/*
 * Copyright 2026 Jeremiah Jordan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dev.keytend.kmip.kms;

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Streaming seal and open (the KTS format, {@link StreamEnvelopes}). */
class StreamingSealTest {
  static final byte[] AAD = "record 7".getBytes(StandardCharsets.UTF_8);

  /** The smallest chunk size a reader accepts, so that small streams have several chunks. */
  static final int C = StreamEnvelopes.MIN_CHUNK;

  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  Kms connect(InMemoryKmipServer server) {
    servers.add(server);
    Kms kms = Kms.connect(server.configure().build());
    clients.add(kms);
    return kms;
  }

  static KeyHandle aes(Kms kms, String name) {
    return kms.keys()
        .createAes(256)
        .named(name)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .create();
  }

  static byte[] data(int size, long seed) {
    byte[] b = new byte[size];
    new Random(seed).nextBytes(b);
    return b;
  }

  /** Seals with the writer's chunk size {@code chunk}; {@code mode} 0 writes byte by byte, 1 in one call, 2 in odd pieces. */
  static byte[] seal(KeyHandle kek, byte[] plain, int chunk, int mode) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try (SealingStream s =
        StreamEnvelopes.sealing(kek, out, AAD, chunk, StreamEnvelopes.MAX_CHUNKS)) {
      if (mode == 0) for (byte b : plain) s.write(b);
      else if (mode == 1) s.write(plain);
      else
        for (int off = 0, n = 1; off < plain.length; off += n, n = n * 3 + 1)
          s.write(plain, off, Math.min(n, plain.length - off));
      s.finish();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    return out.toByteArray();
  }

  static byte[] seal(KeyHandle kek, byte[] plain) {
    return seal(kek, plain, C, 1);
  }

  /** Reads everything; {@code singleBytes} reads with read(), else with read(byte[], off, len) into an odd-sized buffer. */
  static byte[] readAll(InputStream in, boolean singleBytes, ByteArrayOutputStream seen) {
    try (in) {
      if (singleBytes) for (int b; (b = in.read()) >= 0; ) seen.write(b);
      else {
        byte[] buf = new byte[1000];
        for (int n; (n = in.read(buf, 3, 997)) >= 0; ) {
          assertTrue(n > 0);
          seen.write(buf, 3, n);
        }
      }
      return seen.toByteArray();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  static byte[] open(KeyHandle kek, byte[] stream, byte[] aad) {
    try {
      return readAll(
          kek.opening(new ByteArrayInputStream(stream), aad), false, new ByteArrayOutputStream());
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * Opening {@code stream} fails as BAD_DATA, with operation "opening" (the header, which opening()
   * checks) or "open" (a chunk, which a read checks); returns the failure.
   */
  static KmsException assertRejected(KeyHandle kek, byte[] stream, String what) {
    KmsException e = assertThrows(KmsException.class, () -> open(kek, stream, AAD), what);
    assertEquals(KmsException.Category.BAD_DATA, e.category(), what + ": " + e);
    assertTrue(Set.of("opening", "open").contains(e.operation()), what + ": " + e);
    return e;
  }

  static CryptographicFailureException.Kind kindOf(KmsException e) {
    return assertInstanceOf(CryptographicFailureException.class, e, e.toString()).kind();
  }

  static int headerLength(byte[] stream) {
    return 3 + 1 + 2 + (((stream[4] & 0xff) << 8) | (stream[5] & 0xff)) + 4 + 7;
  }

  // ---- A reference implementation of the format as docs/stored-formats.md documents it ----

  static byte[] header(byte[] wrapped, int chunkSize, byte[] prefix) {
    return ByteBuffer.allocate(3 + 1 + 2 + wrapped.length + 4 + 7)
        .put(new byte[] {'K', 'T', 'S', 1})
        .putShort((short) wrapped.length)
        .put(wrapped)
        .putInt(chunkSize)
        .put(prefix)
        .array();
  }

  /** AES-256-GCM of one chunk: nonce prefix || u32 i || flag, additional data header || aad. */
  static byte[] chunk(
      SecretKey key,
      byte[] header,
      byte[] aad,
      long i,
      boolean last,
      byte[] plain,
      int off,
      int len,
      boolean decrypt)
      throws Exception {
    byte[] prefix = Arrays.copyOfRange(header, header.length - 7, header.length);
    byte[] nonce =
        ByteBuffer.allocate(12).put(prefix).putInt((int) i).put((byte) (last ? 1 : 0)).array();
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    cipher.init(
        decrypt ? Cipher.DECRYPT_MODE : Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, nonce));
    cipher.updateAAD(header);
    cipher.updateAAD(aad);
    return cipher.doFinal(plain, off, len);
  }

  /** A stream built by the reference: {@code flags[i]} is chunk i's final flag, {@code sizes[i]} its plaintext size. */
  record Reference(byte[] stream, byte[] plain) {}

  static Reference reference(DataKey dek, int chunkSize, int[] sizes, boolean[] flags)
      throws Exception {
    return reference(dek, chunkSize, sizes, flags, AAD);
  }

  static Reference reference(
      DataKey dek, int chunkSize, int[] sizes, boolean[] flags, byte[] chunkAad) throws Exception {
    byte[] prefix = data(7, 99);
    byte[] header = header(dek.wrapped().toBytes(), chunkSize, prefix);
    ByteArrayOutputStream out = new ByteArrayOutputStream(), plain = new ByteArrayOutputStream();
    out.write(header);
    for (int i = 0; i < sizes.length; i++) {
      byte[] p = data(sizes[i], i);
      plain.write(p);
      out.write(chunk(dek.key(), header, chunkAad, i, flags[i], p, 0, p.length, false));
    }
    return new Reference(out.toByteArray(), plain.toByteArray());
  }

  // ---- Round trips ----

  /**
   * Round trips at the chunk boundaries, writing byte by byte, at once and in odd pieces, and
   * reading byte by byte and in odd pieces. The output has exactly one chunk per started chunk of
   * plaintext (one for empty plaintext), and nothing else.
   */
  @Test
  void roundTripsAtEveryBoundary() {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "orders");
    for (int size : new int[] {0, 1, C - 1, C, C + 1, 3 * C + 17}) {
      byte[] plain = data(size, size);
      for (int mode = 0; mode < 3; mode++) {
        byte[] stream = seal(kek, plain, C, mode);
        int chunks = Math.max(1, (size + C - 1) / C);
        assertEquals(
            headerLength(stream) + size + 16 * chunks,
            stream.length,
            "size " + size + " mode " + mode);
        for (boolean single : new boolean[] {true, false}) {
          try {
            byte[] back =
                readAll(
                    kek.opening(new ByteArrayInputStream(stream), AAD),
                    single,
                    new ByteArrayOutputStream());
            assertArrayEquals(plain, back, "size " + size + " mode " + mode);
          } catch (IOException e) {
            throw new UncheckedIOException(e);
          }
        }
      }
    }
  }

  /**
   * The public API writes 64 KiB chunks in the documented layout: an independent decoder written
   * from docs/stored-formats.md reads it, and the SDK opens a stream that decoder's encoder wrote.
   */
  @Test
  void theFormatIsTheDocumentedOne() throws Exception {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "orders");
    byte[] plain = data(2 * 65536 + 5, 1);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try (SealingStream s = kek.sealing(out, AAD)) {
      s.write(plain);
      s.finish();
    }
    byte[] stream = out.toByteArray();
    ByteBuffer b = ByteBuffer.wrap(stream);
    byte[] magic = new byte[4];
    b.get(magic);
    assertArrayEquals(new byte[] {'K', 'T', 'S', 1}, magic);
    byte[] wrapped = new byte[Short.toUnsignedInt(b.getShort())];
    b.get(wrapped);
    assertEquals(65536, b.getInt());
    b.position(b.position() + 7);
    byte[] header = Arrays.copyOf(stream, b.position());
    Ciphertext w = Ciphertext.fromBytes(wrapped);
    assertEquals(kek.id(), w.keyId());
    assertEquals(kek.id(), KmsKeys.sealedStreamKeyId(new ByteArrayInputStream(stream)));
    ByteArrayOutputStream back = new ByteArrayOutputStream();
    try (DestroyableSecretKey dek = kek.unwrapKey(Expect.aes(256), w, AAD)) {
      for (int i = 0; b.hasRemaining(); i++) {
        int n = Math.min(65536 + 16, b.remaining());
        back.write(chunk(dek, header, AAD, i, n == b.remaining(), stream, b.position(), n, true));
        b.position(b.position() + n);
      }
    }
    assertArrayEquals(plain, back.toByteArray());

    try (DataKey dek = kek.generateDataKey(256, AAD)) {
      Reference r =
          reference(dek, 8192, new int[] {8192, 8192, 100}, new boolean[] {false, false, true});
      assertArrayEquals(r.plain(), open(kek, r.stream(), AAD));
      assertArrayEquals(r.plain(), open(kek, r.stream(), AAD));
    }
  }

  // ---- Tampering ----

  /** Flipping one bit in any byte of a two-chunk stream, header included, makes it fail. */
  @Test
  void everyBitFlipIsRejected() {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "orders");
    byte[] plain = data(C + 40, 3);
    byte[] stream = seal(kek, plain);
    assertArrayEquals(plain, open(kek, stream, AAD));
    for (int i = 0; i < stream.length; i++) {
      byte[] t = stream.clone();
      t[i] ^= (byte) (1 << (i % 8));
      assertRejected(kek, t, "bit flipped at " + i + " of " + stream.length);
    }
  }

  /**
   * Random cuts, byte changes, insertions and deletions, and random chunk-level edits (chunks
   * dropped, repeated or moved, the stream cut at a chunk boundary, or continued with another
   * stream's chunks under the same key) never yield other plaintext: every changed stream fails,
   * and an unchanged one yields the original.
   */
  @Test
  void fuzzedStreamsNeverYieldOtherPlaintext() {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "orders");
    byte[] plain = data(3 * C + 300, 4);
    byte[] stream = seal(kek, plain), other = seal(kek, data(3 * C + 300, 5));
    int h = headerLength(stream), full = C + 16;
    List<byte[]> chunks = new ArrayList<>(), others = new ArrayList<>();
    for (int at = h; at < stream.length; at += full) {
      chunks.add(Arrays.copyOfRange(stream, at, Math.min(stream.length, at + full)));
      others.add(Arrays.copyOfRange(other, at, Math.min(other.length, at + full)));
    }
    Random random = new Random(2026_10_27);
    int changed = 0, rejected = 0;
    for (int round = 0; round < 600; round++) {
      byte[] t;
      switch (round % 6) {
        case 0 -> t = Arrays.copyOf(stream, random.nextInt(stream.length));
        case 1 -> {
          t = stream.clone();
          for (int k = 1 + random.nextInt(3); k > 0; k--)
            t[random.nextInt(t.length)] = (byte) random.nextInt(256);
        }
        case 2 -> {
          int at = random.nextInt(stream.length + 1);
          byte[] extra = data(1 + random.nextInt(40), round);
          t =
              ByteBuffer.allocate(stream.length + extra.length)
                  .put(stream, 0, at)
                  .put(extra)
                  .put(stream, at, stream.length - at)
                  .array();
        }
        case 3 -> {
          int at = random.nextInt(stream.length),
              n = 1 + random.nextInt(Math.min(64, stream.length - at));
          t =
              ByteBuffer.allocate(stream.length - n)
                  .put(stream, 0, at)
                  .put(stream, at + n, stream.length - at - n)
                  .array();
        }
        case 4 -> {
          List<byte[]> edited = new ArrayList<>(chunks);
          for (int k = 1 + random.nextInt(2); k > 0; k--) {
            int i = random.nextInt(edited.size());
            switch (random.nextInt(4)) {
              case 0 -> {
                if (edited.size() > 1) edited.remove(i);
              }
              case 1 -> edited.add(i, edited.get(i));
              case 2 -> {
                byte[] moved = edited.remove(i);
                edited.add(random.nextInt(edited.size() + 1), moved);
              }
              default -> edited.subList(i + 1, edited.size()).clear();
            }
          }
          t = concat(Arrays.copyOf(stream, h), concat(edited.toArray(byte[][]::new)));
        }
        default -> {
          int i = random.nextInt(chunks.size() + 1);
          List<byte[]> spliced = new ArrayList<>(chunks.subList(0, i));
          spliced.addAll(others.subList(random.nextInt(others.size() + 1), others.size()));
          t = concat(Arrays.copyOf(stream, h), concat(spliced.toArray(byte[][]::new)));
        }
      }
      boolean same = Arrays.equals(stream, t);
      if (!same) changed++;
      try {
        byte[] back = open(kek, t, AAD);
        assertTrue(same, "round " + round + ": a changed stream opened");
        assertArrayEquals(plain, back, "round " + round);
      } catch (KmsException e) {
        assertEquals(KmsException.Category.BAD_DATA, e.category(), "round " + round + ": " + e);
        rejected++;
      }
    }
    assertEquals(changed, rejected);
    assertTrue(changed > 550, "changed " + changed);
  }

  /**
   * Cuts, extensions, reordering and splicing at chunk boundaries fail with a stated kind, and a
   * reader that fails part-way has seen only an authentic prefix: the chunks before the bad one.
   */
  @Test
  void truncationReorderingAndSplicingFail() {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "orders");
    byte[] plain = data(3 * C + 100, 5);
    byte[] stream = seal(kek, plain), other = seal(kek, data(3 * C + 100, 6));
    int h = headerLength(stream), full = C + 16;
    byte[] head = Arrays.copyOf(stream, h);
    byte[][] chunks = new byte[4][];
    for (int i = 0; i < 4; i++)
      chunks[i] =
          Arrays.copyOfRange(stream, h + i * full, Math.min(stream.length, h + (i + 1) * full));
    byte[] otherChunk1 = Arrays.copyOfRange(other, h + full, h + 2 * full);

    Map<String, byte[]> authentication = new LinkedHashMap<>();
    authentication.put(
        "chunks 0 and 1 swapped", concat(head, chunks[1], chunks[0], chunks[2], chunks[3]));
    authentication.put(
        "chunk 1 duplicated", concat(head, chunks[0], chunks[1], chunks[1], chunks[2], chunks[3]));
    authentication.put("chunk 1 dropped", concat(head, chunks[0], chunks[2], chunks[3]));
    authentication.put("final chunk dropped", concat(head, chunks[0], chunks[1], chunks[2]));
    authentication.put("cut after chunk 0", concat(head, chunks[0]));
    authentication.put("cut inside the final chunk", Arrays.copyOf(stream, stream.length - 1));
    authentication.put("cut inside chunk 2", Arrays.copyOf(stream, h + 2 * full + 100));
    authentication.put("a byte appended", concat(stream, new byte[1]));
    authentication.put("the final chunk repeated", concat(stream, chunks[3]));
    authentication.put("another stream appended", concat(stream, other));
    authentication.put(
        "chunk 1 from another stream under the same key",
        concat(head, chunks[0], otherChunk1, chunks[2], chunks[3]));
    authentication.put(
        "another stream's chunks under this header",
        concat(head, Arrays.copyOfRange(other, h, other.length)));
    for (var e : authentication.entrySet())
      assertEquals(
          CryptographicFailureException.Kind.AUTHENTICATION_FAILED,
          kindOf(assertRejected(kek, e.getValue(), e.getKey())),
          e.getKey());

    Map<String, byte[]> invalid = new LinkedHashMap<>();
    invalid.put("cut inside the header", Arrays.copyOf(stream, h - 1));
    invalid.put("cut after the header", head);
    invalid.put(
        "cut leaving 15 bytes of the final chunk",
        concat(head, chunks[0], chunks[1], chunks[2], Arrays.copyOf(chunks[3], 15)));
    invalid.put("not a stream", new byte[] {'K', 'T', 'E', 1, 0, 1, 0});
    for (var e : invalid.entrySet())
      assertEquals(
          CryptographicFailureException.Kind.INVALID_CIPHERTEXT,
          kindOf(assertRejected(kek, e.getValue(), e.getKey())),
          e.getKey());

    // A reader that fails at chunk 2 has seen chunks 0 and 1, authentic and in order.
    ByteArrayOutputStream seen = new ByteArrayOutputStream();
    CryptographicFailureException e =
        assertThrows(
            CryptographicFailureException.class,
            () ->
                readAll(
                    kek.opening(
                        new ByteArrayInputStream(concat(head, chunks[0], chunks[1], chunks[2])),
                        AAD),
                    false,
                    seen));
    assertEquals(KmsException.Category.BAD_DATA, e.category());
    assertEquals("open", e.operation());
    assertEquals(Optional.of(kek.id()), e.objectId());
    assertTrue(
        e.getMessage().contains("chunk 2") && e.getMessage().contains("discard everything"),
        e.getMessage());
    assertArrayEquals(Arrays.copyOf(plain, 2 * C), seen.toByteArray());
  }

  /**
   * A full last chunk carries the final flag: a stream of exactly one chunk followed by anything
   * fails. (A reader that tried the final flag after a failed tag would stop there and ignore
   * what follows.)
   */
  @Test
  void dataAfterAFullFinalChunkFails() {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "orders");
    byte[] plain = data(C, 7);
    byte[] stream = seal(kek, plain);
    assertArrayEquals(plain, open(kek, stream, AAD));
    for (byte[] tail : List.of(new byte[1], data(17, 8), data(C + 16, 9), seal(kek, data(10, 10))))
      assertEquals(
          CryptographicFailureException.Kind.AUTHENTICATION_FAILED,
          kindOf(assertRejected(kek, concat(stream, tail), tail.length + " bytes appended")));
  }

  /**
   * Streams the SDK never writes but a forger could try: no chunk carries the final flag (the
   * stream was cut at a chunk boundary), the final flag on a chunk followed by more, and an empty
   * final chunk after a full one.
   */
  @Test
  void theFinalFlagMarksTheEndAndOnlyTheEnd() throws Exception {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "orders");
    try (DataKey dek = kek.generateDataKey(256, AAD)) {
      Reference good = reference(dek, C, new int[] {C, C, 9}, new boolean[] {false, false, true});
      assertArrayEquals(good.plain(), open(kek, good.stream(), AAD));
      Reference oneChunk = reference(dek, C, new int[] {C}, new boolean[] {true});
      assertArrayEquals(oneChunk.plain(), open(kek, oneChunk.stream(), AAD));

      Reference noFinal = reference(dek, C, new int[] {C, C}, new boolean[] {false, false});
      assertEquals(
          CryptographicFailureException.Kind.AUTHENTICATION_FAILED,
          kindOf(assertRejected(kek, noFinal.stream(), "no final chunk")));
      Reference shortNoFinal = reference(dek, C, new int[] {C, 9}, new boolean[] {false, false});
      assertEquals(
          CryptographicFailureException.Kind.AUTHENTICATION_FAILED,
          kindOf(assertRejected(kek, shortNoFinal.stream(), "short, no flag")));
      Reference earlyFinal =
          reference(dek, C, new int[] {C, C, 9}, new boolean[] {true, false, true});
      assertEquals(
          CryptographicFailureException.Kind.AUTHENTICATION_FAILED,
          kindOf(assertRejected(kek, earlyFinal.stream(), "final flag on chunk 0")));
      Reference emptyFinal = reference(dek, C, new int[] {C, 0}, new boolean[] {false, true});
      KmsException e =
          assertRejected(kek, emptyFinal.stream(), "an empty final chunk after a full one");
      assertEquals(CryptographicFailureException.Kind.INVALID_CIPHERTEXT, kindOf(e));
      assertTrue(e.getMessage().contains("empty"), e.getMessage());
    }
  }

  /**
   * The header is bound into every chunk: the same data key wrapped again (another IV), or another
   * chunk size that keeps the chunking of a one-chunk stream, in an otherwise unchanged stream,
   * fails. So does other additional data, and a chunk size outside 4 KiB..1 MiB even when
   * authentic.
   */
  @Test
  void theHeaderAndTheAdditionalDataAreBound() throws Exception {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "orders");
    byte[] sealed = seal(kek, data(100, 10));
    int h = headerLength(sealed);
    byte[] body = Arrays.copyOfRange(sealed, h, sealed.length);
    byte[] prefix = Arrays.copyOfRange(sealed, h - 7, h);
    Ciphertext wrapped = Ciphertext.fromBytes(Arrays.copyOfRange(sealed, 6, h - 11));
    assertArrayEquals(header(wrapped.toBytes(), C, prefix), Arrays.copyOf(sealed, h));
    try (DestroyableSecretKey dek = kek.unwrapKey(Expect.aes(256), wrapped, AAD)) {
      byte[] rewrapped = kek.wrapKey(dek, AAD).toBytes();
      assertEquals(wrapped.toBytes().length, rewrapped.length);
      assertArrayEquals(
          data(100, 10), open(kek, concat(header(wrapped.toBytes(), C, prefix), body), AAD));
      assertEquals(
          CryptographicFailureException.Kind.AUTHENTICATION_FAILED,
          kindOf(
              assertRejected(
                  kek, concat(header(rewrapped, C, prefix), body), "the data key wrapped again")));
      assertEquals(
          CryptographicFailureException.Kind.AUTHENTICATION_FAILED,
          kindOf(
              assertRejected(
                  kek,
                  concat(header(wrapped.toBytes(), 2 * C, prefix), body),
                  "chunk size relabeled")));
    }

    // The chunks bind the additional data too, not only the wrapped key: chunks sealed for other
    // additional data, under a header whose wrapped key binds this one, fail. (Only a forger that
    // holds the data key could write them: this binding repeats the server's, as in KTE.)
    try (DataKey dek = kek.generateDataKey(256, AAD)) {
      Reference r = reference(dek, C, new int[] {100}, new boolean[] {true});
      assertArrayEquals(r.plain(), open(kek, r.stream(), AAD));
      Reference otherAad =
          reference(
              dek,
              C,
              new int[] {100},
              new boolean[] {true},
              "record 8".getBytes(StandardCharsets.UTF_8));
      assertEquals(
          CryptographicFailureException.Kind.AUTHENTICATION_FAILED,
          kindOf(assertRejected(kek, otherAad.stream(), "chunks bound to other additional data")));
    }

    byte[] stream = seal(kek, data(10, 11));
    KmsException other =
        assertThrows(
            KmsException.class,
            () -> open(kek, stream, "record 8".getBytes(StandardCharsets.UTF_8)));
    assertEquals(KmsException.Category.BAD_DATA, other.category());
    assertEquals("opening", other.operation());
    KmsException none = assertThrows(KmsException.class, () -> open(kek, stream, null));
    assertEquals(KmsException.Category.BAD_DATA, none.category());

    // Authentic streams with a chunk size outside the bounds, then headers changed to 0 and 2^32 -
    // 1.
    for (int size : new int[] {C - 1, StreamEnvelopes.MAX_CHUNK + 1, 0, -1}) {
      byte[] outside = seal(kek, data(10, 12), size > 0 ? size : C, 1);
      if (size <= 0) ByteBuffer.wrap(outside).putInt(headerLength(outside) - 11, size);
      KmsException e = assertRejected(kek, outside, "chunk size " + Integer.toUnsignedString(size));
      assertEquals(CryptographicFailureException.Kind.INVALID_CIPHERTEXT, kindOf(e));
      assertTrue(e.getMessage().contains("chunk size"), e.getMessage());
    }
    for (int size : new int[] {C, StreamEnvelopes.MAX_CHUNK}) {
      byte[] plain = data(10, 13);
      assertArrayEquals(plain, open(kek, seal(kek, plain, size, 1), AAD), "chunk size " + size);
    }
  }

  // ---- Keys ----

  /**
   * The key rules of open: after a rotation either handle opens, a Compromised key is refused
   * unless named with allowingCompromised (through sealedStreamKeyId), another key's handle is
   * BAD_DATA, and the query variant is BAD_DATA for another key and FIX_REQUEST for a query that
   * matches nothing.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void openingFollowsTheKeyRulesOfOpen(KmipVersion version) throws IOException {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle kek = aes(kms, "orders"), other = aes(kms, "other");
    byte[] plain = data(C + 5, 14);
    byte[] old = seal(kek, plain);
    KeyHandle next = kek.rotate();
    byte[] fresh = seal(next, plain);
    assertArrayEquals(plain, open(next, old, AAD));
    assertArrayEquals(plain, open(kek, fresh, AAD));
    assertArrayEquals(
        plain,
        readAll(
            kms.keys().opening(KeyQuery.byName("orders"), new ByteArrayInputStream(old), AAD),
            true,
            new ByteArrayOutputStream()));

    KeyMismatchException foreign =
        assertThrows(
            KeyMismatchException.class, () -> other.opening(new ByteArrayInputStream(old), AAD));
    assertEquals(KmsException.Category.BAD_DATA, foreign.category());
    assertEquals("opening", foreign.operation());
    KeyMismatchException wrongQuery =
        assertThrows(
            KeyMismatchException.class,
            () -> kms.keys().opening(KeyQuery.byName("other"), new ByteArrayInputStream(old), AAD));
    assertEquals(KmsException.Category.BAD_DATA, wrongQuery.category());
    assertEquals("opening", wrongQuery.operation());
    KeyMismatchException nothing =
        assertThrows(
            KeyMismatchException.class,
            () -> kms.keys().opening(KeyQuery.byName("nope"), new ByteArrayInputStream(old), AAD));
    assertEquals(KmsException.Category.FIX_REQUEST, nothing.category());
    assertEquals("opening", nothing.operation());

    kek.revoke(RevocationReason.keyCompromise("leaked", Instant.now().minusSeconds(60)));
    StateConflictException refused =
        assertThrows(
            StateConflictException.class, () -> next.opening(new ByteArrayInputStream(old), AAD));
    assertEquals("opening", refused.operation());
    assertThrows(
        StateConflictException.class, () -> kek.opening(new ByteArrayInputStream(old), AAD));
    assertThrows(
        StateConflictException.class,
        () -> kms.keys().opening(KeyQuery.byName("orders"), new ByteArrayInputStream(old), AAD));
    InputStream in = new ByteArrayInputStream(old);
    String id = KmsKeys.sealedStreamKeyId(in);
    assertEquals(kek.id(), id);
    assertEquals(old.length - headerLength(old), in.available(), "reads only the header");
    assertArrayEquals(plain, open(kms.keys().handle(id).allowingCompromised(), old, AAD));
    assertArrayEquals(plain, open(next, fresh, AAD));

    assertEquals(
        CryptographicFailureException.Kind.INVALID_CIPHERTEXT,
        assertThrows(
                CryptographicFailureException.class,
                () -> KmsKeys.sealedStreamKeyId(new ByteArrayInputStream(Arrays.copyOf(old, 20))))
            .kind());
  }

  /** Like seal, streaming needs KMIP 1.4 (the data key is wrapped with AES-GCM); nothing is written before that. */
  @Test
  void streamingNeedsKmip14() {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V1_2));
    KeyHandle kek = aes(kms, "orders");
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    UnsupportedException e = assertThrows(UnsupportedException.class, () -> kek.sealing(out, AAD));
    assertEquals("sealing", e.operation());
    assertEquals(0, out.size());
    Ciphertext wrapped =
        Ciphertext.builder()
            .keyId(kek.id())
            .specName(CipherSpec.aesGcm().name())
            .iv(new byte[12])
            .tag(new byte[16])
            .data(new byte[32])
            .build();
    byte[] stream = concat(header(wrapped.toBytes(), C, new byte[7]), new byte[16]);
    UnsupportedException o =
        assertThrows(
            UnsupportedException.class, () -> kek.opening(new ByteArrayInputStream(stream), AAD));
    assertEquals("opening", o.operation());
  }

  /**
   * Sealing sends one request (Encrypt) when the stream is created, opening two (Get Attributes and
   * Decrypt), whatever the size; nothing is sent per chunk.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void requestsDoNotDependOnTheSize(KmipVersion version) throws IOException {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle kek = aes(kms, "orders");
    kek.seal(new byte[1], AAD);
    for (int size : new int[] {0, 200_000}) {
      byte[] plain = data(size, size);
      int before = server.exchanges();
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      SealingStream s = kek.sealing(out, AAD);
      assertEquals(1, server.exchanges() - before, "sealing, size " + size);
      s.write(plain);
      s.finish();
      s.close();
      assertEquals(1, server.exchanges() - before, "sealing, size " + size);
      before = server.exchanges();
      InputStream in = kek.opening(new ByteArrayInputStream(out.toByteArray()), AAD);
      assertEquals(2, server.exchanges() - before, "opening, size " + size);
      assertArrayEquals(plain, readAll(in, false, new ByteArrayOutputStream()));
      assertEquals(2, server.exchanges() - before, "opening, size " + size);
    }
  }

  // ---- Stream behavior ----

  /**
   * The writer: finish writes the final chunk without closing the target, close closes the target
   * once (flush after close does nothing, as an enclosing stream may call it); a write after
   * finish or close or after the target failed throws IOException, and a failed stream can be
   * neither finished nor completed by closing; a stream never finished cannot be opened; and no
   * more chunks than the format allows are written.
   */
  @Test
  void theSealingStreamEndsOnlyWhenFinished() throws IOException {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "orders");
    int[] closes = {0};
    ByteArrayOutputStream out =
        new ByteArrayOutputStream() {
          @Override
          public void close() {
            closes[0]++;
          }
        };
    SealingStream s = StreamEnvelopes.sealing(kek, out, AAD, C, StreamEnvelopes.MAX_CHUNKS);
    byte[] plain = data(2 * C + 1, 15);
    s.write(plain);
    byte[] unclosed = out.toByteArray();
    assertEquals(
        headerLength(unclosed) + 2 * (C + 16),
        unclosed.length,
        "full chunks are written once more data arrives");
    assertRejected(kek, unclosed, "never finished");
    s.finish();
    s.finish();
    assertEquals(0, closes[0], "finish does not close the target");
    assertTrue(assertThrows(IOException.class, () -> s.write(1)).getMessage().contains("finished"));
    s.flush();
    s.close();
    s.close();
    s.flush();
    assertEquals(1, closes[0]);
    assertThrows(IOException.class, () -> s.write(1));
    assertThrows(IOException.class, () -> s.write(new byte[3]));
    assertArrayEquals(plain, open(kek, out.toByteArray(), AAD));

    // The target fails during the second chunk: later writes fail, and close does not complete it.
    ByteArrayOutputStream partial = new ByteArrayOutputStream();
    int[] budget = {headerLength(unclosed) + C + 16 + 10};
    OutputStream failing =
        new OutputStream() {
          @Override
          public void write(int b) throws IOException {
            write(new byte[] {(byte) b}, 0, 1);
          }

          @Override
          public void write(byte[] b, int off, int len) throws IOException {
            int n = Math.min(len, budget[0]);
            partial.write(b, off, n);
            budget[0] -= n;
            if (n < len) throw new IOException("disk full");
          }
        };
    SealingStream f = StreamEnvelopes.sealing(kek, failing, AAD, C, StreamEnvelopes.MAX_CHUNKS);
    assertEquals("disk full", assertThrows(IOException.class, () -> f.write(plain)).getMessage());
    assertTrue(
        assertThrows(IOException.class, () -> f.write(1)).getMessage().contains("failed earlier"));
    int written = partial.size();
    assertTrue(assertThrows(IOException.class, f::finish).getMessage().contains("failed earlier"));
    assertTrue(assertThrows(IOException.class, f::close).getMessage().contains("cannot be opened"));
    assertEquals(written, partial.size(), "finishing or closing a failed stream writes nothing");
    assertRejected(kek, partial.toByteArray(), "a failed stream");

    // At most maxChunks chunks: two chunks hold 2C bytes, one byte more is refused when written.
    ByteArrayOutputStream two = new ByteArrayOutputStream();
    SealingStream t = StreamEnvelopes.sealing(kek, two, AAD, C, 2);
    t.write(new byte[2 * C]);
    IOException tooMany = assertThrows(IOException.class, () -> t.write(0));
    assertTrue(tooMany.getMessage().contains("split the data"), tooMany.getMessage());
    assertThrows(IOException.class, t::finish);
    assertThrows(IOException.class, t::close);
    assertRejected(kek, two.toByteArray(), "a stream that hit the limit is not completed");
    byte[] exactly = seal(kek, new byte[2 * C], C, 1);
    InputStream limited =
        StreamEnvelopes.opening(
            new ByteArrayInputStream(exactly), AAD, w -> kek.unwrapKey(Expect.aes(256), w, AAD), 2);
    assertArrayEquals(new byte[2 * C], readAll(limited, false, new ByteArrayOutputStream()));
    InputStream over =
        StreamEnvelopes.opening(
            new ByteArrayInputStream(seal(kek, new byte[2 * C + 1], C, 1)),
            AAD,
            w -> kek.unwrapKey(Expect.aes(256), w, AAD),
            2);
    assertEquals(
        CryptographicFailureException.Kind.INVALID_CIPHERTEXT,
        assertThrows(
                CryptographicFailureException.class,
                () -> readAll(over, false, new ByteArrayOutputStream()))
            .kind());
  }

  /**
   * The reader: it reads the input in any pieces, an I/O error can be retried without losing
   * bytes, a failure repeats on every later read, available() counts released bytes only, and
   * close closes the input and refuses later reads.
   */
  @Test
  void theOpeningStreamReleasesOnlyVerifiedChunks() throws IOException {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "orders");
    byte[] plain = data(2 * C + 50, 16);
    byte[] stream = seal(kek, plain);

    // One byte per read, and an IOException in the middle of chunk 1, retried.
    int[] calls = {0};
    boolean[] closed = {false};
    InputStream trickle =
        new InputStream() {
          final ByteArrayInputStream in = new ByteArrayInputStream(stream);
          int position;

          @Override
          public int read() throws IOException {
            byte[] one = new byte[1];
            return read(one, 0, 1) < 0 ? -1 : one[0] & 0xff;
          }

          @Override
          public int read(byte[] b, int off, int len) throws IOException {
            if (len == 0) return 0;
            if (position == stream.length - C && calls[0]++ == 0) throw new IOException("timeout");
            int n = in.read(b, off, 1);
            if (n > 0) position++;
            return n;
          }

          @Override
          public void close() {
            closed[0] = true;
          }
        };
    InputStream in = kek.opening(trickle, AAD);
    ByteArrayOutputStream seen = new ByteArrayOutputStream();
    assertEquals(0, in.available());
    byte[] buf = new byte[C];
    IOException timeout = null;
    while (true) {
      try {
        int n = in.read(buf, 0, buf.length);
        if (n < 0) break;
        seen.write(buf, 0, n);
      } catch (IOException e) {
        timeout = e;
      }
    }
    assertNotNull(timeout);
    assertArrayEquals(plain, seen.toByteArray());
    in.close();
    assertTrue(closed[0]);
    assertThrows(IOException.class, in::read);

    // A bad chunk 1: chunk 0 is released whole, then every read fails, and available() is 0.
    byte[] bad = stream.clone();
    bad[headerLength(stream) + C + 16 + 5] ^= 1;
    InputStream b = kek.opening(new ByteArrayInputStream(bad), AAD);
    assertEquals(plain[0] & 0xff, b.read());
    assertEquals(C - 1, b.available());
    assertEquals(C - 1, b.readNBytes(C - 1).length);
    CryptographicFailureException first =
        assertThrows(CryptographicFailureException.class, b::read);
    assertEquals(CryptographicFailureException.Kind.AUTHENTICATION_FAILED, first.kind());
    assertSame(
        first, assertThrows(CryptographicFailureException.class, () -> b.read(new byte[10])));
    assertEquals(0, b.available());
    b.close();
  }

  static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] p : parts) out.writeBytes(p);
    return out.toByteArray();
  }
}
