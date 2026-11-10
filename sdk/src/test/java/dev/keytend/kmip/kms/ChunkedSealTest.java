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

import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.ByteArrayOutputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Random-access sealed data ({@link KeyHandle#chunkedSealer},
 * {@link ChunkedSealer}, {@link ChunkedOpener}, the KTR format of {@link ChunkedEnvelopes}).
 */
class ChunkedSealTest {
  static final byte[] FILE = "sstable-nb-42-big".getBytes(StandardCharsets.UTF_8);
  static final int CORE = 44;
  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  Kms connect(InMemoryKmipServer server) {
    servers.add(server);
    Kms kms = server.connect();
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

  /** The operations sent to {@code s} since request number {@code from}. */
  static List<Operation> ops(InMemoryKmipServer s, int from) {
    List<Operation> out = new ArrayList<>();
    List<Ttlv> all = s.protocolRequests();
    for (Ttlv r : all.subList(from, all.size()))
      for (Ttlv item : r.children(Tag.BATCH_ITEM))
        out.add(Operation.fromCode(item.require(Tag.OPERATION).intValue()));
    return out;
  }

  static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] p : parts) out.writeBytes(p);
    return out.toByteArray();
  }

  static byte[] u32(long index) {
    return ByteBuffer.allocate(4).putInt((int) index).array();
  }

  static byte[] flip(byte[] b, int at) {
    byte[] c = b.clone();
    c[at] ^= 0x01;
    return c;
  }

  /** A file: its header and its chunks, the last sealed as the final chunk. */
  record SealedFile(byte[] header, List<byte[]> plain, List<byte[]> chunks) {}

  static SealedFile sealFile(KeyHandle kek, byte[] fileId, int... sizes) {
    List<byte[]> plain = new ArrayList<>(), chunks = new ArrayList<>();
    try (ChunkedSealer s = kek.chunkedSealer(fileId)) {
      for (int i = 0; i < sizes.length; i++) {
        byte[] p = data(sizes[i], 1000L * sizes.length + i);
        plain.add(p);
        chunks.add(i == sizes.length - 1 ? s.sealFinal(i, p) : s.seal(i, p));
      }
      return new SealedFile(s.header(), plain, chunks);
    }
  }

  static CryptographicFailureException.Kind failure(Executable call, String what) {
    CryptographicFailureException e =
        assertThrows(CryptographicFailureException.class, call::run, what);
    assertEquals(KmsException.Category.BAD_DATA, e.category(), what);
    return e.kind();
  }

  interface Executable {
    void run() throws Throwable;
  }

  // ---- A reference implementation of the format as docs/stored-formats.md documents it ----

  static byte[] hkdfExpand(byte[] prk, String info) throws Exception {
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(prk, "HmacSHA256"));
    mac.update(info.getBytes(StandardCharsets.US_ASCII));
    mac.update((byte) 1);
    return mac.doFinal();
  }

  /** Opens chunk {@code index} of {@code header} by the documented layout alone. */
  static byte[] referenceOpen(
      KeyHandle kek, byte[] header, byte[] fileId, long index, boolean last, byte[] chunk)
      throws Exception {
    assertArrayEquals(new byte[] {'K', 'T', 'R', 1}, Arrays.copyOf(header, 4));
    byte[] core = Arrays.copyOf(header, CORE);
    byte[] prefix = Arrays.copyOfRange(header, 4, 12);
    byte[] commitment = Arrays.copyOfRange(header, 12, CORE);
    int w = ((header[CORE] & 0xff) << 8) | (header[CORE + 1] & 0xff);
    assertEquals(header.length, CORE + 2 + w, "nothing follows the wrapped key");
    Ciphertext wrapped = Ciphertext.fromBytes(Arrays.copyOfRange(header, CORE + 2, header.length));
    assertEquals("AES-GCM-16", wrapped.specName());
    try (DestroyableSecretKey dek = kek.unwrapKey(Expect.aes(256), wrapped, concat(core, fileId))) {
      assertArrayEquals(
          hkdfExpand(dek.getEncoded(), "keytend-kmip KTR 1 key commitment"), commitment);
      byte[] chunkKey = hkdfExpand(dek.getEncoded(), "keytend-kmip KTR 1 chunk key");
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      c.init(
          Cipher.DECRYPT_MODE,
          new SecretKeySpec(chunkKey, "AES"),
          new GCMParameterSpec(128, concat(prefix, u32(index))));
      c.updateAAD(concat(core, new byte[] {(byte) (last ? 1 : 0)}, u32(index), fileId));
      return c.doFinal(chunk);
    }
  }

  // ---- Round trips and the format ----

  /**
   * Chunks of 0 bytes to 1 MiB round-trip through the sealer and an opener, in any order; the
   * header has the documented layout and names the KEK; each chunk is its plaintext plus a tag and
   * opens by the documented layout alone.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void chunksRoundTripInAnyOrder(KmipVersion version) throws Exception {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle kek = aes(kms, "orders");
    int[] sizes = {4096, 0, 1, ChunkedEnvelopes.MAX_CHUNK, 65536, 100};
    byte[][] chunks = new byte[sizes.length][];
    byte[] header;
    try (ChunkedSealer s = kek.chunkedSealer(FILE)) {
      header = s.header();
      assertEquals(kek.id(), s.keyId());
      for (int i : new int[] {3, 0, 4, 1, 2}) {
        chunks[i] = s.seal(i, data(sizes[i], i));
        assertEquals(sizes[i] + 16, chunks[i].length);
      }
      chunks[5] = s.sealFinal(5, data(sizes[5], 5));
      for (int i = 0; i < sizes.length; i++)
        assertArrayEquals(data(sizes[i], i), s.open(i, chunks[i]), "the sealer opens " + i);
      assertArrayEquals(data(100, 5), s.openFinal(5, chunks[5]));
      assertArrayEquals(header, s.header());
    }
    assertEquals(kek.id(), KmsKeys.chunkedHeaderKeyId(header));
    try (ChunkedOpener o = kek.chunkedOpener(header, FILE)) {
      assertEquals(kek.id(), o.keyId());
      for (int i : new int[] {5, 2, 0, 4, 1, 3})
        assertArrayEquals(data(sizes[i], i), o.open(i, chunks[i]), "chunk " + i);
      assertArrayEquals(data(100, 5), o.openFinal(5, chunks[5]));
    }
    for (int i = 0; i < sizes.length; i++)
      assertArrayEquals(
          data(sizes[i], i),
          referenceOpen(kek, header, FILE, i, i == 5, chunks[i]),
          "reference, chunk " + i);
    // An empty file identifier is allowed; the file identifier is not stored.
    SealedFile empty = sealFile(kek, new byte[0], 10);
    try (ChunkedOpener o = kek.chunkedOpener(empty.header(), new byte[0])) {
      assertArrayEquals(empty.plain().get(0), o.open(0, empty.chunks().get(0)));
    }
  }

  /**
   * Nonces differ per index (prefix || index) and per file (a random prefix and a fresh data key):
   * the same plaintext sealed at two indices, or in two files, gives unrelated ciphertexts.
   */
  @Test
  void theSamePlaintextNeverSealsAlike() {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "orders");
    byte[] p = new byte[64];
    byte[] a0, a1, b0, ha, hb;
    try (ChunkedSealer a = kek.chunkedSealer(FILE);
        ChunkedSealer b = kek.chunkedSealer(FILE)) {
      a0 = a.seal(0, p);
      a1 = a.seal(1, p);
      b0 = b.seal(0, p);
      ha = a.header();
      hb = b.header();
    }
    assertFalse(
        Arrays.equals(Arrays.copyOf(a0, 64), Arrays.copyOf(a1, 64)), "the index is in the nonce");
    assertFalse(
        Arrays.equals(Arrays.copyOf(a0, 64), Arrays.copyOf(b0, 64)), "another file, another key");
    assertFalse(
        Arrays.equals(Arrays.copyOfRange(ha, 4, 12), Arrays.copyOfRange(hb, 4, 12)),
        "a random prefix per file");
    assertFalse(
        Arrays.equals(Arrays.copyOfRange(ha, 12, CORE), Arrays.copyOfRange(hb, 12, CORE)),
        "a data key per file");
  }

  // ---- Tampering ----

  /**
   * Every change fails: a flipped byte anywhere in a chunk, a chunk at another index, chunks
   * swapped, another file's chunk (same KEK, same file identifier), another file identifier, a cut
   * or extended chunk, and another file's header.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void everyTamperingFails(KmipVersion version) {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle kek = aes(kms, "orders");
    SealedFile a = sealFile(kek, FILE, 300, 300, 200);
    SealedFile b = sealFile(kek, FILE, 300, 300, 200);
    var auth = CryptographicFailureException.Kind.AUTHENTICATION_FAILED;
    var invalid = CryptographicFailureException.Kind.INVALID_CIPHERTEXT;
    try (ChunkedOpener o = kek.chunkedOpener(a.header(), FILE)) {
      byte[] c0 = a.chunks().get(0), c1 = a.chunks().get(1), c2 = a.chunks().get(2);
      for (int at = 0; at < c0.length; at++) {
        int i = at;
        assertEquals(auth, failure(() -> o.open(0, flip(c0, i)), "a flipped byte at " + at));
      }
      assertEquals(auth, failure(() -> o.open(1, c0), "chunk 0 at index 1"));
      assertEquals(auth, failure(() -> o.open(0, c1), "chunk 1 at index 0 (swapped)"));
      assertEquals(auth, failure(() -> o.open(1L << 31, c0), "chunk 0 at a far index"));
      assertEquals(auth, failure(() -> o.open(0, b.chunks().get(0)), "another file's chunk 0"));
      assertEquals(auth, failure(() -> o.open(2, b.chunks().get(2)), "another file's final chunk"));
      assertEquals(
          auth,
          failure(() -> o.open(0, Arrays.copyOf(c0, c0.length - 1)), "a chunk one byte short"));
      assertEquals(
          auth, failure(() -> o.open(0, Arrays.copyOf(c0, 16)), "a chunk cut to a tag's length"));
      assertEquals(
          invalid, failure(() -> o.open(0, Arrays.copyOf(c0, 15)), "a chunk shorter than a tag"));
      assertEquals(invalid, failure(() -> o.open(0, new byte[0]), "an empty chunk"));
      assertEquals(
          auth, failure(() -> o.open(0, concat(c0, new byte[1])), "a chunk one byte long"));
      assertEquals(
          invalid,
          failure(() -> o.open(0, new byte[ChunkedEnvelopes.MAX_CHUNK + 17]), "a chunk too long"));
      // The final chunk: openFinal proves the count; open accepts either.
      assertArrayEquals(a.plain().get(2), o.openFinal(2, c2));
      assertArrayEquals(a.plain().get(2), o.open(2, c2));
      assertEquals(
          auth,
          failure(() -> o.openFinal(1, c1), "a file cut after chunk 1: chunk 1 is not final"));
      assertEquals(auth, failure(() -> o.openFinal(0, c0), "chunk 0 is not final"));
      assertEquals(auth, failure(() -> o.openFinal(2, flip(c2, 3)), "a changed final chunk"));
    }
    // Another file identifier fails at the unwrap (the server binds it), another file's header on
    // this file's chunks fails per chunk.
    assertEquals(
        auth,
        failure(
            () ->
                kek.chunkedOpener(a.header(), "sstable-nb-43-big".getBytes(StandardCharsets.UTF_8)),
            "another file id"));
    assertEquals(auth, failure(() -> kek.chunkedOpener(a.header(), new byte[0]), "no file id"));
    try (ChunkedOpener ob = kek.chunkedOpener(b.header(), FILE)) {
      assertEquals(
          auth,
          failure(() -> ob.open(0, a.chunks().get(0)), "file a's chunk under file b's header"));
    }
  }

  /**
   * A flipped byte anywhere in the header fails: the magic, version and wrapped-key length as
   * INVALID_CIPHERTEXT, the core (nonce prefix, key commitment) when the server unwraps (it is in
   * the wrapped key's additional data), and the wrapped key with some refusal; none opens.
   */
  @Test
  void everyFlippedHeaderByteFails() {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "orders");
    SealedFile a = sealFile(kek, FILE, 50);
    byte[] h = a.header();
    for (int at = 0; at < h.length; at++) {
      byte[] bad = flip(h, at);
      KmsException e =
          assertThrows(
              KmsException.class,
              () -> {
                try (ChunkedOpener o = kek.chunkedOpener(bad, FILE)) {
                  o.open(0, a.chunks().get(0));
                }
              },
              "a flipped header byte at " + at);
      if (at < 4 || at == CORE || at == CORE + 1)
        assertEquals(
            CryptographicFailureException.Kind.INVALID_CIPHERTEXT,
            ((CryptographicFailureException) e).kind(),
            "at " + at);
      else if (at < CORE)
        assertEquals(
            CryptographicFailureException.Kind.AUTHENTICATION_FAILED,
            ((CryptographicFailureException) e).kind(),
            "at " + at);
    }
    // Lengths: cut, extended, empty, and a header of another format.
    for (byte[] bad :
        List.of(
            Arrays.copyOf(h, h.length - 1),
            concat(h, new byte[1]),
            new byte[0],
            Arrays.copyOf(h, CORE + 2),
            kek.seal(new byte[1], FILE))) {
      assertEquals(
          CryptographicFailureException.Kind.INVALID_CIPHERTEXT,
          failure(() -> kek.chunkedOpener(bad, FILE), "length " + bad.length));
      assertEquals(
          CryptographicFailureException.Kind.INVALID_CIPHERTEXT,
          failure(() -> KmsKeys.chunkedHeaderKeyId(bad), "length " + bad.length));
    }
    byte[] v2 = h.clone();
    v2[3] = 2;
    assertTrue(
        assertThrows(CryptographicFailureException.class, () -> kek.chunkedOpener(v2, FILE))
            .getMessage()
            .contains("unknown format version"));
  }

  /**
   * The key commitment: a header whose wrapped key was replaced by another key wrapped with the same
   * additional data (by someone allowed to use the KEK) is refused when the opener is made, and
   * rewrapHeader refuses it before wrapping anything.
   */
  @Test
  void aReplacedDataKeyFailsTheKeyCommitment() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server);
    KeyHandle kek = aes(kms, "orders");
    SealedFile a = sealFile(kek, FILE, 50);
    byte[] core = Arrays.copyOf(a.header(), CORE);
    byte[] other = kek.wrapKey(new SecretKeySpec(data(32, 9), "AES"), concat(core, FILE)).toBytes();
    byte[] forged =
        concat(core, new byte[] {(byte) (other.length >> 8), (byte) other.length}, other);
    CryptographicFailureException e =
        assertThrows(CryptographicFailureException.class, () -> kek.chunkedOpener(forged, FILE));
    assertEquals(CryptographicFailureException.Kind.AUTHENTICATION_FAILED, e.kind());
    assertTrue(e.getMessage().contains("key commitment"), e.getMessage());
    assertEquals("chunkedOpener", e.operation());
    KeyHandle next = kek.rotate();
    next.seal(new byte[1], null);
    int from = server.protocolRequests().size();
    CryptographicFailureException r =
        assertThrows(CryptographicFailureException.class, () -> next.rewrapHeader(forged, FILE));
    assertTrue(r.getMessage().contains("key commitment"), r.getMessage());
    assertEquals("rewrapHeader", r.operation());
    assertTrue(ops(server, from).contains(Operation.DECRYPT));
    assertFalse(ops(server, from).contains(Operation.ENCRYPT), "nothing wrapped");
  }

  // ---- Each index once, limits ----

  /**
   * A second seal of an index is refused, final or not, also after the sealer opened it; the final
   * chunk bounds the file: nothing past it, no second final, and no final before a sealed index.
   * Indices 0 to 2^32 - 1 and chunks up to 1 MiB; beyond is refused.
   */
  @Test
  void eachIndexIsSealedOnceAndWithinTheLimits() {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "orders");
    try (ChunkedSealer s = kek.chunkedSealer(FILE)) {
      byte[] c3 = s.seal(3, data(10, 3));
      IllegalStateException again =
          assertThrows(IllegalStateException.class, () -> s.seal(3, data(10, 4)));
      assertTrue(again.getMessage().contains("sealed already"), again.getMessage());
      assertThrows(
          IllegalStateException.class,
          () -> s.sealFinal(3, data(10, 4)),
          "a second seal, as the final chunk");
      assertArrayEquals(data(10, 3), s.open(3, c3), "the first seal stands");
      s.seal(7, new byte[1]);
      assertThrows(
          IllegalStateException.class,
          () -> s.sealFinal(5, new byte[1]),
          "a final chunk before a sealed index");
      s.sealFinal(9, new byte[1]);
      assertThrows(
          IllegalStateException.class, () -> s.seal(10, new byte[1]), "past the final chunk");
      assertThrows(
          IllegalStateException.class, () -> s.sealFinal(8, new byte[1]), "a second final chunk");
      s.seal(8, new byte[1]);
      s.seal(0, new byte[1]);
    }
    try (ChunkedSealer s = kek.chunkedSealer(FILE)) {
      byte[] top = s.seal((1L << 32) - 1, new byte[ChunkedEnvelopes.MAX_CHUNK]);
      assertEquals(ChunkedEnvelopes.MAX_CHUNK + 16, top.length);
      assertThrows(IllegalStateException.class, () -> s.seal((1L << 32) - 1, new byte[1]));
      assertThrows(IllegalArgumentException.class, () -> s.seal(1L << 32, new byte[1]));
      assertThrows(IllegalArgumentException.class, () -> s.seal(-1, new byte[1]));
      assertThrows(
          IllegalArgumentException.class,
          () -> s.seal(0, new byte[ChunkedEnvelopes.MAX_CHUNK + 1]));
      assertThrows(NullPointerException.class, () -> s.seal(0, null));
      assertThrows(IllegalArgumentException.class, () -> s.open(1L << 32, top));
      assertThrows(IllegalArgumentException.class, () -> s.open(-1, top));
      // Refused calls claimed nothing: index 0 seals.
      s.seal(0, new byte[1]);
      try (ChunkedOpener o = kek.chunkedOpener(s.header(), FILE)) {
        assertArrayEquals(new byte[ChunkedEnvelopes.MAX_CHUNK], o.open((1L << 32) - 1, top));
      }
    }
  }

  /** Nothing seals from a stored header: an opener has no seal method, and a sealer no public constructor. */
  @Test
  void nothingSealsFromAStoredHeader() {
    for (Method m : ChunkedOpener.class.getMethods())
      assertFalse(m.getName().startsWith("seal"), m.toString());
    assertEquals(0, ChunkedSealer.class.getConstructors().length);
    assertEquals(0, ChunkedOpener.class.getConstructors().length);
    for (Class<?> c : List.of(KeyHandle.class, KmsKeys.class, CurrentKey.class))
      for (Method m : c.getMethods())
        if (m.getReturnType() == ChunkedSealer.class)
          assertEquals(
              List.of(byte[].class),
              List.of(m.getParameterTypes()),
              "only a file id makes a sealer: " + m);
    assertTrue(
        Modifier.isFinal(ChunkedSealer.class.getModifiers())
            && Modifier.isFinal(ChunkedOpener.class.getModifiers()));
  }

  /**
   * Many threads seal different indices of one sealer at once, and all open; threads racing for one
   * index: exactly one seals it.
   */
  @Test
  void concurrentSealsOfDifferentIndices() throws Exception {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "orders");
    int threads = 8, n = 4000, rounds = 300;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try (ChunkedSealer s = kek.chunkedSealer(FILE)) {
      byte[][] sealed = new byte[n][];
      List<Future<?>> done = new ArrayList<>();
      for (int t = 0; t < threads; t++) {
        int first = t;
        done.add(
            pool.submit(
                () -> {
                  for (int i = first; i < n; i += threads) sealed[i] = s.seal(i, data(64, i));
                }));
      }
      for (Future<?> f : done) f.get();
      for (int r = 0; r < rounds; r++) {
        long index = (long) n + r;
        CyclicBarrier start = new CyclicBarrier(threads);
        AtomicInteger won = new AtomicInteger(), refused = new AtomicInteger();
        List<Future<?>> race = new ArrayList<>();
        for (int t = 0; t < threads; t++)
          race.add(
              pool.submit(
                  () -> {
                    start.await();
                    try {
                      s.seal(index, new byte[8]);
                      won.incrementAndGet();
                    } catch (IllegalStateException e) {
                      refused.incrementAndGet();
                    }
                    return null;
                  }));
        for (Future<?> f : race) f.get();
        assertEquals(1, won.get(), "round " + r + ": one seal of index " + index);
        assertEquals(threads - 1, refused.get());
      }
      try (ChunkedOpener o = kek.chunkedOpener(s.header(), FILE)) {
        List<Future<?>> opens = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
          int first = t;
          opens.add(
              pool.submit(
                  () -> {
                    for (int i = first; i < n; i += threads)
                      assertArrayEquals(data(64, i), o.open(i, sealed[i]));
                  }));
        }
        for (Future<?> f : opens) f.get();
      }
    } finally {
      pool.shutdownNow();
    }
  }

  // ---- Keys: rotation, rewrap, lineage, query, states ----

  /**
   * After the KEK is rotated and the old key deactivated, rewrapHeader gives a header under the new
   * key with the same core, the old chunks open with it (through the new key, the old one and a
   * query), and still after the old key is destroyed; a header under the new key is returned as it
   * is, without a request.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void rewrapHeaderMovesOnlyTheHeader(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle kek = aes(kms, "orders");
    SealedFile a = sealFile(kek, FILE, 100, 4096, 7);
    KeyHandle next = kek.rotate();
    next.deactivatePredecessors();
    assertEquals(KeyState.DEACTIVATED, kek.attributes().state());

    byte[] h1 = next.rewrapHeader(a.header(), FILE);
    assertEquals(next.id(), KmsKeys.chunkedHeaderKeyId(h1));
    assertArrayEquals(Arrays.copyOf(a.header(), CORE), Arrays.copyOf(h1, CORE), "the core is kept");
    assertFalse(Arrays.equals(a.header(), h1));
    int before = server.exchanges();
    assertSame(
        h1, next.rewrapHeader(h1, FILE), "a header under the key already is returned as it is");
    assertEquals(0, server.exchanges() - before);
    assertEquals(
        CryptographicFailureException.Kind.AUTHENTICATION_FAILED,
        failure(
            () -> next.rewrapHeader(a.header(), "other".getBytes(StandardCharsets.UTF_8)),
            "another file id"));

    for (ChunkedOpener o :
        List.of(
            next.chunkedOpener(h1, FILE),
            kek.chunkedOpener(h1, FILE),
            kms.keys().chunkedOpener(KeyQuery.byName("orders"), h1, FILE),
            next.chunkedOpener(a.header(), FILE))) {
      try (o) {
        for (int i = 0; i < 3; i++)
          assertArrayEquals(
              a.plain().get(i),
              i == 2 ? o.openFinal(i, a.chunks().get(i)) : o.open(i, a.chunks().get(i)));
      }
    }
    kek.destroy();
    try (ChunkedOpener o = next.chunkedOpener(h1, FILE)) {
      assertArrayEquals(
          a.plain().get(1),
          o.open(1, a.chunks().get(1)),
          "the old KEK is gone; the chunks are not");
    }
    assertThrows(
        KmsException.class,
        () -> next.chunkedOpener(a.header(), FILE),
        "the old header needs the old key");
  }

  /**
   * Opening follows the key rules of open: through the lineage either way, through a query
   * (BAD_DATA for another key, FIX_REQUEST for a query matching nothing, KeyQuery.all() refused), a
   * foreign key is BAD_DATA, a Compromised key refused unless named with allowingCompromised; a
   * sealer needs an Active key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void openingFollowsTheKeyRulesOfOpen(KmipVersion version) {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle kek = aes(kms, "orders"), other = aes(kms, "other");
    SealedFile old = sealFile(kek, FILE, 30);
    KeyHandle next = kek.rotate();
    SealedFile fresh = sealFile(next, FILE, 40);
    try (ChunkedOpener a = next.chunkedOpener(old.header(), FILE);
        ChunkedOpener b = kek.chunkedOpener(fresh.header(), FILE);
        ChunkedOpener c = kms.keys().chunkedOpener(KeyQuery.byName("orders"), old.header(), FILE)) {
      assertArrayEquals(old.plain().get(0), a.open(0, old.chunks().get(0)));
      assertArrayEquals(fresh.plain().get(0), b.open(0, fresh.chunks().get(0)));
      assertArrayEquals(old.plain().get(0), c.open(0, old.chunks().get(0)));
    }
    KeyMismatchException foreign =
        assertThrows(KeyMismatchException.class, () -> other.chunkedOpener(old.header(), FILE));
    assertEquals(KmsException.Category.BAD_DATA, foreign.category());
    assertEquals("chunkedOpener", foreign.operation());
    KeyMismatchException wrongQuery =
        assertThrows(
            KeyMismatchException.class,
            () -> kms.keys().chunkedOpener(KeyQuery.byName("other"), old.header(), FILE));
    assertEquals(KmsException.Category.BAD_DATA, wrongQuery.category());
    KeyMismatchException nothing =
        assertThrows(
            KeyMismatchException.class,
            () -> kms.keys().chunkedOpener(KeyQuery.byName("nope"), old.header(), FILE));
    assertEquals(KmsException.Category.FIX_REQUEST, nothing.category());
    assertThrows(
        IllegalArgumentException.class,
        () -> kms.keys().chunkedOpener(KeyQuery.all(), old.header(), FILE));
    assertThrows(
        NullPointerException.class, () -> kms.keys().chunkedOpener(null, old.header(), FILE));
    assertThrows(NullPointerException.class, () -> kek.chunkedOpener(null, FILE));
    assertThrows(NullPointerException.class, () -> kek.chunkedOpener(old.header(), null));
    assertThrows(NullPointerException.class, () -> kek.chunkedSealer(null));
    assertThrows(NullPointerException.class, () -> next.rewrapHeader(old.header(), null));

    kek.revoke(RevocationReason.keyCompromise("leaked", Instant.now().minusSeconds(60)));
    StateConflictException refused =
        assertThrows(StateConflictException.class, () -> next.chunkedOpener(old.header(), FILE));
    assertEquals("chunkedOpener", refused.operation());
    assertThrows(
        StateConflictException.class,
        () -> kms.keys().chunkedOpener(KeyQuery.byName("orders"), old.header(), FILE));
    assertThrows(StateConflictException.class, () -> next.rewrapHeader(old.header(), FILE));
    try (ChunkedOpener o =
        kms.keys()
            .handle(KmsKeys.chunkedHeaderKeyId(old.header()))
            .allowingCompromised()
            .chunkedOpener(old.header(), FILE)) {
      assertArrayEquals(old.plain().get(0), o.open(0, old.chunks().get(0)), "forensic recovery");
    }
    StateConflictException notActive =
        assertThrows(StateConflictException.class, () -> kek.chunkedSealer(FILE));
    assertEquals("seal", notActive.operation());
  }

  /**
   * One Encrypt for a sealer, two requests for an opener (Get Attributes, Decrypt), the same for each
   * new opener (nothing cached), none per chunk; a query opener costs what open by query costs, and
   * rewrapHeader what rewrapKey costs (three, and one per rotation crossed).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void requestCounts(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle kek = aes(kms, "orders");
    int before = server.exchanges();
    byte[] header;
    List<byte[]> chunks = new ArrayList<>();
    try (ChunkedSealer s = kek.chunkedSealer(FILE)) {
      assertEquals(1, server.exchanges() - before, "a sealer: one Encrypt");
      assertEquals(List.of(Operation.ENCRYPT), ops(server, server.protocolRequests().size() - 1));
      for (int i = 0; i < 50; i++) chunks.add(s.seal(i, data(1000, i)));
      for (int i = 0; i < 50; i++) s.open(i, chunks.get(i));
      header = s.header();
    }
    assertEquals(1, server.exchanges() - before, "no request per chunk");
    for (int round = 0; round < 2; round++) {
      before = server.exchanges();
      try (ChunkedOpener o = kek.chunkedOpener(header, FILE)) {
        assertEquals(2, server.exchanges() - before, "an opener: Get Attributes and Decrypt");
        for (int i = 0; i < 50; i++) o.open(i, chunks.get(i));
      }
      assertEquals(
          2, server.exchanges() - before, "no request per chunk, nothing cached between openers");
    }
    byte[] record = kek.seal(new byte[10], FILE);
    before = server.exchanges();
    kms.keys().open(KeyQuery.byName("orders"), record, FILE);
    int openByQuery = server.exchanges() - before;
    before = server.exchanges();
    kms.keys().chunkedOpener(KeyQuery.byName("orders"), header, FILE).close();
    assertEquals(
        openByQuery, server.exchanges() - before, "a query opener costs what open by query costs");

    KeyHandle next = kek.rotate();
    next.seal(new byte[1], null);
    Ciphertext wrapped = kek.wrapKey(new SecretKeySpec(new byte[32], "AES"), FILE);
    before = server.exchanges();
    next.rewrapKey(wrapped, FILE);
    int rewrapKey = server.exchanges() - before;
    before = server.exchanges();
    next.rewrapHeader(header, FILE);
    assertEquals(rewrapKey, server.exchanges() - before, "rewrapHeader costs what rewrapKey costs");
    assertEquals(
        4,
        rewrapKey,
        "Get Attributes, Decrypt, Encrypt, and one Get Attributes for the rotation crossed");
  }

  /**
   * Closed: a closed sealer and opener refuse to seal and open (IllegalStateException), keep their
   * header and key identifier, and close again quietly; a Deactivated KEK makes no sealer, and a
   * destroyed one no opener.
   */
  @Test
  void closedSealersAndOpenersAndDestroyedKeys() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server);
    KeyHandle kek = aes(kms, "orders");
    ChunkedSealer s = kek.chunkedSealer(FILE);
    byte[] c0 = s.seal(0, new byte[5]);
    byte[] header = s.header();
    assertFalse(s.isClosed());
    s.close();
    assertTrue(s.isClosed());
    assertTrue(
        assertThrows(IllegalStateException.class, () -> s.seal(1, new byte[5]))
            .getMessage()
            .contains("closed"));
    assertThrows(IllegalStateException.class, () -> s.sealFinal(2, new byte[5]));
    assertThrows(IllegalStateException.class, () -> s.open(0, c0));
    assertArrayEquals(header, s.header());
    assertEquals(kek.id(), s.keyId());
    s.close();
    assertTrue(s.toString().contains("closed"));

    ChunkedOpener o = kek.chunkedOpener(header, FILE);
    assertArrayEquals(new byte[5], o.open(0, c0));
    o.close();
    assertTrue(o.isClosed());
    assertTrue(
        assertThrows(IllegalStateException.class, () -> o.open(0, c0))
            .getMessage()
            .contains("closed"));
    assertThrows(IllegalStateException.class, () -> o.openFinal(0, c0));
    o.close();

    kek.deactivate();
    assertEquals(
        "seal",
        assertThrows(StateConflictException.class, () -> kek.chunkedSealer(FILE)).operation());
    kek.destroy();
    assertThrows(
        KmsException.class, () -> kek.chunkedOpener(header, FILE), "a destroyed KEK opens nothing");
  }

  /**
   * Like seal, chunked sealing needs KMIP 1.4 (the data key is wrapped with AES-GCM) and does not
   * fall back to another wrapping; opening and rewrapping a header are refused there too.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_3"})
  void chunkedSealingNeedsKmip14(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle kek = aes(kms, "orders");
    int from = server.protocolRequests().size();
    UnsupportedException e =
        assertThrows(UnsupportedException.class, () -> kek.chunkedSealer(FILE));
    assertEquals("seal", e.operation());
    assertFalse(ops(server, from).contains(Operation.ENCRYPT), "no Encrypt with another spec");
    Ciphertext wrapped =
        Ciphertext.builder()
            .keyId(kek.id())
            .specName(CipherSpec.aesGcm().name())
            .iv(new byte[12])
            .tag(new byte[16])
            .data(new byte[32])
            .build();
    byte[] w = wrapped.toBytes();
    byte[] header =
        concat(
            new byte[] {'K', 'T', 'R', 1},
            new byte[8],
            new byte[32],
            new byte[] {(byte) (w.length >> 8), (byte) w.length},
            w);
    assertEquals(kek.id(), KmsKeys.chunkedHeaderKeyId(header));
    assertEquals(
        "chunkedOpener",
        assertThrows(UnsupportedException.class, () -> kek.chunkedOpener(header, FILE))
            .operation());
    KeyHandle next = kek.rotate();
    assertEquals(
        "rewrapHeader",
        assertThrows(UnsupportedException.class, () -> next.rewrapHeader(header, FILE))
            .operation());
  }

  // ---- The guide ----

  /** A block store, as in the guide: a header and numbered chunks per file. */
  static final class Store {
    byte[] header;
    final Map<Integer, byte[]> chunks = new HashMap<>();
  }

  /**
   * docs/envelope-encryption.md, "Seal files chunk by chunk", in its order and with its calls:
   * seal the blocks (the last with sealFinal), open one block and prove the count; after a rotation,
   * rewrite the header (the same array the second time), retire the old keys, and the blocks still
   * open under the new header, through the handle and a query; the old header opens nothing.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theGuideFlow(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle kek = aes(kms, "sstables-kek");
    byte[] fileId = "sstable-nb-42-big".getBytes(StandardCharsets.UTF_8);
    Store store = new Store();
    int n = 9;
    int before = server.exchanges();
    try (ChunkedSealer sealer = kek.chunkedSealer(fileId)) {
      store.header = sealer.header();
      for (int i = 0; i < n; i++)
        store.chunks.put(
            i, i == n - 1 ? sealer.sealFinal(i, data(512, i)) : sealer.seal(i, data(512, i)));
    }
    assertEquals(1, server.exchanges() - before, "one request");
    before = server.exchanges();
    try (ChunkedOpener opener = kek.chunkedOpener(store.header, fileId)) {
      assertArrayEquals(data(512, 7), opener.open(7, store.chunks.get(7)));
      assertArrayEquals(data(512, n - 1), opener.openFinal(n - 1, store.chunks.get(n - 1)));
    }
    assertEquals(2, server.exchanges() - before, "two requests, none per chunk");

    KeyHandle current = kek.rotate();
    byte[] old = store.header;
    byte[] header = store.header;
    byte[] moved = current.rewrapHeader(header, fileId);
    if (moved != header) store.header = moved;
    assertNotSame(old, store.header);
    assertSame(store.header, current.rewrapHeader(store.header, fileId), "the job can be repeated");
    assertEquals(
        List.of(kek.id()),
        current.retirePredecessors(RevocationReason.superseded("rotated")).stream()
            .map(KeyHandle::id)
            .toList());
    try (ChunkedOpener opener = current.chunkedOpener(store.header, fileId);
        ChunkedOpener byName =
            kms.keys().chunkedOpener(KeyQuery.byName("sstables-kek"), store.header, fileId)) {
      for (int i = 0; i < n; i++) {
        assertArrayEquals(data(512, i), opener.open(i, store.chunks.get(i)));
        assertArrayEquals(data(512, i), byName.open(i, store.chunks.get(i)));
      }
      assertArrayEquals(data(512, n - 1), opener.openFinal(n - 1, store.chunks.get(n - 1)));
    }
    assertThrows(
        KmsException.class,
        () -> current.chunkedOpener(old, fileId),
        "the retired key opens nothing");
  }

  /** The stored-formats page describes what the code does: the HKDF infos and the limits. */
  @Test
  void theDocumentsDescribeTheFormat() throws Exception {
    String design =
        java.nio.file.Files.readString(java.nio.file.Path.of("../docs/stored-formats.md"));
    assertTrue(design.contains("## Chunked files (KTR)"));
    for (String s :
        List.of(
            "\"keytend-kmip KTR 1 chunk key\"",
            "\"keytend-kmip KTR 1 key commitment\"",
            "2^32",
            "1 MiB",
            "| `ChunkedSealer`, `ChunkedOpener` |")) assertTrue(design.contains(s), s);
    String source =
        java.nio.file.Files.readString(
            java.nio.file.Path.of("src/main/java/dev/keytend/kmip/kms/ChunkedEnvelopes.java"));
    assertTrue(
        source.contains("\"keytend-kmip KTR 1 chunk key\"")
            && source.contains("\"keytend-kmip KTR 1 key commitment\""));
    assertEquals(1L << 32, ChunkedEnvelopes.MAX_CHUNKS);
    assertEquals(1 << 20, ChunkedEnvelopes.MAX_CHUNK);
    assertEquals(CORE, ChunkedEnvelopes.CORE);
  }
}
