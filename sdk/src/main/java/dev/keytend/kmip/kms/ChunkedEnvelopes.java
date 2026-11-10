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

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.BiFunction;
import java.util.function.Function;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Random-access sealed data ({@link CurrentKey#chunkedSealer}, {@link ChunkedSealer}, {@link
 * ChunkedOpener}): chunks sealed and opened one at a time, in any order, with AES-256-GCM under a
 * fresh data key per file that the key-encryption key wraps on the server. The header is stored
 * once per file; the chunks are bare AES-GCM ciphertexts:
 *
 * <pre>
 * header: "KTR" (3 bytes) | version 0x01 | 8-byte nonce prefix (random)
 *   | 32-byte key commitment                                  -- the core ends here (44 bytes)
 *   | u16 wrapped-key length w (1..65535)
 *   | w bytes: the wrapped data key, a {@link Ciphertext} in its stored format (AES-GCM by the KEK,
 *     additional data core || file id)
 * chunk i: AES-GCM(chunk key, nonce = prefix || u32 i, additional data = core || flags || u32 i
 *   || file id) followed by its 16-byte tag; flags 0x01 for the final chunk, else 0x00
 * </pre>
 *
 * The chunk key and the key commitment are HKDF-SHA256-Expand (RFC 5869 §2.3) of the data key with
 * the infos {@code "keytend-kmip KTR 1 chunk key"} and {@code "keytend-kmip KTR 1 key commitment"}. Chunks
 * depend on the data key and the core, never on the wrapped key, so re-wrapping the data key under
 * another key-encryption key rewrites the header only. Nonces are unique because a data key exists
 * only inside the one sealer that made it, which seals each index at most once.
 */
final class ChunkedEnvelopes {
  private static final byte[] MAGIC = {'K', 'T', 'R'};
  private static final byte VERSION = 1;
  static final int PREFIX = 8, COMMITMENT = 32, TAG = 16, KEY_BYTES = 32;

  /** The length of the core: magic, version, nonce prefix and key commitment. */
  static final int CORE = MAGIC.length + 1 + PREFIX + COMMITMENT;

  /** The most plaintext bytes in one chunk. */
  static final int MAX_CHUNK = 1 << 20;

  /** The most chunks under one data key: the index is a u32 in the nonce. */
  static final long MAX_CHUNKS = 1L << 32;

  private static final byte FINAL = 1;
  private static final byte[] CHUNK_KEY =
      "keytend-kmip KTR 1 chunk key".getBytes(StandardCharsets.US_ASCII);
  private static final byte[] KEY_COMMITMENT =
      "keytend-kmip KTR 1 key commitment".getBytes(StandardCharsets.US_ASCII);
  private static final SecureRandom RANDOM = new SecureRandom();

  private ChunkedEnvelopes() {}

  /** A parsed header: its bytes, its core, and the parts of each. */
  record Header(
      byte[] bytes, byte[] core, byte[] prefix, byte[] commitment, Ciphertext wrappedKey) {}

  /**
   * A sealer under a fresh data key, which {@code wrap} (the key-encryption key's wrapKey, one
   * Encrypt request) wraps with the additional data core || file id. The data key is destroyed
   * before this returns; the sealer holds only the chunk key derived from it.
   */
  static ChunkedSealer sealer(
      String kekId, byte[] fileId, BiFunction<DestroyableSecretKey, byte[], Ciphertext> wrap) {
    byte[] file = Objects.requireNonNull(fileId, "fileId").clone();
    byte[] raw = new byte[KEY_BYTES];
    RANDOM.nextBytes(raw);
    DestroyableSecretKey dek = new DestroyableSecretKey(raw, "AES");
    Arrays.fill(raw, (byte) 0);
    try {
      byte[] prefix = new byte[PREFIX];
      RANDOM.nextBytes(prefix);
      byte[] core = core(prefix, expand(dek, KEY_COMMITMENT, "seal", kekId));
      byte[] wrapped = wrap.apply(dek, wrapAad(core, file)).toBytes();
      if (wrapped.length > 0xffff)
        throw new IllegalArgumentException("The key identifier is too long for a chunked header");
      byte[] header =
          ByteBuffer.allocate(CORE + 2 + wrapped.length)
              .put(core)
              .putShort((short) wrapped.length)
              .put(wrapped)
              .array();
      return new ChunkedSealer(
          new Chunks(chunkKey(dek, "seal", kekId), core, prefix, file, kekId), header);
    } finally {
      dek.destroy();
    }
  }

  /**
   * An opener for {@code header}: {@code unwrap} recovers the data key from the wrapped key with
   * the additional data core || file id (with the key and state rules of the caller's entry point:
   * one Get Attributes and one Decrypt), the key commitment is checked, and the data key is
   * destroyed before this returns.
   */
  static ChunkedOpener opener(
      byte[] header, byte[] fileId, BiFunction<Ciphertext, byte[], DestroyableSecretKey> unwrap) {
    Header h = parse(header);
    byte[] file = Objects.requireNonNull(fileId, "fileId").clone();
    String keyId = h.wrappedKey().keyId();
    DestroyableSecretKey dek = unwrap.apply(h.wrappedKey(), wrapAad(h.core(), file));
    try {
      // In the call of the method that opens the header (chunkedOpener): named after it.
      String operation = Kms.named("open");
      requireCommitted(h, dek, operation);
      return new ChunkedOpener(
          new Chunks(chunkKey(dek, operation, keyId), h.core(), h.prefix(), file, keyId));
    } finally {
      dek.destroy();
    }
  }

  /**
   * {@code h} with its data key wrapped again: {@code unwrap} recovers it with the additional data
   * core || file id, the key commitment is checked, and {@code wrap} wraps it with the same
   * additional data. The core, and so every chunk, stays as it was.
   */
  static byte[] rewrapped(
      Header h,
      byte[] fileId,
      Function<byte[], DestroyableSecretKey> unwrap,
      BiFunction<DestroyableSecretKey, byte[], Ciphertext> wrap) {
    byte[] aad = wrapAad(h.core(), fileId);
    DestroyableSecretKey dek = unwrap.apply(aad);
    try {
      requireCommitted(h, dek, Kms.named("rewrapHeader"));
      byte[] wrapped = wrap.apply(dek, aad).toBytes();
      if (wrapped.length > 0xffff)
        throw new IllegalArgumentException("The key identifier is too long for a chunked header");
      return ByteBuffer.allocate(CORE + 2 + wrapped.length)
          .put(h.core())
          .putShort((short) wrapped.length)
          .put(wrapped)
          .array();
    } finally {
      dek.destroy();
    }
  }

  /**
   * Parses a header, checking every length against the input.
   *
   * @throws CryptographicFailureException of kind {@code INVALID_CIPHERTEXT} for anything else
   */
  static Header parse(byte[] header) {
    Objects.requireNonNull(header, "header");
    try {
      ByteBuffer b = ByteBuffer.wrap(header);
      byte[] magic = new byte[MAGIC.length];
      b.get(magic);
      if (!Arrays.equals(magic, MAGIC)) throw invalid("is not a chunked header", null);
      if (b.get() != VERSION) throw invalid("has an unknown format version", null);
      byte[] prefix = new byte[PREFIX];
      b.get(prefix);
      byte[] commitment = new byte[COMMITMENT];
      b.get(commitment);
      int w = Short.toUnsignedInt(b.getShort());
      if (w == 0 || w != b.remaining())
        throw invalid("has a bad wrapped-key length or trailing bytes", null);
      byte[] wrapped = new byte[w];
      b.get(wrapped);
      Ciphertext key;
      try {
        key = Ciphertext.fromBytes(wrapped);
      } catch (CryptographicFailureException e) {
        throw invalid("holds a malformed wrapped key", null);
      }
      return new Header(header.clone(), Arrays.copyOf(header, CORE), prefix, commitment, key);
    } catch (BufferUnderflowException e) {
      throw invalid("is truncated", null);
    }
  }

  private static byte[] core(byte[] prefix, byte[] commitment) {
    return ByteBuffer.allocate(CORE).put(MAGIC).put(VERSION).put(prefix).put(commitment).array();
  }

  /** The additional data the key-encryption key binds to the wrapped data key: core || file id. */
  private static byte[] wrapAad(byte[] core, byte[] fileId) {
    return ByteBuffer.allocate(core.length + fileId.length).put(core).put(fileId).array();
  }

  private static void requireCommitted(Header h, DestroyableSecretKey dek, String operation) {
    byte[] commitment = expand(dek, KEY_COMMITMENT, operation, h.wrappedKey().keyId());
    if (!MessageDigest.isEqual(commitment, h.commitment()))
      throw new CryptographicFailureException(
          operation
              + ": the chunked header's key commitment does not match its data key (the header was changed)",
          null,
          operation,
          h.wrappedKey().keyId(),
          null,
          null,
          CryptographicFailureException.Kind.AUTHENTICATION_FAILED);
  }

  private static DestroyableSecretKey chunkKey(
      DestroyableSecretKey dek, String operation, String keyId) {
    byte[] raw = expand(dek, CHUNK_KEY, operation, keyId);
    try {
      return new DestroyableSecretKey(raw, "AES");
    } finally {
      Arrays.fill(raw, (byte) 0);
    }
  }

  /** HKDF-SHA256-Expand(PRK = the data key, info, 32 bytes): HMAC-SHA256(dek, info || 0x01). */
  private static byte[] expand(
      DestroyableSecretKey dek, byte[] info, String operation, String keyId) {
    byte[] raw = dek.getEncoded();
    DestroyableSecretKey prk = new DestroyableSecretKey(raw, "HmacSHA256");
    Arrays.fill(raw, (byte) 0);
    try {
      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(prk);
      mac.update(info);
      mac.update((byte) 1);
      return mac.doFinal();
    } catch (GeneralSecurityException e) {
      throw failure("HMAC-SHA256 failed: " + e.getClass().getSimpleName(), operation, keyId);
    } finally {
      prk.destroy();
    }
  }

  static CryptographicFailureException invalid(String why, String keyId) {
    return new CryptographicFailureException(
        "open: the chunked header " + why,
        null,
        Kms.named("open"),
        keyId,
        null,
        null,
        CryptographicFailureException.Kind.INVALID_CIPHERTEXT);
  }

  private static CryptographicFailureException failure(String why, String operation, String keyId) {
    return new CryptographicFailureException(
        operation + ": " + why,
        null,
        operation,
        keyId,
        null,
        null,
        CryptographicFailureException.Kind.OTHER);
  }

  static void checkIndex(long index) {
    if (index < 0 || index >= MAX_CHUNKS)
      throw new IllegalArgumentException("A chunk index is 0 to 2^32 - 1, not " + index);
  }

  /**
   * The chunk key of one file and what every chunk binds: thread-safe (a cipher per call), until
   * {@link #destroy()}.
   */
  static final class Chunks {
    private final DestroyableSecretKey key;
    private final byte[] core, prefix, fileId;
    final String keyId;

    Chunks(DestroyableSecretKey key, byte[] core, byte[] prefix, byte[] fileId, String keyId) {
      this.key = key;
      this.core = core;
      this.prefix = prefix;
      this.fileId = fileId;
      this.keyId = keyId;
    }

    /** Seals chunk {@code index}; the caller has made sure the index is sealed only this once. */
    byte[] seal(long index, boolean last, byte[] plaintext) {
      byte[] sealed = crypt(Cipher.ENCRYPT_MODE, index, last, plaintext, "seal");
      if (sealed == null) throw failure("local AES-GCM failed", "seal", keyId);
      return sealed;
    }

    /**
     * Opens chunk {@code index}: as the final chunk when {@code last} is true, as another chunk when
     * false, and as either when null (another chunk first, so only the final chunk costs two tries).
     */
    byte[] open(long index, Boolean last, byte[] chunk) {
      checkIndex(index);
      Objects.requireNonNull(chunk, "chunk");
      if (chunk.length < TAG)
        throw invalidChunk(index, "is shorter than a tag (" + chunk.length + " bytes)");
      if (chunk.length > MAX_CHUNK + TAG)
        throw invalidChunk(index, "is longer than a chunk may be (" + chunk.length + " bytes)");
      if (last == null) {
        byte[] plain = crypt(Cipher.DECRYPT_MODE, index, false, chunk, "open");
        if (plain == null) plain = crypt(Cipher.DECRYPT_MODE, index, true, chunk, "open");
        if (plain != null) return plain;
      } else {
        byte[] plain = crypt(Cipher.DECRYPT_MODE, index, last, chunk, "open");
        if (plain != null) return plain;
      }
      throw new CryptographicFailureException(
          "open: chunk "
              + index
              + " did not authenticate"
              + (Boolean.TRUE.equals(last) ? " as the final chunk" : "")
              + " (it was changed or cut, it is another chunk or another file's, or the file id differs"
              + (Boolean.TRUE.equals(last)
                  ? "; or it is not the final chunk: the file was cut or extended"
                  : "")
              + "); discard it",
          null,
          "open",
          keyId,
          null,
          null,
          CryptographicFailureException.Kind.AUTHENTICATION_FAILED);
    }

    /** Encrypts, or decrypts and returns null when the tag does not verify. */
    private byte[] crypt(int mode, long index, boolean last, byte[] input, String operation) {
      byte[] nonce = ByteBuffer.allocate(PREFIX + 4).put(prefix).putInt((int) index).array();
      byte[] aad =
          ByteBuffer.allocate(CORE + 1 + 4 + fileId.length)
              .put(core)
              .put(last ? FINAL : 0)
              .putInt((int) index)
              .put(fileId)
              .array();
      Cipher cipher;
      try {
        cipher = Cipher.getInstance("AES/GCM/NoPadding");
      } catch (GeneralSecurityException e) {
        throw failure(
            "AES-GCM is not available: " + e.getClass().getSimpleName(), operation, keyId);
      }
      try {
        // JCA reads the key here; once closed, the key is destroyed and this fails.
        cipher.init(mode, key, new GCMParameterSpec(TAG * 8, nonce));
      } catch (GeneralSecurityException | IllegalStateException e) {
        if (key.isDestroyed()) throw closed(operation);
        throw failure("local AES-GCM failed: " + e.getClass().getSimpleName(), operation, keyId);
      }
      try {
        cipher.updateAAD(aad);
        return cipher.doFinal(input);
      } catch (AEADBadTagException e) {
        return null;
      } catch (GeneralSecurityException e) {
        throw failure("local AES-GCM failed: " + e.getClass().getSimpleName(), operation, keyId);
      }
    }

    private CryptographicFailureException invalidChunk(long index, String why) {
      return new CryptographicFailureException(
          "open: chunk " + index + " " + why,
          null,
          "open",
          keyId,
          null,
          null,
          CryptographicFailureException.Kind.INVALID_CIPHERTEXT);
    }

    static IllegalStateException closed(String operation) {
      return new IllegalStateException(operation + ": the chunked sealer or opener is closed");
    }

    boolean isDestroyed() {
      return key.isDestroyed();
    }

    void destroy() {
      key.destroy();
    }
  }

  /**
   * The indices a sealer has sealed, one bit each in pages of 4096, and its final chunk: a chunk
   * index is claimed once, before it is sealed, and never released. Not thread-safe: the sealer
   * holds its lock.
   */
  static final class Claims {
    private static final int PAGE_BITS = 12;
    private final Map<Long, long[]> pages = new HashMap<>();
    private long highest = -1, finalIndex = -1;

    /**
     * Claims {@code index}, as the final chunk when {@code last}.
     *
     * @throws IllegalStateException when the index was sealed already, is past the final chunk, or
     *     is to be the final chunk while a later index is sealed already (so a second final chunk
     *     is refused as one of these)
     */
    void claim(long index, boolean last) {
      long[] page = pages.get(index >>> PAGE_BITS);
      int bit = (int) (index & ((1 << PAGE_BITS) - 1));
      if (page != null && (page[bit >>> 6] & (1L << bit)) != 0)
        throw new IllegalStateException(
            "seal: chunk "
                + index
                + " was sealed already by this sealer: each index is sealed once per data key"
                + " (its nonce is fixed), so seal changed data into a new file with a new sealer");
      if (finalIndex >= 0 && index > finalIndex)
        throw new IllegalStateException(
            "seal: chunk " + index + " is past the final chunk, " + finalIndex);
      if (last && highest > index)
        throw new IllegalStateException(
            "seal: chunk "
                + index
                + " cannot be the final chunk: chunk "
                + highest
                + " is sealed already");
      if (page == null) pages.put(index >>> PAGE_BITS, page = new long[(1 << PAGE_BITS) / 64]);
      page[bit >>> 6] |= 1L << bit;
      highest = Math.max(highest, index);
      if (last) finalIndex = index;
    }
  }
}
