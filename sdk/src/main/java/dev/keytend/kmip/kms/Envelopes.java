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
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.function.Function;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * Sealed data ({@link CurrentKey#seal}, {@link CurrentKey#open}): local AES-256-GCM under a fresh data
 * key that the key-encryption key wraps on the server, in one versioned container:
 *
 * <pre>
 * "KTE" (3 bytes) | version 0x01 | u16 wrapped-key length w (1..65535)
 *   | w bytes: the wrapped data key, a {@link Ciphertext} in its stored format
 *   | u8 nonce length (12) | nonce                         -- the prefix ends here
 *   | u32 data length d (at least 16) | d bytes: AES-GCM ciphertext followed by the 16-byte tag
 * </pre>
 *
 * Lengths are unsigned big-endian and nothing may follow the data. The wrapped data key binds the
 * caller's additional data (and its own header) on the server; the local encryption binds the
 * whole prefix, wrapped key included, followed by the additional data. So neither the data key nor
 * the data can be moved to another record or container.
 */
final class Envelopes {
  private static final byte[] MAGIC = {'K', 'T', 'E'};
  private static final byte VERSION = 1;
  private static final int NONCE = 12, TAG = 16, KEY_BITS = 256;
  private static final SecureRandom RANDOM = new SecureRandom();

  private Envelopes() {}

  /** A parsed container. */
  record Sealed(byte[] prefix, Ciphertext wrappedKey, byte[] nonce, byte[] data) {}

  static byte[] seal(KeyHandle kek, byte[] plaintext, byte[] aad) {
    Objects.requireNonNull(plaintext, "plaintext");
    try (DataKey dek = kek.generateDataKey(KEY_BITS, aad)) {
      byte[] wrapped = dek.wrapped().toBytes();
      if (wrapped.length > 0xffff)
        throw new IllegalArgumentException("The key identifier is too long for a sealed container");
      byte[] nonce = new byte[NONCE];
      RANDOM.nextBytes(nonce);
      byte[] prefix =
          ByteBuffer.allocate(MAGIC.length + 1 + 2 + wrapped.length + 1 + NONCE)
              .put(MAGIC)
              .put(VERSION)
              .putShort((short) wrapped.length)
              .put(wrapped)
              .put((byte) NONCE)
              .put(nonce)
              .array();
      if (plaintext.length > Integer.MAX_VALUE - prefix.length - 4 - TAG)
        throw new IllegalArgumentException("The plaintext is too large to seal in one container");
      byte[] data = local(Cipher.ENCRYPT_MODE, dek.key(), prefix, nonce, aad, plaintext, kek.id());
      return ByteBuffer.allocate(prefix.length + 4 + data.length)
          .put(prefix)
          .putInt(data.length)
          .put(data)
          .array();
    }
  }

  /**
   * Opens a container: {@code unwrap} recovers the data key from the wrapped key (with the key and
   * state rules of the caller's entry point), and the data is decrypted locally.
   */
  static byte[] open(byte[] sealed, byte[] aad, Function<Ciphertext, DestroyableSecretKey> unwrap) {
    Sealed s = parse(sealed);
    try (DestroyableSecretKey dek = unwrap.apply(s.wrappedKey())) {
      return local(
          Cipher.DECRYPT_MODE, dek, s.prefix(), s.nonce(), aad, s.data(), s.wrappedKey().keyId());
    }
  }

  /**
   * Parses a container, checking every length against the input.
   *
   * @throws CryptographicFailureException of kind {@code INVALID_CIPHERTEXT} for anything else
   */
  static Sealed parse(byte[] sealed) {
    Objects.requireNonNull(sealed, "sealed");
    try {
      ByteBuffer b = ByteBuffer.wrap(sealed);
      byte[] magic = new byte[MAGIC.length];
      b.get(magic);
      if (!Arrays.equals(magic, MAGIC)) throw invalid("is not a sealed container");
      if (b.get() != VERSION) throw invalid("has an unknown format version");
      int w = Short.toUnsignedInt(b.getShort());
      if (w == 0 || w > b.remaining()) throw invalid("has a bad wrapped-key length");
      byte[] wrapped = new byte[w];
      b.get(wrapped);
      if (Byte.toUnsignedInt(b.get()) != NONCE) throw invalid("has a bad nonce length");
      byte[] nonce = new byte[NONCE];
      b.get(nonce);
      int prefixLength = b.position();
      long d = Integer.toUnsignedLong(b.getInt());
      if (d < TAG || d != b.remaining()) throw invalid("has a bad data length or trailing bytes");
      byte[] data = new byte[(int) d];
      b.get(data);
      Ciphertext key;
      try {
        key = Ciphertext.fromBytes(wrapped);
      } catch (CryptographicFailureException e) {
        throw invalid("holds a malformed wrapped key");
      }
      return new Sealed(Arrays.copyOf(sealed, prefixLength), key, nonce, data);
    } catch (BufferUnderflowException e) {
      throw invalid("is truncated");
    }
  }

  private static byte[] local(
      int mode,
      SecretKey key,
      byte[] prefix,
      byte[] nonce,
      byte[] aad,
      byte[] input,
      String keyId) {
    String operation = mode == Cipher.ENCRYPT_MODE ? "seal" : "open";
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      cipher.init(mode, key, new GCMParameterSpec(TAG * 8, nonce));
      cipher.updateAAD(prefix);
      if (aad != null) cipher.updateAAD(aad);
      return cipher.doFinal(input);
    } catch (AEADBadTagException e) {
      throw new CryptographicFailureException(
          "open: the sealed data did not authenticate (it, its container or the additional data changed)",
          null,
          operation,
          keyId,
          null,
          null,
          CryptographicFailureException.Kind.AUTHENTICATION_FAILED);
    } catch (GeneralSecurityException e) {
      throw new CryptographicFailureException(
          operation + ": local AES-GCM failed: " + e.getClass().getSimpleName(),
          null,
          operation,
          keyId,
          null,
          null,
          CryptographicFailureException.Kind.OTHER);
    }
  }

  private static CryptographicFailureException invalid(String why) {
    return new CryptographicFailureException(
        "The sealed data " + why,
        null,
        "open",
        null,
        null,
        null,
        CryptographicFailureException.Kind.INVALID_CIPHERTEXT);
  }
}
