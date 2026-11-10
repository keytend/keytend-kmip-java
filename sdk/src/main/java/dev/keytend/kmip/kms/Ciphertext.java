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

import java.io.ByteArrayOutputStream;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * The output of a server-side encryption: which key and {@link CipherSpec} produced it, the
 * encrypted data, the IV or nonce, and the authentication tag for AEAD modes. Get one from {@link
 * KeyHandle#encrypt(CipherSpec, byte[], byte[])}, or read a stored one with {@link
 * #fromBytes(byte[])}.
 *
 * <pre>{@code
 * byte[] stored = kek.encrypt(CipherSpec.aesGcm(), orderJson, orderId).toBytes();
 * byte[] opened = kek.decrypt(Ciphertext.fromBytes(stored), orderId);
 * }</pre>
 *
 * <p>{@code kek} is a {@link KeyHandle}. {@code orderJson} and {@code orderId} are {@code byte[]}.
 * The stored key identifier lets data be decrypted after the key is rotated, while the old key
 * exists.
 *
 * <p>A stored ciphertext cannot choose its key or a weaker mode. Decryption takes only
 * tamper-evident specs from it, and {@link KmsKeys#decrypt(KeyQuery, Ciphertext, byte[])} checks
 * the named key against the caller's {@link KeyQuery}. For AEAD specs the SDK binds the {@linkplain
 * #header() header} (format, key identifier and spec name) into the additional data, so the
 * server sees {@code header || aad}. Changing the stored key identifier or spec name therefore
 * makes decryption fail like any other modification.
 *
 * <p>{@link #toBytes()} is the stable storage format, KTC 1 (see <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/stored-formats.md#server-side-ciphertexts-ktc">Stored
 * formats</a>). A {@code Ciphertext} is immutable and thread-safe. Arrays are copied in and out.
 *
 * @since 0.10.0
 */
public final class Ciphertext {
  private static final byte[] MAGIC = {'K', 'T', 'C'};
  private static final byte VERSION = 1;
  private final String keyId, spec;
  private final byte[] data, iv, tag;

  /** See {@link Builder#build()}. */
  Ciphertext(String keyId, String spec, byte[] data, byte[] iv, byte[] tag) {
    this.keyId = Objects.requireNonNull(keyId, "keyId");
    this.spec = Objects.requireNonNull(spec, "spec");
    this.data = Objects.requireNonNull(data, "data").clone();
    this.iv = iv == null ? new byte[0] : iv.clone();
    this.tag = tag == null ? new byte[0] : tag.clone();
    int idLength = utf8Length(keyId);
    if (idLength == 0 || idLength > 0xffff)
      throw new IllegalArgumentException("The key identifier must be 1 to 65535 UTF-8 bytes");
    if (spec.isEmpty() || spec.length() > 0xff || !spec.chars().allMatch(c -> c > 0x20 && c < 0x7f))
      throw new IllegalArgumentException(
          "The spec name must be 1 to 255 printable ASCII characters");
    if (this.iv.length > 0xff || this.tag.length > 0xff)
      throw new IllegalArgumentException("IVs and tags are at most 255 bytes");
  }

  /**
   * A builder for a ciphertext from its parts, for applications that store them separately:
   *
   * <pre>{@code
   * Ciphertext c = Ciphertext.builder().keyId(row.keyId()).specName(row.specName())
   *     .iv(row.iv()).tag(row.tag()).data(row.data()).build();
   * }</pre>
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /** Builds a {@link Ciphertext} from its parts. Not thread-safe. */
  public static final class Builder {
    private String keyId, spec;
    private byte[] iv, tag, data;

    private Builder() {}

    /**
     * The identifier of the key that encrypted (required).
     *
     * @param value the key identifier, 1 to 65535 UTF-8 bytes
     * @return this builder
     */
    public Builder keyId(String value) {
      this.keyId = Objects.requireNonNull(value, "keyId");
      return this;
    }

    /**
     * The {@link CipherSpec#name()} used (required), as {@link Ciphertext#specName()} returns it.
     *
     * @param value the spec name, 1 to 255 printable ASCII characters
     * @return this builder
     */
    public Builder specName(String value) {
      this.spec = Objects.requireNonNull(value, "spec");
      return this;
    }

    /**
     * The IV, counter block or nonce; omit or pass an empty array when the mode has none.
     *
     * @param value the IV (copied), or null or empty for none
     * @return this builder
     */
    public Builder iv(byte[] value) {
      this.iv = value == null ? null : value.clone();
      return this;
    }

    /**
     * The authentication tag; omit or pass an empty array for modes without one.
     *
     * @param value the tag (copied), or null or empty for none
     * @return this builder
     */
    public Builder tag(byte[] value) {
      this.tag = value == null ? null : value.clone();
      return this;
    }

    /**
     * The encrypted data (required; may be empty).
     *
     * @param value the encrypted data (copied)
     * @return this builder
     */
    public Builder data(byte[] value) {
      this.data = Objects.requireNonNull(value, "data").clone();
      return this;
    }

    /**
     * The ciphertext. Nothing is checked against a key here; decryption checks the key, the spec
     * and the lengths.
     *
     * @return the ciphertext
     * @throws NullPointerException when the key identifier, spec or data is missing
     * @throws IllegalArgumentException when a part does not fit the format (an empty key identifier
     *     or one over 65535 UTF-8 bytes, a spec name that is not 1 to 255 printable ASCII
     *     characters, an IV or tag over 255 bytes)
     */
    public Ciphertext build() {
      return new Ciphertext(
          Objects.requireNonNull(keyId, "keyId"),
          Objects.requireNonNull(spec, "spec"),
          Objects.requireNonNull(data, "data"),
          iv,
          tag);
    }
  }

  /**
   * The identifier of the key that encrypted this.
   *
   * @return the key identifier
   */
  public String keyId() {
    return keyId;
  }

  /**
   * The {@link CipherSpec#name()} used, as stored. A name rather than a {@link CipherSpec}: a
   * stored ciphertext can name a spec that this SDK version does not know or does not take from
   * ciphertexts, and decryption reports that.
   *
   * @return the spec name
   */
  public String specName() {
    return spec;
  }

  /**
   * The encrypted data, without the IV and the tag.
   *
   * @return a new copy of the data
   */
  public byte[] data() {
    return data.clone();
  }

  /**
   * The IV, counter block or nonce; empty if the mode has none.
   *
   * @return a new copy of the IV; empty if the mode has none
   */
  public byte[] iv() {
    return iv.clone();
  }

  /**
   * The authentication tag; empty for non-AEAD modes.
   *
   * @return a new copy of the tag; empty for non-AEAD modes
   */
  public byte[] tag() {
    return tag.clone();
  }

  /**
   * The header bound into the AAD of AEAD specs: the first bytes of {@link #toBytes()}, up to and
   * including the spec name.
   *
   * @return a new array holding the header
   */
  public byte[] header() {
    return header(keyId, spec);
  }

  static byte[] header(String keyId, String spec) {
    byte[] id = keyId.getBytes(StandardCharsets.UTF_8),
        name = spec.getBytes(StandardCharsets.US_ASCII);
    return ByteBuffer.allocate(MAGIC.length + 1 + 2 + id.length + 1 + name.length)
        .put(MAGIC)
        .put(VERSION)
        .putShort((short) id.length)
        .put(id)
        .put((byte) name.length)
        .put(name)
        .array();
  }

  /** {@code header || aad}: what the server authenticates for an AEAD spec. */
  static byte[] boundAad(String keyId, String spec, byte[] aad) {
    byte[] header = header(keyId, spec);
    if (aad == null || aad.length == 0) return header;
    ByteArrayOutputStream out = new ByteArrayOutputStream(header.length + aad.length);
    out.writeBytes(header);
    out.writeBytes(aad);
    return out.toByteArray();
  }

  /**
   * The storage format described above.
   *
   * @return a new array in the KTC format
   */
  public byte[] toBytes() {
    byte[] header = header();
    return ByteBuffer.allocate(header.length + 1 + iv.length + 1 + tag.length + 4 + data.length)
        .put(header)
        .put((byte) iv.length)
        .put(iv)
        .put((byte) tag.length)
        .put(tag)
        .putInt(data.length)
        .put(data)
        .array();
  }

  /**
   * Parses {@link #toBytes()} output. Nothing is checked against a key here; decryption checks the
   * key, the spec and the lengths.
   *
   * @param bytes the stored form; not kept
   * @return the ciphertext
   * @throws CryptographicFailureException of kind {@link
   *     CryptographicFailureException.Kind#INVALID_CIPHERTEXT} for bytes that are not this format
   *     (wrong magic or version, bad lengths, trailing bytes, an invalid key identifier or spec)
   */
  public static Ciphertext fromBytes(byte[] bytes) {
    Objects.requireNonNull(bytes, "bytes");
    try {
      ByteBuffer b = ByteBuffer.wrap(bytes);
      byte[] magic = new byte[MAGIC.length];
      b.get(magic);
      if (!Arrays.equals(magic, MAGIC))
        throw invalid("is not in the keytend-kmip ciphertext format", null);
      if (b.get() != VERSION) throw invalid("has an unknown format version", null);
      String id = utf8(field(b, Short.toUnsignedInt(b.getShort())));
      String name = new String(field(b, Byte.toUnsignedInt(b.get())), StandardCharsets.US_ASCII);
      byte[] iv = field(b, Byte.toUnsignedInt(b.get()));
      byte[] tag = field(b, Byte.toUnsignedInt(b.get()));
      long dataLength = Integer.toUnsignedLong(b.getInt());
      if (dataLength != b.remaining())
        throw invalid("has a bad data length or trailing bytes", null);
      byte[] data = field(b, (int) dataLength);
      return new Ciphertext(id, name, data, iv, tag);
    } catch (BufferUnderflowException e) {
      throw invalid("is truncated", null);
    } catch (IllegalArgumentException e) {
      throw invalid("has an invalid field: " + e.getMessage(), null);
    }
  }

  private static byte[] field(ByteBuffer b, int length) {
    if (length > b.remaining()) throw new BufferUnderflowException();
    byte[] out = new byte[length];
    b.get(out);
    return out;
  }

  /** The UTF-8 length of a key identifier; unpaired surrogates are refused, not replaced by '?'. */
  private static int utf8Length(String keyId) {
    try {
      return StandardCharsets.UTF_8
          .newEncoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .encode(java.nio.CharBuffer.wrap(keyId))
          .remaining();
    } catch (CharacterCodingException e) {
      throw new IllegalArgumentException(
          "The key identifier is not valid Unicode (an unpaired surrogate)");
    }
  }

  private static String utf8(byte[] bytes) {
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(bytes))
          .toString();
    } catch (CharacterCodingException e) {
      throw new IllegalArgumentException("the key identifier is not UTF-8");
    }
  }

  static CryptographicFailureException invalid(String why, String keyId) {
    return new CryptographicFailureException(
        "The ciphertext " + why,
        null,
        Kms.named("decrypt"),
        keyId,
        null,
        null,
        CryptographicFailureException.Kind.INVALID_CIPHERTEXT);
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof Ciphertext c
        && c.keyId.equals(keyId)
        && c.spec.equals(spec)
        && Arrays.equals(c.data, data)
        && Arrays.equals(c.iv, iv)
        && Arrays.equals(c.tag, tag);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        keyId, spec, Arrays.hashCode(data), Arrays.hashCode(iv), Arrays.hashCode(tag));
  }

  @Override
  public String toString() {
    return "Ciphertext[" + spec + ", key " + keyId + ", " + data.length + " bytes]";
  }
}
