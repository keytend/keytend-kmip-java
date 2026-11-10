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

import dev.keytend.kmip.client.CryptoParameters;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.ProtocolVersion;
import dev.keytend.kmip.model.Tag;
import java.util.Objects;
import java.util.function.BiFunction;

/**
 * How the server encrypts: algorithm, mode and padding. Get one from a static factory such as
 * {@link #aesGcm()}, and pass it to {@link KeyHandle#encrypt(CipherSpec, byte[], byte[])}.
 *
 * <pre>{@code
 * Ciphertext ciphertext = kek.encrypt(CipherSpec.aesGcm(), orderJson, orderId);
 * }</pre>
 *
 * <p>{@code kek} is a {@link KeyHandle}. {@code orderJson} and {@code orderId} are {@code byte[]}.
 *
 * <p><b>Choose a tamper-evident spec.</b> {@link #aesGcm()} (KMIP 1.4+) is the choice for data,
 * and for wrapping keys with {@link CurrentKey#wrapKey(javax.crypto.SecretKey, byte[])}. {@link
 * #keyWrap()} (AES key wrap) also wraps keys. Both detect a modified ciphertext, and only these
 * two are taken from a stored {@link Ciphertext} ({@link KeyHandle#decrypt(Ciphertext, byte[])}).
 * The caller must name every other spec again when decrypting ({@link
 * KeyHandle#decrypt(CipherSpec, Ciphertext, byte[])}), so a stored ciphertext cannot downgrade
 * itself:
 *
 * <ul>
 *   <li>{@link #rsaOaep(Hash)} detects modification, but anyone with the public key can make a
 *       valid ciphertext of their own, so it says nothing about who encrypted.
 *   <li>{@link #cbc()} and {@link #ctr()} detect nothing (malleable).
 *   <li>{@link #fromProtocol} and {@link #aeadFromProtocol} are protocol-defined escape hatches.
 * </ul>
 *
 * <p>For GCM, CBC and CTR the SDK draws a fresh random IV or nonce from {@link
 * java.security.SecureRandom} for every request, so a nonce is never reused by mistake. Callers
 * cannot choose it. A {@code CipherSpec} is immutable and thread-safe. See <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/envelope-encryption.md#encrypt-on-the-server">Encrypt
 * on the server</a>.
 *
 * @since 0.10.0
 */
public final class CipherSpec {
  /** The suffix of an RSA-OAEP spec name whose label binds the header and additional data. */
  static final String BOUND = "-BOUND";

  private final String name;

  /** The parameters at a version, given the OAEP label (null when none is bound). */
  private final BiFunction<ProtocolVersion, byte[], CryptoParameters> parameters;

  private final int ivLength;
  private final boolean aead;
  private final int tagLength;
  private final boolean tamperEvident;
  private final boolean custom;
  private final boolean oaep;
  private final ProtocolVersion since;

  private CipherSpec(
      String name,
      BiFunction<ProtocolVersion, byte[], CryptoParameters> parameters,
      int ivLength,
      boolean aead,
      int tagLength,
      boolean tamperEvident,
      boolean custom,
      ProtocolVersion since) {
    this(name, parameters, ivLength, aead, tagLength, tamperEvident, custom, false, since);
  }

  private CipherSpec(
      String name,
      BiFunction<ProtocolVersion, byte[], CryptoParameters> parameters,
      int ivLength,
      boolean aead,
      int tagLength,
      boolean tamperEvident,
      boolean custom,
      boolean oaep,
      ProtocolVersion since) {
    this.oaep = oaep;
    this.name = name;
    this.parameters = parameters;
    this.ivLength = ivLength;
    this.aead = aead;
    this.tagLength = tagLength;
    this.tamperEvident = tamperEvident;
    this.custom = custom;
    this.since = since;
  }

  static CipherSpec gcm(int tagLength) {
    if (tagLength < 12 || tagLength > 16)
      throw new IllegalArgumentException("GCM tags are 12 to 16 bytes");
    return new CipherSpec(
        "AES-GCM-" + tagLength,
        (v, label) ->
            CryptoParameters.builder()
                .algorithm(Enums.CryptographicAlgorithm.AES)
                .mode(Enums.BlockCipherMode.GCM)
                .ivLength(96)
                .tagLength(tagLength)
                .build(),
        12,
        true,
        tagLength,
        true,
        false,
        ProtocolVersion.V1_4);
  }

  /**
   * AES-GCM with a 16-byte tag and a 12-byte nonce that the SDK draws from {@link
   * java.security.SecureRandom} for each encryption: authenticated encryption, which also protects
   * additional data. Needs KMIP 1.4 or later, the default minimum version of {@link KmsConfig}.
   *
   * @return the spec, named {@code AES-GCM-16}
   */
  public static CipherSpec aesGcm() {
    return gcm(16);
  }

  /**
   * AES-GCM with a {@code tagLength}-byte tag (12 to 16); see {@link #aesGcm()}.
   *
   * @param tagLength the tag length in bytes, 12 to 16
   * @return the spec
   * @throws IllegalArgumentException when {@code tagLength} is out of range
   */
  public static CipherSpec aesGcm(int tagLength) {
    return gcm(tagLength);
  }

  /**
   * AES-CBC with PKCS#5 padding. Not tamper-evident: prefer {@link #aesGcm()}.
   *
   * @return the spec
   */
  public static CipherSpec cbc() {
    return new CipherSpec(
        "AES-CBC",
        (v, label) ->
            CryptoParameters.builder()
                .algorithm(Enums.CryptographicAlgorithm.AES)
                .mode(Enums.BlockCipherMode.CBC)
                .padding(Enums.PaddingMethod.PKCS5)
                .build(),
        16,
        false,
        0,
        false,
        false,
        ProtocolVersion.V1_1);
  }

  /**
   * AES-CTR; the IV is the initial 16-byte counter block. Not tamper-evident: prefer {@link
   * #aesGcm()}.
   *
   * @return the spec
   */
  public static CipherSpec ctr() {
    return new CipherSpec(
        "AES-CTR",
        (v, label) -> {
          CryptoParameters.Builder b =
              CryptoParameters.builder()
                  .algorithm(Enums.CryptographicAlgorithm.AES)
                  .mode(Enums.BlockCipherMode.CTR);
          if (v.atLeast(Tag.IV_LENGTH.since())) b.ivLength(128);
          return b.build();
        },
        16,
        false,
        0,
        false,
        false,
        ProtocolVersion.V1_1);
  }

  /**
   * RSA-OAEP with {@code hash} and MGF1 over the same hash; encrypt with the public key, decrypt
   * with the private one. Needs KMIP 1.4, which added the MGF1 hash field; see {@link
   * #rsaOaep(Hash, Hash)}.
   *
   * @param hash the hash, for the label and MGF1
   * @return the spec
   */
  public static CipherSpec rsaOaep(Hash hash) {
    return rsaOaep(hash, hash);
  }

  /**
   * RSA-OAEP with {@code hash} for the label and MGF1 over {@code mgf1Hash}. The name stored in a
   * {@link Ciphertext} states both, for example {@code RSA-OAEP-SHA-256-MGF1-SHA-256}.
   *
   * <p><b>What it protects.</b> From KMIP 1.4 the SDK sends the ciphertext header and the
   * additional data as the OAEP label (P Source), and the stored name ends in {@code -BOUND}. A
   * ciphertext then decrypts only with the same key identifier, spec and additional data. But
   * anyone with the public key can make a valid ciphertext for any label they know, so RSA-OAEP
   * never shows <em>who</em> encrypted. It is therefore never taken from a stored ciphertext:
   * decrypting needs the expected spec ({@link KeyHandle#decrypt(CipherSpec, Ciphertext,
   * byte[])}). Where the origin of a wrapped key matters, wrap it with {@link #aesGcm()} or {@link
   * #keyWrap()}, or sign it. The binding relies on the server applying P Source, which the SDK
   * cannot check.
   *
   * <p>Before KMIP 1.4 neither the MGF1 hash nor a label can be stated. There only {@code
   * mgf1Hash} SHA-1 is accepted, relying on the server's PKCS #1 default, and additional data is
   * refused. Other choices fail with {@link UnsupportedException} before anything is sent.
   *
   * @param hash the hash for the label
   * @param mgf1Hash the hash for MGF1
   * @return the spec
   */
  public static CipherSpec rsaOaep(Hash hash, Hash mgf1Hash) {
    Objects.requireNonNull(hash, "hash");
    Objects.requireNonNull(mgf1Hash, "mgf1Hash");
    return new CipherSpec(
        "RSA-OAEP-" + hash.jcaName() + "-MGF1-" + mgf1Hash.jcaName(),
        (v, label) -> {
          CryptoParameters.Builder b =
              CryptoParameters.builder()
                  .algorithm(Enums.CryptographicAlgorithm.RSA)
                  .padding(Enums.PaddingMethod.OAEP)
                  .hashing(hash.protocolValue());
          if (v.atLeast(Tag.MASK_GENERATOR_HASHING_ALGORITHM.since()))
            b.maskGenerator(Enums.MaskGenerator.MGF1)
                .maskGeneratorHashing(mgf1Hash.protocolValue());
          else if (mgf1Hash != Hash.SHA_1)
            throw new UnsupportedException(
                "RSA-OAEP with MGF1-"
                    + mgf1Hash.jcaName()
                    + " needs KMIP 1.4; this connection uses "
                    + v,
                null,
                null,
                null,
                null,
                null);
          if (label != null) {
            if (!v.atLeast(Tag.P_SOURCE.since()))
              throw new UnsupportedException(
                  "a bound RSA-OAEP label (P Source) needs KMIP 1.4; this connection uses " + v,
                  null,
                  null,
                  null,
                  null,
                  null);
            b.pSource(label);
          }
          return b.build();
        },
        0,
        false,
        0,
        true,
        false,
        true,
        ProtocolVersion.V1_1);
  }

  /**
   * AES key wrap (RFC 3394, KMIP NIST Key Wrap), for wrapping keys; no IV is sent.
   *
   * @return the spec
   */
  public static CipherSpec keyWrap() {
    return new CipherSpec(
        "AES-KW",
        (v, label) ->
            CryptoParameters.builder()
                .algorithm(Enums.CryptographicAlgorithm.AES)
                .mode(Enums.BlockCipherMode.NISTKEY_WRAP)
                .build(),
        0,
        false,
        0,
        true,
        false,
        ProtocolVersion.V1_1);
  }

  /**
   * Protocol-layer escape hatch: any other Cryptographic Parameters for a mode that is not
   * authenticated encryption, stored in a {@link Ciphertext} as {@code custom:name}. No IV is
   * generated, and a ciphertext made with it must be decrypted with {@link
   * KeyHandle#decrypt(CipherSpec, Ciphertext, byte[])}.
   *
   * @param name the name stored after {@code custom:}
   * @param parameters the Cryptographic Parameters to send
   * @return the spec
   */
  public static CipherSpec fromProtocol(String name, CryptoParameters parameters) {
    return custom(name, parameters, false);
  }

  /**
   * Protocol-layer escape hatch for an authenticated-encryption mode, as {@link #fromProtocol}. The
   * parameters must state the Tag Length, which is used to split a tag the server appends to the
   * ciphertext. Additional data is bound with the ciphertext header, as for {@link #aesGcm()}.
   *
   * @param name the name stored after {@code custom:}
   * @param parameters the Cryptographic Parameters to send, with a Tag Length
   * @return the spec
   * @throws IllegalArgumentException when the parameters have no Tag Length, or one outside 1..16
   */
  public static CipherSpec aeadFromProtocol(String name, CryptoParameters parameters) {
    return custom(name, parameters, true);
  }

  private static CipherSpec custom(String name, CryptoParameters parameters, boolean aead) {
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(parameters, "parameters");
    int tag = 0;
    if (aead) {
      tag =
          parameters
              .toTtlv()
              .child(Tag.TAG_LENGTH)
              .map(t -> t.intValue())
              .orElseThrow(
                  () -> new IllegalArgumentException("An AEAD custom spec needs a Tag Length"));
      if (tag < 1 || tag > 16) throw new IllegalArgumentException("Invalid Tag Length " + tag);
    }
    return new CipherSpec(
        "custom:" + name,
        (v, label) -> parameters,
        0,
        aead,
        tag,
        false,
        true,
        aead ? ProtocolVersion.V1_4 : ProtocolVersion.V1_1);
  }

  /**
   * The built-in spec a {@link Ciphertext} names.
   *
   * @throws CryptographicFailureException for a name that is not a built-in spec
   */
  static CipherSpec forName(String name) {
    if (name.startsWith("AES-GCM-")) {
      String digits = name.substring(8);
      if (digits.matches("1[2-6]")) return gcm(Integer.parseInt(digits));
    }
    switch (name) {
      case "AES-CBC":
        return cbc();
      case "AES-CTR":
        return ctr();
      case "AES-KW":
        return keyWrap();
      default:
        break;
    }
    String base = name.endsWith(BOUND) ? name.substring(0, name.length() - BOUND.length()) : name;
    for (Hash h : Hash.values())
      for (Hash m : Hash.values())
        if (base.equals("RSA-OAEP-" + h.jcaName() + "-MGF1-" + m.jcaName())) return rsaOaep(h, m);
    throw Ciphertext.invalid("names an unknown cipher spec; pass its CipherSpec to decrypt", null);
  }

  /**
   * True for AEAD modes, which take additional data and produce a tag.
   *
   * @return whether this is an AEAD mode
   */
  public boolean authenticated() {
    return aead;
  }

  /**
   * True when decryption detects a modified ciphertext (GCM, AES key wrap, RSA-OAEP). Of these,
   * only GCM and AES key wrap are taken from a stored {@link Ciphertext}: anyone with an RSA public
   * key can make a valid RSA-OAEP ciphertext (see {@link #rsaOaep(Hash, Hash)}).
   *
   * @return whether decryption detects a modified ciphertext
   */
  public boolean tamperEvident() {
    return tamperEvident;
  }

  /**
   * The name stored in a {@link Ciphertext} made with this spec. RSA-OAEP ciphertexts made at KMIP
   * 1.4 or later store it with the suffix {@code -BOUND} (see {@link #rsaOaep(Hash, Hash)}).
   *
   * @return the name
   */
  public String name() {
    return name;
  }

  /** Whether a stored ciphertext may name this spec itself: the symmetric tamper-evident ones. */
  boolean selectableByCiphertext() {
    return tamperEvident && !oaep;
  }

  boolean rsaOaep() {
    return oaep;
  }

  /**
   * The output length for {@code input} bytes where the mode fixes it, else -1: GCM (data without
   * the tag) and CTR keep the length; AES key wrap adds 8 bytes when wrapping and removes them when
   * unwrapping. CBC, RSA-OAEP and protocol-defined specs are not checked.
   */
  int outputLength(int input, boolean encrypt) {
    if (custom) return -1;
    if (aead || name.equals("AES-CTR")) return input;
    // RFC 3394 wraps at least 16 bytes into at least 24: a shorter input has no valid output.
    if (name.equals("AES-KW")) return encrypt ? input + 8 : input >= 24 ? input - 8 : -1;
    return -1;
  }

  /** Whether this is AES key wrap, which servers also allow with the Wrap/Unwrap Key usages. */
  boolean keyWrapMode() {
    if (name.equals("AES-KW")) return true;
    if (!custom) return false;
    int mode =
        parameters
            .apply(ProtocolVersion.V2_1, null)
            .toTtlv()
            .child(Tag.BLOCK_CIPHER_MODE)
            .map(t -> t.intValue())
            .orElse(-1);
    return mode == Enums.BlockCipherMode.NISTKEY_WRAP.code()
        || mode == Enums.BlockCipherMode.AESKEY_WRAP_PADDING.code();
  }

  /** Whether additional data (and the header) are authenticated at {@code version}. */
  boolean bindsAad(ProtocolVersion version) {
    return aead || (oaep && version.atLeast(Tag.P_SOURCE.since()));
  }

  /** The name to store for a ciphertext made at {@code version}. */
  String storedName(ProtocolVersion version) {
    return oaep && bindsAad(version) ? name + BOUND : name;
  }

  /** Whether {@code stored} names this spec (for RSA-OAEP, with or without a bound label). */
  boolean accepts(String stored) {
    return stored.equals(name) || (oaep && stored.equals(name + BOUND));
  }

  /** The tag length in bytes (0 when not AEAD). */
  int tagLength() {
    return tagLength;
  }

  /** The IV the SDK generates, in bytes (0 for none). */
  int ivLength() {
    return ivLength;
  }

  boolean custom() {
    return custom;
  }

  /** The parameters to send at {@code version}. */
  CryptoParameters parameters(ProtocolVersion version, String operation, String keyId) {
    return parameters(version, operation, keyId, null);
  }

  /** The parameters to send at {@code version}, with an RSA-OAEP label to bind (or null). */
  CryptoParameters parameters(
      ProtocolVersion version, String operation, String keyId, byte[] label) {
    if (!version.atLeast(since))
      throw new UnsupportedException(
          operation + ": " + name + " needs KMIP " + since + "; this connection uses " + version,
          null,
          operation,
          keyId,
          null,
          null);
    try {
      return parameters.apply(version, label);
    } catch (UnsupportedException e) {
      throw new UnsupportedException(
          operation + ": " + e.getMessage(), null, operation, keyId, null, null);
    }
  }

  @Override
  public boolean equals(Object o) {
    return o == this || (o instanceof CipherSpec c && !custom && !c.custom && c.name.equals(name));
  }

  @Override
  public int hashCode() {
    return name.hashCode();
  }

  @Override
  public String toString() {
    return name;
  }
}
