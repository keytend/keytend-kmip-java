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

package dev.keytend.kmip.client;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.model.*;
import java.util.*;

/**
 * A typed Cryptographic Parameters structure, for the cryptographic requests in {@link
 * CryptoRequests} and for key attributes. Fields are emitted in the specification's table order.
 *
 * <p>A field that the client's version does not define is rejected when the request is sent, with
 * {@link IllegalArgumentException}. Mask Generator, Mask Generator Hashing Algorithm, Salt Length,
 * P Source and Trailer Field (RSA-PSS and OAEP details) require KMIP 1.4. The IV, tag and counter
 * lengths and Random IV require 1.2.
 *
 * <pre>{@code
 * CryptoParameters gcm = CryptoParameters.builder()
 *     .algorithm(Enums.CryptographicAlgorithm.AES)
 *     .mode(Enums.BlockCipherMode.GCM).tagLength(16).build();
 * CryptoParameters pss = CryptoParameters.rsaPss(Enums.HashingAlgorithm.SHA_256, 32);
 * }</pre>
 *
 * @since 0.10.0
 */
public final class CryptoParameters {
  private final Ttlv structure;

  private CryptoParameters(Ttlv structure) {
    this.structure = structure;
  }

  /**
   * A builder with no fields set.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * AES-GCM with a 96-bit IV and a 16-byte tag (KMIP 1.2 and later, for the IV and tag lengths).
   *
   * @return the parameters
   */
  public static CryptoParameters aesGcm() {
    return builder()
        .algorithm(Enums.CryptographicAlgorithm.AES)
        .mode(Enums.BlockCipherMode.GCM)
        .ivLength(96)
        .tagLength(16)
        .build();
  }

  /**
   * RSA-PSS with MGF1 over {@code hash} (KMIP 1.4 and later).
   *
   * @param hash the message hash, also used by MGF1
   * @param saltLength the salt length in bytes
   * @return the parameters
   */
  public static CryptoParameters rsaPss(Enums.HashingAlgorithm hash, int saltLength) {
    return builder()
        .algorithm(Enums.CryptographicAlgorithm.RSA)
        .padding(Enums.PaddingMethod.PSS)
        .hashing(hash)
        .maskGenerator(Enums.MaskGenerator.MGF1)
        .maskGeneratorHashing(hash)
        .saltLength(saltLength)
        .build();
  }

  /**
   * RSA-OAEP with {@code hash} and MGF1 over the same hash (KMIP 1.4+, which added the Mask
   * Generator fields; without them a server applies MGF1 with SHA-1). Before 1.4 build the
   * structure without the mask fields, and only with MGF1-SHA-1 in mind.
   *
   * @param hash the OAEP hash, also used by MGF1
   * @return the parameters
   */
  public static CryptoParameters rsaOaep(Enums.HashingAlgorithm hash) {
    return builder()
        .algorithm(Enums.CryptographicAlgorithm.RSA)
        .padding(Enums.PaddingMethod.OAEP)
        .hashing(hash)
        .maskGenerator(Enums.MaskGenerator.MGF1)
        .maskGeneratorHashing(hash)
        .build();
  }

  /**
   * The Cryptographic Parameters structure.
   *
   * @return the structure
   */
  public Ttlv toTtlv() {
    return structure;
  }

  /**
   * Field setters, one per field of the structure. Each field may be set once: a second call
   * throws {@link IllegalStateException}. A field left unset is not sent.
   */
  public static final class Builder {
    private final Map<Tag, Ttlv> fields = new LinkedHashMap<>();
    private final List<Ttlv> extra = new ArrayList<>();

    /** A builder with no fields set, as {@link CryptoParameters#builder()} returns. */
    public Builder() {}

    private Builder set(Ttlv field) {
      Tag tag = field.standardTag().orElseThrow();
      if (fields.putIfAbsent(tag, field) != null)
        throw new IllegalStateException(tag.wireName() + " already set");
      return this;
    }

    /**
     * Cryptographic Algorithm.
     *
     * @param value the value
     * @return this builder
     */
    public Builder algorithm(Enums.CryptographicAlgorithm value) {
      return set(enumeration(CRYPTOGRAPHIC_ALGORITHM, value));
    }

    /**
     * Block Cipher Mode.
     *
     * @param value the value
     * @return this builder
     */
    public Builder mode(Enums.BlockCipherMode value) {
      return set(enumeration(BLOCK_CIPHER_MODE, value));
    }

    /**
     * Padding Method.
     *
     * @param value the value
     * @return this builder
     */
    public Builder padding(Enums.PaddingMethod value) {
      return set(enumeration(PADDING_METHOD, value));
    }

    /**
     * Hashing Algorithm.
     *
     * @param value the value
     * @return this builder
     */
    public Builder hashing(Enums.HashingAlgorithm value) {
      return set(enumeration(HASHING_ALGORITHM, value));
    }

    /**
     * Key Role Type.
     *
     * @param value the value
     * @return this builder
     */
    public Builder keyRole(Enums.KeyRoleType value) {
      return set(enumeration(KEY_ROLE_TYPE, value));
    }

    /**
     * Digital Signature Algorithm.
     *
     * @param value the value
     * @return this builder
     */
    public Builder digitalSignature(Enums.DigitalSignatureAlgorithm value) {
      return set(enumeration(DIGITAL_SIGNATURE_ALGORITHM, value));
    }

    /**
     * Random IV: whether the server generates the IV (KMIP 1.2 and later).
     *
     * @param value the value
     * @return this builder
     */
    public Builder randomIv(boolean value) {
      return set(bool(RANDOM_IV, value));
    }

    /**
     * IV Length, in bits (KMIP 1.2 and later).
     *
     * @param bits the value
     * @return this builder
     */
    public Builder ivLength(int bits) {
      return set(integer(IV_LENGTH, bits));
    }

    /**
     * Tag Length of authenticated encryption, in bytes (KMIP 1.2 and later).
     *
     * @param bytes the tag length
     * @return this builder
     */
    public Builder tagLength(int bytes) {
      return set(integer(TAG_LENGTH, bytes));
    }

    /**
     * Fixed Field Length of a GCM IV, in bits (KMIP 1.2 and later).
     *
     * @param bits the value
     * @return this builder
     */
    public Builder fixedFieldLength(int bits) {
      return set(integer(FIXED_FIELD_LENGTH, bits));
    }

    /**
     * Invocation Field Length of a GCM IV, in bits (KMIP 1.2 and later).
     *
     * @param bits the value
     * @return this builder
     */
    public Builder invocationFieldLength(int bits) {
      return set(integer(INVOCATION_FIELD_LENGTH, bits));
    }

    /**
     * Counter Length, in bits (KMIP 1.2 and later).
     *
     * @param bits the value
     * @return this builder
     */
    public Builder counterLength(int bits) {
      return set(integer(COUNTER_LENGTH, bits));
    }

    /**
     * Initial Counter Value (KMIP 1.2 and later).
     *
     * @param value the value
     * @return this builder
     */
    public Builder initialCounterValue(int value) {
      return set(integer(INITIAL_COUNTER_VALUE, value));
    }

    /**
     * Salt Length of RSA-PSS, in bytes (KMIP 1.4 and later).
     *
     * @param bytes the salt length
     * @return this builder
     */
    public Builder saltLength(int bytes) {
      return set(integer(SALT_LENGTH, bytes));
    }

    /**
     * Mask Generator (KMIP 1.4 and later).
     *
     * @param value the value
     * @return this builder
     */
    public Builder maskGenerator(Enums.MaskGenerator value) {
      return set(enumeration(MASK_GENERATOR, value));
    }

    /**
     * Mask Generator Hashing Algorithm (KMIP 1.4 and later).
     *
     * @param value the value
     * @return this builder
     */
    public Builder maskGeneratorHashing(Enums.HashingAlgorithm value) {
      return set(enumeration(MASK_GENERATOR_HASHING_ALGORITHM, value));
    }

    /**
     * P Source, the OAEP label (KMIP 1.4 and later).
     *
     * @param value the value
     * @return this builder
     */
    public Builder pSource(byte[] value) {
      return set(bytes(P_SOURCE, value));
    }

    /**
     * Trailer Field of RSA-PSS (KMIP 1.4 and later).
     *
     * @param value the value
     * @return this builder
     */
    public Builder trailerField(int value) {
      return set(integer(TRAILER_FIELD, value));
    }

    /**
     * Any other field, for example a vendor extension. A standard tag counts as that field, and
     * may be set once; other fields are appended in the order given.
     *
     * @param value the field
     * @return this builder
     */
    public Builder field(Ttlv value) {
      if (value.standardTag().isPresent()) return set(value);
      extra.add(value);
      return this;
    }

    /**
     * Builds the parameters.
     *
     * @return the parameters
     */
    public CryptoParameters build() {
      List<Ttlv> all = new ArrayList<>(fields.values());
      all.addAll(extra);
      return new CryptoParameters(
          Structures.structure(CRYPTOGRAPHIC_PARAMETERS, all.toArray(Ttlv[]::new)));
    }
  }
}
