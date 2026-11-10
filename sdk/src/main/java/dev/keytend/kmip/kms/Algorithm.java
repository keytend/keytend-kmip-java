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

import dev.keytend.kmip.model.Enums;

/**
 * A key's cryptographic algorithm. {@link #OTHER} stands for any algorithm this API does not name;
 * {@link KeyAttributes#rawAlgorithm()} keeps the KMIP code.
 *
 * @since 0.10.0
 */
public enum Algorithm {
  /** AES (Advanced Encryption Standard); JCA name {@code "AES"}. */
  AES(Enums.CryptographicAlgorithm.AES, "AES"),
  /** Triple DES (TDEA); JCA name {@code "DESede"}. */
  TRIPLE_DES(Enums.CryptographicAlgorithm.N_3_DES, "DESede"),
  /** ChaCha20; JCA name {@code "ChaCha20"}. */
  CHACHA20(Enums.CryptographicAlgorithm.CHA_CHA20, "ChaCha20"),
  /** RSA; JCA name {@code "RSA"}. */
  RSA(Enums.CryptographicAlgorithm.RSA, "RSA"),
  /** DSA; JCA name {@code "DSA"}. */
  DSA(Enums.CryptographicAlgorithm.DSA, "DSA"),
  /** Elliptic curve (KMIP 1.2+); servers may also record EC keys as ECDSA, ECDH or ECMQV. */
  EC(Enums.CryptographicAlgorithm.EC, "EC"),
  /** ECDSA, as some servers record an elliptic-curve key; JCA name {@code "EC"}. */
  ECDSA(Enums.CryptographicAlgorithm.ECDSA, "EC"),
  /** ECDH, as some servers record an elliptic-curve key; JCA name {@code "EC"}. */
  ECDH(Enums.CryptographicAlgorithm.ECDH, "EC"),
  /** ECMQV, as some servers record an elliptic-curve key; JCA name {@code "EC"}. */
  ECMQV(Enums.CryptographicAlgorithm.ECMQV, "EC"),
  /** HMAC with SHA-1; JCA name {@code "HmacSHA1"}. */
  HMAC_SHA1(Enums.CryptographicAlgorithm.HMAC_SHA1, "HmacSHA1"),
  /** HMAC with SHA-224; JCA name {@code "HmacSHA224"}. */
  HMAC_SHA224(Enums.CryptographicAlgorithm.HMAC_SHA224, "HmacSHA224"),
  /** HMAC with SHA-256; JCA name {@code "HmacSHA256"}. */
  HMAC_SHA256(Enums.CryptographicAlgorithm.HMAC_SHA256, "HmacSHA256"),
  /** HMAC with SHA-384; JCA name {@code "HmacSHA384"}. */
  HMAC_SHA384(Enums.CryptographicAlgorithm.HMAC_SHA384, "HmacSHA384"),
  /** HMAC with SHA-512; JCA name {@code "HmacSHA512"}. */
  HMAC_SHA512(Enums.CryptographicAlgorithm.HMAC_SHA512, "HmacSHA512"),
  /** HMAC with SHA3-256; JCA name {@code "HmacSHA3-256"}. */
  HMAC_SHA3_256(Enums.CryptographicAlgorithm.HMAC_SHA3_256, "HmacSHA3-256"),
  /** HMAC with SHA3-384; JCA name {@code "HmacSHA3-384"}. */
  HMAC_SHA3_384(Enums.CryptographicAlgorithm.HMAC_SHA3_384, "HmacSHA3-384"),
  /** HMAC with SHA3-512; JCA name {@code "HmacSHA3-512"}. */
  HMAC_SHA3_512(Enums.CryptographicAlgorithm.HMAC_SHA3_512, "HmacSHA3-512"),
  /** Any other or vendor algorithm (not accepted as input). */
  OTHER(null, null);

  private final Enums.CryptographicAlgorithm wire;
  private final String jcaName;

  Algorithm(Enums.CryptographicAlgorithm wire, String jcaName) {
    this.wire = wire;
    this.jcaName = jcaName;
  }

  /**
   * The KMIP Cryptographic Algorithm (protocol layer), or null for {@link #OTHER}.
   *
   * @return the KMIP value, or null for {@link #OTHER}
   */
  public Enums.CryptographicAlgorithm protocolValue() {
    return wire;
  }

  /**
   * The JCA key algorithm name, for example {@code "AES"} or {@code "HmacSHA256"}.
   *
   * @return the JCA name, or null for {@link #OTHER}
   */
  public String jcaName() {
    return jcaName;
  }

  /**
   * True for EC, ECDSA, ECDH and ECMQV.
   *
   * @return whether this is an elliptic-curve algorithm
   */
  public boolean ellipticCurve() {
    return this == EC || this == ECDSA || this == ECDH || this == ECMQV;
  }

  boolean symmetric() {
    return this == AES || this == TRIPLE_DES || this == CHACHA20 || name().startsWith("HMAC_");
  }

  /** The HMAC algorithm over {@code hash}. */
  static Algorithm hmac(Hash hash) {
    return switch (hash) {
      case SHA_1 -> HMAC_SHA1;
      case SHA_224 -> HMAC_SHA224;
      case SHA_256 -> HMAC_SHA256;
      case SHA_384 -> HMAC_SHA384;
      case SHA_512 -> HMAC_SHA512;
      case SHA3_256 -> HMAC_SHA3_256;
      case SHA3_384 -> HMAC_SHA3_384;
      case SHA3_512 -> HMAC_SHA3_512;
    };
  }

  static Algorithm of(int code) {
    for (Algorithm a : values()) if (a.wire != null && a.wire.code() == code) return a;
    return OTHER;
  }

  /** The algorithm for a JCA secret-key algorithm name. */
  static Algorithm fromJca(String name) {
    for (Algorithm a : values())
      if (a.jcaName != null && a.symmetric() && a.jcaName.equalsIgnoreCase(name)) return a;
    throw new IllegalArgumentException("Unsupported secret key algorithm " + name);
  }

  Enums.CryptographicAlgorithm requireWire() {
    if (wire == null) throw new IllegalArgumentException("OTHER is not an algorithm to request");
    return wire;
  }
}
