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

import java.util.Objects;

/**
 * What a retrieved or unwrapped key must be. Before building a JCA key, retrieval checks the
 * object's identity and type, that it is not wrapped, and the algorithm and size given here; a
 * mismatch is a {@link KeyMismatchException}. A Destroyed key is always refused with a {@link
 * StateConflictException}, and so is a Compromised one unless the handle is {@link
 * KeyHandle#allowingCompromised()}. Immutable.
 *
 * @since 0.10.0
 */
public final class Expect {
  private final Algorithm algorithm;
  private final int bits;

  private Expect(Algorithm algorithm, int bits) {
    this.algorithm = algorithm;
    this.bits = bits;
  }

  /**
   * A key of {@code algorithm} and {@code bits} (the AES key length, RSA modulus or EC field size;
   * 0 accepts any size, but an AES key's must still be 128, 192 or 256 bits).
   *
   * @param algorithm the algorithm, not {@link Algorithm#OTHER}
   * @param bits the size in bits, 0 for any
   * @return the expectation
   * @throws IllegalArgumentException for {@link Algorithm#OTHER} or a negative size
   */
  public static Expect of(Algorithm algorithm, int bits) {
    Objects.requireNonNull(algorithm, "algorithm");
    if (algorithm == Algorithm.OTHER)
      throw new IllegalArgumentException("Name the expected algorithm");
    if (bits < 0) throw new IllegalArgumentException("Negative key size");
    return new Expect(algorithm, bits);
  }

  /**
   * An AES key of any AES size: 128, 192 or 256 bits. The material's size must be one of these, and
   * equal the Cryptographic Length the server declares with it; a key of another size, or whose
   * declared length differs, is a {@link KeyMismatchException}. For reading keys of a lineage whose
   * size changed (a key of 128 bits rotated to 256, say), where {@link #aes(int)} would refuse the
   * older ones; {@code javax.crypto.Cipher}s take the size from the key.
   *
   * @return the expectation; never null
   * @since 0.10.0
   */
  public static Expect aes() {
    return new Expect(Algorithm.AES, 0);
  }

  /**
   * An AES key of 128, 192 or 256 bits.
   *
   * @param bits 128, 192 or 256
   * @return the expectation
   * @throws IllegalArgumentException for any other size
   */
  public static Expect aes(int bits) {
    if (bits != 128 && bits != 192 && bits != 256)
      throw new IllegalArgumentException("AES keys have 128, 192 or 256 bits");
    return new Expect(Algorithm.AES, bits);
  }

  /**
   * An RSA key with a {@code bits}-bit modulus.
   *
   * @param bits the modulus size in bits, 0 for any
   * @return the expectation
   */
  public static Expect rsa(int bits) {
    return of(Algorithm.RSA, bits);
  }

  /**
   * An elliptic-curve key on a {@code bits}-bit curve (256, 384 or 521). Servers record EC keys as
   * EC, ECDSA, ECDH or ECMQV; any of these is accepted.
   *
   * @param bits 256, 384 or 521
   * @return the expectation
   * @throws IllegalArgumentException for any other size
   */
  public static Expect ec(int bits) {
    return of(Algorithm.EC, Curve.ofBits(bits).bits());
  }

  /**
   * An elliptic-curve key on {@code curve}.
   *
   * @param curve the curve
   * @return the expectation
   */
  public static Expect ec(Curve curve) {
    return of(Algorithm.EC, curve.bits());
  }

  /**
   * An HMAC key over {@code hash}, of any size.
   *
   * @param hash the HMAC's hash
   * @return the expectation
   */
  public static Expect hmac(Hash hash) {
    return of(Algorithm.hmac(Objects.requireNonNull(hash, "hash")), 0);
  }

  /**
   * The expected algorithm.
   *
   * @return the algorithm
   */
  public Algorithm algorithm() {
    return algorithm;
  }

  /**
   * The expected size in bits; 0 accepts any size (any AES size, for AES).
   *
   * @return the size in bits, 0 for any
   */
  public int bits() {
    return bits;
  }

  boolean ecFamily() {
    return algorithm.ellipticCurve();
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof Expect e && e.algorithm == algorithm && e.bits == bits;
  }

  @Override
  public int hashCode() {
    return Objects.hash(algorithm, bits);
  }

  @Override
  public String toString() {
    return "Expect[" + algorithm + (bits == 0 ? "" : "-" + bits) + "]";
  }
}
