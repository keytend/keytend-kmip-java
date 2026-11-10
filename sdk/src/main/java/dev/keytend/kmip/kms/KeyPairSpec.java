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
 * The kind of asymmetric key pair to create on the server. Immutable.
 *
 * @since 0.10.0
 */
public final class KeyPairSpec {
  private final Algorithm algorithm;
  private final int bits;
  private final Curve curve;

  private KeyPairSpec(Algorithm algorithm, int bits, Curve curve) {
    this.algorithm = algorithm;
    this.bits = bits;
    this.curve = curve;
  }

  /**
   * RSA with a {@code bits}-bit modulus (2048 or more recommended).
   *
   * @param bits the modulus size in bits, at least 1024
   * @return the spec
   * @throws IllegalArgumentException when {@code bits} is below 1024
   */
  public static KeyPairSpec rsa(int bits) {
    if (bits < 1024) throw new IllegalArgumentException("RSA keys need at least 1024 bits");
    return new KeyPairSpec(Algorithm.RSA, bits, null);
  }

  /**
   * An EC key pair on {@code curve}. It is created as algorithm EC on KMIP 1.2 and later, and as
   * ECDSA on 1.1.
   *
   * @param curve the curve
   * @return the spec
   */
  public static KeyPairSpec ec(Curve curve) {
    Objects.requireNonNull(curve, "curve");
    return new KeyPairSpec(Algorithm.EC, curve.bits(), curve);
  }

  /**
   * An EC key pair on the NIST curve of {@code bits} bits (256, 384 or 521).
   *
   * @param bits the field size: 256, 384 or 521
   * @return the spec
   * @throws IllegalArgumentException for any other size
   */
  public static KeyPairSpec ec(int bits) {
    return ec(Curve.ofBits(bits));
  }

  /**
   * The algorithm: {@link Algorithm#RSA} or {@link Algorithm#EC}.
   *
   * @return the algorithm
   */
  public Algorithm algorithm() {
    return algorithm;
  }

  /**
   * The RSA modulus or EC field size.
   *
   * @return the size in bits
   */
  public int bits() {
    return bits;
  }

  /**
   * The curve, for EC.
   *
   * @return the curve; empty for RSA
   */
  public java.util.Optional<Curve> ecCurve() {
    return java.util.Optional.ofNullable(curve);
  }

  Curve curve() {
    return curve;
  }

  /**
   * What a retrieved key of this pair must be.
   *
   * @return the expectation: this spec's algorithm and size
   */
  public Expect expect() {
    return Expect.of(algorithm, bits);
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof KeyPairSpec k
        && k.algorithm == algorithm
        && k.bits == bits
        && k.curve == curve;
  }

  @Override
  public int hashCode() {
    return Objects.hash(algorithm, bits, curve);
  }

  @Override
  public String toString() {
    return curve == null ? algorithm + "-" + bits : "EC-" + curve;
  }
}
