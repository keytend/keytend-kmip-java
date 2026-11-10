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
 * A NIST elliptic curve for EC key pairs.
 *
 * @since 0.10.0
 */
public enum Curve {
  /** NIST P-256 (secp256r1), 256 bits. */
  P_256(Enums.RecommendedCurve.P_256, 256),
  /** NIST P-384 (secp384r1), 384 bits. */
  P_384(Enums.RecommendedCurve.P_384, 384),
  /** NIST P-521 (secp521r1), 521 bits. */
  P_521(Enums.RecommendedCurve.P_521, 521);

  private final Enums.RecommendedCurve wire;
  private final int bits;

  Curve(Enums.RecommendedCurve wire, int bits) {
    this.wire = wire;
    this.bits = bits;
  }

  /**
   * The field size in bits.
   *
   * @return the field size: 256, 384 or 521
   */
  public int bits() {
    return bits;
  }

  /**
   * The KMIP Recommended Curve (protocol layer).
   *
   * @return the KMIP value
   */
  public Enums.RecommendedCurve protocolValue() {
    return wire;
  }

  static Curve ofBits(int bits) {
    for (Curve c : values()) if (c.bits == bits) return c;
    throw new IllegalArgumentException("EC keys are 256, 384 or 521 bits");
  }
}
