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

package dev.keytend.kmip.model;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import java.math.BigInteger;
import java.util.*;

/**
 * All transparent key structures, emitted in the field order of the Key Format Type's table (KMIP
 * 1.4 §2.1.7, 2.1 §2.1.7). Missing optional private CRT components can be omitted.
 *
 * @since 0.10.0
 */
public final class KeyMaterials {
  private KeyMaterials() {}

  public static Ttlv symmetric(byte[] key) {
    return material(Enums.KeyFormatType.TRANSPARENT_SYMMETRIC_KEY, bytes(KEY, key));
  }

  public static Ttlv rsaPublic(BigInteger modulus, BigInteger exponent) {
    return material(
        Enums.KeyFormatType.TRANSPARENT_RSA_PUBLIC_KEY,
        bigInteger(MODULUS, modulus),
        bigInteger(PUBLIC_EXPONENT, exponent));
  }

  /**
   * Optional components (PublicExponent, P, Q, PrimeExponentP, PrimeExponentQ, CRTCoefficient) may
   * be supplied in any order; they are emitted as Modulus, PrivateExponent, PublicExponent, P, Q,
   * PrimeExponentP, PrimeExponentQ, CRTCoefficient.
   */
  public static Ttlv rsaPrivate(
      BigInteger modulus, BigInteger privateExponent, Ttlv... optionalCrt) {
    List<Ttlv> fields =
        new ArrayList<>(
            List.of(bigInteger(MODULUS, modulus), bigInteger(PRIVATE_EXPONENT, privateExponent)));
    fields.addAll(List.of(optionalCrt));
    return Structures.keyMaterial(Enums.KeyFormatType.TRANSPARENT_RSA_PRIVATE_KEY, fields);
  }

  public static Ttlv dsaPublic(BigInteger p, BigInteger q, BigInteger g, BigInteger y) {
    return material(
        Enums.KeyFormatType.TRANSPARENT_DSA_PUBLIC_KEY,
        bigInteger(P, p),
        bigInteger(Q, q),
        bigInteger(G, g),
        bigInteger(Y, y));
  }

  public static Ttlv dsaPrivate(BigInteger p, BigInteger q, BigInteger g, BigInteger x) {
    return material(
        Enums.KeyFormatType.TRANSPARENT_DSA_PRIVATE_KEY,
        bigInteger(P, p),
        bigInteger(Q, q),
        bigInteger(G, g),
        bigInteger(X, x));
  }

  /** Emits P, Q, G, J, Y; optional Q and J may be supplied in any order. */
  public static Ttlv dhPublic(BigInteger p, BigInteger g, BigInteger y, Ttlv... optionalQOrJ) {
    List<Ttlv> fields =
        new ArrayList<>(List.of(bigInteger(P, p), bigInteger(G, g), bigInteger(Y, y)));
    fields.addAll(List.of(optionalQOrJ));
    return Structures.keyMaterial(Enums.KeyFormatType.TRANSPARENT_DH_PUBLIC_KEY, fields);
  }

  /** KMIP 1.4 Table 20: P, Q (optional), G, J (optional), Y. Null q or j is omitted. */
  public static Ttlv dhPublic(
      BigInteger p, BigInteger q, BigInteger g, BigInteger j, BigInteger y) {
    return dh(Enums.KeyFormatType.TRANSPARENT_DH_PUBLIC_KEY, p, q, g, j, bigInteger(Y, y));
  }

  /** Emits P, Q, G, J, X; optional Q and J may be supplied in any order. */
  public static Ttlv dhPrivate(BigInteger p, BigInteger g, BigInteger x, Ttlv... optionalQOrJ) {
    List<Ttlv> fields =
        new ArrayList<>(List.of(bigInteger(P, p), bigInteger(G, g), bigInteger(X, x)));
    fields.addAll(List.of(optionalQOrJ));
    return Structures.keyMaterial(Enums.KeyFormatType.TRANSPARENT_DH_PRIVATE_KEY, fields);
  }

  /** KMIP 1.4 Table 19: P, Q (optional), G, J (optional), X. Null q or j is omitted. */
  public static Ttlv dhPrivate(
      BigInteger p, BigInteger q, BigInteger g, BigInteger j, BigInteger x) {
    return dh(Enums.KeyFormatType.TRANSPARENT_DH_PRIVATE_KEY, p, q, g, j, bigInteger(X, x));
  }

  public static Ttlv ecPublic(Enums.RecommendedCurve curve, byte[] qString) {
    return material(
        Enums.KeyFormatType.TRANSPARENT_EC_PUBLIC_KEY,
        enumeration(RECOMMENDED_CURVE, curve),
        bytes(Q_STRING, qString));
  }

  public static Ttlv ecPrivate(Enums.RecommendedCurve curve, BigInteger d) {
    return material(
        Enums.KeyFormatType.TRANSPARENT_EC_PRIVATE_KEY,
        enumeration(RECOMMENDED_CURVE, curve),
        bigInteger(D, d));
  }

  private static Ttlv dh(
      Enums.KeyFormatType format,
      BigInteger p,
      BigInteger q,
      BigInteger g,
      BigInteger j,
      Ttlv publicOrPrivate) {
    List<Ttlv> fields = new ArrayList<>();
    fields.add(bigInteger(P, p));
    if (q != null) fields.add(bigInteger(Q, q));
    fields.add(bigInteger(G, g));
    if (j != null) fields.add(bigInteger(J, j));
    fields.add(publicOrPrivate);
    return Structures.keyMaterial(format, fields);
  }

  private static Ttlv material(Enums.KeyFormatType format, Ttlv... fields) {
    return Structures.keyMaterial(format, List.of(fields));
  }
}
