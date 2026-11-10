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

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Validates managed key identity, metadata and explicit formats before JCA conversion.
 *
 * <p>The {@code aesKey}, {@code publicKey} and {@code privateKey} methods, and the two-argument
 * {@code rsaPublicKey}, take a Get response payload (Unique Identifier, Object Type and the
 * object) and check, before building a JCA key, that the payload names the expected identifier and
 * object type, that the key is not wrapped, and that its algorithm and strength match what the
 * caller expects. The one-argument {@link #rsaPublicKey(Ttlv)} takes the inner Public Key
 * structure and checks only its format. Supported formats: Raw, Transparent and PKCS#1 RSA;
 * X.509 SubjectPublicKeyInfo; PKCS#8; Transparent EC (and the 1.x ECDSA/ECDH/ECMQV forms) on the
 * NIST P-256, P-384 and P-521 curves; SEC1 EC private keys that name their curve.
 *
 * @since 0.10.0
 */
public final class Keys {
  private Keys() {}

  /**
   * Converts the inner Public Key structure (not a Get payload) to an RSA public key. Checks the
   * declared format and algorithm metadata, not identity; prefer {@link #rsaPublicKey(Ttlv,
   * String)}.
   */
  public static PublicKey rsaPublicKey(Ttlv object) throws GeneralSecurityException, IOException {
    Ttlv block = object.require(KEY_BLOCK), value = block.require(KEY_VALUE);
    // A wrapped Key Value is a Byte String; MAC/sign-only wrapping keeps a structure but still
    // carries Key Wrapping Data, which this conversion does not verify.
    if (value.type() != Ttlv.Type.STRUCTURE || block.child(KEY_WRAPPING_DATA).isPresent())
      throw new InvalidKeyException("Wrapped key must be unwrapped before JCA conversion");
    if (block.child(CRYPTOGRAPHIC_ALGORITHM).isPresent()
        && block.require(CRYPTOGRAPHIC_ALGORITHM).intValue()
            != Enums.CryptographicAlgorithm.RSA.code())
      throw new InvalidKeyException("Unexpected RSA algorithm metadata");
    int declaredFormat = block.require(KEY_FORMAT_TYPE).intValue();
    Ttlv material = value.require(KEY_MATERIAL);
    if (material.type() == Ttlv.Type.STRUCTURE
        && declaredFormat != Enums.KeyFormatType.TRANSPARENT_RSA_PUBLIC_KEY.code())
      throw new InvalidKeyException("Unexpected transparent RSA format");
    KeyFactory factory = KeyFactory.getInstance("RSA");
    if (material.type() == Ttlv.Type.STRUCTURE)
      return factory.generatePublic(
          new RSAPublicKeySpec(
              material.require(MODULUS).bigIntegerValue(),
              material.require(PUBLIC_EXPONENT).bigIntegerValue()));
    byte[] der = material.bytesValue();
    int format = block.require(KEY_FORMAT_TYPE).intValue();
    if (format == Enums.KeyFormatType.RAW.code()) {
      try {
        return factory.generatePublic(new X509EncodedKeySpec(der));
      } catch (InvalidKeySpecException ignored) {
        /* Some servers expose a DER RSA value as Raw. */
      }
    }
    if (format == Enums.KeyFormatType.X_509.code())
      return factory.generatePublic(new X509EncodedKeySpec(der));
    if (format != Enums.KeyFormatType.PKCS_1.code() && format != Enums.KeyFormatType.RAW.code())
      throw new InvalidKeyException("Unsupported RSA public-key format: " + format);
    ByteBuffer input = ByteBuffer.wrap(der), sequence = derValue(input, 0x30);
    if (input.hasRemaining()) throw new IOException("Trailing PKCS#1 data");
    BigInteger modulus = new BigInteger(bytes(derValue(sequence, 2))),
        exponent = new BigInteger(bytes(derValue(sequence, 2)));
    if (sequence.hasRemaining() || modulus.signum() <= 0 || exponent.signum() <= 0)
      throw new IOException("Invalid PKCS#1 RSA public key");
    return factory.generatePublic(new RSAPublicKeySpec(modulus, exponent));
  }

  /** Validates an exact Get response before exposing an AES key to an application. */
  public static SecretKey aesKey(Ttlv payload, String expectedIdentifier, int expectedBits)
      throws GeneralSecurityException {
    if (!payload.require(UNIQUE_IDENTIFIER).textValue().equals(expectedIdentifier)
        || payload.require(OBJECT_TYPE).intValue() != Enums.ObjectType.SYMMETRIC_KEY.code())
      throw new InvalidKeyException("Unexpected key identity or object type");
    Ttlv block = payload.require(SYMMETRIC_KEY).require(KEY_BLOCK);
    if (block.require(CRYPTOGRAPHIC_ALGORITHM).intValue() != Enums.CryptographicAlgorithm.AES.code()
        || block.require(CRYPTOGRAPHIC_LENGTH).intValue() != expectedBits
        || (expectedBits != 128 && expectedBits != 192 && expectedBits != 256))
      throw new InvalidKeyException("Unexpected AES algorithm or key length");
    Ttlv value = block.require(KEY_VALUE);
    if (value.type() != Ttlv.Type.STRUCTURE || block.child(KEY_WRAPPING_DATA).isPresent())
      throw new InvalidKeyException("Wrapped material requires an explicit unwrap");
    int format = block.require(KEY_FORMAT_TYPE).intValue();
    Ttlv material = value.require(KEY_MATERIAL);
    if (format == Enums.KeyFormatType.TRANSPARENT_SYMMETRIC_KEY.code())
      material = material.require(KEY);
    else if (format != Enums.KeyFormatType.RAW.code())
      throw new InvalidKeyException("Unsupported AES key format");
    byte[] encoded = material.bytesValue();
    try {
      if (encoded.length * 8 != expectedBits)
        throw new InvalidKeyException("AES material length mismatch");
      return new SecretKeySpec(encoded, "AES");
    } finally {
      java.util.Arrays.fill(encoded, (byte) 0);
    }
  }

  /** {@link #publicKey} for an RSA key of any size, from a Get response payload. */
  public static PublicKey rsaPublicKey(Ttlv payload, String expectedIdentifier)
      throws GeneralSecurityException {
    return publicKey(payload, expectedIdentifier, Enums.CryptographicAlgorithm.RSA, 0);
  }

  /**
   * Validates a Get response payload and converts its public key.
   *
   * @param expectedAlgorithm RSA, or EC/ECDSA/ECDH/ECMQV; the key block must declare this
   *     algorithm
   * @param expectedBits the modulus or curve size the key must have, or 0 to accept any size
   * @throws InvalidKeyException for an identity, type, algorithm, size or wrapping mismatch
   * @throws InvalidKeySpecException for malformed or unsupported key material
   */
  public static PublicKey publicKey(
      Ttlv payload,
      String expectedIdentifier,
      Enums.CryptographicAlgorithm expectedAlgorithm,
      int expectedBits)
      throws GeneralSecurityException {
    Ttlv block = keyBlock(payload, expectedIdentifier, Enums.ObjectType.PUBLIC_KEY, PUBLIC_KEY);
    checkAlgorithm(block, expectedAlgorithm, expectedBits);
    PublicKey key;
    try {
      key =
          expectedAlgorithm == Enums.CryptographicAlgorithm.RSA
              ? rsaPublicKey(payload.require(PUBLIC_KEY))
              : ecPublicKey(block);
    } catch (IOException | IllegalArgumentException | IllegalStateException e) {
      throw spec("Malformed public key material", e);
    }
    checkStrength(key, expectedBits);
    return key;
  }

  /**
   * Validates a Get response payload and converts its private key.
   *
   * @param expectedAlgorithm RSA, or EC/ECDSA/ECDH/ECMQV; the key block must declare this
   *     algorithm
   * @param expectedBits the modulus or curve size the key must have, or 0 to accept any size
   * @throws InvalidKeyException for an identity, type, algorithm, size or wrapping mismatch
   * @throws InvalidKeySpecException for malformed or unsupported key material
   */
  public static PrivateKey privateKey(
      Ttlv payload,
      String expectedIdentifier,
      Enums.CryptographicAlgorithm expectedAlgorithm,
      int expectedBits)
      throws GeneralSecurityException {
    Ttlv block = keyBlock(payload, expectedIdentifier, Enums.ObjectType.PRIVATE_KEY, PRIVATE_KEY);
    checkAlgorithm(block, expectedAlgorithm, expectedBits);
    PrivateKey key;
    try {
      key =
          expectedAlgorithm == Enums.CryptographicAlgorithm.RSA
              ? rsaPrivateKey(block)
              : ecPrivateKey(block);
    } catch (IOException | IllegalArgumentException | IllegalStateException e) {
      throw spec("Malformed private key material", e);
    }
    checkStrength(key, expectedBits);
    return key;
  }

  private static Ttlv keyBlock(
      Ttlv payload, String expectedIdentifier, Enums.ObjectType type, Tag objectTag)
      throws InvalidKeyException {
    try {
      if (!payload.require(UNIQUE_IDENTIFIER).textValue().equals(expectedIdentifier)
          || payload.require(OBJECT_TYPE).intValue() != type.code())
        throw new InvalidKeyException("Unexpected key identity or object type");
      Ttlv block = payload.require(objectTag).require(KEY_BLOCK);
      if (block.require(KEY_VALUE).type() != Ttlv.Type.STRUCTURE
          || block.child(KEY_WRAPPING_DATA).isPresent())
        throw new InvalidKeyException("Wrapped material requires an explicit unwrap");
      return block;
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw (InvalidKeyException) new InvalidKeyException("Malformed Get response").initCause(e);
    }
  }

  private static final Set<Enums.CryptographicAlgorithm> EC_FAMILY =
      Set.of(
          Enums.CryptographicAlgorithm.EC,
          Enums.CryptographicAlgorithm.ECDSA,
          Enums.CryptographicAlgorithm.ECDH,
          Enums.CryptographicAlgorithm.ECMQV);

  private static void checkAlgorithm(
      Ttlv block, Enums.CryptographicAlgorithm expected, int expectedBits)
      throws InvalidKeyException {
    if (expected != Enums.CryptographicAlgorithm.RSA && !EC_FAMILY.contains(expected))
      throw new InvalidKeyException("Only RSA and EC keys are converted, not " + expected);
    Optional<Ttlv> algorithm = block.child(CRYPTOGRAPHIC_ALGORITHM);
    if (algorithm.isEmpty() || algorithm.get().intValue() != expected.code())
      throw new InvalidKeyException("Unexpected key algorithm metadata");
    Optional<Ttlv> length = block.child(CRYPTOGRAPHIC_LENGTH);
    if (expectedBits > 0 && length.isPresent() && length.get().intValue() != expectedBits)
      throw new InvalidKeyException("Unexpected key length metadata");
  }

  private static void checkStrength(Key key, int expectedBits) throws InvalidKeyException {
    if (expectedBits <= 0) return;
    int bits =
        key instanceof java.security.interfaces.RSAKey rsa
            ? rsa.getModulus().bitLength()
            : ((java.security.interfaces.ECKey) key)
                .getParams()
                .getCurve()
                .getField()
                .getFieldSize();
    if (bits != expectedBits)
      throw new InvalidKeyException("Key size " + bits + " is not the expected " + expectedBits);
  }

  private static InvalidKeySpecException spec(String message, Exception cause) {
    return (InvalidKeySpecException) new InvalidKeySpecException(message).initCause(cause);
  }

  private static int format(Ttlv block) {
    return block.require(KEY_FORMAT_TYPE).intValue();
  }

  private static boolean transparentEc(int format, boolean privateKey) {
    return privateKey
        ? format == Enums.KeyFormatType.TRANSPARENT_EC_PRIVATE_KEY.code()
            || format == Enums.KeyFormatType.TRANSPARENT_ECDSA_PRIVATE_KEY.code()
            || format == Enums.KeyFormatType.TRANSPARENT_ECDH_PRIVATE_KEY.code()
            || format == Enums.KeyFormatType.TRANSPARENT_ECMQV_PRIVATE_KEY.code()
        : format == Enums.KeyFormatType.TRANSPARENT_EC_PUBLIC_KEY.code()
            || format == Enums.KeyFormatType.TRANSPARENT_ECDSA_PUBLIC_KEY.code()
            || format == Enums.KeyFormatType.TRANSPARENT_ECDH_PUBLIC_KEY.code()
            || format == Enums.KeyFormatType.TRANSPARENT_ECMQV_PUBLIC_KEY.code();
  }

  private static PublicKey ecPublicKey(Ttlv block) throws GeneralSecurityException, IOException {
    int format = format(block);
    Ttlv material = block.require(KEY_VALUE).require(KEY_MATERIAL);
    KeyFactory factory = KeyFactory.getInstance("EC");
    if (transparentEc(format, false)) {
      ECParameterSpec curve = curve(material.require(RECOMMENDED_CURVE).intValue());
      byte[] point = material.require(Q_STRING).bytesValue();
      return factory.generatePublic(new ECPublicKeySpec(decodePoint(point, curve), curve));
    }
    if (format == Enums.KeyFormatType.X_509.code())
      return factory.generatePublic(new X509EncodedKeySpec(material.bytesValue()));
    throw new InvalidKeySpecException("Unsupported EC public-key format: " + format);
  }

  private static PrivateKey ecPrivateKey(Ttlv block) throws GeneralSecurityException, IOException {
    int format = format(block);
    Ttlv material = block.require(KEY_VALUE).require(KEY_MATERIAL);
    KeyFactory factory = KeyFactory.getInstance("EC");
    if (transparentEc(format, true))
      return factory.generatePrivate(
          new ECPrivateKeySpec(
              material.require(D).bigIntegerValue(),
              curve(material.require(RECOMMENDED_CURVE).intValue())));
    byte[] der = material.bytesValue();
    try {
      if (format == Enums.KeyFormatType.PKCS_8.code())
        return factory.generatePrivate(new PKCS8EncodedKeySpec(der));
      if (format == Enums.KeyFormatType.ECPRIVATE_KEY.code())
        return withPkcs8(der, pkcs8 -> factory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8)));
    } finally {
      Arrays.fill(der, (byte) 0);
    }
    throw new InvalidKeySpecException("Unsupported EC private-key format: " + format);
  }

  private static PrivateKey rsaPrivateKey(Ttlv block) throws GeneralSecurityException, IOException {
    int format = format(block);
    Ttlv material = block.require(KEY_VALUE).require(KEY_MATERIAL);
    KeyFactory factory = KeyFactory.getInstance("RSA");
    if (format == Enums.KeyFormatType.TRANSPARENT_RSA_PRIVATE_KEY.code()) {
      BigInteger n = material.require(MODULUS).bigIntegerValue(),
          d = material.require(PRIVATE_EXPONENT).bigIntegerValue();
      List<Tag> crt =
          List.of(PUBLIC_EXPONENT, P, Q, PRIME_EXPONENT_P, PRIME_EXPONENT_Q, CRT_COEFFICIENT);
      if (crt.stream().allMatch(t -> material.child(t).isPresent()))
        return factory.generatePrivate(
            new RSAPrivateCrtKeySpec(
                n,
                material.require(PUBLIC_EXPONENT).bigIntegerValue(),
                d,
                material.require(P).bigIntegerValue(),
                material.require(Q).bigIntegerValue(),
                material.require(PRIME_EXPONENT_P).bigIntegerValue(),
                material.require(PRIME_EXPONENT_Q).bigIntegerValue(),
                material.require(CRT_COEFFICIENT).bigIntegerValue()));
      return factory.generatePrivate(new RSAPrivateKeySpec(n, d));
    }
    byte[] der = material.bytesValue();
    try {
      if (format == Enums.KeyFormatType.PKCS_8.code())
        return factory.generatePrivate(new PKCS8EncodedKeySpec(der));
      if (format == Enums.KeyFormatType.PKCS_1.code()) {
        ByteBuffer input = ByteBuffer.wrap(der), sequence = derValue(input, 0x30);
        if (input.hasRemaining()) throw new IOException("Trailing PKCS#1 data");
        BigInteger[] v = new BigInteger[9];
        for (int i = 0; i < 9; i++) v[i] = new BigInteger(bytes(derValue(sequence, 2)));
        if (v[0].signum() != 0) throw new IOException("Unsupported PKCS#1 version");
        return factory.generatePrivate(
            new RSAPrivateCrtKeySpec(v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8]));
      }
    } finally {
      Arrays.fill(der, (byte) 0);
    }
    throw new InvalidKeySpecException("Unsupported RSA private-key format: " + format);
  }

  private static final Map<Integer, String> CURVES =
      Map.of(
          Enums.RecommendedCurve.P_256.code(), "secp256r1",
          Enums.RecommendedCurve.P_384.code(), "secp384r1",
          Enums.RecommendedCurve.P_521.code(), "secp521r1");

  private static ECParameterSpec curve(int recommendedCurve) throws GeneralSecurityException {
    String name = CURVES.get(recommendedCurve);
    if (name == null)
      throw new InvalidKeySpecException(
          "Unsupported recommended curve: " + String.format("0x%08X", recommendedCurve));
    AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
    parameters.init(new ECGenParameterSpec(name));
    return parameters.getParameterSpec(ECParameterSpec.class);
  }

  /** The Recommended Curve for a JCA EC key on a supported curve. */
  public static Enums.RecommendedCurve recommendedCurve(ECParameterSpec params)
      throws InvalidKeyException {
    for (var entry : CURVES.entrySet())
      try {
        ECParameterSpec candidate = curve(entry.getKey());
        if (candidate.getCurve().equals(params.getCurve())
            && candidate.getGenerator().equals(params.getGenerator())
            && candidate.getOrder().equals(params.getOrder()))
          return Enums.RecommendedCurve.fromCode(entry.getKey()).orElseThrow();
      } catch (GeneralSecurityException ignored) {
        // curve not available on this JDK
      }
    throw new InvalidKeyException("Unsupported EC curve; P-256, P-384 and P-521 are supported");
  }

  /** SEC1 uncompressed point (0x04 || X || Y). */
  private static ECPoint decodePoint(byte[] point, ECParameterSpec curve)
      throws InvalidKeySpecException {
    int size = (curve.getCurve().getField().getFieldSize() + 7) / 8;
    if (point.length != 1 + 2 * size || point[0] != 4)
      throw new InvalidKeySpecException("Expected an uncompressed EC point");
    return new ECPoint(
        new BigInteger(1, Arrays.copyOfRange(point, 1, 1 + size)),
        new BigInteger(1, Arrays.copyOfRange(point, 1 + size, point.length)));
  }

  /** The uncompressed SEC1 encoding of a JCA EC public key, for Transparent EC Public Key. */
  public static byte[] encodePoint(java.security.interfaces.ECPublicKey key) {
    int size = (key.getParams().getCurve().getField().getFieldSize() + 7) / 8;
    byte[] out = new byte[1 + 2 * size];
    out[0] = 4;
    unsigned(key.getW().getAffineX(), out, 1, size);
    unsigned(key.getW().getAffineY(), out, 1 + size, size);
    return out;
  }

  private static void unsigned(BigInteger n, byte[] out, int offset, int size) {
    byte[] b = n.toByteArray();
    int start = Math.max(0, b.length - size);
    System.arraycopy(b, start, out, offset + size - (b.length - start), b.length - start);
  }

  private static final byte[] EC_PUBLIC_KEY_OID = {
    0x06, 0x07, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01
  };

  /** Reads a temporary PKCS#8 encoding; see {@link #withPkcs8}. */
  @FunctionalInterface
  interface Pkcs8Reader<T> {
    T read(byte[] pkcs8) throws GeneralSecurityException;
  }

  /**
   * Converts a SEC1 ECPrivateKey to PKCS#8 for {@code reader} and zeroes every temporary copy of
   * the private key afterwards (best effort: the JCA key spec keeps its own copy).
   */
  static <T> T withPkcs8(byte[] sec1, Pkcs8Reader<T> reader)
      throws GeneralSecurityException, IOException {
    byte[] pkcs8 = sec1ToPkcs8(sec1);
    try {
      return reader.read(pkcs8);
    } finally {
      Arrays.fill(pkcs8, (byte) 0);
    }
  }

  /** Wraps a SEC1 ECPrivateKey whose [0] parameters name the curve OID into PKCS#8. */
  private static byte[] sec1ToPkcs8(byte[] sec1) throws IOException {
    ByteBuffer input = ByteBuffer.wrap(sec1), sequence = derValue(input, 0x30);
    if (input.hasRemaining()) throw new IOException("Trailing SEC1 data");
    derValue(sequence, 0x02); // version
    derValue(sequence, 0x04); // private key
    if (!sequence.hasRemaining()) throw new IOException("SEC1 key does not name its curve");
    ByteBuffer parameters = derValue(sequence, 0xa0);
    int start = parameters.position();
    derValue(parameters, 0x06);
    byte[] curveOid = new byte[parameters.position() - start];
    parameters.position(start).get(curveOid);
    byte[] algorithm = der(0x30, EC_PUBLIC_KEY_OID, curveOid);
    byte[] privateKey = der(0x04, sec1);
    try {
      return der(0x30, new byte[] {0x02, 0x01, 0x00}, algorithm, privateKey);
    } finally {
      Arrays.fill(privateKey, (byte) 0);
    }
  }

  /** A DER TLV in one exactly sized array, so no intermediate copy of the value is left behind. */
  private static byte[] der(int tag, byte[]... parts) {
    int length = 0;
    for (byte[] p : parts) length += p.length;
    if (length > 0xffff) throw new IllegalArgumentException("DER value too long");
    int header = length < 0x80 ? 2 : length < 0x100 ? 3 : 4;
    byte[] out = new byte[header + length];
    out[0] = (byte) tag;
    if (length < 0x80) out[1] = (byte) length;
    else if (length < 0x100) {
      out[1] = (byte) 0x81;
      out[2] = (byte) length;
    } else {
      out[1] = (byte) 0x82;
      out[2] = (byte) (length >> 8);
      out[3] = (byte) length;
    }
    int at = header;
    for (byte[] p : parts) {
      System.arraycopy(p, 0, out, at, p.length);
      at += p.length;
    }
    return out;
  }

  private static byte[] bytes(ByteBuffer b) {
    byte[] out = new byte[b.remaining()];
    b.get(out);
    return out;
  }

  private static ByteBuffer derValue(ByteBuffer in, int tag) throws IOException {
    if (in.remaining() < 2 || Byte.toUnsignedInt(in.get()) != tag)
      throw new IOException("Invalid DER tag");
    int length = Byte.toUnsignedInt(in.get());
    if ((length & 0x80) != 0) {
      int octets = length & 0x7f;
      if (octets == 0 || octets > 4 || in.remaining() < octets)
        throw new IOException("Invalid DER length");
      long size = 0;
      for (int i = 0; i < octets; i++) size = (size << 8) | Byte.toUnsignedInt(in.get());
      if (size > Integer.MAX_VALUE) throw new IOException("DER length overflow");
      length = (int) size;
    }
    if (length > in.remaining()) throw new IOException("Truncated DER value");
    if (length == 0 && tag == 2) throw new IOException("Empty DER INTEGER");
    ByteBuffer value = in.slice();
    value.limit(length);
    in.position(in.position() + length);
    return value;
  }
}
