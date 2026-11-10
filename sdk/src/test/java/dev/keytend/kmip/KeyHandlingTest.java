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

package dev.keytend.kmip;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.*;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

/** Key conversion and secret lifetime. */
class KeyHandlingTest {
  static final KeyPair RSA, EC;

  static {
    try {
      KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
      rsa.initialize(2048);
      RSA = rsa.generateKeyPair();
      KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
      ec.initialize(new ECGenParameterSpec("secp256r1"));
      EC = ec.generateKeyPair();
    } catch (GeneralSecurityException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  /** A Get response payload for a public or private key object. */
  static Ttlv payload(
      String id,
      boolean privateKey,
      Enums.KeyFormatType format,
      Ttlv material,
      Enums.CryptographicAlgorithm algorithm,
      int bits) {
    Ttlv block = ManagedObjects.keyBlock(format, material, algorithm, bits);
    return structure(
        RESPONSE_PAYLOAD,
        enumeration(
            OBJECT_TYPE, privateKey ? Enums.ObjectType.PRIVATE_KEY : Enums.ObjectType.PUBLIC_KEY),
        text(UNIQUE_IDENTIFIER, id),
        privateKey ? ManagedObjects.privateKey(block) : ManagedObjects.publicKey(block));
  }

  /** The DER value bytes inside a PKCS#8 PrivateKeyInfo's OCTET STRING. */
  static byte[] innerKey(byte[] pkcs8) {
    ByteBuffer b = ByteBuffer.wrap(pkcs8);
    header(b); // SEQUENCE
    b.position(b.position() + 3); // INTEGER 0
    int algLength = header(b);
    b.position(b.position() + algLength);
    int keyLength = header(b); // OCTET STRING
    byte[] key = new byte[keyLength];
    b.get(key);
    return key;
  }

  static int header(ByteBuffer b) {
    b.get();
    int length = b.get() & 0xff;
    if ((length & 0x80) != 0) {
      int n = length & 0x7f;
      length = 0;
      for (int i = 0; i < n; i++) length = (length << 8) | (b.get() & 0xff);
    }
    return length;
  }

  @Test
  void rsaPublicKeysConvertFromEveryFormatWithIdentityChecks() throws Exception {
    RSAPublicKey key = (RSAPublicKey) RSA.getPublic();
    byte[] pkcs1 = innerBitString(key.getEncoded());
    for (Ttlv material :
        List.of(
            KeyMaterials.rsaPublic(key.getModulus(), key.getPublicExponent()),
            bytes(KEY_MATERIAL, pkcs1),
            bytes(KEY_MATERIAL, key.getEncoded()))) {
      Enums.KeyFormatType format =
          material.type() == Ttlv.Type.STRUCTURE
              ? Enums.KeyFormatType.TRANSPARENT_RSA_PUBLIC_KEY
              : material.bytesValue().length == pkcs1.length
                  ? Enums.KeyFormatType.PKCS_1
                  : Enums.KeyFormatType.X_509;
      Ttlv p = payload("pub", false, format, material, Enums.CryptographicAlgorithm.RSA, 2048);
      assertArrayEquals(
          key.getEncoded(),
          Keys.publicKey(p, "pub", Enums.CryptographicAlgorithm.RSA, 2048).getEncoded());
      assertArrayEquals(key.getEncoded(), Keys.rsaPublicKey(p, "pub").getEncoded());
      assertThrows(InvalidKeyException.class, () -> Keys.rsaPublicKey(p, "other"));
      assertThrows(
          InvalidKeyException.class,
          () -> Keys.publicKey(p, "pub", Enums.CryptographicAlgorithm.RSA, 3072));
      assertThrows(
          InvalidKeyException.class,
          () -> Keys.publicKey(p, "pub", Enums.CryptographicAlgorithm.EC, 256));
    }
  }

  /** The RSAPublicKey (PKCS#1) inside an X.509 SubjectPublicKeyInfo's BIT STRING. */
  static byte[] innerBitString(byte[] spki) {
    ByteBuffer b = ByteBuffer.wrap(spki);
    header(b);
    int algLength = header(b);
    b.position(b.position() + algLength);
    int bits = header(b);
    b.get(); // unused-bits byte
    byte[] out = new byte[bits - 1];
    b.get(out);
    return out;
  }

  @Test
  void rsaPrivateKeysConvertFromEveryFormat() throws Exception {
    RSAPrivateCrtKey key = (RSAPrivateCrtKey) RSA.getPrivate();
    Ttlv transparent =
        KeyMaterials.rsaPrivate(
            key.getModulus(),
            key.getPrivateExponent(),
            bigInteger(PUBLIC_EXPONENT, key.getPublicExponent()),
            bigInteger(P, key.getPrimeP()),
            bigInteger(Q, key.getPrimeQ()),
            bigInteger(PRIME_EXPONENT_P, key.getPrimeExponentP()),
            bigInteger(PRIME_EXPONENT_Q, key.getPrimeExponentQ()),
            bigInteger(CRT_COEFFICIENT, key.getCrtCoefficient()));
    Map<Enums.KeyFormatType, Ttlv> formats =
        Map.of(
            Enums.KeyFormatType.TRANSPARENT_RSA_PRIVATE_KEY, transparent,
            Enums.KeyFormatType.PKCS_8, bytes(KEY_MATERIAL, key.getEncoded()),
            Enums.KeyFormatType.PKCS_1, bytes(KEY_MATERIAL, innerKey(key.getEncoded())));
    for (var e : formats.entrySet()) {
      Ttlv p =
          payload("priv", true, e.getKey(), e.getValue(), Enums.CryptographicAlgorithm.RSA, 2048);
      PrivateKey converted = Keys.privateKey(p, "priv", Enums.CryptographicAlgorithm.RSA, 2048);
      assertArrayEquals(key.getEncoded(), converted.getEncoded(), e.getKey().toString());
    }
  }

  @Test
  void ecKeysConvertWithCurveAndSizeChecks() throws Exception {
    ECPublicKey pub = (ECPublicKey) EC.getPublic();
    ECPrivateKey priv = (ECPrivateKey) EC.getPrivate();
    assertEquals(Enums.RecommendedCurve.P_256, Keys.recommendedCurve(pub.getParams()));
    for (Ttlv p :
        List.of(
            payload(
                "ec",
                false,
                Enums.KeyFormatType.TRANSPARENT_EC_PUBLIC_KEY,
                KeyMaterials.ecPublic(Enums.RecommendedCurve.P_256, Keys.encodePoint(pub)),
                Enums.CryptographicAlgorithm.EC,
                256),
            payload(
                "ec",
                false,
                Enums.KeyFormatType.X_509,
                bytes(KEY_MATERIAL, pub.getEncoded()),
                Enums.CryptographicAlgorithm.EC,
                256))) {
      assertArrayEquals(
          pub.getEncoded(),
          Keys.publicKey(p, "ec", Enums.CryptographicAlgorithm.EC, 256).getEncoded());
      assertThrows(
          InvalidKeyException.class,
          () -> Keys.publicKey(p, "ec", Enums.CryptographicAlgorithm.EC, 384));
    }
    // SEC1 ECPrivateKey naming its curve: SEQUENCE { 1, OCTET STRING d, [0] secp256r1 }.
    byte[] d =
        Arrays.copyOfRange(
            priv.getS().toByteArray(),
            priv.getS().toByteArray().length - 32,
            priv.getS().toByteArray().length);
    byte[] secp256r1 = {0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};
    byte[] sec1 = new byte[2 + 3 + 2 + 32 + 2 + secp256r1.length];
    ByteBuffer b = ByteBuffer.wrap(sec1);
    b.put((byte) 0x30).put((byte) (sec1.length - 2)).put(new byte[] {0x02, 0x01, 0x01});
    b.put((byte) 0x04).put((byte) 32).put(d);
    b.put((byte) 0xa0).put((byte) secp256r1.length).put(secp256r1);
    for (Ttlv p :
        List.of(
            payload(
                "ecp",
                true,
                Enums.KeyFormatType.TRANSPARENT_EC_PRIVATE_KEY,
                KeyMaterials.ecPrivate(Enums.RecommendedCurve.P_256, priv.getS()),
                Enums.CryptographicAlgorithm.EC,
                256),
            payload(
                "ecp",
                true,
                Enums.KeyFormatType.PKCS_8,
                bytes(KEY_MATERIAL, priv.getEncoded()),
                Enums.CryptographicAlgorithm.EC,
                256),
            payload(
                "ecp",
                true,
                Enums.KeyFormatType.ECPRIVATE_KEY,
                bytes(KEY_MATERIAL, sec1),
                Enums.CryptographicAlgorithm.EC,
                256))) {
      ECPrivateKey converted =
          (ECPrivateKey) Keys.privateKey(p, "ecp", Enums.CryptographicAlgorithm.EC, 256);
      assertEquals(priv.getS(), converted.getS());
    }
  }

  @Test
  void wrappedOrMistypedObjectsAreRefused() {
    Ttlv wrapped =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, Enums.ObjectType.PRIVATE_KEY),
            text(UNIQUE_IDENTIFIER, "w"),
            ManagedObjects.privateKey(
                structure(
                    KEY_BLOCK,
                    enumeration(KEY_FORMAT_TYPE, Enums.KeyFormatType.PKCS_8),
                    bytes(KEY_VALUE, new byte[32]),
                    enumeration(CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.RSA),
                    integer(CRYPTOGRAPHIC_LENGTH, 2048),
                    structure(KEY_WRAPPING_DATA, enumeration(WRAPPING_METHOD, 1)))));
    assertThrows(
        InvalidKeyException.class,
        () -> Keys.privateKey(wrapped, "w", Enums.CryptographicAlgorithm.RSA, 2048));
    Ttlv publicAsPrivate =
        payload(
            "x",
            false,
            Enums.KeyFormatType.X_509,
            bytes(KEY_MATERIAL, RSA.getPublic().getEncoded()),
            Enums.CryptographicAlgorithm.RSA,
            2048);
    assertThrows(
        InvalidKeyException.class,
        () -> Keys.privateKey(publicAsPrivate, "x", Enums.CryptographicAlgorithm.RSA, 2048));
  }

  /**
   * The wrapped Key Value branch of every conversion. Encrypting wraps
   * turn the Key Value into a Byte String; MAC/sign-only wrapping keeps a structured Key Value but
   * adds Key Wrapping Data. Neither is handed to the JCA as if it were plain key material.
   */
  @Test
  void everyConversionRefusesBothWrappedKeyValueForms() throws Exception {
    Ttlv macSign =
        structure(KEY_WRAPPING_DATA, enumeration(WRAPPING_METHOD, Enums.WrappingMethod.MAC_SIGN));
    Ttlv encrypt =
        structure(KEY_WRAPPING_DATA, enumeration(WRAPPING_METHOD, Enums.WrappingMethod.ENCRYPT));
    byte[] rsaPublic = RSA.getPublic().getEncoded(), rsaPrivate = RSA.getPrivate().getEncoded();
    byte[] ecPrivate = EC.getPrivate().getEncoded(), aes = new byte[16];
    record Case(
        Enums.ObjectType type,
        Tag object,
        Enums.KeyFormatType format,
        byte[] material,
        Enums.CryptographicAlgorithm algorithm,
        int bits) {}
    List<Case> cases =
        List.of(
            new Case(
                Enums.ObjectType.PUBLIC_KEY,
                PUBLIC_KEY,
                Enums.KeyFormatType.X_509,
                rsaPublic,
                Enums.CryptographicAlgorithm.RSA,
                2048),
            new Case(
                Enums.ObjectType.PRIVATE_KEY,
                PRIVATE_KEY,
                Enums.KeyFormatType.PKCS_8,
                rsaPrivate,
                Enums.CryptographicAlgorithm.RSA,
                2048),
            new Case(
                Enums.ObjectType.PRIVATE_KEY,
                PRIVATE_KEY,
                Enums.KeyFormatType.PKCS_8,
                ecPrivate,
                Enums.CryptographicAlgorithm.EC,
                256),
            new Case(
                Enums.ObjectType.SYMMETRIC_KEY,
                SYMMETRIC_KEY,
                Enums.KeyFormatType.RAW,
                aes,
                Enums.CryptographicAlgorithm.AES,
                128));
    for (Case c : cases)
      for (Ttlv wrapping : List.of(macSign, encrypt)) {
        // MAC/sign keeps the structured Key Value; Encrypt replaces it with ciphertext bytes.
        Ttlv value =
            wrapping == macSign
                ? structure(KEY_VALUE, bytes(KEY_MATERIAL, c.material()))
                : bytes(KEY_VALUE, new byte[48]);
        Ttlv block = ManagedObjects.keyBlock(c.format(), value, c.algorithm(), c.bits(), wrapping);
        Ttlv payload =
            structure(
                RESPONSE_PAYLOAD,
                enumeration(OBJECT_TYPE, c.type()),
                text(UNIQUE_IDENTIFIER, "w"),
                structure(c.object(), block));
        String what = c.algorithm() + " " + c.type() + " " + (wrapping == macSign ? "MAC" : "enc");
        Executable convert =
            switch (c.type()) {
              case PUBLIC_KEY -> () -> Keys.publicKey(payload, "w", c.algorithm(), c.bits());
              case PRIVATE_KEY -> () -> Keys.privateKey(payload, "w", c.algorithm(), c.bits());
              default -> () -> Keys.aesKey(payload, "w", c.bits());
            };
        var e = assertThrows(InvalidKeyException.class, convert, what);
        assertTrue(e.getMessage().contains("unwrap"), what + ": " + e.getMessage());
        if (c.type() == Enums.ObjectType.PUBLIC_KEY) {
          assertThrows(
              InvalidKeyException.class,
              () -> Keys.rsaPublicKey(payload, "w"),
              what + " (rsaPublicKey by payload)");
          assertThrows(
              InvalidKeyException.class,
              () -> Keys.rsaPublicKey(structure(PUBLIC_KEY, block)),
              what + " (rsaPublicKey by object)");
        }
      }
  }

  @Test
  void credentialsAcceptCharArraysAndAuthenticationAcceptsACredential() {
    Ttlv credential = Credentials.usernamePassword("u", "p".toCharArray());
    RequestOptions options = RequestOptions.DEFAULT.authentication(credential);
    assertEquals(AUTHENTICATION.code(), options.authentication().tag());
    assertEquals(
        options.authentication(), RequestOptions.passwordAuthentication("u", "p".toCharArray()));
  }

  @Test
  void withBytesZeroesItsTemporaryCopy() {
    Ttlv key = bytes(KEY, new byte[] {1, 2, 3, 4});
    byte[][] seen = new byte[1][];
    int sum =
        key.withBytes(
            b -> {
              seen[0] = b;
              int s = 0;
              for (byte x : b) s += x;
              return s;
            });
    assertEquals(10, sum);
    assertArrayEquals(new byte[4], seen[0], "the reader's copy is wiped");
    assertArrayEquals(new byte[] {1, 2, 3, 4}, key.bytesValue(), "the value itself is unchanged");
    assertEquals(4, key.byteLength());
  }
}
