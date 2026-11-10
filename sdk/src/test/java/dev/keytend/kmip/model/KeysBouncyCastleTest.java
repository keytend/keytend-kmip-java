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
import static org.junit.jupiter.api.Assertions.*;

import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.SECObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.ECNamedCurveTable;
import org.bouncycastle.asn1.x9.X962Parameters;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.util.io.pem.PemReader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 * {@link Keys} against Bouncy Castle as an independent encoder of the key forms KMIP carries:
 * PKCS#1 RSA private and public keys, SEC1 EC private keys (with and without their public key, on
 * every supported curve), PKCS#8 and SubjectPublicKeyInfo, each built by Bouncy Castle from the
 * keys' components, give the same keys. A SEC1 key that does not name its curve (none, or explicit
 * parameters) is refused with {@link InvalidKeySpecException}, as documented: also the {@code EC
 * PRIVATE KEY} Bouncy Castle's PEM writer makes of a JDK key, which has no curve.
 */
class KeysBouncyCastleTest {
  private static KeyPair rsa;
  private static final List<String> CURVES = List.of("secp256r1", "secp384r1", "secp521r1");

  @BeforeAll
  static void keys() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(2048);
    rsa = g.generateKeyPair();
  }

  private static Ttlv payload(
      String id,
      boolean privateKey,
      Enums.KeyFormatType format,
      byte[] material,
      Enums.CryptographicAlgorithm algorithm,
      int bits) {
    Ttlv block = ManagedObjects.keyBlock(format, bytes(KEY_MATERIAL, material), algorithm, bits);
    return structure(
        RESPONSE_PAYLOAD,
        enumeration(
            OBJECT_TYPE, privateKey ? Enums.ObjectType.PRIVATE_KEY : Enums.ObjectType.PUBLIC_KEY),
        text(UNIQUE_IDENTIFIER, id),
        privateKey ? ManagedObjects.privateKey(block) : ManagedObjects.publicKey(block));
  }

  private static RSAPrivateKey pkcs1(RSAPrivateCrtKey k) {
    return new RSAPrivateKey(
        k.getModulus(),
        k.getPublicExponent(),
        k.getPrivateExponent(),
        k.getPrimeP(),
        k.getPrimeQ(),
        k.getPrimeExponentP(),
        k.getPrimeExponentQ(),
        k.getCrtCoefficient());
  }

  private static void assertSameRsa(RSAPrivateCrtKey expected, PrivateKey read) {
    RSAPrivateCrtKey r = (RSAPrivateCrtKey) read;
    assertEquals(expected.getModulus(), r.getModulus());
    assertEquals(expected.getPublicExponent(), r.getPublicExponent());
    assertEquals(expected.getPrivateExponent(), r.getPrivateExponent());
    assertEquals(expected.getPrimeP(), r.getPrimeP());
    assertEquals(expected.getPrimeQ(), r.getPrimeQ());
    assertEquals(expected.getPrimeExponentP(), r.getPrimeExponentP());
    assertEquals(expected.getPrimeExponentQ(), r.getPrimeExponentQ());
    assertEquals(expected.getCrtCoefficient(), r.getCrtCoefficient());
  }

  @Test
  void rsaPrivateKeysInPkcs1AndPkcs8FromBouncyCastle() throws Exception {
    RSAPrivateCrtKey key = (RSAPrivateCrtKey) rsa.getPrivate();
    byte[] pkcs1 = pkcs1(key).getEncoded();
    byte[] pkcs8 =
        new PrivateKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                pkcs1(key))
            .getEncoded();
    assertSameRsa(
        key,
        Keys.privateKey(
            payload(
                "k",
                true,
                Enums.KeyFormatType.PKCS_1,
                pkcs1,
                Enums.CryptographicAlgorithm.RSA,
                2048),
            "k",
            Enums.CryptographicAlgorithm.RSA,
            2048));
    assertSameRsa(
        key,
        Keys.privateKey(
            payload(
                "k",
                true,
                Enums.KeyFormatType.PKCS_8,
                pkcs8,
                Enums.CryptographicAlgorithm.RSA,
                2048),
            "k",
            Enums.CryptographicAlgorithm.RSA,
            2048));
    // The PKCS#1 body of an OpenSSL "RSA PRIVATE KEY" block, as Bouncy Castle's PEM writer
    // writes it: the form PemIdentity refuses with advice, read here from KMIP.
    byte[] fromPem = pemBody(key, "RSA PRIVATE KEY");
    assertSameRsa(
        key,
        Keys.privateKey(
            payload(
                "k",
                true,
                Enums.KeyFormatType.PKCS_1,
                fromPem,
                Enums.CryptographicAlgorithm.RSA,
                0),
            "k",
            Enums.CryptographicAlgorithm.RSA,
            0));
  }

  @Test
  void rsaPublicKeysInPkcs1AndX509FromBouncyCastle() throws Exception {
    RSAPublicKey key = (RSAPublicKey) rsa.getPublic();
    org.bouncycastle.asn1.pkcs.RSAPublicKey pkcs1 =
        new org.bouncycastle.asn1.pkcs.RSAPublicKey(key.getModulus(), key.getPublicExponent());
    byte[] spki =
        new SubjectPublicKeyInfo(
                new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                pkcs1)
            .getEncoded();
    for (var form :
        List.of(
            new Object[] {Enums.KeyFormatType.PKCS_1, pkcs1.getEncoded()},
            new Object[] {Enums.KeyFormatType.X_509, spki})) {
      Ttlv p =
          payload(
              "p",
              false,
              (Enums.KeyFormatType) form[0],
              (byte[]) form[1],
              Enums.CryptographicAlgorithm.RSA,
              2048);
      RSAPublicKey read = (RSAPublicKey) Keys.rsaPublicKey(p, "p");
      assertEquals(key.getModulus(), read.getModulus(), form[0].toString());
      assertEquals(key.getPublicExponent(), read.getPublicExponent(), form[0].toString());
      assertArrayEquals(key.getEncoded(), read.getEncoded(), form[0].toString());
    }
  }

  private static ASN1ObjectIdentifier oid(String curve) {
    return switch (curve) {
      case "secp256r1" -> X9ObjectIdentifiers.prime256v1;
      case "secp384r1" -> SECObjectIdentifiers.secp384r1;
      default -> SECObjectIdentifiers.secp521r1;
    };
  }

  private static int bits(String curve) {
    return switch (curve) {
      case "secp256r1" -> 256;
      case "secp384r1" -> 384;
      default -> 521;
    };
  }

  @Test
  void ecPrivateKeysInSec1AndPkcs8FromBouncyCastleOnEveryCurve() throws Exception {
    for (String curve : CURVES) {
      KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
      g.initialize(new ECGenParameterSpec(curve));
      KeyPair pair = g.generateKeyPair();
      ECPrivateKey key = (ECPrivateKey) pair.getPrivate();
      int bits = bits(curve);
      ASN1ObjectIdentifier oid = oid(curve);
      DERBitString point =
          new DERBitString(
              SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded())
                  .getPublicKeyData()
                  .getBytes());
      int orderBits = key.getParams().getOrder().bitLength();
      var withPublic =
          new org.bouncycastle.asn1.sec.ECPrivateKey(orderBits, key.getS(), point, oid);
      var withoutPublic = new org.bouncycastle.asn1.sec.ECPrivateKey(orderBits, key.getS(), oid);
      for (byte[] sec1 : List.of(withPublic.getEncoded(), withoutPublic.getEncoded())) {
        ECPrivateKey read =
            (ECPrivateKey)
                Keys.privateKey(
                    payload(
                        "e",
                        true,
                        Enums.KeyFormatType.ECPRIVATE_KEY,
                        sec1,
                        Enums.CryptographicAlgorithm.EC,
                        bits),
                    "e",
                    Enums.CryptographicAlgorithm.EC,
                    bits);
        assertEquals(key.getS(), read.getS(), curve);
        assertEquals(key.getParams().getOrder(), read.getParams().getOrder(), curve);
      }
      byte[] pkcs8 =
          new PrivateKeyInfo(
                  new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, oid), withPublic)
              .getEncoded();
      ECPrivateKey read =
          (ECPrivateKey)
              Keys.privateKey(
                  payload(
                      "e",
                      true,
                      Enums.KeyFormatType.PKCS_8,
                      pkcs8,
                      Enums.CryptographicAlgorithm.ECDSA,
                      bits),
                  "e",
                  Enums.CryptographicAlgorithm.ECDSA,
                  bits);
      assertEquals(key.getS(), read.getS(), curve);
      // The public key as Bouncy Castle encodes SubjectPublicKeyInfo.
      byte[] spki =
          new SubjectPublicKeyInfo(
                  new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, oid),
                  point.getBytes())
              .getEncoded();
      ECPublicKey pub =
          (ECPublicKey)
              Keys.publicKey(
                  payload(
                      "q",
                      false,
                      Enums.KeyFormatType.X_509,
                      spki,
                      Enums.CryptographicAlgorithm.EC,
                      bits),
                  "q",
                  Enums.CryptographicAlgorithm.EC,
                  bits);
      assertEquals(((ECPublicKey) pair.getPublic()).getW(), pub.getW(), curve);
      assertArrayEquals(point.getBytes(), Keys.encodePoint(pub), curve);
    }
  }

  @Test
  void sec1KeysThatDoNotNameTheirCurveAreRefused() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec("secp256r1"));
    ECPrivateKey key = (ECPrivateKey) g.generateKeyPair().getPrivate();
    // No parameters at all (SEC1 makes them optional), explicit curve parameters, and what Bouncy
    // Castle's PEM writer makes of a JDK key: the JDK's PKCS#8 body, whose SEC1 leaves the curve
    // to the outer AlgorithmIdentifier.
    byte[] none = new org.bouncycastle.asn1.sec.ECPrivateKey(256, key.getS()).getEncoded();
    byte[] explicit =
        new org.bouncycastle.asn1.sec.ECPrivateKey(
                256, key.getS(), new X962Parameters(ECNamedCurveTable.getByName("secp256r1")))
            .getEncoded();
    for (byte[] sec1 : List.of(none, explicit, pemBody(key, "EC PRIVATE KEY"))) {
      Ttlv p =
          payload(
              "e",
              true,
              Enums.KeyFormatType.ECPRIVATE_KEY,
              sec1,
              Enums.CryptographicAlgorithm.EC,
              256);
      InvalidKeySpecException e =
          assertThrows(
              InvalidKeySpecException.class,
              () -> Keys.privateKey(p, "e", Enums.CryptographicAlgorithm.EC, 256));
      assertEquals("Malformed private key material", e.getMessage());
    }
  }

  /** The DER body of the block Bouncy Castle's {@code JcaPEMWriter} writes for {@code key}. */
  private static byte[] pemBody(PrivateKey key, String label) throws Exception {
    StringWriter out = new StringWriter();
    try (JcaPEMWriter w = new JcaPEMWriter(out)) {
      w.writeObject(key);
    }
    try (PemReader r = new PemReader(new StringReader(out.toString()))) {
      var object = r.readPemObject();
      assertEquals(label, object.getType());
      return object.getContent();
    }
  }
}
