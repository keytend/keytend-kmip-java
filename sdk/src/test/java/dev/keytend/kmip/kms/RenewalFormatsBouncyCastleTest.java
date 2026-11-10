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

import static org.junit.jupiter.api.Assertions.*;

import java.io.StringReader;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.spec.ECGenParameterSpec;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The SDK's own DER for a client certificate renewal, read by Bouncy Castle: the PKCS#10 request
 * ({@link Pkcs10}), the encrypted PKCS#8 key of the renewal files ({@link RenewalFiles}), and the
 * DER writer's elements ({@link Der}).
 */
class RenewalFormatsBouncyCastleTest {
  static final java.security.Provider BC = new org.bouncycastle.jce.provider.BouncyCastleProvider();

  static final X500Principal SUBJECT =
      new X500Principal("CN=orders-service, OU=payments, O=Example, C=US");

  static KeyPair pair(String kind) throws Exception {
    KeyPairGenerator g;
    switch (kind) {
      case "rsa" -> {
        g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
      }
      case "p256", "p384", "p521" -> {
        g = KeyPairGenerator.getInstance("EC");
        g.initialize(
            new ECGenParameterSpec(
                switch (kind) {
                  case "p256" -> "secp256r1";
                  case "p384" -> "secp384r1";
                  default -> "secp521r1";
                }));
      }
      default -> throw new IllegalArgumentException(kind);
    }
    return g.generateKeyPair();
  }

  @ParameterizedTest
  @ValueSource(strings = {"rsa", "p256", "p384", "p521"})
  void theRequestParsesAndVerifiesWithBouncyCastle(String kind) throws Exception {
    KeyPair pair = pair(kind);
    byte[] der = Pkcs10.request(SUBJECT, pair);
    PKCS10CertificationRequest request = new PKCS10CertificationRequest(der);
    assertArrayEquals(der, request.getEncoded(), "canonical DER: BC encodes it back the same");
    assertTrue(
        request.isSignatureValid(
            new JcaContentVerifierProviderBuilder()
                .setProvider(BC)
                .build(request.getSubjectPublicKeyInfo())),
        "self-signed with the new key");
    assertArrayEquals(
        pair.getPublic().getEncoded(), request.getSubjectPublicKeyInfo().getEncoded(), "the key");
    assertArrayEquals(SUBJECT.getEncoded(), request.getSubject().getEncoded(), "the subject");
    assertEquals(0, request.getAttributes().length, "no attributes");
    AlgorithmIdentifier signature = request.getSignatureAlgorithm();
    if (kind.equals("rsa")) {
      assertEquals(PKCSObjectIdentifiers.sha256WithRSAEncryption, signature.getAlgorithm());
      assertEquals(org.bouncycastle.asn1.DERNull.INSTANCE, signature.getParameters());
    } else {
      assertEquals(X9ObjectIdentifiers.ecdsa_with_SHA256, signature.getAlgorithm());
      assertNull(signature.getParameters(), "ECDSA has no parameters");
    }
    assertEquals(
        BigInteger.ZERO,
        request.toASN1Structure().getCertificationRequestInfo().getVersion().getValue());
  }

  @Test
  void aKeyOfAnotherAlgorithmGetsNoRequest() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
    assertThrows(
        java.security.GeneralSecurityException.class,
        () -> Pkcs10.request(SUBJECT, g.generateKeyPair()));
  }

  @ParameterizedTest
  @ValueSource(strings = {"rsa", "p256"})
  void theEncryptedKeyDecryptsWithBouncyCastleAndTheSdk(String kind, @TempDir Path dir)
      throws Exception {
    KeyPair pair = pair(kind);
    char[] password = "correct horse battery".toCharArray();
    byte[] encrypted = new RenewalFiles(null).encrypt(pair.getPrivate().getEncoded(), password);
    PKCS8EncryptedPrivateKeyInfo info = new PKCS8EncryptedPrivateKeyInfo(encrypted);
    assertEquals(PKCSObjectIdentifiers.id_PBES2, info.getEncryptionAlgorithm().getAlgorithm());
    byte[] bc =
        info.decryptPrivateKeyInfo(
                new JceOpenSSLPKCS8DecryptorProviderBuilder().setProvider(BC).build(password))
            .getEncoded();
    assertArrayEquals(pair.getPrivate().getEncoded(), bc, "Bouncy Castle decrypts it");
    // The PEM block, as the SDK writes it: Bouncy Castle's PEM reader and the SDK's own key reader.
    byte[] pem = RenewalFiles.pem("ENCRYPTED PRIVATE KEY", encrypted);
    try (PEMParser parser =
        new PEMParser(new StringReader(new String(pem, StandardCharsets.US_ASCII)))) {
      assertInstanceOf(PKCS8EncryptedPrivateKeyInfo.class, parser.readObject());
    }
    Path file = dir.resolve("key.pem");
    Files.write(file, pem);
    PrivateKey sdk = PemIdentity.privateKey(Files.readAllBytes(file), file, password);
    assertArrayEquals(pair.getPrivate().getEncoded(), sdk.getEncoded(), "the SDK decrypts it");
    assertThrows(
        IllegalArgumentException.class,
        () -> PemIdentity.privateKey(Files.readAllBytes(file), file, "wrong".toCharArray()));
  }

  @Test
  void derElementsMatchBouncyCastle() throws Exception {
    for (String oid :
        List.of(
            "1.2.840.113549.1.1.11",
            "1.2.840.10045.4.3.2",
            "2.16.840.1.101.3.4.1.42",
            "2.999.3",
            "0.39",
            "1.3.6.1.4.1.311.21.20",
            "2.25.329800735698586629295641978511506172918".substring(0, 20))) {
      assertArrayEquals(
          new ASN1ObjectIdentifier(oid).getEncoded(ASN1Encoding.DER), Der.oid(oid), oid);
    }
    for (long v : new long[] {0, 1, 127, 128, 255, 256, -1, -128, -129, 600_000, Long.MAX_VALUE})
      assertArrayEquals(new ASN1Integer(v).getEncoded(ASN1Encoding.DER), Der.integer(v), "" + v);
    byte[] big = new byte[300];
    java.util.Arrays.fill(big, (byte) 7);
    byte[] octets = Der.octetString(big);
    assertArrayEquals(
        new org.bouncycastle.asn1.DEROctetString(big).getEncoded(ASN1Encoding.DER), octets);
    assertEquals(ASN1Primitive.fromByteArray(octets).getEncoded(ASN1Encoding.DER).length, 304);
    for (String bad : List.of("1", "3.1", "1.40", "1.2.03", "1..2", "1.2.", "a.b"))
      assertThrows(IllegalArgumentException.class, () -> Der.oid(bad), bad);
    assertThrows(IllegalArgumentException.class, () -> Der.whole(new byte[] {0x30, 0x05, 0x01}));
    assertThrows(IllegalArgumentException.class, () -> Der.element(0x1f));
  }
}
