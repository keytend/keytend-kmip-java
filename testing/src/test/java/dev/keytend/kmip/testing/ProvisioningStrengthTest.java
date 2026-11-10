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

package dev.keytend.kmip.testing;

import static dev.keytend.kmip.testing.ProvisioningPurposeTest.KEY_CERT_SIGN;
import static dev.keytend.kmip.testing.ProvisioningPurposeTest.ca;
import static dev.keytend.kmip.testing.ProvisioningPurposeTest.element;
import static dev.keytend.kmip.testing.ProvisioningPurposeTest.extension;
import static dev.keytend.kmip.testing.ProvisioningPurposeTest.integer;
import static dev.keytend.kmip.testing.ProvisioningPurposeTest.keyUsage;
import static dev.keytend.kmip.testing.ProvisioningPurposeTest.name;
import static dev.keytend.kmip.testing.ProvisioningPurposeTest.oid;
import static dev.keytend.kmip.testing.ProvisioningPurposeTest.sequence;
import static dev.keytend.kmip.testing.ProvisioningPurposeTest.utc;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * keytend-kmip-server's certificate strength and curve checks, as the in-memory listener applies
 * them: to its provisioning CA at start ({@link Provisioning#weakness}) and to every certificate of
 * a new client certificate's path ({@link Provisioning#chainWeakness}).
 */
class ProvisioningStrengthTest {
  static final String WEAK_DIGEST = "is signed with a weak digest";

  final KeyPair root = ec("secp256r1");

  /** OpenSSL 3.5's EVP_PKEY_get_security_bits for RSA keys of these sizes. */
  @Test
  void rsaKeysAreRatedAsOpenSslRatesThem() {
    Map<Integer, Integer> openssl =
        Map.ofEntries(
            Map.entry(1024, 80),
            Map.entry(1100, 80),
            Map.entry(1536, 96),
            Map.entry(1800, 104),
            Map.entry(1950, 104),
            Map.entry(1962, 104),
            Map.entry(1963, 112),
            Map.entry(3990, 144),
            Map.entry(2000, 112),
            Map.entry(2047, 112),
            Map.entry(2048, 112),
            Map.entry(2304, 120),
            Map.entry(3000, 128),
            Map.entry(3072, 128),
            Map.entry(4096, 152),
            Map.entry(5000, 160),
            Map.entry(10000, 216),
            Map.entry(20000, 296));
    openssl.forEach(
        (n, bits) -> assertEquals(bits, Provisioning.rsaSecurityBits(n), n + "-bit modulus"));
  }

  @Test
  void otherKeysAreRatedByTheirSize() throws Exception {
    assertEquals(128, Provisioning.securityBits(ec("secp256r1").getPublic()));
    assertEquals(192, Provisioning.securityBits(ec("secp384r1").getPublic()));
    assertEquals(256, Provisioning.securityBits(ec("secp521r1").getPublic()));
    assertEquals(112, Provisioning.securityBits(rsa(2048).getPublic()));
    assertEquals(128, Provisioning.securityBits(generate("Ed25519").getPublic()));
    assertEquals(224, Provisioning.securityBits(generate("Ed448").getPublic()));
    assertEquals(128, Provisioning.securityBits(generate("X25519").getPublic()));
  }

  @Test
  void aKeyBelow112BitsIsWeak() throws Exception {
    KeyPair weak = rsa(1024);
    X509Certificate c = issued("CA", weak.getPublic(), ca(true), keyUsage(KEY_CERT_SIGN));
    assertEquals("key has 80-bit security, below 112", Provisioning.weakness(c));
    assertNull(Provisioning.weakness(issued("CA", rsa(2048).getPublic(), ca(true))));
    // The key comes first, whatever signs the certificate.
    assertEquals(
        "key has 80-bit security, below 112",
        Provisioning.weakness(
            certificate("CA", weak.getPublic(), "Root", root.getPrivate(), SHA1_ECDSA, ca(true))));
  }

  @Test
  void aWeakDigestCountsOnACertificateThatIsNotSelfIssued() throws Exception {
    KeyPair k = ec("secp256r1");
    assertEquals(
        WEAK_DIGEST,
        Provisioning.weakness(
            certificate("CA", k.getPublic(), "Root", root.getPrivate(), SHA1_ECDSA, ca(true))));
    KeyPair r = rsa(2048);
    assertEquals(
        WEAK_DIGEST,
        Provisioning.weakness(
            certificate("CA", k.getPublic(), "Root", r.getPrivate(), MD5_RSA, ca(true))));
    assertNull(
        Provisioning.weakness(
            certificate("CA", k.getPublic(), "Root", root.getPrivate(), SHA256_ECDSA, ca(true))));
    // Self-issued: its own subject, a Key Usage that allows keyCertSign (or none), its own key.
    assertNull(
        Provisioning.weakness(
            certificate(
                "Root", root.getPublic(), "Root", root.getPrivate(), SHA1_ECDSA, ca(true))));
    assertNull(
        Provisioning.weakness(
            certificate(
                "Root",
                root.getPublic(),
                "Root",
                root.getPrivate(),
                SHA1_ECDSA,
                ca(true),
                keyUsage(KEY_CERT_SIGN))));
    assertEquals(
        WEAK_DIGEST,
        Provisioning.weakness(
            certificate(
                "Root",
                root.getPublic(),
                "Root",
                root.getPrivate(),
                SHA1_ECDSA,
                ca(true),
                keyUsage(ProvisioningPurposeTest.CRL_SIGN))));
    // Its name, but signed by an RSA key's algorithm: OpenSSL does not take it as self-issued.
    assertEquals(
        WEAK_DIGEST,
        Provisioning.weakness(
            certificate("Root", k.getPublic(), "Root", r.getPrivate(), SHA1_RSA, ca(true))));
  }

  @Test
  void anAuthorityKeyIdentifierMustMatchForASelfIssuedCertificate() throws Exception {
    byte[] own = {1, 2, 3, 4}, other = {9, 9, 9, 9};
    assertNull(Provisioning.weakness(selfSha1(skid(own), akid(element(0x80, own)))));
    assertEquals(
        WEAK_DIGEST, Provisioning.weakness(selfSha1(skid(own), akid(element(0x80, other)))));
    // A key identifier with no Subject Key Identifier to compare with does not count.
    assertNull(Provisioning.weakness(selfSha1(akid(element(0x80, other)))));
    assertEquals(
        WEAK_DIGEST,
        Provisioning.weakness(selfSha1(akid(element(0x82, BigInteger.valueOf(7).toByteArray())))));
    assertNull(
        Provisioning.weakness(
            selfSha1(akid(element(0x82, BigInteger.valueOf(SERIAL).toByteArray())))));
    assertNull(Provisioning.weakness(selfSha1(akid(element(0xa1, element(0xa4, name("Root")))))));
    assertEquals(
        WEAK_DIGEST,
        Provisioning.weakness(selfSha1(akid(element(0xa1, element(0xa4, name("Other")))))));
  }

  @Test
  void aCurveTheServerDoesNotImplementIsUnsupported() throws Exception {
    assertTrue(Provisioning.supportedCurve(issued("CA", ec("secp256r1").getPublic())));
    assertTrue(Provisioning.supportedCurve(issued("CA", ec("secp521r1").getPublic())));
    assertTrue(Provisioning.supportedCurve(issued("CA", rsa(2048).getPublic())));
    assertTrue(Provisioning.supportedCurve(issued("CA", generate("Ed25519").getPublic())));
    // The JDK parses no certificate on these curves; the check reads the SubjectPublicKeyInfo.
    // secp256k1 and brainpoolP256r1 to P512t1 are implemented; secp224k1 and brainpoolP224r1 not.
    assertTrue(Provisioning.supportedCurve(onCurve("1.3.132.0.10")));
    assertTrue(Provisioning.supportedCurve(onCurve("1.3.36.3.3.2.8.1.1.7")));
    assertTrue(Provisioning.supportedCurve(onCurve("1.3.36.3.3.2.8.1.1.14")));
    assertFalse(Provisioning.supportedCurve(onCurve("1.3.132.0.32")));
    assertFalse(Provisioning.supportedCurve(onCurve("1.3.36.3.3.2.8.1.1.5")));
    // Parameters that are not a curve's name, or none, are not checked.
    byte[] point = Arrays.copyOfRange(p256(), p256().length - 68, p256().length);
    assertTrue(
        Provisioning.supportedCurve(
            sequence(sequence(oid("1.2.840.10045.2.1"), sequence()), point)));
    assertTrue(Provisioning.supportedCurve(sequence(sequence(oid("1.2.840.10045.2.1")), point)));
  }

  @Test
  void eachCertificateOfThePathIsCheckedByDepth() throws Exception {
    X509Certificate leaf = issued("client", ec("secp256r1").getPublic());
    X509Certificate strong = issued("CA", ec("secp384r1").getPublic(), ca(true));
    assertNull(Provisioning.chainWeakness(List.of(leaf, strong)));
    KeyPair weak = rsa(1024);
    X509Certificate weakRoot =
        certificate("Root", weak.getPublic(), "Root", weak.getPrivate(), SHA256_RSA, ca(true));
    assertEquals(
        "depth 2: key has 80-bit security, below 112",
        Provisioning.chainWeakness(List.of(leaf, strong, weakRoot)));
    X509Certificate sha1Ca =
        certificate(
            "CA", ec("secp256r1").getPublic(), "Root", root.getPrivate(), SHA1_ECDSA, ca(true));
    assertEquals(
        "depth 1: " + WEAK_DIGEST, Provisioning.chainWeakness(List.of(leaf, sha1Ca, weakRoot)));
  }

  // ---- certificates: DER, signed by the given algorithm ----

  record Algorithm(String jca, byte[] identifier) {}

  static final Algorithm
      SHA256_ECDSA = new Algorithm("SHA256withECDSA", sequence(oid("1.2.840.10045.4.3.2"))),
      SHA1_ECDSA = new Algorithm("SHA1withECDSA", sequence(oid("1.2.840.10045.4.1"))),
      SHA256_RSA = new Algorithm("SHA256withRSA", rsaAlgorithm("1.2.840.113549.1.1.11")),
      SHA1_RSA = new Algorithm("SHA1withRSA", rsaAlgorithm("1.2.840.113549.1.1.5")),
      MD5_RSA = new Algorithm("MD5withRSA", rsaAlgorithm("1.2.840.113549.1.1.4"));

  static final long SERIAL = 4242;

  private static byte[] rsaAlgorithm(String oid) {
    return sequence(oid(oid), new byte[] {0x05, 0x00});
  }

  /** A certificate for {@code key} that the root signs with SHA-256. */
  private X509Certificate issued(String subject, PublicKey key, byte[]... extensions)
      throws Exception {
    return certificate(subject, key, "Root", root.getPrivate(), SHA256_ECDSA, extensions);
  }

  /** The root's certificate, signed by itself with SHA-1, with {@code extensions}. */
  private X509Certificate selfSha1(byte[]... extensions) throws Exception {
    List<byte[]> all = new ArrayList<>(List.of(ca(true)));
    all.addAll(Arrays.asList(extensions));
    return certificate(
        "Root",
        root.getPublic(),
        "Root",
        root.getPrivate(),
        SHA1_ECDSA,
        all.toArray(byte[][]::new));
  }

  private static byte[] skid(byte[] id) {
    return extension("2.5.29.14", false, element(0x04, id));
  }

  private static byte[] akid(byte[]... fields) {
    return extension("2.5.29.35", false, sequence(fields));
  }

  private static X509Certificate certificate(
      String subject,
      PublicKey key,
      String issuer,
      PrivateKey signer,
      Algorithm algorithm,
      byte[]... extensions)
      throws Exception {
    List<byte[]> tbs = new ArrayList<>();
    tbs.add(element(0xa0, integer(BigInteger.TWO)));
    tbs.add(integer(BigInteger.valueOf(SERIAL)));
    tbs.add(algorithm.identifier());
    tbs.add(name(issuer));
    tbs.add(sequence(utc("250101000000Z"), utc("491231235959Z")));
    tbs.add(name(subject));
    tbs.add(key.getEncoded());
    if (extensions.length > 0) tbs.add(element(0xa3, sequence(extensions)));
    byte[] body = sequence(tbs.toArray(byte[][]::new));
    Signature s = Signature.getInstance(algorithm.jca());
    s.initSign(signer);
    s.update(body);
    byte[] der = sequence(body, algorithm.identifier(), element(0x03, new byte[] {0}, s.sign()));
    return (X509Certificate)
        CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
  }

  /** A SubjectPublicKeyInfo that names {@code curve}, with a P-256 point. */
  private static byte[] onCurve(String curve) {
    byte[] spki = p256();
    // The BIT STRING of the point is the last 68 bytes of a P-256 SubjectPublicKeyInfo.
    byte[] point = Arrays.copyOfRange(spki, spki.length - 68, spki.length);
    return sequence(sequence(oid("1.2.840.10045.2.1"), oid(curve)), point);
  }

  private static byte[] p256() {
    return ec("secp256r1").getPublic().getEncoded();
  }

  private static KeyPair ec(String curve) {
    try {
      KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
      g.initialize(new ECGenParameterSpec(curve));
      return g.generateKeyPair();
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static KeyPair rsa(int bits) throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(bits);
    return g.generateKeyPair();
  }

  private static KeyPair generate(String algorithm) throws Exception {
    return KeyPairGenerator.getInstance(algorithm).generateKeyPair();
  }
}
