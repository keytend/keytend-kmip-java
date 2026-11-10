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

import dev.keytend.kmip.TestX509;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * The in-house PKCS#10 builder against Bouncy Castle: Bouncy Castle reads each request, verifies
 * its signature, finds the subject, key and names given, and encodes it to the same DER; a request
 * Bouncy Castle builds from the same input has the same CertificationRequestInfo. Also the checks
 * of an issued certificate ({@link TlsCertify#problem}).
 */
class Pkcs10Test {
  static final List<Pkcs10.AltName> NAMES =
      List.of(
          new Pkcs10.AltName(Pkcs10.AltName.DNS, "node1.cluster1.internal"),
          new Pkcs10.AltName(Pkcs10.AltName.IP, "10.0.0.11"),
          new Pkcs10.AltName(Pkcs10.AltName.IP, "fd00::11"),
          new Pkcs10.AltName(Pkcs10.AltName.URI, "spiffe://cluster1/node1"),
          new Pkcs10.AltName(Pkcs10.AltName.EMAIL, "ops@cluster1.example"));

  static KeyPair pair(String kind) throws Exception {
    if (kind.startsWith("RSA")) {
      KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
      g.initialize(Integer.parseInt(kind.substring(4)));
      return g.generateKeyPair();
    }
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec(kind));
    return g.generateKeyPair();
  }

  @ParameterizedTest
  @ValueSource(strings = {"RSA-2048", "RSA-3072", "secp256r1", "secp384r1", "secp521r1"})
  void bouncyCastleReadsVerifiesAndReEncodesTheRequest(String kind) throws Exception {
    KeyPair pair = pair(kind);
    X500Principal subject = new X500Principal("CN=node1,OU=db,O=cluster1,C=US");
    for (List<Pkcs10.AltName> names : List.of(List.<Pkcs10.AltName>of(), NAMES)) {
      byte[] der = Pkcs10.request(subject, pair.getPublic(), pair.getPrivate(), names);
      PKCS10CertificationRequest csr = new PKCS10CertificationRequest(der);
      assertTrue(
          csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(pair.getPublic())));
      assertArrayEquals(der, csr.getEncoded(), "DER, as Bouncy Castle encodes it");
      assertArrayEquals(subject.getEncoded(), csr.getSubject().getEncoded());
      assertArrayEquals(pair.getPublic().getEncoded(), csr.getSubjectPublicKeyInfo().getEncoded());
      assertEquals(
          kind.startsWith("RSA") ? Pkcs10.SHA256_WITH_RSA : Pkcs10.ECDSA_WITH_SHA256,
          csr.getSignatureAlgorithm().getAlgorithm().getId());
      Attribute[] requested = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
      if (names.isEmpty()) {
        assertEquals(0, csr.getAttributes().length);
        continue;
      }
      assertEquals(1, requested.length);
      Extensions extensions = Extensions.getInstance(requested[0].getAttrValues().getObjectAt(0));
      Extension san = extensions.getExtension(Extension.subjectAlternativeName);
      assertFalse(san.isCritical(), "a subject is given");
      assertEquals(expected(), GeneralNames.getInstance(san.getParsedValue()));
      // Bouncy Castle's own request from the same input: the same signed content.
      ExtensionsGenerator generator = new ExtensionsGenerator();
      generator.addExtension(Extension.subjectAlternativeName, false, expected());
      PKCS10CertificationRequest theirs =
          new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic())
              .addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, generator.generate())
              .build(
                  new JcaContentSignerBuilder(
                          kind.startsWith("RSA") ? "SHA256withRSA" : "SHA256withECDSA")
                      .build(pair.getPrivate()));
      assertArrayEquals(
          theirs.toASN1Structure().getCertificationRequestInfo().getEncoded(),
          csr.toASN1Structure().getCertificationRequestInfo().getEncoded());
      // RSA PKCS#1 v1.5 signatures are deterministic: the whole request is the same.
      if (kind.startsWith("RSA")) assertArrayEquals(theirs.getEncoded(), der);
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"RSA-2048", "secp256r1"})
  void anEmptySubjectMakesTheNamesCritical(String kind) throws Exception {
    KeyPair pair = pair(kind);
    byte[] der = Pkcs10.request(new X500Principal(""), pair.getPublic(), pair.getPrivate(), NAMES);
    PKCS10CertificationRequest csr = new PKCS10CertificationRequest(der);
    assertEquals(new X500Name(new org.bouncycastle.asn1.x500.RDN[0]), csr.getSubject());
    Extensions extensions =
        Extensions.getInstance(
            csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)[0]
                .getAttrValues()
                .getObjectAt(0));
    assertTrue(extensions.getExtension(Extension.subjectAlternativeName).isCritical());
    assertArrayEquals(der, csr.getEncoded());
    // The same signature over the two-argument form.
    byte[] plain = Pkcs10.request(new X500Principal("CN=x"), pair);
    assertTrue(
        new PKCS10CertificationRequest(plain)
            .isSignatureValid(new JcaContentVerifierProviderBuilder().build(pair.getPublic())));
  }

  @ParameterizedTest
  @ValueSource(strings = {"node1", "10.0.0", "1.2.3.256", "::g", ""})
  void onlyIpLiteralsAreTaken(String notAnAddress) {
    assertThrows(IllegalArgumentException.class, () -> Pkcs10.ipAddress(notAnAddress));
  }

  static GeneralNames expected() {
    return new GeneralNames(
        new GeneralName[] {
          new GeneralName(GeneralName.dNSName, "node1.cluster1.internal"),
          new GeneralName(GeneralName.iPAddress, "10.0.0.11"),
          new GeneralName(GeneralName.iPAddress, "fd00::11"),
          new GeneralName(GeneralName.uniformResourceIdentifier, "spiffe://cluster1/node1"),
          new GeneralName(GeneralName.rfc822Name, "ops@cluster1.example")
        });
  }

  @org.junit.jupiter.api.Test
  void theIssuedCertificateIsCheckedBeforeUse() throws Exception {
    KeyPair caKey = pair("secp256r1"), other = pair("secp256r1"), key = pair("secp256r1");
    Instant now = Instant.now();
    X509Certificate ca =
        TestX509.certificate("CA", caKey.getPublic()).selfSigned(caKey.getPrivate()).ca().build();
    X509Certificate otherCa =
        TestX509.certificate("CA", other.getPublic()).selfSigned(other.getPrivate()).ca().build();
    TlsCertify request =
        TlsCertify.issue(
            new X500Principal("CN=node1"),
            List.of(new Pkcs10.AltName(Pkcs10.AltName.DNS, "node1")),
            KeyPairSpec.ec(Curve.P_256),
            Duration.ofDays(20),
            null);
    // Without an issuer in the KMS, the chain is not checked: build the request's view by hand.
    java.lang.reflect.Field chain = TlsCertify.class.getDeclaredField("issuerChain");
    chain.setAccessible(true);
    chain.set(request, List.of(ca));
    Instant until = now.plus(Duration.ofDays(20));
    X509Certificate good = leaf("node1", key, ca, caKey, now, until, "node1", false);
    assertNull(request.problem(good, key.getPublic(), until, now));
    assertNull(request.problem(good, key.getPublic(), null, now));
    String why;
    why = request.problem(good, other.getPublic(), until, now).why();
    assertTrue(why.contains("not for the public key"), why);
    why =
        request
            .problem(
                leaf("node2", key, ca, caKey, now, until, "node1", false),
                key.getPublic(),
                until,
                now)
            .why();
    assertTrue(why.contains("subject"), why);
    why =
        request
            .problem(
                leaf("node1", key, ca, caKey, now, until, "node9", false),
                key.getPublic(),
                until,
                now)
            .why();
    assertTrue(why.contains("subject alternative names"), why);
    why =
        request
            .problem(
                leaf("node1", key, otherCa, other, now, until, "node1", false),
                key.getPublic(),
                until,
                now)
            .why();
    assertTrue(why.contains("not issued by"), why);
    why =
        request
            .problem(
                leaf("node1", key, ca, caKey, now, until, "node1", true),
                key.getPublic(),
                until,
                now)
            .why();
    assertTrue(why.contains("CA certificate"), why);
    X509Certificate expired =
        leaf(
            "node1",
            key,
            ca,
            caKey,
            now.minus(Duration.ofDays(10)),
            now.minus(Duration.ofDays(1)),
            "node1",
            false);
    assertTrue(
        request
            .problem(expired, key.getPublic(), null, now)
            .why()
            .contains("does not include now"));
    X509Certificate later =
        leaf("node1", key, ca, caKey, now.plus(Duration.ofHours(1)), until, "node1", false);
    assertTrue(
        request.problem(later, key.getPublic(), null, now).why().contains("does not include now"));
    // A notAfter a year off the Deactivation Date asked: the server ignored it.
    X509Certificate year =
        leaf("node1", key, ca, caKey, now, now.plus(Duration.ofDays(365)), "node1", false);
    TlsCertify.Problem ignored = request.problem(year, key.getPublic(), until, now);
    assertTrue(ignored.validity(), ignored.why());
    // Within the tolerance: a server that rounds.
    X509Certificate rounded =
        leaf("node1", key, ca, caKey, now, until.plusSeconds(90), "node1", false);
    assertNull(request.problem(rounded, key.getPublic(), until, now));
  }

  private static X509Certificate leaf(
      String cn,
      KeyPair key,
      X509Certificate ca,
      KeyPair caKey,
      Instant from,
      Instant to,
      String dns,
      boolean isCa) {
    TestX509.Builder b =
        TestX509.certificate(cn, key.getPublic())
            .issuedBy(ca, caKey.getPrivate())
            .validity(from, to)
            .dns(dns);
    if (isCa) b.ca();
    return b.build();
  }
}
