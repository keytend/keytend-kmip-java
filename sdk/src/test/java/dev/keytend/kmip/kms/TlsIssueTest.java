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

import static dev.keytend.kmip.kms.TlsIdentityTest.HOURLY;
import static dev.keytend.kmip.kms.TlsIdentityTest.SCHEDULER;
import static dev.keytend.kmip.kms.TlsIdentityTest.assertWhole;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.TestX509;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.stream.Stream;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * TLS identities the KMS issues with Certify: registering an issuer, issuing, reissuing with the
 * same or a new key, the validity asked, and the refusals, against the in-memory server's Certify.
 */
class TlsIssueTest {
  static final String NAME = "cassandra/node1";
  static final String CA_NAME = "cluster1/issuing-ca";
  static final CustomAttribute ROLE = CustomAttribute.client("tls-role");

  static Stream<Arguments> servers() {
    return TlsIdentityTest.servers();
  }

  /** An issuing CA valid for two years, which may sign certificates. */
  static final class Ca {
    final KeyPair key;
    final X509Certificate certificate;

    Ca(String name, KeyPair key) {
      this.key = key;
      this.certificate =
          TestX509.certificate(name, key.getPublic())
              .selfSigned(key.getPrivate())
              .ca()
              .keyUsage(TestPki.KEY_CERT_SIGN, TestPki.CRL_SIGN)
              .validity(
                  Instant.now().minus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(800)))
              .build();
    }

    static Ca ec(String name) throws Exception {
      return new Ca(name, TestPki.ec());
    }
  }

  static TlsIssuer register(Kms kms, Ca ca) {
    return kms.tls()
        .registerIssuer(ca.key.getPrivate(), ca.certificate)
        .named(CA_NAME)
        .custom(ROLE, "cluster1:ca")
        .register();
  }

  static TlsIdentityIssuance request(Kms kms, TlsIssuer ca) {
    return kms.tls()
        .issue(NAME)
        .keyPair(KeyPairSpec.ec(Curve.P_256))
        .subject("CN=node1,O=cluster1")
        .dnsNames("node1.cluster1.internal")
        .ipAddresses("10.0.0.11")
        .issuedBy(ca)
        .custom(ROLE, "cluster1:identity");
  }

  static X509Certificate certificate(Kms kms, KeyHandle h) {
    return TlsIdentities.certificate(kms, h.id());
  }

  /** The objects in an Active state, by identifier. */
  static Set<String> active(InMemoryKmipServer server) {
    Set<String> out = new java.util.TreeSet<>();
    for (String id : server.ids())
      if (server.state(id).orElseThrow() == KeyState.ACTIVE) out.add(id);
    return out;
  }

  @ParameterizedTest
  @MethodSource("servers")
  void registerIssuerLinksTheCaTheWayCertifyNeeds(KmipVersion version, boolean unique)
      throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    Ca ca = Ca.ec("Issuing CA");
    try (Kms kms = TlsIdentityTest.connect(server)) {
      TlsIssuer issuer = register(kms, ca);
      String cert = issuer.certificate().id(),
          pub = issuer.publicKey().id(),
          key = issuer.privateKey().id();
      assertEquals(List.of(CA_NAME), server.names(cert));
      assertEquals(List.of(), server.names(pub));
      assertEquals(List.of(), server.names(key));
      for (String id : List.of(cert, pub, key))
        assertEquals(KeyState.ACTIVE, server.state(id).orElseThrow(), id);
      assertEquals(List.of(pub), server.links(cert, LinkKind.PUBLIC_KEY));
      assertEquals(List.of(key), server.links(pub, LinkKind.PRIVATE_KEY));
      assertEquals(List.of(pub), server.links(key, LinkKind.PUBLIC_KEY));
      assertEquals(List.of(key), server.links(cert, LinkKind.PRIVATE_KEY));
      assertEquals(List.of(cert), server.links(key, LinkKind.CERTIFICATE));
      assertTrue(
          server.usages(key).contains(KeyUsage.CERTIFICATE_SIGN), server.usages(key).toString());
      assertTrue(server.usages(pub).contains(KeyUsage.VERIFY));
      assertEquals(List.of(issuer.certificate()), issuer.chain());
      TlsIssuer found = kms.tls().issuer(CA_NAME).orElseThrow();
      assertEquals(issuer.toString(), found.toString());
      assertTrue(kms.tls().issuer("nobody").isEmpty());
      assertTrue(TlsIdentityTest.allNames(server).stream().noneMatch(n -> n.contains(".issuing-")));
      // A repeat after success returns the issuer.
      assertEquals(issuer.toString(), register(kms, ca).toString());
      assertEquals(List.of(), server.violations());
    }
  }

  @Test
  void registerIssuerRefusesALeafAndAKeyOfAnotherCertificate() throws Exception {
    Ca ca = Ca.ec("Issuing CA");
    KeyPair other = TestPki.ec();
    X509Certificate leaf = TestPki.leaf("node", other, TestPki.ca("Root")).certificate();
    try (Kms kms = TlsIdentityTest.connect(InMemoryKmipServer.of(KmipVersion.V2_1))) {
      assertThrows(
          IllegalArgumentException.class, () -> kms.tls().registerIssuer(other.getPrivate(), leaf));
      assertThrows(
          IllegalArgumentException.class,
          () -> kms.tls().registerIssuer(other.getPrivate(), ca.certificate));
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void issueReissueAndReissueWithANewKey(KmipVersion version, boolean unique) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    Ca ca = Ca.ec("Issuing CA");
    try (Kms kms = TlsIdentityTest.connect(server)) {
      TlsIssuer issuer = register(kms, ca);
      TlsIdentityHandle h1 = request(kms, issuer).issue();
      String c1 = h1.certificate().id(), k1 = h1.privateKey().id();
      String p1 = server.links(k1, LinkKind.PUBLIC_KEY).get(0);
      assertEquals(List.of(NAME), server.names(c1));
      assertEquals(List.of(), server.names(k1));
      assertEquals(List.of(), server.names(p1));
      for (String id : List.of(c1, k1, p1))
        assertEquals(KeyState.ACTIVE, server.state(id).orElseThrow(), id);
      assertEquals(List.of(k1), server.links(c1, LinkKind.PRIVATE_KEY));
      assertEquals(List.of(p1), server.links(c1, LinkKind.PUBLIC_KEY));
      assertEquals(List.of(issuer.certificate().id()), server.links(c1, LinkKind.CERTIFICATE));
      assertEquals(List.of(c1), server.links(k1, LinkKind.CERTIFICATE));
      assertEquals(List.of(c1), server.links(p1, LinkKind.CERTIFICATE));
      assertEquals(List.of(h1.certificate(), issuer.certificate()), h1.chain());
      assertEquals("cluster1:identity", h1.certificate().attributes().custom().get(ROLE));
      X509Certificate leaf1 = certificate(kms, h1.certificate());
      assertEquals("CN=node1,O=cluster1", leaf1.getSubjectX500Principal().getName());
      assertEquals(ca.certificate.getSubjectX500Principal(), leaf1.getIssuerX500Principal());
      leaf1.verify(ca.certificate.getPublicKey());
      assertEquals(-1, leaf1.getBasicConstraints());
      assertEquals(
          List.of(List.of(2, "node1.cluster1.internal"), List.of(7, "10.0.0.11")),
          List.copyOf(leaf1.getSubjectAlternativeNames()));
      // Bouncy Castle reads the in-memory server's DER: signature and critical extensions.
      X509CertificateHolder holder = new X509CertificateHolder(leaf1.getEncoded());
      assertTrue(
          holder.isSignatureValid(
              new JcaContentVerifierProviderBuilder().build(ca.certificate.getPublicKey())));
      assertTrue(holder.getExtension(Extension.basicConstraints).isCritical());
      assertTrue(holder.getExtension(Extension.keyUsage).isCritical());
      assertFalse(holder.getExtension(Extension.subjectAlternativeName).isCritical());
      assertArrayEquals(leaf1.getEncoded(), holder.getEncoded());
      assertTrue(TlsIdentityTest.allNames(server).stream().noneMatch(n -> n.contains(".issuing-")));

      try (TlsIdentityFollower follower = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
        assertEquals(c1, assertWhole(follower).certificateId());

        // Same key.
        TlsIdentityHandle h2 = h1.reissue();
        String c2 = h2.certificate().id();
        assertNotEquals(c1, c2);
        assertEquals(k1, h2.privateKey().id());
        assertEquals(List.of(NAME), server.names(c2));
        assertEquals(List.of(), server.names(c1));
        assertEquals(KeyState.DEACTIVATED, server.state(c1).orElseThrow());
        assertEquals(KeyState.ACTIVE, server.state(k1).orElseThrow());
        assertEquals(KeyState.ACTIVE, server.state(p1).orElseThrow());
        assertEquals(List.of(c2), server.links(c1, LinkKind.REPLACEMENT));
        assertEquals(List.of(c1), server.links(c2, LinkKind.REPLACED));
        assertEquals(List.of(p1), server.links(c2, LinkKind.PUBLIC_KEY));
        assertTrue(server.links(k1, LinkKind.CERTIFICATE).contains(c2));
        X509Certificate leaf2 = certificate(kms, h2.certificate());
        assertEquals(leaf1.getSubjectX500Principal(), leaf2.getSubjectX500Principal());
        assertEquals(
            List.copyOf(leaf1.getSubjectAlternativeNames()),
            List.copyOf(leaf2.getSubjectAlternativeNames()));
        assertEquals(leaf1.getPublicKey(), leaf2.getPublicKey());
        assertEquals("cluster1:identity", h2.certificate().attributes().custom().get(ROLE));
        follower.refresh();
        assertEquals(c2, assertWhole(follower).certificateId());
        // A repeat after success, from the old handle, returns the identity.
        assertEquals(c2, h1.reissue().certificate().id());

        // A new key.
        TlsIdentityHandle h3 = h2.reissueWithNewKey();
        String c3 = h3.certificate().id(), k3 = h3.privateKey().id();
        String p3 = server.links(k3, LinkKind.PUBLIC_KEY).get(0);
        assertNotEquals(k1, k3);
        assertNotEquals(p1, p3);
        for (String id : List.of(c2, k1, p1))
          assertEquals(KeyState.DEACTIVATED, server.state(id).orElseThrow(), id);
        for (String id : List.of(c3, k3, p3))
          assertEquals(KeyState.ACTIVE, server.state(id).orElseThrow(), id);
        X509Certificate leaf3 = certificate(kms, h3.certificate());
        assertNotEquals(leaf2.getPublicKey(), leaf3.getPublicKey());
        assertEquals(leaf1.getSubjectX500Principal(), leaf3.getSubjectX500Principal());
        follower.refresh();
        assertEquals(c3, assertWhole(follower).certificateId());
        assertEquals(c3, h2.reissueWithNewKey().certificate().id());

        // The identity follows its issuer: kms.tls().identity reads it the same.
        assertEquals(h3.toString(), kms.tls().identity(NAME).orElseThrow().toString());
      }
      assertEquals(List.of(), server.violations());
    }
  }

  @Test
  void anRsaKeyPairAndARsaIssuer() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V1_4);
    Ca ca = new Ca("RSA Issuing CA", TestPki.rsa());
    try (Kms kms = TlsIdentityTest.connect(server)) {
      TlsIssuer issuer = register(kms, ca);
      TlsIdentityHandle h =
          kms.tls()
              .issue(NAME)
              .keyPair(KeyPairSpec.rsa(2048))
              .dnsNames("node1.cluster1.internal")
              .uris("spiffe://cluster1/node1")
              .emails("ops@cluster1.example")
              .issuedBy(issuer)
              .issue();
      X509Certificate leaf = certificate(kms, h.certificate());
      assertEquals("", leaf.getSubjectX500Principal().getName());
      // An empty subject: the subject alternative names are critical (RFC 5280, 4.2.1.6).
      assertTrue(leaf.getCriticalExtensionOIDs().contains("2.5.29.17"));
      assertEquals(3, leaf.getSubjectAlternativeNames().size());
      assertEquals("RSA", leaf.getPublicKey().getAlgorithm());
      TlsIdentityHandle again = h.reissueWithNewKey();
      assertEquals(
          2048,
          ((java.security.interfaces.RSAPublicKey)
                  certificate(kms, again.certificate()).getPublicKey())
              .getModulus()
              .bitLength());
      assertEquals(List.of(), server.violations());
    }
  }

  @Test
  void theRequestedValidityIsHonoredOrRefused() throws Exception {
    Ca ca = Ca.ec("Issuing CA");
    // A server that honors the dates, as the in-memory server does by default: the certificate
    // ends at the Deactivation Date asked.
    InMemoryKmipServer honors = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = TlsIdentityTest.connect(honors)) {
      TlsIssuer issuer = register(kms, ca);
      TlsIdentityHandle h = request(kms, issuer).validFor(Duration.ofDays(30)).issue();
      Instant notAfter = certificate(kms, h.certificate()).getNotAfter().toInstant();
      assertTrue(
          Duration.between(Instant.now().plus(Duration.ofDays(30)), notAfter).abs().toMinutes() < 2,
          notAfter.toString());
      TlsIdentityHandle again = h.reissue(TlsReissue.sameKey().validFor(Duration.ofDays(10)));
      Instant end = certificate(kms, again.certificate()).getNotAfter().toInstant();
      assertTrue(
          Duration.between(Instant.now().plus(Duration.ofDays(10)), end).abs().toMinutes() < 2);
      // A date after the issuer's notAfter is refused before anything is changed: the server
      // would refuse it, never cut it short.
      Set<String> before = Set.copyOf(honors.ids());
      for (TlsReissue how :
          List.of(
              TlsReissue.sameKey().validFor(Duration.ofDays(5000)),
              TlsReissue.newKey().validFor(Duration.ofDays(5000)))) {
        InvalidRequestException tooLong =
            assertThrows(InvalidRequestException.class, () -> again.reissue(how));
        assertTrue(
            tooLong.getMessage().contains("after the issuing CA's notAfter"), tooLong.getMessage());
        assertTrue(tooLong.getMessage().contains("Nothing was changed"), tooLong.getMessage());
      }
      InvalidRequestException firstTooLong =
          assertThrows(
              InvalidRequestException.class,
              () ->
                  kms.tls()
                      .issue("other/node")
                      .keyPair(KeyPairSpec.ec(Curve.P_256))
                      .subject("CN=other")
                      .issuedBy(issuer)
                      .validFor(Duration.ofDays(5000))
                      .issue());
      assertTrue(firstTooLong.getMessage().contains("CA's notAfter"), firstTooLong.getMessage());
      assertEquals(before, Set.copyOf(honors.ids()), "nothing made");
      assertEquals(
          again.certificate().id(), kms.tls().identity(NAME).orElseThrow().certificate().id());
    }
    // A server that ignores the dates (earlier keytend-kmip-server builds): the call refuses
    // the certificate, and leaves its objects.
    InMemoryKmipServer ignores = InMemoryKmipServer.of(KmipVersion.V2_1).certifyHonorsDates(false);
    try (Kms kms = TlsIdentityTest.connect(ignores)) {
      TlsIssuer issuer = register(kms, ca);
      Set<String> before = Set.copyOf(ignores.ids());
      UnsupportedException e =
          assertThrows(
              UnsupportedException.class,
              () -> request(kms, issuer).validFor(Duration.ofDays(30)).issue());
      assertTrue(e.getMessage().contains("does not honor the requested validity"), e.getMessage());
      List<String> left = new ArrayList<>(ignores.ids());
      left.removeAll(before);
      assertEquals(3, left.size(), left.toString());
      // The private key, activated to sign the request, then the public key and the leaf.
      assertEquals(ObjectKind.PRIVATE_KEY, ignores.kind(left.get(0)).orElseThrow());
      assertEquals(KeyState.ACTIVE, ignores.state(left.get(0)).orElseThrow());
      assertTrue(e.getMessage().contains("which signed the certificate request"), e.getMessage());
      for (String id : left) {
        if (!id.equals(left.get(0)))
          assertEquals(KeyState.PRE_ACTIVE, ignores.state(id).orElseThrow(), id);
        assertTrue(e.getMessage().contains(id), e.getMessage());
        assertFalse(ignores.names(id).contains(NAME));
      }
      assertTrue(kms.tls().identity(NAME).isEmpty());
      // Without a validity, the server's own applies.
      TlsIdentityHandle h = request(kms, issuer).issue();
      Instant notAfter = certificate(kms, h.certificate()).getNotAfter().toInstant();
      assertTrue(notAfter.isAfter(Instant.now().plus(Duration.ofDays(360))));
      // A reissue asking for a validity is refused the same way, and the identity stays.
      assertThrows(
          UnsupportedException.class,
          () -> h.reissue(TlsReissue.newKey().validFor(Duration.ofDays(30))));
      assertEquals(h.certificate().id(), kms.tls().identity(NAME).orElseThrow().certificate().id());
      assertEquals(KeyState.ACTIVE, ignores.state(h.certificate().id()).orElseThrow());
    }
  }

  @Test
  void theIssuedDatesAreCheckedByTheKmsClockWithinTheTolerance() throws Exception {
    Ca ca = Ca.ec("Issuing CA");
    // A server that ignores the dates issues from its own clock: notBefore its time, notAfter a
    // year later. The Kms's clock, which the call checks the certificate by, is set off from it.
    Duration year = Duration.ofDays(365);
    for (long minutes : new long[] {-4, 4, -6, 6}) {
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1).certifyHonorsDates(false);
      try (Kms kms = TlsIdentityTest.connect(server)) {
        TlsIssuer issuer = register(kms, ca);
        Duration off = Duration.ofMinutes(minutes);
        kms.clock(java.time.Clock.offset(java.time.Clock.systemUTC(), off));
        if (Math.abs(minutes) < TlsCertify.TOLERANCE.toMinutes()) {
          // Within the tolerance either way: the notBefore and the notAfter pass.
          TlsIdentityHandle h = request(kms, issuer).validFor(year).issue();
          assertNotNull(certificate(kms, h.certificate()), "off " + off);
        } else if (minutes < 0) {
          // The Kms's clock behind: the notBefore is more than the tolerance ahead of it.
          KmsException e =
              assertThrows(KmsException.class, () -> request(kms, issuer).validFor(year).issue());
          assertTrue(e.getMessage().contains("which does not include now"), e.getMessage());
        } else {
          // The Kms's clock ahead: the notAfter is more than the tolerance before the date asked.
          UnsupportedException e =
              assertThrows(
                  UnsupportedException.class, () -> request(kms, issuer).validFor(year).issue());
          assertTrue(
              e.getMessage().contains("does not honor the requested validity"), e.getMessage());
        }
      }
    }
  }

  /** A clock the test moves forward, for the Kms ({@link Kms#clock}). */
  static final class MovingClock extends java.time.Clock {
    volatile Duration ahead = Duration.ZERO;

    @Override
    public java.time.ZoneId getZone() {
      return java.time.ZoneOffset.UTC;
    }

    @Override
    public java.time.Clock withZone(java.time.ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return Instant.now().plus(ahead);
    }
  }

  static boolean has(Ttlv request, Operation... operations) {
    for (Ttlv item : request.children(Tag.BATCH_ITEM)) {
      int op = item.child(Tag.OPERATION).map(Ttlv::intValue).orElse(0);
      for (Operation o : operations) if (o.code() == op) return true;
    }
    return false;
  }

  /**
   * The issued certificate is checked by the Kms's clock after Certify, not by the time the
   * validity was asked from, and again just before the switch: a certificate that expires while
   * the server is slow, or between the checks and the switch, is refused, and the certificate it
   * would replace stays Active and named.
   */
  @Test
  void aCertificateThatExpiresBeforeTheSwitchIsRefused() throws Exception {
    Ca ca = Ca.ec("Issuing CA");
    Duration day = Duration.ofDays(1), twoDays = Duration.ofDays(2);
    // While Certify is processed; and once the checks are done, at the first link.
    for (boolean duringCertify : new boolean[] {true, false}) {
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      MovingClock clock = new MovingClock();
      try (Kms kms = TlsIdentityTest.connect(server)) {
        kms.clock(clock);
        TlsIssuer issuer = register(kms, ca);
        TlsIdentityHandle h = request(kms, issuer).issue();
        String c1 = h.certificate().id();
        java.util.concurrent.atomic.AtomicBoolean certified =
            new java.util.concurrent.atomic.AtomicBoolean();
        server.injectAfterProcessing(
            request -> {
              if (has(request, Operation.CERTIFY)) {
                certified.set(true);
                if (duringCertify) clock.ahead = twoDays;
              } else if (!duringCertify
                  && certified.get()
                  && has(
                      request,
                      Operation.ADD_ATTRIBUTE,
                      Operation.SET_ATTRIBUTE,
                      Operation.MODIFY_ATTRIBUTE)) clock.ahead = twoDays;
              return null;
            });
        KeyMismatchException e =
            assertThrows(
                KeyMismatchException.class, () -> h.reissue(TlsReissue.newKey().validFor(day)));
        server.injectAfterProcessing(null);
        assertTrue(
            e.getMessage()
                .contains(duringCertify ? "which does not include now" : "before the switch"),
            e.getMessage());
        assertEquals(KeyState.ACTIVE, server.state(c1).orElseThrow());
        assertEquals(List.of(NAME), server.names(c1));
        assertEquals(List.of(), server.links(c1, LinkKind.REPLACEMENT));
        assertEquals(c1, kms.tls().identity(NAME).orElseThrow().certificate().id());
      }
    }
  }

  /**
   * A repeat that finds the switch made, to a certificate that expired since, neither activates
   * it nor retires the certificate it replaces, which still works.
   */
  @Test
  void aRepeatDoesNotFinishASwitchToAnExpiredCertificate() throws Exception {
    Ca ca = Ca.ec("Issuing CA");
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    MovingClock clock = new MovingClock();
    try (Kms kms = TlsIdentityTest.connect(server)) {
      kms.clock(clock);
      TlsIssuer issuer = register(kms, ca);
      TlsIdentityHandle h = request(kms, issuer).issue();
      String c1 = h.certificate().id();
      // A same-key reissue stops after its switch, at the Activate of the new certificate.
      server.failNext(ServerOperation.ACTIVATE, Fault.SERVER_FAILURE);
      assertThrows(
          KmsException.class, () -> h.reissue(TlsReissue.sameKey().validFor(Duration.ofDays(1))));
      String c2 = server.links(c1, LinkKind.REPLACEMENT).get(0);
      assertEquals(KeyState.PRE_ACTIVE, server.state(c2).orElseThrow());
      clock.ahead = Duration.ofDays(2);
      StateConflictException e =
          assertThrows(
              StateConflictException.class,
              () -> h.reissue(TlsReissue.sameKey().validFor(Duration.ofDays(1))));
      assertTrue(e.getMessage().contains("expired at"), e.getMessage());
      assertTrue(e.getMessage().contains("nothing was changed"), e.getMessage());
      assertTrue(e.getMessage().contains("Replacement Object link to " + c2), e.getMessage());
      assertEquals(KeyState.ACTIVE, server.state(c1).orElseThrow());
      assertEquals(KeyState.PRE_ACTIVE, server.state(c2).orElseThrow());
    }
  }

  /**
   * A repeat of a reissue that finished, once its certificate has expired: the advice follows the
   * certificate it replaced as it is now, retired, and says to reissue, not to undo a switch.
   */
  @Test
  void aRepeatOfAFinishedReissueAfterItsCertificateExpiredSaysToReissue() throws Exception {
    Ca ca = Ca.ec("Issuing CA");
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    MovingClock clock = new MovingClock();
    try (Kms kms = TlsIdentityTest.connect(server)) {
      kms.clock(clock);
      TlsIssuer issuer = register(kms, ca);
      TlsIdentityHandle h = request(kms, issuer).issue();
      String c1 = h.certificate().id();
      TlsIdentityHandle done = h.reissue(TlsReissue.sameKey().validFor(Duration.ofDays(1)));
      String c2 = done.certificate().id();
      assertEquals(KeyState.DEACTIVATED, server.state(c1).orElseThrow());
      clock.ahead = Duration.ofDays(2);
      StateConflictException e =
          assertThrows(
              StateConflictException.class,
              () -> h.reissue(TlsReissue.sameKey().validFor(Duration.ofDays(1))));
      String m = e.getMessage();
      assertTrue(m.contains(c2 + ", which an earlier call's switch made"), m);
      assertTrue(m.contains("expired at"), m);
      assertTrue(m.contains("The earlier call finished"), m);
      assertTrue(m.contains(c1 + " is DEACTIVATED"), m);
      assertTrue(m.contains(c2 + " has expired since"), m);
      assertTrue(m.contains("Reissue the identity for a certificate that works"), m);
      assertFalse(m.contains("still Active"), m);
      assertFalse(m.contains("Replacement Object link"), m);
      assertTrue(m.contains("nothing was changed"), m);
      assertEquals(KeyState.ACTIVE, server.state(c2).orElseThrow());
      assertEquals(KeyState.DEACTIVATED, server.state(c1).orElseThrow());
    }
  }

  /**
   * A repeat that finds the switch made to a certificate that expired since, after another caller
   * retired the certificate it replaced: undoing the switch would leave nothing that works, so the
   * advice is to reissue.
   */
  @Test
  void aRepeatAfterTheReplacedCertificateWasRetiredSaysToReissue() throws Exception {
    Ca ca = Ca.ec("Issuing CA");
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    MovingClock clock = new MovingClock();
    try (Kms kms = TlsIdentityTest.connect(server)) {
      kms.clock(clock);
      TlsIssuer issuer = register(kms, ca);
      TlsIdentityHandle h = request(kms, issuer).issue();
      String c1 = h.certificate().id();
      server.failNext(ServerOperation.ACTIVATE, Fault.SERVER_FAILURE);
      assertThrows(
          KmsException.class, () -> h.reissue(TlsReissue.sameKey().validFor(Duration.ofDays(1))));
      String c2 = server.links(c1, LinkKind.REPLACEMENT).get(0);
      kms.keys().handle(c1).deactivate(RevocationReason.superseded("by hand"));
      clock.ahead = Duration.ofDays(2);
      StateConflictException e =
          assertThrows(
              StateConflictException.class,
              () -> h.reissue(TlsReissue.sameKey().validFor(Duration.ofDays(1))));
      String m = e.getMessage();
      assertTrue(m.contains("does not activate it"), m);
      assertTrue(m.contains(c1 + " is DEACTIVATED"), m);
      assertTrue(m.contains("Reissue the identity for a certificate that works"), m);
      assertFalse(m.contains("still Active"), m);
      assertFalse(m.contains("The earlier call finished"), m);
      assertEquals(KeyState.PRE_ACTIVE, server.state(c2).orElseThrow());
    }
  }

  /**
   * A call whose certificate expires after its switch, on a server that answers Not Found for the
   * certificate it replaced (a server that drops destroyed objects): that certificate is not taken
   * as Active, the message says it no longer exists, and the advice is to reissue, not to undo the
   * switch. The same when the new certificate reads as Not Found too.
   */
  @ParameterizedTest
  @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
  void aReplacedCertificateTheServerNoLongerHasIsNotTakenAsActive(boolean leafGone)
      throws Exception {
    Ca ca = Ca.ec("Issuing CA");
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    MovingClock clock = new MovingClock();
    java.util.concurrent.atomic.AtomicBoolean withheld =
        new java.util.concurrent.atomic.AtomicBoolean();
    // The first change after the switch is withheld by its check: from then on, with leafGone,
    // the new certificate reads as Not Found too (earlier, the call's own reads of it would stop
    // the call for another reason).
    KmsListener checks =
        new KmsListener() {
          @Override
          public void finished(KmsEvent event) {
            if (event.failure().map(f -> f.getMessage().contains("withheld")).orElse(false))
              withheld.set(true);
          }
        };
    try (Kms kms =
        Kms.connect(
            server
                .configure()
                .maximumVersion(KmipVersion.V3_0)
                .callTimeout(Duration.ofSeconds(10))
                .addListener(checks)
                .build())) {
      kms.clock(clock);
      TlsIssuer issuer = register(kms, ca);
      TlsIdentityHandle h = request(kms, issuer).issue();
      String c1 = h.certificate().id();
      java.util.concurrent.atomic.AtomicReference<String> c2 =
          new java.util.concurrent.atomic.AtomicReference<>();
      // Once the switch is made: the certificate expires, and the server no longer has c1.
      server.injectAfterProcessing(
          request -> {
            if (has(request, Operation.ADD_ATTRIBUTE) && replacementLink(request)) {
              c2.set(server.links(c1, LinkKind.REPLACEMENT).get(0));
              clock.ahead = Duration.ofDays(2);
            }
            return null;
          });
      server.injectBeforeProcessing(
          request -> {
            String leaf = c2.get();
            if (leaf != null
                && has(request, Operation.GET_ATTRIBUTES)
                && (holdsText(request, c1)
                    || (leafGone && withheld.get() && holdsText(request, leaf))))
              server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.NOT_FOUND);
            return null;
          });
      StateConflictException e =
          assertThrows(
              StateConflictException.class,
              () -> h.reissue(TlsReissue.sameKey().validFor(Duration.ofDays(1))));
      server.injectBeforeProcessing(null);
      server.injectAfterProcessing(null);
      String m = e.getMessage();
      assertTrue(m.contains(c2.get() + ", which this call's switch made"), m);
      assertTrue(m.contains("expired at"), m);
      assertTrue(m.contains("does not activate it"), m);
      assertTrue(m.contains(c1 + " no longer exists"), m);
      assertEquals(leafGone, m.contains(c2.get() + " no longer exists"), m);
      assertTrue(m.contains("Reissue the identity for a certificate that works"), m);
      assertFalse(m.contains("still Active"), m);
      assertFalse(m.contains("Replacement Object link"), m);
      assertFalse(m.contains("retires what it replaced"), m);
      // Nothing was retired: on this server c1 is still there, Active.
      assertEquals(KeyState.ACTIVE, server.state(c1).orElseThrow());
      assertEquals(KeyState.PRE_ACTIVE, server.state(c2.get()).orElseThrow());
    }
  }

  /** The three calls that issue a certificate: issue, reissue with the same key, with a new key. */
  enum Issuing {
    ISSUE,
    SAME_KEY,
    NEW_KEY
  }

  /** Whether {@code t} holds, at any depth, a Link Type of a Replacement Object link. */
  static boolean replacementLink(Ttlv t) {
    if (t.tag() == Tag.LINK_TYPE.code()
        && t.intValue() == dev.keytend.kmip.model.Enums.LinkType.REPLACEMENT_OBJECT_LINK.code())
      return true;
    if (t.type() != Ttlv.Type.STRUCTURE) return false;
    for (Ttlv c : t.children()) if (replacementLink(c)) return true;
    return false;
  }

  /** Whether {@code t} holds, at any depth, a text equal to {@code text}. */
  static boolean holdsText(Ttlv t, String text) {
    if (t.type() == Ttlv.Type.TEXT_STRING) return text.equals(t.textValue());
    if (t.type() != Ttlv.Type.STRUCTURE) return false;
    for (Ttlv c : t.children()) if (holdsText(c, text)) return true;
    return false;
  }

  /** The switch of {@code issuing}: the Replacement Object link, or an issue's name. */
  static boolean isSwitch(Issuing issuing, Ttlv request) {
    if (!has(request, Operation.ADD_ATTRIBUTE)) return false;
    return issuing == Issuing.ISSUE ? holdsText(request, NAME) : replacementLink(request);
  }

  /**
   * Runs {@code issuing} with a one-day validity on a new server, the Kms's clock moved two days
   * ahead once the server has processed request {@code at} (counted from 0 after the first issue
   * of a reissue); {@code at} below 0 moves nothing. Returns the requests, the identity's first
   * certificate (null for an issue), the server and what the call threw (null for none).
   */
  record Slow(List<Ttlv> requests, String first, InMemoryKmipServer server, Exception thrown) {}

  static Slow slowAt(Issuing issuing, int at, boolean unique) throws Exception {
    Ca ca = Ca.ec("Issuing CA");
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1).uniqueNames(unique);
    MovingClock clock = new MovingClock();
    List<Ttlv> requests = java.util.Collections.synchronizedList(new ArrayList<>());
    try (Kms kms = TlsIdentityTest.connect(server)) {
      kms.clock(clock);
      TlsIssuer issuer = register(kms, ca);
      TlsIdentityHandle h = issuing == Issuing.ISSUE ? null : request(kms, issuer).issue();
      server.injectAfterProcessing(
          request -> {
            if (requests.size() == at) clock.ahead = Duration.ofDays(2);
            requests.add(request);
            return null;
          });
      Exception thrown = null;
      try {
        switch (issuing) {
          case ISSUE -> request(kms, issuer).validFor(Duration.ofDays(1)).issue();
          case SAME_KEY -> h.reissue(TlsReissue.sameKey().validFor(Duration.ofDays(1)));
          case NEW_KEY -> h.reissue(TlsReissue.newKey().validFor(Duration.ofDays(1)));
        }
      } catch (KmsException e) {
        thrown = e;
      }
      server.injectAfterProcessing(null);
      return new Slow(
          List.copyOf(requests), h == null ? null : h.certificate().id(), server, thrown);
    }
  }

  /**
   * An issued certificate that expires while a reply is slow, at any exchange from the read just
   * before the switch until the first deactivation (for an issue, until its certificate's
   * Activate): the call stops before it activates the
   * certificate, moves the name, or deactivates what it replaced, which stays Active and, while
   * the new certificate is not Active, named and presented. Before the switch, nothing of the
   * identity changed; after it, the message says how to undo the switch.
   */
  @ParameterizedTest
  @org.junit.jupiter.params.provider.CsvSource({
    "ISSUE, false",
    "ISSUE, true",
    "SAME_KEY, false",
    "SAME_KEY, true",
    "NEW_KEY, false",
    "NEW_KEY, true"
  })
  void aCertificateThatExpiresAfterAnyExchangeAroundTheSwitchIsNotActivated(
      Issuing issuing, boolean unique) throws Exception {
    // A run where nothing expires: where the switch and the first deactivation are.
    Slow plain = slowAt(issuing, -1, unique);
    assertNull(plain.thrown(), () -> String.valueOf(plain.thrown()));
    int sw = -1, end = plain.requests().size();
    for (int i = 0; i < plain.requests().size(); i++) {
      Ttlv r = plain.requests().get(i);
      if (sw < 0 && isSwitch(issuing, r)) sw = i;
      if (sw >= 0 && has(r, Operation.REVOKE)) {
        end = i;
        break;
      }
    }
    assertTrue(sw > 0, "no switch");
    // An issue replaces nothing: it is done once its certificate is activated, the last Activate.
    if (issuing == Issuing.ISSUE)
      for (int i = plain.requests().size() - 1; i > sw; i--)
        if (has(plain.requests().get(i), Operation.ACTIVATE)) {
          end = i;
          break;
        }
    for (int at = sw - 1; at < end; at++) {
      Slow slow = slowAt(issuing, at, unique);
      String where = issuing + " slow at request " + at + " (switch at " + sw + ")";
      assertNotNull(slow.thrown(), where);
      InMemoryKmipServer server = slow.server();
      String m = slow.thrown().getMessage();
      assertTrue(m.contains("expired at"), where + ": " + m);
      if (at < sw) {
        // The read just before the switch: refused before it, nothing of the identity changed.
        assertInstanceOf(KeyMismatchException.class, slow.thrown(), where);
        assertTrue(m.contains("before the switch"), where + ": " + m);
        if (slow.first() != null)
          assertEquals(List.of(), server.links(slow.first(), LinkKind.REPLACEMENT), where);
        else for (String id : server.ids()) assertFalse(server.names(id).contains(NAME), where);
        continue;
      }
      StateConflictException e = assertInstanceOf(StateConflictException.class, slow.thrown());
      assertTrue(m.contains("this call's switch"), where + ": " + m);
      String leaf;
      if (slow.first() == null) {
        leaf =
            server.ids().stream()
                .filter(id -> server.names(id).contains(NAME))
                .findFirst()
                .orElseThrow();
        // An issue activates its certificate last and has nothing to retire.
        assertEquals(KeyState.PRE_ACTIVE, server.state(leaf).orElseThrow(), where);
        assertTrue(m.contains("does not activate it"), where + ": " + m);
        assertTrue(m.contains("take the name " + NAME + " off " + leaf), where + ": " + m);
        continue;
      }
      String c1 = slow.first();
      leaf = server.links(c1, LinkKind.REPLACEMENT).get(0);
      assertEquals(leaf, e.objectId().orElseThrow(), where);
      // What the certificate replaced still works: it is Active.
      assertEquals(KeyState.ACTIVE, server.state(c1).orElseThrow(), where);
      if (server.state(leaf).orElseThrow() == KeyState.PRE_ACTIVE) {
        assertEquals(List.of(NAME), server.names(c1), where);
        assertTrue(m.contains("neither activates it nor retires"), where + ": " + m);
        assertTrue(m.contains("Replacement Object link to " + leaf), where + ": " + m);
        try (Kms kms = TlsIdentityTest.connect(server)) {
          assertEquals(c1, kms.tls().identity(NAME).orElseThrow().certificate().id(), where);
        }
      } else {
        assertTrue(m.contains("does not retire what it replaced"), where + ": " + m);
        assertTrue(m.contains("To present " + c1 + " again"), where + ": " + m);
        assertTrue(m.contains("revoke " + leaf), where + ": " + m);
      }
    }
  }

  @Test
  void reissueIfExpiresWithinReissuesOnlyWhenDue() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Ca ca = Ca.ec("Issuing CA");
    try (Kms kms = TlsIdentityTest.connect(server)) {
      TlsIdentityHandle h = request(kms, register(kms, ca)).issue();
      assertSame(h, h.reissueIfExpiresWithin(Duration.ofDays(30)));
      TlsIdentityHandle due = h.reissueIfExpiresWithin(Duration.ofDays(400));
      assertNotEquals(h.certificate().id(), due.certificate().id());
      assertEquals(h.privateKey().id(), due.privateKey().id());
      TlsIdentityHandle rekeyed =
          due.reissueIfExpiresWithin(Duration.ofDays(400), TlsReissue.newKey());
      assertNotEquals(due.privateKey().id(), rekeyed.privateKey().id());
      assertThrows(
          IllegalArgumentException.class,
          () -> rekeyed.reissueIfExpiresWithin(Duration.ofDays(-1)));
    }
  }

  /**
   * Whether the certificate expires within the window is read by the Kms's clock, not the
   * machine's: a clock ahead makes it due sooner, one behind later.
   */
  @Test
  void reissueIfExpiresWithinReadsTheKmsClock() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Ca ca = Ca.ec("Issuing CA");
    MovingClock clock = new MovingClock();
    try (Kms kms = TlsIdentityTest.connect(server)) {
      kms.clock(clock);
      TlsIdentityHandle h = request(kms, register(kms, ca)).issue();
      Duration left =
          Duration.between(
              Instant.now(), certificate(kms, h.certificate()).getNotAfter().toInstant());
      assertTrue(left.compareTo(Duration.ofDays(60)) > 0, left.toString());
      // By the machine's clock it expires after 30 days; by the Kms's, 20 days ahead of that, not.
      clock.ahead = left.minus(Duration.ofDays(20));
      TlsIdentityHandle due = h.reissueIfExpiresWithin(Duration.ofDays(30));
      assertNotEquals(h.certificate().id(), due.certificate().id());
      // By the machine's clock it expires within the window; by the Kms's, 30 days behind, not.
      clock.ahead = Duration.ofDays(-30);
      Duration window =
          Duration.between(
                  Instant.now(), certificate(kms, due.certificate()).getNotAfter().toInstant())
              .plus(Duration.ofDays(10));
      assertSame(due, due.reissueIfExpiresWithin(window));
      clock.ahead = Duration.ZERO;
      assertNotEquals(
          due.certificate().id(), due.reissueIfExpiresWithin(window).certificate().id());
    }
  }

  @Test
  void reissueMovesToAnotherIssuer() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1).uniqueNames(true);
    Ca first = Ca.ec("First CA"), second = Ca.ec("Second CA");
    try (Kms kms = TlsIdentityTest.connect(server)) {
      TlsIssuer one = register(kms, first);
      TlsIssuer two =
          kms.tls()
              .registerIssuer(second.key.getPrivate(), second.certificate)
              .named("cluster1/next-ca")
              .register();
      TlsIdentityHandle h = request(kms, one).issue();
      TlsIdentityHandle moved = h.reissue(TlsReissue.sameKey().issuedBy(two));
      X509Certificate leaf = certificate(kms, moved.certificate());
      assertEquals(second.certificate.getSubjectX500Principal(), leaf.getIssuerX500Principal());
      assertEquals(List.of(moved.certificate(), two.certificate()), moved.chain());
      // The next reissue keeps the issuer the certificate links to.
      TlsIdentityHandle next = moved.reissue();
      assertEquals(
          second.certificate.getSubjectX500Principal(),
          certificate(kms, next.certificate()).getIssuerX500Principal());
    }
  }

  @Test
  void aRegisteredIdentityIsReissuedWithANewKey() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Ca ca = Ca.ec("Issuing CA");
    TlsIdentityTest.Pki pki = new TlsIdentityTest.Pki();
    KeyPair k = TestPki.ec();
    TestPki.Issued leaf = pki.leaf("node1", k);
    try (Kms kms = TlsIdentityTest.connect(server)) {
      TlsIssuer issuer = register(kms, ca);
      TlsIdentityHandle registered =
          kms.tls().register(k.getPrivate(), pki.chain(leaf)).named(NAME).register();
      StateConflictException noPublicKey =
          assertThrows(StateConflictException.class, registered::reissue);
      assertTrue(
          noPublicKey.getMessage().contains("reissueWithNewKey()"), noPublicKey.getMessage());
      assertEquals(
          registered.certificate().id(), kms.tls().identity(NAME).orElseThrow().certificate().id());
      TlsIdentityHandle issued = registered.reissue(TlsReissue.newKey().issuedBy(issuer));
      assertEquals(KeyState.DEACTIVATED, server.state(registered.certificate().id()).orElseThrow());
      assertEquals(KeyState.DEACTIVATED, server.state(registered.privateKey().id()).orElseThrow());
      assertEquals(
          leaf.certificate().getSubjectX500Principal(),
          certificate(kms, issued.certificate()).getSubjectX500Principal());
      // Now it has a public key object: a same-key reissue works.
      assertNotEquals(issued.certificate().id(), issued.reissue().certificate().id());
    }
  }

  @Test
  void certifyRefusalsLeaveTheCallsObjects() throws Exception {
    Ca ca = Ca.ec("Issuing CA");
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = TlsIdentityTest.connect(server)) {
      Set<String> before = Set.copyOf(server.ids());
      // Without an issuer: the in-memory server, as keytend-kmip-server, has no CA of its own.
      PartialCompletionException none =
          assertThrows(
              PartialCompletionException.class,
              () -> kms.tls().issue(NAME).subject("CN=node1").issue());
      assertInstanceOf(PermissionDeniedException.class, none.getCause());
      assertEquals(2, none.created().size());
      assertEquals(KeyState.ACTIVE, server.state(none.created().get(0).id()).orElseThrow());
      assertEquals(KeyState.PRE_ACTIVE, server.state(none.created().get(1).id()).orElseThrow());
      assertTrue(
          none.getMessage().contains("which signed the certificate request"), none.getMessage());
      assertTrue(kms.tls().identity(NAME).isEmpty());
      assertEquals(before.size() + 2, server.ids().size());
    }
    assertThrows(
        IllegalStateException.class,
        () -> {
          try (Kms kms = TlsIdentityTest.connect(server)) {
            kms.tls().issue(NAME).issue();
          }
        });
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          try (Kms kms = TlsIdentityTest.connect(server)) {
            kms.tls().issue(NAME).keyPair(KeyPairSpec.rsa(1024));
          }
        });
    assertThrows(
        IllegalArgumentException.class,
        () -> {
          try (Kms kms = TlsIdentityTest.connect(server)) {
            kms.tls().issue(NAME).ipAddresses("node1.example");
          }
        });
  }

  @Test
  void aNameInUseIsRefusedBeforeAnythingIsMade() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Ca ca = Ca.ec("Issuing CA");
    try (Kms kms = TlsIdentityTest.connect(server)) {
      TlsIssuer issuer = register(kms, ca);
      TlsIdentityHandle h = request(kms, issuer).issue();
      int objects = server.ids().size();
      // Another subject under the same name: the identity's name is taken.
      AlreadyExistsException e =
          assertThrows(
              AlreadyExistsException.class, () -> request(kms, issuer).subject("CN=other").issue());
      assertTrue(e.getMessage().contains("reissueWithNewKey()"), e.getMessage());
      assertEquals(objects, server.ids().size());
      // The same request again is a repeat after success: it returns the identity.
      assertEquals(h.certificate().id(), request(kms, issuer).issue().certificate().id());
      assertEquals(objects, server.ids().size());
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void lostRepliesOfCreateKeyPairAndCertifyAreReadBack(KmipVersion version, boolean unique)
      throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    Ca ca = Ca.ec("Issuing CA");
    try (Kms kms =
        Kms.connect(
            server
                .configure()
                .maximumVersion(KmipVersion.V3_0)
                .retryPolicy(RetryPolicy.none())
                .build())) {
      TlsIssuer issuer = register(kms, ca);
      int objects = server.ids().size();
      server.failNext(ServerOperation.CREATE_KEY_PAIR, Fault.REPLY_LOST);
      server.failNext(ServerOperation.CERTIFY, Fault.REPLY_LOST);
      TlsIdentityHandle h = request(kms, issuer).issue();
      assertEquals(objects + 3, server.ids().size());
      server.failNext(ServerOperation.CERTIFY, Fault.REPLY_LOST);
      TlsIdentityHandle again = h.reissue();
      assertEquals(objects + 4, server.ids().size());
      assertEquals(KeyState.ACTIVE, server.state(again.certificate().id()).orElseThrow());
      assertEquals(List.of(), server.violations());
    }
  }

  @Test
  void theNewKeyIsActivatedThenLeasedBeforeItSigns() throws Exception {
    InMemoryKmipServer server =
        InMemoryKmipServer.of(KmipVersion.V2_1).leaseTime(Duration.ofHours(1));
    Ca ca = Ca.ec("Issuing CA");
    try (Kms kms = TlsIdentityTest.connect(server)) {
      TlsIssuer issuer = register(kms, ca);
      List<String> leased = new ArrayList<>();
      int from = server.protocolRequests().size();
      TlsIdentityHandle h = request(kms, issuer).issue();
      List<Ttlv> sent = server.protocolRequests().subList(from, server.protocolRequests().size());
      int activate = -1, lease = -1, get = -1;
      for (int i = 0; i < sent.size(); i++) {
        Ttlv item = sent.get(i).require(Tag.BATCH_ITEM);
        int op = item.require(Tag.OPERATION).intValue();
        String target =
            item.require(Tag.REQUEST_PAYLOAD)
                .child(Tag.UNIQUE_IDENTIFIER)
                .map(Ttlv::textValue)
                .orElse("");
        if (!target.equals(h.privateKey().id())) continue;
        if (op == Operation.ACTIVATE.code() && activate < 0) activate = i;
        if (op == Operation.OBTAIN_LEASE.code() && lease < 0) lease = i;
        if (op == Operation.GET.code() && get < 0) get = i;
        leased.add(op + "");
      }
      assertTrue(
          activate >= 0 && lease > activate && get > lease,
          "activate " + activate + ", lease " + lease + ", get " + get + ": " + leased);
      // Where only Active objects are leased (keytend-kmip-server never leases a Pre-Active one),
      // the new key is leased all the same: it is Active when it signs.
      server.leasesOnlyForActive(true);
      TlsIdentityHandle again = h.reissueWithNewKey();
      assertNotEquals(h.privateKey().id(), again.privateKey().id());
      assertEquals(
          again.certificate().id(), kms.tls().identity(NAME).orElseThrow().certificate().id());
    }
  }

  /**
   * By default Certify takes the dates as keytend-kmip-server does: the Activation Date
   * is the notBefore and the Deactivation Date the notAfter, the stored certificate gets only the
   * dates asked (so without an Activation Date it stays Pre-Active), and the refusals are Invalid
   * Field.
   */
  @Test
  void certifyTakesTheDatesAsKeytendKmipServerDoes() throws Exception {
    Ca ca = Ca.ec("Issuing CA");
    Instant caEnd = ca.certificate.getNotAfter().toInstant();
    for (KmipVersion version : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0)) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version);
      try (Kms kms = TlsIdentityTest.connect(server)) {
        TlsIssuer issuer = register(kms, ca);
        Instant now = Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        Instant month = now.plus(Duration.ofDays(30)), week = now.plus(Duration.ofDays(7));
        // Deactivation Date only: notBefore now, notAfter the date; Pre-Active.
        String onlyEnd = certify(kms, issuer, null, month);
        X509Certificate c = TlsIdentities.certificate(kms, onlyEnd);
        assertEquals(month, c.getNotAfter().toInstant(), version.name());
        assertTrue(
            Duration.between(now, c.getNotBefore().toInstant()).abs().toSeconds() < 5,
            version.name());
        assertEquals(KeyState.PRE_ACTIVE, server.state(onlyEnd).orElseThrow(), version.name());
        assertEquals(
            month, kms.keys().read(onlyEnd).orElseThrow().deactivationDate().orElseThrow());
        assertTrue(kms.keys().read(onlyEnd).orElseThrow().activationDate().isEmpty());
        // Both dates: as given; Active once its Activation Date has come.
        String both = certify(kms, issuer, week, month);
        c = TlsIdentities.certificate(kms, both);
        assertEquals(week, c.getNotBefore().toInstant());
        assertEquals(month, c.getNotAfter().toInstant());
        assertEquals(KeyState.PRE_ACTIVE, server.state(both).orElseThrow());
        // Activation Date only: 365 days from it, cut short at the CA's notAfter.
        Instant late =
            caEnd.minus(Duration.ofDays(10)).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        c = TlsIdentities.certificate(kms, certify(kms, issuer, late, null));
        assertEquals(late, c.getNotBefore().toInstant());
        assertEquals(caEnd, c.getNotAfter().toInstant());
        // Neither: from now for 365 days.
        c = TlsIdentities.certificate(kms, certify(kms, issuer, null, null));
        assertTrue(c.getNotAfter().toInstant().isAfter(now.plus(Duration.ofDays(364))));
        // Invalid Field: a notAfter at or before the notBefore, an Activation Date at or after the
        // CA's notAfter, a Deactivation Date after it (never cut short).
        for (Instant[] dates :
            List.of(
                new Instant[] {null, now.minusSeconds(60)},
                new Instant[] {month, week},
                new Instant[] {
                  caEnd.truncatedTo(java.time.temporal.ChronoUnit.SECONDS).plusSeconds(1), null
                },
                new Instant[] {
                  null, caEnd.truncatedTo(java.time.temporal.ChronoUnit.SECONDS).plusSeconds(1)
                })) {
          InvalidRequestException e =
              assertThrows(
                  InvalidRequestException.class,
                  () -> certify(kms, issuer, dates[0], dates[1]),
                  version + " " + java.util.Arrays.toString(dates));
          assertEquals(KmsReason.INVALID_FIELD, e.serverReason().orElseThrow());
        }
      }
    }
  }

  /**
   * One Certify, at the protocol level: a new EC key pair, its PKCS#10 request, the issuer's
   * Certificate link and the dates given; the new certificate's identifier.
   */
  static String certify(Kms kms, TlsIssuer issuer, Instant activation, Instant deactivation)
      throws Exception {
    KeyPair pair = TestPki.ec();
    KeyHandle pub =
        kms.keys()
            .register(pair.getPublic())
            .named("certify/" + java.util.UUID.randomUUID())
            .usages(KeyUsage.VERIFY)
            .register();
    List<Ttlv> attributes = new ArrayList<>();
    attributes.add(
        dev.keytend.kmip.model.Attributes.link(
            dev.keytend.kmip.model.Enums.LinkType.CERTIFICATE_LINK, issuer.certificate().id()));
    if (activation != null)
      attributes.add(
          dev.keytend.kmip.model.Attributes.attribute(
              "Activation Date", Ttlv.dateTime(Tag.ACTIVATION_DATE, activation)));
    if (deactivation != null)
      attributes.add(
          dev.keytend.kmip.model.Attributes.attribute(
              "Deactivation Date", Ttlv.dateTime(Tag.DEACTIVATION_DATE, deactivation)));
    boolean legacy = kms.protocolVersion().legacyAttributes();
    byte[] csr = Pkcs10.request(new javax.security.auth.x500.X500Principal("CN=certify"), pair);
    dev.keytend.kmip.client.Request certify =
        dev.keytend.kmip.client.Requests.certify()
            .uniqueIdentifier(pub.id())
            .add(
                Ttlv.enumeration(
                    Tag.CERTIFICATE_REQUEST_TYPE,
                    dev.keytend.kmip.model.Enums.CertificateRequestType.PKCS_10))
            .add(Ttlv.bytes(legacy ? Tag.CERTIFICATE_REQUEST : Tag.CERTIFICATE_REQUEST_VALUE, csr))
            .template(attributes.toArray(Ttlv[]::new))
            .build();
    try {
      return kms.protocol().call(certify).uniqueIdentifier();
    } catch (dev.keytend.kmip.client.KmipException e) {
      throw Failures.classify(
          new Failures.Call("certify", false, null, false), kms.protocolVersion(), e);
    }
  }

  /**
   * A server that refuses the Deactivation Date asked with Invalid Field after the call made its
   * key pair (the client cannot see the CA's notAfter, or it moved): the refusal says what to do,
   * and lists what is left over; nothing of the identity changed.
   */
  @Test
  void aServerRefusalOfTheDateSaysWhatToDo() throws Exception {
    Ca ca = Ca.ec("Issuing CA");
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms setup = TlsIdentityTest.connect(server)) {
      TlsIssuer issuer = register(setup, ca);
      Set<String> before = Set.copyOf(server.ids());
      try (Kms kms =
          Kms.connect(
              server
                  .configure()
                  .retryPolicy(RetryPolicy.none())
                  .transport(
                      e ->
                          r -> {
                            for (Ttlv item : r.children(Tag.BATCH_ITEM))
                              if (item.require(Tag.OPERATION).intValue()
                                  == Operation.CERTIFY.code()) return refusal(r);
                            return server.exchange(r);
                          })
                  .build())) {
        InvalidRequestException e =
            assertThrows(
                InvalidRequestException.class,
                () -> request(kms, issuer).validFor(Duration.ofDays(30)).issue());
        assertTrue(e.getMessage().contains("refused Certify with Invalid Field"), e.getMessage());
        assertTrue(e.getMessage().contains("issuing CA's notAfter"), e.getMessage());
        // The validity is the likely cause, not the only one Invalid Field can mean.
        assertTrue(e.getMessage().contains("The likely cause"), e.getMessage());
        assertTrue(e.getMessage().contains("other faults of the request"), e.getMessage());
        assertTrue(e.getMessage().contains("leave validFor out"), e.getMessage());
        assertTrue(e.getMessage().contains("left over"), e.getMessage());
        List<String> left = new ArrayList<>(server.ids());
        left.removeAll(before);
        assertEquals(2, left.size(), left.toString());
        for (String id : left) assertTrue(e.getMessage().contains(id), e.getMessage());
        assertTrue(kms.tls().identity(NAME).isEmpty());
      }
    }
  }

  /** keytend-kmip-server's refusal of a Deactivation Date past the CA's notAfter, at KMIP 2.1. */
  static Ttlv refusal(Ttlv request) {
    Ttlv version = request.require(Tag.REQUEST_HEADER).require(Tag.PROTOCOL_VERSION);
    return Ttlv.structure(
        Tag.RESPONSE_MESSAGE,
        Ttlv.structure(
            Tag.RESPONSE_HEADER,
            version,
            Ttlv.dateTime(
                Tag.TIME_STAMP, Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS)),
            Ttlv.integer(Tag.BATCH_COUNT, 1)),
        Ttlv.structure(
            Tag.BATCH_ITEM,
            Ttlv.enumeration(Tag.OPERATION, Operation.CERTIFY.code()),
            Ttlv.enumeration(Tag.RESULT_STATUS, 1),
            Ttlv.enumeration(
                Tag.RESULT_REASON, dev.keytend.kmip.model.Enums.ResultReason.INVALID_FIELD),
            Ttlv.text(
                Tag.RESULT_MESSAGE,
                "The requested validity ends after the issuing CA's notAfter")));
  }
}
