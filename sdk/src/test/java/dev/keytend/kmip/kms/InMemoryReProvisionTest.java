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

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.KmipClient;
import dev.keytend.kmip.client.KmipException;
import dev.keytend.kmip.client.LocateRequest;
import dev.keytend.kmip.client.Request;
import dev.keytend.kmip.client.RequestOptions;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.client.Response;
import dev.keytend.kmip.client.Result;
import dev.keytend.kmip.model.Credentials;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Enums.ResultReason;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.ProtocolVersion;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.TlsListener;
import dev.keytend.kmip.transport.TlsTransport;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import javax.net.ssl.SSLContext;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The in-memory server's Re-Provision, at the protocol level: keytend-kmip-server's rules for the
 * message, the request and the retirement of the replaced certificate.
 */
class InMemoryReProvisionTest {
  /** A client on its own connection, with the PKI's client certificate. */
  static KmipClient client(TlsListener tls, SSLContext context) {
    TlsTransport t =
        TlsTransport.builder("localhost", tls.port(), context)
            .pool(1, java.time.Duration.ofMinutes(1))
            .build();
    return new KmipClient(t, ProtocolVersion.V2_1, RequestOptions.DEFAULT);
  }

  static final Request GET = Requests.get().build();

  static ResultReason reason(Result r) {
    return r.reasonEnum().orElseThrow();
  }

  @Test
  void theMessageAndRequestRules(@TempDir Path dir) throws Exception {
    ClientCertificateRenewalTest.Pki pki = new ClientCertificateRenewalTest.Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    SSLContext f = KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem);
    try (TlsListener tls = pki.listener(server).start();
        KmipClient c = client(tls, f)) {
      // Query lists it on a listener with a provisioning CA.
      Result query = c.query(Enums.QueryFunction.QUERY_OPERATIONS);
      assertTrue(
          query.payload().orElseThrow().children(OPERATION).stream()
              .anyMatch(o -> o.intValue() == Operation.RE_PROVISION.code()));
      // Without a Get of the ID Placeholder: Invalid Field before anything is issued.
      Response alone = c.batch(List.of(reProvision(TestPki.ec(), pki)));
      assertEquals(ResultReason.INVALID_FIELD, reason(alone.results().get(0)));
      // Undo cannot be honored.
      Response undo =
          c.batch(
              List.of(reProvision(TestPki.ec(), pki), GET),
              RequestOptions.builder()
                  .batchErrorContinuation(Enums.BatchErrorContinuation.UNDO)
                  .build());
      assertEquals(ResultReason.FEATURE_NOT_SUPPORTED, reason(undo.results().get(0)));
      // Header credentials are refused.
      Response credentials =
          c.batch(
              List.of(reProvision(TestPki.ec(), pki), GET),
              RequestOptions.DEFAULT.authentication(
                  dev.keytend.kmip.model.Credentials.usernamePassword("app", "pw".toCharArray())));
      assertEquals(ResultReason.PERMISSION_DENIED, reason(credentials.results().get(0)));
      // The current key again, or a key of another algorithm.
      KeyPair current = new KeyPair(pki.client.certificate().getPublicKey(), pki.client.key());
      assertEquals(
          ResultReason.INVALID_FIELD,
          reason(c.batch(List.of(reProvision(current, pki), GET)).results().get(0)));
      assertEquals(
          ResultReason.INVALID_FIELD,
          reason(c.batch(List.of(reProvision(TestPki.rsa(), pki), GET)).results().get(0)));
      // Two in one message: the second is denied, so the first's certificate is never fetched,
      // and nothing commits.
      Response twice =
          c.batch(List.of(reProvision(TestPki.ec(), pki), reProvision(TestPki.ec(), pki), GET));
      assertTrue(twice.messageLevelFailure());
      assertEquals(ResultReason.INVALID_FIELD, reason(twice.results().get(0)));
      assertEquals(List.of(), tls.retiredCertificates());
      assertEquals(List.of(), server.ids(), "the issued certificate was rolled back");

      // [Re-Provision, Get, Locate]: the Locate is denied, the message commits.
      Response done =
          c.batch(
              List.of(
                  reProvision(TestPki.ec(), pki),
                  GET,
                  LocateRequest.builder().build().toRequest()));
      assertTrue(done.results().get(0).successful());
      assertTrue(done.results().get(1).successful());
      assertEquals(ResultReason.PERMISSION_DENIED, reason(done.results().get(2)));
      assertEquals(List.of(pki.client.certificate()), tls.retiredCertificates());
      // The open connection keeps working, but cannot re-provision again.
      assertTrue(c.query(Enums.QueryFunction.QUERY_OPERATIONS).successful());
      Response again = c.batch(List.of(reProvision(TestPki.ec(), pki), GET));
      assertEquals(ResultReason.PERMISSION_DENIED, reason(again.results().get(0)));
      // A new connection on the retired certificate is refused.
      try (KmipClient fresh = client(tls, f)) {
        KmipException refused =
            assertThrows(
                KmipException.class, () -> fresh.call(Requests.discoverVersions().build()));
        assertTrue(refused.result().hasReason(ResultReason.PERMISSION_DENIED));
      }
      // As keytend-kmip-server's unlisted path: Permission Denied for each item, naming its
      // operation, under the message's continuation option; then the connection closes.
      Request asked = Requests.query().build();
      Request locate = LocateRequest.builder().build().toRequest();
      try (KmipClient fresh = client(tls, f)) {
        Response stop = fresh.batch(List.of(asked, locate));
        assertFalse(stop.messageLevelFailure(), stop.toString());
        assertEquals(1, stop.results().size(), stop.toString());
        assertEquals(Operation.QUERY, stop.results().get(0).operation());
        assertEquals(ResultReason.PERMISSION_DENIED, reason(stop.results().get(0)));
        // The server closed that connection: the next message goes on a new one, refused too.
        Response next = fresh.batch(List.of(asked));
        assertEquals(ResultReason.PERMISSION_DENIED, reason(next.results().get(0)));
      }
      try (KmipClient fresh = client(tls, f)) {
        Response all =
            fresh.batch(
                List.of(asked, locate),
                RequestOptions.builder()
                    .batchErrorContinuation(Enums.BatchErrorContinuation.CONTINUE)
                    .build());
        assertEquals(2, all.results().size(), all.toString());
        assertEquals(Operation.LOCATE, all.results().get(1).operation());
        for (Result r : all.results()) assertEquals(ResultReason.PERMISSION_DENIED, reason(r));
      }
    }
    // Without TLS (in process) it is not offered.
    try (Kms kms = server.connect()) {
      Result r = kms.protocol().execute(reProvision(TestPki.ec(), pki));
      assertEquals(ResultReason.OPERATION_NOT_SUPPORTED, reason(r));
    }
  }

  @Test
  void aRetiredCertificateCannotRenewOnAnotherOpenConnection(@TempDir Path dir) throws Exception {
    ClientCertificateRenewalTest.Pki pki = new ClientCertificateRenewalTest.Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    SSLContext f = KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem);
    try (TlsListener tls = pki.listener(server).start();
        KmipClient renewing = client(tls, f);
        KmipClient other = client(tls, f)) {
      // Both connections are open on the same certificate before the renewal.
      assertTrue(renewing.query(Enums.QueryFunction.QUERY_OPERATIONS).successful());
      assertTrue(other.query(Enums.QueryFunction.QUERY_OPERATIONS).successful());
      Response done = renewing.batch(List.of(reProvision(TestPki.ec(), pki), GET));
      assertTrue(done.results().get(1).successful(), done.toString());
      String issued = done.results().get(0).uniqueIdentifier();
      assertEquals(List.of(pki.client.certificate()), tls.retiredCertificates());

      // The other connection cannot renew the retired certificate again.
      Response again = other.batch(List.of(reProvision(TestPki.ec(), pki), GET));
      assertEquals(ResultReason.PERMISSION_DENIED, reason(again.results().get(0)));
      assertEquals(
          "This connection's certificate has already been replaced",
          again.results().get(0).message());
      assertEquals(List.of(issued), server.ids(), "nothing more was issued");
      // Its other requests keep working.
      assertTrue(
          other.call(Requests.get().uniqueIdentifier(issued).build()).successful(),
          "Get on the other connection");
      assertEquals(
          List.of(issued),
          other
              .call(LocateRequest.builder().build().toRequest())
              .requirePayload()
              .children(UNIQUE_IDENTIFIER)
              .stream()
              .map(Ttlv::textValue)
              .toList());
    }
  }

  /**
   * A provisioning CA that is an intermediate, with it and the listener's root both trust anchors:
   * the new certificate is checked along the path through it, as keytend-kmip-server's listener
   * verification does with both in its {@code --ca} bundle, and accepted. With the root alone, the
   * listener does not start, as keytend-kmip-server requires the provisioning CA itself
   * in that bundle. One under a root the listener does not trust is refused at {@code start()},
   * as keytend-kmip-server refuses to start with it.
   */
  @Test
  void aProvisioningCaUnderTheListenersRootIsAccepted(@TempDir Path dir) throws Exception {
    ClientCertificateRenewalTest.Pki pki = new ClientCertificateRenewalTest.Pki(dir);
    TestPki.Issued intermediate =
        TestPki.intermediate("Provisioning CA", pki.ca, TestPki.KEY_CERT_SIGN);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    SSLContext f = KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem);
    try (TlsListener tls =
            server
                .tlsListener()
                .identity(pki.server.key(), pki.server.certificate(), pki.ca.certificate())
                .trustAnchors(pki.ca.certificate(), intermediate.certificate())
                .provisioningCa(intermediate.key(), intermediate.certificate())
                .provisioningValidity(Duration.ofDays(1))
                .start();
        KmipClient c = client(tls, f)) {
      Response done = c.batch(List.of(reProvision(TestPki.ec(), pki), GET));
      assertTrue(done.results().get(1).successful(), done.toString());
      X509Certificate issued = ClientRenewal.certificate(done.results().get(1));
      assertEquals(
          intermediate.certificate().getSubjectX500Principal(), issued.getIssuerX500Principal());
      assertEquals(List.of(pki.client.certificate()), tls.retiredCertificates());
    }

    String notInBundle =
        "the provisioning CA must also be in the --ca bundle, so that the certificates it issues"
            + " are accepted";
    assertRefusedAtStart(pki, intermediate, notInBundle, pki.ca.certificate());
    // Byte for byte: another certificate with the same subject and key is not the CA.
    X509Certificate twin =
        dev.keytend.kmip.TestX509.certificate(
                "Provisioning CA", intermediate.certificate().getPublicKey())
            .issuedBy(pki.ca.certificate(), pki.ca.key())
            .ca()
            .keyUsage(TestPki.KEY_CERT_SIGN)
            .build();
    assertRefusedAtStart(pki, intermediate, notInBundle, pki.ca.certificate(), twin);

    TestPki.Issued otherRoot = TestPki.ca("Another root");
    TestPki.Issued outside =
        TestPki.intermediate("Provisioning CA", otherRoot, TestPki.KEY_CERT_SIGN);
    assertRefusedAtStart(
        pki,
        outside,
        "a client certificate from the provisioning CA fails the listener's verification",
        pki.ca.certificate(),
        outside.certificate());
  }

  /**
   * keytend-kmip-server's listener verifier checks client certificates with OpenSSL's purpose
   * sslclient, on every certificate of the path: a provisioning CA whose Extended Key Usage leaves
   * out clientAuth (serverAuth only, or anyExtendedKeyUsage alone, which that purpose does not
   * count) makes certificates the listener would refuse. keytend-kmip-server does not
   * start with one ("unsuitable certificate purpose"), and neither does the listener. One that
   * lists clientAuth is accepted, and its certificates are issued.
   */
  @Test
  void theNewCertificatesPathMustSuitATlsClient(@TempDir Path dir) throws Exception {
    ClientCertificateRenewalTest.Pki pki = new ClientCertificateRenewalTest.Pki(dir);
    SSLContext f = KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem);
    String clientAuth = "1.3.6.1.5.5.7.3.2", serverAuth = "1.3.6.1.5.5.7.3.1", any = "2.5.29.37.0";
    for (List<String> eku :
        List.of(
            List.of(clientAuth),
            List.of(serverAuth, clientAuth),
            List.of(serverAuth),
            List.of(any))) {
      java.security.KeyPair k = TestPki.ec();
      TestPki.Issued provisioning =
          new TestPki.Issued(
              dev.keytend.kmip.TestX509.certificate("Provisioning CA", k.getPublic())
                  .issuedBy(pki.ca.certificate(), pki.ca.key())
                  .ca()
                  .keyUsage(TestPki.KEY_CERT_SIGN)
                  .extendedKeyUsage(eku.toArray(String[]::new))
                  .build(),
              k.getPrivate());
      if (!eku.contains(clientAuth)) {
        assertRefusedAtStart(
            pki,
            provisioning,
            "a client certificate from the provisioning CA fails the listener's verification",
            pki.ca.certificate(),
            provisioning.certificate());
        continue;
      }
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      try (TlsListener tls =
              server
                  .tlsListener()
                  .identity(pki.server.key(), pki.server.certificate(), pki.ca.certificate())
                  .trustAnchors(pki.ca.certificate(), provisioning.certificate())
                  .provisioningCa(provisioning.key(), provisioning.certificate())
                  .provisioningValidity(Duration.ofDays(1))
                  .start();
          KmipClient c = client(tls, f)) {
        Response r = c.batch(List.of(reProvision(TestPki.ec(), pki), GET));
        assertTrue(r.results().get(1).successful(), eku + ": " + r);
        assertEquals(List.of(pki.client.certificate()), tls.retiredCertificates(), eku.toString());
      }
    }
  }

  /**
   * The rules keytend-kmip-server applies to its provisioning CA before it serves, each
   * with its message: a CA (basicConstraints CA true, whatever its Netscape certificate type says),
   * with a Key Usage that allows keyCertSign.
   */
  @Test
  void aProvisioningCaThatCannotSignCertificatesIsRefusedAtStart(@TempDir Path dir)
      throws Exception {
    ClientCertificateRenewalTest.Pki pki = new ClientCertificateRenewalTest.Pki(dir);
    String notCa = "the provisioning CA: Issuer certificate is not a CA";
    // No basicConstraints, but a Key Usage, or a Netscape type that names SSL CA.
    assertRefusedAtStart(
        pki,
        under(pki, b -> b.keyUsage(TestPki.KEY_CERT_SIGN, TestPki.CRL_SIGN)),
        notCa,
        pki.ca.certificate());
    assertRefusedAtStart(
        pki,
        under(pki, b -> b.extension("2.16.840.1.113730.1.1", false, new byte[] {3, 2, 2, 4})),
        notCa,
        pki.ca.certificate());
    assertRefusedAtStart(
        pki,
        under(pki, b -> b.notCa().keyUsage(TestPki.KEY_CERT_SIGN)),
        notCa,
        pki.ca.certificate());
    assertRefusedAtStart(
        pki,
        under(pki, b -> b.ca().keyUsage(TestPki.CRL_SIGN)),
        "the provisioning CA: Issuer key usage does not permit certificate signing",
        pki.ca.certificate());
    assertRefusedAtStart(
        pki,
        under(pki, b -> b.ca()),
        "the provisioning CA certificate lacks the keyCertSign key usage",
        pki.ca.certificate());
  }

  /**
   * The listener's verification builds the path up to a self-signed root, as OpenSSL does without
   * partial chains: a root above the provisioning CA whose Extended Key Usage is serverAuth only is
   * checked too, and a trust that holds the provisioning CA but not its root has no path. Both
   * stop {@code start()}, as each stops keytend-kmip-server from starting ("unsuitable
   * certificate purpose (depth 2)", "unable to get issuer certificate").
   */
  @Test
  void thePathEndsAtASelfSignedRoot(@TempDir Path dir) throws Exception {
    ClientCertificateRenewalTest.Pki pki = new ClientCertificateRenewalTest.Pki(dir);
    String fails =
        "a client certificate from the provisioning CA fails the listener's verification";
    java.security.KeyPair r = TestPki.ec();
    X509Certificate serverRoot =
        dev.keytend.kmip.TestX509.certificate("Server root", r.getPublic())
            .selfSigned(r.getPrivate())
            .ca()
            .keyUsage(TestPki.KEY_CERT_SIGN, TestPki.CRL_SIGN)
            .extendedKeyUsage("1.3.6.1.5.5.7.3.1")
            .build();
    TestPki.Issued provisioning =
        TestPki.intermediate(
            "Provisioning CA",
            new TestPki.Issued(serverRoot, r.getPrivate()),
            TestPki.KEY_CERT_SIGN);
    assertRefusedAtStart(
        pki, provisioning, fails, pki.ca.certificate(), serverRoot, provisioning.certificate());
    TestPki.Issued intermediate =
        TestPki.intermediate("Provisioning CA", pki.ca, TestPki.KEY_CERT_SIGN);
    assertRefusedAtStart(pki, intermediate, fails, intermediate.certificate());
  }

  /**
   * keytend-kmip-server checks the strength of its provisioning CA's certificate before
   * it looks for the CA in the bundle, and its listener verification checks every certificate of a
   * client's path: a key below 112-bit security, or a signature with SHA-1 (or MD2, MD4, MD5) on a
   * certificate that is not self-issued, stops {@code start()}, each with the server's message. A
   * self-signed root signed with SHA-1 is not refused for it, above the CA or as the CA.
   */
  @Test
  void aWeakProvisioningCaOrPathIsRefusedAtStart(@TempDir Path dir) throws Exception {
    ClientCertificateRenewalTest.Pki pki = new ClientCertificateRenewalTest.Pki(dir);
    String fails =
        "a client certificate from the provisioning CA fails the listener's verification";
    // Not in the bundle either: the strength check comes first.
    TestPki.Issued sha1 =
        under(pki, b -> b.ca().keyUsage(TestPki.KEY_CERT_SIGN).signatureAlgorithm("SHA1withECDSA"));
    assertRefusedAtStart(
        pki,
        sha1,
        "the provisioning CA certificate is signed with a weak digest",
        pki.ca.certificate());
    KeyPair weak = rsaKey(1024);
    TestPki.Issued rsa1024 =
        new TestPki.Issued(
            dev.keytend.kmip.TestX509.certificate("Provisioning CA", weak.getPublic())
                .issuedBy(pki.ca.certificate(), pki.ca.key())
                .ca()
                .keyUsage(TestPki.KEY_CERT_SIGN)
                .build(),
            weak.getPrivate());
    assertRefusedAtStart(
        pki,
        rsa1024,
        "the provisioning CA certificate key has 80-bit security, below 112",
        pki.ca.certificate());

    // A root of RSA-1024 above a strong CA: its listener verification refuses depth 2.
    X509Certificate weakRoot =
        dev.keytend.kmip.TestX509.certificate("Weak root", weak.getPublic())
            .selfSigned(weak.getPrivate())
            .ca()
            .keyUsage(TestPki.KEY_CERT_SIGN, TestPki.CRL_SIGN)
            .build();
    TestPki.Issued underWeak =
        TestPki.intermediate(
            "Provisioning CA",
            new TestPki.Issued(weakRoot, weak.getPrivate()),
            TestPki.KEY_CERT_SIGN);
    assertRefusedAtStart(pki, underWeak, fails, weakRoot, underWeak.certificate());

    // A self-signed root signed with SHA-1 is self-issued: as the CA, and above one, it renews.
    KeyPair r = TestPki.ec();
    X509Certificate sha1Root =
        dev.keytend.kmip.TestX509.certificate("SHA-1 root", r.getPublic())
            .selfSigned(r.getPrivate())
            .ca()
            .keyUsage(TestPki.KEY_CERT_SIGN, TestPki.CRL_SIGN)
            .signatureAlgorithm("SHA1withECDSA")
            .build();
    TestPki.Issued below =
        TestPki.intermediate(
            "Provisioning CA", new TestPki.Issued(sha1Root, r.getPrivate()), TestPki.KEY_CERT_SIGN);
    SSLContext f = KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem);
    for (TestPki.Issued provisioning :
        List.of(new TestPki.Issued(sha1Root, r.getPrivate()), below)) {
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      try (TlsListener tls =
              server
                  .tlsListener()
                  .identity(pki.server.key(), pki.server.certificate(), pki.ca.certificate())
                  .trustAnchors(pki.ca.certificate(), sha1Root, provisioning.certificate())
                  .provisioningCa(provisioning.key(), provisioning.certificate())
                  .provisioningValidity(Duration.ofDays(1))
                  .start();
          KmipClient c = client(tls, f)) {
        Response r2 = c.batch(List.of(reProvision(TestPki.ec(), pki), GET));
        assertTrue(r2.results().get(1).successful(), r2.toString());
        assertEquals(
            provisioning.certificate().getSubjectX500Principal(),
            ClientRenewal.certificate(r2.results().get(1)).getIssuerX500Principal());
      }
    }
  }

  /**
   * A new certificate that the listener's check refuses after it started, by the server's clock,
   * is refused with Cryptographic Failure, and nothing is retired: the listener's root expires
   * before its provisioning CA does.
   */
  @Test
  void aNewCertificateTheListenerRefusesLaterIsACryptographicFailure(@TempDir Path dir)
      throws Exception {
    ClientCertificateRenewalTest.Pki pki = new ClientCertificateRenewalTest.Pki(dir);
    Instant now = Instant.now();
    java.security.KeyPair r = TestPki.ec(), k = TestPki.ec();
    X509Certificate root =
        dev.keytend.kmip.TestX509.certificate("Short root", r.getPublic())
            .selfSigned(r.getPrivate())
            .ca()
            .keyUsage(TestPki.KEY_CERT_SIGN, TestPki.CRL_SIGN)
            .validity(now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(2)))
            .build();
    X509Certificate provisioning =
        dev.keytend.kmip.TestX509.certificate("Provisioning CA", k.getPublic())
            .issuedBy(root, r.getPrivate())
            .ca()
            .keyUsage(TestPki.KEY_CERT_SIGN)
            .validity(now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(30)))
            .build();
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    SSLContext f = KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem);
    try (TlsListener tls =
            server
                .tlsListener()
                .identity(pki.server.key(), pki.server.certificate(), pki.ca.certificate())
                .trustAnchors(pki.ca.certificate(), root, provisioning)
                .provisioningCa(k.getPrivate(), provisioning)
                .provisioningValidity(Duration.ofDays(1))
                .start();
        KmipClient c = client(tls, f)) {
      server.clock(java.time.Clock.offset(java.time.Clock.systemUTC(), Duration.ofDays(3)));
      Response refused = c.batch(List.of(reProvision(TestPki.ec(), pki), GET));
      assertEquals(ResultReason.CRYPTOGRAPHIC_FAILURE, reason(refused.results().get(0)));
      assertEquals(List.of(), tls.retiredCertificates());
    }
  }

  /** A provisioning CA issued by the Pki's root, made by {@code shape} from a fresh builder. */
  private static TestPki.Issued under(
      ClientCertificateRenewalTest.Pki pki,
      java.util.function.UnaryOperator<dev.keytend.kmip.TestX509.Builder> shape)
      throws Exception {
    java.security.KeyPair k = TestPki.ec();
    return new TestPki.Issued(
        shape
            .apply(
                dev.keytend.kmip.TestX509.certificate("Provisioning CA", k.getPublic())
                    .issuedBy(pki.ca.certificate(), pki.ca.key()))
            .build(),
        k.getPrivate());
  }

  /** That a listener with {@code provisioning} and {@code anchors} does not start: {@code why}. */
  private static void assertRefusedAtStart(
      ClientCertificateRenewalTest.Pki pki,
      TestPki.Issued provisioning,
      String why,
      X509Certificate... anchors) {
    TlsListener.Builder b =
        InMemoryKmipServer.of(KmipVersion.V2_1)
            .tlsListener()
            .identity(pki.server.key(), pki.server.certificate(), pki.ca.certificate())
            .trustAnchors(anchors)
            .provisioningCa(provisioning.key(), provisioning.certificate());
    IllegalStateException e = assertThrows(IllegalStateException.class, () -> b.start().close());
    assertEquals("provisioningCa: " + why, e.getMessage());
  }

  @Test
  void aRenewalThatRolledBackLeavesItsKeyUnused(@TempDir Path dir) throws Exception {
    ClientCertificateRenewalTest.Pki pki = new ClientCertificateRenewalTest.Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    SSLContext f = KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem);
    KeyPair key = TestPki.ec();
    try (TlsListener tls = pki.listener(server).start();
        KmipClient c = client(tls, f)) {
      // The first Re-Provision issues, the second is denied, and the message rolls back.
      Response twice = c.batch(List.of(reProvision(key, pki), reProvision(TestPki.ec(), pki), GET));
      assertTrue(twice.messageLevelFailure());
      assertEquals(List.of(), server.ids());
      // A denied item stops the message before its Get, so it rolls back too.
      Response stopped =
          c.batch(List.of(reProvision(key, pki), LocateRequest.builder().build().toRequest(), GET));
      assertTrue(stopped.messageLevelFailure(), stopped.toString());
      assertEquals(List.of(), server.ids());
      assertEquals(List.of(), tls.retiredCertificates());

      // The same request again succeeds: the key was not used up.
      Response done = c.batch(List.of(reProvision(key, pki), GET));
      assertTrue(done.results().get(0).successful(), done.toString());
      assertTrue(done.results().get(1).successful(), done.toString());
      assertEquals(
          key.getPublic(), ClientRenewal.certificate(done.results().get(1)).getPublicKey());
      assertEquals(List.of(pki.client.certificate()), tls.retiredCertificates());
    }
  }

  @Test
  void theRequestKeyMustBeOnTheServersCurvesOrRsa2048(@TempDir Path dir) throws Exception {
    String unsupported =
        "The new key must be of the current certificate's algorithm (and curve): RSA-2048 or more,"
            + " or EC P-256, P-384 or P-521";
    // An EC P-256 certificate: other named curves are invalid requests; another NIST curve or
    // RSA is not the current certificate's kind.
    ClientCertificateRenewalTest.Pki ec = new ClientCertificateRenewalTest.Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    SSLContext f = KmsConfig.sslContextFromPem(ec.chain, ec.key, ec.caPem);
    X500Principal subject = ec.client.certificate().getSubjectX500Principal();
    try (TlsListener tls = ec.listener(server).start();
        KmipClient c = client(tls, f)) {
      for (String curve : List.of("brainpoolP256r1", "secp256k1")) {
        Result r =
            c.batch(List.of(reProvisionOf(otherCurveRequest(subject, curve)), GET))
                .results()
                .get(0);
        assertEquals(ResultReason.INVALID_FIELD, reason(r), curve);
        assertEquals("Invalid Certificate Request", r.message(), curve);
      }
      for (KeyPair other : List.of(ecKey("secp384r1"), ecKey("secp521r1"), rsaKey(2048))) {
        Result r = c.batch(List.of(reProvision(other, ec), GET)).results().get(0);
        assertEquals(ResultReason.INVALID_FIELD, reason(r), other.getPublic().toString());
        assertEquals(unsupported, r.message());
      }
      assertEquals(List.of(), server.ids(), "nothing issued");
      assertEquals(List.of(), tls.retiredCertificates());
    }
  }

  @Test
  void anRsaRequestKeyMustHave2048Bits(@TempDir Path dir) throws Exception {
    ClientCertificateRenewalTest.Pki rsa = new ClientCertificateRenewalTest.Pki(dir, rsaKey(2048));
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    SSLContext f = KmsConfig.sslContextFromPem(rsa.chain, rsa.key, rsa.caPem);
    try (TlsListener tls = rsa.listener(server).start();
        KmipClient c = client(tls, f)) {
      Result small = c.batch(List.of(reProvision(rsaKey(1024), rsa), GET)).results().get(0);
      assertEquals(ResultReason.INVALID_FIELD, reason(small));
      assertTrue(small.message().contains("RSA-2048 or more"), small.message());
      assertEquals(List.of(), server.ids());
      Response done = c.batch(List.of(reProvision(rsaKey(3072), rsa), GET));
      assertTrue(done.results().get(1).successful(), done.toString());
    }
  }

  static KeyPair ecKey(String curve) throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec(curve));
    return g.generateKeyPair();
  }

  static KeyPair rsaKey(int bits) throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(bits);
    return g.generateKeyPair();
  }

  private static final Provider BC = new BouncyCastleProvider();

  /**
   * A PKCS#10 request for a new key on {@code curve}, a named curve the JDK does not sign with,
   * made and signed with Bouncy Castle.
   */
  static byte[] otherCurveRequest(X500Principal subject, String curve) throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC", BC);
    g.initialize(new ECGenParameterSpec(curve));
    KeyPair pair = g.generateKeyPair();
    return new JcaPKCS10CertificationRequestBuilder(subject, pair.getPublic())
        .build(
            new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BC).build(pair.getPrivate()))
        .getEncoded();
  }

  /** A Re-Provision of the PKCS#10 request {@code der}. */
  static Request reProvisionOf(byte[] der) {
    return Requests.reProvision()
        .add(
            structure(
                CERTIFICATE_REQUEST,
                enumeration(CERTIFICATE_REQUEST_TYPE, Enums.CertificateRequestType.PKCS_10),
                bytes(CERTIFICATE_REQUEST_VALUE, der)))
        .build();
  }

  /** A Re-Provision of {@code key} with {@code extensions} on its batch item. */
  static Request reProvision(KeyPair key, ClientCertificateRenewalTest.Pki pki, Ttlv... extensions)
      throws Exception {
    Request.Builder b =
        Requests.reProvision()
            .add(
                structure(
                    CERTIFICATE_REQUEST,
                    enumeration(CERTIFICATE_REQUEST_TYPE, Enums.CertificateRequestType.PKCS_10),
                    bytes(
                        CERTIFICATE_REQUEST_VALUE,
                        Pkcs10.request(pki.client.certificate().getSubjectX500Principal(), key))));
    for (Ttlv e : extensions) b.extension(e);
    return b.build();
  }

  /** keytend-kmip-server's validity extension, with {@code fields} in its Vendor Extension. */
  static Ttlv validity(boolean critical, Ttlv... fields) {
    return Credentials.extension("keytend_kmip_server", critical, fields);
  }

  static Ttlv until(Instant notAfter) {
    return dateTime(DEACTIVATION_DATE, notAfter.truncatedTo(ChronoUnit.SECONDS));
  }

  @Test
  void theRequestedValidityExtension(@TempDir Path dir) throws Exception {
    ClientCertificateRenewalTest.Pki pki = new ClientCertificateRenewalTest.Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    SSLContext f = KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem);
    Instant month = Instant.now().plus(Duration.ofDays(30)).truncatedTo(ChronoUnit.SECONDS);
    try (TlsListener tls = pki.listener(server).start();
        KmipClient c = client(tls, f)) {
      // Invalid Field, and nothing issued: two extensions, a body other than one Deactivation
      // Date, a date that has passed, a date after the provisioning CA's notAfter, the
      // certificate form.
      for (Request bad :
          List.of(
              reProvision(
                  TestPki.ec(), pki, validity(true, until(month)), validity(false, until(month))),
              reProvision(
                  TestPki.ec(),
                  pki,
                  validity(
                      true,
                      until(month),
                      dateTime(ACTIVATION_DATE, Instant.now().truncatedTo(ChronoUnit.SECONDS)))),
              reProvision(TestPki.ec(), pki, validity(true)),
              reProvision(TestPki.ec(), pki, validity(true, dateTime(ACTIVATION_DATE, month))),
              reProvision(TestPki.ec(), pki, validity(true, until(Instant.now().minusSeconds(60)))),
              reProvision(
                  TestPki.ec(),
                  pki,
                  validity(
                      true,
                      until(
                          pki.provisioning
                              .certificate()
                              .getNotAfter()
                              .toInstant()
                              .plusSeconds(1)))),
              Requests.reProvision()
                  .add(
                      structure(
                          CERTIFICATE,
                          enumeration(CERTIFICATE_TYPE, Enums.CertificateType.X_509),
                          bytes(CERTIFICATE_VALUE, pki.client.certificate().getEncoded())))
                  .extension(validity(true, until(month)))
                  .build())) {
        Response r = c.batch(List.of(bad, GET));
        assertEquals(ResultReason.INVALID_FIELD, reason(r.results().get(0)), bad.toString());
      }
      // Another vendor's Critical extension, or this one on another operation, rejects the whole
      // message; Non-Critical ones are ignored.
      Response unknown =
          c.batch(
              List.of(
                  reProvision(
                      TestPki.ec(),
                      pki,
                      Credentials.extension("another_vendor", true, until(month))),
                  GET));
      assertTrue(unknown.messageLevelFailure());
      assertEquals(ResultReason.UNKNOWN_MESSAGE_EXTENSION, reason(unknown.results().get(0)));
      Response elsewhere =
          c.batch(
              List.of(Requests.discoverVersions().extension(validity(true, until(month))).build()));
      assertTrue(elsewhere.messageLevelFailure());
      assertEquals(ResultReason.UNKNOWN_MESSAGE_EXTENSION, reason(elsewhere.results().get(0)));
      assertTrue(
          c.batch(
                  List.of(
                      Requests.discoverVersions()
                          .extension(validity(false, until(month)))
                          .extension(Credentials.extension("another_vendor", false))
                          .build()))
              .results()
              .get(0)
              .successful());
      assertEquals(List.of(), tls.retiredCertificates(), "nothing issued so far");
      assertEquals(List.of(), server.ids());

      // Non-Critical, understood: the notAfter and the stored Deactivation Date are the date.
      Response done =
          c.batch(List.of(reProvision(TestPki.ec(), pki, validity(false, until(month))), GET));
      assertTrue(done.results().get(0).successful(), done.toString());
      X509Certificate issued = ClientRenewal.certificate(done.results().get(1));
      assertEquals(month, issued.getNotAfter().toInstant());
      Result stored =
          c.call(
              Requests.getAttributes()
                  .uniqueIdentifier(done.results().get(0).uniqueIdentifier())
                  .build());
      assertEquals(
          month,
          stored
              .payload()
              .orElseThrow()
              .require(ATTRIBUTES)
              .require(DEACTIVATION_DATE)
              .instantValue());
    }
  }
}
