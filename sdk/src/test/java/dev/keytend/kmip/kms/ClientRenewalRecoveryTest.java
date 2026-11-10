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

import static dev.keytend.kmip.TestAwait.await;
import static dev.keytend.kmip.kms.ClientCertificateRenewalTest.RENEW_WITHIN;
import static dev.keytend.kmip.kms.ClientCertificateRenewalTest.leaf;
import static dev.keytend.kmip.kms.ClientCertificateRenewalTest.reProvision;
import static dev.keytend.kmip.kms.KmsApiTest.pem;
import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.TestX509;
import dev.keytend.kmip.client.KmipClient;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.client.Response;
import dev.keytend.kmip.kms.ClientCertificateRenewalTest.Events;
import dev.keytend.kmip.kms.ClientCertificateRenewalTest.Pki;
import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Enums.ResultReason;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.testing.TlsListener;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@link Kms#renewClientCertificate()} when things go wrong in between: unwritten renewals under
 * automatic renewal, earlier attempts that commit late, searches through the connections the
 * process still has, searches that are refused or cut short, certificates the client refuses,
 * pending files of other identity files, and renewals of the same files at the same time.
 */
class ClientRenewalRecoveryTest {
  @AfterEach
  void reset() {
    StagedFiles.directorySync = StagedFiles::forceDirectory;
    ClientRenewal.firstBackoff = Duration.ofMinutes(1);
    ClientRenewal.maxBackoff = Duration.ofHours(1);
    ClientRenewal.maxCheck = Duration.ofHours(1);
    ClientRenewal.beforeReProvision = null;
    ClientRenewal.searchLimit = ClientRenewal.SEARCH_LIMIT;
    ClientRenewal.searchPage = ClientRenewal.SEARCH_PAGE;
  }

  static Path pendingFile(Path dir) {
    return dir.resolve("client.key.renewal");
  }

  /** The pending file of {@code pki}'s files, read. */
  static RenewalFiles.Pending pending(Pki pki) throws IOException {
    return files(pki).readPending(null);
  }

  static RenewalFiles files(Pki pki) {
    return new RenewalFiles(
        new TlsFiles.Identity(
            TlsFiles.IdentityKind.PEM, null, pki.chain, pki.key, null, List.of()));
  }

  /** A raw client on the PKI's current certificate, its connection opened now. */
  static KmipClient onCurrentCertificate(TlsListener tls, Pki pki) throws Exception {
    SSLContext f = KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem);
    KmipClient c = InMemoryReProvisionTest.client(tls, f);
    c.call(Requests.discoverVersions().build());
    return c;
  }

  /**
   * {@code key}'s Re-Provision, sent on {@code c}: an earlier attempt's message, committing late.
   *
   * @return the certificate the server issued
   */
  static X509Certificate commitLate(KmipClient c, Pki pki, KeyPair key) throws Exception {
    Response r =
        c.batch(List.of(InMemoryReProvisionTest.reProvision(key, pki), Requests.get().build()));
    assertTrue(r.results().get(0).successful(), r.results().get(0).toString());
    X509Certificate issued = ClientRenewal.certificate(r.results().get(1));
    assertNotNull(issued);
    return issued;
  }

  /** The PEM private key block of a pending file, as an operator would copy it out. */
  static String keyBlock(Path pendingFile) throws IOException {
    String text = Files.readString(pendingFile);
    return text.substring(text.lastIndexOf("-----BEGIN"));
  }

  /** Leaves a pending key whose request the server never processed: a reply lost before it. */
  static void leavePendingKey(InMemoryKmipServer server, Kms kms) {
    server.injectBeforeProcessing(
        request -> reProvision(request) ? new SocketTimeoutException("lost before") : null);
    TransientException e = assertThrows(TransientException.class, kms::renewClientCertificate);
    assertTrue(e.getMessage().contains("issued no certificate"), e.getMessage());
  }

  static String base64(java.security.PublicKey key) {
    return Base64.getEncoder().encodeToString(key.getEncoded());
  }

  // ---- automatic renewal and unwritten files ----

  @Test
  void automaticRenewalWritesAnUnwrittenRenewalBeforeItLooksAtExpiry(@TempDir Path dir)
      throws Exception {
    // The directory forces of a renewal: 1 the pending key, 2 the pending key and certificate,
    // 3 the chain file. A failure at 2 is one while saving the issued pending record; at 3, one
    // during the switch of the identity files.
    for (int failing : new int[] {2, 3}) {
      Path sub = dir.resolve("force-" + failing);
      Files.createDirectory(sub);
      ClientRenewal.firstBackoff = Duration.ofMillis(20);
      ClientRenewal.maxBackoff = Duration.ofMillis(40);
      Pki pki = new Pki(sub);
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      Events events = new Events();
      AtomicInteger forces = new AtomicInteger();
      StagedFiles.directorySync =
          d -> {
            if (forces.incrementAndGet() == failing) throw new IOException("injected");
          };
      try (TlsListener tls = pki.listener(server).start();
          Kms kms =
              Kms.connect(
                  pki.renewing(tls, CertificateRenewal.automatic(RENEW_WITHIN))
                      .addListener(events)
                      .build())) {
        await("the files written by a later check").until(() -> !events.renewed.isEmpty());
        assertEquals(1, events.failed.size(), events.failed.toString());
        assertTrue(events.failed.get(0).contains("this process uses it"), events.failed.get(0));
        // The server was asked once: the later check wrote the files, it did not renew again.
        assertEquals(1, tls.retiredCertificates().size());
        X509Certificate now = leaf(pki.chain);
        assertNotEquals(pki.client.certificate(), now);
        assertNotNull(KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem));
        assertFalse(Files.exists(pendingFile(sub)));
        tls.dropConnections();
        kms.ping();
      }
    }
  }

  // ---- earlier attempts that commit late ----

  @Test
  void aResumedAttemptRefusedAfterALateCommitFindsTheCertificate(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        KmipClient earlier = onCurrentCertificate(tls, pki);
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      leavePendingKey(server, kms);
      RenewalFiles.Pending pending = pending(pki);
      KeyPair key = new KeyPair(pending.publicKey(), pending.key());
      // The earlier attempt's message commits after the resumed attempt searched, before its own
      // Re-Provision runs: the server then refuses that one.
      ClientRenewal.beforeReProvision =
          () -> {
            ClientRenewal.beforeReProvision = null;
            try {
              commitLate(earlier, pki, key);
            } catch (Exception e) {
              throw new AssertionError(e);
            }
          };
      RenewedCertificate r = kms.renewClientCertificate();
      assertTrue(r.finishedEarlierAttempt());
      assertEquals(base64(pending.publicKey()), base64(r.certificate().getPublicKey()));
      assertEquals(r.certificate(), leaf(pki.chain));
      assertFalse(Files.exists(pendingFile(dir)));
      assertEquals(1, tls.retiredCertificates().size());
      assertTrue(events.lockedOut.isEmpty());
      tls.dropConnections();
      kms.ping();
    }
  }

  @Test
  void aSlowCommitAfterTheSearchIsFinishedThroughAnOpenConnection(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        KmipClient earlier = onCurrentCertificate(tls, pki);
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      leavePendingKey(server, kms);
      RenewalFiles.Pending pending = pending(pki);
      // The lost message commits after the search: the current certificate is retired.
      commitLate(earlier, pki, new KeyPair(pending.publicKey(), pending.key()));
      // New connections on it are refused; the Kms's own open connection still works.
      RenewedCertificate r = kms.renewClientCertificate();
      assertTrue(r.finishedEarlierAttempt());
      assertEquals(base64(pending.publicKey()), base64(r.certificate().getPublicKey()));
      assertEquals(r.certificate(), leaf(pki.chain));
      assertFalse(Files.exists(pendingFile(dir)));
      assertTrue(events.lockedOut.isEmpty());
    }
  }

  // ---- searches after a lost reply ----

  @Test
  void aLostReplyIsFoundThroughAnOpenConnectionOfTheKmsWhenTheStandbyFails(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      // The server commits and the reply is lost; the standby's search fails too, and a new
      // connection on the retired certificate is refused.
      server.failNext(ServerOperation.RE_PROVISION, Fault.REPLY_LOST);
      server.failNext(ServerOperation.LOCATE, Fault.REPLY_LOST);
      RenewedCertificate r = kms.renewClientCertificate();
      assertFalse(r.finishedEarlierAttempt());
      assertEquals(r.certificate(), leaf(pki.chain));
      assertEquals(1, tls.retiredCertificates().size());
    }
  }

  @Test
  void theSecondConnectionDroppingWhenNothingWasIssuedIsTransient(@TempDir Path dir)
      throws Exception {
    // Nothing is processed; the searches through the standby and the Kms's connection fail. A new
    // connection, which the server accepts, shows that nothing was issued (two failures), or at
    // least that the current certificate is not retired (three).
    for (int failing : new int[] {2, 3}) {
      Path sub = dir.resolve("failing-" + failing);
      Files.createDirectory(sub);
      Pki pki = new Pki(sub);
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      Events events = new Events();
      try (TlsListener tls = pki.listener(server).start();
          Kms kms =
              Kms.connect(
                  pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
        server.injectBeforeProcessing(
            request -> reProvision(request) ? new SocketTimeoutException("lost before") : null);
        for (int i = 0; i < failing; i++) server.failNext(ServerOperation.LOCATE, Fault.REPLY_LOST);
        TransientException e = assertThrows(TransientException.class, kms::renewClientCertificate);
        assertTrue(
            e.getMessage().contains(failing == 2 ? "issued no certificate" : "nothing changed"),
            e.getMessage());
        assertTrue(Files.exists(pendingFile(sub)), "the key is kept");
        assertTrue(events.lockedOut.isEmpty());
        assertEquals(List.of(), tls.retiredCertificates());
        assertEquals(kms.renewClientCertificate().certificate(), leaf(pki.chain));
      }
    }
  }

  @Test
  void aRefusedSearchAfterALostReplyMayLockTheClientOutThenRecovers(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      server.failNext(ServerOperation.RE_PROVISION, Fault.REPLY_LOST);
      server.failNext(ServerOperation.LOCATE, Fault.PERMISSION_DENIED);
      OutcomeUnknownException e =
          assertThrows(OutcomeUnknownException.class, kms::renewClientCertificate);
      assertTrue(e.getMessage().contains("Locate (8) and Get (10)"), e.getMessage());
      assertTrue(e.getMessage().contains("may be locked out"), e.getMessage());
      assertEquals(1, events.lockedOut.size());
      assertTrue(Files.exists(pendingFile(dir)));
      // Once the policy allows Locate: the server refuses the retired certificate on new
      // connections, and the Kms's open connection finds the new one.
      RenewedCertificate r = kms.renewClientCertificate();
      assertTrue(r.finishedEarlierAttempt());
      assertEquals(r.certificate(), leaf(pki.chain));
      assertEquals(1, tls.retiredCertificates().size());
    }
  }

  @Test
  void aRefusedSearchOnAResumedAttemptKeepsTheKeyAndChangesNothing(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      leavePendingKey(server, kms);
      String kept = Files.readString(pendingFile(dir));
      server.failNext(ServerOperation.LOCATE, Fault.PERMISSION_DENIED);
      PermissionDeniedException e =
          assertThrows(PermissionDeniedException.class, kms::renewClientCertificate);
      assertTrue(e.getMessage().contains("Locate (8) and Get (10)"), e.getMessage());
      assertTrue(e.getMessage().contains("nothing changed"), e.getMessage());
      assertEquals(kept, Files.readString(pendingFile(dir)));
      assertEquals(List.of(), tls.retiredCertificates());
      assertTrue(events.lockedOut.isEmpty());
      assertEquals(kms.renewClientCertificate().certificate(), leaf(pki.chain));
    }
  }

  @Test
  void anExhaustedSearchIsProofButATruncatedOneIsNot(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      // Certificates created around the attempt, none for the new key, over several pages.
      for (int i = 0; i < 3; i++) register(kms, TestPki.leaf("other-" + i, TestPki.ec(), pki.ca));
      ClientRenewal.searchPage = 2;
      try {
        // Every page seen, none for the key: the server issued nothing, the failure is transient.
        leavePendingKey(server, kms);
        assertEquals(List.of(), tls.retiredCertificates());
        String kept = Files.readString(pendingFile(dir));
        // A search cut short before a resumed attempt sends its key again: transient, and the
        // key is kept.
        ClientRenewal.searchLimit = 2;
        TransientException cut =
            assertThrows(TransientException.class, kms::renewClientCertificate);
        assertTrue(cut.getMessage().contains("the search stopped there"), cut.getMessage());
        assertEquals(kept, Files.readString(pendingFile(dir)));
        ClientRenewal.searchLimit = ClientRenewal.SEARCH_LIMIT;
        assertFalse(kms.renewClientCertificate().finishedEarlierAttempt());
        // A search cut short after a lost reply is no proof that nothing was issued: the client
        // may be locked out, and the key is kept.
        ClientRenewal.searchLimit = 2;
        server.injectBeforeProcessing(
            request -> reProvision(request) ? new SocketTimeoutException("lost before") : null);
        OutcomeUnknownException e =
            assertThrows(OutcomeUnknownException.class, kms::renewClientCertificate);
        assertTrue(e.getMessage().contains("the search stopped there"), e.getMessage());
        assertTrue(Files.exists(pendingFile(dir)));
        assertEquals(1, events.lockedOut.size());
      } finally {
        ClientRenewal.searchPage = ClientRenewal.SEARCH_PAGE;
      }
    }
  }

  /** Registers {@code issued}'s certificate on the server: a certificate created now. */
  static String register(Kms kms, Issued issued) throws Exception {
    return kms.protocol()
        .execute(
            Requests.register()
                .add(enumeration(OBJECT_TYPE, Enums.ObjectType.CERTIFICATE))
                .add(
                    structure(
                        ATTRIBUTES,
                        enumeration(CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.EC),
                        integer(CRYPTOGRAPHIC_LENGTH, 256),
                        integer(CERTIFICATE_LENGTH, issued.certificate().getEncoded().length),
                        integer(CRYPTOGRAPHIC_USAGE_MASK, 1)))
                .add(
                    structure(
                        CERTIFICATE,
                        enumeration(CERTIFICATE_TYPE, Enums.CertificateType.X_509),
                        bytes(CERTIFICATE_VALUE, issued.certificate().getEncoded())))
                .build())
        .uniqueIdentifier();
  }

  @Test
  void aResumedAttemptRefusedWithInvalidFieldThenFoundFinishes(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      leavePendingKey(server, kms);
      RenewalFiles.Pending pending = pending(pki);
      // A certificate for the pending key appears after the resumed attempt's first search, and
      // the server refuses the request as for a key it has seen.
      X509Certificate issued =
          TestX509.certificate("client", pending.publicKey())
              .issuedBy(pki.ca.certificate(), pki.ca.key())
              .localhost()
              .extendedKeyUsage(ClientRenewal.CLIENT_AUTH)
              .build();
      ClientRenewal.beforeReProvision =
          () -> {
            ClientRenewal.beforeReProvision = null;
            try {
              register(kms, new Issued(issued, pending.key()));
            } catch (Exception e) {
              throw new AssertionError(e);
            }
            server.failNext(ServerOperation.RE_PROVISION, ResultReason.INVALID_FIELD);
          };
      RenewedCertificate r = kms.renewClientCertificate();
      assertTrue(r.finishedEarlierAttempt());
      assertEquals(issued, r.certificate());
      assertEquals(issued, leaf(pki.chain));
      assertFalse(Files.exists(pendingFile(dir)));
    }
  }

  @Test
  void aRefusedFirstRequestDeletesItsKey(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      // The only message that carried the key was refused, with no lost reply before it.
      server.failNext(ServerOperation.RE_PROVISION, Fault.UNSUPPORTED);
      assertThrows(UnsupportedException.class, kms::renewClientCertificate);
      assertFalse(Files.exists(pendingFile(dir)));
      assertEquals(List.of(), files(pki).unresolved());
      assertEquals(List.of(), tls.retiredCertificates());
    }
  }

  @Test
  void aResumedAttemptRefusedMovesItsKeyAsideAndALateCommitIsFoundLater(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        KmipClient earlier = onCurrentCertificate(tls, pki);
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      leavePendingKey(server, kms);
      RenewalFiles.Pending pending = pending(pki);
      KeyPair key = new KeyPair(pending.publicKey(), pending.key());
      // The resumed attempt's own request is refused, and its search after the refusal finds
      // nothing: the earlier request has not committed yet.
      ClientRenewal.beforeReProvision =
          () -> {
            ClientRenewal.beforeReProvision = null;
            server.failNext(ServerOperation.RE_PROVISION, ResultReason.INVALID_FIELD);
          };
      InvalidRequestException e =
          assertThrows(InvalidRequestException.class, kms::renewClientCertificate);
      assertFalse(Files.exists(pendingFile(dir)), "no key is pending");
      List<Path> aside = files(pki).unresolved();
      assertEquals(1, aside.size());
      assertTrue(aside.get(0).getFileName().toString().endsWith(".unresolved"), aside.toString());
      assertEquals(
          base64(pending.publicKey()),
          base64(RenewalFiles.readPending(aside.get(0), null).publicKey()),
          "moved, not deleted");
      assertTrue(e.getMessage().contains(aside.get(0).toString()), e.getMessage());
      assertTrue(e.getMessage().contains("rather than deleted"), e.getMessage());
      String failed = events.failed.get(events.failed.size() - 1);
      assertTrue(failed.contains(aside.get(0).toString()), failed);
      assertEquals(List.of(), tls.retiredCertificates());

      // The earlier request commits only now, after that search: the server retires the current
      // certificate and issues one for the key that was moved aside.
      X509Certificate issued = commitLate(earlier, pki, key);
      assertEquals(1, tls.retiredCertificates().size());
      // A new connect on the retired certificate names the key moved aside.
      PermissionDeniedException connect =
          assertThrows(
              PermissionDeniedException.class,
              () -> Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build()));
      assertTrue(connect.getMessage().contains(aside.get(0).toString()), connect.getMessage());

      // The next renewal looks for a certificate for that key through the Kms's open connection,
      // finds it, and finishes: the client is not locked out.
      RenewedCertificate r = kms.renewClientCertificate();
      assertTrue(r.finishedEarlierAttempt());
      assertEquals(issued, r.certificate());
      assertEquals(issued, leaf(pki.chain));
      assertEquals(List.of(), files(pki).unresolved());
      assertFalse(Files.exists(pendingFile(dir)));
      assertTrue(events.lockedOut.isEmpty());
      tls.dropConnections();
      kms.ping();
    }
  }

  @Test
  void aKeyMovedAsideRecoversByHandWhenNoConnectionIsLeft(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        KmipClient earlier = onCurrentCertificate(tls, pki);
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      leavePendingKey(server, kms);
      RenewalFiles.Pending pending = pending(pki);
      KeyPair key = new KeyPair(pending.publicKey(), pending.key());
      ClientRenewal.beforeReProvision =
          () -> {
            ClientRenewal.beforeReProvision = null;
            server.failNext(ServerOperation.RE_PROVISION, ResultReason.INVALID_FIELD);
          };
      assertThrows(InvalidRequestException.class, kms::renewClientCertificate);
      Path aside = files(pki).unresolved().get(0);
      // The earlier request commits after the final search, then every connection on the old
      // certificate closes.
      X509Certificate issued = commitLate(earlier, pki, key);
      tls.dropConnections();
      // The SDK cannot look for the certificate any more: a possible lockout, naming the key.
      OutcomeUnknownException locked =
          assertThrows(OutcomeUnknownException.class, kms::renewClientCertificate);
      assertTrue(locked.getMessage().contains(aside.toString()), locked.getMessage());
      assertEquals(1, events.lockedOut.size());
      assertTrue(Files.exists(aside), "the key is kept");
      // The operator's recovery: the certificate the server issued (its startup log, say) and
      // the key moved aside make the identity again.
      Files.writeString(pki.chain, pem("CERTIFICATE", issued.getEncoded()));
      Files.writeString(pki.key, keyBlock(aside));
      try (Kms recovered =
          Kms.connect(pki.client(tls).clientIdentityPem(pki.chain, pki.key).build())) {
        recovered.ping();
      }
      X509Certificate presented = tls.clientCertificates().get(tls.clientCertificates().size() - 1);
      assertEquals(issued, presented);
    }
  }

  @Test
  void refusedOnNewConnectionsWithNothingFoundMovesThePendingKeyAside(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start();
        KmipClient other = onCurrentCertificate(tls, pki);
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      leavePendingKey(server, kms);
      RenewalFiles.Pending pending = pending(pki);
      // Another client renews the same certificate with another key: the server refuses the
      // current certificate on new connections, and holds nothing for the pending key.
      commitLate(other, pki, TestPki.ec());
      PermissionDeniedException e =
          assertThrows(PermissionDeniedException.class, kms::renewClientCertificate);
      assertFalse(Files.exists(pendingFile(dir)));
      List<Path> aside = files(pki).unresolved();
      assertEquals(1, aside.size());
      assertTrue(e.getMessage().contains(aside.get(0).toString()), e.getMessage());
      assertEquals(
          base64(pending.publicKey()),
          base64(RenewalFiles.readPending(aside.get(0), null).publicKey()));
    }
  }

  // ---- the server's clock ----

  @Test
  void theSearchUsesTheServersClock(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    // The server's clock is three hours behind this machine's: it dates what it creates, Initial
    // Date among them, three hours earlier than this machine would.
    server.clock(java.time.Clock.offset(java.time.Clock.systemUTC(), Duration.ofHours(-3)));
    try (TlsListener tls = pki.listener(server).start();
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      // A lost reply: the search through the standby finds the certificate by the server's time.
      server.failNext(ServerOperation.RE_PROVISION, Fault.REPLY_LOST);
      RenewedCertificate r = kms.renewClientCertificate();
      assertFalse(r.finishedEarlierAttempt());
      assertEquals(r.certificate(), leaf(pki.chain));
      assertEquals(1, tls.retiredCertificates().size());
    }
    Path second = dir.resolve("resumed");
    Files.createDirectory(second);
    Pki again = new Pki(second);
    try (TlsListener tls = again.listener(server).start();
        KmipClient earlier = onCurrentCertificate(tls, again);
        Kms kms = Kms.connect(again.renewing(tls, CertificateRenewal.onDemand()).build())) {
      // The pending file records the server's time when its key was written.
      leavePendingKey(server, kms);
      RenewalFiles.Pending pending = pending(again);
      assertNotNull(pending.serverTime());
      assertTrue(
          Duration.between(pending.serverTime(), pending.written().minus(Duration.ofHours(3)))
                  .abs()
                  .compareTo(Duration.ofMinutes(1))
              < 0,
          pending.serverTime() + " " + pending.written());
      // A late commit is found by a resumed attempt's search, by the recorded server time.
      X509Certificate issued =
          commitLate(earlier, again, new KeyPair(pending.publicKey(), pending.key()));
      RenewedCertificate r = kms.renewClientCertificate();
      assertTrue(r.finishedEarlierAttempt());
      assertEquals(issued, r.certificate());
    }
  }

  // ---- a certificate the SDK could not write ----

  @Test
  void aCertificateTheSdkCouldNotWriteIsCarriedAndUsedByLaterConfigurations(@TempDir Path dir)
      throws Exception {
    Path files = dir.resolve("files");
    Files.createDirectory(files);
    org.junit.jupiter.api.Assumptions.assumeTrue(
        files.getFileSystem().supportedFileAttributeViews().contains("posix")
            && !"root".equals(System.getProperty("user.name")),
        "a read-only directory needs POSIX permissions, and refuses root nothing");
    Pki pki = new Pki(files);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    java.util.Set<java.nio.file.attribute.PosixFilePermission> writable =
        Files.getPosixFilePermissions(files);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      // The directory turns read-only (a full disk, say) once the request is on its way: the
      // pending key is written, nothing after it can be.
      ClientRenewal.beforeReProvision =
          () -> {
            ClientRenewal.beforeReProvision = null;
            try {
              Files.setPosixFilePermissions(
                  files, java.nio.file.attribute.PosixFilePermissions.fromString("r-x------"));
            } catch (IOException e) {
              throw new AssertionError(e);
            }
          };
      RenewalNotSavedException e;
      try {
        e = assertThrows(RenewalNotSavedException.class, kms::renewClientCertificate);
      } finally {
        Files.setPosixFilePermissions(files, writable);
      }
      X509Certificate issued = e.chain().get(0);
      assertEquals(1, tls.retiredCertificates().size());
      assertEquals(pki.client.certificate(), leaf(pki.chain), "the files hold the old one");
      assertFalse(pending(pki).issued(), "the pending file holds only the key");
      // The certificate is in the exception and the failure event, in PEM.
      assertTrue(e.pem().startsWith("-----BEGIN CERTIFICATE-----"), e.pem());
      assertTrue(e.getMessage().contains(e.pem()), e.getMessage());
      assertTrue(events.failed.get(events.failed.size() - 1).contains(e.pem()));
      assertEquals(
          issued,
          java.security.cert.CertificateFactory.getInstance("X.509")
              .generateCertificate(
                  new java.io.ByteArrayInputStream(
                      e.pem().getBytes(java.nio.charset.StandardCharsets.US_ASCII))));

      // A configuration of the same files built now uses the new certificate, not the files'.
      tls.dropConnections();
      try (Kms later = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
        later.ping();
        assertEquals(issued, tls.clientCertificates().get(tls.clientCertificates().size() - 1));
        // Its renewal writes the files: the pending file with the certificate first, so a stop
        // during the switch can be finished. The switch stops after the chain file here.
        AtomicInteger forces = new AtomicInteger();
        StagedFiles.directorySync =
            d -> {
              if (forces.incrementAndGet() == 2) throw new IOException("injected");
            };
        RenewalNotSavedException stopped =
            assertThrows(RenewalNotSavedException.class, later::renewClientCertificate);
        assertTrue(stopped.getMessage().contains("A restart finishes the switch"));
        StagedFiles.directorySync = StagedFiles::forceDirectory;
        assertTrue(pending(pki).issued(), "the pending file holds the certificate");
        assertEquals(issued, pending(pki).chain().get(0));
        assertEquals(issued, leaf(pki.chain), "the chain file was switched");
      }
      // A new start finishes the switch from the pending file.
      KmsConfig restarted = pki.renewing(tls, CertificateRenewal.onDemand()).build();
      assertFalse(Files.exists(pendingFile(files)));
      assertNotNull(KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem));
      try (Kms k = Kms.connect(restarted)) {
        tls.dropConnections();
        k.ping();
      }
    }
  }

  @Test
  void aKeyOnlyPendingFileWhoseKeyTheChainFileHoldsIsFinished(@TempDir Path dir) throws Exception {
    // A switch that stopped between the chain file and the key file, while the pending file held
    // only the key: the chain file holds a certificate for the pending key.
    Pki pki = new Pki(dir);
    RenewalFiles files = files(pki);
    KeyPair next = TestPki.ec();
    files.writeNewPending(
        next.getPrivate(),
        RenewalFiles.fingerprint(pki.client.certificate()),
        next.getPublic(),
        null,
        null,
        p -> new IllegalStateException());
    X509Certificate issued = TestPki.leaf("client", next, pki.ca).certificate();
    Files.writeString(pki.chain, pem("CERTIFICATE", issued.getEncoded()));
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig config = pki.renewing(tls, CertificateRenewal.onDemand()).build();
      assertFalse(Files.exists(pendingFile(dir)));
      assertEquals(issued, leaf(pki.chain));
      assertNotNull(KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem));
      try (Kms kms = Kms.connect(config)) {
        kms.ping();
      }
    }
    // A key-only pending file for another key is left as it is.
    KeyPair other = TestPki.ec();
    files.writeNewPending(
        other.getPrivate(), "00", other.getPublic(), null, null, p -> new IllegalStateException());
    assertNull(files.finishIssued(null));
    assertTrue(Files.exists(pendingFile(dir)));
  }

  // ---- a certificate the client refuses ----

  @Test
  void anIssuerSignatureTheClientCannotVerifyIsReportedNotRefused(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    // The client trusts an impostor of the provisioning CA: the same name, another key, so the
    // issued certificate's signature does not verify with the issuer the client knows. The server
    // trusts the real one, and has retired the current certificate: refusing would lock out.
    Issued impostor = TestPki.ca("Provisioning CA");
    Path trust = dir.resolve("trust.pem");
    Files.writeString(
        trust,
        pem("CERTIFICATE", pki.ca.certificate().getEncoded())
            + pem("CERTIFICATE", impostor.certificate().getEncoded()));
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand())
                    .trustPem(trust)
                    .addListener(events)
                    .build())) {
      RenewedCertificate r = kms.renewClientCertificate();
      assertEquals(r.certificate(), leaf(pki.chain));
      assertTrue(events.lockedOut.isEmpty());
      assertEquals(1, events.warned.size(), events.warned.toString());
      assertTrue(events.warned.get(0).contains("its signature does not verify"));
      tls.dropConnections();
      kms.ping();
    }
  }

  @Test
  void aCertificateTheClientRefusesIsReportedAsALockout(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      leavePendingKey(server, kms);
      RenewalFiles.Pending pending = pending(pki);
      // The server holds a certificate for the pending key with another subject: the resumed
      // attempt's search finds it, and the client cannot use it.
      String id = register(kms, new Issued(otherSubject(pki, pending.publicKey()), pending.key()));
      OutcomeUnknownException e =
          assertThrows(OutcomeUnknownException.class, kms::renewClientCertificate);
      assertInstanceOf(ProtocolViolationException.class, e.getCause());
      assertTrue(e.getMessage().contains("may be locked out"), e.getMessage());
      assertTrue(e.getMessage().contains("its subject"), e.getMessage());
      assertTrue(
          e.getMessage().contains("The new private key is in " + pendingFile(dir) + ". "),
          e.getMessage());
      assertEquals(java.util.Optional.of(id), e.objectId());
      assertEquals(1, events.lockedOut.size());
      assertNotNull(pending(pki), "the new key is kept");
      assertFalse(pending(pki).issued());
      assertEquals(pki.client.certificate(), leaf(pki.chain), "the files are not switched");
    }
  }

  /** A certificate for {@code key} from {@code pki}'s CA, for another subject than the client's. */
  static X509Certificate otherSubject(Pki pki, java.security.PublicKey key) {
    return TestX509.certificate("someone-else", key)
        .issuedBy(pki.ca.certificate(), pki.ca.key())
        .localhost()
        .extendedKeyUsage(ClientRenewal.CLIENT_AUTH)
        .build();
  }

  // ---- keys moved aside ----

  /**
   * A key an earlier attempt moved aside for {@code pki}'s current certificate, as {@link
   * RenewalFiles#setAside} leaves it.
   */
  static Path keyAside(Pki pki, KeyPair key) throws Exception {
    RenewalFiles f = files(pki);
    f.writeNewPending(
        key.getPrivate(),
        RenewalFiles.fingerprint(leaf(pki.chain)),
        key.getPublic(),
        null,
        null,
        p -> new IllegalStateException());
    return f.setAside(Instant.now());
  }

  @Test
  void aRefusedCertificateForAKeyMovedAsideNamesThatKeysFile(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        KmipClient other = onCurrentCertificate(tls, pki);
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      kms.ping();
      KeyPair key = TestPki.ec();
      Path aside = keyAside(pki, key);
      // The server holds a certificate for that key the client cannot use, and the current
      // certificate is retired: the search through the Kms's open connection finds it.
      register(kms, new Issued(otherSubject(pki, key.getPublic()), key.getPrivate()));
      commitLate(other, pki, TestPki.ec());
      OutcomeUnknownException e =
          assertThrows(OutcomeUnknownException.class, kms::renewClientCertificate);
      assertTrue(e.getMessage().contains("its subject"), e.getMessage());
      assertTrue(
          e.getMessage().contains("The new private key is in " + aside + ". "), e.getMessage());
      assertFalse(
          e.getMessage().contains("The new private key is in " + pendingFile(dir) + ". "),
          e.getMessage());
      assertFalse(Files.exists(pendingFile(dir)));
      assertTrue(Files.exists(aside), "the key is kept");
      assertEquals(1, events.lockedOut.size());
    }
  }

  @Test
  void aFailedPendingWriteForAKeyMovedAsideNamesThatKeysFile(@TempDir Path dir) throws Exception {
    Path files = dir.resolve("files");
    Files.createDirectory(files);
    org.junit.jupiter.api.Assumptions.assumeTrue(
        files.getFileSystem().supportedFileAttributeViews().contains("posix")
            && !"root".equals(System.getProperty("user.name")),
        "a read-only directory needs POSIX permissions, and refuses root nothing");
    Pki pki = new Pki(files);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    java.util.Set<java.nio.file.attribute.PosixFilePermission> writable =
        Files.getPosixFilePermissions(files);
    try (TlsListener tls = pki.listener(server).start();
        KmipClient earlier = onCurrentCertificate(tls, pki);
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      kms.ping();
      KeyPair key = TestPki.ec();
      Path aside = keyAside(pki, key);
      X509Certificate issued = commitLate(earlier, pki, key);
      Files.createFile(files.resolve("client.key.renewal.lock"));
      // The directory turns read-only: the pending file cannot be written.
      Files.setPosixFilePermissions(
          files, java.nio.file.attribute.PosixFilePermissions.fromString("r-x------"));
      RenewalNotSavedException e;
      try {
        e = assertThrows(RenewalNotSavedException.class, kms::renewClientCertificate);
      } finally {
        Files.setPosixFilePermissions(files, writable);
      }
      assertEquals(issued, e.chain().get(0));
      assertTrue(e.getMessage().contains("writing the pending file"), e.getMessage());
      assertTrue(e.getMessage().contains("private key is in " + aside + ";"), e.getMessage());
      assertFalse(Files.exists(pendingFile(files)));
      assertTrue(Files.exists(aside), "the key is kept");
      // A second failure names the same file: the key is still only there.
      Files.setPosixFilePermissions(
          files, java.nio.file.attribute.PosixFilePermissions.fromString("r-x------"));
      try {
        e = assertThrows(RenewalNotSavedException.class, kms::renewClientCertificate);
      } finally {
        Files.setPosixFilePermissions(files, writable);
      }
      assertTrue(e.getMessage().contains("private key is in " + aside + ";"), e.getMessage());
      // Once writable, the next call writes the files, and the key moved aside goes.
      RenewedCertificate r = kms.renewClientCertificate();
      assertEquals(issued, r.certificate());
      assertEquals(issued, leaf(pki.chain));
      assertEquals(List.of(), files(pki).unresolved());
    }
  }

  @Test
  void aRequestRefusedWithPermissionDeniedLooksForKeysMovedAside(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        KmipClient earlier = onCurrentCertificate(tls, pki);
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      KeyPair key = TestPki.ec();
      Path aside = keyAside(pki, key);
      // The earlier request for the key moved aside commits once this attempt's connections are
      // open: the server refuses this attempt's request (the certificate is retired).
      X509Certificate[] issued = new X509Certificate[1];
      ClientRenewal.beforeReProvision =
          () -> {
            ClientRenewal.beforeReProvision = null;
            try {
              issued[0] = commitLate(earlier, pki, key);
            } catch (Exception e) {
              throw new AssertionError(e);
            }
          };
      RenewedCertificate r = kms.renewClientCertificate();
      assertTrue(r.finishedEarlierAttempt());
      assertEquals(issued[0], r.certificate());
      assertEquals(issued[0], leaf(pki.chain));
      assertFalse(Files.exists(pendingFile(dir)), "this attempt's own key is deleted");
      assertFalse(Files.exists(aside));
      assertTrue(events.lockedOut.isEmpty());
      assertEquals(1, tls.retiredCertificates().size());
      tls.dropConnections();
      kms.ping();
    }
  }

  @Test
  void aRequestRefusedWithPermissionDeniedWithNothingFoundSaysSo(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      Path aside = keyAside(pki, TestPki.ec());
      // The policy refuses Re-Provision: nothing was issued for the key moved aside either.
      server.failNext(ServerOperation.RE_PROVISION, Fault.PERMISSION_DENIED);
      PermissionDeniedException e =
          assertThrows(PermissionDeniedException.class, kms::renewClientCertificate);
      assertTrue(e.getMessage().contains("found no certificate"), e.getMessage());
      assertTrue(e.getMessage().contains(aside.toString()), e.getMessage());
      assertFalse(Files.exists(pendingFile(dir)));
      assertTrue(Files.exists(aside), "kept: the earlier request may still commit");
      assertEquals(List.of(), tls.retiredCertificates());
    }
  }

  @Test
  void automaticRenewalFollowsUpAKeyMovedAside(@TempDir Path dir) throws Exception {
    ClientRenewal.firstBackoff = Duration.ofMillis(20);
    ClientRenewal.maxBackoff = Duration.ofMillis(40);
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        KmipClient earlier = onCurrentCertificate(tls, pki)) {
      KeyPair key = TestPki.ec();
      Path aside = keyAside(pki, key);
      // The certificate expires in 30 days, far outside a one-day window: only the key moved
      // aside makes the checks look at the server.
      try (Kms kms =
          Kms.connect(
              pki.renewing(tls, CertificateRenewal.automatic(Duration.ofDays(1)))
                  .addListener(events)
                  .build())) {
        kms.ping();
        Thread.sleep(100);
        assertEquals(List.of(), events.renewed, "the server still accepts the certificate");
        // The earlier request commits late, and retires the current certificate.
        X509Certificate issued = commitLate(earlier, pki, key);
        await("the certificate found and switched to").until(() -> !events.renewed.isEmpty());
        assertEquals(issued, leaf(pki.chain));
        assertFalse(Files.exists(aside));
        assertEquals(List.of(), events.failed);
        assertTrue(events.lockedOut.isEmpty());
        tls.dropConnections();
        kms.ping();
      }
    }
  }

  @Test
  void aRunningKmsRefusedOnANewConnectionNamesTheKeysMovedAside(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start();
        KmipClient other = onCurrentCertificate(tls, pki);
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      kms.ping();
      Path aside = keyAside(pki, TestPki.ec());
      commitLate(other, pki, TestPki.ec());
      // An open connection still works; a new one is refused, and the message names the key.
      kms.ping();
      tls.dropConnections();
      PermissionDeniedException e = assertThrows(PermissionDeniedException.class, kms::ping);
      assertTrue(e.getMessage().contains(aside.toString()), e.getMessage());
      assertTrue(e.getMessage().contains("may be locked out"), e.getMessage());
    }
  }

  @Test
  void aRunningKmsRefusedOnlyByPolicyIsNotToldItMayBeLockedOut(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      kms.ping();
      Path aside = keyAside(pki, TestPki.ec());
      // The server's policy refuses one operation on a new connection; a Discover Versions on
      // another new connection is accepted, so the certificate is not refused.
      tls.dropConnections();
      server.failNext(ServerOperation.LOCATE, Fault.PERMISSION_DENIED);
      PermissionDeniedException e =
          assertThrows(PermissionDeniedException.class, () -> kms.keys().findByName("any"));
      assertFalse(e.getMessage().contains(aside.toString()), e.getMessage());
      assertFalse(e.getMessage().contains("locked out"), e.getMessage());
      kms.ping();
    }
  }

  // ---- reloads, recovery-file names and the pending file's format ----

  @Test
  void aReloadKeepsAnUnwrittenRenewalAndReadsTheNewTrust(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicInteger reloads = new AtomicInteger();
    KmsListener counting =
        new KmsListener() {
          @Override
          public void credentialsReloaded(String files) {
            reloads.incrementAndGet();
          }
        };
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand())
                    .reloadOnChange(Duration.ofMillis(50))
                    .addListener(counting)
                    .build())) {
      // Nothing can be written once the request is on its way.
      ClientRenewal.beforeReProvision =
          () -> {
            ClientRenewal.beforeReProvision = null;
            StagedFiles.directorySync =
                d -> {
                  throw new IOException("injected: the disk is full");
                };
          };
      RenewalNotSavedException e =
          assertThrows(RenewalNotSavedException.class, kms::renewClientCertificate);
      X509Certificate issued = e.chain().get(0);
      assertEquals(pki.client.certificate(), leaf(pki.chain), "the files hold the retired one");
      tls.dropConnections();
      kms.ping();
      assertEquals(issued, ClientCertificateRenewalTest.lastPresented(tls));
      // The trust bundle changes: the reload reads it, and keeps the renewed identity, since the
      // identity files still hold the certificate the server retired.
      Files.writeString(pki.caPem, Files.readString(pki.caPem) + "\n");
      long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
      while (reloads.get() == 0 && System.nanoTime() < deadline) {
        Thread.sleep(60);
        tls.dropConnections();
        kms.ping();
      }
      assertTrue(reloads.get() > 0, "the trust was reloaded");
      for (int i = 0; i < 3; i++) {
        tls.dropConnections();
        kms.ping();
        assertEquals(issued, ClientCertificateRenewalTest.lastPresented(tls));
      }
      // Written now: the files hold it, and a reload reads them again.
      StagedFiles.directorySync = StagedFiles::forceDirectory;
      RenewedCertificate r = kms.renewClientCertificate();
      assertEquals(issued, r.certificate());
      assertEquals(issued, leaf(pki.chain));
      int before = reloads.get();
      deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
      while (reloads.get() == before && System.nanoTime() < deadline) {
        Thread.sleep(60);
        tls.dropConnections();
        kms.ping();
      }
      assertTrue(reloads.get() > before, "the written files were read");
      tls.dropConnections();
      kms.ping();
      assertEquals(issued, ClientCertificateRenewalTest.lastPresented(tls));
    }
  }

  @Test
  void keysMovedAsideAtTheSameTimeNeverReplaceEachOther(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    RenewalFiles f = files(pki);
    String current = RenewalFiles.fingerprint(leaf(pki.chain));
    Instant same = Instant.parse("2026-11-08T12:00:00.123Z");
    List<Path> moved = new ArrayList<>();
    List<KeyPair> keys = new ArrayList<>();
    for (String suffix :
        List.of("unresolved", "unresolved", "unresolved", "orphaned", "orphaned")) {
      KeyPair key = TestPki.ec();
      keys.add(key);
      f.writeNewPending(
          key.getPrivate(), current, key.getPublic(), null, null, p -> new IllegalStateException());
      moved.add(suffix.equals("unresolved") ? f.setAside(same) : f.orphanPending(same));
    }
    // A clock that stepped back, or two moves in one millisecond: each file has a name of its own.
    assertEquals(moved.size(), new java.util.HashSet<>(moved).size(), moved.toString());
    for (int i = 0; i < moved.size(); i++) {
      assertTrue(moved.get(i).getFileName().toString().contains("20261108T120000123Z"));
      assertEquals(
          base64(keys.get(i).getPublic()),
          base64(RenewalFiles.readPending(moved.get(i), null).publicKey()),
          "the key moved there, not a later one");
    }
    assertEquals(moved.subList(0, 3).stream().sorted().toList(), f.unresolved());
    // An empty name a stopped move reserved holds nothing, and is not listed.
    Path reserved =
        moved.get(0).resolveSibling("client.key.renewal.20261108T120000124Z.unresolved");
    Files.createFile(reserved);
    assertFalse(f.unresolved().contains(reserved));
  }

  @Test
  void thePendingFileNamesItsFormatAndRefusesAnotherHeader(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    RenewalFiles f = files(pki);
    String current = RenewalFiles.fingerprint(leaf(pki.chain));
    KeyPair key = TestPki.ec();
    f.writeNewPending(
        key.getPrivate(), current, key.getPublic(), null, null, p -> new IllegalStateException());
    String written = Files.readString(pendingFile(dir));
    assertTrue(
        written.startsWith("keytend-kmip client certificate renewal 1\n"),
        written.substring(0, 60));
    assertEquals(base64(key.getPublic()), base64(pending(pki).publicKey()));
    assertEquals(current, RenewalFiles.replaces(pendingFile(dir)));
    // A header line without its format's version is not this SDK's header: refused, never guessed.
    Files.writeString(
        pendingFile(dir),
        written.replace(
            "keytend-kmip client certificate renewal 1\n",
            "keytend-kmip client certificate renewal\n"));
    IllegalArgumentException unversioned =
        assertThrows(IllegalArgumentException.class, () -> pending(pki));
    assertTrue(unversioned.getMessage().contains("no header"), unversioned.getMessage());
    assertNull(RenewalFiles.replaces(pendingFile(dir)));
    // A later format is refused by name, never misread.
    Files.writeString(pendingFile(dir), written.replace("renewal 1\n", "renewal 2\n"));
    IllegalArgumentException later =
        assertThrows(IllegalArgumentException.class, () -> pending(pki));
    assertTrue(later.getMessage().contains("format 2"), later.getMessage());
  }

  @Test
  void keysMovedAsideForARetiredCertificateAreDeletedAfterARenewal(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      Path mine = keyAside(pki, TestPki.ec());
      // One for another certificate stays.
      KeyPair otherKey = TestPki.ec();
      RenewalFiles f = files(pki);
      f.writeNewPending(
          otherKey.getPrivate(),
          "00".repeat(32),
          otherKey.getPublic(),
          null,
          null,
          p -> new IllegalStateException());
      Path theirs = f.setAside(Instant.now().plusSeconds(1));
      kms.renewClientCertificate();
      assertFalse(Files.exists(mine));
      assertTrue(Files.exists(theirs));
      assertEquals(1, events.warned.size(), events.warned.toString());
      assertTrue(events.warned.get(0).contains("deleted [" + mine + "]"), events.warned.get(0));
    }
  }

  @Test
  void anIoFailureAfterARefusalKeepsTheRefusal(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      // The directory forces: 1 the pending key, 2 its deletion after the refusal.
      AtomicInteger forces = new AtomicInteger();
      StagedFiles.directorySync =
          d -> {
            if (forces.incrementAndGet() == 2) throw new IOException("injected");
          };
      server.failNext(ServerOperation.RE_PROVISION, Fault.UNSUPPORTED);
      UnsupportedException e =
          assertThrows(UnsupportedException.class, kms::renewClientCertificate);
      assertEquals(1, e.getSuppressed().length);
      assertEquals("injected", e.getSuppressed()[0].getMessage());
    }
  }

  // ---- pending files of other identity files ----

  @Test
  void aPendingFileOfOtherIdentityFilesIsMovedAsideNotDeleted(@TempDir Path dir) throws Exception {
    for (boolean issued : new boolean[] {false, true}) {
      Path sub = dir.resolve("issued-" + issued);
      Files.createDirectory(sub);
      Pki pki = new Pki(sub);
      KeyPair other = TestPki.ec();
      List<X509Certificate> chain =
          issued ? List.of(TestPki.leaf("client", other, pki.ca).certificate()) : List.of();
      files(pki)
          .writePending(
              other.getPrivate(),
              chain,
              "00".repeat(32),
              issued ? "an-identifier" : null,
              other.getPublic(),
              null,
              null);
      byte[] before = Files.readAllBytes(pendingFile(sub));
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      Events events = new Events();
      try (TlsListener tls = pki.listener(server).start();
          Kms kms =
              Kms.connect(
                  pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
        RenewedCertificate r = kms.renewClientCertificate();
        assertFalse(r.finishedEarlierAttempt());
        List<Path> orphaned;
        try (Stream<Path> s = Files.list(sub)) {
          orphaned = s.filter(p -> p.toString().endsWith(".orphaned")).toList();
        }
        assertEquals(1, orphaned.size(), "issued " + issued);
        assertTrue(
            orphaned.get(0).getFileName().toString().startsWith("client.key.renewal."),
            orphaned.get(0).toString());
        assertArrayEquals(before, Files.readAllBytes(orphaned.get(0)));
        // A warning, not a failure: the attempt went on and renewed, and is told once.
        assertEquals(1, events.warned.size(), events.warned.toString());
        assertTrue(events.warned.get(0).contains(orphaned.get(0).toString()), events.warned.get(0));
        assertEquals(List.of(), events.failed);
        assertFalse(Files.exists(pendingFile(sub)));
        assertEquals(1, events.renewed.size());
      }
    }
  }

  // ---- renewals of the same files at the same time ----

  @Test
  void twoThreadsAndTwoConfigurationsTakeTurns(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig first = pki.renewing(tls, CertificateRenewal.onDemand()).build();
      KmsConfig second = pki.renewing(tls, CertificateRenewal.onDemand()).build();
      ExecutorService pool = Executors.newFixedThreadPool(4);
      try (Kms a = Kms.connect(first);
          Kms b = Kms.connect(first);
          Kms c = Kms.connect(second)) {
        CountDownLatch start = new CountDownLatch(1);
        List<Future<RenewedCertificate>> runs = new ArrayList<>();
        for (Kms k : List.of(a, b, c)) {
          Callable<RenewedCertificate> renew =
              () -> {
                start.await();
                return k.renewClientCertificate();
              };
          runs.add(pool.submit(renew));
        }
        start.countDown();
        int renewed = 0;
        for (Future<RenewedCertificate> f : runs) {
          try {
            f.get();
            renewed++;
          } catch (java.util.concurrent.ExecutionException e) {
            assertInstanceOf(TransientException.class, e.getCause());
          }
        }
        assertTrue(renewed >= 1);
        // One renewal after another: each retired the certificate the one before it issued.
        assertEquals(renewed, tls.retiredCertificates().size());
        assertFalse(Files.exists(pendingFile(dir)));
        assertNotNull(KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem));
        // Every Kms of both configurations uses the files' certificate on new connections.
        tls.dropConnections();
        for (Kms k : List.of(a, b, c)) k.ping();
        List<X509Certificate> presented = tls.clientCertificates();
        X509Certificate now = leaf(pki.chain);
        for (X509Certificate p : presented.subList(presented.size() - 3, presented.size()))
          assertEquals(now, p);
      } finally {
        pool.shutdownNow();
      }
    }
  }

  @Test
  void anotherProcessHoldingTheLockMakesTheAttemptTransient(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Path lockFile = dir.resolve("client.key.renewal.lock");
    try (TlsListener tls = pki.listener(server).start();
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      try (FileChannel other =
          FileChannel.open(lockFile, StandardOpenOption.CREATE, StandardOpenOption.WRITE)) {
        other.lock();
        TransientException e = assertThrows(TransientException.class, kms::renewClientCertificate);
        assertTrue(e.getMessage().contains("another process"), e.getMessage());
        assertFalse(Files.exists(pendingFile(dir)));
        assertEquals(List.of(), tls.retiredCertificates());
      }
      assertNotNull(kms.renewClientCertificate());
      assertTrue(Files.exists(lockFile), "the lock file stays");
    }
  }

  @Test
  void theFirstPendingWriteNeverReplacesAnotherHoldersFile(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    RenewalFiles files = files(pki);
    KeyPair key = TestPki.ec();
    Files.writeString(pendingFile(dir), "another holder's");
    IllegalStateException claimed =
        assertThrows(
            IllegalStateException.class,
            () ->
                files.writeNewPending(
                    key.getPrivate(),
                    "00",
                    key.getPublic(),
                    null,
                    null,
                    p -> new IllegalStateException("claimed " + p)));
    assertTrue(claimed.getMessage().contains("claimed"));
    assertEquals("another holder's", Files.readString(pendingFile(dir)));
    // An empty file is a claim that stopped before the key was written: read as none.
    Files.write(pendingFile(dir), new byte[0]);
    assertNull(files.readPending(null));
    assertFalse(Files.exists(pendingFile(dir)));
    files.writeNewPending(
        key.getPrivate(), "00", key.getPublic(), null, null, p -> new IllegalStateException());
    assertNotNull(files.readPending(null));
  }
}
