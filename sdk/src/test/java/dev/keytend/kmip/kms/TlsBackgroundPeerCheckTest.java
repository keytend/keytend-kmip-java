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
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.TestAwait;
import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.kms.TlsHandshakeTest.Server;
import dev.keytend.kmip.kms.TlsIdentityTest.Pki;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The default check of a peer not allowed yet: a handshake never waits for the KMS; it refuses the
 * peer at once and queues the check on the follower's executor, and the peer's next handshake is
 * accepted once the check admitted it. Real JSSE handshakes against a KMS that answers slowly.
 */
class TlsBackgroundPeerCheckTest {
  static final CustomAttribute TAG = CustomAttribute.client("tls");

  /**
   * A KMS transport whose answers take {@code delayMillis}, or that holds every request while
   * {@linkplain #hold() held}, until {@link #release()}.
   */
  static final class Slow implements KmipTransport {
    final InMemoryKmipServer server;
    final AtomicLong delayMillis = new AtomicLong();
    volatile CountDownLatch gate;
    final CountDownLatch reached = new CountDownLatch(1);

    Slow(InMemoryKmipServer server) {
      this.server = server;
    }

    @Override
    public Ttlv exchange(Ttlv request) throws IOException {
      return exchange(request, CallContext.NONE);
    }

    @Override
    public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
      long delay = delayMillis.get();
      CountDownLatch held = gate;
      try {
        if (held != null) {
          reached.countDown();
          if (!held.await(30, TimeUnit.SECONDS)) throw new IOException("never released");
        }
        if (delay > 0) Thread.sleep(delay);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new java.io.InterruptedIOException();
      }
      return server.exchange(request, context);
    }

    /** Holds every request from now until {@link #release()}. */
    void hold() {
      gate = new CountDownLatch(1);
    }

    void release() {
      CountDownLatch held = gate;
      gate = null;
      if (held != null) held.countDown();
    }
  }

  /** An executor that holds what is executed until the test runs it, or refuses it. */
  static final class Held extends ScheduledThreadPoolExecutor {
    final List<Runnable> held = new CopyOnWriteArrayList<>();
    volatile boolean refuse;

    Held() {
      super(1);
    }

    @Override
    public void execute(Runnable task) {
      if (refuse) throw new RejectedExecutionException("refused");
      held.add(task);
    }

    void runAll() {
      while (!held.isEmpty()) held.remove(0).run();
    }
  }

  static X509TrustManager pkixOf(Issued root) throws Exception {
    java.security.KeyStore store = java.security.KeyStore.getInstance("PKCS12");
    store.load(null, null);
    store.setCertificateEntry("root", root.certificate());
    TrustManagerFactory f = TrustManagerFactory.getInstance("PKIX");
    f.init(store);
    for (TrustManager tm : f.getTrustManagers()) if (tm instanceof X509TrustManager x) return x;
    throw new AssertionError();
  }

  /** Waits, up to 30 s (a background check on a loaded machine), until {@code certificate} is allowed. */
  static void awaitAllowed(TlsTrustFollower trust, X509Certificate certificate) {
    TestAwait.await("the background check admits " + certificate.getSubjectX500Principal())
        .atMost(Duration.ofSeconds(30))
        .until(() -> trust.allowedPeers().orElseThrow().containsValue(certificate));
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aHandshakeNeverWaitsForTheKmsAndTheNextOneIsAccepted(KmipVersion version) throws Exception {
    InMemoryKmipServer kmsServer = InMemoryKmipServer.of(version);
    Slow slow = new Slow(kmsServer);
    Pki pki = new Pki();
    KeyPair serverKey = TestPki.ec();
    try (Kms admin = kmsServer.connect();
        Kms kms =
            Kms.connect(
                kmsServer
                    .configure()
                    .maximumVersion(KmipVersion.V3_0)
                    .callTimeout(Duration.ofSeconds(10))
                    .transport(e -> slow)
                    .build())) {
      admin
          .keys()
          .register(pki.root.certificate())
          .usages(KeyUsage.VERIFY)
          .custom(TAG, "ca")
          .register();
      admin
          .tls()
          .register(serverKey.getPrivate(), pki.chain(pki.leaf("server", serverKey)))
          .named("server")
          .register();
      KeyQuery anchors = KeyQuery.all().custom(TAG, "ca"),
          peers = KeyQuery.all().custom(TAG, "peer");
      try (TlsIdentityFollower identity = kms.tls().follow("server", HOURLY, SCHEDULER);
          TlsTrustFollower trust = kms.tls().trustAnchors(anchors, peers, HOURLY, SCHEDULER);
          Server server = new Server(identity.keyManager(), trust.trustManager())) {
        // In the background a longer bound costs no handshake any time.
        trust.unknownPeerCheck(Duration.ofSeconds(20));
        X509TrustManager clientTrust = pkixOf(pki.root);
        // A client that has just renewed: registered, but not read by the follower yet.
        Issued renewed = pki.leaf("renewed", TestPki.ec());
        admin
            .keys()
            .register(renewed.certificate())
            .usages(KeyUsage.VERIFY)
            .custom(TAG, "peer")
            .register();
        // The KMS answers nothing until the handshake has ended: a handshake that waited for it
        // would wait for the check's 20 s bound.
        slow.hold();
        long start;
        try {
          start = System.nanoTime();
          assertNull(
              server.connect(TlsHandshakeTest.held(renewed, pki.chain(renewed)), clientTrust),
              "refused at once");
          long took = (System.nanoTime() - start) / 1_000_000;
          assertTrue(took < 2500, "the handshake did not wait for the KMS: " + took + " ms");
          assertTrue(slow.reached.await(10, TimeUnit.SECONDS), "the check asked the KMS");
        } finally {
          slow.release();
        }
        awaitAllowed(trust, renewed.certificate());
        X509Certificate seen =
            server.connect(TlsHandshakeTest.held(renewed, pki.chain(renewed)), clientTrust);
        assertNotNull(seen, "accepted at its next handshake: " + server.refused);
        assertEquals(identity.identity().orElseThrow().certificate(), seen);

        // A certificate the KMS does not allow is refused before and after its check.
        Issued stranger = pki.leaf("stranger", TestPki.ec());
        assertNull(
            server.connect(TlsHandshakeTest.held(stranger, pki.chain(stranger)), clientTrust));
        Thread.sleep(300); // its check runs and finds nothing
        assertNull(
            server.connect(TlsHandshakeTest.held(stranger, pki.chain(stranger)), clientTrust));
        assertFalse(trust.allowedPeers().orElseThrow().containsValue(stranger.certificate()));

        // Opting in: the handshake waits for the check, and is accepted in that handshake.
        trust.unknownPeerCheckInHandshake(true);
        Issued waited = pki.leaf("waited", TestPki.ec());
        admin
            .keys()
            .register(waited.certificate())
            .usages(KeyUsage.VERIFY)
            .custom(TAG, "peer")
            .register();
        trust.unknownPeerCheckGap(Duration.ZERO); // no wait for the gap after the stranger's check
        slow.delayMillis.set(100);
        start = System.nanoTime();
        assertNotNull(
            server.connect(TlsHandshakeTest.held(waited, pki.chain(waited)), clientTrust),
            server.refused.toString());
        assertTrue((System.nanoTime() - start) / 1_000_000 >= 100, "it waited for the KMS");
      }
    }
  }

  @Test
  void checksAreQueuedOncePerCertificateBoundedAndNeverRunOnTheHandshake() throws Exception {
    InMemoryKmipServer kmsServer = InMemoryKmipServer.of(KmipVersion.V2_1);
    Pki pki = new Pki();
    Held executor = new Held();
    try (Kms kms = TlsIdentityTest.connect(kmsServer)) {
      kms.keys()
          .register(pki.root.certificate())
          .usages(KeyUsage.VERIFY)
          .custom(TAG, "ca")
          .register();
      TlsTrustFollower trust =
          kms.tls()
              .trustAnchors(
                  KeyQuery.all().custom(TAG, "ca"),
                  KeyQuery.all().custom(TAG, "peer"),
                  HOURLY,
                  executor);
      Issued peer = pki.leaf("peer", TestPki.ec());
      kms.keys()
          .register(peer.certificate())
          .usages(KeyUsage.VERIFY)
          .custom(TAG, "peer")
          .register();
      int exchanges = kmsServer.exchanges();
      CertificateException first =
          assertThrows(
              CertificateException.class,
              () -> trust.trustManager().checkClientTrusted(pki.chain(peer), "EC"));
      assertTrue(first.getMessage().contains("queued"), first.getMessage());
      CertificateException again =
          assertThrows(
              CertificateException.class,
              () -> trust.trustManager().checkClientTrusted(pki.chain(peer), "EC"));
      assertTrue(again.getMessage().contains("under way"), again.getMessage());
      assertEquals(1, executor.held.size(), "one check per certificate");
      assertEquals(exchanges, kmsServer.exchanges(), "nothing is sent on the handshake's thread");
      executor.runAll();
      trust.trustManager().checkClientTrusted(pki.chain(peer), "EC");

      // Bounded: at most QUEUED checks wait; a refused executor or checks turned off queue none.
      Issued[] strangers = new Issued[TlsTrustFollower.QUEUED + 1];
      for (int i = 0; i < strangers.length; i++) {
        strangers[i] = pki.leaf("s" + i, TestPki.ec());
        Issued s = strangers[i];
        CertificateException e =
            assertThrows(
                CertificateException.class,
                () -> trust.trustManager().checkClientTrusted(pki.chain(s), "EC"));
        if (i == TlsTrustFollower.QUEUED)
          assertTrue(e.getMessage().contains("too many"), e.getMessage());
      }
      assertEquals(TlsTrustFollower.QUEUED, executor.held.size());
      executor
          .runAll(); // each check ends (most within the gap between checks), and leaves the queue
      executor.refuse = true;
      Issued refused = pki.leaf("refused", TestPki.ec());
      CertificateException e =
          assertThrows(
              CertificateException.class,
              () -> trust.trustManager().checkClientTrusted(pki.chain(refused), "EC"));
      assertTrue(e.getMessage().contains("executor refused"), e.getMessage());
      executor.refuse = false;
      trust.unknownPeerCheck(Duration.ZERO);
      e =
          assertThrows(
              CertificateException.class,
              () -> trust.trustManager().checkClientTrusted(pki.chain(refused), "EC"));
      assertTrue(e.getMessage().contains("off"), e.getMessage());
      assertTrue(executor.held.isEmpty());

      // A queued check that waited longer than its own bound is dropped, unread.
      trust.unknownPeerCheck(Duration.ofMillis(50));
      Issued late = pki.leaf("late", TestPki.ec());
      kms.keys()
          .register(late.certificate())
          .usages(KeyUsage.VERIFY)
          .custom(TAG, "peer")
          .register();
      assertThrows(
          CertificateException.class,
          () -> trust.trustManager().checkClientTrusted(pki.chain(late), "EC"));
      Thread.sleep(150);
      int before = kmsServer.exchanges();
      executor.runAll();
      assertEquals(before, kmsServer.exchanges(), "the stale check sent nothing");
      assertThrows(
          CertificateException.class,
          () -> trust.trustManager().checkClientTrusted(pki.chain(late), "EC"));
      trust.unknownPeerCheck(Duration.ofSeconds(2));
      Thread.sleep(1100); // past the gap after the last check that ran
      executor.runAll();
      trust.trustManager().checkClientTrusted(pki.chain(late), "EC");
      trust.close();
      executor.shutdownNow();
    }
  }

  /**
   * A check re-reads every allowed peer, as a refresh does, so one check admits every peer
   * renewed before it, not just the one whose handshake asked: after a mass renewal the rate limits
   * delay only peers renewed after the last check. The first renewed peer's handshake queues one
   * check; the others, within the gap and never checked, are accepted at their next handshake.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void oneCheckAdmitsEveryPeerRenewedBeforeIt(KmipVersion version) throws Exception {
    InMemoryKmipServer kmsServer = InMemoryKmipServer.of(version);
    Pki pki = new Pki();
    Held executor = new Held();
    try (Kms kms = TlsIdentityTest.connect(kmsServer)) {
      kms.keys()
          .register(pki.root.certificate())
          .usages(KeyUsage.VERIFY)
          .custom(TAG, "ca")
          .register();
      TlsTrustFollower trust =
          kms.tls()
              .trustAnchors(
                  KeyQuery.all().custom(TAG, "ca"),
                  KeyQuery.all().custom(TAG, "peer"),
                  HOURLY,
                  executor);
      Issued[] renewed = new Issued[20];
      for (int i = 0; i < renewed.length; i++) {
        renewed[i] = pki.leaf("node" + i, TestPki.ec());
        kms.keys()
            .register(renewed[i].certificate())
            .usages(KeyUsage.VERIFY)
            .custom(TAG, "peer")
            .register();
      }
      for (Issued peer : renewed) assertFalse(trust.allows(pki.chain(peer)), "not read yet");
      CertificateException first =
          assertThrows(
              CertificateException.class,
              () -> trust.trustManager().checkClientTrusted(pki.chain(renewed[0]), "EC"));
      assertTrue(first.getMessage().contains("queued"), first.getMessage());
      assertEquals(1, executor.held.size());
      executor.runAll(); // the one check
      for (Issued peer : renewed) {
        assertTrue(trust.allows(pki.chain(peer)), "admitted by the one check");
        trust.trustManager().checkClientTrusted(pki.chain(peer), "EC");
      }
      assertTrue(executor.held.isEmpty(), "no further check was needed");
      trust.close();
      executor.shutdownNow();
    }
  }

  @Test
  void theGapBetweenChecksRunsFromTheEndOfTheLastOne() throws Exception {
    InMemoryKmipServer kmsServer = InMemoryKmipServer.of(KmipVersion.V2_1);
    Pki pki = new Pki();
    AtomicLong ticker = new AtomicLong(System.nanoTime());
    java.util.concurrent.atomic.AtomicBoolean slowCheck =
        new java.util.concurrent.atomic.AtomicBoolean();
    try (Kms kms =
        Kms.connect(
            kmsServer
                .configure()
                .maximumVersion(KmipVersion.V3_0)
                .callTimeout(Duration.ofSeconds(10))
                .transport(
                    e ->
                        request -> {
                          if (slowCheck.get())
                            ticker.addAndGet(
                                5_000_000_000L); // the check takes 5 s by the follower's clock
                          return kmsServer.exchange(request);
                        })
                .build())) {
      kms.keys()
          .register(pki.root.certificate())
          .usages(KeyUsage.VERIFY)
          .custom(TAG, "ca")
          .register();
      try (TlsTrustFollower trust =
          kms.tls()
              .trustAnchors(
                  KeyQuery.all().custom(TAG, "ca"),
                  KeyQuery.all().custom(TAG, "peer"),
                  HOURLY,
                  SCHEDULER)
              .unknownPeerCheckInHandshake(true)) {
        trust.ticker = ticker::get;
        ticker.addAndGet(5_000_000_000L);
        Issued first = pki.leaf("first", TestPki.ec()), second = pki.leaf("second", TestPki.ec());
        slowCheck.set(true);
        assertThrows(
            CertificateException.class,
            () -> trust.trustManager().checkClientTrusted(pki.chain(first), "EC"));
        slowCheck.set(false);
        CertificateException gap =
            assertThrows(
                CertificateException.class,
                () -> trust.trustManager().checkClientTrusted(pki.chain(second), "EC"));
        assertTrue(
            gap.getMessage().contains("another unknown peer was checked less than 1 s ago"),
            "measured from the end of the 5-second check: " + gap.getMessage());
      }
    }
  }
}
