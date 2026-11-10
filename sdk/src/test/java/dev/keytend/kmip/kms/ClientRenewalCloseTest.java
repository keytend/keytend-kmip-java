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
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.ClientCertificateRenewalTest.Pki;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.testing.TlsListener;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * {@link Kms#close()} while a renewal of the client certificate runs, on demand or automatic: a
 * renewal that has not sent its request sends nothing; one that has is waited for until it ends;
 * the last {@code Kms} of a configuration waits for the renewals of all of them; a close on the
 * renewal's own thread does not wait for it; a wait that runs out reports what is on disk; and
 * no listener hears an event after the close returns.
 */
class ClientRenewalCloseTest {
  @AfterEach
  void reset() {
    StagedFiles.directorySync = StagedFiles::forceDirectory;
    ClientRenewal.beforeReProvision = null;
  }

  /** Where the renewal is when the {@code Kms} closes. */
  enum Stage {
    /** Just before Re-Provision is sent. */
    BEFORE_SEND,
    /** The server committed Re-Provision and holds the reply. */
    REPLY_HELD,
    /** Writing the issued certificate to the pending file. */
    PENDING_RECORD,
    /** Switching the identity files. */
    SWITCH
  }

  /** Records the renewal events, and each one heard once the close returned. */
  static class Late implements KmsListener {
    final AtomicBoolean closed = new AtomicBoolean();
    final List<String> renewed = new CopyOnWriteArrayList<>(),
        lockedOut = new CopyOnWriteArrayList<>(),
        warned = new CopyOnWriteArrayList<>(),
        late = new CopyOnWriteArrayList<>();

    private void after(String what) {
      if (closed.get()) late.add(what);
    }

    @Override
    public void clientCertificateRenewed(String previous, String fingerprint, Instant notAfter) {
      after("renewed");
      renewed.add(previous + " -> " + fingerprint);
    }

    @Override
    public void clientCertificateRenewalFailed(String fingerprint, String why) {
      after("failed: " + why);
    }

    @Override
    public void clientCertificateMayBeLockedOut(String fingerprint, String why) {
      after("locked out: " + why);
      lockedOut.add(why);
    }

    @Override
    public void clientCertificateRenewalWarning(String fingerprint, String why) {
      after("warning: " + why);
      warned.add(why);
    }
  }

  static boolean reProvision(Ttlv request) {
    for (Ttlv item : request.children(Tag.BATCH_ITEM))
      if (item.child(Tag.OPERATION).map(Ttlv::intValue).orElse(0) == Operation.RE_PROVISION.code())
        return true;
    return false;
  }

  /**
   * Holds the renewal at {@code stage}: {@code reached} counts down there, and it goes on once
   * {@code release} does. The server's Re-Provision count goes to {@code sent}.
   */
  static void holdAt(
      Stage stage,
      InMemoryKmipServer server,
      CountDownLatch reached,
      CountDownLatch release,
      AtomicInteger sent) {
    AtomicInteger forced = new AtomicInteger();
    server.injectAfterProcessing(
        request -> {
          if (reProvision(request)) {
            sent.incrementAndGet();
            if (stage == Stage.REPLY_HELD) reached.countDown();
          }
          return null;
        });
    switch (stage) {
      case BEFORE_SEND ->
          ClientRenewal.beforeReProvision =
              () -> {
                reached.countDown();
                awaitQuietly(release);
              };
      case REPLY_HELD -> {
        server.slowReplyDelay(Duration.ofSeconds(2));
        server.failNext(ServerOperation.RE_PROVISION, Fault.SLOW);
      }
      case PENDING_RECORD, SWITCH ->
          // After the send, the first directory force is the pending file's, then the switch's.
          StagedFiles.directorySync =
              d -> {
                if (sent.get() > 0
                    && forced.incrementAndGet() == (stage == Stage.PENDING_RECORD ? 1 : 2)) {
                  reached.countDown();
                  awaitQuietly(release);
                }
                StagedFiles.forceDirectory(d);
              };
    }
  }

  static void awaitQuietly(CountDownLatch latch) {
    try {
      assertTrue(latch.await(60, TimeUnit.SECONDS), "never released");
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  /** Closes {@code kms} on a thread of its own; joined by the caller. */
  static Thread closing(Kms kms, Late events) {
    Thread t =
        new Thread(
            () -> {
              kms.close();
              events.closed.set(true);
            },
            "close");
    t.start();
    return t;
  }

  /**
   * A renewal held at each stage when its {@code Kms} closes. Before the send, the close does
   * not wait: the renewal sends nothing, deletes its key, and fails with {@link
   * IllegalStateException}. After it, the close waits until the files hold the new certificate.
   * Either way, no listener hears an event after the close returns.
   */
  @ParameterizedTest
  @CsvSource({
    "false, BEFORE_SEND",
    "false, REPLY_HELD",
    "false, PENDING_RECORD",
    "false, SWITCH",
    "true, BEFORE_SEND",
    "true, REPLY_HELD",
    "true, PENDING_RECORD",
    "true, SWITCH"
  })
  void closeStopsARenewalNotSentAndWaitsForOneSent(
      boolean automatic, Stage stage, @TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Late events = new Late();
    CountDownLatch reached = new CountDownLatch(1), release = new CountDownLatch(1);
    AtomicInteger sent = new AtomicInteger();
    holdAt(stage, server, reached, release, sent);
    AtomicReference<Object> outcome = new AtomicReference<>();
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig config =
          pki.renewing(
                  tls,
                  automatic
                      ? CertificateRenewal.automatic(RENEW_WITHIN)
                      : CertificateRenewal.onDemand())
              .addListener(events)
              .build();
      Kms kms = Kms.connect(config);
      Thread onDemand = null;
      if (!automatic) {
        onDemand =
            new Thread(
                () -> {
                  try {
                    outcome.set(kms.renewClientCertificate());
                  } catch (Exception | AssertionError e) {
                    outcome.set(e);
                  }
                },
                "renew");
        onDemand.start();
      }
      assertTrue(reached.await(30, TimeUnit.SECONDS), "the renewal reached " + stage);
      Thread close = closing(kms, events);
      if (stage == Stage.BEFORE_SEND) {
        // Nothing sent: the close does not wait for the renewal.
        close.join(10_000);
        assertFalse(close.isAlive(), "close waited for a renewal that sent nothing");
        release.countDown();
      } else {
        // Sent: the close waits for the renewal.
        close.join(500);
        assertTrue(close.isAlive(), "close returned while the renewal it must wait for runs");
        release.countDown();
        close.join(30_000);
        assertFalse(close.isAlive());
      }
      if (onDemand != null) onDemand.join(30_000);
      await("the renewal ends").until(() -> config.renewal.runningWorkers() == 0);
      Path pending = dir.resolve("client.key.renewal");
      if (stage == Stage.BEFORE_SEND) {
        assertEquals(0, sent.get(), "Re-Provision sent after close");
        assertFalse(Files.exists(pending), "the unsent key is deleted");
        assertEquals(pki.client.certificate(), leaf(pki.chain));
        assertEquals(List.of(), tls.retiredCertificates());
        if (!automatic) {
          IllegalStateException e = assertInstanceOf(IllegalStateException.class, outcome.get());
          assertEquals("Kms is closed", e.getMessage());
        }
      } else {
        // The close returned once the renewal was written: the files hold the new certificate.
        assertEquals(1, sent.get());
        assertFalse(Files.exists(pending));
        X509Certificate now = leaf(pki.chain);
        assertNotEquals(pki.client.certificate(), now);
        assertEquals(List.of(pki.client.certificate()), tls.retiredCertificates());
        assertEquals(1, events.renewed.size(), "the renewal's event, before close returned");
        if (!automatic)
          assertEquals(
              now, assertInstanceOf(RenewedCertificate.class, outcome.get()).certificate());
      }
      assertEquals(List.of(), events.late, "events after close returned");
      assertEquals(List.of(), events.lockedOut);
      assertThrows(IllegalStateException.class, kms::renewClientCertificate);
    }
  }

  /**
   * A renewal that outlives the close's wait: the close returns after three times the call
   * timeout, having reported what is on disk, and the renewal finishes in its thread, reporting
   * to the log only.
   */
  @Test
  void aCloseWhoseWaitRunsOutReportsWhatIsOnDisk(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Late events = new Late();
    CountDownLatch reached = new CountDownLatch(1), release = new CountDownLatch(1);
    AtomicInteger sent = new AtomicInteger();
    holdAt(Stage.SWITCH, server, reached, release, sent);
    AtomicReference<Object> outcome = new AtomicReference<>();
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig config =
          pki.renewing(tls, CertificateRenewal.onDemand())
              .callTimeout(Duration.ofSeconds(1))
              .addListener(events)
              .build();
      Kms kms = Kms.connect(config);
      Thread renew =
          new Thread(
              () -> {
                try {
                  outcome.set(kms.renewClientCertificate());
                } catch (Exception e) {
                  outcome.set(e);
                }
              });
      renew.start();
      assertTrue(reached.await(30, TimeUnit.SECONDS));
      long start = System.nanoTime();
      kms.close();
      events.closed.set(true);
      Duration waited = Duration.ofNanos(System.nanoTime() - start);
      assertTrue(waited.compareTo(Duration.ofMillis(2_900)) >= 0, waited.toString());
      assertTrue(waited.compareTo(Duration.ofSeconds(20)) < 0, waited.toString());
      String report = events.warned.get(events.warned.size() - 1);
      assertTrue(report.contains("waited PT3S"), report);
      assertTrue(report.contains("switching"), report);
      assertTrue(
          report.contains("holds the new private key and the certificate the server issued"),
          report);
      assertTrue(report.contains("the next start finishes the switch"), report);
      release.countDown();
      renew.join(30_000);
      // The renewal finished in its thread, after the close, heard by no listener.
      assertInstanceOf(RenewedCertificate.class, outcome.get());
      assertFalse(Files.exists(dir.resolve("client.key.renewal")));
      assertNotEquals(pki.client.certificate(), leaf(pki.chain));
      assertEquals(List.of(), events.renewed);
      assertEquals(List.of(), events.late);
    }
  }

  /**
   * A close from the listener that hears the close's report returns at once: it neither waits
   * again nor reports again, and the outer close returns after one wait.
   */
  @Test
  void aCloseFromTheWarningListenerNeitherWaitsNorWarnsAgain(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    CountDownLatch reached = new CountDownLatch(1), release = new CountDownLatch(1);
    AtomicInteger sent = new AtomicInteger();
    holdAt(Stage.SWITCH, server, reached, release, sent);
    AtomicReference<Kms> kms = new AtomicReference<>();
    List<Duration> inner = new CopyOnWriteArrayList<>();
    Late events =
        new Late() {
          @Override
          public void clientCertificateRenewalWarning(String fingerprint, String why) {
            super.clientCertificateRenewalWarning(fingerprint, why);
            long start = System.nanoTime();
            kms.get().close();
            inner.add(Duration.ofNanos(System.nanoTime() - start));
          }
        };
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig config =
          pki.renewing(tls, CertificateRenewal.onDemand())
              .callTimeout(Duration.ofSeconds(1))
              .addListener(events)
              .build();
      kms.set(Kms.connect(config));
      Thread renew =
          new Thread(
              () -> {
                try {
                  kms.get().renewClientCertificate();
                } catch (Exception e) {
                  // the renewal finishes after the close; the files say how it ended
                }
              });
      renew.start();
      assertTrue(reached.await(30, TimeUnit.SECONDS));
      long start = System.nanoTime();
      kms.get().close();
      events.closed.set(true);
      Duration waited = Duration.ofNanos(System.nanoTime() - start);
      assertEquals(1, events.warned.size(), events.warned.toString());
      assertEquals(1, inner.size());
      assertTrue(inner.get(0).compareTo(Duration.ofMillis(500)) < 0, inner.toString());
      // One wait of three times the call timeout, not one more for each close.
      assertTrue(waited.compareTo(Duration.ofMillis(2_900)) >= 0, waited.toString());
      assertTrue(waited.compareTo(Duration.ofMillis(5_500)) < 0, waited.toString());
      release.countDown();
      renew.join(30_000);
      assertFalse(Files.exists(dir.resolve("client.key.renewal")));
      assertEquals(List.of(), events.late);
      assertEquals(1, events.warned.size(), events.warned.toString());
    }
  }

  /**
   * A second close from another thread, while the first waits for a renewal, returns once the
   * first has returned: then no listener hears the renewal's events. It reports nothing itself.
   */
  @Test
  void aSecondCloseFromAnotherThreadReturnsOnceTheFirstHasReturned(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Late events = new Late();
    CountDownLatch reached = new CountDownLatch(1), release = new CountDownLatch(1);
    AtomicInteger sent = new AtomicInteger();
    holdAt(Stage.PENDING_RECORD, server, reached, release, sent);
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig config =
          pki.renewing(tls, CertificateRenewal.onDemand())
              .callTimeout(Duration.ofSeconds(1))
              .addListener(events)
              .build();
      Kms kms = Kms.connect(config);
      Thread renew =
          new Thread(
              () -> {
                try {
                  kms.renewClientCertificate();
                } catch (Exception e) {
                  // reported below through the files
                }
              });
      renew.start();
      assertTrue(reached.await(30, TimeUnit.SECONDS));
      Thread first = new Thread(kms::close, "first close");
      first.start();
      await("the first close waits").until(() -> first.getState() == Thread.State.TIMED_WAITING);
      Thread second = closing(kms, events);
      second.join(500);
      assertTrue(second.isAlive(), "the second close returned while the first waits");
      release.countDown();
      second.join(30_000);
      assertFalse(second.isAlive());
      // What the first close waited for is done when the second returns.
      assertFalse(Files.exists(dir.resolve("client.key.renewal")));
      assertNotEquals(pki.client.certificate(), leaf(pki.chain));
      assertEquals(1, events.renewed.size());
      first.join(30_000);
      assertFalse(first.isAlive());
      renew.join(30_000);
      assertEquals(List.of(), events.warned);
      assertEquals(List.of(), events.late);
    }
  }

  /**
   * The last {@code Kms} of a configuration to close waits for a renewal another one started,
   * even after that one's own close stopped waiting for it.
   */
  @Test
  void theLastKmsToCloseWaitsForTheRenewalsOfAll(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Late events = new Late();
    CountDownLatch reached = new CountDownLatch(1), release = new CountDownLatch(1);
    AtomicInteger sent = new AtomicInteger();
    holdAt(Stage.PENDING_RECORD, server, reached, release, sent);
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig config =
          pki.renewing(tls, CertificateRenewal.onDemand())
              .callTimeout(Duration.ofSeconds(1))
              .addListener(events)
              .build();
      Kms first = Kms.connect(config), last = Kms.connect(config);
      Thread renew =
          new Thread(
              () -> {
                try {
                  first.renewClientCertificate();
                } catch (Exception e) {
                  // reported below through the files
                }
              });
      renew.start();
      assertTrue(reached.await(30, TimeUnit.SECONDS));
      // The first's close waits for its renewal until its wait runs out.
      first.close();
      assertTrue(renew.isAlive());
      // The last one's close waits for it too, until it ends.
      Thread close = closing(last, events);
      close.join(500);
      assertTrue(close.isAlive(), "the last close returned while a renewal of the files ran");
      release.countDown();
      close.join(30_000);
      assertFalse(close.isAlive());
      assertFalse(Files.exists(dir.resolve("client.key.renewal")));
      assertNotEquals(pki.client.certificate(), leaf(pki.chain));
      renew.join(30_000);
      assertEquals(List.of(), events.late);
    }
  }

  /**
   * A close from a listener on the renewal's own thread, or from inside the renewal, does not
   * wait for it, and does not deadlock.
   */
  @ParameterizedTest
  @CsvSource({"false, false", "false, true", "true, false", "true, true"})
  void aCloseOnTheRenewalsOwnThreadDoesNotWaitForIt(
      boolean automatic, boolean fromListener, @TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicReference<Kms> kms = new AtomicReference<>();
    CountDownLatch closed = new CountDownLatch(1);
    AtomicReference<Thread> closer = new AtomicReference<>();
    Runnable close =
        () -> {
          closer.set(Thread.currentThread());
          kms.get().close();
          closed.countDown();
        };
    Late events =
        new Late() {
          @Override
          public void clientCertificateRenewed(
              String previous, String fingerprint, Instant notAfter) {
            super.clientCertificateRenewed(previous, fingerprint, notAfter);
            if (fromListener) close.run();
          }
        };
    CountDownLatch go = new CountDownLatch(1);
    if (!fromListener)
      ClientRenewal.beforeReProvision =
          () -> {
            awaitQuietly(go);
            close.run();
          };
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig config =
          pki.renewing(
                  tls,
                  automatic
                      ? CertificateRenewal.automatic(RENEW_WITHIN)
                      : CertificateRenewal.onDemand())
              .addListener(events)
              .build();
      kms.set(Kms.connect(config));
      go.countDown();
      Object outcome = null;
      if (!automatic) {
        try {
          outcome = kms.get().renewClientCertificate();
        } catch (IllegalStateException e) {
          outcome = e;
        }
        assertSame(Thread.currentThread(), closer.get());
      }
      assertTrue(closed.await(30, TimeUnit.SECONDS), "close did not return");
      await("the renewal ends").until(() -> config.renewal.runningWorkers() == 0);
      assertThrows(IllegalStateException.class, () -> kms.get().ping());
      if (fromListener) {
        // Closed after the renewal was written.
        assertNotEquals(pki.client.certificate(), leaf(pki.chain));
        if (!automatic) assertInstanceOf(RenewedCertificate.class, outcome);
      } else {
        // Closed just before the send: nothing was sent.
        assertEquals(pki.client.certificate(), leaf(pki.chain));
        assertEquals(List.of(), tls.retiredCertificates());
        assertFalse(Files.exists(dir.resolve("client.key.renewal")));
        if (!automatic) assertInstanceOf(IllegalStateException.class, outcome);
      }
    }
  }

  /**
   * A renewal through a {@link Kms#withTimeout} view waits for its reply as long as the view
   * says, and the close waits three times that: the server commits and holds its reply longer
   * than three times the configured call timeout, and the close still returns only once the files
   * hold the new certificate.
   */
  @Test
  void theCloseWaitsByTheCallTimeoutOfTheViewTheRenewalRunsThrough(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Late events = new Late();
    CountDownLatch committed = new CountDownLatch(1);
    server.injectAfterProcessing(
        request -> {
          if (reProvision(request)) committed.countDown();
          return null;
        });
    server.slowReplyDelay(Duration.ofSeconds(5));
    server.failNext(ServerOperation.RE_PROVISION, Fault.SLOW);
    AtomicReference<Object> outcome = new AtomicReference<>();
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig config =
          pki.renewing(tls, CertificateRenewal.onDemand())
              .callTimeout(Duration.ofSeconds(1))
              .addListener(events)
              .build();
      Kms kms = Kms.connect(config);
      Kms view = kms.withTimeout(Duration.ofSeconds(10));
      Thread renew =
          new Thread(
              () -> {
                try {
                  outcome.set(view.renewClientCertificate());
                } catch (Exception e) {
                  outcome.set(e);
                }
              });
      renew.start();
      assertTrue(committed.await(30, TimeUnit.SECONDS));
      long start = System.nanoTime();
      kms.close();
      events.closed.set(true);
      Duration waited = Duration.ofNanos(System.nanoTime() - start);
      // Past three times the configured timeout: the renewal ended first, written.
      assertTrue(waited.compareTo(Duration.ofSeconds(3)) > 0, waited.toString());
      assertTrue(waited.compareTo(Duration.ofSeconds(30)) < 0, waited.toString());
      assertEquals(List.of(), events.warned, "the wait ran out");
      assertFalse(Files.exists(dir.resolve("client.key.renewal")));
      assertNotEquals(pki.client.certificate(), leaf(pki.chain));
      assertEquals(List.of(pki.client.certificate()), tls.retiredCertificates());
      assertEquals(1, events.renewed.size());
      renew.join(30_000);
      assertInstanceOf(RenewedCertificate.class, outcome.get());
      assertEquals(List.of(), events.late);
    }
  }

  /**
   * The search after a lost reply, through a {@link Kms#withTimeout} view, is waited for by the
   * view's call timeout too: the server issues the certificate and loses the reply, holds the
   * search's Locate longer than three times the configured call timeout, and the close, called
   * during the search, returns once the files hold the certificate the search found.
   */
  @Test
  void theCloseWaitsForTheSearchAfterALostReplyByTheViewsCallTimeout(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Late events = new Late();
    CountDownLatch searching = new CountDownLatch(1);
    AtomicInteger sent = new AtomicInteger();
    // Seen before processing: the lost reply skips the hook after it.
    server.injectBeforeProcessing(
        request -> {
          if (reProvision(request)) sent.incrementAndGet();
          for (Ttlv item : request.children(Tag.BATCH_ITEM))
            if (item.child(Tag.OPERATION).map(Ttlv::intValue).orElse(0) == Operation.LOCATE.code()
                && sent.get() > 0) searching.countDown();
          return null;
        });
    server.failNext(ServerOperation.RE_PROVISION, Fault.REPLY_LOST);
    server.slowReplyDelay(Duration.ofSeconds(5));
    server.failNext(ServerOperation.LOCATE, Fault.SLOW);
    AtomicReference<Object> outcome = new AtomicReference<>();
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig config =
          pki.renewing(tls, CertificateRenewal.onDemand())
              .callTimeout(Duration.ofSeconds(1))
              .addListener(events)
              .build();
      Kms kms = Kms.connect(config);
      Kms view = kms.withTimeout(Duration.ofSeconds(10));
      Thread renew =
          new Thread(
              () -> {
                try {
                  outcome.set(view.renewClientCertificate());
                } catch (Exception e) {
                  outcome.set(e);
                }
              });
      renew.start();
      assertTrue(searching.await(30, TimeUnit.SECONDS), "the search after the lost reply");
      long start = System.nanoTime();
      kms.close();
      events.closed.set(true);
      Duration waited = Duration.ofNanos(System.nanoTime() - start);
      // Past three times the configured timeout: the search ended first, and its find is written.
      assertTrue(waited.compareTo(Duration.ofSeconds(3)) > 0, waited.toString());
      assertTrue(waited.compareTo(Duration.ofSeconds(30)) < 0, waited.toString());
      assertEquals(List.of(), events.warned, "the wait ran out");
      assertEquals(1, sent.get());
      assertFalse(Files.exists(dir.resolve("client.key.renewal")));
      assertNotEquals(pki.client.certificate(), leaf(pki.chain));
      assertEquals(List.of(pki.client.certificate()), tls.retiredCertificates());
      assertEquals(1, events.renewed.size());
      renew.join(30_000);
      assertInstanceOf(RenewedCertificate.class, outcome.get());
      assertEquals(List.of(), events.late);
    }
  }

  /**
   * An event that the close silences while it is being delivered reaches no listener after that:
   * the first listener closes the Kms from its callback, on the renewal's thread, and the second
   * never hears the event.
   */
  @Test
  void aListenerThatClosesTheKmsKeepsTheEventFromTheListenersAfterIt(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicReference<Kms> kms = new AtomicReference<>();
    Late closer =
        new Late() {
          @Override
          public void clientCertificateRenewed(
              String previous, String fingerprint, Instant notAfter) {
            super.clientCertificateRenewed(previous, fingerprint, notAfter);
            kms.get().close();
            closed.set(true);
          }
        };
    Late after = new Late();
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig config =
          pki.renewing(tls, CertificateRenewal.onDemand())
              .addListener(closer)
              .addListener(after)
              .build();
      kms.set(Kms.connect(config));
      RenewedCertificate renewed = kms.get().renewClientCertificate();
      assertNotNull(renewed);
      assertEquals(1, closer.renewed.size());
      assertEquals(List.of(), after.renewed, "the listener after the close heard the event");
      assertNotEquals(pki.client.certificate(), leaf(pki.chain));
    }
  }

  /**
   * A listener that is still running its callback when the close's wait runs out finishes it, and
   * the listeners after it never hear that event.
   */
  @Test
  void aListenerThatOutlastsTheCloseKeepsTheEventFromTheListenersAfterIt(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    CountDownLatch reached = new CountDownLatch(1), release = new CountDownLatch(1);
    Late blocking =
        new Late() {
          @Override
          public void clientCertificateRenewed(
              String previous, String fingerprint, Instant notAfter) {
            super.clientCertificateRenewed(previous, fingerprint, notAfter);
            reached.countDown();
            awaitQuietly(release);
          }
        };
    Late after = new Late();
    AtomicReference<Object> outcome = new AtomicReference<>();
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig config =
          pki.renewing(tls, CertificateRenewal.onDemand())
              .callTimeout(Duration.ofSeconds(1))
              .addListener(blocking)
              .addListener(after)
              .build();
      Kms kms = Kms.connect(config);
      Thread renew =
          new Thread(
              () -> {
                try {
                  outcome.set(kms.renewClientCertificate());
                } catch (Exception e) {
                  outcome.set(e);
                }
              });
      renew.start();
      assertTrue(reached.await(30, TimeUnit.SECONDS));
      long start = System.nanoTime();
      kms.close();
      after.closed.set(true);
      Duration waited = Duration.ofNanos(System.nanoTime() - start);
      assertTrue(waited.compareTo(Duration.ofMillis(2_900)) >= 0, waited.toString());
      // The close's report reached both listeners before it returned.
      assertEquals(1, after.warned.size(), after.warned.toString());
      release.countDown();
      renew.join(30_000);
      assertInstanceOf(RenewedCertificate.class, outcome.get());
      assertEquals(1, blocking.renewed.size());
      assertEquals(List.of(), after.renewed, "the listener after the close heard the event");
      assertEquals(List.of(), after.late);
    }
  }

  /**
   * A closed {@code Kms} keeps no reference to the thread that closed it, so a container's request
   * thread and its context class loader can go once the thread ends. A later {@code close()} then
   * returns at once.
   */
  @Test
  void aClosedKmsDoesNotKeepTheThreadThatClosedIt(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start()) {
      Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build());
      Thread t = new Thread(kms::close, "closes the Kms");
      t.setContextClassLoader(new java.net.URLClassLoader(new java.net.URL[0], null));
      java.lang.ref.WeakReference<Thread> thread = new java.lang.ref.WeakReference<>(t);
      java.lang.ref.WeakReference<ClassLoader> loader =
          new java.lang.ref.WeakReference<>(t.getContextClassLoader());
      t.start();
      t.join(30_000);
      assertFalse(t.isAlive(), "close did not return");
      t = null;
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20);
      while ((thread.get() != null || loader.get() != null) && System.nanoTime() < deadline) {
        System.gc();
        Thread.sleep(50);
      }
      assertNull(thread.get(), "the closed Kms keeps the thread that closed it");
      assertNull(loader.get(), "the closed Kms keeps that thread's context class loader");
      long start = System.nanoTime();
      kms.close();
      assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(1), "a later close waited");
      assertThrows(IllegalStateException.class, kms::ping);
    }
  }
}
