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
import static dev.keytend.kmip.kms.TlsIdentityTest.connect;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.TestAwait;
import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.kms.TlsIdentityTest.Pki;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The trust follower's check of the KMS for a peer whose certificate chains to the anchors but is
 * not an allowed peer yet: what it reads, and its bounds (the per-certificate and global rate
 * limits, one check shared by concurrent handshakes, the timeout), counted in exchanges with a
 * clock the test moves.
 */
class TlsUnknownPeerTest {
  static final CustomAttribute TAG = CustomAttribute.client("tls");
  static final long SECOND = 1_000_000_000L;

  /** A clock the test moves. */
  static final class Ticker {
    final AtomicLong now = new AtomicLong(System.nanoTime());

    void advance(long nanos) {
      now.addAndGet(nanos);
    }
  }

  /** A server, a CA, a trust follower with an allowlist of {@code peer}-tagged certificates. */
  static final class Fixture implements AutoCloseable {
    final InMemoryKmipServer server;
    final Kms kms;
    final Pki pki = new Pki();
    final TlsTrustFollower trust;
    final Ticker ticker = new Ticker();
    final List<String> told = new ArrayList<>();

    Fixture(InMemoryKmipServer server, Kms kms) throws Exception {
      this.server = server;
      this.kms = kms;
      kms.keys()
          .register(pki.root.certificate())
          .usages(KeyUsage.VERIFY)
          .custom(TAG, "ca")
          .register();
      register(issue("peer0"));
      trust =
          kms.tls()
              .trustAnchors(
                  KeyQuery.all().custom(TAG, "ca"),
                  KeyQuery.all().custom(TAG, "peer"),
                  HOURLY,
                  SCHEDULER)
              .unknownPeerCheckInHandshake(
                  true); // these tests count what the check sends, in the handshake
      // Ahead of the first read, which used the real clock.
      ticker.now.set(System.nanoTime() + SECOND);
      trust.ticker = ticker.now::get;
      trust.onChange(
          () -> {
            synchronized (told) {
              told.add(Thread.currentThread().getName());
            }
          });
    }

    Fixture(KmipVersion version) throws Exception {
      this(InMemoryKmipServer.of(version));
    }

    private Fixture(InMemoryKmipServer server) throws Exception {
      this(server, connect(server));
    }

    Issued issue(String name) throws Exception {
      return pki.leaf(name, TestPki.ec());
    }

    KeyHandle register(Issued leaf) {
      return kms.keys()
          .register(leaf.certificate())
          .usages(KeyUsage.VERIFY)
          .custom(TAG, "peer")
          .register();
    }

    /** Whether the trust manager accepts {@code leaf} as a client; the exchanges it cost. */
    int[] present(Issued leaf) {
      int before = server.exchanges();
      boolean accepted;
      try {
        trust.trustManager().checkClientTrusted(pki.chain(leaf), "EC");
        accepted = true;
      } catch (CertificateException e) {
        accepted = false;
      }
      return new int[] {accepted ? 1 : 0, server.exchanges() - before};
    }

    void assertAccepted(Issued leaf, int exchanges) {
      int[] r = present(leaf);
      assertEquals(1, r[0], "accepted");
      assertEquals(exchanges, r[1], "exchanges");
    }

    void assertRefused(Issued leaf, int exchanges) {
      int[] r = present(leaf);
      assertEquals(0, r[0], "refused");
      assertEquals(exchanges, r[1], "exchanges");
    }

    @Override
    public void close() {
      trust.close();
      kms.close();
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anAllowedPeerNotReadYetIsCheckedOnceAndTheRateLimitsHold(KmipVersion version)
      throws Exception {
    try (Fixture f = new Fixture(version)) {
      Issued u1 = f.issue("u1"), u2 = f.issue("u2"), n1 = f.issue("n1");
      // An unknown certificate: one check (Locate, batched Get Attributes; nothing new to Get),
      // refused.
      f.assertRefused(u1, 2);
      assertTrue(f.trust.failure().isEmpty());
      // The same certificate again: not checked for 30 s.
      f.ticker.advance(2 * SECOND);
      f.assertRefused(u1, 0);
      // Another one within the global gap: not checked.
      f.ticker.advance(-SECOND - SECOND / 2);
      f.assertRefused(u2, 0);
      // After the gap: checked, refused.
      f.ticker.advance(2 * SECOND);
      f.assertRefused(u2, 2);
      // u1 again after 30 s: checked again.
      f.ticker.advance(31 * SECOND);
      f.assertRefused(u1, 2);

      // A new allowed peer: within the gap refused without a check; after it, accepted with one
      // check that reads only the new certificate (Locate, batched Get Attributes, one Get).
      f.register(n1);
      f.ticker.advance(SECOND / 2);
      f.assertRefused(n1, 0);
      f.ticker.advance(SECOND);
      f.assertAccepted(n1, 3);
      assertEquals(2, f.trust.allowedPeers().orElseThrow().size());
      // Now an allowed peer: no check, and no rate limit applies.
      f.assertAccepted(n1, 0);
      // Listeners were told of the change on the executor, not the handshake's thread.
      TestAwait.await("the listeners are told")
          .until(
              () -> {
                synchronized (f.told) {
                  return !f.told.isEmpty();
                }
              });
      synchronized (f.told) {
        assertEquals(List.of("tls-follower-test"), f.told);
      }

      // A chain that does not validate against the anchors is never checked.
      Issued foreign = TestPki.leaf("foreign", TestPki.ec(), TestPki.ca("Foreign CA"));
      f.ticker.advance(60 * SECOND);
      int before = f.server.exchanges();
      assertThrows(
          CertificateException.class,
          () -> f.trust.trustManager().checkClientTrusted(foreign.chain(), "EC"));
      assertEquals(before, f.server.exchanges());

      // The check turned off: refused, not checked.
      f.trust.unknownPeerCheck(Duration.ZERO);
      Issued n2 = f.issue("n2");
      f.register(n2);
      f.ticker.advance(60 * SECOND);
      f.assertRefused(n2, 0);
      f.trust.unknownPeerCheck(Duration.ofSeconds(2));
      f.assertAccepted(n2, 3);
      assertEquals(List.of(), f.server.violations());
    }
  }

  @ParameterizedTest
  @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
  void aCheckSharesOneDeadlineEvenInsideAnEnclosingCall(boolean enclosingCall) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    java.util.concurrent.atomic.AtomicBoolean slow =
        new java.util.concurrent.atomic.AtomicBoolean();
    List<Long> deadlines = new ArrayList<>();
    KmipTransport transport =
        new KmipTransport() {
          @Override
          public Ttlv exchange(Ttlv request) throws IOException {
            return exchange(request, CallContext.NONE);
          }

          @Override
          public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
            if (slow.get()) {
              deadlines.add(context.deadlineBefore(Long.MAX_VALUE));
              try {
                TimeUnit.NANOSECONDS.sleep(
                    Math.min(
                        TimeUnit.MILLISECONDS.toNanos(80), Math.max(0, context.remainingNanos())));
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new java.io.InterruptedIOException();
              }
              context.check();
            }
            return server.exchange(request, context);
          }
        };
    try (Fixture f =
        new Fixture(
            server,
            Kms.connect(
                server
                    .configure()
                    .transport(e -> transport)
                    .callTimeout(Duration.ofSeconds(5))
                    .retryPolicy(RetryPolicy.none())
                    .build()))) {
      f.trust.ticker = System::nanoTime;
      f.trust.unknownPeerCheck(Duration.ofMillis(200));
      Issued peer = f.issue("new peer");
      f.register(peer);
      KeyHandle key =
          f.kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
      Runnable handshake =
          () ->
              assertThrows(
                  CertificateException.class,
                  () -> f.trust.trustManager().checkClientTrusted(f.pki.chain(peer), "EC"));
      if (enclosingCall) {
        // A call of the SDK's that runs the handshake (a listener, a callback), with its own
        // deadline.
        f.kms.run(
            "test",
            () -> {
              slow.set(true);
              handshake.run();
              // The shorter check scope must restore its caller's longer deadline.
              slow.set(false);
              assertEquals(KeyState.ACTIVE, key.attributes().state());
            });
      } else {
        slow.set(true);
        handshake.run();
      }
      assertTrue(deadlines.size() >= 2, "the check sent multiple requests");
      long spread =
          deadlines.stream().mapToLong(Long::longValue).max().orElseThrow()
              - deadlines.stream().mapToLong(Long::longValue).min().orElseThrow();
      assertTrue(
          spread < TimeUnit.MILLISECONDS.toNanos(40),
          "all requests share the check deadline: " + Duration.ofNanos(spread));
      assertTrue(
          f.trust.failure().isEmpty(),
          "a failed peer check does not replace periodic-refresh failure");
    }
  }

  @Test
  void aCheckCannotLengthenItsEnclosingCallDeadline() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      f.trust.ticker = System::nanoTime;
      f.trust.unknownPeerCheck(Duration.ofSeconds(2));
      Issued peer = f.issue("new peer");
      f.register(peer);
      var shortKms = f.kms.withTimeout(Duration.ofMillis(150));
      f.server.slowReplyDelay(Duration.ofMillis(300));
      f.server.failNext(ServerOperation.LOCATE, Fault.SLOW);
      long start = System.nanoTime();
      shortKms.run(
          "test",
          () -> {
            assertThrows(
                CertificateException.class,
                () -> f.trust.trustManager().checkClientTrusted(f.pki.chain(peer), "EC"));
          });
      assertTrue(
          System.nanoTime() - start < TimeUnit.SECONDS.toNanos(1),
          "the outer 150 ms budget was preserved");
    }
  }

  @Test
  void aCheckThatTimesOutOrFailsRefusesWithinItsTimeoutAndIsNotAFailure() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      Issued n1 = f.issue("n1");
      f.register(n1);
      f.trust.unknownPeerCheck(Duration.ofMillis(300));
      f.server.failNext(ServerOperation.LOCATE, Fault.HANG);
      long start = System.nanoTime();
      assertEquals(0, f.present(n1)[0]);
      long took = System.nanoTime() - start;
      assertTrue(took < 3 * SECOND, "bounded by the check's timeout: " + took / 1_000_000 + " ms");
      assertTrue(f.trust.failure().isEmpty(), "a failed check is not a failure of the follower");
      // The KMS down: refused, at once.
      f.ticker.advance(60 * SECOND);
      f.server.unreachable(true);
      assertEquals(0, f.present(n1)[0]);
      f.server.unreachable(false);
      f.ticker.advance(60 * SECOND);
      f.assertAccepted(n1, 3);
    }
  }

  @Test
  void aCheckWaitsForARunningRefreshAtMostItsTimeout() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Fixture f =
        new Fixture(
            server, Kms.connect(server.configure().callTimeout(Duration.ofSeconds(2)).build()))) {
      Issued n1 = f.issue("n1");
      f.register(n1);
      f.trust.unknownPeerCheck(Duration.ofMillis(200));
      // A refresh that hangs (its Locate) holds the follower: the handshake does not wait for it.
      f.server.failNext(ServerOperation.LOCATE, Fault.HANG);
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        CountDownLatch started = new CountDownLatch(1);
        Future<Boolean> refresh =
            pool.submit(
                () -> {
                  started.countDown();
                  return f.trust.refresh();
                });
        started.await();
        Thread.sleep(100);
        long start = System.nanoTime();
        int[] r = f.present(n1);
        long took = System.nanoTime() - start;
        assertEquals(0, r[0]);
        assertTrue(took < SECOND, "waited " + took / 1_000_000 + " ms");
        refresh.get(30, TimeUnit.SECONDS);
      } finally {
        pool.shutdownNow();
      }
    }
  }

  @Test
  void concurrentHandshakesShareOneCheck() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      f.trust.ticker = System::nanoTime;
      f.trust.unknownPeerCheck(Duration.ofSeconds(10));
      Issued n1 = f.issue("n1"), u1 = f.issue("u1");
      f.register(n1);
      for (Issued leaf : List.of(n1, u1)) {
        // Hold the check's Locate a while, so the other handshakes wait for it.
        f.server.slowReplyDelay(Duration.ofMillis(300));
        f.server.failNext(ServerOperation.LOCATE, Fault.SLOW);
        int before = f.server.exchanges();
        ExecutorService pool = Executors.newFixedThreadPool(8);
        AtomicInteger accepted = new AtomicInteger();
        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> all = new ArrayList<>();
        try {
          for (int i = 0; i < 8; i++)
            all.add(
                pool.submit(
                    () -> {
                      go.await();
                      if (f.present(leaf)[0] == 1) accepted.incrementAndGet();
                      return null;
                    }));
          go.countDown();
          for (Future<?> x : all) x.get(30, TimeUnit.SECONDS);
        } finally {
          pool.shutdownNow();
        }
        assertEquals(leaf == n1 ? 8 : 0, accepted.get());
        assertEquals(leaf == n1 ? 3 : 2, f.server.exchanges() - before, "one check for all eight");
        Thread.sleep(1100); // past the gap
      }
    }
  }

  /** {@code t} without the custom attributes of its Locate requests, as a server that ignores them sees it. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void theCheckDoesNotTrustAServerThatIgnoresCustomFilters(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    KmipTransport ignoring =
        new KmipTransport() {
          @Override
          public Ttlv exchange(Ttlv request) throws IOException {
            return exchange(request, CallContext.NONE);
          }

          @Override
          public Ttlv exchange(Ttlv request, CallContext c) throws IOException {
            boolean locate =
                request.require(Tag.BATCH_ITEM).require(Tag.OPERATION).intValue()
                    == Operation.LOCATE.code();
            return server.exchange(
                locate ? TlsTrustTest.withoutCustomFilters(request) : request, c);
          }
        };
    Kms kms =
        Kms.connect(
            server
                .configure()
                .transport(e -> ignoring)
                .callTimeout(Duration.ofSeconds(10))
                .build());
    try (Fixture f = new Fixture(server, kms)) {
      // Chains to the anchors and is Active, but tagged otherwise: the server's Locate returns it.
      Issued other = f.issue("other");
      kms.keys()
          .register(other.certificate())
          .usages(KeyUsage.VERIFY)
          .custom(TAG, "other")
          .register();
      assertEquals(0, f.present(other)[0]);
      assertEquals(1, f.trust.allowedPeers().orElseThrow().size());
      Issued n1 = f.issue("n1");
      f.register(n1);
      f.ticker.advance(60 * SECOND);
      f.assertAccepted(n1, 3);
    }
  }

  @Test
  void aCheckDuringAnotherChecksKmsCallIsRefused() throws Exception {
    // The KMS connection's own handshake using this trust manager would nest a check in a check.
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      Issued n1 = f.issue("n1"), n2 = f.issue("n2");
      f.register(n1);
      f.register(n2);
      AtomicInteger nested = new AtomicInteger(-1);
      java.util.concurrent.atomic.AtomicBoolean entered =
          new java.util.concurrent.atomic.AtomicBoolean();
      f.server.injectBeforeProcessing(
          request -> {
            if (entered.compareAndSet(false, true)) {
              f.ticker.advance(60 * SECOND); // past every rate limit
              nested.set(f.present(n2)[0]);
            }
            return null;
          });
      f.assertAccepted(n1, 3);
      assertEquals(0, nested.get(), "the nested check refused n2");
    }
  }
}
