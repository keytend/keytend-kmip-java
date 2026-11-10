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
import static dev.keytend.kmip.kms.TlsUnknownPeerTest.SECOND;
import static dev.keytend.kmip.kms.TlsUnknownPeerTest.TAG;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.kms.TlsBackgroundPeerCheckTest.Held;
import dev.keytend.kmip.kms.TlsIdentityTest.Pki;
import dev.keytend.kmip.kms.TlsUnknownPeerTest.Fixture;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The configurable rate limits of the trust follower's check of an unknown peer: the
 * per-certificate interval, the gap between checks and the queue, each at its boundaries, lifted
 * with zero, changed while the follower runs, and under concurrent handshakes. Counted in exchanges
 * with a clock the test moves ({@link TlsUnknownPeerTest.Fixture}).
 */
class TlsUnknownPeerLimitsTest {
  static final long MILLI = 1_000_000L;

  @Test
  void theSettersValidateAndSaturate() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      TlsTrustFollower t = f.trust;
      assertSame(t, t.unknownPeerCheckPerCertificate(Duration.ZERO));
      assertSame(t, t.unknownPeerCheckGap(Duration.ZERO));
      assertSame(t, t.unknownPeerCheckQueue(1));
      assertSame(t, t.unknownPeerCheckQueue(Integer.MAX_VALUE));
      Duration negative = Duration.ofNanos(-1);
      IllegalArgumentException e =
          assertThrows(
              IllegalArgumentException.class, () -> t.unknownPeerCheckPerCertificate(negative));
      assertTrue(e.getMessage().contains("interval must not be negative"), e.getMessage());
      e = assertThrows(IllegalArgumentException.class, () -> t.unknownPeerCheckGap(negative));
      assertTrue(e.getMessage().contains("gap must not be negative"), e.getMessage());
      for (int bad : new int[] {0, -1, Integer.MIN_VALUE}) {
        e = assertThrows(IllegalArgumentException.class, () -> t.unknownPeerCheckQueue(bad));
        assertTrue(e.getMessage().contains("limit must be positive"), e.getMessage());
      }
      assertThrows(NullPointerException.class, () -> t.unknownPeerCheckPerCertificate(null));
      assertThrows(NullPointerException.class, () -> t.unknownPeerCheckGap(null));

      // Longer than nanoseconds can count: never again, without an overflow that would check at
      // once.
      Duration forever = Duration.ofSeconds(Long.MAX_VALUE);
      t.unknownPeerCheckPerCertificate(forever).unknownPeerCheckGap(Duration.ZERO);
      Issued u1 = f.issue("u1");
      f.assertRefused(u1, 2);
      f.ticker.advance(Long.MAX_VALUE / 4);
      f.assertRefused(u1, 0);
      t.unknownPeerCheckPerCertificate(Duration.ZERO).unknownPeerCheckGap(forever);
      f.assertRefused(f.issue("u2"), 0);
      assertEquals(List.of(), f.server.violations());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theIntervalPerCertificateHoldsToTheNanosecond(KmipVersion version) throws Exception {
    try (Fixture f = new Fixture(version)) {
      f.trust
          .unknownPeerCheckPerCertificate(Duration.ofSeconds(10))
          .unknownPeerCheckGap(Duration.ZERO);
      Issued u1 = f.issue("u1");
      f.assertRefused(u1, 2); // checked: Locate, batched Get Attributes
      f.ticker.advance(10 * SECOND - 1);
      CertificateException refused =
          assertThrows(
              CertificateException.class,
              () -> f.trust.trustManager().checkClientTrusted(f.pki.chain(u1), "EC"));
      assertTrue(refused.getMessage().contains("checked less than 10 s ago"), refused.getMessage());
      f.assertRefused(u1, 0);
      f.ticker.advance(1);
      f.assertRefused(u1, 2); // exactly the interval later: checked again

      // Registered meanwhile: the next check, an interval on, admits it and reads its certificate.
      f.register(u1);
      f.ticker.advance(10 * SECOND - 1);
      f.assertRefused(u1, 0);
      f.ticker.advance(1);
      f.assertAccepted(u1, 3);

      // Zero lifts the limit: each handshake checks again.
      f.trust.unknownPeerCheckPerCertificate(Duration.ZERO);
      Issued u2 = f.issue("u2");
      for (int i = 0; i < 3; i++) f.assertRefused(u2, 2);
      assertTrue(f.trust.failure().isEmpty(), "a check is not a failure");
      assertEquals(List.of(), f.server.violations());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theGapBetweenChecksHoldsToTheNanosecond(KmipVersion version) throws Exception {
    try (Fixture f = new Fixture(version)) {
      f.trust
          .unknownPeerCheckGap(Duration.ofMillis(250))
          .unknownPeerCheckPerCertificate(Duration.ZERO);
      Issued u1 = f.issue("u1"), u2 = f.issue("u2"), n1 = f.issue("n1");
      f.assertRefused(u1, 2);
      f.ticker.advance(250 * MILLI - 1);
      CertificateException refused =
          assertThrows(
              CertificateException.class,
              () -> f.trust.trustManager().checkClientTrusted(f.pki.chain(u2), "EC"));
      assertTrue(
          refused.getMessage().contains("checked less than 250 ms ago"), refused.getMessage());
      f.ticker.advance(1);
      f.assertRefused(u2, 2);
      // A peer renewed meanwhile is admitted by the first check after the gap.
      f.register(n1);
      f.assertRefused(n1, 0);
      f.ticker.advance(250 * MILLI);
      f.assertAccepted(n1, 3);

      // Zero lifts the gap: checks one after another, each reading the KMS.
      f.trust.unknownPeerCheckGap(Duration.ZERO);
      for (int i = 0; i < 3; i++) f.assertRefused(f.issue("x" + i), 2);
      // A gap that is not whole milliseconds is said as a duration.
      f.trust.unknownPeerCheckGap(Duration.ofNanos(1500));
      refused =
          assertThrows(
              CertificateException.class,
              () -> f.trust.trustManager().checkClientTrusted(f.pki.chain(u1), "EC"));
      assertTrue(refused.getMessage().contains("less than PT0.0000015S ago"), refused.getMessage());
      assertEquals(List.of(), f.server.violations());
    }
  }

  @Test
  void refusalsSayTheLimitInItsUnit() {
    assertEquals("30 s", TlsTrustFollower.human(30 * SECOND));
    assertEquals("0 s", TlsTrustFollower.human(0));
    assertEquals("1500 ms", TlsTrustFollower.human(1500 * MILLI));
    assertEquals("PT0.000001S", TlsTrustFollower.human(1000));
  }

  /**
   * Handshakes that wait for the check, at once from many threads: the follower's lock puts their
   * checks one after another, so the limits decide exactly how many read the KMS, whatever the
   * interleaving.
   */
  @RepeatedTest(10)
  void concurrentHandshakesAreLimitedExactly() throws Exception {
    int threads = 8;
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      Issued u1 = f.issue("u1");
      // The default interval per certificate: one check of u1 among all of them.
      f.trust.unknownPeerCheckGap(Duration.ZERO);
      assertEquals(2, concurrently(f, threads, i -> u1));
      // No limit: every handshake checks.
      f.trust.unknownPeerCheckPerCertificate(Duration.ZERO);
      assertEquals(2 * threads, concurrently(f, threads, i -> u1));
      // A gap: one check among different certificates.
      f.trust.unknownPeerCheckGap(Duration.ofSeconds(1));
      f.ticker.advance(SECOND);
      List<Issued> distinct = new ArrayList<>();
      for (int i = 0; i < threads; i++) distinct.add(f.issue("d" + i));
      assertEquals(2, concurrently(f, threads, distinct::get));
      assertEquals(List.of(), f.server.violations());
    }
  }

  interface Leaf {
    Issued of(int thread);
  }

  /** The exchanges {@code threads} handshakes made at once, all refused. */
  static int concurrently(Fixture f, int threads, Leaf leaf) throws Exception {
    int before = f.server.exchanges();
    CyclicBarrier go = new CyclicBarrier(threads);
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    try {
      List<Future<int[]>> all = new ArrayList<>();
      for (int i = 0; i < threads; i++) {
        Issued l = leaf.of(i);
        all.add(
            pool.submit(
                () -> {
                  go.await(30, TimeUnit.SECONDS);
                  return f.present(l);
                }));
      }
      for (Future<int[]> r : all) assertEquals(0, r.get(30, TimeUnit.SECONDS)[0], "refused");
    } finally {
      pool.shutdownNow();
    }
    return f.server.exchanges() - before;
  }

  /**
   * The queue of checks waiting for the executor holds exactly its limit, however many handshakes
   * ask at once; a raised limit queues more at once, and a lowered one refuses until the queue
   * drains below it.
   */
  @RepeatedTest(10)
  void theQueueHoldsItsLimitUnderConcurrentHandshakes() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Pki pki = new Pki();
    Held executor = new Held();
    try (Kms kms = TlsIdentityTest.connect(server)) {
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
                  executor)
              .unknownPeerCheckQueue(3);
      int threads = 12;
      List<Issued> strangers = new ArrayList<>();
      for (int i = 0; i < threads + 4; i++) strangers.add(pki.leaf("s" + i, TestPki.ec()));
      List<String> refusals = new CopyOnWriteArrayList<>();
      CyclicBarrier go = new CyclicBarrier(threads);
      ExecutorService pool = Executors.newFixedThreadPool(threads);
      try {
        List<Future<?>> all = new ArrayList<>();
        for (int i = 0; i < threads; i++) {
          Issued s = strangers.get(i);
          all.add(
              pool.submit(
                  () -> {
                    go.await(30, TimeUnit.SECONDS);
                    CertificateException e =
                        assertThrows(
                            CertificateException.class,
                            () -> trust.trustManager().checkClientTrusted(pki.chain(s), "EC"));
                    refusals.add(e.getMessage());
                    return null;
                  }));
        }
        for (Future<?> x : all) x.get(30, TimeUnit.SECONDS);
      } finally {
        pool.shutdownNow();
      }
      assertEquals(3, executor.held.size(), "exactly the limit queued");
      assertEquals(
          threads - 3, refusals.stream().filter(m -> m.contains("too many checks")).count());
      assertEquals(3, refusals.stream().filter(m -> m.contains("was queued")).count());

      // Raised: one more fits at once.
      trust.unknownPeerCheckQueue(4);
      assertTrue(refusal(trust, pki, strangers.get(threads)).contains("was queued"));
      assertTrue(refusal(trust, pki, strangers.get(threads + 1)).contains("too many checks"));
      // Lowered below what waits: refused until the queue drains below it.
      trust.unknownPeerCheckQueue(1);
      assertTrue(refusal(trust, pki, strangers.get(threads + 2)).contains("too many checks"));
      assertEquals(4, executor.held.size());
      executor.runAll();
      assertTrue(refusal(trust, pki, strangers.get(threads + 3)).contains("was queued"));
      assertEquals(1, executor.held.size());
      trust.close();
    } finally {
      executor.shutdownNow();
    }
  }

  static String refusal(TlsTrustFollower trust, Pki pki, Issued leaf) {
    return assertThrows(
            CertificateException.class,
            () -> trust.trustManager().checkClientTrusted(pki.chain(leaf), "EC"))
        .getMessage();
  }
}
