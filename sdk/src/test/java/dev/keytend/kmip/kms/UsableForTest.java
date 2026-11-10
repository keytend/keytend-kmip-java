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

import static dev.keytend.kmip.kms.TlsIdentityTest.SCHEDULER;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TestPki.Issued;
import java.time.Duration;
import java.util.Optional;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@code usableFor()} on {@link LocalKeys}, {@link TlsIdentityFollower} and {@link TlsTrustFollower}:
 * how long what is presented now stays usable without the KMS (the earliest of its leases, TTL and
 * protection deadline), from memory, for metrics and alerts.
 */
class UsableForTest {
  private static void near(Duration expected, Duration actual) {
    long ms = expected.minus(actual).abs().toMillis();
    assertTrue(ms <= 1000, "expected about " + expected + ", was " + actual);
  }

  private static void near(Duration expected, Optional<Duration> actual) {
    near(
        expected,
        actual.orElseThrow(
            () -> new AssertionError("expected about " + expected + ", was unlimited")));
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void localKeysReportsTheEarlierOfItsTtlAndLeaseAndFallsDuringAnOutage(KmipVersion version) {
    try (LocalKeysTest.Fixture f = new LocalKeysTest.Fixture(version)) {
      f.key();
      LocalKeys c = f.cache(); // TTL 10 s, update interval 5 s
      assertEquals(Optional.of(Duration.ZERO), c.usableFor(), "nothing cached yet");
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      assertEquals(Optional.of(Duration.ofSeconds(10)), c.usableFor(), "no lease: the TTL");
      f.advance(3);
      assertEquals(Optional.of(Duration.ofSeconds(7)), c.usableFor());
      int exchanges = f.server.exchanges();
      assertEquals(Optional.of(Duration.ofSeconds(7)), c.usableFor());
      assertEquals(exchanges, f.server.exchanges(), "a diagnostic sends nothing");
      assertTrue(f.executor.queue.isEmpty(), "and starts no refresh");
      f.advance(8);
      assertEquals(Optional.of(Duration.ZERO), c.usableFor(), "expired");

      // A lease shorter than the TTL bounds it; a renewal raises it again.
      f.server.leaseTime(Duration.ofSeconds(6));
      c.invalidateAll();
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      assertEquals(Optional.of(Duration.ofSeconds(6)), c.usableFor());
      f.advance(4);
      assertEquals(Optional.of(Duration.ofSeconds(2)), c.usableFor());
      try (LocalKeys.Use ignored = c.forEncrypt()) {} // due at half the lease: queued
      f.executor.run();
      assertEquals(Optional.of(Duration.ofSeconds(6)), c.usableFor(), "renewed");
      assertEquals(Optional.empty(), c.writeFailure(), "healthy");
      f.server.unreachable(true);
      f.advance(4);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.executor.run(); // fails: the KMS is down
      assertEquals(Optional.of(Duration.ofSeconds(2)), c.usableFor(), "falls while refreshes fail");
      RuntimeException failing =
          c.writeFailure().orElseThrow(() -> new AssertionError("a failed refresh is reported"));
      assertInstanceOf(KmsException.class, failing);
      f.advance(2);
      assertEquals(Optional.of(Duration.ZERO), c.usableFor());
      assertEquals(Optional.of(failing), c.writeFailure(), "kept until a validation succeeds");
      f.server.unreachable(false);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      assertEquals(Optional.empty(), c.writeFailure(), "cleared by a successful validation");
      c.close();
      assertEquals(Optional.of(Duration.ZERO), c.usableFor(), "closed: nothing usable");
    }
  }

  /**
   * An idle, healthy cache runs its figure down to zero, as a
   * failing one does; {@link LocalKeys#writeFailure()} tells them apart, from memory. A failed cold
   * load at a call counts as a failed validation too.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void localKeysWriteFailureTellsAnIdleCacheFromAFailingOne(KmipVersion version) {
    try (LocalKeysTest.Fixture f = new LocalKeysTest.Fixture(version)) {
      f.key();
      LocalKeys c = f.cache(); // TTL 10 s
      assertEquals(Optional.empty(), c.writeFailure(), "nothing validated yet");
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.advance(11); // idle for a TTL: nothing asked it to refresh
      assertEquals(Optional.of(Duration.ZERO), c.usableFor());
      assertEquals(Optional.empty(), c.writeFailure(), "idle, not failing");
      int exchanges = f.server.exchanges();
      c.writeFailure();
      assertEquals(exchanges, f.server.exchanges(), "read from memory");

      f.server.unreachable(true);
      KmsException cold = assertThrows(KmsException.class, c::forEncrypt);
      assertEquals(Optional.of(cold), c.writeFailure(), "the failed load at the call");
      f.server.unreachable(false);
      f.advance(2); // past the backoff
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      assertEquals(Optional.empty(), c.writeFailure());
      assertEquals(Optional.of(Duration.ofSeconds(10)), c.usableFor());
    }
  }

  /**
   * An explicit invalidation or a close starts over, so it clears {@link LocalKeys#writeFailure()}
   * (nothing has been tried since); a closed caller-owned {@link Kms} makes the figure zero, as the
   * cache's own close does.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void localKeysWriteFailureEndsAtAnInvalidationOrCloseAndAClosedKmsLeavesNothingUsable(
      KmipVersion version) {
    try (LocalKeysTest.Fixture f = new LocalKeysTest.Fixture(version)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      f.server.unreachable(true);
      assertThrows(KmsException.class, c::forEncrypt);
      assertTrue(c.writeFailure().isPresent());
      c.invalidateAll();
      assertEquals(Optional.empty(), c.writeFailure(), "invalidateAll");
      f.advance(2);
      assertThrows(KmsException.class, c::forEncrypt);
      assertTrue(c.writeFailure().isPresent());
      f.server.unreachable(false);
      c.invalidate(key.id()); // not cached: the failure was the selection's, kept
      f.advance(2);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.server.unreachable(true);
      f.advance(6);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.executor.run(); // the refresh fails
      assertTrue(c.writeFailure().isPresent());
      c.invalidate(key.id());
      assertEquals(Optional.empty(), c.writeFailure(), "invalidate(the write key)");
      f.advance(2);
      assertThrows(KmsException.class, c::forEncrypt);
      assertTrue(c.writeFailure().isPresent());
      c.close();
      assertEquals(Optional.empty(), c.writeFailure(), "closed: nothing tried");
      assertEquals(Optional.of(Duration.ZERO), c.usableFor());

      f.server.unreachable(false);
      LocalKeys d = f.cache();
      try (LocalKeys.Use ignored = d.forEncrypt()) {}
      assertEquals(Optional.of(Duration.ofSeconds(10)), d.usableFor());
      f.client.close();
      assertEquals(
          Optional.of(Duration.ZERO), d.usableFor(), "its Kms is closed: nothing is handed out");
      assertThrows(IllegalStateException.class, d::forEncrypt);
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theTlsFollowersReportTheEarliestLeaseOfWhatTheyPresent(KmipVersion version)
      throws Exception {
    try (TlsLeaseTest.Fixture fx = new TlsLeaseTest.Fixture(version, false)) {
      Issued peer = fx.pki.leaf("peer", TestPki.ec());
      fx.anchor(fx.pki.root);
      fx.peer(peer);
      fx.register(TlsLeaseTest.NAME, TestPki.ec());
      // No Lease Time: nothing bounds them.
      TlsIdentityFollower plain = fx.follow(TlsLeaseTest.NAME);
      TlsTrustFollower plainTrust = fx.trust(SCHEDULER);
      assertEquals(Optional.empty(), plain.usableFor());
      assertEquals(Optional.empty(), plainTrust.usableFor());
      plain.close();
      plainTrust.close();
      assertEquals(Optional.of(Duration.ZERO), plain.usableFor(), "closed: presents nothing");
      assertEquals(Optional.of(Duration.ZERO), plainTrust.usableFor());

      fx.server.leaseTime(Duration.ofMinutes(5));
      TlsIdentityFollower f = fx.follow(TlsLeaseTest.NAME);
      TlsTrustFollower t = fx.trust(SCHEDULER);
      near(Duration.ofMinutes(5), f.usableFor());
      near(Duration.ofMinutes(5), t.usableFor());
      fx.advance(100);
      near(Duration.ofSeconds(200), f.usableFor());
      near(Duration.ofSeconds(200), t.usableFor());
      int exchanges = fx.server.exchanges();
      f.usableFor();
      t.usableFor();
      assertEquals(exchanges, fx.server.exchanges(), "a diagnostic sends nothing");
      // A refresh renews: back to the full lease.
      f.refresh();
      t.refresh();
      near(Duration.ofMinutes(5), f.usableFor());
      near(Duration.ofMinutes(5), t.usableFor());
      // An outage: it falls, and reaches zero as the material stops being used.
      fx.server.unreachable(true);
      fx.advance(250);
      f.refresh();
      t.refresh();
      near(Duration.ofSeconds(50), f.usableFor());
      near(Duration.ofSeconds(50), t.usableFor());
      assertTrue(f.identity().isPresent());
      fx.advance(51);
      assertEquals(Optional.of(Duration.ZERO), f.usableFor());
      assertEquals(Optional.of(Duration.ZERO), t.usableFor());
      assertTrue(f.identity().isEmpty());
      assertTrue(t.anchors().isEmpty());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1"})
  void theTrustFollowersEarliestLeaseIsAPeersWhenThatEndsFirst(KmipVersion version)
      throws Exception {
    try (TlsLeaseTest.Fixture fx = new TlsLeaseTest.Fixture(version, false)) {
      Issued peer = fx.pki.leaf("peer", TestPki.ec());
      String anchor = fx.anchor(fx.pki.root).id();
      String allowed = fx.peer(peer).id();
      fx.leasing.leaseTimes.put(anchor, 300L);
      fx.leasing.leaseTimes.put(allowed, 60L);
      TlsTrustFollower t = fx.trust(SCHEDULER);
      near(Duration.ofSeconds(60), t.usableFor());
      fx.advance(61);
      // The peer's lease ended: it is no longer in use, and the anchor's lease is what remains.
      near(Duration.ofSeconds(239), t.usableFor());
      assertTrue(t.allowedPeers().orElseThrow().isEmpty());
    }
  }
}
