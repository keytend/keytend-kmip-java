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

import static dev.keytend.kmip.kms.LocalKeysTest.FAMILY;
import static dev.keytend.kmip.kms.LocalKeysTest.NAME;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.LeasingTransport.Grant;
import dev.keytend.kmip.kms.LeasingTransport.Malformed;
import dev.keytend.kmip.kms.LeasingTransport.Refuse;
import dev.keytend.kmip.kms.LocalKeysTest.QueueExecutor;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * KMIP Lease Time and {@link LocalKeys}: a leased key is fetched only after Obtain Lease grants a
 * lease, and handed out only while that lease runs, measured on the cache's ticker (which the test
 * moves) from before the first send. Refusals fail closed across purposes; outages keep copies only
 * to their own ends.
 */
class LocalKeysLeaseTest {
  static final Duration TTL = Duration.ofSeconds(20);

  static final class Fixture implements AutoCloseable {
    final InMemoryKmipServer server;
    final LeasingTransport leasing;
    final Kms admin, client;
    final AtomicLong time = new AtomicLong(100);
    final QueueExecutor executor = new QueueExecutor();
    final List<LocalKeys> caches = new ArrayList<>();
    final KmipVersion version;

    Fixture(KmipVersion version) {
      this(version, RetryPolicy.none());
    }

    Fixture(KmipVersion version, RetryPolicy retry) {
      this.version = version;
      server = InMemoryKmipServer.of(version);
      leasing = new LeasingTransport(server);
      admin = server.connect();
      client =
          Kms.connect(
              server
                  .configure()
                  .retryPolicy(retry)
                  .callTimeout(Duration.ofSeconds(5))
                  .transport(e -> leasing)
                  .build());
    }

    KeyHandle key() {
      KeyCreation c =
          admin
              .keys()
              .createAes(256)
              .custom(FAMILY, "orders")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named(NAME);
      // Extractable came with KMIP 1.4; the in-memory server releases values before it.
      if (version.compareTo(KmipVersion.V1_4) >= 0) c.extractable(true);
      return c.create();
    }

    LocalKeys.Builder builder() {
      LocalKeys.Builder b =
          client
              .keys()
              .localKeys(NAME)
              .scope(KeyQuery.all().custom(FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(TTL)
              .refreshExecutor(executor);
      b.ticker = time::get;
      return b;
    }

    LocalKeys cache() {
      LocalKeys c = builder().open();
      caches.add(c);
      return c;
    }

    void advance(double seconds) {
      time.addAndGet((long) (seconds * 1e9));
    }

    /** The operations sent, without Locate (which names no object). */
    List<String> ops() {
      return leasing.trace.stream().map(t -> t.substring(0, t.indexOf(' '))).toList();
    }

    long gets() {
      return leasing.trace.stream().filter(t -> t.startsWith("Get ")).count();
    }

    @Override
    public void close() {
      caches.forEach(LocalKeys::close);
      client.close();
      admin.close();
      server.close();
    }
  }

  private static void use(LocalKeys c, String expected, boolean encrypt) {
    try (LocalKeys.Use u = encrypt ? c.forEncrypt() : c.forDecrypt(expected)) {
      assertEquals(expected, u.id());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_1", "V1_4", "V2_0", "V2_1", "V3_0"})
  void noLeaseTimeSendsNoObtainLeaseAndKeepsTheTtl(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      use(c, key.id(), true);
      use(c, key.id(), false);
      f.advance(19.9);
      use(c, key.id(), false);
      assertEquals(0, f.leasing.obtainRequests.get());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_1", "V1_4", "V2_0", "V2_1", "V3_0"})
  void aLeaseIsObtainedBeforeGetAndHandoutStopsAtItsEndDuringAnOutage(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 6L);
      LocalKeys c = f.cache();
      f.leasing.reset();
      use(c, key.id(), false);
      assertEquals(List.of("GetAttributes", "ObtainLease", "Get"), f.ops());
      f.server.unreachable(true);
      f.leasing.dropObtains = true;
      f.advance(5.999);
      use(c, key.id(), false); // Still within the lease: memory only; the renewal is queued.
      assertEquals(1, f.executor.queue.size());
      f.executor.run(); // The outage: no new lease.
      use(c, key.id(), false);
      f.advance(0.001);
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
      f.server.unreachable(false);
      f.leasing.dropObtains = false;
      // Back: the lease is renewed (no Get counts as one) before the key is fetched again.
      f.leasing.reset();
      f.advance(1);
      use(c, key.id(), false);
      assertEquals(List.of("GetAttributes", "ObtainLease", "Get"), f.ops());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theLeaseRunsFromBeforeTheFirstSendNotFromItsAnswer(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 6L);
      f.leasing.onObtain = () -> f.advance(2); // The server takes 2 s to answer.
      LocalKeys c = f.cache();
      use(c, key.id(), true);
      f.leasing.onObtain = () -> {};
      f.server.unreachable(true);
      f.leasing.dropObtains = true;
      f.advance(3.999);
      assertEquals(key.id(), c.currentWriteId().orElseThrow());
      f.advance(0.001);
      assertTrue(c.currentWriteId().isEmpty());
    }
  }

  @Test
  void aRetriedObtainLeaseIsTimedFromItsFirstAttempt() {
    RetryPolicy retry =
        RetryPolicy.builder()
            .maxAttempts(3)
            .initialBackoff(Duration.ofMillis(1))
            .maxBackoff(Duration.ofMillis(1))
            .jitter(0)
            .cooldown(Duration.ZERO)
            .build();
    try (Fixture f = new Fixture(KmipVersion.V2_1, retry)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 6L);
      LocalKeys c = f.cache();
      AtomicInteger attempts = new AtomicInteger();
      // The first Obtain Lease attempt is lost after 3 s; the retry is granted 6 s.
      f.leasing.beforeEach =
          request -> {
            if (!obtainLease(request)) return;
            boolean first = attempts.incrementAndGet() == 1;
            if (first) f.advance(3);
            f.leasing.dropObtains = first;
          };
      use(c, key.id(), false);
      assertEquals(2, attempts.get(), "retried");
      f.leasing.beforeEach = request -> {};
      f.server.unreachable(true);
      f.leasing.dropObtains = true;
      f.advance(2.999);
      use(c, key.id(), false);
      f.advance(0.001);
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
    }
  }

  static boolean obtainLease(Ttlv request) {
    return request.children(Tag.BATCH_ITEM).stream()
        .anyMatch(
            i ->
                i.require(Tag.OPERATION).intValue()
                    == dev.keytend.kmip.model.Operation.OBTAIN_LEASE.code());
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void zeroGrantIsNoLeaseLimitEvenUnderAPositiveStatedMaximum(KmipVersion version) {
    // KMIP 1.4 §4.17 / 2.1 §6.1.35: "If the returned value of the lease time is zero ... the client
    // MAY use the object without any lease time limit"; zero is <= any stated maximum (1.4 §3.20).
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 300L);
      f.leasing.answer = id -> new Grant(0);
      LocalKeys c = f.cache();
      use(c, key.id(), false);
      f.server.unreachable(true);
      f.leasing.dropObtains = true;
      f.advance(19.999);
      use(c, key.id(), false); // Bounded by the TTL alone.
      f.advance(0.001);
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void positiveGrantUnderAStatedZeroIsABoundedLease(KmipVersion version) {
    // A server may grant the time left before a Deactivation Date even when its maximum is 0.
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 0L);
      f.leasing.answer = id -> new Grant(6);
      LocalKeys c = f.cache();
      use(c, key.id(), false);
      f.server.unreachable(true);
      f.leasing.dropObtains = true;
      f.advance(5.999);
      use(c, key.id(), false);
      f.advance(0.001);
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
    }
  }

  @Test
  void aGrantAboveThePositiveStatedMaximumIsHeldToIt() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 6L);
      f.leasing.answer = id -> new Grant(100);
      LocalKeys c = f.cache();
      use(c, key.id(), false);
      f.server.unreachable(true);
      f.leasing.dropObtains = true;
      f.advance(5.999);
      use(c, key.id(), false);
      f.advance(0.001);
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
    }
  }

  @Test
  void aMalformedLeaseTimeStillNeedsAndUsesTheGrant() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 300L);
      f.leasing.integerLeaseTime = true;
      f.leasing.answer = id -> new Grant(6);
      LocalKeys c = f.cache();
      f.leasing.reset();
      use(c, key.id(), false);
      assertEquals(List.of("GetAttributes", "ObtainLease", "Get"), f.ops());
      f.advance(6);
      f.leasing.dropObtains = true;
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anEarlyShortLeaseIsRenewedFromHalfItsLengthBeforeTheRefreshInterval(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 4L);
      LocalKeys c = f.cache();
      use(c, key.id(), true);
      f.advance(1.999);
      use(c, key.id(), true);
      assertTrue(f.executor.queue.isEmpty());
      f.advance(0.001);
      use(c, key.id(), true); // Half the lease: renewal queued; the hit is still served.
      assertEquals(1, f.executor.queue.size());
      f.leasing.reset();
      f.executor.run();
      assertTrue(f.ops().contains("ObtainLease"));
      f.server.unreachable(true);
      f.leasing.dropObtains = true;
      f.advance(3.999); // The renewed lease (from t=2) runs to t=6.
      use(c, key.id(), true);
      f.advance(0.001);
      assertTrue(c.currentWriteId().isEmpty());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_1", "V1_4", "V2_1", "V3_0"})
  void aRefusedRenewalFailsClosedAcrossPurposesWithTheServerReason(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 6L);
      LocalKeys c = f.cache();
      use(c, key.id(), true);
      use(c, key.id(), false); // Seeded from the write validation.
      f.advance(3);
      f.leasing.answer = id -> new Refuse(Enums.ResultReason.PERMISSION_DENIED);
      use(c, key.id(), false); // Queues the renewal.
      long gets = f.gets();
      f.executor.run();
      assertEquals(gets, f.gets(), "no Get after a refused lease");
      PermissionDeniedException read =
          assertThrows(PermissionDeniedException.class, () -> c.forDecrypt(key.id()));
      assertEquals(key.id(), read.objectId().orElseThrow());
      assertEquals(KmsReason.PERMISSION_DENIED, read.serverReason().orElseThrow());
      assertEquals("lease refused for " + key.id(), read.serverMessage().orElseThrow());
      assertEquals("obtainLease", read.operation());
      assertTrue(read.getMessage().contains(key.id() + " for DECRYPT"), read.getMessage());
      assertTrue(c.currentWriteId().isEmpty());
      KmsException write = assertThrows(KmsException.class, c::forEncrypt);
      assertInstanceOf(PermissionDeniedException.class, write);
      assertEquals(gets, f.gets());
      // Remembered for the TTL without a request; invalidation clears it.
      int asked = f.leasing.obtainRequests.get();
      assertThrows(PermissionDeniedException.class, () -> c.forDecrypt(key.id()));
      assertEquals(asked, f.leasing.obtainRequests.get());
      f.leasing.answer = id -> new Grant(6);
      c.invalidate(key.id());
      use(c, key.id(), false);
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void eachRefusalKindIsDefiniteRememberedAndEvictsBothPurposesBeforeAnyGet(KmipVersion version) {
    for (Enums.ResultReason reason :
        List.of(
            Enums.ResultReason.PERMISSION_DENIED,
            Enums.ResultReason.OPERATION_NOT_SUPPORTED,
            Enums.ResultReason.ITEM_NOT_FOUND,
            Enums.ResultReason.INVALID_FIELD))
      try (Fixture f = new Fixture(version)) {
        KeyHandle key = f.key();
        f.leasing.leaseTimes.put(key.id(), 6L);
        LocalKeys c = f.cache();
        use(c, key.id(), true); // Write and seeded read copies.
        f.advance(3);
        f.leasing.answer = id -> new Refuse(reason);
        use(c, key.id(), false);
        long gets = f.gets();
        f.executor.run(); // The read renewal is refused.
        assertEquals(gets, f.gets(), reason.toString());
        assertTrue(c.currentWriteId().isEmpty(), reason + ": the write copy is evicted at once");
        KmsException e =
            assertThrows(KmsException.class, () -> c.forDecrypt(key.id()), reason.toString());
        assertTrue(Leases.refusal(e), reason + ": " + e);
        assertEquals(key.id(), e.objectId().orElseThrow());
        assertTrue(e.serverReason().isPresent());
        assertTrue(e.result().isPresent(), "a server answer, never a local trust rejection");
        assertTrue(e.getMessage().contains(key.id() + " for DECRYPT"), e.getMessage());
        int asked = f.leasing.obtainRequests.get();
        assertSame(e, assertThrows(KmsException.class, () -> c.forDecrypt(key.id())), "remembered");
        assertEquals(asked, f.leasing.obtainRequests.get());
        assertEquals(gets, f.gets());
      }
  }

  @Test
  void theInMemoryServersMissingObtainLeaseIsARefusal() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 6L);
      LeasingTransport passThrough = f.leasing;
      passThrough.answer = id -> new Refuse(Enums.ResultReason.OPERATION_NOT_SUPPORTED);
      LocalKeys c = f.cache();
      assertThrows(UnsupportedException.class, c::forEncrypt);
      assertEquals(0, f.gets());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void malformedGrantsGrantNothingAndKeepEarlierCopiesOnlyToTheirLeaseEnd(KmipVersion version) {
    List<Function<String, List<Ttlv>>> malformed =
        List.of(
            id ->
                List.of(
                    Ttlv.text(Tag.UNIQUE_IDENTIFIER, id + "-other"),
                    Ttlv.interval(Tag.LEASE_TIME, 600)),
            id -> List.of(Ttlv.text(Tag.UNIQUE_IDENTIFIER, id)),
            id -> List.of(Ttlv.text(Tag.UNIQUE_IDENTIFIER, id), Ttlv.integer(Tag.LEASE_TIME, 600)),
            id ->
                List.of(
                    Ttlv.text(Tag.UNIQUE_IDENTIFIER, id),
                    Ttlv.interval(Tag.LEASE_TIME, 600),
                    Ttlv.interval(Tag.LEASE_TIME, 600)),
            id -> List.of(Ttlv.interval(Tag.LEASE_TIME, 600)));
    for (Function<String, List<Ttlv>> payload : malformed)
      try (Fixture f = new Fixture(version)) {
        KeyHandle key = f.key();
        f.leasing.leaseTimes.put(key.id(), 6L);
        LocalKeys c = f.cache();
        use(c, key.id(), false);
        f.advance(3);
        f.leasing.answer = id -> new Malformed(payload);
        use(c, key.id(), false);
        long gets = f.gets();
        f.executor.run();
        assertEquals(gets, f.gets());
        f.advance(2.999);
        use(c, key.id(), false); // Not a refusal: the earlier lease still runs.
        f.advance(0.001);
        KmsException e = assertThrows(KmsException.class, () -> c.forDecrypt(key.id()));
        assertFalse(Leases.refusal(e), e.toString());
        assertEquals(gets, f.gets());
      }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aDeactivatedHistoricalKeyDecryptsOnlyWhileTheServerGrantsItALease(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle old = f.key();
      f.leasing.everyObject = 6L;
      old.deactivate();
      // A server that leases only Active objects refuses with Permission Denied.
      f.leasing.answer =
          id ->
              id.equals(old.id()) ? new Refuse(Enums.ResultReason.PERMISSION_DENIED) : new Grant(6);
      LocalKeys c = f.cache();
      // Its lifecycle, not access: STATE, with the state read and the server's reason.
      StateConflictException e =
          assertThrows(StateConflictException.class, () -> c.forDecrypt(old.id()));
      assertEquals(KeyState.DEACTIVATED, e.observedState().orElseThrow());
      assertEquals("obtainLease", e.operation());
      assertEquals(old.id(), e.objectId().orElseThrow());
      assertEquals(KmsReason.PERMISSION_DENIED, e.serverReason().orElseThrow());
      assertTrue(e.getMessage().contains(old.id() + " for DECRYPT"), e.getMessage());
      assertTrue(
          e.getMessage().contains("lease refused for " + old.id()),
          "the server's message: " + e.getMessage());
      assertEquals(0, f.gets());
      // A server that grants the historical lease: decrypt only while it runs.
      try (Fixture g = new Fixture(version)) {
        KeyHandle key = g.key();
        g.leasing.everyObject = 6L;
        key.deactivate();
        LocalKeys d = g.cache();
        use(d, key.id(), false);
        g.leasing.dropObtains = true;
        g.server.unreachable(true);
        g.advance(5.999);
        use(d, key.id(), false);
        g.advance(0.001);
        assertThrows(TransientException.class, () -> d.forDecrypt(key.id()));
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theSupportedRotationKeepsTheOldKeyActiveAndStopsWritesOnceItIsNotNamed(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle old = f.key();
      f.leasing.everyObject = 6L;
      f.leasing.answer = id -> new Grant(6);
      LocalKeys c = f.cache();
      use(c, old.id(), true);
      // The operator moves the write name; the old key stays Active (no dates), in scope.
      old.removeName(NAME);
      KeyHandle next = f.key();
      f.advance(3); // Half the lease: the next write revalidates.
      use(c, old.id(), true);
      f.executor.run();
      use(c, next.id(), true);
      use(c, old.id(), false); // Historical read of the Active old key, under its own lease.
      f.advance(10);
      use(c, old.id(), false);
      use(c, next.id(), true);
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theSeededDecryptCopySharesTheWriteValidationsLeaseAndAge(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 6L);
      LocalKeys c = f.cache();
      use(c, key.id(), true);
      int asked = f.leasing.obtainRequests.get();
      f.server.unreachable(true);
      f.leasing.dropObtains = true;
      f.advance(1);
      use(c, key.id(), false); // Seeded: no request.
      assertEquals(asked, f.leasing.obtainRequests.get());
      f.advance(4.999);
      use(c, key.id(), false);
      f.advance(0.001);
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
      assertThrows(TransientException.class, c::forEncrypt);
    }
  }

  @Test
  void aTransientLeaseFailureForOnePurposeLeavesTheOtherPurposesCopy() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 6L);
      LocalKeys c = f.cache();
      use(c, key.id(), true); // Write and seeded read copies: lease [0, 6).
      f.advance(3);
      use(c, key.id(), false);
      f.executor.run(); // The read copy's own renewal: lease [3, 9).
      use(c, key.id(), true);
      f.leasing.dropObtains = true;
      f.executor.run(); // The write renewal is lost: its copy keeps [0, 6).
      f.advance(2.999);
      use(c, key.id(), true);
      f.advance(0.001);
      assertTrue(c.currentWriteId().isEmpty());
      use(c, key.id(), false); // Unaffected by the write purpose's failure.
      f.advance(2.999);
      use(c, key.id(), false);
      f.advance(0.001);
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
    }
  }

  @Test
  void aStalledRefreshExecutorCannotExtendALeaseAndAnExpiredUseLoadsItself() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 6L);
      LocalKeys c = f.cache();
      use(c, key.id(), false);
      f.advance(3);
      use(c, key.id(), false);
      assertEquals(1, f.executor.queue.size()); // Never run.
      f.advance(3);
      f.leasing.reset();
      use(c, key.id(), false); // Expired: a synchronous load with a new lease.
      assertEquals(List.of("GetAttributes", "ObtainLease", "Get"), f.ops());
      f.executor.run(); // The superseded queued refresh does nothing.
      assertEquals(List.of("GetAttributes", "ObtainLease", "Get"), f.ops());
    }
  }

  @Test
  void anUnleasedCopyIsDroppedOnceItsKeyStatesALeaseTime() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      use(c, key.id(), false);
      assertEquals(0, f.leasing.obtainRequests.get());
      f.leasing.leaseTimes.put(key.id(), 6L);
      use(c, key.id(), true); // The write validation observes the Lease Time for the same ID.
      f.leasing.dropObtains = true;
      f.server.unreachable(true);
      f.advance(6); // The write copy's lease ended; the old unleased read copy was dropped.
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
    }
  }

  @Test
  void invalidationDuringObtainLeaseSupersedesItsRefusal() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 6L);
      LocalKeys c = f.cache();
      AtomicBoolean first = new AtomicBoolean(true);
      f.leasing.answer =
          id -> {
            if (first.getAndSet(false)) {
              c.invalidate(id);
              return new Refuse(Enums.ResultReason.PERMISSION_DENIED);
            }
            return new Grant(6);
          };
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
      use(c, key.id(), false); // The superseded refusal was not remembered.
      assertEquals(2, f.leasing.obtainRequests.get());
    }
  }

  @Test
  void closeDuringObtainLeasePublishesNothing() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 6L);
      LocalKeys c = f.cache();
      f.leasing.onObtain = c::close;
      assertThrows(RuntimeException.class, () -> c.forDecrypt(key.id()));
      assertEquals(0, f.gets());
      assertThrows(IllegalStateException.class, () -> c.forDecrypt(key.id()));
    }
  }

  @Test
  void concurrentColdUsesShareOneLeaseAndOneGet() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 6L);
      LocalKeys c = f.cache();
      CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
      f.leasing.onObtain =
          () -> {
            entered.countDown();
            try {
              assertTrue(release.await(3, TimeUnit.SECONDS));
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            }
          };
      ExecutorService pool = Executors.newFixedThreadPool(8);
      try {
        List<Future<?>> uses = new ArrayList<>();
        uses.add(pool.submit(() -> use(c, key.id(), false)));
        assertTrue(entered.await(3, TimeUnit.SECONDS));
        for (int i = 0; i < 7; i++) uses.add(pool.submit(() -> use(c, key.id(), false)));
        release.countDown();
        for (Future<?> u : uses) u.get(5, TimeUnit.SECONDS);
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
      assertEquals(1, f.leasing.obtainRequests.get());
      assertEquals(1, f.gets());
    }
  }

  @Test
  void aGetThatOutlastsTheLeasePublishesNothing() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 6L);
      LocalKeys c = f.cache();
      f.leasing.beforeEach =
          request -> {
            if (!f.leasing.trace.isEmpty()
                && f.leasing.trace.get(f.leasing.trace.size() - 1).startsWith("ObtainLease"))
              f.advance(6);
          };
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
      f.leasing.beforeEach = request -> {};
      f.leasing.dropObtains = true;
      f.server.unreachable(true);
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
    }
  }

  @Test
  void usageLimitsRemainRefusedBeforeLeaseOrGet() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      f.leasing.leaseTimes.put(key.id(), 6L);
      f.leasing.usageLimited.add(key.id());
      LocalKeys c = f.cache();
      assertThrows(UnsupportedException.class, () -> c.forDecrypt(key.id()));
      assertEquals(0, f.leasing.obtainRequests.get());
      assertEquals(0, f.gets());
    }
  }
}
