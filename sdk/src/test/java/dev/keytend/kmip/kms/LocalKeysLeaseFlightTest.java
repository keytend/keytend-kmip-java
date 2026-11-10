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

import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BiConsumer;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/** Deterministic checks that a loading flight honors the newest lease observation, in every interleaving. */
class LocalKeysLeaseFlightTest {
  private static final KmipVersion[] VERSIONS = {
    KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0
  };

  static Stream<Arguments> races() {
    return Stream.of(VERSIONS)
        .flatMap(
            v ->
                Stream.of(true, false)
                    .flatMap(
                        write ->
                            Stream.of(true, false)
                                .map(beforeGet -> Arguments.of(v, write, beforeGet))));
  }

  private static void use(LocalKeys c, String id, boolean write) {
    try (LocalKeys.Use u = write ? c.forEncrypt() : c.forDecrypt(id)) {
      assertEquals(id, u.id());
    }
  }

  /** Holds a complete response outside all cache locks; no sleeps or scheduler-dependent races. */
  private static final class Gate implements AutoCloseable {
    final CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);

    void hold() {
      entered.countDown();
      try {
        assertTrue(release.await(8, TimeUnit.SECONDS), "response was never released");
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new AssertionError(e);
      }
    }

    void await() throws InterruptedException {
      assertTrue(entered.await(8, TimeUnit.SECONDS), "response gate was never reached");
    }

    @Override
    public void close() {
      release.countDown();
    }
  }

  private static void completed(Future<?> task) throws Exception {
    try {
      task.get(8, TimeUnit.SECONDS);
    } catch (ExecutionException e) {
      if (e.getCause() instanceof AssertionError assertion) throw assertion;
      throw e;
    }
  }

  /** A separate client lets each test intercept already captured responses, not just request entry. */
  private static Kms client(LocalKeysLeaseTest.Fixture f, BiConsumer<Ttlv, Ttlv> after) {
    return Kms.connect(
        f.server
            .configure()
            .retryPolicy(RetryPolicy.none())
            .callTimeout(Duration.ofSeconds(15))
            .transport(
                endpoint ->
                    request -> {
                      Ttlv response = f.leasing.exchange(request);
                      after.accept(request, response);
                      return response;
                    })
            .build());
  }

  private static LocalKeys cache(LocalKeysLeaseTest.Fixture f, Kms client, int capacity) {
    LocalKeys.Builder b =
        client
            .keys()
            .localKeys(NAME)
            .scope(KeyQuery.all().custom(FAMILY, "orders"))
            .expect(Expect.aes(256))
            .ttl(Duration.ofSeconds(20))
            .capacity(capacity)
            .refreshExecutor(f.executor);
    b.ticker = f.time::get;
    LocalKeys c = b.open();
    f.caches.add(c);
    return c;
  }

  @ParameterizedTest(name = "{0}, old write={1}, before Get={2}")
  @MethodSource("races")
  void observationWinsAtLoaderAndPublicationInBothDirections(
      KmipVersion version, boolean oldWrite, boolean beforeGet) throws Exception {
    try (var f = new LocalKeysLeaseTest.Fixture(version);
        var gate = new Gate()) {
      String id = f.key().id();
      AtomicInteger seen = new AtomicInteger();
      Operation held = beforeGet ? Operation.GET_ATTRIBUTES : Operation.GET;
      // The write validation's only Get Attributes is its selection's, which its checks reuse
      // ; an observation applied meanwhile makes it read again, so it obtains its own lease.
      boolean reread = beforeGet && oldWrite;
      try (Kms client =
          client(
              f,
              (request, response) -> {
                if (LocalKeysTest.is(request, held) && seen.incrementAndGet() == 1) gate.hold();
              })) {
        LocalKeys c = cache(f, client, 8);
        var pool = Executors.newSingleThreadExecutor();
        try {
          var old =
              pool.submit(
                  () -> {
                    if (reread) use(c, id, true);
                    else assertThrows(TransientException.class, () -> use(c, id, oldWrite));
                  });
          gate.await();
          // The held response really contains an older, unleased snapshot (or its material).
          f.leasing.leaseTimes.put(id, 6L);
          use(c, id, !oldWrite);
          gate.close();
          completed(old);
          assertEquals(
              beforeGet && !reread ? 1 : 2, f.gets(), "a rejected pre-Get load must not fetch");
          if (reread)
            assertEquals(2, f.leasing.obtainRequests.get(), "the old write obtained its own lease");
          int obtains = f.leasing.obtainRequests.get();
          use(c, id, !oldWrite);
          assertEquals(obtains, f.leasing.obtainRequests.get(), "observer kept its valid grant");
          // The old write must neither replace nor seed over the observer's leased read.
          f.server.unreachable(true);
          f.leasing.dropObtains = true;
          f.advance(6);
          assertTrue(c.currentWriteId().isEmpty());
          assertThrows(TransientException.class, () -> use(c, id, true));
          assertThrows(TransientException.class, () -> use(c, id, false));
          f.server.unreachable(false);
          f.leasing.dropObtains = false;
          f.advance(1);
          use(c, id, oldWrite);
          use(c, id, !oldWrite);
        } finally {
          gate.close();
          pool.shutdownNow();
          assertTrue(pool.awaitTermination(8, TimeUnit.SECONDS));
        }
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void selectorObservationSurvivesAmbiguityWithoutPoisoningTheId(KmipVersion version)
      throws Exception {
    try (var f = new LocalKeysLeaseTest.Fixture(version);
        var gate = new Gate()) {
      String id = f.key().id();
      f.key(); // a cold write selector must fail as ambiguous, after observing both candidates
      AtomicInteger seen = new AtomicInteger();
      try (Kms client =
          client(
              f,
              (request, response) -> {
                if (LocalKeysTest.is(request, Operation.GET_ATTRIBUTES)
                    && seen.incrementAndGet() == 1) gate.hold();
              })) {
        LocalKeys c = cache(f, client, 8);
        var pool = Executors.newSingleThreadExecutor();
        try {
          var old =
              pool.submit(() -> assertThrows(TransientException.class, () -> use(c, id, false)));
          gate.await();
          f.leasing.leaseTimes.put(id, 6L);
          assertThrows(StateConflictException.class, c::forEncrypt);
          assertEquals(
              0, f.leasing.obtainRequests.get(), "selector failure never acquired a lease");
          gate.close();
          completed(old);
          assertEquals(0, f.gets());
          f.advance(1);
          use(c, id, false); // only short retry suppression, no definite ID refusal
        } finally {
          gate.close();
          pool.shutdownNow();
          assertTrue(pool.awaitTermination(8, TimeUnit.SECONDS));
        }
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void supersededSelectorCannotImposeItsStaleLeaseObservation(KmipVersion version)
      throws Exception {
    try (var f = new LocalKeysLeaseTest.Fixture(version);
        var gate = new Gate()) {
      String id = f.key().id();
      f.leasing.leaseTimes.put(id, 6L);
      AtomicInteger seen = new AtomicInteger();
      try (Kms client =
          client(
              f,
              (request, response) -> {
                if (LocalKeysTest.is(request, Operation.GET_ATTRIBUTES)
                    && seen.incrementAndGet() == 1) gate.hold();
              })) {
        LocalKeys c = cache(f, client, 8);
        var pool = Executors.newSingleThreadExecutor();
        try {
          var old = pool.submit(() -> assertThrows(TransientException.class, c::forEncrypt));
          gate.await();
          c.invalidateAll();
          f.leasing.leaseTimes.remove(id);
          use(c, id, true);
          use(c, id, false);
          gate.close();
          completed(old);
          f.server.unreachable(true);
          f.advance(7);
          use(c, id, true);
          use(c, id, false);
          assertEquals(0, f.leasing.obtainRequests.get());
          assertEquals(
              1, f.gets(), "fresh write seeded a usable read; stale selector did not evict it");
        } finally {
          gate.close();
          pool.shutdownNow();
          assertTrue(pool.awaitTermination(8, TimeUnit.SECONDS));
        }
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anOldSelectionCannotImposeALeaseOnAnotherLoadingId(KmipVersion version) throws Exception {
    try (var f = new LocalKeysLeaseTest.Fixture(version);
        var gate = new Gate()) {
      KeyHandle a = f.key();
      AtomicReference<String> loading = new AtomicReference<>();
      try (Kms client =
          client(
              f,
              (request, response) -> {
                // B's Get: the write flight has registered B as its loadingId and passed its
                // checks.
                if (LocalKeysTest.is(request, Operation.GET)
                    && LocalKeysTest.id(request).equals(loading.get())) gate.hold();
              })) {
        LocalKeys c = cache(f, client, 2);
        use(c, a.id(), true); // attributes 1 (selector, reused by the loader), seeds A
        String other =
            f.admin
                .keys()
                .createAes(256)
                .custom(FAMILY, "orders")
                .usages(KeyUsage.DECRYPT)
                .extractable(true)
                .create()
                .id();
        use(c, other, false); // attributes 2; evicts seeded A with capacity 2
        a.removeName(NAME);
        String b = f.key().id();
        loading.set(b);
        f.advance(10);
        use(c, a.id(), true); // queues refresh; still the cached A
        var pool = Executors.newSingleThreadExecutor();
        try {
          var refresh = pool.submit(f.executor::run); // attrs 3 selector B, then B's Get
          gate.await();
          f.leasing.leaseTimes.put(a.id(), 6L);
          use(c, a.id(), false); // sees cached write A, but the pending flight is loading B
          gate.close();
          completed(refresh);
          assertEquals(
              b, c.currentWriteId().orElse(null), "an unrelated ID observation rejected B");
          use(c, b, true);
          use(c, b, false);
          assertEquals(java.util.List.of(a.id()), f.leasing.obtained);
          f.server.unreachable(true);
          f.advance(6);
          use(c, b, true);
          use(c, b, false);
        } finally {
          gate.close();
          pool.shutdownNow();
          assertTrue(pool.awaitTermination(8, TimeUnit.SECONDS));
        }
      }
    }
  }

  static Stream<Arguments> purposes() {
    return Stream.of(VERSIONS)
        .flatMap(v -> Stream.of(true, false).map(write -> Arguments.of(v, write)));
  }

  @ParameterizedTest(name = "{0}, write={1}")
  @MethodSource("purposes")
  void expiredArrivalStopsBothPurposesBeforeGetAndAllowsRetry(KmipVersion version, boolean write) {
    try (var f = new LocalKeysLeaseTest.Fixture(version)) {
      String id = f.key().id();
      f.leasing.leaseTimes.put(id, 0L); // a positive grant under stated zero must still expire
      f.leasing.answer = ignored -> new LeasingTransport.Grant(6);
      f.leasing.onObtain = () -> f.advance(6);
      LocalKeys c = f.cache();
      assertThrows(TransientException.class, () -> use(c, id, write));
      assertEquals(0, f.gets());
      assertTrue(c.currentWriteId().isEmpty());
      f.leasing.onObtain = () -> {};
      f.advance(1);
      use(c, id, write);
      use(c, id, !write);
    }
  }

  @ParameterizedTest(name = "{0}, old write={1}")
  @MethodSource("purposes")
  void zeroGrantObserverRemainsUnlimitedAndOldFlightCanRetry(KmipVersion version, boolean oldWrite)
      throws Exception {
    try (var f = new LocalKeysLeaseTest.Fixture(version);
        var gate = new Gate()) {
      String id = f.key().id();
      AtomicInteger seen = new AtomicInteger();
      try (Kms client =
          client(
              f,
              (request, response) -> {
                if (LocalKeysTest.is(request, Operation.GET_ATTRIBUTES)
                    && seen.incrementAndGet() == 1) gate.hold();
              })) {
        LocalKeys c = cache(f, client, 8);
        var pool = Executors.newSingleThreadExecutor();
        try {
          // The old write's held read is its selection's: the observation makes it read again.
          var old =
              pool.submit(
                  () -> {
                    if (oldWrite) use(c, id, true);
                    else assertThrows(TransientException.class, () -> use(c, id, false));
                  });
          gate.await();
          f.leasing.leaseTimes.put(id, 6L);
          f.leasing.answer = ignored -> new LeasingTransport.Grant(0);
          use(c, id, !oldWrite);
          gate.close();
          completed(old);
          f.advance(1);
          use(c, id, oldWrite);
          f.server.unreachable(true);
          f.leasing.dropObtains = true;
          f.advance(6); // zero is not capped by the stated positive maximum
          use(c, id, true);
          use(c, id, false);
          f.advance(14); // both copies have reached their original TTL
          assertTrue(c.currentWriteId().isEmpty());
          assertThrows(TransientException.class, () -> use(c, id, true));
          assertThrows(TransientException.class, () -> use(c, id, false));
        } finally {
          gate.close();
          pool.shutdownNow();
          assertTrue(pool.awaitTermination(8, TimeUnit.SECONDS));
        }
      }
    }
  }

  @ParameterizedTest(name = "{0}, hold Locate={1}")
  @MethodSource("purposes")
  void observationBeforeWriteLoadingIdIsRegisteredStillRequiresFreshLoaderAttributes(
      KmipVersion version, boolean holdLocate) throws Exception {
    try (var f = new LocalKeysLeaseTest.Fixture(version);
        var gate = new Gate()) {
      String id = f.key().id();
      AtomicInteger seen = new AtomicInteger();
      Operation held = holdLocate ? Operation.LOCATE : Operation.GET_ATTRIBUTES;
      try (Kms client =
          client(
              f,
              (request, response) -> {
                if (LocalKeysTest.is(request, held) && seen.incrementAndGet() == 1) gate.hold();
              })) {
        LocalKeys c = cache(f, client, 8);
        var pool = Executors.newSingleThreadExecutor();
        try {
          var selection = pool.submit(() -> use(c, id, true));
          gate.await(); // write has not yet set loadingId, and has no retained Entry
          f.leasing.leaseTimes.put(id, 6L);
          use(c, id, false);
          gate.close();
          completed(selection);
          assertEquals(
              2, f.leasing.obtainRequests.get(), "both validations acquired their own lease");
          f.server.unreachable(true);
          f.leasing.dropObtains = true;
          f.advance(6);
          assertTrue(c.currentWriteId().isEmpty());
          assertThrows(TransientException.class, () -> use(c, id, true));
          assertThrows(TransientException.class, () -> use(c, id, false));
        } finally {
          gate.close();
          pool.shutdownNow();
          assertTrue(pool.awaitTermination(8, TimeUnit.SECONDS));
        }
      }
    }
  }

  @ParameterizedTest(name = "{0}, old write={1}")
  @MethodSource("purposes")
  void supersededLoaderCannotImposeItsStaleLeaseObservation(KmipVersion version, boolean oldWrite)
      throws Exception {
    try (var f = new LocalKeysLeaseTest.Fixture(version);
        var gate = new Gate()) {
      String id = f.key().id();
      f.leasing.leaseTimes.put(id, 6L);
      AtomicInteger seen = new AtomicInteger();
      // The write's loader reuses its selection's read: hold that one, the only one.
      try (Kms client =
          client(
              f,
              (request, response) -> {
                if (LocalKeysTest.is(request, Operation.GET_ATTRIBUTES)
                    && seen.incrementAndGet() == 1) gate.hold();
              })) {
        LocalKeys c = cache(f, client, 8);
        var pool = Executors.newSingleThreadExecutor();
        try {
          var old =
              pool.submit(() -> assertThrows(TransientException.class, () -> use(c, id, oldWrite)));
          gate.await();
          c.invalidateAll();
          f.leasing.leaseTimes.remove(id);
          use(c, id, true);
          use(c, id, false);
          gate.close();
          completed(old);
          f.server.unreachable(true);
          f.advance(7);
          use(c, id, true);
          use(c, id, false);
          assertEquals(0, f.leasing.obtainRequests.get());
          assertEquals(1, f.gets());
        } finally {
          gate.close();
          pool.shutdownNow();
          assertTrue(pool.awaitTermination(8, TimeUnit.SECONDS));
        }
      }
    }
  }
}
