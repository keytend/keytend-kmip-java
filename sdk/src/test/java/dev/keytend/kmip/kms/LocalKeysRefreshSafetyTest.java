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

import static dev.keytend.kmip.kms.LocalKeysTest.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;

/**
 * LocalKeys under refresh: what observations, failures, invalidations and dropped work do to the
 * cached keys and selections. Each test pins the safe behavior against the failure its comment
 * names; tests named {@code holds...} check properties that must always hold.
 */
class LocalKeysRefreshSafetyTest {

  static CountDownLatch[] gate() {
    return new CountDownLatch[] {new CountDownLatch(1), new CountDownLatch(1)};
  }

  static void await(CountDownLatch latch) {
    try {
      assertTrue(latch.await(3, TimeUnit.SECONDS));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AssertionError(e);
    }
  }

  // Guards against: a historical read's Deactivated observation negative-caches the write
  // *selector* for a
  // whole TTL, although an unambiguous Active replacement exists (routine rotation runbook).
  @Test
  void deactivatedHistoryObservationReselectsTheActiveReplacement() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle old = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use a = c.forEncrypt();
          LocalKeys.Use b = c.forDecrypt(old.id())) {
        assertEquals(old.id(), a.id());
      }
      KeyHandle next = f.key(); // runbook step 1: replacement first
      old.deactivate(); // then deactivate old: Locate(Active) now selects only `next`
      f.advance(5);
      try (LocalKeys.Use ignored = c.forDecrypt(old.id())) {} // queues the historical refresh
      f.executor.run();
      try (LocalKeys.Use use = c.forDecrypt(old.id())) {
        assertEquals(old.id(), use.id());
      }
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(next.id(), use.id());
      }
      f.advance(9);
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(next.id(), use.id());
      }
    }
  }

  // Guards against: a KMIP General Failure (ServerFailureException, e.g. an HSM backend fault)
  // during a
  // refresh is treated as definite: valid copies are destroyed and refused for a whole TTL.
  @Test
  void generalFailureDuringRefreshRetainsValidKeysUntilTtl() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use a = c.forEncrypt();
          LocalKeys.Use b = c.forDecrypt(key.id())) {}
      AtomicBoolean failing = new AtomicBoolean(true);
      f.after.set(
          (r, p) ->
              failing.get() && is(r, Operation.GET)
                  ? Faults.failure(r, Enums.ResultReason.GENERAL_FAILURE, "HSM backend unavailable")
                  : p);
      f.advance(5);
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      f.executor.run();
      try (LocalKeys.Use use = c.forDecrypt(key.id());
          LocalKeys.Use write = c.forEncrypt()) {
        assertEquals(key.id(), use.id());
        assertEquals(key.id(), write.id());
      }
      f.advance(5);
      assertThrows(KmsException.class, () -> c.forDecrypt(key.id()));
      assertTrue(c.currentWriteId().isEmpty());
      failing.set(false);
      f.advance(1);
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
    }
  }

  // Guards against: the same for a General Failure on Locate during a write refresh.
  @Test
  void generalFailureOnLocateRetainsTheValidWriteKey() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use a = c.forEncrypt()) {}
      f.after.set(
          (r, p) ->
              is(r, Operation.LOCATE)
                  ? Faults.failure(r, Enums.ResultReason.GENERAL_FAILURE, "index offline")
                  : p);
      f.advance(5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.executor.run();
      assertTrue(c.currentWriteId().isPresent());
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.advance(5);
      assertThrows(ServerFailureException.class, c::forEncrypt);
    }
  }

  // The cold write flight's loading ID is matched by a concurrent historical Compromised
  // observation, which must supersede the flight. Uses a real server-side compromise.
  @Test
  void holdsColdWriteFlightIsSupersededByConcurrentCompromiseObservation() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      CountDownLatch[] g = gate();
      AtomicBoolean first = new AtomicBoolean(true);
      f.before.set(
          r -> {
            if (is(r, Operation.GET) && first.compareAndSet(true, false)) {
              g[0].countDown();
              await(g[1]);
            }
          });
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        Future<LocalKeys.Use> write = pool.submit(() -> c.forEncrypt());
        await(g[0]);
        key.revoke(RevocationReason.keyCompromise("probe", Instant.now()));
        assertThrows(StateConflictException.class, () -> c.forDecrypt(key.id()));
        g[1].countDown();
        ExecutionException e =
            assertThrows(ExecutionException.class, () -> write.get(2, TimeUnit.SECONDS));
        assertInstanceOf(KmsException.class, e.getCause());
        assertTrue(c.currentWriteId().isEmpty());
      } finally {
        g[1].countDown();
        pool.shutdownNow();
      }
    }
  }

  // Guards against: invalidate(unrelated) while a write refresh is queued destroys the valid write
  // copy and
  // forgets the warm selection, so a tolerated ambiguity becomes a TTL-long write refusal.
  @Test
  void invalidatingAnUnrelatedIdPreservesTheWarmSelection() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle first = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(first.id(), use.id());
      }
      f.key(); // a second Active key with the name: warm selection tolerates it
      LocalKeys control = f.cache();
      try (LocalKeys.Use ignored = control.forDecrypt(first.id())) {}
      f.advance(5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {} // queues the write refresh
      assertEquals(1, f.executor.queue.size());
      c.invalidate("some-unrelated-historical-id");
      assertEquals(first.id(), c.currentWriteId().orElseThrow());
      f.executor.run();
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(first.id(), use.id());
      }
    }
  }

  // Guards against: a refresh executor that silently drops work (DiscardPolicy, dead pool) wedges
  // an expired
  // slot until invalidation: expired callers wait for the queued flight, never load themselves.
  @Test
  void expiredCallTakesOverADiscardedRefresh() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys.Builder b =
          f.client
              .withTimeout(Duration.ofMillis(100))
              .keys()
              .localKeys(NAME)
              .scope(KeyQuery.all().custom(FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(TTL)
              .refreshExecutor(task -> {}); // accepted, never run
      b.ticker = f.time::get;
      LocalKeys c = f.keep(b.open());
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      f.advance(5);
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      for (int i = 0; i < 3; i++) {
        f.advance(1000);
        try (LocalKeys.Use use = c.forDecrypt(key.id())) {
          assertEquals(key.id(), use.id());
        }
      }
    }
  }

  // Guards against: an Error escaping a loader leaves its flight pending forever (catch
  // RuntimeException).
  @Test
  void anErrorInRefreshLeavesNoOrphanedFlight() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys.Builder b =
          f.client
              .withTimeout(Duration.ofMillis(100))
              .keys()
              .localKeys(NAME)
              .scope(KeyQuery.all().custom(FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(TTL)
              .refreshExecutor(f.executor);
      b.ticker = f.time::get;
      LocalKeys c = f.keep(b.open());
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      AtomicBoolean once = new AtomicBoolean(true);
      f.before.set(
          r -> {
            if (is(r, Operation.GET) && once.compareAndSet(true, false))
              throw new StackOverflowError("probe");
          });
      f.advance(5);
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      assertThrows(StackOverflowError.class, f.executor::run);
      f.advance(1000);
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
    }
  }

  // Guards against: an explicit ID-set scope is accepted, but the write selector always fails
  // because
  // Locate refuses queries with identifiers.
  @Test
  void idSetScopeSelectsOnlyListedWriteKeys() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys.Builder b =
          f.client
              .keys()
              .localKeys(NAME)
              .scope(KeyQuery.all().ids(List.of(key.id())))
              .expect(Expect.aes(256))
              .ttl(TTL)
              .refreshExecutor(f.executor);
      b.ticker = f.time::get;
      LocalKeys c = f.keep(b.open());
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(key.id(), use.id());
      }
    }
  }

  // Guards against: a refusal decided before invalidate() but delivered after it poisons the new,
  // successful
  // validation for a TTL (fail-safe direction).
  @Test
  void aSupersededRefusalCannotPoisonTheFreshEntry() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      CountDownLatch[] g = gate();
      AtomicInteger gets = new AtomicInteger();
      f.after.set(
          (r, p) -> {
            if (is(r, Operation.GET) && gets.incrementAndGet() == 1) {
              g[0].countDown();
              await(g[1]);
              throw new PermissionDeniedException("answered before the operator re-granted access");
            }
            return p;
          });
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        Future<LocalKeys.Use> stale = pool.submit(() -> c.forDecrypt(key.id()));
        await(g[0]);
        c.invalidate(key.id()); // operator re-granted and invalidated
        try (LocalKeys.Use use = c.forDecrypt(key.id())) {
          assertEquals(key.id(), use.id());
        }
        g[1].countDown();
        assertThrows(ExecutionException.class, () -> stale.get(2, TimeUnit.SECONDS));
        try (LocalKeys.Use use = c.forDecrypt(key.id())) {
          assertEquals(key.id(), use.id());
        }
      } finally {
        g[1].countDown();
        pool.shutdownNow();
      }
    }
  }

  // Guards against: invalidation during a caller's own cold load fails that call instead of
  // retrying.
  @Test
  void observedInvalidationDuringColdLoadFailsTheLoadingCaller() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      CountDownLatch[] g = gate();
      AtomicBoolean first = new AtomicBoolean(true);
      f.before.set(
          r -> {
            if (is(r, Operation.GET) && first.compareAndSet(true, false)) {
              g[0].countDown();
              await(g[1]);
            }
          });
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        Future<LocalKeys.Use> load = pool.submit(() -> c.forDecrypt(key.id()));
        await(g[0]);
        c.invalidateAll();
        g[1].countDown();
        ExecutionException e =
            assertThrows(ExecutionException.class, () -> load.get(2, TimeUnit.SECONDS));
        assertInstanceOf(TransientException.class, e.getCause());
      } finally {
        g[1].countDown();
        pool.shutdownNow();
      }
    }
  }

  // Guards against: an Error during lazy negotiation leaves `connecting` set; invalidateAll cannot
  // recover.
  @Test
  void anErrorDuringLazyNegotiationLeavesNoOrphanedFlight() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeysStartupTest.Connections connections = new LocalKeysStartupTest.Connections();
      AtomicBoolean once = new AtomicBoolean(true);
      connections.before =
          (r, ctx) -> {
            if (is(r, Operation.DISCOVER_VERSIONS) && once.compareAndSet(true, false))
              throw new StackOverflowError("probe");
          };
      LocalKeys c = LocalKeysStartupTest.cache(f, connections.config(f, Duration.ofMillis(200)));
      assertThrows(StackOverflowError.class, c::forEncrypt);
      c.invalidateAll();
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
      assertEquals(2, connections.opened.get());
      c.close();
    }
  }

  // Holds: identifiers and material always come from one snapshot, and match the server, under
  // concurrent use, rotation, invalidation, eviction and clock movement. No deadlock.
  @Test
  void holdsSnapshotConsistencyAndNoDeadlockUnderConcurrentChurn() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      List<KeyHandle> keys = new ArrayList<>();
      for (int i = 0; i < 6; i++)
        keys.add(f.key(256, "orders", i == 0 ? NAME : null, KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
      Map<String, byte[]> material = new ConcurrentHashMap<>();
      for (KeyHandle k : keys)
        try (DestroyableSecretKey s =
            f.admin.keys().handle(k.id()).asSecretKey(Expect.aes(256), LocalUse.DECRYPT)) {
          material.put(k.id(), s.getEncoded());
        }
      ThreadPoolExecutor refresh =
          new ThreadPoolExecutor(2, 2, 1, TimeUnit.SECONDS, new ArrayBlockingQueue<>(64));
      LocalKeys.Builder b =
          f.client
              .keys()
              .localKeys(NAME)
              .scope(KeyQuery.all().custom(FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(Duration.ofMillis(40))
              .refreshAfter(Duration.ofMillis(10))
              .capacity(4)
              .refreshExecutor(refresh);
      LocalKeys c = f.keep(b.open());
      AtomicBoolean stop = new AtomicBoolean();
      List<Throwable> unexpected = new CopyOnWriteArrayList<>();
      AtomicInteger uses = new AtomicInteger();
      ExecutorService pool = Executors.newFixedThreadPool(8);
      List<Future<?>> workers = new ArrayList<>();
      for (int t = 0; t < 8; t++) {
        int seed = t;
        workers.add(
            pool.submit(
                () -> {
                  Random random = new Random(seed);
                  while (!stop.get()) {
                    try {
                      int op = random.nextInt(20);
                      if (op == 0) c.invalidateAll();
                      else if (op == 1) c.invalidate(keys.get(random.nextInt(keys.size())).id());
                      else {
                        try (LocalKeys.Use use =
                            op < 8
                                ? c.forEncrypt()
                                : c.forDecrypt(keys.get(random.nextInt(keys.size())).id())) {
                          if (!Arrays.equals(material.get(use.id()), use.key().getEncoded()))
                            unexpected.add(
                                new AssertionError("material does not belong to " + use.id()));
                          uses.incrementAndGet();
                        }
                      }
                    } catch (KmsException expected) {
                      // Transient races (evicted, invalidated, capacity) are permitted outcomes.
                    } catch (Throwable e) {
                      unexpected.add(e);
                    }
                  }
                }));
      }
      Thread rotator =
          new Thread(
              () -> {
                Random random = new Random(42);
                int current = 0;
                while (!stop.get()) {
                  int next = 1 + random.nextInt(keys.size() - 1);
                  if (next == current) continue;
                  keys.get(next).addName(NAME);
                  keys.get(current).removeName(NAME);
                  current = next;
                  try {
                    Thread.sleep(15);
                  } catch (InterruptedException e) {
                    return;
                  }
                }
              });
      rotator.start();
      Thread.sleep(1500);
      stop.set(true);
      rotator.join(2000);
      for (Future<?> w : workers) w.get(5, TimeUnit.SECONDS); // a lock cycle would time out here
      pool.shutdownNow();
      refresh.shutdownNow();
      assertTrue(unexpected.isEmpty(), () -> unexpected.toString());
      assertTrue(uses.get() > 100, "made progress: " + uses.get());
    }
  }
}
