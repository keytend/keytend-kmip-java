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

import static dev.keytend.kmip.kms.LocalKeysLoadScheduleTest.await;
import static dev.keytend.kmip.kms.LocalKeysLoadScheduleTest.awaitWaiters;
import static dev.keytend.kmip.kms.LocalKeysTest.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.Operation;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Capacity pressure with a healthy KMS: calls wait for capacity within their one original deadline
 * instead of failing on internal races; reservations keep a slot from being evicted under its
 * caller; explicit invalidation, close and refusals still reach the calls they affect, and another
 * ID's outcome is only a wake-up.
 */
class LocalKeysPressureTest {
  /** Gates every Get of {@code id} until released, optionally then failing it. */
  static final class Gate {
    final CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
    final AtomicInteger gets = new AtomicInteger();
    volatile RuntimeException then;

    Gate(Fixture f, String id) {
      f.before.set(
          r -> {
            if (is(r, Operation.GET) && id.equals(id(r))) {
              gets.incrementAndGet();
              entered.countDown();
              await(release);
              RuntimeException failure = then;
              if (failure != null) throw failure;
            }
          });
    }
  }

  private static Callable<String> decrypt(LocalKeys c, String id) {
    return () -> {
      try (LocalKeys.Use u = c.forDecrypt(id)) {
        return u.id();
      }
    };
  }

  private static Throwable failure(Future<?> task) throws Exception {
    ExecutionException e =
        assertThrows(ExecutionException.class, () -> task.get(5, TimeUnit.SECONDS));
    return e.getCause();
  }

  @Test
  void aCachedSlotWhoseExpiredCallerIsAboutToLoadIsNotEvicted() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key(), b = f.key();
      CountDownLatch pinned = new CountDownLatch(1), release = new CountDownLatch(1);
      AtomicReference<Thread> loader = new AtomicReference<>();
      LocalKeys.Builder builder = f.builder().capacity(2);
      builder.ticker =
          () -> {
            // The access sweep's tick: after the reservation, before the flight is installed.
            Thread self = Thread.currentThread();
            if (self == loader.get() && loader.compareAndSet(self, null)) {
              pinned.countDown();
              await(release);
            }
            return f.time.get();
          };
      LocalKeys c = f.keep(builder.open());
      try (LocalKeys.Use ignored = c.forDecrypt(a.id())) {}
      f.advance(11); // A's entry expired; its idle slot is the oldest.
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<String> first =
            pool.submit(
                () -> {
                  loader.set(Thread.currentThread());
                  return decrypt(c, a.id()).call();
                });
        await(pinned);
        Future<String> second = pool.submit(decrypt(c, b.id()));
        awaitWaiters(c, 1);
        release.countDown();
        assertEquals(a.id(), first.get(5, TimeUnit.SECONDS));
        assertEquals(b.id(), second.get(5, TimeUnit.SECONDS));
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void anUnrelatedDeniedFlightWakesTheWaiterWithoutBecomingItsResult() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key(), b = f.key();
      LocalKeys c = f.keep(f.builder().capacity(2).open());
      Gate gate = new Gate(f, a.id());
      gate.then = new PermissionDeniedException("Get permission removed for A");
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<String> first = pool.submit(decrypt(c, a.id()));
        await(gate.entered);
        Future<String> second = pool.submit(decrypt(c, b.id()));
        awaitWaiters(c, 1);
        gate.release.countDown();
        assertInstanceOf(PermissionDeniedException.class, failure(first));
        assertEquals(b.id(), second.get(5, TimeUnit.SECONDS));
        // A's refusal stays A's: evicted for B, its next use validates again and is refused again.
        assertThrows(PermissionDeniedException.class, () -> c.forDecrypt(a.id()));
        assertEquals(2, gate.gets.get());
      } finally {
        gate.release.countDown();
        pool.shutdownNow();
      }
    }
  }

  enum Explicit {
    ID,
    ALL
  }

  @ParameterizedTest
  @EnumSource(Explicit.class)
  void invalidatingTheLoadingIdFailsItsCallAndReleasesCapacityToTheWaiter(Explicit action)
      throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key(), b = f.key();
      LocalKeys c = f.keep(f.builder().capacity(2).open());
      Gate gate = new Gate(f, a.id());
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<String> first = pool.submit(decrypt(c, a.id()));
        await(gate.entered);
        Future<String> second = pool.submit(decrypt(c, b.id()));
        awaitWaiters(c, 1);
        if (action == Explicit.ID) c.invalidate(a.id());
        else c.invalidateAll();
        // All-cache invalidation cancels the waiter; an unrelated ID only releases capacity.
        if (action == Explicit.ALL) assertInstanceOf(TransientException.class, failure(second));
        else assertEquals(b.id(), second.get(5, TimeUnit.SECONDS));
        gate.release.countDown();
        // The displaced call is told, and is not silently turned into a new load.
        Throwable displaced = failure(first);
        assertInstanceOf(TransientException.class, displaced);
        assertTrue(displaced.getMessage().contains("invalidated"), displaced.toString());
        assertEquals(1, gate.gets.get());
      } finally {
        gate.release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void closeEndsACapacityWaitPromptly() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key(), b = f.key();
      LocalKeys c = f.keep(f.builder().capacity(2).open());
      Gate gate = new Gate(f, a.id());
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<String> first = pool.submit(decrypt(c, a.id()));
        await(gate.entered);
        Future<String> second = pool.submit(decrypt(c, b.id()));
        awaitWaiters(c, 1);
        long closing = System.nanoTime();
        c.close();
        assertInstanceOf(IllegalStateException.class, failure(second));
        assertTrue(
            System.nanoTime() - closing < TimeUnit.MILLISECONDS.toNanos(1500),
            "woken, not timed out");
        gate.release.countDown();
        assertInstanceOf(IllegalStateException.class, failure(first));
        assertEquals(0, c.historicalSlots());
      } finally {
        gate.release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void anInterruptedCapacityWaitFailsAndKeepsTheInterrupt() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key(), b = f.key();
      LocalKeys c = f.keep(f.builder().capacity(2).open());
      Gate gate = new Gate(f, a.id());
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<String> first = pool.submit(decrypt(c, a.id()));
        await(gate.entered);
        AtomicReference<Thread> waiter = new AtomicReference<>();
        AtomicBoolean stillInterrupted = new AtomicBoolean();
        Future<String> second =
            pool.submit(
                () -> {
                  waiter.set(Thread.currentThread());
                  try {
                    return decrypt(c, b.id()).call();
                  } finally {
                    stillInterrupted.set(Thread.interrupted());
                  }
                });
        awaitWaiters(c, 1);
        waiter.get().interrupt();
        Throwable interrupted = failure(second);
        assertInstanceOf(TransientException.class, interrupted);
        assertInstanceOf(InterruptedIOException.class, interrupted.getCause());
        assertTrue(stillInterrupted.get());
        assertEquals(0, c.capacityWaiters());
        gate.release.countDown();
        assertEquals(a.id(), first.get(5, TimeUnit.SECONDS));
      } finally {
        gate.release.countDown();
        pool.shutdownNow();
      }
    }
  }

  private static LocalKeys.Builder timed(Fixture f, Duration timeout) {
    LocalKeys.Builder b =
        f.client
            .withTimeout(timeout)
            .keys()
            .localKeys(NAME)
            .scope(dev.keytend.kmip.kms.KeyQuery.all().custom(FAMILY, "orders"))
            .expect(Expect.aes(256))
            .ttl(TTL)
            .refreshExecutor(f.executor)
            .capacity(2);
    b.ticker = f.time::get;
    return b;
  }

  @Test
  void aCapacityWaitEndsAtTheCallDeadline() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key(), b = f.key();
      LocalKeys c = f.keep(timed(f, Duration.ofMillis(800)).open());
      Gate gate = new Gate(f, a.id());
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<String> first = pool.submit(decrypt(c, a.id()));
        await(gate.entered);
        long start = System.nanoTime();
        Throwable expired = assertThrows(TransientException.class, () -> c.forDecrypt(b.id()));
        long elapsed = System.nanoTime() - start;
        assertInstanceOf(SocketTimeoutException.class, expired.getCause());
        assertTrue(
            elapsed >= TimeUnit.MILLISECONDS.toNanos(790), "consumed its budget: " + elapsed);
        assertTrue(
            elapsed < TimeUnit.MILLISECONDS.toNanos(1600), "bounded by one budget: " + elapsed);
        assertEquals(0, c.capacityWaiters());
        gate.release.countDown();
        try {
          first.get(5, TimeUnit.SECONDS);
        } catch (ExecutionException ignored) {
        } // A's own budget also ran
      } finally {
        gate.release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void aLoadAfterACapacityWaitHasOnlyTheRemainingBudget() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key(), b = f.key();
      Duration budget = Duration.ofMillis(1500);
      LocalKeys c = f.keep(timed(f, budget).open());
      CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
      AtomicLong remainingAtB = new AtomicLong(-1);
      f.before.set(
          r -> {
            if (is(r, Operation.GET) && a.id().equals(id(r))) {
              entered.countDown();
              await(release);
            }
            // The scope's deadline as B's first load request sees it.
            if (b.id().equals(id(r)))
              remainingAtB.compareAndSet(-1, Kms.callRemaining(Duration.ofHours(1)));
          });
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<String> first = pool.submit(decrypt(c, a.id()));
        await(entered);
        Future<String> second = pool.submit(decrypt(c, b.id()));
        awaitWaiters(c, 1);
        Thread.sleep(700);
        release.countDown();
        assertEquals(a.id(), first.get(5, TimeUnit.SECONDS));
        assertEquals(b.id(), second.get(5, TimeUnit.SECONDS));
        long remaining = remainingAtB.get();
        assertTrue(
            remaining > 0 && remaining <= budget.minusMillis(700).toNanos(),
            "admission after waiting must not restart the deadline: "
                + Duration.ofNanos(remaining));
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void aWriteSeedNeverEvictsAReservedHistoricalSlot() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle w = f.key(), a = f.key(256, "orders", null, KeyUsage.DECRYPT);
      CountDownLatch pinned = new CountDownLatch(1), release = new CountDownLatch(1);
      AtomicReference<Thread> loader = new AtomicReference<>();
      AtomicInteger ticks = new AtomicInteger();
      LocalKeys.Builder builder = f.builder().capacity(2);
      builder.ticker =
          () -> {
            if (Thread.currentThread() == loader.get() && ticks.incrementAndGet() == 3) {
              pinned.countDown();
              await(release);
            }
            return f.time.get();
          };
      LocalKeys c = f.keep(builder.open());
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        Future<String> first =
            pool.submit(
                () -> {
                  loader.set(Thread.currentThread());
                  return decrypt(c, a.id()).call();
                });
        await(pinned);
        try (LocalKeys.Use use = c.forEncrypt()) {
          assertEquals(w.id(), use.id());
        } // seed skipped, write succeeds
        release.countDown();
        assertEquals(a.id(), first.get(5, TimeUnit.SECONDS));
        AtomicInteger gets = new AtomicInteger();
        f.before.set(
            r -> {
              if (is(r, Operation.GET)) gets.incrementAndGet();
            });
        try (LocalKeys.Use use = c.forDecrypt(w.id())) {
          assertEquals(w.id(), use.id());
        }
        assertEquals(
            1, gets.get(), "the write's Decrypt copy was not seeded over the reserved slot");
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void healthyChurnBelowTheWorkingSetNeverFailsOnInternalRaces() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      List<String> ids = new ArrayList<>();
      for (int i = 0; i < 8; i++) ids.add(f.key(256, "orders", null, KeyUsage.DECRYPT).id());
      LocalKeys c = f.keep(f.builder().capacity(3).open()); // two historical slots, eight IDs
      long budget = TimeUnit.SECONDS.toNanos(2); // the fixture's call timeout
      int threads = 6, rounds = 150;
      ExecutorService pool = Executors.newFixedThreadPool(threads);
      List<Throwable> unexpected = new CopyOnWriteArrayList<>();
      AtomicInteger succeeded = new AtomicInteger(),
          deadlines = new AtomicInteger(),
          maxSlots = new AtomicInteger();
      try {
        List<Future<?>> tasks = new ArrayList<>();
        for (int t = 0; t < threads; t++) {
          int seed = t;
          tasks.add(
              pool.submit(
                  () -> {
                    Random random = new Random(seed);
                    for (int i = 0; i < rounds; i++) {
                      String id = ids.get(random.nextInt(ids.size()));
                      long start = System.nanoTime();
                      try (LocalKeys.Use u = c.forDecrypt(id)) {
                        assertEquals(id, u.id());
                        succeeded.incrementAndGet();
                      } catch (TransientException e) {
                        // Only an exhausted budget is a permitted outcome, never an immediate race.
                        if (e.getCause() instanceof SocketTimeoutException
                            && System.nanoTime() - start >= budget) deadlines.incrementAndGet();
                        else unexpected.add(e);
                      } catch (Throwable e) {
                        unexpected.add(e);
                      }
                      maxSlots.accumulateAndGet(c.historicalSlots(), Math::max);
                    }
                  }));
        }
        for (Future<?> task : tasks) task.get(120, TimeUnit.SECONDS);
      } finally {
        pool.shutdownNow();
      }
      assertEquals(List.of(), unexpected);
      assertEquals(threads * rounds, succeeded.get() + deadlines.get());
      assertTrue(succeeded.get() > 0);
      assertTrue(maxSlots.get() <= 2, "retention stays within capacity: " + maxSlots.get());
      assertEquals(0, c.capacityWaiters());
      assertTrue(f.executor.queue.isEmpty());
    }
  }
}
