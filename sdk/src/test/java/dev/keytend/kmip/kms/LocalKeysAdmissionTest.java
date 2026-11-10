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
import java.util.Map;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Admission under capacity pressure: same-identifier groups, termination checks after pauses and
 * contention, and no tombstones for absent identifiers. Reflection only reads private state or
 * acquires real monitors; it never writes fields, tokens, pins, versions or cache entries.
 */
class LocalKeysAdmissionTest {
  private static Object field(Object owner, String name) throws Exception {
    var field = owner.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field.get(owner);
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> groups(LocalKeys cache) throws Exception {
    synchronized (field(cache, "admissionLock")) {
      return Map.copyOf((Map<String, Object>) field(cache, "admissions"));
    }
  }

  private static int callers(LocalKeys cache, Object group) throws Exception {
    synchronized (field(cache, "admissionLock")) {
      return (int) field(group, "callers");
    }
  }

  private static String use(LocalKeys cache, String id, boolean write) {
    try (LocalKeys.Use use = write ? cache.forEncrypt() : cache.forDecrypt(id)) {
      return use.id();
    }
  }

  private static Throwable failure(Future<?> task) {
    return assertThrows(ExecutionException.class, () -> task.get(5, TimeUnit.SECONDS)).getCause();
  }

  /** Whether the calling thread is inside {@code LocalKeys.method}. */
  static boolean calledFrom(String method) {
    return StackWalker.getInstance()
        .walk(
            frames ->
                frames.anyMatch(
                    frame ->
                        frame.getClassName().equals(LocalKeys.class.getName())
                            && frame.getMethodName().equals(method)));
  }

  /** Waits for {@code latch} without consuming an interrupt, which stays set for the caller. */
  static void awaitKeepingInterrupt(CountDownLatch latch) {
    boolean interrupted = false;
    try {
      for (; ; ) {
        try {
          assertTrue(latch.await(5, TimeUnit.SECONDS), "probe gate timed out");
          return;
        } catch (InterruptedException e) {
          interrupted = true;
        }
      }
    } finally {
      if (interrupted) Thread.currentThread().interrupt();
    }
  }

  private static void blockedIn(Thread thread, String method) throws Exception {
    long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    for (; ; ) {
      if (thread.getState() == Thread.State.BLOCKED) {
        for (StackTraceElement frame : thread.getStackTrace()) {
          if (frame.getClassName().equals(LocalKeys.class.getName())
              && frame.getMethodName().equals(method)) return;
        }
      }
      assertTrue(System.nanoTime() < until, "call did not contend in LocalKeys." + method);
      Thread.sleep(1);
    }
  }

  enum Invalidation {
    ID,
    ALL
  }

  @ParameterizedTest
  @EnumSource(Invalidation.class)
  void lastOldCallerCannotRemoveTheNewSameIdGroup(Invalidation invalidation) throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key(), b = f.key();
      ConcurrentMap<Thread, CountDownLatch> pauses = new ConcurrentHashMap<>();
      CountDownLatch paused = new CountDownLatch(2);
      CountDownLatch releaseOne = new CountDownLatch(1), releaseTwo = new CountDownLatch(1);
      LocalKeys.Builder builder = f.builder().capacity(2);
      // A hit takes no admission, so the old calls find B expired and pause once admitted.
      builder.ticker =
          () -> {
            CountDownLatch release =
                calledFrom("access") ? pauses.remove(Thread.currentThread()) : null;
            if (release != null) {
              paused.countDown();
              await(release);
            }
            return f.time.get();
          };
      LocalKeys cache = f.keep(builder.open());
      assertEquals(b.id(), use(cache, b.id(), false));
      f.advance(11); // Past B's TTL.
      LocalKeysPressureTest.Gate gate = new LocalKeysPressureTest.Gate(f, a.id());
      AtomicInteger bGets = new AtomicInteger();
      var previous = f.before.get();
      f.before.set(
          request -> {
            previous.accept(request);
            if (is(request, Operation.GET) && b.id().equals(id(request))) bGets.incrementAndGet();
          });
      ExecutorService pool = Executors.newFixedThreadPool(5);
      try {
        Future<String> oldOne =
            pool.submit(
                () -> {
                  pauses.put(Thread.currentThread(), releaseOne);
                  return use(cache, b.id(), false);
                });
        Future<String> oldTwo =
            pool.submit(
                () -> {
                  pauses.put(Thread.currentThread(), releaseTwo);
                  return use(cache, b.id(), false);
                });
        await(paused); // Both calls have registered and pinned B, before any entry lock.
        Object oldGroup = groups(cache).get(b.id());
        assertEquals(2, callers(cache, oldGroup));
        if (invalidation == Invalidation.ID) cache.invalidate(b.id());
        else cache.invalidateAll();
        assertEquals(true, field(oldGroup, "invalidated"));
        assertTrue(groups(cache).isEmpty());

        Future<String> occupant = pool.submit(() -> use(cache, a.id(), false));
        await(gate.entered);
        Future<String> newOne = pool.submit(() -> use(cache, b.id(), false));
        Future<String> newTwo = pool.submit(() -> use(cache, b.id(), false));
        awaitWaiters(cache, 2);
        Object newGroup = groups(cache).get(b.id());
        assertNotSame(oldGroup, newGroup);
        assertEquals(2, callers(cache, newGroup));
        assertEquals(false, field(newGroup, "invalidated"));

        releaseOne.countDown();
        assertInstanceOf(TransientException.class, failure(oldOne));
        assertEquals(1, callers(cache, oldGroup));
        assertSame(newGroup, groups(cache).get(b.id()));
        releaseTwo.countDown();
        assertInstanceOf(TransientException.class, failure(oldTwo));
        assertEquals(0, callers(cache, oldGroup));
        assertSame(
            newGroup, groups(cache).get(b.id()), "last old cleanup must compare token identity");
        assertEquals(0, bGets.get(), "neither invalidated caller may silently load again");

        cache.invalidate(b.id()); // Proves the new group is still discoverable by invalidation.
        assertInstanceOf(TransientException.class, failure(newOne));
        assertInstanceOf(TransientException.class, failure(newTwo));
        assertEquals(0, callers(cache, newGroup));
        assertEquals(0, bGets.get());
        assertEquals(0, cache.capacityWaiters());
        assertEquals(1, groups(cache).size(), "only unrelated A is still active");
        gate.release.countDown();
        assertEquals(a.id(), occupant.get(5, TimeUnit.SECONDS), "B invalidation must not cancel A");
        assertTrue(groups(cache).isEmpty());
        assertEquals(
            b.id(), use(cache, b.id(), false), "a later application call can load normally");
        assertEquals(1, bGets.get());
        assertTrue(groups(cache).isEmpty());
        assertEquals(1, cache.historicalSlots());
      } finally {
        releaseOne.countDown();
        releaseTwo.countDown();
        gate.release.countDown();
        pool.shutdownNow();
      }
    }
  }

  enum Contention {
    READ_DEADLINE,
    WRITE_DEADLINE,
    READ_INTERRUPT,
    WRITE_INTERRUPT
  }

  @ParameterizedTest
  @EnumSource(Contention.class)
  void warmHandoutChecksTerminationAfterAPauseInsideTheCopy(Contention contention)
      throws Exception {
    boolean write =
        contention == Contention.WRITE_DEADLINE || contention == Contention.WRITE_INTERRUPT;
    boolean interrupt =
        contention == Contention.READ_INTERRUPT || contention == Contention.WRITE_INTERRUPT;
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      AtomicReference<Thread> paused = new AtomicReference<>();
      CountDownLatch inCopy = new CountDownLatch(1), release = new CountDownLatch(1);
      LocalKeys.Builder builder = f.builder();
      // A hit takes no entry lock, so there is no monitor to contend on. The pause is
      // the copy's own validity tick: after the key was copied, before the handout.
      builder.ticker =
          () -> {
            Thread current = Thread.currentThread();
            if (current == paused.get()
                && calledFrom("copy")
                && paused.compareAndSet(current, null)) {
              inCopy.countDown();
              awaitKeepingInterrupt(release);
            }
            return f.time.get();
          };
      LocalKeys cache = f.keep(builder.open());
      assertEquals(key.id(), use(cache, key.id(), write));
      int exchanges = f.server.exchanges();
      ExecutorService pool = Executors.newSingleThreadExecutor();
      AtomicReference<Thread> caller = new AtomicReference<>();
      AtomicBoolean keptInterrupt = new AtomicBoolean();
      AtomicLong deadline = new AtomicLong();
      Duration budget = Duration.ofMillis(500);
      try {
        Future<String> task =
            pool.submit(
                () -> {
                  try {
                    return Kms.call(
                        budget,
                        "localKeys",
                        () -> {
                          caller.set(Thread.currentThread());
                          deadline.set(System.nanoTime() + Kms.callRemaining(budget));
                          paused.set(Thread.currentThread());
                          return use(cache, key.id(), write);
                        });
                  } finally {
                    keptInterrupt.set(Thread.interrupted());
                  }
                });
        await(inCopy);
        if (interrupt) caller.get().interrupt();
        else {
          Thread.sleep(550);
          assertTrue(System.nanoTime() - deadline.get() > 0, "original outer scope has expired");
        }
        release.countDown();
        Throwable stopped = failure(task);
        assertInstanceOf(TransientException.class, stopped);
        if (interrupt) assertInstanceOf(InterruptedIOException.class, stopped.getCause());
        else assertInstanceOf(SocketTimeoutException.class, stopped.getCause());
        assertEquals(interrupt, keptInterrupt.get());
        assertEquals(
            exchanges, f.server.exchanges(), "a warm call sends no request, even after contention");
        assertTrue(groups(cache).isEmpty());
        assertEquals(key.id(), use(cache, key.id(), write), "later call gets its own live scope");
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  enum Stop {
    DEADLINE,
    INTERRUPT
  }

  @ParameterizedTest
  @EnumSource(Stop.class)
  void coldAdmissionRechecksTerminationAfterMembershipContention(Stop stop) throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys cache = f.keep(f.builder().capacity(2).open());
      int exchanges = f.server.exchanges();
      ExecutorService pool = Executors.newSingleThreadExecutor();
      AtomicReference<Thread> caller = new AtomicReference<>();
      AtomicBoolean keptInterrupt = new AtomicBoolean();
      AtomicLong deadline = new AtomicLong();
      CountDownLatch started = new CountDownLatch(1);
      Duration budget = Duration.ofMillis(500);
      try {
        Future<String> task;
        synchronized (field(cache, "membership")) {
          task =
              pool.submit(
                  () -> {
                    try {
                      return Kms.call(
                          budget,
                          "localKeys",
                          () -> {
                            caller.set(Thread.currentThread());
                            deadline.set(System.nanoTime() + Kms.callRemaining(budget));
                            started.countDown();
                            return use(cache, key.id(), false);
                          });
                    } finally {
                      keptInterrupt.set(Thread.interrupted());
                    }
                  });
          await(started);
          blockedIn(caller.get(), "admit");
          assertEquals(1, groups(cache).size());
          if (stop == Stop.INTERRUPT) caller.get().interrupt();
          else {
            Thread.sleep(550);
            assertTrue(System.nanoTime() - deadline.get() > 0);
          }
        }
        Throwable stopped = failure(task);
        assertInstanceOf(TransientException.class, stopped);
        if (stop == Stop.INTERRUPT)
          assertInstanceOf(InterruptedIOException.class, stopped.getCause());
        else assertInstanceOf(SocketTimeoutException.class, stopped.getCause());
        assertEquals(stop == Stop.INTERRUPT, keptInterrupt.get());
        assertEquals(
            exchanges, f.server.exchanges(), "no request after resuming with a terminated scope");
        assertEquals(
            0, cache.historicalSlots(), "no admission after termination while taking membership");
        assertTrue(groups(cache).isEmpty());
      } finally {
        pool.shutdownNow();
      }
    }
  }

  @Test
  void closeClearsSharedAndDistinctActiveGroupsBeforeGatedLoaderCanFinish() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key(), b = f.key(), c = f.key();
      LocalKeys cache = f.keep(f.builder().capacity(2).open());
      LocalKeysPressureTest.Gate gate = new LocalKeysPressureTest.Gate(f, a.id());
      ExecutorService pool = Executors.newFixedThreadPool(4);
      try {
        Future<String> occupant = pool.submit(() -> use(cache, a.id(), false));
        await(gate.entered);
        Future<String> bOne = pool.submit(() -> use(cache, b.id(), false));
        Future<String> bTwo = pool.submit(() -> use(cache, b.id(), false));
        Future<String> cOne = pool.submit(() -> use(cache, c.id(), false));
        awaitWaiters(cache, 3);
        assertEquals(3, groups(cache).size(), "one group per active ID, not per call");
        assertEquals(2, callers(cache, groups(cache).get(b.id())));
        cache.close();
        assertTrue(
            groups(cache).isEmpty(), "close drops map retention while old loader remains gated");
        for (Future<?> waiter : new Future<?>[] {bOne, bTwo, cOne})
          assertInstanceOf(IllegalStateException.class, failure(waiter));
        assertEquals(0, cache.capacityWaiters());
        assertEquals(0, cache.historicalSlots());
        gate.release.countDown();
        assertInstanceOf(IllegalStateException.class, failure(occupant));
        assertEquals(1, gate.gets.get());
        assertTrue(groups(cache).isEmpty());
        assertThrows(IllegalStateException.class, () -> cache.forDecrypt(b.id()));
      } finally {
        gate.release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void completedCallsAndAbsentIdInvalidationsLeaveNoPerIdHistory() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      LocalKeys cache = f.keep(f.builder().capacity(3).open());
      for (int i = 0; i < 24; i++) {
        KeyHandle key = f.key();
        assertEquals(key.id(), use(cache, key.id(), false));
        assertTrue(groups(cache).isEmpty(), "success must release the group's map reference");
        assertTrue(cache.historicalSlots() <= 2);
        KeyHandle wrongScope = f.key(256, "another-family", null, KeyUsage.DECRYPT);
        assertThrows(KeyMismatchException.class, () -> cache.forDecrypt(wrongScope.id()));
        assertTrue(
            groups(cache).isEmpty(), "definite refusal must release the group's map reference");
        assertTrue(cache.historicalSlots() <= 2);
      }
      int exchanges = f.server.exchanges();
      for (int i = 0; i < 1000; i++) cache.invalidate("absent-id-" + i);
      assertTrue(
          groups(cache).isEmpty(), "invalidating arbitrary absent IDs creates no tombstones");
      assertEquals(exchanges, f.server.exchanges());
    }
  }
}
