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
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Capacity waiters: invalidation cancels them, churn cannot bypass admission checks, and warm copies keep their deadline. */
class LocalKeysCapacityWaitTest {
  private static String decrypt(LocalKeys cache, String id) {
    try (LocalKeys.Use use = cache.forDecrypt(id)) {
      return use.id();
    }
  }

  private static String encrypt(LocalKeys cache) {
    try (LocalKeys.Use use = cache.forEncrypt()) {
      return use.id();
    }
  }

  private static Throwable failure(Future<?> task) throws Exception {
    return assertThrows(ExecutionException.class, () -> task.get(5, TimeUnit.SECONDS)).getCause();
  }

  enum Invalidation {
    WAITING_ID,
    ALL,
    UNRELATED_OCCUPANT
  }

  @ParameterizedTest
  @EnumSource(Invalidation.class)
  void invalidationCancelsApplicableCapacityWaiters(Invalidation action) throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key(), b = f.key();
      LocalKeys cache = f.keep(f.builder().capacity(2).open());
      LocalKeysPressureTest.Gate gate = new LocalKeysPressureTest.Gate(f, a.id());
      AtomicInteger bGets = new AtomicInteger();
      var previous = f.before.get();
      f.before.set(
          request -> {
            previous.accept(request);
            if (is(request, Operation.GET) && b.id().equals(id(request))) bGets.incrementAndGet();
          });
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<String> occupant = pool.submit(() -> decrypt(cache, a.id()));
        await(gate.entered);
        Future<String> waiting = pool.submit(() -> decrypt(cache, b.id()));
        awaitWaiters(cache, 1);
        assertEquals(0, bGets.get(), "B has not loaded or acquired a slot");
        switch (action) {
          case WAITING_ID -> cache.invalidate(b.id());
          case ALL -> cache.invalidateAll();
          case UNRELATED_OCCUPANT -> cache.invalidate(a.id());
        }
        if (action == Invalidation.UNRELATED_OCCUPANT) {
          assertEquals(b.id(), waiting.get(5, TimeUnit.SECONDS));
          assertEquals(1, bGets.get());
        } else {
          assertInstanceOf(TransientException.class, failure(waiting));
          assertEquals(0, bGets.get(), "canceled waiter must send no Get");
        }
        gate.release.countDown();
        if (action == Invalidation.WAITING_ID)
          assertEquals(a.id(), occupant.get(5, TimeUnit.SECONDS));
        else assertInstanceOf(TransientException.class, failure(occupant));
        assertEquals(b.id(), decrypt(cache, b.id()), "a later application call may succeed");
        assertEquals(1, cache.historicalSlots());
        assertEquals(0, cache.capacityWaiters());
      } finally {
        gate.release.countDown();
        pool.shutdownNow();
      }
    }
  }

  enum Termination {
    DEADLINE,
    INTERRUPT
  }

  @ParameterizedTest
  @EnumSource(Termination.class)
  void progressChurnCannotBypassAdmissionTerminationChecks(Termination terminal) throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key(), b = f.key();
      AtomicReference<LocalKeys> cacheRef = new AtomicReference<>();
      AtomicReference<Thread> waiterThread = new AtomicReference<>();
      AtomicBoolean churn = new AtomicBoolean(true);
      ExecutorService hitPool = Executors.newSingleThreadExecutor();
      AtomicInteger afterTerminal = new AtomicInteger();
      Duration budget = Duration.ofMillis(200);
      LocalKeys.Builder builder =
          f.client
              .withTimeout(budget)
              .keys()
              .localKeys(NAME)
              .scope(KeyQuery.all().custom(FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(TTL)
              .capacity(2)
              .refreshExecutor(f.executor);
      builder.ticker =
          () -> {
            Thread current = Thread.currentThread();
            if (current == waiterThread.get() && churn.get()) {
              LocalKeys cache = cacheRef.get();
              if (cache.capacityWaiters() > 0) {
                // Interleave another thread's warm A use after B snapshots progressVersion, before
                // it waits. Its last unpin signals progress; A's running refresh prevents eviction.
                // The scheduling handshake must preserve B's interrupt rather than consume it.
                boolean interruptedBeforeHandshake = Thread.interrupted();
                try {
                  assertEquals(
                      a.id(),
                      hitPool.submit(() -> decrypt(cache, a.id())).get(5, TimeUnit.SECONDS));
                } catch (Exception e) {
                  throw new AssertionError("warm-hit scheduling handshake failed", e);
                } finally {
                  if (interruptedBeforeHandshake) current.interrupt();
                }
                if (terminal == Termination.INTERRUPT) current.interrupt();
                boolean ended =
                    terminal == Termination.INTERRUPT
                        ? current.isInterrupted()
                        : Kms.callRemaining(budget) <= 0;
                if (ended)
                  assertTrue(
                      afterTerminal.incrementAndGet() <= 2,
                      "admission must terminate despite repeated progress");
              }
            }
            return f.time.get();
          };
      LocalKeys cache = f.keep(builder.open());
      cacheRef.set(cache);
      assertEquals(a.id(), decrypt(cache, a.id()));
      LocalKeysPressureTest.Gate gate = new LocalKeysPressureTest.Gate(f, a.id());
      f.advance(5);
      assertEquals(a.id(), decrypt(cache, a.id())); // queue A's refresh, retaining its valid entry
      ExecutorService pool = Executors.newFixedThreadPool(2);
      AtomicBoolean interruptKept = new AtomicBoolean();
      try {
        Future<?> refresh = pool.submit(f.executor::run);
        await(gate.entered);
        int exchanges = f.server.exchanges();
        Future<String> waiting =
            pool.submit(
                () -> {
                  waiterThread.set(Thread.currentThread());
                  try {
                    return decrypt(cache, b.id());
                  } finally {
                    interruptKept.set(Thread.interrupted());
                  }
                });
        Throwable stopped = failure(waiting);
        assertTrue(afterTerminal.get() <= 2, "no progress loop after termination");
        assertEquals(
            exchanges, f.server.exchanges(), "progress interleavings send no KMS requests");
        assertEquals(1, cache.historicalSlots());
        churn.set(false);
        assertInstanceOf(TransientException.class, stopped);
        if (terminal == Termination.DEADLINE)
          assertInstanceOf(SocketTimeoutException.class, stopped.getCause());
        else assertInstanceOf(InterruptedIOException.class, stopped.getCause());
        assertEquals(terminal == Termination.INTERRUPT, interruptKept.get());
        gate.release.countDown();
        refresh.get(5, TimeUnit.SECONDS);
        assertEquals(0, cache.capacityWaiters());
      } finally {
        churn.set(false);
        gate.release.countDown();
        pool.shutdownNow();
        hitPool.shutdownNow();
      }
    }
  }

  @ParameterizedTest
  @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
  void warmCopyFailsWhenItsOriginalDeadlinePassesBeforeAccess(boolean write) throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key();
      AtomicReference<Thread> pausedThread = new AtomicReference<>();
      CountDownLatch admitted = new CountDownLatch(1), release = new CountDownLatch(1);
      AtomicLong remainingAfterPause = new AtomicLong(Long.MAX_VALUE);
      Duration budget = Duration.ofMillis(100);
      LocalKeys.Builder builder =
          f.client
              .withTimeout(budget)
              .keys()
              .localKeys(NAME)
              .scope(KeyQuery.all().custom(FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(TTL)
              .capacity(2)
              .refreshExecutor(f.executor);
      builder.ticker =
          () -> {
            Thread current = Thread.currentThread();
            // Existing A is admitted by pinning without reading the ticker. Pause the access sweep,
            // representing descheduling or a contended sweep lock, after the original scope began.
            if (current == pausedThread.get() && pausedThread.compareAndSet(current, null)) {
              admitted.countDown();
              await(release);
              remainingAfterPause.set(Kms.callRemaining(budget));
            }
            return f.time.get();
          };
      LocalKeys cache = f.keep(builder.open());
      assertEquals(a.id(), write ? encrypt(cache) : decrypt(cache, a.id()));
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        Future<String> call =
            pool.submit(
                () -> {
                  pausedThread.set(Thread.currentThread());
                  return write ? encrypt(cache) : decrypt(cache, a.id());
                });
        await(admitted);
        Thread.sleep(150);
        release.countDown();
        Throwable stopped = failure(call);
        assertInstanceOf(TransientException.class, stopped);
        assertInstanceOf(SocketTimeoutException.class, stopped.getCause());
        assertTrue(
            remainingAfterPause.get() < 0, "real original call budget had ended before copying");
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void nameWithdrawalStillRefusesWritesDuringHistoricalCapacityPressure() throws Exception {
    LocalKeysListenerTest.Recorder recorder = new LocalKeysListenerTest.Recorder();
    try (Fixture f = new Fixture(KmipVersion.V2_1, RetryPolicy.none(), recorder)) {
      KeyHandle write = f.key(), a = f.key(256, "orders", null, KeyUsage.DECRYPT);
      KeyHandle b = f.key(256, "orders", null, KeyUsage.DECRYPT);
      LocalKeys cache = f.keep(f.builder().capacity(2).open());
      assertEquals(write.id(), encrypt(cache));
      LocalKeysPressureTest.Gate gate = new LocalKeysPressureTest.Gate(f, a.id());
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<String> occupant = pool.submit(() -> decrypt(cache, a.id()));
        await(gate.entered);
        Future<String> waiting = pool.submit(() -> decrypt(cache, b.id()));
        awaitWaiters(cache, 1);
        write.removeName(NAME);
        f.advance(5);
        assertEquals(write.id(), encrypt(cache)); // valid until the refresh observes withdrawal
        f.executor.run();
        assertTrue(cache.currentWriteId().isEmpty());
        for (int i = 0; i < 4; i++) assertThrows(NotFoundException.class, cache::forEncrypt);
        assertEquals(
            1, recorder.failed.size(), "one real failed selector refresh, no per-hit reports");
        var failed = recorder.failed.get(0);
        assertNull(failed.keyId());
        assertEquals(LocalUse.ENCRYPT, failed.purpose());
        assertInstanceOf(NotFoundException.class, failed.failure());
        assertEquals(Duration.ZERO, failed.remaining());
        assertEquals(1, recorder.selected.size(), "only the first committed selection");
        gate.release.countDown();
        assertEquals(a.id(), occupant.get(5, TimeUnit.SECONDS));
        assertEquals(b.id(), waiting.get(5, TimeUnit.SECONDS));
        assertEquals(
            write.id(), decrypt(cache, write.id()), "exact-ID history survives name withdrawal");
        assertThrows(NotFoundException.class, cache::forEncrypt);
        assertEquals(1, cache.historicalSlots());
      } finally {
        gate.release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void concurrentCommittedSelectionsCanBeDeliveredInReverseOrderWithoutRestoringAnOldEntry()
      throws Exception {
    CountDownLatch firstCallback = new CountDownLatch(1), releaseFirst = new CountDownLatch(1);
    List<String> delivered = new CopyOnWriteArrayList<>();
    AtomicInteger callbacks = new AtomicInteger();
    KmsListener listener =
        new KmsListener() {
          @Override
          public void localKeySelected(String name, String previous, String selected) {
            // Schedule the first delivery late. Blocking is only test instrumentation, modeling a
            // descheduled callback thread; production consumers must obey the nonblocking contract.
            if (callbacks.incrementAndGet() == 1) {
              firstCallback.countDown();
              await(releaseFirst);
            }
            delivered.add(selected);
          }
        };
    try (Fixture f = new Fixture(KmipVersion.V2_1, RetryPolicy.none(), listener)) {
      KeyHandle a = f.key();
      LocalKeys cache = f.cache();
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        Future<String> first = pool.submit(() -> encrypt(cache));
        await(firstCallback);
        assertEquals(a.id(), cache.currentWriteId().orElseThrow(), "A really committed");
        a.removeName(NAME);
        KeyHandle b = f.key();
        cache.invalidateAll();
        assertEquals(b.id(), encrypt(cache));
        assertEquals(List.of(b.id()), delivered);
        releaseFirst.countDown();
        assertInstanceOf(
            TransientException.class,
            failure(first),
            "invalidation still reaches the original caller");
        assertEquals(List.of(b.id(), a.id()), delivered);
        assertEquals(
            b.id(),
            cache.currentWriteId().orElseThrow(),
            "diagnostic delivery changes no selection");
      } finally {
        releaseFirst.countDown();
        pool.shutdownNow();
      }
    }
  }
}
