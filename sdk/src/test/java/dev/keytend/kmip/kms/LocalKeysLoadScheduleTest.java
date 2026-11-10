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

import dev.keytend.kmip.model.Operation;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;

/**
 * Load schedules under capacity pressure with a healthy KMS: when every historical slot is
 * loading, another identifier waits and both succeed, and a published slot is reserved before its
 * first access. The queued-task and name-removal invariants hold. No KMS failure is injected.
 */
class LocalKeysLoadScheduleTest {
  static void await(CountDownLatch latch) {
    try {
      assertTrue(latch.await(5, TimeUnit.SECONDS), "probe gate timed out");
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AssertionError(e);
    }
  }

  /** Waits until {@code n} calls wait for capacity: the schedule really reached the wait. */
  static void awaitWaiters(LocalKeys c, int n) throws InterruptedException {
    long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (c.capacityWaiters() != n) {
      assertTrue(System.nanoTime() < end, "no capacity waiter");
      Thread.sleep(1);
    }
  }

  @Test
  void allHistoricalSlotsLoadingMakesAnotherIdWaitThenBothSucceed() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key(), b = f.key();
      LocalKeys c = f.keep(f.builder().capacity(2).open());
      CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
      f.before.set(
          r -> {
            if (is(r, Operation.GET) && a.id().equals(id(r))) {
              entered.countDown();
              await(release);
            }
          });
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<String> first =
            pool.submit(
                () -> {
                  try (LocalKeys.Use u = c.forDecrypt(a.id())) {
                    return u.id();
                  }
                });
        await(entered);
        Future<String> second =
            pool.submit(
                () -> {
                  try (LocalKeys.Use u = c.forDecrypt(b.id())) {
                    return u.id();
                  }
                });
        awaitWaiters(c, 1);
        assertFalse(second.isDone(), "waits instead of failing on internal pressure");
        release.countDown();
        assertEquals(a.id(), first.get(5, TimeUnit.SECONDS));
        assertEquals(b.id(), second.get(5, TimeUnit.SECONDS));
        assertEquals(0, c.capacityWaiters());
        assertEquals(1, c.historicalSlots());
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void aPublishedSlotIsReservedBeforeItsFirstAccess() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key(), b = f.key();
      CountDownLatch published = new CountDownLatch(1), release = new CountDownLatch(1);
      AtomicReference<Thread> loader = new AtomicReference<>();
      AtomicInteger ticks = new AtomicInteger();
      LocalKeys.Builder builder = f.builder().capacity(2);
      builder.ticker =
          () -> {
            // Ticks 1-2: admission sweep and slot insertion under membership. Tick 3: the access
            // sweep, outside every lock, before any flight exists.
            if (Thread.currentThread() == loader.get() && ticks.incrementAndGet() == 3) {
              published.countDown();
              await(release);
            }
            return f.time.get();
          };
      LocalKeys c = f.keep(builder.open());
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<String> first =
            pool.submit(
                () -> {
                  loader.set(Thread.currentThread());
                  try (LocalKeys.Use u = c.forDecrypt(a.id())) {
                    return u.id();
                  }
                });
        await(published);
        assertEquals(1, c.historicalSlots());
        Future<String> second =
            pool.submit(
                () -> {
                  try (LocalKeys.Use u = c.forDecrypt(b.id())) {
                    return u.id();
                  }
                });
        awaitWaiters(c, 1); // The reserved slot is not evicted from under its caller.
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
  void expiredUseSupersedesQueuedRefreshAndItsLateTaskCannotPoisonTheNewLoad() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      f.advance(5);
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      assertEquals(1, f.executor.queue.size());
      f.advance(5);
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
      int exchanges = f.server.exchanges();
      f.executor.run(); // obsolete flight exits before making requests
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
      assertEquals(exchanges, f.server.exchanges());
    }
  }

  @Test
  void nameRemovalIsADefiniteSelectionRefusalBeforeOriginalTtl() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle old = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      old.removeName(NAME);
      f.advance(5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {} // queues validation at half TTL
      f.executor.run();
      assertTrue(c.currentWriteId().isEmpty());
      assertThrows(NotFoundException.class, c::forEncrypt);
      assertEquals(KeyState.ACTIVE, old.attributes().state());
      try (LocalKeys.Use historical = c.forDecrypt(old.id())) {
        assertEquals(old.id(), historical.id());
      }
    }
  }
}
