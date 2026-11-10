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
import static dev.keytend.kmip.kms.LocalKeysTest.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.Operation;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.BiConsumer;
import org.junit.jupiter.api.Test;

/**
 * The cache mechanics {@link LocalKeys} documents, each pinned on its own: when material is wiped
 * (invalidation, eviction, expiry, replacement, close, a load that finishes after close), when
 * refresh work is queued and from which age, how long refusals and transient failures are
 * remembered, what takes capacity, and who owns the refresh thread.
 */
class LocalKeysSemanticsTest {
  /** Every copy the cache retains, by identifier: its own live bytes (Builder#retained). */
  static final class Retained implements BiConsumer<String, byte[]> {
    final List<Map.Entry<String, byte[]>> all = new CopyOnWriteArrayList<>();

    @Override
    public void accept(String id, byte[] key) {
      all.add(Map.entry(id, key));
    }

    static boolean wiped(byte[] key) {
      for (byte b : key) if (b != 0) return false;
      return true;
    }

    /** The copies retained for {@code id}, oldest first. */
    List<byte[]> of(String id) {
      return all.stream().filter(e -> e.getKey().equals(id)).map(Map.Entry::getValue).toList();
    }

    long live() {
      return all.stream().filter(e -> !wiped(e.getValue())).count();
    }
  }

  private static LocalKeys.Builder tracked(Fixture f, Retained retained) {
    LocalKeys.Builder b = f.builder();
    b.retained = retained;
    return b;
  }

  private static void use(LocalKeys c) {
    try (LocalKeys.Use ignored = c.forEncrypt()) {}
  }

  private static void use(LocalKeys c, String id) {
    try (LocalKeys.Use ignored = c.forDecrypt(id)) {}
  }

  private static KeyHandle history(Fixture f) {
    return f.key(256, "orders", null, KeyUsage.DECRYPT);
  }

  @Test
  void invalidationWipesEveryCopyOfTheIdAtOnceAndCloseWipesTheRest() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle w = f.key(), h = history(f);
      Retained r = new Retained();
      LocalKeys c = f.keep(tracked(f, r).open());
      LocalKeys.Use handed = c.forEncrypt(); // The write copy and its seeded decryption copy.
      use(c, h.id());
      assertEquals(2, r.of(w.id()).size(), "the write copy and the seeded read copy");
      assertEquals(1, r.of(h.id()).size());
      assertEquals(3, r.live());
      c.invalidate(w.id());
      assertTrue(
          r.of(w.id()).stream().allMatch(Retained::wiped), "wiped before invalidate returns");
      assertFalse(Retained.wiped(r.of(h.id()).get(0)), "another identifier's copy is kept");
      assertFalse(handed.key().isDestroyed(), "a copy handed out stays the caller's");
      c.close();
      assertEquals(0, r.live(), "close wipes every retained copy, expired or not");
      assertFalse(handed.key().isDestroyed());
      handed.close();
    }
  }

  @Test
  void capacityEvictionWipesTheVictimBeforeTheNewEntryIsHandedOut() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = history(f), b = history(f);
      Retained r = new Retained();
      LocalKeys c = f.keep(tracked(f, r).capacity(2).open()); // One historical entry.
      use(c, a.id());
      try (LocalKeys.Use use = c.forDecrypt(b.id())) {
        assertTrue(Retained.wiped(r.of(a.id()).get(0)), "the evicted copy is already wiped");
        assertFalse(Retained.wiped(r.of(b.id()).get(0)));
        assertEquals(b.id(), use.id());
      }
      assertEquals(1, c.historicalSlots(), "nothing beyond capacity is retained");
    }
  }

  @Test
  void anExpiredCopyIsNeverHandedOutAndIsWipedAtTheNextAccess() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = history(f);
      Retained r = new Retained();
      LocalKeys c = f.keep(tracked(f, r).open());
      use(c, a.id());
      f.server.unreachable(true);
      f.advance(TTL.toSeconds());
      assertFalse(Retained.wiped(r.of(a.id()).get(0)), "wiped lazily, not by a timer");
      assertThrows(TransientException.class, () -> c.forDecrypt(a.id()));
      assertTrue(Retained.wiped(r.of(a.id()).get(0)));
      assertEquals(1, r.all.size(), "the failed load retained nothing");
    }
  }

  @Test
  void aRefreshWipesTheCopyItReplaces() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = history(f);
      Retained r = new Retained();
      LocalKeys c = f.keep(tracked(f, r).open());
      use(c, a.id());
      f.advance(5);
      use(c, a.id());
      f.executor.run();
      List<byte[]> copies = r.of(a.id());
      assertEquals(2, copies.size());
      assertTrue(Retained.wiped(copies.get(0)));
      assertFalse(Retained.wiped(copies.get(1)));
    }
  }

  @Test
  void aLoadThatFinishesAfterCloseIsWipedAndPublishesNothing() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = history(f);
      Retained r = new Retained();
      LocalKeys c = f.keep(tracked(f, r).open());
      CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
      f.before.set(
          q -> {
            if (is(q, Operation.GET)) {
              entered.countDown();
              await(release);
            }
          });
      ExecutorService caller = Executors.newSingleThreadExecutor();
      try {
        Future<?> load = caller.submit(() -> use(c, a.id()));
        await(entered);
        c.close();
        release.countDown();
        ExecutionException failed =
            assertThrows(ExecutionException.class, () -> load.get(5, TimeUnit.SECONDS));
        assertInstanceOf(IllegalStateException.class, failed.getCause());
      } finally {
        release.countDown();
        caller.shutdownNow();
      }
      assertEquals(1, r.all.size(), "the late Get's material reached the cache");
      assertEquals(0, r.live(), "and was wiped, never published");
      assertEquals(0, c.historicalSlots());
    }
  }

  @Test
  void theOwnedRefreshThreadIsADaemonThatStopsAtClose() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      f.key();
      LocalKeys.Builder b =
          f.client
              .keys()
              .localKeys(NAME)
              .scope(KeyQuery.all().custom(FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(TTL);
      b.ticker = f.time::get;
      LocalKeys c = f.keep(b.open());
      use(c); // A cold load runs on the calling thread.
      AtomicReference<Thread> refresher = new AtomicReference<>();
      CountDownLatch refreshed = new CountDownLatch(1);
      f.before.set(
          q -> {
            if (is(q, Operation.GET) && Thread.currentThread() != refresher.get()) {
              refresher.set(Thread.currentThread());
              refreshed.countDown();
            }
          });
      f.advance(5);
      Thread self = Thread.currentThread();
      use(c); // Due: queued on the cache's own thread.
      await(refreshed);
      Thread thread = refresher.get();
      assertNotSame(self, thread);
      assertEquals("keytend-local-keys-refresh", thread.getName());
      assertTrue(thread.isDaemon());
      c.close();
      c.close(); // Idempotent.
      thread.join(TimeUnit.SECONDS.toMillis(5));
      assertFalse(thread.isAlive(), "close stops the thread the cache owns");
    }
  }

  @Test
  void aDueRefreshIsQueuedOnceAndTheHitsReturnAtOnce() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      f.key();
      LocalKeys c = f.cache();
      use(c);
      f.advance(4);
      int requests = f.server.exchanges();
      use(c);
      assertTrue(f.executor.queue.isEmpty(), "not due before refreshAfter");
      f.advance(1);
      for (int i = 0; i < 3; i++) use(c);
      assertEquals(requests, f.server.exchanges(), "hits send nothing, a due one included");
      assertEquals(1, f.executor.queue.size(), "one refresh, shared by every later hit");
      f.executor.run();
      f.advance(1);
      use(c);
      assertTrue(f.executor.queue.isEmpty(), "the refreshed entry is young again");
    }
  }

  @Test
  void idleEntriesAreNotPolledAndTheNextCallLoadsOnItsOwnThread() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      f.key();
      LocalKeys c = f.cache();
      use(c);
      int requests = f.server.exchanges();
      f.advance(3 * TTL.toSeconds());
      assertEquals(requests, f.server.exchanges(), "no idle refresh");
      assertTrue(f.executor.queue.isEmpty());
      Set<Thread> senders = ConcurrentHashMap.newKeySet();
      f.before.set(q -> senders.add(Thread.currentThread()));
      use(c);
      assertEquals(Set.of(Thread.currentThread()), senders);
      assertTrue(f.executor.queue.isEmpty());
    }
  }

  @Test
  void theRefreshAgeStartsBeforeTheValidationsFirstRequest() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = history(f);
      LocalKeys c = f.cache();
      AtomicBoolean first = new AtomicBoolean(true);
      f.before.set(
          q -> {
            if (first.getAndSet(false)) f.advance(3); // The validation takes three seconds.
          });
      use(c, a.id());
      f.before.set(q -> {});
      f.advance(1); // Age four, published one second ago.
      use(c, a.id());
      assertTrue(f.executor.queue.isEmpty());
      f.advance(1); // Age five: refreshAfter, half the TTL.
      use(c, a.id());
      assertEquals(1, f.executor.queue.size());
    }
  }

  @Test
  void aDefiniteRefusalIsRememberedForTheTtlAndThenAskedAgain() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      LocalKeys c = f.cache();
      NotFoundException refused =
          assertThrows(NotFoundException.class, () -> c.forDecrypt("absent-id"));
      int requests = f.server.exchanges();
      f.advance(TTL.toSeconds() - 1);
      assertSame(refused, assertThrows(NotFoundException.class, () -> c.forDecrypt("absent-id")));
      assertEquals(requests, f.server.exchanges(), "remembered: no request");
      f.advance(1);
      assertThrows(NotFoundException.class, () -> c.forDecrypt("absent-id"));
      assertTrue(f.server.exchanges() > requests, "asked again once the TTL ran");
    }
  }

  @Test
  void theTransientBackoffIsAnEighthOfAShortTtl() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = history(f);
      LocalKeys c = f.keep(f.builder().ttl(Duration.ofSeconds(4)).open());
      f.server.unreachable(true);
      assertThrows(TransientException.class, () -> c.forDecrypt(a.id()));
      f.server.unreachable(false);
      int requests = f.server.exchanges();
      f.time.addAndGet(TimeUnit.MILLISECONDS.toNanos(499));
      TransientException fast = assertThrows(TransientException.class, () -> c.forDecrypt(a.id()));
      assertTrue(fast.getMessage().contains("retry backoff"), fast.getMessage());
      assertEquals(requests, f.server.exchanges());
      f.time.addAndGet(TimeUnit.MILLISECONDS.toNanos(1));
      use(c, a.id());
    }
  }

  @Test
  void aRememberedRefusalTakesCapacityAndIsEvictedLikeAnEntry() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = history(f);
      LocalKeys c = f.keep(f.builder().capacity(2).open()); // One historical entry.
      assertThrows(NotFoundException.class, () -> c.forDecrypt("absent-id"));
      assertEquals(1, c.historicalSlots(), "the negative answer holds the entry");
      use(c, a.id()); // Evicts it: it was idle.
      assertEquals(1, c.historicalSlots());
      int requests = f.server.exchanges();
      assertThrows(NotFoundException.class, () -> c.forDecrypt("absent-id"));
      assertTrue(f.server.exchanges() > requests, "the evicted refusal is asked again");
    }
  }
}
