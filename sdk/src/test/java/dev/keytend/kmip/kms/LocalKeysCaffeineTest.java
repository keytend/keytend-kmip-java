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

import dev.keytend.kmip.kms.LocalKeysSemanticsTest.Retained;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * What the cache's use of Caffeine adds to the semantics {@link LocalKeysSemanticsTest} pins: the
 * expiry timers wipe a key nobody asks for at the next sweep, the slot outlives the material it
 * wiped (its fingerprint still refuses changed material), and no timer outlives its entry; and
 * its eviction order: recency and frequency rather than strict LRU, never a reserved slot, and a
 * hit told to Caffeine at most once a millisecond per key.
 */
class LocalKeysCaffeineTest {
  private static void use(LocalKeys c, String id) {
    try (LocalKeys.Use ignored = c.forDecrypt(id)) {}
  }

  private static KeyHandle history(Fixture f) {
    return f.key(256, "orders", null, KeyUsage.DECRYPT);
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theSweepWipesAnExpiredKeyNobodyAsksForAndKeepsItsSlot(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle a = history(f), b = history(f);
      Retained r = new Retained();
      LocalKeys.Builder builder = f.builder();
      builder.retained = r;
      LocalKeys c = f.keep(builder.open());
      use(c, a.id());
      f.advance(6);
      use(c, b.id());
      f.advance(5); // a's TTL has ended; b's has not.
      assertFalse(Retained.wiped(r.of(a.id()).get(0)), "wiped lazily, not by a timer thread");
      int requests = f.server.exchanges();
      use(c, b.id()); // A hit on b runs the sweep, a second after the last one.
      assertTrue(Retained.wiped(r.of(a.id()).get(0)), "a's timer ended: wiped by the sweep");
      assertFalse(Retained.wiped(r.of(b.id()).get(0)));
      assertEquals(requests, f.server.exchanges(), "the hit and the sweep send nothing");
      assertEquals(1, c.stats().evictions());
      assertEquals(1, c.stats().size());
      assertEquals(2, c.historicalSlots(), "a's slot stays, with what it remembers");
      assertEquals(1, c.timers(), "b's timer is the one left");
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void changedMaterialIsRefusedAfterTheSweepWipedTheExpiredCopy(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle a = history(f), b = history(f);
      Retained r = new Retained();
      LocalKeys.Builder builder = f.builder();
      builder.retained = r;
      LocalKeys c = f.keep(builder.open());
      use(c, a.id());
      f.advance(TTL.toSeconds() + 1);
      use(c, b.id()); // Loads b; the sweep wipes a.
      assertTrue(Retained.wiped(r.of(a.id()).get(0)));
      f.after.set(
          (request, response) ->
              is(request, Operation.GET)
                  ? KeyPolicyTest.rewrite(
                      response,
                      node ->
                          node.tag() == Tag.KEY_MATERIAL.code()
                                  && node.type() == Ttlv.Type.BYTE_STRING
                              ? Ttlv.bytes(Tag.KEY_MATERIAL, new byte[node.bytesValue().length])
                              : node)
                  : response);
      KeyMismatchException changed =
          assertThrows(KeyMismatchException.class, () -> c.forDecrypt(a.id()));
      assertTrue(changed.getMessage().contains("changed"), changed.getMessage());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void noTimerOutlivesItsEntry(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle w = f.key(), a = history(f), b = history(f);
      LocalKeys c = f.keep(f.builder().capacity(2).open()); // One historical entry.
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      assertEquals(2, c.timers(), "the write key and its seeded decryption copy");
      for (int i = 0; i < 20; i++) {
        use(c, a.id());
        c.invalidate(a.id());
      }
      assertEquals(1, c.timers(), "invalidated entries stop their timers");
      use(c, a.id());
      use(c, b.id()); // Evicts a.
      assertEquals(2, c.timers(), "the write key and b");
      f.advance(TTL.toSeconds() - 4);
      try (LocalKeys.Use ignored = c.forEncrypt()) {} // Queues the write key's refresh.
      f.executor.run();
      assertEquals(2, c.timers(), "a refresh replaces its entry's timer");
      assertEquals(w.id(), c.currentWriteId().orElseThrow());
      c.invalidateAll();
      assertEquals(0, c.timers());
      use(c, b.id());
      c.close();
      assertEquals(0, c.timers(), "close stops every timer");
    }
  }

  static final long MILLISECOND = TimeUnit.MILLISECONDS.toNanos(1);

  /**
   * Caffeine's order keeps a key used often through a burst of keys used once, which strict LRU
   * would have evicted (it was used before more keys than the cache holds): only the one-off keys
   * are evicted, and the frequent key is still a hit.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aFrequentlyUsedKeySurvivesABurstOfOneOffKeys(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle hot = history(f);
      List<KeyHandle> once = new ArrayList<>();
      for (int i = 0; i < 12; i++) once.add(history(f));
      LocalKeys c = f.keep(f.builder().capacity(5).open()); // Four historical slots.
      use(c, hot.id());
      use(c, once.get(0).id());
      use(c, once.get(1).id());
      for (int i = 0; i < 50; i++) {
        f.time.addAndGet(MILLISECOND); // Each hit is told to Caffeine.
        use(c, hot.id());
      }
      for (KeyHandle k : once.subList(2, once.size())) {
        f.time.addAndGet(MILLISECOND);
        use(c, k.id());
      }
      assertEquals(once.size() + 1 - 4, c.stats().evictions(), "only one-off keys were evicted");
      assertEquals(4, c.historicalSlots());
      assertFalse(c.evictionOrder().subList(0, 3).contains(hot.id()), c.evictionOrder().toString());
      int exchanges = f.server.exchanges();
      use(c, hot.id());
      assertEquals(exchanges, f.server.exchanges(), "the frequent key is still cached");
    }
  }

  /**
   * A slot a call has reserved is never evicted, even first in Caffeine's order: here a call
   * blocked in its key's Get, the cache full; another key's admission evicts the coldest idle
   * slot, and the blocked call completes with its key cached.
   */
  @Test
  void aReservedSlotIsNeverEvictedEvenWhenColdest() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle reserved = history(f),
          b = history(f),
          d = history(f),
          e = history(f),
          g = history(f);
      LocalKeys c = f.keep(f.builder().capacity(5).open());
      AtomicBoolean blockNextGet = new AtomicBoolean(true);
      CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
      f.before.set(
          r -> {
            if (is(r, Operation.GET) && blockNextGet.compareAndSet(true, false)) {
              entered.countDown();
              try {
                assertTrue(release.await(10, TimeUnit.SECONDS));
              } catch (InterruptedException x) {
                Thread.currentThread().interrupt();
              }
            }
          });
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        Future<String> call =
            pool.submit(
                () -> {
                  try (LocalKeys.Use use = c.forDecrypt(reserved.id())) {
                    return use.id();
                  }
                });
        assertTrue(entered.await(10, TimeUnit.SECONDS));
        use(c, b.id());
        use(c, d.id());
        use(c, e.id());
        List<String> order = c.evictionOrder();
        assertEquals(reserved.id(), order.get(0), "the reserved slot is coldest");
        String victim = order.get(1); // The coldest idle slot.
        use(c, g.id()); // Full: evicts the coldest idle slot, not the reserved one.
        assertEquals(1, c.stats().evictions());
        assertFalse(c.evictionOrder().contains(victim), victim + " was evicted");
        assertTrue(c.evictionOrder().contains(reserved.id()), "the reserved slot stays");
        release.countDown();
        assertEquals(reserved.id(), call.get(10, TimeUnit.SECONDS));
        int exchanges = f.server.exchanges();
        use(c, reserved.id());
        assertEquals(exchanges, f.server.exchanges(), "the reserved key stayed cached");
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  /**
   * Hits on one key within a millisecond tell Caffeine once, however many threads make them; the
   * next millisecond's first hit tells again.
   */
  @Test
  void aHitTellsCaffeineAtMostOnceAMillisecondPerKey() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = history(f), b = history(f);
      LocalKeys c = f.keep(f.builder().open());
      use(c, a.id());
      use(c, b.id());
      long base = c.hitsRecorded();
      for (int i = 0; i < 10; i++) use(c, a.id());
      assertEquals(base + 1, c.hitsRecorded(), "ten hits within a millisecond: told once");
      use(c, b.id());
      assertEquals(base + 2, c.hitsRecorded(), "per key");
      f.time.addAndGet(MILLISECOND - 1);
      use(c, a.id());
      assertEquals(base + 2, c.hitsRecorded(), "not yet a millisecond");
      f.time.addAndGet(1);
      use(c, a.id());
      assertEquals(base + 3, c.hitsRecorded(), "a millisecond later: told again");
      f.time.addAndGet(MILLISECOND);
      int threads = 8;
      CountDownLatch start = new CountDownLatch(1);
      ExecutorService pool = Executors.newFixedThreadPool(threads);
      try {
        List<Future<?>> hits = new ArrayList<>();
        for (int t = 0; t < threads; t++)
          hits.add(
              pool.submit(
                  () -> {
                    assertTrue(start.await(10, TimeUnit.SECONDS));
                    for (int i = 0; i < 200; i++) use(c, a.id());
                    return null;
                  }));
        start.countDown();
        for (Future<?> h : hits) h.get(10, TimeUnit.SECONDS);
      } finally {
        pool.shutdownNow();
      }
      assertEquals(base + 4, c.hitsRecorded(), "concurrent hits in one millisecond: told once");
    }
  }
}
