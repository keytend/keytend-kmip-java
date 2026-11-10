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

import dev.keytend.kmip.kms.LeasingTransport.Grant;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;

/**
 * {@link LocalKeys#stats()}, each counter as {@link LocalKeys.Stats} documents it, and the load and
 * lease events: {@link KmsListener#localKeyLoaded} once per committed load, {@link
 * KmsListener#leaseGranted} once per committed grant, neither for a superseded or failed load.
 */
class LocalKeysStatsAndEventsTest {
  record Refreshed(String name, String keyId, LocalUse purpose, Duration loadTime) {}

  record Granted(String keyId, Duration lease, boolean renewal) {}

  static final class Recorder implements KmsListener {
    final List<Refreshed> refreshed = new CopyOnWriteArrayList<>();
    final List<Granted> granted = new CopyOnWriteArrayList<>();
    final List<String> order = new CopyOnWriteArrayList<>();

    @Override
    public void localKeyLoaded(String name, String keyId, LocalUse purpose, Duration loadTime) {
      refreshed.add(new Refreshed(name, keyId, purpose, loadTime));
      order.add("refreshed " + keyId);
    }

    @Override
    public void leaseGranted(String keyId, Duration lease, boolean renewal) {
      granted.add(new Granted(keyId, lease, renewal));
      order.add("granted " + keyId);
    }
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

  /** encrypt hits/misses, decrypt hits/misses, loads, failures, evictions, waits, size. */
  private static void assertStats(LocalKeys c, long... expected) {
    LocalKeys.Stats s = c.stats();
    long[] actual = {
      s.encryptHits(),
      s.encryptMisses(),
      s.decryptHits(),
      s.decryptMisses(),
      s.loads(),
      s.loadFailures(),
      s.evictions(),
      s.capacityWaits(),
      s.size()
    };
    assertArrayEquals(expected, actual, s.toString());
  }

  @Test
  void hitsMissesLoadsAndSizeAreCountedPerPurpose() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle w = f.key(), h = history(f);
      LocalKeys c = f.cache();
      assertStats(c, 0, 0, 0, 0, 0, 0, 0, 0, 0);
      use(c); // A cold load: the write key and its seeded read copy.
      assertStats(c, 0, 1, 0, 0, 1, 0, 0, 0, 2);
      use(c);
      use(c, w.id()); // The seeded copy: a hit, no load.
      try (LocalKeys.Use ignored = c.forAppend(w.id())) {} // The write copy, by identifier.
      assertStats(c, 2, 1, 1, 0, 1, 0, 0, 0, 2);
      use(c, h.id());
      use(c, h.id());
      assertStats(c, 2, 1, 2, 1, 2, 0, 0, 0, 3);
      f.advance(5);
      use(c); // Due: a hit that queues a refresh.
      f.executor.run();
      assertStats(c, 3, 1, 2, 1, 3, 0, 0, 0, 3);
      assertTrue(c.stats().toString().contains("loads 3"), c.stats().toString());
    }
  }

  @Test
  void failuresCountFailedRefreshesAndFirstLoadsButNotTheBackoffOrSupersededLoads() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      f.key();
      KeyHandle h = history(f);
      LocalKeys c = f.cache();
      f.server.unreachable(true);
      assertThrows(TransientException.class, () -> c.forDecrypt(h.id()));
      assertThrows(TransientException.class, () -> c.forDecrypt(h.id())); // Backoff: no load.
      assertStats(c, 0, 0, 0, 0, 0, 1, 0, 0, 0);
      f.server.unreachable(false);
      f.advance(1);
      use(c);
      f.advance(5);
      use(c); // Queues a refresh, which fails.
      f.server.unreachable(true);
      f.executor.run();
      assertEquals(2, c.stats().loadFailures());
      f.server.unreachable(false);
      f.advance(1);
      use(c); // Queues a refresh that an invalidation supersedes: no outcome is counted.
      c.invalidateAll();
      f.executor.run();
      assertEquals(2, c.stats().loadFailures());
      assertEquals(1, c.stats().loads());
    }
  }

  @Test
  void evictionsCountCapacityAndExpiryButNotInvalidationOrClose() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = history(f), b = history(f);
      LocalKeys c = f.keep(f.builder().capacity(2).open()); // One historical entry.
      use(c, a.id());
      use(c, b.id()); // Evicts a's entry.
      assertEquals(1, c.stats().evictions());
      f.server.unreachable(true);
      f.advance(TTL.toSeconds());
      assertThrows(TransientException.class, () -> c.forDecrypt(b.id())); // b expired.
      assertEquals(2, c.stats().evictions());
      assertEquals(0, c.stats().size());
      f.server.unreachable(false);
      f.advance(1);
      use(c, b.id());
      c.invalidate(b.id());
      c.invalidateAll();
      assertEquals(2, c.stats().evictions());
      c.close();
      LocalKeys.Stats closed = c.stats();
      assertEquals(2, closed.evictions(), "close keeps the counters");
      assertEquals(0, closed.size(), "and holds no keys");
      assertEquals(3, closed.loads());
    }
  }

  @Test
  void aCallThatWaitsForCapacityIsCountedOnce() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = history(f), b = history(f);
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
        Future<?> first = pool.submit(() -> use(c, a.id()));
        await(entered);
        Future<?> second = pool.submit(() -> use(c, b.id()));
        awaitWaiters(c, 1);
        // A waiter registers, rechecks admission once, and only then counts its wait.
        long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
        while (c.stats().capacityWaits() == 0) {
          assertTrue(System.nanoTime() < end, "the waiter never counted its wait");
          Thread.sleep(1);
        }
        assertEquals(1, c.stats().capacityWaits());
        release.countDown();
        first.get(5, TimeUnit.SECONDS);
        second.get(5, TimeUnit.SECONDS);
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
      assertEquals(1, c.stats().capacityWaits());
      assertEquals(2, c.stats().decryptMisses());
    }
  }

  @Test
  void everyCommittedLoadIsReportedOnceWithItsDuration() {
    Recorder r = new Recorder();
    try (Fixture f = new Fixture(KmipVersion.V2_1, RetryPolicy.none(), r)) {
      KeyHandle w = f.key(), h = history(f);
      LocalKeys c = f.cache();
      f.before.set(
          q -> {
            if (is(q, Operation.GET)) f.advance(2); // Each Get takes two seconds.
          });
      use(c); // A first load; its seeded read copy is not a load.
      use(c, w.id());
      use(c);
      assertEquals(
          List.of(new Refreshed(NAME, w.id(), LocalUse.ENCRYPT, Duration.ofSeconds(2))),
          r.refreshed);
      use(c, h.id());
      assertEquals(
          new Refreshed(NAME, h.id(), LocalUse.DECRYPT, Duration.ofSeconds(2)), r.refreshed.get(1));
      f.advance(3);
      use(c); // Due: a background refresh.
      assertEquals(2, r.refreshed.size(), "reported when it commits, not when it is queued");
      f.executor.run();
      assertEquals(
          new Refreshed(NAME, w.id(), LocalUse.ENCRYPT, Duration.ofSeconds(2)), r.refreshed.get(2));
      f.advance(TTL.toSeconds());
      use(c, h.id()); // Expired: a foreground renewal.
      assertEquals(
          new Refreshed(NAME, h.id(), LocalUse.DECRYPT, Duration.ofSeconds(2)), r.refreshed.get(3));
      assertEquals(4, r.refreshed.size());
      assertEquals(List.of(), r.granted, "these keys state no Lease Time");
    }
  }

  @Test
  void aSupersededOrFailedLoadIsNotReported() {
    Recorder r = new Recorder();
    try (Fixture f = new Fixture(KmipVersion.V2_1, RetryPolicy.none(), r)) {
      KeyHandle h = history(f);
      f.key();
      LocalKeys c = f.cache();
      use(c);
      f.advance(5);
      use(c);
      c.invalidateAll(); // Supersedes the queued refresh.
      f.executor.run();
      f.server.unreachable(true);
      assertThrows(TransientException.class, () -> c.forDecrypt(h.id()));
      f.server.unreachable(false);
      f.advance(1);
      f.before.set(
          q -> {
            if (is(q, Operation.GET)) throw new PermissionDeniedException("Get permission removed");
          });
      assertThrows(PermissionDeniedException.class, () -> c.forDecrypt(h.id()));
      assertEquals(1, r.refreshed.size(), r.refreshed.toString());
    }
  }

  /** A client on a {@link LeasingTransport}, reporting to {@code listener}. */
  static final class Leasing implements AutoCloseable {
    final InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    final LeasingTransport leasing = new LeasingTransport(server);
    final Kms admin = server.connect();
    final Kms client;
    final QueueExecutor executor = new QueueExecutor();
    final java.util.concurrent.atomic.AtomicLong time =
        new java.util.concurrent.atomic.AtomicLong();
    LocalKeys cache;

    Leasing(KmsListener listener) {
      client =
          Kms.connect(
              server
                  .configure()
                  .retryPolicy(RetryPolicy.none())
                  .addListener(listener)
                  .transport(e -> leasing)
                  .build());
    }

    KeyHandle key(String name) {
      KeyCreation c =
          admin
              .keys()
              .createAes(256)
              .extractable(true)
              .custom(FAMILY, "orders")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
      if (name != null) c.named(name);
      return c.create();
    }

    LocalKeys cache() {
      LocalKeys.Builder b =
          client
              .keys()
              .localKeys(NAME)
              .scope(KeyQuery.all().custom(FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(TTL)
              .refreshExecutor(executor);
      b.ticker = time::get;
      cache = b.open();
      return cache;
    }

    void advance(long seconds) {
      time.addAndGet(TimeUnit.SECONDS.toNanos(seconds));
    }

    @Override
    public void close() {
      if (cache != null) cache.close();
      client.close();
      admin.close();
      server.close();
    }
  }

  @Test
  void aCommittedGrantIsReportedOnceAndLaterGrantsForTheKeyAreRenewals() {
    Recorder r = new Recorder();
    try (Leasing l = new Leasing(r)) {
      KeyHandle w = l.key(NAME);
      l.leasing.leaseTimes.put(w.id(), 6L);
      LocalKeys c = l.cache();
      use(c);
      use(c, w.id()); // The seeded copy shares the write validation's lease.
      assertEquals(List.of(new Granted(w.id(), Duration.ofSeconds(6), false)), r.granted);
      assertEquals(List.of("granted " + w.id(), "refreshed " + w.id()), r.order);
      l.advance(3); // Half the lease: due.
      use(c);
      l.executor.run();
      assertEquals(new Granted(w.id(), Duration.ofSeconds(6), true), r.granted.get(1));
      KeyHandle k = l.key(null);
      l.leasing.leaseTimes.put(k.id(), 6L);
      use(c, k.id());
      assertEquals(new Granted(k.id(), Duration.ofSeconds(6), false), r.granted.get(2));
      try (LocalKeys.Use ignored = c.forAppend(k.id())) {} // Its own entry, with its own lease.
      assertEquals(
          new Granted(k.id(), Duration.ofSeconds(6), true),
          r.granted.get(3),
          "a grant for the other purpose's entry is a renewal too");
      assertEquals(4, r.granted.size());
    }
  }

  @Test
  void aZeroGrantIsReportedAsZeroAndADiscardedGrantIsNotReported() {
    Recorder r = new Recorder();
    try (Leasing l = new Leasing(r)) {
      l.key(NAME);
      KeyHandle unlimited = l.key(null), discarded = l.key(null);
      l.leasing.leaseTimes.put(unlimited.id(), 0L);
      l.leasing.leaseTimes.put(discarded.id(), 6L);
      l.leasing.answer = id -> new Grant(id.equals(unlimited.id()) ? 0 : 6);
      LocalKeys c = l.cache();
      use(c, unlimited.id());
      assertEquals(List.of(new Granted(unlimited.id(), Duration.ZERO, false)), r.granted);
      l.leasing.beforeEach =
          q -> {
            if (is(q, Operation.GET) && discarded.id().equals(id(q)))
              throw new PermissionDeniedException("Get permission removed");
          };
      assertThrows(PermissionDeniedException.class, () -> c.forDecrypt(discarded.id()));
      assertTrue(l.leasing.obtained.contains(discarded.id()), "the server granted it");
      assertEquals(1, r.granted.size(), "but the load that obtained it was discarded");
      assertEquals(1, r.refreshed.size());
    }
  }
}
