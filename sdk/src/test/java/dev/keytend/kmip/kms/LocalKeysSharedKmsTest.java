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

import dev.keytend.kmip.kms.LocalKeysStartupTest.Connections;
import dev.keytend.kmip.model.Operation;
import java.io.IOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link LocalKeys.SharedKms}: the caches of several key families on one lazily connected KMS.
 * Building sends nothing; the first key use of any cache connects, once for all; concurrent first
 * uses share the attempt; a failed attempt's backoff is each cache's; closing a cache leaves the
 * KMS to the others, and closing the shared KMS cancels an attempt and ends the caches' calls.
 */
class LocalKeysSharedKmsTest {
  /** A cache of {@code family}'s keys, named {@code family + "-write"}, on the shared KMS. */
  private static LocalKeys cache(Fixture f, LocalKeys.SharedKms kms, String family, Duration ttl) {
    LocalKeys.Builder b =
        kms.localKeys(family + "-write")
            .scope(KeyQuery.all().custom(FAMILY, family))
            .expect(Expect.aes(256))
            .ttl(ttl)
            .refreshExecutor(f.executor);
    b.ticker = f.time::get;
    return f.keep(b.open());
  }

  private static LocalKeys cache(Fixture f, LocalKeys.SharedKms kms, String family) {
    return cache(f, kms, family, TTL);
  }

  /** An Active write key of {@code family}, named for its cache. */
  private static KeyHandle writeKey(Fixture f, String family) {
    return f.admin
        .keys()
        .createAes(256)
        .extractable(true)
        .custom(FAMILY, family)
        .named(family + "-write")
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .create();
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void severalFamiliesShareOneConnectionMadeAtTheFirstKeyUse(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle orders = writeKey(f, "orders"), users = writeKey(f, "users");
      Connections connections = new Connections();
      int exchanges = f.server.exchanges();
      try (LocalKeys.SharedKms kms =
          LocalKeys.sharedKms(connections.config(f, Duration.ofSeconds(2)))) {
        LocalKeys a = cache(f, kms, "orders"), b = cache(f, kms, "users");
        assertEquals(0, connections.opened.get(), "building and opening connect nothing");
        assertEquals(exchanges, f.server.exchanges(), "and send nothing");
        assertEquals("LocalKeys.SharedKms[not connected]", kms.toString());
        try (LocalKeys.Use use = a.forEncrypt()) {
          assertEquals(orders.id(), use.id());
        }
        int opened = connections.opened.get();
        assertTrue(opened >= 1);
        assertEquals("LocalKeys.SharedKms[connected]", kms.toString());
        try (LocalKeys.Use use = b.forEncrypt()) {
          assertEquals(users.id(), use.id());
        }
        try (LocalKeys.Use use = b.forDecrypt(users.id())) {
          assertEquals(users.id(), use.id());
        }
        assertEquals(opened, connections.opened.get(), "the second family connects nothing");
        assertThrows(KeyMismatchException.class, () -> b.forDecrypt(orders.id()), "own scope");
        a.close();
        try (LocalKeys.Use use = b.forEncrypt()) {
          assertEquals(users.id(), use.id(), "closing a cache leaves the KMS to the others");
        }
        assertEquals(0, connections.closed.get());
        try (LocalKeys c = cache(f, kms, "orders");
            LocalKeys.Use use = c.forEncrypt()) {
          assertEquals(orders.id(), use.id(), "a cache opened later uses the connected KMS");
        }
        assertEquals(opened, connections.opened.get());
        b.close();
      }
      assertEquals(connections.opened.get(), connections.closed.get(), "close closes the KMS");
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theSharedKmsOpensWhileTheKmsIsDownAndEachCacheKeepsItsOwnBackoff(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle orders = writeKey(f, "orders"), users = writeKey(f, "users");
      Connections connections = new Connections();
      f.server.unreachable(true);
      try (LocalKeys.SharedKms kms =
          LocalKeys.sharedKms(connections.config(f, Duration.ofSeconds(1)))) {
        // Backoffs: min(1 s, ttl / 8): 1 s for orders, 500 ms for users.
        LocalKeys a = cache(f, kms, "orders"), b = cache(f, kms, "users", Duration.ofSeconds(4));
        assertThrows(TransientException.class, a::forEncrypt);
        int attempts = connections.opened.get();
        TransientException fast = assertThrows(TransientException.class, b::forEncrypt);
        assertTrue(fast.getMessage().contains("connection retry backoff"), fast.getMessage());
        assertEquals(attempts, connections.opened.get(), "the failure is shared: no new attempt");
        f.server.unreachable(false);
        f.time.addAndGet(TimeUnit.MILLISECONDS.toNanos(500));
        try (LocalKeys.Use use = b.forEncrypt()) {
          assertEquals(users.id(), use.id(), "users' backoff ended: it connects, for both");
        }
        int connected = connections.opened.get();
        TransientException own = assertThrows(TransientException.class, a::forEncrypt);
        assertTrue(own.getMessage().contains("retry backoff"), "orders' own: " + own.getMessage());
        f.time.addAndGet(TimeUnit.MILLISECONDS.toNanos(500));
        try (LocalKeys.Use use = a.forEncrypt()) {
          assertEquals(orders.id(), use.id(), "orders' backoff ended: the KMS is connected");
        }
        assertEquals(connected, connections.opened.get(), "no second connection");
      }
    }
  }

  @Test
  void invalidatingAnyCacheClearsTheSharedBackoff() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle users = writeKey(f, "users");
      writeKey(f, "orders");
      Connections connections = new Connections();
      try (LocalKeys.SharedKms kms =
          LocalKeys.sharedKms(connections.config(f, Duration.ofSeconds(1)))) {
        LocalKeys a = cache(f, kms, "orders"), b = cache(f, kms, "users");
        f.server.unreachable(true);
        assertThrows(TransientException.class, a::forEncrypt);
        f.server.unreachable(false);
        a.invalidateAll();
        try (LocalKeys.Use use = b.forEncrypt()) {
          assertEquals(users.id(), use.id());
        }
      }
    }
  }

  /** Repeated: the two first uses race for the attempt; either may start it. */
  @RepeatedTest(10)
  void concurrentFirstUsesOfTwoCachesShareOneAttempt() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle orders = writeKey(f, "orders"), users = writeKey(f, "users");
      Connections connections = new Connections();
      CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
      connections.before =
          (request, context) -> {
            if (is(request, Operation.DISCOVER_VERSIONS)) {
              entered.countDown();
              await(release);
            }
          };
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try (LocalKeys.SharedKms kms =
          LocalKeys.sharedKms(connections.config(f, Duration.ofSeconds(5)))) {
        LocalKeys a = cache(f, kms, "orders"), b = cache(f, kms, "users");
        Future<String> first = pool.submit(() -> id(a));
        assertTrue(entered.await(5, TimeUnit.SECONDS));
        assertEquals("LocalKeys.SharedKms[connecting]", kms.toString());
        Future<String> second = pool.submit(() -> id(b));
        release.countDown();
        assertEquals(orders.id(), first.get(5, TimeUnit.SECONDS));
        assertEquals(users.id(), second.get(5, TimeUnit.SECONDS));
        assertEquals(1, connections.opened.get(), "one attempt, one connection, for both");
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void closingACacheEndsOnlyItsOwnWaitForTheSharedAttempt() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      writeKey(f, "orders");
      KeyHandle users = writeKey(f, "users");
      Connections connections = new Connections();
      CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
      connections.before =
          (request, context) -> {
            if (is(request, Operation.DISCOVER_VERSIONS)) {
              entered.countDown();
              await(release);
            }
          };
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try (LocalKeys.SharedKms kms =
          LocalKeys.sharedKms(connections.config(f, Duration.ofSeconds(5)))) {
        LocalKeys a = cache(f, kms, "orders"), b = cache(f, kms, "users");
        Future<String> connecting = pool.submit(() -> id(b)); // b's call makes the attempt.
        assertTrue(entered.await(5, TimeUnit.SECONDS));
        Thread[] waiter = new Thread[1];
        CountDownLatch started = new CountDownLatch(1);
        Future<String> waiting =
            pool.submit(
                () -> {
                  waiter[0] = Thread.currentThread();
                  started.countDown();
                  return id(a);
                });
        await(started);
        awaitTimedWaiting(waiter[0]); // a's call waits for b's attempt.
        a.close();
        ExecutionException closed =
            assertThrows(ExecutionException.class, () -> waiting.get(5, TimeUnit.SECONDS));
        assertInstanceOf(IllegalStateException.class, closed.getCause());
        assertFalse(connecting.isDone(), "the attempt goes on for the other cache");
        release.countDown();
        assertEquals(users.id(), connecting.get(5, TimeUnit.SECONDS));
        assertEquals(1, connections.opened.get());
        assertEquals(0, connections.closed.get());
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void closingTheSharedKmsCancelsItsAttemptAndEndsItsCaches() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      writeKey(f, "orders");
      Connections connections = new Connections();
      CountDownLatch entered = new CountDownLatch(1), canceled = new CountDownLatch(1);
      connections.before =
          (request, context) -> {
            if (is(request, Operation.DISCOVER_VERSIONS)) {
              entered.countDown();
              try (java.io.Closeable cancellation = context.onCancel(canceled::countDown)) {
                assertTrue(canceled.await(5, TimeUnit.SECONDS));
              } catch (IOException | InterruptedException e) {
                throw new AssertionError(e);
              }
            }
          };
      ExecutorService pool = Executors.newSingleThreadExecutor();
      LocalKeys.SharedKms kms = LocalKeys.sharedKms(connections.config(f, Duration.ofSeconds(5)));
      try {
        LocalKeys a = cache(f, kms, "orders");
        Future<String> first = pool.submit(() -> id(a));
        assertTrue(entered.await(5, TimeUnit.SECONDS));
        kms.close();
        assertTrue(canceled.await(5, TimeUnit.SECONDS), "close cancels the attempt");
        ExecutionException failed =
            assertThrows(ExecutionException.class, () -> first.get(5, TimeUnit.SECONDS));
        assertInstanceOf(IllegalStateException.class, failed.getCause());
        IllegalStateException later = assertThrows(IllegalStateException.class, a::forEncrypt);
        assertEquals("Shared KMS closed", later.getMessage());
        assertEquals(Duration.ZERO, a.usableFor().orElseThrow());
        assertThrows(IllegalStateException.class, () -> kms.localKeys("users-write"));
        assertEquals("LocalKeys.SharedKms[closed]", kms.toString());
        kms.close(); // Idempotent.
        assertEquals(connections.opened.get(), connections.closed.get(), "nothing left open");
      } finally {
        canceled.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void aConnectedSharedKmsClosesItsConnectionsAndItsCachesFailClosed() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      writeKey(f, "orders");
      Connections connections = new Connections();
      LocalKeys.SharedKms kms = LocalKeys.sharedKms(connections.config(f, Duration.ofSeconds(2)));
      LocalKeys a = cache(f, kms, "orders");
      LocalKeys.Builder unopened =
          kms.localKeys("users-write")
              .scope(KeyQuery.all().custom(FAMILY, "users"))
              .expect(Expect.aes(256));
      try (LocalKeys.Use ignored = a.forEncrypt()) {}
      kms.close();
      assertEquals(connections.opened.get(), connections.closed.get());
      assertThrows(IllegalStateException.class, a::forEncrypt);
      assertThrows(IllegalStateException.class, () -> a.forDecrypt("any-id"));
      assertThrows(IllegalStateException.class, unopened::open, "a builder of a closed KMS");
      assertEquals(Duration.ZERO, a.usableFor().orElseThrow());
      a.close();
    }
  }

  /**
   * A shared KMS reports its configured endpoints' connections for metrics before it connects
   * (nothing opened), once connected (the KMS's) and after it is closed, without a request.
   */
  @Test
  void connectionStatsListTheConfiguredEndpointsBeforeAndAfterConnecting() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      writeKey(f, "orders");
      Connections connections = new Connections();
      LocalKeys.SharedKms kms = LocalKeys.sharedKms(connections.config(f, Duration.ofSeconds(2)));
      int exchanges = f.server.exchanges();
      List<Kms.ConnectionStats> before = kms.connectionStats();
      assertEquals(1, before.size());
      assertEquals("in-memory:5696", before.get(0).endpoint());
      assertEquals(0, before.get(0).opened());
      assertEquals(0, before.get(0).open());
      assertFalse(before.get(0).measured(), "the in-memory transport reports no counts");
      assertEquals(exchanges, f.server.exchanges(), "read from memory");
      assertEquals(0, connections.opened.get(), "and connects nothing");
      try (LocalKeys a = cache(f, kms, "orders")) {
        try (LocalKeys.Use ignored = a.forEncrypt()) {}
        assertEquals(
            List.of("in-memory:5696"),
            kms.connectionStats().stream().map(Kms.ConnectionStats::endpoint).toList());
      }
      kms.close();
      assertEquals(1, kms.connectionStats().size(), "also after close");
      assertThrows(UnsupportedOperationException.class, () -> kms.connectionStats().clear());
    }
  }

  @Test
  void argumentsAreChecked() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      assertThrows(NullPointerException.class, () -> LocalKeys.sharedKms(null));
      try (LocalKeys.SharedKms kms = LocalKeys.sharedKms(f.server.configure().build())) {
        assertThrows(NullPointerException.class, () -> kms.localKeys(null));
        assertThrows(IllegalArgumentException.class, () -> kms.localKeys(""));
        assertThrows(IllegalStateException.class, () -> kms.localKeys("orders-write").open());
      }
    }
  }

  private static String id(LocalKeys cache) {
    try (LocalKeys.Use use = cache.forEncrypt()) {
      return use.id();
    }
  }

  private static void await(CountDownLatch latch) {
    try {
      assertTrue(latch.await(5, TimeUnit.SECONDS));
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AssertionError(e);
    }
  }

  /** Waits until {@code thread} waits with a timeout: a call waits so for a connection attempt. */
  private static void awaitTimedWaiting(Thread thread) throws InterruptedException {
    for (int i = 0; i < 1000 && thread.getState() != Thread.State.TIMED_WAITING; i++)
      TimeUnit.MILLISECONDS.sleep(5);
    assertEquals(Thread.State.TIMED_WAITING, thread.getState());
  }
}
