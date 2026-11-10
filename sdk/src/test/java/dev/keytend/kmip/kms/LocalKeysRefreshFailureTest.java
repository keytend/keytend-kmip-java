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
import java.io.IOException;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Supplier;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * LocalKeys when a refresh fails: refusals, TLS distrust and removed access, and the identifier-set
 * scope. Tests named {@code holds...} check properties that must always hold.
 */
class LocalKeysRefreshFailureTest {

  private static Optional<String> itemTarget(Ttlv item) {
    return item.child(Tag.REQUEST_PAYLOAD)
        .flatMap(p -> p.child(Tag.UNIQUE_IDENTIFIER))
        .map(Ttlv::textValue);
  }

  /** Replaces only the batch items addressed to {@code denied} with Permission Denied. */
  static Ttlv denyItems(Ttlv request, Ttlv response, String denied) {
    List<Ttlv> asked = request.children(Tag.BATCH_ITEM);
    if (asked.stream().noneMatch(i -> itemTarget(i).filter(denied::equals).isPresent()))
      return response;
    List<Ttlv> refused =
        Faults.failure(request, Enums.ResultReason.PERMISSION_DENIED, "access removed")
            .children(Tag.BATCH_ITEM);
    List<Ttlv> answered = response.children(Tag.BATCH_ITEM);
    List<Ttlv> out = new ArrayList<>();
    out.add(response.require(Tag.RESPONSE_HEADER));
    for (int i = 0; i < asked.size(); i++)
      out.add(
          itemTarget(asked.get(i)).filter(denied::equals).isPresent()
              ? refused.get(i)
              : answered.get(i));
    return Ttlv.structure(Tag.RESPONSE_MESSAGE, out);
  }

  // Retiring an old listed key must not destroy an accessible replacement's write copy.
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void idSetScopeSkipsAnOldListedIdWhoseAccessWasRemoved(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle old = f.key();
      KeyHandle next = f.key(256, "orders", null, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
      LocalKeys.Builder b =
          f.client
              .keys()
              .localKeys(NAME)
              .scope(KeyQuery.all().ids(List.of(old.id(), next.id())))
              .expect(Expect.aes(256))
              .ttl(TTL)
              .refreshExecutor(f.executor);
      b.ticker = f.time::get;
      LocalKeys ids = f.keep(b.open());
      LocalKeys attribute = f.cache(); // the custom-attribute scope as a contrast
      try (LocalKeys.Use a = ids.forEncrypt();
          LocalKeys.Use c = attribute.forEncrypt()) {
        assertEquals(old.id(), a.id());
        assertEquals(old.id(), c.id());
      }
      // Runbook 1: provision the replacement, deactivate the old write key.
      next.addName(NAME);
      old.deactivate();
      ids.invalidateAll();
      attribute.invalidateAll();
      try (LocalKeys.Use a = ids.forEncrypt();
          LocalKeys.Use c = attribute.forEncrypt()) {
        assertEquals(next.id(), a.id());
        assertEquals(next.id(), c.id());
      }
      // Runbook 4: after upgradesstables, retire historical read access by removing access.
      f.after.set((request, response) -> denyItems(request, response, old.id()));
      assertThrows(PermissionDeniedException.class, () -> attribute.forDecrypt(old.id()));
      f.advance(5);
      try (LocalKeys.Use a = ids.forEncrypt();
          LocalKeys.Use c = attribute.forEncrypt()) {
        assertEquals(next.id(), a.id());
        assertEquals(next.id(), c.id());
      }
      f.executor.run();
      f.executor.run();
      try (LocalKeys.Use c = attribute.forEncrypt()) {
        assertEquals(next.id(), c.id());
      }
      assertEquals(Optional.of(next.id()), attribute.currentWriteId());
      assertEquals(Optional.of(next.id()), ids.currentWriteId());
      try (LocalKeys.Use use = ids.forEncrypt()) {
        assertEquals(next.id(), use.id());
      }
      for (int i = 0; i < 3; i++) {
        f.advance(20);
        try (LocalKeys.Use use = ids.forEncrypt()) {
          assertEquals(next.id(), use.id());
        }
        try (LocalKeys.Use use = attribute.forEncrypt()) {
          assertEquals(next.id(), use.id());
        }
      }
    }
  }

  static IOException serverCertificateExpired() {
    javax.net.ssl.SSLHandshakeException e =
        new javax.net.ssl.SSLHandshakeException("PKIX path validation failed");
    e.initCause(
        new java.security.cert.CertificateExpiredException(
            "NotAfter: Thu Oct 29 00:00:00 UTC 2026"));
    return e;
  }

  record Outcome(
      boolean readAfterFailedRefresh,
      boolean writePresent,
      boolean readAfterRecovery,
      Class<?> error) {}

  static Outcome failedRefresh(Supplier<IOException> fault) {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      AtomicBoolean failing = new AtomicBoolean();
      Kms client =
          Kms.connect(
              f.server
                  .configure()
                  .retryPolicy(RetryPolicy.none())
                  .callTimeout(Duration.ofSeconds(2))
                  .transport(
                      e ->
                          request -> {
                            if (failing.get()) throw fault.get();
                            return f.server.exchange(request);
                          })
                  .build());
      try {
        LocalKeys.Builder b =
            client
                .keys()
                .localKeys(NAME)
                .scope(KeyQuery.all().custom(FAMILY, "orders"))
                .expect(Expect.aes(256))
                .ttl(TTL)
                .refreshExecutor(f.executor);
        b.ticker = f.time::get;
        LocalKeys c = f.keep(b.open());
        try (LocalKeys.Use w = c.forEncrypt();
            LocalKeys.Use r = c.forDecrypt(key.id())) {}
        failing.set(true);
        f.advance(5);
        try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
        f.executor.run();
        Class<?> error = null;
        boolean read;
        try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {
          read = true;
        } catch (KmsException e) {
          read = false;
          error = e.getClass();
        }
        boolean write = c.currentWriteId().isPresent();
        failing.set(false); // certificate renewed / endpoint back
        f.advance(4); // age 9 of 10: the original copy would still be valid
        boolean recovered;
        try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {
          recovered = true;
        } catch (KmsException e) {
          recovered = false;
        }
        return new Outcome(read, write, recovered, error);
      } finally {
        client.close();
      }
    }
  }

  // Rejecting the server's certificate is an endpoint outage, not an object-access refusal.
  @Test
  void serverCertificateRejectionRetainsAuthorizationUntilItsOriginalExpiry() {
    Outcome outage = failedRefresh(() -> new java.net.ConnectException("Connection refused"));
    assertEquals(new Outcome(true, true, true, null), outage);
    Outcome tls = failedRefresh(LocalKeysRefreshFailureTest::serverCertificateExpired);
    assertEquals(new Outcome(true, true, true, null), tls);
  }

  // The internal supersession marker must be absent from caller and listener causes.
  @Test
  void supersededMarkerIsAbsentFromPublicCallerAndListenerChains() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      f.key();
      f.key(); // two Locate candidates: the batched Get Attributes path inside Kms.execute
      List<KmsEvent> failures = new CopyOnWriteArrayList<>();
      AtomicReference<LocalKeys> cache = new AtomicReference<>();
      Kms client =
          Kms.connect(
              f.server
                  .configure()
                  .retryPolicy(RetryPolicy.defaults())
                  .callTimeout(Duration.ofSeconds(2))
                  .addListener(
                      new KmsListener() {
                        @Override
                        public void finished(KmsEvent event) {
                          if (event.outcome() == KmsEvent.Outcome.FAILED) failures.add(event);
                        }
                      })
                  .transport(
                      e ->
                          request -> {
                            Ttlv response = f.server.exchange(request);
                            if (is(request, Operation.GET_ATTRIBUTES) && cache.get() != null)
                              cache.get().invalidateAll();
                            return response;
                          })
                  .build());
      try {
        LocalKeys.Builder b =
            client
                .keys()
                .localKeys(NAME)
                .scope(KeyQuery.all().custom(FAMILY, "orders"))
                .expect(Expect.aes(256))
                .ttl(TTL)
                .refreshExecutor(f.executor);
        b.ticker = f.time::get;
        LocalKeys c = f.keep(b.open());
        cache.set(c);
        TransientException caller = assertThrows(TransientException.class, c::forEncrypt);
        for (Throwable t = caller; t != null; t = t.getCause())
          assertFalse(t.getClass().getName().endsWith("Kms$Superseded"), "caller chain is clean");
        assertEquals(1, failures.size(), "one failed attempt, no protocol retry");
        Throwable cause = failures.get(0).failure().orElseThrow().getCause();
        assertNull(cause, "internal marker must not leak through the listener");
      } finally {
        client.close();
      }
    }
  }

  // An old ID's refusal invalidates the selector; the displaced write call is retryable.
  @Test
  void supersededWriteCallerGetsARetryableFailureAndReselects() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle old = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.advance(10); // both the write and its seeded read copy expired
      CountDownLatch[] g = LocalKeysRefreshSafetyTest.gate();
      AtomicBoolean first = new AtomicBoolean(true);
      f.before.set(
          r -> {
            if (is(r, Operation.GET) && first.compareAndSet(true, false)) {
              g[0].countDown();
              LocalKeysRefreshSafetyTest.await(g[1]);
            }
          });
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        Future<LocalKeys.Use> write = pool.submit(() -> c.forEncrypt());
        LocalKeysRefreshSafetyTest.await(g[0]); // write loader holds loadingId=old, at its Get
        KeyHandle next = f.key();
        old.deactivate();
        try (LocalKeys.Use read = c.forDecrypt(old.id())) {
          assertEquals(old.id(), read.id());
        }
        g[1].countDown();
        ExecutionException e =
            assertThrows(ExecutionException.class, () -> write.get(2, TimeUnit.SECONDS));
        TransientException retry = assertInstanceOf(TransientException.class, e.getCause());
        StateConflictException refusal =
            assertInstanceOf(StateConflictException.class, retry.getCause());
        assertEquals(Optional.of(KeyState.DEACTIVATED), refusal.observedState());
        try (LocalKeys.Use use = c.forEncrypt()) {
          assertEquals(next.id(), use.id());
        }
      } finally {
        g[1].countDown();
        pool.shutdownNow();
      }
    }
  }

  // Seeding never displaces a newer historical validation (equal/newer validatedAt is kept).
  @Test
  void holdsSeedingKeepsANewerHistoricalValidation() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      CountDownLatch[] g = LocalKeysRefreshSafetyTest.gate();
      AtomicBoolean first = new AtomicBoolean(true);
      f.before.set(
          r -> {
            if (is(r, Operation.GET) && first.compareAndSet(true, false)) {
              g[0].countDown();
              LocalKeysRefreshSafetyTest.await(g[1]);
            }
          });
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        Future<LocalKeys.Use> write =
            pool.submit(() -> c.forEncrypt()); // validation starts at t=100
        LocalKeysRefreshSafetyTest.await(g[0]);
        f.advance(3);
        try (LocalKeys.Use read = c.forDecrypt(key.id())) {
          assertEquals(key.id(), read.id());
        } // t=103
        g[1].countDown();
        try (LocalKeys.Use w = write.get(2, TimeUnit.SECONDS)) {
          assertEquals(key.id(), w.id());
        }
      } finally {
        g[1].countDown();
        pool.shutdownNow();
      }
      f.server.unreachable(true);
      f.advance(8); // t=111: write copy (start 100) expired, read copy (start 103) still valid
      assertThrows(TransientException.class, c::forEncrypt);
      try (LocalKeys.Use read = c.forDecrypt(key.id())) {
        assertEquals(key.id(), read.id());
      }
      f.advance(2); // t=113
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
    }
  }

  // Seeding never displaces a running historical validation: a third reader waits for it.
  @Test
  void holdsSeedingDoesNotDisplaceARunningHistoricalValidation() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      CountDownLatch[] g = LocalKeysRefreshSafetyTest.gate();
      AtomicBoolean first = new AtomicBoolean(true);
      f.before.set(
          r -> {
            if (is(r, Operation.GET) && first.compareAndSet(true, false)) {
              g[0].countDown();
              LocalKeysRefreshSafetyTest.await(g[1]);
            }
          });
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<LocalKeys.Use> read = pool.submit(() -> c.forDecrypt(key.id()));
        LocalKeysRefreshSafetyTest.await(g[0]); // historical flight running, at its Get
        try (LocalKeys.Use w = c.forEncrypt()) {
          assertEquals(key.id(), w.id());
        }
        Future<LocalKeys.Use> third = pool.submit(() -> c.forDecrypt(key.id()));
        assertThrows(
            TimeoutException.class,
            () -> third.get(300, TimeUnit.MILLISECONDS),
            "no seeded copy may be published over the running historical validation");
        g[1].countDown();
        try (LocalKeys.Use r = read.get(2, TimeUnit.SECONDS);
            LocalKeys.Use t = third.get(2, TimeUnit.SECONDS)) {
          assertEquals(key.id(), r.id());
          assertEquals(key.id(), t.id());
        }
      } finally {
        g[1].countDown();
        pool.shutdownNow();
      }
    }
  }

  // Seeding is skipped (write still succeeds) when every historical slot is loading.
  @Test
  void holdsSeedingIsSkippedWhenHistoricalCapacityIsAllLoading() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key(), other = f.key(256, "orders", null, KeyUsage.DECRYPT);
      LocalKeys c = f.keep(f.builder().capacity(2).open()); // one historical slot
      CountDownLatch[] g = LocalKeysRefreshSafetyTest.gate();
      f.before.set(
          r -> {
            if (is(r, Operation.GET) && other.id().equals(id(r))) {
              g[0].countDown();
              LocalKeysRefreshSafetyTest.await(g[1]);
            }
          });
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        Future<LocalKeys.Use> read = pool.submit(() -> c.forDecrypt(other.id()));
        LocalKeysRefreshSafetyTest.await(g[0]);
        try (LocalKeys.Use w = c.forEncrypt()) {
          assertEquals(key.id(), w.id());
        }
        g[1].countDown();
        try (LocalKeys.Use r = read.get(2, TimeUnit.SECONDS)) {
          assertEquals(other.id(), r.id());
        }
      } finally {
        g[1].countDown();
        pool.shutdownNow();
      }
      f.server.unreachable(true);
      // No seeded copy: the historical read would need the (unreachable) server.
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
      try (LocalKeys.Use w = c.forEncrypt()) {
        assertEquals(key.id(), w.id());
      }
    }
  }

  // Once any call has observed X Compromised, no later-starting call may return X, under write
  // refresh, write-to-read seeding, capacity eviction, invalidation and rotation churn.
  @Test
  void holdsNoCompromisedResurrectionUnderSeedingChurn() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      List<KeyHandle> keys = new ArrayList<>();
      for (int i = 0; i < 10; i++)
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
              .ttl(Duration.ofMillis(400))
              .refreshAfter(Duration.ofMillis(5))
              .capacity(4)
              .refreshExecutor(refresh);
      LocalKeys c = f.keep(b.open());
      Set<String> observedCompromised = ConcurrentHashMap.newKeySet();
      AtomicBoolean stop = new AtomicBoolean();
      List<Throwable> unexpected = new CopyOnWriteArrayList<>();
      AtomicInteger uses = new AtomicInteger(), seen = new AtomicInteger();
      ExecutorService pool = Executors.newFixedThreadPool(8);
      List<Future<?>> workers = new ArrayList<>();
      for (int t = 0; t < 8; t++) {
        int seed = t;
        workers.add(
            pool.submit(
                () -> {
                  Random random = new Random(seed);
                  while (!stop.get()) {
                    Set<String> before = Set.copyOf(observedCompromised);
                    try {
                      int op = random.nextInt(40);
                      if (op == 0) c.invalidate(keys.get(random.nextInt(keys.size())).id());
                      else
                        try (LocalKeys.Use use =
                            op < 16
                                ? c.forEncrypt()
                                : c.forDecrypt(keys.get(random.nextInt(keys.size())).id())) {
                          if (!Arrays.equals(material.get(use.id()), use.key().getEncoded()))
                            unexpected.add(
                                new AssertionError("material does not belong to " + use.id()));
                          if (before.contains(use.id()))
                            unexpected.add(
                                new AssertionError("resurrected compromised " + use.id()));
                          uses.incrementAndGet();
                        }
                    } catch (StateConflictException s) {
                      if (s.observedState().orElse(null) == KeyState.COMPROMISED
                          && s.objectId().isPresent()) {
                        observedCompromised.add(s.objectId().get());
                        seen.incrementAndGet();
                      }
                    } catch (KmsException expected) {
                      // Transient races, backoff, ambiguity and capacity are permitted outcomes.
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
                int current = 0, compromised = 0;
                while (!stop.get()) {
                  int next = 1 + random.nextInt(keys.size() - 1);
                  KeyHandle k = keys.get(next);
                  if (next == current || f.server.state(k.id()).orElse(null) != KeyState.ACTIVE)
                    continue;
                  k.addName(NAME);
                  KeyHandle previous = keys.get(current);
                  previous.removeName(NAME);
                  // Compromise the outgoing write key while its copies are still seeded and cached.
                  if (compromised < 6 && random.nextBoolean()) {
                    previous.revoke(RevocationReason.keyCompromise("probe", Instant.now()));
                    compromised++;
                  }
                  current = next;
                  try {
                    Thread.sleep(40);
                  } catch (InterruptedException e) {
                    return;
                  }
                }
              });
      rotator.start();
      Thread.sleep(2000);
      stop.set(true);
      rotator.join(2000);
      for (Future<?> w : workers) w.get(5, TimeUnit.SECONDS); // a lock cycle would time out here
      pool.shutdownNow();
      refresh.shutdownNow();
      assertTrue(unexpected.isEmpty(), () -> unexpected.toString());
      assertTrue(uses.get() > 100, "made progress: " + uses.get());
      assertTrue(seen.get() > 0, "observed at least one compromise");
    }
  }

  // Once a call has received X's Compromised refusal, a call that starts later must not get X from
  // another slot. The refusal of X reaches X's read slot first and the write slot last. Here it
  // pauses at its first slot: a read call sees the refusal there, then a write call starts. The
  // refusal comes from a read refresh (false) or from a write refresh's selection (true).
  @ParameterizedTest
  @org.junit.jupiter.params.provider.ValueSource(booleans = {false, true})
  void holdsNoCompromisedHandoutWhileTheRefusalReachesEachSlot(boolean bySelection)
      throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      CountDownLatch[] reading = LocalKeysRefreshSafetyTest.gate();
      CountDownLatch[] refusing = LocalKeysRefreshSafetyTest.gate();
      AtomicReference<Thread> reader = new AtomicReference<>(), refuser = new AtomicReference<>();
      LocalKeys.Builder b = f.builder();
      b.ticker =
          () -> {
            Thread t = Thread.currentThread();
            if (t == reader.get() || t == refuser.get()) {
              List<String> at = LocalKeysHitPathConcurrencyTest.frames();
              // The read call, after reserving X's slot and reading its displacement count.
              if (at.size() > 1
                  && at.subList(0, 2).equals(List.of("sweep", "hit"))
                  && reader.compareAndSet(t, null)) {
                reading[0].countDown();
                LocalKeysRefreshSafetyTest.await(reading[1]);
              }
              // The refusal, inside its first slot's retirement.
              if (!at.isEmpty() && at.get(0).equals("retire") && refuser.compareAndSet(t, null)) {
                refusing[0].countDown();
                LocalKeysRefreshSafetyTest.await(refusing[1]);
              }
            }
            return f.time.get();
          };
      LocalKeys c = f.keep(b.open());
      try (LocalKeys.Use w = c.forEncrypt()) { // also seeds X's read slot
        assertEquals(key.id(), w.id());
      }
      f.advance(6); // past refreshAfter, within the TTL
      if (bySelection) {
        // The write refresh's Locate still lists X; X is Compromised when its attributes are read.
        f.after.set(
            (r, p) -> {
              if (is(r, Operation.LOCATE)) {
                f.after.set((r2, p2) -> p2);
                key.revoke(RevocationReason.keyCompromise("probe", Instant.now()));
              }
              return p;
            });
        c.forEncrypt().close(); // a hit that queues the write refresh
      } else {
        c.forDecrypt(key.id()).close(); // a hit that queues X's read refresh
        key.revoke(RevocationReason.keyCompromise("probe", Instant.now()));
      }
      assertEquals(1, f.executor.queue.size());
      ExecutorService pool = Executors.newCachedThreadPool();
      try {
        Future<StateConflictException> read =
            pool.submit(
                () -> {
                  reader.set(Thread.currentThread());
                  return assertThrows(StateConflictException.class, () -> c.forDecrypt(key.id()));
                });
        LocalKeysRefreshSafetyTest.await(reading[0]);
        Future<?> refusal =
            pool.submit(
                () -> {
                  refuser.set(Thread.currentThread());
                  f.executor.run();
                });
        LocalKeysRefreshSafetyTest.await(refusing[0]);
        reading[1].countDown();
        StateConflictException seen = read.get(2, TimeUnit.SECONDS);
        assertEquals(KeyState.COMPROMISED, seen.observedState().orElseThrow());
        assertEquals(key.id(), seen.objectId().orElseThrow());
        Future<String> write =
            pool.submit(
                () -> {
                  try (LocalKeys.Use u = c.forEncrypt()) {
                    return u.id();
                  } catch (KmsException refused) {
                    return null;
                  }
                });
        try {
          write.get(300, TimeUnit.MILLISECONDS); // returns at once if the write slot still had X
        } catch (TimeoutException waiting) {
          // It waits for the refusal to finish.
        }
        refusing[1].countDown();
        refusal.get(2, TimeUnit.SECONDS);
        assertNotEquals(key.id(), write.get(2, TimeUnit.SECONDS));
      } finally {
        reading[1].countDown();
        refusing[1].countDown();
        pool.shutdownNow();
      }
    }
  }
}
