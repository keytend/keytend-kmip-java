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

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** External lifecycle, password-cache-style refresh, exact-ID historical use and cache safety. */
class LocalKeysTest {
  static final String NAME = "sstable-write";
  static final CustomAttribute FAMILY = CustomAttribute.client("tde-family");
  static final Duration TTL = Duration.ofSeconds(10);

  static final class QueueExecutor implements Executor {
    final Queue<Runnable> queue = new ConcurrentLinkedQueue<>();

    @Override
    public void execute(Runnable r) {
      queue.add(r);
    }

    void run() {
      Runnable r = queue.poll();
      assertNotNull(r);
      r.run();
    }
  }

  static final class Fixture implements AutoCloseable {
    final InMemoryKmipServer server;
    final Kms admin, client;
    final AtomicLong time = new AtomicLong(100);
    final QueueExecutor executor = new QueueExecutor();
    final List<LocalKeys> caches = new ArrayList<>();
    final AtomicReference<Consumer<Ttlv>> before = new AtomicReference<>(r -> {});
    final AtomicReference<BiFunction<Ttlv, Ttlv, Ttlv>> after = new AtomicReference<>((r, p) -> p);

    Fixture(KmipVersion version) {
      this(version, RetryPolicy.none());
    }

    Fixture(KmipVersion version, RetryPolicy retryPolicy) {
      this(version, retryPolicy, new KmsListener() {});
    }

    Fixture(KmipVersion version, RetryPolicy retryPolicy, KmsListener listener) {
      server = InMemoryKmipServer.of(version);
      admin = server.connect();
      client =
          Kms.connect(
              server
                  .configure()
                  .retryPolicy(retryPolicy)
                  .callTimeout(Duration.ofSeconds(2))
                  .addListener(listener)
                  .transport(
                      e ->
                          request -> {
                            before.get().accept(request);
                            return after.get().apply(request, server.exchange(request));
                          })
                  .build());
    }

    KeyHandle key() {
      return key(256, "orders", NAME, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
    }

    KeyHandle key(int bits, String family, String name, KeyUsage... usages) {
      KeyCreation c =
          admin.keys().createAes(bits).extractable(true).custom(FAMILY, family).usages(usages);
      if (name != null) c.named(name);
      return c.create();
    }

    LocalKeys.Builder builder() {
      LocalKeys.Builder b =
          client
              .keys()
              .localKeys(NAME)
              .scope(KeyQuery.all().custom(FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(TTL)
              .refreshExecutor(executor);
      b.ticker = time::get;
      return b;
    }

    LocalKeys cache() {
      return keep(builder().open());
    }

    LocalKeys keep(LocalKeys cache) {
      caches.add(cache);
      return cache;
    }

    void advance(long seconds) {
      time.addAndGet(TimeUnit.SECONDS.toNanos(seconds));
    }

    @Override
    public void close() {
      caches.forEach(LocalKeys::close);
      client.close();
      admin.close();
      server.close();
    }
  }

  static boolean is(Ttlv request, Operation op) {
    return RotationAndNameChoiceTest.isOperation(request, op);
  }

  static String id(Ttlv request) {
    return KeyPolicyTest.target(request);
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void externalUnlinkedRotationRewritesDataAndHistoricalRemovalIsObserved(KmipVersion version)
      throws Exception {
    try (Fixture f = new Fixture(version)) {
      KeyHandle old = f.key();
      LocalKeys c = f.cache();
      byte[] plaintext =
          "persisted SSTable chunk".getBytes(java.nio.charset.StandardCharsets.UTF_8);
      byte[] iv = new byte[12];
      Arrays.fill(iv, (byte) 7);
      byte[] encrypted;
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(old.id(), use.id());
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, use.key(), new GCMParameterSpec(128, iv));
        encrypted = cipher.doFinal(plaintext);
      }
      // No SDK rotation call, replacement link, scheduled deactivation or automatic key creation.
      old.deactivate();
      old.removeName(NAME);
      KeyHandle next = f.key();
      assertTrue(next.attributes().links().isEmpty());
      f.advance(5);
      try (LocalKeys.Use stillValid = c.forEncrypt()) {
        assertEquals(old.id(), stillValid.id());
      }
      assertEquals(1, f.executor.queue.size());
      f.executor.run();
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(next.id(), use.id());
      }
      try (LocalKeys.Use use = c.forDecrypt(old.id())) {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, use.key(), new GCMParameterSpec(128, iv));
        assertArrayEquals(plaintext, cipher.doFinal(encrypted));
      }
      old.destroy();
      f.advance(10);
      assertEquals(
          KeyState.DESTROYED,
          assertThrows(StateConflictException.class, () -> c.forDecrypt(old.id()))
              .observedState()
              .orElseThrow());
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(next.id(), use.id());
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void cacheHitsNeverExtendAgeAndAnOutageCannotCrossTheHardExpiry(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
      int exchanges = f.server.exchanges();
      for (int i = 0; i < 1000; i++) try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      assertEquals(exchanges, f.server.exchanges());
      f.advance(5);
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      assertEquals(1, f.executor.queue.size());
      for (int i = 0; i < 20; i++) try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      assertEquals(1, f.executor.queue.size(), "one refresh");
      f.server.unreachable(true);
      f.executor.run();
      f.advance(4);
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      f.advance(1);
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
      f.server.unreachable(false);
      f.advance(1);
      // A queued refresh may remain from a valid hit at +9; execute it before the expired caller.
      if (!f.executor.queue.isEmpty()) f.executor.run();
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anObservedCompromiseEvictsBothPurposesImmediatelyAndSurvivesAnOutage(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use ignored = c.forEncrypt();
          LocalKeys.Use ignored2 = c.forDecrypt(key.id())) {}
      key.revoke(RevocationReason.keyCompromise("test", Instant.now()));
      f.advance(5);
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      f.executor.run();
      assertThrows(StateConflictException.class, () -> c.forDecrypt(key.id()));
      assertThrows(KmsException.class, c::forEncrypt);
      assertTrue(c.currentWriteId().isEmpty());
      f.server.unreachable(true);
      assertThrows(KmsException.class, c::forEncrypt);
    }
  }

  @Test
  void writesFailWithoutAReplacementButDeactivatedHistoryStillDecrypts() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use ignored = c.forEncrypt();
          LocalKeys.Use ignored2 = c.forDecrypt(key.id())) {}
      key.deactivate();
      f.advance(5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.executor.run();
      assertThrows(NotFoundException.class, c::forEncrypt);
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
    }
  }

  @Test
  void ambiguousColdSelectionFailsAndWarmSelectionDoesNotFlap() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle first = f.key();
      LocalKeys warm = f.cache();
      try (LocalKeys.Use ignored = warm.forEncrypt()) {}
      KeyHandle second = f.key();
      LocalKeys cold = f.cache();
      StateConflictException failure = assertThrows(StateConflictException.class, cold::forEncrypt);
      assertTrue(failure.getMessage().contains(first.id()));
      assertTrue(failure.getMessage().contains(second.id()));
      f.advance(5);
      try (LocalKeys.Use ignored = warm.forEncrypt()) {}
      f.executor.run();
      try (LocalKeys.Use use = warm.forEncrypt()) {
        assertEquals(first.id(), use.id());
      }
      first.deactivate();
      warm.invalidate(first.id());
      try (LocalKeys.Use use = warm.forEncrypt()) {
        assertEquals(second.id(), use.id());
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void historyScopeSizeAndUsageAreCheckedBeforeFetching(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      LocalKeys c = f.cache();
      List<KeyHandle> bad =
          List.of(
              f.key(256, "elsewhere", null, KeyUsage.DECRYPT),
              f.key(128, "orders", null, KeyUsage.DECRYPT),
              f.key(256, "orders", null, KeyUsage.ENCRYPT));
      AtomicInteger gets = new AtomicInteger();
      f.before.set(
          r -> {
            if (is(r, Operation.GET)) gets.incrementAndGet();
          });
      for (KeyHandle k : bad) assertThrows(KeyMismatchException.class, () -> c.forDecrypt(k.id()));
      assertEquals(0, gets.get());
      int exchanges = f.server.exchanges();
      for (KeyHandle k : bad) assertThrows(KeyMismatchException.class, () -> c.forDecrypt(k.id()));
      assertEquals(exchanges, f.server.exchanges(), "bounded negative cache");
    }
  }

  /**
   * A scope narrowed to a manifest ({@code scope.ids(...)}) keeps its custom-attribute boundary: a
   * listed key of another family is refused. While {@code KeyQuery.ids(String...)} was static, the
   * same call dropped the boundary and the other family's key was handed out.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aManifestOnTheScopeKeepsItsBoundary(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle own = f.key(256, "orders", null, KeyUsage.DECRYPT);
      KeyHandle other = f.key(256, "elsewhere", null, KeyUsage.DECRYPT);
      LocalKeys c =
          f.keep(
              f.builder()
                  .scope(KeyQuery.all().custom(FAMILY, "orders").ids(own.id(), other.id()))
                  .open());
      try (LocalKeys.Use use = c.forDecrypt(own.id())) {
        assertEquals(own.id(), use.id());
      }
      assertThrows(KeyMismatchException.class, () -> c.forDecrypt(other.id()));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void ungrantedLeaseAndUsageLimitsAreRefusedBeforeGetIncludingMalformedLease(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      AtomicInteger gets = new AtomicInteger();
      f.before.set(
          r -> {
            if (is(r, Operation.GET)) gets.incrementAndGet();
          });
      for (Ttlv obligation :
          List.of(
              Ttlv.interval(Tag.LEASE_TIME, 300),
              Ttlv.interval(Tag.LEASE_TIME, 0),
              Ttlv.integer(Tag.LEASE_TIME, 300),
              Ttlv.structure(Tag.USAGE_LIMITS))) {
        c.invalidateAll();
        f.after.set((r, p) -> is(r, Operation.GET_ATTRIBUTES) ? addAttribute(p, obligation) : p);
        // The in-memory server does not implement Obtain Lease: no lease, so no Get.
        assertThrows(UnsupportedException.class, () -> c.forDecrypt(key.id()));
      }
      assertEquals(0, gets.get());
    }
  }

  static Ttlv addAttribute(Ttlv reply, Ttlv attribute) {
    return KeyPolicyTest.rewrite(
        reply,
        node -> {
          if (node.tag() == Tag.ATTRIBUTES.code()) {
            List<Ttlv> fields = new ArrayList<>(node.children());
            fields.add(attribute);
            return Ttlv.structure(Tag.ATTRIBUTES, fields);
          }
          if (node.tag() == Tag.RESPONSE_PAYLOAD.code()
              && !node.children(Tag.ATTRIBUTE).isEmpty()) {
            List<Ttlv> fields = new ArrayList<>(node.children());
            String n = attribute.tag() == Tag.LEASE_TIME.code() ? "Lease Time" : "Usage Limits";
            fields.add(Attributes.attribute(n, attribute));
            return Ttlv.structure(Tag.RESPONSE_PAYLOAD, fields);
          }
          return node;
        });
  }

  @Test
  void getPermissionRemovalIsDetectedEvenWhenAttributesRemainReadable() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use ignored = c.forEncrypt();
          LocalKeys.Use ignored2 = c.forDecrypt(key.id())) {}
      f.before.set(
          r -> {
            if (is(r, Operation.GET)) throw new PermissionDeniedException("Get permission removed");
          });
      f.advance(5);
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      f.executor.run();
      assertThrows(PermissionDeniedException.class, () -> c.forDecrypt(key.id()));
      assertThrows(PermissionDeniedException.class, c::forEncrypt);
    }
  }

  @Test
  void invalidationAndCloseSupersedeQueuedLoadsAndCopiesRemainCallerOwned() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      LocalKeys.Use handed = c.forEncrypt();
      byte[] bytes = handed.key().getEncoded();
      f.advance(5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      assertEquals(1, f.executor.queue.size());
      c.invalidateAll();
      f.executor.run();
      assertTrue(c.currentWriteId().isEmpty());
      assertArrayEquals(bytes, handed.key().getEncoded());
      c.close();
      assertThrows(IllegalStateException.class, c::forEncrypt);
      assertArrayEquals(bytes, handed.key().getEncoded());
      handed.close();
      assertTrue(handed.key().isDestroyed());
      Arrays.fill(bytes, (byte) 0);
      assertFalse(
          f.client.keys().list(KeyQuery.byName(NAME)).isEmpty(), "cache never owns Kms/server key");
    }
  }

  @Test
  void concurrentMissIsSingleFlightAndRevalidationWaitRespectsDeadline() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
      AtomicInteger gets = new AtomicInteger();
      f.before.set(
          r -> {
            if (is(r, Operation.GET)) {
              gets.incrementAndGet();
              entered.countDown();
              try {
                assertTrue(release.await(3, TimeUnit.SECONDS));
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError(e);
              }
            }
          });
      ExecutorService pool = Executors.newFixedThreadPool(4);
      try {
        Future<LocalKeys.Use> one = pool.submit(() -> c.forDecrypt(key.id()));
        assertTrue(entered.await(1, TimeUnit.SECONDS));
        Future<LocalKeys.Use> two = pool.submit(() -> c.forDecrypt(key.id()));
        release.countDown();
        try (LocalKeys.Use a = one.get(2, TimeUnit.SECONDS);
            LocalKeys.Use b = two.get(2, TimeUnit.SECONDS)) {
          assertEquals(a.id(), b.id());
          assertNotSame(a.key(), b.key());
        }
        assertEquals(1, gets.get());
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  enum Invalidation {
    ID,
    ALL,
    CLOSE
  }

  @ParameterizedTest
  @EnumSource(
      value = KeyState.class,
      names = {"COMPROMISED", "DEACTIVATED"})
  void aHistoricalObservationSupersedesTheFirstWriteLoadBeforeItPublishes(KeyState state)
      throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      CountDownLatch fetched = new CountDownLatch(1), release = new CountDownLatch(1);
      AtomicBoolean first = new AtomicBoolean(true);
      f.after.set(
          (request, response) -> {
            if (is(request, Operation.GET) && first.compareAndSet(true, false)) {
              fetched.countDown();
              try {
                assertTrue(release.await(3, TimeUnit.SECONDS));
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError(e);
              }
            }
            return response;
          });
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        Future<LocalKeys.Use> write = pool.submit(() -> c.forEncrypt());
        assertTrue(fetched.await(1, TimeUnit.SECONDS));
        if (state == KeyState.COMPROMISED) {
          key.revoke(RevocationReason.keyCompromise("test", Instant.now()));
          assertThrows(StateConflictException.class, () -> c.forDecrypt(key.id()));
        } else {
          key.deactivate();
          try (LocalKeys.Use use = c.forDecrypt(key.id())) {
            assertEquals(key.id(), use.id());
          }
        }
        release.countDown();
        ExecutionException refused =
            assertThrows(ExecutionException.class, () -> write.get(1, TimeUnit.SECONDS));
        TransientException retry = assertInstanceOf(TransientException.class, refused.getCause());
        assertInstanceOf(StateConflictException.class, retry.getCause());
        assertTrue(c.currentWriteId().isEmpty());
        f.server.unreachable(true);
        assertThrows(KmsException.class, c::forEncrypt);
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @ParameterizedTest
  @EnumSource(Invalidation.class)
  void invalidationDiscardsAnActuallyRunningRefresh(Invalidation action) throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
      f.before.set(
          request -> {
            if (is(request, Operation.GET)) {
              entered.countDown();
              try {
                assertTrue(release.await(3, TimeUnit.SECONDS));
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError(e);
              }
            }
          });
      f.advance(5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        Future<?> refresh = pool.submit(f.executor::run);
        assertTrue(entered.await(1, TimeUnit.SECONDS));
        switch (action) {
          case ID -> c.invalidate(key.id());
          case ALL -> c.invalidateAll();
          case CLOSE -> c.close();
        }
        release.countDown();
        refresh.get(1, TimeUnit.SECONDS);
        if (action == Invalidation.CLOSE) assertThrows(IllegalStateException.class, c::forEncrypt);
        else {
          assertTrue(c.currentWriteId().isEmpty(), "late refresh must not publish");
          f.before.set(request -> {});
          f.server.unreachable(true);
          assertThrows(TransientException.class, c::forEncrypt);
        }
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void aNewWriteKeyLoadsWithoutBlockingUsesOfTheStillValidSelection() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle old = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      old.removeName(NAME); // The held key remains Active; the selector's name moves externally.
      KeyHandle next = f.key();
      CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
      f.before.set(
          request -> {
            if (is(request, Operation.GET) && next.id().equals(id(request))) {
              entered.countDown();
              try {
                assertTrue(release.await(3, TimeUnit.SECONDS));
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new AssertionError(e);
              }
            }
          });
      f.advance(5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<?> refresh = pool.submit(f.executor::run);
        assertTrue(entered.await(1, TimeUnit.SECONDS));
        Future<LocalKeys.Use> hit = pool.submit(() -> c.forEncrypt());
        try (LocalKeys.Use use = hit.get(500, TimeUnit.MILLISECONDS)) {
          assertEquals(old.id(), use.id());
        }
        assertEquals(old.id(), c.currentWriteId().orElseThrow());
        release.countDown();
        refresh.get(1, TimeUnit.SECONDS);
        try (LocalKeys.Use use = c.forEncrypt()) {
          assertEquals(next.id(), use.id());
        }
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void handedOffKeysRemainUsableBySunJceAfterTheProviderReturnsAndCacheCloses() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      f.key();
      LocalKeys c = f.cache();
      LocalKeys.Use use = c.forEncrypt();
      DestroyableSecretKey handedOff = use.key(); // Ownership goes to the receiving caller.
      c.close();
      assertEquals("AES", handedOff.getAlgorithm());
      assertEquals("RAW", handedOff.getFormat());
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "SunJCE");
      try {
        cipher.init(Cipher.ENCRYPT_MODE, handedOff, new GCMParameterSpec(128, new byte[12]));
        assertEquals(19, cipher.doFinal(new byte[3]).length);
      } finally {
        handedOff.destroy();
      }
      assertTrue(use.key().isDestroyed());
    }
  }

  @Test
  void closeLeavesTheCallerExecutorUsable() throws Exception {
    ExecutorService executor = Executors.newSingleThreadExecutor();
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      LocalKeys c = f.keep(f.builder().refreshExecutor(executor).open());
      c.close();
      assertFalse(executor.isShutdown());
      assertEquals(7, executor.submit(() -> 7).get(1, TimeUnit.SECONDS));
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  void accessDenialDuringRefreshNeverResurrectsAfterTheNextOutage() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      f.before.set(
          r -> {
            if (is(r, Operation.GET)) throw new PermissionDeniedException("removed");
          });
      f.advance(5);
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      f.executor.run();
      f.server.unreachable(true);
      assertThrows(PermissionDeniedException.class, () -> c.forDecrypt(key.id()));
      f.before.set(r -> {});
      f.advance(10);
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
    }
  }

  @Test
  void hardExpiryTakesOverAQueuedRefreshAndDiscardsItsLateResult() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      f.key();
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
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.advance(5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      assertEquals(1, f.executor.queue.size());
      f.advance(5);
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertTrue(c.currentWriteId().isPresent());
      }
      f.executor.run(); // The old queued task must not replace the synchronous validation.
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
    }
  }

  @Test
  void changedMaterialForARetainedIdInvalidatesBothPurposes() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use ignored = c.forEncrypt();
          LocalKeys.Use ignored2 = c.forDecrypt(key.id())) {}
      f.after.set(
          (r, p) ->
              is(r, Operation.GET)
                  ? KeyPolicyTest.rewrite(
                      p,
                      node ->
                          node.tag() == Tag.KEY_MATERIAL.code()
                                  && node.type() == Ttlv.Type.BYTE_STRING
                              ? Ttlv.bytes(Tag.KEY_MATERIAL, new byte[node.bytesValue().length])
                              : node)
                  : p);
      f.advance(5);
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      f.executor.run();
      assertThrows(KeyMismatchException.class, () -> c.forDecrypt(key.id()));
      assertThrows(KeyMismatchException.class, c::forEncrypt);
    }
  }

  @Test
  void aColdHistoricalReadAlsoChecksMaterialAlreadyHeldForWriting() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key(), other = f.key(256, "orders", null, KeyUsage.DECRYPT);
      LocalKeys c = f.keep(f.builder().capacity(2).open());
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      // Evict the seeded read copy, retaining the pinned write fingerprint.
      try (LocalKeys.Use ignored = c.forDecrypt(other.id())) {}
      f.after.set(
          (r, p) ->
              is(r, Operation.GET)
                  ? KeyPolicyTest.rewrite(
                      p,
                      node ->
                          node.tag() == Tag.KEY_MATERIAL.code()
                                  && node.type() == Ttlv.Type.BYTE_STRING
                              ? Ttlv.bytes(Tag.KEY_MATERIAL, new byte[node.bytesValue().length])
                              : node)
                  : p);
      assertThrows(KeyMismatchException.class, () -> c.forDecrypt(key.id()));
      assertThrows(KeyMismatchException.class, c::forEncrypt);
    }
  }

  @Test
  void theLoadersLaterAttributesCanAddAnObligationBeforeAnyGet() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      f.key();
      LocalKeys c = f.cache();
      AtomicInteger reads = new AtomicInteger(), gets = new AtomicInteger();
      f.before.set(
          r -> {
            if (is(r, Operation.GET)) gets.incrementAndGet();
          });
      // The selection's read is also the loader's: the obligation it adds is checked before Get.
      f.after.set(
          (r, p) ->
              is(r, Operation.GET_ATTRIBUTES) && reads.incrementAndGet() == 1
                  ? addAttribute(p, Ttlv.structure(Tag.USAGE_LIMITS))
                  : p);
      assertThrows(UnsupportedException.class, c::forEncrypt);
      assertEquals(0, gets.get());
    }
  }

  @Test
  void validationTimeCountsAgainstTtlAndCannotPublishAnAlreadyExpiredKey() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      f.before.set(
          r -> {
            if (is(r, Operation.GET)) f.advance(10);
          });
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
      assertTrue(c.currentWriteId().isEmpty());
    }
  }

  @Test
  void boundedCapacityEvictsAndALaterAccessReallyRevalidates() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key(), b = f.key(256, "orders", null, KeyUsage.DECRYPT);
      LocalKeys c = f.keep(f.builder().capacity(2).open());
      AtomicInteger gets = new AtomicInteger();
      f.before.set(
          r -> {
            if (is(r, Operation.GET)) gets.incrementAndGet();
          });
      try (LocalKeys.Use ignored = c.forDecrypt(a.id())) {}
      try (LocalKeys.Use ignored = c.forDecrypt(b.id())) {}
      try (LocalKeys.Use ignored = c.forDecrypt(a.id())) {}
      assertEquals(3, gets.get());
    }
  }

  @Test
  void rejectedRefreshWorkDoesNotExtendTtlAndExpiredLoadsNeedNoExecutor() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      f.key();
      LocalKeys c =
          f.keep(
              f.builder()
                  .refreshExecutor(
                      r -> {
                        throw new RejectedExecutionException();
                      })
                  .open());
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.advance(5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.advance(5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.advance(5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.server.unreachable(true);
      f.advance(5);
      assertThrows(TransientException.class, c::forEncrypt);
    }
  }

  @Test
  void localCacheMakesNoServerMutationsAndMissesNeverCreateKeys() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      LocalKeys c = f.cache();
      f.before.set(
          r -> {
            for (Ttlv item : r.children(Tag.BATCH_ITEM)) {
              int op = item.require(Tag.OPERATION).intValue();
              assertTrue(
                  op == Operation.LOCATE.code()
                      || op == Operation.GET_ATTRIBUTES.code()
                      || op == Operation.GET.code(),
                  "unexpected operation " + op);
            }
          });
      assertThrows(NotFoundException.class, c::forEncrypt);
      assertThrows(NotFoundException.class, () -> c.forDecrypt("not-an-id"));
    }
  }

  @Test
  void configurationRequiresStableScopeAndExpectation() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      LocalKeys defaults = f.cache();
      assertEquals(TTL, defaults.ttl());
      assertEquals(TTL.dividedBy(2), defaults.refreshAfter());
      LocalKeys configured = f.keep(f.builder().refreshAfter(Duration.ofSeconds(3)).open());
      assertEquals(Duration.ofSeconds(3), configured.refreshAfter());
      assertThrows(IllegalStateException.class, () -> f.client.keys().localKeys(NAME).open());
      assertThrows(IllegalArgumentException.class, () -> f.builder().scope(KeyQuery.all()));
      assertThrows(
          IllegalArgumentException.class,
          () -> f.builder().scope(KeyQuery.byName(NAME).custom(FAMILY, "orders")));
      assertThrows(
          IllegalArgumentException.class,
          () -> f.builder().scope(KeyQuery.all().custom(FAMILY, "orders").state(KeyState.ACTIVE)));
      assertThrows(IllegalArgumentException.class, () -> f.builder().capacity(1));
      assertThrows(IllegalArgumentException.class, () -> f.builder().ttl(Duration.ZERO));
      assertThrows(IllegalArgumentException.class, () -> f.builder().refreshAfter(TTL).open());
    }
  }
}
