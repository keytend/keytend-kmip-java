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
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

/**
 * {@link LocalKeys}' diagnostic callbacks: a selection only when a write selection is committed for
 * the first time or changes; a refresh failure once per refresh that actually failed; both outside
 * the cache's locks and call scope, never able to change authorization.
 */
class LocalKeysListenerTest {
  record Selected(String name, String previousId, String newId) {}

  record RefreshFailed(
      String name, String keyId, LocalUse purpose, KmsException failure, Duration remaining) {}

  static final class Recorder implements KmsListener {
    final List<Selected> selected = new CopyOnWriteArrayList<>();
    final List<RefreshFailed> failed = new CopyOnWriteArrayList<>();
    volatile Consumer<Object> during = e -> {};

    @Override
    public void localKeySelected(String name, String previousId, String newId) {
      Selected e = new Selected(name, previousId, newId);
      selected.add(e);
      during.accept(e);
    }

    @Override
    public void localKeyRefreshFailed(
        String name,
        String keyId,
        LocalUse purpose,
        KmsException failure,
        Duration remainingValidity) {
      RefreshFailed e = new RefreshFailed(name, keyId, purpose, failure, remainingValidity);
      failed.add(e);
      during.accept(e);
    }
  }

  private static void use(LocalKeys c) {
    try (LocalKeys.Use ignored = c.forEncrypt()) {}
  }

  private static void use(LocalKeys c, String id) {
    try (LocalKeys.Use ignored = c.forDecrypt(id)) {}
  }

  @Test
  void selectionIsReportedOnceForTheFirstCommitAndOncePerChange() {
    Recorder r = new Recorder();
    try (Fixture f = new Fixture(KmipVersion.V2_1, RetryPolicy.none(), r)) {
      KeyHandle x = f.key();
      LocalKeys c = f.cache();
      for (int i = 0; i < 5; i++) use(c);
      assertEquals(List.of(new Selected(NAME, null, x.id())), r.selected);
      f.advance(5);
      use(c);
      f.executor.run(); // Revalidation keeps x: no callback.
      use(c, x.id());
      assertEquals(1, r.selected.size());
      x.removeName(NAME);
      KeyHandle y = f.key();
      f.advance(5);
      use(c);
      f.executor.run();
      assertEquals(
          List.of(new Selected(NAME, null, x.id()), new Selected(NAME, x.id(), y.id())),
          r.selected);
      c.invalidateAll();
      use(c); // Cold reselection of the same key is not a change.
      assertEquals(2, r.selected.size());
      assertEquals(List.of(), r.failed);
    }
  }

  @Test
  void aSupersededRefreshReportsNeitherSelectionNorFailure() throws Exception {
    Recorder r = new Recorder();
    try (Fixture f = new Fixture(KmipVersion.V2_1, RetryPolicy.none(), r)) {
      KeyHandle x = f.key();
      LocalKeys c = f.cache();
      use(c);
      x.removeName(NAME);
      KeyHandle y = f.key();
      CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
      f.before.set(
          q -> {
            if (is(q, Operation.GET) && y.id().equals(id(q))) {
              entered.countDown();
              await(release);
            }
          });
      f.advance(5);
      use(c);
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        Future<?> refresh = pool.submit(f.executor::run);
        await(entered);
        c.invalidateAll();
        release.countDown();
        refresh.get(5, TimeUnit.SECONDS);
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
      assertEquals(List.of(new Selected(NAME, null, x.id())), r.selected);
      assertEquals(List.of(), r.failed);
      f.before.set(q -> {});
      use(c);
      assertEquals(new Selected(NAME, x.id(), y.id()), r.selected.get(1));
      assertEquals(2, r.selected.size());
    }
  }

  @Test
  void aFailedBackgroundRefreshIsReportedOnceWithTheRemainingValidity() {
    Recorder r = new Recorder();
    try (Fixture f = new Fixture(KmipVersion.V2_1, RetryPolicy.none(), r)) {
      KeyHandle x = f.key();
      LocalKeys c = f.cache();
      use(c);
      use(c, x.id());
      f.server.unreachable(true);
      f.advance(5);
      use(c);
      use(c, x.id());
      assertEquals(2, f.executor.queue.size());
      f.executor.run();
      f.executor.run();
      assertEquals(2, r.failed.size());
      RefreshFailed write = r.failed.get(0), read = r.failed.get(1);
      // Selection failed before an identifier was known.
      assertEquals(
          new RefreshFailed(NAME, null, LocalUse.ENCRYPT, write.failure(), Duration.ofSeconds(5)),
          write);
      assertEquals(
          new RefreshFailed(NAME, x.id(), LocalUse.DECRYPT, read.failure(), Duration.ofSeconds(5)),
          read);
      assertInstanceOf(TransientException.class, read.failure());
      // Hits served from the still-valid entries, during and after the backoff, add nothing.
      for (int i = 0; i < 20; i++) {
        use(c);
        use(c, x.id());
      }
      assertEquals(2, r.failed.size());
      assertTrue(f.executor.queue.isEmpty());
      f.advance(1);
      use(c, x.id()); // After the backoff: a new refresh, which also fails.
      f.executor.run();
      assertEquals(3, r.failed.size());
      assertEquals(Duration.ofSeconds(4), r.failed.get(2).remaining());
      assertEquals(List.of(new Selected(NAME, null, x.id())), r.selected);
    }
  }

  @Test
  void aDefiniteRefusalReportsZeroRemainingAndIsNotRepeatedForCachedRefusals() {
    Recorder r = new Recorder();
    try (Fixture f = new Fixture(KmipVersion.V2_1, RetryPolicy.none(), r)) {
      KeyHandle x = f.key();
      LocalKeys c = f.cache();
      use(c, x.id());
      f.before.set(
          q -> {
            if (is(q, Operation.GET)) throw new PermissionDeniedException("Get permission removed");
          });
      f.advance(5);
      use(c, x.id());
      f.executor.run();
      assertEquals(1, r.failed.size());
      RefreshFailed refused = r.failed.get(0);
      assertEquals(x.id(), refused.keyId());
      assertEquals(LocalUse.DECRYPT, refused.purpose());
      assertInstanceOf(PermissionDeniedException.class, refused.failure());
      assertEquals(Duration.ZERO, refused.remaining());
      for (int i = 0; i < 5; i++)
        assertThrows(PermissionDeniedException.class, () -> c.forDecrypt(x.id()));
      assertEquals(1, r.failed.size());
    }
  }

  @Test
  void aForegroundRenewalOfAnExpiredEntryCountsButAColdLoadDoesNot() {
    Recorder r = new Recorder();
    try (Fixture f = new Fixture(KmipVersion.V2_1, RetryPolicy.none(), r)) {
      KeyHandle x = f.key(), y = f.key();
      LocalKeys c = f.cache();
      use(c, x.id());
      f.server.unreachable(true);
      assertThrows(
          TransientException.class, () -> c.forDecrypt(y.id())); // cold: its caller is told
      assertEquals(List.of(), r.failed);
      f.advance(11);
      assertThrows(TransientException.class, () -> c.forDecrypt(x.id()));
      assertThrows(TransientException.class, () -> c.forDecrypt(x.id())); // backoff: no new flight
      assertEquals(1, r.failed.size());
      assertEquals(x.id(), r.failed.get(0).keyId());
      assertEquals(Duration.ZERO, r.failed.get(0).remaining());
    }
  }

  @Test
  void aQueuedRefreshTakenOverByAnExpiredUseIsNotAFailure() {
    Recorder r = new Recorder();
    try (Fixture f = new Fixture(KmipVersion.V2_1, RetryPolicy.none(), r)) {
      KeyHandle x = f.key();
      LocalKeys c = f.cache();
      use(c);
      f.advance(5);
      use(c);
      f.advance(5);
      use(c);
      f.executor.run(); // the late task exits superseded
      assertEquals(List.of(), r.failed);
      assertEquals(List.of(new Selected(NAME, null, x.id())), r.selected);
    }
  }

  @Test
  void callbacksRunOutsideCacheLocksAndCallScopeAndCannotChangeAuthorization() throws Exception {
    Recorder r = new Recorder();
    try (Fixture f = new Fixture(KmipVersion.V2_1, RetryPolicy.none(), r)) {
      KeyHandle x = f.key(), other = f.key(256, "orders", null, KeyUsage.DECRYPT);
      LocalKeys c = f.cache();
      ExecutorService pool = Executors.newSingleThreadExecutor();
      List<Long> scopes = new CopyOnWriteArrayList<>();
      try {
        r.during =
            event -> {
              scopes.add(Kms.callRemaining(Duration.ofHours(1)));
              // Another thread needs the membership, write and slot locks: it would block if held
              // here.
              Future<String> concurrent =
                  pool.submit(
                      () -> {
                        c.invalidate("unrelated-id");
                        try (LocalKeys.Use u = c.forDecrypt(other.id())) {
                          return u.id();
                        }
                      });
              try {
                assertEquals(other.id(), concurrent.get(3, TimeUnit.SECONDS));
              } catch (Exception e) {
                throw new AssertionError("callback held a cache lock", e);
              }
              throw new IllegalStateException("listener failure is ignored");
            };
        try (LocalKeys.Use u = c.forEncrypt()) {
          assertEquals(x.id(), u.id());
        }
        assertEquals(x.id(), c.currentWriteId().orElseThrow());
        f.server.unreachable(true);
        f.advance(5);
        use(c);
        f.executor.run();
        try (LocalKeys.Use u = c.forEncrypt()) {
          assertEquals(x.id(), u.id());
        } // still valid to TTL
        assertEquals(1, r.failed.size());
        r.during =
            event -> {
              throw new IllegalStateException("listener failure is ignored");
            };
        f.advance(5);
        assertThrows(TransientException.class, c::forEncrypt); // and not beyond it
        assertEquals(2, r.failed.size()); // the foreground renewal's own failure
      } finally {
        pool.shutdownNow();
      }
      assertEquals(1, r.selected.size());
      for (long remaining : scopes)
        assertTrue(remaining > Duration.ofMinutes(59).toNanos(), "no cache call scope");
    }
  }

  @Test
  void theOwnedLazyFormReportsThroughItsConfigWithoutConnectingEarly() {
    Recorder r = new Recorder();
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle x = f.key();
      int exchanges = f.server.exchanges();
      try (LocalKeys c =
          LocalKeys.builder(f.server.configure().addListener(r).build(), NAME)
              .scope(KeyQuery.all().custom(FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(TTL)
              .open()) {
        assertEquals(exchanges, f.server.exchanges());
        assertTrue(c.currentWriteId().isEmpty());
        assertEquals(exchanges, f.server.exchanges(), "diagnostics do not connect");
        assertEquals(List.of(), r.selected);
        use(c);
        assertEquals(List.of(new Selected(NAME, null, x.id())), r.selected);
      }
    }
  }
}
