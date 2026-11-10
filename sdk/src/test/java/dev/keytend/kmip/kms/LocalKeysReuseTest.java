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
import java.time.Duration;
import java.util.List;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Read-back availability from the write validation, with no second authorization lifetime. */
class LocalKeysReuseTest {
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aWriteValidationAuthorizingDecryptAlsoSupportsImmediateOfflineReadBack(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      AtomicInteger gets = new AtomicInteger();
      f.before.set(
          request -> {
            if (is(request, Operation.GET)) gets.incrementAndGet();
          });
      try (LocalKeys.Use write = c.forEncrypt()) {
        assertEquals(key.id(), write.id());
      }
      assertEquals(1, gets.get());
      int requests = f.server.exchanges();
      f.server.unreachable(true);
      try (LocalKeys.Use read = c.forDecrypt(key.id())) {
        assertEquals(key.id(), read.id());
      }
      assertEquals(requests, f.server.exchanges());
      f.advance(10);
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void switchingWritesKeepsTheSeededHistoricalKeyWithinItsOriginalTtl(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle old = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      old.deactivate();
      old.removeName(NAME);
      KeyHandle next = f.key();
      f.advance(5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.executor.run();
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(next.id(), use.id());
      }
      f.server.unreachable(true);
      try (LocalKeys.Use use = c.forDecrypt(old.id())) {
        assertEquals(old.id(), use.id());
      }
      f.executor.run(); // Failed historical refresh must not renew its initial authorization.
      f.advance(5);
      assertThrows(TransientException.class, () -> c.forDecrypt(old.id()));
      try (LocalKeys.Use use = c.forDecrypt(next.id())) {
        assertEquals(next.id(), use.id());
      }
    }
  }

  @Test
  void encryptPermissionAloneCannotSeedDecryption() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key(256, "orders", NAME, KeyUsage.ENCRYPT);
      LocalKeys c = f.cache();
      AtomicInteger gets = new AtomicInteger();
      f.before.set(
          request -> {
            if (is(request, Operation.GET)) gets.incrementAndGet();
          });
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      assertThrows(KeyMismatchException.class, () -> c.forDecrypt(key.id()));
      assertEquals(1, gets.get(), "refuse Decrypt from attributes without fetching again");
    }
  }

  @Test
  void readBackUsesTheValidationStartNotThePublicationTime() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      f.before.set(
          request -> {
            if (is(request, Operation.GET)) f.advance(4);
          });
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.before.set(request -> {});
      f.server.unreachable(true);
      f.advance(5); // Age9, publication only5 seconds ago.
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      f.executor.run();
      f.advance(1);
      assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
    }
  }

  @Test
  void cachedTransientFailureSaysItIsSuppressingRetryAndPreservesItsCause() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      f.server.unreachable(true);
      TransientException live =
          assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
      int requests = f.server.exchanges();
      f.server.unreachable(false);
      TransientException cached =
          assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
      assertNotSame(live, cached);
      assertSame(live, cached.getCause());
      assertTrue(cached.getMessage().contains("key-load retry backoff"));
      assertTrue(cached.getMessage().contains("PT1S"));
      assertEquals(requests, f.server.exchanges());
      f.advance(1);
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
    }
  }

  @Test
  void connectionBackoffMessageIsSharedAcrossDifferentIds() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeysStartupTest.Connections connections = new LocalKeysStartupTest.Connections();
      LocalKeys c = LocalKeysStartupTest.cache(f, connections.config(f, Duration.ofSeconds(1)));
      f.server.unreachable(true);
      assertThrows(TransientException.class, c::forEncrypt);
      int opens = connections.opened.get();
      f.server.unreachable(false);
      TransientException cached =
          assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
      assertTrue(cached.getMessage().contains("connection retry backoff"));
      assertEquals(opens, connections.opened.get());
      f.advance(1);
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
    }
  }

  @Test
  void idSetScopeSkipsAbsentCandidatesAndNeverSendsLocate() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key(), outside = f.key(256, "orders", null, KeyUsage.DECRYPT);
      LocalKeys.Builder b =
          f.client
              .keys()
              .localKeys(NAME)
              .scope(KeyQuery.all().ids(List.of(key.id(), "absent")))
              .expect(Expect.aes(256))
              .ttl(TTL)
              .refreshExecutor(f.executor);
      b.ticker = f.time::get;
      LocalKeys c = f.keep(b.open());
      f.before.set(request -> assertFalse(is(request, Operation.LOCATE)));
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(key.id(), use.id());
      }
      assertThrows(KeyMismatchException.class, () -> c.forDecrypt(outside.id()));
    }
  }

  @Test
  void aConcurrentAccessDenialPreventsWriteToReadSeeding() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      CountDownLatch[] gate = LocalKeysRefreshSafetyTest.gate();
      AtomicBoolean first = new AtomicBoolean(true);
      f.before.set(
          request -> {
            if (is(request, Operation.GET) && first.compareAndSet(true, false)) {
              gate[0].countDown();
              LocalKeysRefreshSafetyTest.await(gate[1]);
            }
          });
      ExecutorService pool = Executors.newSingleThreadExecutor();
      try {
        Future<LocalKeys.Use> write = pool.submit(() -> c.forEncrypt());
        LocalKeysRefreshSafetyTest.await(gate[0]);
        f.after.set(
            (request, response) ->
                is(request, Operation.GET)
                    ? Faults.failure(
                        request, Enums.ResultReason.PERMISSION_DENIED, "read access removed")
                    : response);
        assertThrows(PermissionDeniedException.class, () -> c.forDecrypt(key.id()));
        f.after.set((request, response) -> response);
        gate[1].countDown();
        ExecutionException failed =
            assertThrows(ExecutionException.class, () -> write.get(2, TimeUnit.SECONDS));
        assertInstanceOf(KmsException.class, failed.getCause());
        int requests = f.server.exchanges();
        assertThrows(PermissionDeniedException.class, () -> c.forDecrypt(key.id()));
        assertEquals(requests, f.server.exchanges(), "no seeded copy can override the denial");
        assertTrue(c.currentWriteId().isEmpty());
      } finally {
        gate[1].countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void aSupersededSelectorBatchIsNotRetriedByTheProtocolPolicy() {
    try (Fixture f = new Fixture(KmipVersion.V2_1, RetryPolicy.defaults())) {
      f.key();
      f.key(); // Two candidates exercise the batch callback inside Kms.execute.
      LocalKeys c = f.cache();
      AtomicInteger batches = new AtomicInteger();
      f.after.set(
          (request, response) -> {
            if (is(request, Operation.GET_ATTRIBUTES)) {
              batches.incrementAndGet();
              c.invalidateAll();
            }
            return response;
          });
      assertThrows(TransientException.class, c::forEncrypt);
      assertEquals(
          1, batches.get(), "a superseded callback must not retry a multi-request operation");
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aDeniedLocateCandidateIsSkippedOnTheUnbatchedFallback(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle old = f.key();
      LocalKeys c = f.cache();
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(old.id(), use.id());
      }
      KeyHandle next = f.key(); // Both Active, but access to the held key is explicitly removed.
      f.after.set(
          (request, response) -> {
            if (is(request, Operation.GET_ATTRIBUTES)
                && request.children(Tag.BATCH_ITEM).size() > 1)
              return Faults.failure(
                  request, Enums.ResultReason.OPERATION_NOT_SUPPORTED, "no batch support");
            return LocalKeysRefreshFailureTest.denyItems(request, response, old.id());
          });
      f.advance(5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.executor.run();
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(next.id(), use.id());
      }
      assertThrows(PermissionDeniedException.class, () -> c.forDecrypt(old.id()));
      f.advance(10);
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(next.id(), use.id());
      }
    }
  }

  @Test
  void serverCertificateRejectionDuringLazyConnectUsesShortSharedBackoff() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      AtomicBoolean rejecting = new AtomicBoolean(true);
      KmsConfig config =
          f.server
              .configure()
              .retryPolicy(RetryPolicy.none())
              .callTimeout(java.time.Duration.ofSeconds(2))
              .transport(
                  endpoint ->
                      request -> {
                        if (rejecting.get())
                          throw LocalKeysRefreshFailureTest.serverCertificateExpired();
                        return f.server.exchange(request);
                      })
              .build();
      LocalKeys.Builder builder =
          LocalKeys.builder(config, NAME)
              .scope(KeyQuery.all().custom(FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(TTL)
              .refreshExecutor(f.executor);
      builder.ticker = f.time::get;
      LocalKeys c = f.keep(builder.open());
      assertThrows(PermissionDeniedException.class, c::forEncrypt);
      rejecting.set(false);
      TransientException backoff =
          assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
      assertTrue(backoff.getMessage().contains("connection retry backoff"));
      f.advance(1);
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
    }
  }

  @Test
  void serverRefusingClientCredentialsStillRevokesTheCachedAuthorization() {
    LocalKeysRefreshFailureTest.Outcome result =
        LocalKeysRefreshFailureTest.failedRefresh(
            () ->
                new javax.net.ssl.SSLHandshakeException(
                    "Received fatal alert: certificate_revoked"));
    assertEquals(
        new LocalKeysRefreshFailureTest.Outcome(
            false, false, false, PermissionDeniedException.class),
        result);
  }
}
