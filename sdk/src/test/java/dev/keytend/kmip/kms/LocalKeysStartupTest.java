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
import dev.keytend.kmip.transport.*;
import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.BiConsumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Schema-time startup while down, first-use negotiation, shared failures and owned resources. */
class LocalKeysStartupTest {
  static final class Connections {
    final AtomicInteger opened = new AtomicInteger(), closed = new AtomicInteger();
    volatile BiConsumer<Ttlv, CallContext> before = (r, c) -> {};

    KmsConfig config(Fixture f, Duration timeout) {
      return f.server
          .configure()
          .retryPolicy(RetryPolicy.none())
          .callTimeout(timeout)
          .transport(
              endpoint -> {
                opened.incrementAndGet();
                return new KmipTransport() {
                  final AtomicBoolean done = new AtomicBoolean();

                  @Override
                  public Ttlv exchange(Ttlv request) throws IOException {
                    return exchange(request, CallContext.NONE);
                  }

                  @Override
                  public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
                    context.check();
                    before.accept(request, context);
                    context.check();
                    return f.server.exchange(request);
                  }

                  @Override
                  public void close() {
                    if (done.compareAndSet(false, true)) closed.incrementAndGet();
                  }
                };
              })
          .build();
    }
  }

  static LocalKeys cache(Fixture f, KmsConfig config) {
    LocalKeys.Builder b =
        LocalKeys.builder(config, NAME)
            .scope(KeyQuery.all().custom(FAMILY, "orders"))
            .expect(Expect.aes(256))
            .ttl(TTL)
            .refreshExecutor(f.executor);
    b.ticker = f.time::get;
    return f.keep(b.open());
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void schemaConstructionIsOfflineAndChunkCallsRecoverAfterSharedBackoff(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      Connections connections = new Connections();
      KmsConfig config = connections.config(f, Duration.ofSeconds(1));
      int exchanges = f.server.exchanges();
      f.server.unreachable(true);
      LocalKeys c = cache(f, config);
      assertEquals(TTL, c.ttl());
      assertTrue(c.currentWriteId().isEmpty());
      c.invalidateAll();
      assertEquals(0, connections.opened.get());
      assertEquals(exchanges, f.server.exchanges(), "schema setup sends nothing");
      assertThrows(TransientException.class, c::forEncrypt);
      int attempts = connections.opened.get();
      for (int i = 0; i < 40; i++) {
        String id = "untrusted-chunk-" + i;
        assertThrows(TransientException.class, () -> c.forDecrypt(id));
      }
      assertEquals(
          attempts, connections.opened.get(), "backoff is shared across chunk IDs and purposes");
      f.server.unreachable(false);
      f.advance(1);
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(key.id(), use.id());
      }
      c.close();
      assertEquals(connections.opened.get(), connections.closed.get());
    }
  }

  @Test
  void closeBeforeUseNeverOpensATransport() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      Connections connections = new Connections();
      LocalKeys c = cache(f, connections.config(f, Duration.ofSeconds(1)));
      c.close();
      assertThrows(IllegalStateException.class, c::forEncrypt);
      assertEquals(0, connections.opened.get());
    }
  }

  @Test
  void concurrentPurposesShareNegotiationAndCloseCancelsIt() throws Exception {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      Connections connections = new Connections();
      CountDownLatch entered = new CountDownLatch(1), released = new CountDownLatch(1);
      connections.before =
          (request, context) -> {
            if (is(request, Operation.DISCOVER_VERSIONS)) {
              entered.countDown();
              try (java.io.Closeable cancellation = context.onCancel(released::countDown)) {
                assertTrue(released.await(2, TimeUnit.SECONDS));
              } catch (IOException | InterruptedException e) {
                throw new AssertionError(e);
              }
            }
          };
      LocalKeys c = cache(f, connections.config(f, Duration.ofSeconds(2)));
      ExecutorService pool = Executors.newFixedThreadPool(3);
      try {
        Future<LocalKeys.Use> first = pool.submit(() -> c.forEncrypt());
        assertTrue(entered.await(1, TimeUnit.SECONDS));
        Future<LocalKeys.Use> second = pool.submit(() -> c.forDecrypt(key.id()));
        c.close();
        assertThrows(ExecutionException.class, () -> first.get(1, TimeUnit.SECONDS));
        assertThrows(ExecutionException.class, () -> second.get(1, TimeUnit.SECONDS));
        assertEquals(1, connections.opened.get(), "no second connection or late publication");
        assertEquals(1, connections.closed.get());
      } finally {
        released.countDown();
        pool.shutdownNow();
      }
    }
  }

  @Test
  void negotiationAndMaterialShareOneDeadlineEvenWithALongConnectRetryWindow() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      f.key();
      Connections connections = new Connections();
      KmsConfig config =
          connections.config(f, Duration.ofMillis(100)).toBuilder()
              .connectRetry(Duration.ofSeconds(30))
              .build();
      connections.before =
          (request, context) -> {
            try {
              TimeUnit.NANOSECONDS.sleep(
                  Math.max(1, context.remainingNanos()) + TimeUnit.MILLISECONDS.toNanos(5));
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
              throw new AssertionError(e);
            }
          };
      LocalKeys c = cache(f, config);
      long start = System.nanoTime();
      assertThrows(TransientException.class, c::forEncrypt);
      assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(1));
      assertEquals(1, connections.opened.get());
      assertEquals(1, connections.closed.get());
      assertTrue(c.currentWriteId().isEmpty());
    }
  }

  @Test
  void configuredConnectRetryCanRecoverWithinTheFirstKeyCall() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      Connections connections = new Connections();
      AtomicInteger attempts = new AtomicInteger();
      connections.before =
          (request, context) -> {
            if (is(request, Operation.DISCOVER_VERSIONS) && attempts.incrementAndGet() == 2)
              f.server.unreachable(false);
          };
      KmsConfig config =
          connections.config(f, Duration.ofSeconds(2)).toBuilder()
              .connectRetry(Duration.ofSeconds(1))
              .build();
      LocalKeys c = cache(f, config);
      f.server.unreachable(true);
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(key.id(), use.id());
      }
      assertEquals(2, attempts.get());
      c.close();
      assertEquals(connections.opened.get(), connections.closed.get());
    }
  }

  @Test
  void unsupportedGroupsAreDeferredUntilFirstUseWithTheLazyBuilder() {
    try (Fixture f = new Fixture(KmipVersion.V3_0)) {
      Connections connections = new Connections();
      LocalKeys c =
          f.keep(
              LocalKeys.builder(connections.config(f, Duration.ofSeconds(1)), NAME)
                  .scope(KeyQuery.all().group("orders"))
                  .expect(Expect.aes(256))
                  .open());
      assertEquals(0, connections.opened.get());
      assertThrows(UnsupportedException.class, c::forEncrypt);
      assertEquals(1, connections.opened.get());
      c.close();
      assertEquals(1, connections.closed.get());
    }
  }

  @Test
  void authorizationAgeStartsWithTheKeyValidationAfterNegotiation() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      Connections connections = new Connections();
      connections.before =
          (request, context) -> {
            if (is(request, Operation.DISCOVER_VERSIONS)) f.advance(11);
          };
      LocalKeys c = cache(f, connections.config(f, Duration.ofSeconds(1)));
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(key.id(), use.id());
      }
      assertEquals(key.id(), c.currentWriteId().orElseThrow());
      f.advance(10);
      assertTrue(c.currentWriteId().isEmpty(), "key authorization still expires after its own TTL");
    }
  }

  @Test
  void explicitInvalidationClearsTheSharedConnectionBackoff() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      Connections connections = new Connections();
      LocalKeys c = cache(f, connections.config(f, Duration.ofSeconds(1)));
      f.server.unreachable(true);
      assertThrows(TransientException.class, c::forEncrypt);
      f.server.unreachable(false);
      c.invalidateAll();
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(key.id(), use.id());
      }
    }
  }
}
