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

import dev.keytend.kmip.TestKmipServer;
import dev.keytend.kmip.TestTls;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * {@link Kms#connectionStats()}: per endpoint, the connections open, idle and in use, opened in
 * total, and the waits for the pool, from the SDK's TLS transport; nothing measured for another
 * transport.
 */
class ConnectionStatsTest {
  final List<AutoCloseable> closing = new ArrayList<>();

  @AfterEach
  void close() throws Exception {
    for (AutoCloseable c : closing) c.close();
  }

  /** A mutual-TLS server in front of {@code store}. */
  TestKmipServer tls(InMemoryKmipServer store) throws Exception {
    TestKmipServer server =
        new TestKmipServer(
            "server",
            request -> {
              try {
                return store.exchange(request);
              } catch (IOException e) {
                throw new UncheckedIOException(e);
              }
            });
    closing.add(0, server);
    return server;
  }

  KmsConfig.Builder config(TestKmipServer... servers) throws Exception {
    List<String> endpoints = new ArrayList<>();
    for (TestKmipServer s : servers) endpoints.add("localhost:" + s.port());
    return KmsConfig.builder()
        .tls(TestTls.context("client", "server"))
        .versions(KmipVersion.V2_1)
        .endpoints(endpoints.toArray(String[]::new));
  }

  @Test
  void anEndpointsPoolIsCounted() throws Exception {
    InMemoryKmipServer store = InMemoryKmipServer.of(KmipVersion.V2_1);
    TestKmipServer a = tls(store), b = tls(store);
    try (Kms kms = Kms.connect(config(a, b).poolSize(1).build())) {
      KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
      key.attributes();
      List<Kms.ConnectionStats> stats = kms.connectionStats();
      assertEquals(2, stats.size());
      Kms.ConnectionStats first = stats.get(0), second = stats.get(1);
      assertEquals("localhost:" + a.port(), first.endpoint());
      assertTrue(first.measured());
      assertEquals(1, first.open(), first.toString());
      assertEquals(1, first.idle(), first.toString());
      assertEquals(0, first.inUse());
      assertEquals(1, first.opened(), "one pooled connection, reused");
      assertEquals(0, first.poolWaits());
      assertEquals(Duration.ZERO, first.poolWaitTime());
      assertEquals("localhost:" + b.port(), second.endpoint());
      assertTrue(second.measured(), "the SDK's transport, not opened yet");
      assertEquals(0, second.open());
      assertEquals(0, second.opened());
      assertEquals(
          stats.toString(),
          kms.withTimeout(Duration.ofSeconds(5)).connectionStats().toString(),
          "a view shares them");
      assertThrows(UnsupportedOperationException.class, () -> stats.add(first));

      // Two calls at once on a pool of one: one waits for the other's connection.
      a.delay(200);
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        List<Future<KeyAttributes>> reads = new ArrayList<>();
        for (int i = 0; i < 2; i++) reads.add(pool.submit(key::attributes));
        for (Future<KeyAttributes> r : reads) r.get();
      } finally {
        pool.shutdownNow();
      }
      Kms.ConnectionStats after = kms.connectionStats().get(0);
      assertEquals(1, after.poolWaits(), after.toString());
      assertTrue(after.poolWaitTime().toMillis() >= 100, after.toString());
      assertEquals(1, after.opened(), after.toString());
      kms.close();
      Kms.ConnectionStats closed = kms.connectionStats().get(0);
      assertEquals(0, closed.open(), "nothing open after close: " + closed);
      assertEquals(0, closed.idle());
      assertEquals(1, closed.opened(), "the totals stay");
      assertEquals(1, closed.poolWaits());
    }
  }

  @Test
  void withoutAPoolEachExchangeOpensOne() throws Exception {
    InMemoryKmipServer store = InMemoryKmipServer.of(KmipVersion.V2_1);
    TestKmipServer a = tls(store);
    try (Kms kms = Kms.connect(config(a).poolSize(0).build())) {
      KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
      long before = kms.connectionStats().get(0).opened();
      key.attributes();
      key.attributes();
      Kms.ConnectionStats stats = kms.connectionStats().get(0);
      assertEquals(before + 2, stats.opened(), stats.toString());
      assertEquals(0, stats.open(), "none kept open: " + stats);
      assertEquals(0, stats.idle());
      assertEquals(0, stats.poolWaits());
    }
  }

  @Test
  void anotherTransportIsNotMeasured() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = server.connect()) {
      kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
      List<Kms.ConnectionStats> stats = kms.connectionStats();
      assertEquals(1, stats.size());
      Kms.ConnectionStats s = stats.get(0);
      assertEquals("in-memory:5696", s.endpoint());
      assertFalse(s.measured());
      assertEquals(0, s.open());
      assertEquals(0, s.opened());
      assertTrue(s.toString().contains("not measured"), s.toString());
    }
  }
}
