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

package dev.keytend.kmip.transport;

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.TestKmipServer;
import dev.keytend.kmip.TestTls;
import dev.keytend.kmip.client.*;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.model.*;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * A pooled connection used within {@link TlsTransport.Builder#validateAfterIdle} is
 * reused after a check that does not wait, not the 1 ms probe; one idle longer is probed. Either
 * way a connection the server closed while it sat idle is discarded before the request is written,
 * so the request goes on a new connection and the server sees it exactly once.
 */
class PooledReuseTest {
  static final Duration THRESHOLD = Duration.ofMillis(400);

  static Ttlv query() {
    return Messages.request(
        ProtocolVersion.V1_4, List.of(Requests.query().build()), RequestOptions.DEFAULT);
  }

  static TlsTransport pooled(TestKmipServer server, Duration validateAfterIdle) throws Exception {
    return TlsTransport.builder("localhost", server.port(), TestTls.context("client", "server"))
        .pool(1, Duration.ofSeconds(30))
        .validateAfterIdle(validateAfterIdle)
        .build();
  }

  /** Recent connections are reused without the probe; with ZERO every reuse is probed (0.8). */
  @Test
  void aRecentlyUsedConnectionIsReusedWithoutTheProbe() throws Exception {
    try (var server = TestKmipServer.answeringQueries()) {
      try (TlsTransport t = pooled(server, TlsTransport.DEFAULT_VALIDATE_AFTER_IDLE)) {
        for (int i = 0; i < 50; i++) assertNotNull(t.exchange(query()));
        assertEquals(1, t.connectionsOpened());
        assertEquals(0, t.probes.get());
        assertEquals(49, t.quickChecks.get());
      }
      try (TlsTransport t = pooled(server, Duration.ZERO)) {
        for (int i = 0; i < 50; i++) assertNotNull(t.exchange(query()));
        assertEquals(1, t.connectionsOpened());
        assertEquals(49, t.probes.get());
        assertEquals(0, t.quickChecks.get());
      }
    }
  }

  /**
   * Just under the threshold: the server closes the pooled connection (close_notify, then a
   * reset), and the check before reuse sees the close without waiting (the close_notify read
   * through TLS, the reset by the non-blocking read): the request goes on a new connection and is
   * answered; the server received it once.
   */
  @Test
  void aConnectionClosedJustUnderTheThresholdIsReplacedWithoutTheProbe() throws Exception {
    for (boolean reset : new boolean[] {false, true}) {
      try (var server = TestKmipServer.answeringQueries();
          TlsTransport t = pooled(server, THRESHOLD)) {
        assertNotNull(t.exchange(query()));
        if (reset) server.resetConnections();
        else server.dropConnections();
        Thread.sleep(100); // the close arrives; still well under the threshold
        assertNotNull(t.exchange(query()), reset ? "reset" : "closed");
        assertEquals(2, server.acceptedCount());
        assertEquals(2, server.exchangeCount(), "each request reached the server once");
        // The check of a recent connection decided (quickChecks); TLS bytes waiting (JSSE sends
        // close_notify before a reset too) are read through TLS by alive(), which returns at once.
        assertEquals(1, t.quickChecks.get());
        assertTrue(t.probes.get() <= 1);
      }
    }
  }

  /** Just over the threshold: the probe sees the close; the request goes on a new connection. */
  @Test
  void aConnectionClosedJustOverTheThresholdIsCaughtByTheProbe() throws Exception {
    try (var server = TestKmipServer.answeringQueries();
        TlsTransport t = pooled(server, THRESHOLD)) {
      assertNotNull(t.exchange(query()));
      Thread.sleep(THRESHOLD.toMillis() + 100);
      server.dropConnections();
      Thread.sleep(50);
      assertNotNull(t.exchange(query()));
      assertEquals(2, server.acceptedCount());
      assertEquals(2, server.exchangeCount());
      assertEquals(1, t.probes.get());
      assertEquals(0, t.quickChecks.get());
    }
  }

  @Test
  void theSettingIsCheckedAndKept() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            TlsTransport.builder("h", 1, TestTls.context("client", "server"))
                .validateAfterIdle(Duration.ofMillis(-1)));
    assertThrows(
        IllegalArgumentException.class,
        () -> KmsConfig.builder().validateAfterIdle(Duration.ofMillis(-1)));
    assertEquals(Duration.ofSeconds(2), TlsTransport.DEFAULT_VALIDATE_AFTER_IDLE);
    var server =
        dev.keytend.kmip.testing.InMemoryKmipServer.of(dev.keytend.kmip.kms.KmipVersion.V2_1);
    try {
      assertEquals(Duration.ofSeconds(2), server.configure().build().validateAfterIdle());
      assertEquals(
          Duration.ZERO,
          server.configure().validateAfterIdle(Duration.ZERO).build().validateAfterIdle());
    } finally {
      server.close();
    }
  }
}
