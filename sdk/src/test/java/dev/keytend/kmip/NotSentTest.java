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

package dev.keytend.kmip;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.*;
import java.io.IOException;
import java.net.*;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.Test;

/**
 * Protocol-layer behavior the application API relies on: "request not sent" failures, negotiation that follows the
 * version a server stamps on its error, non-owning views and pool eviction.
 */
class NotSentTest {
  static Ttlv query() {
    return Messages.request(
        ProtocolVersion.V1_4, List.of(Requests.query().build()), RequestOptions.DEFAULT);
  }

  @Test
  void refusedConnectionsAreNotSent() throws Exception {
    int port;
    try (ServerSocket s = new ServerSocket(0)) {
      port = s.getLocalPort();
    }
    try (var t =
        TlsTransport.builder("localhost", port, TestTls.context("client", "server")).build()) {
      var e = assertThrows(RequestNotSentException.class, () -> t.exchange(query()));
      assertInstanceOf(ConnectException.class, e.getCause());
    }
  }

  @Test
  void failedHandshakesAreNotSent() throws Exception {
    // The client does not trust the server's certificate.
    try (var server = new TestKmipServer("server", TransportTest::queryReply);
        var t =
            TlsTransport.builder("localhost", server.port(), TestTls.context("client", "stranger"))
                .build()) {
      assertThrows(RequestNotSentException.class, () -> t.exchange(query()));
      assertEquals(0, server.exchanges.get());
    }
  }

  @Test
  void anExhaustedPoolAndAClosedTransportAreNotSent() throws Exception {
    try (var server = new TestKmipServer("server", TransportTest::queryReply)) {
      server.replyDelayMillis = 1000;
      try (var t =
          TlsTransport.builder("localhost", server.port(), TestTls.context("client", "server"))
              .pool(1, Duration.ofSeconds(30))
              .build()) {
        Thread busy =
            new Thread(
                () -> {
                  try {
                    t.exchange(query());
                  } catch (IOException ignored) {
                  }
                });
        busy.start();
        Thread.sleep(300);
        var e =
            assertThrows(
                RequestNotSentException.class,
                () -> t.exchange(query(), CallContext.withTimeout(Duration.ofMillis(200))));
        assertInstanceOf(SocketTimeoutException.class, e.getCause());
        busy.join();
        t.closeIdleConnections();
        t.exchange(query());
        assertEquals(2, t.connectionsOpened(), "the idle connection was evicted");
        t.close();
        assertThrows(RequestNotSentException.class, () -> t.exchange(query()));
      }
    }
    var hashed = new HashedPasswordTransport(r -> null, "u", "p".toCharArray());
    hashed.close();
    assertThrows(
        RequestNotSentException.class,
        () ->
            hashed.exchange(
                Messages.request(
                    ProtocolVersion.V2_1,
                    List.of(Requests.query().build()),
                    RequestOptions.DEFAULT)));
  }

  /** A 1.2-only server answers a 2.1 header with an error stamped 1.2; the client follows it. */
  @Test
  void negotiationFollowsTheVersionTheServerStamps() throws Exception {
    InMemoryKmipServer server = new InMemoryKmipServer(ProtocolVersion.V1_2);
    try (var client = KmipClient.negotiated(server, VersionPolicy.ANY)) {
      assertEquals(ProtocolVersion.V1_2, client.version());
      KmipClient view = client.view();
      assertFalse(view.ownsTransport());
      view.close();
      assertFalse(server.closed());
    }
    assertTrue(server.closed());
    var e =
        assertThrows(
            VersionNegotiationException.class,
            () ->
                KmipClient.negotiated(
                    new InMemoryKmipServer(ProtocolVersion.V1_2),
                    VersionPolicy.atLeast(ProtocolVersion.V1_4)));
    assertEquals(List.of(ProtocolVersion.V1_2), e.offered());
  }

  @Test
  void vendorAttributesPassThroughConversion() {
    Ttlv vendor = ModernAttributes.vendor("acme", "Region", text(ATTRIBUTE_VALUE, "eu"));
    assertSame(vendor, ModernAttributes.fromLegacy(vendor, ProtocolVersion.V2_1));
  }
}
