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

import dev.keytend.kmip.client.KmipClient;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.CallContext;
import java.io.IOException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link Kms#serverVersions()} and {@link Kms#serverInfo()}, reads of the application API, and the
 * call timeout of {@link Kms#protocol()}.
 */
class ServerInfoTest {
  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  Kms connect(KmsConfig.Builder config) {
    Kms kms = Kms.connect(config.build());
    clients.add(kms);
    return kms;
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theServerSaysWhatItOffers(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    servers.add(s);
    Kms kms = connect(s.configure());
    assertEquals(List.of(version.toString()), kms.serverVersions());
    ServerInfo info = kms.serverInfo();
    assertEquals(Optional.of("keytend-kmip InMemoryKmipServer"), info.vendor());
    assertTrue(info.operations().contains("Create"), info.operations().toString());
    assertTrue(info.operations().contains("Query"), info.operations().toString());
    assertTrue(info.objectTypes().contains("SymmetricKey"), info.objectTypes().toString());
    assertEquals(Map.of(), info.serverInformation());
    assertThrows(UnsupportedOperationException.class, () -> info.operations().add("x"));
  }

  @Test
  void everyOfferedVersionIsListedInTheServersOrder() {
    InMemoryKmipServer s =
        InMemoryKmipServer.of(KmipVersion.V3_0, KmipVersion.V2_1, KmipVersion.V1_4);
    servers.add(s);
    Kms kms = connect(s.configure());
    assertEquals(List.of("3.0", "2.1", "1.4"), kms.serverVersions());
  }

  @Test
  void aRefusedQueryIsTypedAndVersionsStillRead() {
    InMemoryKmipServer s = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(s);
    Kms kms = connect(s.configure().retryPolicy(RetryPolicy.none()));
    s.failNext(ServerOperation.QUERY, Fault.UNSUPPORTED);
    assertThrows(UnsupportedException.class, kms::serverInfo);
    assertEquals(List.of("2.1"), kms.serverVersions());
    s.failNext(ServerOperation.QUERY, Fault.PERMISSION_DENIED);
    assertThrows(PermissionDeniedException.class, kms::serverInfo);
  }

  /** Reads: an endpoint that is down is passed over, as for any read. */
  @Test
  void bothFailOver() {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica();
    servers.add(a);
    servers.add(b);
    Kms kms = connect(a.configureReplicas(b));
    kms.ping();
    a.unreachable(true);
    assertEquals(List.of("2.1"), kms.serverVersions());
    assertTrue(kms.serverInfo().operations().contains("Locate"));
  }

  /**
   * A protocol-layer call without a deadline of its own is bounded by the call timeout: a hung
   * server fails it then, instead of after the transport's limit of several minutes.
   */
  @Test
  void protocolCallsWithoutADeadlineHaveTheCallTimeout() throws IOException {
    InMemoryKmipServer s = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(s);
    Kms kms =
        connect(s.configure().retryPolicy(RetryPolicy.none()).callTimeout(Duration.ofSeconds(1)));
    KmipClient protocol = kms.protocol();
    assertNotNull(protocol.call(Requests.query().build()), "an answered call is unchanged");
    for (CallContext context : List.of(CallContext.NONE, CallContext.cancellable())) {
      s.failNext(ServerOperation.LOCATE, Fault.HANG);
      long start = System.nanoTime();
      assertThrows(IOException.class, () -> protocol.call(Requests.locate().build(), context));
      long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
      assertTrue(millis >= 900 && millis < 5000, "failed after " + millis + " ms");
    }
    s.failNext(ServerOperation.LOCATE, Fault.HANG);
    long start = System.nanoTime();
    assertThrows(IOException.class, () -> protocol.call(Requests.locate().build()));
    assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 5000);
    // A deadline of the caller's own is kept.
    s.failNext(ServerOperation.LOCATE, Fault.HANG);
    start = System.nanoTime();
    assertThrows(
        IOException.class,
        () ->
            protocol.call(
                Requests.locate().build(), CallContext.withTimeout(Duration.ofMillis(200))));
    assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 900);
    protocol.close();
    assertNotNull(kms.protocol().call(Requests.query().build()), "closing a view does nothing");
  }
}
