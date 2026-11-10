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
import dev.keytend.kmip.server.*;
import dev.keytend.kmip.transport.TlsTransport;
import java.net.InetSocketAddress;
import java.util.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

class CallbackRoleControlTest {
  private static final byte[] BATCH_ID = {1, 2, 3};

  private static Ttlv request(ProtocolVersion version, Operation operation) {
    List<Ttlv> header = new ArrayList<>(List.of(Messages.protocolVersion(version)));
    if (version != ProtocolVersion.V3_0) header.add(integer(BATCH_COUNT, 1));
    return structure(
        REQUEST_MESSAGE,
        structure(REQUEST_HEADER, header),
        structure(
            BATCH_ITEM,
            enumeration(OPERATION, operation.code()),
            bytes(UNIQUE_BATCH_ITEM_ID, BATCH_ID),
            structure(
                REQUEST_PAYLOAD,
                operation == Operation.DISCOVER_VERSIONS
                    ? Messages.protocolVersion(version)
                    : enumeration(ENDPOINT_ROLE, Enums.EndpointRole.CLIENT))));
  }

  @ParameterizedTest
  @EnumSource(ProtocolVersion.class)
  void dispatchesRoleControlOnlyInItsServerToClientVersions(ProtocolVersion version)
      throws Exception {
    for (Operation operation : List.of(Operation.DISCOVER_VERSIONS, Operation.SET_ENDPOINT_ROLE)) {
      boolean supported =
          version.atLeast(
              operation == Operation.DISCOVER_VERSIONS
                  ? ProtocolVersion.V1_4
                  : ProtocolVersion.V2_0);
      List<Operation> dispatched = new ArrayList<>();
      Ttlv payload =
          structure(
              RESPONSE_PAYLOAD,
              operation == Operation.DISCOVER_VERSIONS
                  ? Messages.protocolVersion(version)
                  : enumeration(ENDPOINT_ROLE, Enums.EndpointRole.CLIENT));
      Ttlv response =
          CallbackMessages.respond(
              request(version, operation),
              (op, received) -> {
                dispatched.add(op);
                return CallbackHandler.Reply.success(payload);
              });
      Result result = Messages.response(response).results().get(0);
      assertEquals(supported, result.successful(), version + " " + operation);
      assertArrayEquals(
          BATCH_ID, response.require(BATCH_ITEM).require(UNIQUE_BATCH_ITEM_ID).bytesValue());
      if (supported) {
        assertEquals(List.of(operation), dispatched);
        assertEquals(payload, result.requirePayload());
      } else {
        assertTrue(dispatched.isEmpty());
        assertTrue(result.hasReason(Enums.ResultReason.OPERATION_NOT_SUPPORTED));
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V1_4", "V2_0", "V2_1", "V3_0"})
  void authenticatedListenerDeliversRoleControlWithPeerContext(ProtocolVersion version)
      throws Exception {
    List<Operation> delivered = new ArrayList<>();
    ContextualCallbackHandler handler =
        (context, operation, payload) -> {
          assertEquals(version, context.version());
          assertEquals(
              "CN=kms", context.peerCertificates().get(0).getSubjectX500Principal().getName());
          delivered.add(operation);
          return CallbackHandler.Reply.success(payload.retag(RESPONSE_PAYLOAD));
        };
    try (CallbackServer listener =
        CallbackServer.builder(
                new InetSocketAddress("127.0.0.1", 0), TestTls.context("listener", "kms"), handler)
            .build()) {
      List<Operation> operations =
          version == ProtocolVersion.V1_4
              ? List.of(Operation.DISCOVER_VERSIONS)
              : List.of(Operation.DISCOVER_VERSIONS, Operation.SET_ENDPOINT_ROLE);
      for (Operation operation : operations) {
        try (TlsTransport transport =
            new TlsTransport("localhost", listener.port(), TestTls.context("kms", "listener"))) {
          Result result =
              Messages.response(transport.exchange(request(version, operation))).results().get(0);
          assertTrue(result.successful(), result.toString());
        }
      }
      assertEquals(operations, delivered);
    }
  }
}
