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
import java.util.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Callback control operations: direction boundaries and validation of every dispatchable item. */
class CallbackControlDirectionTest {
  private static final List<Operation> CONTROLS =
      List.of(Operation.DISCOVER_VERSIONS, Operation.SET_ENDPOINT_ROLE);

  private static Ttlv item(Operation operation, int id, Ttlv... extras) {
    List<Ttlv> fields = new ArrayList<>();
    fields.add(enumeration(OPERATION, operation));
    fields.add(bytes(UNIQUE_BATCH_ITEM_ID, new byte[] {(byte) id}));
    fields.addAll(List.of(extras));
    return structure(BATCH_ITEM, fields);
  }

  private static Ttlv message(ProtocolVersion version, int continuation, Ttlv... items) {
    List<Ttlv> header =
        new ArrayList<>(
            List.of(
                Messages.protocolVersion(version),
                text(CLIENT_CORRELATION_VALUE, "control-direction"),
                enumeration(BATCH_ERROR_CONTINUATION_OPTION, continuation)));
    if (version != ProtocolVersion.V3_0) header.add(integer(BATCH_COUNT, items.length));
    List<Ttlv> roots = new ArrayList<>(List.of(structure(REQUEST_HEADER, header)));
    roots.addAll(List.of(items));
    return structure(REQUEST_MESSAGE, roots);
  }

  private static Ttlv replaceHeader(Ttlv request, Ttlv field) {
    List<Ttlv> fields = new ArrayList<>(request.require(REQUEST_HEADER).children());
    fields.removeIf(n -> n.tag() == field.tag());
    fields.add(field);
    List<Ttlv> roots = new ArrayList<>(List.of(structure(REQUEST_HEADER, fields)));
    roots.addAll(request.children(BATCH_ITEM));
    return structure(REQUEST_MESSAGE, roots);
  }

  private static Response reject(Ttlv request, Enums.ResultReason reason, boolean wholeMessage)
      throws Exception {
    Response response =
        Messages.response(
            CallbackMessages.respond(
                request,
                (op, payload) -> {
                  fail("Invalid callback reached the handler: " + op);
                  return CallbackHandler.Reply.success(null);
                }));
    if (wholeMessage) response = Messages.correlate(request, response);
    assertEquals(wholeMessage, response.messageLevelFailure());
    assertTrue(response.results().stream().allMatch(r -> r.hasReason(reason)), response.toString());
    assertEquals("control-direction", response.clientCorrelation().orElseThrow());
    return response;
  }

  @ParameterizedTest
  @EnumSource(ProtocolVersion.class)
  void exactDirectionAllowlistAcrossEveryRegisteredOperation(ProtocolVersion version)
      throws Exception {
    for (Operation operation : Operation.values()) {
      boolean allowed =
          switch (operation) {
            case NOTIFY, PUT, QUERY -> true;
            case DISCOVER_VERSIONS -> version.atLeast(ProtocolVersion.V1_4);
            case SET_ENDPOINT_ROLE -> version.atLeast(ProtocolVersion.V2_0);
            default -> false;
          };
      List<Operation> calls = new ArrayList<>();
      Ttlv request = message(version, 1, item(operation, 7, structure(REQUEST_PAYLOAD)));
      Response response =
          Messages.correlate(
              request,
              Messages.response(
                  CallbackMessages.respond(
                      request,
                      (op, payload) -> {
                        assertEquals(structure(REQUEST_PAYLOAD), payload);
                        calls.add(op);
                        return CallbackHandler.Reply.success(
                            op == Operation.SET_ENDPOINT_ROLE
                                ? structure(
                                    RESPONSE_PAYLOAD,
                                    enumeration(ENDPOINT_ROLE, Enums.EndpointRole.CLIENT))
                                : null);
                      })));
      Result result = response.results().get(0);
      assertEquals(allowed, result.successful(), version + " " + operation);
      assertEquals(allowed ? List.of(operation) : List.of(), calls);
      assertEquals(operation, result.operation());
      assertArrayEquals(new byte[] {7}, result.batchId().orElseThrow());
      if (!allowed) assertTrue(result.hasReason(Enums.ResultReason.OPERATION_NOT_SUPPORTED));
      // This public API continues to identify exclusively server-to-client operations.
      assertEquals(
          operation == Operation.NOTIFY || operation == Operation.PUT, operation.serverToClient());
    }
    Ttlv vendor =
        structure(
            BATCH_ITEM,
            enumeration(OPERATION, 0x80000077),
            bytes(UNIQUE_BATCH_ITEM_ID, new byte[] {8}),
            structure(REQUEST_PAYLOAD));
    Result rejected =
        reject(message(version, 1, vendor), Enums.ResultReason.OPERATION_NOT_SUPPORTED, false)
            .results()
            .get(0);
    assertEquals(0x80000077, rejected.operationCode().orElseThrow());
  }

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V2_0", "V2_1", "V3_0"})
  void controlsStillRequirePayloadOperationAndNonUndoBatch(ProtocolVersion version)
      throws Exception {
    for (Operation operation : CONTROLS) {
      for (Ttlv bad :
          List.of(
              item(operation, 1),
              item(operation, 1, text(REQUEST_PAYLOAD, "not a structure")),
              structure(
                  BATCH_ITEM,
                  bytes(UNIQUE_BATCH_ITEM_ID, new byte[] {1}),
                  structure(REQUEST_PAYLOAD)),
              structure(
                  BATCH_ITEM,
                  integer(OPERATION, operation.code()),
                  bytes(UNIQUE_BATCH_ITEM_ID, new byte[] {1}),
                  structure(REQUEST_PAYLOAD)))) {
        reject(message(version, 1, bad), Enums.ResultReason.INVALID_MESSAGE, false);
      }
      Response undo =
          reject(
              message(
                  version,
                  3,
                  item(operation, 1, structure(REQUEST_PAYLOAD)),
                  item(operation, 2, structure(REQUEST_PAYLOAD))),
              Enums.ResultReason.FEATURE_NOT_SUPPORTED,
              false);
      assertEquals(2, undo.results().size());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V2_0", "V2_1", "V3_0"})
  void laterCriticalExtensionsRejectWholeControlBatchBeforeAnySideEffect(ProtocolVersion version)
      throws Exception {
    for (Operation operation : CONTROLS) {
      Ttlv valid = item(operation, 1, structure(REQUEST_PAYLOAD));
      Ttlv critical = Credentials.extension("test-vendor", true, text(COMMENT, "x"));
      Ttlv request =
          message(version, 1, valid, item(operation, 2, structure(REQUEST_PAYLOAD), critical));
      reject(request, Enums.ResultReason.UNKNOWN_MESSAGE_EXTENSION, true);
      List<Operation> calls = new ArrayList<>();
      Response known =
          Messages.correlate(
              request,
              Messages.response(
                  CallbackMessages.respond(
                      request,
                      (op, p) -> {
                        calls.add(op);
                        return CallbackHandler.Reply.success(
                            op == Operation.SET_ENDPOINT_ROLE
                                ? structure(
                                    RESPONSE_PAYLOAD,
                                    enumeration(ENDPOINT_ROLE, Enums.EndpointRole.CLIENT))
                                : null);
                      },
                      Set.of("test-vendor"))));
      assertEquals(List.of(operation, operation), calls);
      assertTrue(known.results().stream().allMatch(Result::successful));
      Ttlv malformed =
          structure(
              MESSAGE_EXTENSION,
              text(VENDOR_IDENTIFICATION, "test-vendor"),
              integer(CRITICALITY_INDICATOR, 1));
      reject(
          message(version, 1, valid, item(operation, 2, structure(REQUEST_PAYLOAD), malformed)),
          Enums.ResultReason.INVALID_MESSAGE,
          true);
      if (version != ProtocolVersion.V3_0) {
        reject(
            replaceHeader(message(version, 1, valid), integer(BATCH_COUNT, 2)),
            Enums.ResultReason.INVALID_MESSAGE,
            true);
      }
      Ttlv v4 =
          structure(
              PROTOCOL_VERSION,
              integer(PROTOCOL_VERSION_MAJOR, 4),
              integer(PROTOCOL_VERSION_MINOR, 0));
      Ttlv unsupported =
          CallbackMessages.respond(
              replaceHeader(message(version, 1, valid), v4),
              (op, p) -> {
                fail("Unsupported wire version dispatched");
                return CallbackHandler.Reply.success(null);
              });
      assertEquals(v4, unsupported.require(RESPONSE_HEADER).require(PROTOCOL_VERSION));
      assertEquals(
          Enums.ResultReason.UNSUPPORTED_PROTOCOL_VERSION.code(),
          unsupported.require(BATCH_ITEM).require(RESULT_REASON).intValue());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V2_0", "V2_1", "V3_0"})
  void preservesControlFailureContextCorrelationAndStopContinueSemantics(ProtocolVersion version)
      throws Exception {
    for (Operation first : CONTROLS) {
      Operation second =
          first == Operation.DISCOVER_VERSIONS
              ? Operation.SET_ENDPOINT_ROLE
              : Operation.DISCOVER_VERSIONS;
      for (int continuation : List.of(1, 2)) {
        Ttlv payload =
            structure(
                REQUEST_PAYLOAD,
                text(COMMENT, "opaque application data"),
                enumeration(ENDPOINT_ROLE, Enums.EndpointRole.CLIENT));
        Ttlv request =
            message(version, continuation, item(first, 11, payload), item(second, 22, payload));
        List<Operation> calls = new ArrayList<>();
        ContextualCallbackHandler handler =
            (context, op, received) -> {
              assertEquals(version, context.version());
              assertEquals(request.require(REQUEST_HEADER), context.requestHeader());
              assertTrue(context.peerCertificates().isEmpty());
              assertEquals(payload, received);
              calls.add(op);
              return op == first
                  ? CallbackHandler.Reply.failure(
                      Enums.ResultReason.PERMISSION_DENIED, "role policy")
                  : CallbackHandler.Reply.success(payload);
            };
        Response response =
            Messages.correlate(
                request, Messages.response(CallbackMessages.respond(request, handler)));
        assertEquals(continuation == 1 ? List.of(first, second) : List.of(first), calls);
        assertEquals(continuation == 1 ? 2 : 1, response.results().size());
        assertEquals("control-direction", response.clientCorrelation().orElseThrow());
        Result failure = response.resultFor(0).orElseThrow();
        assertEquals(first, failure.operation());
        assertArrayEquals(new byte[] {11}, failure.batchId().orElseThrow());
        assertTrue(failure.hasReason(Enums.ResultReason.PERMISSION_DENIED));
        assertEquals("role policy", failure.message());
        if (continuation == 1) {
          Result success = response.resultFor(1).orElseThrow();
          assertEquals(second, success.operation());
          assertArrayEquals(new byte[] {22}, success.batchId().orElseThrow());
          assertEquals(payload.retag(RESPONSE_PAYLOAD), success.requirePayload());
        } else assertTrue(response.resultFor(1).isEmpty());
      }
      RuntimeException secret = new IllegalStateException("private handler details");
      List<RuntimeException> observed = new ArrayList<>();
      Ttlv request = message(version, 1, item(first, 33, structure(REQUEST_PAYLOAD)));
      Result error =
          Messages.correlate(
                  request,
                  Messages.response(
                      CallbackMessages.respond(
                          request,
                          (op, p) -> {
                            throw secret;
                          },
                          Set.of(),
                          CallbackContext.NONE,
                          observed::add)))
              .results()
              .get(0);
      assertTrue(error.hasReason(Enums.ResultReason.GENERAL_FAILURE));
      assertEquals("Application callback failed", error.message());
      assertEquals(List.of(secret), observed);
      assertArrayEquals(new byte[] {33}, error.batchId().orElseThrow());
    }
  }
}
