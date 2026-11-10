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
import dev.keytend.kmip.transport.KmipTransport;
import java.time.Instant;
import java.util.*;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/** Response correlation and batch semantics. */
class CorrelationTest {
  static Ttlv header(Ttlv request, int count, Ttlv... extra) {
    List<Ttlv> fields = new ArrayList<>();
    fields.add(request.require(REQUEST_HEADER).require(PROTOCOL_VERSION));
    fields.add(dateTime(TIME_STAMP, Instant.ofEpochSecond(1700000000)));
    fields.addAll(List.of(extra));
    if (Messages.version(request.require(REQUEST_HEADER)) != ProtocolVersion.V3_0)
      fields.add(integer(BATCH_COUNT, count));
    return structure(RESPONSE_HEADER, fields);
  }

  static Ttlv response(Ttlv request, List<Ttlv> items, Ttlv... headerExtra) {
    List<Ttlv> fields = new ArrayList<>();
    fields.add(header(request, items.size(), headerExtra));
    fields.addAll(items);
    return structure(RESPONSE_MESSAGE, fields);
  }

  /** A response item answering {@code requestItem} with the given status and payload fields. */
  static Ttlv item(Ttlv requestItem, int status, Ttlv... payload) {
    return item(requestItem, requestItem.require(OPERATION).intValue(), status, payload);
  }

  static Ttlv item(Ttlv requestItem, int operation, int status, Ttlv... payload) {
    List<Ttlv> fields = new ArrayList<>();
    fields.add(enumeration(OPERATION, operation));
    requestItem.child(UNIQUE_BATCH_ITEM_ID).ifPresent(fields::add);
    fields.add(enumeration(RESULT_STATUS, status));
    if (status == 1) fields.add(enumeration(RESULT_REASON, Enums.ResultReason.ITEM_NOT_FOUND));
    if (status == 2) fields.add(bytes(ASYNCHRONOUS_CORRELATION_VALUE, new byte[] {7}));
    // A successful item always carries a Response Payload (KMIP 1.4 Table 285); failures carry
    // one only when a test gives fields.
    if (status == 0 || payload.length > 0) fields.add(structure(RESPONSE_PAYLOAD, payload));
    return structure(BATCH_ITEM, fields);
  }

  /** A conforming Get response payload: identifier, Object Type and the object. */
  static Ttlv[] gotKey(Ttlv id) {
    return new Ttlv[] {
      id,
      enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY),
      ManagedObjects.rawSymmetricKey(new byte[16], Enums.CryptographicAlgorithm.AES)
    };
  }

  static Ttlv[] gotKey(String id) {
    return gotKey(text(UNIQUE_IDENTIFIER, id));
  }

  /** A conforming Create response payload. */
  static Ttlv[] created(String id) {
    return new Ttlv[] {
      enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY), text(UNIQUE_IDENTIFIER, id)
    };
  }

  static KmipClient client(ProtocolVersion version, Function<Ttlv, Ttlv> server) {
    KmipTransport transport = server::apply;
    return new KmipClient(transport, version);
  }

  /** OASIS TC-CS-CORVAL-1-14 sends a Client Correlation Value and the response omits it. */
  @Test
  void omittedClientCorrelationIsAccepted_kmip14Section6_18() throws Exception {
    var options = RequestOptions.DEFAULT.correlation("audit-123", null);
    try (var c =
        client(
            ProtocolVersion.V1_4,
            req -> response(req, List.of(item(req.require(BATCH_ITEM), 0, created("k1")))))) {
      assertTrue(
          c.batch(List.of(Requests.create().build()), options).results().get(0).successful());
    }
    try (var c =
        client(
            ProtocolVersion.V1_4,
            req ->
                response(
                    req,
                    List.of(item(req.require(BATCH_ITEM), 0)),
                    text(CLIENT_CORRELATION_VALUE, "audit-123")))) {
      assertTrue(c.batch(List.of(Requests.query().build()), options).results().get(0).successful());
    }
    try (var c =
        client(
            ProtocolVersion.V1_4,
            req ->
                response(
                    req,
                    List.of(item(req.require(BATCH_ITEM), 0)),
                    text(CLIENT_CORRELATION_VALUE, "someone-else")))) {
      var e =
          assertThrows(
              ProtocolException.class, () -> c.batch(List.of(Requests.query().build()), options));
      assertEquals("Client correlation mismatch", e.getMessage());
    }
  }

  /** BATCH-06: Create, missing Get, Create with Undo; Create/Undone then Get/Failed. */
  @Test
  void undoProcessedPrefixIsReturned_kmip14Section6_13Table366() throws Exception {
    var undo = RequestOptions.DEFAULT.batching(true, Enums.BatchErrorContinuation.UNDO);
    List<Request> batch =
        List.of(
            Requests.createSymmetricKey(
                Enums.CryptographicAlgorithm.AES, 128, Enums.CryptographicUsageMask.ENCRYPT),
            Requests.get().uniqueIdentifier("missing").build(),
            Requests.createSymmetricKey(
                Enums.CryptographicAlgorithm.AES, 128, Enums.CryptographicUsageMask.ENCRYPT));
    try (var c =
        client(
            ProtocolVersion.V1_4,
            req -> {
              var items = req.children(BATCH_ITEM);
              return response(
                  req,
                  List.of(
                      item(items.get(0), 3, text(UNIQUE_IDENTIFIER, "k1")), item(items.get(1), 1)));
            })) {
      Response r = c.batch(batch, undo);
      assertEquals(2, r.results().size());
      assertEquals(3, r.resultFor(0).orElseThrow().status());
      assertEquals(1, r.resultFor(1).orElseThrow().status());
      assertTrue(r.resultFor(2).isEmpty(), "the unprocessed tail is not returned");
    }
    // Still rejected: an Undo prefix whose earlier item was not undone,
    try (var c =
        client(
            ProtocolVersion.V1_4,
            req -> {
              var items = req.children(BATCH_ITEM);
              return response(req, List.of(item(items.get(0), 0), item(items.get(1), 1)));
            })) {
      assertThrows(ProtocolException.class, () -> c.batch(batch, undo));
    }
    // truncation under Continue,
    try (var c =
        client(
            ProtocolVersion.V1_4,
            req -> {
              var items = req.children(BATCH_ITEM);
              return response(req, List.of(item(items.get(0), 3), item(items.get(1), 1)));
            })) {
      assertThrows(
          ProtocolException.class,
          () ->
              c.batch(
                  batch,
                  RequestOptions.DEFAULT.batching(true, Enums.BatchErrorContinuation.CONTINUE)));
    }
    // a truncated response whose last item did not fail,
    try (var c =
        client(
            ProtocolVersion.V1_4,
            req -> {
              var items = req.children(BATCH_ITEM);
              return response(req, List.of(item(items.get(0), 3), item(items.get(1), 3)));
            })) {
      assertThrows(ProtocolException.class, () -> c.batch(batch, undo));
    }
    // and an item answering an unrelated operation.
    try (var c =
        client(
            ProtocolVersion.V1_4,
            req -> {
              var items = req.children(BATCH_ITEM);
              return response(
                  req,
                  List.of(item(items.get(0), Operation.DESTROY.code(), 3), item(items.get(1), 1)));
            })) {
      var e = assertThrows(ProtocolException.class, () -> c.batch(batch, undo));
      assertNotNull(e.response(), "the raw response is kept for diagnostics");
    }
  }

  @Test
  void enumeratedAndIntegerIdentifiersSkipTheIdentityCheck_kmip21Table145() throws Exception {
    for (Ttlv placeholder :
        List.of(
            enumeration(UNIQUE_IDENTIFIER, Enums.UniqueIdentifier.ID_PLACEHOLDER),
            integer(UNIQUE_IDENTIFIER, 0))) {
      try (var c =
          client(
              ProtocolVersion.V2_1,
              req -> {
                var items = req.children(BATCH_ITEM);
                return response(
                    req,
                    List.of(
                        item(items.get(0), 0, created("k1")), item(items.get(1), 0, gotKey("k1"))));
              })) {
        Response r =
            c.batch(
                List.of(
                    Requests.createSymmetricKey(
                        Enums.CryptographicAlgorithm.AES,
                        128,
                        Enums.CryptographicUsageMask.ENCRYPT),
                    Requests.get().add(placeholder).build()));
        assertTrue(r.resultFor(1).orElseThrow().successful());
      }
    }
  }

  @Test
  void getResponsesMustNameTheRequestedObject() throws Exception {
    for (Ttlv[] payload : List.of(Arrays.copyOfRange(gotKey("key-A"), 1, 3), gotKey("key-B"))) {
      try (var c =
          client(
              ProtocolVersion.V1_4,
              req -> response(req, List.of(item(req.require(BATCH_ITEM), 0, payload))))) {
        var e = assertThrows(ProtocolException.class, () -> c.get("key-A"));
        assertTrue(
            Set.of("Get response missing UniqueIdentifier", "Get response names another object")
                .contains(e.getMessage()),
            e.getMessage());
      }
    }
    try (var c =
        client(
            ProtocolVersion.V1_4,
            req -> response(req, List.of(item(req.require(BATCH_ITEM), 0, gotKey("key-A")))))) {
      assertTrue(c.get("key-A").successful());
    }
  }

  @Test
  void completedPollMayCarryTheOriginalOperation_kmip21Section6_1_38() throws Exception {
    try (var c =
        client(
            ProtocolVersion.V2_1,
            req ->
                response(
                    req,
                    List.of(
                        item(
                            req.require(BATCH_ITEM),
                            Operation.CREATE.code(),
                            0,
                            enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY),
                            text(UNIQUE_IDENTIFIER, "k1")))))) {
      assertEquals("k1", c.poll(new byte[] {7}).uniqueIdentifier());
      assertEquals("k1", c.poll(new byte[] {7}, Operation.CREATE).uniqueIdentifier());
      assertThrows(ProtocolException.class, () -> c.poll(new byte[] {7}, Operation.REGISTER));
    }
    try (var c =
        client(
            ProtocolVersion.V2_1,
            req -> response(req, List.of(item(req.require(BATCH_ITEM), 0))))) {
      assertEquals(Operation.POLL, c.poll(new byte[] {7}, Operation.CREATE).operation());
    }
  }

  /** An unknown or vendor operation code is not the polled operation either. */
  @Test
  void pollRejectsUnknownAndVendorOperationCodes() throws Exception {
    for (int code : new int[] {0x8000_0001, 0x7F}) {
      try (var c =
          client(
              ProtocolVersion.V2_1,
              req ->
                  response(
                      req,
                      List.of(
                          item(
                              req.require(BATCH_ITEM), code, 0, text(UNIQUE_IDENTIFIER, "k1")))))) {
        assertThrows(
            ProtocolException.class,
            () -> c.poll(new byte[] {7}, Operation.CREATE),
            Integer.toHexString(code));
      }
    }
  }

  @Test
  void resultForMapsReorderedRepliesBackToTheirRequests() throws Exception {
    try (var c =
        client(
            ProtocolVersion.V1_4,
            req -> {
              List<Ttlv> items = new ArrayList<>();
              for (Ttlv b : req.children(BATCH_ITEM))
                items.add(
                    item(b, 0, gotKey(b.require(REQUEST_PAYLOAD).require(UNIQUE_IDENTIFIER))));
              Collections.reverse(items);
              return response(req, items);
            })) {
      Response r =
          c.batch(
              List.of(
                  Requests.get().uniqueIdentifier("key-A").build(),
                  Requests.get().uniqueIdentifier("key-B").build()));
      assertEquals("key-B", r.results().get(0).uniqueIdentifier(), "results() keeps wire order");
      assertEquals("key-A", r.resultFor(0).orElseThrow().uniqueIdentifier());
      assertEquals("key-B", r.resultFor(1).orElseThrow().uniqueIdentifier());
    }
  }

  @Test
  void messageLevelFailureIsReportedByResultFor() throws Exception {
    try (var c =
        client(
            ProtocolVersion.V1_4,
            req ->
                response(
                    req,
                    List.of(
                        structure(
                            BATCH_ITEM,
                            enumeration(RESULT_STATUS, 1),
                            enumeration(RESULT_REASON, Enums.ResultReason.PERMISSION_DENIED)))))) {
      Response r = c.batch(List.of(Requests.get().build(), Requests.getAttributes().build()));
      assertTrue(r.messageLevelFailure());
      var e = assertThrows(KmipException.class, () -> r.resultFor(1));
      assertEquals(Enums.ResultReason.PERMISSION_DENIED.code(), e.result().reason());
    }
  }

  @Test
  void batchOptionsAreOnlySentWithMoreThanOneItem_kmip21Section9_6() {
    var options = RequestOptions.DEFAULT.batching(true, Enums.BatchErrorContinuation.STOP);
    Ttlv single =
        Messages.request(ProtocolVersion.V1_4, List.of(Requests.get().build()), options)
            .require(REQUEST_HEADER);
    assertTrue(single.child(BATCH_ERROR_CONTINUATION_OPTION).isEmpty());
    assertTrue(single.child(BATCH_ORDER_OPTION).isEmpty());
    Ttlv two =
        Messages.request(
                ProtocolVersion.V1_4,
                List.of(Requests.get().build(), Requests.get().build()),
                options)
            .require(REQUEST_HEADER);
    assertEquals(2, two.require(BATCH_ERROR_CONTINUATION_OPTION).intValue());
    assertTrue(two.require(BATCH_ORDER_OPTION).booleanValue());
  }

  // ---- acknowledgments, truncated batches, multi-part operations, batch order ----

  /** One Request answered by {@code reply}, through a real client. */
  static Result call(ProtocolVersion v, Request request, Function<Ttlv, Ttlv[]> payload)
      throws Exception {
    try (var c =
        client(
            v,
            req -> response(req, List.of(item(req.require(BATCH_ITEM), 0, payload.apply(req)))))) {
      return c.call(request);
    }
  }

  /** Every operation on a fixed object must echo it, and required results must be present. */
  @Test
  void successfulAcknowledgmentsAreCheckedAgainstThePayloadTables() throws Exception {
    Request macVerify =
        CryptoRequests.macVerify("mac-key").data(new byte[] {1}).macData(new byte[] {2}).build();
    // A MAC Verify answer naming another key is not VALID.
    var e =
        assertThrows(
            ProtocolException.class,
            () ->
                call(
                    ProtocolVersion.V2_1,
                    macVerify,
                    req ->
                        new Ttlv[] {
                          text(UNIQUE_IDENTIFIER, "other-key"),
                          enumeration(VALIDITY_INDICATOR, Enums.ValidityIndicator.VALID)
                        }));
    assertEquals("MACVerify response names another object", e.getMessage());
    assertThrows(
        ProtocolException.class,
        () ->
            call(
                ProtocolVersion.V2_1,
                macVerify,
                req -> new Ttlv[] {text(UNIQUE_IDENTIFIER, "mac-key")}),
        "Validity Indicator is required");
    assertEquals(
        0,
        call(
                ProtocolVersion.V2_1,
                macVerify,
                req ->
                    new Ttlv[] {
                      text(UNIQUE_IDENTIFIER, "mac-key"),
                      enumeration(VALIDITY_INDICATOR, Enums.ValidityIndicator.VALID)
                    })
            .status());
    // Destroy answered Success with no payload, or without the identifier.
    Request destroy = Requests.destroy().uniqueIdentifier("k1").build();
    assertThrows(
        ProtocolException.class, () -> call(ProtocolVersion.V1_4, destroy, req -> new Ttlv[0]));
    for (Operation op : List.of(Operation.ACTIVATE, Operation.REVOKE, Operation.DESTROY)) {
      Request r =
          op == Operation.REVOKE
              ? Requests.revoke()
                  .uniqueIdentifier("k1")
                  .add(
                      structure(
                          REVOCATION_REASON,
                          enumeration(
                              REVOCATION_REASON_CODE, Enums.RevocationReasonCode.UNSPECIFIED)))
                  .build()
              : Request.operation(op).uniqueIdentifier("k1").build();
      assertThrows(
          ProtocolException.class,
          () -> call(ProtocolVersion.V2_1, r, req -> new Ttlv[] {text(UNIQUE_IDENTIFIER, "k2")}),
          op.wireName());
      assertTrue(
          call(ProtocolVersion.V2_1, r, req -> new Ttlv[] {text(UNIQUE_IDENTIFIER, "k1")})
              .successful());
    }
    // Operations that create an object must name it; Create Key Pair must name both keys.
    assertThrows(
        ProtocolException.class,
        () ->
            call(
                ProtocolVersion.V2_1,
                Requests.createSymmetricKey(
                    Enums.CryptographicAlgorithm.AES, 128, Enums.CryptographicUsageMask.ENCRYPT),
                req -> new Ttlv[] {enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY)}));
    assertThrows(
        ProtocolException.class,
        () ->
            call(
                ProtocolVersion.V2_1,
                Request.operation(Operation.CREATE_KEY_PAIR).build(),
                req -> new Ttlv[] {text(PRIVATE_KEY_UNIQUE_IDENTIFIER, "priv")}));
    // A cryptographic result is required unless the request is a part of a multi-part operation;
    // a Correlation Value only in the response does not make it one.
    Request sign = CryptoRequests.sign("signer").data(new byte[] {1}).build();
    assertThrows(
        ProtocolException.class,
        () ->
            call(
                ProtocolVersion.V1_4, sign, req -> new Ttlv[] {text(UNIQUE_IDENTIFIER, "signer")}));
    assertThrows(
        ProtocolException.class,
        () ->
            call(
                ProtocolVersion.V1_4,
                sign,
                req ->
                    new Ttlv[] {
                      text(UNIQUE_IDENTIFIER, "signer"), bytes(CORRELATION_VALUE, new byte[] {9})
                    }));
    // Without a requested identifier (ID Placeholder) the response must still name the object.
    Request placeholder = CryptoRequests.encrypt(null).data(new byte[] {1}).build();
    assertThrows(
        ProtocolException.class,
        () ->
            call(
                ProtocolVersion.V1_4,
                placeholder,
                req -> new Ttlv[] {bytes(DATA, new byte[] {2})}));
    assertTrue(
        call(
                ProtocolVersion.V1_4,
                placeholder,
                req -> new Ttlv[] {text(UNIQUE_IDENTIFIER, "any"), bytes(DATA, new byte[] {2})})
            .successful());
  }

  /** A truncated ordered batch must be the request's prefix, ending at its only failure. */
  @Test
  void truncatedBatchesMustBeAPrefixEndingAtTheFailure() throws Exception {
    List<Request> batch =
        List.of(
            Requests.activate().uniqueIdentifier("a").build(),
            Requests.activate().uniqueIdentifier("b").build(),
            Requests.activate().uniqueIdentifier("c").build());
    var orderedStop = RequestOptions.DEFAULT.batching(true, Enums.BatchErrorContinuation.STOP);
    var unorderedStop = RequestOptions.DEFAULT.batching(false, Enums.BatchErrorContinuation.STOP);
    Function<int[], Function<Ttlv, Ttlv>> answer =
        spec ->
            req -> {
              var items = req.children(BATCH_ITEM);
              List<Ttlv> out = new ArrayList<>();
              // spec: pairs of (request index, status)
              for (int i = 0; i < spec.length; i += 2) {
                Ttlv it = items.get(spec[i]);
                String id = it.require(REQUEST_PAYLOAD).require(UNIQUE_IDENTIFIER).textValue();
                out.add(
                    spec[i + 1] == 1
                        ? item(it, 1)
                        : item(it, spec[i + 1], text(UNIQUE_IDENTIFIER, id)));
              }
              return response(req, out);
            };
    // Accepted: the prefix a (Success), b (Failed).
    try (var c = client(ProtocolVersion.V2_1, answer.apply(new int[] {0, 0, 1, 1}))) {
      Response r = c.batch(batch, orderedStop);
      assertTrue(r.resultFor(2).isEmpty());
      assertThrows(IndexOutOfBoundsException.class, () -> r.resultFor(3), "out of range");
      assertThrows(IndexOutOfBoundsException.class, () -> r.resultFor(-1));
    }
    // Rejected when ordered: a processed middle item is omitted (a, c) ...
    try (var c = client(ProtocolVersion.V2_1, answer.apply(new int[] {0, 0, 2, 1}))) {
      var e = assertThrows(ProtocolException.class, () -> c.batch(batch, orderedStop));
      assertTrue(e.getMessage().contains("prefix"), e.getMessage());
    }
    // ... unless the batch is unordered, where c may have run (and failed) before b.
    try (var c = client(ProtocolVersion.V2_1, answer.apply(new int[] {0, 0, 2, 1}))) {
      assertTrue(c.batch(batch, unorderedStop).resultFor(1).isEmpty());
    }
    // Rejected: an earlier item failed under Stop (two failures), or the failure is not last.
    try (var c = client(ProtocolVersion.V2_1, answer.apply(new int[] {0, 1, 1, 1}))) {
      assertThrows(ProtocolException.class, () -> c.batch(batch, orderedStop));
    }
    try (var c = client(ProtocolVersion.V2_1, answer.apply(new int[] {0, 1, 1, 0}))) {
      assertThrows(ProtocolException.class, () -> c.batch(batch, orderedStop));
    }
    // Rejected: an Undone item under Stop.
    try (var c = client(ProtocolVersion.V2_1, answer.apply(new int[] {0, 3, 1, 1}))) {
      assertThrows(ProtocolException.class, () -> c.batch(batch, orderedStop));
    }
    // Unordered, b may run before a fails; KMIP 3.0 batches are always ordered, so there it may
    // not.
    try (var c = client(ProtocolVersion.V2_1, answer.apply(new int[] {0, 1, 1, 0}))) {
      assertTrue(c.batch(batch, unorderedStop).resultFor(2).isEmpty());
    }
    try (var c = client(ProtocolVersion.V3_0, answer.apply(new int[] {0, 1, 1, 0}))) {
      assertThrows(
          ProtocolException.class,
          () ->
              c.batch(
                  batch, RequestOptions.DEFAULT.batching(true, Enums.BatchErrorContinuation.STOP)));
    }
  }

  /** A part of a multi-part operation returns no result yet. */
  @Test
  void multipartPartsNeedNoResultUntilTheEnd() throws Exception {
    Request middle =
        CryptoRequests.sign("signer").data(new byte[] {1}).continuing(new byte[] {7}).build();
    assertTrue(
        call(ProtocolVersion.V1_4, middle, req -> new Ttlv[] {text(UNIQUE_IDENTIFIER, "signer")})
            .successful());
    // The first part returns no result yet either, but it returns the Correlation Value that the
    // later parts send (KMIP 1.4 §2.1.15).
    Request init = CryptoRequests.encrypt("k").data(new byte[] {1}).init().build();
    assertTrue(
        call(
                ProtocolVersion.V1_4,
                init,
                req ->
                    new Ttlv[] {
                      text(UNIQUE_IDENTIFIER, "k"), bytes(CORRELATION_VALUE, new byte[] {7})
                    })
            .successful());
  }

  /** Batch Order Option defaults to True from KMIP 2.0. */
  @Test
  void anOmittedBatchOrderOptionIsOrderedFrom20AndUnorderedIn1x() throws Exception {
    List<Request> batch =
        List.of(
            Requests.activate().uniqueIdentifier("a").build(),
            Requests.activate().uniqueIdentifier("b").build(),
            Requests.activate().uniqueIdentifier("c").build());
    var stop =
        RequestOptions.DEFAULT.toBuilder()
            .batchErrorContinuation(Enums.BatchErrorContinuation.STOP)
            .build();
    Function<Ttlv, Ttlv> skipsTheMiddle =
        req -> {
          var items = req.children(BATCH_ITEM);
          return response(
              req,
              List.of(item(items.get(0), 0, text(UNIQUE_IDENTIFIER, "a")), item(items.get(2), 1)));
        };
    try (var c = client(ProtocolVersion.V2_1, skipsTheMiddle)) {
      assertThrows(ProtocolException.class, () -> c.batch(batch, stop));
    }
    try (var c = client(ProtocolVersion.V1_4, skipsTheMiddle)) {
      assertTrue(c.batch(batch, stop).resultFor(1).isEmpty(), "1.x defaults to unordered");
    }
  }

  /** A successful item answered with no Response Payload at all, as a payload-less Locate. */
  static Ttlv withoutPayload(Ttlv requestItem) {
    return structure(BATCH_ITEM, requestItem.require(OPERATION), enumeration(RESULT_STATUS, 0));
  }

  /**
   * KMIP 1.4 Table 285, 2.1 §9 and 3.0 §8.2.3 require the Response Payload unless the item failed,
   * also when every field of the payload is optional: a Locate that found nothing returns an empty
   * payload, not none. The SDK reports a missing one as a protocol error, not as an empty result.
   */
  @Test
  void aSuccessfulItemWithoutResponsePayloadIsAProtocolError() throws Exception {
    for (ProtocolVersion version :
        List.of(ProtocolVersion.V1_4, ProtocolVersion.V2_1, ProtocolVersion.V3_0))
      try (var c =
          client(version, req -> response(req, List.of(withoutPayload(req.require(BATCH_ITEM)))))) {
        var e =
            assertThrows(
                ProtocolException.class,
                () -> c.call(Requests.locate().build()),
                version.toString());
        assertEquals("Locate response missing ResponsePayload", e.getMessage(), version.toString());
      }
    try (var c =
        client(
            ProtocolVersion.V1_4,
            req ->
                response(
                    req,
                    List.of(
                        structure(
                            BATCH_ITEM,
                            req.require(BATCH_ITEM).require(OPERATION),
                            enumeration(RESULT_STATUS, 0),
                            structure(RESPONSE_PAYLOAD)))))) {
      assertTrue(
          c.call(Requests.locate().build()).requirePayload().children().isEmpty(),
          "an empty payload is a Locate that found nothing");
    }
  }

  /**
   * KMIP 1.4 §2.1.15: the server returns the Correlation Value in the first response of a
   * multi-part operation. A reply to an Init Indicator request without one was answered as a
   * single-part operation, and the next part would start another operation, so the SDK refuses it.
   */
  @Test
  void aFirstPartReplyWithoutCorrelationValueIsAProtocolError() throws Exception {
    Function<Ttlv, Ttlv> singlePart =
        req ->
            response(
                req,
                List.of(
                    item(
                        req.require(BATCH_ITEM),
                        0,
                        text(UNIQUE_IDENTIFIER, "k1"),
                        bytes(DATA, new byte[16]))));
    Request first =
        Requests.encrypt()
            .uniqueIdentifier("k1")
            .data(new byte[16])
            .add(bool(INIT_INDICATOR, true), bool(FINAL_INDICATOR, false))
            .build();
    try (var c = client(ProtocolVersion.V1_4, singlePart)) {
      var e = assertThrows(ProtocolException.class, () -> c.call(first));
      assertEquals("Encrypt response missing CorrelationValue", e.getMessage());
      // A request that is both the first and the last part is a whole operation.
      c.call(
          Requests.encrypt()
              .uniqueIdentifier("k1")
              .data(new byte[16])
              .add(bool(INIT_INDICATOR, true), bool(FINAL_INDICATOR, true))
              .build());
    }
    try (var c =
        client(
            ProtocolVersion.V1_4,
            req ->
                response(
                    req,
                    List.of(
                        item(
                            req.require(BATCH_ITEM),
                            0,
                            text(UNIQUE_IDENTIFIER, "k1"),
                            bytes(CORRELATION_VALUE, new byte[] {1})))))) {
      assertArrayEquals(
          new byte[] {1},
          c.call(first).requirePayload().require(CORRELATION_VALUE).bytesValue(),
          "a continued first part");
    }
  }
}
