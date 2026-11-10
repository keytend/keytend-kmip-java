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
import java.io.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.*;

class ClientTest {
  static Ttlv response(Ttlv request, List<Ttlv> results) {
    return structure(
        RESPONSE_MESSAGE,
        java.util.stream.Stream.concat(
                java.util.stream.Stream.of(
                    structure(
                        RESPONSE_HEADER,
                        request.require(REQUEST_HEADER).require(PROTOCOL_VERSION),
                        dateTime(TIME_STAMP, Instant.ofEpochSecond(1700000000)),
                        integer(BATCH_COUNT, results.size()))),
                results.stream())
            .toList());
  }

  /** A successful reply naming key-1, with the Object Type (and object) Create and Get return. */
  static Ttlv success(Ttlv requestItem) {
    List<Ttlv> items = new ArrayList<>();
    items.add(requestItem.require(OPERATION));
    requestItem.child(UNIQUE_BATCH_ITEM_ID).ifPresent(items::add);
    items.add(enumeration(RESULT_STATUS, 0));
    List<Ttlv> payload = new ArrayList<>(List.of(text(UNIQUE_IDENTIFIER, "key-1")));
    int op = requestItem.require(OPERATION).intValue();
    if (op == Operation.CREATE.code() || op == Operation.GET.code())
      payload.add(enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY));
    if (op == Operation.GET.code())
      payload.add(ManagedObjects.rawSymmetricKey(new byte[16], Enums.CryptographicAlgorithm.AES));
    items.add(structure(RESPONSE_PAYLOAD, payload));
    return structure(BATCH_ITEM, items);
  }

  @Test
  void malformedResponseIdentifiesMissingFieldWithoutExposingPayload() {
    String secret = "DO_NOT_LOG_SYNTHETIC_KEY";
    Ttlv malformed =
        structure(
            RESPONSE_MESSAGE,
            structure(
                RESPONSE_HEADER,
                Messages.protocolVersion(ProtocolVersion.V1_4),
                integer(BATCH_COUNT, 1)),
            structure(
                BATCH_ITEM,
                enumeration(OPERATION, Operation.GET),
                enumeration(RESULT_STATUS, 0),
                structure(
                    RESPONSE_PAYLOAD,
                    bytes(
                        KEY_MATERIAL, secret.getBytes(java.nio.charset.StandardCharsets.UTF_8)))));
    IOException failure = assertThrows(IOException.class, () -> Messages.response(malformed));
    assertTrue(failure.getMessage().contains("TimeStamp"));
    assertFalse(failure.getMessage().contains(secret));
  }

  /**
   * A response the codec cannot decode is a protocol violation (ProtocolException, no
   * response), not a transient I/O failure, and no value from it reaches a message or a cause.
   */
  @Test
  void undecodableResponsesAreProtocolExceptionsWithoutValues() throws Exception {
    String secret = "SECRET-4b1d9e0f00112233";
    byte[] json =
        ("{\"tag\":\"ResponseMessage\",\"value\":[{\"tag\":\"ResultStatus\","
                + "\"type\":\"Enumeration\",\"value\":\""
                + secret
                + "\"}]}")
            .getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] xml =
        ("<ResponseMessage><ActivationDate type=\"DateTime\" value=\""
                + secret
                + "\"/></ResponseMessage>")
            .getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] ttlv = TextProfileTest.malformedTtlvWithSecret();
    List<dev.keytend.kmip.transport.KmipTransport> servers =
        List.of(
            req -> new dev.keytend.kmip.codec.JsonCodec().decode(json),
            req -> new dev.keytend.kmip.codec.XmlCodec().decode(xml),
            req -> new dev.keytend.kmip.codec.TtlvCodec().decode(ttlv),
            req -> new dev.keytend.kmip.codec.TtlvCodec().read(new ByteArrayInputStream(ttlv)));
    for (var server : servers)
      try (var client = new KmipClient(server, ProtocolVersion.V2_1)) {
        ProtocolException e =
            assertThrows(ProtocolException.class, () -> client.call(Requests.query().build()));
        assertNull(e.response());
        assertInstanceOf(dev.keytend.kmip.codec.DecodeException.class, e.getCause());
        TextProfileTest.assertScrubbed(e);
      }
    // A decodable response whose checks fail on a value (version 19229.0 = 0x4B1D) does not
    // repeat that value in the message or the cause chain either.
    try (var client =
        new KmipClient(
            req ->
                structure(
                    RESPONSE_MESSAGE,
                    structure(
                        RESPONSE_HEADER,
                        structure(
                            PROTOCOL_VERSION,
                            integer(PROTOCOL_VERSION_MAJOR, 0x4B1D),
                            integer(PROTOCOL_VERSION_MINOR, 0)),
                        dateTime(TIME_STAMP, Instant.ofEpochSecond(1700000000)),
                        integer(BATCH_COUNT, 1)),
                    success(req.require(BATCH_ITEM))),
            ProtocolVersion.V2_1)) {
      ProtocolException e =
          assertThrows(ProtocolException.class, () -> client.call(Requests.query().build()));
      for (Throwable t = e; t != null; t = t.getCause())
        assertFalse(t.toString().contains("19229"), t.toString());
    }
  }

  @Test
  void versionGatesEveryOperationBeforeSending() throws Exception {
    int[] sends = {0};
    try (var client =
        new KmipClient(
            req -> {
              sends[0]++;
              return response(req, List.of(success(req.require(BATCH_ITEM))));
            },
            ProtocolVersion.V1_1)) {
      assertThrows(IllegalArgumentException.class, () -> client.call(Requests.encrypt().build()));
      assertEquals(0, sends[0]);
      assertEquals("key-1", client.call(Requests.create().build()).uniqueIdentifier());
      assertThrows(
          IllegalArgumentException.class,
          () ->
              client.batch(
                  List.of(Requests.get().build()), RequestOptions.DEFAULT.correlation("id", null)));
    }
    for (ProtocolVersion v : ProtocolVersion.values())
      for (Operation op : Operation.values())
        if (!v.atLeast(op.since()))
          assertThrows(
              IllegalArgumentException.class,
              () ->
                  Messages.request(
                      v, List.of(Request.operation(op).build()), RequestOptions.DEFAULT));
  }

  @Test
  void batchIdsAreCorrelatedEvenWhenRepliesAreReordered() throws Exception {
    try (var client =
        new KmipClient(
            req -> {
              List<Ttlv> items = new ArrayList<>(req.children(BATCH_ITEM));
              Collections.reverse(items);
              return response(req, items.stream().map(ClientTest::success).toList());
            },
            ProtocolVersion.V1_4)) {
      Response r = client.batch(List.of(Requests.get().build(), Requests.getAttributes().build()));
      assertEquals(2, r.results().size());
      assertArrayEquals(new byte[] {0, 0, 0, 2}, r.results().get(0).batchId().orElseThrow());
    }
  }

  @Test
  void rejectsMismatchedAndDuplicatedResponses() throws Exception {
    try (var c =
        new KmipClient(
            req ->
                response(
                    req,
                    List.of(
                        structure(
                            BATCH_ITEM,
                            enumeration(OPERATION, Operation.DESTROY),
                            enumeration(RESULT_STATUS, 0)))),
            ProtocolVersion.V1_4)) {
      assertThrows(ProtocolException.class, () -> c.call(Requests.get().build()));
    }
    try (var c =
        new KmipClient(
            req ->
                response(
                    req,
                    List.of(success(req.require(BATCH_ITEM)), success(req.require(BATCH_ITEM)))),
            ProtocolVersion.V1_4)) {
      assertThrows(
          ProtocolException.class,
          () -> c.batch(List.of(Requests.get().build(), Requests.get().build())));
    }
    Request a = Requests.get().batchId(new byte[] {1}).build(),
        b = Requests.get().batchId(new byte[] {1}).build();
    assertThrows(
        IllegalArgumentException.class,
        () -> Messages.request(ProtocolVersion.V1_4, List.of(a, b), RequestOptions.DEFAULT));
  }

  @Test
  void failuresPendingAndVendorReasonsRemainInspectable() throws Exception {
    try (var c =
        new KmipClient(
            req ->
                response(
                    req,
                    List.of(
                        structure(
                            BATCH_ITEM,
                            enumeration(OPERATION, Operation.GET),
                            enumeration(RESULT_STATUS, 1),
                            enumeration(RESULT_REASON, 0x80000001),
                            text(RESULT_MESSAGE, "vendor error")))),
            ProtocolVersion.V1_4)) {
      Result r = c.execute(Requests.get().build());
      assertEquals(0x80000001, r.reason());
      assertEquals("vendor error", r.message());
      assertSame(r, assertThrows(KmipException.class, r::requireSuccess).result());
    }
    byte[] correlation = {1, 2, 3};
    try (var c =
        new KmipClient(
            req ->
                response(
                    req,
                    List.of(
                        structure(
                            BATCH_ITEM,
                            enumeration(OPERATION, Operation.CREATE),
                            enumeration(RESULT_STATUS, 2),
                            bytes(ASYNCHRONOUS_CORRELATION_VALUE, correlation)))),
            ProtocolVersion.V1_4)) {
      Result r = c.execute(Requests.create().build());
      assertTrue(r.pending());
      assertArrayEquals(correlation, r.asynchronousCorrelation().orElseThrow());
      assertThrows(KmipException.class, r::requireSuccess);
    }
  }

  @Test
  void preservesRawNonconformantError() throws Exception {
    Ttlv bad =
        structure(
            RESPONSE_MESSAGE,
            structure(
                RESPONSE_HEADER,
                structure(
                    PROTOCOL_VERSION,
                    integer(PROTOCOL_VERSION_MAJOR, 1),
                    integer(PROTOCOL_VERSION_MINOR, 0)),
                dateTime(TIME_STAMP, Instant.EPOCH),
                integer(BATCH_COUNT, 1)),
            structure(BATCH_ITEM, enumeration(RESULT_STATUS, 1), enumeration(RESULT_REASON, 5)));
    try (var client = new KmipClient(req -> bad, ProtocolVersion.V1_4)) {
      ProtocolException e =
          assertThrows(ProtocolException.class, () -> client.execute(Requests.get().build()));
      assertSame(bad, e.response());
    }
  }

  @Test
  void discoverFiltersOtherVersionsAndNegotiates() throws Exception {
    try (var c =
        new KmipClient(
            req ->
                response(
                    req,
                    List.of(
                        structure(
                            BATCH_ITEM,
                            enumeration(OPERATION, Operation.DISCOVER_VERSIONS),
                            enumeration(RESULT_STATUS, 0),
                            structure(
                                RESPONSE_PAYLOAD,
                                structure(
                                    PROTOCOL_VERSION,
                                    integer(PROTOCOL_VERSION_MAJOR, 2),
                                    integer(PROTOCOL_VERSION_MINOR, 1)),
                                Messages.protocolVersion(ProtocolVersion.V1_2),
                                Messages.protocolVersion(ProtocolVersion.V1_1))))),
            ProtocolVersion.V1_4)) {
      assertEquals(
          List.of(ProtocolVersion.V2_1, ProtocolVersion.V1_2, ProtocolVersion.V1_1),
          c.discoverVersions());
      assertEquals(ProtocolVersion.V1_2, c.negotiate().version());
    }
  }

  @Test
  void callbacksExposeNotifyPutAndQuery() throws Exception {
    List<Operation> handled = new ArrayList<>();
    Ttlv request =
        Messages.request(
            ProtocolVersion.V1_4,
            List.of(
                Requests.notifyRequest().build(), Requests.put().build(), Requests.query().build()),
            RequestOptions.DEFAULT);
    Ttlv response =
        CallbackMessages.respond(
            request,
            (op, payload) -> {
              handled.add(op);
              return CallbackHandler.Reply.success(
                  structure(RESPONSE_PAYLOAD, text(UNIQUE_IDENTIFIER, "stored")));
            });
    var result = Messages.correlate(request, Messages.response(response));
    assertEquals(List.of(Operation.NOTIFY, Operation.PUT, Operation.QUERY), handled);
    assertTrue(result.results().stream().allMatch(Result::successful));
  }

  @Test
  void cryptographicParametersUseNormativeOrder() {
    Ttlv payload =
        Requests.sign()
            .cryptographicParameters(
                enumeration(CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.RSA),
                enumeration(HASHING_ALGORITHM, Enums.HashingAlgorithm.SHA_256),
                enumeration(PADDING_METHOD, Enums.PaddingMethod.PKCS1_V1_5))
            .build()
            .payload();
    assertEquals(
        List.of(PADDING_METHOD.code(), HASHING_ALGORITHM.code(), CRYPTOGRAPHIC_ALGORITHM.code()),
        payload.require(CRYPTOGRAPHIC_PARAMETERS).children().stream().map(Ttlv::tag).toList());
  }
}
