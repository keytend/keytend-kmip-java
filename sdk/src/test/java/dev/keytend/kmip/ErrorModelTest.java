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
import java.io.IOException;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;

/** Error model and typed results. */
class ErrorModelTest {
  static Ttlv reply(Ttlv request, Ttlv... itemFields) {
    List<Ttlv> fields = new ArrayList<>(List.of(itemFields));
    return structure(
        RESPONSE_MESSAGE,
        structure(
            RESPONSE_HEADER,
            request.require(REQUEST_HEADER).require(PROTOCOL_VERSION),
            dateTime(TIME_STAMP, Instant.ofEpochSecond(1700000000)),
            integer(BATCH_COUNT, 1)),
        structure(BATCH_ITEM, fields));
  }

  static Result result(int status, Integer reason, String message, Ttlv... payload) {
    List<Ttlv> fields = new ArrayList<>();
    fields.add(enumeration(OPERATION, Operation.GET));
    fields.add(enumeration(RESULT_STATUS, status));
    if (reason != null) fields.add(enumeration(RESULT_REASON, reason));
    if (payload.length > 0) fields.add(structure(RESPONSE_PAYLOAD, payload));
    return new Result(Operation.GET, status, reason, message, structure(BATCH_ITEM, fields));
  }

  @Test
  void enumsHaveCodeLookupsAndResultsHaveTypedReasons() {
    assertEquals(Optional.of(Enums.State.ACTIVE), Enums.State.fromCode(2));
    assertEquals(Optional.empty(), Enums.State.fromCode(0x80000001));
    assertEquals(Enums.ObjectType.SYMMETRIC_KEY, WireEnums.requireCode(Enums.ObjectType.class, 2));
    Result ok = result(0, null, null);
    assertFalse(ok.hasReason(Enums.ResultReason.ITEM_NOT_FOUND), "no NullPointerException");
    assertEquals(Optional.of(Enums.ResultStatus.SUCCESS), ok.statusEnum());
    Result missing = result(1, Enums.ResultReason.ITEM_NOT_FOUND.code(), "gone");
    assertTrue(missing.hasReason(Enums.ResultReason.ITEM_NOT_FOUND));
    assertEquals(Optional.of(Enums.ResultReason.ITEM_NOT_FOUND), missing.reasonEnum());
  }

  @Test
  void exceptionMessagesNameTheFailureWithoutPeerText() {
    var get = new KmipException(result(1, 1, "Object key-A not found"));
    assertEquals(
        "KMIP Get returned OperationFailed (1), reason ItemNotFound (0x00000001)",
        get.getMessage());
    assertEquals(
        "Object key-A not found", get.result().message(), "the server text stays available");
    Result whole =
        new Result(
            null,
            1,
            Enums.ResultReason.PERMISSION_DENIED.code(),
            "bad auth\n\u0007",
            structure(BATCH_ITEM, enumeration(RESULT_STATUS, 1)));
    String text = new KmipException(whole).getMessage();
    assertFalse(text.contains("null"), text);
    assertTrue(text.startsWith("KMIP message-level returned OperationFailed"), text);
    assertTrue(text.contains("PermissionDenied"), text);
    assertFalse(text.contains("bad auth"), "peer-controlled text is not logged");
  }

  @Test
  void malformedSuccessPayloadsAreProtocolExceptions() throws Exception {
    try (var c =
        new KmipClient(
            req ->
                reply(
                    req, req.require(BATCH_ITEM).require(OPERATION), enumeration(RESULT_STATUS, 0)),
            ProtocolVersion.V1_4)) {
      var e =
          assertThrows(
              ProtocolException.class,
              () ->
                  c.createSymmetricKey(
                      Enums.CryptographicAlgorithm.AES, 128, Enums.CryptographicUsageMask.ENCRYPT));
      assertNotNull(e.response(), "the batch item is kept for reconciliation");
      assertThrows(
          ProtocolException.class,
          () ->
              c.register(
                  ManagedObjects.rawSymmetricKey(new byte[16], Enums.CryptographicAlgorithm.AES)));
    }
    try (var c =
        new KmipClient(
            req ->
                reply(
                    req,
                    req.require(BATCH_ITEM).require(OPERATION),
                    enumeration(RESULT_STATUS, 0),
                    structure(
                        RESPONSE_PAYLOAD,
                        structure(PROTOCOL_VERSION, text(PROTOCOL_VERSION_MAJOR, "one")))),
            ProtocolVersion.V1_4)) {
      assertThrows(ProtocolException.class, c::discoverVersions);
    }
    // A zero-length DER INTEGER in a PKCS#1 key is an IOException, not NumberFormatException.
    Ttlv object =
        ManagedObjects.publicKey(
            ManagedObjects.keyBlock(
                Enums.KeyFormatType.PKCS_1,
                bytes(KEY_MATERIAL, new byte[] {0x30, 0x04, 0x02, 0x00, 0x02, 0x00}),
                Enums.CryptographicAlgorithm.RSA,
                2048));
    assertThrows(IOException.class, () -> Keys.rsaPublicKey(object));
  }

  @Test
  void boundaryArgumentsFailWithClearExceptions() {
    var e =
        assertThrows(
            IllegalArgumentException.class,
            () -> ManagedObjects.objectType(structure(0x540001, List.of())));
    assertTrue(e.getMessage().contains("Not a managed object"));
    var wrongType =
        assertThrows(
            IllegalArgumentException.class, () -> Ttlv.of(0x540001, Ttlv.Type.LONG_INTEGER, 5));
    assertTrue(wrongType.getMessage().contains("Long"), wrongType.getMessage());
    Ttlv reason =
        Requests.revoke("k", Enums.RevocationReasonCode.KEY_COMPROMISE, null)
            .payload()
            .require(REVOCATION_REASON);
    assertTrue(reason.child(REVOCATION_MESSAGE).isEmpty());
    var npe = assertThrows(NullPointerException.class, () -> Ttlv.text(COMMENT, null));
    assertTrue(npe.getMessage().contains("Comment"), npe.getMessage());
  }

  @Test
  void signatureVerifyValidityIsTyped_kmip21Section6_1_51() throws Exception {
    var invalid =
        SignatureVerifyResult.of(
            result(
                0,
                null,
                null,
                text(UNIQUE_IDENTIFIER, "k"),
                enumeration(VALIDITY_INDICATOR, Enums.ValidityIndicator.INVALID)));
    assertFalse(invalid.valid(), "a successful call returning Invalid is not a valid signature");
    assertEquals(Optional.of(Enums.ValidityIndicator.INVALID), invalid.validity());
    assertTrue(
        SignatureVerifyResult.of(
                result(
                    0,
                    null,
                    null,
                    text(UNIQUE_IDENTIFIER, "k"),
                    enumeration(VALIDITY_INDICATOR, Enums.ValidityIndicator.VALID)))
            .valid());
    assertThrows(
        ProtocolException.class,
        () -> SignatureVerifyResult.of(result(0, null, null, text(UNIQUE_IDENTIFIER, "k"))));
  }

  @Test
  void getAttributesWithOnlyTheIdentifierIsEmpty() throws Exception {
    var empty = GetAttributesResult.of(result(0, null, null, text(UNIQUE_IDENTIFIER, "k")));
    assertTrue(empty.isEmpty());
    assertEquals("k", empty.uniqueIdentifier());
    var modern =
        GetAttributesResult.of(
            result(
                0,
                null,
                null,
                text(UNIQUE_IDENTIFIER, "k"),
                structure(ATTRIBUTES, enumeration(STATE, Enums.State.ACTIVE))));
    assertEquals(1, modern.attributes().size());
  }
}
