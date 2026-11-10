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

/**
 * A successful response is checked against the Required fields of its version's
 * payload table (KMIP 1.x section 4, 2.x and 3.0 section 6), and only a multi-part request exempts
 * a single-part result.
 */
class ResponsePayloadTablesTest {
  private static final List<ProtocolVersion> V1X =
      List.of(
          ProtocolVersion.V1_1, ProtocolVersion.V1_2, ProtocolVersion.V1_3, ProtocolVersion.V1_4);
  private static final List<ProtocolVersion> V2X =
      List.of(ProtocolVersion.V2_0, ProtocolVersion.V2_1, ProtocolVersion.V3_0);

  private static Result call(ProtocolVersion v, Request request, Ttlv... payload) throws Exception {
    return CorrelationTest.call(v, request, req -> payload);
  }

  private static void accepted(ProtocolVersion v, Request request, Ttlv... payload)
      throws Exception {
    assertTrue(call(v, request, payload).successful(), v.toString());
  }

  private static void rejected(
      String message, ProtocolVersion v, Request request, Ttlv... payload) {
    var e =
        assertThrows(ProtocolException.class, () -> call(v, request, payload), v + ": " + message);
    assertEquals(message, e.getMessage(), v.toString());
  }

  private static Ttlv id(String id) {
    return text(UNIQUE_IDENTIFIER, id);
  }

  private static Ttlv key() {
    return ManagedObjects.rawSymmetricKey(new byte[16], Enums.CryptographicAlgorithm.AES);
  }

  private static Ttlv symmetric() {
    return enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY);
  }

  /**
   * Data is "No." in the 2.0, 2.1 and 3.0 Encrypt and Decrypt response tables (a GCM decrypt of an
   * empty plaintext), while 1.2 requires it and 1.3 and 1.4 require it for a single-part request.
   */
  @Test
  void
      dataIsOptionalInCryptoResponsesFrom20Only_kmip21Section6_1_11And6_1_17_kmip14Section4_29And4_30()
          throws Exception {
    for (ProtocolVersion v : V2X) {
      accepted(v, CryptoRequests.decrypt("k").data(new byte[16]).build(), id("k"));
      accepted(v, CryptoRequests.encrypt("k").data(new byte[0]).build(), id("k"));
    }
    for (ProtocolVersion v :
        List.of(ProtocolVersion.V1_2, ProtocolVersion.V1_3, ProtocolVersion.V1_4)) {
      rejected(
          "Decrypt response missing Data",
          v,
          CryptoRequests.decrypt("k").data(new byte[16]).build(),
          id("k"));
      rejected(
          "Encrypt response missing Data",
          v,
          CryptoRequests.encrypt("k").data(new byte[1]).build(),
          id("k"));
      accepted(
          v,
          CryptoRequests.decrypt("k").data(new byte[16]).build(),
          id("k"),
          bytes(DATA, new byte[0]));
    }
  }

  /** Only the request makes an item a part of a multi-part operation. */
  @Test
  void anUnsolicitedResponseCorrelationValueExemptsNothing() throws Exception {
    Ttlv correlation = bytes(CORRELATION_VALUE, new byte[] {9});
    Request macVerify =
        CryptoRequests.macVerify("m").data(new byte[] {1}).macData(new byte[] {2}).build();
    rejected(
        "MACVerify response missing ValidityIndicator",
        ProtocolVersion.V2_1,
        macVerify,
        id("m"),
        correlation);
    rejected(
        "Sign response missing SignatureData",
        ProtocolVersion.V2_1,
        CryptoRequests.sign("s").data(new byte[] {1}).build(),
        id("s"),
        correlation);
    rejected(
        "Decrypt response missing Data",
        ProtocolVersion.V1_4,
        CryptoRequests.decrypt("k").data(new byte[16]).build(),
        id("k"),
        correlation);
    // The same parts of a multi-part request need no result yet ("No for multi-part").
    accepted(
        ProtocolVersion.V2_1,
        CryptoRequests.macVerify("m").data(new byte[] {1}).continuing(new byte[] {9}).build(),
        id("m"),
        correlation);
    accepted(
        ProtocolVersion.V1_4,
        CryptoRequests.decrypt("k").data(new byte[16]).init().build(),
        id("k"),
        correlation);
  }

  /**
   * {@link SignatureVerifyResult#of} does not let a response Correlation Value stand in for a
   * missing Validity Indicator, as the payload checks do not. It is
   * the reader of a verdict and cannot see the request, so it now requires the Validity Indicator;
   * a part of a multi-part verification is read with {@link CryptoResult#of}.
   */
  @Test
  void signatureVerifyResultNeedsAVerdictWhateverTheCorrelationValue() throws Exception {
    Ttlv correlation = bytes(CORRELATION_VALUE, new byte[] {9});
    // A multi-part part may omit the verdict from 2.0 ("No for multi-part"), so correlate accepts
    // it.
    Result part =
        call(
            ProtocolVersion.V2_1,
            CryptoRequests.signatureVerify("s").data(new byte[] {1}).init().build(),
            id("s"),
            correlation);
    var e = assertThrows(ProtocolException.class, () -> SignatureVerifyResult.of(part));
    assertEquals(
        "Malformed Signature Verify response: ResponsePayload missing ValidityIndicator",
        e.getMessage());
    assertTrue(CryptoResult.of(part).validity().isEmpty());
    Result verdict =
        call(
            ProtocolVersion.V2_1,
            CryptoRequests.signatureVerify("s")
                .data(new byte[] {1})
                .signature(new byte[] {2})
                .build(),
            id("s"),
            correlation,
            enumeration(VALIDITY_INDICATOR, Enums.ValidityIndicator.VALID));
    assertTrue(SignatureVerifyResult.of(verdict).valid());
  }

  /** Get returns Object Type and the object in every version (1.4 section 4.11, 2.1 section 6.1.19). */
  @Test
  void getMustReturnTheObjectTypeAndTheObject_kmip14Section4_11() throws Exception {
    Request get = Requests.get().uniqueIdentifier("k").build();
    for (ProtocolVersion v : ProtocolVersion.values()) {
      rejected("Get response missing ObjectType", v, get, id("k"), key());
      rejected("Get response missing its object", v, get, id("k"), symmetric());
      accepted(v, get, id("k"), symmetric(), key());
    }
  }

  /** Export (1.4 section 4.40, 2.1 section 6.1.18) returns the object and its attributes. */
  @Test
  void exportMustReturnTheObjectAndItsAttributes_kmip14Section4_40() throws Exception {
    Request export = Requests.export().uniqueIdentifier("k").build();
    Ttlv attribute =
        structure(
            ATTRIBUTE, text(ATTRIBUTE_NAME, "Object Type"), symmetric().retag(ATTRIBUTE_VALUE));
    rejected(
        "Export response missing Attribute",
        ProtocolVersion.V1_4,
        export,
        symmetric(),
        id("k"),
        key());
    rejected(
        "Export response missing its object",
        ProtocolVersion.V1_4,
        export,
        symmetric(),
        id("k"),
        attribute);
    accepted(ProtocolVersion.V1_4, export, symmetric(), id("k"), attribute, key());
    Ttlv attributes = structure(ATTRIBUTES, symmetric());
    for (ProtocolVersion v : V2X) {
      rejected("Export response missing Attributes", v, export, symmetric(), id("k"), key());
      rejected("Export response missing its object", v, export, symmetric(), id("k"), attributes);
      accepted(v, export, symmetric(), id("k"), attributes, key());
    }
  }

  /** Attributes is Required in the 2.x Get Attributes response (2.1 section 6.1.20), not in 1.x. */
  @Test
  void getAttributesRequiresAttributesFrom20_kmip21Section6_1_20() throws Exception {
    Request get = Requests.getAttributes().uniqueIdentifier("k").build();
    for (ProtocolVersion v : V1X) accepted(v, get, id("k"));
    for (ProtocolVersion v : V2X) {
      rejected("GetAttributes response missing Attributes", v, get, id("k"));
      accepted(v, get, id("k"), structure(ATTRIBUTES));
    }
  }

  /** The 1.x attribute edits return the attribute (1.4 sections 4.14-4.16); 2.x ones do not. */
  @Test
  void oneXAttributeEditsReturnTheAttribute_kmip14Section4_14() throws Exception {
    Request add =
        Requests.addAttribute()
            .uniqueIdentifier("k")
            .add(structure(ATTRIBUTE, text(ATTRIBUTE_NAME, "x-a"), text(ATTRIBUTE_VALUE, "v")))
            .build();
    for (ProtocolVersion v : V1X)
      rejected("AddAttribute response missing Attribute", v, add, id("k"));
    for (ProtocolVersion v : V2X) accepted(v, add, id("k"));
  }

  /** Obtain Lease returns Lease Time and Last Change Date (1.4 section 4.17). */
  @Test
  void obtainLeaseReturnsTheLease_kmip14Section4_17() throws Exception {
    Request lease = Requests.obtainLease().uniqueIdentifier("k").build();
    Ttlv time = interval(LEASE_TIME, 60), changed = dateTime(LAST_CHANGE_DATE, Instant.EPOCH);
    for (ProtocolVersion v : ProtocolVersion.values()) {
      rejected("ObtainLease response missing LeaseTime", v, lease, id("k"), changed);
      rejected("ObtainLease response missing LastChangeDate", v, lease, id("k"), time);
      accepted(v, lease, id("k"), time, changed);
    }
  }

  /** Validate returns a Validity Indicator (1.4 section 4.24). */
  @Test
  void validateReturnsAValidityIndicator_kmip14Section4_24() throws Exception {
    Request validate = Requests.validate().add(id("cert")).build();
    for (ProtocolVersion v : ProtocolVersion.values()) {
      rejected("Validate response missing ValidityIndicator", v, validate);
      accepted(v, validate, enumeration(VALIDITY_INDICATOR, Enums.ValidityIndicator.VALID));
    }
  }

  /** Cancel returns the correlation value and the Cancellation Result (1.4 section 4.27). */
  @Test
  void cancelReturnsItsResult_kmip14Section4_27() throws Exception {
    Ttlv correlation = bytes(ASYNCHRONOUS_CORRELATION_VALUE, new byte[] {7});
    Ttlv result = enumeration(CANCELLATION_RESULT, Enums.CancellationResult.CANCELED);
    Request cancel = Requests.cancel().add(correlation).build();
    for (ProtocolVersion v : ProtocolVersion.values()) {
      rejected("Cancel response missing CancellationResult", v, cancel, correlation);
      rejected("Cancel response missing AsynchronousCorrelationValue", v, cancel, result);
      accepted(v, cancel, correlation, result);
    }
  }

  /** Create returns the Object Type it created (1.4 section 4.1, 2.1 section 6.1.8). */
  @Test
  void createReturnsItsObjectType_kmip14Section4_1() throws Exception {
    Request create =
        Requests.createSymmetricKey(
            Enums.CryptographicAlgorithm.AES, 128, Enums.CryptographicUsageMask.ENCRYPT);
    for (ProtocolVersion v : ProtocolVersion.values()) {
      rejected("Create response missing ObjectType", v, create, id("k"));
      accepted(v, create, symmetric(), id("k"));
    }
  }

  private static Ttlv secretType() {
    return enumeration(OBJECT_TYPE, Enums.ObjectType.SECRET_DATA);
  }

  private static Ttlv secret() {
    return ManagedObjects.secretData(
        Enums.SecretDataType.PASSWORD,
        ManagedObjects.keyBlock(
            Enums.KeyFormatType.OPAQUE, bytes(KEY_MATERIAL, new byte[8]), null, null));
  }

  /**
   * A Create response's Object Type is the type created (1.4 section 4.1, 2.1
   * section 6.1.8, 3.0 section 6.1.12), so it must be the requested one. Before the fix an AES Create
   * answered with the identifier of an existing Secret Data object and Object Type Secret Data was
   * accepted, and {@code createAes().create()} then activated that secret.
   */
  @Test
  void createMustReturnTheRequestedObjectType() throws Exception {
    Request create =
        Requests.createSymmetricKey(
            Enums.CryptographicAlgorithm.AES, 128, Enums.CryptographicUsageMask.ENCRYPT);
    for (ProtocolVersion v : ProtocolVersion.values()) {
      rejected("Create response has another ObjectType", v, create, secretType(), id("secret"));
      // The right code with the wrong type is not the requested Object Type either.
      rejected(
          "Create response has another ObjectType",
          v,
          create,
          integer(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY.code()),
          id("k"));
      accepted(v, create, symmetric(), id("k"));
    }
  }

  /**
   * Register and Create Key Pair responses have no Object Type in any version (1.4 Tables
   * 167 and 170, 2.1 Tables 190 and 292, 3.0 Tables 284 and 401), so a response without one is
   * accepted and its identifiers cannot be checked; a Register response that adds an Object Type
   * anyway must name the registered type. Create Split Key and Join Split Key return the type
   * created in 1.2 (1.2 Tables 221 and 223) and must echo the request.
   */
  @Test
  void otherCreationsEchoTheObjectTypeWhereTheyReturnOne() throws Exception {
    Request register =
        Requests.registerObject(key(), Attributes.usage(Enums.CryptographicUsageMask.ENCRYPT));
    Request pair =
        KeyPairRequest.ec(Enums.RecommendedCurve.P_256, Enums.CryptographicAlgorithm.ECDSA).build();
    for (ProtocolVersion v : ProtocolVersion.values()) {
      accepted(v, register, id("k"));
      accepted(v, register, symmetric(), id("k"));
      rejected("Register response has another ObjectType", v, register, secretType(), id("k"));
      accepted(
          v,
          pair,
          text(PRIVATE_KEY_UNIQUE_IDENTIFIER, "a"),
          text(PUBLIC_KEY_UNIQUE_IDENTIFIER, "b"));
    }
    Ttlv splitType = enumeration(OBJECT_TYPE, Enums.ObjectType.SPLIT_KEY);
    Request split =
        SplitKeyRequests.create(
            Enums.ObjectType.SPLIT_KEY, "k", 2, 2, Enums.SplitKeyMethod.XOR, null);
    Request join = SplitKeyRequests.join(Enums.ObjectType.SYMMETRIC_KEY, List.of("a", "b"), null);
    rejected(
        "CreateSplitKey response has another ObjectType",
        ProtocolVersion.V1_2,
        split,
        symmetric(),
        id("a"),
        id("b"));
    accepted(ProtocolVersion.V1_2, split, splitType, id("a"), id("b"));
    rejected(
        "JoinSplitKey response has another ObjectType",
        ProtocolVersion.V1_2,
        join,
        secretType(),
        id("k"));
    accepted(ProtocolVersion.V1_2, join, symmetric(), id("k"));
    for (ProtocolVersion v : V2X) {
      accepted(v, split, id("a"), id("b"));
      accepted(v, join, id("k"));
    }
  }

  /**
   * The object a Get (1.4 section 4.11, 2.1 section 6.1.19) or Export (1.4 section 4.40,
   * 2.1 section 6.1.18) response returns must be of the Object Type it declares. Which type the
   * caller expected is not checked here (a Get request names none); the kms layer checks the kind.
   */
  @Test
  void theReturnedObjectMustMatchItsObjectType() throws Exception {
    Request get = Requests.get().uniqueIdentifier("k").build();
    Request export = Requests.export().uniqueIdentifier("k").build();
    for (ProtocolVersion v : ProtocolVersion.values()) {
      rejected(
          "Get response object does not match its ObjectType",
          v,
          get,
          id("k"),
          symmetric(),
          secret());
      rejected(
          "Get response object does not match its ObjectType",
          v,
          get,
          id("k"),
          secretType(),
          key());
      rejected(
          "Get response object does not match its ObjectType",
          v,
          get,
          id("k"),
          symmetric(),
          key(),
          secret());
      rejected(
          "Get response object does not match its ObjectType",
          v,
          get,
          id("k"),
          integer(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY.code()),
          key());
      accepted(v, get, id("k"), secretType(), secret());
      if (!v.atLeast(ProtocolVersion.V1_4)) continue;
      Ttlv attributes =
          v.atLeast(ProtocolVersion.V2_0)
              ? structure(ATTRIBUTES, symmetric())
              : structure(
                  ATTRIBUTE,
                  text(ATTRIBUTE_NAME, "Object Type"),
                  symmetric().retag(ATTRIBUTE_VALUE));
      rejected(
          "Export response object does not match its ObjectType",
          v,
          export,
          symmetric(),
          id("k"),
          attributes,
          secret());
      accepted(v, export, symmetric(), id("k"), attributes, key());
    }
  }

  /**
   * The remaining operations with required response fields. Hash
   * returns Data (1.2 section 4.30, "for single-part" from 1.3), RNG Seed its Data Length (1.2
   * section 4.31), Create Split Key its identifiers, and in 1.2 its Object Type (1.2 section 4.38).
   */
  @Test
  void hashRngSeedAndCreateSplitKeyReturnTheirFields_sol3() throws Exception {
    Request hash = Requests.hash().add(bytes(DATA, new byte[] {1})).build();
    Request seed = Requests.rngSeed().add(bytes(DATA, new byte[] {1})).build();
    Request split = Requests.createSplitKey().build();
    for (ProtocolVersion v : ProtocolVersion.values()) {
      if (!v.atLeast(ProtocolVersion.V1_2)) continue;
      rejected("Hash response missing Data", v, hash);
      accepted(v, hash, bytes(DATA, new byte[32]));
      rejected("RNGSeed response missing DataLength", v, seed);
      accepted(v, seed, integer(DATA_LENGTH, 1));
      rejected("CreateSplitKey response missing UniqueIdentifier", v, split, symmetric());
      if (v == ProtocolVersion.V1_2)
        rejected("CreateSplitKey response missing ObjectType", v, split, id("a"), id("b"));
      accepted(v, split, symmetric(), id("a"), id("b"));
    }
    // A response Correlation Value does not make a single-part Hash multi-part.
    rejected(
        "Hash response missing Data",
        ProtocolVersion.V1_4,
        hash,
        bytes(CORRELATION_VALUE, new byte[] {9}));
  }

  /**
   * Sol-3: an unsolicited response Correlation Value on a single-part Encrypt let a response
   * without Data through. On 1.3 and 1.4, where single-part Encrypt requires Data, it no longer does
   * (from 2.0 Data is optional in the table and the kms layer requires it for non-empty input:
   * {@code KmsResponseValidationTest.anUnsolicitedCorrelationValueDoesNotExcuseAMissingEncryptOutput}).
   */
  @Test
  void anUnsolicitedCorrelationValueOnASinglePartEncryptIsNoExcuse_sol3() throws Exception {
    Request encrypt = CryptoRequests.encrypt("k").data(new byte[16]).build();
    Ttlv correlation = bytes(CORRELATION_VALUE, new byte[] {9});
    for (ProtocolVersion v : List.of(ProtocolVersion.V1_3, ProtocolVersion.V1_4))
      rejected("Encrypt response missing Data", v, encrypt, id("k"), correlation);
    accepted(
        ProtocolVersion.V1_4,
        CryptoRequests.encrypt("k").data(new byte[16]).init().build(),
        id("k"),
        correlation);
  }

  /**
   * Deactivate (3.0) echoes the object it deactivated, as the identifier-echo list says.
   */
  @Test
  void deactivateEchoesItsObject_kmip30() throws Exception {
    Request deactivate = Requests.deactivate().uniqueIdentifier("k").build();
    rejected("Deactivate response missing UniqueIdentifier", ProtocolVersion.V3_0, deactivate);
    rejected(
        "Deactivate response names another object", ProtocolVersion.V3_0, deactivate, id("other"));
    accepted(ProtocolVersion.V3_0, deactivate, id("k"));
  }

  /**
   * Every Required field of every response table is enforced: a payload holding all of them is
   * accepted, and one missing any single field is rejected. A field required "for single-part"
   * only is also exempt for a multi-part request.
   */
  @Test
  void everyRequiredFieldOfEveryResponseTableIsEnforced() throws Exception {
    int checked = 0;
    for (ProtocolVersion v : ProtocolVersion.values())
      for (Operation op : Operation.values()) {
        if (!v.atLeast(op.since())) continue;
        List<ProtocolSchema.Field> required =
            ProtocolSchema.fields(v, op, ProtocolSchema.Direction.RESPONSE).stream()
                .filter(f -> f.requirement().startsWith("Yes"))
                .toList();
        List<Ttlv> all = new ArrayList<>();
        for (ProtocolSchema.Field f : required)
          all.add(
              f.tag()
                  .map(t -> t == OBJECT_TYPE ? symmetric() : text(t, "x"))
                  .orElseGet(ResponsePayloadTablesTest::key));
        assertTrue(correlates(v, op, structure(REQUEST_PAYLOAD), all), v + " " + op);
        for (int i = 0; i < required.size(); i++) {
          List<Ttlv> missing = new ArrayList<>(all);
          missing.remove(i);
          ProtocolSchema.Field f = required.get(i);
          assertFalse(
              correlates(v, op, structure(REQUEST_PAYLOAD), missing),
              v + " " + op + " " + f.name());
          boolean singlePartOnly = f.requirement().startsWith("Yes for single-part");
          assertEquals(
              singlePartOnly,
              correlates(
                  v,
                  op,
                  structure(REQUEST_PAYLOAD, bytes(CORRELATION_VALUE, new byte[] {7})),
                  missing),
              v + " " + op + " " + f.name() + " in a multi-part request");
          checked++;
        }
      }
    assertTrue(checked > 350, "checked " + checked);
  }

  /** Whether a lone success for {@code op} with {@code payload} passes {@link Messages#correlate}. */
  private static boolean correlates(
      ProtocolVersion v, Operation op, Ttlv requestPayload, List<Ttlv> payload) throws IOException {
    Ttlv request =
        structure(
            REQUEST_MESSAGE,
            structure(REQUEST_HEADER, Messages.protocolVersion(v), integer(BATCH_COUNT, 1)),
            structure(BATCH_ITEM, enumeration(OPERATION, op.code()), requestPayload));
    List<Ttlv> header = new ArrayList<>();
    header.add(Messages.protocolVersion(v));
    header.add(dateTime(TIME_STAMP, Instant.EPOCH));
    if (v != ProtocolVersion.V3_0) header.add(integer(BATCH_COUNT, 1));
    Ttlv response =
        structure(
            RESPONSE_MESSAGE,
            structure(RESPONSE_HEADER, header),
            structure(
                BATCH_ITEM,
                enumeration(OPERATION, op.code()),
                enumeration(RESULT_STATUS, 0),
                structure(RESPONSE_PAYLOAD, payload)));
    try {
      Messages.correlate(request, Messages.response(response));
      return true;
    } catch (IOException e) {
      return false;
    }
  }
}
