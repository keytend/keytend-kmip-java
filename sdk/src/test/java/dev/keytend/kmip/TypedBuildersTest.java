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
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.*;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.Test;

/** API ergonomics and typed builders. */
class TypedBuildersTest {
  static Ttlv wire(ProtocolVersion version, Request request) {
    return Messages.request(version, List.of(request), RequestOptions.DEFAULT)
        .require(BATCH_ITEM)
        .require(REQUEST_PAYLOAD);
  }

  static List<String> names(Ttlv structure) {
    return structure.children().stream().map(Ttlv::tagName).toList();
  }

  static Ttlv success(Ttlv request, Ttlv... payload) {
    Ttlv item = request.require(BATCH_ITEM);
    List<Ttlv> fields = new ArrayList<>(List.of(item.require(OPERATION)));
    item.child(UNIQUE_BATCH_ITEM_ID).ifPresent(fields::add);
    fields.add(enumeration(RESULT_STATUS, 0));
    fields.add(structure(RESPONSE_PAYLOAD, payload));
    return structure(
        RESPONSE_MESSAGE,
        structure(
            RESPONSE_HEADER,
            request.require(REQUEST_HEADER).require(PROTOCOL_VERSION),
            dateTime(TIME_STAMP, Instant.ofEpochSecond(1700000000)),
            integer(BATCH_COUNT, 1)),
        structure(BATCH_ITEM, fields));
  }

  @Test
  void enumAndMaskHelpersRefuseTheWrongGroup() {
    assertThrows(
        IllegalArgumentException.class,
        () -> enumeration(PADDING_METHOD, Enums.BlockCipherMode.CBC));
    assertEquals(1, enumeration(PADDING_METHOD, 1).intValue(), "the int overload stays raw");
    assertThrows(
        IllegalArgumentException.class, () -> Attributes.mask(Enums.CryptographicAlgorithm.AES));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            Attributes.mask(
                Enums.CryptographicUsageMask.ENCRYPT, Enums.StorageStatusMask.ARCHIVAL_STORAGE));
    assertEquals(
        12,
        Attributes.mask(
            Enums.CryptographicUsageMask.ENCRYPT, Enums.CryptographicUsageMask.DECRYPT));
  }

  @Test
  void requestOptionsHaveABuilderAndValidateTimestampsEarly() {
    assertThrows(
        IllegalArgumentException.class,
        () -> RequestOptions.builder().timestamp(Instant.ofEpochSecond(1, 5)));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            new RequestOptions(
                null,
                null,
                null,
                null,
                null,
                Instant.ofEpochSecond(1, 5),
                null,
                List.of(),
                null,
                null));
    RequestOptions o =
        RequestOptions.builder()
            .maximumResponseSize(4096)
            .timestamp(Instant.ofEpochSecond(1700000000))
            .attestationCapable(true)
            .batchOrder(true)
            .correlation("c", null)
            .build();
    assertEquals(4096, o.maximumResponseSize());
    assertEquals(true, o.attestationCapable());
    assertEquals(true, o.batchOrder());
    assertEquals(o, o.toBuilder().build());
  }

  @Test
  void createSymmetricKeyNeedsAUsage() {
    assertThrows(
        IllegalArgumentException.class,
        () -> Requests.createSymmetricKey(Enums.CryptographicAlgorithm.AES, 256));
  }

  @Test
  void requestsHaveContentEquality() {
    Request a = Requests.get().uniqueIdentifier("x").batchId(new byte[] {1}).build();
    Request b = Requests.get().uniqueIdentifier("x").batchId(new byte[] {1}).build();
    assertEquals(a, b);
    assertEquals(a.hashCode(), b.hashCode());
    assertTrue(a.toString().contains("batchId=01"), a.toString());
    assertNotEquals(a, Requests.get().uniqueIdentifier("y").batchId(new byte[] {1}).build());
  }

  /** Wrap with a NIST Key Wrap KEK, no encoding (KMIP 1.1 §2.1.6, §9.1.3.2.32). */
  @Test
  void keyWrappingSpecification() {
    Ttlv spec =
        KeyWrapping.encrypt(
                "kek", CryptoParameters.builder().mode(Enums.BlockCipherMode.NISTKEY_WRAP).build())
            .noEncoding()
            .toTtlv();
    assertEquals(
        List.of("WrappingMethod", "EncryptionKeyInformation", "EncodingOption"), names(spec));
    Ttlv payload =
        wire(ProtocolVersion.V1_1, Requests.get().uniqueIdentifier("k").add(spec).build());
    assertEquals(
        Enums.BlockCipherMode.NISTKEY_WRAP.code(),
        payload
            .require(KEY_WRAPPING_SPECIFICATION)
            .require(ENCRYPTION_KEY_INFORMATION)
            .require(CRYPTOGRAPHIC_PARAMETERS)
            .require(BLOCK_CIPHER_MODE)
            .intValue());
  }

  /** 1.4 Import uses repeated Attribute fields; 2.x uses one Attributes structure. */
  @Test
  void importRestoresFromAnExportInTheRightShape() {
    Ttlv key = ManagedObjects.rawSymmetricKey(new byte[16], Enums.CryptographicAlgorithm.AES);
    Ttlv export14 =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY),
            text(UNIQUE_IDENTIFIER, "id:with:colons:é"),
            Attributes.algorithm(Enums.CryptographicAlgorithm.AES),
            Attributes.length(128),
            key);
    Ttlv import14 = wire(ProtocolVersion.V1_4, ImportRequest.restore(export14, true));
    assertTrue(import14.child(TEMPLATE_ATTRIBUTE).isEmpty());
    assertEquals(2, import14.children(ATTRIBUTE).size());
    assertEquals("id:with:colons:é", import14.require(UNIQUE_IDENTIFIER).textValue());
    Ttlv export21 =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY),
            text(UNIQUE_IDENTIFIER, "k"),
            structure(
                ATTRIBUTES,
                enumeration(CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.AES),
                integer(CRYPTOGRAPHIC_LENGTH, 128)),
            key);
    Ttlv import21 = wire(ProtocolVersion.V2_1, ImportRequest.restore(export21, false));
    assertEquals(2, import21.require(ATTRIBUTES).children().size());
    // A portable Template-Attribute is flattened for 1.4 and becomes Attributes for 2.x.
    Request portable =
        Requests.importObject()
            .uniqueIdentifier("k")
            .add(enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY))
            .template(Attributes.length(128))
            .add(key)
            .build();
    assertEquals(1, wire(ProtocolVersion.V1_4, portable).children(ATTRIBUTE).size());
    assertEquals(1, wire(ProtocolVersion.V2_1, portable).require(ATTRIBUTES).children().size());
  }

  /**
   * Import carries all of the object's attributes (KMIP 1.4 §4.41, 2.1 §6.1.25). Restoring under
   * another identifier keeps the exported Unique Identifier attribute with the new identifier, in
   * the version's own form, and gives a Short Unique Identifier the SHA-256 of the new identifier
   * (2.1 §4.56), so it stays unique while the exported object exists. Restoring under the same
   * identifier sends the export unchanged.
   */
  @Test
  void restoringUnderAnotherIdentifierRenamesTheIdentityAttributes() throws Exception {
    Ttlv key = ManagedObjects.rawSymmetricKey(new byte[16], Enums.CryptographicAlgorithm.AES);
    String fresh = "catalog-1:雪:" + "x".repeat(256);
    byte[] freshShort =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(fresh.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    byte[] oldShort = new byte[32];
    Arrays.fill(oldShort, (byte) 7);
    Ttlv export14 =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY),
            text(UNIQUE_IDENTIFIER, "old"),
            Attributes.textAttribute("Unique Identifier", "old"),
            Attributes.length(128),
            Attributes.attribute("Sensitive", bool(ATTRIBUTE_VALUE, false)),
            key);
    Ttlv renamed = wire(ProtocolVersion.V1_4, ImportRequest.restoreAs(export14, fresh, false));
    assertEquals(fresh, renamed.require(UNIQUE_IDENTIFIER).textValue());
    List<Ttlv> attributes = renamed.children(ATTRIBUTE);
    assertEquals(3, attributes.size());
    assertEquals("Unique Identifier", attributes.get(0).require(ATTRIBUTE_NAME).textValue());
    assertEquals(fresh, attributes.get(0).require(ATTRIBUTE_VALUE).textValue());
    assertEquals(export14.children(ATTRIBUTE).subList(1, 3), attributes.subList(1, 3));
    // The same identifier sends the export as it is.
    assertEquals(
        export14.children(ATTRIBUTE),
        wire(ProtocolVersion.V1_4, ImportRequest.restoreAs(export14, "old", false))
            .children(ATTRIBUTE));

    for (ProtocolVersion v : List.of(ProtocolVersion.V2_0, ProtocolVersion.V2_1)) {
      Ttlv export2 =
          structure(
              RESPONSE_PAYLOAD,
              enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY),
              text(UNIQUE_IDENTIFIER, "old"),
              structure(
                  ATTRIBUTES,
                  text(UNIQUE_IDENTIFIER, "old"),
                  bytes(SHORT_UNIQUE_IDENTIFIER, oldShort),
                  integer(CRYPTOGRAPHIC_LENGTH, 128),
                  enumeration(CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.AES)),
              key);
      Ttlv modern = wire(v, ImportRequest.restoreAs(export2, fresh, false));
      assertEquals(fresh, modern.require(UNIQUE_IDENTIFIER).textValue());
      Ttlv sent = modern.require(ATTRIBUTES);
      assertEquals(4, sent.children().size(), v + "");
      assertEquals(fresh, sent.require(UNIQUE_IDENTIFIER).textValue());
      assertArrayEquals(freshShort, sent.require(SHORT_UNIQUE_IDENTIFIER).bytesValue());
      assertEquals(128, sent.require(CRYPTOGRAPHIC_LENGTH).intValue());
      assertEquals(
          Enums.CryptographicAlgorithm.AES.code(),
          sent.require(CRYPTOGRAPHIC_ALGORITHM).intValue());
      Ttlv same = wire(v, ImportRequest.restoreAs(export2, "old", false)).require(ATTRIBUTES);
      assertArrayEquals(oldShort, same.require(SHORT_UNIQUE_IDENTIFIER).bytesValue());
      assertEquals("old", same.require(UNIQUE_IDENTIFIER).textValue());
    }
    // An export without the identity attributes gets none added.
    Ttlv bare =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY),
            text(UNIQUE_IDENTIFIER, "old"),
            structure(ATTRIBUTES, integer(CRYPTOGRAPHIC_LENGTH, 128)),
            key);
    Ttlv sent =
        wire(ProtocolVersion.V2_1, ImportRequest.restoreAs(bare, fresh, false)).require(ATTRIBUTES);
    assertEquals(List.of(integer(CRYPTOGRAPHIC_LENGTH, 128)), sent.children());
  }

  @Test
  void encryptAndDecryptAreTyped() throws Exception {
    Request encrypt =
        CryptoRequests.encrypt("k")
            .parameters(CryptoParameters.aesGcm())
            .data(new byte[] {1})
            .iv(new byte[12])
            .aad(new byte[] {2})
            .build();
    assertEquals(
        List.of(
            "UniqueIdentifier",
            "CryptographicParameters",
            "Data",
            "IVCounterNonce",
            "AuthenticatedEncryptionAdditionalData"),
        names(wire(ProtocolVersion.V1_4, encrypt)));
    assertThrows(IllegalArgumentException.class, () -> CryptoRequests.sign("k").iv(new byte[1]));
    assertThrows(
        IllegalArgumentException.class, () -> CryptoRequests.encrypt("k").tag(new byte[1]));
    try (var client =
        new KmipClient(
            req ->
                success(
                    req,
                    text(UNIQUE_IDENTIFIER, "k"),
                    bytes(DATA, new byte[] {9}),
                    bytes(IV_COUNTER_NONCE, new byte[12]),
                    bytes(AUTHENTICATED_ENCRYPTION_TAG, new byte[16])),
            ProtocolVersion.V1_4)) {
      CryptoResult r = CryptoResult.of(client.call(encrypt));
      assertArrayEquals(new byte[] {9}, r.data().orElseThrow());
      assertEquals(16, r.authenticatedEncryptionTag().orElseThrow().length);
    }
  }

  @Test
  void signAndVerifyAreTypedAndPssIsVersionAware() throws Exception {
    assertThrows(
        IllegalArgumentException.class,
        () -> CryptoRequests.sign("k").data(new byte[1]).digestedData(new byte[1]).build());
    Request pss =
        CryptoRequests.sign("k")
            .parameters(CryptoParameters.rsaPss(Enums.HashingAlgorithm.SHA_256, 32))
            .data(new byte[] {1})
            .build();
    assertThrows(IllegalArgumentException.class, () -> wire(ProtocolVersion.V1_2, pss));
    assertTrue(
        wire(ProtocolVersion.V1_4, pss)
            .require(CRYPTOGRAPHIC_PARAMETERS)
            .child(MASK_GENERATOR)
            .isPresent());
    try (var client =
        new KmipClient(
            req ->
                success(
                    req,
                    text(UNIQUE_IDENTIFIER, "k"),
                    enumeration(VALIDITY_INDICATOR, Enums.ValidityIndicator.INVALID)),
            ProtocolVersion.V1_4)) {
      CryptoResult verify =
          CryptoResult.of(
              client.call(
                  CryptoRequests.signatureVerify("k")
                      .data(new byte[] {1})
                      .signature(new byte[] {2})
                      .build()));
      assertFalse(verify.valid());
    }
  }

  @Test
  void keyPairsUseVersionedTemplates() throws Exception {
    Request ec =
        KeyPairRequest.ec(Enums.RecommendedCurve.P_256, Enums.CryptographicAlgorithm.EC)
            .privateUsage(UsageMask.of(Enums.CryptographicUsageMask.SIGN))
            .publicUsage(UsageMask.of(Enums.CryptographicUsageMask.VERIFY))
            .name("signer")
            .build();
    assertEquals(
        List.of("CommonAttributes", "PrivateKeyAttributes", "PublicKeyAttributes"),
        names(wire(ProtocolVersion.V2_1, ec)));
    assertEquals(
        List.of(
            "CommonTemplateAttribute", "PrivateKeyTemplateAttribute", "PublicKeyTemplateAttribute"),
        names(wire(ProtocolVersion.V1_4, ec)));
    var ids =
        KeyPairRequest.result(
            new Result(
                Operation.CREATE_KEY_PAIR,
                0,
                null,
                null,
                structure(
                    BATCH_ITEM,
                    enumeration(OPERATION, Operation.CREATE_KEY_PAIR),
                    enumeration(RESULT_STATUS, 0),
                    structure(
                        RESPONSE_PAYLOAD,
                        text(PRIVATE_KEY_UNIQUE_IDENTIFIER, "priv"),
                        text(PUBLIC_KEY_UNIQUE_IDENTIFIER, "pub")))));
    assertEquals(new KeyPairRequest.Ids("priv", "pub"), ids);
  }

  @Test
  void locatePagesThroughEveryMatch() throws Exception {
    LocateRequest query = LocateRequest.builder().name("orders").state(Enums.State.ACTIVE).build();
    Ttlv page = wire(ProtocolVersion.V1_4, query.page(10, 5));
    assertEquals(5, page.require(MAXIMUM_ITEMS).intValue());
    assertEquals(10, page.require(OFFSET_ITEMS).intValue());
    assertThrows(
        IllegalArgumentException.class, () -> wire(ProtocolVersion.V1_2, query.page(10, 5)));
    assertEquals(
        2, wire(ProtocolVersion.V2_1, query.toRequest()).require(ATTRIBUTES).children().size());
    List<String> all = new ArrayList<>();
    for (int i = 0; i < 7; i++) all.add("k" + i);
    UnaryOperator<Ttlv> server =
        req -> {
          Ttlv p = req.require(BATCH_ITEM).require(REQUEST_PAYLOAD);
          int offset = p.child(OFFSET_ITEMS).map(Ttlv::intValue).orElse(0);
          int max = p.require(MAXIMUM_ITEMS).intValue();
          return success(
              req,
              all.subList(Math.min(offset, all.size()), Math.min(offset + max, all.size())).stream()
                  .map(id -> text(UNIQUE_IDENTIFIER, id))
                  .toArray(Ttlv[]::new));
        };
    try (var client = new KmipClient(server::apply, ProtocolVersion.V1_4)) {
      assertEquals(all, client.locateAll(query, 3));
    }
  }

  /** A Locate server over {@code all} with its own page cap, offset and Located Items habits. */
  private static KmipClient locateServer(
      List<String> all,
      int cap,
      boolean honorsOffset,
      Integer locatedItems,
      List<Integer> offsets) {
    return new KmipClient(
        req -> {
          Ttlv p = req.require(BATCH_ITEM).require(REQUEST_PAYLOAD);
          int offset = honorsOffset ? p.child(OFFSET_ITEMS).map(Ttlv::intValue).orElse(0) : 0;
          offsets.add(p.child(OFFSET_ITEMS).map(Ttlv::intValue).orElse(0));
          int max = Math.min(cap, p.require(MAXIMUM_ITEMS).intValue());
          List<Ttlv> fields = new ArrayList<>();
          if (locatedItems != null) fields.add(integer(LOCATED_ITEMS, locatedItems));
          for (String id :
              all.subList(Math.min(offset, all.size()), Math.min(offset + max, all.size())))
            fields.add(text(UNIQUE_IDENTIFIER, id));
          return success(req, fields.toArray(Ttlv[]::new));
        },
        ProtocolVersion.V1_4);
  }

  /** Maximum Items is an upper bound; Located Items, when sent, says when to stop. */
  @Test
  void locateAllKeepsPagingPastShortPagesAndUsesLocatedItems() throws Exception {
    LocateRequest query = LocateRequest.builder().name("orders").build();
    List<String> all = List.of("k0", "k1", "k2", "k3", "k4");
    List<Integer> offsets = new ArrayList<>();
    // The server caps pages at 2 although 3 were asked for: the first short page is not the end.
    try (var client = locateServer(all, 2, true, null, offsets)) {
      assertEquals(all, client.locateAll(query, 3));
    }
    assertEquals(List.of(0, 2, 4, 5), offsets, "offsets follow what was received");
    // With Located Items the final empty request is not needed.
    offsets.clear();
    try (var client = locateServer(all, 2, true, 5, offsets)) {
      assertEquals(all, client.locateAll(query, 3));
    }
    assertEquals(List.of(0, 2, 4), offsets);
    // A page larger than requested means the server ignored Maximum Items: it is complete.
    offsets.clear();
    try (var client =
        new KmipClient(
            req -> {
              offsets.add(0);
              return success(
                  req, all.stream().map(id -> text(UNIQUE_IDENTIFIER, id)).toArray(Ttlv[]::new));
            },
            ProtocolVersion.V1_4)) {
      assertEquals(all, client.locateAll(query, 2));
    }
    assertEquals(1, offsets.size());
  }

  /** The no-progress guard, and when Located Items shows nothing is missing. */
  @Test
  void locateAllNoProgressGuard() throws Exception {
    LocateRequest query = LocateRequest.builder().name("orders").build();
    List<String> four = List.of("k0", "k1", "k2", "k3");
    List<Integer> offsets = new ArrayList<>();
    // Offset ignored, full pages, more matches than one page: paging cannot reach them.
    try (var client = locateServer(four, 10, false, 4, offsets)) {
      assertThrows(ProtocolException.class, () -> client.locateAll(query, 2));
    }
    try (var client = locateServer(four, 10, false, null, offsets)) {
      assertThrows(ProtocolException.class, () -> client.locateAll(query, 2));
    }
    // Offset ignored, but Located Items shows the first page already held everything.
    try (var client = locateServer(four.subList(0, 2), 10, false, 2, offsets)) {
      assertEquals(four.subList(0, 2), client.locateAll(query, 2));
    }
    // Offset ignored and the page is short: without Located Items the repeat proves nothing is
    // missing.
    try (var client = locateServer(four.subList(0, 3), 10, false, null, offsets)) {
      assertEquals(four.subList(0, 3), client.locateAll(query, 5));
    }
    // A repeated short page while Located Items counts more is not the end. The server
    // caps pages at 2 and ignores Offset Items, so k2 and k3 cannot be reached.
    offsets.clear();
    try (var client = locateServer(four, 2, false, 4, offsets)) {
      var e = assertThrows(ProtocolException.class, () -> client.locateAll(query, 3));
      assertTrue(e.getMessage().contains("no progress"), e.getMessage());
    }
    assertEquals(List.of(0, 2), offsets);
    // An empty page while Located Items says more exist is truncation (before: [k0, k1]).
    try (var client =
        new KmipClient(
            req -> {
              int offset =
                  req.require(BATCH_ITEM)
                      .require(REQUEST_PAYLOAD)
                      .child(OFFSET_ITEMS)
                      .map(Ttlv::intValue)
                      .orElse(0);
              List<Ttlv> fields = new ArrayList<>(List.of(integer(LOCATED_ITEMS, 4)));
              if (offset == 0)
                for (String id : four.subList(0, 2)) fields.add(text(UNIQUE_IDENTIFIER, id));
              return success(req, fields.toArray(Ttlv[]::new));
            },
            ProtocolVersion.V1_4)) {
      assertThrows(ProtocolException.class, () -> client.locateAll(query, 2));
    }
    // An oversized page (Maximum Items ignored) is everything only when Located Items agrees.
    for (Integer located : new Integer[] {null, 3, 5}) {
      try (var client =
          new KmipClient(
              req -> {
                List<Ttlv> fields = new ArrayList<>();
                if (located != null) fields.add(integer(LOCATED_ITEMS, located));
                for (String id : four.subList(0, 3)) fields.add(text(UNIQUE_IDENTIFIER, id));
                return success(req, fields.toArray(Ttlv[]::new));
              },
              ProtocolVersion.V1_4)) {
        if (located != null && located == 5)
          // Before the fix: [k0, k1, k2], silently.
          assertThrows(ProtocolException.class, () -> client.locateAll(query, 2));
        else assertEquals(four.subList(0, 3), client.locateAll(query, 2));
      }
    }
  }

  @Test
  void multipartMacStreamsWithCorrelation() throws Exception {
    List<Ttlv> sent = new ArrayList<>();
    try (var client =
        new KmipClient(
            req -> {
              Ttlv p = req.require(BATCH_ITEM).require(REQUEST_PAYLOAD);
              sent.add(p);
              boolean last = p.child(FINAL_INDICATOR).isPresent();
              return last
                  ? success(req, text(UNIQUE_IDENTIFIER, "k"), bytes(MAC_DATA, new byte[] {7}))
                  : success(
                      req, text(UNIQUE_IDENTIFIER, "k"), bytes(CORRELATION_VALUE, new byte[] {5}));
            },
            ProtocolVersion.V1_4)) {
      var stream = new MultipartOperation(client, () -> CryptoRequests.mac("k"));
      stream.update(new byte[] {1});
      stream.update(new byte[] {2});
      CryptoResult mac = stream.finish(new byte[] {3});
      assertArrayEquals(new byte[] {7}, mac.macData().orElseThrow());
    }
    assertTrue(sent.get(0).require(INIT_INDICATOR).booleanValue());
    assertArrayEquals(new byte[] {5}, sent.get(1).require(CORRELATION_VALUE).bytesValue());
    assertTrue(sent.get(2).require(FINAL_INDICATOR).booleanValue());
  }

  @Test
  void splitKeysValidateCountsAndRepeatIdentifiers() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SplitKeyRequests.create(
                Enums.ObjectType.SYMMETRIC_KEY, null, 3, 4, Enums.SplitKeyMethod.XOR, null));
    Ttlv join =
        wire(
            ProtocolVersion.V1_4,
            SplitKeyRequests.join(Enums.ObjectType.SYMMETRIC_KEY, List.of("a", "b", "c"), null));
    assertEquals(3, join.children(UNIQUE_IDENTIFIER).size());
    Ttlv create =
        wire(
            ProtocolVersion.V1_4,
            SplitKeyRequests.create(
                Enums.ObjectType.SYMMETRIC_KEY,
                "k",
                3,
                2,
                Enums.SplitKeyMethod.POLYNOMIAL_SHARING_PRIME_FIELD,
                BigInteger.valueOf(65521)));
    assertEquals(2, create.require(SPLIT_KEY_THRESHOLD).intValue());
  }

  @Test
  void protectionStorageAlternativesStaySeparate() {
    Ttlv masks =
        ModernAttributes.protectionStorageMasks(
            EnumSet.of(Enums.ProtectionStorageMask.SOFTWARE),
            EnumSet.of(
                Enums.ProtectionStorageMask.HARDWARE, Enums.ProtectionStorageMask.ON_PREMISES));
    assertEquals(2, masks.children(PROTECTION_STORAGE_MASK).size());
    assertEquals(
        Enums.ProtectionStorageMask.SOFTWARE.code(),
        masks.children(PROTECTION_STORAGE_MASK).get(0).intValue());
  }

  /** Certificate Register requires algorithm, length, certificate length and usage. */
  @Test
  void certificatesRegisterWithDerivedAttributes() throws Exception {
    X509Certificate rsa =
        (X509Certificate) TestTls.identity("rsa-cert", "RSA").getCertificate("rsa-cert");
    Ttlv template =
        wire(
                ProtocolVersion.V1_4,
                CertificateRegistration.of(rsa, UsageMask.of(Enums.CryptographicUsageMask.VERIFY))
                    .build())
            .require(TEMPLATE_ATTRIBUTE);
    Map<String, Ttlv> attrs = new HashMap<>();
    for (Ttlv a : template.children(ATTRIBUTE))
      attrs.put(a.require(ATTRIBUTE_NAME).textValue(), a.require(ATTRIBUTE_VALUE));
    assertEquals(
        Enums.CryptographicAlgorithm.RSA.code(), attrs.get("Cryptographic Algorithm").intValue());
    assertEquals(2048, attrs.get("Cryptographic Length").intValue());
    assertEquals(rsa.getEncoded().length, attrs.get("Certificate Length").intValue());
    assertEquals(
        Enums.CryptographicUsageMask.VERIFY.code(),
        attrs.get("Cryptographic Usage Mask").intValue());
    X509Certificate ec = TestTls.certificate("ec-cert");
    assertThrows(
        IllegalStateException.class,
        () ->
            CertificateRegistration.of(ec, UsageMask.of(Enums.CryptographicUsageMask.VERIFY))
                .build());
    assertThrows(
        IllegalArgumentException.class, () -> CertificateRegistration.of(ec, UsageMask.of()));
    Ttlv modern =
        wire(
                ProtocolVersion.V2_1,
                CertificateRegistration.of(ec, UsageMask.of(Enums.CryptographicUsageMask.VERIFY))
                    .ecAlgorithm(Enums.CryptographicAlgorithm.ECDSA)
                    .build())
            .require(ATTRIBUTES);
    assertEquals(256, modern.require(CRYPTOGRAPHIC_LENGTH).intValue());
    assertEquals(
        Enums.CryptographicAlgorithm.ECDSA.code(),
        modern.require(CRYPTOGRAPHIC_ALGORITHM).intValue());
  }

  @Test
  void objectViewsCheckIdentityAndKeepEmptyValuesDistinct() throws Exception {
    X509Certificate cert = TestTls.certificate("view-cert");
    Ttlv payload =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, Enums.ObjectType.CERTIFICATE),
            text(UNIQUE_IDENTIFIER, "c"),
            ManagedObjects.certificate(Enums.CertificateType.X_509, cert.getEncoded()));
    assertEquals(cert, ObjectViews.certificate(payload, "c"));
    assertThrows(
        java.security.cert.CertificateException.class, () -> ObjectViews.certificate(payload, "d"));
    Ttlv empty =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, Enums.ObjectType.OPAQUE_OBJECT),
            text(UNIQUE_IDENTIFIER, "o"),
            ManagedObjects.opaque(0x80000001, new byte[0]));
    assertEquals(0, ObjectViews.opaque(empty, "o").value().orElseThrow().length);
    Ttlv absent =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, Enums.ObjectType.OPAQUE_OBJECT),
            text(UNIQUE_IDENTIFIER, "o"),
            structure(OPAQUE_OBJECT, enumeration(OPAQUE_DATA_TYPE, 0x80000001)));
    assertTrue(ObjectViews.opaque(absent, "o").value().isEmpty());
    Ttlv pgp =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, Enums.ObjectType.PGP_KEY),
            text(UNIQUE_IDENTIFIER, "p"),
            ManagedObjects.pgpKey(
                4,
                ManagedObjects.keyBlock(
                    Enums.KeyFormatType.RAW, bytes(KEY_MATERIAL, new byte[] {1, 2}), null, null)));
    assertEquals(4, ObjectViews.pgpKey(pgp, "p").version());
    assertArrayEquals(new byte[] {1, 2}, ObjectViews.pgpKey(pgp, "p").material().orElseThrow());
  }

  @Test
  void usageMasksAreCheckedPerFlagBeforeBecomingAnInteger() {
    UsageMask modern =
        UsageMask.of(
            Enums.CryptographicUsageMask.ENCRYPT, Enums.CryptographicUsageMask.FPE_ENCRYPT);
    assertThrows(
        IllegalArgumentException.class, () -> modern.requireDefinedIn(ProtocolVersion.V1_4));
    modern.requireDefinedIn(ProtocolVersion.V2_0);
    assertEquals(modern, UsageMask.fromInt(modern.toInt()));
    assertEquals(0x40000000, UsageMask.unknownBits(0x40000000 | 4));
    assertEquals(
        Ttlv.Type.INTEGER, modern.toTtlv().type(), "a mask is an Integer, not an Enumeration");
  }

  /** KMIP 3.0 selects wrapped attributes by Attribute Reference, earlier by name. */
  @Test
  void wrappedAttributeSelectorsFollowTheVersion() {
    Ttlv spec =
        KeyWrapping.encrypt("kek", null)
            .wrapAttribute("Cryptographic Usage Mask")
            .wrapAttribute("x-Owner")
            .toTtlv();
    for (Request request :
        List.of(
            Requests.get().uniqueIdentifier("k").add(spec).build(),
            Requests.export().uniqueIdentifier("k").add(spec).build())) {
      Ttlv modern = wire(ProtocolVersion.V3_0, request).require(KEY_WRAPPING_SPECIFICATION);
      assertTrue(modern.children(ATTRIBUTE_NAME).isEmpty(), modern.toString());
      List<Ttlv> references = modern.children(ATTRIBUTE_REFERENCE);
      assertEquals(2, references.size());
      assertEquals(Tag.CRYPTOGRAPHIC_USAGE_MASK.code(), references.get(0).intValue());
      assertEquals("x", references.get(1).require(VENDOR_IDENTIFICATION).textValue());
      assertEquals("Owner", references.get(1).require(ATTRIBUTE_NAME).textValue());
      Ttlv legacy = wire(ProtocolVersion.V2_1, request).require(KEY_WRAPPING_SPECIFICATION);
      assertEquals(
          List.of("Cryptographic Usage Mask", "x-Owner"),
          legacy.children(ATTRIBUTE_NAME).stream().map(Ttlv::textValue).toList());
    }
  }

  /** MAC/sign-only wrapping has its own Wrapping Method and no encryption key. */
  @Test
  void keyWrappingCanBeMacOrSignOnly() {
    Ttlv macOnly = KeyWrapping.macSign("mac-key", null).toTtlv();
    assertEquals(Enums.WrappingMethod.MAC_SIGN.code(), macOnly.require(WRAPPING_METHOD).intValue());
    assertTrue(macOnly.child(ENCRYPTION_KEY_INFORMATION).isEmpty());
    assertEquals(
        "mac-key",
        macOnly.require(MAC_SIGNATURE_KEY_INFORMATION).require(UNIQUE_IDENTIFIER).textValue());
    Ttlv both = KeyWrapping.encrypt("kek", null).macOrSign("mac-key", null).toTtlv();
    assertEquals(
        Enums.WrappingMethod.ENCRYPT_THEN_MAC_SIGN.code(),
        both.require(WRAPPING_METHOD).intValue());
    assertEquals(
        Enums.WrappingMethod.ENCRYPT.code(),
        KeyWrapping.encrypt("kek", null).toTtlv().require(WRAPPING_METHOD).intValue());
    wire(ProtocolVersion.V1_1, Requests.get().uniqueIdentifier("k").add(macOnly).build());
  }

  /** Import can say whether a wrapped object is unwrapped or stored as provided. */
  @Test
  void importCanRequestAKeyWrapType() {
    Ttlv export =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY),
            text(UNIQUE_IDENTIFIER, "k"),
            ManagedObjects.symmetricKey(
                ManagedObjects.keyBlock(
                    Enums.KeyFormatType.RAW,
                    structure(KEY_VALUE, bytes(KEY_MATERIAL, new byte[24])).retag(KEY_VALUE),
                    Enums.CryptographicAlgorithm.AES,
                    128,
                    structure(KEY_WRAPPING_DATA, enumeration(WRAPPING_METHOD, 1)))));
    for (ProtocolVersion v : List.of(ProtocolVersion.V1_4, ProtocolVersion.V2_1)) {
      Ttlv sent =
          wire(v, ImportRequest.restoreAs(export, null, false, Enums.KeyWrapType.AS_REGISTERED));
      assertEquals(Enums.KeyWrapType.AS_REGISTERED.code(), sent.require(KEY_WRAP_TYPE).intValue());
      assertTrue(wire(v, ImportRequest.restore(export, false)).child(KEY_WRAP_TYPE).isEmpty());
    }
  }

  /** XOR splitting needs every part (KMIP 1.4 §2.2.5: parts identical to threshold). */
  @Test
  void xorSplittingNeedsAThresholdEqualToTheParts() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            SplitKeyRequests.create(
                Enums.ObjectType.SYMMETRIC_KEY, null, 3, 2, Enums.SplitKeyMethod.XOR, null));
    assertEquals(
        3,
        wire(
                ProtocolVersion.V1_4,
                SplitKeyRequests.create(
                    Enums.ObjectType.SYMMETRIC_KEY, null, 3, 3, Enums.SplitKeyMethod.XOR, null))
            .require(SPLIT_KEY_THRESHOLD)
            .intValue());
  }

  /** views never expose wrapped bytes as key material and fail with checked types. */
  @Test
  void objectViewsRefuseWrappedMaterialAndFailConsistently() throws Exception {
    Ttlv wrappedPgp =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, Enums.ObjectType.PGP_KEY),
            text(UNIQUE_IDENTIFIER, "p"),
            ManagedObjects.pgpKey(
                4,
                ManagedObjects.keyBlock(
                    Enums.KeyFormatType.RAW,
                    bytes(KEY_VALUE, new byte[] {9, 9, 9}),
                    null,
                    null,
                    structure(KEY_WRAPPING_DATA, enumeration(WRAPPING_METHOD, 1)))));
    ObjectViews.PgpKey view = ObjectViews.pgpKey(wrappedPgp, "p");
    assertTrue(view.wrapped());
    assertTrue(view.material().isEmpty(), "wrapped bytes are not key material");
    // MAC/sign-only wrapping keeps a structured Key Value, which is still not handed out.
    Ttlv macSigned =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, Enums.ObjectType.PGP_KEY),
            text(UNIQUE_IDENTIFIER, "p"),
            ManagedObjects.pgpKey(
                4,
                ManagedObjects.keyBlock(
                    Enums.KeyFormatType.RAW,
                    bytes(KEY_MATERIAL, new byte[] {1, 2}),
                    null,
                    null,
                    structure(KEY_WRAPPING_DATA, enumeration(WRAPPING_METHOD, 2)))));
    assertTrue(ObjectViews.pgpKey(macSigned, "p").material().isEmpty());
    // Another identifier or object type, and a missing field, are checked exceptions everywhere.
    assertThrows(
        java.security.InvalidKeyException.class, () -> ObjectViews.pgpKey(wrappedPgp, "q"));
    assertThrows(
        java.security.GeneralSecurityException.class, () -> ObjectViews.opaque(wrappedPgp, "p"));
    assertThrows(
        java.security.cert.CertificateException.class,
        () -> ObjectViews.certificate(wrappedPgp, "p"));
    Ttlv noBlock =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, Enums.ObjectType.PGP_KEY),
            text(UNIQUE_IDENTIFIER, "p"),
            structure(PGP_KEY, integer(PGP_KEY_VERSION, 4)));
    assertThrows(java.security.InvalidKeyException.class, () -> ObjectViews.pgpKey(noBlock, "p"));
    Ttlv noType =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, Enums.ObjectType.OPAQUE_OBJECT),
            text(UNIQUE_IDENTIFIER, "o"),
            structure(OPAQUE_OBJECT));
    assertThrows(
        java.security.GeneralSecurityException.class, () -> ObjectViews.opaque(noType, "o"));
  }

  /** A failed Init is sent again as an Init, never followed by single-shot parts. */
  @Test
  void multipartStateAdvancesOnlyAfterTheServerAcceptsAPart() throws Exception {
    List<Ttlv> sent = new ArrayList<>();
    boolean[] failNext = {true};
    try (var client =
        new KmipClient(
            req -> {
              Ttlv p = req.require(BATCH_ITEM).require(REQUEST_PAYLOAD);
              sent.add(p);
              if (failNext[0]) {
                failNext[0] = false;
                throw new java.io.IOException("connection lost");
              }
              return p.child(FINAL_INDICATOR).isPresent()
                  ? success(req, text(UNIQUE_IDENTIFIER, "k"), bytes(MAC_DATA, new byte[] {7}))
                  : success(
                      req, text(UNIQUE_IDENTIFIER, "k"), bytes(CORRELATION_VALUE, new byte[] {5}));
            },
            ProtocolVersion.V1_4)) {
      var stream = new MultipartOperation(client, () -> CryptoRequests.mac("k"));
      assertThrows(java.io.IOException.class, () -> stream.update(new byte[] {1}));
      stream.update(new byte[] {1});
      stream.finish(new byte[] {2});
    }
    assertTrue(sent.get(0).require(INIT_INDICATOR).booleanValue());
    assertTrue(sent.get(1).require(INIT_INDICATOR).booleanValue(), "the Init is repeated");
    assertArrayEquals(new byte[] {5}, sent.get(2).require(CORRELATION_VALUE).bytesValue());
    // An Init answered without a Correlation Value cannot be continued.
    try (var client =
        new KmipClient(req -> success(req, text(UNIQUE_IDENTIFIER, "k")), ProtocolVersion.V1_4)) {
      var stream = new MultipartOperation(client, () -> CryptoRequests.mac("k"));
      assertThrows(ProtocolException.class, () -> stream.update(new byte[] {1}));
    }
  }

  /**
   * docs/protocol-layer.md recipe: before 1.4, RSA-PSS is Padding Method PSS without the 1.4
   * details.
   */
  @Test
  void pssBeforeKmip14UsesPaddingAndHashingOnly() {
    CryptoParameters pss =
        CryptoParameters.builder()
            .algorithm(Enums.CryptographicAlgorithm.RSA)
            .padding(Enums.PaddingMethod.PSS)
            .hashing(Enums.HashingAlgorithm.SHA_256)
            .build();
    for (ProtocolVersion v : List.of(ProtocolVersion.V1_2, ProtocolVersion.V1_3)) {
      Ttlv sent =
          wire(v, CryptoRequests.sign("k").parameters(pss).data(new byte[] {1}).build())
              .require(CRYPTOGRAPHIC_PARAMETERS);
      assertEquals(Enums.PaddingMethod.PSS.code(), sent.require(PADDING_METHOD).intValue());
      assertTrue(sent.child(MASK_GENERATOR).isEmpty() && sent.child(SALT_LENGTH).isEmpty());
    }
  }
}
