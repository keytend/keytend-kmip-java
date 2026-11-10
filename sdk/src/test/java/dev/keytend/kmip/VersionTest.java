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
import dev.keytend.kmip.codec.XmlCodec;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.EOFException;
import java.io.IOException;
import java.net.SocketException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

/** Version handling and attribute conversion. */
class VersionTest {
  private static Ttlv payload(ProtocolVersion version, Request request) {
    return Messages.request(version, List.of(request), RequestOptions.DEFAULT)
        .require(BATCH_ITEM)
        .require(REQUEST_PAYLOAD);
  }

  /** OASIS AX-M-1-20 converts 1.4's x-ID to Vendor Identification "x", Attribute Name "ID". */
  @Test
  void customAttributesBecomeXAndYVendorAttributes_kmip21Section4_60() {
    Ttlv attrs =
        payload(
                ProtocolVersion.V2_0,
                Requests.create()
                    .add(enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY))
                    .template(
                        Attributes.textAttribute("x-ID", "a"), Attributes.textAttribute("y-Z", "b"))
                    .build())
            .require(ATTRIBUTES);
    List<Ttlv> vendor = attrs.children(ATTRIBUTE);
    assertEquals("x", vendor.get(0).require(VENDOR_IDENTIFICATION).textValue());
    assertEquals("ID", vendor.get(0).require(ATTRIBUTE_NAME).textValue());
    assertEquals("y", vendor.get(1).require(VENDOR_IDENTIFICATION).textValue());
    assertEquals("Z", vendor.get(1).require(ATTRIBUTE_NAME).textValue());
    assertThrows(
        IllegalArgumentException.class,
        () ->
            ModernAttributes.fromLegacy(
                Attributes.textAttribute("Not An Attribute", "v"), ProtocolVersion.V2_1));
  }

  @Test
  void customAttributeNamesBecomeVendorReferences() {
    Ttlv reference =
        payload(
                ProtocolVersion.V2_1,
                Requests.getAttributes()
                    .uniqueIdentifier("u")
                    .add(text(ATTRIBUTE_NAME, "x-custom"))
                    .build())
            .require(ATTRIBUTE_REFERENCE);
    assertEquals("x", reference.require(VENDOR_IDENTIFICATION).textValue());
    assertEquals("custom", reference.require(ATTRIBUTE_NAME).textValue());
    assertEquals(
        STATE.code(),
        payload(
                ProtocolVersion.V2_1,
                Requests.getAttributes()
                    .uniqueIdentifier("u")
                    .add(text(ATTRIBUTE_NAME, "State"))
                    .build())
            .require(ATTRIBUTE_REFERENCE)
            .intValue());
  }

  @Test
  void legacyAttributeIndexIsNotSilentlyDropped() {
    Ttlv second =
        Attributes.attribute("Name", 1, Attributes.name("second").require(ATTRIBUTE_VALUE));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            payload(
                ProtocolVersion.V2_1,
                Requests.modifyAttribute().uniqueIdentifier("u").attribute(second).build()));
    Ttlv first = Attributes.attribute("Name", 0, Attributes.name("first").require(ATTRIBUTE_VALUE));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            payload(
                ProtocolVersion.V2_1,
                Requests.deleteAttribute().uniqueIdentifier("u").attribute(first).build()),
        "without an index, 2.x Delete Attribute would remove every instance");
    Ttlv modified =
        payload(
            ProtocolVersion.V2_1,
            Requests.modifyAttribute().uniqueIdentifier("u").attribute(first).build());
    assertTrue(modified.require(NEW_ATTRIBUTE).child(NAME).isPresent());
    // 1.x keeps the index.
    assertEquals(
        1,
        payload(
                ProtocolVersion.V1_4,
                Requests.modifyAttribute().uniqueIdentifier("u").attribute(second).build())
            .require(ATTRIBUTE)
            .require(ATTRIBUTE_INDEX)
            .intValue());
  }

  @Test
  void enumerationAndMaskValuesAreCheckedAgainstTheVersion() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            VersionValidator.validate(
                ProtocolVersion.V1_2,
                enumeration(CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.ML_KEM_512)));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            VersionValidator.validate(
                ProtocolVersion.V1_2, enumeration(KEY_FORMAT_TYPE, Enums.KeyFormatType.PKCS_12)));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            VersionValidator.validate(
                ProtocolVersion.V1_4,
                integer(
                    CRYPTOGRAPHIC_USAGE_MASK,
                    Attributes.mask(
                        Enums.CryptographicUsageMask.ENCRYPT,
                        Enums.CryptographicUsageMask.FPE_ENCRYPT))));
    // The same mask inside a 1.x Attribute is found through its Attribute Name.
    assertThrows(
        IllegalArgumentException.class,
        () ->
            VersionValidator.validate(
                ProtocolVersion.V1_4, Attributes.usage(Enums.CryptographicUsageMask.FPE_ENCRYPT)));
    // Vendor values pass.
    VersionValidator.validate(
        ProtocolVersion.V1_2, enumeration(CRYPTOGRAPHIC_ALGORITHM, 0x80000001));
    VersionValidator.validate(
        ProtocolVersion.V3_0,
        enumeration(CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.ML_KEM_512));
  }

  @Test
  void tagsRemovedInLaterVersionsAreRejected() {
    Ttlv template = structure(TEMPLATE_ATTRIBUTE, Attributes.length(128));
    VersionValidator.validate(ProtocolVersion.V1_4, template);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            VersionValidator.validate(ProtocolVersion.V2_1, structure(VENDOR_EXTENSION, template)));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            VersionValidator.validate(
                ProtocolVersion.V3_0, bytes(UNIQUE_BATCH_ITEM_ID, new byte[] {1})));
  }

  /** The stricter validator still accepts every OASIS request vector at its own version. */
  @Test
  void everyOasisRequestVectorValidates() throws Exception {
    int requests = 0;
    List<String> rejected = new ArrayList<>();
    try (var walk = Files.walk(Path.of("src/test/resources/oasis"))) {
      for (Path path : walk.filter(p -> p.toString().endsWith(".xml")).sorted().toList())
        for (Ttlv node :
            new XmlCodec()
                .decodeAll(
                    OasisVectorsTest.resolve(Files.readString(path))
                        .getBytes(StandardCharsets.UTF_8))) {
          if (node.tag() != REQUEST_MESSAGE.code()) continue;
          ProtocolVersion version;
          try {
            version = Messages.version(node.require(REQUEST_HEADER));
          } catch (IllegalArgumentException outOfScope) {
            continue;
          }
          requests++;
          try {
            VersionValidator.validate(version, node);
          } catch (IllegalArgumentException e) {
            rejected.add(path + ": " + e.getMessage());
          }
        }
    }
    assertTrue(requests > 3000);
    assertEquals(List.of(), rejected);
  }

  private static Ttlv discoverReply(
      Ttlv request, ProtocolVersion header, ProtocolVersion... offered) {
    List<Ttlv> versions = new ArrayList<>();
    for (ProtocolVersion v : offered) versions.add(Messages.protocolVersion(v));
    return structure(
        RESPONSE_MESSAGE,
        structure(
            RESPONSE_HEADER,
            Messages.protocolVersion(header),
            dateTime(TIME_STAMP, Instant.ofEpochSecond(1700000000)),
            integer(BATCH_COUNT, 1)),
        structure(
            BATCH_ITEM,
            enumeration(OPERATION, Operation.DISCOVER_VERSIONS),
            enumeration(RESULT_STATUS, 0),
            structure(RESPONSE_PAYLOAD, versions)));
  }

  /** A 1.x-only server answers a 2.x header with an error stamped 1.0 (as PyKMIP does). */
  private static Ttlv onePointFourOnly(Ttlv request) {
    ProtocolVersion header = Messages.version(request.require(REQUEST_HEADER));
    if (!header.legacyAttributes())
      return structure(
          RESPONSE_MESSAGE,
          structure(
              RESPONSE_HEADER,
              structure(
                  PROTOCOL_VERSION,
                  integer(PROTOCOL_VERSION_MAJOR, 1),
                  integer(PROTOCOL_VERSION_MINOR, 0)),
              dateTime(TIME_STAMP, Instant.ofEpochSecond(1700000000)),
              integer(BATCH_COUNT, 1)),
          structure(
              BATCH_ITEM,
              enumeration(RESULT_STATUS, 1),
              enumeration(RESULT_REASON, Enums.ResultReason.INVALID_MESSAGE)));
    return discoverReply(request, header, ProtocolVersion.V1_4, ProtocolVersion.V1_3);
  }

  @Test
  void negotiationStepsDownAcrossMajorVersions_kmip21Section9_16() throws Exception {
    try (KmipClient client =
        KmipClient.negotiated(
            VersionTest::onePointFourOnly, VersionPolicy.atLeast(ProtocolVersion.V1_2))) {
      assertEquals(ProtocolVersion.V1_4, client.version());
      assertTrue(client.ownsTransport());
    }
  }

  /** A server that closes the connection on the 3.0 header gets a lower one. */
  @Test
  void negotiationStepsDownOnceWhenTheServerDropsTheConnection() throws Exception {
    for (IOException drop :
        List.of(
            new EOFException("Truncated TTLV header"), new SocketException("Connection reset"))) {
      List<ProtocolVersion> headers = new ArrayList<>();
      KmipTransport dropsModernHeaders =
          request -> {
            ProtocolVersion header = Messages.version(request.require(REQUEST_HEADER));
            headers.add(header);
            if (header == ProtocolVersion.V3_0) throw drop;
            return discoverReply(request, header, ProtocolVersion.V2_1, ProtocolVersion.V1_4);
          };
      try (KmipClient client = KmipClient.negotiated(dropsModernHeaders, VersionPolicy.ANY)) {
        assertEquals(ProtocolVersion.V2_1, client.version());
      }
      assertEquals(List.of(ProtocolVersion.V3_0, ProtocolVersion.V2_1), headers);
    }
    // A connection that keeps dropping is a transport failure: one step down, then the error.
    List<ProtocolVersion> headers = new ArrayList<>();
    KmipTransport alwaysDrops =
        request -> {
          headers.add(Messages.version(request.require(REQUEST_HEADER)));
          throw new EOFException("Truncated TTLV header");
        };
    assertThrows(EOFException.class, () -> KmipClient.negotiated(alwaysDrops, VersionPolicy.ANY));
    assertEquals(List.of(ProtocolVersion.V3_0, ProtocolVersion.V2_1), headers);
  }

  /** 2.x Delete Attribute selects by Current Attribute (KMIP 2.1 Table 196). */
  @Test
  void deleteAttributeWithAValueSendsItAsTheCurrentAttribute() {
    Ttlv contact = Attributes.textAttribute("Contact Information", "ops");
    Ttlv deleted =
        payload(
            ProtocolVersion.V2_1,
            Requests.deleteAttribute().uniqueIdentifier("u").attribute(contact).build());
    assertEquals(
        List.of("UniqueIdentifier", "CurrentAttribute"),
        deleted.children().stream().map(Ttlv::tagName).toList());
    assertEquals(
        "ops", deleted.require(CURRENT_ATTRIBUTE).require(CONTACT_INFORMATION).textValue());
    // 1.x keeps the Attribute Name form; 2.x Attribute Reference still deletes every instance.
    assertTrue(
        payload(
                ProtocolVersion.V1_4,
                Requests.deleteAttribute().uniqueIdentifier("u").attribute(contact).build())
            .child(ATTRIBUTE)
            .isPresent());
  }

  /** Values a later version lists as Reserved, and masks sent as Enumerations. */
  @Test
  void valuesReservedInLaterVersionsAndEnumerationTypedMasksAreRejected() {
    for (Enums.CryptographicUsageMask flag :
        List.of(
            Enums.CryptographicUsageMask.EXPORT,
            Enums.CryptographicUsageMask.CONTENT_COMMITMENT_NON_REPUDIATION,
            Enums.CryptographicUsageMask.TRANSLATE_ENCRYPT)) {
      UsageMask mask = UsageMask.of(Enums.CryptographicUsageMask.ENCRYPT, flag);
      mask.requireDefinedIn(ProtocolVersion.V1_4);
      for (ProtocolVersion v :
          List.of(ProtocolVersion.V2_0, ProtocolVersion.V2_1, ProtocolVersion.V3_0)) {
        var e = assertThrows(IllegalArgumentException.class, () -> mask.requireDefinedIn(v));
        assertTrue(e.getMessage().contains("Reserved in KMIP " + v), e.getMessage());
        assertThrows(
            IllegalArgumentException.class, () -> VersionValidator.validate(v, mask.toTtlv()));
      }
      VersionValidator.validate(ProtocolVersion.V1_4, Attributes.usage(flag));
      assertFalse(flag.definedIn(ProtocolVersion.V2_0));
      assertTrue(flag.definedIn(ProtocolVersion.V1_1));
    }
    assertThrows(
        IllegalArgumentException.class,
        () ->
            payload(
                ProtocolVersion.V2_1,
                Requests.createSymmetricKey(
                    Enums.CryptographicAlgorithm.AES, 128, Enums.CryptographicUsageMask.EXPORT)));
    // Enumeration values are checked the same way (Template, Transparent ECDSA keys from 2.0).
    assertThrows(
        IllegalArgumentException.class,
        () ->
            VersionValidator.validate(
                ProtocolVersion.V2_0,
                enumeration(KEY_FORMAT_TYPE, Enums.KeyFormatType.TRANSPARENT_ECDSA_PRIVATE_KEY)));
    VersionValidator.validate(
        ProtocolVersion.V1_4,
        enumeration(KEY_FORMAT_TYPE, Enums.KeyFormatType.TRANSPARENT_ECDSA_PRIVATE_KEY));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            VersionValidator.validate(
                ProtocolVersion.V2_1, enumeration(OBJECT_TYPE, Enums.ObjectType.TEMPLATE)));
    // A mask is an Integer: the typed helper refuses it, the raw int overload fails validation.
    assertThrows(
        IllegalArgumentException.class,
        () -> enumeration(CRYPTOGRAPHIC_USAGE_MASK, Enums.CryptographicUsageMask.ENCRYPT));
    for (ProtocolVersion v : ProtocolVersion.values())
      assertThrows(
          IllegalArgumentException.class,
          () -> VersionValidator.validate(v, enumeration(CRYPTOGRAPHIC_USAGE_MASK, 4)));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            VersionValidator.validate(
                ProtocolVersion.V1_4,
                Attributes.attribute("Cryptographic Usage Mask", enumeration(ATTRIBUTE_VALUE, 4))));
  }

  @Test
  void negotiationEnforcesTheMinimumBeforeAnyMutation() {
    AtomicBoolean closed = new AtomicBoolean();
    List<Integer> operations = new ArrayList<>();
    KmipTransport transport =
        new KmipTransport() {
          @Override
          public Ttlv exchange(Ttlv request) {
            operations.add(request.require(BATCH_ITEM).require(OPERATION).intValue());
            return onePointFourOnly(request);
          }

          @Override
          public void close() {
            closed.set(true);
          }
        };
    var e =
        assertThrows(
            IOException.class,
            () -> KmipClient.negotiated(transport, VersionPolicy.atLeast(ProtocolVersion.V2_0)));
    assertTrue(e.getMessage().contains("No KMIP version acceptable"), e.getMessage());
    assertTrue(closed.get(), "the factory owns the transport and closes it on failure");
    assertTrue(operations.stream().allMatch(op -> op == Operation.DISCOVER_VERSIONS.code()));
  }

  @Test
  void negotiatedViewDoesNotCloseTheOwnersTransport() throws Exception {
    AtomicBoolean closed = new AtomicBoolean();
    KmipTransport transport =
        new KmipTransport() {
          @Override
          public Ttlv exchange(Ttlv request) {
            return discoverReply(
                request,
                Messages.version(request.require(REQUEST_HEADER)),
                ProtocolVersion.V2_0,
                ProtocolVersion.V1_4);
          }

          @Override
          public void close() {
            closed.set(true);
          }
        };
    try (KmipClient owner = new KmipClient(transport, ProtocolVersion.V2_1)) {
      try (KmipClient view = owner.negotiate()) {
        assertEquals(ProtocolVersion.V2_0, view.version());
        assertFalse(view.ownsTransport());
      }
      assertFalse(closed.get(), "closing the view leaves the owner's transport open");
      assertEquals(
          ProtocolVersion.V1_4,
          owner.negotiate(VersionPolicy.only(ProtocolVersion.V1_4)).version());
    }
    assertTrue(closed.get());
  }

  @Test
  void vendorOperationCodesTravelThroughTheRawApi() throws Exception {
    int vendor = 0x80000010;
    try (var client =
        new KmipClient(
            request -> {
              Ttlv item = request.require(BATCH_ITEM);
              assertEquals(vendor, item.require(OPERATION).intValue());
              assertEquals("raw", item.require(REQUEST_PAYLOAD).require(COMMENT).textValue());
              return structure(
                  RESPONSE_MESSAGE,
                  structure(
                      RESPONSE_HEADER,
                      Messages.protocolVersion(ProtocolVersion.V2_1),
                      dateTime(TIME_STAMP, Instant.ofEpochSecond(1700000000)),
                      integer(BATCH_COUNT, 1)),
                  structure(
                      BATCH_ITEM,
                      enumeration(OPERATION, vendor),
                      enumeration(RESULT_STATUS, 0),
                      structure(RESPONSE_PAYLOAD, text(COMMENT, "ok"))));
            },
            ProtocolVersion.V2_1)) {
      Request request = Request.operation(vendor).add(text(COMMENT, "raw")).build();
      assertNull(request.operation());
      Result result = client.call(request);
      assertNull(result.operation());
      assertEquals(vendor, result.operationCode().getAsInt());
      assertEquals("ok", result.requirePayload().require(COMMENT).textValue());
    }
    assertSame(Operation.GET, Request.operation(Operation.GET.code()).build().operation());
  }
}
