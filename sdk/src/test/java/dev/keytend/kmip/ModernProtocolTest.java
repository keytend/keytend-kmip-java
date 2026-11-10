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
import dev.keytend.kmip.codec.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;

class ModernProtocolTest {
  @Test
  void additionalWireTypesRemainExact() throws Exception {
    var ttlv = new TtlvCodec();
    var xml = new XmlCodec();
    var json = new JsonCodec();
    for (Ttlv n :
        List.of(
            dateTimeExtended(TIME_STAMP, Instant.ofEpochSecond(-1, 123456000)),
            identifier(UNIQUE_IDENTIFIER, "urn:uuid:test"),
            reference(UNIQUE_IDENTIFIER, "key-1"),
            nameReference(UNIQUE_IDENTIFIER, "friendly-name"))) {
      assertEquals(n, ttlv.decode(ttlv.encode(n)));
      assertEquals(n, xml.decode(xml.encode(n)));
      assertEquals(n, json.decode(json.encode(n)));
    }
    assertEquals(11, ttlv.encode(dateTimeExtended(TIME_STAMP, Instant.EPOCH))[3]);
    assertEquals(12, ttlv.encode(identifier(UNIQUE_IDENTIFIER, "id"))[3]);
  }

  @Test
  void modernAttributesAndThreePointZeroBatchChanges() {
    Request create =
        Requests.createSymmetricKey(
            Enums.CryptographicAlgorithm.AES, 256, Enums.CryptographicUsageMask.ENCRYPT);
    Ttlv two =
        Messages.request(
            ProtocolVersion.V2_0, List.of(create), RequestOptions.DEFAULT.asynchronous(true));
    assertTrue(two.require(BATCH_ITEM).require(REQUEST_PAYLOAD).child(ATTRIBUTES).isPresent());
    assertEquals(
        Ttlv.Type.ENUMERATION, two.require(REQUEST_HEADER).require(ASYNCHRONOUS_INDICATOR).type());
    Ttlv three =
        Messages.request(
            ProtocolVersion.V3_0,
            List.of(
                create,
                Requests.get().uniqueIdentifier("key-1").ephemeral(Enums.Ephemeral.DATA).build()),
            RequestOptions.DEFAULT);
    assertTrue(three.require(REQUEST_HEADER).child(BATCH_COUNT).isEmpty());
    for (Ttlv batch : three.children(BATCH_ITEM))
      assertTrue(batch.child(UNIQUE_BATCH_ITEM_ID).isEmpty());
    Ttlv second = three.children(BATCH_ITEM).get(1);
    assertEquals(
        Ttlv.Type.REFERENCE, second.require(REQUEST_PAYLOAD).require(UNIQUE_IDENTIFIER).type());
    assertEquals(1, second.require(EPHEMERAL).intValue());
    assertThrows(
        IllegalArgumentException.class,
        () ->
            Messages.request(
                ProtocolVersion.V2_1,
                List.of(Requests.get().ephemeral(Enums.Ephemeral.DATA).build()),
                RequestOptions.DEFAULT));
  }

  @Test
  void modernAttributeReferencesAndLocateFilters() {
    Ttlv get =
        Messages.request(
            ProtocolVersion.V2_1,
            List.of(
                Requests.getAttributes()
                    .uniqueIdentifier("id")
                    .add(text(ATTRIBUTE_NAME, "State"))
                    .build()),
            RequestOptions.DEFAULT);
    assertEquals(
        STATE.code(),
        get.require(BATCH_ITEM).require(REQUEST_PAYLOAD).require(ATTRIBUTE_REFERENCE).intValue());
    Ttlv locate =
        VersionedPayloads.prepare(
            ProtocolVersion.V2_0,
            Operation.LOCATE,
            Requests.locate()
                .attribute(Attributes.algorithm(Enums.CryptographicAlgorithm.AES))
                .build()
                .payload());
    assertEquals(
        Enums.CryptographicAlgorithm.AES.code(),
        locate.require(ATTRIBUTES).require(CRYPTOGRAPHIC_ALGORITHM).intValue());
  }

  @Test
  void criticalResponseExtensionsRequireExplicitUnderstanding() throws Exception {
    var transport =
        (KmipTransport)
            req -> {
              Ttlv item = ClientTest.success(req.require(BATCH_ITEM));
              List<Ttlv> fields = new ArrayList<>(item.children());
              fields.add(
                  Credentials.extension("vendor", true, Ttlv.of(0x540001, Ttlv.Type.INTEGER, 1)));
              return ClientTest.response(req, List.of(structure(BATCH_ITEM, fields)));
            };
    try (var c = new KmipClient(transport, ProtocolVersion.V2_1)) {
      assertThrows(ProtocolException.class, () -> c.call(Requests.get().build()));
    }
    try (var c =
        new KmipClient(transport, ProtocolVersion.V2_1, RequestOptions.DEFAULT, Set.of("vendor"))) {
      assertTrue(c.call(Requests.get().build()).successful());
    }
  }

  @Test
  void hashedPasswordValidatesTheServerBeforeReturningResults() throws Exception {
    byte[] s1 = sha("alicepassword".getBytes(StandardCharsets.UTF_8)),
        s2 = sha("passwordalice".getBytes(StandardCharsets.UTF_8));
    long[] previous = {0};
    KmipTransport peer =
        request -> {
          Ttlv credential =
              request
                  .require(REQUEST_HEADER)
                  .require(AUTHENTICATION)
                  .require(CREDENTIAL)
                  .require(CREDENTIAL_VALUE);
          long timestamp = credential.require(TIME_STAMP).longValue();
          assertTrue(timestamp > previous[0]);
          previous[0] = timestamp;
          byte[] proof = credential.require(HASHED_PASSWORD).bytesValue(),
              first = sha(s1, ByteBuffer.allocate(8).putLong(timestamp).array());
          assertArrayEquals(first, Arrays.copyOf(proof, 32));
          assertArrayEquals(s2, Arrays.copyOfRange(proof, 32, 64));
          Ttlv response =
              ClientTest.response(
                  request, List.of(ClientTest.success(request.require(BATCH_ITEM))));
          List<Ttlv> headers = new ArrayList<>(response.require(RESPONSE_HEADER).children());
          headers.add(
              bytes(
                  SERVER_HASHED_PASSWORD,
                  sha(ByteBuffer.allocate(8).putLong(1700000000L).array(), s1, sha(s2))));
          return structure(
              RESPONSE_MESSAGE, structure(RESPONSE_HEADER, headers), response.require(BATCH_ITEM));
        };
    try (var client =
        new KmipClient(
            new HashedPasswordTransport(peer, "alice", "password".toCharArray()),
            ProtocolVersion.V2_1)) {
      assertTrue(client.call(Requests.get().build()).successful());
      assertTrue(client.call(Requests.get().build()).successful());
    }
    try (var client =
        new KmipClient(
            new HashedPasswordTransport(
                req ->
                    ClientTest.response(req, List.of(ClientTest.success(req.require(BATCH_ITEM)))),
                "alice",
                "password".toCharArray()),
            ProtocolVersion.V3_0)) {
      assertThrows(ProtocolException.class, () -> client.call(Requests.get().build()));
    }
  }

  @Test
  void rekeyPairUsesTheVersionSpecificPrivateIdentifierField() {
    for (ProtocolVersion version : ProtocolVersion.values()) {
      for (Request request :
          List.of(
              Requests.reKeyKeyPair().uniqueIdentifier("private-key").build(),
              Requests.reKeyKeyPair()
                  .add(text(PRIVATE_KEY_UNIQUE_IDENTIFIER, "private-key"))
                  .build())) {
        Ttlv payload = VersionedPayloads.prepare(version, request.operation(), request.payload());
        Tag expected =
            version == ProtocolVersion.V3_0 ? UNIQUE_IDENTIFIER : PRIVATE_KEY_UNIQUE_IDENTIFIER;
        assertEquals("private-key", payload.require(expected).textValue());
        assertEquals(
            version == ProtocolVersion.V3_0 ? Ttlv.Type.REFERENCE : Ttlv.Type.TEXT_STRING,
            payload.require(expected).type());
      }
    }
  }

  private static byte[] sha(byte[]... bytes) {
    try {
      MessageDigest d = MessageDigest.getInstance("SHA-256");
      for (byte[] b : bytes) d.update(b);
      return d.digest();
    } catch (Exception e) {
      throw new AssertionError(e);
    }
  }
}
