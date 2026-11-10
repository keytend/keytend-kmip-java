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

package dev.keytend.kmip.interop;

import static dev.keytend.kmip.model.Enums.*;
import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import java.nio.file.*;
import java.security.KeyPairGenerator;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The corrected request shapes of the generic suite's setups, on the wire of each version they
 * run on, without a server. The live controls (ServerSetupControls) show the old shapes refused and
 * these accepted by keytend-kmip-server.
 */
class InteropScenarioRequestsTest {
  private static final List<ProtocolVersion> SPLIT_VERSIONS =
      List.of(
          ProtocolVersion.V1_2,
          ProtocolVersion.V1_3,
          ProtocolVersion.V1_4,
          ProtocolVersion.V2_0,
          ProtocolVersion.V2_1,
          ProtocolVersion.V3_0);

  /** The Request Payload of {@code request} as {@code version} sends it. */
  private static Ttlv wire(ProtocolVersion version, Request request) {
    return Messages.request(version, List.of(request), RequestOptions.DEFAULT)
        .require(BATCH_ITEM)
        .require(REQUEST_PAYLOAD);
  }

  @Test
  void createSplitKeyNamesSplitKeyObjectsAndCarriesTheAttributeContainer() {
    for (ProtocolVersion v : SPLIT_VERSIONS) {
      Ttlv attributes = v.legacyAttributes() ? Attributes.template() : ModernAttributes.of();
      Ttlv payload = wire(v, InteropSuite.splitRequest("key-1", attributes));
      assertEquals(ObjectType.SPLIT_KEY.code(), payload.require(OBJECT_TYPE).intValue(), v + "");
      assertEquals("key-1", payload.require(UNIQUE_IDENTIFIER).textValue());
      assertEquals(3, payload.require(SPLIT_KEY_PARTS).intValue());
      assertEquals(3, payload.require(SPLIT_KEY_THRESHOLD).intValue());
      assertEquals(SplitKeyMethod.XOR.code(), payload.require(SPLIT_KEY_METHOD).intValue());
      // 1.x Template-Attribute, 2.x Attributes: required, and naming no length that would
      // contradict the split key's own.
      Ttlv container = payload.require(v.legacyAttributes() ? TEMPLATE_ATTRIBUTE : ATTRIBUTES);
      assertTrue(container.children().isEmpty(), v + "");
    }
  }

  @Test
  void legacyImportRestoresEveryExportedAttributeOverTheExportedObject() {
    Ttlv key = ManagedObjects.rawSymmetricKey(new byte[16], CryptographicAlgorithm.AES);
    Ttlv state = Attributes.attribute("State", enumeration(ATTRIBUTE_VALUE, State.ACTIVE));
    Ttlv initial =
        Attributes.attribute("Initial Date", dateTime(ATTRIBUTE_VALUE, Instant.ofEpochSecond(1)));
    Ttlv changed =
        Attributes.attribute(
            "Last Change Date", dateTime(ATTRIBUTE_VALUE, Instant.ofEpochSecond(2)));
    Ttlv exported =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY),
            text(UNIQUE_IDENTIFIER, "key-1"),
            state,
            initial,
            changed,
            key);
    Ttlv payload =
        wire(
            ProtocolVersion.V1_4,
            InteropSuite.restoreRequest(ProtocolVersion.V1_4, "key-1", exported));
    assertEquals("key-1", payload.require(UNIQUE_IDENTIFIER).textValue());
    assertEquals(ObjectType.SYMMETRIC_KEY.code(), payload.require(OBJECT_TYPE).intValue());
    assertTrue(
        payload.require(REPLACE_EXISTING).booleanValue(), "restores over the exported object");
    assertEquals(List.of(state, initial, changed), payload.children(ATTRIBUTE));
    assertEquals(key, payload.require(SYMMETRIC_KEY));
  }

  @Test
  void modernImportRestoresTheExportedAttributesStructure() {
    Ttlv key = ManagedObjects.rawSymmetricKey(new byte[16], CryptographicAlgorithm.AES);
    Ttlv attributes =
        ModernAttributes.of(
            enumeration(STATE, State.PRE_ACTIVE),
            dateTime(INITIAL_DATE, Instant.ofEpochSecond(1)),
            dateTime(LAST_CHANGE_DATE, Instant.ofEpochSecond(2)));
    Ttlv exported =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY),
            text(UNIQUE_IDENTIFIER, "key-1"),
            attributes,
            key);
    for (ProtocolVersion v : List.of(ProtocolVersion.V2_0, ProtocolVersion.V2_1)) {
      Ttlv payload = wire(v, InteropSuite.restoreRequest(v, "key-1", exported));
      assertEquals(attributes, payload.require(ATTRIBUTES), v + "");
      assertTrue(payload.require(REPLACE_EXISTING).booleanValue());
      assertEquals(key, payload.require(SYMMETRIC_KEY));
    }
  }

  @Test
  void importWithoutAnExportedObjectIsRefusedBeforeSending() {
    Ttlv exported = structure(RESPONSE_PAYLOAD, enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY));
    assertThrows(
        AssertionError.class,
        () -> InteropSuite.restoreRequest(ProtocolVersion.V2_1, "key-1", exported));
  }

  @Test
  void theRegisteredSubjectKeyIsTheKeyItself() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    var key = generator.generateKeyPair().getPublic();
    Ttlv block = InteropSuite.rsaPublicKey(key).require(KEY_BLOCK);
    assertEquals(KeyFormatType.X_509.code(), block.require(KEY_FORMAT_TYPE).intValue());
    assertEquals(2048, block.require(CRYPTOGRAPHIC_LENGTH).intValue());
    assertArrayEquals(key.getEncoded(), InteropSuite.keyBytes(block));
  }

  @Test
  void theAdministratorCredentialIsOptionalAndComplete(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("admin-credential.properties");
    assertNull(InteropApplication.administrator(file), "no file: no header credential");
    Files.writeString(file, "username=interop-admin\npassword=s3cret\n");
    assertEquals(
        Credentials.usernamePassword("interop-admin", "s3cret"),
        InteropApplication.administrator(file));
    Files.writeString(file, "username=interop-admin\n");
    assertThrows(IllegalArgumentException.class, () -> InteropApplication.administrator(file));
  }
}
