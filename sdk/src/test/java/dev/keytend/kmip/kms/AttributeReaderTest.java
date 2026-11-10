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

package dev.keytend.kmip.kms;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;

/**
 * Version normalization of Get Attributes payloads, from hand-built payloads in
 * each version's shape: the same {@link KeyAttributes} must come out.
 */
class AttributeReaderTest {
  static final Instant ACTIVATED = Instant.ofEpochSecond(1_700_000_000);

  static void assertNormalized(KeyAttributes a) {
    assertEquals("k1", a.id());
    assertEquals(ObjectKind.SYMMETRIC_KEY, a.kind());
    assertEquals(KeyState.ACTIVE, a.state());
    assertEquals(List.of("orders", "orders-alias"), a.names());
    assertEquals(Optional.of(Algorithm.AES), a.algorithm());
    assertEquals(256, a.length().getAsInt());
    assertEquals(Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), a.usages());
    assertEquals(Optional.of(ACTIVATED), a.activationDate());
    assertEquals(Optional.of("k0"), a.link(LinkKind.REPLACED));
    assertEquals("acme", a.custom().get(CustomAttribute.client("Tenant")));
  }

  static Ttlv name(String value) {
    return structure(
        NAME,
        text(NAME_VALUE, value),
        enumeration(NAME_TYPE, Enums.NameType.UNINTERPRETED_TEXT_STRING));
  }

  @Test
  void kmip1xAttributeStructures() {
    Ttlv payload =
        structure(
            RESPONSE_PAYLOAD,
            text(UNIQUE_IDENTIFIER, "k1"),
            Attributes.attribute(
                "Object Type", enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY)),
            Attributes.attribute("State", enumeration(STATE, Enums.State.ACTIVE)),
            Attributes.attribute("Name", 0, name("orders")),
            Attributes.attribute("Name", 1, name("orders-alias")),
            Attributes.algorithm(Enums.CryptographicAlgorithm.AES),
            Attributes.length(256),
            Attributes.usage(
                Enums.CryptographicUsageMask.ENCRYPT, Enums.CryptographicUsageMask.DECRYPT),
            Attributes.attribute("Activation Date", dateTime(ACTIVATION_DATE, ACTIVATED)),
            Attributes.link(Enums.LinkType.REPLACED_OBJECT_LINK, "k0"),
            Attributes.textAttribute("x-Tenant", "acme"),
            Attributes.textAttribute("Some Future Attribute", "kept"));
    KeyAttributes a = AttributeReader.read(payload);
    assertNormalized(a);
    assertTrue(a.protocolAttributes().size() >= 11, "unknown attributes are kept raw");
  }

  @Test
  void kmip2xAttributesStructure() {
    Ttlv payload =
        structure(
            RESPONSE_PAYLOAD,
            text(UNIQUE_IDENTIFIER, "k1"),
            structure(
                ATTRIBUTES,
                enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY),
                enumeration(STATE, Enums.State.ACTIVE),
                name("orders"),
                name("orders-alias"),
                enumeration(CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.AES),
                integer(CRYPTOGRAPHIC_LENGTH, 256),
                integer(CRYPTOGRAPHIC_USAGE_MASK, 12),
                dateTime(ACTIVATION_DATE, ACTIVATED),
                structure(
                    LINK,
                    enumeration(LINK_TYPE, Enums.LinkType.REPLACED_OBJECT_LINK),
                    text(LINKED_OBJECT_IDENTIFIER, "k0")),
                ModernAttributes.vendor("x", "Tenant", text(ATTRIBUTE_VALUE, "acme")),
                ModernAttributes.vendor("acme", "Region", text(ATTRIBUTE_VALUE, "eu"))));
    KeyAttributes a = AttributeReader.read(payload);
    assertNormalized(a);
    assertEquals("eu", a.custom().get(new CustomAttribute("acme", "Region")));
  }

  @Test
  void kmip30TextNamesAndPerTypeLinks() {
    Ttlv payload =
        structure(
            RESPONSE_PAYLOAD,
            identifier(UNIQUE_IDENTIFIER, "k1"),
            structure(
                ATTRIBUTES,
                enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY),
                enumeration(STATE, Enums.State.ACTIVE),
                text(NAME, "orders"),
                text(NAME, "orders-alias"),
                enumeration(CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.AES),
                integer(CRYPTOGRAPHIC_LENGTH, 256),
                integer(CRYPTOGRAPHIC_USAGE_MASK, 12),
                dateTimeExtended(ACTIVATION_DATE, ACTIVATED),
                reference(REPLACED_OBJECT_LINK, "k0"),
                ModernAttributes.vendor("x", "Tenant", text(ATTRIBUTE_VALUE, "acme"))));
    assertNormalized(AttributeReader.read(payload));
  }

  @Test
  void unknownStatesAndKindsKeepTheirCodes() {
    KeyAttributes a =
        AttributeReader.read(
            structure(
                RESPONSE_PAYLOAD,
                text(UNIQUE_IDENTIFIER, "v"),
                structure(
                    ATTRIBUTES,
                    enumeration(OBJECT_TYPE, 0x80000002),
                    enumeration(STATE, 0x80000001),
                    integer(CRYPTOGRAPHIC_USAGE_MASK, 0x40000000 | 4))));
    assertEquals(ObjectKind.OTHER, a.kind());
    assertEquals(0x80000002, a.rawObjectType());
    assertEquals(KeyState.UNKNOWN, a.state());
    assertEquals(0x80000001, a.rawState());
    assertEquals(Set.of(KeyUsage.ENCRYPT), a.usages());
    assertEquals(0x40000004, a.rawUsageMask(), "unknown usage bits are kept");
  }
}
