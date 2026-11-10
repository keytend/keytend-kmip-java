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

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/**
 * A {@link KeyAttributes} snapshot is deeply immutable: {@link KeyAttributes#custom()} never
 * returns its own {@code byte[]} values, so a caller that changes one does not change the snapshot
 * every other holder sees, and the constructor does not keep the arrays it is given.
 */
class AttributeSnapshotTest {
  static final CustomAttribute BINDING = CustomAttribute.client("binding");
  static final CustomAttribute TENANT = CustomAttribute.client("tenant");

  /** Changing a returned {@code byte[]} value does not change the snapshot. */
  @Test
  void changingAReturnedArrayDoesNotChangeTheSnapshot() {
    try (InMemoryKmipServer s = InMemoryKmipServer.of(KmipVersion.V2_1);
        Kms kms = s.connect()) {
      KeyHandle key =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .custom(BINDING, new byte[] {1, 2})
              .custom(TENANT, "acme")
              .create();
      KeyAttributes attributes = key.attributes();
      byte[] returned = (byte[]) attributes.custom().get(BINDING);
      returned[0] = 9;
      assertArrayEquals(new byte[] {1, 2}, (byte[]) attributes.custom().get(BINDING));
      assertNotSame(
          attributes.custom().get(BINDING), attributes.custom().get(BINDING), "a copy per call");
      assertEquals("acme", attributes.custom().get(TENANT));
      assertThrows(
          UnsupportedOperationException.class, () -> attributes.custom().put(TENANT, "other"));

      // The protocol form was never shared: Ttlv copies its byte strings.
      for (Ttlv a : attributes.protocolAttributes())
        if (a.type() == Ttlv.Type.BYTE_STRING) a.bytesValue()[0] = 9;
      assertEquals(attributes.protocolAttributes(), key.attributes().protocolAttributes());
    }
  }

  /** The constructor keeps its own arrays: changing the map or arrays it was given changes nothing. */
  @Test
  void changingTheConstructorsInputDoesNotChangeTheSnapshot() {
    byte[] binding = {1, 2};
    Map<CustomAttribute, Object> custom = new LinkedHashMap<>();
    custom.put(BINDING, binding);
    custom.put(TENANT, "acme");
    KeyAttributes attributes =
        new KeyAttributes(
            "k",
            2,
            2,
            12,
            List.of("name"),
            List.of(),
            3,
            256,
            null,
            null,
            null,
            null,
            null,
            List.of(),
            custom,
            List.of());
    binding[0] = 9;
    custom.put(TENANT, "other");
    custom.remove(BINDING);
    assertArrayEquals(new byte[] {1, 2}, (byte[]) attributes.custom().get(BINDING));
    assertEquals("acme", attributes.custom().get(TENANT));
    assertEquals(List.of(BINDING, TENANT), List.copyOf(attributes.custom().keySet()), "in order");
  }

  /** Without {@code byte[]} values there is nothing to copy: the same unmodifiable map each time. */
  @Test
  void aSnapshotWithoutArraysReturnsOneMap() {
    KeyAttributes attributes =
        new KeyAttributes(
            "k",
            2,
            2,
            12,
            List.of(),
            List.of(),
            3,
            256,
            null,
            null,
            null,
            null,
            null,
            List.of(),
            Map.of(TENANT, "acme"),
            List.of());
    assertSame(attributes.custom(), attributes.custom());
    assertThrows(UnsupportedOperationException.class, () -> attributes.custom().clear());
  }
}
