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

package dev.keytend.kmip.client;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.model.*;
import java.util.*;

/**
 * Adapts portable convenience builders to a version; explicitly supplied modern fields remain
 * lossless.
 *
 * @since 0.10.0
 */
public final class VersionedPayloads {
  private VersionedPayloads() {}

  public static Ttlv prepare(ProtocolVersion version, Operation operation, Ttlv payload) {
    List<Ttlv> fields = new ArrayList<>();
    for (Ttlv field : payload.children()) {
      // KMIP 1.4 Import carries repeated Attribute fields, not a Template-Attribute.
      if (version.legacyAttributes()
          && operation == Operation.IMPORT
          && field.tag() == TEMPLATE_ATTRIBUTE.code()) {
        fields.addAll(field.children());
        continue;
      }
      if (operation == Operation.RE_KEY_KEY_PAIR) {
        if (version == ProtocolVersion.V3_0 && field.tag() == PRIVATE_KEY_UNIQUE_IDENTIFIER.code())
          field = field.retag(UNIQUE_IDENTIFIER);
        else if (version != ProtocolVersion.V3_0 && field.tag() == UNIQUE_IDENTIFIER.code())
          field = field.retag(PRIVATE_KEY_UNIQUE_IDENTIFIER);
      }
      if (!version.legacyAttributes()) {
        Tag target =
            switch (field.standardTag().orElse(DATA)) {
              case TEMPLATE_ATTRIBUTE -> ATTRIBUTES;
              case COMMON_TEMPLATE_ATTRIBUTE -> COMMON_ATTRIBUTES;
              case PRIVATE_KEY_TEMPLATE_ATTRIBUTE -> PRIVATE_KEY_ATTRIBUTES;
              case PUBLIC_KEY_TEMPLATE_ATTRIBUTE -> PUBLIC_KEY_ATTRIBUTES;
              default -> null;
            };
        if (target != null) {
          if (!field.children(NAME).isEmpty())
            throw new IllegalArgumentException(
                "Template object references were removed in KMIP 2.0");
          fields.add(
              structure(
                  target,
                  field.children().stream()
                      .map(a -> ModernAttributes.fromLegacy(a, version))
                      .toList()));
          continue;
        }
        if (field.tag() == ATTRIBUTE_NAME.code()) {
          fields.add(ModernAttributes.referenceFromLegacy(field.textValue()));
          continue;
        }
        if (field.tag() == ATTRIBUTE_INDEX.code())
          throw new IllegalArgumentException(
              "AttributeIndex was removed in KMIP 2.0; use CurrentAttribute for value selection");
        if (field.tag() == ATTRIBUTE.code()) {
          // Without an index, 2.x Delete Attribute removes every instance; refuse to widen it.
          if (operation == Operation.DELETE_ATTRIBUTE && field.child(ATTRIBUTE_INDEX).isPresent())
            throw new IllegalArgumentException(
                "AttributeIndex was removed in KMIP 2.0; use CurrentAttribute for value selection");
          Ttlv direct = ModernAttributes.fromLegacy(field, version);
          if (operation == Operation.ADD_ATTRIBUTE
              || operation == Operation.MODIFY_ATTRIBUTE
              || operation == Operation.SET_ATTRIBUTE)
            fields.add(ModernAttributes.newAttribute(direct));
          // 2.x Delete Attribute selects by Current Attribute or Attribute Reference (2.1
          // Table 196); an Attribute with a value deletes that value, so it is the current one.
          else if (operation == Operation.DELETE_ATTRIBUTE)
            fields.add(ModernAttributes.currentAttribute(direct));
          else fields.add(direct);
          continue;
        }
      }
      fields.add(field);
    }
    // 2.x Import takes one Attributes structure; gather portable Attribute fields into it.
    if (!version.legacyAttributes() && operation == Operation.IMPORT) {
      Set<Integer> structural =
          Set.of(
              UNIQUE_IDENTIFIER.code(),
              OBJECT_TYPE.code(),
              REPLACE_EXISTING.code(),
              KEY_WRAP_TYPE.code(),
              ATTRIBUTES.code());
      List<Ttlv> loose =
          fields.stream()
              .filter(n -> !structural.contains(n.tag()) && !isManagedObject(n))
              .toList();
      if (!loose.isEmpty()) {
        fields.removeAll(loose);
        Optional<Ttlv> existing =
            fields.stream().filter(n -> n.tag() == ATTRIBUTES.code()).findFirst();
        List<Ttlv> merged = new ArrayList<>(existing.map(Ttlv::children).orElse(List.of()));
        merged.addAll(loose);
        existing.ifPresent(fields::remove);
        fields.add(structure(ATTRIBUTES, merged));
      }
    }
    if (!version.legacyAttributes()
        && operation == Operation.LOCATE
        && fields.stream().noneMatch(n -> n.tag() == ATTRIBUTES.code())) {
      Set<Integer> controls =
          Set.of(
              MAXIMUM_ITEMS.code(),
              OFFSET_ITEMS.code(),
              STORAGE_STATUS_MASK.code(),
              OBJECT_GROUP_MEMBER.code(),
              OBJECT_CLASS_MASK.code());
      List<Ttlv> filters = fields.stream().filter(n -> !controls.contains(n.tag())).toList();
      fields.removeAll(filters);
      fields.add(structure(ATTRIBUTES, filters));
    }
    Ttlv prepared = Structures.requestPayload(operation, version, fields);
    return Structures.canonical(
        version,
        convertReferences(version, operation, wrapSelectors(version, prepared), false, false));
  }

  /**
   * KMIP 3.0 names the attributes to wrap in a Key Wrapping Specification by Attribute Reference
   * (CSD02), not by Attribute Name; nested specifications are converted wherever they occur.
   */
  private static Ttlv wrapSelectors(ProtocolVersion version, Ttlv n) {
    if (version != ProtocolVersion.V3_0 || n.type() != Ttlv.Type.STRUCTURE) return n;
    boolean specification = n.tag() == KEY_WRAPPING_SPECIFICATION.code();
    return structure(
        n.tag(),
        n.children().stream()
            .map(
                c ->
                    specification
                            && c.tag() == ATTRIBUTE_NAME.code()
                            && c.type() == Ttlv.Type.TEXT_STRING
                        ? ModernAttributes.referenceFromLegacy(c.textValue())
                        : wrapSelectors(version, c))
            .toList());
  }

  private static boolean isManagedObject(Ttlv field) {
    try {
      ManagedObjects.objectType(field);
      return true;
    } catch (IllegalArgumentException notAnObject) {
      return false;
    }
  }

  private static Ttlv convertReferences(
      ProtocolVersion version,
      Operation operation,
      Ttlv n,
      boolean attributes,
      boolean directPayloadField) {
    if (version != ProtocolVersion.V3_0) return n;
    if (n.type() == Ttlv.Type.STRUCTURE)
      return structure(
          n.tag(),
          n.children().stream()
              .map(
                  c ->
                      convertReferences(
                          version,
                          operation,
                          c,
                          attributes
                              || Set.of(
                                      ATTRIBUTES.code(),
                                      COMMON_ATTRIBUTES.code(),
                                      PRIVATE_KEY_ATTRIBUTES.code(),
                                      PUBLIC_KEY_ATTRIBUTES.code())
                                  .contains(n.tag()),
                          n.tag() == REQUEST_PAYLOAD.code()))
              .toList());
    if (n.type() == Ttlv.Type.TEXT_STRING
        && Set.of(
                UNIQUE_IDENTIFIER.code(),
                PRIVATE_KEY_UNIQUE_IDENTIFIER.code(),
                PUBLIC_KEY_UNIQUE_IDENTIFIER.code(),
                LINKED_OBJECT_IDENTIFIER.code(),
                CERTIFICATE_REQUEST_UNIQUE_IDENTIFIER.code())
            .contains(n.tag()))
      return Ttlv.of(
          n.tag(),
          (attributes || (operation == Operation.IMPORT && directPayloadField))
              ? Ttlv.Type.IDENTIFIER
              : Ttlv.Type.REFERENCE,
          n.textValue());
    return n;
  }
}
