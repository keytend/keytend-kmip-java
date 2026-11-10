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

import dev.keytend.kmip.model.*;
import java.math.BigInteger;
import java.time.Instant;
import java.util.*;

/** Reads a Get Attributes payload of any version into {@link KeyAttributes}. */
final class AttributeReader {
  private AttributeReader() {}

  private static final Map<Integer, Enums.LinkType> LINK_TAGS = linkTags();

  /** 3.0 per-type link attributes: each Link Type's own attribute (PublicKeyLink, ...). */
  private static Map<Integer, Enums.LinkType> linkTags() {
    Map<Integer, Enums.LinkType> m = new HashMap<>();
    for (Enums.LinkType type : Enums.LinkType.values())
      dev.keytend.kmip.model.ModernAttributes.linkAttribute(type.code())
          .ifPresent(tag -> m.put(tag.code(), type));
    return Map.copyOf(m);
  }

  static KeyAttributes read(Ttlv payload) {
    String id = payload.require(UNIQUE_IDENTIFIER).textValue();
    List<Ttlv> modern = new ArrayList<>();
    Map<CustomAttribute, Object> custom = new LinkedHashMap<>();
    for (Ttlv legacy : payload.children(ATTRIBUTE)) {
      String name = legacy.require(ATTRIBUTE_NAME).textValue();
      Ttlv value = legacy.require(ATTRIBUTE_VALUE);
      if (name.length() > 2 && (name.startsWith("x-") || name.startsWith("y-"))) {
        CustomAttribute key = new CustomAttribute(name.substring(0, 1), name.substring(2));
        custom.putIfAbsent(key, value(value));
        modern.add(dev.keytend.kmip.model.ModernAttributes.vendor(key.vendor(), key.name(), value));
        continue;
      }
      try {
        modern.add(value.retag(Tag.fromName(name)));
      } catch (IllegalArgumentException unknownName) {
        modern.add(legacy);
      }
    }
    for (Ttlv attributes : payload.children(ATTRIBUTES))
      for (Ttlv a : attributes.children()) {
        modern.add(a);
        if (a.tag() == ATTRIBUTE.code() && a.child(VENDOR_IDENTIFICATION).isPresent()) {
          CustomAttribute key =
              new CustomAttribute(
                  a.require(VENDOR_IDENTIFICATION).textValue(),
                  a.require(ATTRIBUTE_NAME).textValue());
          custom.putIfAbsent(key, value(a.require(ATTRIBUTE_VALUE)));
        }
      }
    int objectType = 0, state = 0, usage = 0, algorithm = 0;
    Integer length = null;
    Instant created = null,
        activated = null,
        deactivated = null,
        compromised = null,
        destroyed = null;
    List<String> names = new ArrayList<>(), groups = new ArrayList<>();
    List<Link> links = new ArrayList<>();
    for (Ttlv a : modern) {
      Optional<Tag> tag = a.standardTag();
      if (tag.isEmpty()) continue;
      switch (tag.get()) {
        case OBJECT_TYPE -> objectType = a.intValue();
        case STATE -> state = a.intValue();
        case CRYPTOGRAPHIC_USAGE_MASK -> usage = a.intValue();
        case CRYPTOGRAPHIC_LENGTH -> length = a.intValue();
        case CRYPTOGRAPHIC_ALGORITHM -> algorithm = a.intValue();
        case INITIAL_DATE -> created = a.instantValue();
        case ACTIVATION_DATE -> activated = a.instantValue();
        case DEACTIVATION_DATE -> deactivated = a.instantValue();
        case COMPROMISE_DATE -> compromised = a.instantValue();
        case DESTROY_DATE -> destroyed = a.instantValue();
        case NAME ->
            names.add(
                a.type() == Ttlv.Type.STRUCTURE
                    ? a.require(NAME_VALUE).textValue()
                    : a.textValue());
        case OBJECT_GROUP -> groups.add(a.textValue());
        case LINK -> {
          int type = a.require(LINK_TYPE).intValue();
          links.add(
              new Link(LinkKind.of(type), type, a.require(LINKED_OBJECT_IDENTIFIER).textValue()));
        }
        default -> {
          Enums.LinkType type = LINK_TAGS.get(a.tag());
          if (type != null && a.type() != Ttlv.Type.STRUCTURE)
            links.add(new Link(LinkKind.of(type.code()), type.code(), a.textValue()));
        }
      }
    }
    return new KeyAttributes(
        id,
        objectType,
        state,
        usage,
        names,
        groups,
        algorithm,
        length,
        created,
        activated,
        deactivated,
        compromised,
        destroyed,
        links,
        custom,
        modern);
  }

  /** The Java form of a custom attribute value. */
  static Object value(Ttlv v) {
    return switch (v.type()) {
      case TEXT_STRING, IDENTIFIER, REFERENCE, NAME_REFERENCE -> v.textValue();
      case INTEGER, ENUMERATION -> v.intValue();
      case LONG_INTEGER, INTERVAL -> v.longValue();
      case BIG_INTEGER -> v.bigIntegerValue();
      case BOOLEAN -> v.booleanValue();
      case DATE_TIME, DATE_TIME_EXTENDED -> v.instantValue();
      case BYTE_STRING -> v.bytesValue();
      case STRUCTURE -> v;
    };
  }

  /** A custom attribute value as TTLV (tagged Attribute Value). */
  static Ttlv encode(Object value) {
    Tag t = ATTRIBUTE_VALUE;
    if (value instanceof String s) return Ttlv.text(t, s);
    if (value instanceof Integer i) return Ttlv.integer(t, i);
    if (value instanceof Long l) return Ttlv.longInteger(t, l);
    if (value instanceof BigInteger b) return Ttlv.bigInteger(t, b);
    if (value instanceof Boolean b) return Ttlv.bool(t, b);
    if (value instanceof Instant i)
      return Ttlv.dateTime(t, i.truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
    if (value instanceof byte[] b) return Ttlv.bytes(t, b);
    throw new IllegalArgumentException(
        "Custom attribute values are String, Integer, Long, BigInteger, Boolean, Instant or byte[]");
  }
}
