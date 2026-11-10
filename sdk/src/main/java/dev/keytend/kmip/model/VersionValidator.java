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

package dev.keytend.kmip.model;

import java.util.Optional;

/**
 * Guards wire types, tags and enumeration values against the target version: a tag or value must
 * be defined by that version's tables. That rejects values introduced later (for example
 * Cryptographic Algorithm ML-KEM-512 or Key Format Type PKCS#12 in a 1.2 request) and tags the
 * version turned into Reserved (Template and the Template-Attribute structures from 2.0; Batch
 * Count, Unique Batch Item ID and the Name/Link sub-structures from 3.0). Enumeration values and
 * mask flags are checked the same way, including values a later version lists as Reserved (Usage
 * Mask Export from 2.0), and a mask tag must be an Integer, never an Enumeration. Vendor and
 * unknown numeric values pass unchanged. Deprecated but still defined fields remain available.
 *
 * @since 0.10.0
 */
public final class VersionValidator {
  private VersionValidator() {}

  public static void validate(ProtocolVersion version, Ttlv value) {
    validate(version, value, null);
  }

  private static void validate(ProtocolVersion version, Ttlv value, String attributeName) {
    Optional<Tag> tag = value.standardTag();
    if (tag.isPresent()) {
      if (!version.atLeast(tag.get().since()))
        throw new IllegalArgumentException(
            tag.get().wireName() + " requires KMIP " + tag.get().since());
      if (!tag.get().definedIn(version))
        throw new IllegalArgumentException(
            tag.get().wireName() + " is not defined in KMIP " + version);
    }
    if (value.type() == Ttlv.Type.DATE_TIME_EXTENDED && !version.atLeast(ProtocolVersion.V2_0))
      throw new IllegalArgumentException("DateTimeExtended requires KMIP 2.0");
    if ((value.type() == Ttlv.Type.IDENTIFIER
            || value.type() == Ttlv.Type.REFERENCE
            || value.type() == Ttlv.Type.NAME_REFERENCE)
        && version != ProtocolVersion.V3_0)
      throw new IllegalArgumentException("Identifier/Reference types require KMIP 3.0");
    if (value.type() == Ttlv.Type.ENUMERATION || value.type() == Ttlv.Type.INTEGER) {
      Optional<Class<? extends WireEnum>> group =
          attributeName != null && tag.isPresent() && tag.get() == Tag.ATTRIBUTE_VALUE
              ? WireEnums.forAttributeName(attributeName)
              : tag.flatMap(WireEnums::forTag);
      if (group.isPresent()) checkValue(version, value, group.get());
    }
    if (value.type() == Ttlv.Type.STRUCTURE) {
      String name = null;
      if (value.tag() == Tag.ATTRIBUTE.code())
        name =
            value
                .child(Tag.ATTRIBUTE_NAME)
                .filter(n -> n.type() == Ttlv.Type.TEXT_STRING)
                .map(Ttlv::textValue)
                .orElse(null);
      for (Ttlv child : value.children()) validate(version, child, name);
    }
  }

  private static void checkValue(
      ProtocolVersion version, Ttlv value, Class<? extends WireEnum> group) {
    int code = value.intValue();
    if (value.type() == Ttlv.Type.ENUMERATION && WireEnums.isMask(group))
      // A mask sent as an Enumeration (Ttlv.enumeration(CRYPTOGRAPHIC_USAGE_MASK, ...)) has the
      // wrong wire type; servers reject it or, worse, read a single flag as the whole mask.
      throw new IllegalArgumentException(
          group.getSimpleName() + " is an Integer bit mask, not an Enumeration");
    if (value.type() == Ttlv.Type.ENUMERATION) {
      WireEnums.constant(group, code).ifPresent(known -> requireDefined(version, group, known));
    } else if (value.type() == Ttlv.Type.INTEGER && WireEnums.isMask(group)) {
      for (Object constant : group.getEnumConstants()) {
        WireEnum flag = (WireEnum) constant;
        if (flag.code() != 0
            && (code & flag.code()) == flag.code()
            && Integer.bitCount(flag.code()) == 1) requireDefined(version, group, flag);
      }
    }
  }

  private static void requireDefined(
      ProtocolVersion version, Class<? extends WireEnum> group, WireEnum known) {
    if (!version.atLeast(known.since()))
      throw new IllegalArgumentException(
          group.getSimpleName() + " " + known.wireName() + " requires KMIP " + known.since());
    if (!known.definedIn(version))
      throw new IllegalArgumentException(
          group.getSimpleName() + " " + known.wireName() + " is Reserved in KMIP " + version);
  }
}
