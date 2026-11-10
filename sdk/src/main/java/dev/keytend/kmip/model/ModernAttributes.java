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

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import java.util.*;

/**
 * KMIP 2.x/3.0 direct attribute representation and standard/vendor attribute references.
 *
 * @since 0.10.0
 */
public final class ModernAttributes {
  private ModernAttributes() {}

  public static Ttlv of(Ttlv... attributes) {
    return structure(ATTRIBUTES, attributes);
  }

  public static Ttlv reference(Tag attribute) {
    return enumeration(ATTRIBUTE_REFERENCE, attribute.code());
  }

  public static Ttlv vendorReference(String vendor, String name) {
    return structure(
        ATTRIBUTE_REFERENCE, text(VENDOR_IDENTIFICATION, vendor), text(ATTRIBUTE_NAME, name));
  }

  public static Ttlv vendor(String vendor, String name, Ttlv value) {
    return structure(
        ATTRIBUTE,
        text(VENDOR_IDENTIFICATION, vendor),
        text(ATTRIBUTE_NAME, name),
        value.retag(ATTRIBUTE_VALUE));
  }

  /**
   * The Protection Storage Masks operation field (KMIP 2.0+): each alternative is one whole mask
   * the server may satisfy, kept separate rather than ORed together. Not to be confused with the
   * read-only Protection Storage Mask attribute, which reports where an object is stored.
   */
  @SafeVarargs
  public static Ttlv protectionStorageMasks(Set<Enums.ProtectionStorageMask>... alternatives) {
    List<Ttlv> masks = new ArrayList<>();
    for (Set<Enums.ProtectionStorageMask> alternative : alternatives) {
      if (alternative.isEmpty()) throw new IllegalArgumentException("Empty protection mask");
      masks.add(
          integer(
              PROTECTION_STORAGE_MASK,
              Attributes.mask(alternative.toArray(Enums.ProtectionStorageMask[]::new))));
    }
    if (masks.isEmpty()) throw new IllegalArgumentException("No protection mask alternatives");
    return structure(PROTECTION_STORAGE_MASKS, masks);
  }

  public static Ttlv newAttribute(Ttlv value) {
    return structure(NEW_ATTRIBUTE, value);
  }

  public static Ttlv currentAttribute(Ttlv value) {
    return structure(CURRENT_ATTRIBUTE, value);
  }

  /**
   * Explicit conversion of a 1.x Attribute to its 2.x/3.0 form.
   *
   * <p>A standard name becomes the attribute's own tag. A 1.x custom attribute {@code x-Name} or
   * {@code y-Name} becomes a vendor attribute with Vendor Identification {@code x} or {@code y}
   * and Attribute Name {@code Name} (KMIP 2.1 §4.60 reserves these for 1.x custom attributes; the
   * OASIS 2.0 vectors map {@code x-ID} this way). Other names are not valid 1.x attribute names
   * and are rejected. A non-zero Attribute Index cannot be expressed after 2.0 removed it and is
   * rejected; use CurrentAttribute to select a value. On the KMIP 3.0 draft, a Name structure
   * becomes its Text String value, and a Link structure the link type's own attribute ({@link
   * #linkAttribute}), since 3.0 has neither structure.
   *
   * @throws IllegalArgumentException for an unknown name or a non-zero index
   */
  public static Ttlv fromLegacy(Ttlv attribute, ProtocolVersion version) {
    if (attribute.tag() != ATTRIBUTE.code()) return attribute;
    // Already a 2.x vendor attribute (Vendor Identification, Attribute Name, Attribute Value).
    if (attribute.child(VENDOR_IDENTIFICATION).isPresent()) return attribute;
    String name = attribute.require(ATTRIBUTE_NAME).textValue();
    Ttlv value = attribute.require(ATTRIBUTE_VALUE);
    Optional<Ttlv> index = attribute.child(ATTRIBUTE_INDEX);
    if (index.isPresent() && index.get().intValue() != 0)
      throw new IllegalArgumentException(
          "AttributeIndex was removed in KMIP 2.0; use CurrentAttribute for value selection");
    Optional<String[]> custom = custom(name);
    if (custom.isPresent()) return vendor(custom.get()[0], custom.get()[1], value);
    Tag tag = standard(name);
    if (version == ProtocolVersion.V3_0 && tag == NAME && value.type() == Ttlv.Type.STRUCTURE)
      return text(NAME, value.require(NAME_VALUE).textValue());
    if (version == ProtocolVersion.V3_0 && tag == LINK && value.type() == Ttlv.Type.STRUCTURE) {
      Optional<Tag> typed = linkAttribute(value.require(LINK_TYPE).intValue());
      // An object's identifier, so a Reference in 3.0, as Unique Identifier is.
      if (typed.isPresent())
        return Ttlv.reference(typed.get(), value.require(LINKED_OBJECT_IDENTIFIER).textValue());
    }
    return value.retag(tag);
  }

  /**
   * The KMIP 3.0 draft's attribute for a link of the Link Type {@code linkType} (its wire code):
   * 3.0 has no Link structure, and gives each link type an attribute of its own whose value is the
   * linked object's identifier, a Reference (Replaced Object Link, Public Key Link, ...). Empty for a type the
   * draft has no attribute for. {@link #fromLegacy} converts a 1.x/2.x Link this way on 3.0.
   */
  public static Optional<Tag> linkAttribute(int linkType) {
    return Optional.ofNullable(LINK_ATTRIBUTES.get(linkType));
  }

  private static final Map<Integer, Tag> LINK_ATTRIBUTES = linkAttributes();

  private static Map<Integer, Tag> linkAttributes() {
    Map<Integer, Tag> tags = new HashMap<>();
    for (Enums.LinkType t : Enums.LinkType.values()) {
      // The draft renames two of them.
      String name =
          switch (t) {
            case DERIVATION_BASE_OBJECT_LINK -> "DerivationObjectLink";
            case DERIVED_KEY_LINK -> "DerivedObjectLink";
            default -> t.wireName();
          };
      try {
        Tag tag = Tag.fromName(name);
        if (tag.definedIn(ProtocolVersion.V3_0)) tags.put(t.code(), tag);
      } catch (IllegalArgumentException none) {
        // no 3.0 attribute for this type
      }
    }
    return Map.copyOf(tags);
  }

  /**
   * The 2.x/3.0 Attribute Reference for a 1.x Attribute Name: the standard attribute's tag, or a
   * vendor reference for an {@code x-}/{@code y-} custom name.
   */
  public static Ttlv referenceFromLegacy(String name) {
    Optional<String[]> custom = custom(name);
    if (custom.isPresent()) return vendorReference(custom.get()[0], custom.get()[1]);
    return reference(standard(name));
  }

  private static Optional<String[]> custom(String name) {
    if (name.length() > 2 && (name.startsWith("x-") || name.startsWith("y-")))
      return Optional.of(new String[] {name.substring(0, 1), name.substring(2)});
    return Optional.empty();
  }

  private static Tag standard(String name) {
    try {
      return Tag.fromName(name);
    } catch (IllegalArgumentException e) {
      throw new IllegalArgumentException(
          "Not a standard attribute or an x-/y- custom attribute name: " + name, e);
    }
  }
}
