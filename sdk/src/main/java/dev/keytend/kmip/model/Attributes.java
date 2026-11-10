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
 * Builds attributes in the KMIP 1.x form: Attribute structures and the Template-Attribute that
 * carries them.
 *
 * <pre>{@code
 * Ttlv template = Attributes.template(
 *     Attributes.name("invoices-kek"),
 *     Attributes.usage(
 *         Enums.CryptographicUsageMask.ENCRYPT, Enums.CryptographicUsageMask.DECRYPT));
 * }</pre>
 *
 * <p>Requests sent through {@code KmipClient} convert this form to the KMIP 2.x form ({@link
 * ModernAttributes}) when the client's version needs it. An Attribute Index has no 2.x form: at
 * 2.x, select a value with {@link ModernAttributes} instead.
 *
 * @since 0.10.0
 */
public final class Attributes {
  private Attributes() {}

  /**
   * An Attribute with no index.
   *
   * @param name the attribute name, for example "Cryptographic Algorithm" or "x-Owner"
   * @param value the value; it is retagged as Attribute Value
   * @return the Attribute structure
   */
  public static Ttlv attribute(String name, Ttlv value) {
    return attribute(name, null, value);
  }

  /**
   * An Attribute with an Attribute Index, which selects one instance of a multivalued attribute.
   *
   * @param name the attribute name
   * @param index the Attribute Index; null for none
   * @param value the value; it is retagged as Attribute Value
   * @return the Attribute structure
   * @throws IllegalArgumentException if {@code index} is negative
   */
  public static Ttlv attribute(String name, Integer index, Ttlv value) {
    List<Ttlv> children = new ArrayList<>();
    children.add(text(ATTRIBUTE_NAME, name));
    if (index != null) {
      if (index < 0) throw new IllegalArgumentException("Negative attribute index");
      children.add(integer(ATTRIBUTE_INDEX, index));
    }
    children.add(value.retag(ATTRIBUTE_VALUE));
    return structure(ATTRIBUTE, children);
  }

  /**
   * A Template-Attribute structure holding {@code attributes}.
   *
   * @param attributes the Attribute structures
   * @return the Template-Attribute
   */
  public static Ttlv template(Ttlv... attributes) {
    return structure(TEMPLATE_ATTRIBUTE, attributes);
  }

  /**
   * A Name attribute of type Uninterpreted Text String.
   *
   * @param name the name
   * @return the Attribute structure
   */
  public static Ttlv name(String name) {
    return attribute(
        "Name",
        structure(
            NAME,
            text(NAME_VALUE, name),
            enumeration(NAME_TYPE, Enums.NameType.UNINTERPRETED_TEXT_STRING)));
  }

  /**
   * A Cryptographic Algorithm attribute.
   *
   * @param algorithm the algorithm
   * @return the Attribute structure
   */
  public static Ttlv algorithm(Enums.CryptographicAlgorithm algorithm) {
    return attribute("Cryptographic Algorithm", enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm));
  }

  /**
   * A Cryptographic Length attribute.
   *
   * @param bits the length in bits
   * @return the Attribute structure
   * @throws IllegalArgumentException if {@code bits} is not positive
   */
  public static Ttlv length(int bits) {
    if (bits <= 0) throw new IllegalArgumentException("Invalid key size");
    return attribute("Cryptographic Length", integer(CRYPTOGRAPHIC_LENGTH, bits));
  }

  /**
   * A Cryptographic Usage Mask attribute with the given flags set.
   *
   * @param flags the usages
   * @return the Attribute structure
   */
  public static Ttlv usage(Enums.CryptographicUsageMask... flags) {
    return attribute("Cryptographic Usage Mask", integer(CRYPTOGRAPHIC_USAGE_MASK, mask(flags)));
  }

  /**
   * ORs mask flags of one group. Generated flags must come from a mask group (Cryptographic Usage
   * Mask, Storage Status Mask, Protection Storage Mask, ...) and all from the same one; vendor
   * {@link WireEnum} implementations are not checked.
   *
   * @param flags the flags
   * @return the mask; 0 for no flags
   * @throws IllegalArgumentException if a flag is not a mask flag, or flags come from different
   *     groups
   */
  public static int mask(WireEnum... flags) {
    int mask = 0;
    Class<?> group = null;
    for (WireEnum f : flags) {
      if (f.getClass().getEnclosingClass() == Enums.class) {
        if (!WireEnums.isMask(f.getClass().asSubclass(WireEnum.class)))
          throw new IllegalArgumentException(
              f.getClass().getSimpleName() + " is an enumeration, not a mask");
        if (group != null && group != f.getClass())
          throw new IllegalArgumentException("Mask flags from different groups");
        group = f.getClass();
      }
      mask |= f.code();
    }
    return mask;
  }

  /**
   * An attribute with a Text String value, for example a custom "x-" attribute.
   *
   * @param name the attribute name
   * @param value the value
   * @return the Attribute structure
   */
  public static Ttlv textAttribute(String name, String value) {
    return attribute(name, text(ATTRIBUTE_VALUE, value));
  }

  /**
   * An attribute with a Boolean value.
   *
   * @param name the attribute name
   * @param value the value
   * @return the Attribute structure
   */
  public static Ttlv booleanAttribute(String name, boolean value) {
    return attribute(name, bool(ATTRIBUTE_VALUE, value));
  }

  /**
   * A Link attribute to another object.
   *
   * @param type the Link Type
   * @param id the linked object's Unique Identifier
   * @return the Attribute structure
   */
  public static Ttlv link(Enums.LinkType type, String id) {
    return attribute(
        "Link", structure(LINK, enumeration(LINK_TYPE, type), text(LINKED_OBJECT_IDENTIFIER, id)));
  }
}
