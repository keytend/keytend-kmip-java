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
 * A typed Import (KMIP 1.4+) that restores an object from an Export response. Import restores an
 * object with its identifier and complete attributes; it is not a Register with a chosen ID (KMIP
 * 1.4 §4.41, 2.1 §6.1.25). The attributes are copied in the export's own form: repeated Attribute
 * fields for 1.4, one Attributes structure for 2.x and 3.0. Send the import with the same major
 * version that produced the export.
 *
 * @since 0.10.0
 */
public final class ImportRequest {
  private ImportRequest() {}

  /**
   * An Import request that restores the exported object under its exported identifier.
   *
   * @param exportPayload the Response Payload of a successful Export
   * @param replaceExisting whether an existing object with the same identifier is replaced
   * @return the Import request
   * @throws IllegalArgumentException when {@code exportPayload} is not a Response Payload, or has
   *     no Unique Identifier, Object Type or managed object
   */
  public static Request restore(Ttlv exportPayload, boolean replaceExisting) {
    return restoreAs(exportPayload, null, replaceExisting);
  }

  /**
   * An Import request that restores the exported object under {@code identifier}. A null or
   * unchanged identifier sends the exported attributes as they are. With a different identifier,
   * an exported Unique Identifier attribute is sent with that identifier. An exported Short Unique
   * Identifier (KMIP 2.0 and later) is sent as the SHA-256 of the new identifier's UTF-8 bytes.
   * Other attributes are sent as exported, and none is added.
   *
   * <p>The hash is the form KMIP 2.1 §4.56 recommends. It differs from the exported object's, which
   * may still exist.
   *
   * @param exportPayload the Response Payload of a successful Export
   * @param identifier the identifier to restore under; null keeps the exported one
   * @param replaceExisting whether an existing object with that identifier is replaced
   * @return the Import request
   * @throws IllegalArgumentException when {@code exportPayload} is not a Response Payload, or has
   *     no Unique Identifier, Object Type or managed object
   */
  public static Request restoreAs(Ttlv exportPayload, String identifier, boolean replaceExisting) {
    return restoreAs(exportPayload, identifier, replaceExisting, null);
  }

  /**
   * {@link #restoreAs(Ttlv, String, boolean)} with a Key Wrap Type (KMIP 1.4 §4.41). {@link
   * Enums.KeyWrapType#NOT_WRAPPED} asks the server to unwrap a wrapped object before storing it,
   * and to fail if it cannot. {@link Enums.KeyWrapType#AS_REGISTERED} asks it to store the object
   * as provided.
   *
   * @param exportPayload the Response Payload of a successful Export
   * @param identifier the identifier to restore under; null keeps the exported one
   * @param replaceExisting whether an existing object with that identifier is replaced
   * @param keyWrapType the Key Wrap Type; null omits the field, which servers treat as storing the
   *     object as provided
   * @return the Import request
   * @throws IllegalArgumentException when {@code exportPayload} is not a Response Payload, or has
   *     no Unique Identifier, Object Type or managed object
   */
  public static Request restoreAs(
      Ttlv exportPayload,
      String identifier,
      boolean replaceExisting,
      Enums.KeyWrapType keyWrapType) {
    if (exportPayload.tag() != RESPONSE_PAYLOAD.code())
      throw new IllegalArgumentException("Expected an Export ResponsePayload");
    Request.Builder b =
        Requests.importObject()
            .add(
                identifier == null
                    ? exportPayload.require(UNIQUE_IDENTIFIER)
                    : text(UNIQUE_IDENTIFIER, identifier),
                exportPayload.require(OBJECT_TYPE),
                bool(REPLACE_EXISTING, replaceExisting));
    if (keyWrapType != null) b.add(enumeration(KEY_WRAP_TYPE, keyWrapType));
    Identity identity =
        identifier == null
                || identifier.equals(exportPayload.require(UNIQUE_IDENTIFIER).textValue())
            ? null
            : new Identity(identifier);
    Ttlv object = null;
    for (Ttlv field : exportPayload.children()) {
      if (field.tag() == ATTRIBUTE.code())
        b.add(identity == null ? field : identity.attribute(field));
      else if (field.tag() == ATTRIBUTES.code())
        b.add(
            identity == null
                ? field
                : structure(ATTRIBUTES, field.children().stream().map(identity::modern).toList()));
      else if (field.tag() == TEMPLATE_ATTRIBUTE.code())
        b.add(
            field.children().stream()
                .map(a -> identity == null ? a : identity.attribute(a))
                .toArray(Ttlv[]::new));
      else if (isObject(field)) object = field;
    }
    if (object == null) throw new IllegalArgumentException("Export payload has no managed object");
    return b.add(object).build();
  }

  /**
   * The attributes that name an object, rewritten for a new identifier: Unique Identifier becomes
   * the new identifier and Short Unique Identifier its SHA-256 (KMIP 2.1 §4.56).
   */
  private record Identity(String value) {
    byte[] shortIdentifier() {
      try {
        return java.security.MessageDigest.getInstance("SHA-256")
            .digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      } catch (java.security.NoSuchAlgorithmException e) {
        throw new IllegalStateException("SHA-256 is required of every Java platform", e);
      }
    }

    /** A 2.x or 3.0 attribute inside Attributes. */
    Ttlv modern(Ttlv a) {
      if (a.tag() == UNIQUE_IDENTIFIER.code())
        return a.type() == Ttlv.Type.IDENTIFIER
            ? identifier(UNIQUE_IDENTIFIER, value)
            : text(UNIQUE_IDENTIFIER, value);
      if (a.tag() == SHORT_UNIQUE_IDENTIFIER.code())
        return bytes(SHORT_UNIQUE_IDENTIFIER, shortIdentifier());
      return a;
    }

    /** A 1.x Attribute (name, optional index, value). */
    Ttlv attribute(Ttlv a) {
      if (a.tag() != ATTRIBUTE.code()) return a;
      String name = a.child(ATTRIBUTE_NAME).map(n -> Tag.normalize(n.textValue())).orElse("");
      Ttlv replacement;
      if (name.equals("uniqueidentifier")) replacement = text(ATTRIBUTE_VALUE, value);
      else if (name.equals("shortuniqueidentifier"))
        replacement = bytes(ATTRIBUTE_VALUE, shortIdentifier());
      else return a;
      return structure(
          ATTRIBUTE,
          a.children().stream()
              .map(c -> c.tag() == ATTRIBUTE_VALUE.code() ? replacement : c)
              .toList());
    }
  }

  private static boolean isObject(Ttlv field) {
    try {
      ManagedObjects.objectType(field);
      return true;
    } catch (IllegalArgumentException notAnObject) {
      return false;
    }
  }
}
