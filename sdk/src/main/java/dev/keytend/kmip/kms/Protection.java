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

import static dev.keytend.kmip.model.Ttlv.bool;

import dev.keytend.kmip.model.*;
import java.util.*;

/**
 * The KMIP Extractable and Sensitive attributes a caller asked for (KMIP 1.4 §3.50 and §3.48, 2.1
 * §4.23 and §4.55); null where it asked nothing. Both came with KMIP 1.4: below it a request for
 * either is refused before anything is sent, never dropped. What was asked is checked against what
 * the server then states ({@link #differences}): an attribute the server does not state, or states
 * otherwise, is a difference, so the protection is never taken on trust or silently weakened.
 */
record Protection(Boolean extractable, Boolean sensitive) {
  static final Protection NONE = new Protection(null, null);

  boolean any() {
    return extractable != null || sensitive != null;
  }

  /**
   * Refuses a protection below KMIP 1.4, which has neither attribute, before anything is sent:
   * {@link UnsupportedException} naming {@code operation}.
   */
  void require(ProtocolVersion version, String operation) {
    if (!any() || version.atLeast(ProtocolVersion.V1_4)) return;
    throw new UnsupportedException(
        operation
            + ": "
            + this
            + " needs KMIP 1.4 or later (the Extractable and Sensitive attributes came"
            + " with 1.4); this connection uses KMIP "
            + version
            + ", which cannot express it, so nothing was"
            + " sent. Leave it out only if the key's protection is provisioned on the server some other way",
        null,
        operation,
        null,
        null,
        null);
  }

  /** The attributes to send (1.x form; later versions convert them). */
  List<Ttlv> attributes() {
    List<Ttlv> a = new ArrayList<>();
    if (extractable != null)
      a.add(Attributes.attribute("Extractable", bool(Tag.EXTRACTABLE, extractable)));
    if (sensitive != null) a.add(Attributes.attribute("Sensitive", bool(Tag.SENSITIVE, sensitive)));
    return a;
  }

  /**
   * How {@code a} differs from this protection: each attribute asked for that the server does not
   * state, or states otherwise. Empty when it matches.
   */
  List<String> differences(KeyAttributes a) {
    List<String> out = new ArrayList<>();
    difference(out, "Extractable", extractable, a.extractable());
    difference(out, "Sensitive", sensitive, a.sensitive());
    return out;
  }

  private static void difference(
      List<String> out, String name, Boolean asked, Optional<Boolean> stated) {
    if (asked == null) return;
    if (stated.isEmpty())
      out.add(
          "the server does not state its "
              + name
              + " attribute, so "
              + name
              + " "
              + asked
              + " cannot be confirmed");
    else if (!stated.get().equals(asked))
      out.add("its " + name + " is " + stated.get() + ", not " + asked);
  }

  /**
   * This protection, with what it leaves unset taken from {@code old} where {@code old} is protected:
   * Extractable false, Sensitive true. What a replacement must keep (KMIP's Re-key copies both), and
   * what a new key made in its place is given. KMIP's defaults (Extractable true, Sensitive false)
   * are not carried: they are what the server gives anyway.
   */
  Protection keeping(KeyAttributes old) {
    Boolean x = extractable, s = sensitive;
    if (x == null && old.extractable().equals(Optional.of(false))) x = false;
    if (s == null && old.sensitive().equals(Optional.of(true))) s = true;
    return new Protection(x, s);
  }

  @Override
  public String toString() {
    List<String> parts = new ArrayList<>();
    if (extractable != null) parts.add("Extractable " + extractable);
    if (sensitive != null) parts.add("Sensitive " + sensitive);
    return parts.isEmpty() ? "no protection" : String.join(" and ", parts);
  }
}
