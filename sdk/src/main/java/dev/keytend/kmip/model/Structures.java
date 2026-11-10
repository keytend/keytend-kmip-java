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

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Canonical field ordering from OASIS structure and payload tables.
 *
 * <p>Fields named in the version's table are placed in table order. Fields the table does not name
 * (vendor extensions, tags from another version) keep the positions they were supplied in. Key
 * Material and Credential Value have one table per Key Format Type or Credential Type; their order
 * is chosen from that discriminator (the enclosing Key Block's Key Format Type, or the Credential's
 * Credential Type). When the discriminator is absent or not a transparent/known variant, the
 * supplied order is kept unchanged.
 *
 * @since 0.10.0
 */
public final class Structures {
  private Structures() {}

  private static final Map<String, List<Integer>> ORDER = load();

  private static Map<String, List<Integer>> load() {
    Map<String, List<Integer>> order = new HashMap<>();
    try (InputStream in = Structures.class.getResourceAsStream("/dev/keytend/kmip/order.tsv")) {
      if (in == null) throw new IOException("Missing field order registry");
      for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
        String[] parts = line.split("\t");
        List<Integer> fields = new ArrayList<>();
        for (int i = 1; i < parts.length; i++) fields.add(Tag.fromName(parts[i]).code());
        order.put(parts[0], List.copyOf(fields));
      }
    } catch (IOException e) {
      throw new ExceptionInInitializerError(e);
    }
    return Map.copyOf(order);
  }

  public static Ttlv structure(Tag tag, Ttlv... fields) {
    return Ttlv.structure(tag, ordered(ORDER.get("14:" + tag.wireName()), List.of(fields)));
  }

  public static Ttlv requestPayload(Operation operation, List<Ttlv> fields) {
    return Ttlv.structure(
        Tag.REQUEST_PAYLOAD,
        ordered(ORDER.get("14:RequestPayload:" + operation.wireName()), fields));
  }

  public static Ttlv requestPayload(
      Operation operation, ProtocolVersion version, List<Ttlv> fields) {
    return Ttlv.structure(
        Tag.REQUEST_PAYLOAD,
        ordered(ORDER.get(version.code() + ":RequestPayload:" + operation.wireName()), fields));
  }

  /** Key Material for a transparent Key Format Type, in that format's table order. */
  public static Ttlv keyMaterial(Enums.KeyFormatType format, List<Ttlv> fields) {
    return Ttlv.structure(
        Tag.KEY_MATERIAL, ordered(variant(null, "KeyMaterial", format.wireName()), fields));
  }

  /** Credential Value for a Credential Type, in that type's table order. */
  public static Ttlv credentialValue(Enums.CredentialType type, List<Ttlv> fields) {
    return Ttlv.structure(
        Tag.CREDENTIAL_VALUE, ordered(variant(null, "CredentialValue", type.wireName()), fields));
  }

  public static Ttlv canonical(ProtocolVersion version, Ttlv node) {
    return canonical(version, node, null);
  }

  /**
   * @param variant the discriminator name for a polymorphic structure (Key Format Type for Key
   *     Material, Credential Type for Credential Value), or null when not known
   */
  private static Ttlv canonical(ProtocolVersion version, Ttlv node, String variant) {
    if (node.type() != Ttlv.Type.STRUCTURE) return node;
    String format = null, credential = null;
    if (node.tag() == Tag.KEY_BLOCK.code())
      format = discriminator(node, Tag.KEY_FORMAT_TYPE, Enums.KeyFormatType.values());
    if (node.tag() == Tag.CREDENTIAL.code())
      credential = discriminator(node, Tag.CREDENTIAL_TYPE, Enums.CredentialType.values());
    List<Ttlv> fields = new ArrayList<>();
    for (Ttlv child : node.children()) {
      String childVariant = null;
      if (format != null && child.tag() == Tag.KEY_VALUE.code()) childVariant = format;
      if (variant != null
          && node.tag() == Tag.KEY_VALUE.code()
          && child.tag() == Tag.KEY_MATERIAL.code()) childVariant = variant;
      if (credential != null && child.tag() == Tag.CREDENTIAL_VALUE.code())
        childVariant = credential;
      fields.add(canonical(version, child, childVariant));
    }
    List<Integer> order;
    if (node.tag() == Tag.KEY_MATERIAL.code())
      order = variant == null ? null : variant(version, "KeyMaterial", variant);
    else if (node.tag() == Tag.CREDENTIAL_VALUE.code())
      order = variant == null ? null : variant(version, "CredentialValue", variant);
    else order = ORDER.get(version.code() + ":" + node.tagName());
    return Ttlv.structure(node.tag(), ordered(order, fields));
  }

  private static String discriminator(Ttlv node, Tag tag, WireEnum[] values) {
    Optional<Ttlv> field = node.child(tag);
    if (field.isEmpty() || field.get().type() != Ttlv.Type.ENUMERATION) return null;
    int code = field.get().intValue();
    for (WireEnum value : values) if (value.code() == code) return value.wireName();
    return null;
  }

  /**
   * The variant's table in the requested version, or else in the newest version that defines it
   * (for example a deprecated 1.x EC format sent with a 2.x header). Null means "keep order".
   */
  private static List<Integer> variant(ProtocolVersion version, String parent, String variant) {
    if (version != null) {
      List<Integer> exact = ORDER.get(version.code() + ":" + parent + "@" + variant);
      if (exact != null) return exact;
    }
    ProtocolVersion[] versions = ProtocolVersion.values();
    for (int i = versions.length - 1; i >= 0; i--) {
      List<Integer> fallback = ORDER.get(versions[i].code() + ":" + parent + "@" + variant);
      if (fallback != null) return fallback;
    }
    return null;
  }

  /** Sorts table-listed fields into the slots they occupy; unlisted fields keep their slots. */
  private static List<Ttlv> ordered(List<Integer> order, List<Ttlv> fields) {
    List<Ttlv> copy = new ArrayList<>(fields);
    if (order == null || order.isEmpty()) return copy;
    List<Integer> slots = new ArrayList<>();
    List<Ttlv> listed = new ArrayList<>();
    for (int i = 0; i < copy.size(); i++)
      if (order.contains(copy.get(i).tag())) {
        slots.add(i);
        listed.add(copy.get(i));
      }
    listed.sort(Comparator.comparingInt(n -> order.indexOf(n.tag())));
    for (int i = 0; i < slots.size(); i++) copy.set(slots.get(i), listed.get(i));
    return copy;
  }
}
