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

package dev.keytend.kmip.cli;

import dev.keytend.kmip.kms.Algorithm;
import dev.keytend.kmip.kms.CustomAttribute;
import dev.keytend.kmip.kms.KeyAttributes;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmsException;
import dev.keytend.kmip.kms.LineageKey;
import dev.keytend.kmip.kms.Link;
import dev.keytend.kmip.kms.ObjectKind;
import java.io.PrintStream;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * How objects, attributes and lineages are shown, as text and as JSON. Text from the server is
 * escaped for the terminal ({@link Values#safe}) where it is printed: in {@link #text}, {@link
 * #summary} and {@link Table}.
 */
final class Render {
  /** What an unset date shows as in text. */
  static final String UNSET = "n/a";

  private Render() {}

  /**
   * The algorithm and length, for example {@code AES-256}; an algorithm this API does not name
   * shows as {@code OTHER(0x...)} with its code.
   *
   * @param a the attributes
   * @return the text, or {@link #UNSET}
   */
  static String cipher(KeyAttributes a) {
    Optional<Algorithm> algorithm = a.algorithm();
    if (algorithm.isEmpty()) return UNSET;
    String name =
        algorithm.get() == Algorithm.OTHER
            ? String.format(Locale.ROOT, "OTHER(0x%08X)", a.rawAlgorithm())
            : algorithm.get().name();
    return a.length().isPresent() ? name + "-" + a.length().getAsInt() : name;
  }

  /** The kind for people, with its code when this API does not name it. */
  static String kind(KeyAttributes a) {
    return Values.title(a.kind(), a.kind() == ObjectKind.OTHER, a.rawObjectType());
  }

  /** The state for people, with its code when this API does not name it. */
  static String state(KeyAttributes a) {
    return Values.title(a.state(), a.state() == KeyState.UNKNOWN, a.rawState());
  }

  static String date(Optional<Instant> date) {
    return date.map(Instant::toString).orElse(UNSET);
  }

  static String names(KeyAttributes a) {
    return a.names().isEmpty() ? "" : String.join(", ", a.names());
  }

  static String usages(KeyAttributes a) {
    return a.usages().stream().map(Values::token).collect(Collectors.joining(", "));
  }

  static String custom(KeyAttributes a) {
    return a.custom().entrySet().stream()
        .map(e -> e.getKey() + "=" + Values.text(e.getValue()))
        .collect(Collectors.joining(", "));
  }

  static String links(KeyAttributes a) {
    List<String> out = new ArrayList<>();
    for (Link l : a.links())
      out.add(
          (l.kind() == null ? "link " + l.rawType() : Values.token(l.kind()))
              + " -> "
              + l.targetId());
    return String.join(", ", out);
  }

  /**
   * The Lease Time, or what is wrong with it.
   *
   * @param a the attributes
   * @return the time, empty when unset; or the error for a malformed one
   */
  private static Lease lease(KeyAttributes a) {
    try {
      return new Lease(a.leaseTime().orElse(null), null);
    } catch (KmsException malformed) {
      return new Lease(null, malformed.getMessage());
    }
  }

  private record Lease(Duration time, String error) {}

  /**
   * Every modeled attribute as JSON, with the raw protocol codes beside the named values; unset
   * dates are null.
   *
   * @param a the attributes
   * @return the map, in a fixed order
   */
  static Map<String, Object> json(KeyAttributes a) {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("id", a.id());
    m.put("kind", Values.token(a.kind()));
    m.put("rawObjectType", a.rawObjectType());
    m.put("state", Values.token(a.state()));
    m.put("rawState", a.rawState());
    m.put("names", a.names());
    m.put("algorithm", a.algorithm().map(Enum::name).orElse(null));
    m.put("rawAlgorithm", a.rawAlgorithm());
    m.put("length", a.length().isPresent() ? Integer.valueOf(a.length().getAsInt()) : null);
    m.put("usages", a.usages().stream().map(Values::token).toList());
    m.put("rawUsageMask", a.rawUsageMask());
    m.put("creationDate", a.creationDate().orElse(null));
    m.put("activationDate", a.activationDate().orElse(null));
    m.put("processStartDate", a.processStartDate().orElse(null));
    m.put("protectStopDate", a.protectStopDate().orElse(null));
    m.put("deactivationDate", a.deactivationDate().orElse(null));
    m.put("compromiseOccurrenceDate", a.compromiseOccurrenceDate().orElse(null));
    m.put("compromiseDate", a.compromiseDate().orElse(null));
    m.put("destroyDate", a.destroyDate().orElse(null));
    Lease lease = lease(a);
    m.put("leaseTime", lease.time() == null ? null : lease.time().toString());
    m.put("leaseTimeError", lease.error());
    m.put("objectGroups", a.groups());
    Map<String, Object> custom = new LinkedHashMap<>();
    for (Map.Entry<CustomAttribute, Object> e : a.custom().entrySet())
      custom.put(e.getKey().toString(), Values.json(e.getValue()));
    m.put("custom", custom);
    List<Map<String, Object>> links = new ArrayList<>();
    for (Link l : a.links()) {
      Map<String, Object> link = new LinkedHashMap<>();
      link.put("kind", l.kind() == null ? null : Values.token(l.kind()));
      link.put("rawType", l.rawType());
      link.put("target", l.targetId());
      links.add(link);
    }
    m.put("links", links);
    m.put("extractable", a.extractable().orElse(null));
    m.put("sensitive", a.sensitive().orElse(null));
    return m;
  }

  /**
   * The attributes as {@code label: value} lines, escaped for the terminal, then {@code more}.
   *
   * @param a the attributes
   * @param more more lines, aligned with the attributes
   * @param out where to print
   */
  static void text(KeyAttributes a, Map<String, String> more, PrintStream out) {
    Map<String, String> lines = new LinkedHashMap<>();
    lines.put("ID", a.id());
    lines.put("Kind", kind(a));
    lines.put("State", state(a));
    lines.put("Names", names(a));
    lines.put("Cipher", cipher(a));
    lines.put("Usages", usages(a));
    lines.put("Object groups", String.join(", ", a.groups()));
    lines.put("Custom", custom(a));
    lines.put("Creation date", date(a.creationDate()));
    lines.put("Activation date", date(a.activationDate()));
    lines.put("Process start date", date(a.processStartDate()));
    lines.put("Protect stop date", date(a.protectStopDate()));
    lines.put("Deactivation date", date(a.deactivationDate()));
    lines.put("Compromise occurred", date(a.compromiseOccurrenceDate()));
    lines.put("Compromise date", date(a.compromiseDate()));
    lines.put("Destroy date", date(a.destroyDate()));
    Lease lease = lease(a);
    lines.put(
        "Lease time",
        lease.error() != null
            ? "malformed: " + lease.error()
            : lease.time() == null ? UNSET : lease.time().toString());
    lines.put("Links", links(a));
    lines.put("Extractable", a.extractable().map(String::valueOf).orElse(UNSET));
    lines.put("Sensitive", a.sensitive().map(String::valueOf).orElse(UNSET));
    lines.putAll(more);
    labeled(lines, out);
  }

  /**
   * Prints {@code label: value} lines with the values aligned and escaped for the terminal; an
   * empty value prints as {@code -}.
   *
   * @param lines the labels and values, in order
   * @param out where to print
   */
  static void labeled(Map<String, String> lines, PrintStream out) {
    int width = lines.keySet().stream().mapToInt(String::length).max().orElse(0);
    for (Map.Entry<String, String> e : lines.entrySet())
      out.println(
          e.getKey()
              + ":"
              + " ".repeat(width - e.getKey().length() + 2)
              + (e.getValue() == null || e.getValue().isEmpty() ? "-" : Values.safe(e.getValue())));
  }

  /**
   * One line naming an object, for plans and confirmations, escaped for the terminal.
   *
   * @param a the attributes
   * @return for example {@code 12 (Symmetric Key AES-256, Active, names: orders-kek)}
   */
  static String summary(KeyAttributes a) {
    return Values.safe(
        a.id()
            + " ("
            + kind(a)
            + (a.algorithm().isPresent() ? " " + cipher(a) : "")
            + ", "
            + state(a)
            + (a.names().isEmpty() ? ", no name" : ", names: " + names(a))
            + ")");
  }

  static List<Map<String, Object>> lineageJson(List<LineageKey> lineage) {
    List<Map<String, Object>> out = new ArrayList<>();
    for (LineageKey k : lineage) {
      Map<String, Object> m = new LinkedHashMap<>();
      m.put("id", k.id());
      m.put("state", Values.token(k.attributes().state()));
      m.put("newest", k.newest());
      m.put("branch", k.branch());
      m.put("names", k.attributes().names());
      m.put("replaced", k.replaced());
      m.put("replacedBy", k.replacedBy());
      m.put("joinedInto", k.joinedInto());
      m.put("activationDate", k.attributes().activationDate().orElse(null));
      m.put("deactivationDate", k.attributes().deactivationDate().orElse(null));
      out.add(m);
    }
    return out;
  }

  static Table lineageTable(List<LineageKey> lineage) {
    Table t =
        new Table(
            "ID",
            "STATE",
            "NEWEST",
            "BRANCH",
            "REPLACED",
            "JOINED INTO",
            "NAMES",
            "ACTIVATION",
            "DEACTIVATION");
    for (LineageKey k : lineage) {
      KeyAttributes a = k.attributes();
      t.row(
          k.id(),
          state(a),
          k.newest() ? "yes" : "",
          k.branch() ? "yes" : "",
          String.join(", ", k.replaced()),
          String.join(", ", k.joinedInto()),
          names(a),
          date(a.activationDate()),
          date(a.deactivationDate()));
    }
    return t;
  }

  /**
   * Parses {@code NAME=VALUE} for a custom attribute: {@code x-NAME}, {@code y-NAME}, {@code
   * VENDOR:NAME}, or a bare {@code NAME} for {@code x-NAME}.
   *
   * @param text the option's value
   * @return the attribute and its value
   */
  static Map.Entry<CustomAttribute, String> customOption(String text) {
    int equals = text.indexOf('=');
    if (equals <= 0) throw CliException.usage("--custom: expected NAME=VALUE, got " + text);
    String name = text.substring(0, equals).trim();
    String value = text.substring(equals + 1);
    CustomAttribute attribute;
    int colon = name.indexOf(':');
    if (colon > 0 && colon < name.length() - 1) {
      attribute = new CustomAttribute(name.substring(0, colon), name.substring(colon + 1));
    } else if ((name.startsWith("x-") || name.startsWith("y-")) && name.length() > 2) {
      attribute = new CustomAttribute(name.substring(0, 1), name.substring(2));
    } else {
      attribute = CustomAttribute.client(name);
    }
    return Map.entry(attribute, value);
  }

  static KeyUsage[] usageOption(String text) {
    List<String> tokens = Values.list(text);
    if (tokens.isEmpty()) throw CliException.usage("--usage: give at least one usage");
    KeyUsage[] out = new KeyUsage[tokens.size()];
    for (int i = 0; i < out.length; i++)
      out[i] = Values.constant(KeyUsage.class, tokens.get(i), "--usage");
    return out;
  }
}
