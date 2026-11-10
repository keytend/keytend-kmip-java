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

package dev.keytend.kmip.codec;

import dev.keytend.kmip.model.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.time.*;
import java.util.*;

/** Shared XML/JSON scalar and symbolic enumeration mapping. */
final class TextValues {
  private TextValues() {}

  private static final Map<String, Map<String, Integer>> ENUMS = load();

  private static Map<String, Map<String, Integer>> load() {
    Map<String, Map<String, Integer>> groups = new HashMap<>();
    // A name that stands for different values in one group is not a usable symbolic name and must
    // not decode to either.
    Set<String> ambiguous = new HashSet<>();
    try (InputStream in =
        TextValues.class.getResourceAsStream("/dev/keytend/kmip/enumerations.tsv")) {
      if (in == null) throw new IOException("Missing enumeration registry");
      for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
        String[] cols = line.split("\t");
        String groupName = Tag.normalize(cols[0]);
        Map<String, Integer> group = groups.computeIfAbsent(groupName, ignored -> new HashMap<>());
        int value = (int) Long.parseLong(cols[2]);
        String name = Tag.normalize(cols[1]);
        List<String> names = new ArrayList<>(List.of(name));
        // OASIS vectors also use the abbreviated RSA signature names without the parenthesized PKCS
        // qualifier.
        if (name.endsWith("pkcs1v15")) names.add(name.substring(0, name.length() - 8));
        for (String n : names) {
          // "Reserved" marks an unassigned or withdrawn value (Object Type 6 from 2.0, Certificate
          // Request Type 4, ...); it is never a symbolic name, even where only one value has it.
          if (n.equals("reserved")) continue;
          Integer prior = group.put(n, value);
          if (prior != null && prior != value) ambiguous.add(groupName + ":" + n);
        }
      }
    } catch (IOException e) {
      throw new ExceptionInInitializerError(e);
    }
    for (String entry : ambiguous) {
      String[] parts = entry.split(":", 2);
      groups.get(parts[0]).remove(parts[1]);
    }
    groups
        .computeIfAbsent("pkcs11function", ignored -> new HashMap<>())
        .putAll(Map.of("cinitialize", 1, "cfinalize", 2, "cgetinfo", 3));
    groups.computeIfAbsent("pkcs11returncode", ignored -> new HashMap<>()).put("ok", 0);
    return groups;
  }

  /**
   * An input problem whose message is fixed text (tag and type names at most, never input values),
   * so the codecs may pass it on in a {@link DecodeException}. Any other exception raised while
   * decoding is reported without its message.
   */
  static final class Malformed extends IllegalArgumentException {
    private static final long serialVersionUID = 1L;

    Malformed(String message) {
      super(message);
    }
  }

  /** The message of a {@link Malformed}, or nothing for exceptions whose text may echo input. */
  static String detail(Throwable e) {
    return e instanceof Malformed ? ": " + e.getMessage() : "";
  }

  static int tag(String name) {
    if (name == null) throw new Malformed("Missing tag");
    if (name.startsWith("0x")) {
      return (int) unsignedHex(name.substring(2), 24, "tag");
    }
    try {
      return Tag.fromName(name).code();
    } catch (IllegalArgumentException unknown) {
      throw new Malformed("Unknown tag name");
    }
  }

  static Ttlv.Type type(String name) {
    if (name == null) throw new Malformed("Missing type");
    return Arrays.stream(Ttlv.Type.values())
        .filter(t -> Tag.normalize(t.name()).equals(Tag.normalize(name)))
        .findFirst()
        .orElseThrow(() -> new Malformed("Unknown TTLV type name"));
  }

  static String typeName(Ttlv.Type type) {
    return switch (type) {
      case STRUCTURE -> "Structure";
      case INTEGER -> "Integer";
      case LONG_INTEGER -> "LongInteger";
      case BIG_INTEGER -> "BigInteger";
      case ENUMERATION -> "Enumeration";
      case BOOLEAN -> "Boolean";
      case TEXT_STRING -> "TextString";
      case BYTE_STRING -> "ByteString";
      case DATE_TIME -> "DateTime";
      case INTERVAL -> "Interval";
      case DATE_TIME_EXTENDED -> "DateTimeExtended";
      case IDENTIFIER -> "Identifier";
      case REFERENCE -> "Reference";
      case NAME_REFERENCE -> "NameReference";
    };
  }

  static String group(int tag, String attributeName) {
    String name =
        tag == Tag.ATTRIBUTE_VALUE.code() && attributeName != null
            ? attributeName
            : Tag.fromCode(tag).map(Tag::wireName).orElse("");
    return switch (Tag.normalize(name)) {
      case "batcherrorcontinuationoption" -> "BatchErrorContinuation";
      case "objectgroupmember" -> "ObjectGroupMemberOption";
      case "maskgeneratorhashingalgorithm" -> "HashingAlgorithm";
      case "profileinformation", "profilename" -> "ProfileNameType";
      case "destroyaction" -> "DestroyActionType";
      case "fips186variant" -> "FIPS186Variation";
      default -> name;
    };
  }

  /** Mask-typed Integers (Cryptographic Usage Mask, Storage Status Mask, ...) take name lists. */
  static boolean maskGroup(String group) {
    return Tag.normalize(group).endsWith("mask");
  }

  /**
   * A KMIP Integer (signed 32-bit, xsd:int). Hex may use the 32-bit two's-complement form. For
   * mask tags the text may be a list of component names or numbers separated by whitespace or
   * {@code |} (KMIP Profiles 2.1 §5.4.1.6.4 / §5.5.1.6.4); an empty list is 0.
   */
  static int integerValue(String text, String group) {
    if (maskGroup(group)) {
      String trimmed = text.trim();
      if (trimmed.isEmpty()) return 0;
      int result = 0;
      // Limit -1 keeps trailing empty components, so "Encrypt|" is rejected like "|Encrypt".
      for (String part : trimmed.split("\\s*\\|\\s*|\\s+", -1)) {
        if (part.isEmpty()) throw new Malformed("Empty component in " + label(group) + " list");
        result |= scalarInt(part, group, true);
      }
      return result;
    }
    return scalarInt(text, group, true);
  }

  /** A KMIP Enumeration (unsigned 32-bit): hex, a decimal in [0, 2^32), or a symbolic name. */
  static int enumerationValue(String text, String group) {
    return scalarInt(text, group, false);
  }

  private static int scalarInt(String text, String group, boolean signed) {
    String kind = signed ? "Integer" : "Enumeration";
    if (text.startsWith("0x")) return (int) unsignedHex(text.substring(2), 32, kind);
    if (numeric(text)) {
      long n = decimal(text, kind);
      if (signed ? n < Integer.MIN_VALUE || n > Integer.MAX_VALUE : n < 0 || n > 0xffff_ffffL)
        throw new Malformed(kind + " out of range for " + label(group));
      return (int) n;
    }
    if (Tag.normalize(group).equals("attributereference")) {
      try {
        return Tag.fromName(text).code();
      } catch (IllegalArgumentException unknown) {
        throw new Malformed("Unknown AttributeReference tag name");
      }
    }
    Integer n = ENUMS.getOrDefault(Tag.normalize(group), Map.of()).get(Tag.normalize(text));
    if (n == null) throw new Malformed("Unknown symbolic value for " + label(group));
    return n;
  }

  /**
   * A group name safe to print: standard enumeration groups and tags only, since the group can
   * come from a peer-supplied Attribute Name.
   */
  private static String label(String group) {
    if (ENUMS.containsKey(Tag.normalize(group))) return group;
    try {
      return Tag.fromName(group).wireName();
    } catch (IllegalArgumentException notStandard) {
      return "a custom attribute";
    }
  }

  /** Starts like a decimal number: an ASCII digit, or '-' (no '+', no non-ASCII digits). */
  private static boolean numeric(String text) {
    return !text.isEmpty()
        && ((text.charAt(0) >= '0' && text.charAt(0) <= '9') || text.charAt(0) == '-');
  }

  /**
   * Strict unsigned hex: one or more ASCII hex digits (no sign, no other Unicode digits) with at
   * most {@code bits} significant bits. The result is the bit pattern, so a 64-bit value may be
   * negative.
   */
  static long unsignedHex(String digits, int bits, String kind) {
    if (digits.isEmpty()) throw new Malformed("Empty hex " + kind);
    long n = 0;
    for (int i = 0; i < digits.length(); i++) {
      int d = hexDigit(digits.charAt(i));
      if (d < 0) throw new Malformed("Invalid hex digit in " + kind);
      if ((n >>> (bits - 4)) != 0) throw new Malformed(kind + " exceeds " + bits + " bits");
      n = (n << 4) | d;
    }
    return n;
  }

  private static int hexDigit(char c) {
    return c >= '0' && c <= '9'
        ? c - '0'
        : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1;
  }

  /** Strict signed decimal: optional '-', then one or more ASCII digits, within a long. */
  static long decimal(String text, String kind) {
    int start = text.startsWith("-") ? 1 : 0;
    if (start == text.length()) throw new Malformed("Invalid decimal " + kind);
    long n = 0;
    try {
      for (int i = start; i < text.length(); i++) {
        char c = text.charAt(i);
        if (c < '0' || c > '9') throw new Malformed("Invalid decimal " + kind);
        // Accumulate negatively so that Long.MIN_VALUE is reachable.
        n = Math.subtractExact(Math.multiplyExact(n, 10), c - '0');
      }
      return start == 1 ? n : Math.negateExact(n);
    } catch (ArithmeticException overflow) {
      throw new Malformed(kind + " exceeds 64 bits");
    }
  }

  /** Strict ASCII hex bytes; on failure the partial output is wiped. */
  static byte[] hexBytes(String text, String kind) {
    if (text.length() % 2 != 0) throw new Malformed("Odd-length hex " + kind);
    byte[] out = new byte[text.length() / 2];
    for (int i = 0; i < out.length; i++) {
      int hi = hexDigit(text.charAt(2 * i)), lo = hexDigit(text.charAt(2 * i + 1));
      if (hi < 0 || lo < 0) {
        Arrays.fill(out, (byte) 0);
        throw new Malformed("Invalid hex digit in " + kind);
      }
      out[i] = (byte) (hi << 4 | lo);
    }
    return out;
  }

  /** Text DateTime range that xsd:dateTime and the JSON profile pattern can express. */
  private static final long FIRST_ISO_SECOND = -62135596800L, LAST_ISO_SECOND = 253402300799L;

  /**
   * ISO-8601 for years 0001-9999; otherwise the fixed-width hex form, which both profiles allow and
   * which never produces a leading '+'.
   */
  static String dateTimeText(long seconds) {
    if (seconds < FIRST_ISO_SECOND || seconds > LAST_ISO_SECOND)
      return String.format("0x%016X", seconds);
    return Instant.ofEpochSecond(seconds).toString();
  }

  /** Decimal microseconds (xsd:long), hex, or (leniently) ISO-8601 text with whole microseconds. */
  static long dateTimeExtended(String text) {
    if (text.startsWith("0x")) return longValue(text);
    if (numeric(text) && text.indexOf('T') < 0 && text.indexOf(':') < 0)
      return decimal(text, "DateTimeExtended");
    Instant instant = isoDateTime(text, "DateTimeExtended").toInstant();
    if (instant.getNano() % 1000 != 0)
      throw new Malformed("DateTimeExtended has microsecond precision");
    return Math.addExact(
        Math.multiplyExact(instant.getEpochSecond(), 1_000_000L), instant.getNano() / 1000);
  }

  /** Hex or ISO-8601 text; KMIP DateTime has whole seconds, so a fraction other than 0 fails. */
  static long dateTime(String text) {
    if (text.startsWith("0x")) return longValue(text);
    OffsetDateTime time = isoDateTime(text, "DateTime");
    if (time.getNano() != 0) throw new Malformed("DateTime has second precision");
    return time.toEpochSecond();
  }

  private static OffsetDateTime isoDateTime(String text, String kind) {
    // ISO-8601 digits are ASCII; the JDK parser would also accept other Unicode digits.
    for (int i = 0; i < text.length(); i++)
      if (text.charAt(i) > 0x7f) throw new Malformed("Invalid " + kind);
    try {
      return OffsetDateTime.parse(text);
    } catch (DateTimeException e) {
      throw new Malformed("Invalid " + kind);
    }
  }

  /** A 64-bit value: strict hex (the two's-complement bit pattern) or a strict signed decimal. */
  static long longValue(String text) {
    return text.startsWith("0x")
        ? unsignedHex(text.substring(2), 64, "LongInteger")
        : decimal(text, "LongInteger");
  }

  static Ttlv scalar(int tag, Ttlv.Type type, String text, String attributeName) {
    String group = group(tag, attributeName);
    Object value =
        switch (type) {
          case INTEGER -> integerValue(text, group);
          case ENUMERATION -> enumerationValue(text, group);
          case LONG_INTEGER, INTERVAL -> longValue(text);
          case BIG_INTEGER -> {
            byte[] bytes = hexBytes(text.startsWith("0x") ? text.substring(2) : text, "BigInteger");
            if (bytes.length == 0) throw new Malformed("Empty BigInteger");
            try {
              yield new BigInteger(bytes);
            } finally {
              Arrays.fill(bytes, (byte) 0);
            }
          }
          case BOOLEAN -> {
            if (text.equals("true") || text.equals("1") || text.equals("0x0000000000000001"))
              yield true;
            if (text.equals("false") || text.equals("0") || text.equals("0x0000000000000000"))
              yield false;
            throw new Malformed("Invalid Boolean");
          }
          case TEXT_STRING, IDENTIFIER, REFERENCE, NAME_REFERENCE -> text;
          case BYTE_STRING -> hexBytes(text, "ByteString");
          case DATE_TIME_EXTENDED -> dateTimeExtended(text);
          case DATE_TIME -> dateTime(text);
          case STRUCTURE -> throw new Malformed("Expected scalar");
        };
    try {
      return Ttlv.of(tag, type, value);
    } finally {
      // Ttlv keeps its own copy of a Byte String; wipe the decoded one.
      if (value instanceof byte[] bytes) Arrays.fill(bytes, (byte) 0);
    }
  }

  static String bigInteger(Ttlv n) {
    byte[] bytes = n.bigIntegerValue().toByteArray();
    int size = (bytes.length + 7) & ~7;
    byte[] padded = new byte[size];
    if (bytes[0] < 0) Arrays.fill(padded, (byte) 0xff);
    System.arraycopy(bytes, 0, padded, size - bytes.length, bytes.length);
    return HexFormat.of().formatHex(padded);
  }

  static String scalarText(Ttlv n) {
    return switch (n.type()) {
      case INTEGER -> Integer.toString(n.intValue());
      case ENUMERATION -> String.format("0x%08X", n.intValue());
      case LONG_INTEGER, INTERVAL -> Long.toString(n.longValue());
      case BIG_INTEGER -> bigInteger(n);
      case BOOLEAN -> Boolean.toString(n.booleanValue());
      case TEXT_STRING, IDENTIFIER, REFERENCE, NAME_REFERENCE -> n.textValue();
      case BYTE_STRING -> HexFormat.of().formatHex(n.bytesValue());
      case DATE_TIME -> dateTimeText(n.longValue());
      // KMIP Profiles 2.0 §5.4.1.6.13: DateTimeExtended is xsd:long microseconds.
      case DATE_TIME_EXTENDED -> Long.toString(n.longValue());
      case STRUCTURE -> throw new IllegalArgumentException("Expected scalar");
    };
  }
}
