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

import dev.keytend.kmip.kms.KmipVersion;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.DateTimeException;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Parsing and formatting of the values on the command line and in the configuration file. The
 * command line's options convert their values with these functions while it is parsed ({@link
 * Commands.Conversion}).
 */
final class Values {
  private static final Pattern SHORT_DURATION = Pattern.compile("(\\d+)(ms|s|m|h|d)");
  private static final Pattern LIST = Pattern.compile("\\s*,\\s*");
  private static final Pattern SHELL_SAFE = Pattern.compile("[A-Za-z0-9._:/@%+=,-]+");

  private Values() {}

  /**
   * A duration: {@code 30s}, {@code 15m}, {@code 12h}, {@code 30d}, {@code 500ms}, or ISO-8601
   * ({@code PT30S}, {@code P30D}).
   *
   * @param text the text
   * @param what what it is, for the error message
   * @return the duration, not negative
   */
  static Duration duration(String text, String what) {
    String t = text.trim();
    Duration d;
    Matcher m = SHORT_DURATION.matcher(t.toLowerCase(Locale.ROOT));
    try {
      if (m.matches()) {
        long n = Long.parseLong(m.group(1));
        d =
            switch (m.group(2)) {
              case "ms" -> Duration.ofMillis(n);
              case "s" -> Duration.ofSeconds(n);
              case "m" -> Duration.ofMinutes(n);
              case "h" -> Duration.ofHours(n);
              default -> Duration.ofDays(n);
            };
      } else {
        d = Duration.parse(t.toUpperCase(Locale.ROOT));
      }
    } catch (DateTimeException | ArithmeticException | NumberFormatException e) {
      throw CliException.usage(
          what + ": not a duration: " + text + " (examples: 30s, 15m, 12h, 30d, PT90M)");
    }
    if (d.isNegative()) throw CliException.usage(what + ": negative duration " + text);
    return d;
  }

  /**
   * A date and time: an ISO-8601 instant ({@code 2026-12-01T00:00:00Z}), one with an offset
   * ({@code 2026-12-01T01:00:00+01:00}), a local date and time ({@code 2026-12-01T00:00:00} or
   * {@code 2026-12-01 00:00:00}) or a date ({@code 2026-12-01}, its start), the last two in {@code
   * zone}.
   *
   * @param text the text
   * @param zone the zone of a local date and time
   * @param what what it is, for the error message
   * @return the instant
   */
  static Instant dateTime(String text, ZoneId zone, String what) {
    String t = text.trim();
    try {
      return Instant.parse(t);
    } catch (DateTimeException notInstant) {
      // the other forms below
    }
    try {
      return OffsetDateTime.parse(t.replace(' ', 'T')).toInstant();
    } catch (DateTimeException notOffset) {
      // the other forms below
    }
    try {
      return ZonedDateTime.parse(t.replace(' ', 'T')).toInstant();
    } catch (DateTimeException notZoned) {
      // the other forms below
    }
    try {
      return LocalDateTime.parse(t.replace(' ', 'T')).atZone(zone).toInstant();
    } catch (DateTimeException notLocal) {
      // the other forms below
    }
    try {
      return LocalDate.parse(t).atStartOfDay(zone).toInstant();
    } catch (DateTimeException notDate) {
      throw CliException.usage(
          what
              + ": not an ISO-8601 date and time: "
              + text
              + " (examples: 2026-12-01T00:00:00Z,"
              + " 2026-12-01T00:00:00+01:00, '2026-12-01 00:00:00' in the local time zone)");
    }
  }

  /**
   * A whole number, such as a key's size in bits.
   *
   * @param text the text
   * @param what what it is, for the error message
   * @return the number
   */
  static int number(String text, String what) {
    try {
      return Integer.parseInt(text);
    } catch (NumberFormatException e) {
      throw CliException.usage(what + ": not a number: " + text);
    }
  }

  /**
   * A KMIP version, {@code 1.4}, {@code 2.1} or {@code 3.0}.
   *
   * @param text the text
   * @param what what it is, for the error message
   * @return the version
   */
  static KmipVersion version(String text, String what) {
    for (KmipVersion v : KmipVersion.values()) if (v.toString().equals(text.trim())) return v;
    throw CliException.usage(
        what
            + ": unknown KMIP version "
            + text
            + " (one of "
            + java.util.Arrays.stream(KmipVersion.values())
                .map(KmipVersion::toString)
                .collect(Collectors.joining(", "))
            + ")");
  }

  /**
   * The command-line token of an enum constant: lower case, with hyphens ({@code PRE_ACTIVE} is
   * {@code pre-active}).
   *
   * @param value the constant
   * @return the token
   */
  static String token(Enum<?> value) {
    return value.name().toLowerCase(Locale.ROOT).replace('_', '-');
  }

  /**
   * The constant whose {@link #token} is {@code text}.
   *
   * @param type the enum
   * @param text the token (case and {@code _} or {@code -} do not matter)
   * @param what what it is, for the error message
   * @param <E> the enum
   * @return the constant
   */
  static <E extends Enum<E>> E constant(Class<E> type, String text, String what) {
    String wanted = text.trim().toLowerCase(Locale.ROOT).replace('_', '-');
    for (E e : type.getEnumConstants()) if (token(e).equals(wanted)) return e;
    List<String> tokens = new ArrayList<>();
    for (E e : type.getEnumConstants()) tokens.add(token(e));
    throw CliException.usage(
        what + ": unknown value " + text + " (one of " + String.join(", ", tokens) + ")");
  }

  /**
   * A constant's name for people: {@code PRE_ACTIVE} is {@code Pre-Active}, {@code SYMMETRIC_KEY}
   * is {@code Symmetric Key}.
   *
   * @param value the constant
   * @return the name
   */
  static String title(Enum<?> value) {
    if (value.name().equals("PRE_ACTIVE")) return "Pre-Active";
    StringBuilder out = new StringBuilder();
    for (String word : value.name().split("_", -1)) {
      if (out.length() > 0) out.append(' ');
      out.append(word.charAt(0)).append(word.substring(1).toLowerCase(Locale.ROOT));
    }
    return out.toString();
  }

  /**
   * A value as a word for a POSIX shell: as it is when it has only {@code [A-Za-z0-9._:/@%+=,-]},
   * otherwise in single quotes (a quote inside written {@code '\''}).
   *
   * @param value the value
   * @return the word, to paste into a command line
   */
  static String shell(String value) {
    if (SHELL_SAFE.matcher(value).matches()) return value;
    return "'" + value.replace("'", "'\\''") + "'";
  }

  /**
   * Text from the server made safe for a terminal: C0 and C1 control characters, DEL and the bidi
   * format characters (U+200E, U+200F, U+202A to U+202E, U+2066 to U+2069) are written as a
   * backslash, {@code u} and four hexadecimal digits, so that a name or an attribute value cannot move the cursor, change colors or
   * reorder the text around it. JSON output escapes the same characters.
   *
   * @param text the text, or null
   * @return the text with those characters escaped; null for null
   */
  static String safe(String text) {
    if (text == null) return null;
    StringBuilder out = null;
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      boolean unsafe = unsafe(c);
      if (unsafe && out == null) out = new StringBuilder(text.length() + 8).append(text, 0, i);
      if (unsafe) out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
      else if (out != null) out.append(c);
    }
    return out == null ? text : out.toString();
  }

  /**
   * {@code target} for text meant for a terminal: every string printed with {@code print} or
   * {@code println} is escaped with {@link #safe(String)}, so no message, plan line, hint,
   * warning or identifier the server sent can carry a control or bidi character to the terminal.
   * The line separator {@code println} adds is written as it is; a line break inside a printed
   * string is escaped, also one {@code printf} formats, so print each line with {@code println}. Bytes written with {@code write} pass through unchanged, for {@code
   * get-secret --stdout}. Errors are recorded on {@code target}, where {@link PrintStream#checkError}
   * finds them.
   *
   * @param target the stream
   * @return the escaping stream
   */
  static PrintStream terminal(PrintStream target) {
    return target instanceof Escaping ? target : new Escaping(target);
  }

  /** The stream {@link #terminal} returns. */
  private static final class Escaping extends PrintStream {
    Escaping(PrintStream target) {
      super(target, true, StandardCharsets.UTF_8);
    }

    @Override
    public void print(String s) {
      super.print(safe(String.valueOf(s)));
    }

    @Override
    public void print(Object o) {
      print(String.valueOf(o));
    }

    @Override
    public void print(char[] s) {
      print(new String(s));
    }

    @Override
    public void println(char[] s) {
      synchronized (this) {
        print(s);
        println();
      }
    }
  }

  /**
   * Whether {@code c} is a character {@link #safe} escapes.
   *
   * @param c the character
   * @return true for a C0 or C1 control, DEL, or a bidi format character
   */
  static boolean unsafe(char c) {
    return c < 0x20
        || (c >= 0x7F && c <= 0x9F)
        || c == 0x200E
        || c == 0x200F
        || (c >= 0x202A && c <= 0x202E)
        || (c >= 0x2066 && c <= 0x2069);
  }

  /**
   * A constant's name for people, with its protocol code when this API does not name it: {@code
   * Other (0x00000099)}.
   *
   * @param value the constant
   * @param unnamed whether {@code value} stands for a code this API does not name
   * @param raw the protocol code
   * @return the name
   */
  static String title(Enum<?> value, boolean unnamed, int raw) {
    return unnamed ? title(value) + String.format(Locale.ROOT, " (0x%08X)", raw) : title(value);
  }

  /**
   * A comma-separated list, without empty items.
   *
   * @param text the text
   * @return the items, trimmed
   */
  static List<String> list(String text) {
    List<String> out = new ArrayList<>();
    for (String item : LIST.split(text.trim(), -1)) if (!item.isEmpty()) out.add(item);
    return out;
  }

  /**
   * A custom attribute's value as text: hexadecimal for bytes.
   *
   * @param value the value
   * @return the text
   */
  static String text(Object value) {
    return value instanceof byte[] b ? HexFormat.of().formatHex(b) : String.valueOf(value);
  }

  /**
   * A custom attribute's value for JSON: a string, number or boolean.
   *
   * @param value the value
   * @return the JSON value
   */
  static Object json(Object value) {
    if (value instanceof Boolean
        || value instanceof Integer
        || value instanceof Long
        || value instanceof Instant) return value;
    return text(value);
  }
}
