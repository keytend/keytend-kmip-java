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

import java.io.StringWriter;
import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.ObjectWriteContext;
import tools.jackson.core.PrettyPrinter;
import tools.jackson.core.SerializableString;
import tools.jackson.core.io.CharacterEscapes;
import tools.jackson.core.io.SerializedString;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.util.DefaultIndenter;
import tools.jackson.core.util.DefaultPrettyPrinter;
import tools.jackson.core.util.Separators;

/**
 * The tool's JSON output, written with Jackson's streaming generator: maps (in their iteration
 * order), collections, strings, numbers, booleans, instants (as ISO-8601 strings) and null,
 * indented by two spaces. An {@link Integer} or a {@link Long} is a JSON number; another {@link
 * Number} is written as a string, as it prints. Control and bidi format characters in strings
 * ({@link Values#unsafe}), and U+2028 and U+2029, are escaped, so the output is safe to print.
 */
final class Json {
  private static final JsonFactory FACTORY = new JsonFactory();

  /** Objects and arrays one entry a line, indented by two spaces; {@code "name": value}. */
  private static final Separators SEPARATORS =
      new Separators()
          .withObjectNameValueSpacing(Separators.Spacing.AFTER)
          .withObjectEmptySeparator("")
          .withArrayEmptySeparator("");

  private static final DefaultIndenter INDENTER = new DefaultIndenter("  ", "\n");

  private Json() {}

  /**
   * The value as indented JSON.
   *
   * @param value the value
   * @return the JSON text, without a final newline
   */
  static String write(Object value) {
    StringWriter out = new StringWriter();
    try (JsonGenerator g = FACTORY.createGenerator(new Output(), out)) {
      write(g, value);
    }
    return out.toString();
  }

  private static void write(JsonGenerator g, Object value) {
    if (value == null) {
      g.writeNull();
    } else if (value instanceof String s) {
      g.writeString(s);
    } else if (value instanceof Boolean b) {
      g.writeBoolean(b);
    } else if (value instanceof Integer i) {
      g.writeNumber(i);
    } else if (value instanceof Long l) {
      g.writeNumber(l);
    } else if (value instanceof Map<?, ?> map) {
      g.writeStartObject();
      for (Map.Entry<?, ?> e : map.entrySet()) {
        g.writeName(String.valueOf(e.getKey()));
        write(g, e.getValue());
      }
      g.writeEndObject();
    } else if (value instanceof Collection<?> list) {
      g.writeStartArray();
      for (Object item : list) write(g, item);
      g.writeEndArray();
    } else {
      // An Instant as ISO-8601, and other numbers as they print.
      g.writeString(value.toString());
    }
  }

  /** The generator's settings: the layout above and the terminal-safe escapes. */
  private static final class Output extends ObjectWriteContext.Base {
    @Override
    public PrettyPrinter getPrettyPrinter() {
      return new DefaultPrettyPrinter(SEPARATORS)
          .withObjectIndenter(INDENTER)
          .withArrayIndenter(INDENTER);
    }

    @Override
    public boolean hasPrettyPrinter() {
      return true;
    }

    @Override
    public CharacterEscapes getCharacterEscapes() {
      return TerminalEscapes.INSTANCE;
    }
  }

  /**
   * JSON's escapes, and a backslash, {@code u} and four lower-case hexadecimal digits for every
   * character {@link Values#unsafe} names (C0 and C1 controls but line feed, carriage return and
   * tab, DEL, the bidi format characters) and for U+2028 and U+2029, which some JavaScript parsers
   * take for line breaks.
   */
  private static final class TerminalEscapes extends CharacterEscapes {
    private static final long serialVersionUID = 1L;
    static final TerminalEscapes INSTANCE = new TerminalEscapes();

    private final int[] ascii = CharacterEscapes.standardAsciiEscapesForJSON();

    private TerminalEscapes() {
      for (int c = 0; c < ascii.length; c++)
        if (Values.unsafe((char) c) && c != '\n' && c != '\r' && c != '\t')
          ascii[c] = ESCAPE_CUSTOM;
    }

    @Override
    public int[] getEscapeCodesForAscii() {
      return ascii.clone();
    }

    @Override
    public SerializableString getEscapeSequence(int c) {
      if (!Values.unsafe((char) c) && c != 0x2028 && c != 0x2029) return null;
      return new SerializedString(String.format(Locale.ROOT, "\\u%04x", c));
    }
  }
}
