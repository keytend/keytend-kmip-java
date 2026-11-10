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
import java.math.*;
import java.nio.*;
import java.nio.charset.*;
import java.util.*;

/**
 * OASIS JSON profile. Integers remain exact; long/big integers and DateTimeExtended encode as
 * sign-extended hex strings. Decoding is bounded by input bytes, nesting depth and element count
 * (default {@link TtlvCodec#DEFAULT_MAX_ELEMENTS}, as for TTLV), and a numeric value's magnitude is
 * bounded by its text length, so exponent forms such as {@code 1e100000} cannot expand.
 *
 * @since 0.10.0
 */
public final class JsonCodec {
  private final int maxBytes, maxDepth, maxElements;

  /** A codec with the default limits of {@link TtlvCodec}. */
  public JsonCodec() {
    this(TtlvCodec.DEFAULT_MAX_BYTES, TtlvCodec.DEFAULT_MAX_DEPTH);
  }

  /**
   * A codec with these limits and {@link TtlvCodec#DEFAULT_MAX_ELEMENTS}; see {@link
   * #JsonCodec(int, int, int)}.
   *
   * @param maxBytes the largest message, in bytes; at least 8
   * @param maxDepth the deepest nesting of structures; at least 1
   */
  public JsonCodec(int maxBytes, int maxDepth) {
    this(maxBytes, maxDepth, TtlvCodec.DEFAULT_MAX_ELEMENTS);
  }

  /**
   * A codec with these limits. Size and nesting apply when encoding and when decoding; the
   * element count applies when decoding.
   *
   * @param maxBytes the largest message, in bytes; at least 8
   * @param maxDepth the deepest nesting of structures; at least 1
   * @param maxElements the most values in one decoded message; at least 1
   * @throws IllegalArgumentException if a limit is below its minimum
   */
  public JsonCodec(int maxBytes, int maxDepth, int maxElements) {
    if (maxBytes < 8 || maxDepth < 1 || maxElements < 1)
      throw new IllegalArgumentException("Invalid limits");
    this.maxBytes = maxBytes;
    this.maxDepth = maxDepth;
    this.maxElements = maxElements;
  }

  /**
   * Encodes one TTLV value in the JSON profile, as UTF-8.
   *
   * @param n the value
   * @return the encoded bytes
   * @throws IOException if {@code n} exceeds the size or nesting limit
   */
  public byte[] encode(Ttlv n) throws IOException {
    StringBuilder b = new StringBuilder();
    write(b, n, 0);
    byte[] out = b.toString().getBytes(StandardCharsets.UTF_8);
    if (out.length > maxBytes) throw new IOException("JSON message exceeds limit");
    return out;
  }

  private void write(StringBuilder b, Ttlv n, int depth) throws IOException {
    if (depth >= maxDepth) throw new IOException("JSON nesting limit");
    b.append("{\"tag\":");
    quote(b, n.tagName());
    b.append(",\"type\":");
    quote(b, TextValues.typeName(n.type()));
    b.append(",\"value\":");
    switch (n.type()) {
      case STRUCTURE -> {
        b.append('[');
        boolean first = true;
        for (Ttlv c : n.children()) {
          if (!first) b.append(',');
          write(b, c, depth + 1);
          first = false;
        }
        b.append(']');
      }
      case INTEGER -> b.append(n.intValue());
      case INTERVAL -> b.append(n.longValue());
      case DATE_TIME -> quote(b, TextValues.dateTimeText(n.longValue()));
      // KMIP Profiles 2.0 §5.5.1.6.13: a Number or a hex string; hex is always exact.
      case LONG_INTEGER, DATE_TIME_EXTENDED -> quote(b, String.format("0x%016X", n.longValue()));
      case BIG_INTEGER -> quote(b, "0x" + TextValues.bigInteger(n));
      case BOOLEAN -> b.append(n.booleanValue());
      default -> quote(b, TextValues.scalarText(n));
    }
    b.append('}');
  }

  private static void quote(StringBuilder b, String s) {
    b.append('"');
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"' -> b.append("\\\"");
        case '\\' -> b.append("\\\\");
        case '\b' -> b.append("\\b");
        case '\f' -> b.append("\\f");
        case '\n' -> b.append("\\n");
        case '\r' -> b.append("\\r");
        case '\t' -> b.append("\\t");
        default -> {
          if (c < 32) b.append(String.format("\\u%04x", (int) c));
          else b.append(c);
        }
      }
    }
    b.append('"');
  }

  /**
   * Decodes one TTLV value from JSON.
   *
   * @param bytes the UTF-8 JSON text
   * @return the value
   * @throws DecodeException for malformed or oversized input; its message never contains input
   *     values
   */
  public Ttlv decode(byte[] bytes) throws IOException {
    if (bytes.length > maxBytes) throw new DecodeException("JSON message exceeds limit");
    try {
      String text =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(bytes))
              .toString();
      // Each TTLV element is one JSON object holding a few values.
      Parser p = new Parser(text, maxDepth * 3 + 4, maxElements * 8L + 8);
      Object json = p.value(0);
      p.white();
      if (p.pos != text.length()) throw new TextValues.Malformed("Trailing JSON input");
      return node(json, 0, null, new int[] {0});
    } catch (CharacterCodingException e) {
      throw new DecodeException("Malformed KMIP JSON: invalid UTF-8", e);
    } catch (RuntimeException e) {
      throw new DecodeException("Malformed KMIP JSON" + TextValues.detail(e), e);
    }
  }

  private Ttlv node(Object object, int depth, String attributeName, int[] elements) {
    if (depth >= maxDepth) throw new TextValues.Malformed("JSON nesting limit");
    if (++elements[0] > maxElements) throw new TextValues.Malformed("JSON element limit");
    if (!(object instanceof Map<?, ?> map)) throw new TextValues.Malformed("Expected TTLV object");
    int tag = TextValues.tag((String) map.get("tag"));
    Ttlv.Type type =
        map.containsKey("type") ? TextValues.type((String) map.get("type")) : Ttlv.Type.STRUCTURE;
    Object value = map.get("value");
    if (type == Ttlv.Type.STRUCTURE) {
      List<Ttlv> children = new ArrayList<>();
      if (value != null)
        for (Object child : (List<?>) value) {
          Ttlv n = node(child, depth + 1, attributeName, elements);
          children.add(n);
          if (n.tag() == Tag.ATTRIBUTE_NAME.code()) attributeName = n.textValue();
        }
      return Ttlv.structure(tag, children);
    }
    if (value == null) throw new TextValues.Malformed("Scalar missing value");
    if (value instanceof BigDecimal number) {
      if (type == Ttlv.Type.BIG_INTEGER) return Ttlv.of(tag, type, number.toBigIntegerExact());
      if (type == Ttlv.Type.INTEGER) return Ttlv.of(tag, type, number.intValueExact());
      if (type == Ttlv.Type.ENUMERATION) {
        long n = number.longValueExact();
        if (n < 0 || n > 0xffff_ffffL) throw new TextValues.Malformed("Enumeration overflow");
        return Ttlv.of(tag, type, (int) n);
      }
      if (type == Ttlv.Type.LONG_INTEGER
          || type == Ttlv.Type.INTERVAL
          || type == Ttlv.Type.DATE_TIME_EXTENDED)
        return Ttlv.of(tag, type, number.longValueExact());
      throw new TextValues.Malformed("Numeric value invalid for " + type);
    }
    if (value instanceof Boolean b) {
      if (type != Ttlv.Type.BOOLEAN) throw new TextValues.Malformed("Unexpected boolean");
      return Ttlv.of(tag, type, b);
    }
    return TextValues.scalar(tag, type, (String) value, attributeName);
  }

  /**
   * Strict JSON reader; bounded input/depth, duplicate properties rejected, no floating point
   * conversion.
   */
  private static final class Parser {
    private final String s;
    private final int maxDepth;
    private final long maxValues;
    private long values;
    private int pos;

    Parser(String s, int maxDepth, long maxValues) {
      this.s = s;
      this.maxDepth = maxDepth;
      this.maxValues = maxValues;
    }

    void white() {
      while (pos < s.length() && " \r\n\t".indexOf(s.charAt(pos)) >= 0) pos++;
    }

    boolean take(char c) {
      white();
      if (pos < s.length() && s.charAt(pos) == c) {
        pos++;
        return true;
      }
      return false;
    }

    void expect(char c) {
      if (!take(c)) throw new TextValues.Malformed("Expected '" + c + "' at offset " + pos);
    }

    Object value(int depth) {
      if (depth > maxDepth) throw new TextValues.Malformed("JSON nesting limit");
      if (++values > maxValues) throw new TextValues.Malformed("JSON element limit");
      white();
      if (pos >= s.length()) throw new TextValues.Malformed("Truncated JSON");
      char c = s.charAt(pos);
      if (c == '{') {
        pos++;
        Map<String, Object> map = new LinkedHashMap<>();
        if (take('}')) return map;
        do {
          String key = string();
          expect(':');
          if (map.containsKey(key)) throw new TextValues.Malformed("Duplicate JSON property");
          map.put(key, value(depth + 1));
        } while (take(','));
        expect('}');
        return map;
      }
      if (c == '[') {
        pos++;
        List<Object> list = new ArrayList<>();
        if (take(']')) return list;
        do {
          list.add(value(depth + 1));
        } while (take(','));
        expect(']');
        return list;
      }
      if (c == '"') return string();
      for (String word : List.of("true", "false", "null"))
        if (s.startsWith(word, pos)) {
          pos += word.length();
          return word.equals("null") ? null : Boolean.valueOf(word);
        }
      int start = pos;
      if (s.charAt(pos) == '-') pos++;
      if (pos >= s.length() || s.charAt(pos) < '0' || s.charAt(pos) > '9')
        throw new TextValues.Malformed("Invalid JSON number");
      if (s.charAt(pos) == '0') pos++;
      else while (pos < s.length() && s.charAt(pos) >= '0' && s.charAt(pos) <= '9') pos++;
      if (pos < s.length() && s.charAt(pos) == '.') {
        pos++;
        int p = pos;
        while (pos < s.length() && s.charAt(pos) >= '0' && s.charAt(pos) <= '9') pos++;
        if (p == pos) throw new TextValues.Malformed("Missing fraction");
      }
      if (pos < s.length() && "eE".indexOf(s.charAt(pos)) >= 0) {
        pos++;
        if (pos < s.length() && "+-".indexOf(s.charAt(pos)) >= 0) pos++;
        int p = pos;
        while (pos < s.length() && s.charAt(pos) >= '0' && s.charAt(pos) <= '9') pos++;
        if (p == pos) throw new TextValues.Malformed("Missing exponent");
      }
      String num = s.substring(start, pos);
      if (num.length() > 4096) throw new TextValues.Malformed("JSON number too long");
      BigDecimal n = new BigDecimal(num);
      if (Math.abs((long) n.scale()) > 100000)
        throw new TextValues.Malformed("JSON exponent limit");
      // An integer value may have at most 8 bits per input character: 10 digits per 24 chars.
      long integerDigits = (long) n.precision() - n.scale();
      if (integerDigits * 10 > 24L * num.length())
        throw new TextValues.Malformed("JSON number magnitude exceeds its text");
      return n;
    }

    String string() {
      expect('"');
      StringBuilder b = new StringBuilder();
      while (pos < s.length()) {
        char c = s.charAt(pos++);
        if (c == '"') {
          String out = b.toString();
          for (int i = 0; i < out.length(); i++) {
            char u = out.charAt(i);
            if (Character.isHighSurrogate(u)) {
              if (++i >= out.length() || !Character.isLowSurrogate(out.charAt(i)))
                throw new TextValues.Malformed("Unpaired Unicode surrogate");
            } else if (Character.isLowSurrogate(u))
              throw new TextValues.Malformed("Unpaired Unicode surrogate");
          }
          return out;
        }
        if (c < 32) throw new TextValues.Malformed("Unescaped control character");
        if (c == '\\') {
          if (pos >= s.length()) break;
          c = s.charAt(pos++);
          switch (c) {
            case '"', '\\', '/' -> b.append(c);
            case 'b' -> b.append('\b');
            case 'f' -> b.append('\f');
            case 'n' -> b.append('\n');
            case 'r' -> b.append('\r');
            case 't' -> b.append('\t');
            case 'u' -> {
              if (pos + 4 > s.length()) throw new TextValues.Malformed("Truncated Unicode escape");
              // RFC 8259 §7: exactly four ASCII hex digits (Integer.parseInt would accept a
              // sign, Character.digit other Unicode digits).
              b.append((char) TextValues.unsignedHex(s.substring(pos, pos + 4), 16, "escape"));
              pos += 4;
            }
            default -> throw new TextValues.Malformed("Invalid JSON escape");
          }
        } else b.append(c);
      }
      throw new TextValues.Malformed("Unterminated JSON string");
    }
  }
}
