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

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.json.JsonFactory;

/**
 * The tests' JSON reader, on Jackson's streaming parser: strict JSON only, and it refuses a name
 * given twice in an object and anything after the value. Objects become {@link LinkedHashMap}s,
 * arrays {@link List}s, numbers {@link Long} (a larger integer {@link java.math.BigInteger}) or
 * {@link Double}, and strings, booleans and null are as they are. Text that is not such JSON fails
 * the test with an {@link AssertionError}.
 */
final class JsonReader {
  private static final JsonFactory FACTORY =
      JsonFactory.builder().enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION).build();

  private JsonReader() {}

  /** Parses one JSON value, which must be all of {@code text} but white space. */
  static Object parse(String text) {
    try (JsonParser p = FACTORY.createParser(ObjectReadContext.empty(), text)) {
      if (p.nextToken() == null) throw new AssertionError("no JSON value: " + text);
      Object value = value(p);
      if (p.nextToken() != null) throw new AssertionError("text after the value: " + text);
      return value;
    } catch (JacksonException e) {
      throw new AssertionError("not JSON (" + e.getOriginalMessage() + "): " + text, e);
    }
  }

  /** Parses a JSON object. */
  @SuppressWarnings("unchecked")
  static Map<String, Object> object(String text) {
    Object value = parse(text);
    if (!(value instanceof Map)) throw new AssertionError("not a JSON object: " + text);
    return (Map<String, Object>) value;
  }

  /** The value that starts at the current token. */
  private static Object value(JsonParser p) {
    JsonToken token = p.currentToken();
    switch (token) {
      case START_OBJECT -> {
        Map<String, Object> object = new LinkedHashMap<>();
        while (p.nextToken() == JsonToken.PROPERTY_NAME) {
          String name = p.currentName();
          p.nextToken();
          object.put(name, value(p));
        }
        return object;
      }
      case START_ARRAY -> {
        List<Object> array = new ArrayList<>();
        while (p.nextToken() != JsonToken.END_ARRAY) array.add(value(p));
        return array;
      }
      case VALUE_STRING -> {
        return p.getString();
      }
      case VALUE_NUMBER_INT -> {
        return p.getNumberType() == JsonParser.NumberType.BIG_INTEGER
            ? p.getBigIntegerValue()
            : Long.valueOf(p.getLongValue());
      }
      case VALUE_NUMBER_FLOAT -> {
        return p.getDoubleValue();
      }
      case VALUE_TRUE -> {
        return true;
      }
      case VALUE_FALSE -> {
        return false;
      }
      case VALUE_NULL -> {
        return null;
      }
      default -> throw new AssertionError("unexpected JSON token " + token);
    }
  }
}
