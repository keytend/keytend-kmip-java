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

package dev.keytend.kmip.interop;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.Instant;
import java.util.*;
import tools.jackson.core.JsonGenerator;
import tools.jackson.core.ObjectWriteContext;
import tools.jackson.core.PrettyPrinter;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.core.json.JsonWriteFeature;
import tools.jackson.core.util.DefaultPrettyPrinter;

/** Research catalog identities and evidence. A result never changes its execution layer. */
public final class Catalog {
  public enum Outcome {
    NOT_RUN,
    PASS,
    FAIL_CLIENT,
    FAIL_SERVER,
    BLOCKED_ENV,
    UNSUPPORTED_SERVER,
    NOT_APPLICABLE
  }

  public record Case(
      String id, String family, String title, String layer, String priority, Set<String> servers) {}

  public static final List<Case> CASES = load();

  private static List<Case> load() {
    try (var in = Catalog.class.getResourceAsStream("/dev/keytend/kmip/catalog/cases.tsv")) {
      if (in == null) throw new IOException("Missing catalog");
      List<Case> cases = new ArrayList<>();
      for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
        String[] c = line.split("\t", -1);
        cases.add(new Case(c[0], c[1], c[2], c[3], c[4], Set.of(c[5].split(","))));
      }
      if (cases.size() != 145 || cases.stream().map(Case::id).distinct().count() != 145)
        throw new IOException("Catalog identity mismatch");
      return List.copyOf(cases);
    } catch (IOException e) {
      throw new ExceptionInInitializerError(e);
    }
  }

  public static class Classification extends Exception {
    public final Outcome outcome;

    public Classification(Outcome outcome, String reason) {
      super(reason);
      this.outcome = outcome;
    }
  }

  public static void blocked(String reason) throws Classification {
    throw new Classification(Outcome.BLOCKED_ENV, reason);
  }

  public static void outside(String reason) throws Classification {
    throw new Classification(Outcome.NOT_APPLICABLE, reason);
  }

  public static void require(boolean condition, String reason) {
    if (!condition) throw new AssertionError(reason);
  }

  public static String digest(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * The reports' JSON (Jackson's streaming generator; no data binding): compact, members in the
   * maps' iteration order. Only safe evidence goes in: null, booleans, numbers, maps (keys by
   * {@code toString()}), iterables, and anything else as its {@code toString()} text. Callers never
   * serialize key objects. A non-finite double or float (NaN, an infinity) is written as the string
   * {@code "NaN"}, {@code "Infinity"} or {@code "-Infinity"}, which JSON has no number for: the
   * report stays valid JSON and says what was measured.
   */
  public static String json(Object value) {
    return json(value, ObjectWriteContext.empty());
  }

  /** {@link #json(Object)}, indented: Jackson's default pretty printer. */
  static String indentedJson(Object value) {
    return json(
        value,
        new ObjectWriteContext.Base() {
          @Override
          public PrettyPrinter getPrettyPrinter() {
            return new DefaultPrettyPrinter();
          }

          @Override
          public boolean hasPrettyPrinter() {
            return true;
          }
        });
  }

  private static final JsonFactory JSON =
      JsonFactory.builder().enable(JsonWriteFeature.WRITE_NAN_AS_STRINGS).build();

  private static String json(Object value, ObjectWriteContext context) {
    StringWriter out = new StringWriter();
    try (JsonGenerator g = JSON.createGenerator(context, out)) {
      write(g, value);
    }
    return out.toString();
  }

  private static void write(JsonGenerator g, Object value) {
    if (value == null) g.writeNull();
    else if (value instanceof Boolean b) g.writeBoolean(b);
    else if (value instanceof Integer
        || value instanceof Long
        || value instanceof Short
        || value instanceof Byte) g.writeNumber(((Number) value).longValue());
    else if (value instanceof Double || value instanceof Float)
      g.writeNumber(((Number) value).doubleValue());
    else if (value instanceof java.math.BigInteger n) g.writeNumber(n);
    else if (value instanceof java.math.BigDecimal n) g.writeNumber(n);
    else if (value instanceof Number n) g.writeNumber(new java.math.BigDecimal(n.toString()));
    else if (value instanceof Map<?, ?> m) {
      g.writeStartObject();
      for (var e : m.entrySet()) {
        g.writeName(e.getKey().toString());
        write(g, e.getValue());
      }
      g.writeEndObject();
    } else if (value instanceof Iterable<?> items) {
      g.writeStartArray();
      for (Object x : items) write(g, x);
      g.writeEndArray();
    } else g.writeString(value.toString());
  }

  public static void write(Path path, Map<String, ?> report) throws IOException {
    Files.createDirectories(path.toAbsolutePath().getParent());
    Files.writeString(path, json(report) + "\n");
  }

  public static Map<String, Object> runtime() {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("jdk_vendor_update", System.getProperty("java.vendor") + " " + Runtime.version());
    m.put(
        "crypto_provider",
        Arrays.stream(Security.getProviders())
            .map(p -> p.getName() + " " + p.getVersionStr())
            .toList());
    m.put("observed_at", Instant.now().toString());
    return m;
  }
}
