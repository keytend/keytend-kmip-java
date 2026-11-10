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

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.ProtocolVersion;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
import tools.jackson.core.json.JsonFactory;

/** The laboratory's report JSON: valid, in the maps' order, whatever the evidence holds. */
class CatalogJsonTest {
  /** A strict parser (Jackson's defaults: no NaN, no comments, no trailing data) over {@code json}. */
  private static List<String> tokens(String json) {
    List<String> out = new ArrayList<>();
    try (JsonParser p =
        JsonFactory.builder().build().createParser(ObjectReadContext.empty(), json)) {
      for (JsonToken t; (t = p.nextToken()) != null; )
        out.add(
            switch (t) {
              case PROPERTY_NAME -> "name:" + p.currentName();
              case VALUE_STRING -> "string:" + p.getString();
              case VALUE_NUMBER_INT, VALUE_NUMBER_FLOAT -> "number:" + p.getDecimalValue();
              default -> t.name();
            });
    }
    return out;
  }

  @Test
  void nonFiniteNumbersAreStringsAndTheReportStaysValid() {
    Map<String, Object> evidence = new LinkedHashMap<>();
    evidence.put("nan", Double.NaN);
    evidence.put("up", Double.POSITIVE_INFINITY);
    evidence.put("down", Float.NEGATIVE_INFINITY);
    evidence.put("p99", 12.5);
    String json = Catalog.json(evidence);
    assertEquals("{\"nan\":\"NaN\",\"up\":\"Infinity\",\"down\":\"-Infinity\",\"p99\":12.5}", json);
    assertEquals(
        List.of(
            "START_OBJECT",
            "name:nan",
            "string:NaN",
            "name:up",
            "string:Infinity",
            "name:down",
            "string:-Infinity",
            "name:p99",
            "number:12.5",
            "END_OBJECT"),
        tokens(json));
  }

  @Test
  void valuesKeepTheirKindsAndMembersTheirOrder() {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("z", 1);
    m.put("a", Long.MAX_VALUE);
    m.put("big", new BigInteger("123456789012345678901234567890"));
    m.put("exact", new BigDecimal("0.10"));
    m.put("counter", new AtomicLong(7));
    m.put("flag", true);
    m.put("none", null);
    m.put("when", Instant.parse("2026-11-04T00:00:00Z"));
    m.put("list", List.of(1, "two", List.of()));
    m.put("map", Map.of());
    m.put(ProtocolVersion.V2_1.toString(), "key by text");
    assertEquals(
        "{\"z\":1,\"a\":9223372036854775807,\"big\":123456789012345678901234567890,"
            + "\"exact\":0.10,\"counter\":7,\"flag\":true,\"none\":null,"
            + "\"when\":\"2026-11-04T00:00:00Z\",\"list\":[1,\"two\",[]],\"map\":{},"
            + "\""
            + ProtocolVersion.V2_1
            + "\":\"key by text\"}",
        Catalog.json(m));
    tokens(Catalog.json(m));
  }

  @Test
  void stringsAreEscapedAndAPrivateKeyIsStillVisibleToTheGuard() {
    String text = "quote \" backslash \\ newline \n tab \t nul \0 bell \u0007 é ✓";
    String json = Catalog.json(Map.of("s", text));
    assertEquals(List.of("START_OBJECT", "name:s", "string:" + text, "END_OBJECT"), tokens(json));
    for (char c : json.toCharArray()) assertTrue(c >= 0x20, "a raw control character");
    // CatalogLiveSuite refuses a report whose JSON contains this text.
    assertTrue(Catalog.json(List.of("-----BEGIN PRIVATE KEY-----")).contains("PRIVATE KEY"));
  }

  @Test
  void theInteropReportIsIndentedJsonInItsOrder(@TempDir Path dir) throws Exception {
    Path file = dir.resolve("out/report.json");
    InteropSuite.writeReport(
        file,
        "server \"one\"",
        ProtocolVersion.V1_4,
        List.of(
            new InteropSuite.Check("ping", "PASS", "ok"),
            new InteropSuite.Check("get", "FAIL", "line 1\nline 2")));
    String json = Files.readString(file);
    assertTrue(json.endsWith("}\n"));
    assertTrue(json.contains("\n  \"checks\" : [ {\n"), json);
    assertEquals(
        List.of(
            "START_OBJECT",
            "name:server",
            "string:server \"one\"",
            "name:version",
            "string:" + ProtocolVersion.V1_4,
            "name:java",
            "string:" + System.getProperty("java.version"),
            "name:checks",
            "START_ARRAY",
            "START_OBJECT",
            "name:name",
            "string:ping",
            "name:outcome",
            "string:PASS",
            "name:detail",
            "string:ok",
            "END_OBJECT",
            "START_OBJECT",
            "name:name",
            "string:get",
            "name:outcome",
            "string:FAIL",
            "name:detail",
            "string:line 1\nline 2",
            "END_OBJECT",
            "END_ARRAY",
            "END_OBJECT"),
        tokens(json));
  }
}
