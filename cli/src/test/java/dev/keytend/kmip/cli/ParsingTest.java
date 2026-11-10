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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.ObjectKind;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** The argument parser, value parsing and the JSON writer. */
class ParsingTest {
  /** Parses a command line as the tool does. */
  private static Cli.Line parse(String... argv) {
    PrintStream none =
        new PrintStream(OutputStream.nullOutputStream(), true, StandardCharsets.UTF_8);
    return new Cli(none, none, null, Map.of(), Clock.systemUTC(), ZoneOffset.UTC, null).parse(argv);
  }

  /** The arguments of a command line that parses. */
  private static Args args(String... argv) {
    Cli.Line line = parse(argv);
    if (line.error() != null) throw line.error();
    return line.args();
  }

  /** The usage error of a command line that does not parse. */
  private static CliException mistake(String... argv) {
    CliException e = parse(argv).error();
    assertNotNull(e, List.of(argv).toString());
    return e;
  }

  @Test
  void parsesOptionsAnywhereInBothForms() {
    Args a =
        args(
            "create",
            "id-1",
            "--name=orders",
            "-g",
            "prod",
            "--custom",
            "a=1",
            "--custom=b=2",
            "--if-absent",
            "--json");
    assertEquals(List.of("id-1"), a.positionals());
    assertEquals("orders", a.value("--name").orElseThrow());
    assertEquals("prod", a.value("--group").orElseThrow());
    assertEquals(List.of("a=1", "b=2"), a.values("--custom"));
    assertTrue(a.flag("--if-absent"));
    assertTrue(a.flag("--json"));
    assertFalse(a.flag("--yes"));
  }

  @Test
  void doubleDashEndsOptions() {
    Args a = args("create", "--", "--name");
    assertEquals(List.of("--name"), a.positionals());
  }

  @Test
  void refusesUnknownMissingRepeatedAndValuedFlags() {
    assertEquals(ExitCode.USAGE, mistake("create", "--nope").exit);
    assertTrue(mistake("create", "--name").getMessage().contains("needs a value"));
    assertTrue(
        mistake("create", "--name", "a", "--name", "b").getMessage().contains("more than once"));
    assertTrue(mistake("create", "--if-absent=yes").getMessage().contains("no value"));
  }

  @Test
  void findsTheCommandAfterGlobalOptions() {
    Cli.Line list = parse("--config", "x", "-g", "prod", "list", "--name", "n");
    assertEquals("list", list.command().name());
    assertEquals("x", list.args().value("--config").orElseThrow());
    assertEquals("prod", list.args().value("--group").orElseThrow());
    assertEquals("n", list.args().value("--name").orElseThrow());
    Cli.Line show = parse("--json", "show", "7");
    assertEquals("show", show.command().name());
    assertEquals(List.of("7"), show.args().positionals());
    assertEquals("servers", parse("--config=x", "servers").command().name());
    assertNull(parse("--help").command());
  }

  @Test
  void singleAndNone() {
    assertEquals("7", args("show", "7").single("an id"));
    assertThrows(CliException.class, () -> args("show").single("an id"));
    assertThrows(CliException.class, () -> args("show", "7", "8").single("an id"));
    assertThrows(CliException.class, () -> args("list", "7").none());
  }

  @Test
  void durations() {
    assertEquals(Duration.ofSeconds(30), Values.duration("30s", "t"));
    assertEquals(Duration.ofMinutes(15), Values.duration("15m", "t"));
    assertEquals(Duration.ofHours(12), Values.duration("12h", "t"));
    assertEquals(Duration.ofDays(30), Values.duration("30d", "t"));
    assertEquals(Duration.ofMillis(500), Values.duration("500ms", "t"));
    assertEquals(Duration.ofMinutes(90), Values.duration("PT90M", "t"));
    assertEquals(Duration.ofDays(2), Values.duration("p2d", "t"));
    assertThrows(CliException.class, () -> Values.duration("soon", "t"));
    assertThrows(CliException.class, () -> Values.duration("-PT1S", "t"));
  }

  @Test
  void dateTimes() {
    Instant expected = Instant.parse("2026-12-01T00:00:00Z");
    assertEquals(expected, Values.dateTime("2026-12-01T00:00:00Z", ZoneOffset.UTC, "t"));
    assertEquals(expected, Values.dateTime("2026-12-01T01:00:00+01:00", ZoneOffset.UTC, "t"));
    assertEquals(expected, Values.dateTime("2026-12-01 00:00:00", ZoneOffset.UTC, "t"));
    assertEquals(expected, Values.dateTime("2026-12-01T02:00:00", ZoneOffset.ofHours(2), "t"));
    assertEquals(expected, Values.dateTime("2026-12-01", ZoneOffset.UTC, "t"));
    assertThrows(
        CliException.class, () -> Values.dateTime("2026-12-01 00:00:00:000", ZoneOffset.UTC, "t"));
    assertThrows(CliException.class, () -> Values.dateTime("tomorrow", ZoneOffset.UTC, "t"));
  }

  @Test
  void enumTokensAndTitles() {
    assertEquals("pre-active", Values.token(KeyState.PRE_ACTIVE));
    assertEquals(
        KeyState.DESTROYED_COMPROMISED,
        Values.constant(KeyState.class, "Destroyed_Compromised", "s"));
    assertEquals(ObjectKind.SECRET_DATA, Values.constant(ObjectKind.class, "secret-data", "k"));
    assertTrue(
        assertThrows(CliException.class, () -> Values.constant(KeyState.class, "gone", "--state"))
            .getMessage()
            .contains("active"));
    assertEquals("Pre-Active", Values.title(KeyState.PRE_ACTIVE));
    assertEquals("Symmetric Key", Values.title(ObjectKind.SYMMETRIC_KEY));
    assertEquals(KmipVersion.V2_1, Values.version("2.1", "v"));
    assertThrows(CliException.class, () -> Values.version("2.2", "v"));
  }

  @Test
  void customAttributeOptions() {
    assertEquals("x-purpose", Render.customOption("purpose=archive").getKey().toString());
    assertEquals("x-purpose", Render.customOption("x-purpose=archive").getKey().toString());
    assertEquals("y-owner", Render.customOption("y-owner=a").getKey().toString());
    assertEquals("acme:tier", Render.customOption("acme:tier=gold").getKey().toString());
    assertEquals("a=b", Render.customOption("x-k=a=b").getValue());
    assertThrows(CliException.class, () -> Render.customOption("novalue"));
  }

  @Test
  void jsonEscapesAndNests() {
    Map<String, Object> m = new LinkedHashMap<>();
    m.put("s", "a\"b\\c\nd\u0001");
    m.put("n", 3);
    m.put("b", true);
    m.put("z", null);
    m.put("t", Instant.parse("2026-01-01T00:00:00Z"));
    m.put("l", List.of(1, "x"));
    m.put("e", Map.of());
    String json = Json.write(m);
    assertTrue(json.contains("\"s\": \"a\\\"b\\\\c\\nd\\u0001\""), json);
    assertTrue(json.contains("\"n\": 3"));
    assertTrue(json.contains("\"b\": true"));
    assertTrue(json.contains("\"z\": null"));
    assertTrue(json.contains("\"t\": \"2026-01-01T00:00:00Z\""));
    assertTrue(json.contains("\"l\": [\n    1,\n    \"x\"\n  ]"), json);
    assertTrue(json.contains("\"e\": {}"));
    assertEquals("a\"b\\c\nd\u0001", JsonReader.object(json).get("s"), "it reads back");
    // The whole layout, independent of the JSON library: two-space indents, one entry a line.
    Map<String, Object> nested = new LinkedHashMap<>();
    nested.put("a", List.of(1, Map.of()));
    nested.put("b", Collections.singletonMap("c", null));
    nested.put("d", List.of());
    assertEquals(
        "{\n  \"a\": [\n    1,\n    {}\n  ],\n  \"b\": {\n    \"c\": null\n  },\n  \"d\": []\n}",
        Json.write(nested));
  }

  @Test
  void tablePadsColumns() {
    java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
    new Table("ID", "NAME")
        .row("1", "orders")
        .row("1234", null)
        .print(new java.io.PrintStream(bytes, true, java.nio.charset.StandardCharsets.UTF_8));
    assertEquals(
        "ID    NAME\n1     orders\n1234\n",
        bytes.toString(java.nio.charset.StandardCharsets.UTF_8).replace("\r\n", "\n"));
  }

  @Test
  void theJsonScanForAnUnparsedCommandLine() {
    assertTrue(parse("list", "--json").json());
    assertTrue(parse("list", "--bogus", "--json").json());
    assertNotNull(parse("list", "--bogus", "--json").error());
    assertFalse(parse("list", "--name", "--json").json());
    assertFalse(parse("list", "--custom", "--json", "--bogus").json());
    assertNotNull(parse("list", "--custom", "--json", "--bogus").error());
    assertFalse(parse("--config", "--json", "list").json());
    assertFalse(parse("show", "--", "--json").json());
    assertTrue(parse("list", "--name=x", "--json").json());
  }

  @Test
  void shellQuoting() {
    assertEquals("orders-kek", Values.shell("orders-kek"));
    assertEquals("/etc/keytend/cli.properties", Values.shell("/etc/keytend/cli.properties"));
    assertEquals("a@b:c%d+e=f,g", Values.shell("a@b:c%d+e=f,g"));
    assertEquals("'two words'", Values.shell("two words"));
    assertEquals("'$HOME'", Values.shell("$HOME"));
    assertEquals("'it'\\''s'", Values.shell("it's"));
    assertEquals("''", Values.shell(""));
  }

  @Test
  void terminalEscaping() {
    assertEquals("plain text", Values.safe("plain text"));
    assertEquals("a\\u001b[31mb", Values.safe("a\u001b[31mb"));
    assertEquals("\\u0000\\u007f\\u0085\\u009f", Values.safe("\u0000\u007f\u0085\u009f"));
    StringBuilder bidi = new StringBuilder();
    for (int c : new int[] {0x200e, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069}) bidi.append((char) c);
    assertEquals("\\u200e\\u200f\\u202a\\u202e\\u2066\\u2069", Values.safe(bidi.toString()));
    assertEquals("caf\u00e9 \u4e2d", Values.safe("caf\u00e9 \u4e2d"), "printable text stays");
    String c1AndBidi = "" + (char) 0x85 + (char) 0x202e;
    String json = Json.write(Map.of("s", c1AndBidi));
    assertTrue(json.contains("\\u0085\\u202e"), json);
    assertEquals(c1AndBidi, JsonReader.object(json).get("s"));
    java.io.ByteArrayOutputStream bytes = new java.io.ByteArrayOutputStream();
    new Table("NAME")
        .row("x\u001by")
        .print(new java.io.PrintStream(bytes, true, java.nio.charset.StandardCharsets.UTF_8));
    assertTrue(bytes.toString(java.nio.charset.StandardCharsets.UTF_8).contains("x\\u001by"));
  }

  @Test
  void theTestJsonReader() {
    Map<String, Object> m =
        JsonReader.object("{\"a\": [1, 2.5, true, null, \"x\\ny\"], \"b\": {}}");
    List<?> a = (List<?>) m.get("a");
    assertEquals(5, a.size());
    assertEquals(1L, a.get(0));
    assertEquals(2.5, a.get(1));
    assertEquals(true, a.get(2));
    assertNull(a.get(3));
    assertEquals("x\ny", a.get(4));
    assertEquals(Map.of(), m.get("b"));
    assertThrows(AssertionError.class, () -> JsonReader.parse("{\"a\": 1} x"));
    assertThrows(AssertionError.class, () -> JsonReader.parse("{\"a\": 1} {}"));
    assertThrows(AssertionError.class, () -> JsonReader.parse("{\"a\": 1, \"a\": 2}"));
    assertThrows(AssertionError.class, () -> JsonReader.parse("[1, 2,]"));
    assertThrows(AssertionError.class, () -> JsonReader.parse("01"));
  }
}
