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

package dev.keytend.kmip;

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.codec.*;
import dev.keytend.kmip.model.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import java.util.stream.*;
import org.junit.jupiter.api.*;

/** Unmodified OASIS messages, not generated from our Java model. */
class OasisVectorsTest {
  private static final Pattern NOW = Pattern.compile("\\$NOW([+-]\\d+)?");

  static String resolve(String xml) {
    Matcher m = NOW.matcher(xml);
    StringBuilder b = new StringBuilder();
    while (m.find()) {
      long seconds = 1_700_000_000L + (m.group(1) == null ? 0 : Long.parseLong(m.group(1)));
      m.appendReplacement(b, java.time.Instant.ofEpochSecond(seconds).toString());
    }
    m.appendTail(b);
    return b.toString()
        .replace("</KMIP>\n\n</KMIP>", "</KMIP>")
        .replaceAll("\\$[A-Za-z0-9_]+", "DEADBEEFCAFE");
  }

  @TestFactory
  Stream<DynamicTest> originalOasisMessages() throws Exception {
    Path root = Path.of("src/test/resources/oasis");
    List<Path> files;
    try (var walk = Files.walk(root)) {
      files = walk.filter(p -> p.toString().endsWith(".xml")).sorted().toList();
    }
    assertTrue(files.size() >= 250, "OASIS fixtures must be available offline");
    return files.stream()
        .map(
            path ->
                DynamicTest.dynamicTest(
                    root.relativize(path).toString(),
                    () -> {
                      var xml = new XmlCodec();
                      var binary = new TtlvCodec();
                      var json = new JsonCodec();
                      List<Ttlv> nodes =
                          xml.decodeAll(
                              resolve(Files.readString(path)).getBytes(StandardCharsets.UTF_8));
                      assertFalse(nodes.isEmpty());
                      for (Ttlv node : nodes) {
                        byte[] bytes = binary.encode(node);
                        assertEquals(node, binary.decode(bytes), "binary round trip");
                        assertEquals(node, xml.decode(xml.encode(node)), "XML round trip");
                        assertEquals(node, json.decode(json.encode(node)), "JSON round trip");
                      }
                    }));
  }
}
