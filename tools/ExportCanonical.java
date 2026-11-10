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

import dev.keytend.kmip.codec.XmlCodec;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.regex.*;

/** Input preparation only: the separate Go process generates the binary oracle. */
public class ExportCanonical {
  public static void main(String[] args) throws Exception {
    Path root = Path.of("sdk/src/test/resources/oasis");
    StringBuilder xml = new StringBuilder("<KMIP>"), index = new StringBuilder();
    var codec = new XmlCodec();
    try (var walk = Files.walk(root)) {
      for (Path path :
          walk.filter(
                  p ->
                      p.toString().endsWith(".xml")
                          && root.relativize(p).toString().startsWith("1."))
              .sorted()
              .toList()) {
        Matcher m = Pattern.compile("\\$NOW([+-]\\d+)?").matcher(Files.readString(path));
        StringBuilder normalized = new StringBuilder();
        while (m.find())
          m.appendReplacement(
              normalized,
              java.time.Instant.ofEpochSecond(
                      1700000000L + (m.group(1) == null ? 0 : Long.parseLong(m.group(1))))
                  .toString());
        m.appendTail(normalized);
        String text =
            normalized
                .toString()
                .replace("</KMIP>\n\n</KMIP>", "</KMIP>")
                .replaceAll("\\$[A-Za-z0-9_]+", "DEADBEEFCAFE");
        int message = 0;
        for (var node : codec.decodeAll(text.getBytes(StandardCharsets.UTF_8))) {
          xml.append(new String(codec.encode(node), StandardCharsets.UTF_8));
          index.append(root.relativize(path)).append('\t').append(message++).append('\n');
        }
      }
    }
    xml.append("</KMIP>");
    Files.createDirectories(Path.of(".cache"));
    Files.writeString(Path.of(".cache/canonical.xml"), xml);
    Files.writeString(Path.of(".cache/canonical-index.tsv"), index);
  }
}
