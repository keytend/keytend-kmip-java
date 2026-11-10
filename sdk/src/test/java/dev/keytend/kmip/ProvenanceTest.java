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

import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

class ProvenanceTest {
  @Test
  void originalFixtureChecksumsMatchTheOasisManifest() throws Exception {
    Path root = Path.of("src/test/resources/oasis");
    String manifest = Files.readString(root.resolve("manifest.json"));
    var entries =
        Pattern.compile(
                "\\\"file\\\": \\\"([^\\\"]+)\\\",.*?\\\"sha256\\\": \\\"([0-9a-f]{64})\\\"",
                Pattern.DOTALL)
            .matcher(manifest);
    int count = 0;
    while (entries.find()) {
      Path file = root.resolve(entries.group(1));
      assertTrue(file.normalize().startsWith(root));
      String hash =
          HexFormat.of()
              .formatHex(MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(file)));
      assertEquals(entries.group(2), hash, entries.group(1));
      count++;
    }
    assertEquals(542, count);
  }
}
