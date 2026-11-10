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
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;
import org.junit.jupiter.api.Test;

class IndependentCodecTest {
  @Test
  void binaryBytesMatchIndependentOvhEncoder() throws Exception {
    Map<Path, List<dev.keytend.kmip.model.Ttlv>> decoded = new HashMap<>();
    var xml = new XmlCodec();
    var binary = new TtlvCodec();
    int count = 0;
    for (String line : Files.readAllLines(Path.of("src/test/resources/oracle.tsv"))) {
      if (line.startsWith("#")) continue;
      String[] parts = line.split("\t");
      Path file = Path.of("src/test/resources/oasis", parts[0]);
      List<dev.keytend.kmip.model.Ttlv> nodes = decoded.get(file);
      if (nodes == null) {
        nodes =
            xml.decodeAll(
                OasisVectorsTest.resolve(Files.readString(file)).getBytes(StandardCharsets.UTF_8));
        decoded.put(file, nodes);
      }
      byte[] wire = binary.encode(nodes.get(Integer.parseInt(parts[1])));
      String actual = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(wire));
      assertEquals(parts[2], actual, parts[0] + " message " + parts[1]);
      count++;
    }
    assertEquals(2712, count);
  }
}
