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

package dev.keytend.kmip.model;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Operation payload requirements from the version-specific OASIS tables. Conditional rules are
 * preserved as prose.
 *
 * @since 0.10.0
 */
public final class ProtocolSchema {
  public enum Direction {
    REQUEST,
    RESPONSE
  }

  public record Field(String name, String requirement, Optional<Tag> tag) {}

  private static final Map<String, List<Field>> FIELDS = load();

  private ProtocolSchema() {}

  public static List<Field> fields(
      ProtocolVersion version, Operation operation, Direction direction) {
    return FIELDS.getOrDefault(
        version.code()
            + ":"
            + operation.wireName()
            + ":"
            + direction.name().toLowerCase(Locale.ROOT),
        List.of());
  }

  private static Map<String, List<Field>> load() {
    Map<String, List<Field>> fields = new HashMap<>();
    try (InputStream in =
        ProtocolSchema.class.getResourceAsStream("/dev/keytend/kmip/payloads.tsv")) {
      if (in == null) throw new IOException("Missing operation schemas");
      for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
        String[] cells = line.split("\t", -1);
        if (cells.length < 5) continue;
        Optional<Tag> tag;
        try {
          tag = Optional.of(Tag.fromName(cells[3]));
        } catch (IllegalArgumentException e) {
          tag = Optional.empty();
        }
        fields
            .computeIfAbsent(
                cells[0] + ":" + cells[1] + ":" + cells[2], ignored -> new ArrayList<>())
            .add(new Field(cells[3], cells[4], tag));
      }
    } catch (IOException e) {
      throw new ExceptionInInitializerError(e);
    }
    fields.replaceAll((k, v) -> List.copyOf(v));
    return Map.copyOf(fields);
  }
}
