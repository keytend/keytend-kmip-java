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

package dev.keytend.kmip.kms;

import java.util.*;

/** The attributes shared by the create and register builders. Not thread-safe. */
final class ObjectOptions {
  final Set<KeyUsage> usages = EnumSet.noneOf(KeyUsage.class);
  final List<String> names = new ArrayList<>(), groups = new ArrayList<>();
  final Map<CustomAttribute, Object> custom = new LinkedHashMap<>();

  /** The Extractable and Sensitive attributes asked for (KMIP 1.4); null: not asked. */
  Boolean extractable, sensitive;

  Protection protection() {
    return new Protection(extractable, sensitive);
  }

  /** Copies the other builder's protection (the options of a replacement). */
  void protection(Protection p) {
    extractable = p.extractable();
    sensitive = p.sensitive();
  }

  void name(String name) {
    names.add(Objects.requireNonNull(name, "name"));
  }

  void usages(KeyUsage... values) {
    for (KeyUsage u : values) usages.add(Objects.requireNonNull(u, "usage"));
  }

  void group(String group) {
    groups.add(Objects.requireNonNull(group, "group"));
  }

  void custom(CustomAttribute name, Object value) {
    AttributeReader.encode(Objects.requireNonNull(value, "value"));
    custom.put(Objects.requireNonNull(name, "name"), value instanceof byte[] b ? b.clone() : value);
  }

  /**
   * The custom values as an immutable map with content equality, whatever order they were set in:
   * byte arrays compare by content and dates as they are sent (whole seconds). Part of the {@link
   * KeyCreation#findOrCreate()} single-flight key, which must not change when the builder does.
   */
  Map<CustomAttribute, Object> customValues() {
    Map<CustomAttribute, Object> out = new HashMap<>();
    custom.forEach(
        (k, v) ->
            out.put(
                k,
                v instanceof byte[] b
                    ? java.nio.ByteBuffer.wrap(b.clone()).asReadOnlyBuffer()
                    : v instanceof java.time.Instant i
                        ? i.truncatedTo(java.time.temporal.ChronoUnit.SECONDS)
                        : v));
    return Map.copyOf(out);
  }

  void requireUsages() {
    if (usages.isEmpty()) throw new IllegalArgumentException("At least one usage is required");
  }
}
