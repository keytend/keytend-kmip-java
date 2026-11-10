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

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * What a server says about itself in reply to Query ({@link Kms#serverInfo()}): its vendor, its
 * server information, and the operations and object types it implements. For diagnostics and
 * support bundles: a server may implement less than it lists, so it is no guarantee.
 *
 * <p>Operations and object types are KMIP wire names, such as {@code "Create"} and {@code
 * "SymmetricKey"}; a code this SDK does not name is written {@code 0x} and eight hexadecimal digits.
 * Immutable, so thread-safe.
 *
 * @since 0.10.0
 */
public final class ServerInfo {
  private final String vendor;
  private final Map<String, List<String>> information;
  private final List<String> operations, objectTypes;

  ServerInfo(
      String vendor,
      Map<String, List<String>> information,
      List<String> operations,
      List<String> objectTypes) {
    this.vendor = vendor;
    this.information = copy(information);
    this.operations = List.copyOf(operations);
    this.objectTypes = List.copyOf(objectTypes);
  }

  private static Map<String, List<String>> copy(Map<String, List<String>> values) {
    Map<String, List<String>> out = new java.util.LinkedHashMap<>();
    values.forEach((k, v) -> out.put(k, List.copyOf(v)));
    return java.util.Collections.unmodifiableMap(out);
  }

  /**
   * The Vendor Identification.
   *
   * @return the vendor; empty when the server did not give one
   */
  public Optional<String> vendor() {
    return Optional.ofNullable(vendor);
  }

  /**
   * The Server Information structure, flattened: each value under its path of wire tag names,
   * such as {@code "ServerName"} or {@code "Build.Version"}, in the server's order. A field the
   * server repeats keeps every value. Text is as sent, a byte string is {@code "(N bytes)"}, and
   * other values are written as text.
   *
   * @return the fields, unmodifiable; empty when the server gave none
   */
  public Map<String, List<String>> serverInformation() {
    return information;
  }

  /**
   * The operations the server lists, in its order.
   *
   * @return the wire names, unmodifiable
   */
  public List<String> operations() {
    return operations;
  }

  /**
   * The object types the server lists, in its order.
   *
   * @return the wire names, unmodifiable
   */
  public List<String> objectTypes() {
    return objectTypes;
  }

  @Override
  public String toString() {
    return "ServerInfo["
        + (vendor == null ? "no vendor" : vendor)
        + ", "
        + operations.size()
        + " operations, "
        + objectTypes.size()
        + " object types]";
  }
}
