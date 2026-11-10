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

import java.util.Objects;

/**
 * The name of a custom or vendor attribute, the same on every version: KMIP 1.x {@code x-Name}
 * and 2.x vendor {@code x} / attribute {@code Name} are both {@code new CustomAttribute("x",
 * "Name")}. Vendors other than {@code x} (client-defined) and {@code y} (server-defined) exist
 * only from KMIP 2.0.
 *
 * @param vendor the vendor: {@code x} for client-defined attributes, {@code y} for server-defined
 *     ones, or (from KMIP 2.0) another vendor identification; not empty
 * @param name the attribute name, not empty
 * @since 0.10.0
 */
public record CustomAttribute(String vendor, String name) {
  /**
   * Checks the components.
   *
   * @param vendor the vendor, not empty
   * @param name the attribute name, not empty
   * @throws IllegalArgumentException when the vendor or the name is empty
   */
  public CustomAttribute {
    Objects.requireNonNull(vendor, "vendor");
    Objects.requireNonNull(name, "name");
    if (vendor.isEmpty() || name.isEmpty()) throw new IllegalArgumentException("Empty name");
  }

  /**
   * A client-defined attribute ({@code x-Name} in KMIP 1.x).
   *
   * @param name the attribute name, without the {@code x-} prefix
   * @return the attribute {@code new CustomAttribute("x", name)}
   */
  public static CustomAttribute client(String name) {
    return new CustomAttribute("x", name);
  }

  @Override
  public String toString() {
    return vendor.equals("x") || vendor.equals("y") ? vendor + "-" + name : vendor + ":" + name;
  }
}
