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

import java.util.Arrays;

/**
 * Supported major/minor wire versions. V3_0 targets OASIS Committee Specification Draft 02.
 *
 * @since 0.10.0
 */
public enum ProtocolVersion {
  V1_1(1, 1),
  V1_2(1, 2),
  V1_3(1, 3),
  V1_4(1, 4),
  V2_0(2, 0),
  V2_1(2, 1),
  /**
   * KMIP 3.0, experimental: implemented as the OASIS Committee Specification Draft 02, and to follow
   * the standard when OASIS publishes it, as {@code dev.keytend.kmip.kms.KmipVersion.V3_0} says.
   */
  V3_0(3, 0);
  private final int major, minor;

  ProtocolVersion(int major, int minor) {
    this.major = major;
    this.minor = minor;
  }

  public int major() {
    return major;
  }

  public int minor() {
    return minor;
  }

  public int code() {
    return major * 10 + minor;
  }

  public boolean atLeast(ProtocolVersion other) {
    return code() >= other.code();
  }

  public boolean legacyAttributes() {
    return major == 1;
  }

  public static ProtocolVersion of(int major, int minor) {
    return Arrays.stream(values())
        .filter(v -> v.major == major && v.minor == minor)
        .findFirst()
        .orElseThrow(
            () -> new IllegalArgumentException("Unsupported KMIP version " + major + "." + minor));
  }

  public static ProtocolVersion fromCode(int code) {
    return of(code / 10, code % 10);
  }

  @Override
  public String toString() {
    return major + "." + minor;
  }
}
