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

import dev.keytend.kmip.model.ProtocolVersion;

/**
 * A KMIP protocol version: 1.1 to 1.4, 2.0, 2.1, and 3.0, experimental, which the SDK implements as
 * the OASIS CSD02 draft ({@link #V3_0}).
 *
 * @since 0.10.0
 */
public enum KmipVersion {
  /** KMIP 1.1. */
  V1_1(ProtocolVersion.V1_1),
  /** KMIP 1.2. */
  V1_2(ProtocolVersion.V1_2),
  /** KMIP 1.3. */
  V1_3(ProtocolVersion.V1_3),
  /** KMIP 1.4, the lowest version a {@link Kms} negotiates by default. */
  V1_4(ProtocolVersion.V1_4),
  /** KMIP 2.0. */
  V2_0(ProtocolVersion.V2_0),
  /** KMIP 2.1, the highest version a {@link Kms} negotiates by default. */
  V2_1(ProtocolVersion.V2_1),
  /**
   * KMIP 3.0, the wire version a server negotiates as 3.0: <b>experimental</b>. Today the SDK
   * implements the OASIS Committee Specification Draft 02 (CSD02) of KMIP 3.0. A final 3.0 standard
   * is expected to use the same wire version number, so a server's answer cannot tell the two apart,
   * and this constant names the version rather than the draft. When OASIS publishes KMIP 3.0, this
   * constant follows the standard in a minor release, with no CSD02 dialect kept, and that
   * release's notes list the 3.0 changes; until then a minor release may change what is sent or
   * accepted at 3.0 to follow a later draft. Behavior at 3.0 is outside the compatibility
   * guarantees (see <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/compatibility.md#kmip-versions">KMIP
   * versions</a>).
   *
   * <p>Opt-in: a {@link Kms} negotiates 1.4 to 2.1 unless its configuration names 3.0 ({@link
   * KmsConfig.Builder#maximumVersion(KmipVersion)}, or a {@link
   * KmsConfig.Builder#minimumVersion(KmipVersion) minimum} of 3.0).
   */
  V3_0(ProtocolVersion.V3_0);

  private final ProtocolVersion wire;

  KmipVersion(ProtocolVersion wire) {
    this.wire = wire;
  }

  /**
   * The protocol-layer version.
   *
   * @return the protocol-layer version
   */
  public ProtocolVersion protocolValue() {
    return wire;
  }

  /**
   * Whether this version is {@code other} or later.
   *
   * @param other the version to compare with
   * @return whether this version is {@code other} or later
   */
  public boolean atLeast(KmipVersion other) {
    return compareTo(other) >= 0;
  }

  /**
   * The application version for a protocol-layer one.
   *
   * @param v the protocol-layer version
   * @return the application version
   * @throws IllegalArgumentException when {@code v} is not one of the versions this enum names
   */
  public static KmipVersion fromProtocol(ProtocolVersion v) {
    for (KmipVersion k : values()) if (k.wire == v) return k;
    throw new IllegalArgumentException("Unknown version " + v);
  }

  static KmipVersion of(ProtocolVersion v) {
    return fromProtocol(v);
  }

  @Override
  public String toString() {
    return wire.toString();
  }
}
