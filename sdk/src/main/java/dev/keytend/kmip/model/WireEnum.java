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

/**
 * An extensible KMIP enumeration; use numeric values for vendor extensions.
 *
 * @since 0.10.0
 */
public interface WireEnum {
  int code();

  String wireName();

  /** The first protocol version that defines this value. Generated constants override this. */
  default ProtocolVersion since() {
    return ProtocolVersion.V1_1;
  }

  /**
   * Whether {@code version} defines this value: from {@link #since()} on, unless that version's
   * table turned it into Reserved (for example Cryptographic Usage Mask Export, or Key Format Type
   * Transparent ECDSA Private Key, from 2.0). Generated constants override this.
   */
  default boolean definedIn(ProtocolVersion version) {
    return version.atLeast(since());
  }
}
