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

import dev.keytend.kmip.model.Enums;

/**
 * A managed object's lifecycle state (KMIP State attribute).
 *
 * @since 0.10.0
 */
public enum KeyState {
  /** Created but not yet usable for protecting data (KMIP Pre-Active). */
  PRE_ACTIVE(Enums.State.PRE_ACTIVE),
  /** Usable for every permitted operation (KMIP Active). */
  ACTIVE(Enums.State.ACTIVE),
  /**
   * Past its use for protecting data; servers may still allow processing old data with it (KMIP
   * Deactivated).
   */
  DEACTIVATED(Enums.State.DEACTIVATED),
  /** Revoked as compromised (KMIP Compromised). */
  COMPROMISED(Enums.State.COMPROMISED),
  /** Its key material is destroyed; the object and its attributes may remain (KMIP Destroyed). */
  DESTROYED(Enums.State.DESTROYED),
  /** Destroyed, and compromised before or after that (KMIP Destroyed Compromised). */
  DESTROYED_COMPROMISED(Enums.State.DESTROYED_COMPROMISED),
  /** A vendor or future state; {@link KeyAttributes#rawState()} has the code. */
  UNKNOWN(null);

  private final Enums.State wire;

  KeyState(Enums.State wire) {
    this.wire = wire;
  }

  /**
   * The KMIP State (protocol layer), or null for {@link #UNKNOWN}.
   *
   * @return the KMIP value, or null for {@link #UNKNOWN}
   */
  public Enums.State protocolValue() {
    return wire;
  }

  static KeyState of(int code) {
    for (KeyState s : values()) if (s.wire != null && s.wire.code() == code) return s;
    return UNKNOWN;
  }
}
