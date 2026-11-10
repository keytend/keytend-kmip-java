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

import java.util.EnumSet;
import java.util.Set;

/**
 * What the caller will do with a key it takes out of the KMS ({@link
 * KeyHandle#asSecretKey(Expect, LocalUse)}): once the key's value has left the server, nothing
 * there checks its state or usages again, so they are checked before it is handed out. Not a KMIP
 * term: {@link KeyUsage} is the KMIP Cryptographic Usage Mask a key permits; a {@code LocalUse} is
 * one purpose the caller states, checked against the key's state and that mask.
 *
 * <ul>
 *   <li>{@link #ENCRYPT} and {@link #WRAP} protect new data: the key must be Active (KMIP 1.4 §3.22: a
 *       Deactivated or Compromised object "SHALL NOT be used for applying cryptographic protection
 *       (e.g., encryption, signing, wrapping ...)", and a Pre-Active one not at all).
 *   <li>{@link #DECRYPT} and {@link #UNWRAP} process data protected before: the key may be Active
 *       or Deactivated (where the server's policy releases a Deactivated key's value at all), and
 *       Compromised only through {@link KeyHandle#allowingCompromised()}.
 * </ul>
 *
 * Pre-Active, Destroyed and other states are refused for every use. Each use also needs its usage
 * in the key's Cryptographic Usage Mask.
 *
 * @since 0.10.0
 */
public enum LocalUse {
  /** Encrypt new data: an Active key that permits {@link KeyUsage#ENCRYPT}. */
  ENCRYPT(KeyUsage.ENCRYPT, true),
  /** Decrypt data encrypted before: a key that permits {@link KeyUsage#DECRYPT}. */
  DECRYPT(KeyUsage.DECRYPT, false),
  /** Wrap other keys (for example AES key wrap): an Active key that permits {@link KeyUsage#WRAP_KEY}. */
  WRAP(KeyUsage.WRAP_KEY, true),
  /** Unwrap keys wrapped before: a key that permits {@link KeyUsage#UNWRAP_KEY}. */
  UNWRAP(KeyUsage.UNWRAP_KEY, false);

  private final KeyUsage usage;
  private final boolean protecting;

  LocalUse(KeyUsage usage, boolean protecting) {
    this.usage = usage;
    this.protecting = protecting;
  }

  /** The usage the key's Cryptographic Usage Mask must include. */
  KeyUsage usage() {
    return usage;
  }

  /** Whether this use protects new data, which needs an Active key. */
  boolean protecting() {
    return protecting;
  }

  /** The states a key may be in for this use; Compromised also needs {@code allowingCompromised()}. */
  Set<KeyState> states() {
    return protecting
        ? EnumSet.of(KeyState.ACTIVE)
        : EnumSet.of(KeyState.ACTIVE, KeyState.DEACTIVATED, KeyState.COMPROMISED);
  }
}
