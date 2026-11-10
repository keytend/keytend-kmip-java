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

/**
 * What {@link CurrentKey#rewrapRecord} and {@link KeyHandle#rewrapRecordTo} did with a sealed
 * record: the record to store, and whether it changed. A re-sealing job writes only changed
 * records:
 *
 * <pre>{@code
 * Rewrapped moved = kek.rewrapRecord(r.sealed(), r.aad());
 * if (moved.changed()) store.put(r.id(), moved.bytes());
 * }</pre>
 *
 * @since 0.10.0
 */
public final class Rewrapped {
  private final byte[] bytes;
  private final boolean changed;
  private final String keyId;

  Rewrapped(byte[] bytes, boolean changed, String keyId) {
    this.bytes = bytes;
    this.changed = changed;
    this.keyId = keyId;
  }

  /**
   * The record to store: sealed under the target key. When not {@link #changed()}, the array the
   * call was given (not a copy).
   *
   * @return the record under the target key: a new array when {@link #changed()}, otherwise the
   *     caller's own array
   */
  public byte[] bytes() {
    return bytes;
  }

  /**
   * Whether the record was re-sealed: false when it was sealed under the target key already, and
   * then nothing was sent (for a target of the same {@code Kms}) and {@link #bytes()} is the record given (not authenticated: {@link
   * KeyHandle#open} it to check it).
   *
   * @return whether the record was re-sealed
   */
  public boolean changed() {
    return changed;
  }

  /**
   * The identifier of the key the record is sealed under now ({@link KmsKeys#sealedKeyId}).
   *
   * @return the key identifier
   */
  public String keyId() {
    return keyId;
  }

  @Override
  public String toString() {
    return "Rewrapped["
        + (changed ? "changed" : "unchanged")
        + ", key "
        + keyId
        + ", "
        + bytes.length
        + " bytes]";
  }
}
