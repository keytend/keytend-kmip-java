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

package dev.keytend.kmip.kms.samples;

import dev.keytend.kmip.kms.*;
import java.util.List;

/**
 * A5. Key lifecycle and rotation: create a named key, activate it, rotate it (KMIP Re-key), find
 * the current key by name, read its attributes as a typed record (the same code on 1.x and 2.x),
 * keep decrypting old data (the current key, and a lookup by name, both accept ciphertexts of the
 * key it replaced), re-encrypt it under the new key, and only then retire and destroy the old
 * key.
 */
public final class LifecycleRotation {
  private LifecycleRotation() {}

  public record Rotation(KeyHandle previous, KeyHandle current, KeyAttributes currentAttributes) {}

  public static KeyHandle create(Kms kms, String name) {
    KeyHandle key =
        kms.keys().createAes(256).named(name).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
    key.activate();
    return key;
  }

  /**
   * Re-keys, then finds the replacement among the Active keys with the name. (Servers differ in
   * which of the two keys keeps the name; {@link KeyHandle#latest()} follows the Replacement links
   * instead, on servers that record them.)
   */
  public static Rotation rotate(Kms kms, KeyHandle current, String name) {
    KeyHandle replacement = current.rotate();
    List<KeyHandle> active = kms.keys().list(KeyQuery.byName(name).state(KeyState.ACTIVE));
    if (!active.contains(replacement))
      throw new IllegalStateException("The replacement is not an Active key named " + name + ": " + active);
    return new Rotation(current, replacement, replacement.attributes());
  }

  /**
   * Re-encrypts data written before the rotation with the current key alone: it decrypts
   * ciphertexts of the key it replaced while that key exists (Deactivated keys may decrypt), and
   * encrypts the result.
   */
  public static Ciphertext reencrypt(Rotation rotation, Ciphertext old, byte[] aad) {
    byte[] plaintext = rotation.current().decrypt(old, aad);
    return rotation.current().encrypt(CipherSpec.aesGcm(), plaintext, aad);
  }

  /**
   * Reads data written before the rotation by the key's name, as the README quickstart does: the
   * key that encrypted it, or the key that replaced it, has the name.
   */
  public static byte[] readByName(Kms kms, String name, Ciphertext old, byte[] aad) {
    return kms.keys().decrypt(KeyQuery.byName(name), old, aad);
  }

  /**
   * Retires the previous key once nothing new is encrypted with it: revoke it if it is still
   * Active (some servers deactivate a replaced key themselves). It keeps decrypting old data.
   */
  public static KeyAttributes retire(KeyHandle previous) {
    if (previous.attributes().state() == KeyState.ACTIVE)
      previous.revoke(RevocationReason.superseded("rotated"));
    return previous.attributes();
  }

  /** Destroys the retired key after all its data was re-encrypted. */
  public static void destroyRetired(KeyHandle previous) {
    previous.destroy();
  }
}
