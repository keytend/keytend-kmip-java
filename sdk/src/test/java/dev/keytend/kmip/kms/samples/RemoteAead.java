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

/**
 * A3. Remote authenticated encryption: the key stays in the KMS, which performs AES-GCM with
 * additional authenticated data. The {@link Ciphertext} (data, nonce and tag) serializes to bytes
 * for storage; a modified ciphertext, nonce, tag or AAD fails with a typed exception.
 */
public final class RemoteAead {
  private RemoteAead() {}

  public static KeyHandle createKey(Kms kms, String name) {
    return kms.keys().createAes(256).named(name).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
  }

  public static byte[] encryptForStorage(KeyHandle key, byte[] plaintext, byte[] aad) {
    return key.encrypt(CipherSpec.aesGcm(), plaintext, aad).toBytes();
  }

  public static byte[] decryptFromStorage(KeyHandle key, byte[] stored, byte[] aad) {
    return key.decrypt(Ciphertext.fromBytes(stored), aad);
  }

  /** True when tampering was detected (and nothing was returned). */
  public static boolean detectsTampering(KeyHandle key, byte[] stored, byte[] aad) {
    try {
      decryptFromStorage(key, stored, aad);
      return false;
    } catch (CryptographicFailureException tampered) {
      return true;
    }
  }
}
