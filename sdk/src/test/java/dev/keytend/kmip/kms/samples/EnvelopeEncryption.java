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
 * A2. Envelope encryption: data is encrypted locally with a fresh data-encryption key (DEK); the
 * DEK is wrapped by a key-encryption key (KEK) that never leaves the KMS, because it is created
 * non-extractable (KMIP 1.4 and later: the server refuses to return its value), and the wrapped
 * DEK is stored next to the data. {@link CurrentKey#seal} does all of it and returns one versioned,
 * bounded container; the record's identity is the additional data, so neither the DEK nor the data
 * can be moved to another record. One server request to seal, two to open, whatever the data size.
 * The KEK is followed through {@link KmsKeys#current(KeyHandle)}, so sealing moves to a newer key
 * after a rotation.
 */
public final class EnvelopeEncryption {
  private EnvelopeEncryption() {}

  /**
   * Creates the server-held KEK once. Wrapping uses the KMIP Encrypt and Decrypt operations, which
   * servers authorize with the Encrypt and Decrypt usages; nothing here ever needs the KEK's value,
   * so it is created with Extractable false, and an existing KEK without it is refused. KMIP 1.4
   * introduced the attribute: below 1.4 it cannot be asked for, and the KEK stays on the server only
   * because nothing gets it, so provision that policy (access control) on the server.
   */
  public static KeyHandle createKek(Kms kms, String name) {
    KeyCreation kek = kms.keys().createAes(256).named(name).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
    if (kms.version().atLeast(KmipVersion.V1_4)) kek.extractable(false);
    return kek.findOrCreate();
  }

  /** Encrypts {@code plaintext} for the record identified by {@code recordId}; store the result. */
  public static byte[] seal(CurrentKey kek, byte[] plaintext, byte[] recordId) {
    return kek.seal(plaintext, recordId);
  }

  /** Decrypts what {@link #seal} stored for {@code recordId}, with the current KEK or an older one. */
  public static byte[] open(CurrentKey kek, byte[] sealed, byte[] recordId) {
    return kek.open(sealed, recordId);
  }

  /** The same, naming the KEK by name only: it keeps working after the KEK is rotated. */
  public static byte[] openByName(Kms kms, String kekName, byte[] sealed, byte[] recordId) {
    return kms.keys().open(KeyQuery.byName(kekName), sealed, recordId);
  }
}
