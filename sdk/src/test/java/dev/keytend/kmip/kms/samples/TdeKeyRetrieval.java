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
import java.time.Instant;
import java.util.Optional;
import javax.crypto.SecretKey;

/**
 * A1. A database loads its transparent-data-encryption key at startup.
 *
 * <p>The Active key is found by name (or used by identifier), validated as a 256-bit AES key with
 * the expected identity, and returned as a JCA {@link SecretKey}. A Compromised or Destroyed key is
 * refused rather than loaded. A missing key, a permission problem
 * and an unreachable KMS are handled differently, and a failed read never leads to creating a
 * replacement key: a new key would make the existing data unreadable.
 *
 * <p>The incident procedure after a compromise ({@link #replaceCompromised}, {@link #reseal},
 * {@link #reencrypt}): revoke the key as Compromised and get an Active replacement that the name
 * finds, in one call ({@code KeyHandle.replaceCompromised}), then re-open each
 * record with the compromised key named explicitly, {@code
 * kms.keys().handle(oldId).allowingCompromised()}, and seal or encrypt it again under the
 * replacement. The compromised key is not used for anything else.
 *
 * <p>This sample loads one key at startup. {@link #loadByName} returns the current key, which is
 * right for encrypting new data, but never for decrypting a file written before a rotation: the
 * name has moved on by then. A database that records the key with each file and follows rotation
 * (Cassandra's commit log and hints) needs the full recipe, sample A8, {@link TdeKeyProvider}:
 * immutable exact-identifier aliases, and one lease-compliant key service per node on {@link
 * LocalKeys}.
 */
public final class TdeKeyRetrieval {
  private TdeKeyRetrieval() {}

  /** What happened, for the caller (and the test) to act on. */
  public enum Status {
    LOADED,
    MISSING,
    /** The key exists but is Compromised or Destroyed: follow the incident procedure. */
    UNUSABLE,
    DENIED,
    UNAVAILABLE
  }

  public record Outcome(Status status, Optional<SecretKey> key, String detail) {}

  /** Loads the key named {@code keyName}. */
  public static Outcome loadByName(Kms kms, String keyName) {
    try {
      Optional<KeyHandle> handle = kms.keys().findByName(keyName);
      if (handle.isEmpty())
        return new Outcome(
            Status.MISSING, Optional.empty(), "No Active key named " + keyName + "; not creating one");
      return load(handle.get(), LocalUse.ENCRYPT);
    } catch (KmsException e) {
      return failed(e);
    }
  }

  /** Loads the key with identifier {@code keyId}. */
  public static Outcome loadById(Kms kms, String keyId) {
    try {
      return load(kms.keys().handle(keyId), LocalUse.DECRYPT);
    } catch (KmsException e) {
      return failed(e);
    }
  }

  /** The compromised key and its Active replacement. */
  public record Replacement(KeyHandle compromised, KeyHandle current) {}

  /**
   * Step 1 of the incident procedure: revoke the key named {@code keyName} as Compromised (since
   * {@code compromisedAt}) and replace it. {@code replaceCompromised} returns the replacement
   * Active, with the name, so the database's next start loads the new key. (Not {@code rotate()}:
   * it refuses a Compromised key, so that a routine rotation never stands in for this procedure.)
   * If it fails part-way, its message says whether repeating it resumes.
   */
  public static Replacement replaceCompromised(Kms kms, String keyName, Instant compromisedAt) {
    KeyHandle compromised = kms.keys().findByName(keyName).orElseThrow();
    KeyHandle current = compromised.replaceCompromised(RevocationReason.keyCompromise("TDE key exposed", compromisedAt));
    return new Replacement(compromised, current);
  }

  /**
   * Step 2 for sealed records: open with the key the record names, explicitly allowed while
   * Compromised (the replacement's own handle refuses it, even {@code allowingCompromised()}),
   * and seal again under the replacement, without the plaintext leaving the SDK.
   */
  public static byte[] reseal(Kms kms, byte[] sealed, byte[] aad, KeyHandle current) {
    KeyHandle sealedWith = kms.keys().handle(KmsKeys.sealedKeyId(sealed)).allowingCompromised();
    return sealedWith.rewrapTo(current, sealed, aad);
  }

  /** Step 2 for ciphertexts: the same, with {@link Ciphertext#keyId()}. */
  public static Ciphertext reencrypt(Kms kms, Ciphertext old, byte[] aad, KeyHandle current) {
    KeyHandle encryptedWith = kms.keys().handle(old.keyId()).allowingCompromised();
    return current.encrypt(CipherSpec.aesGcm(), encryptedWith.decrypt(old, aad), aad);
  }

  /**
   * The key for {@code use}: the current key (by name) encrypts, a key named by identifier (one
   * recorded with the data) decrypts, so a Deactivated key still loads for reading.
   */
  private static Outcome load(KeyHandle handle, LocalUse use) {
    SecretKey key = handle.asSecretKey(Expect.aes(256), use);
    return new Outcome(Status.LOADED, Optional.of(key), handle.id());
  }

  private static Outcome failed(KmsException e) {
    if (e instanceof NotFoundException)
      // Restore the key from backup; creating a new one would orphan the encrypted data.
      return new Outcome(Status.MISSING, Optional.empty(), e.getMessage());
    if (e instanceof StateConflictException)
      // Compromised or Destroyed: do not use it; re-key under the incident procedure.
      return new Outcome(Status.UNUSABLE, Optional.empty(), e.getMessage());
    if (e instanceof PermissionDeniedException)
      // Fix the database's KMS identity or the key's access policy.
      return new Outcome(Status.DENIED, Optional.empty(), e.getMessage());
    if (e instanceof TransientException)
      // The SDK already retried across endpoints; start later or keep the database read-only.
      return new Outcome(Status.UNAVAILABLE, Optional.empty(), e.getMessage());
    throw e;
  }
}
