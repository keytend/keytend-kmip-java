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

import java.util.Objects;

/**
 * The two halves of a key pair on the server, from {@link KeyPairCreation} or {@link
 * KmsKeys#keyPair(String)}: either way the SDK has established that the two keys belong together,
 * so applications cannot pair arbitrary keys. Immutable and thread-safe.
 *
 * @since 0.10.0
 */
public final class KeyPairHandle {
  private final KeyHandle privateKey;
  private final KeyHandle publicKey;

  KeyPairHandle(KeyHandle privateKey, KeyHandle publicKey) {
    this.privateKey = Objects.requireNonNull(privateKey, "privateKey");
    this.publicKey = Objects.requireNonNull(publicKey, "publicKey");
  }

  /**
   * The private key.
   *
   * @return the private key's handle
   */
  public KeyHandle privateKey() {
    return privateKey;
  }

  /**
   * The public key.
   *
   * @return the public key's handle
   */
  public KeyHandle publicKey() {
    return publicKey;
  }

  /**
   * Encrypts with the public key without additional data.
   *
   * @param spec how to encrypt, for example {@link CipherSpec#rsaOaep(Hash)}
   * @param plaintext the data to encrypt
   * @return the ciphertext, which names the public key
   */
  public Ciphertext encrypt(CipherSpec spec, byte[] plaintext) {
    return publicKey.encrypt(spec, plaintext);
  }

  /**
   * Encrypts with the public key (for example {@link CipherSpec#rsaOaep(Hash)}).
   *
   * @param spec how to encrypt
   * @param plaintext the data to encrypt
   * @param aad the additional data to bind (RSA-OAEP from KMIP 1.4, as the label); null or empty
   *     for none
   * @return the ciphertext, which names the public key
   */
  public Ciphertext encrypt(CipherSpec spec, byte[] plaintext, byte[] aad) {
    return publicKey.encrypt(spec, plaintext, aad);
  }

  /**
   * Decrypts with the private key a ciphertext made with either key of this pair, with an expected
   * spec (see {@link KeyHandle#decrypt(CipherSpec, Ciphertext, byte[])}). The private key is read
   * first: a Compromised or Destroyed key is refused (use {@code
   * privateKey().allowingCompromised().decrypt(...)} for forensic recovery).
   *
   * @param spec the spec the ciphertext must have been made with
   * @param ciphertext the ciphertext
   * @param aad the additional data given when encrypting; null or empty for none
   * @return the plaintext, a new array
   * @throws KeyMismatchException when the ciphertext names a key outside this pair, or the private
   *     key does not permit decryption
   * @throws StateConflictException when the private key is Compromised or Destroyed
   */
  public byte[] decrypt(CipherSpec spec, Ciphertext ciphertext, byte[] aad) {
    Objects.requireNonNull(spec, "spec");
    Objects.requireNonNull(ciphertext, "ciphertext");
    KeyHandle.check(spec, ciphertext, aad, false);
    String keyId = ciphertext.keyId();
    if (!keyId.equals(publicKey.id()) && !keyId.equals(privateKey.id()))
      throw KeyMismatchException.ciphertext(
          "decrypt: the ciphertext was made with key " + keyId + ", which is not in this pair",
          "decrypt",
          privateKey.id());
    return privateKey.decryptForPair(spec, ciphertext, aad);
  }

  /**
   * Revokes both keys, the private key first, as {@link KeyHandle#revoke} does: a compromise reason
   * makes them Compromised, any other reason deactivates them (a Revoke up to KMIP 2.1, the draft's
   * Deactivate on 3.0, where a Revoke would compromise them; {@link #deactivate} is the verb for
   * retiring a pair). After a compromise of the private
   * key, the public key then refuses verification by its own state too, also where its link to the
   * private key cannot be followed. Both requests share one call deadline. A failure revoking the
   * public key leaves the private key revoked; repeat {@code publicKey().revoke(reason)}.
   *
   * @param reason why the keys are revoked
   * @throws StateConflictException as {@link KeyHandle#revoke} for each key: for a compromise, when
   *     the server refuses because the private key is Compromised already ({@link
   *     StateConflictException#observedState()} {@code COMPROMISED}; nothing is sent for the public
   *     key: compromise it with {@code publicKey().revoke(reason)})
   */
  public void revoke(RevocationReason reason) {
    Objects.requireNonNull(reason, "reason");
    privateKey.kms.run(
        "revoke",
        () -> {
          privateKey.revoke(reason);
          publicKey.revoke(reason);
        });
  }

  /**
   * Deactivates both keys without compromising them: {@link #deactivate(RevocationReason)} with
   * {@link RevocationReason#unspecified()}.
   *
   * @throws KmsException as {@link #deactivate(RevocationReason)}
   * @since 0.10.0
   */
  public void deactivate() {
    deactivate(RevocationReason.unspecified());
  }

  /**
   * Deactivates both keys, the private key first, as {@link KeyHandle#deactivate(RevocationReason)}
   * does: a Revoke with {@code reason} up to KMIP 2.1, the draft's Deactivate on 3.0 (where a Revoke
   * would compromise them), and a refusal that may be about a key's state read back. The pair then
   * no longer signs or encrypts; it still verifies and decrypts what it protected where the
   * server's policy allows (see {@link KeyHandle#deactivate(RevocationReason)}). Both requests share
   * one call deadline. A
   * failure deactivating the public key leaves the private key Deactivated; repeat {@code
   * publicKey().deactivate(reason)}.
   *
   * @param reason why, not a compromise (usually {@link RevocationReason#superseded}); recorded as
   *     the Revocation Reason up to KMIP 2.1
   * @throws IllegalArgumentException when {@code reason} is a compromise, before anything is sent:
   *     {@link #revoke} handles a compromise
   * @throws StateConflictException when the server refuses because of a key's state
   * @since 0.10.0
   */
  public void deactivate(RevocationReason reason) {
    Objects.requireNonNull(reason, "reason");
    if (reason.compromise())
      throw new IllegalArgumentException(
          "deactivate: "
              + reason.kind()
              + " makes the keys Compromised, not Deactivated; use revoke(reason)");
    privateKey.kms.run(
        "deactivate",
        () -> {
          privateKey.deactivate(reason);
          publicKey.deactivate(reason);
        });
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof KeyPairHandle k
        && k.privateKey.equals(privateKey)
        && k.publicKey.equals(publicKey);
  }

  @Override
  public int hashCode() {
    return Objects.hash(privateKey, publicKey);
  }

  @Override
  public String toString() {
    return "KeyPairHandle[private " + privateKey.id() + ", public " + publicKey.id() + "]";
  }
}
