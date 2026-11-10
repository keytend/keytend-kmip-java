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

package dev.keytend.kmip.client;

import static dev.keytend.kmip.model.Tag.*;

import dev.keytend.kmip.model.*;
import java.util.*;

/**
 * The typed payload of a successful cryptographic operation. Byte arrays are copied on every
 * access; fields the operation does not return are empty.
 *
 * <p>For Signature Verify and MAC Verify a successful call does not mean the signature or MAC
 * matched: check {@link #valid()} (true only for Validity Indicator Valid).
 *
 * @since 0.10.0
 */
public final class CryptoResult {
  private final Operation operation;
  private final String uniqueIdentifier;
  private final byte[] data, iv, tag, signature, mac, correlation;
  private final Integer validity;

  private CryptoResult(Operation operation, Ttlv payload) {
    this.operation = operation;
    uniqueIdentifier = payload.child(UNIQUE_IDENTIFIER).map(Ttlv::textValue).orElse(null);
    data = bytes(payload, DATA);
    iv = bytes(payload, IV_COUNTER_NONCE);
    tag = bytes(payload, AUTHENTICATED_ENCRYPTION_TAG);
    signature = bytes(payload, SIGNATURE_DATA);
    mac = bytes(payload, MAC_DATA);
    correlation = bytes(payload, CORRELATION_VALUE);
    validity = payload.child(VALIDITY_INDICATOR).map(Ttlv::intValue).orElse(null);
  }

  private static byte[] bytes(Ttlv payload, Tag tag) {
    return payload.child(tag).map(Ttlv::bytesValue).orElse(null);
  }

  /**
   * @throws KmipException when the result is not Success
   * @throws ProtocolException for a malformed payload, or a final Signature Verify or MAC Verify
   *     response without a Validity Indicator
   */
  public static CryptoResult of(Result result) throws ProtocolException {
    result.requireSuccess();
    try {
      Ttlv payload = result.payload().orElseThrow(() -> new IllegalArgumentException("no payload"));
      CryptoResult r = new CryptoResult(result.operation(), payload);
      if ((r.operation == Operation.SIGNATURE_VERIFY || r.operation == Operation.MAC_VERIFY)
          && r.validity == null
          && r.correlation == null) throw new IllegalArgumentException("missing ValidityIndicator");
      return r;
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new ProtocolException(
          "Malformed " + result.operation() + " response: " + e.getMessage(),
          result.batchItem(),
          e);
    }
  }

  public Operation operation() {
    return operation;
  }

  public Optional<String> uniqueIdentifier() {
    return Optional.ofNullable(uniqueIdentifier);
  }

  private static Optional<byte[]> copy(byte[] b) {
    return Optional.ofNullable(b == null ? null : b.clone());
  }

  /** Ciphertext (Encrypt), plaintext (Decrypt), recovered data or random bytes. */
  public Optional<byte[]> data() {
    return copy(data);
  }

  /** The IV, counter or nonce the server chose (Encrypt with a random IV). */
  public Optional<byte[]> ivCounterNonce() {
    return copy(iv);
  }

  /** The AEAD tag (Encrypt with GCM/CCM). */
  public Optional<byte[]> authenticatedEncryptionTag() {
    return copy(tag);
  }

  public Optional<byte[]> signatureData() {
    return copy(signature);
  }

  public Optional<byte[]> macData() {
    return copy(mac);
  }

  /** Present between parts of a multi-part operation. */
  public Optional<byte[]> correlationValue() {
    return copy(correlation);
  }

  public Optional<Enums.ValidityIndicator> validity() {
    return validity == null ? Optional.empty() : Enums.ValidityIndicator.fromCode(validity);
  }

  /** True only when the Validity Indicator is Valid. */
  public boolean valid() {
    return validity().filter(v -> v == Enums.ValidityIndicator.VALID).isPresent();
  }

  /** Names the operation; data is not shown. */
  @Override
  public String toString() {
    return "CryptoResult[" + operation + "]";
  }
}
