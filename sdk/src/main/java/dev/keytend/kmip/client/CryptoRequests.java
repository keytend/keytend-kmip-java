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
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.model.*;
import java.util.*;

/**
 * Typed builders for the server-side cryptographic operations: Encrypt, Decrypt, Sign, Signature
 * Verify, MAC, MAC Verify and RNG Retrieve. Read the result with {@link CryptoResult#of(Result)}.
 *
 * <p>Multi-part (streaming) operations: send the first part with {@link Builder#init()}, keep
 * {@link CryptoResult#correlationValue()}, and send later parts with {@link
 * Builder#continuing(byte[])} and the last one also with {@link Builder#last()}.
 *
 * <pre>{@code
 * Request encrypt = CryptoRequests.encrypt(keyId)
 *     .parameters(CryptoParameters.aesGcm()).data(plaintext).aad(aad).build();
 * CryptoResult out = CryptoResult.of(client.call(encrypt));
 * }</pre>
 *
 * @since 0.10.0
 */
public final class CryptoRequests {
  private CryptoRequests() {}

  public static Builder encrypt(String keyId) {
    return new Builder(Operation.ENCRYPT, keyId);
  }

  public static Builder decrypt(String keyId) {
    return new Builder(Operation.DECRYPT, keyId);
  }

  public static Builder sign(String keyId) {
    return new Builder(Operation.SIGN, keyId);
  }

  public static Builder signatureVerify(String keyId) {
    return new Builder(Operation.SIGNATURE_VERIFY, keyId);
  }

  public static Builder mac(String keyId) {
    return new Builder(Operation.MAC, keyId);
  }

  public static Builder macVerify(String keyId) {
    return new Builder(Operation.MAC_VERIFY, keyId);
  }

  /** RNG Retrieve of {@code length} bytes. */
  public static Request rngRetrieve(int length) {
    if (length < 1) throw new IllegalArgumentException("Length must be positive");
    return Requests.rngRetrieve().add(integer(DATA_LENGTH, length)).build();
  }

  /** One cryptographic request. Field setters check that the operation takes the field. */
  public static final class Builder {
    private final Operation operation;
    private final String keyId;
    private CryptoParameters parameters;
    private byte[] data, digested, iv, aad, tag, signature, mac, correlation;
    private Boolean init, last;

    private Builder(Operation operation, String keyId) {
      this.operation = operation;
      this.keyId = keyId;
    }

    private Builder only(boolean allowed, String field) {
      if (!allowed)
        throw new IllegalArgumentException(operation.wireName() + " does not take " + field);
      return this;
    }

    public Builder parameters(CryptoParameters value) {
      parameters = value;
      return this;
    }

    public Builder data(byte[] value) {
      data = value.clone();
      return this;
    }

    /** Sign / Signature Verify over a precomputed digest; exclusive with {@link #data}. */
    public Builder digestedData(byte[] value) {
      only(operation == Operation.SIGN || operation == Operation.SIGNATURE_VERIFY, "DigestedData");
      digested = value.clone();
      return this;
    }

    /** IV, counter or nonce (Encrypt / Decrypt). */
    public Builder iv(byte[] value) {
      only(operation == Operation.ENCRYPT || operation == Operation.DECRYPT, "IVCounterNonce");
      iv = value.clone();
      return this;
    }

    /** AEAD additional data (Encrypt / Decrypt, KMIP 1.4+). */
    public Builder aad(byte[] value) {
      only(
          operation == Operation.ENCRYPT || operation == Operation.DECRYPT,
          "AuthenticatedEncryptionAdditionalData");
      aad = value.clone();
      return this;
    }

    /** AEAD tag to verify (Decrypt, KMIP 1.4+). */
    public Builder tag(byte[] value) {
      only(operation == Operation.DECRYPT, "AuthenticatedEncryptionTag");
      tag = value.clone();
      return this;
    }

    /** Signature to verify (Signature Verify). */
    public Builder signature(byte[] value) {
      only(operation == Operation.SIGNATURE_VERIFY, "SignatureData");
      signature = value.clone();
      return this;
    }

    /** MAC to verify (MAC Verify). */
    public Builder macData(byte[] value) {
      only(operation == Operation.MAC_VERIFY, "MACData");
      mac = value.clone();
      return this;
    }

    /** First part of a multi-part operation (KMIP 1.3+). */
    public Builder init() {
      init = true;
      return this;
    }

    /** A later part, continuing the stream identified by {@code correlationValue}. */
    public Builder continuing(byte[] correlationValue) {
      correlation = correlationValue.clone();
      return this;
    }

    /** The final part of a multi-part operation. */
    public Builder last() {
      last = true;
      return this;
    }

    public Request build() {
      if (data != null && digested != null)
        throw new IllegalArgumentException("Data and DigestedData are mutually exclusive");
      Request.Builder b = Request.operation(operation);
      if (keyId != null) b.uniqueIdentifier(keyId);
      if (parameters != null) b.add(parameters.toTtlv());
      if (data != null) b.data(data);
      if (digested != null) b.add(bytes(DIGESTED_DATA, digested));
      if (iv != null) b.add(bytes(IV_COUNTER_NONCE, iv));
      if (signature != null) b.add(bytes(SIGNATURE_DATA, signature));
      if (mac != null) b.add(bytes(MAC_DATA, mac));
      if (correlation != null) b.add(bytes(CORRELATION_VALUE, correlation));
      if (init != null) b.add(bool(INIT_INDICATOR, init));
      if (last != null) b.add(bool(FINAL_INDICATOR, last));
      if (aad != null) b.add(bytes(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA, aad));
      if (tag != null) b.add(bytes(AUTHENTICATED_ENCRYPTION_TAG, tag));
      return b.build();
    }
  }
}
