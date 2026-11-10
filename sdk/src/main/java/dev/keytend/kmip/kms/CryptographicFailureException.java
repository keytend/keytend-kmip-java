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

import dev.keytend.kmip.client.Result;
import dev.keytend.kmip.model.Ttlv;
import java.util.Objects;

/**
 * A cryptographic operation failed. {@link #kind()} separates a confirmed authentication failure
 * (tampering, or the wrong key or additional data) from an ambiguous server error and from a
 * stored ciphertext that was rejected before anything was sent.
 *
 * @since 0.10.0
 */
public final class CryptographicFailureException extends KmsException {
  /** Why the operation failed. */
  public enum Kind {
    /**
     * The server reported Cryptographic Failure for an authenticated decryption or unwrap: the tag
     * or integrity check did not verify. The ciphertext, IV, tag, header or additional data
     * changed, or another key or additional data was used.
     */
    AUTHENTICATION_FAILED,
    /**
     * The server rejected an authenticated decryption with a generic reason (Invalid Field or
     * General Failure). Some servers report a tag mismatch this way, but it can also be a server
     * fault: treat the data as unverified, and do not conclude it was tampered with. Its {@link
     * #category()} is {@link KmsException.Category#SERVER}, not {@code BAD_DATA}.
     */
    UNCONFIRMED,
    /**
     * The stored ciphertext was rejected before anything was sent: it is malformed, or its spec,
     * IV or tag does not match the expected spec, or it names a mode that is not tamper-evident.
     */
    INVALID_CIPHERTEXT,
    /** Any other Cryptographic Failure result, for example from signing or RSA decryption. */
    OTHER
  }

  /** Why the operation failed. */
  private final Kind kind;

  CryptographicFailureException(
      String message,
      Throwable cause,
      String operation,
      String objectId,
      Result result,
      Ttlv response) {
    this(message, cause, operation, objectId, result, response, Kind.OTHER);
  }

  CryptographicFailureException(
      String message,
      Throwable cause,
      String operation,
      String objectId,
      Result result,
      Ttlv response,
      Kind kind) {
    super(
        message,
        cause,
        operation,
        objectId,
        result,
        response,
        Objects.requireNonNull(kind, "kind") == Kind.UNCONFIRMED ? Category.SERVER : null);
    this.kind = kind;
  }

  /**
   * For application code and tests: a failure of {@code kind} with {@code message}.
   *
   * @param message the detail message, or null
   * @param kind why the operation failed
   */
  public CryptographicFailureException(String message, Kind kind) {
    this(message, null, "", null, null, null, kind);
  }

  /**
   * Why the operation failed.
   *
   * @return the kind; never null
   */
  public Kind kind() {
    return kind;
  }
}
