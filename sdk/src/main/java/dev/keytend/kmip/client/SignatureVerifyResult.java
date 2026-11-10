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
 * A typed Signature Verify response. A successful call only means the server evaluated the
 * request: the signature is valid only when {@link #valid()} is true. A response with the Validity
 * Indicator Invalid or Unknown is a successful call that must not be treated as a valid signature.
 *
 * <p>This is the view of a verdict: {@link #of(Result)} requires a Validity Indicator. A part of a
 * multi-part (streaming) Signature Verify that has no verdict yet is read with {@link
 * CryptoResult#of(Result)} (as {@link MultipartOperation} does). A Correlation Value in the
 * response does not excuse a missing verdict: only the request makes a call multi-part, and
 * {@link Messages#correlate} checks the response against it.
 *
 * @param validityCode the raw Validity Indicator
 * @since 0.10.0
 */
public record SignatureVerifyResult(String uniqueIdentifier, Integer validityCode) {
  /**
   * Reads a successful Signature Verify result.
   *
   * @throws KmipException when the result is not Success
   * @throws ProtocolException when the payload is malformed or has no Validity Indicator
   */
  public static SignatureVerifyResult of(Result result) throws ProtocolException {
    Ttlv payload = result.requireSuccess().payload().orElse(null);
    if (payload == null)
      throw new ProtocolException(
          "Signature Verify response has no payload", result.batchItem(), null);
    try {
      String id = payload.child(UNIQUE_IDENTIFIER).map(Ttlv::textValue).orElse(null);
      Integer validity = payload.child(VALIDITY_INDICATOR).map(Ttlv::intValue).orElse(null);
      if (validity == null)
        throw new IllegalArgumentException("ResponsePayload missing ValidityIndicator");
      return new SignatureVerifyResult(id, validity);
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new ProtocolException(
          "Malformed Signature Verify response: " + e.getMessage(), result.batchItem(), e);
    }
  }

  /** The Validity Indicator; empty when absent or a vendor code. */
  public Optional<Enums.ValidityIndicator> validity() {
    return validityCode == null ? Optional.empty() : Enums.ValidityIndicator.fromCode(validityCode);
  }

  /** True only for Validity Indicator Valid. */
  public boolean valid() {
    return validity().filter(v -> v == Enums.ValidityIndicator.VALID).isPresent();
  }
}
