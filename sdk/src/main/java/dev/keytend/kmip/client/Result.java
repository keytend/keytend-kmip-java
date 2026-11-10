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
 * A batch result, including failure, pending and undone states, extensions and opaque correlation.
 *
 * @since 0.10.0
 */
public record Result(
    Operation operation, int status, Integer reason, String message, Ttlv batchItem) {
  public boolean successful() {
    return status == 0;
  }

  /** The Result Status as a constant; empty only for a status outside the KMIP range. */
  public Optional<Enums.ResultStatus> statusEnum() {
    return Enums.ResultStatus.fromCode(status);
  }

  /** The Result Reason as a constant; empty for Success/Pending or a vendor/unknown code. */
  public Optional<Enums.ResultReason> reasonEnum() {
    return reason == null ? Optional.empty() : Enums.ResultReason.fromCode(reason);
  }

  /** Null-safe comparison: {@code result.hasReason(ResultReason.ITEM_NOT_FOUND)}. */
  public boolean hasReason(Enums.ResultReason expected) {
    return reason != null && reason == expected.code();
  }

  public boolean pending() {
    return status == 2;
  }

  /**
   * The raw Operation code of the batch item, also for vendor or future codes that have no {@link
   * #operation()} constant; empty for a message-level failure.
   */
  public OptionalInt operationCode() {
    return batchItem
        .child(OPERATION)
        .filter(n -> n.type() == Ttlv.Type.ENUMERATION)
        .map(n -> OptionalInt.of(n.intValue()))
        .orElse(OptionalInt.empty());
  }

  public Optional<Ttlv> payload() {
    return batchItem.child(RESPONSE_PAYLOAD);
  }

  /**
   * The payload of a successful result.
   *
   * @throws KmipException when the result is not Success
   * @throws IllegalStateException when a successful result has no payload; the {@code KmipClient}
   *     convenience methods report that as a {@link ProtocolException} instead
   */
  public Ttlv requirePayload() {
    requireSuccess();
    return payload().orElseThrow(() -> new IllegalStateException("Response has no payload"));
  }

  public Optional<byte[]> asynchronousCorrelation() {
    return batchItem.child(ASYNCHRONOUS_CORRELATION_VALUE).map(Ttlv::bytesValue);
  }

  public Optional<byte[]> batchId() {
    return batchItem.child(UNIQUE_BATCH_ITEM_ID).map(Ttlv::bytesValue);
  }

  public Result requireSuccess() {
    if (!successful()) throw new KmipException(this);
    return this;
  }

  public String uniqueIdentifier() {
    return requirePayload().require(UNIQUE_IDENTIFIER).textValue();
  }

  @Override
  public String toString() {
    return "Result[operation=" + operation + ", status=" + status + ", reason=" + reason + "]";
  }
}
