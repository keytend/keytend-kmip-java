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

import dev.keytend.kmip.model.*;

/**
 * A KMIP operation result other than Success; the original result remains inspectable.
 *
 * <p>This unchecked exception is the operation-failure path: the server answered, and the answer
 * was Failed, Pending or Undone. Transport and protocol problems use the checked {@link
 * java.io.IOException} path ({@link ProtocolException} for a response that was received but
 * rejected). The message names the operation (or "message-level" for a failure of the whole
 * request) and the symbolic status and reason with their codes. The server's Result Message is
 * peer-controlled text, so it is not part of the message (which ends up in logs); read it with
 * {@code result().message()}.
 *
 * @since 0.10.0
 */
public final class KmipException extends RuntimeException {
  private final Result result;

  public KmipException(Result result) {
    super(describe(result));
    this.result = result;
  }

  public Result result() {
    return result;
  }

  /** The reason as a constant; empty for no reason or a vendor code. */
  public java.util.Optional<Enums.ResultReason> reason() {
    return result.reasonEnum();
  }

  private static String describe(Result result) {
    String operation =
        result.operation() != null
            ? result.operation().wireName()
            : result.operationCode().stream()
                .mapToObj(code -> String.format("operation 0x%08X", code))
                .findFirst()
                .orElse("message-level");
    StringBuilder b = new StringBuilder("KMIP ").append(operation).append(" returned ");
    b.append(result.statusEnum().map(WireEnum::wireName).orElse("status"));
    b.append(" (").append(result.status()).append(")");
    if (result.reason() != null) {
      b.append(", reason ");
      b.append(result.reasonEnum().map(WireEnum::wireName).orElse("vendor"));
      b.append(String.format(" (0x%08X)", result.reason()));
    }
    return b.toString();
  }
}
