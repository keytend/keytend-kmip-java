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

/**
 * A mutation failed after the request may have reached the server (lost connection, timeout,
 * cancellation or an invalid response). It may or may not have taken effect. The SDK never re-sends
 * a mutation, so check the server's state, for example by locating the object, before you repeat
 * it. See <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/getting-started.md#handle-failures">Handle
 * failures</a>.
 *
 * @since 0.10.0
 */
public final class OutcomeUnknownException extends KmsException {
  OutcomeUnknownException(
      String message,
      Throwable cause,
      String operation,
      String objectId,
      Result result,
      Ttlv response) {
    super(message, cause, operation, objectId, result, response);
  }

  /**
   * For application code and tests: a failure with {@code message} and no protocol details.
   *
   * @param message the detail message, or null
   */
  public OutcomeUnknownException(String message) {
    this(message, null);
  }

  /**
   * For application code and tests: a failure with {@code message} and {@code cause}.
   *
   * @param message the detail message, or null
   * @param cause the cause, or null
   */
  public OutcomeUnknownException(String message, Throwable cause) {
    super(message, cause, "", null, null, null);
  }
}
