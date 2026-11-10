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
 * The object to create or register conflicts with an existing one (KMIP Object Already Exists or
 * Non Unique Name Attribute): for example a server that enforces unique names already has a key
 * with this name. A {@link StateConflictException} whose {@link #conflict()} is {@link
 * StateConflictException.Conflict#NAME}.
 *
 * @since 0.10.0
 */
public final class AlreadyExistsException extends StateConflictException {
  AlreadyExistsException(
      String message,
      Throwable cause,
      String operation,
      String objectId,
      Result result,
      Ttlv response) {
    super(message, cause, operation, objectId, result, response);
    because(Conflict.NAME);
  }

  /**
   * For application code and tests: a failure with {@code message} and no protocol details.
   *
   * @param message the detail message, or null
   */
  public AlreadyExistsException(String message) {
    this(message, null, "", null, null, null);
  }

  /**
   * For application code and tests: a failure with {@code message} and {@code cause}.
   *
   * @param message the detail message, or null
   * @param cause the cause, or null
   */
  public AlreadyExistsException(String message, Throwable cause) {
    this(message, cause, "", null, null, null);
  }
}
