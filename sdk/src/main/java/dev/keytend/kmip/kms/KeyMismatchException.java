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
 * The server's object is not what the caller asked for, or a stored ciphertext names a key outside
 * the expected lineage, query or key pair. The first covers a different identity, object type,
 * algorithm, size or usages, an unexpected format, wrapped material, or a {@link KeyQuery} that
 * matches no object at all ({@link KmsException.Category#FIX_REQUEST}). The second is a
 * relabeled or misfiled record ({@link KmsException.Category#BAD_DATA}).
 *
 * @since 0.10.0
 */
public final class KeyMismatchException extends KmsException {
  KeyMismatchException(
      String message,
      Throwable cause,
      String operation,
      String objectId,
      Result result,
      Ttlv response) {
    super(message, cause, operation, objectId, result, response);
  }

  private KeyMismatchException(
      String message, String operation, String objectId, Category category) {
    super(message, null, operation, objectId, null, null, category);
  }

  /**
   * A stored ciphertext or sealed container names a key outside the expected lineage, query or
   * pair: the record was relabeled or misfiled. {@link Category#BAD_DATA}, unlike a key of the
   * wrong kind or usages, which is the caller's to fix.
   */
  static KeyMismatchException ciphertext(String message, String operation, String objectId) {
    return new KeyMismatchException(message, operation, objectId, Category.BAD_DATA);
  }

  /**
   * For application code and tests: a failure with {@code message} and no protocol details.
   *
   * @param message the detail message, or null
   */
  public KeyMismatchException(String message) {
    this(message, (Throwable) null);
  }

  /**
   * For application code and tests: a failure with {@code message} and {@code cause}.
   *
   * @param message the detail message, or null
   * @param cause the cause, or null
   */
  public KeyMismatchException(String message, Throwable cause) {
    super(message, cause, "", null, null, null);
  }

  /**
   * For application code and tests: a failure with {@code message} and either category this
   * exception has, {@link Category#FIX_REQUEST} (what the other constructors give) or {@link
   * Category#BAD_DATA} (a record that names a key outside the expected lineage, query or pair), so
   * that a handler keyed on {@link #category()} can be tested for both.
   *
   * @param message the detail message, or null
   * @param category {@link Category#FIX_REQUEST} or {@link Category#BAD_DATA}
   * @throws IllegalArgumentException for any other category
   */
  public KeyMismatchException(String message, Category category) {
    this(message, "", null, requireOwn(category));
  }

  private static Category requireOwn(Category category) {
    if (Objects.requireNonNull(category, "category") != Category.FIX_REQUEST
        && category != Category.BAD_DATA)
      throw new IllegalArgumentException(
          "A KeyMismatchException is FIX_REQUEST or BAD_DATA, not " + category);
    return category;
  }
}
