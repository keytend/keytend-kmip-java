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

package dev.keytend.kmip.codec;

import java.io.IOException;
import java.io.Serial;

/**
 * Malformed TTLV, XML or JSON input: a protocol violation by the peer, not a transport failure.
 *
 * <p>The message is fixed text that may name tags and types but never a value from the input,
 * because decoded values can be key material or credentials. A cause is kept only as its type
 * and stack trace ({@link #redact}); messages of underlying parser exceptions, which often echo
 * the offending input, are dropped. {@code KmipClient} reports a decode failure of a response as
 * a {@code ProtocolException} without the response.
 *
 * @since 0.10.0
 */
public class DecodeException extends IOException {
  @Serial private static final long serialVersionUID = 1L;

  /** @param message fixed text; never include decoded or peer-supplied values */
  public DecodeException(String message) {
    super(message);
  }

  /**
   * @param message fixed text; never include decoded or peer-supplied values
   * @param cause kept as {@link #redact redacted}: type and stack trace only
   */
  public DecodeException(String message, Throwable cause) {
    super(message, redact(cause));
  }

  /**
   * A copy of {@code cause} and its cause chain that keeps each exception's type and stack trace
   * but not its message or suppressed exceptions, for causes whose text may echo peer input. A
   * {@code DecodeException} in the chain keeps its message, which is fixed text by contract.
   * Returns null for null.
   */
  public static Throwable redact(Throwable cause) {
    return cause == null ? null : new Redacted(cause, 0);
  }

  /** A stand-in naming the original exception type; its message holds no input text. */
  private static final class Redacted extends Exception {
    @Serial private static final long serialVersionUID = 1L;

    Redacted(Throwable original, int depth) {
      super(
          original instanceof Redacted
              ? original.getMessage()
              // A DecodeException's message is fixed text by contract.
              : original instanceof DecodeException
                  ? original.getClass().getName() + ": " + original.getMessage()
                  : original.getClass().getName() + " (message withheld)",
          original.getCause() == null || original.getCause() == original || depth >= 16
              ? null
              : new Redacted(original.getCause(), depth + 1),
          false,
          true);
      setStackTrace(original.getStackTrace());
    }
  }
}
