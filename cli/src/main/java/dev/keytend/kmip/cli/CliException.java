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

package dev.keytend.kmip.cli;

import java.util.Map;

/** A failure the tool reports itself, with its exit code and an optional hint. */
final class CliException extends RuntimeException {
  private static final long serialVersionUID = 1L;

  final ExitCode exit;
  final String hint;

  /** Extra fields of the JSON error; empty for most failures. */
  final transient Map<String, Object> details;

  CliException(ExitCode exit, String message) {
    this(exit, message, null, null);
  }

  CliException(ExitCode exit, String message, String hint) {
    this(exit, message, hint, null);
  }

  CliException(ExitCode exit, String message, String hint, Throwable cause) {
    this(exit, message, hint, cause, Map.of());
  }

  CliException(
      ExitCode exit, String message, String hint, Throwable cause, Map<String, Object> details) {
    super(message, cause);
    this.exit = exit;
    this.hint = hint;
    this.details = Map.copyOf(details);
  }

  static CliException usage(String message) {
    return new CliException(ExitCode.USAGE, message);
  }
}
