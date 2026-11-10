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

/** The process exit codes, documented in the module's README. */
enum ExitCode {
  /** The command did what it was asked, or found nothing to do. */
  OK(0),
  /**
   * The command failed, for a reason without a code of its own below: a server or local failure,
   * such as standard output that could not be written.
   */
  FAILED(1),
  /**
   * The command line or the configuration file is wrong, or the SDK refused a setting or a value
   * before anything was sent; nothing was changed. A check that needs the object, such as whether
   * it is a symmetric key, may have read it first.
   */
  USAGE(2),
  /** A change may or may not have taken effect: check before repeating it. */
  OUTCOME_UNKNOWN(3),
  /** The object does not exist. */
  NOT_FOUND(4),
  /** The server denied access: the client identity or the object's access policy. */
  PERMISSION_DENIED(5),
  /** The object's state, or an existing object, conflicts with the command. */
  STATE_CONFLICT(6),
  /** Some steps of a multi-step change were made, then one failed. */
  PARTIAL(7),
  /** The server could not be reached, or was busy. */
  UNAVAILABLE(8),
  /** The change was not confirmed: no --yes, and no confirmation at the console. */
  NOT_CONFIRMED(9);

  final int code;

  ExitCode(int code) {
    this.code = code;
  }
}
