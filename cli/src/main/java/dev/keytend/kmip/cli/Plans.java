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

import dev.keytend.kmip.kms.KeyAttributes;
import dev.keytend.kmip.kms.KeyState;
import java.util.List;

/** Sentences and refusals that several commands' plans share. */
final class Plans {
  private Plans() {}

  /** What a Deactivated key can and cannot do, as plan lines. */
  static final List<String> DEACTIVATED =
      List.of(
          "  it no longer encrypts, wraps, signs or computes MACs; it still decrypts, unwraps and"
              + " verifies",
          "  where the server's policy allows. KMIP has no way back to Active.");

  /**
   * Whether {@code state} is a destroyed state.
   *
   * @param state the state
   * @return true for Destroyed and Destroyed Compromised
   */
  static boolean destroyed(KeyState state) {
    return state == KeyState.DESTROYED || state == KeyState.DESTROYED_COMPROMISED;
  }

  /**
   * The refusal to deactivate a Pre-Active key, which KMIP does not allow.
   *
   * @param a the key's attributes
   * @param c the command's context, for the suggested commands
   * @return the exception to throw (exit code 6)
   */
  static CliException preActive(KeyAttributes a, Context c) {
    return new CliException(
        ExitCode.STATE_CONFLICT,
        a.id()
            + " is Pre-Active: it encrypts nothing, and KMIP has no transition from Pre-Active to"
            + " Deactivated",
        "destroy it ("
            + c.suggest("destroy", a.id())
            + "), or activate it first ("
            + c.suggest("activate", a.id())
            + ")");
  }
}
