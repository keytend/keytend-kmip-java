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

import java.util.Optional;

/**
 * What a replacement of a named object did ({@link KeyRegistration#replaceResult(KeyHandle,
 * KeyAttributes)}): the new object, which has the name now, and what became of the old one.
 *
 * <p>Immutable, so thread-safe.
 *
 * @since 0.10.0
 */
public final class ReplacementResult {
  private final KeyHandle replacement, previous;
  private final KeyState previousState;
  private final boolean deactivated;
  private final OutcomeUnknownException recoveredFrom, deactivationRecoveredFrom;

  ReplacementResult(
      KeyHandle replacement,
      KeyHandle previous,
      KeyState previousState,
      boolean deactivated,
      OutcomeUnknownException recoveredFrom,
      OutcomeUnknownException deactivationRecoveredFrom) {
    this.replacement = replacement;
    this.previous = previous;
    this.previousState = previousState;
    this.deactivated = deactivated;
    this.recoveredFrom = recoveredFrom;
    this.deactivationRecoveredFrom = deactivationRecoveredFrom;
  }

  /**
   * The new object, Active, with the name.
   *
   * @return the new object
   */
  public KeyHandle replacement() {
    return replacement;
  }

  /**
   * The object that had the name.
   *
   * @return the old object
   */
  public KeyHandle previous() {
    return previous;
  }

  /**
   * The state of {@link #previous()} as this call left it: {@link KeyState#DEACTIVATED} when it
   * deactivated it; the state it read last otherwise, such as Pre-Active, Deactivated or
   * Compromised for an object it left as it was, or the state another caller gave it meanwhile. It
   * is what the call established, not a fresh read: another caller may change it afterwards.
   *
   * @return the state
   */
  public KeyState previousState() {
    return previousState;
  }

  /**
   * Whether this call deactivated {@link #previous()}: it was Active, or became Active at its
   * Activation Date during the call, and the reply to the call's Revoke (Deactivate on the 3.0
   * draft) confirmed it. False for an object the call left as it was, for one another caller
   * retired first (also when the server then refused this call's request, and {@link
   * #previousState()} is Deactivated), and when that request's reply was lost ({@link
   * #deactivationRecoveredFrom()}).
   *
   * @return whether the old object was deactivated by this call
   */
  public boolean deactivatedPrevious() {
    return deactivated;
  }

  /**
   * The first step whose reply was lost, which reading back went past: the Register (the new object
   * was then found by the temporary name only this call uses), or a later step whose effect was
   * read back: the activation, a name's move, or the old object's deactivation.
   *
   * @return the step whose outcome was unknown; empty when every reply came
   * @since 0.10.0
   */
  public Optional<OutcomeUnknownException> recoveredFrom() {
    return Optional.ofNullable(recoveredFrom);
  }

  /**
   * The deactivation of {@link #previous()} when its reply was lost and reading back found the
   * object out of use ({@link #previousState()}): Deactivated, by this call's request or another
   * caller's, or Compromised or destroyed, by another caller meanwhile. Which one cannot be told,
   * so {@link #deactivatedPrevious()} is false. Reported even when an earlier step's reply was lost
   * too, which {@link #recoveredFrom()} holds then.
   *
   * @return the deactivation whose outcome was unknown; empty when its reply came, or the call did
   *     not deactivate the object
   * @since 0.10.0
   */
  public Optional<OutcomeUnknownException> deactivationRecoveredFrom() {
    return Optional.ofNullable(deactivationRecoveredFrom);
  }

  @Override
  public String toString() {
    return "ReplacementResult["
        + previous.id()
        + " -> "
        + replacement.id()
        + ", "
        + previousState
        + "]";
  }
}
