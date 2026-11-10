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

import java.time.Instant;
import java.util.Optional;

/**
 * What a rotation did ({@link KeyHandle#rotateIfActiveForResult}, {@link KeyHandle#rotateResult},
 * {@link KeyHandle#rotateOrLatestResult}): rotated the key, found it not due, followed the
 * replacement another caller made, or found a replacement after its own request's outcome was
 * unknown.
 *
 * <p>Immutable, so thread-safe.
 *
 * @since 0.10.0
 */
public final class RotationResult {
  /** What the call did. */
  public enum Outcome {
    /** This call rotated {@link #previous()}: the server's reply to its Re-key named {@link #current()}. */
    ROTATED,
    /**
     * The current key was not due: nothing was sent but reads, and {@link #current()} is {@link
     * #previous()}.
     */
    NOT_DUE,
    /**
     * Another caller replaced {@link #previous()} meanwhile, so this call made no key and {@link
     * #current()} is the lineage's current key. A grace period is still scheduled on {@link
     * #previous()}, as {@link KeyHandle#rotateOrLatest(Rotation)} does.
     */
    FOLLOWED,
    /**
     * This call's Re-key of {@link #previous()} had an unknown outcome (its reply, or the server's
     * refusal, was lost), and reading the keys back found {@link #current()}, a replacement of
     * {@link #previous()}. This call or another caller made it: which one cannot be told. A grace
     * period is scheduled on {@link #previous()} as for {@link #ROTATED}. Count it apart from
     * ROTATED, or check the server's audit log. {@link #recoveredFrom()} is the lost Re-key.
     */
    RECOVERED
  }

  private final Outcome outcome;
  private final KeyHandle previous, current;
  private final Instant deactivation;
  private final OutcomeUnknownException recoveredFrom;

  RotationResult(
      Outcome outcome,
      KeyHandle previous,
      KeyHandle current,
      Instant deactivation,
      OutcomeUnknownException recoveredFrom) {
    this.outcome = outcome;
    this.previous = previous;
    this.current = current;
    this.deactivation = deactivation;
    this.recoveredFrom = recoveredFrom;
  }

  /**
   * What the call did.
   *
   * @return the outcome
   */
  public Outcome outcome() {
    return outcome;
  }

  /**
   * The key the call considered: the lineage's current key when the call started. It is the key
   * the call was made on, or the key that one led to when it had been replaced already.
   *
   * @return the key considered
   */
  public KeyHandle previous() {
    return previous;
  }

  /**
   * The key to use now, Active: {@link #previous()} when {@link Outcome#NOT_DUE}, otherwise its
   * replacement.
   *
   * @return the current key
   */
  public KeyHandle current() {
    return current;
  }

  /**
   * The Deactivation Date of {@link #previous()} after this call's grace period: the date it set,
   * or an earlier one the key had already and kept.
   *
   * @return the date; empty when the call scheduled nothing (no grace period, or {@link
   *     Outcome#NOT_DUE})
   */
  public Optional<Instant> previousDeactivationDate() {
    return Optional.ofNullable(deactivation);
  }

  /**
   * The step whose reply was lost, which reading back went past: this call's Re-key of {@link
   * #previous()} for {@link Outcome#RECOVERED}.
   *
   * @return the step whose outcome was unknown; empty when every reply came
   * @since 0.10.0
   */
  public Optional<OutcomeUnknownException> recoveredFrom() {
    return Optional.ofNullable(recoveredFrom);
  }

  @Override
  public String toString() {
    return "RotationResult["
        + outcome
        + ", "
        + previous.id()
        + (outcome == Outcome.NOT_DUE ? "" : " -> " + current.id())
        + (deactivation == null ? "" : ", deactivates " + deactivation)
        + "]";
  }
}
