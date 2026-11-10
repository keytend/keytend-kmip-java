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

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

/**
 * How a rotation treats the old key and the replacement: an optional grace period that schedules
 * the old key's deactivation ({@link #grace(Duration)}), and the lifecycle dates the replacement
 * gets ({@link #dates(RotationDates)}). Immutable, so thread-safe: keep one as the policy of a
 * scheduled job, and pass it to the rotation calls of {@link KeyHandle} and {@link CurrentKey}.
 *
 * <pre>{@code
 * static final Rotation POLICY = Rotation.grace(Duration.ofDays(7));
 * // in one scheduled job, run daily: a new key every 30 days, and
 * // each old key stops encrypting 7 days after it was replaced
 * kek.rotateIfActiveFor(Duration.ofDays(30), POLICY);
 * }</pre>
 *
 * <p><b>The grace period.</b> After the Re-key, the old key gets a Deactivation Date of now plus
 * the grace period, by this machine's clock. Until then it stays Active, so instances that still
 * hold it keep sealing. Then it no longer encrypts, and still decrypts where the server's policy
 * allows (see {@link KeyHandle#deactivate()}). A {@link CurrentKey} that still holds it moves to
 * the current key on its first refused seal. A grace period never extends a key's life: an earlier
 * Deactivation Date stays. Without one ({@link #of(RotationDates)}), the old key stays Active until
 * {@link KeyHandle#deactivatePredecessors()} or {@link KeyHandle#retirePredecessors}.
 *
 * <p><b>A server that will not schedule it.</b> Some servers do not let a client set a Deactivation
 * Date. The rotation has happened then, and the old key stays Active. The call ends in a {@link
 * PartialCompletionException} whose message names both keys. Run {@link
 * KeyHandle#deactivatePredecessors()} from the current key once the grace period is over.
 *
 * @see <a
 *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#rotation-with-a-grace-period">Rotation
 *     with a grace period</a>
 * @since 0.10.0
 */
public final class Rotation {
  private final RotationDates dates;
  private final Duration grace;
  private final Protection protection;

  private Rotation(RotationDates dates, Duration grace, Protection protection) {
    this.dates = dates;
    this.grace = grace;
    this.protection = protection;
  }

  /**
   * A rotation without a grace period, giving the replacement the dates {@code dates} asks for.
   *
   * @param dates the replacement's dates
   * @return the rotation
   */
  public static Rotation of(RotationDates dates) {
    return new Rotation(Objects.requireNonNull(dates, "dates"), null, Protection.NONE);
  }

  /**
   * A rotation that schedules the old key's deactivation {@code grace} after the rotation, with
   * {@link RotationDates#COPIED} dates for the replacement.
   *
   * @param grace how long the old key stays Active after the rotation; {@link Duration#ZERO}
   *     deactivates it at once
   * @return the rotation
   * @throws IllegalArgumentException when {@code grace} is negative
   */
  public static Rotation grace(Duration grace) {
    Objects.requireNonNull(grace, "grace");
    if (grace.isNegative())
      throw new IllegalArgumentException("grace must not be negative: " + grace);
    return new Rotation(RotationDates.COPIED, grace, Protection.NONE);
  }

  /**
   * This rotation, giving the replacement the dates {@code dates} asks for.
   *
   * @param dates the replacement's dates
   * @return a new rotation; this one is unchanged
   */
  public Rotation dates(RotationDates dates) {
    return new Rotation(Objects.requireNonNull(dates, "dates"), grace, protection);
  }

  /**
   * This rotation, giving the replacement the KMIP Extractable attribute {@code extractable} (see
   * {@link KeyCreation#extractable(boolean)}). The Re-key carries it.
   *
   * <p>Without it, a KMIP Re-key copies the old key's Extractable and Sensitive values, and the
   * rotation checks that it did. A replacement that does not state Extractable false where the old
   * key does, or Sensitive true where the old key does, is not activated or returned ({@link
   * PartialCompletionException}, the cause a {@link KeyMismatchException}). With it, the
   * replacement must state this value instead. Only a replacement the call makes is checked, not
   * one that {@link KeyHandle#rotateOrLatest(Rotation)} returns because another call made it.
   *
   * @param extractable the replacement's Extractable attribute
   * @return a new rotation; this one is unchanged
   * @throws UnsupportedException (from the rotation, before anything is sent) below KMIP 1.4, which
   *     has no Extractable attribute
   * @since 0.10.0
   */
  public Rotation extractable(boolean extractable) {
    return new Rotation(dates, grace, new Protection(extractable, protection.sensitive()));
  }

  /**
   * This rotation, giving the replacement the KMIP Sensitive attribute {@code sensitive} (see
   * {@link KeyCreation#sensitive(boolean)}), checked as for {@link #extractable(boolean)}.
   *
   * @param sensitive the replacement's Sensitive attribute
   * @return a new rotation; this one is unchanged
   * @throws UnsupportedException (from the rotation, before anything is sent) below KMIP 1.4
   * @since 0.10.0
   */
  public Rotation sensitive(boolean sensitive) {
    return new Rotation(dates, grace, new Protection(protection.extractable(), sensitive));
  }

  /** The protection asked for the replacement; {@link Protection#NONE}: the old key's is kept. */
  Protection protection() {
    return protection;
  }

  /**
   * The dates the replacement gets.
   *
   * @return the dates
   */
  public RotationDates rotationDates() {
    return dates;
  }

  /**
   * The grace period after which the old key is deactivated; empty when none is scheduled.
   *
   * @return the grace period; empty when the rotation schedules no deactivation
   */
  public Optional<Duration> gracePeriod() {
    return Optional.ofNullable(grace);
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof Rotation r
        && r.dates == dates
        && Objects.equals(r.grace, grace)
        && r.protection.equals(protection);
  }

  @Override
  public int hashCode() {
    return Objects.hash(dates, grace, protection);
  }

  @Override
  public String toString() {
    return "Rotation["
        + dates
        + (grace == null ? "" : ", grace " + grace)
        + (protection.any() ? ", " + protection : "")
        + "]";
  }
}
