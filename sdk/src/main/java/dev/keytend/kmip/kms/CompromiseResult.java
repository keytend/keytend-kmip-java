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
import java.util.List;
import java.util.Optional;

/**
 * What a replacement after a compromise did ({@link
 * KeyHandle#replaceCompromisedResult(RevocationReason, CompromisePlan)}): whether this call
 * revoked the key, whether it made the replacement or finished with one that existed, which
 * Compromised descendant it replaced in turn, and the compromise date in effect, which is another
 * responder's when that one revoked the key first. Each fact is this call's own only when a reply
 * confirmed it: a step whose reply was lost is {@link #recoveredFrom()}, and does not make the
 * others uncertain.
 *
 * <pre>{@code
 * CompromisePlan plan = key.compromisePlan();
 * // show plan.attributes(), existingReplacement(), replacedInTurn() and creates(); approved, then:
 * CompromiseResult r = key.replaceCompromisedResult(RevocationReason.keyCompromise(why, since), plan);
 * if (!r.revoked()) log.warn("{} keeps the compromise date {}", r.compromised().id(),
 *     r.compromiseOccurrenceDate().orElse(null));
 * }</pre>
 *
 * <p>Immutable, so thread-safe.
 *
 * @since 0.10.0
 */
public final class CompromiseResult {
  /** What the call did. */
  public enum Outcome {
    /** This call revoked the key, and made its replacement. */
    REPLACED,
    /**
     * The key was Compromised already, and this call made its replacement: the first compromise's
     * reason and dates stay.
     */
    COMPLETED,
    /**
     * This call made no replacement: it finished with one an earlier call, another caller or a
     * rotation made ({@link CompromisePlan#existingReplacement()}), activating it and giving it the
     * names where needed. {@link #revoked()} says whether this call revoked the key.
     */
    EXISTING,
    /**
     * A step's outcome was unknown (its reply was lost: {@link #recoveredFrom()}), and reading back
     * found the key revoked, the fallback Create's key under its temporary name, that key's
     * temporary name removed, the existing replacement activated, or (in the unbound form only) a
     * Re-key's replacement: this call or another caller did that step, and which one cannot be
     * told. The plan-bound form stops
     * instead after a lost Re-key reply. {@link #revoked()} and {@link #created()} still say what
     * this call's confirmed replies did: a confirmed Revoke followed by a lost Re-key is {@code
     * revoked()}, with the replacement not in {@code created()}.
     */
    RECOVERED
  }

  private final Outcome outcome;
  private final KeyHandle compromised, replacement;
  private final boolean revoked;
  private final Instant occurrence;
  private final List<KeyHandle> created, replacedInTurn;
  private final OutcomeUnknownException recoveredFrom;

  CompromiseResult(
      Outcome outcome,
      KeyHandle compromised,
      KeyHandle replacement,
      boolean revoked,
      Instant occurrence,
      List<KeyHandle> created,
      List<KeyHandle> replacedInTurn,
      OutcomeUnknownException recoveredFrom) {
    this.outcome = outcome;
    this.compromised = compromised;
    this.replacement = replacement;
    this.revoked = revoked;
    this.occurrence = occurrence;
    this.created = List.copyOf(created);
    this.replacedInTurn = List.copyOf(replacedInTurn);
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
   * The Compromised key, as an {@link KeyHandle#allowingCompromised()} view: re-seal its records
   * through it.
   *
   * @return the Compromised key
   */
  public KeyHandle compromised() {
    return compromised;
  }

  /**
   * The replacement, Active, with the Compromised key's names.
   *
   * @return the replacement
   */
  public KeyHandle replacement() {
    return replacement;
  }

  /**
   * Whether this call's Revoke took effect, its reply confirming it, so the key has this call's
   * reason and Compromise Occurrence Date. Also with {@link Outcome#RECOVERED} when the step whose
   * reply was lost came later (the Re-key). False when the key was Compromised already, when
   * another caller revoked it at the same moment, and when the Revoke's own reply was lost.
   *
   * @return whether this call revoked the key
   */
  public boolean revoked() {
    return revoked;
  }

  /**
   * The Compromise Occurrence Date in effect on {@link #compromised()}, as read after the
   * revocation: this call's when {@link #revoked()}, otherwise the one the first compromise
   * recorded. Treat data sealed under the key after it as possibly an attacker's.
   *
   * @return the date; empty when the server reports none
   */
  public Optional<Instant> compromiseOccurrenceDate() {
    return Optional.ofNullable(occurrence);
  }

  /**
   * The keys this call created, confirmed by the server's replies: the replacement for {@link
   * Outcome#REPLACED} and {@link Outcome#COMPLETED}, and a key it made that lost to another
   * caller's replacement, which is left Pre-Active, unnamed and unlinked: it never encrypted, so
   * destroy it once you have checked it.
   *
   * @return the keys, unmodifiable; empty when this call created none
   */
  public List<KeyHandle> created() {
    return created;
  }

  /**
   * The Compromised keys this call replaced after {@link #compromised()}, in order, each as an
   * {@link KeyHandle#allowingCompromised()} view: the newest key descending from it was Compromised
   * too ({@link CompromisePlan#replacedInTurn()}), so {@link #replacement()} replaces that key and
   * has its names as well. Re-seal their records too. Each keeps its own first compromise's reason
   * and dates.
   *
   * @return the keys, unmodifiable; empty in the usual case
   */
  public List<KeyHandle> replacedInTurn() {
    return replacedInTurn;
  }

  /**
   * The step whose reply was lost, which reading back went past: for {@link Outcome#RECOVERED},
   * the first of them. Its {@link KmsException#objectId()} names the key it was sent for: the
   * compromised key for its Revoke or Re-key ({@link #compromised()}, or a key {@link
   * #replacedInTurn()}), {@link #replacement()} for the Activate of an existing replacement, and
   * for the removal of the temporary name from the key this call created (then in {@link
   * #created()}). A fallback Create's names none: the key it made was found by the temporary name
   * only this call gave it, which was removed before the key was linked.
   *
   * @return the step whose outcome was unknown; empty when every reply came
   */
  public Optional<OutcomeUnknownException> recoveredFrom() {
    return Optional.ofNullable(recoveredFrom);
  }

  @Override
  public String toString() {
    return "CompromiseResult["
        + outcome
        + ", "
        + compromised.id()
        + " -> "
        + replacement.id()
        + (replacedInTurn.isEmpty()
            ? ""
            : ", also replaced " + replacedInTurn.stream().map(KeyHandle::id).toList())
        + (occurrence == null ? "" : ", compromised from " + occurrence)
        + "]";
  }
}
