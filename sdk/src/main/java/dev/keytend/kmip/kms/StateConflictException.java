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
 * The object's state forbids the operation (for example destroying an Active key, or using a
 * Pre-Active one), or the object conflicts with an existing one. {@link #conflict()} says which
 * kind of conflict it is, so code that reacts to it switches on that:
 *
 * <pre>{@code
 * } catch (StateConflictException e) {
 *   switch (e.conflict()) {
 *     case NOT_AS_PLANNED -> showTheNewPlan();          // nothing was changed
 *     case REPLACED -> retryWith(key.latest());          // another caller rotated it
 *     default -> throw e;
 *   }
 * }
 * }</pre>
 *
 * @since 0.10.0
 */
public sealed class StateConflictException extends KmsException permits AlreadyExistsException {
  /**
   * The kind of a {@link StateConflictException}: what the operation found in the way. Each SDK
   * method that throws one documents its refusals under these kinds.
   *
   * @since 0.10.0
   */
  public enum Conflict {
    /**
     * The object's lifecycle state forbids the operation: {@link #observedState()} is that state
     * when the client read it. Also a refusal the server gave for the object's state, and the
     * kind of an exception made by application code.
     */
    STATE,
    /**
     * The key was replaced: rotated already, or by another caller at the same moment, so an
     * operation on a lineage's newest key was refused. {@link KeyHandle#latest()} finds the
     * current key.
     */
    REPLACED,
    /**
     * A call bound to a plan (a plan object, the attributes a plan was made from, or an expected
     * current key) found other objects than the plan named, or found them in other states. Nothing
     * was changed: make a new plan.
     */
    NOT_AS_PLANNED,
    /**
     * About a name: it is taken ({@link AlreadyExistsException}), the object does not have it,
     * several objects have it and which one is meant cannot be decided, or it is being moved
     * between keys.
     */
    NAME,
    /**
     * About the links between keys: a rotation lineage cannot be followed (a link cannot be
     * resolved), is wider than one walk reads, has several newest keys, or would be cut; or an
     * object is not linked as the operation needs (a certificate without its private key).
     */
    LINEAGE,
    /**
     * A key was created to replace the key and is not linked to it: {@link
     * KeyHandle#compromisePlan()} refuses to plan a second replacement beside it, which would
     * leave it unaccounted for. {@link #objectId()} names that key. It is an earlier call's (its
     * Create's reply was lost, or it stopped before the links), or another caller's being made now.
     *
     * @since 0.10.0
     */
    UNLINKED_REPLACEMENT
  }

  /** Set once, before the exception is thrown ({@link #observed}). */
  private KeyState observedState;

  /** Set once, before the exception is thrown ({@link #because}). */
  private Conflict conflict = Conflict.STATE;

  StateConflictException(
      String message,
      Throwable cause,
      String operation,
      String objectId,
      Result result,
      Ttlv response) {
    super(message, cause, operation, objectId, result, response);
  }

  /**
   * The state of the object {@link #objectId()} names, as this client read it for the refusal: for
   * example {@link KeyState#COMPROMISED} or {@link KeyState#DEACTIVATED} when a rotation refuses a
   * key (start the compromise runbook for the first, page for the second), or the state of a key
   * whose refusal the client read back after the server's. Empty when the refusal is not about a
   * state the client read (a name conflict, a refusal by the server alone, a refusal about several
   * keys). The state the server reports, as {@link KeyHandle#attributes()} would give it then; it
   * may have changed since. {@link #serverReason()} stays the server's own reason, empty for a
   * refusal the client made before sending.
   *
   * @return the state the client read for the refusal; empty when the refusal is not about one
   */
  public java.util.Optional<KeyState> observedState() {
    return java.util.Optional.ofNullable(observedState);
  }

  /** This exception, with {@link #observedState()} {@code state}; for the SDK's own refusals. */
  StateConflictException observed(KeyState state) {
    observedState = state;
    return this;
  }

  /**
   * The kind of conflict: what the operation found in the way. The method that threw the
   * exception documents which kinds it gives. A refusal by the server alone is {@link
   * Conflict#STATE}, or {@link Conflict#NAME} for an {@link AlreadyExistsException}.
   *
   * @return the kind of conflict
   * @since 0.10.0
   */
  public Conflict conflict() {
    return conflict;
  }

  /** This exception, with {@link #conflict()} {@code kind}; for the SDK's own refusals. */
  StateConflictException because(Conflict kind) {
    conflict = java.util.Objects.requireNonNull(kind, "kind");
    return this;
  }

  /**
   * For application code and tests: a failure with {@code message} and no protocol details.
   *
   * @param message the detail message, or null
   */
  public StateConflictException(String message) {
    this(message, (Throwable) null);
  }

  /**
   * For application code and tests: a failure with {@code message} and {@code cause}.
   *
   * @param message the detail message, or null
   * @param cause the cause, or null
   */
  public StateConflictException(String message, Throwable cause) {
    super(message, cause, "", null, null, null);
  }

  /**
   * For application code and tests: a failure with {@code message} and the kind {@code conflict},
   * so that a handler that switches on {@link #conflict()} can be tested for each kind, such as
   * {@link Conflict#NOT_AS_PLANNED}, without a race against a server.
   *
   * @param message the detail message, or null
   * @param conflict the kind of conflict
   * @since 0.10.0
   */
  public StateConflictException(String message, Conflict conflict) {
    this(message, (Throwable) null);
    this.conflict = java.util.Objects.requireNonNull(conflict, "conflict");
  }
}
