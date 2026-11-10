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

import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * A composite call stopped part-way: some steps took effect, then a later one failed. The objects
 * in {@link #created()} exist on the server, and the keys in {@link #deactivated()} and {@link
 * #destroyed()} were changed. {@link #getCause()} is the failed step's failure: a {@link
 * KmsException}, whose {@link KmsException#objectId()} names the object of that step, or the {@link
 * IllegalStateException} of a {@link Kms} closed meanwhile. When the cause is an {@link
 * OutcomeUnknownException}, the step itself may have taken effect.
 *
 * <p>It is never {@link #retryable()}: repeating {@code create()} or {@code register()} would make
 * more objects. Resume as the message says. After a failed activation, it says to activate each
 * created handle that is still Pre-Active ({@code handle.attributes().state()}). When the server
 * did not keep a key's requested protection (Extractable, Sensitive), the message says not to
 * activate it. When reading a created object back failed, it says what to check before activating
 * it. Before you destroy a created object, check that nothing uses it. Some calls differ:
 *
 * <ul>
 *   <li>{@link KeyHandle#retirePredecessors}, {@link KeyHandle#retirePredecessorsOlderThan} and
 *       {@link KeyHandle#deactivatePredecessors} create nothing. They report the keys they changed
 *       before the failure, and are repeated to resume.
 *   <li>{@link KeyCreation#findOrCreate()} and {@link KeyPairCreation#findOrCreate()} are
 *       idempotent, and repeating them activates the key or pair they created.
 *   <li>{@link KeyHandle#replaceCompromised} may be repeated when its message says so.
 *   <li>{@link KeyRegistration#replace(KeyHandle)} reports the new object. Its message says which
 *       object has the name and how to finish or undo the replacement.
 *   <li>{@link KeyHandle#reconcile()} creates nothing ({@link #created()} is empty), and is
 *       repeated to resume.
 *   <li>{@link TlsIdentityRegistration#register()}, {@link TlsIdentityHandle#renew} and {@link
 *       TlsIdentityHandle#rekey} are repeated with the same arguments, unless the message says
 *       otherwise. Activate their {@link #created()} objects only when the message says to: a call
 *       stopped before its switch leaves them out of the identity, and an Active leftover
 *       certificate can match a trust query (<a
 *       href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/tls-identities.md#what-a-stopped-call-leaves">What
 *       a stopped call leaves</a>).
 * </ul>
 *
 * <p>A call that went on with an object it did not confirm creating lists it in {@link #found()},
 * not in {@link #created()}. That is a replacement found by reading back after a step's outcome
 * was unknown ({@link #recoveredFrom()}), which this call or another caller made, or one an
 * earlier call or another caller made. Inspect it before you act on it.
 *
 * <p>No advice in its message says to destroy a key that may be in use.
 *
 * @since 0.10.0
 */
public final class PartialCompletionException extends KmsException {
  /** The objects that were created, in order; unmodifiable. */
  private final List<KeyHandle> created;

  /** The key pair that was created, or null when the call did not create a pair. */
  private final KeyPairHandle pair;

  /** The keys the call deactivated, and destroyed, before the failure; unmodifiable. */
  private final List<KeyHandle> deactivated, destroyed;

  /** The objects the call went on with but did not confirm creating; unmodifiable. */
  private final List<KeyHandle> found;

  /** The earlier step whose outcome was unknown, read back past; null when none. */
  private final OutcomeUnknownException recoveredFrom;

  private PartialCompletionException(
      String message,
      String operation,
      List<KeyHandle> created,
      KeyPairHandle pair,
      RuntimeException cause) {
    this(message, operation, created, pair, List.of(), List.of(), cause);
  }

  private PartialCompletionException(
      String message,
      String operation,
      List<KeyHandle> created,
      KeyPairHandle pair,
      List<KeyHandle> deactivated,
      List<KeyHandle> destroyed,
      RuntimeException cause) {
    this(message, operation, created, pair, deactivated, destroyed, List.of(), null, cause);
  }

  private PartialCompletionException(
      String message,
      String operation,
      List<KeyHandle> created,
      KeyPairHandle pair,
      List<KeyHandle> deactivated,
      List<KeyHandle> destroyed,
      List<KeyHandle> found,
      OutcomeUnknownException recoveredFrom,
      RuntimeException cause) {
    super(
        message,
        cause,
        operation,
        !created.isEmpty()
            ? created.get(0).id()
            : !found.isEmpty()
                ? found.get(0).id()
                : cause instanceof KmsException k ? k.objectId().orElse(null) : null,
        cause instanceof KmsException k ? k.result().orElse(null) : null,
        cause instanceof KmsException k ? k.response().orElse(null) : null);
    this.created = List.copyOf(created);
    this.pair = pair;
    this.deactivated = List.copyOf(deactivated);
    this.destroyed = List.copyOf(destroyed);
    this.found = List.copyOf(found);
    this.recoveredFrom = recoveredFrom;
    if (recoveredFrom != null && recoveredFrom != cause) addSuppressed(recoveredFrom);
  }

  /**
   * For application code and tests: {@code created} exist, and the next step failed with {@code
   * cause}.
   *
   * @param message the detail message, or null
   * @param created the objects that exist on the server (copied; may be empty)
   * @param cause the failure of the step after the creation
   */
  public PartialCompletionException(String message, List<KeyHandle> created, KmsException cause) {
    this(message, "", created, null, Objects.requireNonNull(cause, "cause"));
  }

  /**
   * For application code and tests: the key pair {@code created} exists, and the next step failed
   * with {@code cause}.
   *
   * @param message the detail message, or null
   * @param created the key pair that exists on the server
   * @param cause the failure of the step after the creation
   */
  public PartialCompletionException(String message, KeyPairHandle created, KmsException cause) {
    this(
        message,
        "",
        List.of(created.privateKey(), created.publicKey()),
        created,
        Objects.requireNonNull(cause, "cause"));
  }

  private static String ids(List<KeyHandle> created) {
    return created.stream().map(KeyHandle::id).toList().toString();
  }

  /**
   * The objects that were created (for a key pair: the private key, then the public key).
   *
   * @return the created objects, unmodifiable; empty for {@link KeyHandle#reconcile()}
   */
  public List<KeyHandle> created() {
    return created;
  }

  /**
   * The keys the call deactivated (or revoked) and did not destroy before the failure, in order:
   * for a retirement, the key whose destruction failed when its revocation took effect; for {@link
   * KeyHandle#reconcile()}, the keys it deactivated before its last step failed; for {@link
   * KeyHandle#replaceCompromised}, the key whose Revoke this call's reply confirmed (a Revoke whose
   * reply was lost is {@link #recoveredFrom()} instead).
   *
   * @return the keys, unmodifiable; empty for a call that changed no key's state before it stopped
   * @since 0.10.0
   */
  public List<KeyHandle> deactivated() {
    return deactivated;
  }

  /**
   * The keys the call destroyed before the failure, in the order they were destroyed.
   *
   * @return the keys, unmodifiable; empty for a call that destroys nothing
   * @since 0.10.0
   */
  public List<KeyHandle> destroyed() {
    return destroyed;
  }

  /**
   * The objects the call went on with but did not confirm creating, so they are not in {@link
   * #created()}: a replacement found by reading back after a step's outcome was unknown ({@link
   * #recoveredFrom()} is that step: this call's request or another caller's made it), or one an
   * earlier call or another caller made ({@link KeyHandle#replaceCompromised} finishing an
   * existing replacement). They exist on the server; check each before you activate, use or
   * destroy it.
   *
   * @return the objects, unmodifiable; empty when the call went on only with objects it created
   * @since 0.10.0
   */
  public List<KeyHandle> found() {
    return found;
  }

  /**
   * The earlier step whose outcome was unknown, when the call read the server's state back past it
   * and went on: for example a Re-key whose reply was lost, after which a replacement was found
   * ({@link #found()}). {@link #getCause()} stays the step that stopped the call.
   *
   * @return the step whose outcome was unknown; empty when every earlier step's outcome was known
   * @since 0.10.0
   */
  public Optional<OutcomeUnknownException> recoveredFrom() {
    return Optional.ofNullable(recoveredFrom);
  }

  /**
   * The key pair that was created, when the call created a pair.
   *
   * @return the created key pair; empty when the call did not create a pair
   */
  public Optional<KeyPairHandle> createdPair() {
    return Optional.ofNullable(pair);
  }

  /** After a creation, activation failed; the advice depends on the operation. */
  static PartialCompletionException of(
      String operation, List<KeyHandle> created, KeyPairHandle pair, RuntimeException cause) {
    return of(operation, created, pair, "activation failed", activationAdvice(operation), cause);
  }

  /** What to do when activating what {@code operation} made, or went on with, failed. */
  static String activationAdvice(String operation) {
    return switch (operation) {
      case "findOrCreate" -> "repeat findOrCreate() to resume (it activates the key it created)";
      case "rotate" ->
          "activate the replacement instead of rotating again (rotate() refuses a key that was"
              + " already replaced; latest() finds the replacement)";
      case "replaceCompromised" ->
          "repeat replaceCompromised() to resume (it activates the replacement)";
      default -> "activate the created object(s) instead of repeating the call";
    };
  }

  /**
   * The call went on with {@code found}, which it did not confirm creating ({@link #found()}):
   * found by reading back after {@code recoveredFrom}, or, with {@code recoveredFrom} null, made
   * by an earlier call or another caller. Then the step described by {@code step} failed with
   * {@code cause}; {@code advice} says what to do.
   */
  static PartialCompletionException found(
      String operation,
      List<KeyHandle> found,
      OutcomeUnknownException recoveredFrom,
      String step,
      String advice,
      RuntimeException cause) {
    Objects.requireNonNull(cause, "cause");
    return new PartialCompletionException(
        operation
            + ": "
            + (recoveredFrom != null
                ? "an earlier step's outcome was unknown, and reading back found "
                    + ids(found)
                    + ", which this call or another caller made"
                : "went on with " + ids(found) + ", which an earlier call or another caller made")
            + "; then "
            + step
            + ": "
            + cause.getMessage()
            + "; "
            + advice,
        operation,
        List.of(),
        null,
        List.of(),
        List.of(),
        found,
        recoveredFrom,
        cause);
  }

  /**
   * The failure {@code e} of a composite call after its earlier steps took effect ({@code done}
   * says which, for the message): it lists them too. When {@code e} is itself a partial completion
   * (an inner step's), the facts of both are kept: the objects created, found and deactivated, and
   * the earliest step whose reply was lost ({@code recoveredFrom}, else {@code e}'s; the other is
   * suppressed). Then {@code e}'s cause, message and advice stay; {@code e} is returned as it is
   * when it lists everything already. Otherwise {@code advice} says how to resume.
   */
  static PartialCompletionException withProgress(
      String operation,
      String done,
      List<KeyHandle> created,
      List<KeyHandle> deactivated,
      OutcomeUnknownException recoveredFrom,
      String advice,
      RuntimeException e) {
    Objects.requireNonNull(e, "e");
    if (e instanceof PartialCompletionException p && p.getCause() instanceof RuntimeException c) {
      List<KeyHandle> allCreated = union(p.created, created);
      List<KeyHandle> allDeactivated = union(deactivated, p.deactivated);
      OutcomeUnknownException first = recoveredFrom != null ? recoveredFrom : p.recoveredFrom;
      if (allCreated.equals(p.created)
          && allDeactivated.equals(p.deactivated)
          && first == p.recoveredFrom) return p;
      String inner = p.getMessage();
      String prefix = operation + ": ";
      PartialCompletionException out =
          new PartialCompletionException(
              prefix
                  + done
                  + "; then "
                  + (inner != null && inner.startsWith(prefix)
                      ? inner.substring(prefix.length())
                      : inner),
              operation,
              allCreated,
              p.pair,
              allDeactivated,
              p.destroyed,
              p.found.stream().filter(k -> !allCreated.contains(k)).toList(),
              first,
              c);
      // The constructor suppressed first; p's own recoveredFrom is among p's suppressed.
      for (Throwable s : p.getSuppressed()) if (s != first) out.addSuppressed(s);
      return out;
    }
    return new PartialCompletionException(
        operation + ": " + done + ", then: " + e.getMessage() + "; " + advice,
        operation,
        created,
        null,
        deactivated,
        List.of(),
        List.of(),
        recoveredFrom,
        e);
  }

  /** {@code a}, then those of {@code b} not in it. */
  private static List<KeyHandle> union(List<KeyHandle> a, List<KeyHandle> b) {
    List<KeyHandle> out = new java.util.ArrayList<>(a);
    for (KeyHandle k : b) if (!out.contains(k)) out.add(k);
    return out;
  }

  /**
   * A call that creates nothing ({@link KeyHandle#reconcile()}) stopped part-way: the step
   * described by {@code step} failed with {@code cause}; {@code advice} says how to resume.
   */
  static PartialCompletionException interrupted(
      String operation, String step, String advice, RuntimeException cause) {
    Objects.requireNonNull(cause, "cause");
    return new PartialCompletionException(
        operation + ": " + step + ": " + cause.getMessage() + "; " + advice,
        operation,
        List.of(),
        null,
        cause);
  }

  /**
   * A call that changes existing keys ({@link KeyHandle#retirePredecessors}, {@link
   * KeyHandle#deactivatePredecessors}) stopped part-way: it deactivated {@code deactivated} and
   * destroyed {@code destroyed}, then the step described by {@code step} failed with {@code cause};
   * repeating the call resumes it.
   */
  static PartialCompletionException progress(
      String operation,
      List<KeyHandle> deactivated,
      List<KeyHandle> destroyed,
      String step,
      RuntimeException cause) {
    Objects.requireNonNull(cause, "cause");
    StringBuilder done = new StringBuilder();
    if (!destroyed.isEmpty()) done.append("destroyed ").append(ids(destroyed));
    if (!deactivated.isEmpty())
      done.append(done.length() == 0 ? "" : " and ")
          .append("deactivated ")
          .append(ids(deactivated));
    return new PartialCompletionException(
        operation
            + ": "
            + done
            + ", then "
            + step
            + ": "
            + cause.getMessage()
            + "; repeat "
            + operation
            + "() to continue where it stopped",
        operation,
        List.of(),
        null,
        deactivated,
        destroyed,
        cause);
  }

  /**
   * {@code created} exist and the step described by {@code step} failed with {@code cause}; {@code
   * advice} says what to do instead of repeating the call.
   */
  static PartialCompletionException of(
      String operation,
      List<KeyHandle> created,
      KeyPairHandle pair,
      String step,
      String advice,
      RuntimeException cause) {
    return of(operation, created, pair, step, advice, null, cause);
  }

  /**
   * {@link #of(String, List, KeyPairHandle, String, String, RuntimeException)}, after an earlier
   * step whose reply was lost and that reading back went past ({@code recoveredFrom}, may be null):
   * it is kept as {@link #recoveredFrom()}, and suppressed on the exception.
   */
  static PartialCompletionException of(
      String operation,
      List<KeyHandle> created,
      KeyPairHandle pair,
      String step,
      String advice,
      OutcomeUnknownException recoveredFrom,
      RuntimeException cause) {
    Objects.requireNonNull(cause, "cause");
    return new PartialCompletionException(
        operation
            + ": created "
            + ids(created)
            + ", then "
            + step
            + ": "
            + cause.getMessage()
            + "; "
            + advice,
        operation,
        created,
        pair,
        List.of(),
        List.of(),
        List.of(),
        recoveredFrom,
        cause);
  }
}
