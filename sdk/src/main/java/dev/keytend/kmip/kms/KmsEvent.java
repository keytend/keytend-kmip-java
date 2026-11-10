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
 * One attempt of one operation, or one whole application call ({@link #kind()}), for {@link
 * KmsListener}. Events carry identifiers and outcomes, never key material or data. Only the SDK
 * creates events; new accessors may be added in later releases. Immutable.
 *
 * <p>As metric tags, {@link #operation()}, {@link #endpoint()}, {@link #version()}, {@link
 * #outcome()} and the failure's {@link KmsException#category()} and {@link
 * KmsException#serverReason()} take few values (the endpoints are
 * the configured ones). {@link #objectId()} and {@link #callId()} take a new value for nearly
 * every event: use them in traces and logs, never as tags.
 *
 * @since 0.10.0
 */
public final class KmsEvent {
  /** What an event describes. */
  public enum Kind {
    /** One attempt: one execution of a step on one endpoint ({@link KmsListener#started}). */
    ATTEMPT,
    /** One application call, all its attempts included ({@link KmsListener#callStarted}). */
    CALL
  }

  /** The state of an attempt or a call. */
  public enum Outcome {
    /** The attempt is about to send its request, or the call its first attempt. */
    STARTED,
    /** The attempt succeeded, or the call returned. */
    SUCCEEDED,
    /** The attempt failed, or the call threw; {@link #failure()} says how. */
    FAILED
  }

  private final Kind kind;
  private final long callId;
  private final String operation, step, endpoint, objectId;
  private final int attempt;
  private final KmipVersion version;
  private final Duration latency;
  private final Outcome outcome;
  private final KmsException failure;

  KmsEvent(
      Kind kind,
      long callId,
      String operation,
      String step,
      String endpoint,
      int attempt,
      KmipVersion version,
      String objectId,
      Duration latency,
      Outcome outcome,
      KmsException failure) {
    this.kind = Objects.requireNonNull(kind, "kind");
    this.callId = callId;
    this.operation = operation;
    this.step = step;
    this.endpoint = endpoint;
    this.attempt = attempt;
    this.version = version;
    this.objectId = objectId;
    this.latency = latency;
    this.outcome = Objects.requireNonNull(outcome, "outcome");
    this.failure = failure;
  }

  /**
   * Whether this event is one attempt or a whole call.
   *
   * @return the kind
   * @since 0.10.0
   */
  public Kind kind() {
    return kind;
  }

  /**
   * The call this event belongs to: the same in a call's {@link KmsListener#callStarted}, {@link
   * KmsListener#callFinished} and every attempt event between, so that a tracer can pair them
   * without a thread-local. Unique within the JVM, from 1.
   *
   * @return the call's identifier
   * @since 0.10.0
   */
  public long callId() {
    return callId;
  }

  /**
   * The application operation, for example {@code "get"} or {@code "encrypt"}.
   *
   * @return the operation's name
   */
  public String operation() {
    return operation;
  }

  /**
   * The SDK execution step the attempt belongs to, while {@link #operation()} names the
   * application call it serves: a {@link LocalKeys} load is operation {@code "localKeys"} in all of
   * its steps, {@code "locate"} (the write key by name), {@code "attributes"} (Get Attributes),
   * {@code "obtainLease"} and {@code "asSecretKey"} (Get, for the material).
   * The same as {@code operation()} for a call made of one step. A step is one execution with its
   * own attempts and retries, not necessarily one request on the wire (a step may send a batch, or
   * a probe before its request), and its name says what was asked, not what the server granted.
   * Step names are diagnostics: they may change between releases. For a call ({@link Kind#CALL}),
   * the same as {@code operation()}.
   *
   * @return the step's name
   * @since 0.10.0
   */
  public String step() {
    return step;
  }

  /**
   * {@code host:port} of the endpoint used. For a call ({@link Kind#CALL}), that of its first
   * attempt when it starts, of its last when it finishes.
   *
   * @return the endpoint's {@code host:port}
   */
  public String endpoint() {
    return endpoint;
  }

  /**
   * For an attempt, 1 for the first attempt, 2 for the first retry, and so on; it can exceed
   * {@link RetryPolicy#maxAttempts()} when an attempt was cut off at the attempt timeout (the
   * request then goes once more to an endpoint not tried yet, or to the cut-off one with the rest
   * of the deadline). For a call ({@link Kind#CALL}), the number of attempts it made, in all its
   * steps: 0 when it starts.
   *
   * @return the attempt's number, from 1; for a call, its attempts
   */
  public int attempt() {
    return attempt;
  }

  /**
   * The negotiated protocol version.
   *
   * @return the version
   */
  public KmipVersion version() {
    return version;
  }

  /**
   * The object concerned, when known. For a call ({@link Kind#CALL}), the first object its
   * attempts named.
   *
   * @return the object's identifier; empty when the call concerns no single known object
   */
  public Optional<String> objectId() {
    return Optional.ofNullable(objectId);
  }

  /**
   * Time spent so far (zero for a start event). For a call ({@link Kind#CALL}), since its first
   * attempt started.
   *
   * @return the time since the attempt (or call) started; zero for {@link Outcome#STARTED}
   */
  public Duration latency() {
    return latency;
  }

  /**
   * Whether the attempt is starting, succeeded or failed. For a call ({@link Kind#CALL}), starting,
   * returned or threw ({@link KmsListener#callFinished}).
   *
   * @return the outcome
   */
  public Outcome outcome() {
    return outcome;
  }

  /**
   * The failure, for a failed attempt (its type and {@link KmsException#category()} tell which),
   * or what a call threw, when it threw a {@link KmsException}.
   *
   * @return the failure; empty unless the outcome is {@link Outcome#FAILED}, and for a call that
   *     threw something else
   */
  public Optional<KmsException> failure() {
    return Optional.ofNullable(failure);
  }

  @Override
  public String toString() {
    return "KmsEvent["
        + (kind == Kind.CALL ? "call " : "")
        + callId
        + " "
        + operation
        + (step.equals(operation) ? "" : "/" + step)
        + (objectId == null ? "" : " " + objectId)
        + " #"
        + attempt
        + " at "
        + endpoint
        + ", KMIP "
        + version
        + ", "
        + outcome
        + (failure == null ? "" : " (" + failure.getClass().getSimpleName() + ")")
        + ", "
        + latency.toMillis()
        + " ms]";
  }
}
