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

package dev.keytend.kmip.testing;

import dev.keytend.kmip.model.Enums.ResultReason;
import dev.keytend.kmip.model.ProtocolVersion;

/**
 * A failure that {@link InMemoryKmipServer#failNext(ServerOperation, Fault) failNext} makes the
 * server produce once, named for what the application sees. Each is a real server answer or
 * transport failure, so the SDK handles it as it would a real server's. Each constant says what
 * the server sends and which exception the {@code Kms} API then throws.
 *
 * <pre>{@code
 * server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
 * assertThrows(PermissionDeniedException.class, () -> key.attributes());
 * }</pre>
 *
 * <p>Some faults end differently for a read and a mutation. A <em>read</em> is a call that does
 * not change the server, such as {@code attributes()}, lookups, encrypt, decrypt, sign, verify,
 * MAC and {@code random}. A <em>mutation</em> changes it: create, register, activate, revoke,
 * destroy, rotate and attribute changes. The SDK retries a read after a {@code
 * TransientException}, 3 attempts by default. So arm the fault once per attempt, or connect with
 * {@code server.configure().retryPolicy(RetryPolicy.none())}. A mutation is never re-sent. A call
 * that sends several requests reports a failure of a later one as that call documents, for example
 * {@code PartialCompletionException} when the Activate of {@code create()} fails.
 *
 * <p>The faults that answer with a Result Reason, {@link #NOT_FOUND} to {@link #SERVER_BUSY}, fail
 * the matching request item before it is processed, so a failed mutation changed nothing. Their
 * Result Message names the fault. {@link #HANG} waits for the exchange's deadline, which the {@code
 * Kms} call timeout sets, so test it with a short one. {@link #SLOW} holds the reply for {@link
 * InMemoryKmipServer#slowReplyDelay slowReplyDelay} and times out only if the deadline comes
 * first, so a timeout test needs a call timeout shorter than that delay.
 *
 * <p>Test support, outside the compatibility promises, like the rest of this package (<a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/compatibility.md#the-testing-package">The
 * testing package</a>).
 *
 * @since 0.10.0
 */
public enum Fault {
  /**
   * Answers Object Not Found, or Item Not Found on 1.x: {@code NotFoundException}. On 1.x, Item
   * Not Found also means a missing attribute. So there the SDK's attribute removals ({@code
   * removeName}, {@code removeFromGroup}, {@code removeCustomAttribute}) and the Modify step of
   * {@code setCustomAttribute} read this fault as an absent attribute when the object exists. Test
   * a missing object on 1.x with another operation.
   */
  NOT_FOUND(ResultReason.OBJECT_NOT_FOUND, null),
  /** Answers Permission Denied: {@code PermissionDeniedException}. */
  PERMISSION_DENIED(ResultReason.PERMISSION_DENIED, null),
  /**
   * Answers Missing Data: {@code InvalidRequestException}. It uses Missing Data rather than Invalid
   * Field because the SDK reads Invalid Field on an authenticated decryption as an unconfirmed
   * authentication failure.
   */
  INVALID_REQUEST(ResultReason.MISSING_DATA, null),
  /** Answers Feature Not Supported: {@code UnsupportedException}. */
  UNSUPPORTED(ResultReason.FEATURE_NOT_SUPPORTED, null),
  /** Answers Wrong Key Lifecycle State, or Illegal Operation on 1.x: {@code StateConflictException}. */
  STATE_CONFLICT(ResultReason.WRONG_KEY_LIFECYCLE_STATE, null),
  /**
   * Answers Object Already Exists: {@code AlreadyExistsException}. KMIP 1.2 and 1.3 have no such
   * Result Reason, so {@code failNext} refuses this fault on a server that speaks only those
   * versions. Arm {@link #STATE_CONFLICT} there. On a server that also speaks 1.4 or later, a 1.2 or
   * 1.3 request gets Illegal Operation, which the application sees as the superclass {@code
   * StateConflictException}. The server then records a {@link InMemoryKmipServer#violations()
   * violation} saying so.
   */
  ALREADY_EXISTS(ResultReason.OBJECT_ALREADY_EXISTS, ResultReason.ILLEGAL_OPERATION),
  /**
   * Answers Internal Server Error, or General Failure on 1.x: {@code ServerFailureException}. On
   * 1.x, an authenticated decryption such as AES-GCM, key unwrap or RSA-OAEP sees {@code
   * CryptographicFailureException} of kind {@code UNCONFIRMED} instead. A real 1.x server's
   * failure cannot be told from a tag mismatch either.
   */
  SERVER_FAILURE(ResultReason.INTERNAL_SERVER_ERROR, null),
  /**
   * Answers Server Limit Exceeded: {@code TransientException} for a read, which the SDK retries,
   * and {@code ServerFailureException} for a mutation. KMIP 1.x has no such Result Reason, so
   * {@code failNext} refuses this fault on a server that speaks only 1.x. Arm {@link
   * #SERVER_FAILURE} there. On a server that also speaks 2.0 or later, a 1.x request gets General
   * Failure, which the application sees as for {@link #SERVER_FAILURE}. The server then records a
   * {@link InMemoryKmipServer#violations() violation} saying so.
   */
  SERVER_BUSY(ResultReason.SERVER_LIMIT_EXCEEDED, ResultReason.GENERAL_FAILURE),
  /**
   * Refuses the connection before anything is sent, so nothing is processed. Reads and mutations
   * both see {@code TransientException}, because the SDK knows the request was not sent. The SDK
   * retries it like any transient failure, so a read succeeds on the next attempt unless the fault
   * is armed again. The endpoint also cools down, which matters only with several endpoints.
   */
  UNREACHABLE(null, null),
  /**
   * Processes the request, then loses the reply as a read timeout: {@code TransientException} for
   * a read, and {@code OutcomeUnknownException} for a mutation, which did take effect.
   */
  REPLY_LOST(null, null),
  /**
   * Processes the request, then sends a reply whose items lack Result Status: {@code
   * ProtocolViolationException} for a read, and {@code OutcomeUnknownException} for a mutation,
   * which did take effect.
   */
  MALFORMED_REPLY(null, null),
  /**
   * Receives the request, processes nothing and never answers, like a hung server or a stalled
   * connection. The exchange waits for its deadline, its cancellation or an interrupt, at most 60
   * seconds, then fails as a read timeout. A read sees {@code TransientException}. A mutation sees
   * {@code OutcomeUnknownException}, although nothing changed, because the SDK cannot know that.
   * The wait does not hold the server's lock, so other clients and {@link
   * InMemoryKmipServer#replica() replicas} keep working. With several endpoints ({@link
   * InMemoryKmipServer#configureReplicas}), a read with no reply within {@code
   * RetryPolicy.attemptTimeout()} moves to the next endpoint in the same call and succeeds there.
   * The listener then hears {@code endpointUnavailable} for the hung one. A mutation is not
   * re-sent.
   */
  HANG(null, null),
  /**
   * Processes the request, then holds the reply for the server's {@link
   * InMemoryKmipServer#slowReplyDelay slowReplyDelay}, 1 second by default: a slow server. If the
   * exchange's deadline comes first, the reply is lost as with {@link #REPLY_LOST}. A read then
   * sees {@code TransientException}, and a mutation {@code OutcomeUnknownException}, though it did
   * take effect. Otherwise the call succeeds, late. Like {@link #HANG}, the wait does not hold the
   * server's lock.
   */
  SLOW(null, null);

  private final ResultReason reason;
  private final ResultReason fallback;

  Fault(ResultReason reason, ResultReason fallback) {
    this.reason = reason;
    this.fallback = fallback;
  }

  /** The Result Reason this fault answers with; null for transport faults. */
  ResultReason reason() {
    return reason;
  }

  /**
   * Whether {@code version} has no Result Reason for this fault, so the server answers {@link
   * #fallback()} instead.
   */
  boolean inexpressible(ProtocolVersion version) {
    return fallback != null && !version.atLeast(reason.since());
  }

  /** The closest answer in versions that cannot express this fault. */
  ResultReason fallback() {
    return fallback;
  }

  /** The fault that sends {@link #fallback()}: what to arm where this one cannot be expressed. */
  Fault nearest() {
    return this == ALREADY_EXISTS ? STATE_CONFLICT : SERVER_FAILURE;
  }
}
