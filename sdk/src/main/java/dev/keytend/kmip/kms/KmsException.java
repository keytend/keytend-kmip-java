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
import dev.keytend.kmip.model.*;
import java.util.Optional;

/**
 * The one exception type of the application API. It is unchecked and sealed: every failure is
 * one of the subtypes below. Branch on {@link #category()}, or catch a subtype.
 *
 * <pre>{@code
 * try {
 *   byte[] opened = kek.open(sealed, orderId);
 * } catch (KmsException e) {
 *   if (e.category() != KmsException.Category.RETRY) throw e;
 *   // A transient failure: try again later.
 * }
 * }</pre>
 *
 * <p>{@code kek} is a {@link CurrentKey}. Exceptions are immutable.
 *
 * <table>
 *   <caption>Subtypes and their {@link Category}</caption>
 *   <tr><th>Subtype</th><th>Meaning</th><th>{@link #category()}</th></tr>
 *   <tr><td>{@link TransientException}</td><td>safe to retry</td><td>{@code RETRY}</td></tr>
 *   <tr><td>{@link NotFoundException}</td><td>the object does not exist (or was destroyed)</td>
 *       <td>{@code NOT_FOUND}</td></tr>
 *   <tr><td>{@link PermissionDeniedException}</td><td>authentication or authorization failed</td>
 *       <td>{@code FIX_ACCESS}</td></tr>
 *   <tr><td>{@link InvalidRequestException}</td><td>the server rejected the request as invalid</td>
 *       <td>{@code FIX_REQUEST}</td></tr>
 *   <tr><td>{@link UnsupportedException}</td><td>the server, the negotiated version or this SDK
 *       does not support the operation or feature</td><td>{@code FIX_REQUEST}</td></tr>
 *   <tr><td>{@link KeyMismatchException}</td><td>the object is not what the caller expected (kind,
 *       algorithm, size, usages), or a query matches no object; or a stored ciphertext names a key
 *       outside the expected lineage, query or pair</td><td>{@code FIX_REQUEST}; {@code BAD_DATA}
 *       for the stored ciphertext</td></tr>
 *   <tr><td>{@link StateConflictException}</td><td>the object's state forbids the operation</td>
 *       <td>{@code STATE}</td></tr>
 *   <tr><td>{@link AlreadyExistsException} (a {@code StateConflictException})</td><td>an object
 *       with that name or identity already exists</td><td>{@code STATE}</td></tr>
 *   <tr><td>{@link CryptographicFailureException}</td><td>the data did not decrypt or verify, for
 *       example an AEAD tag did not verify; {@link CryptographicFailureException#kind()} says
 *       which</td><td>{@code BAD_DATA}; {@code SERVER} for {@link
 *       CryptographicFailureException.Kind#UNCONFIRMED}</td></tr>
 *   <tr><td>{@link OutcomeUnknownException}</td><td>a mutation may or may not have happened</td>
 *       <td>{@code OUTCOME_UNKNOWN}</td></tr>
 *   <tr><td>{@link PartialCompletionException}</td><td>some steps took effect (objects created,
 *       keys deactivated or destroyed), then a later step failed</td><td>{@code PARTIAL}</td></tr>
 *   <tr><td>{@link ServerFailureException}</td><td>any other failure result</td>
 *       <td>{@code SERVER}</td></tr>
 *   <tr><td>{@link ProtocolViolationException}</td><td>a read got a response the SDK rejected</td>
 *       <td>{@code SERVER}</td></tr>
 * </table>
 *
 * <p>{@link #category()} is the stable way to decide what to do, and the subtype says exactly what
 * happened. Within a major version, the {@link Category} constants and the direct subtypes above
 * do not change. A new subtype extends one of them and reports a category that one already
 * reports, so existing {@code catch} clauses still catch it. A failure keeps its subtype and
 * category, except to correct a misclassification, which the release notes list (see <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/compatibility.md#api-compatibility">API
 * compatibility</a>).
 *
 * <p>What the SDK writes into the message never contains key material. {@link #result()} and
 * {@link #response()} are redacted copies that may be logged. An exception is serializable, but
 * without its protocol objects: after deserialization {@link #result()}, {@link #response()},
 * {@link #serverReason()}, {@link #protocolReason()}, {@link #reasonCode()} and {@link
 * #serverMessage()} are empty. Its category, operation and object identifier are kept. See <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/getting-started.md#handle-failures">Handle
 * failures</a>.
 *
 * @since 0.10.0
 */
public abstract sealed class KmsException extends RuntimeException
    permits NotFoundException,
        PermissionDeniedException,
        InvalidRequestException,
        UnsupportedException,
        StateConflictException,
        CryptographicFailureException,
        KeyMismatchException,
        ServerFailureException,
        TransientException,
        OutcomeUnknownException,
        ProtocolViolationException,
        PartialCompletionException {
  /** The application operation that failed; the empty string for an application's exception. */
  private final String operation;

  /** The object concerned, or null when none is known. */
  private final String objectId;

  private final transient Result result;
  private final transient Ttlv response;

  /** The category when the subtype alone does not give it, or null to take it from the subtype. */
  private final Category category;

  KmsException(
      String message,
      Throwable cause,
      String operation,
      String objectId,
      Result result,
      Ttlv response) {
    this(message, cause, operation, objectId, result, response, null);
  }

  /** With {@code category} for an instance whose subtype alone would give the wrong one. */
  KmsException(
      String message,
      Throwable cause,
      String operation,
      String objectId,
      Result result,
      Ttlv response,
      Category category) {
    super(withServerMessage(message, operation, result), cause);
    this.operation = operation;
    this.objectId = objectId;
    this.result = result;
    this.response = response;
    this.category = category;
  }

  /**
   * {@code message} ending with the server's Result Message of {@code result}, {@link #sanitized}
   * and quoted: unless there is none (also a blank one), the result is a success, the exception is
   * an application's (operation {@code ""}), or {@code message} quotes it already (built from an
   * exception that has it, or a lease refusal's).
   */
  private static String withServerMessage(String message, String operation, Result result) {
    if (message == null
        || result == null
        || result.successful()
        || result.message() == null
        || operation == null
        || operation.isEmpty()) return message;
    String said = sanitized(result.message());
    if (said.isEmpty()) return message;
    String quoted = "\"" + said + "\"";
    return message.contains(quoted) ? message : message + " (server message: " + quoted + ")";
  }

  /**
   * A server's message for an SDK message: one line of at most 200 characters, without controls,
   * line or paragraph separators, format characters (bidirectional overrides among them), unpaired
   * surrogates or quotes (each becomes a space), and without leading or trailing spaces; longer text
   * ends with "...".
   */
  static String sanitized(String m) {
    StringBuilder b = new StringBuilder();
    m.codePoints()
        .limit(200)
        .forEach(
            c -> {
              int type = Character.getType(c);
              boolean hidden =
                  Character.isISOControl(c)
                      || type == Character.FORMAT
                      || type == Character.LINE_SEPARATOR
                      || type == Character.PARAGRAPH_SEPARATOR
                      || type == Character.SURROGATE;
              b.appendCodePoint(hidden || c == '"' ? ' ' : c);
            });
    return b.toString().strip() + (m.codePointCount(0, m.length()) > 200 ? "..." : "");
  }

  /** What an application can do about a failure. */
  public enum Category {
    /** Repeating the same call may succeed ({@link TransientException}). */
    RETRY,
    /** The object does not exist ({@link NotFoundException}). */
    NOT_FOUND,
    /** Fix the credentials or the object's access policy ({@link PermissionDeniedException}). */
    FIX_ACCESS,
    /**
     * Fix the request: an invalid argument, a feature the server or version lacks, or a key of the
     * wrong kind, algorithm or usages ({@link InvalidRequestException}, {@link
     * UnsupportedException}, {@link KeyMismatchException} except as under {@link #BAD_DATA}).
     */
    FIX_REQUEST,
    /**
     * The object's lifecycle state, or an existing object, conflicts with the operation ({@link
     * StateConflictException}, {@link AlreadyExistsException}).
     */
    STATE,
    /**
     * The data did not decrypt or verify: it was tampered with or corrupted, or the wrong key or
     * additional data was used ({@link CryptographicFailureException}, except {@code UNCONFIRMED};
     * see its {@code kind()}). Also a stored ciphertext or sealed container that names a key outside
     * the expected lineage, query or key pair ({@link KeyMismatchException}): a relabeled or
     * misfiled record, not a mistake in the call.
     */
    BAD_DATA,
    /**
     * A mutation may or may not have taken effect: check before repeating it ({@link
     * OutcomeUnknownException}).
     */
    OUTCOME_UNKNOWN,
    /**
     * Some steps took effect (objects created, keys deactivated or destroyed), then a later step
     * failed: resume as the exception says ({@link PartialCompletionException}).
     */
    PARTIAL,
    /**
     * The server failed, or answered in a way the SDK rejects ({@link ServerFailureException},
     * {@link ProtocolViolationException}), or rejected an authenticated decryption without
     * confirming why ({@link CryptographicFailureException} of kind {@code UNCONFIRMED}, which a
     * server fault also produces: do not quarantine the data for it).
     */
    SERVER
  }

  /**
   * What an application can do about this failure; see the table above. Mostly given by the
   * subtype; two subtypes depend on the case: {@link CryptographicFailureException} of kind {@code
   * UNCONFIRMED} is {@link Category#SERVER}, and a {@link KeyMismatchException} for a ciphertext
   * that names a key outside the expected lineage, query or pair is {@link Category#BAD_DATA}. The
   * same failure has the same category on every protocol version.
   *
   * @return the category; never null
   */
  public final Category category() {
    if (category != null) return category;
    if (this instanceof TransientException) return Category.RETRY;
    if (this instanceof NotFoundException) return Category.NOT_FOUND;
    if (this instanceof PermissionDeniedException) return Category.FIX_ACCESS;
    if (this instanceof InvalidRequestException
        || this instanceof UnsupportedException
        || this instanceof KeyMismatchException) return Category.FIX_REQUEST;
    if (this instanceof StateConflictException) return Category.STATE;
    if (this instanceof CryptographicFailureException) return Category.BAD_DATA;
    if (this instanceof OutcomeUnknownException) return Category.OUTCOME_UNKNOWN;
    if (this instanceof PartialCompletionException) return Category.PARTIAL;
    return Category.SERVER;
  }

  /**
   * True only for {@link TransientException}: the same call may be repeated.
   *
   * @return whether repeating the same call may succeed
   */
  public boolean retryable() {
    return this instanceof TransientException;
  }

  /**
   * The application operation that failed, for example {@code "encrypt"} or {@code
   * "findOrCreate"}. Not null: an exception made by one of the public constructors (application
   * code, tests) has the empty string {@code ""}. A name, not an {@code Optional}.
   *
   * @return the operation's name, or {@code ""} for an exception constructed by application code
   */
  public String operation() {
    return operation;
  }

  /**
   * The object concerned, when known: the target of the call, or an object that was created before
   * a later step failed (for example a key whose activation failed).
   *
   * @return the object's identifier; empty when the failure concerns no single known object (or the
   *     exception was constructed by application code)
   */
  public Optional<String> objectId() {
    return Optional.ofNullable(objectId);
  }

  /**
   * The reason the server gave for this failure, as a constant of this package. It is empty when
   * the exception carries no Result Reason from the server, for example a refusal by the SDK
   * before sending. A reason {@link KmsReason} does not name, or a vendor code, is {@link
   * KmsReason#OTHER}. It is the server's word: to decide what to do, prefer {@link #category()}
   * and the subtype, which are the same for the same failure on every protocol version. Present
   * exactly when {@link #reasonCode()} is.
   *
   * @return the server's reason; empty when the failure carries no Result Reason
   */
  public Optional<KmsReason> serverReason() {
    return reasonCode().map(KmsReason::of);
  }

  /**
   * The KMIP Result Reason of a failure result, a protocol-layer enum; empty also for a vendor
   * code. The escape hatch for a reason {@link #serverReason()} reports as {@link
   * KmsReason#OTHER}.
   *
   * @return the protocol-layer reason; empty when there is none or it is a vendor code
   */
  public Optional<Enums.ResultReason> protocolReason() {
    return result == null ? Optional.empty() : result.reasonEnum();
  }

  /**
   * The raw Result Reason code (also for vendor codes); {@link #serverReason()} is the same reason
   * as a constant of this package.
   *
   * @return the reason code; empty when the failure carries no Result Reason
   */
  public Optional<Integer> reasonCode() {
    return result == null ? Optional.empty() : Optional.ofNullable(result.reason());
  }

  /**
   * The server's Result Message. When the SDK reports a failure result that has one, its own
   * message ends with this text once, in quotes. There it is one line of at most 200 characters:
   * controls, separators, format characters (bidirectional overrides among them), unpaired
   * surrogates and quotes become spaces, and longer text ends with "...". It is the server's text,
   * not checked by the SDK, so treat it as untrusted in logs.
   *
   * @return the server's message; empty when the failure carries no result or the result has no
   *     message
   */
  public Optional<String> serverMessage() {
    return result == null ? Optional.empty() : Optional.ofNullable(result.message());
  }

  /**
   * The failure result the server returned, for diagnostics: a redacted copy, with the status,
   * reason and message as sent. Every Byte String is empty, every Big Integer zero and every
   * password empty, so it holds no key material, plaintext, signature or credential, and may be
   * logged. Other text, such as names, identifiers and the server's message, is kept as sent. The
   * protocol exceptions in the cause chain hold the same redacted copies.
   *
   * @return the redacted result; empty when the failure carries none (a refusal by the SDK, a
   *     transport failure, a rejected response, an exception constructed by application code or
   *     one deserialized)
   */
  public Optional<Result> result() {
    return Optional.ofNullable(result);
  }

  /**
   * The response message that the SDK rejected as invalid, for diagnostics: a redacted copy, as
   * {@link #result()} describes.
   *
   * @return the redacted response; empty unless the SDK rejected a response ({@link
   *     ProtocolViolationException}, or an {@link OutcomeUnknownException} for a mutation, or a
   *     {@link PartialCompletionException} whose cause is one of them); empty also for a
   *     deserialized exception
   */
  public Optional<Ttlv> response() {
    return Optional.ofNullable(response);
  }
}
