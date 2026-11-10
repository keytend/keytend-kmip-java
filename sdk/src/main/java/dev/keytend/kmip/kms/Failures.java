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

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.RequestNotSentException;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.cert.CertPathBuilderException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.util.*;
import java.util.regex.Pattern;
import javax.net.ssl.SSLException;

/** Maps protocol-layer failures to the {@link KmsException} hierarchy. */
final class Failures {
  private Failures() {}

  /** What the classification needs to know about the call. */
  record Call(String operation, boolean idempotent, String objectId, boolean integrityDecrypt) {}

  private static final Set<Enums.ResultReason> NOT_FOUND =
      EnumSet.of(
          Enums.ResultReason.ITEM_NOT_FOUND,
          Enums.ResultReason.OBJECT_NOT_FOUND,
          Enums.ResultReason.OBJECT_DESTROYED);
  private static final Set<Enums.ResultReason> DENIED =
      EnumSet.of(
          Enums.ResultReason.PERMISSION_DENIED,
          Enums.ResultReason.AUTHENTICATION_NOT_SUCCESSFUL,
          Enums.ResultReason.NOT_AUTHORISED,
          Enums.ResultReason.SENSITIVE,
          Enums.ResultReason.NOT_EXTRACTABLE,
          Enums.ResultReason.ATTESTATION_REQUIRED,
          Enums.ResultReason.ATTESTATION_FAILED,
          Enums.ResultReason.BAD_PASSWORD,
          Enums.ResultReason.INVALID_TICKET);
  private static final Set<Enums.ResultReason> UNSUPPORTED =
      EnumSet.of(
          Enums.ResultReason.OPERATION_NOT_SUPPORTED,
          Enums.ResultReason.FEATURE_NOT_SUPPORTED,
          Enums.ResultReason.APPLICATION_NAMESPACE_NOT_SUPPORTED,
          Enums.ResultReason.KEY_FORMAT_TYPE_NOT_SUPPORTED,
          Enums.ResultReason.KEY_COMPRESSION_TYPE_NOT_SUPPORTED,
          Enums.ResultReason.KEY_WRAP_TYPE_NOT_SUPPORTED,
          Enums.ResultReason.UNSUPPORTED_ATTRIBUTE,
          Enums.ResultReason.UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS,
          Enums.ResultReason.UNSUPPORTED_PROTOCOL_VERSION,
          Enums.ResultReason.UNKNOWN_MESSAGE_EXTENSION);
  private static final Set<Enums.ResultReason> STATE =
      EnumSet.of(
          Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE,
          Enums.ResultReason.ILLEGAL_OPERATION,
          Enums.ResultReason.OBJECT_ARCHIVED,
          Enums.ResultReason.READ_ONLY_ATTRIBUTE,
          Enums.ResultReason.ATTRIBUTE_READ_ONLY,
          Enums.ResultReason.WRAPPING_OBJECT_ARCHIVED,
          Enums.ResultReason.WRAPPING_OBJECT_DESTROYED,
          Enums.ResultReason.USAGE_LIMIT_EXCEEDED,
          Enums.ResultReason.CONSTRAINT_VIOLATION);
  private static final Set<Enums.ResultReason> INVALID =
      EnumSet.of(
          Enums.ResultReason.INVALID_MESSAGE,
          Enums.ResultReason.MISSING_DATA,
          Enums.ResultReason.INVALID_FIELD,
          Enums.ResultReason.INDEX_OUT_OF_BOUNDS,
          Enums.ResultReason.ENCODING_OPTION_ERROR,
          Enums.ResultReason.KEY_VALUE_NOT_PRESENT,
          Enums.ResultReason.RESPONSE_TOO_LARGE,
          Enums.ResultReason.NUMERIC_RANGE,
          Enums.ResultReason.INVALID_DATA_TYPE,
          Enums.ResultReason.MULTI_VALUED_ATTRIBUTE,
          Enums.ResultReason.ATTRIBUTE_INSTANCE_NOT_FOUND,
          Enums.ResultReason.ATTRIBUTE_NOT_FOUND,
          Enums.ResultReason.ATTRIBUTE_SINGLE_VALUED,
          Enums.ResultReason.BAD_CRYPTOGRAPHIC_PARAMETERS,
          Enums.ResultReason.CODEC_ERROR,
          Enums.ResultReason.ILLEGAL_OBJECT_TYPE,
          Enums.ResultReason.INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK,
          Enums.ResultReason.INVALID_ATTRIBUTE,
          Enums.ResultReason.INVALID_ATTRIBUTE_VALUE,
          Enums.ResultReason.INVALID_CORRELATION_VALUE,
          Enums.ResultReason.INVALID_CSR,
          Enums.ResultReason.INVALID_OBJECT_TYPE,
          Enums.ResultReason.MISSING_INITIALIZATION_VECTOR,
          Enums.ResultReason.UNKNOWN_ENUMERATION,
          Enums.ResultReason.UNKNOWN_TAG,
          Enums.ResultReason.UNKNOWN_OBJECT_GROUP,
          Enums.ResultReason.WRAPPING_OBJECT_NOT_FOUND,
          Enums.ResultReason.CIRCULAR_LINK_ERROR);

  /** Application operations that use a key cryptographically. */
  private static final Set<String> CRYPTO =
      Set.of(
          "encrypt",
          "decrypt",
          "sign",
          "verify",
          "mac",
          "macVerify",
          "wrapKey",
          "unwrapKey",
          "generateDataKey",
          "seal",
          "open",
          "rewrap",
          "rewrapKey");

  /**
   * A failure the caller caused after the request was sent: its thread was interrupted (a canceled
   * task, {@code shutdownNow()}), or it timed out in a {@code withTimeout} view shorter than the
   * configured call timeout ({@code shortened}). The transport's own read limit is never shorter
   * than the call timeout, so such a timeout is the caller's choice. Neither says anything about
   * the endpoint; an endpoint silent for a whole configured call timeout does.
   */
  static boolean callerStopped(Throwable e, boolean interrupted, boolean shortened) {
    if (e instanceof java.nio.channels.ClosedByInterruptException) return true;
    if (!(e instanceof java.io.InterruptedIOException)) return false;
    if (interrupted || !(e instanceof java.net.SocketTimeoutException)) return true;
    return shortened;
  }

  /** A failure in transport (not a response the SDK rejected, not a local hold-up). */
  static boolean transportFailure(Throwable e) {
    return e instanceof IOException && !(e instanceof ProtocolException);
  }

  /**
   * A refusal that may be the server's answer to an object's lifecycle state rather than to this
   * client, so that reading the object can tell which: Permission Denied (KMIP 1.x refuses an
   * operation the object's state forbids with it, for example KMIP 1.4 Tables 331 and 346), Illegal
   * Operation and Wrong Key Lifecycle State. Only these are read back and may become a {@link
   * StateConflictException} (or, for a cryptographic call, a {@link KeyMismatchException}). Every
   * other refusal is as the server said: Authentication Not Successful, Bad Password, Not
   * Authorized, Sensitive and the other access reasons, a refused TLS handshake, and other state
   * refusals (Object Archived, say).
   */
  static boolean lifecycleAmbiguous(KmsException e) {
    Enums.ResultReason reason = e.protocolReason().orElse(null);
    return reason == Enums.ResultReason.PERMISSION_DENIED
        || reason == Enums.ResultReason.ILLEGAL_OPERATION
        || reason == Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE;
  }

  /**
   * The server refused this client's credentials, not its access to one object: Authentication Not
   * Successful, Bad Password, or a TLS handshake refused because of a certificate (the one {@link
   * PermissionDeniedException} without a server result). Never read as a fact about an object (an
   * object that "cannot be read", a link or a re-key "the server refuses"): it is FIX_ACCESS.
   */
  static boolean credentialsRefused(KmsException e) {
    if (!(e instanceof PermissionDeniedException)) return false;
    Enums.ResultReason reason = e.protocolReason().orElse(null);
    return reason == null
        || reason == Enums.ResultReason.AUTHENTICATION_NOT_SUCCESSFUL
        || reason == Enums.ResultReason.BAD_PASSWORD;
  }

  /** A server-busy result: the reasons {@link KmsReason#SERVER_BUSY} lists. */
  static boolean busy(KmsException e) {
    return e.serverReason().orElse(null) == KmsReason.SERVER_BUSY;
  }

  /**
   * A TLS handshake that failed because this client rejected the server's certificate (PKIX path,
   * validity or host name), as opposed to the server rejecting this client's credentials: a
   * certificate or certification-path exception anywhere in the cause chain. Only this client's
   * trust manager raises those; the JDK chains them under the handshake exception.
   */
  static boolean serverNotTrusted(Throwable e) {
    for (Throwable t = e; t != null; t = t.getCause())
      if (t instanceof CertificateException
          || t instanceof CertPathValidatorException
          || t instanceof CertPathBuilderException) return true;
    return false;
  }

  /**
   * The TLS alerts (RFC 8446 §6.2 names) a server sends when it refuses the client's certificate or
   * access. Alert names are protocol identifiers: JSSE (also "Received fatal alert: x" up to JDK 21
   * and "(x) Received fatal alert: x" from JDK 22), BCJSSE ("x(42)") and BoringSSL/OpenSSL ("..._ALERT_X")
   * all put them in the message, whatever the surrounding prose. Not handshake_failure, which also
   * means no common cipher suite or protocol version.
   */
  private static final Pattern REFUSED_ALERT =
      Pattern.compile(
          "(?<![a-z0-9_])(?:[a-z0-9]+_alert_)?(?:bad_certificate|unsupported_certificate|certificate_revoked"
              + "|certificate_expired|certificate_unknown|unknown_ca|access_denied|certificate_required)"
              + "(?![a-z0-9_])");

  /**
   * A TLS handshake the server refused because of this client's certificate: an {@link
   * SSLException} in the cause chain whose message names one of {@link #REFUSED_ALERT}. JSSE raises
   * a received alert as an exception without a cause, so the alert name in the message is the only
   * signal (JSSE has no alert-code API); the name, not the prose around it, is matched.
   */
  static boolean clientRefused(Throwable e) {
    for (Throwable t = e; t != null; t = t.getCause())
      if (t instanceof SSLException
          && t.getMessage() != null
          && REFUSED_ALERT.matcher(t.getMessage().toLowerCase(Locale.ROOT)).find()) return true;
    return false;
  }

  static KmsException classify(Call call, ProtocolVersion version, Throwable failure) {
    if (failure instanceof KmsException k) return k;
    if (failure instanceof Kms.NotExpressible e)
      return new UnsupportedException(
          call.operation()
              + (call.objectId() == null ? "" : " " + call.objectId())
              + ": cannot be expressed in KMIP "
              + version
              + ": "
              + e.getMessage(),
          null,
          call.operation(),
          call.objectId(),
          null,
          null);
    String what = call.operation() + (call.objectId() == null ? "" : " " + call.objectId());
    // Raw protocol objects in causes could hold key material: chain redacted copies only.
    if (failure instanceof KmipException e)
      return fromResult(call, what, e.result(), new KmipException(Redaction.copy(e.result())));
    if (failure instanceof VersionNegotiationException e)
      return new UnsupportedException(
          what + ": " + e.getMessage(), e, call.operation(), call.objectId(), null, null);
    if (failure instanceof RequestNotSentException e) {
      if (certificateProblem(e))
        return new PermissionDeniedException(
            what + ": TLS handshake rejected: " + rootMessage(e),
            e,
            call.operation(),
            call.objectId(),
            null,
            null);
      return new TransientException(
          what + ": " + e.getMessage() + " (" + rootMessage(e) + ")",
          e,
          call.operation(),
          call.objectId(),
          null,
          null);
    }
    if (failure instanceof ProtocolException raw) {
      // The cause chain of a rejected response can quote peer-controlled values: drop it.
      Ttlv redacted = Redaction.copy(raw.response());
      ProtocolException e = new ProtocolException(raw.getMessage(), redacted, null);
      e.setStackTrace(raw.getStackTrace());
      String text = what + ": invalid response: " + e.getMessage();
      return call.idempotent()
          ? new ProtocolViolationException(
              text, e, call.operation(), call.objectId(), null, redacted)
          : new OutcomeUnknownException(
              text + "; the operation may have taken effect",
              e,
              call.operation(),
              call.objectId(),
              null,
              redacted);
    }
    if (failure instanceof IOException e) {
      // TLS 1.3 reports a refused client certificate at the first read, after the request was
      // written: the server refused the handshake, so it did not run the request.
      if (certificateProblem(e))
        return new PermissionDeniedException(
            what + ": TLS handshake rejected: " + rootMessage(e),
            e,
            call.operation(),
            call.objectId(),
            null,
            null);
      String text = what + ": " + e.getClass().getSimpleName() + ": " + e.getMessage();
      return call.idempotent()
          ? new TransientException(text, e, call.operation(), call.objectId(), null, null)
          : new OutcomeUnknownException(
              text + "; the request may have reached the server",
              e,
              call.operation(),
              call.objectId(),
              null,
              null);
    }
    if (failure instanceof GeneralSecurityException e)
      return new KeyMismatchException(
          what + ": " + e.getMessage(), e, call.operation(), call.objectId(), null, null);
    // Anything else (including IllegalArgumentException or IllegalStateException from inside the
    // call) is unexpected: never reported as unsupported, and a mutation's outcome is unknown.
    return call.idempotent()
        ? new ProtocolViolationException(
            what + ": unexpected " + failure,
            failure,
            call.operation(),
            call.objectId(),
            null,
            null)
        : new OutcomeUnknownException(
            what + ": unexpected " + failure,
            failure,
            call.operation(),
            call.objectId(),
            null,
            null);
  }

  static KmsException fromResult(Call call, String what, Result raw, Throwable cause) {
    Result result = Redaction.copy(raw);
    String op = call.operation(), id = call.objectId();
    String text = what + " failed: " + (cause == null ? describe(raw) : cause.getMessage());
    if (raw.status() == 2 || raw.status() == 3) {
      String unexpected =
          what + ": unexpected " + (raw.status() == 2 ? "Pending" : "Undone") + " result";
      return call.idempotent()
          ? new ProtocolViolationException(unexpected, cause, op, id, result, null)
          : new OutcomeUnknownException(unexpected, cause, op, id, result, null);
    }
    Enums.ResultReason reason = raw.reasonEnum().orElse(null);
    // A tamper-evident decryption (AEAD, key wrap, OAEP): the SDK validated the request itself.
    if (reason != null && call.integrityDecrypt()) {
      if (reason == Enums.ResultReason.CRYPTOGRAPHIC_FAILURE)
        return new CryptographicFailureException(
            what
                + ": authentication failed (the ciphertext, nonce, tag, header or additional data"
                + " changed, or another key was used): "
                + text,
            cause,
            op,
            id,
            result,
            null,
            CryptographicFailureException.Kind.AUTHENTICATION_FAILED);
      // Some servers report a tag mismatch as Invalid Field or General Failure; so do server
      // faults.
      if (reason == Enums.ResultReason.INVALID_FIELD
          || reason == Enums.ResultReason.GENERAL_FAILURE)
        return new CryptographicFailureException(
            what
                + ": the server rejected the authenticated decryption without confirming why: "
                + text,
            cause,
            op,
            id,
            result,
            null,
            CryptographicFailureException.Kind.UNCONFIRMED);
    }
    if (reason == null) return new ServerFailureException(text, cause, op, id, result, null);
    if (KmsReason.of(reason) == KmsReason.SERVER_BUSY && call.idempotent())
      return new TransientException(text + " (server busy)", cause, op, id, result, null);
    if (NOT_FOUND.contains(reason)) return new NotFoundException(text, cause, op, id, result, null);
    if (DENIED.contains(reason))
      return new PermissionDeniedException(text, cause, op, id, result, null);
    if (UNSUPPORTED.contains(reason))
      return new UnsupportedException(text, cause, op, id, result, null);
    if (reason == Enums.ResultReason.OBJECT_ALREADY_EXISTS
        || reason == Enums.ResultReason.NON_UNIQUE_NAME_ATTRIBUTE)
      return new AlreadyExistsException(text, cause, op, id, result, null);
    // On an operation addressed to an object, the wrong kind of object, or a key whose usage mask
    // does not permit the operation, is a key mismatch, the same as when the SDK knows the kind and
    // refuses before sending. (KMIP 1.x servers report these as Permission Denied or Invalid Field;
    // KeyHandle reads the key's attributes to tell, so every version gives the same exception.)
    if (id != null
        && (reason == Enums.ResultReason.ILLEGAL_OBJECT_TYPE
            || reason == Enums.ResultReason.INVALID_OBJECT_TYPE
            || reason == Enums.ResultReason.INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK))
      return new KeyMismatchException(text, cause, op, id, result, null);
    if (STATE.contains(reason)) {
      // Pre-Active keys are the usual cause: say so (KMIP 1.x servers report Illegal Operation).
      if (CRYPTO.contains(op)
          && (reason == Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE
              || reason == Enums.ResultReason.ILLEGAL_OPERATION))
        text +=
            " (check the key's state with attributes(): a Pre-Active key needs activate() first;"
                + " a Deactivated or Compromised key can no longer encrypt, sign or compute MACs)";
      if (op.equals("destroy")
          && (reason == Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE
              || reason == Enums.ResultReason.ILLEGAL_OPERATION))
        text += " (an Active object cannot be destroyed: deactivate it first)";
      return new StateConflictException(text, cause, op, id, result, null);
    }
    if (INVALID.contains(reason))
      return new InvalidRequestException(text, cause, op, id, result, null);
    if (reason == Enums.ResultReason.CRYPTOGRAPHIC_FAILURE)
      return new CryptographicFailureException(text, cause, op, id, result, null);
    return new ServerFailureException(text, cause, op, id, result, null);
  }

  private static String describe(Result r) {
    return new KmipException(r).getMessage();
  }

  /** A TLS handshake the peer or this client rejected because of a certificate. */
  private static boolean certificateProblem(Throwable e) {
    return serverNotTrusted(e) || clientRefused(e);
  }

  private static String rootMessage(Throwable e) {
    Throwable root = e;
    while (root.getCause() != null) root = root.getCause();
    return root.getClass().getSimpleName() + ": " + root.getMessage();
  }
}
