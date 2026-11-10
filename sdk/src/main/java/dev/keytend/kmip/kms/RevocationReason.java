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

import dev.keytend.kmip.model.Enums;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.Optional;

/**
 * Why an object is revoked or deactivated.
 *
 * <p>With {@link KeyHandle#revoke}, a compromise reason makes the object Compromised and records
 * when the compromise happened. Any other reason deactivates it, on every KMIP version. Up to KMIP
 * 2.1 both are a Revoke with the reason. On the KMIP 3.0 draft a Revoke compromises whatever its
 * reason (CSD02 §6.1.51), so the SDK sends a deactivation as the draft's Deactivate, which carries
 * no reason or message ({@link KeyHandle#deactivate(RevocationReason)}).
 *
 * <p>So on KMIP 3.0 a deactivation records neither the reason's code nor its message. Only a
 * compromise records both there. A Revoke sent through the protocol layer ({@code
 * Requests.revoke}) keeps the protocol's meaning: on 3.0 it compromises. Instances are immutable.
 *
 * @since 0.10.0
 */
public final class RevocationReason {
  /** The KMIP Revocation Reason Code, as an application type. */
  public enum Kind {
    /** No reason given (KMIP Unspecified). */
    UNSPECIFIED(Enums.RevocationReasonCode.UNSPECIFIED),
    /** The key was compromised (KMIP Key Compromise). */
    KEY_COMPROMISE(Enums.RevocationReasonCode.KEY_COMPROMISE),
    /** The issuing CA was compromised (KMIP CA Compromise). */
    CA_COMPROMISE(Enums.RevocationReasonCode.CA_COMPROMISE),
    /** The owner's affiliation changed (KMIP Affiliation Changed). */
    AFFILIATION_CHANGED(Enums.RevocationReasonCode.AFFILIATION_CHANGED),
    /** The object was replaced, for example by a rotation (KMIP Superseded). */
    SUPERSEDED(Enums.RevocationReasonCode.SUPERSEDED),
    /** The object is no longer needed (KMIP Cessation of Operation). */
    CESSATION_OF_OPERATION(Enums.RevocationReasonCode.CESSATION_OF_OPERATION),
    /** The owner's privilege was withdrawn (KMIP Privilege Withdrawn). */
    PRIVILEGE_WITHDRAWN(Enums.RevocationReasonCode.PRIVILEGE_WITHDRAWN);

    private final Enums.RevocationReasonCode wire;

    Kind(Enums.RevocationReasonCode wire) {
      this.wire = wire;
    }

    /**
     * The protocol-layer code.
     *
     * @return the KMIP value
     */
    public Enums.RevocationReasonCode protocolValue() {
      return wire;
    }

    /**
     * Whether this kind is a compromise: {@link #KEY_COMPROMISE} or {@link #CA_COMPROMISE}. A
     * revocation with it makes the object Compromised; any other kind deactivates it.
     *
     * @return true for a compromise
     * @since 0.10.0
     */
    public boolean compromise() {
      return this == KEY_COMPROMISE || this == CA_COMPROMISE;
    }
  }

  private final Kind kind;
  private final String message;
  private final Instant occurred;

  private RevocationReason(Kind kind, String message, Instant occurred) {
    this.kind = kind;
    this.message = message;
    this.occurred = occurred;
  }

  /**
   * The reason of {@code kind}, for a reason chosen at run time, such as from configuration or a
   * command line. The named factories give the same values.
   *
   * <pre>{@code
   * RevocationReason reason = RevocationReason.of(RevocationReason.Kind.SUPERSEDED, "key switch", null);
   * }</pre>
   *
   * @param kind the reason's kind
   * @param message free text to record with the revocation, or null for none
   * @param compromiseOccurred when the compromise happened (whole seconds), for a compromise kind;
   *     null for any other kind
   * @return the reason
   * @throws IllegalArgumentException when {@code kind} is a compromise and {@code
   *     compromiseOccurred} is null, or {@code kind} is not a compromise and it is not null
   * @since 0.10.0
   */
  public static RevocationReason of(Kind kind, String message, Instant compromiseOccurred) {
    Objects.requireNonNull(kind, "kind");
    if (kind.compromise() && compromiseOccurred == null)
      throw new IllegalArgumentException(
          kind + " needs the date the compromise happened (compromiseOccurred)");
    if (!kind.compromise() && compromiseOccurred != null)
      throw new IllegalArgumentException(
          kind + " is not a compromise, so it takes no compromise date");
    return new RevocationReason(
        kind, message, compromiseOccurred == null ? null : seconds(compromiseOccurred));
  }

  /**
   * The key was compromised at {@code occurredAt} (sent as the Compromise Occurrence Date, whole
   * seconds; the server records when it learned of it separately).
   *
   * @param message free text to record with the revocation, or null for none
   * @param occurredAt when the compromise happened (truncated to whole seconds)
   * @return the reason, of kind {@link Kind#KEY_COMPROMISE}
   */
  public static RevocationReason keyCompromise(String message, Instant occurredAt) {
    return new RevocationReason(Kind.KEY_COMPROMISE, message, seconds(occurredAt));
  }

  /**
   * The issuing CA was compromised at {@code occurredAt}.
   *
   * @param message free text to record with the revocation, or null for none
   * @param occurredAt when the compromise happened (truncated to whole seconds)
   * @return the reason, of kind {@link Kind#CA_COMPROMISE}
   */
  public static RevocationReason caCompromise(String message, Instant occurredAt) {
    return new RevocationReason(Kind.CA_COMPROMISE, message, seconds(occurredAt));
  }

  /**
   * The object was replaced, for example by a rotation: a reason {@link KeyHandle#revoke}
   * deactivates with.
   *
   * @param message free text to record with the revocation, or null for none
   * @return the reason, of kind {@link Kind#SUPERSEDED}
   */
  public static RevocationReason superseded(String message) {
    return new RevocationReason(Kind.SUPERSEDED, message, null);
  }

  /**
   * The object is no longer needed: a reason {@link KeyHandle#revoke} deactivates with.
   *
   * @param message free text to record with the revocation, or null for none
   * @return the reason, of kind {@link Kind#CESSATION_OF_OPERATION}
   */
  public static RevocationReason cessationOfOperation(String message) {
    return new RevocationReason(Kind.CESSATION_OF_OPERATION, message, null);
  }

  /**
   * The owner's affiliation changed: a reason {@link KeyHandle#revoke} deactivates with.
   *
   * @param message free text to record with the revocation, or null for none
   * @return the reason, of kind {@link Kind#AFFILIATION_CHANGED}
   */
  public static RevocationReason affiliationChanged(String message) {
    return new RevocationReason(Kind.AFFILIATION_CHANGED, message, null);
  }

  /**
   * The owner's privilege was withdrawn: a reason {@link KeyHandle#revoke} deactivates with.
   *
   * @param message free text to record with the revocation, or null for none
   * @return the reason, of kind {@link Kind#PRIVILEGE_WITHDRAWN}
   */
  public static RevocationReason privilegeWithdrawn(String message) {
    return new RevocationReason(Kind.PRIVILEGE_WITHDRAWN, message, null);
  }

  /**
   * No reason code, and no message: a reason {@link KeyHandle#revoke} deactivates with.
   *
   * @return the reason, of kind {@link Kind#UNSPECIFIED}
   */
  public static RevocationReason unspecified() {
    return new RevocationReason(Kind.UNSPECIFIED, null, null);
  }

  /**
   * No reason code, but a message: a reason {@link KeyHandle#revoke} deactivates with.
   *
   * @param message free text to record with the revocation, or null for none
   * @return the reason, of kind {@link Kind#UNSPECIFIED}
   * @since 0.10.0
   */
  public static RevocationReason unspecified(String message) {
    return new RevocationReason(Kind.UNSPECIFIED, message, null);
  }

  private static Instant seconds(Instant occurredAt) {
    return Objects.requireNonNull(occurredAt, "occurredAt").truncatedTo(ChronoUnit.SECONDS);
  }

  /**
   * The KMIP reason code.
   *
   * @return the kind
   */
  public Kind kind() {
    return kind;
  }

  /**
   * Free text recorded with the revocation.
   *
   * @return the text; empty when none was given
   */
  public Optional<String> message() {
    return Optional.ofNullable(message);
  }

  /**
   * When the compromise happened (compromise reasons only).
   *
   * @return when the compromise happened, to the second; empty for a reason that is not a
   *     compromise
   */
  public Optional<Instant> compromiseOccurred() {
    return Optional.ofNullable(occurred);
  }

  /**
   * Whether this reason is a compromise ({@link Kind#compromise()}).
   *
   * @return true for a key or CA compromise
   * @since 0.10.0
   */
  public boolean compromise() {
    return kind.compromise();
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof RevocationReason r
        && r.kind == kind
        && Objects.equals(r.message, message)
        && Objects.equals(r.occurred, occurred);
  }

  @Override
  public int hashCode() {
    return Objects.hash(kind, message, occurred);
  }

  @Override
  public String toString() {
    return "RevocationReason[" + kind + (occurred == null ? "" : ", occurred " + occurred) + "]";
  }
}
