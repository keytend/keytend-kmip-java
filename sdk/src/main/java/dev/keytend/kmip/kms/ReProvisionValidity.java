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

import static dev.keytend.kmip.model.Tag.DEACTIVATION_DATE;

import dev.keytend.kmip.client.Result;
import dev.keytend.kmip.model.Credentials;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Ttlv;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

/**
 * The wire form of a requested validity period ({@link CertificateRenewal#validFor}). KMIP 2.1
 * Re-Provision (section 6.1.48) and the 3.0 draft have no field for it, so the request carries
 * keytend-kmip-server's Message Extension on the Re-Provision batch item (its
 * docs/re-provision.md, "Validity period"):
 *
 * <pre>
 * Message Extension
 *   Vendor Identification   keytend_kmip_server
 *   Criticality Indicator   True
 *   Vendor Extension
 *     Deactivation Date     the notAfter asked for
 * </pre>
 *
 * <p>It is sent Critical. The server retires the current certificate when the message commits, so
 * a server that ignored a Non-Critical extension would issue its own period and retire the old
 * certificate before the client could see the difference. A server that does not understand a
 * Critical extension rejects the whole message before anything runs (KMIP 2.1 section 9.13), and
 * the current certificate stays in use. If a server issues another period anyway, {@link
 * ClientRenewal} still switches to the certificate rather than leave the client with a retired
 * certificate and a refused one.
 */
final class ReProvisionValidity {
  private ReProvisionValidity() {}

  /** keytend-kmip-server's Vendor Identification. */
  static final String VENDOR = "keytend_kmip_server";

  /**
   * The Vendor Identification and criticality sent. Tests change them to act as a client whose
   * extension a server does not understand.
   */
  static volatile String vendor = VENDOR;

  static volatile boolean critical = true;

  /** The notAfter to ask for: {@code validFor} from {@code now}, to the second (KMIP dates). */
  static Instant notAfter(Duration validFor, Instant now) {
    return now.plus(validFor).truncatedTo(ChronoUnit.SECONDS);
  }

  /** The Message Extension asking for {@code notAfter}, for the Re-Provision batch item. */
  static Ttlv extension(Instant notAfter) {
    return Credentials.extension(vendor, critical, Ttlv.dateTime(DEACTIVATION_DATE, notAfter));
  }

  /**
   * {@code refused}, the server's refusal of a Re-Provision that asked for {@code validFor} (a
   * notAfter of {@code notAfter}), with what the validity has to do with it: a server that does not
   * understand the extension rejects the whole message (Unknown Message Extension, or Feature Not
   * Supported); keytend-kmip-server refuses a date that has passed or is after its provisioning
   * CA's notAfter with Invalid Field, the likely cause, but it uses Invalid Field for other faults
   * of the request too. Either way nothing was issued. Other refusals are returned as they are.
   */
  static KmsException refused(
      KmsException refused,
      Result result,
      boolean wholeMessage,
      Duration validFor,
      Instant notAfter) {
    Enums.ResultReason reason = result.reasonEnum().orElse(null);
    String server = refused.getMessage();
    if (wholeMessage
        && (reason == Enums.ResultReason.UNKNOWN_MESSAGE_EXTENSION
            || reason == Enums.ResultReason.FEATURE_NOT_SUPPORTED))
      return new UnsupportedException(
          ClientRenewal.OP
              + ": the server does not take a requested validity ("
              + validFor
              + "): it refused the whole message ("
              + server
              + "), so it issued nothing and the current certificate stays in use."
              + " keytend-kmip-server takes one. Remove CertificateRenewal.validFor"
              + " to accept the server's period",
          refused,
          ClientRenewal.OP,
          null,
          refused.result().orElse(null),
          null);
    if (reason == Enums.ResultReason.INVALID_FIELD)
      return new InvalidRequestException(
          ClientRenewal.OP
              + ": the server refused the Re-Provision ("
              + server
              + ") with Invalid Field, so it issued nothing, and the current certificate stays in"
              + " use. A validity was asked for ("
              + validFor
              + ", a notAfter of "
              + notAfter
              + "). The likely cause: keytend-kmip-server refuses a period that ends after its"
              + " provisioning CA's notAfter rather than cut it short. It also answers Invalid"
              + " Field for a request it cannot read or whose signature or key it refuses; the"
              + " server's message above says which. For the period, ask for a shorter one, or"
              + " remove CertificateRenewal.validFor",
          refused,
          ClientRenewal.OP,
          null,
          refused.result().orElse(null),
          null);
    return refused;
  }
}
