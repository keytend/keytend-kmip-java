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
 * How the SDK renews the client's own TLS certificate, the one the configuration authenticates
 * with, through KMIP Re-Provision (KMIP 2.0 and later). Set it with {@link
 * KmsConfig.Builder#clientCertificateRenewal}; then {@link Kms#renewClientCertificate()} renews on
 * demand, and {@link #automatic(Duration)} also renews before the certificate expires.
 *
 * <pre>{@code
 * KmsConfig config = KmsConfig.builder()
 *     .endpoints("kms.example.com:5696")
 *     .clientIdentityPem(Path.of("client.crt"), Path.of("client.key"))
 *     .trustPem(Path.of("ca.pem"))
 *     .clientCertificateRenewal(CertificateRenewal.automatic(Duration.ofDays(30)))
 *     .build();
 * }</pre>
 *
 * <p>The SDK makes the new key pair itself, of the current key's algorithm and size or curve,
 * writes the new private key beside the key file before it sends anything, and sends a PKCS#10
 * request. It checks the certificate the server issues, then replaces the configured files. The
 * server retires the old certificate when it issues the new one, so read <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/production.md#renew-the-client-certificate">Renew
 * the client certificate</a> before you turn this on: it needs the server's provisioning CA, a
 * policy step after each renewal, and one certificate for each client.
 *
 * <p>Immutable: each method returns a new value.
 *
 * @since 0.10.0
 */
public final class CertificateRenewal {
  /**
   * The shortest validity {@link #validFor} asks for. The server's dates are whole seconds, and the
   * SDK checks the certificate only once it arrives, after the server retired the current one: a
   * shorter one could expire first. Automatic renewal renews such a certificate again after half
   * its remaining validity, which leaves room to retry a failure after the first backoffs (a
   * minute, then two).
   */
  static final Duration MIN_VALIDITY = Duration.ofMinutes(10);

  private final Duration renewBefore, validFor;
  private final boolean storeShared;

  private CertificateRenewal(Duration renewBefore, Duration validFor, boolean storeShared) {
    this.renewBefore = renewBefore;
    this.validFor = validFor;
    this.storeShared = storeShared;
  }

  /**
   * Renewal when the application calls {@link Kms#renewClientCertificate()}, and never on its own.
   *
   * @return the setting
   * @since 0.10.0
   */
  public static CertificateRenewal onDemand() {
    return new CertificateRenewal(null, null, false);
  }

  /**
   * Renewal on demand, and also on the SDK's own thread once the certificate expires within {@code
   * renewBefore}. Each open {@link Kms} checks the certificate's notAfter, at least once an hour,
   * and the {@code Kms} instances of one configuration make one attempt at a time. A failed attempt
   * is tried again after a minute, then after twice as long each time, up to an hour. {@link
   * KmsListener#clientCertificateRenewed}, {@link KmsListener#clientCertificateRenewalFailed} and
   * {@link KmsListener#clientCertificateMayBeLockedOut} report each attempt, once.
   *
   * <p>Choose {@code renewBefore} well within the certificate's validity: a third of it is common
   * (30 days for a 90-day certificate). A window longer than the validity of the certificates the
   * server issues would renew again at once. The SDK then reports the new certificate with {@link
   * KmsListener#clientCertificateRenewalWarning}, and renews it again after half its remaining
   * validity: always before it expires, and so never at once in a loop. The same holds for a
   * certificate the server issued for a shorter time than {@link #validFor} asks.
   *
   * <p>While a key that an earlier attempt moved aside may still be issued a certificate (see the
   * guide), each check also opens one new connection with the current certificate, at the failure
   * backoff's pace. When the server refuses it, the SDK looks for that certificate through the
   * connections still open on the current one, and finishes the renewal.
   *
   * @param renewBefore how long before the certificate's notAfter to renew it, positive
   * @return the setting
   * @throws IllegalArgumentException when {@code renewBefore} is not positive
   * @since 0.10.0
   */
  public static CertificateRenewal automatic(Duration renewBefore) {
    return new CertificateRenewal(positive(renewBefore, "renewBefore"), null, false);
  }

  /**
   * Ask for a new certificate valid for {@code validity}, instead of the period the server chooses
   * (one year on keytend-kmip-server). KMIP Re-Provision has no field for it, so the SDK sends the
   * notAfter it asks for in keytend-kmip-server's Message Extension on the Re-Provision item,
   * marked Critical.
   *
   * <ul>
   *   <li>A server that takes it issues a certificate that expires at that time.
   *   <li>A server that does not understand it refuses the whole message before anything is
   *       issued: the renewal fails with {@link UnsupportedException}, and the current certificate
   *       stays in use. Remove the period to renew there.
   *   <li>keytend-kmip-server refuses a period that ends after its provisioning CA's notAfter
   *       ({@link InvalidRequestException}), and the current certificate stays in use.
   * </ul>
   *
   * <p>The server retires the current certificate when it issues the new one, so the SDK never
   * refuses an issued certificate for its period alone: a server that issued another period anyway
   * would otherwise leave the client with a retired certificate and a refused one. A notAfter more
   * than a minute from the one asked for is reported with {@link
   * KmsListener#clientCertificateRenewalWarning}, which names both. {@link
   * RenewedCertificate#notAfter()} gives the period issued.
   *
   * <p>The period must be at least ten minutes. The server's dates are whole seconds, and the SDK
   * sees the certificate only after the server retired the current one, so a shorter certificate
   * could expire before the SDK can use it. With {@link #automatic(Duration)}, ten minutes also
   * leaves time to renew again after half the period and to retry a failure.
   *
   * @param validity the validity period to ask for, at least ten minutes
   * @return a copy with the period
   * @throws IllegalArgumentException when {@code validity} is shorter than ten minutes
   * @since 0.10.0
   */
  public CertificateRenewal validFor(Duration validity) {
    positive(validity, "validity");
    if (validity.compareTo(MIN_VALIDITY) < 0)
      throw new IllegalArgumentException(
          "validity must be at least "
              + MIN_VALIDITY
              + ": "
              + validity
              + ". The server's dates are whole seconds and the SDK checks the certificate only"
              + " after the server retired the current one, so a shorter certificate could expire"
              + " before it is used"
              + (renewBefore == null
                  ? ""
                  : ", and automatic renewal would have no time to renew it again or to retry a"
                      + " failure"));
    return new CertificateRenewal(renewBefore, validity, storeShared);
  }

  /**
   * State that the configured endpoints share one store, so each knows a certificate that another
   * retired. A configuration with several endpoints refuses renewal without it, because a renewal
   * through one endpoint would leave the old certificate valid on the others, or the new one
   * unknown there.
   *
   * @return a copy that allows several endpoints
   * @since 0.10.0
   */
  public CertificateRenewal endpointsShareOneStore() {
    return new CertificateRenewal(renewBefore, validFor, true);
  }

  /**
   * How long before expiry an automatic renewal starts.
   *
   * @return the window; empty for {@link #onDemand()}
   * @since 0.10.0
   */
  public Optional<Duration> renewBefore() {
    return Optional.ofNullable(renewBefore);
  }

  /**
   * The validity period asked for with {@link #validFor(Duration)}.
   *
   * @return the period; empty when the server chooses it
   * @since 0.10.0
   */
  public Optional<Duration> validFor() {
    return Optional.ofNullable(validFor);
  }

  /**
   * Whether {@link #endpointsShareOneStore()} was stated.
   *
   * @return true when several endpoints are allowed
   * @since 0.10.0
   */
  public boolean sharesOneStore() {
    return storeShared;
  }

  private static Duration positive(Duration d, String what) {
    Objects.requireNonNull(d, what);
    if (d.isNegative() || d.isZero())
      throw new IllegalArgumentException(what + " must be positive: " + d);
    return d;
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof CertificateRenewal r
        && Objects.equals(renewBefore, r.renewBefore)
        && Objects.equals(validFor, r.validFor)
        && storeShared == r.storeShared;
  }

  @Override
  public int hashCode() {
    return Objects.hash(renewBefore, validFor, storeShared);
  }

  @Override
  public String toString() {
    return "CertificateRenewal["
        + (renewBefore == null ? "on demand" : "automatic, " + renewBefore + " before expiry")
        + (validFor == null ? "" : ", valid for " + validFor)
        + (storeShared ? ", endpoints share one store" : "")
        + "]";
  }
}
