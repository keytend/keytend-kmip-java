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

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;

/**
 * A client certificate renewal that finished ({@link Kms#renewClientCertificate()}): the new
 * certificate is in the configured files and new connections use it. Fingerprints are the SHA-256
 * of the certificate's DER encoding, in lowercase hex, as keytend-kmip-server's policy file and
 * logs write them.
 *
 * @since 0.10.0
 */
public final class RenewedCertificate {
  private final List<X509Certificate> chain;
  private final String certificateId, previousFingerprint, fingerprint;
  private final boolean finishedEarlierAttempt;

  RenewedCertificate(
      List<X509Certificate> chain,
      String certificateId,
      String previousFingerprint,
      String fingerprint,
      boolean finishedEarlierAttempt) {
    this.chain = List.copyOf(chain);
    this.certificateId = certificateId;
    this.previousFingerprint = previousFingerprint;
    this.fingerprint = fingerprint;
    this.finishedEarlierAttempt = finishedEarlierAttempt;
  }

  /**
   * The new certificate.
   *
   * @return the certificate the server issued
   * @since 0.10.0
   */
  public X509Certificate certificate() {
    return chain.get(0);
  }

  /**
   * The chain written to the files: the new certificate, then the certificates of the previous
   * chain that issued it, if any.
   *
   * @return the chain, leaf first, unmodifiable
   * @since 0.10.0
   */
  public List<X509Certificate> chain() {
    return chain;
  }

  /**
   * The identifier of the new certificate's Certificate object on the server.
   *
   * @return the identifier; null when the SDK finished a switch of a PEM key and chain that stopped
   *     before the identifier was recorded (the chain file already held the new certificate)
   * @since 0.10.0
   */
  public String certificateId() {
    return certificateId;
  }

  /**
   * The fingerprint of the certificate replaced, which the server now refuses on new connections.
   *
   * @return the SHA-256 fingerprint, lowercase hex
   * @since 0.10.0
   */
  public String previousFingerprint() {
    return previousFingerprint;
  }

  /**
   * The fingerprint of the new certificate, for the server's policy file.
   *
   * @return the SHA-256 fingerprint, lowercase hex
   * @since 0.10.0
   */
  public String fingerprint() {
    return fingerprint;
  }

  /**
   * When the new certificate expires.
   *
   * @return its notAfter
   * @since 0.10.0
   */
  public Instant notAfter() {
    return certificate().getNotAfter().toInstant();
  }

  /**
   * Whether this call finished a renewal that an earlier call began and did not finish, such as one
   * whose reply was lost or whose process stopped, instead of asking the server for a new one.
   *
   * @return true when an earlier attempt was finished
   * @since 0.10.0
   */
  public boolean finishedEarlierAttempt() {
    return finishedEarlierAttempt;
  }

  @Override
  public String toString() {
    return "RenewedCertificate["
        + previousFingerprint
        + " -> "
        + fingerprint
        + ", id "
        + certificateId
        + ", notAfter "
        + notAfter()
        + (finishedEarlierAttempt ? ", finished an earlier attempt" : "")
        + "]";
  }
}
