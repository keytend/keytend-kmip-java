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

/**
 * How {@link TlsIdentityHandle#reissue(TlsReissue)} reissues an identity's certificate: for the
 * same key or a new key pair, for how long, and by which issuer. Immutable.
 *
 * <pre>{@code
 * node = node.reissue(TlsReissue.newKey().validFor(Duration.ofDays(30)));
 * node = node.reissueIfExpiresWithin(Duration.ofDays(10), TlsReissue.sameKey().issuedBy(newCa));
 * }</pre>
 *
 * <p>A reissue asks for the subject and subject alternative names of the certificate it replaces.
 * By default it asks for the server's own validity, and the issuer is the CA certificate the
 * replaced certificate links to.
 *
 * @since 0.10.0
 */
public final class TlsReissue {
  private final boolean newKey;
  private final KeyPairSpec spec;
  private final Duration validFor;
  private final TlsIssuer issuer;

  private TlsReissue(boolean newKey, KeyPairSpec spec, Duration validFor, TlsIssuer issuer) {
    this.newKey = newKey;
    this.spec = spec;
    this.validFor = validFor;
    this.issuer = issuer;
  }

  /**
   * A new certificate for the identity's private key. The key must be Active, and have a public
   * key object linked to it and back, as an issued identity's has.
   *
   * @return the options
   * @since 0.10.0
   */
  public static TlsReissue sameKey() {
    return new TlsReissue(false, null, null, null);
  }

  /**
   * A new key pair of the current key's algorithm and size, and a new certificate for it.
   *
   * @return the options
   * @since 0.10.0
   */
  public static TlsReissue newKey() {
    return new TlsReissue(true, null, null, null);
  }

  /**
   * A new key pair of {@code spec}, and a new certificate for it.
   *
   * @param spec RSA of at least 2048 bits, or EC on P-256, P-384 or P-521
   * @return the options
   * @throws IllegalArgumentException for RSA below 2048 bits
   * @since 0.10.0
   */
  public static TlsReissue newKey(KeyPairSpec spec) {
    Objects.requireNonNull(spec, "spec");
    TlsCertify.checkSpec(spec, "reissue");
    return new TlsReissue(true, spec, null, null);
  }

  /**
   * How long the new certificate is valid from now, as {@link
   * TlsIdentityIssuance#validFor(Duration)} says, the shortest validity a call asks for included.
   *
   * @param validFor how long, positive
   * @return options with this validity
   * @throws IllegalArgumentException when it is not positive
   * @since 0.10.0
   */
  public TlsReissue validFor(Duration validFor) {
    Objects.requireNonNull(validFor, "validFor");
    if (validFor.isNegative() || validFor.isZero())
      throw new IllegalArgumentException("validFor must be positive: " + validFor);
    return new TlsReissue(newKey, spec, validFor, issuer);
  }

  /**
   * The CA in the KMS that signs the new certificate, for example a new CA that replaces the old
   * one.
   *
   * @param issuer the issuer
   * @return options with this issuer
   * @since 0.10.0
   */
  public TlsReissue issuedBy(TlsIssuer issuer) {
    return new TlsReissue(newKey, spec, validFor, Objects.requireNonNull(issuer, "issuer"));
  }

  boolean newKeyPair() {
    return newKey;
  }

  TlsCertify request() {
    return TlsCertify.reissue(spec, validFor, issuer);
  }

  @Override
  public String toString() {
    return "TlsReissue["
        + (newKey ? "new key" + (spec == null ? "" : " " + spec) : "same key")
        + (validFor == null ? "" : ", valid for " + validFor)
        + (issuer == null ? "" : ", issued by " + issuer.name())
        + "]";
  }
}
