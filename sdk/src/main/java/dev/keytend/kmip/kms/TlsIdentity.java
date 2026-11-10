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
import java.util.List;

/**
 * A pair a {@link TlsIdentityFollower} presents: the identity's leaf certificate and chain, and the
 * identifiers of the certificate and of its private key, as read from the KMS. The private key
 * itself is not part of it; the follower's key manager hands it to JSSE. Immutable; equal when
 * the name and both identifiers are.
 *
 * @since 0.10.0
 */
public final class TlsIdentity {
  private final String name, certificateId, privateKeyId;
  private final List<X509Certificate> chain;

  TlsIdentity(String name, String certificateId, String privateKeyId, List<X509Certificate> chain) {
    this.name = name;
    this.certificateId = certificateId;
    this.privateKeyId = privateKeyId;
    this.chain = List.copyOf(chain);
  }

  /**
   * The identity's name.
   *
   * @return the name
   * @since 0.10.0
   */
  public String name() {
    return name;
  }

  /**
   * The identifier of the leaf certificate.
   *
   * @return the leaf certificate's identifier
   * @since 0.10.0
   */
  public String certificateId() {
    return certificateId;
  }

  /**
   * The identifier of the private key.
   *
   * @return the private key's identifier
   * @since 0.10.0
   */
  public String privateKeyId() {
    return privateKeyId;
  }

  /**
   * The leaf certificate.
   *
   * @return the leaf certificate, the first of {@link #chain()}
   * @since 0.10.0
   */
  public X509Certificate certificate() {
    return chain.get(0);
  }

  /**
   * The chain presented, the leaf first.
   *
   * @return the chain, leaf first; unmodifiable
   * @since 0.10.0
   */
  public List<X509Certificate> chain() {
    return chain;
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof TlsIdentity t
        && t.name.equals(name)
        && t.certificateId.equals(certificateId)
        && t.privateKeyId.equals(privateKeyId);
  }

  @Override
  public int hashCode() {
    return java.util.Objects.hash(name, certificateId, privateKeyId);
  }

  @Override
  public String toString() {
    return "TlsIdentity["
        + name
        + ", certificate "
        + certificateId
        + " ("
        + certificate().getSubjectX500Principal()
        + ", serial "
        + certificate().getSerialNumber().toString(16)
        + "), private key "
        + privateKeyId
        + "]";
  }
}
