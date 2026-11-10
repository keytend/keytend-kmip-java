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

import java.util.List;

/**
 * An issuing CA kept in the KMS, which signs the certificates of {@link KmsTls#issue} and {@link
 * TlsIdentityHandle#reissue()} through KMIP Certify. Register one with {@link
 * KmsTls#registerIssuer}, or look one up with {@link KmsTls#issuer(String)}.
 *
 * <p>The CA's objects are linked the way Certify finds the signing key: the CA certificate, which
 * has the name, links to the CA public key (Public Key link), which links to the CA private key
 * (Private Key link). The private key links back to both, and the certificate also links to the
 * private key, as a TLS identity's leaf does. The CA certificate's Certificate link names the next
 * certificate of its chain, and so on.
 *
 * <p>A handle names these objects. It reads nothing by itself.
 *
 * @since 0.10.0
 */
public final class TlsIssuer {
  private final String name;
  private final KeyHandle certificate, publicKey, privateKey;
  private final List<KeyHandle> chain;

  TlsIssuer(
      String name,
      KeyHandle certificate,
      KeyHandle publicKey,
      KeyHandle privateKey,
      List<KeyHandle> chain) {
    this.name = name;
    this.certificate = certificate;
    this.publicKey = publicKey;
    this.privateKey = privateKey;
    this.chain = List.copyOf(chain);
  }

  /**
   * The issuer's name, which its CA certificate has.
   *
   * @return the name
   * @since 0.10.0
   */
  public String name() {
    return name;
  }

  /**
   * The CA certificate. An issued certificate's Certificate link names it.
   *
   * @return the CA certificate's handle
   * @since 0.10.0
   */
  public KeyHandle certificate() {
    return certificate;
  }

  /**
   * The CA public key, which the CA certificate's Public Key link names.
   *
   * @return the CA public key's handle
   * @since 0.10.0
   */
  public KeyHandle publicKey() {
    return publicKey;
  }

  /**
   * The CA private key, which the CA public key's Private Key link names, and which signs the
   * certificates the KMS issues.
   *
   * @return the CA private key's handle
   * @since 0.10.0
   */
  public KeyHandle privateKey() {
    return privateKey;
  }

  /**
   * The CA certificate and the certificates above it, as the links name them when the handle was
   * made. An issued identity's chain is its leaf and these.
   *
   * @return the chain's handles, the CA certificate first; unmodifiable
   * @since 0.10.0
   */
  public List<KeyHandle> chain() {
    return chain;
  }

  @Override
  public String toString() {
    return "TlsIssuer["
        + name
        + ", certificate "
        + certificate.id()
        + ", public key "
        + publicKey.id()
        + ", private key "
        + privateKey.id()
        + "]";
  }
}
