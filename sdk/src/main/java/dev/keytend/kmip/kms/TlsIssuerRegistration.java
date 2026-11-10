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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Registers an issuing CA ({@link KmsTls#registerIssuer}): {@code
 * kms.tls().registerIssuer(caKey, caCertificate).named("cluster1/issuing-ca").register()}. The CA
 * private key is registered with the usages Sign and Certificate Sign, the CA public key with
 * Verify, and each certificate with the usages its own X.509 Key Usage extension grants. The name
 * and the custom attributes go on the CA certificate. Not thread-safe.
 *
 * @since 0.10.0
 */
public final class TlsIssuerRegistration {
  private final KmsTls tls;
  private final PrivateKey key;
  private final List<X509Certificate> chain;
  private final Map<CustomAttribute, Object> custom = new LinkedHashMap<>();
  private String name;

  TlsIssuerRegistration(KmsTls tls, PrivateKey key, List<X509Certificate> chain) {
    this.tls = tls;
    this.key = key;
    this.chain = chain;
  }

  /**
   * The issuer's name (required, one): {@link KmsTls#issuer(String)} finds the issuer by it.
   *
   * @param name the name, not empty
   * @return this builder
   * @since 0.10.0
   */
  public TlsIssuerRegistration named(String name) {
    Objects.requireNonNull(name, "name");
    if (name.isEmpty()) throw new IllegalArgumentException("Empty name");
    this.name = name;
    return this;
  }

  /**
   * Sets a custom attribute on the CA certificate, for example a tag that the anchors query of
   * {@link KmsTls#trustAnchors(KeyQuery, java.time.Duration,
   * java.util.concurrent.ScheduledExecutorService)} matches.
   *
   * @param attribute the attribute
   * @param value its value, of a type {@link KeyAttributes} lists; a {@code byte[]} is copied here
   * @return this builder
   * @since 0.10.0
   */
  public TlsIssuerRegistration custom(CustomAttribute attribute, Object value) {
    Objects.requireNonNull(attribute, "attribute");
    AttributeReader.encode(Objects.requireNonNull(value, "value"));
    custom.put(attribute, value instanceof byte[] b ? b.clone() : value);
    return this;
  }

  /**
   * Registers the issuer, as {@link TlsIdentityRegistration#register()} registers an identity.
   * The CA certificate, the CA private key, the CA public key and the other certificates of the
   * chain are registered Pre-Active under a temporary name that only this call uses, then linked.
   * The CA certificate then gets the name, the switch, and they are activated, the CA certificate
   * last. Until the name no lookup finds the issuer, and until the CA certificate's Activate,
   * Certify refuses it.
   *
   * <p>When the call stops part-way ({@link PartialCompletionException}) or its outcome is unknown,
   * repeat it with the same key and chain. Before the name, a repeat starts over, and what the
   * stopped call registered is left over, none of it activated. After the name, a repeat activates
   * the objects and returns the issuer, but only when the certificate's chain and key are the ones
   * given. What a stopped call leaves is as for an identity (<a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/tls-identities.md#what-a-stopped-call-leaves">TLS
   * identities</a>).
   *
   * @return the issuer
   * @throws IllegalStateException when no name was given; nothing is sent
   * @throws AlreadyExistsException when a certificate or another object has the name already;
   *     nothing was registered. Also when the server refuses the name although no object it
   *     locates has it, as {@link TlsIdentityRegistration#register()} says
   * @throws StateConflictException as {@link TlsIdentityRegistration#register()} says for a repeat
   *     that finds the name given by an earlier call
   * @throws PartialCompletionException when a step after the first registration failed: repeat
   * @since 0.10.0
   */
  public TlsIssuer register() {
    if (name == null) throw new IllegalStateException("register: name the issuer first (named)");
    return new TlsIssue(
            tls, TlsIssue.Kind.REGISTER_ISSUER, name, key, chain, new LinkedHashMap<>(custom), null)
        .runIssuer();
  }
}
