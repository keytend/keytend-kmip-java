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
 * Registers a TLS identity ({@link KmsTls#register}): {@code kms.tls().register(privateKey, leaf,
 * intermediate).named("cassandra/node1").register()}. The private key is registered with the
 * usage Sign; each certificate with the usages its own X.509 Key Usage extension grants (Verify
 * for a leaf's digitalSignature, Certificate Sign and CRL Sign for a CA's keyCertSign and cRLSign;
 * see {@link KmsKeys#register(java.security.cert.X509Certificate)}), which KMIP 1.x servers may
 * not let a mask exceed. The name and the custom attributes go on the leaf certificate, and
 * renewals copy the custom attributes to the new leaf. Not thread-safe.
 *
 * @since 0.10.0
 */
public final class TlsIdentityRegistration {
  private final KmsTls tls;
  private final PrivateKey key;
  private final List<X509Certificate> chain;
  private final Map<CustomAttribute, Object> custom = new LinkedHashMap<>();
  private String name;

  TlsIdentityRegistration(KmsTls tls, PrivateKey key, List<X509Certificate> chain) {
    this.tls = tls;
    this.key = key;
    this.chain = chain;
  }

  /**
   * The identity's name (required, one): readers and followers find the identity by it.
   *
   * @param name the name, not empty
   * @return this builder
   * @since 0.10.0
   */
  public TlsIdentityRegistration named(String name) {
    Objects.requireNonNull(name, "name");
    if (name.isEmpty()) throw new IllegalArgumentException("Empty name");
    this.name = name;
    return this;
  }

  /**
   * Sets a custom attribute on the leaf certificate, for example a tag that an allowed-peers query
   * of {@link KmsTls#trustAnchors(KeyQuery, KeyQuery, java.time.Duration,
   * java.util.concurrent.ScheduledExecutorService)} matches; see {@link KeyAttributes} for the
   * value types.
   *
   * @param attribute the attribute
   * @param value its value, of a type {@link KeyAttributes} lists; a {@code byte[]} is copied
   *     here, so later changes to the caller's array are not registered
   * @return this builder
   * @since 0.10.0
   */
  public TlsIdentityRegistration custom(CustomAttribute attribute, Object value) {
    Objects.requireNonNull(attribute, "attribute");
    AttributeReader.encode(Objects.requireNonNull(value, "value"));
    custom.put(attribute, value instanceof byte[] b ? b.clone() : value);
    return this;
  }

  /**
   * Registers the identity. The leaf certificate, the private key and the other certificates of
   * the chain are registered Pre-Active under a temporary name that only this call uses, then
   * linked. The leaf is then given the name, the switch, and they are activated, the leaf last.
   * Until the name no reader finds the identity, and until the leaf's Activate a follower finds
   * nothing to present.
   *
   * <p>When the call stops part-way ({@link PartialCompletionException}) or its outcome is unknown,
   * repeat it with the same key and chain. Before the name, a repeat starts over, and what the
   * stopped call registered is left over. The call activates none of it before the name, and gives
   * it no name but its temporary one (the identity's name, {@code .issuing-} and a random part).
   * The exception lists it ({@link PartialCompletionException#created()}). After the name, a repeat
   * activates the pair and returns the identity, but only when the leaf's chain and key are the
   * ones given. Otherwise it stops, as below. How to find and clean up what a stopped call leaves
   * is in <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/tls-identities.md#what-a-stopped-call-leaves">TLS
   * identities</a>.
   *
   * <p>The call changes an object it registered only while a read just before shows it as this
   * call left it, and stops at the first that is not (<a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/kms-design.md#tls-identities">design
   * notes</a>). About 26 + 16 n requests for a chain of n certificates (27 + 17 n on KMIP 1.x).
   *
   * @return the identity
   * @throws IllegalStateException when no name was given; nothing is sent
   * @throws AlreadyExistsException when a certificate has the name already (another identity, or a
   *     revoked one: renew or re-key it with {@link KmsTls#identity(String)} instead, which also
   *     replaces a revoked or compromised identity; or a Pre-Active one another registration is
   *     making), or a destroyed one where Locate returns destroyed objects; nothing was registered.
   *     Also when the server refuses the name although no object it locates has it (a server that
   *     keeps the names of destroyed objects, such as keytend-kmip-server with
   *     --destroyed-name-reuse reserve): the call activated none of the objects it registered and
   *     gave none the name, and the message lists them. Register under another name
   * @throws StateConflictException when a repeat finds the name on this leaf already, given by an
   *     earlier call, and the leaf's chain or private key is not the one given, or the leaf, its key
   *     or a Pre-Active certificate of its chain is not as that call left it ({@link
   *     KmsException#objectId()} names it); nothing was changed. The message says how to finish
   * @throws PartialCompletionException when a step after the first registration failed: repeat.
   *     Its cause is a {@code StateConflictException} when another caller changed an object this
   *     call registered: do as that says
   * @since 0.10.0
   */
  public TlsIdentityHandle register() {
    if (name == null) throw new IllegalStateException("register: name the identity first (named)");
    return new TlsIssue(
            tls, TlsIssue.Kind.REGISTER, name, key, chain, new LinkedHashMap<>(custom), null)
        .run();
  }
}
