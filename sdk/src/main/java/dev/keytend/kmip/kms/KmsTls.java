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
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;

/**
 * TLS identities and trust anchors kept in the KMS. Get it from {@link Kms#tls()}. An identity is
 * a private key and its certificate chain under one name. Followers give a JSSE key manager the
 * current identity at each handshake, and a trust manager the current anchors and allowed peers.
 *
 * <pre>{@code
 * KmsTls tls = kms.tls();
 * TlsIdentityHandle node = tls.register(privateKey, leaf, intermediate)
 *     .named("payments/node1").register();
 * node = node.renew(renewedLeaf, intermediate);       // same key, new certificate
 * KeyQuery anchors = KeyQuery.all().custom(tag, "cluster1:ca");
 * TlsIdentityFollower identity = tls.follow("payments/node1", Duration.ofMinutes(1), scheduler);
 * TlsTrustFollower trust = tls.trustAnchors(anchors, Duration.ofMinutes(1), scheduler);
 * SSLContext ssl = SSLContext.getInstance("TLS");
 * ssl.init(new KeyManager[] {identity.keyManager()}, new TrustManager[] {trust.trustManager()},
 *     null);
 * }</pre>
 *
 * <p>{@code leaf}, {@code renewedLeaf} and {@code intermediate} are {@code X509Certificate}s.
 * {@code tag} is a {@link CustomAttribute}. {@code scheduler} is a {@code
 * ScheduledExecutorService} you own.
 *
 * <p>The leaf certificate alone has the name, and links lead to its private key and issuers. A
 * renewal or re-key links a new leaf to the old one, as Re-key links keys. Registration, renewal
 * and re-key are single-actor jobs. Run one at a time per identity, from one place.
 *
 * <p>A call registers and links the new objects Pre-Active. One request, the switch, then makes
 * them the identity's. It sets the old leaf's Replacement link, or a new identity's name. The call
 * then activates them, the leaf last, so readers never see a certificate without its key, or a gap
 * while a name moves. It activates nothing before the switch. A call that stopped part-way ({@link
 * PartialCompletionException}) is finished by repeating it with the same arguments. Before the
 * switch, the repeat starts over, and what the stopped call registered is left over.
 * After it, the repeat finishes the call when the switched-in objects hold the chain and key given.
 * What a stopped call leaves, and how to clean it up, is in <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/tls-identities.md#what-a-stopped-call-leaves">TLS
 * identities</a>.
 *
 * <p>The KMS can also issue an identity ({@link #issue}): it creates the key pair, and a CA it
 * holds ({@link #registerIssuer}) signs the certificate through KMIP Certify. The SDK checks the
 * certificate, then switches it in as a registration does. {@link TlsIdentityHandle#reissue()}
 * gets a new certificate the same way. See <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/tls-identities.md#issue-from-the-kms">Issue
 * from the KMS</a>.
 *
 * <p>{@code KmsTls} is thread-safe and holds no resource. The followers it returns are the
 * caller's to close.
 *
 * @since 0.10.0
 */
public final class KmsTls {
  private final KmsKeys keys;

  KmsTls(KmsKeys keys) {
    this.keys = keys;
  }

  KmsKeys keys() {
    return keys;
  }

  /**
   * Starts registering an identity: {@code privateKey} and its certificate chain, the leaf (whose
   * public key is {@code privateKey}'s) first, each certificate followed by its issuer. The root
   * may be left out, as TLS peers usually leave it. Name it, then {@link
   * TlsIdentityRegistration#register()}.
   *
   * @param privateKey the identity's private key (RSA or EC)
   * @param chain the certificate chain, leaf first
   * @return a registration to name and register
   * @throws IllegalArgumentException when the chain is empty or out of order, or the leaf is not
   *     for {@code privateKey}, or the key is neither RSA nor EC; nothing is sent
   * @since 0.10.0
   */
  public TlsIdentityRegistration register(PrivateKey privateKey, X509Certificate... chain) {
    Objects.requireNonNull(privateKey, "privateKey");
    List<X509Certificate> checked = TlsIdentities.checkedChain("register", chain);
    if (!TlsIdentities.matches(privateKey, checked.get(0).getPublicKey()))
      throw new IllegalArgumentException(
          "register: the leaf certificate ("
              + checked.get(0).getSubjectX500Principal()
              + ") is not for this"
              + " private key");
    return new TlsIdentityRegistration(this, privateKey, checked);
  }

  /**
   * Starts registering an issuing CA for {@link #issue}: its private key, its certificate, and the
   * certificates above it, each followed by its issuer. Name it, then {@link
   * TlsIssuerRegistration#register()}. The objects are linked the way KMIP Certify finds the
   * signing key ({@link TlsIssuer}). keytend-kmip-server signs only with a CA whose certificate and
   * keys the caller's credentials own.
   *
   * @param caPrivateKey the CA's private key (RSA or EC)
   * @param caCertificate the CA's certificate, for {@code caPrivateKey}, with basicConstraints
   *     cA=TRUE and, when it has a Key Usage extension, keyCertSign
   * @param intermediates the certificates above it, the CA certificate's issuer first; may be
   *     empty
   * @return a registration to name and register
   * @throws IllegalArgumentException when the chain is out of order, the certificate is not for
   *     {@code caPrivateKey} or is not a CA certificate, or the key is neither RSA nor EC; nothing
   *     is sent
   * @since 0.10.0
   */
  public TlsIssuerRegistration registerIssuer(
      PrivateKey caPrivateKey, X509Certificate caCertificate, X509Certificate... intermediates) {
    Objects.requireNonNull(caPrivateKey, "caPrivateKey");
    Objects.requireNonNull(caCertificate, "caCertificate");
    Objects.requireNonNull(intermediates, "intermediates");
    X509Certificate[] all = new X509Certificate[intermediates.length + 1];
    all[0] = caCertificate;
    System.arraycopy(intermediates, 0, all, 1, intermediates.length);
    List<X509Certificate> checked = TlsIdentities.checkedChain("registerIssuer", all);
    if (!TlsIdentities.matches(caPrivateKey, caCertificate.getPublicKey()))
      throw new IllegalArgumentException(
          "registerIssuer: the CA certificate ("
              + caCertificate.getSubjectX500Principal()
              + ") is not for this private key");
    boolean[] usage = caCertificate.getKeyUsage();
    if (caCertificate.getBasicConstraints() < 0
        || (usage != null && (usage.length <= 5 || !usage[5])))
      throw new IllegalArgumentException(
          "registerIssuer: "
              + caCertificate.getSubjectX500Principal()
              + " is not a CA certificate that may sign certificates (basicConstraints cA=TRUE,"
              + " and keyCertSign when it has a Key Usage extension)");
    return new TlsIssuerRegistration(this, caPrivateKey, checked);
  }

  /**
   * The issuer named {@code name}, in whatever state: its CA certificate, the private and public
   * keys linked to it, and its chain, found as {@link #identity(String)} finds an identity.
   *
   * @param name the issuer's name
   * @return empty when no certificate has the name
   * @throws StateConflictException when the name's certificate has no private key that links to it
   *     and back, or no public key object that it links to and that links to that private key (not
   *     an issuer {@link #registerIssuer} made)
   * @since 0.10.0
   */
  public Optional<TlsIssuer> issuer(String name) {
    Objects.requireNonNull(name, "name");
    return keys.kms()
        .call(
            "issuer",
            () -> {
              Optional<TlsIdentities.Found> found = TlsIdentities.find(keys, name, List.of(), null);
              if (found.isEmpty()) return Optional.empty();
              Map<String, KeyAttributes> read = found.get().read;
              KeyAttributes certificate = found.get().current();
              KeyAttributes key = TlsIdentities.keyOf(keys, certificate, read);
              String publicKey = null;
              if (key != null)
                for (String id : certificate.links(LinkKind.PUBLIC_KEY)) {
                  KeyAttributes p = TlsIdentities.attributes(keys, read, id);
                  if (p != null
                      && p.kind() == ObjectKind.PUBLIC_KEY
                      && p.links(LinkKind.PRIVATE_KEY).equals(List.of(key.id()))) publicKey = id;
                }
              if (publicKey == null)
                throw new StateConflictException(
                        "issuer: certificate "
                            + certificate.id()
                            + " has the name "
                            + name
                            + ", and no private key and public key object link to it and to"
                            + " each other as an issuer's do; register one with"
                            + " kms.tls().registerIssuer(caKey, caCertificate)",
                        null,
                        "issuer",
                        certificate.id(),
                        null,
                        null)
                    .because(StateConflictException.Conflict.LINEAGE)
                    .observed(certificate.state());
              List<KeyHandle> chain =
                  TlsIdentities.chainIds(keys, certificate, read).stream()
                      .map(keys::handle)
                      .toList();
              return Optional.of(
                  new TlsIssuer(
                      name,
                      keys.handle(certificate.id()),
                      keys.handle(publicKey),
                      keys.handle(key.id()),
                      chain));
            });
  }

  /**
   * Starts issuing an identity from the KMS: the KMS creates its key pair and signs its
   * certificate with KMIP Certify, with a CA held in the KMS ({@link
   * TlsIdentityIssuance#issuedBy}) or the server's own. Set what the certificate says, then {@link
   * TlsIdentityIssuance#issue()}. The identity is then followed, renewed and revoked as a
   * registered one is, and reissued with {@link TlsIdentityHandle#reissue()}.
   *
   * @param name the identity's name, not empty
   * @return an issuance to fill in and issue
   * @since 0.10.0
   */
  public TlsIdentityIssuance issue(String name) {
    Objects.requireNonNull(name, "name");
    if (name.isEmpty()) throw new IllegalArgumentException("Empty name");
    return new TlsIdentityIssuance(this, name);
  }

  /**
   * The identity named {@code name}, in whatever state: its current certificate, the private key
   * linked to it and its chain. The current certificate is the newest activated one the name
   * leads to, through Replacement links both certificates confirm. Use it to renew, re-key or
   * revoke the identity, also after it was revoked or compromised. Costs one Locate, one batched
   * Get Attributes, and one Get Attributes per link followed.
   *
   * @param name the identity's name
   * @return empty when no certificate has the name, and none records it as being moved to it
   * @throws StateConflictException when the name's certificate has no private key that links to it
   *     and back (not an identity this API made), or the certificates with the name cannot be
   *     ranked (as {@link KmsKeys#findByName})
   * @since 0.10.0
   */
  public Optional<TlsIdentityHandle> identity(String name) {
    Objects.requireNonNull(name, "name");
    return keys.kms()
        .call(
            "identity",
            () -> {
              Optional<TlsIdentities.Found> found = TlsIdentities.find(keys, name, List.of(), null);
              if (found.isEmpty()) return Optional.empty();
              KeyAttributes leaf = found.get().current();
              KeyAttributes key = TlsIdentities.keyOf(keys, leaf, found.get().read);
              if (key == null)
                throw new StateConflictException(
                        "identity: certificate "
                            + leaf.id()
                            + " has the name "
                            + name
                            + ", and no private key links to it"
                            + " and back, so it is not a TLS identity; register one with kms.tls().register(key, chain)",
                        null,
                        "identity",
                        leaf.id(),
                        null,
                        null)
                    .because(StateConflictException.Conflict.LINEAGE)
                    .observed(leaf.state());
              List<KeyHandle> chain =
                  TlsIdentities.chainIds(keys, leaf, found.get().read).stream()
                      .map(keys::handle)
                      .toList();
              return Optional.of(
                  new TlsIdentityHandle(
                      this, name, keys.handle(leaf.id()), keys.handle(key.id()), chain));
            });
  }

  /**
   * Follows the identity named {@code name}: reads it now, on the caller's thread, then every
   * {@code refreshEvery} on {@code executor}, and gives out a key manager that presents the pair
   * read last at each handshake without asking the KMS ({@link TlsIdentityFollower}). The executor
   * is the caller's: {@link TlsIdentityFollower#close()} cancels the follower's task, not the
   * executor.
   *
   * @param name the identity's name
   * @param refreshEvery how often to read the identity again, positive
   * @param executor the caller's executor that runs the refreshes; not shut down by the follower
   * @return the follower, presenting the pair read now; the caller closes it
   * @throws NotFoundException when no certificate has the name
   * @throws StateConflictException when the identity has no whole pair to present now: its
   *     current certificate or private key is not Active (revoked, compromised, deactivated without
   *     an Active replacement, or Pre-Active while a registration has not activated it yet), or
   *     they do not link to or match each other
   * @throws KmsException when the first read fails (the KMS unreachable, say), or no lease of the
   *     pair can be obtained where its objects have a KMIP Lease Time; nothing is scheduled
   * @throws IllegalArgumentException when {@code refreshEvery} is not positive
   * @since 0.10.0
   */
  public TlsIdentityFollower follow(
      String name, Duration refreshEvery, ScheduledExecutorService executor) {
    return TlsIdentityFollower.start(
        keys,
        Objects.requireNonNull(name, "name"),
        refreshEvery,
        Objects.requireNonNull(executor, "executor"));
  }

  /**
   * Follows the Active certificates {@code anchors} matches as the trust anchors of a trust
   * manager ({@link TlsTrustFollower}): read now, then every {@code refreshEvery} on {@code
   * executor}. Certificates that are revoked, compromised, deactivated or destroyed in the KMS are
   * not anchors from the next refresh on, whatever the query says about state and kind.
   *
   * @param anchors the query for the anchor certificates
   * @param refreshEvery how often to read the anchors again, positive
   * @param executor the caller's executor that runs the refreshes; not shut down by the follower
   * @return the follower, trusting the anchors read now; the caller closes it
   * @throws KmsException when the first read fails, or an Obtain Lease of what it read fails
   *     (certificates with a KMIP Lease Time); nothing is scheduled
   * @throws IllegalArgumentException when {@code refreshEvery} is not positive
   * @since 0.10.0
   */
  public TlsTrustFollower trustAnchors(
      KeyQuery anchors, Duration refreshEvery, ScheduledExecutorService executor) {
    return TlsTrustFollower.start(
        keys,
        Objects.requireNonNull(anchors, "anchors"),
        null,
        refreshEvery,
        Objects.requireNonNull(executor, "executor"));
  }

  /**
   * {@link #trustAnchors(KeyQuery, Duration, ScheduledExecutorService)} with a peer allowlist, for
   * mutual TLS. A peer is accepted only when its own certificate, the first of the chain it
   * presents, is also one of the Active certificates {@code allowedPeers} matches. Certificates are
   * compared by their DER encoding. A client whose certificate is revoked in the KMS is refused at
   * its first handshake after the next refresh, even though its chain still validates.
   *
   * <p>A peer that has just renewed presents a certificate the allowlist has not read yet. When
   * its chain validates, the follower checks the KMS once, within a short timeout and rate limits
   * ({@link TlsTrustFollower}). By default the check runs on the executor. That handshake is
   * refused, and the peer's next one is accepted once the certificate is found Active. Renewals
   * copy the leaf's custom attributes, so a query by custom attribute matches the renewed leaf. A
   * renewed peer still presents its old, deactivated certificate until its own follower
   * refreshes. Refresh that follower right after the renewal, keep its interval short, and let
   * clients retry.
   *
   * @param anchors the query for the anchor certificates
   * @param allowedPeers the query for the peer certificates to accept
   * @param refreshEvery how often to read both again, positive
   * @param executor the caller's executor that runs the refreshes and the checks of unknown peers;
   *     not shut down by the follower
   * @return the follower, trusting what was read now; the caller closes it
   * @throws KmsException when the first read fails, or an Obtain Lease of what it read fails
   *     (certificates with a KMIP Lease Time); nothing is scheduled
   * @throws IllegalArgumentException when {@code refreshEvery} is not positive
   * @since 0.10.0
   */
  public TlsTrustFollower trustAnchors(
      KeyQuery anchors,
      KeyQuery allowedPeers,
      Duration refreshEvery,
      ScheduledExecutorService executor) {
    return TlsTrustFollower.start(
        keys,
        Objects.requireNonNull(anchors, "anchors"),
        Objects.requireNonNull(allowedPeers, "allowedPeers"),
        refreshEvery,
        Objects.requireNonNull(executor, "executor"));
  }

  /**
   * The certificates {@code query} matches, by identifier. Only certificates are kept. It sends
   * one Locate, one batched Get Attributes and one batched Get, and checks each object found
   * against the query locally, since some servers ignore filters on client attributes. The
   * query's state filter applies as given: add {@code state(KeyState.ACTIVE)} for the usable ones.
   * A certificate destroyed between the Locate and the Get is left out.
   *
   * <p><b>Advanced.</b> For tooling that reads certificates. Nodes present and check TLS material
   * through {@link #follow} and {@link #trustAnchors}, which lease it and follow its renewal.
   *
   * @param query the query; only certificates are kept
   * @return the certificates by object identifier, unmodifiable
   * @since 0.10.0
   */
  public Map<String, X509Certificate> certificates(KeyQuery query) {
    Objects.requireNonNull(query, "query");
    return Kms.named(
        "certificates",
        () -> {
          List<String> ids = TlsIdentities.located(keys, query.kind(ObjectKind.CERTIFICATE));
          return java.util.Collections.unmodifiableMap(TlsIdentities.certificates(keys.kms(), ids));
        });
  }
}
