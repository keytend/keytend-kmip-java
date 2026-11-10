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
import java.util.Objects;

/**
 * A TLS identity in the KMS ({@link KmsTls}): its leaf certificate, which has the name, the private
 * key linked to it, and its chain. A handle names these objects; it reads nothing by itself, and
 * does not follow later renewals (look the identity up again with {@link KmsTls#identity(String)},
 * or follow it with {@link KmsTls#follow}). Renewal, re-key and revocation are single-actor jobs:
 * run one at a time per identity.
 *
 * <p><b>Replacing a revoked or compromised identity.</b> {@link #rekey} (and {@link #renew}, when
 * the private key is still Active) works whether the identity's certificate is Active,
 * Deactivated or Compromised. The name moves from the old certificate to the new one also on
 * servers that keep names on revoked objects and allow a name once, and the old certificate is
 * linked to the new one (Replacement Object link), so the lineage stays readable. An identity
 * whose certificate was destroyed is no longer found by its name (Locate passes destroyed objects
 * over), and is not renewed or re-keyed where it is: register a new one, under another name where
 * the server keeps the names of destroyed objects (see {@link TlsIdentityRegistration#register()}).
 *
 * @since 0.10.0
 */
public final class TlsIdentityHandle {
  private final KmsTls tls;
  private final String name;
  private final KeyHandle certificate, privateKey;
  private final List<KeyHandle> chain;

  TlsIdentityHandle(
      KmsTls tls, String name, KeyHandle certificate, KeyHandle privateKey, List<KeyHandle> chain) {
    this.tls = tls;
    this.name = name;
    this.certificate = certificate;
    this.privateKey = privateKey;
    this.chain = List.copyOf(chain);
  }

  /**
   * The identity's name, which its leaf certificate has.
   *
   * @return the name
   * @since 0.10.0
   */
  public String name() {
    return name;
  }

  /**
   * The leaf certificate.
   *
   * @return the leaf certificate's handle
   * @since 0.10.0
   */
  public KeyHandle certificate() {
    return certificate;
  }

  /**
   * The private key, which the leaf certificate links to and which links back to it.
   *
   * @return the private key's handle
   * @since 0.10.0
   */
  public KeyHandle privateKey() {
    return privateKey;
  }

  /**
   * The certificates of the chain, the leaf first, as the links name them when the handle was made.
   *
   * @return the chain's handles, leaf first; unmodifiable
   * @since 0.10.0
   */
  public List<KeyHandle> chain() {
    return chain;
  }

  /**
   * Renews the certificate and keeps the private key. The new leaf gets the old one's custom
   * attributes.
   *
   * <p>The call registers {@code newChain} Pre-Active, leaf first, under a temporary name that only
   * it uses, and links it. The leaf is for the same key. Issuers the old chain ends with are not
   * registered again. One request, the switch, then makes the new leaf the identity's: it gives the
   * old leaf a Replacement Object link to it ({@link KmsTls}). The call then links the key to the
   * new leaf and activates the new issuers and the new leaf. Readers present the new pair from that
   * Activate. Then the name moves to the new leaf, and the old leaf is deactivated, not destroyed.
   *
   * <p>When the call stops part-way ({@link PartialCompletionException}) or its outcome is unknown,
   * repeat it with the same chain. Before the switch, the repeat starts over. What the stopped call
   * registered is left over, and the call activated none of it. After the switch, the repeat
   * activates the new objects, moves the name and deactivates the old leaf, but only when the new
   * leaf's chain is the one given. A repeat after success returns the identity.
   * After a lost race, or a stop after which another call moved the identity on, repeat from
   * {@link KmsTls#identity(String)}. What a stopped call leaves is in <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/tls-identities.md#what-a-stopped-call-leaves">TLS
   * identities</a>.
   *
   * <p>The call changes an object it registered, or after the switch the new leaf and its new
   * issuers, only while a read just before shows it as expected, as {@link
   * TlsIdentityRegistration#register()} says. About 41 requests for a chain of the leaf and an
   * issuer the old chain ends with (43 on KMIP 1.x), about 4 fewer for the leaf alone, about 12
   * more for each issuer the old chain does not end with, and about 13 more where names are unique
   * (15 on KMIP 1.x).
   *
   * <p>The pair check retrieves the private key from the KMS and signs with it locally. The key
   * must be Active and explicitly permit SIGN. The check refuses Usage Limits, and obtains a lease
   * first when Lease Time is stated. The same checks run again on the key's attributes as read
   * just before the key is fetched.
   *
   * @param newChain the new chain, leaf first (at least the leaf), for the same private key
   * @return the renewed identity
   * @throws IllegalArgumentException when the chain is empty or out of order; nothing is sent
   * @throws KeyMismatchException when the new leaf is not for the identity's private key; nothing
   *     was registered
   * @throws StateConflictException when nothing of the identity changed because:
   *     <ul>
   *       <li>this handle's certificate is no longer the identity's (it was renewed or re-keyed
   *           meanwhile);
   *       <li>the private key is not Active (re-key instead);
   *       <li>another renewal of the identity won a race with this one (the message lists this
   *           call's objects, which it did not activate);
   *       <li>a newer certificate linked after this handle's is not Active yet. Another call is
   *           under way, or one stopped after its switch. {@link KmsException#objectId()} names it;
   *       <li>its certificate is destroyed (where Locate returns destroyed objects).
   *     </ul>
   *     A repeat also throws it, with nothing changed, when it finds the switch to this leaf made
   *     and the leaf's chain is not the one given, or the leaf does not link to the key the identity
   *     keeps ({@link StateConflictException.Conflict#LINEAGE LINEAGE}). So does a call when another
   *     caller changed an object this call registered, or the new leaf or a new issuer a repeat
   *     finds switched in, before this call changed anything. The message says what to do
   * @throws UnsupportedException when the key states Usage Limits, does not permit SIGN, or the
   *     server does not support a required Obtain Lease; nothing was registered
   * @throws PermissionDeniedException when the server refuses a required lease; nothing was registered
   * @throws TransientException when a required lease cannot be obtained because the KMS is
   *     unreachable, or expires before the pair check; nothing was registered
   * @throws PartialCompletionException when a step after the first registration failed: repeat.
   *     Its cause is a {@code StateConflictException} when another caller changed an object after
   *     this call had changed something: do as that says
   * @since 0.10.0
   */
  public TlsIdentityHandle renew(X509Certificate... newChain) {
    List<X509Certificate> checked = TlsIdentities.checkedChain("renew", newChain);
    return new TlsIssue(tls, TlsIssue.Kind.RENEW, name, null, checked, null, certificate.id())
        .run();
  }

  /**
   * Replaces the private key and the certificate. This is also the way to replace an identity
   * whose certificate or key was revoked or compromised. The new leaf gets the old one's custom
   * attributes.
   *
   * <p>The call registers {@code newKey} and {@code newChain} (leaf first, for {@code newKey})
   * Pre-Active and links them. One request, the switch, makes them the identity's. The call then
   * activates them, the leaf last. The name moves to the new leaf, and the old leaf and old key are
   * deactivated, not destroyed, where they are still Active.
   *
   * <p>Repeat it after a stop as {@link #renew} says, with the same key and chain. After the
   * switch, a repeat also checks that the new leaf's key holds {@code newKey} (one Get). About 18
   * more requests than {@link #renew} (19 on KMIP 1.x).
   *
   * @param newKey the new private key (RSA or EC)
   * @param newChain the new chain, leaf first (at least the leaf), for {@code newKey}
   * @return the re-keyed identity
   * @throws IllegalArgumentException when the chain is empty or out of order, the leaf is not for
   *     {@code newKey}, or the key is neither RSA nor EC; nothing is sent
   * @throws StateConflictException when this handle's certificate is no longer the identity's,
   *     another renewal of the identity won a race with this one, a newer certificate linked after
   *     this handle's is not Active yet, or its certificate is destroyed (where Locate returns
   *     destroyed objects; a destroyed identity is replaced by registering a new one). Nothing of
   *     the identity changed. A repeat also throws it, with nothing changed, when it finds the
   *     switch to this leaf made and the leaf's chain or key is not the one given. So does a call
   *     when another caller changed an object this call registered, as {@link #renew} says
   * @throws PartialCompletionException when a step after the first registration failed: repeat.
   *     Its cause is a {@code StateConflictException} when another caller changed an object after
   *     this call had changed something: do as that says
   * @since 0.10.0
   */
  public TlsIdentityHandle rekey(PrivateKey newKey, X509Certificate... newChain) {
    Objects.requireNonNull(newKey, "newKey");
    List<X509Certificate> checked = TlsIdentities.checkedChain("rekey", newChain);
    if (!TlsIdentities.matches(newKey, checked.get(0).getPublicKey()))
      throw new IllegalArgumentException(
          "rekey: the leaf certificate ("
              + checked.get(0).getSubjectX500Principal()
              + ") is not for the new"
              + " private key");
    return new TlsIssue(tls, TlsIssue.Kind.REKEY, name, newKey, checked, null, certificate.id())
        .run();
  }

  /**
   * Has the KMS issue a new certificate for the identity's private key, with KMIP Certify: {@link
   * #reissue(TlsReissue)} with {@link TlsReissue#sameKey()}.
   *
   * @return the reissued identity
   * @throws KmsException as {@link #reissue(TlsReissue)}
   * @since 0.10.0
   */
  public TlsIdentityHandle reissue() {
    return reissue(TlsReissue.sameKey());
  }

  /**
   * Has the KMS create a new key pair of the current key's algorithm and size, and issue a new
   * certificate for it: {@link #reissue(TlsReissue)} with {@link TlsReissue#newKey()}. This also
   * replaces an identity whose certificate or key was revoked or compromised, and an identity
   * registered with {@link KmsTls#register}, once an issuer can sign its subject.
   *
   * @return the reissued identity
   * @throws KmsException as {@link #reissue(TlsReissue)}
   * @since 0.10.0
   */
  public TlsIdentityHandle reissueWithNewKey() {
    return issued(TlsReissue.newKey());
  }

  /**
   * Has the KMS issue a new certificate with KMIP Certify, as {@code how} says, for the same
   * subject and subject alternative names as this handle's certificate. The new leaf gets the old
   * one's custom attributes.
   *
   * <p>The steps are those of {@link TlsIdentityIssuance#issue()} up to the checks of the new
   * certificate. A same-key reissue retrieves the identity's private key (with a lease where it
   * states one) to sign the request, as {@link #renew} does for its pair check, and certifies the
   * public key object linked to it. Then the steps of {@link #renew} (same key) or {@link #rekey}
   * (new key) follow: the switch, the activation, the name, and the retirement of what the new leaf
   * replaces, its old key and public key too after a new key. Re-certify is not used: it would
   * move the name and set the links on the server, around the switch that makes a stopped or
   * repeated call safe. Each change from the switch on is sent only while the new certificate
   * outlasts the safety margin, as {@link TlsIdentityIssuance#issue()} says.
   *
   * <p>When the call stops part-way ({@link PartialCompletionException}) or its outcome is unknown,
   * repeat it on this handle with the same options. Before the switch, the repeat starts over, and
   * what the stopped call made is left over. After the switch, the repeat finishes the call, when
   * the new leaf replaces this handle's certificate and has its subject, names and issuer, and the
   * key asked, and its chain verifies. A repeat after success returns the identity. After a lost
   * race, repeat from {@link KmsTls#identity(String)}.
   *
   * @param how the key, validity and issuer of the new certificate
   * @return the reissued identity
   * @throws StateConflictException as {@link #renew} and {@link #rekey} say, and when a same-key
   *     reissue finds no public key object linked to the private key and back (an identity
   *     registered with {@link KmsTls#register}: reissue with a new key); nothing was made. Also
   *     when the new certificate no longer outlasts the safety margin after the switch, or a
   *     repeat finds it so: the call activates nothing more and retires nothing, and the message
   *     says what to do
   * @throws UnsupportedException when this handle's certificate has subject alternative names a
   *     request does not carry (other than DNS names, IP addresses, URIs and email addresses), or
   *     as {@link TlsIdentityIssuance#issue()} says for the validity
   * @throws KeyMismatchException as {@link TlsIdentityIssuance#issue()} says
   * @throws InvalidRequestException as {@link TlsIdentityIssuance#issue()} says for a validity
   *     too short for the safety margin, or one that would end after the issuing CA's notAfter
   * @throws PartialCompletionException when a step after the first change failed: repeat. Its
   *     cause is a {@code StateConflictException} when another caller changed an object after
   *     this call had changed something: do as that says
   * @since 0.10.0
   */
  public TlsIdentityHandle reissue(TlsReissue how) {
    Objects.requireNonNull(how, "how");
    return certificate.kms.call("reissue", () -> issued(how));
  }

  private TlsIdentityHandle issued(TlsReissue how) {
    return new TlsIssue(
            tls,
            how.newKeyPair() ? TlsIssue.Kind.REISSUE_NEW_KEY : TlsIssue.Kind.REISSUE,
            name,
            how.request(),
            null,
            certificate.id())
        .run();
  }

  /**
   * {@link #reissue()} when this handle's certificate expires within {@code window}: the scheduled
   * job of an issued identity. It reads the certificate (one Get), and reissues it only when its
   * notAfter is less than {@code window} from now.
   *
   * <pre>{@code
   * node = node.reissueIfExpiresWithin(Duration.ofDays(10));
   * }</pre>
   *
   * @param window how long before its notAfter the certificate is reissued, not negative
   * @return the reissued identity, or this handle when the certificate is not due
   * @throws KmsException as {@link #reissue(TlsReissue)}
   * @since 0.10.0
   */
  public TlsIdentityHandle reissueIfExpiresWithin(Duration window) {
    return reissueIfExpiresWithin(window, TlsReissue.sameKey());
  }

  /**
   * {@link #reissue(TlsReissue)} as {@code how} says, when this handle's certificate expires
   * within {@code window}, as {@link #reissueIfExpiresWithin(Duration)} says.
   *
   * @param window how long before its notAfter the certificate is reissued, not negative
   * @param how the key, validity and issuer of the new certificate
   * @return the reissued identity, or this handle when the certificate is not due
   * @throws KmsException as {@link #reissue(TlsReissue)}
   * @since 0.10.0
   */
  public TlsIdentityHandle reissueIfExpiresWithin(Duration window, TlsReissue how) {
    Objects.requireNonNull(window, "window");
    Objects.requireNonNull(how, "how");
    if (window.isNegative())
      throw new IllegalArgumentException("window must not be negative: " + window);
    return certificate.kms.call(
        "reissueIfExpiresWithin",
        () -> {
          X509Certificate current = TlsIdentities.certificate(certificate.kms, certificate.id());
          if (current.getNotAfter().toInstant().isAfter(certificate.kms.now().plus(window)))
            return this;
          return issued(how);
        });
  }

  /**
   * Revokes this handle's certificate (and key), so that followers stop presenting it at their
   * next refresh. A handle does not follow renewals: to revoke what the identity is now, use the
   * handle {@link KmsTls#identity(String)} returns. For {@link
   * RevocationReason#keyCompromise} the certificate and the private key become Compromised; for
   * {@link RevocationReason#caCompromise} the certificate does; for any other reason the
   * certificate is deactivated ({@link KeyHandle#revoke}), and the key stays Active, so a {@link
   * #renew} can still reuse it. The name stays on the certificate: {@link #rekey} or {@link #renew}
   * moves it to the replacement. A lost reply is read back, and an object already in the state
   * asked for is passed over.
   *
   * @param reason why the certificate is revoked
   * @throws StateConflictException when the server refuses because of an object's state
   * @since 0.10.0
   */
  public void revoke(RevocationReason reason) {
    Objects.requireNonNull(reason, "reason");
    certificate.kms.run(
        "revoke",
        () -> {
          revoke(certificate, reason);
          if (reason.kind() == RevocationReason.Kind.KEY_COMPROMISE) revoke(privateKey, reason);
        });
  }

  private static void revoke(KeyHandle h, RevocationReason reason) {
    for (int attempt = 1; ; attempt++) {
      try {
        h.revoke(reason);
        return;
      } catch (OutcomeUnknownException | StateConflictException e) {
        KeyState state = h.attributes().state();
        boolean done =
            reason.compromise()
                ? state == KeyState.COMPROMISED || state == KeyState.DESTROYED_COMPROMISED
                : state != KeyState.ACTIVE
                    && state != KeyState.PRE_ACTIVE
                    && state != KeyState.UNKNOWN;
        if (done) return;
        // A lost reply that did not take effect is sent again (three times at most); a refusal is
        // not.
        if (!(e instanceof OutcomeUnknownException) || attempt == 3) throw e;
      }
    }
  }

  @Override
  public String toString() {
    return "TlsIdentityHandle["
        + name
        + ", certificate "
        + certificate.id()
        + ", private key "
        + privateKey.id()
        + "]";
  }
}
