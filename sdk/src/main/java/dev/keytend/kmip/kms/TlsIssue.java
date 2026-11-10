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

import dev.keytend.kmip.client.Request;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.Attributes;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Ttlv;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * One registration, renewal or re-key of a TLS identity ({@link KmsTls}, {@link
 * TlsIdentityHandle}). The steps:
 *
 * <ol>
 *   <li>what the name leads to is read ({@link TlsIdentities#find}); when it leads to the new leaf
 *       already, current or as the replacement being made current, an earlier call made the
 *       switch, and only the steps after it are left ({@link #finishSwitched});
 *   <li>the new leaf, the new private key and the new intermediate certificates are registered
 *       Pre-Active under temporary names of this call's own ({@link
 *       TlsIdentities#temporaryName}, random): a lost reply is settled by looking the name up,
 *       which no other call uses;
 *   <li>they are linked: the leaf to its key (Private Key link) and a new key back (Certificate
 *       link), each certificate to its issuer (Certificate link), and the leaf to the certificate it
 *       replaces (Replaced Object link); then their temporary names are removed. They are all
 *       still Pre-Active, so no reader trusts or uses them, and nothing of the identity links to
 *       them;
 *   <li>the switch, one request: the replaced certificate's Replacement Object link to the leaf,
 *       or for a registration the name. A server that allows one replacement refuses a second
 *       caller here, which loses the race;
 *   <li>a kept key is linked to the leaf, and the new key, the new intermediates and then the leaf
 *       are activated: readers present the new pair from the leaf's Activate;
 *   <li>the name moves to the leaf (where names are unique, recorded on the leaf as pending while
 *       it is on no object), and the certificates it replaced, and their keys when the key changed,
 *       are deactivated.
 * </ol>
 *
 * <p>A call never reads, changes or links to what an earlier call left before its switch: a repeat
 * of a call that stopped before the switch starts over, and what the earlier call registered is
 * left over: that call activated none of it (but an issue's new private key, activated to sign its
 * certificate request, which no certificate certifies yet), named it only with its temporary name
 * and linked nothing of the identity to it (an object another caller changed is as that caller left
 * it). Only the server links to it: Certify links the public key it certifies to the new
 * certificate, so a same-key reissue's leftover leaf has a Certificate link from the identity's
 * public key, which no reader or later call follows. The objects a call changes are the ones it
 * registered, the identity's own (its current certificate, what that replaced, and their keys),
 * and, after the switch, the new leaf, its new key and its new intermediates, which the switch made
 * the identity's. A repeat finishes with those only when they hold the chain and key it was given,
 * linked as a switch leaves them; an object of the same DER (or the same key) that another caller
 * registered, unnamed and linked exactly as this call's own, cannot be told from it. Undoing a
 * switch is offered only while that leaves nothing of the switched call Active or linked from the
 * identity ({@link #exposed}); what another caller linked in is left as it was. Each change to one
 * that is not the identity's own, and each link to one, is made only while a read just before it
 * shows the object exactly as this call expects ({@link #change}, {@link TlsOwnership}); the first
 * that is not stops the call, which changes nothing more and names it.
 */
final class TlsIssue {
  /**
   * What a call makes. {@link #first} kinds give a new identity its name; {@link #keepsKey} kinds
   * keep the identity's private key; the others make a new one. {@link #issued} kinds have the KMS
   * issue the leaf (Certify, {@link TlsCertify}); {@link #pairObjects} kinds keep a public key
   * object in the pair, linked as Certify needs it.
   */
  enum Kind {
    REGISTER("register", 0, false),
    RENEW("renew", 1, false),
    REKEY("rekey", 2, false),
    REGISTER_ISSUER("registerIssuer", 0, false),
    ISSUE("issue", 0, true),
    REISSUE("reissue", 1, true),
    REISSUE_NEW_KEY("reissueWithNewKey", 2, true);

    final String operation;
    private final int role;
    private final boolean issued;

    Kind(String operation, int role, boolean issued) {
      this.operation = operation;
      this.role = role;
      this.issued = issued;
    }

    boolean first() {
      return role == 0;
    }

    boolean keepsKey() {
      return role == 1;
    }

    boolean issued() {
      return issued;
    }

    boolean pairObjects() {
      return issued || this == REGISTER_ISSUER;
    }

    /** What the identity is called in messages. */
    String noun() {
      return this == REGISTER_ISSUER ? "issuer" : "identity";
    }

    /** How to replace both the key and the certificate, for a message. */
    String replaceBoth() {
      return issued ? "reissueWithNewKey()" : "rekey(newKey, newChain)";
    }

    /** What a repeat is given again, for a message. */
    String sameArguments() {
      if (issued) return "the same arguments";
      return role == 1
          ? "the same certificate chain"
          : "the same private key and certificate chain";
    }
  }

  /**
   * The part of the {@linkplain #margin safety margin} that does not grow with the call timeout:
   * the clock difference the SDK allows between machines for an issued certificate's dates ({@link
   * TlsCertify#TOLERANCE}).
   */
  static final Duration MARGIN_FLOOR = TlsCertify.TOLERANCE;

  /**
   * How long an issued leaf must still be valid, by the Kms's clock, at each check before a change
   * of the identity ({@link #lastsTheMargin}): {@link #MARGIN_FLOOR} plus twice {@code
   * callTimeout}, the call timeout of the Kms the call runs on. A check runs just before the one
   * request it guards is sent; every exchange of the call shares the call's one deadline, so
   * however many are left, the client waits for that request's reply for at most one call timeout.
   * The second call timeout is for a server that processes a request after the client stopped
   * waiting for it (queued, or answered too late), and the floor for a peer whose clock runs ahead
   * of the Kms's.
   */
  static Duration margin(Duration callTimeout) {
    try {
      return MARGIN_FLOOR.plus(callTimeout.multipliedBy(2));
    } catch (ArithmeticException tooLong) {
      return FOREVER;
    }
  }

  /** What {@link #margin} and {@link #shortestValidity} give for a call timeout too long to add. */
  private static final Duration FOREVER = java.time.temporal.ChronoUnit.FOREVER.getDuration();

  /**
   * The shortest validity an issued call asks for ({@link TlsCertify#validFor}): longer than the
   * {@link #margin} after a call that took its whole call timeout to reach a check, with the
   * notAfter up to {@link TlsCertify#TOLERANCE} before the date asked. Ten minutes plus three times
   * the call timeout.
   */
  static Duration shortestValidity(Duration callTimeout) {
    try {
      return margin(callTimeout).plus(callTimeout).plus(TlsCertify.TOLERANCE);
    } catch (ArithmeticException tooLong) {
      return FOREVER;
    }
  }

  private final KmsTls tls;
  private final KmsKeys keys;
  private final Kind kind;
  private final String operation;
  private final String name;
  private final PrivateKey newKey;

  /**
   * The new chain, leaf first. For an {@link Kind#issued} call, null until the leaf is issued, or
   * a repeat finds the leaf an earlier call issued; then that leaf and the issuer's chain.
   */
  private List<X509Certificate> chain;

  /** What an {@link Kind#issued} call asks the KMS to issue; null otherwise. */
  private final TlsCertify request;

  /** The new or kept public key object, for {@link Kind#pairObjects} kinds, once known. */
  private String publicId;

  /** The leaf's custom attributes; null to copy the current leaf's. */
  private final Map<CustomAttribute, Object> custom;

  /** The certificate the caller's handle names (renew, rekey); null for register. */
  private final String expected;

  /** This call's temporary name: random, so that no other call uses it. */
  private final String temporary;

  private final List<KeyHandle> created = new ArrayList<>();
  private String step = "reading the identity";

  /** The new leaf, once registered or found current. */
  private String leafId;

  /** Whether this call may have changed the server: from its first registration on. */
  private boolean changed;

  /** The refusal {@link #lostRace} threw, which is not a partial completion. */
  private StateConflictException lost;

  /** A registration's name refused by the server: thrown as it is. */
  private AlreadyExistsException nameRefused;

  /** The refusal of an issued certificate that is not what was asked: thrown as it is. */
  private KmsException issuedRefused;

  /** A same-key reissue's retrieved private key, until it signs the request; then wiped. */
  private PrivateKey signingKey;

  /** The new private key an issued call activated to sign its request, once it did. */
  private String activatedKey;

  /** The public key an issued leaf's request is for. */
  private java.security.PublicKey requestedKey;

  /** An issued leaf's issuers in the KMS, the issuing CA's certificate first; empty for none. */
  private List<String> issuerIds = List.of();

  /**
   * The Deactivation Date an issued call asks for, from the Kms's clock when the call checked it
   * against the issuing CA's notAfter ({@link TlsCertify#checkValidity}); null for none. Certify
   * asks for this date, so the date checked is the date sent.
   */
  private java.time.Instant until;

  /**
   * What each object this call may change, other than the identity's own, must be just before its
   * next change: the ownership predicate ({@link #own}, {@link TlsOwnership}). The leaf, the new
   * key and the issuers this call registers, as their Register left them; or the new leaf, key and
   * issuers a repeat finds the switch made, as a switch leaves them.
   */
  private final Map<String, TlsOwnership.Expected> owned = new LinkedHashMap<>();

  /** How each object in {@link #owned} was found, for a refusal. */
  private final Map<String, String> foundAs = new LinkedHashMap<>();

  /** Whether this call has sent a change (a refusal before then changed nothing). */
  private boolean wrote;

  /** The last refusal of the ownership predicate. */
  private StateConflictException lastRefusal;

  /**
   * Whether the switch is made, the new leaf is Active (readers present it), the name moved, and
   * what it replaced retired.
   */
  private boolean finishing, activated, named, retired;

  /** Whether the switch was sent: when its outcome is unknown, it may have been made. */
  private boolean switchSent;

  /** The certificate the new leaf replaces (renew, rekey), once known. */
  private String replaced;

  /** {@link #replaced} as read before the switch; null for none. */
  private KeyAttributes previous;

  /** Whether this call finishes a switch an earlier call made ({@link #finishSwitched}). */
  private boolean repeat;

  /** The certificates and keys this call deactivated, as it did. */
  private final List<String> deactivated = new ArrayList<>();

  /** The refusal to go on with a switch to an issued leaf that expired: thrown as it is. */
  private StateConflictException expiredRefusal;

  TlsIssue(
      KmsTls tls,
      Kind kind,
      String name,
      PrivateKey newKey,
      List<X509Certificate> chain,
      Map<CustomAttribute, Object> custom,
      String expected) {
    this(tls, kind, name, newKey, chain, custom, expected, null);
  }

  /** An {@link Kind#issued} call: {@code request} says what to issue. */
  TlsIssue(
      KmsTls tls,
      Kind kind,
      String name,
      TlsCertify request,
      Map<CustomAttribute, Object> custom,
      String expected) {
    this(tls, kind, name, null, null, custom, expected, request);
  }

  private TlsIssue(
      KmsTls tls,
      Kind kind,
      String name,
      PrivateKey newKey,
      List<X509Certificate> chain,
      Map<CustomAttribute, Object> custom,
      String expected,
      TlsCertify request) {
    this.tls = tls;
    this.keys = tls.keys();
    this.kind = kind;
    this.operation = kind.operation;
    this.name = name;
    this.newKey = newKey;
    this.chain = chain;
    this.custom = custom;
    this.expected = expected;
    this.request = request;
    this.temporary = TlsIdentities.temporaryName(name);
  }

  TlsIdentityHandle run() {
    try {
      return steps();
    } finally {
      // A same-key reissue that stopped before it signed: its copy of the key is wiped too.
      wipe(signingKey);
      signingKey = null;
    }
  }

  private TlsIdentityHandle steps() {
    return keys.kms()
        .call(
            operation,
            () -> {
              // Before anything is sent: a validity the safety margin leaves no room for.
              if (kind.issued())
                request.checkShortest(operation, shortestValidity(keys.kms().callTimeout()));
              Optional<TlsIdentities.Found> found =
                  TlsIdentities.find(keys, name, List.of(), expected);
              KeyAttributes current = found.map(TlsIdentities.Found::current).orElse(null);
              // What an issued leaf must hold: the subject, names and key type asked, or for a
              // reissue those of the certificate it replaces, and the issuer's chain.
              if (kind.issued() && (kind.first() || found.isPresent()))
                request.prepare(
                    keys, kind, expected, found.map(f -> f.read).orElseGet(java.util.HashMap::new));
              // A repeat of a call that made its switch: what is left is the activation, the name
              // and the retirement.
              KeyAttributes switched = switched(found.orElse(null), current);
              if (switched != null) return guarded(() -> finishSwitched(found.get(), switched));
              check(found, current);
              if (kind.issued()) {
                request.requirePrepared(operation);
                // The time the requested validity runs from: Certify asks for the date checked.
                java.time.Instant asked = keys.kms().now();
                request.checkValidity(operation, asked);
                until = request.deactivation(asked);
              }
              KeyAttributes oldKey = kind.keepsKey() ? renewedKey(found.get(), current) : null;
              Map<CustomAttribute, Object> leafCustom = custom != null ? custom : copied(current);
              List<String> oldChain =
                  current == null
                      ? List.of()
                      : TlsIdentities.chainIds(keys, current, found.get().read);
              // Only from here on is anything changed.
              return guarded(() -> issue(found.orElse(null), oldKey, leafCustom, oldChain));
            });
  }

  /** {@link #run()} of an issuer's registration: the issuer, with its public key object. */
  TlsIssuer runIssuer() {
    TlsIdentityHandle h = run();
    return new TlsIssuer(
        name,
        h.certificate(),
        new KeyHandle(keys, Objects.requireNonNull(publicId, "publicId"), ObjectKind.PUBLIC_KEY),
        h.privateKey(),
        h.chain());
  }

  /** Refuses a call that does not fit what the name leads to; nothing was changed. */
  private void check(Optional<TlsIdentities.Found> found, KeyAttributes current) {
    if (current != null
        && (current.state() == KeyState.DESTROYED
            || current.state() == KeyState.DESTROYED_COMPROMISED)) {
      // Found only where Locate returns destroyed objects; there the name is the destroyed one's.
      if (kind.first())
        throw new AlreadyExistsException(
            operation
                + ": the name "
                + name
                + " is held by certificate "
                + current.id()
                + ", which is "
                + current.state()
                + ": this server returns destroyed objects for their names, and servers that"
                + " do usually keep the name for good (a destroyed object's attributes cannot be changed); register"
                + " the identity under another name; nothing was registered",
            null,
            operation,
            current.id(),
            null,
            null);
      throw new StateConflictException(
              operation
                  + ": the certificate "
                  + current.id()
                  + " of "
                  + name
                  + " is "
                  + current.state()
                  + ": a"
                  + " destroyed identity cannot be renewed or re-keyed (its certificate cannot be linked to a new"
                  + " one); register a new identity, under another name where the server keeps the names of"
                  + " destroyed objects; nothing was registered",
              null,
              operation,
              current.id(),
              null,
              null)
          .observed(current.state());
    }
    if (kind.first()) {
      if (found.isPresent() && current.state() == KeyState.PRE_ACTIVE) {
        // Taking the name off is offered only while it leaves nothing of that registration Active.
        Exposed e = exposed(current, null, found.get().read);
        throw new AlreadyExistsException(
            operation
                + ": the name "
                + name
                + " is on certificate "
                + current.id()
                + ", which is Pre-Active: another registration of the identity is under way, or one"
                + " stopped after it gave the name. Repeat that registration, with its key and"
                + " chain, to finish it"
                + (e.none()
                    ? "; otherwise take the name off " + current.id() + ", then register"
                    : ", then renew or re-key that identity. Do not take the name off "
                        + current.id()
                        + ": that would leave "
                        + e.left(current.id())
                        + ". If another caller made "
                        + current.id()
                        + " and what it links to, take the name off instead, then register: that"
                        + " leaves them as they were")
                + "; nothing was registered",
            null,
            operation,
            current.id(),
            null,
            null);
      }
      if (found.isPresent())
        throw new AlreadyExistsException(
            operation
                + ": the name "
                + name
                + " is the TLS "
                + kind.noun()
                + " whose certificate is "
                + current.id()
                + " ("
                + current.state()
                + "); "
                + (kind == Kind.REGISTER_ISSUER
                    ? "look it up with kms.tls().issuer(\"" + name + "\"), or choose another name"
                    : (kind.issued() ? "reissue it" : "renew or re-key it")
                        + " instead: kms.tls().identity(\""
                        + name
                        + "\")"
                        + (kind.issued()
                            ? ".orElseThrow().reissueWithNewKey()"
                            : ".orElseThrow().rekey(key, chain)")
                        + ", which also replaces a revoked or compromised identity")
                + "; nothing was registered",
            null,
            operation,
            current.id(),
            null,
            null);
      // Another kind of object with the name: giving it to the leaf would fail (or confuse
      // lookups).
      List<String> others =
          keys.locate(KeyQuery.byName(name)).map(KeyHandle::id).distinct().toList();
      if (!others.isEmpty())
        throw new AlreadyExistsException(
            operation
                + ": "
                + others
                + " already "
                + (others.size() == 1 ? "has" : "have")
                + " the name "
                + name
                + " and "
                + (others.size() == 1 ? "is" : "are")
                + " not a TLS identity's certificate; choose another"
                + " name, or remove it from them first; nothing was registered",
            null,
            operation,
            others.get(0),
            null,
            null);
      return;
    }
    if (found.isEmpty())
      throw new NotFoundException(
          operation
              + ": no certificate has the name "
              + name
              + "; register the identity with kms.tls()"
              + ".register(key, chain).named(\""
              + name
              + "\").register(); nothing was registered",
          null,
          operation,
          expected,
          null,
          null);
    if (!current.id().equals(expected))
      throw new StateConflictException(
              operation
                  + ": the identity "
                  + name
                  + " is certificate "
                  + current.id()
                  + " now, not "
                  + expected
                  + " (it was renewed or re-keyed meanwhile); use kms.tls().identity(\""
                  + name
                  + "\") for the"
                  + " current one; nothing was registered",
              null,
              operation,
              expected,
              null,
              null)
          .because(StateConflictException.Conflict.REPLACED);
    // A newer certificate that is not Active yet: another call is making it current, or another
    // caller linked it. This call links only after the identity's own current certificate.
    KeyAttributes newest = found.get().newest();
    if (!newest.id().equals(current.id())) {
      // Taking the link off is offered only while it leaves nothing of that call Active or linked.
      Exposed e = exposed(newest, current, found.get().read);
      throw new StateConflictException(
              operation
                  + ": certificate "
                  + newest.id()
                  + ", which "
                  + current.id()
                  + " of "
                  + name
                  + " names as its replacement, is "
                  + newest.state()
                  + ": another renewal or re-key of the identity is under way (run one at a time),"
                  + " or one stopped after its switch, or another caller linked it. Wait for that"
                  + " call to finish, or repeat it with its key and chain to finish it"
                  + (e.none()
                      ? "; otherwise take the Replacement Object link to "
                          + newest.id()
                          + " off "
                          + current.id()
                          + e.otherLinkOff(newest.id())
                          + ", then repeat"
                      : ", then repeat from kms.tls().identity(\""
                          + name
                          + "\"). Do not take the Replacement Object link to "
                          + newest.id()
                          + " off: that would leave "
                          + e.left(newest.id())
                          + ". If another caller made "
                          + newest.id()
                          + " and what it links to, take the link off instead"
                          + e.otherLinkOff(newest.id())
                          + ", then repeat: that leaves them as they were")
                  + "; nothing was registered",
              null,
              operation,
              newest.id(),
              null,
              null)
          .because(StateConflictException.Conflict.REPLACED)
          .observed(newest.state());
    }
  }

  /**
   * The private key a renewal keeps: the current leaf's, which must be Active, and whose private
   * half the new leaf must certify (one Get Attributes and one Get, plus Obtain Lease when required).
   * A same-key reissue certifies the current leaf's own key: its private half signs the request
   * ({@link #signingKey}), and its public key object, which Certify names, must link to it and
   * back ({@link #publicId}).
   */
  private KeyAttributes renewedKey(TlsIdentities.Found found, KeyAttributes current) {
    KeyAttributes key = TlsIdentities.keyOf(keys, current, found.read);
    if (key == null)
      throw new StateConflictException(
              operation
                  + ": certificate "
                  + current.id()
                  + " of "
                  + name
                  + " has no private key linked to it and"
                  + " back, so there is no key to keep: use "
                  + kind.replaceBoth()
                  + "; nothing was registered",
              null,
              operation,
              current.id(),
              null,
              null)
          .because(StateConflictException.Conflict.LINEAGE);
    if (key.state() != KeyState.ACTIVE)
      throw new StateConflictException(
              operation
                  + ": the private key "
                  + key.id()
                  + " of "
                  + name
                  + " is "
                  + key.state()
                  + "; "
                  + (kind.issued() ? "a same-key reissue" : "a renewal")
                  + " keeps the key, so it must be Active: replace both with "
                  + kind.replaceBoth()
                  + "; nothing was registered",
              null,
              operation,
              key.id(),
              null,
              null)
          .observed(key.state());
    if (kind.issued()) publicId = publicKeyOf(key, found.read);
    java.security.PublicKey certified =
        kind.issued() ? request.currentKey() : chain.get(0).getPublicKey();
    Leases leases = new Leases();
    leaseForSigning(leases, key, true);
    PrivateKey held;
    try {
      held =
          keys.handle(key.id())
              .asPrivateKey(
                  TlsIdentities.expect(certified), a -> leaseForSigning(leases, a, false));
    } catch (KeyMismatchException other) {
      held = null;
    }
    if (!leases.usable(key.id())) {
      wipe(held);
      throw new TransientException(
          operation + ": the lease of private key " + key.id() + " ended before its pair check");
    }
    if (held == null || !TlsIdentities.matches(held, certified)) {
      wipe(held);
      throw new KeyMismatchException(
          operation
              + (kind.issued()
                  ? ": the identity's certificate " + current.id()
                  : ": the new certificate (" + chain.get(0).getSubjectX500Principal() + ")")
              + " is not for the private key "
              + key.id()
              + " of "
              + name
              + (kind.issued()
                  ? "; replace both with reissueWithNewKey()"
                  : "; a renewal keeps the key: use rekey(newKey, newChain) for a new one")
              + "; nothing was registered",
          null,
          operation,
          key.id(),
          null,
          null);
    }
    if (kind.issued()) signingKey = held;
    else wipe(held);
    return key;
  }

  /**
   * The public key object of the private key {@code key} a same-key reissue keeps: the one its
   * Public Key link names, which names it back with a Private Key link. Certify certifies a public
   * key object, so an identity whose key has none (one registered with {@link KmsTls#register}) is
   * reissued with a new key.
   */
  private String publicKeyOf(KeyAttributes key, Map<String, KeyAttributes> read) {
    for (String id : key.links(LinkKind.PUBLIC_KEY)) {
      KeyAttributes p = TlsIdentities.attributes(keys, read, id);
      if (p != null
          && p.kind() == ObjectKind.PUBLIC_KEY
          && p.links(LinkKind.PRIVATE_KEY).contains(key.id())
          && (p.state() == KeyState.ACTIVE || p.state() == KeyState.PRE_ACTIVE)) return p.id();
    }
    throw new StateConflictException(
            operation
                + ": the private key "
                + key.id()
                + " of "
                + name
                + " has no Active or Pre-Active public key object linked to it and back, which"
                + " Certify needs to issue a certificate for the same key (an identity registered"
                + " with kms.tls().register has none): reissue it with a new key,"
                + " reissueWithNewKey(); nothing was registered",
            null,
            operation,
            key.id(),
            null,
            null)
        .because(StateConflictException.Conflict.LINEAGE);
  }

  /** Wipes {@code key}, a copy retrieved for signing, where its class lets it be wiped. */
  static void wipe(PrivateKey key) {
    if (key == null || key.isDestroyed()) return;
    try {
      key.destroy();
    } catch (javax.security.auth.DestroyFailedException notWipeable) {
      // The JDK's RSA and EC key classes cannot be wiped: the copy is dropped.
    }
  }

  /** Before the renewal's signature: obey both the initial and the loader's later key attributes. */
  private void leaseForSigning(Leases leases, KeyAttributes key, boolean renew) {
    TlsIdentities.requireActiveSigningKey(key, operation);
    leaseForUse(leases, key, renew);
  }

  /**
   * The checks before a private key signs, other than its state (a new key signs its certificate
   * request while Pre-Active): no Usage Limits, SIGN permitted, and a lease running where it
   * states a Lease Time.
   */
  private void leaseForUse(Leases leases, KeyAttributes key, boolean renew) {
    UnsupportedException refusal = TlsIdentities.signingRefusal(key, operation);
    if (refusal != null) throw refusal;
    Map<String, Duration> times = new LinkedHashMap<>();
    times.put(key.id(), key.leaseToObtain());
    Leases.Outcome lease = leases.obtain(keys.kms(), times, renew);
    if (lease.refused() != null) throw lease.refused();
    if (!leases.usable(key.id())) {
      if (lease.failed() != null) throw lease.failed();
      throw new TransientException(
          operation + ": no lease of private key " + key.id() + " runs for its pair check");
    }
  }

  /** The current leaf's custom attributes, without the records of names being moved to it. */
  private static Map<CustomAttribute, Object> copied(KeyAttributes current) {
    Map<CustomAttribute, Object> out = new LinkedHashMap<>();
    if (current != null)
      for (var e : current.custom().entrySet())
        if (!KeyHandle.isPendingRecord(e.getKey())) out.put(e.getKey(), e.getValue());
    return out;
  }

  private TlsIdentityHandle issue(
      TlsIdentities.Found found,
      KeyAttributes oldKey,
      Map<CustomAttribute, Object> leafCustom,
      List<String> oldChain) {
    int reused = kind.issued() ? 0 : sharedTail(oldChain, found);
    // check() refused a newer certificate that is not Active yet: the current one is the newest.
    KeyAttributes predecessor = found == null ? null : found.current();
    boolean newKeyMade = oldKey == null;
    String keyName = temporary + ".key";
    String publicName = temporary + ".pub";
    KeyHandle leaf;
    KeyHandle key;
    // 2. The objects, registered Pre-Active under this call's temporary names.
    if (kind.issued()) {
      issuerIds = request.issuerIds();
      // An issued leaf: the new key pair first (or the kept key), then the request it signs,
      // then Certify, which makes the leaf under the temporary name.
      if (newKeyMade) {
        step = "creating the new key pair";
        KeyPairHandle pair = createPair(keyName, publicName);
        key = pair.privateKey();
        publicId = pair.publicKey().id();
      } else key = keys.handle(oldKey.id());
      step = "signing the certificate request";
      byte[] csr = certificationRequest(key, newKeyMade);
      step = "issuing the new certificate (Certify)";
      leaf = certify(csr, leafCustom, newKeyMade);
    } else {
      step = "registering the new certificate";
      leaf =
          register(
              certificate(chain.get(0), temporary, leafCustom),
              temporary,
              ObjectKind.CERTIFICATE,
              chain.get(0));
      leafId = leaf.id();
      created.add(leaf);
      if (!newKeyMade) key = keys.handle(oldKey.id());
      else {
        step = "registering the new private key";
        key =
            register(
                keys.register(newKey)
                    .named(keyName)
                    .usages(
                        kind == Kind.REGISTER_ISSUER
                            ? new KeyUsage[] {KeyUsage.SIGN, KeyUsage.CERTIFICATE_SIGN}
                            : new KeyUsage[] {KeyUsage.SIGN}),
                keyName,
                ObjectKind.PRIVATE_KEY,
                null);
        created.add(key);
      }
      if (kind == Kind.REGISTER_ISSUER) {
        // Certify reaches an issuer's private key through its certificate's public key object.
        step = "registering the new public key";
        KeyHandle pub =
            register(
                keys.register(chain.get(0).getPublicKey())
                    .named(publicName)
                    .usages(KeyUsage.VERIFY),
                publicName,
                ObjectKind.PUBLIC_KEY,
                null);
        created.add(pub);
        publicId = pub.id();
      }
    }
    // The intermediate certificates: an issued leaf's are the issuer's, which exist already;
    // otherwise the old chain's where the new one ends the same way, or registered now, with
    // their temporary names.
    List<String> ids = new ArrayList<>(List.of(leaf.id()));
    Map<String, String> fresh = new LinkedHashMap<>();
    if (kind.issued()) ids.addAll(issuerIds);
    else
      for (int i = 1; i < chain.size(); i++) {
        int fromEnd = chain.size() - i;
        if (fromEnd <= reused) {
          ids.add(oldChain.get(oldChain.size() - fromEnd));
          continue;
        }
        step = "registering certificate " + i + " of the chain";
        String caName = temporary + ".ca" + i;
        KeyHandle ca =
            register(
                certificate(chain.get(i), caName, Map.of()),
                caName,
                ObjectKind.CERTIFICATE,
                chain.get(i));
        created.add(ca);
        ids.add(ca.id());
        fresh.put(ca.id(), caName);
      }
    // 3. Links: the pair, the chain, and the leaf to what it replaces; then the temporary names
    // off. A kept key is linked to the leaf only after the switch: until then nothing of the
    // identity links to this call's objects. Where the pair has a public key object, the leaf, the
    // private key and it link to each other as Certify needs (links a Create Key Pair or Certify
    // made already are passed over).
    step = "linking the new certificate to its private key";
    link(leaf.id(), LinkKind.PRIVATE_KEY, key.id());
    if (newKeyMade) link(key.id(), LinkKind.CERTIFICATE, leaf.id());
    if (publicId != null) {
      step = "linking the new certificate to its public key";
      link(leaf.id(), LinkKind.PUBLIC_KEY, publicId);
      if (newKeyMade) {
        link(publicId, LinkKind.PRIVATE_KEY, key.id());
        link(key.id(), LinkKind.PUBLIC_KEY, publicId);
        link(publicId, LinkKind.CERTIFICATE, leaf.id());
      }
    }
    step = "linking the chain";
    for (int i = 0; i + 1 < ids.size(); i++)
      if (i == 0 || fresh.containsKey(ids.get(i)))
        link(ids.get(i), LinkKind.CERTIFICATE, ids.get(i + 1));
    if (predecessor != null) {
      replaced = predecessor.id();
      previous = predecessor;
      step = "linking the new certificate to " + predecessor.id();
      link(leaf.id(), LinkKind.REPLACED, predecessor.id());
    }
    step = "removing the temporary names";
    if (newKeyMade) unname(key.id(), keyName);
    if (newKeyMade && publicId != null) unname(publicId, publicName);
    for (Map.Entry<String, String> e : fresh.entrySet()) unname(e.getKey(), e.getValue());
    unname(leaf.id(), temporary);
    // 4. The switch, all of this call's objects still Pre-Active; 5. the activation.
    List<String> toActivate = new ArrayList<>();
    if (newKeyMade) toActivate.add(key.id());
    if (newKeyMade && publicId != null) toActivate.add(publicId);
    toActivate.addAll(fresh.keySet());
    // An issued leaf must outlast the safety margin just before each change from the switch on
    // ({@link #guardedSend}): each is an exchange of its own, which a slow reply can outlast.
    if (predecessor == null) {
      step = "giving the name " + name + " to " + leaf.id();
      nameRegistration(leaf.id());
      finishing = named = retired = true;
      publish(leaf.id(), key, false, toActivate);
      return handle(leaf.id(), key.id(), ids);
    }
    step = "linking " + predecessor.id() + " to the new certificate";
    replacementLink(predecessor, leaf);
    finishing = true;
    publish(leaf.id(), key, !newKeyMade, toActivate);
    List<KeyAttributes> older = new ArrayList<>();
    for (KeyAttributes a : found.path) {
      older.add(a);
      if (a.id().equals(predecessor.id())) break;
    }
    return finish(older, found.read, leaf.id(), key.id(), ids);
  }

  /**
   * Creates the new key pair of an issued leaf, Pre-Active under {@code keyName} and {@code
   * publicName}, this call's own names: the private key with the usage Sign, the public key with
   * Verify. A lost reply, or a refusal of a name in use (a resent request that took effect), is
   * settled by looking the names up ({@link KmsKeys#madeUnder}): the pair is taken only when each
   * key is the only object with its name, Pre-Active, with that name alone, and linked to nothing
   * but the other key. Both keys are then in {@link #owned}, as Create Key Pair left them.
   */
  private KeyPairHandle createPair(String keyName, String publicName) {
    wrote = true;
    changed = true;
    KeyPairHandle pair;
    try {
      pair =
          keys.createPair(
              request.spec(),
              java.util.EnumSet.of(KeyUsage.SIGN),
              java.util.EnumSet.of(KeyUsage.VERIFY),
              keyName,
              publicName,
              new ObjectOptions());
      created.add(pair.privateKey());
      created.add(pair.publicKey());
      keys.checkCreated(operation, List.of(pair.privateKey(), pair.publicKey()), pair);
    } catch (OutcomeUnknownException | AlreadyExistsException unknown) {
      pair = pairMadeUnder(keyName, publicName, unknown);
      created.add(pair.privateKey());
      created.add(pair.publicKey());
    }
    String keyId = pair.privateKey().id(), pubId = pair.publicKey().id();
    KeyAttributes k = keys.read(keyId).orElse(null), p = keys.read(pubId).orElse(null);
    Set<String> keyLinks = k == null ? Set.of() : TlsOwnership.links(k);
    Set<String> pubLinks = p == null ? Set.of() : TlsOwnership.links(p);
    String toPublic = link(LinkKind.PUBLIC_KEY, pubId),
        toPrivate = link(LinkKind.PRIVATE_KEY, keyId);
    // As Create Key Pair leaves them: each linked to nothing but the other, if to anything.
    Set<String> keyAllowed = Set.of(toPublic), pubAllowed = Set.of(toPrivate);
    model(
        keyId,
        new TlsOwnership.Expected(
            ObjectKind.PRIVATE_KEY,
            KeyState.PRE_ACTIVE,
            Set.of(keyName),
            keyAllowed.containsAll(keyLinks) ? keyLinks : keyAllowed,
            pubLinks.contains(toPrivate) ? Set.of(pubId) : Set.of()),
        "is this call's private key under " + keyName);
    model(
        pubId,
        new TlsOwnership.Expected(
            ObjectKind.PUBLIC_KEY,
            KeyState.PRE_ACTIVE,
            Set.of(publicName),
            pubAllowed.containsAll(pubLinks) ? pubLinks : pubAllowed,
            keyLinks.contains(toPublic) ? Set.of(keyId) : Set.of()),
        "is this call's public key under " + publicName);
    own(keyId);
    own(pubId);
    return pair;
  }

  /**
   * The pair a Create Key Pair made under {@code keyName} and {@code publicName} whose reply was
   * lost: each key the only object with its name, as Create Key Pair leaves it ({@link
   * KmsKeys#madeUnder}), linked to nothing but the other key. Otherwise {@code unknown} is thrown.
   */
  private KeyPairHandle pairMadeUnder(String keyName, String publicName, KmsException unknown) {
    Optional<KeyAttributes> k, p;
    try {
      k =
          keys.madeUnder(
                  keyName,
                  ObjectKind.PRIVATE_KEY,
                  links ->
                      links.size() <= 1
                          && links.stream().allMatch(l -> l.kind() == LinkKind.PUBLIC_KEY),
                  a -> true,
                  unknown)
              .made();
      p =
          keys.madeUnder(
                  publicName,
                  ObjectKind.PUBLIC_KEY,
                  links ->
                      links.size() <= 1
                          && links.stream().allMatch(l -> l.kind() == LinkKind.PRIVATE_KEY),
                  a -> true,
                  unknown)
              .made();
    } catch (KmsException lookup) {
      unknown.addSuppressed(lookup);
      throw unknown;
    }
    if (k.isEmpty() || p.isEmpty()) throw unknown;
    String keyId = k.get().id(), pubId = p.get().id();
    if (!k.get().links(LinkKind.PUBLIC_KEY).stream().allMatch(pubId::equals)
        || !p.get().links(LinkKind.PRIVATE_KEY).stream().allMatch(keyId::equals)) throw unknown;
    return new KeyPairHandle(
        new KeyHandle(keys, keyId, ObjectKind.PRIVATE_KEY),
        new KeyHandle(keys, pubId, ObjectKind.PUBLIC_KEY));
  }

  /**
   * The PKCS#10 request for the new leaf ({@link Pkcs10}), signed locally with the private key: a
   * new key is activated first (KMIP lets no Pre-Active key be used), then retrieved (one Get, an
   * Obtain Lease first where it states a Lease Time) with its public key (one Get); a kept key was
   * retrieved by {@link #renewedKey}. The copy is
   * wiped once it has signed. The public key requested is kept in {@link #requestedKey}.
   */
  private byte[] certificationRequest(KeyHandle key, boolean newKeyMade) {
    PrivateKey held = null;
    try {
      java.security.PublicKey publicKey;
      if (newKeyMade) {
        Expect expect = request.spec().expect();
        // A Pre-Active key may not be used for any cryptographic purpose (KMIP 1.4 3.22, 2.1
        // 4.57), and servers lease no Pre-Active object: the new private key, which no
        // certificate certifies yet and nothing of the identity links to, is activated to sign.
        // Its public key and the leaf stay Pre-Active until the switch.
        step = "activating the new private key to sign the certificate request";
        activate(key.id());
        activatedKey = key.id();
        step = "signing the certificate request";
        KeyAttributes a = own(key.id());
        Leases leases = new Leases();
        leaseForSigning(leases, a, true);
        publicKey = keys.handle(publicId).asPublicKey(expect);
        held = key.asPrivateKey(expect, read -> leaseForSigning(leases, read, false));
        if (!leases.usable(key.id()))
          throw new TransientException(
              operation
                  + ": the lease of private key "
                  + key.id()
                  + " ended before it signed the certificate request");
      } else {
        held = signingKey;
        publicKey = request.currentKey();
      }
      if (!TlsIdentities.matches(held, publicKey))
        throw new KeyMismatchException(
            operation
                + ": the private key "
                + key.id()
                + " is not the private half of the public key "
                + publicId,
            null,
            operation,
            key.id(),
            null,
            null);
      requestedKey = publicKey;
      try {
        return Pkcs10.request(request.subject(), publicKey, held, request.names());
      } catch (java.security.GeneralSecurityException e) {
        throw new CryptographicFailureException(
            operation + ": signing the certificate request failed: " + e.getMessage(),
            e,
            operation,
            key.id(),
            null,
            null);
      }
    } finally {
      signingKey = null;
      wipe(held);
    }
  }

  /**
   * Has the KMS issue the leaf: one Certify of the public key object {@link #publicId}, with the
   * request {@code csr}, the temporary name, the leaf's custom attributes, a Certificate link to
   * the issuer's certificate when there is one, and the Deactivation Date when a validity was asked
   * ({@link TlsCertify#certify}). A lost reply, or a refusal of a name in use (a resent request
   * that took effect), is settled by looking the name up: the certificate is taken only when it is
   * the only object with the name, Pre-Active, with that name alone, and linked to nothing but the
   * public key and the issuer. Then the leaf is read (Get Attributes and Get) and checked ({@link
   * TlsCertify#problem}): one that is not what was asked stops the call ({@link #issuedRefused}),
   * and this call's objects are left over.
   */
  private KeyHandle certify(
      byte[] csr, Map<CustomAttribute, Object> leafCustom, boolean newKeyMade) {
    Request certify =
        request.certify(
            keys,
            publicId,
            csr,
            temporary,
            leafCustom,
            until,
            issuerIds.isEmpty() ? null : issuerIds.get(0));
    wrote = true;
    changed = true;
    String id;
    try {
      id =
          keys.kms()
              .execute(
                  operation, Kms.Kind.MUTATION, publicId, s -> KmsKeys.identifier(s.call(certify)));
    } catch (OutcomeUnknownException | AlreadyExistsException unknown) {
      Optional<KeyAttributes> made;
      try {
        made =
            keys.madeUnder(
                    temporary,
                    ObjectKind.CERTIFICATE,
                    links ->
                        links.stream()
                            .allMatch(
                                l ->
                                    (l.kind() == LinkKind.PUBLIC_KEY
                                            && l.targetId().equals(publicId))
                                        || (l.kind() == LinkKind.CERTIFICATE
                                            && (issuerIds.isEmpty()
                                                || l.targetId().equals(issuerIds.get(0))))),
                    a -> true,
                    unknown)
                .made();
      } catch (KmsException lookup) {
        unknown.addSuppressed(lookup);
        throw unknown;
      }
      if (made.isEmpty()) throw unknown;
      id = made.get().id();
    } catch (InvalidRequestException | StateConflictException refused) {
      KmsException named = keys.duplicateName(refused, List.of(temporary));
      // With a validity asked, the date is the likely cause of Invalid Field, not the only one.
      if (named == refused
          && until != null
          && refused.serverReason().orElse(null) == KmsReason.INVALID_FIELD)
        throw issuedRefused = refusedValidity(refused, until);
      throw named;
    }
    KeyHandle leaf = new KeyHandle(keys, id, ObjectKind.CERTIFICATE);
    leafId = id;
    created.add(leaf);
    step = "checking the issued certificate";
    KeyAttributes a = keys.read(id).orElse(null);
    X509Certificate issued = null;
    TlsCertify.Problem problem;
    if (a == null || a.kind() != ObjectKind.CERTIFICATE)
      problem = new TlsCertify.Problem("it is " + (a == null ? "gone" : "a " + a.kind()), false);
    else {
      issued = TlsIdentities.certificate(keys.kms(), id);
      // Checked by the Kms's clock now, after Certify, the reads and the Get: not by the time the
      // validity was asked from, which a slow server leaves behind.
      problem = request.problem(issued, requestedKey, until, keys.kms().now());
      if (problem == null && a.state() != KeyState.PRE_ACTIVE)
        problem =
            new TlsCertify.Problem(
                "the server made it "
                    + a.state()
                    + " at Certify, and this call activates no certificate before its switch;"
                    + " revoke it",
                false);
      if (problem == null && !a.names().equals(List.of(temporary)))
        problem =
            new TlsCertify.Problem(
                "it has the names " + a.names() + ", not only " + temporary, false);
      if (problem == null)
        for (Link l : a.links())
          if (!(l.kind() == LinkKind.PUBLIC_KEY && l.targetId().equals(publicId))
              && !(l.kind() == LinkKind.CERTIFICATE
                  && (issuerIds.isEmpty() || l.targetId().equals(issuerIds.get(0))))) {
            problem = new TlsCertify.Problem("it has a link the call does not expect: " + l, false);
            break;
          }
    }
    if (problem != null) throw issuedRefused = refusedCertificate(id, problem);
    // The leaf's chain: the issuer's, or for a leaf of the server's own CA, what its links lead to.
    if (issuerIds.isEmpty()) {
      List<String> above = TlsIdentities.chainIds(keys, a, new java.util.HashMap<>());
      issuerIds = List.copyOf(above.subList(1, above.size()));
    }
    chain = request.chain(keys, issued, issuerIds);
    // As register() checks a chain given: each certificate issued by the next.
    String broken = TlsIdentities.chainBreak(chain);
    if (broken != null)
      throw issuedRefused =
          refusedCertificate(
              id, new TlsCertify.Problem("its chain does not verify: " + broken, false));
    // The leaf and, for a new pair, its public key, as Certify left them.
    KeyAttributes pub = keys.read(publicId).orElse(null);
    String toLeaf = link(LinkKind.CERTIFICATE, id);
    boolean pubLinked = pub != null && TlsOwnership.links(pub).contains(toLeaf);
    model(
        id,
        TlsOwnership.Expected.of(a, pubLinked ? Set.of(publicId) : Set.of()),
        "is the certificate this call's Certify made under " + temporary);
    if (newKeyMade) {
      TlsOwnership.Expected before = owned.get(publicId);
      TlsOwnership.Expected after = pubLinked ? before.linked(LinkKind.CERTIFICATE, id) : before;
      if (TlsOwnership.links(a).contains(link(LinkKind.PUBLIC_KEY, publicId)))
        after = after.linkedFrom(id);
      owned.put(publicId, after);
      own(publicId);
    }
    own(id);
    return leaf;
  }

  /**
   * Certify refused with Invalid Field while a validity was asked. The validity is the likely
   * cause: keytend-kmip-server refuses so a Deactivation Date after the issuing CA's notAfter (it
   * never cuts one short), and a notAfter at or before the notBefore. It also uses Invalid Field
   * for other faults of a request, so the message names the validity as the likely cause and keeps
   * the server's message, which says which.
   */
  private KmsException refusedValidity(KmsException refused, java.time.Instant until) {
    java.time.Instant caEnd = request.issuerNotAfter();
    return new InvalidRequestException(
        operation
            + ": the KMS refused Certify with Invalid Field ("
            + refused.getMessage()
            + "). A validity was asked ("
            + request.validFor()
            + ", a Deactivation Date of "
            + until
            + "). The likely cause: a KMS that takes the date as the certificate's notAfter"
            + " refuses one after its issuing CA's notAfter"
            + (caEnd == null ? "" : " (" + caEnd + ")")
            + ", and one already passed, rather than cut it short. Invalid Field also answers"
            + " other faults of the request; the server's message above says which. For the"
            + " validity, ask for one that ends before the CA expires, reissue the CA first, or"
            + " leave validFor out for the server's default. Nothing of the identity "
            + name
            + " changed."
            + leftovers(),
        refused,
        operation,
        null,
        refused.result().orElse(null),
        null);
  }

  /**
   * Stops an {@link Kind#issued} call whose leaf does not outlast the {@linkplain #margin safety
   * margin} now, by the Kms's clock ({@link #lastsTheMargin}). A repeat checks this before its
   * reads; the changes from the switch on check it just before each is sent ({@link
   * #guardedSend}).
   */
  private void unexpired() {
    java.time.Instant now = lastsTheMargin();
    if (now != null) throw tooShort(now);
  }

  /**
   * Null when the call has no issued leaf yet (before Certify), or its leaf is valid for more than
   * the {@link #margin} after now, by the Kms's clock; else that now. No exchange.
   */
  private java.time.Instant lastsTheMargin() {
    if (!kind.issued() || chain == null) return null;
    java.time.Instant now = keys.kms().now();
    java.time.Instant notAfter = chain.get(0).getNotAfter().toInstant();
    return Duration.between(now, notAfter).compareTo(margin()) > 0 ? null : now;
  }

  /** The {@link #margin} of the Kms this call runs on. */
  private Duration margin() {
    return margin(keys.kms().callTimeout());
  }

  /**
   * Sends {@code mutation}, a change from the switch on, only while the issued leaf outlasts the
   * {@link #margin}: checked just before each of its requests is sent, after the attempt's started
   * callbacks ({@link Kms#beforeSend}). Each change is an exchange of its own, and a slow reply can
   * take the leaf near or past its notAfter between any two, so this guards the switch, the link
   * from a kept key, each activation, the first change of the name's move (the move then runs to
   * its end, as a move left halfway gives the name to neither certificate), and the deactivation of
   * each certificate the leaf replaces. Before the switch is sent, the refusal is the issued
   * certificate's ({@link #refusedCertificate}): nothing of the identity changed. After it, {@link
   * #expiredSwitch}: the call stops before it activates the leaf or retires what it replaced, which
   * keeps working.
   */
  private void guardedSend(Runnable mutation) {
    if (!kind.issued() || chain == null) {
      mutation.run();
      return;
    }
    java.time.Instant[] at = new java.time.Instant[1];
    try {
      Kms.beforeSend(() -> (at[0] = lastsTheMargin()) == null, mutation);
    } catch (Kms.Withheld withheld) {
      throw tooShort(at[0]);
    }
  }

  /**
   * The refusal to go on with a leaf that did not outlast the {@link #margin} at {@code now}.
   * Before the switch, the certificate is too short-lived to use safely: nothing of the identity
   * changed, and a longer validity or a shorter call timeout (a smaller margin) is the remedy.
   */
  private KmsException tooShort(java.time.Instant now) {
    java.time.Instant notAfter = chain.get(0).getNotAfter().toInstant();
    if (finishing) return expiredRefusal = expiredSwitch(notAfter, now);
    String message =
        operation
            + ": the certificate "
            + leafId
            + " that the KMS issued is too short-lived to use safely: it "
            + lasts(notAfter, now)
            + ", before the switch, and each change of the identity needs it valid for more than"
            + " the safety margin. It was not used: nothing of the identity "
            + name
            + " changed."
            + sentence(leftovers())
            + " Ask for a longer validity (validFor), or call through a Kms with a shorter call"
            + " timeout";
    return issuedRefused = new KeyMismatchException(message, null, operation, leafId, null, null);
  }

  /** {@code text} ended with a period; "" for "". */
  private static String sentence(String text) {
    return text.isEmpty() ? "" : text + ".";
  }

  /**
   * How the leaf ending at {@code notAfter} stands at {@code now}: expired, or within the margin.
   */
  private String lasts(java.time.Instant notAfter, java.time.Instant now) {
    return notAfter.isAfter(now)
        ? "expires at "
            + notAfter
            + ", within the safety margin of "
            + margin()
            + " (now "
            + now
            + ")"
        : "expired at " + notAfter + " (now " + now + ")";
  }

  /** The refusal of the issued certificate {@code id}: {@code problem} says why. */
  private KmsException refusedCertificate(String id, TlsCertify.Problem problem) {
    String message =
        operation
            + ": the certificate "
            + id
            + " that the KMS issued is not what was requested: "
            + problem.why()
            + ". It was not used: nothing of the identity "
            + name
            + " changed."
            + (problem.validity()
                ? sentence(leftovers())
                    + " Issue without a validity (the server's default), or on a server that"
                    + " honors the requested Deactivation Date"
                : leftovers());
    return problem.validity()
        ? new UnsupportedException(message, null, operation, id, null, null)
        : new KeyMismatchException(message, null, operation, id, null, null);
  }

  /**
   * Step 5, after the switch: links a key the call keeps ({@code linkKept}) to the leaf, then
   * activates {@code objects} (the new key and the new intermediates, which are in {@link #owned}),
   * then the leaf, from which readers present the new pair.
   */
  private void publish(String leafId, KeyHandle key, boolean linkKept, List<String> objects) {
    if (linkKept) {
      step = "linking the private key " + key.id() + " to the new certificate";
      linkKept(key, leafId);
    }
    step = "activating the new objects";
    for (String id : objects) activate(id);
    step = "activating " + leafId;
    activate(leafId);
    activated = true;
  }

  /**
   * Gives a registration's leaf, still Pre-Active, the identity's name: the switch. A server that
   * refuses it although Locate finds no holder (it keeps the names of destroyed objects) leaves this
   * call's objects left over: it activated none of them and named none with the identity's name.
   */
  private void nameRegistration(String id) {
    try {
      change(
          id,
          e -> e.named(name),
          () -> {
            // A read just before showed the name not given: an earlier send did not take effect.
            // This one may: a send withheld by its check, or refused, is not.
            switchSent = true;
            try {
              guardedSend(() -> keys.handle(id).addName(name));
            } catch (OutcomeUnknownException unknown) {
              throw unknown;
            } catch (KmsException refused) {
              // The server answered: the name was not given.
              switchSent = false;
              throw refused;
            }
          });
    } catch (InvalidRequestException | StateConflictException taken) {
      if (taken == lastRefusal || taken == expiredRefusal) throw taken;
      // KMIP 1.x servers refuse a name in use with Invalid Field or Illegal Operation; addName
      // names the holder (AlreadyExistsException) only when Locate finds it.
      boolean legacy = !(taken instanceof AlreadyExistsException);
      // From KMIP 2.0 a name in use has its own reason: another refusal stands.
      if (legacy
          && (!KmsKeys.nameRefusal(taken) || !keys.kms().protocolVersion().legacyAttributes()))
        throw taken;
      throw nameRefused =
          new AlreadyExistsException(
              operation
                  + ": the server refuses the name "
                  + name
                  + (legacy
                      ? " ("
                          + taken.serverReason().map(Object::toString).orElse("")
                          + ", a KMIP 1.x answer for a name in use)"
                      : "")
                  + " although no object it locates has it: it keeps"
                  + " the names of objects it no longer returns (destroyed objects, on servers that keep their"
                  + " names), so the name cannot be used; register the identity under another name. This call's"
                  + " objects "
                  + ids(created)
                  + " are left over: "
                  + activatedBefore()
                  + ", and gave none the identity's name. A"
                  + " repeat under"
                  + " this name starts over and is refused the same way",
              taken,
              operation,
              id,
              null,
              null);
    }
  }

  /**
   * The new leaf an earlier call's switch made the identity's, if {@code found} leads to it: the
   * current certificate, Active; or the Pre-Active replacement being made current (for a
   * registration, the Pre-Active certificate with the name). Compared by DER encoding (one Get
   * each); null when there is none.
   */
  private KeyAttributes switched(TlsIdentities.Found found, KeyAttributes current) {
    if (found == null) return null;
    if (kind.issued()) return switchedIssued(found, current);
    if (current.state() == KeyState.ACTIVE && same(current.id(), chain.get(0))) return current;
    KeyAttributes newest = found.newest();
    boolean pending = kind.first() ? found.path.size() == 1 : !newest.id().equals(current.id());
    if (pending && newest.state() == KeyState.PRE_ACTIVE && same(newest.id(), chain.get(0)))
      return newest;
    return null;
  }

  /**
   * {@link #switched} for an issued leaf, which a repeat cannot compare with a chain it was given:
   * the leaf an earlier call's switch made, current and Active, or Pre-Active as the replacement
   * being made current (for a first issue, the Pre-Active certificate with the name), when it holds
   * what this call asks for ({@link TlsCertify#holds}, one Get). A first issue's leaf replaces
   * nothing; a reissue's replaces the certificate of the caller's handle, which links to it. The
   * chain the call then checks it against is that leaf and the issuer's chain.
   */
  private KeyAttributes switchedIssued(TlsIdentities.Found found, KeyAttributes current) {
    KeyAttributes candidate = null;
    if (current.state() == KeyState.ACTIVE && follows(current, found)) candidate = current;
    else {
      KeyAttributes newest = found.newest();
      boolean pending =
          kind.first()
              ? found.path.size() == 1
              : !newest.id().equals(current.id()) && follows(newest, found);
      if (pending && newest.state() == KeyState.PRE_ACTIVE) candidate = newest;
    }
    if (candidate == null) return null;
    X509Certificate issued;
    try {
      issued = TlsIdentities.certificate(keys.kms(), candidate.id());
    } catch (NotFoundException | StateConflictException gone) {
      return null;
    }
    if (!request.holds(issued, kind.keepsKey())) return null;
    // The issuer's chain, which the leaf's links must lead to; for the server's own CA, what they
    // lead to.
    issuerIds = request.issuerIds();
    if (issuerIds.isEmpty()) {
      List<String> above = TlsIdentities.chainIds(keys, candidate, found.read);
      issuerIds = List.copyOf(above.subList(1, above.size()));
    }
    chain = request.chain(keys, issued, issuerIds);
    return candidate;
  }

  /**
   * Whether {@code leaf} is where this call's switch puts its leaf: for a first issue, a leaf that
   * replaces nothing; for a reissue, the replacement of the caller's certificate, by links both
   * name.
   */
  private boolean follows(KeyAttributes leaf, TlsIdentities.Found found) {
    if (kind.first()) return leaf.links(LinkKind.REPLACED).isEmpty();
    if (!leaf.links(LinkKind.REPLACED).contains(expected)) return false;
    KeyAttributes old = TlsIdentities.attributes(keys, found.read, expected);
    return old != null && Lineage.replaced(leaf, old);
  }

  /**
   * A repeat that finds this call's leaf made the identity's by an earlier call's switch: what is
   * left is the activation ({@link #publish}) and {@link #finish}. Before any change, the leaf's
   * chain must hold this call's chain, certificate by certificate, and its key this call's key (a
   * renewal's, the key the identity keeps); otherwise the repeat stops, with nothing changed. Its
   * objects are changed only while a read just before shows them as a switch leaves them: the
   * leaf with no name or the identity's, linked exactly to its key, its issuer and the
   * certificates it replaced, and only its key linked to it; a Pre-Active new key or issuer with no
   * name, linked exactly to the leaf or to the next issuer, and only from the leaf or the
   * certificate it issued. An Active leaf with a Pre-Active key or issuer is not as a call leaves
   * it (the leaf is activated last). The certificates of the chain that are not Pre-Active are not
   * changed.
   */
  private TlsIdentityHandle finishSwitched(TlsIdentities.Found found, KeyAttributes leaf) {
    finishing = true;
    repeat = true;
    leafId = leaf.id();
    activated = leaf.state() == KeyState.ACTIVE;
    List<KeyAttributes> older = new ArrayList<>();
    for (KeyAttributes a : found.path) {
      if (a.id().equals(leaf.id())) break;
      older.add(a);
    }
    if (older.isEmpty())
      // Found by the name already: what it replaced, by links both name.
      for (String id : leaf.links(LinkKind.REPLACED)) {
        KeyAttributes p = TlsIdentities.attributes(keys, found.read, id);
        if (p != null && Lineage.replaced(leaf, p)) older.add(p);
      }
    if (!older.isEmpty()) {
      previous = older.get(older.size() - 1);
      replaced = previous.id();
    }
    unexpired();
    KeyAttributes key;
    if (kind.keepsKey()) {
      KeyAttributes kept =
          replaced == null
              ? null
              : TlsIdentities.keyOf(keys, older.get(older.size() - 1), found.read);
      if (kept == null || !leaf.links(LinkKind.PRIVATE_KEY).equals(List.of(kept.id())))
        throw differs(
            leaf,
            leaf.id(),
            "its Private Key link does not name the key the renewal keeps"
                + (kept == null ? "" : ", " + kept.id()),
            null);
      if (kept.state() != KeyState.ACTIVE)
        throw new StateConflictException(
                operation
                    + ": the private key "
                    + kept.id()
                    + " that the renewal to "
                    + leaf.id()
                    + " keeps is "
                    + kept.state()
                    + "; nothing was changed. "
                    + (kind.issued()
                        ? "Reissue the identity with a new key instead"
                        : "Re-key the identity instead")
                    + (activated
                        ? ""
                        : ", once the switch to "
                            + leaf.id()
                            + " is undone: "
                            + cleanUndo(
                                leaf,
                                exposed(leaf, older.get(older.size() - 1), found.read),
                                "that call's objects")),
                null,
                operation,
                kept.id(),
                null,
                null)
            .observed(kept.state());
      key = kept;
    } else {
      key = TlsIdentities.keyOf(keys, leaf, found.read);
      if (key == null)
        throw new StateConflictException(
                operation
                    + ": certificate "
                    + leaf.id()
                    + " has no private key linked to it and back; nothing was changed",
                null,
                operation,
                leaf.id(),
                null,
                null)
            .because(StateConflictException.Conflict.LINEAGE);
      if (kind.issued() ? !pairHolds(key, leaf) : !holdsTheKey(key))
        throw differs(
            leaf,
            key.id(),
            kind.issued()
                ? "its private key "
                    + key.id()
                    + " and it do not link to one public key object holding its key"
                : "its private key " + key.id() + " is not the key given",
            null);
    }
    // The pair's public key object: the leaf's Public Key link, which a new key's names too.
    String pub = null;
    if (kind.pairObjects()) {
      List<String> fromLeaf = leaf.links(LinkKind.PUBLIC_KEY);
      List<String> fromKey = key.links(LinkKind.PUBLIC_KEY);
      if (fromLeaf.size() != 1 || !fromKey.equals(fromLeaf))
        throw differs(
            leaf,
            leaf.id(),
            "it and its private key " + key.id() + " do not link to one public key object",
            null);
      pub = fromLeaf.get(0);
      publicId = pub;
    }
    KeyAttributes pubRead = pub == null ? null : TlsIdentities.attributes(keys, found.read, pub);
    List<String> ids = TlsIdentities.chainIds(keys, leaf, found.read);
    KeyAttributes previous = older.isEmpty() ? null : older.get(older.size() - 1);
    if (ids.size() != chain.size())
      throw differs(
          leaf,
          leaf.id(),
          "its chain has " + ids.size() + " certificates, not the " + chain.size() + " given",
          activated ? null : exposed(leaf, previous, found.read));
    for (int i = 1; i < ids.size(); i++)
      if (!same(ids.get(i), chain.get(i)))
        throw differs(
            leaf,
            ids.get(i),
            "certificate " + i + " of its chain, " + ids.get(i) + ", is not the one given",
            activated ? null : exposed(leaf, previous, found.read));
    // An issued leaf's chain is the issuer's, or what the links of the server's own CA lead to:
    // the repeat checks it as the call does before its switch.
    String broken = kind.issued() ? TlsIdentities.chainBreak(chain) : null;
    if (broken != null)
      throw new KeyMismatchException(
          operation
              + ": certificate "
              + leaf.id()
              + " holds what this call asks for, and an earlier call made it "
              + (leaf.state() == KeyState.ACTIVE
                  ? "the certificate " + name + " presents"
                  : kind.first()
                      ? "the certificate with the name " + name
                      : "the replacement of " + replaced)
              + ", but its chain does not verify: "
              + broken
              + "; nothing was changed. Link each certificate of the chain to the certificate"
              + " that issued it, then repeat to finish that call."
              + (activated ? "" : undo(leaf, exposed(leaf, previous, found.read))),
          null,
          operation,
          leaf.id(),
          null,
          null);
    boolean keyLinked = key.links(LinkKind.CERTIFICATE).contains(leaf.id());
    if (activated && !keyLinked)
      // A renewal links the key it keeps to the leaf before it activates the leaf.
      throw new StateConflictException(
              operation
                  + ": certificate "
                  + leaf.id()
                  + " is Active, and its private key "
                  + key.id()
                  + " does not link back to it; nothing was changed",
              null,
              operation,
              leaf.id(),
              null,
              null)
          .because(StateConflictException.Conflict.LINEAGE);
    Set<String> links = new LinkedHashSet<>();
    links.add(link(LinkKind.PRIVATE_KEY, key.id()));
    if (pub != null) links.add(link(LinkKind.PUBLIC_KEY, pub));
    if (ids.size() > 1) links.add(link(LinkKind.CERTIFICATE, ids.get(1)));
    for (KeyAttributes p : older)
      if (leaf.links(LinkKind.REPLACED).contains(p.id()))
        links.add(link(LinkKind.REPLACED, p.id()));
    String made =
        activated
            ? "is the certificate " + name + " presents, which an earlier call made current"
            : "is the new certificate of " + name + ", which an earlier call's switch made";
    model(
        leaf.id(),
        new TlsOwnership.Expected(
            ObjectKind.CERTIFICATE,
            leaf.state(),
            leaf.names().contains(name) ? Set.of(name) : Set.of(),
            links,
            linkedToLeaf(key.id(), keyLinked, pubRead, leaf.id())),
        made);
    List<String> toActivate = new ArrayList<>();
    if (!kind.keepsKey() && key.state() != KeyState.ACTIVE) {
      model(
          key.id(),
          new TlsOwnership.Expected(
              ObjectKind.PRIVATE_KEY,
              KeyState.PRE_ACTIVE,
              Set.of(),
              pub == null
                  ? Set.of(link(LinkKind.CERTIFICATE, leaf.id()))
                  : Set.of(link(LinkKind.CERTIFICATE, leaf.id()), link(LinkKind.PUBLIC_KEY, pub)),
              pub == null ? Set.of(leaf.id()) : Set.of(leaf.id(), pub)),
          "is the private key of " + leaf.id() + ", which an earlier call's switch made");
      toActivate.add(key.id());
    }
    if (!kind.keepsKey() && pubRead != null && pubRead.state() != KeyState.ACTIVE) {
      model(
          pub,
          new TlsOwnership.Expected(
              ObjectKind.PUBLIC_KEY,
              KeyState.PRE_ACTIVE,
              Set.of(),
              Set.of(link(LinkKind.PRIVATE_KEY, key.id()), link(LinkKind.CERTIFICATE, leaf.id())),
              Set.of(key.id(), leaf.id())),
          "is the public key of " + leaf.id() + ", which an earlier call's switch made");
      toActivate.add(pub);
    }
    // The issuers as this call's chain makes them: the last links to nothing. An issued leaf's
    // issuers existed before the call, which changes none of them.
    for (int i = 1; !kind.issued() && i < ids.size() && i < chain.size(); i++) {
      KeyAttributes c = TlsIdentities.attributes(keys, found.read, ids.get(i));
      if (c == null || c.state() != KeyState.PRE_ACTIVE) continue;
      model(
          c.id(),
          new TlsOwnership.Expected(
              ObjectKind.CERTIFICATE,
              KeyState.PRE_ACTIVE,
              Set.of(),
              i + 1 < chain.size() && i + 1 < ids.size()
                  ? Set.of(link(LinkKind.CERTIFICATE, ids.get(i + 1)))
                  : Set.of(),
              Set.of(ids.get(i - 1))),
          "is certificate "
              + i
              + " of the chain of "
              + leaf.id()
              + ", which an earlier call's"
              + " switch made");
      toActivate.add(c.id());
    }
    if (activated && !toActivate.isEmpty())
      throw refusal(
          toActivate.get(0),
          new TlsOwnership.Mismatch(
              StateConflictException.Conflict.STATE,
              KeyState.PRE_ACTIVE,
              "it is Pre-Active while "
                  + leaf.id()
                  + " is Active, which a call activates after it"));
    if (!activated) {
      // Each object as a switch leaves it, before the first change to any of them.
      for (String id : List.copyOf(owned.keySet())) own(id);
      publish(leaf.id(), keys.handle(key.id()), kind.keepsKey() && !keyLinked, toActivate);
    }
    return finish(older, found.read, leaf.id(), key.id(), ids);
  }

  /**
   * The refusal to go on with a switch to an issued leaf that expired at {@code notAfter}, or ends
   * within the {@link #margin} of {@code now} (by the Kms's clock): this call's switch, or for a
   * repeat an earlier call's. The call stops before it activates the leaf, moves the name or
   * retires what the leaf replaced: that certificate, while it is Active, still works and, unless
   * the leaf is Active, readers present it. The advice follows the leaf and the certificate it
   * replaced as they are now (read now), not what this call did: a repeat of a call that finished
   * finds the replaced certificate retired already. It says how to undo the switch ({@link
   * #exposed}) while the replaced certificate is Active. A certificate the server no longer has
   * (a read that finds nothing is Not Found) is not Active: a server that drops destroyed objects
   * answers so, and nothing can be undone to it.
   */
  private StateConflictException expiredSwitch(java.time.Instant notAfter, java.time.Instant now) {
    Map<String, KeyAttributes> read = new java.util.HashMap<>();
    KeyAttributes leaf = TlsIdentities.attributes(keys, read, leafId);
    boolean active = leaf != null && leaf.state() == KeyState.ACTIVE;
    KeyAttributes before =
        previous == null ? null : TlsIdentities.attributes(keys, read, previous.id());
    boolean previousActive = before != null && before.state() == KeyState.ACTIVE;
    // A repeat of a call that finished: the leaf Active, named, and nothing left to retire.
    boolean finished =
        repeat
            && active
            && deactivated.isEmpty()
            && !previousActive
            && leaf != null
            && leaf.names().contains(name);
    String whose = repeat ? "an earlier call's" : "this call's";
    String objects = repeat ? "that call's objects" : "this call's objects";
    StringBuilder m = new StringBuilder(operation);
    m.append(": certificate ")
        .append(leafId)
        .append(", which ")
        .append(whose)
        .append(" switch made the identity ")
        .append(name)
        .append("'s, ")
        .append(lasts(notAfter, now))
        .append(", so this ")
        .append(repeat ? "repeat " : "call ")
        .append(
            finished || (active && !previousActive)
                ? "stops"
                : active
                    ? "does not retire what it replaced"
                    : previous == null
                        ? "does not activate it"
                        : previousActive
                            ? "neither activates it nor retires what it replaced"
                            : "does not activate it")
        .append(wrote ? "; it changed nothing more." : "; nothing was changed.");
    if (!deactivated.isEmpty())
      m.append(" It deactivated ").append(Exposed.list(deactivated)).append(" already.");
    Exposed e = leaf == null ? null : exposed(leaf, previous, read);
    if (finished) {
      m.append(" The earlier call finished: ").append(name).append(" presents ").append(leafId);
      if (previous != null)
        m.append(", and ")
            .append(previous.id())
            .append(before == null ? " no longer exists" : " is " + before.state());
      m.append(". ")
          .append(leafId)
          .append(
              notAfter.isAfter(now) ? " now ends within the safety margin" : " has expired since")
          .append(". Reissue the identity for a certificate that works.");
    } else if (previous == null) {
      if (active) m.append(" Reissue the identity for a certificate that works.");
      else if (leaf == null)
        m.append(" ")
            .append(leafId)
            .append(" no longer exists, so the next call starts over, and ")
            .append(objects)
            .append(" are left over.");
      else if (e != null)
        m.append(" To issue again, first take the name ")
            .append(name)
            .append(" off ")
            .append(leafId)
            .append(e.active().isEmpty() ? "" : " and revoke " + Exposed.list(e.active()))
            .append(". The next call starts over, and ")
            .append(objects)
            .append(" are left over.");
    } else if (!previousActive) {
      m.append(" ")
          .append(previous.id())
          .append(before == null ? " no longer exists" : " is " + before.state())
          .append(leaf == null ? ", and " + leafId + " no longer exists" : "")
          .append(". Reissue the identity for a certificate that works.");
    } else if (!active) {
      m.append(" ").append(previous.id()).append(" is still Active, and readers present it.");
      if (leaf == null) m.append(" ").append(leafId).append(" no longer exists.");
      else if (e != null) m.append(" To issue again, first ").append(cleanUndo(leaf, e, objects));
    } else {
      m.append(" ")
          .append(previous.id())
          .append(" is still Active, but readers present ")
          .append(leafId)
          .append(" while it is Active.");
      if (e != null) {
        List<String> revoke = new ArrayList<>();
        revoke.add(leafId);
        revoke.addAll(e.active());
        m.append(" To present ")
            .append(previous.id())
            .append(" again, take the Replacement Object link to ")
            .append(leafId)
            .append(" off ")
            .append(previous.id())
            .append(
                e.linkedKey() == null
                    ? ""
                    : ", and the Certificate link to " + leafId + " off " + e.linkedKey())
            .append(
                named
                    ? "; give "
                        + previous.id()
                        + " the name "
                        + name
                        + " back and take it off "
                        + leafId
                    : "")
            .append("; then revoke ")
            .append(Exposed.list(revoke))
            .append(". Then reissue.");
      }
    }
    StateConflictException refusal =
        new StateConflictException(m.toString(), null, operation, leafId, null, null);
    return leaf == null ? refusal : refusal.observed(leaf.state());
  }

  /**
   * Whether {@code key} holds the private half of the new leaf's public key, the key this call
   * was given (one Get, after the leaf's checks; an Obtain Lease first where it states a Lease
   * Time).
   */
  private boolean holdsTheKey(KeyAttributes key) {
    java.security.PublicKey leafKey = chain.get(0).getPublicKey();
    try {
      return TlsIdentities.matches(
          keys.handle(key.id()).asPrivateKey(TlsIdentities.expect(leafKey)), leafKey);
    } catch (KeyMismatchException other) {
      return false;
    }
  }

  /**
   * For an issued leaf: whether its private key {@code key} and it link to one public key object,
   * which links back to the key and holds the leaf's public key (one Get). Certify issued the leaf
   * for that public key, and Create Key Pair made it with the private key.
   */
  private boolean pairHolds(KeyAttributes key, KeyAttributes leaf) {
    List<String> pub = key.links(LinkKind.PUBLIC_KEY);
    if (pub.size() != 1 || !leaf.links(LinkKind.PUBLIC_KEY).equals(pub)) return false;
    java.security.PublicKey leafKey = chain.get(0).getPublicKey();
    try {
      KeyHandle p = keys.handle(pub.get(0));
      return p.attributes().links(LinkKind.PRIVATE_KEY).contains(key.id())
          && TlsCertify.sameKey(p.asPublicKey(TlsIdentities.expect(leafKey)), leafKey);
    } catch (KeyMismatchException | NotFoundException | IllegalStateException other) {
      return false;
    }
  }

  /**
   * The objects that link to the leaf {@code leafId} with Certificate links as a switch leaves
   * them: its private key, once linked ({@code keyLinked}), and its public key object, read as
   * {@code pub} (null: none), when Certify or the call linked it.
   */
  private Set<String> linkedToLeaf(
      String keyId, boolean keyLinked, KeyAttributes pub, String leafId) {
    Set<String> from = new LinkedHashSet<>();
    if (keyLinked) from.add(keyId);
    if (pub != null && pub.links(LinkKind.CERTIFICATE).contains(leafId)) from.add(pub.id());
    return from;
  }

  /**
   * How to undo the switch to {@code leaf}, whatever {@code e} it would leave, so that nothing is
   * left Active or linked from the identity: for a renewal whose kept key is no longer Active, which
   * cannot be finished.
   */
  private String cleanUndo(KeyAttributes leaf, Exposed e, String objects) {
    return "take the Replacement Object link to "
        + leaf.id()
        + " off "
        + replaced
        + (e.linkedKey() == null
            ? ""
            : ", and the Certificate link to " + leaf.id() + " off " + e.linkedKey())
        + (e.active().isEmpty() ? "" : "; then revoke " + Exposed.list(e.active()))
        + ". The next call starts over, and "
        + objects
        + " are left over"
        + (e.taken() != null
            ? ". " + e.taken()
            : e.active().isEmpty() ? ", Pre-Active." : ", none Active.");
  }

  /**
   * The refusal of a repeat whose arguments differ from what the switch it finds made: {@code
   * leaf} holds the leaf given, but {@code why}; {@code id} names the object that differs. Nothing
   * was changed. {@code exposed}, when the leaf is not Active: what undoing the switch would leave
   * (see {@link #undo}); null when the leaf's links may not show what that call made (its key
   * differs), and the undo is not offered.
   */
  private StateConflictException differs(
      KeyAttributes leaf, String id, String why, Exposed exposed) {
    return lastRefusal =
        new StateConflictException(
                operation
                    + ": certificate "
                    + leaf.id()
                    + (kind.issued() ? " holds what this call asks for" : " holds the leaf given")
                    + ", and an earlier call made it "
                    + (leaf.state() == KeyState.ACTIVE
                        ? "the certificate " + name + " presents"
                        : kind.first()
                            ? "the certificate with the name " + name
                            : "the replacement of " + replaced)
                    + ", but "
                    + why
                    + "; nothing was changed. "
                    + (kind.issued()
                        ? "To finish that call, repeat it with the arguments it was given; to"
                            + " present another chain, reissue afterwards."
                        : "To finish that call, repeat it with the chain"
                            + (kind.keepsKey() ? "" : " and the private key")
                            + " it was given; to present another chain, renew afterwards with a"
                            + " new certificate issued under it.")
                    + (leaf.state() == KeyState.ACTIVE ? "" : undo(leaf, exposed))
                    + " When another caller changed the links of "
                    + leaf.id()
                    + " or of its chain, undo that, then repeat",
                null,
                operation,
                id,
                null,
                null)
            .because(StateConflictException.Conflict.LINEAGE);
  }

  /**
   * What taking the switch to {@code leaf} off would leave of the stopped call behind other than
   * Pre-Active and unlinked: {@code active}, each object of that call that is not Pre-Active, with
   * its state; {@code linkedKey}, the identity's key when that call linked it to the leaf (a renewal
   * links it first after the switch). {@code otherLink}: the identity's key when it links to a leaf
   * that is not a renewal's (another caller linked it), a link the undo takes off too. {@code
   * taken}: where the count stopped at an object in the place of one of that call's that is not
   * Pre-Active but has a name or links that call does not give it, which counts as another
   * caller's, a sentence saying the undo leaves it, and what follows it, as they are; null
   * otherwise. A call activates its key and issuers before the leaf, so a leaf that is not Active
   * says nothing of them.
   */
  private record Exposed(List<String> active, String linkedKey, String otherLink, String taken) {
    boolean none() {
      return active.isEmpty() && linkedKey == null;
    }

    /**
     * The sentence for {@link #taken} on {@code a}, {@code rest} what follows it ("" for none).
     */
    static String taken(KeyAttributes a, String rest) {
      return a.id()
          + " ("
          + a.state()
          + ") has a name or links that call does not give it, so it counts as another caller's:"
          + " the undo leaves it"
          + (rest.isEmpty() ? " as it is." : ", and " + rest + ", as they are.");
    }

    /** What would be left, as a phrase. */
    String left(String leafId) {
      String keyLinked =
          linkedKey == null
              ? ""
              : "the identity's private key " + linkedKey + " linked to " + leafId;
      if (active.isEmpty()) return keyLinked;
      return list(active) + (keyLinked.isEmpty() ? "" : ", and " + keyLinked);
    }

    /** The undo's step for {@link #otherLink}, as a clause; empty when there is none. */
    String otherLinkOff(String leafId) {
      return otherLink == null
          ? ""
          : ", and the Certificate link to " + leafId + " off " + otherLink;
    }

    /** {@code items}, joined with commas and a last "and". */
    static String list(List<String> items) {
      int n = items.size();
      return n == 1
          ? items.get(0)
          : String.join(", ", items.subList(0, n - 1)) + " and " + items.get(n - 1);
    }
  }

  /**
   * {@link Exposed} for the switch to {@code leaf} that {@code predecessor} (null for a
   * registration) names: reads, from {@code read} or now (one Get Attributes each, and a Locate by
   * link for each object counted, on a refusal only).
   *
   * <p>Only what the stopped call could have made and changed counts, so that an object another
   * caller linked in, which the undo leaves as it was, does not: the call's steps after its switch
   * are, in order, a renewal's link from the key it keeps to the leaf, a new key's Activate (a
   * re-key's or a registration's), and the new issuers' Activates, the leaf's issuer first. An
   * object counts only when each step before its own was made, and it is as the call leaves it: no
   * name, linked only to the leaf (the key) or the next issuer, and linked to only from the leaf or
   * the issuer below ({@link TlsOwnership#mismatch}). A leaf whose Private Key link is not the
   * identity's key (a renewal's) or one new key (a re-key's), such as another caller's
   * certificate, has nothing of a call.
   */
  private Exposed exposed(
      KeyAttributes leaf, KeyAttributes predecessor, Map<String, KeyAttributes> read) {
    Set<String> own = new java.util.HashSet<>();
    String identityKey = null;
    boolean keyLinked = false;
    if (predecessor != null) {
      own.add(predecessor.id());
      own.addAll(TlsIdentities.chainIds(keys, predecessor, read));
      KeyAttributes k = TlsIdentities.keyOf(keys, predecessor, read);
      if (k != null) {
        own.add(k.id());
        own.addAll(k.links(LinkKind.PUBLIC_KEY));
        identityKey = k.id();
        keyLinked = k.links(LinkKind.CERTIFICATE).contains(leaf.id());
      }
    }
    List<String> keyLinks = leaf.links(LinkKind.PRIVATE_KEY);
    // A pair with a public key object (an issued leaf, or an issuer): the leaf's Public Key link.
    List<String> pubLinks = leaf.links(LinkKind.PUBLIC_KEY);
    String pub = pubLinks.size() == 1 && !own.contains(pubLinks.get(0)) ? pubLinks.get(0) : null;
    boolean renewal = identityKey != null && keyLinks.equals(List.of(identityKey));
    List<String> active = new ArrayList<>();
    String taken = null;
    boolean made = renewal && keyLinked;
    if (!renewal && keyLinks.size() == 1 && !own.contains(keyLinks.get(0))) {
      KeyAttributes k = TlsIdentities.attributes(keys, read, keyLinks.get(0));
      boolean on = k != null && k.state() != KeyState.PRE_ACTIVE;
      made =
          on
              && asLeft(
                  k,
                  ObjectKind.PRIVATE_KEY,
                  pub == null
                      ? Set.of(link(LinkKind.CERTIFICATE, leaf.id()))
                      : Set.of(
                          link(LinkKind.CERTIFICATE, leaf.id()), link(LinkKind.PUBLIC_KEY, pub)),
                  pub == null ? Set.of(leaf.id()) : Set.of(leaf.id(), pub));
      if (made) active.add(k.id() + " (" + k.state() + ")");
      else if (on) taken = Exposed.taken(k, "the issuers of " + leaf.id());
      // Its public key object, which a call activates next.
      if (made && pub != null) {
        KeyAttributes p = TlsIdentities.attributes(keys, read, pub);
        boolean pon = p != null && p.state() != KeyState.PRE_ACTIVE;
        made =
            pon
                && asLeft(
                    p,
                    ObjectKind.PUBLIC_KEY,
                    Set.of(
                        link(LinkKind.PRIVATE_KEY, k.id()), link(LinkKind.CERTIFICATE, leaf.id())),
                    Set.of(k.id(), leaf.id()));
        if (made) active.add(pub + " (" + p.state() + ")");
        else if (pon) taken = Exposed.taken(p, "the issuers of " + leaf.id());
      }
    }
    List<String> ids = TlsIdentities.chainIds(keys, leaf, read);
    for (int i = 1; made && i < ids.size(); i++) {
      String id = ids.get(i);
      // The issuers a renewal keeps are the identity's own, and the last of the chain.
      if (own.contains(id)) continue;
      KeyAttributes c = TlsIdentities.attributes(keys, read, id);
      // An issuer in the KMS (a certificate with a Public Key link, as registerIssuer makes it)
      // existed before the call, as do those above it: a call registers no such certificate.
      if (c != null && !c.links(LinkKind.PUBLIC_KEY).isEmpty()) break;
      boolean on = c != null && c.state() != KeyState.PRE_ACTIVE;
      made =
          on
              && asLeft(
                  c,
                  ObjectKind.CERTIFICATE,
                  i + 1 < ids.size()
                      ? Set.of(link(LinkKind.CERTIFICATE, ids.get(i + 1)))
                      : Set.of(),
                  ids.get(i - 1));
      if (made) active.add(id + " (" + c.state() + ")");
      else if (on) taken = Exposed.taken(c, i + 1 < ids.size() ? "its issuers" : "");
    }
    return new Exposed(
        List.copyOf(active),
        renewal && keyLinked ? identityKey : null,
        !renewal && keyLinked ? identityKey : null,
        taken);
  }

  /**
   * Whether {@code a} is as a call leaves an object of {@code kind} it made: no name, exactly the
   * {@code links}, and only {@code from} linked to it, where a Locate by link shows them.
   */
  private boolean asLeft(KeyAttributes a, ObjectKind kind, Set<String> links, String from) {
    return asLeft(a, kind, links, Set.of(from));
  }

  private boolean asLeft(KeyAttributes a, ObjectKind kind, Set<String> links, Set<String> from) {
    TlsOwnership.Expected e = new TlsOwnership.Expected(kind, a.state(), Set.of(), links, from);
    return TlsOwnership.mismatch(e, a, linkedTo(e, a.id())) == null;
  }

  /**
   * How to undo the switch to {@code leaf}, which is not Active yet, so that a repeat starts over:
   * offered only while nothing it would leave is Active or linked from the identity ({@code e}).
   * Otherwise empty: a plain repeat finishes that call. Where the count stopped at an Active
   * object that counts as another caller's ({@link Exposed#taken}), the offer names it instead of
   * saying nothing of that call is Active.
   */
  private String undo(KeyAttributes leaf, Exposed e) {
    if (e == null) return "";
    if (!e.none())
      return " Do not take the switch to "
          + leaf.id()
          + " off: that would leave "
          + e.left(leaf.id())
          + ". Finish that call instead.";
    return (e.taken() == null ? " Or, as nothing that call made is Active yet, take " : " Or take ")
        + (kind.first()
            ? "the name " + name + " off it"
            : "the Replacement Object link to it off " + replaced + e.otherLinkOff(leaf.id()))
        + ", then repeat with the chain you want: the repeat starts over, and that call's objects"
        + " are left over"
        + (e.taken() == null ? ", Pre-Active." : ". " + e.taken());
  }

  /**
   * Step 6: the name, and the retirement of the {@code older} certificates the leaf replaced, the
   * identity's own. Changes to the leaf, which is in {@link #owned}, are checked by {@link #change}.
   */
  private TlsIdentityHandle finish(
      List<KeyAttributes> older,
      Map<String, KeyAttributes> read,
      String leafId,
      String keyId,
      List<String> chainIds) {
    changed = true;
    finishing = true;
    step = "giving the name " + name + " to " + leafId;
    moveName(leafId, older);
    named = true;
    step = "deactivating what " + leafId + " replaced";
    for (KeyAttributes old : older) {
      if (old.state() == KeyState.ACTIVE) {
        retire(keys.handle(old.id()), leafId, this::guardedSend);
        deactivated.add(old.id());
      }
      KeyAttributes oldKey = TlsIdentities.keyOf(keys, old, read);
      if (oldKey != null && !oldKey.id().equals(keyId) && oldKey.state() == KeyState.ACTIVE) {
        retire(keys.handle(oldKey.id()), leafId, Runnable::run);
        deactivated.add(oldKey.id());
      }
      // The old key's public key object, which links back to it, when the key changed.
      if (oldKey != null && !oldKey.id().equals(keyId))
        for (String id : oldKey.links(LinkKind.PUBLIC_KEY)) {
          KeyAttributes p = TlsIdentities.attributes(keys, read, id);
          if (p != null
              && p.kind() == ObjectKind.PUBLIC_KEY
              && p.links(LinkKind.PRIVATE_KEY).contains(oldKey.id())
              && p.state() == KeyState.ACTIVE) {
            retire(keys.handle(id), leafId, Runnable::run);
            deactivated.add(id);
          }
        }
    }
    retired = true;
    return handle(leafId, keyId, chainIds);
  }

  private TlsIdentityHandle handle(String leafId, String keyId, List<String> chainIds) {
    List<KeyHandle> chainHandles = chainIds.stream().map(keys::handle).toList();
    return new TlsIdentityHandle(tls, name, keys.handle(leafId), keys.handle(keyId), chainHandles);
  }

  /**
   * How many certificates at the end of the new chain equal those at the end of the old one (the
   * leaf excluded), by their DER encoding: the issuers a renewal keeps are not registered again.
   */
  private int sharedTail(List<String> oldChain, TlsIdentities.Found found) {
    if (found == null || oldChain.size() < 2) return 0;
    int n = 0;
    while (n < chain.size() - 1 && n < oldChain.size() - 1) {
      X509Certificate mine = chain.get(chain.size() - 1 - n);
      X509Certificate theirs;
      try {
        theirs = TlsIdentities.certificate(keys.kms(), oldChain.get(oldChain.size() - 1 - n));
      } catch (NotFoundException | StateConflictException gone) {
        break;
      }
      if (!Arrays.equals(encoded(mine), encoded(theirs))) break;
      n++;
    }
    return n;
  }

  /**
   * Gives the name to the leaf and takes it off the {@code older} certificates that have it. A
   * server without unique names takes it on the leaf at once: both have it until it is taken off
   * the others, and lookups find either, each a whole pair. A server with unique names refuses it:
   * the leaf then records the name as being moved to it, the name is taken off the others and given
   * to the leaf, and the record removed; meanwhile lookups find the leaf through the record. Lost
   * replies are read back.
   */
  private void moveName(String leafId, List<KeyAttributes> older) {
    List<KeyHandle> holders = new ArrayList<>();
    for (KeyAttributes o : older) if (o.names().contains(name)) holders.add(keys.handle(o.id()));
    if (!owned.get(leafId).names().contains(name)) {
      try {
        addName(leafId, true);
      } catch (AlreadyExistsException unique) {
        if (holders.isEmpty()) throw unique;
        pending(leafId);
        for (KeyHandle h : holders) removeName(h, name);
        try {
          addName(leafId, false);
        } catch (InvalidRequestException | StateConflictException refused) {
          if (refused instanceof AlreadyExistsException || refused == lastRefusal) throw refused;
          // Refused again with the name on no holder: the first refusal was not a name in use
          // either. The name goes back to the certificate that had it, its record removed.
          try {
            KeyHandle back = holders.get(0);
            if (!back.attributes().names().contains(name)) back.addName(name);
            removePending(leafId);
          } catch (KmsException | IllegalStateException failed) {
            refused.addSuppressed(failed);
          }
          throw refused;
        }
      }
    }
    for (KeyHandle h : holders) removeName(h, name);
    removePending(leafId);
  }

  /**
   * Removes the record of the name being moved from the leaf {@code leafId}: one instance of this
   * name's value per request, each only while a read just before shows the leaf as expected
   * ({@link #unseen}), until a read shows none. An instance of another value is left.
   */
  private void removePending(String leafId) {
    KeyHandle leaf = keys.handle(leafId);
    unseen(
        leafId,
        () -> leaf.removeOneCustom(KeyHandle.pendingName(name), name),
        read -> !KeyHandle.pendingNames(read).contains(name),
        true);
  }

  /**
   * Gives the identity's name to the leaf {@code leafId}; a lost reply is read back. With {@code
   * first}, the first change of the name's move, an issued leaf must outlast the safety margin
   * just before each send ({@link #guardedSend}).
   */
  private void addName(String leafId, boolean first) {
    change(
        leafId,
        e -> e.named(name),
        () -> {
          if (first) guardedSend(() -> keys.handle(leafId).addName(name));
          else keys.handle(leafId).addName(name);
        });
  }

  /**
   * Runs {@code change}; when its reply is lost, {@code done} reads whether it took effect, and
   * when it did not, it is sent again (three times at most): a change that a read shows not to have
   * happened can be repeated.
   */
  private static void settle(Runnable change, java.util.function.BooleanSupplier done) {
    for (int attempt = 1; ; attempt++) {
      try {
        change.run();
        return;
      } catch (OutcomeUnknownException lost) {
        if (done.getAsBoolean()) return;
        if (attempt == 3) throw lost;
      }
    }
  }

  /**
   * Links {@code predecessor}, the identity's current certificate, to {@code leaf} with its
   * Replacement Object link: the switch. Before each send, the race is read and the leaf checked
   * ({@link #own}); a lost reply is read back. When another certificate replaced it first (another
   * renewal won the race; a server that allows one replacement refuses this link), this call stops
   * with a {@link StateConflictException}.
   */
  private void replacementLink(KeyAttributes predecessor, KeyHandle leaf) {
    KeyHandle p = keys.handle(predecessor.id());
    try {
      for (int attempt = 1; ; attempt++) {
        KeyAttributes read = p.attributes();
        boolean made = read.links(LinkKind.REPLACEMENT).contains(leaf.id());
        if (made && attempt > 1) return;
        // Not made, as read: an earlier send whose reply was lost did not take effect.
        switchSent = false;
        lostRace(read, leaf);
        own(leaf.id());
        if (made) return;
        wrote = true;
        changed = true;
        switchSent = true;
        try {
          guardedSend(
              () -> add(p, Attributes.link(Enums.LinkType.REPLACEMENT_OBJECT_LINK, leaf.id())));
          return;
        } catch (OutcomeUnknownException unknown) {
          if (attempt == 3) throw unknown;
        } catch (KmsException refused) {
          // The server answered: the switch was not made.
          switchSent = false;
          throw refused;
        }
      }
    } catch (StateConflictException
        | InvalidRequestException
        | PermissionDeniedException
        | UnsupportedException refused) {
      if (refused == lastRefusal
          || refused == lost
          || refused == expiredRefusal
          || Failures.credentialsRefused(refused)) throw refused;
      lostRace(p.attributes(), leaf);
      throw refused;
    }
  }

  /** Stops when a certificate other than {@code leaf} replaced {@code predecessor} (links both name). */
  private void lostRace(KeyAttributes predecessor, KeyHandle leaf) {
    for (String id : predecessor.links(LinkKind.REPLACEMENT)) {
      if (id.equals(leaf.id())) continue;
      Optional<KeyAttributes> other = keys.read(id);
      if (other.isPresent() && Lineage.replaced(other.get(), predecessor))
        throw lost =
            new StateConflictException(
                    operation
                        + ": "
                        + predecessor.id()
                        + " was replaced meanwhile by "
                        + id
                        + " (another renewal or re-key of "
                        + name
                        + " ran at the same time: run one at a time); kms.tls().identity(\""
                        + name
                        + "\") is the identity now."
                        + leftovers(),
                    null,
                    operation,
                    predecessor.id(),
                    null,
                    null)
                .because(StateConflictException.Conflict.REPLACED);
    }
  }

  /**
   * What this call activated before its switch: nothing, but for an issue's or new-key reissue's
   * new private key, which it activated to sign the certificate request.
   */
  private String activatedBefore() {
    return activatedKey == null
        ? "it activated none of them"
        : "it activated none of them but the new private key "
            + activatedKey
            + ", which signed the certificate request";
  }

  /** What becomes of this call's objects when it stops before the switch; "" when it made none. */
  private String leftovers() {
    return created.isEmpty()
        ? ""
        : " This call's objects "
            + ids(created)
            + " are left over: "
            + activatedBefore()
            + ". A repeat leaves them, and any change"
            + " another caller made to them, as they are";
  }

  private static List<String> ids(List<KeyHandle> handles) {
    return handles.stream().map(KeyHandle::id).toList();
  }

  /**
   * Links {@code from}, an object in {@link #owned}, to {@code target} with a link of {@code
   * linkKind}, unless it is so already ({@link #change}). A target in {@link #owned} is checked
   * before each send too ({@link #own}): the call links nothing to an object another caller
   * changed. Its link is then among those the target expects.
   */
  private void link(String from, LinkKind linkKind, String target) {
    TlsOwnership.Expected t = owned.get(target);
    change(
        from,
        e -> e.linked(linkKind, target),
        () -> add(keys.handle(from), Attributes.link(linkKind.protocolValue(), target)),
        t == null ? List.of() : List.of(target));
    if (t != null && linkKind == TlsOwnership.toIt(t.kind()))
      owned.put(target, owned.get(target).linkedFrom(from));
  }

  private static String link(LinkKind linkKind, String target) {
    return TlsOwnership.link(linkKind, linkKind.protocolValue().code(), target);
  }

  /**
   * Links the private key a renewal keeps, the identity's own, to the new leaf with a Certificate
   * link. The leaf is checked before each send ({@link #own}); a lost reply is read back.
   */
  private void linkKept(KeyHandle key, String leaf) {
    for (int attempt = 1; ; attempt++) {
      if (attempt > 1 && key.attributes().links(LinkKind.CERTIFICATE).contains(leaf)) break;
      own(leaf);
      wrote = true;
      changed = true;
      try {
        guardedSend(() -> add(key, Attributes.link(Enums.LinkType.CERTIFICATE_LINK, leaf)));
        break;
      } catch (OutcomeUnknownException unknown) {
        if (attempt == 3) throw unknown;
      }
    }
    owned.put(leaf, owned.get(leaf).linkedFrom(key.id()));
  }

  /**
   * Records on the leaf that the name is being moved to it, before the name is taken off the
   * old certificate; a lost reply is read back, and the move does not go on until the record is
   * known to be there. A server that refuses client attributes is passed over: there, a reader
   * that holds no pair finds nothing while the name moves (followers that hold one find the leaf
   * through the links).
   */
  private void pending(String leafId) {
    KeyHandle leaf = keys.handle(leafId);
    // One request: the read before it shows no record there (a KMIP 1.x Modify Attribute, then
    // Add Attribute, would be two changes with no read between them).
    Ttlv record = keys.custom(KeyHandle.pendingName(name), name);
    Runnable request =
        keys.kms().protocolVersion().legacyAttributes()
            ? () -> add(leaf, record)
            : () -> {
              Request set =
                  Request.operation(dev.keytend.kmip.model.Operation.SET_ATTRIBUTE)
                      .uniqueIdentifier(leafId)
                      .attribute(record)
                      .build();
              keys.kms().execute(operation, Kms.Kind.MUTATION, leafId, s -> s.call(set));
            };
    try {
      // The first change of the move where names are unique (the name was refused on the leaf).
      unseen(
          leafId,
          () -> guardedSend(request),
          read -> KeyHandle.pendingNames(read).contains(name),
          false);
    } catch (StateConflictException
        | InvalidRequestException
        | UnsupportedException
        | PermissionDeniedException refused) {
      if (refused == lastRefusal
          || refused == expiredRefusal
          || Failures.credentialsRefused(refused)) throw refused;
    }
  }

  /**
   * Removes {@code name} from {@code h}, one of the identity's own certificates, when it has it; a
   * lost reply is read back.
   */
  private static void removeName(KeyHandle h, String name) {
    if (!h.attributes().names().contains(name)) return;
    settle(() -> h.removeName(name), () -> !h.attributes().names().contains(name));
  }

  /**
   * Removes {@code temporaryName} from {@code id}, an object in {@link #owned}, when it has it: one
   * instance per request, each after a read ({@link #change}).
   */
  private void unname(String id, String temporaryName) {
    change(id, e -> e.unnamed(temporaryName), () -> keys.handle(id).removeOneName(temporaryName));
  }

  /**
   * Deactivates {@code old} as superseded by {@code by}; done once it is out of use, also when
   * another caller revoked or destroyed it meanwhile. A lost reply is read back. {@code send}
   * sends each Revoke ({@link #guardedSend}, or {@code Runnable::run}); its refusal of a leaf that
   * does not outlast the margin stops the call, also when another caller retired {@code old}.
   */
  private void retire(KeyHandle old, String by, java.util.function.Consumer<Runnable> send) {
    java.util.function.BooleanSupplier done =
        () -> {
          KeyState state = old.attributes().state();
          return state != KeyState.ACTIVE
              && state != KeyState.PRE_ACTIVE
              && state != KeyState.UNKNOWN;
        };
    try {
      settle(
          () -> send.accept(() -> old.deactivate(RevocationReason.superseded("replaced by " + by))),
          done);
    } catch (StateConflictException e) {
      if (e == expiredRefusal || !done.getAsBoolean()) throw e;
    }
  }

  private void add(KeyHandle h, Ttlv attribute) {
    Request request = Requests.addAttribute().uniqueIdentifier(h.id()).attribute(attribute).build();
    keys.kms().execute(operation, Kms.Kind.MUTATION, h.id(), s -> s.call(request));
  }

  /**
   * Activates {@code id}, an object in {@link #owned}, unless it is Active already ({@link
   * #change}); a refusal because it is Active is read back by the next check of it.
   */
  private void activate(String id) {
    change(
        id,
        e -> e.in(KeyState.ACTIVE),
        () ->
            guardedSend(
                () -> {
                  try {
                    keys.handle(id).activate();
                  } catch (StateConflictException refused) {
                    if (refused.observedState().orElse(null) != KeyState.ACTIVE) throw refused;
                  }
                }));
  }

  private KeyRegistration certificate(
      X509Certificate c, String temporaryName, Map<CustomAttribute, Object> attributes) {
    // Its usages from its own Key Usage extension, which a KMIP 1.x server may not let a mask
    // exceed.
    KeyRegistration r = keys.register(c).named(temporaryName);
    for (var e : attributes.entrySet()) r.custom(e.getKey(), e.getValue());
    return r;
  }

  /**
   * Registers Pre-Active under {@code temporaryName}, this call's own; a lost reply, or a refusal
   * of a name in use (a resent request that took effect), is settled by looking the name up. An
   * object found that way is taken only as a Register left it ({@link KmsKeys#madeUnder}): the only
   * object with the name, Pre-Active, linked to nothing, with that name alone, and, for a
   * certificate, holding {@code expected}. Otherwise the failure is thrown. The object is then in
   * {@link #owned}, as a Register left it.
   */
  private KeyHandle register(
      KeyRegistration registration,
      String temporaryName,
      ObjectKind objectKind,
      X509Certificate expected) {
    KeyHandle made = registered(registration, temporaryName, objectKind, expected);
    model(
        made.id(),
        TlsOwnership.Expected.registered(objectKind, temporaryName),
        "is this call's object under " + temporaryName);
    return made;
  }

  private KeyHandle registered(
      KeyRegistration registration,
      String temporaryName,
      ObjectKind objectKind,
      X509Certificate expected) {
    wrote = true;
    changed = true;
    try {
      return registration.registerPreActive();
    } catch (PartialCompletionException unread) {
      // Registered, and not read back: the later steps read it.
      return unread.created().get(0);
    } catch (OutcomeUnknownException | AlreadyExistsException unknown) {
      Optional<KeyAttributes> made;
      try {
        made =
            keys.madeUnder(
                    temporaryName,
                    objectKind,
                    a -> expected == null || same(a.id(), expected),
                    unknown)
                .made();
      } catch (KmsException lookup) {
        unknown.addSuppressed(lookup);
        throw unknown;
      }
      if (made.isPresent()) return keys.handle(made.get().id());
      throw unknown;
    }
  }

  /**
   * Makes {@code request}, the change {@code effect} says, to {@code id}, an object in {@link
   * #owned}: only while a read just before it shows the object exactly as {@link #owned} says
   * ({@link #own}), and each of {@code targets}, the objects in {@link #owned} it links to, too. A
   * lost reply is read back the same way: made, it is done; not made, and the object and its
   * targets otherwise as expected, it is sent again (three times at most); otherwise the call
   * stops. Before the change is first sent, the object already changed so is another caller's
   * doing, and stops the call too.
   */
  private void change(
      String id,
      java.util.function.UnaryOperator<TlsOwnership.Expected> effect,
      Runnable request,
      List<String> targets) {
    TlsOwnership.Expected before = owned.get(id), after = effect.apply(before);
    if (after.equals(before)) return;
    for (int attempt = 1; ; attempt++) {
      KeyAttributes a = keys.read(id).orElse(null);
      KmsKeys.Search by = linkedTo(before, id);
      if (attempt > 1 && TlsOwnership.mismatch(after, a, by) == null) {
        owned.put(id, after);
        return;
      }
      TlsOwnership.Mismatch m = TlsOwnership.mismatch(before, a, by);
      if (m != null) throw refusal(id, m);
      for (String t : targets) own(t);
      wrote = true;
      changed = true;
      try {
        request.run();
        owned.put(id, after);
        return;
      } catch (OutcomeUnknownException unknown) {
        if (attempt == 3) throw unknown;
      }
    }
  }

  private void change(
      String id, java.util.function.UnaryOperator<TlsOwnership.Expected> effect, Runnable request) {
    change(id, effect, request, List.of());
  }

  /**
   * Makes {@code request} to {@code id}, an object in {@link #owned}, a change of an attribute the
   * predicate does not compare (the record of the name being moved), unless a read shows it made
   * ({@code done}): each request only while the read just before it, and the objects linked to
   * it, show the object as expected. A request whose reply is lost is sent again when a read shows
   * it not done; with {@code untilDone}, so is one that succeeded (a removal of one instance, when
   * there are more). Three requests at most.
   */
  private void unseen(
      String id,
      Runnable request,
      java.util.function.Predicate<KeyAttributes> done,
      boolean untilDone) {
    TlsOwnership.Expected e = owned.get(id);
    for (int sent = 0; sent < 3; sent++) {
      KeyAttributes a = keys.read(id).orElse(null);
      if (a != null && done.test(a)) return;
      TlsOwnership.Mismatch m = TlsOwnership.mismatch(e, a, linkedTo(e, id));
      if (m != null) throw refusal(id, m);
      wrote = true;
      changed = true;
      try {
        request.run();
        if (!untilDone) return;
      } catch (OutcomeUnknownException unknown) {
        if (sent == 2) throw unknown;
      }
    }
  }

  /** The refusal of a change to {@code id}, which is not as {@link #owned} says ({@code m}). */
  private StateConflictException refusal(String id, TlsOwnership.Mismatch m) {
    String advice =
        finishing
            ? switchMade()
                + ". To finish by hand, once you have checked that no other identity uses "
                + id
                + ": "
                + (activated
                    ? ""
                    : (kind.keepsKey()
                            ? "link the private key to "
                                + leafId
                                + " (Certificate link) if it is not, "
                            : "")
                        + "activate the Pre-Active private key and certificates of "
                        + leafId
                        + "'s chain, then "
                        + leafId
                        + "; ")
                + (named
                    ? ""
                    : "take the name "
                        + name
                        + " off the certificates "
                        + leafId
                        + " replaced and give it to "
                        + leafId
                        + "; ")
                + (retired
                    ? ""
                    : "deactivate the certificates it replaced (and their keys, after a re-key). ")
                + "Or undo the change, then repeat"
            : "Nothing of the identity "
                + name
                + " changed: repeat, and the repeat starts over under a new temporary name."
                + leftovers();
    StateConflictException e =
        new StateConflictException(
                operation
                    + ": "
                    + id
                    + " "
                    + foundAs.getOrDefault(id, "is this call's object")
                    + ", but "
                    + m.why()
                    + ": another caller changed it. This call changes such an object only while a"
                    + " read just before shows it as this call left it, and stops at the first that"
                    + " is not; "
                    + (wrote ? "it changed nothing after that" : "nothing was changed")
                    + ". "
                    + advice,
                null,
                operation,
                id,
                null,
                null)
            .because(m.conflict());
    if (m.observed() != null) e.observed(m.observed());
    return lastRefusal = e;
  }

  /** What the switch made, once it is made. */
  private String switchMade() {
    if (activated) return "The identity " + name + " presents " + leafId + " already";
    return (kind.first()
            ? leafId + " has the name " + name
            : replaced + " names " + leafId + " as its replacement")
        + " (the switch is made), and readers present "
        + leafId
        + " once it is Active";
  }

  /** Puts {@code id} in {@link #owned} as {@code expected}; {@code how} it was found, for a refusal. */
  private void model(String id, TlsOwnership.Expected expected, String how) {
    owned.put(id, expected);
    foundAs.putIfAbsent(id, how);
  }

  /**
   * The ownership predicate: reads {@code id}, an object in {@link #owned}, now, and the objects
   * linked to it, and stops unless it is exactly as {@link #owned} says.
   */
  private KeyAttributes own(String id) {
    TlsOwnership.Expected e = owned.get(id);
    KeyAttributes a = keys.read(id).orElse(null);
    TlsOwnership.Mismatch m = TlsOwnership.mismatch(e, a, linkedTo(e, id));
    if (m != null) throw refusal(id, m);
    return a;
  }

  /** The objects with a link of the kind {@link TlsOwnership#toIt} compares to {@code id}. */
  private KmsKeys.Search linkedTo(TlsOwnership.Expected e, String id) {
    return keys.linkedTo(TlsOwnership.toIt(e.kind()), id);
  }

  /** Whether {@code id} holds {@code certificate} (one Get). */
  private boolean same(String id, X509Certificate certificate) {
    try {
      return Arrays.equals(
          encoded(TlsIdentities.certificate(keys.kms(), id)), encoded(certificate));
    } catch (NotFoundException | StateConflictException gone) {
      return false;
    }
  }

  private static byte[] encoded(X509Certificate c) {
    try {
      return c.getEncoded();
    } catch (java.security.cert.CertificateEncodingException e) {
      throw new IllegalArgumentException("A certificate that cannot be encoded", e);
    }
  }

  /**
   * Runs the steps that change the server; a failure of one is a {@link PartialCompletionException}
   * whose advice is to repeat the call: before the switch, the repeat starts over, and this call's
   * objects are left over, none activated by it ({@link #leftovers}); after it, the repeat finishes
   * the activation, the name and the retirement; when the switch's outcome is unknown, the repeat
   * does one or the other. A lost race ({@link StateConflictException} from {@link #lostRace}), a
   * refused registration name, a refused issued certificate, the refusal to go on with a switch to
   * an issued leaf that expired ({@link #unexpired}), and a failure before anything was registered
   * are thrown as they are. So is a refusal by the ownership predicate ({@link #own}) before this
   * call changed anything; after, it is the cause of a {@link PartialCompletionException} whose
   * advice is that refusal's.
   */
  private TlsIdentityHandle guarded(java.util.function.Supplier<TlsIdentityHandle> steps) {
    try {
      return steps.get();
    } catch (PartialCompletionException e) {
      throw e;
    } catch (KmsException | IllegalStateException e) {
      if (e == lastRefusal && !wrote) throw e;
      if (!changed || e == lost || e == nameRefused || e == issuedRefused || e == expiredRefusal)
        throw e;
      String what = kind.sameArguments();
      String until =
          " until then the identity's readers present "
              + (kind.first() ? "nothing" : "the old pair")
              + ".";
      String advice =
          e == lastRefusal
              ? "do as that says"
              : finishing
                  ? "repeat "
                      + operation
                      + "(...) with "
                      + what
                      + ": "
                      + switchMade()
                      + ", and the repeat "
                      + (activated ? "" : "activates it, ")
                      + "moves the name to it and deactivates what it replaced"
                  : switchSent
                      ? "repeat "
                          + operation
                          + "(...) with "
                          + what
                          + ": the switch ("
                          + (kind.first()
                              ? "the name on " + leafId
                              : replaced + "'s Replacement Object link to " + leafId)
                          + ") was sent and may have been made; the repeat finishes with "
                          + leafId
                          + " if it was, and starts over under a new temporary name if not;"
                          + until
                          + " This call's objects "
                          + ids(created)
                          + " are left over if the switch was not made: before the switch "
                          + activatedBefore()
                      : "repeat "
                          + operation
                          + "(...) with "
                          + what
                          + ": it starts over under a new temporary name;"
                          + until
                          + leftovers();
      throw created.isEmpty()
          ? PartialCompletionException.interrupted(operation, step, advice, e)
          : PartialCompletionException.of(operation, List.copyOf(created), null, step, advice, e);
    }
  }

  @Override
  public String toString() {
    return "TlsIssue[" + operation + " " + Objects.requireNonNull(name) + "]";
  }
}
