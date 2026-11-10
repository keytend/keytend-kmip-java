<!--
Copyright 2026 Jeremiah Jordan

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# TLS identities

A node's TLS identity is its private key and certificate chain. With `kms.tls()` the identity can
live in the KMS, together with the trust anchors and the certificates allowed to connect. The
node's key manager and trust manager follow them. A renewal is presented, and a revocation
refused, at the next refresh, with no restart.

This page is about the identities your nodes present to each other. The SDK's own connection to
the KMS uses the client credentials of `KmsConfig`. To reload those, see
[Reload client credentials](production.md#reload-client-credentials); to have the KMS renew them,
see [Renew the client certificate](production.md#renew-the-client-certificate). The rules behind
each step
are in the `KmsTls`, `TlsIdentityFollower` and `TlsTrustFollower` Javadoc and in
[the design notes](kms-design.md).

- [Issue an identity](#issue-an-identity)
- [Issue from the KMS](#issue-from-the-kms)
  - [Register the issuer](#register-the-issuer)
  - [Issue](#issue)
  - [Reissue](#reissue)
  - [The safety margin](#the-safety-margin)
  - [Validity](#validity)
  - [Servers that issue](#servers-that-issue)
  - [Credentials for issuing](#credentials-for-issuing)
- [Follow it on the node](#follow-it-on-the-node)
- [Leases](#leases)
- [How long TLS material stays usable](#how-long-tls-material-stays-usable)
- [Renew and re-key](#renew-and-re-key)
  - [When a repeat is refused](#when-a-repeat-is-refused)
  - [What a stopped call leaves](#what-a-stopped-call-leaves)
- [Revoke](#revoke)
- [Recover](#recover)
- [Peers that have just renewed](#peers-that-have-just-renewed)
  - [Rate limits and mass renewals](#rate-limits-and-mass-renewals)
- [Checks after the handshake](#checks-after-the-handshake)
- [Credentials](#credentials)

The examples use these inputs:

- `nodeKey` is the node's `PrivateKey`, and `nodeLeaf` its `X509Certificate`.
- `issuingCa` is the issuing CA's certificate, and `rootCa` the root CA's.
- `renewedLeaf`, `newKey`, `newLeaf`, `freshKey` and `freshLeaf` are the later keys and
  certificates of the same node.
- `TLS_ROLE` is a constant, `CustomAttribute.client("tls-role")`.
- `scheduler` is a `ScheduledExecutorService` you own, and `log` is your logger.

## Issue an identity

Register the key and its chain, the leaf first, under the identity's name. Only the leaf gets the
name. The key and the issuers are linked to it. A custom attribute on the leaf lets an allowlist
find it.

```java
TlsIdentityHandle node = kms.tls().register(nodeKey, nodeLeaf, issuingCa)
    .named("cassandra/node1").custom(TLS_ROLE, "cluster1:identity").register();
KeyHandle root = kms.keys().register(rootCa).custom(TLS_ROLE, "cluster1:ca").register();
```

The key and the chain are registered Pre-Active and linked. The leaf then gets the name, and they
are activated, the leaf last. Until the leaf has the name, no reader finds the identity. Until the
leaf is activated, `follow()` finds nothing to present (`StateConflictException`). If `register()`
stops, repeat it with the same key and chain. Before the name, the repeat starts over, and what the
stopped call registered is left over ([What a stopped call leaves](#what-a-stopped-call-leaves)).
After it, the repeat activates the pair and returns it.

To have the KMS create the key pair and sign the certificate instead, see
[Issue from the KMS](#issue-from-the-kms).

## Issue from the KMS

The KMS can also make the identity: it creates the key pair, and a CA it holds signs the
certificate, through KMIP Certify. The identity is then followed, revoked and recovered like a
registered one. The examples use `caKey` and `caCertificate`, your issuing CA's private key and
certificate, and `nextCa`, a second issuer.

### Register the issuer

Put the issuing CA in the KMS once, under a name:

```java
TlsIssuer ca = kms.tls().registerIssuer(caKey, caCertificate)   // then its issuers, if any
    .named("cluster1/issuing-ca").custom(TLS_ROLE, "cluster1:ca").register();
TlsIssuer same = kms.tls().issuer("cluster1/issuing-ca").orElseThrow();   // elsewhere, later
```

- The CA certificate must be a CA certificate: basicConstraints cA=TRUE, and keyCertSign when it
  has a Key Usage extension.
- The objects are linked the way Certify finds the signing key. The CA certificate links to the CA
  public key (Public Key link), which links to the CA private key (Private Key link). The private
  key links back to both.
- The private key gets the usages Sign and Certificate Sign, and the public key Verify.
- Only the CA certificate gets the name. The objects are registered Pre-Active and activated after
  the name, as `register()` does. A stopped call is repeated the same way.
- A custom attribute on the CA certificate lets the anchors query of `trustAnchors` find it.

### Issue

```java
TlsIdentityHandle node = kms.tls().issue("cassandra/node1")
    .keyPair(KeyPairSpec.ec(Curve.P_256))      // the default; RSA of 2048 bits or more, or EC
    .subject("CN=node1,O=cluster1")
    .dnsNames("node1.cluster1.internal")
    .ipAddresses("10.0.0.11")                  // also uris(...) and emails(...)
    .issuedBy(ca)
    .custom(TLS_ROLE, "cluster1:identity")
    .issue();
```

1. The KMS creates the key pair (Create Key Pair), Pre-Active, under the call's temporary names.
2. The call activates the new private key, because KMIP lets no Pre-Active key be used, and
   servers lease no Pre-Active object. No certificate certifies the key yet, and nothing of the
   identity links to it. The call then retrieves it, signs a PKCS#10 request with it locally, and
   wipes the copy. Where the key states a Lease Time, the call obtains a lease first. RSA keys
   sign with SHA-256 and PKCS#1 v1.5, EC keys with ECDSA and SHA-256.
3. Certify: the KMS issues the certificate for the new public key. The certificate is Pre-Active,
   under the temporary name, with the custom attributes and a Certificate link to the issuer's
   certificate.
4. The call checks the certificate before it uses it:
   - It is for the new public key, with exactly the subject and subject alternative names asked.
   - It is issued by the issuer's certificate, and its chain verifies as `register()` checks a
     chain: each certificate is issued and signed by the next. Without `issuedBy`, the chain is
     what the leaf's Certificate links lead to.
   - It is not a CA certificate.
   - A node can present it at both ends of a TLS connection, since a node presents its identity
     when it accepts a connection and when it makes one. A Key Usage extension must have
     digitalSignature, for RSA and EC keys alike: TLS 1.3 signs the handshake with the key, and so
     does TLS 1.2 for client authentication and ECDHE. So a certificate with only keyEncipherment
     or only keyAgreement is refused. An Extended Key Usage extension must have both serverAuth
     and clientAuth, or anyExtendedKeyUsage. Without these extensions nothing is restricted.
     keytend-kmip-server and `InMemoryKmipServer` issue digitalSignature and no Extended Key Usage.
   - It is valid now, by the `Kms`'s clock after Certify and the reads, and ends at the validity
     asked ([Validity](#validity)). Just before the switch is sent, the call checks again that it
     outlasts the [safety margin](#the-safety-margin), so a slow server never leaves an expired
     certificate in place of one that works.
   - The certificate object is still Pre-Active: a server that activates it at Certify is refused
     too.

   Otherwise the call stops with `KeyMismatchException`, or `UnsupportedException` for the
   validity. Nothing of the identity changed, and the message lists the call's objects, which are
   left over.
5. Then the steps of `register()`: the objects are linked, the leaf gets the name, and they are
   activated, the leaf last.

Give a subject, subject alternative names, or both. The identity's chain is the leaf and the
issuer's chain. Its public key object stays linked to the key and the leaf, because a same-key
reissue certifies it again.

If `issue()` stops, repeat it with the same arguments. Before the name, the repeat starts over,
and the stopped call's key pair, and its certificate if Certify ran, are left over
([What a stopped call leaves](#what-a-stopped-call-leaves)). Its private key is Active once the
call has activated it to sign. After the name, the repeat activates the objects. It does so only
when the leaf has the subject, names, issuer and key type asked, and its chain verifies. A repeat
after success returns the identity. An `issue()` that asks for something else under a name in use
is refused with `AlreadyExistsException`.

### Reissue

```java
node = node.reissue();                                   // same key, new certificate
node = node.reissueWithNewKey();                         // new key pair, new certificate
node = node.reissueIfExpiresWithin(Duration.ofDays(10)); // the scheduled job
node = node.reissue(TlsReissue.newKey(KeyPairSpec.ec(Curve.P_384))
    .validFor(Duration.ofDays(30)).issuedBy(nextCa));
```

- A reissue asks for the subject and subject alternative names of the certificate it replaces. The
  new leaf gets the old one's custom attributes. The issuer is the CA certificate the old leaf
  links to, unless `issuedBy` names another.
- `reissue()` keeps the key. It retrieves the private key to sign the request, as `renew` does for
  its pair check: the key must be Active, permit SIGN and have no Usage Limits, with a lease where
  it states a Lease Time. It certifies the public key object linked to the key. An identity
  registered with `register()` has none, so reissue it with a new key, naming the issuer.
- `reissueWithNewKey()` creates a key pair of the current key's algorithm and size, unless
  `TlsReissue.newKey(spec)` gives another.
- Then the steps of `renew` (same key) or `rekey` (new key) follow: the switch, the activation, the
  name, and the old certificate deactivated. A new key also deactivates the old key and its public
  key object.
- Stops, repeats, lost races and refused repeats work as for `renew` and `rekey`
  ([Renew and re-key](#renew-and-re-key)). Repeat on the same handle with the same options.
- Each step after Certify is a request of its own, and a slow reply can outlast a short
  certificate. Just before it sends the switch, the kept key's link to the new certificate, each
  activation, the first change of the name's move and each deactivation of a certificate it
  replaces, the call checks that the issued certificate outlasts the
  [safety margin](#the-safety-margin) by the `Kms`'s clock:
  - Not before the switch: `KeyMismatchException`, and nothing of the identity changed. The
    message says the certificate is too short-lived to use safely: ask for a longer validity
    (`validFor`), or call through a `Kms` with a shorter call timeout.
  - Not after the switch: `StateConflictException`. The call activates nothing more and
    deactivates nothing, so the certificate it replaces stays Active. While the new certificate
    is not Active, the identity keeps its name and presents the old one. The message says how to
    undo the switch, or, when the new certificate was activated, how to present the old one
    again.
  - A repeat that finds the switch made to a certificate that no longer outlasts the margin stops
    the same way. An issue has nothing to deactivate; it stops before it activates its
    certificate.
  - The advice follows what the certificate it replaces is now. When that one is no longer
    Active, undoing the switch would leave nothing that works, so the message says to reissue
    the identity. That includes a repeat of a call that finished: the message says that it
    finished and that its certificate has expired, or is within the margin, since. A certificate
    the server answers Not Found for, as a server that drops destroyed objects does, counts as
    not Active, and the message says it no longer exists.
- `reissueIfExpiresWithin` reads the certificate and reissues it only when it ends within the
  window, by the `Kms`'s clock. Otherwise it returns the same handle.

The SDK does not use KMIP Re-certify. Re-certify moves the name and sets the Replacement links on
the server, in one step around the switch. That switch is what makes a stopped or repeated call
safe.

### The safety margin

An issue or reissue sends each change of the identity from the switch on only while the issued
certificate is valid for more than a safety margin, by the `Kms`'s clock. The margin is five
minutes plus twice the call timeout of the `Kms` the call runs on: `callTimeout`, or the timeout
of a `withTimeout` view the call goes through.

- The call checks just before each request goes out, after the `KmsListener.started` callbacks,
  so a slow listener cannot carry the certificate past the check. A change sent again after a
  lost reply is checked again before it goes out.
- Some time always remains between that check and the server's processing: the client takes a
  connection, waiting for a pooled one when all are busy, sends, and waits. All the requests of
  a call share one deadline, the call timeout, so however many are left, the client waits at
  most one call timeout for the reply. A request still waiting for a connection at the deadline
  is not sent.
- The second call timeout allows for a server that processes a request after the client stopped
  waiting for it, queued or answered late.
- The five minutes are the clock difference the SDK allows between machines for an issued
  certificate's dates. They keep a certificate that a peer with a clock slightly ahead already
  sees as expired from being put in use.

So an issued certificate must live longer than the margin. A `validFor` shorter than ten minutes
plus three times the call timeout (the margin, the call itself, and a notAfter up to five minutes
before the date asked) is refused with `InvalidRequestException` before anything is sent: 11
minutes 30 seconds with the default 30-second call timeout, 40 minutes through a 10-minute view.
Without `validFor`, a certificate the server issues too short to outlast the margin at the
switch is refused there. Issue it for longer, or call through a `Kms` with a shorter call
timeout.

### Validity

`validFor` asks for the certificate's validity from now. The call sends it as the certificate's
Deactivation Date, and checks that the certificate's notAfter is that date, give or take 5
minutes. Without `validFor`, the server's own validity applies. The shortest validity a call asks
for follows its call timeout ([The safety margin](#the-safety-margin)).

The call sends no Activation Date. A date at or before now would make the certificate Active at
Certify, before the switch.

keytend-kmip-server takes the dates as the validity. With only a Deactivation
Date, it issues from now to that date and keeps the certificate Pre-Active until the call's
switch activates it. It refuses a date after the issuing CA's notAfter with Invalid Field and
never cuts it short.

- When the issuer is in the KMS (`issuedBy`), the call refuses a validity that would end after the
  issuing CA's notAfter itself, with `InvalidRequestException`, before it changes anything. Ask
  for a shorter validity, or reissue the CA first.
- A server's Invalid Field refusal of Certify with a validity asked stops the call with
  `InvalidRequestException` rather than `PartialCompletionException`. The date is the likely
  cause, but the server also answers Invalid Field for other faults of the request, so the
  message names the date as the likely cause and keeps the server's message. It says what to do
  and lists the objects the call left over. Repeating with the same validity is refused again
  when the date was the cause.
- Earlier keytend-kmip-server builds ignore the dates. They issue for 365 days, capped at the CA's
  notAfter. Against them, an issue or reissue with `validFor` fails with `UnsupportedException`,
  rather than present a certificate that lives longer than you asked. Leave `validFor` out there.

### Servers that issue

| Server | Issue from the KMS |
|---|---|
| keytend-kmip-server | Yes, with an issuer you register (`issuedBy`). The issuing credentials must own the CA certificate and both CA keys: grants do not count. It honors `validFor` up to the CA's notAfter ([Validity](#validity)). |
| PQCToday | Only with the CA configured inside the server. Leave out `issuedBy`, which is the mode for such servers. |
| PyKMIP | No: Certify is not implemented. |
| `InMemoryKmipServer` | Yes, with an issuer you register. It honors `validFor` as keytend-kmip-server does; `certifyHonorsDates(false)` ignores it as earlier builds do ([In-memory test server](in-memory-server.md#certify)). |

A server that refuses Certify stops the call with `PartialCompletionException`. Its cause is the
server's refusal, and the key pair the call created is left over.

### Credentials for issuing

The job that issues needs Create Key Pair and Certify, besides what registration needs. On
keytend-kmip-server it must also own the issuer's objects, so register the issuer with the same
credentials. Nodes still need only reads. The full list is in
[What each consumer's credential needs](production.md#what-each-consumers-credential-needs).

## Follow it on the node

The identity follower reads the identity once now, then every interval on your executor. Its key
manager presents the pair read last at each handshake, from memory. The trust follower does the
same for the anchors and the allowed peers.

```java
TlsIdentityFollower identity =
    kms.tls().follow("cassandra/node1", Duration.ofSeconds(60), scheduler);
TlsTrustFollower trust = kms.tls().trustAnchors(
    KeyQuery.all().custom(TLS_ROLE, "cluster1:ca"),         // the anchors
    KeyQuery.all().custom(TLS_ROLE, "cluster1:identity"),   // who may connect
    Duration.ofSeconds(60), scheduler);
SSLContext ssl = SSLContext.getInstance("TLS");
ssl.init(new KeyManager[] {identity.keyManager()},
    new TrustManager[] {trust.trustManager()}, null);
identity.onChange(state -> log.info("TLS identity {}", state));
```

- `follow` fails when there is no pair to present, such as no certificate with the name or a
  revoked identity. It also fails when the KMS cannot be read. The node then has no identity to
  start with.
- While the KMS is unreachable later, the last pair stays and `status()` is `STALE`. On a server
  that sets a Lease Time, it stays only until a lease runs out ([Leases](#leases)).
- Once a refresh reads the certificate or its key as not Active, the follower presents nothing.
  A renewal or re-key that finishes while a refresh reads deactivates what the refresh read: the
  refresh then reads again and presents the new pair.
- A renewal whose new certificate cannot be loaded presents nothing until the next successful
  refresh.
- Close both followers at shutdown. `close()` cancels their tasks, not your executor.

## Leases

A KMS may give the identity's objects, the anchors or the allowed peers a KMIP Lease Time.
keytend-kmip-server gives every object 3600 s by default. Then, under the default lease policy,
`LeasePolicy.REQUIRE`, the followers:

- obtain a lease for each object at every refresh (Obtain Lease);
- renew it before it ends, sooner than the interval when the lease is shorter;
- use an object only while its lease runs, checked at each handshake from memory.

`LeasePolicy.HONOR_IF_SUPPORTED` changes this only on a server that does not implement Obtain
Lease. There the followers use an object's stated Lease Time as the bound instead
([Local keys](local-keys.md#servers-that-do-not-implement-obtain-lease)).

So the last pair survives a KMS outage only until its lease ends. After that the node presents
nothing, and refuses peers whose anchor's or own lease ended, until the KMS answers again. A lease
the server refuses stops that object at once. Size the Lease Time on the server for the outages
you must ride through. Servers that set no Lease Time are asked for no lease.

## How long TLS material stays usable

On a leasing server, a KMS outage becomes a TLS outage on each node as its leases end. Export
`usableFor()` of both followers as metrics to see it coming:

```java
Optional<Duration> left = identity.usableFor();   // empty: no lease limits it
long seconds = left.map(Duration::toSeconds).orElse(Long.MAX_VALUE);
```

`usableFor()` is how long what is presented or trusted now stays usable without another
successful refresh. It is read from memory, with no request.

- **Empty**: no lease bounds it.
- **`Duration.ZERO`**: nothing is usable now, and handshakes fail.
- **Otherwise**: the time to the earliest lease end.

While refreshes succeed, the figure stays near the full Lease Time. While the KMS cannot be read,
it falls. Alarm when it falls below the time you need to restore the KMS, for example a quarter of
the Lease Time, and page before it reaches zero. Meanwhile `identity.status()` is `STALE` and
`trust.failure()` holds the refresh's failure. `LocalKeys.usableFor()` is the same figure for raw
keys. It is never empty, because its TTL always bounds it.

`KmsListener.keyStateChanged(id, from, to)` hears of each state change a refresh reads of the
identity's certificate and private key. Examples are a revocation, a compromise, or the old
certificate a renewal deactivated. So an alert needs no polling.

## Renew and re-key

A renewal keeps the key and issues a new certificate. A re-key replaces both. Run them from the
place that issues certificates, one at a time per identity:

```java
node = kms.tls().identity("cassandra/node1").orElseThrow().renew(renewedLeaf, issuingCa);
node = node.rekey(newKey, newLeaf, issuingCa);
```

Each call registers the new objects Pre-Active under a temporary name that only it uses, and links
them. One request then makes them the identity's. That request is the switch. It gives the old
certificate a Replacement link to the new one. The call then activates the new key and issuers,
and the new leaf last. Readers present the old pair until that Activate and the new pair from it.
They never see a certificate without its key, and never find no identity while the name moves.
The old certificate is then deactivated, not destroyed. A re-key also deactivates the old key.

- If a call stops (`PartialCompletionException`, or an unknown outcome), repeat it with the same
  arguments. Before the switch, the repeat starts over and leaves the stopped call's objects as
  they are ([What a stopped call leaves](#what-a-stopped-call-leaves)). After it, the repeat
  activates the new pair, moves the name and deactivates the old certificate. When the call cannot
  tell whether its switch was made, the repeat does whichever is needed.
- If a renewal or re-key lost a race, repeat it from `kms.tls().identity(name)`.
- A renewal retrieves the identity's private key from the KMS and signs with it locally, to check
  that the new certificate is for that key. The key must be Active, permit SIGN, and have no
  Usage Limits.
- When that key states a Lease Time, the renewal obtains a lease first. A refused lease stops the
  renewal before anything is registered.

### When a repeat is refused

A refusal is a `StateConflictException`. Its message names the objects involved, and says whether
to finish the stopped call or undo its switch, and how. Do what it says. These are the cases:

- A repeat finds the switch made with a different chain or key from the one it was given. Nothing is
  changed. To present another chain, finish with the first one, then renew with a new certificate.
- The identity's certificate already links to a newer one that is not Active yet. Another call is
  under way, or one stopped after its switch. Wait for it, or repeat it with its arguments.
- A repeat of a renewal finds the kept key no longer Active, so it cannot finish. The message says
  how to undo the switch and which new issuers to revoke. Then re-key.
- Another caller changed one of the call's objects. The call stops at the first object it finds
  changed (`objectId()`) and changes nothing more
  ([Objects another caller changed](#objects-another-caller-changed)). If it had changed something
  already, the refusal is the cause of a `PartialCompletionException`. Before the switch, repeat.
  After it, the message says how to finish by hand, or to undo the other caller's change and
  repeat.

To undo a switch, take the old certificate's Replacement Object link to the new leaf off, or for a
registration, the name off the new leaf. Then repeat with the chain you want. The repeat starts
over, and the stopped call's objects are left over. How a refusal decides which to offer is in
[the design notes](kms-design.md#tls-identities).

### What a stopped call leaves

A call that stops after its switch leaves the new objects as the identity's. Some of them may be
Active, and a repeat finishes them.

A call that stops before its switch, or whose switch is undone, leaves the objects it registered.
No repeat reads or changes them. They are Pre-Active, nothing of the identity links to them, and
their only name is a temporary one (`NAME.issuing-` and a random part), or none if the call
stopped just before its switch. While they stay Pre-Active, no trust follower uses them, no
identity follower finds them, and a leftover private key cannot be used. A leftover private key
from a registration or a re-key is a copy of the key you gave. When that key is compromised,
destroy its leftover copies as well.

An issue or new-key reissue leaves the key pair the KMS created and, once Certify ran, the
certificate the CA signed for it. They are Pre-Active, except the private key once the call has
activated it to sign the certificate request. Deactivate such a key before you destroy it. No
reader presents it, because no Active certificate certifies it and nothing of the identity links
to it. A same-key reissue leaves, once Certify ran, the Pre-Active certificate the CA signed for the
identity's key. Certify itself links the identity's public key object to it (a Certificate link,
as it links a public key to each certificate it issues for it). No reader follows that link, and
later calls on the identity work with it in place. The certificate stays valid in X.509 terms until
it ends, whatever its state in the KMS. So with an issuing CA in the KMS, accept peers through an allowlist
(`trustAnchors` with allowed peers), which takes only Active certificates.

#### Objects another caller changed

An object of the call that another caller activated, named or linked to, before or after the call
stopped, is left as that caller left it. If it is an Active certificate a trust query matches, the
trust follower uses it. A leftover leaf has the custom attributes the call gave the new leaf, so
an allowed-peers query can match it. An Active private key among them can be used.

An undo that a refusal offers after finding such an object leaves that object as it is. It also
leaves the new issuers above it in the chain as they are, all of them when the object is the new
key. The call may have activated those issuers before it stopped, so they can be Active.
The refusal names that object with its state. Neither a repeat nor an undo revokes these objects,
or takes off the other caller's names or links.

#### Find and clean up leftovers

The exception lists the objects (`PartialCompletionException.created()`, and the messages of a lost
race or a refused name). A process that stopped has no exception. To find its leftovers, list the
certificates (`kms.tls().certificates(KeyQuery.all())`) and keep those whose DER encoding equals a
certificate you gave. One whose identifier is not in the identity's chain
(`kms.tls().identity(name)`, then `chain()`) is a leftover, or another caller's. A renewal's or
re-key's leftover leaf has a Replaced Object link to the identity's certificate, which does not link
back to it. The leaf's Private Key and Certificate links lead to the rest. Listing only the
Pre-Active certificates misses leftovers that are now Active.

Read each object's state, names and links before you change it. A name or link the call does not
give means another caller uses the object, so leave it to that caller. Do not activate a
leftover. Once you have checked that nothing uses a leftover, destroy it with
`kms.keys().handle(id).destroy()`. Servers refuse to destroy an Active object, so deactivate an
Active leftover first, such as an issuer an undo left (`kms.keys().handle(id).deactivate()`). A
Pre-Active object, or an issuer you revoked when undoing a renewal, can be destroyed as it is.

## Revoke

For a key compromise, the certificate and the key become Compromised. For another reason, the
certificate is deactivated and the key kept. Followers stop presenting it at their next refresh.
A peer presenting it is refused once the other side's trust follower refreshes.

```java
node.revoke(RevocationReason.keyCompromise("node1 disk stolen", Instant.now()));
```

## Recover

Re-key the revoked identity under its name. This links the old certificate to the new one. It
works on servers that keep names on revoked objects, including those that allow a name only once.

```java
node = kms.tls().identity("cassandra/node1").orElseThrow().rekey(freshKey, freshLeaf, issuingCa);
```

- A certificate revoked for a reason other than a compromise keeps its key, which `renew` reuses.
- A destroyed identity cannot be re-keyed. Register a new one instead.
- Whether a destroyed identity's name is free again depends on the server. With
  keytend-kmip-server's default (`--destroyed-name-reuse allow`), `register` under the same name
  succeeds. With `reserve`, `register` throws `AlreadyExistsException`, so use another name. The
  objects the call registered are left over, and the message lists them
  ([What a stopped call leaves](#what-a-stopped-call-leaves)).

## Peers that have just renewed

With an allowlist, a peer that has just renewed presents a certificate the trust follower has not
read yet. Such a certificate chains to the anchors but is not allowed yet. The trust manager
refuses it at once and asks the KMS about it on the follower's executor. Once that check finds an
Active certificate the allowlist matches, the peer's next handshake is accepted.

- Peers that reconnect by themselves, as Cassandra's internode connections and drivers do, need
  nothing more.
- Query the allowlist by a custom attribute. Renewals copy it to the new certificate.
- Until the renewed node's own follower refreshes, it still presents its old certificate. Peers
  refuse that once they read it as deactivated. Where a node renews itself, call its follower's
  `refresh()` right after, and let clients retry the connection.
- The check never runs on the handshake's thread, so an event loop never waits for the KMS. Give
  the followers an executor with a thread to spare, so that checks against a slow KMS cannot
  delay a refresh that renews a lease.
- `trust.unknownPeerCheck(Duration)` bounds how long the check waits for the KMS: 2 seconds by
  default. `Duration.ZERO` turns the check off, and such a peer is refused until the next refresh.
- `trust.unknownPeerCheckInHandshake(true)` makes the handshake wait for the check, at most its
  timeout, and accept the peer in that handshake. Use it only where handshakes run on threads
  that may block.

### Rate limits and mass renewals

Each trust follower limits its checks of unknown peers. By default, a certificate is checked at most
once per 30 seconds. No check begins within 1 second of the end of the last one. Also, at most 64
checks wait in its queue. A queued check that has waited longer than its timeout is dropped. The
limits bound how often a follower asks the KMS, not how many peers it admits. Each check re-reads
every allowed peer, as a refresh does, so one check admits every peer renewed before it, not only
the one whose handshake asked.

After a mass renewal, say 100 nodes in one window, the first renewed peer to connect makes the
check. Every peer renewed by then is accepted at its next connection. A peer renewed after the
last check and refused within the 1-second gap is accepted at a reconnection after the gap, or at
the next refresh. Renewals need no staggering for the check's sake. Each renewed node's own follower
still has to refresh, so keep the refresh interval short, or call `refresh()` right after a node
renews itself.

With the defaults, certificates that chain to your CA cost the KMS at most about one check a second
per follower. Change the limits on the follower:

```java
trust.unknownPeerCheckPerCertificate(Duration.ofSeconds(10))   // default 30 seconds
    .unknownPeerCheckGap(Duration.ofMillis(250))               // default 1 second
    .unknownPeerCheckQueue(16);                                // default 64
```

- A shorter gap admits peers renewed one after another sooner, at the cost of more reads.
  `Duration.ZERO` lifts a limit; checks still run one at a time.
- A smaller queue keeps a shared executor freer. A handshake that finds the queue full is
  refused without a check.

## Checks after the handshake

- A check that runs after the handshake, such as a certificate validator of a mutual-TLS
  authenticator, asks `trust.allows(peerChain)`. It answers from memory whether the chain
  validates against the anchors in use and its leaf is an allowed peer, with their leases. It
  never asks the KMS, so a certificate the follower has not read yet is not allowed.
- Session resumption skips the authentication of a new handshake. Where a revocation must end
  sessions too, bound their lifetime with `ssl.getServerSessionContext().setSessionTimeout(...)`.

## Credentials

A node's followers need only reads (Discover Versions, Locate, Get Attributes, Get, Obtain Lease).
The place that issues identities needs more, and issuing from the KMS also needs Create Key Pair
and Certify ([Credentials for issuing](#credentials-for-issuing)). The full list per consumer is in
[What each consumer's credential needs](production.md#what-each-consumers-credential-needs).
The TLS private key must be readable for the node to present it, so keep its access narrow.
