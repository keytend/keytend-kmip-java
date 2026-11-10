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

# Design notes

These notes record why the application API (`dev.keytend.kmip.kms`) behaves as
it does. Each section starts with the decision and its reason, then the
details. For tasks, read the guides in the [docs index](index.md). For the
contract of each type and method, read the Javadoc. The byte formats are in
[Stored formats](stored-formats.md).

- [Goals and scope](#goals-and-scope)
- [Version normalization](#version-normalization)
- [Errors](#errors)
- [Names, lookup, findOrCreate and duplicates](#names-lookup-findorcreate-and-duplicates)
- [Lineage and rotation](#lineage-and-rotation)
- [Compromised keys](#compromised-keys)
- [Retiring keys](#retiring-keys)
- [Ownership](#ownership)
- [Retries and failover](#retries-and-failover)
- [Secrets](#secrets)
- [The LocalKeys cache](#the-localkeys-cache)
- [Security trade-offs](#security-trade-offs)
- [TLS identities](#tls-identities)

## Goals and scope

The application API sits on the protocol layer, in the same JAR, on the Java 17
API. Its one external runtime dependency is slf4j-api; Caffeine is bundled
([Dependencies](dependencies.md)). Applications see JCA types, typed records and
one exception hierarchy, never TTLV, batches or KMIP templates.

- The same code runs at every negotiated version: 1.2, 1.4, 2.0, 2.1, and 3.0
  where the feature exists.
- Split Key, PKCS#11, Log, Interop, user and group management, and Process stay
  in the protocol layer.
- `kms.protocol()` is the way down to the protocol layer
  ([Protocol layer](protocol-layer.md)).

## Version normalization

The SDK builds every request in the portable KMIP 1.x form and lets the protocol
layer convert it for the negotiated version. Responses are read into one model,
`KeyAttributes`, whatever the version. A feature the version lacks fails before
anything is sent, so code never half-works on an older server.

- In requests, 1.x Template-Attribute structures become 2.x Attributes, and 3.0
  text names and reference identifiers.
- In responses, `KeyAttributes` reads 1.x Attribute structures, 2.x and 3.0
  Attributes structures, and 3.0's per-type link attributes.
- Custom attributes are keyed `x-Name` or `y-Name` on 1.x and `vendor:Name` on
  2.x. The `x` and `y` vendors map back to `x-Name`, so they work on every
  version.
- These are refused with `UnsupportedException` before anything is sent:
  AES-GCM, additional data and RSA-PSS before 1.4; other vendor attributes
  before 2.0; object groups on 3.0, which has no Object Group attribute.
- Locate pages with Maximum Items and Offset Items from 1.3. Before 1.3 it asks
  for one more item than the limit and refuses when more match, instead of
  truncating silently.
- The 3.0 draft replaced the Link structure with one attribute per link type.
  The protocol layer sends and reads both forms, so links work the same on every
  version.
- On the 3.0 draft every Revoke makes a key Compromised. So no call sends a
  Revoke there unless the caller gave a compromise reason. `deactivate()`,
  `reconcile`, `deactivatePredecessors`, `retirePredecessors` and
  `KeyRegistration.replace` send Deactivate instead.

## Errors

`KmsException` is unchecked and sealed, and `category()` is the stable way to
decide what to do. The protocol layer's split between checked and unchecked
exceptions is a trap for applications. A category that is the same on every
KMIP version lets one `switch` handle every server.

How to handle each category is in
[Getting started](getting-started.md#handle-failures). The design choices:

- Categories follow the subtype, with two exceptions. An unconfirmed
  `CryptographicFailureException` is SERVER, because a 1.x General Failure on
  Decrypt does not show the data is bad. A `KeyMismatchException` for a record
  that names a key outside the expected lineage is BAD_DATA.
- Two failures differ between 1.x and 2.x, both correctly. The SDK normalizes
  them with one more read, on the failure path only. A 1.x server that enforces
  unique names refuses a taken name with Invalid Field. One Locate then confirms
  it, and the failure becomes an `AlreadyExistsException`. A 1.x server refuses
  a key that is not Active with Permission Denied. One Get Attributes then shows
  the state, and the failure becomes a `StateConflictException`.
- A refused Obtain Lease is a `StateConflictException` with the key's state
  when that state is not Active, as read before the request or once more after
  the refusal. So a key deactivated, revoked or destroyed in between is
  reported by its state. Item Not Found keeps the server's type. So does a
  refusal when the read after it shows the key still Active or in a state the
  SDK does not know, or fails. `LocalKeys`, the one-shot reads and the TLS
  followers all report a refused lease this way.
- `serverReason()` is not normalized. A `KmsReason` is the server's own word, so
  an application can log it and tell cases apart within a category. Constants
  merge only where the specification uses several codes for one refusal, or
  where codes share one remedy.
- Exceptions hold no key material. Their protocol objects are redacted copies. A
  server's Result Message is quoted once, cut to 200 characters, with control
  and bidirectional characters replaced. It is still untrusted input for logs.
- Misuse is not a `KmsException`. Bad arguments are `NullPointerException` or
  `IllegalArgumentException`. A closed `Kms` is `IllegalStateException`.

## Names, lookup, findOrCreate and duplicates

KMIP names are attributes, not unique keys. Most servers let several objects
share one, so `findByName` must choose one, and every caller must choose the
same one. It ranks whole rotation lineages by their first key, not single
objects, so a key planted under the name cannot win when the real key rotates.

Names are not access control. The rule and what to do are in
[Getting started](getting-started.md#key-names-are-not-access-control).

### Identifiers

An identifier is assigned by its server and names an object only there. Records
bind the identifier of the key they were made with.

- After key material moves to another server under a new identifier,
  `newHandle.acceptingOriginalId(oldId)` opens records that name `oldId`.
  Nothing needs re-encrypting at once.
- `KeyRegistration.replace(old)` refuses a handle of another `Kms`. Its
  identifier may name an unrelated object on this server.
- `rewrapTo(target, ...)` accepts a target of another `Kms`, to move records
  between servers.

### How a lookup chooses

- Each object with the name is placed in its lineage by following its confirmed
  Replaced Object links back, at most 64 steps.
- The lineage whose first key was created earliest wins (Initial Date, then the
  lowest identifier). Within it, the newest key with the name wins, an Active one
  first.
- States do not decide between lineages. An Active key is not preferred over a
  Pre-Active one, so the winner does not change as callers activate keys.
- When a lineage's start cannot be read, the lookup fails with
  `StateConflictException`. A guess could switch silently to a duplicate after
  old keys are purged.
- Only a lookup that finds several objects reads more than the Locate.

### findOrCreate

`findOrCreate` runs once at startup, and the caller keeps the handle. It never
destroys a key, because another instance may already have found and used it.

- In one process, concurrent calls through one `Kms` for the same name and
  settings run one at a time and get the same key.
- Across processes, every caller gets the same key only on a server that
  enforces unique names. The second Create is refused and the caller looks the
  name up again.
- Elsewhere it is best effort. A key that lost the race stays Pre-Active under
  the name. `KeyHandle.leftovers()` lists such candidates.
- It refuses when only Compromised or Deactivated keys have the name. A new,
  unrelated key would make every record under the old one look misfiled.
  `.replacingCompromised()` opts into replacing the Compromised key.
- `KeyPairCreation.findOrCreate()` does the same for key pairs, found by the
  private key's name.

### Duplicate names

To find and retire duplicates on a server without unique names:

1. `kms.keys().list(KeyQuery.byName(n))` lists every object with the name.
   `kms.keys().findByName(n, KeyState.ACTIVE, KeyState.PRE_ACTIVE)` returns the
   one `findOrCreate` chooses.
2. A Pre-Active duplicate that was never activated and has no links was never
   used. Destroy it if it is yours. A name proves nothing about who made it.
3. An Active duplicate may have encrypted data. Remove the name from it
   (`removeName(n)`) so lookups stop finding it. Re-encrypt its data under the
   chosen key with its own handle, then deactivate it. Destroy it once nothing
   refers to it.

## Lineage and rotation

A lineage is the tree of keys joined by Replacement Object and Replaced Object
links, where both keys of each step name each other. A one-sided link proves
nothing, because whoever controls a key can set its links. Every key of the tree
opens what any other key of it sealed.

### Walking the tree

- A handle decrypts a record that names its own key or another key of its tree.
  The SDK walks forward first, then back, one Get Attributes per key.
- `kms.keys().decrypt(query, ...)` and the other query paths require the
  record's key, or a key of its tree, to match the query. So a name query
  survives rotation.
- Walks are bounded: 64 rotations either way, 32 links of one kind on a stored
  record's key, and 256 keys a walk. The bounds stop links that others set on
  their own keys from making a decrypt expensive.
- A link the walk cannot resolve proves nothing. The result is then
  `StateConflictException` (STATE), not BAD_DATA, so good records are never
  quarantined.
- Records sealed more than 64 rotations before the current key need a query
  that the record's own key matches. Use an attribute that Re-key copies, or
  `KeyQuery.byIds` with identifiers you recorded. See
  [Key lifecycle](operating-keys.md).

### Concurrent rotations

Rotation (`rotate()`) and compromise replacement (`replaceCompromised`) run from
one scheduled job. Startup `findOrCreate` runs on every instance. KMIP has no
atomic "replace this key unless someone else just did", so concurrent rotations
can leave several newest keys. The SDK handles that as follows:

- A call changes only the key it was asked to rotate and the replacement it
  made. It never revokes, destroys, links or renames another caller's key.
- Each caller gets its own Active replacement, linked to the old key. Every
  record still opens through any key of the tree.
- Among several newest keys, `latest()` chooses an Active one, then one with a
  name, then the one created first. Every caller that sees the same keys chooses
  the same one.
- Names move only from the key being replaced, and only while it still has
  them.
- Lost replies are read back. A step that cannot be settled that way is a
  `PartialCompletionException`. No message of the SDK says to destroy a key
  another caller may use.
- `reconcile` joins the other newest keys into the chosen one, moves the names
  to it, and deactivates the others. It never destroys.
- A server that refuses a second Re-key never forks. There the second of two
  concurrent rotations is refused, and the caller learns the winner.

How to run rotation, several instances and a grace period is in
[Key lifecycle](operating-keys.md#rotate-on-a-schedule).

### Rotation refuses Compromised and Deactivated keys

`rotate()` and its variants refuse a Compromised or Deactivated key before
sending a Re-key, although KMIP allows one. A routine rotation of a Compromised
key would move on silently while its records became unreadable, and the
compromise procedure would never start.

- `replaceCompromised` is the one call that re-keys a Compromised key.
- A Deactivated key's replacement would copy its Deactivation Date and be
  Deactivated too.
- A key retired and later found compromised is re-keyed with an Offset of 0, so
  the replacement is Active for the span the old key had. That holds only when
  each span is at least a day. Otherwise the SDK creates a new key and links it.

## Compromised keys

KMIP lets a Compromised key decrypt and verify, but its output may be an
attacker's. So the SDK refuses a Compromised key for decryption, unwrapping,
verification and retrieval unless the handle is `allowingCompromised()`.
Destroyed keys are always refused.

- The state check fails closed. A response without State, or with an unknown
  State, is a `ProtocolViolationException`, because it cannot show that the key
  is neither Compromised nor Destroyed.
- The opt-in covers the handle's own key only. A record that names a Compromised
  predecessor is refused even through `current.allowingCompromised()`. Recovery
  names the compromised key.
- A record under a Compromised key outside the lineage is STATE, not BAD_DATA.
  It is probably good data whose key was compromised.
- Recovery never starts from an identifier taken from the record. Anyone who can
  create keys can make a record that names their own key and revoke it. The
  message says to recover only with a key you revoked yourself.
- `replaceCompromisedResult(reason, plan)` makes the plan again before its first
  change and compares it with the approved one: the key's state, compromise date
  and names, its replacements, the newest keys descending from it with their
  states and names, the unfinished name moves, and the search for an earlier
  call's unlinked key. The plans differ when, while the plan waited, another
  responder revoked or replaced the key, or another caller rotated it, moved a
  name or compromised a replacement. They also differ when another caller is
  making a replacement now.

The procedure is in [Key lifecycle](operating-keys.md#a-compromised-key).

## Retiring keys

Retirement destroys the oldest keys first and never purges the middle of a
chain. Lookups and decrypts walk the links through every key, so a missing
middle key cuts the keys before it off from the keys after it.

- `retirePredecessors` refuses while the tree has a newest key other than the
  receiver. Retiring shared older keys would cut that branch's records off.
- It refuses too when the tree reaches back past a key that exists but cannot be
  read, or is longer than 64 rotations.
- It destroys only keys of the receiver's confirmed tree. A name and a date do
  not show who made an object, so another client's key under the same name
  survives.
- Joined branches go first, because they reach the current key only through the
  key their branch replaced.
- Deactivated keys still decrypt where the server allows it. Deactivation is the
  safe middle phase between rotating and destroying.
- It refuses a Compromised receiver, because the keys before it may be the
  lineage's only keys that are not compromised. Replace it, then retire from the
  replacement.
- `retirementPlan()` runs the same walk and checks, and changes nothing. A
  retirement given that plan computes the set again and refuses when it differs.
  It then acts on the checked keys only, so nobody destroys a key that was not
  shown. KMIP has no transaction, so the check and the destroys are separate
  requests. Retire from one place. `deactivatePredecessors(reason, plan)` and
  `reconcile(name, plan)` follow the same rule and act on exactly the plan.
- A failure after the first key changed reports the keys deactivated and
  destroyed so far. Repeating the call resumes it.
- Retirement is irreversible.

The steps are in [Key lifecycle](operating-keys.md#retire-old-keys).

## Ownership

Whoever creates a resource closes it. The SDK closes only what it made or what a
method's contract says it takes over. It keeps no process-wide state an
application would have to manage.

- `Kms` is the sole owner of its transports and connections. `close()` ends
  them. `withTimeout(d)` views share them.
- There is no process-wide `Kms` registry. The application or framework owns
  each `Kms` and closes it. A registry keyed by configuration would need an
  equality that `KmsConfig` cannot have, because it holds suppliers, listeners
  and transports. A static registry would also outlive the class loaders of the
  applications that use it.
- `sealing` and `opening` own the stream they are given. They close it, also
  when they throw. `sealTo` does not close its `plaintext` stream, as
  `Files.copy` does not.
- Executors passed to `refreshingEvery` and the TLS followers stay the caller's.
- `CurrentKey` is not `AutoCloseable`. Most callers hold a synchronous follower,
  and linters would ask them to close it. `close()` stops a background
  follower's checks, and the object keeps working with the key it holds.
- The SDK's own threads are daemons in one `keytend-kmip` thread group, with no
  context class loader. Shared pools end idle threads after a second.

## Retries and failover

Reads are retried and mutations are never re-sent. A mutation that fails after
it may have reached the server has an unknown outcome. Only the application can
check whether it took effect, so the SDK reports it and stops.

- Get, Locate, Get Attributes, Query, Discover Versions, Obtain Lease and the
  cryptographic operations are retried, each attempt on the next healthy
  endpoint. 1.x Usage Limits count cryptographic operations, so
  `retryCrypto(false)` can exclude them.
- A mutation that was never sent is a `TransientException`. One that may have
  been delivered is an `OutcomeUnknownException`.
- Each call has one deadline. It covers every attempt, back-off and request of
  the call. No retry starts that the deadline would cut short.
- A read attempt waits at most the attempt timeout while an untried endpoint is
  left. A replica that accepts a request but never answers is then left within
  the same call.
- Only signs of an unhealthy endpoint move traffic. A definite answer such as
  Not Found does not, so one caller's error does not move every thread.
- `Kms.connect` returns only a working `Kms`. A lazy open would hide a
  misconfiguration until the first call. `connectRetry(d)` waits for a KMS that
  is starting.
- A `Kms` uses one KMIP version, and every endpoint must offer it. Endpoints
  must be replicas of one KMS.

Settings and defaults are in [Running in production](production.md#deadlines-and-retries)
and the `RetryPolicy` Javadoc.

### A lost Create or Register reply

Two calls make an object under a temporary name of their own, with a random
part. When the reply is lost, they look that name up with a Locate by Name,
which every server supports:

- `replaceCompromised`, where the server refuses Re-key, names the key
  `keytend-replacing-`, the compromised key's identifier and a random suffix.
  It records the compromised key's identifier in the client attribute
  `x-keytend-replacement-of`, which stays as the record of which key it
  replaced. It removes the temporary name before it links the key, and reads
  back a lost reply to that removal.
- `KeyRegistration.replace` registers under `NAME.replacing-` and a random
  suffix, for secrets, keys and certificates alike.

Each goes on only with the one object that has the name, and only while it is
Pre-Active, linked to nothing and has that name alone. `replaceCompromised`
also needs the recorded attribute, and reports such a key as `RECOVERED`. A
key another caller re-keyed from the object has the name, since a Re-key moves
names and copies client attributes, but it also has a Replaced Object link, so
it is never taken for the call's. When no object qualifies, the call stops and
reports what the search found: no object with the temporary name, objects
another caller may have changed or re-keyed, or a result it cannot rely on.
That last case covers a server that refused the search, did not filter by the
name, or returned an object these credentials cannot read.

## Secrets

Java cannot guarantee that memory is erased, so the SDK's wiping is best effort.
It wipes the buffers it owns once it no longer needs them, and leaves alone what
the caller, the JDK or JCA owns. Destroy keys and secrets promptly and keep
references short.

The policy is in [SECURITY.md](../SECURITY.md#handling-secrets). The protocol
layer's list is in [Protocol layer](protocol-layer.md#secret-lifetime).

- **Wiped by the application API:**
  - the `getEncoded()` copy of a registered or wrapped `SecretKey`;
  - the PKCS#8 encoding of a registered private key;
  - unwrapped key bytes, after the `DestroyableSecretKey` copied them;
  - locally generated data-key bytes;
  - the copies `registerSecret` takes, after sending;
  - the decoded PEM private key of `clientIdentityPem`, with the file contents,
    the encrypted and decrypted DER and the password-based key;
  - a password the `KmsConfig.Builder` replaces or discards;
  - the temporary buffers of `SecretData.chars()`.
- **Kept for the life of their owner:** the `KmsConfig.Builder`'s copies of
  the credential password (`usernamePassword`, `hashedPassword`) and of TLS file
  passwords given as a `char[]`. Each built `KmsConfig` keeps its own copy of
  the credential password, and of those file passwords only with
  `reloadOnChange`. Building twice is safe.
- **Wiped on request:** `DestroyableSecretKey.destroy()`, `DataKey.close()` and
  `SecretData.close()` zero their own copy.
- **Not wiped:**
  - every `Ttlv` request and response tree;
  - plaintext and ciphertext arrays passed in or returned;
  - JCA objects (`SecretKeySpec`, `PrivateKey`, key stores, key managers);
  - the KMIP password `String`, for the life of the `Kms`;
  - copies made by the JDK's TLS stack or the garbage collector.

Key-bearing responses are not retained. `toString()` of every type is redacted,
and listener events carry identifiers and outcomes only.

## The LocalKeys cache

The bundled Caffeine stores the cached keys, orders their eviction and times
their expiry. `LocalKeys` keeps the rules: TTL, leases, protection deadlines,
refusals, compromise and the events. Caffeine does the generic work. Only the
SDK knows which entries a call is using.

- When a new identifier needs room, the cache evicts the coldest entry in
  Caffeine's order that no call holds and no validation is loading, and wipes it
  before the new entry is handed out. Caffeine's own size bound is never
  reached.
- A cache hit takes no lock. It tells Caffeine of the access at most once a
  millisecond per entry, so many threads on one key do not contend.
- Each published key has a timer in Caffeine's timer wheel, ending at its TTL,
  lease or protection deadline. A sweep on access wipes the keys whose timers
  fired. The slot keeps its remembered refusal and its material fingerprint.
- The SDK schedules refreshes itself. A refresh is due at half the lease or the
  refresh interval, whichever comes first, from the validation's start.
  Caffeine's `refreshAfterWrite` is one fixed time after a write.
- The cache starts no threads. Caffeine runs its maintenance on the calling
  thread and reads the cache's own clock.

## Security trade-offs

Where safety and convenience conflict, the SDK refuses and says why.

- The record never chooses the key or the mode. A stored identifier is chosen by
  whoever made the record. Decryption accepts it only inside the caller's
  lineage or query. RSA-OAEP is never chosen from a stored spec name
  ([Stored formats](stored-formats.md#which-spec-decrypts)).
- On a server without unique names, anyone allowed to create keys can create one
  with your name, and a name query will match it. **Names are not an
  access-control boundary.** Filter on an attribute others cannot set, or
  decrypt with the key's handle.
- Extractable and Sensitive are two booleans, as in KMIP, not a policy type.
  Below KMIP 1.4 setting either is refused, never dropped. A key created with a
  protection is read back and not activated unless the server states it.
  `findOrCreate` never accepts an existing key that states less.
- Raw keys are handed out for one purpose. `asSecretKey(Expect, LocalUse)`
  checks the key's state and usage mask for that purpose. The type is `LocalUse`
  so it is not confused with `KeyUsage`, the mask a key permits.
- `Expect.rsa` and `Expect.ec` have no form without a size, since any RSA
  modulus would include weak ones and an EC curve is the key's security level.
  `Expect.rsa(0)` and `Expect.of(Algorithm.EC, 0)` accept any size, and
  `Expect.ec(0)` throws. `Expect.aes()` accepts any AES size and still checks
  the material.
- `encrypt`, `seal` and `wrapKey` refuse a symmetric key that cannot decrypt
  what it would encrypt, before anything is sent.
- `CurrentKey` does not prefetch raw key values. They would be the caller's,
  never wiped by the SDK. Raw keys belong in [`LocalKeys`](local-keys.md), which
  bounds, leases and wipes them.

## TLS identities

A TLS identity has one name, on its leaf certificate, and links for the rest.
Every change is staged Pre-Active under a temporary name of its own, then
switched by one request: the old leaf's Replacement link to the new one, or a
new identity's name. Only then is it activated, the leaf last. So a reader
always finds one whole pair.

How to register, follow and renew identities, and what a stopped call leaves,
is in [TLS identities](tls-identities.md). The choices behind it:

- The leaf's Private Key link names its key, which links back. Each
  certificate's Certificate link names its issuer. A Public Key object between
  them would add one object and two reads per identity, and TLS does not use it.
  A second name on the key would be a second name to move on every re-key.
- The new key, chain and leaf are linked first, then switched in, then
  activated: a new key, the new issuers from the leaf's issuer up, then the leaf.
  After the switch, a renewal first links the kept key to the new leaf. Readers
  find the old pair until the new leaf's Activate, and the new pair from then
  on. The name moves later, through a recorded pending move where names are
  unique. A call that stops after the switch can leave some or all of the new
  key and issuers Active with the leaf Pre-Active, or the leaf Active before the
  name has moved and the old leaf is deactivated.
- The SDK activates nothing before the switch. Trust followers use every
  Active certificate their queries match, wherever it came from. A leftover
  that was Active, holding the identity's certificate, would stay trusted after
  that certificate is revoked, and a leftover key would stay usable. Activating
  first and cleaning up after a stop was rejected, because a process that stops
  dead cleans up nothing, and a repeat cannot prove which objects an earlier
  call made. An object another caller changed is left as that caller left it
  ([Objects another caller changed](tls-identities.md#objects-another-caller-changed)).
- A repeat of a call that stopped before the switch starts over. It never
  resumes that call. Each call's temporary names have a random part, so no
  other call finds them. The stopped call's objects are left over, and the
  exception lists them. Resuming was rejected, because an object found by a
  name anyone can compute may be another caller's, and proving it is not took a
  model of every state an earlier call can leave.
- After the switch, a repeat activates the new objects, moves the name and
  deactivates the old leaf, and after a re-key the old key. First it compares
  each certificate of the new leaf's chain with its arguments by DER encoding,
  and the leaf's key with the key given (for a renewal, the identity's key). If
  one differs, it stops with nothing changed. Its changes follow the read rule
  below.
- A repeat cannot tell its own new issuer or key from one of the same DER (or
  the same key) that another caller registered, unnamed, and linked exactly as
  the call's own, and it activates that one. This is accepted, because it needs
  a write to the identity's own switched-in leaf, and the identity then presents
  exactly the chain and key it was given. Telling them apart would need a record
  of the identifiers each call made, kept outside the KMS. The leaf itself has
  the same limit.
- A call changes its objects, and a repeat the objects it finds switched in,
  only while a read just before shows each exactly as expected: its state,
  names and links, and the certificates or keys that link to it with
  Certificate or Private Key links, as far as the server and the credentials
  let a Locate show them. The call reads again before each change and each link
  to the object, resends included. On KMIP 1.x it removes one attribute
  instance per request, each after its own read. At the first object that is
  not as expected, it stops with a `StateConflictException` that names it,
  changes nothing more, and revokes nothing.
- A refusal offers to undo a switch only while it finds nothing of the stopped
  call Active or linked from the identity. To decide, it walks the call's steps
  after the switch in the order above: a renewal's link from the kept key, or a
  re-key's or registration's new key, then the new issuers. An object counts as
  the call's when its own step and every earlier one are made, and it is as the
  call leaves it: no name, linked only to the leaf (the key) or the next issuer,
  and linked to only from the leaf or the issuer below. Nothing counts when the
  leaf's Private Key link leads neither to the identity's key nor to one new
  key, as for a leaf another caller made. The count stops at the first object
  that does not count. If that object is not Pre-Active, it has a name or links
  the call does not give, so it is taken as another caller's. As with a repeat,
  another caller's unnamed object with the links the call gives counts as the
  call's.
- An offered undo leaves the object where the count stopped, and the new
  issuers above it (all of them when it is the new key), as they are. The call
  may have activated those issuers. The undo takes off the Replacement Object
  link, or a registration's name, and any Certificate link another caller made
  from the identity's key to the new leaf. It revokes nothing. The refusal says
  to finish the call, or, if another caller made the leaf and what it links to,
  to take its link or name off. When the object where the count stopped is
  taken as another caller's, the refusal names it with its state.
- Where an object has a Lease Time, followers obtain a lease before use and stop
  using it when the lease runs out. So a follower keeps presenting its pair
  while the KMS is unreachable only while the pair's leases run, and it does not
  see a revocation in that time. A server that sets no Lease Time sets no such
  limit. Once the KMS says the pair is not Active, nothing is presented.
- A peer that has just renewed is checked against the KMS once, off the
  handshake thread, instead of being refused for a whole interval. Accepting
  certificates linked to an allowed one was rejected, because it would accept
  certificates the query does not match.
- Run one renewal at a time, from one place. Concurrent renewals keep the
  identity usable but can leave objects to clean up.
- An identity can be issued by the KMS ([Issue from the
  KMS](tls-identities.md#issue-from-the-kms)). The KMS creates the key pair, the
  SDK signs a PKCS#10 request with the new key locally, and Certify issues the
  leaf under the call's temporary name. The SDK checks the leaf before it uses
  it. The new private key is activated before it signs, the one object an issue
  activates before its switch. KMIP lets no Pre-Active key be used, and servers
  lease no Pre-Active object. No certificate certifies the key yet, and nothing
  of the identity links to it, so no reader presents a leftover one. The rest
  is the same staged switch, so stops, repeats, races and leftovers behave as
  for a registered identity. Such a pair keeps its public key object, linked to
  the key and the leaf, and the read rule covers it too.
- A repeat of an issue cannot compare a leaf with a chain it was given. It takes
  the switched-in leaf as its own when the leaf has the subject, subject
  alternative names, issuer and key type asked, and, for a reissue, replaces the
  handle's certificate. Another caller's leaf that holds the same request is
  finished as the call's own, the same limit as an object of the same DER.
- Re-certify is not used. It moves the name and sets the Replacement links on
  the server in one step, around the SDK's switch, so a stopped or repeated
  call could not be told apart from another caller's.
- A requested validity is sent as a Deactivation Date and checked against the
  issued notAfter. An Activation Date is never sent, because one at or before
  now would make the certificate Active before the switch. A server that
  ignores the date fails the call instead of issuing a longer validity.
- An issuing CA is registered like an identity, with a public key object
  between its certificate and its private key, linked as Certify needs.
- The SDK does not share intermediates across identities, retire unused
  intermediates, or keep an on-disk cache for starting while the KMS is down.
