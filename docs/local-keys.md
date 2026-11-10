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

# Local keys

`LocalKeys` hands out raw AES keys to code that encrypts locally, such as a database encrypting
its files. It keeps a small cache of keys, each authorized for a limited time. The data records
the identifier of the key it was written under, and is read back with exactly that key.

Use it when your code must hold the key's value. When the KMS can keep the key, use
[envelope encryption](envelope-encryption.md) instead. External tools own key creation, rotation
and retirement. `LocalKeys` never creates, rotates, deactivates or destroys a key, not even on a
miss.

On this page:

- [Build one cache per node](#build-one-cache-per-node): open a cache that borrows or owns a `Kms`.
- [Writing and reading files](#writing-and-reading-files): how the write key is chosen and reads
  are checked.
- [Append-only files](#append-only-files): files that stay open and ask for their key per chunk.
- [Refresh and expiry](#refresh-and-expiry): the TTL, refresh, capacity and outages.
- [Leases](#leases): KMIP Lease Times, and servers that do not implement Obtain Lease.
- [Alarms before keys stop](#alarms-before-keys-stop): what to export and alarm on.
- [Keys taken out of the KMS](#keys-taken-out-of-the-kms): one-shot reads of a raw key.
- [Transparent data encryption keys](#transparent-data-encryption-keys): a database key provider.
- [Keys revoked as Compromised](#keys-revoked-as-compromised): files under a compromised key.

A cache in use:

```java
try (LocalKeys keys = kms.keys().localKeys("orders-write")
    .scope(KeyQuery.all().custom(CustomAttribute.client("tde-family"), "orders"))
    .expect(Expect.aes(256))
    .ttl(Duration.ofMinutes(5))
    .refreshAfter(Duration.ofMinutes(2))
    .capacity(64)
    .open()) {
  try (LocalKeys.Use use = keys.forEncrypt()) {
    // Initialize the cipher with use.key(), and record use.id() in the chunk header.
  }
  try (LocalKeys.Use use = keys.forDecrypt(idFromChunkHeader)) {
    // Initialize the decrypting cipher with this exact historical key.
  }
}
```

`kms` is a connected `Kms`. `"orders-write"` is the name that selects the key for new data.
`idFromChunkHeader` is the key identifier stored with the data being read.

- `forEncrypt()` returns the write key. Record `use.id()` with the data it encrypts.
- `forDecrypt(id)` returns the key that `id` names, and no other.
- Each `Use` owns its own copy of the key. Close it once the cipher is initialized. Closing
  destroys the copy.
- Ask for a new `Use` right before each bounded operation, such as each chunk. Do not keep the
  key or an initialized cipher across operations.
- A provider that returns `use.key()` to a caller that initializes the cipher later does not
  close the `Use`. That caller then owns the key and destroys it.

> [!WARNING]
> The cache checks a key's authorization (TTL, lease, protection deadline) only when it hands a
> `Use` out. It cannot recall a key already handed out, nor a cipher initialized from it.

## Build one cache per node

There are two ways to build a cache. Neither sends a request when it opens.

```java
// Borrows a Kms you connected and close yourself, after the cache.
LocalKeys borrowing = kms.keys().localKeys("orders-write")
    .scope(KeyQuery.all().custom(CustomAttribute.client("tde-family"), "orders"))
    .expect(Expect.aes(256)).open();

// Owns a Kms that connects at the first key use, so it opens while the KMS is down.
LocalKeys owning = LocalKeys.builder(config, "orders-write")
    .scope(KeyQuery.all().custom(CustomAttribute.client("tde-family"), "orders"))
    .expect(Expect.aes(256)).open();
```

`config` is your `KmsConfig`. `Kms.connect(config)` needs a reachable endpoint, so a service
that must start during an outage uses the owning form. Its first key use connects, and
concurrent calls share that connection attempt. Encrypted reads and writes fail until the KMS
answers.

- The first call's deadline, the call timeout, covers connecting, the configured
  `connectRetry` attempts and the key's validation. To wait longer at boot, raise both
  `callTimeout` and `connectRetry` on the `KmsConfig`.
- On each node, share one cache for each combination of connection, write name, scope and
  policy, across all tables. A cache per table duplicates connections, threads and
  authorizations.
- For several key families, share one lazily connected KMS between their caches. The owning
  form opens one set of connections per cache.

  ```java
  // One Kms, connected at the first key use of either cache.
  LocalKeys.SharedKms shared = LocalKeys.sharedKms(config);
  LocalKeys orders = shared.localKeys("orders-write")
      .scope(KeyQuery.all().custom(CustomAttribute.client("tde-family"), "orders"))
      .expect(Expect.aes(256)).open();
  LocalKeys users = shared.localKeys("users-write")
      .scope(KeyQuery.all().custom(CustomAttribute.client("tde-family"), "users"))
      .expect(Expect.aes(256)).open();
  ```

  Concurrent first uses share one connection attempt. After a failed one, each cache waits its
  own backoff. Close the caches, then the `SharedKms`. A `Kms` you have already connected works
  too: `kms.keys().localKeys(...)`.
- `shared.connectionStats()` reports the `SharedKms`'s connections, zero until it connects. The
  metrics modules read them with `connections(shared)`. To measure the connections of a single
  cache, build it from a `SharedKms` instead of the owning form.
- The application starts and closes its caches. The SDK keeps no process-wide
  registry. Closing the owning form, or a `SharedKms`, cancels its connection attempt and closes
  its connections. Closing a cache of a `SharedKms` leaves the KMS to the others.

## Writing and reading files

Each validation of the write key looks the write name up again, within the scope. One matching
Active key is selected. If several are Active, the key already selected stays selected. A cold
or invalidated cache then fails and names the candidates. It does not choose by date. Make the
selection unambiguous before rotating.

For reads, `forDecrypt(id)` fetches the exact stored identifier, never a name. It accepts Active
and Deactivated keys that permit Decrypt. It refuses Compromised keys
([Keys revoked as Compromised](#keys-revoked-as-compromised)), and Destroyed, Pre-Active and
unknown states.

The scope is required and must be stable: a custom attribute, a group or an explicit
set of up to 256 identifiers. It cannot contain a name or a state, which change at rotation.
It bounds both write selection and reads, so a crafted header cannot authorize an arbitrary
readable key.

- Use custom attributes on the KMIP 3.0 draft, which has no Object Group.
- Node credentials must not be able to change the attributes or groups that define the scope.
  Otherwise whoever can move keys into scope moves the authorization boundary.
- A candidate the server denies is skipped, and drops only the cached copies of that key.

An Active key with a Deactivation Date or Protect Stop Date encrypts only until the earlier
date, and within its TTL. Every use checks the date, also during an outage. A key past its date
is not selected for writes, even if the server still reports it Active. Keep the client's clock
accurate. Copies for decryption keep their own TTL.

Provision keys without Usage Limits. The cache refuses a key with Usage Limits before the Get,
because it obtains no usage allocation.

When a write validation also permits Decrypt, it seeds a decryption copy from the same
material. An immediate read-back then works without a second Get,
even during an outage, as long as there is capacity for the copy.

## Append-only files

A file written once, from start to end, takes its key from `forEncrypt()`. A file that stays
open and grows, such as a commit log segment or a hints file, may stay open for hours. It can
outlast a rotation and a lease. If it kept the key it started with, a key that may no longer
encrypt would stop only the next file's writes. So such a file follows three rules:

1. Open it with `forEncrypt()`, and record `use.id()` in its header.
2. Before each chunk, call `forAppend(fileKeyId)` with that identifier. Initialize a fresh
   cipher with the key it hands out, then close the `Use`.
3. When that call is refused, close the file and start a new one with `forEncrypt()`. What
   the file holds stays readable through `forDecrypt(fileKeyId)`, where the key may still
   decrypt.

This writer stores each chunk as its nonce, its ciphertext and its 16-byte tag. `keys` is the
node's `LocalKeys`, and `store` stands for the file's storage.

```java
SecureRandom random = new SecureRandom();
String fileKeyId;
try (LocalKeys.Use first = keys.forEncrypt()) {    // a new file
  fileKeyId = first.id();                          // record it in the file's header
}

// For each chunk appended later:
long index = 0;                                    // the chunk's position in the file
byte[] chunk = "order-1042 paid".getBytes(StandardCharsets.UTF_8);
byte[] nonce = new byte[12];
random.nextBytes(nonce);                           // a fresh nonce for every chunk
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
try (LocalKeys.Use use = keys.forAppend(fileKeyId)) {
  cipher.init(Cipher.ENCRYPT_MODE, use.key(), new GCMParameterSpec(128, nonce));
}                                                  // our copy is destroyed; the cipher has its own
byte[] stored = new byte[12 + chunk.length + 16];  // nonce, ciphertext, tag
System.arraycopy(nonce, 0, stored, 0, 12);
cipher.doFinal(chunk, 0, chunk.length, stored, 12);
store.writeChunk(index, stored);
```

The reader takes the nonce from the first 12 bytes of the stored chunk:

```java
long index = 0;
String fileKeyId = idFromChunkHeader;              // read from the file's header
byte[] stored = store.readChunk(index);
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
try (LocalKeys.Use use = keys.forDecrypt(fileKeyId)) {
  cipher.init(Cipher.DECRYPT_MODE, use.key(), new GCMParameterSpec(128, stored, 0, 12));
}
byte[] chunk = cipher.doFinal(stored, 12, stored.length - 12);
```

- **A nonce must never repeat under one key.** Generate a new random 12-byte nonce for every
  chunk with a `SecureRandom`. Random nonces are safe up to 2^32 encryptions per key, across
  every file that key encrypts
  ([Limits of AES-GCM per key](envelope-encryption.md#limits-of-aes-gcm-per-key)).
- To stop chunks being reordered or moved between files, pass the chunk's index and the file's
  identity to `cipher.updateAAD` on both sides.

`forAppend(id)` hands out that exact key only while it may still encrypt. The checks are those
of the write key: Active, in the scope, permitting Encrypt, before its protection deadline, and
leased where the key states a Lease Time ([Leases](#leases)). It need not be the current write
key. After a rotation, an open file keeps its key while new files move to the new one.

So a key that is deactivated, compromised, past its protection deadline or refused a lease stops
the file's writes within one TTL, or its lease if shorter. When the identifier is the write key
the cache holds, the call sends no request. Otherwise the identifier takes its own entry in the
cache's capacity, and a refusal is remembered for the TTL.

On a server that leases only Active keys, keep the old key Active until every file that names
it has been closed and is no longer needed.

### Writers that cannot start a new file

Rule 3 assumes the writer can close the file and open another when its key is refused. Some cannot.
Cassandra's commit log, for one, cannot end a segment early from inside its writer. For such a
writer the refusal stops writes, and the database's failure policy applies (Cassandra's
`commit_failure_policy`).

Do not retry around the refusal, and do not fall back to a key or cipher kept from before. The
refusal is the bound. So order key changes so that no open file's key is refused while it is
still being written:

- At a rotation, keep the old key Active, in scope and leasable until every file that names it
  has been closed. The rotation moves the name, so writers move to the new key as they start new
  files.
- A compromise is a choice between availability and confidentiality. To keep writes up,
  note the identifier of each compromised key, rotate, and restart every writer so that its open
  files close. Then revoke each of those keys by its identifier, with
  `kms.keys().handle(oldId).revoke(RevocationReason.keyCompromise(why, since))`. Do not look them
  up by name, because the name now points to the new key. Until the revocation, open files keep
  encrypting under the compromised keys. If the newest key is not one of them, the name already
  points to a clean key, so skip the rotation. Revoking first is safer for confidentiality. It
  stops, within one TTL or lease, every write still open under those keys.

## Refresh and expiry

A key is handed out only while it is authorized. A revocation takes effect for later handouts
once the cache observes it, or at hard expiry when the cache cannot refresh. A key already
handed out cannot be recalled.

| Situation | What a call does |
|---|---|
| Cache hit | Returns the cached key. No request. |
| Refresh due | Returns the cached key at once, and queues one background revalidation that callers share. |
| Miss | Loads the key in the calling thread, within the call deadline. |
| Hard expiry | Never returns the expired copy. Loads again in the calling thread, within the call deadline. |
| Observed revocation | Drops every cached copy of that key at once, and remembers the refusal for the TTL. |
| Server outage | Returns valid copies until their TTL or lease ends. Cold or expired calls fail. |

A refresh is due at `refreshAfter`, or at half the lease if sooner. Hard expiry is the earliest
of the TTL, the lease end and, for encryption, the protection deadline. A validation reads the
attributes and the key itself, so removing Get permission is observed too. Only a successful
validation renews authorization. Hits and failed refreshes do not.

The settings, on the builder:

| Setting | Default | Meaning |
|---|---|---|
| `ttl(Duration)` | 5 minutes | The longest a key is handed out without the KMS confirming it. |
| `refreshAfter(Duration)` | half the TTL | The age at which a use queues revalidation. Shorter than the TTL. |
| `capacity(int)` | 64 | Entries kept: the write key, keys for reading, remembered refusals. At least 2. |
| `refreshExecutor(Executor)` | one daemon thread | Runs background refreshes. A supplied executor stays yours. |
| `scope(KeyQuery)`, `expect(Expect)` | none | Required: the stable scope, and the algorithm and size. |

Each call also has one deadline: the `Kms` call timeout (30 seconds by default), or that of a
`kms.withTimeout(...)` view. Waiting for capacity, connecting and validating all share it.

The TTL bounds how long a node keeps using a key without the KMS, so it is
also the longest a node keeps working through an outage, unless a lease ends sooner. A shorter
TTL sees revocations sooner. A longer one rides out longer outages. `refreshAfter` sets how soon
a node in use follows a rotation.

Details:

- Idle entries are not polled. After more than a TTL without use, the first call loads in the
  calling thread, and fails if the KMS is down.
- After a transient failure, new attempts wait `min(1 second, ttl / 8)`. Meanwhile cold or
  expired calls fail fast with `TransientException`, whose cause is the earlier failure. Valid
  copies keep their original expiry.
- Absence, access denial and a state the key may not be used in are refusals. So is the server
  refusing this node's credentials. A General Failure, a malformed answer or a rejected server
  certificate is transient.
- `invalidate(id)` and `invalidateAll()` drop cached copies locally, and clear remembered
  failures. A call in progress for that key fails with `TransientException`. A later call loads
  normally.
- A working set of keys for reading larger than `capacity` costs reloads and waits. It can
  exhaust a deadline even with a healthy KMS. Size capacity and the call timeout instead of
  adding retry loops. When a new key needs room, the coldest idle entry (by recency and
  frequency, in Caffeine's order) is evicted and wiped first. An entry a call is using or
  loading is never evicted, and a new key waits for one to become idle.
- `close()` fails calls in progress with `IllegalStateException`, and wipes the
  cached copies. Expired copies are wiped lazily, but never handed out.

## Leases

A KMIP server may give a key a Lease Time. Past its lease, a client "SHALL NOT use the object
without obtaining another lease". Only Obtain Lease grants one (KMIP 1.4 §3.20 and §4.17, 2.1
§4.30 and §6.1.35).

Every SDK path that hands key material to the application follows the same rules. These paths
are `LocalKeys`, the one-shot reads such as `asSecretKey`
([Keys taken out of the KMS](#keys-taken-out-of-the-kms)), and the TLS followers. The rules below
are those of the default lease policy, `LeasePolicy.REQUIRE`. `LeasePolicy.HONOR_IF_SUPPORTED`
changes them only for a server that does not implement Obtain Lease, where it reads a key without
a grant ([below](#servers-that-do-not-implement-obtain-lease)).

- A stated Lease Time is an obligation. When Get Attributes states one, of any value, the SDK
  sends Obtain Lease before the Get. A stated zero or a malformed value counts too. The key's
  value is read only once the server grants a lease. A key that states no Lease Time is asked for
  no lease.
- A grant of zero means no time limit. A positive grant is the time the copy may be used. It
  counts from before Obtain Lease was first sent, so a retry or a slow answer never lengthens it.
  It is held to a positive stated maximum.
- A refusal hands out nothing. Permission Denied, Operation Not Supported, Item Not Found, or a
  state or request refusal is thrown with `operation()` `obtainLease`, and the server's reason
  and message. Apart from Item Not Found, a refusal of a key the SDK reads as not Active is a
  `StateConflictException` whose `observedState()` is that state. Otherwise the server's type is
  kept ([when the SDK reads the state](kms-design.md#errors)). The TLS followers report a refused
  lease through their state.
- An outage, a General Failure or a malformed grant gives no new lease.
- No setting extends a lease.

In `LocalKeys`, the lease is one more bound on each copy:

- A copy is handed out only while its lease, its TTL and, for encryption, its protection
  deadline all still run. The check is local and made at every handout.
- The first use after half the lease, or after `refreshAfter` if sooner, queues revalidation,
  which obtains a new lease. A use after the lease ended loads in the calling thread.
- A refusal drops every cached copy of the key, for both purposes, before any Get. It is
  remembered for the TTL, and `invalidate(id)` clears it.
- Encryption and decryption keep separate leases. Each validation obtains its own.

Under `REQUIRE`, a Deactivated key that states a Lease Time decrypts only if the server grants it
a lease. Some servers lease Deactivated keys, and some lease only Active ones.

> [!WARNING]
> On a server that leases only Active keys, never deactivate a key that stored data still
> needs. No client can then decrypt that data, and KMIP cannot make a Deactivated key Active
> again. Keep the key Active until its data is re-encrypted.

### Servers that do not implement Obtain Lease

A server may state a Lease Time and not implement Obtain Lease, for example answering Obtain Lease
with Invalid Message. Under the default policy, `LeasePolicy.REQUIRE`, every raw-key read is then
refused. An operator may opt in for such a server:

```java
KmsConfig config = KmsConfig.builder().endpoints("kms.example.com:5696")
    // ... TLS identity and trust ...
    .leases(LeasePolicy.HONOR_IF_SUPPORTED)
    .build();
```

Under `HONOR_IF_SUPPORTED`:

- Only a server that does not implement Obtain Lease is excused. It must answer Operation Not
  Supported or a message-level Invalid Message. Its own list of operations, read once per `Kms`,
  must also lack Obtain Lease. Any other answer is treated as under `REQUIRE`.
- The stated Lease Time then becomes a hard local bound, exactly as a grant of it would be. A
  stated zero or a malformed value bounds nothing, and stays refused.
- `KmsListener.leaseNotGranted(keyId, bound)` is told once per key and `Kms`.

This is a decision for one server, not KMIP behavior. The server cannot recall a copy, and the
SDK sees a revocation only at the next validation. Keep the server's Lease Time, and the cache's
TTL, as short as your outage tolerance allows.

### keytend-kmip-server's lease policy

keytend-kmip-server states a Lease Time on every object it creates, and leases by
state:

| Server option | Default | Effect |
|---|---|---|
| `--max-lease-seconds` | `3600` | The Lease Time stored on each new object. `0` means no limit. |
| `--lease-states` | `active-deactivated` | Leases Active and Deactivated keys. `active` leases Active keys only. |
| (either setting) | n/a | Never leases Pre-Active, Compromised or Destroyed keys. |

An Active key's lease is capped at the time left before its next Deactivation Date or Protect
Stop Date. Under `active-deactivated`, a Protect Stop Date already passed does not refuse the
lease. A lease never lets a Deactivated key encrypt.

## Alarms before keys stop

During a KMS outage, a node stops new files once the write key it holds is no longer usable. Two
figures tell how close a node is. Both are read from memory, with no request.

- `usableFor()` is how long `forEncrypt()` can still hand out the write key it holds without the
  KMS. It is the earliest of its TTL end, lease end and protection deadline. It is `Duration.ZERO`
  when nothing is usable, and is always present.
- `writeFailure()` is the failure of the write key's last validation. It is empty once one
  succeeds, after an invalidation of the write key, and after `close()`.

Export both:

```java
long seconds = keys.usableFor().orElseThrow().toSeconds(); // always present: the TTL bounds it
boolean failing = keys.writeFailure().isPresent();
```

A cache in use renews its write key at `refreshAfter`, or at half its lease if sooner. Once
refreshes fail, the figure keeps falling and `writeFailure()` is present.

A cache that is not used is not refreshed. On an idle node the figure runs down to zero too, with
`writeFailure()` empty. So pair them:

- Alarm when `usableFor()` falls below the time you need to restore the KMS while
  `writeFailure()` is present.
- Page before it reaches zero, when writes stop.

Neither figure is an authorization.

### Diagnostic callbacks

A `KmsListener` on the `KmsConfig`, or on the borrowed `Kms`, receives four callbacks:

- `localKeySelected(name, previousId, newId)` runs when a write key is first selected
  (`previousId` is null) and at each later change.
- `localKeyLoaded(name, keyId, purpose, loadTime)` runs once per load that succeeded: a first
  load, a background refresh or the renewal of an expired key. `purpose` is `LocalUse.ENCRYPT`
  for the write key and `forAppend(id)`, `LocalUse.DECRYPT` for `forDecrypt(id)`. A decryption
  copy seeded from the write key is not a load.
- `localKeyRefreshFailed(name, keyId, purpose, failure, remainingValidity)` runs once per
  refresh that failed. `remainingValidity` is the same figure as `usableFor()`. A failed first
  load is not reported, because its caller gets the exception. `stats().loadFailures()` counts
  every load that failed, first loads included.
- `leaseGranted(keyId, lease, renewal)` runs once per lease the server granted to a load that
  succeeded. `lease` is zero for a grant without a time limit. `renewal` is false for the
  cache's first grant for the key, and true for later ones, for either purpose, while the cache
  keeps an entry for the key.

A load that an invalidation or `close()` superseded, or that failed after Obtain Lease, reports
neither its load nor its lease. Callbacks run on the thread that ran the validation, outside the
cache's locks. They must not block or use the cache. An exception they throw is ignored.

### Counters

`stats()` returns the cache's counters since it opened, read from memory with no request:

| Counter | Counts |
|---|---|
| `encryptHits()`, `decryptHits()` | Handouts served from a valid cached key. |
| `encryptMisses()`, `decryptMisses()` | Handouts that loaded first, or waited for a load already running. |
| `loads()`, `loadFailures()` | Loads that succeeded, and loads that failed. A load an invalidation superseded is neither. |
| `evictions()` | Keys removed for capacity, or because their TTL, lease or protection deadline ended. |
| `capacityWaits()` | Calls that waited for capacity. |
| `size()` | The cached keys held now, the write key's included. |

A high miss rate with a healthy KMS means `capacity` is smaller than the working set. Calls that
wait for capacity point the same way.

## Keys taken out of the KMS

`asSecretKey`, `asPrivateKey` and `asSecretData` return a snapshot copy of the key.
Deactivating, revoking or destroying the key on the server later does not reach that copy. Nor
does it reach a JCA `Cipher` initialized with it. Destroy copies you no longer need
(`DestroyableSecretKey.destroy()`). When the key is compromised, stop using every copy yourself.

Every path follows the [lease rules](#leases). What each keeps afterwards differs:

| Path | What it keeps | Lease |
|---|---|---|
| `asSecretKey`, `asPrivateKey`, `asSecretData` | Nothing: the copy is yours, for immediate use. | Obtained before the Get. |
| `LocalKeys` | A bounded cache of keys, by identifier. | Obtained at each validation, checked at each handout. |
| TLS followers ([TLS identities](tls-identities.md)) | The presented private key and certificates. | Obtained, renewed, checked at each handshake. |

So keep raw keys in `LocalKeys`, for a database's SSTables, commit log and hints alike
([Transparent data encryption keys](#transparent-data-encryption-keys)). A one-shot copy kept in
your own cache beyond its lease breaks the server's policy. So do a database's own key or cipher
caches, unless the database is changed not to keep keys.

Check whether a key states a Lease Time. Empty means the server states none:

```java
Optional<Duration> lease = key.attributes().leaseTime();
```

A malformed Lease Time makes `leaseTime()` throw `ProtocolViolationException`. The SDK's own
paths then obtain an explicit lease and rely only on its answer.

### Raw keys

The one-shot reads `asSecretKey` and `asPrivateKey` are advanced
([Choosing an API](choosing-an-api.md)). `asSecretData` reads secrets the same way.

Some keys are meant to leave the KMS. A database's transparent data encryption encrypts pages
with the key itself. Such a key must be extractable, so create it with `extractable(true)`.
`findOrCreate` then checks that on an existing key too, so a key provisioned non-extractable
fails at startup rather than at the first rotation. Give the identity that retrieves it access
to those keys only, since whoever can Get the key has its value.

Retrieve the key for the purpose you will use it for. Nothing on the server checks a key's state
or usages once its value has left. So `asSecretKey(Expect, LocalUse)` checks them first. It sends
Get Attributes, then Get, with Obtain Lease between them when the key states a Lease Time.

```java
// Writing: the key in force, Active and permitting Encrypt.
KeyHandle writing = kms.keys().findByName("orders-tde").orElseThrow();
DestroyableSecretKey writeKey = writing.asSecretKey(Expect.aes(), LocalUse.ENCRYPT);
String writeKeyId = writing.id();          // stored with every page it encrypts

// Reading: the key the page names, Active or Deactivated, permitting Decrypt.
DestroyableSecretKey readKey =
    kms.keys().handle(storedKeyId).asSecretKey(Expect.aes(), LocalUse.DECRYPT);
```

`storedKeyId` is the identifier stored with the page being read.

- Record the key's identifier with the data it encrypts. Decrypt with the key that
  identifier names (`kms.keys().handle(storedKeyId)`).
- **Never resolve a name to decrypt.** A name finds the current key, which after a rotation is
  not the key the data was written with.
- `LocalUse.ENCRYPT` (and `WRAP`) is for the key that writes. It must be Active. A Deactivated,
  Compromised or Pre-Active key is refused with `StateConflictException`. A key whose usages lack
  Encrypt (or Wrap Key) is refused with `KeyMismatchException`.
- `LocalUse.DECRYPT` (and `UNWRAP`) is for reading old data. It accepts Active or Deactivated
  keys, and Compromised ones only through `allowingCompromised()`. Pre-Active and Destroyed keys
  are refused.
- `Expect.aes()` takes any AES size, for a lineage whose size changed. `Expect.aes(256)`
  insists on one.

To keep raw keys, use `LocalKeys`, which makes these checks each time it loads or revalidates a
key ([Transparent data encryption keys](#transparent-data-encryption-keys)).

## Transparent data encryption keys

A database that encrypts its own files with a key's value, such as Cassandra with transparent
data encryption, takes raw keys out of the KMS
([Keys taken out of the KMS](#keys-taken-out-of-the-kms)). Its key provider gets them from one
`LocalKeys` per node, which follows the [lease rules](#leases) and bounds every copy by its TTL.

The sample
[`TdeKeyProvider`](../sdk/src/test/java/dev/keytend/kmip/kms/samples/TdeKeyProvider.java) is such
a provider for a commit log and hints, in the shape of Cassandra's `KeyProvider`. Its test runs it
on KMIP 1.4, 2.1 and 3.0, with no Lease Time, Lease Time 0 and Lease Time 3600 s, and on a server
that leases only Active keys. The
[Cassandra commit log and hints integration](../integration/cassandra-trunk-tde/README.md)
applies it to Cassandra trunk. No SSTable adapter is included.

A provider follows four rules. The excerpts below come from the sample. The first three are
methods of its `NodeKeys`, the node's key service. In them, `keys` is the node's `LocalKeys`, and
the helpers are private to the sample: `decoded` is `AliasCodec.decode`, `copyOf` returns a copy
of the key that the caller destroys after `Cipher.init`, `requireRunning` refuses calls once the
node has stopped the service, and `unavailable` and `stopped` wrap a failure in the sample's
`KeyUnavailableException`.

An alias always names the same key. Each file records the alias of its key. Replay, perhaps
years later, decrypts the file with exactly that key, read by its identifier:

```java
public DestroyableSecretKey secretKey(String alias) throws IOException {
  String id = decoded(alias);
  requireRunning();
  try (LocalKeys.Use use = keys.forDecrypt(id)) {
    return copyOf(use.key());
  } catch (KmsException e) {
    throw unavailable("Cannot use key " + id + " for " + alias, e);
  } catch (IllegalStateException e) {
    throw stopped(e);
  }
}
```

Never resolve a name to decrypt. A name moves to each new key at rotation, and AES-CBC,
Cassandra's default cipher, cannot tell a wrong key from the right one.

The sample's alias is `kmip:` and the base64url of the identifier. The Cassandra integration
records `<key_alias>#<unique identifier>`, which keeps the name readable in file headers. Either
works if it is decoded strictly, so that each identifier has one form. Both refuse a malformed
alias before any request.

One handout gives a new file its alias and its key. `keyName` is the name new files go under:

```java
public KeyForFile keyForNewFile() throws IOException {
  requireRunning();
  try (LocalKeys.Use use = keys.forEncrypt()) {
    return new KeyForFile(AliasCodec.encode(use.id()), copyOf(use.key()));
  } catch (KmsException e) {
    throw unavailable("No key for new files under " + keyName, e);
  } catch (IllegalStateException e) {
    throw stopped(e);
  }
}
```

Asking for the current alias, then for the key by that alias, takes two authorizations. The
second is a read (`forDecrypt`), which also accepts a Deactivated key. And the write key can
change in between.

An open file asks for its own key again before each chunk. A commit log segment or hints file
may stay open for hours. Before each chunk the database asks `keyForAppend` for the file's key,
and initializes a fresh cipher with it:

```java
public DestroyableSecretKey keyForAppend(String alias) throws IOException {
  String id = decoded(alias);
  requireRunning();
  try (LocalKeys.Use use = keys.forAppend(id)) {
    return copyOf(use.key());
  } catch (KmsException e) {
    throw unavailable("Cannot append under key " + id + " for " + alias + "; start a new file", e);
  } catch (IllegalStateException e) {
    throw stopped(e);
  }
}
```

A refusal closes the file, and the database starts a new one with `keyForNewFile`
([Append-only files](#append-only-files)). A transient failure, such as an unreachable KMS, leaves
the file open to retry. The sample's `AppendOnlyFile` does both.

Each node has one key service. `NodeKeys` holds one `LocalKeys` that owns a lazily connected `Kms`
([Build one cache per node](#build-one-cache-per-node)). The sample's `Settings` record builds it.
`keyName`, `family`, `ttl`, `refreshAfter` and `capacity` are its fields, and `FAMILY` is the
custom attribute `tde-family`, set when a key is provisioned and copied by Re-key:

```java
public LocalKeys.Builder localKeys(KmsConfig config) {
  return LocalKeys.builder(config, keyName)
      .scope(KeyQuery.all().custom(FAMILY, family))
      .expect(Expect.aes()) // any AES size: a lineage's size may change
      .ttl(ttl)
      .refreshAfter(refreshAfter)
      .capacity(capacity);
}
```

The node starts the service before it opens its commit log, and stops it after it stops writing.
Providers that the database instantiates reflectively find the running service
(`NodeKeys.running`). They fail if there is none, and never connect by themselves.

The database itself must keep no key or cipher beyond one handout, fail closed and tell a key
outage from corruption. These rules, and the Cassandra changes for them, are in
[The Cassandra patches](../integration/cassandra-trunk-tde/README.md#the-cassandra-patches).

The sample's `provision`, `rotate`, `retireUnreferenced` and `replaceCompromised` are the
operator's steps, run from one place, never from the nodes.
[Operating it](../integration/cassandra-trunk-tde/README.md#operating-it) gives the procedure,
with a `KmipTool` command for each.

## Keys revoked as Compromised

The cache refuses a Compromised key for encryption and for decryption. After a compromise, move
new files to a replacement first. The key's name and scope go to an Active key, and
`invalidate(id)` makes a node ask at once. Then deal with the files still under the compromised
key:

- Recover them from replicas. Data under a compromised key may have been read or forged by
  whoever had the key. Where the database keeps replicas, as Cassandra does, rebuild the node's
  copy from the others. Discard the node's commit log segments and hints under that key. Destroy
  the key once no file names it. This is the supported path.
- Where nothing else holds the data, start the node for maintenance. A cache built with
  `allowCompromisedForDecrypt()` also hands a Compromised key to `forDecrypt`, to replay or
  re-encrypt what only this node has. It never encrypts with one. It logs a warning through
  SLF4J (`dev.keytend.kmip.kms.LocalKeys`) when it opens and at each validation that accepts a
  Compromised key. The server still decides. keytend-kmip-server leases no Compromised key, so
  with it the setting changes nothing. Configure it for the recovery only, and remove it
  once the data is re-encrypted.
