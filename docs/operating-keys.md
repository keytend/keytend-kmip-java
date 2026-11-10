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

# Key lifecycle

This guide covers the life of a key-encryption key (KEK) after it is created. The lifecycle in
four steps:

1. Run rotation from one scheduled job.
2. Application instances seal through `CurrentKey` and follow the replacement. A key and its
   replacements form a [lineage](kms-design.md#lineage-and-rotation).
3. Keep older keys until every retained copy of the data has moved to the new key.
4. Then retire the older keys through the newest key.

The examples use the application API, `dev.keytend.kmip.kms`, and work on KMIP 1.4 to 2.1 and
the 3.0 draft. They start from a connected `Kms` and a key made with `findOrCreate`
([Getting started](getting-started.md#find-or-create-a-key)). Sealing itself is in
[Envelope encryption](envelope-encryption.md#seal-and-open-records). The reasons behind each rule
are in [the design notes](kms-design.md). Operators can do the same steps from the
[command line](../cli/README.md) (`rotate`, `expire`, `retire-predecessors`, `replace-compromised`).

- [Rotate on a schedule](#rotate-on-a-schedule)
  - [A server-set cryptoperiod](#a-server-set-cryptoperiod)
- [Several instances](#several-instances)
  - [Startup on several instances](#startup-on-several-instances)
  - [Following in the background](#following-in-the-background)
  - [Handles without CurrentKey](#handles-without-currentkey)
  - [Several newest keys](#several-newest-keys)
- [Rotation with a grace period](#rotation-with-a-grace-period)
  - [A server that will not schedule it](#a-server-that-will-not-schedule-it)
  - [Deactivate at a date](#deactivate-at-a-date)
  - [What other instances see](#what-other-instances-see)
  - [Deactivated keys and the server's policy](#deactivated-keys-and-the-servers-policy)
- [Move data to the new key](#move-data-to-the-new-key)
- [Retire old keys](#retire-old-keys)
  - [Confirm what will be destroyed](#confirm-what-will-be-destroyed)
  - [Rules for retiring by hand](#rules-for-retiring-by-hand)
  - [Retiring part of a lineage](#retiring-part-of-a-lineage)
  - [Advanced: keys left by findOrCreate races](#advanced-keys-left-by-findorcreate-races)
- [Approve a change first](#approve-a-change-first)
- [Records older than 64 rotations](#records-older-than-64-rotations)
- [Moving a write name between keys](#moving-a-write-name-between-keys)
- [A compromised key](#a-compromised-key)
  - [After a restart](#after-a-restart)
  - [Edge cases of a compromise](#edge-cases-of-a-compromise)
  - [A server that refuses Re-key](#a-server-that-refuses-re-key)
- [Replacing a secret](#replacing-a-secret)

## Rotate on a schedule

Rotation runs from **one scheduled job**, not from every instance. Every instance follows the new
key through its `CurrentKey`.

```java
// The rotation job. Run it from one place only, for example once a day.
KeyHandle newest = kms.keys().current("orders-kek")
    .rotateIfActiveFor(Duration.ofDays(30)); // rotates when the key is 30 days old
```

Each application instance seals through one shared `CurrentKey`:

```java
CurrentKey current = kms.keys().current("orders-kek"); // one per key, shared in the instance
byte[] orderId = "order-1042".getBytes(StandardCharsets.UTF_8);
byte[] orderJson = "{\"total\":42}".getBytes(StandardCharsets.UTF_8);
byte[] sealed = current.seal(orderJson, orderId);       // under the newest key
byte[] opened = current.open(sealed, orderId);          // under any key of the lineage
```

`rotateIfActiveFor(period)` rotates the lineage's current key only when it has been Active for
`period`. Otherwise it returns the current key. Fire the job more often than the period. A job
that fires again finds the new key and does not rotate again until the period has passed.

To log or count what the job did, call `rotateIfActiveForResult` on a key handle. Its outcome is
`ROTATED`, `NOT_DUE`, `FOLLOWED` when another caller rotated the key first, or `RECOVERED` when
the Re-key's reply was lost and reading back found a replacement, which this call or another
caller made (`recoveredFrom()` is that Re-key). `rotateResult(rotation)` and
`rotateOrLatestResult(rotation)` report the same way for `rotate` and `rotateOrLatest`.

```java
RotationResult r = kek.rotateIfActiveForResult(Duration.ofDays(30), Rotation.grace(Duration.ofDays(7)));
if (r.outcome() == RotationResult.Outcome.ROTATED)
  log.info("rotated {} to {}", r.previous().id(), r.current().id());
```

Rotation needs no downtime:

- The new key is Active and linked to the old one.
- The new key opens what the old one sealed, and the other way round.
- The old key stays Active. Rotating revokes and destroys nothing.

To switch the old key off after a while, use a [grace period](#rotation-with-a-grace-period). To
stop depending on it, [move the data](#move-data-to-the-new-key), then
[retire](#retire-old-keys) it.

Watch out for:

- The rotation calls refuse Compromised and Deactivated keys with `StateConflictException`
  (category `STATE`). `observedState()` says which. A Compromised key needs
  [the compromise steps](#a-compromised-key), not a rotation, so alert a person.
- Two jobs that rotate one key at the same moment can leave
  [several newest keys](#several-newest-keys). Every record still opens.
- A Re-key without an Offset copies the old key's Activation Date to the replacement. If you
  write your own due check, measure a key's age from the later of its Activation Date and
  Initial Date, as `rotateIfActiveFor` does.
- `rotate()` rotates at once and refuses a key that was already replaced. `rotateOrLatest()`
  returns the current key in that case.

### A server-set cryptoperiod

Some server policies give each key a Deactivation Date. The default Re-key copies the first key's
date to every replacement, so the whole lineage stops at that date. Rotate with shifted dates,
more often than the cryptoperiod:

```java
// The rotation job. The server deactivates each key 90 days after activation.
kms.keys().current("orders-kek")
    .rotateIfActiveFor(Duration.ofDays(60), Rotation.of(RotationDates.SHIFTED));
```

`RotationDates.SHIFTED` sends the Re-key with an Offset of 0. The replacement is activated now.
Its Deactivation, Protect Stop and Process Start Dates are the old key's, moved forward by the
same amount. So each key gets the full cryptoperiod. A server that does not support an Offset
refuses the Re-key.

## Several instances

Every instance calls `findOrCreate` once at startup and keeps one `CurrentKey` per key, shared by
all its components. When the rotation job rotates, each `CurrentKey` moves its sealing to the new
key at its next check. Every instance keeps opening every record meanwhile.

```java
CurrentKey current = kms.keys().current("orders-kek"); // or kms.keys().current(kek)
current.refresh();                                     // move to the newest key now
```

How a `CurrentKey` follows:

- It checks `latest()` at most once a minute, on the calling thread.
  `current.checkingEvery(Duration)` returns a follower with another interval.
- When the server refuses a seal because the key is no longer Active, it checks at once and
  repeats the call once under the newer key. `seal`, `sealing`, `sealTo`, `chunkedSealer`,
  `rewrapRecord`, `rewrapHeader`, `generateDataKey`, `wrapKey` and `rewrapKey` are repeated this
  way.
- `open`, `openTo` and `unwrapKey` need no repeat. They work through every key of the lineage.
- A check that fails is passed over and the instance goes on with the key it holds.
  `KmsListener.currentKeyCheckFailed` hears of it. Alert when `failuresInARow` grows. Until a
  check succeeds, the instance does not follow rotations
  ([Listeners and events](production.md#listeners-and-events)).
- Each call has one deadline, the call timeout. It covers the check, the call and any repeat. A
  call that runs out of time while waiting fails with `TransientException`.

If the instance that runs the rotation job also seals, it can rotate through its `CurrentKey`.
Its components then seal under the new key from their next call:

```java
// In the rotation job, on the instance that runs it.
current.rotateIfActiveFor(Duration.ofDays(30));
```

After a [compromise](#a-compromised-key) or [`reconcile`](#several-newest-keys), move the
follower with `current.moveTo(replacement)`. It holds any key of the same `Kms`, with no request.

### Startup on several instances

Several instances may run `findOrCreate` for a new name at the same moment. On a server that
enforces unique names, they all end with the same key. On other servers they can end with
separate, unlinked keys. For a brand-new name on such a server, create the key from a deployment
step, or start one instance first. The rules are in
[the design notes](kms-design.md#names-lookup-findorcreate-and-duplicates).

A creator that lost the race destroys nothing. A key it made but did not activate stays
Pre-Active, and [`leftovers()`](#advanced-keys-left-by-findorcreate-races) lists it. A key it
activated before the other key was found stays Active, and may be in use.
`findOrCreateResult()` says what the call did. Its `outcome()` is `FOUND`, `ACTIVATED`,
`CREATED`, `REPLACED` or `RECOVERED`. `RECOVERED` means a reply was lost and reading back went
past it. Either the Create's reply was lost and the key was then found by name, or the Activate's
reply for a Pre-Active key it found was lost and the key was then read back Active.
`recoveredFrom()` is that step. Its `objectId()` names the key for a lost Activate, and is empty
for a lost Create. The result's `created()` lists a key the call left behind. A key pair's
`findOrCreateResult()` is the same for pairs (`FindOrCreatePairResult`), without `REPLACED`.

### Following in the background

A due check runs on the thread that seals and can wait for the KMS. Where that thread must never
wait, such as a database's commit log, check on an executor instead. `scheduler` is a
`ScheduledExecutorService` you own, and `log` is your logger.

```java
CurrentKey kek = kms.keys().current("orders-kek")
    .refreshingEvery(Duration.ofSeconds(60), scheduler);
kek.onChange(k -> log.info("new records use {}", k.id()));
byte[] sealed = kek.seal(record, recordId); // no check on this thread
// ...
kek.close(); // at shutdown: cancels the task, not the executor
```

- `refreshingEvery` and `checkingEvery` are advanced. Each returns a new follower. Call it
  once, before the object is shared, and share what it returns.
- Calls never check on the calling thread. A refused seal still refreshes at once, as above.
- A check moves only to an Active key.
- `KmsListener.keyStateChanged(keyId, from, to)` hears when a check reads the held key in a new
  state, such as Active to Compromised.
- Raw keys for a database's files go through [`LocalKeys`](local-keys.md), not a `CurrentKey`.

### Handles without CurrentKey

A plain `KeyHandle` does not follow rotation. To keep one current, refresh it now and then, not
per record:

```java
// On a timer, for example every minute.
if (!kek.isLatest()) kek = kek.latest();
```

`isLatest()` costs one request when the key was replaced, and otherwise one per key of its
lineage. A `KmsListener` also hears `staleHandle(keyId, replacements)` when an operation finds the
handle's key replaced.

### Several newest keys

Callers that rotate or replace one key at the same moment can each get their own replacement.
This happens on a server that re-keys a key twice. A server that refuses a second Re-key, such as
keytend-kmip-server, never forks. The later `rotate()` gets `StateConflictException` "replaced
meanwhile", and `rotateOrLatest()` returns the winner.

When it does happen, a record sealed under any newest key still opens through every key of the
lineage. `latest()`, `findByName` and `isLatest()` choose among them the same way on every
instance. But new records spread across them, and retirement refuses to run. Join them from the
rotation job:

```java
KeyHandle kept = kms.keys().reconcile("orders-kek").orElseThrow();
```

`reconcile` keeps the newest key every instance chooses and links the others into it. It gives
the kept key the names and deactivates the lineage's other Active keys, which still open what
they sealed. It never destroys. After a failure, repeat it, and it continues where it stopped. To
have a person approve it first, see [Approve a change first](#approve-a-change-first).

- `KmsListener.concurrentReplacement(keyId, replacements)` tells a caller of `rotate` or
  `replaceCompromised` that saw another replacement. That is a good moment to run `reconcile`.
- On a server that refuses links, `reconcile` throws `UnsupportedException` and deactivates
  nothing. Choose the key to keep and deactivate the others by hand, oldest first.
- If a startup `findOrCreate` keeps refusing because the name "is being moved" to a key you
  retired on purpose, clear that record with `kms.keys().clearPendingName("orders-kek")`.
- On a server that cannot search client attributes (PyKMIP) or ignores that filter,
  `findOrCreate` may not see such a record, and then creates a new key under the name. On those
  servers, finish a stopped replacement or `reconcile` before instances start.

## Rotation with a grace period

A grace period lets the old key keep encrypting for a while, then switches it off. The phases:

1. **Rotate** from the scheduled job with `Rotation.grace(grace)`. New records go under the new
   key from each instance's next check.
2. **Grace period.** The old key stays fully Active. Instances that have not moved yet keep
   sealing under it.
3. **Deactivate.** The server deactivates the old key when the grace period ends. A Deactivated
   key no longer encrypts, wraps, signs or computes MACs.
4. **Move the data** still under old keys ([Move data to the new key](#move-data-to-the-new-key)).
5. **Retire** the old keys once nothing needs them ([Retire old keys](#retire-old-keys)).

```java
Rotation policy = Rotation.grace(Duration.ofDays(7)); // a constant of the rotation job

// The rotation job, run from one place once a day: a new key every 30 days.
// Each old key stops encrypting 7 days after it is replaced.
KeyHandle kek = kms.keys().findByName("orders-kek").orElseThrow();
kek.rotateIfActiveFor(Duration.ofDays(30), policy);
```

`Rotation.grace(grace)` sets the old key's Deactivation Date to now plus the grace period, by
this machine's clock. It is set on the old key only, after the Re-key, so the replacement copies
nothing of it. A grace never extends a key's life. An earlier Deactivation Date stays.
`RotationResult.previousDeactivationDate()` is the date in effect.

- Choose a grace period much longer than the `CurrentKey` check interval (one minute by default).
- Allow for clock skew between this machine and the server.
- `Rotation.grace(grace).dates(RotationDates.SHIFTED)` combines a grace period with
  [a server-set cryptoperiod](#a-server-set-cryptoperiod).
- `rotate`, `rotateOrLatest` and the `CurrentKey` forms take a `Rotation` too.

### A server that will not schedule it

Some servers do not let a client set a Deactivation Date. There the rotation still happens, the
old key stays Active, and the call throws `PartialCompletionException`. Its `created()` is the new
key, and its message says what to do. A `CurrentKey` holds the new key before it throws.

On such a server, or to keep the schedule in your own job, rotate without a grace and deactivate
explicitly later:

```java
// The rotation job, daily: a new key on day 0, 30, 60, ...
kek.rotateIfActiveFor(Duration.ofDays(30));
// A later job, once the grace period after the last rotation is over:
kms.keys().findByName("orders-kek").orElseThrow().deactivatePredecessors();
```

`deactivatePredecessors()` deactivates the older keys of the current key's lineage. It destroys
nothing and can be repeated safely. It passes over keys that are already Deactivated, Compromised,
Destroyed or Pre-Active. It refuses while the lineage has [several newest
keys](#several-newest-keys). It also refuses, with `UnsupportedException`, when more than 64
rotations that are not destroyed lie behind the current key. Retire the oldest keys first
([Retiring part of a lineage](#retiring-part-of-a-lineage)).
`deactivatePredecessors(reason, plan)` deactivates only the keys a `retirementPlan()` showed as
Active ([Approve a change first](#approve-a-change-first)).

Another failure after the Re-key, such as a lost reply, also ends in `PartialCompletionException`.
Repeat `rotateOrLatest` with the same `Rotation` from the old key's handle, as the message says.
The daily job does not finish it by itself, because the new key is not due.

### Deactivate at a date

To stop a key at a date without rotating it, such as at the end of a key switch, set its
Deactivation Date:

```java
Instant date = old.deactivateAt(Instant.parse("2026-12-01T00:00:00Z")); // the date in effect
```

From that date the server treats the key as Deactivated. It no longer encrypts, and still
decrypts where the server's policy allows.

- The call never postpones a date. A key whose Deactivation Date is no later keeps it, and that
  date is returned. The date is rounded up to a whole second.
- A date is written on Active or Pre-Active keys only. A key in another state whose Deactivation
  Date is no later is returned that date. Otherwise the call throws `StateConflictException`. On a
  Pre-Active key the date applies once the key is Active. KMIP has no transition from Pre-Active
  to Deactivated, so a date that passes first is up to the server.
- The call reads the date, then sets it. KMIP has no compare-and-set, so change a key's
  lifecycle from one place at a time.
- A server that will not schedule a deactivation answers `UnsupportedException` from KMIP 2.0,
  and `PermissionDeniedException` on KMIP 1.x. Deactivate the key at that time instead.

The attribute change is sent once and never re-sent. If its reply is lost, or a refusal may be
about the key's state, the call reads the date back to see whether it took effect. It uses the
same operations on every KMIP version (Get Attributes, then Add Attribute or Modify Attribute), so
the 3.0 draft's Revoke does not apply.

### What other instances see

- During the grace period, an instance with a `CurrentKey` seals under the old key until its
  next check, then under the new one. A plain handle on the old key keeps sealing under it
  without an error, and `isLatest()` is false. Records sealed under either key still open through
  the lineage.
- Once the old key is Deactivated, sealing under it is refused with `StateConflictException`
  (`observedState()` is `DEACTIVATED`). A `CurrentKey` moves on that refusal and repeats the seal.
  A plain handle must be refreshed (`kek = kek.latest()`).
- After retirement, records that were not moved no longer open.

### Deactivated keys and the server's policy

KMIP does not promise that a Deactivated key decrypts. It allows decryption with one only "under
extraordinary circumstances and only when special permission is granted" (KMIP 1.4 §3.27).
Servers differ. The in-memory server and keytend-kmip-server decrypt with a Deactivated key. A
stricter server refuses unless your identity has that permission.

- Check it on your server, with the application's own identity
  ([Qualifying a server](production.md#qualifying-a-server)).
- `LocalKeys` needs a lease for a key that states a Lease Time. On a server that leases only
  Active keys, it cannot read a Deactivated key's data at all ([Leases](local-keys.md#leases)).
- On a server that refuses, move the data during the grace period, or have the permission granted
  to the identity that moves it.
- KMIP's Protect Stop Date means "stop encrypting, keep decrypting". The SDK does not set it, but
  a server policy may. The server then refuses to encrypt with a key past that date.
  `attributes().protectStopDate()` shows it.

## Move data to the new key

After a rotation, move each stored record to the newest key. `store` is your record store, whose
`Record` has `id()`, `sealed()` and `aad()`.

```java
CurrentKey current = kms.keys().current("orders-kek");
current.refresh(); // hold the newest key before the job starts
for (Record r : store.all()) {
  Rewrapped moved = current.rewrapRecord(r.sealed(), r.aad()); // no request if already moved
  if (moved.changed()) store.put(r.id(), moved.bytes());
}
```

`rewrapRecord` re-seals the record under a fresh data key, and the plaintext never leaves the SDK.
The loop can run again after a failure, because records already moved are returned unchanged.

- A wrapped data key from `generateDataKey` moves with `current.rewrapKey(wrapped, aad)`.
- A chunked file moves by its header, with `current.rewrapHeader(header, fileId)`
  ([Seal files chunk by chunk](envelope-encryption.md#seal-files-chunk-by-chunk)).
- Backups, snapshots and replicas hold copies too. Keep the old keys until every retained copy has
  moved or expired.
- Each record that moves is one AES-GCM encryption under the KEK
  ([Limits of AES-GCM per key](envelope-encryption.md#limits-of-aes-gcm-per-key)).

## Retire old keys

Retirement destroys the older keys of a lineage. Do it only after the data has moved:

1. Run the [move](#move-data-to-the-new-key) to completion.
2. Check that no retained copy still needs an older key: backups, snapshots, replicas, exports.
3. Run retirement from the rotation job, or while that job does not run.

> [!WARNING]
> Retirement is irreversible. A destroyed key opens nothing, so any record, backup or snapshot
> still sealed under an older key becomes unreadable.

```java
CurrentKey current = kms.keys().current("orders-kek");
current.refresh();                   // follow any rotation made elsewhere
KeyHandle newest = current.handle(); // the key new records go under
for (Record r : store.all()) {       // verify the move: every record names the newest key
  if (!KmsKeys.sealedKeyId(r.sealed()).equals(newest.id()))
    throw new IllegalStateException("record " + r.id() + " has not moved yet");
}
List<KeyHandle> destroyed = newest.retirePredecessors(RevocationReason.superseded("rotated"));
```

`retirePredecessors` deactivates and destroys the other keys of the newest key's lineage. Those
are the keys it replaced, each confirmed by both keys' links, and keys `reconcile` joined in. It
touches nothing else. It goes oldest first, so a retirement that stops part-way never cuts the
chain. After a failure, repeat it, and it continues where it stopped. A failure after some keys
changed is a `PartialCompletionException`. Its `destroyed()` and `deactivated()` list those keys,
and its cause is the step that failed.

- If another caller rotated at the same moment, there is a competing newest key. The call throws
  `StateConflictException` and destroys nothing. Run `kms.keys().reconcile("orders-kek")`, move
  the data again, then repeat these steps through the key `reconcile` returns.
- A lineage that reaches more than 64 rotations behind the newest key is refused with
  `UnsupportedException`, with nothing changed. Retire it in two steps
  ([Retiring part of a lineage](#retiring-part-of-a-lineage)).
- Active keys are deactivated first, so on the KMIP 3.0 draft they end Destroyed, not Destroyed
  Compromised. Keys already Deactivated or Compromised are destroyed without another Revoke.
- Retiring from a Compromised newest key is refused with `StateConflictException`, with nothing
  changed, because the keys before it may be the lineage's only keys that are not compromised.
  Replace it first ([A compromised key](#a-compromised-key)), then retire from the replacement.

### Confirm what will be destroyed

Where a person or a change process approves the destruction, show the plan first, then retire
exactly what was approved:

```java
RetirementPlan plan = newest.retirementPlan(); // reads only; refused as the retirement would be
for (KeyAttributes k : plan.keys()) log.info("will destroy {} ({})", k.id(), k.state());
// after approval:
newest.retirePredecessors(RevocationReason.superseded("rotated"), plan);
```

The plan lists the keys in the order they are destroyed, joined branches included. The
retirement computes the set again and compares it with the plan before it changes anything. When
the lineage changed meanwhile, for example a rotation or a reconcile, it throws
`StateConflictException` and changes nothing, and you make a new plan. Otherwise it acts on the
planned keys only. Keys of the plan that were destroyed meanwhile are passed over, so repeating
the call with the same plan resumes a retirement that stopped.
`retirementPlanOlderThan(keepFrom)` plans [part of a lineage](#retiring-part-of-a-lineage). The
same holds for every change in [Approve a change first](#approve-a-change-first).

### Rules for retiring by hand

The same rules hold when you retire keys yourself:

- Never destroy a key whose records you have not moved.
- Retire a key with `key.deactivate()`, never with a Revoke you send yourself. On the KMIP 3.0
  draft a Revoke makes a key Compromised, whatever its reason.
- Only an Active key can be deactivated. Destroy a Pre-Active key you no longer want instead.
- Go oldest first. Never destroy a key in the middle of the chain while keys on both sides are
  kept. The keys before and after it would stop opening each other's records.

### Retiring part of a lineage

When something still needs one old key, such as a replay log, retire only the keys before it.
`oldestStillNeeded` is that key's identifier.

```java
KeyHandle newest = kms.keys().current("orders-kek").handle();
List<LineageKey> versions = newest.lineage();                // newest first, to choose from
KeyHandle keepFrom = kms.keys().handle(oldestStillNeeded);  // one of versions' ids
List<KeyHandle> retired =
    newest.retirePredecessorsOlderThan(keepFrom, RevocationReason.superseded("rotated"));
```

`lineage()` lists every key of the lineage with its attributes and its place in the chain. Use it
rather than following `attributes().replacedLink()` by hand. That is one key's raw link, which
anyone who controls the key can set.

`retirePredecessorsOlderThan` retires the keys `keepFrom` descends from, by the rules of
`retirePredecessors`. It keeps `keepFrom` and every newer key. It refuses a `keepFrom` outside the
lineage (`KeyMismatchException`), or one whose keeping would cut a key off
(`StateConflictException`). Keep from an older key then.

`retirePredecessorsOlderThan` walks from `keepFrom`, 64 rotations either way. When
`retirePredecessors` refuses a lineage as too long, `newest.lineage()` refuses it too. Retire that
lineage in two steps:

1. Call `retirePredecessorsOlderThan` with a `keepFrom` at most 64 rotations from each end of the
   lineage. To choose it, call `kms.keys().handle(id).lineage()`, where `id` identifies a key
   nearer the middle. A record sealed under such a key gives its identifier
   (`KmsKeys.sealedKeyId`).
2. Call `retirePredecessors`. Its walk stops at the keys the first step destroyed.

Two steps reach a lineage of up to 128 rotations. For a longer one, first retire its oldest keys by
hand ([Rules for retiring by hand](#rules-for-retiring-by-hand)), until two steps reach the rest.

### Advanced: keys left by findOrCreate races

A `findOrCreate` that lost a race on a server without unique names leaves its key under the name,
usually Pre-Active. When the other key was found only after this call activated its own, that key
is Active. Something may use it, so `leftovers()` does not list it and it is never a candidate
for destruction. Left in place, such a key makes `findOrCreate` fail once the oldest key is purged.
`leftovers()` lists candidates: keys of the same kind, algorithm and length, with one of the
names, Pre-Active, never activated and without links.

A name proves nothing about who made a key, and another instance may be about to activate one.
So destroy a candidate only with independent evidence that your identity created it and nothing
uses it. Do this before retiring the oldest keys. `manifest` is your own record of the key
identifiers your identity created, for example from the server's audit log.

```java
KeyHandle newest = kms.keys().current("orders-kek").handle();
Set<String> ours = Set.copyOf(manifest.ids()); // independent evidence, not the name
for (KeyHandle candidate : newest.leftovers())
  if (ours.contains(candidate.id())) candidate.destroy();
```

## Approve a change first

Where a person or a change process approves a change before it is made, show what the SDK will
change, then make exactly that change. Each call below acts only on the keys the approval named.
When the server would change another key, or a key changed since the plan, it throws
`StateConflictException` whose `conflict()` is `NOT_AS_PLANNED`, and changes nothing. Then show a
new plan.

| Change | What to show | The call bound to it |
|---|---|---|
| Retire older keys | `newest.retirementPlan()` | `newest.retirePredecessors(reason, plan)` |
| Deactivate older keys | the Active keys of `newest.retirementPlan()` | `newest.deactivatePredecessors(reason, plan)` |
| Reconcile a name | `kms.keys().reconcilePlan(name)` | `kms.keys().reconcile(name, plan)` |
| Rotate if due, with a grace period | the current key | `current.rotateIfActiveForResult(period, rotation, current)` |
| Find or create, activating a staged key | the key the refusal names | `refusingPreActive()`, then `allowingPreActive(staged)` |
| Replace a compromised key | `key.compromisePlan()`: what it revokes, finishes, replaces in turn and creates | `key.replaceCompromisedResult(reason, plan)` |
| Replace a secret | `old.attributes()` | `registration.replaceResult(old, planned)` |

```java
ReconcilePlan plan = kms.keys().reconcilePlan("orders-kek").orElseThrow(); // reads only
log.info("keeps {}, deactivates {}", plan.winner().id(), plan.deactivated().size());
// after approval:
KeyHandle kept = kms.keys().reconcile("orders-kek", plan);
```

```java
KeyCreation creation = kms.keys().createAes(256).named("orders-kek")
    .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).refusingPreActive();
try {
  creation.findOrCreateResult();
} catch (StateConflictException e) {
  if (e.conflict() != StateConflictException.Conflict.STATE
      || e.observedState().orElse(null) != KeyState.PRE_ACTIVE) throw e;
  KeyHandle staged = kms.keys().handle(e.objectId().orElseThrow()); // show it; after approval:
  creation.allowingPreActive(staged).findOrCreateResult(); // activates it, or refuses another
}
```

The repeated call activates the approved key itself and returns it (`ACTIVATED`), so no step is
left between the approval and the result. When this call's own Create had an unknown outcome, a
Pre-Active key found then is not activated. It may be this call's or another caller's, so the
call throws that `OutcomeUnknownException`, with the refusal suppressed on it.

- The check is made once, before the first change. KMIP has no transactions, so a change
  another caller makes after it is not detected. Change a lineage from one place at a time.
- A planned key already deactivated or destroyed is skipped, so after a
  `PartialCompletionException` the same plan, or a new one, resumes.
- A rotation bound to its key still follows a rotation another caller makes after the check
  (`FOLLOWED`), and then schedules the grace period on the approved key.
- When a step's reply was lost and reading back found a key, the call does not claim that key.
  A later failure lists it in `PartialCompletionException.found()`, with that step in
  `recoveredFrom()`, never in `created()`, because this call or another caller made it. The
  results say the same on success. `FindOrCreateResult`, `RotationResult`, `CompromiseResult` and
  `ReplacementResult` each have `recoveredFrom()`, and attribute a change to the call only when
  its own reply confirmed it.

## Records older than 64 rotations

A handle opens a record by walking its lineage from its own key to the key the record names. It
costs one request per rotation crossed, and stops at 64 rotations. A record sealed more than 64
rotations before the current key is refused with `UnsupportedException`. That applies through the
current key's handle, a `CurrentKey` and `KeyQuery.byName`.

| Rotation period | 64 rotations |
|---|---|
| daily | 64 days |
| weekly | about 15 months |
| 30 days | about 5.3 years |
| 90 days | about 16 years |

Two ways keep old records in reach:

- Move them to the current key more often than every 64 rotations
  ([Move data to the new key](#move-data-to-the-new-key)).
- Open them by a binding you trust, so no walk is needed. It costs one Get Attributes and the
  Decrypt, whatever the record's age.

**Bind by an attribute Re-key copies.** KMIP's Re-key copies a key's custom attributes to its
replacement, so every key of the lineage carries the first key's attribute:

```java
CustomAttribute purpose = CustomAttribute.client("purpose");
KeyHandle kek = kms.keys().createAes(256).named("archive-kek")
    .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
    .custom(purpose, "archive")
    .findOrCreate();
// ... any number of rotations later:
byte[] plain = kms.keys().open(KeyQuery.all().custom(purpose, "archive"), sealed, recordId);
```

This is only as strong as the attribute. Anyone who can create a key with it can make records the
query opens. Use it where only your application's identity may set the attribute, and check that
your server's Re-key copies it ([Qualifying a server](production.md#qualifying-a-server)).

**Bind by a manifest of identifiers.** Record each new key's identifier where only the application
can change it, never from the records. `manifest` is that store.

```java
KeyHandle next = kek.rotateIfActiveFor(Duration.ofDays(30)); // in the rotation job
if (!next.equals(kek)) manifest.add(next.id());
// ...
byte[] plain = kms.keys().open(KeyQuery.all().ids(manifest.ids()), sealed, recordId);
```

`KeyQuery.byIds(previousId, currentId)` starts the same query from identifiers you list in code.
`ids(...)` adds them to a query you have, which keeps its other filters. The identifiers are
checked against the key the record names and never sent to the server. This relies on the server
never reusing an identifier. `decrypt`, `unwrapKey`, `opening` and `openTo` take the same queries.
Never trust the identifier a record names without a binding, because whoever made the record
chose it.

Retirement has the same limit. Retire regularly and a lineage never reaches it, because the walk
stops at a destroyed key. A longer lineage is retired in two steps
([Retiring part of a lineage](#retiring-part-of-a-lineage)).

## Moving a write name between keys

This is advanced. An operator moves a write name to a key created separately. A scheduled
rotation moves the name itself, so most applications never need it. An external tool that selects
its write key by name, as [`LocalKeys`](local-keys.md) does, moves it with `moveName`:

```java
Kms bounded = kms.withTimeout(Duration.ofSeconds(10)); // one deadline for every request below
bounded.keys().moveName("orders-write", oldId, newId);
```

`moveName` moves exactly that name and does nothing else. No key is activated, deactivated or
revoked, and whether `newId` suits the application is the tool's own check.

- It reads both keys, then sends one batch that deletes the name from `oldId` and adds it to
  `newId`. The batch is never re-sent. The other names of both keys are kept.
- The call reads both keys back and returns once `newId` holds the name and `oldId` does not. A
  refusal is thrown typed only when the reads find the original state. Anything else after the
  batch may have been sent is `OutcomeUnknownException`, whose message says what each key holds.
- **After an unknown outcome, read both keys before deciding what to do.**
- If only `newId` holds the name, the call returns without a mutation.
- The move is not a transaction. Run one operator at a time per name. A server that does not
  isolate the batch can briefly show readers no key with the name. keytend-kmip-server runs each
  request in one storage transaction. Qualify any other server for that.

## A compromised key

When a key is compromised, replace it, re-seal every record under the replacement, then destroy
it. `since` is the `Instant` from which the key may have been exposed.

```java
KeyHandle replacement =
    kek.replaceCompromised(RevocationReason.keyCompromise("key file leaked", since));
KeyHandle compromised = kek.allowingCompromised();
for (Record r : store.all())
  store.put(r.id(), compromised.rewrapTo(replacement, r.sealed(), r.aad()));
kek = replacement;
```

1. `replaceCompromised` revokes the key as Compromised and makes an Active replacement with the
   key's names, linked to it where the server allows. After a failure, do what its message says,
   usually repeat it. Run it from one place, like rotation.
2. The loop re-seals every record under the replacement with a fresh data key. It covers records
   of the compromised key and its older keys, and returns records already moved unchanged. Treat
   records sealed after `since` as possibly an attacker's.
3. Once no record names the compromised key, destroy it with
   `kms.keys().handle(id).destroy()`. If several replacements were made, run
   `kms.keys().reconcile(name)` first.

Where a responder approves the replacement first, show `kek.compromisePlan()` and pass it to
`kek.replaceCompromisedResult(reason, plan)`. The call acts on the keys the plan names and on no
other:

| Plan | What the call does to it |
|---|---|
| `revokes()` | revokes the key first, with your reason and date |
| `existingReplacement()` | finishes with it: activates it if it is Pre-Active, gives it the names |
| `replacedInTurn()` | replaces that Compromised descendant too, with one new key |
| `creates()` | creates the replacement |
| `unfinishedNameMoves()` | finishes name moves an earlier call stopped part-way, and removes their records |
| `otherDescendants()` | nothing else: other newest keys of a forked lineage stay as they are |
| `checkedForUnlinkedKeys()` | false when the server could not be searched for an earlier call's unlinked key. Look yourself (by `REPLACEMENT_RECORD`) before you approve |
| `unreadableCandidates()` | the objects that search found and could not read. Have them read with other credentials before you approve |

The plan refuses a newest descendant that cannot be the replacement, such as a Deactivated one.
It also refuses a key an earlier call created for the replacement and did not link
(`UNLINKED_REPLACEMENT`, and `objectId()` names it), because a second replacement would leave
that key unaccounted for. The plan finds such a key with a Locate by the client attribute
`x-keytend-replacement-of` (`CompromisePlan.REPLACEMENT_RECORD`). The plan cannot tell, and
`checkedForUnlinkedKeys()` is false, when the server:

- refuses that search (PyKMIP);
- ignores the filter;
- returns more than 256 objects;
- returns an object these credentials cannot read.

On PyKMIP that is every plan for a Compromised key without a replacement. An object
the search found and could not read is in `unreadableCandidates()`.

Such a key records that attribute. It is Pre-Active and unlinked, and is either named
`CompromisePlan.TEMPORARY_NAME_PREFIX` + the key's identifier + `-…` or has no name. Where the
server refused that call's links, it is Active instead, with the key's names. To look for the
Pre-Active ones yourself, with `key` the Compromised key whose replacement the earlier attempt was
creating:

```java
List<KeyAttributes> unlinked;
try (java.util.stream.Stream<KeyAttributes> staged =
    kms.keys().locateWithAttributes(
        KeyQuery.all().kind(ObjectKind.SYMMETRIC_KEY).state(KeyState.PRE_ACTIVE))) {
  unlinked =
      staged.filter(a -> key.id().equals(a.custom().get(CompromisePlan.REPLACEMENT_RECORD)))
          .toList();
}
```

A transient failure of the search, such as a lost reply, is thrown (`TransientException`) by the
plan and by the bound call, with nothing changed. It is never reported as a server that cannot be
searched, or as `NOT_AS_PLANNED`.

Before its first change, the call makes the plan again and compares it with yours
([what it compares](kms-design.md#compromised-keys)). When they differ, it throws
`StateConflictException` (`NOT_AS_PLANNED`) and changes nothing. Show a new plan for approval. A
step that fails stops the call, so a refused activation of the planned key is never followed by
a replacement of another.

Its `CompromiseResult` says:

- what the call did: `REPLACED`, `COMPLETED`, `EXISTING` or `RECOVERED`;
- whether this call revoked the key;
- the keys it replaced in turn;
- the step whose reply was lost, in `recoveredFrom()`: a Revoke, Re-key, Create or Activate;
- the Compromise Occurrence Date in effect.

An earlier responder's Compromise Occurrence Date stays, so treat data sealed since the earlier
date as an attacker's. A failure after the revocation is a `PartialCompletionException` that lists
the key in `deactivated()`. The key stays Compromised, and a new plan resumes, as the message
says.

The unbound `replaceCompromised` makes the same choice and acts on the same keys. It differs from
the bound call in three ways:

- It does not compare the changes with an approved plan.
- If another caller's replacement appears while it runs, it finishes with that key and activates
  only that key. This includes a replacement found while reading back a lost Re-key reply. The
  bound call stops in these cases.
- It does not look for an earlier call's unlinked key, which may be a key another caller is
  creating at that moment.

A Compromised key cannot seal new data. To open or read it for recovery, use
`allowingCompromised()`. The rotation calls refuse it too, so a scheduled job never replaces a
compromised key as routine.

At startup, `findOrCreate` fails with `StateConflictException` when the named key is
Compromised. Do not create a new key under the name. Records sealed under the old key would then
look misfiled. Replace it as above, or add `.replacingCompromised()` before `findOrCreate()`.
If the message says the key is Deactivated, someone retired it on purpose. Remove the name from
it with `kms.keys().handle(id).removeName("orders-kek")` before creating another.

### After a restart

A process that started with `.replacingCompromised().findOrCreate()`, or restarted after the
replacement, never held the revoked key's handle. It finds the revoked keys through the
replacement's own links. `quarantine` is your own list of records to examine by hand:

```java
KeyHandle current = kms.keys().createAes(256).named("orders-kek")
    .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
    .replacingCompromised()
    .findOrCreate();
Map<String, KeyHandle> compromised = new HashMap<>();
for (KeyHandle k : current.compromisedPredecessors()) compromised.put(k.id(), k);
for (Record r : store.all()) {
  KeyHandle from = compromised.getOrDefault(KmsKeys.sealedKeyId(r.sealed()), current);
  try {
    store.put(r.id(), from.rewrapTo(current, r.sealed(), r.aad())); // unchanged if under current
  } catch (StateConflictException | KeyMismatchException refused) {
    quarantine.add(r.id()); // names a key outside the trusted set
  }
}
```

`compromisedPredecessors()` returns the Compromised keys the current key descends from, nearest
first, each confirmed by both keys' links. Each is an `allowingCompromised()` view.

- Until a record is moved, opening it through the replacement or by name is a
  `StateConflictException` naming the compromised key. The data is not misfiled.
- A record that names some other Compromised key, or a key outside the lineage, goes to
  `current`, which refuses it. The loop quarantines it and goes on. Anyone who can create keys
  can name one like yours and revoke it.
- A record that fails to decrypt still ends the loop with a `CryptographicFailureException`. Its
  `kind()` tells a confirmed authentication failure from an ambiguous server error. Examine the
  record before a rerun.
- `KmsKeys.sealedKeyId(sealed)` names the key a record needs without contacting the server.

### Edge cases of a compromise

- Callers that run `replaceCompromised` at the same moment can each make a replacement. Then the
  [rules for several newest keys](#several-newest-keys) apply. The re-seal loop covers records of
  all of them.
- When a Re-key reply is lost, reading back cannot tell whether this call's Re-key or another
  caller's made the replacement it finds. The bound call stops with that unknown outcome, and
  activates, links and names none of the keys. The message names them, and a new plan shows them.
- In a forked lineage, the call finishes with one newest key and leaves the others
  (`otherDescendants()`). Join them with `reconcile()` from the replacement afterwards.
- For a key retired by hand and then found compromised, pass `Rotation.of(RotationDates.COPIED)`
  to `replaceCompromised`. Otherwise the replacement inherits the span from the old key's
  activation to its retirement as a cryptoperiod.

### A server that refuses Re-key

Where the server refuses Re-key, the call creates the replacement under a temporary name that only
it uses (`keytend-replacing-`, the compromised key's identifier and a random suffix). The client
attribute `x-keytend-replacement-of` on the replacement records which key it replaced.

When the Create's reply is lost, the call looks the name up. It goes on (`RECOVERED`) only when it
can confirm that the key it finds is the one it created
([how](kms-design.md#a-lost-create-or-register-reply)). Otherwise it stops. The message says what
the search found, or why it could not tell, and gives the name. When it found one object,
`objectId()` is that object. Look the key up before you repeat. A lost reply to the removal of the
temporary name is read back and is `recoveredFrom()`.

Where the server refuses both Re-key and links, the replacement is Active with the names but
unlinked, and the call throws `PartialCompletionException` naming both keys. Use the replacement,
and re-seal from the old key's own handle:
`kms.keys().handle(oldId).allowingCompromised().rewrapTo(...)`. Do not call `replaceCompromised`
again.

## Replacing a secret

Replace a password, token or other secret by registering the new value and moving the name to it.
`newPassword` is the new value, a `char[]`.

```java
KeyHandle old = kms.keys().findByName("db-password").orElseThrow();
KeyHandle current = kms.keys().registerSecret(newPassword).named("db-password").replace(old);
```

An Active old secret is deactivated, with a Revoke as superseded up to KMIP 2.1 and with the
Deactivate operation on the 3.0 draft. Instances that read the secret look it up again by name to
see the new value.

The old secret need not be Active. `replace` moves the name from it whatever its state, and
changes nothing else about it:

| The old secret is | After `replace` |
|---|---|
| Active | Deactivated, as superseded |
| Pre-Active (never used, such as a registration whose reply was lost) | Still Pre-Active (below the table) |
| Deactivated, for example past its Deactivation Date | Still Deactivated |
| Compromised | Still Compromised, readable by identifier for forensics |
| Destroyed | Refused, nothing registered: register the new secret under the name instead |

A Pre-Active old secret:

- KMIP has no transition from Pre-Active to Deactivated. Destroy the old secret if you do not
  keep it.
- With an Activation Date, it becomes Active by itself at that date. If that happens before the
  name moves, `replace` deactivates it as superseded. Otherwise it becomes Active later, without
  the name.

A secret that is not Active is not found by `findByName(name)`. Name its states:

```java
KeyHandle expired = kms.keys()
    .findByName("db-password", KeyState.DEACTIVATED, KeyState.COMPROMISED, KeyState.PRE_ACTIVE)
    .orElseThrow();
KeyHandle renewed = kms.keys().registerSecret(newPassword).named("db-password").replace(expired);
```

- To act only on the plan you showed, such as one an operator confirmed, pass the attributes it
  was made from: `replace(old, planned)`, where `planned` is the `old.attributes()` you read for
  it. The state and the Activation Date decide what happens to `old`. When another caller changed
  either meanwhile, the call is refused (`StateConflictException`, with the state it read) before
  anything is registered.
- Run one replacement per name at a time.
- On a server that allows a name once, a lookup during the request that moves the name finds
  nothing. Retry it.
- If a step fails, the `PartialCompletionException` says which secret has the name and how to
  finish.

The new secret is registered under a temporary name that only this call uses (`NAME.replacing-` and
a random suffix). When the Register's reply is lost, the call looks that name up, and goes on only
when it can confirm the object it registered ([how](kms-design.md#a-lost-create-or-register-reply)).
Otherwise it throws `OutcomeUnknownException` with nothing else changed, and the old secret keeps
the name. The message gives the temporary name and what the search found, or why it could not
tell. When it found one object, `objectId()` is that object. Check it before you repeat.
The same holds for keys and certificates `replace` registers.

To register a secret under a new name, add `refusingExistingName()` before `register()`. A name
that an object not destroyed has already is then refused with `AlreadyExistsException`, instead of
making a second secret that lookups by name do not choose. It is a check this client makes, so
only a server that enforces unique names stops two callers at the same moment.

How the SDK holds and wipes secret values is in [SECURITY.md](../SECURITY.md#handling-secrets).
