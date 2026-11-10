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

# Cassandra commit log and hints encryption (trial)

> [!WARNING]
> **Experimental: not for production use.** Trial code on the experimental keytend-kmip SDK. Do
> not use it to encrypt real data.

This is a `KeyProvider` for Apache Cassandra's transparent data encryption of the commit log and
hints. Its keys live in a KMIP server and are used through the SDK's
[`LocalKeys`](../../docs/local-keys.md). It is trial code for Apache Cassandra trunk at `275a3a5`,
with the four Cassandra patches in [`patches/`](patches). It is built separately, is not part of
the SDK artifact, and the SDK has no Cassandra dependency.

Each new file records the exact KMIP identifier of its key. An operator tool, `KmipTool`,
creates, rotates, scans for and retires the keys from one place. How a key provider for
transparent data encryption uses `LocalKeys` is in
[Transparent data encryption keys](../../docs/local-keys.md#transparent-data-encryption-keys).
What Cassandra must change for it is in [The Cassandra patches](#the-cassandra-patches).

## Before you use it

- **Trial, not qualified for production.** It is tested on a two-node in-JVM cluster against one
  real KMS product. Separate-process nodes, other KMS products, performance and long outages are
  not tested.
- **The commit log reuses its IV.** Upstream Cassandra initializes a segment's CBC cipher once.
  `doFinal` resets it to the same IV for every chunk of the segment. This is from source
  inspection, not tested. The patches do not change it.
- **A long KMS outage stops writes.** Once an outage outlasts the shorter of `key_cache_ttl` and
  the key's lease on a node, no segment on that node can get its key, and its
  `commit_failure_policy` applies.

> [!WARNING]
> Do not deactivate a key that open files still need: an open commit log segment under it stops
> within one TTL. On a server that leases only Active keys, a node also cannot replay the files
> under it, so it cannot start.

## When to use it

- You run Cassandra trunk and want commit log and hints keys held in a KMIP server.
- You can apply four patches to Cassandra and build it yourself.
- You want to try per-file key identifiers, lease-bounded key use and KMS-driven rotation.

## Requirements

- Apache Cassandra trunk at `275a3a5`, with the four patches applied.
- A JDK 17, Apache Ant and git.
- The SDK, built from this repository (below).
- A KMIP server. The live test uses keytend-kmip-server 0.10.0-rc.1, the pinned build, through
  Podman, as [tools/kmip-server](../../tools/kmip-server/README.md) describes.

## Build and run

From the repository root. The Cassandra checkout goes beside it, in `../cassandra-trunk`.

```sh
JAVA17_HOME=/path/to/jdk-17
export JAVA_HOME=$JAVA17_HOME PATH=$JAVA17_HOME/bin:$PATH
git clone https://github.com/apache/cassandra.git ../cassandra-trunk
git -C ../cassandra-trunk checkout 275a3a5
for p in integration/cassandra-trunk-tde/patches/000*.patch; do
  git -C ../cassandra-trunk apply "$PWD/$p"
done
(cd ../cassandra-trunk && ant jar build-test)
./mvnw -B -ntp -pl sdk,testing -am package -DskipTests
integration/cassandra-trunk-tde/build.sh ../cassandra-trunk sdk/target/keytend-kmip-0.10.0-rc.1.jar
```

`build.sh` checks that every patch is applied to the checkout and built into its jar, and stops
otherwise. It compiles the provider and writes `target/keytend-kmip-cassandra-trunk-tde.jar`. It
runs the standalone tests and compiles the dtest against the checkout's test classes. It writes
nothing outside `target/` without `--install`. The standalone tests use the in-memory KMIP server,
`testing/target/keytend-kmip-testing-<version>.jar` (or `KEYTEND_TESTING_JAR`), which is never
installed.

To run the bounded test run, including the live dtest against two keytend-kmip-server
containers, load the pinned image first, as in
[tools/kmip-server](../../tools/kmip-server/README.md#build-and-run), which downloads it to
`/tmp/kts`. Then:

```sh
integration/cassandra-trunk-tde/run-trial.sh ../cassandra-trunk \
  sdk/target/keytend-kmip-0.10.0-rc.1.jar /tmp/tde-run \
  /tmp/kts/release/linux-amd64/keytend-kmip-server-0.10.0-rc.1.docker.tar
```

```text
integration/cassandra-trunk-tde/build.sh CASSANDRA_DIR SDK_JAR [--install]
integration/cassandra-trunk-tde/run-trial.sh [--server-unpinned] CASSANDRA_DIR SDK_JAR OUT
    [SERVER_IMAGE [VERSIONS [LEASE_STATES]]]
```

- `--install` copies the SDK jar and the provider's jar into the checkout's `lib/` and
  `build/lib/jars/`. It replaces only an SDK jar and this provider's jar there. It also copies
  `cassandra-tests/` into the checkout's `test/unit` and `test/distributed`.
- `run-trial.sh` runs `build.sh --install`, then one `ant testsome` per test class: the hints
  test and the upstream tests of the code the patches change. With `SERVER_IMAGE` it also runs
  the dtest `KmipTdeRotationTest`.
- `OUT` must be new or empty. It gets `PROVENANCE.txt`, one log per suite, the servers' logs
  under `kms/`, and `SUMMARY.txt`.
- `SERVER_IMAGE` is the release's Docker archive or an image already loaded. Nothing runs unless
  it is the pinned image, or `--server-unpinned` is given. `PROVENANCE.txt` then says `UNPINNED`.
- `VERSIONS` defaults to `1.4,2.1,3.0`. `LEASE_STATES` is the server's `--lease-states`,
  `active-deactivated` by default.
- The dtest's servers are a replica and its standby on one store, the two `kmip_endpoints`. The
  server locks its store, so the standby starts only when the dtest kills the replica.
- The dtest's servers have a Lease Time of 120 s. They are stopped and removed when the script
  ends, however it ends.

On a node, put both jars in `lib/` and configure `cassandra.yaml` as below.

### The Cassandra patches

A key provider can only hand keys out. Honoring a key's TTL and lease also needs the database to
follow five rules, and Cassandra needs core changes for them. The patches are `git format-patch`
files against trunk `275a3a5`. Every new path runs only when the provider's `keysMayBeCached()` is
false, so providers that keep the defaults, such as `JKSKeyProvider`, behave as before.

1. The database keeps no key or cipher beyond one handout (0002). An authorization is checked only
   when a key is handed out, so a key or initialized cipher the database keeps escapes it.
   `KeyProvider` gains `keysMayBeCached()`. For a provider that returns false, `CipherFactory`
   caches no key or cipher. Each file gets its key from the provider and a fresh random IV, and the
   key is destroyed once its cipher is initialized.
2. A new file gets its alias and key in one handout (0002). `KeyProvider.keyForNewFile(alias)`
   returns both. `EncryptionContext` uses it for new commit log segments and hints files.
3. An open file asks for its key per chunk (0002, 0003). `KeyProvider.keyForAppend(alias)` hands
   out an open file's own key. A segment asks for it before each section it encrypts, and a hints
   file before each flush. A file that kept one cipher for its whole life would keep writing after
   its key's lease or TTL ended. The commit log cannot roll a segment when its key is refused, so a
   refusal stops its writes. See
   [Writers that cannot start a new file](../../docs/local-keys.md#writers-that-cannot-start-a-new-file).
4. Hints fail closed (0003). Hints are encrypted when encryption is enabled and hints are not
   compressed. A new hints file whose key cannot be had is not written unencrypted.
   `HintsDescriptor` throws instead. A file being read gets its decryptor when it is read, not when
   it is listed.
5. A key outage is not corruption (0003). A file whose key the KMS cannot give now, or refuses, is
   intact. `HintsReader` and hint dispatch keep it for the next dispatch. Unpatched, the file failed
   its checksum and was marked corrupt and deleted.

Two more patches support the integration:

- **0001, commit log disk access mode.** Trunk chooses the mode before the encryption context
  exists, so it could pick a direct-I/O mode an encrypted segment cannot use. The patch counts
  encryption from the configuration.
- **0004, metric group.** Adds the `Kmip` metric group. Without it the provider works, but logs
  that its gauges are not registered.

### Layout

| Path | What it is |
| --- | --- |
| `src/main/java/.../tde/KmipKeyProvider.java` | the `key_provider`; one `LocalKeys` cache per configuration |
| `src/main/java/.../tde/KmipConnections.java` | the KMS connection parameters and the `KmsConfig` |
| `src/main/java/.../tde/KmipMetrics.java` | the gauges `KeyUsableForSeconds` and `WriteKeyFailing` |
| `src/main/java/.../tde/KmipTool.java` | the operator's commands |
| `patches/` | the four Cassandra patches |
| `src/test/java/...` | standalone tests, without a node, against the in-memory server |
| `cassandra-tests/unit/.../HintsKeyUnavailableTest.java` | the hints side of the patches, without the SDK |
| `cassandra-tests/distributed/.../KmipTdeRotationTest.java` | the in-JVM dtest against keytend-kmip-server |
| `qual/` | the dtest's throwaway PKI and its server replica and standby |
| `build.sh`, `run-trial.sh` | build and test; the bounded test run with the live dtest |

## Configuration

In `cassandra.yaml` on each node:

```yaml
transparent_data_encryption_options:
  enabled: true
  chunk_length_kb: 64
  cipher: AES/CBC/PKCS5Padding
  key_alias: cassandra-tde            # the KMIP Name; each file records <name>#<unique identifier>
  key_provider:
    - class_name: dev.keytend.kmip.cassandra.tde.KmipKeyProvider
      parameters:
        - kmip_endpoints: kms1.example:5696,kms2.example:5696
          kmip_client_certificate: /etc/cassandra/kms/node.pem
          kmip_client_key: /etc/cassandra/kms/node.key
          kmip_trust_certificates: /etc/cassandra/kms/kms-ca.pem
          kmip_call_timeout: 10s
          kmip_startup_timeout: 5s
          key_cache_ttl: 10m          # the longest a node uses a key without the KMS
          key_cache_refresh: 1m
```

These parameters, and the credential files they name, are node-local. There is no separate
connection file.

| Parameter | Default | Meaning |
| --- | --- | --- |
| `kmip_endpoints` | required | `host:port,...`, replicas of one KMS |
| `kmip_client_certificate` | required | PEM file of the node's KMS client certificate |
| `kmip_client_key` | required | PEM file of its key, or the same combined PEM file |
| `kmip_client_key_password` | none | the password of an encrypted client key |
| `kmip_trust_certificates` | required | PEM of the KMS's CA |
| `kmip_min_version`, `kmip_max_version` | the SDK's | `1.4`, `2.1` or `3.0` |
| `kmip_call_timeout` | `10s` | the longest one KMS call, and so one segment allocation, waits |
| `kmip_reload_credentials` | `true` | re-read the client files when they change; replace them atomically |
| `kmip_startup_timeout` | `0s` | how long the first connection keeps trying an unreachable KMS |
| `key_bits` | any AES length | the AES key length the keys must have |
| `kmip_key_family` | `key_alias` | use only keys whose attribute `x-cassandra-tde` has this value |
| `key_cache_ttl` | `10m` | how long a key is handed out without the KMS confirming it |
| `key_cache_refresh` | half the TTL | when a used key is confirmed in the background |
| `key_cache_capacity` | `64` | keys kept, including the write key and the open files' keys |

`key_alias` is the KMIP Name of the write key and must not contain `#`. The keys must be AES,
permit Encrypt and Decrypt, be Extractable, and carry the family attribute. `KmipTool key-create`
makes them so.

### Node credentials

A node's credential needs only Discover Versions, Locate, Get Attributes, Get and Obtain Lease.
It must not be able to create, rotate, revoke or destroy keys, or change their family attribute.
Rotation and retirement run with the operator's credential. Other consumers' credentials are in
[What each consumer's credential needs](../../docs/production.md#what-each-consumers-credential-needs).

### Monitoring

The gauges need patch 0004. They are
`org.apache.cassandra.metrics:type=Kmip,scope=<key_alias>,name=...`:

- **`KeyUsableForSeconds`:** how long new segments and hints files can still get their key
  without the KMS. Alarm when it falls below the time you need to restore the KMS while
  `WriteKeyFailing` is 1. It is also 0 before the first file, and on a node that has written
  nothing for a TTL.
- **`WriteKeyFailing`:** 1 while the write key's last validation failed, else 0.

The SDK logs for the provider, under its fixed loggers
([Logging](../../docs/production.md#logging)): "LocalKeys ... moved its write key from ... to
..." at each change of write key (INFO, `dev.keytend.kmip.kms.LocalKeys`), refresh failures and
unavailable endpoints at most once a minute (WARN, `dev.keytend.kmip.kms.LocalKeys` and
`dev.keytend.kmip.kms.Endpoints`), TLS reloads (`dev.keytend.kmip.kms.Tls`). Cassandra itself
logs "Closing hints file ..., which can no longer be appended to" and "Cannot dispatch hints
file ... now". In `logback.xml`:

```xml
<logger name="dev.keytend.kmip" level="INFO"/>
```

## Operating it

### How it behaves

- A new file records `<key_alias>#<unique identifier>` in its header. Replay and delivery read
  exactly that key, whatever the name points to by then. An alias without an identifier, with
  another key name, or outside the family is refused.
- A segment asks for its key before each section it encrypts. A hints file asks before each flush. A
  key that may no longer encrypt stops the open files under it within one TTL. An open segment then
  fails, and `commit_failure_policy` applies. An open hints file is closed, and hints go on in a new
  file under the current key.
- Cassandra keeps no key or cipher between files for this provider, so no key outlives its
  authorization. An open file's cipher holds its key schedule until the file closes or its next
  section initializes it again.
- A node needs the KMS to start. It replays its encrypted segments, each with its own key, and
  writes new ones. A start with the KMS down is not tested.
- Cassandra gives key providers no shutdown call. The caches stay open to the end, so the last
  commit log sections still get their key.

### Run KmipTool from one place

Run `KmipTool` with the operator's KMS credential, never from the nodes. `--yaml` reads the
`key_provider` parameters of a `cassandra.yaml` that names the operator's credential. `-p` sets
or overrides one parameter. From a Cassandra installation with both jars in `lib/`:

```sh
java -cp 'lib/*' dev.keytend.kmip.cassandra.tde.KmipTool --yaml ops/cassandra.yaml \
  key-status cassandra-tde
```

Below, `KmipTool` stands for `java -cp 'lib/*' dev.keytend.kmip.cassandra.tde.KmipTool --yaml
ops/cassandra.yaml`.

```text
KmipTool [--yaml FILE] [-p NAME=VALUE]... COMMAND ARGS
  key-create NAME [BITS] [FAMILY]       create and activate an extractable AES key
  key-status NAME                       the key's lineage, newest first
  key-rotate NAME [IF_ACTIVE_FOR]       a new key for new files; the old one stays Active
  key-scan DIR...                       the keys that segment and hints headers name
  key-retire NAME SCAN_OUTPUT...        destroy the older keys that no node's scan names
  key-replace-compromised NAME SINCE    revoke as compromised and activate a replacement
  key-revoke-compromised NAME ID SINCE  revoke an older key of the lineage as compromised
```

### Server policy

- **Lease Time** is the longest a node rides out a KMS outage. `key_cache_ttl` bounds it further.
  On keytend-kmip-server it is `--max-lease-seconds`, 3600 s by default. See
  [Leases](../../docs/local-keys.md#leases).
- **Leased states.** keytend-kmip-server leases Active and Deactivated keys by default. With
  `--lease-states active` it leases only Active keys, so the files under a Deactivated key
  cannot be read at all ([Leases](../../docs/local-keys.md#leases)).

### Provision and rotate

1. Provision once with `KmipTool key-create cassandra-tde 256`. This makes an extractable
   AES-256 key named `cassandra-tde`, Active, with the family attribute. Nodes never create keys.
2. Configure every node as above, and start them.
3. Rotate with `KmipTool key-rotate cassandra-tde 30d`. With a period it rotates only if the
   current key has been Active that long. No grace period is set, so the old key stays Active.

New files move to the new key at the first key use after `key_cache_refresh`. Open segments and
hints files finish under the old key. Confirm each node with its "LocalKeys ... moved its write
key" line, or with `key-scan` of the newest files. Nothing proves that every node has switched.

### Retire old keys

Retirement revokes and destroys keys. It cannot be undone.

1. On every node, let the segments under the old key be recycled. Run `nodetool flush`, wait for
   the commit log to recycle them, and let the hints drain.
2. On each node, run `KmipTool key-scan <commitlog_directory> <hints_directory> > nodeN.scan`.
   It reads only file headers and sends nothing.
3. Run `KmipTool key-retire cassandra-tde node1.scan node2.scan ...` with every node's scan.

`key-retire` keeps the oldest key any scan names and every newer one. It destroys only older
keys. It refuses, destroying nothing, if a scan names a key outside the name's lineage.

- A node whose commit log names a destroyed key cannot replay it, so it cannot start. Retire
  only after the scans.
- Retire only once no snapshot or backup of the commit log or hints that you keep needs the key.

### A compromised key

`KmipTool key-replace-compromised cassandra-tde 2026-11-01T00:00:00Z` revokes the key the name
points to as compromised at once, and activates a replacement under the name. The time is when
the key is considered compromised. For an older key of the lineage, use
`KmipTool key-revoke-compromised cassandra-tde <its id> 2026-11-01T00:00:00Z` instead. It
revokes that key at once and creates no replacement. Then:

- every node with a segment open under the key stops its commit log within one TTL;
- open hints files under it are closed, and hints continue under the key the name points to;
- files under the key cannot be read, because `LocalKeys` refuses Compromised keys. A restarted
  node cannot replay such segments. Recover their data from replicas with repair.

The commit log cannot end a segment early, so revoking first trades availability for
confidentiality. The order, and why, is in
[Writers that cannot start a new file](../../docs/local-keys.md#writers-that-cannot-start-a-new-file).
To keep writes up instead:

1. Find each compromised key in `KmipTool key-status cassandra-tde` and note its identifier. If
   the first line, the key marked `newest`, is not one of them, the name already points to a
   clean key. Skip step 2.
2. `KmipTool key-rotate cassandra-tde`, so new files move to the replacement.
3. A rolling `nodetool drain` and restart of every node, which closes the open segments.
4. `KmipTool key-revoke-compromised cassandra-tde <old id> 2026-11-01T00:00:00Z` for each of
   them. It revokes only the key it is given, and refuses the key the name points to or a key
   outside its lineage.
5. Repair anything only the revoked keys' files held, and truncate those hints.

> [!WARNING]
> Do not use `key-replace-compromised` at step 4. After the rotation the name points to the new
> key, so it would revoke that one and leave the compromised key Active.

See also [A compromised key](../../docs/operating-keys.md#a-compromised-key).

### KMS outage

- Nodes keep writing, open segments included, until min(TTL, lease) after their last successful
  validation.
- After that, segment allocation and sections fail on every node, and `commit_failure_policy`
  applies.
- New hints files cannot be opened. Hints whose flush fails then are lost. This is from reading
  the code, not tested. Run repair after such an outage.
- Hints files whose key cannot be had at delivery are kept and retried at the next dispatch.
- Restart nodes only while the KMS is reachable.

Size the TTL and the Lease Time for the outages you must ride out. Run the KMS replicated, and set
the alert described in [Monitoring](#monitoring).

## Rewriting SSTables under a new key

This integration encrypts the commit log and hints only. No SSTable adapter is included. This
section is the pattern an SSTable adapter built on `LocalKeys` would follow to move a table to a
new key.

The adapter must:

- initialize the cipher from the cache for each chunk it writes or reads, so that every chunk is
  authorized (`forEncrypt()` to write, `forDecrypt(id)` to read);
- write the key's immutable identifier into a fixed-size header, and read with exactly that
  identifier, never a name;
- share the node's one `LocalKeys` cache with the other table providers, and add no key or
  authorization cache of its own;
- keep key failures apart from corruption. A KMS outage or a denial fails the read or the
  startup explicitly. It never marks an intact SSTable corrupt, nor silently leaves it out of
  reads.

Test the database's reader and startup paths for that last rule, not only the adapter.

With such an adapter, an operator moves a table to a new key in four steps:

1. Provision a replacement in the same scope, and move the write name to it with
   `kms.keys().moveName(name, fromId, toId)`. See
   [Moving a write name between keys](../../docs/operating-keys.md#moving-a-write-name-between-keys).
   That call sends one ordered batch and reads both keys back. It changes no lifecycle state. Do not
   remove the name and add it again in two steps. In between, no key has the name and writes fail.
   Removing the name from the old key is enough to stop new writes under it. On a server that leases
   only Active keys, keep the old key Active, with no Deactivation Date or Protect Stop Date.
2. Wait for the next refresh on each node, within `refreshAfter` and at most the TTL, and confirm
   each node's selection. `localKeySelected` and `currentWriteId()` show it. Do not invalidate
   during live flushes. A write in progress then fails. `currentWriteId()` is a local snapshot, not
   a cluster barrier.
3. Rewrite the SSTables. Run this on every relevant node, then check that no rewritten chunk names
   the old key's identifier:

   ```sh
   nodetool upgradesstables -a orders_keyspace orders
   ```

4. Deactivate the old key only after the rewrites and the scans, with `KeyHandle.deactivate()`
   ([what it sends](../../docs/kms-design.md#version-normalization)). On a server that leases only
   Active keys, the cache cannot then decrypt anything still under it, and no client setting
   bypasses that. Remove historical access, or destroy the key, only after every required copy has
   migrated.

keytend-kmip-server applies the `moveName` batch so that concurrent lookups see the name only
before or after the move. Other servers may not isolate the batch from concurrent requests.
Qualify that before relying on it, and run one operator at a time.

Snapshots, backups, open readers, commit logs and hints are outside this rewrite. Account for
them before destroying a key. A compromise is an incident, not a routine rotation
([Keys revoked as Compromised](../../docs/local-keys.md#keys-revoked-as-compromised)).

## Limits

- Only the commit log and hints are encrypted, not SSTables
  ([Rewriting SSTables under a new key](#rewriting-sstables-under-a-new-key)).
- Cassandra gives `KeyProvider` no `close()`, so caches live until the process ends. If Cassandra
  adds one, providers must close after the commit log and hints writers.
- Hints may be lost during a long outage. Run repair afterwards.
- This sample is tested only on the pinned Apache Cassandra trunk revision.

## Tested

```text
Cassandra:  Apache Cassandra trunk 275a3a5, with the four patches
JDK:        17
KMS:        the in-memory server, keytend-kmip-testing (standalone tests);
            keytend-kmip-server, the pinned image, a replica and its standby (dtest)
KMIP:       1.4, 2.1 and 3.0
Scope:      standalone tests, the upstream tests of the patched code, and the two-node dtest,
            under both --lease-states active-deactivated and active
```

The release checks do not build Cassandra. The dtest's latest result, with its date and the
server build it ran against, is kept in the source tree's `validation/recorded/live-server.json`,
which each release's binary ZIP carries
([Recorded results](../../docs/releasing.md#recorded-results)). A release cannot be packaged
unless that result is of the pinned server build. When the pin moves, record it again, from the
repository root:

```sh
tools/record-live.sh cassandra-dtest --server <the pinned Docker archive or image> \
  --cassandra ../cassandra-trunk
```

It runs `run-trial.sh` under both `--lease-states` settings and replaces the entries. A missing
`../cassandra-trunk` is cloned, patched and built as above.

The dtest creates a key, rotates it while a segment stays open, and kills the KMS replica so that
its standby takes over. It reloads a node's client certificate, restarts and replays through both
keys, and delivers hints. It then retires the old key, and checks that a deactivated key's hints
file is closed.

The standalone tests run `KmipTool`'s `key-rotate`, `key-retire`, `key-replace-compromised` and,
after a rotation, `key-revoke-compromised`.

Not tested: a node started with the KMS down, an outage longer than min(TTL, lease) on a running
cluster, the compromise order for writers that cannot roll on a running cluster, `KmipTool` as a
separate process, Cassandra built without patch 0004, separate-process nodes, more than two
nodes, other KMS products, and performance.

To reproduce, run the commands in [Build and run](#build-and-run), with the server image.
