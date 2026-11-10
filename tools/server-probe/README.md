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

# Live probe against keytend-kmip-server

`ServerProbe` checks the application API's key lifecycle against a real keytend-kmip-server. It
covers rotation, retirement, names, raw-key leases and TLS identities, plus a few protocol-layer
controls. No Maven module or test runs it. The release checks run it when given the server image
(`--server`).

## When to use it

- Before a release: `tools/release-check.sh --server DOCKER-TAR` runs `all` on KMIP 1.1, 1.2,
  1.4, 2.1 and 3.0 under the server's defaults and its other settings.
- To check an SDK build, or a new server image, before you change the
  [pin](../kmip-server/README.md).
- To see how the server answers a lifecycle path you depend on.

## Requirements

- A JDK 17 or later, `openssl` and `python3` on the `PATH`.
- Podman and the pinned keytend-kmip-server image, loaded as
  [tools/kmip-server](../kmip-server/README.md) describes.
- An SDK jar and slf4j-api, which `./mvnw package` copies to `sdk/target/lib/`.

## Build and run

From the repository root, after loading the pinned image:

```sh
./mvnw -B -ntp -pl sdk -am package -DskipTests
tools/server-probe/run.sh --jar sdk/target/keytend-kmip-0.10.0-rc.1.jar
```

This probes KMIP 1.1, 1.2, 1.4, 2.1 and 3.0 with every scenario in `all`, which is every
scenario. In `all`, `tls-issue-repeat` runs from KMIP 1.4 and reports `SKIP` at 1.1 and 1.2,
whose calls send the same writes as 1.4; named, it runs at every version given. To run one
scenario on fewer versions:

```sh
tools/server-probe/run.sh --jar sdk/target/keytend-kmip-0.10.0-rc.1.jar \
  --scenarios tls --versions "1.4 2.1 3.0" --work /tmp/server-probe
```

```text
tools/server-probe/run.sh [--jar SDK_JAR] [--versions "V ..."] [--scenarios all|NAME,...]
    [--work DIR]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--jar` | the first `sdk/target/keytend-kmip-*.jar` | the SDK jar to probe |
| `--versions` | `"1.1 1.2 1.4 2.1 3.0"` | KMIP versions, one server per version |
| `--scenarios` | `all` | comma-separated scenario names (below), or `all` |
| `--work` | a new `/tmp/server-probe.*` directory | PKI, stores and logs |

`run.sh` makes a throwaway PKI and a master key in the work directory. For each version it
starts the pinned image with `serve --experimental-v3` on a fresh store and free loopback ports.
It runs `ServerProbe` pinned to that version, then removes the container, also on exit or
interrupt. The logs are `<work>/v<version>/probe.log` and `server.log`.

`ServerProbe` also runs against a server you started. The PKI directory holds `ca.pem`,
`client.pem` and `client.key`.

```sh
java -cp 'sdk/target/keytend-kmip-0.10.0-rc.1.jar:sdk/target/lib/*' \
  tools/server-probe/ServerProbe.java --endpoint 127.0.0.1:5696 --version 3.0 --pki /path/to/pki
```

### Scenarios

| Scenario | What it checks |
| --- | --- |
| `grace` | rotation with a grace period, and old records opened after each step |
| `deactivate-predecessors` | `deactivatePredecessors` and reads afterwards |
| `reconcile` | `reconcile`, and an attempt to fork the lineage |
| `retire` | `retirePredecessors` after rewrapping |
| `low-level` | KMIP 3.0 Deactivate, Revoke and Re-key at the protocol layer |
| `legacy` | the KMIP 1.1 and 1.2 Compromise Occurrence Date rule |
| `sdk-deactivate` | `deactivate()` leaves a key Deactivated. Old records still open, sealing is refused |
| `protection` | `extractable(false)` keys and `LocalUse` (KMIP 1.4 and later) |
| `names` | a name in use on every path that adds one |
| `raw-leases` | the lease rule for raw keys, Active then Deactivated |
| `tls` | `kms.tls()` identities, followers, renewal, re-key, revocation and leases |
| `tls-issue` | identities the KMS issues with Certify: an issuer the probe registers, issue, same-key and new-key reissue, the requested validity, and an issue without an issuer |
| `tls-issue-repeat` | an issue, a same-key reissue and a new-key reissue each stopped four ways at every write, then repeated from a new `Kms`: the end state, followers and leftovers (in `all` from KMIP 1.4) |

## Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `KEYTEND_SERVER_IMAGE` | the pinned image | another image; it runs only with `KEYTEND_SERVER_UNPINNED=1` |
| `KMIP_*` | none | passed to the server, such as `KMIP_LEASE_STATES=active` |

Two server policies change what some scenarios observe. Both pass.

```sh
jar=sdk/target/keytend-kmip-0.10.0-rc.1.jar
KMIP_DESTROYED_NAME_REUSE=reserve tools/server-probe/run.sh --jar "$jar"
KMIP_LEASE_STATES=active tools/server-probe/run.sh --jar "$jar"
```

Run `raw-leases` with `KMIP_MAX_LEASE_SECONDS=0` too. The server then states a Lease Time of 0,
which means no limit.

## Output

Each observation is one line:

- `PASS` or `FAIL`: against what the SDK documents, or the KMIP rule the step names.
- `INFO`: recorded only, such as the server's answer to a protocol-layer request.
- `SKIP`: the scenario does not apply to this version.

An exception shows its class, category, result reason, observed state and message. Each version
ends with a `SUMMARY` line. `run.sh` exits 1 when any version reports a `FAIL`.

### What some scenarios accept

- **`names`.** At KMIP 1.4 the server answers Illegal Operation to Add Attribute of a name in
  use. The SDK must still throw `AlreadyExistsException` naming the holder.
- **`raw-leases`.** A server that leases only Active keys refuses a Deactivated key's lease. The
  SDK must report that as the key's state (`StateConflictException`, `operation()`
  `obtainLease`). Under the server's default the Deactivated key is leased and read (`INFO`).
- **`protection`.** A server that refuses or drops Extractable passes when the SDK refuses as
  documented. It is recorded as `INFO`.
- **`tls`.** The probe makes its own PKI in code, with CA Key Usage keyCertSign and cRLSign. It
  registers the anchor without usages, so they come from its Key Usage. A destroyed identity's
  name is refused under `KMIP_DESTROYED_NAME_REUSE=reserve` and reusable under `allow`. Re-keying
  a destroyed identity is refused either way.
- **`tls-issue`.** The probe registers its issuing CA with its own credentials, which then own
  it, as keytend-kmip-server's Certify requires. The requested validity passes when the server
  honors it, as keytend-kmip-server does, also on a same-key reissue, or when the SDK refuses the
  certificate (`UnsupportedException`) because the server ignored it, as earlier builds do. A
  validity past the issuing CA's notAfter must be refused before anything is made
  (`InvalidRequestException`). An issue without an issuer passes when the server refuses it
  (keytend-kmip-server has no CA of its own) and the key pair is reported left over.
- **`tls-issue-repeat`.** Each call stops at its first write, then at its second, and so on until
  it completes. A write is a request that changes an object (Create Key Pair, Certify, Activate,
  Add, Set or Delete Attribute, Revoke and the like). It stops four ways, through a transport
  wrapper: the process stopping dead (an `Error` nothing catches), or the connection dropping
  (an `IOException`), each before the server sees the write or after it answered. A new `Kms`,
  with a handle it read before the call, then repeats the call. The repeat must reach the end
  state of a call that did not stop: the identity's leaf, key and public key, and what a reissue
  replaced, each with the same state, names and links. A later reissue of the result must
  succeed. A follower of the name, refreshed after every write, after the stop and after the
  repeat, must present nothing or a certificate with its own key, and the new leaf after the
  repeat. What the stopped call made and the identity does not hold must be left over as
  [What a stopped call leaves](../../docs/tls-identities.md#what-a-stopped-call-leaves) says:
  not Active (but a private key no Active certificate certifies), named only with the call's
  temporary name, not linked from the identity's leaf or key, and named by the exception when the
  call threw and the client had seen it. On a same-key reissue, Certify links the identity's
  public key to the leftover certificate. The scenario takes that link out of the comparison and
  counts it.
- **How long `tls-issue-repeat` takes.** About three minutes a version: 44 stops four ways, each
  followed by a repeat.
- **`tls` leases.** A Protect Stop Date caps the next lease, which then runs out. Under
  `KMIP_LEASE_STATES=active` the next lease is refused and nothing is presented. Under the
  default the server leases the key again and the identity is presented again.

## Limits

- One server product, on loopback, one version at a time.
- The probe checks documented behavior, not performance or long outages.
- Server-specific answers are recorded as `INFO`, not judged.

## Tested

The release checks run `all` against the pinned image at KMIP 1.1, 1.2, 1.4, 2.1 and 3.0, on the
SDK JAR of the release's distribution build, with JDK 17, under the server's defaults, under
`KMIP_DESTROYED_NAME_REUSE=reserve` and under `KMIP_LEASE_STATES=active`, and `raw-leases,tls` at
1.4, 2.1 and 3.0 under `KMIP_MAX_LEASE_SECONDS=0`
([the release checks](../../docs/releasing.md#the-release-checks)). `all` includes `tls-issue`,
`tls` and `tls-issue-repeat` (from 1.4). Every version must report `fail=0` and exit 0.

Each release's binary ZIP holds the latest result of each scenario set, setting and version in
`validation/live-server.json`, with each scenario's counts, and each version's `probe.log` in
`validation/server-probe/` (`server-probe-name-reuse-reserve/`, `server-probe-lease-states-active/`
and `server-probe-max-lease-0/` for the other settings)
([Where the results are](../../docs/validation.md#where-the-results-are)).
To run them yourself: `run.sh --scenarios tls-issue,tls --versions "1.4 2.1 3.0"` and
`run.sh --scenarios tls-issue-repeat --versions "1.4 2.1 3.0"`.
