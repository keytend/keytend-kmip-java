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

# Interoperability catalog

The catalog is a set of 145 interoperability cases, written by the Keytend project with the
tests that run them. Its manifest is `integration/catalog/catalog.json`
([catalog files](../integration/catalog/README.md)). `CatalogContractTest` verifies the
manifest's checksum. It also checks that every case ID has a scenario in the live suite or the
controlled-peer suite.

A scenario can record a missing prerequisite instead of a result. What the catalog covers is in
[Validation](validation.md#shared-catalog). Each release's results are in its binary ZIP
([Where the results are](validation.md#where-the-results-are)), and the outcomes are explained in
[How to read the results](validation.md#how-to-read-the-results).

## What a record holds

The live runner writes one record per case for each server, build, version and JDK. A record
holds:

- the runtime and security providers;
- the source revision, source-tree hash, image and configuration identity;
- the wire version, negotiated TLS version, identity, namespace, seed and parameters;
- the timing, the outcome and its evidence.

Records never contain key bytes, passwords or private keys. Controlled peers run separately and
never qualify a vendor.

## Targets

| Profile | License | JDK 17 versions | JDK 21 | JDK 25 |
|---|---|---|---|---|
| PyKMIP, pinned source | Apache-2.0 | 1.1–1.4, 2.0 probe | 1.4 | 2.0 |
| PQCToday, pinned source | AGPL-3.0-only | 3.0 CSD02 | 3.0 CSD02 | 3.0 CSD02 |
| Krypton, pinned source | Apache-2.0 | 1.4 | 1.4 | 1.4 |

That is seven tuples on JDK 17 and three on each other JDK. Every JDK also runs the 47 controlled
scenarios.

- Krypton runs its production KMIP listener, authorizer, key processor and encrypted SQLite
  vault. A small adapter, derived from its upstream test setup, provisions one known AES key. It
  keeps its sealing key and vault across restarts. It is not a full administrative deployment,
  and it does not exercise native rotation.

KMIP 3.0 is the pinned CSD02 draft. The future-version rejection case therefore uses a
hypothetical KMIP 4.0.

## Running the catalog

The catalog runs within the integration build ([Running the tests](validation.md#running-the-tests)):

```sh
./integration/run.sh
./tools/verify-jdks.sh -Pintegration
```

Options, added to either command:

```sh
# Every catalog version on every JDK, instead of the pairwise selection.
./integration/run.sh -Dkmip.catalog.exhaustive=true
# Only some server profiles.
./integration/run.sh -Dkmip.catalog.servers=pykmip,krypton
# Independent server profiles on three JUnit workers. Versions within a profile stay sequential.
./integration/run.sh -Djunit.jupiter.execution.parallel.enabled=true \
  -Djunit.jupiter.execution.parallel.config.strategy=fixed \
  -Djunit.jupiter.execution.parallel.config.fixed.parallelism=3
```

| Property | Effect |
|---|---|
| `-Dkmip.catalog.strict=true` | Fail the build when a profile is not fully qualified. |
| `-Dkmip.catalog.p95Millis=…`, `-Dkmip.catalog.p99Millis=…` | Change the Get latency budget. |
| `-Dkmip.catalog.soak=PT24H` | Run the 24-hour soak case (at least 24 hours). |
| `-Dkmip.catalog.previousArtifact=…` | The previous release's SDK JAR, for the upgrade case. |

### An external server

`CatalogApplication` runs the catalog against a disposable server you started. Build the
integration JAR first. Its manifest names the runtime libraries that the build copies beside it.
H2 is a test dependency, so add it yourself:

```sh
./mvnw -B -ntp -pl integration-tests -am package -DskipTests
java -Dkmip.server.build=EXACT_BUILD -Dkmip.server.image=sha256:IMAGE_DIGEST \
  -Dkmip.client.commit=CLIENT_REVISION \
  -cp 'integration-tests/target/keytend-kmip-integration-0.10.0-rc.1.jar:/path/to/h2-2.5.252.jar' \
  dev.keytend.kmip.interop.CatalogApplication \
  SERVER_ID localhost 5696 integration/certs 1.4 integration/reports/catalog
```

- `SERVER_ID` is a live profile ID from
  [the inventory](../integration/catalog/server-inventory.json).
- The certificate directory holds PKCS12 client and server identities and CA files. Generate
  them with `./integration/catalog/generate-pki.sh "$PWD/integration/certs"`.
- The extra Compose targets start with
  `docker compose -f integration/compose.yaml --profile catalog up --build -d`. Krypton
  listens on port 55696.

> [!WARNING]
> Run it only against a disposable server with synthetic test data. The runner creates and
> destroys objects.

Cleanup removes only the object IDs the run created. It has 8 seconds plus 250 ms for each of
them, at most 60 seconds, and records any objects left over.

The external runner cannot restart the server, grant policies or reload its CA. Cases that
need those stay blocked.

## Results and reports

The runner writes its reports to `integration/reports/catalog`. `tools/summarize-catalog.py`
validates the matrix: it refuses a client failure and a record without its identity fields. It
writes these to a directory, `target/validation/catalog` by default (`--out`):

- `summary.json`: every tuple's outcomes, with the SHA-256 of each run's full record file;
- `cases.csv`: one flat row per record;
- `results/`: each run's full record file, gzipped.

`tools/render-catalog.py --dir` adds two HTML reports: `overview.html`, each case and its reason,
and `policy-coverage.html`. They are self-contained; download them and open them locally.

The release checks run both into their run directory's `validation/catalog/`, which each
release's binary ZIP carries ([Where the results are](validation.md#where-the-results-are)). Each
run's record file holds the fixture's configuration hash and the image ID the run used.

## Outcome rules

The outcomes are defined in [How to read the results](validation.md#how-to-read-the-results).
The catalog adds these rules:

- The build fails only on client failures. Server rejections, malformed responses and missing
  prerequisites stay in the JSON.
- `qualification.qualified` is true only when every applicable P0 record passes. An unsupported
  or blocked required case prevents it.
- A request the SDK refuses to build is a client failure. It never reached the server. The
  record says "Fixture request could not be built" (`local_request_construction`).
  `CatalogContractTest` runs the whole catalog against the SDK's in-process mock for every lane,
  and at KMIP 2.1, which no lane runs, so `./mvnw verify` catches such a break without a server.
- Each record has `attribution` and `review_status`, so an observed server failure says who
  rejected what. A server failure stays `unreviewed`.
- `last_request_shape` and `last_response_shape` hold the tag and type outline of the last
  exchange, with values redacted.
- `client_assertions.no_client_failures_observed` covers only the SDK's own assertions in this
  run.
- An evidence label such as `CATALOG-<SERVER>-<CASE>` names a local finding, not an upstream
  issue.

## Independent checks and consumer tests

- `reference.py` encodes and decodes binary TTLV without the Java SDK. It provisions known
  synthetic AES bytes and reads them back by exact ID over verified mTLS.
- JCE checks retrieved bytes, AES known answers, wrapped keys, RSA and EC signatures, and
  ciphertexts.
- The OVH oracle checks 2,712 exact binary digests ([research](research.md#independent-checks)).
- Fault proxies forward real mutations and drop the reply after the server has committed. The
  SDK must not send the mutation again.
- 12 database scenarios use real encrypted H2 files. They cover reopening in a new process,
  envelope encryption, two key generations, backup and restore, cold and warm KMS outages,
  revocation, concurrent consumers, server restart, renewed identities and corrupt metadata.
  H2 derives its AES-128 file key from a password that contains the retrieved KMIP material.
- Application certificate tests retrieve real key and certificate objects and complete a JSSE
  handshake. They then rotate a listener and check both a new certificate and an existing
  session.

## Case notes

### TLS chain, revocation and CA rollover (TLS-07, TLS-11, TLS-13)

Every container profile has a native certificate-switch adapter.

- TLS-07 tests complete and missing intermediate chains.
- TLS-11 tests client-side PKIX CRL revocation.
- TLS-13 tests overlap and retirement of CA trust.

Each positive check does an exact-ID Get on the real server. Every switch confirms a new native
process start and restores the original identity afterwards. Administrative readiness uses a
separate trust bundle, never used for a credited check. The SDK opens a fresh socket per
exchange, so these cases do not test revoking an established pooled session.

### Persistence (KEY-04)

KEY-04 restarts the server and then reads both registered key material and a server-generated
key, where the server can create one. PQCToday runs with both native durable stores enabled.
Registered key material survives restart; server-generated AES material fails the restart
check on the pinned build.
Krypton keeps its sealing key and only seeds a vault record that is absent.

### Authorization policies (AUTH-01, AUTH-02, LIFE-06)

These cases need native server policy, set up by an administrative adapter. The SDK never
replaces server authorization with a client-side check.

| Case | Native setup | Fixtures with that setup |
|---|---|---|
| AUTH-01 | Grant and revoke exact-object Get for a second certificate identity | PyKMIP |
| AUTH-02 | Get without Locate, then Locate without Get | PyKMIP |
| LIFE-06 | Global read-only identity: Get allowed, Create, AddAttribute and Destroy denied | none |

- PyKMIP policies update the run-owned object's row in its SQLite store, because
  OperationPolicyName is server-managed. PyKMIP's own engine then makes every Get and Locate
  decision.
- No fixture has a global read-only role, so LIFE-06 is blocked on every lane.

A policy case counts as executed when it ran on every fixture in the last column, on every
selected version and JDK. A fixture without the setup does not block that count. The release's
`validation/catalog/policy-coverage.html` and the summary's `policy_coverage` list the tuples and
outcomes.

### Get latency (JAVA-05)

The local-fixture budget is **p95 ≤ 1,000 ms and p99 ≤ 2,000 ms** per Get. The Maven
`integration` profile sets it, so `integration/run.sh` and `tools/verify-jdks.sh` use it. The
external runner needs explicit budgets for its deployment.

- Each report records the limits, one cold context and Get, and 100 warm-context Gets.
- p95 and p99 are nearest-rank: sorted samples 95 and 99.
- Each Get opens a fresh socket. The time includes TLS, server work, decoding and key validation.
- Server CPU time is not measured separately.

Fresh-socket Gets do not predict an application's paths. [Performance](performance.md) measures
those.

### Soak (JAVA-06)

JAVA-06 needs `-Dkmip.catalog.soak=PT24H` or longer. A shorter run is labeled `SMOKE_ONLY` and
never passes. After a ten-minute warm-up, the soak rotates keys, decrypts historical data,
expires the cache and reconnects. It samples retained heap, threads and file descriptors.

To run the soak on its own, with Podman:

```sh
JAVA_HOME=/path/to/jdk17 bash tools/run-soak.sh PT24H .cache/soak-24h
```

- It copies the candidate SDK and application JARs first, so a rebuild cannot change them.
- It starts a fresh PyKMIP container, with new certificates, and checks mTLS readiness.
- Progress JSON is replaced atomically every minute.
- It records the worker's exit status and removes its container when the worker finishes.

### Upgrade from a previous release (JAVA-07)

JAVA-07 reads one exact object and its material through a previous release's public API,
compiled and run in a fresh JVM. The candidate then reads it again. Name that release's SDK JAR
with `-Dkmip.catalog.previousArtifact=/path/to/prior.jar`. Without one, the case is blocked.

### Requests the scenarios send

- AES remote-crypto scenarios name the algorithm explicitly. GCM sends IV Length 96 bits and
  Tag Length 16 bytes, as [KMIP 1.4 §3.6](https://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html)
  requires.
- BATCH-09 accepts a whole-request rejection of an ordered batch, and checks that no retry or
  fallback was sent.
- Other batch scenarios record a clean whole-request rejection as unsupported. They still fail
  on any side effect.
- Each continuation scenario uses its own object names and sends the mandatory usage mask.
- Rollback probes validate the server's response before blaming an older client.

## Prerequisite gaps

These cases are recorded as blocked, not as failures:

- PQCToday and Krypton have no grant and revoke adapter for the policy cases. Only PyKMIP has
  the exclusive Get and Locate pair. No fixture has a global read-only role, so LIFE-06 does not
  run. Adding an adapter adds that fixture to the case's required set.
- A full administrative or PostgreSQL deployment of Krypton is not tested.
- JAVA-06 needs a completed 24-hour soak run.
- JAVA-07 needs a released SDK JAR.
