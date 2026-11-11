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

# Validation

This page has three parts:

- [What is tested](#what-is-tested): which checks run, against which servers, what each covers,
  and where each release's results are.
- [How to read the results](#how-to-read-the-results): what each outcome means. The other
  evidence pages use these terms.
- [Running the tests](#running-the-tests): how to run each check.

## What is tested

The release checks run every check below that needs no hand-run step, on Linux with rootless
Podman, on JDK 17, 21 and 25 ([the release checks](releasing.md#the-release-checks)). The SDK's
bytecode targets Java 17. All runs are local, and the repository uses no hosted CI.

The lab servers are PyKMIP at commit 4815637 on Python 3.12, PQCToday at `010da23` and Krypton
at `7ca8dc5`. Their images use Red Hat Universal Base Image 9
([research](research.md#how-the-test-servers-were-chosen)).

### Where the results are

Each release's binary ZIP, `keytend-kmip-X.Y.Z.zip`, holds the results of the release checks that
built it, in its top-level `validation/` directory:

| Path | What it holds |
|---|---|
| `release-check.txt` | the release checks that ran before packaging, with their results |
| `workflows/` | the [workflow suite](#workflow-suite): `summary.json`, an HTML report (`overview.html`), and one JSON report per server, version and JDK |
| `catalog/` | the [catalog](catalog.md#results-and-reports): `summary.json`, `cases.csv`, two HTML reports, and each run's records in `results/` |
| `live-server.json` | the latest result of each check against [keytend-kmip-server](#keytend-kmip-server), one entry per check and KMIP version |
| `server-probe*/`, `interop*/`, `bench-smoke/` | the logs of the release checks' runs against keytend-kmip-server |
| `recorded/` | evidence the release checks cannot produce; `recorded/index.json` gives each file's date and server |

The HTML reports are self-contained. Download them and open them locally.

A check against keytend-kmip-server keeps only its latest result: a new run replaces the entry of
its check and KMIP version, and nothing is appended. Each entry's `source` says where it comes
from. `release check` is a run of the release's own checks. `recorded` is an earlier run, outside
the release checks, kept in the source tree's `validation/recorded/live-server.json`: the
Cassandra integration's dtest, which needs a Cassandra build. Each entry names its date, server
build and image. A release ships passing results of the pinned server build only, recorded ones
included ([Recorded results](releasing.md#recorded-results)).

The catalog records name the client source by a SHA-256 fingerprint of its source tree.

### Workflow suite

The workflow suite runs application workflows against each server and checks the results
independently with JCA/JCE. The workflows cover:

- key lifecycle, registration, import and export, attributes and batches;
- encryption, signing and verification, MAC, hashing, key derivation and split keys;
- certificate validation, system operations and, on 3.0, ML-KEM.

It runs against PyKMIP at KMIP 1.1 to 1.4 and PQCToday at the 3.0 CSD02 draft, on every JDK. A
known server nonconformance counts as `SERVER_LIMITATION`, matched by server and exact message,
and for some by the exact build. The suite names each one in its result. A `FAIL` result fails the
build.

Transport tests exercise real TLS, HTTPS and callback connections on all seven versions. They
reject missing identities, untrusted CAs and wrong host names.

### Shared catalog

The [catalog](catalog.md) runs 13 server, version and JDK tuples: seven on JDK 17 and three on
each of 21 and 25 ([targets](catalog.md#targets)). Every JDK also runs 47 scenarios against
controlled peers. Its summary counts each tuple's records by outcome.

- A server failure stays `FAIL_SERVER`, and a client failure fails the build.
- A blocked record is a fixture without the native setup its case needs, or the opt-in 24-hour
  soak.
- The [authorization-policy cases](catalog.md#authorization-policies-auth-01-auth-02-life-06)
  run on every fixture that has the native policy they need.
- Live TLS certificate-chain, CRL and CA-rollover checks run on every container profile.
- The local-fixture Get latency budget is p95 ≤ 1,000 ms and p99 ≤ 2,000 ms.
- A server profile is fully qualified only when every applicable required case passes. The
  summary records it for each tuple.
- The [24-hour soak](catalog.md#soak-java-06) runs only when asked, not in the release checks.

### OASIS scenario replay

The replay sends complete OASIS test scenarios to a dedicated, freshly started server: PyKMIP at
KMIP 1.3 and PQCToday at 3.0, on JDK 25. It reports mismatches, such as
omitted fields, different algorithm or profile choices, and different result codes. The workflow
and catalog counts do not include replay results.

The replay runs by hand ([OASIS replay](#oasis-replay)), not in the release checks. Its last
recorded results are in the binary ZIP's `validation/recorded/oasis-replay/`.

### keytend-kmip-server

The release checks run against the pinned build of keytend-kmip-server
([the pinned build](releasing.md#the-pinned-keytend-kmip-server-build)):

- the [server probe](../tools/server-probe/README.md) with its `all` scenarios at KMIP 1.1, 1.2,
  1.4, 2.1 and 3.0, under the server's defaults, under `KMIP_DESTROYED_NAME_REUSE=reserve` and
  under `KMIP_LEASE_STATES=active`;
- the probe's `raw-leases` and `tls` scenarios at 1.4, 2.1 and 3.0 under
  `KMIP_MAX_LEASE_SECONDS=0`;
- the generic interop suite and its programs in
  [integration/keytend-kmip-server](../integration/keytend-kmip-server/README.md), with the
  configured setup, and the suite with the minimal setup, on all seven protocol versions;
- the [benchmark](../tools/bench/README.md)'s smoke run at 1.4, 2.1 and 3.0, which checks the
  tool and measures nothing.

Their results are in the binary ZIP's `validation/live-server.json`.

### Offline checks

`./mvnw verify` runs these on every JDK, with no server:

- 542 original OASIS fixture files, each round-tripped through binary, XML and JSON. Their
  checksums are verified.
- 2,712 binary wire digests from an independent Go encoder ([research](research.md#independent-checks)).
- Malformed frames, size limits, Unicode, numeric boundaries, batches, credentials, version
  conversion, correlation and critical extensions.

### Known gaps

- Only the servers named above were run. Of the lab servers, only PyKMIP's 2.0 probe runs
  between 1.4 and 3.0; KMIP 2.0 and 2.1 are tested live against keytend-kmip-server.

## How to read the results

### Outcomes

The workflow suite and the catalog use different codes for the same ideas:

| Meaning | Workflow suite | Catalog |
|---|---|---|
| The check passed | `PASS` | `PASS` |
| The SDK or the test failed | `FAIL` | `FAIL_CLIENT` |
| The server's answer failed a check, cause not yet confirmed | `FAIL` | `FAIL_SERVER` |
| A known server limitation, matched exactly | `SERVER_LIMITATION` | none: stays `FAIL_SERVER` |
| The server does not implement the operation | `UNSUPPORTED` | `UNSUPPORTED_SERVER` |
| A prerequisite was missing, so the check did not run | `UNEXERCISED` | `BLOCKED_ENV` |
| The check does not apply to this version or fixture | `VERSION`, `CALLBACK` | `NOT_APPLICABLE` |

Only `PASS` counts as a pass. The rules:

- A pass counts a check, not an operation. One operation can appear in several checks.
  Cleanup steps and negative checks count too.
- An observed server failure is not yet a confirmed defect. The record says whether the server
  rejected the request or the SDK rejected the response.
- Each `SERVER_LIMITATION` rule names its server, its exact failure message and its checks. Most
  also name one server build and its protocol versions. Any other failure stays visible.
- Unsupported and blocked results are not passes. A dependent step after an unsupported
  operation is recorded as unexercised or blocked.
- `CALLBACK` marks an operation that the separate callback test covers.

### Coverage, execution and qualification

These are three different claims:

1. **Wire coverage.** The SDK can encode and decode a message.
   [Protocol coverage](protocol-coverage.md) lists it, and the offline checks test it.
2. **Executed scenario.** A scenario ran against a real server and its outcome was recorded. A
   policy case counts as executed when it ran on every fixture that has the native policy it
   needs, on every selected version and JDK.
3. **Full qualification.** Every applicable required (P0) catalog case passes on one server
   profile. This is the claim a deployment needs. The catalog's summary records it for each
   tuple (`qualification.qualified`).

A green build means no workflow check failed and the catalog saw no client failure. It does not
qualify a server. To qualify your own server, see
[Qualifying a server](production.md#qualifying-a-server).

## Running the tests

### Requirements

- JDK 17 or later. The full matrix uses JDK 17, 21 and 25.
- Docker, or a rootless Podman socket that speaks the Docker API.
- OpenSSL, for the test certificates.

### Offline tests

```sh
./mvnw verify
```

This runs the SDK tests, the OASIS fixture round trips, the oracle digests and the replay
regression tests. Each module's test classes run in several JVMs at once, one class per JVM at a
time. The number of JVMs is a quarter of the CPUs, at least one. `-Dtest.forks=N` sets it, and
`-Dtest.forks=1` runs them in one JVM. `-T 4` builds the modules after the SDK at once.

Some long tests run a sample by default:

- `-Dkeytend.matrix=full` runs each of `ReconcileJoinFaultsTest`'s sampled fault sweeps on both
  KMIP versions instead of splitting the sample between them. The release check passes it on
  JDK 17.
- `-Dkeytend.sweep=full` runs every failure point of those sweeps.
- `-Dkeytend.storm=long` runs `ConcurrentRotationStormTest`'s long storm.

### Real servers

```sh
./integration/run.sh
```

`./integration/run.sh` finds a rootless Podman socket on its own. With Docker, run
`./mvnw -Pintegration verify` instead.

Testcontainers builds PyKMIP and PQCToday KMIP from pinned revisions and images.
It creates fresh mTLS certificates and a test CA, runs the workflows, then removes the
containers. JSON reports go to `integration/reports`, which Git ignores.

- A `FAIL` result fails the build.
- The integration profile fails, rather than skips, when Docker is not available.

### Every JDK

```sh
./tools/verify-jdks.sh -Pintegration
```

The script runs `verify` once per JDK. Set `JDK17_HOME`, `JDK21_HOME` and `JDK25_HOME`, or install
the JDKs with SDKMAN. The release check runs this matrix too ([Releasing](releasing.md)).

### The catalog

The catalog runs within the same integration build. [Catalog](catalog.md#running-the-catalog)
lists its options and its runner for an external server.

### A lab server and the integration application

To keep the lab servers running and run the workflow suite by hand:

```sh
./integration/generate-certs.sh
docker compose -f integration/compose.yaml up --build -d
./mvnw package
CP=sdk/target/keytend-kmip-0.10.0-rc.1.jar
CP=$CP:integration-tests/target/keytend-kmip-integration-0.10.0-rc.1.jar
java -cp "$CP" dev.keytend.kmip.interop.InteropApplication \
  pqctoday localhost 45696 integration/certs
```

The arguments are the server name, host, port and certificate directory. Then come an optional
report directory (default `integration/reports`) and an optional single version.

| Server name | Port |
|---|--:|
| `pykmip` | 15696 |
| `pqctoday` | 45696 |

The application does not read the server's build. So the build-pinned server limitations do
not apply, and those checks report `FAIL`.

To stop the lab:

```sh
docker compose -f integration/compose.yaml down
```

### OASIS replay

Replay sends the original OASIS scenarios for one version to a dedicated lab server. It runs from
the integration JAR (`./mvnw -B -ntp -pl integration-tests -am package -DskipTests`):

```sh
java -cp integration-tests/target/keytend-kmip-integration-0.10.0-rc.1.jar \
  dev.keytend.kmip.interop.OasisReplay \
  pqctoday localhost 45696 integration/certs \
  sdk/src/test/resources/oasis/3.0/archive/test-cases/kmip-v3.0 3.0
```

Replay reports mismatches. It does not certify a profile.

- It binds the identifiers and correlation values the server returns.
- It accepts extra response fields and the variations that
  [OASIS Profiles 2.1 §4.1](https://docs.oasis-open.org/kmip/kmip-profiles/v2.1/os/kmip-profiles-v2.1-os.html)
  permits. These are optional ResultMessage text and consistently bound digests of
  server-generated objects.
- Expected fields, required reasons and the digests of registered key material must still match.
- Add `-Dkmip.oasis.strict=true` before `-cp` to make a mismatch fail the process.
- Add `-Dkmip.oasis.literal=true` to compare every value literally, for diagnosis.

### Summarizing the results

`tools/summarize-validation.py` reads the reports in `integration/reports` and each JDK's test
totals, rejects any workflow failure, and writes `summary.json` and a copy of each report to a
directory, `target/validation/workflows` by default (`--out`). `tools/render-validation.py --dir`
writes the HTML report from that summary. After `./tools/verify-jdks.sh -Pintegration`, they read
its logs, `.cache/integration-jdkNN.log`.

The release checks run both, and the catalog's (`tools/summarize-catalog.py` and
`tools/render-catalog.py`), into their run directory's `validation/`, which the binary ZIP
carries ([Where the results are](#where-the-results-are)). Nothing is committed: results are not
part of the source tree.
