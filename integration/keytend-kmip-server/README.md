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

# Interop suite against keytend-kmip-server

> [!WARNING]
> **Experimental: not for production use.** keytend-kmip is experimental in every release.
> Passing this suite does not certify the SDK or the server.

`run-interop.sh` runs the generic interop suite and four programs of its own against
keytend-kmip-server, on every KMIP version from 1.1 to the 3.0 draft. It runs the image that
[tools/kmip-server](../../tools/kmip-server/README.md) pins (0.10.0-rc.1). No Maven
module or test runs it. The release checks run it when given the server image (`--server`).

## When to use it

- To check an SDK build against a real server on every protocol version.
- To check a new server image before you change the pin in
  [`pinned-image.properties`](../../tools/kmip-server/pinned-image.properties).

## Requirements

- A JDK 17 or later, `openssl` and `python3` on the `PATH`.
- Podman and the pinned image, loaded as [tools/kmip-server](../../tools/kmip-server/README.md)
  describes.

## Build and run

From the repository root, after loading the pinned image:

```sh
./mvnw -B -ntp -pl integration-tests -am package -DskipTests
jars=sdk/target/keytend-kmip-0.10.0-rc.1.jar
jars=$jars:integration-tests/target/keytend-kmip-integration-0.10.0-rc.1.jar
jars=$jars:testing/target/keytend-kmip-testing-0.10.0-rc.1.jar
integration/keytend-kmip-server/run-interop.sh --classpath "$jars" --work /tmp/server-interop
```

```text
run-interop.sh --classpath SDK_JAR:INTEGRATION_JAR:TESTING_JAR --work DIR
    [--setup configured|minimal] [--programs "suite controls reversal renewal purpose"]
    [--versions "1.1 1.2 1.3 1.4 2.0 2.1 3.0"]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--classpath` | required | the SDK jar, the integration jar, and for `purpose` the testing jar |
| `--work` | required | a new directory for each setup: PKI, logs and reports |
| `--setup` | `configured` | `configured` adds the server policy the scenarios need; `minimal` does not |
| `--programs` | `"suite controls reversal renewal purpose"` | the programs to run; `minimal` runs only `suite` |
| `--versions` | `"1.1 1.2 1.3 1.4 2.0 2.1 3.0"` | KMIP versions |

For each version and program the script starts a container with `serve --experimental-v3`. It
uses a fresh SQLite store and free loopback ports, runs the program, and stops the container.
Every container of the run is removed on exit or interrupt. The script exits 1 when any program
failed on any version.

It writes:

- `<work>/<program>/v<version>/out.log`, `server.log` and `exit.txt`;
- the suite's JSON reports under `suite/v<version>/reports/`, named
  `keytend-kmip-server-<version>-jdk<n>.json`;
- `run.txt`: the pin, the image ID, the server version, the `KMIP_*` variables, the jar hashes,
  Java and the setup.

## Configuration

### Setups

The work directory gets a throwaway PKI in the layout of `integration/generate-certs.sh`, and a
master key made by the image.

- **`minimal`** is the bare server: one principal, the client certificate, allowed every
  operation. Only the suite runs.
- **`configured`** adds the server policy that KMIP leaves to the server:
  - `--validation-ca ca.pem`, the trust anchor for Validate. Without it no certificate validates.
  - `--users users.json`, a users-file administrator `interop-admin`. Its random password is in
    `admin-credential.properties`. The 3.0 draft's Login and System Object operations need it in
    the request header. The suite and the controls send it on those requests only.
  - Two more principals, `reverse-2.0` and `reverse-2.1`, each with a reverse-only client
    endpoint in that protocol version. `EndpointRoleReversal` uses them.
  - For the `renewal` program: a provisioning sub-CA of the test CA (`provisioning-ca.pem`,
    `pathlen:0`), a `--ca` bundle with both CAs, and two clients valid for 6 days, `renewal` (PEM)
    and `renewal-store` (PKCS#12), each a principal of its own. They expire a day before the rest
    of the test PKI and the provisioning CA, so a renewal issues a certificate that outlives the
    one it replaces, and a rerun of the same `--work` directory works as long as the rest does.
    Only the `renewal` and `purpose` programs' servers run with `--provisioning-ca`. The other
    programs' servers do not offer Re-Provision, so the suite's no-parameter Re-Provision cannot
    retire their client certificate.
  - For the `purpose` program: `pki/shapes/<shape>/`, each shape's provisioning CA and `--ca`
    bundle, made the first time the program runs in the work directory with that shape.

The Certify scenario names the issuing CA with a Certificate Link to the test CA, which the
client registers. keytend-kmip-server has no CA of its own.

### Environment

| Setting | Default | Meaning |
| --- | --- | --- |
| `KEYTEND_SERVER_IMAGE` | the pinned image | another image; it runs only with `KEYTEND_SERVER_UNPINNED=1` |
| `KMIP_*` | none | passed to the server and recorded in `run.txt` |

`run.txt` records an image that is not the pin as `UNPINNED`.

## The programs

- **`suite`:** `InteropApplication keytend-kmip-server ...`, the same scenarios as the
  Testcontainers runs.
- **`controls`:** `ServerSetupControls`. For each setup correction that applies to the version,
  it sends the uncorrected request and requires the server's exact refusal. Then it sends the
  corrected request and requires success.
- **`reversal`** (2.0, 2.1 and 3.0): `EndpointRoleReversal`. On 2.0 and 2.1 it sends Set Endpoint
  Role Client, answers the server's Discover Versions and Query on that channel, and receives
  Put and Notify for a key that a second connection changes. It then answers the server's
  hand-back. Any other version, and the 3.0 draft, must be refused with Feature Not Supported.

- **`renewal`** (2.0, 2.1 and 3.0): `ClientCertificateRenewal`. It renews the `renewal` client's
  PEM files on demand, twice, and checks the files, the issuer, the fingerprints, that the same
  `Kms` and a new process go on with the new certificate and still see the principal's key, and
  that the retired certificate is refused on new connections. It asks for a validity (half the
  provisioning CA's remaining validity, at most 30 days) and checks the notAfter issued, then asks
  for one past the provisioning CA's notAfter and checks that it is refused and nothing changes.
  Two checks run the search a renewal makes after a lost reply (`RenewalSearchCheck`), through a
  connection opened on the old certificate before the first renewal retired it. For the new
  certificate's key, the search must find the certificate the server issued. For a key the server
  never saw, it must read every page of Locate results and find nothing.
  Then an automatic renewal (a two-day window) renews the `renewal-store` key store on the SDK's
  thread. Each version gets a new store, since the server retires what it renews.
- **`purpose`** (2.0, 2.1 and 3.0): a differential check of the provisioning CA rules. The script
  makes one provisioning CA for each shape of its table, a sub-CA of the test CA with or without
  basicConstraints, a Key Usage and an Extended Key Usage; one under a root whose Extended Key
  Usage is serverAuth only; one under an RSA-1024 root; one signed with SHA-1; one with an
  RSA-1024 key; one whose `--ca` bundle leaves out its root; and one whose bundle holds its root
  but not the CA. For each, it starts a server with that CA, and
  `ProvisioningCaShapes.java` renews the `renewal` client once on it, and once on the in-memory
  server's listener set up with the same files. Each verdict must be the table's, exactly: both
  renew by the shape's CA, or both refuse to start with the table's message, and
  keytend-kmip-server with the detail after it where the table gives one (its listener's reason).
  So a check that refuses a shape for another reason than the table's fails it, on either side.
  The pinned build refuses every shape but two before it serves: the CA must be a CA (basicConstraints
  CA true) with a Key Usage that allows keyCertSign, its certificate must be strong (a key of at
  least 112-bit security, and no SHA-1 or MD5 signature unless it is self-issued), it must be in
  the `--ca` bundle byte for byte, and a client certificate from it must pass the listener's
  verification: purpose sslclient, curves and strength, up to a self-signed root included. `<work>/purpose/v<version>/` holds `out.log`, with both verdicts
  for each shape, and each shape's logs.

The hand-back comes after 30 s without a message on the reversed channel. That is a fixed limit
of the server, so a reversal run takes about 31 s.

`reversal` is a test fixture. It answers through the SDK's `CallbackMessages.respond` and
switches the channel between roles itself. The SDK does not manage a reversed channel.

## Limits

- `ServerSetupControls` requires the pinned build's exact Result Reasons and Messages. Another server
  build may fail a control with no defect on either side. Re-check the refusal before you change the
  pin.
- The `purpose` table holds the pinned build's startup messages, and the program compares them
  exactly. Another server build may word them otherwise, or check the provisioning CA in another
  order, and then a shape fails with no defect on either side. Re-check the table before you
  change the pin.
- The `minimal` setup is expected to fail. Without a trust anchor, Validate fails on every
  version. On 3.0, Login, Create Credential, Create User and Create Group are refused without the
  header credential.
- The suite runs against one server product. For other servers, see
  [Validation](../../docs/validation.md).

## Tested

The release checks run this script against the pinned image, with the configured setup, every
program and every version, on the JARs of the release's distribution build, with JDK 17
([the release checks](../../docs/releasing.md#the-release-checks)). Every program must exit 0 on
every version: `renewal` and `purpose` on 2.0, 2.1 and 3.0, `purpose` with each shape of its
table agreeing on both servers. They also run the suite with the minimal setup on every
version; it is expected to show only the refusals listed under [Limits](#limits).

Each release's binary ZIP holds the latest result of each setup, program and version in
`validation/live-server.json`, and each program's output in `validation/interop/` and
`validation/interop-minimal/`
([Where the results are](../../docs/validation.md#where-the-results-are)).

To run it yourself, use the commands above with `--setup configured`, then with `--setup minimal`
and a new `--work`. For the suite's per-version results and how to read them, see
[How to read the results](../../docs/validation.md#how-to-read-the-results).
