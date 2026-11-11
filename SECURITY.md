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

# Security policy

## Supported versions

keytend-kmip is experimental and not for production use, in every release. Security fixes are
best effort.

| Version | Security fixes |
|---|---|
| The latest release | yes |
| Any other release or pre-release | no: upgrade to the latest release |

A fix ships as a new release. Upgrading keeps the API and stored data compatible, as
[Compatibility and support](docs/compatibility.md) promises. Upgrade notes are in the
[release notes](RELEASE.md), and releases are on the
[releases page](https://github.com/keytend/keytend-kmip-java/releases).

## Reporting a vulnerability

Report it privately on GitHub:
[Report a vulnerability](https://github.com/keytend/keytend-kmip-java/security/advisories/new),
also on the repository's Security tab. The report becomes a draft security
advisory that only you and the maintainer can see. It is discussed and fixed
there, and the advisory is published from it.

Do not open a public issue, pull request or discussion for a suspected
vulnerability.

Please include:

- the keytend-kmip version (or commit) and the JDK version;
- the KMIP version negotiated and, if a real server is involved, which server;
- what an attacker controls (the network, the server's replies, the
  application's input) and what they gain;
- a reproduction, ideally a test against `InMemoryKmipServer` or a TTLV
  transcript. Remove real keys, passwords and certificates from it first.

## What to expect

keytend-kmip is maintained by one person. These are goals, not a service level
agreement:

- acknowledgment within 7 days;
- an initial assessment (in scope or not, and how severe) within 14 days;
- for a confirmed vulnerability, a fixed release within 90 days of the report,
  sooner for a severe one.

A fix is published as a new release with a GitHub security advisory. The
advisory credits the reporter, unless they prefer otherwise. Please keep the
report private until the advisory is published. If we have not agreed on a
date, keep it private for 90 days.

## Scope

In scope are the SDK (`keytend-kmip`), the metrics modules
(`keytend-kmip-micrometer`, `keytend-kmip-opentelemetry`) and the command-line
tool (`keytend-kmip-cli`). For the SDK that covers the protocol layer (TTLV, XML
and JSON codecs, transports, authentication) and the `kms` application API.
The release artifacts and the build that produces them are in scope too.
Examples:

- key material or credentials leaking into strings, exceptions, events, logs,
  metrics or spans;
- a secret the CLI writes to a file that other users can read;
- TLS certificate or hostname validation that can be bypassed;
- a reply from a malicious server that makes the client crash, hang, exhaust
  memory or use the wrong key;
- a call that reports success for something the server did not do.

Out of scope:

- `InMemoryKmipServer` and the other test fixtures. The in-memory server is
  the separate test artifact `keytend-kmip-testing`, not part of the SDK JAR
  or the release's `lib/`. It does not protect what it stores and must not
  hold real keys. A defect in it is an ordinary bug, unless it hides an SDK
  vulnerability.
- The integration application (`keytend-kmip-integration`), the lab servers,
  certificates and Compose files under `integration/`, and the tools under
  `tools/`. They are test and research code.
- Vulnerabilities in KMIP servers. Report those to the server's maintainers.
- Weaknesses of the KMIP protocol itself, or of the 3.0 draft, that the SDK
  implements as specified.
- Attacks that need control of the JVM, its class path or the application's
  configuration.

## Handling secrets

The SDK handles key material and credentials. Java cannot guarantee that memory
is erased. Follow these rules:

- Destroy keys and secrets promptly. Call `DestroyableSecretKey.destroy()`,
  `DataKey.close()` or `SecretData.close()` when you are done, and keep
  references short-lived.
- Expect copies the SDK cannot wipe. The SDK wipes the buffers it owns. It
  cannot wipe `Ttlv` trees, arrays you pass in or receive, JCA objects, the
  KMIP password `String`, or copies made by the TLS stack or the garbage
  collector.
- Do not log values. `toString()` of SDK types is redacted, and so are the
  protocol objects in exceptions. `KmsListener` events carry identifiers and
  outcomes only. A `Ttlv`'s values, its XML or JSON encoding, or a payload you
  retrieved are not redacted, so logging them logs secrets.
- Keep TLS verification on. The SDK verifies the server's certificate chain
  and hostname, over TLS 1.2 or 1.3. Never supply an `SSLContext` or trust
  manager that trusts every certificate, except against a local test server.
- Protect credentials at rest. The SDK reads client private keys, PKCS#12
  files and passwords from where you put them. Protect those files and the
  process environment. Prefer client certificates to passwords where the
  server allows it.
- Keep test fixtures out of production. `InMemoryKmipServer` and the
  certificates under `integration/certs` are for tests only.

The full lists are in [Design notes: Secrets](docs/kms-design.md#secrets)
and [Protocol layer: Secret lifetime](docs/protocol-layer.md#secret-lifetime).

## Verifying release artifacts

Every release is signed, and so is every pre-release (a version such as
`0.10.0-rc.1`). Nothing is published unsigned.

A GitHub release holds these assets, where `X.Y.Z` is the release's version,
such as `0.10.0`, or a pre-release's, such as `0.10.0-rc.1`:

- `keytend-kmip-X.Y.Z.zip`, the binary distribution. It holds no source tree.
  Its `lib/` holds each module's JARs and a CycloneDX SBOM of each module.
  The SDK's (`lib/keytend-kmip-X.Y.Z-cyclonedx.json`) lists slf4j-api, its
  one runtime dependency, and the bundled Caffeine. Its `keytend:shaded` property names Caffeine's relocated package, so a Caffeine
  advisory needs an SDK release. The metrics modules' SBOMs list Micrometer and
  the OpenTelemetry API. The CLI's and the integration application's list the
  libraries `lib/` holds for them. Its `validation/` holds the release's test
  reports ([Where the results are](docs/validation.md#where-the-results-are)).
- `keytend-kmip-X.Y.Z-src.zip`, the source tree that builds the release.
- `keytend-kmip-testing-X.Y.Z.jar`, the in-memory KMIP server for tests, with
  `keytend-kmip-testing-X.Y.Z-sources.jar` and its SBOM,
  `keytend-kmip-testing-X.Y.Z-cyclonedx.json`, which lists the SDK and
  slf4j-api. They are not in the ZIPs. Use them in tests only.
- `keytend-kmip-X.Y.Z-central-bundle.zip`, the signed Maven artifacts exactly
  as they are uploaded to Maven Central. Users do not need it.
- A `.sha256` of each ZIP and of each of those four files.
- `SHA256SUMS`. It lists the SHA-256 of each file in the binary ZIP, under
  `keytend-kmip-X.Y.Z/`, then of the binary ZIP's own `SHA256SUMS`, then of the
  two ZIPs and the four files beside them. The binary ZIP's own `SHA256SUMS`
  lists its contents only.
- A `.asc` of each ZIP, of each of the four files and of `SHA256SUMS`:
  detached OpenPGP signatures by the release key.

Checksums show that a download is intact. Only the signatures show who
published it.

**Release key fingerprint:** `3A84912AFBE7D2B04EBA2A8A51E65DD49C6F987F`

The key's user ID is `keytend-kmip releases <releases@keytend.dev>`. It is
published on keys.openpgp.org and keyserver.ubuntu.com. A key with the right
name and a different fingerprint is not the release key.

Signatures are made by a signing subkey, so verify against the primary
fingerprint above, not the subkey's. A revoked subkey's signatures no longer
verify, so refresh the key before you verify
(`gpg --refresh-keys 3A84912AFBE7D2B04EBA2A8A51E65DD49C6F987F`).

To verify a release:

<!-- release-check: verify -->
```sh
gpg --keyserver keys.openpgp.org --recv-keys 3A84912AFBE7D2B04EBA2A8A51E65DD49C6F987F
# "Good signature", by this fingerprint:
gpg --verify keytend-kmip-X.Y.Z.zip.asc keytend-kmip-X.Y.Z.zip
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c keytend-kmip-X.Y.Z.zip.sha256
unzip -q keytend-kmip-X.Y.Z.zip
sha256sum -c --ignore-missing SHA256SUMS   # the ZIP, its contents, and what else you downloaded
```

`SHA256SUMS` also lists the source ZIP and the in-memory server's three files.
`--ignore-missing` skips those you did not download (GNU coreutils 8.25 or later; on macOS,
`shasum -a 256 -c --ignore-missing SHA256SUMS`). Every line it prints must say
`OK`, and the binary ZIP and its JARs must be among them, so unzip in the same
directory first.

For the source ZIP alone, in the directory you downloaded it to:

<!-- release-check: verify-source -->
```sh
gpg --verify keytend-kmip-X.Y.Z-src.zip.asc keytend-kmip-X.Y.Z-src.zip
sha256sum -c keytend-kmip-X.Y.Z-src.zip.sha256
unzip -q keytend-kmip-X.Y.Z-src.zip   # keytend-kmip-X.Y.Z-src/, which builds with ./mvnw
```

For the in-memory server alone, in the directory you downloaded it to:

<!-- release-check: verify-testing -->
```sh
gpg --verify keytend-kmip-testing-X.Y.Z.jar.asc keytend-kmip-testing-X.Y.Z.jar
sha256sum -c keytend-kmip-testing-X.Y.Z.jar.sha256
```

keytend-kmip is not on Maven Central. A release deployed there would be the
same build: its JARs and SBOMs would have the SHA-256 values `SHA256SUMS`
lists.
