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

# keytend-kmip 0.10.0

keytend-kmip 0.10.0 is the first release. It is a Java KMIP client for JDK 17, 21 and 25, with an
application API (`dev.keytend.kmip.kms`) over a protocol layer for KMIP 1.1 to 2.1 and the 3.0
draft (CSD02).

It is experimental and not meant for production use, in this and every later release. It started
as an experiment in implementing the KMIP specification.

0.10.0 is a GitHub release of <https://github.com/keytend/keytend-kmip-java>, signed by the
release key SECURITY.md publishes, and each of its pre-release builds (tag `v0.10.0-rc.N`) is
a signed GitHub pre-release. It is not published to Maven Central. Build and install it from a clone at its
tag with `./mvnw install` ([Build and install](docs/getting-started.md#build-and-install)), or
download the GitHub release and install the SDK from its ZIP
([From the GitHub release](docs/getting-started.md#from-the-github-release)).
Its in-memory server for tests, `keytend-kmip-testing-<version>.jar`, is a separate asset beside
the ZIP, signed the same way
([The in-memory server from the GitHub release](docs/getting-started.md#the-in-memory-server-from-the-github-release)).
To check a download, see [Verifying release artifacts](SECURITY.md#verifying-release-artifacts).

The [compatibility](docs/compatibility.md) promises start with 0.10.0. The API history starts
here, and every public element says `@since 0.10.0`.

## What 0.10.0 contains

- The application API (`dev.keytend.kmip.kms`) connects, finds or creates keys, seals and opens
  data, rotates, retires, signs, computes MACs and stores secrets
  ([Getting started](docs/getting-started.md)).
- Envelope encryption with local AES-GCM under a fresh data key that the KMS wraps, for records,
  streams and files ([Envelope encryption](docs/envelope-encryption.md)).
- Key lifecycle: rotation with an optional grace period, a Deactivation Date set at any time,
  lineages, and retirement, reconciliation and compromise replacement from a plan you can confirm
  first ([Key lifecycle](docs/operating-keys.md)).
- `LocalKeys`, a cache of raw keys for local encryption that honors KMIP leases
  ([Local keys](docs/local-keys.md)).
- TLS identities kept in the KMS through `kms.tls()`, renewed and revoked without a restart
  ([TLS identities](docs/tls-identities.md)).
- TLS identities issued by the KMS through KMIP Certify
  ([Issue from the KMS](docs/tls-identities.md#issue-from-the-kms)). `kms.tls().registerIssuer(...)`
  puts an issuing CA in the KMS, linked as Certify needs, and `kms.tls().issuer(name)` finds it.
  `kms.tls().issue(name)` has the KMS create the key pair and sign the certificate.
  `TlsIdentityHandle.reissue()`, `reissueWithNewKey()`, `reissue(TlsReissue)` and
  `reissueIfExpiresWithin(...)` get a new certificate for the same key or a new one. The SDK checks
  each issued certificate before it uses it, by its clock after Certify, then switches it in as
  `register`, `renew` and `rekey` do. Just before each change from the switch to the deactivation of
  the old certificate is sent, it checks that the new certificate is still valid for more than a
  safety margin of five minutes plus twice the call timeout
  ([The safety margin](docs/tls-identities.md#the-safety-margin)). It never activates a certificate
  that fails that check, nor deactivates the one it replaces for it. `validFor` asks for the
  validity, at least ten minutes plus three times the call timeout, which keytend-kmip-server honors.
  `InMemoryKmipServer` implements Certify with a registered CA and honors the
  validity asked as that server does; `certifyHonorsDates(false)` models server builds that
  ignore it.
- The SDK renews its own client certificate through KMIP Re-Provision, on demand with
  `Kms.renewClientCertificate()` and, when `KmsConfig.Builder.clientCertificateRenewal`
  sets `CertificateRenewal.automatic(renewBefore)`, before the certificate expires. It makes the
  new key itself, writes it beside the key file before it sends anything, sends a PKCS#10
  request, checks the certificate the server issues, and replaces the PEM files or the key store.
  `CertificateRenewal.validFor` asks for a validity period, which keytend-kmip-server takes
  in a Critical Message Extension; a server that does not take it refuses the renewal
  before it issues anything.
  Renewals of the same files take turns, in one process and across processes (a lock file
  beside the key file). When the server refuses the old certificate on new connections after a
  lost reply, the SDK looks for the new certificate through the connections the `Kms` still has
  open on it. Every possible lockout is an `OutcomeUnknownException`, including a certificate the
  SDK refuses. Once the server retired the old certificate, the SDK refuses the new one only when
  it cannot serve as the client's TLS certificate, and reports what the server judges by its own
  clock or policy as a warning, including a period other than the one asked for. A pending key
  the server might still issue a certificate for is moved aside under a name of its own, never
  replacing another, and never deleted until a later renewal of that certificate succeeds, and
  the SDK looks for a certificate issued for it when the server refuses the old one. The renewal
  files are a stored format that later releases read
  ([Stored formats](docs/compatibility.md#stored-formats)). A certificate issued but not written
  to the files is a `RenewalNotSavedException`, which carries it in PEM, and later configurations
  of the same files in the process use it, as does a reload of the trust files meanwhile.
  `Kms.close()` stops a renewal that has not sent its request, and waits, up to three times the
  call timeout the renewal uses, for one that has, and reports through
  `clientCertificateRenewalWarning` when one outlives the wait. A later `close()` from another
  thread returns once the first has returned; one from inside the first, or from a renewal's
  thread, returns at once.
  `KmsListener` events report each renewal, each failure, a possible lockout and warnings that
  need attention, and the metrics modules count them as `kmip.tls.renewals`, one outcome per
  attempt, and `kmip.tls.renewal.warnings`. The in-memory server's `TlsListener` offers
  Re-Provision with `provisioningCa(...)`. Like keytend-kmip-server, it does not start
  with a provisioning CA that cannot sign certificates, is weak (a key below 112-bit security, or
  signed with SHA-1 or MD5), is not itself among its trust anchors or whose client certificates its
  trust refuses, and it checks each new certificate as that server's listener does: purpose
  sslclient, curves and strength, up to a self-signed root included. The CLI has
  `renew-certificate`
  ([Renew the client certificate](docs/production.md#renew-the-client-certificate)).
- The protocol layer (`client`, `model`, `codec`, `transport`, `server`), with every operation in
  TTLV, XML and JSON ([Protocol layer](docs/protocol-layer.md)).
- An in-memory KMIP server for tests and for trying the SDK out, with fault injection and a
  TLS listener ([In-memory server](docs/in-memory-server.md)). It is its own test artifact,
  `keytend-kmip-testing`, not in the SDK JAR or the release ZIP's `lib/`. Add it in test scope
  ([Test without a server](docs/getting-started.md#test-without-a-server)). The GitHub release
  has its JAR, sources and SBOM as separate assets.
- Client TLS credentials from PEM, PKCS#12 and JKS files, reloaded when they change
  ([Reload client credentials](docs/production.md#reload-client-credentials)).
- Logging, listeners and metrics. The SDK logs through SLF4J under fixed logger names, and never
  logs secrets ([Logging](docs/production.md#logging)). Listeners (`addListener`) hear each call,
  attempt, endpoint change, lease and cache load. `keytend-kmip-micrometer` and
  `keytend-kmip-opentelemetry` turn them into metrics, and the second also into spans
  ([Metrics](docs/production.md#metrics)).
- One runtime dependency, slf4j-api, for logging. The SDK's API has no other library's
  types. The JAR bundles Caffeine, relocated, for the `LocalKeys` cache
  ([Dependencies](docs/dependencies.md)).
- Integrations, built separately from the SDK artifact:
  a [Cassandra trunk commit log and hints key provider](integration/cassandra-trunk-tde/README.md)
  and a [Cassandra trunk TLS sample](integration/cassandra-trunk-tls/README.md).
- `keytend-kmip-cli`, a command-line tool to list, create, activate, rotate, expire, revoke
  and destroy keys, retire and reconcile lineages, store secrets and renew its client
  certificate. It is in the binary ZIP, with the libraries it needs, not on Maven Central
  ([cli/README.md](cli/README.md)). When `retire-predecessors` or `deactivate-predecessors`
  refuses a lineage as too long, each says how to proceed in steps and how to list the lineage
  from an older key ([cli/README.md](cli/README.md#retire-predecessors)).
- The GitHub release has two ZIPs. `keytend-kmip-<version>.zip` is the binary distribution: `lib/`,
  the CLI's launcher in `bin/`, and the release's test reports in `validation/`
  ([Where the results are](docs/validation.md#where-the-results-are)). It holds no source tree.
  The source is `keytend-kmip-<version>-src.zip`. Both are signed and listed in `SHA256SUMS`
  ([Verifying release artifacts](SECURITY.md#verifying-release-artifacts)).
- Reproducible, byte-identical distribution builds, a CycloneDX SBOM for each module the release
  ships, and fixtures of every stored format, which later releases must still read.

## Known limitations

- A server that states a Lease Time but does not implement Obtain Lease has every raw-key path
  refuse its keys under the default policy. `LeasePolicy.HONOR_IF_SUPPORTED` opts in, but such a
  server cannot recall a copy within its Lease Time.
- A raw key handed out cannot be recalled. A copy kept beyond its lease, in your own cache or
  a database's, breaks the server's lease policy. Keep raw keys in `LocalKeys`.
  [The Cassandra patches](integration/cassandra-trunk-tde/README.md#the-cassandra-patches) show
  what a database must do.
- Append-only files are re-checked only when the database asks. A database that sets up one
  cipher per file keeps writing under that key until the file ends. Cassandra's commit log and
  hints do this, and the trunk integration patches them.
- On JDK 17, the HTTPS client's selector thread ends only once the client is unreachable.
  JDK 21 and later stop it on `close()`.

## Validation

What the release checks test, and how to read and rerun them, is in
[Validation](docs/validation.md). This release's results are in its binary ZIP's `validation/`
([Where the results are](docs/validation.md#where-the-results-are)).

