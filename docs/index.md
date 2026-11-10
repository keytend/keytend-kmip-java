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

# Documentation

> [!WARNING]
> **Experimental: not for production use.** keytend-kmip is experimental in every release. It
> started as an experiment in implementing the KMIP specification.

These docs are those of 0.10.0-rc.1, a pre-release of the first release, 0.10.0. For the docs of a
published release, read them at its tag, such as
[`v0.10.0-rc.1`](https://github.com/keytend/keytend-kmip-java/tree/v0.10.0-rc.1/docs).

## Start here

- [Getting started](getting-started.md): build and install, connect to a KMS, seal a record,
  handle failures and test without a server.
- [Choosing an API](choosing-an-api.md): the entry point for each job.

## Guides

- [Envelope encryption](envelope-encryption.md): seal records, streams and files with a key that
  stays in the KMS.
- [Local keys](local-keys.md): raw keys from the KMS for local file encryption, with caching,
  leases and database key providers.
- [Key lifecycle](operating-keys.md): rotate keys, retire old ones, recover from a compromise and
  replace secrets.
- [TLS identities](tls-identities.md): node certificates and trust taken from the KMS.
- [Running in production](production.md): failover, deadlines and retries, credential reload, client
  certificate renewal, readiness, logging, metrics (Micrometer or OpenTelemetry), traces, listeners,
  per-consumer credentials and qualifying a server.
- [Protocol layer](protocol-layer.md): KMIP requests, batches, codecs and transports.
- [Migration](migration.md): replace protocol-layer calls with the application API.

## Integrations and tools

- [keytend-kmip-cli](../cli/README.md): manage keys on a KMIP server from the command line.
- [Cassandra commit log and hints encryption](../integration/cassandra-trunk-tde/README.md)
  (trial), for Apache Cassandra trunk on `LocalKeys`.
- [Cassandra TLS with node identities from the KMS](../integration/cassandra-trunk-tls/README.md)
  (sample), on `kms.tls()`.
- [Benchmark](../tools/bench/README.md): measure the application API in process or live.
- [Live probe](../tools/server-probe/README.md): check the SDK against keytend-kmip-server.
- [Pinned keytend-kmip-server](../tools/kmip-server/README.md): the server image the live tools
  use.

## Reference

- [Compatibility and support](compatibility.md): what each release promises, API tiers, Java
  and KMIP versions.
- [Dependencies](dependencies.md): the libraries the SDK, the CLI and the tests use, why, and
  their licenses.
- [Stored formats](stored-formats.md): the byte layouts of ciphertexts and sealed data.
- [In-memory test server](in-memory-server.md): how `InMemoryKmipServer` (the test artifact
  `keytend-kmip-testing`) answers KMIP requests, and what it does not support.
- [Design notes](kms-design.md): why the application API behaves as it does.
- [Protocol coverage](protocol-coverage.md): the KMIP operations, objects and attributes the SDK
  encodes.
- [Security policy](../SECURITY.md): reporting vulnerabilities, handling secrets, verifying
  releases.
- [Release notes](../RELEASE.md).

## Evidence

- [Validation](validation.md): current results against real KMIP servers, how to read them and
  how to run the tests.
- [Interoperability catalog](catalog.md): the shared test cases and their outcomes.
  Its data files are in [integration/catalog](../integration/catalog/README.md).
- [Interop suite against keytend-kmip-server](../integration/keytend-kmip-server/README.md):
  the generic interop suite on every KMIP version from 1.1 to the 3.0 draft.
- [Performance](performance.md): measured costs of the application paths.
- [Research](research.md): KMIP sources and how the test servers were chosen.

## Maintainers

- [Releasing](releasing.md): the release checks and publication steps.
- [Licensing](licensing.md): the SDK's license, source headers and third-party material.
