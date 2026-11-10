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

# Protocol and server research

This page lists the sources the SDK is built from, how the test servers were chosen, and how the
independent checks work. The research is dated 2026-10-23.

## Protocol versions

A KMIP protocol version is a major and a minor number. There is no patch field. The SDK
supports 1.1, 1.2, 1.3, 1.4, 2.0, 2.1 and 3.0.

KMIP 3.0 is still a draft. The SDK pins 3.0 CSD02, not a moving draft URL.

## Normative sources

- [KMIP 1.1 OASIS Standard](https://docs.oasis-open.org/kmip/spec/v1.1/os/kmip-spec-v1.1-os.html)
- [KMIP 1.2 OASIS Standard](https://docs.oasis-open.org/kmip/spec/v1.2/os/kmip-spec-v1.2-os.html)
- [KMIP 1.3 OASIS Standard](https://docs.oasis-open.org/kmip/spec/v1.3/os/kmip-spec-v1.3-os.html)
- [KMIP 1.4 OASIS Standard](https://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html)
- [KMIP 2.0 OASIS Standard](https://docs.oasis-open.org/kmip/kmip-spec/v2.0/os/kmip-spec-v2.0-os.html)
- [KMIP 2.1 OASIS Standard](https://docs.oasis-open.org/kmip/kmip-spec/v2.1/os/kmip-spec-v2.1-os.html)
- [KMIP 3.0 Specification CSD02, 7 May 2026](https://docs.oasis-open.org/kmip/kmip-spec/v3.0/csd02/kmip-spec-v3.0-csd02.html)
- [KMIP 3.0 Profiles CSD02, 21 May 2026](https://docs.oasis-open.org/kmip/kmip-profiles/v3.0/csd02/kmip-profiles-v3.0-csd02.html)

## Changes between versions that matter to applications

- KMIP 1.x wraps attributes in AttributeName and AttributeValue, and uses TemplateAttribute.
  2.x uses direct attributes, with AttributeReference, CurrentAttribute and NewAttribute.
- KMIP 1.2 adds the cryptographic and streaming operations.
- KMIP 1.4 adds Import and Export, correlation strings and AEAD parameters.
- KMIP 2.0 adds extended timestamps, authentication and administrative operations.
  AsynchronousIndicator becomes an enumeration.
- KMIP 2.1 adds constraints, defaults and more asynchronous controls.
- KMIP 3.0 adds the Identifier, Reference and NameReference types. It adds user, group and
  credential operations, explicit deactivation, obliteration and KEM encapsulation. It removes
  BatchCount, BatchOrderOption and UniqueBatchItemID. Ephemeral controls which response data is
  returned.

[Protocol coverage](protocol-coverage.md) lists every operation by version.

## How the test servers were chosen

Every selected server has public source, builds from a pinned revision or image digest, runs in
a container and accepts mutual TLS. PyKMIP covers 1.1 to 1.4 (with a 2.0 probe) and PQCToday
the 3.0 draft. [keytend-kmip-server](../integration/keytend-kmip-server/README.md) covers every
supported version.

No server here implements the whole protocol, and the profiles are separate conformance
targets. [Validation](validation.md) records what each server ran.

### PyKMIP

- **Source:** [OpenKMIP/PyKMIP](https://github.com/OpenKMIP/PyKMIP), Apache-2.0, pinned to
  `481563735cc96eb9f7b363df3c24b2ea68b9353f`.
- **Used for:** KMIP 1.1 to 1.4 lifecycle, attributes, registration and cryptography.
- **Limits:** its documentation positions the server for tests and demonstrations. Some
  operation handlers and parts of discovery are missing.
- **Fixture:** Python 3.12 from Red Hat UBI 9, pinned cryptography and SQLAlchemy versions,
  mTLS and an ephemeral SQLite store.

### PQCToday KMIP

- **Source:** [pqctoday-hsm/kmip](https://github.com/pqctoday-org/pqctoday-hsm/tree/main/kmip),
  AGPL-3.0-only, pinned to `010da23173bd39a57113fe8f5e9466981a52e27c`.
- **Used for:** the 3.0 draft. It is a Rust server over its own PKCS#11 engine. It covers
  modern attributes, system objects and ML-KEM.
- **Fixture:** the original server built with its locked Cargo dependencies, data-plane mTLS,
  and the server's Interop test mode.

### Krypton

- **Source:** [openkcm/krypton](https://github.com/openkcm/krypton), Apache-2.0, pinned to
  `7ca8dc58615f506b8ce7e9359e625df5cf72a7e5`.
- **Used for:** KMIP 1.4 exact-ID Get against a production listener, authorizer and encrypted
  vault. It exposes a narrow, read-oriented set of handlers.
- **Fixture:** a small adapter from its upstream test setup provisions one known AES key
  ([catalog](catalog.md#targets)).

The fixtures this project builds run on Red Hat Universal Base Image 9: `ubi-micro` for the
static Go server (Krypton), `ubi-minimal` for PyKMIP and PQCToday. UBI 9 receives Red Hat's
security updates and ships FIPS-capable OpenSSL packages.

PyKMIP, PQCToday and Krypton are OSI open source. No server code is linked into the SDK, and the
SDK has no runtime dependency on any of them.

## Independent checks

Each check uses code that does not share the SDK's encoder or decoder.

- `tools/generate_registry.py` generates the registry. It reads each version's tag, enumeration,
  operation, structure-order and payload tables from the OASIS documents. The generated files and
  source URLs are checked in, so a build downloads nothing.
- `tools/fetch_oasis_vectors.py` downloads the unmodified OASIS test transcripts. Its manifest
  records each URL and SHA-256. The codec tests round-trip every transcript through binary, XML
  and JSON.
- OVH [kmip-go](https://github.com/ovh/kmip-go) v0.9.2, a separate Go implementation,
  generated 2,712 binary wire digests as an oracle. `oracle.tsv` holds them, and the tests
  compare the SDK's bytes with them.
- The integration tests check server cryptography with JCA/JCE.
- `OasisReplay` sends whole OASIS transcripts to a server and binds the identifiers and
  correlation values it returns. It reports differences. It never rewrites a request to suit a
  server.

One published ECDSA transcript ends with a duplicated `</KMIP>`. Only the test and replay input
normalizer repairs it. The downloaded original and its checksum are kept unchanged.

[Validation](validation.md#how-to-read-the-results) explains what each kind of check shows.
