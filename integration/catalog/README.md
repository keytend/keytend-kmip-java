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

# Interoperability catalog fixtures

> [!WARNING]
> **Experimental: not for production use.** keytend-kmip is experimental in every release. Its
> catalog is a test record. Passing it does not certify the SDK or any server.

Data fixtures for the interoperability catalog: the case manifest, the target inventory and the
pinned images. The Keytend project wrote the catalog and its tests. The runner records its
results separately and never rewrites the manifest. To run the catalog and read its results, see
[Interoperability catalog](../../docs/catalog.md).

## Files

| File | What it is |
| --- | --- |
| `catalog.json` | the case manifest: 145 cases |
| `server-inventory.json` | the servers the catalog runs against, and scope overlays |
| `qualified-images.properties` | the exact local images the catalog and the samples were qualified on |
| `pykmip-image-layers.json` | the layer list of the qualified PyKMIP image, behind its `layers:` pin |
| `reference.py` | an independent Python KMIP probe, with no SDK encoding or decoding |
| `generate-pki.sh` | a throwaway test PKI for the container and peer tests |

## Integrity

- `catalog.json` defines the cases only (status `DEFINITIONS_ONLY`). The runner never edits it.
- `tools/generate-catalog.py` derives the Java runner's case registry and the manifest's SHA-256
  from it.
- `CatalogContractTest` checks all 145 case IDs and that checksum.

## Scope notes

- The fixtures target KMIP 3.0 CSD02 and JDK 17, 21 and 25. A JDK 11 lane is outside the SDK's
  Java 17 minimum.
- `VER-11` uses a hypothetical KMIP 4.0 to test that a future version is rejected.
- `reference.py` provisions and reads back a known synthetic AES key over mutual TLS. It checks
  the CA and the host name, with no insecure fallback.
- The Krypton fixture under [`../krypton`](../krypton) runs a restricted profile with one known
  AES-256 key. It does not claim administrative, rotation or general lifecycle support.

## Test data

Only disposable synthetic keys are used. Cleanup deletes only the object IDs a run created, within
8 seconds plus 250 ms for each (at most 60 seconds), and records any that remain.
Testcontainers then removes the fixture. Licensed servers run only within their license terms.
