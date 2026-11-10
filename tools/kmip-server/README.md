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

# keytend-kmip-server for the live tools

`run-server.sh` starts [keytend-kmip-server](https://github.com/keytend/keytend-kmip-server)
for every live tool in this repository. It runs one pinned container image with Podman. It is a
test tool, not a way to deploy the server.

## When to use it

The live tools call it for you:

- the [server probe](../server-probe/README.md), also run by `tools/release-check.sh --server DOCKER-TAR`;
- the [generic interop run](../../integration/keytend-kmip-server/README.md), also run by
  `tools/release-check.sh --server DOCKER-TAR`;
- the [benchmark](../bench/README.md), with `--topologies live`, whose smoke run
  `tools/release-check.sh --server DOCKER-TAR` runs too;
- the live test of the
  [Cassandra commit log and hints encryption](../../integration/cassandra-trunk-tde/README.md).

Run it yourself to load the pinned image on a new machine, or to start a throwaway server for
your own tests.

## Requirements

- Linux on amd64, with Podman. The script uses Podman's `--userns keep-id`.
- `python3`, to wait until the server is ready.
- To get the image: the GitHub CLI `gh`, `sha256sum`, `tar` and `cmp`.
- Optional: `gpg` and `cosign`, to verify the release's signatures.

## Build and run

Load the pinned image once. Run this block from the repository root.

```sh
repo_dir=$PWD
gh release download v0.10.0-rc.1 -R keytend/keytend-kmip-server -D /tmp/kts
(
  set -e
  cd /tmp/kts
  sha256sum -c keytend-kmip-server-0.10.0-rc.1-signed-release.tar.sha256
  tar -xf keytend-kmip-server-0.10.0-rc.1-signed-release.tar
  cmp SHA256SUMS release/SHA256SUMS
  cd release && sha256sum -c SHA256SUMS
)
# Optional: verify the signatures (needs gpg and cosign)
(cd /tmp/kts && gpg --verify SHA256SUMS.asc SHA256SUMS && \
  cosign verify-blob --key cosign.pub --insecure-ignore-tlog=true \
  --bundle SHA256SUMS.sigstore.json SHA256SUMS)
"$repo_dir/tools/kmip-server/run-server.sh" image \
  /tmp/kts/release/linux-amd64/keytend-kmip-server-0.10.0-rc.1.docker.tar
```

The optional step checks `SHA256SUMS` twice:

- `gpg` checks its OpenPGP signature. It must be a good signature by the keytend release key,
  primary fingerprint `3A84912AFBE7D2B04EBA2A8A51E65DD49C6F987F`. Import the key first, as
  [SECURITY.md](../../SECURITY.md#verifying-release-artifacts) shows.
- `cosign` checks the Sigstore bundle against the `cosign.pub` in the same download, without the
  Rekor transparency log (`--insecure-ignore-tlog=true`). It shows that the files are
  consistent, not who published them.

The check that matters is the last command. `run-server.sh image` refuses an archive whose
SHA-256 is not the `archive_sha256` pinned in `pinned-image.properties`. It loads the archive,
then checks the loaded image's ID and prints it. Without an argument, it checks the image that is
already loaded.

Then start a server on a store directory you own. `pki_dir` is your directory with
`server.pem`, `server.key`, `ca.pem` and `policy.json`. The first command adds `master.key`.

```sh
pki_dir=/path/to/pki
tools/kmip-server/run-server.sh master-key "$pki_dir/master.key"
mkdir -p /tmp/kts-store
tools/kmip-server/run-server.sh start kts-1 --data /tmp/kts-store --pki "$pki_dir" \
  -- --experimental-v3
tools/kmip-server/run-server.sh stop kts-1
```

`start` waits until `/readyz` answers 200, then prints `port=P health=P`.

### Commands

```text
run-server.sh image [DOCKER-TAR|IMAGE]   verify (and load) the image; print its ID
run-server.sh version                    the image's --version
run-server.sh master-key FILE            a new master key (the image's generate-master-key)
run-server.sh start NAME --data DIR (--pki DIR | --cert F --key F --ca F --policy F --master-key F)
    [--users F] [--validation-ca F] [--provisioning-ca F --provisioning-ca-key F]
    [--port P] [--health-port P] [--log FILE] [-- SERVE-OPTION...]
run-server.sh stop NAME...               SIGTERM, SIGKILL after 2 s; wait until removed
run-server.sh kill NAME...               SIGKILL at once (an outage); wait until removed
run-server.sh running NAME               exit 0 if running
run-server.sh cleanup PREFIX             remove every container of this helper named PREFIX*
```

`image` exits 0 for the pinned image and 10 for another image allowed by
`KEYTEND_SERVER_UNPINNED=1`. Any other non-zero exit is a refusal or a failure.

### What `start` runs

`start` runs the image's `serve` with `podman run --rm`:

- The server certificate, key, client CA, policy and master key are each mounted read-only.
  `--users`, `--validation-ca`, and `--provisioning-ca` with `--provisioning-ca-key` (the two go
  together) mount and pass those files too. No other PKI file enters the container. The server
  takes a provisioning CA only when its certificate is also in the `--ca` bundle.
- The store is `kmip.sqlite` in `--data DIR`, which must exist. The container runs as UID
  10001, mapped to you, so you own the store and can read it.
- The root file system is read-only, with a 64 MiB `/tmp`. The container has no capabilities
  and `no-new-privileges`.
- KMIP (5696) and health (8080) listen on `127.0.0.1`, on the given host ports or on free ones.
- The `SERVE-OPTION`s after `--` follow, such as `--experimental-v3` or `--max-lease-seconds N`.
- Every `KMIP_*` variable of your environment reaches the server, such as
  `KMIP_LEASE_STATES=active`.
- The container's output is appended to `--log`, by default `DIR/server-NAME.log`.

A stopped, killed or crashed container is removed, but its store stays. `start` again on the
same `--data` and ports recovers the same server. The tools `cleanup` their own prefix on exit,
so nothing is left running after a failure.

## Configuration

[`pinned-image.properties`](pinned-image.properties) names one build: keytend-kmip-server
0.10.0-rc.1, its linux/amd64 Docker archive by SHA-256, and the image that archive loads by ID.
`run-server.sh` starts only that image ID. It loads an archive only if its SHA-256 matches.

| Setting | Default | Meaning |
| --- | --- | --- |
| `KEYTEND_SERVER_IMAGE` | the pin's `image` | the image ID or reference to run |
| `KEYTEND_SERVER_UNPINNED` | unset | `1` runs an image that is not the pin, with a warning |
| `PODMAN` | `podman` | the container command |
| `KMIP_*` | none | passed to the server unchanged |

`tools/release-check.sh` records a run with `--server-unpinned` as `UNPIN`, never as a pass.

## Limits

- Only one server can use a store at a time. The server locks its store, and a second container
  given the same `--data` exits at startup (`the store is in use by a running server`). Start it
  only once the first is down. The server's own documentation says more replicas are not a
  high-availability configuration.
- Stores written by early development builds of the server do not open (`invalid master key`). Every tool makes a fresh store per run.
- The pin covers one platform, linux/amd64.
