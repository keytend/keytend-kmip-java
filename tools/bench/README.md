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

# Application API benchmark

`Bench.java` measures the calls an application makes through the application API: key lookups,
raw-key reads, sealing, rotation, concurrency, failover, `LocalKeys` and TLS followers. It is an
opt-in tool. No Maven module, test or CI job runs it. The results and what they mean are in
[Performance](../../docs/performance.md).

## When to use it

- To measure an SDK build before and after a change.
- To see what a path costs against the in-memory server and against a real one.
- To check an SDK build's failover and credential reload on loopback.

## Requirements

- A JDK 17 or later, `openssl` and `python3`.
- An SDK jar, slf4j-api and the in-memory server's jar (`keytend-kmip-testing`). `./mvnw package`
  copies slf4j-api to `sdk/target/lib/`. `Bench.java` is one plain Java file compiled against
  them.
- For the `live` topology: Podman and the pinned keytend-kmip-server image, loaded as
  [tools/kmip-server](../kmip-server/README.md) describes.

## Build and run

From the repository root:

```sh
./mvnw -B -ntp -pl sdk,testing -am package -DskipTests
tools/bench/run.sh --jar sdk/target/keytend-kmip-0.10.0-rc.1.jar
```

This runs every scenario in the `inmemory` and `inmemory-tls` topologies. Add `live` to run
against two keytend-kmip-server containers. A short run checks the tool itself:

```sh
tools/bench/run.sh --jar sdk/target/keytend-kmip-0.10.0-rc.1.jar --topologies live \
  --versions "2.1 1.4 3.0" --scale 0.05 --work /tmp/kts-bench
```

`--scale 0.05` runs everything about twenty times shorter. Its numbers are not results. The
release checks run this smoke run against the pinned image
([the release checks](../../docs/releasing.md#the-release-checks)).

```text
tools/bench/run.sh [--jar SDK_JAR] [--testing-jar TESTING_JAR] [--topologies "T ..."] [--versions "V ..."]
    [--scale N] [--scenarios all|NAME,...] [--localkeys-threads N,...] [--work DIR]
```

| Option | Default | Meaning |
| --- | --- | --- |
| `--jar` | the first `sdk/target/keytend-kmip-*.jar` | the SDK jar to measure |
| `--testing-jar` | `testing/target/keytend-kmip-testing-<version>.jar`, the `--jar`'s version | the in-memory server (`keytend-kmip-testing`) |
| `--topologies` | `"inmemory inmemory-tls"` | any of `inmemory`, `inmemory-tls`, `live` |
| `--versions` | `"2.1"` | KMIP versions of the `live` topology, one run each |
| `--scale` | `1` | multiplies every iteration count |
| `--scenarios` | `all` | comma-separated scenario names (below) |
| `--localkeys-threads` | `1,4,16,64` | thread counts of the concurrent `localkeys` hits |
| `--work` | a new `/tmp/keytend-kmip-bench.*` directory | PKI, classes and logs |

`run.sh` makes a throwaway PKI in the work directory. It holds a CA, a server certificate for
127.0.0.1, and two client certificates for the reload scenario. A policy maps both to one
principal allowed every operation. `run.sh` then compiles `Bench.java` and runs it once per
topology with `-Xms1g -Xmx1g -XX:+UseG1GC`.

`Bench` also runs by hand:

```sh
cp='sdk/target/keytend-kmip-0.10.0-rc.1.jar:sdk/target/lib/*'
cp=$cp:testing/target/keytend-kmip-testing-0.10.0-rc.1.jar
java -cp "$cp" tools/bench/Bench.java --topology inmemory
java -cp "$cp" tools/bench/Bench.java --topology inmemory-tls --pki /path/to/pki
```

For `live`, add `--endpoints host:port,host:port` and `--kill-command CMD` or `--kill-pid PID`.
The failover scenario uses it to stop the first endpoint's server. The PKI directory holds
`ca.pem`, `server.pem`, `server.key`, `client.pem`, `client.key`, `client2.pem` and
`client2.key`, with unencrypted PKCS#8 keys. Without `--pki`, `tls-handshake` is skipped.

### Topologies

| Topology | What the `Kms` talks to | What it shows |
| --- | --- | --- |
| `inmemory` | `InMemoryKmipServer` in process: no sockets, TLS or pool | the SDK's own CPU cost per call |
| `inmemory-tls` | the same server behind a loopback TLS 1.3 listener in the JVM | the TLS transport, pool, failover and reload |
| `live` | two keytend-kmip-server containers on loopback, each with its own store | a real server, per KMIP version |

For `live`, `run.sh` checks the image, makes a master key with it and starts two containers.
Each has its own SQLite store under `live-v<version>/`. Every scenario but failover uses the
first endpoint. Failover runs last. It stops the first server with `run-server.sh stop`, then
times a `findByName` that the second server answers. KMIP 3.0 starts the server with
`--experimental-v3`. `run.sh` removes every container it started, also on exit or interrupt.

## Scenarios

| Scenario | Flag | What it measures |
| --- | --- | --- |
| Pinned lookups | `pinned` | a map of raw keys, `CurrentKey.handle()` with no check due, `CurrentKey.refresh()` |
| Cache misses | `miss` | `asSecretKey` of an identifier not read before, and on a new `Kms` |
| Warm pool | `pooled` | `asSecretKey` repeated, and `attributes()` |
| Records | `seal-open` | `seal` and `open` of 100 B and 4 KiB records |
| Streams | `streams` | `sealing` and `opening` of 1 MiB and 64 MiB streams |
| Old records | `rotations` | `open` through the newest key of a record sealed 0, 1, 32 and 64 rotations earlier |
| Checks under load | `current-check` | `CurrentKey.handle()` on 16 threads while inline or background checks run |
| Concurrency | `concurrency` | 1, 4, 16 and 64 callers against a pool of 4 and a pool of 16 |
| Credential reload | `reload` | calls around a client-certificate reload (`reloadOnChange`) |
| `LocalKeys` | `localkeys` | hits, misses and renewals of `forEncrypt()` and `forDecrypt(id)` |
| TLS handshakes | `tls-handshake` | full TLS 1.3 handshakes through the TLS followers, against JDK managers |
| Chunked files | `chunked` | `chunkedSealer`, `chunkedOpener`, one 64 KiB chunk and a 64 MiB file |
| Name moves | `movename` | `kms.keys().moveName(name, from, to)` back and forth |
| Failover | `failover` | the first call after the first endpoint dies, refuses connections or never answers |

The `localkeys`, `tls-handshake`, `chunked` and `movename` scenarios create their own objects.
Each object carries the client custom attribute `keytend-bench`, with a value unique to the run.

### `localkeys`

The cache has a TTL of 1 h and a capacity of 64, over a write key and 32 historical keys.

- **Hit:** a call, and closing its `Use`.
- **Miss:** `invalidate(id)`, then the call, which loads on the calling thread.
- **Concurrent hits:** at each count of `--localkeys-threads`. `forEncrypt()` shares one entry.
  `forDecrypt(id)` runs spread over the 32 keys, and on one key from every thread.
- **The caller's access to a due renewal:** a second cache with `refreshAfter(20 ms)` makes the
  access after a 20 ms pause queue a renewal. A control row times a hit after the same pause.
- **The renewal:** from that access to the answer of the renewal's Get on the refresh thread.

In memory it runs with no Lease Time, with a Lease Time of 1 h, and with a Lease Time of 2 s
that makes the renewal due. Live, each object has the server's Lease Time (3600 s by default).

### `tls-handshake`

The scenario registers the CA certificate as the anchor, the server's identity and the client's
certificate as an allowed peer. It runs two loopback TLS 1.3 servers that require client
authentication. One uses the followers' key and trust managers. The other uses the JDK's static
managers from the same files.

On one thread the two servers alternate. On 8 threads each runs on its own. Each connection uses
its own host name, so no session is resumed. Each server prints how many client chains it
checked, one per full handshake. The scenario also times each manager's own call and each
follower's `refresh()`.

### `chunked`

It times `chunkedSealer(fileId)`, which wraps a new data key in the KMS, and
`chunkedOpener(header, fileId)`, which unwraps it. Then it times one 64 KiB chunk and a 64 MiB
file of 1024 chunks. For reference it seals the same 64 MiB as a stream. It prints MiB/s.

## Output

Each scenario first prints its `Kms` configuration: endpoints, pool size, timeouts, retry policy
and KMIP version. Then it prints one Markdown table row per measurement.

| Column | Meaning |
| --- | --- |
| n | calls measured, after the warm-up calls |
| p50 ... p99.9, max | latency of one call in µs, nearest-rank, exact below 2048 ns, then within 0.1% |
| ops/s | calls divided by the wall time of the measurement, over all threads |
| req/op | KMIP requests sent per call, retries included (`KmsListener.started`) |
| B/op | bytes the calling thread allocated per call; other threads are not counted |

After each scenario a `resources` line gives the heap after `System.gc()`, the live threads and
the open file descriptors. It shows them before the scenario and after its `Kms` closed. Every
scenario also prints the 1, 5 and 15 minute load averages. On a shared machine, repeat a run
whose load was high.

The failover scenario prints what the `KmsListener` saw during the first call after the first
endpoint died. That shows the time of the refused attempt, the back-off, and the handshake with
the second endpoint.

The logs are `<work>/<topology>.log` and `<work>/live-v<version>/bench.log`. The server logs are
next to them.

## Limits

- There is no soak test. Each measurement runs for seconds, not hours. The 24-hour lane is `JAVA-06`
  in the [interoperability catalog](../../docs/catalog.md).
- Everything runs on one machine, over loopback. There is no network latency or loss, and the
  client and the servers share the CPUs.
- Nothing else runs in the JVM, so there is no GC pressure from an application.
- The two live servers do not share a store. keytend-kmip-server is a single-server design, so
  failover here is between two independent servers.
