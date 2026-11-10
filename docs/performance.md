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

# Performance

This page measures the paths an application takes through the application API, and says what
they mean for a database write path. The tool is [tools/bench](../tools/bench/README.md).

## Summary

- On the hot path, a pinned key costs nanoseconds. An application map lookup is about 6 ns.
  `CurrentKey.handle()` with no check due is about 70–90 ns. Local AES-GCM of a 4 KiB record
  costs 1.7 µs.
- A `LocalKeys` hit costs 0.22–0.25 µs and sends no request. Hits scale with threads. Together,
  64 threads made 25–55 million calls per second.
- Every KMS request costs a round trip and the server's own work. Over pooled loopback TLS to an
  in-memory server, a Get Attributes takes about 46 µs. Against the live server it takes about
  0.6 ms, most of it the server's.
- On a write path, cache hits send no KMS request. A miss, or a key past its hard TTL, waits for
  the KMS or fails closed.
- Chunked files keep 73–81 % of streaming throughput.
- TLS followers add no measurable cost to a handshake.

## Environment

| | |
|---|---|
| Machine | AMD Ryzen AI MAX+ 395, 32 hardware threads, Linux 7.2.7 |
| JDK | Amazon Corretto 17.0.20+8-LTS, `-Xms1g -Xmx1g -XX:+UseG1GC` |
| SDK | development builds before the first release, 0.10.0 (identities below) |
| Server | native development builds of keytend-kmip-server, `serve` with its defaults |
| `Kms` settings | the defaults: pool 4, call timeout 30 s, connect timeout 10 s, 3 attempts; KMIP 2.1 |
| TLS | TLS 1.3, `TLS_AES_256_GCM_SHA384`, RSA-2048 test certificates |
| Load | 1-minute load average 0.4–23; other jobs shared the machine |

The figures were measured on those development builds, not on the keytend-kmip-server images
the release checks pin. Against the images, the release checks run the tool only as a smoke test,
which measures nothing.

| Topology | The `Kms` talks to | It shows |
|---|---|---|
| in process | `InMemoryKmipServer` through its in-process transport | the SDK's CPU cost per call |
| in-memory over TLS | the same server behind a loopback TLS 1.3 listener | the TLS transport and the pool |
| live | two keytend-kmip-server processes on loopback, mutual TLS | a real server |

In the in-process topology the server's work runs on the calling thread and is included. That
server build is a single-server design, so the two live servers have separate stores. Every live
scenario except failover uses the first server.

<details>
<summary>Build identities</summary>

```text
SDK jar, in-process rows, setup, rotation and failover rows
  91b40c0f433ad9c7fe72e2549e0627a6f4c74cf84cc08cef89de85b33bc17043
SDK jar, LocalKeys misses and renewals, TLS handshakes, chunked envelopes, moveName
  f8949cc5a16c387a7db3a22176dec32330e58d0a3d2637fb2e9a40bbfa2745f3
SDK jar, LocalKeys hits on many threads (commit 1ac57344)
  b9205a9bee114ebffd38257e3a6c1058feeee57f5d2d774896b79c1d150c2fe8
Server for the first set
  b5be56bbed64644dea866c4a188657c04a6e73e78e4b1eab74f35f356562d9c6
Server for the second set (default --max-lease-seconds 3600; --experimental-v3 for KMIP 3.0)
  7919b5b6c22090f6ed4ad5a7c676faf3bf8d19914e9a3483d6f9a64706252439
```

The pooled-request rows over TLS and live come from a development build whose jar hash was not
recorded. Compare numbers within one table.

</details>

## Results

Microseconds at p50 unless stated. "Requests" counts KMIP request messages per call.

### In process

This topology has no socket, so it shows the SDK's own cost.

| Call | Requests | p50 µs | p99 µs |
|---|--:|--:|--:|
| `map.get(id)` of a raw key, mean of 1000 | 0 | 0.006 | n/a |
| `CurrentKey.handle()`, no check due, mean of 1000 | 0 | 0.068 | n/a |
| `map.get` and local AES-GCM of 4 KiB | 0 | 1.65 | 2.96 |
| `attributes()`, one Get Attributes | 1 | 29.8 | 33.3 |
| `asSecretKey`, same handle again | 2 | 69.6 | 77.1 |
| `seal`, 4 KiB | 1 | 39.7 | 44.6 |
| `open`, 4 KiB | 2 | 70.0 | 76.0 |
| `sealing`, 64 MiB stream | 1 | 9,257 | 9,285 |
| `opening`, 64 MiB stream | 2 | 11,608 | 11,679 |
| `rotate()` | 4 | 292 | 1,903 |
| open a record sealed 64 rotations earlier | 66 | 2,421 | 4,989 |

The 64 MiB stream seals at 6,917 MiB/s and opens at 5,514 MiB/s. JCA AES-GCM over the same 64 KiB
chunks runs at 5,894 MiB/s. `CurrentKey.handle()` allocates 72 bytes per call. A map lookup
allocates nothing.

### In-memory server over loopback TLS

| Call | p50 µs | p99 µs | Calls/s |
|---|--:|--:|--:|
| `attributes()`, one Get Attributes | 46.2 | 68.4 | 20,966 |
| `asSecretKey`, same handle again | 103.8 | 184.1 | 9,193 |
| `asSecretKey`, a key not read before | 371.7 | 708.1 | 2,487 |
| `seal`, 100 B | 63.5 | 152.1 | 14,320 |
| `open`, 100 B | 107.9 | 263.4 | 8,581 |
| `asSecretKey`, 4 threads, pool 4 | 217.9 | 365.8 | 17,348 |
| `asSecretKey`, 64 threads, pool 4 | 4,276 | 7,246 | 14,714 |
| `asSecretKey`, 16 threads, pool 16 | 883.7 | 3,199 | 15,703 |
| open a record sealed 64 rotations earlier | 3,842 | 6,226 | 253 |
| `asSecretKey`, 4 threads, across two credential reloads | 215.0 | 365.3 | 17,162 |
| `findByName` on the second endpoint, after failover | 50.4 | 86.3 | 18,949 |

A request costs tens of microseconds, and the pool scales with the threads. The listener runs in
the same JVM, and its JSSE handshake is slower than the native server's. For connection setup,
use the live figures.

### Live server

At KMIP 2.1, four runs alternated on fresh stores. Each cell gives the range.

| Call | p50 µs | Calls/s |
|---|--:|--:|
| `attributes()`, one Get Attributes | 615–622 | 1,602–1,632 |
| `asSecretKey`, same handle again | 1,206–1,222 | 802–824 |
| `asSecretKey`, 1 thread, pool 4 | 1,282–1,288 | 785–792 |
| `asSecretKey`, 4 threads, pool 4 | 4,424–4,456 | 869–873 |
| `asSecretKey`, 16 threads, pool 4 | 17,285–17,973 | 855–903 |

With several callers the server is the limit, at about 850–900 `asSecretKey` calls per second.
A pool of 16 was no faster than a pool of 4. KMIP 1.4 performs as 2.1 does.

Other live costs:

- `KmsConfig.build()` takes 8.5 ms (PEM files and TLS context). `Kms.connect` takes 46 ms.
- Against a store grown by earlier scenarios, a Get Attributes took 1.1 ms.
- `rotate()` sends 4 requests and took 748 ms, nearly all of it the server's.
- Opening a record sealed *n* rotations earlier sends *n* + 2 requests. At *n* = 64 it took
  73 ms. A `CurrentKey` check after 64 rotations sends 65 requests and took 75 ms. Neither
  result is cached.
- After the first endpoint dies, the next call takes 139–216 ms, for the retry back-off and a
  new connection. Later calls cost what calls to a healthy server cost.
- A first endpoint that accepts TCP but never answers TLS costs the 10 s connect timeout at
  `Kms.connect`.
- A credential reload is noticed about 1 s after the files change, because they must be stable
  for the check interval. The call that reloads pays for a new TLS context and connection, up to
  62 ms in this run. No call failed.

### `LocalKeys`

Each cache has a TTL of 1 h and a capacity of 64. A hit is `forEncrypt()` or `forDecrypt(id)`,
then closing the `Use`.

#### Hits on many threads

In process, without Lease Time, calls per second over all threads, with p99. The machine's load
average was 3 to 16 during the run.

| Threads | `forEncrypt()` | `forDecrypt(id)`, 32 keys | `forDecrypt(id)`, 1 key |
|--:|--:|--:|--:|
| 1 | 4.1 M, 0.24 µs | 3.9 M, 0.26 µs | 3.9 M, 0.25 µs |
| 4 | 14.6 M, 0.34 µs | 13.5 M, 0.45 µs | 13.4 M, 0.47 µs |
| 16 | 39.2 M, 0.73 µs | 26.5 M, 0.93 µs | 20.5 M, 1.2 µs |
| 64 | 54.5 M, 0.99 µs | 46.3 M, 1.2 µs | 24.8 M, 2.8 µs |

On one thread a hit takes 0.22 µs at p50 (`forEncrypt`, 352 B) or 0.24 µs (`forDecrypt`,
376 B). The bytes are the `Use` and its copy of the key. One historical key that every thread
uses scales least. It still scales, because a hit records its access at most once a
millisecond. A leased key costs the same, because a hit checks its lease in memory.

#### Misses and renewals

Against the live server at KMIP 2.1, 1.4 and 3.0:

| Event | Requests | Caller waits | Live cost |
|---|--:|---|---|
| Hit | 0 | 0.22–0.25 µs | none |
| `forDecrypt(id)` miss | 3 | the load | 0.52–0.55 ms |
| `forEncrypt()` miss | 4 | the load | 2.2–2.3 ms |
| Renewal of a historical key | 3 | 6–41 µs to queue it | 1.4–1.5 ms, on the refresh thread |
| Renewal of the write key | 4 | 6–41 µs to queue it | 3.5–3.8 ms, on the refresh thread |

- A historical miss sends Get Attributes, Obtain Lease and Get. Obtain Lease is sent only when the
  key states a Lease Time.
- A write-key miss adds the name selection's Locate. Most of its cost is that selection. The
  measured build sent one more Get Attributes per write-key load, miss or renewal, for 5
  requests.
- A renewal never blocks a caller. The access that finds it due only queues it.

### TLS handshakes through the followers

A server using a `TlsIdentityFollower` and a `TlsTrustFollower` is compared with a server using
the JDK's static managers. One client with static managers connects to both, alternating.

| Measurement | Static managers | Followers |
|---|--:|--:|
| Full handshake, 1 thread | 1.95–2.39 ms | 2.03–2.36 ms |
| Handshakes per second, 8 threads | 2,983–3,296 | 3,002–3,310 |
| Key manager: alias, chain and key | 0.03–0.07 µs | 0.10–0.17 µs |
| Trust manager: `checkClientTrusted` | 2.5–4.1 µs | 3.0–3.1 µs |

A handshake sends no KMS request, also when the follower holds leases. In the background, a
refresh that finds nothing new costs:

- the identity follower: 3 requests, 2.7–2.8 ms live;
- the trust follower, with two queries: 5 requests, 4.7–4.8 ms live.

### Chunked files

The key-encryption key is AES-256. A file is 64 MiB in 1024 chunks of 64 KiB, on one thread.

| Operation | Requests | Live |
|---|--:|---|
| `chunkedSealer(fileId)`: new data key and header | 1 | 0.17–0.20 ms |
| `chunkedOpener(header, fileId)`: unwrap the data key | 2 | 0.35–0.39 ms |
| Seal or open one 64 KiB chunk | 0 | 12.0–12.6 µs |
| Seal a 64 MiB file | 0 | 12.4–12.5 ms, 5,110–5,167 MiB/s |
| Open a 64 MiB file | 0 | 12.9–13.1 ms, 4,895–4,963 MiB/s |
| Reference: `sealing` a 64 MiB stream | 1 | 9.5–10.0 ms, 6,409–6,752 MiB/s |

In these measurements chunked envelopes keep 73–81 % of streaming throughput, depending on the
operation. Each chunk runs a separate GCM operation and allocates
its output. Chunked sealing allocated 73 MB per 64 MiB file, against 1.8 MB for the stream. A
sealed chunk is 16 B longer than its plaintext.

### `moveName`

A move sends 5 requests at every version and took 3.0–3.1 ms live. Over 2000 moves, every move
succeeded.

## Guidance for a database write path

A database that encrypts on its write path, such as a commit log or a storage engine, must not
wait for a KMS on each write. [Local keys](local-keys.md) is the guide.

- Keep raw keys in one `LocalKeys` per node, not in an application map of `asSecretKey`
  copies. A copy kept past its KMIP lease breaks the server's lease policy. `LocalKeys` renews
  leases, revalidates in the background and drops a key once the KMS refuses it.
- Take one `Use` per cryptographic operation, not one per small record in a loop. A hit costs
  0.22–0.25 µs, against about 12 µs of AES-GCM for a 64 KiB chunk.
- Cache hits send no KMS request. A miss happens at startup, after `invalidate`, for an
  identifier not in the cache, and when the working set exceeds the capacity (64 by default). A
  miss, or a key past its hard TTL, waits for the KMS within the call deadline, or fails closed
  ([Refresh and expiry](local-keys.md#refresh-and-expiry)).
- With the default TTL of 5 minutes, a key in use is revalidated every 2.5 minutes. For 63
  historical keys and one write key, that is about 1.3 requests per second per node.
- `LocalKeys` follows rotation by name. It selects the write key again at each revalidation. Do
  not call `CurrentKey.handle()` with a check interval, `seal` or `open` on the write path. A due
  check stalls every caller for its duration, which after 64 rotations is 65 requests and about
  75 ms live. Run `refresh()` on a background thread instead.
- Read old data by identifier. `forDecrypt(id)` costs one load on a miss. A record sealed with
  `seal` *n* rotations ago costs *n* + 2 requests to open. Rewrap such records (`rewrapRecord`)
  after rotations.
- The default pool of 4 is enough for background traffic. A burst of misses, such as startup
  with many old files, queues on it. Against a live server, the server is the limit, and a
  larger pool did not help.
- `KmsConfig.build()` and `Kms.connect` take about 55 ms together. An endpoint that never
  answers costs the 10 s connect timeout. Order the endpoints, or lower `connectTimeout` for
  startup.
- A server that dies costs the next call 139–216 ms. A credential reload costs the call that
  notices it up to 62 ms. Neither touches the write path when that call runs on the refresh
  thread.
- Together, the TLS followers send 8 requests per refresh interval, about 7.5 ms live. At a 60 s
  interval, that is 0.13 requests per second.
- Chunked files give up some throughput for random access. At about 5 GiB/s per thread they are
  faster than a disk. Opening a file costs 2 requests and nothing is cached between openers, so
  opening many files at startup queues on the pool.

## Limits of these measurements

- Everything ran on one machine, over loopback, so there is no network round trip, loss or
  congestion. Client and servers share 32 hardware threads, and other jobs ran on the machine.
- Each measurement runs for seconds, once per topology, on JDK 17 only. No scenario left heap,
  threads or descriptors behind once its `Kms` closed. The 24-hour soak is JAVA-06 in
  [Catalog](catalog.md#soak-java-06).
- The server is small, with a store of about 40 objects, on the same machine. Its Locate, which
  the write key's selection and both followers send, costs more with a large store and over a
  network. A commercial KMS or a real replica set will differ.
- No application ran beside the bench. There is no database process, no competing allocation or
  GC pressure, and no disk I/O. Streams were sealed to a null sink and opened from memory.
- The in-memory server (`keytend-kmip-testing`) answers in microseconds and does not enforce
  leases. Its figures show the SDK's own cost.
- Password authentication, the HTTPS transport, Locate paging, lineages longer than 64
  rotations, and registering or renewing a TLS identity were not measured.

## Method and reproduction

`tools/bench/Bench.java` is one plain Java file, with no JMH. It is compiled against the SDK jar,
slf4j-api and the testing jar.
`tools/bench/run.sh` makes a throwaway PKI, compiles the tool and runs it once per topology.

- Warm-up calls run unrecorded first, so the JIT has compiled the path.
- Each call is timed with `System.nanoTime()` into a log-linear histogram, accurate to 0.1 %.
  Percentiles are nearest-rank.
- A timer pair alone costs 20 ns, so the pinned lookups are also given as the mean of batches of
  1000 calls.
- A `KmsListener` counts the requests per call. The bench also records bytes allocated per call,
  calls per second, and heap, threads and file descriptors before and after each scenario.

To reproduce, build the SDK and the in-memory server, and run the bench. The live topology runs
keytend-kmip-server from the pinned image ([tools/kmip-server](../tools/kmip-server/README.md)).

```sh
./mvnw -q -pl sdk,testing -am package -DskipTests
tools/bench/run.sh --topologies "inmemory inmemory-tls live" --versions "2.1 1.4" \
    --work /tmp/bench
tools/bench/run.sh --topologies "inmemory inmemory-tls live" --versions "2.1 1.4 3.0" \
    --scenarios localkeys,tls-handshake,chunked,movename --work /tmp/bench-paths
# A quick check of the tool, twenty times shorter:
tools/bench/run.sh --scale 0.05
```

Logs go to `<work>/<topology>.log` and `<work>/live-v<version>/bench.log`. Each log ends with its
rows as one Markdown table. [The benchmark's README](../tools/bench/README.md) lists the options
and the output.
