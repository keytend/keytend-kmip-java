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

# Cassandra TLS with node identities from the KMS (sample)

> [!WARNING]
> **Experimental: not for production use.** A sample on the experimental keytend-kmip SDK. Do
> not use it to protect real traffic.

This sample gives Apache Cassandra client and internode TLS whose identities, trust anchors and
allowed peers live in a KMIP server. It follows them through the SDK's `kms.tls()`
([TLS identities](../../docs/tls-identities.md)), so a renewal takes effect without a restart. It
is a sample for Apache Cassandra trunk at `275a3a5`, built separately from the SDK.

No private key, anchor or allowlist is on the node's disk. The node keeps only its KMS client
credential.

> [!WARNING]
> A node presents its certificate, and trusts anchors and peers, only while their KMIP leases
> run. A KMS outage longer than the Lease Time is a TLS outage on each node, as its leases end.

## When to use it

- You run Cassandra trunk and want node and client certificates managed in a KMS.
- You want renewal, re-key and revocation to reach every node without a restart.
- You want Cassandra's mutual-TLS authenticators to accept only peers the KMS allows.

For commit log and hints encryption with keys in the same kind of KMS, see
[`cassandra-trunk-tde`](../cassandra-trunk-tde/README.md).

## Requirements

- Apache Cassandra trunk at `275a3a5`, built with `ant jar build-test`. No Cassandra patch is
  needed. The sample uses only the public `ISslContextFactory` and
  `MutualTlsCertificateValidator` hooks.
- A JDK 17, Apache Ant and git.
- The SDK, built from this repository (below).
- A KMIP server that holds the node identities. The tests use the in-memory server
  (`keytend-kmip-testing`, a test-only artifact).

## Build and run

From the repository root. The Cassandra checkout goes beside it, in `../cassandra-trunk`.

```sh
JAVA17_HOME=/path/to/jdk-17
export JAVA_HOME=$JAVA17_HOME PATH=$JAVA17_HOME/bin:$PATH
git clone https://github.com/apache/cassandra.git ../cassandra-trunk
git -C ../cassandra-trunk checkout 275a3a5
(cd ../cassandra-trunk && ant jar build-test)
./mvnw -B -ntp -pl sdk,testing -am package -DskipTests
integration/cassandra-trunk-tls/build.sh ../cassandra-trunk sdk/target/keytend-kmip-0.10.0-rc.1.jar
```

`build.sh` compiles the sample and writes `target/keytend-kmip-cassandra-tls.jar`. It runs the
standalone tests, and compiles the dtest against the checkout's test classes. It writes nothing
outside `target/` without `--install`.

To run the in-JVM dtest, install into the checkout and run it there:

```sh
integration/cassandra-trunk-tls/build.sh ../cassandra-trunk \
  sdk/target/keytend-kmip-0.10.0-rc.1.jar --install
cd ../cassandra-trunk
ant build-test
ant test-jvm-dtest-some -Dtest.name=org.apache.cassandra.distributed.test.KmipTlsTest
```

```text
integration/cassandra-trunk-tls/build.sh CASSANDRA_DIR SDK_JAR [--install]
```

`--install` copies the SDK jar and the sample's jar into the checkout's `lib/` and
`build/lib/jars/`, replacing any `keytend-kmip-*.jar` there. It also copies `cassandra-tests/`
into its `test/unit` and `test/distributed`. Use a clean trunk checkout.

The tests use the in-memory KMIP server, `keytend-kmip-testing`. `build.sh` takes
`testing/target/keytend-kmip-testing-<version>.jar` (or `KEYTEND_TESTING_JAR`) for its tests,
and `--install` puts it only on ant's test class path, `build/test/lib/jars/`, never in `lib/`.

On a node, put both jars in `lib/` and configure `cassandra.yaml` as below.

### Layout

| Path | What it is |
| --- | --- |
| `src/main/java/.../tls/KmipSslContextFactory.java` | the `ssl_context_factory`, with the SDK's key and trust managers |
| `src/main/java/.../tls/KmipTlsMaterial.java` | the identity and trust followers per configuration, and their status |
| `src/main/java/.../tls/KmipCertificateValidator.java` | the authenticators' `validator_class_name` |
| `src/main/java/.../tls/KmipConnections.java` | the KMS connection parameters, one `Kms` per configuration |
| `src/test/java/...` | standalone tests, without a node |
| `cassandra-tests/unit/.../tls/` | test support: `TestPki`, `TlsAdmin` and `KmsTestServer` |
| `cassandra-tests/distributed/.../KmipTlsTest.java` | the in-JVM dtest |
| `build.sh` | build, test, and optionally install into a trunk checkout |

## Configuration

The sample's classes are in `dev.keytend.kmip.cassandra.tls`. Both encryption option sets use
the factory with the same parameters, so they share one material. Both authenticators use the
validator.

```yaml
server_encryption_options:
  internode_encryption: all
  require_client_auth: true
  ssl_context_factory:
    class_name: dev.keytend.kmip.cassandra.tls.KmipSslContextFactory
    parameters:
      kmip_endpoints: kms1.example:5696,kms2.example:5696
      kmip_client_certificate: /etc/cassandra/kms/node1-client.pem
      kmip_client_key: /etc/cassandra/kms/node1-client.key
      kmip_trust_certificates: /etc/cassandra/kms/kms-ca.pem
      kmip_tls_identity: cluster1/node1
      kmip_tls_domain: cluster1
client_encryption_options:
  enabled: true
  require_client_auth: required
  ssl_context_factory:
    class_name: dev.keytend.kmip.cassandra.tls.KmipSslContextFactory
    parameters:   # the same as above, written out (not a YAML alias)
      kmip_endpoints: kms1.example:5696,kms2.example:5696
      kmip_client_certificate: /etc/cassandra/kms/node1-client.pem
      kmip_client_key: /etc/cassandra/kms/node1-client.key
      kmip_trust_certificates: /etc/cassandra/kms/kms-ca.pem
      kmip_tls_identity: cluster1/node1
      kmip_tls_domain: cluster1
authenticator:
  class_name: org.apache.cassandra.auth.MutualTlsAuthenticator
  parameters:
    validator_class_name: dev.keytend.kmip.cassandra.tls.KmipCertificateValidator
internode_authenticator:
  class_name: org.apache.cassandra.auth.MutualTlsInternodeAuthenticator
  parameters:
    validator_class_name: dev.keytend.kmip.cassandra.tls.KmipCertificateValidator
    trusted_peer_identities: spiffe://cluster1/node1,spiffe://cluster1/node2,spiffe://cluster1/node3
```

`trusted_peer_identities` is required. Without it, `MutualTlsInternodeAuthenticator` reads the
node's identity from an outbound keystore file, which this setup does not have. Clients are
mapped to roles by their SPIFFE ID as usual:
`ADD IDENTITY 'spiffe://cluster1/app' TO ROLE app_role`.

| Parameter | Default | Meaning |
| --- | --- | --- |
| `kmip_endpoints` | required | `host:port,...`, replicas of one KMS |
| `kmip_client_certificate` | required | PEM file of the node's KMS client certificate |
| `kmip_client_key` | required | PEM file of its private key; `kmip_client_key_password` if encrypted |
| `kmip_trust_certificates` | required | PEM of the KMS's CA |
| `kmip_min_version`, `kmip_max_version` | the SDK's | `1.4`, `2.1` or `3.0` |
| `kmip_call_timeout` | `10s` | the deadline of one KMS call |
| `kmip_reload_credentials` | `true` | re-read the KMS client files when they change |
| `kmip_startup_timeout` | `0s` | how long the first connection keeps trying an unreachable KMS |
| `kmip_tls_identity` | required | the node's TLS identity name in the KMS |
| `kmip_tls_domain` | required | the domain of the anchors and registered peers (below) |
| `kmip_tls_refresh_interval` | `60s` | how often the identity, anchors and peers are read again |
| `kmip_tls_require_registered_peers` | `true` | accept only registered peers at the handshake |
| `kmip_tls_unknown_peer_check` | `2s` | the bound of the background check of an unknown peer; `0s` is off |
| `kmip_tls_unknown_peer_check_in_handshake` | `false` | run that check in the handshake; keep `false` |
| `kmip_tls_unknown_peer_check_per_certificate` | `30s` | check one certificate at most this often; `0s` lifts the limit |
| `kmip_tls_unknown_peer_check_gap` | `1s` | the least time between two checks; `0s` lifts the limit |
| `kmip_tls_unknown_peer_check_queue` | `64` | the most checks waiting for a refresh thread |
| `kmip_tls_usable_warn` | a quarter of the longest `usableFor` seen | warn when usable for less; `0s` is off |

Notes on the parameters:

- `kmip_client_certificate`, `kmip_client_key`: the KMS client credential is a file. The node
  needs it to reach the KMS before it has any TLS material.
- `kmip_tls_domain`: anchors carry the client custom attribute `cassandra-tls=<domain>:ca`.
  Registered peers carry `cassandra-tls=<domain>:identity`.
- `kmip_tls_refresh_interval`: a follower refreshes sooner when a lease ends sooner.
- `kmip_tls_require_registered_peers`: the validator consults only materials with `true`. With
  `false`, any chain to an anchor is accepted, so a revoked certificate that still chains to an
  anchor passes.
- `kmip_tls_unknown_peer_check`: a peer that chains to an anchor but is not read yet, such as one
  that has just renewed, is refused at once. The check then runs on the refresh threads, and the
  peer's next handshake is accepted. With `0s` it is refused until the next refresh.
- `kmip_tls_unknown_peer_check_in_handshake`: `true` makes the handshake wait for the check.
  Cassandra runs TLS handshakes on Netty event loops, which must not block, so keep `false`.
- `kmip_tls_usable_warn`: the WARN line repeats at most once a minute.

## Operating it

### How it behaves

- Handshakes read the current pair, anchors and peers from memory. Nothing waits for the KMS. A
  change takes effect for new connections at the next refresh.
- A change also makes `shouldReload()` true. Cassandra's hot reloading, every 10 minutes, then
  rebuilds its cached contexts and logs "SSL certificates have been updated". Correctness does not
  depend on that rebuild.
- The validator asks `allows(chain)` of each material that requires registered peers. The chain must
  validate against anchors whose leases run. Its leaf must be an Active registered peer whose lease
  runs. A peer the node has not read yet is refused until it is read.
- Each change is logged with its state and how long the material stays usable without the KMS, such
  as `TLS identity cluster1/node1 is now CURRENT: ...; usable for PT59M59S without the KMS`. The SDK
  logs the rest under its fixed loggers ([Logging](../../docs/production.md#logging)): unavailable
  endpoints, TLS file reloads, state changes of the identity's objects (`<logger
  name="dev.keytend.kmip" level="INFO"/>` in `logback.xml`).
- The status is not exposed over JMX. `KmipTlsMaterial.minUsableFor()` is the least time any
  material of the node stays usable. It is empty when no lease limits it. Per material
  (`KmipTlsMaterial.all()`) there are `identityUsableFor()`, `trustUsableFor()`, `usableFor()`,
  `usableWarning()` and `status()`. Export `minUsableFor()` to your metrics, or alert on the WARN
  line.

### KMS outage

While the KMS cannot be reached, each follower keeps what it read last. Its `status()` is
`STALE` and `usableFor()` falls. Once a lease runs out, the node stops presenting or trusting
that object.

- Size the server's Lease Time for the outages you must ride out. keytend-kmip-server states
  `--max-lease-seconds`, 3600 s by default.
- Alarm on `usableFor` well before zero.
- On a server that states no Lease Time, nothing limits it and `usableFor()` is empty.

A node cannot start TLS while the KMS is down. The factory fails, and Cassandra does not start.
`kmip_startup_timeout` waits for the KMS for a bounded time. There is no on-disk cache, because a
private key on disk would outlive a revocation. Restart nodes only while the KMS is reachable.

### Runbook

Run these from one place with the operator's KMS credential, never from the nodes. Make one
change at a time per identity. `TlsAdmin` in the tests makes the same calls.

```java
// kms is the operator's Kms. caCert, leaf, issuingCa, newLeaf and appCert are X509Certificates.
// nodeKey and newKey are PrivateKeys.
CustomAttribute tag = CustomAttribute.client("cassandra-tls");

// Trust anchor. Nodes read it at their next refresh.
kms.keys().register(caCert).custom(tag, "cluster1:ca").register();

// Node identity. The node reads it when it starts.
kms.tls().register(nodeKey, leaf, issuingCa)
    .named("cluster1/node1")
    .custom(tag, "cluster1:identity")
    .register();

// Client. Allowed at the next refresh, or at its second connection.
kms.keys().register(appCert).custom(tag, "cluster1:identity").register();

// Renew a node with the same key. The node presents the new certificate at its next refresh.
// Peers admit it at its second connection, or at their next refresh.
kms.tls().identity("cluster1/node1").orElseThrow().renew(newLeaf, issuingCa);

// Or re-key it: a new key and certificate, with the same effect.
kms.tls().identity("cluster1/node1").orElseThrow().rekey(newKey, newLeaf, issuingCa);

// Revoke a client. It is refused at its next connection after the next refresh.
Map<String, X509Certificate> peers =
    kms.tls().certificates(KeyQuery.all().custom(tag, "cluster1:identity"));
peers.forEach((id, cert) -> {
  if (cert.equals(appCert)) {
    kms.keys().handle(id).revoke(RevocationReason.cessationOfOperation("client retired"));
  }
});

// A compromised node: revoke, then re-key under the same name.
// compromisedSince is the Instant from which the key is considered compromised.
kms.tls().identity("cluster1/node1").orElseThrow()
    .revoke(RevocationReason.keyCompromise("node1 key compromised", compromisedSince));
kms.tls().identity("cluster1/node1").orElseThrow().rekey(newKey, newLeaf, issuingCa);
```

After a compromise the node stops presenting the old pair at its next refresh, and cannot start
with it. After the re-key it starts and presents the new pair.

Registration without `usages(...)` derives each certificate's usages from its X.509 Key Usage.
A CA with keyCertSign and cRLSign gets Certificate Sign and CRL Sign, not Verify. So ordinary CA
chains register on KMIP 1.x servers that refuse a usage the certificate does not grant.

A renewed node presents its old certificate until its own follower refreshes. Peers refuse that
certificate once they read the renewal. Keep the refresh interval short, and let clients retry.
For the background check's rate limits during a mass renewal, see
[TLS identities](../../docs/tls-identities.md).

### Node credentials

A node's KMS credential (`kmip_client_*`) needs only:

- Discover Versions, to connect;
- Locate, Get Attributes and Get, for certificates and the node's own private key;
- Obtain Lease, where the server states a Lease Time.

The KMS performs no Encrypt, Decrypt or Sign for TLS. The node signs handshakes with the private
key it reads. Where the server's policy can, restrict Get of private keys to each node's own
identity. Other consumers' credentials are in
[What each consumer's credential needs](../../docs/production.md#what-each-consumers-credential-needs).

## Limits

- This is sample code. It is not part of the SDK artifact, and the SDK has no Cassandra
  dependency.
- This sample is tested only on the pinned Apache Cassandra trunk revision.
- The tests use the in-memory KMIP server, not a real KMS.
- Cassandra gives neither hook a shutdown call. The refresh threads are daemons in the sample's
  own thread group.
- There is no on-disk cache, so a node cannot start TLS without the KMS.
- Netty's OpenSSL provider (the tests use JDK contexts) and leases running out on a real server
  are not tested.

## Tested

```text
Cassandra:  Apache Cassandra trunk 275a3a5, unpatched
JDK:        17
KMS:        the in-memory KMIP server (keytend-kmip-testing) behind mutual TLS, with leases (no real server)
KMIP:       1.4, 2.1 and 3.0
Scope:      standalone tests (build.sh) and the two-node in-JVM dtest KmipTlsTest
```

The standalone tests run real JSSE handshakes between a server context from the factory and
clients with their own certificates. They cover renewal, re-key, revocation, compromise, KMS
outage, the unknown-peer check and the refresh threads. The dtest adds driver clients and
internode TLS on two nodes.

The in-memory server leases Deactivated objects, as keytend-kmip-server does by default. The
tests show a renewed node's old certificate and a revoked client refused by their state.

To reproduce, run the commands in [Build and run](#build-and-run).
