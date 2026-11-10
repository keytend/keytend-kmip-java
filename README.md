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

# <img src="assets/icon.svg" width="32" height="32" alt=""> keytend-kmip

A Java client for KMIP key management servers (KMS), for JDK 17 and later.

> [!WARNING]
> **Experimental: not for production use.** keytend-kmip started as an experiment in
> implementing the KMIP specification, and every release stays experimental. Use it to learn
> KMIP and to test with. Do not use it to protect real keys or data.

With it, a Java application that keeps its keys in a KMIP server can:

- create and find keys, and envelope-encrypt records and files with them;
- load raw keys for local encryption, such as a database's encrypted files;
- rotate, retire and replace keys without downtime;
- take its TLS identity and trust from the KMS.

It has two parts:

- **Application API** (`dev.keytend.kmip.kms`): JCA keys, typed records and one exception
  hierarchy. The same code runs on every negotiated KMIP version.
- **Protocol layer** (`client`, `model`, `codec`, `transport`, `server`): every KMIP operation
  from 1.1 to the 3.0 draft, in TTLV, XML or JSON, over mutual TLS or HTTPS.

A separate test artifact, `keytend-kmip-testing`, is an in-memory KMIP server for testing
application code without a real KMS.

> [!NOTE]
> **Status:** 0.10.0-rc.1, a pre-release of the first release, 0.10.0, is a signed GitHub
> pre-release. Build it from source or install it from the release's ZIP. keytend-kmip is not on
> Maven Central. The [compatibility](docs/compatibility.md) promises start with 0.10.0.

## Requirements

- JDK 17 or later. The SDK is tested on JDK 17, 21 and 25.
- A KMIP server. By default the SDK negotiates KMIP 1.4 to 2.1. It can also use 1.1 to 1.3 and
  the [3.0 draft](docs/compatibility.md#kmip-versions) when you configure them.
- [SLF4J](https://www.slf4j.org/) 2.0 (`slf4j-api`), which Maven and Gradle bring with the SDK.
  Bind it to your logging ([Logging](docs/production.md#logging)). With a 1.7-era binding, such
  as Logback 1.2, see [Which slf4j-api version](docs/production.md#which-slf4j-api-version).
- No other runtime library ([Dependencies](docs/dependencies.md)).

## Install

<!-- The release version: step 1 of docs/releasing.md edits the versions in this file. -->
From a clone of this repository, check out the release's tag, then build the SDK and install it in
your local Maven repository:

```sh
git checkout v0.10.0-rc.1
./mvnw install
```

Then add the dependency:

```xml
<dependency>
  <groupId>dev.keytend</groupId>
  <artifactId>keytend-kmip</artifactId>
  <version>0.10.0-rc.1</version>
</dependency>
```

Optional modules: `keytend-kmip-micrometer` for [Micrometer metrics](docs/production.md#metrics),
`keytend-kmip-opentelemetry` for [OpenTelemetry](docs/production.md#opentelemetry), and
`keytend-kmip-testing`, the in-memory server, in test scope ([below](#quickstart)).

0.10.0-rc.1's files are also on the
[releases page](https://github.com/keytend/keytend-kmip-java/releases).
Getting started says how to verify and install [the SDK](docs/getting-started.md#from-the-github-release)
and [the in-memory server](docs/getting-started.md#the-in-memory-server-from-the-github-release)
from there.

## Quickstart

These lines connect to a KMS, find or create a key, and seal and open one record:

```java
import dev.keytend.kmip.kms.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

char[] password = System.getenv("KMS_CLIENT_PASSWORD").toCharArray();
KmsConfig config = KmsConfig.builder()
    .endpoints("kms1.example.com:5696", "kms2.example.com:5696")
    .clientIdentityKeyStore(Path.of("client.p12"), password)
    .trustPem(Path.of("ca.pem"))
    .build();
byte[] orderJson = "{\"id\":1042,\"total\":\"19.99\"}".getBytes(StandardCharsets.UTF_8);

try (Kms kms = Kms.connect(config)) {
  kms.keys().createAes(256).named("orders-kek")
      .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
      .findOrCreate();
  CurrentKey kek = kms.keys().current("orders-kek");
  byte[] orderId = "order-1042".getBytes(StandardCharsets.UTF_8);
  byte[] sealed = kek.seal(orderJson, orderId);
  byte[] opened = kek.open(sealed, orderId);
}
```

> [!WARNING]
> A key name is not an access-control boundary. On a server where others may create keys, anyone
> can create one with your name. Where that matters, keep and use the key's handle, use a server
> that enforces unique names, or select keys by an attribute only you can set.
> See [key names](docs/getting-started.md#key-names-are-not-access-control).

- `client.p12` holds the client's certificate and private key. `KMS_CLIENT_PASSWORD` is its
  password.
- `ca.pem` holds the CA certificates that the server's certificate must chain to.
- The two endpoints are replicas of one KMS. Reads fail over between them.
- `findOrCreate` returns the Active key named `orders-kek`, or creates it. Call it once at startup.
- `current` follows the newest key with that name, also after the key is rotated.
- `seal` encrypts the record locally with AES-256-GCM under a fresh data key. The named key wraps
  the data key on the server and never leaves it. `orderId` is bound to the sealed record, so pass
  the same value to `open`.

The same lines run in the tested sample
[Quickstart.java](sdk/src/test/java/dev/keytend/kmip/kms/samples/Quickstart.java).

To try it without a server, replace `Kms.connect(config)` with
`InMemoryKmipServer.of(KmipVersion.V2_1).connect()`, imported from `dev.keytend.kmip.testing`.
That server is not in the SDK, so add the `keytend-kmip-testing` artifact as well. It is for tests
and for trying the SDK out, not for production. In your tests, give it the test scope:

```xml
<dependency>
  <groupId>dev.keytend</groupId>
  <artifactId>keytend-kmip-testing</artifactId>
  <version>0.10.0-rc.1</version>
  <scope>test</scope>
</dependency>
```

```kotlin
// Gradle
testImplementation("dev.keytend:keytend-kmip-testing:0.10.0-rc.1")
```

[Getting started](docs/getting-started.md#try-it-without-a-server) has a complete program to run.

## Next steps

| I want to… | Read |
|---|---|
| Connect, handle failures and write tests | [Getting started](docs/getting-started.md) |
| Pick the entry point for a job | [Choosing an API](docs/choosing-an-api.md) |
| Encrypt records, streams and files | [Envelope encryption](docs/envelope-encryption.md) |
| Encrypt files locally with raw keys from the KMS | [Local keys](docs/local-keys.md) |
| Rotate keys, retire old ones, recover from a compromise | [Key lifecycle](docs/operating-keys.md) |
| Take TLS identities and trust from the KMS | [TLS identities](docs/tls-identities.md) |
| Configure failover, deadlines and credentials | [Running in production](docs/production.md) |
| Call KMIP operations directly | [Protocol layer](docs/protocol-layer.md) |
| Manage keys from the command line | [keytend-kmip-cli](cli/README.md) |

Every guide and reference page is listed in the [documentation index](docs/index.md).

## Examples

These example classes are in
[`sdk/src/test/java/dev/keytend/kmip/kms/samples`](sdk/src/test/java/dev/keytend/kmip/kms/samples).
`SamplesTest` runs each one against the in-memory server on several KMIP versions:

- `EnvelopeEncryption`: seal and open records through `CurrentKey`.
- `TdeKeyRetrieval`: load a database key at startup, with identity, size and state checks.
- `TdeKeyProvider`: a commit-log key provider for a database, built on `LocalKeys`.
- `RemoteAead`: AES-GCM on the server, with a stored `Ciphertext`.
- `RemoteSignVerify`: RSA and EC signatures made and checked on the server.
- `LifecycleRotation`: create, rotate, re-encrypt, retire and destroy a key.
- `CertificateStorage`: register an X.509 certificate and read it back.
- `BringYourOwnKey`: import JCA secret, private and public keys.

Run them with `./mvnw -pl sdk test -Dtest=SamplesTest`.

## Command-line tool

[`keytend-kmip-cli`](cli/README.md) manages keys on a KMIP server from a shell: list,
show, create, rotate, expire, revoke and destroy keys, and store secrets. Commands that expire,
revoke or destroy keys act on key identifiers and ask for confirmation.

```sh
keytend-kmip-cli --group prod list --state active
keytend-kmip-cli --group prod expire 7f3a1c --at 2026-12-01T00:00:00Z
```

## Integrations

- [Cassandra commit log and hints encryption](integration/cassandra-trunk-tde/README.md)
  (trial), for Apache Cassandra trunk on `LocalKeys`.
- [Cassandra TLS with node identities from the KMS](integration/cassandra-trunk-tls/README.md)
  (sample), on `kms.tls()`.

## Project

- [Compatibility and support](docs/compatibility.md): what each release promises.
- [Validation](docs/validation.md): tested against PyKMIP, PQCToday, Krypton and
  keytend-kmip-server, and the OASIS test cases.
- [Security policy](SECURITY.md): report vulnerabilities privately, not in a public issue.
- [Release notes](RELEASE.md).
- License: Apache-2.0. See [licensing](docs/licensing.md) and [NOTICE](NOTICE).
