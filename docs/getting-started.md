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

# Getting started

This page takes you from a source checkout to an application that seals records with a key held
in a KMIP server.

- [Build and install](#build-and-install)
- [Try it without a server](#try-it-without-a-server)
- [Connect to your KMS](#connect-to-your-kms)
- [Find or create a key](#find-or-create-a-key)
- [Key names are not access control](#key-names-are-not-access-control)
- [Seal and open a record](#seal-and-open-a-record)
- [Handle failures](#handle-failures)
- [Test without a server](#test-without-a-server)
- [Next steps](#next-steps)

## Build and install

You need JDK 17 or later. keytend-kmip is not on Maven Central. Build 0.10.0-rc.1 from a clone of
this repository, or take the JARs from the GitHub release
([From the GitHub release](#from-the-github-release)). From the repository root:

```sh
git checkout v0.10.0-rc.1
./mvnw install
```

This builds the SDK, runs its unit tests and installs `dev.keytend:keytend-kmip:0.10.0-rc.1` in
your local Maven repository, with the other modules (among them `keytend-kmip-testing`, the
in-memory server). The JAR is also at `sdk/target/keytend-kmip-0.10.0-rc.1.jar`. Add the dependency
to your project:

<!-- release-check: dependency -->
```xml
<dependency>
  <groupId>dev.keytend</groupId>
  <artifactId>keytend-kmip</artifactId>
  <version>0.10.0-rc.1</version>
</dependency>
```

At run time the SDK needs one library, the logging API slf4j-api. Maven brings it with the SDK.
Bind it to your logging ([Logging](production.md#logging)). The JAR is the named module
`dev.keytend.kmip`, which requires `org.slf4j`. A modular application adds
`requires dev.keytend.kmip;`.

### From the GitHub release

Without a build from source, take the SDK from the release's ZIP. Download
`keytend-kmip-0.10.0-rc.1.zip`, verify and unpack it
([Verifying release artifacts](../SECURITY.md#verifying-release-artifacts)), and install its JAR in
your local Maven repository:

<!-- release-check: install-sdk -->
```sh
mvn install:install-file -Dfile=keytend-kmip-0.10.0-rc.1/lib/keytend-kmip-0.10.0-rc.1.jar \
  -DgroupId=dev.keytend -DartifactId=keytend-kmip -Dversion=0.10.0-rc.1 -Dpackaging=jar \
  -DgeneratePom=true
```

`-DgeneratePom=true` installs a POM without a parent. Without it, Maven installs the POM from
inside the JAR. Its parent, `keytend-kmip-parent`, is installed only by a build from source, so
every build that uses the SDK then fails. The generated POM lists no dependencies, so add
slf4j-api beside the SDK dependency above:

<!-- release-check: dependency -->
```xml
<dependency>
  <groupId>org.slf4j</groupId>
  <artifactId>slf4j-api</artifactId>
  <version>2.0.20</version>
</dependency>
```

In Gradle, `implementation(files("libs/keytend-kmip-0.10.0-rc.1.jar"))` and
`implementation("org.slf4j:slf4j-api:2.0.20")` do the same without installing anything. The ZIP's
`lib/` also holds the SDK's sources, Javadoc and SBOM.

## Try it without a server

`InMemoryKmipServer` is an in-memory KMIP server for tests and for trying the SDK out. It is in its
own artifact, `keytend-kmip-testing`, not in the SDK. It is not for production: it does not protect
what it stores. For this throwaway program only, add it beside `keytend-kmip` without a scope. In
an application, put it in test scope (`<scope>test</scope>`, or Gradle's `testImplementation`),
never on the run-time class path:

```xml
<dependency>
  <groupId>dev.keytend</groupId>
  <artifactId>keytend-kmip-testing</artifactId>
  <version>0.10.0-rc.1</version>
</dependency>
```

In Gradle, with `mavenLocal()` among the repositories, because keytend-kmip is not on Maven
Central:

```kotlin
implementation("dev.keytend:keytend-kmip-testing:0.10.0-rc.1")
```

This program runs the quickstart with no KMS. Save it as `TryKeytend.java`:

```java
import dev.keytend.kmip.kms.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.nio.charset.StandardCharsets;

class TryKeytend {
  public static void main(String[] args) {
    byte[] orderJson = "{\"id\":1042,\"total\":\"19.99\"}".getBytes(StandardCharsets.UTF_8);
    try (Kms kms = InMemoryKmipServer.of(KmipVersion.V2_1).connect()) {
      kms.keys().createAes(256).named("orders-kek")
          .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
          .findOrCreate();
      CurrentKey kek = kms.keys().current("orders-kek");
      byte[] orderId = "order-1042".getBytes(StandardCharsets.UTF_8);
      byte[] sealed = kek.seal(orderJson, orderId);
      byte[] opened = kek.open(sealed, orderId);
      System.out.println(new String(opened, StandardCharsets.UTF_8));
    }
  }
}
```

Run it with the JARs you built: the SDK, slf4j-api (in `sdk/target/lib/`) and the in-memory
server:

```sh
cp='sdk/target/keytend-kmip-0.10.0-rc.1.jar:sdk/target/lib/*'
java -cp "$cp:testing/target/keytend-kmip-testing-0.10.0-rc.1.jar" TryKeytend.java
```

It prints `{"id":1042,"total":"19.99"}`, after SLF4J's note that no logging is bound. The
sections below explain each line and replace the in-memory server with a real KMS. For an
application's tests, see [Test without a server](#test-without-a-server).

## Connect to your KMS

A `Kms` is the connection to one key management server (KMS). Build its configuration from three
inputs:

- **Endpoints**: one or more `host:port` pairs. List several only when they are replicas of one
  KMS that share the same keys. The KMIP port is usually 5696.
- **Client identity**: the certificate and private key the server knows the application by.
- **Trust**: the CA certificates that the server's certificate must chain to. The SDK also checks
  the server's host name.

```java
import dev.keytend.kmip.kms.*;
import java.nio.file.Path;
import java.util.Arrays;

char[] password = System.getenv("KMS_CLIENT_PASSWORD").toCharArray();
KmsConfig config = KmsConfig.builder()
    .endpoints("kms1.example.com:5696", "kms2.example.com:5696")
    .clientIdentityKeyStore(Path.of("client.p12"), password)
    .trustPem(Path.of("ca.pem"))
    .build();
Arrays.fill(password, '\0');      // the builder keeps its own copy

try (Kms kms = Kms.connect(config)) {
  System.out.println("Connected with KMIP " + kms.version());
}
```

`client.p12` is a PKCS#12 file with exactly one private key and its certificate chain.
`KMS_CLIENT_PASSWORD` holds its password. The builder copies the password, so the example wipes
the array once `build()` returns. Each builder method that takes a file's password also takes a
`Supplier<char[]>`, asked at each read of the file, so that nothing keeps a copy.

Other identity and trust sources:

| Builder method | Use it for |
|---|---|
| `clientIdentityPem(chain, key)` | a PEM certificate chain and an unencrypted PEM key |
| `clientIdentityPem(chain, key, keyPassword)` | an encrypted PEM key |
| `clientIdentityKeyStore(file, password)` | a PKCS#12 or JKS key store with one private key, told from its contents |
| `clientIdentity(keyStore, password)` | a `KeyStore` you loaded |
| `trustStore(file, password)` | a JKS or PKCS#12 trust store file |
| `trustStore(keyStore)` | trusted CAs in a `KeyStore` |
| `trustSystemDefaults()` | the JDK's default trusted CAs |

`Kms.connect` negotiates the KMIP version before it returns. By default it accepts KMIP 1.4 to
2.1. For an older server, lower the floor with `minimumVersion(KmipVersion.V1_2)`. Features the
negotiated version lacks fail before anything is sent (see [KMIP versions](compatibility.md#kmip-versions)).

A `Kms` is thread-safe and owns a bounded pool of connections per endpoint. Create one per
application and close it on shutdown. [Running in production](production.md) covers failover,
deadlines, reloading and renewing credentials, and readiness checks.

## Find or create a key

Create the application's key the first time it starts, and find it every time after that:

```java
KeyHandle kek = kms.keys().createAes(256).named("orders-kek")
    .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
    .findOrCreate();
```

`findOrCreate` returns the Active key with that name. If there is none, it creates and activates
one. Call it once at startup and keep the result. `findOrCreateResult()` does the same and also
says how the key was obtained (`outcome()`), for a startup log. Calls that race through one
`Kms` get the same key. Instances that race in separate processes get the same key only on a
server that enforces unique names
([several instances](operating-keys.md#startup-on-several-instances)).

To always make a new key, end the builder with `create()` instead. `createPreActive()` makes a
key that is not usable until you activate it. Add `refusingExistingName()` before either to
refuse a name another object has already, rather than make a second object with it.

Key pairs are found or created by name the same way:

```java
KeyPairHandle signer = kms.keys().createKeyPair(KeyPairSpec.ec(Curve.P_256))
    .named("manifest-signer", "manifest-signer-public")
    .privateUsages(KeyUsage.SIGN).publicUsages(KeyUsage.VERIFY)
    .findOrCreate();
```

Their `findOrCreateResult()` returns a `FindOrCreatePairResult`: the `pair()`, the same
`outcome()` values and the pairs it `created()`.

## Key names are not access control

> [!WARNING]
> A key name is not an access-control boundary. On a server where others may create keys, anyone
> can create one with your name, and a lookup by name may find it.

Where other identities can create keys on the same server:

- keep the key's handle or identifier, and decrypt with it;
- use a server that enforces unique names;
- or select keys by an attribute only you can set, such as a custom attribute or object group
  under the server's access control.

The server's access control decides who may use a key. Give each application its own identity,
with only the operations it needs ([what each consumer's credential needs](production.md#what-each-consumers-credential-needs)).

## Seal and open a record

`kms.keys().current(name)` returns a `CurrentKey`. It follows the newest key with that name, so
code that seals through it keeps working after a rotation. Share one `CurrentKey` per name.

```java
CurrentKey kek = kms.keys().current("orders-kek");
byte[] orderId = "order-1042".getBytes(StandardCharsets.UTF_8);
byte[] sealed = kek.seal(orderJson, orderId);
byte[] opened = kek.open(sealed, orderId);
```

`orderJson` is the record to protect, as bytes.

- `seal` encrypts the record locally with AES-256-GCM under a fresh data key. The KMS key wraps
  that data key on the server, and the KMS key never leaves the KMS. The result is one byte array
  to store.
- `orderId` is the additional authenticated data. It binds the sealed record to its identity. A
  sealed record copied to another order fails to open.
- `open` takes the same `orderId`. It also opens records sealed under older keys of the key's
  [lineage](kms-design.md#lineage-and-rotation), the keys that replaced one another.
- Sealing needs KMIP 1.4 or later.

[Envelope encryption](envelope-encryption.md) covers streams, files and random-access chunks.
[Key lifecycle](operating-keys.md) covers rotation and retirement.

## Handle failures

Every failure that the server or the network causes is an unchecked `KmsException`. Misuse throws
the usual JDK exceptions instead: `NullPointerException` and `IllegalArgumentException` for bad
arguments, and `IllegalStateException` for a closed `Kms`.

Catch the cases your application handles and let the rest propagate:

```java
try {
  byte[] opened = kek.open(sealed, orderId);
} catch (CryptographicFailureException e) {
  // e.kind() says which failure it was. AUTHENTICATION_FAILED: the record was modified, or
  // orderId is not the value it was sealed with. INVALID_CIPHERTEXT: the stored record was
  // rejected before anything was sent. UNCONFIRMED: the server gave a generic error, which can be
  // a server fault, so it does not prove the record was modified.
} catch (KeyMismatchException e) {
  // The record names a key outside this key's lineage, so this application did not seal it.
} catch (StateConflictException e) {
  // The record's key is Compromised or Destroyed.
} catch (PermissionDeniedException e) {
  // Fix the client identity or the key's access policy on the server.
} catch (TransientException e) {
  // The KMS is unreachable. The SDK already retried on the other endpoints.
}
```

`kek`, `sealed` and `orderId` are from the previous section.

Code that branches on the kind of failure can use `KmsException.category()` instead. A failure has
the same category on every KMIP version:

| Category | Raised as | What to do |
|---|---|---|
| `RETRY` | `TransientException` | Repeat the call later. |
| `NOT_FOUND` | `NotFoundException` | The object does not exist. |
| `FIX_ACCESS` | `PermissionDeniedException` | Fix the credentials or the object's access policy. |
| `FIX_REQUEST` | `InvalidRequestException`, `UnsupportedException`, `KeyMismatchException` | Fix the request, the version or the key it names. |
| `STATE` | `StateConflictException`, `AlreadyExistsException` | The object's state, or an existing object, conflicts with the call. |
| `BAD_DATA` | `CryptographicFailureException`, and `KeyMismatchException` for a record that names a key outside the lineage | The data was modified, corrupted or misfiled. |
| `OUTCOME_UNKNOWN` | `OutcomeUnknownException` | Check the object's state before you repeat the call. |
| `PARTIAL` | `PartialCompletionException` | Resume as the exception says. |
| `SERVER` | `ServerFailureException`, `ProtocolViolationException`, and `CryptographicFailureException` of kind `UNCONFIRMED` | The server failed. Do not quarantine data for it. |

Two rules matter when you change keys:

- **Reads are retried on the next endpoint. Mutations are never re-sent.**
- **A mutation that fails in transit has an unknown outcome.** It raises
  `OutcomeUnknownException`. Check the object's state before you repeat the call
  ([deadlines and retries](production.md#deadlines-and-retries)).

A call of several steps that stops half-way raises `PartialCompletionException`. It names the
objects it created, and the keys it deactivated or destroyed.

## Test without a server

Connect the code under test to `InMemoryKmipServer`. It answers KMIP requests in memory, and the
`Kms` reaches it in process instead of over TLS. It can also inject failures. Add
`keytend-kmip-testing` in test scope. Your application never needs it at run time:

<!-- release-check: dependency -->
```xml
<dependency>
  <groupId>dev.keytend</groupId>
  <artifactId>keytend-kmip-testing</artifactId>
  <version>0.10.0-rc.1</version>
  <scope>test</scope>
</dependency>
```

In Gradle:

```kotlin
testImplementation("dev.keytend:keytend-kmip-testing:0.10.0-rc.1")
```

A modular test adds `requires dev.keytend.kmip.testing;`. These JUnit Jupiter tests seal and open
a record, and check that a denied key is reported:

<!-- release-check: test -->
```java
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.*;
import dev.keytend.kmip.testing.*;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

class OrderSealingTest {
  @Test
  void opensWhatItSeals() {
    try (Kms kms = InMemoryKmipServer.of(KmipVersion.V2_1).connect()) {
      kms.keys().createAes(256).named("orders-kek")
          .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
          .findOrCreate();
      CurrentKey kek = kms.keys().current("orders-kek");
      byte[] orderId = "order-1042".getBytes(StandardCharsets.UTF_8);
      byte[] orderJson = "{\"id\":1042}".getBytes(StandardCharsets.UTF_8);
      assertArrayEquals(orderJson, kek.open(kek.seal(orderJson, orderId), orderId));
    }
  }

  @Test
  void reportsADeniedKey() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = server.connect()) {
      KeyHandle kek = kms.keys().createAes(256).named("orders-kek")
          .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
          .findOrCreate();
      server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
      assertThrows(PermissionDeniedException.class, kek::attributes);
    }
  }
}
```

- `failNext` makes the next matching request fail as a real server or network would. `Fault`
  lists the failures: server refusals such as `NOT_FOUND` and `PERMISSION_DENIED`, and network
  faults such as `UNREACHABLE`, `REPLY_LOST`, `HANG` and `SLOW`.
- `server.state(id)`, `server.names(id)` and `server.violations()` inspect what the server holds
  and any malformed requests.
- `server.tlsListener()` builds a TLS listener for the server, to test your TLS settings
  ([Over TLS](in-memory-server.md#over-tls)).
- [In-memory test server](in-memory-server.md) lists how the server answers KMIP requests and what
  it does not support.
- `keytend-kmip-testing` is test support. It is outside the compatibility promises
  ([the testing package](compatibility.md#the-testing-package)). Never give it real keys.

### The in-memory server from the GitHub release

Without a build from source, install the SDK from the release
([From the GitHub release](#from-the-github-release)), then take the in-memory server from there
too. `keytend-kmip-testing-0.10.0-rc.1.jar` is a separate asset beside the ZIP, not inside it.
Download it with its `.asc` and `.sha256` and verify it
([Verifying release artifacts](../SECURITY.md#verifying-release-artifacts)):

```sh
gpg --verify keytend-kmip-testing-0.10.0-rc.1.jar.asc keytend-kmip-testing-0.10.0-rc.1.jar
sha256sum -c keytend-kmip-testing-0.10.0-rc.1.jar.sha256
```

Then install it in your local Maven repository, again with a POM without a parent, and add the
test-scope dependency from [Test without a server](#test-without-a-server):

<!-- release-check: install-testing -->
```sh
mvn install:install-file -Dfile=keytend-kmip-testing-0.10.0-rc.1.jar \
  -DgroupId=dev.keytend -DartifactId=keytend-kmip-testing -Dversion=0.10.0-rc.1 -Dpackaging=jar \
  -DgeneratePom=true
```

In Gradle, `testImplementation(files("libs/keytend-kmip-testing-0.10.0-rc.1.jar"))` adds the file
itself. Its sources (`keytend-kmip-testing-0.10.0-rc.1-sources.jar`) and SBOM are assets beside it.

## Next steps

- [Choosing an API](choosing-an-api.md): the entry point for each job.
- [Envelope encryption](envelope-encryption.md): records, streams and files.
- [Local keys](local-keys.md): raw keys for local file encryption.
- [Key lifecycle](operating-keys.md): rotation, retirement and compromise.
- [TLS identities](tls-identities.md): node certificates and trust from the KMS.
- [Running in production](production.md): failover, deadlines and credentials.
