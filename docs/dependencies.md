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

# Dependencies

keytend-kmip takes a maintained library when the library does the job well, rather
than writing and tuning its own. This page lists every library the build uses,
why it was chosen, where it is used, and under which license.

## The policy

- The project keeps in-house code only where it is KMIP-specific, small and
  plainly correct, or where a library would cost more than it saves. The
  [kept in-house](#kept-in-house) section lists the main cases.
- The SDK's API has no third-party types. The SDK logs through SLF4J, an
  ordinary dependency that applications bind to their own backend. The opt-in
  Micrometer and OpenTelemetry modules expose those libraries' types, so
  applications can use their own metrics backends.
- Any other SDK runtime library is bundled and relocated ("shaded") into the
  SDK JAR, so applications never inherit it and cannot clash with their own
  copy. The only one is Caffeine, under
  `dev.keytend.kmip.internal.shaded.caffeine`, which the module neither exports
  nor opens.
- The CLI and the integration application (the "lab") are applications, and use
  ordinary dependencies.
- Every version is pinned once, in the root `pom.xml`, and kept current
  ([Keeping versions current](#keeping-versions-current)).

## SDK runtime dependencies

The enforcer rule `runtime-dependency-allowlist` in `sdk/pom.xml` fails the
build on any SDK dependency outside test scope, also a transitive one, that is
not in this table. To add one, review it against the policy, then list it here
and in the rule.

| Library | Version | Why | Shipped as | License |
|---|---|---|---|---|
| `com.github.ben-manes.caffeine:caffeine` | 3.3.1 | The [`LocalKeys`](local-keys.md) cache's storage, eviction and expiry | Bundled, relocated ([below](#the-bundled-caffeine)) | Apache-2.0 |
| `org.slf4j:slf4j-api` | 2.0.20 | Logging API ([Logging](production.md#logging)); runs with 1.7.36 too | Ordinary Maven dependency; its JPMS requirement is not transitive | MIT |

### The bundled Caffeine

Caffeine is relocated to `dev.keytend.kmip.internal.shaded.caffeine`, which the
module neither exports nor opens. The published POM does not list it. No
Caffeine type is in the API, so your own Caffeine, of any version, does not
meet it. Its two annotation libraries are not bundled.

- Caffeine holds the cached keys and orders their eviction. The SDK still
  decides when a key may be used: TTL, leases, protection deadlines and
  compromise.
- An entry in use is never evicted. An evicted key is wiped before its slot is
  reused.
- Caffeine runs on the calling thread, so the SDK starts no thread for it.

[Design notes](kms-design.md#the-localkeys-cache) say how the cache uses it.

### slf4j-api

The SDK calls only what SLF4J 1.7 also has, and a test runs it with 1.7.36.
With a 1.7-era binding, pin 1.7.36
([Which slf4j-api version](production.md#which-slf4j-api-version)). It is not
shaded, because your application binds it. It is not transitive in the module
descriptor, because no SLF4J type is in the API.

## The Micrometer module

`keytend-kmip-micrometer` ([Metrics](production.md#metrics)) is opt-in. The SDK
does not depend on it, and has no metrics library of its own. The module's
libraries are normal dependencies, never shaded, because the application's
registry is Micrometer's.

| Library | Version | Why | License |
|---|---|---|---|
| `io.micrometer:micrometer-core` | 1.17.2 | The application's `MeterRegistry`: the JVM's common metrics API, with exporters for Prometheus, OTLP and others. | Apache-2.0 |
| `io.micrometer:micrometer-commons`, `micrometer-observation` | 1.17.2 | Required by micrometer-core. | Apache-2.0 |
| `org.jspecify:jspecify` | 1.0.1 | Required by micrometer-core (nullness annotations). | Apache-2.0 |
| `org.hdrhistogram:HdrHistogram` | 2.2.2 | Required by micrometer-core at run time (histograms). | CC0 or BSD-2-Clause; taken as BSD-2-Clause (`micrometer/licenses.properties`) |

## The OpenTelemetry module

`keytend-kmip-opentelemetry` ([OpenTelemetry](production.md#opentelemetry)) is
opt-in too, and the SDK does not depend on it. It takes the OpenTelemetry API
only, never its SDK. The application brings its own implementation: an SDK, the
Java agent's, or none. The enforcer rule `runtime-dependency-allowlist` in
`opentelemetry/pom.xml` fails the build on any other runtime dependency.

| Library | Version | Why | License |
|---|---|---|---|
| `io.opentelemetry:opentelemetry-api` | 1.68.0 | The application's `OpenTelemetry`: its meters and tracers, which export through OTLP, Prometheus and others. An automatic module, `io.opentelemetry.api`. | Apache-2.0 |
| `io.opentelemetry:opentelemetry-context`, `opentelemetry-common` | 1.68.0 | Required by the API (the current span's context). | Apache-2.0 |

## The test module

`keytend-kmip-testing`, the in-memory KMIP server, is a test dependency:
applications add it in test scope ([Test without a
server](getting-started.md#test-without-a-server)). It depends on the SDK
alone and adds no library. No main code of the SDK, the metrics modules, the
CLI, the lab or the integrations depends on it. Their tests do. It is
published on its own. The binary ZIP's `lib/` does not carry it, and the GitHub
release has it as a separate asset beside the ZIPs.

## The CLI and the lab

`keytend-kmip-cli` and the integration application (`keytend-kmip-integration`)
are applications, so their libraries are ordinary dependencies. The binary ZIP's
`lib/` carries them beside the module JARs.

| Library | Version | Used by | Why | License |
|---|---|---|---|---|
| `info.picocli:picocli` | 4.7.7 | CLI | Command-line parsing, help and usage errors. | Apache-2.0 |
| `tools.jackson.core:jackson-core` | 3.2.4 | CLI, lab | JSON output (`--json`, the lab's reports), with the CLI's escaping of control and bidi characters. The CLI's tests read it back with the same parser. | Apache-2.0 |
| `org.slf4j:slf4j-simple` | 2.0.20 | CLI, lab | Prints the SDK's warnings and errors on standard error. | MIT |

## Test and build dependencies

These build and test the project and never ship. Their licenses may also be
EPL or MPL.

| Library | Version | Why | License |
|---|---|---|---|
| `org.junit.jupiter:junit-jupiter` | 6.1.3 | The test framework. | EPL-2.0 |
| `org.bouncycastle:bcpkix-jdk18on` (with `bcprov`, `bcutil`) | 1.86 | Builds the tests' certificates, in place of forking `keytool`, and checks the SDK's PEM, PKCS#8, PKCS#1 and SEC1 parsing against an independent implementation. | MIT (the Bouncy Castle Licence) |
| `org.awaitility:awaitility` (with `hamcrest`) | 4.3.0 | Bounded waits for conditions in the transport and TLS tests. | Apache-2.0; BSD-3-Clause |
| `net.jqwik:jqwik` | 1.10.2 | Property tests of the TTLV, JSON and XML codecs. | EPL-2.0 |
| `org.testcontainers:testcontainers` | 2.0.5 | Runs the lab's KMIP servers in containers. | MIT |
| `com.h2database:h2` | 2.5.252 | The lab's encrypted test database. | MPL-2.0 or EPL-1.0 |
| `io.opentelemetry:opentelemetry-sdk`, `opentelemetry-sdk-testing` | 1.68.0 | The OpenTelemetry module's tests read its instruments and spans with the SDK's in-memory reader and exporter. | Apache-2.0 |
| `org.slf4j:slf4j-api`, `slf4j-simple` | 1.7.36 | The oldest SLF4J the SDK supports: the lab's `Slf4j17ConsumerIT` compiles the SDK against it and runs it with it, on the class path and the module path. Copied by the build, outside every class path. | MIT |

Build plugins are pinned in the root `pom.xml` too: the enforcer with
extra-enforcer-rules, the license plugin, SpotBugs with find-sec-bugs, Error
Prone, Spotless, CycloneDX and japicmp among them.

## Keeping versions current

- Dependabot (`.github/dependabot.yml`) proposes newer Maven dependencies
  and plugins each week, grouped by area, and security fixes at once.
- The versions reports list what is behind, pre-releases ignored
  (`tools/versions-rules.xml`):

  ```sh
  ./mvnw -B -ntp versions:display-dependency-updates versions:display-plugin-updates \
      versions:display-property-updates
  ```

  `tools/release-check.sh` records them with every release check.
- The SBOMs are scanned for known vulnerabilities before each release: one
  per shipped module, the CLI's and the lab's listing the libraries the binary
  ZIP carries for them
  ([releasing](releasing.md#scanning-the-sbom-for-known-vulnerabilities)).
  A vulnerability in a bundled library needs an SDK release, because users
  cannot upgrade the bundled copy.

## Build rules

Every module's `verify` checks:

- One version of each dependency in each module's tree
  (`dependencyConvergence`), none declared twice.
- No dependency compiled for a newer JDK than 17 (`enforceBytecodeVersion`,
  from extra-enforcer-rules).
- No class in two artifacts (`banDuplicateClasses`).
- The in-memory server in test scope only. A module that takes
  `keytend-kmip-testing` in any other scope, also transitively, fails
  (`bannedDependencies`).
- Licenses. What ships (compile and runtime scope) must be under
  Apache-2.0, MIT, BSD-2-Clause or BSD-3-Clause. What only builds and tests may
  also be under EPL-1.0, EPL-2.0 or MPL-2.0. A dependency with another license,
  or none, fails the build.

## Kept in-house

These were weighed against libraries and stay as SDK code:

- The OASIS JSON and XML codecs. The XML codec uses the JDK's StAX, always the
  JDK's own implementation (`newDefaultFactory()`), so a StAX library on an
  application's class path does not change how the SDK parses.
- ASN.1/DER and the key formats (PEM, PKCS#8, PKCS#1, SEC1). The parsers are
  narrow and strict and wipe what they copy. Tests compare them with Bouncy
  Castle.
- The envelope and streaming formats ([stored formats](stored-formats.md)),
  built on the JDK's AES-GCM and HMAC.
- Retry, failover and the connection pool. They follow KMIP's rules on what
  may be sent again.
- The HTTPS transport (the JDK's `HttpClient`), executors, crypto primitives
  (the JDK's JCA) and hex, Base64 and time parsing (the JDK's).
