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

# Compatibility and support

What keytend-kmip promises from its first release, 0.10.0, on, and what it does not.
Vulnerability reporting is in [SECURITY.md](../SECURITY.md).

**The promises start at keytend-kmip 0.10.0.** They cover the API and stored
formats only. Every release is experimental and not meant for production use.
A pre-release, such as 0.10.0-rc.1, makes no promise of its own: its release
may still change what it has.

- [Versions](#versions)
- [Java](#java)
- [KMIP versions](#kmip-versions)
- [API compatibility](#api-compatibility)
- [Exceptions](#exceptions)
- [Deprecation and removal](#deprecation-and-removal)
- [`@since` in the Javadoc](#since-in-the-javadoc)
- [Stored formats](#stored-formats)
- [The testing package](#the-testing-package)
- [Support](#support)

## Versions

A release's version has three parts, major, minor and patch, as in
[semantic versioning](https://semver.org/):

- **Patch** (0.10.1): fixes only, no incompatible API change.
- **Minor** (0.11.0): additions, and fixes that change behavior. From 1.0 they
  are compatible as described below. While the major version is 0, a minor
  release may also change the API incompatibly
  ([below](#while-the-major-version-is-0)).
- **Major** (from 1.0): anything else.

A pre-release adds `-rc.N` to the version of the release it comes before
(`0.10.0-rc.1`).

### While the major version is 0

Until 1.0, the API settles from one minor release to the next:

- A patch release (0.10.0 to 0.10.1) keeps every promise on this page. It never
  changes the API incompatibly.
- A minor release (0.10 to 0.11) may change the API incompatibly, in any tier,
  without an earlier deprecation. Its release notes say so: its section of
  RELEASE.md lists each change under "Incompatible changes".
- The promises below that hold "within a major version" hold within a minor
  version (0.10.x) until 1.0.
- The [stored formats](#stored-formats) are not part of this: data written by
  0.10.0 or any later release stays readable by every later release, 0.x minor
  releases included.

From 1.0, semantic versioning applies as written below: minor and patch
releases keep the API compatible, and only a major release breaks it.

## Java

- Java 17 is the floor. The bytecode targets 17 and the API uses nothing
  newer. Raising the floor needs a major release.
- The SDK is tested on 17, 21 and 25, the LTS releases. Other JDKs are expected
  to work, as a best effort.
- The JAR is the named module `dev.keytend.kmip`, and the name stays within a
  major version. It exports `kms`, `client`, `model`, `codec`, `transport` and
  `server`, and each stays exported within a major version. A minor release that
  adds an exported package
  says so in its release notes. On the class path the JAR works as a plain
  library. The in-memory test server is a separate module
  ([the testing package](#the-testing-package)).
- The SDK has one runtime dependency, SLF4J. The module requires
  `java.net.http`, `java.xml` and `org.slf4j`. A `jlink` image needs the first
  two. `org.slf4j` is not transitive, because no SLF4J type is in the API. The
  SDK calls only the SLF4J methods that 1.7 also has.
- Caffeine is bundled and relocated, and is not part of the API. Its version may
  change in any release ([Dependencies](dependencies.md#the-bundled-caffeine)).
- Metrics and traces are in separate modules. `keytend-kmip-micrometer` (the
  named module `dev.keytend.kmip.micrometer`) requires the SDK and
  Micrometer's `micrometer.core`. `keytend-kmip-opentelemetry` (the named
  module `dev.keytend.kmip.opentelemetry`) requires the SDK and the
  OpenTelemetry API (`io.opentelemetry.api`, `io.opentelemetry.context`), never
  its SDK. The SDK depends on neither.

## KMIP versions

| Version | Tier | Offline | Live, protocol layer | Live, application API |
|---|---|---|---|---|
| 1.1 | supported | protocol-layer tests | PyKMIP, keytend-kmip-server | keytend-kmip-server |
| 1.2 | supported | the in-memory server | PyKMIP, keytend-kmip-server | PyKMIP, keytend-kmip-server |
| 1.3 | supported | the in-memory server, OASIS fixtures | PyKMIP, keytend-kmip-server | none |
| 1.4 | supported, default range | the in-memory server, OASIS fixtures | PyKMIP, Krypton, keytend-kmip-server | PyKMIP, keytend-kmip-server |
| 2.0 | supported, default range | the in-memory server, OASIS fixtures | keytend-kmip-server (PyKMIP in the catalog) | none |
| 2.1 | supported, default range | the in-memory server, OASIS fixtures | keytend-kmip-server | keytend-kmip-server |
| 3.0 CSD02 | **experimental**, opt-in | the in-memory server, OASIS 3.0 fixtures | PQCToday, keytend-kmip-server | PQCToday, keytend-kmip-server |

The live columns name the servers each layer's tests ran against. The results
and how to run them are in [Validation](validation.md).

"Tested" means the SDK's own tests pass at that version against the servers
named. It does not certify any server. Qualify your own server and version
before you rely on it, as [Qualifying a server](production.md#qualifying-a-server)
describes.

**KMIP 3.0 is a draft, and experimental.** `KmipVersion.V3_0` and
`ProtocolVersion.V3_0` name the wire version a server negotiates as 3.0. The SDK
implements the OASIS Committee Specification Draft 02 (CSD02) of KMIP 3.0. A
final 3.0 standard is expected to use the same wire version number. A server's
answer cannot tell the two apart, and a constant renamed for the draft could
not either, so the name `V3_0` stays.

- 3.0 is opt-in. `connect` negotiates 1.4 to 2.1 unless the configuration names
  3.0, with `maximumVersion(KmipVersion.V3_0)` or a `minimumVersion` of 3.0. The
  protocol layer negotiates 3.0 only when the caller's `VersionPolicy` includes
  it. `VersionPolicy.ANY` does, and says so.
- When OASIS publishes KMIP 3.0, `V3_0` follows the standard in a minor
  release, with no CSD02 dialect kept, and that release's notes list the 3.0
  changes. Until then a minor release may also change what the SDK sends or
  accepts at 3.0 to follow a later draft. Its release notes say so.
- Behavior at 3.0 is outside the API guarantees below. Keep 3.0 off where a
  change of behavior matters.

## API compatibility

The public API has four tiers:

| Tier | Packages | Promise within a major version |
|---|---|---|
| **Application** | `dev.keytend.kmip.kms` | every public and protected type and member is kept (below) |
| **Protocol** | `client`, `model`, `codec`, `transport`, `server` | changes only after a minor release of deprecation, with fixed points |
| **Observability** | `micrometer` and `opentelemetry`, in their own modules | as the application tier |
| **Test support** | `testing`, in the separate `keytend-kmip-testing` | any minor release may change it ([below](#the-testing-package)) |

The application tier is what this SDK is for, and what its guides use. The
protocol tier is the KMIP layer under it, for what `kms` does not cover:
`kms.protocol()`, custom transports and callback servers. It is large and
partly generated from the KMIP specification, so it is not frozen as a whole.

### The application tier

A minor release keeps every application-tier element, binary and source
compatible. These additions are the exceptions:

- Enums gain constants, because KMIP adds values. `Algorithm`, `KeyState`,
  `KmsReason`, the generated `Tag` and the enums nested in `Enums` are among
  them. A `switch` over one needs a `default`.
- Classes gain methods and overloads. A call passing a bare `null` where a new
  overload makes it ambiguous needs a cast.
- Interfaces that applications implement (`KmsListener`, `KmipTransport`,
  `CallbackHandler` and the like) gain only `default` methods. Interfaces the
  SDK implements, such as its results and views, may gain abstract ones. Do not
  implement them.
- New `KmsException` subtypes, under the rules in [Exceptions](#exceptions).

Behavior documented in Javadoc and the guides is part of the contract. A
fix that makes the SDK do what its documentation or KMIP says may change
behavior in a minor or patch release. The release notes list it under
"Upgrading".

### Names other tools depend on

Dashboards, alerts and scripts read these, so minor and patch releases keep them:

- the meter, instrument, span, attribute and tag names of the observability
  modules ([Metrics](production.md#metrics),
  [OpenTelemetry](production.md#opentelemetry));
- the logger names ([Logging](production.md#logging));
- the CLI's commands, options, exit codes and `--json` fields
  ([keytend-kmip-cli](../cli/README.md)).

A minor release may add names, tags, log lines, commands, options and fields.
The wording of log lines and messages is not covered.

### The protocol tier

- A patch release never changes a protocol-tier element incompatibly.
- A minor release may change or remove one only after an earlier minor release
  of the same major version deprecated it. The deprecation is
  `@Deprecated(since = "X.Y.Z")`, naming the release that made it, with the
  replacement in its Javadoc. The release notes list the change under
  "Upgrading".
- Additions (new types, members, constants and overloads) need no notice.

These **fixed points** are kept as the application tier is:

- Every protocol-tier type that an application-tier signature names. It is never
  removed, renamed or moved, and its members follow the rules above. The types
  are `client.CryptoParameters`, `client.KmipClient`, `client.Result`,
  `client.VersionPolicy`, `model.ProtocolVersion`, `model.Ttlv`,
  `transport.KmipTransport`, and these enums of `model.Enums`:
  `CryptographicAlgorithm`, `CryptographicUsageMask`, `HashingAlgorithm`,
  `LinkType`, `ObjectType`, `RecommendedCurve`, `ResultReason`,
  `RevocationReasonCode`, `SecretDataType` and `State`.
- The interfaces applications implement, in full: `KmipTransport`,
  `CallbackHandler` and `ContextualCallbackHandler`, and the `CallContext` and
  `CallbackContext` they are given. They gain only `default` methods.
- The generated tables (`Tag`, `Enums`, `Operation`, `Requests`). They only gain
  constants and methods, as KMIP adds them.

### Not covered

- package-private code;
- the wording of messages, `toString()` and log output;
- behavior specific to the 3.0 draft;
- the `keytend-kmip-testing` module ([below](#the-testing-package)).

### How it is checked

Each release is compared by [japicmp](https://siom79.github.io/japicmp/) with
the latest release, which the `api.baseline.version` property of `sdk/pom.xml`
names. A binary or source incompatible change fails the release build when the
baseline is of the same 0.x minor version (or, from 1.0, the same major
version) as the release. Against an earlier one, such as 0.10.x for 0.11.0, the
check reports the changes, and the release checks require RELEASE.md's section
of the release to list them under "Incompatible changes". A patch release is
compared with a release of its own minor version: against an earlier one, the
release checks fail and ask for X.Y.0 as the baseline. The first release,
0.10.0, has no earlier release to compare with: until it is published, no
baseline is pinned and the check is skipped. japicmp compares the SDK only,
not the testing, observability or CLI modules. The procedure is in
[Releasing](releasing.md#api-compatibility-checks).

## Exceptions

`KmsException` is sealed, and its `Category` is the stable way to decide what
to do. Within a major version:

- The set of categories does not change. A new `Category` constant needs a
  major release, so a `switch` over `Category` may be exhaustive.
- The direct subtypes of `KmsException` do not change. A new subtype in a
  minor release extends an existing one. It reports a category that its parent
  already reports, so existing `catch` clauses still catch it.
- A failure keeps its subtype and category, except to correct a
  misclassification, which the release notes list. It may become a more
  specific subtype of the same one.
- Misuse is not a `KmsException`, and will not become one. It is reported as
  `NullPointerException`, `IllegalArgumentException` or
  `IllegalStateException`.

## Deprecation and removal

- An element to be replaced is marked `@Deprecated(since = "X.Y.Z")`, and its
  Javadoc names the replacement.
- An application-tier (`kms`) element keeps working for the rest of that major
  version. It is removed only in a major release, after at least one minor
  release in which it was deprecated.
- A protocol-tier element follows that tier's rules above. It may be removed in
  a minor release after an earlier minor deprecated it.
- keytend-kmip 0.10.0, the first release, starts with no deprecated element.

## `@since` in the Javadoc

The Javadoc says since when each element is in the API. keytend-kmip's history
starts at 0.10.0, its first release.

- `@since 0.10.0` on a top-level type means it was in the API in 0.10.0. Its
  members, nested types included, inherit it. Some repeat it.
- An element new in a later release carries the release it came in. A new
  type says so in its own Javadoc, and its members inherit it. A new member or
  nested type of an older type says so in its own.
- The generated protocol tables (`Tag`, `Enums`, `Operation` and `Requests`)
  say `@since 0.10.0` too.
- A pre-release's elements name the release it comes before: `0.10.0-rc.1`
  says `@since 0.10.0`.
- The build checks that every new element says `@since` with its release, and
  that every deprecated element says why.

## Stored formats

The SDK's storage formats have a guarantee of their own. Data that 0.10.0 or any
later release writes in them stays readable by every later release, majors
included. A pre-release writes the formats of the release it comes before.

| Format | Written by | Since |
|---|---|---|
| KTC 1 | `Ciphertext.toBytes()`, read by `Ciphertext.fromBytes` | 0.10.0 |
| KTE 1 | `seal`, read by `open` | 0.10.0 |
| KTS 1 | `sealing` and `sealTo`, read by `opening` and `openTo` | 0.10.0 |
| KTR 1 | `chunkedSealer` and `rewrapHeader`, read by `chunkedOpener` | 0.10.0 |
| Client certificate renewal 1 | `renewClientCertificate()` and automatic renewal: the pending file (`<key file>.renewal`) and the files it moves aside (`.unresolved`, `.orphaned`), read by later renewals and by the builder's `clientIdentityPem` and `clientIdentityKeyStore` | 0.10.0 |

The layouts are in [Stored formats](stored-formats.md), and the renewal files in
[What is on disk](production.md#what-is-on-disk). A renewal file may hold the only copy of the
private key of a certificate the server issued, for as long as that certificate is valid. So
every later release reads it, as it reads the formats above, finds the files moved aside by
their names, and finishes or follows up the renewal they record.

- A new format version is only added beside the old one. Readers keep reading
  every earlier version.
- A writer moves to a new version only in a minor release that says so.
- Reading an old version would be dropped only if it became unsafe. A release
  would first ship a way to migrate the data.
- Each release's format fixtures are kept in the test suite, and every later
  release must open them. They start at 0.10.0.

Opening still needs the key. A format guarantee does not keep a key the server
destroyed, or a lineage that [retirement](operating-keys.md#retire-old-keys)
cut.

## The testing package

`keytend-kmip-testing` (the module `dev.keytend.kmip.testing`, with
`InMemoryKmipServer`, `TlsListener`, `Fault` and `ServerOperation`) is a
separate artifact for tests and for trying the SDK out. It is not in the SDK JAR,
and applications add it in test scope. It is test support, outside the
guarantees above:

- Any minor release may change it. The release notes list the changes.
- The application-level methods change least: `of`, `connect`, `configure`, the
  inspection methods, and `failNext` with `Fault` and `ServerOperation`. Where
  practical they are deprecated for one minor release before they change.
- Hooks named `protocol...` or `inject...` may change in any release.
- Its version is always the SDK's. Use the same version of both.
- It is not a key manager. Never give it real keys. It is outside the scope of
  SECURITY.md.

## Support

keytend-kmip is maintained by one person, as a best effort. There is no service
level agreement.

- Questions and bugs: [GitHub issues](https://github.com/keytend/keytend-kmip-java/issues).
- Vulnerabilities: privately, as [SECURITY.md](../SECURITY.md) says, with its
  response goals.
- Fixes go into the next release of the latest major version. Older releases
  are not patched unless SECURITY.md says otherwise for a version.
