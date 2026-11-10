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

# Protocol layer

The protocol layer gives you every KMIP operation as it is on the wire. Use it for exact field
control and for operations the application API does not cover. For managing keys and encrypting
data, start with the application API instead: see [Choosing an API](choosing-an-api.md) and
[Getting started](getting-started.md).

| Package | Contents |
|---|---|
| `dev.keytend.kmip.model` | Immutable TTLV values, tags, enumerations, versions, attributes, managed objects |
| `dev.keytend.kmip.client` | `KmipClient`, request builders, results and protocol exceptions |
| `dev.keytend.kmip.codec` | Strict binary TTLV and the OASIS XML and JSON profiles |
| `dev.keytend.kmip.transport` | Mutual-TLS sockets, HTTPS, key store loading, hashed passwords |
| `dev.keytend.kmip.server` | An optional mutual-TLS listener for Notify, Put and Query callbacks |

The protocol layer has its own compatibility tier
([compatibility](compatibility.md#api-compatibility)).
`kms.protocol()` returns a non-owning `KmipClient` on the same connection as a `Kms`. It does not
fail over or retry. A call on it without a deadline of its own is bounded by the `Kms`'s call
timeout.

## Build a client

```java
import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.*;
import java.nio.file.Path;

char[] password = System.getenv("KMS_P12_PASSWORD").toCharArray();
var ssl = Tls.context(Path.of("client.p12"), password, Path.of("ca.pem"));

try (var client = KmipClient.negotiated(
        new TlsTransport("kms.example.com", 5696, ssl),
        VersionPolicy.atLeast(ProtocolVersion.V1_4))) {
    String id = client.createSymmetricKey(
        Enums.CryptographicAlgorithm.AES, 256,
        Enums.CryptographicUsageMask.ENCRYPT,
        Enums.CryptographicUsageMask.DECRYPT);
    client.activate(id);
    // Checks identity, type, algorithm, length and wrapping before building the key.
    javax.crypto.SecretKey key = Keys.aesKey(client.get(id).requirePayload(), id, 256);
    client.revoke(id, Enums.RevocationReasonCode.CESSATION_OF_OPERATION, "retired");
    client.destroy(id);
}
```

`client.p12` holds the client's key and certificate. `ca.pem` is the CA bundle that signed the
server's certificate. A call can fail in two ways:

- The server answered with a failure. `call` throws the unchecked `KmipException`.
  `e.result().hasReason(...)` gives the reason. `execute` returns failures as `Result` values.
- No usable answer came back. Transport and protocol problems are checked `IOException`s. After one,
  a mutation's outcome is unknown. Check the server (for example with Locate) before you repeat it.
  Reads can be retried.

No request is replayed automatically after a transport error.
[Handle failures](#handle-failures) has the details.

## Negotiate a version

`KmipClient.negotiated(transport, policy)` runs Discover Versions. It picks the highest version
the server offers that the `VersionPolicy` accepts. A policy sets a minimum, a maximum and an
optional allowlist.

```java
try (KmipClient client = KmipClient.negotiated(
        new TlsTransport("kms.example.com", 5696, ssl),
        VersionPolicy.atLeast(ProtocolVersion.V1_4))) {
  // client.version() is 1.4, 2.0 or 2.1
}
```

- The returned client owns the transport. Close the client once, and the transport closes too.
- With no acceptable version, `negotiated` closes the transport and throws. It sends no other
  request.
- Some servers cannot answer a newer request header. Discover Versions is then sent again with a
  lower header version: one named in the error response's header, else the highest accepted
  version of a lower major, else 1.4. The `KmipClient.negotiated` Javadoc has the details.
- `client.negotiate()` returns a non-owning view. Closing the view leaves the transport open.
  `ownsTransport()` tells the two apart.

## Handle failures

`call` requires Success. It throws `KmipException` for Failed, Pending or Undone. `execute`
returns the same outcomes as `Result` values to inspect.

```java
try {
  client.destroy(keyId);
} catch (KmipException e) {
  if (e.result().hasReason(Enums.ResultReason.ITEM_NOT_FOUND)) { /* already gone */ }
  else throw e;                               // permission, state, ...
} catch (IOException e) {
  // The request may have reached the server: the outcome of a mutation is
  // unknown. Reconcile (for example Locate or Get Attributes) before retrying.
  // Reads such as Get or Locate can be retried.
}
```

- `Result.reasonEnum()`, `hasReason(...)` and `statusEnum()` give typed codes.
  `Enums.X.fromCode(int)` maps any wire enumeration back to its constant.
- The exception message names the operation and the symbolic status and reason. It leaves out
  the server's Result Message, which the server controls. Read it with `e.result().message()`.
- `ProtocolException` (an `IOException`) means a response arrived but was rejected. It may be
  nonconformant, mis-correlated, or a Success without a required field.
- `RequestNotSentException` means nothing was sent, so the request is safe to repeat.

`CallContext` bounds or cancels one call. A call that times out or is canceled before anything
was sent is a `RequestNotSentException`. After the request may have been written, it is a
`SocketTimeoutException` or an `InterruptedIOException`.

```java
var context = CallContext.withTimeout(Duration.ofSeconds(2));
try {
  client.call(Requests.query().build(), context);
} catch (RequestNotSentException e) {
  if (e.timedOut() || e.cancelled()) { /* never sent: safe to repeat later */ }
} catch (InterruptedIOException e) { // includes SocketTimeoutException
  // possibly sent: reconcile a mutation before repeating it
}
```

To cancel from another thread, keep a `CallContext.cancellable()` and call its `cancel()`.
Closing the transport cancels every call in progress.

## Build any request

Each operation has an entry point in `Requests`. Builders take typed TTLV fields and keep the
whole payload, including fields with no convenience method.

```java
var request = Requests.encrypt()
    .uniqueIdentifier(keyId)
    .cryptographicParameters(
        Ttlv.enumeration(Tag.BLOCK_CIPHER_MODE, Enums.BlockCipherMode.CBC),
        Ttlv.enumeration(Tag.PADDING_METHOD, Enums.PaddingMethod.PKCS5),
        Ttlv.enumeration(Tag.CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.AES))
    .data(plaintext)
    .add(Ttlv.bytes(Tag.IV_COUNTER_NONCE, iv))
    .build();
byte[] ciphertext = client.call(request).requirePayload()
    .require(Tag.DATA).bytesValue();
```

`keyId`, `plaintext` and `iv` are your key's identifier, the data and a fresh 16-byte IV.

- Every response keeps its header, batch items, payload and extensions. Unknown vendor tags and
  numeric values stay intact.
- A known critical extension must be accepted with the client's `knownExtensions` constructor
  argument.
- `Structures` and request builders put fields in the order of the version's OASIS table. Fields
  the table does not list keep their positions. Low-level `Ttlv` structures keep the order you give.
- The SDK checks the version that introduced each tag, type and operation. It does not enforce
  every conditional rule, so you can build negative requests and inspect the failures.

`ProtocolSchema` gives the exact payload fields of a version:

```java
var fields = ProtocolSchema.fields(ProtocolVersion.V3_0,
    Operation.ENCAPSULATE, ProtocolSchema.Direction.REQUEST);
```

Vendor extensions:

- Vendor field values use numeric tags in the `0x54xxxx` range:
  `Ttlv.of(0x540001, Ttlv.Type.BYTE_STRING, bytes)`.
- Vendor operations use `Request.operation(0x80000010)`. The payload is sent as built.
- `Result.operationCode()` returns the raw code of any response item, also without an
  `Operation` constant. `WireEnums.fromCode(Enums.State.class, code)` maps a code to its constant.

## Typed builders

Typed builders cover the payloads that are easy to get wrong by hand. They produce ordinary
`Request`s, so `add(Ttlv...)` still works. Their result readers throw `ProtocolException` for a
malformed response.

| Need | Builder or reader |
|---|---|
| Cryptographic Parameters | `CryptoParameters.builder()`, `aesGcm()`, `rsaPss(hash, salt)`, `rsaOaep(hash)` |
| Encrypt, Decrypt, Sign, Verify, MAC, RNG | `CryptoRequests.encrypt(id)` and siblings, `CryptoResult.of(result)` |
| Multi-part (streaming) crypto | `MultipartOperation` |
| Key Wrapping Specification | `KeyWrapping.encrypt(kekId, params)`, `KeyWrapping.macSign(keyId, params)` |
| Import that restores an Export | `ImportRequest.restore(exportPayload, replaceExisting)`, `restoreAs(...)` |
| Create Key Pair | `KeyPairRequest.rsa(bits)`, `ec(curve, algorithm)`, `KeyPairRequest.result(result)` |
| Paginated Locate | `LocateRequest.builder()`, `page(offset, max)`, `client.locateAll(query, pageSize)` |
| Create and Join Split Key | `SplitKeyRequests.create(...)`, `join(...)`, `partIds(result)` |
| Protection Storage Masks | `ModernAttributes.protectionStorageMasks(set, set...)` |
| Register an X.509 certificate | `CertificateRegistration.of(cert, usage)` |
| Certificate, Opaque and PGP Key views | `ObjectViews.certificate`, `opaque`, `pgpKey(payload, id)` |
| Usage masks | `UsageMask.of(...)`, `requireDefinedIn(version)` |
| Request header options | `RequestOptions.builder()` |

Watch out for:

- A `KeyWrapping`'s `wrapAttribute(name)` becomes an Attribute Reference on 3.0.
- `CertificateRegistration.of` derives the algorithm and lengths. An EC certificate needs
  `ecAlgorithm`.
- `ObjectViews` throw a checked `GeneralSecurityException` subtype for the wrong object.
  `PgpKey.material()` is empty when the key is wrapped.
- `requireDefinedIn` also refuses flags a version lists as Reserved, such as Export from 2.0.
- `Ttlv.enumeration(tag, constant)` and `Attributes.mask(...)` reject a constant from the wrong
  group. The `int` overloads stay unchecked, for vendor values.
- `Requests.createSymmetricKey` needs at least one usage flag.

### Check a signature

A successful Signature Verify can still report Invalid. `SignatureVerifyResult.of(result)`
rejects a response without a Validity Indicator.

```java
CryptoResult verify = CryptoResult.of(client.call(
    CryptoRequests.signatureVerify(publicKeyId)
        .parameters(CryptoParameters.builder()
            .digitalSignature(
                Enums.DigitalSignatureAlgorithm.SHA_256_WITH_RSA_ENCRYPTION_PKCS_1_V1_5)
            .build())
        .data(message).signature(signature).build()));
if (!verify.valid()) throw new SecurityException("signature rejected: " + verify.validity());
```

### Sign with RSA-PSS on any version

RSA-PSS exists from KMIP 1.1, and Sign from 1.2. The explicit PSS details (mask generator, its
hash and the salt length) are 1.4 fields. `CryptoParameters.rsaPss` sends them, so it fails
before sending on 1.2 and 1.3. There, request PSS without them and the server uses its defaults.

```java
CryptoParameters pss = client.version().atLeast(ProtocolVersion.V1_4)
    ? CryptoParameters.rsaPss(Enums.HashingAlgorithm.SHA_256, 32)
    : CryptoParameters.builder()                // 1.2/1.3: PSS, server-default MGF and salt
        .algorithm(Enums.CryptographicAlgorithm.RSA)
        .padding(Enums.PaddingMethod.PSS)
        .hashing(Enums.HashingAlgorithm.SHA_256)
        .build();
CryptoResult signed = CryptoResult.of(client.call(
    CryptoRequests.sign(privateKeyId).parameters(pss).data(message).build()));
```

### Read attributes that may be missing

A successful Get Attributes may carry only the Unique Identifier. The result is then empty,
which is not an error.

```java
GetAttributesResult attributes = GetAttributesResult.of(client.call(
    Requests.getAttributes().uniqueIdentifier(keyId)
        .add(Ttlv.text(Tag.ATTRIBUTE_NAME, "Contact Information")).build()));
if (attributes.isEmpty()) { /* not set: not an error */ }
```

### Build a usage mask

A Cryptographic Usage Mask is an Integer bit mask, not an Enumeration. On 1.x it is wrapped in
an Attribute named "Cryptographic Usage Mask". On 2.x it is the tagged Integer itself. Portable
builders send the 1.x form and the SDK converts it.

Flags differ by version. Unrestricted and the FPE and PQC flags are 2.0 and later. Export and the
Translate flags are 1.x only. Check the set against the version first:

```java
UsageMask usage = UsageMask.of(Enums.CryptographicUsageMask.ENCRYPT,
    Enums.CryptographicUsageMask.DECRYPT).requireDefinedIn(client.version());
Ttlv legacy = Attributes.attribute("Cryptographic Usage Mask", usage.toTtlv()); // 1.x
Ttlv modern = usage.toTtlv();                                                   // 2.x
```

## Version differences

`Attributes` builds the 1.x form. Portable create and register builders translate it to direct
attributes when a 2.x or 3.0 client sends it. For modern operations you call directly,
`ModernAttributes` builds Attributes, vendor attributes, references and value selectors.

```java
var request = Requests.create()
    .add(Ttlv.enumeration(Tag.OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY))
    .attributes(
        Ttlv.enumeration(Tag.CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.AES),
        Ttlv.integer(Tag.CRYPTOGRAPHIC_LENGTH, 256),
        Ttlv.integer(Tag.CRYPTOGRAPHIC_USAGE_MASK, 12))
    .build();
```

What does not translate:

- Template object references and AttributeIndex were removed in 2.0. Use direct attributes and
  CurrentAttribute instead.
- A non-zero AttributeIndex, or any index on Delete Attribute, is rejected, not dropped.
- 1.x custom attributes `x-Name` and `y-Name` become 2.x vendor attributes. Their Vendor
  Identification is `x` or `y` and their Attribute Name is `Name` (KMIP 2.1 §4.60). Other
  non-standard names are rejected.
- `VersionValidator` rejects tags, enumeration values and mask bits the target version does not
  define. That includes tags that 2.0 or 3.0 made Reserved.

KMIP 3.0 specifics:

- Identifiers and references have distinct wire types. Portable `uniqueIdentifier(String)`
  builders emit a Reference for 3.0.
- `Ttlv.identifier`, `reference` and `nameReference` choose a type explicitly.
- `Ttlv.dateTimeExtended` keeps microseconds.
- `Request.Builder.ephemeral` sets the Ephemeral enumeration.
- `RequestOptions` accepts both the legacy asynchronous booleans and the Mandatory, Optional and
  Prohibited values.

## Batches and asynchronous operations

```java
var response = client.batch(List.of(
    Requests.get().uniqueIdentifier(keyId).build(),
    Requests.getAttributes().uniqueIdentifier(keyId).build()));
for (var result : response.results()) result.requireSuccess();
```

- `Response.results()` is in the order the server sent the items. `Response.resultFor(i)` gives
  the result for the `i`th request.
- `results()` can be shorter than the request list. A whole-message failure is one result
  without an operation (`messageLevelFailure()`). `resultFor` then throws `KmipException`.
- Under Stop or Undo, the items after the failing one are not returned. `resultFor` gives
  `Optional.empty()` for them. Under Undo, every item before the failure must be Undone.
- On 1.x and 2.x the SDK assigns unique batch IDs unless the request sets one. It correlates
  responses that arrive out of order. On 3.0 it correlates the ordered response list.
- Batch Order and Batch Error Continuation are sent only with more than one item. Undoing side
  effects is the server's job.

The SDK validates each response before you see it:

- The operation, protocol version and batch count
- The identifier echoed by Get, Get Attributes, Get Attribute List and Export
- A Client Correlation Value, if the server echoes one
- A Response Payload on every successful item, also when all its fields are optional (a Locate
  that finds nothing returns an empty one)
- The Required fields of the version's payload table
- The Correlation Value in the first response of a multi-part operation (Init Indicator True,
  Final Indicator not True); without it the next part would start another operation
- The Object Type of a Create, Get or Export response (and of a 1.2 Create or Join Split Key)

A mismatch is a `ProtocolException`. Register and Create Key Pair responses carry no Object Type,
so their identifiers cannot be checked this way.

For asynchronous operations, call `execute` with asynchronous request options. Keep
`Result.asynchronousCorrelation()`, then call `poll` or `cancel`. A completed Poll may be answered
with Operation Poll or with the original operation. `poll(correlation, Operation.CREATE)` accepts
only those two. `Requests.queryAsynchronousRequests` and `process` expose the 2.1 controls.

## Authentication

- `Tls.context(store, password, trust)` loads a PKCS#12 client key store and a PEM CA bundle. A
  key store with several private keys needs the alias: `Tls.context(store, password, trust, alias)`.
- `Credentials.credential` and its typed fields build device, attestation, OTP and ticket
  credentials. Username and password has a convenience method.
- For hashed passwords, wrap the transport in `HashedPasswordTransport`. It creates fresh
  monotonic credentials. It checks ServerHashedPassword before any result reaches you.
- You own the password `char[]` you pass in. Erase it when you are done.

`HashedPasswordTransport` runs one exchange at a time. A caller waits for its turn up to its
deadline or the maximum wait (60 s by default, or the constructor's `maxWait`). A `Kms` sets the
maximum with `KmsConfig.Builder.hashedPasswordLockWait(Duration)`. The server proof shows the
responder knows the password. TLS, not the proof, authenticates the response body.

## Transports

| Transport | Use |
|---|---|
| `TlsTransport` | Binary TTLV over mutual TLS (KMIP's port is 5696) |
| `HttpsTransport` | The KMIP HTTPS profile, with TTLV, XML or JSON bodies |
| `HashedPasswordTransport` | Wraps either one to add hashed-password credentials |

Every transport:

- Verifies the server's certificate chain and hostname, over TLS 1.2 or 1.3
- Has finite connect and read deadlines, and bounds message size and nesting
- Never replays a request after a connection failure
- Reports a failure before any byte was written as `RequestNotSentException`
- Cancels exchanges in progress when closed

`TlsTransport` is thread safe. It opens one connection per exchange unless you enable a pool:

```java
var pooled = TlsTransport.builder("kms.example.com", 5696, ssl)
    .pool(8, Duration.ofMinutes(5))
    .build();
```

A pool saves the TLS handshake. Over loopback on JDK 17 with TLS 1.3, a full handshake took about
2 ms, and a pooled Get Attributes to the in-memory server about 46 µs
([Performance](performance.md#tls-handshakes-through-the-followers)). Measure your own deployment.

- A pooled connection keeps the credentials of the handshake that opened it. For certificates
  that change, build the transport with `TlsTransport.builder(host, port, Supplier<SSLContext>)`.
- Idle connections close only when next taken. Call `closeIdleConnections()` to release them
  sooner.
- `builder.kmipCipherSuites()` limits the transport to the KMIP profile suites enabled on the JDK.
  JDK 24 and later disable `TLS_RSA_*`. A TLS 1.2-only server that needs them requires
  `jdk.tls.disabledAlgorithms` to be adjusted.
- `new TtlvCodec(maxBytes, maxDepth, maxElements)` bounds a whole message (65,536 elements by
  default). `Messages.MAX_BATCH_ITEMS` is 128. The five-argument `KmipClient` constructor sets
  another batch limit.

`HttpsTransport` enforces HTTPS and content types, sends no-cache and refuses redirects. Its XML
decoder forbids DTDs and external entities. Its JSON decoder keeps exact integers and rejects
duplicate properties. Text values must fit their type, or they are rejected rather than truncated.

The class Javadoc has the full contracts: deadlines, cancellation, pool reuse checks and changing
credentials. See [`TlsTransport`](../sdk/src/main/java/dev/keytend/kmip/transport/TlsTransport.java),
[`HttpsTransport`](../sdk/src/main/java/dev/keytend/kmip/transport/HttpsTransport.java) and
[`CallContext`](../sdk/src/main/java/dev/keytend/kmip/transport/CallContext.java).

## Callbacks

`CallbackServer` is a bounded mutual-TLS listener for server-initiated Notify, Put and Query.
Implement a `CallbackHandler`. The listener handles framing, versioned responses, batching,
failures and critical extensions. You choose how to store received objects and apply
notifications.

> [!WARNING]
> Every certificate the listener's `SSLContext` trusts can push key material (Put) and Notify.
> Give the listener a trust store that accepts only the KMIP server, and check the peer.

```java
var listener = CallbackServer.builder(bind, kmsOnlyContext, handler)
    .authorize(session -> {
      try {
        return expectedServer.equals(session.getPeerPrincipal());
      } catch (SSLPeerUnverifiedException e) {
        return false;
      }
    })
    .knownExtensions(Set.of("acme"))
    .errors(error -> log.warn("callback", error))
    .build();
```

`bind` is the listener's address. `kmsOnlyContext` trusts only the KMIP server's CA, and
`expectedServer` is the server's certificate principal.

- A `ContextualCallbackHandler` receives the verified peer chain and the request header.
- An exception thrown by `authorize` refuses the peer and reaches `errors`.
- `peerAddresses(address -> ...)` closes connections from other addresses before any TLS work. It
  is an address check, not authentication.
- The whole batch is validated before any handler runs. Unknown, vendor or out-of-version
  operations get Operation Not Supported. A handler exception becomes General Failure and reaches
  `errors`.

Handshakes, frames and idle connections have deadlines. `pendingHandshakes` (default 16) bounds
the handshakes in progress. The
[`CallbackServer`](../sdk/src/main/java/dev/keytend/kmip/server/CallbackServer.java) Javadoc
describes which handshake a new connection evicts when every thread is busy.

## KMIP 3.0 KEM workflow

The server performs the cryptography, so this works on JDK 17 without a local ML-KEM provider.
Create a key pair with algorithm `ML_KEM_768` and activate both keys. Then:

```java
var encapsulated = client.call(Requests.encapsulate()
    .uniqueIdentifier(publicKeyId).build()).requirePayload();
byte[] ciphertext = encapsulated.require(Tag.DATA).bytesValue();
String sharedSecretId = encapsulated.require(Tag.UNIQUE_IDENTIFIER).textValue();
var decapsulated = client.call(Requests.decapsulate()
    .uniqueIdentifier(privateKeyId).data(ciphertext).build());
String recoveredSecretId = decapsulated.uniqueIdentifier();
```

Both secret identifiers name server-managed objects. Export policy still decides whether you may
retrieve their material.

## Turn a Get response into a JCA key

```java
var payload = client.get(keyId).requirePayload();
SecretKey dek = Keys.aesKey(payload, keyId, 256);
PublicKey verifier = Keys.publicKey(client.get(pubId).requirePayload(), pubId,
    Enums.CryptographicAlgorithm.EC, 256);
```

- `Keys.aesKey(payload, expectedIdentifier, expectedBits)` checks the identifier, object type,
  AES algorithm, length, format and that the material is not wrapped.
- `Keys.publicKey(payload, id, algorithm, bits)` and `Keys.privateKey(...)` do the same for RSA
  and EC keys. They check the real modulus or curve size.
- They accept Transparent, PKCS#1, PKCS#8, X.509 and SEC1 formats, on P-256, P-384 and P-521.
  `Keys.rsaPublicKey(payload, id)` accepts RSA of any size.
- The one-argument `Keys.rsaPublicKey(object)` takes the inner Public Key structure. It does not
  check the identifier.

A failed retrieval is not a reason to create a replacement key.

## Secret lifetime

Java has no guaranteed zeroization. `Ttlv` is immutable: byte strings are copied when a value
is built and again by every `bytesValue()` call. Wiping your own array does not wipe the SDK's
copy, and the SDK cannot wipe it either.

The SDK wipes the temporaries it owns, as best-effort hygiene:

- `TlsTransport`: the encoded request after each exchange, whether it succeeded or failed.
- `HttpsTransport`: the encoded request and response bodies after each exchange. The HTTP
  client's own copy of the request is wiped only after a complete exchange. After a timeout it
  may still be sending it.
- `HashedPasswordTransport`: the per-request credential temporaries, and the password-derived
  secrets on close.
- `TtlvCodec`: discarded buffers as a frame grows, and decoded byte strings once copied.
- `Keys`: DER and PKCS#8 buffers during key conversion.
- `Ttlv.withBytes`: its temporary copy.

What stays behind:

- The `Ttlv` copies, the decoded response tree and the request tree you built
- The XML and JSON encodings, which are `String`s inside the codecs
- Buffers inside the JDK's TLS and HTTP code
- JCA objects such as `SecretKeySpec`, which copies its input
- Copies the garbage collector made while moving arrays

To limit exposure:

- Do not keep or log `Response`, `Result` or `Ttlv` objects that carry key material.
- Read key bytes with `ttlv.withBytes(bytes -> ...)`, which zeroes its copy afterwards.
- Destroy JCA keys when you are done, where the provider supports it.

Usernames and passwords are KMIP Text Strings, so they are `String`s inside the request. That is
true even when built from a `char[]`, as with `Credentials.usernamePassword(user, chars)` or
`RequestOptions.passwordAuthentication(user, chars)`.
