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

# From the protocol layer to the application API

This page maps common [protocol-layer](protocol-layer.md) code to the application API,
`dev.keytend.kmip.kms`. To decide which API fits a task, see
[Choosing an API](choosing-an-api.md).

You can move one call at a time. `kms.protocol()` returns a non-owning `KmipClient` on the same
connection as a `Kms`.

## Connect

A `KmipClient` on a `TlsTransport` becomes a `Kms`:

```java
Kms kms = Kms.connect(KmsConfig.builder()
    .endpoints("kms.example.com:5696")
    .clientIdentityKeyStore(Path.of("client.p12"), password)
    .trustPem(Path.of("ca.pem"))
    .build());
```

`password` is the key store's `char[]` password. Pass `.tls(ssl)` instead of the two files to use
an `SSLContext` you built. Add `.minimumVersion(KmipVersion.V1_2)` for servers older than 1.4.

## Common calls and their replacements

`handle` is a `KeyHandle`, for example from `kms.keys().handle(id)` or `findByName(name)`.

| Protocol layer | Application API |
|---|---|
| `client.createSymmetricKey(...)`, `client.activate(id)` | `kms.keys().createAes(256).usages(...).create()` |
| Locate by name, then create if missing | `kms.keys().createAes(256).named(name).findOrCreate()` |
| `client.createKeyPair(...)` | `kms.keys().createKeyPair(spec).named(privateName, publicName).findOrCreate()` |
| `Requests.locate()` with `Attributes.name(name)` | `kms.keys().findByName(name)`, `kms.keys().list(KeyQuery.byName(name))` |
| Locate, then Get Attributes for each result | `kms.keys().locateWithAttributes(query)` |
| `Keys.aesKey(client.get(id).requirePayload(), id, 256)` | `handle.asSecretKey(Expect.aes(256), LocalUse.DECRYPT)` |
| `Keys.rsaPublicKey(...)`, EC and private-key conversion | `handle.asPublicKey(Expect.rsa(2048))`, `handle.asPrivateKey(Expect.ec(256))` |
| `Requests.encrypt()...cryptographicParameters(...)` | `handle.encrypt(CipherSpec.aesGcm(), plaintext, aad)` |
| `Requests.decrypt()` | `handle.decrypt(ciphertext, aad)`, `kms.keys().decrypt(query, ciphertext, aad)` |
| `Requests.signatureVerify()`, then `ValidityIndicator` | `handle.verify(spec, message, signature) == VerifyResult.VALID` |
| `Requests.getAttributes()` per version | `handle.attributes()` |
| `client.register(ManagedObjects.certificate(...), ...)` | `kms.keys().register(x509Certificate).register()` |
| Register Secret Data | `kms.keys().registerSecret(chars).named(name).register()` |
| Register a new secret, move the name, revoke the old | `kms.keys().registerSecret(chars).named(name).replace(old)` |
| `client.revoke(id, reason, message)` to deactivate a key | `handle.deactivate()` |
| Add or Modify Attribute of the Deactivation Date | `handle.deactivateAt(date)` |
| Locate a lineage, show it, then revoke and destroy | `newest.retirementPlan()`, then `newest.retirePredecessors(reason, plan)` or `deactivatePredecessors(reason, plan)` |
| Locate a name's keys, link and rename them by hand | `kms.keys().reconcilePlan(name)`, then `kms.keys().reconcile(name, plan)` |
| `client.discoverVersions()`, Query | `kms.serverVersions()`, `kms.serverInfo()` |
| `client.revoke(...)` for a compromise | `handle.revoke(RevocationReason.keyCompromise(message, occurredAt))` |
| `client.destroy(id)` | `handle.destroy()` |
| Catching `KmipException` and `IOException` | Catching `KmsException` subtypes |

Notes on the mapping:

- `asSecretKey` checks the purpose against the key's state and usages.
- `register(x509Certificate)` takes the usages from the certificate's Key Usage extension.
- `replace(old)` is described in [Replacing a secret](operating-keys.md#replacing-a-secret).
- The `KmsException` subtypes are described in [Handle failures](getting-started.md#handle-failures).

## Behavior to be aware of

- A `Kms` negotiates one version. Every endpoint must offer it and be a replica of the same KMS
  ([Endpoints and failover](production.md#endpoints-and-failover)).
- A `Kms` logs its operational events through SLF4J: failover, credential reloads, lease and
  cache problems ([Logging](production.md#logging)). The protocol layer logs nothing. A `Kms`
  also tells the listeners you add (`addListener`), and the opt-in metrics modules turn them into
  Micrometer meters ([Metrics](production.md#metrics)) or OpenTelemetry metrics and spans
  ([OpenTelemetry](production.md#opentelemetry)).
- Reads are retried on the next endpoint. Mutations are never re-sent. An
  `OutcomeUnknownException` means a mutation may have happened. Check before you repeat it.
- Calls on `kms.protocol()` neither fail over nor retry. One without a deadline of its own is
  bounded by the call timeout.
- Features a version lacks fail before sending with `UnsupportedException`. See
  [KMIP versions](compatibility.md#kmip-versions) for what each version supports.
- Use `handle.deactivate()` for routine deactivation, not a raw Revoke: on the KMIP 3.0 draft every
  Revoke makes the key Compromised ([Version normalization](kms-design.md#version-normalization)).
- A stored `Ciphertext` does not choose its own mode or key. Only AES-GCM and AES key wrap are
  read from it. RSA-OAEP, CBC and CTR need the expected spec, and `kms.keys().decrypt` needs the
  expected key.
- A rotated key's successor decrypts its ciphertexts.
- Retirement from a Compromised newest key is refused (`StateConflictException`), because it could
  destroy the lineage's only keys that are not compromised. Replace the key with
  `replaceCompromised`, then retire from the replacement.
- Calls that take a plan (`retirePredecessors(reason, plan)`, `deactivatePredecessors(reason,
  plan)`, `reconcile(name, plan)`) check it once before their first change and act only on what it
  names. KMIP has no transactions, so change a lineage from one place at a time.
- Retrieval, decryption, unwrapping and verification refuse Compromised keys unless the handle is
  `allowingCompromised()`. They always refuse Destroyed keys.
- `create()` and `register()` return Active objects. Use `createPreActive()` or
  `registerPreActive()` to stage one.
- The SDK chooses GCM, CBC and CTR IVs itself. You cannot pass one.
- Retrieved secret keys are `DestroyableSecretKey`s. Destroy them when you are done.
