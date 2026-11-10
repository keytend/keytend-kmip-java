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

# Protocol coverage

The SDK models KMIP 1.1 to 2.1 and the pinned 3.0 CSD02 draft. Its registry, generated from
the OASIS specifications, holds:

- 66 operation codes;
- 431 standard tags;
- 71 enumeration groups;
- all 14 TTLV types.

Every operation has a request builder in `Requests`. A generic immutable TTLV payload keeps
every operation-specific field. `ProtocolSchema` lists the required fields of each payload,
per version.

This page lists what the SDK can encode. Whether a given server runs an operation is a separate
question, answered in [Validation](validation.md).

The table starts at 1.1, the SDK's minimum version. Some operations already existed in KMIP 1.0.

| Operation | Available since (SDK) | Request builder |
|---|---|---|
| Create | 1.1 | `Requests.create()` |
| Create Key Pair | 1.1 | `Requests.createKeyPair()` |
| Register | 1.1 | `Requests.register()` |
| Re-key | 1.1 | `Requests.reKey()` |
| Derive Key | 1.1 | `Requests.deriveKey()` |
| Certify | 1.1 | `Requests.certify()` |
| Re-certify | 1.1 | `Requests.reCertify()` |
| Locate | 1.1 | `Requests.locate()` |
| Check | 1.1 | `Requests.check()` |
| Get | 1.1 | `Requests.get()` |
| Get Attributes | 1.1 | `Requests.getAttributes()` |
| Get Attribute List | 1.1 | `Requests.getAttributeList()` |
| Add Attribute | 1.1 | `Requests.addAttribute()` |
| Modify Attribute | 1.1 | `Requests.modifyAttribute()` |
| Delete Attribute | 1.1 | `Requests.deleteAttribute()` |
| Obtain Lease | 1.1 | `Requests.obtainLease()` |
| Get Usage Allocation | 1.1 | `Requests.getUsageAllocation()` |
| Activate | 1.1 | `Requests.activate()` |
| Revoke | 1.1 | `Requests.revoke()` |
| Destroy | 1.1 | `Requests.destroy()` |
| Archive | 1.1 | `Requests.archive()` |
| Recover | 1.1 | `Requests.recover()` |
| Validate | 1.1 | `Requests.validate()` |
| Query | 1.1 | `Requests.query()` |
| Cancel | 1.1 | `Requests.cancel()` |
| Poll | 1.1 | `Requests.poll()` |
| Notify | 1.1 | `Requests.notifyRequest()` |
| Put | 1.1 | `Requests.put()` |
| Re-key Key Pair | 1.1 | `Requests.reKeyKeyPair()` |
| Discover Versions | 1.1 | `Requests.discoverVersions()` |
| Encrypt | 1.2 | `Requests.encrypt()` |
| Decrypt | 1.2 | `Requests.decrypt()` |
| Sign | 1.2 | `Requests.sign()` |
| Signature Verify | 1.2 | `Requests.signatureVerify()` |
| MAC | 1.2 | `Requests.mac()` |
| MAC Verify | 1.2 | `Requests.macVerify()` |
| RNG Retrieve | 1.2 | `Requests.rngRetrieve()` |
| RNG Seed | 1.2 | `Requests.rngSeed()` |
| Hash | 1.2 | `Requests.hash()` |
| Create Split Key | 1.2 | `Requests.createSplitKey()` |
| Join Split Key | 1.2 | `Requests.joinSplitKey()` |
| Import | 1.4 | `Requests.importObject()` |
| Export | 1.4 | `Requests.export()` |
| Log | 2.0 | `Requests.log()` |
| Login | 2.0 | `Requests.login()` |
| Logout | 2.0 | `Requests.logout()` |
| Delegated Login | 2.0 | `Requests.delegatedLogin()` |
| Adjust Attribute | 2.0 | `Requests.adjustAttribute()` |
| Set Attribute | 2.0 | `Requests.setAttribute()` |
| Set Endpoint Role | 2.0 | `Requests.setEndpointRole()` |
| PKCS#11 | 2.0 | `Requests.pkcs11()` |
| Interop | 2.0 | `Requests.interop()` |
| Re-Provision | 2.0 | `Requests.reProvision()` |
| Set Defaults | 2.1 | `Requests.setDefaults()` |
| Set Constraints | 2.1 | `Requests.setConstraints()` |
| Get Constraints | 2.1 | `Requests.getConstraints()` |
| Query Asynchronous Requests | 2.1 | `Requests.queryAsynchronousRequests()` |
| Process | 2.1 | `Requests.process()` |
| Ping | 2.1 | `Requests.ping()` |
| Create Group | 3.0 | `Requests.createGroup()` |
| Obliterate | 3.0 | `Requests.obliterate()` |
| Create User | 3.0 | `Requests.createUser()` |
| Create Credential | 3.0 | `Requests.createCredential()` |
| Deactivate | 3.0 | `Requests.deactivate()` |
| Encapsulate | 3.0 | `Requests.encapsulate()` |
| Decapsulate | 3.0 | `Requests.decapsulate()` |

## Version-specific encoding

- KMIP 1.1–1.4: 10 TTLV types, TemplateAttribute and indexed attributes.
- KMIP 2.0–2.1: 11 TTLV types, direct Attributes and attribute references.
- KMIP 3.0 CSD02: 14 TTLV types, separate Identifier and Reference types, ephemeral results,
  and ordered batches without the removed count, order and ID fields.

## Beyond operations

The SDK also covers:

- managed objects, including transparent and wrapped keys;
- attributes, batches and asynchronous results;
- streaming fields, authentication and server-initiated callbacks;
- binary TTLV and the OASIS XML and JSON encodings;
- Mutual-TLS sockets and HTTPS transports.

## Related pages

- [Protocol layer](protocol-layer.md): building requests and reading results.
- [Validation](validation.md#how-to-read-the-results): which servers ran which operations, and
  what each result means.
- [Research](research.md): the OASIS sources the registry is generated from.
