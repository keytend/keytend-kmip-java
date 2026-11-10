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

# In-memory test server

This page lists how `InMemoryKmipServer` handles KMIP messages, versions, objects, cryptography and
lifecycle, and what it does not support. Read it when a test result depends on a protocol detail.
To set the server up and inject faults, start with
[Test without a server](getting-started.md#test-without-a-server) and the class Javadoc.

The server is in the `keytend-kmip-testing` artifact, a test dependency
([Test without a server](getting-started.md#test-without-a-server) has the Maven and Gradle
lines). It is test support, outside the compatibility promises
([the testing package](compatibility.md#the-testing-package)). Never give it real keys.

- [Messages and versions](#messages-and-versions)
- [Result reasons on KMIP 1.x](#result-reasons-on-kmip-1x)
- [Objects and attributes](#objects-and-attributes)
- [Cryptography](#cryptography)
- [Wrapped Get](#wrapped-get)
- [Lifecycle](#lifecycle)
- [Locate and Get Attributes](#locate-and-get-attributes)
- [Certify](#certify)
- [Not supported](#not-supported)
- [Over TLS](#over-tls)
  - [Client certificate renewal](#client-certificate-renewal)

## Messages and versions

- Each request is checked against its version's wire shapes. `violations()` lists what it found
  and the rules it checks. Assert that it is empty in tests of well-formed traffic.
- A request whose header version the server does not speak gets a message-level failure, stamped
  with the server's highest version. The reason is Invalid Message when that version is 1.x, and
  Unsupported Protocol Version otherwise.
- Every other response carries the request's version.
- Batches honor the Batch Error Continuation Option (Continue, Stop or Undo) and the ID
  Placeholder. An item with the ID Placeholder enumeration (2.0 and later), or on KMIP 1.x and 2.x
  an item without a Unique Identifier, uses the identifier the previous item produced. KMIP 3.0
  requires the field, so a 3.0 item without it fails with Missing Data and is recorded as a
  violation.

## Result reasons on KMIP 1.x

KMIP 2.0 added result reasons. On a 1.x request the server answers with the 1.x equivalent:

| Reason from 2.0                                                                        | Answer on 1.x     |
|----------------------------------------------------------------------------------------|-------------------|
| Wrong Key Lifecycle State, Attribute Single Valued                                     | Illegal Operation |
| Incompatible Cryptographic Usage Mask, Attribute Read Only, Sensitive, Not Extractable | Permission Denied |
| Attribute Not Found, Object Not Found, Wrapping Object Not Found                       | Item Not Found    |

Two lifecycle refusals follow what real 1.x servers answer instead. A key whose state forbids a
cryptographic operation, and an Activate of an object that is not Pre-Active, are Permission
Denied on 1.x.

## Objects and attributes

- New objects receive identifiers `mock-1`, `mock-2`, ... in creation order, unless
  `identifierSource` sets another source. Any text is accepted as an identifier in requests.
- Attributes are stored once and rendered in each version's form. An attribute a version does not
  define is left out of its responses, for example Object Group in 3.0 or Sensitive before 1.4.
- A new object gets Sensitive False and Extractable True unless the request sets them. Re-Key
  copies both. Modify and Set Attribute may change either in any direction.
- Get refuses an object whose Extractable is False (Not Extractable). Without a Key Wrapping
  Specification, it also refuses one whose Sensitive is True (Sensitive). Both are Permission
  Denied below 1.4.
- A destroyed object keeps its attributes. Get Attributes still works on it, and Get answers Item
  Not Found.
- On 1.x, Register of an X.509 certificate refuses a Cryptographic Usage Mask that claims a usage
  its Key Usage extension does not grant, with Invalid Field. KMIP 2.0 and later keep any mask.

## Cryptography

- Encrypt, Sign and MAC need an Active key. Decrypt, Signature Verify and MAC Verify also accept
  Deactivated and Compromised keys.
- Each operation needs the matching usage flag. Wrap Key and Unwrap Key also allow AES key wrap.
- A request without Cryptographic Parameters uses the key's first stored Cryptographic Parameters
  attribute.

| Mode or scheme | Defaults and rules                                                                |
|----------------|-----------------------------------------------------------------------------------|
| AES-GCM        | Encrypt picks a random IV of the IV Length, 12 bytes without one, and returns it. |
| AES-GCM        | The tag is a separate field from 1.4, and appended to the ciphertext before 1.4.  |
| AES-GCM, CTR   | From 1.2 the request must give IV Length, and a given IV must match it.           |
| AES-CBC, CTR   | Encrypt picks a random 16-byte IV when none is given, and returns it.             |
| AES-CBC, ECB   | PKCS5 padding, unless Padding Method is None.                                     |
| RSA-OAEP       | The hash and the MGF1 hash default to SHA-1.                                      |
| RSA-PSS        | The MGF1 hash defaults to SHA-1, and the salt length to the hash length.          |
| RSA-PSS        | The hash defaults to SHA-256 with Digital Signature Algorithm RSASSA-PSS.         |
| RSA-PSS        | With Padding Method PSS instead, the request must give Hashing Algorithm.         |

## Wrapped Get

- The wrapping key must be an Active AES key with Wrap Key usage.
- Its stored Cryptographic Parameters must have the requested Block Cipher Mode, or any mode when
  the request names none. Otherwise the answer is Invalid Field.
- NIST Key Wrap and AES Key Wrap with Padding are supported.
- Encoding Option No Encoding wraps the raw key bytes. Otherwise the TTLV-encoded Key Value is
  wrapped.

## Lifecycle

- Activate needs Pre-Active. Destroy refuses Active objects.
- Up to 2.1, Revoke with Key Compromise or CA Compromise makes the object Compromised. Other
  reasons make it Deactivated, from Active only.
- On 3.0 every Revoke makes the object Compromised, and Deactivate makes it Deactivated, from
  Active only.
- A second Revoke of a Compromised object is refused. The object keeps the first compromise's
  reason and dates.
- From 1.3, a Compromise Occurrence Date the request omits is the object's Initial Date. On 1.1
  and 1.2, a Key Compromise without one is Missing Data and a violation.
- A Pre-Active object becomes Active at its Activation Date, and an Active one Deactivated at its
  Deactivation Date, by the server's `clock`. `refuseClientDeactivationDate` controls whether a
  client may set a Deactivation Date.
- Re-Key of a symmetric key moves the Name attributes to the new key and copies the other client
  attributes. It links the keys with Replacement Object and Replaced Object links. Without an
  Offset the new key keeps the old key's dates. `freshDatesOnReKey` changes that.

## Locate and Get Attributes

- Locate matches each attribute in the request by equality, with three exceptions. Name matches
  by value, usage masks by containment, and two values of a date attribute as an inclusive range.
- Results are in creation order. Locate skips destroyed objects unless the request filters on
  State.
- From 1.3, the response has Located Items when the request gives Maximum Items or Offset Items.
- Get Attributes with no matching attribute answers the identifier alone on 1.x, and an empty
  Attributes structure on 2.x and 3.0.

## Certify

Certify issues a certificate with a CA the client registered, with keytend-kmip-server's
observable rules. `kms.tls().registerIssuer` links a CA this way.

- The request's Certificate link names the CA certificate. Its Public Key link names the CA public
  key, whose Private Key link names the CA private key. A missing or second link is Permission
  Denied.
- The CA certificate must be Active, a CA (basicConstraints cA=TRUE, keyCertSign when it has Key
  Usage) and within its validity. The CA private key must be Active, permit Certificate Sign, and
  be the private half of the certificate's key. Otherwise the answer is Permission Denied.
- The server has no owners, so any CA it holds signs. keytend-kmip-server also requires the caller
  to own the CA's three objects.
- The Unique Identifier names the public key to certify, Pre-Active or Active. Another object type
  is Permission Denied on 1.x and Invalid Object Type from 2.0.
- The request is PKCS#10 DER or PEM, in Certificate Request (1.x) or Certificate Request Value
  (2.0 and later). Without one, the answer is Feature Not Supported. A request whose signature does
  not verify is Invalid Field on 1.x and Invalid CSR from 2.0. Its key must be the public key's
  (Invalid Field).
- The subject key must be RSA of 2048 bits or more, or EC on P-256, P-384 or P-521 (Feature Not
  Supported). A request for a key on another named curve is Feature Not Supported before anything
  else is checked. A usage mask with Certificate Sign or CRL Sign is Permission Denied: only
  end-entity certificates are issued. Key and replacement links in the request are Invalid Field.
- The certificate has the request's subject and subject alternative names (DNS, email, URI and IP;
  another kind is Invalid Field), critical basicConstraints CA:FALSE, and a critical keyUsage from
  the requested Cryptographic Usage Mask or the public key's. An RSA CA signs with SHA-256, and an
  EC CA with SHA-256, SHA-384 or SHA-512 for P-256, P-384 or P-521.
- It is stored with the request's attributes, Pre-Active unless their dates make it otherwise, and
  linked to the public key and back.
- In a batch with the Batch Error Continuation Option Undo, Certify is Feature Not Supported
  before anything is issued, since an undone certificate would still be a valid certificate.
- By default it takes the dates as keytend-kmip-server does: the Activation Date is
  the notBefore (now without one), and the Deactivation Date the notAfter (without one, 365 days
  from the notBefore, capped at the CA's notAfter). An Activation Date at or after the CA's
  notAfter, a Deactivation Date after it (never cut short), and a Deactivation Date at or before
  the notBefore are Invalid Field.
- `certifyHonorsDates(false)` models servers that ignore the dates, as earlier
  keytend-kmip-server builds did: the certificate is valid from now for 365 days, capped at the CA's notAfter,
  whatever dates the request asks for.
- Either way the stored certificate gets only the dates the request gives. Without an Activation
  Date it stays Pre-Active, which is how the SDK's issue asks for it.
- `failNext(ServerOperation.CERTIFY, ...)` injects a fault into the next Certify.

## Not supported

Multi-part cryptography, templates, wrapped Register, Key Compression, MAC or signature key
wrapping, PSS over Digested Data, Re-certify, Derive Key, Import and Export. Re-Provision is offered
only over TLS, in its certificate-request form ([Client certificate
renewal](#client-certificate-renewal)). Operations the class
Javadoc does not list answer Operation Not Supported.

## Over TLS

`server.tlsListener()` serves the server over TLS on a loopback port, so a test can run the SDK's
TLS transport and its client credentials, as with a real KMS. Give it the server's key and
certificate, which must name `localhost`, and the CA that client certificates chain to:

```java
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.*;
import dev.keytend.kmip.testing.*;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;

class KmsOverTlsTest {
  PrivateKey serverKey;                          // made with your test CA
  X509Certificate serverCertificate, clientCa;
  Path clientChain, clientKey, serverCaPem;      // the client's PEM files

  @Test
  void connectsWithMutualTls() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = server.tlsListener()
            .identity(serverKey, serverCertificate)
            .trustAnchors(clientCa)
            .start();
        Kms kms = Kms.connect(tls.configure()
            .clientIdentityPem(clientChain, clientKey)
            .trustPem(serverCaPem)
            .build())) {
      kms.ping();
      assertEquals(1, tls.clientCertificates().size());
    }
  }
}
```

- `tls.configure()` has the listener's endpoint and the server's version range, as
  `server.configure()` does. Add the client's TLS settings and build.
- A client certificate is required by default. `clientAuth(ClientAuth.OPTIONAL)` accepts clients
  without one, and `ClientAuth.NONE` asks for none.
- `keyManager(...)` and `trustManager(...)` take a `TlsIdentityFollower`'s key manager and a
  `TlsTrustFollower`'s trust manager, so the server presents and checks what `kms.tls()` follows.
  `context(sslContext)` takes a TLS context of your own.
- `clientCertificates()`, `handshakes()` and `handshakeFailures()` show what each handshake did.
  `dropConnections()` closes the open connections, as a server restart would.
- The server's faults apply. One that fails an exchange, such as `Fault.REPLY_LOST`, closes the
  connection without a reply. While the server is `unreachable(true)`, new connections are closed
  before their handshake.
- `close()` stops the listener, not the server. The port is chosen by the system unless set with
  `port(...)`.

### Client certificate renewal

A listener with a provisioning CA offers Re-Provision (KMIP 2.0 and later), so a test can renew
the client's certificate with `kms.renewClientCertificate()` or automatic renewal
([Renew the client certificate](production.md#renew-the-client-certificate)). Put the
provisioning CA itself among the trust anchors too, as keytend-kmip-server requires it in its
`--ca` bundle, with the self-signed root it chains to, since each new certificate must pass the
listener's check of clients:

```java
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.*;
import dev.keytend.kmip.testing.*;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;

class RenewalTest {
  PrivateKey serverKey, provisioningKey;         // made with your test CAs
  X509Certificate serverCertificate, clientCa, provisioningCa;
  Path clientChain, clientKey, serverCaPem;      // the client's PEM files, which renewal rewrites

  @Test
  void renewsTheClientCertificate() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = server.tlsListener()
            .identity(serverKey, serverCertificate)
            .trustAnchors(clientCa, provisioningCa)
            .provisioningCa(provisioningKey, provisioningCa)
            .start();
        Kms kms = Kms.connect(tls.configure()
            .clientIdentityPem(clientChain, clientKey)
            .trustPem(serverCaPem)
            .clientCertificateRenewal(CertificateRenewal.onDemand())
            .build())) {
      RenewedCertificate renewed = kms.renewClientCertificate();
      assertEquals(1, tls.retiredCertificates().size());
    }
  }
}
```

It follows keytend-kmip-server's observable rules:

- `start()` refuses a provisioning CA that keytend-kmip-server does not start with,
  with `IllegalStateException` and the server's reason. The CA must be one (basicConstraints CA
  true, whatever its Netscape certificate type says) with a Key Usage that allows keyCertSign. Its
  certificate must be strong: a key of at least 112-bit security as OpenSSL 3 rates it (an RSA
  modulus of 1963 bits or more, or an EC curve of 224 bits or more), and, unless it is
  self-issued, a signature with neither MD2, MD4, MD5 nor SHA-1. The same certificate, byte for
  byte, must be among the trust anchors (the accepted issuers of a `trustManager(...)`), as the
  server requires it in its `--ca` bundle. A client certificate it issues must then pass the listener's
  check of clients, described below.
- Only the certificate-request form (PKCS#10 or PEM, self-signed with RSA PKCS#1 v1.5 or ECDSA and
  SHA-224 to SHA-512). The certificate form and the no-parameter form answer Feature Not
  Supported.
- The message is `[Re-Provision, Get(ID Placeholder)]`. Without the Get, the Re-Provision fails
  with Invalid Field before anything is issued. Only Get, Get Attributes and Get Attribute List may
  follow it (another item is Permission Denied), one Re-Provision per message (Permission Denied),
  and Undo is Feature Not Supported. Header credentials are Permission Denied.
- Once a certificate is retired, a Re-Provision on any connection that presents it is Permission
  Denied, also on connections opened before the renewal. Their other requests keep working.
- The new key must be new, and RSA of 2048 bits or more for an RSA certificate, or EC on the
  same curve: P-256, P-384 or P-521. Another key is Invalid Field. A key is used up only when its
  message commits, so a request that rolled back may be sent again.
- The new certificate has the replaced one's subject and subjectAltName, CA false, digitalSignature
  (and keyEncipherment for RSA), clientAuth, a notBefore five minutes back and a validity of 365
  days (`provisioningValidity(...)` sets another), cut short when the CA expires earlier, all by the
  server's clock (`clock(...)`). The listener's trust checks the new certificate by that clock too,
  as keytend-kmip-server checks by its own: a path through the provisioning CA, with at most 4
  intermediates, up to a self-signed trust anchor. A trust anchor that is not self-signed is part of
  the path, not its end, as in OpenSSL without partial chains, so the root above it is checked too,
  and a trust without that root has no path. So a provisioning CA that is an intermediate is
  accepted when it and its root are both trust anchors, as on keytend-kmip-server with both in its
  `--ca` bundle. Every certificate of that path must also suit a TLS client, as OpenSSL's purpose
  sslclient on keytend-kmip-server has it: an Extended Key Usage, where present, lists clientAuth
  (anyExtendedKeyUsage alone does not count), and each CA's Key Usage, where present, allows
  keyCertSign. Each CA must be one: basicConstraints with CA true, or without basicConstraints a
  version 1 self-signed root, a certificate with a Key Usage, or one whose Netscape certificate type
  names SSL CA. So a provisioning CA, or a root above it, whose Extended Key Usage is serverAuth
  only is refused, at `start()` as on keytend-kmip-server. Every certificate of the path must
  also pass the strength check above, and an EC key must be on a curve keytend-kmip-server
  implements (P-224 to P-521, secp256k1, or brainpool of 256 bits or more), so a root above the
  provisioning CA with an RSA-1024 key is refused at `start()` too. A new certificate that the
  trust, the purpose or these checks refuse later, by the server's clock, is Cryptographic
  Failure.
- A requested validity, as keytend-kmip-server takes it: the Re-Provision batch item's
  Message Extension with Vendor Identification `keytend_kmip_server`, Critical or not, whose
  Vendor Extension holds one Deactivation Date. That date is the notAfter and the stored
  certificate's Deactivation Date, and is never cut short. A date that has passed, one after the
  provisioning CA's notAfter, a Vendor Extension that holds anything else, two such extensions in
  one item, or the extension with the certificate form is Invalid Field.
- Any other Critical Message Extension, or this one on another operation, rejects the whole
  message before anything runs: Unknown Message Extension from KMIP 2.0, Feature Not Supported in
  1.x. A Non-Critical one is ignored.
- The message commits only when its Get returned the new certificate; otherwise the whole message
  fails with Invalid Field and the certificate is removed.
- When it commits, the replaced certificate is retired. A new connection that presents it gets
  one answer, Permission Denied for each item of its first message (only the first item unless
  the option is Continue), then closes. Open connections keep working.
  `retiredCertificates()` lists them, across the listeners and replicas of the server.
- Query lists Re-Provision on a listener with a provisioning CA. Without one, and in process
  (`server.connect()`), Re-Provision answers Operation Not Supported.
- `failNext(ServerOperation.RE_PROVISION, Fault.REPLY_LOST)` commits the message and then closes
  the connection without a reply, as a lost reply after the commit does.
