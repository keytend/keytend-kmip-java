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

# Running in production

> [!WARNING]
> **Experimental: not for production use.** keytend-kmip is experimental in every release. This
> page shows what a production deployment would need, for evaluation and testing.

This page covers what an application needs beyond a working connection: several endpoints,
deadlines, credential reloads, health checks, alerts, least-privilege credentials, and checking
your KMS before you rely on it. It starts from the connection in
[Getting started](getting-started.md#connect-to-your-kms). The exceptions and their categories are
in [Handle failures](getting-started.md#handle-failures).

- [Endpoints and failover](#endpoints-and-failover)
  - [Starting while the KMS is down](#starting-while-the-kms-is-down)
- [Deadlines and retries](#deadlines-and-retries)
- [Reload client credentials](#reload-client-credentials)
  - [Details](#details)
  - [Reloading on your own signal](#reloading-on-your-own-signal)
- [Renew the client certificate](#renew-the-client-certificate)
  - [What the server needs](#what-the-server-needs)
  - [After each renewal: the policy file](#after-each-renewal-the-policy-file)
  - [One certificate per client](#one-certificate-per-client)
  - [Several endpoints](#several-endpoints)
  - [What is on disk](#what-is-on-disk)
  - [Closing a Kms during a renewal](#closing-a-kms-during-a-renewal)
  - [Lockout and recovery](#lockout-and-recovery)
  - [The validity period](#the-validity-period)
- [Readiness](#readiness)
- [Logging](#logging)
  - [Which slf4j-api version](#which-slf4j-api-version)
- [Metrics](#metrics)
- [OpenTelemetry](#opentelemetry)
- [Listeners and events](#listeners-and-events)
- [What each consumer's credential needs](#what-each-consumers-credential-needs)
- [Qualifying a server](#qualifying-a-server)

## Endpoints and failover

List every replica of your KMS, in failover order:

```java
KmsConfig config = KmsConfig.builder()
    .endpoints("kms1.example.com:5696", "kms2.example.com:5696") // replicas of one KMS
    .clientIdentityPem(Path.of("client.pem"), Path.of("client.key"))
    .trustPem(Path.of("ca.pem"))
    .callTimeout(Duration.ofSeconds(10))
    .build();
Kms kms = Kms.connect(config); // one per process; thread-safe; close it at shutdown
```

- Endpoints listed together must be replicas of one KMS that serve the same keys.
- `connect` negotiates the KMIP version with the first endpoint that answers. Each other
  endpoint is checked with Discover Versions before its first request. One that does not offer
  that version is not used.
- A read that fails with a transient error is retried on the next endpoint. An endpoint that
  refused a connection is skipped for a cool-down, 5 seconds by default.
- Only signs of an unhealthy endpoint move traffic: a transport failure, a refused connection, a
  busy answer. A definite answer such as Not Found does not.
- A hung replica costs one attempt, not the whole call ([Deadlines and
  retries](#deadlines-and-retries)).

`KmsListener.endpointUnavailable` hears of each endpoint that is left
([Listeners and events](#listeners-and-events)).

### Starting while the KMS is down

An instance that may start while the KMS, or the network to it, is briefly down can let `connect`
wait for it instead of writing a retry loop:

```java
KmsConfig config = KmsConfig.builder()
    .endpoints("kms1.example.com:5696", "kms2.example.com:5696")
    .clientIdentityPem(Path.of("client.pem"), Path.of("client.key"))
    .trustPem(Path.of("ca.pem"))
    .connectRetry(Duration.ofMinutes(2))
    .build();
Kms kms = Kms.connect(config); // a working Kms, or the last failure after about 2 minutes
```

- Only unreachability (`TransientException`: refused connections, timeouts) is retried, with the
  retry policy's back-off.
- A wrong configuration, TLS or KMIP authentication, access and version failures fail at once.
  So does an interrupt.
- `connect` still returns a working `Kms` or throws, so a misconfiguration is found at startup.
- By default (`Duration.ZERO`), `connect` makes one attempt.

## Deadlines and retries

Each call has one deadline, the call timeout, which is 30 seconds by default and set with
`callTimeout`. It covers every attempt, back-off and wait for a pooled connection. For one call
site, use a view with another deadline:

```java
Kms quick = kms.withTimeout(Duration.ofSeconds(2)); // shares the connections; close does nothing
KeyHandle kek = quick.keys().findByName("orders-kek").orElseThrow();
```

Get, Locate, Get Attributes, Query, Discover Versions, Obtain Lease, Encrypt, Decrypt, Sign,
Signature Verify, MAC, MAC Verify and RNG Retrieve are retried after a `TransientException`.
Each retry goes to the next healthy endpoint, within the same deadline. Create, Register,
Activate, Revoke, Destroy, Re-key and attribute changes are never re-sent.

> [!WARNING]
> A mutation that fails in transit has an unknown outcome: `OutcomeUnknownException`. It may or
> may not have happened. Read the object's state before you repeat it.

```java
KeyHandle old = kms.keys().handle(oldId);
try {
  old.deactivate();
} catch (OutcomeUnknownException e) {
  KeyState state = old.attributes().state(); // read before deciding to repeat
  if (state == KeyState.ACTIVE) old.deactivate();
}
```

The default `RetryPolicy` makes 3 attempts, with a back-off from 100 ms doubling up to 2 s and a
jitter of 0.5. Change it on the configuration:

```java
RetryPolicy policy = RetryPolicy.defaults().toBuilder()
    .maxAttempts(5)
    .retryCrypto(false) // for servers that count Usage Limits: retry only the reads of objects
    .build();
KmsConfig config = KmsConfig.builder()
    .endpoints("kms1.example.com:5696", "kms2.example.com:5696")
    .clientIdentityPem(Path.of("client.pem"), Path.of("client.key"))
    .trustPem(Path.of("ca.pem"))
    .retryPolicy(policy)
    .build();
```

- While another endpoint is left to try, one attempt of a read waits at most the attempt
  timeout. By default that is the call timeout divided by the attempts: 10 seconds for 30
  seconds and 3 attempts. The last endpoint gets the rest of the deadline, so a slow but healthy
  server is still waited for.
- A timeout in a `withTimeout` view shorter than the call timeout is the caller's choice. It
  does not count against the endpoint, and moves no traffic.
- `RetryPolicy.none()` makes one attempt per call.
- `retryCrypto(false)` limits retries to Get, Locate, Get Attributes, Query, Discover Versions
  and Obtain Lease.

## Reload client credentials

For short-lived client certificates (cert-manager, SPIFFE) and rotated CA bundles, enable
`reloadOnChange()`:

```java
KmsConfig config = KmsConfig.builder()
    .endpoints("kms1.example.com:5696")
    .clientIdentityPem(Path.of("tls.crt"), Path.of("tls.key"))
    .trustPem(Path.of("ca.crt"))
    .reloadOnChange()   // checks the files at most once a second, before a request
    .build();
```

Publish the files atomically:

1. Write each new file under another name, in the same directory.
2. Rename it into place.
3. When several files change together, such as a certificate and its key, swap a directory of
   them in one rename. Kubernetes secret and projected volumes do this.

On success, `KmsListener.credentialsReloaded(files)` is called. From that request on, new
connections present the new certificate. Pooled connections opened with the old credentials are
closed.

On failure, the previous credentials stay in use and `KmsListener.credentialsReloadFailed(files,
why)` is called once. `why` names the file and the problem, never key material. Fix or republish
the files. They are read again at later checks, and after the next change. Alert on this event.

While a writer is not done, `KmsListener.credentialsStillChanging(files, changingFor)` is
called. That is not a failure. Alert on it only when `changingFor` grows long.

### Details

- The check runs on the calling thread before a request, at most once per interval. It compares
  each file's modification time, size and file key. No thread is started.
- `reloadOnChange(Duration)` sets another interval.
- A changed file is read once it has stayed unchanged for one interval. Files that keep changing
  are read all the same at the fifth check.
- Each file is read once, at most 1 MiB of it, with the same checks as the builder methods. A file
  that changed while it was read is read again later.
- A certificate and a key that do not match count as still changing for two reads and 10 seconds,
  then as a failure. Write the second file within 10 seconds of the first.
- Files that fail to load are tried again at the 1st, 2nd and 4th check, and so on up to every
  64th check, while they do not change.
- It watches only what was read from files. With `trustSystemDefaults()`, only the identity is
  watched. It works the same with `clientIdentityKeyStore` and
  `trustStore(file, password)`, for JKS and PKCS#12 files. A key store cut short is a writer not
  done, as a PEM file is.
- For an encrypted key or a key store, the configuration keeps a copy of the password for its
  life, unless the password comes from a supplier (below).
- A change that keeps a file's modification time, size and file key is missed. A writer that
  pauses at a valid point, such as after the first certificate of a bundle, may be loaded half
  done. Renaming into place avoids both.

To keep no copy of a file's password, pass a `Supplier<char[]>`.
It is asked at each read of the file, on the request's thread. Each array it returns is wiped
after that read, so return a new one each time:

```java
KmsConfig config = KmsConfig.builder()
    .endpoints("kms1.example.com:5696")
    .clientIdentityKeyStore(Path.of("client.jks"), () -> System.getenv("KMS_STORE_PASSWORD").toCharArray())
    .trustStore(Path.of("truststore.p12"), () -> System.getenv("KMS_TRUST_PASSWORD").toCharArray())
    .reloadOnChange()
    .build();
```

### Reloading on your own signal

To decide yourself when to reload, for example on a signal or from your own watcher, give the
configuration a supplier. `certPem`, `keyPem` and `caPem` are the `Path`s of the PEM files.

```java
AtomicReference<SSLContext> current =
    new AtomicReference<>(KmsConfig.sslContextFromPem(certPem, keyPem, caPem));
KmsConfig config = KmsConfig.builder().endpoints("kms1:5696").tls(current::get).build();
// when the certificate files change:
try {
  current.set(KmsConfig.sslContextFromPem(certPem, keyPem, caPem));
} catch (IllegalArgumentException e) {
  // not complete yet: keep the previous context
}
```

- `sslContextFromPem`, `sslContextFromPkcs12` and `sslContextFromKeyStores` (JKS or PKCS#12
  identity and trust store) validate the files as the builder does.
- The supplier is called before each request. Return the same instance until the credentials
  change. A new instance on every call disables connection pooling.
- If loading fails, keep returning the previous context. A supplier that throws makes the request
  fail with `TransientException`.

## Renew the client certificate

The SDK can renew its own client certificate, the one the configuration authenticates with,
through KMIP Re-Provision (KMIP 2.0 and later). It makes a new key pair, sends a PKCS#10 request,
checks the certificate the server issues, and replaces the configured files. Renew on demand, or
let the SDK renew before the certificate expires:

```java
KmsConfig config = KmsConfig.builder()
    .endpoints("kms1.example.com:5696")
    .clientIdentityPem(Path.of("tls.crt"), Path.of("tls.key"))
    .trustPem(Path.of("ca.crt"))
    .clientCertificateRenewal(CertificateRenewal.automatic(Duration.ofDays(30)))
    .build();

try (Kms kms = Kms.connect(config)) {
  RenewedCertificate renewed = kms.renewClientCertificate();   // on demand, at any time
}
```

- `CertificateRenewal.onDemand()` renews only when you call `renewClientCertificate()`.
  `CertificateRenewal.automatic(renewBefore)` also renews on an SDK thread once the certificate
  expires within `renewBefore`. Automatic renewal is off by default.
- Each open `Kms` checks the certificate's notAfter at least once an hour. The `Kms` instances of
  one configuration make one attempt at a time. A failed attempt is tried again after a minute,
  then after twice as long each time, up to an hour. A renewal that is not finished comes before
  the expiry check: one whose new certificate is in use but whose files were not all written, or
  a pending file ([below](#what-is-on-disk)). The SDK tries it again, with the same backoff, until
  it is done.
- Each check runs on a thread of its own, so a renewal that waits on its server never delays the
  checks of other identities.
- Choose `renewBefore` well within the validity of the certificates the server issues. When the
  new certificate already expires within `renewBefore`, the SDK reports it with
  `clientCertificateRenewalWarning` and renews again after half the new certificate's remaining
  validity. So it renews before the certificate expires, and never at once in a loop. This also
  covers a server that issues a shorter period than `validFor` asks.
- While a key that an earlier attempt moved aside exists for the current certificate
  ([below](#what-is-on-disk)), each check also opens one new connection with that certificate,
  at the failure backoff's pace. When the server refuses it, a late request may have retired the
  certificate: the SDK looks for the new one through the connections the `Kms` still has open, and
  finishes the renewal.
- The identity must come from files the SDK can rewrite: `clientIdentityPem`, with an
  unencrypted or an encrypted key, or with the key and chain in one file, or
  `clientIdentityKeyStore`, PKCS#12 or JKS. `build()` refuses renewal with
  `clientIdentity(KeyStore, ...)`, `tls(...)` or a custom `transport(...)`.
- The new key is RSA of the current modulus size, or EC on the current curve. An encrypted PEM key
  is replaced by one encrypted under the same password, and a key store keeps its type, alias,
  password and other entries.
- The SDK uses the new certificate at once, for the new connections of every `Kms` of the
  configuration, with or without `reloadOnChange()`. Connections opened with the old certificate
  finish the request they carry, then close. None is cut off. Until the new certificate is
  written to the files, a reload keeps it and reads only the trust files, since the identity
  files still hold the retired certificate.
- Like `reloadOnChange()`, renewal keeps the file names and a copy of a `char[]` password for the
  configuration's life.
- `KmsListener.clientCertificateRenewed(previousFingerprint, fingerprint, notAfter)` reports each
  renewal, `clientCertificateRenewalFailed(fingerprint, why)` each failure (the current
  certificate stays in use, unless `why` says otherwise), and
  `clientCertificateMayBeLockedOut(fingerprint, why)` a renewal that may have locked the client
  out. Each attempt gets one of the three. Alert on the last one. The metrics modules count them
  as `kmip.tls.renewals`.
- `clientCertificateRenewalWarning(fingerprint, why)` reports what needs attention but is not an
  attempt's outcome:
  - a pending file of other identity files moved aside;
  - a new certificate that expires within `renewBefore` already;
  - a new certificate the SDK uses although the server judged something by its own clock or
    policy, such as a period other than the one asked for ([below](#lockout-and-recovery));
  - `.unresolved` keys deleted after a renewal ([below](#what-is-on-disk));
  - a `Kms.close()` that stopped waiting for a renewal still running
    ([below](#closing-a-kms-during-a-renewal)).

  The metrics modules count it as `kmip.tls.renewal.warnings`.
- The CLI renews its own certificate with
  [`renew-certificate`](../cli/README.md#renew-certificate).

The failures of `renewClientCertificate()` follow
[Handle failures](getting-started.md#handle-failures):

- `TransientException` when nothing changed and a later call may succeed: the server could not be
  reached, another renewal of the same files is running, or a reply was lost and the server had
  issued nothing when the SDK looked.
- `OutcomeUnknownException` for every case where the client may be locked out
  ([below](#lockout-and-recovery)), including a certificate the server issued that the SDK
  refuses. The CLI exits with code 3 for it.
- `PermissionDeniedException` when the server refuses the current certificate or the request, or
  its policy does not allow the search for a certificate an earlier attempt may have received.
  When the server refuses the request with Permission Denied and an earlier attempt moved keys
  aside, the SDK first looks for a certificate issued for them: a late request may have retired
  the current certificate.
- `UnsupportedException` and `InvalidRequestException` when the server refuses the request and
  issues nothing.
- `RenewalNotSavedException`, an `IOException`, when the server issued the certificate and the
  process uses it, but the SDK could not write it to the files (a full disk, say). It carries the
  certificate chain in PEM (`pem()`), and its message ends with it: until the files are written,
  it may be the only copy outside the server. Every `Kms` of the configuration, and every
  configuration of the same files built later in the process, use the new certificate. Fix the
  cause and call `renewClientCertificate()` again before the process stops: it writes the files.
  The CLI exits with code 3 and prints the certificate.
- `IOException` when a file cannot be read or written before anything is issued.
- When the server refuses a request that resent the key of an earlier attempt, the exception is
  the refusal's own type, and its message names the file the key was moved to
  ([below](#what-is-on-disk)).

### What the server needs

keytend-kmip-server offers Re-Provision when it runs with a provisioning CA (`--provisioning-ca`
and `--provisioning-ca-key`, at KMIP 2.0 and later). Without one, `renewClientCertificate()`
fails with `UnsupportedException` and nothing changes. The server's
[Re-Provision guide](https://github.com/keytend/keytend-kmip-server/blob/main/docs/re-provision.md)
has the details. In short:

- Use a dedicated sub-CA as the provisioning CA, and put its certificate in the `--ca` bundle too.
  The client's trust of the server does not change.
- The client's policy entry must allow Re-Provision (53) and Get (10). Allow Locate (8) too: after
  a lost reply, and before it sends a pending key again, the SDK looks for the new certificate
  with Locate and Get. Without them it cannot tell whether an earlier attempt was issued a
  certificate, so it keeps the pending key and fails.
- The search looks for certificates by Initial Date, which the server sets by its own clock. The
  SDK reads the server's clock first, from the Time Stamp of a Discover Versions response on the
  same connection, so a server whose clock differs from the client's is searched at the right
  time. The pending file records the server's time when its key was written, and a requested
  notAfter is also counted on the server's clock.
- The server issues a certificate for the subject and subjectAltName of the old one, with
  clientAuth and a validity of one year, cut short when the provisioning CA expires earlier, or
  the validity you ask for ([below](#the-validity-period)).
- Each renewal needs a new key. The server refuses a key it has seen before.
- Another server must offer Re-Provision in its certificate-request form, with the message
  `[Re-Provision(Certificate Request), Get(ID Placeholder)]`. The [in-memory
  server](in-memory-server.md#client-certificate-renewal) does, for tests.

### After each renewal: the policy file

When the server issues the new certificate, it retires the old one: new connections that
present it are refused. The new certificate works at once, through the old certificate's policy
entry, its *anchor*. Fold it into the policy:

1. Copy the old certificate's entry under the new fingerprint, with the same `name`,
   `operations` and grants. `RenewedCertificate.fingerprint()`, the event and the SDK's log line
   give it.
2. Remove the old fingerprint's entry, in the same edit or later, never before step 1.
3. Restart the server, which reads the policy file at startup.

Until then the new certificate depends on the old entry: removing the old fingerprint before
adding the new one refuses the new certificate from the next start.

### One certificate per client

Several clients that share one certificate, such as replicas or pods given the same files, are
all affected when one renews: the others still present the retired certificate and are refused
when they reconnect. Give each client its own certificate, or keep renewal off and do not grant
Re-Provision to a shared certificate.

Renewals of the same files take turns:

- In one process, every configuration that renews the same files shares one attempt at a time,
  and every `Kms` of those configurations switches to the new certificate.
- Across processes, such as an application with automatic renewal and an operator running the
  CLI's `renew-certificate`, an attempt holds an exclusive lock on a lock file beside the key file
  (`tls.key.renewal.lock`) from start to end. Another process's attempt fails with
  `TransientException` meanwhile, and an automatic one waits for its next check.
- A process that renewed retires the certificate the other process still presents. That process
  picks up the new files with `reloadOnChange()`; without it, it needs a restart.

### Several endpoints

The server that issues the new certificate is the only one that knows the old one is retired,
unless the endpoints share one store. `build()` refuses renewal with several endpoints, unless
you state that they share one store:

```java
CertificateRenewal renewal =
    CertificateRenewal.automatic(Duration.ofDays(30)).endpointsShareOneStore();
```

The SDK renews through the endpoint the `Kms` uses at the time.

### What is on disk

The SDK writes every file atomically and durably: a temporary file in the same directory, forced
to the device, renamed into place, then the directory forced.

1. Before it sends anything, it writes the new private key to the *pending file*, beside the key
   file: `tls.key.renewal` (or `client.p12.renewal` for a key store). It creates the file only if
   none exists, so it never replaces another attempt's key. The pending file is for the owner
   only. It holds the key in PKCS#8 PEM, encrypted under the key's password when the key file is
   encrypted, and always for a key store (PBES2, PBKDF2-HMAC-SHA256, AES-256-CBC).
2. Once the new certificate is checked, it writes the pending file again with the certificate.
3. It replaces the chain file, then the key file (or the one combined file, or the key store),
   at the same paths. The key file and the key store are for the owner only, and a chain file
   keeps its permissions.
4. It deletes the pending file.

The pending file, and every file moved aside below, starts with the line
`keytend-kmip client certificate renewal 1`: the format and its version. Later releases read it
([Stored formats](compatibility.md#stored-formats)).

A process that stops between steps 2 and 4 is finished by the next one: the builder's
`clientIdentityPem` and `clientIdentityKeyStore` switch the files from the pending file before
they read them. That also covers a two-file PEM switch that stopped after the chain file, when the
pending file holds only the key and the chain file already holds a certificate for it. A pending
file that holds only a key is otherwise an attempt whose outcome is not known: the next
`renewClientCertificate()` looks for a certificate for that key, then sends the request again with
the same key if the server issued none.

What happens to a pending key:

| When | The pending key |
|---|---|
| The renewal finished: the identity files hold the new key and certificate | Deleted, since the files hold it. |
| The first request that carried the key was never sent (`RequestNotSentException`) | Deleted: the server never saw it. |
| The server refused the first request that carried the key, with no lost reply before it | Deleted: that refusal is final, and no other request carried the key. |
| A reply was lost, a search could not finish, or the SDK refused the certificate issued | Kept as `tls.key.renewal`, for the next call and for recovery. |
| The server refused a request that resent the key of an earlier attempt, and a search of every page then found no certificate for it | Moved to `tls.key.renewal.<time>.unresolved`. |
| The server refused the old certificate on new connections while the key was pending, and a search of every page found no certificate for it | Moved to `tls.key.renewal.<time>.unresolved`. |

A search that finds nothing shows only that the server had issued nothing at that moment. The
earlier request, whose reply was lost, may still commit later, retire the old certificate and
issue a certificate for that key. So in the last two cases the SDK moves the key aside instead of
deleting it, and the failure's message and the `clientCertificateRenewalFailed` event name the
file. The next attempt starts with a new key.

The SDK follows up each `.unresolved` key of the current certificate. It looks for a certificate
issued for the key, through the connections the `Kms` still has open on the old certificate, and
finishes the renewal if it finds one:

- when the server refuses the old certificate on new connections, in `renewClientCertificate()`;
- when the server refuses a new attempt's request with Permission Denied;
- with automatic renewal, as soon as a check finds the old certificate refused on a new
  connection (see the list at the top of this section).

A connect that the server refuses names the pending file and the `.unresolved` files. So does a
call of a running `Kms` refused on a new connection, once one Discover Versions on another new
connection shows that the server refuses the certificate: a policy that refuses only that
operation is not a lockout.

After a renewal of the same certificate succeeds, the SDK deletes its `.unresolved` files: those
whose `replaces:` line is the retired certificate's fingerprint, including the one whose key the
identity files now hold. The server retired that certificate and refuses any request still sent
with it, so it can no longer issue a certificate for those keys. `clientCertificateRenewalWarning`
names the files deleted, and any it could not delete. Until then, keep them: each holds the only
copy of the private key of a certificate the server may issue, unencrypted when the key file is.
`.unresolved` files of another certificate stay.

A pending file written for other identity files, because its certificate is not the current one,
is never deleted: it may hold the only copy of the key of a certificate the server holds as
active. The SDK moves it to `tls.key.renewal.<time>.orphaned`, reports the move with
`clientCertificateRenewalWarning`, and starts afresh. Keep the moved file until you know that no
client needs it.

Every moved file holds the key as the pending file does, with a few header lines before it. Copy
the `PRIVATE KEY` (or `ENCRYPTED PRIVATE KEY`) block when you need the key itself. A move never
replaces another file: when a file of that name exists already (two moves in one millisecond, or
a clock that stepped back), the SDK adds `-1`, `-2` and so on after the time.

The lock file `tls.key.renewal.lock` holds nothing and stays: deleting it while a process holds
it would let two processes lock two files of one name.

### Closing a Kms during a renewal

`Kms.close()` first stops the `Kms`'s automatic renewal. Then it handles a renewal that is
running, on demand or automatic, by how far it got:

- **Not sent yet.** The renewal checks just before it sends Re-Provision. Once the `Kms` is
  closed, it sends nothing, deletes the new key it wrote to the pending file, and fails with
  `IllegalStateException`, as every call of a closed `Kms` does. A key that an earlier attempt
  sent stays in the pending file. `close()` does not wait for such a renewal.
- **Sent, or finishing a certificate the server issued.** `close()` waits until the renewal ends:
  the new certificate is in the identity files, or the SDK concluded that the server issued none.
  It waits at most three times the call timeout the renewal uses: one for the reply, whose wait
  the call timeout bounds, and two for the search after a lost reply and the writes. The renewal
  uses the call timeout of the `Kms` it runs on: `callTimeout`, or a `withTimeout` view's for
  `view.renewClientCertificate()`. So a view with a longer timeout makes the wait longer, never
  shorter than three times `callTimeout`; with several renewals, the longest counts. Closing the
  last open `Kms` of a configuration also waits for the renewals that the other `Kms` instances
  of it started.
- **Still running when the wait runs out.** `close()` returns. Before it does,
  `clientCertificateRenewalWarning` says what the renewal is doing, what is on disk now (the
  pending file's state and the certificate the identity files hold), and how the next start
  recovers. The renewal goes on in its own thread.

Only the first `close()` of a `Kms` does this. A later call from another thread returns once the
first has returned, so what follows holds for it too. A call made inside the first, from a
listener it tells such as `clientCertificateRenewalWarning`, or on a renewal's thread returns at
once: it neither waits nor reports again.

After `close()` returns, no listener is called with an event of a renewal of that `Kms`: a
renewal that outlives it reports to the SDK's log only. So a metrics binder removed at close
never misses one. The renewal looks before each listener it calls:

- A listener that calls `close()` from its callback finishes that callback, and the listeners
  after it do not hear the event. `close()` on the renewal's own thread does not wait for that
  renewal.
- A listener that is still running its callback when the wait runs out finishes it after
  `close()` returns. The listeners after it do not hear that event.

The renewal threads are daemons. A process that exits without `close()`, or before the wait ends
(`System.exit`, a kill, a crash), stops a renewal where it is. The next start recovers from what
is on disk:

| What the process left | The next start |
|---|---|
| A pending file that holds only the new key, never sent | The next renewal looks for a certificate for it, finds none, and sends the request again with the same key. |
| A pending file that holds only the new key, sent | If the server issued nothing, the next renewal finds nothing and sends the request again with the same key. If it issued a certificate, it retired the old one, so a new process cannot connect with it: `Kms.connect` fails with `PermissionDeniedException` naming the pending file. Recover as in [Lockout and recovery](#lockout-and-recovery). |
| A pending file that holds the new key and certificate | The builder finishes the switch from it before it reads the identity files. |
| A two-file PEM switch stopped after the chain file | The builder finishes it, as above. |
| No pending file | Nothing to recover. |

So call `close()` before the process exits, and give it time to return.

### Lockout and recovery

The server retires the old certificate when the request's message commits. It then refuses the
old certificate on new connections, but connections already open on it keep working. So when
the reply is lost, the SDK looks for the new certificate with Locate and Get through, in turn:

1. a second connection of its own, opened with the old certificate before the request;
2. the idle connections that the `Kms` it was called on has open on the old certificate;
3. a new connection, which works only while the server has not retired the old certificate.

If it finds the certificate, it finishes the renewal. If a search that saw every page found
none, or a new connection shows that the server has not retired the old certificate, the call
fails with `TransientException` and keeps the pending key. A slow server may still commit the
lost message later. Calling `renewClientCertificate()` again is safe either way: it looks for
the certificate first, through the same connections, and finishes the renewal if the server
issued it meanwhile. If the server did not, it sends the request again with the same key.

The client may be locked out when the SDK cannot tell: no connection is left that the server
accepts, the search was refused or cut short, or the server issued a certificate the SDK refuses.
Then `renewClientCertificate()` throws `OutcomeUnknownException`, and
`KmsListener.clientCertificateMayBeLockedOut` is called. Its message says where the new private
key is. Later connects fail with `PermissionDeniedException` and a message that names the pending
file.

To recover:

1. Call `renewClientCertificate()` again on a `Kms` that still has connections open on the old
   certificate, for example after you fix the policy so that it allows Locate (8) and Get (10).
   The SDK finds the new certificate through those connections and finishes the renewal, for the
   pending key and for each `.unresolved` key. The connections close when they are idle for
   longer than the `Kms`'s idle timeout, or when the server or the network closes them, so do it
   soon.
2. Otherwise, follow the server's
   [lockout recovery](https://github.com/keytend/keytend-kmip-server/blob/main/docs/re-provision.md#lockout-recovery).
   The operator finds the new certificate in the server's startup log, or issues a new client
   certificate and maps it to the same principal in the policy file. Put the certificate and its
   key in the configured files: the key from the pending file, or from the `.unresolved` file
   whose public key the certificate holds. Then delete that file and restart the client.

The server has retired the old certificate by the time the SDK sees the new one. So the SDK
refuses the new certificate only when it cannot serve as the client's TLS certificate now:

- it is for another key, or has another subject or subjectAltName;
- its notAfter has passed;
- it is a CA certificate;
- its key usage excludes digitalSignature, or it has an extended key usage that excludes
  clientAuth. A certificate without an extended key usage is accepted, as TLS accepts it.

A refusal is reported as a possible lockout like the others: an `OutcomeUnknownException` whose
cause is a `ProtocolViolationException` that says why, and the file that holds the new key keeps
it (the message names it). What the server judges by its own clock or policy is no reason to
refuse the certificate, and `clientCertificateRenewalWarning` reports it instead:

- a period other than the one asked for ([below](#the-validity-period));
- a notBefore after the client's time: the server dates the certificate by its own clock, so the
  client's clock is likely behind;
- a signature that does not verify with the certificate the client has for its issuer: the
  server's trust of client certificates decides.

### The validity period

By default the server chooses the new certificate's validity (one year on keytend-kmip-server).
`CertificateRenewal.validFor(Duration)` asks for another:

```java
CertificateRenewal renewal = CertificateRenewal.onDemand().validFor(Duration.ofDays(90));
```

KMIP Re-Provision has no field for the period, so the SDK sends the notAfter it asks for in
keytend-kmip-server's Message Extension on the Re-Provision batch item: Vendor Identification
`keytend_kmip_server`, and a Vendor Extension that holds one Deactivation Date. keytend-kmip-server
takes it on KMIP 2.0, 2.1 and 3.0, and issues a certificate that expires at that
time
([its Re-Provision guide](https://github.com/keytend/keytend-kmip-server/blob/main/docs/re-provision.md#validity-period)).

The SDK marks the extension Critical. Each server answers in one of three ways:

| Server | What happens |
|---|---|
| Takes the extension | It issues the period asked for, and the SDK switches to the new certificate. |
| Does not understand it | It refuses the whole message before anything runs, as KMIP requires for a Critical extension. `renewClientCertificate()` throws `UnsupportedException`, nothing is issued, and the current certificate stays in use. Remove `validFor` to renew there. |
| keytend-kmip-server, for a period that ends after its provisioning CA's notAfter | It refuses with Invalid Field rather than cut the period short. `renewClientCertificate()` throws `InvalidRequestException`, and the current certificate stays in use. Ask for a shorter period. The server also uses Invalid Field for a request it cannot read or a key it refuses, so the exception names the period as the likely cause and keeps the server's message. |

Why Critical: the server retires the old certificate when it issues the new one. A server that
ignored a Non-Critical extension would issue its own period and retire the old certificate before
the SDK could see the difference. Refusing that certificate would then leave the client with a
retired certificate and a refused one, a lockout. With Critical, a server that does not understand
the request refuses it before it changes anything.

For the same reason the SDK never refuses an issued certificate for its period alone. If a server
ignores the Critical flag and issues another period, the SDK still switches to the certificate.
When its notAfter is more than a minute from the one asked for, `clientCertificateRenewalWarning`
names both. For a key an earlier attempt sent, the date asked for is a range: from the period
after the server's time when the key was first written to the period after now.
`RenewedCertificate.notAfter()` and the `clientCertificateRenewed` event give the period issued.

`validFor` takes at least ten minutes, and refuses a shorter period with
`IllegalArgumentException` before anything is sent. The server's dates are whole seconds, and the
SDK sees the certificate only after the server retired the old one, so a shorter certificate could
expire before the SDK can use it. With automatic renewal, ten minutes also leaves time to renew
again after half the period and to retry a failure. The notAfter asked for is counted on the
server's clock, as the server dates the certificate.

## Readiness

```java
Kms probe = kms.withTimeout(Duration.ofSeconds(15)); // longer than the attempt timeout
probe.ping(); // one Discover Versions; throws a KmsException when no endpoint answers
```

`ping()` needs no key and is retried and failed over like any read. Give a probe's own deadline
more than the attempt timeout (10 seconds with the defaults). A shorter deadline reports not-ready
while the current replica hangs, instead of trying the next one.

For a support bundle or a status page, `serverVersions()` lists the versions the server offers,
and `serverInfo()` its Query answer: vendor, server information, operations and object types.
Both are reads too. A server may implement less than it lists, so check the calls you depend on
when you [qualify the server](#qualifying-a-server).

```java
List<String> versions = kms.serverVersions(); // for example [2.1, 2.0, 1.4]
ServerInfo info = kms.serverInfo();            // UnsupportedException where Query is not implemented
log.info("KMS {} offers {}, {} operations", info.vendor().orElse("?"), versions, info.operations().size());
```

## Logging

The SDK logs its own operational events through [SLF4J](https://www.slf4j.org/), under fixed
logger names. Bind SLF4J to your logging as usual: Logback, or Log4j 2 through
`log4j-slf4j2-impl`, for example. Without a binding, SLF4J prints one notice and the SDK logs
nothing.

### Which slf4j-api version

The SDK brings slf4j-api 2.0.20, and uses only calls that SLF4J 1.7 also has, so it runs with
either. Use the one your binding is written for:

- With a 2.x provider (Logback 1.3 or later, `log4j-slf4j2-impl`, `slf4j-simple` 2.x), take
  slf4j-api 2.0.x, as the SDK brings it.
- With a 1.7-era binding (Logback 1.2 or earlier, `log4j-slf4j-impl`, `slf4j-log4j12`,
  `slf4j-simple` 1.7), pin slf4j-api 1.7.36. Maven may otherwise pick the SDK's 2.0.20 (nearest
  wins), and slf4j-api 2 ignores a 1.7 binding. Then your application's logs go nowhere either,
  not only the SDK's. SLF4J says so once at startup:
  `SLF4J(W): No SLF4J providers were found.` and `SLF4J(W): Ignoring binding found at
  [jar:file:.../slf4j-simple-1.7.36.jar!/org/slf4j/impl/StaticLoggerBinder.class]`.

Pin it in Maven:

```xml
<dependencyManagement>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>1.7.36</version>
    </dependency>
  </dependencies>
</dependencyManagement>
```

or in Gradle: `implementation('org.slf4j:slf4j-api') { version { strictly '1.7.36' } }`.

| Logger (`dev.keytend.kmip.kms.` prefix) | What | Level |
|---|---|---|
| `Endpoints` | An endpoint marked unavailable | WARN |
| `Endpoints` | An endpoint back in service | INFO |
| `Calls` | Each call, attempt and retry | DEBUG |
| `Tls` | New TLS files loaded (`reloadOnChange()`) | INFO |
| `Tls` | New TLS files that did not load | ERROR |
| `Tls` | TLS files still being written | WARN |
| `Tls` | The client certificate renewed | INFO |
| `Tls` | A renewal of the client certificate failed | WARN |
| `Tls` | A renewal that may have locked the client out | ERROR |
| `LocalKeys` | A cache selected a new write key | INFO |
| `LocalKeys` | A cache loaded a key | DEBUG |
| `LocalKeys` | A cache's refresh failed | WARN |
| `LocalKeys` | Compromised keys allowed for decryption (`allowCompromisedForDecrypt()`) | WARN |
| `Leases` | A lease granted | DEBUG |
| `Leases` | A key used without a granted lease | WARN |
| `Keys` | A key or certificate in use changed state | INFO; WARN to Compromised or Destroyed |
| `Keys` | A handle's key was replaced (stale handle) | INFO |
| `Keys` | A key another caller replaced at the same time | INFO |
| `Keys` | A key with several replacements, or a `CurrentKey` check that failed | WARN |
| `KmsListener` | A listener of yours threw: its class, the exception's class and the line that threw | WARN once per listener class |
| `KmsListener` | The same, with the stack trace | DEBUG, each time |

- Each WARN line, and the INFO lines of events that repeat, is logged at most once a minute per
  endpoint, key or set of files. The next line says how many were suppressed. The exception is a
  listener's failure, a WARN once per listener class. An endpoint's "unavailable" and "answers
  again" lines are limited separately. So on an endpoint that flaps, the last line logged may be
  out of date for up to a minute. The events and the metrics modules' gauges are not limited.
- What your call throws is logged only in the `Calls` lines, at DEBUG. What it met on the way is
  logged whatever its outcome: an endpoint found unavailable (WARN), a key found compromised. So
  a call that fails because its only endpoint is down logs one `Endpoints` WARN and throws.
- Lines carry key names and identifiers, endpoints, states and the SDK's failure messages. They
  never carry key material, passwords, plaintext or request bodies. Every value is escaped, so a
  name with a line break cannot forge a log line.

For a production deployment, set `dev.keytend.kmip` to INFO, and `dev.keytend.kmip.kms.Calls` to
DEBUG only while you investigate.

## Metrics

The opt-in module `keytend-kmip-micrometer` turns the SDK's events and counters into
[Micrometer](https://micrometer.io/) meters. The SDK itself has no metrics dependency. For
OpenTelemetry metrics and traces, see [OpenTelemetry](#opentelemetry). Add the module beside the
SDK:

```xml
<dependency>
  <groupId>dev.keytend</groupId>
  <artifactId>keytend-kmip-micrometer</artifactId>
  <version>0.10.0-rc.1</version>
</dependency>
```

Add its listener to the configuration. `registry` is your `MeterRegistry`:

```java
KmsConfig config = KmsConfig.builder()
    .endpoints("kms1.example.com:5696", "kms2.example.com:5696")
    .clientIdentityPem(Path.of("client.pem"), Path.of("client.key"))
    .trustPem(Path.of("ca.pem"))
    .addListener(KmipMeters.listener(registry))
    .build();
```

Some meters are read when the registry publishes, not counted from events. Bind them for each
`Kms` (or `LocalKeys.SharedKms`) and each `LocalKeys` cache. A binder's `close()` removes its
meters. It never closes your registry.

```java
try (Kms kms = Kms.connect(config);
    LocalKeys keys = kms.keys().localKeys("orders-kek")
        .scope(KeyQuery.all().custom(CustomAttribute.client("family"), "orders"))
        .expect(Expect.aes(256))
        .open();
    KmipMeterBinder connections = KmipMeters.connections(kms);
    KmipMeterBinder cache = KmipMeters.localKeys(keys)) {
  connections.bindTo(registry);
  cache.bindTo(registry);
  ...
}
```

From the listener:

| Meter | Type | Tags |
|---|---|---|
| `kmip.client.calls` | timer: each application call, retries and failover included | `operation`, `outcome` (`success` when it returned, `failure` when it threw), `category`, `reason` |
| `kmip.client.attempts` | timer: each attempt | `operation`, `endpoint`, `version`, `outcome` |
| `kmip.client.retries` | counter | `operation`, `category`, `reason` |
| `kmip.client.failovers` | counter | `operation`, `from`, `to` |
| `kmip.client.endpoint.available` | gauge: 1 while the endpoint answers, 0 once it was found unavailable | `endpoint` |
| `kmip.localkeys.loads` | timer: loads that succeeded | `cache`, `purpose` |
| `kmip.localkeys.refresh.failures` | counter | `cache`, `purpose` |
| `kmip.localkeys.selections` | counter: new write keys | `cache` |
| `kmip.leases` | counter | `result` (`granted`, `renewed`, `not_granted`) |
| `kmip.tls.reloads` | counter | `outcome` (`success`, `failure`, `still_changing`) |
| `kmip.tls.renewals` | counter: renewals of the client certificate, one outcome per attempt; alert on `locked_out` | `outcome` (`success`, `failure`, `locked_out`) |
| `kmip.tls.renewal.warnings` | counter: reports about renewal that need attention but are not an outcome | none |
| `kmip.keys.state.changes` | counter | `from`, `to` |
| `kmip.keys.stale.handles` | counter | none |
| `kmip.keys.concurrent.replacements` | counter | `kind` (`several`: run `reconcile`; `another_caller`: use `latest()`) |
| `kmip.currentkey.check.failures` | counter | none |

From the binders:

| Meter | Type | Binder | Tags |
|---|---|---|---|
| `kmip.client.connections` | gauge | `connections(kms)` | `endpoint`, `state` (`open`, `idle`, `in_use`) |
| `kmip.client.connections.opened` | counter | `connections(kms)` | `endpoint` |
| `kmip.client.pool.wait` | timer | `connections(kms)` | `endpoint` |
| `kmip.localkeys.requests` | counter | `localKeys(cache)` | `cache`, `purpose`, `result` (`hit`, `miss`) |
| `kmip.localkeys.load.failures` | counter: first loads included | `localKeys(cache)` | `cache` |
| `kmip.localkeys.evictions` | counter | `localKeys(cache)` | `cache` |
| `kmip.localkeys.capacity.waits` | counter | `localKeys(cache)` | `cache` |
| `kmip.localkeys.size` | gauge | `localKeys(cache)` | `cache` |
| `kmip.localkeys.usable` | time gauge: how long the write key stays usable | `localKeys(cache)` | `cache` |
| `kmip.localkeys.write.failing` | gauge: 1 while the write key's last validation failed | `localKeys(cache)` | `cache` |
| `kmip.tls.certificate.expiry` | time gauge | `tlsIdentity(follower)` | `identity` |

- `operation` is the public method's name: `seal`, `rewrapTo`, `list`, `findOrCreate`. A
  `...Result` form has its method's name (`rotateResult` is `rotate`, `findOrCreateResult` is
  `findOrCreate`). A `LocalKeys` cache, a scheduled check and a TLS follower have names of their
  own, which `KmsListener.callStarted` lists. Each page of a lazy `locate` is a call of its own.
  Build dashboard queries on these names.
- Tags take few values: operations, the configured endpoints, versions, outcomes, failure
  categories and reasons, and the names of your caches and identities. Key identifiers are never
  tags. `reason` takes about 70 KMIP reasons, and multiplies `kmip.client.calls` by operation.
  That is bounded, but large on Prometheus.
- Two `Kms` to the same endpoint, or two caches of one write key name, would make the same meter
  twice, and a binder refuses that (`IllegalStateException`). Give each its own tag:
  `KmipMeters.connections(kms, Tags.of("client", "billing"))`. `localKeys`, `tlsIdentity` and
  `listener` take tags too.
- Prometheus registries refuse a meter whose tag keys differ from those of a meter of the same
  name. So give every source of a meter the same tag keys. Tag the first `Kms` too (`client`),
  not only the second. A binder that the registry refuses registers nothing.
- Histograms and percentiles are off unless a `MeterFilter` of your registry turns them on.

Alert on `kmip.localkeys.usable` falling while `kmip.localkeys.write.failing` is 1
([Alarms before keys stop](local-keys.md#alarms-before-keys-stop)), and on
`kmip.client.endpoint.available` staying 0. The module's Javadoc (`KmipMeters`) describes each
meter.

## OpenTelemetry

The opt-in module `keytend-kmip-opentelemetry` records the same measurements as
[OpenTelemetry](https://opentelemetry.io/) metrics, and the SDK's calls as spans. It uses the
OpenTelemetry API only: pass your `OpenTelemetry`, your SDK's or the Java agent's
(`GlobalOpenTelemetry.get()`). Add the module beside the SDK:

```xml
<dependency>
  <groupId>dev.keytend</groupId>
  <artifactId>keytend-kmip-opentelemetry</artifactId>
  <version>0.10.0-rc.1</version>
</dependency>
```

Make a `KmipTelemetry` of your `openTelemetry` and add its listeners to the configuration. The
tracing listener is optional:

```java
KmipTelemetry telemetry = KmipTelemetry.create(openTelemetry);
KmsConfig config = KmsConfig.builder()
    .endpoints("kms1.example.com:5696", "kms2.example.com:5696")
    .clientIdentityPem(Path.of("client.pem"), Path.of("client.key"))
    .trustPem(Path.of("ca.pem"))
    .addListener(telemetry.metricsListener())
    .addListener(telemetry.tracingListener())
    .build();
```

Some instruments are read when your SDK collects, not counted from events. Observe them for each
`Kms` and each `LocalKeys` cache. `close()` removes the callback. It never closes your
`OpenTelemetry`.

```java
try (Kms kms = Kms.connect(config);
    LocalKeys keys = kms.keys().localKeys("orders-kek")
        .scope(KeyQuery.all().custom(CustomAttribute.client("family"), "orders"))
        .expect(Expect.aes(256))
        .open();
    KmipInstruments connections = telemetry.connections(kms);
    KmipInstruments cache = telemetry.localKeys(keys)) {
  ...
}
```

The instruments follow the semantic conventions: durations are histograms in seconds,
`error.type` is set on a failure only (the failure's category, such as `not_found`), and an
endpoint is `server.address` and `server.port`. The scope is `dev.keytend.kmip`. Each Micrometer
meter has its counterpart:

| Micrometer | OpenTelemetry | Type, unit | Attributes |
|---|---|---|---|
| `kmip.client.calls` | `kmip.client.call.duration` | histogram, `s` | `kmip.operation`; on a failure `error.type`, `kmip.result_reason` |
| `kmip.client.attempts` | `kmip.client.attempt.duration` | histogram, `s` | `kmip.operation`, `server.address`, `server.port`, `network.protocol.version`; `error.type` |
| `kmip.client.retries` | `kmip.client.retries` | counter, `{retry}` | `kmip.operation`, `error.type`, `kmip.result_reason` |
| `kmip.client.failovers` | `kmip.client.failovers` | counter, `{failover}` | `kmip.operation`, `kmip.failover.from`, `kmip.failover.to` |
| `kmip.client.endpoint.available` | `kmip.client.endpoint.available` | gauge, `1` | `server.address`, `server.port` |
| `kmip.localkeys.loads` | `kmip.localkeys.load.duration` | histogram, `s` | `kmip.localkeys.name`, `kmip.localkeys.purpose` |
| `kmip.localkeys.refresh.failures` | `kmip.localkeys.refresh.failures` | counter, `{failure}` | `kmip.localkeys.name`, `kmip.localkeys.purpose` |
| `kmip.localkeys.selections` | `kmip.localkeys.selections` | counter, `{selection}` | `kmip.localkeys.name` |
| `kmip.leases` | `kmip.leases` | counter, `{lease}` | `kmip.lease.result` |
| `kmip.tls.reloads` | `kmip.tls.reloads` | counter, `{reload}` | `kmip.tls.reload.result` |
| `kmip.tls.renewals` | `kmip.tls.renewals` | counter, `{renewal}` | `kmip.tls.renewal.result` |
| `kmip.tls.renewal.warnings` | `kmip.tls.renewal.warnings` | counter, `{warning}` | none |
| `kmip.keys.state.changes` | `kmip.key.state.changes` | counter, `{change}` | `kmip.key.state.from`, `kmip.key.state.to` |
| `kmip.keys.stale.handles` | `kmip.key.stale_handles` | counter, `{handle}` | none |
| `kmip.keys.concurrent.replacements` | `kmip.key.concurrent_replacements` | counter, `{replacement}` | `kmip.key.replacement.kind` |
| `kmip.currentkey.check.failures` | `kmip.currentkey.check.failures` | counter, `{failure}` | none |
| `kmip.client.connections` | `kmip.client.connection.count` | up-down counter, `{connection}` | `server.address`, `server.port`, `kmip.connection.state` (`idle`, `used`) |
| `kmip.client.connections.opened` | `kmip.client.connection.opened` | counter, `{connection}` | `server.address`, `server.port` |
| `kmip.client.pool.wait` | `kmip.client.connection.waits`, `kmip.client.connection.wait.time` | counters, `{wait}` and `s` | `server.address`, `server.port` |
| `kmip.localkeys.requests` | `kmip.localkeys.requests` | counter, `{request}` | `kmip.localkeys.name`, `kmip.localkeys.purpose`, `kmip.localkeys.result` |
| `kmip.localkeys.load.failures` | `kmip.localkeys.load.failures` | counter, `{failure}` | `kmip.localkeys.name` |
| `kmip.localkeys.evictions` | `kmip.localkeys.evictions` | counter, `{eviction}` | `kmip.localkeys.name` |
| `kmip.localkeys.capacity.waits` | `kmip.localkeys.capacity.waits` | counter, `{wait}` | `kmip.localkeys.name` |
| `kmip.localkeys.size` | `kmip.localkeys.entry.count` | up-down counter, `{entry}` | `kmip.localkeys.name` |
| `kmip.localkeys.usable` | `kmip.localkeys.usable` | gauge, `s` | `kmip.localkeys.name` |
| `kmip.localkeys.write.failing` | `kmip.localkeys.write.failing` | gauge, `1` | `kmip.localkeys.name` |
| `kmip.tls.certificate.expiry` | `kmip.tls.certificate.expiry` | gauge, `s` | `kmip.tls.identity` |

The rows down to `kmip.currentkey.check.failures` come from the metrics listener. The others come
from `connections(kms)`, `localKeys(cache)` and `tlsIdentity(follower)`. The tags map to the
attributes in the table's last column, with the same values. A success has no `error.type`.

- The tracing listener makes a span `KMIP <operation>` for each application call, under the
  span current when you make the call. Each attempt is a child span `KMIP <step> attempt`, of
  kind `CLIENT`.
- A call's span carries `kmip.call.id` (the `Call` number of the `Calls` log lines),
  `kmip.object.id` and `kmip.attempt.count`. Each retry adds a `kmip.retry` event. A call that
  threw records the exception and an error status.
- The spans are never made current. Background work, such as a `LocalKeys` refresh or a
  scheduled check, is a trace of its own.
- As with Micrometer, attributes take few values. Identifiers are on spans only, never on a
  metric.
- Two `Kms` to the same endpoint, or two caches of one write key name, would report the same
  series, and the second is refused (`IllegalStateException`). Give each its own telemetry with
  your own attributes:
  `KmipTelemetry.builder(openTelemetry).attributes(Attributes.of(AttributeKey.stringKey("client"),
  "billing")).build()`.
- Histogram boundaries are the semantic conventions' for durations (5 ms to 10 s), given as
  advice. A View in your SDK can change them.
- Without an SDK (`OpenTelemetry.noop()`), every instrument and span does nothing. A series two
  sources would report is still refused, so the code behaves the same with and without one.

The module's Javadoc (`KmipTelemetry`) describes each instrument and span attribute.

## Listeners and events

A `KmsListener` receives events for metrics, tracing and alerts. Implement only the methods you
need. `addListener` adds one beside the others, the metrics modules' among them. `log` is your
logger.

```java
KmsListener alerts = new KmsListener() {
  @Override
  public void currentKeyCheckFailed(String keyId, int failuresInARow, KmsException failure) {
    if (failuresInARow >= 3) log.warn("not following rotations of {}", keyId, failure);
  }

  @Override
  public void credentialsReloadFailed(String files, String why) {
    log.warn("TLS files {} did not load: {}", files, why);
  }
};
KmsConfig config = KmsConfig.builder()
    .endpoints("kms1.example.com:5696", "kms2.example.com:5696")
    .clientIdentityPem(Path.of("client.pem"), Path.of("client.key"))
    .trustPem(Path.of("ca.pem"))
    .addListener(alerts)
    .build();
```

Listeners are called in the order added, on the thread that does the work, so keep them quick.
What one throws, an `Error` included, is ignored, and the next one is still called. Events carry
identifiers and outcomes, never key material.

| Event | What to do |
|---|---|
| `callStarted`, `callFinished` | Each application call, retries and failover included: its latency, and whether it returned or threw. |
| `started`, `finished` | Each attempt, with its latency and outcome: metrics and tracing. |
| `retrying` | A read is retried after a back-off: count it. |
| `endpointUnavailable` | An endpoint was left: alert when it stays unavailable. |
| `endpointAvailable` | That endpoint answers again. |
| `currentKeyCheckFailed` | Alert when `failuresInARow` grows: rotations are not followed. |
| `staleHandle` | A handle's key was replaced: refresh it with `latest()`. |
| `concurrentReplacement` | Several newest keys (two or more `replacements`): run `reconcile`. One, made by another caller: use `latest()`. |
| `keyStateChanged` | A key or certificate in use changed state: alert on Compromised. |
| `credentialsReloaded` | New client credentials are in use. |
| `credentialsReloadFailed` | The new TLS files did not load: fix them, and alert. |
| `credentialsStillChanging` | Alert only when `changingFor` grows long. |
| `clientCertificateRenewed` | The client certificate was renewed: add the new fingerprint to the server's policy ([Renew the client certificate](#renew-the-client-certificate)). |
| `clientCertificateRenewalFailed` | A renewal failed and the current certificate stays in use: alert when it keeps failing near expiry. |
| `clientCertificateMayBeLockedOut` | The client may be locked out: alert at once, and follow [Lockout and recovery](#lockout-and-recovery). |
| `clientCertificateRenewalWarning` | A file was moved aside, or `renewBefore` is longer than the validity the server issues: read `why`. |
| `localKeySelected`, `localKeyLoaded`, `localKeyRefreshFailed` | See [Local keys](local-keys.md). |
| `leaseGranted`, `leaseNotGranted` | A lease granted or renewed; a key used without one. |

`KmsEvent.callId()` is the same in a call's events and in each of its attempts, so a tracer can
pair them. Use `operation`, `endpoint`, `version` and `outcome` as metric tags; never `objectId`
or `callId`.

Two sets of counters are not events. Poll them, which is cheap:

- `LocalKeys.stats()`: hits and misses for each purpose, loads, load failures, evictions, capacity
  waits and size.
- `Kms.connectionStats()`: for each endpoint, open, idle and in-use connections, connections
  opened, and pool waits and their time. An endpoint that does not use the SDK's TLS transport
  reports `measured()` false.

What the lifecycle events mean is in
[Key lifecycle](operating-keys.md#several-instances).

## What each consumer's credential needs

Give each KMS identity only the operations its job sends. The table lists the operations the
SDK's calls for each job send on KMIP 1.4, 2.1 and 3.0, against a server that leases. The server's
own access policy still decides which objects each identity reaches.

| Consumer | Operations |
|---|---|
| A node's `LocalKeys` (SSTable, commit log and hints keys) | Discover Versions, Locate, Get Attributes, Get, Obtain Lease |
| A node that seals and opens with `CurrentKey` (envelope encryption) | Discover Versions, Locate, Get Attributes, Encrypt, Decrypt |
| An application that reads a secret | Discover Versions, Locate, Get Attributes, Get, Obtain Lease |
| A node's TLS followers (`follow`, `trustAnchors`) | Discover Versions, Locate, Get Attributes, Get, Obtain Lease |
| The place that issues TLS identities (`register`, `renew`, `rekey`, `revoke`) | Discover Versions, Register, Activate, Add Attribute, Delete Attribute, Locate, Get Attributes, Get, Obtain Lease, Revoke, Deactivate |
| The place that registers an issuing CA (`registerIssuer`) | Discover Versions, Register, Activate, Add Attribute, Delete Attribute, Locate, Get Attributes, Get, Obtain Lease |
| The place that issues TLS identities from the KMS (`issue`, `reissue`, `reissueWithNewKey`) | Discover Versions, Create Key Pair, Certify, Activate, Add Attribute, Delete Attribute, Locate, Get Attributes, Get, Obtain Lease, Revoke, Deactivate |
| The rotation job (run from one place) | Discover Versions, Locate, Get Attributes, Re-key, Activate, Add Attribute, Modify Attribute, Delete Attribute, Revoke, Deactivate, Destroy |
| An operator that provisions keys (`findOrCreate`) | Discover Versions, Locate, Get Attributes, Create, Activate |
| An operator that moves a write name (`moveName`) | Discover Versions, Get Attributes, Add Attribute, Delete Attribute |

- Raw-key consumers (`LocalKeys`, the TLS followers, secret readers) need Get, because the key
  leaves the KMS. They never need Create, Re-key, Revoke or Destroy.
- Envelope consumers need Encrypt and Decrypt on the key-encryption key, and never Get. Create
  that key non-extractable ([Envelope encryption](envelope-encryption.md)).
- So an identity with Get but no Encrypt cannot seal, and one with Encrypt and Decrypt but no Get
  cannot read raw keys.
- The job that issues TLS identities from the KMS gets the new private key once, to sign the
  certificate request. On keytend-kmip-server it must also own the issuing CA's certificate and
  both CA keys, because Certify does not count grants: register the issuer with the same
  credentials. The nodes that follow issued identities still need only the reads of their row.
- The rotation job sends Activate only when the server leaves a replacement Pre-Active. Add
  Attribute and Modify Attribute set a Deactivation Date, for a grace period (`Rotation.grace`)
  or `deactivateAt`. `reconcile` moves names with Add Attribute and Delete Attribute.
  `replaceCompromised` can also need Create and attribute changes where the server refuses
  Re-key. Its Javadoc describes those steps.
- Obtain Lease is sent only for objects whose attributes state a KMIP Lease Time. Under
  `LeasePolicy.HONOR_IF_SUPPORTED`, a server that does not implement Obtain Lease is also asked
  Query once per `Kms`, so that server's credentials need Query too.
- Deactivate is the KMIP 3.0 draft's operation. On 1.x and 2.x the SDK sends Revoke with a
  reason other than a compromise instead.
- Discover Versions negotiates the protocol version, and checks each endpoint before its first
  request.

## Qualifying a server

The SDK's tests show that it speaks each KMIP version correctly. They do not show that your
server, its version and its policy do what your application needs. Check these on that server,
with the identities the application will use, before production. Never qualify with
`InMemoryKmipServer` (`keytend-kmip-testing`). It is the in-memory test server and never belongs on
a production class path.

- [ ] **Operations**: the calls you use, with your algorithms, sizes and modes. AES-GCM and
  sealing need KMIP 1.4.
- [ ] **Names**: whether the server enforces unique names
  ([Startup on several instances](operating-keys.md#startup-on-several-instances)).
- [ ] **Rotation**: Re-key of your keys, the Replacement and Replaced Object links, and a
  client-set Deactivation Date for `Rotation.grace` and `deactivateAt`.
- [ ] **Old records**: Re-key copies the custom attribute you bind them to, and only your
  identity may set it ([Records older than 64
  rotations](operating-keys.md#records-older-than-64-rotations)).
- [ ] **Historical reads**: decrypting with a Deactivated key, with the application's identity
  ([Deactivated keys](operating-keys.md#deactivated-keys-and-the-servers-policy)).
- [ ] **Retirement and compromise**: `deactivate()`, `replaceCompromised`, and the server's
  answers to a repeated request. Its reasons show in `serverReason()`.
- [ ] **Durability**: keys you created and keys the server generated still work after a server
  restart, with their attributes and links.
- [ ] **Access control**: each identity can do its row of the table above and no more. A Get of a
  key created with `extractable(false)` is refused.
- [ ] **Extractable and Sensitive**: the server keeps them on Create, Register and Re-key, and
  states them in Get Attributes.
- [ ] **Leases**: whether the server sets a Lease Time, grants leases for Deactivated keys, and
  implements Obtain Lease at all ([Leases](local-keys.md#leases)).
- [ ] **Replicas**: every endpoint given to one `Kms` serves the same keys.

Tools that help:

- [The server probe](../tools/server-probe/README.md) runs the key lifecycle against a live
  server and reports each observation as `PASS`, `FAIL` or `INFO`.
- [Validation](validation.md) has the results for the servers already tested, and
  [how to run the tests](validation.md#running-the-tests) against your own.
