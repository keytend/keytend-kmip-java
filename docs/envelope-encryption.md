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

# Envelope encryption

Envelope encryption keeps the key-encryption key (KEK) in the KMS. The SDK encrypts your data
locally with AES-256-GCM under a fresh data key. The KMS wraps that data key with the KEK. The
sealed result holds both, so you store one value.

This page covers records, streams, files and random-access files, then encryption on the server
and the limits of AES-GCM. It assumes a connected `Kms` and a KEK created with `findOrCreate`
([Getting started](getting-started.md#find-or-create-a-key)). The byte layouts are in
[Stored formats](stored-formats.md).

The calls on this page use AES-GCM, which needs KMIP 1.4 or later. The KEK needs both the
Encrypt and Decrypt usages. A key without Decrypt is refused before anything is sent, because
it could seal data that nobody can open.

## Seal and open records

Seal through the KEK's `CurrentKey`. It seals under the key in force and follows rotations
made by other instances ([Several instances](operating-keys.md#several-instances)). Make one at
startup and share it.

```java
CurrentKey current = kms.keys().current("orders-kek");      // once, at startup
byte[] orderJson = "{\"total\":42}".getBytes(StandardCharsets.UTF_8);
byte[] orderId = "order-1042".getBytes(StandardCharsets.UTF_8);

byte[] sealed = current.seal(orderJson, orderId);           // one request, whatever the size
byte[] opened = current.open(sealed, orderId);              // two requests
```

- `orderId` is additional data, bound to the sealed record. Opening needs the same bytes, so a
  record copied under another identity fails to open. Pass `null` for none.
- `seal` sends one Encrypt. `open` sends Get Attributes and Decrypt, plus one request per rotation
  since the record was sealed.
- `open` works through every key of the KEK's [lineage](kms-design.md#lineage-and-rotation), so
  records sealed before a rotation keep opening. To move them to the new key, see
  [Move data to the new key](operating-keys.md#move-data-to-the-new-key).
- `KmsKeys.sealedKeyId(sealed)` names the key a sealed record needs, without a request. Use it to
  find the records under a [compromised key](operating-keys.md#a-compromised-key).

## Stream large data

For data too large for memory, seal a stream. The data is sealed in 64 KiB chunks under one
data key, so the costs stay one request to seal and two to open.

`sealing` writes to any `OutputStream`, such as an upload. When the KEK is refused because
another instance rotated it, `sealing` follows the newer key and starts again under it, as `seal`
does. Nothing is written to the output before the KEK has wrapped the data key, so the stream you
get is always under one key.

In this example, `upload` is your destination: `start()` returns an `OutputStream` and
`commit()` keeps what was written. `source` is an `InputStream`.

```java
byte[] backupId = "backup-2026-11-04".getBytes(StandardCharsets.UTF_8);
try (SealingStream out = current.sealing(upload.start(), backupId)) {
  source.transferTo(out);
  out.finish();                    // writes the end; without it the output cannot be opened
}
upload.commit();                   // keep the output only now
```

Read it back with `opening`, which works through the KEK's lineage. Here the upload above was
saved as the file `backup-2026-11-04.sealed`:

```java
byte[] backupId = "backup-2026-11-04".getBytes(StandardCharsets.UTF_8);
InputStream sealedIn = Files.newInputStream(Path.of("backup-2026-11-04.sealed"));
try (InputStream plain = current.opening(sealedIn, backupId)) {
  Files.copy(plain, Path.of("backup.staged"));      // a staging place, not the final one
}
```

- Only `finish()` ends the data. If the source fails part-way, `close()` writes no end and
  throws. The output then fails to open, instead of opening as a shorter stream.
- Only the end of the stream proves the data complete. A read that fails part-way has already
  returned an authentic but incomplete prefix. Write to a staging place and keep the result only
  after the end of the stream.
- Closing the returned stream closes the one you passed in. `sealing` and `opening` also close it
  when they throw, for example for a refused key with no newer key to follow.

## Seal and open files

To seal into a file, use `sealTo` and `openTo`. They stage the output and replace the target
only once it is complete. The target's directory must exist, so the example creates it.

```java
Path export = Path.of("orders-export.json");
Path backup = Path.of("backups/orders.sealed");
Path restored = Path.of("restore/orders-export.json");
byte[] backupId = "orders-export-2026-11-04".getBytes(StandardCharsets.UTF_8);
Files.createDirectories(backup.getParent());
Files.createDirectories(restored.getParent());

try (InputStream in = Files.newInputStream(export)) {
  current.sealTo(backup, in, backupId);      // reads to the end; does not close the stream
}
current.openTo(backup, restored, backupId);  // restored appears only once all of it verified
```

Both calls write a temporary file next to the target, named `.<name>.<random>.partial`. It is
readable by its owner only, where the file system has POSIX permissions. Once complete, it is
moved onto the target atomically.

- A failure before the move leaves the old target as it was and deletes the temporary file. A
  refused key creates no file at all. A file system that cannot move atomically fails the call
  instead of copying.
- A failure to force the directory comes after the move. The call throws a
  `FileSystemException` that says the target was replaced. The new file is in place, but a crash
  may still undo the move. Keep the source.

> [!WARNING]
> `openTo` writes plaintext to disk: the target, and the temporary file while it runs. Owner-only
> permissions are not encryption at rest. Where plaintext must not reach the disk, use `opening`
> into memory or into your own encrypted storage.

By default (`FileDurability.DURABLE`) the directory is forced after the move. So
once the call returns, the new file is the target after a crash too, as far as the platform's
fsync goes. On Windows, and where a directory cannot be opened, that step is skipped. Keep this
order:

1. `sealTo` returns.
2. Record what you need to open the file, such as its name in a manifest and its additional
   data. Make that record durable.
3. Only then delete or overwrite the source.

When writing many files to one directory, pass `FileDurability.CONTENT_ONLY` to each call. Then
force the directory once at the end, before step 3.

A crash during a call can leave a temporary file behind. At startup, while
nothing writes to the directory, delete the files whose names start with `.` and end in
`.partial`. The target's name in them is cut to 32 characters.

## Seal files chunk by chunk

A storage engine that reads its files block by block, at any offset, seals each block on its
own. In this example, `store` is your file storage, `n` is the number of blocks, and `block(i)`
returns block `i`'s bytes.

```java
byte[] fileId = "sstable-nb-42-big".getBytes(StandardCharsets.UTF_8); // names this file only
try (ChunkedSealer sealer = current.chunkedSealer(fileId)) {           // one request
  store.writeHeader(sealer.header());                                  // once per file
  for (int i = 0; i < n; i++) {
    byte[] chunk = i == n - 1 ? sealer.sealFinal(i, block(i)) : sealer.seal(i, block(i));
    store.writeChunk(i, chunk);
  }
}
try (ChunkedOpener opener = current.chunkedOpener(store.readHeader(), fileId)) { // two requests
  byte[] block7 = opener.open(7, store.readChunk(7));                       // none per chunk
  opener.openFinal(n - 1, store.readChunk(n - 1));                          // proves n chunks
}
```

- Use one sealer per file and seal each index once. A sealer refuses to seal an index twice.
  Nothing can seal under a stored header. To change a block, write the file again with a new
  sealer, as compaction does.
- A sealed chunk is its plaintext plus 16 bytes. A chunk holds at most 1 MiB of plaintext, and a
  file at most 2^32 chunks.
- Opening a block proves that block, not the whole file. Seal the last block with `sealFinal`
  and open it with `openFinal` where a cut file must be detected. Otherwise keep the number of
  blocks somewhere it cannot be changed.
- The sealer and the opener hold the file's chunk key. Close the sealer when the file is written
  and the opener when the file is closed. Keep one opener per open file, because each costs two
  requests. Both are thread-safe.
- An opener works through the KEK's lineage after a rotation. You can also open by name, with
  `kms.keys().chunkedOpener(KeyQuery.byName("sstables-kek"), header, fileId)`.

After a rotation, rewrite only the headers. The chunks do not depend on how the data key is
wrapped, so moving a file to the new key rewrites only its header:

```java
byte[] header = store.readHeader();
byte[] moved = current.rewrapHeader(header, fileId); // no request if already moved
if (moved != header) {
  store.replaceHeader(moved);                        // atomically: a new file, then a rename
}
```

`rewrapHeader` sends three requests, plus one per rotation crossed. Until the new header is
stored, the old one still opens through the old key. Replace each header atomically. Retire the
old key only once every header names the new one
([Retire old keys](operating-keys.md#retire-old-keys)).

After a compromise, rewriting headers is not enough. The data key itself must be taken as
exposed, so seal the data again with a new sealer.

The format and its reasoning are in
[Chunked files (KTR)](stored-formats.md#chunked-files-ktr).

## Encrypt on the server

These calls send the data or the key to the KMS, which encrypts it with a key that never leaves
the server. They are advanced. For records and files, `seal` is simpler and costs one request
whatever the size ([The advanced alternatives](choosing-an-api.md#the-advanced-alternatives)).

### Encrypt and decrypt small values

The KMS encrypts every byte, so keep this for small values such as a token or a password.

```java
KeyHandle kek = kms.keys().createAes(256).named("invoices-kek")
    .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).findOrCreate();
byte[] cardToken = "tok_4242".getBytes(StandardCharsets.UTF_8);
byte[] invoiceId = "invoice-7731".getBytes(StandardCharsets.UTF_8);

byte[] stored = kek.encrypt(CipherSpec.aesGcm(), cardToken, invoiceId).toBytes();
byte[] back = kek.decrypt(Ciphertext.fromBytes(stored), invoiceId);
```

The stored `Ciphertext` binds its key identifier and cipher into the authenticated data. A
modified or relabeled ciphertext fails instead of choosing another key or mode. `kek.decrypt`
also decrypts what other keys of its rotation lineage encrypted.

You can also decrypt by a query, `kms.keys().decrypt(KeyQuery.byName("invoices-kek"), ...)`. A
name is not an access-control boundary, so prefer the handle
([Key names are not access control](getting-started.md#key-names-are-not-access-control)).

### Wrap keys and make data keys

To build an envelope format of your own, let the KMS wrap your data keys. `generateDataKey`
creates an AES key locally and returns it with its wrapped form, in one Encrypt.

```java
CurrentKey current = kms.keys().current("invoices-kek");
byte[] invoiceId = "invoice-7731".getBytes(StandardCharsets.UTF_8);
byte[] wrapped;
try (DataKey dataKey = current.generateDataKey(256, invoiceId)) {
  wrapped = dataKey.wrapped().toBytes();       // store this next to the data
  SecretKey forCipher = dataKey.key();         // encrypt locally; destroyed on close
}
DestroyableSecretKey again =
    current.unwrapKey(Expect.aes(256), Ciphertext.fromBytes(wrapped), invoiceId);
```

- `current.wrapKey(secretKey, aad)` wraps a key you already have, with AES-GCM. It does not
  destroy `secretKey`.
- `unwrapKey` works through the KEK's lineage. Destroy the key it returns when you are done.
- `current.rewrapKey(wrapped, aad)` moves a wrapped key to the current KEK after a rotation,
  without the key leaving the SDK.

### Keys that never leave the KMS

`seal`, `wrapKey`, `generateDataKey` and the other server-side operations never retrieve the
KEK. That is not a policy, though. Any identity allowed to Get the key could read it. From KMIP
1.4, create it non-extractable, and the server itself refuses to return its value.

```java
KeyHandle kek = kms.keys().createAes(256).named("orders-kek")
    .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
    .extractable(false)                          // KMIP 1.4 and later
    .findOrCreate();
Optional<Boolean> extractable = kek.attributes().extractable();  // Optional[false]
```

`extractable(boolean)` and `sensitive(boolean)` are on `KeyCreation`, `KeyRegistration` and
`Rotation`. The SDK checks that each requested protection is applied:

- Below KMIP 1.4 neither attribute exists. A request for one is refused with
  `UnsupportedException` before anything is sent. Use the server's access control instead.
- A new key is read back before it is activated. If the server did not apply the attribute, the
  key stays Pre-Active and the call throws `PartialCompletionException`.
- `findOrCreate` refuses an existing key that states another value, or states none
  (`KeyMismatchException`). An absent attribute is unknown, not extractable.
- A rotation keeps the protection. The replacement is checked to state Extractable false and
  Sensitive true where the old key does.

On KMIP 1.4 to 2.1, a client allowed to modify a key can set Extractable back to true. Grant
attribute changes on such keys narrowly.

A key that a database uses to encrypt its own files is the opposite case. It must be extractable
([Keys taken out of the KMS](local-keys.md#keys-taken-out-of-the-kms)).

## Limits of AES-GCM per key

Every AES-GCM encryption with a server key uses a fresh random 96-bit nonce. With random nonces,
NIST SP 800-38D §8.3 allows at most **2^32 encryptions per key, in total**. That total covers
every instance and node that uses the key, retries included.

These calls count against the KEK:

- each `encrypt(CipherSpec.aesGcm(), ...)`;
- each `seal`, `sealing` and `sealTo` (one Encrypt wraps the data key, whatever the data's size);
- each `wrapKey` and `generateDataKey` with AES-GCM;
- each rewrap that writes under the KEK with AES-GCM: `rewrapRecord`, the `...To` forms on their
  target, and `rewrapKey` of a key wrapped with AES-GCM;
- each `chunkedSealer`, and each `rewrapHeader` that moves a header to the KEK.

The data itself does not count against the KEK. `seal` encrypts it once under a fresh data key. A
sealed stream uses a fresh data key with a counter nonce per 64 KiB chunk, up to 2^32 chunks. A
chunked file's chunks are under the file's own data key, up to 2^32 chunks a file.

Rotate the KEK well before its count reaches 2^32:

- Count the operations above in your application. As an upper bound, count every attempt
  `KmsListener.started` reports for the KEK. That includes reads and decryptions, and a failed
  attempt may still have encrypted.
- Plan rotation at half the limit or less, which leaves room for miscounting
  ([Rotate on a schedule](operating-keys.md#rotate-on-a-schedule)).
- Where the server supports the Usage Limits attribute, it can enforce a limit too.
