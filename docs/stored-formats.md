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

# Stored formats

The SDK writes four binary formats that applications store. This page gives
their byte layouts, what each one authenticates, its limits and why it is
sound. It is for people who decode the data with other software, check
compatibility, or review the cryptography.

To use the formats, read [Envelope encryption](envelope-encryption.md). The
readability promise is in [Compatibility](compatibility.md#stored-formats).

- [The four formats](#the-four-formats)
- [Rules every format follows](#rules-every-format-follows)
- [Server-side ciphertexts (KTC)](#server-side-ciphertexts-ktc)
- [Sealed records (KTE)](#sealed-records-kte)
- [Sealed streams (KTS)](#sealed-streams-kts)
- [Chunked files (KTR)](#chunked-files-ktr)
- [Finding the key without the server](#finding-the-key-without-the-server)
- [How the formats evolve](#how-the-formats-evolve)

## The four formats

| Types | Format | Magic | Holds |
|---|---|---|---|
| `Ciphertext` | KTC 1 | `KTC` | the result of one encryption on the server |
| `CurrentKey.seal`, `open` | KTE 1 | `KTE` | one record, encrypted locally under a fresh data key |
| `SealingStream`, `opening` | KTS 1 | `KTS` | one stream, in chunks read in order |
| `ChunkedSealer`, `ChunkedOpener` | KTR 1 | `KTR` | a file header; its chunks are stored by the caller |

The code is in `Ciphertext`, `Envelopes` (KTE), `StreamEnvelopes` (KTS) and
`ChunkedEnvelopes` (KTR), all in `dev.keytend.kmip.kms`.

## Rules every format follows

- Every length is unsigned big-endian.
- Byte 3 is the format version. Every format is at version `0x01`.
- Parsing is strict. Wrong magic, an unknown version, a bad length or trailing
  bytes is a `CryptographicFailureException` of kind `INVALID_CIPHERTEXT`.
- Data that parses but fails the SDK's own check, a tag or the key commitment,
  is kind `AUTHENTICATION_FAILED`.
- KTE, KTS and KTR encrypt locally with AES-256-GCM under a fresh 256-bit data
  key. The key-encryption key (KEK) wraps the data key on the server with
  AES-GCM, through KMIP Encrypt. The wrapped key is stored as a KTC ciphertext.
- For KTE, KTS and KTR, the data key is unwrapped on the server before the SDK's
  own check. When the server refuses the unwrap with Cryptographic Failure, the
  kind is also `AUTHENTICATION_FAILED`. Invalid Field or General Failure gives
  kind `UNCONFIRMED`, category `SERVER`. The data is then not verified, but that
  answer does not prove tampering. Any other server failure is reported as
  usual, for example `NotFoundException` or `PermissionDeniedException`
  ([Handle failures](getting-started.md#handle-failures)).
- Wrapping with AES-GCM needs KMIP 1.4 or later. Before 1.4, sealing and
  opening throw `UnsupportedException`. There is no fallback wrapping.
- "Authentic" means sealed by someone allowed to use the KEK for Encrypt with
  the same additional data.

## Server-side ciphertexts (KTC)

`Ciphertext.toBytes()` writes this format and `Ciphertext.fromBytes` reads it.

```text
offset  size  field
0       3     magic "KTC" (0x4B 0x54 0x43)
3       1     format version 0x01
4       2     key-identifier length n (1..65535)
6       n     key identifier (UTF-8)
6+n     1     spec-name length m (1..255)
7+n     m     spec name (printable ASCII, 0x21..0x7E), e.g. AES-GCM-16
              -- the header ends here --
        1     IV length i (0..255), then i IV bytes
        1     tag length t (0..255), then t tag bytes
        4     data length d, then d data bytes; nothing may follow
```

An absent IV or tag has length 0. `Ciphertext.header()` returns the header
bytes.

### What KTC authenticates

For AEAD specs the SDK sends `header || aad` to the server as the KMIP
Authenticated Encryption Additional Data. Changing the stored key identifier or
spec name therefore fails the tag check.

Other software can decrypt KTC with the key:

- **AES-GCM:** decrypt `data || tag` with the stored IV and the additional data
  `header || aad`.
- **RSA-OAEP from KMIP 1.4:** `header || aad` is the OAEP label (P Source). The
  stored spec name ends in `-BOUND`, for example
  `RSA-OAEP-SHA-256-MGF1-SHA-256-BOUND`. In JCA, use
  `OAEPParameterSpec(..., new PSource.PSpecified(header || aad))`.

Before KMIP 1.4 no OAEP label can be sent. Additional data is then refused, and
a `-BOUND` ciphertext cannot be decrypted on such a connection. From 1.4 the
spec name states both the OAEP hash and the MGF1 hash. Before 1.4 only an MGF1
hash of SHA-1 is accepted.

### Which spec decrypts

The stored spec name never chooses the mode by itself. Decryption takes the spec
from the ciphertext only for AES-GCM and AES key wrap. Only a holder of the
symmetric key can make a valid ciphertext in those specs.

RSA-OAEP, CBC, CTR and custom specs need the caller to name the expected spec.
The stored name must then be that spec's, and the IV and tag lengths must fit
it. Additional data with a spec that cannot authenticate it is an
`IllegalArgumentException`.

RSA-OAEP is never chosen from the record, because anyone with the public key can
encrypt. An attacker who can write a stored RSA-wrapped data key could
substitute their own, if they know the record's additional data. Where the
origin of a wrapped key matters, wrap it with a symmetric KEK or sign it. The
binding also relies on the server applying P Source, which the SDK cannot
check.

## Sealed records (KTE)

`CurrentKey.seal(plaintext, aad)` writes one container. `open` on a
`CurrentKey`, a `KeyHandle` or `KmsKeys` reads it.

```text
offset  size  field
0       3     magic "KTE"
3       1     format version 0x01
4       2     wrapped-key length w (1..65535)
6       w     the wrapped data key: a KTC ciphertext, AES-GCM by the KEK
6+w     1     nonce length (12)
7+w     12    nonce                              -- the prefix ends here
19+w    4     data length d (at least 16)
23+w    d     AES-GCM ciphertext followed by the 16-byte tag; nothing may follow
```

- The local AES-GCM additional data is the prefix (bytes 0 to 19+w) followed
  by the caller's `aad`. The wrapped key binds `aad` on the server as well.
- Neither the data key nor the data can therefore be moved to another record
  or container.
- `open` parses strictly, then unwraps the data key with the key-choice and
  state rules of `unwrapKey`. It checks that the data key is 256-bit AES,
  decrypts locally, and destroys the data key.
- The whole record is in memory. Use KTS for large data.

## Sealed streams (KTS)

`CurrentKey.sealing(out, aad)`, `CurrentKey.sealTo` and `KeyHandle.sealing(out, aad)`
write a stream. `opening` and `openTo` read it.

KTS is the STREAM construction of Hoang, Reyhanitabar, Rogaway and Vizár
("Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance",
CRYPTO 2015), as in Tink's streaming AEAD. It runs over AES-256-GCM under a
fresh data key per stream.

```text
offset  size  field
0       3     magic "KTS"
3       1     format version 0x01
4       2     wrapped-key length w (1..65535)
6       w     the wrapped data key: a KTC ciphertext, AES-GCM by the KEK, binding aad
6+w     4     chunk size c: plaintext bytes per chunk
              (the writer uses 65536; a reader accepts 4096..1048576)
10+w    7     nonce prefix (random)             -- the header ends here (h = 17+w bytes)
h       ...   chunks 0, 1, ..., n-1: each is the AES-GCM ciphertext of its plaintext
              followed by its 16-byte tag
```

Each chunk is sealed like this:

```text
chunk i
  nonce (12):      the nonce prefix (7) || i as u32 big-endian (4)
                   || 0x01 for the last chunk, else 0x00 (1)
  additional data: the whole header (bytes 0 to h) || the caller's aad (none when null)
```

### Chunks and ends

- Every chunk but the last holds exactly c plaintext bytes, so c+16 bytes are
  stored.
- The last chunk holds 0 to c bytes. It is empty only when it is chunk 0, for an
  empty plaintext.
- The writer emits a full chunk only when more data follows. A plaintext of k·c
  bytes therefore ends with a full last chunk.
- Nothing follows the last chunk. There is no length field.
- The reader decides which chunk is last from where the input ends, never from
  the data. It reads c+16 bytes and one more. If that byte exists, the chunk is
  not the last.

### KTS limits

- **Chunks.** At most 2^32 chunks, because the counter is 32 bits. That is
  256 TiB at the writer's 64 KiB. A longer write throws `IOException`, and a
  reader refuses a longer stream.
- **Chunk size.** A reader refuses a chunk size outside 4 KiB to 1 MiB before it
  contacts the server. The upper bound caps what a hostile header can make it
  allocate. The lower bound keeps the per-chunk overhead small.
- **Writer.** The writer always uses 64 KiB. The accepted range lets a later
  release change that without a new format version.
- **Header.** w is at most 65535, so the header is at most 65552 bytes.

### KTS failures

These are `INVALID_CIPHERTEXT`, because the stream is malformed:

- anything wrong with the header;
- a stream that ends right after its header;
- a last chunk shorter than a tag;
- an empty last chunk after a full one;
- more than 2^32 chunks.

Every other failure after the header that the SDK detects itself is
`AUTHENTICATION_FAILED`. That covers a cut, an extension, a dropped, repeated or
moved chunk, a chunk from another stream, other additional data, and a changed
header field that still parses. Other additional data and a changed wrapped key
usually fail earlier, when the server refuses to unwrap the data key. That
refusal is `AUTHENTICATION_FAILED` only when the server answers Cryptographic
Failure, and `UNCONFIRMED` for Invalid Field or General Failure, as above.

A reader of a failed stream has seen the plaintext of the chunks before the
failing one. That plaintext is authentic and in order, but may not be all of it.
Only reaching the end (`read` returning -1) proves the data complete.

### Why KTS is sound

Each chunk is AES-GCM under a key used for one stream only. Its nonce is unique
within the stream, so GCM's nonce-respecting security applies to every chunk.
STREAM's proof then gives these properties:

- **Reordering.** A moved, dropped or repeated chunk is decrypted with another
  counter, and fails.
- **Truncation.** The reader decrypts the new last chunk with the final flag.
  The writer used 0x00 for it, so it fails. A cut inside a chunk changes its
  bytes.
- **Extension.** Anything after the true last chunk makes the reader decrypt
  that chunk as not the last, or with extra bytes. It fails.
- **Splicing.** Every stream has its own data key, prefix and wrapped key. A
  chunk from another stream does not verify, even under the same KEK and `aad`.
- **Header substitution.** The whole header is in every chunk's additional data.
  Changing any field fails, even another wrapping of the same data key.
- **Unambiguous input.** The header length follows from w, so `header || aad`
  has one reading.

The caller's `aad` is bound twice: by the server to the wrapped key, and locally
to every chunk. A stream stays far inside the GCM limits. It has at most 1 MiB
per chunk and 2^32 chunks, with unique deterministic nonces under a one-stream
key.

## Chunked files (KTR)

KTR is for storage engines that read blocks at any offset. A file's chunks are
sealed and opened one at a time, by index, in any order.

- `CurrentKey.chunkedSealer(fileId)` returns a `ChunkedSealer`.
- `chunkedOpener(header, fileId)` on a `CurrentKey`, a `KeyHandle` or `KmsKeys`
  (with a query) returns a `ChunkedOpener`.
- `CurrentKey.rewrapHeader(header, fileId)` moves a file to a newer KEK by
  rewriting its header only.

The header is stored once per file:

```text
offset  size  field
0       3     magic "KTR"
3       1     format version 0x01
4       8     nonce prefix (random)
12      32    key commitment: HKDF-SHA256-Expand(data key, "keytend-kmip KTR 1 key commitment", 32)
                                                -- the core ends here (44 bytes)
44      2     wrapped-key length w (1..65535)
46      w     the wrapped data key: a KTC ciphertext, AES-GCM by the KEK, whose
              additional data is the core (bytes 0..44) followed by the file id;
              nothing may follow
```

The caller stores each chunk on its own. The SDK does not frame or place chunks.

```text
chunk i = AES-256-GCM ciphertext of the chunk's plaintext, followed by its 16-byte tag
  key:             HKDF-SHA256-Expand(data key, "keytend-kmip KTR 1 chunk key", 32)
  nonce (12):      the nonce prefix (8) || i as u32 big-endian (4)
  additional data: the core (44) || flags (1: 0x01 for the final chunk, else 0x00)
                   || i as u32 big-endian (4) || the file id
```

HKDF-Expand is RFC 5869 §2.3 with the data key as the pseudorandom key. The data
key is uniformly random, so Extract is skipped, as §3.3 allows. The result is
one HMAC-SHA256 block: `HMAC(data key, info || 0x01)`.

A sealed chunk is exactly 16 bytes longer than its plaintext. The file id is not
stored. The caller gives it to both sides, like the additional data of `seal`.

### Key commitment

The wrapped key is not in the chunks' additional data. A header could therefore
carry another data key, wrapped by someone allowed to use the KEK with the same
additional data. So `chunkedOpener` and `rewrapHeader` derive the commitment
from the unwrapped key. They compare it with the header's in constant time,
before an opener is made or anything is wrapped. A mismatch is
`AUTHENTICATION_FAILED`. The commitment also binds the header to its data key,
which AES-GCM alone does not.

### Rewrapping without touching the data

The chunks depend on the data key and the core, never on the wrapped key.
`rewrapHeader` unwraps the data key with the handle's key-choice rules and checks
it against the commitment. It wraps it under the current key with the same
additional data, and returns the core followed by the new wrapped key.

- A header already under the current key is returned unchanged, without a
  request. It is not authenticated then.
- The new header's length follows the new key identifier's.
- Rewrapping is for routine rotation. The data key stays the same, so after a
  compromise of a key that wrapped it, seal the data again with a new sealer.

### Each index once

The nonce is fixed by the index, so a sealer seals each index at most once:

- It claims the index (one bit, under its lock) before sealing and never
  releases it, even if sealing then fails. A second seal of the index is an
  `IllegalStateException`.
- A data key exists only inside the sealer that generated it. Nothing makes a
  sealer from a stored header, and an opener has no method that seals.

So no nonce is ever used twice under one key. Each (file, index) pair also has
exactly one authentic chunk, so a chunk cannot be rolled back to an older
version.

Random per-chunk nonces were not chosen. They would add 12 bytes to every chunk,
and storage engines expect plaintext plus tag. Their only gain, sealing an index
twice, is what the rule above refuses anyway. The random prefix is defense in
depth.

### KTR limits

- **Indices.** 0 to 2^32 − 1. An index outside that range is an
  `IllegalArgumentException`.
- **Chunk size.** At most 1 MiB of plaintext a chunk. A larger one is an
  `IllegalArgumentException`.
- **Per data key.** At most 2^32 chunks and 4 PiB (2^48 AES blocks). AES-GCM's
  bound with unique nonces stays below 2^-33 there.
- **Memory.** The claims take one bit per index, in pages of 4096 bits. A
  million chunks take about 128 KiB.

### The end of a file

Opening a chunk by its index proves the chunk, not the file. A file cut after a
chunk, or with chunks missing, still opens chunk by chunk.

- `sealFinal(i, ...)` seals the final chunk with the flag set. After it, no
  later index can be sealed.
- A final chunk below an index already sealed is refused, and so is a second
  final chunk.
- `openFinal(i, chunk)` opens only a chunk sealed that way. It proves the file
  has exactly i + 1 chunks, so it detects a cut or an extension.
- `open` accepts either flag. It tries a non-final chunk first, so only the
  final chunk costs two tries.

Without a final chunk, the caller must keep the number of chunks authentic.

### KTR failures

Failures to open a chunk report the operation `open`. Header failures report
the method that read the header, `chunkedOpener` or `rewrapHeader`.
`KmsKeys.chunkedHeaderKeyId` reports a malformed header as `open`.

- `INVALID_CIPHERTEXT`: a malformed header (magic, version, lengths, trailing
  bytes, a malformed wrapped key). Also a chunk shorter than a tag or longer
  than 1 MiB + 16 bytes.
- A header whose core changed, or another file id: the server refuses to unwrap
  the data key in both cases. That is `AUTHENTICATION_FAILED` when the server
  answers Cryptographic Failure, and `UNCONFIRMED` (category `SERVER`) when it
  answers Invalid Field or General Failure.
- `AUTHENTICATION_FAILED`: a commitment that does not match.
- `AUTHENTICATION_FAILED`: every chunk that does not verify. That is a changed or
  cut chunk, another index's or another file's chunk, or a non-final chunk
  opened with `openFinal`.

### Why KTR is sound

Each chunk is AES-GCM under a key used for one file only, with a nonce unique
within it. GCM's nonce-respecting security applies to every chunk.

- **Reordering or swapping.** A chunk opened at another index uses another nonce
  and additional data. It fails.
- **Splicing between files.** Every file has its own data key and core. Another
  file's chunk fails, even under the same KEK and file id.
- **Another file id.** The server refuses to unwrap the data key, and every
  chunk binds the file id as well.
- **Header substitution.** The core is in the wrap's additional data and in
  every chunk's. The wrap ties the wrapped key to the core, and the commitment
  ties it to the chunks.
- **A cut file.** `openFinal` detects it, as above.

## Finding the key without the server

Each format names its KEK in the clear. These static methods read it without a
request, for example to recover after a compromise:

| Format | Method |
|---|---|
| KTE | `KmsKeys.sealedKeyId(sealed)` |
| KTS | `KmsKeys.sealedStreamKeyId(in)` (reads the header only and leaves `in` open) |
| KTR | `KmsKeys.chunkedHeaderKeyId(header)` |

A KTC ciphertext names its key in `Ciphertext.keyId()`. The identifier a record
names was chosen by whoever made the record. Never trust it alone to choose a
key. The recovery procedure is in
[Key lifecycle](operating-keys.md#a-compromised-key).

## How the formats evolve

Data that 0.10.0 or any later release writes stays readable by every later release,
majors included. [Compatibility](compatibility.md#stored-formats) states that
promise and the rules for new format versions. Where a field has a range, such
as the KTS chunk size, a later writer may choose another value in that range
without a new version.
