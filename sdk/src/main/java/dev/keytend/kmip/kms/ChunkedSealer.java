/*
 * Copyright 2026 Jeremiah Jordan
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package dev.keytend.kmip.kms;

import java.util.Objects;

/**
 * Seals one file's chunks for random access. Get one from {@link CurrentKey#chunkedSealer}. Each
 * chunk is sealed on its own with AES-256-GCM under the file's data key, and bound to its index, to
 * the file identifier and to the {@linkplain #header() header}. Store the header once per file. It
 * holds the data key, wrapped by the key-encryption key. Open the chunks later with {@link
 * KeyHandle#chunkedOpener} or {@link KmsKeys#chunkedOpener}. See <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/stored-formats.md#chunked-files-ktr">
 * Chunked files (KTR)</a>.
 *
 * <pre>{@code
 * byte[] fileId = "sstable-nb-42-big".getBytes(StandardCharsets.UTF_8);
 * try (ChunkedSealer sealer = kek.chunkedSealer(fileId)) {
 *   store.writeHeader(sealer.header());
 *   for (int i = 0; i < chunks.size(); i++) {
 *     boolean last = i == chunks.size() - 1;
 *     store.writeChunk(i, last ? sealer.sealFinal(i, chunks.get(i)) : sealer.seal(i, chunks.get(i)));
 *   }
 * }
 * }</pre>
 *
 * <p><b>Each index once.</b> A chunk's nonce is fixed by its index, so this sealer seals each index
 * at most once and refuses a second seal ({@link IllegalStateException}), even after the first
 * failed. A sealer exists only with a new data key and a new header: nothing makes a sealer from a
 * stored header, and an opener never seals. To change a chunk, seal the file again with a new
 * sealer. Indices may be sealed in any order.
 *
 * <p><b>Limits.</b> Indices are 0 to 2^32 - 1, and a chunk holds at most 1 MiB (1,048,576 bytes)
 * of plaintext. So one data key seals at most 2^32 chunks and 4 PiB. More is refused with {@link
 * IllegalArgumentException}. A sealed chunk is 16 bytes longer than its plaintext.
 *
 * <p><b>The end of the file.</b> Opening a chunk proves the chunk authentic, not that the file is
 * complete. A file cut after a chunk, or missing chunks, still opens chunk by chunk. Seal the last
 * chunk with {@link #sealFinal} and check it with {@link ChunkedOpener#openFinal}. That proves the
 * number of chunks, because no index past the final one can be sealed. Otherwise keep the number
 * of chunks where it cannot be changed.
 *
 * <p><b>Ownership and threads.</b> The sealer holds the chunk key derived from the data key, and
 * destroys it on {@link #close()}. The data key itself is destroyed when the sealer is made. Close
 * the sealer when the file is written. It is thread-safe, so chunks may be sealed and opened from
 * several threads at once. A call running while {@code close()} runs may still complete.
 *
 * @since 0.10.0
 */
public final class ChunkedSealer implements AutoCloseable {
  private final ChunkedEnvelopes.Chunks chunks;
  private final byte[] header;
  private final ChunkedEnvelopes.Claims claims = new ChunkedEnvelopes.Claims();
  private boolean closed;

  ChunkedSealer(ChunkedEnvelopes.Chunks chunks, byte[] header) {
    this.chunks = chunks;
    this.header = header;
  }

  /**
   * The header to store once for the file: the wrapped data key, the nonce prefix and the key
   * commitment, in the KTR format. A copy; available after {@link #close()} too.
   *
   * @return a new copy of the header
   * @since 0.10.0
   */
  public byte[] header() {
    return header.clone();
  }

  /**
   * The identifier of the key-encryption key that wrapped the data key.
   *
   * @return the key identifier
   * @since 0.10.0
   */
  public String keyId() {
    return chunks.keyId;
  }

  /**
   * Seals chunk {@code index}, which is not the final chunk ({@link #sealFinal}). No server request.
   *
   * @param index the chunk's index, 0 to 2^32 - 1
   * @param plaintext the chunk's plaintext (not null; at most 1 MiB, may be empty); not kept
   * @return the sealed chunk, {@code plaintext.length + 16} bytes
   * @throws IllegalStateException when this index was sealed already by this sealer, is past the
   *     final chunk, or the sealer is closed
   * @throws IllegalArgumentException when the index or the plaintext's size is out of range
   * @since 0.10.0
   */
  public byte[] seal(long index, byte[] plaintext) {
    return seal(index, false, plaintext);
  }

  /**
   * Seals chunk {@code index} as the final chunk of the file: no later index can be sealed after
   * it, and {@link ChunkedOpener#openFinal} opens only this chunk at this index. No server request.
   *
   * @param index the final chunk's index, 0 to 2^32 - 1
   * @param plaintext the chunk's plaintext (not null; at most 1 MiB, may be empty); not kept
   * @return the sealed chunk, {@code plaintext.length + 16} bytes
   * @throws IllegalStateException when this index was sealed already, a final chunk was sealed
   *     already, a later index was sealed already, or the sealer is closed
   * @throws IllegalArgumentException when the index or the plaintext's size is out of range
   * @since 0.10.0
   */
  public byte[] sealFinal(long index, byte[] plaintext) {
    return seal(index, true, plaintext);
  }

  private byte[] seal(long index, boolean last, byte[] plaintext) {
    ChunkedEnvelopes.checkIndex(index);
    Objects.requireNonNull(plaintext, "plaintext");
    if (plaintext.length > ChunkedEnvelopes.MAX_CHUNK)
      throw new IllegalArgumentException(
          "A chunk holds at most "
              + ChunkedEnvelopes.MAX_CHUNK
              + " bytes, not "
              + plaintext.length);
    synchronized (claims) {
      if (closed) throw ChunkedEnvelopes.Chunks.closed("seal");
      claims.claim(index, last);
    }
    return chunks.seal(index, last, plaintext);
  }

  /**
   * Opens a chunk this sealer sealed, final or not, as {@link ChunkedOpener#open} does. No server
   * request.
   *
   * @param index the chunk's index, 0 to 2^32 - 1
   * @param chunk the sealed chunk; not kept
   * @return the chunk's plaintext
   * @throws CryptographicFailureException as for {@link ChunkedOpener#open}
   * @throws IllegalStateException when the sealer is closed
   * @since 0.10.0
   */
  public byte[] open(long index, byte[] chunk) {
    return chunks.open(index, null, chunk);
  }

  /**
   * Opens the final chunk this sealer sealed, as {@link ChunkedOpener#openFinal} does. No server
   * request.
   *
   * @param index the chunk's index, 0 to 2^32 - 1
   * @param chunk the sealed final chunk; not kept
   * @return the chunk's plaintext
   * @throws CryptographicFailureException as for {@link ChunkedOpener#openFinal}
   * @throws IllegalStateException when the sealer is closed
   * @since 0.10.0
   */
  public byte[] openFinal(long index, byte[] chunk) {
    return chunks.open(index, true, chunk);
  }

  /**
   * Whether {@link #close()} was called.
   *
   * @return whether the sealer is closed
   * @since 0.10.0
   */
  public boolean isClosed() {
    synchronized (claims) {
      return closed;
    }
  }

  /**
   * Destroys the chunk key; later seals and opens throw {@link IllegalStateException}. The header
   * stays readable. Idempotent.
   *
   * @since 0.10.0
   */
  @Override
  public void close() {
    synchronized (claims) {
      closed = true;
    }
    chunks.destroy();
  }

  @Override
  public String toString() {
    return "ChunkedSealer[key " + chunks.keyId + (isClosed() ? ", closed]" : "]");
  }
}
