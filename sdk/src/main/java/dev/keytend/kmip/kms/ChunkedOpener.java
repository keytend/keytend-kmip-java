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

/**
 * Opens the chunks of one file sealed by a {@link ChunkedSealer}, by index, in any order: from
 * {@link KeyHandle#chunkedOpener} or {@link KmsKeys#chunkedOpener}, which unwrap the file's data
 * key once (two server requests); opening chunks sends none. Read-only: it never seals, so a
 * stored header can never be used to seal again under its data key.
 *
 * <pre>{@code
 * try (ChunkedOpener opener = kek.chunkedOpener(store.readHeader(), fileId)) {
 *   byte[] chunk7 = opener.open(7, store.readChunk(7));
 * }
 * }</pre>
 *
 * <p>Each open checks that the chunk is the one sealed at that index for that file and file
 * identifier: a changed, cut or moved chunk, another index's, another file's (even under the same
 * key-encryption key), or another file identifier fails with {@link CryptographicFailureException}
 * ({@code AUTHENTICATION_FAILED}). It does not prove that the file is complete: see {@link
 * #openFinal}.
 *
 * <p><b>Ownership and threads.</b> The opener holds the chunk key derived from the file's data key
 * (the data key itself is destroyed once the opener is made) and destroys it on {@link #close()};
 * keep one opener per open file and close it with the file. Nothing is cached between openers.
 * Thread-safe: chunks may be opened from several threads at once; a call running while {@code
 * close()} runs may still complete.
 *
 * @since 0.10.0
 */
public final class ChunkedOpener implements AutoCloseable {
  private final ChunkedEnvelopes.Chunks chunks;

  ChunkedOpener(ChunkedEnvelopes.Chunks chunks) {
    this.chunks = chunks;
  }

  /**
   * The identifier of the key-encryption key the header names.
   *
   * @return the key identifier
   * @since 0.10.0
   */
  public String keyId() {
    return chunks.keyId;
  }

  /**
   * Opens chunk {@code index}, whether or not it was sealed as the final chunk. No server request.
   *
   * @param index the chunk's index, 0 to 2^32 - 1
   * @param chunk the sealed chunk (not null; 16 bytes to 1 MiB + 16 bytes); not kept
   * @return the chunk's plaintext
   * @throws CryptographicFailureException ({@code BAD_DATA}, operation {@code open}) of kind {@code
   *     INVALID_CIPHERTEXT} when the chunk is shorter than a tag or longer than a chunk may be, and
   *     {@code AUTHENTICATION_FAILED} when it does not verify as chunk {@code index} of this file
   *     with this file identifier
   * @throws IllegalArgumentException when the index is out of range
   * @throws IllegalStateException when the opener is closed
   * @since 0.10.0
   */
  public byte[] open(long index, byte[] chunk) {
    return chunks.open(index, null, chunk);
  }

  /**
   * Opens chunk {@code index} only if it was sealed as the final chunk ({@link
   * ChunkedSealer#sealFinal}): success proves that the file has exactly {@code index + 1} chunks,
   * as no later index can be sealed under its data key. Use it on the chunk the caller believes is
   * the last, to detect a file that was cut or extended. No server request.
   *
   * @param index the chunk's index, 0 to 2^32 - 1
   * @param chunk the sealed chunk (16 bytes to 1 MiB + 16 bytes); not kept
   * @return the chunk's plaintext
   * @throws CryptographicFailureException as for {@link #open}, and {@code AUTHENTICATION_FAILED}
   *     when the chunk is authentic but not the final chunk
   * @throws IllegalArgumentException when the index is out of range
   * @throws IllegalStateException when the opener is closed
   * @since 0.10.0
   */
  public byte[] openFinal(long index, byte[] chunk) {
    return chunks.open(index, true, chunk);
  }

  /**
   * Whether {@link #close()} was called.
   *
   * @return whether the opener is closed
   * @since 0.10.0
   */
  public boolean isClosed() {
    return chunks.isDestroyed();
  }

  /**
   * Destroys the chunk key; later opens throw {@link IllegalStateException}. Idempotent.
   *
   * @since 0.10.0
   */
  @Override
  public void close() {
    chunks.destroy();
  }

  @Override
  public String toString() {
    return "ChunkedOpener[key " + chunks.keyId + (isClosed() ? ", closed]" : "]");
  }
}
