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

import java.io.IOException;
import java.io.OutputStream;

/**
 * The stream {@link CurrentKey#sealing} and {@link KeyHandle#sealing} return: it seals what is
 * written to it, and the sealed data ends only when {@link #finish()} is called. Closing a stream
 * that was not finished writes no end, so its output cannot be opened: a job whose source fails
 * part-way, inside {@code try-with-resources}, leaves output that fails to open rather than an
 * authentic but truncated stream. To seal into a file, {@link CurrentKey#sealTo} does this and
 * moves the result into place once it is finished.
 *
 * <pre>{@code
 * try (SealingStream out = kek.sealing(upload.start(), recordId)) {
 *   source.transferTo(out);
 *   out.finish(); // only now can the output be opened
 * }
 * upload.commit();
 * }</pre>
 *
 * A stream wrapped around this one (a {@code GZIPOutputStream}, say) does not finish it when it is
 * closed: finish the outer stream, then this one, then close the outer one. Not thread-safe.
 *
 * @since 0.10.0
 */
public abstract class SealingStream extends OutputStream {
  SealingStream() {}

  /**
   * Ends the sealed data: writes the last chunk (which marks the end of the data), flushes the
   * underlying stream and destroys the data key, without closing the underlying stream (as {@code
   * GZIPOutputStream.finish()} does). Call it once everything is written; then close the stream.
   * Writes after it throw {@link IOException}; finishing again does nothing.
   *
   * @throws IOException for errors of the underlying stream (the stream is failed then: discard
   *     its output, which may or may not open, depending on how much of the last chunk reached the
   *     underlying stream before the error; an error of the final flush can come after all of it
   *     did), or when the stream is closed, or failed earlier
   */
  public abstract void finish() throws IOException;

  /**
   * Closes the underlying stream and destroys the data key. A stream that was not {@linkplain
   * #finish() finished} gets no last chunk, so its output cannot be opened: this method then closes
   * the underlying stream all the same and throws {@link IOException} saying so (in {@code
   * try-with-resources} whose block threw, that exception is suppressed under the block's). Discard
   * the output of a stream that was not finished. Closing again does nothing.
   *
   * @throws IOException when the stream was not finished, or for errors of the underlying stream
   */
  @Override
  public abstract void close() throws IOException;
}
