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

package dev.keytend.kmip.client;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

/**
 * Streams data through a multi-part Encrypt, Decrypt, Sign, Signature Verify, MAC or MAC Verify
 * (KMIP 1.3+). The first {@link #update} sends Init Indicator; later parts carry the server's
 * Correlation Value; {@link #finish} sends Final Indicator. A part that fails leaves the stream
 * where it was (a failed Init is sent again as an Init), and an Init answered without a
 * Correlation Value is a {@link ProtocolException}, since later parts could not be tied to it.
 * Not thread-safe; one stream per instance.
 *
 * <pre>{@code
 * var stream = new MultipartOperation(client,
 *     () -> CryptoRequests.mac(keyId).parameters(hmacSha256));
 * stream.update(part1);
 * CryptoResult mac = stream.finish(part2);
 * }</pre>
 *
 * @since 0.10.0
 */
public final class MultipartOperation {
  private final KmipClient client;
  private final Supplier<CryptoRequests.Builder> template;
  private byte[] correlation;
  private boolean started, finished;

  /** @param template a fresh builder for each part, with key and parameters set */
  public MultipartOperation(KmipClient client, Supplier<CryptoRequests.Builder> template) {
    this.client = Objects.requireNonNull(client);
    this.template = Objects.requireNonNull(template);
  }

  /** Sends one part; returns its result (for example a block of ciphertext). */
  public CryptoResult update(byte[] part) throws IOException {
    return send(part, false);
  }

  /** Sends the last part and ends the stream. */
  public CryptoResult finish(byte[] part) throws IOException {
    return send(part, true);
  }

  private CryptoResult send(byte[] part, boolean last) throws IOException {
    if (finished) throw new IllegalStateException("Stream already finished");
    CryptoRequests.Builder b = template.get().data(part);
    if (!started) b.init();
    else if (correlation != null) b.continuing(correlation);
    if (last) b.last();
    Result raw = client.call(b.build());
    // State changes only after the server accepted the part: a failed Init must be re-sent as an
    // Init, not followed by parts that would go out as single-shot operations.
    CryptoResult result = CryptoResult.of(raw);
    Optional<byte[]> returned = result.correlationValue();
    if (!started && !last && returned.isEmpty())
      throw new ProtocolException(
          "Multi-part Init response has no Correlation Value", raw.batchItem(), null);
    returned.ifPresent(c -> correlation = c);
    started = true;
    finished = last;
    return result;
  }
}
