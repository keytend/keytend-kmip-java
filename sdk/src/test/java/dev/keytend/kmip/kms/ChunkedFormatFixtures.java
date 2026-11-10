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

import static dev.keytend.kmip.kms.FormatFixtures.KEK_ID;

import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;

/**
 * The fixtures of the random-access format (KTR) for {@link PersistedFormatsTest}, on {@link
 * FormatFixtures}' server and KEK, written as {@link FormatFixtures} says. Never regenerate the
 * fixtures of a released version: they are what that version wrote.
 */
public final class ChunkedFormatFixtures {
  /** The plaintext's size: two whole 4 KiB chunks and a final chunk of 100 bytes. */
  public static final int SIZE = 2 * 4096 + 100;

  /** The chunks' plaintext size, but for the final chunk. */
  public static final int CHUNK = 4096;

  /** The number of chunks. */
  public static final int CHUNKS = 3;

  private ChunkedFormatFixtures() {}

  /** The file identifier: {@link FormatFixtures#AAD}. */
  public static byte[] fileId() {
    return FormatFixtures.AAD.clone();
  }

  /** The plaintext of chunk {@code index}: its part of {@code FormatFixtures.plaintext(SIZE)}. */
  public static byte[] chunk(int index) {
    byte[] all = FormatFixtures.plaintext(SIZE);
    return Arrays.copyOfRange(all, index * CHUNK, Math.min(SIZE, (index + 1) * CHUNK));
  }

  /** Writes {@code ktr-header.bin} and {@code ktr-chunk-0.bin} to {@code ktr-chunk-2.bin} (the final chunk) into {@code args[0]}. */
  public static void main(String[] args) throws IOException {
    Path out = Files.createDirectories(Path.of(args[0]));
    InMemoryKmipServer server = FormatFixtures.server();
    try (Kms kms = server.connect();
        ChunkedSealer sealer = kms.keys().handle(KEK_ID).chunkedSealer(fileId())) {
      Files.write(out.resolve("ktr-header.bin"), sealer.header());
      for (int i = 0; i < CHUNKS; i++)
        Files.write(
            out.resolve("ktr-chunk-" + i + ".bin"),
            i == CHUNKS - 1 ? sealer.sealFinal(i, chunk(i)) : sealer.seal(i, chunk(i)));
    } finally {
      server.close();
    }
  }
}
