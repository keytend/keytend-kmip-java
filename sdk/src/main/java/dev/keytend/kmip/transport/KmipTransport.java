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

package dev.keytend.kmip.transport;

import dev.keytend.kmip.model.Ttlv;
import java.io.*;

/**
 * A request/response exchange. Implementations must document their concurrency behavior.
 *
 * @since 0.10.0
 */
@FunctionalInterface
public interface KmipTransport extends AutoCloseable {
  /**
   * Sends one KMIP Request Message and returns the Response Message. Throw {@link
   * RequestNotSentException} when nothing was sent, so the caller may repeat it. Throw another
   * {@link IOException} when the request may have reached the server: the SDK then never repeats a
   * mutation, and reports its outcome as unknown.
   *
   * @param request a Request Message
   * @return the Response Message
   * @throws RequestNotSentException when the request was not sent
   * @throws IOException when the exchange failed after the request may have been sent
   */
  Ttlv exchange(Ttlv request) throws IOException;

  /**
   * An exchange bounded by {@code context}'s deadline and cancellation. The SDK's transports
   * honor both while the exchange is in progress; this default only checks them before it starts,
   * failing with a local {@link RequestNotSentException} (see {@link CallContext}).
   */
  default Ttlv exchange(Ttlv request, CallContext context) throws IOException {
    context.checkNotSent();
    return exchange(request);
  }

  @Override
  default void close() throws IOException {}
}
