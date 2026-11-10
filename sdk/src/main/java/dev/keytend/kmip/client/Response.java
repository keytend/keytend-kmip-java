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

import static dev.keytend.kmip.model.Tag.*;

import dev.keytend.kmip.model.*;
import java.time.Instant;
import java.util.*;

/**
 * Complete response, preserving headers and every batch item's original fields.
 *
 * <p>{@link #results()} is in the order the server sent the batch items (wire order). It can be
 * shorter than the request list: a whole-message failure returns one result with no operation,
 * and with the Stop or Undo batch error continuation option the items after the failing one are
 * not returned. Use {@link #resultFor(int)} to look a result up by the position of its request.
 *
 * @param requestIndexes for each element of {@code results()}, the position of the request it
 *     answers, or -1 for a whole-message failure. Empty when the response was parsed but not
 *     correlated with a request ({@link Messages#response(Ttlv)} alone).
 * @param requestCount the number of items in the request, or -1 when not known
 * @since 0.10.0
 */
public record Response(
    ProtocolVersion version,
    Instant timestamp,
    List<Result> results,
    Ttlv message,
    List<Integer> requestIndexes,
    int requestCount) {
  public Response {
    results = List.copyOf(results);
    requestIndexes = List.copyOf(requestIndexes);
    if (!requestIndexes.isEmpty() && requestIndexes.size() != results.size())
      throw new IllegalArgumentException("One request index per result");
    if (requestCount < -1) throw new IllegalArgumentException("Invalid request count");
  }

  /** An uncorrelated response. */
  public Response(ProtocolVersion version, Instant timestamp, List<Result> results, Ttlv message) {
    this(version, timestamp, results, message, List.of(), -1);
  }

  /** A correlated response whose request size is not known ({@code requestCount} -1). */
  public Response(
      ProtocolVersion version,
      Instant timestamp,
      List<Result> results,
      Ttlv message,
      List<Integer> requestIndexes) {
    this(version, timestamp, results, message, requestIndexes, -1);
  }

  public Ttlv header() {
    return message.require(RESPONSE_HEADER);
  }

  public Optional<String> clientCorrelation() {
    return header().child(CLIENT_CORRELATION_VALUE).map(Ttlv::textValue);
  }

  public Optional<String> serverCorrelation() {
    return header().child(SERVER_CORRELATION_VALUE).map(Ttlv::textValue);
  }

  /** True when the server rejected the whole message rather than answering individual items. */
  public boolean messageLevelFailure() {
    return requestIndexes.size() == 1 && requestIndexes.get(0) == -1;
  }

  /**
   * The result for the request at {@code requestIndex} in the list passed to {@code batch}.
   *
   * @return empty when the server did not return an item for that request (Stop or Undo ended the
   *     batch before it)
   * @throws KmipException when the server rejected the whole message; it carries that failure
   * @throws IllegalStateException when this response was not correlated with its request
   * @throws IndexOutOfBoundsException when {@code requestIndex} is not an index of the request
   */
  public Optional<Result> resultFor(int requestIndex) {
    if (requestIndexes.isEmpty())
      throw new IllegalStateException("Response was not correlated with a request");
    if (requestIndex < 0 || (requestCount >= 0 && requestIndex >= requestCount))
      throw new IndexOutOfBoundsException(requestIndex);
    if (messageLevelFailure()) throw new KmipException(results.get(0));
    for (int i = 0; i < results.size(); i++)
      if (requestIndexes.get(i) == requestIndex) return Optional.of(results.get(i));
    return Optional.empty();
  }
}
