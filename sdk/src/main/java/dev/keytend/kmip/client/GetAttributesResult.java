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
import java.util.*;

/**
 * A typed Get Attributes response. A successful response may carry only the Unique Identifier
 * (the object has none of the requested attributes); that is an empty {@link #attributes()} list,
 * not an error.
 *
 * @param attributes for KMIP 1.x the {@code Attribute} structures; for 2.x/3.0 the children of the
 *     {@code Attributes} structure (each tagged with the attribute itself)
 * @since 0.10.0
 */
public record GetAttributesResult(String uniqueIdentifier, List<Ttlv> attributes) {
  public GetAttributesResult {
    attributes = List.copyOf(attributes);
  }

  /**
   * Reads a successful Get Attributes result.
   *
   * @throws KmipException when the result is not Success
   * @throws ProtocolException when the payload is malformed
   */
  public static GetAttributesResult of(Result result) throws ProtocolException {
    result.requireSuccess();
    try {
      Ttlv payload =
          result
              .payload()
              .orElseThrow(() -> new IllegalArgumentException("Response has no payload"));
      String id = payload.require(UNIQUE_IDENTIFIER).textValue();
      List<Ttlv> attributes = new ArrayList<>(payload.children(ATTRIBUTE));
      for (Ttlv modern : payload.children(ATTRIBUTES)) attributes.addAll(modern.children());
      return new GetAttributesResult(id, attributes);
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new ProtocolException(
          "Malformed Get Attributes response: " + e.getMessage(), result.batchItem(), e);
    }
  }

  public boolean isEmpty() {
    return attributes.isEmpty();
  }
}
