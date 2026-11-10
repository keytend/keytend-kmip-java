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

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.client.Messages;
import dev.keytend.kmip.model.*;
import java.time.Instant;
import java.util.*;

/** Scripted failure responses for kms tests. */
final class Faults {
  private Faults() {}

  static int operation(Ttlv request) {
    return request.require(BATCH_ITEM).require(OPERATION).intValue();
  }

  /** A version-correct response failing every item of {@code request}. */
  static Ttlv failure(Ttlv request, Enums.ResultReason reason, String message) {
    ProtocolVersion version = Messages.version(request.require(REQUEST_HEADER));
    List<Ttlv> items = new ArrayList<>();
    List<Ttlv> header =
        new ArrayList<>(
            List.of(
                Messages.protocolVersion(version),
                dateTime(TIME_STAMP, Instant.ofEpochSecond(1700000000))));
    for (Ttlv b : request.children(BATCH_ITEM)) {
      List<Ttlv> f = new ArrayList<>(List.of(b.require(OPERATION)));
      b.child(UNIQUE_BATCH_ITEM_ID).ifPresent(f::add);
      f.add(enumeration(RESULT_STATUS, 1));
      f.add(enumeration(RESULT_REASON, reason));
      f.add(text(RESULT_MESSAGE, message));
      items.add(structure(BATCH_ITEM, f));
    }
    if (version != ProtocolVersion.V3_0) header.add(integer(BATCH_COUNT, items.size()));
    items.add(0, structure(RESPONSE_HEADER, header));
    return structure(RESPONSE_MESSAGE, items);
  }
}
