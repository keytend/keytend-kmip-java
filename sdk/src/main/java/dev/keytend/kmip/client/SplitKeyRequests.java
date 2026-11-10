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
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.model.*;
import java.math.BigInteger;
import java.util.*;

/**
 * Typed Create Split Key and Join Split Key requests (KMIP 1.2+). Join takes the part identifiers
 * as repeated Unique Identifier fields.
 *
 * @since 0.10.0
 */
public final class SplitKeyRequests {
  private SplitKeyRequests() {}

  /**
   * Splits a new key, or the existing key {@code splitId} when it is non-null, into {@code parts}
   * parts of which {@code threshold} recover it.
   */
  public static Request create(
      Enums.ObjectType type,
      String splitId,
      int parts,
      int threshold,
      Enums.SplitKeyMethod method,
      BigInteger primeFieldSize,
      Ttlv... attributes) {
    if (parts < 2 || threshold < 1 || threshold > parts)
      throw new IllegalArgumentException("Need 2+ parts and a threshold between 1 and parts");
    // XOR needs every part: Split Key Parts equals the threshold (1.4 §2.2.5, 2.1 §13.1).
    if (method == Enums.SplitKeyMethod.XOR && threshold != parts)
      throw new IllegalArgumentException("XOR splitting needs a threshold equal to the parts");
    if (method == Enums.SplitKeyMethod.POLYNOMIAL_SHARING_PRIME_FIELD && primeFieldSize == null)
      throw new IllegalArgumentException("Prime field sharing needs a prime field size");
    Request.Builder b = Requests.createSplitKey().add(enumeration(OBJECT_TYPE, type));
    if (splitId != null) b.uniqueIdentifier(splitId);
    b.add(
        integer(SPLIT_KEY_PARTS, parts),
        integer(SPLIT_KEY_THRESHOLD, threshold),
        enumeration(SPLIT_KEY_METHOD, method));
    if (primeFieldSize != null) b.add(bigInteger(PRIME_FIELD_SIZE, primeFieldSize));
    if (attributes.length > 0) b.template(attributes);
    return b.build();
  }

  /** Joins the parts {@code partIds} into a new object of {@code type}. */
  public static Request join(
      Enums.ObjectType type,
      List<String> partIds,
      Enums.SecretDataType secretDataType,
      Ttlv... attributes) {
    if (partIds.isEmpty()) throw new IllegalArgumentException("No split key parts");
    Request.Builder b = Requests.joinSplitKey().add(enumeration(OBJECT_TYPE, type));
    for (String id : partIds) b.uniqueIdentifier(id);
    if (secretDataType != null) b.add(enumeration(SECRET_DATA_TYPE, secretDataType));
    if (attributes.length > 0) b.template(attributes);
    return b.build();
  }

  /** The part identifiers of a Create Split Key result, in server order. */
  public static List<String> partIds(Result result) throws ProtocolException {
    result.requireSuccess();
    try {
      List<String> ids = new ArrayList<>();
      for (Ttlv id :
          result
              .payload()
              .orElseThrow(() -> new IllegalArgumentException("no payload"))
              .children(UNIQUE_IDENTIFIER)) ids.add(id.textValue());
      if (ids.isEmpty()) throw new IllegalArgumentException("no part identifiers");
      return List.copyOf(ids);
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new ProtocolException(
          "Malformed Create Split Key response: " + e.getMessage(), result.batchItem(), e);
    }
  }
}
