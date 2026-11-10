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

import dev.keytend.kmip.client.Result;
import dev.keytend.kmip.model.*;
import java.math.BigInteger;
import java.util.*;

/**
 * Copies of protocol objects that are safe to keep in exceptions: every Byte String becomes empty,
 * every Big Integer zero and every password or one-time password empty, so key material,
 * plaintext, signatures and credentials never outlive the call that received them.
 */
final class Redaction {
  private Redaction() {}

  private static final Set<Integer> SECRET_TEXT =
      Set.of(Tag.PASSWORD.code(), Tag.ONE_TIME_PASSWORD.code());

  static Ttlv copy(Ttlv node) {
    if (node == null) return null;
    return switch (node.type()) {
      case STRUCTURE ->
          Ttlv.structure(node.tag(), node.children().stream().map(Redaction::copy).toList());
      case BYTE_STRING -> Ttlv.of(node.tag(), Ttlv.Type.BYTE_STRING, new byte[0]);
      case BIG_INTEGER -> Ttlv.of(node.tag(), Ttlv.Type.BIG_INTEGER, BigInteger.ZERO);
      case TEXT_STRING ->
          SECRET_TEXT.contains(node.tag()) ? Ttlv.of(node.tag(), Ttlv.Type.TEXT_STRING, "") : node;
      default -> node;
    };
  }

  static Result copy(Result result) {
    if (result == null) return null;
    return new Result(
        result.operation(),
        result.status(),
        result.reason(),
        result.message(),
        copy(result.batchItem()));
  }
}
