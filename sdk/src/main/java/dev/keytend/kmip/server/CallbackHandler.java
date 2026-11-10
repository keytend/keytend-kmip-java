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

package dev.keytend.kmip.server;

import dev.keytend.kmip.model.*;
import java.util.*;

/**
 * Application handling of a server-initiated Notify, Put, or Query operation, and
 * Discover Versions from KMIP 1.4, or Set Endpoint Role from KMIP 2.0 (both in the supported
 * 3.0 draft). The application supplies
 * operation-specific response payloads and manages any transport role change;
 * dispatching Set Endpoint Role does not switch a connection automatically.
 *
 * <p>To see who sent the message, implement {@link ContextualCallbackHandler} instead; it receives
 * the authenticated TLS peer and the request header.
 *
 * @since 0.10.0
 */
@FunctionalInterface
public interface CallbackHandler {
  /**
   * Answers one batch item of a validated request. {@link CallbackMessages} calls it for each item,
   * in order, after it has checked the whole message. Under Stop, the items after the first
   * failure are not answered.
   *
   * @param operation the item's operation: Notify, Put, Query, Discover Versions or Set Endpoint
   *     Role
   * @param payload the item's Request Payload, a structure
   * @return the item's result: {@link Reply#success}, {@link Reply#failure} or {@link
   *     Reply#pending}; not null. An exception the handler throws is answered with General Failure.
   */
  Reply handle(Operation operation, Ttlv payload);

  /**
   * Answers one batch item, with the context of the message it came in. {@link CallbackMessages}
   * calls this one. The default ignores the context and calls {@link #handle(Operation, Ttlv)}.
   *
   * @param context the authenticated peer and the request header
   * @param operation the item's operation
   * @param payload the item's Request Payload
   * @return the item's result; not null
   */
  default Reply handle(CallbackContext context, Operation operation, Ttlv payload) {
    return handle(operation, payload);
  }

  /**
   * One batch item's result. The canonical constructor rejects shapes that a KMIP peer, and this
   * SDK's own response parser, would refuse: Failed (1) requires a Result Reason, Pending (2)
   * requires an Asynchronous Correlation Value in {@code extraFields}, and every Response Batch
   * Item field occurs at most once.
   *
   * @param extraFields extra batch item fields, each tag at most once, and none of the fields the
   *     record writes itself (Operation, Unique Batch Item ID, Result Status, Result Reason, Result
   *     Message, Response Payload). Message Extensions are written after the payload, other fields
   *     before it.
   */
  record Reply(int status, Integer reason, String message, Ttlv payload, List<Ttlv> extraFields) {
    private static final Set<Integer> WRITTEN_BY_REPLY =
        Set.of(
            Tag.OPERATION.code(),
            Tag.UNIQUE_BATCH_ITEM_ID.code(),
            Tag.RESULT_STATUS.code(),
            Tag.RESULT_REASON.code(),
            Tag.RESULT_MESSAGE.code(),
            Tag.RESPONSE_PAYLOAD.code());

    public Reply {
      extraFields = List.copyOf(extraFields);
      Set<Integer> seen = new HashSet<>();
      for (Ttlv field : extraFields) {
        if (WRITTEN_BY_REPLY.contains(field.tag()))
          throw new IllegalArgumentException(
              field.tagName() + " is set by the Reply itself, not through extraFields");
        if (!seen.add(field.tag()))
          throw new IllegalArgumentException(field.tagName() + " occurs more than once");
      }
      if (status < 0 || status > 3) throw new IllegalArgumentException("Invalid result status");
      if (status == 1 && reason == null)
        throw new IllegalArgumentException("Failed result requires a ResultReason");
      if (status == 2
          && extraFields.stream()
              .noneMatch(f -> f.tag() == Tag.ASYNCHRONOUS_CORRELATION_VALUE.code()))
        throw new IllegalArgumentException("Pending result requires AsynchronousCorrelationValue");
      if (payload != null && payload.type() != Ttlv.Type.STRUCTURE)
        throw new IllegalArgumentException("Payload must be a structure");
    }

    /**
     * Result Status Success, with {@code payload} as the Response Payload.
     *
     * @param payload the operation's response payload, a structure, or null for an empty one
     * @return the reply
     */
    public static Reply success(Ttlv payload) {
      return new Reply(0, null, null, payload, List.of());
    }

    /**
     * Result Status Operation Failed, with no payload.
     *
     * @param reason the Result Reason sent to the peer
     * @param message the Result Message, or null for none; the peer sees it
     * @return the reply
     */
    public static Reply failure(Enums.ResultReason reason, String message) {
      return new Reply(1, reason.code(), message, null, List.of());
    }

    /**
     * Result Status Operation Pending: the result follows later, under {@code correlation}.
     *
     * @param correlation the Asynchronous Correlation Value the peer polls with
     * @return the reply
     */
    public static Reply pending(byte[] correlation) {
      return new Reply(
          2,
          null,
          null,
          null,
          List.of(Ttlv.bytes(Tag.ASYNCHRONOUS_CORRELATION_VALUE, correlation)));
    }
  }
}
