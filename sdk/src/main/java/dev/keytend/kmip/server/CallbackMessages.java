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

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.client.Messages;
import dev.keytend.kmip.model.*;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.function.Consumer;

/**
 * Builds protocol-correct callback responses without prescribing an application's persistence
 * model.
 *
 * <p>The whole request is validated before any handler runs, so a bad later item cannot abort the
 * reply after earlier items had side effects. Problems are answered with KMIP failures rather than
 * exceptions:
 *
 * <ul>
 *   <li>an unsupported protocol version, a Batch Count that does not match, or an unknown critical
 *       Message Extension (KMIP 2.1 §9.13: reject the entire message) gives a message-level
 *       failure;
 *   <li>an unknown or vendor operation code, an operation newer than the message version, or an
 *       operation that is not server-to-client gives that item Operation Not Supported, echoing
 *       the received operation code; a missing operation or payload gives Invalid Message;
 *   <li>Undo is answered with Feature Not Supported for every item, because the adapter cannot
 *       undo an application's side effects.
 * </ul>
 *
 * Under Stop (the default) items after the first failure are not answered. {@link #respond}
 * throws {@link IllegalArgumentException} only when the input is not a request message with a
 * readable protocol version, so no response can be addressed.
 *
 * @since 0.10.0
 */
public final class CallbackMessages {
  private CallbackMessages() {}

  /**
   * The response to {@code request}, with {@code handler} answering each batch item. A message with
   * any critical Message Extension is refused as a whole. A handler's exception is answered with
   * General Failure and not reported further.
   *
   * @param request a KMIP Request Message
   * @param handler answers each item; not null
   * @return the Response Message, a failure included
   * @throws IllegalArgumentException when {@code request} is not a request message with a readable
   *     protocol version
   */
  public static Ttlv respond(Ttlv request, CallbackHandler handler) {
    return respond(request, handler, Set.of());
  }

  /**
   * The response to {@code request}, as {@link #respond(Ttlv, CallbackHandler)} gives it, with
   * critical Message Extensions of the vendors in {@code knownExtensions} accepted.
   *
   * @param request a KMIP Request Message
   * @param handler answers each item; not null
   * @param knownExtensions the Vendor Identifications of the critical Message Extensions you
   *     understand; a message with any other critical extension is refused as a whole
   * @return the Response Message, a failure included
   * @throws IllegalArgumentException when {@code request} is not a request message with a readable
   *     protocol version
   */
  public static Ttlv respond(Ttlv request, CallbackHandler handler, Set<String> knownExtensions) {
    return respond(request, handler, knownExtensions, CallbackContext.NONE, e -> {});
  }

  /**
   * The response to {@code request}, as {@link #respond(Ttlv, CallbackHandler, Set)} gives it,
   * with the peer's context for the handler and its exceptions reported.
   *
   * @param request a KMIP Request Message
   * @param handler answers each item; not null
   * @param knownExtensions the Vendor Identifications of the critical Message Extensions you
   *     understand
   * @param context the authenticated peer, passed to the handler with the request header added
   * @param handlerFailures receives exceptions thrown by the handler; the peer is sent General
   *     Failure without the exception text
   * @return the Response Message, a failure included
   * @throws IllegalArgumentException when {@code request} is not a request message with a readable
   *     protocol version
   */
  public static Ttlv respond(
      Ttlv request,
      CallbackHandler handler,
      Set<String> knownExtensions,
      CallbackContext context,
      Consumer<RuntimeException> handlerFailures) {
    Objects.requireNonNull(handler, "handler");
    Objects.requireNonNull(context, "context");
    Objects.requireNonNull(handlerFailures, "handlerFailures");
    Set<String> known = Set.copyOf(knownExtensions);
    if (request.tag() != REQUEST_MESSAGE.code() || request.type() != Ttlv.Type.STRUCTURE)
      throw new IllegalArgumentException("Expected callback RequestMessage");
    Ttlv header =
        request
            .child(REQUEST_HEADER)
            .orElseThrow(() -> new IllegalArgumentException("Callback request has no header"));
    Ttlv rawVersion =
        header
            .child(PROTOCOL_VERSION)
            .orElseThrow(() -> new IllegalArgumentException("Callback request has no version"));
    int major = rawVersion.require(PROTOCOL_VERSION_MAJOR).intValue();
    int minor = rawVersion.require(PROTOCOL_VERSION_MINOR).intValue();
    ProtocolVersion version;
    try {
      version = ProtocolVersion.of(major, minor);
    } catch (IllegalArgumentException unsupported) {
      return messageFailure(
          rawVersion,
          null,
          major >= 2
              ? Enums.ResultReason.UNSUPPORTED_PROTOCOL_VERSION
              : Enums.ResultReason.INVALID_MESSAGE,
          "Unsupported protocol version");
    }
    Ttlv protocolVersion = Messages.protocolVersion(version);
    Optional<Ttlv> correlation = header.child(CLIENT_CORRELATION_VALUE);
    List<Ttlv> batches = request.children(BATCH_ITEM);
    if (batches.isEmpty()
        || (version != ProtocolVersion.V3_0
            && header.child(BATCH_COUNT).map(n -> n.intValue() != batches.size()).orElse(true)))
      return messageFailure(
          protocolVersion,
          correlation.orElse(null),
          Enums.ResultReason.INVALID_MESSAGE,
          "Callback batch count mismatch");
    for (Ttlv batch : batches)
      for (Ttlv extension : batch.children(MESSAGE_EXTENSION)) {
        Optional<Ttlv> critical = extension.child(CRITICALITY_INDICATOR);
        Optional<Ttlv> vendor = extension.child(VENDOR_IDENTIFICATION);
        if (critical.isEmpty()
            || critical.get().type() != Ttlv.Type.BOOLEAN
            || vendor.isEmpty()
            || vendor.get().type() != Ttlv.Type.TEXT_STRING)
          return messageFailure(
              protocolVersion,
              correlation.orElse(null),
              Enums.ResultReason.INVALID_MESSAGE,
              "Malformed message extension");
        if (critical.get().booleanValue() && !known.contains(vendor.get().textValue()))
          return messageFailure(
              protocolVersion,
              correlation.orElse(null),
              version.atLeast(ProtocolVersion.V2_0)
                  ? Enums.ResultReason.UNKNOWN_MESSAGE_EXTENSION
                  : Enums.ResultReason.FEATURE_NOT_SUPPORTED,
              "Unknown critical message extension");
      }
    int continuation =
        header
            .child(BATCH_ERROR_CONTINUATION_OPTION)
            .filter(n -> n.type() == Ttlv.Type.ENUMERATION)
            .map(Ttlv::intValue)
            .orElse(2);
    // Validate every item before any handler runs.
    List<CallbackHandler.Reply> planned = new ArrayList<>();
    for (Ttlv batch : batches) planned.add(validate(batch, version, continuation));
    CallbackContext itemContext = context.withRequest(version, header);
    List<Ttlv> items = new ArrayList<>();
    for (int i = 0; i < batches.size(); i++) {
      Ttlv batch = batches.get(i);
      CallbackHandler.Reply reply = planned.get(i);
      if (reply == null) {
        Operation operation = Operation.fromCode(batch.require(OPERATION).intValue());
        try {
          reply =
              Objects.requireNonNull(
                  handler.handle(itemContext, operation, batch.require(REQUEST_PAYLOAD)),
                  "CallbackHandler returned null");
        } catch (RuntimeException e) {
          handlerFailures.accept(e);
          reply =
              CallbackHandler.Reply.failure(
                  Enums.ResultReason.GENERAL_FAILURE, "Application callback failed");
        }
      }
      items.add(item(batch, reply));
      if (continuation == 2 && reply.status() == 1) break;
    }
    List<Ttlv> responseHeader = new ArrayList<>();
    responseHeader.add(protocolVersion);
    responseHeader.add(now());
    correlation.ifPresent(responseHeader::add);
    if (version != ProtocolVersion.V3_0) responseHeader.add(integer(BATCH_COUNT, items.size()));
    items.add(0, structure(RESPONSE_HEADER, responseHeader));
    return structure(RESPONSE_MESSAGE, items);
  }

  /** A failure reply for an item that must not reach the handler, or null to dispatch it. */
  private static CallbackHandler.Reply validate(
      Ttlv batch, ProtocolVersion version, int continuation) {
    Optional<Ttlv> code = batch.child(OPERATION);
    if (code.isEmpty() || code.get().type() != Ttlv.Type.ENUMERATION)
      return CallbackHandler.Reply.failure(
          Enums.ResultReason.INVALID_MESSAGE, "Batch item has no operation");
    Operation operation;
    try {
      operation = Operation.fromCode(code.get().intValue());
    } catch (IllegalArgumentException unknown) {
      return CallbackHandler.Reply.failure(
          Enums.ResultReason.OPERATION_NOT_SUPPORTED, "Unknown operation");
    }
    if (!version.atLeast(operation.since()))
      return CallbackHandler.Reply.failure(
          Enums.ResultReason.OPERATION_NOT_SUPPORTED, "Operation not defined in this version");
    if (continuation == 3)
      return CallbackHandler.Reply.failure(
          Enums.ResultReason.FEATURE_NOT_SUPPORTED,
          "Callback adapter does not provide transactional Undo");
    // Server-initiated Discover Versions starts in 1.4 OS section 5.4; Set Endpoint Role starts
    // in 2.0. Both remain in the supported 3.0 draft. The application supplies their payloads
    // and manages a channel's role; dispatch does not change transport state.
    boolean roleControl =
        (operation == Operation.DISCOVER_VERSIONS && version.atLeast(ProtocolVersion.V1_4))
            || (operation == Operation.SET_ENDPOINT_ROLE && version.atLeast(ProtocolVersion.V2_0));
    if (!operation.serverToClient() && operation != Operation.QUERY && !roleControl)
      return CallbackHandler.Reply.failure(
          Enums.ResultReason.OPERATION_NOT_SUPPORTED, "Not a server-to-client operation");
    Optional<Ttlv> payload = batch.child(REQUEST_PAYLOAD);
    if (payload.isEmpty() || payload.get().type() != Ttlv.Type.STRUCTURE)
      return CallbackHandler.Reply.failure(
          Enums.ResultReason.INVALID_MESSAGE, "Batch item has no request payload");
    return null;
  }

  private static Ttlv item(Ttlv batch, CallbackHandler.Reply reply) {
    List<Ttlv> fields = new ArrayList<>();
    batch
        .child(OPERATION)
        .filter(n -> n.type() == Ttlv.Type.ENUMERATION)
        .ifPresent(n -> fields.add(enumeration(OPERATION, n.intValue())));
    batch.child(UNIQUE_BATCH_ITEM_ID).ifPresent(fields::add);
    fields.add(enumeration(RESULT_STATUS, reply.status()));
    if (reply.reason() != null) fields.add(enumeration(RESULT_REASON, reply.reason()));
    if (reply.message() != null) fields.add(text(RESULT_MESSAGE, reply.message()));
    for (Ttlv extra : reply.extraFields())
      if (extra.tag() != MESSAGE_EXTENSION.code()) fields.add(extra);
    // KMIP 1.4 Table 285, 2.1 §9 and 3.0 §8.2.3: a successful item carries a Response Payload,
    // empty when the operation returns nothing.
    if (reply.payload() != null) fields.add(reply.payload().retag(RESPONSE_PAYLOAD));
    else if (reply.status() == 0) fields.add(structure(RESPONSE_PAYLOAD));
    for (Ttlv extra : reply.extraFields())
      if (extra.tag() == MESSAGE_EXTENSION.code()) fields.add(extra);
    return structure(BATCH_ITEM, fields);
  }

  private static Ttlv messageFailure(
      Ttlv protocolVersion, Ttlv correlation, Enums.ResultReason reason, String message) {
    List<Ttlv> header = new ArrayList<>(List.of(protocolVersion, now()));
    if (correlation != null) header.add(correlation);
    if (protocolVersion.require(PROTOCOL_VERSION_MAJOR).intValue() < 3)
      header.add(integer(BATCH_COUNT, 1));
    return structure(
        RESPONSE_MESSAGE,
        structure(RESPONSE_HEADER, header),
        structure(
            BATCH_ITEM,
            enumeration(RESULT_STATUS, 1),
            enumeration(RESULT_REASON, reason),
            text(RESULT_MESSAGE, message)));
  }

  private static Ttlv now() {
    return dateTime(TIME_STAMP, Instant.now().truncatedTo(ChronoUnit.SECONDS));
  }
}
