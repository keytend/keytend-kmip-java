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
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.*;

/**
 * Public message model for transports, relays, asynchronous and server-to-client messages.
 *
 * @since 0.10.0
 */
public final class Messages {
  public static final int MAX_BATCH_ITEMS = 128;

  private Messages() {}

  public static Ttlv protocolVersion(ProtocolVersion version) {
    return structure(
        PROTOCOL_VERSION,
        integer(PROTOCOL_VERSION_MAJOR, version.major()),
        integer(PROTOCOL_VERSION_MINOR, version.minor()));
  }

  public static ProtocolVersion version(Ttlv header) {
    Ttlv v = header.require(PROTOCOL_VERSION);
    return ProtocolVersion.of(
        v.require(PROTOCOL_VERSION_MAJOR).intValue(), v.require(PROTOCOL_VERSION_MINOR).intValue());
  }

  public static Ttlv request(
      ProtocolVersion version, List<Request> requests, RequestOptions options) {
    return request(version, requests, options, MAX_BATCH_ITEMS);
  }

  public static Ttlv request(
      ProtocolVersion version,
      List<Request> requests,
      RequestOptions options,
      int maximumBatchItems) {
    if (maximumBatchItems < 1) throw new IllegalArgumentException("Invalid batch item limit");
    if (requests.size() > maximumBatchItems)
      throw new IllegalArgumentException("KMIP batch item limit");
    if (requests.isEmpty()) throw new IllegalArgumentException("Empty batch");
    List<Ttlv> header = new ArrayList<>();
    header.add(protocolVersion(version));
    if (options.maximumResponseSize() != null)
      header.add(integer(MAXIMUM_RESPONSE_SIZE, options.maximumResponseSize()));
    if (options.clientCorrelation() != null || options.serverCorrelation() != null) {
      if (!version.atLeast(ProtocolVersion.V1_4))
        throw new IllegalArgumentException("Correlation strings require KMIP 1.4");
      if (options.clientCorrelation() != null)
        header.add(text(CLIENT_CORRELATION_VALUE, options.clientCorrelation()));
      if (options.serverCorrelation() != null)
        header.add(text(SERVER_CORRELATION_VALUE, options.serverCorrelation()));
    }
    if (options.asynchronousMode() != null) {
      if (version.legacyAttributes())
        throw new IllegalArgumentException("Asynchronous enumeration requires KMIP 2.0+");
      header.add(enumeration(ASYNCHRONOUS_INDICATOR, options.asynchronousMode()));
    } else if (options.asynchronous() != null)
      header.add(
          version.legacyAttributes()
              ? bool(ASYNCHRONOUS_INDICATOR, options.asynchronous())
              : enumeration(
                  ASYNCHRONOUS_INDICATOR,
                  options.asynchronous()
                      ? Enums.AsynchronousIndicator.OPTIONAL
                      : Enums.AsynchronousIndicator.PROHIBITED));
    if (options.attestationCapable() != null || !options.attestationTypes().isEmpty()) {
      if (!version.atLeast(ProtocolVersion.V1_2))
        throw new IllegalArgumentException("Attestation requires KMIP 1.2");
      if (options.attestationCapable() != null)
        header.add(bool(ATTESTATION_CAPABLE_INDICATOR, options.attestationCapable()));
      header.addAll(options.attestationTypes());
    }
    if (options.authentication() != null) header.add(options.authentication());
    // KMIP 1.4 §6.12-6.13 / 2.1 §9.6: batch options apply only when Batch Count > 1, and the
    // continuation option SHALL only be present then.
    boolean batched = requests.size() > 1;
    if (options.batchError() != null && batched)
      header.add(enumeration(BATCH_ERROR_CONTINUATION_OPTION, options.batchError()));
    if (options.batchOrder() != null) {
      if (version == ProtocolVersion.V3_0 && !options.batchOrder())
        throw new IllegalArgumentException("KMIP 3.0 batches are ordered");
      if (version != ProtocolVersion.V3_0 && batched)
        header.add(bool(BATCH_ORDER_OPTION, options.batchOrder()));
    }
    if (options.timestamp() != null) header.add(dateTime(TIME_STAMP, options.timestamp()));
    if (version != ProtocolVersion.V3_0) header.add(integer(BATCH_COUNT, requests.size()));
    List<Ttlv> items = new ArrayList<>();
    items.add(Structures.canonical(version, structure(REQUEST_HEADER, header)));
    Set<String> ids = new HashSet<>();
    for (int i = 0; i < requests.size(); i++) {
      Request r = requests.get(i);
      if (r.operation() != null) r.operation().requireVersion(version);
      List<Ttlv> fields = new ArrayList<>();
      fields.add(enumeration(OPERATION, r.operationCode()));
      byte[] id = r.batchId();
      if (version == ProtocolVersion.V3_0 && id != null)
        throw new IllegalArgumentException("UniqueBatchItemID was removed in KMIP 3.0");
      // Auto-assigned IDs are the request position plus one, as a 4-byte big-endian value.
      if (id == null && requests.size() > 1 && version != ProtocolVersion.V3_0)
        id = ByteBuffer.allocate(4).putInt(i + 1).array();
      if (id != null) {
        if (!ids.add(HexFormat.of().formatHex(id)))
          throw new IllegalArgumentException("Duplicate batch ID");
        fields.add(bytes(UNIQUE_BATCH_ITEM_ID, id));
      }
      if (r.ephemeral() != null) {
        if (version != ProtocolVersion.V3_0)
          throw new IllegalArgumentException("Ephemeral requires KMIP 3.0");
        fields.add(r.ephemeral());
      }
      // A vendor operation's payload is the caller's exact wire form.
      fields.add(
          r.operation() == null
              ? r.payload()
              : VersionedPayloads.prepare(version, r.operation(), r.payload()));
      fields.addAll(r.extensions());
      items.add(structure(BATCH_ITEM, fields));
    }
    Ttlv message = structure(REQUEST_MESSAGE, items);
    VersionValidator.validate(version, message);
    return message;
  }

  public static Response response(Ttlv root) throws IOException {
    return response(root, MAX_BATCH_ITEMS);
  }

  public static Response response(Ttlv root, int maximumBatchItems) throws IOException {
    if (maximumBatchItems < 1) throw new IllegalArgumentException("Invalid batch item limit");
    try {
      if (root.tag() != RESPONSE_MESSAGE.code())
        throw new IOException("Expected KMIP ResponseMessage");
      Ttlv header = need(root, RESPONSE_HEADER);
      need(header, PROTOCOL_VERSION);
      need(header, TIME_STAMP);
      requireSingletons(
          header,
          PROTOCOL_VERSION,
          TIME_STAMP,
          BATCH_COUNT,
          CLIENT_CORRELATION_VALUE,
          SERVER_CORRELATION_VALUE);
      ProtocolVersion version = version(header);
      List<Ttlv> batches = root.children(BATCH_ITEM);
      if (batches.size() > maximumBatchItems)
        throw new IOException("KMIP response batch item limit");
      if ((version != ProtocolVersion.V3_0
              && need(header, BATCH_COUNT).intValue() != batches.size())
          || batches.isEmpty()) throw new IOException("Response batch count mismatch");
      List<Result> results = new ArrayList<>();
      for (Ttlv batch : batches) {
        requireSingletons(
            batch,
            OPERATION,
            UNIQUE_BATCH_ITEM_ID,
            RESULT_STATUS,
            RESULT_REASON,
            RESULT_MESSAGE,
            ASYNCHRONOUS_CORRELATION_VALUE,
            RESPONSE_PAYLOAD);
        // A vendor or future operation code has no constant; Result.operationCode() keeps it.
        Operation op =
            batch
                .child(OPERATION)
                .flatMap(n -> WireEnums.fromCode(Operation.class, n.intValue()))
                .orElse(null);
        int status = need(batch, RESULT_STATUS).intValue();
        if (status < 0 || status > 3) throw new IOException("Invalid result status");
        Integer reason = batch.child(RESULT_REASON).map(Ttlv::intValue).orElse(null);
        if (status == 1 && reason == null)
          throw new IOException("Failed result missing ResultReason");
        if (status == 2 && batch.child(ASYNCHRONOUS_CORRELATION_VALUE).isEmpty())
          throw new IOException("Pending result missing correlation value");
        results.add(
            new Result(
                op,
                status,
                reason,
                batch.child(RESULT_MESSAGE).map(Ttlv::textValue).orElse(null),
                batch));
      }
      return new Response(version, header.require(TIME_STAMP).instantValue(), results, root);
    } catch (IllegalArgumentException | IllegalStateException e) {
      // Accessor messages can quote response values: keep only fixed text and a redacted cause.
      throw new IOException(
          "Invalid KMIP response", dev.keytend.kmip.codec.DecodeException.redact(e));
    }
  }

  /** A required field; the message names tags only, never a value. */
  private static Ttlv need(Ttlv structure, Tag tag) throws IOException {
    Optional<Ttlv> field = structure.child(tag);
    if (field.isEmpty()) throw new IOException(structure.tagName() + " missing " + tag.wireName());
    return field.get();
  }

  private static void requireSingletons(Ttlv structure, Tag... tags) throws IOException {
    for (Tag tag : tags)
      if (structure.children(tag).size() > 1)
        throw new IOException("Duplicate singleton " + tag.wireName());
  }

  /**
   * Enforce message correlation before handing results to an application.
   *
   * <p>Checks the protocol version, batch IDs (1.x/2.x) or positions (3.0), the operation of each
   * item, the Required fields of each successful payload in the version's payload table, the
   * identifier and Object Type it echoes (see {@code checkPayload}), and a Client Correlation
   * Value when the server echoes one (echoing it is optional for client-to-server operations, KMIP
   * 1.4 §6.18 and 2.1 §9.9). A response shorter than the request is accepted only when the server
   * stopped at a failed item under the Stop or Undo option: with Undo every returned item before it
   * must be Undone (KMIP 1.4 §6.13 and Table 366). The returned response records which request each
   * result answers; see {@link Response#resultFor(int)}.
   *
   * <p>A Poll response may carry Poll or the operation that was originally submitted asynchronously
   * (KMIP 2.1 §6.1.38 makes a completed Poll response identical to the synchronous response), so
   * any operation is accepted for a Poll item; {@link KmipClient#poll(byte[], Operation)} narrows
   * it to the expected one.
   */
  public static Response correlate(Ttlv request, Response response) throws IOException {
    if (version(request.require(REQUEST_HEADER)) != response.version())
      throw new IOException("Response protocol version mismatch");
    List<Ttlv> requested = request.children(BATCH_ITEM);
    Optional<Ttlv> client = request.require(REQUEST_HEADER).child(CLIENT_CORRELATION_VALUE);
    Optional<String> echoed = response.clientCorrelation();
    if (client.isPresent() && echoed.isPresent() && !echoed.get().equals(client.get().textValue()))
      throw new IOException("Client correlation mismatch");
    // A whole-message failure cannot correlate operations that were never parsed/executed.
    if (response.results().size() == 1) {
      Result only = response.results().get(0);
      if (only.status() == 1
          && only.operationCode().isEmpty()
          && only.batchId().isEmpty()
          && only.payload().isEmpty())
        return new Response(
            response.version(),
            response.timestamp(),
            response.results(),
            response.message(),
            List.of(-1),
            requested.size());
    }
    if (response.results().size() > requested.size())
      throw new IOException("Too many response batch items");
    int continuation =
        request
            .require(REQUEST_HEADER)
            .child(BATCH_ERROR_CONTINUATION_OPTION)
            .map(Ttlv::intValue)
            .orElse(2);
    boolean truncated = response.results().size() != requested.size();
    if (truncated && continuation != 2 && continuation != 3)
      throw new IOException("Incomplete batch response");
    Map<String, Integer> ids = new HashMap<>();
    for (int i = 0; i < requested.size(); i++) {
      int index = i;
      requested
          .get(i)
          .child(UNIQUE_BATCH_ITEM_ID)
          .ifPresent(n -> ids.put(HexFormat.of().formatHex(n.bytesValue()), index));
    }
    Set<String> seen = new HashSet<>();
    List<Integer> indexes = new ArrayList<>();
    for (int i = 0; i < response.results().size(); i++) {
      Result r = response.results().get(i);
      int index = i;
      if (!ids.isEmpty()) {
        byte[] id = r.batchId().orElseThrow(() -> new IOException("Missing response batch ID"));
        String key = HexFormat.of().formatHex(id);
        if (!seen.add(key) || !ids.containsKey(key))
          throw new IOException("Unknown or duplicate response batch ID");
        index = ids.get(key);
      } else if (r.batchId().isPresent()) throw new IOException("Unexpected response batch ID");
      Ttlv expected = requested.get(index);
      indexes.add(index);
      int requestedOperation = expected.require(OPERATION).intValue();
      // A message-level error can omit Operation. It is still returned as an inspectable failure.
      OptionalInt returnedOperation = r.operationCode();
      if (returnedOperation.isEmpty() && r.successful())
        throw new IOException("Successful response missing operation");
      if (returnedOperation.isPresent()
          && returnedOperation.getAsInt() != requestedOperation
          && requestedOperation != Operation.POLL.code())
        throw new IOException("Response operation mismatch");
      checkPayload(response.version(), expected.require(REQUEST_PAYLOAD), r);
    }
    if (truncated) checkTruncated(request, response.results(), indexes, continuation);
    return new Response(
        response.version(),
        response.timestamp(),
        response.results(),
        response.message(),
        indexes,
        requested.size());
  }

  /**
   * A batch the server ended early under Stop (2, the default) or Undo (3): exactly one returned
   * item failed and it ended the batch; under Stop every other returned item succeeded (or is
   * Pending), under Undo every other one was Undone. When the batch is ordered (Batch Order Option
   * True, its default from 2.0, or KMIP 3.0) the returned items must also be the request's prefix, so an
   * omitted item really was not executed: a response that leaves out a processed item in the middle
   * is rejected instead of reading as "not executed" through {@link Response#resultFor(int)}.
   */
  private static void checkTruncated(
      Ttlv request, List<Result> results, List<Integer> indexes, int continuation)
      throws IOException {
    int failed = -1;
    for (int i = 0; i < results.size(); i++) {
      int status = results.get(i).status();
      if (status == 1) {
        if (failed >= 0)
          throw new IOException("Truncated batch response has more than one failure");
        failed = indexes.get(i);
      } else if (continuation == 2 ? status == 3 : status != 3)
        throw new IOException(
            continuation == 2
                ? "Truncated Stop response has an item that was undone"
                : "Truncated Undo response has an item that was not undone");
    }
    if (failed < 0) throw new IOException("Incomplete batch response without a failure");
    Ttlv header = request.require(REQUEST_HEADER);
    // Batch Order Option defaults to False in 1.x (1.4 section 6.12) and True from 2.0 (2.1 section
    // 9.8); 3.0 batches are always ordered.
    ProtocolVersion version = version(header);
    boolean ordered =
        version == ProtocolVersion.V3_0
            || header
                .child(BATCH_ORDER_OPTION)
                .map(Ttlv::booleanValue)
                .orElse(!version.legacyAttributes());
    if (ordered) {
      List<Integer> sorted = new ArrayList<>(indexes);
      Collections.sort(sorted);
      for (int i = 0; i < sorted.size(); i++)
        if (sorted.get(i) != i)
          throw new IOException("Truncated ordered batch response is not a prefix of the request");
      if (failed != sorted.size() - 1)
        throw new IOException("Truncated ordered batch response continued after its failure");
    }
  }

  /** Operations on an existing object: a successful response echoes its Unique Identifier. */
  private static final Set<Operation> ECHOES_IDENTIFIER =
      EnumSet.of(
          Operation.CHECK,
          Operation.GET,
          Operation.GET_ATTRIBUTES,
          Operation.GET_ATTRIBUTE_LIST,
          Operation.ADD_ATTRIBUTE,
          Operation.MODIFY_ATTRIBUTE,
          Operation.DELETE_ATTRIBUTE,
          Operation.SET_ATTRIBUTE,
          Operation.ADJUST_ATTRIBUTE,
          Operation.OBTAIN_LEASE,
          Operation.GET_USAGE_ALLOCATION,
          Operation.ACTIVATE,
          Operation.DEACTIVATE,
          Operation.REVOKE,
          Operation.DESTROY,
          Operation.ARCHIVE,
          Operation.RECOVER,
          Operation.ENCRYPT,
          Operation.DECRYPT,
          Operation.SIGN,
          Operation.SIGNATURE_VERIFY,
          Operation.MAC,
          Operation.MAC_VERIFY,
          Operation.EXPORT);

  /**
   * The Required fields of each successful response payload, by version and operation, from the
   * payload tables (KMIP 1.x section 4, 2.x and 3.0 section 6; {@code payloads.tsv}). Built once,
   * so a required field the client cannot look for fails loudly instead of going unchecked.
   */
  private static final Map<String, List<Required>> REQUIRED = requiredFields();

  /**
   * A Required response field. The table's object field ("Any Object", or the 1.x list of object
   * types) has no tag: any managed object satisfies it. A field marked "Yes for single-part. No for
   * multi-part." is required only when the request is not a part of a multi-part operation. (The
   * 1.3 and 1.4 Signature Verify and MAC Verify tables mark Validity Indicator plain "Yes", so
   * there every part carries one, Unknown until the verdict.)
   */
  private record Required(Tag tag, boolean singlePartOnly) {
    boolean presentIn(Ttlv payload) {
      return tag != null
          ? payload.child(tag).isPresent()
          : payload.children().stream().anyMatch(Messages::managedObject);
    }

    String wireName() {
      return tag != null ? tag.wireName() : "its object";
    }
  }

  private static Map<String, List<Required>> requiredFields() {
    Map<String, List<Required>> required = new HashMap<>();
    for (ProtocolVersion version : ProtocolVersion.values())
      for (Operation op : Operation.values())
        for (ProtocolSchema.Field field :
            ProtocolSchema.fields(version, op, ProtocolSchema.Direction.RESPONSE)) {
          // "Yes", "Yes, MAY be repeated", "Yes, is repeated", "Yes, unless a failure," (a failed
          // Check is not a successful result) and "Yes for single-part. No for multi-part[.]".
          String rule = field.requirement();
          if (!rule.startsWith("Yes")) continue;
          Tag tag = field.tag().orElse(null);
          if (tag == null
              && !field.name().startsWith("Any Object")
              && !field.name().endsWith(" or Opaque Object"))
            throw new IllegalStateException("Unchecked required response field " + field.name());
          required
              .computeIfAbsent(version.code() + ":" + op.wireName(), k -> new ArrayList<>())
              .add(new Required(tag, rule.startsWith("Yes for single-part")));
        }
    required.replaceAll((k, v) -> List.copyOf(v));
    return Map.copyOf(required);
  }

  private static boolean managedObject(Ttlv field) {
    try {
      ManagedObjects.objectType(field);
      return true;
    } catch (IllegalArgumentException notAnObject) {
      return false;
    }
  }

  /**
   * Validates a successful response payload against the version's payload table ({@link
   * #REQUIRED}) and checks the identifier it echoes. Every operation on an existing object must
   * return that object's Unique Identifier, and the same one when the request named it concretely
   * (so a MAC Verify verdict about another key is refused). Only the request makes an item a part
   * of a multi-part operation (Init Indicator, Final Indicator or Correlation Value, KMIP 1.4
   * Tables 230-240 and 2.1 section 6.1): a Correlation Value the server adds to the response of a
   * single-part request exempts nothing. This guards against mis-correlation and malformed
   * acknowledgments from a buggy server or relay; it does not authenticate the response. Only
   * textual identifiers are compared: an ID Placeholder enumeration, an integer index or a 3.0 Name
   * Reference does not name the object the server will resolve.
   *
   * <p>A created object's Object Type must be the requested one ({@link #ECHOES_OBJECT_TYPE}), and
   * the managed object a Get or Export returns must be of the Object Type it declares. Whether that
   * type is the one the caller expected is not decided here: a Get request names no type.
   */
  private static void checkPayload(ProtocolVersion version, Ttlv requestPayload, Result r)
      throws IOException {
    Operation op = r.operation();
    if (!r.successful() || op == null) return;
    Optional<Ttlv> payload = r.payload();
    // KMIP 1.4 Table 285, 2.1 §9 and 3.0 §8.2.3: the Response Payload is required unless the item
    // failed, even when every field of the operation's payload is optional (Locate, Query).
    if (payload.isEmpty())
      throw new IOException(op.wireName() + " response missing ResponsePayload");
    // KMIP 1.4 §2.1.15: the server returns the Correlation Value in the first response of a
    // multi-part operation. A reply without one was not continued, and its next part would start
    // another operation.
    if (requestPayload.child(INIT_INDICATOR).map(Ttlv::booleanValue).orElse(false)
        && !requestPayload.child(FINAL_INDICATOR).map(Ttlv::booleanValue).orElse(false)
        && payload.get().child(CORRELATION_VALUE).isEmpty())
      throw new IOException(op.wireName() + " response missing CorrelationValue");
    if (ECHOES_IDENTIFIER.contains(op)) {
      Optional<Ttlv> returnedId = payload.flatMap(p -> p.child(UNIQUE_IDENTIFIER));
      if (returnedId.isEmpty())
        throw new IOException(op.wireName() + " response missing UniqueIdentifier");
      Optional<Ttlv> requestedId = requestPayload.child(UNIQUE_IDENTIFIER);
      if (requestedId.isPresent()
          && concreteIdentifier(requestedId.get())
          && (!textual(returnedId.get())
              || !requestedId.get().textValue().equals(returnedId.get().textValue())))
        throw new IOException(op.wireName() + " response names another object");
    }
    boolean multipart =
        requestPayload.child(CORRELATION_VALUE).isPresent()
            || requestPayload.child(INIT_INDICATOR).isPresent()
            || requestPayload.child(FINAL_INDICATOR).isPresent();
    for (Required field : REQUIRED.getOrDefault(version.code() + ":" + op.wireName(), List.of()))
      if (!(multipart && field.singlePartOnly()) && !field.presentIn(payload.get()))
        throw new IOException(op.wireName() + " response missing " + field.wireName());
    Optional<Ttlv> returnedType = payload.get().child(OBJECT_TYPE);
    if (returnedType.isEmpty()) return;
    Optional<Ttlv> requestedType = requestPayload.child(OBJECT_TYPE);
    if (ECHOES_OBJECT_TYPE.contains(op)
        && requestedType.isPresent()
        && requestedType.get().type() == Ttlv.Type.ENUMERATION
        && !sameEnumeration(requestedType.get(), returnedType.get()))
      throw new IOException(op.wireName() + " response has another ObjectType");
    if (RETURNS_OBJECT.contains(op))
      for (Ttlv child : payload.get().children())
        if (managedObject(child)
            && !sameEnumeration(
                enumeration(OBJECT_TYPE, ManagedObjects.objectType(child)), returnedType.get()))
          throw new IOException(op.wireName() + " response object does not match its ObjectType");
  }

  /**
   * Operations that create an object of the requested Object Type. Where the response table has an
   * Object Type (Create in every version; Create Split Key and Join Split Key in 1.2), it is the
   * type created and must be the requested one: otherwise the returned identifier may name some
   * other object, which a caller would then activate or use as the requested kind. Register and
   * Create Key Pair responses carry no Object Type in any version (1.4 Tables 167 and 170, 2.1
   * Tables 190 and 292, 3.0 Tables 284 and 401), so their identifiers cannot be checked here (a
   * Register response that adds one anyway must still name the requested type).
   */
  private static final Set<Operation> ECHOES_OBJECT_TYPE =
      EnumSet.of(
          Operation.CREATE,
          Operation.REGISTER,
          Operation.CREATE_SPLIT_KEY,
          Operation.JOIN_SPLIT_KEY);

  /** Operations whose response returns a managed object next to its Object Type. */
  private static final Set<Operation> RETURNS_OBJECT = EnumSet.of(Operation.GET, Operation.EXPORT);

  private static boolean sameEnumeration(Ttlv a, Ttlv b) {
    return a.type() == Ttlv.Type.ENUMERATION
        && b.type() == Ttlv.Type.ENUMERATION
        && a.intValue() == b.intValue();
  }

  private static boolean concreteIdentifier(Ttlv id) {
    return (id.type() == Ttlv.Type.TEXT_STRING
            || id.type() == Ttlv.Type.IDENTIFIER
            || id.type() == Ttlv.Type.REFERENCE)
        && !id.textValue().isEmpty();
  }

  private static boolean textual(Ttlv id) {
    return id.type() == Ttlv.Type.TEXT_STRING
        || id.type() == Ttlv.Type.IDENTIFIER
        || id.type() == Ttlv.Type.REFERENCE
        || id.type() == Ttlv.Type.NAME_REFERENCE;
  }
}
