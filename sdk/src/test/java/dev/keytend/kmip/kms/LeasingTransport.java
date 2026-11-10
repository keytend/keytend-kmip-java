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

import dev.keytend.kmip.model.Attributes;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;

/**
 * Fakes and records KMIP leases in front of an {@link InMemoryKmipServer}: its Get Attributes
 * replies state a Lease Time for the objects the test gives one (or for every object, {@link
 * #everyObject}), and it answers Obtain Lease as {@link #answer} says, recording each identifier
 * asked for. Everything else goes to the server unchanged. A test that only needs a server that
 * leases uses the server's own emulation ({@link InMemoryKmipServer#leaseTime}, {@link
 * InMemoryKmipServer#leasesOnlyForActive}) instead; through this transport its Obtain Lease answers
 * pass unchanged (and are recorded) for every object this transport states no Lease Time for, while
 * {@link #answer} is the default.
 */
final class LeasingTransport implements KmipTransport {
  /** How Obtain Lease answers for one object. */
  sealed interface Answer {}

  /** A lease of {@code seconds} (0: no limit). */
  record Grant(long seconds) implements Answer {}

  /** A failure result with {@code reason}. */
  record Refuse(Enums.ResultReason reason) implements Answer {}

  /** A success whose payload is {@code payload(id)}: malformed on purpose. */
  record Malformed(Function<String, List<Ttlv>> payload) implements Answer {}

  /** The request hangs until the exchange's deadline (the in-memory server's {@link Fault#HANG}). */
  record Hang() implements Answer {}

  /**
   * A message-level failure, Invalid Message: a server that cannot parse Obtain Lease at all
   * ("unsupported operation: ObtainLease").
   */
  record NotUnderstood() implements Answer {}

  /** Whether Query Operations lists Obtain Lease (the in-memory server does not implement it). */
  volatile boolean listsObtainLease;

  /** Query requests seen. */
  final AtomicInteger queries = new AtomicInteger();

  final InMemoryKmipServer server;

  /** Stated Lease Time by identifier, in seconds. */
  final Map<String, Long> leaseTimes = new ConcurrentHashMap<>();

  /** Stated for objects not in {@link #leaseTimes}; null for none. */
  volatile Long everyObject;

  /** Keys whose attributes state Usage Limits; allocations are intentionally not simulated. */
  final java.util.Set<String> usageLimited = ConcurrentHashMap.newKeySet();

  final java.util.Set<String> signingForbidden = ConcurrentHashMap.newKeySet();

  /** Non-conformant encoding for the Lease Time hardening tests. */
  volatile boolean integerLeaseTime;

  /** The default {@link #answer}. */
  private final Function<String, Answer> byDefault =
      id -> new Grant(stated(id) == null ? 0 : stated(id));

  /**
   * The answer to an Obtain Lease of an identifier; by default its stated Lease Time (the server's
   * own answer when this transport states none and the server leases).
   */
  volatile Function<String, Answer> answer = byDefault;

  /**
   * Whether a grant names the object exactly as the request did (on KMIP 3.0 the draft's Reference
   * type); by default as keytend-kmip-server does (a Text String, or on 3.0 the Identifier type).
   */
  volatile boolean echoIdentifier;

  /** Run as each Obtain Lease request arrives (to move a clock, or hold the request). */
  volatile Runnable onObtain = () -> {};

  /** Run as each request arrives, before the server (which it may hold, as a network that stalls). */
  volatile java.util.function.Consumer<Ttlv> beforeEach = request -> {};

  /** Every identifier asked for with Obtain Lease, in order. */
  final List<String> obtained = new CopyOnWriteArrayList<>();

  final AtomicInteger obtainRequests = new AtomicInteger();

  /** Every request item that names an object, in order: its operation's wire name and the identifier. */
  final List<String> trace = new CopyOnWriteArrayList<>();

  LeasingTransport(InMemoryKmipServer server) {
    this.server = server;
  }

  Long stated(String id) {
    Long l = leaseTimes.get(id);
    return l != null ? l : everyObject;
  }

  /** Whether Obtain Lease requests are lost (no connection). */
  volatile boolean dropObtains;

  /** Clears what was recorded. */
  void reset() {
    obtained.clear();
    obtainRequests.set(0);
    trace.clear();
  }

  @Override
  public Ttlv exchange(Ttlv request) throws IOException {
    return exchange(request, CallContext.NONE);
  }

  @Override
  public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
    beforeEach.accept(request);
    List<Ttlv> items = request.children(Tag.BATCH_ITEM);
    for (Ttlv item : items) {
      Ttlv id =
          item.child(Tag.REQUEST_PAYLOAD).flatMap(p -> p.child(Tag.UNIQUE_IDENTIFIER)).orElse(null);
      if (id != null)
        trace.add(
            dev.keytend.kmip.model.WireEnums.fromCode(
                        Operation.class, item.require(Tag.OPERATION).intValue())
                    .map(Operation::wireName)
                    .orElse("?")
                + " "
                + id.textValue());
    }
    boolean leasing = !items.isEmpty();
    for (Ttlv item : items)
      leasing &= item.require(Tag.OPERATION).intValue() == Operation.OBTAIN_LEASE.code();
    List<Answer> answers = new ArrayList<>();
    if (leasing && dropObtains) throw new java.net.ConnectException("Obtain Lease unanswered");
    if (leasing) {
      obtainRequests.incrementAndGet();
      onObtain.run();
      for (Ttlv item : items) {
        String id = item.require(Tag.REQUEST_PAYLOAD).require(Tag.UNIQUE_IDENTIFIER).textValue();
        obtained.add(id);
        // Null: the server's own answer, unless it does not lease (Operation Not Supported).
        Answer a = answer == byDefault && stated(id) == null ? null : answer.apply(id);
        if (a instanceof Hang) server.failNext(ServerOperation.ANY, Fault.HANG);
        answers.add(a);
      }
    }
    // The in-memory server answers Obtain Lease with Operation Not Supported: its replies' headers
    // and item fields are kept, and each result replaced.
    Ttlv response = server.exchange(request, context);
    List<Ttlv> top = new ArrayList<>();
    int index = 0;
    for (Ttlv field : response.children()) {
      if (field.tag() != Tag.BATCH_ITEM.code()) {
        top.add(field);
        continue;
      }
      Ttlv item = items.get(index);
      Answer a = leasing ? answers.get(index) : null;
      if (leasing && a == null && !notSupported(field)) top.add(field);
      else
        top.add(
            leasing
                ? leased(
                    field,
                    item,
                    a != null
                        ? a
                        : byDefault.apply(
                            item.require(Tag.REQUEST_PAYLOAD)
                                .require(Tag.UNIQUE_IDENTIFIER)
                                .textValue()))
                : stated(field, item));
      index++;
    }
    return Ttlv.structure(response.tag(), top);
  }

  /** Whether the server answered Operation Not Supported: it does not lease. */
  private static boolean notSupported(Ttlv responseItem) {
    return responseItem
        .child(Tag.RESULT_REASON)
        .map(r -> r.intValue() == Enums.ResultReason.OPERATION_NOT_SUPPORTED.code())
        .orElse(false);
  }

  private static List<Ttlv> header(Ttlv responseItem) {
    List<Ttlv> fields = new ArrayList<>();
    for (Ttlv f : responseItem.children())
      if (f.tag() != Tag.RESPONSE_PAYLOAD.code()
          && f.tag() != Tag.RESULT_STATUS.code()
          && f.tag() != Tag.RESULT_REASON.code()
          && f.tag() != Tag.RESULT_MESSAGE.code()) fields.add(f);
    return fields;
  }

  private Ttlv leased(Ttlv responseItem, Ttlv requestItem, Answer answer) {
    Ttlv asked = requestItem.require(Tag.REQUEST_PAYLOAD).require(Tag.UNIQUE_IDENTIFIER);
    String id = asked.textValue();
    Ttlv named =
        echoIdentifier || asked.type() == Ttlv.Type.TEXT_STRING
            ? asked
            : Ttlv.of(Tag.UNIQUE_IDENTIFIER.code(), Ttlv.Type.IDENTIFIER, id);
    List<Ttlv> fields = header(responseItem);
    if (answer instanceof NotUnderstood) {
      List<Ttlv> bare = new ArrayList<>();
      for (Ttlv f : fields)
        if (f.tag() != Tag.OPERATION.code() && f.tag() != Tag.UNIQUE_BATCH_ITEM_ID.code())
          bare.add(f);
      bare.add(Ttlv.enumeration(Tag.RESULT_STATUS, Enums.ResultStatus.OPERATION_FAILED));
      bare.add(Ttlv.enumeration(Tag.RESULT_REASON, Enums.ResultReason.INVALID_MESSAGE));
      bare.add(
          Ttlv.text(
              Tag.RESULT_MESSAGE,
              "Failed to parse RequestMessage: unsupported operation: ObtainLease"));
      return Ttlv.structure(Tag.BATCH_ITEM, bare);
    }
    if (answer instanceof Refuse r) {
      fields.add(Ttlv.enumeration(Tag.RESULT_STATUS, Enums.ResultStatus.OPERATION_FAILED));
      fields.add(Ttlv.enumeration(Tag.RESULT_REASON, r.reason()));
      fields.add(Ttlv.text(Tag.RESULT_MESSAGE, "lease refused for " + id));
      return Ttlv.structure(Tag.BATCH_ITEM, fields);
    }
    List<Ttlv> payload =
        answer instanceof Malformed m
            ? m.payload().apply(id)
            : List.of(
                named,
                Ttlv.interval(Tag.LEASE_TIME, ((Grant) answer).seconds()),
                Ttlv.dateTime(
                    Tag.LAST_CHANGE_DATE, Instant.ofEpochSecond(Instant.now().getEpochSecond())));
    fields.add(Ttlv.enumeration(Tag.RESULT_STATUS, Enums.ResultStatus.SUCCESS));
    fields.add(Ttlv.structure(Tag.RESPONSE_PAYLOAD, payload));
    return Ttlv.structure(Tag.BATCH_ITEM, fields);
  }

  /** A Get Attributes result with the object's Lease Time added, in the form of the reply's version. */
  private Ttlv stated(Ttlv responseItem, Ttlv requestItem) {
    if (requestItem.require(Tag.OPERATION).intValue() == Operation.QUERY.code()) {
      queries.incrementAndGet();
      Ttlv payload = responseItem.child(Tag.RESPONSE_PAYLOAD).orElse(null);
      if (!listsObtainLease || payload == null) return responseItem;
      List<Ttlv> ops = new ArrayList<>(payload.children());
      ops.add(Ttlv.enumeration(Tag.OPERATION, Operation.OBTAIN_LEASE));
      List<Ttlv> fields = new ArrayList<>();
      for (Ttlv f : responseItem.children())
        fields.add(
            f.tag() == Tag.RESPONSE_PAYLOAD.code() ? Ttlv.structure(Tag.RESPONSE_PAYLOAD, ops) : f);
      return Ttlv.structure(Tag.BATCH_ITEM, fields);
    }
    if (requestItem.require(Tag.OPERATION).intValue() != Operation.GET_ATTRIBUTES.code())
      return responseItem;
    Ttlv payload = responseItem.child(Tag.RESPONSE_PAYLOAD).orElse(null);
    if (payload == null) return responseItem;
    String id = payload.require(Tag.UNIQUE_IDENTIFIER).textValue();
    Long lease = stated(id);
    List<Ttlv> added = new ArrayList<>();
    if (lease != null)
      added.add(
          integerLeaseTime
              ? Ttlv.integer(Tag.LEASE_TIME, lease.intValue())
              : Ttlv.interval(Tag.LEASE_TIME, lease));
    if (usageLimited.contains(id))
      added.add(
          Ttlv.structure(
              Tag.USAGE_LIMITS,
              Ttlv.longInteger(Tag.USAGE_LIMITS_TOTAL, 1),
              Ttlv.longInteger(Tag.USAGE_LIMITS_COUNT, 1),
              Ttlv.enumeration(Tag.USAGE_LIMITS_UNIT, 2)));
    if (added.isEmpty() && !signingForbidden.contains(id)) return responseItem;
    List<Ttlv> children = new ArrayList<>();
    boolean modern = payload.child(Tag.ATTRIBUTES).isPresent();
    for (Ttlv c : payload.children())
      if (modern && c.tag() == Tag.ATTRIBUTES.code()) {
        List<Ttlv> attributes = new ArrayList<>(c.children());
        if (signingForbidden.contains(id))
          attributes.replaceAll(
              a ->
                  a.tag() == Tag.CRYPTOGRAPHIC_USAGE_MASK.code()
                      ? Ttlv.integer(Tag.CRYPTOGRAPHIC_USAGE_MASK, 0)
                      : a);
        attributes.addAll(added);
        children.add(Ttlv.structure(Tag.ATTRIBUTES, attributes));
      } else if (!modern
          && signingForbidden.contains(id)
          && c.tag() == Tag.ATTRIBUTE.code()
          && c.child(Tag.ATTRIBUTE_NAME)
              .map(Ttlv::textValue)
              .orElse("")
              .equals("Cryptographic Usage Mask"))
        children.add(
            Attributes.attribute(
                "Cryptographic Usage Mask", Ttlv.integer(Tag.CRYPTOGRAPHIC_USAGE_MASK, 0)));
      else children.add(c);
    if (!modern)
      for (Ttlv attribute : added)
        children.add(
            Attributes.attribute(
                attribute.tag() == Tag.LEASE_TIME.code() ? "Lease Time" : "Usage Limits",
                attribute));
    List<Ttlv> fields = new ArrayList<>();
    for (Ttlv f : responseItem.children())
      fields.add(
          f.tag() == Tag.RESPONSE_PAYLOAD.code()
              ? Ttlv.structure(Tag.RESPONSE_PAYLOAD, children)
              : f);
    return Ttlv.structure(Tag.BATCH_ITEM, fields);
  }
}
