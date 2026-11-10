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
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.model.WireEnums;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link KmsKeys#moveName} sends one ordered Undo batch that moves exactly one Name value, never
 * resends or splits it, and settles every outcome by reading both objects back within the one call
 * deadline.
 */
class KmsKeysMoveNameTest {
  static final String NAME = "orders-write";

  /** What the client's transport does with a request; by default, the server's answer. */
  @FunctionalInterface
  interface Hook {
    Ttlv exchange(Ttlv request, CallContext context, InMemoryKmipServer server) throws IOException;
  }

  static final class Fixture implements AutoCloseable {
    final InMemoryKmipServer server;
    final Kms admin, client;
    final KmipVersion version;

    /** Every request message the client sent, from the end of its connect. */
    final List<Ttlv> sent = new CopyOnWriteArrayList<>();

    final KmsEventStepTest.Recorder events = new KmsEventStepTest.Recorder();
    volatile Hook hook = (r, c, s) -> s.exchange(r, c);

    Fixture(KmipVersion version) {
      this(version, Duration.ofSeconds(5));
    }

    Fixture(KmipVersion version, Duration callTimeout) {
      this.version = version;
      server = InMemoryKmipServer.of(version);
      admin = server.connect();
      KmipTransport transport =
          new KmipTransport() {
            @Override
            public Ttlv exchange(Ttlv request) throws IOException {
              return exchange(request, CallContext.NONE);
            }

            @Override
            public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
              sent.add(request);
              return hook.exchange(request, context, server);
            }
          };
      client =
          Kms.connect(
              server
                  .configure()
                  .retryPolicy(RetryPolicy.none())
                  .callTimeout(callTimeout)
                  .addListener(events)
                  .transport(e -> transport)
                  .build());
      sent.clear();
      events.events.clear();
      events.heard.clear();
    }

    /** A key named {@code names}, in that order (so on 1.x the i-th has Attribute Index i). */
    KeyHandle key(String... names) {
      KeyCreation c = admin.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
      if (version.compareTo(KmipVersion.V1_4) >= 0) c.extractable(true);
      KeyHandle key = c.create();
      for (String n : names) key.addName(n);
      return key;
    }

    List<String> names(KeyHandle key) {
      return admin.keys().handle(key.id()).attributes().names();
    }

    /** The requests sent that change something: anything but Get Attributes. */
    List<Ttlv> mutations() {
      return sent.stream()
          .filter(r -> !operations(r).equals(List.of(Operation.GET_ATTRIBUTES)))
          .toList();
    }

    @Override
    public void close() {
      client.close();
      admin.close();
      server.close();
    }
  }

  static List<Operation> operations(Ttlv request) {
    List<Operation> ops = new ArrayList<>();
    for (Ttlv item : request.children(BATCH_ITEM))
      ops.add(
          WireEnums.fromCode(Operation.class, item.require(OPERATION).intValue()).orElseThrow());
    return ops;
  }

  /** Every text value of {@code tag} anywhere in {@code t}. */
  static List<String> texts(Ttlv t, Tag tag) {
    List<String> out = new ArrayList<>();
    if (t.tag() == tag.code()) out.add(t.textValue());
    if (t.type() == Ttlv.Type.STRUCTURE) for (Ttlv c : t.children()) out.addAll(texts(c, tag));
    return out;
  }

  static boolean isBatch(Ttlv request) {
    return operations(request).contains(Operation.DELETE_ATTRIBUTE);
  }

  /** {@code message} with {@code items} as its batch items (and a matching Batch Count). */
  static Ttlv withItems(Ttlv message, List<Ttlv> items) {
    List<Ttlv> out = new ArrayList<>();
    for (Ttlv c : message.children()) {
      if (c.tag() == BATCH_ITEM.code()) continue;
      if (c.tag() == RESPONSE_HEADER.code())
        c = replace(c, BATCH_COUNT, Ttlv.integer(BATCH_COUNT, items.size()));
      out.add(c);
    }
    out.addAll(items);
    return Ttlv.structure(message.tag(), out);
  }

  /** {@code structure} with its {@code tag} child replaced by {@code value} (or without it, for null). */
  static Ttlv replace(Ttlv structure, Tag tag, Ttlv value) {
    List<Ttlv> out = new ArrayList<>();
    for (Ttlv c : structure.children()) {
      if (c.tag() != tag.code()) out.add(c);
      else if (value != null) out.add(value);
    }
    return Ttlv.structure(structure.tag(), out);
  }

  /** A response item for request item {@code index} of {@code request} with only a status. */
  static Ttlv item(Ttlv request, int index, int status, Ttlv... extra) {
    Ttlv requested = request.children(BATCH_ITEM).get(index);
    List<Ttlv> fields = new ArrayList<>();
    fields.add(requested.require(OPERATION));
    requested.child(UNIQUE_BATCH_ITEM_ID).ifPresent(fields::add);
    fields.add(Ttlv.enumeration(RESULT_STATUS, status));
    fields.addAll(List.of(extra));
    return Ttlv.structure(BATCH_ITEM, fields);
  }

  /** The batch, refused on its delete by the server, answered with {@code items} instead. */
  static Hook refusedThenAnswered(java.util.function.BiFunction<Ttlv, Ttlv, List<Ttlv>> items) {
    return (r, c, s) -> {
      if (!isBatch(r)) return s.exchange(r, c);
      s.failNext(ServerOperation.DELETE_ATTRIBUTE, Fault.PERMISSION_DENIED);
      Ttlv response = s.exchange(r, c);
      return withItems(response, items.apply(r, response));
    };
  }

  // ---- success and exactness ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void movesExactlyTheNameInOneOrderedUndoBatchKeepingOtherNames(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      // The write name sits between two others: Attribute Index 1 on 1.x, not 0.
      KeyHandle from = f.key("from-a", NAME, "from-b");
      KeyHandle to = f.key("to-a");
      f.client.keys().moveName(NAME, from.id(), to.id());
      assertEquals(List.of("from-a", "from-b"), f.names(from));
      assertEquals(List.of("to-a", NAME), f.names(to));
      assertEquals(KeyState.ACTIVE, from.attributes().state());
      assertEquals(KeyState.ACTIVE, to.attributes().state());

      // Two reads, the batch, two read-backs; nothing else, no lifecycle request.
      assertEquals(5, f.sent.size(), f.sent.toString());
      List<Ttlv> mutations = f.mutations();
      assertEquals(1, mutations.size());
      Ttlv batch = mutations.get(0);
      assertEquals(List.of(Operation.DELETE_ATTRIBUTE, Operation.ADD_ATTRIBUTE), operations(batch));
      Ttlv header = batch.require(REQUEST_HEADER);
      assertEquals(
          Enums.BatchErrorContinuation.UNDO.code(),
          header.require(BATCH_ERROR_CONTINUATION_OPTION).intValue());
      if (version != KmipVersion.V3_0)
        assertTrue(header.require(BATCH_ORDER_OPTION).booleanValue());
      Ttlv delete = batch.children(BATCH_ITEM).get(0).require(REQUEST_PAYLOAD);
      assertEquals(from.id(), delete.require(UNIQUE_IDENTIFIER).textValue());
      if (version == KmipVersion.V1_4) {
        assertEquals("Name", delete.require(ATTRIBUTE_NAME).textValue());
        assertEquals(1, delete.require(ATTRIBUTE_INDEX).intValue());
        assertTrue(delete.child(ATTRIBUTE).isEmpty());
      } else {
        // Selected by value, never by a bare reference that would delete every Name.
        Ttlv current = delete.require(CURRENT_ATTRIBUTE);
        // 3.0 encodes a Name as a text string, earlier versions as a structure with a Name Value.
        List<String> named = new ArrayList<>(texts(current, NAME_VALUE));
        for (Ttlv n : current.children())
          if (n.tag() == Tag.NAME.code() && n.type() != Ttlv.Type.STRUCTURE)
            named.add(n.textValue());
        assertEquals(List.of(NAME), named);
        assertTrue(delete.child(ATTRIBUTE_REFERENCE).isEmpty());
      }
      Ttlv add = batch.children(BATCH_ITEM).get(1).require(REQUEST_PAYLOAD);
      assertEquals(to.id(), add.require(UNIQUE_IDENTIFIER).textValue());

      for (KmsEvent e : f.events.events) assertEquals("moveName", e.operation(), e.toString());
      assertEquals(
          List.of("attributes", "attributes", "moveName", "attributes", "attributes"),
          f.events.steps("started"));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void orderedDeleteFirstMovesTheNameWhereNamesAreUnique(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      f.server.uniqueNames(true);
      KeyHandle from = f.key(NAME, "other"), to = f.key();
      f.client.keys().moveName(NAME, from.id(), to.id());
      assertEquals(List.of("other"), f.names(from));
      assertEquals(List.of(NAME), f.names(to));
      assertEquals(1, f.mutations().size());
    }
  }

  @Test
  void anAlreadyCompletedTransferIsObservedWithoutAChange() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key("other"), to = f.key(NAME);
      f.client.keys().moveName(NAME, from.id(), to.id());
      assertEquals(2, f.sent.size());
      assertEquals(List.of(), f.mutations());
      assertEquals(List.of(NAME), f.names(to));
    }
  }

  @Test
  void neitherOrBothHoldersAndARepeatedSourceNameAreRefusedBeforeAnyChange() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle a = f.key("x"), b = f.key("y");
      StateConflictException neither =
          assertThrows(
              StateConflictException.class, () -> f.client.keys().moveName(NAME, a.id(), b.id()));
      assertTrue(neither.getMessage().contains("neither"), neither.getMessage());
      KeyHandle c = f.key(NAME), d = f.key(NAME);
      StateConflictException both =
          assertThrows(
              StateConflictException.class, () -> f.client.keys().moveName(NAME, c.id(), d.id()));
      assertTrue(both.getMessage().contains("both"), both.getMessage());
      KeyHandle twice = f.key(NAME, NAME);
      assertEquals(List.of(NAME, NAME), f.names(twice));
      assertThrows(
          StateConflictException.class, () -> f.client.keys().moveName(NAME, twice.id(), a.id()));
      assertEquals(List.of(), f.mutations());
    }
  }

  @Test
  void badArgumentsSendNothing() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KmsKeys keys = f.client.keys();
      assertThrows(NullPointerException.class, () -> keys.moveName(null, "a", "b"));
      assertThrows(NullPointerException.class, () -> keys.moveName(NAME, null, "b"));
      assertThrows(NullPointerException.class, () -> keys.moveName(NAME, "a", null));
      assertThrows(IllegalArgumentException.class, () -> keys.moveName(" ", "a", "b"));
      assertThrows(IllegalArgumentException.class, () -> keys.moveName(NAME, "", "b"));
      assertThrows(IllegalArgumentException.class, () -> keys.moveName(NAME, "a", "\t"));
      assertThrows(IllegalArgumentException.class, () -> keys.moveName(NAME, "a", "a"));
      assertEquals(List.of(), f.sent);
    }
  }

  @Test
  void aMissingObjectAtTheFirstReadIsDefinite() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME);
      assertThrows(
          NotFoundException.class,
          () -> f.client.keys().moveName(NAME, from.id(), "no-such-object"));
      assertEquals(List.of(), f.mutations());
      assertEquals(List.of(NAME), f.names(from));
    }
  }

  @Test
  void legacyNameInstancesTheServerCannotTellApartAreRefusedBeforeSending() {
    try (Fixture f = new Fixture(KmipVersion.V1_4)) {
      KeyHandle from = f.key("other", NAME), to = f.key();
      // The server reports both Name instances without an Attribute Index (both index 0).
      f.hook =
          (r, c, s) -> {
            Ttlv response = s.exchange(r, c);
            if (!operations(r).equals(List.of(Operation.GET_ATTRIBUTES))) return response;
            List<Ttlv> items = new ArrayList<>();
            for (Ttlv item : response.children(BATCH_ITEM)) {
              Ttlv payload = item.child(RESPONSE_PAYLOAD).orElse(null);
              if (payload == null) {
                items.add(item);
                continue;
              }
              List<Ttlv> fields = new ArrayList<>();
              for (Ttlv a : payload.children())
                fields.add(a.tag() == ATTRIBUTE.code() ? replace(a, ATTRIBUTE_INDEX, null) : a);
              items.add(replace(item, RESPONSE_PAYLOAD, Ttlv.structure(RESPONSE_PAYLOAD, fields)));
            }
            return withItems(response, items);
          };
      UnsupportedException refused =
          assertThrows(
              UnsupportedException.class, () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertTrue(refused.getMessage().contains("nothing was changed"), refused.getMessage());
      assertEquals(List.of(), f.mutations());
      f.hook = (r, c, s) -> s.exchange(r, c);
      assertEquals(List.of("other", NAME), f.names(from));
    }
  }

  // ---- acknowledged refusals ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRefusedDeleteIsTypedAfterTheOriginalStateIsReadBack(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle from = f.key("other", NAME), to = f.key();
      f.server.failNext(ServerOperation.DELETE_ATTRIBUTE, Fault.PERMISSION_DENIED);
      PermissionDeniedException denied =
          assertThrows(
              PermissionDeniedException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertEquals(from.id(), denied.objectId().orElseThrow());
      assertEquals("moveName", denied.operation());
      assertEquals(Enums.ResultReason.PERMISSION_DENIED, denied.protocolReason().orElseThrow());
      assertEquals(1, f.mutations().size());
      assertEquals(5, f.sent.size());
      assertEquals(List.of("other", NAME), f.names(from));
      assertEquals(List.of(), f.names(to));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1", "V3_0"})
  void aRolledBackAddKeepsItsOwnTypedReasonNotAnUnexpectedUndone(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle from = f.key(NAME), to = f.key("other");
      f.server.failNext(
          ServerOperation.ADD_ATTRIBUTE, Enums.ResultReason.NON_UNIQUE_NAME_ATTRIBUTE);
      AlreadyExistsException refused =
          assertThrows(
              AlreadyExistsException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertEquals(to.id(), refused.objectId().orElseThrow());
      assertEquals(
          Enums.ResultReason.NON_UNIQUE_NAME_ATTRIBUTE, refused.protocolReason().orElseThrow());
      // The server's Undo restored the deleted name.
      assertEquals(List.of(NAME), f.names(from));
      assertEquals(List.of("other"), f.names(to));
      assertEquals(1, f.mutations().size());
    }
  }

  @Test
  void aRolledBackLegacyAddIsTyped() {
    try (Fixture f = new Fixture(KmipVersion.V1_4)) {
      KeyHandle from = f.key("other", NAME), to = f.key();
      f.server.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.STATE_CONFLICT);
      StateConflictException refused =
          assertThrows(
              StateConflictException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertEquals(to.id(), refused.objectId().orElseThrow());
      assertEquals(List.of("other", NAME), f.names(from));
    }
  }

  @Test
  void aServerThatDoesNotSupportTheBatchIsUnsupportedOnceTheOriginalStateIsReadBack() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      // A whole-message refusal: the server processed no item.
      f.hook =
          (r, c, s) -> {
            if (!isBatch(r)) return s.exchange(r, c);
            Ttlv response = s.exchange(Ttlv.structure(r.tag(), List.of(r.children().get(0))), c);
            Ttlv only = response.children(BATCH_ITEM).get(0);
            only =
                replace(
                    only,
                    RESULT_REASON,
                    Ttlv.enumeration(RESULT_REASON, Enums.ResultReason.FEATURE_NOT_SUPPORTED));
            return withItems(response, List.of(only));
          };
      UnsupportedException refused =
          assertThrows(
              UnsupportedException.class, () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertEquals(
          Enums.ResultReason.FEATURE_NOT_SUPPORTED, refused.protocolReason().orElseThrow());
      assertEquals(List.of(NAME), f.names(from));
      assertEquals(1, f.mutations().size());
    }
  }

  @Test
  void aRefusalWhoseOriginalStateIsNotReadBackIsUnknown() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.hook =
          (r, c, s) -> {
            if (isBatch(r)) {
              s.failNext(ServerOperation.DELETE_ATTRIBUTE, Fault.PERMISSION_DENIED);
              Ttlv response = s.exchange(r, c);
              s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
              return response;
            }
            return s.exchange(r, c);
          };
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      // The original refusal is kept as the cause, the unreadable read as suppressed.
      assertInstanceOf(PermissionDeniedException.class, unknown.getCause());
      assertEquals(1, unknown.getSuppressed().length);
      assertTrue(unknown.getMessage().contains(from.id() + " unreadable"), unknown.getMessage());
      assertTrue(
          unknown.getMessage().contains(to.id() + " does not hold " + NAME), unknown.getMessage());
      assertEquals(1, f.mutations().size());
    }
  }

  // ---- replies that do not establish the outcome ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aReplyLostAfterTheBatchAppliedIsSettledByReadingBackAndNeverResent(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.server.failNext(ServerOperation.DELETE_ATTRIBUTE, Fault.REPLY_LOST);
      f.client.keys().moveName(NAME, from.id(), to.id());
      assertEquals(List.of(), f.names(from));
      assertEquals(List.of(NAME), f.names(to));
      assertEquals(1, f.mutations().size());
      assertEquals(5, f.sent.size());
    }
  }

  @Test
  void aMalformedReplyAfterTheBatchAppliedIsSettledByReadingBack() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.server.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.MALFORMED_REPLY);
      f.client.keys().moveName(NAME, from.id(), to.id());
      assertEquals(List.of(NAME), f.names(to));
      assertEquals(1, f.mutations().size());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostReplyWithTheOriginalStateReadBackStaysUnknown(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle from = f.key(NAME), to = f.key();
      // The connection fails after the request was written; the server never saw it.
      f.hook =
          (r, c, s) -> {
            if (isBatch(r)) throw new SocketTimeoutException("Read timed out");
            return s.exchange(r, c);
          };
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertInstanceOf(OutcomeUnknownException.class, unknown.getCause());
      assertTrue(unknown.getMessage().contains(from.id() + " holds " + NAME), unknown.getMessage());
      assertTrue(
          unknown.getMessage().contains("rather than repeating the move blindly"),
          unknown.getMessage());
      // Observing the original state did not authorize a second attempt.
      assertEquals(1, f.mutations().size());
      assertEquals(5, f.sent.size());
      assertEquals(List.of(NAME), f.names(from));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1", "V3_0"})
  void anUndoTheServerDidNotPerformIsUnknownWithThePartialStateObserved(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle from = f.key(NAME), to = f.key();
      // The server applies the delete and fails the add, but leaves the delete in place: it
      // answers Success then Failed (it ran the batch as Stop, not Undo).
      f.hook =
          (r, c, s) -> {
            if (!isBatch(r)) return s.exchange(r, c);
            Ttlv header =
                replace(
                    r.require(REQUEST_HEADER),
                    BATCH_ERROR_CONTINUATION_OPTION,
                    Ttlv.enumeration(
                        BATCH_ERROR_CONTINUATION_OPTION, Enums.BatchErrorContinuation.STOP));
            s.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.SERVER_FAILURE);
            return s.exchange(replace(r, REQUEST_HEADER, header), c);
          };
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      String m = unknown.getMessage();
      assertTrue(m.contains("SUCCESS then OPERATION_FAILED"), m);
      assertTrue(
          m.contains(from.id() + " does not hold " + NAME)
              && m.contains(to.id() + " does not hold " + NAME),
          m);
      assertEquals(List.of(), f.names(from));
      assertEquals(List.of(), f.names(to));
      assertEquals(1, f.mutations().size());
    }
  }

  @Test
  void pendingResultsAreUnknownEvenWithTheOriginalStateReadBack() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      Ttlv correlation = Ttlv.bytes(ASYNCHRONOUS_CORRELATION_VALUE, new byte[] {1, 2, 3, 4});
      f.hook =
          refusedThenAnswered(
              (r, response) -> List.of(item(r, 0, 2, correlation), item(r, 1, 2, correlation)));
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertTrue(unknown.getMessage().contains(from.id() + " holds " + NAME), unknown.getMessage());
      assertEquals(List.of(NAME), f.names(from));
      assertEquals(1, f.mutations().size());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void missingExtraAndReorderedItemsAreUnknownNotARefusal(KmipVersion version) {
    List<java.util.function.BiFunction<Ttlv, Ttlv, List<Ttlv>>> shapes =
        List.of(
            // Missing: only an Undone delete, no failed item.
            (r, response) -> List.of(item(r, 0, 3)),
            // Extra: a third item.
            (r, response) -> {
              List<Ttlv> items = new ArrayList<>(response.children(BATCH_ITEM));
              items.add(items.get(0));
              items.add(items.get(0));
              return items;
            },
            // Reordered: the add's result first.
            (r, response) ->
                List.of(
                    item(
                        r,
                        1,
                        1,
                        Ttlv.enumeration(RESULT_REASON, Enums.ResultReason.PERMISSION_DENIED)),
                    item(r, 0, 3)),
            // The add failed but the delete is reported Success: no confirmed undo.
            (r, response) ->
                List.of(
                    item(r, 0, 0),
                    item(
                        r,
                        1,
                        1,
                        Ttlv.enumeration(RESULT_REASON, Enums.ResultReason.PERMISSION_DENIED))));
    for (var shape : shapes)
      try (Fixture f = new Fixture(version)) {
        KeyHandle from = f.key(NAME), to = f.key();
        f.hook = refusedThenAnswered(shape);
        OutcomeUnknownException unknown =
            assertThrows(
                OutcomeUnknownException.class,
                () -> f.client.keys().moveName(NAME, from.id(), to.id()));
        assertTrue(
            unknown.getMessage().contains(from.id() + " holds " + NAME), unknown.getMessage());
        assertEquals(1, f.mutations().size());
        assertEquals(5, f.sent.size());
      }
  }

  @Test
  void bothItemsAcknowledgedButNotObservedIsUnknown() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      // Another client gives the name back to the source right after the batch.
      f.hook =
          (r, c, s) -> {
            Ttlv response = s.exchange(r, c);
            if (isBatch(r)) f.admin.keys().handle(from.id()).addName(NAME);
            return response;
          };
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertNull(unknown.getCause());
      assertTrue(
          unknown.getMessage().contains("both items succeeded but the transfer is not verified"),
          unknown.getMessage());
      assertTrue(unknown.getMessage().contains(from.id() + " holds " + NAME), unknown.getMessage());
      assertEquals(1, f.mutations().size());
    }
  }

  @Test
  void anInaccessibleReadBackAfterSuccessIsUnknown() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.hook =
          (r, c, s) -> {
            Ttlv response = s.exchange(r, c);
            if (isBatch(r)) s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
            return response;
          };
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertInstanceOf(PermissionDeniedException.class, unknown.getSuppressed()[0]);
      assertTrue(unknown.getMessage().contains(to.id() + " holds " + NAME), unknown.getMessage());
      assertEquals(5, f.sent.size());
    }
  }

  // ---- one deadline ----

  @Test
  void aBatchThatHangsUsesUpTheOneDeadlineAndLeavesNoReadBack() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      Kms view = f.client.withTimeout(Duration.ofMillis(400));
      f.server.failNext(ServerOperation.DELETE_ATTRIBUTE, Fault.HANG);
      long start = System.nanoTime();
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class, () -> view.keys().moveName(NAME, from.id(), to.id()));
      long elapsed = System.nanoTime() - start;
      assertTrue(elapsed < Duration.ofMillis(1500).toNanos(), "took " + Duration.ofNanos(elapsed));
      // No read-back got a deadline of its own: with one, both reads would have succeeded.
      assertTrue(
          unknown.getMessage().contains(from.id() + " unreadable")
              && unknown.getMessage().contains(to.id() + " unreadable"),
          unknown.getMessage());
      assertEquals(2, unknown.getSuppressed().length);
      for (Throwable t : unknown.getSuppressed()) assertInstanceOf(TransientException.class, t);
      assertEquals(1, f.mutations().size());
      assertEquals(List.of(NAME), f.names(from));
    }
  }

  @Test
  void aReadBackThatHangsEndsAtTheOriginalDeadline() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      Kms view = f.client.withTimeout(Duration.ofMillis(400));
      f.hook =
          (r, c, s) -> {
            Ttlv response = s.exchange(r, c);
            if (isBatch(r)) s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.HANG);
            return response;
          };
      long start = System.nanoTime();
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class, () -> view.keys().moveName(NAME, from.id(), to.id()));
      long elapsed = System.nanoTime() - start;
      assertTrue(elapsed < Duration.ofMillis(1500).toNanos(), "took " + Duration.ofNanos(elapsed));
      assertTrue(unknown.getMessage().contains("both items succeeded"), unknown.getMessage());
      // The source's read-back hung to the deadline, leaving the target's none of its own.
      assertTrue(
          unknown.getMessage().contains(from.id() + " unreadable")
              && unknown.getMessage().contains(to.id() + " unreadable"),
          unknown.getMessage());
      assertEquals(1, f.mutations().size());
      // The batch itself did apply.
      assertEquals(List.of(NAME), f.names(to));
    }
  }

  @Test
  void aBatchNotSentIsDefiniteAndNotRepeated() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.server.failNext(ServerOperation.DELETE_ATTRIBUTE, Fault.UNREACHABLE);
      assertThrows(
          TransientException.class, () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertEquals(3, f.sent.size());
      assertEquals(List.of(NAME), f.names(from));
    }
  }

  // ---- close racing the call ----

  @Test
  void aCloseBeforeTheBatchIsAnOrdinaryClosedKms() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.client.close();
      assertThrows(
          IllegalStateException.class, () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertEquals(List.of(), f.sent);
    }
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      // Closed by another thread after the first reads, before the batch.
      f.hook =
          (r, c, s) -> {
            Ttlv response = s.exchange(r, c);
            if (f.sent.size() == 2) f.client.close();
            return response;
          };
      IllegalStateException closed =
          assertThrows(
              IllegalStateException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertNull(closed.getCause());
      assertEquals(List.of(), f.mutations());
      assertEquals(List.of(NAME), f.names(from));
    }
  }

  @Test
  void aCloseWhileTheSentBatchsReplyIsLostIsUnknownAndNotRetried() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.hook =
          (r, c, s) -> {
            if (!isBatch(r)) return s.exchange(r, c);
            s.exchange(r, c); // applied
            f.client.close();
            throw new SocketTimeoutException("Read timed out");
          };
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertInstanceOf(OutcomeUnknownException.class, unknown.getCause());
      assertTrue(
          unknown.getMessage().contains(from.id() + " unreadable (Kms closed)")
              && unknown.getMessage().contains(to.id() + " unreadable (Kms closed)"),
          unknown.getMessage());
      // No read-back on the closed Kms, no second batch.
      assertEquals(3, f.sent.size());
      assertEquals(1, f.mutations().size());
      assertEquals(List.of(NAME), f.names(to));
    }
  }

  @Test
  void aCloseAfterAnAcknowledgedRefusalLeavesItUnverifiedSoUnknown() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.hook =
          (r, c, s) -> {
            if (!isBatch(r)) return s.exchange(r, c);
            s.failNext(ServerOperation.DELETE_ATTRIBUTE, Fault.PERMISSION_DENIED);
            Ttlv response = s.exchange(r, c);
            f.client.close();
            return response;
          };
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertInstanceOf(PermissionDeniedException.class, unknown.getCause());
      assertTrue(
          unknown.getMessage().contains("original state is not verified"), unknown.getMessage());
      assertEquals(3, f.sent.size());
      assertEquals(List.of(NAME), f.names(from));
    }
  }

  @Test
  void aCloseAfterBothItemsSucceededLeavesTheTransferUnverified() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.hook =
          (r, c, s) -> {
            Ttlv response = s.exchange(r, c);
            if (isBatch(r)) f.client.close();
            return response;
          };
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertNull(unknown.getCause());
      assertTrue(unknown.getMessage().contains("both items succeeded"), unknown.getMessage());
      assertEquals(2, unknown.getSuppressed().length);
      for (Throwable t : unknown.getSuppressed()) assertInstanceOf(IllegalStateException.class, t);
      assertEquals(3, f.sent.size());
    }
  }

  @Test
  void aCloseDuringTheReadBackIsUnknown() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.hook =
          (r, c, s) -> {
            if (f.sent.size() == 4) { // the first read-back
              f.client.close();
              throw new SocketTimeoutException("Read timed out");
            }
            return s.exchange(r, c);
          };
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertTrue(unknown.getMessage().contains("both items succeeded"), unknown.getMessage());
      assertTrue(
          unknown.getMessage().contains(from.id() + " unreadable (Kms closed)")
              && unknown.getMessage().contains(to.id() + " unreadable (Kms closed)"),
          unknown.getMessage());
      assertEquals(4, f.sent.size());
      assertEquals(1, f.mutations().size());
    }
  }

  // ---- compatibility ----

  @Test
  void handleNameMethodsAreUnchanged() {
    try (Fixture f = new Fixture(KmipVersion.V1_4)) {
      KeyHandle key = f.key("a", NAME, "b");
      f.client.keys().handle(key.id()).removeName(NAME);
      assertEquals(List.of("a", "b"), f.names(key));
      f.client.keys().handle(key.id()).addName(NAME);
      assertEquals(List.of("a", "b", NAME), f.names(key));
      // One Get Attributes for the index, one Delete Attribute; one Add Attribute: no batches.
      for (Ttlv r : f.sent) assertEquals(1, r.children(BATCH_ITEM).size());
    }
  }
}
