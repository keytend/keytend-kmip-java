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

import static dev.keytend.kmip.kms.KmsKeysMoveNameTest.*;
import static dev.keytend.kmip.kms.KmsKeysMoveNameTest.NAME;
import static dev.keytend.kmip.model.Tag.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Name transfers keep one absolute deadline across their exchanges, refuse bad selectors before
 * any mutation, and report ambiguous outcomes with structured, redacted diagnostics.
 * Uses the existing fixture for wire construction, with its own schedules and replies.
 */
class NameTransferDeadlineTest {
  @Test
  void legacyDeletionUsesTheStableSparseIndexRatherThanTheCurrentOrdinal() {
    try (Fixture f = new Fixture(KmipVersion.V1_4)) {
      KeyHandle from = f.key("removed", "keep-before", NAME, "keep-after"),
          to = f.key("keep-target");
      from.removeName("removed"); // remaining indexes are 1, 2, 3, not 0, 1, 2
      f.client.keys().moveName(NAME, from.id(), to.id());
      assertEquals(
          2,
          f.mutations()
              .get(0)
              .children(BATCH_ITEM)
              .get(0)
              .require(REQUEST_PAYLOAD)
              .require(ATTRIBUTE_INDEX)
              .intValue());
      assertEquals(List.of("keep-before", "keep-after"), f.names(from));
      assertEquals(List.of("keep-target", NAME), f.names(to));
      assertEquals(5, f.sent.size());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void allFiveExchangesKeepTheSameAbsoluteDeadline(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle from = f.key("unrelated", NAME), to = f.key("target-other");
      List<Long> deadlines = new ArrayList<>();
      f.hook =
          (r, c, s) -> {
            assertTrue(c.hasDeadline());
            deadlines.add(c.deadlineBefore(Long.MAX_VALUE));
            pause(25);
            return s.exchange(r, c);
          };
      f.client.withTimeout(Duration.ofSeconds(2)).keys().moveName(NAME, from.id(), to.id());
      assertEquals(5, deadlines.size());
      long spread =
          deadlines.stream().mapToLong(Long::longValue).max().orElseThrow()
              - deadlines.stream().mapToLong(Long::longValue).min().orElseThrow();
      assertTrue(
          spread < Duration.ofMillis(10).toNanos(), "deadline spread: " + Duration.ofNanos(spread));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void wrongOperationOrIdentifierInBatchIsUnknownAndReadBackStillRuns(KmipVersion version) {
    for (boolean wrongOperation : List.of(true, false)) {
      try (Fixture f = new Fixture(version)) {
        KeyHandle from = f.key(NAME), to = f.key();
        f.hook =
            (r, c, s) -> {
              if (!isBatch(r)) return s.exchange(r, c);
              s.failNext(ServerOperation.DELETE_ATTRIBUTE, Fault.PERMISSION_DENIED);
              Ttlv response = s.exchange(r, c);
              Ttlv bad;
              if (wrongOperation) {
                bad =
                    replace(
                        response.children(BATCH_ITEM).get(0),
                        OPERATION,
                        Ttlv.enumeration(OPERATION, Operation.DESTROY));
              } else {
                bad =
                    item(
                        r,
                        0,
                        0,
                        Ttlv.structure(
                            RESPONSE_PAYLOAD, Ttlv.text(UNIQUE_IDENTIFIER, "another-object")));
              }
              return withItems(response, List.of(bad));
            };
        OutcomeUnknownException unknown =
            assertThrows(
                OutcomeUnknownException.class,
                () -> f.client.keys().moveName(NAME, from.id(), to.id()));
        assertInstanceOf(OutcomeUnknownException.class, unknown.getCause());
        assertEquals(5, f.sent.size());
        assertEquals(1, f.mutations().size());
        assertTrue(unknown.getMessage().contains(from.id() + " holds " + NAME));
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void undoFailureReportedAsTwoFailuresCannotBecomeAKnownRefusal(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.hook =
          refusedThenAnswered(
              (r, response) ->
                  List.of(
                      // The local ResultReason tables have no UndoFailed constant: represent a
                      // failed
                      // rollback with GeneralFailure and a diagnostic, without inventing a wire
                      // code.
                      item(
                          r,
                          0,
                          1,
                          Ttlv.enumeration(RESULT_REASON, Enums.ResultReason.GENERAL_FAILURE),
                          Ttlv.text(RESULT_MESSAGE, "Undo failed"),
                          Ttlv.bytes(DATA, new byte[] {1, 2, 3}),
                          Ttlv.text(PASSWORD, "secret-password")),
                      item(
                          r,
                          1,
                          1,
                          Ttlv.enumeration(RESULT_REASON, Enums.ResultReason.PERMISSION_DENIED))));
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertTrue(unknown.getMessage().contains(from.id() + " holds " + NAME));
      assertEquals(5, f.sent.size());
      assertEquals(1, f.mutations().size());
    }
  }

  @Test
  void secondPrecheckFailureCannotSendABatch() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.hook =
          (r, c, s) -> {
            if (f.sent.size() == 2)
              s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
            return s.exchange(r, c);
          };
      assertThrows(
          PermissionDeniedException.class,
          () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertEquals(2, f.sent.size());
      assertEquals(0, f.mutations().size());
    }
  }

  @Test
  void deadlineSpentAfterTheSecondPrecheckPreventsMutation() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.hook =
          (r, c, s) -> {
            Ttlv response = s.exchange(r, c);
            if (f.sent.size() == 2) pause(180);
            return response;
          };
      assertThrows(
          TransientException.class,
          () ->
              f.client
                  .withTimeout(Duration.ofMillis(120))
                  .keys()
                  .moveName(NAME, from.id(), to.id()));
      assertEquals(2, f.sent.size());
      assertEquals(0, f.mutations().size());
      assertEquals(List.of(NAME), f.names(from));
    }
  }

  @Test
  void secondReadBackFailureIsUnknownDespiteTheFirstReadObservingCompletion() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.hook =
          (r, c, s) -> {
            if (f.sent.size() == 5)
              s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
            return s.exchange(r, c);
          };
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertTrue(unknown.getMessage().contains(from.id() + " does not hold " + NAME));
      assertTrue(unknown.getMessage().contains(to.id() + " unreadable"));
      assertEquals(1, unknown.getSuppressed().length);
      assertEquals(1, f.mutations().size());
    }
  }

  @Test
  void closingAfterTheFinalSuccessfulObservationStillAllowsObservedSuccess() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.hook =
          (r, c, s) -> {
            Ttlv response = s.exchange(r, c);
            if (f.sent.size() == 5) f.client.close();
            return response;
          };
      assertDoesNotThrow(() -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertEquals(5, f.sent.size());
      assertEquals(1, f.mutations().size());
      assertEquals(List.of(NAME), f.names(to));
    }
  }

  @Test
  void aLostMutationReplyIsNotRetriedEvenWithAnAggressiveReadRetryPolicy() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      List<Ttlv> sent = new ArrayList<>();
      AtomicBoolean refusedRead = new AtomicBoolean();
      try (Kms client =
          Kms.connect(
              f.server
                  .configure()
                  .retryPolicy(
                      RetryPolicy.defaults().toBuilder()
                          .maxAttempts(5)
                          .initialBackoff(Duration.ofMillis(1))
                          .maxBackoff(Duration.ofMillis(1))
                          .build())
                  .transport(
                      e ->
                          transport(
                              (r, c) -> {
                                sent.add(r);
                                if (isBatch(r))
                                  throw new SocketTimeoutException("lost mutation reply");
                                if (operations(r).equals(List.of(Operation.GET_ATTRIBUTES))
                                    && refusedRead.compareAndSet(false, true))
                                  f.server.failNext(
                                      ServerOperation.GET_ATTRIBUTES, Fault.SERVER_BUSY);
                                return f.server.exchange(r, c);
                              }))
                  .build())) {
        sent.clear();
        assertThrows(
            OutcomeUnknownException.class, () -> client.keys().moveName(NAME, from.id(), to.id()));
        assertTrue(refusedRead.get());
        assertEquals(6, sent.size()); // one retried read, four other reads, one batch
        assertEquals(1, sent.stream().filter(KmsKeysMoveNameTest::isBatch).count());
      }
    }
  }

  @Test
  void startedCallbackCannotExtendMutationDeadlineOrSendAfterScopeExpired() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      AtomicInteger mutationSends = new AtomicInteger();
      KmsListener listener =
          new KmsListener() {
            @Override
            public void started(KmsEvent event) {
              if (event.step().equals("moveName")) pause(180);
            }
          };
      try (Kms client =
          Kms.connect(
              f.server
                  .configure()
                  .addListener(listener)
                  .transport(
                      e ->
                          transport(
                              (r, c) -> {
                                if (isBatch(r)) {
                                  mutationSends.incrementAndGet();
                                }
                                return f.server.exchange(r, c);
                              }))
                  .build())) {
        TransientException stopped =
            assertThrows(
                TransientException.class,
                () ->
                    client
                        .withTimeout(Duration.ofMillis(120))
                        .keys()
                        .moveName(NAME, from.id(), to.id()));
        assertInstanceOf(
            dev.keytend.kmip.transport.RequestNotSentException.class, stopped.getCause());
        assertEquals(0, mutationSends.get());
        assertEquals(List.of(NAME), f.names(from));
        assertEquals(List.of(), f.names(to));
      }
    }
  }

  @Test
  void negativeLegacyIndexIsRefusedBeforeAnyMutation() {
    try (Fixture f = new Fixture(KmipVersion.V1_4)) {
      KeyHandle from = f.key("unrelated", NAME), to = f.key();
      f.hook =
          (r, c, s) -> {
            Ttlv response = s.exchange(r, c);
            if (f.sent.size() != 1) return response;
            Ttlv item = response.children(BATCH_ITEM).get(0);
            Ttlv payload = item.require(RESPONSE_PAYLOAD);
            List<Ttlv> fields = new ArrayList<>();
            for (Ttlv a : payload.children()) {
              if (a.tag() == ATTRIBUTE.code()
                  && a.require(ATTRIBUTE_VALUE).require(NAME_VALUE).textValue().equals(NAME))
                a = replace(a, ATTRIBUTE_INDEX, Ttlv.integer(ATTRIBUTE_INDEX, -1));
              fields.add(a);
            }
            return withItems(
                response,
                List.of(replace(item, RESPONSE_PAYLOAD, Ttlv.structure(RESPONSE_PAYLOAD, fields))));
          };
      assertThrows(
          ProtocolViolationException.class,
          () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      assertEquals(0, f.mutations().size());
      assertEquals(List.of("unrelated", NAME), f.names(from));
      assertEquals(List.of(), f.names(to));
    }
  }

  @Test
  void ambiguousParsedBatchRetainsRedactedResponseAndResultReasons() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      f.hook =
          refusedThenAnswered(
              (r, response) ->
                  List.of(
                      item(
                          r,
                          0,
                          1,
                          Ttlv.enumeration(RESULT_REASON, Enums.ResultReason.GENERAL_FAILURE),
                          Ttlv.text(RESULT_MESSAGE, "Undo failed"),
                          Ttlv.bytes(DATA, new byte[] {1, 2, 3}),
                          Ttlv.text(PASSWORD, "secret-password")),
                      item(
                          r,
                          1,
                          1,
                          Ttlv.enumeration(RESULT_REASON, Enums.ResultReason.PERMISSION_DENIED))));
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      Ttlv safe = unknown.response().orElseThrow();
      List<Ttlv> items = safe.children(BATCH_ITEM);
      assertEquals(
          Enums.ResultReason.GENERAL_FAILURE.code(),
          items.get(0).require(RESULT_REASON).intValue());
      assertEquals(
          Enums.ResultReason.PERMISSION_DENIED.code(),
          items.get(1).require(RESULT_REASON).intValue());
      assertEquals(0, items.get(0).require(DATA).bytesValue().length);
      assertEquals("", items.get(0).require(PASSWORD).textValue());
      assertTrue(unknown.result().isEmpty(), "there is no single authoritative failing item");
      OutcomeUnknownException original =
          assertInstanceOf(OutcomeUnknownException.class, unknown.getCause());
      assertEquals(safe, original.response().orElseThrow());
      assertTrue(original.result().isEmpty());
      assertFalse(unknown.getMessage().contains("Undo failed"));
      assertTrue(unknown.getMessage().contains("OPERATION_FAILED then OPERATION_FAILED"));
      assertEquals(5, f.sent.size());
    }
  }

  @Test
  void sharedHelpersRestoreScopeAndOperationAfterListenerReentrancyAndFailure() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      AtomicInteger callbacks = new AtomicInteger();
      List<String> callbackOperations = new ArrayList<>();
      KmsConfig config =
          f.server
              .configure()
              .addListener(
                  new KmsListener() {
                    private void callback() {
                      assertEquals("inner", Kms.named("inner"));
                      assertTrue(
                          Kms.callRemaining(Duration.ofMinutes(5))
                              > Duration.ofMinutes(4).toNanos());
                      Kms.runNamed(
                          "listener-operation",
                          () -> {
                            callbackOperations.add(Kms.named("ignored"));
                            f.admin.ping();
                          });
                      callbacks.incrementAndGet();
                      throw new IllegalArgumentException("diagnostic failure");
                    }

                    @Override
                    public void localKeySelected(String name, String previousId, String newId) {
                      callback();
                    }

                    @Override
                    public void localKeyRefreshFailed(
                        String name,
                        String id,
                        LocalUse purpose,
                        KmsException failure,
                        Duration validity) {
                      callback();
                    }
                  })
              .build();
      Kms.run(
          Duration.ofSeconds(2),
          "outer",
          () -> {
            long before = Kms.callRemaining(Duration.ofSeconds(20));
            Kms.localKeySelected(config, NAME, null, "new");
            Kms.localKeyRefreshFailed(
                config,
                NAME,
                null,
                LocalUse.ENCRYPT,
                new TransientException("test", null, "refresh", null, null, null),
                Duration.ZERO);
            assertEquals("outer", Kms.named("ignored"));
            assertTrue(Kms.callRemaining(Duration.ofSeconds(20)) <= before);
          });
      assertEquals(2, callbacks.get());
      assertEquals(List.of("listener-operation", "listener-operation"), callbackOperations);
    }
  }

  @FunctionalInterface
  private interface Exchange {
    Ttlv exchange(Ttlv request, CallContext context) throws IOException;
  }

  private static KmipTransport transport(Exchange exchange) {
    return new KmipTransport() {
      @Override
      public Ttlv exchange(Ttlv request) throws IOException {
        return exchange(request, CallContext.NONE);
      }

      @Override
      public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
        return exchange.exchange(request, context);
      }
    };
  }

  private static void pause(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new AssertionError("probe interrupted", e);
    }
  }
}
