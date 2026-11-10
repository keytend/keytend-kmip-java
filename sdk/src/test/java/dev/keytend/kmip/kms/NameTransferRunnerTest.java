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

import dev.keytend.kmip.client.ProtocolException;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import dev.keytend.kmip.transport.RequestNotSentException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Name transfers through the real shared runner and wire parser, with no production substitutions:
 * listener expiry, slow listeners, deadlines spent after dispatch, selectors and structured failures.
 */
class NameTransferRunnerTest {
  private static final long MS = 1_000_000;
  private static final String RAW = "peer-diagnostic-must-not-be-interpolated";

  @ParameterizedTest
  @EnumSource(Kms.Kind.class)
  void listenerExpiryIsLocalAndDefiniteForEveryRunnerKind(Kms.Kind kind) {
    try (Runner r = new Runner()) {
      AtomicInteger bodies = new AtomicInteger();
      long[] deadline = {0};
      r.started =
          e -> {
            if (e.step().equals("transfer-step")) waitUntil(deadline[0] + 20 * MS);
          };
      Kms.run(
          Duration.ofMillis(200),
          "transfer-outer",
          () -> {
            deadline[0] = scopeDeadline();
            TransientException stopped =
                assertThrows(
                    TransientException.class,
                    () ->
                        r.client
                            .withTimeout(Duration.ofMillis(200))
                            .execute(
                                "transfer-step",
                                kind,
                                null,
                                s -> {
                                  bodies.incrementAndGet();
                                  return s.call(Requests.discoverVersions().build());
                                }));
            assertTrue(assertInstanceOf(RequestNotSentException.class, stopped.getCause()).local());
            assertEquals("transfer-outer", stopped.operation());
            assertEquals("transfer-outer", Kms.named("ignored"));
            assertTrue(Kms.callRemaining(Duration.ofSeconds(3)) < 0);
          });
      assertEquals(0, bodies.get());
      assertEquals(List.of(), r.wireHosts);
      assertEquals(1, r.finished.size());
      assertEquals("transfer-step", r.finished.get(0).step());
      assertEquals(1, r.finished.get(0).attempt());
      assertEquals(0, r.retries.size());
      r.client.ping();
      assertEquals(List.of("a"), r.wireHosts, "local expiry must not cool down or advance a");
    }
  }

  @Test
  void slowListenerShrinksAttemptToCallerRemainderWithoutFalseFailover() {
    try (Runner r = new Runner()) {
      long[] deadline = {0};
      r.started =
          e -> {
            if (e.step().equals("transfer-read")) waitUntil(deadline[0] - 150 * MS);
          };
      r.exchange =
          (host, request, context) -> {
            if (operations(request).equals(List.of(Operation.GET_ATTRIBUTES))) {
              long left = context.remainingNanos();
              assertTrue(left > 0 && left <= 190 * MS, "stale attempt limit supplied: " + left);
              assertTrue(context.deadlineBefore(Long.MAX_VALUE) <= deadline[0] + 10 * MS);
              waitUntil(context.deadlineBefore(Long.MAX_VALUE) + MS);
              throw new SocketTimeoutException("call budget spent");
            }
            return r.f.server.exchange(request, context);
          };
      Kms.run(
          Duration.ofMillis(800),
          "read",
          () -> {
            deadline[0] = scopeDeadline();
            TransientException failure =
                assertThrows(
                    TransientException.class,
                    () -> r.read(r.client.withTimeout(Duration.ofMillis(800))));
            assertFalse(failure.getMessage().contains("within the attempt timeout"));
          });
      assertEquals(List.of("a"), r.wireHosts);
      assertEquals(0, r.retries.size());
      r.client.ping();
      assertEquals(List.of("a", "a"), r.wireHosts);
    }
  }

  @Test
  void slowListenerStillAllowsARealAttemptCutAndFailoverWithinOneDeadline() {
    try (Runner r = new Runner()) {
      long[] deadline = {0};
      List<String> reads = new ArrayList<>();
      r.started =
          e -> {
            if (e.step().equals("transfer-read") && e.attempt() == 1)
              waitUntil(deadline[0] - 900 * MS);
          };
      r.exchange =
          (host, request, context) -> {
            if (operations(request).equals(List.of(Operation.GET_ATTRIBUTES))) {
              reads.add(host);
              assertTrue(context.deadlineBefore(Long.MAX_VALUE) <= deadline[0] + 10 * MS);
              if (host.equals("a")) {
                assertTrue(context.remainingNanos() <= 400 * MS);
                waitUntil(context.deadlineBefore(Long.MAX_VALUE) + MS);
                throw new SocketTimeoutException("attempt budget spent");
              }
              assertTrue(context.remainingNanos() > 0);
            }
            return r.f.server.exchange(request, context);
          };
      Kms.run(
          Duration.ofSeconds(2),
          "transfer-outer",
          () -> {
            deadline[0] = scopeDeadline();
            assertDoesNotThrow(() -> r.read(r.client.withTimeout(Duration.ofSeconds(2))));
            assertEquals("transfer-outer", Kms.named("ignored"));
          });
      assertEquals(List.of("a", "b"), reads);
      assertEquals(1, r.retries.size());
      assertTrue(
          r.retries
              .get(0)
              .failure()
              .orElseThrow()
              .getMessage()
              .contains("within the attempt timeout"));
      assertEquals(List.of(1, 2), r.finished.stream().map(KmsEvent::attempt).toList());
      assertEquals(
          List.of("transfer-outer", "transfer-outer"),
          r.finished.stream().map(KmsEvent::operation).toList());
      assertEquals(
          List.of("transfer-read", "transfer-read"),
          r.finished.stream().map(KmsEvent::step).toList());
      r.client.ping();
      assertEquals("b", r.wireHosts.get(r.wireHosts.size() - 1));
    }
  }

  @Test
  void deadlineSpentAfterBatchDispatchRemainsUnknownWithNoReadbackOrReplay() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle from = f.key(NAME), to = f.key();
      long[] deadline = {0};
      f.hook =
          (request, context, server) -> {
            if (!isBatch(request)) return server.exchange(request, context);
            assertTrue(context.remainingNanos() > 0, "batch starts before expiry");
            assertTrue(context.deadlineBefore(Long.MAX_VALUE) <= deadline[0] + 10 * MS);
            waitUntil(deadline[0] + 20 * MS);
            throw new SocketTimeoutException("sent, reply lost");
          };
      Kms.run(
          Duration.ofMillis(250),
          "moveName",
          () -> {
            deadline[0] = scopeDeadline();
            OutcomeUnknownException unknown =
                assertThrows(
                    OutcomeUnknownException.class,
                    () -> f.client.keys().moveName(NAME, from.id(), to.id()));
            assertInstanceOf(OutcomeUnknownException.class, unknown.getCause());
            assertEquals(2, unknown.getSuppressed().length);
            for (Throwable failure : unknown.getSuppressed())
              assertInstanceOf(TransientException.class, failure);
          });
      assertEquals(3, f.sent.size());
      assertEquals(1, f.mutations().size());
      assertEquals(List.of(NAME), f.names(from));
      assertEquals(List.of(), f.names(to));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_1", "V1_2", "V1_3", "V1_4"})
  void negativeSelectorsAreRefusedEvenOnUnrelatedTargetOrAlreadyCompletedNames(
      KmipVersion version) {
    // Each runtime invocation exercises 12 malformed cases: six placements, two negative bounds.
    for (int scenario = 0; scenario < 6; scenario++)
      for (int badIndex : new int[] {-1, Integer.MIN_VALUE}) {
        try (Fixture f = new Fixture(version)) {
          List<String> sourceNames =
              switch (scenario) {
                case 3, 4 -> List.of("other");
                case 5 -> List.of(NAME, NAME);
                default -> List.of(NAME, "other");
              };
          List<String> targetNames =
              scenario == 3 ? List.of(NAME, "target-other") : List.of("target-other");
          KeyHandle from = f.key(sourceNames.toArray(String[]::new)),
              to = f.key(targetNames.toArray(String[]::new));
          boolean target = scenario == 2 || scenario == 3;
          String badId = target ? to.id() : from.id();
          String badName =
              switch (scenario) {
                case 1, 4 -> "other";
                case 2 -> "target-other";
                default -> NAME;
              };
          f.hook =
              (request, context, server) -> {
                Ttlv response = server.exchange(request, context);
                if (!texts(request, UNIQUE_IDENTIFIER).contains(badId)) return response;
                Ttlv item = response.require(BATCH_ITEM), payload = item.require(RESPONSE_PAYLOAD);
                boolean replaced = false;
                List<Ttlv> fields = new ArrayList<>();
                for (Ttlv field : payload.children()) {
                  if (!replaced
                      && field.tag() == ATTRIBUTE.code()
                      && field
                          .require(ATTRIBUTE_VALUE)
                          .require(NAME_VALUE)
                          .textValue()
                          .equals(badName)) {
                    List<Ttlv> malformed =
                        new ArrayList<>(
                            field.children().stream()
                                .filter(child -> child.tag() != ATTRIBUTE_INDEX.code())
                                .toList());
                    malformed.add(Ttlv.integer(ATTRIBUTE_INDEX, badIndex));
                    field = Ttlv.structure(ATTRIBUTE, malformed);
                    replaced = true;
                  }
                  fields.add(field);
                }
                assertTrue(replaced);
                return withItems(
                    response,
                    List.of(
                        replace(item, RESPONSE_PAYLOAD, Ttlv.structure(RESPONSE_PAYLOAD, fields))));
              };
          ProtocolViolationException failure =
              assertThrows(
                  ProtocolViolationException.class,
                  () -> f.client.keys().moveName(NAME, from.id(), to.id()));
          assertTrue(failure.getMessage().contains("negative Name Attribute Index"));
          assertInstanceOf(ProtocolException.class, failure.getCause());
          assertTrue(failure.response().isPresent());
          assertEquals(target ? 2 : 1, f.sent.size());
          assertEquals(0, f.mutations().size());
          assertEquals(sourceNames, f.names(from));
          assertEquals(targetNames, f.names(to));
        }
      }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_1", "V1_2", "V1_3", "V1_4"})
  void omittedLegacyZeroIndexStillSelectsExactlyTheMatchingName(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle from = f.key(NAME, "keep"), to = f.key("target-keep");
      f.hook =
          (request, context, server) -> {
            Ttlv response = server.exchange(request, context);
            if (isBatch(request) || !texts(request, UNIQUE_IDENTIFIER).contains(from.id()))
              return response;
            Ttlv item = response.require(BATCH_ITEM), payload = item.require(RESPONSE_PAYLOAD);
            List<Ttlv> fields =
                payload.children().stream()
                    .map(
                        field ->
                            field.tag() == ATTRIBUTE.code()
                                    && field.child(ATTRIBUTE_INDEX).map(Ttlv::intValue).orElse(0)
                                        == 0
                                ? replace(field, ATTRIBUTE_INDEX, null)
                                : field)
                    .toList();
            return withItems(
                response,
                List.of(replace(item, RESPONSE_PAYLOAD, Ttlv.structure(RESPONSE_PAYLOAD, fields))));
          };
      f.client.keys().moveName(NAME, from.id(), to.id());
      assertEquals(
          0,
          f.mutations()
              .get(0)
              .children(BATCH_ITEM)
              .get(0)
              .require(REQUEST_PAYLOAD)
              .require(ATTRIBUTE_INDEX)
              .intValue());
      assertEquals(List.of("keep"), f.names(from));
      assertEquals(List.of("target-keep", NAME), f.names(to));
      assertEquals(5, f.sent.size());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void customStatusFailureKeepsStructuredReasonsAndOnlyRedactedCauses(KmipVersion version) {
    checkEvidence(version, false);
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void customShapeFailureKeepsStructuredReasonsAndOnlyRedactedCauses(KmipVersion version) {
    // 1.x/2.x IDs correlate a complete reversed reply; 3.0 rejects wrong operations below this
    // layer.
    checkEvidence(version, true);
  }

  private void checkEvidence(KmipVersion version, boolean reversed) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle from = f.key(NAME), to = f.key();
      List<Ttlv> raw = new ArrayList<>();
      f.hook =
          refusedThenAnswered(
              (request, response) -> {
                Ttlv delete = evidenceItem(request, 0, Enums.ResultReason.GENERAL_FAILURE);
                Ttlv add = evidenceItem(request, 1, Enums.ResultReason.PERMISSION_DENIED);
                List<Ttlv> items = reversed ? List.of(add, delete) : List.of(delete, add);
                raw.add(withItems(response, items));
                return items;
              });
      OutcomeUnknownException unknown =
          assertThrows(
              OutcomeUnknownException.class,
              () -> f.client.keys().moveName(NAME, from.id(), to.id()));
      String branch =
          reversed ? "Batch reply items [1, 0]" : "OPERATION_FAILED then OPERATION_FAILED";
      assertTrue(unknown.getMessage().contains(branch), unknown.getMessage());
      Ttlv safe = unknown.response().orElseThrow();
      assertNotSame(raw.get(0), safe);
      List<Integer> reasons =
          safe.children(BATCH_ITEM).stream().map(i -> i.require(RESULT_REASON).intValue()).toList();
      int general = Enums.ResultReason.GENERAL_FAILURE.code(),
          denied = Enums.ResultReason.PERMISSION_DENIED.code();
      assertEquals(reversed ? List.of(denied, general) : List.of(general, denied), reasons);
      for (Ttlv item : safe.children(BATCH_ITEM))
        assertEquals(RAW, item.require(RESULT_MESSAGE).textValue());
      assertSafeTree(safe);
      for (Throwable cause = unknown; cause != null; cause = cause.getCause()) {
        assertFalse(String.valueOf(cause.getMessage()).contains(RAW));
        assertFalse(cause.toString().contains("password-sentinel"));
        if (cause instanceof KmsException k) {
          assertTrue(k.result().isEmpty(), "ambiguous batch has no authoritative single failure");
          assertEquals(safe, k.response().orElseThrow());
        } else {
          ProtocolException protocol = assertInstanceOf(ProtocolException.class, cause);
          assertEquals(safe, protocol.response());
          assertNull(protocol.getCause());
        }
      }
      // The delivered peer object stays raw; the SDK must retain a separate, redacted copy.
      assertEquals(3, raw.get(0).children(BATCH_ITEM).get(0).require(DATA).bytesValue().length);
      assertEquals(5, f.sent.size());
      assertEquals(1, f.mutations().size());
      assertEquals(List.of(NAME), f.names(from));
      assertEquals(List.of(), f.names(to));
      for (KmsEvent event : f.events.events) {
        assertFalse(event.toString().contains(RAW));
        event
            .failure()
            .ifPresent(
                k -> {
                  assertSafeTree(k.response().orElseThrow());
                  assertFalse(k.getMessage().contains(RAW));
                });
      }
    }
  }

  private static Ttlv evidenceItem(Ttlv request, int index, Enums.ResultReason reason) {
    return item(
        request,
        index,
        1,
        Ttlv.enumeration(RESULT_REASON, reason),
        Ttlv.text(RESULT_MESSAGE, RAW),
        Ttlv.bytes(DATA, new byte[] {7, 8, 9}),
        Ttlv.structure(
            CREDENTIAL_VALUE,
            Ttlv.text(PASSWORD, "password-sentinel"),
            Ttlv.text(ONE_TIME_PASSWORD, "otp-sentinel"),
            Ttlv.bigInteger(KEY_MATERIAL, BigInteger.valueOf(123456789))));
  }

  private static void assertSafeTree(Ttlv node) {
    switch (node.type()) {
      case STRUCTURE -> node.children().forEach(NameTransferRunnerTest::assertSafeTree);
      case BYTE_STRING -> assertEquals(0, node.bytesValue().length);
      case BIG_INTEGER -> assertEquals(BigInteger.ZERO, node.bigIntegerValue());
      case TEXT_STRING -> {
        if (node.tag() == PASSWORD.code() || node.tag() == ONE_TIME_PASSWORD.code())
          assertEquals("", node.textValue());
      }
      default -> {}
    }
  }

  private static long scopeDeadline() {
    return System.nanoTime() + Kms.callRemaining(Duration.ofSeconds(20));
  }

  private static void waitUntil(long deadline) {
    for (long left; (left = deadline - System.nanoTime()) > 0; ) {
      LockSupport.parkNanos(left);
      if (Thread.currentThread().isInterrupted()) throw new AssertionError("probe interrupted");
    }
  }

  @FunctionalInterface
  private interface Wire {
    Ttlv exchange(String host, Ttlv request, CallContext context) throws IOException;
  }

  private static final class Runner implements AutoCloseable {
    final Fixture f = new Fixture(KmipVersion.V2_1);
    final KeyHandle key = f.key();
    final List<String> wireHosts = new ArrayList<>();
    final List<KmsEvent> finished = new ArrayList<>(), retries = new ArrayList<>();
    Consumer<KmsEvent> started = e -> {};
    Wire exchange = (host, request, context) -> f.server.exchange(request, context);
    boolean armed;
    final Kms client;

    Runner() {
      client =
          Kms.connect(
              f.server
                  .configure()
                  .endpoints("a", "b")
                  .callTimeout(Duration.ofSeconds(3))
                  .retryPolicy(
                      RetryPolicy.defaults().toBuilder()
                          .maxAttempts(2)
                          .attemptTimeout(Duration.ofMillis(400))
                          .initialBackoff(Duration.ZERO)
                          .maxBackoff(Duration.ZERO)
                          .jitter(0)
                          .build())
                  .addListener(
                      new KmsListener() {
                        @Override
                        public void started(KmsEvent event) {
                          started.accept(event);
                        }

                        @Override
                        public void finished(KmsEvent event) {
                          finished.add(event);
                        }

                        @Override
                        public void retrying(KmsEvent event, Duration delay) {
                          retries.add(event);
                        }
                      })
                  .transport(
                      endpoint ->
                          new KmipTransport() {
                            @Override
                            public Ttlv exchange(Ttlv request) throws IOException {
                              return exchange(request, CallContext.NONE);
                            }

                            @Override
                            public Ttlv exchange(Ttlv request, CallContext context)
                                throws IOException {
                              if (armed) wireHosts.add(endpoint.host());
                              return exchange.exchange(endpoint.host(), request, context);
                            }
                          })
                  .build());
      armed = true;
      finished.clear();
      retries.clear();
    }

    void read(Kms kms) {
      kms.execute(
          "transfer-read",
          Kms.Kind.READ,
          key.id(),
          s ->
              s.call(
                  Requests.getAttributes()
                      .uniqueIdentifier(key.id())
                      .add(Ttlv.text(ATTRIBUTE_NAME, "Name"))
                      .build()));
    }

    @Override
    public void close() {
      client.close();
      f.close();
    }
  }
}
