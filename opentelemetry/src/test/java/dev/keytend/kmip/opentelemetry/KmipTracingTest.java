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
package dev.keytend.kmip.opentelemetry;

import static dev.keytend.kmip.opentelemetry.Otel.attrs;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsEvent;
import dev.keytend.kmip.kms.KmsListener;
import dev.keytend.kmip.kms.NotFoundException;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import io.opentelemetry.sdk.trace.data.EventData;
import io.opentelemetry.sdk.trace.data.SpanData;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The tracing listener's spans, exported to memory by the OpenTelemetry SDK: a span per call, a
 * child per attempt, under the application's span, with the call's identifiers and outcome.
 */
class KmipTracingTest {
  static List<SpanData> named(List<SpanData> spans, String name) {
    return spans.stream().filter(s -> s.getName().equals(name)).collect(Collectors.toList());
  }

  static List<SpanData> childrenOf(List<SpanData> spans, SpanData parent) {
    return spans.stream()
        .filter(s -> s.getParentSpanId().equals(parent.getSpanId()))
        .collect(Collectors.toList());
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aCallIsASpanUnderTheApplicationsWithAChildPerAttempt(KmipVersion version) {
    try (Otel otel = new Otel()) {
      KmipTelemetry telemetry = KmipTelemetry.create(otel.sdk);
      InMemoryKmipServer first = InMemoryKmipServer.of(version), second = first.replica();
      String id;
      Span application = otel.sdk.getTracer("app").spanBuilder("handle order").startSpan();
      try (Kms kms =
          Kms.connect(
              KmipTelemetryTest.replicas(first, second)
                  .addListener(telemetry.tracingListener())
                  .build())) {
        KeyHandle key = kms.keys().createAes(256).named("traced").usages(KeyUsage.ENCRYPT).create();
        id = key.id();
        otel.exporter.reset();
        first.unreachable(true);
        try (Scope scope = application.makeCurrent()) {
          key.attributes(); // fails over, after retries
        }
      } finally {
        application.end();
      }
      List<SpanData> spans = otel.spans();
      SpanData app = named(spans, "handle order").get(0);
      List<SpanData> calls = named(spans, "KMIP attributes");
      assertEquals(1, calls.size(), "one span for the call: " + spans);
      SpanData call = calls.get(0);
      assertEquals(app.getSpanId(), call.getParentSpanId(), "under the application's span");
      assertEquals(app.getTraceId(), call.getTraceId());
      assertEquals(SpanKind.INTERNAL, call.getKind());
      assertEquals(StatusCode.UNSET, call.getStatus().getStatusCode(), "it returned");
      assertEquals("attributes", call.getAttributes().get(Keys.OPERATION));
      assertEquals(id, call.getAttributes().get(Keys.OBJECT_ID));
      assertNotNull(call.getAttributes().get(Keys.CALL_ID));
      assertNull(call.getAttributes().get(Keys.ERROR_TYPE));
      assertEquals(
          KmipTelemetry.INSTRUMENTATION_SCOPE, call.getInstrumentationScopeInfo().getName());
      assertEquals(Otel.projectVersion(), call.getInstrumentationScopeInfo().getVersion());

      List<SpanData> attempts = childrenOf(spans, call);
      assertEquals(
          (long) attempts.size(), call.getAttributes().get(Keys.ATTEMPT_COUNT), "every attempt");
      assertTrue(attempts.size() >= 2, "a failed attempt, then the other endpoint: " + attempts);
      for (SpanData a : attempts) {
        assertEquals(SpanKind.CLIENT, a.getKind());
        assertEquals("KMIP " + a.getAttributes().get(Keys.STEP) + " attempt", a.getName());
        assertEquals("kmip", a.getAttributes().get(Keys.PROTOCOL_NAME));
        assertEquals(version.toString(), a.getAttributes().get(Keys.PROTOCOL_VERSION));
        assertEquals(5696L, a.getAttributes().get(Keys.SERVER_PORT));
        assertEquals(call.getAttributes().get(Keys.CALL_ID), a.getAttributes().get(Keys.CALL_ID));
        assertTrue(a.getEndEpochNanos() <= call.getEndEpochNanos(), "ended inside the call");
      }
      SpanData failed = attempts.get(0);
      assertEquals("in-memory", failed.getAttributes().get(Keys.SERVER_ADDRESS));
      assertEquals(StatusCode.ERROR, failed.getStatus().getStatusCode());
      assertNotNull(failed.getAttributes().get(Keys.ERROR_TYPE));
      assertEquals(1L, failed.getAttributes().get(Keys.ATTEMPT_NUMBER));
      SpanData last = attempts.get(attempts.size() - 1);
      assertEquals("in-memory-2", last.getAttributes().get(Keys.SERVER_ADDRESS));
      assertEquals(StatusCode.UNSET, last.getStatus().getStatusCode());
      List<EventData> retries =
          call.getEvents().stream().filter(e -> e.getName().equals("kmip.retry")).toList();
      assertFalse(retries.isEmpty(), "the retries are events of the call");
      for (EventData e : retries) {
        assertEquals("retry", e.getAttributes().get(Keys.ERROR_TYPE));
        assertNotNull(e.getAttributes().get(Keys.RETRY_DELAY));
      }
      assertEquals(0, ((TracingListener) telemetry.tracingListener()).tracked(), "forgotten");
    }
  }

  @Test
  void aCallThatThrowsIsAnErrorWithTheException() {
    try (Otel otel = new Otel()) {
      KmipTelemetry telemetry =
          KmipTelemetry.builder(otel.sdk).attributes(attrs("client", "billing")).build();
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      try (Kms kms =
          Kms.connect(server.configure().addListener(telemetry.tracingListener()).build())) {
        assertThrows(NotFoundException.class, () -> kms.keys().handle("no-such").attributes());
      }
      List<SpanData> spans = otel.spans();
      SpanData call = named(spans, "KMIP attributes").get(0);
      assertEquals(SpanKind.INTERNAL, call.getKind());
      assertFalse(call.getParentSpanContext().isValid(), "no application span: a root");
      assertEquals(StatusCode.ERROR, call.getStatus().getStatusCode());
      assertEquals("not_found", call.getAttributes().get(Keys.ERROR_TYPE));
      assertEquals("not_found", call.getAttributes().get(Keys.RESULT_REASON));
      assertEquals("no-such", call.getAttributes().get(Keys.OBJECT_ID));
      EventData exception =
          call.getEvents().stream().filter(e -> e.getName().equals("exception")).findFirst().get();
      assertEquals(
          NotFoundException.class.getName(),
          exception.getAttributes().get(AttributeKey.stringKey("exception.type")));
      for (SpanData s : spans)
        assertEquals(
            "billing", s.getAttributes().get(AttributeKey.stringKey("client")), s.getName());
      SpanData attempt = childrenOf(spans, call).get(0);
      assertEquals(StatusCode.ERROR, attempt.getStatus().getStatusCode());
      assertEquals("not_found", attempt.getAttributes().get(Keys.ERROR_TYPE));
    }
  }

  @Test
  void aListenerGivenTwiceTracesACallOnce() {
    try (Otel otel = new Otel()) {
      KmsListener tracing = KmipTelemetry.create(otel.sdk).tracingListener();
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      try (Kms kms =
          Kms.connect(
              server
                  .configure()
                  .addListener(tracing)
                  .addListener(KmsListener.all(tracing, tracing))
                  .build())) {
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
      }
      assertEquals(1, named(otel.spans(), "KMIP create").size(), otel.spans().toString());
    }
  }

  /**
   * At the bound, a call that starts is not traced, and the calls being traced still end and
   * export their spans; tracing resumes as they finish.
   */
  @Test
  void callsInProgressAreBoundedAndTheTracedOnesStillEnd() {
    List<KmsEvent> starts = new ArrayList<>();
    List<KmsEvent> attempts = new ArrayList<>();
    Map<Long, KmsEvent> firstAttempt = new HashMap<>(), attemptEnd = new HashMap<>();
    Map<Long, KmsEvent> callEnd = new HashMap<>();
    KmsListener recorder =
        new KmsListener() {
          @Override
          public void callStarted(KmsEvent call) {
            starts.add(call);
          }

          @Override
          public void started(KmsEvent event) {
            attempts.add(event);
            firstAttempt.putIfAbsent(event.callId(), event);
          }

          @Override
          public void finished(KmsEvent event) {
            if (event.kind() == KmsEvent.Kind.ATTEMPT)
              attemptEnd.putIfAbsent(event.callId(), event);
          }

          @Override
          public void callFinished(KmsEvent call) {
            callEnd.put(call.callId(), call);
          }
        };
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = Kms.connect(server.configure().addListener(recorder).build())) {
      KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
      for (int i = 0; i <= TracingListener.MAX_TRACKED_CALLS + 1; i++) key.attributes();
    }
    int max = TracingListener.MAX_TRACKED_CALLS;
    try (Otel otel = new Otel()) {
      TracingListener tracing = (TracingListener) KmipTelemetry.create(otel.sdk).tracingListener();
      for (int i = 0; i < max; i++) {
        tracing.callStarted(starts.get(i));
        tracing.started(firstAttempt.get(starts.get(i).callId()));
      }
      assertEquals(max, tracing.tracked());
      KmsEvent over = starts.get(max);
      tracing.callStarted(over);
      assertEquals(max, tracing.tracked(), "not traced: the others are kept");
      assertEquals(1, tracing.untraced());
      long first = starts.get(0).callId();
      tracing.finished(attemptEnd.get(first));
      tracing.callFinished(callEnd.get(first));
      assertEquals(2, otel.spans().size(), "a traced call still ends its spans: " + otel.spans());
      assertEquals(max - 1, tracing.tracked());
      // Room now, but the untraced call's attempt has no call span: it gets no span either.
      tracing.started(firstAttempt.get(over.callId()));
      tracing.finished(attemptEnd.get(over.callId()));
      tracing.callFinished(callEnd.get(over.callId()));
      assertEquals(2, otel.spans().size(), "the untraced call has no span: " + otel.spans());
      assertEquals(max - 1, tracing.tracked());
      KmsEvent next = starts.get(max + 1);
      tracing.callStarted(next);
      assertEquals(max, tracing.tracked(), "traced again once a call finished");
      assertEquals(1, tracing.untraced());
    }
    try (Otel otel = new Otel()) {
      MetricsListener metrics = (MetricsListener) KmipTelemetry.create(otel.sdk).metricsListener();
      for (KmsEvent attempt : attempts) metrics.started(attempt);
      assertTrue(metrics.trackedForFailovers() <= MetricsListener.MAX_TRACKED_CALLS);
      assertEquals(
          firstAttempt.size() - MetricsListener.MAX_TRACKED_CALLS,
          metrics.trackedForFailovers(),
          "the bound cleared them once");
    }
  }

  /**
   * The bound holds when calls start on many threads at once. With one place left, eight
   * calls start together; the tracer holds each one that gets as far as making its span. Checking
   * the map's size let all eight past the bound (10,007 tracked); a place is reserved before the
   * span is made, so exactly one makes its span and the seven others are not traced.
   */
  @Test
  void callsStartingAtOnceCannotPassTheBound() throws Exception {
    int max = TracingListener.MAX_TRACKED_CALLS, racing = 8;
    List<KmsEvent> starts = new ArrayList<>();
    KmsListener recorder =
        new KmsListener() {
          @Override
          public void callStarted(KmsEvent call) {
            starts.add(call);
          }
        };
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = Kms.connect(server.configure().addListener(recorder).build())) {
      KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
      while (starts.size() < max - 1 + racing) key.attributes();
    }
    AtomicBoolean armed = new AtomicBoolean();
    AtomicInteger held = new AtomicInteger();
    CountDownLatch release = new CountDownLatch(1);
    Tracer noop = OpenTelemetry.noop().getTracer("test");
    Tracer holding =
        name -> {
          if (armed.get()) {
            held.incrementAndGet();
            try {
              release.await(30, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            }
          }
          return noop.spanBuilder(name);
        };
    TracingListener tracing = new TracingListener(holding, Attributes.empty());
    for (int i = 0; i < max - 1; i++) tracing.callStarted(starts.get(i));
    assertEquals(max - 1, tracing.tracked());
    armed.set(true);
    ExecutorService pool = Executors.newFixedThreadPool(racing);
    try {
      CountDownLatch go = new CountDownLatch(1);
      AtomicInteger returned = new AtomicInteger();
      List<Future<?>> done = new ArrayList<>();
      for (KmsEvent call : starts.subList(max - 1, max - 1 + racing))
        done.add(
            pool.submit(
                () -> {
                  go.await();
                  tracing.callStarted(call);
                  returned.incrementAndGet();
                  return null;
                }));
      go.countDown();
      // Each call either returned (not traced) or is held making its span.
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(30);
      while (returned.get() + held.get() < racing && System.nanoTime() < deadline)
        Thread.onSpinWait();
      assertEquals(racing, returned.get() + held.get(), "every call returned or is held");
      assertEquals(1, held.get(), "only the call with the last place makes its span");
      release.countDown();
      for (Future<?> f : done) f.get(30, TimeUnit.SECONDS);
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
    assertEquals(max, tracing.tracked(), "never more than the bound");
    assertEquals(racing - 1, tracing.untraced());
  }
}
