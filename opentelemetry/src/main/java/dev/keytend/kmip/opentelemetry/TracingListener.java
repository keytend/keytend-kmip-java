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

import static dev.keytend.kmip.opentelemetry.Keys.*;

import dev.keytend.kmip.kms.KmsEvent;
import dev.keytend.kmip.kms.KmsListener;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanBuilder;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Context;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.LongAdder;

/**
 * {@link KmipTelemetry#tracingListener()}: a span per application call, a child span per attempt.
 * The call's span is a child of the context current on the thread that starts the call (the
 * application's span, for a call it makes); the spans are never made current. Paired by {@link
 * KmsEvent#callId()}: at most {@link #MAX_TRACKED_CALLS} calls in progress are tracked, also when
 * calls start on many threads at once (a call reserves its place before its span is made). While
 * that many are, a call that starts is not traced: it has no span, nor do its attempts, also when
 * room appears before they start. The calls being traced still end theirs; tracing resumes for
 * calls that start as they finish. Takes no lock.
 */
final class TracingListener implements KmsListener {
  static final int MAX_TRACKED_CALLS = 10_000;

  /** One call in progress: its span and its open attempt. */
  static final class Call {
    final Span span;

    /** The attempt in progress; a call's attempts run one after the other, on its thread. */
    volatile Span attempt;

    Call(Span span) {
      this.span = span;
    }
  }

  private final Tracer tracer;
  private final Attributes common;
  private final ConcurrentMap<Long, Call> calls = new ConcurrentHashMap<>();

  /**
   * The places taken: the calls in {@link #calls}, and those whose span is being made. Reserved
   * before the span is made, so that calls starting at once cannot all pass the bound.
   */
  private final AtomicInteger reserved = new AtomicInteger();

  /** Calls not traced because {@link #MAX_TRACKED_CALLS} were in progress; for tests. */
  private final LongAdder untraced = new LongAdder();

  TracingListener(Tracer tracer, Attributes common) {
    this.tracer = tracer;
    this.common = common;
  }

  /** The calls in progress; for tests. */
  int tracked() {
    return calls.size();
  }

  /** The calls not traced because the bound was reached; for tests. */
  long untraced() {
    return untraced.sum();
  }

  /** Reserves a place for another call, if there is one; counts one that has none. */
  private boolean reserve() {
    for (int taken = reserved.get(); taken < MAX_TRACKED_CALLS; taken = reserved.get())
      if (reserved.compareAndSet(taken, taken + 1)) return true;
    untraced.increment();
    return false;
  }

  private SpanBuilder span(String name, Context parent, SpanKind kind) {
    return tracer.spanBuilder(name).setParent(parent).setSpanKind(kind).setAllAttributes(common);
  }

  @Override
  public void callStarted(KmsEvent call) {
    if (!reserve()) return;
    Span span;
    try {
      SpanBuilder b =
          span("KMIP " + call.operation(), Context.current(), SpanKind.INTERNAL)
              .setAttribute(OPERATION, call.operation())
              .setAttribute(CALL_ID, call.callId());
      call.objectId().ifPresent(id -> b.setAttribute(OBJECT_ID, id));
      span = b.startSpan();
    } catch (RuntimeException | Error e) {
      reserved.decrementAndGet();
      throw e;
    }
    // A call starts once (Kms tells each listener once by identity): a second start keeps the
    // first.
    if (calls.putIfAbsent(call.callId(), new Call(span)) != null) {
      reserved.decrementAndGet();
      span.end();
    }
  }

  @Override
  public void started(KmsEvent event) {
    if (event.kind() != KmsEvent.Kind.ATTEMPT) return;
    // Kms tells callStarted before an attempt starts: a call without an entry is not traced.
    Call call = calls.get(event.callId());
    if (call == null) return;
    Context parent = Context.current().with(call.span);
    AttributesBuilder a =
        endpoint(Attributes.builder(), event.endpoint())
            .put(OPERATION, event.operation())
            .put(STEP, event.step())
            .put(ATTEMPT_NUMBER, (long) event.attempt())
            .put(CALL_ID, event.callId())
            .put(PROTOCOL_NAME, "kmip")
            .put(PROTOCOL_VERSION, String.valueOf(event.version()));
    event.objectId().ifPresent(id -> a.put(OBJECT_ID, id));
    Span attempt =
        span("KMIP " + event.step() + " attempt", parent, SpanKind.CLIENT)
            .setAllAttributes(a.build())
            .startSpan();
    Span previous = call.attempt;
    call.attempt = attempt;
    if (previous != null) previous.end();
  }

  @Override
  public void finished(KmsEvent event) {
    Call call = calls.get(event.callId());
    Span attempt = call == null ? null : call.attempt;
    if (attempt == null) return;
    call.attempt = null;
    if (event.outcome() == KmsEvent.Outcome.FAILED) {
      attempt.setAllAttributes(failure(Attributes.builder(), event.failure()).build());
      attempt.setStatus(StatusCode.ERROR);
    }
    attempt.end();
  }

  @Override
  public void retrying(KmsEvent failed, Duration delay) {
    Call call = calls.get(failed.callId());
    if (call == null) return;
    call.span.addEvent(
        "kmip.retry",
        failure(Attributes.builder(), failed.failure())
            .put(ATTEMPT_NUMBER, (long) failed.attempt())
            .put(RETRY_DELAY, seconds(delay))
            .build());
  }

  @Override
  public void callFinished(KmsEvent call) {
    Call c = calls.remove(call.callId());
    if (c == null) return;
    reserved.decrementAndGet();
    Span open = c.attempt;
    if (open != null) open.end();
    Span span = c.span;
    span.setAttribute(ATTEMPT_COUNT, (long) call.attempt());
    call.objectId().ifPresent(id -> span.setAttribute(OBJECT_ID, id));
    if (call.outcome() == KmsEvent.Outcome.FAILED) {
      span.setAllAttributes(failure(Attributes.builder(), call.failure()).build());
      call.failure().ifPresent(span::recordException);
      span.setStatus(StatusCode.ERROR);
    }
    span.end();
  }
}
