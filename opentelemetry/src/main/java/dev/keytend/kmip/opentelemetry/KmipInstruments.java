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

import io.opentelemetry.api.metrics.BatchCallback;
import java.lang.ref.WeakReference;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Function;

/**
 * The observable instruments of one object of the SDK ({@link KmipTelemetry#connections}, {@link
 * KmipTelemetry#localKeys}, {@link KmipTelemetry#tlsIdentity}): one callback, which reads the
 * object each time a metric reader collects. {@link #close()} removes the callback; it never
 * closes the object or the application's {@code MeterProvider}.
 *
 * <p>The instruments hold the object until they are closed; the callback holds it weakly, so
 * instruments never closed report nothing once the object is unreachable. Close them when the
 * object is closed. Thread-safe.
 *
 * @since 0.10.0
 */
public final class KmipInstruments implements AutoCloseable {
  private final Shared shared;
  private final List<Shared.Series> series;
  private final AtomicBoolean closed;

  /** The object read, held until closed. */
  private volatile Object held;

  private final BatchCallback callback;

  private KmipInstruments(
      Shared shared,
      List<Shared.Series> series,
      Object held,
      AtomicBoolean closed,
      BatchCallback callback) {
    this.shared = shared;
    this.series = series;
    this.held = held;
    this.closed = closed;
    this.callback = callback;
  }

  /**
   * Claims {@code series}, then registers the callback {@code register} makes: it is given a
   * reader that hands {@code read} the object while it is reachable and these instruments are
   * open, and nothing otherwise. Nothing is claimed or registered when either step fails.
   */
  static <T> KmipInstruments open(
      Shared shared,
      List<Shared.Series> series,
      T object,
      Function<Consumer<Consumer<T>>, BatchCallback> register) {
    shared.claim(series);
    AtomicBoolean closed = new AtomicBoolean();
    WeakReference<T> ref = new WeakReference<>(object);
    Consumer<Consumer<T>> reader =
        read -> {
          T target = ref.get();
          if (target != null && !closed.get()) read.accept(target);
        };
    BatchCallback callback;
    try {
      callback = register.apply(reader);
    } catch (RuntimeException | Error e) {
      shared.release(series);
      throw e;
    }
    return new KmipInstruments(shared, series, object, closed, callback);
  }

  /** The object read; null once closed. For tests. */
  Object held() {
    return held;
  }

  /**
   * Removes the callback, and lets another source report these instruments' series: a collection
   * that comes to the callback after this began reports none of them, also one that had started.
   * Idempotent.
   */
  @Override
  public void close() {
    if (!closed.compareAndSet(false, true)) return;
    held = null;
    try {
      callback.close();
    } finally {
      shared.release(series);
    }
  }
}
