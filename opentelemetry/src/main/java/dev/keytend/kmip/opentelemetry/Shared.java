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

import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.metrics.Meter;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * What the module keeps per {@link Meter}, shared by every {@link KmipTelemetry} whose meter it is
 * (the SDK hands the same meter to every caller of one scope): the endpoint gauge's values, and the
 * observable series the open {@link KmipInstruments} report.
 *
 * <p>No lock of the module is held while it calls OpenTelemetry, and no OpenTelemetry callback
 * takes one: the gauge's callback reads a concurrent map, and this object's monitor guards only
 * {@link #claimed}, a plain set no callback reads.
 */
final class Shared {
  private static final Map<Meter, Shared> BY_METER =
      Collections.synchronizedMap(new WeakHashMap<>());

  /** {@code meter}'s shared state. */
  static Shared of(Meter meter) {
    return BY_METER.computeIfAbsent(meter, m -> new Shared());
  }

  /** An observable series: an instrument's name and the attributes of one of its measurements. */
  record Series(String instrument, Attributes attributes) {}

  /**
   * The value behind each {@code kmip.client.endpoint.available} series, by its attributes (the
   * telemetry's own and the endpoint's): set by every listener of this meter, so that the series
   * shows the last event any of them told, as one gauge does.
   */
  final ConcurrentMap<Attributes, AtomicLong> available = new ConcurrentHashMap<>();

  private final AtomicBoolean gaugeRegistered = new AtomicBoolean();

  /** The series of the open {@link KmipInstruments}, under this object's monitor. */
  private final Set<Series> claimed = new HashSet<>();

  /**
   * Registers the endpoint gauge's callback with {@code meter}, once: it reports {@link
   * #available}, without a lock.
   */
  void registerGauge(Meter meter) {
    if (!gaugeRegistered.compareAndSet(false, true)) return;
    try {
      meter
          .gaugeBuilder("kmip.client.endpoint.available")
          .ofLongs()
          .setUnit("1")
          .setDescription("1 while the endpoint answers, 0 once it was found unavailable")
          .buildWithCallback(m -> available.forEach((a, v) -> m.record(v.get(), a)));
    } catch (RuntimeException | Error e) {
      gaugeRegistered.set(false);
      throw e;
    }
  }

  /** {@code endpoint}'s first value, 1: only when no event set one yet. */
  void firstUse(Attributes endpoint) {
    if (!available.containsKey(endpoint)) available.putIfAbsent(endpoint, new AtomicLong(1));
  }

  /** {@code endpoint}'s value, whatever it was. */
  void set(Attributes endpoint, long value) {
    available.computeIfAbsent(endpoint, a -> new AtomicLong()).set(value);
  }

  /**
   * Claims {@code series} for one {@link KmipInstruments}: all or none.
   *
   * @throws IllegalStateException when another open one reports one of them
   */
  synchronized void claim(List<Series> series) {
    for (Series s : series)
      if (claimed.contains(s))
        throw new IllegalStateException(
            "Another source reports "
                + s.instrument()
                + " "
                + s.attributes()
                + " already: give this KmipTelemetry attributes of its own");
    Set<Series> distinct = new HashSet<>(series);
    if (distinct.size() != series.size())
      throw new IllegalStateException("A source reports one series twice: " + series);
    claimed.addAll(series);
  }

  /** Releases what {@link #claim} claimed. */
  synchronized void release(List<Series> series) {
    series.forEach(claimed::remove);
  }

  /** Whether {@code series} is claimed; for tests. */
  synchronized boolean claimed(Series series) {
    return claimed.contains(series);
  }
}
