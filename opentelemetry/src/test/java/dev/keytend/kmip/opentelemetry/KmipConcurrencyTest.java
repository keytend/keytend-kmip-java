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
import dev.keytend.kmip.testing.InMemoryKmipServer;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.metrics.BatchCallback;
import io.opentelemetry.api.metrics.DoubleGaugeBuilder;
import io.opentelemetry.api.metrics.DoubleHistogramBuilder;
import io.opentelemetry.api.metrics.LongCounterBuilder;
import io.opentelemetry.api.metrics.LongUpDownCounterBuilder;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.api.metrics.MeterBuilder;
import io.opentelemetry.api.metrics.MeterProvider;
import io.opentelemetry.api.metrics.ObservableMeasurement;
import io.opentelemetry.api.trace.TracerProvider;
import io.opentelemetry.context.propagation.ContextPropagators;
import io.opentelemetry.sdk.trace.data.SpanData;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;
import org.junit.jupiter.api.RepeatedTest;
import org.junit.jupiter.api.Test;

/**
 * The module under concurrent use: events from many threads add up and pair with their own calls,
 * an attempt's first use and an endpoint found unavailable never leave the gauge at 1, a series is
 * claimed by one source only, and no lock of the module is held while it is inside OpenTelemetry
 * or needed by a collection.
 */
class KmipConcurrencyTest {
  static final int THREADS = 8;

  static <T> List<T> all(List<Future<T>> futures) throws Exception {
    List<T> out = new ArrayList<>();
    for (Future<T> f : futures) out.add(f.get(60, TimeUnit.SECONDS));
    return out;
  }

  /**
   * Eight threads call one {@code Kms} at once: every call is timed once, every call span holds
   * only its own attempts, and nothing is left tracked.
   */
  @RepeatedTest(10)
  void callsFromManyThreadsAddUpAndPairWithTheirOwnAttempts() throws Exception {
    int perThread = 25;
    ExecutorService pool = Executors.newFixedThreadPool(THREADS);
    try (Otel otel = new Otel()) {
      KmipTelemetry telemetry = KmipTelemetry.create(otel.sdk);
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      try (Kms kms =
          Kms.connect(
              server
                  .configure()
                  .addListener(telemetry.metricsListener())
                  .addListener(telemetry.tracingListener())
                  .build())) {
        KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
        otel.exporter.reset();
        CyclicBarrier start = new CyclicBarrier(THREADS);
        List<Future<Integer>> futures = new ArrayList<>();
        for (int t = 0; t < THREADS; t++)
          futures.add(
              pool.submit(
                  () -> {
                    start.await();
                    for (int i = 0; i < perThread; i++) key.attributes();
                    return perThread;
                  }));
        all(futures);
      }
      assertEquals(
          (long) THREADS * perThread,
          otel.histogramCount("kmip.client.call.duration", attrs("kmip.operation", "attributes")));
      List<SpanData> spans = otel.spans();
      Map<String, SpanData> calls =
          spans.stream()
              .filter(s -> s.getName().equals("KMIP attributes"))
              .collect(Collectors.toMap(SpanData::getSpanId, s -> s));
      assertEquals(THREADS * perThread, calls.size());
      for (SpanData s : spans) {
        if (calls.containsKey(s.getSpanId())) continue;
        SpanData call = calls.get(s.getParentSpanId());
        assertNotNull(call, "an attempt under a call: " + s);
        assertEquals(
            call.getAttributes().get(Keys.CALL_ID),
            s.getAttributes().get(Keys.CALL_ID),
            "under its own call");
      }
      assertEquals(0, ((TracingListener) telemetry.tracingListener()).tracked());
    } finally {
      pool.shutdownNow();
    }
  }

  /** Events of every kind from eight threads at once: the counts are exact. */
  @RepeatedTest(10)
  void eventsFromManyThreadsAreCountedExactly() throws Exception {
    int perThread = 500;
    ExecutorService pool = Executors.newFixedThreadPool(THREADS);
    try (Otel otel = new Otel()) {
      KmsListener l = KmipTelemetry.create(otel.sdk).metricsListener();
      CyclicBarrier start = new CyclicBarrier(THREADS);
      List<Future<Integer>> futures = new ArrayList<>();
      for (int t = 0; t < THREADS; t++)
        futures.add(
            pool.submit(
                () -> {
                  start.await();
                  for (int i = 0; i < perThread; i++) {
                    l.leaseGranted("k", java.time.Duration.ofMinutes(1), i % 2 == 0);
                    l.localKeySelected("tde", null, "k");
                    l.endpointUnavailable("kms:5696", "refused");
                  }
                  return perThread;
                }));
      all(futures);
      int n = THREADS * perThread;
      assertEquals(n / 2, otel.longValue("kmip.leases", attrs("kmip.lease.result", "renewed")));
      assertEquals(n / 2, otel.longValue("kmip.leases", attrs("kmip.lease.result", "granted")));
      assertEquals(n, otel.longValue("kmip.localkeys.selections", Attributes.empty()));
      assertEquals(0, otel.longValue("kmip.client.endpoint.available", Attributes.empty()));
    } finally {
      pool.shutdownNow();
    }
  }

  /**
   * An attempt's first use of an endpoint sets 1 only when nothing was told of it; an endpoint
   * found unavailable always sets 0. Raced, in either order, the gauge reads 0.
   */
  @RepeatedTest(5)
  void aFirstUseRacingAnUnavailableEndpointLeavesZero() throws Exception {
    KmsEvent[] attempt = new KmsEvent[1];
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms =
        Kms.connect(
            server
                .configure()
                .addListener(
                    new KmsListener() {
                      @Override
                      public void started(KmsEvent event) {
                        attempt[0] = event;
                      }
                    })
                .build())) {
      kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
    }
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try (Otel otel = new Otel()) {
      int rounds = 200;
      for (int i = 0; i < rounds; i++) {
        // Each round its own series, new to the meter's shared values.
        KmsListener l =
            KmipTelemetry.builder(otel.sdk)
                .attributes(attrs("round", String.valueOf(i)))
                .build()
                .metricsListener();
        CyclicBarrier start = new CyclicBarrier(2);
        Future<?> used =
            pool.submit(
                () -> {
                  start.await();
                  l.started(attempt[0]);
                  return null;
                });
        Future<?> down =
            pool.submit(
                () -> {
                  start.await();
                  l.endpointUnavailable(attempt[0].endpoint(), "refused");
                  return null;
                });
        used.get(30, TimeUnit.SECONDS);
        down.get(30, TimeUnit.SECONDS);
      }
      for (int i = 0; i < rounds; i++)
        assertEquals(
            0,
            otel.longValue("kmip.client.endpoint.available", attrs("round", String.valueOf(i))),
            "round " + i);
    } finally {
      pool.shutdownNow();
    }
  }

  /** Eight threads open the same series at once: one wins, the others are refused. */
  @RepeatedTest(10)
  void oneOfManyOpeningTheSameSeriesAtOnceWins() throws Exception {
    ExecutorService pool = Executors.newFixedThreadPool(THREADS);
    try (Otel otel = new Otel();
        Kms kms = InMemoryKmipServer.of(KmipVersion.V2_1).connect()) {
      CyclicBarrier start = new CyclicBarrier(THREADS);
      List<Future<KmipInstruments>> futures = new ArrayList<>();
      AtomicInteger refused = new AtomicInteger();
      for (int t = 0; t < THREADS; t++)
        futures.add(
            pool.submit(
                () -> {
                  KmipTelemetry telemetry = KmipTelemetry.create(otel.sdk);
                  start.await();
                  try {
                    return telemetry.connections(kms);
                  } catch (IllegalStateException e) {
                    refused.incrementAndGet();
                    return null;
                  }
                }));
      List<KmipInstruments> opened = new ArrayList<>();
      for (KmipInstruments i : all(futures)) if (i != null) opened.add(i);
      assertEquals(1, opened.size());
      assertEquals(THREADS - 1, refused.get());
      opened.get(0).close();
      KmipTelemetry.create(otel.sdk).connections(kms).close(); // released
    } finally {
      pool.shutdownNow();
    }
  }

  /**
   * A collection runs while another thread holds the lock of the module's shared state (as an
   * open or close of instruments does): it does not wait for it, since no callback of the module
   * takes a lock.
   */
  @Test
  void aCollectionNeedsNoLockOfTheModule() throws Exception {
    try (Otel otel = new Otel();
        Kms kms = InMemoryKmipServer.of(KmipVersion.V2_1).connect()) {
      KmipTelemetry telemetry = KmipTelemetry.create(otel.sdk);
      telemetry.metricsListener().endpointUnavailable("kms:5696", "refused");
      try (KmipInstruments instruments = telemetry.connections(kms)) {
        CountDownLatch holding = new CountDownLatch(1), release = new CountDownLatch(1);
        Thread holder =
            new Thread(
                () -> {
                  synchronized (telemetry.shared()) {
                    holding.countDown();
                    try {
                      release.await();
                    } catch (InterruptedException e) {
                      Thread.currentThread().interrupt();
                    }
                  }
                });
        holder.start();
        try {
          assertTrue(holding.await(30, TimeUnit.SECONDS));
          ExecutorService collector = Executors.newSingleThreadExecutor();
          try {
            Future<Long> value =
                collector.submit(
                    () -> otel.longValue("kmip.client.endpoint.available", Attributes.empty()));
            assertEquals(0, value.get(30, TimeUnit.SECONDS), "collected while the lock is held");
          } finally {
            collector.shutdownNow();
          }
        } finally {
          release.countDown();
          holder.join(30_000);
        }
      }
    }
  }

  /**
   * An open of instruments that is held inside OpenTelemetry (its callback's registration blocks)
   * holds no lock of the module meanwhile: another open of the same series is refused at once,
   * another of other series opens and closes, the listeners record, and a collection completes.
   */
  @Test
  void anOpenHeldInsideOpenTelemetryHoldsNoLockOfTheModule() throws Exception {
    try (Otel otel = new Otel();
        Kms first = InMemoryKmipServer.of(KmipVersion.V2_1).connect();
        Kms second = InMemoryKmipServer.of(KmipVersion.V2_1).connect()) {
      CountDownLatch inside = new CountDownLatch(1), release = new CountDownLatch(1);
      AtomicInteger blocking = new AtomicInteger(1);
      OpenTelemetry blocked = blockingRegistration(otel.sdk, blocking, inside, release);
      KmipTelemetry telemetry = KmipTelemetry.create(blocked);
      KmipTelemetry tagged =
          KmipTelemetry.builder(blocked).attributes(attrs("client", "second")).build();
      ExecutorService pool = Executors.newSingleThreadExecutor();
      ExecutorService probe = Executors.newSingleThreadExecutor();
      try {
        Future<KmipInstruments> held = pool.submit(() -> telemetry.connections(first));
        assertTrue(inside.await(30, TimeUnit.SECONDS), "the open is inside OpenTelemetry");
        // On another thread, so that a lock held by the open fails the test rather than hang it.
        Future<?> meanwhile =
            probe.submit(
                () -> {
                  assertThrows(
                      IllegalStateException.class,
                      () -> KmipTelemetry.create(blocked).connections(first),
                      "refused at once: the series are claimed");
                  tagged.connections(second).close();
                  telemetry.metricsListener().endpointUnavailable("kms:5696", "refused");
                  assertEquals(
                      0,
                      otel.longValue(
                          "kmip.client.endpoint.available", attrs("server.address", "kms")));
                  return null;
                });
        meanwhile.get(10, TimeUnit.SECONDS);
        assertFalse(held.isDone());
        release.countDown();
        held.get(30, TimeUnit.SECONDS).close();
      } finally {
        release.countDown();
        pool.shutdownNow();
        probe.shutdownNow();
      }
    }
  }

  /**
   * {@code delegate} with meters whose first {@code batchCallback} (while {@code blocking} is
   * positive) signals {@code inside} and waits for {@code release} before it registers.
   */
  static OpenTelemetry blockingRegistration(
      OpenTelemetry delegate,
      AtomicInteger blocking,
      CountDownLatch inside,
      CountDownLatch release) {
    MeterProvider meters =
        new MeterProvider() {
          @Override
          public MeterBuilder meterBuilder(String name) {
            MeterBuilder real = delegate.getMeterProvider().meterBuilder(name);
            return new MeterBuilder() {
              @Override
              public MeterBuilder setSchemaUrl(String url) {
                real.setSchemaUrl(url);
                return this;
              }

              @Override
              public MeterBuilder setInstrumentationVersion(String version) {
                real.setInstrumentationVersion(version);
                return this;
              }

              @Override
              public Meter build() {
                return blockingMeter(real.build(), blocking, inside, release);
              }
            };
          }
        };
    return new OpenTelemetry() {
      @Override
      public TracerProvider getTracerProvider() {
        return delegate.getTracerProvider();
      }

      @Override
      public MeterProvider getMeterProvider() {
        return meters;
      }

      @Override
      public ContextPropagators getPropagators() {
        return delegate.getPropagators();
      }
    };
  }

  /** The meters of {@link #blockingRegistration}: one per real meter, as the SDK's are. */
  private static final Map<Meter, Meter> BLOCKING = new java.util.concurrent.ConcurrentHashMap<>();

  static Meter blockingMeter(
      Meter real, AtomicInteger blocking, CountDownLatch inside, CountDownLatch release) {
    return BLOCKING.computeIfAbsent(
        real,
        r ->
            new Meter() {
              @Override
              public LongCounterBuilder counterBuilder(String name) {
                return r.counterBuilder(name);
              }

              @Override
              public LongUpDownCounterBuilder upDownCounterBuilder(String name) {
                return r.upDownCounterBuilder(name);
              }

              @Override
              public DoubleHistogramBuilder histogramBuilder(String name) {
                return r.histogramBuilder(name);
              }

              @Override
              public DoubleGaugeBuilder gaugeBuilder(String name) {
                return r.gaugeBuilder(name);
              }

              @Override
              public BatchCallback batchCallback(
                  Runnable callback,
                  ObservableMeasurement observableMeasurement,
                  ObservableMeasurement... additionalMeasurements) {
                if (blocking.getAndDecrement() > 0) {
                  inside.countDown();
                  try {
                    assertTrue(release.await(30, TimeUnit.SECONDS));
                  } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                  }
                }
                return r.batchCallback(callback, observableMeasurement, additionalMeasurements);
              }
            });
  }
}
