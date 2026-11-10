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

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.sdk.OpenTelemetrySdk;
import io.opentelemetry.sdk.metrics.SdkMeterProvider;
import io.opentelemetry.sdk.metrics.data.DoublePointData;
import io.opentelemetry.sdk.metrics.data.HistogramPointData;
import io.opentelemetry.sdk.metrics.data.LongPointData;
import io.opentelemetry.sdk.metrics.data.MetricData;
import io.opentelemetry.sdk.metrics.data.MetricDataType;
import io.opentelemetry.sdk.metrics.data.PointData;
import io.opentelemetry.sdk.testing.exporter.InMemoryMetricReader;
import io.opentelemetry.sdk.testing.exporter.InMemorySpanExporter;
import io.opentelemetry.sdk.trace.SdkTracerProvider;
import io.opentelemetry.sdk.trace.data.SpanData;
import io.opentelemetry.sdk.trace.export.SimpleSpanProcessor;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * An OpenTelemetry SDK for a test: its metrics read by an in-memory reader (cumulative), its spans
 * exported to memory as each ends. Looks up points by their attributes.
 */
final class Otel implements AutoCloseable {
  /** The project's version, the root POM's: the module's, which the instrumentation scope has. */
  static String projectVersion() {
    try {
      java.util.regex.Matcher m =
          java.util.regex.Pattern.compile(
                  "<artifactId>keytend-kmip-parent</artifactId>\\s*<version>([^<]+)</version>")
              .matcher(java.nio.file.Files.readString(java.nio.file.Path.of("../pom.xml")));
      assertTrue(m.find(), "the project version in pom.xml");
      return m.group(1).strip();
    } catch (java.io.IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
  }

  final InMemoryMetricReader reader = InMemoryMetricReader.create();
  final InMemorySpanExporter exporter = InMemorySpanExporter.create();
  final OpenTelemetrySdk sdk =
      OpenTelemetrySdk.builder()
          .setMeterProvider(SdkMeterProvider.builder().registerMetricReader(reader).build())
          .setTracerProvider(
              SdkTracerProvider.builder()
                  .addSpanProcessor(SimpleSpanProcessor.create(exporter))
                  .build())
          .build();

  /** The attributes {@code keyValues} names: a {@code server.port} value is a long. */
  static Attributes attrs(Object... keyValues) {
    AttributesBuilder b = Attributes.builder();
    for (int i = 0; i < keyValues.length; i += 2) {
      String key = (String) keyValues[i];
      Object value = keyValues[i + 1];
      if (value instanceof Long l) b.put(AttributeKey.longKey(key), l);
      else if (value instanceof Integer n) b.put(AttributeKey.longKey(key), (long) n);
      else b.put(AttributeKey.stringKey(key), (String) value);
    }
    return b.build();
  }

  /** One collection. */
  Collection<MetricData> collect() {
    return reader.collectAllMetrics();
  }

  /** {@code name}'s metric in {@code collected}, if any. */
  static Optional<MetricData> metric(Collection<MetricData> collected, String name) {
    return collected.stream().filter(m -> m.getName().equals(name)).findFirst();
  }

  /** {@code name}'s metric of a new collection; it must be there. */
  MetricData metric(String name) {
    return metric(collect(), name).orElseThrow(() -> new AssertionError("no metric " + name));
  }

  static List<? extends PointData> points(MetricData m) {
    MetricDataType type = m.getType();
    return switch (type) {
      case HISTOGRAM -> new ArrayList<>(m.getHistogramData().getPoints());
      case LONG_SUM -> new ArrayList<>(m.getLongSumData().getPoints());
      case DOUBLE_SUM -> new ArrayList<>(m.getDoubleSumData().getPoints());
      case LONG_GAUGE -> new ArrayList<>(m.getLongGaugeData().getPoints());
      case DOUBLE_GAUGE -> new ArrayList<>(m.getDoubleGaugeData().getPoints());
      default -> throw new AssertionError("unexpected type " + type);
    };
  }

  /** Whether {@code point}'s attributes hold all of {@code subset}. */
  static boolean matches(PointData point, Attributes subset) {
    Map<AttributeKey<?>, Object> all = point.getAttributes().asMap();
    for (Map.Entry<AttributeKey<?>, Object> e : subset.asMap().entrySet())
      if (!e.getValue().equals(all.get(e.getKey()))) return false;
    return true;
  }

  /** The points of {@code m} whose attributes hold {@code subset}. */
  static List<PointData> matching(MetricData m, Attributes subset) {
    List<PointData> out = new ArrayList<>();
    for (PointData p : points(m)) if (matches(p, subset)) out.add(p);
    return out;
  }

  /** The one point of {@code m} whose attributes are exactly {@code exact}. */
  static PointData exactly(MetricData m, Attributes exact) {
    List<PointData> found = new ArrayList<>();
    for (PointData p : points(m)) if (p.getAttributes().equals(exact)) found.add(p);
    assertEquals(1, found.size(), m.getName() + " " + exact + " in " + points(m));
    return found.get(0);
  }

  /** The count of the histogram points of {@code name} that hold {@code subset}. */
  long histogramCount(String name, Attributes subset) {
    long n = 0;
    for (PointData p : matching(metric(name), subset)) n += ((HistogramPointData) p).getCount();
    return n;
  }

  /** The sum of the long points (counters, gauges) of {@code name} that hold {@code subset}. */
  long longValue(String name, Attributes subset) {
    long n = 0;
    for (PointData p : matching(metric(name), subset)) n += ((LongPointData) p).getValue();
    return n;
  }

  /** The one double point of {@code name} that holds {@code subset}. */
  double doubleValue(String name, Attributes subset) {
    List<PointData> found = matching(metric(name), subset);
    assertEquals(1, found.size(), name + " " + subset + ": " + found);
    return ((DoublePointData) found.get(0)).getValue();
  }

  List<SpanData> spans() {
    return exporter.getFinishedSpanItems();
  }

  @Override
  public void close() {
    sdk.close();
  }
}
