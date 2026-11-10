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

import dev.keytend.kmip.kms.CustomAttribute;
import dev.keytend.kmip.kms.Expect;
import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyMismatchException;
import dev.keytend.kmip.kms.KeyQuery;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.kms.KmsListener;
import dev.keytend.kmip.kms.LocalKeys;
import dev.keytend.kmip.kms.LocalUse;
import dev.keytend.kmip.kms.NotFoundException;
import dev.keytend.kmip.kms.RetryPolicy;
import dev.keytend.kmip.kms.TlsIdentityFollower;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.sdk.metrics.data.HistogramPointData;
import io.opentelemetry.sdk.metrics.data.MetricData;
import io.opentelemetry.sdk.metrics.data.MetricDataType;
import io.opentelemetry.sdk.metrics.data.PointData;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The instruments, read through the OpenTelemetry SDK's in-memory reader, against the SDK's
 * in-memory KMIP server: the listener's histograms and counters with bounded attributes only, the
 * observable instruments' values, their names, units and types, and their close.
 */
class KmipTelemetryTest {
  static final CustomAttribute FAMILY = CustomAttribute.client("otel-family");

  static KmsConfig.Builder replicas(InMemoryKmipServer first, InMemoryKmipServer second) {
    return first
        .configureReplicas(second)
        .retryPolicy(
            RetryPolicy.builder()
                .maxAttempts(3)
                .initialBackoff(Duration.ofMillis(1))
                .cooldown(Duration.ZERO)
                .build());
  }

  static long available(Otel otel, String host) {
    return otel.longValue(
        "kmip.client.endpoint.available", attrs("server.address", host, "server.port", 5696L));
  }

  /** Every attribute value of every point collected: none may be an identifier or a file. */
  static void noIdentifiers(Collection<MetricData> collected, List<String> ids) {
    for (MetricData m : collected)
      for (PointData p : Otel.points(m))
        p.getAttributes()
            .forEach(
                (k, v) -> {
                  for (String id : ids)
                    assertFalse(
                        String.valueOf(v).contains(id), "an identifier as an attribute: " + m);
                });
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theListenerRecordsCallsAttemptsRetriesAndFailovers(KmipVersion version) {
    String v = version.toString();
    try (Otel otel = new Otel()) {
      KmipTelemetry telemetry = KmipTelemetry.create(otel.sdk);
      InMemoryKmipServer first = InMemoryKmipServer.of(version), second = first.replica();
      List<String> ids = new ArrayList<>();
      try (Kms kms =
          Kms.connect(replicas(first, second).addListener(telemetry.metricsListener()).build())) {
        KeyHandle key =
            kms.keys().createAes(256).named("metered").usages(KeyUsage.ENCRYPT).create();
        ids.add(key.id());
        key.attributes();
        assertEquals(1, available(otel, "in-memory"));

        first.unreachable(true);
        key.attributes(); // fails over
        assertEquals(0, available(otel, "in-memory"));
        assertEquals(1, available(otel, "in-memory-2"));
        first.unreachable(false);
        second.unreachable(true);
        key.attributes(); // back to the first
        assertEquals(1, available(otel, "in-memory"));
        assertEquals(0, available(otel, "in-memory-2"));
        second.unreachable(false);
        assertThrows(NotFoundException.class, () -> kms.keys().handle("no-such").attributes());
        ids.add("no-such");
      }
      Collection<MetricData> collected = otel.collect();
      MetricData calls = Otel.metric(collected, "kmip.client.call.duration").orElseThrow();
      assertEquals(MetricDataType.HISTOGRAM, calls.getType());
      assertEquals("s", calls.getUnit());
      assertEquals(
          3,
          ((HistogramPointData) Otel.exactly(calls, attrs("kmip.operation", "attributes")))
              .getCount(),
          "a success has no error.type");
      HistogramPointData failed =
          (HistogramPointData)
              Otel.exactly(
                  calls,
                  attrs(
                      "kmip.operation",
                      "attributes",
                      "error.type",
                      "not_found",
                      "kmip.result_reason",
                      "not_found"));
      assertEquals(1, failed.getCount());
      assertEquals(Keys.DURATION_BUCKETS, failed.getBoundaries(), "the conventions' boundaries");

      MetricData attempts = Otel.metric(collected, "kmip.client.attempt.duration").orElseThrow();
      assertEquals("s", attempts.getUnit());
      Attributes firstEndpoint =
          attrs(
              "kmip.operation",
              "attributes",
              "server.address",
              "in-memory",
              "server.port",
              5696L,
              "network.protocol.version",
              v);
      assertTrue(
          Otel.matching(attempts, firstEndpoint).stream()
              .anyMatch(p -> p.getAttributes().get(Keys.ERROR_TYPE) != null),
          "a failed attempt at the first endpoint: " + Otel.points(attempts));
      assertTrue(
          Otel.matching(
                  attempts, attrs("server.address", "in-memory-2", "network.protocol.version", v))
              .stream()
              .anyMatch(p -> p.getAttributes().get(Keys.ERROR_TYPE) == null));

      MetricData retries = Otel.metric(collected, "kmip.client.retries").orElseThrow();
      assertEquals(MetricDataType.LONG_SUM, retries.getType());
      assertTrue(retries.getLongSumData().isMonotonic());
      assertEquals("{retry}", retries.getUnit());
      assertEquals(
          2,
          Otel.matching(retries, attrs("kmip.operation", "attributes", "error.type", "retry"))
              .stream()
              .mapToLong(p -> ((io.opentelemetry.sdk.metrics.data.LongPointData) p).getValue())
              .sum());
      MetricData failovers = Otel.metric(collected, "kmip.client.failovers").orElseThrow();
      assertEquals("{failover}", failovers.getUnit());
      assertEquals(
          1,
          ((io.opentelemetry.sdk.metrics.data.LongPointData)
                  Otel.exactly(
                      failovers,
                      attrs(
                          "kmip.operation",
                          "attributes",
                          "kmip.failover.from",
                          "in-memory:5696",
                          "kmip.failover.to",
                          "in-memory-2:5696")))
              .getValue());
      assertEquals(
          1,
          otel.longValue(
              "kmip.client.failovers",
              attrs(
                  "kmip.failover.from", "in-memory-2:5696", "kmip.failover.to", "in-memory:5696")));
      MetricData gauge = Otel.metric(collected, "kmip.client.endpoint.available").orElseThrow();
      assertEquals(MetricDataType.LONG_GAUGE, gauge.getType());
      assertEquals("1", gauge.getUnit());
      for (MetricData m : collected) {
        assertEquals(
            KmipTelemetry.INSTRUMENTATION_SCOPE, m.getInstrumentationScopeInfo().getName());
        assertEquals(
            Otel.projectVersion(),
            m.getInstrumentationScopeInfo().getVersion(),
            "the module's version");
        assertFalse(m.getDescription().isEmpty(), m.getName());
      }
      noIdentifiers(collected, ids);
    }
  }

  @Test
  void eachEventHasItsInstrument() {
    try (Otel otel = new Otel()) {
      KmsListener l = KmipTelemetry.create(otel.sdk).metricsListener();
      l.leaseGranted("k-1", Duration.ofMinutes(1), false);
      l.leaseGranted("k-1", Duration.ofMinutes(1), true);
      l.leaseGranted("k-1", Duration.ofMinutes(1), true);
      l.leaseNotGranted("k-2", Duration.ofMinutes(1));
      l.credentialsReloaded("/etc/kms/client.pem");
      l.credentialsReloadFailed("/etc/kms/client.pem", "cut short");
      l.credentialsStillChanging("/etc/kms/client.pem", Duration.ofSeconds(4));
      l.clientCertificateRenewed("aa", "bb", java.time.Instant.EPOCH);
      l.clientCertificateRenewalFailed("bb", "refused");
      l.clientCertificateMayBeLockedOut("bb", "lost");
      l.clientCertificateRenewalWarning("bb", "within renewBefore already");
      l.keyStateChanged("k-1", KeyState.ACTIVE, KeyState.COMPROMISED);
      l.staleHandle("k-1", List.of("k-3"));
      l.concurrentReplacement("k-1", List.of("k-3", "k-4"));
      l.concurrentReplacement("k-5", List.of("k-6"));
      l.concurrentReplacement("k-7", List.of("k-8"));
      l.currentKeyCheckFailed("k-1", 1, notFound());
      l.localKeySelected("tde", null, "k-1");
      l.localKeyLoaded("tde", "k-1", LocalUse.ENCRYPT, Duration.ofMillis(5));
      l.localKeyRefreshFailed("tde", "k-1", LocalUse.DECRYPT, notFound(), Duration.ZERO);
      Collection<MetricData> collected = otel.collect();
      Map<String, String> units =
          Map.ofEntries(
              Map.entry("kmip.leases", "{lease}"),
              Map.entry("kmip.tls.reloads", "{reload}"),
              Map.entry("kmip.tls.renewals", "{renewal}"),
              Map.entry("kmip.tls.renewal.warnings", "{warning}"),
              Map.entry("kmip.key.state.changes", "{change}"),
              Map.entry("kmip.key.stale_handles", "{handle}"),
              Map.entry("kmip.key.concurrent_replacements", "{replacement}"),
              Map.entry("kmip.currentkey.check.failures", "{failure}"),
              Map.entry("kmip.localkeys.selections", "{selection}"),
              Map.entry("kmip.localkeys.load.duration", "s"),
              Map.entry("kmip.localkeys.refresh.failures", "{failure}"));
      units.forEach(
          (name, unit) ->
              assertEquals(unit, Otel.metric(collected, name).orElseThrow().getUnit(), name));
      assertEquals(units.size(), collected.size(), "no other instrument: " + collected);
      assertEquals(1, otel.longValue("kmip.leases", attrs("kmip.lease.result", "granted")));
      assertEquals(2, otel.longValue("kmip.leases", attrs("kmip.lease.result", "renewed")));
      assertEquals(1, otel.longValue("kmip.leases", attrs("kmip.lease.result", "not_granted")));
      for (String result : List.of("success", "failure", "still_changing"))
        assertEquals(
            1, otel.longValue("kmip.tls.reloads", attrs("kmip.tls.reload.result", result)));
      for (String result : List.of("success", "failure", "locked_out"))
        assertEquals(
            1, otel.longValue("kmip.tls.renewals", attrs("kmip.tls.renewal.result", result)));
      // A warning is not an outcome: the renewals stay one per attempt.
      assertEquals(3, otel.longValue("kmip.tls.renewals", attrs()));
      assertEquals(1, otel.longValue("kmip.tls.renewal.warnings", attrs()));
      assertEquals(
          1,
          otel.longValue(
              "kmip.key.state.changes",
              attrs("kmip.key.state.from", "active", "kmip.key.state.to", "compromised")));
      assertEquals(1, otel.longValue("kmip.key.stale_handles", Attributes.empty()));
      assertEquals(
          1,
          otel.longValue(
              "kmip.key.concurrent_replacements", attrs("kmip.key.replacement.kind", "several")));
      assertEquals(
          2,
          otel.longValue(
              "kmip.key.concurrent_replacements",
              attrs("kmip.key.replacement.kind", "another_caller")));
      assertEquals(1, otel.longValue("kmip.currentkey.check.failures", Attributes.empty()));
      assertEquals(
          1, otel.longValue("kmip.localkeys.selections", attrs("kmip.localkeys.name", "tde")));
      HistogramPointData load =
          (HistogramPointData)
              Otel.exactly(
                  Otel.metric(collected, "kmip.localkeys.load.duration").orElseThrow(),
                  attrs("kmip.localkeys.name", "tde", "kmip.localkeys.purpose", "encrypt"));
      assertEquals(0.005, load.getSum(), 1e-9, "seconds");
      assertEquals(
          1,
          otel.longValue(
              "kmip.localkeys.refresh.failures",
              attrs("kmip.localkeys.name", "tde", "kmip.localkeys.purpose", "decrypt")));
      for (MetricData m : collected)
        for (PointData p : Otel.points(m))
          p.getAttributes()
              .forEach(
                  (k, value) ->
                      assertFalse(
                          String.valueOf(value).startsWith("k-")
                              || String.valueOf(value).contains("/etc/"),
                          "an identifier or a file as an attribute: " + m));
    }
  }

  @Test
  void aCallTheSdkRefusesAfterItsRequestsIsAFailure() {
    try (Otel otel = new Otel()) {
      KmipTelemetry telemetry = KmipTelemetry.create(otel.sdk);
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      try (Kms kms =
          Kms.connect(server.configure().addListener(telemetry.metricsListener()).build())) {
        KeyHandle key =
            kms.keys()
                .createAes(256)
                .named("decrypt-only")
                .extractable(true)
                .usages(KeyUsage.DECRYPT)
                .create();
        KeyMismatchException refused =
            assertThrows(
                KeyMismatchException.class,
                () -> key.asSecretKey(Expect.aes(256), LocalUse.ENCRYPT));
        MetricData calls = otel.metric("kmip.client.call.duration");
        assertEquals(
            1,
            ((HistogramPointData)
                    Otel.exactly(
                        calls,
                        attrs(
                            "kmip.operation",
                            "asSecretKey",
                            "error.type",
                            Keys.lower(refused.category()))))
                .getCount());
        assertTrue(
            Otel.matching(calls, attrs("kmip.operation", "asSecretKey")).stream()
                .allMatch(p -> p.getAttributes().get(Keys.ERROR_TYPE) != null),
            "no success");
      }
    }
  }

  /**
   * A shared KMS's connection instruments report its endpoint before it connects (nothing opened),
   * and the connections its caches opened once it has.
   */
  @Test
  void theConnectionsOfASharedKmsReadZeroUntilItConnects(@TempDir Path dir) throws Exception {
    try (Otel otel = new Otel();
        TlsKmipServer tls = new TlsKmipServer(InMemoryKmipServer.of(KmipVersion.V2_1), dir)) {
      KmipTelemetry telemetry = KmipTelemetry.create(otel.sdk);
      CustomAttribute family = CustomAttribute.client("family");
      try (Kms admin = Kms.connect(tls.configure().build())) {
        admin
            .keys()
            .createAes(256)
            .extractable(true)
            .custom(family, "orders")
            .named("orders-write")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .create();
      }
      Attributes endpoint = attrs("server.address", "localhost", "server.port", tls.port());
      try (LocalKeys.SharedKms shared = LocalKeys.sharedKms(tls.configure().build());
          KmipInstruments instruments = telemetry.connections(shared);
          LocalKeys cache =
              shared
                  .localKeys("orders-write")
                  .scope(KeyQuery.all().custom(family, "orders"))
                  .expect(Expect.aes(256))
                  .open()) {
        MetricData opened =
            Otel.metric(otel.collect(), "kmip.client.connection.opened").orElseThrow();
        assertEquals(
            0,
            ((io.opentelemetry.sdk.metrics.data.LongPointData) Otel.exactly(opened, endpoint))
                .getValue(),
            "not connected");
        try (LocalKeys.Use ignored = cache.forEncrypt()) {}
        long now = shared.connectionStats().get(0).opened();
        assertTrue(now >= 1, shared.connectionStats().toString());
        opened = Otel.metric(otel.collect(), "kmip.client.connection.opened").orElseThrow();
        assertEquals(
            now,
            ((io.opentelemetry.sdk.metrics.data.LongPointData) Otel.exactly(opened, endpoint))
                .getValue());
      }
    }
  }

  @Test
  void theConnectionsInstrumentsReadEachMeasuredEndpointAndCloseRemovesThem(@TempDir Path dir)
      throws Exception {
    try (Otel otel = new Otel();
        TlsKmipServer tls = new TlsKmipServer(InMemoryKmipServer.of(KmipVersion.V2_1), dir)) {
      KmipTelemetry telemetry = KmipTelemetry.create(otel.sdk);
      try (Kms kms = Kms.connect(tls.configure().build())) {
        KmipInstruments instruments = telemetry.connections(kms);
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
        Kms.ConnectionStats stats = kms.connectionStats().get(0);
        assertTrue(stats.measured());
        Attributes endpoint = attrs("server.address", "localhost", "server.port", tls.port());
        Collection<MetricData> collected = otel.collect();
        MetricData count = Otel.metric(collected, "kmip.client.connection.count").orElseThrow();
        assertEquals(MetricDataType.LONG_SUM, count.getType());
        assertFalse(count.getLongSumData().isMonotonic(), "an up-down counter");
        assertEquals("{connection}", count.getUnit());
        long idle =
            ((io.opentelemetry.sdk.metrics.data.LongPointData)
                    Otel.exactly(
                        count, endpoint.toBuilder().put(Keys.CONNECTION_STATE, "idle").build()))
                .getValue();
        long used =
            ((io.opentelemetry.sdk.metrics.data.LongPointData)
                    Otel.exactly(
                        count, endpoint.toBuilder().put(Keys.CONNECTION_STATE, "used").build()))
                .getValue();
        assertEquals(stats.open(), idle + used, "the states add up to all open");
        assertTrue(idle >= 1, "the pooled connection: " + stats);
        MetricData opened = Otel.metric(collected, "kmip.client.connection.opened").orElseThrow();
        assertTrue(opened.getLongSumData().isMonotonic());
        assertEquals(
            stats.opened(),
            ((io.opentelemetry.sdk.metrics.data.LongPointData) Otel.exactly(opened, endpoint))
                .getValue());
        assertTrue(stats.opened() >= 1);
        assertEquals(
            "{wait}",
            Otel.metric(collected, "kmip.client.connection.waits").orElseThrow().getUnit());
        MetricData waitTime =
            Otel.metric(collected, "kmip.client.connection.wait.time").orElseThrow();
        assertEquals(MetricDataType.DOUBLE_SUM, waitTime.getType());
        assertEquals("s", waitTime.getUnit());

        assertThrows(
            IllegalStateException.class,
            () -> telemetry.connections(kms.withTimeout(Duration.ofSeconds(5))),
            "a view reports the same series");
        assertThrows(
            IllegalStateException.class,
            () -> KmipTelemetry.create(otel.sdk).connections(kms),
            "another telemetry of the same meter, without attributes of its own");
        try (KmipInstruments tagged =
            KmipTelemetry.builder(otel.sdk)
                .attributes(attrs("client", "second"))
                .build()
                .connections(kms)) {
          assertEquals(
              stats.opened(),
              otel.longValue(
                  "kmip.client.connection.opened",
                  endpoint.toBuilder().put(AttributeKey.stringKey("client"), "second").build()));
        }
        assertSame(kms, instruments.held());
        instruments.close();
        instruments.close(); // idempotent
        assertNull(instruments.held(), "no longer held");
        assertTrue(
            Otel.metric(otel.collect(), "kmip.client.connection.opened").stream()
                .allMatch(m -> Otel.points(m).isEmpty()),
            "nothing reported once closed");
        try (KmipInstruments again = telemetry.connections(kms)) {
          assertEquals(stats.opened(), otel.longValue("kmip.client.connection.opened", endpoint));
        }
      }
    }
  }

  @Test
  void anEndpointWhoseTransportIsNotMeasuredReportsNothing() {
    try (Otel otel = new Otel()) {
      KmipTelemetry telemetry = KmipTelemetry.create(otel.sdk);
      InMemoryKmipServer first = InMemoryKmipServer.of(KmipVersion.V2_1), second = first.replica();
      try (Kms kms = Kms.connect(replicas(first, second).build());
          KmipInstruments instruments = telemetry.connections(kms)) {
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
        assertFalse(kms.connectionStats().get(0).measured());
        for (MetricData m : otel.collect())
          assertFalse(m.getName().startsWith("kmip.client.connection"), "reported: " + m);
      }
    }
  }

  @Test
  void aRegistrationThatFailsClaimsNothing() {
    try (Otel otel = new Otel()) {
      KmipTelemetry telemetry = KmipTelemetry.create(otel.sdk);
      List<Shared.Series> series =
          List.of(
              new Shared.Series("kmip.localkeys.entry.count", attrs("kmip.localkeys.name", "x")));
      IllegalStateException failure = new IllegalStateException("refused");
      assertSame(
          failure,
          assertThrows(
              IllegalStateException.class,
              () ->
                  KmipInstruments.open(
                      telemetry.shared(),
                      series,
                      new Object(),
                      reader -> {
                        throw failure;
                      })));
      assertFalse(telemetry.shared().claimed(series.get(0)), "released");
    }
  }

  @Test
  void theLocalKeysInstrumentsReadTheCache() {
    try (Otel otel = new Otel()) {
      KmipTelemetry telemetry = KmipTelemetry.create(otel.sdk);
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      try (Kms kms =
          Kms.connect(server.configure().addListener(telemetry.metricsListener()).build())) {
        KeyHandle key =
            kms.keys()
                .createAes(256)
                .named("otel-cache")
                .extractable(true)
                .custom(FAMILY, "orders")
                .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                .create();
        KmipInstruments instruments;
        try (LocalKeys cache =
            kms.keys()
                .localKeys("otel-cache")
                .scope(KeyQuery.all().custom(FAMILY, "orders"))
                .expect(Expect.aes(256))
                .ttl(Duration.ofMinutes(10))
                .open()) {
          instruments = telemetry.localKeys(cache);
          assertThrows(
              IllegalStateException.class,
              () -> telemetry.localKeys(cache),
              "one cache name, one set of series");
          for (int i = 0; i < 3; i++)
            try (LocalKeys.Use use = cache.forEncrypt()) {
              assertEquals(key.id(), use.id());
            }
          LocalKeys.Stats stats = cache.stats();
          Attributes name = attrs("kmip.localkeys.name", "otel-cache");
          assertEquals(
              stats.encryptHits(),
              otel.longValue(
                  "kmip.localkeys.requests",
                  attrs(
                      "kmip.localkeys.name",
                      "otel-cache",
                      "kmip.localkeys.purpose",
                      "encrypt",
                      "kmip.localkeys.result",
                      "hit")));
          assertEquals(
              stats.encryptMisses(),
              otel.longValue(
                  "kmip.localkeys.requests",
                  attrs("kmip.localkeys.purpose", "encrypt", "kmip.localkeys.result", "miss")));
          assertEquals(2, stats.encryptHits());
          Collection<MetricData> collected = otel.collect();
          MetricData entries = Otel.metric(collected, "kmip.localkeys.entry.count").orElseThrow();
          assertFalse(entries.getLongSumData().isMonotonic());
          assertEquals("{entry}", entries.getUnit());
          assertEquals(stats.size(), otel.longValue("kmip.localkeys.entry.count", name));
          for (String counter :
              List.of(
                  "kmip.localkeys.load.failures",
                  "kmip.localkeys.evictions",
                  "kmip.localkeys.capacity.waits"))
            assertEquals(0, otel.longValue(counter, name), counter);
          MetricData usable = Otel.metric(collected, "kmip.localkeys.usable").orElseThrow();
          assertEquals(MetricDataType.DOUBLE_GAUGE, usable.getType());
          assertEquals("s", usable.getUnit());
          double seconds = otel.doubleValue("kmip.localkeys.usable", name);
          assertTrue(seconds > 500 && seconds <= 600, "within the TTL: " + seconds);
          assertEquals(0, otel.longValue("kmip.localkeys.write.failing", name));
          assertEquals(1, otel.longValue("kmip.localkeys.selections", name), "from the listener");
          assertEquals(
              1,
              otel.histogramCount(
                  "kmip.client.call.duration", attrs("kmip.operation", "localKeys")),
              "one load, then hits");
          instruments.close();
        }
        assertTrue(
            Otel.metric(otel.collect(), "kmip.localkeys.usable").stream()
                .allMatch(m -> Otel.points(m).isEmpty()),
            "nothing reported once closed");
      }
    }
  }

  @Test
  void theTlsIdentityInstrumentReadsTheExpiryOfThePresentedCertificate(@TempDir Path dir)
      throws Exception {
    ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
    try (Otel otel = new Otel()) {
      KmipTelemetry telemetry = KmipTelemetry.create(otel.sdk);
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      KeyStore store = TlsKmipServer.selfSigned(dir);
      try (Kms kms = server.connect()) {
        kms.tls()
            .register(
                (PrivateKey) store.getKey("localhost", TlsKmipServer.PASSWORD),
                (X509Certificate) store.getCertificate("localhost"))
            .named("otel-node")
            .register();
        try (TlsIdentityFollower follower =
                kms.tls().follow("otel-node", Duration.ofHours(1), executor);
            KmipInstruments instruments = telemetry.tlsIdentity(follower)) {
          MetricData expiry = otel.metric("kmip.tls.certificate.expiry");
          assertEquals("s", expiry.getUnit());
          double days =
              otel.doubleValue(
                      "kmip.tls.certificate.expiry", attrs("kmip.tls.identity", "otel-node"))
                  / 86_400;
          assertTrue(days > 1 && days <= 2.01, "about 2 days: " + days);
          follower.close();
          assertTrue(
              Otel.metric(otel.collect(), "kmip.tls.certificate.expiry").stream()
                  .allMatch(m -> Otel.points(m).isEmpty()),
              "nothing presented once closed");
        }
      }
    } finally {
      executor.shutdownNow();
    }
  }

  @Test
  void theCallersAttributesAreOnEveryMeasurementAndMayNotUseTheModulesKeys() {
    for (String key :
        List.of(
            "kmip.operation",
            "kmip.anything",
            "error.type",
            "server.address",
            "server.port",
            "network.protocol.version",
            "network.protocol.name"))
      assertThrows(
          IllegalArgumentException.class,
          () -> KmipTelemetry.builder(OpenTelemetry.noop()).attributes(attrs(key, "x")),
          key);
    try (Otel otel = new Otel()) {
      KmsListener l =
          KmipTelemetry.builder(otel.sdk)
              .attributes(attrs("client", "billing"))
              .build()
              .metricsListener();
      l.leaseGranted("k-1", Duration.ofMinutes(1), false);
      l.staleHandle("k-1", List.of("k-2"));
      l.endpointUnavailable("kms-1.example.com:5696", "refused");
      for (MetricData m : otel.collect())
        for (PointData p : Otel.points(m))
          assertEquals(
              "billing", p.getAttributes().get(AttributeKey.stringKey("client")), m.getName());
      assertEquals(
          0,
          otel.longValue(
              "kmip.client.endpoint.available",
              attrs(
                  "client",
                  "billing",
                  "server.address",
                  "kms-1.example.com",
                  "server.port",
                  5696L)));
    }
  }

  @Test
  void listenersOfOneMeterShareTheEndpointGaugeUnlessTheirAttributesDiffer() {
    try (Otel otel = new Otel()) {
      KmsListener a = KmipTelemetry.create(otel.sdk).metricsListener();
      KmsListener b = KmipTelemetry.create(otel.sdk).metricsListener();
      KmsListener tagged =
          KmipTelemetry.builder(otel.sdk)
              .attributes(attrs("client", "b"))
              .build()
              .metricsListener();
      a.endpointUnavailable("kms:5696", "refused");
      b.endpointAvailable("kms:5696");
      tagged.endpointUnavailable("kms:5696", "refused");
      MetricData gauge = otel.metric("kmip.client.endpoint.available");
      assertEquals(2, Otel.points(gauge).size(), "one series each: " + Otel.points(gauge));
      assertEquals(
          1,
          ((io.opentelemetry.sdk.metrics.data.LongPointData)
                  Otel.exactly(gauge, attrs("server.address", "kms", "server.port", 5696L)))
              .getValue(),
          "the last event told");
      assertEquals(0, otel.longValue("kmip.client.endpoint.available", attrs("client", "b")));
    }
  }

  @Test
  void endpointsAreSplitIntoAddressAndPort() {
    assertEquals(
        attrs("server.address", "kms.example.com", "server.port", 5696L),
        Keys.endpoint(Attributes.builder(), "kms.example.com:5696").build());
    assertEquals(
        attrs("server.address", "::1", "server.port", 5696L),
        Keys.endpoint(Attributes.builder(), "[::1]:5696").build());
    assertEquals(
        attrs("server.address", "kms.example.com"),
        Keys.endpoint(Attributes.builder(), "kms.example.com").build());
    assertEquals(
        attrs("server.address", "::1"), Keys.endpoint(Attributes.builder(), "::1").build());
    assertEquals(
        attrs("server.address", "kms:http"),
        Keys.endpoint(Attributes.builder(), "kms:http").build());
  }

  @Test
  void withTheNoopOpenTelemetryEverythingDoesNothing() {
    KmipTelemetry telemetry = KmipTelemetry.create(OpenTelemetry.noop());
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms =
            Kms.connect(
                server
                    .configure()
                    .addListener(telemetry.metricsListener())
                    .addListener(telemetry.tracingListener())
                    .build());
        KmipInstruments instruments = telemetry.connections(kms)) {
      kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
      assertThrows(NotFoundException.class, () -> kms.keys().handle("no-such").attributes());
    }
    assertEquals(0, ((TracingListener) telemetry.tracingListener()).tracked());
  }

  /** A real failure: the SDK's exceptions are made only by the SDK. */
  static NotFoundException notFound() {
    try (Kms kms = InMemoryKmipServer.of(KmipVersion.V2_1).connect()) {
      return assertThrows(NotFoundException.class, () -> kms.keys().handle("gone").attributes());
    }
  }
}
