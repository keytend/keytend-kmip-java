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

import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.kms.KmsListener;
import dev.keytend.kmip.kms.LocalKeys;
import dev.keytend.kmip.kms.TlsIdentity;
import dev.keytend.kmip.kms.TlsIdentityFollower;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.metrics.Meter;
import io.opentelemetry.api.metrics.MeterBuilder;
import io.opentelemetry.api.metrics.ObservableDoubleMeasurement;
import io.opentelemetry.api.metrics.ObservableLongMeasurement;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.api.trace.TracerBuilder;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Properties;
import java.util.function.Function;

/**
 * OpenTelemetry metrics and traces for keytend-kmip. Make one with {@link #create} or {@link
 * #builder}, from your application's {@link OpenTelemetry}: your SDK's, or the Java agent's {@code
 * GlobalOpenTelemetry.get()}. Only the OpenTelemetry API is used. With {@link OpenTelemetry#noop()}
 * every instrument and span does nothing.
 *
 * <ul>
 *   <li>{@link #metricsListener()} turns the SDK's events into histograms and counters.
 *   <li>{@link #tracingListener()} turns its calls and attempts into spans.
 *   <li>{@link #connections}, {@link #localKeys} and {@link #tlsIdentity} make observable
 *       instruments, read when your SDK collects: connections, a {@link LocalKeys} cache's
 *       counters, a TLS certificate's expiry.
 * </ul>
 *
 * <p>In this example, {@code openTelemetry} is your application's {@code OpenTelemetry}, and the
 * PEM files hold the client's certificate chain, its private key and the CA certificates:
 *
 * <pre>{@code
 * KmipTelemetry telemetry = KmipTelemetry.create(openTelemetry);
 * KmsConfig config = KmsConfig.builder()
 *     .endpoints("kms-1.example.com:5696", "kms-2.example.com:5696")
 *     .clientIdentityPem(Path.of("client.pem"), Path.of("client.key"))
 *     .trustPem(Path.of("ca.pem"))
 *     .addListener(telemetry.metricsListener())
 *     .addListener(telemetry.tracingListener())
 *     .build();
 * try (Kms kms = Kms.connect(config);
 *     KmipInstruments connections = telemetry.connections(kms)) {
 *   // ...
 * }
 * }</pre>
 *
 * <p>The instrumentation scope is {@value #INSTRUMENTATION_SCOPE}, at the module's version. Names
 * follow the semantic conventions:
 *
 * <ul>
 *   <li>names are dot-separated;
 *   <li>durations are histograms in seconds ({@code s}), with the conventions' boundaries as
 *       advice, and counts have a {@code {unit}};
 *   <li>{@code error.type} is set on a failure only;
 *   <li>an endpoint is {@code server.address} and {@code server.port}.
 * </ul>
 *
 * <p>Metric attributes take few values: operations, the configured endpoints, KMIP versions, the
 * SDK's failure categories and the servers' reasons, key states, and the names the application
 * gives its caches and identities. A key or object identifier, a call id, a file name or a message
 * is never on a metric. The spans carry the identifiers, and the SDK's logs the messages.
 *
 * <p>From the metrics listener ({@link #metricsListener()}):
 *
 * <ul>
 *   <li>{@code kmip.client.call.duration}, histogram, {@code s}: each application call, with its
 *       retries, failovers and steps ({@link KmsListener#callFinished}). Attributes: {@code
 *       kmip.operation}, and when the call threw, {@code error.type} and {@code
 *       kmip.result_reason}. {@code error.type} is the failure's category in lower case, such as
 *       {@code not_found} or {@code retry}, or {@code _OTHER} for a failure that is not a {@code
 *       KmsException}. {@code kmip.result_reason} is the server's reason, when it gave one.
 *   <li>{@code kmip.client.attempt.duration}, histogram, {@code s}, attributes {@code
 *       kmip.operation}, {@code server.address}, {@code server.port}, {@code
 *       network.protocol.version} (the KMIP version), {@code error.type} on a failure: each
 *       attempt ({@link KmsListener#finished}).
 *   <li>{@code kmip.client.retries}, counter, {@code {retry}}, attributes {@code kmip.operation},
 *       {@code error.type}, {@code kmip.result_reason} ({@link KmsListener#retrying}).
 *   <li>{@code kmip.client.failovers}, counter, {@code {failover}}, attributes {@code
 *       kmip.operation}, {@code kmip.failover.from}, {@code kmip.failover.to} (the endpoints'
 *       {@code host:port}): each attempt sent to a different endpoint from the call's previous
 *       attempt.
 *   <li>{@code kmip.client.endpoint.available}, gauge, {@code 1}, attributes {@code
 *       server.address}, {@code server.port}: 1 once the endpoint was used or answered again
 *       ({@link KmsListener#endpointAvailable}), 0 once it was found unavailable ({@link
 *       KmsListener#endpointUnavailable}). Listeners whose events reach one series, with the same
 *       attributes, share it. It then shows the last event any of them reported. For a series per
 *       {@code Kms}, give each a telemetry with attributes of its own ({@link
 *       Builder#attributes}).
 *   <li>{@code kmip.localkeys.load.duration}, histogram, {@code s}, attributes {@code
 *       kmip.localkeys.name}, {@code kmip.localkeys.purpose} ({@code encrypt}, {@code decrypt}):
 *       each load that succeeded ({@link KmsListener#localKeyLoaded}).
 *   <li>{@code kmip.localkeys.refresh.failures}, counter, {@code {failure}}, attributes {@code
 *       kmip.localkeys.name}, {@code kmip.localkeys.purpose} ({@link
 *       KmsListener#localKeyRefreshFailed}).
 *   <li>{@code kmip.localkeys.selections}, counter, {@code {selection}}, attribute {@code
 *       kmip.localkeys.name} ({@link KmsListener#localKeySelected}).
 *   <li>{@code kmip.leases}, counter, {@code {lease}}, attribute {@code kmip.lease.result}
 *       ({@code granted}, {@code renewed}, {@code not_granted}).
 *   <li>{@code kmip.tls.reloads}, counter, {@code {reload}}, attribute {@code
 *       kmip.tls.reload.result} ({@code success}, {@code failure}, {@code still_changing}): the
 *       TLS files of {@code reloadOnChange()}.
 *   <li>{@code kmip.tls.renewals}, counter, {@code {renewal}}, attribute {@code
 *       kmip.tls.renewal.result} ({@code success}, {@code failure}, {@code locked_out}): renewals
 *       of the client certificate ({@link KmsListener#clientCertificateRenewed}, {@link
 *       KmsListener#clientCertificateRenewalFailed}, {@link
 *       KmsListener#clientCertificateMayBeLockedOut}), one result per attempt. Alert on {@code
 *       locked_out}.
 *   <li>{@code kmip.tls.renewal.warnings}, counter, {@code {warning}}: reports about renewal that
 *       need attention but are not an attempt's outcome ({@link
 *       KmsListener#clientCertificateRenewalWarning}).
 *   <li>{@code kmip.key.state.changes}, counter, {@code {change}}, attributes {@code
 *       kmip.key.state.from}, {@code kmip.key.state.to} (a {@code KeyState}, lower case).
 *   <li>{@code kmip.key.concurrent_replacements}, counter, {@code {replacement}}, attribute {@code
 *       kmip.key.replacement.kind}: {@code several} when a key has several newest keys (run
 *       {@code reconcile}), {@code another_caller} when another caller's one replacement was
 *       found (use {@code latest()}) ({@link KmsListener#concurrentReplacement}).
 *   <li>{@code kmip.key.stale_handles}, counter, {@code {handle}}, and {@code
 *       kmip.currentkey.check.failures}, counter, {@code {failure}}, without attributes of their
 *       own.
 * </ul>
 *
 * <p>From the tracing listener ({@link #tracingListener()}):
 *
 * <ul>
 *   <li><b>A call span</b> {@code KMIP <operation>}, of kind {@code INTERNAL}, for each application
 *       call, from {@link KmsListener#callStarted} to {@link KmsListener#callFinished}. Its
 *       attributes:
 *       <ul>
 *         <li>{@code kmip.operation};
 *         <li>{@code kmip.call.id}, the {@code Call} number of the SDK's logs;
 *         <li>{@code kmip.object.id}, when the call names an object;
 *         <li>{@code kmip.attempt.count};
 *         <li>when the call threw: {@code error.type}, {@code kmip.result_reason}, the exception
 *             and an error status.
 *       </ul>
 *   <li><b>A {@code kmip.retry} event</b> on the call span for each retry.
 *   <li><b>An attempt span</b> {@code KMIP <step> attempt}, of kind {@code CLIENT}, a child of the
 *       call span, for each attempt. Its attributes:
 *       <ul>
 *         <li>{@code kmip.operation}, {@code kmip.step}, {@code kmip.attempt.number} and {@code
 *             kmip.call.id};
 *         <li>{@code kmip.object.id}, when the attempt names an object;
 *         <li>{@code server.address}, {@code server.port}, {@code network.protocol.name} ({@code
 *             kmip}) and {@code network.protocol.version};
 *         <li>when the attempt failed: {@code error.type} and an error status.
 *       </ul>
 * </ul>
 *
 * <p><b>Context.</b> A call span is a child of the context current on the thread that starts the
 * call. The spans are never made current, so a span of another instrumentation started inside a
 * call is a child of the application's span. Background work, such as a {@code LocalKeys} refresh
 * or a scheduled check, is a call on the thread that runs it.
 *
 * <p>From the observable instruments: {@link #connections}, {@link #localKeys} and {@link
 * #tlsIdentity} list theirs.
 *
 * <p><b>Your own attributes.</b> A telemetry's attributes ({@link Builder#attributes}) are put on
 * every measurement and span it makes.
 *
 * <ul>
 *   <li>Use them to tell apart two sources that the module's attributes do not: two {@code Kms} to
 *       the same endpoint, or two caches of one write key name. Observable instruments that would
 *       report a series another open one of the same meter reports are refused ({@link
 *       IllegalStateException}), because the reader would keep only one of the two values.
 *   <li>Use keys of your own, such as {@code application} or {@code client}. The {@code kmip.}
 *       namespace is refused, and so are the conventions' keys the module sets: {@code
 *       error.type}, {@code server.address}, {@code server.port}, {@code network.protocol.name}
 *       and {@code network.protocol.version}.
 * </ul>
 *
 * <p>Thread-safe. The listeners record on the calling thread. The module holds no lock while it
 * calls OpenTelemetry, and its callbacks take none. Nothing here closes or flushes your {@code
 * OpenTelemetry}.
 *
 * @since 0.10.0
 */
public final class KmipTelemetry {
  /** The instrumentation scope's name, of the meter and the tracer. */
  public static final String INSTRUMENTATION_SCOPE = "dev.keytend.kmip";

  /** The module's version, the scope's; null when the build did not record it. */
  static final String VERSION = version();

  private final Meter meter;
  private final Shared shared;
  private final Attributes common;
  private final MetricsListener metrics;
  private final TracingListener tracing;

  private KmipTelemetry(OpenTelemetry openTelemetry, Attributes attributes) {
    MeterBuilder meterBuilder = openTelemetry.meterBuilder(INSTRUMENTATION_SCOPE);
    TracerBuilder tracerBuilder = openTelemetry.tracerBuilder(INSTRUMENTATION_SCOPE);
    if (VERSION != null) {
      meterBuilder.setInstrumentationVersion(VERSION);
      tracerBuilder.setInstrumentationVersion(VERSION);
    }
    this.meter = meterBuilder.build();
    Tracer tracer = tracerBuilder.build();
    this.shared = Shared.of(meter);
    this.common = attributes;
    this.metrics = new MetricsListener(meter, shared, common);
    this.tracing = new TracingListener(tracer, common);
  }

  private static String version() {
    try (InputStream in = KmipTelemetry.class.getResourceAsStream("version.properties")) {
      if (in == null) return null;
      Properties p = new Properties();
      p.load(in);
      String v = p.getProperty("version");
      return v == null || v.isBlank() || v.startsWith("$") ? null : v;
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /**
   * A telemetry of {@code openTelemetry}, without attributes of the caller's.
   *
   * @param openTelemetry the application's, which stays the application's
   * @return the telemetry
   */
  public static KmipTelemetry create(OpenTelemetry openTelemetry) {
    return builder(openTelemetry).build();
  }

  /**
   * A builder of a telemetry of {@code openTelemetry}.
   *
   * @param openTelemetry the application's, which stays the application's
   * @return the builder
   */
  public static Builder builder(OpenTelemetry openTelemetry) {
    return new Builder(Objects.requireNonNull(openTelemetry, "openTelemetry"));
  }

  /**
   * The listener that records the SDK's events as metrics: pass it to {@link
   * KmsConfig.Builder#addListener}. The same listener each time, so a configuration given it twice,
   * or several configurations given it, count a call once; their events add up in its
   * instruments. Quick on the calling thread: an attribute set and a recording per event.
   *
   * @return the listener
   */
  public KmsListener metricsListener() {
    return metrics;
  }

  /**
   * The listener that records the SDK's calls and attempts as spans, as the class description
   * says. Pass it to {@link KmsConfig.Builder#addListener}, beside {@link #metricsListener()} or
   * alone. It is the same listener each time.
   *
   * <p>It is quick on the calling thread: it starts or ends a span per event, and keeps a map of
   * the calls in progress. The map holds at most 10,000 calls, also when calls start on many
   * threads at once. While it is full, a call that starts is not traced, nor are its attempts. The
   * calls being traced still end their spans.
   *
   * @return the listener
   */
  public KmsListener tracingListener() {
    return tracing;
  }

  /** The telemetry's meter; for tests. */
  Meter meter() {
    return meter;
  }

  /** The state this telemetry shares with every other of its meter; for tests. */
  Shared shared() {
    return shared;
  }

  /**
   * The connections of each endpoint of {@code kms} ({@link Kms#connectionStats()}), attributes
   * {@code server.address} and {@code server.port}:
   *
   * <ul>
   *   <li>{@code kmip.client.connection.count}, up-down counter, {@code {connection}}, attribute
   *       {@code kmip.connection.state} ({@code idle}, {@code used}): the connections open, by
   *       state, which add up to all open;
   *   <li>{@code kmip.client.connection.opened}, counter, {@code {connection}}: connections
   *       opened, each a TLS handshake;
   *   <li>{@code kmip.client.connection.waits}, counter, {@code {wait}}: exchanges that waited for
   *       a pooled connection;
   *   <li>{@code kmip.client.connection.wait.time}, counter, {@code s}: how long they waited, in
   *       all.
   * </ul>
   *
   * An endpoint whose transport reports no counts (not the SDK's TLS transport, {@link
   * Kms.ConnectionStats#measured()}) reports nothing. The endpoints are those of the configuration;
   * a view of {@code kms} reports the same ones, so it is refused while {@code kms}'s instruments
   * are open.
   *
   * @param kms the {@code Kms}, held by the instruments until they are closed
   * @return the instruments, registered: close them when {@code kms} is closed
   * @throws IllegalStateException when instruments of this meter report one of the series already
   */
  public KmipInstruments connections(Kms kms) {
    Objects.requireNonNull(kms, "kms");
    return connections(kms, Kms::connectionStats);
  }

  /**
   * {@link #connections(Kms)} of the lazily connected KMS of {@link LocalKeys} caches ({@link
   * LocalKeys#sharedKms}): the same instruments, zero until it connects. For a cache that owns its
   * KMS ({@link LocalKeys#builder(KmsConfig, String)}), build it from a {@code SharedKms} instead to
   * measure its connections.
   *
   * @param kms the shared KMS, held by the instruments until they are closed
   * @return the instruments, registered: close them when {@code kms} is closed
   * @throws IllegalStateException when instruments of this meter report one of the series already
   * @since 0.10.0
   */
  public KmipInstruments connections(LocalKeys.SharedKms kms) {
    Objects.requireNonNull(kms, "kms");
    return connections(kms, LocalKeys.SharedKms::connectionStats);
  }

  private <T> KmipInstruments connections(
      T kms, Function<T, List<Kms.ConnectionStats>> connectionStats) {
    List<Attributes> endpoints = new ArrayList<>();
    for (Kms.ConnectionStats s : connectionStats.apply(kms))
      endpoints.add(endpoint(common.toBuilder(), s.endpoint()).build());
    List<Attributes> idle = new ArrayList<>(), used = new ArrayList<>();
    List<Shared.Series> series = new ArrayList<>();
    for (Attributes e : endpoints) {
      idle.add(e.toBuilder().put(CONNECTION_STATE, "idle").build());
      used.add(e.toBuilder().put(CONNECTION_STATE, "used").build());
      series.add(new Shared.Series("kmip.client.connection.count", idle.get(idle.size() - 1)));
      series.add(new Shared.Series("kmip.client.connection.count", used.get(used.size() - 1)));
      for (String name :
          List.of(
              "kmip.client.connection.opened",
              "kmip.client.connection.waits",
              "kmip.client.connection.wait.time")) series.add(new Shared.Series(name, e));
    }
    return KmipInstruments.open(
        shared,
        series,
        kms,
        reader -> {
          ObservableLongMeasurement count =
              meter
                  .upDownCounterBuilder("kmip.client.connection.count")
                  .setUnit("{connection}")
                  .setDescription("Connections open to the endpoint, by state")
                  .buildObserver();
          ObservableLongMeasurement opened =
              meter
                  .counterBuilder("kmip.client.connection.opened")
                  .setUnit("{connection}")
                  .setDescription("Connections opened to the endpoint, each a TLS handshake")
                  .buildObserver();
          ObservableLongMeasurement waits =
              meter
                  .counterBuilder("kmip.client.connection.waits")
                  .setUnit("{wait}")
                  .setDescription("Exchanges that waited for a pooled connection")
                  .buildObserver();
          ObservableDoubleMeasurement waitTime =
              meter
                  .counterBuilder("kmip.client.connection.wait.time")
                  .ofDoubles()
                  .setUnit("s")
                  .setDescription("How long exchanges waited for a pooled connection, in all")
                  .buildObserver();
          return meter.batchCallback(
              () ->
                  reader.accept(
                      k -> {
                        List<Kms.ConnectionStats> stats = connectionStats.apply(k);
                        for (int i = 0; i < endpoints.size() && i < stats.size(); i++) {
                          Kms.ConnectionStats s = stats.get(i);
                          if (!s.measured()) continue;
                          count.record(s.idle(), idle.get(i));
                          count.record(s.inUse(), used.get(i));
                          opened.record(s.opened(), endpoints.get(i));
                          waits.record(s.poolWaits(), endpoints.get(i));
                          waitTime.record(seconds(s.poolWaitTime()), endpoints.get(i));
                        }
                      }),
              count,
              opened,
              waits,
              waitTime);
        });
  }

  /**
   * The counters and state of a {@link LocalKeys} cache ({@link LocalKeys#stats()}, {@link
   * LocalKeys#usableFor()}, {@link LocalKeys#writeFailure()}), attribute {@code
   * kmip.localkeys.name} (its {@link LocalKeys#name()}, as the listener's {@code kmip.localkeys.*}
   * instruments name it):
   *
   * <ul>
   *   <li>{@code kmip.localkeys.requests}, counter, {@code {request}}, attributes {@code
   *       kmip.localkeys.purpose} ({@code encrypt}, {@code decrypt}) and {@code
   *       kmip.localkeys.result} ({@code hit}, {@code miss});
   *   <li>{@code kmip.localkeys.load.failures}, counter, {@code {failure}}: loads that failed,
   *       first loads included;
   *   <li>{@code kmip.localkeys.evictions}, counter, {@code {eviction}}, and {@code
   *       kmip.localkeys.capacity.waits}, counter, {@code {wait}};
   *   <li>{@code kmip.localkeys.entry.count}, up-down counter, {@code {entry}}: the entries held;
   *   <li>{@code kmip.localkeys.usable}, gauge, {@code s}: how long the write key stays usable
   *       without a successful refresh (zero when none is);
   *   <li>{@code kmip.localkeys.write.failing}, gauge, {@code 1}: 1 while the write key's last
   *       validation failed, else 0.
   * </ul>
   *
   * @param cache the cache, held by the instruments until they are closed
   * @return the instruments, registered: close them when {@code cache} is closed
   * @throws IllegalStateException when instruments of this meter report one of the series already
   *     (another cache of the same name, without attributes of its own)
   */
  public KmipInstruments localKeys(LocalKeys cache) {
    Objects.requireNonNull(cache, "cache");
    Attributes base = common.toBuilder().put(CACHE, cache.name()).build();
    Attributes encryptHit = request(base, "encrypt", "hit");
    Attributes encryptMiss = request(base, "encrypt", "miss");
    Attributes decryptHit = request(base, "decrypt", "hit");
    Attributes decryptMiss = request(base, "decrypt", "miss");
    List<Shared.Series> series = new ArrayList<>();
    for (Attributes a : List.of(encryptHit, encryptMiss, decryptHit, decryptMiss))
      series.add(new Shared.Series("kmip.localkeys.requests", a));
    for (String name :
        List.of(
            "kmip.localkeys.load.failures",
            "kmip.localkeys.evictions",
            "kmip.localkeys.capacity.waits",
            "kmip.localkeys.entry.count",
            "kmip.localkeys.usable",
            "kmip.localkeys.write.failing")) series.add(new Shared.Series(name, base));
    return KmipInstruments.open(
        shared,
        series,
        cache,
        reader -> {
          ObservableLongMeasurement requests =
              counter(
                  "kmip.localkeys.requests",
                  "{request}",
                  "Keys handed out, from the cache (hit) or after a load (miss)");
          ObservableLongMeasurement loadFailures =
              counter(
                  "kmip.localkeys.load.failures",
                  "{failure}",
                  "Loads that failed, first loads included");
          ObservableLongMeasurement evictions =
              counter(
                  "kmip.localkeys.evictions",
                  "{eviction}",
                  "Entries removed for the capacity bound or expired unused");
          ObservableLongMeasurement capacityWaits =
              counter("kmip.localkeys.capacity.waits", "{wait}", "Calls that waited for capacity");
          ObservableLongMeasurement entries =
              meter
                  .upDownCounterBuilder("kmip.localkeys.entry.count")
                  .setUnit("{entry}")
                  .setDescription("Entries held, the write key's included")
                  .buildObserver();
          ObservableDoubleMeasurement usable =
              meter
                  .gaugeBuilder("kmip.localkeys.usable")
                  .setUnit("s")
                  .setDescription(
                      "How long the write key stays usable without a successful refresh")
                  .buildObserver();
          ObservableLongMeasurement failing =
              meter
                  .gaugeBuilder("kmip.localkeys.write.failing")
                  .ofLongs()
                  .setUnit("1")
                  .setDescription("1 while the write key's last validation failed")
                  .buildObserver();
          return meter.batchCallback(
              () ->
                  reader.accept(
                      c -> {
                        LocalKeys.Stats s = c.stats();
                        requests.record(s.encryptHits(), encryptHit);
                        requests.record(s.encryptMisses(), encryptMiss);
                        requests.record(s.decryptHits(), decryptHit);
                        requests.record(s.decryptMisses(), decryptMiss);
                        loadFailures.record(s.loadFailures(), base);
                        evictions.record(s.evictions(), base);
                        capacityWaits.record(s.capacityWaits(), base);
                        entries.record(s.size(), base);
                        usable.record(seconds(c.usableFor().orElse(Duration.ZERO)), base);
                        failing.record(c.writeFailure().isPresent() ? 1 : 0, base);
                      }),
              requests,
              loadFailures,
              evictions,
              capacityWaits,
              entries,
              usable,
              failing);
        });
  }

  private static Attributes request(Attributes base, String purpose, String result) {
    return base.toBuilder().put(PURPOSE, purpose).put(CACHE_RESULT, result).build();
  }

  private ObservableLongMeasurement counter(String name, String unit, String description) {
    return meter.counterBuilder(name).setUnit(unit).setDescription(description).buildObserver();
  }

  /**
   * The expiry of the certificate a TLS identity follower presents, attribute {@code
   * kmip.tls.identity} (its {@link TlsIdentityFollower#name()}): {@code
   * kmip.tls.certificate.expiry}, gauge, {@code s}, the time left until the presented leaf's
   * {@code notAfter} by the system clock (negative once it passed); nothing while nothing is
   * presented. Alert well before it reaches zero, as renewal and propagation take time.
   *
   * @param follower the follower, held by the instruments until they are closed
   * @return the instruments, registered: close them when {@code follower} is closed
   * @throws IllegalStateException when instruments of this meter report the series already
   *     (another follower of the same name, without attributes of its own)
   */
  public KmipInstruments tlsIdentity(TlsIdentityFollower follower) {
    Objects.requireNonNull(follower, "follower");
    Attributes a = common.toBuilder().put(IDENTITY, follower.name()).build();
    return KmipInstruments.open(
        shared,
        List.of(new Shared.Series("kmip.tls.certificate.expiry", a)),
        follower,
        reader -> {
          ObservableDoubleMeasurement expiry =
              meter
                  .gaugeBuilder("kmip.tls.certificate.expiry")
                  .setUnit("s")
                  .setDescription("Time left until the presented TLS leaf certificate expires")
                  .buildObserver();
          return meter.batchCallback(
              () ->
                  reader.accept(
                      f -> {
                        double left = untilExpiry(f, System.currentTimeMillis());
                        if (!Double.isNaN(left)) expiry.record(left, a);
                      }),
              expiry);
        });
  }

  /** Seconds from {@code nowMillis} to the presented leaf's notAfter; NaN when none. */
  static double untilExpiry(TlsIdentityFollower follower, long nowMillis) {
    TlsIdentity presented = follower.identity().orElse(null);
    if (presented == null) return Double.NaN;
    return (presented.certificate().getNotAfter().toInstant().toEpochMilli() - (double) nowMillis)
        / 1000;
  }

  /**
   * A builder of a {@link KmipTelemetry}.
   *
   * @since 0.10.0
   */
  public static final class Builder {
    private final OpenTelemetry openTelemetry;
    private Attributes attributes = Attributes.empty();

    private Builder(OpenTelemetry openTelemetry) {
      this.openTelemetry = openTelemetry;
    }

    /**
     * Attributes of the caller's, put on every measurement and span: to tell this telemetry's
     * series from another's of the same meter (two {@code Kms} to one endpoint, say). Replaces
     * those set before.
     *
     * @param attributes keys of your own (see the class description)
     * @return this builder
     * @throws IllegalArgumentException when a key is in the {@code kmip.} namespace or one of the
     *     conventions' keys the module sets
     */
    public Builder attributes(Attributes attributes) {
      this.attributes = own(Objects.requireNonNull(attributes, "attributes"));
      return this;
    }

    /**
     * The telemetry: its meter and tracer, of scope {@value KmipTelemetry#INSTRUMENTATION_SCOPE}.
     *
     * @return the telemetry
     */
    public KmipTelemetry build() {
      return new KmipTelemetry(openTelemetry, attributes);
    }
  }
}
