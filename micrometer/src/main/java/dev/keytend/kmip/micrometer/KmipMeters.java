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
package dev.keytend.kmip.micrometer;

import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.kms.KmsListener;
import dev.keytend.kmip.kms.LocalKeys;
import dev.keytend.kmip.kms.TlsIdentity;
import dev.keytend.kmip.kms.TlsIdentityFollower;
import io.micrometer.core.instrument.FunctionCounter;
import io.micrometer.core.instrument.FunctionTimer;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.TimeGauge;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;
import java.util.function.ToDoubleFunction;

/**
 * Micrometer meters for keytend-kmip. {@link #listener} is a {@link KmsListener} that turns the
 * SDK's events into timers and counters. The binders ({@link #connections}, {@link #localKeys},
 * {@link #tlsIdentity}) register meters that are read when the registry publishes: connections, a
 * {@link LocalKeys} cache's counters, a TLS certificate's expiry.
 *
 * <p>In this example, {@code registry} is your application's {@code MeterRegistry}, and the PEM
 * files hold the client's certificate chain, its private key and the CA certificates:
 *
 * <pre>{@code
 * KmsConfig config = KmsConfig.builder()
 *     .endpoints("kms-1.example.com:5696", "kms-2.example.com:5696")
 *     .clientIdentityPem(Path.of("client.pem"), Path.of("client.key"))
 *     .trustPem(Path.of("ca.pem"))
 *     .addListener(KmipMeters.listener(registry))
 *     .build();
 * try (Kms kms = Kms.connect(config);
 *     KmipMeterBinder connections = KmipMeters.connections(kms)) {
 *   connections.bindTo(registry);
 *   // ...
 * }
 * }</pre>
 *
 * <p>Names are dot-separated. A Prometheus registry shows {@code kmip.client.calls} as {@code
 * kmip_client_calls_seconds}. Tags take few values: operations, the configured endpoints, KMIP
 * versions, outcomes, the SDK's failure categories and the servers' reasons, key states, and the
 * names the application gives its caches and identities. A key or object identifier, a call id, a
 * file name or a message is never a tag. Those go to the SDK's logs.
 *
 * <p>From the listener ({@link #listener}):
 *
 * <ul>
 *   <li>{@code kmip.client.calls}, timer, tags {@code operation}, {@code outcome} ({@code
 *       success} when the call returned, {@code failure} when it threw), {@code category}, {@code
 *       reason} ({@code none} when it returned): each application call, retries, failovers and
 *       steps included ({@link KmsListener#callFinished}).
 *   <li>{@code kmip.client.attempts}, timer, tags {@code operation}, {@code endpoint}, {@code
 *       version}, {@code outcome} ({@code success}, {@code failure}): each attempt ({@link
 *       KmsListener#finished}).
 *   <li>{@code kmip.client.retries}, counter, tags {@code operation}, {@code category}, {@code
 *       reason}: each retry ({@link KmsListener#retrying}).
 *   <li>{@code kmip.client.failovers}, counter, tags {@code operation}, {@code from}, {@code to}:
 *       each attempt sent to a different endpoint from the call's previous attempt.
 *   <li>{@code kmip.client.endpoint.available}, gauge, tag {@code endpoint}: 1 once the endpoint
 *       was used or answered again ({@link KmsListener#endpointAvailable}), 0 once it was found
 *       unavailable ({@link KmsListener#endpointUnavailable}). Listeners whose events reach one
 *       gauge share it: the same tags, or tags the registry's filters make the same. It then shows
 *       the last event any of them reported. For a gauge per {@code Kms}, give each its own
 *       listener with tags of its own ({@link #listener(MeterRegistry, Iterable)}). A gauge removed
 *       from the registry is registered again by the next event.
 *   <li>{@code kmip.localkeys.loads}, timer, tags {@code cache}, {@code purpose} ({@code encrypt},
 *       {@code decrypt}): each load that succeeded ({@link KmsListener#localKeyLoaded}).
 *   <li>{@code kmip.localkeys.refresh.failures}, counter, tags {@code cache}, {@code purpose}
 *       ({@link KmsListener#localKeyRefreshFailed}).
 *   <li>{@code kmip.localkeys.selections}, counter, tag {@code cache} ({@link
 *       KmsListener#localKeySelected}).
 *   <li>{@code kmip.leases}, counter, tag {@code result} ({@code granted}, {@code renewed}, {@code
 *       not_granted}).
 *   <li>{@code kmip.tls.reloads}, counter, tag {@code outcome} ({@code success}, {@code failure},
 *       {@code still_changing}): the TLS files of {@code reloadOnChange()}.
 *   <li>{@code kmip.tls.renewals}, counter, tag {@code outcome} ({@code success}, {@code failure},
 *       {@code locked_out}): renewals of the client certificate ({@link
 *       KmsListener#clientCertificateRenewed}, {@link KmsListener#clientCertificateRenewalFailed},
 *       {@link KmsListener#clientCertificateMayBeLockedOut}), one outcome per attempt. Alert on
 *       {@code locked_out}.
 *   <li>{@code kmip.tls.renewal.warnings}, counter: reports about renewal that need attention but
 *       are not an attempt's outcome ({@link KmsListener#clientCertificateRenewalWarning}).
 *   <li>{@code kmip.keys.state.changes}, counter, tags {@code from}, {@code to} (a {@code
 *       KeyState}, lower case).
 *   <li>{@code kmip.keys.concurrent.replacements}, counter, tag {@code kind}: {@code several}
 *       when a key has several newest keys (run {@code reconcile}), {@code another_caller} when
 *       another caller's one replacement was found (use {@code latest()}) ({@link
 *       KmsListener#concurrentReplacement}).
 *   <li>{@code kmip.keys.stale.handles} and {@code kmip.currentkey.check.failures}, counters
 *       without tags.
 * </ul>
 *
 * <p>From the binders: {@link #connections}, {@link #localKeys} and {@link #tlsIdentity} list
 * theirs.
 *
 * <p><b>Your own tags.</b> Each method takes optional tags, put on every meter it makes.
 *
 * <ul>
 *   <li>Use them to tell apart two sources that the module's tags do not: two {@code Kms} to the
 *       same endpoint, or two caches of one write key name. A binder refuses to bind a meter that
 *       another source registered with the same name and tags ({@link KmipMeterBinder#bindTo}).
 *   <li>Use keys of your own, such as {@code application} or {@code client}. The module's keys
 *       are refused: {@code operation}, {@code outcome}, {@code category}, {@code reason}, {@code
 *       endpoint}, {@code version}, {@code from}, {@code to}, {@code state}, {@code cache}, {@code
 *       purpose}, {@code result}, {@code identity} and {@code kind}.
 *   <li>Give every source of a meter name the same tag keys. Prometheus registries refuse a meter
 *       whose tag keys differ from another of its name.
 * </ul>
 *
 * <p>Timers publish no histogram or percentiles unless a {@code MeterFilter} of the registry turns
 * them on. {@code kmip.client.calls} and {@code kmip.client.retries} carry the server's {@code
 * reason}. It is bounded, at about 70 KMIP reasons, but it multiplies the series by operation.
 *
 * <p>The listener registers its meters as their events first happen. They stay in the registry,
 * because a configuration's listeners are fixed. Remove them by name if you need to. A binder's {@link
 * KmipMeterBinder#close()} removes its meters. Nothing here closes a registry.
 *
 * @since 0.10.0
 */
public final class KmipMeters {
  private KmipMeters() {}

  /**
   * A listener that records the SDK's events in {@code registry}: pass it to {@link
   * KmsConfig.Builder#addListener}. One listener may serve several configurations, whose events
   * then add up in its meters (and share its endpoint gauge); a call through two of them is counted
   * once. Quick on the calling thread: a meter lookup and an update per event.
   *
   * @param registry the registry, which stays the caller's
   * @return the listener
   */
  public static KmsListener listener(MeterRegistry registry) {
    return listener(registry, Tags.empty());
  }

  /**
   * {@link #listener(MeterRegistry)} with {@code tags} on every meter, to tell this listener's
   * meters from another's in the same registry.
   *
   * @param registry the registry, which stays the caller's
   * @param tags the caller's tags; keys of its own (see the class description)
   * @return the listener
   * @throws IllegalArgumentException when a tag uses one of the module's keys
   * @since 0.10.0
   */
  public static KmsListener listener(MeterRegistry registry, Iterable<Tag> tags) {
    return new MeterListener(Objects.requireNonNull(registry, "registry"), own(tags));
  }

  /** The module's tag keys, which the caller's tags may not use. */
  static final Set<String> RESERVED =
      Set.of(
          "operation",
          "outcome",
          "category",
          "reason",
          "endpoint",
          "version",
          "from",
          "to",
          "state",
          "cache",
          "purpose",
          "result",
          "identity",
          "kind");

  /** {@code tags}, checked: none of the module's keys. */
  static Tags own(Iterable<Tag> tags) {
    Tags out = Tags.of(Objects.requireNonNull(tags, "tags"));
    for (Tag t : out)
      if (RESERVED.contains(t.getKey()))
        throw new IllegalArgumentException(
            "The tag " + t.getKey() + " is the module's own; give yours another key");
    return out;
  }

  /**
   * The connections of each endpoint of {@code kms} ({@link Kms#connectionStats()}), tag {@code
   * endpoint}:
   *
   * <ul>
   *   <li>{@code kmip.client.connections}, gauge, tag {@code state} ({@code open}, {@code idle},
   *       {@code in_use});
   *   <li>{@code kmip.client.connections.opened}, function counter: connections opened, each a TLS
   *       handshake;
   *   <li>{@code kmip.client.pool.wait}, function timer: exchanges that waited for a pooled
   *       connection, and how long in all.
   * </ul>
   *
   * An endpoint whose transport reports no counts (not the SDK's TLS transport, {@link
   * Kms.ConnectionStats#measured()}) reads NaN in the gauges and zero in the others. The endpoints
   * are those of the configuration; a view of {@code kms} reports the same ones.
   *
   * @param kms the {@code Kms}, held by the binder until it is closed
   * @return a binder: {@link KmipMeterBinder#bindTo} registers the meters
   */
  public static KmipMeterBinder connections(Kms kms) {
    return connections(kms, Tags.empty());
  }

  /**
   * {@link #connections(Kms)} with {@code tags} on every meter: needed for two {@code Kms} with an
   * endpoint in common (two credentials or configurations), whose meters would otherwise have the
   * same name and tags.
   *
   * @param kms the {@code Kms}, held by the binder until it is closed
   * @param tags the caller's tags; keys of its own (see the class description)
   * @return a binder: {@link KmipMeterBinder#bindTo} registers the meters
   * @throws IllegalArgumentException when a tag uses one of the module's keys
   * @since 0.10.0
   */
  public static KmipMeterBinder connections(Kms kms, Iterable<Tag> tags) {
    Objects.requireNonNull(kms, "kms");
    return connections(kms, Kms::connectionStats, tags);
  }

  /**
   * {@link #connections(Kms)} of the lazily connected KMS of {@link LocalKeys} caches ({@link
   * LocalKeys#sharedKms}): the same meters, zero until it connects. For a cache that owns its KMS
   * ({@link LocalKeys#builder(KmsConfig, String)}), build it from a {@code
   * SharedKms} instead to measure its connections.
   *
   * @param kms the shared KMS, held by the binder until it is closed
   * @return a binder: {@link KmipMeterBinder#bindTo} registers the meters
   * @since 0.10.0
   */
  public static KmipMeterBinder connections(LocalKeys.SharedKms kms) {
    return connections(kms, Tags.empty());
  }

  /**
   * {@link #connections(LocalKeys.SharedKms)} with {@code tags} on every meter, as {@link
   * #connections(Kms, Iterable)}.
   *
   * @param kms the shared KMS, held by the binder until it is closed
   * @param tags the caller's tags; keys of its own (see the class description)
   * @return a binder: {@link KmipMeterBinder#bindTo} registers the meters
   * @throws IllegalArgumentException when a tag uses one of the module's keys
   * @since 0.10.0
   */
  public static KmipMeterBinder connections(LocalKeys.SharedKms kms, Iterable<Tag> tags) {
    Objects.requireNonNull(kms, "kms");
    return connections(kms, LocalKeys.SharedKms::connectionStats, tags);
  }

  private static <T> KmipMeterBinder connections(
      T kms, Function<T, List<Kms.ConnectionStats>> stats, Iterable<Tag> tags) {
    Tags common = own(tags);
    List<String> endpoints = stats.apply(kms).stream().map(Kms.ConnectionStats::endpoint).toList();
    return new KmipMeterBinder(
        (registry, meters) -> {
          for (int i = 0; i < endpoints.size(); i++) {
            int index = i;
            String endpoint = endpoints.get(i);
            for (String state : List.of("open", "idle", "in_use"))
              meters.add(
                  Gauge.builder(
                          "kmip.client.connections",
                          kms,
                          k -> {
                            Kms.ConnectionStats s = stats.apply(k).get(index);
                            if (!s.measured()) return Double.NaN;
                            return switch (state) {
                              case "open" -> s.open();
                              case "idle" -> s.idle();
                              default -> s.inUse();
                            };
                          })
                      .description("Connections to the endpoint, by state")
                      .tags("endpoint", endpoint, "state", state)
                      .tags(common)
                      .register(registry));
            meters.add(
                FunctionCounter.builder(
                        "kmip.client.connections.opened",
                        kms,
                        k -> stats.apply(k).get(index).opened())
                    .description("Connections opened to the endpoint, each a TLS handshake")
                    .tag("endpoint", endpoint)
                    .tags(common)
                    .register(registry));
            meters.add(
                FunctionTimer.builder(
                        "kmip.client.pool.wait",
                        kms,
                        k -> stats.apply(k).get(index).poolWaits(),
                        k -> stats.apply(k).get(index).poolWaitTime().toNanos(),
                        TimeUnit.NANOSECONDS)
                    .description("Exchanges that waited for a pooled connection, and how long")
                    .tag("endpoint", endpoint)
                    .tags(common)
                    .register(registry));
          }
        });
  }

  /**
   * The counters and state of a {@link LocalKeys} cache ({@link LocalKeys#stats()}, {@link
   * LocalKeys#usableFor()}, {@link LocalKeys#writeFailure()}), tag {@code cache} (its {@link
   * LocalKeys#name()}, as the listener's {@code kmip.localkeys.*} meters name it):
   *
   * <ul>
   *   <li>{@code kmip.localkeys.requests}, function counter, tags {@code purpose} ({@code
   *       encrypt}, {@code decrypt}) and {@code result} ({@code hit}, {@code miss});
   *   <li>{@code kmip.localkeys.load.failures}, function counter: loads that failed, first loads
   *       included;
   *   <li>{@code kmip.localkeys.evictions} and {@code kmip.localkeys.capacity.waits}, function
   *       counters;
   *   <li>{@code kmip.localkeys.size}, gauge: the entries held;
   *   <li>{@code kmip.localkeys.usable}, time gauge: how long the write key stays usable without a
   *       successful refresh (zero when none is);
   *   <li>{@code kmip.localkeys.write.failing}, gauge: 1 while the write key's last validation
   *       failed, else 0.
   * </ul>
   *
   * @param cache the cache, held by the binder until it is closed
   * @return a binder: {@link KmipMeterBinder#bindTo} registers the meters
   */
  public static KmipMeterBinder localKeys(LocalKeys cache) {
    return localKeys(cache, Tags.empty());
  }

  /**
   * {@link #localKeys(LocalKeys)} with {@code tags} on every meter: needed for two caches of one
   * write key name (another scope, another {@code Kms}), whose meters would otherwise have the same
   * name and tags.
   *
   * @param cache the cache, held by the binder until it is closed
   * @param tags the caller's tags; keys of its own (see the class description)
   * @return a binder: {@link KmipMeterBinder#bindTo} registers the meters
   * @throws IllegalArgumentException when a tag uses one of the module's keys
   * @since 0.10.0
   */
  public static KmipMeterBinder localKeys(LocalKeys cache, Iterable<Tag> tags) {
    Objects.requireNonNull(cache, "cache");
    Tags cacheTags = Tags.of("cache", cache.name()).and(own(tags));
    return new KmipMeterBinder(
        (registry, meters) -> {
          request(registry, meters, cache, cacheTags, "encrypt", "hit", s -> s.encryptHits());
          request(registry, meters, cache, cacheTags, "encrypt", "miss", s -> s.encryptMisses());
          request(registry, meters, cache, cacheTags, "decrypt", "hit", s -> s.decryptHits());
          request(registry, meters, cache, cacheTags, "decrypt", "miss", s -> s.decryptMisses());
          meters.add(
              FunctionCounter.builder(
                      "kmip.localkeys.load.failures", cache, c -> c.stats().loadFailures())
                  .description("Loads that failed, first loads included")
                  .tags(cacheTags)
                  .register(registry));
          meters.add(
              FunctionCounter.builder("kmip.localkeys.evictions", cache, c -> c.stats().evictions())
                  .description("Entries removed for the capacity bound or expired unused")
                  .tags(cacheTags)
                  .register(registry));
          meters.add(
              FunctionCounter.builder(
                      "kmip.localkeys.capacity.waits", cache, c -> c.stats().capacityWaits())
                  .description("Calls that waited for capacity")
                  .tags(cacheTags)
                  .register(registry));
          meters.add(
              Gauge.builder("kmip.localkeys.size", cache, c -> c.stats().size())
                  .description("Entries held, the write key's included")
                  .tags(cacheTags)
                  .register(registry));
          meters.add(
              TimeGauge.builder(
                      "kmip.localkeys.usable",
                      cache,
                      TimeUnit.NANOSECONDS,
                      c -> c.usableFor().orElse(Duration.ZERO).toNanos())
                  .description("How long the write key stays usable without a successful refresh")
                  .tags(cacheTags)
                  .register(registry));
          meters.add(
              Gauge.builder(
                      "kmip.localkeys.write.failing",
                      cache,
                      c -> c.writeFailure().isPresent() ? 1 : 0)
                  .description("1 while the write key's last validation failed")
                  .tags(cacheTags)
                  .register(registry));
        });
  }

  private static void request(
      MeterRegistry registry,
      List<Meter> meters,
      LocalKeys cache,
      Tags tags,
      String purpose,
      String result,
      ToDoubleFunction<LocalKeys.Stats> count) {
    meters.add(
        FunctionCounter.builder(
                "kmip.localkeys.requests", cache, c -> count.applyAsDouble(c.stats()))
            .description("Keys handed out, from the cache (hit) or after a load (miss)")
            .tags(tags)
            .tags("purpose", purpose, "result", result)
            .register(registry));
  }

  /**
   * The expiry of the certificate a TLS identity follower presents, tag {@code identity} (its
   * {@link TlsIdentityFollower#name()}): {@code kmip.tls.certificate.expiry}, time gauge, the
   * time left until the presented leaf's {@code notAfter} by the registry's clock (negative once it
   * passed); NaN while nothing is presented. Alert well before it reaches zero, as renewal and
   * propagation take time.
   *
   * @param follower the follower, held by the binder until it is closed
   * @return a binder: {@link KmipMeterBinder#bindTo} registers the meter
   */
  public static KmipMeterBinder tlsIdentity(TlsIdentityFollower follower) {
    return tlsIdentity(follower, Tags.empty());
  }

  /**
   * {@link #tlsIdentity(TlsIdentityFollower)} with {@code tags} on the meter: needed for two
   * followers of one identity name.
   *
   * @param follower the follower, held by the binder until it is closed
   * @param tags the caller's tags; keys of its own (see the class description)
   * @return a binder: {@link KmipMeterBinder#bindTo} registers the meter
   * @throws IllegalArgumentException when a tag uses one of the module's keys
   * @since 0.10.0
   */
  public static KmipMeterBinder tlsIdentity(TlsIdentityFollower follower, Iterable<Tag> tags) {
    Objects.requireNonNull(follower, "follower");
    Tags common = own(tags);
    String identity = follower.name();
    return new KmipMeterBinder(
        (registry, meters) ->
            meters.add(
                TimeGauge.builder(
                        "kmip.tls.certificate.expiry",
                        follower,
                        TimeUnit.MILLISECONDS,
                        f -> untilExpiry(f, registry.config().clock().wallTime()))
                    .description("Time left until the presented TLS leaf certificate expires")
                    .tag("identity", identity)
                    .tags(common)
                    .register(registry)));
  }

  /** Milliseconds from {@code nowMillis} to the presented leaf's notAfter; NaN when none. */
  static double untilExpiry(TlsIdentityFollower follower, long nowMillis) {
    TlsIdentity presented = follower.identity().orElse(null);
    if (presented == null) return Double.NaN;
    return presented.certificate().getNotAfter().toInstant().toEpochMilli() - (double) nowMillis;
  }
}
