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

import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KmsEvent;
import dev.keytend.kmip.kms.KmsException;
import dev.keytend.kmip.kms.KmsListener;
import dev.keytend.kmip.kms.LocalUse;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.Timer;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Queue;
import java.util.WeakHashMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

/**
 * {@link KmipMeters#listener}: each event to its meters. Tags take few values only: operations,
 * the configured endpoints, versions, outcomes, failure categories and server reasons, states, and
 * the LocalKeys write key names of the configuration, and the caller's own tags on every meter;
 * never an identifier, a call id, a file name or a message.
 */
final class MeterListener implements KmsListener {
  /** At most this many calls are tracked for failovers at once; beyond that, all are forgotten. */
  static final int MAX_TRACKED_CALLS = 10_000;

  /**
   * The up/down value behind each endpoint gauge, by registry: the value the gauge the registry
   * holds (after its filters) reads, shared by every listener whose events reach that gauge, so
   * that it shows the last event any of them told. Two listeners whose tags a filter maps to one
   * gauge share its value; a gauge removed from the registry is forgotten, and registered again,
   * with a value of its own, by the next event.
   */
  private static final Map<MeterRegistry, Gauges> AVAILABLE =
      Collections.synchronizedMap(new WeakHashMap<>());

  /** A registered endpoint gauge and the value it reads. */
  record Available(Gauge gauge, AtomicInteger value) {}

  /**
   * One registry's endpoint gauges, by the listener's tags and by the registered gauge's id; its
   * monitor guards both maps' changes. The lock order is this monitor, then the registry's own lock
   * (taken by a registration), never the reverse: Micrometer calls {@link #removed} while it holds
   * its lock, so that callback takes no lock. It notes the removal of one of these gauges, and the
   * next event forgets it under this monitor ({@link #forgetRemoved}); the removal of another meter
   * costs the events nothing.
   */
  static final class Gauges {
    final Map<Tags, Available> byTags = new HashMap<>();

    /** Also read by {@link #removed}, without the monitor. */
    final Map<Meter.Id, Available> byId = new ConcurrentHashMap<>();

    /** The gauges of these maps the registry removed, not forgotten yet. */
    private final Queue<Meter> removedOwn = new ConcurrentLinkedQueue<>();

    /**
     * Whether a gauge is being registered and put in the maps, under the monitor: a gauge the
     * registry removes meanwhile may be that one, not in {@link #byId} yet.
     */
    private volatile boolean registering;

    /**
     * The registry's removal callback, for every meter it removes, run inside the registry's lock:
     * notes the removal of one of these gauges (or of any gauge during a registration), and takes
     * no lock.
     */
    void removed(Meter removed) {
      if (!(removed instanceof Gauge)) return;
      // registering is read first: once it is false again, byId holds the gauge registered.
      if (registering || isOwn(removed)) removedOwn.add(removed);
    }

    private boolean isOwn(Meter m) {
      Available a = byId.get(m.getId());
      return a != null && a.gauge() == m;
    }

    /**
     * Under this monitor: registers {@code tags}' gauge with {@code registration} and puts it in
     * the maps, with {@code created} for its value, or another listener's value when a filter made
     * its tags and these one. A removal of it before it is in the maps is noted too, so that the
     * next event registers it again.
     */
    Available register(Tags tags, Supplier<Gauge> registration, AtomicInteger created) {
      Available known;
      registering = true;
      try {
        Gauge gauge = registration.get();
        Available shared = byId.get(gauge.getId());
        known = shared != null && shared.gauge() == gauge ? shared : new Available(gauge, created);
        byId.put(gauge.getId(), known);
        byTags.put(tags, known);
      } finally {
        registering = false;
      }
      forgetRemoved();
      return known;
    }

    /**
     * Under this monitor: forgets the gauges the registry removed. A gauge removed after this
     * looked is forgotten by the next event, which registers it again.
     */
    void forgetRemoved() {
      for (Meter m; (m = removedOwn.poll()) != null; ) {
        Meter gone = m;
        byTags.values().removeIf(a -> a.gauge() == gone);
        byId.values().removeIf(a -> a.gauge() == gone);
      }
    }
  }

  /** {@code registry}'s endpoint gauges, once a listener of it was made; for tests. */
  static Gauges gauges(MeterRegistry registry) {
    return AVAILABLE.get(registry);
  }

  private final MeterRegistry registry;

  /** The caller's tags, on every meter. */
  private final Tags common;

  /** The endpoint of the last attempt of each call in progress, for failovers. */
  private final ConcurrentMap<Long, String> lastEndpoint = new ConcurrentHashMap<>();

  /** This registry's gauges of {@link #AVAILABLE}; also the lock of its endpoint gauges. */
  private final Gauges available;

  MeterListener(MeterRegistry registry, Iterable<Tag> tags) {
    this.registry = registry;
    this.common = Tags.of(tags);
    this.available =
        AVAILABLE.computeIfAbsent(
            registry,
            r -> {
              Gauges gauges = new Gauges();
              r.config().onMeterRemoved(gauges::removed);
              return gauges;
            });
  }

  // ---- calls and attempts ----

  @Override
  public void callFinished(KmsEvent call) {
    lastEndpoint.remove(call.callId());
    Timer.builder("kmip.client.calls")
        .description("Application calls, their retries, failovers and steps included")
        .tags(Tags.of("operation", call.operation(), "outcome", outcome(call)))
        .tags(failureTags(call.failure()))
        .tags(common)
        .register(registry)
        .record(call.latency());
  }

  @Override
  public void started(KmsEvent event) {
    if (event.kind() != KmsEvent.Kind.ATTEMPT) return;
    state(event.endpoint(), 1, false);
    if (lastEndpoint.size() >= MAX_TRACKED_CALLS) lastEndpoint.clear();
    String previous = lastEndpoint.put(event.callId(), event.endpoint());
    if (previous != null && !previous.equals(event.endpoint()))
      Counter.builder("kmip.client.failovers")
          .description("Attempts sent to a different endpoint from the call's previous attempt")
          .tags("operation", event.operation(), "from", previous, "to", event.endpoint())
          .tags(common)
          .register(registry)
          .increment();
  }

  @Override
  public void finished(KmsEvent event) {
    Timer.builder("kmip.client.attempts")
        .description("Attempts: one execution of a step on one endpoint")
        .tags(
            Tags.of(
                "operation",
                event.operation(),
                "endpoint",
                event.endpoint(),
                "version",
                String.valueOf(event.version()),
                "outcome",
                outcome(event)))
        .tags(common)
        .register(registry)
        .record(event.latency());
  }

  @Override
  public void retrying(KmsEvent failed, Duration delay) {
    Counter.builder("kmip.client.retries")
        .description("Failed attempts the SDK retries")
        .tags(Tags.of("operation", failed.operation()).and(failureTags(failed.failure())))
        .tags(common)
        .register(registry)
        .increment();
  }

  @Override
  public void endpointUnavailable(String endpoint, String why) {
    state(endpoint, 0, true);
  }

  @Override
  public void endpointAvailable(String endpoint) {
    state(endpoint, 1, true);
  }

  /**
   * Sets {@code endpoint}'s gauge to {@code value}; only a first value unless {@code always}. The
   * gauge is registered when first told of and after the registry removed it, and the value set is
   * the one the registered gauge reads, whatever the registry's filters made of its tags.
   */
  private void state(String endpoint, int value, boolean always) {
    Tags tags = common.and("endpoint", endpoint);
    synchronized (available) {
      available.forgetRemoved();
      Available known = available.byTags.get(tags);
      if (known == null) {
        AtomicInteger created = new AtomicInteger(value);
        known =
            available.register(
                tags,
                () ->
                    Gauge.builder("kmip.client.endpoint.available", created, AtomicInteger::get)
                        .description(
                            "1 while the endpoint answers, 0 once it was found unavailable")
                        .tags(tags)
                        .register(registry),
                created);
        if (known.value() == created) return;
      }
      if (always) known.value().set(value);
    }
  }

  // ---- keys ----

  @Override
  public void staleHandle(String keyId, List<String> replacements) {
    count("kmip.keys.stale.handles", "Handles found replaced by another instance's rotation");
  }

  @Override
  public void concurrentReplacement(String keyId, List<String> replacements) {
    Counter.builder("kmip.keys.concurrent.replacements")
        .description(
            "Keys found replaced at the same time: kind several (run reconcile), or another"
                + " caller's one replacement (use latest)")
        .tag("kind", replacements.size() > 1 ? "several" : "another_caller")
        .tags(common)
        .register(registry)
        .increment();
  }

  @Override
  public void currentKeyCheckFailed(String keyId, int failuresInARow, KmsException failure) {
    count("kmip.currentkey.check.failures", "CurrentKey checks for a newer key that failed");
  }

  @Override
  public void keyStateChanged(String id, KeyState from, KeyState to) {
    Counter.builder("kmip.keys.state.changes")
        .description("State changes a follower read of an object it uses")
        .tags("from", lower(from), "to", lower(to))
        .tags(common)
        .register(registry)
        .increment();
  }

  // ---- LocalKeys ----

  @Override
  public void localKeySelected(String name, String previousId, String newId) {
    Counter.builder("kmip.localkeys.selections")
        .description("Write key selections a LocalKeys cache committed")
        .tag("cache", name)
        .tags(common)
        .register(registry)
        .increment();
  }

  @Override
  public void localKeyLoaded(String name, String keyId, LocalUse purpose, Duration loadTime) {
    Timer.builder("kmip.localkeys.loads")
        .description("LocalKeys loads that succeeded, requests and validation included")
        .tags("cache", name, "purpose", lower(purpose))
        .tags(common)
        .register(registry)
        .record(loadTime);
  }

  @Override
  public void localKeyRefreshFailed(
      String name,
      String keyId,
      LocalUse purpose,
      KmsException failure,
      Duration remainingValidity) {
    Counter.builder("kmip.localkeys.refresh.failures")
        .description("LocalKeys refreshes of a cached entry that failed")
        .tags("cache", name, "purpose", lower(purpose))
        .tags(common)
        .register(registry)
        .increment();
  }

  // ---- leases ----

  @Override
  public void leaseGranted(String keyId, Duration lease, boolean renewal) {
    lease(renewal ? "renewed" : "granted");
  }

  @Override
  public void leaseNotGranted(String keyId, Duration bound) {
    lease("not_granted");
  }

  private void lease(String result) {
    Counter.builder("kmip.leases")
        .description("Leases granted, renewed, or not granted (a server without Obtain Lease)")
        .tag("result", result)
        .tags(common)
        .register(registry)
        .increment();
  }

  // ---- TLS files ----

  @Override
  public void credentialsReloaded(String files) {
    reload("success");
  }

  @Override
  public void credentialsReloadFailed(String files, String why) {
    reload("failure");
  }

  @Override
  public void credentialsStillChanging(String files, Duration changingFor) {
    reload("still_changing");
  }

  // ---- client certificate renewal ----

  @Override
  public void clientCertificateRenewed(
      String previousFingerprint, String fingerprint, java.time.Instant notAfter) {
    renewal("success");
  }

  @Override
  public void clientCertificateRenewalFailed(String fingerprint, String why) {
    renewal("failure");
  }

  @Override
  public void clientCertificateMayBeLockedOut(String fingerprint, String why) {
    renewal("locked_out");
  }

  @Override
  public void clientCertificateRenewalWarning(String fingerprint, String why) {
    Counter.builder("kmip.tls.renewal.warnings")
        .description("Reports about client certificate renewal that need attention")
        .tags(common)
        .register(registry)
        .increment();
  }

  private void renewal(String outcome) {
    Counter.builder("kmip.tls.renewals")
        .description("Renewals of the client certificate (Re-Provision)")
        .tag("outcome", outcome)
        .tags(common)
        .register(registry)
        .increment();
  }

  private void reload(String outcome) {
    Counter.builder("kmip.tls.reloads")
        .description("Reloads of the TLS files of reloadOnChange()")
        .tag("outcome", outcome)
        .tags(common)
        .register(registry)
        .increment();
  }

  // ---- helpers ----

  private void count(String name, String description) {
    Counter.builder(name).description(description).tags(common).register(registry).increment();
  }

  private static String outcome(KmsEvent event) {
    return event.outcome() == KmsEvent.Outcome.FAILED ? "failure" : "success";
  }

  /** {@code category} and {@code reason} of a failure: the SDK's category, the server's reason. */
  private static Tags failureTags(Optional<KmsException> failure) {
    KmsException f = failure.orElse(null);
    return Tags.of(
        "category",
        f == null ? "none" : lower(f.category()),
        "reason",
        f == null ? "none" : f.serverReason().map(MeterListener::lower).orElse("none"));
  }

  static String lower(Enum<?> value) {
    return value.name().toLowerCase(Locale.ROOT);
  }
}
