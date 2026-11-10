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

import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KmsEvent;
import dev.keytend.kmip.kms.KmsException;
import dev.keytend.kmip.kms.KmsListener;
import dev.keytend.kmip.kms.LocalUse;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import io.opentelemetry.api.metrics.DoubleHistogram;
import io.opentelemetry.api.metrics.LongCounter;
import io.opentelemetry.api.metrics.Meter;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * {@link KmipTelemetry#metricsListener()}: each event to its instrument. Attributes take few values
 * only: operations, the configured endpoints, versions, the failure categories and server reasons,
 * states, the names of caches, and the telemetry's own attributes on every measurement; never an
 * identifier, a call id, a file name or a message. Takes no lock: the instruments are the API's,
 * the endpoint gauge's values a concurrent map.
 */
final class MetricsListener implements KmsListener {
  /** At most this many calls are tracked for failovers at once; beyond that, all are forgotten. */
  static final int MAX_TRACKED_CALLS = 10_000;

  private final Attributes common;
  private final Shared shared;

  /** The endpoint of the last attempt of each call in progress, for failovers. */
  private final ConcurrentMap<Long, String> lastEndpoint = new ConcurrentHashMap<>();

  private final DoubleHistogram calls, attempts, loads;
  private final LongCounter retries, failovers, refreshFailures, selections, leases, reloads;
  private final LongCounter renewals, renewalWarnings;
  private final LongCounter stateChanges, staleHandles, concurrentReplacements, checkFailures;

  MetricsListener(Meter meter, Shared shared, Attributes common) {
    this.common = common;
    this.shared = shared;
    calls =
        duration(
            meter,
            "kmip.client.call.duration",
            "Application calls, their retries, failovers and steps included");
    attempts =
        duration(
            meter,
            "kmip.client.attempt.duration",
            "Attempts: one execution of a step on one endpoint");
    loads =
        duration(
            meter,
            "kmip.localkeys.load.duration",
            "LocalKeys loads that succeeded, requests and validation included");
    retries = counter(meter, "kmip.client.retries", "{retry}", "Failed attempts the SDK retries");
    failovers =
        counter(
            meter,
            "kmip.client.failovers",
            "{failover}",
            "Attempts sent to a different endpoint from the call's previous attempt");
    refreshFailures =
        counter(
            meter,
            "kmip.localkeys.refresh.failures",
            "{failure}",
            "LocalKeys refreshes of a cached entry that failed");
    selections =
        counter(
            meter,
            "kmip.localkeys.selections",
            "{selection}",
            "Write key selections a LocalKeys cache committed");
    leases =
        counter(
            meter,
            "kmip.leases",
            "{lease}",
            "Leases granted, renewed, or not granted (a server without Obtain Lease)");
    reloads =
        counter(
            meter, "kmip.tls.reloads", "{reload}", "Reloads of the TLS files of reloadOnChange()");
    renewals =
        counter(
            meter,
            "kmip.tls.renewals",
            "{renewal}",
            "Renewals of the client certificate (Re-Provision)");
    renewalWarnings =
        counter(
            meter,
            "kmip.tls.renewal.warnings",
            "{warning}",
            "Reports about client certificate renewal that need attention");
    stateChanges =
        counter(
            meter,
            "kmip.key.state.changes",
            "{change}",
            "State changes a follower read of an object it uses");
    staleHandles =
        counter(
            meter,
            "kmip.key.stale_handles",
            "{handle}",
            "Handles found replaced by another instance's rotation");
    concurrentReplacements =
        counter(
            meter,
            "kmip.key.concurrent_replacements",
            "{replacement}",
            "Keys found replaced at the same time: kind several (run reconcile), or another"
                + " caller's one replacement (use latest)");
    checkFailures =
        counter(
            meter,
            "kmip.currentkey.check.failures",
            "{failure}",
            "CurrentKey checks for a newer key that failed");
    shared.registerGauge(meter);
  }

  private static DoubleHistogram duration(Meter meter, String name, String description) {
    return meter
        .histogramBuilder(name)
        .setUnit("s")
        .setDescription(description)
        .setExplicitBucketBoundariesAdvice(DURATION_BUCKETS)
        .build();
  }

  private static LongCounter counter(Meter meter, String name, String unit, String description) {
    return meter.counterBuilder(name).setUnit(unit).setDescription(description).build();
  }

  /** The calls tracked for failovers; for tests. */
  int trackedForFailovers() {
    return lastEndpoint.size();
  }

  private AttributesBuilder attributes() {
    return common.toBuilder();
  }

  // ---- calls and attempts ----

  @Override
  public void callFinished(KmsEvent call) {
    lastEndpoint.remove(call.callId());
    AttributesBuilder a = attributes().put(OPERATION, call.operation());
    if (call.outcome() == KmsEvent.Outcome.FAILED) failure(a, call.failure());
    calls.record(seconds(call.latency()), a.build());
  }

  @Override
  public void started(KmsEvent event) {
    if (event.kind() != KmsEvent.Kind.ATTEMPT) return;
    shared.firstUse(endpoint(attributes(), event.endpoint()).build());
    if (lastEndpoint.size() >= MAX_TRACKED_CALLS) lastEndpoint.clear();
    String previous = lastEndpoint.put(event.callId(), event.endpoint());
    if (previous != null && !previous.equals(event.endpoint()))
      failovers.add(
          1,
          attributes()
              .put(OPERATION, event.operation())
              .put(FAILOVER_FROM, previous)
              .put(FAILOVER_TO, event.endpoint())
              .build());
  }

  @Override
  public void finished(KmsEvent event) {
    AttributesBuilder a =
        endpoint(attributes().put(OPERATION, event.operation()), event.endpoint())
            .put(PROTOCOL_VERSION, String.valueOf(event.version()));
    if (event.outcome() == KmsEvent.Outcome.FAILED) failure(a, event.failure());
    attempts.record(seconds(event.latency()), a.build());
  }

  @Override
  public void retrying(KmsEvent failed, Duration delay) {
    retries.add(
        1, failure(attributes().put(OPERATION, failed.operation()), failed.failure()).build());
  }

  @Override
  public void endpointUnavailable(String endpoint, String why) {
    shared.set(endpoint(attributes(), endpoint).build(), 0);
  }

  @Override
  public void endpointAvailable(String endpoint) {
    shared.set(endpoint(attributes(), endpoint).build(), 1);
  }

  // ---- keys ----

  @Override
  public void staleHandle(String keyId, List<String> replacements) {
    staleHandles.add(1, common);
  }

  @Override
  public void concurrentReplacement(String keyId, List<String> replacements) {
    concurrentReplacements.add(
        1,
        attributes()
            .put(REPLACEMENT_KIND, replacements.size() > 1 ? "several" : "another_caller")
            .build());
  }

  @Override
  public void currentKeyCheckFailed(String keyId, int failuresInARow, KmsException failure) {
    checkFailures.add(1, common);
  }

  @Override
  public void keyStateChanged(String id, KeyState from, KeyState to) {
    stateChanges.add(1, attributes().put(STATE_FROM, lower(from)).put(STATE_TO, lower(to)).build());
  }

  // ---- LocalKeys ----

  @Override
  public void localKeySelected(String name, String previousId, String newId) {
    selections.add(1, attributes().put(CACHE, name).build());
  }

  @Override
  public void localKeyLoaded(String name, String keyId, LocalUse purpose, Duration loadTime) {
    loads.record(
        seconds(loadTime), attributes().put(CACHE, name).put(PURPOSE, purpose(purpose)).build());
  }

  @Override
  public void localKeyRefreshFailed(
      String name,
      String keyId,
      LocalUse purpose,
      KmsException failure,
      Duration remainingValidity) {
    refreshFailures.add(1, attributes().put(CACHE, name).put(PURPOSE, purpose(purpose)).build());
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
    leases.add(1, attributes().put(LEASE_RESULT, result).build());
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
    renewalWarnings.add(1, attributes().build());
  }

  private void renewal(String result) {
    renewals.add(1, attributes().put(RENEWAL_RESULT, result).build());
  }

  private void reload(String result) {
    reloads.add(1, attributes().put(RELOAD_RESULT, result).build());
  }

  static String purpose(LocalUse purpose) {
    return purpose == LocalUse.ENCRYPT ? "encrypt" : "decrypt";
  }
}
