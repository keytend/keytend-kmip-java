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
package dev.keytend.kmip.kms;

import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.function.LongSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The SDK's own logging: the first listener of every {@link KmsConfig}, whatever listeners the
 * application adds. Its loggers and levels are an operational contract (docs/production.md,
 * "Logging"):
 *
 * <ul>
 *   <li>{@code dev.keytend.kmip.kms.Calls}: calls, attempts and retries, at DEBUG;
 *   <li>{@code dev.keytend.kmip.kms.Endpoints}: an endpoint unavailable (WARN) and back (INFO);
 *   <li>{@code dev.keytend.kmip.kms.Tls}: TLS file reloads (INFO), failures (ERROR), files still
 *       changing (WARN); client certificate renewals (INFO), their failures and warnings (WARN)
 *       and a possible lockout (ERROR);
 *   <li>{@code dev.keytend.kmip.kms.LocalKeys}: write selections (INFO), loads (DEBUG), refresh
 *       failures (WARN);
 *   <li>{@code dev.keytend.kmip.kms.Leases}: grants (DEBUG), keys used without one (WARN);
 *   <li>{@code dev.keytend.kmip.kms.Keys}: state changes (INFO; WARN to a compromised or destroyed
 *       state), stale handles (INFO), keys with several replacements and failed CurrentKey checks
 *       (WARN), a key another caller replaced at the same time (INFO).
 * </ul>
 *
 * Each WARN (and the INFO lines of events that repeat: an endpoint back, a stale handle) is logged
 * at most once per minute per key (the endpoint, the key, the files), with the number of lines
 * suppressed since. A call's own failure is logged at DEBUG (the call and attempt lines); the
 * state of the endpoints and keys it met is logged whatever its outcome. Lines carry names, identifiers, endpoints,
 * states and the SDK's failure messages, never key material, passwords, plaintext or requests;
 * every argument passes through {@link LogText#safe}.
 */
final class LoggingListener implements KmsListener {
  static final String CALLS = "dev.keytend.kmip.kms.Calls",
      ENDPOINTS = "dev.keytend.kmip.kms.Endpoints",
      TLS = "dev.keytend.kmip.kms.Tls",
      LOCAL_KEYS = "dev.keytend.kmip.kms.LocalKeys",
      LEASES = "dev.keytend.kmip.kms.Leases",
      KEYS = "dev.keytend.kmip.kms.Keys";

  /** The window of the rate limit: one line per key per minute. */
  static final long WINDOW_NANOS = TimeUnit.MINUTES.toNanos(1);

  /** The listener every configuration installs, sharing one rate limit across the JVM. */
  static final LoggingListener INSTANCE = new LoggingListener(System::nanoTime);

  private static final Logger calls = LoggerFactory.getLogger(CALLS),
      endpoints = LoggerFactory.getLogger(ENDPOINTS),
      tls = LoggerFactory.getLogger(TLS),
      localKeys = LoggerFactory.getLogger(LOCAL_KEYS),
      leases = LoggerFactory.getLogger(LEASES),
      keys = LoggerFactory.getLogger(KEYS);

  private final LogLimiter limiter;

  /** A listener with a rate limit of its own on {@code clock}; tests make one. */
  LoggingListener(LongSupplier clock) {
    limiter = new LogLimiter(WINDOW_NANOS, clock);
  }

  // ---- calls and attempts: DEBUG ----

  @Override
  public void callStarted(KmsEvent call) {
    if (!calls.isDebugEnabled()) return;
    calls.debug(
        "Call {} {} started at {}",
        LogText.safe(call.callId()),
        LogText.safe(call.operation()),
        LogText.safe(call.endpoint()));
  }

  @Override
  public void callFinished(KmsEvent call) {
    if (!calls.isDebugEnabled()) return;
    calls.debug(
        "Call {} {} {} after {} attempts in {} ms, last at {}{}",
        LogText.safe(call.callId()),
        LogText.safe(call.operation()),
        LogText.safe(call.outcome() == KmsEvent.Outcome.FAILED ? "failed" : "succeeded"),
        LogText.safe(call.attempt()),
        LogText.safe(call.latency().toMillis()),
        LogText.safe(call.endpoint()),
        LogText.safe(call.failure().map(f -> ": " + describe(f)).orElse("")));
  }

  @Override
  public void started(KmsEvent event) {
    if (!calls.isDebugEnabled()) return;
    calls.debug(
        "Call {} {}: attempt {} at {} (KMIP {}){}",
        LogText.safe(event.callId()),
        LogText.safe(step(event)),
        LogText.safe(event.attempt()),
        LogText.safe(event.endpoint()),
        LogText.safe(event.version()),
        LogText.safe(event.objectId().map(id -> " for " + id).orElse("")));
  }

  @Override
  public void finished(KmsEvent event) {
    if (!calls.isDebugEnabled()) return;
    calls.debug(
        "Call {} {}: attempt {} at {} {} in {} ms{}",
        LogText.safe(event.callId()),
        LogText.safe(step(event)),
        LogText.safe(event.attempt()),
        LogText.safe(event.endpoint()),
        LogText.safe(event.outcome() == KmsEvent.Outcome.FAILED ? "failed" : "succeeded"),
        LogText.safe(event.latency().toMillis()),
        LogText.safe(event.failure().map(f -> ": " + describe(f)).orElse("")));
  }

  @Override
  public void retrying(KmsEvent failed, Duration delay) {
    if (!calls.isDebugEnabled()) return;
    calls.debug(
        "Call {} {}: retrying in {} ms after attempt {} at {} failed{}",
        LogText.safe(failed.callId()),
        LogText.safe(step(failed)),
        LogText.safe(delay.toMillis()),
        LogText.safe(failed.attempt()),
        LogText.safe(failed.endpoint()),
        LogText.safe(failed.failure().map(f -> ": " + describe(f)).orElse("")));
  }

  // ---- endpoints ----

  @Override
  public void endpointUnavailable(String endpoint, String why) {
    warn(
        endpoints,
        "endpointUnavailable " + endpoint,
        "KMS endpoint {} is unavailable (passed over while it cools down, unless no other endpoint"
            + " is available): {}",
        endpoint,
        why);
  }

  @Override
  public void endpointAvailable(String endpoint) {
    info(endpoints, "endpointAvailable " + endpoint, "KMS endpoint {} answers again", endpoint);
  }

  // ---- keys ----

  @Override
  public void staleHandle(String keyId, List<String> replacements) {
    info(
        keys,
        "staleHandle " + keyId,
        "Key {} was replaced by {}: data encrypted through its handle goes under an old key;"
            + " refresh the handle (latest())",
        keyId,
        replacements);
  }

  @Override
  public void concurrentReplacement(String keyId, List<String> replacements) {
    if (replacements.size() > 1)
      warn(
          keys,
          "concurrentReplacement " + keyId,
          "Key {} has several replacements {}: callers rotated or replaced it at the same time;"
              + " join them with reconcile()",
          keyId,
          replacements);
    else
      info(
          keys,
          "concurrentReplacement " + keyId,
          "Key {} was replaced by another caller at the same time, by {}: use that replacement"
              + " (latest())",
          keyId,
          replacements);
  }

  @Override
  public void currentKeyCheckFailed(String keyId, int failuresInARow, KmsException failure) {
    warn(
        keys,
        "currentKeyCheckFailed " + keyId,
        "A CurrentKey could not check for a key newer than {} ({} checks in a row failed); it goes"
            + " on using {}: {}",
        keyId,
        failuresInARow,
        keyId,
        describe(failure));
  }

  @Override
  public void keyStateChanged(String id, KeyState from, KeyState to) {
    String format = "{} changed state from {} to {}";
    if (to == KeyState.COMPROMISED
        || to == KeyState.DESTROYED
        || to == KeyState.DESTROYED_COMPROMISED)
      warn(keys, "keyStateChanged " + id + " " + to, format, id, from, to);
    else if (keys.isInfoEnabled())
      keys.info(format, LogText.safe(id), LogText.safe(from), LogText.safe(to));
  }

  // ---- LocalKeys ----

  @Override
  public void localKeySelected(String name, String previousId, String newId) {
    if (!localKeys.isInfoEnabled()) return;
    if (previousId == null)
      localKeys.info("LocalKeys {} selected write key {}", LogText.safe(name), LogText.safe(newId));
    else
      localKeys.info(
          "LocalKeys {} moved its write key from {} to {}",
          LogText.safe(name),
          LogText.safe(previousId),
          LogText.safe(newId));
  }

  @Override
  public void localKeyLoaded(String name, String keyId, LocalUse purpose, Duration loadTime) {
    if (!localKeys.isDebugEnabled()) return;
    localKeys.debug(
        "LocalKeys {} loaded {} for {} in {} ms",
        LogText.safe(name),
        LogText.safe(keyId),
        LogText.safe(purpose == LocalUse.ENCRYPT ? "encryption" : "decryption"),
        LogText.safe(loadTime.toMillis()));
  }

  @Override
  public void localKeyRefreshFailed(
      String name,
      String keyId,
      LocalUse purpose,
      KmsException failure,
      Duration remainingValidity) {
    warn(
        localKeys,
        "localKeyRefreshFailed " + name + " " + keyId + " " + purpose,
        "LocalKeys {} could not refresh {} for {}; what it holds stays usable for {} s more: {}",
        name,
        keyId == null ? "the write key" : keyId,
        purpose == LocalUse.ENCRYPT ? "encryption" : "decryption",
        remainingValidity.toSeconds(),
        describe(failure));
  }

  // ---- leases ----

  @Override
  public void leaseNotGranted(String keyId, Duration bound) {
    warn(
        leases,
        "leaseNotGranted " + keyId,
        "The server does not implement Obtain Lease: {} is used without a lease the server"
            + " granted, each copy for at most its stated Lease Time ({} s)",
        keyId,
        bound.toSeconds());
  }

  @Override
  public void leaseGranted(String keyId, Duration lease, boolean renewal) {
    if (!leases.isDebugEnabled()) return;
    leases.debug(
        "Lease of {} {} for {}",
        LogText.safe(keyId),
        LogText.safe(renewal ? "renewed" : "granted"),
        LogText.safe(lease.isZero() ? "no limit" : lease.toSeconds() + " s"));
  }

  // ---- TLS files ----

  @Override
  public void credentialsReloaded(String files) {
    if (tls.isInfoEnabled())
      tls.info(
          "Reloaded the TLS credentials from {}; new connections use them", LogText.safe(files));
  }

  @Override
  public void credentialsReloadFailed(String files, String why) {
    if (tls.isErrorEnabled())
      tls.error(
          "Could not reload the TLS credentials from {}; the previous ones stay in use: {}",
          LogText.safe(files),
          LogText.safe(why));
  }

  @Override
  public void credentialsStillChanging(String files, Duration changingFor) {
    warn(
        tls,
        "credentialsStillChanging " + files,
        "The TLS files {} have been changing for {} s and are not whole yet; the previous"
            + " credentials stay in use",
        files,
        changingFor.toSeconds());
  }

  // ---- client certificate renewal ----

  @Override
  public void clientCertificateRenewed(
      String previousFingerprint, String fingerprint, java.time.Instant notAfter) {
    if (tls.isInfoEnabled())
      tls.info(
          "Renewed the client certificate: {} replaces {} and is valid until {}; new connections"
              + " use it. Add it to the server's policy under the same name",
          LogText.safe(fingerprint),
          LogText.safe(previousFingerprint),
          LogText.safe(notAfter));
  }

  @Override
  public void clientCertificateRenewalFailed(String fingerprint, String why) {
    warn(
        tls,
        "clientCertificateRenewalFailed " + fingerprint,
        "Could not renew the client certificate {}: {}",
        fingerprint == null ? "(unreadable)" : fingerprint,
        why);
  }

  @Override
  public void clientCertificateRenewalWarning(String fingerprint, String why) {
    warn(
        tls,
        "clientCertificateRenewalWarning " + fingerprint,
        "Renewal of the client certificate {}: {}",
        fingerprint == null ? "(unreadable)" : fingerprint,
        why);
  }

  @Override
  public void clientCertificateMayBeLockedOut(String fingerprint, String why) {
    if (tls.isErrorEnabled())
      tls.error(
          "The client may be locked out of the KMS after a renewal of its certificate {}: {}",
          LogText.safe(fingerprint == null ? "(unreadable)" : fingerprint),
          LogText.safe(why));
  }

  // ---- helpers ----

  /** The operation, and the step when it differs. */
  private static String step(KmsEvent event) {
    return event.step().equals(event.operation())
        ? event.operation()
        : event.operation() + "/" + event.step();
  }

  /** A failure as a log line shows it: its type and message, never its response or causes. */
  static String describe(KmsException failure) {
    return failure.getClass().getSimpleName() + ": " + failure.getMessage();
  }

  /** {@code format} with {@code args} at WARN, at most once per minute for {@code key}. */
  private void warn(Logger log, String key, String format, Object... args) {
    if (!log.isWarnEnabled()) return;
    long suppressed = limiter.permit(key);
    if (suppressed == LogLimiter.SUPPRESSED) return;
    log.warn(withSuppressed(format, suppressed), safe(args, suppressed));
  }

  /** {@code format} with {@code args} at INFO, at most once per minute for {@code key}. */
  private void info(Logger log, String key, String format, Object... args) {
    if (!log.isInfoEnabled()) return;
    long suppressed = limiter.permit(key);
    if (suppressed == LogLimiter.SUPPRESSED) return;
    log.info(withSuppressed(format, suppressed), safe(args, suppressed));
  }

  static String withSuppressed(String format, long suppressed) {
    return suppressed == 0 ? format : format + " ({} similar lines suppressed since the last one)";
  }

  /** Each argument through {@link LogText#safe}, and the count of lines suppressed, if any. */
  private static Object[] safe(Object[] args, long suppressed) {
    Object[] out = new Object[args.length + (suppressed == 0 ? 0 : 1)];
    for (int i = 0; i < args.length; i++) out[i] = LogText.safe(args[i]);
    if (suppressed != 0) out[args.length] = suppressed;
    return out;
  }
}
