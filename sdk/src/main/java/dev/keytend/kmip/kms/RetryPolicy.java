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
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Automatic retries of read-only operations after a {@link TransientException}: Get, Locate, Get
 * Attributes, Query, Discover Versions, Obtain Lease, Encrypt, Decrypt, Sign, Signature Verify,
 * MAC, MAC Verify and RNG Retrieve. Each retry goes to the next healthy endpoint after an
 * exponential back-off with jitter. Mutations (create, register, activate, revoke, destroy,
 * re-key, attribute changes) are never re-sent. Set one with {@link
 * KmsConfig.Builder#retryPolicy(RetryPolicy)}.
 *
 * <pre>{@code
 * RetryPolicy policy = RetryPolicy.defaults().toBuilder().maxAttempts(5).build();
 * }</pre>
 *
 * <p>Encrypt and Sign leave no server state behind except KMIP 1.x Usage Limits counters. For
 * servers that enforce such limits, {@link Builder#retryCrypto(boolean) retryCrypto(false)} limits
 * retries to Get, Locate, Get Attributes, Query, Discover Versions and Obtain Lease. An attempt
 * that gets no reply within the {@link #attemptTimeout() attempt timeout} moves on to the next
 * endpoint.
 *
 * <p>A {@code RetryPolicy} is immutable and thread-safe. See <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/production.md#deadlines-and-retries">Deadlines
 * and retries</a>.
 *
 * @since 0.10.0
 */
public final class RetryPolicy {
  private final int maxAttempts;
  private final Duration initialBackoff, maxBackoff, cooldown;

  /** Null: derived from the call timeout. */
  private final Duration attemptTimeout;

  private final double jitter;
  private final boolean retryCrypto;

  private RetryPolicy(Builder b) {
    this.maxAttempts = b.maxAttempts;
    this.initialBackoff = b.initialBackoff;
    this.maxBackoff = b.maxBackoff;
    this.cooldown = b.cooldown;
    this.jitter = b.jitter;
    this.retryCrypto = b.retryCrypto;
    this.attemptTimeout = b.attemptTimeout;
  }

  /**
   * 3 attempts, 100 ms back-off doubling up to 2 s with jitter 0.5, retries of cryptographic
   * operations, a 5 s endpoint cool-down, and an attempt timeout of the call timeout divided by the
   * attempts.
   *
   * @return the default policy
   */
  public static RetryPolicy defaults() {
    return builder().build();
  }

  /**
   * No automatic retries (the cool-down still applies to failover between calls).
   *
   * @return the policy
   */
  public static RetryPolicy none() {
    return builder().maxAttempts(1).initialBackoff(Duration.ZERO).maxBackoff(Duration.ZERO).build();
  }

  /**
   * A builder starting from {@link #defaults()}'s values.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * A builder starting from this policy's values.
   *
   * @return a new builder
   */
  public Builder toBuilder() {
    Builder b = new Builder();
    b.maxAttempts = maxAttempts;
    b.initialBackoff = initialBackoff;
    b.maxBackoff = maxBackoff;
    b.cooldown = cooldown;
    b.jitter = jitter;
    b.retryCrypto = retryCrypto;
    b.attemptTimeout = attemptTimeout;
    return b;
  }

  /**
   * Total attempts for a retryable operation (1 means no retries).
   *
   * @return the number of attempts, at least 1
   */
  public int maxAttempts() {
    return maxAttempts;
  }

  /**
   * The back-off before the first retry; it doubles for each further retry.
   *
   * @return the first back-off
   */
  public Duration initialBackoff() {
    return initialBackoff;
  }

  /**
   * The longest back-off.
   *
   * @return the longest back-off
   */
  public Duration maxBackoff() {
    return maxBackoff;
  }

  /**
   * How long an endpoint that refused a connection is skipped.
   *
   * @return the cool-down
   */
  public Duration cooldown() {
    return cooldown;
  }

  /**
   * The fraction of each back-off that is random: a back-off {@code b} becomes a uniformly random
   * duration between {@code b * (1 - jitter)} and {@code b}, so clients that failed together do not
   * retry together. 0 disables jitter.
   *
   * @return the fraction, 0 to 1
   */
  public double jitter() {
    return jitter;
  }

  /**
   * Whether Encrypt, Decrypt, Sign, Verify, MAC and RNG Retrieve are retried.
   *
   * @return whether cryptographic operations are retried
   */
  public boolean retryCrypto() {
    return retryCrypto;
  }

  /**
   * How long one attempt of a read waits for a reply while an endpoint this call has not tried is
   * available. Empty for the default: the call timeout (of the {@code Kms}, or of a longer {@link
   * Kms#withTimeout} view) divided by {@link #maxAttempts()}, 10 s for the defaults.
   *
   * <p>An endpoint that does not answer within it, also to the SDK's first Discover Versions, is
   * closed, reported to {@link KmsListener#endpointUnavailable} and cooled down. The read goes on
   * to the next endpoint within the same deadline. An attempt with no untried endpoint left, so
   * every attempt with a single endpoint, gets the rest of the deadline, so a slow but healthy
   * server is still waited for. A cut does not use up an attempt:
   * when every attempt fails and time is left, each endpoint cut off is tried again with the rest
   * of the deadline. With {@link #none()} or one attempt a read is never cut off. Mutations are
   * never cut off, because they are never re-sent.
   *
   * @return the attempt timeout; empty for the default
   */
  public Optional<Duration> attemptTimeout() {
    return Optional.ofNullable(attemptTimeout);
  }

  /** The attempt timeout in nanoseconds for calls whose timeout is {@code callTimeout}. */
  long attemptNanos(Duration callTimeout) {
    if (attemptTimeout != null) return attemptTimeout.toNanos();
    long call;
    try {
      call = callTimeout.toNanos();
    } catch (ArithmeticException tooLong) {
      call = Long.MAX_VALUE / 4;
    }
    return Math.max(1, call / maxAttempts);
  }

  /** The back-off before retry number {@code attempt} (1 for the first retry). */
  Duration backoff(int attempt) {
    // Durations are at most a day (2^27 ms), so the shift (at most 2^20) cannot overflow.
    long millis =
        Math.min(
            initialBackoff.toMillis() << Math.min(20, Math.max(0, attempt - 1)),
            maxBackoff.toMillis());
    if (jitter > 0 && millis > 0)
      millis -= (long) (millis * jitter * ThreadLocalRandom.current().nextDouble());
    return Duration.ofMillis(millis);
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof RetryPolicy r
        && r.maxAttempts == maxAttempts
        && r.initialBackoff.equals(initialBackoff)
        && r.maxBackoff.equals(maxBackoff)
        && r.cooldown.equals(cooldown)
        && Double.compare(r.jitter, jitter) == 0
        && r.retryCrypto == retryCrypto
        && Objects.equals(r.attemptTimeout, attemptTimeout);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        maxAttempts, initialBackoff, maxBackoff, cooldown, jitter, retryCrypto, attemptTimeout);
  }

  @Override
  public String toString() {
    return "RetryPolicy[attempts "
        + maxAttempts
        + ", backoff "
        + initialBackoff
        + ".."
        + maxBackoff
        + ", jitter "
        + jitter
        + ", cooldown "
        + cooldown
        + (retryCrypto ? "" : ", no crypto retry")
        + (attemptTimeout == null ? "" : ", attempt timeout " + attemptTimeout)
        + "]";
  }

  /** Builds a {@link RetryPolicy}; starts from the defaults. Not thread-safe. */
  public static final class Builder {
    private int maxAttempts = 3;
    private Duration initialBackoff = Duration.ofMillis(100), maxBackoff = Duration.ofSeconds(2);
    private Duration cooldown = Duration.ofSeconds(5);
    private double jitter = 0.5;
    private boolean retryCrypto = true;
    private Duration attemptTimeout;

    private Builder() {}

    /**
     * Total attempts for a retryable operation, at least 1 (1 disables retries).
     *
     * @param attempts the number of attempts, at least 1
     * @return this builder
     * @throws IllegalArgumentException when {@code attempts} is less than 1
     */
    public Builder maxAttempts(int attempts) {
      if (attempts < 1) throw new IllegalArgumentException("At least one attempt");
      this.maxAttempts = attempts;
      return this;
    }

    /**
     * The back-off before the first retry (default 100 ms). Every duration here is at most one
     * day.
     *
     * @param d the back-off, not negative
     * @return this builder
     * @throws IllegalArgumentException when {@code d} is negative or longer than one day
     */
    public Builder initialBackoff(Duration d) {
      this.initialBackoff = nonNegative(d, "initialBackoff");
      return this;
    }

    /**
     * The longest back-off (default 2 s).
     *
     * @param d the back-off, not negative
     * @return this builder
     * @throws IllegalArgumentException when {@code d} is negative or longer than one day
     */
    public Builder maxBackoff(Duration d) {
      this.maxBackoff = nonNegative(d, "maxBackoff");
      return this;
    }

    /**
     * How long an endpoint that refused a connection is skipped (default 5 s).
     *
     * @param d the cool-down, not negative
     * @return this builder
     * @throws IllegalArgumentException when {@code d} is negative or longer than one day
     */
    public Builder cooldown(Duration d) {
      this.cooldown = nonNegative(d, "cooldown");
      return this;
    }

    /**
     * The random fraction of each back-off, from 0 (none) to 1 (default 0.5); see {@link
     * RetryPolicy#jitter()}.
     *
     * @param fraction the fraction, 0 to 1
     * @return this builder
     * @throws IllegalArgumentException when {@code fraction} is not between 0 and 1
     */
    public Builder jitter(double fraction) {
      if (!(fraction >= 0 && fraction <= 1))
        throw new IllegalArgumentException("Jitter is between 0 and 1");
      this.jitter = fraction;
      return this;
    }

    /**
     * Whether cryptographic operations are retried (default true).
     *
     * @param retry whether to retry them
     * @return this builder
     */
    public Builder retryCrypto(boolean retry) {
      this.retryCrypto = retry;
      return this;
    }

    /**
     * How long one attempt of a read waits for a reply when another attempt may follow (default:
     * the call timeout divided by {@link #maxAttempts}); see {@link RetryPolicy#attemptTimeout()}.
     * Positive, at most one day.
     *
     * @param d the timeout, positive
     * @return this builder
     * @throws IllegalArgumentException when {@code d} is not positive or longer than one day
     */
    public Builder attemptTimeout(Duration d) {
      Duration checked = nonNegative(d, "attemptTimeout");
      if (checked.isZero()) throw new IllegalArgumentException("attemptTimeout must be positive");
      this.attemptTimeout = checked;
      return this;
    }

    /**
     * Derive the attempt timeout from the call timeout again (the default).
     *
     * @return this builder
     */
    public Builder defaultAttemptTimeout() {
      this.attemptTimeout = null;
      return this;
    }

    /**
     * Builds an immutable policy; the builder can build again or be changed further.
     *
     * @return the policy
     * @throws IllegalArgumentException when the initial back-off exceeds the maximum
     */
    public RetryPolicy build() {
      if (initialBackoff.compareTo(maxBackoff) > 0)
        throw new IllegalArgumentException("The initial back-off exceeds the maximum");
      return new RetryPolicy(this);
    }

    /** Longer durations would overflow the back-off arithmetic; no sensible policy needs them. */
    private static final Duration LONGEST = Duration.ofDays(1);

    private static Duration nonNegative(Duration d, String name) {
      Objects.requireNonNull(d, name);
      if (d.isNegative()) throw new IllegalArgumentException("Negative " + name);
      if (d.compareTo(LONGEST) > 0)
        throw new IllegalArgumentException(name + " is at most one day");
      return d;
    }
  }
}
