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

package dev.keytend.kmip.transport;

import java.io.*;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * A deadline and a cancellation signal for one call. Pass it to {@link
 * KmipTransport#exchange(dev.keytend.kmip.model.Ttlv, CallContext)} (or the {@code KmipClient}
 * overloads taking one) to bound or cancel that call alone; {@code close()} on a transport still
 * cancels every call.
 *
 * <p>A call fails in one of two ways when its deadline passes or it is canceled:
 *
 * <ul>
 *   <li>Once the request may have been written, a call past its deadline fails with {@link
 *       SocketTimeoutException}, and a canceled or interrupted call with {@link
 *       InterruptedIOException}. The request may have reached the server, so the outcome of a
 *       mutation is unknown and needs reconciliation.
 *   <li>Before any request byte was written, the call fails with {@link RequestNotSentException}
 *       instead. That includes the wait for a pooled connection or for {@link
 *       HashedPasswordTransport}'s exchange lock, and {@link #cancel()} ends those waits at once.
 *       Its {@link RequestNotSentException#local()} is true, and its cause is the {@code
 *       SocketTimeoutException} or {@code InterruptedIOException}. Its {@link
 *       RequestNotSentException#timedOut()} and {@link RequestNotSentException#cancelled()} tell
 *       the two apart. Such a request is safe to repeat.
 * </ul>
 *
 * <p>Nothing is retried automatically.
 *
 * @since 0.10.0
 */
public final class CallContext {
  /** No deadline beyond the transport's own; cannot be canceled. */
  public static final CallContext NONE = new CallContext(Long.MAX_VALUE, false);

  private final long deadline;
  private final boolean cancellable;
  private volatile boolean canceled;
  private final List<Runnable> listeners = new CopyOnWriteArrayList<>();

  private CallContext(long deadline, boolean cancellable) {
    this.deadline = deadline;
    this.cancellable = cancellable;
  }

  /** A cancellable context without its own deadline. */
  public static CallContext cancellable() {
    return new CallContext(Long.MAX_VALUE, true);
  }

  /** A cancellable context whose deadline is {@code timeout} from now. */
  public static CallContext withTimeout(Duration timeout) {
    if (timeout.isNegative() || timeout.isZero())
      throw new IllegalArgumentException("Timeout must be positive");
    long now = System.nanoTime();
    long nanos;
    try {
      nanos = timeout.toNanos();
    } catch (ArithmeticException tooLong) {
      nanos = Long.MAX_VALUE / 2;
    }
    return new CallContext(now + Math.min(nanos, Long.MAX_VALUE / 2), true);
  }

  /**
   * A cancellable context whose deadline is {@code deadline}, a {@link System#nanoTime()} value.
   * Use it to give several calls one deadline. Building each context with {@code
   * withTimeout(Duration.ofNanos(deadline - System.nanoTime()))} reads the clock again and moves
   * the deadline later by the time between the reads.
   *
   * @param deadline the deadline, on the {@link System#nanoTime()} clock. When it has passed, a
   *     call fails with {@link RequestNotSentException} before anything is sent
   * @return the context
   * @throws IllegalArgumentException when {@code deadline} is {@link Long#MAX_VALUE}, which means no
   *     deadline (use {@link #cancellable()})
   */
  public static CallContext withDeadline(long deadline) {
    if (deadline == Long.MAX_VALUE)
      throw new IllegalArgumentException("Long.MAX_VALUE means no deadline; use cancellable()");
    return new CallContext(deadline, true);
  }

  /** Cancels the call: blocked I/O is closed and the call fails. Idempotent. */
  public void cancel() {
    if (!cancellable)
      throw new UnsupportedOperationException("CallContext.NONE is not cancellable");
    if (canceled) return;
    canceled = true;
    for (Runnable listener : listeners) listener.run();
  }

  /**
   * Whether {@link #cancel()} was called.
   *
   * @return true once canceled
   */
  public boolean isCancelled() {
    return canceled;
  }

  /**
   * Whether this context has a deadline of its own ({@link #withTimeout}, {@link #withDeadline}).
   *
   * @return true when it has one
   */
  public boolean hasDeadline() {
    return deadline != Long.MAX_VALUE;
  }

  /** Nanoseconds left before the deadline ({@link Long#MAX_VALUE} without one; may be negative). */
  public long remainingNanos() {
    return deadline == Long.MAX_VALUE ? Long.MAX_VALUE : deadline - System.nanoTime();
  }

  /** The earlier of this context's deadline and {@code otherDeadline} (both {@code nanoTime}). */
  public long deadlineBefore(long otherDeadline) {
    return deadline == Long.MAX_VALUE ? otherDeadline : Math.min(deadline, otherDeadline);
  }

  /** Throws if the call is canceled or past its deadline. */
  public void check() throws IOException {
    if (canceled) throw new InterruptedIOException("KMIP call canceled");
    if (remainingNanos() <= 0) throw new SocketTimeoutException("KMIP call deadline exceeded");
  }

  /** {@link #check()} for a call that has sent nothing yet: failures are not-sent and local. */
  void checkNotSent() throws RequestNotSentException {
    try {
      check();
    } catch (IOException e) {
      throw new RequestNotSentException("KMIP request not sent: " + e.getMessage(), e, true);
    }
  }

  /**
   * Runs {@code listener} when the call is canceled (at once if it already is). Close the returned
   * handle when the call ends.
   */
  public Closeable onCancel(Runnable listener) {
    if (!cancellable) return () -> {};
    listeners.add(listener);
    if (canceled) listener.run();
    return () -> listeners.remove(listener);
  }
}
