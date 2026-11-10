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

import java.io.Closeable;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.util.ArrayDeque;
import java.util.concurrent.*;

/**
 * A fair (FIFO) counting semaphore whose waits end at a deadline, on {@link CallContext#cancel()},
 * or on interrupt, without losing the waiter's place in the queue before then. A released permit
 * is handed directly to the oldest live waiter, so a free permit never coexists with a live waiter
 * and {@link #tryAcquire()} cannot barge.
 */
final class Permits {
  private final ArrayDeque<CompletableFuture<Boolean>> waiters = new ArrayDeque<>();
  private int available;

  /** The acquires that found no free permit and waited, and how long they waited in all. */
  private final java.util.concurrent.atomic.AtomicLong
      waits = new java.util.concurrent.atomic.AtomicLong(),
      waitNanos = new java.util.concurrent.atomic.AtomicLong();

  /** The acquires so far that found no free permit and waited (however the wait ended). */
  long waits() {
    return waits.get();
  }

  /** How long those acquires waited, in all, in nanoseconds. */
  long waitNanos() {
    return waitNanos.get();
  }

  Permits(int permits) {
    available = permits;
  }

  /** Takes a permit if one is free; never waits. */
  synchronized boolean tryAcquire() {
    if (available == 0) return false;
    available--;
    return true;
  }

  /**
   * Waits for a permit until {@code deadline} ({@code System.nanoTime()}, {@link Long#MAX_VALUE}
   * for none).
   *
   * @throws SocketTimeoutException the deadline passed first ({@code timeoutMessage})
   * @throws InterruptedIOException the context was canceled or the thread interrupted (the
   *     interrupt flag is kept)
   */
  @SuppressWarnings("UndefinedEquals") // each future is removed by identity, as it was added
  void acquire(CallContext context, long deadline, String timeoutMessage) throws IOException {
    CompletableFuture<Boolean> turn;
    synchronized (this) {
      if (available > 0) {
        available--;
        return;
      }
      turn = new CompletableFuture<>();
      waiters.addLast(turn);
    }
    waits.incrementAndGet();
    long waitStart = System.nanoTime();
    boolean interrupted = false, timedOut = false;
    Closeable cancellation = context.onCancel(() -> turn.complete(false));
    try {
      if (deadline == Long.MAX_VALUE) turn.get();
      else turn.get(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
    } catch (InterruptedException e) {
      interrupted = true;
    } catch (TimeoutException e) {
      timedOut = true;
    } catch (ExecutionException impossible) {
      throw new IllegalStateException(impossible);
    } finally {
      cancellation.close();
      waitNanos.addAndGet(System.nanoTime() - waitStart);
    }
    // Either the releaser completed the turn with true (granted) or nobody did yet: end it.
    turn.complete(false);
    boolean granted = turn.join();
    if (granted && !interrupted && !timedOut) return;
    if (granted) release();
    else
      synchronized (this) {
        waiters.remove(turn);
      }
    if (interrupted) {
      Thread.currentThread().interrupt();
      throw new InterruptedIOException("KMIP exchange interrupted");
    }
    if (timedOut) throw new SocketTimeoutException(timeoutMessage);
    throw new InterruptedIOException("KMIP call canceled");
  }

  /** Hands the permit to the oldest live waiter, or makes it free. */
  void release() {
    synchronized (this) {
      for (CompletableFuture<Boolean> w; (w = waiters.pollFirst()) != null; )
        if (w.complete(true)) return;
      available++;
    }
  }
}
