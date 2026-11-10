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

import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.LongSupplier;
import javax.crypto.SecretKey;

/**
 * The current key of a named rotation lineage, followed as the lineage is rotated. It seals under
 * the lineage's newest key and opens through any key of the lineage, so an application instance
 * needs no refresh-and-retry code of its own.
 *
 * <p>Get one with {@link KmsKeys#current(String) kms.keys().current(name)}. Keep one per key for
 * the life of the {@link Kms}, and share that object between the components that seal under the
 * key. Configure it before you share it: {@link #checkingEvery} and {@link #refreshingEvery} return
 * a new object.
 *
 * <pre>{@code
 * // orderJson: the record to protect, as bytes
 * CurrentKey kek = kms.keys().current("orders-kek");
 * byte[] orderId = "order-1042".getBytes(StandardCharsets.UTF_8);
 * byte[] sealed = kek.seal(orderJson, orderId);   // under the current key
 * byte[] plain = kek.open(sealed, orderId);       // through any key of the lineage
 * }</pre>
 *
 * <p><b>How it follows.</b> Before a call, at most once per check interval ({@link
 * #DEFAULT_CHECK_EVERY} unless configured), it looks for a newer Active key with {@link
 * KeyHandle#latest()}. When a seal is refused because the key held is no longer Active, it moves to
 * the newer key at once and repeats the call. Instances may seal under the old key for up to one
 * interval after a rotation. The old key still opens what they sealed. {@link #checkingEvery} and
 * {@link #refreshingEvery} give the details, and {@link #refresh()} the call deadlines.
 *
 * <p><b>Rotation.</b> Rotation is a single-actor job. The instances follow the new key through
 * their {@code CurrentKey}, and one scheduled job rotates, with {@link
 * #rotateIfActiveFor(Duration)}. A rotation through this object moves it at once. {@link
 * #moveTo(KeyHandle)} holds a key it cannot reach by following, such as a replacement made without
 * links.
 *
 * <p>Thread-safe. {@link #close()} stops the background checks of a {@link #refreshingEvery}
 * object; other objects schedule nothing. See <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#several-instances">Several
 * instances</a>.
 *
 * @since 0.10.0
 */
public final class CurrentKey {
  /** The check interval of {@link KmsKeys#current(String)}: one minute. */
  public static final Duration DEFAULT_CHECK_EVERY = Duration.ofMinutes(1);

  private final long checkEvery;
  private final LongSupplier nanos;

  /** Checks run on an executor only ({@link #refreshingEvery}), never on a caller's thread. */
  private final boolean background;

  /** Taken within the caller's deadline ({@link #lock(String)}), never waited for without one. */
  private final ReentrantLock lock = new ReentrantLock();

  private volatile KeyHandle handle;
  private volatile long checkedAt;

  /** Checks in a row that failed, since one succeeded or the key held was set; guarded by {@link #lock}. */
  private int failures;

  private final List<Consumer<KeyHandle>> listeners = new CopyOnWriteArrayList<>();

  /** Calls of {@link #tell()} not yet done; the one that raised it from 0 tells for all of them. */
  private final AtomicInteger telling = new AtomicInteger();

  /** The key the {@link #onChange} listeners were last told of; read and written by the teller only. */
  private KeyHandle told;

  /** The scheduled check of a {@link #refreshingEvery} object. */
  private volatile ScheduledFuture<?> task;

  private volatile boolean closed;

  /**
   * The state a check last read of the key held, for {@link KmsListener#keyStateChanged}; null
   * until one reads it. Written with the lock held.
   */
  private volatile KeyState observed;

  CurrentKey(KeyHandle start, Duration checkEvery, LongSupplier nanos) {
    this(start, nanos(checkEvery, "checkEvery"), nanos, false, null);
  }

  private CurrentKey(
      KeyHandle start, long checkEvery, LongSupplier nanos, boolean background, KeyState observed) {
    this.handle = Objects.requireNonNull(start, "key");
    this.observed = observed;
    this.told = start;
    this.checkEvery = checkEvery;
    this.nanos = nanos;
    this.background = background;
    this.checkedAt = nanos.getAsLong();
  }

  private static long nanos(Duration interval, String what) {
    Objects.requireNonNull(interval, what);
    if (interval.isNegative() || interval.isZero())
      throw new IllegalArgumentException(what + " must be positive: " + interval);
    try {
      return interval.toNanos();
    } catch (ArithmeticException tooLong) {
      return Long.MAX_VALUE;
    }
  }

  /**
   * A new follower of the same key that checks for a newer key every {@code interval} instead of
   * {@link #DEFAULT_CHECK_EVERY}. Call it before the object is shared, and share what it returns:
   *
   * <pre>{@code
   * CurrentKey kek = kms.keys().current("invoices-kek").checkingEvery(Duration.ofSeconds(10));
   * }</pre>
   *
   * <p>The new follower starts from this one's current key and keeps its own state. Rotations and
   * {@link #moveTo} through one do not move the other, and no {@link #onChange} listener is copied.
   *
   * <p><b>Checks before a call.</b> When the last check is older than the interval, a call first
   * runs one {@link KeyHandle#latest()}: one Get Attributes per key of the lineage. The follower
   * moves only to an Active key, so a newest key between its Re-key and its Activate is passed
   * over. A check that fails is passed over until the next interval, and {@link
   * KmsListener#currentKeyCheckFailed} hears of it at most once per interval. Each check also tells
   * {@link KmsListener#keyStateChanged} when it reads the key held in a different state from
   * before. A server that keeps a replaced key Active refuses nothing, so these checks are what
   * moves the follower there.
   *
   * <p><b>After a refusal.</b> When the server refuses a call with a {@link StateConflictException}
   * about the key held, the follower runs {@code latest()} at once and repeats the call once with
   * the newer key. Threads refused at the same time share the newer key the first one found. When
   * there is no other Active key, or {@code latest()} fails, the refusal is thrown. A refusal about
   * another key, such as a record's Compromised key, is thrown as it is. Only calls that fail
   * before anything is written are repeated: {@link #seal}, {@link #sealing}, {@link #sealTo},
   * {@link #chunkedSealer}, {@link #rewrapRecord}, {@link #rewrapHeader}, {@link #rewrapKey},
   * {@link #generateDataKey} and {@link #wrapKey}.
   *
   * <p><b>Advanced.</b> For a check interval other than {@link #DEFAULT_CHECK_EVERY}. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">the
   * advanced alternatives</a>.
   *
   * @param interval how often to check, positive
   * @return a new follower; this one is unchanged
   * @throws IllegalArgumentException when {@code interval} is not positive
   */
  public CurrentKey checkingEvery(Duration interval) {
    return new CurrentKey(handle, nanos(interval, "checkEvery"), nanos, false, observed);
  }

  /** This new object, knowing that its key was read in {@code state} (a key found by name). */
  CurrentKey observing(KeyState state) {
    observed = state;
    return this;
  }

  /**
   * A new follower of the same key whose checks run every {@code interval} on {@code executor},
   * never on the threads that seal. {@link #seal}, {@link #handle()} and the other calls use the
   * key held with no request and no lock for the check. A refused call still moves to the newer key
   * at once, on its own thread (see {@link #checkingEvery}).
   *
   * <pre>{@code
   * // scheduler: a ScheduledExecutorService you own; log: your logger
   * CurrentKey kek = kms.keys().current("invoices-kek")
   *     .refreshingEvery(Duration.ofSeconds(60), scheduler);
   * kek.onChange(k -> log.info("new records use {}", k.id()));
   * // ...
   * kek.close(); // at shutdown: cancels the task; the executor stays yours
   * }</pre>
   *
   * <p>The first check runs one interval from now. Each check is one {@link KeyHandle#latest()}
   * with a call deadline of its own, the call timeout of the key held's {@link Kms}, and moves only
   * to an Active key. A check that fails is told to {@link KmsListener#currentKeyCheckFailed}. The
   * key held stays, and the next interval tries again: nothing a check throws ends the schedule.
   * Like {@link #checkingEvery}, this starts from this one's current key and keeps its own state
   * and listeners, so configure what it returns ({@link #onChange}) and share that. The executor
   * must outlive this object's use.
   *
   * <p><b>Advanced.</b> For sealing threads that must never wait for a check (a lineage walk, a
   * slow KMS). {@link KmsKeys#current(String)}, which checks at most once a minute on the callers'
   * threads, suits most applications. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">the
   * advanced alternatives</a>.
   *
   * @param interval how often to check, positive
   * @param executor the caller's executor that runs the checks; not shut down by this object
   * @return a new follower, owned by the caller, who {@link #close() closes} it to cancel the task
   * @throws IllegalArgumentException when {@code interval} is not positive
   * @throws java.util.concurrent.RejectedExecutionException when {@code executor} refuses the task
   *     (it was shut down)
   * @since 0.10.0
   */
  public CurrentKey refreshingEvery(Duration interval, ScheduledExecutorService executor) {
    long every = nanos(interval, "interval");
    Objects.requireNonNull(executor, "executor");
    CurrentKey k = new CurrentKey(handle, every, nanos, true, observed);
    k.task = executor.scheduleWithFixedDelay(k::scheduledCheck, every, every, TimeUnit.NANOSECONDS);
    return k;
  }

  /**
   * Adds a listener told of the key held after it changes. Every path counts: a check, scheduled or
   * due before a call, the refresh after a refusal, {@link #refresh()}, a rotation through this
   * object, and {@link #moveTo}.
   *
   * <p>A listener runs outside this object's lock, on the thread that changed the key or on a thread
   * still telling of an earlier change. Listeners are told one at a time, each time of the key held
   * then. A change made while listeners run is told after them, so the last key a listener hears of
   * is the key held. A key held only briefly may not be told.
   *
   * <p>A listener that throws is passed over. The call that changed the key is not affected.
   *
   * <p>Listeners must be quick, and must not wait for another thread that uses this object. A
   * listener that calls a {@link Kms} gets its own call deadline.
   *
   * @param listener the listener; an exception it throws is ignored
   * @return this object
   * @since 0.10.0
   */
  public CurrentKey onChange(Consumer<KeyHandle> listener) {
    listeners.add(Objects.requireNonNull(listener, "listener"));
    return this;
  }

  /**
   * Stops the checks {@link #refreshingEvery} scheduled: cancels the task (the executor is the
   * caller's), and a check still walking the lineage does not move the key held any more (one
   * that has finished its walk may still complete its move as {@code close()} runs). The object
   * goes on working with the key it holds, and still follows a refused call, a rotation or {@link
   * #moveTo} through it. Nothing for an object that schedules nothing. Idempotent.
   *
   * @since 0.10.0
   */
  public void close() {
    closed = true;
    ScheduledFuture<?> t = task;
    if (t != null) t.cancel(false);
  }

  /**
   * The key sealing goes under now: the handle held, after the check when one is due (never on an
   * object made by {@link #refreshingEvery}). Keep using this object rather than the handle it
   * returns.
   *
   * @return the key held
   * @throws TransientException when the call timeout passes while another thread's check or
   *     rotation through this object runs (see {@link #refresh()}); a check of its own that fails
   *     is passed over
   */
  public KeyHandle handle() {
    return handle.kms.call(
        "handle",
        () -> {
          return current("handle");
        });
  }

  /** {@link #handle()} within the deadline of the call {@code operation}, whose scope is open. */
  private KeyHandle current(String operation) {
    KeyHandle h = handle;
    // A call from a listener told with the lock held uses the key held: it never nests a check in
    // the check or rotation running on this thread.
    if (background || lock.isHeldByCurrentThread()) return h;
    long now = nanos.getAsLong();
    if (now - checkedAt < checkEvery) return h;
    return check(operation, now, false).key();
  }

  /**
   * The check of {@link #refreshingEvery}: the background call {@code "refresh"}, in a deadline of
   * its own, FAILED when the check failed (told to {@link KmsListener#currentKeyCheckFailed}, not
   * thrown); never throws.
   */
  private void scheduledCheck() {
    try {
      if (closed) return;
      KeyHandle h = handle;
      Kms.background(h.kms.callTimeout(), "refresh", () -> check("refresh", 0, true).failed());
    } catch (RuntimeException | Error e) {
      // Never ends the schedule: the next interval tries again. (A wait for the lock that the
      // deadline ended: another thread's check or rotation is moving the key meanwhile.)
    }
  }

  /**
   * A check for a newer key: one {@code latest()}, and a move to it when it is Active. A due check ({@code scheduled} false) runs when the interval since {@code
   * now} has passed, a scheduled one unless this object was closed. Failures are passed over and
   * told to the listener.
   */
  private Checked check(String operation, long now, boolean scheduled) {
    KeyHandle h;
    KmsException failed = null;
    int inARow = 0;
    StateChange change = null;
    lock(operation);
    try {
      if (scheduled ? closed : now - checkedAt < checkEvery) return new Checked(handle, null);
      try {
        KeyHandle.Walk walk = handle.walk();
        change = observe(walk);
        KeyAttributes newest = walk.newest();
        failures = 0;
        checkedAt = nanos.getAsLong();
        if (movable(newest) && !(scheduled && closed)) {
          hold(handle.handleOf(newest));
          observed = newest.state();
        }
      } catch (KmsException e) {
        // Passed over: the next interval tries again, and sealing goes on with the key held.
        failed = e;
        inARow = ++failures;
      } catch (IllegalStateException closedKms) {
        // The Kms is closed (the call fails anyway), or a listener re-entered findOrCreate.
      }
      checkedAt = nanos.getAsLong();
      h = handle;
    } finally {
      lock.unlock();
    }
    // Outside the lock, and after checkedAt moved on: a listener that seals does not check again.
    if (change != null) change.tell();
    if (failed != null) h.kms.currentKeyCheckFailed(h.id(), inARow, failed);
    tell();
    return new Checked(h, failed);
  }

  /** What a {@link #check} holds afterwards, and its failure, which was passed over (null: none). */
  private record Checked(KeyHandle key, KmsException failed) {}

  /**
   * Looks for a newer key now, whatever the interval: one {@link KeyHandle#latest()} of the key
   * held. The newest key becomes the key held when it is Active. One that is not, such as a key
   * whose rotation has not activated it yet, is not moved to. Call it before a re-sealing job, so
   * the job moves records to the newest key.
   *
   * <p><b>Deadlines.</b> Each call through this object has one deadline: the call timeout of the
   * {@link Kms} (or {@link Kms#withTimeout} view) of the key held when the call starts. It covers
   * the check, the call, and the check and repeated call after a refusal. A call that waits for
   * another thread's check or rotation through this object waits within that deadline too. When the
   * deadline passes first, the call fails with {@link TransientException} ({@code RETRY}, a {@link
   * SocketTimeoutException} as its cause). An interrupted wait fails at once, with an {@link
   * InterruptedIOException} as its cause, and the interrupt flag is kept. {@link #sealTo} and
   * {@link #openTo} bound their requests this way, not the reading and writing of files around
   * them. A check that {@link #refreshingEvery} schedules has a deadline of its own, the call
   * timeout.
   *
   * @return the key held afterwards
   * @throws KmsException as {@link KeyHandle#latest()}; the key held is then unchanged
   */
  public KeyHandle refresh() {
    return handle.kms.call(
        "refresh",
        () -> {
          lock("refresh");
          StateChange change = null;
          try {
            KeyHandle.Walk walk = handle.walk();
            change = observe(walk);
            KeyAttributes newest = walk.newest();
            failures = 0;
            checkedAt = nanos.getAsLong();
            if (movable(newest)) {
              hold(handle.handleOf(newest));
              observed = newest.state();
            }
            return handle;
          } finally {
            lock.unlock();
            if (change != null) change.tell();
            tell();
          }
        });
  }

  /**
   * Rotates the key held and holds the result: {@link KeyHandle#rotateOrLatest()} of the key held.
   * A key another instance replaced already is not rotated again, and its current key is returned.
   * The components that share this object seal under the new key from their next call.
   *
   * <p>The call holds this object's lock while it runs, so two rotations through one {@code
   * CurrentKey} do not race. Listener callbacks made meanwhile, such as {@link
   * KmsListener#concurrentReplacement}, run with the lock held, so they must not wait for another
   * thread that uses this object. Other threads go on sealing under the key held. One whose check
   * is due waits for the rotation within its own deadline (see {@link #refresh()}).
   *
   * <p>A key held that is Compromised or Deactivated is not rotated: {@link
   * StateConflictException}, before any Re-key. Recover with {@code
   * kek.moveTo(kek.handle().replaceCompromised(reason))}.
   *
   * <p><b>Advanced.</b> For a rotation that is not on a schedule. A scheduled job calls {@link
   * #rotateIfActiveFor(Duration)}, which rotates only a key that is due. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">the
   * advanced alternatives</a>.
   *
   * @return the key held afterwards
   * @throws KmsException as {@link KeyHandle#rotateOrLatest()}; the key held is then unchanged
   */
  public KeyHandle rotateOrLatest() {
    return rotateOrLatest(Rotation.of(RotationDates.COPIED));
  }

  /**
   * {@link #rotateOrLatest()} as {@code rotation} says ({@link
   * KeyHandle#rotateOrLatest(Rotation)}). With a grace period, the old key's deactivation is
   * scheduled after the rotation. When the rotation was made and only that scheduling failed, the
   * new key is held all the same before the {@link PartialCompletionException} is thrown.
   *
   * <p><b>Advanced.</b> As {@link #rotateOrLatest()}.
   *
   * @param rotation how to rotate
   * @return the key held afterwards
   * @throws PartialCompletionException when the old key's deactivation could not be scheduled (see
   *     {@link KeyHandle#rotate(Rotation)}); the current key is held
   * @throws KmsException as {@link KeyHandle#rotateOrLatest(Rotation)}; the key held is then
   *     unchanged
   */
  public KeyHandle rotateOrLatest(Rotation rotation) {
    Objects.requireNonNull(rotation, "rotation");
    return handle.kms.call(
        "rotateOrLatest",
        () -> {
          lock("rotateOrLatest");
          try {
            // In the call: holdRotated throws a grace period that was not scheduled.
            return holdRotated(handle.rotated(true, rotation));
          } finally {
            lock.unlock();
            tell();
          }
        });
  }

  /**
   * Rotates the key held when it is due, and holds the result: {@link
   * KeyHandle#rotateIfActiveFor(Duration)} of the key held. The key is due {@code period} after the
   * later of its Activation Date and its Initial Date. When it is not due, the lineage's current
   * key is held and returned.
   *
   * <pre>{@code
   * // in one scheduled job, run daily; every component that shares kek follows
   * kek.rotateIfActiveFor(Duration.ofDays(30));
   * }</pre>
   *
   * <p>Rotation is a single-actor job: run this from one scheduled job, and let the other instances
   * follow through their own {@code CurrentKey}. A repeated firing of that job finds the new key,
   * too new to rotate, and does not rotate again. The lock, and a Compromised key held, are as for
   * {@link #rotateOrLatest()}.
   *
   * @param period how long the current key may be Active before it is due
   * @return the key held afterwards
   * @throws IllegalArgumentException when {@code period} is negative
   * @throws KmsException as {@link KeyHandle#rotateIfActiveFor(Duration)} (also {@link
   *     ProtocolViolationException} for a key without dates); the key held is then unchanged
   * @see <a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#rotate-on-a-schedule">Rotate
   *     on a schedule</a>
   */
  public KeyHandle rotateIfActiveFor(Duration period) {
    return rotateIfActiveFor(period, Rotation.of(RotationDates.COPIED));
  }

  /**
   * {@link #rotateIfActiveFor(Duration)} as {@code rotation} says ({@link
   * KeyHandle#rotateIfActiveFor(Duration, Rotation)}): the scheduled job of a rotation with a grace
   * period.
   *
   * <pre>{@code
   * // in one scheduled job, run daily
   * kek.rotateIfActiveFor(Duration.ofDays(30), Rotation.grace(Duration.ofDays(7)));
   * // keys a server policy deactivates 90 days after activation: shifted dates, a shorter period
   * kek.rotateIfActiveFor(Duration.ofDays(60), Rotation.of(RotationDates.SHIFTED));
   * }</pre>
   *
   * <p>When the rotation was made and only the scheduling of the old key's deactivation failed, the
   * new key is held all the same before the {@link PartialCompletionException} is thrown.
   *
   * @param period how long the current key may be Active before it is due
   * @param rotation how to rotate
   * @return the key held afterwards
   * @throws IllegalArgumentException when {@code period} is negative
   * @throws PartialCompletionException as {@link #rotateOrLatest(Rotation)}; the current key is
   *     held
   * @throws KmsException as {@link KeyHandle#rotateIfActiveFor(Duration, Rotation)}; the key held
   *     is then unchanged
   * @see <a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#rotation-with-a-grace-period">Rotation
   *     with a grace period</a>
   */
  public KeyHandle rotateIfActiveFor(Duration period, Rotation rotation) {
    Objects.requireNonNull(period, "period");
    Objects.requireNonNull(rotation, "rotation");
    return handle.kms.call(
        "rotateIfActiveFor",
        () -> {
          lock("rotateIfActiveFor");
          try {
            return holdRotated(handle.rotatedIfActiveFor(period, rotation, null));
          } finally {
            lock.unlock();
            tell();
          }
        });
  }

  /**
   * Holds {@code key} from now on, whatever it is. Use it for a key this object cannot reach by
   * following, such as one that does not descend from the key held, or for the key a recovery
   * returned:
   *
   * <pre>{@code
   * kek.moveTo(kek.handle().replaceCompromised(reason));
   * kek.moveTo(kek.handle().reconcile());
   * }</pre>
   *
   * <p>No request is sent: the key is used as given. Sealing under a key that is not Active is
   * refused, and then followed as {@link #checkingEvery} describes. The next check is one interval
   * from now. A check or rotation running through this object is waited for, within one call
   * timeout.
   *
   * @param key the key to hold, a handle from the same {@code Kms}
   * @return {@code key}
   * @throws IllegalArgumentException when {@code key} is a handle of another {@link Kms} (an
   *     identifier names an object on its own server only)
   * @throws TransientException when a check or rotation through this object outlasts the call
   *     timeout (see {@link #refresh()}); the key held is then unchanged
   */
  public KeyHandle moveTo(KeyHandle key) {
    Objects.requireNonNull(key, "key");
    return handle.kms.call(
        "moveTo",
        () -> {
          lock("moveTo");
          try {
            if (!key.sameKms(handle.kms))
              throw new IllegalArgumentException(
                  "moveTo: "
                      + key.id()
                      + " is a handle of another Kms; follow it with that Kms's keys().current(key)");
            return hold(key);
          } finally {
            lock.unlock();
            tell();
          }
        });
  }

  /**
   * Takes the lock within what is left of the deadline of the call {@code operation}, whose scope
   * is open: a call queued behind another thread's check or rotation fails as a call whose deadline
   * passed does, not later.
   */
  private void lock(String operation) {
    KeyHandle h = handle;
    try {
      if (lock.tryLock(Math.max(0, h.kms.remainingNanos()), TimeUnit.NANOSECONDS)) return;
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new TransientException(
          operation + " " + h.id() + ": interrupted while waiting for another call through " + this,
          new InterruptedIOException("Interrupted while waiting for " + this),
          operation,
          h.id(),
          null,
          null);
    }
    throw new TransientException(
        operation
            + " "
            + h.id()
            + ": the call deadline passed while waiting for another call through "
            + this
            + " (a check for a newer key, or a rotation)",
        new SocketTimeoutException("KMIP call deadline exceeded"),
        operation,
        h.id(),
        null,
        null);
  }

  /** Holds {@code key}, checked as of now. Called with the lock held. */
  private KeyHandle hold(KeyHandle key) {
    if (!key.id().equals(handle.id())) observed = null;
    handle = key;
    failures = 0;
    checkedAt = nanos.getAsLong();
    return key;
  }

  /**
   * Holds the key the rotation {@code r} returned, and returns it, or throws the rotation's partial
   * failure. Called with the lock held.
   */
  private KeyHandle holdRotated(KeyHandle.Rotated r) {
    hold(r.key());
    return r.returned();
  }

  /** A change of the key held's state, told to {@link KmsListener#keyStateChanged} outside the lock. */
  private record StateChange(Kms kms, String id, KeyState from, KeyState to) {
    void tell() {
      kms.keyStateChanged(id, from, to);
    }
  }

  /**
   * Records the state {@code walk} read of the key held, and returns its change from the state
   * read before (none the first time). Called with the lock held.
   */
  private StateChange observe(KeyHandle.Walk walk) {
    KeyState was = observed, now = walk.own().state();
    observed = now;
    return was == null || was == now
        ? null
        : new StateChange(handle.kms, walk.own().id(), was, now);
  }

  /** Whether {@code newest} is another key than the one held, and Active: one to move to. */
  private boolean movable(KeyAttributes newest) {
    return !newest.id().equals(handle.id()) && newest.state() == KeyState.ACTIVE;
  }

  /**
   * Tells the {@link #onChange} listeners of the key held when it is not the one they were told of
   * last. Called after a change, outside the lock. Only one thread tells at a time; a thread that
   * finds another one telling leaves the change to it, so no caller waits for a listener another
   * thread runs, and the last key told is the key held.
   */
  private void tell() {
    if (telling.getAndIncrement() != 0) return;
    try {
      do {
        KeyHandle h = handle;
        if (h.id().equals(told.id())) continue;
        told = h;
        Kms.outsideCall(
            () -> {
              for (Consumer<KeyHandle> l : listeners)
                try {
                  l.accept(h);
                } catch (RuntimeException ignored) {
                  // A listener cannot change the outcome of the call that moved the key.
                }
            });
      } while (telling.decrementAndGet() != 0);
    } catch (Error e) {
      telling.set(0);
      throw e;
    }
  }

  /**
   * Seals {@code plaintext} under the current key: envelope encryption in one call. The data is
   * encrypted locally with AES-256-GCM under a fresh data key, which the current key wraps on the
   * server with AES-GCM. Both go into one versioned container to store.
   *
   * <p>The data key and the data are bound to {@code aad}, which should be the record's identity,
   * and to each other. One server request (Encrypt), plus one Get Attributes the first time for a
   * key whose usages this object has not read, and the check when one is due. Needs KMIP 1.4. Open
   * the result with {@link #open} or {@link KmsKeys#open}, also after rotations. The key needs the
   * Encrypt usage to seal and Decrypt to open, so a key without Decrypt is refused before anything
   * is sent. A refused key is followed as {@link #checkingEvery} describes.
   *
   * <pre>{@code
   * // orderJson: the record to protect, as bytes
   * byte[] orderId = "order-1042".getBytes(StandardCharsets.UTF_8); // the additional data
   * byte[] stored = kek.seal(orderJson, orderId);
   * byte[] back = kek.open(stored, orderId);
   * }</pre>
   *
   * @param plaintext the data to seal
   * @param aad the additional data to bind; null or empty for none
   * @return the sealed record, a new array
   * @throws UnsupportedException before KMIP 1.4
   * @throws KeyMismatchException when the current key cannot decrypt what it would encrypt (no
   *     Decrypt usage), checked before anything is sent
   * @throws StateConflictException when the current key is refused and no newer Active key is found
   *     (see {@link #checkingEvery})
   * @see <a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/envelope-encryption.md#seal-and-open-records">Seal
   *     and open records</a>
   */
  public byte[] seal(byte[] plaintext, byte[] aad) {
    return following("seal", h -> h.seal(plaintext, aad));
  }

  /**
   * {@link KeyHandle#open} through the current key's handle: any key of its lineage.
   *
   * @param sealed the sealed record
   * @param aad the additional data given when sealing; null or empty for none
   * @return the plaintext, a new array
   */
  public byte[] open(byte[] sealed, byte[] aad) {
    return handle.kms.call(
        "open",
        () -> {
          return current("open").open(sealed, aad);
        });
  }

  /**
   * A stream that seals what is written to it under the current key, for data too large to hold in
   * memory that does not go to a file (an upload, a socket, an archive entry). It encrypts locally
   * with AES-256-GCM under a fresh data key, in 64 KiB chunks, and writes to {@code out}. The format
   * is that of {@link #sealTo} and {@link KeyHandle#sealing}.
   *
   * <p>The data key is wrapped now: one Encrypt, plus one Get Attributes the first time for a key
   * whose usages this object has not read, and the check when one is due. No request is sent per
   * chunk. A refused key is followed and the call repeated, as for {@link #seal}: nothing is written
   * to {@code out} before the data key is wrapped, so the repeat writes to {@code out} as the first
   * call would have. Open the result with {@link #opening} or {@link KmsKeys#opening}, also after
   * rotations.
   *
   * <p>Call {@link SealingStream#finish()} before closing: only a finished stream can be opened, and
   * closing an unfinished one throws {@link IOException}. So a job that fails part-way never leaves
   * an authentic but truncated stream. Closing destroys the data key. Writes throw {@link
   * IOException} for errors of {@code out}, and after 2^32 chunks (256 TiB). The stream is not
   * thread-safe, and stays under the key it started with when this object moves to a newer one.
   *
   * <pre>{@code
   * // upload: your destination; source: an InputStream of the plaintext
   * try (SealingStream sealed = kek.sealing(upload.start(), backupId)) {
   *   source.transferTo(sealed);
   *   sealed.finish();
   * }
   * upload.commit(); // only once the stream is finished and closed
   * }</pre>
   *
   * @param out where the sealed form goes; the returned stream owns it, and this method closes it
   *     before it throws
   * @param aad the additional data to bind; null or empty for none
   * @return a stream to write the plaintext to, owned by the caller, who finishes and closes it
   * @throws UnsupportedException before KMIP 1.4
   * @throws KeyMismatchException when the current key cannot decrypt what it would encrypt (no
   *     Decrypt usage), checked before anything is sent
   * @throws StateConflictException when the current key is refused and no newer Active key is found
   *     (see {@link #checkingEvery})
   * @see <a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/envelope-encryption.md#stream-large-data">Stream
   *     large data</a>
   * @since 0.10.0
   */
  public SealingStream sealing(OutputStream out, byte[] aad) {
    Objects.requireNonNull(out, "out");
    try {
      return following(
          "sealing",
          h ->
              StreamEnvelopes.sealingLeavingOpen(
                  h, out, aad, StreamEnvelopes.CHUNK, StreamEnvelopes.MAX_CHUNKS));
    } catch (RuntimeException | Error e) {
      StreamEnvelopes.closing(out, e);
      throw e;
    }
  }

  /**
   * Opens a stream written by {@link #sealing}, {@link #sealTo} or {@link KeyHandle#sealing},
   * through the current key's handle: under any key of its lineage, with the same additional data,
   * as {@link #open} does for records. The data key is unwrapped now, so key, state and lineage
   * errors come from this method. No request is sent per chunk.
   *
   * <p>Each chunk's plaintext is released only once its tag has verified, but only reaching the end
   * ({@code read} returning -1) proves the data complete. A read that fails throws {@link
   * CryptographicFailureException} ({@code BAD_DATA}): the stream was cut, extended, reordered or
   * changed, or {@code aad} differs. Keep the result only once the end was read; {@link #openTo}
   * does this for a file. Closing the returned stream closes {@code in} and destroys the data key.
   * Not thread-safe.
   *
   * <pre>{@code
   * // download: your source; staging: a temporary destination
   * try (InputStream plain = kek.opening(download.stream(), backupId)) {
   *   plain.transferTo(staging);
   * }
   * staging.commit(); // only once the end was read
   * }</pre>
   *
   * @param in the sealed stream; the returned stream owns it, and this method closes it before it
   *     throws
   * @param aad the additional data given when sealing; null or empty for none
   * @return a stream of the plaintext, owned by the caller, who closes it
   * @throws IOException for errors of {@code in} while the header is read
   * @throws CryptographicFailureException as for {@link KeyHandle#opening}
   * @throws KeyMismatchException as for {@link #open}
   * @throws StateConflictException as for {@link #open}
   * @since 0.10.0
   */
  public InputStream opening(InputStream in, byte[] aad) throws IOException {
    Objects.requireNonNull(in, "in");
    try {
      return handle.kms.call(
          "opening",
          () -> {
            return current("opening").opening(in, aad);
          });
    } catch (IOException | RuntimeException | Error e) {
      // Also when the check for a newer key fails first (closing twice does nothing).
      StreamEnvelopes.closing(in, e);
      throw e;
    }
  }

  /**
   * Seals everything {@code plaintext} gives into the file {@code target} under the current key,
   * and replaces {@code target} only once all of it is sealed.
   *
   * <p>The sealed data goes to a temporary file next to {@code target}, named {@code
   * .<name>.<random>.partial}. Where the file system supports POSIX permissions, only its owner can
   * read and write it. It is forced to the storage device and moved onto {@code target} with {@link
   * java.nio.file.StandardCopyOption#ATOMIC_MOVE ATOMIC_MOVE}, so readers see the old file or the
   * new one, never a part. A failure before the move leaves {@code target} as it was and deletes the
   * temporary file. After the move the directory is forced ({@link FileDurability#DURABLE}), so once
   * this returns the new file survives a crash where the platform can force a directory. If that
   * force fails, {@code target} is already the new file but is not confirmed durable, so keep the
   * source.
   *
   * <p>The one server request, an Encrypt, is made before any file is created. A refused key is
   * followed and the call repeated (see {@link #checkingEvery}). The call timeout does not cover the
   * file I/O. The format is the stream format of {@link KeyHandle#sealing}. A symbolic link at
   * {@code target} is replaced, not followed. Calls writing the same target at once each stage their
   * own file, and the last to move wins. A file system that cannot move atomically fails the call.
   *
   * <p>A crash can leave the temporary file behind. At startup, while nothing writes there, delete
   * the files in the directory that start with {@code .} and end in {@code .partial}. <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/envelope-encryption.md#seal-and-open-files">Seal
   * and open files</a> has an example, and says when the source may be deleted.
   *
   * @param target the file to write
   * @param plaintext the data to seal; read to its end, not closed
   * @param aad the additional data to bind; null or empty for none
   * @throws IOException for errors of {@code plaintext} or of the file system. Before anything is
   *     sent, a {@link java.nio.file.FileSystemException} when {@code target} is a directory, or a
   *     {@link java.nio.file.NoSuchFileException} when its directory does not exist. After the move,
   *     a {@link java.nio.file.FileSystemException} naming the directory when it cannot be forced;
   *     {@code target} is then the new file, as the message says
   * @throws IllegalArgumentException when {@code target} has no file name (a root)
   * @throws UnsupportedException before KMIP 1.4
   * @throws KeyMismatchException when the current key cannot decrypt what it would encrypt (no
   *     Decrypt usage), checked before anything is sent
   * @throws StateConflictException when the current key is refused and no newer Active key is found
   *     (see {@link #checkingEvery})
   */
  public void sealTo(Path target, InputStream plaintext, byte[] aad) throws IOException {
    sealTo(target, plaintext, aad, FileDurability.DURABLE);
  }

  /**
   * {@link #sealTo(Path, InputStream, byte[])} with the durability chosen. {@link
   * FileDurability#CONTENT_ONLY} does not force the directory after the move. Use it to write many
   * files to one directory and force the directory once afterwards.
   *
   * @param target the file to write
   * @param plaintext the data to seal; read to its end, not closed
   * @param aad the additional data to bind; null or empty for none
   * @param durability whether the directory is forced after the move
   * @throws IOException as for {@link #sealTo(Path, InputStream, byte[])}. With {@link
   *     FileDurability#CONTENT_ONLY} the directory is not forced, so that failure cannot happen
   * @since 0.10.0
   */
  public void sealTo(Path target, InputStream plaintext, byte[] aad, FileDurability durability)
      throws IOException {
    Objects.requireNonNull(durability, "durability");
    handle.kms.run(
        "sealTo",
        () -> {
          KeyHandle h = current("sealTo");
          try {
            h.sealTo(target, plaintext, aad, durability);
          } catch (StateConflictException refused) {
            if (!about(refused, h)) throw refused;
            refreshed("sealTo", h, refused).sealTo(target, plaintext, aad, durability);
          }
        });
  }

  /**
   * Opens the sealed file {@code sealed} into the file {@code target}, through the current key's
   * handle, as {@link KeyHandle#openTo} does. It opens files sealed under any key of the lineage,
   * and it writes plaintext to disk. The output is staged and moved onto {@code target} as for
   * {@link #sealTo(Path, InputStream, byte[])}, and the directory is forced after the move ({@link
   * FileDurability#DURABLE}). See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/envelope-encryption.md#seal-and-open-files">Seal
   * and open files</a>.
   *
   * @param sealed the sealed file
   * @param target the file to write
   * @param aad the additional data given when sealing; null or empty for none
   * @throws IOException as for {@link KeyHandle#openTo(Path, Path, byte[])}
   */
  public void openTo(Path sealed, Path target, byte[] aad) throws IOException {
    openTo(sealed, target, aad, FileDurability.DURABLE);
  }

  /**
   * {@link #openTo(Path, Path, byte[])} with the durability chosen, as for {@link
   * KeyHandle#openTo(Path, Path, byte[], FileDurability)}.
   *
   * @param sealed the sealed file
   * @param target the file to write
   * @param aad the additional data given when sealing; null or empty for none
   * @param durability whether the directory is forced after the move
   * @throws IOException as for {@link KeyHandle#openTo(Path, Path, byte[])}
   * @since 0.10.0
   */
  public void openTo(Path sealed, Path target, byte[] aad, FileDurability durability)
      throws IOException {
    Objects.requireNonNull(durability, "durability");
    handle.kms.run(
        "openTo",
        () -> {
          current("openTo").openTo(sealed, target, aad, durability);
        });
  }

  /**
   * A fresh AES data key of {@code bits} (128, 192 or 256), generated locally with {@link
   * java.security.SecureRandom}, and its form wrapped by the current key with AES-GCM and {@code
   * aad}: one Encrypt. A refused key has returned nothing (the data key it made is destroyed), so
   * the call is repeated with the newer key and another data key. Store {@link DataKey#wrapped()},
   * which names the key that wrapped it, use {@link DataKey#key()}, then destroy the data key.
   * Unwrap it later with {@link #unwrapKey unwrapKey(Expect.aes(bits), wrapped, aad)}, also after
   * rotations.
   *
   * <p><b>Advanced.</b> For building an envelope format of your own. {@link #seal} and {@link
   * #chunkedSealer} are the SDK's, versioned and bound to their additional data. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">the
   * advanced alternatives</a>.
   *
   * @param bits the data key's size: 128, 192 or 256
   * @param aad the additional data to bind to the wrapped key; null or empty for none
   * @return a new data key, owned by the caller, who destroys it
   * @throws IllegalArgumentException for any other size
   * @throws KeyMismatchException when the current key cannot decrypt what it would encrypt (no
   *     Decrypt usage), checked before anything is sent
   * @throws StateConflictException when the current key is refused and no newer Active key is found
   *     (see {@link #checkingEvery})
   * @since 0.10.0
   */
  public DataKey generateDataKey(int bits, byte[] aad) {
    Expect.aes(bits);
    return following("generateDataKey", h -> h.generateDataKey(bits, aad));
  }

  /**
   * Wraps a local key with the current key, using AES-GCM on the server (KMIP 1.4+), and binds
   * {@code aad} to it. This is the KMIP Encrypt operation, so the key needs the Encrypt usage (and
   * Decrypt for {@link #unwrapKey}). GCM is the default because servers widely support it for
   * Encrypt, while AES key wrap through Encrypt ({@link #wrapKey(CipherSpec, SecretKey, byte[])}
   * with {@link CipherSpec#keyWrap()}) is not available on all of them. A refused key has returned
   * nothing, so the call is repeated with the newer key. {@code key} is not destroyed.
   *
   * <p><b>Advanced.</b> For building an envelope format of your own. {@link #seal} and {@link
   * #chunkedSealer} are the SDK's, versioned and bound to their additional data. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">the
   * advanced alternatives</a>.
   *
   * @param key the key to wrap; not destroyed
   * @param aad the additional data to bind; null or empty for none
   * @return the wrapped key
   * @throws KeyMismatchException when the current key cannot decrypt what it would encrypt (no
   *     Decrypt usage), checked before anything is sent
   * @throws StateConflictException when the current key is refused and no newer Active key is found
   *     (see {@link #checkingEvery})
   * @since 0.10.0
   */
  public Ciphertext wrapKey(SecretKey key, byte[] aad) {
    return wrapKey(CipherSpec.aesGcm(), key, aad);
  }

  /**
   * {@link KeyHandle#wrapKey(CipherSpec, SecretKey, byte[])} under the current key with {@code
   * spec}; repeated after a refusal as {@link #wrapKey(SecretKey, byte[])} is.
   *
   * <p><b>Advanced.</b> As {@link #wrapKey(SecretKey, byte[])}.
   *
   * @param spec how to wrap
   * @param key the key to wrap; not destroyed
   * @param aad the additional data to bind; null or empty for none
   * @return the wrapped key
   * @since 0.10.0
   */
  public Ciphertext wrapKey(CipherSpec spec, SecretKey key, byte[] aad) {
    Objects.requireNonNull(spec, "spec");
    Objects.requireNonNull(key, "key");
    return following("wrapKey", h -> h.wrapKey(spec, key, aad));
  }

  /**
   * {@link KeyHandle#unwrapKey(Expect, Ciphertext, byte[])} through the current key's handle: a key
   * wrapped by any key of its lineage, as {@link #open} does. That includes older keys, and newer
   * ones another instance made since this object last checked. Destroy the result when finished.
   *
   * <p><b>Advanced.</b> For building an envelope format of your own, with {@link #wrapKey} or
   * {@link #generateDataKey}. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">the
   * advanced alternatives</a>.
   *
   * @param expect what the unwrapped key must be
   * @param wrapped the wrapped key
   * @param aad the additional data given when wrapping; null or empty for none
   * @return a new key, owned by the caller, who destroys it
   * @since 0.10.0
   */
  public DestroyableSecretKey unwrapKey(Expect expect, Ciphertext wrapped, byte[] aad) {
    Objects.requireNonNull(expect, "expect");
    Objects.requireNonNull(wrapped, "wrapped");
    return handle.kms.call(
        "unwrapKey",
        () -> {
          return current("unwrapKey").unwrapKey(expect, wrapped, aad);
        });
  }

  /**
   * Moves a wrapped key ({@link #wrapKey}, {@link #generateDataKey}) to the current key, as {@link
   * #rewrapRecord} moves records.
   *
   * <ul>
   *   <li>A wrapped key already under the key held is returned unchanged, the same object, without
   *       a request.
   *   <li>A wrapped key under an older key of the lineage is unwrapped and wrapped again by the
   *       current key, with the same spec and additional data. The key does not leave the SDK.
   * </ul>
   *
   * <p>Moving a wrapped key costs three requests. Each rotation crossed adds one Get Attributes.
   *
   * <p>Call {@link #refresh()} before a re-wrapping job, as for {@link #rewrapRecord}. A refusal of
   * the current key is followed and the call repeated, and nothing was returned before the repeat. A
   * refusal of the older key, such as Compromised, is thrown.
   *
   * <p>The data the key protects is not touched. After a compromise of an old wrapping key,
   * re-encrypt that data under a new data key instead.
   *
   * @param wrapped the wrapped key
   * @param aad the additional data given when wrapping; null or empty for none
   * @return the key wrapped by the current key: {@code wrapped} itself when it is under the key
   *     held already
   * @throws KeyMismatchException as for {@link #unwrapKey}, or when the current key cannot decrypt
   *     what it would wrap
   * @throws StateConflictException when the older key is Compromised or Destroyed, or as for {@link
   *     #wrapKey(SecretKey, byte[])}
   * @since 0.10.0
   */
  public Ciphertext rewrapKey(Ciphertext wrapped, byte[] aad) {
    Objects.requireNonNull(wrapped, "wrapped");
    return following("rewrapKey", h -> h.rewrapKey(wrapped, aad));
  }

  /**
   * A sealer for the chunks of one file that is read back at random, as a storage engine reads its
   * blocks, under the current key.
   *
   * <p>A fresh 256-bit AES data key is generated locally and wrapped by the current key with
   * AES-GCM, binding {@code fileId}: one Encrypt now, and no request per chunk. Each chunk is
   * sealed locally by its index ({@link ChunkedSealer#seal}). A refused key is followed and the
   * call repeated once, with a new data key. Store {@link ChunkedSealer#header()} once for the
   * file, and open it with {@link #chunkedOpener} or {@link KmsKeys#chunkedOpener}, also after
   * rotations. {@link #rewrapHeader} moves the header to a newer key without touching the chunks.
   *
   * <pre>{@code
   * // fileId: the file's identity; store: where your file's header and chunks go
   * try (ChunkedSealer sealer = kek.chunkedSealer(fileId)) {
   *   store.writeHeader(sealer.header());
   *   store.writeChunk(0, sealer.seal(0, first));
   *   store.writeChunk(1, sealer.sealFinal(1, last));
   * }
   * }</pre>
   *
   * <p>Each index is sealed at most once per sealer, and each sealer has a new data key, so a
   * chunk's nonce is never used twice. {@link ChunkedSealer} gives the limits, the end of the file
   * and threads. The format is <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/stored-formats.md#chunked-files-ktr">Chunked
   * files (KTR)</a>.
   *
   * @param fileId the file's identity (not null; may be empty; copied), bound to the data key and
   *     to every chunk, so a file or a chunk cannot pass for another file's. Use what names this
   *     file and no other, such as its name and generation.
   * @return a new sealer, owned by the caller, who closes it when the file is written
   * @throws UnsupportedException before KMIP 1.4
   * @throws KeyMismatchException when the current key cannot decrypt what it would encrypt (no
   *     Decrypt usage), checked before anything is sent
   * @throws StateConflictException when the current key is refused and no newer Active key is found
   *     (see {@link #checkingEvery})
   * @see <a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/envelope-encryption.md#seal-files-chunk-by-chunk">Seal
   *     files chunk by chunk</a>
   * @since 0.10.0
   */
  public ChunkedSealer chunkedSealer(byte[] fileId) {
    return following("chunkedSealer", h -> h.chunkedSealer(fileId));
  }

  /**
   * {@link KeyHandle#chunkedOpener} through the current key's handle: a header under any key of
   * its lineage. The caller owns the opener and closes it.
   *
   * @param header the file's header
   * @param fileId the file identifier it was sealed with
   * @return a new opener, owned by the caller, who closes it
   * @since 0.10.0
   */
  public ChunkedOpener chunkedOpener(byte[] header, byte[] fileId) {
    return handle.kms.call(
        "chunkedOpener",
        () -> {
          return current("chunkedOpener").chunkedOpener(header, fileId);
        });
  }

  /**
   * Moves a chunked file's header ({@link #chunkedSealer}) to the current key without touching the
   * chunks.
   *
   * <ul>
   *   <li>A header already under the key held is returned unchanged, the same array, without a
   *       request. It is not authenticated then. This lets a re-wrapping job be repeated.
   *   <li>A header under an older key of the lineage has its data key unwrapped and checked against
   *       the header's key commitment. The data key is then wrapped by the current key with the same
   *       additional data.
   * </ul>
   *
   * <p>Moving a header costs three requests. Each rotation crossed adds one Get Attributes.
   *
   * <p>The chunks depend on the data key, not on its wrapping. So they open with the new header as
   * they did with the old. The new header may differ in length, because key identifiers do.
   *
   * <p>Call {@link #refresh()} before a re-wrapping job, as for {@link #rewrapRecord}. After a
   * rotation, rewrite the headers, then retire the old keys ({@link KeyHandle#retirePredecessors}).
   * A refusal of the current key is followed and the call repeated.
   *
   * <p>This is for routine rotation. The data key stays the same. So after a compromise of a key
   * that wrapped it, seal the data again with a new sealer instead.
   *
   * @param header the file's header (not null)
   * @param fileId the file identifier it was sealed with (not null)
   * @return the header under the current key, or {@code header} itself when it is under the key
   *     held already
   * @throws CryptographicFailureException as for {@link #chunkedOpener}
   * @throws KeyMismatchException as for {@link #chunkedOpener}, or when the current key cannot
   *     decrypt what it would wrap (checked before anything is sent)
   * @throws StateConflictException as for {@link #chunkedOpener}, or as for {@link #seal}
   * @since 0.10.0
   */
  public byte[] rewrapHeader(byte[] header, byte[] fileId) {
    return following("rewrapHeader", h -> h.rewrapHeader(header, fileId));
  }

  /**
   * Moves a sealed record to the current key, and says whether it changed.
   *
   * <ul>
   *   <li>A record already under the key held is returned unchanged, the same array, without a
   *       request. It is not authenticated then, so {@link #open} it to check it.
   *   <li>A record under an older key of the lineage is opened and sealed again under the current
   *       key, with a fresh data key and the same additional data. The plaintext does not leave the
   *       SDK.
   * </ul>
   *
   * <p>Moving a record costs three requests: Get Attributes and Decrypt to open, and Encrypt to seal.
   * Each rotation crossed adds one Get Attributes.
   *
   * <p>After a rotation, call {@link #refresh()} first. A record under the key held is returned
   * unchanged even when that key was replaced since the last check. Then run this over the stored
   * records and write back the {@link Rewrapped#changed() changed} ones. The job can be repeated.
   * Retire the old keys afterwards with {@link KeyHandle#retirePredecessors}.
   *
   * <p>A refusal of the current key is followed and the call repeated. A record whose key is
   * Compromised is refused. Recover such records with {@link KeyHandle#rewrapTo} through {@link
   * KeyHandle#allowingCompromised()}.
   *
   * @param sealed the sealed record
   * @param aad the additional data given when sealing; null or empty for none
   * @return the record and whether it changed
   * @throws CryptographicFailureException as for {@link #open}; nothing is sealed then
   * @throws KeyMismatchException as for {@link #open}, or as for {@link #seal}
   * @throws StateConflictException as for {@link #open}, or as for {@link #seal}
   */
  public Rewrapped rewrapRecord(byte[] sealed, byte[] aad) {
    return following("rewrapRecord", h -> h.rewrapRecord(sealed, aad));
  }

  /** Tests only: whether any thread holds this object's lock. */
  boolean locked() {
    return lock.isLocked();
  }

  @Override
  public String toString() {
    return "CurrentKey[" + handle.id() + "]";
  }

  private interface Call<T> {
    T on(KeyHandle key);
  }

  /** {@code call} on the current key, repeated once after a refusal, all within one deadline. */
  private <T> T following(String operation, Call<T> call) {
    return handle.kms.call(
        operation,
        () -> {
          KeyHandle h = current(operation);
          try {
            return call.on(h);
          } catch (StateConflictException refused) {
            if (!about(refused, h)) throw refused;
            return call.on(refreshed(operation, h, refused));
          }
        });
  }

  /**
   * Whether {@code refused} is about the key held, not about another key (a record's Compromised
   * key, when re-sealing): only then can a newer key help.
   */
  private static boolean about(StateConflictException refused, KeyHandle h) {
    return refused.objectId().map(h.id()::equals).orElse(true);
  }

  /**
   * The key to repeat a call refused with {@code refused} under, after {@code seen} was refused: the
   * newer key another thread found already, or {@code seen.latest()} when it is another key and
   * Active. Throws {@code refused} when there is none, also when the deadline of the call {@code
   * operation} passes while it waits for another thread's check (the timeout suppressed on it).
   */
  private KeyHandle refreshed(String operation, KeyHandle seen, StateConflictException refused) {
    // A call refused inside a listener told with the lock held does not refresh again on this
    // thread: the refresh or check running here decides.
    if (lock.isHeldByCurrentThread()) throw refused;
    try {
      lock(operation);
    } catch (TransientException timedOut) {
      refused.addSuppressed(timedOut);
      throw refused;
    }
    StateChange change = null;
    try {
      if (!handle.id().equals(seen.id())) return handle;
      KeyAttributes newest;
      try {
        KeyHandle.Walk walk = seen.walk();
        change = observe(walk);
        newest = walk.newest();
      } catch (KmsException | IllegalStateException failed) {
        refused.addSuppressed(failed);
        throw refused;
      }
      failures = 0;
      checkedAt = nanos.getAsLong();
      if (!movable(newest)) throw refused;
      KeyHandle next = handle.handleOf(newest);
      hold(next);
      observed = newest.state();
      return next;
    } finally {
      lock.unlock();
      if (change != null) change.tell();
      tell();
    }
  }
}
