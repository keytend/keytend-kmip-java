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

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.*;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.util.*;

/**
 * A connection to a key management service, and the entry point of the application API. Get one
 * with {@link #connect(KmsConfig)}, which negotiates the KMIP version before it returns.
 *
 * <pre>{@code
 * try (Kms kms = Kms.connect(config)) {
 *   kms.keys().createAes(256).named("orders-kek")
 *       .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).findOrCreate();
 *   CurrentKey kek = kms.keys().current("orders-kek");
 *   byte[] sealed = kek.seal(orderJson, orderId);
 *   byte[] opened = kek.open(sealed, orderId);
 * }
 * }</pre>
 *
 * <p>{@code config} is a {@link KmsConfig}. {@code orderJson} is the record and {@code orderId} its
 * identifier, both {@code byte[]}.
 *
 * <p>Each call has one deadline, {@link KmsConfig.Builder#callTimeout} or {@link #withTimeout},
 * covering every attempt and back-off. Read-only operations are retried on the next endpoint as
 * the {@link RetryPolicy} says. Mutations are never re-sent. Every endpoint must offer the version
 * negotiated with the first. Failures are {@link KmsException} subtypes, apart from documented
 * argument checks.
 *
 * <p>A {@code Kms} is thread-safe. It owns its connections, and the caller closes it once. Calls
 * after {@link #close()}, and calls that race it, throw {@link IllegalStateException}, except a
 * renewal of the client certificate that has sent its request: {@link #close()} waits for that
 * one. A {@code Kms} keeps no thread of its own (see {@link #close()}). See <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/production.md#endpoints-and-failover">Endpoints
 * and failover</a>.
 *
 * @since 0.10.0
 */
public final class Kms implements AutoCloseable {
  /** How long a pooled connection waits for a reply at most; views cannot exceed it. */
  static final Duration TRANSPORT_READ_LIMIT = Duration.ofMinutes(10);

  /** The deadline of the application call the current thread is in, when it makes several requests. */
  private static final ThreadLocal<Long> SCOPE = new ThreadLocal<>();

  /**
   * The application call the current thread is in ({@link KmsListener#callStarted}): the outermost
   * {@link #call(String, CallBody)} (or one of its overloads), or a bare {@link #execute} outside
   * one; null outside all.
   */
  private static final ThreadLocal<Call> CALL = new ThreadLocal<>();

  /**
   * The check {@link #beforeSend} sets for the current thread's mutations, run just before each is
   * sent; null for none.
   */
  private static final ThreadLocal<java.util.function.BooleanSupplier> SEND_CHECK =
      new ThreadLocal<>();

  /** The last {@link KmsEvent#callId()} given, unique within the JVM. */
  private static final java.util.concurrent.atomic.AtomicLong CALL_IDS =
      new java.util.concurrent.atomic.AtomicLong();

  final KmsConfig config;
  private final Shared shared;
  private final ProtocolVersion version;
  private final Duration callTimeout;
  private final boolean view;
  private final KmsKeys keys;
  private final KmsTls tls;

  /** State shared by a {@code Kms} and its {@link #withTimeout} views. */
  private static final class Shared {
    final List<Endpoint> endpoints;
    volatile boolean closed;
    int current;

    /** findOrCreate calls running now, by what they find or create (single-flight): their identifiers. */
    final java.util.concurrent.ConcurrentMap<
            Object, java.util.concurrent.CompletableFuture<List<String>>>
        flights = new java.util.concurrent.ConcurrentHashMap<>();

    /** This machine's clock, for what is measured against server dates (a rotation's due time); tests set it. */
    volatile java.time.Clock clock = java.time.Clock.systemUTC();

    /** The TLS source when the configuration renews its client certificate; null otherwise. */
    ClientRenewal.Source renewal;

    /** The automatic renewal checks of this Kms; null without them. */
    volatile ClientRenewal.Auto autoRenewal;

    /** Whether {@link #close()} has been called. */
    final java.util.concurrent.atomic.AtomicBoolean closeCalled =
        new java.util.concurrent.atomic.AtomicBoolean();

    /**
     * The thread that runs the first {@link #close()} while it runs; null before and after, so a
     * closed {@code Kms} does not keep that thread (and its context class loader) reachable.
     */
    volatile Thread closer;

    /** Ends once the first {@link #close()} has returned. */
    final java.util.concurrent.CountDownLatch closeReturned =
        new java.util.concurrent.CountDownLatch(1);

    Shared(List<Endpoint> endpoints, int current) {
      this.endpoints = endpoints;
      this.current = current;
    }
  }

  private Kms(
      KmsConfig config,
      Shared shared,
      ProtocolVersion version,
      Duration callTimeout,
      boolean view) {
    this.config = config;
    this.shared = shared;
    this.version = version;
    this.callTimeout = callTimeout;
    this.view = view;
    this.keys = new KmsKeys(this);
    this.tls = new KmsTls(keys);
  }

  /**
   * Connects and negotiates the KMIP version. Endpoints are tried in order until one answers
   * Discover Versions, all within one {@link KmsConfig.Builder#callTimeout call timeout}.
   *
   * <p>An endpoint that is unreachable, or whose server certificate this client rejects, is
   * skipped. A server that refuses this client's credentials stops the connect at once, since every
   * replica would. Every endpoint but the last first gets only the {@link
   * RetryPolicy#attemptTimeout() attempt timeout}, and one that does not answer within it is
   * skipped. If no later endpoint connects, the skipped ones are tried again in order with the rest
   * of the deadline, so a slow but healthy first endpoint still connects. {@link
   * KmsListener#endpointUnavailable} hears of each endpoint that fails.
   *
   * <p>By default a failed connect is not retried. To start while the KMS is down, set {@link
   * KmsConfig.Builder#connectRetry(Duration)}.
   *
   * @param config the configuration
   * @return a connected {@code Kms}, owned by the caller, who closes it
   * @throws UnsupportedException when the server offers no version the policy accepts
   * @throws PermissionDeniedException when TLS or KMIP authentication fails
   * @throws TransientException when no endpoint could be reached (within {@link
   *     KmsConfig.Builder#connectRetry(Duration)}, when it is set)
   */
  public static Kms connect(KmsConfig config) {
    Objects.requireNonNull(config, "config");
    long window = nanos(config.connectRetry);
    if (window == 0) return connectOnce(config);
    long start = System.nanoTime();
    Deque<KmsException> earlier = new ArrayDeque<>();
    for (int attempt = 1; ; attempt++) {
      KmsException failed;
      try {
        return connectOnce(config);
      } catch (KmsException e) {
        failed = e;
      }
      boolean interrupted = interrupted(failed);
      long backoff = Math.max(nanos(config.retry.backoff(attempt)), CONNECT_BACKOFF_FLOOR);
      if (interrupted
          || failed.category() != KmsException.Category.RETRY
          || System.nanoTime() - start + backoff >= window) throw withEarlier(failed, earlier);
      try {
        java.util.concurrent.TimeUnit.NANOSECONDS.sleep(backoff);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw withEarlier(failed, earlier);
      }
      earlier.addLast(failed);
      if (earlier.size() > CONNECT_FAILURES_KEPT) earlier.removeFirst();
    }
  }

  /** The shortest back-off between connect attempts, so that {@link RetryPolicy#none()} does not spin. */
  static final long CONNECT_BACKOFF_FLOOR = java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(100);

  /** How many earlier connect attempts' failures are suppressed on the last one. */
  static final int CONNECT_FAILURES_KEPT = 16;

  /**
   * Whether the connect that failed with {@code failed} was interrupted: the thread's interrupt
   * flag, or an interrupt among its causes (whose flag a transport may have cleared: set again).
   */
  private static boolean interrupted(KmsException failed) {
    if (Thread.currentThread().isInterrupted()) return true;
    for (Throwable t = failed; t != null; t = t.getCause())
      if (t instanceof InterruptedException
          || t instanceof java.nio.channels.ClosedByInterruptException
          || (t instanceof java.io.InterruptedIOException
              && !(t instanceof java.net.SocketTimeoutException))) {
        Thread.currentThread().interrupt();
        return true;
      }
    return false;
  }

  private static KmsException withEarlier(KmsException last, Collection<KmsException> earlier) {
    for (KmsException e : earlier) last.addSuppressed(e);
    return last;
  }

  /** One connect attempt: every endpoint, within one call timeout (see {@link #connect}). */
  private static Kms connectOnce(KmsConfig config) {
    return connectOnce(config, CallContext.withTimeout(config.callTimeout));
  }

  /** Owned caches negotiate within their enclosing key-use deadline, including connect retries. */
  static Kms connectForCall(KmsConfig config, CallContext deadline) {
    long start = System.nanoTime(), window = nanos(config.connectRetry);
    Deque<KmsException> earlier = new ArrayDeque<>();
    for (int attempt = 1; ; attempt++) {
      KmsException failure;
      try {
        return connectOnce(config, deadline);
      } catch (KmsException e) {
        failure = e;
      }
      long backoff = Math.max(nanos(config.retry.backoff(attempt)), CONNECT_BACKOFF_FLOOR);
      if (window == 0
          || interrupted(failure)
          || deadline.isCancelled()
          || failure.category() != KmsException.Category.RETRY
          || deadline.remainingNanos() <= backoff
          || System.nanoTime() - start + backoff >= window) throw withEarlier(failure, earlier);
      try {
        java.util.concurrent.TimeUnit.NANOSECONDS.sleep(backoff);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw withEarlier(failure, earlier);
      }
      earlier.addLast(failure);
      if (earlier.size() > CONNECT_FAILURES_KEPT) earlier.removeFirst();
    }
  }

  private static Kms connectOnce(KmsConfig config, CallContext deadline) {
    List<Endpoint> endpoints = new ArrayList<>();
    // With reloadOnChange, each Kms watches the files itself, from the context build() made.
    TlsFiles.Reloading reloading =
        config.reloading != null ? config.reloading.start(e -> fire(config.listener, e)) : null;
    // A renewal of the client certificate switches every Kms of the configuration at once.
    ClientRenewal.Source renewal =
        config.renewal == null ? null : config.renewal.source(reloading, config.tls);
    java.util.function.Supplier<javax.net.ssl.SSLContext> tlsSource =
        renewal != null ? renewal : reloading != null ? reloading : config.tlsSource;
    for (KmsConfig.Endpoint e : config.endpoints) endpoints.add(new Endpoint(e, config, tlsSource));
    List<KmsException> failures = new ArrayList<>();
    long attemptLimit = config.retry.attemptNanos(config.callTimeout);
    // Endpoints cut off at the attempt timeout, in order: if every endpoint fails with time left,
    // each gets the rest of the deadline in turn.
    Deque<Integer> cutOff = new ArrayDeque<>();
    // An endpoint offering no acceptable version while a cut-off one may still answer: reported
    // only
    // if none connects.
    UnsupportedException unsupported = null;
    for (int step = 0; ; step++) {
      boolean resuming = step >= endpoints.size();
      if (resuming && (cutOff.isEmpty() || Thread.currentThread().isInterrupted())) break;
      int i = resuming ? cutOff.poll() : step;
      Endpoint endpoint = endpoints.get(i);
      Failures.Call call = new Failures.Call("connect", true, null, false);
      if (deadline.remainingNanos() <= 0 || deadline.isCancelled()) {
        if (!resuming)
          failures.add(
              new TransientException(
                  "connect: the call timeout ("
                      + config.callTimeout
                      + ") passed before "
                      + endpoint.label
                      + " was tried"
                      + (deadline.isCancelled() ? " (canceled)" : ""),
                  deadline.isCancelled()
                      ? new java.io.InterruptedIOException("Connection canceled")
                      : new java.net.SocketTimeoutException("Connection deadline exceeded"),
                  "connect",
                  null,
                  null,
                  null));
        break;
      }
      // A replica that accepts connections but does not answer must not use up the whole call
      // while a later endpoint may answer; one cut off that way and resumed gets the rest.
      boolean bounded =
          !resuming && i < endpoints.size() - 1 && attemptLimit < deadline.remainingNanos();
      try {
        CallContext context =
            bounded ? CallContext.withTimeout(Duration.ofNanos(attemptLimit)) : deadline;
        try (java.io.Closeable cancellation =
            bounded ? deadline.onCancel(context::cancel) : () -> {}) {
          ProtocolVersion version = endpoint.negotiate(context);
          Shared shared = new Shared(endpoints, i);
          shared.renewal = renewal;
          Kms kms = new Kms(config, shared, version, config.callTimeout, false);
          if (renewal != null) {
            config.renewal.opened();
            shared.autoRenewal = config.renewal.startAutomatic(kms, renewal);
          }
          return kms;
        }
      } catch (Exception e) {
        KmsException k = Failures.classify(call, null, e);
        if (k instanceof UnsupportedException u && !cutOff.isEmpty()) {
          if (unsupported == null) unsupported = u;
          failures.add(k);
          continue;
        }
        if (k instanceof UnsupportedException
            || (k instanceof PermissionDeniedException && !Failures.serverNotTrusted(e))) {
          for (Endpoint other : endpoints) other.close();
          throw config.renewal != null && k instanceof PermissionDeniedException denied
              ? config.renewal.connectRefused(denied)
              : k;
        }
        // Cut off by the attempt timeout: no answer in time, or a connection or handshake that the
        // attempt's deadline (not a shorter connect timeout) ended.
        if (bounded
            && (e instanceof java.net.SocketTimeoutException || cutShort(e, attemptLimit, config))
            && !Thread.currentThread().isInterrupted()) cutOff.add(i);
        // A local hold-up (a failing TLS context supplier, the deadline) says nothing about the
        // server.
        if (!(e instanceof RequestNotSentException notSent && notSent.local())) {
          endpoint.unavailable(k.getMessage());
        }
        failures.add(k);
      }
    }
    for (Endpoint other : endpoints) other.close();
    // Report the most specific failure: an endpoint offering no acceptable version, then a rejected
    // server certificate, outrank unreachability.
    KmsException report =
        unsupported != null
            ? unsupported
            : failures.stream()
                .filter(f -> f instanceof PermissionDeniedException)
                .findFirst()
                .orElse(failures.get(failures.size() - 1));
    for (KmsException f : failures) if (f != report) report.addSuppressed(f);
    throw report;
  }

  /**
   * The negotiated protocol version.
   *
   * @return the version negotiated by {@link #connect}
   */
  public KmipVersion version() {
    return KmipVersion.of(version);
  }

  ProtocolVersion protocolVersion() {
    return version;
  }

  /**
   * Keys, certificates and other managed objects.
   *
   * @return the object API of this {@code Kms}, the same object each time
   * @throws IllegalStateException when this {@code Kms} is closed
   */
  public KmsKeys keys() {
    ensureOpen();
    return keys;
  }

  /**
   * TLS identities, and followers of identities and trust anchors for JSSE key and trust managers.
   *
   * @return the TLS API of this {@code Kms}, the same object each time
   * @throws IllegalStateException when this {@code Kms} is closed
   * @since 0.10.0
   */
  public KmsTls tls() {
    ensureOpen();
    return tls;
  }

  /**
   * A view of this {@code Kms} whose calls have {@code timeout} as their deadline instead of the
   * configured call timeout. The view shares the connections, endpoints and version, and handles
   * obtained through it use its timeout. Closing the view does nothing, and it stops working when
   * this {@code Kms} is closed.
   *
   * <p>A timeout in a view shorter than the call timeout does not count against the endpoint, so
   * traffic stays where it is. Once an endpoint has left requests unanswered for a whole configured
   * call timeout, the next timeout counts and traffic moves to the next endpoint. Any answer from
   * the endpoint, also a failure such as Not Found, starts that record again.
   *
   * <pre>{@code
   * KeyHandle key = kms.withTimeout(Duration.ofSeconds(2)).keys().handle(keyId);
   * }</pre>
   *
   * @param timeout the deadline of each call made through the view: positive, and at most the
   *     larger of the call timeout and 10 minutes (how long a pooled connection waits for a reply)
   * @return the view; closing it does nothing
   * @throws IllegalArgumentException when {@code timeout} is not positive or is above that limit
   */
  public Kms withTimeout(Duration timeout) {
    Objects.requireNonNull(timeout, "timeout");
    if (timeout.isNegative() || timeout.isZero())
      throw new IllegalArgumentException("Timeout must be positive");
    if (timeout.compareTo(readLimit(config)) > 0)
      throw new IllegalArgumentException("A view's timeout is at most " + readLimit(config));
    ensureOpen();
    return new Kms(config, shared, version, timeout, true);
  }

  static Duration readLimit(KmsConfig config) {
    return config.callTimeout.compareTo(TRANSPORT_READ_LIMIT) > 0
        ? config.callTimeout
        : TRANSPORT_READ_LIMIT;
  }

  /**
   * What a public method does inside its application call ({@link #call(String, CallBody)}).
   *
   * @param <T> what it returns
   * @param <X> the checked exception it throws, if any
   */
  @FunctionalInterface
  interface CallBody<T, X extends Throwable> {
    T run() throws X;
  }

  /**
   * A {@link CallBody} that returns nothing.
   *
   * @param <X> the checked exception it throws, if any
   */
  @FunctionalInterface
  interface VoidBody<X extends Throwable> {
    void run() throws X;
  }

  /**
   * Runs {@code body} as the application call {@code operation} ({@link KmsListener#callStarted})
   * under one deadline, this {@code Kms}'s call timeout. This, its overloads and a bare {@link
   * #execute} (a call of one step, named after it) are the only ways a call opens, so every call is
   * named when it opens and its attempts carry that name; and its outcome is decided here: SUCCEEDED
   * when {@code body} returns, FAILED with what it threw when it throws. Inside a call already,
   * {@code body} is part of that call, under its name and deadline.
   */
  <T, X extends Throwable> T call(String operation, CallBody<T, X> body) throws X {
    return open(deadlineIn(callTimeout), false, operation, body);
  }

  /** {@link #call(String, CallBody)} of a method that returns nothing. */
  <X extends Throwable> void run(String operation, VoidBody<X> body) throws X {
    open(deadlineIn(callTimeout), false, operation, voidBody(body));
  }

  /** {@link #call(String, CallBody)} before a lazy cache owns a connected KMS, under {@code timeout}. */
  static <T, X extends Throwable> T call(Duration timeout, String operation, CallBody<T, X> body)
      throws X {
    return open(deadlineIn(timeout), false, operation, body);
  }

  /** {@link #call(Duration, String, CallBody)} of a method that returns nothing. */
  static <X extends Throwable> void run(Duration timeout, String operation, VoidBody<X> body)
      throws X {
    open(deadlineIn(timeout), false, operation, voidBody(body));
  }

  /**
   * {@link #call(String, CallBody)} under the absolute {@code deadline} ({@link System#nanoTime()}),
   * or an enclosing call's when that is earlier; the enclosing deadline is restored afterwards.
   */
  <T, X extends Throwable> T call(long deadline, String operation, CallBody<T, X> body) throws X {
    return open(deadline, true, operation, body);
  }

  /**
   * {@link #call(String, CallBody)} without a deadline of its own: each request has the call
   * timeout of the {@code Kms} that sends it (a method of one request after a local step, say).
   */
  static <T, X extends Throwable> T named(String operation, CallBody<T, X> body) throws X {
    return open(null, false, operation, body);
  }

  /** {@link #named(String, CallBody)} of a method that returns nothing. */
  static <X extends Throwable> void runNamed(String operation, VoidBody<X> body) throws X {
    open(null, false, operation, voidBody(body));
  }

  /**
   * Background work as the call {@code operation}, under {@code timeout}: work whose failure is
   * told rather than thrown ({@link KmsListener#currentKeyCheckFailed}) returns it, and the call is
   * FAILED with it; null when the work succeeded. What {@code work} throws is thrown, the call
   * FAILED with it.
   */
  static void background(
      Duration timeout, String operation, java.util.function.Supplier<? extends Throwable> work) {
    background(deadlineIn(timeout), false, operation, work);
  }

  /**
   * {@link #background(Duration, String, java.util.function.Supplier)} under the absolute {@code
   * deadline} ({@link System#nanoTime()}), or an enclosing call's when that is earlier.
   */
  static void background(
      long deadline, String operation, java.util.function.Supplier<? extends Throwable> work) {
    background(deadline, true, operation, work);
  }

  private static void background(
      long deadline,
      boolean narrow,
      String operation,
      java.util.function.Supplier<? extends Throwable> work) {
    boolean opens = CALL.get() == null;
    open(
        deadline,
        narrow,
        operation,
        () -> {
          Throwable failed = work.get();
          if (failed != null && opens) CALL.get().thrown = failed;
          return null;
        });
  }

  private static <X extends Throwable> CallBody<Void, X> voidBody(VoidBody<X> body) {
    return () -> {
      body.run();
      return null;
    };
  }

  /** The deadline {@code timeout} from now. */
  private static long deadlineIn(Duration timeout) {
    return System.nanoTime() + Math.min(nanos(timeout), Long.MAX_VALUE / 4);
  }

  /**
   * Runs {@code body} in the application call {@code operation}, which it opens unless the thread
   * is in one already. {@code deadline} (null for none) is set when no deadline is, or, when {@code
   * narrow}, when it is earlier than the one set; the previous one is restored afterwards.
   */
  private static <T, X extends Throwable> T open(
      Long deadline, boolean narrow, String operation, CallBody<T, X> body) throws X {
    Objects.requireNonNull(operation, "operation");
    Long outer = SCOPE.get();
    boolean deadlineSet = deadline != null && (outer == null || (narrow && deadline - outer < 0));
    if (deadlineSet) SCOPE.set(deadline);
    Call call = null;
    if (CALL.get() == null) {
      call = new Call(operation);
      CALL.set(call);
    }
    try {
      return body.run();
    } catch (Throwable thrown) {
      if (call != null) call.thrown = thrown;
      throw thrown;
    } finally {
      if (deadlineSet) {
        if (outer == null) SCOPE.remove();
        else SCOPE.set(outer);
      }
      if (call != null) {
        CALL.remove();
        call.finish();
      }
    }
  }

  /** What is left of the current call's deadline: the scope's, else a whole call timeout. */
  long remainingNanos() {
    return callRemaining(callTimeout);
  }

  /**
   * A context with the current call's deadline when the thread is in one, else {@code timeout} from
   * now.
   */
  static CallContext callContext(Duration timeout) {
    Long scoped = SCOPE.get();
    return scoped != null
        ? CallContext.withDeadline(scoped)
        : CallContext.withTimeout(Duration.ofNanos(Math.min(nanos(timeout), Long.MAX_VALUE / 4)));
  }

  /** Remaining budget before a lazy cache has connected. */
  static long callRemaining(Duration timeout) {
    Long scoped = SCOPE.get();
    return scoped != null
        ? scoped - System.nanoTime()
        : Math.min(nanos(timeout), Long.MAX_VALUE / 4);
  }

  /** The {@link KmsKeys#singleFlight} registry, shared with this {@code Kms}'s views. */
  java.util.concurrent.ConcurrentMap<Object, java.util.concurrent.CompletableFuture<List<String>>>
      flights() {
    return shared.flights;
  }

  /**
   * One application call, for {@link KmsListener#callStarted} and {@link
   * KmsListener#callFinished}: named when it opens ({@link #call(String, CallBody)}, or a bare
   * {@link #execute} named after its step), started at its first attempt (a call that sends nothing
   * is never told), finished when it ends, with what it threw to the application, if anything.
   * Used by its own thread only.
   */
  static final class Call {
    /** From {@link #CALL_IDS}; 0 until the first attempt. */
    long id;

    /** The method the application called: the name of the call and of each of its attempts. */
    final String operation;

    private long start;
    private int attempts;
    private String endpoint, objectId;
    private KmipVersion version;

    /** What the call threw to the application; null when it returned. */
    private Throwable thrown;

    /**
     * The call's {@link KmsListener#callStarted} event, made at its first attempt: every listener
     * hears this one, also one first reached by a later attempt through another configuration.
     */
    private KmsEvent started;

    /**
     * The listeners told {@link KmsListener#callStarted}, each once by identity: a call may use
     * {@code Kms} instances of several configurations, which may share listeners (the SDK's
     * logging always).
     */
    private final List<KmsListener> told = new ArrayList<>(4);

    Call(String operation) {
      this.operation = operation;
    }

    /** An attempt of this call is about to be sent through {@code kms}: starts the call first. */
    void attempt(Kms kms, Endpoint endpoint, String objectId, long now) {
      if (id == 0) {
        id = CALL_IDS.incrementAndGet();
        start = now;
      }
      attempts++;
      this.endpoint = endpoint.label;
      this.version = KmipVersion.of(kms.version);
      if (this.objectId == null) this.objectId = objectId;
      if (started == null) started = event(KmsEvent.Outcome.STARTED, now);
      KmsEvent event = started;
      for (KmsListener listener : kms.config.callListeners) {
        if (toldAlready(listener)) continue;
        told.add(listener);
        fire(listener, l -> l.callStarted(event));
      }
    }

    private boolean toldAlready(KmsListener listener) {
      for (KmsListener l : told) if (l == listener) return true;
      return false;
    }

    /** Tells the listeners that the call finished, if it started. */
    void finish() {
      if (id == 0) return;
      KmsEvent finished =
          event(
              thrown == null ? KmsEvent.Outcome.SUCCEEDED : KmsEvent.Outcome.FAILED,
              System.nanoTime());
      for (KmsListener listener : told) fire(listener, l -> l.callFinished(finished));
    }

    private KmsEvent event(KmsEvent.Outcome outcome, long now) {
      return new KmsEvent(
          KmsEvent.Kind.CALL,
          id,
          operation,
          operation,
          endpoint,
          outcome == KmsEvent.Outcome.STARTED ? 0 : attempts,
          version,
          objectId,
          Duration.ofNanos(outcome == KmsEvent.Outcome.STARTED ? 0 : now - start),
          outcome,
          outcome == KmsEvent.Outcome.FAILED && thrown instanceof KmsException k ? k : null);
    }
  }

  /** {@code inner}, or the name of the application call the current thread is in. */
  static String named(String inner) {
    Call call = CALL.get();
    return call != null ? call.operation : inner;
  }

  /**
   * The deadline of each call made through this {@code Kms}.
   *
   * @return the deadline of each call
   */
  public Duration callTimeout() {
    return callTimeout;
  }

  /**
   * {@code length} random bytes from the server's generator (RNG Retrieve, KMIP 1.2+).
   *
   * @param length the number of bytes, at least 1
   * @return a new array of {@code length} bytes
   * @throws ProtocolViolationException when the server returns another number of bytes
   * @throws IllegalArgumentException when {@code length} is less than 1
   */
  public byte[] random(int length) {
    if (length < 1) throw new IllegalArgumentException("Length must be positive");
    Request request = CryptoRequests.rngRetrieve(length);
    return execute(
        "random",
        Kind.READ_CRYPTO,
        null,
        s -> {
          byte[] data = CryptoResult.of(s.call(request)).data().orElseThrow(() -> missing("Data"));
          if (data.length != length)
            throw new ProtocolException(
                "RNG Retrieve returned " + data.length + " bytes, not " + length, null, null);
          return data;
        });
  }

  /**
   * A readiness check that needs no key: one Discover Versions request, which every KMIP server
   * answers to an authenticated client. It is retried and failed over like any read, and reported
   * to the {@link KmsListener} as operation {@code "ping"}. Give a probe's {@link #withTimeout}
   * deadline more than the {@link RetryPolicy#attemptTimeout() attempt timeout}. A shorter one
   * moves no traffic, so it reports not-ready while the current endpoint hangs instead of trying
   * the next. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/production.md#readiness">Readiness</a>.
   *
   * @throws TransientException when no endpoint answers
   * @throws PermissionDeniedException when the server refuses this client
   */
  public void ping() {
    Request request = Requests.discoverVersions().build();
    execute(
        "ping",
        Kind.READ,
        null,
        s -> {
          s.call(request);
          return null;
        });
  }

  /**
   * The protocol versions the server offers, in its order of preference (Discover Versions), such
   * as {@code ["2.1", "2.0", "1.4"]}. A version this SDK does not know is listed too. A read:
   * retried and failed over, and reported to the {@link KmsListener} as {@code "serverVersions"}.
   *
   * @return the versions, {@code major.minor}; unmodifiable
   * @throws TransientException when no endpoint answers
   * @throws ProtocolViolationException when the reply is malformed
   * @since 0.10.0
   */
  public List<String> serverVersions() {
    Request request = Requests.discoverVersions().build();
    return execute(
        "serverVersions",
        Kind.READ,
        null,
        s -> {
          Result result = s.call(request);
          List<String> out = new ArrayList<>();
          try {
            for (Ttlv v :
                result.payload().map(p -> p.children(Tag.PROTOCOL_VERSION)).orElse(List.of()))
              out.add(
                  v.require(Tag.PROTOCOL_VERSION_MAJOR).intValue()
                      + "."
                      + v.require(Tag.PROTOCOL_VERSION_MINOR).intValue());
          } catch (IllegalArgumentException | IllegalStateException e) {
            throw new ProtocolException(
                "Malformed Discover Versions response", result.batchItem(), null);
          }
          return List.copyOf(out);
        });
  }

  /**
   * What the server says about itself: one Query for its operations, object types and server
   * information ({@link ServerInfo}). For diagnostics; a server may implement less than it lists.
   * A read: retried and failed over, and reported to the {@link KmsListener} as {@code
   * "serverInfo"}.
   *
   * @return the server's answer
   * @throws UnsupportedException when the server does not implement Query
   * @throws TransientException when no endpoint answers
   * @since 0.10.0
   */
  public ServerInfo serverInfo() {
    Request request =
        Requests.query()
            .add(
                Ttlv.enumeration(Tag.QUERY_FUNCTION, Enums.QueryFunction.QUERY_OPERATIONS),
                Ttlv.enumeration(Tag.QUERY_FUNCTION, Enums.QueryFunction.QUERY_OBJECTS),
                Ttlv.enumeration(Tag.QUERY_FUNCTION, Enums.QueryFunction.QUERY_SERVER_INFORMATION))
            .build();
    return execute(
        "serverInfo",
        Kind.READ,
        null,
        s -> {
          Result result = s.call(request);
          String vendor = null;
          Map<String, List<String>> information = new LinkedHashMap<>();
          List<String> operations = new ArrayList<>(), objects = new ArrayList<>();
          for (Ttlv child : result.payload().map(Ttlv::children).orElse(List.of())) {
            if (child.tag() == Tag.OPERATION.code() && child.type() == Ttlv.Type.ENUMERATION)
              operations.add(wireName(Operation.class, child.intValue()));
            else if (child.tag() == Tag.OBJECT_TYPE.code() && child.type() == Ttlv.Type.ENUMERATION)
              objects.add(wireName(Enums.ObjectType.class, child.intValue()));
            else if (child.tag() == Tag.VENDOR_IDENTIFICATION.code()
                && child.type() == Ttlv.Type.TEXT_STRING
                && vendor == null) vendor = child.textValue();
            else if (child.tag() == Tag.SERVER_INFORMATION.code()
                && child.type() == Ttlv.Type.STRUCTURE) flatten(child, "", information);
          }
          return new ServerInfo(vendor, information, operations, objects);
        });
  }

  private static <E extends Enum<E> & WireEnum> String wireName(Class<E> type, int code) {
    return WireEnums.fromCode(type, code)
        .map(WireEnum::wireName)
        .orElse(String.format(java.util.Locale.ROOT, "0x%08X", code));
  }

  /** The leaves of {@code node} as {@code path -> values}, in order. */
  private static void flatten(Ttlv node, String prefix, Map<String, List<String>> out) {
    for (Ttlv child : node.children()) {
      String key = prefix.isEmpty() ? child.tagName() : prefix + "." + child.tagName();
      String value;
      if (child.type() == Ttlv.Type.STRUCTURE) {
        flatten(child, key, out);
        continue;
      } else if (child.type() == Ttlv.Type.TEXT_STRING) value = child.textValue();
      else if (child.type() == Ttlv.Type.BYTE_STRING) value = "(" + child.byteLength() + " bytes)";
      else value = String.valueOf(child.value());
      out.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
    }
  }

  /**
   * A protocol-layer client for operations this API does not cover. It talks to the current
   * endpoint at the negotiated version, and does not fail over or retry.
   *
   * <p>It does not own the connection. Closing it does nothing, and it stops working when this
   * {@code Kms} is closed.
   *
   * <p>Each call that has no deadline of its own is bounded by {@link #callTimeout()}: one without a
   * {@link CallContext}, or with one that has no deadline, such as {@code
   * CallContext.cancellable()}, which can still be canceled. Pass {@code
   * CallContext.withTimeout(...)} for another bound.
   *
   * @return a non-owning client
   */
  public KmipClient protocol() {
    ensureOpen();
    try {
      return pick().bounded(version, CallContext.withTimeout(callTimeout), callTimeout);
    } catch (Exception e) {
      if (shared.closed) throw new IllegalStateException("Kms is closed");
      throw Failures.classify(new Failures.Call("protocol", true, null, false), version, e);
    }
  }

  /**
   * Renews this client's own TLS certificate now, through KMIP Re-Provision, as {@link
   * KmsConfig.Builder#clientCertificateRenewal} sets it up. The SDK makes a new key pair like the
   * current one, writes the private key beside the key file ({@code <key file>.renewal}) before it
   * sends anything, and sends a PKCS#10 request on a connection authenticated with the current
   * certificate. The server retires the current certificate when it issues the new one, so the SDK
   * refuses the new one only when it cannot serve as this client's TLS certificate now: another
   * key, another subject or subjectAltName, expired, a CA, or a key usage or extended key usage
   * that excludes client authentication. What the server judges by its own clock or policy (the
   * period, a notBefore ahead of this machine's clock, an issuer signature this client cannot
   * verify) is reported with {@link KmsListener#clientCertificateRenewalWarning}. The SDK then uses
   * the certificate for new connections of every {@code Kms} of this configuration and writes it
   * to the configured files. Connections opened with the old certificate finish the request they
   * carry and then close; none is cut off. The server refuses the old certificate on new
   * connections from then on.
   *
   * <p>Repeating the call after one that stopped is safe: it finishes an earlier renewal whose
   * certificate the server issued, or starts again with the key the earlier one wrote. When the
   * server refuses the current certificate on new connections by then, the SDK looks for the new
   * certificate through the connections this {@code Kms} still has open on it. When the SDK
   * cannot tell whether the server issued the certificate, or the server issued one the SDK
   * refuses, the client may be locked out: the {@link OutcomeUnknownException} says what is on
   * disk and how to recover. Renewals of the same files take turns, in this process and with
   * other processes (a lock file beside the pending file). See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/production.md#renew-the-client-certificate">Renew
   * the client certificate</a>.
   *
   * @return the renewal
   * @throws IllegalStateException when the configuration has no {@code clientCertificateRenewal},
   *     or this {@code Kms} is closed, or closes before the request is sent (see {@link #close()})
   * @throws UnsupportedException before anything is sent, when the connection uses KMIP 1.x or the
   *     current key is neither RSA nor EC; when the server does not offer Re-Provision; and when
   *     a validity period is asked for ({@link CertificateRenewal#validFor}) and the server does
   *     not take it: it refused the whole message, and issued nothing
   * @throws InvalidRequestException when the server refuses the request, such as a validity
   *     period that ends after its provisioning CA's notAfter; it issued nothing
   * @throws PermissionDeniedException when the server refuses the current certificate or the
   *     request, or its policy does not allow the search for a certificate the server may have
   *     issued to an earlier attempt (Locate and Get). When the key of an earlier attempt may
   *     still be issued a certificate, the message names the file it was moved to. When the server
   *     refuses the request with Permission Denied and earlier attempts moved keys aside, the SDK
   *     first looks for a certificate issued for them, and finishes the renewal with one it finds
   * @throws TransientException when nothing changed and a later call may succeed: the server could
   *     not be reached, another renewal of these files is running (in this process or another),
   *     or a reply was lost and the server had issued nothing when the SDK looked
   * @throws OutcomeUnknownException when the client may be locked out: the SDK cannot tell whether
   *     the server issued the certificate, or the server issued one the SDK refuses (then its
   *     cause is a {@link ProtocolViolationException} that says why)
   * @throws KmsException for another refusal by the server
   * @throws RenewalNotSavedException when the server issued the certificate and this process uses
   *     it, but writing it to the files failed: it carries the certificate; call again once the
   *     cause is fixed
   * @throws IOException when the identity files or the pending file cannot be read or written
   *     before anything is issued
   * @since 0.10.0
   */
  public RenewedCertificate renewClientCertificate() throws IOException {
    ensureOpen();
    ClientRenewal.Source source = shared.renewal;
    if (source == null)
      throw new IllegalStateException(
          "renewClientCertificate() needs KmsConfig.Builder.clientCertificateRenewal(...)");
    return config.renewal.renew(this, source);
  }

  /**
   * Closes the connections. A {@link #withTimeout} view's {@code close()} does nothing.
   *
   * <p>The first call closes. A later call from another thread returns once the first has
   * returned, so the guarantees below of a returned {@code close()} hold for each of them. A call
   * made inside the first (from a listener it tells, such as {@link
   * KmsListener#clientCertificateRenewalWarning}) or on a renewal's thread returns at once: it
   * neither waits nor reports again. An interrupt ends a later call's wait, with the thread's
   * interrupt status set.
   *
   * <p>The SDK's helper threads are daemons in its own {@code keytend-kmip} thread group, with no
   * context class loader. A shared transport watchdog ends a second after the last exchange. An
   * HTTPS transport's own threads end with this call (on JDK 17 the HTTP client's selector thread
   * ends once the client is unreachable). {@link LocalKeys}'s default refresh worker ends with the
   * cache. {@link CurrentKey#refreshingEvery} and the TLS followers run on the executor the caller
   * passes, which stays the caller's to shut down.
   *
   * <p>With {@link KmsConfig.Builder#clientCertificateRenewal}, this call first stops this {@code
   * Kms}'s automatic renewal. A renewal of the client certificate, on demand or automatic, that has
   * not sent its request yet sends nothing: it deletes the new key it wrote and fails with {@link
   * IllegalStateException} (a key an earlier attempt sent stays in the pending file). A renewal
   * that has sent Re-Provision, or is finishing one the server issued, is waited for until it ends:
   * the new certificate is then in the files, or the SDK concluded that the server issued none.
   * The wait lasts three times the call timeout the renewal uses at most: the reply, then the
   * search after a lost reply and the writes. That is the {@link KmsConfig.Builder#callTimeout call
   * timeout}, or for a renewal through a {@link #withTimeout} view the view's when it is longer;
   * with several renewals, the longest of them. Closing the last open {@code Kms} of a
   * configuration waits for the renewals of every {@code Kms} of it. When the wait runs out, this
   * call returns, after {@link KmsListener#clientCertificateRenewalWarning} says what is on disk
   * and how the next start recovers; the renewal goes on in its thread. A call on the renewal's own
   * thread (from a listener, say) does not wait for it. After this call returns, no listener is
   * called with an event of a renewal of this {@code Kms}: one that outlives it reports to the
   * SDK's log only. The renewal looks before each listener it calls, so a listener that closes the
   * {@code Kms} keeps its event from the listeners after it. A listener already running its
   * callback when the wait runs out finishes it after this call returns.
   * The renewal threads are daemons: a process that exits without this call ({@code System.exit},
   * a kill) stops a renewal where it is. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/production.md#renew-the-client-certificate">Renew
   * the client certificate</a> for how the next start recovers.
   */
  @Override
  public void close() {
    if (view) return;
    if (!shared.closeCalled.compareAndSet(false, true)) {
      awaitFirstClose();
      return;
    }
    shared.closer = Thread.currentThread();
    try {
      ClientRenewal.Auto auto = shared.autoRenewal;
      if (auto != null) auto.stop();
      // A renewal that sent its request is waited for before the connections it may search
      // through close.
      if (config.renewal != null) config.renewal.close(this, () -> shared.closed = true);
      else shared.closed = true;
      for (Endpoint e : shared.endpoints) e.close();
    } finally {
      shared.closeReturned.countDown();
      shared.closer = null;
    }
  }

  /**
   * A {@link #close()} after the first: waits until the first returns, unless it has returned, or
   * this thread runs the first (a listener the first close tells) or a renewal of this
   * configuration (which the first close may be waiting for). An interrupt ends the wait, and the
   * thread's interrupt status stays set.
   */
  private void awaitFirstClose() {
    if (shared.closeReturned.getCount() == 0) return;
    if (shared.closer == Thread.currentThread()) return;
    if (config.renewal != null && config.renewal.onRenewalThread()) return;
    try {
      shared.closeReturned.await();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  @Override
  public String toString() {
    return "Kms["
        + config.endpoints
        + ", KMIP "
        + version
        + (view ? ", view, timeout " + callTimeout : "")
        + "]";
  }

  /**
   * The connections of each configured endpoint, in configured order, for metrics: read from
   * memory, no request. A view reports those of the {@code Kms} it was made from, which it shares.
   * Also after {@link #close()}: the totals stay, nothing is open.
   *
   * <p>The counts come from the SDK's TLS transport ({@link dev.keytend.kmip.transport.TlsTransport}),
   * the default, also when a {@link KmsConfig.TransportFactory} returns one. An endpoint whose
   * transport is another kind ({@link dev.keytend.kmip.transport.HttpsTransport}, the in-memory
   * test server, an application's own) has no counts to report: {@link
   * ConnectionStats#measured()} is false and every count is zero.
   *
   * @return one entry per configured endpoint; unmodifiable
   * @since 0.10.0
   */
  public List<ConnectionStats> connectionStats() {
    List<ConnectionStats> out = new ArrayList<>(shared.endpoints.size());
    for (Endpoint e : shared.endpoints) out.add(e.stats());
    return Collections.unmodifiableList(out);
  }

  /**
   * {@link #connectionStats()} of a {@code Kms} of {@code config} that is not connected yet: every
   * configured endpoint, nothing opened ({@link LocalKeys.SharedKms#connectionStats()}).
   */
  static List<ConnectionStats> unconnectedStats(KmsConfig config) {
    List<ConnectionStats> out = new ArrayList<>(config.endpoints.size());
    for (KmsConfig.Endpoint e : config.endpoints)
      out.add(
          new ConnectionStats(
              e.toString(), config.transport == null, 0, 0, 0, 0, 0, Duration.ZERO));
    return Collections.unmodifiableList(out);
  }

  /**
   * One endpoint's connections ({@link Kms#connectionStats()}): SDK-owned values, read from memory,
   * cheap enough to poll. {@link #open()}, {@link #idle()} and {@link #inUse()} are a snapshot,
   * the others only grow. The counts of one endpoint add up those of every transport the {@code
   * Kms} opened to it (one, normally; also those it opened to probe the endpoint and closed). Only
   * the SDK creates them. Immutable.
   *
   * @since 0.10.0
   */
  public static final class ConnectionStats {
    private final String endpoint;
    private final boolean measured;
    private final int open, idle, inUse;
    private final long opened, poolWaits;
    private final Duration poolWaitTime;

    ConnectionStats(
        String endpoint,
        boolean measured,
        int open,
        int idle,
        int inUse,
        long opened,
        long poolWaits,
        Duration poolWaitTime) {
      this.endpoint = endpoint;
      this.measured = measured;
      this.open = open;
      this.idle = idle;
      this.inUse = inUse;
      this.opened = opened;
      this.poolWaits = poolWaits;
      this.poolWaitTime = poolWaitTime;
    }

    /**
     * The endpoint, as configured and as {@link KmsEvent#endpoint()} names it.
     *
     * @return its {@code host:port}
     */
    public String endpoint() {
      return endpoint;
    }

    /**
     * Whether the endpoint's transport reports these counts: the SDK's TLS transport does. False
     * for another transport (every count is then zero).
     *
     * @return whether the counts are measured
     */
    public boolean measured() {
      return measured;
    }

    /**
     * Connections open now: idle in the pool, in use by an exchange, or being opened.
     *
     * @return the number open
     */
    public int open() {
      return open;
    }

    /**
     * Pooled connections open and waiting for an exchange ({@link KmsConfig.Builder#poolSize}).
     *
     * @return the number idle
     */
    public int idle() {
      return idle;
    }

    /**
     * Connections in use by an exchange now (or being opened for one): {@link #open()} less
     * {@link #idle()}.
     *
     * @return the number in use
     */
    public int inUse() {
      return inUse;
    }

    /**
     * Connections opened so far, each one a TCP connection and a TLS handshake.
     *
     * @return the number opened
     */
    public long opened() {
      return opened;
    }

    /**
     * Exchanges so far that found every pooled connection busy and waited for one, however the
     * wait ended.
     *
     * @return the number of waits
     */
    public long poolWaits() {
      return poolWaits;
    }

    /**
     * How long the exchanges counted by {@link #poolWaits()} waited, in all.
     *
     * @return the total wait
     */
    public Duration poolWaitTime() {
      return poolWaitTime;
    }

    @Override
    public String toString() {
      return "ConnectionStats["
          + endpoint
          + (measured ? "" : ", not measured")
          + ", open "
          + open
          + ", idle "
          + idle
          + ", in use "
          + inUse
          + ", opened "
          + opened
          + ", pool waits "
          + poolWaits
          + " ("
          + poolWaitTime.toMillis()
          + " ms)]";
    }
  }

  /** The {@code Kms} that owns the connections (itself, or the one a view was made from). */
  Object owner() {
    return shared;
  }

  /** Now, by this machine's clock (or the one a test set with {@link #clock(java.time.Clock)}). */
  java.time.Instant now() {
    return shared.clock.instant();
  }

  /** For tests in this package: the clock {@link #now()} reads, for this {@code Kms} and its views. */
  void clock(java.time.Clock clock) {
    shared.clock = Objects.requireNonNull(clock, "clock");
  }

  // ---- execution ----

  enum Kind {
    /** Get, Locate, Get Attributes, Query, Discover Versions, Obtain Lease: always retryable. */
    READ,
    /** Encrypt, Decrypt, Sign, Verify, MAC, RNG: retryable unless the policy disables it. */
    READ_CRYPTO,
    /** Everything that changes server state: never re-sent. */
    MUTATION
  }

  @FunctionalInterface
  interface GetReader<T> {
    T read(dev.keytend.kmip.model.Ttlv payload) throws IOException, GeneralSecurityException;
  }

  @FunctionalInterface
  interface Body<T> {
    T run(Session session) throws IOException, GeneralSecurityException;
  }

  /** One attempt: the endpoint's client and the call's remaining deadline. */
  static final class Session {
    private final KmipClient client;
    private final CallContext context;
    private final ProtocolVersion version;

    /** Whether the endpoint answered with a valid response, successful or not. */
    private boolean answered;

    Session(KmipClient client, CallContext context, ProtocolVersion version) {
      this.client = client;
      this.context = context;
      this.version = version;
    }

    /** Sends one request; a request the version cannot express fails before anything is sent. */
    Result call(Request request) throws IOException {
      Request checked = checked(version, request);
      try {
        Result result = client.call(checked, context);
        answered = true;
        return result;
      } catch (KmipException failure) {
        answered = true; // a failure result is an answer too
        throw failure;
      }
    }

    /** Sends a batch (each request checked as above). */
    Response batch(List<Request> requests, RequestOptions options) throws IOException {
      for (Request r : requests) checked(version, r);
      try {
        Response response = client.batch(requests, options, context);
        answered = true;
        return response;
      } catch (KmipException failure) {
        answered = true;
        throw failure;
      }
    }
  }

  /**
   * The explicit capability check: the operation and every field of the payload must exist in
   * {@code version}. Anything else raised later is not reported as unsupported.
   */
  static Request checked(ProtocolVersion version, Request request) {
    if (request.operation() == null) return request;
    try {
      request.operation().requireVersion(version);
      VersionValidator.validate(
          version, VersionedPayloads.prepare(version, request.operation(), request.payload()));
    } catch (IllegalArgumentException e) {
      throw new NotExpressible(e.getMessage());
    }
    return request;
  }

  /** A request the negotiated version cannot express; becomes {@link UnsupportedException}. */
  static final class NotExpressible extends RuntimeException {
    NotExpressible(String message) {
      super(message, null, false, false);
    }
  }

  /**
   * Runs {@code mutations}, each of whose attempts to send a mutation first runs {@code check}:
   * after the attempt's {@link KmsListener#started} callbacks and its deadline check, just before
   * the request goes to the transport (which then takes a connection and sends it). When {@code
   * check} returns false, the attempt sends nothing and fails with {@link Withheld}. Reads are not
   * checked, nor is what a listener callback sends ({@link #outsideCall}).
   */
  static void beforeSend(java.util.function.BooleanSupplier check, Runnable mutations) {
    java.util.function.BooleanSupplier outer = SEND_CHECK.get();
    SEND_CHECK.set(Objects.requireNonNull(check, "check"));
    try {
      mutations.run();
    } finally {
      if (outer == null) SEND_CHECK.remove();
      else SEND_CHECK.set(outer);
    }
  }

  /** A mutation that its {@link #beforeSend} check kept from being sent: nothing was sent. */
  static final class Withheld extends RuntimeException {
    Withheld() {
      super(
          "The request was withheld by the check before its send; nothing was sent",
          null,
          false,
          false);
    }
  }

  /** An SDK-owned multi-request operation was superseded; do not retry or fall back. */
  static final class Superseded extends RuntimeException {
    Superseded(String message) {
      super(message, null, false, false);
    }
  }

  <T> T execute(String operation, Kind kind, String objectId, Body<T> body) {
    return execute(operation, kind, objectId, false, body);
  }

  <T> T execute(String step, Kind kind, String objectId, boolean integrityDecrypt, Body<T> body) {
    Call current = CALL.get();
    if (current != null) return attempts(current, step, kind, objectId, integrityDecrypt, body);
    // Outside a call, this execute is the application call, of one step named after it.
    Call call = new Call(step);
    CALL.set(call);
    try {
      return attempts(call, step, kind, objectId, integrityDecrypt, body);
    } catch (Throwable thrown) {
      call.thrown = thrown;
      throw thrown;
    } finally {
      CALL.remove();
      call.finish();
    }
  }

  /** {@link #execute}'s attempts, as part of {@code record}, the application call. */
  private <T> T attempts(
      Call record,
      String step,
      Kind kind,
      String objectId,
      boolean integrityDecrypt,
      Body<T> body) {
    ensureOpen();
    String operation = named(step);
    boolean idempotent = kind != Kind.MUTATION;
    boolean retryable =
        kind == Kind.READ || (kind == Kind.READ_CRYPTO && config.retry.retryCrypto());
    int attempts = retryable ? config.retry.maxAttempts() : 1;
    Failures.Call call = new Failures.Call(operation, idempotent, objectId, integrityDecrypt);
    long start = System.nanoTime();
    long deadline = start + Math.min(nanos(callTimeout), Long.MAX_VALUE / 4);
    Long scoped = SCOPE.get();
    if (scoped != null && scoped - deadline < 0) deadline = scoped;
    // Derived from the configured call timeout (or a longer view's), never a shorter view's: an
    // endpoint that does not answer within it is unhealthy whatever the caller's own deadline.
    long attemptLimit =
        config.retry.attemptNanos(
            callTimeout.compareTo(config.callTimeout) > 0 ? callTimeout : config.callTimeout);
    Set<Endpoint> tried = new HashSet<>();
    // Endpoints this call cut off at the attempt timeout, in order, not tried again since: if every
    // attempt fails with time left, each gets the rest of the deadline in turn.
    Deque<Endpoint> cutOff = new ArrayDeque<>();
    Endpoint resume = null;
    // Attempts cut off at the attempt timeout: each lets one more request go to an endpoint this
    // call has not tried once the policy's attempts are used up.
    int owed = 0;
    for (int n = 1; ; n++) {
      int attempt = n;
      boolean resuming = resume != null;
      Endpoint endpoint = resuming ? resume : pick();
      resume = null;
      long attemptStart = System.nanoTime();
      // With renewal of the client certificate: whether this attempt opens a new connection, which
      // a server that retired the certificate refuses.
      long openedBefore = config.renewal == null ? 0 : endpoint.connectionsOpened();
      long remaining = deadline - attemptStart;
      // A read that another attempt may follow waits at most the attempt timeout, so a hung
      // endpoint
      // is left in time for the next one, but only while an endpoint this call has not tried is
      // available: with nowhere new to go, a slow but healthy endpoint gets the rest of the
      // deadline
      // (as does every mutation, and an endpoint cut off earlier in the call when it is resumed).
      // An attempt a cut gave back (owed) counts as one more that may follow.
      boolean bounded =
          !resuming
              && retryable
              && attempt < attempts + owed
              && attemptLimit < remaining
              && untriedBesides(endpoint, tried);
      tried.add(endpoint);
      cutOff.remove(endpoint);
      record.attempt(this, endpoint, objectId, attemptStart);
      fire(
          l ->
              l.started(
                  event(
                      record,
                      call,
                      step,
                      endpoint,
                      attempt,
                      attemptStart,
                      KmsEvent.Outcome.STARTED,
                      null)));
      // Listener dispatch or descheduling may consume the budget. Never give the transport the
      // stale remainder from before the callback, including for a mutation's sole attempt.
      remaining = deadline - System.nanoTime();
      bounded = bounded && attemptLimit < remaining;
      Session session = null;
      try {
        if (remaining <= 0)
          throw new RequestNotSentException(
              "The call deadline passed before attempt " + attempt,
              new java.net.SocketTimeoutException("KMIP call deadline exceeded"),
              true);
        // The caller's own check of a mutation, as late as this path allows: after the started
        // callbacks, which may take any time, and just before the transport sends.
        java.util.function.BooleanSupplier check = kind == Kind.MUTATION ? SEND_CHECK.get() : null;
        if (check != null && !check.getAsBoolean()) throw new Withheld();
        // The call's own deadline, not "remaining" from now: rebuilding it from a second clock
        // read would move it later by the time between the reads.
        CallContext context =
            bounded
                ? CallContext.withTimeout(Duration.ofNanos(attemptLimit))
                : CallContext.withDeadline(deadline);
        session = new Session(endpoint.client(version, context), context, version);
        T value = body.run(session);
        endpoint.unansweredSince.set(0);
        endpoint.answered();
        fire(
            l ->
                l.finished(
                    event(
                        record,
                        call,
                        step,
                        endpoint,
                        attempt,
                        attemptStart,
                        KmsEvent.Outcome.SUCCEEDED,
                        null)));
        return value;
      } catch (Exception e) {
        // Any valid response, also an operation failure (not found, denied, state), shows the
        // endpoint answers: its record of unanswered requests starts again.
        if (session != null && session.answered) {
          endpoint.unansweredSince.set(0);
          endpoint.answered();
        }
        if (e instanceof Withheld withheld) {
          KmsException stopped =
              new StateConflictException(
                  operation
                      + (objectId == null ? "" : " " + objectId)
                      + ": "
                      + withheld.getMessage(),
                  null,
                  operation,
                  objectId,
                  null,
                  null);
          fire(
              l ->
                  l.finished(
                      event(
                          record,
                          call,
                          step,
                          endpoint,
                          attempt,
                          attemptStart,
                          KmsEvent.Outcome.FAILED,
                          stopped)));
          throw withheld;
        }
        if (e instanceof Superseded canceled) {
          KmsException stopped =
              new TransientException(canceled.getMessage(), null, operation, objectId, null, null);
          fire(
              l ->
                  l.finished(
                      event(
                          record,
                          call,
                          step,
                          endpoint,
                          attempt,
                          attemptStart,
                          KmsEvent.Outcome.FAILED,
                          stopped)));
          throw canceled;
        }
        KmsException failure = Failures.classify(call, version, e);
        // A refusal on a new connection while a renewal of the certificate left a key: when one
        // Discover Versions on another new connection shows the server refuses the certificate
        // (not only this operation), the message names the key, as Kms.connect's does.
        if (config.renewal != null
            && failure instanceof PermissionDeniedException denied
            && !Failures.serverNotTrusted(e)
            && (openedBefore < 0 || endpoint.connectionsOpened() > openedBefore))
          failure = config.renewal.callRefused(this, shared.renewal, denied);
        boolean interrupted = Thread.currentThread().isInterrupted();
        // A newly contacted endpoint that does not answer its Discover Versions probe in time is as
        // silent as one that does not answer the request (only, the request was not sent): the
        // probe's timeout is weighed like a read timeout below.
        boolean probeTimeout =
            e instanceof RequestNotSentException p && p.getCause() instanceof ProbeTimeout;
        // Likewise a connection or TLS handshake that the attempt's deadline cut short (reported as
        // not sent, with a timeout as its cause): the endpoint's silence, or the caller's own short
        // deadline, never a refused connection.
        boolean cutShort = !probeTimeout && cutShort(e, bounded ? attemptLimit : remaining, config);
        Throwable signal = probeTimeout || cutShort ? e.getCause() : e;
        // No reply within the attempt timeout: the endpoint is unhealthy. In a bounded attempt the
        // attempt's deadline is the earliest one, so a read timeout is that one (not compared with
        // the clock: a transport may wake a moment early).
        boolean expired =
            bounded && signal instanceof java.net.SocketTimeoutException && !interrupted;
        if (expired) {
          cutOff.add(endpoint);
          owed++;
        }
        if (expired)
          failure =
              new TransientException(
                  operation
                      + (objectId == null ? "" : " " + objectId)
                      + ": no reply from "
                      + endpoint.label
                      + " within the attempt timeout ("
                      + Duration.ofNanos(attemptLimit)
                      + ")",
                  e,
                  operation,
                  objectId,
                  null,
                  null);
        // A replica whose server certificate this client rejects is unhealthy, not a reason to stop
        // when other replicas exist: the read is retried elsewhere.
        if (failure instanceof PermissionDeniedException
            && e instanceof RequestNotSentException
            && Failures.serverNotTrusted(e)
            && shared.endpoints.size() > 1)
          failure =
              new TransientException(
                  failure.getMessage(), e, call.operation(), call.objectId(), null, null);
        if (shared.closed) {
          // A call racing close(): the cause says whether a mutation may have been sent.
          IllegalStateException closed = new IllegalStateException("Kms is closed", failure);
          KmsEvent event =
              event(
                  record,
                  call,
                  step,
                  endpoint,
                  attempt,
                  attemptStart,
                  KmsEvent.Outcome.FAILED,
                  failure);
          fire(l -> l.finished(event));
          throw closed;
        }
        boolean local = e instanceof RequestNotSentException notSent && notSent.local();
        // A refused connection cools the endpoint down; a local hold-up (closed, canceled, pool or
        // lock wait, deadline) says nothing about the server.
        if ((e instanceof RequestNotSentException && !local && !cutShort) || expired) {
          endpoint.unavailable(failure.getMessage());
        }
        if (e instanceof ProtocolException) endpoint.closeIdle();
        // Only signs of an unhealthy endpoint move the shared current endpoint; a definite answer
        // (not found, state conflict, ...), a local failure, or the caller's own interrupt or
        // shorter deadline keeps every caller where it is. An endpoint that does not answer within
        // the whole configured call timeout counts as unhealthy.
        boolean refusedProbe =
            failure instanceof PermissionDeniedException && !endpoint.established();
        boolean callerStopped =
            !expired
                && Failures.callerStopped(
                    signal, interrupted, callTimeout.compareTo(config.callTimeout) < 0);
        // Short views must not keep a silent endpoint current forever: once requests to it (or its
        // probes) have gone unanswered (timeouts only, not interrupts) for a whole configured call
        // timeout, it counts as unhealthy whatever each caller's own deadline was.
        if (callerStopped && signal instanceof java.net.SocketTimeoutException && !interrupted) {
          endpoint.unansweredSince.compareAndSet(0, attemptStart);
          long since = endpoint.unansweredSince.get();
          if (since != 0 && System.nanoTime() - since >= nanos(config.callTimeout)) {
            callerStopped = false;
            endpoint.unansweredSince.set(0);
          }
        }
        if ((!local || probeTimeout)
            && !callerStopped
            && (Failures.transportFailure(signal) || Failures.busy(failure) || refusedProbe))
          advancePast(endpoint);
        KmsEvent event =
            event(
                record,
                call,
                step,
                endpoint,
                attempt,
                attemptStart,
                KmsEvent.Outcome.FAILED,
                failure);
        fire(l -> l.finished(event));
        if (!(failure instanceof TransientException)) throw failure;
        if (attempt >= attempts) {
          // Every attempt failed, but one was cut off only because there seemed to be somewhere
          // else to go: a cut is the SDK giving up early, not a failure the server reported. So it
          // lets an endpoint this call has not tried have a request (with the rest of the deadline)
          // before any cut-off one; then each cut-off endpoint gets the rest of the deadline in
          // order, so a slow but healthy endpoint is not given up on with time left.
          if (interrupted) throw failure;
          Endpoint untried = owed > 0 ? untried(tried) : null;
          if (untried != null) owed--;
          resume = untried != null ? untried : cutOff.poll();
          if (resume == null) throw failure;
        }
        Duration delay = config.retry.backoff(attempt);
        if (System.nanoTime() + nanos(delay) - deadline >= 0) throw failure;
        fire(l -> l.retrying(event, delay));
        sleep(delay, failure);
      }
    }
  }

  /**
   * Whether {@code e} is a connection or TLS handshake that an attempt of {@code attemptNanos} ended
   * by its deadline: not sent, not local, with a timeout as its cause, and the configured connect
   * timeout no shorter than the attempt (else the connect timeout ended it, a sign that the endpoint
   * does not accept connections, as before).
   */
  static boolean cutShort(Exception e, long attemptNanos, KmsConfig config) {
    return e instanceof RequestNotSentException n
        && !n.local()
        && n.getCause() instanceof java.net.SocketTimeoutException
        && nanos(config.connectTimeout) >= attemptNanos;
  }

  private static long nanos(Duration d) {
    try {
      return d.toNanos();
    } catch (ArithmeticException tooLong) {
      return Long.MAX_VALUE;
    }
  }

  private KmsEvent event(
      Call record,
      Failures.Call call,
      String step,
      Endpoint endpoint,
      int attempt,
      long start,
      KmsEvent.Outcome outcome,
      KmsException failure) {
    return new KmsEvent(
        KmsEvent.Kind.ATTEMPT,
        record.id,
        call.operation(),
        step,
        endpoint.label,
        attempt,
        KmipVersion.of(version),
        call.objectId(),
        Duration.ofNanos(outcome == KmsEvent.Outcome.STARTED ? 0 : System.nanoTime() - start),
        outcome,
        failure);
  }

  void fire(java.util.function.Consumer<KmsListener> event) {
    fire(config.listener, event);
  }

  /** The listeners of this {@code Kms}'s configuration, the SDK's logging first. */
  KmsListener listener() {
    return config.listener;
  }

  /** Whether {@code other} is this {@code Kms}, or a view of the same one. */
  boolean sameKms(Kms other) {
    return shared == other.shared;
  }

  /** The endpoint a renewal of the client certificate connects to: the current one. */
  KmsConfig.Endpoint renewalEndpoint() {
    synchronized (shared) {
      return shared.endpoints.get(shared.current).address;
    }
  }

  /**
   * For a renewal of the client certificate that must look for the new certificate after the
   * server refused the current one on new connections: clients on the idle connections this {@code
   * Kms} has open, the current endpoint's first. Endpoints with none are left out, so a search
   * through these opens a connection only when an idle one closes meanwhile.
   */
  List<ClientRenewal.Pooled> renewalPools() {
    List<Endpoint> order = new ArrayList<>();
    synchronized (shared) {
      int n = shared.endpoints.size();
      for (int i = 0; i < n; i++) order.add(shared.endpoints.get((shared.current + i) % n));
    }
    List<ClientRenewal.Pooled> out = new ArrayList<>();
    for (Endpoint e : order) {
      ClientRenewal.Pooled p = e.pooled(version);
      if (p != null) out.add(p);
    }
    return out;
  }

  static void fire(KmsListener listener, java.util.function.Consumer<KmsListener> event) {
    // A listener cannot change an operation's outcome: whatever it throws, an Error included, is
    // ignored (KmsListeners.call).
    outsideCall(() -> KmsListeners.call(listener, event));
  }

  /**
   * Runs {@code callback} outside the deadline, operation name, application call ({@link
   * KmsListener#callStarted}) and {@link #beforeSend} check the current thread is in: a callback
   * that calls a Kms gets its own deadline, operation names and calls, not this call's.
   */
  static void outsideCall(Runnable callback) {
    Long scope = SCOPE.get();
    Call call = CALL.get();
    java.util.function.BooleanSupplier check = SEND_CHECK.get();
    SCOPE.remove();
    CALL.remove();
    SEND_CHECK.remove();
    try {
      callback.run();
    } finally {
      if (scope != null) SCOPE.set(scope);
      if (call != null) CALL.set(call);
      if (check != null) SEND_CHECK.set(check);
    }
  }

  /** Set while this thread runs a {@code staleHandle} callback, so the callback cannot recurse. */
  private static final ThreadLocal<Boolean> STALE = new ThreadLocal<>();

  /**
   * Tells the listener that {@code key}, a handle's own key, was found replaced; not again from
   * inside that callback (a listener that calls {@code isLatest()} would otherwise recurse).
   */
  void stale(KeyAttributes key) {
    stale(key.id(), key.links(LinkKind.REPLACEMENT));
  }

  /**
   * Tells the listener that {@code keyId}, a handle's own key, is not the newest key of its lineage:
   * {@code newer} replaced it, or was chosen over it among the lineage's newest keys.
   */
  void stale(String keyId, List<String> newer) {
    if (newer.isEmpty() || STALE.get() != null) return;
    STALE.set(Boolean.TRUE);
    try {
      fire(l -> l.staleHandle(keyId, newer));
    } finally {
      STALE.remove();
    }
  }

  /** Tells the listener that {@code keyId} was replaced by each of {@code replacements} at once. */
  void concurrentReplacement(String keyId, List<String> replacements) {
    fire(l -> l.concurrentReplacement(keyId, replacements));
  }

  /** Tells the listener that a {@link CurrentKey} holding {@code keyId} could not check for a newer key. */
  void currentKeyCheckFailed(String keyId, int failuresInARow, KmsException failure) {
    fire(l -> l.currentKeyCheckFailed(keyId, failuresInARow, failure));
  }

  /** Tells the listener that a follower read {@code id} in state {@code to}, after {@code from}. */
  void keyStateChanged(String id, KeyState from, KeyState to) {
    fire(l -> l.keyStateChanged(id, from, to));
  }

  /** Whether the server lists Obtain Lease among its operations (Query Operations); null until read. */
  private volatile Boolean listsObtainLease;

  /** The keys {@link KmsListener#leaseNotGranted} was told of; bounded, then each is told again. */
  private final Set<String> unleased = java.util.concurrent.ConcurrentHashMap.newKeySet();

  /**
   * Whether the server lists Obtain Lease among the operations it implements: one Query
   * Operations, read once per {@code Kms} and kept. When it cannot be read, true (nothing is
   * decided, and it is read again next time).
   */
  boolean listsObtainLease() {
    Boolean known = listsObtainLease;
    if (known != null) return known;
    Request request =
        Requests.query()
            .add(Ttlv.enumeration(Tag.QUERY_FUNCTION, Enums.QueryFunction.QUERY_OPERATIONS))
            .build();
    try {
      boolean listed =
          execute(
              "query",
              Kind.READ,
              null,
              s -> {
                Result result = s.call(request);
                Ttlv payload = result.payload().orElse(null);
                if (payload == null) return true;
                for (Ttlv op : payload.children(Tag.OPERATION))
                  if (op.type() == Ttlv.Type.ENUMERATION
                      && op.intValue() == Operation.OBTAIN_LEASE.code()) return true;
                return false;
              });
      listsObtainLease = listed;
      return listed;
    } catch (KmsException | IllegalStateException unknown) {
      return true;
    }
  }

  /** Tells the listener, once per key, that {@code keyId} is used without a granted lease. */
  void leaseNotGranted(String keyId, Duration bound) {
    if (unleased.size() > 10_000) unleased.clear();
    if (unleased.add(keyId)) fire(config.listener, l -> l.leaseNotGranted(keyId, bound));
  }

  /**
   * Tells {@code config}'s listener that a {@link LocalKeys} cache committed a write selection.
   * Takes the configuration, not a {@code Kms}, so an owned cache that has not connected yet can
   * tell it too. Runs outside the current call's deadline and operation name, and ignores what the
   * listener throws; the caller must hold no cache lock.
   */
  static void localKeySelected(KmsConfig config, String name, String previousId, String newId) {
    fire(config.listener, l -> l.localKeySelected(name, previousId, newId));
  }

  /**
   * Tells {@code config}'s listener that a {@link LocalKeys} refresh failed, as {@link
   * #localKeySelected}; a negative or null {@code remainingValidity} is reported as zero.
   */
  static void localKeyRefreshFailed(
      KmsConfig config,
      String name,
      String keyId,
      LocalUse purpose,
      KmsException failure,
      Duration remainingValidity) {
    Duration remaining =
        remainingValidity == null || remainingValidity.isNegative()
            ? Duration.ZERO
            : remainingValidity;
    fire(config.listener, l -> l.localKeyRefreshFailed(name, keyId, purpose, failure, remaining));
  }

  /**
   * Tells {@code config}'s listeners that a {@link LocalKeys} cache loaded a key, as {@link
   * #localKeySelected}.
   */
  static void localKeyLoaded(
      KmsConfig config, String name, String keyId, LocalUse purpose, Duration loadTime) {
    fire(config.listener, l -> l.localKeyLoaded(name, keyId, purpose, loadTime));
  }

  /** Tells {@code config}'s listeners that the server granted a lease on {@code keyId}. */
  static void leaseGranted(KmsConfig config, String keyId, Duration lease, boolean renewal) {
    fire(config.listener, l -> l.leaseGranted(keyId, lease, renewal));
  }

  private static void sleep(Duration delay, KmsException failure) {
    try {
      Thread.sleep(delay.toMillis());
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw failure;
    }
  }

  /** The first endpoint, from the current one, that is not cooling down. */
  private Endpoint pick() {
    synchronized (shared) {
      List<Endpoint> endpoints = shared.endpoints;
      long now = System.nanoTime();
      for (int i = 0; i < endpoints.size(); i++) {
        int index = (shared.current + i) % endpoints.size();
        if (endpoints.get(index).available(now)) {
          shared.current = index;
          return endpoints.get(index);
        }
      }
      // All cooling down: use the eligible one whose cool-down ends first.
      Endpoint best = null;
      for (Endpoint e : endpoints)
        if (!e.ineligible && (best == null || e.downUntil - best.downUntil < 0)) best = e;
      if (best == null) best = endpoints.get(shared.current);
      shared.current = endpoints.indexOf(best);
      return best;
    }
  }

  /** The first endpoint, from the current one, that this call has not tried and is available now; null when none. */
  private Endpoint untried(Set<Endpoint> tried) {
    synchronized (shared) {
      List<Endpoint> endpoints = shared.endpoints;
      long now = System.nanoTime();
      for (int i = 0; i < endpoints.size(); i++) {
        Endpoint e = endpoints.get((shared.current + i) % endpoints.size());
        if (!tried.contains(e) && e.available(now)) return e;
      }
      return null;
    }
  }

  /** Whether an endpoint other than {@code current} that this call has not tried is available now. */
  private boolean untriedBesides(Endpoint current, Set<Endpoint> tried) {
    long now = System.nanoTime();
    for (Endpoint e : shared.endpoints)
      if (e != current && !tried.contains(e) && e.available(now)) return true;
    return false;
  }

  private void advancePast(Endpoint failed) {
    synchronized (shared) {
      List<Endpoint> endpoints = shared.endpoints;
      if (endpoints.size() > 1 && endpoints.get(shared.current) == failed)
        shared.current = (shared.current + 1) % endpoints.size();
    }
  }

  void ensureOpen() {
    if (shared.closed) throw new IllegalStateException("Kms is closed");
  }

  /** Whether {@link #close()} was called on this {@code Kms} or the one it is a view of. */
  boolean closed() {
    return shared.closed;
  }

  static ProtocolException missing(String field) {
    return new ProtocolException("Response missing " + field, null, null);
  }

  /**
   * The cause of a not-sent failure when a newly contacted endpoint did not answer its Discover
   * Versions probe before the attempt's deadline; its own cause is what the transport reported.
   */
  static final class ProbeTimeout extends java.net.SocketTimeoutException {
    ProbeTimeout(Throwable cause) {
      super("No reply to Discover Versions");
      initCause(cause);
    }
  }

  /** An endpoint that offers a different version than the one this Kms negotiated. */
  static final class EndpointUnavailable extends IOException {
    EndpointUnavailable(String message) {
      super(message);
    }
  }

  /** One configured endpoint: its transport and protocol client, created on first use. */
  static final class Endpoint {
    final String label;
    private final KmsConfig.Endpoint address;
    private final KmsConfig config;

    /** The TLS context source: {@code tls(Supplier)}'s or the reloading one; null for a fixed context. */
    private final java.util.function.Supplier<javax.net.ssl.SSLContext> tlsSource;

    private KmipTransport transport;
    private KmipClient client;
    private boolean closed;

    /** Transports opened to probe this endpoint; {@link #close()} closes them too. */
    private final Set<KmipTransport> provisional = new HashSet<>();

    volatile boolean ineligible;
    volatile long downUntil = System.nanoTime();

    /** When requests that timed out in short views started going unanswered; 0 after any answer. */
    final java.util.concurrent.atomic.AtomicLong unansweredSince =
        new java.util.concurrent.atomic.AtomicLong();

    Endpoint(
        KmsConfig.Endpoint address,
        KmsConfig config,
        java.util.function.Supplier<javax.net.ssl.SSLContext> tlsSource) {
      this.address = address;
      this.config = config;
      this.tlsSource = tlsSource;
      this.label = address.toString();
    }

    boolean available(long now) {
      return !ineligible && now - downUntil >= 0;
    }

    void markDown(Duration cooldown) {
      downUntil = System.nanoTime() + cooldown.toNanos();
    }

    /**
     * Whether {@link KmsListener#endpointUnavailable} was told of this endpoint since it last
     * answered: {@link #answered()} then tells {@link KmsListener#endpointAvailable}, once.
     */
    private final java.util.concurrent.atomic.AtomicBoolean toldUnavailable =
        new java.util.concurrent.atomic.AtomicBoolean();

    /** Marks this endpoint down for the cool-down, and tells the listeners {@code why}. */
    void unavailable(String why) {
      markDown(config.retry.cooldown());
      toldUnavailable.set(true);
      fire(config.listener, l -> l.endpointUnavailable(label, why));
    }

    /**
     * This endpoint answered a request (successfully or with a failure result): when it was told
     * unavailable, the listeners hear it is available again, once for this recovery.
     */
    void answered() {
      if (toldUnavailable.get() && toldUnavailable.compareAndSet(true, false))
        fire(config.listener, l -> l.endpointAvailable(label));
    }

    /** Negotiates for the first endpoint, within {@code context}; the result becomes the Kms version. */
    synchronized ProtocolVersion negotiate(CallContext context) throws IOException {
      KmipTransport t = open();
      try {
        client =
            KmipClient.negotiated(
                t, config.versions, options(), Set.of(), Messages.MAX_BATCH_ITEMS, context);
      } catch (Error fatal) {
        closeQuietly(t);
        throw fatal;
      }
      transport = t;
      return client.version();
    }

    /**
     * The client at {@code version}. A later endpoint is first checked to offer it with Discover
     * Versions, sent outside this endpoint's lock with the caller's deadline, so neither other
     * callers nor {@link #close()} wait for the probe; concurrent first callers may each probe.
     */
    KmipClient client(ProtocolVersion version, CallContext context) throws IOException {
      synchronized (this) {
        if (closed) throw new RequestNotSentException("Kms is closed", null, true);
        if (client != null) return client;
        // Any failure here happens before the caller's request is sent.
        if (ineligible)
          throw new RequestNotSentException(
              label + " does not offer KMIP " + version, new EndpointUnavailable(label));
      }
      KmipTransport t;
      try {
        t = open();
      } catch (IOException | RuntimeException e) {
        throw new RequestNotSentException(label + " could not be opened", e);
      }
      synchronized (this) {
        if (closed) {
          closeQuietly(t);
          throw new RequestNotSentException("Kms is closed", null, true);
        }
        provisional.add(t);
      }
      KmipClient candidate = new KmipClient(t, version, options());
      List<ProtocolVersion> offered;
      try {
        offered = offered(candidate.call(Requests.discoverVersions().build(), context));
      } catch (RequestNotSentException e) {
        discard(t);
        throw e;
      } catch (KmipException e) {
        discard(t);
        // Credentials the replica refuses are the caller's problem; anything else makes this
        // endpoint unavailable for now, and the caller's request was not sent.
        // The endpoint cools down, so traffic does not stay pinned to a replica that refuses it.
        if (e.result().hasReason(Enums.ResultReason.PERMISSION_DENIED)
            || e.result().hasReason(Enums.ResultReason.AUTHENTICATION_NOT_SUCCESSFUL)) {
          markDown(config.retry.cooldown());
          throw e;
        }
        throw new RequestNotSentException(label + " is unavailable for KMIP " + version, e);
      } catch (IOException | RuntimeException e) {
        discard(t);
        // The caller's own cancellation or interrupt says nothing about the endpoint.
        if (context.isCancelled()
            || Thread.currentThread().isInterrupted()
            || Failures.callerStopped(e, false, false))
          throw new RequestNotSentException(
              "The call was interrupted or canceled while probing " + label, e, true);
        // No answer in time: the caller weighs it like a read timeout (the endpoint's silence, or
        // the caller's own short deadline); either way the caller's request was not sent.
        if (e instanceof java.net.SocketTimeoutException || context.remainingNanos() <= 0)
          throw new RequestNotSentException(
              "The call deadline passed while probing " + label, new ProbeTimeout(e), true);
        throw new RequestNotSentException(label + " is unavailable for KMIP " + version, e);
      }
      synchronized (this) {
        provisional.remove(t);
        if (closed) {
          closeQuietly(t);
          throw new RequestNotSentException("Kms is closed", null, true);
        }
        if (!offered.contains(version)) {
          closeQuietly(t);
          ineligible = true;
          throw new RequestNotSentException(
              label + " offers " + offered + ", not KMIP " + version,
              new EndpointUnavailable(label));
        }
        if (client != null) {
          closeQuietly(t); // another caller's probe finished first
          return client;
        }
        transport = t;
        client = candidate;
        return client;
      }
    }

    synchronized boolean established() {
      return client != null;
    }

    /**
     * How many connections this endpoint's TLS transport has opened; -1 before it has one, or when
     * its connections are not counted.
     */
    long connectionsOpened() {
      KmipTransport t;
      synchronized (this) {
        if (closed || client == null) return -1;
        t = transport;
      }
      TlsTransport counted;
      synchronized (statsLock) {
        counted = measured.get(t);
      }
      return counted == null ? -1 : counted.connectionsOpened();
    }

    /**
     * A client at {@code version} on this endpoint's pooled connections, and the TLS transport
     * that counts the connections it opens; null when it has no idle connection open.
     */
    ClientRenewal.Pooled pooled(ProtocolVersion version) {
      KmipTransport t;
      synchronized (this) {
        if (closed || client == null) return null;
        t = transport;
      }
      TlsTransport counted;
      synchronized (statsLock) {
        counted = measured.get(t);
      }
      if (counted == null || counted.idleConnections() == 0) return null;
      RequestOptions o = options();
      return new ClientRenewal.Pooled(new KmipClient(t, version, o), counted, o);
    }

    /**
     * A client at {@code version} over this endpoint's transport whose calls without a deadline are
     * bounded by {@code timeout} each ({@link Kms#protocol()}); closing it does nothing.
     */
    KmipClient bounded(ProtocolVersion version, CallContext context, Duration timeout)
        throws IOException {
      client(version, context);
      KmipTransport t;
      synchronized (this) {
        t = transport;
      }
      return new KmipClient(new Bounded(t, timeout), version, options());
    }

    /** A transport that gives each exchange without a deadline one of {@code timeout}. */
    private static final class Bounded implements KmipTransport {
      private final KmipTransport transport;
      private final Duration timeout;

      Bounded(KmipTransport transport, Duration timeout) {
        this.transport = transport;
        this.timeout = timeout;
      }

      @Override
      public Ttlv exchange(Ttlv request) throws IOException {
        return transport.exchange(request, CallContext.withTimeout(timeout));
      }

      @Override
      public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
        if (context.hasDeadline()) return transport.exchange(request, context);
        CallContext bounded = CallContext.withTimeout(timeout);
        try (java.io.Closeable cancel = context.onCancel(bounded::cancel)) {
          return transport.exchange(request, bounded);
        }
      }

      @Override
      public void close() {
        // The Kms owns the connection.
      }
    }

    private void discard(KmipTransport t) {
      synchronized (this) {
        provisional.remove(t);
      }
      closeQuietly(t);
    }

    /** The versions in a Discover Versions response. */
    private static List<ProtocolVersion> offered(Result result) throws ProtocolException {
      try {
        List<ProtocolVersion> out = new ArrayList<>();
        for (Ttlv v :
            result.payload().map(p -> p.children(Tag.PROTOCOL_VERSION)).orElse(List.of())) {
          int major = v.require(Tag.PROTOCOL_VERSION_MAJOR).intValue();
          int minor = v.require(Tag.PROTOCOL_VERSION_MINOR).intValue();
          for (ProtocolVersion p : ProtocolVersion.values())
            if (p.major() == major && p.minor() == minor) out.add(p);
        }
        return out;
      } catch (IllegalArgumentException | IllegalStateException e) {
        throw new ProtocolException(
            "Malformed Discover Versions response", result.batchItem(), null);
      }
    }

    private RequestOptions options() {
      return config.auth == KmsConfig.Authentication.PASSWORD
          ? RequestOptions.DEFAULT.authentication(
              Credentials.usernamePassword(config.username, config.password))
          : RequestOptions.DEFAULT;
    }

    private KmipTransport open() throws IOException {
      KmipTransport t;
      if (config.transport != null) t = config.transport.open(address);
      else {
        TlsTransport.Builder b =
            (tlsSource != null
                    ? TlsTransport.builder(address.host(), address.port(), tlsSource)
                    : TlsTransport.builder(address.host(), address.port(), config.tls))
                .connectTimeout(config.connectTimeout)
                .readTimeout(readLimit(config))
                .pool(config.poolSize, config.idleTimeout)
                .validateAfterIdle(config.validateAfterIdle);
        if (config.cipherSuites != null) b.cipherSuites(config.cipherSuites);
        // A supplied context may change: the transport works the suites out for each one.
        else if (config.kmipCipherSuites && tlsSource != null) b.kmipCipherSuites();
        else if (config.kmipCipherSuites) b.cipherSuites(Tls.kmipCipherSuites(config.tls));
        t = b.build();
      }
      TlsTransport counted = t instanceof TlsTransport tls ? tls : null;
      if (config.auth == KmsConfig.Authentication.HASHED_PASSWORD)
        t =
            new HashedPasswordTransport(
                t, config.username, config.password, config.hashedPasswordLockWait);
      if (counted != null) {
        synchronized (statsLock) {
          measured.put(t, counted);
        }
        countable = true;
      }
      return t;
    }

    synchronized void closeIdle() {
      KmipTransport t = transport;
      if (t instanceof TlsTransport tls) tls.closeIdleConnections();
    }

    void close() {
      List<KmipTransport> toClose = new ArrayList<>();
      synchronized (this) {
        closed = true;
        if (transport != null) toClose.add(transport);
        toClose.addAll(provisional);
        provisional.clear();
        transport = null;
        client = null;
      }
      // Closing aborts in-flight probes and exchanges without holding the lock.
      for (KmipTransport t : toClose) closeQuietly(t);
    }

    /** Closes {@code t}, keeping the totals of its counts ({@link #stats()}). */
    private void closeQuietly(KmipTransport t) {
      try {
        t.close();
      } catch (IOException ignored) {
      } finally {
        synchronized (statsLock) {
          TlsTransport tls = measured.remove(t);
          if (tls != null) {
            retiredOpened += tls.connectionsOpened();
            retiredWaits += tls.poolWaits();
            retiredWaitNanos += nanos(tls.poolWaitTime());
          }
        }
      }
    }

    /**
     * The transports open now whose counts the SDK can read (its TLS transport, also one a {@link
     * KmsConfig.TransportFactory} returned), by the transport this endpoint uses (the TLS one, or
     * the hashed-password transport around it); guarded by {@link #statsLock} for consistent totals.
     */
    private final Map<KmipTransport, TlsTransport> measured =
        new java.util.concurrent.ConcurrentHashMap<>();

    /** Guards {@link #measured} and the totals of the transports closed. */
    private final Object statsLock = new Object();

    private long retiredOpened, retiredWaits, retiredWaitNanos;

    /** Whether a transport of this endpoint reported counts (always with the SDK's own transport). */
    private volatile boolean countable;

    /** This endpoint's connection counts now ({@link Kms#connectionStats()}). */
    ConnectionStats stats() {
      int open = 0, idle = 0;
      long opened, waits, waitNanos;
      synchronized (statsLock) {
        opened = retiredOpened;
        waits = retiredWaits;
        waitNanos = retiredWaitNanos;
        for (TlsTransport t : measured.values()) {
          open += t.openConnections();
          idle += t.idleConnections();
          opened += t.connectionsOpened();
          waits += t.poolWaits();
          waitNanos += nanos(t.poolWaitTime());
        }
      }
      return new ConnectionStats(
          label,
          countable || config.transport == null,
          open,
          idle,
          Math.max(0, open - idle),
          opened,
          waits,
          Duration.ofNanos(waitNanos));
    }
  }
}
