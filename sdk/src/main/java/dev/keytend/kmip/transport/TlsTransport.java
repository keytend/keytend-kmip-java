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

import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.model.Ttlv;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Consumer;
import java.util.function.Supplier;
import javax.net.ssl.*;

/**
 * Binary TTLV over mutually authenticated TLS: the usual {@link KmipTransport}. It is thread-safe,
 * and it never repeats a request on its own.
 *
 * <pre>{@code
 * SSLContext ssl = Tls.context(Path.of("client.p12"), password, Path.of("ca.pem"));
 * TlsTransport transport = TlsTransport.builder("kms.example.com", 5696, ssl)
 *     .connectTimeout(Duration.ofSeconds(5))
 *     .pool(4, Duration.ofSeconds(30))
 *     .build();
 * }</pre>
 *
 * <p>{@code password} is the keystore password. The defaults are a 10 s connect timeout, a 30 s
 * read timeout, no pool (one connection per exchange), the JDK's cipher suites and a default
 * {@link TtlvCodec}. TLS 1.3 and 1.2 are enabled, and the server's certificate must match {@code
 * host}. For client credentials that change while the transport is in use, build it with {@link
 * #builder(String, int, Supplier)}.
 *
 * <p>Close the transport when you are done, unless you passed it to {@link
 * dev.keytend.kmip.client.KmipClient#negotiated(KmipTransport,
 * dev.keytend.kmip.client.VersionPolicy) KmipClient.negotiated}, which then owns it.
 *
 * <p>A failure before any byte of the request was written is a {@link RequestNotSentException}:
 * the server cannot have seen the request. After any other failure the request may have reached
 * the server, so the outcome of a mutation is unknown.
 *
 * @since 0.10.0
 */
public final class TlsTransport implements KmipTransport {
  /** The exchanges' watchdogs; its thread ends when no exchange runs. */
  private static final ScheduledThreadPoolExecutor DEADLINES =
      SdkThreads.scheduler("kmip-transport-deadlines");

  private final String host;
  private final int port, connectTimeout, readTimeout;
  private final Supplier<SSLContext> source;
  private final TtlvCodec codec;
  private final String[] cipherSuites;
  private final boolean kmipCipherSuites;

  /** The context the supplier returned last, with its cipher suites; null before the first. */
  private volatile Credentials latest;

  private final int poolSize;
  private final long idleNanos;

  /** Idle at least this long, a pooled connection is probed with a 1 ms read before reuse. */
  private final long validateNanos;

  /** Tests only: the reuse checks made, waiting (1 ms) and not waiting. */
  final AtomicLong probes = new AtomicLong(), quickChecks = new AtomicLong();

  private final Permits permits;
  private final Deque<Connection> idle = new ConcurrentLinkedDeque<>();
  private final Set<Socket> active = ConcurrentHashMap.newKeySet();
  private final AtomicBoolean closed = new AtomicBoolean();
  private final AtomicLong connectionsOpened = new AtomicLong();

  /** Tests only: runs in an abort after it took the socket and before it closes it. */
  volatile Consumer<Socket> beforeAbortClose;

  /** Tests only: sees each encoded request buffer as soon as it exists. */
  volatile Consumer<byte[]> afterEncode;

  /** Tests only: sees each buffer the transport wipes, just before it is wiped. */
  volatile Consumer<byte[]> beforeWipe;

  /** Tests only: runs once the exchange may use a connection (after the pool permit, if any). */
  volatile Runnable afterPermit;

  private static final class Connection {
    final Socket raw;

    /** {@link #raw}'s channel, for a check that does not wait; null through a proxy. */
    final SocketChannel channel;

    final SSLSocket socket;

    /** The context whose handshake opened this connection. */
    final SSLContext context;

    long lastUsed = System.nanoTime();

    Connection(Socket raw, SocketChannel channel, SSLSocket socket, SSLContext context) {
      this.channel = channel;
      this.raw = raw;
      this.socket = socket;
      this.context = context;
    }
  }

  /** A context and the cipher suites to enable with it (null: the JDK's defaults). */
  private record Credentials(SSLContext context, String[] suites) {}

  /**
   * A transport with the default settings: {@code builder(host, port, ssl).build()}.
   *
   * @param host the server's host name, which its certificate must match
   * @param port the server's port, usually 5696
   * @param ssl the TLS context, for example from {@link Tls#context(java.nio.file.Path, char[],
   *     java.nio.file.Path)}
   * @throws IllegalArgumentException if {@code port} is not 1 to 65535
   */
  public TlsTransport(String host, int port, SSLContext ssl) {
    this(builder(host, port, ssl));
  }

  /**
   * A transport with the given timeouts and codec, and the other defaults; see {@link Builder}.
   *
   * @param host the server's host name, which its certificate must match
   * @param port the server's port, usually 5696
   * @param ssl the TLS context
   * @param connectTimeout see {@link Builder#connectTimeout}
   * @param readTimeout see {@link Builder#readTimeout}
   * @param codec see {@link Builder#codec}
   * @throws IllegalArgumentException if {@code port} or a timeout is out of range
   */
  public TlsTransport(
      String host,
      int port,
      SSLContext ssl,
      Duration connectTimeout,
      Duration readTimeout,
      TtlvCodec codec) {
    this(
        builder(host, port, ssl)
            .connectTimeout(connectTimeout)
            .readTimeout(readTimeout)
            .codec(codec));
  }

  /**
   * A builder for a transport with the fixed TLS context {@code ssl}. To change credentials while
   * the transport is in use, see {@link #builder(String, int, Supplier)}.
   *
   * @param host the server's host name, which its certificate must match
   * @param port the server's port, usually 5696
   * @param ssl the TLS context
   * @return a new builder with the defaults
   * @throws IllegalArgumentException if {@code port} is not 1 to 65535
   */
  public static Builder builder(String host, int port, SSLContext ssl) {
    Objects.requireNonNull(ssl, "ssl");
    return new Builder(host, port, () -> ssl);
  }

  /**
   * A transport that takes its TLS context from {@code source}, for credentials that change while
   * it is in use, such as short-lived client certificates or a rotated trust bundle.
   *
   * <p>{@code source} is called once per exchange, before a connection is taken. It runs on the
   * calling thread, with no lock held. It must be thread-safe and quick.
   *
   * <p>A pooled connection is reused only if the supplier returned the same {@code SSLContext}
   * instance that opened it. Identity counts, not equality. A new connection uses the context just
   * returned. So return the same instance until the credentials change: cache it, and replace it
   * when new certificate files are ready. While a reload is in progress, return the previous
   * context rather than fail. {@link #closeIdleConnections()} says what happens to pooled
   * connections.
   *
   * <p>When the supplier throws a {@code RuntimeException} or returns null, the exchange fails with
   * a {@link RequestNotSentException}. Its {@link RequestNotSentException#local()} is true, and its
   * cause is that exception, or a {@code NullPointerException} for null. Nothing was sent, and the
   * server is not to blame.
   *
   * @param host the server's host name, which its certificate must match
   * @param port the server's port, usually 5696
   * @param source returns the TLS context for each exchange
   * @return a new builder with the defaults
   * @throws IllegalArgumentException if {@code port} is not 1 to 65535
   */
  public static Builder builder(String host, int port, Supplier<SSLContext> source) {
    return new Builder(host, port, Objects.requireNonNull(source, "source"));
  }

  /**
   * Transport settings. Defaults: 10 s connect, 30 s read, no pool, the JDK's cipher suites and a
   * default {@link TtlvCodec}.
   */
  public static final class Builder {
    private final String host;
    private final int port;
    private final Supplier<SSLContext> source;
    private Duration connectTimeout = Duration.ofSeconds(10), readTimeout = Duration.ofSeconds(30);
    private TtlvCodec codec = new TtlvCodec();
    private List<String> cipherSuites;
    private boolean kmipCipherSuites;
    private int poolSize;
    private Duration idleTimeout = Duration.ofSeconds(30);
    private Duration validateAfterIdle = DEFAULT_VALIDATE_AFTER_IDLE;

    private Builder(String host, int port, Supplier<SSLContext> source) {
      this.host = Objects.requireNonNull(host, "host");
      if (port < 1 || port > 65535) throw new IllegalArgumentException("Invalid port");
      this.port = port;
      this.source = source;
    }

    /**
     * How long opening a connection may take: the TCP connect and the TLS handshake together.
     * Default 10 s.
     *
     * @param timeout from 1 ms to {@code Integer.MAX_VALUE} ms
     * @return this builder
     * @throws IllegalArgumentException if {@code timeout} is out of range
     */
    public Builder connectTimeout(Duration timeout) {
      millis(timeout);
      connectTimeout = timeout;
      return this;
    }

    /**
     * How long a read from the server may wait once the request is sent. Default 30 s. The whole
     * exchange must also end within the connect timeout plus the read timeout, counted from its
     * start, or by an earlier {@link CallContext} deadline.
     *
     * @param timeout from 1 ms to {@code Integer.MAX_VALUE} ms
     * @return this builder
     * @throws IllegalArgumentException if {@code timeout} is out of range
     */
    public Builder readTimeout(Duration timeout) {
      millis(timeout);
      readTimeout = timeout;
      return this;
    }

    /**
     * The binary TTLV codec, whose limits bound each reply's size and nesting. Default {@code new
     * TtlvCodec()}.
     *
     * @param codec the codec
     * @return this builder
     */
    public Builder codec(TtlvCodec codec) {
      this.codec = Objects.requireNonNull(codec, "codec");
      return this;
    }

    /**
     * Restricts the TLS cipher suites, for example to {@link Tls#kmipCipherSuites(SSLContext)};
     * replaces {@link #kmipCipherSuites()}. By default the JDK's suites are enabled.
     *
     * @param suites the JSSE suite names; at least one
     * @return this builder
     * @throws IllegalArgumentException if {@code suites} is empty
     */
    public Builder cipherSuites(List<String> suites) {
      if (suites.isEmpty()) throw new IllegalArgumentException("No cipher suites");
      cipherSuites = List.copyOf(suites);
      kmipCipherSuites = false;
      return this;
    }

    /**
     * Restricts the TLS cipher suites to {@link Tls#kmipCipherSuites(SSLContext)} of each context
     * the transport uses, worked out at the first exchange and again whenever a supplier returns
     * a different context from the time before; replaces {@link #cipherSuites}. When a context
     * enables none of them, an exchange that would use it fails with a {@link
     * RequestNotSentException} whose {@code local()} is true.
     *
     * @return this builder
     */
    public Builder kmipCipherSuites() {
      kmipCipherSuites = true;
      cipherSuites = null;
      return this;
    }

    /**
     * Keeps up to {@code size} connections open for reuse. {@code size} 0, the default, opens one
     * connection per exchange.
     *
     * <p>Each exchange has one connection to itself for its request and reply. An exchange that
     * finds every connection busy waits in arrival order, until its deadline, a {@link
     * CallContext#cancel()} or an interrupt. A connection is closed instead of returned after any
     * error (also a reply that does not decode), a deadline or a cancellation. One idle longer than
     * {@code idleTimeout} is closed instead of reused.
     *
     * <p>Before reuse, an idle connection is checked ({@link #validateAfterIdle}). One that the
     * server has closed, or that carries unsolicited data, is discarded. A failure on a reused
     * connection is reported, not retried on another, because the request may have reached the
     * server. Idle connections close only when next taken, or by {@link
     * TlsTransport#closeIdleConnections()}: there is no background reaper.
     *
     * @param size the most connections kept open; 0 for none
     * @param idleTimeout how long a connection may stay idle and still be reused, from 1 ms
     * @return this builder
     * @throws IllegalArgumentException if {@code size} is negative or {@code idleTimeout} is out of
     *     range
     */
    public Builder pool(int size, Duration idleTimeout) {
      if (size < 0) throw new IllegalArgumentException("Invalid pool size");
      millis(idleTimeout);
      poolSize = size;
      this.idleTimeout = idleTimeout;
      return this;
    }

    /**
     * How long a pooled connection may sit idle before it is probed. The default is {@link
     * #DEFAULT_VALIDATE_AFTER_IDLE}, 2 s. Each check discards a connection whose close (TLS
     * close_notify, TCP FIN or reset) or stray data has arrived.
     *
     * <ul>
     *   <li>Idle for less: a quick check that does not wait for anything still in flight.
     *   <li>Idle this long or longer: a probe, a read that waits 1 ms. It also catches a close or
     *       data in flight.
     * </ul>
     *
     * <p>TLS bytes already waiting, such as a TLS 1.3 ticket after a reply, are read through the TLS
     * layer with the 1 ms read in both cases. {@link Duration#ZERO} probes before every reuse, at
     * about 1 ms a request.
     *
     * @param idle the idle time after which a connection is probed
     * @return this builder
     * @throws IllegalArgumentException when {@code idle} is negative
     * @since 0.10.0
     */
    public Builder validateAfterIdle(Duration idle) {
      Objects.requireNonNull(idle, "idle");
      if (idle.isNegative())
        throw new IllegalArgumentException("validateAfterIdle must not be negative: " + idle);
      this.validateAfterIdle = idle;
      return this;
    }

    /**
     * Builds the transport. It opens no connection until the first exchange.
     *
     * @return a new transport
     */
    public TlsTransport build() {
      return new TlsTransport(this);
    }
  }

  private TlsTransport(Builder b) {
    host = b.host;
    port = b.port;
    source = b.source;
    kmipCipherSuites = b.kmipCipherSuites;
    connectTimeout = millis(b.connectTimeout);
    readTimeout = millis(b.readTimeout);
    codec = b.codec;
    cipherSuites = b.cipherSuites == null ? null : b.cipherSuites.toArray(String[]::new);
    poolSize = b.poolSize;
    idleNanos = b.idleTimeout.toNanos();
    validateNanos = saturatedNanos(b.validateAfterIdle);
    permits = poolSize > 0 ? new Permits(poolSize) : null;
  }

  /**
   * The idle time after which {@link Builder#validateAfterIdle} probes a pooled connection, unless
   * set: 2 s, as HTTP clients' validate-after-inactivity defaults are.
   *
   * @since 0.10.0
   */
  public static final Duration DEFAULT_VALIDATE_AFTER_IDLE = Duration.ofSeconds(2);

  private static long saturatedNanos(Duration d) {
    try {
      return d.toNanos();
    } catch (ArithmeticException tooLong) {
      return Long.MAX_VALUE;
    }
  }

  private static int millis(Duration d) {
    long n = d.toMillis();
    if (n < 1 || n > Integer.MAX_VALUE)
      throw new IllegalArgumentException("Timeout must be 1..2147483647 ms");
    return (int) n;
  }

  /**
   * Connections opened so far. Each one is a TLS handshake.
   *
   * @return the number of connections opened
   */
  public long connectionsOpened() {
    return connectionsOpened.get();
  }

  /**
   * Connections open now: pooled ones, idle or in use by an exchange, and those being opened.
   * Without a pool, the exchanges under way. Read from memory, for metrics.
   *
   * @return the number of connections open now
   * @since 0.10.0
   */
  public int openConnections() {
    return active.size();
  }

  /**
   * Pooled connections open now and waiting for an exchange (zero without a pool). Read from
   * memory, for metrics.
   *
   * @return the number of idle pooled connections
   * @since 0.10.0
   */
  public int idleConnections() {
    return idle.size();
  }

  /**
   * Exchanges so far that found every pooled connection busy ({@link Builder#pool}) and waited
   * for one, however the wait ended (a connection, the deadline, a cancellation). Zero without a
   * pool.
   *
   * @return the number of exchanges that waited for the pool
   * @since 0.10.0
   */
  public long poolWaits() {
    return permits == null ? 0 : permits.waits();
  }

  /**
   * How long the exchanges counted by {@link #poolWaits()} waited for the pool, in all.
   *
   * @return the total wait, zero without a pool
   * @since 0.10.0
   */
  public Duration poolWaitTime() {
    return permits == null ? Duration.ZERO : Duration.ofNanos(permits.waitNanos());
  }

  /** {@link #exchange(Ttlv, CallContext)} with no deadline but the transport's own. */
  @Override
  public Ttlv exchange(Ttlv request) throws IOException {
    return exchange(request, CallContext.NONE);
  }

  /**
   * Sends {@code request} and reads one reply. The exchange must end within the connect timeout
   * plus the read timeout from its start, or by the earlier deadline of {@code context}.
   * Interrupting the thread, canceling the context, passing the deadline or {@link #close()}
   * closes the connection in use. An interrupted exchange always fails with {@link
   * InterruptedIOException}, even when the reply had arrived, so check the outcome of an
   * interrupted mutation.
   *
   * @param request the request message
   * @param context the deadline and cancellation of this exchange
   * @return the reply
   * @throws RequestNotSentException if nothing was sent: the connection, the TLS handshake, the
   *     wait for a pooled connection or the context supplier failed, the deadline or cancellation
   *     came first, or the transport is closed
   * @throws SocketTimeoutException if a read timed out, or the deadline passed, after the request
   *     may have been written
   * @throws InterruptedIOException if the call was canceled or interrupted after the request may
   *     have been written
   * @throws IOException for any other failure; the request may have reached the server
   */
  @Override
  public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
    // Checked before encoding, so a call that is not sent leaves no encoded copy behind.
    context.checkNotSent();
    if (closed.get())
      throw new RequestNotSentException(
          "KMIP request not sent: KMIP transport closed",
          new IOException("KMIP transport closed"),
          true);
    Thread caller = Thread.currentThread();
    long deadline =
        context.deadlineBefore(
            System.nanoTime() + TimeUnit.MILLISECONDS.toNanos((long) connectTimeout + readTimeout));
    Exchange current = new Exchange(deadline);
    byte[] encoded = codec.encode(request);
    Consumer<byte[]> encodedHook = afterEncode;
    if (encodedHook != null) encodedHook.accept(encoded);
    // The watchdog also checks cancellation, so a cancel whose listener ran before anything could
    // be closed still stops the exchange.
    var watchdog =
        DEADLINES.scheduleAtFixedRate(
            () -> {
              if (caller.isInterrupted()
                  || context.isCancelled()
                  || System.nanoTime() >= current.limit) current.abort();
            },
            10,
            10,
            TimeUnit.MILLISECONDS);
    Closeable cancellation = context.onCancel(current::abort);
    boolean permit = false;
    Connection connection = null;
    try {
      if (permits != null) {
        try {
          permits.acquire(context, deadline, "KMIP connection pool exhausted");
          permit = true;
        } catch (IOException notSent) {
          throw new RequestNotSentException(
              "KMIP request not sent: " + notSent.getMessage(), notSent, true);
        }
      }
      Runnable permitHook = afterPermit;
      if (permitHook != null) permitHook.run();
      Credentials tls = credentials();
      try {
        // A cancellation, interrupt or deadline that took effect while nothing could be closed
        // (waiting for the permit, or before) stops the exchange here.
        current.check(context, caller);
        connection = reusable(tls.context);
        if (connection == null) connection = connect(current, context, caller, tls);
        else current.publish(connection.raw);
      } catch (IOException notSent) {
        IOException cause = classify(notSent, context, caller, deadline, true);
        throw new RequestNotSentException(
            "KMIP request not sent: " + notSent.getMessage(),
            cause,
            context.isCancelled() || caller.isInterrupted() || closed.get());
      }
      try {
        context.check();
        if (closed.get()) throw new IOException("KMIP transport closed");
        if (current.socket.get() != connection.raw)
          throw classify(
              new SocketException("KMIP connection aborted before sending"),
              context,
              caller,
              deadline,
              true);
      } catch (IOException notSent) {
        throw new RequestNotSentException(
            "KMIP request not sent: " + notSent.getMessage(), notSent, true);
      }
      connection.socket.setSoTimeout(readTimeout);
      connection.socket.getOutputStream().write(encoded);
      connection.socket.getOutputStream().flush();
      Ttlv reply = codec.read(connection.socket.getInputStream());
      // An interrupted exchange always reports the interruption, even if the reply arrived.
      if (caller.isInterrupted()) throw new InterruptedIOException("KMIP exchange interrupted");
      watchdog.cancel(false);
      cancellation.close();
      Connection done = connection;
      connection = null;
      // Pool the connection only if no abort took it; an abort that did closes it.
      if (current.socket.getAndSet(null) == done.raw) release(done);
      else discard(done);
      return reply;
    } catch (RequestNotSentException e) {
      throw e;
    } catch (IOException e) {
      // Taking the socket back also stops a later abort; null means an abort already took it.
      boolean aborted = current.socket.getAndSet(null) == null;
      throw classify(e, context, caller, deadline, aborted);
    } finally {
      watchdog.cancel(false);
      cancellation.close();
      if (connection != null) discard(connection);
      if (permit) permits.release();
      // Best-effort hygiene: the encoded request may hold key material or credentials.
      wipe(encoded);
    }
  }

  /**
   * The socket one exchange may still use, and whether the exchange was stopped. Whoever takes the
   * socket out first owns it: an abort closes it, the exchange returns it to the pool. So an abort
   * that fires late cannot close a socket already handed to another exchange. An abort that finds
   * no socket is remembered, and a socket published after it is closed at once: the abort sets the
   * flag before it looks for a socket, and publication sets the socket before it looks at the flag,
   * so at least one of them sees the other.
   */
  private final class Exchange {
    final AtomicReference<Socket> socket = new AtomicReference<>();
    final AtomicBoolean stopped = new AtomicBoolean();

    /** When the watchdog aborts: the exchange deadline, or earlier while connecting. */
    volatile long limit;

    Exchange(long deadline) {
      limit = deadline;
    }

    void abort() {
      stopped.set(true);
      Socket s = socket.getAndSet(null);
      if (s == null) return;
      Consumer<Socket> hook = beforeAbortClose;
      if (hook != null) hook.accept(s);
      try {
        s.close();
      } catch (IOException ignored) {
      }
    }

    void publish(Socket s) {
      socket.set(s);
      if (stopped.get()) abort();
    }

    /** Fails if the exchange was stopped, or should be; nothing is open yet. */
    void check(CallContext context, Thread caller) throws IOException {
      context.check();
      if (caller.isInterrupted()) throw new InterruptedIOException("KMIP exchange interrupted");
      if (stopped.get() || System.nanoTime() >= limit)
        throw new SocketException("KMIP connection aborted before sending");
    }
  }

  private void wipe(byte[] buffer) {
    Consumer<byte[]> hook = beforeWipe;
    if (hook != null) hook.accept(buffer);
    Arrays.fill(buffer, (byte) 0);
  }

  /**
   * Reports cancellation, interruption and deadline expiry with their specific types. A failure
   * that no abort caused (for example a malformed reply) keeps its own type, unless the caller was
   * interrupted: an interrupted exchange always reports the interruption.
   */
  private static IOException classify(
      IOException e, CallContext context, Thread caller, long deadline, boolean aborted) {
    if (aborted && context.isCancelled())
      return (IOException) chain(new InterruptedIOException("KMIP call canceled"), e);
    if (caller.isInterrupted())
      return (IOException) chain(new InterruptedIOException("KMIP exchange interrupted"), e);
    if (aborted && System.nanoTime() >= deadline && !(e instanceof SocketTimeoutException))
      return (IOException) chain(new SocketTimeoutException("KMIP exchange deadline exceeded"), e);
    return e;
  }

  private static Throwable chain(Throwable outer, Throwable cause) {
    outer.initCause(cause);
    return outer;
  }

  /**
   * Opens a connection: the TCP connect and the TLS handshake together end at the connect timeout
   * (or the exchange deadline, if earlier). The watchdog enforces that limit while connecting, so a
   * peer that accepts but never completes the handshake, or completes it slowly, is left in time.
   */
  private Connection connect(Exchange current, CallContext context, Thread caller, Credentials tls)
      throws IOException {
    long deadline = current.limit;
    long connectDeadline =
        Math.min(deadline, System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(connectTimeout));
    // A channel's socket, so that a pooled connection can be checked without waiting (quiet()),
    // unless the JVM's proxy settings name a proxy for the KMS: only a plain Socket goes through
    // one, as the SDK's earliest transport did.
    SocketChannel channel = proxied() ? null : SocketChannel.open();
    Socket raw = channel == null ? new Socket() : channel.socket();
    active.add(raw);
    current.limit = connectDeadline;
    try {
      current.publish(raw);
      if (closed.get()) throw new IOException("KMIP transport closed");
      current.check(context, caller);
      raw.connect(new InetSocketAddress(host, port), remainingMillis(connectDeadline));
      current.check(context, caller);
      raw.setSoTimeout(remainingMillis(connectDeadline));
      SSLSocket socket =
          (SSLSocket) tls.context.getSocketFactory().createSocket(raw, host, port, true);
      SSLParameters parameters = socket.getSSLParameters();
      parameters.setEndpointIdentificationAlgorithm("HTTPS");
      parameters.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
      if (tls.suites != null) parameters.setCipherSuites(tls.suites);
      socket.setSSLParameters(parameters);
      socket.startHandshake();
      current.limit = deadline;
      // The watchdog may have closed the socket at the connect limit as the handshake ended: it
      // sets the stopped flag and closes the socket, and if that happens between the handshake's
      // last read and the line above, startHandshake() returns normally on a closed socket. The
      // window is a few instructions wide, so no test hits it deterministically;
      // without this check the first write would fail as a local "aborted before sending" instead
      // of the connect timeout (not sent, not local) that every other late handshake reports.
      if (current.stopped.get()) throw new SocketException("KMIP connection aborted");
      socket.setSoTimeout(readTimeout);
      connectionsOpened.incrementAndGet();
      return new Connection(raw, channel, socket, tls.context);
    } catch (IOException | RuntimeException e) {
      active.remove(raw);
      raw.close();
      // The connect timeout, not the exchange deadline, ended it (by the socket timeout or by the
      // watchdog closing the socket).
      if (e instanceof IOException
          && (e instanceof SocketTimeoutException || System.nanoTime() >= connectDeadline)
          && connectDeadline < deadline
          && !context.isCancelled()
          && !caller.isInterrupted()
          && !closed.get())
        throw (IOException)
            chain(
                new SocketTimeoutException(
                    "KMIP connect timed out (TCP connect and TLS handshake)"),
                e);
      throw e;
    }
  }

  /**
   * Whether the JVM's {@link ProxySelector} (which also reads {@code socksProxyHost}) names a proxy
   * for the KMS, as a plain {@link Socket} asks it for {@code socket://host:port}.
   */
  private boolean proxied() {
    ProxySelector selector = ProxySelector.getDefault();
    if (selector == null) return false;
    try {
      for (Proxy proxy : selector.select(new URI("socket", null, host, port, null, null, null)))
        if (proxy.type() != Proxy.Type.DIRECT) return true;
    } catch (URISyntaxException | RuntimeException unknown) {
      return false;
    }
    return false;
  }

  /** Milliseconds until {@code deadline}, at least 1 (a timeout of 0 would mean none). */
  private static int remainingMillis(long deadline) throws SocketTimeoutException {
    long millis = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime());
    if (millis < 1) throw new SocketTimeoutException("KMIP exchange deadline exceeded");
    return (int) Math.min(Integer.MAX_VALUE, millis);
  }

  /**
   * The TLS context for this exchange, from the supplier, with its cipher suites. Fails, not sent
   * and local, when the supplier throws or returns null, or no KMIP profile suite is enabled.
   */
  private Credentials credentials() throws RequestNotSentException {
    SSLContext context;
    try {
      context = Objects.requireNonNull(source.get(), "The TLS context supplier returned null");
    } catch (RuntimeException e) {
      throw new RequestNotSentException(
          "KMIP request not sent: the TLS context supplier failed", e, true);
    }
    Credentials last = latest;
    if (last != null && last.context == context) return last;
    String[] suites = cipherSuites;
    if (kmipCipherSuites)
      try {
        suites = Tls.kmipCipherSuites(context).toArray(String[]::new);
      } catch (IllegalStateException e) {
        throw new RequestNotSentException("KMIP request not sent: " + e.getMessage(), e, true);
      }
    Credentials fresh = new Credentials(context, suites);
    latest = fresh;
    return fresh;
  }

  /** An idle pooled connection opened with {@code context} that still looks healthy, or null. */
  private Connection reusable(SSLContext context) {
    if (permits == null) return null;
    for (Connection c; (c = idle.pollFirst()) != null; ) {
      long idleFor = System.nanoTime() - c.lastUsed;
      if (c.context != context
          || idleFor > idleNanos
          || c.raw.isClosed()
          || !(idleFor >= validateNanos ? alive(c) : quiet(c))) {
        discard(c);
        continue;
      }
      return c;
    }
    return null;
  }

  /** A 1 ms read: a timeout means open and quiet; EOF, data or an error means unusable. */
  private boolean alive(Connection c) {
    probes.incrementAndGet();
    try {
      c.socket.setSoTimeout(1);
      c.socket.getInputStream().read();
      return false; // EOF, or unsolicited bytes that would desynchronize framing
    } catch (SocketTimeoutException quiet) {
      return true;
    } catch (IOException dead) {
      return false;
    }
  }

  /**
   * A check that does not wait when nothing has arrived: decrypted bytes the TLS layer holds mean
   * unusable; TLS bytes waiting on the socket (a TLS 1.3 server's NewSessionTicket or KeyUpdate
   * after its reply, or its close_notify) are read through the TLS layer by {@link #alive}, which
   * consumes post-handshake messages; otherwise a one-byte non-blocking read of the socket's
   * channel sees a FIN or reset (a byte read there is lost, but so is the connection). A socket
   * without a channel (through a proxy) is probed.
   */
  private boolean quiet(Connection c) {
    if (c.channel == null) return alive(c);
    quickChecks.incrementAndGet();
    try {
      if (c.socket.getInputStream().available() > 0) return false;
      // A channel socket's available() reads nothing.
      if (c.raw.getInputStream().available() > 0) return alive(c);
      synchronized (c.channel.blockingLock()) {
        c.channel.configureBlocking(false);
        try {
          return c.channel.read(ByteBuffer.allocate(1)) == 0;
        } finally {
          c.channel.configureBlocking(true);
        }
      }
    } catch (IOException | RuntimeException dead) {
      return false;
    }
  }

  /** Pools {@code c}, unless the supplier has returned another context since it was opened. */
  private void release(Connection c) {
    Credentials last = latest;
    if (permits == null
        || closed.get()
        || c.raw.isClosed()
        || last == null
        || last.context != c.context) {
      discard(c);
      return;
    }
    c.lastUsed = System.nanoTime();
    idle.offerFirst(c);
    if (closed.get() && idle.remove(c)) discard(c);
  }

  private void discard(Connection c) {
    active.remove(c.raw);
    try {
      c.raw.close();
    } catch (IOException ignored) {
    }
  }

  /**
   * Closes the idle pooled connections; connections in use are not affected and are pooled again
   * when their exchange ends.
   *
   * <p>The pool has no background reaper: a connection idle past the idle timeout stays open (and
   * keeps its TLS session and the server-side state of that connection) until an exchange next
   * takes it from the pool, or until this method or {@link #close()} runs. Call it periodically to
   * release idle sockets sooner, and after a protocol error that suggests the server is in a bad
   * state.
   *
   * <p>A pooled connection keeps the authentication of the handshake that opened it, and nothing
   * re-checks it later (TLS cannot re-authenticate an open connection without renegotiation). With
   * a fixed context, when the client credentials or the trusted server identity change (rotation, a
   * revoked certificate), build a new transport and close this one; this method alone is not
   * enough, because connections in use when it runs are pooled again afterwards. With a context
   * supplier ({@link #builder(String, int, Supplier)}), make the supplier return a new {@code
   * SSLContext} instead: from the next exchange on, every exchange uses a connection opened with
   * the new context. An idle connection opened with another context is closed when an exchange
   * next takes it from the pool (or by this method), and a connection in use is closed instead of
   * pooled when its exchange ends, if the supplier has returned another context meanwhile. An
   * exchange already under way finishes on its connection.
   */
  public void closeIdleConnections() {
    for (Connection c; (c = idle.pollFirst()) != null; ) discard(c);
  }

  /**
   * Closes idle and in-use connections. Exchanges in progress fail, and later ones fail with a
   * {@link RequestNotSentException}.
   *
   * @throws IOException if closing a connection fails
   */
  @Override
  public void close() throws IOException {
    closed.set(true);
    for (Connection c; (c = idle.pollFirst()) != null; ) discard(c);
    IOException failure = null;
    for (Socket socket : active)
      try {
        socket.close();
      } catch (IOException e) {
        failure = e;
      }
    if (failure != null) throw failure;
  }
}
