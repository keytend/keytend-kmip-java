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

package dev.keytend.kmip.server;

import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.model.Ttlv;
import java.io.*;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.*;
import javax.net.ServerSocketFactory;
import javax.net.ssl.*;

/**
 * Optional mTLS listener for server-initiated Notify/Put/Query messages, with bounded worker
 * resources.
 *
 * <p><b>Trust model.</b> Mutual TLS authenticates the peer, but every certificate that the
 * {@link SSLContext}'s trust managers accept can push Put (key material) and Notify (state
 * changes) to the handler. Reusing a client context whose CA also issues other clients'
 * certificates therefore lets any of those clients call the listener. Give the listener a trust
 * store that accepts only the KMIP server's certificate or CA, and use {@link
 * Builder#authorize(Predicate)} or a {@link ContextualCallbackHandler} to check the peer's
 * identity (for example its subject or SAN). {@link Builder#peerAddresses(Predicate)} can also
 * refuse connections from unexpected source addresses before any TLS work.
 *
 * <p><b>Bounds.</b> TLS handshakes run on their own pool of {@link Builder#pendingHandshakes(int)}
 * threads with an absolute deadline. A connection holds its thread until its handshake and
 * authorization check are done and it is passed to a worker. When every thread is held, a new
 * connection evicts at most one pending handshake (one whose TLS handshake has not finished) and
 * then waits briefly for the freed thread; if none frees, the new connection is closed. The
 * eviction counts the connections holding threads, plus the new one, by source address:
 *
 * <ul>
 *   <li>If every one comes from a different address, the oldest pending handshake is evicted.
 *       The new connection is served, so connections from many addresses cannot keep the KMIP
 *       server's callback out by holding every thread until the handshake deadline.
 *   <li>Otherwise the oldest pending handshake from the address with the most connections is
 *       evicted, preferring the new connection's own address when it ties for the most. If that
 *       address has no pending handshake (its handshakes have finished and their threads are about
 *       to be free) nothing is evicted. So once a flood from one address holds two threads, its
 *       connections evict only its own, never the KMIP server's handshake from another address,
 *       and connections from other addresses evict the flood's.
 * </ul>
 *
 * <p>So at most {@code pendingHandshakes} handshakes run at once, one more accepted connection
 * waits for a thread, and each arrival evicts at most one other. A flood from many addresses can
 * still evict the KMIP server's handshake by opening {@code pendingHandshakes} connections while
 * it is in progress; {@link Builder#peerAddresses(Predicate)} keeps other addresses out of the
 * pool.
 *
 * <p>Authenticated connections are served by {@code concurrency} workers with a bounded queue; each
 * frame (read, handler, reply write) has an absolute deadline, and an idle connection is closed
 * after the read timeout. Deadlines and {@link #close()} close the TCP connection under the TLS
 * layer, so they never wait for a peer that has stopped reading.
 *
 * @since 0.10.0
 */
public final class CallbackServer implements AutoCloseable {
  /** The connections' deadlines; its thread ends when no deadline is pending. */
  private static final ScheduledThreadPoolExecutor DEADLINES =
      SdkThreads.scheduler("kmip-callback-deadlines");

  /** One accepted connection: the TCP socket and the TLS layer over it. */
  private static final class Connection {
    final Socket raw;
    final SSLSocket tls;
    final InetAddress peer;

    Connection(Socket raw, SSLSocket tls) {
      this.raw = raw;
      this.tls = tls;
      this.peer = raw.getInetAddress();
    }
  }

  private final ServerSocket listener;
  private final SSLSocketFactory tlsFactory;
  private final Thread acceptor;
  private final ThreadPoolExecutor handshakes;
  private final ThreadPoolExecutor workers;
  private final Set<Connection> connections = ConcurrentHashMap.newKeySet();

  /** Connections holding (or, for the newest, waiting for) a handshake thread, oldest first. */
  private final Deque<Connection> holders = new ConcurrentLinkedDeque<>();

  /** The holders whose TLS handshake has not finished: the ones an arrival may evict. */
  private final Set<Connection> pending = ConcurrentHashMap.newKeySet();

  private final int handshakeThreads;
  private final CallbackHandler handler;
  private final Consumer<IOException> errors;
  private final Duration handshakeTimeout, frameTimeout;
  private final int readTimeout;
  private final TtlvCodec codec;
  private final Set<String> knownExtensions;
  private final Predicate<SSLSession> authorizer;
  private final Predicate<InetAddress> peerAddresses;
  private volatile boolean closed;

  /**
   * Binds and starts a listener with the defaults of {@link #builder}. The same as {@code
   * builder(bind, context, handler).errors(errors).build()}.
   *
   * @param bind the local address and port; port 0 picks a free one
   * @param context the listener's TLS context: its key managers hold the listener's certificate,
   *     its trust managers accept the KMIP server's
   * @param handler answers each batch item
   * @param errors receives connection failures and refused peers
   * @throws IOException when the address cannot be bound
   */
  public CallbackServer(
      InetSocketAddress bind,
      SSLContext context,
      CallbackHandler handler,
      Consumer<IOException> errors)
      throws IOException {
    this(builder(bind, context, handler).errors(errors));
  }

  /**
   * Binds and starts a listener with these settings and the other defaults of {@link #builder}.
   *
   * @param bind the local address and port; port 0 picks a free one
   * @param context the listener's TLS context
   * @param handler answers each batch item
   * @param errors receives connection failures and refused peers
   * @param concurrency authenticated connections served at once
   * @param readTimeout per-read timeout, and the longest an authenticated connection may sit idle
   * @param codec decodes requests and encodes responses
   * @throws IOException when the address cannot be bound
   */
  public CallbackServer(
      InetSocketAddress bind,
      SSLContext context,
      CallbackHandler handler,
      Consumer<IOException> errors,
      int concurrency,
      Duration readTimeout,
      TtlvCodec codec)
      throws IOException {
    this(
        builder(bind, context, handler)
            .errors(errors)
            .concurrency(concurrency)
            .readTimeout(readTimeout)
            .codec(codec));
  }

  /**
   * A builder of a listener on {@code bind}. Nothing is bound until {@link Builder#build()}.
   *
   * @param bind the local address and port; port 0 picks a free one
   * @param context the listener's TLS context: its key managers hold the listener's certificate,
   *     its trust managers accept the KMIP server's (the class description says why that matters)
   * @param handler answers each batch item; a {@link ContextualCallbackHandler} also sees the peer
   * @return the builder
   */
  public static Builder builder(
      InetSocketAddress bind, SSLContext context, CallbackHandler handler) {
    return new Builder(bind, context, handler);
  }

  /** Listener settings. Defaults: 4 workers, 16 pending handshakes, 10 s handshake, 30 s read. */
  public static final class Builder {
    private final InetSocketAddress bind;
    private final SSLContext context;
    private final CallbackHandler handler;
    private Consumer<IOException> errors = e -> {};
    private int concurrency = 4, pendingHandshakes = 16;
    private Duration readTimeout = Duration.ofSeconds(30),
        handshakeTimeout = Duration.ofSeconds(10),
        frameTimeout;
    private TtlvCodec codec = new TtlvCodec();
    private Set<String> knownExtensions = Set.of();
    private Predicate<SSLSession> authorizer = session -> true;
    private Predicate<InetAddress> peerAddresses = address -> true;

    private Builder(InetSocketAddress bind, SSLContext context, CallbackHandler handler) {
      this.bind = Objects.requireNonNull(bind, "bind");
      this.context = Objects.requireNonNull(context, "context");
      this.handler = Objects.requireNonNull(handler, "handler");
    }

    /**
     * Receives listener, handshake, authorization (including an exception thrown by the {@link
     * #authorize(Predicate) authorizer}, as the cause), deadline and handler failures.
     */
    public Builder errors(Consumer<IOException> errors) {
      this.errors = Objects.requireNonNull(errors, "errors");
      return this;
    }

    /** Authenticated connections served at once (the queue holds twice as many). */
    public Builder concurrency(int concurrency) {
      if (concurrency < 1) throw new IllegalArgumentException("Invalid listener limits");
      this.concurrency = concurrency;
      return this;
    }

    /**
     * Handshakes in progress at once (default 16). When all are in use, a new connection evicts at
     * most one pending handshake, chosen as the class description says.
     */
    public Builder pendingHandshakes(int pendingHandshakes) {
      if (pendingHandshakes < 1) throw new IllegalArgumentException("Invalid listener limits");
      this.pendingHandshakes = pendingHandshakes;
      return this;
    }

    /** Per-read timeout, and the longest an authenticated connection may sit idle. */
    public Builder readTimeout(Duration readTimeout) {
      this.readTimeout = millis(readTimeout);
      return this;
    }

    /** Absolute deadline for completing the TLS handshake. */
    public Builder handshakeTimeout(Duration handshakeTimeout) {
      this.handshakeTimeout = millis(handshakeTimeout);
      return this;
    }

    /**
     * Absolute deadline for one frame: reading it, running the handler and writing the reply.
     * Defaults to the read timeout. The connection is closed when it passes.
     */
    public Builder frameTimeout(Duration frameTimeout) {
      this.frameTimeout = millis(frameTimeout);
      return this;
    }

    /**
     * The codec that decodes requests and encodes responses. Default: a {@link TtlvCodec} with its
     * default limits.
     *
     * @param codec the codec
     * @return this builder
     */
    public Builder codec(TtlvCodec codec) {
      this.codec = Objects.requireNonNull(codec, "codec");
      return this;
    }

    /** Vendor identifications whose critical Message Extensions the handler understands. */
    public Builder knownExtensions(Set<String> knownExtensions) {
      this.knownExtensions = Set.copyOf(knownExtensions);
      return this;
    }

    /**
     * Runs after the handshake and before any frame is read; a peer that fails is disconnected
     * and reported to {@link #errors}. An exception thrown by the authorizer refuses the peer and
     * is reported as the cause.
     */
    public Builder authorize(Predicate<SSLSession> authorizer) {
      this.authorizer = Objects.requireNonNull(authorizer, "authorizer");
      return this;
    }

    /**
     * Source addresses allowed to connect (for example the KMIP servers' addresses). Other
     * connections are closed when accepted, before any TLS handshake, and reported to {@link
     * #errors}. This is not authentication (addresses can be spoofed on some networks); it keeps
     * strangers from using handshake capacity. Default: every address.
     */
    public Builder peerAddresses(Predicate<InetAddress> allowed) {
      this.peerAddresses = Objects.requireNonNull(allowed, "allowed");
      return this;
    }

    /**
     * Binds the address and starts accepting connections, on daemon threads.
     *
     * @return the listener, which the caller closes
     * @throws IOException when the address cannot be bound
     */
    public CallbackServer build() throws IOException {
      return new CallbackServer(this);
    }

    private static Duration millis(Duration d) {
      if (d.toMillis() < 1 || d.toMillis() > Integer.MAX_VALUE)
        throw new IllegalArgumentException("Invalid listener limits");
      return d;
    }
  }

  private CallbackServer(Builder b) throws IOException {
    handler = b.handler;
    errors = b.errors;
    handshakeTimeout = b.handshakeTimeout;
    frameTimeout = b.frameTimeout == null ? b.readTimeout : b.frameTimeout;
    codec = b.codec;
    knownExtensions = b.knownExtensions;
    authorizer = b.authorizer;
    peerAddresses = b.peerAddresses;
    readTimeout = (int) b.readTimeout.toMillis();
    handshakeThreads = b.pendingHandshakes;
    tlsFactory = b.context.getSocketFactory();
    // Plain TCP accept with TLS layered per connection, so that deadlines and close() can close
    // the TCP socket directly: closing an SSLSocket waits for a writer blocked on a full buffer.
    listener = ServerSocketFactory.getDefault().createServerSocket();
    try {
      listener.bind(b.bind);
    } catch (IOException e) {
      listener.close();
      throw e;
    }
    handshakes =
        new ThreadPoolExecutor(
            b.pendingHandshakes,
            b.pendingHandshakes,
            0,
            TimeUnit.SECONDS,
            new SynchronousQueue<>(),
            daemon("kmip-callback-handshake"),
            new ThreadPoolExecutor.AbortPolicy());
    workers =
        new ThreadPoolExecutor(
            b.concurrency,
            b.concurrency,
            0,
            TimeUnit.SECONDS,
            new ArrayBlockingQueue<>(b.concurrency * 2),
            daemon("kmip-callback"),
            new ThreadPoolExecutor.AbortPolicy());
    acceptor = SdkThreads.daemon(this::acceptLoop, "kmip-callback-accept");
    acceptor.start();
  }

  private void acceptLoop() {
    while (!closed) {
      Socket raw;
      try {
        raw = listener.accept();
      } catch (IOException e) {
        if (!closed) errors.accept(e);
        continue;
      }
      try {
        if (!peerAddresses.test(raw.getInetAddress())) {
          closeQuietly(raw);
          errors.accept(
              new IOException("Callback connection refused from " + raw.getInetAddress()));
          continue;
        }
        raw.setSoTimeout(readTimeout);
        SSLSocket tls = (SSLSocket) tlsFactory.createSocket(raw, null, true); // server mode
        tls.setNeedClientAuth(true);
        tls.setEnabledProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
        Connection connection = new Connection(raw, tls);
        connections.add(connection);
        if (closed) drop(connection);
        else submitHandshake(connection);
      } catch (IOException | RuntimeException e) {
        closeQuietly(raw);
        if (!closed) errors.accept(new IOException("Callback connection setup failed", e));
      }
    }
  }

  private static ThreadFactory daemon(String name) {
    return r -> SdkThreads.daemon(r, name);
  }

  private void submitHandshake(Connection connection) {
    holders.addLast(connection);
    pending.add(connection);
    boolean evicted = false;
    for (int attempt = 0; ; attempt++) {
      try {
        handshakes.execute(
            () -> {
              try {
                handshake(connection);
              } finally {
                holders.remove(connection);
              }
            });
        return;
      } catch (RejectedExecutionException full) {
        if (closed || attempt >= 100) {
          abandon(connection);
          if (!closed) errors.accept(new IOException("Callback handshake capacity exhausted"));
          return;
        }
        // Evict at most one unauthenticated connection per arrival; its handshake thread then
        // fails fast. Fewer holders than threads means a thread is being returned: just retry.
        if (!evicted && holders.size() > handshakeThreads) {
          Connection victim =
              victim(List.copyOf(holders), pending::contains, connection, c -> c.peer);
          if (victim != null && pending.remove(victim)) {
            drop(victim);
            evicted = true;
          }
        }
        try {
          Thread.sleep(1);
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          abandon(connection);
          return;
        }
      }
    }
  }

  private void abandon(Connection connection) {
    pending.remove(connection);
    holders.remove(connection);
    drop(connection);
  }

  /**
   * The pending handshake to evict for {@code arriving}, or null to evict nothing. {@code holders}
   * are the connections holding a handshake thread, oldest first, plus {@code arriving}; {@code
   * evictable} says which of them are still in their TLS handshake. If every holder comes from a
   * different address, the oldest evictable holder. Otherwise the oldest evictable holder from the
   * address with the most holders, with {@code arriving}'s own address chosen on a tie, and null
   * if that address has none. Never {@code arriving} itself.
   *
   * <p>Holders whose handshake has finished still count for their address: a flood whose
   * handshakes failed a moment ago still holds those threads, so its next connection evicts
   * nothing rather than the KMIP server's handshake.
   */
  static <T> T victim(
      List<T> holders, Predicate<T> evictable, T arriving, Function<T, InetAddress> peer) {
    Map<InetAddress, Integer> counts = new HashMap<>();
    for (T c : holders) counts.merge(peer.apply(c), 1, Integer::sum);
    int most = counts.values().stream().max(Integer::compare).orElse(0);
    InetAddress own = peer.apply(arriving);
    InetAddress target = counts.getOrDefault(own, 0) == most ? own : null;
    for (T c : holders) { // oldest first
      if (c == arriving || !evictable.test(c)) continue;
      if (most == 1) return c; // every holder from a different address: the oldest
      InetAddress address = peer.apply(c);
      if (target == null ? counts.get(address) == most : address.equals(target)) return c;
    }
    return null;
  }

  private void handshake(Connection connection) {
    var deadline =
        DEADLINES.schedule(
            () -> drop(connection), handshakeTimeout.toMillis(), TimeUnit.MILLISECONDS);
    CallbackContext context;
    try {
      connection.tls.startHandshake();
      context = CallbackContext.of(connection.tls.getSession());
    } catch (IOException e) {
      drop(connection);
      if (!closed) errors.accept(new IOException("Callback TLS handshake failed", e));
      return;
    } finally {
      deadline.cancel(false);
      pending.remove(connection);
    }
    RuntimeException authorizerFailure = null;
    boolean authorized;
    try {
      authorized = authorizer.test(connection.tls.getSession());
    } catch (RuntimeException e) {
      authorized = false;
      authorizerFailure = e;
    }
    if (!authorized) {
      drop(connection);
      Object subject = context.peerCertificates().get(0).getSubjectX500Principal();
      errors.accept(
          authorizerFailure == null
              ? new IOException("Callback peer not authorized: " + subject)
              : new IOException(
                  "Callback peer not authorized: the authorizer failed for " + subject,
                  authorizerFailure));
      return;
    }
    try {
      workers.execute(() -> serve(connection, context));
    } catch (RejectedExecutionException busy) {
      drop(connection);
      if (!closed) errors.accept(new IOException("Callback workers busy"));
    }
  }

  private void serve(Connection connection, CallbackContext context) {
    SSLSocket socket = connection.tls;
    AtomicBoolean frameExpired = new AtomicBoolean();
    try {
      // A connection may carry successive KMIP frames; the codec reads exactly one at a time.
      PushbackInputStream in = new PushbackInputStream(socket.getInputStream(), 1);
      OutputStream out = socket.getOutputStream();
      while (!closed) {
        int first;
        try {
          first = in.read();
        } catch (SocketTimeoutException idle) {
          break;
        }
        if (first < 0) break;
        in.unread(first);
        var deadline =
            DEADLINES.schedule(
                () -> {
                  frameExpired.set(true);
                  drop(connection);
                },
                frameTimeout.toMillis(),
                TimeUnit.MILLISECONDS);
        try {
          Ttlv request = codec.read(in);
          Ttlv response =
              CallbackMessages.respond(
                  request,
                  handler,
                  knownExtensions,
                  context,
                  e -> errors.accept(new IOException("Callback handler failed", e)));
          out.write(codec.encode(response));
          out.flush();
        } finally {
          deadline.cancel(false);
        }
      }
    } catch (IOException e) {
      if (frameExpired.get() && !closed)
        errors.accept(new IOException("Callback frame deadline exceeded; connection closed", e));
      else if (!closed) errors.accept(e);
    } catch (RuntimeException e) {
      if (!closed) errors.accept(new IOException("Invalid callback message", e));
    } finally {
      closeGracefully(connection);
    }
  }

  /** Sends close_notify if the peer lets it, but never waits longer than the frame deadline. */
  private void closeGracefully(Connection connection) {
    var deadline =
        DEADLINES.schedule(() -> drop(connection), frameTimeout.toMillis(), TimeUnit.MILLISECONDS);
    try {
      connection.tls.close();
    } catch (IOException ignored) {
    } finally {
      deadline.cancel(false);
      drop(connection);
    }
  }

  /** Closes the TCP connection under the TLS layer: never blocks on TLS locks or the peer. */
  private void drop(Connection connection) {
    connections.remove(connection);
    closeQuietly(connection.raw);
  }

  private static void closeQuietly(Socket socket) {
    try {
      socket.close();
    } catch (IOException ignored) {
    }
  }

  /**
   * The local port the listener is bound to: the one picked when {@code bind} gave port 0.
   *
   * @return the port
   */
  public int port() {
    return listener.getLocalPort();
  }

  /**
   * Stops accepting, closes every connection and stops the threads. A handler still running is
   * interrupted.
   *
   * @throws IOException when closing the listening socket fails
   */
  @Override
  public void close() throws IOException {
    closed = true;
    listener.close();
    for (Connection connection : connections) drop(connection);
    handshakes.shutdownNow();
    workers.shutdownNow();
  }
}
