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

import dev.keytend.kmip.codec.*;
import dev.keytend.kmip.model.Ttlv;
import java.io.*;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.*;
import javax.net.ssl.*;

/**
 * KMIP HTTPS profile, with bounded responses and TTLV/XML/JSON content negotiation.
 *
 * @since 0.10.0
 */
public final class HttpsTransport implements KmipTransport {
  /** How the messages are encoded in the HTTP bodies, as the KMIP HTTPS profile allows. */
  public enum Encoding {
    /** TTLV, the binary encoding, as {@code application/octet-stream}. */
    TTLV("application/octet-stream"),
    /** The KMIP XML encoding, as {@code text/xml}. */
    XML("text/xml"),
    /** The KMIP JSON encoding, as {@code application/json}. */
    JSON("application/json");
    private final String media;

    Encoding(String media) {
      this.media = media;
    }

    /**
     * The media type sent as Content-Type and Accept.
     *
     * @return for example {@code application/octet-stream}
     */
    public String mediaType() {
      return media;
    }
  }

  private final URI endpoint;
  private final HttpClient client;
  private final Encoding encoding;
  private final Duration timeout;
  private final int maxBytes;
  private final TtlvCodec ttlv;
  private final XmlCodec xml;
  private final JsonCodec json;
  private volatile boolean closed;

  /** The exchanges' watchdogs and body readers; their threads end when idle. */
  private static final ScheduledThreadPoolExecutor DEADLINES =
      SdkThreads.scheduler("kmip-https-deadlines");

  private static final ExecutorService BODY_READERS = SdkThreads.cached("kmip-https-body");

  /** The HTTP client's own executor, shut down by {@link #close()}. */
  private final ExecutorService clientThreads = SdkThreads.cached("kmip-https-client");

  private final java.util.Set<CompletableFuture<?>> active = ConcurrentHashMap.newKeySet();
  private final java.util.Set<InputStream> bodies = ConcurrentHashMap.newKeySet();

  /**
   * A transport to {@code endpoint} with a timeout of 30 seconds and responses of at most {@link
   * TtlvCodec#DEFAULT_MAX_BYTES} (16 MiB).
   *
   * @param endpoint the server's HTTPS URI, without user information or fragment
   * @param ssl the TLS context: the client's identity and the server's trust anchors
   * @param encoding how the messages are encoded
   * @throws IllegalArgumentException when {@code endpoint} is not such an HTTPS URI
   */
  public HttpsTransport(URI endpoint, SSLContext ssl, Encoding encoding) {
    this(endpoint, ssl, encoding, Duration.ofSeconds(30), TtlvCodec.DEFAULT_MAX_BYTES);
  }

  /**
   * A transport to {@code endpoint} with the limits given.
   *
   * @param endpoint the server's HTTPS URI, without user information or fragment
   * @param ssl the TLS context: the client's identity and the server's trust anchors
   * @param encoding how the messages are encoded
   * @param timeout the longest one exchange may take, connecting included; positive
   * @param maxBytes the largest response body accepted; at least 8
   * @throws IllegalArgumentException when {@code endpoint} is not such an HTTPS URI, or a limit is
   *     out of range
   */
  public HttpsTransport(
      URI endpoint, SSLContext ssl, Encoding encoding, Duration timeout, int maxBytes) {
    this(endpoint, ssl, encoding, timeout, maxBytes, null);
  }

  /**
   * A transport to {@code endpoint} with the limits and cipher suites given.
   *
   * @param endpoint the server's HTTPS URI, without user information or fragment
   * @param ssl the TLS context: the client's identity and the server's trust anchors
   * @param encoding how the messages are encoded
   * @param timeout the longest one exchange may take, connecting included; positive
   * @param maxBytes the largest response body accepted; at least 8
   * @param cipherSuites the TLS cipher suites to offer, for example {@link
   *     Tls#kmipCipherSuites(SSLContext)}; null keeps the JDK defaults
   * @throws IllegalArgumentException when {@code endpoint} is not such an HTTPS URI, or a limit is
   *     out of range
   */
  public HttpsTransport(
      URI endpoint,
      SSLContext ssl,
      Encoding encoding,
      Duration timeout,
      int maxBytes,
      java.util.List<String> cipherSuites) {
    if (!"https".equalsIgnoreCase(endpoint.getScheme())
        || endpoint.getHost() == null
        || endpoint.getUserInfo() != null
        || endpoint.getFragment() != null)
      throw new IllegalArgumentException(
          "KMIP requires an HTTPS endpoint without userinfo or fragment");
    if (timeout.isNegative() || timeout.isZero() || maxBytes < 8 || maxBytes == Integer.MAX_VALUE)
      throw new IllegalArgumentException("Invalid transport limits");
    this.endpoint = endpoint;
    this.encoding = Objects.requireNonNull(encoding);
    this.timeout = timeout;
    this.maxBytes = maxBytes;
    SSLParameters parameters = new SSLParameters();
    parameters.setProtocols(new String[] {"TLSv1.3", "TLSv1.2"});
    parameters.setEndpointIdentificationAlgorithm("HTTPS");
    if (cipherSuites != null) parameters.setCipherSuites(cipherSuites.toArray(String[]::new));
    HttpClient.Builder builder =
        HttpClient.newBuilder()
            .sslContext(ssl)
            .sslParameters(parameters)
            .version(HttpClient.Version.HTTP_1_1)
            .followRedirects(HttpClient.Redirect.NEVER)
            .connectTimeout(timeout)
            .executor(clientThreads);
    // Built on an SDK thread: the client's selector thread takes its group and (no) class loader.
    HttpClient[] built = new HttpClient[1];
    Throwable[] failed = new Throwable[1];
    Thread setup =
        SdkThreads.daemon(
            () -> {
              try {
                built[0] = builder.build();
              } catch (RuntimeException | Error e) {
                failed[0] = e;
              }
            },
            "kmip-https-setup");
    setup.start();
    boolean interrupted = false;
    while (true)
      try {
        setup.join();
        break;
      } catch (InterruptedException e) {
        interrupted = true;
      }
    if (interrupted) Thread.currentThread().interrupt();
    if (failed[0] != null) {
      clientThreads.shutdownNow();
      if (failed[0] instanceof Error e) throw e;
      throw (RuntimeException) failed[0];
    }
    this.client = built[0];
    ttlv = new TtlvCodec(maxBytes, 64);
    xml = new XmlCodec(maxBytes, 64);
    json = new JsonCodec(maxBytes, 64);
  }

  @Override
  public Ttlv exchange(Ttlv request) throws IOException {
    return exchange(request, CallContext.NONE);
  }

  /**
   * Sends one request. Timeouts and interruption are reported with the same types as {@link
   * TlsTransport}: {@link java.net.SocketTimeoutException} when the exchange deadline (the
   * transport timeout, shortened by {@code context}) passes and {@link InterruptedIOException} when
   * the thread is interrupted or the context canceled. The body is read on a dedicated daemon
   * thread (never the common pool) that the caller awaits within the deadline; a watchdog closes
   * the body on cancellation.
   */
  @Override
  public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
    context.checkNotSent();
    if (closed)
      throw new RequestNotSentException(
          "KMIP request not sent: KMIP transport closed",
          new IOException("KMIP transport closed"),
          true);
    long deadline = context.deadlineBefore(System.nanoTime() + timeout.toNanos());
    long remaining = deadline - System.nanoTime();
    if (remaining <= 0)
      throw new RequestNotSentException(
          "KMIP request not sent",
          new java.net.SocketTimeoutException("KMIP exchange deadline exceeded"),
          true);
    RequestBody body =
        new RequestBody(
            switch (encoding) {
              case TTLV -> ttlv.encode(request);
              case XML -> xml.encode(request);
              case JSON -> json.encode(request);
            });
    byte[] response = null;
    try {
      response = send(body, deadline, remaining, context);
      return switch (encoding) {
        case TTLV -> ttlv.decode(response);
        case XML -> xml.decode(response);
        case JSON -> json.decode(response);
      };
    } finally {
      // Once send() has returned the response body, the exchange is complete and the HTTP client
      // no longer reads its copy of the request, whether or not the response decodes.
      if (response != null) body.wipeCopies(this::wipe);
      body.wipeOriginal(this::wipe);
      if (response != null) wipe(response);
    }
  }

  /** Tests only: sees each buffer the transport wipes, just before it is wiped. */
  volatile java.util.function.Consumer<byte[]> beforeWipe;

  private void wipe(byte[] buffer) {
    var hook = beforeWipe;
    if (hook != null) hook.accept(buffer);
    java.util.Arrays.fill(buffer, (byte) 0);
  }

  /**
   * The encoded request. The HTTP client is given a copy, so the original can be wiped as soon as
   * the exchange ends. The client's copy is wiped only after a complete exchange: after a timeout
   * or cancellation the client may still be sending it, and zeroing it then could deliver a
   * different, well-formed request (for example one with an all-zero key).
   */
  private static final class RequestBody implements Iterable<byte[]> {
    private final byte[] original;
    private final java.util.List<byte[]> copies = new java.util.ArrayList<>();
    private boolean wiped;

    RequestBody(byte[] original) {
      this.original = original;
    }

    int length() {
      return original.length;
    }

    @Override
    public synchronized java.util.Iterator<byte[]> iterator() {
      if (wiped) throw new IllegalStateException("KMIP request body already wiped");
      byte[] copy = original.clone();
      copies.add(copy);
      return java.util.List.of(copy).iterator();
    }

    synchronized void wipeOriginal(java.util.function.Consumer<byte[]> wipe) {
      if (wiped) return;
      wiped = true;
      wipe.accept(original);
    }

    synchronized void wipeCopies(java.util.function.Consumer<byte[]> wipe) {
      for (byte[] copy : copies) wipe.accept(copy);
      copies.clear();
    }
  }

  /** Sends the request and returns the response body (at most {@code maxBytes + 1} bytes). */
  @SuppressWarnings("UndefinedEquals") // each future is removed by identity, as it was added
  private byte[] send(RequestBody body, long deadline, long remaining, CallContext context)
      throws IOException {
    HttpRequest http =
        HttpRequest.newBuilder(endpoint)
            .timeout(Duration.ofNanos(remaining))
            .header("Content-Type", encoding.mediaType())
            .header("Accept", encoding.mediaType())
            .header("Cache-Control", "no-cache")
            .POST(
                HttpRequest.BodyPublishers.fromPublisher(
                    HttpRequest.BodyPublishers.ofByteArrays(body), body.length()))
            .build();
    CompletableFuture<HttpResponse<InputStream>> pending =
        client.sendAsync(http, HttpResponse.BodyHandlers.ofInputStream());
    active.add(pending);
    Closeable cancellation = context.onCancel(() -> pending.cancel(true));
    if (closed) pending.cancel(true);
    try {
      HttpResponse<InputStream> response =
          pending.get(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
      InputStream in = response.body();
      bodies.add(in);
      // Why the body was closed early: a closed body may read as a short stream, not an error.
      java.util.concurrent.atomic.AtomicReference<String> aborted =
          new java.util.concurrent.atomic.AtomicReference<>();
      java.util.function.Consumer<String> abort =
          why -> {
            aborted.compareAndSet(null, why);
            try {
              in.close();
            } catch (IOException ignored) {
            }
          };
      Thread caller = Thread.currentThread();
      // Closing the body at the deadline, on interrupt or on cancel unblocks the read below.
      var watchdog =
          DEADLINES.scheduleAtFixedRate(
              () -> {
                if (caller.isInterrupted()) abort.accept("interrupted");
                else if (System.nanoTime() >= deadline) abort.accept("deadline");
              },
              10,
              10,
              TimeUnit.MILLISECONDS);
      Closeable bodyCancellation = context.onCancel(() -> abort.accept("canceled"));
      try (in) {
        if (closed) throw new IOException("KMIP transport closed");
        if (response.statusCode() != 200)
          throw new IOException("KMIP HTTP status " + response.statusCode());
        String type = response.headers().firstValue("Content-Type").orElse("").split(";")[0].trim();
        // Fixed text: the header value is the server's and could carry anything.
        if (!type.equalsIgnoreCase(encoding.mediaType()))
          throw new IOException(
              "Unexpected KMIP HTTP content type (expected " + encoding.mediaType() + ")");
        // The body is read on a dedicated thread (not the common pool) and awaited interruptibly:
        // on some JDKs a blocked body read reacts neither to interrupts nor to close().
        // 0 pending, 1 handed to the caller, 2 abandoned: the reader then wipes what it read.
        java.util.concurrent.atomic.AtomicInteger handover =
            new java.util.concurrent.atomic.AtomicInteger();
        Future<byte[]> read =
            BODY_READERS.submit(
                () -> {
                  try (in) {
                    byte[] b = in.readNBytes(maxBytes + 1);
                    if (!handover.compareAndSet(0, 1)) wipe(b);
                    return b;
                  }
                });
        byte[] bytes;
        try {
          bytes = read.get(Math.max(1, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
        } catch (InterruptedException e) {
          abandon(read, handover);
          abort.accept("interrupted");
          Thread.currentThread().interrupt();
          throw interrupted("KMIP exchange interrupted", e);
        } catch (TimeoutException e) {
          abandon(read, handover);
          abort.accept("deadline");
          throw timedOut(e);
        } catch (ExecutionException e) {
          throw e.getCause() instanceof IOException io ? io : new IOException(e.getCause());
        }
        try {
          if (aborted.get() != null)
            throw new IOException("KMIP HTTP body closed: " + aborted.get());
          if (bytes.length > maxBytes) throw new IOException("KMIP HTTP response exceeds limit");
          if (closed) throw new IOException("KMIP transport closed");
        } catch (IOException rejected) {
          wipe(bytes);
          throw rejected;
        }
        // Decoded by the caller, outside this block: a malformed reply keeps its own type.
        return bytes;
      } catch (IOException e) {
        String why = aborted.get();
        if (context.isCancelled() || "canceled".equals(why))
          throw interrupted("KMIP call canceled", e);
        if (caller.isInterrupted() || "interrupted".equals(why))
          throw interrupted("KMIP exchange interrupted", e);
        if (System.nanoTime() >= deadline || "deadline".equals(why)) throw timedOut(e);
        throw e;
      } finally {
        watchdog.cancel(false);
        bodyCancellation.close();
        bodies.remove(in);
      }
    } catch (CancellationException e) {
      if (context.isCancelled()) throw interrupted("KMIP call canceled", e);
      throw new IOException("KMIP HTTP canceled", e);
    } catch (InterruptedException e) {
      pending.cancel(true);
      Thread.currentThread().interrupt();
      throw interrupted("KMIP exchange interrupted", e);
    } catch (TimeoutException e) {
      pending.cancel(true);
      throw timedOut(e);
    } catch (ExecutionException e) {
      // The HTTP client reports its own cancellation as a failure, not as a canceled future.
      if (context.isCancelled()) throw interrupted("KMIP call canceled", e.getCause());
      if (e.getCause() instanceof HttpConnectTimeoutException
          || e.getCause() instanceof java.net.ConnectException
          || e.getCause() instanceof javax.net.ssl.SSLHandshakeException)
        throw new RequestNotSentException("KMIP request not sent", e.getCause());
      if (e.getCause() instanceof HttpTimeoutException timeout) throw timedOut(timeout);
      throw new IOException("KMIP HTTP exchange failed", e.getCause());
    } finally {
      cancellation.close();
      active.remove(pending);
    }
  }

  /** Gives up on a body read; whatever it read, now or later, is wiped. */
  private void abandon(Future<byte[]> read, java.util.concurrent.atomic.AtomicInteger handover) {
    if (handover.compareAndSet(0, 2)) {
      read.cancel(true);
      return;
    }
    try {
      wipe(read.get(1, TimeUnit.SECONDS)); // finished just now: wipe its result here
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    } catch (ExecutionException | TimeoutException | CancellationException ignored) {
      // nothing was read, or the reader is stuck past its own result
    }
  }

  private static InterruptedIOException interrupted(String message, Throwable cause) {
    InterruptedIOException e = new InterruptedIOException(message);
    e.initCause(cause);
    return e;
  }

  private static java.net.SocketTimeoutException timedOut(Throwable cause) {
    var e = new java.net.SocketTimeoutException("KMIP exchange deadline exceeded");
    e.initCause(cause);
    return e;
  }

  @Override
  public void close() {
    closed = true;
    for (var future : active) future.cancel(true);
    for (InputStream body : bodies)
      try {
        body.close();
      } catch (IOException ignored) {
      }
    // From JDK 21 the client can be stopped (its selector thread with it), before its executor,
    // which
    // runs its shutdown; on JDK 17 it ends once the client is unreachable.
    try {
      HttpClient.class.getMethod("shutdownNow").invoke(client);
    } catch (ReflectiveOperationException olderJdk) {
      // JDK 17: nothing to call.
    }
    clientThreads.shutdownNow();
  }
}
