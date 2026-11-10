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

package dev.keytend.kmip;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.*;
import dev.keytend.kmip.client.*;
import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.*;
import java.io.*;
import java.net.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;

/** Transport lifecycle, deadlines and throughput. */
class TransportTest {
  static Ttlv queryReply(Ttlv request) {
    return structure(
        RESPONSE_MESSAGE,
        structure(
            RESPONSE_HEADER,
            request.require(REQUEST_HEADER).require(PROTOCOL_VERSION),
            dateTime(TIME_STAMP, Instant.ofEpochSecond(1700000000)),
            integer(BATCH_COUNT, 1)),
        structure(
            BATCH_ITEM,
            request.require(BATCH_ITEM).require(OPERATION),
            enumeration(RESULT_STATUS, 0),
            structure(RESPONSE_PAYLOAD)));
  }

  static Ttlv query() {
    return Messages.request(
        ProtocolVersion.V1_4, List.of(Requests.query().build()), RequestOptions.DEFAULT);
  }

  static TlsTransport.Builder client(TestKmipServer server) throws Exception {
    return TlsTransport.builder("localhost", server.port(), TestTls.context("client", "server"));
  }

  @Test
  void hashedPasswordCloseCancelsInsteadOfWaiting() throws Exception {
    CountDownLatch entered = new CountDownLatch(1), released = new CountDownLatch(1);
    AtomicBoolean delegateClosed = new AtomicBoolean();
    KmipTransport slow =
        new KmipTransport() {
          @Override
          public Ttlv exchange(Ttlv request) throws IOException {
            entered.countDown();
            try {
              if (!released.await(5, TimeUnit.SECONDS)) throw new IOException("not canceled");
            } catch (InterruptedException e) {
              throw new InterruptedIOException();
            }
            throw new IOException("canceled by close");
          }

          @Override
          public void close() {
            delegateClosed.set(true);
            released.countDown();
          }
        };
    var transport = new HashedPasswordTransport(slow, "alice", "secret".toCharArray());
    var client = new KmipClient(transport, ProtocolVersion.V2_1);
    Future<?> call =
        Executors.newSingleThreadExecutor().submit(() -> client.call(Requests.query().build()));
    assertTrue(entered.await(5, TimeUnit.SECONDS));
    long start = System.nanoTime();
    transport.close();
    assertTrue(System.nanoTime() - start < TimeUnit.MILLISECONDS.toNanos(500), "close blocked");
    assertTrue(delegateClosed.get());
    var e = assertThrows(ExecutionException.class, () -> call.get(5, TimeUnit.SECONDS));
    assertInstanceOf(IOException.class, e.getCause());
    assertThrows(IOException.class, () -> client.call(Requests.query().build()));
  }

  /** The frame buffer grows with the data instead of being allocated from the header. */
  @Test
  void frameBufferGrowsAsBytesArrive() {
    byte[] header = {0x42, 0x00, 0x78, 0x01, 0x00, (byte) 0xF0, 0x00, 0x00}; // ~15.7 MB declared
    int[] largestRead = {0};
    InputStream stalled =
        new InputStream() {
          int pos;

          @Override
          public int read() {
            return pos < 8 ? header[pos++] & 0xff : -1;
          }

          @Override
          public int read(byte[] b, int off, int len) {
            largestRead[0] = Math.max(largestRead[0], len);
            if (pos < 8) {
              int n = Math.min(len, 8 - pos);
              System.arraycopy(header, pos, b, off, n);
              pos += n;
              return n;
            }
            if (pos < 24) {
              pos += 16;
              return Math.min(len, 16);
            }
            return -1;
          }
        };
    assertThrows(EOFException.class, () -> new TtlvCodec().read(stalled));
    assertTrue(largestRead[0] <= 64 * 1024 + 8, "requested " + largestRead[0] + " bytes at once");
  }

  @Test
  void kmipCipherSuiteProfileCanBeRequired_profiles21Section3_1_2() throws Exception {
    SSLContextHolder holder = new SSLContextHolder();
    List<String> suites = Tls.kmipCipherSuites(holder.client);
    assertEquals("TLS_AES_256_GCM_SHA384", suites.get(0));
    assertTrue(Tls.KMIP_CIPHER_SUITES.containsAll(suites));
    try (var server =
            new TestKmipServer("server", TransportTest::queryReply, "TLS_AES_256_GCM_SHA384");
        var ok = client(server).cipherSuites(suites).build()) {
      assertNotNull(ok.exchange(query()));
    }
    // A server offering only a suite outside the profile is refused.
    try (var server =
            new TestKmipServer("server", TransportTest::queryReply, "TLS_AES_128_GCM_SHA256");
        var strict = client(server).cipherSuites(suites).build()) {
      assertThrows(IOException.class, () -> strict.exchange(query()));
    }
  }

  private static final class SSLContextHolder {
    final javax.net.ssl.SSLContext client;

    SSLContextHolder() throws Exception {
      client = TestTls.context("client", "server");
    }
  }

  @Test
  void callContextBoundsAndCancelsOneCall() throws Exception {
    try (var server = new TestKmipServer("server", TransportTest::queryReply)) {
      server.replyDelayMillis = 10_000;
      try (var transport = client(server).readTimeout(Duration.ofSeconds(30)).build()) {
        long start = System.nanoTime();
        assertThrows(
            SocketTimeoutException.class,
            () -> transport.exchange(query(), CallContext.withTimeout(Duration.ofMillis(300))));
        assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(5));
        CallContext cancel = CallContext.cancellable();
        Executors.newSingleThreadScheduledExecutor()
            .schedule(cancel::cancel, 300, TimeUnit.MILLISECONDS);
        start = System.nanoTime();
        assertThrows(InterruptedIOException.class, () -> transport.exchange(query(), cancel));
        assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(5));
      }
    }
  }

  @Test
  void pooledConnectionsAreReusedAndReplacedWhenTheServerClosesThem() throws Exception {
    try (var server = new TestKmipServer("server", TransportTest::queryReply);
        var transport = client(server).pool(2, Duration.ofSeconds(30)).build()) {
      for (int i = 0; i < 20; i++) assertNotNull(transport.exchange(query()));
      assertEquals(1, server.accepted.get(), "sequential exchanges share one connection");
      server.dropConnections();
      Thread.sleep(100);
      assertNotNull(transport.exchange(query()), "a closed idle connection is replaced");
      assertEquals(2, server.accepted.get());
      // Concurrency is bounded by the pool size.
      ExecutorService pool = Executors.newFixedThreadPool(8);
      List<Future<Ttlv>> calls = new ArrayList<>();
      for (int i = 0; i < 32; i++) calls.add(pool.submit(() -> transport.exchange(query())));
      for (Future<Ttlv> f : calls) assertNotNull(f.get(30, TimeUnit.SECONDS));
      pool.shutdown();
      assertTrue(server.accepted.get() <= 4, "at most the pool size connections at a time");
    }
  }

  @Test
  void idleConnectionsExpire() throws Exception {
    try (var server = new TestKmipServer("server", TransportTest::queryReply);
        var transport = client(server).pool(1, Duration.ofMillis(50)).build()) {
      transport.exchange(query());
      Thread.sleep(150);
      transport.exchange(query());
      assertEquals(2, server.accepted.get());
    }
  }

  @Test
  void httpsTimeoutsAndInterruptsUseTheSameTypesAsTls() throws Exception {
    HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setHttpsConfigurator(new HttpsConfigurator(TestTls.context("server", "client")));
    CountDownLatch requested = new CountDownLatch(1);
    server.createContext(
        "/kmip",
        exchange -> {
          exchange.getRequestBody().readAllBytes();
          exchange.getResponseHeaders().add("Content-Type", "application/octet-stream");
          exchange.sendResponseHeaders(200, 0);
          requested.countDown();
          try {
            Thread.sleep(5_000); // headers sent, body stalls
          } catch (InterruptedException ignored) {
          }
          exchange.close();
        });
    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
    try (var transport =
        new HttpsTransport(
            URI.create("https://localhost:" + server.getAddress().getPort() + "/kmip"),
            TestTls.context("client", "server"),
            HttpsTransport.Encoding.TTLV,
            Duration.ofMillis(500),
            1 << 20)) {
      assertThrows(SocketTimeoutException.class, () -> transport.exchange(query()));
      Thread caller = Thread.currentThread();
      Executors.newSingleThreadScheduledExecutor()
          .schedule(caller::interrupt, 200, TimeUnit.MILLISECONDS);
      try (var slow =
          new HttpsTransport(
              URI.create("https://localhost:" + server.getAddress().getPort() + "/kmip"),
              TestTls.context("client", "server"),
              HttpsTransport.Encoding.TTLV,
              Duration.ofSeconds(10),
              1 << 20)) {
        assertThrows(InterruptedIOException.class, () -> slow.exchange(query()));
      } finally {
        Thread.interrupted();
      }
    } finally {
      server.stop(0);
    }
  }

  // ---- HTTPS CallContext and cipher suites ----

  /** A slow delegate that holds HashedPasswordTransport's lock until released. */
  private static KmipTransport holding(CountDownLatch entered, CountDownLatch release) {
    return request -> {
      entered.countDown();
      try {
        release.await(10, TimeUnit.SECONDS);
      } catch (InterruptedException e) {
        throw new InterruptedIOException();
      }
      throw new IOException("done");
    };
  }

  private static Ttlv query21() {
    return Messages.request(
        ProtocolVersion.V2_1, List.of(Requests.query().build()), RequestOptions.DEFAULT);
  }

  /** Cancel() wakes a call waiting for a pooled connection; it is local and not sent. */
  @Test
  void cancelWakesACallQueuedForAPooledConnection() throws Exception {
    try (var server = new TestKmipServer("server", TransportTest::queryReply)) {
      server.replyDelayMillis = 3_000;
      try (var transport = client(server).pool(1, Duration.ofSeconds(30)).build()) {
        ExecutorService threads = Executors.newCachedThreadPool();
        try {
          threads.submit(() -> transport.exchange(query()));
          TestAwait.await("the first exchange arrives").until(() -> server.exchanges.get() > 0);
          CallContext queued = CallContext.cancellable();
          Future<Ttlv> waiting = threads.submit(() -> transport.exchange(query(), queued));
          Thread.sleep(200);
          long start = System.nanoTime();
          queued.cancel();
          var e = assertThrows(ExecutionException.class, () -> waiting.get(5, TimeUnit.SECONDS));
          assertTrue(
              System.nanoTime() - start < TimeUnit.MILLISECONDS.toNanos(1_000),
              "cancel did not wake the wait");
          var notSent = assertInstanceOf(RequestNotSentException.class, e.getCause());
          assertTrue(notSent.local());
          assertTrue(notSent.cancelled());
          assertFalse(notSent.timedOut());
          assertEquals(1, server.exchanges.get(), "the canceled call was never sent");
        } finally {
          threads.shutdownNow();
        }
      }
    }
  }

  /**
   * Cancel() wakes a call waiting for the hashed-password exchange lock, and without a
   * deadline the wait is still bounded by the transport's maximum wait.
   */
  @Test
  void hashedPasswordLockWaitIsCancellableAndBounded() throws Exception {
    CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
    var transport =
        new HashedPasswordTransport(
            holding(entered, release), "alice", "secret".toCharArray(), Duration.ofMillis(300));
    ExecutorService threads = Executors.newCachedThreadPool();
    try {
      threads.submit(() -> transport.exchange(query21()));
      assertTrue(entered.await(5, TimeUnit.SECONDS));
      CallContext queued = CallContext.cancellable();
      Future<Ttlv> waiting = threads.submit(() -> transport.exchange(query21(), queued));
      Thread.sleep(100);
      long start = System.nanoTime();
      queued.cancel();
      var e = assertThrows(ExecutionException.class, () -> waiting.get(5, TimeUnit.SECONDS));
      assertTrue(
          System.nanoTime() - start < TimeUnit.MILLISECONDS.toNanos(1_000),
          "cancel did not wake the wait");
      var canceled = assertInstanceOf(RequestNotSentException.class, e.getCause());
      assertTrue(canceled.local() && canceled.cancelled());

      start = System.nanoTime();
      var timedOut =
          assertThrows(
              RequestNotSentException.class, () -> transport.exchange(query21(), CallContext.NONE));
      assertTrue(
          System.nanoTime() - start < TimeUnit.SECONDS.toNanos(3), "the wait was not bounded");
      assertTrue(timedOut.local() && timedOut.timedOut());
      assertInstanceOf(SocketTimeoutException.class, timedOut.getCause());
    } finally {
      release.countDown();
      threads.shutdownNow();
    }
  }

  /**
   * A deadline or cancellation that takes effect before sending is a local
   * RequestNotSentException whose cause has the documented type, on every transport.
   */
  @Test
  void deadlineOrCancellationBeforeSendingIsNotSentWithATypedCause() throws Exception {
    CallContext canceled = CallContext.cancellable();
    canceled.cancel();
    CallContext expired = CallContext.withTimeout(Duration.ofMillis(1));
    Thread.sleep(20);
    try (var server = TestKmipServer.answeringQueries();
        var tls = client(server).build();
        var https =
            new HttpsTransport(
                URI.create("https://localhost:1/kmip"),
                TestTls.context("client", "server"),
                HttpsTransport.Encoding.TTLV);
        var hashed = new HashedPasswordTransport(r -> null, "u", "p".toCharArray())) {
      KmipTransport plain = r -> null; // the interface's default exchange(request, context)
      Map<String, Callable<?>> calls = new LinkedHashMap<>();
      for (CallContext context : List.of(canceled, expired)) {
        String what = context == canceled ? "canceled" : "expired";
        calls.put("tls " + what, () -> tls.exchange(query(), context));
        calls.put("https " + what, () -> https.exchange(query(), context));
        calls.put("hashed " + what, () -> hashed.exchange(query21(), context));
        calls.put("default " + what, () -> plain.exchange(query(), context));
      }
      for (var call : calls.entrySet()) {
        var e = assertThrows(RequestNotSentException.class, call.getValue()::call, call.getKey());
        assertTrue(e.local(), call.getKey());
        if (call.getKey().endsWith("canceled")) {
          assertTrue(e.cancelled() && !e.timedOut(), call.getKey());
          assertInstanceOf(InterruptedIOException.class, e.getCause(), call.getKey());
        } else {
          assertTrue(e.timedOut() && !e.cancelled(), call.getKey());
          assertInstanceOf(SocketTimeoutException.class, e.getCause(), call.getKey());
        }
      }
      assertEquals(0, server.exchanges.get());
    }
  }

  /** An HTTPS server for the tests below; {@code handler} answers /kmip. */
  static HttpsServer https(HttpHandler handler, String... serverSuites) throws Exception {
    HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setHttpsConfigurator(
        new HttpsConfigurator(TestTls.context("server", "client")) {
          @Override
          public void configure(HttpsParameters params) {
            var p = getSSLContext().getDefaultSSLParameters();
            if (serverSuites.length > 0) p.setCipherSuites(serverSuites);
            params.setSSLParameters(p);
          }
        });
    server.createContext("/kmip", handler);
    server.setExecutor(Executors.newCachedThreadPool());
    server.start();
    return server;
  }

  static URI uri(HttpsServer server) {
    return URI.create("https://localhost:" + server.getAddress().getPort() + "/kmip");
  }

  static HttpHandler answering() {
    TtlvCodec codec = new TtlvCodec();
    return exchange -> {
      byte[] reply =
          codec.encode(queryReply(codec.decode(exchange.getRequestBody().readAllBytes())));
      exchange.getResponseHeaders().add("Content-Type", "application/octet-stream");
      exchange.sendResponseHeaders(200, reply.length);
      exchange.getResponseBody().write(reply);
      exchange.close();
    };
  }

  /** Headers after {@code headerDelay} ms, then a body that stalls for {@code bodyDelay} ms. */
  private static HttpHandler stalling(long headerDelay, long bodyDelay) {
    return exchange -> {
      exchange.getRequestBody().readAllBytes();
      try {
        Thread.sleep(headerDelay);
        exchange.getResponseHeaders().add("Content-Type", "application/octet-stream");
        exchange.sendResponseHeaders(200, 0);
        exchange.getResponseBody().flush(); // the headers leave now; the body stalls
        Thread.sleep(bodyDelay);
      } catch (InterruptedException ignored) {
      }
      exchange.close();
    };
  }

  /** Section C test gap: CallContext deadline and cancellation on HttpsTransport. */
  @Test
  void httpsHonorsTheCallContextBeforeAndAfterTheHeaders() throws Exception {
    for (boolean stallBody : List.of(false, true)) {
      HttpsServer server = https(stallBody ? stalling(0, 5_000) : stalling(5_000, 0));
      try (var transport =
          new HttpsTransport(
              uri(server),
              TestTls.context("client", "server"),
              HttpsTransport.Encoding.TTLV,
              Duration.ofSeconds(30),
              1 << 20)) {
        long start = System.nanoTime();
        assertThrows(
            SocketTimeoutException.class,
            () -> transport.exchange(query(), CallContext.withTimeout(Duration.ofMillis(300))));
        assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(3), "deadline ignored");
        CallContext cancel = CallContext.cancellable();
        var timer = Executors.newSingleThreadScheduledExecutor();
        timer.schedule(cancel::cancel, 300, TimeUnit.MILLISECONDS);
        start = System.nanoTime();
        var e =
            assertThrows(InterruptedIOException.class, () -> transport.exchange(query(), cancel));
        assertFalse(e instanceof SocketTimeoutException, "cancellation reported as a timeout");
        assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(3), "cancel ignored");
        timer.shutdown();
      } finally {
        server.stop(0);
      }
    }
  }

  /**
   * The HTTPS body is read on the transport's dedicated daemon thread, never on a
   * ForkJoinPool common-pool worker (which a blocked read could starve).
   */
  @Test
  void httpsBodyIsReadOnTheDedicatedThread() throws Exception {
    HttpsServer server = https(stalling(0, 5_000));
    ExecutorService caller = Executors.newSingleThreadExecutor();
    try (var transport =
        new HttpsTransport(
            uri(server),
            TestTls.context("client", "server"),
            HttpsTransport.Encoding.TTLV,
            Duration.ofSeconds(30),
            1 << 20)) {
      CallContext context = CallContext.cancellable();
      Future<Ttlv> call = caller.submit(() -> transport.exchange(query(), context));
      Thread reader = null;
      for (int i = 0; i < 300 && reader == null; i++) {
        for (var entry : Thread.getAllStackTraces().entrySet())
          if (Arrays.stream(entry.getValue()).anyMatch(f -> f.getMethodName().equals("readNBytes")))
            reader = entry.getKey();
        if (reader == null) Thread.sleep(10);
      }
      assertNotNull(reader, "no thread is reading the body");
      assertEquals("kmip-https-body", reader.getName());
      assertTrue(reader.isDaemon());
      context.cancel();
      var e = assertThrows(ExecutionException.class, () -> call.get(5, TimeUnit.SECONDS));
      assertInstanceOf(InterruptedIOException.class, e.getCause());
    } finally {
      caller.shutdownNow();
      server.stop(0);
    }
  }

  /** Section C test gap: the HttpsTransport cipher-suite restriction reaches the handshake. */
  @Test
  void httpsCipherSuitesAreApplied() throws Exception {
    List<String> kmip = Tls.kmipCipherSuites(TestTls.context("client", "server"));
    HttpsServer inProfile = https(answering(), "TLS_AES_256_GCM_SHA384");
    HttpsServer outsideProfile = https(answering(), "TLS_AES_128_GCM_SHA256");
    try {
      try (var t =
          new HttpsTransport(
              uri(inProfile),
              TestTls.context("client", "server"),
              HttpsTransport.Encoding.TTLV,
              Duration.ofSeconds(10),
              1 << 20,
              kmip)) {
        assertNotNull(t.exchange(query()));
      }
      // Without the restriction the server outside the profile is reachable ...
      try (var t =
          new HttpsTransport(
              uri(outsideProfile),
              TestTls.context("client", "server"),
              HttpsTransport.Encoding.TTLV)) {
        assertNotNull(t.exchange(query()));
      }
      // ... and with it the handshake is refused before anything is sent.
      try (var t =
          new HttpsTransport(
              uri(outsideProfile),
              TestTls.context("client", "server"),
              HttpsTransport.Encoding.TTLV,
              Duration.ofSeconds(10),
              1 << 20,
              kmip)) {
        var e = assertThrows(RequestNotSentException.class, () -> t.exchange(query()));
        assertInstanceOf(javax.net.ssl.SSLHandshakeException.class, e.getCause());
      }
    } finally {
      inProfile.stop(0);
      outsideProfile.stop(0);
    }
  }
}
