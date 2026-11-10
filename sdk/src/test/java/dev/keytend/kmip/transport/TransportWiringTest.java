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

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.*;
import dev.keytend.kmip.TestAwait;
import dev.keytend.kmip.TestKmipServer;
import dev.keytend.kmip.TestTls;
import dev.keytend.kmip.client.*;
import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.model.*;
import java.io.*;
import java.net.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.Test;

/**
 * Transport internals that need a forced interleaving or a view of private buffers, through the
 * package-private test hooks.
 */
class TransportWiringTest {
  private static final byte[] SECRET = "0123456789abcdef-secret-key-bytes".getBytes(UTF_8);

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
            structure(RESPONSE_PAYLOAD, bytes(DATA, SECRET))));
  }

  /** A request carrying secret-looking bytes, so a leftover buffer would be visible. */
  static Ttlv secretRequest() {
    return Messages.request(
        ProtocolVersion.V1_4,
        List.of(
            new Request(
                Operation.ENCRYPT,
                structure(REQUEST_PAYLOAD, bytes(DATA, SECRET)),
                null,
                List.of())),
        RequestOptions.DEFAULT);
  }

  private static boolean zero(byte[] b) {
    for (byte x : b) if (x != 0) return false;
    return true;
  }

  private static boolean contains(byte[] haystack, byte[] needle) {
    outer:
    for (int i = 0; i + needle.length <= haystack.length; i++) {
      for (int j = 0; j < needle.length; j++) if (haystack[i + j] != needle[j]) continue outer;
      return true;
    }
    return false;
  }

  /**
   * An abort (here a cancellation) that has taken the socket but not yet closed it must not
   * close the connection after the exchange handed it to the pool and the next exchange took it.
   * The abort is held between taking and closing the socket until the next exchange is in flight.
   */
  @Test
  void aLateAbortCannotCloseAConnectionHandedToTheNextExchange() throws Exception {
    try (var server = new TestKmipServer("server", TransportWiringTest::queryReply)) {
      server.delay(300);
      try (var transport =
          TlsTransport.builder("localhost", server.port(), TestTls.context("client", "server"))
              .pool(1, Duration.ofSeconds(30))
              .build()) {
        CountDownLatch abortHoldsSocket = new CountDownLatch(1),
            letAbortClose = new CountDownLatch(1);
        transport.beforeAbortClose =
            socket -> {
              abortHoldsSocket.countDown();
              try {
                letAbortClose.await(10, TimeUnit.SECONDS);
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
              }
            };
        ExecutorService threads = Executors.newCachedThreadPool();
        try {
          CallContext first = CallContext.cancellable();
          Future<Ttlv> a = threads.submit(() -> transport.exchange(secretRequest(), first));
          awaitExchanges(server, 1);
          threads.submit(first::cancel); // runs the abort on this thread; the hook holds it
          assertTrue(abortHoldsSocket.await(5, TimeUnit.SECONDS));
          // The reply arrives before the held abort closes anything.
          assertNotNull(a.get(5, TimeUnit.SECONDS));
          Future<Ttlv> b = threads.submit(() -> transport.exchange(secretRequest()));
          awaitExchanges(server, 2); // the next exchange is waiting for its reply
          letAbortClose.countDown(); // the held abort now closes the socket it took
          assertNotNull(b.get(5, TimeUnit.SECONDS), "the next exchange was not disturbed");
          assertEquals(2, transport.connectionsOpened(), "the aborted connection was not pooled");
        } finally {
          letAbortClose.countDown();
          threads.shutdownNow();
        }
      }
    }
  }

  private static void awaitExchanges(TestKmipServer server, int n) {
    TestAwait.await(n + " exchanges").until(() -> server.exchangeCount() >= n);
    assertEquals(n, server.exchangeCount());
  }

  /**
   * Close() that runs while an exchange is about to let go of the lock (so close() cannot
   * take it) must still lead to the secrets being wiped.
   */
  @Test
  void closeWhileAnExchangeReleasesTheLockStillWipesTheSecrets() throws Exception {
    var transport =
        new HashedPasswordTransport(
            r -> {
              throw new IOException("server gone");
            },
            "alice",
            "secret".toCharArray());
    transport.beforeUnlock =
        () -> {
          try {
            transport.close(); // cannot take the lock: this exchange still holds it
          } catch (IOException e) {
            throw new UncheckedIOException(e);
          }
        };
    Ttlv request =
        Messages.request(
            ProtocolVersion.V2_1, List.of(Requests.query().build()), RequestOptions.DEFAULT);
    assertThrows(IOException.class, () -> transport.exchange(request));
    assertTrue(transport.wiped(), "the secrets outlived close()");
  }

  /**
   * Every encoded request buffer is wiped after use, on success, after a failure and
   * when the call is not sent at all.
   */
  @Test
  void tlsWipesEveryEncodedRequestBuffer() throws Exception {
    byte[] expected = new TtlvCodec().encode(secretRequest());
    try (var server = new TestKmipServer("server", TransportWiringTest::queryReply);
        var transport =
            TlsTransport.builder("localhost", server.port(), TestTls.context("client", "server"))
                .build()) {
      List<byte[]> encoded = new CopyOnWriteArrayList<>(), wiped = new CopyOnWriteArrayList<>();
      List<byte[]> contentBeforeWipe = new CopyOnWriteArrayList<>();
      transport.afterEncode = encoded::add;
      transport.beforeWipe =
          b -> {
            wiped.add(b);
            contentBeforeWipe.add(b.clone());
          };

      assertNotNull(transport.exchange(secretRequest()));
      server.delay(5_000);
      assertThrows(
          SocketTimeoutException.class,
          () ->
              transport.exchange(secretRequest(), CallContext.withTimeout(Duration.ofMillis(200))));
      CallContext canceled = CallContext.cancellable();
      canceled.cancel();
      assertThrows(
          RequestNotSentException.class, () -> transport.exchange(secretRequest(), canceled));
      transport.close();
      assertThrows(RequestNotSentException.class, () -> transport.exchange(secretRequest()));

      for (byte[] b : encoded) {
        assertTrue(wiped.stream().anyMatch(w -> w == b), "an encoded buffer was not wiped");
        assertTrue(zero(b));
      }
      assertEquals(2, encoded.size(), "only requests that could be sent are encoded");
      for (byte[] before : contentBeforeWipe) assertArrayEquals(expected, before);
    }
  }

  /** HTTPS wipes the request body, the HTTP client's copy and the response body. */
  @Test
  void httpsWipesRequestAndResponseBodies() throws Exception {
    TtlvCodec codec = new TtlvCodec();
    byte[] expectedRequest = codec.encode(secretRequest());
    byte[] expectedResponse = codec.encode(queryReply(secretRequest()));
    HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setHttpsConfigurator(new HttpsConfigurator(TestTls.context("server", "client")));
    server.createContext(
        "/kmip",
        exchange -> {
          byte[] reply =
              codec.encode(queryReply(codec.decode(exchange.getRequestBody().readAllBytes())));
          exchange.getResponseHeaders().add("Content-Type", "application/octet-stream");
          exchange.sendResponseHeaders(200, reply.length);
          exchange.getResponseBody().write(reply);
          exchange.close();
        });
    server.start();
    try (var transport =
        new HttpsTransport(
            URI.create("https://localhost:" + server.getAddress().getPort() + "/kmip"),
            TestTls.context("client", "server"),
            HttpsTransport.Encoding.TTLV)) {
      List<byte[]> wiped = new CopyOnWriteArrayList<>(), before = new CopyOnWriteArrayList<>();
      transport.beforeWipe =
          b -> {
            wiped.add(b);
            before.add(b.clone());
          };
      Ttlv reply = transport.exchange(secretRequest());
      assertArrayEquals(
          SECRET, reply.require(BATCH_ITEM).require(RESPONSE_PAYLOAD).require(DATA).bytesValue());
      assertEquals(
          2,
          before.stream().filter(b -> Arrays.equals(b, expectedRequest)).count(),
          "the request body and the HTTP client's copy");
      assertEquals(1, before.stream().filter(b -> Arrays.equals(b, expectedResponse)).count());
      for (byte[] b : wiped) assertTrue(zero(b));
      assertFalse(wiped.stream().anyMatch(b -> contains(b, SECRET)));
    } finally {
      server.stop(0);
    }
  }

  /** A TCP peer that accepts connections and never says anything (no TLS handshake). */
  static final class SilentPeer implements AutoCloseable {
    final ServerSocket server = new ServerSocket(0, 200, InetAddress.getLoopbackAddress());
    final List<Socket> accepted = new CopyOnWriteArrayList<>();

    SilentPeer() throws IOException {
      Thread acceptor =
          new Thread(
              () -> {
                try {
                  while (true) accepted.add(server.accept());
                } catch (IOException closed) {
                  // done
                }
              },
              "silent-peer");
      acceptor.setDaemon(true);
      acceptor.start();
    }

    int port() {
      return server.getLocalPort();
    }

    @Override
    public void close() throws IOException {
      server.close();
      for (Socket s : accepted) s.close();
    }
  }

  private static TlsTransport.Builder towards(SilentPeer peer) throws Exception {
    return TlsTransport.builder("localhost", peer.port(), TestTls.context("client", "server"))
        .connectTimeout(Duration.ofSeconds(10))
        .readTimeout(Duration.ofSeconds(10));
  }

  /** The exchange fails as not sent, locally, because it was canceled, well before any timeout. */
  private static void assertCanceledQuickly(Callable<Ttlv> exchange) {
    long start = System.nanoTime();
    RequestNotSentException e = assertThrows(RequestNotSentException.class, exchange::call);
    long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
    assertTrue(millis < 2_000, "took " + millis + " ms");
    assertInstanceOf(InterruptedIOException.class, e.getCause(), String.valueOf(e.getCause()));
    assertTrue(e.getCause().getMessage().contains("canceled"), e.getCause().getMessage());
  }

  /**
   * A cancellation whose listener ran while the exchange had no socket yet was lost: the
   * exchange then connected and waited out the handshake (canceling in afterEncode against a peer that never does TLS
   * blocked for the read timeout). Here the
   * cancellation comes at that point, and right after the pool permit is taken.
   */
  @Test
  void aCancellationBeforeAnySocketExistsStopsTheExchange() throws Exception {
    try (var peer = new SilentPeer();
        var transport = towards(peer).build();
        var pooled = towards(peer).pool(1, Duration.ofSeconds(30)).build()) {
      CallContext early = CallContext.cancellable();
      transport.afterEncode = b -> early.cancel();
      assertCanceledQuickly(() -> transport.exchange(secretRequest(), early));
      CallContext afterPermit = CallContext.cancellable();
      pooled.afterPermit = afterPermit::cancel;
      assertCanceledQuickly(() -> pooled.exchange(secretRequest(), afterPermit));
      assertEquals(0, peer.accepted.size(), "nothing connected after the cancellation");
      // The permit was returned: a later exchange gets one at once (and is canceled too).
      pooled.afterPermit = null;
      CallContext next = CallContext.cancellable();
      transport.afterEncode = null;
      Executors.newSingleThreadScheduledExecutor()
          .schedule(next::cancel, 200, TimeUnit.MILLISECONDS);
      assertCanceledQuickly(() -> pooled.exchange(secretRequest(), next));
    }
  }

  /**
   * Cancellations at arbitrary moments around connecting (before, during and after the
   * socket is published) all end the exchange promptly; before the fix, those before publication
   * left it waiting for the read timeout.
   */
  @Test
  void aCancellationAtAnyMomentEndsTheExchangePromptly() throws Exception {
    ScheduledExecutorService cancels = Executors.newScheduledThreadPool(2);
    try (var peer = new SilentPeer();
        var transport = towards(peer).build()) {
      Random random = new Random(7);
      for (int i = 0; i < 300; i++) {
        CallContext context = CallContext.cancellable();
        cancels.schedule(context::cancel, random.nextInt(400), TimeUnit.MICROSECONDS);
        assertCanceledQuickly(() -> transport.exchange(secretRequest(), context));
      }
    } finally {
      cancels.shutdownNow();
    }
  }

  /**
   * The connect timeout ("TCP and TLS connection timeout") now covers the handshake. A peer
   * that accepts but never handshakes used to hold the exchange for the read timeout.
   */
  @Test
  void theConnectTimeoutCoversTheTlsHandshake() throws Exception {
    try (var peer = new SilentPeer();
        var transport = towards(peer).connectTimeout(Duration.ofMillis(300)).build()) {
      long start = System.nanoTime();
      RequestNotSentException e =
          assertThrows(RequestNotSentException.class, () -> transport.exchange(secretRequest()));
      long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
      assertTrue(millis >= 250 && millis < 3_000, "took " + millis + " ms");
      assertInstanceOf(SocketTimeoutException.class, e.getCause());
      assertTrue(e.getCause().getMessage().contains("TLS handshake"), e.getCause().getMessage());
      assertFalse(e.local(), "the endpoint's failure, not the caller's");
      assertEquals(1, peer.accepted.size());
    }
  }

  /** An HTTPS server whose /kmip answers every request with {@code reply}. */
  private static HttpsServer https(HttpHandler reply) throws Exception {
    HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.setHttpsConfigurator(new HttpsConfigurator(TestTls.context("server", "client")));
    server.createContext("/kmip", reply);
    server.start();
    return server;
  }

  private static HttpsTransport httpsTo(HttpsServer server) throws Exception {
    return new HttpsTransport(
        URI.create("https://localhost:" + server.getAddress().getPort() + "/kmip"),
        TestTls.context("client", "server"),
        HttpsTransport.Encoding.TTLV);
  }

  /**
   * The HTTP client's copy of the request was wiped only after the response decoded, so a
   * malformed response left it in memory. Now both copies are wiped once the response arrived.
   */
  @Test
  void httpsWipesTheRequestCopiesWhenTheResponseDoesNotDecode() throws Exception {
    byte[] expectedRequest = new TtlvCodec().encode(secretRequest());
    HttpsServer server =
        https(
            exchange -> {
              exchange.getRequestBody().readAllBytes();
              byte[] garbage = "not a KMIP message".getBytes(UTF_8);
              exchange.getResponseHeaders().add("Content-Type", "application/octet-stream");
              exchange.sendResponseHeaders(200, garbage.length);
              exchange.getResponseBody().write(garbage);
              exchange.close();
            });
    try (var transport = httpsTo(server)) {
      List<byte[]> wiped = new CopyOnWriteArrayList<>(), before = new CopyOnWriteArrayList<>();
      transport.beforeWipe =
          b -> {
            wiped.add(b);
            before.add(b.clone());
          };
      assertThrows(IOException.class, () -> transport.exchange(secretRequest()));
      assertEquals(
          2,
          before.stream().filter(b -> Arrays.equals(b, expectedRequest)).count(),
          "the request body and the HTTP client's copy");
      for (byte[] b : wiped) assertTrue(zero(b));
    } finally {
      server.stop(0);
    }
  }

  /** The server's Content-Type value is not quoted in the failure (only a fixed text). */
  @Test
  void httpsDoesNotQuoteAnUnexpectedContentType() throws Exception {
    HttpsServer server =
        https(
            exchange -> {
              exchange.getRequestBody().readAllBytes();
              exchange
                  .getResponseHeaders()
                  .add("Content-Type", "SECRET-MATERIAL-987654321; q=SECRET-2");
              exchange.sendResponseHeaders(200, 3);
              exchange.getResponseBody().write(new byte[3]);
              exchange.close();
            });
    try (var transport = httpsTo(server)) {
      IOException e = assertThrows(IOException.class, () -> transport.exchange(secretRequest()));
      assertTrue(e.getMessage().contains("content type"), e.getMessage());
      for (Throwable t = e; t != null; t = t.getCause()) {
        assertFalse(String.valueOf(t).contains("SECRET"), t.toString());
        for (Throwable suppressed : t.getSuppressed())
          assertFalse(String.valueOf(suppressed).contains("SECRET"));
      }
    } finally {
      server.stop(0);
    }
  }
}
