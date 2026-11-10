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

import static dev.keytend.kmip.kms.SlowEndpointFailoverTest.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.TestKmipServer;
import dev.keytend.kmip.TestTls;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.*;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Failover when an endpoint is cut during its TLS handshake or answers slowly, short views,
 * attempt counts and sealing streams. The TLS cases use a proxy that holds back
 * the server's first bytes, so a handshake is slow (the in-memory transport has none).
 */
class TlsHandshakeFailoverTest {
  /** Probe output, kept for debugging. */
  static void log(String line) {}

  final List<Kms> clients = new ArrayList<>();
  final List<AutoCloseable> closeables = new ArrayList<>();

  @AfterEach
  void cleanUp() throws Exception {
    clients.forEach(Kms::close);
    for (AutoCloseable c : closeables) c.close();
  }

  Kms connect(KmsConfig.Builder builder) {
    Kms kms = Kms.connect(builder.build());
    clients.add(kms);
    return kms;
  }

  /** A TCP proxy to {@code target} that holds the server's first bytes (the TLS ServerHello) back. */
  static final class SlowHandshakeProxy implements AutoCloseable {
    final ServerSocket listener = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    final AtomicInteger accepted = new AtomicInteger();
    volatile long delayMillis;
    final List<Socket> sockets = Collections.synchronizedList(new ArrayList<>());
    // Set under the sockets' lock before the listener closes: a connection accept() returns after
    // close() began is dropped, never forwarded.
    boolean closed;
    // For the test of that race: runs after accept() returns, before the connection is kept.
    volatile Runnable afterAccept = () -> {};

    SlowHandshakeProxy(int target, long delayMillis) throws IOException {
      this.delayMillis = delayMillis;
      Thread t =
          new Thread(
              () -> {
                while (!listener.isClosed()) {
                  try {
                    Socket client = listener.accept();
                    afterAccept.run();
                    if (!keep(client)) return;
                    accepted.incrementAndGet();
                    Socket server = new Socket(InetAddress.getLoopbackAddress(), target);
                    if (!keep(server)) {
                      client.close();
                      return;
                    }
                    pump(client, server, 0);
                    pump(server, client, this.delayMillis);
                  } catch (IOException e) {
                    return;
                  }
                }
              });
      t.setDaemon(true);
      t.start();
    }

    int port() {
      return listener.getLocalPort();
    }

    /** Keeps a socket to close with the proxy, or closes it now if the proxy is closed. */
    boolean keep(Socket s) throws IOException {
      synchronized (sockets) {
        if (!closed) {
          sockets.add(s);
          return true;
        }
      }
      s.close();
      return false;
    }

    static void pump(Socket from, Socket to, long firstDelay) {
      Thread t =
          new Thread(
              () -> {
                try {
                  InputStream in = from.getInputStream();
                  OutputStream out = to.getOutputStream();
                  byte[] buf = new byte[16384];
                  boolean first = true;
                  int n;
                  while ((n = in.read(buf)) >= 0) {
                    if (first && firstDelay > 0) Thread.sleep(firstDelay);
                    first = false;
                    out.write(buf, 0, n);
                    out.flush();
                  }
                } catch (Exception ignored) {
                } finally {
                  try {
                    from.close();
                    to.close();
                  } catch (IOException ignored) {
                  }
                }
              });
      t.setDaemon(true);
      t.start();
    }

    @Override
    public void close() throws IOException {
      synchronized (sockets) {
        closed = true;
      }
      listener.close();
      synchronized (sockets) {
        for (Socket s : sockets) s.close();
      }
    }
  }

  static int closedPort() throws IOException {
    try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      return s.getLocalPort();
    }
  }

  TestKmipServer tlsServer(InMemoryKmipServer store) throws Exception {
    TestKmipServer tls =
        new TestKmipServer(
            "server",
            request -> {
              try {
                return store.exchange(request);
              } catch (IOException e) {
                throw new UncheckedIOException(e);
              }
            });
    closeables.add(tls);
    return tls;
  }

  // ---- the resume covers an endpoint cut during its TLS handshake ----

  /**
   * {@code SlowEndpointFailoverTest.connectGivesASlowFirstEndpointTheRestWhenTheOthersFail} over
   * real TLS, with the slowness in the handshake instead of the Discover Versions reply: A
   * completes the handshake after 450 ms, B refuses connections, 900 ms deadline (300 ms attempt
   * timeout). A must get the rest of the deadline once B has failed.
   */
  @Test
  void connectResumesAnEndpointCutDuringItsTlsHandshake() throws Exception {
    InMemoryKmipServer store = InMemoryKmipServer.of(KmipVersion.V2_1);
    TestKmipServer real = tlsServer(store);
    SlowHandshakeProxy a = new SlowHandshakeProxy(real.port(), 450);
    closeables.add(a);
    int b = closedPort();
    Recorder events = new Recorder();
    long start = System.nanoTime();
    try {
      Kms kms =
          connect(
              KmsConfig.builder()
                  .tls(TestTls.context("client", "server"))
                  .endpoints("localhost:" + a.port(), "localhost:" + b)
                  .versions(KmipVersion.V2_1)
                  .callTimeout(Duration.ofMillis(900))
                  .addListener(events));
      log(
          "TLS connect: connected after "
              + millisSince(start)
              + " ms, accepted "
              + a.accepted.get());
      kms.ping();
    } catch (KmsException e) {
      fail(
          "connect failed after "
              + millisSince(start)
              + " ms of 900 with A accepted "
              + a.accepted.get()
              + " time(s): "
              + e
              + " events "
              + events.unavailable
              + " "
              + events.why);
    }
  }

  /** The same for a read: A is cut during the handshake of a new connection, B refuses. */
  @Test
  void aReadResumesAnEndpointCutDuringItsTlsHandshake() throws Exception {
    InMemoryKmipServer store = InMemoryKmipServer.of(KmipVersion.V2_1);
    TestKmipServer real = tlsServer(store);
    SlowHandshakeProxy a = new SlowHandshakeProxy(real.port(), 0);
    closeables.add(a);
    int b = closedPort();
    Recorder events = new Recorder();
    Kms kms =
        connect(
            KmsConfig.builder()
                .tls(TestTls.context("client", "server"))
                .endpoints("localhost:" + a.port(), "localhost:" + b)
                .versions(KmipVersion.V2_1)
                .poolSize(0)
                .callTimeout(Duration.ofMillis(900))
                .retryPolicy(
                    noBackoff().maxAttempts(2).attemptTimeout(Duration.ofMillis(300)).build())
                .addListener(events));
    a.delayMillis = 450;
    long start = System.nanoTime();
    try {
      kms.ping();
      log("TLS read: ping after " + millisSince(start) + " ms");
    } catch (KmsException e) {
      fail(
          "ping failed after "
              + millisSince(start)
              + " ms of 900, A accepted "
              + a.accepted.get()
              + " connections: "
              + e
              + " / events "
              + events.unavailable
              + " "
              + events.why);
    }
  }

  /**
   * Control for the read above: the same, with the slowness in the reply instead of the handshake,
   * succeeds.
   */
  @Test
  void controlAReadResumesAnEndpointWhoseReplyIsSlow() throws Exception {
    InMemoryKmipServer store = InMemoryKmipServer.of(KmipVersion.V2_1);
    TestKmipServer real = tlsServer(store);
    int b = closedPort();
    Kms kms =
        connect(
            KmsConfig.builder()
                .tls(TestTls.context("client", "server"))
                .endpoints("localhost:" + real.port(), "localhost:" + b)
                .versions(KmipVersion.V2_1)
                .poolSize(0)
                .callTimeout(Duration.ofMillis(900))
                .retryPolicy(
                    noBackoff().maxAttempts(2).attemptTimeout(Duration.ofMillis(300)).build()));
    real.delay(450);
    long start = System.nanoTime();
    kms.ping();
    log("control ping after " + millisSince(start) + " ms");
  }

  // ---- a short view's deadline during a TLS handshake neither reports nor cools the endpoint ----

  /**
   * In a short view a probe's timeout is the caller's own deadline. Over real TLS the
   * probe of a never-contacted replica needs a handshake; a 150 ms view that ends during B's 2 s
   * handshake reports B unavailable and cools it down, unlike the in-memory test
   * aShortViewsProbeTimeoutStaysLocalUntilTheEndpointIsSilentForACallTimeout.
   */
  @Test
  void aShortViewEndingDuringAHandshakeStaysLocal() throws Exception {
    InMemoryKmipServer store = InMemoryKmipServer.of(KmipVersion.V2_1);
    TestKmipServer real = tlsServer(store);
    SlowHandshakeProxy a = new SlowHandshakeProxy(real.port(), 0);
    SlowHandshakeProxy b = new SlowHandshakeProxy(real.port(), 2000);
    closeables.add(a);
    closeables.add(b);
    Recorder events = new Recorder();
    Kms kms =
        connect(
            KmsConfig.builder()
                .tls(TestTls.context("client", "server"))
                .endpoints("localhost:" + a.port(), "localhost:" + b.port())
                .versions(KmipVersion.V2_1)
                .poolSize(0)
                .callTimeout(Duration.ofSeconds(3))
                .retryPolicy(noBackoff().maxAttempts(2).build())
                .addListener(events));
    a.close(); // A now refuses connections
    Kms quick = kms.withTimeout(Duration.ofMillis(150));
    assertThrows(TransientException.class, quick::ping);
    log("short view: events " + events.unavailable + " " + events.why);
    assertEquals(
        List.of("localhost:" + a.port()),
        events.unavailable,
        "B reported unavailable for the caller's own 150 ms deadline: " + events.why);
  }

  /**
   * The proxy itself: a connection that accept() returns while close() runs is dropped, not
   * forwarded. Before, it was forwarded, so an endpoint the tests had closed could still answer.
   */
  @Test
  void aClosedProxyDropsAConnectionAcceptedDuringItsClose() throws Exception {
    try (ServerSocket target = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
      SlowHandshakeProxy proxy = new SlowHandshakeProxy(target.getLocalPort(), 0);
      closeables.add(proxy);
      java.util.concurrent.CountDownLatch accepted = new java.util.concurrent.CountDownLatch(1);
      java.util.concurrent.CountDownLatch closing = new java.util.concurrent.CountDownLatch(1);
      proxy.afterAccept =
          () -> {
            accepted.countDown();
            try {
              closing.await();
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            }
          };
      try (Socket client = new Socket(InetAddress.getLoopbackAddress(), proxy.port())) {
        assertTrue(accepted.await(5, java.util.concurrent.TimeUnit.SECONDS));
        proxy.close();
        closing.countDown();
        client.setSoTimeout(5000);
        assertEquals(-1, client.getInputStream().read(), "the proxy closed the late connection");
        assertEquals(0, proxy.accepted.get(), "nothing was forwarded");
      }
    }
  }

  /** The same with an established endpoint (new connection per call), on the request path. */
  @Test
  void aShortViewEndingDuringAHandshakeDoesNotMoveTraffic() throws Exception {
    InMemoryKmipServer store = InMemoryKmipServer.of(KmipVersion.V2_1);
    TestKmipServer real = tlsServer(store);
    SlowHandshakeProxy a = new SlowHandshakeProxy(real.port(), 0);
    closeables.add(a);
    TestKmipServer b = tlsServer(store);
    Recorder events = new Recorder();
    Kms kms =
        connect(
            KmsConfig.builder()
                .tls(TestTls.context("client", "server"))
                .endpoints("localhost:" + a.port(), "localhost:" + b.port())
                .versions(KmipVersion.V2_1)
                .poolSize(0)
                .callTimeout(Duration.ofSeconds(3))
                .addListener(events));
    kms.ping();
    a.delayMillis = 2000;
    assertThrows(TransientException.class, kms.withTimeout(Duration.ofMillis(150))::ping);
    log("short view, A cut: events " + events.unavailable + " " + events.why);
    assertEquals(
        List.of(),
        events.unavailable,
        "A reported for the caller's own short deadline: " + events.why);
    int atB = b.exchangeCount();
    a.delayMillis = 0;
    kms.ping();
    assertEquals(
        atB, b.exchangeCount(), "traffic moved to B after the caller's own short deadline");
  }

  /**
   * Control for {@code connectResumesAnEndpointCutDuringItsTlsHandshake}: a slow Discover Versions
   * reply over real TLS is resumed and connects.
   */
  @Test
  void controlConnectResumesASlowReplyOverTls() throws Exception {
    InMemoryKmipServer store = InMemoryKmipServer.of(KmipVersion.V2_1);
    TestKmipServer real = tlsServer(store);
    real.delay(450);
    int b = closedPort();
    long start = System.nanoTime();
    connect(
        KmsConfig.builder()
            .tls(TestTls.context("client", "server"))
            .endpoints("localhost:" + real.port(), "localhost:" + b)
            .versions(KmipVersion.V2_1)
            .callTimeout(Duration.ofMillis(900)));
    log("control connect after " + millisSince(start) + " ms");
  }

  /**
   * The second half of the case above: after the short view, traffic has moved off the healthy A.
   */
  @Test
  void aShortViewEndingDuringAHandshakeLeavesTheNextCallWhereItWas() throws Exception {
    InMemoryKmipServer store = InMemoryKmipServer.of(KmipVersion.V2_1);
    TestKmipServer real = tlsServer(store);
    SlowHandshakeProxy a = new SlowHandshakeProxy(real.port(), 0);
    closeables.add(a);
    TestKmipServer b = tlsServer(store);
    Kms kms =
        connect(
            KmsConfig.builder()
                .tls(TestTls.context("client", "server"))
                .endpoints("localhost:" + a.port(), "localhost:" + b.port())
                .versions(KmipVersion.V2_1)
                .poolSize(0)
                .callTimeout(Duration.ofSeconds(3)));
    kms.ping();
    a.delayMillis = 2000;
    assertThrows(TransientException.class, kms.withTimeout(Duration.ofMillis(150))::ping);
    a.delayMillis = 0;
    int atB = b.exchangeCount(), atA = a.accepted.get();
    kms.ping();
    log(
        "next ping: B +"
            + (b.exchangeCount() - atB)
            + ", A connections +"
            + (a.accepted.get() - atA));
    assertEquals(
        atB,
        b.exchangeCount(),
        "the next call went to B after the caller's own short deadline on A");
  }

  // ---- an untried healthy endpoint goes before the resume of a known-silent one ----

  @Test
  void aCutOffAttemptLetsAnUntriedEndpointGoBeforeTheResume() {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer c = a.replica();
    AtomicBoolean connected = new AtomicBoolean();
    AtomicInteger aHung = new AtomicInteger(), bTries = new AtomicInteger();
    KmipTransport hungA = slow(a, r -> connected.get(), Duration.ofSeconds(60), aHung);
    KmipTransport refusedB = refused(bTries);
    Recorder events = new Recorder();
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("a:5696", "b:5696", "c:5696")
                .transport(e -> e.host().equals("a") ? hungA : e.host().equals("b") ? refusedB : c)
                .versions(KmipVersion.V2_1)
                .callTimeout(Duration.ofMillis(600))
                .retryPolicy(noBackoff().maxAttempts(2).build())
                .addListener(events));
    connected.set(true);
    int atC = c.exchanges();
    long start = System.nanoTime();
    kms.ping();
    long millis = millisSince(start);
    // The cut-off attempt at A did not use up an attempt: C, not tried yet, gets the extra request,
    // and A is not sent the read again. Before, A was resumed and the call failed at the deadline.
    assertTrue(c.exchanges() - atC > 0, "C got no request");
    assertEquals(1, aHung.get(), "A was sent the read again");
    assertTrue(millis < 550, "answered after " + millis + " ms");
  }

  // ---- a cut endpoint is resumed when a later one offers no acceptable version ----

  @Test
  void connectResumesASlowFirstEndpointWhenTheNextOffersNoAcceptableVersion() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer old = InMemoryKmipServer.of(KmipVersion.V1_4);
    AtomicInteger aProbes = new AtomicInteger();
    KmipTransport slowA =
        slow(server, r -> is(r, Operation.DISCOVER_VERSIONS), Duration.ofMillis(450), aProbes);
    long start = System.nanoTime();
    try {
      connect(
          KmsConfig.builder()
              .endpoints("a:5696", "b:5696")
              .transport(e -> e.host().equals("a") ? slowA : old)
              .versions(KmipVersion.V2_1)
              .callTimeout(Duration.ofMillis(900)));
    } catch (KmsException e) {
      fail(
          "connect: "
              + e.getClass().getSimpleName()
              + " after "
              + millisSince(start)
              + " ms with A probed "
              + aProbes.get()
              + " time(s): "
              + e.getMessage());
    }
  }

  // ---- held-up checks ----

  /** RetryPolicy.none() and maxAttempts(1): exactly one request, never a resume. */
  @Test
  void oneAttemptMeansOneRequest() {
    for (RetryPolicy p :
        List.of(
            RetryPolicy.none(),
            noBackoff().maxAttempts(1).attemptTimeout(Duration.ofMillis(100)).build())) {
      InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
      InMemoryKmipServer b = a.replica();
      AtomicBoolean connected = new AtomicBoolean();
      AtomicInteger aHung = new AtomicInteger();
      KmipTransport hungA = slow(a, r -> connected.get(), Duration.ofSeconds(60), aHung);
      Kms kms =
          connect(
              KmsConfig.builder()
                  .endpoints("a:5696", "b:5696")
                  .transport(e -> e.host().equals("a") ? hungA : b)
                  .versions(KmipVersion.V2_1)
                  .callTimeout(Duration.ofMillis(400))
                  .retryPolicy(p));
      connected.set(true);
      int atB = b.exchanges();
      long start = System.nanoTime();
      assertThrows(TransientException.class, kms::ping);
      long ms = millisSince(start);
      assertEquals(1, aHung.get(), p.toString());
      assertEquals(atB, b.exchanges(), p.toString());
      assertTrue(ms >= 380 && ms < 600, ms + " ms");
    }
  }

  /** A hung Encrypt with retryCrypto off (default) is sent once, never resumed. */
  @Test
  void aHungEncryptIsNeverResent() {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica();
    AtomicBoolean hang = new AtomicBoolean();
    AtomicInteger seen = new AtomicInteger();
    KmipTransport hungA =
        slow(a, r -> hang.get() && is(r, Operation.ENCRYPT), Duration.ofSeconds(60), seen);
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("a:5696", "b:5696")
                .transport(e -> e.host().equals("a") ? hungA : b)
                .versions(KmipVersion.V2_1)
                .callTimeout(Duration.ofMillis(600))
                .retryPolicy(noBackoff().retryCrypto(false).build()));
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    hang.set(true);
    int atB = b.exchanges();
    long start = System.nanoTime();
    assertThrows(KmsException.class, () -> key.encrypt(CipherSpec.aesGcm(), new byte[16]));
    assertEquals(1, seen.get());
    assertEquals(atB, b.exchanges());
    assertTrue(millisSince(start) >= 570);
  }

  /** connect with three endpoints, two slow and one refused: never past the deadline. */
  @Test
  void connectWithSeveralCutOffEndpointsEndsAtTheDeadline() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicInteger aProbes = new AtomicInteger(),
        bProbes = new AtomicInteger(),
        cTries = new AtomicInteger();
    KmipTransport slowA =
        slow(server, r -> is(r, Operation.DISCOVER_VERSIONS), Duration.ofMillis(700), aProbes);
    KmipTransport slowB =
        slow(server, r -> is(r, Operation.DISCOVER_VERSIONS), Duration.ofMillis(700), bProbes);
    KmipTransport refusedC = refused(cTries);
    long start = System.nanoTime();
    assertThrows(
        KmsException.class,
        () ->
            connect(
                KmsConfig.builder()
                    .endpoints("a:5696", "b:5696", "c:5696")
                    .transport(
                        e -> e.host().equals("a") ? slowA : e.host().equals("b") ? slowB : refusedC)
                    .versions(KmipVersion.V2_1)
                    .callTimeout(Duration.ofMillis(900))));
    long ms = millisSince(start);
    log("connect 3 slow: " + ms + " ms, A " + aProbes + " B " + bProbes + " C " + cTries);
    assertTrue(ms < 1000, ms + " ms");
  }

  // ---- streams ----

  @Test
  void sealingStreamLifecycle() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server.configure());
    KeyHandle kek = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    byte[] aad = {1};
    // finish twice, flush after finish, close twice; write after finish throws.
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    SealingStream s = kek.sealing(bytes, aad);
    s.write(new byte[70000]);
    s.finish();
    s.finish();
    s.flush();
    assertThrows(IOException.class, () -> s.write(1));
    s.close();
    s.close();
    s.finish();
    try (InputStream in = kek.opening(new ByteArrayInputStream(bytes.toByteArray()), aad)) {
      assertEquals(70000, in.readAllBytes().length);
    }
    // GZIP wrapped, finished in order.
    ByteArrayOutputStream gzBytes = new ByteArrayOutputStream();
    try (SealingStream sealed = kek.sealing(gzBytes, aad);
        java.util.zip.GZIPOutputStream gz = new java.util.zip.GZIPOutputStream(sealed)) {
      gz.write("hello".repeat(1000).getBytes(UTF_8));
      gz.finish();
      sealed.finish();
    }
    try (InputStream in =
        new java.util.zip.GZIPInputStream(
            kek.opening(new ByteArrayInputStream(gzBytes.toByteArray()), aad))) {
      assertEquals(5000, in.readAllBytes().length);
    }
    // Buffered wrapper finished without flushing: the tail is lost, and close says so.
    ByteArrayOutputStream bufBytes = new ByteArrayOutputStream();
    IOException lost =
        assertThrows(
            IOException.class,
            () -> {
              try (SealingStream sealed = kek.sealing(bufBytes, aad);
                  BufferedOutputStream buf = new BufferedOutputStream(sealed)) {
                buf.write(new byte[100]);
                sealed.finish();
              }
            });
    log("buffered: " + lost);
    // An encrypt failure inside finish (Kms closed is irrelevant: local) - a RuntimeException from
    // out.
    OutputStream exploding =
        new OutputStream() {
          @Override
          public void write(int b) {
            throw new IllegalStateException("boom");
          }

          @Override
          public void write(byte[] b, int off, int len) {
            throw new IllegalStateException("boom");
          }
        };
    SealingStream bad = kek.sealing(exploding, aad);
    bad.write(1);
    assertThrows(IllegalStateException.class, bad::finish);
    assertThrows(IOException.class, bad::finish);
    IOException closing = assertThrows(IOException.class, bad::close);
    assertTrue(closing.getMessage().contains("failed earlier"), closing.getMessage());
  }

  // ---- in-memory server: Decrypt with a Compromised key stays allowed at 1.x ----

  @Test
  void decryptWithACompromisedKeyIsNotRefusedAt1x() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V1_4);
    Kms kms = connect(server.configure());
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    Ciphertext ct = key.encrypt(CipherSpec.aesGcm(), new byte[16]);
    byte[] sealed = key.seal(new byte[5], null);
    key.revoke(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
    assertEquals(16, key.allowingCompromised().decrypt(ct, null).length);
    assertEquals(5, key.allowingCompromised().open(sealed, null).length);
  }

  // ---- DISCOVER_VERSIONS PERMISSION_DENIED on a replica's probe ----

  @Test
  void aReplicaRefusingTheProbe() {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica();
    Recorder events = new Recorder();
    Kms kms = connect(a.configureReplicas(b).addListener(events));
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    a.failNext(ServerOperation.GET_ATTRIBUTES, Fault.UNREACHABLE);
    b.failNext(ServerOperation.DISCOVER_VERSIONS, Fault.PERMISSION_DENIED);
    KmsException e = assertThrows(KmsException.class, key::attributes);
    log(
        "probe refused: "
            + e.getClass().getSimpleName()
            + " "
            + e.getMessage()
            + " events "
            + events.unavailable);
  }
}
