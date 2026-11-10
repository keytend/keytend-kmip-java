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

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.TestTls;
import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.ProtocolVersion;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.transport.RequestNotSentException;
import dev.keytend.kmip.transport.TlsTransport;
import java.nio.file.*;
import java.security.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Supplier;
import javax.net.ssl.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Client credentials that change while a {@link Kms} is in use, through {@link
 * KmsConfig.Builder#tls(Supplier)} and {@link TlsTransport#builder(String, int, Supplier)}, over
 * real mutual TLS.
 */
class CredentialReloadTest {
  private static SSLContext serverContext() throws Exception {
    return TestTls.context("server", "client", "client2");
  }

  private static Kms connect(RecordingTlsServer server, Supplier<SSLContext> source) {
    return Kms.connect(
        KmsConfig.builder().endpoints(server.endpoint()).tls(source).poolSize(4).build());
  }

  private static KeyHandle aes(Kms kms, String name) {
    return kms.keys()
        .createAes(256)
        .named(name)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .create();
  }

  private static Ttlv query() {
    return Messages.request(
        ProtocolVersion.V2_1, List.of(Requests.query().build()), RequestOptions.DEFAULT);
  }

  /**
   * Once the supplier returns a new context, the next call opens a new connection that presents
   * the new client certificate; the idle connection of the old context is closed, not reused; and
   * the new connection is pooled and reused in turn.
   */
  @Test
  void aNewContextFromTheSupplierIsUsedForTheNextCall() throws Exception {
    AtomicReference<SSLContext> current =
        new AtomicReference<>(TestTls.context("client", "server"));
    try (RecordingTlsServer server = new RecordingTlsServer(serverContext());
        Kms kms = connect(server, current::get)) {
      KeyHandle key = aes(kms, "reload");
      key.attributes();
      key.attributes();
      assertEquals(List.of("CN=client"), server.peers, "one pooled connection so far");

      current.set(TestTls.context("client2", "server"));
      assertEquals(KeyState.ACTIVE, key.attributes().state());
      assertEquals(
          List.of("CN=client", "CN=client2"),
          server.peers,
          "the next call presented the new certificate");
      RecordingTlsServer.await(() -> server.ended.get() == 1, "the old idle connection is closed");

      key.attributes();
      key.attributes();
      assertEquals(2, server.peers.size(), "the new connection is reused");
      assertEquals(1, server.ended.get());
    }
  }

  /**
   * The supplier is called once per exchange; while it returns the same instance the pool is
   * reused (one handshake). A connection in use when the supplier changes finishes its exchange and
   * is then closed instead of pooled.
   */
  @Test
  void theSameContextReusesThePoolAndAConnectionInUseIsClosedAfterARotation() throws Exception {
    SSLContext first = TestTls.context("client", "server"),
        second = TestTls.context("client2", "server");
    AtomicReference<SSLContext> current = new AtomicReference<>(first);
    AtomicInteger calls = new AtomicInteger();
    ExecutorService executor = Executors.newSingleThreadExecutor();
    try (RecordingTlsServer server = new RecordingTlsServer(serverContext());
        TlsTransport transport =
            TlsTransport.builder(
                    "localhost",
                    server.port(),
                    () -> {
                      calls.incrementAndGet();
                      return current.get();
                    })
                .pool(2, Duration.ofSeconds(30))
                .build()) {
      for (int i = 0; i < 5; i++) transport.exchange(query());
      assertEquals(1, transport.connectionsOpened());
      assertEquals(5, calls.get(), "consulted once per exchange");

      // An exchange in flight on the first connection while the context changes.
      server.delayMillis = 400;
      Future<Ttlv> slow = executor.submit(() -> transport.exchange(query()));
      RecordingTlsServer.await(() -> server.exchanges.get() == 6, "the slow request arrived");
      server.delayMillis = 0;
      current.set(second);
      transport.exchange(query()); // opens a second connection with the new context
      assertEquals(2, transport.connectionsOpened());
      assertNotNull(slow.get(5, TimeUnit.SECONDS));
      RecordingTlsServer.await(
          () -> server.ended.get() == 1, "the old connection is closed after its exchange");
      assertEquals(List.of("CN=client", "CN=client2"), server.peers);

      for (int i = 0; i < 3; i++) transport.exchange(query());
      assertEquals(
          2, transport.connectionsOpened(), "only the new connection is pooled and reused");
      assertEquals(1, server.ended.get());
    } finally {
      executor.shutdownNow();
    }
  }

  /**
   * A supplier that throws or returns null fails the attempt before anything is sent: a
   * TransientException (also for a mutation, never OutcomeUnknownException) whose causes hold the
   * failure. It is a local failure: the endpoint is not reported unavailable and traffic does not
   * move to the next endpoint. The supplier runs on the calling thread.
   */
  @Test
  void aFailingSupplierIsANotSentLocalFailure() throws Exception {
    SSLContext good = TestTls.context("client", "server");
    AtomicInteger mode = new AtomicInteger();
    Set<Thread> threads = ConcurrentHashMap.newKeySet();
    Supplier<SSLContext> source =
        () -> {
          threads.add(Thread.currentThread());
          return switch (mode.get()) {
            case 1 -> throw new IllegalStateException("credentials are being replaced");
            case 2 -> null;
            default -> good;
          };
        };
    List<String> unavailable = new CopyOnWriteArrayList<>();
    KmsListener listener =
        new KmsListener() {
          @Override
          public void endpointUnavailable(String endpoint, String why) {
            unavailable.add(endpoint);
          }
        };
    try (RecordingTlsServer one = new RecordingTlsServer(serverContext());
        RecordingTlsServer two = new RecordingTlsServer(serverContext());
        Kms kms =
            Kms.connect(
                KmsConfig.builder()
                    .endpoints(one.endpoint(), two.endpoint())
                    .tls(source)
                    .addListener(listener)
                    .retryPolicy(
                        RetryPolicy.builder()
                            .maxAttempts(3)
                            .initialBackoff(Duration.ofMillis(1))
                            .build())
                    .build())) {
      KeyHandle key = aes(kms, "supplied");
      for (int failing : new int[] {1, 2}) {
        mode.set(failing);
        TransientException create = assertThrows(TransientException.class, () -> aes(kms, "never"));
        assertTrue(create.getMessage().startsWith("create"), create.getMessage());
        Class<?> expected = failing == 1 ? IllegalStateException.class : NullPointerException.class;
        assertTrue(causes(create).stream().anyMatch(expected::isInstance), create.toString());
        RequestNotSentException notSent =
            (RequestNotSentException)
                causes(create).stream()
                    .filter(RequestNotSentException.class::isInstance)
                    .findFirst()
                    .orElseThrow();
        assertTrue(notSent.local());
        assertThrows(
            TransientException.class,
            key::attributes,
            "a read is retried, then fails the same way");
      }
      mode.set(0);
      assertEquals(KeyState.ACTIVE, key.attributes().state());
      assertEquals(List.of(), unavailable, "the endpoint is not reported unavailable");
      assertEquals(List.of(), two.peers, "traffic stayed on the first endpoint");
      assertEquals(1, one.peers.size(), "the pooled connection is used again");
      assertEquals(
          Set.of(Thread.currentThread()), threads, "the supplier runs on the calling thread");
    }
    // At connect too: a supplier that fails once does not report the first endpoint unavailable.
    AtomicInteger connectCalls = new AtomicInteger();
    try (RecordingTlsServer one = new RecordingTlsServer(serverContext());
        RecordingTlsServer two = new RecordingTlsServer(serverContext());
        Kms kms =
            Kms.connect(
                KmsConfig.builder()
                    .endpoints(one.endpoint(), two.endpoint())
                    .tls(
                        () -> {
                          if (connectCalls.incrementAndGet() == 1)
                            throw new IllegalStateException("not yet");
                          return good;
                        })
                    .addListener(listener)
                    .build())) {
      assertEquals(KmipVersion.V2_1, kms.version());
      assertEquals(List.of(), unavailable);
    }
  }

  /** With kmipCipherSuites(), the suites are worked out for each supplied context. */
  @Test
  void kmipCipherSuitesApplyToSuppliedContexts() throws Exception {
    SSLContext good = TestTls.context("client", "server");
    // A server offering only a suite outside the KMIP profile is refused.
    try (RecordingTlsServer outside =
        new RecordingTlsServer(serverContext(), "TLS_AES_128_GCM_SHA256")) {
      KmsConfig config =
          KmsConfig.builder()
              .endpoints(outside.endpoint())
              .tls(() -> good)
              .kmipCipherSuites()
              .build();
      assertThrows(TransientException.class, () -> Kms.connect(config));
      Kms.connect(KmsConfig.builder().endpoints(outside.endpoint()).tls(() -> good).build())
          .close();
    }
    try (RecordingTlsServer server = new RecordingTlsServer(serverContext());
        Kms kms =
            Kms.connect(
                KmsConfig.builder()
                    .endpoints(server.endpoint())
                    .tls(() -> good)
                    .kmipCipherSuites()
                    .build())) {
      assertEquals(KmipVersion.V2_1, kms.version());
    }
    // A context that enables no profile suite fails locally, before connecting.
    try (RecordingTlsServer server = new RecordingTlsServer(serverContext());
        TlsTransport transport =
            TlsTransport.builder("localhost", server.port(), () -> new NoKmipSuites(good))
                .kmipCipherSuites()
                .build()) {
      RequestNotSentException e =
          assertThrows(RequestNotSentException.class, () -> transport.exchange(query()));
      assertTrue(e.local());
      assertTrue(e.getMessage().contains("No KMIP profile cipher suite"), e.getMessage());
      assertEquals(0, transport.connectionsOpened());
    }
  }

  /** A context whose defaults enable only a suite outside the KMIP profile. */
  private static final class NoKmipSuites extends SSLContext {
    NoKmipSuites(SSLContext real) {
      super(
          new SSLContextSpi() {
            @Override
            protected void engineInit(KeyManager[] km, TrustManager[] tm, SecureRandom random) {}

            @Override
            protected SSLSocketFactory engineGetSocketFactory() {
              return real.getSocketFactory();
            }

            @Override
            protected SSLServerSocketFactory engineGetServerSocketFactory() {
              return real.getServerSocketFactory();
            }

            @Override
            protected SSLEngine engineCreateSSLEngine() {
              return real.createSSLEngine();
            }

            @Override
            protected SSLEngine engineCreateSSLEngine(String host, int port) {
              return real.createSSLEngine(host, port);
            }

            @Override
            protected SSLSessionContext engineGetServerSessionContext() {
              return real.getServerSessionContext();
            }

            @Override
            protected SSLSessionContext engineGetClientSessionContext() {
              return real.getClientSessionContext();
            }

            @Override
            protected SSLParameters engineGetDefaultSSLParameters() {
              return new SSLParameters(new String[] {"TLS_AES_128_GCM_SHA256"});
            }
          },
          real.getProvider(),
          real.getProtocol());
    }
  }

  /**
   * tls(Supplier) is refused with the other TLS settings, like tls(SSLContext); the two replace each
   * other; build() does not call the supplier.
   */
  @Test
  void configurationRefusesASupplierWithOtherTlsSettings(@TempDir Path dir) throws Exception {
    AtomicInteger calls = new AtomicInteger();
    SSLContext good = TestTls.context("client", "server");
    Supplier<SSLContext> source =
        () -> {
          calls.incrementAndGet();
          return good;
        };
    KeyStore trust = KeyStore.getInstance("PKCS12");
    trust.load(null, null);
    trust.setCertificateEntry("ca", TestTls.certificate("server"));
    char[] password = "changeit".toCharArray();
    List<KmsConfig.Builder> refused =
        List.of(
            KmsConfig.builder().tls(source).trustStore(trust),
            KmsConfig.builder().tls(source).trustSystemDefaults(),
            KmsConfig.builder()
                .clientIdentity(TestTls.identity("client"), password)
                .trustStore(trust)
                .tls(source));
    for (KmsConfig.Builder b : refused) {
      IllegalArgumentException e =
          assertThrows(IllegalArgumentException.class, () -> b.endpoints("localhost").build());
      assertTrue(
          e.getMessage().startsWith("tls(Supplier) and clientIdentity*/trust* both set"),
          e.getMessage());
    }
    assertThrows(
        NullPointerException.class, () -> KmsConfig.builder().tls((Supplier<SSLContext>) null));
    // Certificate authentication without an inspectable identity is accepted, as with
    // tls(SSLContext).
    KmsConfig config = KmsConfig.builder().endpoints("localhost").tls(source).build();
    assertEquals(0, calls.get(), "build() does not call the supplier");
    assertNotNull(config.toBuilder().build());

    // The last of tls(SSLContext) and tls(Supplier) wins.
    SSLContext distrusting = TestTls.context("client", "stranger");
    try (RecordingTlsServer server = new RecordingTlsServer(serverContext())) {
      try (Kms kms =
          Kms.connect(
              KmsConfig.builder()
                  .endpoints(server.endpoint())
                  .tls(distrusting)
                  .tls(source)
                  .build())) {
        assertEquals(KmipVersion.V2_1, kms.version());
      }
      assertThrows(
          PermissionDeniedException.class,
          () ->
              Kms.connect(
                  KmsConfig.builder()
                      .endpoints(server.endpoint())
                      .tls(source)
                      .tls(distrusting)
                      .build()));
    }
  }

  private static List<Throwable> causes(Throwable e) {
    List<Throwable> out = new ArrayList<>();
    for (Throwable t = e; t != null; t = t.getCause()) out.add(t);
    return out;
  }
}
