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

import static dev.keytend.kmip.TestAwait.await;
import static dev.keytend.kmip.kms.KmsApiTest.pem;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.testing.TlsListener;
import dev.keytend.kmip.testing.TlsListener.ClientAuth;
import dev.keytend.kmip.transport.Tls;
import java.io.IOException;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link TlsListener}: the in-memory server over the SDK's TLS transport, with the SDK's client
 * credentials, on KMIP 1.4, 2.1 and 3.0; client authentication required, optional or not asked
 * for; the server's identity and trust from the {@code kms.tls()} followers; faults, dropped
 * connections and close.
 */
class InMemoryTlsListenerTest {
  static final CustomAttribute TAG = CustomAttribute.client("tls");

  /** A CA, the server's certificate (for localhost) and a client's, as PEM files in {@code dir}. */
  static final class Pki {
    final Issued ca = TestPki.ca("Listener CA");
    final Issued server = TestPki.leaf("in-memory-kms", TestPki.ec(), ca);
    final Issued client = TestPki.leaf("client", TestPki.ec(), ca);
    final Path dir, caPem, clientChain, clientKey;

    Pki(Path dir) throws Exception {
      this.dir = dir;
      caPem = dir.resolve("ca.crt");
      Files.writeString(caPem, pem("CERTIFICATE", ca.certificate().getEncoded()));
      clientChain = dir.resolve("client.crt");
      clientKey = dir.resolve("client.key");
      write(client, clientChain, clientKey);
    }

    void write(Issued leaf, Path chain, Path key) throws Exception {
      Files.writeString(chain, pem("CERTIFICATE", leaf.certificate().getEncoded()));
      Files.writeString(key, pem("PRIVATE KEY", leaf.key().getEncoded()));
    }

    TlsListener.Builder listener(InMemoryKmipServer kms) {
      return kms.tlsListener()
          .identity(server.key(), server.certificate(), ca.certificate())
          .trustAnchors(ca.certificate());
    }

    KmsConfig.Builder client(TlsListener tls) {
      return tls.configure()
          .clientIdentityPem(clientChain, clientKey)
          .trustPem(caPem)
          .connectTimeout(Duration.ofSeconds(5))
          .callTimeout(Duration.ofSeconds(10));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theSdksTlsTransportReachesTheServerAtEachVersion(KmipVersion version, @TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms = Kms.connect(pki.client(tls).maximumVersion(KmipVersion.V3_0).build())) {
      assertEquals(version, kms.version());
      KeyHandle key =
          kms.keys()
              .createAes(256)
              .named("over-tls")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
      assertEquals(java.util.Optional.of(KeyState.ACTIVE), server.state(key.id()));
      assertEquals(KeyState.ACTIVE, key.attributes().state(), "read back over TLS");
      assertEquals(List.of(pki.client.certificate()), tls.clientCertificates());
      assertEquals(1, tls.handshakes(), "one pooled connection");
      assertEquals(List.of(), tls.handshakeFailures());
      assertTrue(tls.port() > 0);
      assertEquals("localhost:" + tls.port(), tls.endpoint());
      assertSame(server, tls.server());
      assertEquals(List.of(), server.violations());
    }
  }

  @Test
  void clientAuthenticationIsRequiredOptionalOrNotAskedFor(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    KmsConfig.Builder anonymous = null;
    // REQUIRED, the default: a client without a certificate is refused, one with is served.
    try (TlsListener tls = pki.listener(server).start()) {
      anonymous =
          tls.configure()
              .trustPem(pki.caPem)
              .usernamePassword("app", "secret".toCharArray())
              .connectTimeout(Duration.ofSeconds(5));
      KmsConfig noCertificate = anonymous.build();
      assertThrows(KmsException.class, () -> Kms.connect(noCertificate).close());
      // The listener records the refusal on its own thread, after the client has seen it.
      await("the listener records the refusal").until(() -> !tls.handshakeFailures().isEmpty());
      assertEquals(0, tls.handshakes());
      try (Kms kms = Kms.connect(pki.client(tls).build())) {
        kms.ping();
      }
      assertEquals(List.of(pki.client.certificate()), tls.clientCertificates());
    }
    // OPTIONAL: both are served; only the certificate presented is recorded.
    try (TlsListener tls = pki.listener(server).clientAuth(ClientAuth.OPTIONAL).start()) {
      try (Kms kms =
          Kms.connect(
              tls.configure()
                  .trustPem(pki.caPem)
                  .usernamePassword("app", "secret".toCharArray())
                  .build())) {
        kms.ping();
      }
      try (Kms kms = Kms.connect(pki.client(tls).build())) {
        kms.ping();
      }
      assertEquals(2, tls.handshakes());
      assertEquals(List.of(pki.client.certificate()), tls.clientCertificates());
    }
    // NONE: no certificate is asked for, so none is presented, and no trust is needed.
    try (TlsListener tls =
        server
            .tlsListener()
            .identity(pki.server.key(), pki.server.certificate())
            .clientAuth(ClientAuth.NONE)
            .start()) {
      try (Kms kms = Kms.connect(pki.client(tls).build())) {
        kms.ping();
      }
      assertEquals(1, tls.handshakes());
      assertEquals(List.of(), tls.clientCertificates());
    }
  }

  @Test
  void aClientTheTrustRefusesAndAServerNotForTheHostAreRefused(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Issued stranger = TestPki.leaf("stranger", TestPki.ec(), TestPki.ca("Other CA"));
    Path chain = dir.resolve("stranger.crt"), key = dir.resolve("stranger.key");
    pki.write(stranger, chain, key);
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig config =
          tls.configure()
              .clientIdentityPem(chain, key)
              .trustPem(pki.caPem)
              .connectTimeout(Duration.ofSeconds(5))
              .build();
      assertThrows(KmsException.class, () -> Kms.connect(config).close());
      assertEquals(0, tls.handshakes());
      await("the listener records the refusal").until(() -> !tls.handshakeFailures().isEmpty());
    }
    // A server certificate without localhost: the SDK checks the host name and refuses it.
    java.security.KeyPair k = TestPki.ec();
    X509Certificate notLocal =
        dev.keytend.kmip.TestX509.certificate("elsewhere", k.getPublic())
            .issuedBy(pki.ca.certificate(), pki.ca.key())
            .dns("kms.example.com")
            .build();
    try (TlsListener tls =
        server
            .tlsListener()
            .identity(k.getPrivate(), notLocal)
            .trustAnchors(pki.ca.certificate())
            .start()) {
      KmsConfig config = pki.client(tls).build();
      assertThrows(KmsException.class, () -> Kms.connect(config).close());
      assertEquals(List.of(), tls.clientCertificates());
    }
  }

  /**
   * The server presents the identity a {@code kms.tls()} follower reads and checks clients with a
   * trust follower, as a node does: the client's certificate is an allowed peer, and a renewed one
   * is admitted by the unknown-peer check at the next connection.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theFollowersOfKmsTlsAreTheListenersIdentityAndTrust(KmipVersion version, @TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer store = InMemoryKmipServer.of(version);
    InMemoryKmipServer served = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms node = TlsIdentityTest.connect(store)) {
      node.tls()
          .register(pki.server.key(), pki.server.certificate(), pki.ca.certificate())
          .named("kms/server")
          .register();
      node.keys().register(pki.ca.certificate()).custom(TAG, "ca").register();
      node.keys().register(pki.client.certificate()).custom(TAG, "client").register();
      try (TlsIdentityFollower identity =
              node.tls().follow("kms/server", TlsIdentityTest.HOURLY, TlsIdentityTest.SCHEDULER);
          TlsTrustFollower trust =
              node.tls()
                  .trustAnchors(
                      KeyQuery.all().custom(TAG, "ca"),
                      KeyQuery.all().custom(TAG, "client"),
                      TlsIdentityTest.HOURLY,
                      TlsIdentityTest.SCHEDULER);
          TlsListener tls =
              served
                  .tlsListener()
                  .keyManager(identity.keyManager())
                  .trustManager(trust.trustManager())
                  .start()) {
        try (Kms kms = Kms.connect(pki.client(tls).build())) {
          kms.ping();
        }
        assertEquals(List.of(pki.client.certificate()), tls.clientCertificates());

        // A renewed client: refused at first (the check runs on the executor), then admitted.
        Issued renewed = TestPki.leaf("client", TestPki.ec(), pki.ca);
        node.keys().register(renewed.certificate()).custom(TAG, "client").register();
        pki.write(renewed, pki.clientChain, pki.clientKey);
        KmsConfig config = pki.client(tls).build();
        assertThrows(KmsException.class, () -> Kms.connect(config).close());
        TlsBackgroundPeerCheckTest.awaitAllowed(trust, renewed.certificate());
        try (Kms kms = Kms.connect(config)) {
          kms.ping();
        }
        assertEquals(
            List.of(pki.client.certificate(), renewed.certificate()), tls.clientCertificates());
      }
      assertEquals(List.of(), store.violations());
    }
  }

  /** The transport's own {@link Tls#context} (a PKCS#12 identity, a PEM CA bundle) connects too. */
  @Test
  void theTransportsTlsContextConnects(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    Path p12 = dir.resolve("client.p12");
    char[] password = "changeit".toCharArray();
    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(null, null);
    store.setKeyEntry(
        "client",
        pki.client.key(),
        password,
        new Certificate[] {pki.client.certificate(), pki.ca.certificate()});
    try (OutputStream out = Files.newOutputStream(p12)) {
      store.store(out, password);
    }
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms = Kms.connect(tls.configure().tls(Tls.context(p12, password, pki.caPem)).build())) {
      kms.ping();
      assertEquals(List.of(pki.client.certificate()), tls.clientCertificates());
    }
    // A context of your own, given to the listener.
    SSLContext own = SSLContext.getInstance("TLS");
    own.init(
        new KeyManager[] {TlsListenerKeys.keyManager(pki.server)},
        new TrustManager[] {TlsBackgroundPeerCheckTest.pkixOf(pki.ca)},
        null);
    try (TlsListener tls = server.tlsListener().context(own).start();
        Kms kms = Kms.connect(pki.client(tls).build())) {
      kms.ping();
      assertEquals(1, tls.handshakes());
    }
  }

  /** The key manager of an identity, as a caller's own server context has. */
  static final class TlsListenerKeys {
    static KeyManager keyManager(Issued identity) throws Exception {
      KeyStore store = KeyStore.getInstance("PKCS12");
      store.load(null, null);
      store.setKeyEntry(
          "server", identity.key(), new char[0], new Certificate[] {identity.certificate()});
      javax.net.ssl.KeyManagerFactory f =
          javax.net.ssl.KeyManagerFactory.getInstance(
              javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
      f.init(store, new char[0]);
      return f.getKeyManagers()[0];
    }
  }

  @Test
  void faultsUnreachableAndDroppedConnectionsBehaveAsANetworkWould(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start()) {
      try (Kms kms = Kms.connect(pki.client(tls).retryPolicy(RetryPolicy.none()).build())) {
        kms.ping();
        // A reply lost: the connection closes without a reply, and the next call reconnects.
        server.failNext(ServerOperation.DISCOVER_VERSIONS, Fault.REPLY_LOST);
        assertThrows(KmsException.class, kms::ping);
        kms.ping();
        // Dropped connections: the pool opens a new one.
        int before = tls.handshakes();
        tls.dropConnections();
        TestAwaitPing.untilServed(kms);
        assertTrue(tls.handshakes() > before, "a new connection after the drop");
      }
      // Unreachable: new connections are closed before their handshake.
      server.unreachable(true);
      int connections = tls.connections();
      KmsConfig config = pki.client(tls).build();
      assertThrows(KmsException.class, () -> Kms.connect(config).close());
      assertEquals(connections, tls.connections(), "not accepted for a handshake");
      server.unreachable(false);
      try (Kms kms = Kms.connect(config)) {
        kms.ping();
      }
    }
  }

  /** Pings until one is served: the first after a drop may meet the closed connection. */
  static final class TestAwaitPing {
    static void untilServed(Kms kms) {
      dev.keytend.kmip.TestAwait.await("a ping is served after the drop")
          .until(
              () -> {
                try {
                  kms.ping();
                  return true;
                } catch (KmsException e) {
                  return false;
                }
              });
    }
  }

  @Test
  void closeStopsListeningAndLeavesTheServer(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    TlsListener tls = pki.listener(server).start();
    int port = tls.port();
    Kms kms = Kms.connect(pki.client(tls).retryPolicy(RetryPolicy.none()).build());
    try {
      kms.ping();
      tls.close();
      tls.close(); // idempotent
      assertTrue(tls.toString().contains("closed"), tls.toString());
      assertThrows(KmsException.class, kms::ping);
      assertThrows(IOException.class, () -> new Socket("localhost", port).close());
    } finally {
      kms.close();
    }
    try (Kms direct = server.connect()) {
      direct.ping(); // the server itself goes on
    }
  }

  @Test
  void theBuilderValidatesAndAFixedPortIsUsed(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    IllegalStateException e =
        assertThrows(IllegalStateException.class, () -> server.tlsListener().start());
    assertTrue(e.getMessage().contains("No server identity"), e.getMessage());
    e =
        assertThrows(
            IllegalStateException.class,
            () ->
                server.tlsListener().identity(pki.server.key(), pki.server.certificate()).start());
    assertTrue(e.getMessage().contains("needs a trust of client certificates"), e.getMessage());
    e =
        assertThrows(
            IllegalStateException.class,
            () ->
                pki.listener(server)
                    .clientAuth(ClientAuth.OPTIONAL)
                    .context(SSLContext.getDefault())
                    .start());
    assertTrue(e.getMessage().contains("use one or the other"), e.getMessage());
    assertThrows(IllegalArgumentException.class, () -> server.tlsListener().port(-1));
    assertThrows(IllegalArgumentException.class, () -> server.tlsListener().port(65536));
    assertThrows(
        IllegalArgumentException.class, () -> server.tlsListener().identity(pki.server.key()));
    assertThrows(IllegalArgumentException.class, () -> server.tlsListener().trustAnchors());
    assertThrows(NullPointerException.class, () -> server.tlsListener().clientAuth(null));

    // Two listeners get two ephemeral ports; a fixed port is the one asked for.
    try (TlsListener a = pki.listener(server).start();
        TlsListener b = pki.listener(server).start()) {
      assertNotEquals(a.port(), b.port());
    }
    for (int attempt = 0; ; attempt++) {
      int free;
      try (ServerSocket probe = new ServerSocket(0)) {
        free = probe.getLocalPort();
      }
      try (TlsListener fixed = pki.listener(server).port(free).start();
          Kms kms = Kms.connect(pki.client(fixed).build())) {
        assertEquals(free, fixed.port());
        kms.ping();
        break;
      } catch (java.net.BindException taken) {
        if (attempt >= 5) throw taken; // another process took the free port: try another
      }
    }
  }
}
