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

import static dev.keytend.kmip.kms.TlsIdentityTest.HOURLY;
import static dev.keytend.kmip.kms.TlsIdentityTest.SCHEDULER;
import static dev.keytend.kmip.kms.TlsIdentityTest.connect;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.kms.TlsIdentityTest.Pki;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Queue;
import java.util.concurrent.ConcurrentLinkedQueue;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Real JSSE handshakes between an {@link SSLServerSocket} and clients whose key and trust managers
 * come from the KMS: accepted with the current pairs, the renewed server pair presented without
 * restarting the server socket, and clients refused once their certificate is revoked.
 */
class TlsHandshakeTest {
  static final CustomAttribute TAG = CustomAttribute.client("tls");

  /** A TLS server that answers each connection with one byte, on one socket for the whole test. */
  static final class Server implements AutoCloseable {
    final SSLServerSocket socket;
    final Queue<Throwable> refused = new ConcurrentLinkedQueue<>();
    final Thread loop;

    Server(KeyManager km, TrustManager tm) throws Exception {
      SSLContext ssl = SSLContext.getInstance("TLS");
      ssl.init(new KeyManager[] {km}, new TrustManager[] {tm}, null);
      socket =
          (SSLServerSocket)
              ssl.getServerSocketFactory()
                  .createServerSocket(0, 50, InetAddress.getLoopbackAddress());
      socket.setNeedClientAuth(true);
      loop =
          new Thread(
              () -> {
                while (!socket.isClosed()) {
                  try (Socket s = socket.accept()) {
                    s.setSoTimeout(5000);
                    try {
                      ((SSLSocket) s).startHandshake();
                      s.getOutputStream().write(1);
                      s.getOutputStream().flush();
                    } catch (IOException e) {
                      refused.add(e);
                    }
                  } catch (IOException closed) {
                    // the socket was closed
                  }
                }
              },
              "tls-handshake-test-server");
      loop.setDaemon(true);
      loop.start();
    }

    /**
     * Connects with a new client context (so no session is resumed); the server's certificate on
     * success, null when either side refused the handshake.
     */
    X509Certificate connect(KeyManager km, TrustManager tm) throws Exception {
      SSLContext ssl = SSLContext.getInstance("TLS");
      ssl.init(new KeyManager[] {km}, new TrustManager[] {tm}, null);
      try (SSLSocket s =
          (SSLSocket)
              ssl.getSocketFactory()
                  .createSocket(InetAddress.getLoopbackAddress(), socket.getLocalPort())) {
        s.setSoTimeout(5000);
        s.startHandshake();
        InputStream in = s.getInputStream();
        // TLS 1.3: a refused client certificate is told after the client's handshake ends.
        if (in.read() != 1) return null;
        return (X509Certificate) s.getSession().getPeerCertificates()[0];
      } catch (IOException e) {
        return null;
      }
    }

    @Override
    public void close() throws IOException {
      socket.close();
    }
  }

  /** A key manager holding {@code issued} and its chain, as a client that kept a revoked certificate would. */
  static KeyManager held(Issued issued, X509Certificate... chain) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(null, null);
    store.setKeyEntry("held", issued.key(), "x".toCharArray(), chain);
    KeyManagerFactory f = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    f.init(store, "x".toCharArray());
    return f.getKeyManagers()[0];
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void handshakesFollowTheKms(KmipVersion version) throws Exception {
    InMemoryKmipServer kmsServer = InMemoryKmipServer.of(version).uniqueNames(true);
    Pki pki = new Pki();
    KeyPair serverKey = TestPki.ec(), clientKey = TestPki.ec();
    Issued serverLeaf = pki.leaf("server", serverKey), clientLeaf = pki.leaf("client", clientKey);
    try (Kms kms = connect(kmsServer)) {
      KeyHandle anchor =
          kms.keys()
              .register(pki.root.certificate())
              .usages(KeyUsage.VERIFY)
              .custom(TAG, "ca")
              .register();
      TlsIdentityHandle server =
          kms.tls()
              .register(serverKey.getPrivate(), pki.chain(serverLeaf))
              .named("server")
              .custom(TAG, "peer")
              .register();
      TlsIdentityHandle client =
          kms.tls()
              .register(clientKey.getPrivate(), pki.chain(clientLeaf))
              .named("client")
              .custom(TAG, "peer")
              .register();
      KeyQuery anchors = KeyQuery.all().custom(TAG, "ca"),
          peers = KeyQuery.all().custom(TAG, "peer");
      try (TlsIdentityFollower serverIdentity = kms.tls().follow("server", HOURLY, SCHEDULER);
          TlsIdentityFollower clientIdentity = kms.tls().follow("client", HOURLY, SCHEDULER);
          TlsTrustFollower serverTrust = kms.tls().trustAnchors(anchors, peers, HOURLY, SCHEDULER);
          TlsTrustFollower clientTrust = kms.tls().trustAnchors(anchors, HOURLY, SCHEDULER);
          Server tls = new Server(serverIdentity.keyManager(), serverTrust.trustManager())) {
        assertEquals(1, serverTrust.anchors().size());
        assertEquals(2, serverTrust.allowedPeers().orElseThrow().size());
        // Accepted with the current pairs.
        assertEquals(
            serverLeaf.certificate(),
            tls.connect(clientIdentity.keyManager(), clientTrust.trustManager()));

        // The server's certificate renewed: presented at the next handshake, on the same socket.
        Issued renewed = pki.leaf("server", serverKey);
        server = server.renew(pki.chain(renewed));
        assertEquals(
            serverLeaf.certificate(),
            tls.connect(clientIdentity.keyManager(), clientTrust.trustManager()),
            "until the refresh");
        serverTrust.refresh();
        serverIdentity.refresh();
        assertEquals(
            renewed.certificate(),
            tls.connect(clientIdentity.keyManager(), clientTrust.trustManager()));

        // The client's certificate revoked in the KMS. A client that kept its key and chain is
        // refused from the server's next refresh on, though its chain still validates.
        KeyManager kept = held(clientLeaf, pki.chain(clientLeaf));
        assertEquals(renewed.certificate(), tls.connect(kept, clientTrust.trustManager()));
        client.revoke(RevocationReason.cessationOfOperation("client retired"));
        assertEquals(
            renewed.certificate(),
            tls.connect(kept, clientTrust.trustManager()),
            "until the refresh");
        assertTrue(serverTrust.refresh());
        assertEquals(1, serverTrust.allowedPeers().orElseThrow().size());
        assertNull(tls.connect(kept, clientTrust.trustManager()));
        // The client's own follower stops presenting it, so it sends no certificate: refused.
        clientIdentity.refresh();
        assertNull(tls.connect(clientIdentity.keyManager(), clientTrust.trustManager()));

        // A new client identity is allowed once the server refreshes.
        KeyPair k2 = TestPki.ec();
        kms.tls()
            .identity("client")
            .orElseThrow()
            .rekey(k2.getPrivate(), pki.chain(pki.leaf("client", k2)));
        clientIdentity.refresh();
        assertNull(
            tls.connect(clientIdentity.keyManager(), clientTrust.trustManager()),
            "not allowed yet");
        serverTrust.refresh();
        assertEquals(
            renewed.certificate(),
            tls.connect(clientIdentity.keyManager(), clientTrust.trustManager()));

        // The server's identity compromised: it presents nothing, and clients cannot connect.
        server.revoke(RevocationReason.keyCompromise("server key leaked", Instant.now()));
        serverIdentity.refresh();
        assertNull(tls.connect(clientIdentity.keyManager(), clientTrust.trustManager()));
        KeyPair k3 = TestPki.ec();
        server =
            kms.tls()
                .identity("server")
                .orElseThrow()
                .rekey(k3.getPrivate(), pki.chain(pki.leaf("server", k3)));
        serverIdentity.refresh();
        serverTrust.refresh();
        assertEquals(
            server.certificate().id(), serverIdentity.identity().orElseThrow().certificateId());
        assertNotNull(tls.connect(clientIdentity.keyManager(), clientTrust.trustManager()));

        // The trust anchor revoked: no anchor, every client refused.
        anchor.revoke(RevocationReason.caCompromise("root compromised", Instant.now()));
        serverTrust.refresh();
        assertEquals(0, serverTrust.anchors().size());
        assertNull(tls.connect(clientIdentity.keyManager(), clientTrust.trustManager()));
      }
    }
  }

  /**
   * The allowlist's renewal window closed: a peer that has just renewed (its follower presents the
   * new certificate) is accepted at once by trust followers that have not refreshed since, in both
   * directions; a certificate that chains to the anchors but is revoked, deactivated, Pre-Active,
   * not registered or not matched by the query is still refused.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aPeerThatJustRenewedIsAcceptedAtOnceByStaleAllowlists(KmipVersion version) throws Exception {
    InMemoryKmipServer kmsServer =
        InMemoryKmipServer.of(version).uniqueNames(version != KmipVersion.V2_1);
    Pki pki = new Pki();
    KeyPair serverKey = TestPki.ec(), clientKey = TestPki.ec();
    Issued clientLeaf = pki.leaf("client", clientKey);
    try (Kms kms = connect(kmsServer)) {
      kms.keys()
          .register(pki.root.certificate())
          .usages(KeyUsage.VERIFY)
          .custom(TAG, "ca")
          .register();
      TlsIdentityHandle server =
          kms.tls()
              .register(serverKey.getPrivate(), pki.chain(pki.leaf("server", serverKey)))
              .named("server")
              .custom(TAG, "peer")
              .register();
      TlsIdentityHandle client =
          kms.tls()
              .register(clientKey.getPrivate(), pki.chain(clientLeaf))
              .named("client")
              .custom(TAG, "peer")
              .register();
      KeyQuery anchors = KeyQuery.all().custom(TAG, "ca"),
          peers = KeyQuery.all().custom(TAG, "peer");
      try (TlsIdentityFollower serverIdentity = kms.tls().follow("server", HOURLY, SCHEDULER);
          TlsIdentityFollower clientIdentity = kms.tls().follow("client", HOURLY, SCHEDULER);
          TlsTrustFollower serverTrust =
              kms.tls()
                  .trustAnchors(anchors, peers, HOURLY, SCHEDULER)
                  .unknownPeerCheckInHandshake(true);
          TlsTrustFollower clientTrust =
              kms.tls()
                  .trustAnchors(anchors, peers, HOURLY, SCHEDULER)
                  .unknownPeerCheckInHandshake(true);
          Server tls = new Server(serverIdentity.keyManager(), serverTrust.trustManager())) {
        assertNotNull(tls.connect(clientIdentity.keyManager(), clientTrust.trustManager()));

        // The client renews and its follower presents the new certificate: the server's trust
        // follower, not refreshed, accepts it at its first handshake.
        Issued renewed = pki.leaf("client", clientKey);
        client = client.renew(pki.chain(renewed));
        clientIdentity.refresh();
        assertEquals(renewed.certificate(), clientIdentity.identity().orElseThrow().chain().get(0));
        assertNotNull(
            tls.connect(clientIdentity.keyManager(), clientTrust.trustManager()),
            "accepted at once");
        assertTrue(serverTrust.allowedPeers().orElseThrow().containsValue(renewed.certificate()));
        // The old certificate, deactivated by the renewal, is gone from the allowlist with it.
        assertFalse(
            serverTrust.allowedPeers().orElseThrow().containsValue(clientLeaf.certificate()));
        assertNull(
            tls.connect(held(clientLeaf, pki.chain(clientLeaf)), clientTrust.trustManager()));

        // The server re-keys: the client's trust follower, not refreshed, accepts it too.
        KeyPair k2 = TestPki.ec();
        Issued rekeyed = pki.leaf("server", k2);
        server = server.rekey(k2.getPrivate(), pki.chain(rekeyed));
        serverIdentity.refresh();
        assertEquals(
            rekeyed.certificate(),
            tls.connect(clientIdentity.keyManager(), clientTrust.trustManager()));

        // Certificates that chain to the anchors but are not current allowed peers are refused,
        // also when the trust followers have not read them. A client holds each.
        KeyPair other = TestPki.ec();
        Issued unregistered = pki.leaf("intruder", other);
        Issued revoked = pki.leaf("revoked", other),
            deactivated = pki.leaf("deactivated", other),
            preActive = pki.leaf("pre-active", other),
            untagged = pki.leaf("untagged", other);
        kms.keys()
            .register(revoked.certificate())
            .usages(KeyUsage.VERIFY)
            .custom(TAG, "peer")
            .register()
            .revoke(RevocationReason.keyCompromise("leaked", Instant.now()));
        kms.keys()
            .register(deactivated.certificate())
            .usages(KeyUsage.VERIFY)
            .custom(TAG, "peer")
            .register()
            .deactivate();
        kms.keys()
            .register(preActive.certificate())
            .usages(KeyUsage.VERIFY)
            .custom(TAG, "peer")
            .registerPreActive();
        kms.keys()
            .register(untagged.certificate())
            .usages(KeyUsage.VERIFY)
            .custom(TAG, "other")
            .register();
        for (Issued refused :
            java.util.List.of(unregistered, revoked, deactivated, preActive, untagged)) {
          serverTrust.ticker =
              advancedBy(serverTrust.ticker, 2_000_000_000L); // past the gap between checks
          assertNull(
              tls.connect(held(refused, pki.chain(refused)), clientTrust.trustManager()),
              refused.certificate().getSubjectX500Principal().toString());
          assertFalse(
              serverTrust.allowedPeers().orElseThrow().containsValue(refused.certificate()));
        }
        // And the renewed client is still accepted.
        assertNotNull(tls.connect(clientIdentity.keyManager(), clientTrust.trustManager()));
        assertEquals(java.util.List.of(), kmsServer.violations());
      }
    }
  }

  /** A clock {@code nanos} ahead of {@code ticker}. */
  static java.util.function.LongSupplier advancedBy(
      java.util.function.LongSupplier ticker, long nanos) {
    return () -> ticker.getAsLong() + nanos;
  }
}
