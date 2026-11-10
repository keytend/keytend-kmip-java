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

package dev.keytend.kmip.testing;

import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.transport.CallContext;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

/**
 * A TLS listener in front of an {@link InMemoryKmipServer}, so that a test can run the SDK's TLS
 * transport, its client credentials ({@link KmsConfig.Builder#clientIdentityPem}, {@link
 * KmsConfig.Builder#trustPem}, ...) and their reloading against the in-memory server. It speaks
 * KMIP over TLS 1.2 and 1.3 on a port of the loopback address, by default one the system chooses.
 * Get a builder from {@link InMemoryKmipServer#tlsListener()}.
 *
 * <pre>{@code
 * InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
 * try (TlsListener tls = server.tlsListener()
 *         .identity(serverKey, serverCertificate)   // what the server presents
 *         .trustAnchors(clientCa)                   // what client certificates chain to
 *         .start();
 *     Kms kms = Kms.connect(tls.configure()
 *         .clientIdentityPem(clientChain, clientKey).trustPem(serverCa).build())) {
 *   kms.ping();
 *   assertEquals(1, tls.clientCertificates().size());
 * }
 * }</pre>
 *
 * <p>{@code serverKey} and {@code serverCertificate} are the server's private key and certificate,
 * which must name {@code localhost} (the SDK checks the server's host name), {@code clientCa} the
 * CA certificate of the client's, and {@code clientChain}, {@code clientKey} and {@code serverCa}
 * the client's PEM files.
 *
 * <p>Each connection is served on its own daemon thread, one request at a time, by the server's
 * {@link InMemoryKmipServer#exchange(Ttlv, CallContext) exchange}. The server's faults apply: a
 * fault that fails the exchange (such as {@link Fault#REPLY_LOST}) closes the connection without a
 * reply, and while the server is {@link InMemoryKmipServer#unreachable(boolean) unreachable} new
 * connections are closed before their handshake. A refused handshake ends with the server's
 * alert, not a reset. {@link #close()} stops listening and closes every connection; it does not
 * close the server. Like the rest of this package, the listener is test support outside the SDK's
 * compatibility promises (<a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/compatibility.md#the-testing-package">The
 * testing package</a>); never give it real keys.
 *
 * @since 0.10.0
 */
public final class TlsListener implements AutoCloseable {
  /**
   * Whether the listener asks the client for a certificate.
   *
   * @since 0.10.0
   */
  public enum ClientAuth {
    /** A client that presents no certificate is refused (mutual TLS), the default. */
    REQUIRED,
    /** A client certificate is asked for; a client without one is accepted. */
    OPTIONAL,
    /** No client certificate is asked for. */
    NONE
  }

  private final InMemoryKmipServer server;
  private final SSLContext context;
  private final ClientAuth clientAuth;

  /** The provisioning CA of Re-Provision; null without one. */
  private final Provisioning provisioning;

  private final ServerSocket listener;
  private final TtlvCodec codec = new TtlvCodec();
  private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
  private final Set<CallContext> inFlight = ConcurrentHashMap.newKeySet();
  private final List<X509Certificate> clients = new CopyOnWriteArrayList<>();
  private final List<String> failures = new CopyOnWriteArrayList<>();
  private final AtomicInteger handshakes = new AtomicInteger();
  private final AtomicInteger connections = new AtomicInteger();
  private volatile boolean closed;

  private TlsListener(Builder b, SSLContext context) throws IOException {
    this.server = b.server;
    this.context = context;
    this.clientAuth = b.clientAuth;
    this.provisioning =
        b.provisioningKey == null
            ? null
            : new Provisioning(
                b.provisioningKey, b.provisioningCa, b.provisioningValidity, b.trustManager);
    if (provisioning != null) {
      String refused;
      try {
        refused = provisioning.startupRefusal(server.now());
      } catch (GeneralSecurityException e) {
        throw new IllegalStateException("provisioningCa: cannot check it: " + e.getMessage(), e);
      }
      if (refused != null) throw new IllegalStateException("provisioningCa: " + refused);
    }
    ServerSocket s = new ServerSocket();
    try {
      s.bind(new InetSocketAddress(InetAddress.getLoopbackAddress(), b.port), 50);
    } catch (IOException e) {
      s.close();
      throw e;
    }
    listener = s;
    daemon(this::accept, "keytend-in-memory-tls-accept-" + port()).start();
  }

  /** A daemon thread without a context class loader, which ends with {@link #close()}. */
  private static Thread daemon(Runnable r, String name) {
    Thread t = new Thread(null, r, name, 0, false);
    t.setDaemon(true);
    t.setContextClassLoader(null);
    return t;
  }

  private void accept() {
    while (!closed) {
      Socket plain;
      try {
        plain = listener.accept();
      } catch (IOException e) {
        return; // closed
      }
      sockets.add(plain);
      if (closed || server.isUnreachable()) {
        // As a server that is down: no handshake.
        drop(plain);
        continue;
      }
      connections.incrementAndGet();
      daemon(() -> serve(plain), "keytend-in-memory-tls-" + port()).start();
    }
  }

  private void serve(Socket plain) {
    // The TLS socket does not close the plain one, so a refused handshake can drain it first.
    try (plain;
        SSLSocket tls = (SSLSocket) context.getSocketFactory().createSocket(plain, null, false)) {
      tls.setUseClientMode(false);
      tls.setEnabledProtocols(protocols(tls.getSupportedProtocols()));
      switch (clientAuth) {
        case REQUIRED -> tls.setNeedClientAuth(true);
        case OPTIONAL -> tls.setWantClientAuth(true);
        case NONE -> tls.setWantClientAuth(false);
      }
      try {
        tls.startHandshake();
      } catch (IOException refused) {
        if (closed) return;
        failures.add(String.valueOf(refused.getMessage()));
        // Read what the client still sends until it closes: it then reads the alert.
        plain.setSoTimeout(5000);
        byte[] discard = new byte[4096];
        while (plain.getInputStream().read(discard) >= 0) {}
        return;
      }
      Certificate[] peer = null;
      try {
        peer = tls.getSession().getPeerCertificates();
      } catch (javax.net.ssl.SSLPeerUnverifiedException none) {
        // OPTIONAL or NONE, and the client presented none
      }
      X509Certificate[] chain = null;
      if (peer != null && peer.length > 0 && peer[0] instanceof X509Certificate leaf) {
        clients.add(leaf);
        chain = new X509Certificate[peer.length];
        for (int i = 0; i < peer.length; i++) chain[i] = (X509Certificate) peer[i];
      }
      handshakes.incrementAndGet();
      InputStream in = tls.getInputStream();
      OutputStream out = tls.getOutputStream();
      if (chain != null && server.retired(chain[0])) {
        // A certificate Re-Provision retired: one answer, Permission Denied for each item, then
        // the connection closes (keytend-kmip-server's unlisted path).
        out.write(codec.encode(server.refuseRetired(codec.read(in))));
        out.flush();
        return;
      }
      InMemoryKmipServer.Channel channel = new InMemoryKmipServer.Channel(chain, provisioning);
      while (!closed) {
        Ttlv request = codec.read(in);
        CallContext call = CallContext.cancellable();
        inFlight.add(call);
        Ttlv response;
        try {
          response = server.exchange(request, call, channel);
        } finally {
          inFlight.remove(call);
        }
        out.write(codec.encode(response));
        out.flush();
      }
    } catch (IOException | RuntimeException done) {
      // The client went away, the exchange failed (a fault: no reply), or the listener closed.
    } finally {
      sockets.remove(plain);
    }
  }

  /** TLS 1.3 and 1.2, as the KMIP profiles ask, of those {@code supported}. */
  private static String[] protocols(String[] supported) {
    List<String> out = new ArrayList<>();
    for (String p : supported) if (p.equals("TLSv1.3") || p.equals("TLSv1.2")) out.add(p);
    return out.toArray(String[]::new);
  }

  private void drop(Socket s) {
    sockets.remove(s);
    try {
      s.close();
    } catch (IOException ignored) {
      // closing
    }
  }

  /**
   * The port the listener accepts connections on, on the loopback address.
   *
   * @return the port
   */
  public int port() {
    return listener.getLocalPort();
  }

  /**
   * The endpoint to connect to, {@code localhost:port}: the server's certificate must name {@code
   * localhost}, or the SDK refuses it.
   *
   * @return the endpoint, for {@link KmsConfig.Builder#endpoints(String...)}
   */
  public String endpoint() {
    return "localhost:" + port();
  }

  /**
   * A {@link KmsConfig} builder for this listener: its {@link #endpoint()}, over the SDK's TLS
   * transport, and the server's version range as {@link InMemoryKmipServer#configure()} sets it.
   * Add the client's TLS settings (a trust choice, and for mutual TLS a client identity) and build.
   *
   * @return a new builder, which the test completes
   */
  public KmsConfig.Builder configure() {
    return server.versions(KmsConfig.builder().endpoints(endpoint()));
  }

  /**
   * The server this listener serves.
   *
   * @return the server
   */
  public InMemoryKmipServer server() {
    return server;
  }

  /**
   * The client certificate (the first of its chain) of each completed handshake that presented
   * one, in the order the handshakes completed.
   *
   * @return the certificates, a copy
   */
  public List<X509Certificate> clientCertificates() {
    return List.copyOf(clients);
  }

  /**
   * The client certificates that Re-Provision replaced, in order, through this listener or another
   * of the server or its replicas: each is refused on new connections, with Permission Denied for
   * its first request, after which the connection closes. Connections open when one was replaced
   * keep working, but cannot re-provision it again.
   *
   * @return the retired certificates, a copy
   * @since 0.10.0
   */
  public List<X509Certificate> retiredCertificates() {
    return server.retiredCertificates();
  }

  /**
   * How many handshakes completed, with or without a client certificate.
   *
   * @return the number of completed handshakes
   */
  public int handshakes() {
    return handshakes.get();
  }

  /**
   * How many connections were accepted for a handshake (not those closed while the server is
   * unreachable).
   *
   * @return the number of connections accepted
   */
  public int connections() {
    return connections.get();
  }

  /**
   * Why each handshake that failed failed, as the listener's TLS layer said, in order: the
   * listener refused the client (no certificate, one its trust refused), or the client refused the
   * listener.
   *
   * @return the messages, a copy
   */
  public List<String> handshakeFailures() {
    return List.copyOf(failures);
  }

  /**
   * Closes every open connection, as a server that restarts or times out idle connections would;
   * the listener goes on accepting new ones.
   */
  public void dropConnections() {
    for (CallContext c : inFlight) c.cancel();
    for (Socket s : sockets) drop(s);
  }

  /** Stops listening and closes every connection; the server is not closed. Idempotent. */
  @Override
  public void close() {
    closed = true;
    try {
      listener.close();
    } catch (IOException ignored) {
      // closing
    }
    dropConnections();
  }

  @Override
  public String toString() {
    return "TlsListener[" + endpoint() + (closed ? ", closed" : "") + "]";
  }

  /**
   * Settings of a {@link TlsListener}: the server's identity, the trust of client certificates,
   * client authentication and the port. Get one from {@link InMemoryKmipServer#tlsListener()}; not
   * thread-safe.
   *
   * @since 0.10.0
   */
  public static final class Builder {
    private final InMemoryKmipServer server;
    private X509KeyManager keyManager;
    private X509TrustManager trustManager;
    private SSLContext context;
    private ClientAuth clientAuth = ClientAuth.REQUIRED;
    private int port;
    private PrivateKey provisioningKey;
    private X509Certificate provisioningCa;
    private java.time.Duration provisioningValidity = Provisioning.DEFAULT_VALIDITY;

    Builder(InMemoryKmipServer server) {
      this.server = server;
    }

    /**
     * The server's identity: its private key and certificate chain, leaf first. The leaf must
     * name {@code localhost} for the SDK to accept it. Replaces a {@link #keyManager} set before.
     *
     * @param key the server's private key
     * @param chain its certificate chain, leaf first, at least the leaf
     * @return this builder
     * @throws IllegalArgumentException when the chain is empty or the key cannot be used
     */
    public Builder identity(PrivateKey key, X509Certificate... chain) {
      Objects.requireNonNull(key, "key");
      Objects.requireNonNull(chain, "chain");
      if (chain.length == 0) throw new IllegalArgumentException("identity: the chain is empty");
      for (X509Certificate c : chain) Objects.requireNonNull(c, "certificate");
      try {
        char[] none = new char[0];
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        store.setKeyEntry("server", key, none, chain.clone());
        KeyManagerFactory f =
            KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        f.init(store, none);
        for (KeyManager m : f.getKeyManagers())
          if (m instanceof X509KeyManager x) {
            keyManager = x;
            return this;
          }
        throw new IllegalArgumentException("identity: the JDK made no X509KeyManager");
      } catch (IOException | GeneralSecurityException e) {
        throw new IllegalArgumentException("identity: cannot use the key: " + e.getMessage(), e);
      }
    }

    /**
     * The server's identity from a key manager, for example a {@code TlsIdentityFollower}'s, so
     * that the server presents what it reads. Replaces an {@link #identity} set before.
     *
     * @param keys the key manager
     * @return this builder
     */
    public Builder keyManager(X509KeyManager keys) {
      keyManager = Objects.requireNonNull(keys, "keys");
      return this;
    }

    /**
     * The CA certificates a client certificate must chain to, checked with the JDK's PKIX trust
     * manager. Replaces a {@link #trustManager} set before.
     *
     * @param anchors the CA certificates, at least one
     * @return this builder
     * @throws IllegalArgumentException when there is none
     */
    public Builder trustAnchors(X509Certificate... anchors) {
      Objects.requireNonNull(anchors, "anchors");
      if (anchors.length == 0) throw new IllegalArgumentException("trustAnchors: none given");
      try {
        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(null, null);
        int i = 0;
        for (X509Certificate a : anchors)
          store.setCertificateEntry("anchor-" + i++, Objects.requireNonNull(a, "anchor"));
        TrustManagerFactory f = TrustManagerFactory.getInstance("PKIX");
        f.init(store);
        for (TrustManager m : f.getTrustManagers())
          if (m instanceof X509TrustManager x) {
            trustManager = x;
            return this;
          }
        throw new IllegalArgumentException("trustAnchors: the JDK made no X509TrustManager");
      } catch (IOException | GeneralSecurityException e) {
        throw new IllegalArgumentException("trustAnchors: " + e.getMessage(), e);
      }
    }

    /**
     * The trust of client certificates from a trust manager, for example a {@code
     * TlsTrustFollower}'s, so that the server checks clients as a node would. Replaces {@link
     * #trustAnchors} set before.
     *
     * @param trust the trust manager
     * @return this builder
     */
    public Builder trustManager(X509TrustManager trust) {
      trustManager = Objects.requireNonNull(trust, "trust");
      return this;
    }

    /**
     * Expert: a ready-made TLS context (the server's identity and the trust of clients), instead
     * of {@link #identity}, {@link #keyManager}, {@link #trustAnchors} and {@link #trustManager};
     * {@link #start()} refuses both.
     *
     * @param context the server's TLS context
     * @return this builder
     */
    public Builder context(SSLContext context) {
      this.context = Objects.requireNonNull(context, "context");
      return this;
    }

    /**
     * Whether the listener asks for a client certificate: {@link ClientAuth#REQUIRED} (the
     * default), {@link ClientAuth#OPTIONAL} or {@link ClientAuth#NONE}.
     *
     * @param clientAuth the client authentication
     * @return this builder
     */
    public Builder clientAuth(ClientAuth clientAuth) {
      this.clientAuth = Objects.requireNonNull(clientAuth, "clientAuth");
      return this;
    }

    /**
     * Offer Re-Provision (KMIP 2.0 and later) in its certificate-request form, as
     * keytend-kmip-server with {@code --provisioning-ca}, so a test can renew a client certificate
     * ({@code Kms.renewClientCertificate()}). {@code certificate} issues the replacements. It must
     * be a CA (basicConstraints CA true) with a Key Usage that allows keyCertSign, and strong: a
     * key of at least 112-bit security, and, unless it is self-issued, not signed with MD2, MD4,
     * MD5 or SHA-1. Put this same certificate among the {@link #trustAnchors} too, as
     * keytend-kmip-server requires it in its {@code --ca} bundle, with the self-signed root it
     * chains to, since each new certificate must pass the listener's check of clients: a path
     * through it, with at most 4 intermediates, up to a self-signed trust anchor, each certificate
     * of which, the root included, suits a TLS client as OpenSSL's purpose sslclient has it (an
     * Extended Key Usage, where present, lists clientAuth), is strong, and has no EC key on a curve
     * keytend-kmip-server does not implement. As keytend-kmip-server does before it serves, {@link
     * #start()} checks the CA,
     * that it is among the trust anchors (the accepted issuers of a {@link #trustManager}), and
     * puts a client certificate from it through that check, and refuses to start when any fails. A
     * new certificate that the check refuses later, by the server's clock, is refused with
     * Cryptographic Failure. The rules are the server's: the message is {@code
     * [Re-Provision(Certificate Request), Get(ID Placeholder)]}, with only Get, Get Attributes or
     * Get Attribute List after the Re-Provision, one Re-Provision per message and per certificate,
     * no header credentials and no Undo. The new key is new, and RSA (2048 bits or more) for an RSA
     * certificate or EC on the same curve (P-256, P-384 or P-521). The new certificate copies the
     * subject and subjectAltName of the one it replaces. When the message commits, the replaced
     * certificate is retired: refused on new connections ({@link #retiredCertificates()}), while
     * open connections keep working but cannot re-provision it again. Without this, Re-Provision
     * answers Operation Not Supported.
     *
     * @param key the provisioning CA's private key
     * @param certificate the provisioning CA's certificate
     * @return this builder
     * @since 0.10.0
     */
    public Builder provisioningCa(PrivateKey key, X509Certificate certificate) {
      provisioningKey = Objects.requireNonNull(key, "key");
      provisioningCa = Objects.requireNonNull(certificate, "certificate");
      return this;
    }

    /**
     * How long a certificate the provisioning CA issues is valid: 365 days by default, as on
     * keytend-kmip-server, cut short when the CA expires earlier.
     *
     * @param validity the validity, positive
     * @return this builder
     * @throws IllegalArgumentException when {@code validity} is not positive
     * @since 0.10.0
     */
    public Builder provisioningValidity(java.time.Duration validity) {
      Objects.requireNonNull(validity, "validity");
      if (validity.isNegative() || validity.isZero())
        throw new IllegalArgumentException("Invalid validity " + validity);
      provisioningValidity = validity;
      return this;
    }

    /**
     * The port to listen on, on the loopback address; 0, the default, lets the system choose a
     * free one ({@link TlsListener#port()} says which).
     *
     * @param port the port, 0 to 65535
     * @return this builder
     * @throws IllegalArgumentException when out of range
     */
    public Builder port(int port) {
      if (port < 0 || port > 65535) throw new IllegalArgumentException("Invalid port " + port);
      this.port = port;
      return this;
    }

    /**
     * Starts listening.
     *
     * @return the listener, accepting connections; the test closes it
     * @throws IllegalStateException when no identity is set, a {@link #context} is combined with
     *     the other TLS settings, a client certificate is asked for ({@link ClientAuth#REQUIRED}
     *     or {@link ClientAuth#OPTIONAL}) without a trust of them, or keytend-kmip-server would
     *     not start with the {@link #provisioningCa}: one that is not a CA (basicConstraints CA
     *     true) with a Key Usage that allows keyCertSign, or whose client certificates the trust
     *     of clients refuses
     * @throws IOException when the port cannot be bound
     */
    public TlsListener start() throws IOException {
      SSLContext ssl = context;
      if (ssl != null) {
        if (keyManager != null || trustManager != null)
          throw new IllegalStateException(
              "context(SSLContext) and identity/keyManager/trustAnchors/trustManager both set:"
                  + " use one or the other");
      } else {
        if (keyManager == null)
          throw new IllegalStateException(
              "No server identity: set identity(key, chain) or keyManager(keys)");
        if (trustManager == null && clientAuth != ClientAuth.NONE)
          throw new IllegalStateException(
              "Client authentication "
                  + clientAuth
                  + " needs a trust of client certificates: set trustAnchors(...) or"
                  + " trustManager(...), or clientAuth(ClientAuth.NONE)");
        try {
          ssl = SSLContext.getInstance("TLS");
          ssl.init(
              new KeyManager[] {keyManager},
              trustManager == null ? null : new TrustManager[] {trustManager},
              null);
        } catch (GeneralSecurityException e) {
          throw new IllegalStateException("Cannot make the listener's TLS context", e);
        }
      }
      return new TlsListener(this, ssl);
    }
  }
}
