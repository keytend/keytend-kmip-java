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

package dev.keytend.kmip.cassandra.tls;

import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.CallContext;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * Test only: a mutual-TLS KMIP endpoint on the loopback address in front of an {@link
 * InMemoryKmipServer}, so that the material reaches it as a node reaches a real KMS, with the
 * file-based connection parameters ({@link #parameters()}); in-JVM dtest instances, which have
 * class loaders of their own, reach it the same way. The test plays the operator with its own
 * {@link #admin()} client. One thread per connection.
 */
public final class KmsTestServer implements AutoCloseable {
  private final InMemoryKmipServer kmip;
  private final KmipVersion version;
  private final Path dir;
  private final ServerSocket listener;
  private final SSLContext context;
  private final TtlvCodec codec = new TtlvCodec();
  private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
  private volatile boolean unreachable;

  /** Issues the server's and the node's KMS credentials under {@code dir} and starts listening. */
  public KmsTestServer(KmipVersion version, Path dir) throws Exception {
    this.version = version;
    this.dir = Files.createDirectories(dir);
    // UUID identifiers, as real servers issue
    kmip = InMemoryKmipServer.of(version).identifierSource(() -> UUID.randomUUID().toString());
    TestPki.Issued ca = TestPki.ca("KMS CA");
    TestPki.Issued server = TestPki.issue(ca, "kms", 1);
    TestPki.Issued client = TestPki.issue(ca, "kms-client", 2);
    TestPki.write(dir.resolve("kms-ca.pem"), TestPki.pem(ca.certificate()));
    TestPki.write(dir.resolve("client.pem"), TestPki.pem(client.chain()));
    TestPki.write(dir.resolve("client.key"), TestPki.pem(client.privateKey()));
    char[] password = "changeit".toCharArray();
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(TestPki.keyStore(server, password), password);
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(TestPki.trustStore(ca.certificate()));
    context = SSLContext.getInstance("TLS");
    context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    listener = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    Thread acceptor = new Thread(this::accept, "kms-test-server");
    acceptor.setDaemon(true);
    acceptor.start();
  }

  private void accept() {
    while (!listener.isClosed()) {
      try {
        Socket s = listener.accept();
        if (unreachable) {
          s.close();
          continue;
        }
        sockets.add(s);
        Thread t = new Thread(() -> serve(s), "kms-test-connection");
        t.setDaemon(true);
        t.start();
      } catch (IOException closed) {
        return;
      }
    }
  }

  private void serve(Socket plain) {
    try (plain;
         SSLSocket s = (SSLSocket) context.getSocketFactory().createSocket(plain, null, true)) {
      s.setUseClientMode(false);
      s.setNeedClientAuth(true);
      s.startHandshake();
      InputStream in = s.getInputStream();
      OutputStream out = s.getOutputStream();
      while (true) {
        Ttlv request = codec.read(in);
        if (unreachable) return; // drop the connection without an answer
        out.write(codec.encode(kmip.exchange(request, CallContext.NONE)));
        out.flush();
      }
    } catch (Exception done) {
      // the client went away, or the server stopped
    } finally {
      sockets.remove(plain);
    }
  }

  /** The KMIP server itself, to inspect or configure (lease times). */
  public InMemoryKmipServer kmip() {
    return kmip;
  }

  /** A client of the same server for the test's operator actions; the caller closes it. */
  public Kms admin() {
    return kmip.connect();
  }

  /** The node's KMS connection parameters for an {@code ssl_context_factory}: endpoint and PEM files. */
  public Map<String, String> parameters() {
    Map<String, String> p = new HashMap<>();
    p.put(KmipConnections.ENDPOINTS, "localhost:" + listener.getLocalPort());
    p.put(KmipConnections.CLIENT_CERTIFICATE, dir.resolve("client.pem").toString());
    p.put(KmipConnections.CLIENT_KEY, dir.resolve("client.key").toString());
    p.put(KmipConnections.TRUST_CERTIFICATES, dir.resolve("kms-ca.pem").toString());
    p.put(KmipConnections.MIN_VERSION, version.toString());
    p.put(KmipConnections.MAX_VERSION, version.toString());
    p.put(KmipConnections.CALL_TIMEOUT, "5s");
    return p;
  }

  /** While true, connections are refused or dropped without an answer: a KMS outage, as the nodes see it. */
  public void unreachable(boolean unreachable) {
    this.unreachable = unreachable;
    if (unreachable)
      for (Socket s : sockets)
        try {
          s.close();
        } catch (IOException ignored) {
          // already closed
        }
  }

  @Override
  public void close() throws IOException {
    listener.close();
    for (Socket s : sockets) s.close();
    kmip.close();
  }
}
