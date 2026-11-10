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

import dev.keytend.kmip.TestAwait;
import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.CallContext;
import java.io.*;
import java.net.*;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BooleanSupplier;
import javax.net.ssl.*;

/**
 * A mutual-TLS KMIP server in front of an {@link InMemoryKmipServer} that records, per connection,
 * the client certificate it saw and when the client closed it. One thread per connection.
 *
 * <p>A refused handshake is followed by reading (and discarding) what the client still sends
 * until it closes, before the server closes: the client then always reads the server's alert. A
 * server that closes at once makes the client's next write fail ("Broken pipe", a reset) while the
 * alert is unread, which the client cannot tell from a network failure.
 */
final class RecordingTlsServer implements AutoCloseable {
  final InMemoryKmipServer kmip = InMemoryKmipServer.of(KmipVersion.V2_1);
  private final ServerSocket listener;
  private final SSLContext context;
  private final String[] suites;
  private final TtlvCodec codec = new TtlvCodec();
  private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();

  /** The subject of each connection's client certificate, in handshake order. */
  final List<String> peers = new CopyOnWriteArrayList<>();

  /** Handshakes the server failed (it refused the client, or the client refused it). */
  final AtomicInteger refused = new AtomicInteger();

  /** Connections that ended after a successful handshake (the client closed them). */
  final AtomicInteger ended = new AtomicInteger();

  final AtomicInteger exchanges = new AtomicInteger();

  /** Read before each reply: how long to wait before answering. */
  volatile long delayMillis;

  /** {@code context} is the server's identity and the client certificates it trusts. */
  RecordingTlsServer(SSLContext context, String... suites) throws IOException {
    this.context = context;
    this.suites = suites;
    listener = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
    Thread acceptor =
        new Thread(
            () -> {
              while (!listener.isClosed())
                try {
                  Socket s = listener.accept();
                  sockets.add(s);
                  Thread t = new Thread(() -> serve(s));
                  t.setDaemon(true);
                  t.start();
                } catch (IOException e) {
                  return;
                }
            });
    acceptor.setDaemon(true);
    acceptor.start();
  }

  int port() {
    return listener.getLocalPort();
  }

  String endpoint() {
    return "localhost:" + port();
  }

  private void serve(Socket plain) {
    // Not closing the plain socket with the TLS one lets a refused handshake drain it first.
    try (plain;
        SSLSocket s = (SSLSocket) context.getSocketFactory().createSocket(plain, null, false)) {
      s.setNeedClientAuth(true);
      if (suites.length > 0) s.setEnabledCipherSuites(suites);
      X509Certificate client;
      try {
        s.startHandshake();
        client = (X509Certificate) s.getSession().getPeerCertificates()[0];
      } catch (IOException refusedHandshake) {
        refused.incrementAndGet();
        plain.setSoTimeout(5000);
        while (plain.getInputStream().read(new byte[4096]) >= 0) {}
        return;
      }
      peers.add(client.getSubjectX500Principal().getName());
      InputStream in = s.getInputStream();
      try {
        while (true) {
          Ttlv request = codec.read(in);
          exchanges.incrementAndGet();
          long delay = delayMillis;
          if (delay > 0) Thread.sleep(delay);
          s.getOutputStream().write(codec.encode(kmip.exchange(request, CallContext.NONE)));
          s.getOutputStream().flush();
        }
      } finally {
        ended.incrementAndGet();
      }
    } catch (Exception done) {
      // the client went away
    } finally {
      sockets.remove(plain);
    }
  }

  /** Waits for {@code condition} ({@link TestAwait}). */
  static void await(BooleanSupplier condition, String what) {
    TestAwait.await(what).until(condition::getAsBoolean);
  }

  @Override
  public void close() throws IOException {
    listener.close();
    for (Socket s : sockets) s.close();
  }
}
