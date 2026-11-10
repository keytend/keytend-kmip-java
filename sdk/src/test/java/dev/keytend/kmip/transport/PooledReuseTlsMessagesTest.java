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

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.TestTls;
import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import java.io.*;
import java.net.*;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import javax.net.ssl.*;
import org.junit.jupiter.api.Test;

/**
 * The check before reusing a recent pooled connection keeps a
 * healthy connection whose TLS 1.3 server sent a post-handshake message (a NewSessionTicket) after
 * its reply, as JSSE's own server does after any write once the application has called
 * SSLSession.putValue; and a JVM SOCKS proxy is used, as a plain Socket uses it.
 */
class PooledReuseTlsMessagesTest {
  static Ttlv query() {
    return Messages.request(
        ProtocolVersion.V1_4, List.of(Requests.query().build()), RequestOptions.DEFAULT);
  }

  /** Echoes each TTLV back; with {@code ticket}, calls putValue first so JSSE sends an NST after the reply. */
  static final class EchoServer implements Closeable {
    final SSLServerSocket listener;
    final AtomicInteger accepted = new AtomicInteger();
    final Thread thread;

    EchoServer(boolean ticket) throws Exception {
      listener =
          (SSLServerSocket)
              TestTls.context("server", "client").getServerSocketFactory().createServerSocket(0);
      listener.setNeedClientAuth(true);
      listener.setEnabledProtocols(new String[] {"TLSv1.3"});
      thread =
          new Thread(
              () -> {
                while (!listener.isClosed()) {
                  try {
                    SSLSocket s = (SSLSocket) listener.accept();
                    accepted.incrementAndGet();
                    new Thread(() -> serve(s, ticket)).start();
                  } catch (IOException e) {
                    return;
                  }
                }
              });
      thread.setDaemon(true);
      thread.start();
    }

    static void serve(SSLSocket s, boolean ticket) {
      try (s) {
        DataInputStream in = new DataInputStream(s.getInputStream());
        OutputStream out = s.getOutputStream();
        for (int n = 0; ; n++) {
          byte[] header = new byte[8];
          in.readFully(header);
          int length =
              ((header[4] & 0xff) << 24)
                  | ((header[5] & 0xff) << 16)
                  | ((header[6] & 0xff) << 8)
                  | (header[7] & 0xff);
          byte[] body = new byte[length];
          in.readFully(body);
          if (ticket) s.getSession().putValue("request", n);
          byte[] reply = new byte[8 + length];
          System.arraycopy(header, 0, reply, 0, 8);
          System.arraycopy(body, 0, reply, 8, length);
          out.write(reply);
          out.flush();
        }
      } catch (IOException e) {
        // closed
      }
    }

    int port() {
      return listener.getLocalPort();
    }

    @Override
    public void close() throws IOException {
      listener.close();
    }
  }

  static int[] run(boolean ticket, Duration validateAfterIdle) throws Exception {
    try (EchoServer server = new EchoServer(ticket);
        TlsTransport t =
            TlsTransport.builder("localhost", server.port(), TestTls.context("client", "server"))
                .pool(1, Duration.ofSeconds(30))
                .validateAfterIdle(validateAfterIdle)
                .build()) {
      for (int i = 0; i < 20; i++) {
        assertNotNull(t.exchange(query()));
        Thread.sleep(20);
      }
      return new int[] {(int) t.connectionsOpened(), server.accepted.get()};
    }
  }

  /** 20 requests 20 ms apart on one connection, with or without a ticket after each reply. */
  @Test
  void aTicketAfterEachReplyKeepsTheConnection() throws Exception {
    int[] plain = run(false, TlsTransport.DEFAULT_VALIDATE_AFTER_IDLE);
    int[] probedEveryTime = run(true, Duration.ZERO);
    int[] quick = run(true, TlsTransport.DEFAULT_VALIDATE_AFTER_IDLE);
    assertEquals(1, plain[0]);
    assertEquals(
        1,
        probedEveryTime[0],
        "the 1 ms probe reads through the SSL layer, which consumes the ticket");
    assertEquals(1, quick[0], "20 requests on one healthy connection");
  }

  /**
   * A TCP connection opened with new Socket() honors the JVM's SOCKS proxy settings
   * (socksProxyHost, or the default ProxySelector for socket:// URIs); a SocketChannel's socket
   * does not, so the transport uses a plain Socket when the selector names a proxy. The fake proxy
   * speaks no SOCKS, so the exchange fails; what counts is that it went to the proxy.
   */
  @Test
  void theJvmsSocksProxyIsUsed() throws Exception {
    AtomicInteger viaProxy = new AtomicInteger();
    ProxySelector before = ProxySelector.getDefault();
    try (ServerSocket proxy = new ServerSocket(0);
        EchoServer server = new EchoServer(false)) {
      Thread t =
          new Thread(
              () -> {
                while (true) {
                  try (Socket s = proxy.accept()) {
                    viaProxy.incrementAndGet();
                  } catch (IOException e) {
                    return;
                  }
                }
              });
      t.setDaemon(true);
      t.start();
      InetSocketAddress at = new InetSocketAddress("127.0.0.1", proxy.getLocalPort());
      ProxySelector.setDefault(
          new ProxySelector() {
            @Override
            public List<Proxy> select(URI uri) {
              return List.of(new Proxy(Proxy.Type.SOCKS, at));
            }

            @Override
            public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {}
          });
      // A plain Socket goes to the proxy.
      try (Socket plain = new Socket()) {
        plain.connect(new InetSocketAddress("localhost", server.port()), 2000);
      } catch (IOException expected) {
        // the fake proxy speaks no SOCKS
      }
      int plainAttempts = viaProxy.get();
      boolean ok;
      try (TlsTransport tls =
          TlsTransport.builder("localhost", server.port(), TestTls.context("client", "server"))
              .pool(1, Duration.ofSeconds(30))
              .build()) {
        ok = tls.exchange(query()) != null;
      } catch (IOException e) {
        ok = false;
      }
      assertEquals(1, plainAttempts);
      assertEquals(
          plainAttempts + 1, viaProxy.get(), "TlsTransport bypassed the JVM's SOCKS proxy");
      assertFalse(ok, "the exchange went to the fake proxy, not directly to the server");
    } finally {
      ProxySelector.setDefault(before);
    }
  }
}
