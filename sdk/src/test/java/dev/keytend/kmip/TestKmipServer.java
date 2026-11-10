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

import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.model.Ttlv;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.UnaryOperator;
import javax.net.ssl.*;

/** A minimal mTLS TTLV server for transport tests: persistent connections, one thread each. */
public final class TestKmipServer implements AutoCloseable {
  private final SSLServerSocket listener;
  private final UnaryOperator<Ttlv> handler;
  private final TtlvCodec codec = new TtlvCodec();
  private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();
  final AtomicInteger accepted = new AtomicInteger();
  final AtomicInteger exchanges = new AtomicInteger();
  volatile long replyDelayMillis;
  volatile boolean closeAfterReply;

  public TestKmipServer(String identity, UnaryOperator<Ttlv> handler, String... suites)
      throws Exception {
    this.handler = handler;
    listener =
        (SSLServerSocket)
            TestTls.context(identity, "client").getServerSocketFactory().createServerSocket(0);
    listener.setNeedClientAuth(true);
    if (suites.length > 0) listener.setEnabledCipherSuites(suites);
    Thread acceptor =
        new Thread(
            () -> {
              while (!listener.isClosed())
                try {
                  Socket s = listener.accept();
                  accepted.incrementAndGet();
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

  public int port() {
    return listener.getLocalPort();
  }

  private void serve(Socket s) {
    try (s) {
      InputStream in = s.getInputStream();
      while (true) {
        Ttlv request = codec.read(in);
        exchanges.incrementAndGet();
        if (replyDelayMillis > 0) Thread.sleep(replyDelayMillis);
        s.getOutputStream().write(codec.encode(handler.apply(request)));
        s.getOutputStream().flush();
        if (closeAfterReply) return;
      }
    } catch (Exception done) {
      // client went away
    } finally {
      sockets.remove(s);
    }
  }

  /** A server answering every request with a successful, empty reply. */
  public static TestKmipServer answeringQueries() throws Exception {
    return new TestKmipServer("server", TransportTest::queryReply);
  }

  /** Requests received so far. */
  public int exchangeCount() {
    return exchanges.get();
  }

  public void delay(long millis) {
    replyDelayMillis = millis;
  }

  /** Closes the server side of every open connection, as an idle timeout on the server would. */
  public void dropConnections() throws IOException {
    for (Socket s : sockets) s.close();
  }

  /** Resets every open connection (SO_LINGER 0), as a server process that dies might. */
  public void resetConnections() throws IOException {
    for (Socket s : sockets) {
      s.setSoLinger(true, 0);
      s.close();
    }
  }

  /** Connections accepted so far. */
  public int acceptedCount() {
    return accepted.get();
  }

  @Override
  public void close() throws IOException {
    listener.close();
    for (Socket s : sockets)
      try {
        s.close();
      } catch (NullPointerException handshakeInProgress) {
        // JDK 17's SSLSocketImpl.close() can throw while a handshake is still starting on another
        // thread ("handshakeContext is null"); the test is over, and the listener is closed.
      }
  }
}
