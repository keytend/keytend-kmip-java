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
package dev.keytend.kmip.opentelemetry;

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.TrustManagerFactory;

/**
 * An in-memory KMIP server behind a TLS listener on localhost, so that the SDK's TLS transport,
 * whose connections {@code Kms.connectionStats()} measures, serves the calls. One self-signed
 * certificate (from the JDK's keytool, for {@code localhost}) is both sides' identity and trust.
 */
final class TlsKmipServer implements AutoCloseable {
  static final char[] PASSWORD = "changeit".toCharArray();

  final InMemoryKmipServer memory;
  private final KeyStore store;
  private final SSLServerSocket listener;
  private final TtlvCodec codec = new TtlvCodec();
  private final Set<Socket> sockets = ConcurrentHashMap.newKeySet();

  TlsKmipServer(InMemoryKmipServer memory, Path dir) throws Exception {
    this.memory = memory;
    this.store = selfSigned(dir);
    SSLContext context = context(store);
    listener = (SSLServerSocket) context.getServerSocketFactory().createServerSocket(0);
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

  /** A configuration of the SDK's TLS transport to this server. */
  KmsConfig.Builder configure() throws Exception {
    return KmsConfig.builder()
        .endpoints("localhost:" + listener.getLocalPort())
        .clientIdentity(store, PASSWORD)
        .trustStore(store);
  }

  String endpoint() {
    return "localhost:" + listener.getLocalPort();
  }

  int port() {
    return listener.getLocalPort();
  }

  private void serve(Socket s) {
    try (s) {
      InputStream in = s.getInputStream();
      while (true) {
        Ttlv request = codec.read(in);
        s.getOutputStream().write(codec.encode(memory.exchange(request)));
        s.getOutputStream().flush();
      }
    } catch (Exception done) {
      // the client went away
    } finally {
      sockets.remove(s);
    }
  }

  @Override
  public void close() throws IOException {
    listener.close();
    for (Socket s : sockets)
      try {
        s.close();
      } catch (RuntimeException handshakeInProgress) {
        // a handshake still starting on another thread; the test is over
      }
  }

  static SSLContext context(KeyStore store) throws Exception {
    KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keys.init(store, PASSWORD);
    TrustManagerFactory trust =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trust.init(store);
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
    return context;
  }

  /** A self-signed EC key pair for {@code localhost}, from the JDK's keytool. */
  static KeyStore selfSigned(Path dir) throws Exception {
    Path file = dir.resolve("localhost.p12");
    keytool(
        "-genkeypair",
        "-alias",
        "localhost",
        "-keyalg",
        "EC",
        "-groupname",
        "secp256r1",
        "-sigalg",
        "SHA256withECDSA",
        "-dname",
        "CN=localhost",
        "-ext",
        "san=dns:localhost",
        "-validity",
        "2",
        "-storetype",
        "PKCS12",
        "-keystore",
        file.toString(),
        "-storepass",
        new String(PASSWORD),
        "-keypass",
        new String(PASSWORD));
    KeyStore store = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(file)) {
      store.load(in, PASSWORD);
    }
    return store;
  }

  /** Runs the JDK's keytool with {@code args}. */
  static void keytool(String... args) throws Exception {
    List<String> command = new ArrayList<>();
    command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
    command.addAll(List.of(args));
    Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
    byte[] out = p.getInputStream().readAllBytes();
    assertTrue(p.waitFor(60, TimeUnit.SECONDS), "keytool hung");
    assertEquals(0, p.exitValue(), new String(out, StandardCharsets.UTF_8));
  }
}
