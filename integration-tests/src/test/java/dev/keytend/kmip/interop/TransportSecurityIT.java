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

package dev.keytend.kmip.interop;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.*;
import dev.keytend.kmip.client.*;
import dev.keytend.kmip.codec.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.server.*;
import dev.keytend.kmip.transport.*;
import java.io.*;
import java.net.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.*;
import org.junit.jupiter.api.*;

/**
 * Real JSSE handshakes, including required client identity and trust, plus callback and HTTPS
 * profiles.
 */
class TransportSecurityIT {
  private static Path certs;
  private static SSLContext client, server;

  @BeforeAll
  static void setup() throws Exception {
    Path root = Path.of(System.getProperty("project.root"));
    certs = Files.createTempDirectory("keytend-security-");
    Process p =
        new ProcessBuilder(
                "bash", root.resolve("integration/generate-certs.sh").toString(), certs.toString())
            .inheritIO()
            .start();
    assertTrue(p.waitFor(30, TimeUnit.SECONDS));
    assertEquals(0, p.exitValue());
    client =
        Tls.context(certs.resolve("client.p12"), "changeit".toCharArray(), certs.resolve("ca.pem"));
    server =
        Tls.context(certs.resolve("server.p12"), "changeit".toCharArray(), certs.resolve("ca.pem"));
  }

  @AfterAll
  static void cleanup() throws Exception {
    try (var walk = Files.walk(certs)) {
      for (Path p : walk.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
    }
  }

  @Test
  void mutualTlsCallbacksAndSuccessiveMessages() throws Exception {
    List<Operation> received = Collections.synchronizedList(new ArrayList<>());
    List<IOException> errors = Collections.synchronizedList(new ArrayList<>());
    try (var listener =
        new CallbackServer(
            new InetSocketAddress("127.0.0.1", 0),
            server,
            (op, payload) -> {
              received.add(op);
              return CallbackHandler.Reply.success(
                  structure(RESPONSE_PAYLOAD, text(UNIQUE_IDENTIFIER, "stored")));
            },
            errors::add)) {
      for (ProtocolVersion version : ProtocolVersion.values()) {
        try (var c =
            new KmipClient(new TlsTransport("localhost", listener.port(), client), version)) {
          assertTrue(c.call(Requests.notifyRequest().build()).successful());
          assertTrue(c.call(Requests.put().build()).successful());
        }
      }
      // The same socket can carry more than one framed exchange.
      try (SSLSocket socket =
          (SSLSocket) client.getSocketFactory().createSocket("localhost", listener.port())) {
        socket.setSoTimeout(5000);
        socket.startHandshake();
        TtlvCodec codec = new TtlvCodec();
        Ttlv request =
            Messages.request(
                ProtocolVersion.V3_0,
                List.of(Requests.notifyRequest().build()),
                RequestOptions.DEFAULT);
        for (int i = 0; i < 2; i++) {
          socket.getOutputStream().write(codec.encode(request));
          socket.getOutputStream().flush();
          assertTrue(
              Messages.response(codec.read(socket.getInputStream())).results().get(0).successful());
        }
      }
      assertEquals(16, received.size());
      SSLContext noIdentity = Tls.context(null, null, certs.resolve("ca.pem"));
      try (var c =
          new KmipClient(
              new TlsTransport("localhost", listener.port(), noIdentity), ProtocolVersion.V3_0)) {
        assertThrows(IOException.class, () -> c.call(Requests.notifyRequest().build()));
      }
      try (var c =
          new KmipClient(
              new TlsTransport("localhost", listener.port(), SSLContext.getDefault()),
              ProtocolVersion.V3_0)) {
        assertThrows(IOException.class, () -> c.call(Requests.notifyRequest().build()));
      }
    }
  }

  @Test
  void serverHostnameIsVerified() throws Exception {
    SSLContext wrong =
        Tls.context(
            certs.resolve("mismatch.p12"), "changeit".toCharArray(), certs.resolve("ca.pem"));
    try (var listener =
            new CallbackServer(
                new InetSocketAddress("127.0.0.1", 0),
                wrong,
                (op, payload) -> CallbackHandler.Reply.success(null),
                ignored -> {});
        var transport = new TlsTransport("localhost", listener.port(), client)) {
      // Handshake failures happen before the request is written (RequestNotSentException).
      var notSent =
          assertThrows(
              dev.keytend.kmip.transport.RequestNotSentException.class,
              () ->
                  transport.exchange(
                      Messages.request(
                          ProtocolVersion.V1_4,
                          List.of(Requests.query().build()),
                          RequestOptions.DEFAULT)));
      assertInstanceOf(SSLHandshakeException.class, notSent.getCause());
    }
  }

  @Test
  void httpsProfilesEncodeAndDecodeAllThreeFormats() throws Exception {
    HttpsServer http = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    ExecutorService executor = Executors.newFixedThreadPool(4);
    http.setExecutor(executor);
    http.setHttpsConfigurator(
        new HttpsConfigurator(server) {
          @Override
          public void configure(HttpsParameters parameters) {
            SSLParameters ssl = server.getDefaultSSLParameters();
            ssl.setNeedClientAuth(true);
            parameters.setSSLParameters(ssl);
          }
        });
    for (HttpsTransport.Encoding encoding : HttpsTransport.Encoding.values())
      http.createContext(
          "/" + encoding.name(),
          exchange -> {
            try {
              assertEquals("POST", exchange.getRequestMethod());
              assertEquals(
                  encoding.mediaType(), exchange.getRequestHeaders().getFirst("Content-Type"));
              assertEquals("no-cache", exchange.getRequestHeaders().getFirst("Cache-Control"));
              byte[] body = exchange.getRequestBody().readNBytes(1024 * 1024);
              Ttlv request =
                  switch (encoding) {
                    case TTLV -> new TtlvCodec().decode(body);
                    case XML -> new XmlCodec().decode(body);
                    case JSON -> new JsonCodec().decode(body);
                  };
              Ttlv reply =
                  CallbackMessages.respond(
                      request,
                      (op, payload) ->
                          CallbackHandler.Reply.success(
                              structure(
                                  RESPONSE_PAYLOAD, enumeration(OPERATION, Operation.CREATE))));
              byte[] response =
                  switch (encoding) {
                    case TTLV -> new TtlvCodec().encode(reply);
                    case XML -> new XmlCodec().encode(reply);
                    case JSON -> new JsonCodec().encode(reply);
                  };
              exchange.getResponseHeaders().add("Content-Type", encoding.mediaType());
              exchange.sendResponseHeaders(200, response.length);
              exchange.getResponseBody().write(response);
            } finally {
              exchange.close();
            }
          });
    http.createContext(
        "/bad-media",
        e -> {
          e.getResponseHeaders().add("Content-Type", "text/plain");
          e.sendResponseHeaders(200, 1);
          e.getResponseBody().write(0);
          e.close();
        });
    http.start();
    try {
      for (HttpsTransport.Encoding encoding : HttpsTransport.Encoding.values())
        for (ProtocolVersion version : ProtocolVersion.values())
          try (var c =
              new KmipClient(
                  new HttpsTransport(
                      URI.create(
                          "https://localhost:"
                              + http.getAddress().getPort()
                              + "/"
                              + encoding.name()),
                      client,
                      encoding),
                  version)) {
            assertTrue(c.query(Enums.QueryFunction.QUERY_OPERATIONS).successful());
          }
      try (var transport =
          new HttpsTransport(
              URI.create("https://localhost:" + http.getAddress().getPort() + "/bad-media"),
              client,
              HttpsTransport.Encoding.TTLV)) {
        assertThrows(
            IOException.class,
            () ->
                transport.exchange(
                    Messages.request(
                        ProtocolVersion.V1_4,
                        List.of(Requests.query().build()),
                        RequestOptions.DEFAULT)));
      }
      assertThrows(
          IllegalArgumentException.class,
          () ->
              new HttpsTransport(
                  URI.create("http://localhost/kmip"), client, HttpsTransport.Encoding.JSON));
    } finally {
      http.stop(0);
      executor.shutdownNow();
    }
  }
}
