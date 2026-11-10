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

import static dev.keytend.kmip.interop.Catalog.*;
import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.client.ProtocolException;
import dev.keytend.kmip.codec.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.*;
import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.stream.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;
import org.junit.jupiter.api.*;

/** Adversarial peer evidence is deliberately never attached to a vendor qualification tuple. */
class CatalogPeerIT {
  static final Path ROOT = Path.of(System.getProperty("project.root"));
  static Path certs;
  static SSLContext server, client;
  static String commit, sourceHash, configurationHash;
  static final Set<String> observedTls = new ConcurrentSkipListSet<>();
  static final TtlvCodec CODEC = new TtlvCodec();
  static final List<Map<String, Object>> records = new ArrayList<>();
  static final Set<String> MIXED =
      Set.of(
          "TLS-07",
          "TLS-09",
          "TLS-11",
          "TLS-13",
          "VER-04",
          "VER-05",
          "VER-06",
          "DISC-01",
          "DISC-04",
          "DISC-08",
          "BATCH-07",
          "BATCH-08",
          "BATCH-09",
          "RETRY-06",
          "OBS-01",
          "OBS-02",
          "OBS-03",
          "OBS-04",
          "OBS-05",
          "OBS-06",
          "JAVA-02",
          "JAVA-08");

  @BeforeAll
  static void setup() throws Exception {
    certs = Files.createTempDirectory("keytend-catalog-peer-");
    Process p =
        new ProcessBuilder(
                "bash",
                ROOT.resolve("integration/catalog/generate-pki.sh").toString(),
                certs.toString())
            .redirectErrorStream(true)
            .start();
    assertTrue(p.waitFor(45, TimeUnit.SECONDS));
    assertEquals(0, p.exitValue());
    server = context("server", "ca.pem");
    client = context("client", "ca.pem");
    Process git = new ProcessBuilder("git", "rev-parse", "HEAD").directory(ROOT.toFile()).start();
    commit =
        new String(git.getInputStream().readAllBytes(), StandardCharsets.UTF_8).trim()
            + "+worktree";
    assertEquals(0, git.waitFor());
    var digest = MessageDigest.getInstance("SHA-256");
    for (String directory :
        List.of("sdk/src/main", "integration-tests/src/main", "integration-tests/src/test"))
      try (var files = Files.walk(ROOT.resolve(directory))) {
        for (Path path : files.filter(Files::isRegularFile).sorted().toList())
          digest.update(Files.readAllBytes(path));
      }
    sourceHash = HexFormat.of().formatHex(digest.digest());
    configurationHash = Catalog.digest(Files.readAllBytes(certs.resolve("ca.pem")));
  }

  static SSLContext context(String identity, String trust) throws Exception {
    return Tls.context(
        identity == null ? null : certs.resolve(identity + ".p12"),
        "changeit".toCharArray(),
        certs.resolve(trust));
  }

  @AfterAll
  static void report() throws Exception {
    Catalog.write(
        ROOT.resolve(
            "integration/reports/catalog/controlled-jdk" + Runtime.version().feature() + ".json"),
        Map.of(
            "records",
            records,
            "scope",
            "client robustness only; not live vendor interoperability"));
    try (var walk = Files.walk(certs)) {
      for (Path p : walk.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
    }
  }

  @TestFactory
  Stream<DynamicTest> cases() {
    return CASES.stream()
        .filter(
            c ->
                Set.of("controlled_peer", "codec_harness").contains(c.layer())
                    || MIXED.contains(c.id()))
        .map(
            c ->
                DynamicTest.dynamicTest(
                    c.id() + " " + c.title(),
                    () -> {
                      long begin = System.nanoTime();
                      Instant started = Instant.now();
                      observedTls.clear();
                      String outcome = "PASS", reason = "Assertions completed";
                      try {
                        run(c.id());
                      } catch (Throwable e) {
                        outcome = "FAIL_CLIENT";
                        reason = e.getClass().getSimpleName() + ": " + e.getMessage();
                        throw e;
                      } finally {
                        Map<String, Object> r = new LinkedHashMap<>(Catalog.runtime());
                        r.put("test_id", c.id());
                        r.put("server_version", "in-process adversarial fixture");
                        r.put("image_digest", null);
                        r.put("client_commit", commit);
                        r.put("client_worktree_sha256", sourceHash);
                        r.put("configuration_hash", configurationHash);
                        r.put("tls_version", List.copyOf(observedTls));
                        r.put(
                            "identity_role",
                            "synthetic client; negative identities where specified");
                        r.put("namespace", "controlled-peer");
                        r.put("started_at", started.toString());
                        r.put("priority", c.priority());
                        r.put("planned_layer", c.layer());
                        r.put(
                            "case_parameters",
                            Map.of(
                                "protocols",
                                List.of("1.4", "2.1", "3.0"),
                                "deterministic_seed",
                                0x4b4d4950));
                        r.put("issue_id", null);
                        r.put(
                            "actual_layer",
                            c.layer().equals("codec_harness")
                                ? "codec_harness"
                                : "controlled_peer");
                        r.put("server_id", "controlled-peer");
                        r.put("wire_version", "1.4, 2.1, 3.0 where applicable");
                        r.put("outcome", outcome);
                        r.put("reason", reason);
                        r.put("duration_ms", (System.nanoTime() - begin) / 1_000_000);
                        r.put("seed", 0x4b4d4950);
                        r.put("evidence_refs", List.of("CatalogPeerIT#" + c.id()));
                        records.add(r);
                      }
                    }));
  }

  @FunctionalInterface
  interface Reply {
    void send(Ttlv request, OutputStream output) throws Exception;
  }

  static final class Peer implements AutoCloseable {
    final SSLServerSocket listener;
    final ExecutorService worker = Executors.newSingleThreadExecutor();
    final Future<?> task;
    volatile Socket active;
    volatile String principal;

    Peer(SSLContext ssl, Reply handler) throws Exception {
      listener =
          (SSLServerSocket)
              ssl.getServerSocketFactory()
                  .createServerSocket(0, 8, InetAddress.getLoopbackAddress());
      listener.setNeedClientAuth(true);
      listener.setSoTimeout(3000);
      task =
          worker.submit(
              () -> {
                try (SSLSocket socket = (SSLSocket) listener.accept()) {
                  active = socket;
                  socket.setSoTimeout(3000);
                  socket.startHandshake();
                  observedTls.add(socket.getSession().getProtocol());
                  principal =
                      ((java.security.cert.X509Certificate)
                              socket.getSession().getPeerCertificates()[0])
                          .getSubjectX500Principal()
                          .getName();
                  handler.send(CODEC.read(socket.getInputStream()), socket.getOutputStream());
                } catch (Exception e) {
                  throw new CompletionException(e);
                }
              });
    }

    KmipClient client(ProtocolVersion v) throws Exception {
      return new KmipClient(
          new TlsTransport(
              "localhost",
              listener.getLocalPort(),
              client,
              Duration.ofMillis(200),
              Duration.ofMillis(250),
              new TtlvCodec(1024 * 1024, 32)),
          v);
    }

    @Override
    public void close() throws Exception {
      listener.close();
      if (active != null) active.close();
      task.cancel(true);
      worker.shutdownNow();
      assertTrue(worker.awaitTermination(2, TimeUnit.SECONDS));
    }
  }

  static Ttlv response(Ttlv request, int status, Ttlv... body) {
    ProtocolVersion v = Messages.version(request.require(REQUEST_HEADER));
    List<Ttlv> h =
        new ArrayList<>(
            List.of(
                Messages.protocolVersion(v),
                dateTime(TIME_STAMP, Instant.ofEpochSecond(1700000000))));
    if (v != ProtocolVersion.V3_0) h.add(integer(BATCH_COUNT, 1));
    Ttlv req = request.require(BATCH_ITEM);
    List<Ttlv> b =
        new ArrayList<>(List.of(req.require(OPERATION), enumeration(RESULT_STATUS, status)));
    req.child(UNIQUE_BATCH_ITEM_ID).ifPresent(b::add);
    b.addAll(List.of(body));
    return structure(RESPONSE_MESSAGE, structure(RESPONSE_HEADER, h), structure(BATCH_ITEM, b));
  }

  static Ttlv payload(String id) {
    return structure(
        RESPONSE_PAYLOAD,
        text(UNIQUE_IDENTIFIER, id),
        enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY),
        ManagedObjects.rawSymmetricKey(
            CatalogLiveSuite.known(32), Enums.CryptographicAlgorithm.AES));
  }

  static void reject(Reply reply) throws Exception {
    for (ProtocolVersion v :
        List.of(ProtocolVersion.V1_4, ProtocolVersion.V2_1, ProtocolVersion.V3_0))
      try (Peer peer = new Peer(server, reply);
          var c = peer.client(v)) {
        assertThrows(IOException.class, () -> c.get("id"));
      }
  }

  static void run(String id) throws Exception {
    switch (id) {
      case "TLS-02" -> badServer("rollover-server");
      case "TLS-03" -> badServer("mismatch");
      case "TLS-04" -> {
        badServer("expired");
        badServer("future");
      }
      case "TLS-07" -> {
        goodServer("chain-server", "ca.pem");
        badServer("missing-chain");
        goodServer("chain-server", "intermediate.pem");
      }
      case "TLS-09" -> aliases();
      case "TLS-11" -> revocation();
      case "TLS-13" -> {
        goodServer("server", "overlap-ca.pem");
        goodServer("rollover-server", "overlap-ca.pem");
        badServer("rollover-server");
        goodServer("rollover-server", "other-ca.pem");
      }
      case "WIRE-01" -> golden();
      case "WIRE-02" -> primitives();
      case "WIRE-03" -> {
        for (int n : List.of(0, 1, 7, 8, 9, 15, 16, 17)) {
          Ttlv node = structure(DATA, bytes(DATA, new byte[n]));
          assertEquals(node, CODEC.decode(CODEC.encode(node)));
          byte[] bad = CODEC.encode(bytes(DATA, new byte[n]));
          if (n % 8 != 0) {
            bad[bad.length - 1] = 1;
            assertThrows(IOException.class, () -> CODEC.decode(bad));
          }
        }
      }
      case "WIRE-04" -> {
        for (String s : List.of("tenant:key:17", "ключ-🔑", "x".repeat(8192))) {
          Ttlv n = text(UNIQUE_IDENTIFIER, s);
          assertEquals(n, CODEC.decode(CODEC.encode(n)));
        }
        byte[] invalid = CODEC.encode(text(UNIQUE_IDENTIFIER, "x"));
        invalid[8] = (byte) 0xff;
        assertThrows(IOException.class, () -> CODEC.decode(invalid));
      }
      case "WIRE-05" -> {
        for (ProtocolVersion v :
            List.of(ProtocolVersion.V1_4, ProtocolVersion.V2_1, ProtocolVersion.V3_0))
          try (Peer peer =
                  new Peer(
                      server,
                      (req, out) -> {
                        byte[] b = CODEC.encode(response(req, 0, payload("id")));
                        for (byte x : b) {
                          out.write(x);
                          out.flush();
                        }
                      });
              var c = peer.client(v)) {
            assertEquals("id", c.get("id").uniqueIdentifier());
          }
      }
      case "WIRE-06" -> {
        try (Peer p =
                new Peer(
                    server,
                    (req, out) -> {
                      byte[] frame = CODEC.encode(response(req, 0, payload("id")));
                      out.write(frame);
                      out.write(frame);
                      out.flush();
                    });
            SSLSocket socket =
                (SSLSocket)
                    client
                        .getSocketFactory()
                        .createSocket("localhost", p.listener.getLocalPort())) {
          socket.setSoTimeout(2000);
          socket.startHandshake();
          socket
              .getOutputStream()
              .write(
                  CODEC.encode(
                      Messages.request(
                          ProtocolVersion.V2_1,
                          List.of(Requests.get().uniqueIdentifier("id").build()),
                          RequestOptions.DEFAULT)));
          assertEquals(
              "id",
              Messages.response(CODEC.read(socket.getInputStream()))
                  .results()
                  .get(0)
                  .uniqueIdentifier());
          assertEquals(
              "id",
              Messages.response(CODEC.read(socket.getInputStream()))
                  .results()
                  .get(0)
                  .uniqueIdentifier());
        }
      }
      case "WIRE-07" -> {
        byte[] frame = CODEC.encode(payload("id"));
        for (int i = 0; i < frame.length; i++) {
          byte[] truncated = Arrays.copyOf(frame, i);
          assertThrows(IOException.class, () -> CODEC.read(new ByteArrayInputStream(truncated)));
        }
        reject(
            (req, out) -> {
              byte[] b = CODEC.encode(response(req, 0, payload("id")));
              out.write(b, 0, b.length - 1);
            });
      }
      case "WIRE-08" -> {
        for (int length : List.of(-1, Integer.MIN_VALUE, Integer.MAX_VALUE, 1024 * 1024 + 1)) {
          byte[] header = CODEC.encode(bytes(DATA, new byte[0]));
          ByteBuffer.wrap(header).putInt(4, length);
          assertThrows(
              IOException.class,
              () -> new TtlvCodec(1024, 32).read(new ByteArrayInputStream(header)));
        }
        reject(
            (req, out) -> {
              byte[] h = CODEC.encode(response(req, 0, payload("id")));
              ByteBuffer.wrap(h).putInt(4, -1);
              out.write(h, 0, 8);
            });
      }
      case "WIRE-09" -> {
        Ttlv n = bytes(DATA, new byte[1]);
        for (int i = 0; i < 40; i++) n = structure(DATA, n);
        byte[] deep = CODEC.encode(n);
        assertThrows(IOException.class, () -> new TtlvCodec(4096, 32).decode(deep));
        Ttlv wide = structure(DATA, Collections.nCopies(50, integer(DATA, 1)));
        assertThrows(
            IOException.class, () -> new TtlvCodec(4096, 32, 32).decode(CODEC.encode(wide)));
        assertThrows(
            IllegalArgumentException.class,
            () ->
                Messages.request(
                    ProtocolVersion.V2_1,
                    Collections.nCopies(129, Requests.get().build()),
                    RequestOptions.DEFAULT));
      }
      case "WIRE-10" -> {
        reject(
            (req, out) -> {
              Ttlv r = response(req, 0, payload("id"));
              List<Ttlv> b = new ArrayList<>(r.require(BATCH_ITEM).children());
              b.add(enumeration(RESULT_STATUS, 0));
              out.write(
                  CODEC.encode(
                      structure(
                          RESPONSE_MESSAGE, r.require(RESPONSE_HEADER), structure(BATCH_ITEM, b))));
            });
        reject(
            (req, out) -> {
              byte[] b = CODEC.encode(response(req, 0, payload("id")));
              b[3] = 127;
              out.write(b);
            });
      }
      case "WIRE-11" -> {
        for (ProtocolVersion v :
            List.of(ProtocolVersion.V1_4, ProtocolVersion.V2_1, ProtocolVersion.V3_0))
          try (Peer p =
                  new Peer(
                      server,
                      (req, out) ->
                          out.write(
                              CODEC.encode(
                                  response(
                                      req,
                                      0,
                                      payload("id"),
                                      Ttlv.of(0x540099, Ttlv.Type.TEXT_STRING, "optional")))));
              var c = p.client(v)) {
            assertEquals("id", c.get("id").uniqueIdentifier());
          }
      }
      case "WIRE-12" -> {
        for (boolean critical : List.of(false, true))
          try (Peer p =
                  new Peer(
                      server,
                      (req, out) ->
                          out.write(
                              CODEC.encode(
                                  response(
                                      req,
                                      0,
                                      payload("id"),
                                      Credentials.extension(
                                          "unknown", critical, integer(DATA, 7))))));
              var c = p.client(ProtocolVersion.V2_1)) {
            if (critical) assertThrows(ProtocolException.class, () -> c.get("id"));
            else assertTrue(c.get("id").successful());
          }
      }
      case "WIRE-13" -> {
        reject((req, out) -> out.write(CODEC.encode(response(req, 0, payload("wrong-id")))));
        reject(
            (req, out) -> {
              Ttlv r = response(req, 0, payload("id"));
              List<Ttlv> b = new ArrayList<>(r.require(BATCH_ITEM).children());
              b.set(0, enumeration(OPERATION, Operation.CREATE));
              out.write(
                  CODEC.encode(
                      structure(
                          RESPONSE_MESSAGE, r.require(RESPONSE_HEADER), structure(BATCH_ITEM, b))));
            });
      }
      case "WIRE-14", "OBS-05" -> {
        byte[] source = {1, 2, 3};
        Ttlv n = bytes(KEY_MATERIAL, source);
        source[0] = 9;
        assertArrayEquals(new byte[] {1, 2, 3}, n.bytesValue());
        byte[] copy = n.bytesValue();
        copy[1] = 9;
        assertEquals(2, n.bytesValue()[1]);
      }
      case "WIRE-15" -> fuzz();
      case "VER-04" -> {
        try (var c =
            new KmipClient(
                req ->
                    response(
                        req,
                        0,
                        structure(
                            RESPONSE_PAYLOAD, Messages.protocolVersion(ProtocolVersion.V3_0))),
                ProtocolVersion.V1_4)) {
          assertThrows(IOException.class, c::negotiate);
        }
      }
      case "VER-05" -> {
        AtomicInteger calls = new AtomicInteger();
        try (var c =
            new KmipClient(
                req -> {
                  calls.incrementAndGet();
                  return response(
                      req,
                      1,
                      enumeration(RESULT_REASON, Enums.ResultReason.OPERATION_NOT_SUPPORTED));
                },
                ProtocolVersion.V2_1)) {
          assertThrows(KmipException.class, c::discoverVersions);
          assertEquals(1, calls.get());
        }
      }
      case "VER-06", "RETRY-06" -> {
        AtomicInteger calls = new AtomicInteger();
        try (var c =
            new KmipClient(
                req -> {
                  calls.incrementAndGet();
                  assertEquals(
                      Operation.GET.code(), req.require(BATCH_ITEM).require(OPERATION).intValue());
                  return response(
                      req, 1, enumeration(RESULT_REASON, Enums.ResultReason.PERMISSION_DENIED));
                },
                ProtocolVersion.V2_1)) {
          assertThrows(KmipException.class, () -> c.get("id"));
          assertEquals(1, calls.get());
        }
      }
      case "VER-11" -> {
        for (ProtocolVersion v : ProtocolVersion.values())
          try (var c =
              new KmipClient(
                  req ->
                      response(
                          req,
                          0,
                          structure(
                              RESPONSE_PAYLOAD,
                              structure(
                                  PROTOCOL_VERSION,
                                  integer(PROTOCOL_VERSION_MAJOR, 4),
                                  integer(PROTOCOL_VERSION_MINOR, 0)),
                              Messages.protocolVersion(v))),
                  v)) {
            assertEquals(v, c.negotiate().version());
          }
      }
      case "DISC-01" -> {
        try (var c =
            new KmipClient(
                req ->
                    response(
                        req,
                        0,
                        structure(
                            RESPONSE_PAYLOAD,
                            enumeration(OPERATIONS, Operation.GET),
                            Ttlv.of(0x540001, Ttlv.Type.INTEGER, 7))),
                ProtocolVersion.V1_4)) {
          assertEquals(
              Operation.GET.code(),
              c.query(Enums.QueryFunction.QUERY_OPERATIONS)
                  .requirePayload()
                  .require(OPERATIONS)
                  .intValue());
        }
      }
      case "DISC-04" -> {
        Ttlv p =
            structure(
                RESPONSE_PAYLOAD, text(UNIQUE_IDENTIFIER, "one"), text(UNIQUE_IDENTIFIER, "two"));
        assertEquals(2, CODEC.decode(CODEC.encode(p)).children(UNIQUE_IDENTIFIER).size());
      }
      case "DISC-08", "KEY-06" -> unsafeKeys();
      case "AUTH-06" -> {
        try (var c =
            new KmipClient(
                req ->
                    response(
                        req,
                        1,
                        enumeration(RESULT_REASON, Enums.ResultReason.PERMISSION_DENIED),
                        payload("id")),
                ProtocolVersion.V2_1)) {
          assertThrows(KmipException.class, () -> c.get("id").requirePayload());
        }
      }
      case "KEY-09" -> wrapVectors();
      case "BATCH-03" -> {
        for (ProtocolVersion v : List.of(ProtocolVersion.V1_4, ProtocolVersion.V2_1)) {
          Ttlv r = Messages.request(v, List.of(Requests.get().build()), RequestOptions.DEFAULT);
          assertTrue(r.require(REQUEST_HEADER).child(BATCH_ORDER_OPTION).isEmpty());
          // Batch options apply only to batches of more than one item.
          RequestOptions batching =
              RequestOptions.DEFAULT.batching(true, Enums.BatchErrorContinuation.STOP);
          Ttlv single = Messages.request(v, List.of(Requests.get().build()), batching);
          assertTrue(single.require(REQUEST_HEADER).child(BATCH_ORDER_OPTION).isEmpty());
          Ttlv ordered =
              Messages.request(
                  v, List.of(Requests.get().build(), Requests.get().build()), batching);
          assertTrue(ordered.require(REQUEST_HEADER).require(BATCH_ORDER_OPTION).booleanValue());
        }
      }
      case "BATCH-07" -> {
        for (int reason : List.of(5, 7, 1, 12, 0x7fffffff))
          try (var c =
              new KmipClient(
                  req -> response(req, 1, enumeration(RESULT_REASON, reason)),
                  ProtocolVersion.V1_4)) {
            KmipException e = assertThrows(KmipException.class, () -> c.get("id"));
            assertEquals(reason, e.result().reason());
          }
      }
      case "BATCH-08" -> pending();
      case "BATCH-09" -> {
        wholeMessageError();
        AtomicInteger calls = new AtomicInteger();
        try (var c =
            new KmipClient(
                req -> {
                  calls.incrementAndGet();
                  return response(
                      req, 1, enumeration(RESULT_REASON, Enums.ResultReason.FEATURE_NOT_SUPPORTED));
                },
                ProtocolVersion.V2_1)) {
          var r =
              c.batch(
                  List.of(Requests.get().build()),
                  RequestOptions.DEFAULT.batching(true, Enums.BatchErrorContinuation.STOP));
          assertFalse(r.results().get(0).successful());
          assertEquals(1, calls.get());
        }
      }
      case "RETRY-08" -> {
        reject(
            (req, out) -> {
              byte[] b = CODEC.encode(response(req, 0, payload("id")));
              out.write(b, 0, b.length - 1);
            });
        try (Peer p =
                new Peer(
                    server,
                    (req, out) -> out.write(CODEC.encode(response(req, 0, payload("id")))));
            var c = p.client(ProtocolVersion.V2_1)) {
          assertEquals("id", c.get("id").uniqueIdentifier());
        }
      }
      case "RETRY-02" -> {
        httpsDeadline();
        long begin = System.nanoTime();
        try (Peer p =
                new Peer(
                    server,
                    (req, out) -> {
                      byte[] b = CODEC.encode(response(req, 0, payload("id")));
                      for (byte x : b) {
                        out.write(x);
                        out.flush();
                        Thread.sleep(60);
                      }
                    });
            var c = p.client(ProtocolVersion.V2_1)) {
          assertThrows(IOException.class, () -> c.get("id"));
        }
        assertTrue(
            System.nanoTime() - begin < TimeUnit.SECONDS.toNanos(2),
            "Slow progress extended overall deadline");
      }
      case "OBS-01" -> {
        String marker = "RECOGNIZABLE_SECRET_MARKER";
        Ttlv secret = bytes(KEY_MATERIAL, marker.getBytes(StandardCharsets.UTF_8));
        assertFalse(secret.toString().contains(marker));
        try (var c =
            new KmipClient(
                req ->
                    response(
                        req,
                        1,
                        enumeration(RESULT_REASON, Enums.ResultReason.PERMISSION_DENIED),
                        text(RESULT_MESSAGE, marker)),
                ProtocolVersion.V2_1)) {
          var e = assertThrows(KmipException.class, () -> c.get("id"));
          assertFalse(e.toString().contains(marker));
          assertFalse(e.result().toString().contains(marker));
        }
      }
      case "OBS-02" -> {
        reject((req, out) -> out.write(new byte[] {0, 0, 0, 0, 0, 0, 0, 0}));
        badServer("mismatch");
      }
      case "OBS-03" -> {
        AtomicInteger attempts = new AtomicInteger();
        try (var c =
            new KmipClient(
                req -> {
                  attempts.incrementAndGet();
                  return response(req, 0, payload("id"));
                },
                ProtocolVersion.V2_1)) {
          c.get("id");
          assertEquals(1, attempts.get());
        }
      }
      case "OBS-04" -> {
        assertFalse(json(records).contains("RECOGNIZABLE_SECRET_MARKER"));
        assertFalse(json(records).contains("BEGIN PRIVATE KEY"));
      }
      case "OBS-06" -> {
        assertTrue(Files.isRegularFile(ROOT.resolve("integration/catalog/catalog.json")));
        assertTrue(CASES.stream().map(Catalog.Case::id).distinct().count() == 145);
      }
      case "JAVA-02" -> https();
      case "JAVA-08" -> {
        httpsClose();
        try (Peer p = new Peer(server, (req, out) -> Thread.sleep(2000));
            var c = p.client(ProtocolVersion.V2_1)) {
          ExecutorService e = Executors.newSingleThreadExecutor();
          try {
            Future<?> pending = e.submit(() -> assertThrows(IOException.class, () -> c.get("id")));
            Thread.sleep(50);
            c.close();
            c.close();
            pending.get(2, TimeUnit.SECONDS);
          } finally {
            e.shutdownNow();
          }
        }
      }
      default -> throw new AssertionError("No peer scenario for " + id);
    }
  }

  static void aliases() throws Exception {
    KeyStore combined = KeyStore.getInstance("PKCS12");
    combined.load(null, null);
    for (String name : List.of("client", "client-b")) {
      KeyStore input = KeyStore.getInstance("PKCS12");
      try (InputStream in = Files.newInputStream(certs.resolve(name + ".p12"))) {
        input.load(in, "changeit".toCharArray());
      }
      String a = input.aliases().nextElement();
      combined.setKeyEntry(
          name,
          input.getKey(a, "changeit".toCharArray()),
          "changeit".toCharArray(),
          input.getCertificateChain(a));
    }
    Path multi = certs.resolve("multi.p12");
    try (OutputStream out = Files.newOutputStream(multi)) {
      combined.store(out, "changeit".toCharArray());
    }
    assertThrows(
        GeneralSecurityException.class,
        () -> Tls.context(multi, "changeit".toCharArray(), certs.resolve("ca.pem")));
    assertThrows(
        GeneralSecurityException.class,
        () -> Tls.context(multi, "changeit".toCharArray(), certs.resolve("ca.pem"), "missing"));
    for (String name : List.of("client", "client-b"))
      try (Peer peer =
              new Peer(
                  server, (req, out) -> out.write(CODEC.encode(response(req, 0, payload("id")))));
          var c =
              new KmipClient(
                  new TlsTransport(
                      "localhost",
                      peer.listener.getLocalPort(),
                      Tls.context(multi, "changeit".toCharArray(), certs.resolve("ca.pem"), name)),
                  ProtocolVersion.V2_1)) {
        c.get("id");
        assertTrue(peer.principal.contains("CN=" + name));
      }
  }

  static void revocation() throws Exception {
    var cf = java.security.cert.CertificateFactory.getInstance("X.509");
    java.security.cert.X509Certificate ca;
    java.security.cert.CRL crl;
    try (InputStream in = Files.newInputStream(certs.resolve("ca.pem"))) {
      ca = (java.security.cert.X509Certificate) cf.generateCertificate(in);
    }
    try (InputStream in = Files.newInputStream(certs.resolve("revoked.crl"))) {
      crl = cf.generateCRL(in);
    }
    var parameters =
        new java.security.cert.PKIXBuilderParameters(
            Set.of(new java.security.cert.TrustAnchor(ca, null)),
            new java.security.cert.X509CertSelector());
    parameters.addCertStore(
        java.security.cert.CertStore.getInstance(
            "Collection", new java.security.cert.CollectionCertStoreParameters(List.of(crl))));
    var checker =
        (java.security.cert.PKIXRevocationChecker)
            java.security.cert.CertPathValidator.getInstance("PKIX").getRevocationChecker();
    checker.setOptions(
        EnumSet.of(
            java.security.cert.PKIXRevocationChecker.Option.PREFER_CRLS,
            java.security.cert.PKIXRevocationChecker.Option.NO_FALLBACK,
            java.security.cert.PKIXRevocationChecker.Option.ONLY_END_ENTITY));
    parameters.addCertPathChecker(checker);
    TrustManagerFactory trust = TrustManagerFactory.getInstance("PKIX");
    trust.init(new CertPathTrustManagerParameters(parameters));
    KeyStore identity = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(certs.resolve("client.p12"))) {
      identity.load(in, "changeit".toCharArray());
    }
    KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keys.init(identity, "changeit".toCharArray());
    SSLContext checked = SSLContext.getInstance("TLS");
    checked.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
    for (boolean revoked : List.of(false, true))
      try (Peer p =
              new Peer(
                  context(revoked ? "revoked-server" : "server", "ca.pem"),
                  (req, out) -> out.write(CODEC.encode(response(req, 0, payload("id")))));
          var c =
              new KmipClient(
                  new TlsTransport("localhost", p.listener.getLocalPort(), checked),
                  ProtocolVersion.V2_1)) {
        if (revoked) assertThrows(IOException.class, () -> c.get("id"));
        else assertEquals("id", c.get("id").uniqueIdentifier());
      }
  }

  static void wholeMessageError() throws Exception {
    try (var c =
        new KmipClient(
            req -> {
              Ttlv r =
                  response(
                      req, 1, enumeration(RESULT_REASON, Enums.ResultReason.FEATURE_NOT_SUPPORTED));
              return structure(
                  RESPONSE_MESSAGE,
                  r.require(RESPONSE_HEADER),
                  structure(
                      BATCH_ITEM,
                      enumeration(RESULT_STATUS, 1),
                      enumeration(RESULT_REASON, Enums.ResultReason.FEATURE_NOT_SUPPORTED)));
            },
            ProtocolVersion.V2_1)) {
      var reply =
          c.batch(
              List.of(Requests.get().build(), Requests.get().build()),
              RequestOptions.DEFAULT.batching(true, Enums.BatchErrorContinuation.CONTINUE));
      assertEquals(1, reply.results().size());
      assertFalse(reply.results().get(0).successful());
    }
  }

  static void httpsClose() throws Exception {
    var http = com.sun.net.httpserver.HttpsServer.create(new InetSocketAddress("localhost", 0), 8);
    http.setHttpsConfigurator(new com.sun.net.httpserver.HttpsConfigurator(server));
    CountDownLatch started = new CountDownLatch(1);
    ExecutorService worker = Executors.newCachedThreadPool();
    http.setExecutor(worker);
    http.createContext(
        "/",
        exchange -> {
          observedTls.add(
              ((com.sun.net.httpserver.HttpsExchange) exchange).getSSLSession().getProtocol());
          try {
            exchange.getRequestBody().readAllBytes();
            exchange.getResponseHeaders().set("Content-Type", "application/octet-stream");
            exchange.sendResponseHeaders(200, 512);
            exchange.getResponseBody().write(0x42);
            exchange.getResponseBody().flush();
            started.countDown();
            try {
              Thread.sleep(2000);
            } catch (InterruptedException ignored) {
              Thread.currentThread().interrupt();
            }
          } finally {
            exchange.close();
          }
        });
    http.start();
    try (var c =
        new KmipClient(
            new HttpsTransport(
                URI.create("https://localhost:" + http.getAddress().getPort() + "/"),
                client,
                HttpsTransport.Encoding.TTLV),
            ProtocolVersion.V2_1)) {
      Future<?> pending = worker.submit(() -> assertThrows(IOException.class, () -> c.get("id")));
      assertTrue(started.await(3, TimeUnit.SECONDS));
      c.close();
      c.close();
      pending.get(2, TimeUnit.SECONDS);
    } finally {
      http.stop(0);
      worker.shutdownNow();
      assertTrue(worker.awaitTermination(3, TimeUnit.SECONDS));
    }
  }

  static void badServer(String identity) throws Exception {
    try (Peer p =
            new Peer(
                context(identity, "ca.pem"),
                (req, out) -> out.write(CODEC.encode(response(req, 0, payload("id")))));
        var c = p.client(ProtocolVersion.V2_1)) {
      assertThrows(IOException.class, () -> c.get("id"));
    }
  }

  static void goodServer(String identity, String ca) throws Exception {
    try (Peer p =
            new Peer(
                context(identity, "ca.pem"),
                (req, out) -> out.write(CODEC.encode(response(req, 0, payload("id")))));
        var c =
            new KmipClient(
                new TlsTransport("localhost", p.listener.getLocalPort(), context("client", ca)),
                ProtocolVersion.V2_1)) {
      assertEquals("id", c.get("id").uniqueIdentifier());
    }
  }

  static void primitives() throws Exception {
    List<Ttlv> values =
        List.of(
            integer(DATA, Integer.MIN_VALUE),
            integer(DATA, Integer.MAX_VALUE),
            Ttlv.of(DATA.code(), Ttlv.Type.LONG_INTEGER, Long.MIN_VALUE),
            Ttlv.of(
                DATA.code(),
                Ttlv.Type.BIG_INTEGER,
                java.math.BigInteger.ONE.shiftLeft(130).negate()),
            enumeration(DATA, 0xffffffff),
            bool(DATA, true),
            bytes(DATA, new byte[0]),
            text(DATA, "雪"),
            dateTime(DATA, Instant.EPOCH),
            Ttlv.of(DATA.code(), Ttlv.Type.INTERVAL, 0xffffffffL),
            Ttlv.of(DATA.code(), Ttlv.Type.DATE_TIME_EXTENDED, -1L),
            identifier(DATA, "id"),
            reference(DATA, "ref"),
            nameReference(DATA, "name"));
    for (Ttlv n : values) {
      assertEquals(n, CODEC.decode(CODEC.encode(n)));
      assertEquals(n, new XmlCodec().decode(new XmlCodec().encode(n)));
      assertEquals(n, new JsonCodec().decode(new JsonCodec().encode(n)));
    }
  }

  static void golden() throws Exception {
    Map<Path, List<Ttlv>> cache = new HashMap<>();
    int count = 0;
    for (String line : Files.readAllLines(ROOT.resolve("sdk/src/test/resources/oracle.tsv"))) {
      if (line.startsWith("#")) continue;
      String[] p = line.split("\t");
      Path path = ROOT.resolve("sdk/src/test/resources/oasis").resolve(p[0]);
      List<Ttlv> nodes = cache.get(path);
      if (nodes == null) {
        String s = Files.readString(path);
        var m = java.util.regex.Pattern.compile("\\$NOW([+-]\\d+)?").matcher(s);
        StringBuilder b = new StringBuilder();
        while (m.find())
          m.appendReplacement(
              b,
              Instant.ofEpochSecond(
                      1700000000L + (m.group(1) == null ? 0 : Long.parseLong(m.group(1))))
                  .toString());
        m.appendTail(b);
        s =
            b.toString()
                .replace("</KMIP>\n\n</KMIP>", "</KMIP>")
                .replaceAll("\\$[A-Za-z0-9_]+", "DEADBEEFCAFE");
        nodes = new XmlCodec().decodeAll(s.getBytes(StandardCharsets.UTF_8));
        cache.put(path, nodes);
      }
      assertEquals(p[2], digest(CODEC.encode(nodes.get(Integer.parseInt(p[1])))));
      count++;
    }
    assertEquals(2712, count);
  }

  static void unsafeKeys() throws Exception {
    for (int variant = 0; variant < 4; variant++) {
      Ttlv block =
          ManagedObjects.keyBlock(
              Enums.KeyFormatType.RAW,
              bytes(KEY_MATERIAL, new byte[variant == 2 ? 31 : 32]),
              variant == 0 ? Enums.CryptographicAlgorithm.RSA : Enums.CryptographicAlgorithm.AES,
              variant == 1 ? 128 : 256);
      Ttlv p =
          structure(
              RESPONSE_PAYLOAD,
              text(UNIQUE_IDENTIFIER, variant == 3 ? "wrong" : "id"),
              enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY),
              ManagedObjects.symmetricKey(block));
      assertThrows(GeneralSecurityException.class, () -> Keys.aesKey(p, "id", 256));
    }
  }

  static void wrapVectors() throws Exception {
    byte[] kek = HexFormat.of().parseHex("000102030405060708090a0b0c0d0e0f"),
        key = HexFormat.of().parseHex("00112233445566778899aabbccddeeff");
    Cipher kw = Cipher.getInstance("AESWrap");
    kw.init(Cipher.WRAP_MODE, new SecretKeySpec(kek, "AES"));
    byte[] wrapped = kw.wrap(new SecretKeySpec(key, "AES"));
    assertEquals(
        "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5", HexFormat.of().formatHex(wrapped));
    kw.init(Cipher.UNWRAP_MODE, new SecretKeySpec(kek, "AES"));
    assertArrayEquals(key, kw.unwrap(wrapped, "AES", Cipher.SECRET_KEY).getEncoded());
    wrapped[0] ^= 1;
    assertThrows(
        GeneralSecurityException.class, () -> kw.unwrap(wrapped, "AES", Cipher.SECRET_KEY));
    Cipher kwp = Cipher.getInstance("AES/KWP/NoPadding");
    byte[] k = HexFormat.of().parseHex("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8"),
        plain = HexFormat.of().parseHex("c37b7e6492584340bed12207808941155068f738");
    kwp.init(Cipher.WRAP_MODE, new SecretKeySpec(k, "AES"));
    assertEquals(
        "138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a",
        HexFormat.of().formatHex(kwp.wrap(new SecretKeySpec(plain, "AES"))));
  }

  static void fuzz() throws Exception {
    assertTimeoutPreemptively(
        Duration.ofSeconds(12),
        () -> {
          Random random = new Random(0x4b4d4950);
          TtlvCodec bounded = new TtlvCodec(4096, 16, 256);
          for (int i = 0; i < 4000; i++) {
            byte[] b = i % 2 == 0 ? CODEC.encode(payload("id")) : new byte[random.nextInt(512)];
            random.nextBytes(i % 2 == 0 ? new byte[0] : b);
            if (b.length > 0) b[random.nextInt(b.length)] ^= (byte) (1 + random.nextInt(255));
            try {
              Ttlv n = bounded.decode(b);
              assertEquals(n, bounded.decode(bounded.encode(n)));
            } catch (IOException | IllegalArgumentException expected) {
            }
          }
        });
  }

  static void pending() throws Exception {
    AtomicInteger calls = new AtomicInteger();
    try (var c =
        new KmipClient(
            req -> {
              int n = calls.getAndIncrement();
              if (n == 0)
                return response(req, 2, bytes(ASYNCHRONOUS_CORRELATION_VALUE, new byte[] {9}));
              return response(
                  req,
                  1,
                  enumeration(RESULT_REASON, Enums.ResultReason.OPERATION_CANCELED_BY_REQUESTER));
            },
            ProtocolVersion.V2_1)) {
      Result first = c.execute(Requests.get().uniqueIdentifier("id").build());
      assertTrue(first.pending());
      assertArrayEquals(new byte[] {9}, first.asynchronousCorrelation().orElseThrow());
      assertFalse(c.poll(new byte[] {9}).successful());
      assertEquals(2, calls.get());
    }
  }

  static void httpsDeadline() throws Exception {
    for (var encoding : HttpsTransport.Encoding.values()) {
      var http =
          com.sun.net.httpserver.HttpsServer.create(new InetSocketAddress("localhost", 0), 8);
      http.setHttpsConfigurator(new com.sun.net.httpserver.HttpsConfigurator(server));
      ExecutorService worker = Executors.newSingleThreadExecutor();
      http.setExecutor(worker);
      http.createContext(
          "/",
          exchange -> {
            observedTls.add(
                ((com.sun.net.httpserver.HttpsExchange) exchange).getSSLSession().getProtocol());
            try {
              exchange.getRequestBody().readAllBytes();
              exchange.getResponseHeaders().set("Content-Type", encoding.mediaType());
              exchange.sendResponseHeaders(200, 512);
              for (int i = 0; i < 32; i++) {
                exchange.getResponseBody().write(42);
                exchange.getResponseBody().flush();
                try {
                  Thread.sleep(60);
                } catch (InterruptedException e) {
                  Thread.currentThread().interrupt();
                  break;
                }
              }
            } finally {
              exchange.close();
            }
          });
      http.start();
      long started = System.nanoTime();
      try (var c =
          new KmipClient(
              new HttpsTransport(
                  URI.create("https://localhost:" + http.getAddress().getPort() + "/"),
                  client,
                  encoding,
                  Duration.ofMillis(250),
                  1024),
              ProtocolVersion.V2_1)) {
        assertThrows(IOException.class, () -> c.get("id"));
      } finally {
        http.stop(0);
        worker.shutdownNow();
        assertTrue(worker.awaitTermination(2, TimeUnit.SECONDS));
      }
      assertTrue(
          System.nanoTime() - started < TimeUnit.SECONDS.toNanos(2),
          "Slow HTTP body exceeded deadline");
    }
  }

  static void https() throws Exception {
    for (HttpsTransport.Encoding encoding : HttpsTransport.Encoding.values())
      for (String identity :
          List.of("server", "mismatch", "expired", "future", "rollover-server")) {
        SSLContext serverContext = context(identity, "ca.pem");
        var http =
            com.sun.net.httpserver.HttpsServer.create(new InetSocketAddress("localhost", 0), 8);
        http.setHttpsConfigurator(
            new com.sun.net.httpserver.HttpsConfigurator(serverContext) {
              @Override
              public void configure(com.sun.net.httpserver.HttpsParameters p) {
                var parameters = serverContext.getDefaultSSLParameters();
                parameters.setNeedClientAuth(true);
                p.setSSLParameters(parameters);
              }
            });
        AtomicInteger requests = new AtomicInteger();
        http.createContext(
            "/",
            exchange -> {
              observedTls.add(
                  ((com.sun.net.httpserver.HttpsExchange) exchange).getSSLSession().getProtocol());
              requests.incrementAndGet();
              try {
                byte[] input = exchange.getRequestBody().readAllBytes();
                Ttlv request =
                    switch (encoding) {
                      case TTLV -> CODEC.decode(input);
                      case XML -> new XmlCodec().decode(input);
                      case JSON -> new JsonCodec().decode(input);
                    };
                Ttlv r = response(request, 0, payload("id"));
                byte[] output =
                    switch (encoding) {
                      case TTLV -> CODEC.encode(r);
                      case XML -> new XmlCodec().encode(r);
                      case JSON -> new JsonCodec().encode(r);
                    };
                exchange.getResponseHeaders().set("Content-Type", encoding.mediaType());
                exchange.sendResponseHeaders(200, output.length);
                exchange.getResponseBody().write(output);
              } finally {
                exchange.close();
              }
            });
        http.start();
        URI endpoint = URI.create("https://localhost:" + http.getAddress().getPort() + "/");
        try {
          try (var c =
              new KmipClient(
                  new HttpsTransport(endpoint, client, encoding), ProtocolVersion.V2_1)) {
            if (identity.equals("server")) assertEquals("id", c.get("id").uniqueIdentifier());
            else {
              assertThrows(IOException.class, () -> c.get("id"));
              assertEquals(0, requests.get(), "Invalid TLS sent a KMIP message");
            }
          }
          if (identity.equals("server"))
            for (String principal : Arrays.asList(null, "untrusted-client"))
              try (var c =
                  new KmipClient(
                      new HttpsTransport(endpoint, context(principal, "ca.pem"), encoding),
                      ProtocolVersion.V2_1)) {
                assertThrows(IOException.class, () -> c.get("id"));
                assertEquals(1, requests.get(), "Anonymous/untrusted request reached KMIP");
              }
        } finally {
          http.stop(0);
        }
      }
  }
}
