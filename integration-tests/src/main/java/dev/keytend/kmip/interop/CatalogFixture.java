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

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.*;
import java.io.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.*;

/** One exact endpoint/build/version/identity tuple; no shared capability or key cache. */
public final class CatalogFixture implements AutoCloseable {
  @FunctionalInterface
  public interface Action {
    void run() throws Exception;
  }

  @FunctionalInterface
  public interface IdentitySwitcher {
    void use(String identity) throws Exception;
  }

  public IdentitySwitcher serverIdentity;
  public final Path root, certs;
  public final String server, host, build, image, commit, configurationHash;
  public final String clientSourceHash;
  public volatile Long clockOffsetMillis;
  public String serverBinarySha256 = "unverified";

  /**
   * SHA-256 of the server image's {@code RootFS.Layers} ({@link Catalog#layerDigest}), the image's
   * content identity; "unverified" when not inspected.
   */
  public String imageLayersSha256 = "unverified";

  public final int port;
  public final ProtocolVersion version;
  public final String namespace = "catalog-" + UUID.randomUUID();
  public final Set<String> owned = new LinkedHashSet<>();
  public final Map<String, Object> evidence = new LinkedHashMap<>();
  public final Map<String, Object> snapshot = new LinkedHashMap<>();
  public final KmipClient client;
  public Action restart;
  public Action grant;
  public Action revokeGrant;
  public Action listOnlyGrant;
  public boolean readOnlyRole;
  public String knownUid;
  public String knownSha;
  public String tlsVersion = "not_observed";
  public long attempts;
  public volatile List<String> lastResponseShape = List.of();

  /** Tag/type outline of the last request (no values), kept with each record. */
  public volatile List<String> lastRequestShape = List.of();

  /** Opens the transport for a named client identity (test seam; live fixtures use TLS). */
  @FunctionalInterface
  interface Identities {
    KmipTransport open(String principal) throws Exception;
  }

  private final Identities identities;

  public CatalogFixture(
      Path root,
      String server,
      String host,
      int port,
      Path certs,
      ProtocolVersion version,
      String build,
      String image,
      String commit,
      String configHash)
      throws Exception {
    this(
        root,
        server,
        host,
        port,
        certs,
        version,
        build,
        image,
        commit,
        configHash,
        tls(host, port, certs, "client"),
        null);
  }

  /**
   * A fixture over an in-process peer: the owner exchanges through {@code primary} and {@link
   * #identity} opens {@code identities}. Used by the contract tests to build every catalog request
   * without a server; TLS, restart and reference helpers still target {@code host:port}.
   */
  CatalogFixture(
      Path root,
      String server,
      String host,
      int port,
      Path certs,
      ProtocolVersion version,
      String build,
      String image,
      String commit,
      String configHash,
      KmipTransport primary,
      Identities identities)
      throws Exception {
    this.identities = identities;
    this.root = root;
    this.server = server;
    this.host = host;
    this.port = port;
    this.certs = certs;
    this.version = version;
    this.build = build;
    this.image = image;
    this.commit = commit;
    this.configurationHash = configHash;
    var sourceDigest = java.security.MessageDigest.getInstance("SHA-256");
    for (String directory :
        List.of("sdk/src/main", "integration-tests/src/main", "integration-tests/src/test"))
      try (var files = Files.walk(root.resolve(directory))) {
        for (Path p : files.filter(Files::isRegularFile).sorted().toList())
          sourceDigest.update(Files.readAllBytes(p));
      }
    clientSourceHash = HexFormat.of().formatHex(sourceDigest.digest());
    client =
        new KmipClient(
            new KmipTransport() {
              @Override
              public Ttlv exchange(Ttlv request) throws IOException {
                synchronized (CatalogFixture.this) {
                  attempts++;
                }
                List<String> requestShape = new ArrayList<>();
                shape(request, requestShape);
                lastRequestShape = List.copyOf(requestShape);
                Ttlv response = primary.exchange(request);
                try {
                  clockOffsetMillis =
                      java.time.Duration.between(
                              response
                                  .require(Tag.RESPONSE_HEADER)
                                  .require(Tag.TIME_STAMP)
                                  .instantValue(),
                              java.time.Instant.now())
                          .toMillis();
                } catch (RuntimeException ignored) {
                }
                List<String> shape = new ArrayList<>();
                shape(response, shape);
                lastResponseShape = List.copyOf(shape);
                List<Ttlv> requested = request.children(dev.keytend.kmip.model.Tag.BATCH_ITEM),
                    returned = response.children(dev.keytend.kmip.model.Tag.BATCH_ITEM);
                for (int i = 0; i < Math.min(requested.size(), returned.size()); i++) {
                  int operation =
                      requested.get(i).require(dev.keytend.kmip.model.Tag.OPERATION).intValue();
                  if (Set.of(1, 2, 3, 4, 5, 6, 7, 29, 40, 41, 42, 59, 61, 62, 64)
                          .contains(operation)
                      && returned
                          .get(i)
                          .child(dev.keytend.kmip.model.Tag.RESULT_STATUS)
                          .map(n -> n.intValue() == 0)
                          .orElse(false))
                    returned
                        .get(i)
                        .child(dev.keytend.kmip.model.Tag.RESPONSE_PAYLOAD)
                        .ifPresent(
                            p -> {
                              for (Tag tag :
                                  List.of(
                                      Tag.UNIQUE_IDENTIFIER,
                                      Tag.PRIVATE_KEY_UNIQUE_IDENTIFIER,
                                      Tag.PUBLIC_KEY_UNIQUE_IDENTIFIER))
                                for (Ttlv uid : p.children(tag)) owned.add(uid.textValue());
                            });
                }
                return response;
              }

              @Override
              public void close() throws IOException {
                primary.close();
              }
            },
            version);
  }

  private static void shape(Ttlv node, List<String> result) {
    if (result.size() >= 48) return;
    result.add(node.tagName() + ":" + node.type());
    if (node.type() == Ttlv.Type.STRUCTURE) for (Ttlv child : node.children()) shape(child, result);
  }

  public TlsTransport transport(String principal) throws Exception {
    return tls(host, port, certs, principal);
  }

  /**
   * The fixture's connection for one identity. It connects with the SDK's default timeout (10 s):
   * a shorter one gives up before Linux's second SYN retransmission (one, then three seconds),
   * which a server with a small listen backlog under concurrent callers needs (PyKMIP's is five).
   */
  private static TlsTransport tls(String host, int port, Path certs, String principal)
      throws Exception {
    return TlsTransport.builder(
            host,
            port,
            Tls.context(
                certs.resolve(principal + ".p12"),
                "changeit".toCharArray(),
                certs.resolve("ca.pem")))
        .readTimeout(Duration.ofSeconds(3))
        .codec(new TtlvCodec(1024 * 1024, 32))
        .build();
  }

  public KmipClient identity(String principal) throws Exception {
    if (identities != null) return new KmipClient(identities.open(principal), version);
    return new KmipClient(transport(principal), version);
  }

  public void handshake(String principal, String... protocols) throws Exception {
    SSLContext context =
        Tls.context(
            principal == null ? null : certs.resolve(principal + ".p12"),
            "changeit".toCharArray(),
            certs.resolve("ca.pem"));
    try (SSLSocket s = (SSLSocket) context.getSocketFactory().createSocket(host, port)) {
      s.setSoTimeout(2000);
      var p = s.getSSLParameters();
      p.setEndpointIdentificationAlgorithm("HTTPS");
      p.setProtocols(protocols.length == 0 ? new String[] {"TLSv1.3", "TLSv1.2"} : protocols);
      s.setSSLParameters(p);
      s.startHandshake();
      tlsVersion = s.getSession().getProtocol();
      // TLS 1.3 may defer the missing-client-certificate alert until the first application read.
      s.getOutputStream()
          .write(
              new TtlvCodec()
                  .encode(
                      Messages.request(
                          version,
                          List.of(Requests.get().uniqueIdentifier("absent").build()),
                          RequestOptions.DEFAULT)));
      new TtlvCodec().read(s.getInputStream());
    }
  }

  public Map<String, String> reference(String action, String uid) throws Exception {
    List<String> command =
        new ArrayList<>(
            List.of(
                "python3",
                root.resolve("integration/catalog/reference.py").toString(),
                action,
                host,
                Integer.toString(port),
                certs.toString(),
                version.toString()));
    if (uid != null) command.addAll(List.of("--uid", uid));
    Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
    if (!process.waitFor(12, TimeUnit.SECONDS)) {
      process.destroyForcibly();
      Catalog.blocked("Independent reference timeout");
    }
    String output =
        new String(
            process.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
    if (process.exitValue() != 0)
      throw new IOException("Independent reference failed; exit=" + process.exitValue());
    Map<String, String> result = new HashMap<>();
    var matcher =
        java.util.regex.Pattern.compile(
                "\\\"(uid|sha256|tls)\\\"\\s*:\\s*\\\"([^\\\"]*)\\\"|\\\"(bits|algorithm)\\\"\\s*:\\s*(\\d+)")
            .matcher(output);
    while (matcher.find())
      result.put(
          matcher.group(1) != null ? matcher.group(1) : matcher.group(3),
          matcher.group(2) != null ? matcher.group(2) : matcher.group(4));
    if (!result.containsKey("uid"))
      throw new IOException("Incomplete independent reference evidence");
    return result;
  }

  public void provision() throws Exception {
    if (knownUid != null) return;
    if (server.equals("krypton")) {
      knownUid = "client:catalog-key:1";
      byte[] b = new byte[32];
      for (int i = 0; i < b.length; i++) b[i] = (byte) (i + 1);
      knownSha = Catalog.digest(b);
    } else {
      var r = reference("register", null);
      knownUid = r.get("uid");
      knownSha = r.get("sha256");
      owned.add(knownUid);
    }
  }

  public Map<String, Object> provenance() {
    Map<String, Object> m = new LinkedHashMap<>(Catalog.runtime());
    m.put("server_id", server);
    m.put("server_version", build);
    m.put("image_digest", image);
    m.put("server_binary_sha256", serverBinarySha256);
    m.put("image_layers_sha256", imageLayersSha256);
    m.put("wire_version", version.toString());
    m.put("tls_version", tlsVersion);
    m.put("client_commit", commit);
    m.put("client_worktree_sha256", clientSourceHash);
    m.put("configuration_hash", configurationHash);
    m.put("identity_role", "owner_a");
    m.put("namespace", namespace);
    m.put("seed", 0x4b4d4950);
    return m;
  }

  private boolean closed;

  /**
   * How long cleanup may take for {@code objects} run-owned objects: 8 s, plus 250 ms an object
   * for its Revoke and Destroy, at most 60 s. A 2.x run owns about 90 objects; a server that takes
   * 45 ms an operation needs about 8 s for them, which the old flat 8 s budget did not leave.
   */
  static Duration cleanupBudget(int objects) {
    Duration budget = Duration.ofSeconds(8).plusMillis(250L * objects);
    Duration limit = Duration.ofSeconds(60);
    return budget.compareTo(limit) < 0 ? budget : limit;
  }

  @Override
  public void close() throws Exception {
    if (closed) return;
    closed = true;
    long until = System.nanoTime() + cleanupBudget(owned.size()).toNanos();
    try {
      for (String uid : List.copyOf(owned)) {
        if (System.nanoTime() >= until) break;
        try {
          client.revoke(uid, Enums.RevocationReasonCode.CESSATION_OF_OPERATION, "catalog cleanup");
        } catch (IOException unavailable) {
          break;
        } catch (KmipException rejected) {
          /* Pre-active/destroyed objects need not accept Revoke. */
        }
        try {
          client.destroy(uid);
          owned.remove(uid);
        } catch (IOException unavailable) {
          break;
        } catch (KmipException rejected) {
          if (rejected.result().reason() != null
              && Set.of(1, 55).contains(rejected.result().reason())) owned.remove(uid);
        }
      }
    } finally {
      client.close();
    }
  }
}
