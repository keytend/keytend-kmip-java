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

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The Maven Central tools the release workflow runs (docs/releasing.md, step 3): {@code
 * tools/central-bundle.py}, which checks that a Central bundle holds the GitHub release's JARs,
 * and {@code tools/central-upload.py}, which uploads a bundle to the Central Portal and publishes
 * or drops it once validated, here against a stub Portal. Only a release X.Y.Z is published: a
 * pre-release's bundle is refused before anything is sent.
 */
class CentralToolsTest {
  @TempDir Path work;

  private HttpServer portal;
  private final List<String> requests = Collections.synchronizedList(new ArrayList<>());
  private final List<String> states = Collections.synchronizedList(new ArrayList<>());
  private volatile byte[] uploaded = new byte[0];
  private volatile String authorization = "";

  record Run(int exit, String out) {}

  @BeforeEach
  void stubPortal() throws IOException {
    assumeTrue(PackageReleaseSigningTest.onPath("python3"), "python3");
    portal = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    portal.createContext("/api/v1/publisher/", this::answer);
    portal.start();
  }

  @AfterEach
  void stop() {
    if (portal != null) portal.stop(0);
  }

  /** Upload: a deployment ID. Status: the next of {@link #states}. Publish and drop: 204. */
  private void answer(HttpExchange exchange) throws IOException {
    String path = exchange.getRequestURI().getPath();
    String query = exchange.getRequestURI().getRawQuery();
    requests.add(exchange.getRequestMethod() + " " + path + (query == null ? "" : "?" + query));
    authorization = String.valueOf(exchange.getRequestHeaders().getFirst("Authorization"));
    byte[] body = exchange.getRequestBody().readAllBytes();
    int status = 204;
    String reply = "";
    if (path.equals("/api/v1/publisher/upload")) {
      uploaded = body;
      status = 201;
      reply = "d-1";
    } else if (path.equals("/api/v1/publisher/status")) {
      String state = states.size() > 1 ? states.remove(0) : states.get(0);
      status = 200;
      reply =
          "{\"deploymentId\":\"d-1\",\"deploymentState\":\""
              + state
              + "\",\"purls\":[\"pkg:maven/dev.keytend/keytend-kmip@9.9.9\"]"
              + (state.equals("FAILED") ? ",\"errors\":{\"pom\":[\"no license\"]}" : "")
              + "}";
    }
    byte[] bytes = reply.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
    if (bytes.length > 0) exchange.getResponseBody().write(bytes);
    exchange.close();
  }

  private Run run(String tool, String... args) throws Exception {
    List<String> command = new ArrayList<>(List.of("python3", "-I"));
    command.add(LicenseHeadersTest.root().resolve("tools").resolve(tool).toString());
    command.addAll(List.of(args));
    ProcessBuilder pb = new ProcessBuilder(command).redirectErrorStream(true);
    pb.environment()
        .putAll(
            Map.of(
                "KEYTEND_CENTRAL_URL", "http://127.0.0.1:" + portal.getAddress().getPort(),
                "KEYTEND_CENTRAL_POLL_SECONDS", "0.01",
                "CENTRAL_TOKEN_USERNAME", "user",
                "CENTRAL_TOKEN_PASSWORD", "secret",
                "HOME", work.toString()));
    Process p = pb.start();
    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    assertTrue(p.waitFor(60, TimeUnit.SECONDS), String.join(" ", command));
    return new Run(p.exitValue(), out);
  }

  /** A bundle of one artifact at {@code version}: its POM and JAR, at Maven repository paths. */
  private Path bundle(String version, byte[] jar) throws IOException {
    Path zip = work.resolve("central-bundle-" + version + ".zip");
    String dir = "dev/keytend/keytend-kmip/" + version + "/keytend-kmip-" + version;
    try (ZipOutputStream out = new ZipOutputStream(Files.newOutputStream(zip))) {
      out.putNextEntry(new ZipEntry(dir + ".pom"));
      out.write("<project/>".getBytes(StandardCharsets.UTF_8));
      out.putNextEntry(new ZipEntry(dir + ".jar"));
      out.write(jar);
    }
    return zip;
  }

  private static String sha256(byte[] content) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
  }

  @Test
  void dropUploadsTheBundleWaitsForValidationAndDropsIt() throws Exception {
    Path zip = bundle("0.10.0-rc.1", new byte[] {1, 2, 3});
    states.addAll(List.of("PENDING", "VALIDATING", "VALIDATED"));
    Run r =
        run("central-upload.py", zip.toString(), "--name", "keytend-kmip 0.10.0-rc.1", "--drop");
    assertEquals(0, r.exit(), r.out());
    assertTrue(r.out().contains("dropped deployment d-1"), r.out());
    assertEquals(
        "Bearer "
            + Base64.getEncoder().encodeToString("user:secret".getBytes(StandardCharsets.UTF_8)),
        authorization);
    assertEquals(
        "POST /api/v1/publisher/upload?name=keytend-kmip+0.10.0-rc.1&publishingType=USER_MANAGED",
        requests.get(0));
    assertEquals("DELETE /api/v1/publisher/deployment/d-1", requests.get(requests.size() - 1));
    assertFalse(requests.contains("POST /api/v1/publisher/deployment/d-1"), requests.toString());
    String multipart = new String(uploaded, StandardCharsets.ISO_8859_1);
    assertTrue(multipart.contains("name=\"bundle\"; filename=\"" + zip.getFileName() + "\""));
    assertTrue(
        multipart.contains(new String(Files.readAllBytes(zip), StandardCharsets.ISO_8859_1)),
        "the bundle is uploaded as is");
  }

  @Test
  void publishPublishesTheValidatedReleaseAndWaitsUntilItIsPublished() throws Exception {
    Path zip = bundle("9.9.9", new byte[] {1, 2, 3});
    states.addAll(List.of("VALIDATING", "VALIDATED", "PUBLISHING", "PUBLISHED"));
    Run r = run("central-upload.py", zip.toString(), "--name", "keytend-kmip 9.9.9", "--publish");
    assertEquals(0, r.exit(), r.out());
    assertTrue(requests.contains("POST /api/v1/publisher/deployment/d-1"), requests.toString());
    assertTrue(r.out().contains("deployment d-1: PUBLISHED"), r.out());
    assertTrue(r.out().contains("published pkg:maven/dev.keytend/keytend-kmip@9.9.9"), r.out());
  }

  @Test
  void aPreReleaseIsNeverPublishedNorSent() throws Exception {
    Path zip = bundle("0.10.0-rc.1", new byte[] {1, 2, 3});
    states.add("VALIDATED");
    Run r = run("central-upload.py", zip.toString(), "--name", "x", "--publish");
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("REFUSED: only a release X.Y.Z goes to Maven Central"), r.out());
    assertTrue(requests.isEmpty(), requests.toString());
  }

  @Test
  void aDeploymentThePortalRefusesFailsWithItsErrors() throws Exception {
    Path zip = bundle("9.9.9", new byte[] {1, 2, 3});
    states.addAll(List.of("VALIDATING", "FAILED"));
    Run r = run("central-upload.py", zip.toString(), "--name", "x", "--publish");
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("no license"), r.out());
    assertTrue(r.out().contains("FAILED: the Portal refused deployment d-1"), r.out());
    assertFalse(requests.contains("POST /api/v1/publisher/deployment/d-1"), requests.toString());
  }

  @Test
  void theBundleMustHoldTheReleasesJars() throws Exception {
    byte[] jar = {4, 5, 6};
    Path tree = Files.createDirectories(work.resolve("tree"));
    Files.write(
        Files.createDirectories(tree.resolve("sdk/target")).resolve("keytend-kmip-9.9.9.jar"), jar);
    Files.copy(
        bundle("9.9.9", jar),
        Files.createDirectories(tree.resolve("target/central-publishing"))
            .resolve("central-bundle.zip"));
    Path sums = work.resolve("SHA256SUMS");
    Files.writeString(sums, sha256(jar) + "  keytend-kmip-9.9.9/lib/keytend-kmip-9.9.9.jar\n");
    Run r = run("central-bundle.py", tree.toString(), sums.toString());
    assertEquals(0, r.exit(), r.out());
    assertTrue(
        r.out().contains("1 of the bundle's 1 JARs are in SHA256SUMS, every one with its hash"),
        r.out());

    // Another JAR than the release's.
    Files.writeString(
        sums, sha256(new byte[] {7}) + "  keytend-kmip-9.9.9/lib/keytend-kmip-9.9.9.jar\n");
    r = run("central-bundle.py", tree.toString(), sums.toString());
    assertEquals(1, r.exit(), r.out());
    assertTrue(
        r.out().contains("keytend-kmip-9.9.9.jar: not the SHA-256 SHA256SUMS lists"), r.out());

    // A published module's JAR the release lists, missing from the bundle.
    Files.writeString(
        sums,
        sha256(jar)
            + "  keytend-kmip-9.9.9/lib/keytend-kmip-9.9.9.jar\n"
            + sha256(jar)
            + "  keytend-kmip-9.9.9/lib/keytend-kmip-micrometer-9.9.9.jar\n");
    r = run("central-bundle.py", tree.toString(), sums.toString());
    assertEquals(1, r.exit(), r.out());
    assertTrue(
        r.out()
            .contains("keytend-kmip-micrometer-9.9.9.jar: listed in SHA256SUMS, not in the bundle"),
        r.out());
  }
}
