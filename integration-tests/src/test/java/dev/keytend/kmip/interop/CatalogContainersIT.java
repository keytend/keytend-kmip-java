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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import java.io.*;
import java.net.*;
import java.net.http.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.*;
import org.junit.jupiter.api.*;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.utility.MountableFile;

/** Same catalog on fresh real servers. Peer qualification failures remain explicit report data. */
class CatalogContainersIT {
  static final Path ROOT = Path.of(System.getProperty("project.root"));
  static Path certs;
  static String commit;

  record Profile(
      String id,
      String directory,
      String build,
      List<ProtocolVersion> versions,
      boolean persistent) {}

  static final List<ProtocolVersion> LEGACY =
      List.of(
          ProtocolVersion.V1_1, ProtocolVersion.V1_2, ProtocolVersion.V1_3, ProtocolVersion.V1_4);

  static final List<Profile> PROFILES =
      List.of(
          new Profile(
              "pykmip",
              "pykmip",
              "481563735cc96eb9f7b363df3c24b2ea68b9353f",
              Stream.concat(LEGACY.stream(), Stream.of(ProtocolVersion.V2_0)).toList(),
              true),
          new Profile(
              "pqctoday",
              "pqctoday",
              "010da23173bd39a57113fe8f5e9466981a52e27c",
              List.of(ProtocolVersion.V3_0),
              true),
          new Profile(
              "krypton",
              "krypton",
              "7ca8dc58615f506b8ce7e9359e625df5cf72a7e5",
              List.of(ProtocolVersion.V1_4),
              true));

  @BeforeAll
  static void setup() throws Exception {
    certs = Files.createTempDirectory("keytend-catalog-servers-");
    Process p =
        new ProcessBuilder(
                "bash",
                ROOT.resolve("integration/catalog/generate-pki.sh").toString(),
                certs.toString())
            .redirectErrorStream(true)
            .start();
    assertTrue(p.waitFor(45, TimeUnit.SECONDS));
    assertEquals(0, p.exitValue());
    Process git =
        new ProcessBuilder("git", "rev-parse", "HEAD")
            .directory(ROOT.toFile())
            .redirectErrorStream(true)
            .start();
    assertTrue(git.waitFor(5, TimeUnit.SECONDS));
    commit = new String(git.getInputStream().readAllBytes(), UTF_8).trim() + "+worktree";
  }

  @AfterAll
  static void cleanup() throws Exception {
    if (certs != null)
      try (var walk = Files.walk(certs)) {
        for (Path p : walk.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
      }
  }

  @TestFactory
  @org.junit.jupiter.api.parallel.Execution(org.junit.jupiter.api.parallel.ExecutionMode.CONCURRENT)
  Stream<DynamicTest> servers() {
    String selected = System.getProperty("kmip.catalog.servers", "");
    Set<String> filter = selected.isBlank() ? Set.of() : Set.of(selected.split(","));
    return PROFILES.stream()
        .filter(p -> filter.isEmpty() || filter.contains(p.id))
        .map(
            profile ->
                DynamicTest.dynamicTest(
                    profile.id,
                    () -> {
                      var image = image(profile);
                      try (var container =
                          new GenericContainer<>(image)
                              .withExposedPorts(5696)
                              .withCopyFileToContainer(MountableFile.forHostPath(certs), "/certs")
                              .withStartupTimeout(Duration.ofMinutes(3))) {
                        container.start();
                        var inspected =
                            container
                                .getDockerClient()
                                .inspectImageCmd(container.getDockerImageName())
                                .exec();
                        String imageId = inspected.getId();
                        String config =
                            digestDirectory(ROOT.resolve("integration/" + profile.directory));
                        List<String> defects = new ArrayList<>();
                        for (ProtocolVersion version : versions(profile)) {
                          try (var fixture =
                              new CatalogFixture(
                                  ROOT,
                                  profile.id,
                                  container.getHost(),
                                  container.getMappedPort(5696),
                                  certs,
                                  version,
                                  profile.build,
                                  imageId,
                                  commit,
                                  config)) {
                            if (profile.persistent)
                              fixture.restart = () -> restart(container, fixture);
                            fixture.serverIdentity =
                                identity -> identity(container, fixture, identity);
                            if (profile.id.equals("pykmip")) {
                              fixture.grant = () -> policy(container, fixture, "catalog-shared");
                              fixture.revokeGrant = () -> policy(container, fixture, "default");
                              fixture.listOnlyGrant =
                                  () -> policy(container, fixture, "catalog-list-only");
                            }
                            var report = new CatalogLiveSuite(fixture).run();
                            fixture.close();
                            report.put(
                                "cleanup",
                                Map.of(
                                    "remaining_run_owned_ids",
                                    List.copyOf(fixture.owned),
                                    "scope",
                                    "Only registered run-owned objects; bounded cleanup, fresh"
                                        + " container removed afterwards"));
                            Catalog.write(
                                ROOT.resolve(
                                    "integration/reports/catalog/"
                                        + profile.id
                                        + "-"
                                        + version
                                        + "-jdk"
                                        + Runtime.version().feature()
                                        + ".json"),
                                report);
                            @SuppressWarnings("unchecked")
                            var results = (List<Map<String, Object>>) report.get("records");
                            assertEquals(145, results.size());
                            for (var result : results)
                              if (result.get("outcome").equals("FAIL_CLIENT"))
                                defects.add(
                                    version
                                        + " "
                                        + result.get("test_id")
                                        + ": "
                                        + result.get("reason"));
                            if (Boolean.getBoolean("kmip.catalog.strict")
                                && !(Boolean)
                                    ((Map<?, ?>) report.get("qualification")).get("qualified"))
                              defects.add(
                                  version
                                      + " required READ_AES/MANAGE_AES qualification did not pass");
                          }
                        }
                        assertTrue(defects.isEmpty(), String.join("\n", defects));
                      }
                    }));
  }

  /** The fixture image, built from its directory. */
  static ImageFromDockerfile image(Profile profile) {
    return new ImageFromDockerfile("localhost/keytend-" + profile.id + ":catalog", false)
        .withFileFromPath(".", ROOT.resolve("integration/" + profile.directory));
  }

  static List<ProtocolVersion> versions(Profile profile) {
    if (Runtime.version().feature() == 17 || Boolean.getBoolean("kmip.catalog.exhaustive"))
      return profile.versions;
    ProtocolVersion representative = profile.versions.get(profile.versions.size() - 1);
    if (Runtime.version().feature() == 21) {
      if (profile.id.equals("pykmip")) representative = ProtocolVersion.V1_4;
    }
    return List.of(representative);
  }

  static void identity(GenericContainer<?> container, CatalogFixture fixture, String identity)
      throws Exception {
    if (!Set.of(
            "server",
            "chain-server",
            "missing-chain",
            "replacement-server",
            "revoked-server",
            "rollover-server")
        .contains(identity)) throw new IllegalArgumentException("Unknown fixture identity");
    String base = identity.equals("missing-chain") ? "chain-server" : identity;
    String pem = identity.equals("chain-server") ? "full-chain-server" : base;
    container.copyFileToContainer(
        MountableFile.forHostPath(fixture.certs.resolve(pem + ".pem"), 0644), "/certs/server.pem");
    container.copyFileToContainer(
        MountableFile.forHostPath(fixture.certs.resolve(base + "-key.pem"), 0644),
        "/certs/server-key.pem");
    container.copyFileToContainer(
        MountableFile.forHostPath(fixture.certs.resolve(identity + ".p12"), 0644),
        "/certs/server.p12");
    String before =
        container
            .getDockerClient()
            .inspectContainerCmd(container.getContainerId())
            .exec()
            .getState()
            .getStartedAt();
    container
        .getDockerClient()
        .restartContainerCmd(container.getContainerId())
        .withTimeout(2)
        .exec();
    CatalogTls.awaitIdentity(fixture, identity);
    String after =
        container
            .getDockerClient()
            .inspectContainerCmd(container.getContainerId())
            .exec()
            .getState()
            .getStartedAt();
    if (Objects.equals(before, after))
      Catalog.blocked("Native certificate switch did not start a new server process");
    @SuppressWarnings("unchecked")
    List<String> transitions =
        (List<String>)
            fixture.evidence.computeIfAbsent(
                "native_certificate_transitions", ignored -> new ArrayList<String>());
    transitions.add(identity);
  }

  static void restart(GenericContainer<?> container, CatalogFixture fixture) throws Exception {
    String before =
        container
            .getDockerClient()
            .inspectContainerCmd(container.getContainerId())
            .exec()
            .getState()
            .getStartedAt();
    try {
      container
          .getDockerClient()
          .restartContainerCmd(container.getContainerId())
          .withTimeout(2)
          .exec();
    } catch (RuntimeException e) {
      fixture.evidence.put("restart_control_error", e.getClass().getSimpleName());
    }
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(15);
    boolean ready = false;
    while (System.nanoTime() < deadline) {
      try {
        fixture.client.get(fixture.knownUid);
        ready = true;
        break;
      } catch (IOException e) {
        Thread.sleep(100);
      }
    }
    if (!ready) Catalog.blocked("Persistent listener failed binary Get readiness after restart");
    String after =
        container
            .getDockerClient()
            .inspectContainerCmd(container.getContainerId())
            .exec()
            .getState()
            .getStartedAt();
    if (Objects.equals(before, after))
      Catalog.blocked(
          "Runtime did not confirm a new process start; existing key read is not credited as"
              + " restart persistence");
    fixture.evidence.put(
        "restart_proof",
        Map.of("before", before, "after", after, "readiness", "successful exact-ID Get"));
  }

  static String digestDirectory(Path directory) throws Exception {
    var digest = java.security.MessageDigest.getInstance("SHA-256");
    try (var files = Files.walk(directory)) {
      for (Path p : files.filter(Files::isRegularFile).sorted().toList()) {
        digest.update(
            directory.relativize(p).toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        digest.update(Files.readAllBytes(p));
      }
    }
    return HexFormat.of().formatHex(digest.digest());
  }

  static void policy(GenericContainer<?> container, CatalogFixture fixture, String name)
      throws Exception {
    fixture.provision();
    // OperationPolicyName is server-managed in PyKMIP. Use the disposable fixture's
    // administrative database access; authorization decisions remain upstream code.
    org.testcontainers.containers.Container.ExecResult result;
    try {
      result =
          container.execInContainer(
              "python",
              "-c",
              "import sqlite3,sys; c=sqlite3.connect('/tmp/pykmip.db',timeout=5); "
                  + "r=c.execute('UPDATE managed_objects SET operation_policy_name=? WHERE uid=?', "
                  + "(sys.argv[2],sys.argv[1])); assert r.rowcount==1; c.commit()",
              fixture.knownUid,
              name);
    } catch (RuntimeException runtimeControlFailure) {
      Catalog.blocked(
          "Container administration failed: " + runtimeControlFailure.getClass().getSimpleName());
      return;
    }
    if (result.getExitCode() != 0) Catalog.blocked("Native PyKMIP policy administration failed");
    fixture.evidence.put(
        "policy_adapter",
        "Administrative SQLite OperationPolicyName update on exact run-owned UID; upstream"
            + " authorization unchanged");
  }
}
