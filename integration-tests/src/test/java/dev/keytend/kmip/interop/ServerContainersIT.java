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

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.*;
import java.nio.file.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import org.junit.jupiter.api.*;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.utility.MountableFile;

/**
 * Starts real independent server implementations. No Docker absence skip: -Pintegration must
 * actually test servers.
 */
class ServerContainersIT {
  private static final Path ROOT = Path.of(System.getProperty("project.root"));
  private static Path CERTS;

  @BeforeAll
  static void certificates() throws Exception {
    CERTS = Files.createTempDirectory("keytend-servers-");
    Process p =
        new ProcessBuilder(
                "bash", ROOT.resolve("integration/generate-certs.sh").toString(), CERTS.toString())
            .inheritIO()
            .start();
    assertTrue(p.waitFor(30, TimeUnit.SECONDS), "Certificate generation timeout");
    assertEquals(0, p.exitValue());
  }

  @AfterAll
  static void cleanup() throws Exception {
    if (CERTS != null)
      try (var walk = Files.walk(CERTS)) {
        for (Path p : walk.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
      }
  }

  @TestFactory
  Stream<DynamicTest> independentServers() {
    return Stream.of("pykmip", "pqctoday")
        .map(
            server ->
                DynamicTest.dynamicTest(
                    server,
                    () -> {
                      var image =
                          new ImageFromDockerfile(
                                  "localhost/keytend-" + server + ":integration", false)
                              .withFileFromPath(".", ROOT.resolve("integration/" + server));
                      try (var container =
                          new GenericContainer<>(image)
                              .withExposedPorts(5696)
                              .withCopyFileToContainer(MountableFile.forHostPath(CERTS), "/certs")
                              .withStartupTimeout(Duration.ofMinutes(2))) {
                        container.start();
                        var ssl =
                            Tls.context(
                                CERTS.resolve("client.p12"),
                                "changeit".toCharArray(),
                                CERTS.resolve("ca.pem"));
                        List<String> failures = new ArrayList<>();
                        for (ProtocolVersion version : ProtocolVersion.values()) {
                          if (server.equals("pykmip") && !version.legacyAttributes()) continue;
                          if (server.equals("pqctoday") && version != ProtocolVersion.V3_0)
                            continue;
                          try (var client =
                              new KmipClient(
                                  new TlsTransport(
                                      container.getHost(), container.getMappedPort(5696), ssl),
                                  version)) {
                            var checks =
                                version.legacyAttributes()
                                    ? new InteropSuite(client, server, CERTS).run()
                                    : new ModernInteropSuite(client, server, CERTS).run();
                            InteropSuite.writeReport(
                                ROOT.resolve(
                                    "integration/reports/"
                                        + server
                                        + "-"
                                        + version
                                        + "-jdk"
                                        + Runtime.version().feature()
                                        + ".json"),
                                server,
                                version,
                                checks);
                            for (var check : checks)
                              if (check.outcome().equals("FAIL"))
                                failures.add(version + " " + check.name() + ": " + check.detail());
                            assertTrue(
                                checks.stream().filter(c -> c.outcome().equals("PASS")).count()
                                    >= 10,
                                "Too few actual success checks for " + version);
                          }
                        }
                        assertTrue(
                            failures.isEmpty(),
                            String.join("\n", failures)
                                + "\nServer log:\n"
                                + container
                                    .getLogs()
                                    .substring(Math.max(0, container.getLogs().length() - 4000)));
                      }
                    }));
  }
}
