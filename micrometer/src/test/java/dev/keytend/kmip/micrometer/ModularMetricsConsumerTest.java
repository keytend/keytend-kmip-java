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
package dev.keytend.kmip.micrometer;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * An application that is a named module uses the metrics module from the module path, with
 * Micrometer as the automatic modules its JARs are: {@code requires dev.keytend.kmip.micrometer}
 * alone gives it the SDK and {@code micrometer.core} (both required transitively), so it compiles
 * against {@code SimpleMeterRegistry} and the SDK's types, and runs: its listener's meters fill. It
 * also requires {@code dev.keytend.kmip.testing}, the in-memory server, as an application's tests
 * would.
 */
class ModularMetricsConsumerTest {
  static final String MODULE_INFO =
      "module consumer {\n  requires dev.keytend.kmip.micrometer;\n  requires dev.keytend.kmip.testing;\n}\n";

  static final String MAIN =
      String.join(
          "\n",
          "package app;",
          "",
          "import dev.keytend.kmip.kms.*;",
          "import dev.keytend.kmip.micrometer.KmipMeters;",
          "import dev.keytend.kmip.testing.InMemoryKmipServer;",
          "import io.micrometer.core.instrument.simple.SimpleMeterRegistry;",
          "",
          "public final class Main {",
          "  public static void main(String[] args) throws Exception {",
          "    SimpleMeterRegistry registry = new SimpleMeterRegistry();",
          "    try (InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);",
          "        Kms kms = Kms.connect(server.configure().addListener(KmipMeters.listener(registry)).build())) {",
          "      kms.keys().createAes(256).named(\"modular-metrics\").usages(KeyUsage.ENCRYPT).create();",
          "    }",
          "    System.out.println(registry.find(\"kmip.client.calls\").timers().isEmpty() ? \"no meters\" : \"OK\");",
          "  }",
          "}",
          "");

  /**
   * The module path: this module (its classes), and the runtime JARs of its graph as this test
   * resolved them: the SDK, keytend-kmip-testing, slf4j-api, Micrometer's core, commons and
   * observation, HdrHistogram and JSpecify. Before package, the SDK is its classes, with the
   * Caffeine they require.
   */
  static String modulePath() throws Exception {
    Set<String> entries = new LinkedHashSet<>();
    entries.add(
        Path.of(KmipMeters.class.getProtectionDomain().getCodeSource().getLocation().toURI())
            .toString());
    Path sdk =
        Path.of(
            dev.keytend.kmip.kms.Kms.class
                .getProtectionDomain()
                .getCodeSource()
                .getLocation()
                .toURI());
    entries.add(sdk.toString());
    entries.add(
        Path.of(
                dev.keytend.kmip.testing.InMemoryKmipServer.class
                    .getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI())
            .toString());
    List<String> wanted =
        new ArrayList<>(
            List.of(
                "slf4j-api-",
                "micrometer-core-",
                "micrometer-commons-",
                "micrometer-observation-",
                "HdrHistogram-",
                "jspecify-"));
    // Before package (./mvnw test, an IDE) the SDK is its class directory, whose descriptor
    // requires the Caffeine the JAR bundles from package on.
    if (Files.isDirectory(sdk)) wanted.add("caffeine-");
    for (String property : List.of("jdk.module.path", "java.class.path"))
      for (String entry : System.getProperty(property, "").split(File.pathSeparator))
        for (String name : wanted)
          if (Path.of(entry).getFileName() != null
              && Path.of(entry).getFileName().toString().startsWith(name)) entries.add(entry);
    assertEquals(3 + wanted.size(), entries.size(), "the graph's JARs: " + entries);
    return String.join(File.pathSeparator, entries);
  }

  @Test
  void aModularApplicationUsesTheMetricsModule(@TempDir Path work) throws Exception {
    Path src = work.resolve("src"), out = work.resolve("out");
    Files.createDirectories(src.resolve("app"));
    Files.writeString(src.resolve("module-info.java"), MODULE_INFO);
    Files.writeString(src.resolve("app/Main.java"), MAIN);
    String modulePath = modulePath();
    JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
    assertNotNull(javac, "a JDK, not a JRE");
    DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
    try (StandardJavaFileManager files =
        javac.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
      List<String> options =
          List.of("--release", "17", "--module-path", modulePath, "-d", out.toString());
      boolean compiled =
          javac
              .getTask(
                  null,
                  files,
                  diagnostics,
                  options,
                  null,
                  files.getJavaFileObjects(
                      src.resolve("module-info.java"), src.resolve("app/Main.java")))
              .call();
      assertTrue(compiled, () -> "the consumer compiles: " + diagnostics.getDiagnostics());
    }
    List<String> command = new ArrayList<>();
    command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
    command.addAll(
        List.of(
            "-Dslf4j.internal.verbosity=ERROR",
            "--module-path",
            modulePath + File.pathSeparator + out,
            "-m",
            "consumer/app.Main"));
    ProcessBuilder run = new ProcessBuilder(command).redirectErrorStream(true);
    run.environment().remove("CLASSPATH");
    Process p = run.start();
    String output;
    try (var in = p.getInputStream()) {
      output = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
    assertTrue(p.waitFor(2, TimeUnit.MINUTES), "the consumer finishes");
    assertEquals(0, p.exitValue(), output);
    assertEquals(List.of("OK"), output.lines().filter(l -> !l.isBlank()).toList(), output);
  }
}
