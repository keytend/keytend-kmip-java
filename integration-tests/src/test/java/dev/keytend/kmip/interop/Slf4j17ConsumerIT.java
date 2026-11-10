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

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import javax.tools.DiagnosticCollector;
import javax.tools.JavaCompiler;
import javax.tools.JavaFileObject;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The SDK with SLF4J 1.7.36, as an application that pins slf4j-api 1.7 runs it (docs/production.md,
 * "Which slf4j-api version"): the SDK's main sources compile against slf4j-api 1.7.36, so it calls
 * nothing that only 2.x has; and a consumer that fails over, has a listener that throws and turns
 * the {@code Calls} logger to DEBUG logs those lines through slf4j-simple 1.7.36, on the class path
 * and on the module path. And the trap the guide warns of: slf4j-api 2.x with a 1.7 binding logs
 * nothing, and says so. The 1.7 JARs are copied to {@code target/slf4j-1.7} by the build
 * (integration-tests/pom.xml), outside the test class path, which has 2.0.20.
 */
class Slf4j17ConsumerIT {
  static final String MODULE_INFO =
      "module consumer {\n  requires dev.keytend.kmip;\n  requires dev.keytend.kmip.testing;\n}\n";

  static final String MAIN =
      String.join(
          "\n",
          "package app;",
          "",
          "import dev.keytend.kmip.kms.*;",
          "import dev.keytend.kmip.testing.InMemoryKmipServer;",
          "",
          "public final class Main {",
          "  public static void main(String[] args) throws Exception {",
          "    KmsListener throwing = new KmsListener() {",
          "      @Override public void finished(KmsEvent e) { throw new IllegalStateException(\"listener defect\"); }",
          "    };",
          "    try (InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1)) {",
          "      InMemoryKmipServer replica = server.replica();",
          "      try (Kms kms = Kms.connect(server.configureReplicas(replica).addListener(throwing).build())) {",
          "        KeyHandle key = kms.keys().createAes(256).named(\"slf4j-17\").usages(KeyUsage.ENCRYPT).create();",
          "        server.unreachable(true);",
          "        key.attributes();",
          "      }",
          "    }",
          "    System.out.println(\"OK\");",
          "  }",
          "}",
          "");

  static Path slf4jApi17, slf4jSimple17;

  @BeforeAll
  static void theOneSevenJars() {
    Path dir = Path.of("target", "slf4j-1.7");
    slf4jApi17 = dir.resolve("slf4j-api-1.7.36.jar");
    slf4jSimple17 = dir.resolve("slf4j-simple-1.7.36.jar");
    assertTrue(
        Files.isRegularFile(slf4jApi17) && Files.isRegularFile(slf4jSimple17),
        dir.toAbsolutePath()
            + " has slf4j-api and slf4j-simple 1.7.36: run the build (the slf4j-1.7"
            + " execution of maven-dependency-plugin), not the test alone");
  }

  @Test
  void theSdkCompilesAgainstSlf4jApi17(@TempDir Path out) throws Exception {
    Path sources = Path.of("..", "sdk", "src", "main", "java");
    assertTrue(
        Files.isRegularFile(sources.resolve("module-info.java")),
        sources.toAbsolutePath().toString());
    List<Path> files;
    try (Stream<Path> walk = Files.walk(sources)) {
      files = walk.filter(p -> p.toString().endsWith(".java")).sorted().toList();
    }
    compile(
        List.of(
            "--release",
            "17",
            "-proc:none",
            "-nowarn",
            "--module-path",
            slf4jApi17 + File.pathSeparator + BundledCaffeineConsumerIT.bundledVersion(),
            "-d",
            out.toString()),
        files);
    assertTrue(Files.isRegularFile(out.resolve("dev/keytend/kmip/kms/Kms.class")));
  }

  @Test
  void aConsumerLogsThroughSlf4j17OnTheClassPathAndTheModulePath(@TempDir Path work)
      throws Exception {
    Path out = consumer(work);
    String sdk = ModularConsumerIT.sdk().toString();
    String testing = ModularConsumerIT.testing().toString();
    String classPath =
        String.join(File.pathSeparator, sdk, testing, jar(slf4jApi17), jar(slf4jSimple17));
    checkLogged(run(work, List.of("-cp", classPath + File.pathSeparator + out, "app.Main")));
    checkLogged(
        run(
            work,
            List.of(
                "--module-path",
                classPath + File.pathSeparator + out,
                "--add-modules",
                "ALL-MODULE-PATH",
                "-m",
                "consumer/app.Main")));
  }

  /** slf4j-api 2.x ignores a 1.7 binding: nothing is logged, and SLF4J says why. */
  @Test
  void slf4jApi2WithA17BindingLogsNothing(@TempDir Path work) throws Exception {
    Path out = consumer(work);
    String api2 =
        Path.of(
                org.slf4j.LoggerFactory.class
                    .getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI())
            .toString();
    String classPath =
        String.join(
            File.pathSeparator,
            ModularConsumerIT.sdk().toString(),
            ModularConsumerIT.testing().toString(),
            api2,
            jar(slf4jSimple17));
    String output = run(work, List.of("-cp", classPath + File.pathSeparator + out, "app.Main"));
    assertTrue(output.contains("No SLF4J providers were found"), output);
    assertTrue(output.contains("Ignoring binding found at"), output);
    assertFalse(output.contains("dev.keytend.kmip.kms."), output);
  }

  static void checkLogged(String output) {
    assertTrue(
        output.contains("WARN dev.keytend.kmip.kms.Endpoints - KMS endpoint in-memory:5696 is"),
        output);
    assertTrue(output.contains("WARN dev.keytend.kmip.kms.KmsListener - A KmsListener ("), output);
    assertTrue(output.contains("DEBUG dev.keytend.kmip.kms.Calls - Call "), output);
    assertFalse(output.contains("SLF4J:"), "no binding notice: " + output);
    assertTrue(output.lines().anyMatch(l -> l.equals("OK")), output);
  }

  static String jar(Path p) {
    return p.toAbsolutePath().toString();
  }

  /** The consumer, compiled as a module against the SDK (used from the class path too). */
  static Path consumer(Path work) throws Exception {
    Path src = work.resolve("src"), out = work.resolve("out");
    Files.createDirectories(src.resolve("app"));
    Files.writeString(src.resolve("module-info.java"), MODULE_INFO);
    Files.writeString(src.resolve("app/Main.java"), MAIN);
    compile(
        List.of(
            "--release",
            "17",
            "--module-path",
            ModularConsumerIT.sdk()
                + File.pathSeparator
                + ModularConsumerIT.testing()
                + File.pathSeparator
                + jar(slf4jApi17),
            "-d",
            out.toString()),
        List.of(src.resolve("module-info.java"), src.resolve("app/Main.java")));
    return out;
  }

  static void compile(List<String> options, List<Path> sources) throws Exception {
    JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
    assertNotNull(javac, "a JDK, not a JRE");
    DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
    try (StandardJavaFileManager files =
        javac.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
      boolean compiled =
          javac
              .getTask(
                  null,
                  files,
                  diagnostics,
                  options,
                  null,
                  files.getJavaFileObjectsFromPaths(sources))
              .call();
      assertTrue(compiled, () -> "compiles: " + diagnostics.getDiagnostics());
    }
  }

  /** Runs the JDK's java with {@code args}, the Calls logger at DEBUG; its output and errors. */
  static String run(Path work, List<String> args) throws Exception {
    List<String> command = new ArrayList<>();
    command.add(Path.of(System.getProperty("java.home"), "bin", "java").toString());
    command.add("-Dorg.slf4j.simpleLogger.log.dev.keytend.kmip.kms.Calls=debug");
    command.addAll(args);
    ProcessBuilder builder = new ProcessBuilder(command).redirectErrorStream(true);
    builder.environment().remove("CLASSPATH");
    builder.directory(work.toFile());
    Process p = builder.start();
    String output;
    try (var in = p.getInputStream()) {
      output = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
    assertTrue(p.waitFor(2, TimeUnit.MINUTES), "the consumer finishes");
    assertEquals(0, p.exitValue(), output);
    return output;
  }
}
