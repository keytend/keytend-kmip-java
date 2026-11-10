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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The SDK JAR, with its bundled and relocated Caffeine, beside an application's own Caffeine of
 * another version (2.9.3, whose API differs from 3.x), on the class path and on the module path
 * (docs/compatibility.md, "Caffeine is bundled"). The application caches with its Caffeine, from
 * its own JAR, while a {@code LocalKeys} cache, which runs on the bundled one, loads, hits, evicts
 * and expires; neither sees the other. The SDK JAR alone runs the cache too: it needs no Caffeine
 * JAR. The Caffeine JARs are copied to {@code target/caffeine} by the build
 * (integration-tests/pom.xml), outside the test class path.
 */
class BundledCaffeineConsumerIT {
  /** The application's own Caffeine, a version the SDK does not bundle. */
  static Path applicationVersion() {
    return copied("caffeine-2.9.3.jar");
  }

  /** The version the SDK bundles, for compiling the SDK's own sources (Slf4j17ConsumerIT). */
  static Path bundledVersion() {
    return copied("caffeine-3.3.1.jar");
  }

  private static Path copied(String name) {
    Path jar = Path.of("target", "caffeine", name).toAbsolutePath();
    assertTrue(
        Files.isRegularFile(jar),
        jar
            + " is missing: run the build (the caffeine execution of maven-dependency-plugin), not"
            + " the test alone");
    return jar;
  }

  /** The application: its own Caffeine, then the SDK's cache ({@link #KEYS}). */
  static final String MAIN =
      String.join(
          "\n",
          "package app;",
          "",
          "import com.github.benmanes.caffeine.cache.Cache;",
          "import com.github.benmanes.caffeine.cache.Caffeine;",
          "",
          "public final class Main {",
          "  public static void main(String[] args) throws Exception {",
          "    Cache<String, String> own = Caffeine.newBuilder().maximumSize(10).build();",
          "    own.put(\"a\", \"1\");",
          "    System.out.println(\"own \" + own.getIfPresent(\"a\") + \" from \"",
          "        + Caffeine.class.getProtectionDomain().getCodeSource().getLocation());",
          "    Keys.main(args);",
          "  }",
          "}",
          "");

  /** A {@code LocalKeys} cache that loads, hits, evicts and expires; no Caffeine of its own. */
  static final String KEYS =
      String.join(
          "\n",
          "package app;",
          "",
          "import dev.keytend.kmip.kms.*;",
          "import dev.keytend.kmip.testing.InMemoryKmipServer;",
          "import java.time.Duration;",
          "",
          "public final class Keys {",
          "  public static void main(String[] args) throws Exception {",
          "    CustomAttribute family = CustomAttribute.client(\"family\");",
          "    try (InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);",
          "        Kms kms = Kms.connect(server.configure().build())) {",
          "      KeyHandle write = kms.keys().createAes(256).named(\"orders-write\").extractable(true)",
          "          .custom(family, \"orders\").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();",
          "      KeyHandle old = kms.keys().createAes(256).extractable(true)",
          "          .custom(family, \"orders\").usages(KeyUsage.DECRYPT).create();",
          "      try (LocalKeys keys = kms.keys().localKeys(\"orders-write\")",
          "          .scope(KeyQuery.all().custom(family, \"orders\")).expect(Expect.aes(256))",
          "          .ttl(Duration.ofMillis(400)).capacity(2).open()) {",
          "        for (int i = 0; i < 3; i++) {",
          "          try (LocalKeys.Use use = keys.forEncrypt()) {",
          "            if (!use.id().equals(write.id())) throw new AssertionError(use.id());",
          "          }",
          "          try (LocalKeys.Use use = keys.forDecrypt(old.id())) {}",
          "        }",
          "        Thread.sleep(1500);",
          "        try (LocalKeys.Use use = keys.forDecrypt(old.id())) {}",
          "        LocalKeys.Stats s = keys.stats();",
          "        System.out.println(\"hits \" + (s.encryptHits() + s.decryptHits()) + \" evictions \"",
          "            + s.evictions() + \" loads \" + s.loads());",
          "      }",
          "    }",
          "    System.out.println(\"OK\");",
          "  }",
          "}",
          "");

  static final String MODULE_INFO =
      "module consumer {\n"
          + "  requires dev.keytend.kmip;\n"
          + "  requires dev.keytend.kmip.testing;\n"
          + "  requires com.github.benmanes.caffeine;\n"
          + "}\n";

  /** The consumer, compiled as a module against the SDK and the application's Caffeine. */
  static Path consumer(Path work) throws Exception {
    Path src = work.resolve("src"), out = work.resolve("out");
    Files.createDirectories(src.resolve("app"));
    Files.writeString(src.resolve("module-info.java"), MODULE_INFO);
    Files.writeString(src.resolve("app/Main.java"), MAIN);
    Files.writeString(src.resolve("app/Keys.java"), KEYS);
    Slf4j17ConsumerIT.compile(
        List.of(
            "--release",
            "17",
            "--module-path",
            String.join(
                File.pathSeparator,
                ModularConsumerIT.testModulePath(),
                applicationVersion().toString()),
            "-d",
            out.toString()),
        List.of(
            src.resolve("module-info.java"),
            src.resolve("app/Main.java"),
            src.resolve("app/Keys.java")));
    return out;
  }

  static void check(String output) {
    assertTrue(
        output
            .lines()
            .anyMatch(l -> l.startsWith("own 1 from ") && l.endsWith("caffeine-2.9.3.jar")),
        "the application's Caffeine is its own JAR's: " + output);
    checkCache(output);
  }

  /** The cache hit, evicted or expired, and the program finished. */
  static void checkCache(String output) {
    String stats =
        output
            .lines()
            .filter(l -> l.startsWith("hits "))
            .findFirst()
            .orElseThrow(() -> new AssertionError(output));
    String[] words = stats.split(" ");
    assertTrue(Long.parseLong(words[1]) >= 4, "the cache hit: " + stats);
    assertTrue(Long.parseLong(words[3]) >= 1, "it evicted or expired: " + stats);
    assertTrue(output.lines().anyMatch(l -> l.equals("OK")), output);
    assertFalse(output.contains("Exception"), output);
  }

  @Test
  void theSdkRunsBesideAnApplicationsOwnCaffeineOnTheClassPath(@TempDir Path work)
      throws Exception {
    Path out = consumer(work);
    String classPath =
        String.join(
            File.pathSeparator,
            ModularConsumerIT.testModulePath(),
            applicationVersion().toString(),
            out.toString());
    check(Slf4j17ConsumerIT.run(work, List.of("-cp", classPath, "app.Main")));
  }

  @Test
  void theSdkRunsBesideAnApplicationsOwnCaffeineOnTheModulePath(@TempDir Path work)
      throws Exception {
    Path out = consumer(work);
    String modulePath =
        String.join(
            File.pathSeparator,
            ModularConsumerIT.testModulePath(),
            applicationVersion().toString(),
            out.toString());
    check(
        Slf4j17ConsumerIT.run(
            work,
            List.of(
                "--module-path",
                modulePath,
                // Caffeine 2.x, an automatic module, uses sun.misc.Unsafe: the application adds
                // jdk.unsupported for its own Caffeine. The SDK's bundled 3.x needs nothing.
                "--add-modules",
                "jdk.unsupported",
                "-m",
                "consumer/app.Main")));
  }

  /** Without any Caffeine JAR: the SDK JAR carries the cache's. */
  @Test
  void theSdkNeedsNoCaffeineJar(@TempDir Path work) throws Exception {
    Path out = consumer(work);
    String classPath =
        String.join(File.pathSeparator, ModularConsumerIT.testModulePath(), out.toString());
    checkCache(Slf4j17ConsumerIT.run(work, List.of("-cp", classPath, "app.Keys")));
  }
}
