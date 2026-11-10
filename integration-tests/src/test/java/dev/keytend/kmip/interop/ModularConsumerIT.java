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

import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.File;
import java.lang.module.ModuleDescriptor;
import java.lang.module.ModuleFinder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.jar.JarFile;
import javax.tools.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * An application that is itself a named module uses the SDK from the module path. A tiny
 * module, {@code consumer}, that {@code requires dev.keytend.kmip} and, as an application's tests
 * would, {@code dev.keytend.kmip.testing} (the in-memory server's own module, keytend-kmip-testing),
 * and nothing else, is compiled with {@code javax.tools} against the SDK this build made, and run by
 * the JDK's {@code java} with {@code --module-path} and no class path. It uses the application API
 * ({@code kms}: a key created, rotated with a {@code Rotation}, encrypting and decrypting through
 * the in-memory server), {@code codec} (XmlCodec, which needs {@code java.xml}) and {@code transport}
 * (HttpsTransport, which needs {@code java.net.http}), none of which the consumer requires itself;
 * and it sees what the module does not give: the SDK's own tables (resources in the unexported
 * package {@code dev.keytend.kmip}, which the SDK reads for the calls above) are not found from
 * another module, through the module or an SDK class, and deep reflection into an exported package
 * is refused (nothing is opened). The Caffeine the SDK JAR bundles, relocated into {@code
 * dev.keytend.kmip.internal.shaded.caffeine}, is inside the module and out of the consumer's reach:
 * Caffeine's own name is not there at all, a consumer that imports the relocated classes does not
 * compile, and reflection into them is refused.
 */
class ModularConsumerIT {
  static final String MODULE_INFO =
      "module consumer {\n  requires dev.keytend.kmip;\n  requires dev.keytend.kmip.testing;\n}\n";

  static final String MAIN =
      String.join(
          "\n",
          "package app;",
          "",
          "import dev.keytend.kmip.codec.XmlCodec;",
          "import dev.keytend.kmip.kms.*;",
          "import dev.keytend.kmip.model.Tag;",
          "import dev.keytend.kmip.model.Ttlv;",
          "import dev.keytend.kmip.testing.InMemoryKmipServer;",
          "import dev.keytend.kmip.transport.HttpsTransport;",
          "import java.lang.reflect.InaccessibleObjectException;",
          "import java.nio.charset.StandardCharsets;",
          "import java.util.Arrays;",
          "",
          "public final class Main {",
          "  public static void main(String[] args) throws Exception {",
          "    Module sdk = Kms.class.getModule();",
          "    check(sdk.isNamed() && sdk.getName().equals(\"dev.keytend.kmip\"), \"the SDK is the named module: \" + sdk);",
          "    check(!sdk.getDescriptor().isAutomatic(), \"with a descriptor, not an automatic module\");",
          "    check(Main.class.getModule().getName().equals(\"consumer\"), \"this is a named module\");",
          "    byte[] aad = \"orders\".getBytes(StandardCharsets.UTF_8);",
          "    byte[] plaintext = \"modular\".getBytes(StandardCharsets.UTF_8);",
          "    try (InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1); Kms kms = server.connect()) {",
          "      KeyHandle key = kms.keys().createAes(256).named(\"modular-kek\").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();",
          "      KeyHandle current = key.rotate(Rotation.of(RotationDates.COPIED));",
          "      byte[] stored = current.encrypt(CipherSpec.aesGcm(), plaintext, aad).toBytes();",
          "      byte[] opened = kms.keys().decrypt(KeyQuery.byName(\"modular-kek\"), Ciphertext.fromBytes(stored), aad);",
          "      check(Arrays.equals(plaintext, opened), \"kms: sealed and opened\");",
          "      System.out.println(\"kms \" + kms.version());",
          "    }",
          "    XmlCodec xml = new XmlCodec();",
          "    Ttlv name = Ttlv.text(Tag.UNIQUE_IDENTIFIER, \"k-1\");",
          "    check(xml.decode(xml.encode(name)).equals(name), \"codec: XML round trip (java.xml)\");",
          "    System.out.println(\"codec xml\");",
          "    new HttpsTransport(java.net.URI.create(\"https://localhost:1/kmip\"), javax.net.ssl.SSLContext.getDefault(),",
          "        HttpsTransport.Encoding.values()[0]).close();",
          "    System.out.println(\"transport https\");",
          "    check(sdk.getResourceAsStream(\"dev/keytend/kmip/payloads.tsv\") == null, \"the SDK's tables are not exported\");",
          "    check(Kms.class.getResourceAsStream(\"/dev/keytend/kmip/payloads.tsv\") == null, \"nor through an SDK class\");",
          "    System.out.println(\"tables encapsulated\");",
          "    try {",
          "      Class.forName(\"dev.keytend.kmip.kms.Lineage\").getDeclaredConstructors()[0].setAccessible(true);",
          "      throw new AssertionError(\"deep reflection into dev.keytend.kmip.kms was allowed\");",
          "    } catch (InaccessibleObjectException refused) {",
          "      System.out.println(\"reflection refused\");",
          "    }",
          "    try {",
          "      Class.forName(\"com.github.benmanes.caffeine.cache.Caffeine\");",
          "      throw new AssertionError(\"Caffeine is on the module path\");",
          "    } catch (ClassNotFoundException absent) {",
          "      System.out.println(\"no Caffeine\");",
          "    }",
          "    Class<?> bundled = Class.forName(\"dev.keytend.kmip.internal.shaded.caffeine.cache.Caffeine\");",
          "    check(bundled.getModule() == sdk, \"the bundled Caffeine is in the SDK's module: \" + bundled.getModule());",
          "    check(!sdk.isExported(bundled.getPackageName()) && !sdk.isOpen(bundled.getPackageName()), \"and not exported\");",
          "    try {",
          "      bundled.getMethod(\"newBuilder\").invoke(null);",
          "      throw new AssertionError(\"the bundled Caffeine was callable\");",
          "    } catch (IllegalAccessException refused) {",
          "      System.out.println(\"bundled Caffeine not accessible\");",
          "    }",
          "    try {",
          "      bundled.getMethod(\"newBuilder\").setAccessible(true);",
          "      throw new AssertionError(\"deep reflection into the bundled Caffeine was allowed\");",
          "    } catch (InaccessibleObjectException refused) {",
          "      System.out.println(\"bundled Caffeine not opened\");",
          "    }",
          "    System.out.println(\"OK\");",
          "  }",
          "",
          "  static void check(boolean ok, String what) {",
          "    if (!ok) throw new AssertionError(what);",
          "  }",
          "}",
          "");

  /**
   * Where this build's SDK is: the JAR (or, in a reactor build stopped before {@code package}, the
   * class directory) the tests resolved it from. Either is a module on the module path.
   */
  static Path sdk() throws Exception {
    return Path.of(Kms.class.getProtectionDomain().getCodeSource().getLocation().toURI());
  }

  /**
   * The module path a consumer needs: the SDK and its one module dependency, {@code org.slf4j}
   * (slf4j-api, which the build resolved with the SDK). With no SLF4J provider, logging is off.
   */
  static String modulePath() throws Exception {
    Path slf4j =
        Path.of(
            org.slf4j.LoggerFactory.class
                .getProtectionDomain()
                .getCodeSource()
                .getLocation()
                .toURI());
    return sdk() + File.pathSeparator + slf4j;
  }

  /** Where this build's keytend-kmip-testing is (its JAR, or its class directory). */
  static Path testing() throws Exception {
    return Path.of(
        InMemoryKmipServer.class.getProtectionDomain().getCodeSource().getLocation().toURI());
  }

  /** The module path of an application's tests: {@link #modulePath} and keytend-kmip-testing. */
  static String testModulePath() throws Exception {
    return modulePath() + File.pathSeparator + testing();
  }

  /** The relocated Caffeine's packages: the JAR bundles them, no descriptor exports them. */
  static final Set<String> BUNDLED =
      Set.of(
          "dev.keytend.kmip.internal.shaded.caffeine.cache",
          "dev.keytend.kmip.internal.shaded.caffeine.cache.stats");

  /**
   * The SDK JAR this build made: the published artifact, Caffeine bundled in it. A class directory
   * (a reactor build stopped before {@code package}) is the unshaded SDK, which these tests do not
   * describe.
   */
  static Path sdkJar() throws Exception {
    Path sdk = sdk();
    assertTrue(
        Files.isRegularFile(sdk) && sdk.getFileName().toString().endsWith(".jar"),
        sdk
            + " is not the SDK's JAR: run ./mvnw verify, which packages it, not a phase before package");
    return sdk;
  }

  /** The SDK's descriptor as the module system reads it from the module path. */
  @Test
  void theSdkIsANamedModuleOnTheModulePath() throws Exception {
    Path sdk = sdkJar();
    ModuleDescriptor d =
        ModuleFinder.of(sdk)
            .find("dev.keytend.kmip")
            .orElseThrow(() -> new AssertionError(sdk + " is not the module dev.keytend.kmip"))
            .descriptor();
    assertFalse(
        d.isAutomatic(),
        sdk
            + " has no module-info.class: build the reactor (./mvnw verify), not this module alone against an older SDK");
    Set<String> exports = new TreeSet<>();
    d.exports().forEach(e -> exports.add(e.source()));
    assertEquals(
        new TreeSet<>(
            List.of(
                "dev.keytend.kmip.client",
                "dev.keytend.kmip.codec",
                "dev.keytend.kmip.kms",
                "dev.keytend.kmip.model",
                "dev.keytend.kmip.server",
                "dev.keytend.kmip.transport")),
        exports);
    assertTrue(
        d.packages().contains("dev.keytend.kmip"),
        "the tables' package is in the module, not exported");
    assertFalse(
        d.packages().contains("dev.keytend.kmip.testing"),
        "the in-memory server is not in the SDK: " + d.packages());
    assertTrue(
        d.packages().containsAll(BUNDLED),
        "the relocated Caffeine's packages are in the module: " + d.packages());
    assertTrue(
        d.packages().stream()
            .filter(p -> p.startsWith("dev.keytend.kmip.internal"))
            .allMatch(p -> p.startsWith("dev.keytend.kmip.internal.shaded.caffeine")),
        "dev.keytend.kmip.internal holds the bundled Caffeine only: " + d.packages());
    assertEquals(Set.of(), d.opens(), "nothing is opened");
    assertFalse(d.isOpen());
    Set<String> requires = new TreeSet<>();
    d.requires().forEach(r -> requires.add(r.name()));
    assertEquals(Set.of("java.base", "java.net.http", "java.xml", "org.slf4j"), requires);
    assertEquals(Set.of(), d.uses());
    assertEquals(List.of(), d.provides().stream().toList());
  }

  /**
   * The published descriptor is the source one (src/main/java/module-info.java, which the SDK's
   * own tests run in) without its requirement of Caffeine, which the JAR bundles: the same exports,
   * opens, services and other requirements, with the same modifiers.
   */
  @Test
  void thePublishedDescriptorIsTheSourceOneWithoutCaffeine() throws Exception {
    Path compiled = Path.of("../sdk/target/classes/module-info.class");
    assertTrue(Files.isRegularFile(compiled), compiled + ": build the reactor (./mvnw verify)");
    ModuleDescriptor source;
    try (var in = Files.newInputStream(compiled)) {
      source = ModuleDescriptor.read(in);
    }
    ModuleDescriptor published =
        ModuleFinder.of(sdkJar()).find("dev.keytend.kmip").orElseThrow().descriptor();
    assertTrue(
        source.requires().stream().anyMatch(r -> r.name().equals("com.github.benmanes.caffeine")),
        "the source descriptor requires Caffeine");
    Set<ModuleDescriptor.Requires> expected = new HashSet<>(source.requires());
    expected.removeIf(r -> r.name().equals("com.github.benmanes.caffeine"));
    assertEquals(source.name(), published.name());
    // moditect marks every descriptor it writes SYNTHETIC, a flag without effect on resolution or
    // access; there is no other difference.
    Set<ModuleDescriptor.Modifier> modifiers = new HashSet<>(source.modifiers());
    modifiers.add(ModuleDescriptor.Modifier.SYNTHETIC);
    assertEquals(modifiers, published.modifiers());
    assertEquals(source.exports(), published.exports());
    assertEquals(source.opens(), published.opens());
    assertEquals(source.uses(), published.uses());
    assertEquals(source.provides(), published.provides());
    // By name and modifiers: javac also records the version each module had at compile time.
    assertEquals(modifiers(expected), modifiers(published.requires()));
    assertEquals(source.version(), published.version());
    assertEquals(Optional.empty(), published.mainClass());
  }

  private static Map<String, Set<ModuleDescriptor.Requires.Modifier>> modifiers(
      Collection<ModuleDescriptor.Requires> requires) {
    Map<String, Set<ModuleDescriptor.Requires.Modifier>> modifiers = new TreeMap<>();
    requires.forEach(r -> modifiers.put(r.name(), r.modifiers()));
    return modifiers;
  }

  /**
   * The JAR bundles Caffeine relocated, and nothing of it under its own name: no entry under
   * {@code com/github/benmanes}, no class (the SDK's or the bundled ones) that names it, and no
   * descriptor, manifest, signature or service file of Caffeine's. The JAR has the SDK's
   * descriptor only, without a ModulePackages attribute (the module system then finds every
   * package in the JAR, the relocated ones too), and no Automatic-Module-Name. Caffeine's license
   * and Maven coordinates are beside the SDK's.
   */
  @Test
  void theJarBundlesCaffeineRelocatedOnly() throws Exception {
    byte[] internal = "com/github/benmanes".getBytes(StandardCharsets.US_ASCII);
    byte[] dotted = "com.github.benmanes".getBytes(StandardCharsets.US_ASCII);
    int sdkClasses = 0, bundledClasses = 0;
    try (java.util.jar.JarFile jar = new java.util.jar.JarFile(sdkJar().toFile())) {
      List<String> names = jar.stream().map(java.util.zip.ZipEntry::getName).toList();
      for (String name : names) {
        assertFalse(name.startsWith("com/"), "an entry under its own name: " + name);
        assertFalse(
            name.endsWith("module-info.class") && !name.equals("module-info.class"),
            "another descriptor: " + name);
        assertFalse(
            name.startsWith("META-INF/services/")
                || name.startsWith("META-INF/versions/")
                || name.matches("META-INF/[^/]+\\.(SF|DSA|RSA|EC)"),
            "a service, versioned or signature entry: " + name);
        if (!name.endsWith(".class") || name.equals("module-info.class")) continue;
        byte[] bytes;
        try (var in = jar.getInputStream(jar.getEntry(name))) {
          bytes = in.readAllBytes();
        }
        assertFalse(contains(bytes, internal), name + " names com/github/benmanes");
        if (name.startsWith("dev/keytend/kmip/internal/shaded/caffeine/")) bundledClasses++;
        else {
          sdkClasses++;
          assertFalse(contains(bytes, dotted), name + " names com.github.benmanes");
        }
      }
      assertTrue(sdkClasses > 100 && bundledClasses > 100, sdkClasses + " " + bundledClasses);
      assertTrue(
          names.contains("META-INF/LICENSE")
              && names.contains("META-INF/NOTICE")
              && names.contains("META-INF/licenses/caffeine/LICENSE"),
          "the SDK's and Caffeine's licenses");
      java.util.Properties caffeine = new java.util.Properties();
      try (var in =
          jar.getInputStream(
              jar.getEntry(
                  "META-INF/maven/com.github.ben-manes.caffeine/caffeine/pom.properties"))) {
        caffeine.load(in);
      }
      assertEquals("com.github.ben-manes.caffeine", caffeine.getProperty("groupId"));
      assertEquals("caffeine", caffeine.getProperty("artifactId"));
      assertTrue(names.contains("META-INF/maven/com.github.ben-manes.caffeine/caffeine/pom.xml"));
      java.util.jar.Attributes manifest = jar.getManifest().getMainAttributes();
      assertNull(manifest.getValue("Automatic-Module-Name"));
      assertNull(manifest.getValue("Multi-Release"));
      byte[] descriptor;
      try (var in = jar.getInputStream(jar.getEntry("module-info.class"))) {
        descriptor = in.readAllBytes();
      }
      assertFalse(
          contains(descriptor, "ModulePackages".getBytes(StandardCharsets.US_ASCII)),
          "the descriptor lists no packages; the module system finds them in the JAR");
    }
  }

  static boolean contains(byte[] bytes, byte[] part) {
    outer:
    for (int i = 0; i + part.length <= bytes.length; i++) {
      for (int j = 0; j < part.length; j++) if (bytes[i + j] != part[j]) continue outer;
      return true;
    }
    return false;
  }

  /**
   * A consumer that imports the bundled, relocated Caffeine does not compile: its packages are in
   * the SDK's module, which does not export them.
   */
  @Test
  void aModuleCannotCompileAgainstTheBundledCaffeine(@TempDir Path work) throws Exception {
    Path src = work.resolve("src");
    Files.createDirectories(src.resolve("app"));
    Files.writeString(src.resolve("module-info.java"), MODULE_INFO);
    Files.writeString(
        src.resolve("app/Main.java"),
        String.join(
            "\n",
            "package app;",
            "",
            "import dev.keytend.kmip.internal.shaded.caffeine.cache.Caffeine;",
            "",
            "public final class Main {",
            "  public static void main(String[] args) {",
            "    Caffeine.newBuilder().build();",
            "  }",
            "}",
            ""));
    sdkJar();
    JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
    DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
    try (StandardJavaFileManager files =
        javac.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
      // An empty class path: javax.tools would otherwise use this JVM's, where the SDK JAR is too.
      Files.createDirectories(work.resolve("empty"));
      List<String> options =
          List.of(
              "--release",
              "17",
              "--class-path",
              work.resolve("empty").toString(),
              "--module-path",
              testModulePath(),
              "-d",
              work.resolve("out").toString());
      assertFalse(
          javac
              .getTask(
                  null,
                  files,
                  diagnostics,
                  options,
                  null,
                  files.getJavaFileObjects(
                      src.resolve("module-info.java"), src.resolve("app/Main.java")))
              .call());
    }
    String messages = diagnostics.getDiagnostics().toString();
    assertTrue(
        messages.contains("dev.keytend.kmip.internal.shaded.caffeine.cache")
            && messages.contains("declared in module dev.keytend.kmip, which does not export it"),
        messages);
  }

  /**
   * The SDK JAR holds no class, source or resource of the in-memory server: it is keytend-kmip-testing's,
   * a test dependency, never part of what an application runs with. (In a reactor build stopped
   * before {@code package} the SDK is its class directory, checked the same way.)
   */
  @Test
  void theSdkHoldsNoneOfTheInMemoryServer() throws Exception {
    Path sdk = sdk();
    List<String> found = new ArrayList<>();
    if (Files.isDirectory(sdk)) {
      Path testing = sdk.resolve("dev/keytend/kmip/testing");
      if (Files.exists(testing))
        try (var files = Files.walk(testing)) {
          files.forEach(f -> found.add(sdk.relativize(f).toString()));
        }
    } else
      try (JarFile jar = new JarFile(sdk.toFile())) {
        jar.stream()
            .map(e -> e.getName())
            .filter(n -> n.startsWith("dev/keytend/kmip/testing/"))
            .forEach(found::add);
      }
    assertEquals(List.of(), found, sdk + " holds the in-memory server");
    assertNotEquals(
        sdk, testing(), "the in-memory server comes from its own artifact, keytend-kmip-testing");
  }

  /**
   * keytend-kmip-testing is the named module {@code dev.keytend.kmip.testing}: it exports only the
   * testing package and requires the SDK transitively (its API shows the SDK's types), and nothing
   * else but {@code java.base}.
   */
  @Test
  void theTestingModuleIsANamedModuleOnTheModulePath() throws Exception {
    Path testing = testing();
    ModuleDescriptor d =
        ModuleFinder.of(testing)
            .find("dev.keytend.kmip.testing")
            .orElseThrow(() -> new AssertionError(testing + " is not dev.keytend.kmip.testing"))
            .descriptor();
    assertFalse(d.isAutomatic());
    Set<String> exports = new TreeSet<>();
    d.exports().forEach(e -> exports.add(e.source()));
    assertEquals(Set.of("dev.keytend.kmip.testing"), exports);
    assertEquals(Set.of("dev.keytend.kmip.testing"), d.packages());
    Map<String, Set<ModuleDescriptor.Requires.Modifier>> requires = new TreeMap<>();
    d.requires().forEach(r -> requires.put(r.name(), r.modifiers()));
    assertEquals(Set.of("java.base", "dev.keytend.kmip"), requires.keySet());
    assertEquals(
        Set.of(ModuleDescriptor.Requires.Modifier.TRANSITIVE), requires.get("dev.keytend.kmip"));
  }

  @Test
  void aModularApplicationCompilesAndRunsAgainstTheSdk(@TempDir Path work) throws Exception {
    sdkJar();
    Path src = work.resolve("src"), out = work.resolve("out");
    Files.createDirectories(src.resolve("app"));
    Files.writeString(src.resolve("module-info.java"), MODULE_INFO);
    Files.writeString(src.resolve("app/Main.java"), MAIN);

    JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
    assertNotNull(javac, "a JDK, not a JRE");
    DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
    try (StandardJavaFileManager files =
        javac.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
      List<String> options =
          List.of("--release", "17", "--module-path", testModulePath(), "-d", out.toString());
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
    assertTrue(Files.exists(out.resolve("module-info.class")));

    Path java = Path.of(System.getProperty("java.home"), "bin", "java");
    // No SLF4J provider: logging is off, and SLF4J's own warning that it is stays unprinted.
    ProcessBuilder run =
        new ProcessBuilder(
                java.toString(),
                // No provider: SLF4J's own notice of the no-operation logger is not the consumer's
                // output.
                "-Dslf4j.internal.verbosity=ERROR",
                "--module-path",
                testModulePath() + File.pathSeparator + out,
                "-m",
                "consumer/app.Main")
            .redirectErrorStream(true);
    run.environment().remove("CLASSPATH");
    Process p = run.start();
    String output;
    try (var in = p.getInputStream()) {
      output = new String(in.readAllBytes(), StandardCharsets.UTF_8);
    }
    assertTrue(p.waitFor(2, TimeUnit.MINUTES), "the consumer finishes");
    assertEquals(0, p.exitValue(), output);
    assertEquals(
        List.of(
            "kms 2.1",
            "codec xml",
            "transport https",
            "tables encapsulated",
            "reflection refused",
            "no Caffeine",
            "bundled Caffeine not accessible",
            "bundled Caffeine not opened",
            "OK"),
        output.lines().filter(l -> !l.isBlank()).toList(),
        output);
  }

  /**
   * The consumer must require the SDK: without {@code requires dev.keytend.kmip}, its {@code kms}
   * types do not resolve (the module system's boundary, not the class path's).
   */
  @Test
  void aModuleThatDoesNotRequireTheSdkCannotUseIt(@TempDir Path work) throws Exception {
    Path src = work.resolve("src");
    Files.createDirectories(src.resolve("app"));
    Files.writeString(src.resolve("module-info.java"), "module consumer {\n}\n");
    Files.writeString(src.resolve("app/Main.java"), MAIN);
    JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
    DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
    try (StandardJavaFileManager files =
        javac.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
      List<String> options =
          List.of(
              "--release",
              "17",
              "--module-path",
              modulePath(),
              "-d",
              work.resolve("out").toString());
      assertFalse(
          javac
              .getTask(
                  null,
                  files,
                  diagnostics,
                  options,
                  null,
                  files.getJavaFileObjects(
                      src.resolve("module-info.java"), src.resolve("app/Main.java")))
              .call());
    }
    String messages = diagnostics.getDiagnostics().toString();
    assertTrue(
        messages.contains("dev.keytend.kmip.kms") && messages.contains("does not read"), messages);
  }

  /**
   * The SDK alone does not give the in-memory server: a module that requires only {@code
   * dev.keytend.kmip}, with only the SDK and slf4j-api on its module path, cannot use {@code
   * dev.keytend.kmip.testing}. The class path is empty: javac would otherwise take this test's.
   */
  @Test
  void theSdkAloneDoesNotGiveTheInMemoryServer(@TempDir Path work) throws Exception {
    Path src = work.resolve("src");
    Files.createDirectories(src.resolve("app"));
    Files.writeString(
        src.resolve("module-info.java"), "module consumer {\n  requires dev.keytend.kmip;\n}\n");
    Files.writeString(src.resolve("app/Main.java"), MAIN);
    JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
    DiagnosticCollector<JavaFileObject> diagnostics = new DiagnosticCollector<>();
    try (StandardJavaFileManager files =
        javac.getStandardFileManager(diagnostics, null, StandardCharsets.UTF_8)) {
      List<String> options =
          List.of(
              "--release",
              "17",
              "--module-path",
              modulePath(),
              "--class-path",
              Files.createDirectories(work.resolve("empty")).toString(),
              "-d",
              work.resolve("out").toString());
      assertFalse(
          javac
              .getTask(
                  null,
                  files,
                  diagnostics,
                  options,
                  null,
                  files.getJavaFileObjects(
                      src.resolve("module-info.java"), src.resolve("app/Main.java")))
              .call());
    }
    List<String> errors = new ArrayList<>();
    for (Diagnostic<?> d : diagnostics.getDiagnostics())
      if (d.getKind() == Diagnostic.Kind.ERROR) errors.add(d.getMessage(Locale.ROOT));
    assertTrue(
        errors.stream()
            .allMatch(
                m -> m.contains("dev.keytend.kmip.testing") || m.contains("InMemoryKmipServer")),
        errors.toString());
    assertTrue(
        errors.stream()
            .anyMatch(m -> m.contains("package dev.keytend.kmip.testing does not exist")),
        errors.toString());
  }
}
