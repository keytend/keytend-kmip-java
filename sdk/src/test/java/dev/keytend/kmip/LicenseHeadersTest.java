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

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;

/**
 * The build's license-header check: every project-authored source document in the
 * repository starts with the Apache-2.0 header in its comment syntax, by the rules of {@code
 * tools/license_headers.py}, which this mirrors so that the build needs no Python. Run that tool
 * without {@code --check} to add missing headers.
 */
class LicenseHeadersTest {
  private static final String TEXT =
      String.join(
          "\n",
          "Copyright 2026 Jeremiah Jordan",
          "",
          "Licensed under the Apache License, Version 2.0 (the \"License\");",
          "you may not use this file except in compliance with the License.",
          "You may obtain a copy of the License at",
          "",
          "    https://www.apache.org/licenses/LICENSE-2.0",
          "",
          "Unless required by applicable law or agreed to in writing, software",
          "distributed under the License is distributed on an \"AS IS\" BASIS,",
          "WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.",
          "See the License for the specific language governing permissions and",
          "limitations under the License.");
  private static final String JAVA = "/*\n" + prefixed(" * ", " *") + "\n */\n";
  private static final String XML = "<!--\n" + TEXT + "\n-->\n";
  private static final String HASH = prefixed("# ", "#") + "\n";
  private static final String SLASH = prefixed("// ", "//") + "\n";

  private static final Set<String> SKIPPED_DIRECTORIES =
      Set.of(".git", ".cache", ".claude", "target", "__pycache__");
  // Original OASIS fixtures, generated certificates and run reports keep their own terms.
  private static final List<String> SKIPPED_PREFIXES =
      List.of("sdk/src/test/resources/", "integration/certs/", "integration/reports/");
  // The license texts and the third-party Maven wrapper scripts.
  private static final Set<String> SKIPPED_NAMES = Set.of("LICENSE", "NOTICE", "mvnw", "mvnw.cmd");
  private static final Set<String> SUFFIXES =
      Set.of(
          ".java",
          ".py",
          ".sh",
          ".go",
          ".xml",
          ".yaml",
          ".yml",
          ".toml",
          ".md",
          ".html",
          ".svg",
          ".properties");
  private static final Set<String> NAMES = Set.of("Dockerfile", "go.mod", ".gitignore");

  private static String prefixed(String prefix, String bare) {
    return TEXT.lines().map(l -> l.isEmpty() ? bare : prefix + l).collect(Collectors.joining("\n"));
  }

  static Path root() {
    return Path.of(System.getProperty("project.root", "..")).toAbsolutePath().normalize();
  }

  /** Python's {@code Path.suffix}: a leading dot alone is not a suffix. */
  private static String suffix(String name) {
    int dot = name.lastIndexOf('.');
    return dot > 0 ? name.substring(dot) : "";
  }

  static List<Path> sourceDocuments(Path root) throws IOException {
    List<Path> files = new ArrayList<>();
    Files.walkFileTree(
        root,
        new SimpleFileVisitor<>() {
          @Override
          public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
            String rel = root.relativize(dir).toString().replace('\\', '/') + "/";
            return SKIPPED_DIRECTORIES.contains(dir.getFileName().toString())
                    || SKIPPED_PREFIXES.stream().anyMatch(rel::startsWith)
                ? FileVisitResult.SKIP_SUBTREE
                : FileVisitResult.CONTINUE;
          }

          @Override
          public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
            String name = file.getFileName().toString();
            if (attrs.isRegularFile()
                && !SKIPPED_NAMES.contains(name)
                && (SUFFIXES.contains(suffix(name)) || NAMES.contains(name))) files.add(file);
            return FileVisitResult.CONTINUE;
          }
        });
    Collections.sort(files);
    return files;
  }

  /** Whether {@code value}, the content of a file called {@code name}, starts with its header. */
  static boolean licensed(String name, String value) {
    value = value.replace("\r\n", "\n");
    String suffix = suffix(name);
    if (suffix.equals(".html"))
      return value.startsWith(XML)
          || value
              .toLowerCase(Locale.ROOT)
              .startsWith("<!doctype html>\n" + XML.toLowerCase(Locale.ROOT));
    String header;
    if (suffix.equals(".java")) header = JAVA;
    else if (suffix.equals(".go") || name.equals("go.mod")) header = SLASH;
    else if (Set.of(".xml", ".svg", ".md").contains(suffix)) header = XML;
    else header = HASH;
    if (value.startsWith("#!") || value.startsWith("<?xml")) {
      int newline = value.indexOf('\n');
      return newline >= 0 && value.substring(newline + 1).startsWith(header);
    }
    return value.startsWith(header);
  }

  @Test
  void everySourceDocumentHasTheApacheHeader() throws IOException {
    Path root = root();
    assertTrue(Files.isRegularFile(root.resolve("NOTICE")), "project root found: " + root);
    List<Path> files = sourceDocuments(root);
    List<String> missing = new ArrayList<>();
    for (Path file : files) {
      String value = new String(Files.readAllBytes(file), StandardCharsets.UTF_8);
      if (!licensed(file.getFileName().toString(), value))
        missing.add(root.relativize(file).toString());
    }
    assertEquals(
        List.of(),
        missing,
        "missing or malformed Apache-2.0 headers (python3 tools/license_headers.py adds them)");
    Set<String> checked =
        files.stream()
            .map(f -> root.relativize(f).toString().replace('\\', '/'))
            .collect(Collectors.toSet());
    for (String expected :
        List.of(
            "pom.xml",
            "SECURITY.md",
            "tools/package-release.py",
            "sdk/src/main/java/dev/keytend/kmip/model/Ttlv.java",
            "sdk/src/test/java/dev/keytend/kmip/LicenseHeadersTest.java"))
      assertTrue(checked.contains(expected), "checked " + expected);
    assertFalse(checked.contains("mvnw"), "the third-party wrapper keeps its own notice");
    assertTrue(
        checked.stream().noneMatch(f -> f.startsWith("sdk/src/test/resources/")),
        "OASIS fixtures keep their own notices");
  }

  @Test
  void theCheckRefusesMalformedHeaders() {
    assertTrue(licensed("A.java", JAVA + "\npackage a;\n"));
    // A header run into the code (as TlsHandshakeFailoverTest's was) is not one.
    assertFalse(licensed("A.java", JAVA.substring(0, JAVA.length() - 1) + "package a;\n"));
    assertFalse(licensed("A.java", "package a;\n"));
    assertFalse(licensed("A.java", HASH + "\npackage a;\n"));
    assertTrue(licensed("run.sh", "#!/bin/sh\n" + HASH + "\necho\n"));
    assertFalse(licensed("run.sh", "#!/bin/sh\necho\n" + HASH));
    assertTrue(licensed("pom.xml", "<?xml version=\"1.0\" ?>\n" + XML + "\n<project/>\n"));
    assertTrue(licensed("README.md", XML + "\n# Title\n"));
    assertFalse(licensed("README.md", "# Title\n" + XML));
    assertTrue(licensed("a.html", "<!DOCTYPE html>\n" + XML + "<html/>"));
    assertTrue(licensed("go.mod", SLASH + "\nmodule a\n"));
    assertTrue(licensed(".gitignore", HASH + "\ntarget/\n"));
    assertTrue(licensed("Dockerfile", HASH.replace("\n", "\r\n") + "\r\nFROM a\r\n"));
  }

  @Test
  void theJarNoticesAreTheRepositorys() throws IOException {
    Path root = root();
    for (String module :
        List.of("sdk", "testing", "micrometer", "opentelemetry", "cli", "integration-tests"))
      for (String notice : List.of("LICENSE", "NOTICE"))
        assertArrayEquals(
            Files.readAllBytes(root.resolve(notice)),
            Files.readAllBytes(root.resolve(module + "/src/main/resources/META-INF/" + notice)),
            module + "'s META-INF/" + notice);
  }

  /**
   * The SDK's JARs bundle Caffeine (sdk/pom.xml): they carry its license as Caffeine ships it, at
   * META-INF/licenses/caffeine/LICENSE beside the SDK's own, and NOTICE names the version the build
   * bundles.
   */
  @Test
  void theBundledCaffeinesLicenseAndNoticeAreIncluded() throws IOException {
    Path root = root();
    byte[] upstream;
    try (var in =
        com.github.benmanes.caffeine.cache.Caffeine.class
            .getModule()
            .getResourceAsStream("META-INF/LICENSE")) {
      assertNotNull(in, "Caffeine's JAR has META-INF/LICENSE");
      upstream = in.readAllBytes();
    }
    assertArrayEquals(
        upstream,
        Files.readAllBytes(
            root.resolve("sdk/src/main/resources/META-INF/licenses/caffeine/LICENSE")),
        "sdk's META-INF/licenses/caffeine/LICENSE is Caffeine's");
    String pom = Files.readString(root.resolve("pom.xml"));
    java.util.regex.Matcher version =
        java.util.regex.Pattern.compile("<caffeine.version>([^<]+)</caffeine.version>")
            .matcher(pom);
    assertTrue(version.find(), "the root POM pins caffeine.version");
    String notice = Files.readString(root.resolve("NOTICE")).replaceAll("\\s+", " ");
    assertTrue(
        notice.contains("Bundled third-party code: The SDK JAR")
            && notice.contains(" bundle Caffeine " + version.group(1) + " ")
            && notice.contains("META-INF/licenses/caffeine/LICENSE"),
        "NOTICE names the bundled Caffeine " + version.group(1) + " and its license");
  }
}
