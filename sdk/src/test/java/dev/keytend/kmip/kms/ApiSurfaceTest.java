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

package dev.keytend.kmip.kms;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import org.junit.jupiter.api.Test;

/** Acceptance checks on the source: documentation and the samples' imports. */
class ApiSurfaceTest {
  private static final Path MAIN = Path.of("src/main/java/dev/keytend/kmip/kms");
  private static final Path SAMPLES = Path.of("src/test/java/dev/keytend/kmip/kms/samples");

  /** Samples import only the application API and the JDK. */
  @Test
  void samplesImportOnlyTheApplicationApiAndTheJdk() throws Exception {
    List<String> found = new ArrayList<>();
    try (var files = Files.list(SAMPLES)) {
      List<Path> samples = files.filter(p -> p.toString().endsWith(".java")).toList();
      assertTrue(samples.size() >= 7, "A1-A7 are present");
      for (Path file : samples)
        found.addAll(outsideTheApi(file.getFileName().toString(), Files.readString(file)));
    }
    assertEquals(List.of(), found);
  }

  /** The README quickstart uses only the application API and the JDK. */
  @Test
  void readmeQuickstartImportsOnlyTheApplicationApi() throws Exception {
    String readme = Files.readString(Path.of("../README.md"));
    int at = readme.indexOf("try (Kms kms = Kms.connect(");
    int start = readme.lastIndexOf("```java", at), end = readme.indexOf("```", at);
    assertTrue(start > 0 && end > at, "README quickstart present");
    assertEquals(List.of(), outsideTheApi("README quickstart", readme.substring(start, end)));
  }

  /** Every line of the README quickstart is a line of samples/Quickstart.java, which SamplesTest runs. */
  @Test
  void readmeQuickstartIsTheTestedSample() throws Exception {
    String readme = Files.readString(Path.of("../README.md"));
    int at = readme.indexOf("try (Kms kms = Kms.connect(");
    int start = readme.lastIndexOf("```java\n", at), end = readme.indexOf("```", at);
    assertTrue(start > 0 && end > at, "README quickstart present");
    List<String> sample =
        Files.readAllLines(SAMPLES.resolve("Quickstart.java")).stream().map(String::strip).toList();
    List<String> missing = new ArrayList<>();
    String block = readme.substring(start + "```java\n".length(), end);
    for (String line : block.split("\n"))
      if (!line.isBlank() && !sample.contains(line.strip())) missing.add(line);
    assertEquals(List.of(), missing, "README quickstart lines that are not in Quickstart.java");
    // No version branch, no lookup right after findOrCreate, no racy state check after encrypting;
    // it seals through the key in force.
    assertFalse(block.contains("legacyAttributes") || block.contains("version()"), block);
    assertFalse(block.contains("findByName") || block.contains("state()"), block);
    assertTrue(block.contains("findOrCreate()") && block.contains("kms.keys().current("), block);
  }

  /** Imports and qualified names outside dev.keytend.kmip.kms, java and javax. */
  static List<String> outsideTheApi(String where, String source) {
    List<String> found = new ArrayList<>();
    for (String line : source.split("\n")) {
      String l = line.trim();
      if (l.startsWith("import ")) {
        String name = l.substring(7).replace("static ", "").replace(";", "").trim();
        if (!name.startsWith("dev.keytend.kmip.kms.")
            && !name.startsWith("java.")
            && !name.startsWith("javax.")) found.add(where + ": " + l);
      } else {
        Matcher q = Pattern.compile("dev\\.keytend\\.kmip\\.(\\w+)").matcher(l);
        while (q.find()) if (!q.group(1).equals("kms")) found.add(where + " uses " + q.group());
      }
    }
    for (String type :
        List.of("Ttlv", "Tag.", "Requests.", "RequestOptions", "ProtocolVersion", "Enums."))
      if (source.contains(type)) found.add(where + " uses " + type);
    return found;
  }

  /**
   * KmsException's branching accessors use this package's types: the server's reason is {@code
   * serverReason()}, a {@link KmsReason}; protocol types come only from {@code protocolReason()},
   * {@code result()} and {@code response()}.
   */
  @Test
  void kmsExceptionBranchesWithoutProtocolTypes() throws Exception {
    List<String> protocolTyped = new ArrayList<>();
    for (var m : KmsException.class.getMethods()) {
      String type = m.getGenericReturnType().getTypeName();
      if (type.matches(".*dev\\.keytend\\.kmip\\.(?!kms\\.).*")) protocolTyped.add(m.getName());
    }
    Collections.sort(protocolTyped);
    assertEquals(List.of("protocolReason", "response", "result"), protocolTyped);
    assertEquals(
        "java.util.Optional<dev.keytend.kmip.kms.KmsReason>",
        KmsException.class.getMethod("serverReason").getGenericReturnType().getTypeName());
    assertTrue(
        Arrays.stream(KmsException.class.getMethods())
            .noneMatch(m -> m.getName().equals("reason")));
  }

  /**
   * Rotation takes one options form, {@link Rotation}: no public method of this package but
   * {@code Rotation}'s own {@code of} and {@code dates} takes a {@link RotationDates}.
   */
  @Test
  void onlyRotationTakesRotationDates() throws Exception {
    List<String> found = new ArrayList<>();
    try (var files = Files.list(MAIN)) {
      for (Path file : files.filter(p -> p.toString().endsWith(".java")).sorted().toList()) {
        String simple = file.getFileName().toString().replace(".java", "");
        if (simple.equals("package-info")) continue;
        Class<?> type = Class.forName("dev.keytend.kmip.kms." + simple);
        if (!java.lang.reflect.Modifier.isPublic(type.getModifiers())) continue;
        for (java.lang.reflect.Method m : type.getDeclaredMethods()) {
          List<Class<?>> params = List.of(m.getParameterTypes());
          if (java.lang.reflect.Modifier.isPublic(m.getModifiers())
              && params.contains(RotationDates.class))
            found.add(
                simple + "." + m.getName() + params.stream().map(Class::getSimpleName).toList());
        }
      }
    }
    Collections.sort(found);
    assertEquals(List.of("Rotation.dates[RotationDates]", "Rotation.of[RotationDates]"), found);
  }

  /**
   * 3.0 is experimental and opt-in. A server that speaks 1.4, 2.1 and 3.0 is negotiated at 2.1 by a
   * default configuration (1.4 to 2.1), and at 3.0 only when the configuration names it ({@code
   * maximumVersion}, or a minimum of 3.0). {@code V3_0}'s Javadoc and docs/compatibility.md say it
   * is experimental.
   */
  @Test
  void threeZeroIsExperimentalAndOptIn() throws Exception {
    dev.keytend.kmip.testing.InMemoryKmipServer server =
        dev.keytend.kmip.testing.InMemoryKmipServer.of(
            KmipVersion.V3_0, KmipVersion.V2_1, KmipVersion.V1_4);
    try (server) {
      KmsConfig.Builder plain =
          KmsConfig.builder().endpoints("in-memory:5696").transport(e -> server);
      KmsConfig defaults = plain.build();
      assertEquals(KmipVersion.V1_4, defaults.minimumVersion());
      assertEquals(KmipVersion.V2_1, defaults.maximumVersion());
      try (Kms kms = Kms.connect(defaults)) {
        assertEquals(KmipVersion.V2_1, kms.version(), "not negotiated unless named");
      }
      try (Kms kms = Kms.connect(plain.minimumVersion(KmipVersion.V2_0).build())) {
        assertEquals(KmipVersion.V2_1, kms.version());
      }
      try (Kms kms =
          Kms.connect(
              KmsConfig.builder()
                  .endpoints("in-memory:5696")
                  .transport(e -> server)
                  .maximumVersion(KmipVersion.V3_0)
                  .build())) {
        assertEquals(KmipVersion.V3_0, kms.version());
      }
      try (Kms kms =
          Kms.connect(
              KmsConfig.builder()
                  .endpoints("in-memory:5696")
                  .transport(e -> server)
                  .minimumVersion(KmipVersion.V3_0)
                  .build())) {
        assertEquals(KmipVersion.V3_0, kms.version());
      }
    }
    String source = Files.readString(MAIN.resolve("KmipVersion.java"));
    String doc =
        source.substring(
            source.lastIndexOf("/**", source.indexOf("V3_0(ProtocolVersion.V3_0)")),
            source.indexOf("V3_0(ProtocolVersion.V3_0)"));
    assertTrue(doc.contains("<b>experimental</b>"), "V3_0's Javadoc says it is experimental");
    String page = Files.readString(Path.of("../docs/compatibility.md")).replaceAll("\\s+", " ");
    assertTrue(page.contains("| 3.0 CSD02 | **experimental**, opt-in |"), "and the page says so");
  }

  /**
   * Next to the name-based example (README, package-info, Quickstart: the first use of the name
   * {@code "orders-kek"}) one sentence says that names are not an access-control boundary and
   * points to the safer alternatives.
   */
  @Test
  void theNameBasedDecryptExamplesSayNamesAreNotAccessControl() throws Exception {
    for (String file :
        List.of(
            "../README.md",
            "src/main/java/dev/keytend/kmip/kms/package-info.java",
            "src/test/java/dev/keytend/kmip/kms/samples/Quickstart.java")) {
      String text = Files.readString(Path.of(file));
      int decrypt = text.indexOf("\"orders-kek\"");
      assertTrue(decrypt > 0, file);
      int warning = text.indexOf("not an access-control boundary");
      assertTrue(
          warning > 0 && Math.abs(warning - decrypt) < 600,
          file + ": the warning is next to the example");
      String near =
          text.substring(warning, Math.min(text.length(), warning + 450))
              .replaceAll("\\s+\\*?\\s*", " ");
      assertTrue(
          near.contains("key's handle") && near.contains("only you can set"), file + ": " + near);
    }
  }
}
