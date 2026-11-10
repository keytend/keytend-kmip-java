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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The API baseline (the release {@code -Papi-compat} compares against, and its JAR's SHA-256) is
 * pinned once, in {@code sdk/pom.xml}; {@code tools/api-baseline.sh}, {@code
 * tools/release-check.sh} and the {@code api-compat} profile read it from there, so changing the
 * baseline is one edit and no two files can disagree. The baseline is the latest release X.Y.Z.
 * The first release, 0.10.0, has none: a tree that builds it or one of its pre-releases pins none,
 * and the script says so (exit 3, the release check's one SKIP); a tree of any other version must
 * pin one.
 */
class ApiBaselinePinTest {
  static final Pattern VERSION =
      Pattern.compile("<api\\.baseline\\.version>([^<]*)</api\\.baseline\\.version>");
  static final Pattern SHA256 =
      Pattern.compile("<api\\.baseline\\.sha256>([^<]*)</api\\.baseline\\.sha256>");
  static final Pattern NAME =
      Pattern.compile("<api\\.baseline\\.name>([^<]*)</api\\.baseline\\.name>");
  static final Pattern HEX64 = Pattern.compile("(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])");

  static String read(String file) throws IOException {
    return Files.readString(LicenseHeadersTest.root().resolve(file));
  }

  static String only(Pattern p, String text, String what) {
    Matcher m = p.matcher(text);
    assertTrue(m.find(), "sdk/pom.xml pins no " + what);
    String value = m.group(1).strip();
    assertFalse(m.find(), "sdk/pom.xml pins " + what + " twice");
    return value;
  }

  /** Whether sdk/pom.xml pins a baseline: all three properties, or none of them. */
  static boolean pinned(String pom) {
    boolean version = VERSION.matcher(pom).find(),
        sha256 = SHA256.matcher(pom).find(),
        name = NAME.matcher(pom).find();
    assertTrue(
        version == sha256 && sha256 == name,
        "api.baseline.name, version and sha256 are pinned together");
    return version;
  }

  record Run(int exit, String out) {}

  static Run script(String... args) throws IOException, InterruptedException {
    return scriptIn(LicenseHeadersTest.root(), args);
  }

  /** Runs {@code tools/api-baseline.sh} of the tree {@code root}. */
  static Run scriptIn(Path root, String... args) throws IOException, InterruptedException {
    List<String> command =
        new ArrayList<>(List.of("bash", root.resolve("tools/api-baseline.sh").toString()));
    command.addAll(List.of(args));
    Process run = new ProcessBuilder(command).redirectErrorStream(true).start();
    String output =
        new String(run.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
    return new Run(run.waitFor(), output);
  }

  @Test
  void theBaselineIsPinnedOnceInTheSdkPom() throws Exception {
    String pom = read("sdk/pom.xml");
    // The profile names the JAR through the property, never a version of its own.
    Matcher jar =
        Pattern.compile("<api\\.baseline\\.jar>([^<]*)</api\\.baseline\\.jar>").matcher(pom);
    assertTrue(jar.find(), "the api-compat profile's api.baseline.jar");
    assertTrue(
        jar.group(1).endsWith("/target/api-baseline/keytend-kmip-${api.baseline.version}.jar"),
        jar.group(1));
    assertFalse(jar.find(), "one api.baseline.jar");
    if (!pinned(pom)) {
      // No earlier release to compare with: no SHA-256 in the POM, and the script says so.
      assertEquals(0, HEX64.matcher(pom).results().count(), "no SHA-256 in sdk/pom.xml");
      for (Run r : List.of(script(), script("--version"), script("--sha256"))) {
        assertEquals(3, r.exit(), r.out());
        assertTrue(r.out().contains("pins no API baseline"), r.out());
      }
      return;
    }
    String version = only(VERSION, pom, "api.baseline.version");
    String sha256 = only(SHA256, pom, "api.baseline.sha256");
    assertTrue(version.matches("\\d+\\.\\d+\\.\\d+"), "a release version: " + version);
    assertTrue(sha256.matches("[0-9a-f]{64}"), "a lower-case SHA-256: " + sha256);
    assertEquals(1, HEX64.matcher(pom).results().count(), "one SHA-256 in sdk/pom.xml");
    assertEquals(new Run(0, version + "\n"), script("--version"));
    assertEquals(new Run(0, sha256 + "\n"), script("--sha256"));
  }

  @Test
  void theScriptsReadThePinAndPinNothing() throws IOException {
    String pom = read("sdk/pom.xml");
    boolean pinned = pinned(pom);
    String version = pinned ? only(VERSION, pom, "api.baseline.version") : null;
    String sha256 = pinned ? only(SHA256, pom, "api.baseline.sha256") : null;
    String script = read("tools/api-baseline.sh");
    assertTrue(
        script.contains("version=$(pinned api.baseline.version)"),
        "api-baseline.sh reads the version");
    assertTrue(
        script.contains("sha256=$(pinned api.baseline.sha256)"),
        "api-baseline.sh reads the SHA-256");
    assertTrue(script.contains("\"$root/sdk/pom.xml\""), "from sdk/pom.xml");
    String check = read("tools/release-check.sh");
    assertTrue(
        check.contains("version=$(\"$check_tree/tools/api-baseline.sh\" --version)"),
        "release-check.sh asks api-baseline.sh for the version");
    // No second pin anywhere in the build: the SHA-256 nowhere else; in the files that use the
    // baseline, no version or SHA-256 assigned and no JAR or ZIP named with the version. (Other
    // tools name the project's own JAR, whose version may equal the baseline's.)
    Path root = LicenseHeadersTest.root();
    List<String> users = List.of("tools/api-baseline.sh", "tools/release-check.sh", "sdk/pom.xml");
    List<Path> files =
        new ArrayList<>(
            List.of(
                root.resolve("pom.xml"),
                root.resolve("sdk/pom.xml"),
                root.resolve("integration-tests/pom.xml")));
    try (Stream<Path> tools = Files.walk(root.resolve("tools"))) {
      tools
          .filter(Files::isRegularFile)
          .filter(p -> p.toString().matches(".*\\.(sh|py|xml|properties|txt)$"))
          .forEach(files::add);
    }
    List<String> pins = new ArrayList<>();
    Pattern assigned =
        Pattern.compile(
            "(?m)^\\s*(?:export\\s+|local\\s+)?(?:baseline_?)?(?:version|sha256)=['\"]?[0-9]");
    String jarName = pinned ? "keytend-kmip-" + version + ".jar" : null;
    for (Path file : files) {
      if (!Files.exists(file)) continue;
      String text = Files.readString(file);
      String name = root.relativize(file).toString();
      if (name.equals("sdk/pom.xml")) {
        if (pinned && text.contains(jarName)) pins.add(name + ": " + jarName);
        continue;
      }
      if (pinned && text.contains(sha256)) pins.add(name + ": the SHA-256");
      if (users.contains(name)) {
        if (assigned.matcher(text).find()) pins.add(name + ": a version or SHA-256 assigned");
        if (HEX64.matcher(text).find()) pins.add(name + ": a SHA-256");
        if (pinned && (text.contains(jarName) || text.contains("keytend-kmip-" + version + ".zip")))
          pins.add(name + ": " + jarName);
      }
    }
    assertEquals(List.of(), pins, "the baseline is pinned only in sdk/pom.xml");
  }

  /**
   * Without a pin, the script accepts only a tree of the first release, 0.10.0, or one of its
   * pre-releases (exit 3, "no earlier release"); a tree of any other version is refused (exit 2).
   */
  @Test
  void onlyTheFirstReleaseHasNoBaseline(@TempDir Path tree) throws Exception {
    Path root = LicenseHeadersTest.root();
    Files.createDirectories(tree.resolve("tools"));
    Files.createDirectories(tree.resolve("sdk"));
    Files.copy(root.resolve("tools/api-baseline.sh"), tree.resolve("tools/api-baseline.sh"));
    Files.writeString(
        tree.resolve("sdk/pom.xml"),
        "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><properties>"
            + "<cyclonedx.skip>false</cyclonedx.skip></properties></project>\n");
    for (String version : List.of("0.10.0", "0.10.0-rc.1", "0.10.0-rc.12", "0.10.1", "0.11.0")) {
      Files.writeString(
          tree.resolve("pom.xml"),
          "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><version>"
              + version
              + "</version></project>\n");
      Run r = scriptIn(tree, "--version");
      if (version.startsWith("0.10.0")) {
        assertEquals(3, r.exit(), version + ": " + r.out());
        assertTrue(r.out().contains("no earlier keytend-kmip release"), r.out());
      } else {
        assertEquals(2, r.exit(), version + ": " + r.out());
        assertTrue(r.out().contains("only the first release, 0.10.0"), r.out());
      }
    }
  }

  /**
   * Whether an incompatible change fails (tools/api-baseline.sh --fails): against a baseline of
   * the same 0.x minor version, or from 1.0 the same major version, it fails; against an earlier
   * series it is reported, and the release notes list it (docs/compatibility.md). A patch release
   * against a baseline of another minor version is refused (exit 2): a stale baseline would let it
   * break the API. The release check reads the answer, fails closed on anything but fail or
   * report, and requires the notes' heading when it reports.
   */
  @Test
  void anIncompatibleChangeFailsWithinItsSeriesOnly(@TempDir Path tree) throws Exception {
    Path root = LicenseHeadersTest.root();
    Files.createDirectories(tree.resolve("tools"));
    Files.createDirectories(tree.resolve("sdk"));
    Files.copy(root.resolve("tools/api-baseline.sh"), tree.resolve("tools/api-baseline.sh"));
    String[][] cases = {
      {"0.10.1", "0.10.0", "fail"},
      {"0.10.2-rc.1", "0.10.1", "fail"},
      {"0.11.0", "0.10.3", "report"},
      {"0.11.0-rc.2", "0.10.0", "report"},
      {"1.0.0", "0.12.4", "report"},
      {"1.0.1", "1.0.0", "fail"},
      {"1.3.0", "1.2.7", "fail"},
      {"2.0.0", "1.9.0", "report"},
      {"0.11.1", "0.10.3", "refused"},
      {"0.11.2-rc.1", "0.10.0", "refused"},
      {"1.3.1", "1.2.7", "refused"},
      {"0.11.1", "0.11.0", "fail"},
    };
    for (String[] c : cases) {
      Files.writeString(
          tree.resolve("sdk/pom.xml"),
          "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><properties>"
              + "<api.baseline.name>keytend-kmip</api.baseline.name>"
              + "<api.baseline.version>"
              + c[1]
              + "</api.baseline.version><api.baseline.sha256>"
              + "0".repeat(64)
              + "</api.baseline.sha256></properties></project>\n");
      Files.writeString(
          tree.resolve("pom.xml"),
          "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><version>"
              + c[0]
              + "</version></project>\n");
      Run r = scriptIn(tree, "--fails");
      if (c[2].equals("refused")) {
        String minor = c[0].replaceFirst("^(\\d+\\.\\d+)\\..*", "$1");
        assertEquals(2, r.exit(), c[0] + " vs " + c[1] + ": " + r.out());
        assertTrue(r.out().contains("make " + minor + ".0 the API baseline"), r.out());
        assertFalse(r.out().lines().anyMatch(l -> l.equals("fail") || l.equals("report")), r.out());
        continue;
      }
      assertEquals(0, r.exit(), c[0] + " vs " + c[1] + ": " + r.out());
      assertEquals(c[2], r.out().lines().reduce((a, b) -> b).orElse(""), c[0] + " vs " + c[1]);
    }
    String check = read("tools/release-check.sh");
    assertTrue(
        check.contains("series=$(\"$check_tree/tools/api-baseline.sh\" --fails"),
        "release-check.sh asks api-baseline.sh whether to fail");
    assertTrue(
        check.contains(
            "[ \"$api_fail\" = auto ] && api_fail=$([ \"$series\" = report ] && echo false || echo"
                + " true)"),
        "release-check.sh reports against an earlier series only");
    assertTrue(check.contains("^## Incompatible changes"), "the notes' heading is required");
  }

  /**
   * The release check's test of RELEASE.md (the Python in tools/release-check.sh that runs when
   * api-compat reports incompatible changes against an earlier series): it passes only when the
   * section of the release the tree builds, a pre-release's included, has a "## Incompatible
   * changes" heading, and not when another section has it or the heading is of a lower level.
   */
  @Test
  void theNotesHeadingIsReadFromTheReleasesSection(@TempDir Path tree) throws Exception {
    String check = read("tools/release-check.sh");
    Matcher block =
        Pattern.compile(
                "python3 -I - \"\\$check_tree/RELEASE\\.md\" \"\\$check_tree/pom\\.xml\" <<'PY'\n"
                    + "(.*?)\nPY\n",
                Pattern.DOTALL)
            .matcher(check);
    assertTrue(block.find(), "release-check.sh tests RELEASE.md's heading");
    Path script = tree.resolve("heading.py");
    Files.writeString(script, block.group(1) + "\n");
    String later =
        "\n# keytend-kmip 0.10.0\n\nThe first release.\n\n## Incompatible changes\n\n- old.\n";
    String[][] cases = {
      {"0.11.0", "# keytend-kmip 0.11.0\n\n## Incompatible changes\n\n- `A` went.\n" + later, "0"},
      {"0.11.0-rc.2", "# keytend-kmip 0.11.0\n\n## Incompatible changes\n\n- `A`.\n" + later, "0"},
      {"0.11.0", "# keytend-kmip 0.11.0\n\n## Changes\n\n- `A` went.\n" + later, "1"},
      {"0.11.0", "# keytend-kmip 0.11.0\n\n### Incompatible changes\n\n- `A`.\n" + later, "1"},
      {"0.11.0", "# keytend-kmip 0.12.0\n\n## Incompatible changes\n" + later, "1"},
      {"0.11.0", "# keytend-kmip 0.11.0 (unreleased)\n\n## Incompatible changes\n" + later, "0"},
    };
    for (String[] c : cases) {
      Path notes = tree.resolve("RELEASE.md");
      Path pom = tree.resolve("pom.xml");
      Files.writeString(notes, c[1]);
      Files.writeString(
          pom,
          "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><version>"
              + c[0]
              + "</version></project>\n");
      Process p =
          new ProcessBuilder("python3", "-I", script.toString(), notes.toString(), pom.toString())
              .redirectErrorStream(true)
              .start();
      String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      assertEquals(Integer.parseInt(c[2]), p.waitFor(), c[0] + "\n" + c[1] + out);
    }
  }

  /**
   * The baseline names its release's artifact, and one released outside keytend/keytend-kmip-java
   * is given as a file: the script downloads only keytend-kmip releases.
   */
  @Test
  void theBaselineNamesItsArtifact() throws IOException {
    String pom = read("sdk/pom.xml");
    String script = read("tools/api-baseline.sh");
    assertTrue(
        script.contains("name=$(pinned api.baseline.name)"), "api-baseline.sh reads the name");
    assertTrue(
        script.contains("pass its ZIP or JAR"),
        "api-baseline.sh downloads only keytend-kmip baselines");
    if (!pinned(pom)) return;
    String name = only(NAME, pom, "api.baseline.name");
    assertEquals("keytend-kmip", name, "a keytend-kmip release");
  }
}
