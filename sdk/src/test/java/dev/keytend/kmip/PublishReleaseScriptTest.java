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

import java.io.File;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@code tools/publish-release.sh}: it refuses unless every asset is present and consistent (the
 * binary and source ZIPs, and beside them the test-only {@code keytend-kmip-testing} JAR, sources
 * and SBOM, each with its {@code .sha256} and signature, and {@code SHA256SUMS} listing them all),
 * the binary ZIP holds no source tree and the reports of release checks that passed, with live
 * results of the pinned keytend-kmip-server build only, the source ZIP is the source tree under its
 * own top directory, the signatures are
 * good ones by the release key (its primary key or one of its signing subkeys), and prints the one
 * {@code gh release create} command that attaches all of them. Nothing is published: the {@code gh} on these runs' {@code PATH} only records its
 * arguments, and the signing key is a throwaway one in a temporary GnuPG home.
 */
class PublishReleaseScriptTest {
  static final String SUMS = sums("9.9.9");

  /** A SHA256SUMS of the ZIP's own (one line, in sha256sum's form). */
  static String sums(String version) {
    return "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  lib/keytend-kmip-"
        + version
        + ".jar\n";
  }

  /** The last line of a binary ZIP's validation/release-check.txt when the checks passed. */
  static final String CHECKS_PASSED = "PASSED BEFORE PACKAGING (17 checks)";

  /** The commit the test releases are packaged from (release.json, release-check.txt). */
  static final String COMMIT = "0123456789abcdef0123456789abcdef01234567";

  /** The arguments of a full release check run. */
  static final String ARGUMENTS =
      "--jdks 17 21 25 --integration --server localhost/keytend-kmip-server:X";

  /** The rows of a full release check run before the packaging, each PASS. */
  static final List<String> ROWS =
      List.of(
          "test-jdk17",
          "verify-jdk17 -Pdistribution -Dkeytend.matrix=full",
          "format-fixtures-jdk17",
          "license-headers-jdk17",
          "verify-jdk21 -Dspotbugs.skip=true",
          "format-fixtures-jdk21",
          "license-headers-jdk21",
          "verify-jdk25 -Dspotbugs.skip=true -P!errorprone",
          "format-fixtures-jdk25",
          "license-headers-jdk25",
          "license_headers.py",
          "dependency-updates",
          "api-baseline",
          "api-compat",
          "server-probe",
          "live-run",
          "live-pin",
          "reports");

  /**
   * A release check table (release-check.txt's, or summary.txt's with its own last lines): the
   * run's identity with {@code arguments}, each of {@code rows} ("NAME" for a PASS, or "RESULT
   * NAME"), then {@code last}.
   */
  static String table(String commit, String arguments, List<String> rows, String last) {
    StringBuilder out =
        new StringBuilder("keytend-kmip release check, before packaging\ncommit ")
            .append(commit)
            .append("\narguments ")
            .append(arguments)
            .append("\nfinished 2026-11-09T00:00:00+00:00\n\n")
            .append(String.format("%-4s  %-34s %s\n", "RESULT", "CHECK", "DETAIL"));
    for (String row : rows) {
      String[] f =
          row.matches("(PASS|FAIL|SKIP|UNPIN) .*") ? row.split(" ", 2) : new String[] {"PASS", row};
      out.append(String.format("%-4s  %-34s %s\n", f[0], f[1], "detail"));
    }
    return out.append('\n').append(last).append('\n').toString();
  }

  /** A full run's release-check.txt of {@link #COMMIT}, ending with {@code last}. */
  static String releaseCheck(String last) {
    return table(COMMIT, ARGUMENTS, ROWS, last);
  }

  /** A binary ZIP's release.json for {@code version}, packaged from {@link #COMMIT}. */
  static String releaseJson(String version) {
    return "{\"version\": \""
        + version
        + "\", \"commit\": \""
        + COMMIT
        + "\", \"prerelease\": "
        + version.contains("-rc.")
        + ", \"packaged\": \"release\"}\n";
  }

  /**
   * How many checks the probe's full tls-issue-repeat passes at a version, as
   * tools/release_reports.py derives it from the probe's source.
   */
  static synchronized int repeatPasses() throws Exception {
    if (repeatPasses == 0) {
      Process p =
          new ProcessBuilder(
                  "python3",
                  "-I",
                  "-c",
                  "import sys; sys.path.insert(0, sys.argv[1]); import release_reports as r\n"
                      + "print(r.full_repeat_passes())",
                  LicenseHeadersTest.root().resolve("tools").toString())
              .redirectErrorStream(true)
              .start();
      String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      assertEquals(0, p.waitFor(), out);
      repeatPasses = Integer.parseInt(out.strip());
    }
    return repeatPasses;
  }

  private static int repeatPasses;

  /**
   * The workflow suite's and the catalog's reports of a run with --integration, under
   * validation/: each summary with a run on JDK 17, 21 and 25, and every file it names.
   */
  static Map<String, String> integrationReports() {
    Map<String, String> files = new java.util.LinkedHashMap<>();
    StringBuilder workflows = new StringBuilder(), tuples = new StringBuilder();
    StringBuilder controlled = new StringBuilder();
    for (String jdk : List.of("17", "21", "25")) {
      String sep = jdk.equals("17") ? "" : ", ";
      workflows
          .append(sep)
          .append("{\"server\": \"pykmip\", \"version\": \"1.4\", \"jdk\": ")
          .append(jdk)
          .append('}');
      files.put("validation/workflows/pykmip-1.4-jdk" + jdk + ".json", "{\"checks\": []}\n");
      tuples
          .append(sep)
          .append("{\"jdk\": ")
          .append(jdk)
          .append(", \"evidence\": \"results/pykmip-1.4-jdk")
          .append(jdk)
          .append(".json\"}");
      files.put("validation/catalog/results/pykmip-1.4-jdk" + jdk + ".json", "{}\n");
      controlled
          .append(sep)
          .append("{\"jdk\": ")
          .append(jdk)
          .append(", \"evidence\": \"results/controlled-jdk")
          .append(jdk)
          .append(".json\"}");
      files.put("validation/catalog/results/controlled-jdk" + jdk + ".json", "{}\n");
    }
    files.put("validation/workflows/summary.json", "{\"workflows\": [" + workflows + "]}\n");
    files.put("validation/workflows/overview.html", "<html></html>\n");
    files.put(
        "validation/catalog/summary.json",
        "{\"tuples\": [" + tuples + "], \"controlled\": [" + controlled + "]}\n");
    files.put("validation/catalog/cases.csv", "case\n");
    files.put("validation/catalog/overview.html", "<html></html>\n");
    files.put("validation/catalog/policy-coverage.html", "<html></html>\n");
    return files;
  }

  /** A binary ZIP's validation/live-server.json without entries: a run without --server. */
  static final String NO_LIVE_RESULTS = "{\"entries\": []}\n";

  /** One live-server.json entry: {@code scope} at KMIP {@code kmip}, from {@code source}. */
  static String entry(
      String scope, String kmip, String source, String image, String result, String server)
      throws Exception {
    return "{\"scope\": \""
        + scope
        + "\", \"kmip\": \""
        + kmip
        + "\", \"date\": \"2026-11-09\", \"server\": \""
        + server
        + "\", \"image\": \""
        + image
        + "\", \"pinned\": true, \"jdk\": \"17\", \"command\": \"run.sh\", \"result\": \""
        + result
        + "\", \"detail\": \""
        // The probe's all: its counts, the full repeat's among them.
        + (scope.startsWith("server-probe all")
            ? "pass=60 fail=0 info=9 skip=0; tls-issue-repeat pass="
                + repeatPasses()
                + " fail=0 info=3 skip=0"
            : "ok")
        + "\", \"source\": \""
        + source
        + "\"}";
  }

  /**
   * The live checks the release check runs with --server, each with its KMIP versions
   * (tools/release_reports.py, RELEASE_CHECK_SCOPES), as "scope|version" lines.
   */
  static List<String> runScopes() throws Exception {
    String tools = LicenseHeadersTest.root().resolve("tools").toString();
    Process p =
        new ProcessBuilder(
                "python3",
                "-I",
                "-c",
                "import sys; sys.path.insert(0, sys.argv[1]); import release_reports as r\n"
                    + "for s, vs in r.RELEASE_CHECK_SCOPES.items():\n"
                    + "    for v in vs: print(s + '|' + v)",
                tools)
            .redirectErrorStream(true)
            .start();
    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    assertEquals(0, p.waitFor(), out);
    return out.lines().toList();
  }

  /**
   * A validation/live-server.json of a complete run on the pinned image (every live check the
   * release check runs, at each version, passed), with each of {@code extra} ("scope|version|
   * source|image|result") over the run's entry of its scope and version, or added.
   */
  static String liveResults(String... extra) throws Exception {
    String pinned = ServerPinTest.pin().getProperty("image_id");
    String server = "keytend-kmip-server " + ServerPinTest.pin().getProperty("version");
    Map<String, String> entries = new java.util.LinkedHashMap<>();
    for (String line : runScopes()) {
      String[] f = line.split("\\|");
      entries.put(line, entry(f[0], f[1], "release check", pinned, "PASS", server));
    }
    for (String e : extra) {
      String[] f = e.split("\\|");
      String built = f[3].equals(pinned) ? server : "keytend-kmip-server 9.9.9";
      entries.put(f[0] + "|" + f[1], entry(f[0], f[1], f[2], f[3], f[4], built));
    }
    return "{\"entries\": [" + String.join(", ", entries.values()) + "]}\n";
  }

  /** {@link #liveResults} with {@code scope} at KMIP 2.1 from {@code source} on {@code image}. */
  static String liveResult(String scope, String source, String image) throws Exception {
    return liveResults(scope + "|2.1|" + source + "|" + image + "|PASS");
  }

  /**
   * Writes the release's two ZIPs into {@code dir}: the binary ZIP, holding {@code inner} as its
   * SHA256SUMS, validation/live-server.json of a complete run ({@link #liveResults}), the workflow
   * and catalog reports ({@link #integrationReports}), {@code binary} (path under its top
   * directory to content, which may replace it, or null to leave it out) and, unless {@code
   * releaseCheck} is null,
   * validation/release-check.txt ending with it; and the source ZIP of {@code source} (paths in
   * the ZIP to content).
   */
  static void zips(
      Path dir,
      String version,
      String inner,
      Map<String, String> binary,
      String releaseCheck,
      Map<String, String> source)
      throws Exception {
    Map<String, String> entries = new java.util.LinkedHashMap<>();
    entries.put("SHA256SUMS", inner);
    entries.put("lib/keytend-kmip-" + version + ".jar", "a JAR\n");
    entries.put("validation/live-server.json", liveResults());
    entries.put("release.json", releaseJson(version));
    entries.putAll(integrationReports());
    if (releaseCheck != null)
      entries.put("validation/release-check.txt", releaseCheck(releaseCheck));
    entries.putAll(binary);
    entries.values().removeIf(java.util.Objects::isNull);
    Map<String, String> under = new java.util.LinkedHashMap<>();
    entries.forEach((path, content) -> under.put("keytend-kmip-" + version + "/" + path, content));
    zip(dir.resolve("keytend-kmip-" + version + ".zip"), under);
    zip(dir.resolve("keytend-kmip-" + version + "-src.zip"), source);
  }

  /** {@link #zips} with a binary ZIP that passed its checks and a source ZIP with its POM. */
  static void zips(Path dir, String version, String inner) throws Exception {
    zips(dir, version, inner, Map.of(), CHECKS_PASSED, source(version));
  }

  /** A source ZIP's entries: the tree's POM and a source file, under its top directory. */
  static Map<String, String> source(String version) {
    String top = "keytend-kmip-" + version + "-src/";
    return Map.of(top + "pom.xml", "<project/>\n", top + "sdk/src/A.java", "class A {}\n");
  }

  static void zip(Path file, Map<String, String> entries) throws Exception {
    try (OutputStream out = Files.newOutputStream(file);
        ZipOutputStream z = new ZipOutputStream(out)) {
      for (Map.Entry<String, String> e : entries.entrySet()) {
        z.putNextEntry(new ZipEntry(e.getKey()));
        z.write(e.getValue().getBytes(StandardCharsets.UTF_8));
        z.closeEntry();
      }
    }
  }

  /**
   * The files a release publishes: the binary and source ZIPs and, beside them, the test-only
   * module's assets and the signed Central bundle.
   */
  static List<String> published(String version) {
    String testing = "keytend-kmip-testing-" + version;
    return List.of(
        "keytend-kmip-" + version + ".zip",
        "keytend-kmip-" + version + "-src.zip",
        testing + ".jar",
        testing + "-sources.jar",
        testing + "-cyclonedx.json",
        "keytend-kmip-" + version + "-central-bundle.zip");
  }

  /** Every asset, in the order the command attaches them: each file and its .sha256, then the signatures. */
  static List<String> assets(String version, boolean signed) {
    List<String> out = new ArrayList<>();
    for (String f : published(version)) {
      out.add(f);
      out.add(f + ".sha256");
    }
    out.add("SHA256SUMS");
    if (signed) {
      for (String f : published(version)) out.add(f + ".asc");
      out.add("SHA256SUMS.asc");
    }
    return out;
  }

  static final List<String> ASSETS = assets("9.9.9", true);

  /** The files the release signs: each published one and SHA256SUMS. */
  static final List<String> SIGNED =
      List.of(
          "keytend-kmip-9.9.9.zip",
          "keytend-kmip-9.9.9-src.zip",
          "keytend-kmip-testing-9.9.9.jar",
          "keytend-kmip-testing-9.9.9-sources.jar",
          "keytend-kmip-testing-9.9.9-cyclonedx.json",
          "keytend-kmip-9.9.9-central-bundle.zip",
          "SHA256SUMS");

  @TempDir static Path gnupg;

  /** The throwaway release key's primary fingerprint, and its signing subkeys. */
  static String fingerprint, subkey, expiredSubkey, revokedSubkey;

  /** Another primary key, not the release key. */
  static String foreign;

  @TempDir Path tmp;
  Path dir, bin, ghCalled, tagCommit, notes;

  record Run(int exit, String out) {}

  static boolean onPath(String tool) {
    for (String d : System.getenv().getOrDefault("PATH", "").split(File.pathSeparator))
      if (Files.isExecutable(Path.of(d, tool))) return true;
    return false;
  }

  static String exec(Map<String, String> env, String... command) throws Exception {
    ProcessBuilder pb = new ProcessBuilder(command).redirectErrorStream(true);
    pb.environment().putAll(env);
    Process p = pb.start();
    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    assertTrue(p.waitFor(120, TimeUnit.SECONDS), String.join(" ", command));
    assertEquals(0, p.exitValue(), String.join(" ", command) + ": " + out);
    return out;
  }

  static Map<String, String> gpgEnv() {
    return Map.of("GNUPGHOME", gnupg.toString());
  }

  /** The fingerprints {@code gpg --list-keys} lists for {@code key}, primary first, then subkeys. */
  static List<String> fingerprints(String key) throws Exception {
    List<String> out = new ArrayList<>();
    for (String line :
        exec(gpgEnv(), "gpg", "--batch", "--with-colons", "--list-keys", "--", key).split("\n"))
      if (line.startsWith("fpr:")) out.add(line.split(":")[9]);
    return out;
  }

  static void gpg(String fakedTime, String... args) throws Exception {
    List<String> command =
        new ArrayList<>(
            List.of("gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", ""));
    if (fakedTime != null) command.addAll(List.of("--faked-system-time", fakedTime));
    command.addAll(List.of(args));
    exec(gpgEnv(), command.toArray(String[]::new));
  }

  /**
   * A throwaway release key, as docs/releasing.md's but with no passphrase: a primary that signs,
   * a signing subkey (as the release key's CI subkey), a signing subkey that expired in 2021 and
   * one revoked later; and a foreign key. Created at a faked time in 2020, so the expired subkey
   * could sign before it expired.
   */
  @BeforeAll
  static void releaseKey() throws Exception {
    for (String tool : List.of("bash", "gpg", "sha256sum", "python3"))
      assumeTrue(onPath(tool), tool);
    Files.setPosixFilePermissions(
        gnupg, java.nio.file.attribute.PosixFilePermissions.fromString("rwx------"));
    gpg(
        "20200101T000000",
        "--quick-gen-key",
        "keytend-kmip publish test <publish-test@example.invalid>",
        "ed25519",
        "sign",
        "never");
    fingerprint = fingerprints("publish-test@example.invalid").get(0);
    gpg("20200101T000100", "--quick-add-key", fingerprint, "ed25519", "sign", "never");
    gpg("20200101T000200", "--quick-add-key", fingerprint, "ed25519", "sign", "2021-01-01");
    gpg("20200101T000300", "--quick-add-key", fingerprint, "ed25519", "sign", "never");
    List<String> keys = fingerprints(fingerprint);
    assertEquals(4, keys.size(), keys.toString());
    subkey = keys.get(1);
    expiredSubkey = keys.get(2);
    revokedSubkey = keys.get(3);
    gpg(
        null,
        "--quick-gen-key",
        "someone else <foreign@example.invalid>",
        "ed25519",
        "sign",
        "never");
    foreign = fingerprints("foreign@example.invalid").get(0);
  }

  @AfterAll
  static void stopAgent() throws Exception {
    if (fingerprint != null && onPath("gpgconf")) exec(gpgEnv(), "gpgconf", "--kill", "gpg-agent");
  }

  @BeforeEach
  void assets() throws Exception {
    dir = Files.createDirectories(tmp.resolve("releases"));
    bin = Files.createDirectories(tmp.resolve("bin"));
    ghCalled = tmp.resolve("gh-called");
    Path gh = bin.resolve("gh");
    // gh api answers the commit the tag names (the file tag-commit, none without it); any other
    // gh command records its arguments.
    tagCommit = tmp.resolve("tag-commit");
    Files.writeString(tagCommit, COMMIT + "\n");
    Files.writeString(
        gh,
        "#!/bin/sh\nif [ \"$1\" = api ]; then cat '"
            + tagCommit
            + "' 2>/dev/null || exit 1; exit 0; fi\nprintf '%s\\n' \"$@\" > '"
            + ghCalled
            + "'\nexit 0\n");
    gh.toFile().setExecutable(true);
    notes = Files.writeString(tmp.resolve("notes.md"), "Notes.\n");
    release("9.9.9", SUMS);
  }

  /**
   * The assets tools/package-release.py writes for {@code version}, signed by the throwaway key: the
   * ZIPs ({@link #zips}, the binary one holding {@code inner} as its SHA256SUMS), the test-only
   * assets, each one's .sha256, and SHA256SUMS ({@link #outer}).
   */
  void release(String version, String inner) throws Exception {
    zips(dir, version, inner);
    sealed(version, inner);
  }

  /** The test-only assets beside the ZIPs already in {@code dir}, the checksums, the signatures. */
  void sealed(String version, String inner) throws Exception {
    List<String> files = published(version);
    for (String f : files.subList(2, files.size()))
      Files.writeString(dir.resolve(f), "the test-only " + f + "\n");
    for (String f : files) writeSha256(f);
    Files.writeString(dir.resolve("SHA256SUMS"), outer(version, inner));
    for (String f : files) sign(dir.resolve(f), dir.resolve(f));
    sign(dir.resolve("SHA256SUMS"), dir.resolve("SHA256SUMS"));
  }

  void writeSha256(String file) throws Exception {
    Files.writeString(
        dir.resolve(file + ".sha256"), sha256(dir.resolve(file)) + "  " + file + "\n");
  }

  /**
   * SHA256SUMS beside the ZIP: the ZIP's own ({@code inner}), each path under {@code
   * keytend-kmip-VERSION/}, that file's SHA-256, then each published file's.
   */
  String outer(String version, String inner) throws Exception {
    String top = "keytend-kmip-" + version + "/";
    StringBuilder out = new StringBuilder();
    for (String line : inner.split("\n"))
      out.append(line, 0, 66).append(top).append(line.substring(66)).append('\n');
    out.append(sha256(inner.getBytes(StandardCharsets.UTF_8)))
        .append("  ")
        .append(top)
        .append("SHA256SUMS\n");
    for (String f : published(version))
      out.append(sha256(dir.resolve(f))).append("  ").append(f).append('\n');
    return out.toString();
  }

  static String sha256(Path p) throws Exception {
    return sha256(Files.readAllBytes(p));
  }

  static String sha256(byte[] content) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(content));
  }

  /** Writes {@code asset}'s {@code .asc}: a detached signature of {@code content} by the primary key. */
  static void sign(Path asset, Path content) throws Exception {
    signAs(fingerprint, null, asset, content);
  }

  /** As {@link #sign}, by exactly {@code key} (a primary or a subkey), at {@code fakedTime} if given. */
  static void signAs(String key, String fakedTime, Path asset, Path content) throws Exception {
    gpg(
        fakedTime,
        "--armor",
        "--detach-sign",
        "--local-user",
        key + "!",
        "--output",
        asset + ".asc",
        content.toString());
  }

  /** Every signed asset of 9.9.9, signed by exactly {@code key}. */
  void signAll(String key, String fakedTime) throws Exception {
    for (String name : SIGNED) signAs(key, fakedTime, dir.resolve(name), dir.resolve(name));
  }

  /**
   * The script of this checkout, with Git pointed at an empty repository, so that the tags of the
   * clone the tests run in (such as the release's own, in a checkout of it) never reach the
   * script's check of the local tag.
   */
  Run run(String... args) throws Exception {
    Path noTags = tmp.resolve("no-tags.git");
    if (!Files.exists(noTags)) exec(Map.of(), "git", "init", "-q", "--bare", noTags.toString());
    return runAt(LicenseHeadersTest.root(), Map.of("GIT_DIR", noTags.toString()), args);
  }

  Run runAt(Path root, String... args) throws Exception {
    return runAt(root, Map.of(), args);
  }

  /** The script of the checkout {@code root} (its SECURITY.md and RELEASE.md are that checkout's). */
  Run runAt(Path root, Map<String, String> env, String... args) throws Exception {
    List<String> command =
        new ArrayList<>(List.of("/bin/bash", root.resolve("tools/publish-release.sh").toString()));
    command.addAll(List.of(args));
    ProcessBuilder pb = new ProcessBuilder(command).redirectErrorStream(true);
    pb.environment().put("PATH", bin + File.pathSeparator + System.getenv("PATH"));
    pb.environment().put("GNUPGHOME", gnupg.toString());
    pb.environment().putAll(env);
    Process p = pb.start();
    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    assertTrue(p.waitFor(60, TimeUnit.SECONDS));
    if (!command.contains("--publish"))
      assertFalse(Files.exists(ghCalled), "gh is run only with --publish");
    return new Run(p.exitValue(), out);
  }

  /** 9.9.9 from the test's directory and notes, signed by the throwaway key, plus {@code extra}. */
  Run run99(String... extra) throws Exception {
    List<String> args =
        new ArrayList<>(
            List.of(
                "9.9.9",
                "--dir",
                dir.toString(),
                "--notes",
                notes.toString(),
                "--fingerprint",
                fingerprint));
    args.addAll(List.of(extra));
    return run(args.toArray(String[]::new));
  }

  void assertRefused(String why) throws Exception {
    Run r = run99();
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains(why), r.out());
    assertFalse(r.out().contains("gh release create"), r.out());
  }

  @Test
  void everyAssetPresentPrintsTheCommandThatAttachesThemAllAndPublishesNothing() throws Exception {
    Run r = run99();
    assertEquals(0, r.exit(), r.out());
    String line =
        r.out()
            .lines()
            .filter(l -> l.startsWith("gh release create"))
            .findFirst()
            .orElseThrow(() -> new AssertionError(r.out()));
    assertTrue(
        line.startsWith("gh release create v9.9.9 -R keytend/keytend-kmip-java --verify-tag "),
        line);
    for (String asset : ASSETS)
      assertTrue(
          line.contains(dir.resolve(asset) + " ") || line.endsWith(dir.resolve(asset).toString()),
          asset + " in " + line);
    assertTrue(r.out().contains("signed by " + fingerprint), r.out());
    assertTrue(r.out().contains("Not published"), r.out());
  }

  /** {@code --publish} runs exactly that command (here, the recording {@code gh}). */
  @Test
  void publishRunsTheCommand() throws Exception {
    Run r = run99("--publish");
    assertEquals(0, r.exit(), r.out());
    List<String> args = Files.readAllLines(ghCalled);
    assertEquals(
        List.of(
            "release",
            "create",
            "v9.9.9",
            "-R",
            "keytend/keytend-kmip-java",
            "--verify-tag",
            "--title",
            "keytend-kmip 9.9.9",
            "--notes-file",
            notes.toString()),
        args.subList(0, 10));
    List<String> attached = new ArrayList<>();
    for (String asset : ASSETS) attached.add(dir.resolve(asset).toString());
    assertEquals(attached, args.subList(10, args.size()));
    assertFalse(r.out().contains("Not published"), r.out());
  }

  /**
   * A release is published with its signed Central bundle, which publish-central.yml uploads:
   * {@code --publish} refuses a release without it, and runs nothing.
   */
  @Test
  void aReleaseNeedsItsCentralBundle() throws Exception {
    String bundle = "keytend-kmip-9.9.9-central-bundle.zip";
    for (String suffix : List.of("", ".sha256", ".asc")) Files.delete(dir.resolve(bundle + suffix));
    Run r = run99("--publish");
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("lacks " + bundle + " " + bundle + ".sha256"), r.out());
    assertFalse(Files.exists(ghCalled), "nothing is published");
  }

  /**
   * {@code --publish --draft} (the release workflow) makes the same release a draft; {@code
   * --draft} alone is refused, since without {@code --publish} nothing is created.
   */
  @Test
  void draftMakesTheReleaseADraft() throws Exception {
    Run r = run99("--publish", "--draft");
    assertEquals(0, r.exit(), r.out());
    List<String> args = Files.readAllLines(ghCalled);
    assertEquals(
        List.of("release", "create", "v9.9.9", "-R", "keytend/keytend-kmip-java", "--verify-tag"),
        args.subList(0, 6));
    assertEquals(1, args.stream().filter("--draft"::equals).count(), args.toString());
    for (String asset : ASSETS) assertTrue(args.contains(dir.resolve(asset).toString()), asset);
    Files.delete(ghCalled);
    r = run99("--draft");
    assertEquals(2, r.exit(), r.out());
    assertTrue(r.out().contains("--draft needs --publish"), r.out());
  }

  /**
   * Only a version X.Y.Z-rc.N is published as a pre-release; a release X.Y.Z is not, whatever its
   * major version (0.10.0 is a normal release). release.json must say the same. A version of
   * another form is refused.
   */
  @Test
  void onlyAnRcIsAPreRelease() throws Exception {
    for (String version : List.of("9.9.9", "0.10.0", "0.10.0-rc.1", "9.9.9-rc.12")) {
      Files.deleteIfExists(ghCalled);
      release(version, sums(version));
      Run r =
          run(
              version,
              "--dir",
              dir.toString(),
              "--notes",
              notes.toString(),
              "--fingerprint",
              fingerprint,
              "--publish");
      assertEquals(0, r.exit(), version + ": " + r.out());
      List<String> args = Files.readAllLines(ghCalled);
      List<String> expected =
          new ArrayList<>(
              List.of(
                  "release",
                  "create",
                  "v" + version,
                  "-R",
                  "keytend/keytend-kmip-java",
                  "--verify-tag",
                  "--title",
                  "keytend-kmip " + version,
                  "--notes-file",
                  notes.toString()));
      if (version.contains("-rc.")) expected.add("--prerelease");
      assertEquals(expected, args.subList(0, expected.size()), version);
      assertEquals(
          dir.resolve("keytend-kmip-" + version + ".zip").toString(),
          args.get(expected.size()),
          version);
    }
    // release.json must say the same: a 0.x release marked a pre-release is refused.
    zips(
        dir,
        "0.10.0",
        sums("0.10.0"),
        Map.of("release.json", releaseJson("0.10.0").replace("false", "true")),
        CHECKS_PASSED,
        source("0.10.0"));
    sealed("0.10.0", sums("0.10.0"));
    Files.deleteIfExists(ghCalled);
    Run marked =
        run(
            "0.10.0",
            "--dir",
            dir.toString(),
            "--notes",
            notes.toString(),
            "--fingerprint",
            fingerprint);
    assertEquals(1, marked.exit(), marked.out());
    assertTrue(
        marked
            .out()
            .contains("release.json says prerelease True, but only an X.Y.Z-rc.N is a pre-release"),
        marked.out());
    Files.deleteIfExists(ghCalled);
    for (String version :
        List.of("2.0", "0.10", "0.10.0-rc", "0.10.0-rc.0", "0.10.0-beta.1", "0.10.0-SNAPSHOT")) {
      Run r = run(version, "--dir", dir.toString(), "--notes", notes.toString(), "--unsigned");
      assertEquals(2, r.exit(), version + ": " + r.out());
      assertTrue(r.out().contains("not a release version (X.Y.Z or X.Y.Z-rc.N)"), r.out());
    }
  }

  /**
   * With --publish, the tag vVERSION on GitHub (gh api) must name the commit release.json names:
   * a missing tag, or one of another commit, is refused before anything is published.
   */
  @Test
  void theTagMustNameTheReleasedCommit() throws Exception {
    Files.delete(tagCommit);
    Run r = run99("--publish");
    assertEquals(1, r.exit(), r.out());
    assertTrue(
        r.out()
            .contains(
                "REFUSED: the tag v9.9.9 of keytend/keytend-kmip-java names nothing, not the"
                    + " release's commit "
                    + COMMIT),
        r.out());
    assertFalse(Files.exists(ghCalled), "nothing published");
    Files.writeString(tagCommit, "f".repeat(40) + "\n");
    r = run99("--publish");
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("names " + "f".repeat(40) + ", not the release's commit"), r.out());
    assertFalse(Files.exists(ghCalled), "nothing published");
    // Without --publish the tag is not looked up.
    r = run99();
    assertEquals(0, r.exit(), r.out());
    Files.writeString(tagCommit, COMMIT + "\n");
    r = run99("--publish");
    assertEquals(0, r.exit(), r.out());
    assertTrue(Files.exists(ghCalled), "published");
  }

  /**
   * A release is made from a full release check run that passed: release-check.txt must have
   * every row a release needs, each PASS, and none of the arguments that leave out a check; the
   * API baseline may be SKIP for the first release, 0.10.0, and its pre-releases only.
   */
  @Test
  void aRunThatLeftOutChecksIsRefused() throws Exception {
    String check = "validation/release-check.txt";
    for (String row :
        List.of("verify-jdk21", "license-headers-jdk25", "live-run", "api-baseline")) {
      List<String> rows = new ArrayList<>(ROWS);
      rows.removeIf(r -> r.startsWith(row + " ") || r.equals(row));
      zips(
          dir,
          "9.9.9",
          SUMS,
          Map.of(check, table(COMMIT, ARGUMENTS, rows, CHECKS_PASSED)),
          CHECKS_PASSED,
          source("9.9.9"));
      sealed("9.9.9", SUMS);
      assertRefused("no " + row + " row: the release check did not run it");
    }
    for (String argument :
        List.of("--skip-verify", "--skip-api", "--skip-repro", "--allow-dirty", "--no-api-fail")) {
      zips(
          dir,
          "9.9.9",
          SUMS,
          Map.of(check, table(COMMIT, ARGUMENTS + " " + argument, ROWS, CHECKS_PASSED)),
          CHECKS_PASSED,
          source("9.9.9"));
      sealed("9.9.9", SUMS);
      assertRefused("the run left out or weakened checks (" + argument + ")");
    }
    // A row that is not PASS, though the last line says the run passed.
    List<String> failed = new ArrayList<>(ROWS);
    failed.set(failed.indexOf("live-pin"), "FAIL live-pin");
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(check, table(COMMIT, ARGUMENTS, failed, CHECKS_PASSED)),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused("live-pin is FAIL");
    // Another commit than release.json's.
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(check, table("f".repeat(40), ARGUMENTS, ROWS, CHECKS_PASSED)),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused("is of commit ['" + "f".repeat(40) + "'], not of " + COMMIT);
    // The API baseline SKIP: only for the first release and its pre-releases.
    List<String> skipped = new ArrayList<>(ROWS);
    skipped.remove("api-compat");
    skipped.set(skipped.indexOf("api-baseline"), "SKIP api-baseline");
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(check, table(COMMIT, ARGUMENTS, skipped, CHECKS_PASSED)),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused(
        "api-baseline is SKIP (SKIP only for the first release, 0.10.0, and its pre-releases)");
    String rc = "0.10.0-rc.1";
    zips(
        dir,
        rc,
        sums(rc),
        Map.of(check, table(COMMIT, ARGUMENTS, skipped, CHECKS_PASSED)),
        CHECKS_PASSED,
        source(rc));
    sealed(rc, sums(rc));
    Run r =
        run(rc, "--dir", dir.toString(), "--notes", notes.toString(), "--fingerprint", fingerprint);
    assertEquals(0, r.exit(), r.out());
  }

  /**
   * The binary ZIP's reports hold no test output and no local path: a Surefire report, a JUnit
   * suite, the home directory, the user name, the release check's default run directory or a
   * temporary path, in a log or a gzip file, is refused.
   */
  @Test
  void reportsWithTestOutputOrLocalPathsAreRefused() throws Exception {
    String home = System.getProperty("user.home");
    Map<String, String> cases = new java.util.LinkedHashMap<>();
    cases.put("validation/surefire-jdk25/sdk-surefire-reports/x.txt", "ok\n");
    cases.put("validation/TEST-dev.keytend.kmip.ATest.xml", "<testsuite/>\n");
    cases.put("validation/server-probe/v1.4.log", "jar " + home + "/x.jar\n");
    cases.put("validation/interop/run.log", "in /tmp/keytend-kmip-release-check.1/x\n");
    cases.put("validation/bench-smoke/live-v2.1.log", "at /var/folders/ab/x\n");
    cases.put("validation/interop/suite-v1.4.log", "in /var/lib/jenkins/workspace/kt/x\n");
    cases.put("validation/server-probe/v2.1.log", "see file:///srv/ci/report.html\n");
    cases.put(
        "validation/workflows/pykmip-1.4-jdk17.json", "{\"java\": \"C:\\\\Users\\\\b\\\\jdk\"}\n");
    cases.put("validation/catalog/results/pykmip-1.4-jdk17.json.gz", "not gzip\n");
    for (Map.Entry<String, String> c : cases.entrySet()) {
      zips(dir, "9.9.9", SUMS, Map.of(c.getKey(), c.getValue()), CHECKS_PASSED, source("9.9.9"));
      sealed("9.9.9", SUMS);
      assertRefused("validation/ holds what a release does not ship (test output or a local path)");
      assertRefused(c.getKey().substring("validation/".length()) + ": ");
    }
    // The scrubbed names, URLs and the committed evidence's own paths are not local paths.
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(
            "validation/server-probe/v1.4.log",
            "<run directory>/tree-a/sdk.jar ~/x https://www.slf4j.org/codes.html\n",
            "validation/recorded/oasis-replay/x.json",
            "{\"store\": \"/tmp/kmip.sqlite\"}\n"),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    Run r = run99();
    assertEquals(0, r.exit(), r.out());
  }

  /**
   * A release is made from a full release check run that had --integration, with its reports row
   * and the workflow suite's and the catalog's reports on each JDK, every run file the summaries
   * name included.
   */
  @Test
  void theWorkflowAndCatalogReportsAreRequired() throws Exception {
    String check = "validation/release-check.txt";
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(check, table(COMMIT, ARGUMENTS.replace(" --integration", ""), ROWS, CHECKS_PASSED)),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused("the run did not have --integration: run the full release check");
    List<String> rows = new ArrayList<>(ROWS);
    rows.remove("reports");
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(check, table(COMMIT, ARGUMENTS, rows, CHECKS_PASSED)),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused("no reports row: the release check did not run it");
    Map<String, String> cases = new java.util.LinkedHashMap<>();
    cases.put("workflows/summary.json", "no workflows/summary.json: the release check ran without");
    cases.put("catalog/policy-coverage.html", "no catalog/policy-coverage.html");
    cases.put(
        "workflows/pykmip-1.4-jdk25.json",
        "no workflows/pykmip-1.4-jdk25.json, which workflows/summary.json names");
    cases.put(
        "catalog/results/controlled-jdk21.json",
        "no catalog/results/controlled-jdk21.json, which catalog/summary.json names");
    for (Map.Entry<String, String> c : cases.entrySet()) {
      Map<String, String> without = new java.util.HashMap<>();
      without.put("validation/" + c.getKey(), null);
      zips(dir, "9.9.9", SUMS, without, CHECKS_PASSED, source("9.9.9"));
      sealed("9.9.9", SUMS);
      assertRefused("a release ships the workflow suite's and the catalog's reports");
      assertRefused(c.getValue());
    }
    // A summary without one of the JDKs.
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(
            "validation/catalog/summary.json",
            integrationReports()
                .get("validation/catalog/summary.json")
                .replaceAll(", \\{\"jdk\": 25[^}]*}", "")),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused("catalog/summary.json has no tuples on JDK 25");
    assertRefused("catalog/summary.json has no controlled on JDK 25");
  }

  /**
   * A signature stands for a full release check run that passed, the checks of what was packaged
   * included, which the ZIP cannot show (the run's summary.txt is not in it): --publish refuses
   * --unsigned before anything is checked or published.
   */
  @Test
  void publishingNeedsASignedRelease() throws Exception {
    for (String name : SIGNED) Files.delete(dir.resolve(name + ".asc"));
    Run r =
        run(
            "9.9.9",
            "--dir",
            dir.toString(),
            "--notes",
            notes.toString(),
            "--unsigned",
            "--publish");
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("REFUSED: --publish with --unsigned"), r.out());
    assertFalse(r.out().contains("gh release create"), r.out());
    assertFalse(Files.exists(ghCalled), "nothing published");
  }

  /**
   * The release check's own packaging (release.json "packaged": "in release check"), made before
   * the run's last checks: checked unsigned without --publish, as the release check does, and
   * never published: signed, it is refused, and --publish refuses it unsigned. So are a ZIP
   * packaged without reports and one whose release.json does not say how it was packaged.
   */
  @Test
  void theReleaseChecksOwnPackagingIsNeverPublished() throws Exception {
    for (String packaged : List.of("\"in release check\"", "\"without reports\"", "null")) {
      zips(
          dir,
          "9.9.9",
          SUMS,
          Map.of("release.json", releaseJson("9.9.9").replace("\"release\"", packaged)),
          CHECKS_PASSED,
          source("9.9.9"));
      sealed("9.9.9", SUMS);
      assertRefused("release.json says packaged " + packaged + ", not release");
      Run r = run99("--publish");
      assertEquals(1, r.exit(), r.out());
      assertFalse(Files.exists(ghCalled), "nothing published: " + r.out());
      for (String name : SIGNED) Files.delete(dir.resolve(name + ".asc"));
      r = run("9.9.9", "--dir", dir.toString(), "--notes", notes.toString(), "--unsigned");
      assertEquals(0, r.exit(), r.out());
      assertTrue(r.out().contains("NOTE: release.json says packaged " + packaged), r.out());
      assertTrue(r.out().contains("Not published"), r.out());
      r =
          run(
              "9.9.9",
              "--dir",
              dir.toString(),
              "--notes",
              notes.toString(),
              "--unsigned",
              "--publish");
      assertEquals(1, r.exit(), r.out());
      assertFalse(Files.exists(ghCalled), "nothing published: " + r.out());
    }
    String packager =
        Files.readString(LicenseHeadersTest.root().resolve("tools/package-release.py"));
    assertTrue(
        packager.contains(
            "packaged = ('in release check' if options.in_release_check\n"
                + "                else 'release' if options.reports else 'without reports')"),
        "package-release.py marks its packaging in release.json");
    // The release check's own packaging is never signed: a key, however given, refuses it before
    // anything is packaged.
    String packageRelease =
        LicenseHeadersTest.root().resolve("tools/package-release.py").toString();
    Path reports = Files.createDirectories(tmp.resolve("run/validation"));
    for (List<String> key :
        List.of(
            List.of("--sign"),
            List.of("--sign-key", "ABCDEF0123456789"),
            List.of("KEYTEND_GPG_KEY=ABCDEF0123456789"))) {
      List<String> command =
          new ArrayList<>(
              List.of(
                  "python3",
                  packageRelease,
                  "--reports",
                  reports.toString(),
                  "--in-release-check"));
      ProcessBuilder pb = new ProcessBuilder().redirectErrorStream(true);
      if (key.get(0).startsWith("KEYTEND_GPG_KEY="))
        pb.environment().put("KEYTEND_GPG_KEY", key.get(0).split("=", 2)[1]);
      else command.addAll(key);
      Process p = pb.command(command).start();
      String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
      assertEquals(1, p.waitFor(), key + ": " + out);
      assertTrue(
          out.contains("--in-release-check packages a running release check's --reports, unsigned"),
          key + ": " + out);
    }
  }

  @Test
  void aMissingAssetIsRefused() throws Exception {
    for (String asset : ASSETS) {
      Path p = dir.resolve(asset);
      byte[] kept = Files.readAllBytes(p);
      Files.delete(p);
      // Without --publish, a release without its Central bundle is one without it: SHA256SUMS,
      // which lists it, is refused instead.
      Run r = asset.endsWith("-central-bundle.zip") ? run99("--publish") : run99();
      assertEquals(1, r.exit(), asset + ": " + r.out());
      assertTrue(r.out().contains("REFUSED") && r.out().contains(asset), r.out());
      assertFalse(r.out().contains("gh release create"), r.out());
      Files.write(p, kept);
    }
  }

  @Test
  void unsignedNeedsSayingSoAndThenAttachesNoSignatures() throws Exception {
    for (String name : SIGNED) Files.delete(dir.resolve(name + ".asc"));
    assertEquals(1, run99().exit());
    Run r = run("9.9.9", "--dir", dir.toString(), "--notes", notes.toString(), "--unsigned");
    assertEquals(0, r.exit(), r.out());
    assertTrue(r.out().contains("UNSIGNED"), r.out());
    assertFalse(r.out().contains(".asc"), r.out());
    for (String asset : assets("9.9.9", false))
      assertTrue(r.out().contains(dir.resolve(asset).toString()), asset + " in " + r.out());
  }

  /** Writes SHA256SUMS (and signs it), so that only its content can be wrong. */
  void writeSums(String content) throws Exception {
    Files.writeString(dir.resolve("SHA256SUMS"), content);
    sign(dir.resolve("SHA256SUMS"), dir.resolve("SHA256SUMS"));
  }

  @Test
  void inconsistentChecksumsAreRefused() throws Exception {
    String sums = outer("9.9.9", SUMS);
    writeSums(outer("9.9.9", SUMS.replace('0', '1')));
    assertRefused("SHA256SUMS differs");
    // the ZIP's own SHA256SUMS as it is, which lists neither the ZIP nor the files beside it
    writeSums(SUMS);
    assertRefused("SHA256SUMS differs");
    // a test-only asset's line with another hash, missing, or followed by another line
    String testingLine =
        sha256(dir.resolve("keytend-kmip-testing-9.9.9.jar"))
            + "  keytend-kmip-testing-9.9.9.jar\n";
    assertTrue(sums.contains(testingLine), sums);
    writeSums(sums.replace(testingLine, "0".repeat(64) + "  keytend-kmip-testing-9.9.9.jar\n"));
    assertRefused("SHA256SUMS does not end with exactly these lines");
    writeSums(sums.replace(testingLine, ""));
    assertRefused("SHA256SUMS does not end with exactly these lines");
    writeSums(sums + "0".repeat(64) + "  decoy\n");
    assertRefused("SHA256SUMS does not end with exactly these lines");
    writeSums(sums);
    assertEquals(0, run99().exit());
    for (String asset : published("9.9.9").subList(1, 5)) {
      Path sha = dir.resolve(asset + ".sha256");
      String kept = Files.readString(sha);
      Files.writeString(sha, "0".repeat(64) + "  " + asset + "\n");
      assertRefused(asset + ".sha256 is not one line");
      Files.writeString(sha, kept);
    }
    Path checksum = dir.resolve("keytend-kmip-9.9.9.zip.sha256");
    String good = Files.readString(checksum);
    Files.writeString(checksum, "0".repeat(64) + "  keytend-kmip-9.9.9.zip\n");
    assertRefused("keytend-kmip-9.9.9.zip.sha256 is not one line");
    // a .sha256 that names another file, which sha256sum -c would check instead of the ZIP
    Path decoy = Files.writeString(dir.resolve("decoy"), "decoy\n");
    Files.writeString(checksum, sha256(decoy) + "  decoy\n");
    assertRefused("keytend-kmip-9.9.9.zip.sha256 is not one line");
    Files.writeString(checksum, good + good);
    assertRefused("keytend-kmip-9.9.9.zip.sha256 is not one line");
    Files.writeString(checksum, good);
    assertEquals(0, run99().exit());
  }

  @Test
  void aSignatureMustBeAGoodOneByTheReleaseKey() throws Exception {
    // a signature of another file
    sign(dir.resolve("keytend-kmip-9.9.9.zip"), dir.resolve("SHA256SUMS"));
    assertRefused("keytend-kmip-9.9.9.zip.asc is not a good signature");
    sign(dir.resolve("keytend-kmip-9.9.9.zip"), dir.resolve("keytend-kmip-9.9.9.zip"));
    Files.writeString(dir.resolve("SHA256SUMS.asc"), "sig\n");
    assertRefused("SHA256SUMS.asc is not a good signature");
    sign(dir.resolve("SHA256SUMS"), dir.resolve("SHA256SUMS"));
    // the source ZIP's and each test-only asset's signature: of another file, or not a signature
    for (String asset : published("9.9.9").subList(1, 5)) {
      sign(dir.resolve(asset), dir.resolve("keytend-kmip-9.9.9.zip"));
      assertRefused(asset + ".asc is not a good signature");
      Files.writeString(dir.resolve(asset + ".asc"), "sig\n");
      assertRefused(asset + ".asc is not a good signature");
      sign(dir.resolve(asset), dir.resolve(asset));
    }
    // good signatures, by a key that is not the release key
    Run other =
        run(
            "9.9.9",
            "--dir",
            dir.toString(),
            "--notes",
            notes.toString(),
            "--fingerprint",
            "0".repeat(40));
    assertEquals(1, other.exit(), other.out());
    assertTrue(other.out().contains("not a good signature"), other.out());
    // no fingerprint given: SECURITY.md's, the real release key's, which did not sign these
    Run none = run("9.9.9", "--dir", dir.toString(), "--notes", notes.toString());
    assertEquals(1, none.exit(), none.out());
    assertTrue(
        none.out()
            .contains(
                "not a good signature of keytend-kmip-9.9.9.zip by the release key " + RELEASE_KEY),
        none.out());
    assertEquals(0, run99().exit());
  }

  /** gpg's status lines for {@code asset}'s signature, as the script reads them. */
  String status(String asset) throws Exception {
    ProcessBuilder pb =
        new ProcessBuilder(
            "gpg",
            "--batch",
            "--status-fd",
            "1",
            "--verify",
            dir.resolve(asset + ".asc").toString(),
            dir.resolve(asset).toString());
    pb.environment().putAll(gpgEnv());
    Process p = pb.redirectError(ProcessBuilder.Redirect.DISCARD).start();
    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    p.waitFor(60, TimeUnit.SECONDS);
    return out;
  }

  static final String NOT_GOOD =
      "keytend-kmip-9.9.9.zip.asc is not a good signature of keytend-kmip-9.9.9.zip by the release key ";

  /*
   * The rule (the same as the server project's): GOODSIG and VALIDSIG, VALIDSIG's last field the
   * primary fingerprint, and none of EXPKEYSIG, REVKEYSIG, BADSIG, ERRSIG, NO_PUBKEY, EXPSIG.
   * KEYEXPIRED and KEYREVOKED are not refusals: gpg prints them for any expired or revoked subkey
   * of the key, also when another, valid subkey signed.
   */

  @Test
  void aSignatureByThePrimaryIsAccepted() throws Exception {
    signAll(fingerprint, null);
    Run r = run99();
    assertEquals(0, r.exit(), r.out());
  }

  /** Subkey B signs while subkey A of the same primary has expired: gpg says KEYEXPIRED (of A). */
  @Test
  void aSubkeySignatureIsAcceptedWhileAnotherSubkeyIsExpired() throws Exception {
    signAll(subkey, null);
    String status = status("keytend-kmip-9.9.9.zip");
    assertTrue(
        status.contains("[GNUPG:] KEYEXPIRED "),
        "the scenario: another subkey is expired\n" + status);
    assertTrue(status.contains("[GNUPG:] GOODSIG "), status);
    Run r = run99();
    assertEquals(0, r.exit(), r.out());
  }

  /** Made in 2020, while that subkey was valid; it expired in 2021. */
  @Test
  void aSignatureByTheExpiredSubkeyIsRefused() throws Exception {
    signAll(expiredSubkey, "20200601T000000");
    assertTrue(status("keytend-kmip-9.9.9.zip").contains("[GNUPG:] EXPKEYSIG "), "EXPKEYSIG");
    assertRefused(NOT_GOOD + fingerprint);
  }

  @Test
  void aSignatureByAForeignKeyIsRefused() throws Exception {
    signAll(foreign, null);
    assertTrue(
        status("keytend-kmip-9.9.9.zip").contains("[GNUPG:] GOODSIG "),
        "a good signature, by another key");
    assertRefused(NOT_GOOD + fingerprint);
  }

  /** The assets change after they were signed (consistently, so only the signatures are wrong). */
  @Test
  void aSignatureOverModifiedDataIsRefused() throws Exception {
    signAll(subkey, null);
    Map<String, byte[]> signatures = new java.util.HashMap<>();
    for (String name : SIGNED)
      signatures.put(name + ".asc", Files.readAllBytes(dir.resolve(name + ".asc")));
    release("9.9.9", SUMS.replace("0123", "4567"));
    for (var e : signatures.entrySet()) Files.write(dir.resolve(e.getKey()), e.getValue());
    assertTrue(status("keytend-kmip-9.9.9.zip").contains("[GNUPG:] BADSIG "), "BADSIG");
    assertRefused(NOT_GOOD + fingerprint);
  }

  /**
   * The test-only JAR changes after it was signed, its .sha256 and SHA256SUMS (signed again) with
   * it: only its signature is wrong.
   */
  @Test
  void aTestOnlyAssetChangedAfterSigningIsRefused() throws Exception {
    String jar = "keytend-kmip-testing-9.9.9.jar";
    Files.writeString(dir.resolve(jar), "another in-memory server\n");
    writeSha256(jar);
    writeSums(outer("9.9.9", SUMS));
    assertTrue(status(jar).contains("[GNUPG:] BADSIG "), "BADSIG");
    assertRefused(
        jar + ".asc is not a good signature of " + jar + " by the release key " + fingerprint);
    sign(dir.resolve(jar), dir.resolve(jar));
    assertEquals(0, run99().exit());
  }

  /**
   * The binary ZIP holds no source tree and the reports of release checks that passed before
   * packaging; the source ZIP is the source tree under its own top directory. Anything else is
   * refused, with every checksum and signature consistent.
   */
  @Test
  void theZipsAreTheBinaryAndTheSourceDistributions() throws Exception {
    String noSource = "a binary ZIP holds only bin/, lib/, validation/ and its top-level files";
    for (String path : List.of("pom.xml", "sdk/src/A.java", "docs/validation.md")) {
      zips(dir, "9.9.9", SUMS, Map.of(path, "source\n"), CHECKS_PASSED, source("9.9.9"));
      sealed("9.9.9", SUMS);
      assertRefused("keytend-kmip-9.9.9.zip holds keytend-kmip-9.9.9/" + path + ": " + noSource);
    }
    zips(dir, "9.9.9", SUMS, Map.of(), null, source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused("keytend-kmip-9.9.9.zip has no validation/release-check.txt");
    zips(dir, "9.9.9", SUMS, Map.of(), "FAILED BEFORE PACKAGING (1 of 12 checks)", source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused("does not say the release checks before packaging passed");
    String sourceTree =
        "keytend-kmip-9.9.9-src.zip is not the source tree under keytend-kmip-9.9.9-src/";
    for (Map<String, String> source :
        List.of(
            Map.of("pom.xml", "<project/>\n"),
            Map.of("keytend-kmip-9.9.9-src/README.md", "no POM\n"),
            Map.of("keytend-kmip-9.9.9-src/pom.xml", "<project/>\n", "elsewhere/A.java", "x\n"))) {
      zips(dir, "9.9.9", SUMS, Map.of(), CHECKS_PASSED, source);
      sealed("9.9.9", SUMS);
      assertRefused(sourceTree);
    }
    zips(dir, "9.9.9", SUMS, Map.of(), CHECKS_PASSED, source("9.9.9"));
    sealed("9.9.9", SUMS);
    Run r = run99();
    assertEquals(0, r.exit(), r.out());
  }

  /**
   * The binary ZIP must hold its own release check run's passing result of every live check that
   * run makes, at every KMIP version, on the pinned image: a run without --server, a run missing
   * one check at one version, and a failed one are each refused.
   */
  @Test
  void theReleaseCheckRunsOwnLiveResultsAreRequired() throws Exception {
    String pinned = ServerPinTest.pin().getProperty("image_id");
    String live = "validation/live-server.json";
    // Without --server: no live entry, or only the recorded ones.
    String recorded =
        "{\"entries\": ["
            + entry(
                "cassandra-trunk-tde dtest",
                "2.1",
                "recorded",
                pinned,
                "PASS",
                "keytend-kmip-server")
            + "]}\n";
    int all = runScopes().size();
    for (String json : List.of(NO_LIVE_RESULTS, recorded)) {
      zips(dir, "9.9.9", SUMS, Map.of(live, json), CHECKS_PASSED, source("9.9.9"));
      sealed("9.9.9", SUMS);
      assertRefused(
          "a release ships the live results of its own release check run"
              + " (tools/release-check.sh --server):");
      assertRefused(
          all + " live results the release check runs are not this run's (server-probe all 1.1,");
      assertRefused(
          "Run tools/release-check.sh --server <the pinned Docker archive or image> and package"
              + " its reports");
    }
    // One check at one version missing.
    String complete = liveResults();
    String withoutOne =
        complete.replaceFirst(
            "\\{\"scope\": \"interop configured renewal\", \"kmip\": \"2\\.1\"[^}]*\\}, ", "");
    assertNotEquals(complete, withoutOne);
    zips(dir, "9.9.9", SUMS, Map.of(live, withoutOne), CHECKS_PASSED, source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused(
        "1 live results the release check runs are not this run's (interop configured renewal"
            + " 2.1)");
    // The run's entry replaced by a recorded one.
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(live, liveResults("bench smoke|1.4|recorded|" + pinned + "|PASS")),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused("bench smoke (KMIP 1.4) is recorded, but the release check runs it");
    // A failed one, of the run or recorded.
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(live, liveResults("bench smoke|3.0|release check|" + pinned + "|FAIL")),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused(
        "bench smoke (KMIP 3.0, release check) is FAIL: a release ships passing results only");
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(live, liveResults("cassandra-trunk-tde dtest|3.0|recorded|" + pinned + "|FAIL")),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused(
        "cassandra-trunk-tde dtest (KMIP 3.0, recorded) is FAIL: a release ships passing results"
            + " only. Run it again: tools/record-live.sh cassandra-dtest");
    // The probe's all without the full tls-issue-repeat at 1.4 and later.
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(
            live, liveResults().replace("tls-issue-repeat pass=" + repeatPasses(), "tls pass=12")),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused("did not pass the full tls-issue-repeat");
    // A part of it is not the full repeat.
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(
            live,
            liveResults()
                .replace(
                    "tls-issue-repeat pass=" + repeatPasses() + " fail=0",
                    "tls-issue-repeat pass=" + (repeatPasses() - 1) + " fail=0")),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused(
        "(pass="
            + (repeatPasses() - 1)
            + " fail=0, not pass="
            + repeatPasses()
            + " fail=0) did not pass the full tls-issue-repeat");
    // Complete, with the recorded checks beside it: accepted.
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(
            live,
            liveResults(
                "cassandra-trunk-tde dtest|2.1|recorded|" + pinned + "|PASS",
                "cassandra-trunk-tde dtest|3.0|recorded|" + pinned + "|PASS")),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    Run r = run99();
    assertEquals(0, r.exit(), r.out());
  }

  /**
   * The binary ZIP's live results must all be of the pinned keytend-kmip-server build, and only
   * the checks the release check cannot run may be recorded; a refusal names the command that
   * runs the check again.
   */
  @Test
  void theLiveResultsMustBeOfThePinnedServerBuild() throws Exception {
    String pinned = ServerPinTest.pin().getProperty("image_id");
    String older = "9".repeat(64);
    String live = "validation/live-server.json";
    for (String source : List.of("recorded", "release check")) {
      String scope = source.equals("recorded") ? "cassandra-trunk-tde dtest" : "server-probe all";
      zips(
          dir,
          "9.9.9",
          SUMS,
          Map.of(live, liveResult(scope, source, pinned)),
          CHECKS_PASSED,
          source("9.9.9"));
      sealed("9.9.9", SUMS);
      Run r = run99();
      assertEquals(0, r.exit(), r.out());
    }
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(live, liveResult("cassandra-trunk-tde dtest", "recorded", older)),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused(
        "a release ships live results of the pinned server build only"
            + " (tools/kmip-server/pinned-image.properties):\n"
            + "keytend-kmip-9.9.9.zip: validation/live-server.json:"
            + " cassandra-trunk-tde dtest (KMIP 2.1)"
            + " ran on keytend-kmip-server 9.9.9 (image 999999999999), not on the pinned");
    assertRefused(
        "Run it again on the pinned image: tools/record-live.sh cassandra-dtest --server <the"
            + " pinned Docker archive or image> --cassandra ../cassandra-trunk");
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(live, liveResult("server-probe tls-issue-repeat", "recorded", pinned)),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused(
        "server-probe tls-issue-repeat (KMIP 2.1) is recorded, but the release check runs it");
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(live, liveResult("server-probe all", "release check", older)),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused(
        "server-probe all (KMIP 2.1) ran on keytend-kmip-server 9.9.9 (image 999999999999),"
            + " not on the pinned");
    assertRefused(
        "Run it again on the pinned image: tools/release-check.sh --server <the pinned Docker"
            + " archive or image>");
    zips(
        dir,
        "9.9.9",
        SUMS,
        Map.of(live, liveResult("interop minimal suite", "recorded", pinned)),
        CHECKS_PASSED,
        source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused(
        "interop minimal suite (KMIP 2.1) is recorded, but the release check runs it: remove it"
            + " from validation/recorded/live-server.json");
    zips(dir, "9.9.9", SUMS, Map.of(live, "{}\n"), CHECKS_PASSED, source("9.9.9"));
    sealed("9.9.9", SUMS);
    assertRefused("validation/live-server.json: no \"entries\" list");
  }

  /**
   * A subkey's signature is accepted until the subkey is revoked, then refused (REVKEYSIG), while
   * the other subkey still signs, the revoked one beside it.
   */
  @Test
  void aSignatureByARevokedSubkeyIsRefusedAndTheOthersStillSign() throws Exception {
    signAll(revokedSubkey, null);
    assertEquals(0, run99().exit(), "before the revocation");
    exec(
        gpgEnv(),
        "/bin/sh",
        "-c",
        "printf 'key 3\\nrevkey\\ny\\n0\\n\\ny\\nsave\\n' | gpg --batch --pinentry-mode loopback"
            + " --passphrase '' --command-fd 0 --edit-key "
            + fingerprint);
    assertTrue(
        exec(gpgEnv(), "gpg", "--batch", "--with-colons", "--list-keys", fingerprint)
            .contains("\nsub:r:"),
        "revoked");
    assertTrue(status("keytend-kmip-9.9.9.zip").contains("[GNUPG:] REVKEYSIG "), "REVKEYSIG");
    assertRefused(NOT_GOOD + fingerprint);
    signAll(subkey, null);
    Run r = run99();
    assertEquals(
        0,
        r.exit(),
        "the other subkey still signs, beside a revoked and an expired one: " + r.out());
  }

  /** The release key's primary key fingerprint, as SECURITY.md publishes it. */
  static final String RELEASE_KEY = "3A84912AFBE7D2B04EBA2A8A51E65DD49C6F987F";

  /**
   * The fingerprint is read from SECURITY.md's "Release key fingerprint" line: the real line names
   * the real key, and the forms the parser accepts (plain, in groups of four, in backticks, lower
   * case) all read as it; a line without one is refused as no fingerprint.
   */
  @Test
  void theFingerprintIsReadFromSecurityMd() throws Exception {
    String security = Files.readString(LicenseHeadersTest.root().resolve("SECURITY.md"));
    assertTrue(
        security.contains("**Release key fingerprint:** `" + RELEASE_KEY + "`"),
        "SECURITY.md publishes the key");
    String grouped = RELEASE_KEY.replaceAll("(.{4})(?!$)", "$1 ");
    Path root = tmp.resolve("checkout");
    Files.createDirectories(root.resolve("tools"));
    // The script, and what it reads beside it: the live results' rules, the server pin and the
    // probe (the full tls-issue-repeat's count).
    Files.createDirectories(root.resolve("tools/kmip-server"));
    Files.createDirectories(root.resolve("tools/server-probe"));
    for (String f :
        List.of(
            "tools/publish-release.sh",
            "tools/release_reports.py",
            "tools/kmip-server/pinned-image.properties",
            "tools/server-probe/ServerProbe.java"))
      Files.copy(LicenseHeadersTest.root().resolve(f), root.resolve(f));
    for (String line :
        List.of(
            "`" + RELEASE_KEY + "`",
            RELEASE_KEY,
            grouped,
            "`" + grouped.toLowerCase(Locale.ROOT) + "`")) {
      Files.writeString(
          root.resolve("SECURITY.md"),
          "# Security\n\n**Release key fingerprint:** " + line + "\n\nMore.\n");
      Run r = runAt(root, "9.9.9", "--dir", dir.toString(), "--notes", notes.toString());
      assertEquals(1, r.exit(), r.out());
      assertTrue(r.out().contains("by the release key " + RELEASE_KEY), line + ": " + r.out());
    }
    Files.writeString(
        root.resolve("SECURITY.md"),
        "# Security\n\n**Release key fingerprint:** published later\n");
    Run r = runAt(root, "9.9.9", "--dir", dir.toString(), "--notes", notes.toString());
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("REFUSED: no release key fingerprint"), r.out());
  }

  /**
   * The notes are RELEASE.md's section of the release, and an unreleased section is refused. A
   * pre-release's notes (X.Y.Z-rc.N) are its release's section, after a line naming it.
   */
  @Test
  void theNotesAreTheReleasedSectionOfReleaseMd() throws Exception {
    // RELEASE.md itself: 0.10.0 is keytend-kmip's first release. A copy with 0.10.0 marked
    // unreleased, as it is before the version is prepared.
    String releaseMd = Files.readString(LicenseHeadersTest.root().resolve("RELEASE.md"));
    java.util.regex.Matcher heading =
        java.util.regex.Pattern.compile("(?m)^# keytend-kmip 0\\.10\\.0(?![.\\d-]).*$")
            .matcher(releaseMd);
    assertTrue(heading.find(), "RELEASE.md has a 0.10.0 section");
    Path marked =
        Files.writeString(
            tmp.resolve("RELEASE-unreleased.md"),
            heading.replaceFirst("# keytend-kmip 0.10.0 (unreleased)"));
    release("0.10.0-rc.1", sums("0.10.0-rc.1"));
    Run unreleased =
        run(
            "0.10.0-rc.1",
            "--dir",
            dir.toString(),
            "--release-md",
            marked.toString(),
            "--fingerprint",
            fingerprint);
    assertEquals(1, unreleased.exit(), unreleased.out());
    assertTrue(unreleased.out().contains("still marks 0.10.0 \"(unreleased)\""), unreleased.out());
    release("9.7.0", sums("9.7.0"));
    Run old = run("9.7.0", "--dir", dir.toString(), "--fingerprint", fingerprint);
    assertEquals(1, old.exit(), old.out());
    assertTrue(old.out().contains("no \"# keytend-kmip 9.7.0\" section"), old.out());
    // Prepared, 0.10.0-rc.1's notes are 0.10.0's section alone, after the line naming it: they
    // end at the next top-level heading.
    Path cut =
        Files.writeString(
            tmp.resolve("RELEASE-0.10.0.md"), heading.replaceFirst("# keytend-kmip 0.10.0"));
    release("0.10.0-rc.1", sums("0.10.0-rc.1"));
    Run first =
        run(
            "0.10.0-rc.1",
            "--dir",
            dir.toString(),
            "--release-md",
            cut.toString(),
            "--fingerprint",
            fingerprint);
    assertEquals(0, first.exit(), first.out());
    String notes = Files.readString(dir.resolve("release-notes-0.10.0-rc.1.md"));
    assertTrue(
        notes.startsWith(
            "This is keytend-kmip 0.10.0-rc.1, a pre-release of 0.10.0.\n\n"
                + "keytend-kmip 0.10.0 is the first release"),
        notes.substring(0, Math.min(200, notes.length())));
    assertFalse(notes.lines().anyMatch(l -> l.startsWith("# ")), "only 0.10.0's section");
    assertTrue(notes.length() < 60_000, "0.10.0's notes: " + notes.length() + " characters");
    Path draft =
        Files.writeString(
            tmp.resolve("RELEASE.md"),
            "# keytend-kmip 9.10.0 (unreleased)\n\nNot yet.\n\n# keytend-kmip 9.9.9\n\nOut.\n");
    release("9.9.9", SUMS);
    Run released =
        run(
            "9.9.9",
            "--dir",
            dir.toString(),
            "--release-md",
            draft.toString(),
            "--fingerprint",
            fingerprint);
    assertEquals(0, released.exit(), released.out());
    String written = Files.readString(dir.resolve("release-notes-9.9.9.md"));
    assertTrue(written.startsWith("Out.\n\n## Assets\n\n"), written);
    // What each asset is: each published file, the .sha256 files, SHA256SUMS and the signatures.
    for (String asset : published("9.9.9"))
      assertTrue(
          written.contains("- `" + asset + "`") || written.contains("`" + asset + "`: "), asset);
    assertTrue(written.contains("for tests only") && written.contains("not in the ZIP"), written);
    for (String part : List.of("`.sha256`", "`SHA256SUMS`", "`.asc`"))
      assertTrue(written.contains("- " + part), part + " in " + written);
    Run unsigned =
        run("9.9.9", "--dir", dir.toString(), "--release-md", draft.toString(), "--unsigned");
    assertEquals(0, unsigned.exit(), unsigned.out());
    written = Files.readString(dir.resolve("release-notes-9.9.9.md"));
    assertTrue(written.contains("this release is unsigned"), written);
    assertFalse(written.contains("- `.asc`"), written);
    release("9.10.0", sums("9.10.0"));
    Run refused =
        run(
            "9.10.0",
            "--dir",
            dir.toString(),
            "--release-md",
            draft.toString(),
            "--fingerprint",
            fingerprint);
    assertEquals(1, refused.exit(), refused.out());
    assertTrue(refused.out().contains("(unreleased)"), refused.out());
    release("9.8.0", sums("9.8.0"));
    Run none =
        run(
            "9.8.0",
            "--dir",
            dir.toString(),
            "--release-md",
            draft.toString(),
            "--fingerprint",
            fingerprint);
    assertEquals(1, none.exit(), none.out());
    assertTrue(none.out().contains("no \"# keytend-kmip 9.8.0\" section"), none.out());
  }

  /**
   * A release page cannot resolve a relative link, so the notes link each file of the repo at the
   * release's tag. Absolute links, anchors and code are left as they are.
   */
  @Test
  void theNotesLinkTheReposFilesAtTheTag() throws Exception {
    Path md =
        Files.writeString(
            tmp.resolve("RELEASE-links.md"),
            String.join(
                "\n",
                "# keytend-kmip 9.9.9",
                "",
                "See [start](docs/getting-started.md#build-and-install), [security](./SECURITY.md)",
                "and [the samples](sdk/src/samples), [above](#assets), [site](https://keytend.dev),",
                "[mail](mailto:security@keytend.dev) and `[code](docs/x.md)`.",
                "",
                "```",
                "[fenced](docs/y.md)",
                "```",
                "",
                "[ref]: cli/README.md",
                ""));
    release("9.9.9-rc.2", sums("9.9.9-rc.2"));
    Run r =
        run(
            "9.9.9-rc.2",
            "--dir",
            dir.toString(),
            "--release-md",
            md.toString(),
            "--fingerprint",
            fingerprint);
    assertEquals(0, r.exit(), r.out());
    String notes = Files.readString(dir.resolve("release-notes-9.9.9-rc.2.md"));
    String blob = "https://github.com/keytend/keytend-kmip-java/blob/v9.9.9-rc.2/";
    for (String link :
        List.of(
            "[start](" + blob + "docs/getting-started.md#build-and-install)",
            "[security](" + blob + "SECURITY.md)",
            "[the samples](" + blob + "sdk/src/samples)",
            "[above](#assets)",
            "[site](https://keytend.dev)",
            "[mail](mailto:security@keytend.dev)",
            "`[code](docs/x.md)`",
            "\n[fenced](docs/y.md)\n",
            "[ref]: " + blob + "cli/README.md"))
      assertTrue(notes.contains(link), link + " in " + notes);
  }
}
