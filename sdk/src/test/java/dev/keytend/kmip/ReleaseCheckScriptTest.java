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

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@code tools/release-check.sh} itself, with the verify runs ({@code --skip-verify} not given),
 * on a small repository whose Maven wrapper is a stub that writes Surefire reports: each report
 * lands where the script says. The Surefire reports go to the run directory's {@code
 * surefire-*}/, the release's reports (release-check.txt first) to its {@code validation/}, which
 * holds no test output and no local path; the run, which left out checks, cannot make a release.
 */
class ReleaseCheckScriptTest {
  @TempDir Path tmp;

  /** A Maven wrapper that writes a passing Surefire report of each module for test and verify. */
  static final String MVNW =
      String.join(
          "\n",
          "#!/usr/bin/env bash",
          "args=(\"$@\")",
          "pom=pom.xml",
          "goals=()",
          "while [ $# -gt 0 ]; do",
          "  case $1 in -f) pom=$2; shift 2 ;; -*) shift ;; *) goals+=(\"$1\"); shift ;; esac",
          "done",
          "tree=$(dirname \"$pom\")",
          "echo \"stub maven ${goals[*]} in $tree\"",
          "case \" ${goals[*]} \" in *' clean '*) rm -rf \"$tree\"/*/target ;; esac",
          "case \" ${goals[*]} \" in",
          "  *' test '*|*' verify '*)",
          "    for m in sdk cli; do",
          "      d=$tree/$m/target/surefire-reports",
          "      mkdir -p \"$d\"",
          "      for c in ATest PersistedFormatsTest LicenseHeadersTest; do",
          "        printf '<testsuite name=\"dev.keytend.%s.%s\" tests=\"2\" failures=\"0\""
              + " errors=\"0\" skipped=\"0\"/>\\n' \"$m\" \"$c\" >\"$d/TEST-dev.keytend.$m.$c.xml\"",
          "      done",
          "    done ;;",
          "esac",
          "for a in \"${args[@]}\"; do case $a in",
          "  -Papi-compat) mkdir -p \"$tree/sdk/target/japicmp\"",
          "    echo '<japicmp><classes/></japicmp>' >\"$tree/sdk/target/japicmp/api-compat.xml\" ;;",
          "  -Dapi.compat.fail=*) echo \"api-compat $a\" ;;",
          "esac; done",
          "echo BUILD SUCCESS",
          "");

  static PackageReleaseSigningTest.Run exec(Path dir, Map<String, String> env, String... command)
      throws Exception {
    ProcessBuilder pb =
        new ProcessBuilder(command).directory(dir.toFile()).redirectErrorStream(true);
    pb.environment().putAll(env);
    Process p = pb.start();
    String out =
        new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
    assertTrue(p.waitFor(300, java.util.concurrent.TimeUnit.SECONDS), String.join(" ", command));
    return new PackageReleaseSigningTest.Run(p.exitValue(), out);
  }

  static void write(Path file, String content, boolean executable) throws Exception {
    Files.createDirectories(file.getParent());
    Files.writeString(file, content);
    if (executable) assertTrue(file.toFile().setExecutable(true), file.toString());
  }

  /** A small repository of the release check and its stubs: its path, environment and commit. */
  record Repo(Path dir, Map<String, String> env, String commit) {}

  /**
   * The repository: tools/release-check.sh and the tools it reads, stubs of what this test does
   * not exercise, {@link #MVNW}, a tree that builds {@code version}, and each of {@code files}
   * (path to content; a {@code .sh} is executable), committed.
   */
  Repo repo(String version, Map<String, String> files) throws Exception {
    for (String tool : List.of("bash", "git", "python3"))
      assumeTrue(PackageReleaseSigningTest.onPath(tool), tool);
    Path root = LicenseHeadersTest.root();
    Path repo = Files.createDirectories(tmp.resolve("repo"));
    Path home = Files.createDirectories(tmp.resolve("home"));
    // The scripts under test, and stubs of what they call that this test does not exercise.
    for (String tool :
        List.of(
            "tools/release-check.sh",
            "tools/release_reports.py",
            "tools/api-baseline.sh",
            "tools/kmip-server/pinned-image.properties")) {
      Files.createDirectories(repo.resolve(tool).getParent());
      Files.copy(root.resolve(tool), repo.resolve(tool));
      if (tool.endsWith(".sh")) assertTrue(repo.resolve(tool).toFile().setExecutable(true), tool);
    }
    write(repo.resolve("tools/license_headers.py"), "print('all files have headers')\n", false);
    write(repo.resolve("mvnw"), MVNW, true);
    write(
        repo.resolve("pom.xml"),
        "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"><version>"
            + version
            + "</version><modules><module>sdk</module><module>cli</module></modules></project>\n",
        false);
    write(
        repo.resolve("sdk/pom.xml"),
        "<project xmlns=\"http://maven.apache.org/POM/4.0.0\"/>\n",
        false);
    write(repo.resolve("cli/README.md"), "cli\n", false);
    write(repo.resolve("validation/recorded/live-server.json"), "{\"entries\": []}\n", false);
    for (Map.Entry<String, String> f : files.entrySet())
      write(repo.resolve(f.getKey()), f.getValue(), f.getKey().endsWith(".sh"));
    // A JDK 17 whose java only says its version.
    Path jdk = tmp.resolve("jdk17");
    write(jdk.resolve("bin/java"), "#!/bin/sh\necho 'openjdk version \"17\"' >&2\n", true);
    Map<String, String> env =
        Map.of("HOME", home.toString(), "JDK17_HOME", jdk.toString(), "GIT_CONFIG_NOSYSTEM", "1");
    String[] git = {"git", "-c", "user.name=t", "-c", "user.email=t@example.invalid"};
    for (List<String> step :
        List.of(
            List.of("init", "-q", "-b", "main"),
            List.of("add", "-A"),
            List.of("commit", "-qm", "t"))) {
      List<String> command = new ArrayList<>(List.of(git));
      command.addAll(step);
      PackageReleaseSigningTest.Run r = exec(repo, env, command.toArray(String[]::new));
      assertEquals(0, r.exit(), r.out());
    }
    return new Repo(repo, env, exec(repo, env, "git", "rev-parse", "HEAD").out().strip());
  }

  /** tools/release-check.sh of {@code repo} with {@code args}. */
  static PackageReleaseSigningTest.Run check(Repo repo, String... args) throws Exception {
    List<String> command =
        new ArrayList<>(List.of("bash", repo.dir().resolve("tools/release-check.sh").toString()));
    command.addAll(List.of(args));
    return exec(repo.dir(), repo.env(), command.toArray(String[]::new));
  }

  /** The row of {@code check} in the table the release check printed. */
  static String row(PackageReleaseSigningTest.Run r, String check) {
    return r.out()
        .lines()
        .filter(l -> l.matches("\\s*(PASS|FAIL|SKIP|UNPIN)\\s+" + check + "\\b.*"))
        .findFirst()
        .orElseThrow(() -> new AssertionError("no " + check + " row: " + r.out()));
  }

  @Test
  void theReportsLandInValidationAndTheTestOutputInTheRunDirectory() throws Exception {
    Repo repository = repo("0.10.0-rc.1", Map.of());
    Path repo = repository.dir();
    Map<String, String> env = repository.env();
    String commit = repository.commit();
    Path run = tmp.resolve("run");
    // The verify runs included (no --skip-verify): the path where the reports once went astray.
    PackageReleaseSigningTest.Run r =
        exec(
            repo,
            env,
            "bash",
            repo.resolve("tools/release-check.sh").toString(),
            "--out",
            run.toString(),
            "--jdks",
            "17",
            "--skip-repro");
    // Without --server the run cannot make a release: live-run fails, so the check fails.
    assertEquals(1, r.exit(), r.out());
    for (String row :
        List.of("test-jdk17", "verify-jdk17", "format-fixtures-jdk17", "license-headers-jdk17"))
      assertTrue(
          r.out().lines().anyMatch(l -> l.matches("\\s*PASS\\s+" + row + "\\b.*")),
          row + ": " + r.out());
    assertTrue(r.out().lines().anyMatch(l -> l.matches("\\s*FAIL\\s+live-run\\b.*")), r.out());
    // The Surefire reports: in the run directory, each module's, and nothing else there.
    for (String dir : List.of("surefire-test-jdk17", "surefire-jdk17")) {
      try (Stream<Path> files = Files.list(run.resolve(dir))) {
        assertEquals(
            List.of("cli-surefire-reports", "sdk-surefire-reports"),
            files.map(p -> p.getFileName().toString()).sorted().toList(),
            dir);
      }
    }
    // The release's reports: release-check.txt of the commit in validation/, no test output.
    Path validation = run.resolve("validation");
    List<String> reports;
    try (Stream<Path> files = Files.walk(validation)) {
      reports =
          files
              .filter(Files::isRegularFile)
              .map(p -> validation.relativize(p).toString())
              .sorted()
              .toList();
    }
    assertEquals(List.of("release-check.txt"), reports);
    String check = Files.readString(validation.resolve("release-check.txt"));
    assertTrue(check.contains("commit " + commit + "\n"), check);
    assertTrue(check.contains("arguments --out <run directory> --jdks 17 --skip-repro\n"), check);
    assertTrue(check.contains("verify-jdk17"), check);
    assertFalse(check.contains(run.toString()), "no local path: " + check);
    assertTrue(Files.isRegularFile(run.resolve("summary.txt")), "summary.txt in the run directory");
    PackageReleaseSigningTest.Run guard =
        exec(
            repo,
            env,
            "python3",
            repo.resolve("tools/release_reports.py").toString(),
            "guard",
            validation.toString());
    assertEquals(0, guard.exit(), guard.out());
    // And the packaging refuses it: no --server, --skip-repro, and checks that did not pass.
    PackageReleaseSigningTest.Run refused =
        exec(
            repo,
            env,
            "python3",
            repo.resolve("tools/release_reports.py").toString(),
            "run",
            validation.toString(),
            "--commit",
            commit,
            "--version",
            "0.10.0-rc.1");
    assertEquals(1, refused.exit(), refused.out());
    for (String why :
        List.of(
            "the run left out or weakened checks (--skip-repro)",
            "the run did not have --integration",
            "no verify-jdk21 row",
            "no reports row",
            "live-run is FAIL",
            "51 live results the release check runs are not this run's",
            "summary.txt does not say the release check passed: RELEASE CHECK FAILED"))
      assertTrue(refused.out().contains(why), why + " in " + refused.out());
  }

  /**
   * The server's Docker archive and the API baseline, downloaded to /tmp as the READMEs say, are
   * recorded by their file names: release-check.txt's arguments line and every report hold no
   * local path, so the run's reports can be packaged (the guard accepts them).
   */
  @Test
  void aDownloadedServerArchiveIsRecordedByItsName() throws Exception {
    Path downloads = Path.of("/tmp");
    assumeTrue(Files.isDirectory(downloads) && Files.isWritable(downloads), "/tmp");
    Path kts = Files.createTempDirectory(downloads, "kts-test");
    try {
      Path archive =
          write(kts.resolve("release/linux-amd64/keytend-kmip-server-0.10.0-rc.1.docker.tar"));
      Path baseline = write(kts.resolve("keytend-kmip-0.10.0.zip"));
      // run-server.sh refuses the archive and names it, as it does an archive of another build.
      Repo repo =
          repo(
              "0.10.0-rc.1",
              Map.of(
                  "tools/kmip-server/run-server.sh",
                  "#!/usr/bin/env bash\necho \"run-server.sh: $2 has SHA-256 0, not the pinned"
                      + " archive's\" >&2\nexit 3\n"));
      Path run = tmp.resolve("run");
      PackageReleaseSigningTest.Run r =
          check(
              repo,
              "--out",
              run.toString(),
              "--jdks",
              "17",
              "--skip-verify",
              "--skip-repro",
              "--server",
              archive.toString(),
              "--baseline",
              baseline.toString());
      assertEquals(1, r.exit(), r.out());
      assertTrue(
          row(r, "server-probe").contains("keytend-kmip-server-0.10.0-rc.1.docker.tar has SHA-256"),
          r.out());
      Path validation = run.resolve("validation");
      String check = Files.readString(validation.resolve("release-check.txt"));
      assertTrue(
          check.contains(
              "\narguments --out <run directory> --jdks 17 --skip-verify --skip-repro --server"
                  + " keytend-kmip-server-0.10.0-rc.1.docker.tar --baseline"
                  + " keytend-kmip-0.10.0.zip\n"),
          check);
      assertFalse(check.contains(kts.toString()), check);
      PackageReleaseSigningTest.Run guard =
          exec(
              repo.dir(),
              repo.env(),
              "python3",
              repo.dir().resolve("tools/release_reports.py").toString(),
              "guard",
              validation.toString());
      assertEquals(0, guard.exit(), guard.out());
    } finally {
      try (Stream<Path> files = Files.walk(kts)) {
        for (Path p : files.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(p);
      }
    }
  }

  static Path write(Path file) throws Exception {
    write(file, "x\n", false);
    return file;
  }

  /**
   * The API check fails closed: unless tools/api-baseline.sh --fails exits 0 and prints exactly
   * fail or report, api-compat is FAIL. With report, an incompatible change is reported
   * (-Dapi.compat.fail=false); with fail, it fails the build.
   */
  @Test
  void theApiCheckFailsClosed() throws Exception {
    String[][] cases = {
      {"exit 1", "FAIL", "exited 1 and printed \"\""},
      {"echo; exit 0", "FAIL", "exited 0 and printed \"\""},
      {"echo maybe; exit 0", "FAIL", "printed \"maybe\", not fail or report"},
      {"echo report; exit 2", "FAIL", "exited 2"},
      {"echo report; exit 0", "PASS", "-Dapi.compat.fail=false"},
      {"echo fail; exit 0", "PASS", "-Dapi.compat.fail=true"},
    };
    int n = 0;
    for (String[] c : cases) {
      n++;
      Path dir = tmp.resolve("repo");
      if (Files.exists(dir))
        try (Stream<Path> files = Files.walk(dir)) {
          for (Path p : files.sorted(java.util.Comparator.reverseOrder()).toList()) Files.delete(p);
        }
      Repo repo =
          repo(
              "0.11.0",
              Map.of(
                  "tools/api-baseline.sh",
                  String.join(
                      "\n",
                      "#!/usr/bin/env bash",
                      "case ${1:-} in",
                      "  --version) echo 0.10.0 ;;",
                      "  --fails) " + c[0] + " ;;",
                      "  *) echo baseline ;;",
                      "esac",
                      "")));
      Path run = tmp.resolve("run-" + n);
      PackageReleaseSigningTest.Run r =
          check(repo, "--out", run.toString(), "--jdks", "17", "--skip-verify", "--skip-repro");
      String compat = row(r, "api-compat");
      assertTrue(compat.matches("\\s*" + c[1] + "\\s+api-compat\\b.*"), c[0] + ": " + r.out());
      if (c[1].equals("FAIL")) assertTrue(compat.contains(c[2]), c[0] + ": " + compat);
      else
        assertTrue(
            Files.readString(run.resolve("logs/api-compat.log")).contains("api-compat " + c[2]),
            c[0] + ": " + r.out());
    }
  }
}
