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
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The release's reports ({@code tools/release_reports.py}): the recorded evidence in {@code
 * validation/recorded/} is listed with its dates and servers; a live result replaces the entry of
 * its check and KMIP version and is never appended; the server probe's and the interop suite's
 * output become entries; the JUnit totals come from the release check's report copies; and {@code
 * tools/package-release.py} packages a release check's reports of the commit it packages only,
 * with the recorded results merged under the run's. A release ships live results of the pinned
 * keytend-kmip-server build only, and records only the checks the release check cannot run.
 * Results are not committed under {@code docs/}.
 */
class ReleaseReportsTest {
  @TempDir Path work;

  static Path root() {
    return LicenseHeadersTest.root();
  }

  @BeforeAll
  static void python() {
    assumeTrue(PackageReleaseSigningTest.onPath("python3"), "python3");
  }

  static PackageReleaseSigningTest.Run python(String... args) throws Exception {
    String[] command = new String[args.length + 2];
    command[0] = "python3";
    command[1] = root().resolve("tools/release_reports.py").toString();
    System.arraycopy(args, 0, command, 2, args.length);
    return PackageReleaseSigningTest.exec(Map.of(), command);
  }

  /** Runs {@code script} with the module of tools/release_reports.py as {@code m}. */
  static PackageReleaseSigningTest.Run module(String file, String script, String... args)
      throws Exception {
    String[] command = new String[args.length + 5];
    command[0] = "python3";
    command[1] = "-I";
    command[2] = "-c";
    command[3] =
        String.join(
            "\n",
            "import importlib.util, json, pathlib, sys",
            "spec = importlib.util.spec_from_file_location('m', sys.argv[1])",
            "m = importlib.util.module_from_spec(spec)",
            "spec.loader.exec_module(m)",
            script);
    command[4] = root().resolve(file).toString();
    System.arraycopy(args, 0, command, 5, args.length);
    return PackageReleaseSigningTest.exec(Map.of(), command);
  }

  static PackageReleaseSigningTest.Run setEntry(
      Path file, String scope, String result, String date, String source, String... versions)
      throws Exception {
    return setEntryOn(file, scope, result, date, source, "", versions);
  }

  /** {@link #setEntry}, run on the image {@code image}. */
  static PackageReleaseSigningTest.Run setEntryOn(
      Path file,
      String scope,
      String result,
      String date,
      String source,
      String image,
      String... versions)
      throws Exception {
    List<String> args =
        new java.util.ArrayList<>(List.of("set", file.toString(), "--scope", scope));
    for (String v : versions) args.addAll(List.of("--kmip", v));
    args.addAll(
        List.of(
            "--result",
            result,
            "--command",
            "run.sh",
            "--detail",
            result + " on " + date,
            "--server",
            "keytend-kmip-server 9.9.9",
            "--image",
            image,
            "--jdk",
            "17",
            "--date",
            date,
            "--source",
            source));
    return python(args.toArray(String[]::new));
  }

  /** The pinned image's ID (tools/kmip-server/pinned-image.properties). */
  static String pinnedImage() throws Exception {
    return ServerPinTest.pin().getProperty("image_id");
  }

  /** The committed validation/recorded/ is complete: every file listed, with date and server. */
  @Test
  void theRecordedEvidenceIsListedWithItsDatesAndServers() throws Exception {
    PackageReleaseSigningTest.Run r = python("check");
    assertEquals(0, r.exit(), r.out());
    assertTrue(r.out().startsWith("validation/recorded: "), r.out());
    // A file that index.json does not list, or a listed file that is gone, is refused.
    Path copy = work.resolve("recorded");
    PackageReleaseSigningTest.ok(
        Map.of(), "cp", "-r", root().resolve("validation/recorded").toString(), copy.toString());
    Files.writeString(copy.resolve("oasis-replay/unlisted.json"), "{}\n");
    PackageReleaseSigningTest.Run unlisted =
        module(
            "tools/release_reports.py",
            "m.check_recorded(pathlib.Path(sys.argv[2]))",
            copy.toString());
    assertNotEquals(0, unlisted.exit(), unlisted.out());
    assertTrue(unlisted.out().contains("oasis-replay/unlisted.json"), unlisted.out());
    Files.delete(copy.resolve("oasis-replay/unlisted.json"));
    Files.delete(copy.resolve("oasis-replay/pykmip-oasis-1.3-jdk25.json"));
    PackageReleaseSigningTest.Run gone =
        module(
            "tools/release_reports.py",
            "m.check_recorded(pathlib.Path(sys.argv[2]))",
            copy.toString());
    assertNotEquals(0, gone.exit(), gone.out());
    assertTrue(gone.out().contains("pykmip-oasis-1.3-jdk25.json"), gone.out());
    // Only the checks the release check cannot run are recorded.
    Files.writeString(copy.resolve("oasis-replay/pykmip-oasis-1.3-jdk25.json"), "{}\n");
    assertEquals(
        0,
        setEntry(
                copy.resolve("live-server.json"),
                "interop minimal suite",
                "PASS",
                "2026-11-09",
                "recorded",
                "2.1")
            .exit());
    PackageReleaseSigningTest.Run released =
        module(
            "tools/release_reports.py",
            "m.check_recorded(pathlib.Path(sys.argv[2]))",
            copy.toString());
    assertNotEquals(0, released.exit(), released.out());
    assertTrue(
        released
            .out()
            .contains(
                "interop minimal suite 2.1: the release check runs it; only"
                    + " cassandra-trunk-tde dtest may be recorded"),
        released.out());
  }

  static String[] identity() {
    return new String[] {
      "--server",
      "keytend-kmip-server 9.9.9",
      "--image",
      "abc",
      "--jdk",
      "17",
      "--date",
      "2026-11-09"
    };
  }

  static PackageReleaseSigningTest.Run python(List<String> args, String... more) throws Exception {
    List<String> all = new java.util.ArrayList<>(args);
    all.addAll(List.of(more));
    all.addAll(List.of(identity()));
    return python(all.toArray(String[]::new));
  }

  static List<String> listed(Path file) throws Exception {
    return module(
            "tools/release_reports.py",
            "print('\\n'.join(e['scope'] + ' ' + e['kmip'] + ' ' + e['result'] + ': ' + e['detail']"
                + " + ' [' + e['command'] + ']' for e in m.load(sys.argv[2])))",
            file.toString())
        .out()
        .lines()
        .toList();
  }

  /**
   * The probe under another server setting is a scope of its own, which names the setting in the
   * command too.
   */
  @Test
  void aProbeUnderAServerSettingIsAScopeOfItsOwn() throws Exception {
    Path probe = work.resolve("probe");
    Files.createDirectories(probe.resolve("v3.0"));
    Files.writeString(
        probe.resolve("v3.0/probe.log"),
        "---- [3.0] raw-leases\nPASS [3.0] raw-leases.zero: ok\n"
            + "SUMMARY [3.0] pass=1 fail=0 info=0 skip=0\n");
    Path file = work.resolve("live-server.json");
    PackageReleaseSigningTest.Run r =
        python(
            List.of("probe", file.toString(), probe.toString()),
            "--scenarios",
            "raw-leases,tls",
            "--env",
            "KMIP_MAX_LEASE_SECONDS=0");
    assertEquals(0, r.exit(), r.out());
    assertEquals(
        List.of(
            "server-probe raw-leases,tls, KMIP_MAX_LEASE_SECONDS=0 3.0 PASS: pass=1 fail=0 info=0"
                + " skip=0; raw-leases pass=1 fail=0 info=0 skip=0 [KMIP_MAX_LEASE_SECONDS=0"
                + " tools/server-probe/run.sh --scenarios raw-leases,tls --versions 3.0]"),
        listed(file));
  }

  /**
   * With the minimal setup, the interop suite passes when it fails exactly the checks a bare
   * server refuses: Validate at every version, and the draft's credentials at 3.0.
   */
  @Test
  void theMinimalInteropSetupPassesWithOnlyTheExpectedRefusals() throws Exception {
    Path run = work.resolve("interop-minimal");
    String expected = "Validate fails without a trust anchor";
    Map<String, String> outputs =
        Map.of(
            "1.4",
            "keytend-kmip-server 1.4 PASS Locate: ok\n"
                + "keytend-kmip-server 1.4 FAIL Validate certificate: AssertionError\n",
            "2.1",
            "keytend-kmip-server 2.1 PASS Locate: ok\n"
                + "keytend-kmip-server 2.1 FAIL Validate independent CA certificate: x\n"
                + "keytend-kmip-server 2.1 FAIL Locate by name: x\n",
            "3.0",
            "keytend-kmip-server 3.0 PASS Locate: ok\n"
                + "keytend-kmip-server 3.0 FAIL Validate independent CA certificate: x\n"
                + "keytend-kmip-server 3.0 FAIL Login and Logout ticket: x\n"
                + "keytend-kmip-server 3.0 FAIL CreateGroup and Obliterate: x\n"
                + "keytend-kmip-server 3.0 FAIL CreateUser: x\n"
                + "keytend-kmip-server 3.0 FAIL CreateCredential password: x\n",
            "2.0",
            "keytend-kmip-server 2.0 PASS Locate: ok\n");
    StringBuilder log = new StringBuilder();
    for (Map.Entry<String, String> e : outputs.entrySet()) {
      Files.createDirectories(run.resolve("suite/v" + e.getKey()));
      Files.writeString(run.resolve("suite/v" + e.getKey() + "/out.log"), e.getValue());
      log.append("KMIP ").append(e.getKey()).append(" suite exit=1\n");
    }
    Path runLog = Files.writeString(work.resolve("interop-minimal.log"), log.toString());
    Path file = work.resolve("live-server.json");
    PackageReleaseSigningTest.Run r =
        python(
            List.of("interop", file.toString(), runLog.toString()),
            "--setup",
            "minimal",
            "--work",
            run.toString());
    assertEquals(3, r.exit(), r.out());
    String command =
        " [integration/keytend-kmip-server/run-interop.sh --setup minimal --programs"
            + " suite --versions ";
    assertEquals(
        List.of(
            "interop minimal suite 1.4 PASS: exit 1; 1 of 2 checks passed; only the expected"
                + " refusals: "
                + expected
                + command
                + "1.4]",
            "interop minimal suite 2.0 FAIL: exit 1; 1 of 1 checks passed; expected refusals"
                + " missing: Validate independent CA certificate"
                + command
                + "2.0]",
            "interop minimal suite 2.1 FAIL: exit 1; 1 of 3 checks passed; unexpected failures:"
                + " Locate by name"
                + command
                + "2.1]",
            "interop minimal suite 3.0 PASS: exit 1; 1 of 6 checks passed; only the expected"
                + " refusals: "
                + expected
                + "; Login, Create Credential, Create User and Create"
                + " Group are refused without the header credential"
                + command
                + "3.0]"),
        listed(file));
  }

  /**
   * The benchmark's smoke run passes per version when it printed its table of rows and no
   * scenario failed.
   */
  @Test
  void theBenchmarkSmokeRunBecomesEntries() throws Exception {
    Path bench = work.resolve("bench");
    String table =
        "## all rows (live, KMIP %s)\n| scenario | measurement | n |\n|---|---|--:|\n"
            + "| pinned | get | 10 |\n| miss | get | 5 |\n";
    Files.createDirectories(bench.resolve("live-v1.4"));
    Files.writeString(
        bench.resolve("live-v1.4/bench.log"),
        "## pinned   (load 1 1 1)\n## miss   (load 1 1 1)\n" + String.format(table, "1.4"));
    Files.createDirectories(bench.resolve("live-v2.1"));
    Files.writeString(
        bench.resolve("live-v2.1/bench.log"),
        "## pinned   (load 1 1 1)\n## failover   (load 1 1 1)\n"
            + "SCENARIO FAILED: java.io.IOException\n"
            + String.format(table, "2.1"));
    Files.createDirectories(bench.resolve("live-v3.0"));
    Files.writeString(bench.resolve("live-v3.0/bench.log"), "## pinned   (load 1 1 1)\n");
    Path file = work.resolve("live-server.json");
    PackageReleaseSigningTest.Run r =
        python(List.of("bench", file.toString(), bench.toString()), "--scale", "0.05");
    assertEquals(3, r.exit(), r.out());
    String smoke = " at --scale 0.05; a smoke run, its figures are not results";
    String command = " [tools/bench/run.sh --topologies live --versions %s --scale 0.05]";
    assertEquals(
        List.of(
            "bench smoke 1.4 PASS: 2 scenarios, 2 rows" + smoke + String.format(command, "1.4"),
            "bench smoke 2.1 FAIL: 2 scenarios, 2 rows"
                + smoke
                + "; failed: failover"
                + String.format(command, "2.1"),
            "bench smoke 3.0 FAIL: 1 scenarios, 0 rows"
                + smoke
                + "; the run did not finish (no table of rows)"
                + String.format(command, "3.0")),
        listed(file));
  }

  /**
   * The Cassandra trunk dtest becomes one entry per KMIP version, passing when every suite of
   * both runs passed on the pinned image (the one given).
   */
  @Test
  void theCassandraDtestBecomesEntries() throws Exception {
    List<String> trials = new java.util.ArrayList<>();
    for (String leases : List.of("default", "active")) {
      Path trial = Files.createDirectories(work.resolve("tde-" + leases));
      Files.writeString(
          trial.resolve("PROVENANCE.txt"),
          "cassandra=/c head=275a3a5aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"
              + "patch 0001-a.patch applied\n"
              + "server_image=abc id=abc pinned version=keytend-kmip-server 9.9.9 kmip=1.4,2.1"
              + " lease_states="
              + leases
              + "\n");
      Files.writeString(
          trial.resolve("SUMMARY.txt"),
          "org.apache.cassandra.hints.HintsReaderTest exit=0 Tests run: 4, Failures: 0, Errors: 0,"
              + " Skipped: 0\n"
              + "org.apache.cassandra.distributed.test.KmipTdeRotationTest exit="
              + (leases.equals("active") ? "1" : "0")
              + " Tests run: 1, Failures: 0, Errors: 0, Skipped: 0\n  (300 s, KMIP 1.4,2.1)\n");
      trials.add(trial.toString());
    }
    Path file = work.resolve("live-server.json");
    List<String> args = new java.util.ArrayList<>(List.of("cassandra", file.toString()));
    args.addAll(trials);
    PackageReleaseSigningTest.Run r = python(args);
    assertEquals(3, r.exit(), r.out());
    List<String> entries = listed(file);
    assertEquals(2, entries.size(), entries.toString());
    assertTrue(
        entries
            .get(0)
            .startsWith(
                "cassandra-trunk-tde dtest 1.4 FAIL: Apache Cassandra trunk 275a3a5 with the 4"
                    + " patches; a KMS replica and its standby. --lease-states active-deactivated:"
                    + " 1 suites and the dtest (Tests run: 1, Failures: 0, Errors: 0, Skipped: 0);"
                    + " --lease-states active: 1 suites and the dtest (Tests run: 1, Failures: 0,"
                    + " Errors: 0, Skipped: 0), failed KmipTdeRotationTest"),
        entries.get(0));
    assertTrue(
        entries
            .get(0)
            .endsWith(
                "[integration/cassandra-trunk-tde/run-trial.sh, KMIP 1.4, under --lease-states"
                    + " active-deactivated and active]"),
        entries.get(0));
    // A run on another image than the one given is refused, and nothing is written.
    Files.delete(file);
    List<String> other = new java.util.ArrayList<>(args);
    other.addAll(List.of(identity()));
    other.set(other.indexOf("abc"), "def");
    r = python(other.toArray(String[]::new));
    assertNotEquals(0, r.exit(), r.out());
    assertTrue(r.out().contains("ran on image abc (pinned), not def"), r.out());
    assertFalse(Files.exists(file));
  }

  /**
   * The guard over what a release would ship: the recorded live results with the run's over them,
   * every one of the pinned server build; a refusal names the command that runs the check again.
   */
  @Test
  void theGuardRefusesLiveResultsOfAnotherBuild() throws Exception {
    Path recorded = work.resolve("recorded.json");
    Path run = work.resolve("run.json");
    String pinned = pinnedImage();
    setEntryOn(
        recorded,
        "cassandra-trunk-tde dtest",
        "PASS",
        "2026-11-09",
        "recorded",
        pinned,
        "1.4",
        "2.1",
        "3.0");
    setEntryOn(run, "server-probe all", "PASS", "2026-11-10", "release check", pinned, "2.1");
    PackageReleaseSigningTest.Run r =
        python("pinned", recorded.toString(), "--run", run.toString());
    assertEquals(0, r.exit(), r.out());
    assertTrue(r.out().contains("live-server.json: 4 entries, every one of the pinned"), r.out());
    // A failed result is refused, the run's or a recorded one, with the command that runs it
    // again.
    setEntryOn(run, "server-probe all", "FAIL", "2026-11-10", "release check", pinned, "2.1");
    r = python("pinned", recorded.toString(), "--run", run.toString());
    assertEquals(1, r.exit(), r.out());
    assertTrue(
        r.out()
            .contains(
                "server-probe all (KMIP 2.1, release check) is FAIL: a release ships passing"
                    + " results only. Run it again: tools/release-check.sh --server"),
        r.out());
    setEntryOn(run, "server-probe all", "PASS", "2026-11-10", "release check", pinned, "2.1");
    setEntryOn(
        recorded, "cassandra-trunk-tde dtest", "FAIL", "2026-11-09", "recorded", pinned, "3.0");
    r = python("pinned", recorded.toString(), "--run", run.toString());
    assertEquals(1, r.exit(), r.out());
    assertTrue(
        r.out()
            .contains(
                "cassandra-trunk-tde dtest (KMIP 3.0, recorded) is FAIL: a release ships passing"
                    + " results only. Run it again: tools/record-live.sh cassandra-dtest"),
        r.out());
    setEntryOn(
        recorded, "cassandra-trunk-tde dtest", "PASS", "2026-11-09", "recorded", pinned, "3.0");
    // The full repeat is the release check's own now: a recorded one is refused.
    setEntryOn(
        recorded, "server-probe tls-issue-repeat", "PASS", "2026-11-09", "recorded", pinned, "2.1");
    r = python("pinned", recorded.toString(), "--run", run.toString());
    assertEquals(1, r.exit(), r.out());
    assertTrue(
        r.out()
            .contains(
                "server-probe tls-issue-repeat (KMIP 2.1) is recorded, but the release check runs"
                    + " it"),
        r.out());
    Files.writeString(recorded, "{\"entries\": []}\n");
    setEntryOn(
        recorded,
        "cassandra-trunk-tde dtest",
        "PASS",
        "2026-11-09",
        "recorded",
        pinned,
        "1.4",
        "2.1",
        "3.0");
    // The Cassandra dtest of an older build: refused, naming it, its versions, its build and the
    // command that records it again.
    String older = "9".repeat(64);
    setEntryOn(
        recorded,
        "cassandra-trunk-tde dtest",
        "PASS",
        "2026-11-06",
        "recorded",
        older,
        "1.4",
        "3.0");
    r = python("pinned", recorded.toString(), "--run", run.toString());
    assertEquals(1, r.exit(), r.out());
    assertEquals(
        List.of(
            "REFUSED: a release ships live results of the pinned server build only",
            "  live-server.json: cassandra-trunk-tde dtest (KMIP 1.4, 3.0) ran on"
                + " keytend-kmip-server 9.9.9 (image 999999999999), not on the pinned"
                + " keytend-kmip-server "
                + ServerPinTest.pin().getProperty("version")
                + " (image "
                + pinned.substring(0, 12)
                + "). Run it again on the pinned image: tools/record-live.sh cassandra-dtest"
                + " --server <the pinned Docker archive or image> --cassandra ../cassandra-trunk,"
                + " and commit validation/recorded/live-server.json"),
        r.out().lines().toList());
    // An entry without an image, or one that was not the pinned one, is of no known build.
    setEntryOn(
        recorded, "cassandra-trunk-tde dtest", "PASS", "2026-11-09", "recorded", "", "1.4", "3.0");
    r = python("pinned", recorded.toString());
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("(image unknown), not on the pinned"), r.out());
  }

  /**
   * What a release needs of its own release check run (tools/publish-release.sh, and the release
   * check's live-run): a passing result of every live check the run makes with --server, at each
   * KMIP version, on the pinned image. A run without --server has none.
   */
  @Test
  void theRunMustHoldEveryLiveCheckItRuns() throws Exception {
    Path file = work.resolve("live-server.json");
    String pinned = pinnedImage();
    PackageReleaseSigningTest.Run r = python("complete", file.toString());
    assertEquals(1, r.exit(), r.out());
    assertTrue(
        r.out().contains("51 live results the release check runs are not this run's"), r.out());
    r =
        module(
            "tools/release_reports.py",
            String.join(
                "\n",
                "pin = m.read_pin()",
                "m.dump(sys.argv[2], [dict(scope=s, kmip=v, date='2026-11-09', server='s',",
                "    image=pin['image_id'], pinned=True, jdk='17', command='c', result='PASS',",
                "    detail='pass=9 fail=0 info=0 skip=0; tls pass=3 fail=0 info=0 skip=0, '",
                "    f'tls-issue-repeat pass={m.full_repeat_passes()} fail=0 info=3 skip=0',",
                "    source='release check')",
                "    for s, vs in m.RELEASE_CHECK_SCOPES.items() for v in vs])"),
            file.toString());
    assertEquals(0, r.exit(), r.out());
    r = python("complete", file.toString());
    assertEquals(0, r.exit(), r.out());
    assertTrue(r.out().contains("this run passed all 51 live results"), r.out());
    // The probe's all must have passed every check of the full tls-issue-repeat from KMIP 1.4:
    // none run, a part of them (one stop mode's), or one failure is refused.
    int full = PublishReleaseScriptTest.repeatPasses();
    String text = Files.readString(file);
    for (String counts :
        List.of(
            "pass=0 fail=0",
            "pass=" + (full - full / 4) + " fail=0",
            "pass=" + (full - 1) + " fail=1",
            "pass=1 fail=0")) {
      Files.writeString(
          file,
          text.replaceFirst(
              "(\"scope\": \"server-probe all, KMIP_LEASE_STATES=active\",\\s*\"kmip\": \"2\\.1\""
                  + "[^}]*?)tls-issue-repeat pass="
                  + full
                  + " fail=0",
              "$1tls-issue-repeat " + counts));
      r = python("complete", file.toString());
      assertEquals(1, r.exit(), counts + ": " + r.out());
      assertTrue(
          r.out()
              .contains(
                  "server-probe all, KMIP_LEASE_STATES=active 2.1 ("
                      + counts
                      + ", not pass="
                      + full
                      + " fail=0) did not pass the full tls-issue-repeat"),
          r.out());
    }
    Files.writeString(file, text);
    // A failure, a recorded entry in the run's place, and another image are each refused.
    setEntryOn(file, "bench smoke", "FAIL", "2026-11-09", "release check", pinned, "2.1");
    r = python("complete", file.toString());
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("this run failed bench smoke 2.1"), r.out());
    setEntryOn(file, "bench smoke", "PASS", "2026-11-09", "recorded", pinned, "2.1");
    r = python("complete", file.toString());
    assertTrue(r.out().contains("are not this run's (bench smoke 2.1)"), r.out());
    setEntryOn(file, "bench smoke", "PASS", "2026-11-09", "release check", "9".repeat(64), "2.1");
    r = python("complete", file.toString());
    assertTrue(r.out().contains("bench smoke 2.1 ran on another image than the pinned"), r.out());
    // The list is what the release check runs: its probes and the benchmark, and
    // run-interop.sh's programs and versions.
    r =
        module(
            "tools/release_reports.py",
            "for s, vs in m.RELEASE_CHECK_SCOPES.items(): print(s + ': ' + ' '.join(vs))");
    assertEquals(
        List.of(
            "server-probe all: 1.1 1.2 1.4 2.1 3.0",
            "server-probe all, KMIP_DESTROYED_NAME_REUSE=reserve: 1.1 1.2 1.4 2.1 3.0",
            "server-probe all, KMIP_LEASE_STATES=active: 1.1 1.2 1.4 2.1 3.0",
            "server-probe raw-leases,tls, KMIP_MAX_LEASE_SECONDS=0: 1.4 2.1 3.0",
            "interop configured suite: 1.1 1.2 1.3 1.4 2.0 2.1 3.0",
            "interop configured controls: 1.1 1.2 1.3 1.4 2.0 2.1 3.0",
            "interop configured reversal: 2.0 2.1 3.0",
            "interop configured renewal: 2.0 2.1 3.0",
            "interop configured purpose: 2.0 2.1 3.0",
            "interop minimal suite: 1.1 1.2 1.3 1.4 2.0 2.1 3.0",
            "bench smoke: 1.4 2.1 3.0"),
        r.out().lines().toList());
    String check = Files.readString(root().resolve("tools/release-check.sh"));
    for (String spec :
        List.of(
            "all=\"1.1 1.2 1.4 2.1 3.0\"",
            "\"server-probe|all|$all|\"",
            "\"server-probe-name-reuse-reserve|all|$all|KMIP_DESTROYED_NAME_REUSE=reserve\"",
            "\"server-probe-lease-states-active|all|$all|KMIP_LEASE_STATES=active\"",
            "\"server-probe-max-lease-0|raw-leases,tls|1.4 2.1 3.0|KMIP_MAX_LEASE_SECONDS=0\")",
            "for setup in configured minimal; do",
            "--topologies live --versions \"1.4 2.1 3.0\"",
            "release_reports.py\" complete \"$reports/live-server.json\""))
      assertTrue(check.contains(spec), "release-check.sh: " + spec);
    String interop =
        Files.readString(root().resolve("integration/keytend-kmip-server/run-interop.sh"));
    for (String spec :
        List.of(
            "programs=\"suite controls reversal renewal purpose\"",
            "versions=\"1.1 1.2 1.3 1.4 2.0 2.1 3.0\"",
            "if [ \"$setup\" = minimal ]; then programs=suite; fi",
            "case $program in reversal|renewal|purpose) [ \"${version%%.*}\" != 1 ] || continue"))
      assertTrue(interop.contains(spec), "run-interop.sh: " + spec);
  }

  /**
   * A release is made from a full release check run that passed (tools/package-release.py
   * --reports, before it writes or signs anything): release-check.txt with every row a release
   * needs and no argument that leaves out a check, the run's passing live results, and summary.txt
   * of the same commit, passed, with the checks of what was packaged. The release check's own
   * packaging (--in-release-check) runs before those last checks, and is refused once the run has
   * finished.
   */
  @Test
  void aReleaseIsMadeFromAFullRunThatPassed() throws Exception {
    String commit = PublishReleaseScriptTest.COMMIT;
    Path run = work.resolve("run");
    Path reports = Files.createDirectories(run.resolve("validation"));
    Path recorded = Files.writeString(work.resolve("recorded.json"), "{\"entries\": []}\n");
    Files.writeString(
        reports.resolve("release-check.txt"),
        PublishReleaseScriptTest.releaseCheck(PublishReleaseScriptTest.CHECKS_PASSED));
    PackageReleaseSigningTest.Run r =
        module(
            "tools/release_reports.py",
            String.join(
                "\n",
                "pin = m.read_pin()",
                "m.dump(sys.argv[2], [dict(scope=s, kmip=v, date='2026-11-09', server='s',",
                "    image=pin['image_id'], pinned=True, jdk='17', command='c', result='PASS',",
                "    detail=f'pass=9 fail=0 info=0 skip=0; tls-issue-repeat"
                    + " pass={m.full_repeat_passes()} fail=0 info=3 skip=0',",
                "    source='release check')",
                "    for s, vs in m.RELEASE_CHECK_SCOPES.items() for v in vs])"),
            reports.resolve("live-server.json").toString());
    assertEquals(0, r.exit(), r.out());
    for (Map.Entry<String, String> f : PublishReleaseScriptTest.integrationReports().entrySet()) {
      Path file = run.resolve(f.getKey());
      Files.createDirectories(file.getParent());
      Files.writeString(file, f.getValue());
    }
    List<String> all = new java.util.ArrayList<>(PublishReleaseScriptTest.ROWS);
    all.addAll(
        List.of(
            "distribution-a",
            "distribution-b",
            "central-bundle",
            "reproducible",
            "reproducible-javadoc",
            "user-commands"));
    Path summary = run.resolve("summary.txt");
    java.util.function.BiFunction<List<String>, String, String> summaryOf =
        (rows, last) -> {
          String table = PublishReleaseScriptTest.table(commit, "-", rows, "");
          return table.substring(table.indexOf("RESULT"))
              + "commit "
              + commit
              + "; run directory /x; finished now\n"
              + last
              + "\n";
        };
    Files.writeString(summary, summaryOf.apply(all, "RELEASE CHECK PASSED (23 checks)"));
    String[] args = {
      "run",
      reports.toString(),
      "--commit",
      commit,
      "--version",
      "9.9.9",
      "--recorded",
      recorded.toString()
    };
    r = python(args);
    assertEquals(0, r.exit(), r.out());
    // The release check's own packaging is refused once the run has finished.
    String[] during = java.util.Arrays.copyOf(args, args.length + 1);
    during[args.length] = "--in-release-check";
    r = python(during);
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("summary.txt exists: the release check that wrote"), r.out());
    // The summary: missing, failed, of another commit, without a check of what was packaged.
    String passed = Files.readString(summary);
    Files.delete(summary);
    r = python(during);
    assertEquals(0, r.exit(), "while the run has not finished: " + r.out());
    r = python(args);
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("has no summary.txt: the release check did not finish"), r.out());
    List<String> failedReproducible = new java.util.ArrayList<>(all);
    failedReproducible.set(all.indexOf("reproducible"), "FAIL reproducible");
    List<String> noUserCommands = new java.util.ArrayList<>(all);
    noUserCommands.remove("user-commands");
    Map<String, String> summaries =
        Map.of(
            summaryOf.apply(failedReproducible, "RELEASE CHECK FAILED (1 of 23 checks)"),
            "does not say the release check passed: RELEASE CHECK FAILED",
            summaryOf.apply(failedReproducible, "RELEASE CHECK PASSED (23 checks)"),
            "summary.txt: reproducible is FAIL",
            summaryOf.apply(noUserCommands, "RELEASE CHECK PASSED (22 checks)"),
            "summary.txt: no user-commands row",
            passed.replace("commit " + commit + ";", "commit " + "f".repeat(40) + ";"),
            "summary.txt is not of commit " + commit);
    for (Map.Entry<String, String> c : summaries.entrySet()) {
      Files.writeString(summary, c.getKey());
      r = python(args);
      assertEquals(1, r.exit(), r.out());
      assertTrue(r.out().contains(c.getValue()), c.getValue() + " in " + r.out());
    }
    Files.writeString(summary, passed);
    // release-check.txt: failed before packaging; without the live results of the run.
    Path check = reports.resolve("release-check.txt");
    String checks = Files.readString(check);
    Files.writeString(
        check,
        checks.replace(
            PublishReleaseScriptTest.CHECKS_PASSED, "FAILED BEFORE PACKAGING (1 of 17)"));
    r = python(args);
    assertEquals(1, r.exit(), r.out());
    assertTrue(
        r.out().contains("does not say the release checks before packaging passed: FAILED"),
        r.out());
    Files.writeString(check, checks);
    Path live = reports.resolve("live-server.json");
    String results = Files.readString(live);
    Files.delete(live);
    r = python(args);
    assertEquals(1, r.exit(), r.out());
    assertTrue(
        r.out().contains("51 live results the release check runs are not this run's"), r.out());
    Files.writeString(live, results);
    assertEquals(0, python(args).exit());
    // Without --integration, or without its reports: the workflow suite's and the catalog's.
    Files.writeString(check, checks.replace(" --integration", ""));
    r = python(args);
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("the run did not have --integration"), r.out());
    Files.writeString(check, checks);
    Path catalog = reports.resolve("catalog/summary.json");
    String catalogSummary = Files.readString(catalog);
    Files.delete(catalog);
    r = python(args);
    assertEquals(1, r.exit(), r.out());
    assertTrue(
        r.out().contains("no catalog/summary.json: the release check ran without --integration"),
        r.out());
    Files.writeString(
        catalog, catalogSummary.replaceAll("\\{\"jdk\": 25[^}]*}, ?|, \\{\"jdk\": 25[^}]*}", ""));
    r = python(args);
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("catalog/summary.json has no tuples on JDK 25"), r.out());
    Files.writeString(catalog, catalogSummary);
    Files.delete(reports.resolve("workflows/pykmip-1.4-jdk21.json"));
    r = python(args);
    assertEquals(1, r.exit(), r.out());
    assertTrue(
        r.out().contains("no workflows/pykmip-1.4-jdk21.json, which workflows/summary.json names"),
        r.out());
  }

  /**
   * Every form of a local path a report could hold is refused: home, temporary, mount, workspace
   * and build directories, file: URLs, Windows drive paths (as written, and JSON-escaped), JSON
   * strings with escaped slashes, text that is not UTF-8 and a gzip file's text; a gzip file that
   * cannot be read and a JSON file that does not parse are refused too. The scrubbed names, URLs,
   * relative paths and prose are not local paths.
   */
  @Test
  void theGuardFindsLocalPathsInEveryForm() throws Exception {
    String script =
        String.join(
            "\n",
            "import gzip",
            "cases = json.loads(sys.argv[2])",
            "for name, text in cases.items():",
            "    content = text.encode('latin-1')",
            "    if name.endswith('.gz') and not text.startswith('raw:'):",
            "        content = gzip.compress(content, mtime=0)",
            "    print(name, '|', m.report_problems({name: content}, home='/nonexistent/nobody',",
            "                                       user='builder'))");
    Map<String, String> refused = new java.util.LinkedHashMap<>();
    refused.put("a.log", "workspace /var/lib/jenkins/workspace/kt/x\n");
    refused.put("b.log", "/opt/ci/kt/x\n");
    refused.put("c.log", "/srv/ci/x\n");
    refused.put("d.log", "/data/ci/x\n");
    refused.put("e.log", "/scratch/ci/x\n");
    refused.put("f.log", "/workspace/kt/x\n");
    refused.put("g.log", "java /nix/store/abc-jdk/bin/java\n");
    refused.put("h.log", "file:///usr/share/report.html\n");
    refused.put("i.log", "C:\\Users\\builder\\jdk\n");
    refused.put("j.json", "{\"java\": \"C:\\\\Users\\\\builder\\\\jdk\"}\n");
    refused.put("k.json", "{\"dir\": \"\\/opt\\/ci\\/x\"}\n");
    refused.put("l.json", "{\"dir\": \"\\u002fsrv\\u002fci\"}\n");
    refused.put("m.log", "caf\u00e9 in /tmp/x\n");
    refused.put("n.log.gz", "caf\u00e9 in /tmp/x\n");
    refused.put("o.log.gz", "raw:not gzip");
    refused.put("p.json", "{not json");
    refused.put("q.log", "C:/Users/builder/jdk\n");
    PackageReleaseSigningTest.Run r = module("tools/release_reports.py", script, json(refused));
    assertEquals(0, r.exit(), r.out());
    for (String line : r.out().lines().toList())
      assertFalse(line.endsWith("| []"), "refused: " + line);
    assertEquals(refused.size(), r.out().lines().count(), r.out());
    assertTrue(r.out().contains("o.log.gz: not a readable gzip file"), r.out());
    assertTrue(r.out().contains("p.json | ['p.json: not JSON"), r.out());
    Map<String, String> accepted = new java.util.LinkedHashMap<>();
    accepted.put(
        "a.log", "<run directory>/tree-a/sdk.jar ~/x <checkout>/sdk https://example.org/srv/x\n");
    accepted.put("b.log", "kmip/services/server/policy.py; protocol/build; 1.4/os/kmip-spec\n");
    accepted.put("c.json", "{\"url\": \"https://docs.oasis-open.org/kmip/spec/v1.4/\"}\n");
    accepted.put("d.log.gz", "Self-signed root validation\n");
    r = module("tools/release_reports.py", script, json(accepted));
    assertEquals(0, r.exit(), r.out());
    for (String line : r.out().lines().toList())
      assertTrue(line.endsWith("| []"), "accepted: " + line);
  }

  /**
   * The user name counts where it identifies a machine's user (a segment of an absolute path, ~USER,
   * USER@HOST, a user or owner field), not as a word: the minimal interop setup's real logs say
   * "Self-signed root validation", which the guard accepts under the user root and under other
   * common words, and refuses once a path or identity field names that user.
   */
  @Test
  void aUserNameCountsOnlyInPathsAndIdentityFields() throws Exception {
    Path logs = root().resolve("sdk/src/test/resources/release-reports/interop-minimal");
    String script =
        String.join(
            "\n",
            "logs = pathlib.Path(sys.argv[2])",
            "files = {'interop-minimal/' + p.name: p.read_bytes() for p in sorted(logs.iterdir())}",
            "assert any(b'Self-signed root validation' in c for c in files.values()), 'the real logs'",
            "for user in sys.argv[3:]:",
            "    print(user, 'alone', m.report_problems(files, home='/nonexistent/nobody', user=user))",
            "    for extra in (f'/srv2/{user}/x', f'{{\"user\": \"{user}\"}}',",
            "                  f'user.name={user}', f'{user}@buildhost', f'cd ~{user}/x',",
            "                  f'D:\\\\ci\\\\{user}\\\\x'):",
            "        named = dict(files)",
            "        named['interop-minimal/suite-v2.1.log'] += ('\\n' + extra + '\\n').encode()",
            "        print(user, 'with', extra,",
            "              m.report_problems(named, home='/nonexistent/nobody', user=user))");
    PackageReleaseSigningTest.Run r =
        module(
            "tools/release_reports.py",
            script,
            logs.toString(),
            "root",
            "server",
            "key",
            "test",
            "admin",
            "build");
    assertEquals(0, r.exit(), r.out());
    List<String> lines = r.out().lines().toList();
    assertEquals(6 * 7, lines.size(), r.out());
    for (String line : lines) {
      String[] f = line.split(" ", 3);
      if (f[1].equals("alone")) assertEquals(f[0] + " alone []", line, "the logs alone pass");
      else
        assertTrue(
            line.contains("['interop-minimal/suite-v2.1.log: ")
                && line.contains("the user name " + f[0])
                && !line.contains("suite-v2.0.log")
                && !line.contains("suite-v3.0.log"),
            "only the line naming the user is refused: " + line);
    }
  }

  /** The JSON object of {@code map}'s strings. */
  static String json(Map<String, String> map) {
    StringBuilder out = new StringBuilder("{");
    for (Map.Entry<String, String> e : map.entrySet()) {
      if (out.length() > 1) out.append(", ");
      out.append(quote(e.getKey())).append(": ").append(quote(e.getValue()));
    }
    return out.append('}').toString();
  }

  static String quote(String s) {
    StringBuilder out = new StringBuilder("\"");
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      if (c == '"' || c == '\\') out.append('\\').append(c);
      else if (c == '\n') out.append("\\n");
      else if (c < 0x20 || c > 0x7e) out.append(String.format("\\u%04x", (int) c));
      else out.append(c);
    }
    return out.append('"').toString();
  }

  /**
   * The full tls-issue-repeat's count is derived from the probe's source: one check per issue
   * operation, way of stopping and check of each.
   */
  @Test
  void theFullRepeatCountComesFromTheProbe() throws Exception {
    Path source = work.resolve("ServerProbe.java");
    Files.writeString(
        source,
        String.join(
            "\n",
            "class ServerProbe {",
            "  enum IssueOp {",
            "    ISSUE(\"issue\"),",
            "    REISSUE(\"reissue\");",
            "    final String step;",
            "  }",
            "  enum StopMode {",
            "    DEAD_BEFORE(\"dead-before\", true, false),",
            "    DEAD_AFTER(\"dead-after\", true, true),",
            "    DROP_BEFORE(\"drop-before\", false, false);",
            "  }",
            "  private static void repeatEach(String scenario) throws Exception {",
            "    String step = scenario;",
            "    check(step, true, \"a\");",
            "    check(step + \".follower\", true, \"b\");",
            "  }",
            "  static void other() {",
            "    check(step + \".leftovers\", true, \"c\");",
            "  }",
            "}",
            ""));
    PackageReleaseSigningTest.Run r =
        module(
            "tools/release_reports.py",
            "print(m.full_repeat_passes(sys.argv[2]), m.full_repeat_passes())",
            source.toString());
    assertEquals(0, r.exit(), r.out());
    String[] counts = r.out().strip().split(" ");
    assertEquals("12", counts[0], "2 operations, 3 ways, 2 checks: " + r.out());
    // The probe's own: three operations, four ways of stopping, three checks of each.
    assertEquals("36", counts[1], r.out());
  }

  /**
   * The reports are written with the run directory's, the checkout's and the home directory's
   * paths named, in text files and in the text of gzip files, which are written without a time
   * (the same text gives the same bytes); other files are copied unchanged.
   */
  @Test
  void theReportsAreScrubbedOfLocalPaths() throws Exception {
    Path source = Files.createDirectories(work.resolve("catalog/results"));
    String run = "/tmp/keytend-kmip-release-check.20261109T000000";
    Files.writeString(work.resolve("catalog/summary.json"), "{\"dir\": \"" + run + "/x\"}\n");
    java.io.ByteArrayOutputStream gz = new java.io.ByteArrayOutputStream();
    try (java.util.zip.GZIPOutputStream out = new java.util.zip.GZIPOutputStream(gz)) {
      out.write(
          "{\"tree\": \"/src/checkout/sdk\", \"home\": \"/srv/u/.m2\"}\n"
              .getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }
    Files.write(source.resolve("r.json.gz"), gz.toByteArray());
    Files.write(source.resolve("blob.bin"), new byte[] {(byte) 0xff, 0, (byte) 0xfe});
    for (String dest : List.of("a", "b")) {
      PackageReleaseSigningTest.Run r =
          python(
              "scrub",
              work.resolve("catalog").toString(),
              work.resolve(dest).toString(),
              "--replace",
              run + "=<run directory>",
              "--replace",
              "/src/checkout=<checkout>",
              "--replace",
              "/srv/u=~");
      assertEquals(0, r.exit(), r.out());
    }
    assertEquals(
        "{\"dir\": \"<run directory>/x\"}\n", Files.readString(work.resolve("a/summary.json")));
    byte[] scrubbed = Files.readAllBytes(work.resolve("a/results/r.json.gz"));
    assertArrayEquals(scrubbed, Files.readAllBytes(work.resolve("b/results/r.json.gz")));
    try (java.util.zip.GZIPInputStream in =
        new java.util.zip.GZIPInputStream(new java.io.ByteArrayInputStream(scrubbed))) {
      assertEquals(
          "{\"tree\": \"<checkout>/sdk\", \"home\": \"~/.m2\"}\n",
          new String(in.readAllBytes(), java.nio.charset.StandardCharsets.UTF_8));
    }
    assertArrayEquals(
        Files.readAllBytes(source.resolve("blob.bin")),
        Files.readAllBytes(work.resolve("a/results/blob.bin")));
    // The release check scrubs every report it writes: the logs, the summaries and the scan.
    String check = Files.readString(root().resolve("tools/release-check.sh"));
    for (String scrub :
        List.of(
            "scrub \"$out/workflows\" \"$reports/workflows\" && scrub \"$out/catalog\" \"$reports/catalog\"",
            "scrub \"$out/osv-scanner.txt\" \"$reports/osv-scanner.txt\"",
            "scrub \"$out/release-check.txt\" \"$reports/release-check.txt\""))
      assertTrue(check.contains(scrub), "release-check.sh: " + scrub);
    assertFalse(check.contains(">\"$reports/osv-scanner.txt\""), "the scan is written scrubbed");
  }

  /** No test results are committed under docs/: they are generated into the release's ZIP. */
  @Test
  void theDocsHoldNoResults() {
    for (String gone : List.of("docs/validation", "docs/catalog"))
      assertFalse(Files.exists(root().resolve(gone)), gone);
  }

  /** A new result replaces the entry of its check and version; nothing is appended. */
  @Test
  void aNewResultReplacesItsEntryAndNothingIsAppended() throws Exception {
    Path file = work.resolve("live-server.json");
    assertEquals(
        0,
        setEntry(file, "server-probe all", "PASS", "2026-11-01", "recorded", "1.4", "2.1").exit());
    assertEquals(
        0,
        setEntry(file, "interop configured suite", "PASS", "2026-11-01", "recorded", "3.0").exit());
    PackageReleaseSigningTest.Run r =
        setEntry(file, "server-probe all", "FAIL", "2026-11-09", "recorded", "2.1");
    assertEquals(0, r.exit(), r.out());
    String json = Files.readString(file);
    PackageReleaseSigningTest.Run listed =
        module(
            "tools/release_reports.py",
            "print('\\n'.join(e['scope'] + ' ' + e['kmip'] + ' ' + e['result'] + ' ' + e['date']"
                + " for e in m.load(sys.argv[2])))",
            file.toString());
    assertEquals(
        List.of(
            "interop configured suite 3.0 PASS 2026-11-01",
            "server-probe all 1.4 PASS 2026-11-01",
            "server-probe all 2.1 FAIL 2026-11-09"),
        listed.out().lines().toList(),
        json);
    // The run's entries over the recorded ones: the run's replace, the rest stay, with their
    // source.
    Path run = work.resolve("run.json");
    assertEquals(
        0, setEntry(run, "server-probe all", "PASS", "2026-11-10", "release check", "2.1").exit());
    Path merged = work.resolve("merged.json");
    assertEquals(0, python("merge", file.toString(), run.toString(), merged.toString()).exit());
    PackageReleaseSigningTest.Run out =
        module(
            "tools/release_reports.py",
            "print('\\n'.join(e['scope'] + ' ' + e['kmip'] + ' ' + e['result'] + ' ' + e['source']"
                + " for e in m.load(sys.argv[2])))",
            merged.toString());
    assertEquals(
        List.of(
            "interop configured suite 3.0 PASS recorded",
            "server-probe all 1.4 PASS recorded",
            "server-probe all 2.1 PASS release check"),
        out.out().lines().toList());
    // An entry without a date, or with a result that is neither PASS nor FAIL, is refused.
    assertNotEquals(
        0, setEntry(file, "server-probe all", "PASS", "yesterday", "recorded", "1.4").exit());
    Files.writeString(
        run, Files.readString(run).replace("\"result\": \"PASS\"", "\"result\": \"PASSED\""));
    assertNotEquals(0, python("merge", file.toString(), run.toString(), merged.toString()).exit());
  }

  /** The server probe's logs and the interop suite's output become one entry per version. */
  @Test
  void theProbeAndTheInteropSuiteBecomeEntries() throws Exception {
    Path probe = work.resolve("probe");
    Files.createDirectories(probe.resolve("v1.4"));
    Files.createDirectories(probe.resolve("v2.1"));
    Files.writeString(
        probe.resolve("v1.4/probe.log"),
        String.join(
            "\n",
            "---- [1.4] tls",
            "PASS [1.4] tls.renew: ok",
            "INFO [1.4] tls.answer: recorded",
            "---- [1.4] names",
            "PASS [1.4] names.add: ok",
            "SUMMARY [1.4] pass=2 fail=0 info=1 skip=0",
            ""));
    Files.writeString(
        probe.resolve("v2.1/probe.log"),
        "---- [2.1] tls\nFAIL [2.1] tls.renew: no\nSUMMARY [2.1] pass=0 fail=1 info=0 skip=0\n");
    Path file = work.resolve("live-server.json");
    String[] identity = {
      "--server",
      "keytend-kmip-server 9.9.9",
      "--image",
      "abc",
      "--jdk",
      "17",
      "--date",
      "2026-11-09"
    };
    String[] probeArgs = new String[4 + identity.length];
    probeArgs[0] = "probe";
    probeArgs[1] = file.toString();
    probeArgs[2] = probe.toString();
    probeArgs[3] = "--scenarios=all";
    System.arraycopy(identity, 0, probeArgs, 4, identity.length);
    PackageReleaseSigningTest.Run r = python(probeArgs);
    // 3: the entries are written, and one is FAIL.
    assertEquals(3, r.exit(), r.out());
    assertTrue(r.out().contains("FAIL server-probe all 2.1: pass=0 fail=1"), r.out());
    Path interop = work.resolve("interop.log");
    Files.writeString(
        interop,
        "KMIP 2.1 suite exit=0\nKMIP 2.1 purpose exit=0 (15 of 15 shapes agree)\nKMIP 3.0 suite exit=1\n");
    String[] interopArgs = new String[3 + identity.length];
    interopArgs[0] = "interop";
    interopArgs[1] = file.toString();
    interopArgs[2] = interop.toString();
    System.arraycopy(identity, 0, interopArgs, 3, identity.length);
    r = python(interopArgs);
    assertEquals(3, r.exit(), r.out());
    PackageReleaseSigningTest.Run listed =
        module(
            "tools/release_reports.py",
            "print('\\n'.join(e['scope'] + ' ' + e['kmip'] + ' ' + e['result'] + ': ' + e['detail']"
                + " + ' (' + e['source'] + ')' for e in m.load(sys.argv[2])))",
            file.toString());
    assertEquals(
        List.of(
            "interop configured purpose 2.1 PASS: exit 0, 15 of 15 shapes agree (release check)",
            "interop configured suite 2.1 PASS: exit 0 (release check)",
            "interop configured suite 3.0 FAIL: exit 1 (release check)",
            "server-probe all 1.4 PASS: pass=2 fail=0 info=1 skip=0; tls pass=1 fail=0 info=1 skip=0,"
                + " names pass=1 fail=0 info=0 skip=0 (release check)",
            "server-probe all 2.1 FAIL: pass=0 fail=1 info=0 skip=0; tls pass=0 fail=1 info=0 skip=0"
                + " (release check)"),
        listed.out().lines().toList());
  }

  /**
   * The JUnit totals come from the release check's report copies, per module and kind; a failed
   * suite is refused.
   */
  @Test
  void theTestTotalsComeFromTheReportCopies() throws Exception {
    Path reports = work.resolve("surefire-jdk17");
    Files.createDirectories(reports.resolve("sdk-surefire-reports"));
    Files.createDirectories(reports.resolve("integration-tests-failsafe-reports"));
    Files.writeString(
        reports.resolve("sdk-surefire-reports/TEST-a.A.xml"),
        "<testsuite name=\"a.A\" tests=\"3\" failures=\"0\" errors=\"0\" skipped=\"1\"/>");
    Files.writeString(
        reports.resolve("sdk-surefire-reports/TEST-a.B.xml"),
        "<testsuite name=\"a.B\" tests=\"2\" failures=\"0\" errors=\"0\" skipped=\"0\"/>");
    Files.writeString(
        reports.resolve("integration-tests-failsafe-reports/TEST-b.IT.xml"),
        "<testsuite name=\"b.IT\" tests=\"4\" failures=\"0\" errors=\"0\" skipped=\"0\"/>");
    String script = "print(json.dumps(m.junit_runs(None, ['17=' + sys.argv[2]]), sort_keys=True))";
    PackageReleaseSigningTest.Run r =
        module("tools/release_reports.py", script, reports.toString());
    assertEquals(0, r.exit(), r.out());
    assertEquals("{\"17\": {\"integration-tests\": [[4, 0]], \"sdk\": [[5, 1]]}}", r.out().strip());
    Files.writeString(
        reports.resolve("sdk-surefire-reports/TEST-a.B.xml"),
        "<testsuite name=\"a.B\" tests=\"2\" failures=\"1\" errors=\"0\" skipped=\"0\"/>");
    r = module("tools/release_reports.py", script, reports.toString());
    assertNotEquals(0, r.exit(), r.out());
  }

  /**
   * The packaging takes a release check's reports of the commit it packages only; recorded
   * evidence comes from the committed tree; live-server.json is the recorded entries with the
   * run's over them, each of the pinned server build.
   */
  @Test
  void thePackagingTakesTheReportsOfItsCommitAndMergesTheLiveResults() throws Exception {
    String commit = "0123456789abcdef0123456789abcdef01234567";
    Path reports = work.resolve("validation");
    Files.createDirectories(reports.resolve("workflows"));
    Files.writeString(reports.resolve("workflows/summary.json"), "{}\n");
    Files.writeString(
        reports.resolve("release-check.txt"),
        "keytend-kmip release check, before packaging\ncommit "
            + commit
            + "\n\n"
            + PublishReleaseScriptTest.CHECKS_PASSED
            + "\n");
    assertEquals(
        0,
        setEntryOn(
                reports.resolve("live-server.json"),
                "server-probe all",
                "PASS",
                "2026-11-10",
                "release check",
                pinnedImage(),
                "2.1")
            .exit());
    // The recorded live results, on the pinned image: the Cassandra dtest.
    Path recorded = work.resolve("recorded.json");
    String pinned = pinnedImage();
    setEntryOn(
        recorded,
        "cassandra-trunk-tde dtest",
        "PASS",
        "2026-11-09",
        "recorded",
        pinned,
        "1.4",
        "2.1",
        "3.0");
    // The source ZIP's entries, as package-release.py reads them: here, the committed recorded
    // files, with live-server.json the one given (sys.argv[5]).
    String script =
        String.join(
            "\n",
            "root = pathlib.Path(sys.argv[2])",
            "source = {p.relative_to(root).as_posix(): (p.read_bytes(), 0)",
            "          for p in (root / 'validation/recorded').rglob('*') if p.is_file()}",
            "source['validation/recorded/live-server.json'] = ("
                + "pathlib.Path(sys.argv[5]).read_bytes(), 0)",
            "out = m.validation_entries(source, pathlib.Path(sys.argv[3]), sys.argv[4])",
            "for path in sorted(out):",
            "    if not path.startswith('validation/recorded/'): print(path)",
            "print(len([p for p in out if p.startswith('validation/recorded/')]) == len(source))",
            "live = json.loads(out['validation/live-server.json'])['entries']",
            "dtest = [e for e in live if e['scope'] == 'cassandra-trunk-tde dtest']",
            "print(sorted((e['kmip'], e['source']) for e in dtest))");
    String root = root().toString();
    PackageReleaseSigningTest.Run r =
        module(
            "tools/package-release.py",
            script,
            root,
            reports.toString(),
            commit,
            recorded.toString());
    assertEquals(0, r.exit(), r.out());
    assertEquals(
        List.of(
            "validation/live-server.json",
            "validation/release-check.txt",
            "validation/workflows/summary.json",
            "True",
            "[('1.4', 'recorded'), ('2.1', 'recorded'), ('3.0', 'recorded')]"),
        r.out().lines().toList());
    // A recorded result of another server build is refused, with the command that records it
    // again on the pinned image.
    String older = "9".repeat(64);
    setEntryOn(
        recorded,
        "cassandra-trunk-tde dtest",
        "PASS",
        "2026-11-06",
        "recorded",
        older,
        "1.4",
        "2.1",
        "3.0");
    r =
        module(
            "tools/package-release.py",
            script,
            root,
            reports.toString(),
            commit,
            recorded.toString());
    assertNotEquals(0, r.exit(), r.out());
    assertTrue(
        r.out().contains("REFUSED: a release ships live results of the pinned server build only"),
        r.out());
    assertTrue(
        r.out()
            .contains(
                "cassandra-trunk-tde dtest (KMIP 1.4, 2.1, 3.0) ran on keytend-kmip-server"
                    + " 9.9.9 (image 999999999999), not on the pinned"),
        r.out());
    assertTrue(
        r.out()
            .contains(
                "tools/record-live.sh cassandra-dtest --server <the pinned Docker archive"
                    + " or image> --cassandra ../cassandra-trunk"),
        r.out());
    setEntryOn(
        recorded,
        "cassandra-trunk-tde dtest",
        "PASS",
        "2026-11-09",
        "recorded",
        pinned,
        "1.4",
        "2.1",
        "3.0");
    // The reports hold no test output and no local path, gzip files included.
    String home = System.getProperty("user.home");
    Map<String, String> bad = new java.util.LinkedHashMap<>();
    bad.put("surefire-jdk25/sdk-surefire-reports/TEST-x.xml", "<testsuite/>\n");
    bad.put("server-probe/v2.1.log", "SDK from " + home + "/sdk.jar\n");
    bad.put("interop/run.log", "work /tmp/keytend-kmip-release-check.20261109/interop\n");
    bad.put("catalog/results/x.json.gz", "{\"report\": \"/Users/someone/x\"}\n");
    for (Map.Entry<String, String> c : bad.entrySet()) {
      Path file = reports.resolve(c.getKey());
      Files.createDirectories(file.getParent());
      byte[] content = c.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8);
      if (c.getKey().endsWith(".gz")) {
        java.io.ByteArrayOutputStream gz = new java.io.ByteArrayOutputStream();
        try (java.util.zip.GZIPOutputStream out = new java.util.zip.GZIPOutputStream(gz)) {
          out.write(content);
        }
        content = gz.toByteArray();
      }
      Files.write(file, content);
      r =
          module(
              "tools/package-release.py",
              script,
              root,
              reports.toString(),
              commit,
              recorded.toString());
      assertNotEquals(0, r.exit(), c.getKey() + ": " + r.out());
      assertTrue(
          r.out().contains("holds what a release does not ship (test output or a local path"),
          r.out());
      assertTrue(r.out().contains("  " + c.getKey() + ": "), r.out());
      Files.delete(file);
    }
    PackageReleaseSigningTest.Run clean =
        module(
            "tools/package-release.py",
            script,
            root,
            reports.toString(),
            commit,
            recorded.toString());
    assertEquals(0, clean.exit(), clean.out());
    // A recorded result of a check the release check runs is refused, whatever its build.
    setEntryOn(
        recorded,
        "server-probe all, KMIP_LEASE_STATES=active",
        "PASS",
        "2026-11-09",
        "recorded",
        pinned,
        "2.1");
    r =
        module(
            "tools/package-release.py",
            script,
            root,
            reports.toString(),
            commit,
            recorded.toString());
    assertNotEquals(0, r.exit(), r.out());
    assertTrue(
        r.out()
            .contains(
                "server-probe all, KMIP_LEASE_STATES=active (KMIP 2.1) is recorded, but the"
                    + " release check runs it: remove it from"
                    + " validation/recorded/live-server.json and run"
                    + " tools/release-check.sh --server <the pinned Docker archive or image>"),
        r.out());
    // A result of the run on another build is refused too (--server-unpinned).
    Files.writeString(recorded, "{\"entries\": []}\n");
    Files.delete(reports.resolve("live-server.json"));
    setEntryOn(
        reports.resolve("live-server.json"),
        "server-probe all",
        "PASS",
        "2026-11-10",
        "release check",
        older,
        "2.1");
    r =
        module(
            "tools/package-release.py",
            script,
            root,
            reports.toString(),
            commit,
            recorded.toString());
    assertNotEquals(0, r.exit(), r.out());
    assertTrue(
        r.out()
            .contains(
                "server-probe all (KMIP 2.1) ran on keytend-kmip-server 9.9.9 (image"
                    + " 999999999999), not on the pinned"),
        r.out());
    assertTrue(
        r.out().contains("Run it again on the pinned image: tools/release-check.sh --server"),
        r.out());
    // Reports of another commit are refused.
    r =
        module(
            "tools/package-release.py",
            script,
            root,
            reports.toString(),
            "f".repeat(40),
            recorded.toString());
    assertNotEquals(0, r.exit(), r.out());
    assertTrue(r.out().contains("is of commit ['" + commit + "'], not of HEAD"), r.out());
    // Reports that carry their own recorded evidence are refused.
    Files.createDirectories(reports.resolve("recorded"));
    Files.writeString(reports.resolve("recorded/index.json"), "{}\n");
    r =
        module(
            "tools/package-release.py",
            script,
            root,
            reports.toString(),
            commit,
            recorded.toString());
    assertNotEquals(0, r.exit(), r.out());
    assertTrue(r.out().contains("recorded evidence comes from the committed"), r.out());
  }
}
