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
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * The keytend-kmip-server build every live tool runs, and the release gate's probe is pinned to,
 * is pinned once, in {@code tools/kmip-server/pinned-image.properties}: {@code
 * tools/kmip-server/run-server.sh} reads it and refuses another image, {@code
 * tools/release-check.sh} fails the probe check for one, no other tool names the image, and {@code
 * docs/releasing.md} names the same build.
 */
class ServerPinTest {
  static final String PIN = "tools/kmip-server/pinned-image.properties";

  static Properties pin() throws IOException {
    Properties p = new Properties();
    p.load(new StringReader(ApiBaselinePinTest.read(PIN)));
    return p;
  }

  @Test
  void thePinNamesOneReleasedImage() throws IOException {
    Properties p = pin();
    assertEquals("keytend-kmip-server", p.getProperty("name"));
    String version = p.getProperty("version");
    assertNotNull(version, "version");
    assertEquals("v" + version, p.getProperty("tag"), "the tag is the version's");
    for (String hash : List.of("archive_sha256", "image_id", "release_asset_sha256"))
      assertTrue(p.getProperty(hash, "").matches("[0-9a-f]{64}"), "a lower-case SHA-256: " + hash);
    for (String commit : List.of("tag_commit", "source_commit"))
      assertTrue(p.getProperty(commit, "").matches("[0-9a-f]{40}"), "a commit: " + commit);
    // The image is built from the tagged commit (its image.json's source_commit).
    assertEquals(
        p.getProperty("tag_commit"),
        p.getProperty("source_commit"),
        "the image's source commit is the tag's");
    assertEquals(
        "keytend-kmip-server-" + version + "-signed-release.tar",
        p.getProperty("release_asset"),
        "the release asset is the version's");
    assertTrue(
        p.getProperty("archive", "").endsWith(version + ".docker.tar"),
        "the archive is the version's");
    assertTrue(
        p.getProperty("image", "").startsWith("localhost/keytend-kmip-server:"),
        "the image's local tag");
  }

  @Test
  void theHelperAndTheGateReadThePinAndTheProcedureNamesIt() throws IOException {
    Properties p = pin();
    String helper = ApiBaselinePinTest.read("tools/kmip-server/run-server.sh");
    assertTrue(helper.contains("pin=$here/pinned-image.properties"), "run-server.sh reads the pin");
    assertTrue(helper.contains("[ \"$id\" != \"$want\" ]"), "run-server.sh compares the image ID");
    assertTrue(
        helper.contains("[ \"$sha\" != \"$want_sha\" ]"),
        "run-server.sh compares the archive's SHA-256");
    String check = ApiBaselinePinTest.read("tools/release-check.sh");
    assertTrue(
        check.contains("pin=\"$check_tree/tools/kmip-server/pinned-image.properties\""),
        "release-check.sh reads the pin");
    assertTrue(
        check.contains("helper=\"$check_tree/tools/kmip-server/run-server.sh\""),
        "release-check.sh verifies through the helper");
    assertTrue(
        check.contains(
            "if $server_unpinned && [ \"$result\" = PASS ]; then result=UNPIN; else result=FAIL; fi"),
        "another build never passes the probe check");
    assertTrue(
        check.contains(
            "[ \"${results[$i]}\" = PASS ] || [ \"${results[$i]}\" = SKIP ] || failed=$((failed + 1))"),
        "only PASS, or SKIP, counts as a pass");
    // SKIP is recorded once only: the API baseline while sdk/pom.xml pins none (UNPIN never
    // passes).
    assertEquals(1, check.split("record SKIP ", -1).length - 1, "one SKIP");
    assertTrue(
        check.contains("[ $? -eq 3 ] && record SKIP api-baseline "),
        "SKIP only for an unpinned API baseline");
    String releasing = ApiBaselinePinTest.read("docs/releasing.md");
    assertTrue(
        releasing.contains("keytend-kmip-server **" + p.getProperty("version") + "**"),
        "docs/releasing.md names the version");
    for (String key :
        List.of(
            "tag",
            "tag_commit",
            "release_asset",
            "release_asset_sha256",
            "archive_sha256",
            "image_id",
            "image"))
      assertTrue(
          releasing.contains("`" + p.getProperty(key) + "`"), "docs/releasing.md names the " + key);
    assertTrue(releasing.contains(PIN), "docs/releasing.md names the file");
  }

  /**
   * The release check runs every live check it can against the pinned image: the probe under the
   * server's defaults and under each other setting it accepts, the interop suite with both
   * setups, and the benchmark's smoke run. Each is PASS, FAIL or UNPIN, never SKIP (the one SKIP
   * is the API baseline's), and a live result of another build than the pin's is refused before
   * packaging, by the packaging and by the publish script.
   */
  @Test
  void theReleaseCheckRunsEveryLiveCheckOnThePinAndShipsNoOtherBuild() throws IOException {
    String check = ApiBaselinePinTest.read("tools/release-check.sh");
    for (String run :
        List.of(
            "\"server-probe|all|$all|\"",
            "\"server-probe-name-reuse-reserve|all|$all|KMIP_DESTROYED_NAME_REUSE=reserve\"",
            "\"server-probe-lease-states-active|all|$all|KMIP_LEASE_STATES=active\"",
            "\"server-probe-max-lease-0|raw-leases,tls|1.4 2.1 3.0|KMIP_MAX_LEASE_SECONDS=0\"",
            "for setup in configured minimal; do",
            "--topologies live --versions \"1.4 2.1 3.0\" --scale \"$scale\""))
      assertTrue(check.contains(run), "release-check.sh runs " + run);
    // Every live check reports through live(), which never passes another build.
    for (String name : List.of("live \"$name\" \"$result\"", "live bench-smoke \"$result\""))
      assertTrue(check.contains(name), "release-check.sh reports " + name + " through live()");
    assertFalse(check.contains("live SKIP") || check.contains("result=SKIP"), "no live SKIP");
    // The full tls-issue-repeat is in the probe's all; nothing runs it apart, or records it.
    assertFalse(check.contains("server-full-repeat"), "no --server-full-repeat");
    assertFalse(
        ApiBaselinePinTest.read("tools/record-live.sh").contains("full-repeat"),
        "record-live.sh records the Cassandra dtest only");
    String probe = ApiBaselinePinTest.read("tools/server-probe/ServerProbe.java");
    assertTrue(
        probe.contains("scenarios.put(\"tls-issue-repeat\", ServerProbe::tlsIssueRepeat);"),
        "the probe has the full repeat");
    assertTrue(probe.contains("all ? List.copyOf(scenarios.keySet())"), "all runs every scenario");
    assertFalse(probe.contains("repeat-quick"), "no quick repeat");
    assertEquals(1, check.split("record SKIP ", -1).length - 1, "one SKIP");
    assertTrue(
        check.contains(
            "release_reports.py\" pinned \\\n"
                + "  \"$check_tree/validation/recorded/live-server.json\" --run"
                + " \"$reports/live-server.json\""),
        "release-check.sh checks what would ship against the pin");
    String reports = ApiBaselinePinTest.read("tools/release_reports.py");
    assertTrue(
        reports.contains("PIN = ROOT / 'tools' / 'kmip-server' / 'pinned-image.properties'"),
        "release_reports.py reads the pin");
    assertTrue(reports.contains("RESULTS = ('PASS', 'FAIL')"), "a live result is PASS or FAIL");
    assertTrue(
        ApiBaselinePinTest.read("tools/package-release.py")
            .contains("release_reports.check_pinned(live, release_reports.read_pin(),"),
        "package-release.py refuses another build");
    assertTrue(
        ApiBaselinePinTest.read("tools/publish-release.sh")
            .contains("release_reports.pin_problems(release_reports.parse(live, where),"),
        "publish-release.sh refuses another build");
    assertTrue(
        ApiBaselinePinTest.read("tools/record-live.sh")
            .contains("image=$(KEYTEND_SERVER_UNPINNED=0 \"$helper\" image \"$server\")"),
        "record-live.sh records on the pinned image only");
  }

  /** No script or program names the image itself: each goes through run-server.sh and its pin. */
  @Test
  void onlyThePinNamesTheImage() throws IOException {
    Properties p = pin();
    List<String> pinned =
        List.of(
            p.getProperty("image_id"),
            p.getProperty("archive_sha256"),
            p.getProperty("image"),
            p.getProperty("image_id").substring(0, 12));
    Path root = LicenseHeadersTest.root();
    List<String> offenders = new ArrayList<>();
    for (String top : List.of("tools", "integration", "integration-tests/src", "sdk/src")) {
      try (Stream<Path> files = Files.walk(root.resolve(top))) {
        for (Path f : (Iterable<Path>) files::iterator) {
          String rel = root.relativize(f).toString().replace('\\', '/');
          if (!Files.isRegularFile(f) || rel.contains("/target/") || rel.contains("__pycache__"))
            continue;
          if (!rel.matches(".*\\.(sh|py|java)$")
              || rel.equals("tools/kmip-server/run-server.sh")
              || rel.endsWith("/ServerPinTest.java")) continue;
          String text = Files.readString(f);
          for (String s : pinned) if (text.contains(s)) offenders.add(rel + " names " + s);
        }
      }
    }
    assertEquals(
        List.of(),
        offenders,
        "tools name the server image only through tools/kmip-server/run-server.sh");
  }
}
