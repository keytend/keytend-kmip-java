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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@code tools/package-release.py}'s signing: by the release key's signing subkey, from a GnuPG home
 * of its own that holds only that subkey's secret (the primary a stub), with the passphrase in a
 * file gpg reads itself. {@code --check-signing} signs and verifies a scratch file; a missing home
 * or passphrase file, or a file others can read, is refused. Beside the ZIP it writes the
 * test-only module's assets, each published file's {@code .sha256}, {@code SHA256SUMS} and the
 * signature of each ({@code write_beside}), which {@code tools/publish-release.sh} accepts. The keys
 * are throwaway ones.
 */
class PackageReleaseSigningTest {
  static final String PASSPHRASE = "throwaway passphrase";
  @TempDir static Path work;
  static Path full, ci, passphrase;
  static String primary, subkey;

  record Run(int exit, String out) {}

  static boolean onPath(String tool) {
    for (String d : System.getenv().getOrDefault("PATH", "").split(File.pathSeparator))
      if (Files.isExecutable(Path.of(d, tool))) return true;
    return false;
  }

  static Run exec(Map<String, String> env, String... command) throws Exception {
    ProcessBuilder pb = new ProcessBuilder(command).redirectErrorStream(true);
    pb.environment().putAll(env);
    Process p = pb.start();
    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    assertTrue(p.waitFor(120, TimeUnit.SECONDS), String.join(" ", command));
    return new Run(p.exitValue(), out);
  }

  static String ok(Map<String, String> env, String... command) throws Exception {
    Run r = exec(env, command);
    assertEquals(0, r.exit(), String.join(" ", command) + ": " + r.out());
    return r.out();
  }

  static Path home(String name) throws Exception {
    Path home = Files.createDirectory(work.resolve(name));
    Files.setPosixFilePermissions(home, PosixFilePermissions.fromString("rwx------"));
    return home;
  }

  /** A release key with a passphrase and a signing subkey; a CI home with only the subkey's secret. */
  @BeforeAll
  static void keys() throws Exception {
    for (String tool : List.of("gpg", "gpgconf", "python3", "git")) assumeTrue(onPath(tool), tool);
    full = home("full");
    ci = home("ci");
    Map<String, String> f = Map.of("GNUPGHOME", full.toString());
    String[] loopback = {
      "gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", PASSPHRASE
    };
    ok(
        f,
        concat(
            loopback,
            "--quick-gen-key",
            "release test <release-test@example.invalid>",
            "ed25519",
            "cert",
            "never"));
    List<String> fprs = fingerprints(f);
    primary = fprs.get(0);
    ok(f, concat(loopback, "--quick-add-key", primary, "ed25519", "sign", "2y"));
    subkey = fingerprints(f).get(1);
    Path pub = work.resolve("public.asc"), secret = work.resolve("subkey.asc");
    ok(f, "gpg", "--batch", "--armor", "--output", pub.toString(), "--export", primary);
    ok(
        f,
        concat(
            loopback,
            "--armor",
            "--output",
            secret.toString(),
            "--export-secret-subkeys",
            subkey + "!"));
    Map<String, String> c = Map.of("GNUPGHOME", ci.toString());
    ok(c, "gpg", "--batch", "--import", pub.toString());
    ok(c, concat(loopback, "--import", secret.toString()));
    assertTrue(
        ok(c, "gpg", "--batch", "--list-secret-keys").contains("sec#"), "the primary is a stub");
    passphrase = Files.writeString(work.resolve("passphrase"), PASSPHRASE + "\n");
    Files.setPosixFilePermissions(passphrase, PosixFilePermissions.fromString("rw-------"));
  }

  @AfterAll
  static void stopAgents() throws Exception {
    for (Path home : new Path[] {full, ci})
      if (home != null && onPath("gpgconf"))
        exec(Map.of("GNUPGHOME", home.toString()), "gpgconf", "--kill", "gpg-agent");
  }

  static String[] concat(String[] a, String... b) {
    List<String> all = new ArrayList<>(List.of(a));
    all.addAll(List.of(b));
    return all.toArray(String[]::new);
  }

  static List<String> fingerprints(Map<String, String> env) throws Exception {
    List<String> out = new ArrayList<>();
    for (String line : ok(env, "gpg", "--batch", "--with-colons", "--list-keys").split("\n"))
      if (line.startsWith("fpr:")) out.add(line.split(":")[9]);
    return out;
  }

  static Run check(Path home, Path passphraseFile, String key) throws Exception {
    Map<String, String> env = new HashMap<>();
    env.put("KEYTEND_SIGNING_HOME", home.toString());
    env.put("KEYTEND_SIGNING_PASSPHRASE_FILE", passphraseFile.toString());
    // The caller's own GnuPG home must not matter.
    env.put("GNUPGHOME", work.resolve("elsewhere").toString());
    return exec(
        env,
        "python3",
        "-I",
        LicenseHeadersTest.root().resolve("tools/package-release.py").toString(),
        "--check-signing",
        "--sign-key",
        key);
  }

  @Test
  void theSubkeySignsFromItsOwnHomeWithThePassphraseFile() throws Exception {
    Run r = check(ci, passphrase, subkey + "!");
    assertEquals(0, r.exit(), r.out());
    assertTrue(r.out().contains("\"signed_by\": \"" + subkey + "\""), r.out());
    assertTrue(r.out().contains("\"primary\": \"" + primary + "\""), r.out());
  }

  @Test
  void theDefaultIsTheReleaseKeysSigningSubkey() throws Exception {
    String script = Files.readString(LicenseHeadersTest.root().resolve("tools/package-release.py"));
    assertTrue(
        script.contains("SIGNING_SUBKEY = 'AAE2AF4DD7F2427F52B800D494E026FE1BF6C09E'"),
        "the CI signing subkey");
    assertTrue(script.contains("'--passphrase-file'"), "gpg reads the passphrase file itself");
    assertFalse(
        script.contains("--passphrase-fd")
            || (script.contains("read_text(") && script.contains("passphrase.read")),
        "the passphrase is never read into the script");
  }

  @Test
  void aMissingHomeOrPassphraseFileIsRefused() throws Exception {
    Run home = check(work.resolve("absent"), passphrase, subkey + "!");
    assertEquals(1, home.exit(), home.out());
    assertTrue(home.out().contains("REFUSED: no signing keyring"), home.out());
    Run file = check(ci, work.resolve("absent-passphrase"), subkey + "!");
    assertEquals(1, file.exit(), file.out());
    assertTrue(file.out().contains("REFUSED: no passphrase file"), file.out());
  }

  @Test
  void aPassphraseFileOthersCanReadIsRefused() throws Exception {
    for (String mode : List.of("rw-r--r--", "rw-rw----", "rw----r--")) {
      Path loose = Files.writeString(work.resolve("loose-" + mode), PASSPHRASE + "\n");
      Files.setPosixFilePermissions(loose, PosixFilePermissions.fromString(mode));
      Run r = check(ci, loose, subkey + "!");
      assertEquals(1, r.exit(), mode + ": " + r.out());
      assertTrue(r.out().contains("must be 0600 or stricter"), r.out());
    }
  }

  /** Stops the CI home's agent, which caches the passphrase of an earlier signature. */
  static void forgetPassphrase() throws Exception {
    ok(Map.of("GNUPGHOME", ci.toString()), "gpgconf", "--kill", "gpg-agent");
  }

  @Test
  void aWrongPassphraseOrAnotherKeyDoesNotSign() throws Exception {
    forgetPassphrase();
    Path wrong = Files.writeString(work.resolve("wrong"), "not it\n");
    Files.setPosixFilePermissions(wrong, PosixFilePermissions.fromString("rw-------"));
    Run r = check(ci, wrong, subkey + "!");
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("gpg could not sign"), r.out());
    Run none = check(ci, passphrase, "0".repeat(40) + "!");
    assertEquals(1, none.exit(), none.out());
    assertTrue(none.out().contains("has no unique secret key"), none.out());
  }

  static final String INNER =
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef  lib/keytend-kmip-9.9.9.jar\n";

  static final List<String> TEST_ONLY =
      List.of(
          "keytend-kmip-testing-9.9.9.jar",
          "keytend-kmip-testing-9.9.9-sources.jar",
          "keytend-kmip-testing-9.9.9-cyclonedx.json");

  /** Every file write_beside signs: the two ZIPs, the test-only assets and SHA256SUMS. */
  static final List<String> SIGNED =
      List.of(
          "keytend-kmip-9.9.9.zip",
          "keytend-kmip-9.9.9-src.zip",
          "keytend-kmip-testing-9.9.9.jar",
          "keytend-kmip-testing-9.9.9-sources.jar",
          "keytend-kmip-testing-9.9.9-cyclonedx.json",
          "SHA256SUMS");

  /** write_beside of tools/package-release.py, on a ZIP of {@code INNER} and fake test-only assets. */
  static final String BESIDE =
      String.join(
          "\n",
          "import importlib.util, json, pathlib, sys",
          "spec = importlib.util.spec_from_file_location('package_release', sys.argv[1])",
          "m = importlib.util.module_from_spec(spec)",
          "spec.loader.exec_module(m)",
          "out = pathlib.Path(sys.argv[2])",
          "test_only = {n: ('the test-only ' + n + '\\n').encode() for n in sys.argv[4].split(',')}",
          "signer = m.Signer(sys.argv[3]) if sys.argv[3] else None",
          "published, signatures, key = m.write_beside(out, '9.9.9', out / 'keytend-kmip-9.9.9.zip',"
              + " sys.argv[5].encode(), test_only, signer)",
          "print(json.dumps({'published': [p.name for p in published], 'key': key}))");

  /**
   * A release directory holding the two ZIPs: a binary ZIP whose SHA256SUMS is {@code INNER}, and
   * the source ZIP ({@link PublishReleaseScriptTest#zips}).
   */
  static Path releaseDir() throws Exception {
    Path dir = Files.createTempDirectory(work, "release");
    PublishReleaseScriptTest.zips(dir, "9.9.9", INNER);
    return dir;
  }

  /** write_beside into {@code dir}, signing with {@code key} (none: unsigned). */
  static Run beside(Path dir, Path passphraseFile, String key, List<String> testOnly)
      throws Exception {
    Map<String, String> env = new HashMap<>();
    env.put("KEYTEND_SIGNING_HOME", ci.toString());
    env.put("KEYTEND_SIGNING_PASSPHRASE_FILE", passphraseFile.toString());
    env.put("GNUPGHOME", work.resolve("elsewhere").toString());
    return exec(
        env,
        "python3",
        "-I",
        "-c",
        BESIDE,
        LicenseHeadersTest.root().resolve("tools/package-release.py").toString(),
        dir.toString(),
        key,
        String.join(",", testOnly),
        INNER);
  }

  static String sha256(byte[] content) throws Exception {
    return java.util.HexFormat.of()
        .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(content));
  }

  static String sha256Line(Path file) throws Exception {
    return sha256(Files.readAllBytes(file)) + "  " + file.getFileName() + "\n";
  }

  static List<String> signatures(Path dir) throws Exception {
    try (var files = Files.list(dir)) {
      return files
          .map(f -> f.getFileName().toString())
          .filter(n -> n.endsWith(".asc"))
          .sorted()
          .collect(Collectors.toList());
    }
  }

  /** tools/publish-release.sh on {@code dir}, the CI home's public keys verifying. */
  static Run publish(Path dir, String... extra) throws Exception {
    Path notes =
        Files.writeString(dir.resolve("../notes-" + dir.getFileName() + ".md"), "Notes.\n");
    List<String> command =
        new ArrayList<>(
            List.of(
                "/bin/bash",
                LicenseHeadersTest.root().resolve("tools/publish-release.sh").toString(),
                "9.9.9",
                "--dir",
                dir.toString(),
                "--notes",
                notes.toString()));
    command.addAll(List.of(extra));
    return exec(Map.of("GNUPGHOME", ci.toString()), command.toArray(String[]::new));
  }

  /**
   * The test-only JAR, its sources and SBOM are written beside the ZIPs; each published file (the
   * two ZIPs and those three) gets its .sha256 and a signature by the subkey; SHA256SUMS lists the
   * binary ZIP's own under its top directory, that file, and each published file; and
   * tools/publish-release.sh accepts the result.
   */
  @Test
  void theAssetsBesideTheZipAreWrittenSignedAndAccepted() throws Exception {
    Path dir = releaseDir();
    Run r = beside(dir, passphrase, subkey + "!", TEST_ONLY);
    assertEquals(0, r.exit(), r.out());
    assertTrue(r.out().contains("\"key\": \"" + subkey + "\""), r.out());
    List<String> published = SIGNED.subList(0, 5);
    for (String name : TEST_ONLY)
      assertEquals("the test-only " + name + "\n", Files.readString(dir.resolve(name)));
    StringBuilder sums = new StringBuilder();
    sums.append(INNER.replace("  lib/", "  keytend-kmip-9.9.9/lib/"));
    sums.append(sha256(INNER.getBytes(StandardCharsets.UTF_8)))
        .append("  keytend-kmip-9.9.9/SHA256SUMS\n");
    for (String name : published) {
      assertEquals(
          sha256Line(dir.resolve(name)), Files.readString(dir.resolve(name + ".sha256")), name);
      sums.append(sha256Line(dir.resolve(name)));
    }
    assertEquals(sums.toString(), Files.readString(dir.resolve("SHA256SUMS")));
    for (String name : SIGNED) {
      String status =
          ok(
              Map.of("GNUPGHOME", ci.toString()),
              "gpg",
              "--batch",
              "--status-fd",
              "1",
              "--verify",
              dir.resolve(name + ".asc").toString(),
              dir.resolve(name).toString());
      assertTrue(
          status
              .lines()
              .anyMatch(
                  l ->
                      l.startsWith("[GNUPG:] VALIDSIG " + subkey + " ")
                          && l.endsWith(" " + primary)),
          "by the subkey, of the primary: " + name + ": " + status);
    }
    Run accepted = publish(dir, "--fingerprint", primary);
    assertEquals(0, accepted.exit(), accepted.out());
    assertTrue(accepted.out().contains("signed by " + primary), accepted.out());
    for (String name : SIGNED)
      assertTrue(accepted.out().contains(dir.resolve(name + ".asc").toString()), name);
  }

  /** Without a key nothing is signed, and the signatures of an earlier run are removed. */
  @Test
  void unsignedRemovesEarlierSignatures() throws Exception {
    Path dir = releaseDir();
    assertEquals(0, beside(dir, passphrase, subkey + "!", TEST_ONLY).exit());
    assertEquals(SIGNED.size(), signatures(dir).size());
    Run r = beside(dir, passphrase, "", TEST_ONLY);
    assertEquals(0, r.exit(), r.out());
    assertEquals(List.of(), signatures(dir));
    assertEquals(1, publish(dir, "--fingerprint", primary).exit(), "signatures required");
    Run unsigned = publish(dir, "--unsigned");
    assertEquals(0, unsigned.exit(), unsigned.out());
  }

  /** A missing test-only asset is refused before anything is written or signed. */
  @Test
  void aMissingTestOnlyAssetIsRefused() throws Exception {
    for (String missing : TEST_ONLY) {
      Path dir = releaseDir();
      List<String> some = new ArrayList<>(TEST_ONLY);
      some.remove(missing);
      Run r = beside(dir, passphrase, subkey + "!", some);
      assertEquals(1, r.exit(), r.out());
      assertTrue(
          r.out().contains("REFUSED: the test-only assets are not") && r.out().contains(missing),
          r.out());
      try (var files = Files.list(dir)) {
        assertEquals(
            List.of(
                dir.resolve("keytend-kmip-9.9.9-src.zip"), dir.resolve("keytend-kmip-9.9.9.zip")),
            files.sorted().collect(Collectors.toList()));
      }
    }
  }

  /** Without the source ZIP beside the binary one, nothing is written or signed. */
  @Test
  void aMissingSourceZipIsRefused() throws Exception {
    Path dir = releaseDir();
    Files.delete(dir.resolve("keytend-kmip-9.9.9-src.zip"));
    Run r = beside(dir, passphrase, subkey + "!", TEST_ONLY);
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("REFUSED: no keytend-kmip-9.9.9-src.zip in "), r.out());
    try (var files = Files.list(dir)) {
      assertEquals(
          List.of(dir.resolve("keytend-kmip-9.9.9.zip")), files.collect(Collectors.toList()));
    }
  }

  /** A signature that cannot be made fails the run, and leaves no signature of any asset. */
  @Test
  void aFailedSignatureLeavesNone() throws Exception {
    Path dir = releaseDir();
    assertEquals(0, beside(dir, passphrase, subkey + "!", TEST_ONLY).exit());
    Path wrong = Files.writeString(work.resolve("wrong-beside"), "not it\n");
    Files.setPosixFilePermissions(wrong, PosixFilePermissions.fromString("rw-------"));
    forgetPassphrase();
    Run r = beside(dir, wrong, subkey + "!", TEST_ONLY);
    assertEquals(1, r.exit(), r.out());
    assertTrue(r.out().contains("gpg could not sign"), r.out());
    assertEquals(List.of(), signatures(dir));
    Run refused = publish(dir, "--fingerprint", primary);
    assertEquals(1, refused.exit(), refused.out());
    assertTrue(refused.out().contains("REFUSED") && refused.out().contains(".asc"), refused.out());
  }
}
