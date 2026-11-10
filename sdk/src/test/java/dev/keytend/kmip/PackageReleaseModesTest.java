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

import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@code canonical_modes} of {@code tools/package-release.py}: the archivers copy each file's
 * permissions from disk, so a build under umask 0077 made JAR entries 0600 and 0700 where one under
 * 0022 made 0644 and 0755, and the release's bytes followed the umask. The packager gives every
 * entry that records Unix permissions 0644 (a file) or 0755 (a directory), changing nothing else:
 * the restrictive JAR becomes byte for byte the ordinary one. The distribution profile runs it on
 * every module's JARs ({@code --canonical-modes}) before the central profile signs them and deploy
 * stages them, and the packager refuses a JAR without those modes rather than change it after
 * Maven signed it, so the JARs on Central are the GitHub release's. {@code tools/release-check.sh}
 * builds the second distribution, a Central dry run, under umask 0077 to check the whole release.
 */
class PackageReleaseModesTest {
  @TempDir Path work;

  /**
   * Writes the same JAR twice, with the modes a 0077 and a 0022 build give its entries (and one
   * entry without Unix permissions, as shade writes them), normalizes both, and prints each step.
   */
  static final String SCRIPT =
      String.join(
          "\n",
          "import importlib.util, pathlib, sys, zipfile",
          "spec = importlib.util.spec_from_file_location('package_release', sys.argv[1])",
          "m = importlib.util.module_from_spec(spec)",
          "spec.loader.exec_module(m)",
          "work = pathlib.Path(sys.argv[2])",
          "def jar(name, directory, file, executable):",
          "    path = work / name",
          "    with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as z:",
          "        for entry, mode, content in [('META-INF/', 0o40000 | directory, b''),",
          "                ('META-INF/MANIFEST.MF', 0o100000 | file, b'Manifest-Version: 1.0\\n'),",
          "                ('dev/', 0o40000 | directory, b''),",
          "                ('dev/A.class', 0o100000 | file, b'\\xca\\xfe\\xba\\xbe'),",
          "                ('dev/run.sh', 0o100000 | executable, b'#!/bin/sh\\n')]:",
          "            info = zipfile.ZipInfo(entry, (2026, 11, 5, 12, 0, 0))",
          "            info.create_system = 3",
          "            info.external_attr = mode << 16 | (0x10 if entry.endswith('/') else 0)",
          "            z.writestr(info, content)",
          "        shaded = zipfile.ZipInfo('dev/Shaded.class', (2026, 11, 5, 12, 0, 0))",
          "        shaded.create_system = 0",
          "        shaded.external_attr = 0x20  # MS-DOS attributes only (writestr would add 0600)",
          "        z.writestr(shaded, b'\\xca\\xfe\\xba\\xbe')",
          "    return path",
          "restrictive = jar('restrictive.jar', 0o700, 0o600, 0o700)",
          "ordinary = jar('ordinary.jar', 0o755, 0o644, 0o644)",
          "before = restrictive.read_bytes()",
          "print('different before', before != ordinary.read_bytes())",
          "print('changed', m.canonical_modes(restrictive), m.canonical_modes(ordinary))",
          "print('identical after', restrictive.read_bytes() == ordinary.read_bytes())",
          "print('again', m.canonical_modes(restrictive))",
          "print('same length', len(before) == len(restrictive.read_bytes()))",
          "with zipfile.ZipFile(restrictive) as z:",
          "    print('intact', z.testzip() is None)",
          "    for info in z.infolist():",
          "        print('mode', info.filename, oct(info.external_attr >> 16))");

  @Test
  void restrictivePermissionsBecomeTheCanonicalOnesAndNothingElseChanges() throws Exception {
    assumeTrue(PackageReleaseSigningTest.onPath("python3"), "python3");
    String out =
        PackageReleaseSigningTest.ok(
            Map.of(),
            "python3",
            "-I",
            "-c",
            SCRIPT,
            LicenseHeadersTest.root().resolve("tools/package-release.py").toString(),
            work.toString());
    assertEquals(
        List.of(
            "different before True",
            "changed 5 0",
            "identical after True",
            "again 0",
            "same length True",
            "intact True",
            "mode META-INF/ 0o40755",
            "mode META-INF/MANIFEST.MF 0o100644",
            "mode dev/ 0o40755",
            "mode dev/A.class 0o100644",
            "mode dev/run.sh 0o100644",
            "mode dev/Shaded.class 0o0"),
        out.lines().toList());
  }

  /**
   * Makes a 0077 build's JAR in a module's {@code target/}: the packager refuses it; {@code
   * --canonical-modes target} (what the distribution profile runs) gives it the modes, after which
   * the packager accepts it; a module without {@code target/} has no JAR. The parent POM runs that
   * step in the distribution profile at pre-integration-test, after package wrote the JARs and
   * before verify, where the central profile signs them.
   */
  static final String MAVEN_STEP =
      String.join(
          "\n",
          "import importlib.util, pathlib, subprocess, sys, zipfile",
          "import xml.etree.ElementTree as ET",
          "script, root, work = sys.argv[1], pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])",
          "spec = importlib.util.spec_from_file_location('package_release', script)",
          "m = importlib.util.module_from_spec(spec)",
          "spec.loader.exec_module(m)",
          "target = work / 'target'",
          "target.mkdir()",
          "jar = target / 'keytend-kmip-9.9-sources.jar'",
          "with zipfile.ZipFile(jar, 'w') as z:",
          "    for entry, mode in [('META-INF/', 0o40700), ('META-INF/maven/pom.properties', 0o100600)]:",
          "        info = zipfile.ZipInfo(entry, (2026, 11, 5, 12, 0, 0))",
          "        info.create_system = 3",
          "        info.external_attr = mode << 16",
          "        z.writestr(info, b'')",
          "try:",
          "    m.refuse_other_modes([jar])",
          "    print('accepted before')",
          "except SystemExit as e:",
          "    print('refused before', str(e).startswith(str(jar) + ': entries without the modes'))",
          "def step(directory):",
          "    return subprocess.run([sys.executable, '-I', script, '--canonical-modes', str(directory)],",
          "                          capture_output=True, text=True, check=True).stdout.strip()",
          "print(step(target).replace(str(work), 'WORK'))",
          "m.refuse_other_modes([jar])",
          "print('accepted after')",
          "with zipfile.ZipFile(jar) as z:",
          "    print('modes', [oct(i.external_attr >> 16) for i in z.infolist()])",
          "print(step(work / 'absent').replace(str(work), 'WORK'))",
          "ns = {'m': 'http://maven.apache.org/POM/4.0.0'}",
          "pom = ET.parse(root / 'pom.xml').getroot()",
          "def phase(profile, plugin, execution):",
          "    for p in pom.iterfind('m:profiles/m:profile', ns):",
          "        if p.findtext('m:id', namespaces=ns) != profile:",
          "            continue",
          "        for q in p.iterfind('m:build/m:plugins/m:plugin', ns):",
          "            if q.findtext('m:artifactId', namespaces=ns) == plugin:",
          "                for e in q.iterfind('m:executions/m:execution', ns):",
          "                    if e.findtext('m:id', namespaces=ns) == execution:",
          "                        return e.findtext('m:phase', namespaces=ns), ET.tostring(e, encoding='unicode')",
          "    return None, ''",
          "modes, body = phase('distribution', 'maven-antrun-plugin', 'canonical-modes')",
          "print('canonical-modes', modes, '--canonical-modes' in body and 'project.build.directory' in body)",
          "print('sign-artifacts', phase('central', 'maven-gpg-plugin', 'sign-artifacts')[0])");

  @Test
  void theDistributionProfileGivesTheModesBeforeSigningAndThePackagerChangesNone()
      throws Exception {
    assumeTrue(PackageReleaseSigningTest.onPath("python3"), "python3");
    Path root = LicenseHeadersTest.root();
    String out =
        PackageReleaseSigningTest.ok(
            Map.of(),
            "python3",
            "-I",
            "-c",
            MAVEN_STEP,
            root.resolve("tools/package-release.py").toString(),
            root.toString(),
            work.toString());
    assertEquals(
        List.of(
            "refused before True",
            "canonical modes: 2 entries changed in 1 JARs of WORK/target",
            "accepted after",
            "modes ['0o40755', '0o100644']",
            "canonical modes: 0 entries changed in 0 JARs of WORK/absent",
            // After the last JAR (package) and before signing (verify): nothing between them.
            "canonical-modes pre-integration-test True",
            "sign-artifacts verify"),
        out.lines().toList());
  }
}
