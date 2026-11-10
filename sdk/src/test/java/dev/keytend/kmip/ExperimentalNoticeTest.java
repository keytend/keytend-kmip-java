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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * The experimental notice is everywhere a reader starts: every README, the documentation index,
 * SECURITY.md, the published modules' Javadoc overviews and every module's POM description (what
 * Maven Central shows). Nothing promises the opposite: no "production-ready", "GA" or "release
 * candidate" outside the review records.
 */
class ExperimentalNoticeTest {
  static final Path ROOT = LicenseHeadersTest.root();

  static List<Path> entryPoints() throws IOException {
    List<Path> files = new ArrayList<>();
    for (String f :
        List.of(
            "README.md",
            "cli/README.md",
            "docs/index.md",
            "SECURITY.md",
            // The Javadoc's landing pages: each published module's overview.
            "sdk/src/main/java/module-info.java",
            "testing/src/main/java/module-info.java",
            "micrometer/src/main/java/module-info.java",
            "opentelemetry/src/main/java/module-info.java")) files.add(ROOT.resolve(f));
    // The integration samples present in this tree (the public one has fewer).
    try (Stream<Path> dirs = Files.list(ROOT.resolve("integration"))) {
      dirs.map(d -> d.resolve("README.md"))
          .filter(Files::isRegularFile)
          .sorted()
          .forEach(files::add);
    }
    return files;
  }

  @Test
  void everyEntryPointSaysItIsExperimental() throws IOException {
    List<String> missing = new ArrayList<>();
    for (Path f : entryPoints()) {
      String text = Files.readString(f).toLowerCase(java.util.Locale.ROOT);
      if (!text.contains("experimental")
          || (!text.contains("not for production use")
              && !text.contains("not meant for production use")))
        missing.add(ROOT.relativize(f).toString());
    }
    assertEquals(List.of(), missing, "no experimental, not-for-production notice");
  }

  @Test
  void everyModuleDescriptionSaysItIsExperimental() throws IOException {
    List<String> missing = new ArrayList<>();
    Pattern description = Pattern.compile("<description>([^<]*)</description>");
    Pattern module = Pattern.compile("<module>([^<]+)</module>");
    List<String> poms = new ArrayList<>(List.of("pom.xml"));
    Matcher m = module.matcher(Files.readString(ROOT.resolve("pom.xml")));
    while (m.find()) poms.add(m.group(1) + "/pom.xml");
    for (String pom : poms) {
      Matcher d = description.matcher(Files.readString(ROOT.resolve(pom)));
      if (!d.find() || !d.group(1).startsWith("Experimental, not for production use. "))
        missing.add(pom);
    }
    assertEquals(List.of(), missing);
  }

  /** The names of earlier review documents in the release notes are history, not a promise. */
  @Test
  void nothingCallsAReleaseProductionReadyGaOrACandidate() throws IOException {
    Pattern promise =
        Pattern.compile(
            "production[- ]ready|\\bGA\\b(?!\\s+(review|readiness))|release candidate",
            Pattern.CASE_INSENSITIVE);
    List<String> found = new ArrayList<>();
    List<Path> files = new ArrayList<>(entryPoints());
    files.add(ROOT.resolve("RELEASE.md"));
    files.add(ROOT.resolve("tools/publish-release.sh"));
    try (Stream<Path> docs = Files.list(ROOT.resolve("docs"))) {
      docs.filter(p -> p.toString().endsWith(".md")).sorted().forEach(files::add);
    }
    for (Path f : files) {
      String text = Files.readString(f);
      Matcher m = promise.matcher(text);
      while (m.find()) {
        int line = (int) text.substring(0, m.start()).chars().filter(c -> c == '\n').count() + 1;
        found.add(ROOT.relativize(f) + ":" + line + ": " + m.group());
      }
    }
    assertEquals(List.of(), found);
  }
}
