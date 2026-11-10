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
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/**
 * One entry point per job (docs/choosing-an-api.md): the calls that overlap with an entry point are
 * marked advanced in the guide and in their Javadoc, every public overload of them, and the guide's
 * list and the marks agree.
 */
class AdvancedApiTest {
  /** The advanced calls, by class, as the guide's "The advanced alternatives" lists them. */
  static final Map<String, List<String>> ADVANCED =
      Map.of(
          "KeyHandle",
          List.of(
              "asSecretKey",
              "asPrivateKey",
              "asCertificate",
              "open",
              "openTo",
              "opening",
              "chunkedOpener",
              "unwrapKey",
              "rewrapTo",
              "rewrapRecordTo",
              "rewrapKeyTo",
              "sealing",
              "wrapKey",
              "encrypt",
              "decrypt",
              "rotate",
              "rotateOrLatest"),
          "CurrentKey",
          List.of(
              "checkingEvery",
              "refreshingEvery",
              "generateDataKey",
              "wrapKey",
              "unwrapKey",
              "rotateOrLatest"),
          "KmsKeys",
          List.of("open", "openTo", "opening", "chunkedOpener", "decrypt", "unwrapKey", "moveName"),
          "KmsTls",
          List.of("certificates"));

  static final Path KMS = Path.of("src/main/java/dev/keytend/kmip/kms");

  /** The Javadoc of each public declaration of {@code name} in {@code source}. */
  static List<String> javadocs(String source, String name) {
    List<String> out = new ArrayList<>();
    Matcher m =
        Pattern.compile("\n  public [^\n(]*\\b" + Pattern.quote(name) + "\\(").matcher(source);
    while (m.find()) {
      int end = source.lastIndexOf("*/", m.start());
      int start = source.lastIndexOf("/**", end);
      assertTrue(
          start >= 0
              && source
                  .substring(end + 2, m.start())
                  .strip()
                  .replaceAll("@\\w+(\\([^)]*\\))?", "")
                  .isBlank(),
          name + " has its own Javadoc");
      out.add(source.substring(start, end));
    }
    return out;
  }

  @Test
  void everyPublicOverloadOfAnAdvancedCallSaysSo() throws IOException {
    List<String> unmarked = new ArrayList<>();
    for (var e : ADVANCED.entrySet()) {
      String source = Files.readString(KMS.resolve(e.getKey() + ".java"));
      for (String name : e.getValue()) {
        List<String> docs = javadocs(source, name);
        assertFalse(docs.isEmpty(), e.getKey() + "." + name + " is public");
        for (int i = 0; i < docs.size(); i++)
          if (!docs.get(i).contains("<b>Advanced.</b>"))
            unmarked.add(e.getKey() + "." + name + " #" + (i + 1));
      }
    }
    assertEquals(List.of(), unmarked, "advanced calls whose Javadoc does not say so");
  }

  /** Every call marked advanced in Javadoc is in the guide's list, and the other way round. */
  @Test
  void theGuideAndTheMarksAgree() throws IOException {
    String guide = Files.readString(Path.of("../docs/choosing-an-api.md"));
    String section = guide.substring(guide.indexOf("## The advanced alternatives"));
    List<String> missing = new ArrayList<>();
    for (var e : ADVANCED.entrySet())
      for (String name : e.getValue())
        if (!section.contains("`" + name)
            && !section.contains(name + "`")
            && !section.contains(name + "(")) missing.add(e.getKey() + "." + name);
    assertEquals(List.of(), missing, "advanced calls the guide does not list");
    List<String> extra = new ArrayList<>();
    for (String type :
        List.of(
            "KeyHandle",
            "CurrentKey",
            "KmsKeys",
            "KmsTls",
            "LocalKeys",
            "Kms",
            "KeyRegistration")) {
      String source = Files.readString(KMS.resolve(type + ".java"));
      Matcher m =
          Pattern.compile(
                  "<b>Advanced\\.</b>(?:(?!\\*/).)*\\*/\\s*(?:@\\w+\\s*)*\n  public [^\n(]*?(\\w+)\\(",
                  Pattern.DOTALL)
              .matcher(source);
      while (m.find())
        if (!ADVANCED.getOrDefault(type, List.of()).contains(m.group(1)))
          extra.add(type + "." + m.group(1));
    }
    assertEquals(List.of(), extra, "marked advanced, but not in the list");
  }

  /** The scan finds every public overload and its own Javadoc. */
  @Test
  void theScanFindsEachOverload() {
    String source =
        "class X {\n  /** A. <b>Advanced.</b> */\n  public void a(int x) {}\n\n  /** B. */\n  public void a(String s) {}\n}\n";
    List<String> docs = javadocs(source, "a");
    assertEquals(2, docs.size());
    assertTrue(docs.get(0).contains("Advanced."));
    assertFalse(docs.get(1).contains("Advanced."));
  }
}
