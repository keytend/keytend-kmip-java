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

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/**
 * No advice of the SDK tells the caller to destroy a key. A failed call cannot show that
 * nothing used a key it created once a name lookup could find it, so the advice of every
 * {@link PartialCompletionException} (and of every other failure) keeps keys. This test lists every
 * string literal of {@code dev.keytend.kmip.kms} that mentions destroying: each must be one of the
 * known texts below, none of which advises destroying a key that may be in use, so any new one
 * fails here until it is judged. A known text that no longer appears fails too.
 */
class DestroyAdviceTest {
  private static final Path MAIN = Path.of("src/main/java/dev/keytend/kmip/kms");

  /**
   * The known texts: file, a part of the literal (after {@code =}: the whole literal), and why it is
   * not advice to destroy a key that may be in use.
   */
  private static final List<String[]> KNOWN =
      List.of(
          new String[] {
            "DestroyableSecretKey.java", "Key destroyed", "local key material, not a server object"
          },
          new String[] {
            "TlsIssue.java",
            "this server returns destroyed objects for their names",
            "explains a name a destroyed identity keeps; advises another name"
          },
          new String[] {
            "TlsIssue.java",
            "do usually keep the name for good (a destroyed object's",
            "the same refusal"
          },
          new String[] {
            "TlsIssue.java",
            " destroyed identity cannot be renewed or re-keyed",
            "a state report; advises a new identity"
          },
          new String[] {
            "TlsIssue.java", " destroyed objects; nothing was registered", "the same refusal"
          },
          new String[] {
            "TlsIssue.java",
            "(destroyed objects, on servers that keep their",
            "explains a refused name; advises another name"
          },
          new String[] {
            "TlsIdentityFollower.java",
            "this refresh found the pair missing, compromised or destroyed",
            "reports absence or an unsafe state and stops presentation; does not advise destroying an object"
          },
          new String[] {"DestroyableSecretKey.java", "DestroyableSecretKey[", "a class name"},
          new String[] {"DataKey.java", "Data key destroyed", "local key material"},
          new String[] {"DataKey.java", ", destroyed]", "local key material"},
          new String[] {"SecretData.java", "Secret destroyed", "local secret material"},
          new String[] {"SecretData.java", ", destroyed]", "local secret material"},
          new String[] {
            "Failures.java",
            "=destroy",
            "the operation's name, for a refusal of the caller's own Destroy"
          },
          new String[] {
            "Failures.java",
            "cannot be destroyed: deactivate it first",
            "explains the caller's own Destroy"
          },
          new String[] {
            "Lineage.java", "for example destroyed and purged", "explains a gap in a lineage"
          },
          new String[] {
            "KmsKeys.java", "(destroyed and purged, not readable", "explains a gap in a lineage"
          },
          new String[] {
            "KeyHandle.java",
            " followed (destroyed and purged, not readable",
            "explains a replacement link that cannot be followed"
          },
          new String[] {
            "KmsKeys.java",
            "= destroy ",
            "findByName's hint for Pre-Active keys never activated and without links: never used to encrypt"
          },
          new String[] {
            "KmsKeys.java", "(kms.keys().handle(id).destroy()), and destroy", "the same hint"
          },
          new String[] {
            "KeyHandle.java",
            " is running, destroy ",
            "compromisePlan's refusal of a key an earlier call's Create made and did not link,"
                + " given only when every such key is Pre-Active and has no names but the"
                + " fallback Create's temporary one: never activated, so never used to encrypt (as"
                + " findByName's hint); and only once it is still unlinked a few minutes after its"
                + " Initial Date, which the text gives, so not another caller's key in flight"
          },
          new String[] {
            "KeyRegistration.java",
            "appears later, destroy it",
            "an OutcomeUnknownException: an object only ever named with the call's own random temporary name"
          },
          new String[] {
            "KeyRegistration.java",
            " destroyed object's name refuse to change it; register the",
            "explains replace's refusal of an object already Destroyed: nothing to destroy"
          },
          new String[] {
            "KeyHandle.java", "would destroy keys in the middle of a chain", "explains a refusal"
          },
          new String[] {"KeyHandle.java", "=destroy", "the operation's name"},
          new String[] {
            "KeyHandle.java",
            "it was destroyed, so the record cannot be recovered",
            "a state report"
          },
          new String[] {"KeyHandle.java", "Compromised or Destroyed", "a state report"},
          new String[] {
            "KeyHandle.java",
            " destroyed, so its oldest keys cannot be reached",
            "explains retirePredecessors' and deactivatePredecessors' refusal past 64 rotations not destroyed"
          },
          new String[] {
            "KeyHandle.java",
            " destroyed, so the oldest keys cannot be reached",
            "explains retirePredecessorsOlderThan's refusal past 64 rotations not destroyed before keepFrom"
          },
          new String[] {
            "KeyHandle.java",
            " rotations behind it that are not destroyed,",
            "explains lineage()'s refusal past 64 rotations"
          },
          new String[] {
            "KeyHandle.java", "destroying ", "names the retirement step that failed (a report)"
          },
          new String[] {
            "KmsKeys.java",
            " (not destroyed), so nothing was ",
            "explains refusingExistingName()'s refusal: a destroyed holder does not count"
          },
          new String[] {
            "PartialCompletionException.java",
            "destroyed ",
            "reports the keys a retirement destroyed before it stopped"
          });

  private static final Pattern LITERAL = Pattern.compile("\"(?:[^\"\\\\]|\\\\.)*\"");

  @Test
  void everyTextAboutDestroyingIsKnownAndNoneAdvisesIt() throws IOException {
    List<String> unknown = new ArrayList<>();
    Set<Integer> used = new HashSet<>();
    try (Stream<Path> files = Files.list(MAIN)) {
      for (Path file : files.filter(f -> f.toString().endsWith(".java")).sorted().toList()) {
        int line = 0;
        for (String text : Files.readAllLines(file)) {
          line++;
          String code = text.strip();
          if (code.startsWith("*") || code.startsWith("/*") || code.startsWith("//")) continue;
          Matcher m = LITERAL.matcher(text);
          while (m.find()) {
            String literal = m.group();
            if (!literal.toLowerCase(Locale.ROOT).contains("destroy")) continue;
            String name = file.getFileName().toString();
            int known = -1;
            for (int i = 0; i < KNOWN.size(); i++)
              if (KNOWN.get(i)[0].equals(name) && matches(literal, KNOWN.get(i)[1])) known = i;
            if (known < 0) unknown.add(name + ":" + line + " " + literal);
            else used.add(known);
          }
        }
      }
    }
    assertEquals(List.of(), unknown, "texts about destroying that are not judged yet");
    List<String> stale = new ArrayList<>();
    for (int i = 0; i < KNOWN.size(); i++)
      if (!used.contains(i)) stale.add(KNOWN.get(i)[0] + " " + KNOWN.get(i)[1]);
    assertEquals(List.of(), stale, "known texts that no longer appear");
  }

  private static boolean matches(String literal, String known) {
    return known.startsWith("=")
        ? literal.equals("\"" + known.substring(1) + "\"")
        : literal.contains(known);
  }

  /** The advice of {@link PartialCompletionException#of} by operation (built in, not at call sites). */
  @Test
  void theBuiltInActivationAdviceKeepsKeys() {
    for (String operation :
        List.of("findOrCreate", "rotate", "replaceCompromised", "register", "create"))
      assertFalse(
          PartialCompletionException.of(
                  operation,
                  List.of(),
                  null,
                  new TransientException("x", null, operation, null, null, null))
              .getMessage()
              .toLowerCase(Locale.ROOT)
              .contains("destroy"),
          operation);
  }
}
