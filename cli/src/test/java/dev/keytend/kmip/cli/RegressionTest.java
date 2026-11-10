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

package dev.keytend.kmip.cli;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.model.Attributes;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.ServerOperation;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Reproductions of the retirement and replacement bugs: each fails on the CLI before its fix. The
 * reproductions for the other commands are in the tests of those commands.
 */
class RegressionTest {
  @TempDir Path dir;

  /** Adds a Replacement Object link from {@code from} to {@code to} that {@code to} does not confirm. */
  static void oneSidedLink(Harness h, String from, String to) {
    try (Kms kms = h.server.connect()) {
      Ttlv link =
          Ttlv.structure(
              Tag.LINK,
              Ttlv.enumeration(Tag.LINK_TYPE, Enums.LinkType.REPLACEMENT_OBJECT_LINK),
              Ttlv.text(Tag.LINKED_OBJECT_IDENTIFIER, to));
      kms.protocol()
          .call(
              Requests.addAttribute()
                  .uniqueIdentifier(from)
                  .attribute(Attributes.attribute("Link", link))
                  .build());
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /** The plan lines that name a key to retire (indented four spaces), as identifiers. */
  private static List<String> planned(String err) {
    List<String> ids = new ArrayList<>();
    for (String line : err.split("\\R"))
      if (line.startsWith("    ")) ids.add(line.strip().split(" ", 2)[0]);
    return ids;
  }

  @Test
  void retirementDestroysExactlyTheConfirmedKeysAfterAReconcile() throws IOException {
    // R forked into A and B, B reconciled into A, A rotated to C. retire C
    // --keep-from A planned R only, and destroyed B and R.
    Harness h = new Harness(dir);
    String root;
    String winner;
    String branch;
    String newest;
    try (Kms kms = h.server.connect()) {
      root =
          kms.keys()
              .createAes(256)
              .named("retire")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create()
              .id();
      String a = KeyCommandsTest.reKey(kms, root);
      String b = KeyCommandsTest.reKey(kms, root);
      winner = kms.keys().handle(root).reconcile().id();
      branch = winner.equals(a) ? b : a;
      newest = kms.keys().handle(winner).rotate().id();
    }
    Map<String, Object> json =
        h.json("retire-predecessors", newest, "--keep-from", winner, "--yes");
    List<Object> plannedIds = Harness.list(json, "planned");
    assertTrue(plannedIds.contains(branch), "the joined branch is in the plan: " + json);
    assertTrue(plannedIds.contains(root), json.toString());
    assertEquals(plannedIds, Harness.list(json, "destroyed"), "destroyed what was confirmed");
    assertEquals(
        plannedIds.stream().map(Object::toString).toList(),
        planned(h.err()),
        "the printed plan lists them in that order");
    assertEquals(KeyState.DESTROYED, h.server.state(branch).orElseThrow());
    assertEquals(KeyState.DESTROYED, h.server.state(root).orElseThrow());
    assertEquals(KeyState.ACTIVE, h.server.state(winner).orElseThrow());
  }

  @Test
  void retirementRefusesALineageWithSeveralNewestKeysBeforeThePlan() throws IOException {
    // With two newest keys, the plan listed the other caller's Active key for destruction.
    Harness h = new Harness(dir);
    String root = h.create("k");
    String second = h.rotate("k");
    String branch;
    try (Kms kms = h.server.connect()) {
      branch = KeyCommandsTest.reKey(kms, root);
    }
    assertEquals(ExitCode.STATE_CONFLICT.code, h.run("retire-predecessors", second));
    assertFalse(h.err().contains("deactivates and destroys"), "no plan: " + h.err());
    assertTrue(h.err().contains(" reconcile k"), "the hint names the command: " + h.err());
    assertEquals(KeyState.ACTIVE, h.server.state(branch).orElseThrow());
    assertEquals(KeyState.ACTIVE, h.server.state(root).orElseThrow());
    // After reconcile, the retirement goes ahead.
    String winner = (String) h.json("reconcile", "k", "--yes").get("winner");
    assertTrue(winner.equals(second) || winner.equals(branch), winner);
    h.ok("retire-predecessors", winner, "--yes");
    assertEquals(KeyState.DESTROYED, h.server.state(root).orElseThrow());
    assertEquals(KeyState.ACTIVE, h.server.state(winner).orElseThrow());
  }

  @Test
  void aPlanThatNoLongerMatchesDestroysNothing() throws IOException {
    Harness h = new Harness(dir);
    String first = h.create("k");
    h.rotate("k");
    String third = h.rotate("k");
    // Another caller rotates while the confirmation waits: the plan's newest key is not newest.
    h.terminal.interactive = true;
    h.terminal.lines.add("2");
    h.terminal.beforeAnswer =
        () -> {
          try (Kms kms = h.server.connect()) {
            kms.keys().handle(third).rotate();
          }
        };
    assertEquals(ExitCode.STATE_CONFLICT.code, h.run("retire-predecessors", third));
    assertEquals(KeyState.ACTIVE, h.server.state(first).orElseThrow());
    assertFalse(LifecycleCommandsTest.sent(h, Operation.DESTROY), "nothing was destroyed");
    assertTrue(h.err().contains("run the command again for a new plan"), h.err());
  }

  @Test
  void aPartlyDoneRetirementListsWhatItChanged() throws IOException {
    // The first Destroy succeeded, the next was refused, and the exit code was 5.
    Harness h = new Harness(dir);
    h.create("partial-retire");
    h.rotate("partial-retire");
    String third = h.rotate("partial-retire");
    AtomicBoolean armed = new AtomicBoolean();
    h.server.injectAfterProcessing(
        request -> {
          if (KeyCommandsTest.has(request, Operation.DESTROY) && armed.compareAndSet(false, true))
            h.server.failNext(ServerOperation.DESTROY, Fault.PERMISSION_DENIED);
          return null;
        });
    assertEquals(ExitCode.PARTIAL.code, h.run("retire-predecessors", third, "--yes", "--json"));
    Map<String, Object> error = h.errorJson();
    assertEquals("partial", error.get("status"));
    List<Object> destroyed = Harness.list(error, "destroyed");
    List<Object> deactivated = Harness.list(error, "deactivated");
    assertEquals(1, destroyed.size(), error.toString());
    assertEquals(1, deactivated.size(), error.toString());
    assertEquals(KeyState.DESTROYED, h.server.state((String) destroyed.get(0)).orElseThrow());
    assertEquals(KeyState.DEACTIVATED, h.server.state((String) deactivated.get(0)).orElseThrow());
    String hint = (String) error.get("hint");
    assertTrue(hint.contains("destroyed " + destroyed.get(0)), hint);
    assertTrue(hint.contains("deactivated " + deactivated.get(0)), hint);
    assertTrue(hint.contains(" retire-predecessors " + third), hint);
    // Repeating it, as the hint says, finishes the retirement.
    h.server.injectAfterProcessing(null);
    Map<String, Object> rest = h.json("retire-predecessors", third, "--yes");
    assertEquals(deactivated, Harness.list(rest, "destroyed"));
  }

  @Test
  void aLongLineageIsRetiredInStepsFromTheMiddle() throws IOException {
    // lineage() refused more than 64 rotations before --keep-from was used.
    Harness h = new Harness(dir);
    List<KeyHandle> keys = new ArrayList<>();
    try (Kms kms = h.server.connect()) {
      KeyHandle key =
          kms.keys()
              .createAes(256)
              .named("long")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
      keys.add(key);
      for (int i = 0; i < 65; i++) {
        key = key.rotate();
        keys.add(key);
      }
    }
    String newest = keys.get(keys.size() - 1).id();
    Map<String, Object> json =
        h.json("retire-predecessors", newest, "--keep-from", keys.get(32).id(), "--yes");
    assertEquals(32, Harness.list(json, "destroyed").size());
    assertEquals(KeyState.DESTROYED, h.server.state(keys.get(0).id()).orElseThrow());
    assertEquals(KeyState.ACTIVE, h.server.state(keys.get(32).id()).orElseThrow());
  }

  @Test
  void aOneSidedLinkIsNotTakenForAReplacement() throws IOException {
    // An unrelated key named by a raw Replacement link was reported as the successor.
    Harness h = new Harness(dir);
    String mine = h.create("mine");
    String stranger = h.create("stranger");
    oneSidedLink(h, mine, stranger);
    // Refused by the SDK's plan, before anything is shown: the link proves nothing.
    int code =
        h.run("replace-compromised", mine, "--compromised-at", "2026-10-01", "--yes", "--json");
    assertEquals(ExitCode.STATE_CONFLICT.code, code, h.out());
    Map<String, Object> error = h.errorJson();
    assertEquals("lineage", error.get("conflict"), error.toString());
    assertFalse(error.get("message").toString().contains(stranger + " replaced it"), h.err());
    assertEquals(KeyState.ACTIVE, h.server.state(mine).orElseThrow());
    assertEquals(List.of("mine"), h.server.names(mine));
    assertFalse(LifecycleCommandsTest.sent(h, Operation.REVOKE), "nothing was revoked");
  }
}
