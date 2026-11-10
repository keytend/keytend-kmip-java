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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.RevocationReason;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Each confirmed change acts on the objects its plan named, or refuses and changes nothing. In each
 * race, another caller acts while the confirmation waits ({@code beforeAnswer}), or at a request of
 * the command (a server hook).
 */
class PlanBoundCommandsTest {
  static final List<KmipVersion> VERSIONS =
      List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0);

  @TempDir Path dir;

  static KeyHandle staged(Kms kms, String name) {
    return kms.keys()
        .createAes(256)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .named(name)
        .createPreActive();
  }

  static boolean is(Ttlv request, Operation operation) {
    return request.children(Tag.BATCH_ITEM).stream()
        .anyMatch(i -> i.require(Tag.OPERATION).intValue() == operation.code());
  }

  /** Answers yes at the console, after {@code meanwhile} runs. */
  static void confirmAfter(Harness h, Runnable meanwhile) {
    h.terminal.interactive = true;
    h.terminal.lines.add("yes");
    h.terminal.beforeAnswer = meanwhile;
  }

  // ---- create --if-absent ----

  /**
   * Another caller stages a key with the name just before the command looks. Without a console or
   * --yes nothing is activated: exit 9, and the key stays Pre-Active.
   */
  @Test
  void aKeyStagedWhileTheCommandLooksIsNotActivatedUnconfirmed() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      AtomicBoolean once = new AtomicBoolean(true);
      AtomicReference<String> theirs = new AtomicReference<>();
      h.server.injectBeforeProcessing(
          r -> {
            if (is(r, Operation.LOCATE) && once.getAndSet(false))
              try (Kms other = h.server.connect()) {
                theirs.set(staged(other, "stage-race").id());
              }
            return null;
          });
      assertEquals(
          ExitCode.NOT_CONFIRMED.code,
          h.run("create", "--name", "stage-race", "--if-absent", "--json"),
          h.err());
      h.server.injectBeforeProcessing(null);
      assertNotNull(theirs.get(), v.toString());
      assertTrue(h.err().contains("activates " + theirs.get()), h.err());
      assertEquals(KeyState.PRE_ACTIVE, h.server.state(theirs.get()).orElseThrow(), v.toString());
      assertEquals(1, h.server.ids().size(), "nothing was created");
    }
  }

  /**
   * The race: the staged key appears after the command's look, before its Create. It ranks first
   * and is not activated, even with --yes: exit 7, and the hint names both keys.
   */
  @Test
  void aKeyStagedAfterTheLookIsNotActivatedEvenWithYes() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      AtomicBoolean once = new AtomicBoolean(true);
      AtomicReference<String> theirs = new AtomicReference<>();
      h.server.injectAfterProcessing(
          r -> {
            if (is(r, Operation.LOCATE) && once.getAndSet(false))
              try (Kms other = h.server.connect()) {
                theirs.set(staged(other, "stage-race").id());
              }
            return null;
          });
      assertEquals(
          ExitCode.PARTIAL.code,
          h.run("create", "--name", "stage-race", "--if-absent", "--yes", "--json"),
          h.err());
      h.server.injectAfterProcessing(null);
      Map<String, Object> error = h.errorJson();
      String mine = (String) Harness.list(error, "created").get(0);
      String hint = Harness.text(error, "hint");
      assertTrue(hint.contains(theirs.get() + ", is Pre-Active and ranks first"), hint);
      assertTrue(hint.contains(" activate " + theirs.get()), hint);
      assertEquals(KeyState.PRE_ACTIVE, h.server.state(theirs.get()).orElseThrow(), v.toString());
      assertEquals(KeyState.PRE_ACTIVE, h.server.state(mine).orElseThrow(), v.toString());
    }
  }

  /**
   * The plan names X. Another caller stages Z while the confirmation waits. Only X is activated; Z
   * stays Pre-Active.
   */
  @Test
  void onlyTheConfirmedStagedKeyIsActivated() throws IOException {
    Harness h = new Harness(dir);
    String x;
    try (Kms kms = h.server.connect()) {
      x = staged(kms, "staged").id();
    }
    AtomicReference<String> z = new AtomicReference<>();
    confirmAfter(
        h,
        () -> {
          try (Kms other = h.server.connect()) {
            z.set(staged(other, "staged").id());
          }
        });
    Map<String, Object> json = h.json("create", "--name", "staged", "--if-absent");
    assertEquals("activated", json.get("action"));
    assertEquals(x, json.get("id"));
    assertEquals(KeyState.ACTIVE, h.server.state(x).orElseThrow());
    assertEquals(KeyState.PRE_ACTIVE, h.server.state(z.get()).orElseThrow(), "never confirmed");
  }

  /**
   * This call's candidate was activated, and then another caller's earlier key won. The warning
   * says the losing key is Active and may be in use, not that it is Pre-Active.
   */
  @Test
  void aLosingKeyThatIsActiveIsNotCalledPreActive() throws IOException {
    Harness h = new Harness(dir);
    MovableClock serverClock = new MovableClock(Instant.now());
    h.server.clock(serverClock);
    AtomicBoolean once = new AtomicBoolean(true);
    AtomicReference<String> theirs = new AtomicReference<>();
    h.server.injectAfterProcessing(
        r -> {
          if (is(r, Operation.ACTIVATE) && once.getAndSet(false)) {
            // Made earlier by the server's clock: it ranks first.
            serverClock.now = serverClock.now.minus(Duration.ofHours(1));
            try (Kms other = h.server.connect()) {
              theirs.set(
                  other
                      .keys()
                      .createAes(256)
                      .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                      .named("race")
                      .create()
                      .id());
            }
            serverClock.now = serverClock.now.plus(Duration.ofHours(2));
          }
          return null;
        });
    Map<String, Object> json = h.json("create", "--name", "race", "--if-absent");
    h.server.injectAfterProcessing(null);
    assertEquals("found", json.get("action"), json.toString());
    assertEquals(theirs.get(), json.get("id"));
    List<Object> created = Harness.list(json, "created");
    assertEquals(1, created.size());
    String mine = (String) created.get(0);
    assertEquals(KeyState.ACTIVE, h.server.state(mine).orElseThrow());
    String warning = Harness.text(json, "warning");
    assertTrue(warning.contains(mine + ", which lost"), warning);
    assertTrue(warning.contains("it is active, so something may use it"), warning);
    assertFalse(warning.contains("Pre-Active"), warning);
  }

  // ---- rotate ----

  /**
   * The plan of rotate --if-active-for 0d --grace 7d names A. Another caller rotates A to B while
   * the confirmation waits. The command refuses: B is not rotated, and no key gets a Deactivation
   * Date.
   */
  @Test
  void aConditionalRotationNeverChangesAKeyItsPlanDidNotName() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = h.create("rotate-race");
      AtomicReference<String> b = new AtomicReference<>();
      confirmAfter(
          h,
          () -> {
            try (Kms other = h.server.connect()) {
              b.set(other.keys().handle(a).rotate().id());
            }
          });
      int code = h.run("rotate", "rotate-race", "--if-active-for", "0d", "--grace", "7d", "--json");
      assertEquals(ExitCode.STATE_CONFLICT.code, code, h.out());
      Map<String, Object> error = h.errorJson();
      assertEquals(b.get(), error.get("objectId"));
      String hint = Harness.text(error, "hint");
      assertTrue(hint.contains("repeat the command for a new plan"), hint);
      assertEquals(2, h.server.ids().size(), v + ": nothing was rotated");
      for (String id : List.of(a, b.get()))
        assertNull(h.json("show", id, "--no-lineage").get("deactivationDate"), v + " " + id);
    }
  }

  /**
   * Just before the command's Re-key, another caller rotates the key; the server refuses the second
   * Re-key, and that refusal's reply is lost. The replacement found is not claimed as this
   * command's: action recovered, rotated null.
   */
  @Test
  void aReplacementFoundAfterALostReplyIsNotClaimed() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v).refuseSecondReKey(true));
      String a = h.create("lost-race");
      AtomicBoolean once = new AtomicBoolean(true);
      AtomicReference<String> theirs = new AtomicReference<>();
      h.server.injectBeforeProcessing(
          r -> {
            if (is(r, Operation.RE_KEY) && once.getAndSet(false)) {
              try (Kms other = h.server.connect()) {
                theirs.set(other.keys().handle(a).rotate().id());
              }
              h.server.failNext(ServerOperation.RE_KEY, Fault.REPLY_LOST);
            }
            return null;
          });
      Map<String, Object> json = h.json("rotate", "lost-race");
      h.server.injectBeforeProcessing(null);
      assertEquals("recovered", json.get("action"), v + " " + json);
      assertTrue(json.containsKey("rotated"));
      assertNull(json.get("rotated"), "unknown");
      assertEquals(theirs.get(), json.get("current"));
      assertEquals(a, json.get("previous"));
      assertTrue(Harness.text(json, "warning").contains("this call or another caller"));
      assertEquals(2, h.server.ids().size(), "only the other caller made a key");
    }
  }

  /** A rotation another caller made while the confirmation waited gets a tool hint. */
  @Test
  void aRotationMeanwhileHasAToolHint() throws IOException {
    Harness h = new Harness(dir);
    String a = h.create("k");
    confirmAfter(
        h,
        () -> {
          try (Kms other = h.server.connect()) {
            other.keys().handle(a).rotate();
          }
        });
    assertEquals(ExitCode.STATE_CONFLICT.code, h.run("rotate", "k", "--grace", "7d", "--json"));
    String hint = Harness.text(h.errorJson(), "hint");
    assertTrue(hint.contains("another caller rotated k"), hint);
    assertTrue(hint.contains(" lineage k"), hint);
    assertNoJava(hint);
  }

  /**
   * A server that refuses client-set Deactivation Dates. The hint does not suggest expire --at,
   * which that server refuses too, and the message gives the grace period as typed.
   */
  @Test
  void aRefusedGracePeriodSuggestsDeactivatingLater() throws IOException {
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1)) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v).refuseClientDeactivationDate(true));
      String a = h.create("k");
      assertEquals(
          ExitCode.PARTIAL.code, h.run("rotate", "k", "--grace", "7d", "--yes", "--json"), h.err());
      Map<String, Object> error = h.errorJson();
      String hint = Harness.text(error, "hint");
      String current = (String) Harness.list(error, "created").get(0);
      assertTrue(hint.contains("deactivate-predecessors " + current), v + ": " + hint);
      assertFalse(hint.contains(" expire " + a), hint);
      assertFalse(Harness.text(error, "message").contains("PT168H"), error.toString());
      assertTrue(Harness.text(error, "message").contains("a grace period of 7d"), error.toString());
      assertEquals(KeyState.ACTIVE, h.server.state(a).orElseThrow());
    }
  }

  // ---- deactivate-predecessors ----

  /**
   * P (Pre-Active) -> A (Active) -> N. The plan lists only A. Another caller activates P while the
   * confirmation waits. Nothing is deactivated.
   */
  @Test
  void deactivatePredecessorsNeverDeactivatesAKeyItsPlanOmitted() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String p, a, n;
      try (Kms kms = h.server.connect()) {
        KeyHandle staged = staged(kms, "k");
        p = staged.id();
        KeyHandle active = staged.rotate();
        a = active.id();
        n = active.rotate().id();
      }
      confirmAfter(
          h,
          () -> {
            try (Kms other = h.server.connect()) {
              other.keys().handle(p).activate();
            }
          });
      assertEquals(
          ExitCode.STATE_CONFLICT.code, h.run("deactivate-predecessors", n, "--json"), h.out());
      assertTrue(h.err().contains("    " + a + " ("), h.err());
      assertFalse(h.err().contains("    " + p + " ("), "P was not in the plan: " + h.err());
      String message = Harness.text(h.errorJson(), "message");
      assertTrue(message.contains("Active now, not when planned: [" + p + "]"), message);
      assertTrue(Harness.text(h.errorJson(), "hint").contains("for a new plan"));
      assertEquals(KeyState.ACTIVE, h.server.state(p).orElseThrow(), v.toString());
      assertEquals(KeyState.ACTIVE, h.server.state(a).orElseThrow(), v.toString());
    }
  }

  // ---- reconcile ----

  /**
   * The name leads to R -> A; the plan keeps A and deactivates R. While the confirmation waits,
   * another caller moves the name to an unrelated U and rotates U to V. Nothing is reconciled: U
   * stays Active, and so does R.
   */
  @Test
  void reconcileNeverActsOnALineageItsPlanDidNotShow() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String r = h.create("k");
      String a = h.rotate("k");
      AtomicReference<String> u = new AtomicReference<>();
      confirmAfter(
          h,
          () -> {
            try (Kms other = h.server.connect()) {
              other.keys().handle(a).removeName("k");
              KeyHandle unrelated =
                  other
                      .keys()
                      .createAes(256)
                      .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                      .named("k")
                      .create();
              u.set(unrelated.id());
              unrelated.rotate();
            }
          });
      assertEquals(ExitCode.STATE_CONFLICT.code, h.run("reconcile", "k", "--json"), h.out());
      assertTrue(h.err().contains("keeps " + a + " ("), h.err());
      assertTrue(h.err().contains("    " + r + " ("), h.err());
      String hint = Harness.text(h.errorJson(), "hint");
      assertTrue(hint.contains("again for a new plan"), hint);
      assertEquals(KeyState.ACTIVE, h.server.state(u.get()).orElseThrow(), v.toString());
      assertEquals(KeyState.ACTIVE, h.server.state(r).orElseThrow(), v.toString());
    }
  }

  /** A Compromised newest key is refused before any plan, with a tool hint. */
  @Test
  void reconcileRefusesACompromisedWinnerBeforeThePlan() throws IOException {
    Harness h = new Harness(dir);
    h.create("k");
    String a = h.rotate("k");
    try (Kms kms = h.server.connect()) {
      kms.keys().handle(a).revoke(RevocationReason.keyCompromise("leaked", Instant.now()));
    }
    assertEquals(ExitCode.STATE_CONFLICT.code, h.run("reconcile", "k", "--yes", "--json"));
    assertFalse(h.err().contains("keeps "), "no plan: " + h.err());
    String hint = Harness.text(h.errorJson(), "hint");
    assertTrue(hint.contains(" replace-compromised " + a), hint);
    assertNoJava(hint);
  }

  // ---- retire-predecessors ----

  /** Retirement from a Compromised newest key would destroy the only clean key. */
  @Test
  void retirementFromACompromisedKeyIsRefusedBeforeThePlan() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String clean = h.create("rn");
      String newest = h.rotate("rn");
      h.ok(
          "revoke",
          newest,
          "--reason",
          "key-compromise",
          "--compromised-at",
          Instant.now().truncatedTo(ChronoUnit.SECONDS).toString(),
          "--yes");
      assertEquals(
          ExitCode.STATE_CONFLICT.code,
          h.run("retire-predecessors", newest, "--yes", "--json"),
          h.out());
      assertFalse(h.err().contains("destroys"), "no plan: " + h.err());
      String hint = Harness.text(h.errorJson(), "hint");
      assertTrue(hint.contains("replace-compromised " + newest), hint);
      assertEquals(KeyState.ACTIVE, h.server.state(clean).orElseThrow(), v.toString());
    }
  }

  /** Each planned key says what is done to it; the refusal is stated truthfully. */
  @Test
  void theRetirementPlanSaysWhatItDoesToEachKey() throws IOException {
    Harness h = new Harness(dir);
    String first = h.create("k");
    String second = h.rotate("k");
    String third = h.rotate("k");
    h.ok("expire", first, "--yes");
    assertEquals(ExitCode.NOT_CONFIRMED.code, h.run("retire-predecessors", third));
    String plan = h.err();
    assertTrue(plan.contains(first + " (") && plan.contains("): destroy\n"), plan);
    assertTrue(plan.contains("): deactivate, then destroy"), plan);
    assertTrue(plan.contains("    " + second + " ("), plan);
    assertTrue(plan.contains("Before its first change it reads the lineage again"), plan);
    assertFalse(plan.contains("If the lineage changes before they are destroyed"), plan);
  }

  /**
   * The reply of the first predecessor's Destroy is lost after it was deactivated. The JSON says
   * the failed step's outcome is unknown, and what it was.
   */
  @Test
  void aPartialRetirementReportsItsFailedStep() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String first = h.create("k");
      String second = h.rotate("k");
      h.server.failNext(ServerOperation.DESTROY, Fault.REPLY_LOST);
      assertEquals(
          ExitCode.PARTIAL.code, h.run("retire-predecessors", second, "--yes", "--json"), h.out());
      Map<String, Object> error = h.errorJson();
      assertEquals("PARTIAL", error.get("category"));
      assertEquals(List.of(first), Harness.list(error, "deactivated"));
      assertEquals(true, error.get("outcomeUnknown"), error.toString());
      Map<String, Object> cause = Harness.object(error, "cause");
      assertEquals("OutcomeUnknownException", cause.get("exception"));
      assertEquals("OUTCOME_UNKNOWN", cause.get("category"));
      assertEquals(first, cause.get("objectId"));
    }
  }

  // ---- expire --at ----

  /** On KMIP 1.x a refused Deactivation Date is Permission Denied: the hint says so. */
  @Test
  void expireAtOnKmip14ExplainsAPermissionDenied() throws IOException {
    Harness h =
        new Harness(
            dir, InMemoryKmipServer.of(KmipVersion.V1_4).refuseClientDeactivationDate(true));
    String id = h.create("k");
    String at = Instant.now().plus(Duration.ofDays(3)).truncatedTo(ChronoUnit.SECONDS).toString();
    assertEquals(
        ExitCode.PERMISSION_DENIED.code, h.run("expire", id, "--at", at, "--yes", "--json"));
    String hint = Harness.text(h.errorJson(), "hint");
    assertTrue(hint.contains("on KMIP 1.x"), hint);
    assertTrue(hint.contains(" expire " + id + " when"), hint);
  }

  /** A date that passes while the confirmation waits is a usage error, with a tool hint. */
  @Test
  void expireAtRefusesADateThatPassedDuringTheConfirmation() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("k");
    MovableClock clock = new MovableClock(Instant.now());
    h.clock = clock;
    String at = clock.now.plus(Duration.ofMinutes(1)).truncatedTo(ChronoUnit.SECONDS).toString();
    confirmAfter(h, () -> clock.now = clock.now.plus(Duration.ofMinutes(2)));
    assertEquals(ExitCode.USAGE.code, h.run("expire", id, "--at", at, "--json"));
    Map<String, Object> error = h.errorJson();
    assertTrue(Harness.text(error, "message").contains("passed while waiting"), error.toString());
    assertNoJava(Harness.text(error, "hint"));
    assertNull(h.json("show", id, "--no-lineage").get("deactivationDate"));
  }

  // ---- register-secret --replace ----

  @Test
  void registerSecretReplaceChecksTheOldSecretBeforeThePlan() throws IOException {
    Harness h = new Harness(dir);
    h.environment.put("V1", "first");
    h.environment.put("V2", "second");
    String a = h.ok("register-secret", "--name", "a", "--value-env", "V1").strip();
    assertEquals(
        ExitCode.STATE_CONFLICT.code,
        h.run("register-secret", "--name", "b", "--value-env", "V2", "--replace", a, "--json"));
    assertFalse(h.err().contains("registers the new value"), "no plan: " + h.err());
    String hint = Harness.text(h.errorJson(), "hint");
    assertTrue(hint.contains(" list --name b"), hint);
    assertNoJava(hint);
    assertEquals(1, h.server.ids().size(), "nothing was registered");
  }

  /** The SDK refusals the commands above document reach operators as tool hints. */
  static void assertNoJava(String hint) {
    assertNotNull(hint);
    for (String java : List.of("()", "kms.", "KeyHandle", "findByName", "deactivatePredecessors"))
      assertFalse(hint.contains(java), "Java advice in the hint: " + hint);
  }

  /** A clock a test moves. */
  static final class MovableClock extends Clock {
    volatile Instant now;

    MovableClock(Instant now) {
      this.now = now;
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }
}
