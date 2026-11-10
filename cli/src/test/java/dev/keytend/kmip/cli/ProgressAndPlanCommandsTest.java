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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.LinkKind;
import dev.keytend.kmip.kms.RevocationReason;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Replace-compromised shows and is bound to every key it acts on, keeps its progress through a
 * failure and attributes each step on its own; an uncertain activation is never reported as a find;
 * the grace hint guesses no refusal; the console prompt is escaped; a secret replacement claims
 * only its own deactivation; and the help says what the commands do. Each loops over KMIP 1.4, 2.1
 * and 3.0.
 */
class ProgressAndPlanCommandsTest {
  static final List<KmipVersion> VERSIONS = PlanBoundCommandsTest.VERSIONS;
  static final RevocationReason THEIRS =
      RevocationReason.keyCompromise("theirs", Instant.parse("2026-01-01T00:00:00Z"));
  static final RevocationReason LATER =
      RevocationReason.keyCompromise("later", Instant.parse("2026-02-01T00:00:00Z"));

  @TempDir Path dir;

  static boolean is(Ttlv request, Operation operation) {
    return PlanBoundCommandsTest.is(request, operation);
  }

  /** Revokes {@code ids} as compromised through another connection. */
  static void compromise(Harness h, RevocationReason reason, String... ids) {
    try (Kms other = h.server.connect()) {
      for (String id : ids) other.keys().handle(id).revoke(reason);
    }
  }

  // ---- the plan names the descendant it replaces in turn ----

  /**
   * The key's replacement is Compromised too. The plan says it replaces that key as well and
   * creates one, and the result names it.
   */
  @Test
  void aCompromisedReplacementIsInThePlanAndTheResult() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = h.create("inc");
      String b = h.rotate("inc");
      compromise(h, THEIRS, a);
      compromise(h, LATER, b);
      int objects = h.server.ids().size();
      Map<String, Object> r =
          h.json("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes");
      String plan = h.err();
      assertFalse(plan.contains("creates nothing"), plan);
      assertTrue(plan.contains(b + " replaced it and is Compromised too"), plan);
      assertTrue(plan.contains("creating an Active key that takes both keys' names"), plan);
      assertTrue(plan.contains("--compromised-at and --message are not recorded"), plan);
      assertEquals("completed", r.get("action"), v + " " + r);
      assertEquals(List.of(b), Harness.list(r, "replacedInTurn"));
      String c = Harness.text(r, "replacement");
      assertEquals(List.of(c), Harness.list(r, "created"));
      assertEquals(objects + 1, h.server.ids().size());
      assertEquals(List.of("inc"), h.server.names(c));

      // In text, the result says which other key it replaced, with that key's date.
      Harness t = new Harness(dir, InMemoryKmipServer.of(v));
      String ta = t.create("inc");
      String tb = t.rotate("inc");
      compromise(t, THEIRS, ta);
      compromise(t, LATER, tb);
      t.ok("replace-compromised", ta, "--compromised-at", "2026-10-01", "--yes");
      assertTrue(t.err().contains("Also replaced " + tb), t.err());
      assertTrue(t.err().contains("2026-02-01T00:00:00Z"), t.err());
    }
  }

  /** An existing Active replacement: finished with, nothing created, as the plan says. */
  @Test
  void anActiveReplacementIsFinishedAsThePlanSays() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = h.create("inc");
      String b = h.rotate("inc");
      compromise(h, THEIRS, a);
      Map<String, Object> r =
          h.json("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes");
      assertTrue(h.err().contains(b + " replaced it: this finishes with that key"), h.err());
      assertTrue(h.err().contains("and creates nothing"), h.err());
      assertEquals("existing", r.get("action"), v + " " + r);
      assertEquals(List.of(), Harness.list(r, "replacedInTurn"));
      assertEquals(List.of(), Harness.list(r, "created"));
    }
  }

  /**
   * The second case: the replacement is compromised while the confirmation waits. The key is as
   * planned, but the call would create a key the plan did not name: exit 6, nothing changed.
   */
  @Test
  void aReplacementCompromisedWhileTheConfirmationWaitsIsRefused() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = h.create("inc");
      String b = h.rotate("inc");
      compromise(h, THEIRS, a);
      PlanBoundCommandsTest.confirmAfter(h, () -> compromise(h, LATER, b));
      int objects = h.server.ids().size();
      int code = h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--json");
      assertEquals(ExitCode.STATE_CONFLICT.code, code, v + " " + h.out());
      Map<String, Object> error = h.errorJson();
      assertEquals("not-as-planned", error.get("conflict"), error.toString());
      assertEquals(objects, h.server.ids().size(), "nothing was created");
      assertEquals(List.of("inc"), h.server.names(b), "the names stay");
    }
  }

  /**
   * The newest key descending from the key is Deactivated. The plan refuses it, before anything is
   * shown or confirmed, with a hint.
   */
  @Test
  void aDeactivatedNewestDescendantIsRefusedBeforeTheConfirmation() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = h.create("inc");
      String b = h.rotate("inc");
      compromise(h, THEIRS, a);
      try (Kms other = h.server.connect()) {
        other.keys().handle(b).deactivate();
      }
      h.terminal.interactive = true;
      h.terminal.lines.add("yes");
      int code = h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--json");
      assertEquals(ExitCode.STATE_CONFLICT.code, code, v + " " + h.out());
      assertEquals(List.of(), h.terminal.prompts, "refused before the confirmation");
      Map<String, Object> error = h.errorJson();
      assertEquals("state", error.get("conflict"));
      assertEquals(b, error.get("objectId"));
      String hint = Harness.text(error, "hint");
      assertTrue(hint.contains("the newest key descending from " + a + ", " + b), hint);
      PlanBoundCommandsTest.assertNoJava(hint);
    }
  }

  // ---- progress through a failure ----

  /** The first case: the Revoke is confirmed and the next read refused: exit 7, not 5. */
  @Test
  void aFailureAfterAConfirmedRevokeIsAPartialCompletion() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = h.create("inc");
      AtomicBoolean first = new AtomicBoolean(true);
      h.server.injectBeforeProcessing(
          r -> {
            if (is(r, Operation.REVOKE) && first.getAndSet(false))
              h.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
            return null;
          });
      int code =
          h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes", "--json");
      h.server.injectBeforeProcessing(null);
      assertEquals(ExitCode.PARTIAL.code, code, v + " " + h.out());
      Map<String, Object> error = h.errorJson();
      assertEquals(List.of(a), Harness.list(error, "deactivated"), error.toString());
      assertEquals(List.of(), Harness.list(error, "created"));
      assertTrue(
          Harness.text(error, "hint").startsWith("deactivated " + a + ". Check"), error.toString());
      assertEquals(KeyState.COMPROMISED, h.server.state(a).orElseThrow());
    }
  }

  /** The second case: the Revoke's reply is lost and its read-back refused: exit 3, not 5. */
  @Test
  void aLostRevokeWhoseReadBackFailsIsUnknown() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = h.create("inc");
      AtomicBoolean first = new AtomicBoolean(true);
      h.server.injectBeforeProcessing(
          r -> {
            if (!is(r, Operation.REVOKE) || !first.getAndSet(false)) return null;
            h.server.failNext(ServerOperation.REVOKE, Fault.REPLY_LOST);
            h.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
            return null;
          });
      int code =
          h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes", "--json");
      h.server.injectBeforeProcessing(null);
      assertEquals(ExitCode.OUTCOME_UNKNOWN.code, code, v + " " + h.out());
      assertEquals(a, h.errorJson().get("objectId"));
      assertEquals(KeyState.COMPROMISED, h.server.state(a).orElseThrow());
    }
  }

  // ---- each step's attribution on its own ----

  /**
   * The Revoke is confirmed and only the Re-key's reply lost. Which caller's Re-key made the key
   * read back cannot be told, so the command stops there: a partial completion that keeps the
   * revocation as this call's. Repeated, its new plan finishes with that key, and the first call's
   * compromise date stays.
   */
  @Test
  void aConfirmedRevokeStaysThisCallsWhenTheReKeyIsLost() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = h.create("inc");
      h.server.failNext(ServerOperation.RE_KEY, Fault.REPLY_LOST);
      int code =
          h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes", "--json");
      assertEquals(ExitCode.PARTIAL.code, code, v + " " + h.out());
      Map<String, Object> error = h.errorJson();
      assertEquals(List.of(a), Harness.list(error, "deactivated"));
      assertEquals(List.of(), Harness.list(error, "created"));
      assertEquals(true, error.get("outcomeUnknown"));
      String replacement = h.server.links(a, LinkKind.REPLACEMENT).get(0);
      assertTrue(Harness.text(error, "message").contains(replacement), error.toString());
      Map<String, Object> r =
          h.json("replace-compromised", a, "--compromised-at", "2026-10-02", "--yes");
      assertEquals("existing", r.get("action"), v + " " + r);
      assertEquals(false, r.get("revoked"));
      assertEquals(replacement, r.get("replacement"));
      assertEquals("2026-10-01T00:00:00Z", r.get("compromiseOccurrenceDate"));
    }
  }

  // ---- an uncertain activation ----

  /** The confirmed activation's reply is lost and read back Active: recovered, with a warning. */
  @Test
  void aLostActivationIsReportedAsRecovered() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String staged = h.create("staged", "--pre-active");
      h.server.failNext(ServerOperation.ACTIVATE, Fault.REPLY_LOST);
      Map<String, Object> r = h.json("create", "--name", "staged", "--if-absent", "--yes");
      assertEquals("recovered", r.get("action"), v + " " + r);
      assertEquals(staged, r.get("id"));
      String warning = Harness.text(r, "warning");
      assertTrue(warning.contains("activation of " + staged + " was lost"), warning);
      assertEquals(KeyState.ACTIVE, h.server.state(staged).orElseThrow());
    }
  }

  /**
   * The confirmed activation's reply is lost and its read-back refused: exit 3, with a hint about
   * the activation, never "nothing was activated".
   */
  @Test
  void aLostActivationWhoseReadBackFailsIsUnknownWithItsOwnHint() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String staged = h.create("staged", "--pre-active");
      AtomicBoolean first = new AtomicBoolean(true);
      h.server.injectBeforeProcessing(
          r -> {
            if (!is(r, Operation.ACTIVATE) || !first.getAndSet(false)) return null;
            h.server.failNext(ServerOperation.ACTIVATE, Fault.REPLY_LOST);
            h.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
            return null;
          });
      int code = h.run("create", "--name", "staged", "--if-absent", "--yes", "--json");
      h.server.injectBeforeProcessing(null);
      assertEquals(ExitCode.OUTCOME_UNKNOWN.code, code, v + " " + h.out());
      Map<String, Object> error = h.errorJson();
      assertEquals(staged, error.get("objectId"));
      String hint = Harness.text(error, "hint");
      assertTrue(hint.contains("activation of " + staged + " was lost"), hint);
      assertFalse(hint.contains("nothing was activated"), hint);
      assertFalse(hint.contains("Create"), hint);
      PlanBoundCommandsTest.assertNoJava(hint);
    }
  }

  // ---- the grace hint after a failure before the date ----

  /**
   * A recovered rotation with a grace period, whose first read after the recovery is refused: the
   * date was never asked for, so the hint does not say the server may refuse it, and it names the
   * replacement it found.
   */
  @Test
  void aReadFailureBeforeTheGraceDateIsNotCalledARefusedDate() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v).refuseSecondReKey(true));
      String a = h.create("raced");
      AtomicBoolean once = new AtomicBoolean(true);
      AtomicReference<String> theirs = new AtomicReference<>();
      AtomicInteger readsOfB = new AtomicInteger();
      h.server.injectBeforeProcessing(
          r -> {
            if (is(r, Operation.RE_KEY) && once.getAndSet(false)) {
              try (Kms other = h.server.connect()) {
                theirs.set(other.keys().handle(a).rotate().id());
              }
              h.server.failNext(ServerOperation.RE_KEY, Fault.REPLY_LOST);
            } else if (is(r, Operation.GET_ATTRIBUTES)
                && theirs.get() != null
                && RecoveryAndOutputTest.uid(r).equals(theirs.get())
                && readsOfB.incrementAndGet() == 2)
              h.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
            return null;
          });
      int code = h.run("rotate", "raced", "--grace", "1d", "--yes", "--json");
      h.server.injectBeforeProcessing(null);
      assertEquals(ExitCode.PARTIAL.code, code, v + " " + h.out());
      String hint = Harness.text(h.errorJson(), "hint");
      assertFalse(hint.contains("expire --at too"), hint);
      assertFalse(hint.contains("NEW_ID"), hint);
      assertTrue(hint.contains("show " + theirs.get()), hint);
      assertTrue(hint.contains("show " + a), hint);
      assertTrue(hint.contains(". Check the new key"), "a sentence after the progress: " + hint);
    }
  }

  // ---- the console prompt ----

  /**
   * An identifier with controls: the prompt shows it escaped, and typing that escaped form
   * confirms; the request uses the exact identifier.
   */
  @Test
  void theConfirmationPromptIsEscapedAndTakesTheEscapedIdentifier() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      AtomicInteger n = new AtomicInteger();
      String rlo = RecoveryAndOutputTest.RLO;
      h.server.identifierSource(() -> "key-\u001b[2J" + rlo + "-forged-" + n.incrementAndGet());
      String id = Harness.text(h.json("create", "--name", "forged", "--pre-active"), "id");
      String shown = Values.safe(id);
      h.terminal.interactive = true;
      h.terminal.lines.add(shown);
      assertEquals(0, h.run("destroy", id), v + " " + h.err());
      assertEquals(1, h.terminal.prompts.size());
      RecoveryAndOutputTest.assertClean(h.terminal.prompts.get(0));
      assertTrue(h.terminal.prompts.get(0).contains(shown), h.terminal.prompts.get(0));
      assertTrue(h.err().contains("type it as shown"), h.err());
      assertEquals(KeyState.DESTROYED, h.server.state(id).orElseThrow());

      // The raw identifier, controls and all, does not confirm.
      String other = Harness.text(h.json("create", "--name", "forged-2", "--pre-active"), "id");
      h.terminal.lines.add(other);
      assertEquals(ExitCode.NOT_CONFIRMED.code, h.run("destroy", other));
      assertEquals(KeyState.PRE_ACTIVE, h.server.state(other).orElseThrow());
    }
  }

  // ---- a secret replacement claims only its own deactivation ----

  @Test
  void aSecretAnotherCallerRetiredFirstIsNotClaimed() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      Path value = dir.resolve("value-" + v);
      Files.writeString(value, "s3cret", StandardCharsets.UTF_8);
      String old =
          h.ok("register-secret", "--name", "db", "--value-file", value.toString()).strip();
      AtomicBoolean first = new AtomicBoolean(true);
      ServerOperation retire =
          v == KmipVersion.V3_0 ? ServerOperation.DEACTIVATE : ServerOperation.REVOKE;
      h.server.injectBeforeProcessing(
          r -> {
            if (!(is(r, Operation.REVOKE) || is(r, Operation.DEACTIVATE))
                || !RecoveryAndOutputTest.uid(r).equals(old)
                || !first.getAndSet(false)) return null;
            try (Kms other = h.server.connect()) {
              other.keys().handle(old).deactivate();
            }
            h.server.failNext(retire, Fault.PERMISSION_DENIED);
            return null;
          });
      Map<String, Object> r =
          h.json(
              "register-secret",
              "--name",
              "db",
              "--value-file",
              value.toString(),
              "--replace",
              old,
              "--yes");
      h.server.injectBeforeProcessing(null);
      assertFalse(first.get(), "the race ran");
      assertEquals(false, r.get("replacedDeactivated"), v + " " + r);
      assertEquals("deactivated", r.get("replacedState"));
      assertNull(r.get("warning"));
    }
  }

  // ---- the help ----

  @Test
  void theHelpSaysWhatTheCommandsDo() throws IOException {
    Harness h = new Harness(dir);
    String rotate = h.ok("rotate", "--help");
    assertFalse(rotate.contains("makes no key"), rotate);
    assertTrue(rotate.contains("rotated if it is due"), rotate);
    String register = h.ok("register-secret", "--help");
    assertTrue(register.contains("deactivates OLD_ID if it is"), register);
    String compromise = h.ok("replace-compromised", "--help");
    assertFalse(compromise.contains("it creates nothing and reports"), compromise);
    assertTrue(compromise.contains("replaces it as well"), compromise);
    String create = h.ok("create", "--help");
    for (String line : create.lines().toList())
      assertFalse(line.stripTrailing().endsWith("[--custom"), "broken inside a group: " + line);
    for (String line : h.ok("--help").lines().toList())
      assertFalse(line.strip().equals("..."), "a lone ...");
  }
}
