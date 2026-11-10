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
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * expire, revoke, replace-compromised, destroy and retire-predecessors: confirmation, states,
 * failures.
 */
class LifecycleCommandsTest {
  @TempDir Path dir;

  static String future() {
    return Instant.now().plus(10, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS).toString();
  }

  @Test
  void changesNeedYesOrAConsoleConfirmation() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    assertEquals(ExitCode.NOT_CONFIRMED.code, h.run("expire", id));
    assertTrue(h.err().contains("expire " + id), "the plan is printed first: " + h.err());
    assertTrue(h.err().contains("--yes"), h.err());
    assertEquals(KeyState.ACTIVE, h.server.state(id).orElseThrow());

    h.terminal.interactive = true;
    h.terminal.lines.add("no");
    assertEquals(ExitCode.NOT_CONFIRMED.code, h.run("expire", id));
    assertEquals(KeyState.ACTIVE, h.server.state(id).orElseThrow());

    h.terminal.lines.add("yes");
    h.ok("expire", id);
    assertEquals(KeyState.DEACTIVATED, h.server.state(id).orElseThrow());
    assertTrue(
        h.terminal.prompts.contains("Type yes to go ahead: "), h.terminal.prompts.toString());
  }

  @Test
  void notConfirmedIsReportedInJson() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    assertEquals(ExitCode.NOT_CONFIRMED.code, h.run("--json", "expire", id));
    Map<String, Object> error = h.errorJson();
    assertEquals(9L, error.get("exitCode"));
    assertEquals("not-confirmed", error.get("status"));
  }

  @Test
  void expireNowDeactivatesAndTheKeyStillDecrypts() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    Map<String, Object> json =
        h.json("expire", id, "--yes", "--reason", "superseded", "--message", "key switch");
    assertEquals("deactivated", json.get("action"));
    assertEquals("deactivated", json.get("state"), "read back from the server");
    assertNull(json.get("warning"));
    assertEquals(KeyState.DEACTIVATED, h.server.state(id).orElseThrow());
    assertTrue(h.err().contains("it still decrypts"), h.err());
    String again = h.ok("expire", id, "--yes");
    assertTrue(again.contains("is Deactivated already; nothing changed."), again);
    assertEquals(ExitCode.USAGE.code, h.run("expire", id, "--yes", "--reason", "key-compromise"));
  }

  @Test
  void theStateAfterAChangeIsReadBackOrAWarning() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    java.util.concurrent.atomic.AtomicBoolean armed =
        new java.util.concurrent.atomic.AtomicBoolean();
    h.server.injectAfterProcessing(
        request -> {
          if (KeyCommandsTest.has(request, Operation.REVOKE) && armed.compareAndSet(false, true))
            h.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
          return null;
        });
    Map<String, Object> json = h.json("revoke", id, "--reason", "superseded", "--yes");
    assertEquals("revoked", json.get("action"));
    assertNull(json.get("state"), "not guessed");
    assertTrue(((String) json.get("warning")).contains("could not be read back"), json.toString());
    assertEquals(KeyState.DEACTIVATED, h.server.state(id).orElseThrow());
  }

  @Test
  void aMessageThatWouldBeDroppedIsRefused() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    // --at sets only the Deactivation Date
    assertEquals(
        ExitCode.USAGE.code, h.run("expire", id, "--at", future(), "--message", "later", "--yes"));
    assertEquals(
        ExitCode.USAGE.code,
        h.run("expire", id, "--at", future(), "--reason", "superseded", "--yes"));
    assertEquals(KeyState.ACTIVE, h.server.state(id).orElseThrow());
    assertNull(h.json("show", id, "--no-lineage").get("deactivationDate"), "nothing scheduled");
    assertFalse(sent(h, Operation.REVOKE), "nothing was revoked");
    // unspecified carries a message now (up to KMIP 2.1)
    h.ok("expire", id, "--message", "key switch", "--yes");
    assertEquals(KeyState.DEACTIVATED, h.server.state(id).orElseThrow());
    String other = h.create("other-kek");
    h.ok("revoke", other, "--reason", "unspecified", "--message", "left", "--yes");
    assertEquals(KeyState.DEACTIVATED, h.server.state(other).orElseThrow());
  }

  @Test
  void onKmip30AMessageIsRecordedOnlyWithACompromise() throws IOException {
    Harness h = new Harness(dir, InMemoryKmipServer.of(KmipVersion.V3_0));
    String id = h.create("orders-kek");
    assertEquals(
        ExitCode.USAGE.code,
        h.run("expire", id, "--reason", "superseded", "--message", "key switch", "--yes"));
    assertTrue(h.err().contains("--message is not recorded on KMIP 3.0"), h.err());
    assertEquals(
        ExitCode.USAGE.code,
        h.run("revoke", id, "--reason", "unspecified", "--message", "key switch", "--yes"));
    assertEquals(KeyState.ACTIVE, h.server.state(id).orElseThrow());
    String newest = h.rotate("orders-kek");
    assertEquals(
        ExitCode.USAGE.code, h.run("retire-predecessors", newest, "--message", "old", "--yes"));
    assertEquals(
        ExitCode.USAGE.code, h.run("deactivate-predecessors", newest, "--message", "old", "--yes"));
    assertEquals(KeyState.ACTIVE, h.server.state(id).orElseThrow());
    h.ok(
        "revoke",
        id,
        "--reason",
        "key-compromise",
        "--compromised-at",
        "2026-10-01T00:00:00Z",
        "--message",
        "leaked",
        "--yes");
    assertEquals(KeyState.COMPROMISED, h.server.state(id).orElseThrow());
  }

  @Test
  void expireOnKmip30SendsDeactivate() throws IOException {
    Harness h = new Harness(dir, InMemoryKmipServer.of(KmipVersion.V3_0));
    String id = h.create("orders-kek");
    h.ok("expire", id, "--yes");
    assertEquals(KeyState.DEACTIVATED, h.server.state(id).orElseThrow());
    assertTrue(h.err().contains("KMIP 3.0: the Deactivate operation"), h.err());
    assertTrue(sent(h, Operation.DEACTIVATE), "a Deactivate was sent");
    assertFalse(sent(h, Operation.REVOKE), "no Revoke was sent");
  }

  @Test
  void expireAtSetsTheDeactivationDate() throws IOException {
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0)) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String id = h.create("orders-kek");
      String at = future();
      Map<String, Object> json = h.json("expire", id, "--at", at, "--yes");
      assertEquals("scheduled", json.get("action"), v.toString());
      assertEquals(at, json.get("deactivationDate"), v.toString());
      assertEquals("active", json.get("state"), v.toString());
      assertEquals(KeyState.ACTIVE, h.server.state(id).orElseThrow());
      assertEquals(at, h.json("show", id).get("deactivationDate"), v.toString());
      // An earlier date replaces it (Modify Attribute); a later one is not needed.
      String earlier = Instant.parse(at).minus(1, ChronoUnit.DAYS).toString();
      h.ok("expire", id, "--at", earlier, "--yes");
      assertEquals(earlier, h.json("show", id).get("deactivationDate"), v.toString());
      assertTrue(h.ok("expire", id, "--at", at, "--yes").contains("nothing changed"), v.toString());
      assertFalse(sent(h, Operation.REVOKE), v + ": no Revoke");
      assertFalse(sent(h, Operation.DEACTIVATE), v + ": no Deactivate");
    }
  }

  @Test
  void expireAtRefusesThePastAndAcceptsLocalTimes() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    assertEquals(ExitCode.USAGE.code, h.run("expire", id, "--at", "2020-01-01T00:00:00Z", "--yes"));
    assertEquals(ExitCode.USAGE.code, h.run("expire", id, "--at", "next week", "--yes"));
    String local =
        Instant.now()
            .plus(3, ChronoUnit.DAYS)
            .truncatedTo(ChronoUnit.SECONDS)
            .toString()
            .replace("T", " ")
            .replace("Z", "");
    h.ok("expire", id, "--at", local, "--yes");
    assertEquals(
        local.replace(" ", "T") + "Z", h.json("show", id).get("deactivationDate"), h.out());
  }

  @Test
  void expireAtSettlesALostReplyByReadingBack() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    h.server.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.REPLY_LOST);
    String at = future();
    h.ok("expire", id, "--at", at, "--yes");
    assertEquals(at, h.json("show", id).get("deactivationDate"));
  }

  @Test
  void expireAtWithNoReplyAndNoChangeIsAnUnknownOutcome() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    h.server.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.HANG);
    assertEquals(
        ExitCode.OUTCOME_UNKNOWN.code,
        h.run("--timeout", "1s", "expire", id, "--at", future(), "--yes"));
    assertTrue(h.err().contains("outcome unknown"), h.err());
    assertTrue(h.err().contains(" show " + id), h.err());
  }

  @Test
  void expireAtFailuresKeepTheSdksClassification() throws IOException {
    // An unsent request was "may have taken effect" (3), an authentication refusal 1.
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    h.server.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.UNREACHABLE);
    assertEquals(ExitCode.UNAVAILABLE.code, h.run("expire", id, "--at", future(), "--yes"));
    h.server.failNext(
        ServerOperation.ADD_ATTRIBUTE,
        dev.keytend.kmip.model.Enums.ResultReason.AUTHENTICATION_NOT_SUCCESSFUL);
    assertEquals(
        ExitCode.PERMISSION_DENIED.code, h.run("expire", id, "--at", future(), "--yes", "--json"));
    Map<String, Object> error = h.errorJson();
    assertEquals("PermissionDeniedException", error.get("exception"));
    assertEquals("FIX_ACCESS", error.get("category"));
    h.server.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.PERMISSION_DENIED);
    assertEquals(ExitCode.PERMISSION_DENIED.code, h.run("expire", id, "--at", future(), "--yes"));
    h.server.refuseClientDeactivationDate(true);
    assertEquals(ExitCode.FAILED.code, h.run("expire", id, "--at", future(), "--yes"));
    assertTrue(
        h.err().contains("hint: this server does not let clients set the Deactivation Date"),
        h.err());
    assertTrue(h.err().contains(" expire " + id + " when the time comes"), h.err());
    assertNull(h.json("show", id, "--no-lineage").get("deactivationDate"));
  }

  @Test
  void expireAtNeverPostponesADateSetDuringTheConfirmation() throws IOException {
    // Another operator set an earlier date while the prompt waited; the stale Modify
    // Attribute postponed it.
    Harness h = new Harness(dir);
    String id = h.create("date-race");
    String initial =
        Instant.now().plus(120, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS).toString();
    String requested = Instant.parse(initial).minus(30, ChronoUnit.DAYS).toString();
    Instant earlier = Instant.parse(initial).minus(60, ChronoUnit.DAYS);
    h.ok("expire", id, "--at", initial, "--yes");
    h.terminal.interactive = true;
    h.terminal.lines.add("yes");
    h.terminal.beforeAnswer =
        () -> {
          try (dev.keytend.kmip.kms.Kms kms = h.server.connect()) {
            kms.keys().handle(id).deactivateAt(earlier);
          }
        };
    Map<String, Object> json = h.json("expire", id, "--at", requested);
    assertEquals(earlier.toString(), json.get("deactivationDate"));
    assertEquals("none", json.get("action"));
    h.terminal.beforeAnswer = () -> {};
    assertEquals(earlier.toString(), h.json("show", id, "--no-lineage").get("deactivationDate"));
  }

  @Test
  void preActiveKeys() throws IOException {
    // The hints sent operators to expire --at, which does not deactivate a Pre-Active key.
    Harness h = new Harness(dir);
    String id = h.create("staged", "--pre-active");
    assertEquals(ExitCode.STATE_CONFLICT.code, h.run("expire", id, "--yes"));
    assertTrue(h.err().contains("hint: destroy it ("), h.err());
    assertTrue(h.err().contains("or activate it first (keytend-kmip-cli"), h.err());
    assertFalse(h.err().contains("--at"), h.err());
    assertEquals(
        ExitCode.STATE_CONFLICT.code, h.run("revoke", id, "--reason", "superseded", "--yes"));
    assertTrue(h.err().contains("activate it first"), h.err());
    assertEquals(KeyState.PRE_ACTIVE, h.server.state(id).orElseThrow());
    assertFalse(sent(h, Operation.REVOKE), "nothing was revoked");
    // --at stays allowed, and the plan says when the date applies.
    h.ok("expire", id, "--at", future(), "--yes");
    assertTrue(h.err().contains("the date takes effect once it is Active"), h.err());
    assertTrue(h.err().contains("is its own"), h.err());
  }

  @Test
  void anUnknownOutcomeHasItsOwnExitCodeAndHint() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    h.server.failNext(ServerOperation.REVOKE, Fault.REPLY_LOST);
    assertEquals(ExitCode.OUTCOME_UNKNOWN.code, h.run("--json", "expire", id, "--yes"));
    Map<String, Object> error = h.errorJson();
    assertEquals(3L, error.get("exitCode"));
    assertEquals("OUTCOME_UNKNOWN", error.get("category"));
    assertTrue(((String) error.get("hint")).contains(" show " + id), error.toString());
  }

  @Test
  void revokeWithCompromiseAndWithout() throws IOException {
    Harness h = new Harness(dir);
    String a = h.create("a-kek");
    assertEquals(ExitCode.USAGE.code, h.run("revoke", a, "--yes"));
    assertEquals(ExitCode.USAGE.code, h.run("revoke", a, "--reason", "key-compromise", "--yes"));
    assertEquals(
        ExitCode.USAGE.code,
        h.run("revoke", a, "--reason", "superseded", "--compromised-at", "2026-01-01", "--yes"));
    h.ok(
        "revoke",
        a,
        "--reason",
        "key-compromise",
        "--compromised-at",
        "2026-10-01T00:00:00Z",
        "--message",
        "leaked",
        "--yes");
    assertEquals(KeyState.COMPROMISED, h.server.state(a).orElseThrow());
    assertTrue(
        h.err().contains("replace-compromised"), "the plan points to the replacement: " + h.err());
    assertTrue(h.ok("show", a).contains("Compromise date:"));
    assertTrue(
        h.ok("revoke", a, "--reason", "ca-compromise", "--compromised-at", "2026-10-01", "--yes")
            .contains("nothing changed"));

    String b = h.create("b-kek");
    Map<String, Object> json = h.json("revoke", b, "--reason", "cessation-of-operation", "--yes");
    assertEquals("deactivated", json.get("state"));
    assertEquals(KeyState.DEACTIVATED, h.server.state(b).orElseThrow());
    assertTrue(h.ok("revoke", b, "--reason", "superseded", "--yes").contains("nothing changed"));
    assertEquals(
        ExitCode.NOT_FOUND.code, h.run("revoke", "no-such-id", "--reason", "superseded", "--yes"));
  }

  @Test
  void revokeRefusesToDeactivateACompromisedKeyBeforeThePlan() throws IOException {
    // The plan said "deactivates it", for a key that stays Compromised.
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0)) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String id = h.create("k");
      h.ok("revoke", id, "--reason", "key-compromise", "--compromised-at", "2026-01-01", "--yes");
      h.terminal.interactive = true;
      assertEquals(
          ExitCode.STATE_CONFLICT.code, h.run("revoke", id, "--reason", "superseded"), v + "");
      assertTrue(h.err().contains("is Compromised; it cannot be deactivated"), h.err());
      assertFalse(h.err().contains("deactivates it"), "no plan: " + h.err());
      assertTrue(h.terminal.prompts.isEmpty(), "no question");
      assertEquals(KeyState.COMPROMISED, h.server.state(id).orElseThrow());
    }
  }

  @Test
  void revokeOnKmip30OnlyCompromisesForACompromise() throws IOException {
    Harness h = new Harness(dir, InMemoryKmipServer.of(KmipVersion.V3_0));
    String id = h.create("orders-kek");
    h.ok("revoke", id, "--reason", "superseded", "--yes");
    assertEquals(KeyState.DEACTIVATED, h.server.state(id).orElseThrow());
  }

  @Test
  void replaceCompromisedRefusesAnOlderKeyOfTheLineage() throws IOException {
    Harness h = new Harness(dir);
    String first = h.create("orders-kek");
    String second = h.rotate("orders-kek");
    assertEquals(
        ExitCode.STATE_CONFLICT.code,
        h.run("replace-compromised", first, "--compromised-at", "2026-10-01T00:00:00Z", "--yes"));
    assertTrue(h.err().contains(second + " replaced it"), h.err());
    assertTrue(h.err().contains(" revoke " + first + " --reason key-compromise"), h.err());
    assertEquals(KeyState.ACTIVE, h.server.state(first).orElseThrow());
    assertFalse(sent(h, Operation.REVOKE), "nothing was revoked");

    // The fix for an older key: revoke it. The name stays on the clean newest key.
    h.ok("revoke", first, "--reason", "key-compromise", "--compromised-at", "2026-10-01", "--yes");
    assertEquals(KeyState.COMPROMISED, h.server.state(first).orElseThrow());
    assertEquals(List.of("orders-kek"), h.server.names(second));
    int keys = h.server.ids().size();
    // A Compromised older key is not refused, but nothing is created, and the plan and the
    // result say so.
    Map<String, Object> json =
        h.json("replace-compromised", first, "--compromised-at", "2026-10-01", "--yes");
    assertEquals("existing", json.get("action"));
    assertEquals(second, json.get("replacement"));
    assertTrue(h.err().contains("creates nothing"), h.err());
    assertEquals(keys, h.server.ids().size());
    h.ok("retire-predecessors", second, "--yes");
  }

  @Test
  void replaceCompromisedMovesTheName() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    Map<String, Object> json =
        h.json("replace-compromised", id, "--compromised-at", "2026-10-01T00:00:00Z", "--yes");
    String replacement = (String) json.get("replacement");
    assertEquals("replaced", json.get("action"));
    assertEquals(KeyState.COMPROMISED, h.server.state(id).orElseThrow());
    assertEquals(KeyState.ACTIVE, h.server.state(replacement).orElseThrow());
    assertEquals(List.of("orders-kek"), h.server.names(replacement));
    assertEquals(ExitCode.USAGE.code, h.run("replace-compromised", id, "--yes"));
  }

  @Test
  void replaceCompromisedChoosesTheDates() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    assertEquals(
        ExitCode.USAGE.code,
        h.run(
            "replace-compromised",
            id,
            "--compromised-at",
            "2026-10-01",
            "--shifted-dates",
            "--copied-dates",
            "--yes"));
    String replacement =
        h.ok(
                "replace-compromised",
                id,
                "--compromised-at",
                "2026-10-01",
                "--shifted-dates",
                "--yes")
            .strip();
    assertEquals(KeyState.ACTIVE, h.server.state(replacement).orElseThrow());
    String other = h.create("other-kek");
    h.ok("replace-compromised", other, "--compromised-at", "2026-10-01", "--copied-dates", "--yes");
    assertEquals(KeyState.COMPROMISED, h.server.state(other).orElseThrow());
  }

  @Test
  void replaceCompromisedRefusesWhatItCannotReplaceBeforeThePlan() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("k");
    h.ok("expire", id, "--yes");
    h.ok("destroy", id, "--yes");
    assertEquals(
        ExitCode.STATE_CONFLICT.code,
        h.run("replace-compromised", id, "--compromised-at", "2026-01-01T00:00:00Z"));
    assertFalse(h.err().contains("revokes it"), "no plan: " + h.err());
    h.environment.put("PW", "hunter2");
    String secret = h.ok("register-secret", "--name", "db", "--value-env", "PW").strip();
    assertEquals(
        ExitCode.USAGE.code,
        h.run("replace-compromised", secret, "--compromised-at", "2026-01-01T00:00:00Z"));
    assertTrue(h.err().contains("replaces symmetric keys"), h.err());
    assertEquals(KeyState.ACTIVE, h.server.state(secret).orElseThrow());
  }

  @Test
  void destroyRefusesActiveKeysAndWantsTheIdentifierTyped() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    assertEquals(ExitCode.STATE_CONFLICT.code, h.run("destroy", id, "--yes"));
    assertTrue(h.err().contains("expire or revoke it first"), h.err());
    h.ok("expire", id, "--yes");

    h.terminal.interactive = true;
    h.terminal.lines.add("yes");
    assertEquals(ExitCode.NOT_CONFIRMED.code, h.run("destroy", id));
    assertTrue(h.err().contains("backups"), "the confirmation warns about backups: " + h.err());
    assertTrue(h.err().contains("CANNOT BE UNDONE"), h.err());
    assertTrue(
        h.terminal.prompts.contains("Type the identifier " + id + " to go ahead: "),
        h.terminal.prompts.toString());
    assertEquals(KeyState.DEACTIVATED, h.server.state(id).orElseThrow());

    h.terminal.lines.add(id);
    assertTrue(h.ok("destroy", id).contains("Destroyed " + id));
    assertEquals(KeyState.DESTROYED, h.server.state(id).orElseThrow());
    assertTrue(h.ok("destroy", id, "--yes").contains("nothing changed"));
  }

  @Test
  void destroysACompromisedKeyAndAPreActiveOne() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    h.ok("revoke", id, "--reason", "key-compromise", "--compromised-at", "2026-10-01", "--yes");
    h.ok("destroy", id, "--yes");
    assertEquals(KeyState.DESTROYED_COMPROMISED, h.server.state(id).orElseThrow());
    String staged = h.create("staged", "--pre-active");
    h.ok("destroy", staged, "--yes");
    assertFalse(h.server.hasMaterial(staged));
  }

  @Test
  void retirePredecessorsActsFromTheNewestKey() throws IOException {
    Harness h = new Harness(dir);
    String first = h.create("orders-kek");
    String second = h.rotate("orders-kek");
    String third = h.rotate("orders-kek");
    assertEquals(ExitCode.STATE_CONFLICT.code, h.run("retire-predecessors", second, "--yes"));
    assertTrue(h.err().contains(third), h.err());
    assertTrue(h.err().contains("lineage --id " + second), h.err());
    assertEquals(ExitCode.NOT_CONFIRMED.code, h.run("retire-predecessors", third));
    assertTrue(h.err().contains("these 2 keys"), h.err());
    assertEquals(KeyState.ACTIVE, h.server.state(first).orElseThrow());

    Map<String, Object> json = h.json("retire-predecessors", third, "--keep-from", second, "--yes");
    assertEquals(List.of(first), Harness.list(json, "planned"));
    assertEquals(List.of(first), Harness.list(json, "destroyed"));
    assertEquals(second, json.get("keepFrom"));
    assertEquals(KeyState.ACTIVE, h.server.state(second).orElseThrow());
    h.ok("retire-predecessors", third, "--yes");
    assertEquals(KeyState.DESTROYED, h.server.state(second).orElseThrow());
    assertTrue(h.ok("retire-predecessors", third, "--yes").contains("Nothing to retire"));
    assertEquals(
        ExitCode.NOT_FOUND.code,
        h.run("retire-predecessors", third, "--keep-from", "elsewhere", "--yes"));
    String unrelated = h.create("other-kek");
    assertEquals(
        ExitCode.USAGE.code,
        h.run("retire-predecessors", third, "--keep-from", unrelated, "--yes"));
    assertTrue(h.err().contains("is not in the lineage of " + third), h.err());
  }

  @Test
  void retirePredecessorsWantsTheNumberOfKeysTyped() throws IOException {
    // "yes" was enough to destroy several keys.
    Harness h = new Harness(dir);
    String first = h.create("orders-kek");
    h.rotate("orders-kek");
    String third = h.rotate("orders-kek");
    h.terminal.interactive = true;
    h.terminal.lines.add("yes");
    assertEquals(ExitCode.NOT_CONFIRMED.code, h.run("retire-predecessors", third));
    assertTrue(
        h.terminal.prompts.contains("Type the number of keys to destroy, 2, to go ahead: "),
        h.terminal.prompts.toString());
    assertEquals(KeyState.ACTIVE, h.server.state(first).orElseThrow());
    h.terminal.lines.add("2");
    h.ok("retire-predecessors", third);
    assertEquals(KeyState.DESTROYED, h.server.state(first).orElseThrow());
  }

  @Test
  void destructiveCommandsTakeIdentifiersNotNames() throws IOException {
    Harness h = new Harness(dir);
    h.create("orders-kek");
    for (String command : List.of("expire", "destroy", "activate"))
      assertEquals(ExitCode.NOT_FOUND.code, h.run(command, "orders-kek", "--yes"), command);
    assertFalse(sent(h, Operation.DESTROY), "nothing was destroyed");
    assertFalse(sent(h, Operation.REVOKE), "nothing was revoked");
  }

  /** Whether the server received a request item for {@code operation}. */
  static boolean sent(Harness h, Operation operation) {
    for (Ttlv request : h.server.protocolRequests())
      for (Ttlv item : request.children(Tag.BATCH_ITEM))
        if (item.child(Tag.OPERATION).map(o -> o.intValue() == operation.code()).orElse(false))
          return true;
    return false;
  }
}
