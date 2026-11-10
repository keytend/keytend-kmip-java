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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.keytend.kmip.client.Requests;
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
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Replace-compromised shows and acts on exactly the keys of its plan, in a forked lineage too; a
 * lost fallback Create is found, never made twice; a recovered activation is reported as one; a
 * secret replacement's text claims nothing its replies did not confirm; and the results say which
 * step was recovered. Each loops over KMIP 1.4, 2.1 and 3.0.
 */
class ForkAndRecoveryCommandsTest {
  static final List<KmipVersion> VERSIONS = PlanBoundCommandsTest.VERSIONS;
  static final RevocationReason THEIRS =
      RevocationReason.keyCompromise("theirs", Instant.parse("2026-01-01T00:00:00Z"));

  @TempDir Path dir;

  static boolean is(Ttlv request, Operation operation) {
    return PlanBoundCommandsTest.is(request, operation);
  }

  /** A server whose Re-key of a Compromised key leaves a Pre-Active key, and that allows forks. */
  static InMemoryKmipServer forking(KmipVersion v) {
    return InMemoryKmipServer.of(v).linkCardinality(false).freshDatesOnReKey(true);
  }

  /** A key named {@code name}, Compromised by another responder. */
  static String compromised(Harness h, String name) {
    String a = h.create(name);
    try (Kms other = h.server.connect()) {
      other.keys().handle(a).revoke(THEIRS);
    }
    return a;
  }

  /** Re-keys {@code id} through another connection: a newest key, Pre-Active, unnamed. */
  static String reKey(Harness h, String id) throws Exception {
    try (Kms other = h.server.connect()) {
      return other
          .protocol()
          .call(Requests.reKey().uniqueIdentifier(id).build())
          .uniqueIdentifier();
    }
  }

  /** Changes {@code id} through another connection. */
  static void change(
      Harness h, String id, java.util.function.Consumer<dev.keytend.kmip.kms.KeyHandle> c) {
    try (Kms other = h.server.connect()) {
      c.accept(other.keys().handle(id).allowingCompromised());
    }
  }

  // ---- a forked lineage ----

  /**
   * An Active replacement with the name, and a Pre-Active branch. The plan names the branch and
   * says it is left alone; afterwards it is still Pre-Active.
   */
  @Test
  void aForkedLineagesOtherBranchIsShownAndLeftAlone() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, forking(v));
      String a = compromised(h, "inc");
      String b = reKey(h, a);
      String c = reKey(h, a);
      change(h, a, k -> k.removeName("inc"));
      change(h, b, k -> k.addName("inc"));
      change(h, b, k -> k.activate());
      Map<String, Object> r =
          h.json("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes");
      String plan = h.err();
      assertTrue(plan.contains(b + " replaced it: this finishes with that key"), plan);
      assertTrue(plan.contains(c + " also replaced it (Pre-Active, no name)"), plan);
      assertTrue(plan.contains("this leaves that key as it is"), plan);
      assertEquals("existing", r.get("action"), v + " " + r);
      assertEquals(b, r.get("replacement"));
      assertEquals(List.of(c), Harness.list(r, "otherDescendants"));
      assertTrue(Harness.text(r, "warning").contains(c + " also replaced " + a), r.toString());
      assertEquals(KeyState.PRE_ACTIVE, h.server.state(c).orElseThrow(), "left as it was");
    }
  }

  /** Two Pre-Active branches; only the one the plan names is activated. */
  @Test
  void ofTwoStagedBranchesOnlyThePlannedOneIsActivated() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, forking(v));
      String a = compromised(h, "inc");
      String b = reKey(h, a);
      String c = reKey(h, a);
      Map<String, Object> r =
          h.json("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes");
      String chosen = Harness.text(r, "replacement");
      String other = chosen.equals(b) ? c : b;
      assertTrue(
          h.err().contains(chosen + " replaced it: this finishes with that key, activating it"));
      assertEquals(KeyState.ACTIVE, h.server.state(chosen).orElseThrow());
      assertEquals(KeyState.PRE_ACTIVE, h.server.state(other).orElseThrow(), v + " " + r);
    }
  }

  /**
   * The first case: two Compromised branches; the plan replaces the named one. The name moves to
   * the other while the confirmation waits: not-as-planned, nothing changed.
   */
  @Test
  void aNameMovedBetweenBranchesWhileTheConfirmationWaitsIsRefused() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, forking(v));
      String a = compromised(h, "inc");
      String b = reKey(h, a);
      String c = reKey(h, a);
      change(h, b, k -> k.addName("b-name"));
      change(h, b, k -> k.revoke(THEIRS));
      change(h, c, k -> k.revoke(THEIRS));
      PlanBoundCommandsTest.confirmAfter(
          h,
          () -> {
            change(h, b, k -> k.removeName("b-name"));
            change(h, c, k -> k.addName("b-name"));
          });
      int objects = h.server.ids().size();
      int code = h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--json");
      assertEquals(ExitCode.STATE_CONFLICT.code, code, v + " " + h.out());
      assertTrue(h.err().contains(b + " replaced it and is Compromised too"), h.err());
      Map<String, Object> error = h.errorJson();
      assertEquals("not-as-planned", error.get("conflict"), error.toString());
      // The hint does not blame the key alone.
      assertTrue(
          Harness.text(error, "hint").contains("or a key descending from it"), error.toString());
      assertEquals(objects, h.server.ids().size(), "nothing was created");
      assertEquals(List.of("b-name"), h.server.names(c));
    }
  }

  /**
   * The second case: a Pre-Active branch without names and a Compromised one with a name. The plan
   * finishes with the Pre-Active one; its Activate is refused. The command fails, creates nothing,
   * and leaves the Compromised branch alone.
   */
  @Test
  void aRefusedActivationOfThePlannedKeyReplacesNoOtherBranch() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, forking(v));
      String a = compromised(h, "inc");
      String b = reKey(h, a);
      String c = reKey(h, a);
      // The shape: the Pre-Active branch has no names (a Re-key moved the key's name to it).
      for (String n : h.server.names(b)) change(h, b, k -> k.removeName(n));
      change(h, c, k -> k.addName("c-name"));
      change(h, c, k -> k.revoke(THEIRS));
      h.server.injectBeforeProcessing(
          r -> {
            if (is(r, Operation.ACTIVATE) && RecoveryAndOutputTest.uid(r).equals(b))
              h.server.failNext(ServerOperation.ACTIVATE, Fault.PERMISSION_DENIED);
            return null;
          });
      int objects = h.server.ids().size();
      int code =
          h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes", "--json");
      h.server.injectBeforeProcessing(null);
      assertNotEquals(0, code, h.out());
      // The planned key's own refusal stops the command, not a check of another branch.
      String error = h.errorJson().toString();
      assertTrue(error.contains("PermissionDeniedException"), error);
      assertFalse(error.contains("not-as-planned"), error);
      assertTrue(h.err().contains(b + " replaced it: this finishes with that key, activating it"));
      assertEquals(objects, h.server.ids().size(), "nothing was created");
      assertEquals(KeyState.COMPROMISED, h.server.state(c).orElseThrow());
      assertEquals(List.of("c-name"), h.server.names(c));
    }
  }

  // ---- a lost fallback Create ----

  /**
   * Re-key refused, the fallback Create's reply lost, and the search for its key lost too. Exit 7
   * with the revocation kept; the message gives the token to look the key up by and does not say a
   * plain repeat resumes. The repeat refuses, naming that key, and creates nothing; once it is
   * destroyed (never activated), the repeat creates one replacement.
   */
  @Test
  void aRepeatAfterALostFallbackCreateNamesTheKeyItMade() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = h.create("inc");
      AtomicBoolean createLost = new AtomicBoolean(true), searching = new AtomicBoolean();
      h.server.injectBeforeProcessing(
          r -> {
            if (is(r, Operation.RE_KEY))
              h.server.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
            else if (is(r, Operation.CREATE) && createLost.getAndSet(false)) {
              h.server.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
              searching.set(true);
            } else if (is(r, Operation.LOCATE) && searching.getAndSet(false))
              h.server.failNext(ServerOperation.LOCATE, Fault.REPLY_LOST);
            return null;
          });
      int code =
          h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes", "--json");
      assertEquals(ExitCode.PARTIAL.code, code, v + " " + h.out());
      Map<String, Object> error = h.errorJson();
      assertEquals(List.of(a), Harness.list(error, "deactivated"));
      assertEquals(true, error.get("outcomeUnknown"));
      String message = Harness.text(error, "message");
      assertTrue(message.contains("keytend-replacing-" + a), message);
      assertTrue(message.contains("could not be searched"), message);
      assertTrue(message.contains("before you repeat"), message);
      assertEquals(2, h.server.ids().size(), "the lost Create made a key");
      String orphan = h.server.ids().get(1);

      code = h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes", "--json");
      assertEquals(ExitCode.STATE_CONFLICT.code, code, h.out());
      error = h.errorJson();
      assertEquals(orphan, error.get("objectId"), error.toString());
      assertEquals("unlinked-replacement", error.get("conflict"), error.toString());
      String hint = Harness.text(error, "hint");
      assertTrue(hint.contains("destroy " + orphan), hint);
      assertEquals(2, h.server.ids().size(), "nothing created beside it");

      h.ok("destroy", orphan, "--yes");
      Map<String, Object> r =
          h.json("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes");
      h.server.injectBeforeProcessing(null);
      assertEquals("completed", r.get("action"), r.toString());
      assertEquals(List.of(r.get("replacement")), Harness.list(r, "created"));
      assertEquals(
          List.of(Harness.text(r, "replacement")), h.server.links(a, LinkKind.REPLACEMENT));
    }
  }

  /** The fallback Create's reply lost, its key found at once: recovered, with the step in JSON. */
  @Test
  void aLostFallbackCreateFoundAtOnceIsRecovered() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = h.create("inc");
      h.server.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
      h.server.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
      Map<String, Object> r =
          h.json("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes");
      assertEquals("recovered", r.get("action"), v + " " + r);
      assertEquals(List.of(), Harness.list(r, "created"));
      Map<String, Object> step = Harness.object(r, "recoveredFrom");
      assertEquals("OutcomeUnknownException", step.get("exception"));
      assertNull(step.get("objectId"), "a Create names no key");
      assertTrue(
          Harness.text(r, "warning").contains(r.get("replacement") + " was made as its"),
          r.toString());
      assertEquals(2, h.server.ids().size());
    }
  }

  // ---- a recovered activation of an existing replacement ----

  @Test
  void aLostActivationOfTheExistingReplacementIsReportedAsOne() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, forking(v));
      String a = compromised(h, "inc");
      String b = reKey(h, a);
      h.server.failNext(ServerOperation.ACTIVATE, Fault.REPLY_LOST);
      Map<String, Object> r =
          h.json("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes");
      assertEquals("recovered", r.get("action"), v + " " + r);
      String warning = Harness.text(r, "warning");
      assertTrue(warning.contains(b + " was activated"), warning);
      assertFalse(warning.contains("was made as its replacement"), warning);
      assertEquals(b, Harness.object(r, "recoveredFrom").get("objectId"));
      assertEquals(KeyState.ACTIVE, h.server.state(b).orElseThrow());
    }
  }

  // ---- an existing replacement that was activated is a change ----

  @Test
  void finishingAStagedReplacementIsReportedAsAChangeWhenTheOutputFails() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, forking(v));
      String a = compromised(h, "inc");
      String b = reKey(h, a);
      ByteArrayOutputStream err = new ByteArrayOutputStream();
      PrintStream broken =
          new PrintStream(
              new OutputStream() {
                @Override
                public void write(int x) throws IOException {
                  throw new IOException("disk full");
                }
              },
              true,
              StandardCharsets.UTF_8);
      Cli cli = h.cli(broken, new PrintStream(err, true, StandardCharsets.UTF_8));
      int code =
          cli.run(
              new String[] {
                "--config",
                h.config.toString(),
                "replace-compromised",
                a,
                "--compromised-at",
                "2026-10-01",
                "--yes"
              });
      assertEquals(ExitCode.FAILED.code, code);
      String text = err.toString(StandardCharsets.UTF_8);
      assertTrue(text.contains("the change was made (replaced compromised key " + a), text);
      assertEquals(KeyState.ACTIVE, h.server.state(b).orElseThrow());
    }
  }

  // ---- a secret replacement's lost deactivation reply ----

  /**
   * The reply to this call's deactivation is lost. The text no longer says "not by this call"; it
   * says the call did not confirm who did it, and warns.
   */
  @Test
  void aLostSecretDeactivationIsNotCalledAnotherCallers() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      Path value = dir.resolve("value-" + v);
      Files.writeString(value, "s3cret", StandardCharsets.UTF_8);
      String old =
          h.ok("register-secret", "--name", "db", "--value-file", value.toString()).strip();
      h.server.failNext(
          v == KmipVersion.V3_0 ? ServerOperation.DEACTIVATE : ServerOperation.REVOKE,
          Fault.REPLY_LOST);
      h.ok(
          "register-secret",
          "--name",
          "db",
          "--value-file",
          value.toString(),
          "--replace",
          old,
          "--yes");
      String text = h.err();
      assertFalse(text.contains("not by this call"), text);
      assertTrue(text.contains("this call did not confirm who deactivated it"), text);
      assertTrue(text.contains("this call or another caller deactivated it"), text);
    }
  }

  /**
   * The Register's reply and the deactivation's are both lost. The deactivation's is still
   * reported, in the warning and in JSON.
   */
  @Test
  void aLostDeactivationAfterALostRegisterIsStillReported() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      Path value = dir.resolve("value-" + v);
      Files.writeString(value, "s3cret", StandardCharsets.UTF_8);
      String old =
          h.ok("register-secret", "--name", "db", "--value-file", value.toString()).strip();
      h.server.failNext(ServerOperation.REGISTER, Fault.REPLY_LOST);
      h.server.failNext(
          v == KmipVersion.V3_0 ? ServerOperation.DEACTIVATE : ServerOperation.REVOKE,
          Fault.REPLY_LOST);
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
      assertEquals(false, r.get("replacedDeactivated"), v + " " + r);
      assertTrue(Harness.text(r, "warning").contains("deactivation of " + old), r.toString());
      assertEquals(old, Harness.object(r, "deactivationRecoveredFrom").get("objectId"));
      assertNull(Harness.object(r, "recoveredFrom").get("objectId"), "the Register's");
    }
  }

  // ---- the JSON shapes of these commands ----

  @Test
  void theChangedJsonShapesAreTheOnesTheReadmeLists() throws IOException {
    Harness h = new Harness(dir);
    String a = h.create("shape");
    Map<String, Object> r =
        h.json("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes");
    assertEquals(
        new TreeSet<>(
            Set.of(
                "compromised",
                "replacement",
                "action",
                "revoked",
                "compromiseOccurrenceDate",
                "replacedInTurn",
                "created",
                "otherDescendants",
                "checkedForUnlinkedKeys",
                "unreadableCandidates",
                "warning",
                "recoveredFrom")),
        new TreeSet<>(r.keySet()));
    Path value = dir.resolve("value");
    Files.writeString(value, "s3cret", StandardCharsets.UTF_8);
    String old = h.ok("register-secret", "--name", "pw", "--value-file", value.toString()).strip();
    Map<String, Object> s =
        h.json(
            "register-secret",
            "--name",
            "pw",
            "--value-file",
            value.toString(),
            "--replace",
            old,
            "--yes");
    assertEquals(
        new TreeSet<>(
            Set.of(
                "id",
                "name",
                "type",
                "replaced",
                "replacedDeactivated",
                "replacedState",
                "warning",
                "recoveredFrom",
                "deactivationRecoveredFrom")),
        new TreeSet<>(s.keySet()));
    String key = h.create("other");
    Map<String, Object> created = h.json("create", "--name", "other", "--if-absent", "--yes");
    assertEquals(key, created.get("id"));
    assertTrue(created.containsKey("recoveredFrom"), created.toString());
    Map<String, Object> rotated = h.json("rotate", "other", "--yes");
    assertTrue(rotated.containsKey("recoveredFrom"), rotated.toString());
  }

  // ---- the sixth pass: recovery after a lost reply keeps to the plan's keys ----

  /** Whether {@code t} holds a text value that contains {@code text}. */
  static boolean mentions(Ttlv t, String text) {
    if (t.type() == Ttlv.Type.TEXT_STRING && String.valueOf(t.value()).contains(text)) return true;
    if (t.type() == Ttlv.Type.STRUCTURE)
      for (Ttlv c : t.children()) if (mentions(c, text)) return true;
    return false;
  }

  /** {@link #reKey}, for a hook that cannot throw. */
  static String reKeyNow(Harness h, String id) {
    try {
      return reKey(h, id);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * Just before the command's Re-key reaches the server, another caller re-keys the key (B); the
   * command's Re-key makes C and its reply is lost. Which one the command made cannot be told: it
   * activates, links and names neither, keeps its revocation, and exits as a partial completion
   * whose message names both.
   */
  @Test
  void aLostReKeyBesideAnotherCallersReKeyAdoptsNeither() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, forking(v));
      String a = h.create("orders");
      AtomicBoolean armed = new AtomicBoolean(true);
      String[] b = new String[1];
      h.before =
          r -> {
            if (is(r, Operation.RE_KEY) && armed.getAndSet(false)) {
              b[0] = reKeyNow(h, a);
              h.server.failNext(ServerOperation.RE_KEY, Fault.REPLY_LOST);
            }
          };
      int code =
          h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes", "--json");
      assertEquals(ExitCode.PARTIAL.code, code, v + " " + h.out());
      Map<String, Object> error = h.errorJson();
      assertEquals(List.of(a), Harness.list(error, "deactivated"));
      assertEquals(List.of(), Harness.list(error, "created"));
      assertEquals(List.of(), Harness.list(error, "found"));
      assertEquals(true, error.get("outcomeUnknown"));
      String message = Harness.text(error, "message");
      List<String> replacements = h.server.links(a, LinkKind.REPLACEMENT);
      assertEquals(2, replacements.size(), replacements.toString());
      for (String r : replacements) {
        assertTrue(message.contains(r), message);
        assertEquals(KeyState.PRE_ACTIVE, h.server.state(r).orElseThrow(), r);
      }
      assertTrue(message.contains("did not activate, link or name"), message);
      assertTrue(replacements.contains(b[0]));
      assertEquals(List.of("orders"), h.server.names(b[0]), "as the other caller's Re-key left it");
    }
  }

  /**
   * The fallback Create's reply is lost, and before the command looks for its key another caller
   * re-keys that key (the Re-key moves its temporary name, and copies its client attributes) and
   * destroys it. The command finds the other caller's key, does not take it, and changes nothing of
   * it.
   */
  @Test
  void aKeyReKeyedFromTheLostCreatesKeyIsNotAdopted() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, forking(v));
      String a = h.create("orders");
      AtomicBoolean reKey = new AtomicBoolean(true), create = new AtomicBoolean(true);
      AtomicBoolean search = new AtomicBoolean(true);
      String[] theirs = new String[1];
      h.before =
          r -> {
            if (is(r, Operation.RE_KEY) && reKey.getAndSet(false))
              h.server.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
            else if (is(r, Operation.CREATE) && create.getAndSet(false))
              h.server.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
            else if (is(r, Operation.LOCATE)
                && mentions(r, "keytend-replacing-")
                && search.getAndSet(false)) {
              List<String> ids = h.server.ids();
              String made = ids.get(ids.size() - 1);
              theirs[0] = reKeyNow(h, made);
              try (Kms other = h.server.connect()) {
                other.protocol().call(Requests.destroy().uniqueIdentifier(made).build());
              } catch (IOException e) {
                throw new java.io.UncheckedIOException(e);
              }
            }
          };
      int code =
          h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes", "--json");
      assertEquals(ExitCode.PARTIAL.code, code, v + " " + h.out());
      Map<String, Object> error = h.errorJson();
      assertEquals(List.of(a), Harness.list(error, "deactivated"));
      assertEquals(List.of(), Harness.list(error, "found"));
      String message = Harness.text(error, "message");
      assertTrue(message.contains(theirs[0]), message);
      assertTrue(message.contains("not as the Create left a key"), message);
      assertEquals(KeyState.PRE_ACTIVE, h.server.state(theirs[0]).orElseThrow());
      assertEquals(List.of(), h.server.links(theirs[0], LinkKind.REPLACEMENT));
      assertEquals(List.of(), h.server.links(a, LinkKind.REPLACEMENT), "nothing linked to " + a);
      assertEquals(
          1, h.server.names(theirs[0]).size(), "only the name the Re-key moved: " + theirs[0]);
      assertEquals(List.of("orders"), h.server.names(a), "the name stays on " + a);
    }
  }

  /**
   * A server that cannot search the client attribute an earlier attempt's unlinked key records. The
   * plan says so, and the result warns, naming the list to check.
   */
  @Test
  void aPlanThatCannotSearchForAnUnlinkedKeySaysSo() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, forking(v));
      String a = compromised(h, "inc");
      h.before =
          r -> {
            if (is(r, Operation.LOCATE) && mentions(r, "keytend-replacement-of"))
              h.server.failNext(
                  ServerOperation.LOCATE,
                  dev.keytend.kmip.model.Enums.ResultReason.GENERAL_FAILURE);
          };
      Map<String, Object> r =
          h.json("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes");
      String plan = h.err();
      assertTrue(
          plan.contains(
              "The server could not be searched for a key an earlier attempt created to replace "
                  + a),
          plan);
      assertEquals("completed", r.get("action"), r.toString());
      String warning = Harness.text(r, "warning");
      assertTrue(warning.contains("could not be searched"), warning);
      assertTrue(warning.contains("--state pre-active"), warning);
    }
  }

  /**
   * While the confirmation waits, another caller's replacement of the key is in flight: created,
   * not linked yet. The command refuses as not as planned, nothing changed, and never advises
   * destroying that key.
   */
  @Test
  void anotherCallersKeyInFlightIsNotAsPlanned() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, forking(v));
      String a = compromised(h, "inc");
      String[] theirs = new String[1];
      PlanBoundCommandsTest.confirmAfter(
          h,
          () -> {
            try (Kms other = h.server.connect()) {
              theirs[0] =
                  other
                      .keys()
                      .createAes(256)
                      .usages(
                          dev.keytend.kmip.kms.KeyUsage.ENCRYPT,
                          dev.keytend.kmip.kms.KeyUsage.DECRYPT)
                      .custom(
                          dev.keytend.kmip.kms.CustomAttribute.client("keytend-replacement-of"), a)
                      .createPreActive()
                      .id();
            }
          });
      int code = h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--json");
      assertEquals(ExitCode.STATE_CONFLICT.code, code, v + " " + h.out());
      Map<String, Object> error = h.errorJson();
      assertEquals("not-as-planned", error.get("conflict"), error.toString());
      String said = Harness.text(error, "message") + " " + Harness.text(error, "hint");
      assertTrue(said.contains(theirs[0]), said);
      assertFalse(said.contains("destroy"), said);
      assertEquals(KeyState.PRE_ACTIVE, h.server.state(theirs[0]).orElseThrow());
    }
  }

  /**
   * The call only finishes an unfinished name move (the replacement is Active and the key has no
   * names), and writing the output fails: the error still says the change was made.
   */
  @Test
  void finishingANameMoveIsReportedAsAChangeWhenTheOutputFails() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, forking(v));
      String a = compromised(h, "orders");
      String b = reKey(h, a);
      change(h, a, k -> k.removeName("orders"));
      change(h, b, k -> k.activate());
      dev.keytend.kmip.kms.CustomAttribute record = pendingName("orders");
      change(h, b, k -> k.setCustomAttribute(record, "orders"));
      ByteArrayOutputStream err = new ByteArrayOutputStream();
      PrintStream broken =
          new PrintStream(
              new OutputStream() {
                @Override
                public void write(int x) throws IOException {
                  throw new IOException("standard output failed");
                }
              },
              true,
              StandardCharsets.UTF_8);
      Cli cli = h.cli(broken, new PrintStream(err, true, StandardCharsets.UTF_8));
      int code =
          cli.run(
              new String[] {
                "--config",
                h.config.toString(),
                "replace-compromised",
                a,
                "--compromised-at",
                "2026-10-01",
                "--yes"
              });
      assertEquals(ExitCode.FAILED.code, code);
      String text = err.toString(StandardCharsets.UTF_8);
      assertTrue(text.contains("the change was made (replaced compromised key " + a), text);
      assertEquals(List.of("orders"), h.server.names(b), "the move was finished");
    }
  }

  /** The SDK's record of a name being moved to a key (KeyHandle.pendingName). */
  static dev.keytend.kmip.kms.CustomAttribute pendingName(String name) throws Exception {
    byte[] digest =
        java.security.MessageDigest.getInstance("SHA-256")
            .digest(name.getBytes(StandardCharsets.UTF_8));
    return dev.keytend.kmip.kms.CustomAttribute.client(
        "keytend-pending-name-" + java.util.HexFormat.of().formatHex(digest, 0, 16));
  }
}
