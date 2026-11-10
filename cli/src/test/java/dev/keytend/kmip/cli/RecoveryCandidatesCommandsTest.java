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
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.kms.CompromisePlan;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.SecretData;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Through the commands: a key the lost Create made that cannot be read is never taken for absent;
 * register-secret --replace never adopts another caller's object after a lost Register; a lost
 * reply to the unlinked-key search is exit 8, not a plan conflict; a lost reply to the removal of
 * the temporary name is reported for what it was; and the JSON result says whether the plan could
 * search. Each loops over KMIP 1.4, 2.1 and 3.0.
 */
class RecoveryCandidatesCommandsTest {
  static final List<KmipVersion> VERSIONS = PlanBoundCommandsTest.VERSIONS;

  @TempDir Path dir;

  static boolean is(Ttlv request, Operation operation) {
    return PlanBoundCommandsTest.is(request, operation);
  }

  /** Whether {@code t} has a field that is exactly {@code id} (Text String, or 3.0 Reference). */
  static boolean refers(Ttlv t, String id) {
    if (t.type() == Ttlv.Type.TEXT_STRING
        || t.type() == Ttlv.Type.IDENTIFIER
        || t.type() == Ttlv.Type.REFERENCE) return id.equals(String.valueOf(t.value()));
    if (t.type() == Ttlv.Type.STRUCTURE) for (Ttlv c : t.children()) if (refers(c, id)) return true;
    return false;
  }

  static String newest(InMemoryKmipServer s) {
    List<String> ids = s.ids();
    return ids.get(ids.size() - 1);
  }

  /**
   * Re-key is refused, the fallback Create's reply is lost, and its key B is found by its temporary
   * name but cannot be read (object-level Permission Denied). Exit 7, keeping the revocation; the
   * message says the server could not be searched and names B, and never says to repeat. Once B can
   * be read, the repeat refuses (unlinked-replacement), naming B; one key was made.
   */
  @Test
  void aLostCreatesKeyThatCannotBeReadIsNeverTakenForAbsent() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = h.create("inc");
      AtomicBoolean armed = new AtomicBoolean(true);
      AtomicReference<String> hidden = new AtomicReference<>();
      h.before =
          r -> {
            if (armed.get() && is(r, Operation.RE_KEY))
              h.server.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
            else if (armed.get() && is(r, Operation.CREATE)) {
              armed.set(false);
              h.server.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
            } else if (is(r, Operation.LOCATE)
                && ForkAndRecoveryCommandsTest.mentions(r, "keytend-replacing-"))
              hidden.set(newest(h.server));
            String id = hidden.get();
            if (id != null && is(r, Operation.GET_ATTRIBUTES) && refers(r, id))
              h.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
          };
      int code =
          h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes", "--json");
      assertEquals(ExitCode.PARTIAL.code, code, v + " " + h.out());
      String b = hidden.get();
      assertNotNull(b, "the search ran");
      Map<String, Object> error = h.errorJson();
      assertEquals(List.of(a), Harness.list(error, "deactivated"));
      String message = Harness.text(error, "message");
      assertTrue(message.contains("could not be searched"), message);
      assertTrue(message.contains("it found " + b + ", which could not be read"), message);
      assertFalse(message.contains("to resume"), message);
      assertEquals(2, h.server.ids().size(), "the lost Create made one key");
      // The stop names B, and the hint says how to look at it (lineage does not show it).
      assertEquals(b, error.get("objectId"), error.toString());
      assertTrue(Harness.text(error, "hint").contains("show " + b), error.toString());

      // While B cannot be read, the plan names it, and never says that the server could not
      // be searched or that a list would show it (which these credentials cannot read).
      assertEquals(
          ExitCode.NOT_CONFIRMED.code,
          h.run("replace-compromised", a, "--compromised-at", "2026-10-01"));
      String plan = h.err();
      assertTrue(
          plan.contains("did not link found " + b + ", which these credentials cannot read"), plan);
      assertTrue(plan.contains("show " + b), plan);
      assertFalse(plan.contains("could not be searched"), plan);
      assertFalse(plan.contains("--state pre-active"), plan);
      assertEquals(2, h.server.ids().size(), "a plan changes nothing");

      hidden.set(null);
      h.before = null;
      code = h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes", "--json");
      assertEquals(ExitCode.STATE_CONFLICT.code, code, h.out());
      error = h.errorJson();
      assertEquals("unlinked-replacement", error.get("conflict"), error.toString());
      assertEquals(b, error.get("objectId"));
      assertEquals(2, h.server.ids().size(), "nothing created beside it");
    }
  }

  /**
   * register-secret --replace, its Register's reply lost. Before the command looks for its object
   * B, another caller replaces B under B's temporary name with its own secret C (Active, with that
   * name) and destroys B. Exit 3: C is not adopted, named or reported as registered; the old secret
   * keeps the name and stays Active.
   */
  @Test
  void anotherCallersSecretUnderTheTemporaryNameIsNeverAdopted() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      Path value = dir.resolve("value-" + v);
      Files.writeString(value, "wanted", StandardCharsets.UTF_8);
      String old =
          h.ok("register-secret", "--name", "db", "--value-file", value.toString()).strip();
      AtomicBoolean registering = new AtomicBoolean(true), searching = new AtomicBoolean(true);
      AtomicReference<String> theirs = new AtomicReference<>();
      h.before =
          r -> {
            if (is(r, Operation.REGISTER) && registering.getAndSet(false))
              h.server.failNext(ServerOperation.REGISTER, Fault.REPLY_LOST);
            else if (is(r, Operation.LOCATE)
                && ForkAndRecoveryCommandsTest.mentions(r, "db.replacing-")
                && searching.getAndSet(false)) {
              String made = newest(h.server);
              String temporary = h.server.names(made).get(0);
              try (Kms other = h.server.connect()) {
                theirs.set(
                    other
                        .keys()
                        .registerSecret(
                            SecretData.Type.PASSWORD,
                            "someone-else".getBytes(StandardCharsets.UTF_8))
                        .named(temporary)
                        .replace(other.keys().handle(made))
                        .id());
                other.protocol().call(Requests.destroy().uniqueIdentifier(made).build());
              } catch (java.io.IOException e) {
                throw new java.io.UncheckedIOException(e);
              }
            }
          };
      int code =
          h.run(
              "register-secret",
              "--name",
              "db",
              "--value-file",
              value.toString(),
              "--replace",
              old,
              "--yes",
              "--json");
      assertEquals(ExitCode.OUTCOME_UNKNOWN.code, code, v + " " + h.out());
      String c = theirs.get();
      assertNotNull(c, "the other caller replaced the lost Register's object");
      Map<String, Object> error = h.errorJson();
      assertTrue(Harness.text(error, "message").contains(c), h.out());
      // The stop names C, and the hint shows C, not the list of the name C lacks.
      assertEquals(c, error.get("objectId"), error.toString());
      String hint = Harness.text(error, "hint");
      assertTrue(hint.contains(old + " keeps the name db"), hint);
      assertTrue(hint.contains("show " + c), hint);
      assertFalse(hint.contains("list --name db"), hint);
      assertEquals(KeyState.ACTIVE, h.server.state(c).orElseThrow());
      assertFalse(h.server.names(c).contains("db"), "not given the name");
      assertEquals(KeyState.ACTIVE, h.server.state(old).orElseThrow());
      assertEquals(List.of("db"), h.server.names(old));
    }
  }

  /**
   * The plan searched for an earlier attempt's unlinked key, and the reply to the bound call's
   * search is lost. That is exit 8 (unavailable), nothing changed, not a plan conflict.
   */
  @Test
  void aLostReplyToTheUnlinkedKeySearchIsUnavailableNotAConflict() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = ForkAndRecoveryCommandsTest.compromised(h, "inc");
      AtomicInteger searches = new AtomicInteger();
      h.before =
          r -> {
            if (is(r, Operation.LOCATE)
                && ForkAndRecoveryCommandsTest.mentions(r, CompromisePlan.REPLACEMENT_RECORD.name())
                && searches.incrementAndGet() > 1)
              h.server.failNext(ServerOperation.LOCATE, Fault.REPLY_LOST);
          };
      int code =
          h.run("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes", "--json");
      assertEquals(ExitCode.UNAVAILABLE.code, code, v + " " + h.out());
      Map<String, Object> error = h.errorJson();
      assertFalse(error.containsKey("conflict"), error.toString());
      assertEquals(1, h.server.ids().size(), "nothing created");
      assertEquals(KeyState.COMPROMISED, h.server.state(a).orElseThrow());
    }
  }

  /**
   * Re-key is refused, the fallback Create's reply comes, and the reply to the removal of its
   * temporary name is lost. Reading back finds the name gone: recovered, the step in JSON naming
   * the replacement, and a warning that says what the step was rather than an activation. The JSON
   * says the plan could search.
   */
  @Test
  void aLostRemovalOfTheTemporaryNameIsReportedForWhatItWas() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = ForkAndRecoveryCommandsTest.compromised(h, "inc");
      AtomicBoolean created = new AtomicBoolean(), lost = new AtomicBoolean(true);
      h.before =
          r -> {
            if (is(r, Operation.RE_KEY))
              h.server.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
            else if (is(r, Operation.CREATE)) created.set(true);
            else if (created.get() && is(r, Operation.DELETE_ATTRIBUTE) && lost.getAndSet(false))
              h.server.failNext(ServerOperation.DELETE_ATTRIBUTE, Fault.REPLY_LOST);
          };
      Map<String, Object> r =
          h.json("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes");
      assertFalse(lost.get(), "the removal's reply was lost");
      String replacement = Harness.text(r, "replacement");
      assertEquals("recovered", r.get("action"), v + " " + r);
      assertEquals(List.of(replacement), Harness.list(r, "created"));
      assertEquals(replacement, Harness.object(r, "recoveredFrom").get("objectId"));
      String warning = Harness.text(r, "warning");
      assertTrue(
          warning.contains(
              "removing the temporary name from " + replacement + ", which this call created"),
          warning);
      assertFalse(warning.contains("was activated"), warning);
      assertEquals(true, r.get("checkedForUnlinkedKeys"));
      assertEquals(List.of("inc"), h.server.names(replacement));
    }
  }

  /**
   * Where the plan cannot search, the JSON says so in its own field, and the advice names the list
   * that shows such a key and how to recognize it.
   */
  @Test
  void anUncheckedPlanHasItsOwnJsonFieldAndAdviceToRecognizeTheKey() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = ForkAndRecoveryCommandsTest.compromised(h, "inc");
      h.before =
          r -> {
            if (is(r, Operation.LOCATE)
                && ForkAndRecoveryCommandsTest.mentions(
                    r, CompromisePlan.REPLACEMENT_RECORD.name()))
              h.server.failNext(
                  ServerOperation.LOCATE,
                  dev.keytend.kmip.model.Enums.ResultReason.GENERAL_FAILURE);
          };
      Map<String, Object> r =
          h.json("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes");
      assertEquals(false, r.get("checkedForUnlinkedKeys"), v + " " + r);
      String warning = Harness.text(r, "warning");
      assertTrue(warning.contains("list --kind symmetric-key --state pre-active"), warning);
      assertTrue(warning.contains(CompromisePlan.TEMPORARY_NAME_PREFIX + a + "-"), warning);
      assertTrue(warning.contains(CompromisePlan.REPLACEMENT_RECORD + " " + a), warning);
      // A key whose links the server refused is Active, with the names the key had.
      assertTrue(warning.contains("or Active with the names " + a + " had"), warning);
      assertEquals(List.of(), Harness.list(r, "unreadableCandidates"), r.toString());
    }
  }

  /**
   * The plan's search locates a key it cannot read, and the operator confirms anyway. The JSON
   * names it in its own field, and the warning names it and how to have it checked, rather than
   * saying the server could not be searched.
   */
  @Test
  void aCandidateThatCannotBeReadIsNamedInThePlanAndTheJson() throws Exception {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String a = ForkAndRecoveryCommandsTest.compromised(h, "inc");
      // An earlier attempt's key, Pre-Active and recording a, that these credentials cannot read.
      String b;
      try (Kms other = h.server.connect()) {
        b =
            other
                .keys()
                .createAes(256)
                .usages(
                    dev.keytend.kmip.kms.KeyUsage.ENCRYPT, dev.keytend.kmip.kms.KeyUsage.DECRYPT)
                .custom(CompromisePlan.REPLACEMENT_RECORD, a)
                .createPreActive()
                .id();
      }
      h.before =
          r -> {
            if (is(r, Operation.GET_ATTRIBUTES) && refers(r, b))
              h.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
          };
      Map<String, Object> r =
          h.json("replace-compromised", a, "--compromised-at", "2026-10-01", "--yes");
      assertEquals(false, r.get("checkedForUnlinkedKeys"), v + " " + r);
      assertEquals(List.of(b), Harness.list(r, "unreadableCandidates"), r.toString());
      String warning = Harness.text(r, "warning");
      assertTrue(warning.contains("found " + b + ", which these credentials cannot read"), warning);
      assertTrue(warning.contains("show " + b), warning);
      assertFalse(warning.contains("could not be searched"), warning);
    }
  }
}
