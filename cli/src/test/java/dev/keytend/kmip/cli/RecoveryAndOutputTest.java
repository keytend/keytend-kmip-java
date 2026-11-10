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

import dev.keytend.kmip.kms.KeyState;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Unknown outcomes and found replacements reported as they are, text output escaped everywhere,
 * plan-bound compromise replacement, kind checks before a plan, a raced activation, and the JSON
 * shapes the README lists. Each runs on KMIP 1.4, 2.1 and 3.0 where versions matter.
 */
class RecoveryAndOutputTest {
  static final List<KmipVersion> VERSIONS = PlanBoundCommandsTest.VERSIONS;

  @TempDir Path dir;

  static boolean is(Ttlv request, Operation operation) {
    return PlanBoundCommandsTest.is(request, operation);
  }

  static String uid(Ttlv request) {
    for (Ttlv item : request.children(Tag.BATCH_ITEM))
      for (Ttlv payload : item.children(Tag.REQUEST_PAYLOAD))
        for (Ttlv id : payload.children(Tag.UNIQUE_IDENTIFIER)) return id.textValue();
    return "";
  }

  // ---- a lost Create stays unknown ----

  /**
   * The Create's reply is lost, and the key it made is Pre-Active under the name. Without a
   * console, and with --yes, the command reports the unknown outcome (exit 3), never "nothing was
   * changed", and does not activate the key.
   */
  @Test
  void aLostCreateIsReportedAsUnknown() throws IOException {
    for (KmipVersion v : VERSIONS)
      for (boolean yes : List.of(false, true)) {
        Harness h = new Harness(dir, InMemoryKmipServer.of(v));
        h.server.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
        int code =
            yes
                ? h.run("create", "--name", "lost", "--if-absent", "--yes", "--json")
                : h.run("create", "--name", "lost", "--if-absent", "--json");
        assertEquals(ExitCode.OUTCOME_UNKNOWN.code, code, v + " " + h.out() + h.err());
        Map<String, Object> error = h.errorJson();
        assertFalse(
            error.get("message").toString().contains("nothing was changed"), v + " " + error);
        String hint = Harness.text(error, "hint");
        assertTrue(hint.contains("may have made a key with the name"), hint);
        assertTrue(hint.contains(" list --name lost"), hint);
        PlanBoundCommandsTest.assertNoJava(hint);
        String made = h.server.ids().get(0);
        assertEquals(KeyState.PRE_ACTIVE, h.server.state(made).orElseThrow(), v + " not activated");
        assertFalse(LifecycleCommandsTest.sent(h, Operation.ACTIVATE), v + " nothing activated");
      }
  }

  /** The Create's reply is lost, and the lookup that would recover it is refused: still exit 3. */
  @Test
  void aRefusedRecoveryLookupKeepsTheUnknownCreate() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      h.server.injectAfterProcessing(
          r -> {
            if (!is(r, Operation.CREATE)) return null;
            h.server.failNext(ServerOperation.LOCATE, Fault.PERMISSION_DENIED);
            return new IOException("reply lost");
          });
      assertEquals(
          ExitCode.OUTCOME_UNKNOWN.code,
          h.run("create", "--name", "lost", "--if-absent", "--json"),
          v + " " + h.out());
      h.server.injectAfterProcessing(null);
      assertEquals(1, h.server.ids().size(), v + ": the Create took effect");
    }
  }

  // ---- the confirmed activation is the SDK's last step ----

  /**
   * A staged key, confirmed with --yes, is activated by the SDK call that returns it: a read
   * refused after the Activate no longer hides the activation behind exit 5.
   */
  @Test
  void aConfirmedActivationIsReportedEvenIfALaterLookupWouldFail() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String staged = h.create("staged", "--pre-active");
      h.server.injectAfterProcessing(
          r -> {
            if (is(r, Operation.ACTIVATE))
              h.server.failNext(ServerOperation.LOCATE, Fault.PERMISSION_DENIED);
            return null;
          });
      Map<String, Object> json = h.json("create", "--name", "staged", "--if-absent", "--yes");
      h.server.injectAfterProcessing(null);
      assertEquals("activated", json.get("action"), v + " " + json);
      assertEquals(staged, json.get("id"));
      assertEquals(KeyState.ACTIVE, h.server.state(staged).orElseThrow());
    }
  }

  // ---- a recovered rotation's replacement is never claimed ----

  @Test
  void aFailureAfterARecoveredRotationDoesNotClaimTheReplacement() throws IOException {
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
                && uid(r).equals(theirs.get())
                && readsOfB.incrementAndGet() == 2)
              h.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
            return null;
          });
      int code = h.run("rotate", "raced", "--json");
      h.server.injectBeforeProcessing(null);
      assertEquals(ExitCode.PARTIAL.code, code, v + " " + h.out());
      Map<String, Object> error = h.errorJson();
      assertEquals(List.of(), Harness.list(error, "created"), v + " " + error);
      assertEquals(List.of(theirs.get()), Harness.list(error, "found"));
      assertNotNull(error.get("recoveredFrom"), error.toString());
      assertEquals(false, error.get("outcomeUnknown"));
      String hint = Harness.text(error, "hint");
      assertFalse(hint.contains("created " + theirs.get()), hint);
      assertTrue(hint.contains("this call or another caller made it"), hint);
      assertEquals(2, h.server.ids().size(), "only the other caller made a key");
    }
  }

  // ---- escaped text output ----

  /** Identifiers, plan lines, errors and hints carry no control or bidi character in text. */
  @Test
  void textOutputEscapesControlsInIdentifiersPlansAndErrors() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      AtomicInteger n = new AtomicInteger();
      h.server.identifierSource(() -> "key-\u001b[2J" + RLO + "-forged-" + n.incrementAndGet());
      String created = h.ok("create", "--name", "escape");
      assertClean(created + h.err());
      assertTrue(created.contains("key-\\u001b[2J\\u202e-forged-1"), created);
      h.ok("rotate", "escape", "--grace", "1d", "--yes");
      assertClean(h.out() + h.err());
      assertTrue(h.err().contains("Deactivation Date of key-\\u001b"), h.err());
      // A name with controls, refused as a duplicate: the error and its hint are escaped.
      String forged = "n\u001b[31m" + RLO;
      h.ok("create", "--name", forged);
      assertEquals(ExitCode.STATE_CONFLICT.code, h.run("create", "--name", forged));
      assertClean(h.out() + h.err());
      assertTrue(h.err().contains("error: "), h.err());
      // JSON keeps the values exact, escaped by the JSON writer.
      Map<String, Object> json = h.json("create", "--name", "exact", "--allow-duplicate-name");
      assertEquals("key-\u001b[2J" + RLO + "-forged-" + n.get(), json.get("id"));
      assertClean(h.out());
    }
  }

  /** U+202E, a bidi override, made at run time: in source it would be a bidi character itself. */
  static final String RLO = String.valueOf((char) 0x202E);

  static void assertClean(String text) {
    for (char c : text.toCharArray())
      if (c != '\n' && Values.unsafe(c))
        throw new AssertionError(
            String.format("raw U+%04X in the output: %s", (int) c, Values.safe(text)));
  }

  // ---- replace-compromised is bound to its plan ----

  @Test
  void anotherRespondersReplacementWhileTheConfirmationWaitsIsRefused() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String id = h.create("incident");
      PlanBoundCommandsTest.confirmAfter(
          h,
          () -> {
            try (Kms other = h.server.connect()) {
              other
                  .keys()
                  .handle(id)
                  .replaceCompromised(
                      RevocationReason.keyCompromise(
                          "theirs", Instant.parse("2026-01-01T00:00:00Z")));
            }
          });
      int objects = h.server.ids().size() + 1;
      int code = h.run("replace-compromised", id, "--compromised-at", "2026-10-01", "--json");
      assertEquals(ExitCode.STATE_CONFLICT.code, code, v + " " + h.out());
      Map<String, Object> error = h.errorJson();
      assertEquals("not-as-planned", error.get("conflict"), error.toString());
      String hint = Harness.text(error, "hint");
      assertTrue(hint.contains("another caller changed " + id), hint);
      PlanBoundCommandsTest.assertNoJava(hint);
      assertEquals(objects, h.server.ids().size(), "only the other responder made a key");
    }
  }

  @Test
  void aRotationWhileTheConfirmationWaitsIsRefused() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String id = h.create("incident");
      PlanBoundCommandsTest.confirmAfter(
          h,
          () -> {
            try (Kms other = h.server.connect()) {
              other.keys().handle(id).rotate();
            }
          });
      int code = h.run("replace-compromised", id, "--compromised-at", "2026-10-01", "--json");
      assertEquals(ExitCode.STATE_CONFLICT.code, code, v + " " + h.out());
      assertEquals("not-as-planned", h.errorJson().get("conflict"));
      assertEquals(KeyState.ACTIVE, h.server.state(id).orElseThrow(), "not revoked");
    }
  }

  /** The result says whether this call revoked the key, and the compromise date in effect. */
  @Test
  void theResultSaysWhoRevokedTheKeyAndWhichDateIsInEffect() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String id = h.create("incident");
      Map<String, Object> mine =
          h.json("replace-compromised", id, "--compromised-at", "2026-10-01", "--yes");
      assertEquals("replaced", mine.get("action"), v + " " + mine);
      assertEquals(true, mine.get("revoked"));
      assertEquals("2026-10-01T00:00:00Z", mine.get("compromiseOccurrenceDate"));
      assertEquals(List.of(mine.get("replacement")), Harness.list(mine, "created"));
      assertNull(mine.get("warning"));

      String other = h.create("earlier");
      try (Kms kms = h.server.connect()) {
        kms.keys()
            .handle(other)
            .revoke(
                RevocationReason.keyCompromise("theirs", Instant.parse("2026-01-01T00:00:00Z")));
      }
      Map<String, Object> theirs =
          h.json("replace-compromised", other, "--compromised-at", "2026-10-01", "--yes");
      assertEquals("completed", theirs.get("action"), theirs.toString());
      assertEquals(false, theirs.get("revoked"));
      assertEquals("2026-01-01T00:00:00Z", theirs.get("compromiseOccurrenceDate"));
      assertTrue(Harness.text(theirs, "warning").contains("keeps its first compromise's date"));
      Map<String, Object> again =
          h.json("replace-compromised", other, "--compromised-at", "2026-10-01", "--yes");
      assertEquals("existing", again.get("action"));
      assertEquals(List.of(), Harness.list(again, "created"));
    }
  }

  // ---- the wrong kind of object ----

  @Test
  void aSecretReplacementOfAKeyIsRefusedBeforeThePlan() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String key = h.create("db");
      Path value = dir.resolve("value-" + v);
      Files.writeString(value, "s3cret", StandardCharsets.UTF_8);
      int code =
          h.run(
              "register-secret",
              "--name",
              "db",
              "--value-file",
              value.toString(),
              "--replace",
              key,
              "--yes",
              "--json");
      assertEquals(ExitCode.USAGE.code, code, v + " " + h.out());
      assertFalse(h.err().contains("deactivates"), "no plan was shown: " + h.err());
      String hint = Harness.text(h.errorJson(), "hint");
      assertTrue(hint.contains(" list --name db"), hint);
      assertEquals(1, h.server.ids().size(), "nothing was registered");
      // A value file that does not exist: refused before the plan too.
      String secret =
          h.ok("register-secret", "--name", "pw", "--value-file", value.toString()).strip();
      code =
          h.run(
              "register-secret",
              "--name",
              "pw",
              "--value-file",
              dir.resolve("missing").toString(),
              "--replace",
              secret,
              "--yes");
      assertEquals(ExitCode.USAGE.code, code, h.err());
      assertFalse(h.err().contains("registers the new value"), "no plan was shown: " + h.err());
    }
  }

  @Test
  void anObjectOfTheWrongKindIsAUsageErrorWithAHint() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      Path value = dir.resolve("value-" + v);
      Files.writeString(value, "s3cret", StandardCharsets.UTF_8);
      String secret =
          h.ok("register-secret", "--name", "pw", "--value-file", value.toString()).strip();
      assertEquals(ExitCode.USAGE.code, h.run("rotate", "pw", "--json"), v + " " + h.out());
      String hint = Harness.text(h.errorJson(), "hint");
      assertTrue(hint.contains("register-secret"), hint);
      PlanBoundCommandsTest.assertNoJava(hint);
      assertFalse(Harness.text(h.errorJson(), "message").contains("()"), h.out());
      String key = h.create("k");
      assertEquals(
          ExitCode.USAGE.code,
          h.run("get-secret", key, "--out", dir.resolve("out-" + v).toString(), "--json"),
          h.out());
      hint = Harness.text(h.errorJson(), "hint");
      assertTrue(hint.contains("get-secret reads secrets"), hint);
      PlanBoundCommandsTest.assertNoJava(hint);
      assertEquals(List.of(secret, key), h.server.ids().subList(0, 2));
    }
  }

  // ---- a raced activation that reached its goal ----

  @Test
  void anActivationAnotherCallerMadeFirstIsNotAFailure() throws IOException {
    for (KmipVersion v : VERSIONS) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String id = h.create("staged", "--pre-active");
      PlanBoundCommandsTest.confirmAfter(
          h,
          () -> {
            try (Kms other = h.server.connect()) {
              other.keys().handle(id).activate();
            }
          });
      assertEquals(0, h.run("activate", id, "--json"), v + " " + h.out() + h.err());
      Map<String, Object> json = h.outJson();
      assertEquals("none", json.get("action"));
      assertEquals("active", json.get("state"));
      assertTrue(Harness.text(json, "warning").contains("another caller activated " + id));
    }
  }

  // ---- the JSON shapes the README lists ----

  @Test
  void theJsonShapesAreTheOnesTheReadmeLists() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("shape");
    Map<String, Object> show = h.json("show", id);
    assertEquals(SHOW, new TreeSet<>(show.keySet()), "show");
    String next = h.rotate("shape");
    Map<String, Object> shown = h.json("show", next);
    @SuppressWarnings("unchecked")
    Map<String, Object> first = (Map<String, Object>) Harness.list(shown, "links").get(0);
    assertEquals(Set.of("kind", "rawType", "target"), first.keySet(), "a link");
    Map<String, Object> lineage = h.json("lineage", "shape");
    assertEquals(Set.of("keys"), lineage.keySet());
    @SuppressWarnings("unchecked")
    Map<String, Object> key = (Map<String, Object>) Harness.list(lineage, "keys").get(0);
    assertEquals(LINEAGE_KEY, new TreeSet<>(key.keySet()), "a lineage key");
    Map<String, Object> servers = h.json("servers");
    assertEquals(Set.of("config", "defaultGroup", "groups"), servers.keySet());
    Path value = dir.resolve("value");
    Files.writeString(value, "s3cret", StandardCharsets.UTF_8);
    String secret =
        h.ok("register-secret", "--name", "pw", "--value-file", value.toString()).strip();
    Map<String, Object> got = h.json("get-secret", secret, "--out", dir.resolve("got").toString());
    assertEquals(Set.of("id", "type", "out", "bytes", "ownerOnly"), got.keySet());
  }

  /** show's fields, as README "JSON output" lists them. */
  static final Set<String> SHOW =
      new TreeSet<>(
          List.of(
              "id",
              "kind",
              "rawObjectType",
              "state",
              "rawState",
              "names",
              "algorithm",
              "rawAlgorithm",
              "length",
              "usages",
              "rawUsageMask",
              "creationDate",
              "activationDate",
              "deactivationDate",
              "processStartDate",
              "protectStopDate",
              "compromiseDate",
              "compromiseOccurrenceDate",
              "destroyDate",
              "leaseTime",
              "leaseTimeError",
              "objectGroups",
              "custom",
              "links",
              "extractable",
              "sensitive",
              "lineage",
              "lineageError"));

  /** The fields of each key lineage lists. */
  static final Set<String> LINEAGE_KEY =
      new TreeSet<>(
          List.of(
              "id",
              "state",
              "newest",
              "branch",
              "names",
              "replaced",
              "replacedBy",
              "joinedInto",
              "activationDate",
              "deactivationDate"));
}
