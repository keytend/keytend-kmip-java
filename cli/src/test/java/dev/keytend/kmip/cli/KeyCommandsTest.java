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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.LinkKind;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** info, list, show, lineage, create and rotate against the in-memory server. */
class KeyCommandsTest {
  @TempDir Path dir;

  /** Whether the request message has an item for {@code operation}. */
  static boolean has(Ttlv request, Operation operation) {
    for (Ttlv item : request.children(Tag.BATCH_ITEM))
      if (item.child(Tag.OPERATION).map(o -> o.intValue() == operation.code()).orElse(false))
        return true;
    return false;
  }

  @Test
  void infoShowsTheVersionAndTheServersAnswers() throws IOException {
    Harness h = new Harness(dir);
    String text = h.ok("info");
    assertTrue(text.matches("(?s).*KMIP version:\\s+2\\.1\\R.*"), text);
    assertTrue(text.contains("Server versions:"), text);
    assertTrue(text.contains("Operations:") && text.contains("Create"), text);
    Map<String, Object> json = h.json("ping");
    assertEquals("2.1", json.get("version"));
    assertTrue(Harness.list(json, "operations").contains("Create"), json.toString());
    assertTrue(Harness.list(json, "serverVersions").contains("2.1"), json.toString());
    assertNull(json.get("serverVersionsError"));
    assertNull(json.get("queryError"));
    assertTrue(json.get("serverInformation") instanceof Map, json.toString());
  }

  @Test
  void infoReportsARefusedQueryInItsOwnField() throws IOException {
    Harness h = new Harness(dir);
    h.server.failNext(ServerOperation.QUERY, Fault.UNSUPPORTED);
    Map<String, Object> json = h.json("info");
    assertNotNull(json.get("queryError"), json.toString());
    assertNull(json.get("operations"));
    assertNull(json.get("objectTypes"));
    assertNull(json.get("vendor"));
    assertNull(json.get("serverInformation"));
    assertTrue(Harness.list(json, "serverVersions").contains("2.1"), "versions still reported");
    h.server.failNext(ServerOperation.QUERY, Fault.PERMISSION_DENIED);
    String text = h.ok("info");
    assertTrue(text.contains("Query:") && text.contains("not answered: "), text);
  }

  @Test
  void listShowsReferenceColumnsAndFilters() throws IOException {
    Harness h = new Harness(dir);
    assertTrue(h.ok("list").contains("No objects match."));
    String orders =
        h.create("orders-kek", "--object-group", "payments", "--custom", "purpose=orders");
    String audit = h.create("audit-kek", "--bits", "128");
    String text = h.ok("list");
    assertTrue(text.startsWith("ID"), text);
    for (String column :
        List.of(
            "NAME",
            "KIND",
            "CIPHER",
            "STATE",
            "ACTIVATION DATE",
            "CREATION DATE",
            "PROTECT STOP DATE",
            "DEACTIVATION DATE",
            "OBJECT GROUP")) assertTrue(text.contains(column), column);
    assertTrue(text.contains("AES-256") && text.contains("AES-128"), text);
    assertTrue(text.contains("n/a"), "unset dates show as n/a: " + text);
    assertTrue(h.ok("list", "--name", "audit-kek").contains(audit));
    assertFalse(h.ok("list", "--name", "audit-kek").contains(orders));
    assertTrue(h.ok("list", "--object-group", "payments").contains(orders));
    assertFalse(h.ok("list", "--object-group", "payments").contains(audit));
    assertTrue(h.ok("list", "--custom", "x-purpose=orders").contains(orders));
    assertFalse(h.ok("list", "--custom", "purpose=orders").contains(audit));
    assertTrue(h.ok("list", "--state", "pre-active").contains("No objects match."));
    Map<String, Object> json =
        h.json("list", "--state", "active", "--kind", "symmetric-key", "--algorithm", "aes");
    assertEquals(2L, json.get("count"));
    for (Object o : Harness.list(json, "objects")) {
      @SuppressWarnings("unchecked")
      Map<String, Object> object = (Map<String, Object>) o;
      assertTrue(object.containsKey("protectStopDate"), object.toString());
      assertNull(object.get("protectStopDate"));
    }
    assertEquals(ExitCode.USAGE.code, h.run("list", "--state", "sleeping"));
    assertEquals(ExitCode.USAGE.code, h.run("list", "stray"));
  }

  @Test
  void showPrintsAttributesAndLineage() throws IOException {
    Harness h = new Harness(dir);
    String first = h.create("orders-kek", "--custom", "purpose=orders");
    String second = h.rotate("orders-kek");
    String text = h.ok("show", second);
    assertTrue(text.matches("(?s).*State:\\s+Active\\R.*"), text);
    assertTrue(text.matches("(?s).*Names:\\s+orders\\-kek\\R.*"), text);
    assertTrue(text.matches("(?s).*Custom:\\s+x\\-purpose=orders\\R.*"), text);
    assertTrue(text.contains("replaced -> " + first), text);
    assertTrue(text.contains("Lineage, newest first:"), text);
    assertTrue(text.indexOf(second) < text.lastIndexOf(first), text);
    Map<String, Object> json = h.json("show", first);
    assertEquals(first, json.get("id"));
    assertEquals(2, Harness.list(json, "lineage").size());
    assertNull(json.get("lineageError"));
    Map<String, Object> without = h.json("show", first, "--no-lineage");
    assertNull(without.get("lineage"));
    assertTrue(without.containsKey("lineage"), "one shape: lineage is null, not missing");
    assertEquals(ExitCode.NOT_FOUND.code, h.run("show", "no-such-id"));
    assertEquals(ExitCode.USAGE.code, h.run("show"));
  }

  @Test
  void showGivesTheRawCodesTheLeaseTimeAndEveryDate() throws IOException {
    Harness h = new Harness(dir);
    h.server.leaseTime(Duration.ofHours(1));
    String id = h.create("orders-kek");
    h.ok(
        "revoke",
        id,
        "--reason",
        "key-compromise",
        "--compromised-at",
        "2026-10-01T00:00:00Z",
        "--yes");
    Map<String, Object> json = h.json("show", id);
    assertEquals("symmetric-key", json.get("kind"));
    assertEquals(2L, json.get("rawObjectType"));
    assertEquals("compromised", json.get("state"));
    assertEquals(4L, json.get("rawState"));
    assertEquals("AES", json.get("algorithm"));
    assertEquals(3L, json.get("rawAlgorithm"));
    assertEquals(12L, json.get("rawUsageMask"));
    assertEquals("PT1H", json.get("leaseTime"));
    assertNull(json.get("leaseTimeError"));
    assertEquals("2026-10-01T00:00:00Z", json.get("compromiseOccurrenceDate"));
    for (String field : List.of("processStartDate", "protectStopDate", "compromiseDate"))
      assertTrue(json.containsKey(field), field);
    String text = h.ok("show", id);
    assertTrue(text.matches("(?s).*Lease time:\\s+PT1H\\R.*"), text);
    assertTrue(text.matches("(?s).*Compromise occurred:\\s+2026-10-01T00:00:00Z\\R.*"), text);
  }

  @Test
  void showReportsALineageItCannotReadAndStillShowsTheKey() throws IOException {
    Harness h = new Harness(dir);
    String mine = h.create("mine");
    String stranger = h.create("stranger");
    RegressionTest.oneSidedLink(h, mine, stranger);
    Map<String, Object> json = h.json("show", mine);
    assertEquals(mine, json.get("id"));
    assertNull(json.get("lineage"));
    assertNotNull(json.get("lineageError"));
    assertTrue(h.ok("show", mine).contains("Lineage:"), h.out());
  }

  @Test
  void textOutputEscapesControlAndBidiCharactersFromTheServer() throws IOException {
    Harness h = new Harness(dir);
    String evil = "kek" + (char) 0x1b + "[31m" + (char) 0x202e + "evil" + (char) 0x85;
    String id = h.create(evil, "--custom", "note=a" + (char) 0x07 + "b");
    for (String text : List.of(h.ok("list"), h.ok("show", id), h.ok("lineage", "--id", id))) {
      for (int c : new int[] {0x1b, 0x202e, 0x85, 0x07})
        assertEquals(-1, text.indexOf(c), "raw " + c + " in " + text);
    }
    assertTrue(h.ok("list").contains("kek\\u001b[31m\\u202eevil\\u0085"), h.out());
    assertTrue(h.ok("show", id).contains("a\\u0007b"), h.out());
    // JSON escapes them too, and keeps the value.
    assertEquals(List.of(evil), Harness.list(h.json("show", id), "names"));
    assertEquals(-1, h.out().indexOf(0x1b));
    assertEquals(-1, h.out().indexOf(0x202e));
  }

  @Test
  void lineageByNameOrIdentifier() throws IOException {
    Harness h = new Harness(dir);
    String first = h.create("orders-kek");
    h.ok("rotate", "orders-kek");
    String text = h.ok("lineage", "orders-kek");
    assertTrue(text.contains(first) && text.contains("yes"), text);
    for (String column : List.of("BRANCH", "JOINED INTO")) assertTrue(text.contains(column), text);
    List<Object> keys = Harness.list(h.json("lineage", "--id", first), "keys");
    @SuppressWarnings("unchecked")
    Map<String, Object> newest = (Map<String, Object>) keys.get(0);
    assertEquals(true, newest.get("newest"));
    assertEquals(ExitCode.NOT_FOUND.code, h.run("lineage", "unknown-name"));
  }

  @Test
  void createPrintsTheIdentifierAndFindsOrCreates() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    assertEquals(KeyState.ACTIVE, h.server.state(id).orElseThrow());
    assertEquals(List.of("orders-kek"), h.server.names(id));
    Map<String, Object> again = h.json("create", "--name", "orders-kek", "--if-absent");
    assertEquals("found", again.get("action"));
    assertEquals(List.of(), Harness.list(again, "created"));
    assertEquals(id, again.get("id"));
    assertEquals(id, Harness.object(again, "key").get("id"));
    String other = h.create("orders-kek", "--allow-duplicate-name");
    assertNotEquals(id, other, "--allow-duplicate-name makes another key with the name");
    Map<String, Object> fresh = h.json("create", "--name", "new-kek", "--if-absent");
    assertEquals("created", fresh.get("action"));
    assertEquals(List.of(fresh.get("id")), Harness.list(fresh, "created"));
    String pre = h.create("staged", "--pre-active", "--usage", "wrap-key,unwrap-key");
    assertEquals(KeyState.PRE_ACTIVE, h.server.state(pre).orElseThrow());
    assertTrue(h.err().contains("Created " + pre), h.err());
    assertEquals(
        ExitCode.USAGE.code, h.run("create", "--name", "x", "--if-absent", "--pre-active"));
    assertEquals(ExitCode.USAGE.code, h.run("create", "--if-absent"));
    assertEquals(ExitCode.USAGE.code, h.run("create", "--name", "x", "--bits", "many"));
    assertEquals(ExitCode.USAGE.code, h.run("create", "--name", "x", "--usage", "fly"));
    assertEquals(ExitCode.USAGE.code, h.run("create", "--name", "x", "--algorithm", "rot13"));
  }

  @Test
  void createRefusesATakenNameWithoutIfAbsent() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    assertEquals(ExitCode.STATE_CONFLICT.code, h.run("create", "--name", "orders-kek"));
    assertTrue(h.err().contains("the name orders-kek is taken by " + id), h.err());
    assertTrue(h.err().contains("--if-absent") && h.err().contains("rotate orders-kek"), h.err());
    assertEquals(1, h.server.ids().size(), "no second key was created");
    // A name that only non-Active keys hold is taken too; a destroyed key's is not.
    h.ok("expire", id, "--yes");
    assertEquals(ExitCode.STATE_CONFLICT.code, h.run("create", "--name", "orders-kek"));
    h.ok("destroy", id, "--yes");
    String next = h.create("orders-kek");
    assertNotEquals(id, next);
    assertEquals(
        ExitCode.USAGE.code,
        h.run("create", "--name", "orders-kek", "--if-absent", "--allow-duplicate-name"));
    assertEquals(ExitCode.USAGE.code, h.run("create", "--allow-duplicate-name"));
  }

  @Test
  void createIfAbsentConfirmsBeforeActivatingAPreActiveKey() throws IOException {
    // A staged key was activated without a plan, and reported as created.
    Harness h = new Harness(dir);
    String staged = h.create("orders-kek", "--pre-active");
    assertEquals(
        ExitCode.NOT_CONFIRMED.code, h.run("create", "--name", "orders-kek", "--if-absent"));
    assertTrue(h.err().contains("activates " + staged), h.err());
    assertTrue(h.err().contains("starts its cryptoperiod"), h.err());
    assertEquals(KeyState.PRE_ACTIVE, h.server.state(staged).orElseThrow());
    Map<String, Object> json = h.json("create", "--name", "orders-kek", "--if-absent", "--yes");
    assertEquals("activated", json.get("action"));
    assertEquals(staged, json.get("id"));
    assertEquals(List.of(), Harness.list(json, "created"));
    assertEquals(KeyState.ACTIVE, h.server.state(staged).orElseThrow());
    assertEquals(1, h.server.ids().size());
    // Found from then on, without a question.
    assertEquals("found", h.json("create", "--name", "orders-kek", "--if-absent").get("action"));
  }

  @Test
  void createIfAbsentRefusesANameWhoseKeysAreOnlyDeactivated() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    h.ok("expire", id, "--yes");
    assertEquals(
        ExitCode.STATE_CONFLICT.code, h.run("create", "--name", "orders-kek", "--if-absent"));
    assertTrue(h.err().contains("hint: see the objects with the name: keytend-kmip-cli"), h.err());
    assertTrue(h.err().contains("list --name orders-kek"), h.err());
    assertEquals(1, h.server.ids().size());
  }

  @Test
  void createIfAbsentReportsAKeyAnotherCallerCreated() throws IOException {
    // The name was provisioned by another caller between the SDK's look and its Create. The
    // other key ranks first: it is returned, and the key this call made is reported, Pre-Active.
    Harness h = new Harness(dir);
    AtomicBoolean armed = new AtomicBoolean();
    h.server.injectAfterProcessing(
        request -> {
          if (has(request, Operation.LOCATE) && armed.compareAndSet(false, true)) {
            try (Kms other = h.server.connect()) {
              other
                  .keys()
                  .createAes(256)
                  .named("race")
                  .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                  .create();
            }
          }
          return null;
        });
    Map<String, Object> json = h.json("create", "--name", "race", "--if-absent");
    h.server.injectAfterProcessing(null);
    assertEquals(2, h.server.ids().size());
    assertEquals("found", json.get("action"));
    List<Object> created = Harness.list(json, "created");
    assertEquals(1, created.size());
    assertEquals(KeyState.PRE_ACTIVE, h.server.state((String) created.get(0)).orElseThrow());
    assertTrue(Harness.text(json, "warning").contains("it is left Pre-Active"), json.toString());
  }

  @Test
  void aCreatedKeyWhoseDisplayReadFailsIsStillASuccess() throws IOException {
    // The read that only shows the new key failed, and turned a creation into exit 5.
    Harness h = new Harness(dir);
    AtomicBoolean armed = new AtomicBoolean();
    h.server.injectAfterProcessing(
        request -> {
          if (has(request, Operation.ACTIVATE) && armed.compareAndSet(false, true))
            h.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
          return null;
        });
    Map<String, Object> json = h.json("create", "--name", "read-fail");
    String id = h.server.ids().get(0);
    assertEquals(KeyState.ACTIVE, h.server.state(id).orElseThrow());
    assertEquals(id, json.get("id"));
    assertEquals("created", json.get("action"));
    assertEquals(List.of(id), Harness.list(json, "created"));
    assertNull(json.get("key"));
    assertTrue(
        ((String) json.get("warning")).contains("reading it back to show it failed"),
        json.toString());
    // In text, the identifier is still the standard output.
    armed.set(false);
    String text = h.ok("create", "--name", "read-fail-2").strip();
    assertTrue(h.server.exists(text), text);
    assertTrue(h.err().contains("warning: "), h.err());
  }

  @Test
  void anUnknownCreateOutcomeSuggestsListingTheName() throws IOException {
    // The hint said "show new-name", a name where an identifier belongs.
    Harness h = new Harness(dir);
    h.server.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
    assertEquals(ExitCode.OUTCOME_UNKNOWN.code, h.run("create", "--name", "new-name", "--json"));
    String hint = (String) h.errorJson().get("hint");
    assertTrue(
        hint.contains("keytend-kmip-cli --config " + h.config + " list --name new-name"), hint);
    assertFalse(hint.contains("show new-name"), hint);
    // A value a shell would split or expand is quoted.
    h.server.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
    assertEquals(
        ExitCode.OUTCOME_UNKNOWN.code, h.run("--group", "test", "create", "--name", "it's $HOME"));
    assertTrue(h.err().contains("--group test list --name 'it'\\''s $HOME'"), h.err());
  }

  @Test
  void rotateWithGraceShowsItsPlanAndNeedsAConfirmation() throws IOException {
    Harness h = new Harness(dir);
    String first = h.create("orders-kek");
    assertEquals(ExitCode.NOT_CONFIRMED.code, h.run("rotate", "orders-kek", "--grace", "7d"));
    assertTrue(h.err().contains("rotate orders-kek: " + first), "the plan comes first: " + h.err());
    assertTrue(h.err().contains("sets the Deactivation Date of " + first), h.err());
    assertTrue(h.err().contains("(7d from now)"), "the operator's own duration: " + h.err());
    assertEquals(List.of("orders-kek"), h.server.names(first), "nothing was rotated");
    assertEquals(1, h.server.ids().size());
    assertNull(
        h.json("show", first, "--no-lineage").get("deactivationDate"), "nothing was scheduled");

    h.terminal.interactive = true;
    h.terminal.lines.add("no");
    assertEquals(ExitCode.NOT_CONFIRMED.code, h.run("rotate", "orders-kek", "--grace", "0s"));
    assertTrue(h.err().contains("deactivates " + first + " at once"), h.err());
    assertEquals(KeyState.ACTIVE, h.server.state(first).orElseThrow());

    h.terminal.lines.add("yes");
    Map<String, Object> json = h.json("rotate", "orders-kek", "--grace", "0s");
    String second = (String) json.get("current");
    assertEquals(List.of("orders-kek"), h.server.names(second));
    Object date = h.json("show", first, "--no-lineage").get("deactivationDate");
    assertNotNull(date, "--grace 0s set the old key's Deactivation Date");
    assertEquals(date, json.get("previousDeactivationDate"), "the date read back is reported");

    // A rotation without --grace changes no existing key's state, and asks nothing.
    h.terminal.interactive = false;
    h.ok("rotate", "orders-kek");
    assertEquals(KeyState.ACTIVE, h.server.state(second).orElseThrow());
  }

  @Test
  void rotateWithConditionAndGrace() throws IOException {
    Harness h = new Harness(dir);
    String first = h.create("orders-kek");
    String notDue = h.ok("rotate", "orders-kek", "--if-active-for", "30d");
    assertEquals(
        "Not due: " + first + " has been Active for less than 30d; nothing changed.\n",
        notDue.replace("\r\n", "\n"));
    String notDueWithGrace =
        h.ok("rotate", "orders-kek", "--if-active-for", "30d", "--grace", "7d", "--yes");
    assertTrue(notDueWithGrace.startsWith("Not due: " + first), notDueWithGrace);
    assertTrue(h.err().contains("if it has been Active for 30d"), h.err());
    Map<String, Object> notDueJson = h.json("rotate", "orders-kek", "--if-active-for", "30d");
    assertEquals("not-due", notDueJson.get("action"));
    assertEquals(false, notDueJson.get("rotated"));
    assertEquals(first, notDueJson.get("current"));
    assertNull(notDueJson.get("previousDeactivationDate"));

    Map<String, Object> json = h.json("rotate", "orders-kek", "--grace", "7d", "--yes");
    assertEquals("rotated", json.get("action"));
    assertEquals(true, json.get("rotated"));
    assertEquals("7d", json.get("grace"));
    String second = (String) json.get("current");
    assertEquals(first, json.get("previous"));
    assertEquals(List.of("orders-kek"), h.server.names(second));
    assertEquals(List.of(first), h.server.links(second, LinkKind.REPLACED));
    Object scheduled = h.json("show", first, "--no-lineage").get("deactivationDate");
    assertNotNull(scheduled, "the grace period scheduled the deactivation");
    assertEquals(scheduled, json.get("previousDeactivationDate"));
    assertEquals(KeyState.ACTIVE, h.server.state(first).orElseThrow());
    String third = h.ok("rotate", "orders-kek", "--shifted-dates");
    assertTrue(third.contains("Rotated orders-kek: " + second + " -> "), third);
    // Zero is always due.
    Map<String, Object> due = h.json("rotate", "orders-kek", "--if-active-for", "0s");
    assertEquals("rotated", due.get("action"));
    assertEquals(ExitCode.NOT_FOUND.code, h.run("rotate", "unknown-kek"));
  }

  @Test
  void conditionalRotationRefusesWhenAnotherCallerRotatedMeanwhile() throws IOException {
    // Another caller rotated while the confirmation waited. The plan named the
    // old key, so the command refuses instead of acting on the new one, and changes nothing.
    Harness h = new Harness(dir);
    String old = h.create("rotation-race");
    h.terminal.interactive = true;
    h.terminal.lines.add("yes");
    String[] theirs = new String[1];
    h.terminal.beforeAnswer =
        () -> {
          try (Kms kms = h.server.connect()) {
            theirs[0] = kms.keys().handle(old).rotate().id();
          }
        };
    assertEquals(
        ExitCode.STATE_CONFLICT.code,
        h.run("rotate", "rotation-race", "--grace", "7d", "--if-active-for", "30d", "--json"));
    assertEquals(theirs[0], h.errorJson().get("objectId"), "the current key is named");
    assertEquals(2, h.server.ids().size(), "this call made no key");
    try (Kms kms = h.server.connect()) {
      assertTrue(kms.keys().handle(old).attributes().deactivationDate().isEmpty());
      assertTrue(kms.keys().handle(theirs[0]).attributes().deactivationDate().isEmpty());
    }
  }

  @Test
  void worksOnKmip14And30() throws IOException {
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V3_0)) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String id = h.create("orders-kek");
      assertEquals(v.toString(), h.json("info").get("version"));
      assertTrue(h.ok("list").contains(id), v.toString());
      h.ok("rotate", "orders-kek");
      assertTrue(h.ok("show", id).contains("Lineage, newest first:"), v.toString());
      assertEquals("found", h.json("create", "--name", "orders-kek", "--if-absent").get("action"));
    }
  }

  @Test
  void anUnavailableEndpointIsSaidOnceInTheErrorAndTheSdkLineIsOff() throws IOException {
    Harness h = new Harness(dir);
    h.create("orders-kek");
    // An endpoint label of its own: the SDK's rate limit of its WARN lines is per label, across the
    // JVM, and other tests use in-memory:5696.
    h.endpointLabel = "stderr-check:5696";
    h.server.unreachable(true);
    // slf4j-simple writes to System.err as it is at each line (logFile=System.err).
    java.io.PrintStream saved = System.err;
    java.io.ByteArrayOutputStream logged = new java.io.ByteArrayOutputStream();
    int code;
    System.setErr(new java.io.PrintStream(logged, true, java.nio.charset.StandardCharsets.UTF_8));
    try {
      code = h.run("list");
    } finally {
      System.setErr(saved);
    }
    assertEquals(ExitCode.UNAVAILABLE.code, code, h.err());
    String sdk = logged.toString(java.nio.charset.StandardCharsets.UTF_8);
    assertFalse(sdk.contains("dev.keytend.kmip.kms.Endpoints"), sdk);
    List<String> lines = h.err().lines().toList();
    assertTrue(lines.get(0).startsWith("error: "), h.err());
    assertTrue(lines.stream().noneMatch(l -> l.startsWith("warning:")), h.err());
    assertEquals(1, lines.stream().filter(l -> l.startsWith("error: ")).count(), h.err());
  }

  @Test
  void failsOverToTheNextEndpoint() throws IOException {
    Harness h = new Harness(dir);
    InMemoryKmipServer replica = h.withReplica();
    String id = h.create("orders-kek");
    h.server.unreachable(true);
    assertTrue(h.ok("list").contains(id), h.out());
    assertEquals(
        "warning: KMS endpoint in-memory:5696 was unavailable; another endpoint served the"
            + " command: ",
        h.err().lines().findFirst().orElse("").replaceFirst("command: .*", "command: "),
        h.err());
    assertEquals(1, h.err().lines().count(), h.err());
    assertEquals(id, h.json("show", id).get("id"));
    String at =
        Instant.now()
            .plus(Duration.ofDays(10))
            .truncatedTo(java.time.temporal.ChronoUnit.SECONDS)
            .toString();
    assertEquals(at, h.json("expire", id, "--at", at, "--yes").get("deactivationDate"));
    assertTrue(replica.exchanges() > 0, "the replica answered");
    h.server.unreachable(false);
    assertEquals(at, h.json("show", id, "--no-lineage").get("deactivationDate"));
  }

  /** Re-key through the protocol layer: a second rotation of {@code id}, which leaves a branch. */
  static String reKey(Kms kms, String id) throws IOException {
    return kms.protocol().call(Requests.reKey().uniqueIdentifier(id).build()).uniqueIdentifier();
  }
}
