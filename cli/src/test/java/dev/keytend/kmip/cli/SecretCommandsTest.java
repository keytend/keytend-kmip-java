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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.model.Attributes;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** register-secret and get-secret: values never on the command line, never echoed. */
class SecretCommandsTest {
  private static final String SECRET = "db-s3cret-Pa55";

  @TempDir Path dir;

  @Test
  void registersFromAFileAndReadsItBackIntoAnOwnerOnlyFile() throws IOException {
    Harness h = new Harness(dir);
    Path value = dir.resolve("value.txt");
    Files.writeString(value, SECRET + "\n", StandardCharsets.UTF_8);
    String id =
        h.ok("register-secret", "--name", "db-password", "--value-file", value.toString()).strip();
    assertEquals(List.of("db-password"), h.server.names(id));
    assertFalse(h.out().contains(SECRET) || h.err().contains(SECRET));
    Path out = dir.resolve("read.txt");
    String json = h.ok("get-secret", id, "--out", out.toString(), "--json");
    assertEquals("password", JsonReader.object(json).get("type"));
    assertFalse(json.contains(SECRET), json);
    assertEquals(
        SECRET, Files.readString(out, StandardCharsets.UTF_8), "the final line break is dropped");
    if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
      assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(out)));
      assertEquals(true, JsonReader.object(json).get("ownerOnly"));
    }
    assertEquals(ExitCode.USAGE.code, h.run("get-secret", id, "--out", out.toString()));
  }

  @Test
  void registersFromTheEnvironmentAndWritesToStandardOutput() throws IOException {
    Harness h = new Harness(dir);
    h.environment.put("NEW_DB_PASSWORD", SECRET);
    String id =
        h.ok("register-secret", "--name", "db-password", "--value-env", "NEW_DB_PASSWORD").strip();
    h.ok("get-secret", id, "--stdout");
    assertArrayEquals(SECRET.getBytes(StandardCharsets.UTF_8), h.outBytes());
    assertEquals(ExitCode.USAGE.code, h.run("get-secret", id, "--stdout", "--json"));
    assertEquals(ExitCode.USAGE.code, h.run("get-secret", id));
    assertEquals(
        ExitCode.USAGE.code,
        h.run("register-secret", "--name", "x", "--value-env", "UNSET_VARIABLE"));
  }

  @Test
  void asksTwiceAtTheConsole() throws IOException {
    Harness h = new Harness(dir);
    h.terminal.interactive = true;
    h.terminal.passwords.add(SECRET);
    h.terminal.passwords.add(SECRET + "x");
    assertEquals(
        ExitCode.USAGE.code, h.run("register-secret", "--name", "db-password", "--value-prompt"));
    assertTrue(h.err().contains("differ"), h.err());
    assertTrue(h.server.ids().isEmpty(), "nothing was registered");
    h.terminal.passwords.add(SECRET);
    h.terminal.passwords.add(SECRET);
    String id = h.ok("register-secret", "--name", "db-password", "--value-prompt").strip();
    assertEquals(KeyState.ACTIVE, h.server.state(id).orElseThrow());
  }

  @Test
  void aSecretIsNeverACommandLineValue() throws IOException {
    Harness h = new Harness(dir);
    assertEquals(
        ExitCode.USAGE.code, h.run("register-secret", "--name", "db-password", "--value", SECRET));
    assertEquals(ExitCode.USAGE.code, h.run("register-secret", "--name", "db-password", SECRET));
    assertEquals(ExitCode.USAGE.code, h.run("register-secret", "--name", "db-password"));
    assertFalse(h.err().contains(SECRET), "a stray value is not repeated: " + h.err());
    assertTrue(h.server.ids().isEmpty());
  }

  @Test
  void registersASeedAsItsExactBytes() throws IOException {
    Harness h = new Harness(dir);
    byte[] seed = {0, 1, 2, '\n'};
    Path value = dir.resolve("seed.bin");
    Files.write(value, seed);
    String id =
        h.ok(
                "register-secret",
                "--name",
                "seed",
                "--type",
                "seed",
                "--value-file",
                value.toString())
            .strip();
    h.ok("get-secret", id, "--stdout");
    assertArrayEquals(seed, h.outBytes());
  }

  @Test
  void replaceMovesTheNameAndDeactivatesTheOldSecret() throws IOException {
    Harness h = new Harness(dir);
    h.environment.put("V1", "one");
    h.environment.put("V2", "two");
    String old = h.ok("register-secret", "--name", "db-password", "--value-env", "V1").strip();
    assertEquals(
        ExitCode.NOT_CONFIRMED.code,
        h.run("register-secret", "--name", "db-password", "--value-env", "V2", "--replace", old));
    assertTrue(h.err().contains("deactivates " + old), h.err());
    assertEquals(1, h.server.ids().size(), "nothing was registered before the confirmation");
    String json =
        h.ok(
            "register-secret",
            "--name",
            "db-password",
            "--value-env",
            "V2",
            "--replace",
            old,
            "--yes",
            "--json");
    Map<String, Object> parsed = JsonReader.object(json);
    String id = (String) parsed.get("id");
    assertEquals(old, parsed.get("replaced"));
    assertEquals(List.of("db-password"), h.server.names(id));
    assertTrue(h.server.names(old).isEmpty());
    assertEquals(KeyState.DEACTIVATED, h.server.state(old).orElseThrow());
  }

  /**
   * A secret that is not Active (here past its Deactivation Date: Deactivated) gives up its name
   * the same way and keeps its state; a destroyed one is refused before the confirmation.
   */
  @Test
  void replaceTakesTheNameFromASecretThatIsNotActive() throws IOException {
    Harness h = new Harness(dir);
    h.environment.put("V1", "one");
    h.environment.put("V2", "two");
    String old = h.ok("register-secret", "--name", "db-password", "--value-env", "V1").strip();
    try (var kms = h.server.connect()) {
      kms.keys().handle(old).deactivate();
    }
    assertEquals(
        ExitCode.NOT_CONFIRMED.code,
        h.run("register-secret", "--name", "db-password", "--value-env", "V2", "--replace", old));
    assertTrue(h.err().contains("leaves " + old + " "), h.err());
    assertFalse(h.err().contains("deactivates " + old), h.err());
    Map<String, Object> parsed =
        JsonReader.object(
            h.ok(
                "register-secret",
                "--name",
                "db-password",
                "--value-env",
                "V2",
                "--replace",
                old,
                "--yes",
                "--json"));
    String id = (String) parsed.get("id");
    assertEquals(old, parsed.get("replaced"));
    assertEquals(List.of("db-password"), h.server.names(id));
    assertTrue(h.server.names(old).isEmpty());
    assertEquals(KeyState.DEACTIVATED, h.server.state(old).orElseThrow());
    assertEquals(KeyState.ACTIVE, h.server.state(id).orElseThrow());

    // Destroyed: refused before the plan, nothing registered.
    String gone = h.ok("register-secret", "--name", "token", "--value-env", "V1").strip();
    try (var kms = h.server.connect()) {
      kms.keys().handle(gone).deactivate();
      kms.keys().handle(gone).destroy();
    }
    int objects = h.server.ids().size();
    assertEquals(
        ExitCode.STATE_CONFLICT.code,
        h.run("register-secret", "--name", "token", "--value-env", "V2", "--replace", gone));
    assertFalse(h.err().contains("registers the new value"), "no plan: " + h.err());
    assertEquals(objects, h.server.ids().size(), "nothing was registered");
  }

  /**
   * The replacement acts on the state its plan showed. Another caller activates the Pre-Active
   * secret while the confirmation waits: the plan said it would be left Pre-Active, so it is not
   * deactivated; the command is refused (exit 6) and nothing is registered. A Pre-Active secret
   * with an Activation Date has the plan say what happens when that date passes.
   */
  @Test
  void aReplacementRefusesAStateChangedWhileTheConfirmationWaits() throws IOException {
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0)) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      h.environment.put("V2", "two");
      String old;
      try (Kms admin = h.server.connect()) {
        old =
            admin
                .keys()
                .registerSecret("one".toCharArray())
                .named("db-password")
                .registerPreActive()
                .id();
      }
      int objects = h.server.ids().size();
      h.terminal.interactive = true;
      h.terminal.lines.add("yes");
      h.terminal.beforeAnswer =
          () -> {
            try (Kms other = h.server.connect()) {
              other.keys().handle(old).activate();
            }
          };
      assertEquals(
          ExitCode.STATE_CONFLICT.code,
          h.run("register-secret", "--name", "db-password", "--value-env", "V2", "--replace", old),
          v + ": " + h.err());
      assertTrue(h.err().contains("leaves " + old), h.err());
      assertTrue(
          h.err().contains("changed while the confirmation waited (its state or Activation Date)"),
          h.err());
      assertEquals(objects, h.server.ids().size(), v + ": nothing was registered");
      assertEquals(KeyState.ACTIVE, h.server.state(old).orElseThrow(), v + ": not deactivated");
      assertEquals(List.of("db-password"), h.server.names(old), v.toString());
    }
  }

  /**
   * The plan showed a Pre-Active secret without an Activation Date, which it leaves
   * Pre-Active. Another caller gives it a date while the confirmation waits, the state unchanged;
   * that date passes while the new secret is activated. Bound only to the state, the replacement
   * deactivated the old secret against its plan (exit 0). Bound to the plan, it is refused (exit 6)
   * before anything is registered, and the old secret keeps its name and its state.
   */
  @Test
  void aReplacementRefusesAnActivationDateAddedWhileTheConfirmationWaits() throws IOException {
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0)) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      PlanBoundCommandsTest.MovableClock clock =
          new PlanBoundCommandsTest.MovableClock(Instant.now().truncatedTo(ChronoUnit.SECONDS));
      h.server.clock(clock);
      h.environment.put("V2", "two");
      String old = preActive(h, null);
      int objects = h.server.ids().size();
      h.server.injectBeforeProcessing(
          r -> {
            if (PlanBoundCommandsTest.is(r, Operation.ACTIVATE))
              clock.now = clock.now.plus(Duration.ofHours(2));
            return null;
          });
      PlanBoundCommandsTest.confirmAfter(
          h, () -> activationDate(h, old, clock.now.plus(Duration.ofHours(1))));
      assertEquals(
          ExitCode.STATE_CONFLICT.code,
          h.run("register-secret", "--name", "db-password", "--value-env", "V2", "--replace", old),
          v + ": " + h.err());
      h.server.injectBeforeProcessing(null);
      assertTrue(h.err().contains("leaves " + old + " Pre-Active."), h.err());
      assertFalse(h.err().contains("It activates at its Activation Date"), h.err());
      assertTrue(h.err().contains("not no Activation Date"), h.err());
      assertTrue(
          h.err().contains("changed while the confirmation waited (its state or Activation Date)"),
          h.err());
      assertEquals(objects, h.server.ids().size(), v + ": nothing was registered");
      assertEquals(KeyState.PRE_ACTIVE, h.server.state(old).orElseThrow(), v + ": left alone");
      assertEquals(List.of("db-password"), h.server.names(old), v.toString());
    }
  }

  /**
   * The plan showed the Activation Date, and that the secret is deactivated if the date makes it
   * Active by the time the name has moved: the date passes while the new secret is activated, so
   * it is, and the command says so.
   */
  @Test
  void aSecretWhoseConfirmedActivationDatePassesIsDeactivated() throws IOException {
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0)) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      PlanBoundCommandsTest.MovableClock clock =
          new PlanBoundCommandsTest.MovableClock(Instant.now().truncatedTo(ChronoUnit.SECONDS));
      h.server.clock(clock);
      h.environment.put("V2", "two");
      String old = preActive(h, clock.now.plus(Duration.ofHours(1)));
      h.server.injectBeforeProcessing(
          r -> {
            if (PlanBoundCommandsTest.is(r, Operation.ACTIVATE))
              clock.now = clock.now.plus(Duration.ofHours(2));
            return null;
          });
      PlanBoundCommandsTest.confirmAfter(h, () -> {});
      assertEquals(
          ExitCode.OK.code,
          h.run("register-secret", "--name", "db-password", "--value-env", "V2", "--replace", old),
          v + ": " + h.err());
      h.server.injectBeforeProcessing(null);
      assertTrue(h.err().contains("It activates at its Activation Date"), h.err());
      assertTrue(h.err().contains(old + " is deactivated"), h.err());
      assertEquals(KeyState.DEACTIVATED, h.server.state(old).orElseThrow(), v.toString());
      assertEquals(List.of(), h.server.names(old), v.toString());
    }
  }

  /** A Pre-Active secret named db-password, with {@code activation} as its Activation Date. */
  private static String preActive(Harness h, Instant activation) {
    String old;
    try (Kms admin = h.server.connect()) {
      old =
          admin
              .keys()
              .registerSecret("one".toCharArray())
              .named("db-password")
              .registerPreActive()
              .id();
    }
    if (activation != null) activationDate(h, old, activation);
    return old;
  }

  /** Adds an Activation Date to {@code id}, as another caller may. */
  private static void activationDate(Harness h, String id, Instant date) {
    try (Kms other = h.server.connect()) {
      other
          .protocol()
          .call(
              Requests.addAttribute()
                  .uniqueIdentifier(id)
                  .attribute(
                      Attributes.attribute(
                          "Activation Date", Ttlv.dateTime(Tag.ACTIVATION_DATE, date)))
                  .build());
    } catch (IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
  }

  @Test
  void aPreActiveSecretWithAnActivationDateHasThePlanSaySo() throws IOException {
    Harness h = new Harness(dir);
    h.environment.put("V2", "two");
    String old;
    try (Kms admin = h.server.connect()) {
      old =
          admin
              .keys()
              .registerSecret("one".toCharArray())
              .named("db-password")
              .registerPreActive()
              .id();
      admin
          .protocol()
          .call(
              Requests.addAttribute()
                  .uniqueIdentifier(old)
                  .attribute(
                      Attributes.attribute(
                          "Activation Date",
                          Ttlv.dateTime(
                              Tag.ACTIVATION_DATE,
                              Instant.now()
                                  .plus(Duration.ofDays(1))
                                  .truncatedTo(ChronoUnit.SECONDS))))
                  .build());
    }
    assertEquals(
        ExitCode.NOT_CONFIRMED.code,
        h.run("register-secret", "--name", "db-password", "--value-env", "V2", "--replace", old));
    assertTrue(h.err().contains("leaves " + old + " Pre-Active"), h.err());
    assertTrue(h.err().contains("It activates at its Activation Date"), h.err());
    String json =
        h.ok(
            "register-secret",
            "--name",
            "db-password",
            "--value-env",
            "V2",
            "--replace",
            old,
            "--yes",
            "--json");
    assertEquals(old, JsonReader.object(json).get("replaced"));
    assertEquals(KeyState.PRE_ACTIVE, h.server.state(old).orElseThrow(), "its date is later");
  }

  @Test
  void aSecondSecretWithATakenNameIsRefused() throws IOException {
    // A second register-secret under a name left readers on the first value.
    Harness h = new Harness(dir);
    h.environment.put("V1", "one");
    h.environment.put("V2", "two");
    String first = h.ok("register-secret", "--name", "db-pass", "--value-env", "V1").strip();
    assertEquals(
        ExitCode.STATE_CONFLICT.code,
        h.run("register-secret", "--name", "db-pass", "--value-env", "V2"));
    assertTrue(h.err().contains(first), h.err());
    assertTrue(h.err().contains("--replace OLD_ID"), h.err());
    assertEquals(List.of(first), h.server.ids(), "nothing was registered");
    // A key's name counts too.
    String key = h.create("kek");
    assertEquals(
        ExitCode.STATE_CONFLICT.code,
        h.run("register-secret", "--name", "kek", "--value-env", "V2"));
    assertEquals(List.of(first, key), h.server.ids());
    // --allow-duplicate-name registers another anyway; it does not go with --replace.
    String second =
        h.ok("register-secret", "--name", "db-pass", "--value-env", "V2", "--allow-duplicate-name")
            .strip();
    assertEquals(List.of("db-pass"), h.server.names(second));
    assertEquals(
        ExitCode.USAGE.code,
        h.run(
            "register-secret",
            "--name",
            "db-pass",
            "--value-env",
            "V2",
            "--replace",
            first,
            "--allow-duplicate-name",
            "--yes"));
  }

  @Test
  void getSecretRefusesAnExistingFileAndASymbolicLink() throws IOException {
    // The file was created, then opened again by name.
    Harness h = new Harness(dir);
    h.environment.put("V", SECRET);
    String id = h.ok("register-secret", "--name", "db", "--value-env", "V").strip();
    Path existing = dir.resolve("existing.txt");
    Files.writeString(existing, "keep", StandardCharsets.UTF_8);
    assertEquals(ExitCode.USAGE.code, h.run("get-secret", id, "--out", existing.toString()));
    assertEquals("keep", Files.readString(existing, StandardCharsets.UTF_8));
    Path link = dir.resolve("link.txt");
    Path dangling = dir.resolve("dangling.txt");
    try {
      Files.createSymbolicLink(link, existing);
      Files.createSymbolicLink(dangling, dir.resolve("nowhere.txt"));
    } catch (UnsupportedOperationException | IOException noLinks) {
      return; // a file system without symbolic links
    }
    assertEquals(ExitCode.USAGE.code, h.run("get-secret", id, "--out", link.toString()));
    assertEquals("keep", Files.readString(existing, StandardCharsets.UTF_8));
    assertEquals(ExitCode.USAGE.code, h.run("get-secret", id, "--out", dangling.toString()));
    assertFalse(Files.exists(dir.resolve("nowhere.txt")), "the link was not followed");
    assertFalse(h.out().contains(SECRET) || h.err().contains(SECRET));
  }
}
