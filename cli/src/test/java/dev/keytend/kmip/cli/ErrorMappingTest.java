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
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.ServerOperation;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Exit codes, messages and hints for server failures, the command line, output and the help. */
class ErrorMappingTest {
  @TempDir Path dir;

  @Test
  void serverFailuresMapToDocumentedExitCodes() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    h.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
    assertEquals(ExitCode.PERMISSION_DENIED.code, h.run("show", id));
    assertTrue(h.err().contains("hint: check the client identity of server group test"), h.err());

    h.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.NOT_FOUND);
    assertEquals(ExitCode.NOT_FOUND.code, h.run("show", id));

    h.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.SERVER_FAILURE);
    assertEquals(ExitCode.FAILED.code, h.run("show", id));

    h.server.failNext(ServerOperation.REVOKE, Fault.STATE_CONFLICT);
    assertEquals(ExitCode.STATE_CONFLICT.code, h.run("expire", id, "--yes"));

    h.server.failNext(ServerOperation.DESTROY, Fault.UNREACHABLE);
    h.ok("expire", id, "--yes");
    assertEquals(ExitCode.UNAVAILABLE.code, h.run("destroy", id, "--yes"));

    h.server.failNext(ServerOperation.DESTROY, Fault.REPLY_LOST);
    assertEquals(ExitCode.OUTCOME_UNKNOWN.code, h.run("destroy", id, "--yes"));
    // The command to check with keeps the --config of the command that failed.
    assertTrue(
        h.err()
            .contains(
                "hint: the change may or may not have been made; check the object with:"
                    + " keytend-kmip-cli --config "
                    + h.config
                    + " show "
                    + id),
        h.err());
  }

  @Test
  void anUnreachableServerFailsListClearly() throws IOException {
    Harness h = new Harness(dir);
    h.server.unreachable(true);
    assertEquals(ExitCode.UNAVAILABLE.code, h.run("list"));
    assertTrue(h.err().startsWith("error: "), h.err());
    assertTrue(h.err().contains("hint: check the endpoints"), h.err());
    assertEquals(ExitCode.UNAVAILABLE.code, h.run("list", "--json"));
    Map<String, Object> error = h.errorJson();
    assertEquals("unavailable", error.get("status"));
    assertEquals(8L, error.get("exitCode"));
    assertEquals("TransientException", error.get("exception"));
  }

  @Test
  void aPartialCompletionNamesWhatWasCreatedAndHowToFinish() throws IOException {
    Harness h = new Harness(dir);
    h.server.failNext(ServerOperation.ACTIVATE, Fault.SERVER_FAILURE);
    assertEquals(ExitCode.PARTIAL.code, h.run("create", "--name", "orders-kek", "--json"));
    Map<String, Object> error = h.errorJson();
    assertEquals("PARTIAL", error.get("category"));
    List<Object> created = Harness.list(error, "created");
    assertEquals(1, created.size());
    assertEquals(List.of(), Harness.list(error, "deactivated"));
    assertEquals(List.of(), Harness.list(error, "destroyed"));
    String id = (String) created.get(0);
    assertEquals(KeyState.PRE_ACTIVE, h.server.state(id).orElseThrow());
    // The hint names this tool's command, not an SDK method.
    String hint = (String) error.get("hint");
    assertTrue(hint.startsWith("created " + id + ". "), hint);
    assertTrue(hint.contains("keytend-kmip-cli --config " + h.config + " activate " + id), hint);
    h.ok("activate", id, "--yes");
    assertEquals(KeyState.ACTIVE, h.server.state(id).orElseThrow());
  }

  @Test
  void commandLineMistakesAreUsageErrors() throws IOException {
    Harness h = new Harness(dir);
    assertEquals(ExitCode.USAGE.code, h.run("frobnicate"));
    assertTrue(h.err().contains("unknown command frobnicate"));
    // An unknown option before the first word is the mistake named, not the word after it.
    assertEquals(ExitCode.USAGE.code, h.run("-yg", "x", "list"));
    assertTrue(h.err().startsWith("error: unknown option -yg"), h.err());
    assertEquals(ExitCode.USAGE.code, h.run());
    assertEquals(ExitCode.USAGE.code, h.run("list", "--bogus"));
    assertEquals(ExitCode.USAGE.code, h.run("--group", "staging", "list"));
    assertEquals(ExitCode.USAGE.code, h.run("--timeout", "later", "list"));
    assertEquals(ExitCode.USAGE.code, h.run("--config", dir.resolve("absent").toString(), "list"));
    // A setting the SDK refuses while connecting is a configuration error too.
    assertEquals(ExitCode.USAGE.code, h.run("--timeout", "0s", "list"));
    assertTrue(h.err().contains("server group test: "), h.err());
    // So is a value the SDK refuses before anything is sent.
    assertEquals(ExitCode.USAGE.code, h.run("create", "--name", "x", "--bits", "-8"));
    assertTrue(h.server.ids().isEmpty());
  }

  @Test
  void anIllegalArgumentAfterTheCommandLineIsAFailureNotAUsageError() {
    Cli.Failure f = Cli.Failure.of(new IllegalArgumentException("bad state"), null);
    assertEquals(ExitCode.FAILED, f.exit());
    assertEquals("bad state", f.message());
  }

  @Test
  void jsonModeComesFromTheParsedOptions() throws IOException {
    Harness h = new Harness(dir);
    // After --, --json is the identifier: the error is text.
    assertEquals(ExitCode.NOT_FOUND.code, h.run("show", "--", "--json"));
    assertEquals("", h.out());
    assertTrue(h.err().startsWith("error: "), h.err());
    // As an option's value, --json is that value: success and failure are both text.
    String id = h.create("orders-kek");
    String done = h.ok("revoke", id, "--reason", "superseded", "--message", "--json", "--yes");
    assertTrue(done.startsWith("Revoked " + id), done);
    assertEquals(
        ExitCode.NOT_FOUND.code,
        h.run("revoke", "no-such-id", "--reason", "superseded", "--message", "--json", "--yes"));
    assertEquals("", h.out());
    assertTrue(h.err().startsWith("error: "), h.err());
    // A command line that cannot be parsed: the scan stops at -- and skips option values.
    assertEquals(ExitCode.USAGE.code, h.run("list", "--bogus", "--json"));
    assertEquals("usage", h.errorJson().get("status"));
    assertEquals(ExitCode.USAGE.code, h.run("list", "--name", "--json", "--bogus"));
    assertEquals("", h.out());
    assertEquals(ExitCode.USAGE.code, h.run("list", "--bogus", "--", "--json"));
    assertEquals("", h.out());
  }

  /** A standard output that fails as a full disk or a closed pipe does. */
  private static PrintStream broken() {
    return new PrintStream(
        new OutputStream() {
          @Override
          public void write(int b) throws IOException {
            throw new IOException("disk full");
          }
        },
        true,
        StandardCharsets.UTF_8);
  }

  @Test
  void aFailedOutputIsAFailureAndSaysWhatWasChanged() throws IOException {
    Harness h = new Harness(dir);
    h.environment.put("V", "one");
    String secret = h.ok("register-secret", "--name", "secret", "--value-env", "V").strip();
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    Cli cli = h.cli(broken(), new PrintStream(err, true, StandardCharsets.UTF_8));
    String config = h.config.toString();
    // get-secret --stdout: the value was not delivered.
    assertEquals(
        ExitCode.FAILED.code,
        cli.run(new String[] {"--config", config, "get-secret", secret, "--stdout"}));
    assertTrue(
        err.toString(StandardCharsets.UTF_8).contains("could not write the output"),
        err.toString(StandardCharsets.UTF_8));
    // create: the key exists, and standard error says so, in text and JSON mode.
    for (String json : List.of("--yes", "--json")) {
      err.reset();
      int before = h.server.ids().size();
      assertEquals(
          ExitCode.FAILED.code,
          cli.run(new String[] {"--config", config, "create", "--name", "k" + json, json}));
      String text = err.toString(StandardCharsets.UTF_8);
      assertEquals(before + 1, h.server.ids().size());
      String id = h.server.ids().get(before);
      assertTrue(text.contains("error: could not write the output"), text);
      assertTrue(text.contains("the change was made (created key " + id + ", Active)"), text);
    }
  }

  @Test
  void theTimeoutOptionBoundsACall() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    h.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.HANG);
    Instant start = Instant.now();
    int code = h.run("--timeout", "1s", "show", id);
    Duration took = Duration.between(start, Instant.now());
    assertTrue(code == ExitCode.UNAVAILABLE.code || code == ExitCode.OUTCOME_UNKNOWN.code, h.err());
    assertTrue(took.compareTo(Duration.ofSeconds(15)) < 0, took.toString());
  }

  @Test
  void anAuthenticationRefusalKeepsTheSdkDetails() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("orders-kek");
    h.server.failNext(
        ServerOperation.GET_ATTRIBUTES, Enums.ResultReason.AUTHENTICATION_NOT_SUCCESSFUL);
    assertEquals(ExitCode.PERMISSION_DENIED.code, h.run("show", id, "--json"));
    Map<String, Object> error = h.errorJson();
    assertEquals("PermissionDeniedException", error.get("exception"));
    assertTrue(error.containsKey("serverReason"));
    assertNull(error.get("observedState"));
    assertFalse(error.containsKey("created"));
  }

  @Test
  void helpAndVersion() throws IOException {
    Harness h = new Harness(dir);
    assertEquals(0, h.run("--help"));
    for (Cli.Command c : Commands.ALL)
      assertTrue(h.out().contains("  " + c.name() + " "), c.name());
    assertTrue(h.out().contains("3 outcome unknown"), h.out());
    for (String line : h.out().split("\n"))
      assertTrue(line.length() <= Commands.WIDTH, "longer than the width: " + line);
    for (Cli.Command c : Commands.ALL) {
      assertEquals(0, h.run(c.name(), "--help"), c.name());
      String help = h.out();
      String words = help.replaceAll("\\s+", " ");
      assertTrue(help.startsWith("usage: keytend-kmip-cli " + c.name()), help);
      // Every option is described, and no line is wider than the help's width.
      for (Commands.Option o : c.options()) {
        assertTrue(help.contains(o.name()), c.name() + " lists " + o.name());
        assertTrue(words.contains(o.help()), c.name() + " describes " + o.name() + ": " + help);
      }
      for (Commands.Option o : Commands.GLOBAL) assertTrue(words.contains(o.help()), help);
      for (String line : help.split("\n"))
        assertTrue(line.length() <= Commands.WIDTH, c.name() + ": longer than the width: " + line);
    }
    assertEquals(0, h.run("--version"));
    assertTrue(h.out().startsWith("keytend-kmip-cli "));
    assertEquals(0, h.run("--version", "--json"));
    assertEquals(Set.of("version"), h.outJson().keySet(), h.out());
  }

  @Test
  void exitCodesAreDistinct() {
    Set<Integer> codes = new HashSet<>();
    for (ExitCode e : ExitCode.values()) assertTrue(codes.add(e.code), e.name());
    assertEquals(0, ExitCode.OK.code);
    assertEquals(3, ExitCode.OUTCOME_UNKNOWN.code);
  }
}
