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

import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.kms.RetryPolicy;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.ZoneOffset;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Runs the tool against an {@link InMemoryKmipServer}: a configuration file with the group {@code
 * test} (the server, through a connector that skips TLS), captured output and a scripted console.
 * A group with two endpoints ({@link #withReplica()}) connects to the server and a replica of it,
 * one per endpoint, so that failover between them is real.
 */
final class Harness {
  static final String CONFIG =
      "default-group = test\n"
          + "group.test.endpoints = in-memory:5696\n"
          + "group.test.identity.type = pem\n"
          + "group.test.identity.certificate = client.pem\n"
          + "group.test.identity.key = client-key.pem\n"
          + "group.test.trust.type = system\n";

  final InMemoryKmipServer server;
  final Path dir;
  final Path config;
  final Map<String, String> environment = new HashMap<>();
  final ScriptedTerminal terminal = new ScriptedTerminal();

  /** The tool's clock: the system's, unless a test sets another. */
  Clock clock = Clock.systemUTC();

  private InMemoryKmipServer replica;

  /**
   * The server's endpoint label in the SDK's events and logs, when a test needs one of its own
   * (the SDK's log rate limit is per label, across the JVM); null for {@code in-memory:5696}.
   */
  String endpointLabel;

  private ByteArrayOutputStream out = new ByteArrayOutputStream();
  private ByteArrayOutputStream err = new ByteArrayOutputStream();
  private byte[] lastOut = new byte[0];

  Harness(Path dir) throws IOException {
    this(dir, InMemoryKmipServer.of(KmipVersion.V2_1));
  }

  Harness(Path dir, InMemoryKmipServer server) throws IOException {
    this.server = server;
    this.dir = dir;
    this.config = dir.resolve("cli.properties");
    Files.writeString(config, CONFIG, StandardCharsets.UTF_8);
  }

  /**
   * Gives the group a second endpoint, {@code in-memory-2:5696}, served by a replica of the server.
   *
   * @return the replica
   */
  InMemoryKmipServer withReplica() throws IOException {
    replica = server.replica();
    Files.writeString(
        config,
        CONFIG.replace("in-memory:5696", "in-memory:5696, in-memory-2:5696"),
        StandardCharsets.UTF_8);
    return replica;
  }

  /**
   * What sees each request the tool sends, on the tool's thread before the server does (one
   * server, no replica); null for none. A test arms faults or acts as another caller here.
   */
  java.util.function.Consumer<dev.keytend.kmip.model.Ttlv> before;

  /** Connects as the tool does, to the endpoints of the group: the server, and the replica. */
  Connector connector() {
    return (group, secrets, listener) -> {
      KmsConfig.Builder builder =
          group.endpoints().size() > 1 && replica != null
              ? server.configureReplicas(replica)
              : server.configure().retryPolicy(RetryPolicy.none());
      java.util.function.Consumer<dev.keytend.kmip.model.Ttlv> sees = before;
      if (sees != null && replica == null)
        builder.transport(
            e ->
                r -> {
                  sees.accept(r);
                  return server.exchange(r);
                });
      if (endpointLabel != null) builder.endpoints(endpointLabel);
      return Kms.connect(group.settings(builder).addListener(listener).build());
    };
  }

  /** The tool, writing to {@code out} and {@code err}. */
  Cli cli(PrintStream out, PrintStream err) {
    return new Cli(out, err, terminal, environment, clock, ZoneOffset.UTC, connector());
  }

  /** Runs one command line with --config set; returns the exit code. */
  int run(String... args) {
    out = new ByteArrayOutputStream();
    err = new ByteArrayOutputStream();
    List<String> argv = new ArrayList<>(List.of("--config", config.toString()));
    argv.addAll(List.of(args));
    Cli cli =
        cli(
            new PrintStream(out, true, StandardCharsets.UTF_8),
            new PrintStream(err, true, StandardCharsets.UTF_8));
    int code = cli.run(argv.toArray(String[]::new));
    lastOut = out.toByteArray();
    return code;
  }

  /** Runs a command that must succeed, and returns its standard output. */
  String ok(String... args) {
    int code = run(args);
    if (code != 0)
      throw new AssertionError(
          "exit " + code + " for " + List.of(args) + "\nout: " + out() + "\nerr: " + err());
    return out();
  }

  /** Runs a command with --json that must succeed, and returns its parsed result. */
  Map<String, Object> json(String... args) {
    List<String> argv = new ArrayList<>(List.of(args));
    argv.add("--json");
    ok(argv.toArray(String[]::new));
    return JsonReader.object(out());
  }

  /** The parsed JSON of the last command's standard output. */
  Map<String, Object> outJson() {
    return JsonReader.object(out());
  }

  /** The {@code error} object of the last command's JSON output. */
  @SuppressWarnings("unchecked")
  Map<String, Object> errorJson() {
    Object error = outJson().get("error");
    if (!(error instanceof Map)) throw new AssertionError("no error object in " + out());
    return (Map<String, Object>) error;
  }

  String out() {
    return new String(lastOut, StandardCharsets.UTF_8);
  }

  byte[] outBytes() {
    return lastOut.clone();
  }

  String err() {
    return err.toString(StandardCharsets.UTF_8);
  }

  /** A key created through the tool: its identifier (the first line of create's output). */
  String create(String name, String... more) {
    List<String> argv = new ArrayList<>(List.of("create", "--name", name));
    argv.addAll(List.of(more));
    return ok(argv.toArray(String[]::new)).strip();
  }

  /** Rotates the key {@code name} leads to through the tool, and returns the new key. */
  String rotate(String name) {
    return (String) json("rotate", name).get("current");
  }

  /** The string {@code field} of a parsed JSON object, which must have it. */
  static String text(Map<String, Object> json, String field) {
    if (!json.containsKey(field)) throw new AssertionError("no field " + field + " in " + json);
    return (String) json.get(field);
  }

  /** The array {@code field} of a parsed JSON object, which must have it. */
  @SuppressWarnings("unchecked")
  static List<Object> list(Map<String, Object> json, String field) {
    if (!json.containsKey(field)) throw new AssertionError("no field " + field + " in " + json);
    return (List<Object>) json.get(field);
  }

  /** The object {@code field} of a parsed JSON object, which must have it. */
  @SuppressWarnings("unchecked")
  static Map<String, Object> object(Map<String, Object> json, String field) {
    if (!json.containsKey(field)) throw new AssertionError("no field " + field + " in " + json);
    return (Map<String, Object>) json.get(field);
  }

  /** A console whose answers the test scripts; {@link #beforeAnswer} runs before each answer. */
  static final class ScriptedTerminal implements Terminal {
    boolean interactive;
    final Deque<String> lines = new ArrayDeque<>();
    final Deque<String> passwords = new ArrayDeque<>();
    final List<String> prompts = new ArrayList<>();

    /** Runs when the tool asks for a line, before the answer: another caller acting meanwhile. */
    Runnable beforeAnswer = () -> {};

    @Override
    public boolean interactive() {
      return interactive;
    }

    @Override
    public String readLine(String prompt) {
      prompts.add(prompt);
      beforeAnswer.run();
      return lines.poll();
    }

    @Override
    public char[] readPassword(String prompt) {
      prompts.add(prompt);
      String p = passwords.poll();
      return p == null ? null : p.toCharArray();
    }
  }
}
