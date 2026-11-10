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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.keytend.kmip.kms.KmipVersion;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The configuration file, the servers command and secret handling. */
class ConfigTest {
  private static final String PASSWORD = "p12-s3cret-value";
  private static final String ENV_PASSWORD = "env-s3cret-value";

  static final String TWO_GROUPS =
      "default-group = prod\n"
          + "group.prod.description = Production KMS\n"
          + "group.prod.endpoints = kms1.example.com:5696, kms2.example.com:5696\n"
          + "group.prod.identity.type = pkcs12\n"
          + "group.prod.identity.file = certs/operator.p12\n"
          + "group.prod.identity.password-file = operator.pass\n"
          + "group.prod.trust.type = pem\n"
          + "group.prod.trust.file = certs/ca.pem\n"
          + "group.prod.timeout = 30s\n"
          + "group.prod.connect-timeout = 5s\n"
          + "group.prod.min-version = 1.4\n"
          + "group.prod.max-version = 2.1\n"
          + "group.prod.cipher-suites = TLS_AES_256_GCM_SHA384,"
          + " TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n"
          + "group.dr.endpoints = kms-dr.example.com:5696\n"
          + "group.dr.identity.type = jks\n"
          + "group.dr.identity.file = /etc/kms/operator.jks\n"
          + "group.dr.identity.password-env = DR_KEYSTORE_PASSWORD\n"
          + "group.dr.trust.type = pkcs12\n"
          + "group.dr.trust.file = /etc/kms/trust.p12\n"
          + "group.dr.trust.password-prompt = true\n";

  private static Path write(Path dir, String text) throws IOException {
    Path file = dir.resolve("cli.properties");
    Files.writeString(file, text, StandardCharsets.UTF_8);
    return file;
  }

  @Test
  void readsGroupsAndResolvesRelativePaths(@TempDir Path dir) throws IOException {
    Config config = Config.load(write(dir, TWO_GROUPS));
    assertEquals("prod", config.defaultGroup);
    assertEquals(List.of("dr", "prod"), List.copyOf(config.groups.keySet()));
    ServerGroup prod = config.group(null);
    assertEquals("prod", prod.name());
    assertEquals(List.of("kms1.example.com:5696", "kms2.example.com:5696"), prod.endpoints());
    assertEquals(
        dir.resolve("certs/operator.p12").toAbsolutePath().normalize(),
        prod.identity().file().toAbsolutePath());
    assertEquals(ServerGroup.IdentityType.PKCS12, prod.identity().type());
    assertEquals(ServerGroup.TrustType.PEM, prod.trust().type());
    assertEquals(Secrets.Source.Kind.FILE, prod.identity().password().kind());
    assertEquals(Duration.ofSeconds(30), prod.timeout());
    assertEquals(KmipVersion.V1_4, prod.minimumVersion());
    assertEquals(2, prod.cipherSuites().size());
    ServerGroup dr = config.group("dr");
    assertEquals(ServerGroup.IdentityType.JKS, dr.identity().type());
    assertEquals(Secrets.Source.Kind.ENV, dr.identity().password().kind());
    assertEquals(ServerGroup.TrustType.PKCS12, dr.trust().type());
    assertEquals(Secrets.Source.Kind.PROMPT, dr.trust().password().kind());
    assertNull(dr.timeout());
  }

  @Test
  void choosesTheOnlyGroupWithoutADefault(@TempDir Path dir) throws IOException {
    Config config = Config.load(write(dir, Harness.CONFIG.replace("default-group = test\n", "")));
    assertEquals("test", config.group(null).name());
  }

  @Test
  void needsAGroupNameWhenSeveralAndNoDefault(@TempDir Path dir) throws IOException {
    Config config = Config.load(write(dir, TWO_GROUPS.replace("default-group = prod\n", "")));
    CliException e = assertThrows(CliException.class, () -> config.group(null));
    assertTrue(e.hint.contains("dr, prod"), e.hint);
    assertThrows(CliException.class, () -> config.group("staging"));
  }

  @Test
  void refusesInlinePasswords(@TempDir Path dir) throws IOException {
    Path file = write(dir, TWO_GROUPS + "group.prod.identity.password = hunter2\n");
    CliException e = assertThrows(CliException.class, () -> Config.load(file));
    assertEquals(ExitCode.USAGE, e.exit);
    assertTrue(
        e.getMessage().contains("password-file, password-env or password-prompt"), e.getMessage());
    assertFalse(e.getMessage().contains("hunter2"));
    Path trust = write(dir, TWO_GROUPS + "group.dr.trust.password = hunter2\n");
    assertThrows(CliException.class, () -> Config.load(trust));
  }

  @Test
  void refusesMistakes(@TempDir Path dir) throws IOException {
    for (String broken :
        List.of(
            TWO_GROUPS + "group.prod.timout = 5s\n",
            TWO_GROUPS + "color = blue\n",
            TWO_GROUPS.replace("group.dr.endpoints = kms-dr.example.com:5696\n", ""),
            TWO_GROUPS.replace("default-group = prod", "default-group = staging"),
            TWO_GROUPS.replace("group.prod.identity.password-file = operator.pass\n", ""),
            TWO_GROUPS + "group.prod.identity.password-env = X\n",
            TWO_GROUPS.replace("identity.type = pkcs12", "identity.type = p12"),
            TWO_GROUPS.replace("group.prod.trust.type = pem", "group.prod.trust.type = system"),
            TWO_GROUPS.replace("max-version = 2.1", "max-version = 9.9"),
            TWO_GROUPS.replace("timeout = 30s", "timeout = soon"))) {
      Path file = write(dir, broken);
      assertEquals(
          ExitCode.USAGE, assertThrows(CliException.class, () -> Config.load(file), broken).exit);
    }
  }

  @Test
  void aMissingFileIsAUsageErrorWithAHint(@TempDir Path dir) {
    CliException e =
        assertThrows(CliException.class, () -> Config.load(dir.resolve("absent.properties")));
    assertEquals(ExitCode.USAGE, e.exit);
    assertTrue(e.hint.contains("--config"));
  }

  @Test
  void serversRedactsSecretsInTextAndJson(@TempDir Path dir) throws IOException {
    Files.writeString(dir.resolve("operator.pass"), PASSWORD + "\n", StandardCharsets.UTF_8);
    Harness h = new Harness(dir);
    Files.writeString(h.config, TWO_GROUPS, StandardCharsets.UTF_8);
    h.environment.put("DR_KEYSTORE_PASSWORD", ENV_PASSWORD);
    String text = h.ok("servers");
    assertTrue(text.contains("prod (default)"), text);
    assertTrue(
        text.contains("kms1.example.com:5696, kms2.example.com:5696 (tried in this order)"), text);
    assertTrue(text.contains("password from file " + dir.resolve("operator.pass")), text);
    assertTrue(text.contains("password from environment variable DR_KEYSTORE_PASSWORD"), text);
    assertTrue(text.contains("password from console prompt"), text);
    String json = h.ok("servers", "--json");
    assertEquals("prod", JsonReader.object(json).get("defaultGroup"));
    String one = h.ok("groups", "dr", "--json");
    assertFalse(one.contains("kms1.example.com"), one);
    // servers NAME: that group only; settings left to their default are null.
    Map<String, Object> dr = group(JsonReader.object(one), 0);
    assertEquals("dr", dr.get("name"));
    assertEquals(false, dr.get("default"));
    for (String field :
        List.of(
            "description",
            "timeout",
            "connectTimeout",
            "minimumVersion",
            "maximumVersion",
            "cipherSuites")) {
      assertTrue(dr.containsKey(field), field);
      assertNull(dr.get(field), field);
    }
    assertEquals(1, Harness.list(JsonReader.object(one), "groups").size());
    Map<String, Object> prod = group(JsonReader.object(json), 1);
    assertEquals("prod", prod.get("name"));
    assertEquals("PT30S", prod.get("timeout"));
    assertEquals(2, Harness.list(prod, "cipherSuites").size());
    String drText = h.ok("servers", "dr");
    assertTrue(drText.contains("dr\n") || drText.contains("dr\r\n"), drText);
    assertTrue(drText.matches("(?s).*timeout:\\s+default\\R.*"), drText);
    for (String output : List.of(text, json, one, h.err())) {
      assertFalse(output.contains(PASSWORD), output);
      assertFalse(output.contains(ENV_PASSWORD), output);
    }
    assertEquals(ExitCode.USAGE.code, h.run("servers", "staging"));
  }

  @Test
  void readsSecretsFromFilesEnvironmentAndConsole(@TempDir Path dir) throws IOException {
    Path file = dir.resolve("pass");
    Files.writeString(file, "line-one\r\n", StandardCharsets.UTF_8);
    Harness.ScriptedTerminal terminal = new Harness.ScriptedTerminal();
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    Secrets secrets =
        new Secrets(
            Map.of("PW", "from-env"), terminal, new PrintStream(err, true, StandardCharsets.UTF_8));
    assertArrayEquals("line-one".toCharArray(), secrets.chars(Secrets.Source.file(file), "p"));
    assertArrayEquals(
        "line-one\r\n".getBytes(StandardCharsets.UTF_8),
        secrets.bytes(Secrets.Source.file(file), "p"));
    assertArrayEquals("from-env".toCharArray(), secrets.chars(Secrets.Source.env("PW"), "p"));
    assertThrows(CliException.class, () -> secrets.chars(Secrets.Source.env("MISSING"), "p"));
    assertThrows(CliException.class, () -> secrets.chars(Secrets.Source.prompt(), "p"));
    terminal.interactive = true;
    terminal.passwords.add("typed");
    assertArrayEquals("typed".toCharArray(), secrets.chars(Secrets.Source.prompt(), "p"));
    assertThrows(
        CliException.class, () -> secrets.chars(Secrets.Source.file(dir.resolve("none")), "p"));
  }

  @Test
  void theRealConnectorReadsTheGroupsPasswordSource(@TempDir Path dir) throws IOException {
    // No password file: the TLS connector stops before any connection, as a configuration error.
    Path file = write(dir, TWO_GROUPS);
    Harness.ScriptedTerminal terminal = new Harness.ScriptedTerminal();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    ByteArrayOutputStream err = new ByteArrayOutputStream();
    Cli cli =
        new Cli(
            new PrintStream(out, true, StandardCharsets.UTF_8),
            new PrintStream(err, true, StandardCharsets.UTF_8),
            terminal,
            Map.of(),
            java.time.Clock.systemUTC(),
            java.time.ZoneOffset.UTC,
            Connector.tls());
    assertEquals(ExitCode.USAGE.code, cli.run(new String[] {"--config", file.toString(), "info"}));
    assertTrue(
        err.toString(StandardCharsets.UTF_8)
            .contains("cannot read " + dir.resolve("operator.pass")),
        err.toString(StandardCharsets.UTF_8));
    assertEquals(
        ExitCode.USAGE.code,
        cli.run(new String[] {"--config", file.toString(), "-g", "dr", "list"}));
    assertTrue(
        err.toString(StandardCharsets.UTF_8).contains("DR_KEYSTORE_PASSWORD is not set"),
        err.toString(StandardCharsets.UTF_8));
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> group(Map<String, Object> servers, int index) {
    return (Map<String, Object>) Harness.list(servers, "groups").get(index);
  }
}
