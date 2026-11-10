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

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The configuration file: named server groups and the default group, in Java properties format
 * (UTF-8). See the README for the keys. Relative paths are resolved against the file's directory.
 */
final class Config {
  private static final Pattern GROUP_KEY = Pattern.compile("group\\.([A-Za-z0-9_-]+)\\.(.+)");
  private static final Set<String> GROUP_SETTINGS =
      Set.of(
          "description",
          "endpoints",
          "identity.type",
          "identity.file",
          "identity.certificate",
          "identity.key",
          "identity.password-file",
          "identity.password-env",
          "identity.password-prompt",
          "trust.type",
          "trust.file",
          "trust.password-file",
          "trust.password-env",
          "trust.password-prompt",
          "timeout",
          "connect-timeout",
          "min-version",
          "max-version",
          "cipher-suites");

  final Path file;
  final String defaultGroup;
  final Map<String, ServerGroup> groups;

  private Config(Path file, String defaultGroup, Map<String, ServerGroup> groups) {
    this.file = file;
    this.defaultGroup = defaultGroup;
    this.groups = groups;
  }

  /**
   * Reads and checks a configuration file.
   *
   * @param file the file
   * @return the configuration
   * @throws CliException ({@link ExitCode#USAGE}) when the file is missing or wrong
   */
  static Config load(Path file) {
    Properties properties = new Properties();
    try (Reader in = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
      properties.load(in);
    } catch (NoSuchFileException e) {
      throw new CliException(
          ExitCode.USAGE,
          "no configuration file " + file,
          "pass --config FILE, set KEYTEND_KMIP_CLI_CONFIG, or create the file (see the README)");
    } catch (IOException | IllegalArgumentException e) {
      throw CliException.usage("cannot read the configuration " + file + ": " + e.getMessage());
    }
    Path base = file.toAbsolutePath().getParent();
    Map<String, Map<String, String>> byGroup = new TreeMap<>();
    String defaultGroup = null;
    for (String key : new TreeSet<>(properties.stringPropertyNames())) {
      String value = properties.getProperty(key).trim();
      if (key.equals("default-group")) {
        defaultGroup = value;
        continue;
      }
      Matcher m = GROUP_KEY.matcher(key);
      if (!m.matches()) throw CliException.usage(file + ": unknown key " + key);
      String setting = m.group(2);
      if (setting.endsWith("password") || setting.endsWith(".pass") || setting.endsWith("secret"))
        throw CliException.usage(
            file
                + ": "
                + key
                + ": passwords are never written in the configuration; use "
                + setting.substring(0, setting.lastIndexOf('.') + 1)
                + "password-file, password-env or password-prompt");
      if (!GROUP_SETTINGS.contains(setting))
        throw CliException.usage(file + ": unknown key " + key);
      byGroup.computeIfAbsent(m.group(1), g -> new LinkedHashMap<>()).put(setting, value);
    }
    Map<String, ServerGroup> groups = new LinkedHashMap<>();
    for (Map.Entry<String, Map<String, String>> e : byGroup.entrySet())
      groups.put(e.getKey(), group(file, base, e.getKey(), e.getValue()));
    if (defaultGroup != null && !groups.containsKey(defaultGroup))
      throw CliException.usage(
          file + ": default-group " + defaultGroup + " is not a configured group");
    return new Config(file, defaultGroup, groups);
  }

  /**
   * The group a command uses: {@code name}, else the default group, else the only group.
   *
   * @param name the --group option, or null
   * @return the group
   */
  ServerGroup group(String name) {
    if (name != null) {
      ServerGroup group = groups.get(name);
      if (group == null)
        throw new CliException(
            ExitCode.USAGE,
            "no server group " + name + " in " + file,
            "configured groups: " + String.join(", ", groups.keySet()));
      return group;
    }
    if (defaultGroup != null) return groups.get(defaultGroup);
    if (groups.size() == 1) return groups.values().iterator().next();
    throw new CliException(
        ExitCode.USAGE,
        groups.isEmpty()
            ? "no server group in " + file
            : "several server groups in " + file + " and no default-group",
        groups.isEmpty()
            ? null
            : "pass --group NAME (one of " + String.join(", ", groups.keySet()) + ")");
  }

  private static ServerGroup group(Path file, Path base, String name, Map<String, String> s) {
    String where = file + ": group " + name;
    List<String> endpoints = Values.list(s.getOrDefault("endpoints", ""));
    if (endpoints.isEmpty())
      throw CliException.usage(where + ": endpoints is required (host:port, host:port, ...)");

    String identityType = s.getOrDefault("identity.type", "");
    ServerGroup.Identity identity;
    Secrets.Source identityPassword = password(where, base, s, "identity");
    switch (identityType) {
      case "pem" -> {
        Path certificate = path(where, base, s, "identity.certificate");
        Path key = path(where, base, s, "identity.key");
        refuse(where, s, "identity.file", "pem");
        identity =
            new ServerGroup.Identity(
                ServerGroup.IdentityType.PEM, null, certificate, key, identityPassword);
      }
      case "pkcs12", "jks" -> {
        Path store = path(where, base, s, "identity.file");
        refuse(where, s, "identity.certificate", identityType);
        refuse(where, s, "identity.key", identityType);
        if (identityPassword == null)
          throw CliException.usage(
              where
                  + ": a "
                  + identityType
                  + " identity needs identity.password-file, identity.password-env or"
                  + " identity.password-prompt");
        identity =
            new ServerGroup.Identity(
                Values.constant(ServerGroup.IdentityType.class, identityType, "identity.type"),
                store,
                null,
                null,
                identityPassword);
      }
      default -> throw CliException.usage(where + ": identity.type must be pkcs12, jks or pem");
    }

    String trustType = s.getOrDefault("trust.type", "");
    Secrets.Source trustPassword = password(where, base, s, "trust");
    ServerGroup.Trust trust;
    switch (trustType) {
      case "system" -> {
        refuse(where, s, "trust.file", "system");
        trust = new ServerGroup.Trust(ServerGroup.TrustType.SYSTEM, null, null);
      }
      case "pem" ->
          trust =
              new ServerGroup.Trust(
                  ServerGroup.TrustType.PEM, path(where, base, s, "trust.file"), null);
      case "pkcs12", "jks" ->
          trust =
              new ServerGroup.Trust(
                  Values.constant(ServerGroup.TrustType.class, trustType, "trust.type"),
                  path(where, base, s, "trust.file"),
                  trustPassword);
      default ->
          throw CliException.usage(where + ": trust.type must be pem, pkcs12, jks or system");
    }
    if (trustPassword != null && !trustType.equals("pkcs12") && !trustType.equals("jks"))
      throw CliException.usage(where + ": a " + trustType + " trust takes no password");

    Duration timeout =
        s.containsKey("timeout") ? Values.duration(s.get("timeout"), where + ": timeout") : null;
    Duration connect =
        s.containsKey("connect-timeout")
            ? Values.duration(s.get("connect-timeout"), where + ": connect-timeout")
            : null;
    return new ServerGroup(
        name,
        s.get("description"),
        endpoints,
        identity,
        trust,
        timeout,
        connect,
        s.containsKey("min-version")
            ? Values.version(s.get("min-version"), where + ": min-version")
            : null,
        s.containsKey("max-version")
            ? Values.version(s.get("max-version"), where + ": max-version")
            : null,
        Values.list(s.getOrDefault("cipher-suites", "")));
  }

  private static Path path(String where, Path base, Map<String, String> s, String key) {
    String value = s.get(key);
    if (value == null || value.isEmpty())
      throw CliException.usage(where + ": " + key + " is required");
    return base.resolve(value).normalize();
  }

  private static void refuse(String where, Map<String, String> s, String key, String type) {
    if (s.containsKey(key))
      throw CliException.usage(where + ": " + key + " does not apply to type " + type);
  }

  /** The one password source given for {@code prefix} (identity or trust), or null. */
  private static Secrets.Source password(
      String where, Path base, Map<String, String> s, String prefix) {
    List<Secrets.Source> sources = new ArrayList<>();
    if (s.containsKey(prefix + ".password-file"))
      sources.add(Secrets.Source.file(path(where, base, s, prefix + ".password-file")));
    if (s.containsKey(prefix + ".password-env")) {
      String variable = s.get(prefix + ".password-env");
      if (variable.isEmpty())
        throw CliException.usage(where + ": " + prefix + ".password-env is empty");
      sources.add(Secrets.Source.env(variable));
    }
    if (s.containsKey(prefix + ".password-prompt")) {
      String value = s.get(prefix + ".password-prompt");
      if (!value.equals("true") && !value.equals("false"))
        throw CliException.usage(where + ": " + prefix + ".password-prompt must be true or false");
      if (value.equals("true")) sources.add(Secrets.Source.prompt());
    }
    if (sources.size() > 1)
      throw CliException.usage(
          where + ": give one of " + prefix + ".password-file, -env or -prompt, not several");
    return sources.isEmpty() ? null : sources.get(0);
  }
}
