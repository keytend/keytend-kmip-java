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

package dev.keytend.kmip.cassandra.tde;

import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.LineageKey;
import dev.keytend.kmip.kms.RevocationReason;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.apache.cassandra.config.DurationSpec;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

/**
 * Operator commands for the commit log and hints keys. Creation, rotation, retirement and
 * replacement are cluster-wide decisions made once, from one place with the operator's KMS
 * credential, never by the nodes:
 *
 * <pre>
 * java -cp 'lib/*' dev.keytend.kmip.cassandra.tde.KmipTool --yaml conf/cassandra.yaml COMMAND ...
 * java -cp 'lib/*' dev.keytend.kmip.cassandra.tde.KmipTool -p kmip_endpoints=kms:5696 -p ... COMMAND ...
 *
 * key-create NAME [BITS] [FAMILY]       create and activate an extractable AES key (once, before enabling TDE)
 * key-status NAME                       the key's lineage, newest first
 * key-rotate NAME [IF_ACTIVE_FOR]       a new key for new files; the old one stays Active until retired
 * key-scan DIR...                       the keys commit log segments and hints files name (run on each node)
 * key-retire NAME SCAN_OUTPUT...        destroy the older keys no node's scan names
 * key-replace-compromised NAME SINCE    revoke as compromised and activate a replacement (SINCE: ISO instant)
 * key-revoke-compromised NAME ID SINCE  revoke an older key of the name's lineage as compromised; no replacement
 * </pre>
 *
 * {@code --yaml} reads the connection parameters of the {@code key_provider} in {@code
 * transparent_data_encryption_options}; {@code -p} sets or overrides one. Run it with the
 * operator's credential, not a node's: a node's may only read keys.
 */
public final class KmipTool {
  private static final Pattern ALIAS = Pattern.compile("\"encKeyAlias\"\\s*:\\s*\"([^\"]+)\"");

  private KmipTool() {}

  public static void main(String[] argv) throws Exception {
    Map<String, Object> parameters = new HashMap<>();
    List<String> args = new ArrayList<>(List.of(argv));
    while (args.size() > 1 && (args.get(0).equals("-p") || args.get(0).equals("--yaml"))) {
      String option = args.remove(0);
      String value = args.remove(0);
      if (option.equals("--yaml")) {
        parameters.putAll(fromYaml(Path.of(value)));
      } else {
        int equals = value.indexOf('=');
        if (equals <= 0) usage();
        parameters.put(value.substring(0, equals), value.substring(equals + 1));
      }
    }
    if (args.isEmpty()) usage();
    String command = args.remove(0);
    try {
      if (command.equals("key-scan")) {
        for (String alias : scan(args)) System.out.println(alias);
        return;
      }
      Kms kms = KmipConnections.get(parameters);
      try {
        run(kms, command, args);
      } finally {
        KmipConnections.closeAll();
      }
    } catch (IllegalStateException | IllegalArgumentException | IndexOutOfBoundsException e) {
      System.err.println(e.getMessage());
      System.exit(2);
    }
  }

  private static void usage() {
    System.err.println(
        "usage: KmipTool [--yaml cassandra.yaml] [-p name=value]... COMMAND ARGS (see the class Javadoc)");
    System.exit(1);
  }

  /** Runs one command with the operator's {@link Kms}; the output goes to standard output. */
  public static void run(Kms kms, String command, List<String> args) throws IOException {
    switch (command) {
      case "key-create": {
        int bits = args.size() > 1 ? Integer.parseInt(args.get(1)) : 256;
        String family = args.size() > 2 ? args.get(2) : args.get(0);
        KeyHandle key = kms.keys().createAes(bits).named(args.get(0))
            .custom(KmipKeyProvider.FAMILY_ATTRIBUTE, family)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).extractable(true).findOrCreate();
        System.out.println("Active: " + key.id());
        break;
      }
      case "key-status":
        for (LineageKey k : named(kms, args.get(0)).lineage())
          System.out.printf("%s %s%s activated=%s%n", k.id(), k.attributes().state(), k.newest() ? " newest" : "",
              k.attributes().activationDate().map(Instant::toString).orElse("-"));
        break;
      case "key-rotate": {
        // no grace period: the old key stays Active until no file names it (key-retire). An open
        // commit log segment appends under its own key only while that key may encrypt (Active), and
        // cannot roll to a new one; a server that leases only Active keys (keytend-kmip-server with
        // --lease-states active) would also refuse the files under a Deactivated key to the nodes
        KeyHandle key = named(kms, args.get(0));
        KeyHandle next = args.size() > 1 ? key.rotateIfActiveFor(duration(args.get(1))) : key.rotateOrLatest();
        System.out.println(next.id().equals(key.id()) ? "Not due: " + key.id() : "Rotated " + key.id() + " -> " + next.id());
        break;
      }
      case "key-retire": {
        if (args.size() < 2) throw new IllegalArgumentException("key-retire needs the key-scan output of every node");
        KeyHandle current = named(kms, args.get(0));
        Set<String> referenced = new TreeSet<>();
        for (String file : args.subList(1, args.size()))
          for (String line : Files.readAllLines(Path.of(file))) {
            if (line.isBlank()) continue;
            String id = KmipKeyProvider.keyId(line.trim());
            if (id == null) throw new IllegalArgumentException(file + ": not a key-scan line: " + line);
            referenced.add(id);
          }
        // newest first: keep the oldest key any file names, and every newer one
        String keepFrom = current.id();
        for (LineageKey k : current.lineage()) if (referenced.remove(k.id())) keepFrom = k.id();
        if (!referenced.isEmpty())
          throw new IllegalStateException(
              "Refusing: files name " + referenced + ", which are not in the lineage of " + args.get(0));
        for (KeyHandle k : current.retirePredecessorsOlderThan(
            kms.keys().handle(keepFrom), RevocationReason.superseded("TDE key retired")))
          System.out.println("Destroyed " + k.id());
        System.out.println("Kept " + keepFrom + " and newer");
        break;
      }
      case "key-replace-compromised": {
        KeyHandle key = named(kms, args.get(0));
        KeyHandle next = key.replaceCompromised(
            RevocationReason.keyCompromise("TDE key compromised", Instant.parse(args.get(1))));
        System.out.println("Revoked " + key.id() + " as compromised; new files use " + next.id());
        break;
      }
      case "key-revoke-compromised": {
        // the compromise order that keeps writes up: the compromised key is an older key of the
        // lineage, either after key-rotate moved the name or because an older key leaked, so it is
        // found by its identifier, not the name
        KeyHandle current = named(kms, args.get(0));
        String id = args.get(1);
        Instant since = Instant.parse(args.get(2));
        if (id.equals(current.id()))
          throw new IllegalArgumentException(
              "Refusing: " + id + " is the key " + args.get(0) + " names; key-rotate first, or use key-replace-compromised");
        if (current.lineage().stream().noneMatch(k -> k.id().equals(id)))
          throw new IllegalArgumentException("Refusing: " + id + " is not in the lineage of " + args.get(0));
        kms.keys().handle(id).revoke(RevocationReason.keyCompromise("TDE key compromised", since));
        System.out.println("Revoked " + id + " as compromised; new files use " + current.id());
        break;
      }
      default:
        throw new IllegalArgumentException("Unknown command " + command);
    }
  }

  private static KeyHandle named(Kms kms, String name) {
    return kms.keys().findByName(name).orElseThrow(() -> new IllegalArgumentException("No Active object named " + name));
  }

  /**
   * The key aliases recorded in the headers of the commit log segments ({@code *.log}) and hints
   * files ({@code *.hints}) in these directories. Reads only the headers; sends nothing.
   */
  public static Set<String> scan(List<String> directories) throws IOException {
    Set<String> aliases = new TreeSet<>();
    for (String directory : directories) {
      List<Path> files;
      try (Stream<Path> listed = Files.list(Path.of(directory))) {
        files = listed.collect(Collectors.toList());
      }
      for (Path file : files) {
        String name = file.getFileName().toString();
        if (!(name.endsWith(".log") || name.endsWith(".hints"))) continue;
        byte[] head = new byte[8192];
        int read;
        try (InputStream in = Files.newInputStream(file)) {
          read = in.readNBytes(head, 0, head.length);
        } catch (NoSuchFileException recycled) {
          continue; // a segment recycled, or hints delivered, while the directory was listed
        }
        Matcher m = ALIAS.matcher(new String(head, 0, read, StandardCharsets.ISO_8859_1));
        if (m.find()) aliases.add(m.group(1));
      }
    }
    return aliases;
  }

  private static Duration duration(String value) {
    return Duration.ofMillis(new DurationSpec.LongMillisecondsBound(value).toMilliseconds());
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> fromYaml(Path yaml) throws IOException {
    Map<String, Object> root;
    try (InputStream in = Files.newInputStream(yaml)) {
      root = new Yaml(new SafeConstructor(new LoaderOptions())).load(in);
    }
    Object options = root == null ? null : root.get("transparent_data_encryption_options");
    if (!(options instanceof Map)) throw new IllegalArgumentException(yaml + " has no transparent_data_encryption_options");
    Object provider = ((Map<String, Object>) options).get("key_provider");
    if (provider instanceof List) provider = ((List<Object>) provider).get(0);
    Object parameters = provider instanceof Map ? ((Map<String, Object>) provider).get("parameters") : null;
    if (parameters instanceof List) parameters = ((List<Object>) parameters).get(0);
    if (!(parameters instanceof Map)) throw new IllegalArgumentException(yaml + ": the key_provider has no parameters");
    Map<String, Object> result = new HashMap<>();
    ((Map<String, Object>) parameters).forEach((k, v) -> result.put(k, String.valueOf(v)));
    return result;
  }
}
