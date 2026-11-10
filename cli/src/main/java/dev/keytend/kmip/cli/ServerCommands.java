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

import dev.keytend.kmip.kms.CertificateRenewal;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsException;
import dev.keytend.kmip.kms.OutcomeUnknownException;
import dev.keytend.kmip.kms.RenewalNotSavedException;
import dev.keytend.kmip.kms.RenewedCertificate;
import dev.keytend.kmip.kms.ServerInfo;
import java.io.IOException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/** {@code servers}, {@code info} and {@code renew-certificate}. */
final class ServerCommands {
  private ServerCommands() {}

  static void servers(Context c) {
    Config config = c.config();
    List<String> names = c.args.positionals();
    if (names.size() > 1) throw CliException.usage("expected at most one group name");
    List<ServerGroup> groups = new ArrayList<>();
    if (names.isEmpty()) groups.addAll(config.groups.values());
    else groups.add(config.group(names.get(0)));
    List<Map<String, Object>> described = new ArrayList<>();
    for (ServerGroup g : groups) described.add(g.describe(g.name().equals(config.defaultGroup)));
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("config", config.file.toString());
    result.put("defaultGroup", config.defaultGroup);
    result.put("groups", described);
    c.emit(
        result,
        () -> {
          c.out.println("Configuration: " + config.file);
          if (groups.isEmpty()) c.out.println("No server groups.");
          for (Map<String, Object> g : described) {
            c.out.println();
            c.out.println(
                g.get("name") + (Boolean.TRUE.equals(g.get("default")) ? " (default)" : ""));
            for (Map.Entry<String, Object> e : g.entrySet()) {
              String key = e.getKey();
              if (key.equals("name") || key.equals("default")) continue;
              if (key.equals("description") && e.getValue() == null) continue;
              String text = e.getValue() == null ? "default" : text(e.getValue());
              if (key.equals("endpoints")) text += " (tried in this order)";
              c.out.println(String.format(Locale.ROOT, "  %-16s %s", key + ":", text));
            }
          }
        });
  }

  /** {@code renew-certificate}: the group's own client certificate, with Re-Provision. */
  static void renewCertificate(Context c) {
    c.args.none();
    java.util.Optional<Duration> validFor = c.args.get("--valid-for", Duration.class);
    boolean shared = c.args.flag("--shared-store");
    ServerGroup g = c.group();
    CertificateRenewal renewal =
        Context.argument(
            () -> {
              CertificateRenewal r = CertificateRenewal.onDemand();
              if (validFor.isPresent()) r = r.validFor(validFor.get());
              return shared ? r.endpointsShareOneStore() : r;
            });
    Path keyFile =
        g.identity().type() == ServerGroup.IdentityType.PEM
            ? g.identity().key()
            : g.identity().file();
    Path pending = keyFile.resolveSibling(keyFile.getFileName() + ".renewal");
    c.confirm(
        List.of(
            "Renew the client certificate of server group " + g.name() + " (KMIP Re-Provision):",
            "  identity: " + g.identity().describe(),
            "  The new private key is written to "
                + pending
                + " first; then these files are replaced.",
            "  The server refuses the current certificate on new connections once it issues the"
                + " new one.",
            "  Then add the new fingerprint to the server's policy under the same name."));
    c.hints(
        e ->
            e instanceof OutcomeUnknownException
                ? "the client may be locked out: the message says where the new key is and how to"
                    + " recover; see the SDK's docs/production.md, \"Renew the client certificate\""
                : null);
    Kms kms = c.renewingKms(renewal);
    RenewedCertificate r;
    try {
      r = kms.renewClientCertificate();
    } catch (RenewalNotSavedException e) {
      // The server issued the certificate and retired the old one, but the files still hold the
      // old one: once this process exits, the certificate below may be the only copy.
      String message = e.getMessage();
      int at = message.indexOf(e.pem());
      if (at > 0) message = message.substring(0, at).strip();
      if (!c.json) {
        c.err.println("The new certificate chain, which is public (save it now):");
        for (String line : e.pem().split("\n")) c.err.println(line);
      }
      throw new CliException(
          ExitCode.OUTCOME_UNKNOWN,
          message,
          "the server issued the new certificate and refuses the old one on new connections, but"
              + " the files still hold the old one: save the certificate"
              + (c.json ? " in certificatePem" : " above")
              + ", fix the cause, and put it with the key the message names in the configured"
              + " files; see the SDK's docs/production.md, \"What is on disk\"",
          e,
          Map.of("certificatePem", e.pem()));
    } catch (IOException e) {
      throw new CliException(
          ExitCode.FAILED, e.getMessage(), "follow the message, then repeat the command", e);
    }
    c.done("renewed the client certificate: " + r.fingerprint());
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("group", g.name());
    result.put("previousFingerprint", r.previousFingerprint());
    result.put("fingerprint", r.fingerprint());
    result.put("certificateId", r.certificateId());
    result.put("subject", r.certificate().getSubjectX500Principal().getName());
    result.put("notAfter", r.notAfter().toString());
    result.put("finishedEarlierAttempt", r.finishedEarlierAttempt());
    c.emit(
        result,
        () -> {
          Map<String, String> lines = new LinkedHashMap<>();
          lines.put("Server group", g.name());
          lines.put("Replaced", r.previousFingerprint());
          lines.put("New certificate", r.fingerprint());
          lines.put(
              "Certificate ID", r.certificateId() == null ? "not recorded" : r.certificateId());
          lines.put("Subject", (String) result.get("subject"));
          lines.put("Valid until", (String) result.get("notAfter"));
          if (r.finishedEarlierAttempt())
            lines.put("Note", "finished a renewal that an earlier run began");
          Render.labeled(lines, c.out);
          c.err.println(
              "Add "
                  + r.fingerprint()
                  + " to the server's policy under the same name, then remove "
                  + r.previousFingerprint()
                  + ".");
        });
  }

  static void info(Context c) {
    c.args.none();
    Kms kms = c.kms();
    kms.ping();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("group", c.group().name());
    result.put("endpoints", c.group().endpoints());
    result.put("version", kms.version().toString());
    // Each answer on its own: a server that refuses Query still reports its versions.
    List<String> versions = null;
    String versionsError = null;
    try {
      versions = kms.serverVersions();
    } catch (KmsException e) {
      versionsError = e.getMessage();
    }
    result.put("serverVersions", versions);
    result.put("serverVersionsError", versionsError);
    ServerInfo info = null;
    String queryError = null;
    try {
      info = kms.serverInfo();
    } catch (KmsException e) {
      queryError = e.getMessage();
    }
    result.put("vendor", info == null ? null : info.vendor().orElse(null));
    result.put("serverInformation", info == null ? null : info.serverInformation());
    result.put("operations", info == null ? null : info.operations());
    result.put("objectTypes", info == null ? null : info.objectTypes());
    result.put("queryError", queryError);
    String notVersions = versionsError;
    String notQuery = queryError;
    c.emit(
        result,
        () -> {
          Map<String, String> lines = new LinkedHashMap<>();
          lines.put("Server group", (String) result.get("group"));
          lines.put("Endpoints", text(result.get("endpoints")));
          lines.put("KMIP version", (String) result.get("version"));
          lines.put(
              "Server versions",
              notVersions != null
                  ? "not answered: " + notVersions
                  : text(result.get("serverVersions")));
          if (notQuery != null) {
            lines.put("Query", "not answered: " + notQuery);
          } else {
            lines.put("Vendor", text(result.get("vendor")));
            lines.put("Server info", text(result.get("serverInformation")));
            lines.put("Operations", text(result.get("operations")));
            lines.put("Object types", text(result.get("objectTypes")));
          }
          Render.labeled(lines, c.out);
        });
  }

  /** A value for the text output: lists joined with commas, maps as {@code key=value; ...}. */
  private static String text(Object value) {
    if (value == null) return "-";
    if (value instanceof List<?> list)
      return String.join(", ", list.stream().map(ServerCommands::text).toList());
    if (value instanceof Map<?, ?> map)
      return map.isEmpty()
          ? "-"
          : String.join(
              "; ",
              map.entrySet().stream().map(x -> x.getKey() + "=" + text(x.getValue())).toList());
    return value.toString();
  }
}
