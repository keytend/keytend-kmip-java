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

package dev.keytend.kmip.interop;

import dev.keytend.kmip.client.KmipClient;
import dev.keytend.kmip.model.Credentials;
import dev.keytend.kmip.model.ProtocolVersion;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.transport.*;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.*;
import java.util.Properties;

/**
 * Runs the same integration scenarios used by Testcontainers against an existing server. The
 * certificate directory holds {@code client.p12} and {@code ca.pem}, and optionally {@code
 * admin-credential.properties} ({@code username}, {@code password}): the header credential of the
 * draft 3.0 Login and System Object requests, for a server whose policy requires one.
 */
public final class InteropApplication {
  private InteropApplication() {}

  public static void main(String[] args) throws Exception {
    if (args.length < 4) {
      System.err.println(
          "Usage: InteropApplication <server-name> <host> <port> <cert-directory>"
              + " [report-directory] [1.1|1.2|1.3|1.4|2.0|2.1|3.0]");
      System.exit(2);
    }
    Path certs = Path.of(args[3]),
        reports = Path.of(args.length > 4 ? args[4] : "integration/reports");
    var ssl =
        Tls.context(certs.resolve("client.p12"), "changeit".toCharArray(), certs.resolve("ca.pem"));
    Ttlv administrator = administrator(certs.resolve("admin-credential.properties"));
    int failures = 0;
    for (ProtocolVersion version : ProtocolVersion.values()) {
      if (args[0].equals("pykmip") && !version.legacyAttributes()) continue;
      if (args[0].equals("pqctoday") && version != ProtocolVersion.V3_0) continue;
      if (args.length > 5 && !version.toString().equals(args[5])) continue;
      try (var client =
          new KmipClient(new TlsTransport(args[1], Integer.parseInt(args[2]), ssl), version)) {
        var checks =
            version.legacyAttributes()
                ? new InteropSuite(client, args[0], certs).run()
                : new ModernInteropSuite(client, args[0], certs, administrator).run();
        for (var c : checks) {
          if (c.outcome().equals("FAIL")) failures++;
          System.out.println(
              args[0]
                  + " "
                  + version
                  + " "
                  + c.outcome()
                  + " "
                  + c.name()
                  + (c.detail().isEmpty() ? "" : ": " + c.detail()));
        }
        InteropSuite.writeReport(
            reports.resolve(
                args[0] + "-" + version + "-jdk" + Runtime.version().feature() + ".json"),
            args[0],
            version,
            checks);
      }
    }
    if (failures > 0) throw new AssertionError(failures + " integration checks failed");
  }

  /** The Username and Password credential in {@code file}, or null when there is none. */
  static Ttlv administrator(Path file) throws IOException {
    if (!Files.exists(file)) return null;
    Properties p = new Properties();
    try (Reader in = Files.newBufferedReader(file)) {
      p.load(in);
    }
    String username = p.getProperty("username"), password = p.getProperty("password");
    if (username == null || password == null)
      throw new IllegalArgumentException(file + " needs username and password");
    return Credentials.usernamePassword(username, password);
  }
}
