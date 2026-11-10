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

package org.apache.cassandra.distributed.test;

import dev.keytend.kmip.cassandra.tde.KmipConnections;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import org.junit.Assume;

/**
 * The real KMS of the live dtest: two keytend-kmip-server replicas (containers) of one store, A and
 * its standby B, started by {@code qual/server-kms.sh} with certificates from {@code
 * qual/server-pki.sh} ({@code run-trial.sh} sets both up). The server locks its store, so one runs at
 * a time: {@code run-trial.sh} starts A, and B takes the store over once A is down. From the
 * environment:
 *
 * <ul>
 *   <li>{@code KEYTEND_SERVER_PKI}: the PKI directory ({@code ca.pem}, {@code admin}, {@code
 *       node1}, {@code node1-renewed}, {@code node2});
 *   <li>{@code KEYTEND_SERVER_WORK}: the pair's state directory;
 *   <li>{@code KEYTEND_SERVER_QUAL}: the {@code qual/} directory, for {@code server-kms.sh};
 *   <li>{@code KEYTEND_SERVER_ENDPOINTS}: {@code host:port,host:port}, replica A first;
 *   <li>{@code KEYTEND_SERVER_VERSIONS}: the KMIP versions to run, default {@code 1.4,2.1,3.0};
 *   <li>{@code KEYTEND_SERVER_LEASE_STATES}: the server's {@code --lease-states}, default {@code
 *       active-deactivated} (its default: Deactivated keys are leased too); {@code active} leases
 *       only Active keys.
 * </ul>
 *
 * The test is skipped without the first four.
 */
public final class LiveKms {
  public final Path pki = Path.of(env("KEYTEND_SERVER_PKI"));
  public final Path work = Path.of(env("KEYTEND_SERVER_WORK"));
  public final Path qual = Path.of(env("KEYTEND_SERVER_QUAL"));
  public final String endpoints = env("KEYTEND_SERVER_ENDPOINTS");

  private LiveKms() {}

  public static LiveKms fromEnvironment() {
    Assume.assumeTrue(
        "KEYTEND_SERVER_PKI, KEYTEND_SERVER_WORK, KEYTEND_SERVER_QUAL and KEYTEND_SERVER_ENDPOINTS are not set",
        env("KEYTEND_SERVER_PKI") != null && env("KEYTEND_SERVER_WORK") != null && env("KEYTEND_SERVER_QUAL") != null
            && env("KEYTEND_SERVER_ENDPOINTS") != null);
    return new LiveKms();
  }

  /** Whether the server leases Deactivated keys ({@code --lease-states active-deactivated}, its default). */
  public static boolean leasesDeactivated() {
    String states = env("KEYTEND_SERVER_LEASE_STATES");
    if (states == null || states.isBlank() || states.equals("active-deactivated")) return true;
    if (states.equals("active")) return false;
    throw new IllegalArgumentException("KEYTEND_SERVER_LEASE_STATES: active or active-deactivated, not " + states);
  }

  public static List<String> versions() {
    String versions = env("KEYTEND_SERVER_VERSIONS");
    return List.of((versions == null || versions.isBlank() ? "1.4,2.1,3.0" : versions).split(","));
  }

  private static String env(String name) {
    // the live test's own settings, not Cassandra configuration
    // checkstyle: suppress below 'blockSystemPropertyUsage'
    return System.getenv(name);
  }

  /** Connection parameters for a node, with its own KMS client identity ({@code node1} or {@code node2}). */
  public Map<String, String> parameters(String version, String identity) {
    Map<String, String> p = new HashMap<>();
    p.put(KmipConnections.ENDPOINTS, endpoints);
    p.put(KmipConnections.CLIENT_CERTIFICATE, pki.resolve(identity + ".pem").toString());
    p.put(KmipConnections.CLIENT_KEY, pki.resolve(identity + ".key").toString());
    p.put(KmipConnections.TRUST_CERTIFICATES, pki.resolve("ca.pem").toString());
    p.put(KmipConnections.MIN_VERSION, version);
    p.put(KmipConnections.MAX_VERSION, version);
    p.put(KmipConnections.CALL_TIMEOUT, "5s");
    return p;
  }

  /** As {@link #parameters}, from a copy of the node's client identity files that the test can replace. */
  public Map<String, String> reloadableParameters(String version, String identity, Path copyDir) throws IOException {
    Files.createDirectories(copyDir);
    Path certificate = copyDir.resolve("client.pem");
    Path key = copyDir.resolve("client.key");
    Files.copy(pki.resolve(identity + ".pem"), certificate, StandardCopyOption.REPLACE_EXISTING);
    Files.copy(pki.resolve(identity + ".key"), key, StandardCopyOption.REPLACE_EXISTING);
    Map<String, String> p = parameters(version, identity);
    p.put(KmipConnections.CLIENT_CERTIFICATE, certificate.toString());
    p.put(KmipConnections.CLIENT_KEY, key.toString());
    p.put(KmipConnections.RELOAD_CREDENTIALS, "true");
    return p;
  }

  /** The operator's connection (certificate {@code admin}), as {@code KmipTool} has it. */
  public Kms admin(String version) {
    KmipVersion v = KmipVersion.valueOf("V" + version.replace('.', '_'));
    return Kms.connect(KmsConfig.builder().endpoints(endpoints.split(","))
        .clientIdentityPem(pki.resolve("admin.pem"), pki.resolve("admin.key"))
        .trustPem(pki.resolve("ca.pem"))
        .minimumVersion(v).maximumVersion(v)
        .callTimeout(Duration.ofSeconds(5)).build());
  }

  /** Kills replica {@code a} or {@code b} (SIGKILL): an outage of that replica. */
  public void kill(String replica) throws Exception {
    script("kill-" + replica);
  }

  /** Starts replica {@code a} or {@code b} on the same store, once the other is down. */
  public void start(String replica) throws Exception {
    script("start-" + replica);
  }

  private void script(String command) throws Exception {
    Process p = new ProcessBuilder(qual.resolve("server-kms.sh").toString(), command, work.toString()).inheritIO().start();
    if (p.waitFor() != 0) throw new IllegalStateException("server-kms.sh " + command + " failed");
  }

  public static Set<String> union(List<Set<String>> sets) {
    Set<String> all = new TreeSet<>();
    sets.forEach(all::addAll);
    return all;
  }
}
