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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.datastax.driver.core.RemoteEndpointAwareJdkSSLOptions;
import com.datastax.driver.core.Session;
import dev.keytend.kmip.cassandra.tls.KmipCertificateValidator;
import dev.keytend.kmip.cassandra.tls.KmipSslContextFactory;
import dev.keytend.kmip.cassandra.tls.KmipTlsMaterial;
import dev.keytend.kmip.cassandra.tls.KmsTestServer;
import dev.keytend.kmip.cassandra.tls.TestPki;
import dev.keytend.kmip.cassandra.tls.TlsAdmin;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import org.apache.cassandra.distributed.Cluster;
import org.apache.cassandra.distributed.api.ConsistencyLevel;
import org.apache.cassandra.distributed.api.Feature;
import org.apache.cassandra.distributed.api.IInvokableInstance;
import org.apache.cassandra.distributed.shared.ClusterUtils;
import org.apache.cassandra.security.SSLFactory;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Client and internode TLS with every certificate, private key and trust anchor in a KMIP server
 * (identities through the SDK's {@code kms.tls()}, leased), and mutual TLS authentication whose
 * allowed certificates are the Active ones in the KMS: connect, revoke, renew, lose the KMS,
 * compromise a node identity and re-key it. The KMS is the in-memory server behind a
 * mutual-TLS socket ({@link KmsTestServer}), with a Lease Time, on KMIP 1.4, 2.1 and 3.0.
 */
public class KmipTlsTest extends TestBaseImpl {
  private static final Logger logger = LoggerFactory.getLogger(KmipTlsTest.class);
  private static final String APP = "spiffe://cluster1/app";

  @Test
  public void tlsAndClientCertificatesFromKms() throws Throwable {
    // No DTEST_IGNORE_SHUTDOWN_THREADCOUNT: neither the SDK's threads nor the sample's refresh threads
    // are in a node's thread group, so each node's shutdown check runs.
    for (KmipVersion version : new KmipVersion[] {KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0})
      run(version);
  }

  private void run(KmipVersion version) throws Throwable {
    logger.info("=== KMIP {} ===", version);
    String domain = "cluster1";
    TestPki.Issued ca = TestPki.ca(domain + " CA"); // Key Usage keyCertSign, cRLSign
    TestPki.Issued node1 = TestPki.issue(ca, "node1", 11);
    TestPki.Issued node2 = TestPki.issue(ca, "node2", 12);
    TestPki.Issued app = TestPki.issue(ca, "app", 21);
    TestPki.Issued app2 = TestPki.issue(ca, "app", 22);
    TestPki.Issued stranger = TestPki.issue(ca, "app", 23); // signed by the CA, never registered

    try (KmsTestServer kms = new KmsTestServer(version, Files.createTempDirectory("kmip-tls"));
         Kms adminKms = kms.admin()) {
      kms.kmip().leaseTime(Duration.ofSeconds(120));
      TlsAdmin admin = new TlsAdmin(adminKms);
      admin.addCa(domain, ca.certificate());
      admin.addIdentity(domain, domain + "/node1", node1.privateKey(), node1.chain());
      admin.addIdentity(domain, domain + "/node2", node2.privateKey(), node2.chain());
      admin.addPeer(domain, app.certificate());
      admin.addPeer(domain, app2.certificate());

      try (Cluster cluster = Cluster.build(2).withConfig(c -> {
             Map<String, String> tls = new HashMap<>(kms.parameters());
             tls.put(KmipTlsMaterial.IDENTITY, domain + "/node" + c.num());
             tls.put(KmipTlsMaterial.DOMAIN, domain);
             tls.put(KmipTlsMaterial.REFRESH_INTERVAL, "1s");
             Map<String, Object> server = new HashMap<>();
             server.put("internode_encryption", "all");
             server.put("require_client_auth", "true");
             // separate copies: one object referenced twice becomes a YAML alias, which the config loader cannot read
             server.put("ssl_context_factory",
                        Map.of("class_name", KmipSslContextFactory.class.getName(), "parameters", new HashMap<>(tls)));
             Map<String, Object> client = new HashMap<>();
             client.put("enabled", true);
             client.put("require_client_auth", "required");
             client.put("ssl_context_factory",
                        Map.of("class_name", KmipSslContextFactory.class.getName(), "parameters", new HashMap<>(tls)));
             c.with(Feature.NETWORK, Feature.GOSSIP, Feature.NATIVE_PROTOCOL)
              .set("server_encryption_options", server)
              .set("client_encryption_options", client)
              .set("authenticator.class_name", "org.apache.cassandra.auth.MutualTlsAuthenticator")
              .set("authenticator.parameters", Map.of("validator_class_name", KmipCertificateValidator.class.getName()))
              .set("internode_authenticator.class_name", "org.apache.cassandra.auth.MutualTlsInternodeAuthenticator")
              .set("internode_authenticator.parameters",
                   Map.of("validator_class_name", KmipCertificateValidator.class.getName(),
                          "trusted_peer_identities", "spiffe://cluster1/node1,spiffe://cluster1/node2"))
              .set("role_manager", "CassandraRoleManager")
              .set("authorizer", "CassandraAuthorizer")
              .set("default_role_initializer.class_name", "org.apache.cassandra.auth.MutualTlsDefaultRoleInitializer")
              .set("default_role_initializer.parameters", Map.of("role", "app_role", "identity", APP));
           }).start()) {
        IInvokableInstance n1 = cluster.get(1);
        IInvokableInstance n2 = cluster.get(2);
        // internode TLS with KMS material: a write at ALL needs both nodes
        cluster.schemaChange("CREATE KEYSPACE ks WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 2}");
        cluster.schemaChange("CREATE TABLE ks.t (k int PRIMARY KEY, v int)");
        cluster.coordinator(1).execute("INSERT INTO ks.t (k, v) VALUES (1, 1)", ConsistencyLevel.ALL);

        // clients: registered certificates connect, an unregistered one is refused
        assertThat(query(cluster, app, ca)).isEqualTo(1);
        assertThat(query(cluster, app2, ca)).isEqualTo(1);
        assertThatThrownBy(() -> query(cluster, stranger, ca)).isInstanceOf(Exception.class);
        assertThat(presentedSerial(n1, app2, ca)).isEqualTo(BigInteger.valueOf(11));
        // leased: the nodes report how long their material stays usable without the KMS
        assertThat(usableForMillis(n1)).isBetween(1L, 120_000L);

        // revoke app in the KMS: refused at its next connection, once the nodes refresh
        admin.revokePeer(domain, app.certificate());
        Thread.sleep(3000);
        assertThatThrownBy(() -> query(cluster, app, ca)).isInstanceOf(Exception.class);
        assertThat(query(cluster, app2, ca)).isEqualTo(1);

        // renew node1 (same key): presented on new connections; node2 admits it in the background
        // at the first handshake that presents it, and hot reloading rebuilds the cached contexts
        admin.renew(domain + "/node1", TestPki.issue(ca, "node1", 13, node1.keyPair()).chain());
        Thread.sleep(3000);
        assertThat(presentedSerial(n1, app2, ca)).isEqualTo(BigInteger.valueOf(13));
        n1.runOnInstance(SSLFactory::checkCertFilesForHotReloading);
        assertThat(n1.logs().grep("SSL certificates have been updated").getResult()).isNotEmpty();
        await(() -> {
          try {
            cluster.coordinator(1).execute("INSERT INTO ks.t (k, v) VALUES (2, 2)", ConsistencyLevel.ALL);
            return true;
          } catch (RuntimeException retry) {
            return false; // a reconnection refused once while node2 checks the renewed certificate
          }
        }, true);

        // the KMS is unreachable: the last material read stays in use while its leases run
        kms.unreachable(true);
        Thread.sleep(3000);
        assertThat(query(cluster, app2, ca)).isEqualTo(1);
        assertThat(presentedSerial(n1, app2, ca)).isEqualTo(BigInteger.valueOf(13));
        assertThat(usableForMillis(n1)).isBetween(1L, 118_000L);
        kms.unreachable(false);

        // node2's identity is compromised: revoked, node2 stops presenting it, and cannot start with it
        admin.revokeIdentity(domain + "/node2", true);
        await(() -> n2.callOnInstance(() -> KmipTlsMaterial.all().stream().allMatch(m -> m.certificate().isEmpty())), true);
        n2.runOnInstance(KmipTlsMaterial::closeAll);
        n2.shutdown().get(1, TimeUnit.MINUTES);
        Map<String, Object> node2Tls = new HashMap<>(kms.parameters());
        node2Tls.put(KmipTlsMaterial.IDENTITY, domain + "/node2");
        node2Tls.put(KmipTlsMaterial.DOMAIN, domain);
        assertThatThrownBy(() -> new KmipSslContextFactory(node2Tls)).hasStackTraceContaining("Cannot load TLS identity");
        KmipTlsMaterial.closeAll();
        // re-keyed from the compromised identity, under the same name: node2 starts and the cluster is whole again
        TestPki.Issued node2b = TestPki.issue(ca, "node2", 14);
        admin.rekey(domain + "/node2", node2b.privateKey(), node2b.chain());
        n2.startup();
        assertThat(presentedSerial(n2, app2, ca)).isEqualTo(BigInteger.valueOf(14));
        cluster.coordinator(1).execute("INSERT INTO ks.t (k, v) VALUES (3, 3)", ConsistencyLevel.ALL);
        assertThat(n2.executeInternal("SELECT v FROM ks.t WHERE k = 3")).hasNumberOfRows(1);
        closeKmip(cluster);
      }
    }
  }

  /** The least time any TLS material of {@code node} stays usable without the KMS; -1 when no lease limits it. */
  private static long usableForMillis(IInvokableInstance node) {
    return node.callOnInstance(() -> KmipTlsMaterial.minUsableFor().map(Duration::toMillis).orElse(-1L));
  }

  private static int query(Cluster cluster, TestPki.Issued client, TestPki.Issued ca) throws Exception {
    SSLContext context = TestPki.context(client, ca.certificate());
    try (com.datastax.driver.core.Cluster c =
             JavaDriverUtils.create(cluster, b -> b.withSSL(RemoteEndpointAwareJdkSSLOptions.builder().withSSLContext(context).build()));
         Session session = c.connect()) {
      return session.execute("SELECT v FROM ks.t WHERE k = 1").one().getInt("v");
    }
  }

  /** The serial number of the certificate the node presents on its native port. */
  private static BigInteger presentedSerial(IInvokableInstance node, TestPki.Issued client, TestPki.Issued ca) throws Exception {
    InetSocketAddress address = ClusterUtils.getNativeInetSocketAddress(node);
    try (SSLSocket socket = (SSLSocket) TestPki.context(client, ca.certificate()).getSocketFactory()
        .createSocket(address.getAddress(), address.getPort())) {
      socket.setSoTimeout(5000);
      socket.startHandshake();
      return ((X509Certificate) socket.getSession().getPeerCertificates()[0]).getSerialNumber();
    }
  }

  private static <T> void await(Callable<T> probe, T expected) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
    T last;
    while (!(last = probe.call()).equals(expected)) {
      if (System.nanoTime() > deadline) throw new AssertionError("expected " + expected + " but was " + last);
      Thread.sleep(250);
    }
  }

  /**
   * Stops the KMIP components of every running instance (Cassandra gives SSL context factories no
   * shutdown call, so their refresh threads would keep each closed cluster's class loaders alive),
   * and the test's own.
   */
  private static void closeKmip(Cluster cluster) {
    cluster.stream().filter(i -> !i.isShutdown()).forEach(i -> i.runOnInstance(KmipTlsMaterial::closeAll));
    KmipTlsMaterial.closeAll();
  }
}
