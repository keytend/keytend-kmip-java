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

package dev.keytend.kmip.cassandra.tls;

import static org.apache.cassandra.config.EncryptionOptions.ClientEncryptionOptions.ClientAuth.REQUIRED;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.TlsIdentityFollower.Status;
import java.math.BigInteger;
import java.nio.file.Files;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.SSLContext;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

/**
 * The material over the file-based connection parameters (PEM client identity and KMS CA), to a
 * KMS behind a mutual-TLS socket, as a node configures it, and as the dtest's nodes reach it.
 */
public class KmipTlsSocketTest {
  private KmsTestServer server;
  private Kms adminKms;
  private TlsAdmin admin;
  private TestPki.Issued ca;

  @Before
  public void start() throws Exception {
    server = new KmsTestServer(KmipVersion.V2_1, Files.createTempDirectory("kms-socket"));
    server.kmip().leaseTime(Duration.ofSeconds(300));
    adminKms = server.admin();
    admin = new TlsAdmin(adminKms);
    ca = TestPki.ca("Cluster1 CA");
    admin.addCa("cluster1", ca.certificate());
  }

  @After
  public void stop() throws Exception {
    KmipTlsMaterial.closeAll();
    adminKms.close();
    server.close();
  }

  @Test
  public void presentsTheKmsIdentityOverTheConfiguredConnection() throws Exception {
    TestPki.Issued node1 = TestPki.issue(ca, "node1", 11);
    admin.addIdentity("cluster1", "cluster1/node1", node1.privateKey(), node1.chain());
    TestPki.Issued app = TestPki.issue(ca, "app", 21);
    admin.addPeer("cluster1", app.certificate());

    Map<String, Object> parameters = new HashMap<>(server.parameters());
    parameters.put(KmipTlsMaterial.IDENTITY, "cluster1/node1");
    parameters.put(KmipTlsMaterial.DOMAIN, "cluster1");
    parameters.put(KmipTlsMaterial.REFRESH_INTERVAL, "1s");
    KmipSslContextFactory factory = new KmipSslContextFactory(parameters);
    SSLContext context = factory.createJSSESslContext(REQUIRED);
    assertThat(KmipSslContextFactoryTest.handshake(context, app, ca.certificate())).isEqualTo(BigInteger.valueOf(11));
    assertThat(factory.material().usableFor().orElseThrow()).isBetween(Duration.ofSeconds(290), Duration.ofSeconds(300));
    // a second factory (the other encryption option set) shares the material
    assertThat(new KmipSslContextFactory(new HashMap<>(parameters)).material()).isSameAs(factory.material());

    server.unreachable(true);
    factory.material().refresh();
    assertThat(factory.material().status()).isEqualTo(Status.STALE);
    assertThat(KmipSslContextFactoryTest.handshake(context, app, ca.certificate())).isEqualTo(BigInteger.valueOf(11));

    KmipTlsMaterial.closeAll();
    assertThatThrownBy(() -> new KmipSslContextFactory(parameters)).isInstanceOf(ConfigurationException.class);
  }
}
