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

import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.TlsIdentityFollower.Status;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.X509KeyManager;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * Node TLS material and client certificate authentication from a KMIP server, with real JSSE
 * handshakes between a server built from the factory's context and clients with their own
 * certificates.
 */
@RunWith(Parameterized.class)
public class KmipSslContextFactoryTest {
  private static final String DOMAIN = "cluster1";
  private static final String NODE = "cluster1/node1";
  private static final BigInteger ONE = BigInteger.ONE;

  @Parameterized.Parameter public KmipVersion version;

  private TestKms kms;
  private Kms adminKms;
  private TlsAdmin admin;
  private TestPki.Issued ca;
  private KeyHandle caHandle;

  @Parameterized.Parameters(name = "KMIP {0}")
  public static Collection<Object[]> versions() {
    return Arrays.asList(new Object[][] {{KmipVersion.V1_4}, {KmipVersion.V2_1}, {KmipVersion.V3_0}});
  }

  @Before
  public void start() throws Exception {
    kms = new TestKms(version);
    adminKms = kms.admin();
    admin = new TlsAdmin(adminKms);
    ca = TestPki.ca("Cluster1 CA");
    caHandle = admin.addCa(DOMAIN, ca.certificate());
  }

  @After
  public void stop() {
    adminKms.close();
    kms.close();
  }

  @Test
  public void caIsRegisteredWithTheUsagesOfItsKeyUsage() {
    // keyCertSign and cRLSign, as a KMIP 1.x server maps them; Verify would be refused by some 1.x servers
    assertThat(kms.a.usages(caHandle.id())).containsExactlyInAnyOrder(KeyUsage.CERTIFICATE_SIGN, KeyUsage.CRL_SIGN);
  }

  @Test
  public void identityPresentedAndRenewedWithoutRestart() throws Exception {
    TestPki.Issued node1 = addIdentity(1);
    TestPki.Issued client = addPeer("app", 2);
    KmipSslContextFactory factory = factory();
    SSLContext server = factory.createJSSESslContext(REQUIRED);
    assertThat(handshake(server, client)).isEqualTo(ONE);
    assertThat(factory.shouldReload()).isFalse();

    admin.renew(NODE, TestPki.issue(ca, "node1", 3, node1.keyPair()).chain());
    factory.material().refresh();
    assertThat(factory.shouldReload()).isTrue();
    // new connections present the renewed certificate, also on the context built before the renewal
    assertThat(handshake(server, client)).isEqualTo(BigInteger.valueOf(3));
    factory.createJSSESslContext(REQUIRED);
    assertThat(factory.shouldReload()).isFalse();
    // a server that states no Lease Time: nothing limits the material
    assertThat(factory.material().usableFor()).isEmpty();
  }

  /**
   * The refresh threads are the sample's, as the SDK's are: not in the thread group of the
   * Cassandra thread that first loads the material (an in-JVM dtest node's), with no context class
   * loader and none of its inheritable thread-locals. Created by a caller with its own group, class
   * loader and thread-local.
   */
  @Test
  public void refreshThreadsLeaveTheCallersThreadGroupClassLoaderAndThreadLocalsAlone() throws Exception {
    addIdentity(1);
    ThreadGroup caller = new ThreadGroup("a-cassandra-node");
    ClassLoader nodeLoader = new java.net.URLClassLoader(new java.net.URL[0], getClass().getClassLoader());
    InheritableThreadLocal<String> context = new InheritableThreadLocal<>();
    java.util.concurrent.atomic.AtomicReference<Object> made = new java.util.concurrent.atomic.AtomicReference<>();
    java.util.concurrent.atomic.AtomicReference<Object> seen = new java.util.concurrent.atomic.AtomicReference<>();
    Thread node = new Thread(caller, () -> {
      Thread.currentThread().setContextClassLoader(nodeLoader);
      context.set("request-1");
      try {
        made.set(factory());
        Thread t = KmipTlsMaterial.refreshThread(() -> seen.set(Arrays.asList(context.get(),
            Thread.currentThread().getContextClassLoader(), Thread.currentThread().getThreadGroup().getName())), "probe");
        t.start();
        t.join();
      } catch (Throwable e) {
        made.set(e);
      }
    }, "node-startup");
    node.start();
    node.join();
    assertThat(made.get()).isInstanceOf(KmipSslContextFactory.class);
    assertThat(seen.get()).isEqualTo(Arrays.asList(null, null, KmipTlsMaterial.THREAD_GROUP));
    ((KmipSslContextFactory) made.get()).material().refresh();
    java.util.List<Thread> refresh = Thread.getAllStackTraces().keySet().stream()
        .filter(t -> t.getName().equals("KmipTlsRefresh:" + NODE)).collect(java.util.stream.Collectors.toList());
    assertThat(refresh).isNotEmpty();
    for (Thread t : refresh) {
      assertThat(t.isDaemon()).isTrue();
      assertThat(t.getContextClassLoader()).isNull();
      for (ThreadGroup g = t.getThreadGroup(); g != null; g = g.getParent()) assertThat(g).isNotSameAs(caller);
      assertThat(t.getThreadGroup().getName()).isEqualTo(KmipTlsMaterial.THREAD_GROUP);
    }
    KmipTlsMaterial.closeAll();
  }

  @Test
  public void rekeyPresentsTheNewPairWithoutRestart() throws Exception {
    addIdentity(1);
    TestPki.Issued client = addPeer("app", 2);
    KmipSslContextFactory factory = factory();
    SSLContext server = factory.createJSSESslContext(REQUIRED);

    TestPki.Issued rekeyed = TestPki.issue(ca, "node1", 3);
    admin.rekey(NODE, rekeyed.privateKey(), rekeyed.chain());
    factory.material().refresh();
    assertThat(handshake(server, client)).isEqualTo(BigInteger.valueOf(3));
  }

  @Test
  public void registeredClientAcceptedUnregisteredAndRevokedRefused() throws Exception {
    addIdentity(1);
    TestPki.Issued client = addPeer("app", 2);
    TestPki.Issued stranger = TestPki.issue(ca, "stranger", 4); // signed by the CA, never registered
    KmipSslContextFactory factory = factory();
    SSLContext server = factory.createJSSESslContext(REQUIRED);
    KmipCertificateValidator validator = new KmipCertificateValidator();

    assertThat(handshake(server, client)).isEqualTo(ONE);
    assertThat(validator.isValidCertificate(chain(client))).isTrue();
    assertThat(validator.identity(chain(client))).isEqualTo("spiffe://cluster1/app");
    assertThatThrownBy(() -> handshake(server, stranger)).isInstanceOf(IOException.class);
    assertThat(validator.isValidCertificate(chain(stranger))).isFalse();
    // a certificate of another CA, never trusted
    TestPki.Issued foreign = TestPki.issue(TestPki.ca("Other CA"), "app", 2);
    assertThat(validator.isValidCertificate(chain(foreign))).isFalse();

    admin.revokePeer(DOMAIN, client.certificate());
    factory.material().refresh();
    assertThatThrownBy(() -> handshake(server, client)).isInstanceOf(IOException.class);
    assertThat(validator.isValidCertificate(chain(client))).isFalse();
  }

  @Test
  public void compromisedIdentityIsNoLongerPresentedThenRekeyedUnderTheSameName() throws Exception {
    addIdentity(1);
    TestPki.Issued client = addPeer("app", 2);
    KmipSslContextFactory factory = factory();
    SSLContext server = factory.createJSSESslContext(REQUIRED);
    assertThat(handshake(server, client)).isEqualTo(ONE);

    admin.revokeIdentity(NODE, true);
    factory.material().refresh();
    assertThat(factory.material().certificate()).isEmpty();
    assertThat(factory.material().status()).isEqualTo(Status.REVOKED);
    assertThat(factory.material().identityUsableFor()).contains(Duration.ZERO);
    assertThatThrownBy(() -> handshake(server, client)).isInstanceOf(IOException.class);
    // hot reloading cannot rebuild a context either, and keeps nothing it cannot serve
    assertThat(factory.shouldReload()).isTrue();
    assertThatThrownBy(() -> factory.createJSSESslContext(REQUIRED)).hasMessageContaining("no Active TLS identity");
    // nor can a node start with it
    KmipTlsMaterial.closeAll();
    assertThatThrownBy(this::factory).isInstanceOf(ConfigurationException.class).hasMessageContaining("Cannot load TLS identity");

    // re-keyed from the compromised identity, under the same name: presented again
    TestPki.Issued replacement = TestPki.issue(ca, "node1", 5);
    admin.rekey(NODE, replacement.privateKey(), replacement.chain());
    assertThat(handshake(factory().createJSSESslContext(REQUIRED), client)).isEqualTo(BigInteger.valueOf(5));
  }

  @Test
  public void kmsUnreachableKeepsTheMaterialWhileItsLeasesRun() throws Exception {
    kms.a.leaseTime(Duration.ofHours(1));
    addIdentity(1);
    TestPki.Issued client = addPeer("app", 2);
    KmipSslContextFactory factory = factory();
    SSLContext server = factory.createJSSESslContext(REQUIRED);
    KmipTlsMaterial material = factory.material();
    Duration leased = material.identityUsableFor().orElseThrow();
    assertThat(leased).isBetween(Duration.ofMinutes(59), Duration.ofHours(1));
    assertThat(material.trustUsableFor().orElseThrow()).isBetween(Duration.ofMinutes(59), Duration.ofHours(1));

    kms.down(true);
    material.refresh();
    assertThat(material.status()).isEqualTo(Status.STALE);
    assertThat(handshake(server, client)).isEqualTo(ONE);
    assertThat(factory.shouldReload()).isFalse();
    // falling while the KMS is down, for metrics and alerts
    Duration left = material.identityUsableFor().orElseThrow();
    assertThat(left).isPositive().isLessThanOrEqualTo(leased);
    assertThat(KmipTlsMaterial.minUsableFor().orElseThrow()).isPositive().isLessThanOrEqualTo(left);
    assertThat(material.toString()).contains("STALE").contains("last refresh failed");

    kms.down(false);
    material.refresh();
    assertThat(material.status()).isEqualTo(Status.CURRENT);

    // a node that starts while the KMS is down does not start: there is no on-disk copy
    KmipTlsMaterial.closeAll();
    kms.down(true);
    assertThatThrownBy(this::factory).isInstanceOf(ConfigurationException.class);
  }

  @Test
  public void warnsWhenTheMaterialIsUsableForLessThanTheThreshold() throws Exception {
    kms.a.leaseTime(Duration.ofMinutes(10));
    addIdentity(1);
    // default: a quarter of the longest time seen, about the Lease Time
    KmipTlsMaterial quiet = factory().material();
    assertThat(quiet.usableWarning()).isFalse();
    assertThat(quiet.usableWarnThreshold()).isBetween(Duration.ofSeconds(140), Duration.ofSeconds(150));
    // a threshold above the Lease Time: always below it
    KmipTlsMaterial loud = factory(KmipTlsMaterial.USABLE_WARN, "1h").material();
    assertThat(loud).isNotSameAs(quiet);
    assertThat(loud.usableWarning()).isTrue();
    assertThat(loud.usableWarnThreshold()).isEqualTo(Duration.ofHours(1));
  }

  @Test
  public void renewedPeerIsRefusedAtItsFirstHandshakeAndAcceptedAtTheNext() throws Exception {
    addIdentity(1);
    TestPki.Issued node2 = TestPki.issue(ca, "node2", 2);
    admin.addIdentity(DOMAIN, "cluster1/node2", node2.privateKey(), node2.chain());
    KmipSslContextFactory factory = factory();
    SSLContext server = factory.createJSSESslContext(REQUIRED);
    KmipCertificateValidator validator = new KmipCertificateValidator();
    assertThat(handshake(server, node2)).isEqualTo(ONE);

    // node2 renews; its new leaf has the tag, and node1 has not read it yet
    TestPki.Issued renewed = TestPki.issue(ca, "node2", 7, node2.keyPair());
    admin.renew("cluster1/node2", renewed.chain());
    assertThat(validator.isValidCertificate(chain(renewed))).isFalse();
    // refused at once, without waiting for the KMS; the check runs in the background
    long began = System.nanoTime();
    assertThatThrownBy(() -> handshake(server, renewed)).isInstanceOf(IOException.class);
    assertThat(Duration.ofNanos(System.nanoTime() - began)).isLessThan(Duration.ofSeconds(2));
    await(() -> factory.material().allows(renewed.chain()));
    assertThat(handshake(server, renewed)).isEqualTo(ONE);
    assertThat(validator.isValidCertificate(chain(renewed))).isTrue();
    // the old certificate, deactivated by the renewal, is refused once node1 has read that
    factory.material().refresh();
    assertThatThrownBy(() -> handshake(server, node2)).isInstanceOf(IOException.class);
  }

  @Test
  public void theValidatorNeverConsultsAMaterialThatChecksOnlyTheAnchors() throws Exception {
    KmipTlsMaterial.closeAll(); // the validator asks every material of the JVM
    addIdentity(1);
    TestPki.Issued client = addPeer("app", 2);
    KmipSslContextFactory anchorsOnly = factory(KmipTlsMaterial.REQUIRE_REGISTERED_PEERS, "false");
    KmipCertificateValidator validator = new KmipCertificateValidator();
    // a certificate that chains to the anchors but is not registered: the anchors-only material
    // would allow it, and is not asked
    TestPki.Issued stranger = TestPki.issue(ca, "stranger", 4);
    assertThat(anchorsOnly.material().allows(stranger.chain())).isTrue();
    assertThat(validator.isValidCertificate(chain(stranger))).isFalse();
    assertThat(validator.isValidCertificate(chain(client))).isFalse(); // no material requires registered peers
    KmipSslContextFactory registered = factory();
    assertThat(validator.isValidCertificate(chain(client))).isTrue();
    assertThat(validator.isValidCertificate(chain(stranger))).isFalse();
    assertThat(registered.material().requiresRegisteredPeers()).isTrue();
  }

  @Test
  public void unknownPeerCheckInHandshakeAcceptsAtTheFirstHandshake() throws Exception {
    addIdentity(1);
    KmipSslContextFactory factory = factory(KmipTlsMaterial.UNKNOWN_PEER_CHECK_IN_HANDSHAKE, "true");
    SSLContext server = factory.createJSSESslContext(REQUIRED);
    TestPki.Issued late = addPeer("late", 8); // registered after the material was read
    assertThat(handshake(server, late)).isEqualTo(ONE);
  }

  @Test
  public void unknownPeerCheckOffRefusesUntilTheNextRefresh() throws Exception {
    addIdentity(1);
    KmipSslContextFactory factory = factory(KmipTlsMaterial.UNKNOWN_PEER_CHECK, "0s");
    SSLContext server = factory.createJSSESslContext(REQUIRED);
    TestPki.Issued late = addPeer("late", 8);
    assertThatThrownBy(() -> handshake(server, late)).isInstanceOf(IOException.class);
    Thread.sleep(1500);
    assertThatThrownBy(() -> handshake(server, late)).isInstanceOf(IOException.class);
    factory.material().refresh();
    assertThat(handshake(server, late)).isEqualTo(ONE);
  }

  /**
   * The check's rate limits are parameters: by default a certificate refused once is not checked
   * again for 30 s; with the per-certificate interval and the gap lifted, it is checked at once.
   * A queue that is not a positive number is refused.
   */
  @Test
  public void unknownPeerCheckRateLimitsAreParameters() throws Exception {
    addIdentity(1);
    TestPki.Issued early = TestPki.issue(ca, "early", 8); // presented before it is registered
    KmipSslContextFactory defaults = factory(KmipTlsMaterial.UNKNOWN_PEER_CHECK_IN_HANDSHAKE, "true");
    SSLContext server = defaults.createJSSESslContext(REQUIRED);
    assertThatThrownBy(() -> handshake(server, early)).isInstanceOf(IOException.class);
    admin.addPeer(DOMAIN, early.certificate());
    assertThatThrownBy(() -> handshake(server, early)).isInstanceOf(IOException.class); // within 30 s
    KmipTlsMaterial.closeAll();

    TestPki.Issued later = TestPki.issue(ca, "later", 9);
    KmipSslContextFactory lifted = factory(KmipTlsMaterial.UNKNOWN_PEER_CHECK_IN_HANDSHAKE, "true",
                                           KmipTlsMaterial.UNKNOWN_PEER_CHECK_PER_CERTIFICATE, "0s",
                                           KmipTlsMaterial.UNKNOWN_PEER_CHECK_GAP, "0s",
                                           KmipTlsMaterial.UNKNOWN_PEER_CHECK_QUEUE, "8");
    SSLContext liftedServer = lifted.createJSSESslContext(REQUIRED);
    assertThatThrownBy(() -> handshake(liftedServer, later)).isInstanceOf(IOException.class);
    admin.addPeer(DOMAIN, later.certificate());
    assertThat(handshake(liftedServer, later)).isEqualTo(ONE); // the node's certificate, presented
    KmipTlsMaterial.closeAll();

    for (String bad : new String[] {"0", "-1", "many"})
      assertThatThrownBy(() -> factory(KmipTlsMaterial.UNKNOWN_PEER_CHECK_QUEUE, bad))
          .isInstanceOf(ConfigurationException.class)
          .hasMessageContaining(KmipTlsMaterial.UNKNOWN_PEER_CHECK_QUEUE);
  }

  @Test
  public void privateKeyIsExtractedFromTheKms() throws Exception {
    TestPki.Issued node1 = addIdentity(1);
    X509KeyManager km = (X509KeyManager) factory().material().keyManager();
    String alias = km.chooseServerAlias("EC", null, null);
    assertThat(km.getPrivateKey(alias).getEncoded()).isEqualTo(node1.privateKey().getEncoded());
    assertThat(km.getCertificateChain(alias)).containsExactly(node1.chain());
  }

  private TestPki.Issued addIdentity(long serial) throws Exception {
    TestPki.Issued node = TestPki.issue(ca, "node1", serial);
    admin.addIdentity(DOMAIN, NODE, node.privateKey(), node.chain());
    return node;
  }

  private TestPki.Issued addPeer(String name, long serial) throws Exception {
    TestPki.Issued peer = TestPki.issue(ca, name, serial);
    admin.addPeer(DOMAIN, peer.certificate());
    return peer;
  }

  private KmipSslContextFactory factory(String... extra) {
    Map<String, Object> parameters = new HashMap<>();
    parameters.put(KmipConnections.ENDPOINTS, "in-memory:5696");
    parameters.put(KmipTlsMaterial.IDENTITY, NODE);
    parameters.put(KmipTlsMaterial.DOMAIN, DOMAIN);
    parameters.put("require_client_auth", "required");
    for (int i = 0; i < extra.length; i += 2) parameters.put(extra[i], extra[i + 1]);
    return new KmipSslContextFactory(parameters);
  }

  private static Certificate[] chain(TestPki.Issued who) {
    return who.chain();
  }

  private static void await(BooleanSupplier condition) throws InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (!condition.getAsBoolean()) {
      if (System.nanoTime() > deadline) throw new AssertionError("not within 10 s");
      Thread.sleep(50);
    }
  }

  /** A handshake of {@code client} with a server on {@code server}; returns the serial the server presented. */
  private BigInteger handshake(SSLContext server, TestPki.Issued client) throws Exception {
    return handshake(server, client, ca.certificate());
  }

  static BigInteger handshake(SSLContext server, TestPki.Issued client, X509Certificate anchor) throws Exception {
    InetAddress loopback = InetAddress.getLoopbackAddress();
    try (SSLServerSocket listener = (SSLServerSocket) server.getServerSocketFactory().createServerSocket(0, 1, loopback)) {
      listener.setNeedClientAuth(true);
      CompletableFuture<Void> accepted = CompletableFuture.runAsync(() -> {
        try (SSLSocket s = (SSLSocket) listener.accept()) {
          s.setSoTimeout(5000);
          s.startHandshake();
          s.getOutputStream().write(1);
          s.getOutputStream().flush();
        } catch (IOException refused) {
          // the client sees it
        }
      });
      try (SSLSocket socket = (SSLSocket) TestPki.context(client, anchor).getSocketFactory()
          .createSocket(loopback, listener.getLocalPort())) {
        socket.setSoTimeout(5000);
        socket.startHandshake();
        if (socket.getInputStream().read() != 1) throw new IOException("the server closed the connection");
        return ((X509Certificate) socket.getSession().getPeerCertificates()[0]).getSerialNumber();
      } finally {
        accepted.get(10, TimeUnit.SECONDS);
      }
    }
  }
}
