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

package dev.keytend.kmip.kms;

import static dev.keytend.kmip.TestAwait.await;
import static dev.keytend.kmip.kms.KmsApiTest.pem;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.testing.TlsListener;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * {@link Kms#renewClientCertificate()} and automatic renewal against the in-memory server's
 * Re-Provision ({@link TlsListener.Builder#provisioningCa}): the files on disk, the switch of
 * every {@code Kms} of a configuration, the retired certificate, lost replies, the lockout, and the
 * configurations that cannot be renewed.
 */
class ClientCertificateRenewalTest {
  static final Duration RENEW_WITHIN = Duration.ofDays(60);

  @AfterEach
  void reset() {
    ReProvisionValidity.vendor = ReProvisionValidity.VENDOR;
    ReProvisionValidity.critical = true;
    StagedFiles.directorySync = StagedFiles::forceDirectory;
    ClientRenewal.firstBackoff = Duration.ofMinutes(1);
    ClientRenewal.maxBackoff = Duration.ofHours(1);
    ClientRenewal.maxCheck = Duration.ofHours(1);
    ClientRenewal.beforeReProvision = null;
  }

  /** A CA for the server and the client, a provisioning CA, and the client's PEM files. */
  static final class Pki {
    final Issued ca = TestPki.ca("Listener CA");

    /** Valid for longer than the certificates it issues (a year), so it does not cut them short. */
    final Issued provisioning = longLivedCa("Provisioning CA");

    final Issued server = TestPki.leaf("in-memory-kms", TestPki.ec(), ca);
    final Issued client;
    final Path dir, caPem, chain, key;

    Pki(Path dir, KeyPair clientKey) throws Exception {
      this.dir = dir;
      client = TestPki.leaf("client", clientKey, ca);
      caPem = dir.resolve("ca.crt");
      Files.writeString(caPem, pem("CERTIFICATE", ca.certificate().getEncoded()));
      chain = dir.resolve("client.crt");
      key = dir.resolve("client.key");
      Files.writeString(chain, pem("CERTIFICATE", client.certificate().getEncoded()));
      Files.writeString(key, pem("PRIVATE KEY", client.key().getEncoded()));
    }

    Pki(Path dir) throws Exception {
      this(dir, TestPki.ec());
    }

    TlsListener.Builder listener(InMemoryKmipServer kms) {
      return kms.tlsListener()
          .identity(server.key(), server.certificate(), ca.certificate())
          .trustAnchors(ca.certificate(), provisioning.certificate())
          .provisioningCa(provisioning.key(), provisioning.certificate());
    }

    KmsConfig.Builder client(TlsListener tls) {
      return tls.configure()
          .trustPem(caPem)
          .connectTimeout(Duration.ofSeconds(5))
          .callTimeout(Duration.ofSeconds(10));
    }

    KmsConfig.Builder renewing(TlsListener tls, CertificateRenewal renewal) {
      return client(tls).clientIdentityPem(chain, key).clientCertificateRenewal(renewal);
    }
  }

  static Issued longLivedCa(String name) throws Exception {
    KeyPair k = TestPki.ec();
    Instant now = Instant.now();
    return new Issued(
        dev.keytend.kmip.TestX509.certificate(name, k.getPublic())
            .selfSigned(k.getPrivate())
            .ca()
            .keyUsage(TestPki.KEY_CERT_SIGN, TestPki.CRL_SIGN)
            .validity(now.minus(Duration.ofDays(1)), now.plus(Duration.ofDays(800)))
            .build(),
        k.getPrivate());
  }

  /** Records the renewal events. */
  static final class Events implements KmsListener {
    final List<String> renewed = new CopyOnWriteArrayList<>(),
        failed = new CopyOnWriteArrayList<>(),
        lockedOut = new CopyOnWriteArrayList<>(),
        warned = new CopyOnWriteArrayList<>(),
        failedFingerprints = new CopyOnWriteArrayList<>();

    @Override
    public void clientCertificateRenewed(String previous, String fingerprint, Instant notAfter) {
      renewed.add(previous + " -> " + fingerprint);
    }

    @Override
    public void clientCertificateRenewalFailed(String fingerprint, String why) {
      failed.add(why);
      failedFingerprints.add(String.valueOf(fingerprint));
    }

    @Override
    public void clientCertificateMayBeLockedOut(String fingerprint, String why) {
      lockedOut.add(why);
    }

    @Override
    public void clientCertificateRenewalWarning(String fingerprint, String why) {
      warned.add(why);
    }
  }

  static X509Certificate leaf(Path chain) {
    return PemIdentity.certificates(chain, TlsFiles.WHOLE).get(0);
  }

  @Test
  void onDemandRenewalReplacesTheFilesAndRetiresTheOldCertificate(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    byte[] oldChain = Files.readAllBytes(pki.chain), oldKey = Files.readAllBytes(pki.key);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      KeyHandle key = kms.keys().createAes(256).named("before").usages(KeyUsage.ENCRYPT).create();
      RenewedCertificate r = kms.renewClientCertificate();

      X509Certificate issued = r.certificate();
      assertEquals(
          pki.client.certificate().getSubjectX500Principal(), issued.getSubjectX500Principal());
      assertEquals(
          List.copyOf(pki.client.certificate().getSubjectAlternativeNames()),
          List.copyOf(issued.getSubjectAlternativeNames()));
      assertEquals(
          pki.provisioning.certificate().getSubjectX500Principal(),
          issued.getIssuerX500Principal());
      assertEquals(RenewalFiles.fingerprint(pki.client.certificate()), r.previousFingerprint());
      assertEquals(RenewalFiles.fingerprint(issued), r.fingerprint());
      assertFalse(r.finishedEarlierAttempt());
      assertTrue(server.exists(r.certificateId()));
      assertEquals(List.of(r.previousFingerprint() + " -> " + r.fingerprint()), events.renewed);
      assertEquals(List.of(), events.failed);

      // The files: the new chain and a new key of the same kind, no pending file left.
      assertEquals(issued, leaf(pki.chain));
      assertFalse(Files.exists(dir.resolve("client.key.renewal")));
      KmsConfig reread = pki.client(tls).clientIdentityPem(pki.chain, pki.key).build();
      assertNotNull(reread);
      if (Files.getFileStore(pki.key).supportsFileAttributeView("posix"))
        assertEquals(
            Set.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE),
            Files.getPosixFilePermissions(pki.key));

      // The server retired the old certificate; new connections present the new one.
      assertEquals(List.of(pki.client.certificate()), tls.retiredCertificates());
      tls.dropConnections();
      assertEquals(KeyState.ACTIVE, key.attributes().state());
      List<X509Certificate> presented = tls.clientCertificates();
      assertEquals(issued, presented.get(presented.size() - 1));

      // The old files are refused on new connections.
      Path old = dir.resolve("old");
      Files.createDirectory(old);
      Files.write(old.resolve("c.crt"), oldChain);
      Files.write(old.resolve("c.key"), oldKey);
      KmsConfig retired =
          pki.client(tls).clientIdentityPem(old.resolve("c.crt"), old.resolve("c.key")).build();
      assertThrows(PermissionDeniedException.class, () -> Kms.connect(retired).close());
      assertEquals(List.of(), server.violations());
    }
  }

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V2_0", "V3_0"})
  void renewalWorksAtEachVersionThatHasReProvision(KmipVersion version, @TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand())
                    .maximumVersion(KmipVersion.V3_0)
                    .build())) {
      assertEquals(version, kms.version());
      RenewedCertificate r = kms.renewClientCertificate();
      assertEquals(r.certificate(), leaf(pki.chain));
      tls.dropConnections();
      kms.ping();
      assertEquals(List.of(), server.violations());
    }
  }

  @Test
  void anEncryptedRsaKeyIsReplacedByOneUnderTheSamePassword(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir, TestPki.rsa());
    char[] password = "pass-word-1".toCharArray();
    byte[] encrypted = new RenewalFiles(null).encrypt(pki.client.key().getEncoded(), password);
    Files.write(pki.key, RenewalFiles.pem("ENCRYPTED PRIVATE KEY", encrypted));
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.client(tls)
                    .clientIdentityPem(pki.chain, pki.key, password)
                    .clientCertificateRenewal(CertificateRenewal.onDemand())
                    .build())) {
      RenewedCertificate r = kms.renewClientCertificate();
      assertEquals("RSA", r.certificate().getPublicKey().getAlgorithm());
      assertEquals(
          2048,
          ((java.security.interfaces.RSAPublicKey) r.certificate().getPublicKey())
              .getModulus()
              .bitLength());
      assertTrue(Files.readString(pki.key).contains("BEGIN ENCRYPTED PRIVATE KEY"));
      assertThrows(
          IllegalArgumentException.class,
          () -> pki.client(tls).clientIdentityPem(pki.chain, pki.key).build(),
          "the new key needs the password");
      assertNotNull(pki.client(tls).clientIdentityPem(pki.chain, pki.key, password).build());
    }
  }

  @Test
  void aCombinedFileAndAKeyStoreAreRenewedInPlace(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    // One file holding the chain and the key.
    Path both = dir.resolve("client.pem");
    Files.writeString(
        both,
        pem("CERTIFICATE", pki.client.certificate().getEncoded())
            + pem("PRIVATE KEY", pki.client.key().getEncoded()));
    try (TlsListener tls = pki.listener(server).start()) {
      try (Kms kms =
          Kms.connect(
              pki.client(tls)
                  .clientIdentityPem(both, both)
                  .clientCertificateRenewal(CertificateRenewal.onDemand())
                  .build())) {
        RenewedCertificate r = kms.renewClientCertificate();
        assertEquals(
            r.certificate(),
            PemIdentity.certificates(Files.readAllBytes(both), both, true, false).get(0));
        tls.dropConnections();
        kms.ping();
      }
      // A PKCS#12 key store, with another client's certificate (the provisioning CA issues to it).
      Issued second = TestPki.leaf("second-client", TestPki.ec(), pki.ca);
      char[] password = "store-pass".toCharArray();
      Path store = dir.resolve("client.p12");
      KeyStore ks = KeyStore.getInstance("PKCS12");
      ks.load(null, null);
      ks.setKeyEntry("me", second.key(), password, new Certificate[] {second.certificate()});
      ks.setCertificateEntry("extra", pki.ca.certificate());
      try (var out = Files.newOutputStream(store)) {
        ks.store(out, password);
      }
      try (Kms kms =
          Kms.connect(
              pki.client(tls)
                  .clientIdentityKeyStore(store, password)
                  .clientCertificateRenewal(CertificateRenewal.onDemand())
                  .build())) {
        RenewedCertificate r = kms.renewClientCertificate();
        KeyStore after = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(store)) {
          after.load(in, password);
        }
        assertEquals(Set.of("me", "extra"), Set.copyOf(Collections.list(after.aliases())));
        assertEquals(r.certificate(), after.getCertificate("me"));
        assertTrue(after.isCertificateEntry("extra"));
        assertFalse(Files.exists(dir.resolve("client.p12.renewal")));
      }
      // A JKS key store stays JKS.
      Issued third = TestPki.leaf("third-client", TestPki.ec(), pki.ca);
      Path jks = dir.resolve("client.jks");
      KeyStore js = KeyStore.getInstance("JKS");
      js.load(null, null);
      js.setKeyEntry("me", third.key(), password, new Certificate[] {third.certificate()});
      try (var out = Files.newOutputStream(jks)) {
        js.store(out, password);
      }
      try (Kms kms =
          Kms.connect(
              pki.client(tls)
                  .clientIdentityKeyStore(jks, password)
                  .clientCertificateRenewal(CertificateRenewal.onDemand())
                  .build())) {
        RenewedCertificate r = kms.renewClientCertificate();
        byte[] magic = java.util.Arrays.copyOf(Files.readAllBytes(jks), 4);
        assertArrayEquals(new byte[] {(byte) 0xfe, (byte) 0xed, (byte) 0xfe, (byte) 0xed}, magic);
        KeyStore after = KeyStore.getInstance("JKS");
        try (var in = Files.newInputStream(jks)) {
          after.load(in, password);
        }
        assertEquals(r.certificate(), after.getCertificate("me"));
      }
      assertEquals(3, tls.retiredCertificates().size());
    }
  }

  @Test
  void everyKmsOfTheConfigurationSwitchesWithOrWithoutReload(@TempDir Path dir) throws Exception {
    for (boolean reload : new boolean[] {false, true}) {
      Path sub = dir.resolve("reload-" + reload);
      Files.createDirectory(sub);
      Pki pki = new Pki(sub);
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      try (TlsListener tls = pki.listener(server).start()) {
        KmsConfig.Builder b = pki.renewing(tls, CertificateRenewal.onDemand());
        if (reload) b.reloadOnChange(Duration.ofMillis(50));
        KmsConfig config = b.build();
        try (Kms first = Kms.connect(config);
            Kms second = Kms.connect(config)) {
          second.ping();
          RenewedCertificate r = first.renewClientCertificate();
          // The second's pooled connection on the old certificate still works, then closes; a new
          // connection presents the new certificate.
          second.ping();
          tls.dropConnections();
          second.ping();
          List<X509Certificate> presented = tls.clientCertificates();
          assertEquals(r.certificate(), presented.get(presented.size() - 1), "reload " + reload);
          try (Kms third = Kms.connect(config)) {
            third.ping();
          }
          // toBuilder keeps the renewed identity.
          try (Kms fourth = Kms.connect(config.toBuilder().build())) {
            fourth.ping();
          }
        }
      }
    }
  }

  @Test
  void aBuilderReusedOrLoadedBeforeARenewalUsesTheRenewedCertificate(@TempDir Path dir)
      throws Exception {
    builderReusedOrLoadedBeforeARenewal(dir);
  }

  /**
   * The same under a PKIX key manager ({@code ssl.KeyManagerFactory.algorithm}, as FIPS setups
   * may set it), whose alias names differ from SunX509's: the builder keeps the leaf it loaded, so
   * no alias name matters.
   */
  @Test
  void aBuilderReusedOrLoadedBeforeARenewalUsesTheRenewedCertificateUnderPkix(@TempDir Path dir)
      throws Exception {
    String was = java.security.Security.getProperty("ssl.KeyManagerFactory.algorithm");
    java.security.Security.setProperty("ssl.KeyManagerFactory.algorithm", "PKIX");
    try {
      assertEquals("PKIX", javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
      builderReusedOrLoadedBeforeARenewal(dir);
    } finally {
      java.security.Security.setProperty(
          "ssl.KeyManagerFactory.algorithm", was == null ? "SunX509" : was);
    }
  }

  private static void builderReusedOrLoadedBeforeARenewal(Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start()) {
      // Both builders read the current certificate's files now: one is built from again after
      // the renewal, the other only after it.
      KmsConfig.Builder reused = pki.renewing(tls, CertificateRenewal.onDemand());
      KmsConfig.Builder early = pki.renewing(tls, CertificateRenewal.onDemand());
      RenewedCertificate first;
      try (Kms kms = Kms.connect(reused.build())) {
        first = kms.renewClientCertificate();
      }
      tls.dropConnections();
      // The server refuses the retired certificate on new connections: each builds a
      // configuration that presents the renewed one.
      for (KmsConfig.Builder b : List.of(reused, early))
        try (Kms kms = Kms.connect(b.build())) {
          kms.ping();
          assertEquals(first.certificate(), lastPresented(tls));
        }
      // After a second renewal, a builder loaded before both presents the latest certificate.
      RenewedCertificate second;
      try (Kms kms = Kms.connect(reused.build())) {
        second = kms.renewClientCertificate();
      }
      tls.dropConnections();
      try (Kms kms = Kms.connect(early.build())) {
        kms.ping();
        assertEquals(second.certificate(), lastPresented(tls));
      }
      // One that reads the files now holds the latest itself, and renews from it.
      try (Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
        kms.ping();
        assertEquals(second.certificate(), lastPresented(tls));
        assertEquals(second.fingerprint(), kms.renewClientCertificate().previousFingerprint());
      }
      assertEquals(3, tls.retiredCertificates().size());
    }
  }

  static X509Certificate lastPresented(TlsListener tls) {
    List<X509Certificate> presented = tls.clientCertificates();
    return presented.get(presented.size() - 1);
  }

  @Test
  void aServerClockAheadOfTheClientsIsNoReasonToRefuse(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    // The server's clock is twenty minutes ahead of this machine's: it dates the new certificate
    // from five minutes before its own time, fifteen minutes after this machine's, and checks it
    // by its own clock.
    Duration ahead = Duration.ofMinutes(20);
    server.clock(java.time.Clock.offset(java.time.Clock.systemUTC(), ahead));
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand().validFor(Duration.ofDays(30)))
                    .addListener(events)
                    .build())) {
      RenewedCertificate r = kms.renewClientCertificate();
      assertEquals(r.certificate(), leaf(pki.chain), "switched");
      assertTrue(r.certificate().getNotBefore().toInstant().isAfter(Instant.now()));
      assertEquals(List.of(pki.client.certificate()), tls.retiredCertificates());
      assertTrue(events.lockedOut.isEmpty());
      assertEquals(1, events.renewed.size());
      // Reported, not refused.
      assertEquals(1, events.warned.size(), events.warned.toString());
      assertTrue(events.warned.get(0).contains("clock is likely behind"), events.warned.get(0));
      // The notAfter asked for is by the server's clock, as the server dates the certificate.
      Duration off =
          Duration.between(Instant.now().plus(ahead).plus(Duration.ofDays(30)), r.notAfter());
      assertTrue(off.abs().compareTo(Duration.ofMinutes(1)) < 0, r.notAfter().toString());
    }
  }

  @Test
  void aLostReplyIsRecoveredThroughTheStandbyConnection(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      server.failNext(ServerOperation.RE_PROVISION, Fault.REPLY_LOST);
      RenewedCertificate r = kms.renewClientCertificate();
      assertEquals(r.certificate(), leaf(pki.chain));
      assertEquals(1, tls.retiredCertificates().size());
      assertEquals(1, events.renewed.size());
      tls.dropConnections();
      kms.ping();
    }
  }

  @Test
  void aReplyLostBeforeTheServerIssuedIsSafeToRepeat(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      server.injectBeforeProcessing(
          request -> reProvision(request) ? new SocketTimeoutException("lost before") : null);
      TransientException e = assertThrows(TransientException.class, kms::renewClientCertificate);
      assertTrue(e.getMessage().contains("issued no certificate"), e.getMessage());
      Path pending = dir.resolve("client.key.renewal");
      assertTrue(Files.exists(pending), "the new key is kept");
      assertEquals(List.of(), tls.retiredCertificates());
      assertEquals(1, events.failed.size());
      String keptKey = Files.readString(pending);

      RenewedCertificate r = kms.renewClientCertificate();
      assertFalse(r.finishedEarlierAttempt(), "the server was asked again");
      assertTrue(
          keptKey.contains(
              java.util.Base64.getEncoder()
                  .encodeToString(r.certificate().getPublicKey().getEncoded())),
          "with the same key");
      assertFalse(Files.exists(pending));
    }
  }

  static boolean reProvision(Ttlv request) {
    for (Ttlv item : request.children(Tag.BATCH_ITEM))
      if (item.child(Tag.OPERATION).map(Ttlv::intValue).orElse(0) == Operation.RE_PROVISION.code())
        return true;
    return false;
  }

  @Test
  void aLostReplyWithNoConnectionLeftMayLockTheClientOut(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand()).addListener(events).build())) {
      // The server commits, then every connection drops before the reply.
      server.injectAfterProcessing(
          request -> {
            if (!reProvision(request)) return null;
            tls.dropConnections();
            return new SocketTimeoutException("lost after");
          });
      OutcomeUnknownException e =
          assertThrows(OutcomeUnknownException.class, kms::renewClientCertificate);
      assertTrue(e.getMessage().contains("may be locked out"), e.getMessage());
      assertTrue(e.getMessage().contains("client.key.renewal"), e.getMessage());
      assertTrue(e.getMessage().contains("Lockout recovery"), e.getMessage());
      assertEquals(1, events.lockedOut.size());
      assertEquals(List.of(), events.failed);
      assertEquals(1, tls.retiredCertificates().size());
      assertTrue(Files.exists(dir.resolve("client.key.renewal")));

      // A new process: the connect is refused, and says why.
      PermissionDeniedException refused =
          assertThrows(
              PermissionDeniedException.class,
              () -> Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build()).close());
      assertTrue(refused.getMessage().contains("may be locked out"), refused.getMessage());
      // Again in this process: the old certificate is refused on new connections.
      assertThrows(OutcomeUnknownException.class, kms::renewClientCertificate);
      assertEquals(2, events.lockedOut.size());
    }
  }

  @Test
  void aSwitchThatStoppedBetweenItsFilesIsFinishedByTheNextStart(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicInteger forces = new AtomicInteger();
    try (TlsListener tls = pki.listener(server).start()) {
      try (Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
        // Forces: the pending key, the pending key and certificate, the chain file (fails).
        StagedFiles.directorySync =
            d -> {
              if (forces.incrementAndGet() == 3) throw new IOException("injected");
            };
        IOException e = assertThrows(IOException.class, kms::renewClientCertificate);
        assertTrue(e.getMessage().contains("this process uses it"), e.getMessage());
        StagedFiles.directorySync = d -> {};
        // This process goes on with the new certificate.
        tls.dropConnections();
        kms.ping();
        // The chain file holds the new certificate, the key file the old key.
        X509Certificate chainNow = leaf(pki.chain);
        assertNotEquals(pki.client.certificate(), chainNow);
        assertThrows(
            IllegalArgumentException.class,
            () -> KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem));
        assertEquals(chainNow, leaf(pki.chain));
      }
      // The next start finishes the switch before it reads the files.
      try (Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
        kms.ping();
        assertFalse(Files.exists(dir.resolve("client.key.renewal")));
        assertNotNull(KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem));
      }
    }
  }

  /** The Re-Provision batch item of the last message the server received. */
  static Ttlv reProvisionItem(InMemoryKmipServer server) {
    List<Ttlv> requests = server.protocolRequests();
    for (int i = requests.size() - 1; i >= 0; i--)
      for (Ttlv item : requests.get(i).children(Tag.BATCH_ITEM))
        if (item.require(Tag.OPERATION).intValue() == Operation.RE_PROVISION.code()) return item;
    throw new AssertionError("no Re-Provision sent");
  }

  @Test
  void aRequestedValidityIsACriticalExtensionTheServerHonorsOnEveryVersion(@TempDir Path dir)
      throws Exception {
    for (KmipVersion version : List.of(KmipVersion.V2_0, KmipVersion.V2_1, KmipVersion.V3_0)) {
      Path sub = dir.resolve(version.name());
      Files.createDirectory(sub);
      Pki pki = new Pki(sub);
      InMemoryKmipServer server = InMemoryKmipServer.of(version);
      Duration asked = Duration.ofDays(30);
      try (TlsListener tls = pki.listener(server).start();
          Kms kms =
              Kms.connect(
                  pki.renewing(tls, CertificateRenewal.onDemand().validFor(asked)).build())) {
        Instant before = Instant.now();
        RenewedCertificate r = kms.renewClientCertificate();
        Instant after = Instant.now();
        // The notAfter asked for, to the second, never cut short.
        assertFalse(r.notAfter().isBefore(before.plus(asked).minusSeconds(1)), version.name());
        assertFalse(r.notAfter().isAfter(after.plus(asked)), version.name());
        assertEquals(r.certificate(), leaf(pki.chain), "switched");
        // On the wire: one Critical keytend_kmip_server extension on the Re-Provision item.
        List<Ttlv> extensions = reProvisionItem(server).children(Tag.MESSAGE_EXTENSION);
        assertEquals(1, extensions.size());
        Ttlv e = extensions.get(0);
        assertEquals("keytend_kmip_server", e.require(Tag.VENDOR_IDENTIFICATION).textValue());
        assertTrue(e.require(Tag.CRITICALITY_INDICATOR).booleanValue());
        List<Ttlv> body = e.require(Tag.VENDOR_EXTENSION).children();
        assertEquals(1, body.size());
        assertEquals(Tag.DEACTIVATION_DATE.code(), body.get(0).tag());
        assertEquals(r.notAfter(), body.get(0).instantValue());
        // The stored certificate's Deactivation Date is that date; it is Active.
        KeyAttributes stored = kms.keys().read(r.certificateId()).orElseThrow();
        assertEquals(r.notAfter(), stored.deactivationDate().orElseThrow());
        assertEquals(KeyState.ACTIVE, stored.state());
      }
    }
  }

  @Test
  void withoutAValidityNoExtensionIsSent(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      RenewedCertificate r = kms.renewClientCertificate();
      assertTrue(reProvisionItem(server).children(Tag.MESSAGE_EXTENSION).isEmpty());
      assertTrue(r.notAfter().isAfter(Instant.now().plus(Duration.ofDays(364))), "365 days");
    }
  }

  @Test
  void aServerThatDoesNotUnderstandTheValidityRefusesTheMessageAndNothingChanges(@TempDir Path dir)
      throws Exception {
    // Another vendor's Critical extension: the server rejects the whole message, as one that does
    // not understand keytend-kmip-server's would.
    ReProvisionValidity.vendor = "another_vendor";
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    byte[] oldChain = Files.readAllBytes(pki.chain), oldKey = Files.readAllBytes(pki.key);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand().validFor(Duration.ofDays(30)))
                    .addListener(events)
                    .build())) {
      UnsupportedException e =
          assertThrows(UnsupportedException.class, kms::renewClientCertificate);
      assertTrue(e.getMessage().contains("does not take a requested validity"), e.getMessage());
      assertTrue(e.getMessage().contains("current certificate stays in use"), e.getMessage());
      assertEquals(
          dev.keytend.kmip.model.Enums.ResultReason.UNKNOWN_MESSAGE_EXTENSION,
          e.protocolReason().orElseThrow());
      assertTrue(tls.retiredCertificates().isEmpty(), "nothing retired");
      assertArrayEquals(oldChain, Files.readAllBytes(pki.chain));
      assertArrayEquals(oldKey, Files.readAllBytes(pki.key));
      assertFalse(Files.exists(dir.resolve("client.key.renewal")));
      assertTrue(events.lockedOut.isEmpty());
      assertEquals(1, events.failed.size());
      kms.ping();
    }
    // The same client without the period renews.
    try (TlsListener tls = pki.listener(server).start();
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      assertNotNull(kms.renewClientCertificate());
    }
  }

  @Test
  void aValidityPastTheProvisioningCaIsRefusedAndNothingChanges(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    byte[] oldChain = Files.readAllBytes(pki.chain);
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand().validFor(Duration.ofDays(900)))
                    .addListener(events)
                    .build())) {
      InvalidRequestException e =
          assertThrows(InvalidRequestException.class, kms::renewClientCertificate);
      assertTrue(e.getMessage().contains("after its provisioning CA's notAfter"), e.getMessage());
      assertTrue(e.getMessage().contains("current certificate stays in use"), e.getMessage());
      assertEquals(KmsReason.INVALID_FIELD, e.serverReason().orElseThrow());
      assertTrue(tls.retiredCertificates().isEmpty(), "nothing retired");
      assertArrayEquals(oldChain, Files.readAllBytes(pki.chain));
      assertFalse(Files.exists(dir.resolve("client.key.renewal")));
      assertTrue(events.lockedOut.isEmpty());
      kms.ping();
    }
  }

  @Test
  void anIssuedPeriodOtherThanTheOneAskedForIsUsedNotRefused(@TempDir Path dir) throws Exception {
    // A Non-Critical extension of another vendor: the server ignores it and issues its own period,
    // as a server that ignores the Critical flag would. The old certificate is retired by then, so
    // refusing the new one would lock the client out.
    ReProvisionValidity.vendor = "another_vendor";
    ReProvisionValidity.critical = false;
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).provisioningValidity(Duration.ofDays(90)).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand().validFor(Duration.ofDays(30)))
                    .addListener(events)
                    .build())) {
      RenewedCertificate r = kms.renewClientCertificate();
      assertTrue(r.notAfter().isAfter(Instant.now().plus(Duration.ofDays(89))), "the server's");
      assertEquals(r.certificate(), leaf(pki.chain), "switched");
      assertEquals(List.of(pki.client.certificate()), tls.retiredCertificates());
      assertTrue(events.lockedOut.isEmpty());
      assertEquals(1, events.renewed.size());
      // Reported with both dates: the one issued and the one asked for.
      List<String> period =
          events.warned.stream().filter(w -> w.contains("not the notAfter the request")).toList();
      assertEquals(1, period.size(), events.warned.toString());
      assertTrue(period.get(0).contains(r.notAfter().toString()), period.get(0));
      assertTrue(period.get(0).contains("validFor PT720H"), period.get(0));
      Instant asked = Instant.now().plus(Duration.ofDays(30));
      assertTrue(
          java.util.regex.Pattern.compile(
                  asked.toString().substring(0, 10) + "T\\d\\d:\\d\\d:\\d\\dZ")
              .matcher(period.get(0))
              .find(),
          period.get(0));
      kms.ping();
    }
  }

  @Test
  void anIssuedPeriodAsAskedForIsNotReported(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand().validFor(Duration.ofDays(30)))
                    .addListener(events)
                    .build())) {
      RenewedCertificate r = kms.renewClientCertificate();
      assertTrue(
          Duration.between(Instant.now().plus(Duration.ofDays(30)), r.notAfter()).abs().toMinutes()
              < 1,
          "asked for");
      assertEquals(List.of(), events.warned);
    }
  }

  @Test
  void configurationsThatCannotBeRenewedAreRefused(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start()) {
      KeyStore ks = KeyStore.getInstance("PKCS12");
      ks.load(null, null);
      ks.setKeyEntry(
          "k", pki.client.key(), new char[0], new Certificate[] {pki.client.certificate()});
      IllegalArgumentException inMemory =
          assertThrows(
              IllegalArgumentException.class,
              () ->
                  pki.client(tls)
                      .clientIdentity(ks, new char[0])
                      .clientCertificateRenewal(CertificateRenewal.onDemand())
                      .build());
      assertTrue(inMemory.getMessage().contains("read from files"), inMemory.getMessage());
      assertThrows(
          IllegalArgumentException.class,
          () ->
              tls.configure()
                  .tls(KmsConfig.sslContextFromPem(pki.chain, pki.key, pki.caPem))
                  .clientCertificateRenewal(CertificateRenewal.automatic(RENEW_WITHIN))
                  .build());
      IllegalArgumentException two =
          assertThrows(
              IllegalArgumentException.class,
              () ->
                  pki.renewing(tls, CertificateRenewal.onDemand())
                      .endpoints(tls.endpoint(), tls.endpoint().replace("localhost", "127.0.0.1"))
                      .build());
      assertTrue(two.getMessage().contains("endpointsShareOneStore"), two.getMessage());
      assertNotNull(
          pki.renewing(tls, CertificateRenewal.onDemand().endpointsShareOneStore())
              .endpoints(tls.endpoint(), tls.endpoint())
              .build());
      // No renewal configured.
      try (Kms kms = Kms.connect(pki.client(tls).clientIdentityPem(pki.chain, pki.key).build())) {
        assertThrows(IllegalStateException.class, kms::renewClientCertificate);
      }
    }
    // KMIP 1.4 has no Re-Provision.
    InMemoryKmipServer old = InMemoryKmipServer.of(KmipVersion.V1_4);
    try (TlsListener tls = pki.listener(old).start();
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      assertThrows(UnsupportedException.class, kms::renewClientCertificate);
      assertFalse(Files.exists(dir.resolve("client.key.renewal")));
    }
    // A server without a provisioning CA does not offer it.
    InMemoryKmipServer plain = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls =
            plain
                .tlsListener()
                .identity(pki.server.key(), pki.server.certificate(), pki.ca.certificate())
                .trustAnchors(pki.ca.certificate())
                .start();
        Kms kms = Kms.connect(pki.renewing(tls, CertificateRenewal.onDemand()).build())) {
      assertThrows(UnsupportedException.class, kms::renewClientCertificate);
      assertFalse(
          Files.exists(dir.resolve("client.key.renewal")), "a refused attempt starts clean");
      assertEquals(pki.client.certificate(), leaf(pki.chain));
    }
  }

  @Test
  void automaticRenewalRenewsWithinTheWindowOnItsOwn(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        // The test certificates are valid for 30 days: within a 60-day window at once.
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.automatic(RENEW_WITHIN))
                    .addListener(events)
                    .build())) {
      await("an automatic renewal").until(() -> !events.renewed.isEmpty());
      // The new certificate is valid for a year: outside the window, so no second renewal.
      Thread.sleep(200);
      assertEquals(1, events.renewed.size());
      assertEquals(1, tls.retiredCertificates().size());
      assertEquals(List.of(), events.failed);
      tls.dropConnections();
      kms.ping();
    }
  }

  @Test
  void theNextRenewalIsAlwaysBeforeExpiry() {
    Instant at = Instant.parse("2026-01-01T00:00:00Z");
    assertEquals(
        Duration.ofMinutes(5), ClientRenewal.renewAgainIn(at, at.plus(Duration.ofMinutes(10))));
    // Around a second: half the remaining validity, never a fixed minimum past the expiry.
    assertEquals(Duration.ofSeconds(1), ClientRenewal.renewAgainIn(at, at.plusSeconds(2)));
    assertEquals(Duration.ofMillis(750), ClientRenewal.renewAgainIn(at, at.plusMillis(1500)));
    assertEquals(Duration.ofMillis(500), ClientRenewal.renewAgainIn(at, at.plusSeconds(1)));
    assertEquals(Duration.ofMillis(250), ClientRenewal.renewAgainIn(at, at.plusMillis(500)));
    // Expired, or expiring now: at once.
    assertEquals(Duration.ZERO, ClientRenewal.renewAgainIn(at, at));
    assertEquals(Duration.ZERO, ClientRenewal.renewAgainIn(at, at.minusSeconds(1)));
    // KMIP dates are whole seconds: a second asked for at .999 ends a millisecond later.
    for (int millis : new int[] {0, 1, 500, 999}) {
      Instant now = at.plusMillis(millis);
      Instant notAfter = ReProvisionValidity.notAfter(Duration.ofSeconds(1), now);
      assertEquals(at.plusSeconds(1), notAfter);
      Duration wait = ClientRenewal.renewAgainIn(now, notAfter);
      assertTrue(now.plus(wait).isBefore(notAfter), millis + ": " + wait);
    }
  }

  /**
   * The timer's one thread waits for the next check with a keep-alive as long as the longest wait
   * while an automatic renewal runs, so it does not wake every second; when the last one stops,
   * it is a second again and the idle thread ends.
   */
  @Test
  void theTimerWakesOnlyForChecksWhileAutomaticRenewalRuns(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Duration idle = Duration.ofMillis(SdkThreads.IDLE_MILLIS);
    assertEquals(idle, ClientRenewal.timerKeepAliveNow());
    try (TlsListener tls = pki.listener(server).start()) {
      // A window the certificate is not in: the checks only read, and nothing is renewed.
      KmsConfig config =
          pki.renewing(tls, CertificateRenewal.automatic(Duration.ofDays(1))).build();
      try (Kms first = Kms.connect(config)) {
        assertEquals(Duration.ofHours(1), ClientRenewal.timerKeepAlive());
        assertEquals(ClientRenewal.timerKeepAlive(), ClientRenewal.timerKeepAliveNow());
        try (Kms second = Kms.connect(config)) {
          second.ping();
        }
        // Another still runs.
        assertEquals(ClientRenewal.timerKeepAlive(), ClientRenewal.timerKeepAliveNow());
        first.close();
        assertEquals(idle, ClientRenewal.timerKeepAliveNow());
      }
      // A second close changes nothing.
      assertEquals(idle, ClientRenewal.timerKeepAliveNow());
    }
  }

  @Test
  void aValidityTooShortToRenewIsRefusedBeforeAnythingIsSent() {
    CertificateRenewal automatic = CertificateRenewal.automatic(Duration.ofDays(30));
    for (Duration tooShort :
        List.of(
            Duration.ofSeconds(1),
            Duration.ofMinutes(1),
            CertificateRenewal.MIN_VALIDITY.minusSeconds(1),
            CertificateRenewal.MIN_VALIDITY.minusNanos(1))) {
      IllegalArgumentException e =
          assertThrows(IllegalArgumentException.class, () -> automatic.validFor(tooShort));
      assertTrue(e.getMessage().contains("at least PT10M"), e.getMessage());
      assertTrue(e.getMessage().contains("automatic renewal"), e.getMessage());
      IllegalArgumentException onDemand =
          assertThrows(
              IllegalArgumentException.class,
              () -> CertificateRenewal.onDemand().validFor(tooShort));
      assertFalse(onDemand.getMessage().contains("automatic renewal"), onDemand.getMessage());
    }
    assertEquals(
        java.util.Optional.of(CertificateRenewal.MIN_VALIDITY),
        automatic.validFor(CertificateRenewal.MIN_VALIDITY).validFor());
    assertEquals(
        java.util.Optional.of(Duration.ofMinutes(10)),
        CertificateRenewal.onDemand().validFor(Duration.ofMinutes(10)).validFor());
  }

  @Test
  void aShortLivedCertificateIsRenewedAgainBeforeItExpires(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start();
        // The server issues ten-minute certificates: each one is within the window at once.
        Kms kms =
            Kms.connect(
                pki.renewing(
                        tls,
                        CertificateRenewal.automatic(RENEW_WITHIN).validFor(Duration.ofMinutes(10)))
                    .addListener(events)
                    .build())) {
      await("a renewal and its warning").until(() -> !events.warned.isEmpty());
      assertEquals(1, events.renewed.size());
      assertEquals(List.of(), events.failed, "a warning is not a failure");
      String warned = events.warned.get(0);
      assertTrue(warned.contains("within renewBefore"), warned);
      // The next renewal comes after half the new certificate's validity, before it expires,
      // not after the hour between two checks.
      int start = warned.indexOf(", in ") + 5;
      Duration wait = Duration.parse(warned.substring(start, warned.indexOf(". ", start)));
      assertTrue(wait.compareTo(Duration.ofMinutes(5)) <= 0, warned);
      assertTrue(wait.compareTo(Duration.ofMinutes(4)) > 0, warned);
      assertFalse(warned.contains("leaves little time"), warned);
    }
  }

  @Test
  void aCertificateTheServerIssuedShorterThanAskedIsRenewedBeforeItExpires(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    // The server issues certificates valid for four seconds (three to four, by its whole-second
    // clock): each is within the window at once, and far shorter than renewal is meant for.
    try (TlsListener tls =
            pki.listener(server).provisioningValidity(Duration.ofSeconds(4)).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.automatic(RENEW_WITHIN))
                    .addListener(events)
                    .build())) {
      await("two renewals").until(() -> events.renewed.size() >= 2);
      // The second renewal ran before the first one's certificate expired: it was accepted on a
      // new connection with it, and nothing failed.
      assertEquals(List.of(), events.failed);
      assertEquals(List.of(), events.lockedOut);
      String warned = events.warned.get(0);
      assertTrue(warned.contains("within renewBefore"), warned);
      assertTrue(warned.contains("leaves little time"), warned);
      int start = warned.indexOf(", in ") + 5;
      Duration wait = Duration.parse(warned.substring(start, warned.indexOf(". ", start)));
      assertTrue(wait.compareTo(Duration.ofSeconds(2)) <= 0, warned);
    }
  }

  @Test
  void oneBlockedAutomaticRenewalDoesNotDelayAnother(@TempDir Path dir) throws Exception {
    Path a = dir.resolve("a"), b = dir.resolve("b");
    Files.createDirectory(a);
    Files.createDirectory(b);
    Pki first = new Pki(a), second = new Pki(b);
    // The first identity's attempt stops just before its Re-Provision until released.
    java.util.concurrent.CountDownLatch blocked = new java.util.concurrent.CountDownLatch(1),
        release = new java.util.concurrent.CountDownLatch(1);
    java.util.concurrent.atomic.AtomicBoolean once =
        new java.util.concurrent.atomic.AtomicBoolean();
    ClientRenewal.beforeReProvision =
        () -> {
          if (!once.compareAndSet(false, true)) return;
          blocked.countDown();
          try {
            release.await();
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
          }
        };
    Events firstEvents = new Events(), secondEvents = new Events();
    try (TlsListener one = first.listener(InMemoryKmipServer.of(KmipVersion.V2_1)).start();
        TlsListener two = second.listener(InMemoryKmipServer.of(KmipVersion.V2_1)).start();
        Kms blockedKms =
            Kms.connect(
                first
                    .renewing(one, CertificateRenewal.automatic(RENEW_WITHIN))
                    .addListener(firstEvents)
                    .build())) {
      try {
        assertTrue(blocked.await(10, java.util.concurrent.TimeUnit.SECONDS));
        try (Kms other =
            Kms.connect(
                second
                    .renewing(two, CertificateRenewal.automatic(RENEW_WITHIN))
                    .addListener(secondEvents)
                    .build())) {
          await("the second identity renewed").until(() -> !secondEvents.renewed.isEmpty());
          assertEquals(List.of(), firstEvents.renewed, "the first is still blocked");
        }
      } finally {
        release.countDown();
      }
      await("the first identity renewed").until(() -> !firstEvents.renewed.isEmpty());
    }
  }

  @Test
  void automaticRenewalBacksOffAfterAFailure(@TempDir Path dir) throws Exception {
    ClientRenewal.firstBackoff = Duration.ofMillis(20);
    ClientRenewal.maxBackoff = Duration.ofMillis(40);
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Events events = new Events();
    try (TlsListener tls = pki.listener(server).start()) {
      server.failNext(ServerOperation.RE_PROVISION, Fault.PERMISSION_DENIED);
      try (Kms kms =
          Kms.connect(
              pki.renewing(tls, CertificateRenewal.automatic(RENEW_WITHIN))
                  .addListener(events)
                  .build())) {
        await("a failure, then a renewal").until(() -> !events.renewed.isEmpty());
        assertEquals(1, events.failed.size(), events.failed.toString());
      }
    }
  }

  @Test
  void theRenewalOptionsAreValues() {
    CertificateRenewal a = CertificateRenewal.automatic(Duration.ofDays(30));
    assertEquals(java.util.Optional.of(Duration.ofDays(30)), a.renewBefore());
    assertEquals(java.util.Optional.empty(), a.validFor());
    assertFalse(a.sharesOneStore());
    CertificateRenewal b = a.validFor(Duration.ofDays(90)).endpointsShareOneStore();
    assertEquals(java.util.Optional.of(Duration.ofDays(90)), b.validFor());
    assertTrue(b.sharesOneStore());
    assertEquals(
        b,
        CertificateRenewal.automatic(Duration.ofDays(30))
            .validFor(Duration.ofDays(90))
            .endpointsShareOneStore());
    assertEquals(
        b.hashCode(),
        CertificateRenewal.automatic(Duration.ofDays(30))
            .validFor(Duration.ofDays(90))
            .endpointsShareOneStore()
            .hashCode());
    assertNotEquals(a, b);
    assertEquals(java.util.Optional.empty(), CertificateRenewal.onDemand().renewBefore());
    assertTrue(b.toString().contains("valid for"));
    assertThrows(IllegalArgumentException.class, () -> CertificateRenewal.automatic(Duration.ZERO));
    assertThrows(IllegalArgumentException.class, () -> a.validFor(Duration.ofDays(-1)));
    assertThrows(NullPointerException.class, () -> CertificateRenewal.automatic(null));
  }

  @Test
  void theChecksOfAnIssuedCertificate() throws Exception {
    Issued ca = TestPki.ca("CA");
    KeyPair current = TestPki.ec(), next = TestPki.ec();
    Issued replaced = TestPki.leaf("client", current, ca);
    Issued good =
        new Issued(
            dev.keytend.kmip.TestX509.certificate("client", next.getPublic())
                .issuedBy(ca.certificate(), ca.key())
                .localhost()
                .extendedKeyUsage(ClientRenewal.CLIENT_AUTH)
                .build(),
            next.getPrivate());
    Instant now = Instant.now();
    List<X509Certificate> known = new ArrayList<>(List.of(ca.certificate()));
    assertNull(
        ClientRenewal.verify(
            good.certificate(), replaced.certificate(), next.getPublic(), next.getPrivate(), now));
    assertEquals(List.of(), ClientRenewal.warnings(good.certificate(), known, now));
    assertEquals(
        "it is not for the new key",
        ClientRenewal.verify(
            good.certificate(),
            replaced.certificate(),
            current.getPublic(),
            current.getPrivate(),
            now));
    // No extended key usage: TLS takes it as unrestricted (the test PKI's leaves carry none).
    assertNull(
        ClientRenewal.verify(
            replaced.certificate(),
            replaced.certificate(),
            current.getPublic(),
            current.getPrivate(),
            now));
    // One that allows any extended key usage, or clientAuth among others, is accepted; one that
    // allows only serverAuth is refused.
    for (String[] eku :
        List.of(
            new String[] {"2.5.29.37.0"},
            new String[] {"1.3.6.1.5.5.7.3.1", ClientRenewal.CLIENT_AUTH},
            new String[] {"1.3.6.1.5.5.7.3.1"})) {
      X509Certificate c =
          dev.keytend.kmip.TestX509.certificate("client", next.getPublic())
              .issuedBy(ca.certificate(), ca.key())
              .localhost()
              .extendedKeyUsage(eku)
              .build();
      String problem =
          ClientRenewal.verify(c, replaced.certificate(), next.getPublic(), next.getPrivate(), now);
      if (eku.length == 1 && eku[0].equals("1.3.6.1.5.5.7.3.1"))
        assertTrue(problem.contains("does not allow clientAuth"), problem);
      else assertNull(problem, String.join(",", eku));
    }
    // An issuer of the same name whose key does not verify it: the server's trust decides, so it
    // is a warning, not a refusal.
    Issued impostor = TestPki.ca("CA");
    List<String> warned =
        ClientRenewal.warnings(good.certificate(), List.of(impostor.certificate()), now);
    assertEquals(1, warned.size(), warned.toString());
    assertTrue(warned.get(0).startsWith("its signature does not verify"), warned.get(0));
    // Expired by the clock given.
    assertTrue(
        ClientRenewal.verify(
                good.certificate(),
                replaced.certificate(),
                next.getPublic(),
                next.getPrivate(),
                now.plus(Duration.ofDays(400)))
            .startsWith("it has expired"));
    // Not valid yet by this machine's clock, whatever the margin: the server dates it by its own
    // clock, so it is a warning, never a refusal.
    Instant behind = now.minus(Duration.ofDays(2));
    assertNull(
        ClientRenewal.verify(
            good.certificate(),
            replaced.certificate(),
            next.getPublic(),
            next.getPrivate(),
            behind));
    warned = ClientRenewal.warnings(good.certificate(), known, behind);
    assertEquals(1, warned.size(), warned.toString());
    assertTrue(warned.get(0).contains("clock is likely behind"), warned.get(0));
    // A CA certificate.
    X509Certificate asCa =
        dev.keytend.kmip.TestX509.certificate("client", next.getPublic())
            .issuedBy(ca.certificate(), ca.key())
            .localhost()
            .ca()
            .build();
    assertEquals(
        "it is a CA certificate",
        ClientRenewal.verify(
            asCa, replaced.certificate(), next.getPublic(), next.getPrivate(), now));
    // Another subject.
    Issued other =
        new Issued(
            dev.keytend.kmip.TestX509.certificate("someone-else", next.getPublic())
                .issuedBy(ca.certificate(), ca.key())
                .localhost()
                .extendedKeyUsage(ClientRenewal.CLIENT_AUTH)
                .build(),
            next.getPrivate());
    assertTrue(
        ClientRenewal.verify(
                other.certificate(),
                replaced.certificate(),
                next.getPublic(),
                next.getPrivate(),
                now)
            .startsWith("its subject"));
    // The chain written keeps the previous chain's issuer of the new certificate.
    Issued intermediate = TestPki.intermediate("Sub CA", ca);
    Issued viaSub = TestPki.leaf("client", next, intermediate);
    assertEquals(
        List.of(viaSub.certificate(), intermediate.certificate(), ca.certificate()),
        ClientRenewal.chain(
            viaSub.certificate(),
            List.of(replaced.certificate(), intermediate.certificate(), ca.certificate())));
    assertEquals(
        List.of(good.certificate(), ca.certificate()),
        ClientRenewal.chain(good.certificate(), List.of(replaced.certificate(), ca.certificate())));
    assertEquals(
        List.of(good.certificate()),
        ClientRenewal.chain(good.certificate(), List.of(replaced.certificate())));
  }
}
