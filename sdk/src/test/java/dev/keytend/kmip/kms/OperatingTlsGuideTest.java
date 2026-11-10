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

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.TlsListener;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ScheduledExecutorService;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/** The guide docs/tls-identities.md, with the calls it shows, in its order. */
class OperatingTlsGuideTest {
  static final CustomAttribute TLS_ROLE = CustomAttribute.client("tls-role");
  static final Path SOURCE = Path.of("src/test/java/dev/keytend/kmip/kms/OperatingTlsGuideTest.java");

  /** The guide's logger, SLF4J-style: {@code {}} stands for the argument. */
  interface Log {
    void info(String format, Object argument);
  }

  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void theGuideRunsAsWritten(KmipVersion version, boolean unique, @TempDir Path dir) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    Issued rootIssued = TestPki.ca("Root"), caIssued = TestPki.intermediate("Issuing CA", rootIssued);
    X509Certificate rootCa = rootIssued.certificate(), issuingCa = caIssued.certificate();
    KeyPair k1 = TestPki.ec(), k2 = TestPki.ec(), k3 = TestPki.ec();
    PrivateKey nodeKey = k1.getPrivate(), newKey = k2.getPrivate(), freshKey = k3.getPrivate();
    X509Certificate nodeLeaf = TestPki.leaf("node1", k1, caIssued).certificate();
    X509Certificate renewedLeaf = TestPki.leaf("node1", k1, caIssued).certificate();
    X509Certificate newLeaf = TestPki.leaf("node1", k2, caIssued).certificate();
    X509Certificate freshLeaf = TestPki.leaf("node1", k3, caIssued).certificate();
    ScheduledExecutorService scheduler = TlsIdentityTest.SCHEDULER;
    List<String> logged = new ArrayList<>();
    Log log = (format, argument) -> logged.add(format.replace("{}", String.valueOf(argument)));
    try (Kms kms = TlsIdentityTest.connect(server)) {
      // Issue.
      TlsIdentityHandle node = kms.tls().register(nodeKey, nodeLeaf, issuingCa)
          .named("cassandra/node1").custom(TLS_ROLE, "cluster1:identity").register();
      KeyHandle root = kms.keys().register(rootCa).custom(TLS_ROLE, "cluster1:ca").register();
      // Follow it on the node.
      TlsIdentityFollower identity =
          kms.tls().follow("cassandra/node1", Duration.ofSeconds(60), scheduler);
      TlsTrustFollower trust = kms.tls().trustAnchors(
          KeyQuery.all().custom(TLS_ROLE, "cluster1:ca"),         // the anchors
          KeyQuery.all().custom(TLS_ROLE, "cluster1:identity"),   // who may connect
          Duration.ofSeconds(60), scheduler);
      SSLContext ssl = SSLContext.getInstance("TLS");
      ssl.init(new KeyManager[] {identity.keyManager()},
          new TrustManager[] {trust.trustManager()}, null);
      identity.onChange(state -> log.info("TLS identity {}", state));
      // Peers that have just renewed: the check's rate limits.
      trust.unknownPeerCheckPerCertificate(Duration.ofSeconds(10))   // default 30 seconds
          .unknownPeerCheckGap(Duration.ofMillis(250))               // default 1 second
          .unknownPeerCheckQueue(16);                                // default 64
      // How long TLS material stays usable.
      Optional<Duration> left = identity.usableFor();   // empty: no lease limits it
      long seconds = left.map(Duration::toSeconds).orElse(Long.MAX_VALUE);
      assertEquals(Long.MAX_VALUE, seconds, "this server states no Lease Time");
      assertEquals(List.of(root.id()), List.copyOf(trust.anchors().keySet()));
      assertEquals(nodeLeaf, identity.identity().orElseThrow().certificate());
      // The node's context in a real handshake: the in-memory server served over TLS with it
      // accepts the node itself, an allowed peer, as a client.
      Path chainPem = dir.resolve("node.crt"), keyPem = dir.resolve("node.key"), rootPem = dir.resolve("root.crt");
      Files.writeString(chainPem, KmsApiTest.pem("CERTIFICATE", nodeLeaf.getEncoded())
          + KmsApiTest.pem("CERTIFICATE", issuingCa.getEncoded()));
      Files.writeString(keyPem, KmsApiTest.pem("PRIVATE KEY", nodeKey.getEncoded()));
      Files.writeString(rootPem, KmsApiTest.pem("CERTIFICATE", rootCa.getEncoded()));
      try (TlsListener served = InMemoryKmipServer.of(version).tlsListener().context(ssl).start();
          Kms peer = Kms.connect(served.configure().maximumVersion(KmipVersion.V3_0)
              .clientIdentityPem(chainPem, keyPem).trustPem(rootPem).build())) {
        peer.ping();
        assertEquals(version, peer.version());
        assertEquals(List.of(nodeLeaf), served.clientCertificates());
      }
      // The node's own chain validates against the anchors and is an allowed peer.
      trust.trustManager().checkClientTrusted(identity.keyManager().getCertificateChain(
          identity.keyManager().chooseClientAlias(new String[] {"EC"}, null, null)), "EC");
      // Renew and re-key.
      node = kms.tls().identity("cassandra/node1").orElseThrow().renew(renewedLeaf, issuingCa);
      identity.refresh();
      assertEquals(renewedLeaf, identity.identity().orElseThrow().certificate());
      node = node.rekey(newKey, newLeaf, issuingCa);
      identity.refresh();
      assertEquals(newLeaf, identity.identity().orElseThrow().certificate());
      // Revoke.
      node.revoke(RevocationReason.keyCompromise("node1 disk stolen", Instant.now()));
      identity.refresh();
      assertEquals(TlsIdentityFollower.Status.REVOKED, identity.status());
      assertTrue(identity.identity().isEmpty());
      // Recover.
      node = kms.tls().identity("cassandra/node1").orElseThrow().rekey(freshKey, freshLeaf, issuingCa);
      identity.refresh();
      trust.refresh();
      assertEquals(freshLeaf, identity.identity().orElseThrow().certificate());
      assertEquals(node.certificate().id(), identity.identity().orElseThrow().certificateId());
      assertEquals(1, trust.allowedPeers().orElseThrow().size(), "the revoked certificates are not allowed");
      assertEquals(4, logged.size(), logged.toString());
      identity.close();
      trust.close();
      assertNotNull(ssl);
    }
  }

  /** The guide's "Issue from the KMS", as written, on a server that honors the validity asked. */
  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void theIssueSectionRunsAsWritten(KmipVersion version, boolean unique) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    TlsIssueTest.Ca first = TlsIssueTest.Ca.ec("Issuing CA"), second = TlsIssueTest.Ca.ec("Next CA");
    PrivateKey caKey = first.key.getPrivate();
    X509Certificate caCertificate = first.certificate;
    try (Kms kms = TlsIdentityTest.connect(server)) {
      TlsIssuer nextCa = kms.tls().registerIssuer(second.key.getPrivate(), second.certificate)
          .named("cluster1/next-ca").register();
      // Register the issuer.
      TlsIssuer ca = kms.tls().registerIssuer(caKey, caCertificate)   // then its issuers, if any
          .named("cluster1/issuing-ca").custom(TLS_ROLE, "cluster1:ca").register();
      TlsIssuer same = kms.tls().issuer("cluster1/issuing-ca").orElseThrow();   // elsewhere, later
      assertEquals(ca.toString(), same.toString());
      // Issue.
      TlsIdentityHandle node = kms.tls().issue("cassandra/node1")
          .keyPair(KeyPairSpec.ec(Curve.P_256))      // the default; RSA of 2048 bits or more, or EC
          .subject("CN=node1,O=cluster1")
          .dnsNames("node1.cluster1.internal")
          .ipAddresses("10.0.0.11")                  // also uris(...) and emails(...)
          .issuedBy(ca)
          .custom(TLS_ROLE, "cluster1:identity")
          .issue();
      String key = node.privateKey().id();
      // Reissue.
      node = node.reissue();                                   // same key, new certificate
      assertEquals(key, node.privateKey().id());
      node = node.reissueWithNewKey();                         // new key pair, new certificate
      assertNotEquals(key, node.privateKey().id());
      String due = node.certificate().id();
      node = node.reissueIfExpiresWithin(Duration.ofDays(10)); // the scheduled job
      assertEquals(due, node.certificate().id(), "a certificate valid for a year is not due");
      node = node.reissue(TlsReissue.newKey(KeyPairSpec.ec(Curve.P_384))
          .validFor(Duration.ofDays(30)).issuedBy(nextCa));
      X509Certificate leaf = TlsIdentities.certificate(kms, node.certificate().id());
      assertEquals(second.certificate.getSubjectX500Principal(), leaf.getIssuerX500Principal());
      assertEquals(
          384,
          ((java.security.interfaces.ECPublicKey) leaf.getPublicKey())
              .getParams().getCurve().getField().getFieldSize());
      assertTrue(leaf.getNotAfter().toInstant().isBefore(Instant.now().plus(Duration.ofDays(31))));
      assertEquals(node.toString(), kms.tls().identity("cassandra/node1").orElseThrow().toString());
      assertEquals(List.of(), server.violations());
    }
  }

  /** Every line of the guide's code blocks is in this test, so the guide shows what runs here. */
  @Test
  void theGuideShowsTheCodeOfThisTest() throws Exception {
    String guide = Files.readString(Path.of("../docs/tls-identities.md"));
    int start = guide.indexOf("\n# TLS identities\n");
    assertTrue(start > 0);
    String section = guide.substring(start);
    List<String> source = Files.readAllLines(SOURCE).stream().map(String::strip).toList();
    Matcher block = Pattern.compile("```java\\n(.*?)```", Pattern.DOTALL).matcher(section);
    int blocks = 0;
    while (block.find()) {
      blocks++;
      for (String line : block.group(1).split("\n"))
        if (!line.isBlank()) assertTrue(source.contains(line.strip()), "not in the test: " + line);
    }
    assertEquals(10, blocks);
  }

  /**
   * The numbers the TLS guide gives for the unknown-peer check's defaults are the follower's: the
   * per-certificate interval, the gap between checks and the queue, in the prose and in the
   * example's comments. Only the numbers are read, not the wording around them.
   */
  @Test
  void theGuidesCheckDefaultsAreTheFollowers() throws Exception {
    String guide = Files.readString(Path.of("../docs/tls-identities.md")).replaceAll("\\s+", " ");
    long perCertificate = TlsTrustFollower.PER_CERTIFICATE.toSeconds();
    long gap = TlsTrustFollower.GAP.toSeconds();
    assertEquals(perCertificate, number(guide, "at most once per (\\d+) seconds"));
    assertEquals(gap, number(guide, "within (\\d+) second"));
    assertEquals(TlsTrustFollower.QUEUED, number(guide, "at most (\\d+) checks wait"));
    assertEquals(perCertificate, number(guide, "// default (\\d+) seconds"));
    assertEquals(gap, number(guide, "// default (\\d+) second\\b"));
    assertEquals(TlsTrustFollower.QUEUED, number(guide, "// default (\\d+)\\b(?! seconds?\\b)"));
  }

  private static long number(String text, String regex) {
    Matcher m = Pattern.compile(regex).matcher(text);
    assertTrue(m.find(), "the guide has no match for " + regex);
    return Long.parseLong(m.group(1));
  }
}
