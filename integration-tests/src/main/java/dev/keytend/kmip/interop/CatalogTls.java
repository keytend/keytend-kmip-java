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
import dev.keytend.kmip.model.Keys;
import dev.keytend.kmip.transport.Tls;
import dev.keytend.kmip.transport.TlsTransport;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.time.Duration;
import java.util.*;
import javax.net.ssl.*;

/** Certificate changes on the actual server listener, with fresh client trust contexts. */
public final class CatalogTls {
  private CatalogTls() {}

  public static void execute(String id, CatalogFixture f) throws Exception {
    if (f.serverIdentity == null) Catalog.blocked("Native server identity reload hook absent");
    f.provision();
    try {
      switch (id) {
        case "TLS-07" -> {
          f.serverIdentity.use("chain-server");
          get(f, context(f, "ca.pem"));
          f.serverIdentity.use("missing-chain");
          reject(f, context(f, "ca.pem"), false);
          get(f, context(f, "intermediate.pem"));
          f.evidence.put(
              "chain_assertions",
              List.of(
                  "complete chain accepted by root",
                  "missing intermediate rejected by root",
                  "explicit intermediate anchor accepted"));
        }
        case "TLS-11" -> {
          f.serverIdentity.use("replacement-server");
          get(f, revocationContext(f));
          f.serverIdentity.use("revoked-server");
          reject(f, revocationContext(f), true);
          f.evidence.put(
              "revocation",
              "Client PKIX CRL validation: unrevoked leaf accepted, revoked leaf rejected with"
                  + " REVOKED cause on the native endpoint");
        }
        case "TLS-13" -> {
          get(f, context(f, "ca.pem"));
          f.serverIdentity.use("rollover-server");
          get(f, context(f, "overlap-ca.pem"));
          reject(f, context(f, "ca.pem"), false);
          get(f, context(f, "other-ca.pem"));
          f.serverIdentity.use("server");
          reject(f, context(f, "other-ca.pem"), false);
          f.evidence.put(
              "rollover",
              "Old CA accepted before rotation; overlap accepted new CA; old-only rejected new"
                  + " chain; new-only accepted new chain and rejected retired old chain");
        }
        default -> throw new IllegalArgumentException(id);
      }
      f.evidence.put(
          "connection_policy",
          "Fresh TLS context and socket for every positive and negative assertion; exact UID and"
              + " SHA-256 checked on every successful Get");
    } finally {
      f.serverIdentity.use("server");
    }
  }

  static SSLContext context(CatalogFixture f, String trust) throws Exception {
    return Tls.context(
        f.certs.resolve("client.p12"), "changeit".toCharArray(), f.certs.resolve(trust));
  }

  static void get(CatalogFixture f, SSLContext context) throws Exception {
    try (var c =
        new KmipClient(
            new TlsTransport(
                f.host,
                f.port,
                context,
                Duration.ofSeconds(2),
                Duration.ofSeconds(3),
                new dev.keytend.kmip.codec.TtlvCodec()),
            f.version)) {
      byte[] key = Keys.aesKey(c.get(f.knownUid).requirePayload(), f.knownUid, 256).getEncoded();
      if (!Catalog.digest(key).equals(f.knownSha))
        throw new Catalog.Classification(
            Catalog.Outcome.FAIL_SERVER, "Certificate rotation changed exact-ID key material");
    }
  }

  static void reject(CatalogFixture f, SSLContext context, boolean revoked) throws Exception {
    try {
      get(f, context);
    } catch (IOException e) {
      boolean handshake = false, certificate = false, revocation = false;
      for (Throwable cause = e; cause != null; cause = cause.getCause()) {
        handshake |= cause instanceof SSLHandshakeException;
        certificate |= cause instanceof CertificateException;
        revocation |=
            cause instanceof CertPathValidatorException validator
                && validator.getReason() == CertPathValidatorException.BasicReason.REVOKED;
      }
      if (handshake && certificate && (!revoked || revocation)) return;
      throw e; // A timeout or broken listener is not a certificate-policy rejection.
    }
    throw new Catalog.Classification(
        Catalog.Outcome.FAIL_SERVER,
        "Connection accepted a certificate excluded by the configured trust policy");
  }

  /** Administrative readiness only; broad trust is never used by credited client assertions. */
  static void awaitIdentity(CatalogFixture f, String identity) throws Exception {
    String leaf = identity.equals("missing-chain") ? "chain-server" : identity;
    X509Certificate expected;
    try (InputStream in = Files.newInputStream(f.certs.resolve(leaf + ".pem"))) {
      expected = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
    }
    SSLContext admin = context(f, "admin-ca.pem");
    long deadline = System.nanoTime() + Duration.ofSeconds(20).toNanos();
    IOException last = null;
    while (System.nanoTime() < deadline) {
      try (SSLSocket socket = (SSLSocket) admin.getSocketFactory().createSocket()) {
        socket.connect(new InetSocketAddress(f.host, f.port), 1000);
        socket.setSoTimeout(1500);
        socket.startHandshake();
        var actual = (X509Certificate) socket.getSession().getPeerCertificates()[0];
        if (Arrays.equals(actual.getEncoded(), expected.getEncoded())) return;
      } catch (IOException e) {
        last = e;
      }
      Thread.sleep(100);
    }
    throw new IOException("Native listener did not present the selected fixture identity", last);
  }

  /** An end-user application can supply JKS-backed JSSE without an SDK-specific store format. */
  static SSLContext jksContext(CatalogFixture f) throws Exception {
    KeyStore source = KeyStore.getInstance("PKCS12"),
        identity = KeyStore.getInstance("JKS"),
        anchors = KeyStore.getInstance("JKS");
    char[] password = "changeit".toCharArray();
    try (InputStream in = Files.newInputStream(f.certs.resolve("client.p12"))) {
      source.load(in, password);
    }
    identity.load(null, password);
    String alias = Collections.list(source.aliases()).get(0);
    identity.setKeyEntry(
        "client", source.getKey(alias, password), password, source.getCertificateChain(alias));
    anchors.load(null, null);
    try (InputStream in = Files.newInputStream(f.certs.resolve("ca.pem"))) {
      int n = 0;
      for (var certificate : CertificateFactory.getInstance("X.509").generateCertificates(in))
        anchors.setCertificateEntry("ca-" + n++, certificate);
    }
    KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keys.init(identity, password);
    TrustManagerFactory trust =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    trust.init(anchors);
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
    return context;
  }

  static SSLContext revocationContext(CatalogFixture f) throws Exception {
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    X509Certificate ca;
    CRL crl;
    try (InputStream in = Files.newInputStream(f.certs.resolve("ca.pem"))) {
      ca = (X509Certificate) cf.generateCertificate(in);
    }
    try (InputStream in = Files.newInputStream(f.certs.resolve("revoked.crl"))) {
      crl = cf.generateCRL(in);
    }
    var parameters =
        new PKIXBuilderParameters(Set.of(new TrustAnchor(ca, null)), new X509CertSelector());
    parameters.addCertStore(
        CertStore.getInstance("Collection", new CollectionCertStoreParameters(List.of(crl))));
    var checker =
        (PKIXRevocationChecker) CertPathValidator.getInstance("PKIX").getRevocationChecker();
    checker.setOptions(
        EnumSet.of(
            PKIXRevocationChecker.Option.PREFER_CRLS,
            PKIXRevocationChecker.Option.NO_FALLBACK,
            PKIXRevocationChecker.Option.ONLY_END_ENTITY));
    parameters.addCertPathChecker(checker);
    TrustManagerFactory trust = TrustManagerFactory.getInstance("PKIX");
    trust.init(new CertPathTrustManagerParameters(parameters));
    KeyStore identity = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(f.certs.resolve("client.p12"))) {
      identity.load(in, "changeit".toCharArray());
    }
    KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    keys.init(identity, "changeit".toCharArray());
    SSLContext checked = SSLContext.getInstance("TLS");
    checked.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
    return checked;
  }
}
