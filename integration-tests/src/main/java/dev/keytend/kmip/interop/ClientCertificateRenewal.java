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
import dev.keytend.kmip.client.RequestOptions;
import dev.keytend.kmip.kms.CertificateRenewal;
import dev.keytend.kmip.kms.InvalidRequestException;
import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.kms.KmsListener;
import dev.keytend.kmip.kms.PermissionDeniedException;
import dev.keytend.kmip.kms.RenewalSearchCheck;
import dev.keytend.kmip.kms.RenewedCertificate;
import dev.keytend.kmip.transport.TlsTransport;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;

/**
 * Live renewal of the client certificate ({@code Kms.renewClientCertificate()} and automatic
 * renewal) against keytend-kmip-server run with a provisioning CA, as {@code
 * integration/keytend-kmip-server/run-interop.sh --programs renewal} starts it. Each check prints
 * one line; the program exits 1 when any fails.
 *
 * <p>Arguments: {@code <host> <port> <pki-directory> <version> <work-directory>}. The PKI
 * directory holds {@code ca.pem}, {@code provisioning-ca.pem}, the PEM client {@code renewal.pem}
 * and {@code renewal-key.pem}, and the key store {@code renewal-store.p12} (password {@code
 * changeit}), each client listed in the server's policy. The program copies them into the work
 * directory, since a renewal rewrites them, and the server's store must be new: it retires the
 * certificates it renews.
 *
 * <p>It also runs the search a renewal makes after a lost reply ({@link RenewalSearchCheck}),
 * through a connection opened on the certificate before the renewal retired it: it must find the
 * certificate the server issued, and see every page and find nothing for a key the server never
 * saw.
 */
public final class ClientCertificateRenewal {
  private static int passed, failed;

  private ClientCertificateRenewal() {}

  @FunctionalInterface
  interface Check {
    void run() throws Exception;
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 5) {
      System.err.println(
          "Usage: ClientCertificateRenewal <host> <port> <pki-directory> <version> <work-directory>");
      System.exit(2);
    }
    String endpoint = args[0] + ":" + args[1];
    Path pki = Path.of(args[2]), work = Path.of(args[4]);
    KmipVersion version = KmipVersion.valueOf("V" + args[3].replace('.', '_'));
    Files.createDirectories(work);
    Path chain = work.resolve("client.crt"), key = work.resolve("client.key");
    Files.copy(pki.resolve("renewal.pem"), chain);
    Files.copy(pki.resolve("renewal-key.pem"), key);
    Path oldChain = work.resolve("old-client.crt"), oldKey = work.resolve("old-client.key");
    Files.copy(chain, oldChain);
    Files.copy(key, oldKey);
    Path store = work.resolve("client.p12");
    Files.copy(pki.resolve("renewal-store.p12"), store);
    X509Certificate provisioningCa = certificate(pki.resolve("provisioning-ca.pem"));
    char[] storePassword = "changeit".toCharArray();

    java.util.function.Supplier<KmsConfig.Builder> base =
        () ->
            KmsConfig.builder()
                .endpoints(endpoint)
                .trustPem(pki.resolve("ca.pem"))
                .minimumVersion(version)
                .maximumVersion(version)
                .callTimeout(Duration.ofSeconds(30));

    String[] keyId = new String[1];
    RenewedCertificate[] first = new RenewedCertificate[1];
    KmsConfig renewing =
        base.get()
            .clientIdentityPem(chain, key)
            .clientCertificateRenewal(CertificateRenewal.onDemand())
            .build();
    // A connection on the certificate being renewed, opened before the renewal: the server keeps
    // it after it retires the certificate, as it keeps the connections a renewal searches through.
    KmipClient early =
        new KmipClient(
            TlsTransport.builder(
                    args[0],
                    Integer.parseInt(args[1]),
                    KmsConfig.sslContextFromPem(chain, key, pki.resolve("ca.pem")))
                .pool(1, Duration.ofHours(1))
                .build(),
            version.protocolValue(),
            RequestOptions.DEFAULT);
    early.discoverVersions();
    Instant sent = Instant.now();
    try (Kms kms = Kms.connect(renewing)) {
      check(
          "on demand: the server issues a certificate for a new key, and the files are replaced",
          () -> {
            KeyHandle k =
                kms.keys()
                    .createAes(256)
                    .named("renewal-" + version)
                    .usages(KeyUsage.ENCRYPT)
                    .create();
            keyId[0] = k.id();
            X509Certificate before = certificate(chain);
            RenewedCertificate r = kms.renewClientCertificate();
            first[0] = r;
            X509Certificate now = certificate(chain);
            require(now.equals(r.certificate()), "the chain file holds the new certificate");
            require(!now.equals(before), "a new certificate");
            require(
                now.getSubjectX500Principal().equals(before.getSubjectX500Principal()),
                "the same subject");
            require(
                now.getIssuerX500Principal().equals(provisioningCa.getSubjectX500Principal()),
                "issued by the provisioning CA");
            require(r.previousFingerprint().equals(fingerprint(before)), "the old fingerprint");
            require(r.fingerprint().equals(fingerprint(now)), "the new fingerprint");
            require(!Files.exists(work.resolve("client.key.renewal")), "no pending file left");
            System.out.println(
                "  renewed "
                    + r.previousFingerprint()
                    + " -> "
                    + r.fingerprint()
                    + ", "
                    + r.notAfter());
          });
      check(
          "the search after a lost reply, on a connection opened before the commit, finds the"
              + " certificate the server issued",
          () -> {
            RenewalSearchCheck.Result found =
                RenewalSearchCheck.search(early, first[0].certificate().getPublicKey(), sent);
            require(found.outcome() == RenewalSearchCheck.Outcome.FOUND, "found: " + found);
            require(
                found.certificateId().equals(first[0].certificateId()),
                "the issued certificate " + first[0].certificateId() + ", not " + found);
            System.out.println("  found " + found.certificateId());
          });
      check(
          "the search for a key the server never saw sees every page and finds nothing",
          () -> {
            KeyPairGenerator g =
                KeyPairGenerator.getInstance(first[0].certificate().getPublicKey().getAlgorithm());
            if (g.getAlgorithm().equals("EC"))
              g.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
            else g.initialize(2048);
            RenewalSearchCheck.Result none =
                RenewalSearchCheck.search(early, g.generateKeyPair().getPublic(), sent);
            require(none.outcome() == RenewalSearchCheck.Outcome.EXHAUSTED, "exhausted: " + none);
          });
      check(
          "the same Kms goes on, on new connections with the new certificate",
          () -> {
            kms.ping();
            require(kms.keys().handle(keyId[0]).attributes().id().equals(keyId[0]), "the key");
          });
      check(
          "a second renewal renews the renewed certificate",
          () -> {
            RenewedCertificate r = kms.renewClientCertificate();
            require(r.previousFingerprint().equals(first[0].fingerprint()), "replaces the first");
          });
    }
    check(
        "a new process connects with the renewed files and sees the principal's objects",
        () -> {
          try (Kms kms =
              Kms.connect(
                  base.get()
                      .clientIdentityPem(chain, key)
                      .clientCertificateRenewal(CertificateRenewal.onDemand())
                      .build())) {
            require(kms.keys().handle(keyId[0]).attributes().id().equals(keyId[0]), "the key");
          }
        });
    check(
        "the retired certificate is refused on new connections",
        () -> {
          KmsConfig retired = base.get().clientIdentityPem(oldChain, oldKey).build();
          try (Kms kms = Kms.connect(retired)) {
            kms.ping();
            throw new AssertionError("connected with the retired certificate");
          } catch (PermissionDeniedException expected) {
            // refused
          }
        });
    check(
        "a requested validity: the server issues a certificate that expires at that time",
        () -> {
          // At most 30 days, within the provisioning CA's validity (a week in run-interop.sh).
          Duration left = Duration.between(Instant.now(), provisioningCa.getNotAfter().toInstant());
          Duration period =
              left.dividedBy(2).compareTo(Duration.ofDays(30)) < 0
                  ? left.dividedBy(2).truncatedTo(java.time.temporal.ChronoUnit.MINUTES)
                  : Duration.ofDays(30);
          try (Kms kms =
              Kms.connect(
                  base.get()
                      .clientIdentityPem(chain, key)
                      .clientCertificateRenewal(CertificateRenewal.onDemand().validFor(period))
                      .build())) {
            X509Certificate before = certificate(chain);
            Instant asked = Instant.now().plus(period);
            RenewedCertificate r = kms.renewClientCertificate();
            require(certificate(chain).equals(r.certificate()), "the chain file holds it");
            require(r.previousFingerprint().equals(fingerprint(before)), "it replaces the last");
            require(
                Duration.between(asked, r.notAfter()).abs().compareTo(Duration.ofMinutes(2)) < 0,
                "notAfter " + r.notAfter() + ", asked " + asked);
            kms.ping();
            System.out.println("  valid to " + r.notAfter() + ", asked " + asked);
          }
        });
    check(
        "a validity past the provisioning CA's notAfter is refused, and nothing changes",
        () -> {
          Duration past =
              Duration.between(Instant.now(), provisioningCa.getNotAfter().toInstant()).plusDays(1);
          try (Kms kms =
              Kms.connect(
                  base.get()
                      .clientIdentityPem(chain, key)
                      .clientCertificateRenewal(CertificateRenewal.onDemand().validFor(past))
                      .build())) {
            X509Certificate before = certificate(chain);
            try {
              kms.renewClientCertificate();
              throw new AssertionError("renewed past the provisioning CA");
            } catch (InvalidRequestException expected) {
              require(certificate(chain).equals(before), "nothing changed");
              require(!Files.exists(work.resolve("client.key.renewal")), "no pending file");
              require(
                  expected.getMessage().contains("provisioning CA's notAfter"),
                  expected.getMessage());
              System.out.println("  " + expected.getMessage());
            }
            kms.ping();
          }
        });
    check(
        "automatic: a key store certificate within the window is renewed on the SDK's thread",
        () -> {
          CountDownLatch renewed = new CountDownLatch(1);
          String[] failure = new String[1];
          KmsListener events =
              new KmsListener() {
                @Override
                public void clientCertificateRenewed(
                    String previous, String now, Instant notAfter) {
                  renewed.countDown();
                }

                @Override
                public void clientCertificateRenewalFailed(String fingerprint, String why) {
                  failure[0] = why;
                }
              };
          X509Certificate before = storeCertificate(store, storePassword);
          // A window an hour longer than the certificate has left: due at once. The certificate
          // the server issues lasts until the provisioning CA expires, a day after the setup's
          // client certificates, so it is outside the window.
          Duration window =
              Duration.between(Instant.now(), before.getNotAfter().toInstant()).plusHours(1);
          try (Kms kms =
              Kms.connect(
                  base.get()
                      .clientIdentityKeyStore(store, storePassword)
                      .clientCertificateRenewal(CertificateRenewal.automatic(window))
                      .addListener(events)
                      .build())) {
            require(renewed.await(60, TimeUnit.SECONDS), "renewed within a minute: " + failure[0]);
            X509Certificate now = storeCertificate(store, storePassword);
            require(!now.equals(before), "the key store holds the new certificate");
            kms.ping();
          }
        });
    early.close();
    System.out.println("SUMMARY " + version + " pass=" + passed + " fail=" + failed);
    if (failed > 0) System.exit(1);
  }

  private static void check(String name, Check check) {
    try {
      check.run();
      passed++;
      System.out.println("PASS " + name);
    } catch (Throwable e) {
      failed++;
      System.out.println("FAIL " + name + ": " + e);
      e.printStackTrace(System.out);
    }
  }

  private static void require(boolean condition, String what) {
    if (!condition) throw new AssertionError(what);
  }

  private static X509Certificate certificate(Path pem) throws Exception {
    try (InputStream in = Files.newInputStream(pem)) {
      return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
    }
  }

  private static X509Certificate storeCertificate(Path store, char[] password) throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    try (InputStream in = Files.newInputStream(store)) {
      ks.load(in, password);
    }
    for (String alias : List.copyOf(java.util.Collections.list(ks.aliases())))
      if (ks.isKeyEntry(alias)) return (X509Certificate) ks.getCertificate(alias);
    throw new AssertionError("no key entry in " + store);
  }

  private static String fingerprint(X509Certificate c) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(c.getEncoded()));
  }
}
