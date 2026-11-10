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

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.TlsListener;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** {@code renew-certificate}: the group's own client certificate, over TLS, with Re-Provision. */
class RenewCertificateCommandTest {
  static KeyPair ec() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec("secp256r1"));
    return g.generateKeyPair();
  }

  static X509Certificate certificate(
      String name, PublicKey key, X509Certificate issuer, PrivateKey signer, boolean ca)
      throws Exception {
    Instant now = Instant.now();
    X500Name subject = new X500Name("CN=" + name);
    JcaX509v3CertificateBuilder b =
        new JcaX509v3CertificateBuilder(
            issuer == null
                ? subject
                : X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()),
            BigInteger.valueOf(now.toEpochMilli())
                .add(BigInteger.valueOf(name.hashCode() & 0xffff)),
            Date.from(now.minus(Duration.ofDays(1))),
            Date.from(now.plus(Duration.ofDays(ca ? 800 : 30))),
            subject,
            key);
    if (ca) {
      b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
      b.addExtension(
          Extension.keyUsage,
          true,
          new org.bouncycastle.asn1.x509.KeyUsage(
              org.bouncycastle.asn1.x509.KeyUsage.keyCertSign
                  | org.bouncycastle.asn1.x509.KeyUsage.cRLSign));
    } else
      b.addExtension(
          Extension.subjectAlternativeName,
          false,
          new GeneralNames(
              new GeneralName[] {
                new GeneralName(GeneralName.dNSName, "localhost"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")
              }));
    X509Certificate c =
        new JcaX509CertificateConverter()
            .getCertificate(b.build(new JcaContentSignerBuilder("SHA256withECDSA").build(signer)));
    return (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new java.io.ByteArrayInputStream(c.getEncoded()));
  }

  static String pem(String label, byte[] der) {
    return "-----BEGIN "
        + label
        + "-----\n"
        + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
        + "\n-----END "
        + label
        + "-----\n";
  }

  @Test
  void renewsTheGroupsCertificateAndReplacesItsFiles(@TempDir Path dir) throws Exception {
    KeyPair caKey = ec(), provisioningKey = ec(), serverKey = ec(), clientKey = ec();
    X509Certificate ca = certificate("CLI CA", caKey.getPublic(), null, caKey.getPrivate(), true);
    X509Certificate provisioning =
        certificate(
            "Provisioning CA",
            provisioningKey.getPublic(),
            null,
            provisioningKey.getPrivate(),
            true);
    X509Certificate server =
        certificate("in-memory-kms", serverKey.getPublic(), ca, caKey.getPrivate(), false);
    X509Certificate client =
        certificate("operator", clientKey.getPublic(), ca, caKey.getPrivate(), false);
    Files.writeString(dir.resolve("ca.pem"), pem("CERTIFICATE", ca.getEncoded()));
    Files.writeString(dir.resolve("client.crt"), pem("CERTIFICATE", client.getEncoded()));
    Files.writeString(
        dir.resolve("client.key"), pem("PRIVATE KEY", clientKey.getPrivate().getEncoded()));
    InMemoryKmipServer kms = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls =
        kms.tlsListener()
            .identity(serverKey.getPrivate(), server, ca)
            .trustAnchors(ca, provisioning)
            .provisioningCa(provisioningKey.getPrivate(), provisioning)
            .start()) {
      Path config = dir.resolve("cli.properties");
      Files.writeString(
          config,
          "group.kms.endpoints = "
              + tls.endpoint()
              + "\ngroup.kms.identity.type = pem\n"
              + "group.kms.identity.certificate = client.crt\n"
              + "group.kms.identity.key = client.key\n"
              + "group.kms.trust.type = pem\n"
              + "group.kms.trust.file = ca.pem\n",
          StandardCharsets.UTF_8);
      ByteArrayOutputStream out = new ByteArrayOutputStream(), err = new ByteArrayOutputStream();
      Cli cli =
          new Cli(
              new PrintStream(out, true, StandardCharsets.UTF_8),
              new PrintStream(err, true, StandardCharsets.UTF_8),
              new Harness.ScriptedTerminal(),
              Map.of(),
              Clock.systemUTC(),
              ZoneOffset.UTC,
              Connector.tls());
      // Without --yes, nothing is done.
      assertEquals(
          ExitCode.NOT_CONFIRMED.code,
          cli.run(new String[] {"--config", config.toString(), "renew-certificate"}));
      assertEquals(0, tls.retiredCertificates().size());
      // A validity too short to use: refused before anything is sent.
      assertEquals(
          ExitCode.USAGE.code,
          cli.run(
              new String[] {
                "--config", config.toString(), "--yes", "renew-certificate", "--valid-for", "5m"
              }));
      assertTrue(
          err.toString(StandardCharsets.UTF_8).contains("at least PT10M"),
          err.toString(StandardCharsets.UTF_8));
      assertEquals(0, tls.retiredCertificates().size());
      assertFalse(Files.exists(dir.resolve("client.key.renewal")));
      err.reset();
      // A validity past the provisioning CA's notAfter: the server refuses it, nothing changes.
      int code =
          cli.run(
              new String[] {
                "--config",
                config.toString(),
                "--yes",
                "renew-certificate",
                "--valid-for",
                "100000d"
              });
      assertNotEquals(ExitCode.OK.code, code);
      assertTrue(
          err.toString(StandardCharsets.UTF_8).contains("after its provisioning CA's notAfter"),
          err.toString(StandardCharsets.UTF_8));
      assertEquals(0, tls.retiredCertificates().size());
      out.reset();
      java.time.Instant asked = java.time.Instant.now().plus(java.time.Duration.ofDays(30));
      assertEquals(
          ExitCode.OK.code,
          cli.run(
              new String[] {
                "--config",
                config.toString(),
                "--yes",
                "--json",
                "renew-certificate",
                "--valid-for",
                "30d"
              }),
          err.toString(StandardCharsets.UTF_8));
      String json = out.toString(StandardCharsets.UTF_8);
      assertTrue(json.contains("\"previousFingerprint\""), json);
      X509Certificate renewed =
          (X509Certificate)
              java.security.cert.CertificateFactory.getInstance("X.509")
                  .generateCertificate(Files.newInputStream(dir.resolve("client.crt")));
      assertTrue(
          java.time.Duration.between(asked, renewed.getNotAfter().toInstant()).abs().toMinutes()
              < 2,
          renewed.getNotAfter().toInstant().toString());
      assertEquals(java.util.List.of(client), tls.retiredCertificates());
      assertFalse(
          Files.readString(dir.resolve("client.crt"))
              .equals(pem("CERTIFICATE", client.getEncoded())));
      assertFalse(Files.exists(dir.resolve("client.key.renewal")));
      // The group connects with the new files.
      assertEquals(
          ExitCode.OK.code,
          cli.run(new String[] {"--config", config.toString(), "info"}),
          err.toString(StandardCharsets.UTF_8));
    }
  }

  @Test
  void aCertificateTheClientRefusesExitsAsAPossibleLockout(@TempDir Path dir) throws Exception {
    KeyPair caKey = ec(), provisioningKey = ec(), serverKey = ec();
    KeyPair clientKey = ec();
    X509Certificate ca = certificate("CLI CA", caKey.getPublic(), null, caKey.getPrivate(), true);
    X509Certificate provisioning =
        certificate(
            "Provisioning CA",
            provisioningKey.getPublic(),
            null,
            provisioningKey.getPrivate(),
            true);
    X509Certificate server =
        certificate("in-memory-kms", serverKey.getPublic(), ca, caKey.getPrivate(), false);
    X509Certificate client =
        certificate("operator", clientKey.getPublic(), ca, caKey.getPrivate(), false);
    Files.writeString(dir.resolve("ca.pem"), pem("CERTIFICATE", ca.getEncoded()));
    Files.writeString(dir.resolve("client.crt"), pem("CERTIFICATE", client.getEncoded()));
    Files.writeString(
        dir.resolve("client.key"), pem("PRIVATE KEY", clientKey.getPrivate().getEncoded()));
    // The server's clock is twelve hours behind and it issues six-hour certificates: by the
    // client's clock the new certificate has already expired, so the SDK refuses it after the
    // server retired the old one.
    InMemoryKmipServer kms =
        InMemoryKmipServer.of(KmipVersion.V2_1)
            .clock(Clock.offset(Clock.systemUTC(), Duration.ofHours(-12)));
    try (TlsListener tls =
        kms.tlsListener()
            .identity(serverKey.getPrivate(), server, ca)
            .trustAnchors(ca, provisioning)
            .provisioningCa(provisioningKey.getPrivate(), provisioning)
            .provisioningValidity(Duration.ofHours(6))
            .start()) {
      Path config = dir.resolve("cli.properties");
      Files.writeString(
          config,
          "group.kms.endpoints = "
              + tls.endpoint()
              + "\ngroup.kms.identity.type = pem\n"
              + "group.kms.identity.certificate = client.crt\n"
              + "group.kms.identity.key = client.key\n"
              + "group.kms.trust.type = pem\n"
              + "group.kms.trust.file = ca.pem\n",
          StandardCharsets.UTF_8);
      ByteArrayOutputStream out = new ByteArrayOutputStream(), err = new ByteArrayOutputStream();
      Cli cli =
          new Cli(
              new PrintStream(out, true, StandardCharsets.UTF_8),
              new PrintStream(err, true, StandardCharsets.UTF_8),
              new Harness.ScriptedTerminal(),
              Map.of(),
              Clock.systemUTC(),
              ZoneOffset.UTC,
              Connector.tls());
      assertEquals(
          ExitCode.OUTCOME_UNKNOWN.code,
          cli.run(new String[] {"--config", config.toString(), "--yes", "renew-certificate"}));
      String said = err.toString(StandardCharsets.UTF_8);
      assertTrue(said.contains("may be locked out"), said);
      assertTrue(said.contains("which this client refuses"), said);
      assertTrue(said.contains("it has expired"), said);
      assertEquals(java.util.List.of(client), tls.retiredCertificates());
      assertTrue(Files.exists(dir.resolve("client.key.renewal")), "the new key is kept");
    }
  }

  @Test
  void aCertificateTheSdkCouldNotWriteExitsAsAPossibleLockoutAndPrintsIt(@TempDir Path dir)
      throws Exception {
    org.junit.jupiter.api.Assumptions.assumeTrue(
        dir.getFileSystem().supportedFileAttributeViews().contains("posix")
            && !"root".equals(System.getProperty("user.name")),
        "a read-only directory needs POSIX permissions, and refuses root nothing");
    for (boolean json : new boolean[] {false, true}) {
      Path sub = dir.resolve(json ? "json" : "text");
      Path files = sub.resolve("identity");
      Files.createDirectories(files);
      KeyPair caKey = ec(), provisioningKey = ec(), serverKey = ec(), clientKey = ec();
      X509Certificate ca = certificate("CLI CA", caKey.getPublic(), null, caKey.getPrivate(), true);
      X509Certificate provisioning =
          certificate(
              "Provisioning CA",
              provisioningKey.getPublic(),
              null,
              provisioningKey.getPrivate(),
              true);
      X509Certificate server =
          certificate("in-memory-kms", serverKey.getPublic(), ca, caKey.getPrivate(), false);
      X509Certificate client =
          certificate("operator", clientKey.getPublic(), ca, caKey.getPrivate(), false);
      Files.writeString(sub.resolve("ca.pem"), pem("CERTIFICATE", ca.getEncoded()));
      Files.writeString(files.resolve("client.crt"), pem("CERTIFICATE", client.getEncoded()));
      Files.writeString(
          files.resolve("client.key"), pem("PRIVATE KEY", clientKey.getPrivate().getEncoded()));
      InMemoryKmipServer kms = InMemoryKmipServer.of(KmipVersion.V2_1);
      java.util.Set<java.nio.file.attribute.PosixFilePermission> writable =
          Files.getPosixFilePermissions(files);
      // The identity directory turns read-only (a full disk, say) once the request arrives: the
      // pending key is written, the certificate the server issues cannot be.
      kms.injectBeforeProcessing(
          request -> {
            boolean reProvision =
                request.children(dev.keytend.kmip.model.Tag.BATCH_ITEM).stream()
                    .anyMatch(
                        i ->
                            i.child(dev.keytend.kmip.model.Tag.OPERATION)
                                    .map(dev.keytend.kmip.model.Ttlv::intValue)
                                    .orElse(0)
                                == dev.keytend.kmip.model.Operation.RE_PROVISION.code());
            if (reProvision) {
              try {
                Files.setPosixFilePermissions(
                    files, java.nio.file.attribute.PosixFilePermissions.fromString("r-x------"));
              } catch (java.io.IOException e) {
                throw new java.io.UncheckedIOException(e);
              }
            }
            return null;
          });
      try (TlsListener tls =
          kms.tlsListener()
              .identity(serverKey.getPrivate(), server, ca)
              .trustAnchors(ca, provisioning)
              .provisioningCa(provisioningKey.getPrivate(), provisioning)
              .start()) {
        Path config = sub.resolve("cli.properties");
        Files.writeString(
            config,
            "group.kms.endpoints = "
                + tls.endpoint()
                + "\ngroup.kms.identity.type = pem\n"
                + "group.kms.identity.certificate = identity/client.crt\n"
                + "group.kms.identity.key = identity/client.key\n"
                + "group.kms.trust.type = pem\n"
                + "group.kms.trust.file = ca.pem\n",
            StandardCharsets.UTF_8);
        ByteArrayOutputStream out = new ByteArrayOutputStream(), err = new ByteArrayOutputStream();
        Cli cli =
            new Cli(
                new PrintStream(out, true, StandardCharsets.UTF_8),
                new PrintStream(err, true, StandardCharsets.UTF_8),
                new Harness.ScriptedTerminal(),
                Map.of(),
                Clock.systemUTC(),
                ZoneOffset.UTC,
                Connector.tls());
        int code;
        try {
          code =
              cli.run(
                  json
                      ? new String[] {
                        "--config", config.toString(), "--yes", "--json", "renew-certificate"
                      }
                      : new String[] {"--config", config.toString(), "--yes", "renew-certificate"});
        } finally {
          Files.setPosixFilePermissions(files, writable);
        }
        assertEquals(ExitCode.OUTCOME_UNKNOWN.code, code, err.toString(StandardCharsets.UTF_8));
        assertEquals(1, tls.retiredCertificates().size());
        String said = err.toString(StandardCharsets.UTF_8);
        String printed = json ? out.toString(StandardCharsets.UTF_8) : said;
        // The certificate the server issued: the only copy once the command exits.
        String begin = json ? "-----BEGIN CERTIFICATE-----\\n" : "-----BEGIN CERTIFICATE-----\n";
        int at = printed.indexOf(begin);
        assertTrue(at >= 0, printed);
        if (json) {
          assertTrue(printed.contains("\"certificatePem\""), printed);
          assertTrue(printed.contains("\"exitCode\": 3"), printed);
        } else {
          String pemText =
              printed.substring(at, printed.indexOf("-----END CERTIFICATE-----", at) + 25) + "\n";
          X509Certificate issued =
              (X509Certificate)
                  CertificateFactory.getInstance("X.509")
                      .generateCertificate(
                          new java.io.ByteArrayInputStream(
                              pemText.getBytes(StandardCharsets.US_ASCII)));
          assertEquals("CN=operator", issued.getSubjectX500Principal().getName());
          assertTrue(said.contains("this process uses it"), said);
        }
        assertEquals(
            pem("CERTIFICATE", client.getEncoded()),
            Files.readString(files.resolve("client.crt")),
            "the files still hold the old certificate");
        assertTrue(Files.exists(files.resolve("client.key.renewal")), "the new key is kept");
      }
    }
  }
}
