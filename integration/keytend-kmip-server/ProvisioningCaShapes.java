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

import dev.keytend.kmip.kms.CertificateRenewal;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.kms.KmsException;
import dev.keytend.kmip.kms.RenewedCertificate;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.TlsListener;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * One provisioning CA shape of {@code run-interop.sh --programs purpose}: one on-demand renewal of
 * the {@code renewal} client's certificate, against the in-memory server's TLS listener set up as
 * keytend-kmip-server is, or against a live keytend-kmip-server the script started with that
 * shape. It prints one line, {@code renewed by <issuer>}, {@code refused <exception>: <message>},
 * or, when the in-memory listener does not start with the shape, as keytend-kmip-server does not,
 * {@code refused at start: <message>}. It exits 0 either way (2 on a usage error).
 *
 * <pre>
 *   in-memory &lt;pki&gt; &lt;shape-directory&gt; &lt;version&gt; &lt;work&gt;
 *   live &lt;host&gt; &lt;port&gt; &lt;pki&gt; &lt;version&gt; &lt;work&gt;
 * </pre>
 *
 * <p>The PKI directory is the script's: {@code ca.pem}, {@code server.pem} and {@code
 * server-key.pem}, and the client {@code renewal.pem} and {@code renewal-key.pem}. The shape
 * directory holds {@code ca.pem} and {@code ca-key.pem}, the provisioning CA, and {@code
 * bundle.pem}, the server's {@code --ca} bundle, whose certificates the in-memory listener takes
 * as its trust anchors. The client files are copied into the work directory, since a renewal
 * rewrites them.
 */
public final class ProvisioningCaShapes {
  private ProvisioningCaShapes() {}

  public static void main(String[] args) throws Exception {
    boolean memory = args.length == 5 && args[0].equals("in-memory");
    if (!memory && !(args.length == 6 && args[0].equals("live"))) {
      System.err.println(
          "Usage: ProvisioningCaShapes in-memory <pki> <shape-directory> <version> <work>\n"
              + "       ProvisioningCaShapes live <host> <port> <pki> <version> <work>");
      System.exit(2);
    }
    Path pki = Path.of(memory ? args[1] : args[3]);
    KmipVersion version = KmipVersion.valueOf("V" + args[memory ? 3 : 4].replace('.', '_'));
    Path work = Path.of(args[memory ? 4 : 5]);
    Files.createDirectories(work);
    Path chain = work.resolve("client.crt"), key = work.resolve("client.key");
    Files.copy(pki.resolve("renewal.pem"), chain);
    Files.copy(pki.resolve("renewal-key.pem"), key);
    if (!memory) {
      KmsConfig.Builder b = KmsConfig.builder().endpoints(args[1] + ":" + args[2]);
      System.out.println(renew(b, pki, version, chain, key));
      return;
    }
    Path shape = Path.of(args[2]);
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    X509Certificate ca = certificates(pki.resolve("ca.pem")).get(0);
    TlsListener.Builder listener =
        server
            .tlsListener()
            .identity(
                privateKey(pki.resolve("server-key.pem")),
                certificates(pki.resolve("server.pem")).get(0),
                ca)
            .trustAnchors(
                certificates(shape.resolve("bundle.pem")).toArray(X509Certificate[]::new))
            .provisioningCa(
                privateKey(shape.resolve("ca-key.pem")),
                certificates(shape.resolve("ca.pem")).get(0));
    TlsListener tls;
    try {
      tls = listener.start();
    } catch (IllegalStateException refused) {
      // As keytend-kmip-server refuses to start with the provisioning CA.
      System.out.println("refused at start: " + refused.getMessage());
      return;
    }
    try (tls) {
      System.out.println(renew(tls.configure(), pki, version, chain, key));
    }
  }

  /** One renewal through {@code b}, with the client files: what came of it, in one line. */
  private static String renew(
      KmsConfig.Builder b, Path pki, KmipVersion version, Path chain, Path key) throws Exception {
    KmsConfig config =
        b.trustPem(pki.resolve("ca.pem"))
            .minimumVersion(version)
            .maximumVersion(version)
            .callTimeout(Duration.ofSeconds(30))
            .clientIdentityPem(chain, key)
            .clientCertificateRenewal(CertificateRenewal.onDemand())
            .build();
    try (Kms kms = Kms.connect(config)) {
      RenewedCertificate r = kms.renewClientCertificate();
      return "renewed by " + r.certificate().getIssuerX500Principal().getName();
    } catch (KmsException e) {
      return "refused " + e.getClass().getSimpleName() + ": " + e.getMessage().replace('\n', ' ');
    }
  }

  private static List<X509Certificate> certificates(Path pem) throws Exception {
    List<X509Certificate> out = new ArrayList<>();
    CertificateFactory f = CertificateFactory.getInstance("X.509");
    for (byte[] der : blocks(pem, "CERTIFICATE"))
      out.add((X509Certificate) f.generateCertificate(new ByteArrayInputStream(der)));
    return out;
  }

  /** A PKCS#8 private key, RSA or EC, as openssl 3 writes it. */
  private static PrivateKey privateKey(Path pem) throws Exception {
    byte[] der = blocks(pem, "PRIVATE KEY").get(0);
    for (String algorithm : List.of("EC", "RSA")) {
      try {
        return KeyFactory.getInstance(algorithm).generatePrivate(new PKCS8EncodedKeySpec(der));
      } catch (GeneralSecurityException other) {
        // the next algorithm
      }
    }
    throw new GeneralSecurityException("Not an EC or RSA PKCS#8 key: " + pem);
  }

  private static List<byte[]> blocks(Path pem, String type) throws Exception {
    List<byte[]> out = new ArrayList<>();
    String begin = "-----BEGIN " + type + "-----", end = "-----END " + type + "-----";
    String text = Files.readString(pem);
    for (int from = text.indexOf(begin); from >= 0; from = text.indexOf(begin, from)) {
      int to = text.indexOf(end, from);
      out.add(Base64.getMimeDecoder().decode(text.substring(from + begin.length(), to)));
      from = to + end.length();
    }
    return out;
  }
}
