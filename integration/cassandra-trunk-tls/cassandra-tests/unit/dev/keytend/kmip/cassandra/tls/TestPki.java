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

import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Test only: certificates as a real PKI issues them (Bouncy Castle, from Cassandra's test
 * libraries). A CA has Basic Constraints CA and Key Usage keyCertSign and cRLSign only, as real CAs
 * have; a leaf has a SPIFFE URI, {@code localhost} and {@code 127.0.0.1}, digitalSignature, and
 * serverAuth and clientAuth, so one certificate serves both sides of internode TLS.
 */
public final class TestPki {
  /** A key pair and its certificate, issued by {@code issuer} (itself for a CA). */
  public record Issued(KeyPair keyPair, X509Certificate certificate, X509Certificate issuer) {
    /** The chain a node registers and presents: the leaf, then its CA. */
    public X509Certificate[] chain() {
      return issuer == certificate ? new X509Certificate[] {certificate} : new X509Certificate[] {certificate, issuer};
    }

    public PrivateKey privateKey() {
      return keyPair.getPrivate();
    }

    public BigInteger serial() {
      return certificate.getSerialNumber();
    }
  }

  private TestPki() {}

  /** A self-signed RSA CA. */
  public static Issued ca(String cn) throws Exception {
    KeyPair keys = rsa();
    X500Name name = new X500Name("CN=" + cn);
    X509v3CertificateBuilder b = builder(name, BigInteger.valueOf(System.nanoTime()), name, keys);
    JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
    b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
    b.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(keys.getPublic()));
    X509Certificate c = sign(b, keys.getPrivate());
    return new Issued(keys, c, c);
  }

  /** A new EC P-256 key and its leaf certificate for {@code spiffe://<trust domain>/<name>}. */
  public static Issued issue(Issued ca, String name, long serial) throws Exception {
    return issue(ca, name, serial, ec());
  }

  /** A renewal when {@code keys} is the old certificate's pair: a new certificate for the same key. */
  public static Issued issue(Issued ca, String name, long serial, KeyPair keys) throws Exception {
    X509v3CertificateBuilder b =
        builder(X500Name.getInstance(ca.certificate().getSubjectX500Principal().getEncoded()), BigInteger.valueOf(serial),
                new X500Name("CN=" + name), keys);
    JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
    b.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
    b.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
    b.addExtension(Extension.extendedKeyUsage, false,
                   new ExtendedKeyUsage(new KeyPurposeId[] {KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth}));
    b.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(new GeneralName[] {
        new GeneralName(GeneralName.uniformResourceIdentifier, "spiffe://cluster1/" + name),
        new GeneralName(GeneralName.dNSName, "localhost"),
        new GeneralName(GeneralName.iPAddress, "127.0.0.1")}));
    b.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(ca.certificate()));
    return new Issued(keys, sign(b, ca.privateKey()), ca.certificate());
  }

  private static X509v3CertificateBuilder builder(X500Name issuer, BigInteger serial, X500Name subject, KeyPair keys) {
    Instant now = Instant.now();
    return new JcaX509v3CertificateBuilder(issuer, serial, Date.from(now.minus(Duration.ofHours(1))),
                                           Date.from(now.plus(Duration.ofDays(2))), subject, keys.getPublic());
  }

  private static X509Certificate sign(X509v3CertificateBuilder b, PrivateKey issuerKey) throws Exception {
    String algorithm = issuerKey.getAlgorithm().equals("RSA") ? "SHA256withRSA" : "SHA256withECDSA";
    ContentSigner signer = new JcaContentSignerBuilder(algorithm).build(issuerKey);
    return new JcaX509CertificateConverter().getCertificate(b.build(signer));
  }

  private static KeyPair rsa() throws GeneralSecurityException {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(2048);
    return g.generateKeyPair();
  }

  private static KeyPair ec() throws GeneralSecurityException {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec("secp256r1"));
    return g.generateKeyPair();
  }

  /** PEM of certificates, in order. */
  public static String pem(X509Certificate... certificates) throws GeneralSecurityException {
    StringBuilder out = new StringBuilder();
    for (X509Certificate c : certificates)
      out.append("-----BEGIN CERTIFICATE-----\n").append(base64(c.getEncoded())).append("-----END CERTIFICATE-----\n");
    return out.toString();
  }

  /** PEM of a private key, PKCS#8 unencrypted. */
  public static String pem(PrivateKey key) {
    return "-----BEGIN PRIVATE KEY-----\n" + base64(key.getEncoded()) + "-----END PRIVATE KEY-----\n";
  }

  private static String base64(byte[] der) {
    return Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der) + "\n";
  }

  public static Path write(Path file, String pem) throws IOException {
    return Files.writeString(file, pem);
  }

  /** A key store holding {@code who}'s key and chain, for a JSSE key manager. */
  public static KeyStore keyStore(Issued who, char[] password) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(null, null);
    store.setKeyEntry("key", who.privateKey(), password, who.chain());
    return store;
  }

  /** A trust store holding {@code anchors}. */
  public static KeyStore trustStore(X509Certificate... anchors) throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(null, null);
    for (int i = 0; i < anchors.length; i++) store.setCertificateEntry("anchor-" + i, anchors[i]);
    return store;
  }

  /** A client's context: it presents {@code client} and trusts {@code anchors}. */
  public static SSLContext context(Issued client, X509Certificate... anchors) throws Exception {
    char[] password = "changeit".toCharArray();
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(keyStore(client, password), password);
    TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(trustStore(anchors));
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    return context;
  }
}
