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

package dev.keytend.kmip;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
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
 * The tests' X.509 certificates, built with Bouncy Castle's {@code X509v3CertificateBuilder} and
 * signed through the JDK's providers ({@code JcaContentSignerBuilder}; Bouncy Castle is never
 * registered as a provider), returned as the JDK's {@link X509Certificate}. A certificate has
 * exactly the extensions asked for, nothing by default: {@link TestTls}'s identities and {@code
 * kms.TestPki}'s authorities each say which they need. Deliberately malformed certificates are not
 * made here: the tests that need one change the bytes of a well-formed one.
 */
public final class TestX509 {
  private static final AtomicLong SERIAL = new AtomicLong(System.nanoTime() & 0xffffffffL);

  /** RFC 5280 §4.2.1.3 Key Usage bit numbers, for {@link Builder#keyUsage}. */
  public static final int DIGITAL_SIGNATURE = 0,
      NON_REPUDIATION = 1,
      KEY_ENCIPHERMENT = 2,
      DATA_ENCIPHERMENT = 3,
      KEY_AGREEMENT = 4,
      KEY_CERT_SIGN = 5,
      CRL_SIGN = 6,
      ENCIPHER_ONLY = 7,
      DECIPHER_ONLY = 8;

  private TestX509() {}

  /** A certificate for {@code key} with the subject {@code CN=commonName}. */
  public static Builder certificate(String commonName, PublicKey key) {
    return new Builder(commonName, key);
  }

  /** The signature algorithm keytool would choose for a signer's key. */
  static String defaultSignatureAlgorithm(PrivateKey signer) {
    return switch (signer.getAlgorithm()) {
      case "EC" -> "SHA256withECDSA";
      case "RSA" -> "SHA256withRSA";
      case "DSA" -> "SHA256withDSA";
      case "RSASSA-PSS" -> "RSASSA-PSS";
      case "Ed25519", "Ed448", "EdDSA" -> signer.getAlgorithm();
      default -> throw new IllegalArgumentException("No signature for " + signer.getAlgorithm());
    };
  }

  /** One certificate's contents; {@link #build} signs it. */
  public static final class Builder {
    private final X500Name subject;
    private final PublicKey key;
    private X500Name issuer;
    private PublicKey issuerKey;
    private boolean selfSigned;
    private PrivateKey signer;
    private Instant notBefore = Instant.now().minus(Duration.ofDays(1));
    private Instant notAfter = Instant.now().plus(Duration.ofDays(30));
    private BigInteger serial;
    private BasicConstraints basicConstraints;
    private Integer keyUsage;
    private KeyPurposeId[] extendedKeyUsage;
    private final List<GeneralName> subjectAlternativeNames = new ArrayList<>();
    private boolean keyIdentifiers;
    private String signatureAlgorithm;
    private final List<org.bouncycastle.asn1.x509.Extension> others = new ArrayList<>();

    private Builder(String commonName, PublicKey key) {
      this.subject = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, commonName).build();
      this.key = key;
    }

    /** Signed by {@code key}, the key of the certificate itself: issuer and subject are one. */
    public Builder selfSigned(PrivateKey key) {
      this.issuer = subject;
      this.issuerKey = this.key;
      this.signer = key;
      this.selfSigned = true;
      return this;
    }

    /** Issued by {@code issuer} (its subject is this certificate's issuer), signed by its key. */
    public Builder issuedBy(X509Certificate issuer, PrivateKey key) {
      this.issuer = X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded());
      this.issuerKey = issuer.getPublicKey();
      this.signer = key;
      this.selfSigned = false;
      return this;
    }

    /** Valid from {@code from} to {@code to}, at a second's precision (by default a day ago to in 30 days). */
    public Builder validity(Instant from, Instant to) {
      this.notBefore = from;
      this.notAfter = to;
      return this;
    }

    public Builder serial(BigInteger serial) {
      this.serial = serial;
      return this;
    }

    /** A critical Basic Constraints extension: a CA, with no path length constraint. */
    public Builder ca() {
      this.basicConstraints = new BasicConstraints(true);
      return this;
    }

    /** A critical Basic Constraints extension that says the certificate is not a CA. */
    public Builder notCa() {
      this.basicConstraints = new BasicConstraints(false);
      return this;
    }

    /** One more extension, {@code oid}, whose extnValue holds the DER of {@code value}. */
    public Builder extension(String oid, boolean critical, byte[] value) {
      others.add(
          new org.bouncycastle.asn1.x509.Extension(
              new org.bouncycastle.asn1.ASN1ObjectIdentifier(oid), critical, value));
      return this;
    }

    /** A critical Basic Constraints extension: a CA, with a path length constraint. */
    public Builder ca(int pathLength) {
      this.basicConstraints = new BasicConstraints(pathLength);
      return this;
    }

    /**
     * A critical Key Usage extension granting the RFC 5280 {@code bits} ({@link
     * #DIGITAL_SIGNATURE} and the others); none when there are none.
     */
    public Builder keyUsage(int... bits) {
      if (bits.length == 0) {
        this.keyUsage = null;
        return this;
      }
      int mask = 0;
      for (int b : bits) mask |= b < 8 ? 1 << (7 - b) : 1 << (15 - (b - 8));
      this.keyUsage = mask;
      return this;
    }

    /** A non-critical Extended Key Usage extension with the purposes {@code oids}. */
    public Builder extendedKeyUsage(String... oids) {
      KeyPurposeId[] purposes = new KeyPurposeId[oids.length];
      for (int i = 0; i < oids.length; i++)
        purposes[i] =
            KeyPurposeId.getInstance(new org.bouncycastle.asn1.ASN1ObjectIdentifier(oids[i]));
      this.extendedKeyUsage = purposes;
      return this;
    }

    /** A Subject Alternative Name DNS name. */
    public Builder dns(String name) {
      subjectAlternativeNames.add(new GeneralName(GeneralName.dNSName, name));
      return this;
    }

    /** A Subject Alternative Name IP address, a literal. */
    public Builder ip(String address) {
      subjectAlternativeNames.add(new GeneralName(GeneralName.iPAddress, address));
      return this;
    }

    /** {@code dns:localhost} and {@code ip:127.0.0.1}, the tests' servers' names. */
    public Builder localhost() {
      return dns("localhost").ip(InetAddress.getLoopbackAddress().getHostAddress());
    }

    /**
     * Subject Key Identifier, and Authority Key Identifier when the issuer is another
     * certificate (RFC 5280 §4.2.1.2 method 1, as keytool writes them).
     */
    public Builder keyIdentifiers() {
      this.keyIdentifiers = true;
      return this;
    }

    /** A JCA signature algorithm name; by default the one keytool chooses for the signer's key. */
    public Builder signatureAlgorithm(String algorithm) {
      this.signatureAlgorithm = algorithm;
      return this;
    }

    public X509Certificate build() {
      if (signer == null) throw new IllegalStateException("selfSigned or issuedBy first");
      try {
        X509v3CertificateBuilder b =
            new JcaX509v3CertificateBuilder(
                issuer,
                serial != null ? serial : BigInteger.valueOf(SERIAL.incrementAndGet()),
                Date.from(notBefore.truncatedTo(ChronoUnit.SECONDS)),
                Date.from(notAfter.truncatedTo(ChronoUnit.SECONDS)),
                subject,
                key);
        if (basicConstraints != null)
          b.addExtension(Extension.basicConstraints, true, basicConstraints);
        if (!subjectAlternativeNames.isEmpty())
          b.addExtension(
              Extension.subjectAlternativeName,
              false,
              new GeneralNames(subjectAlternativeNames.toArray(GeneralName[]::new)));
        if (keyUsage != null) b.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
        if (extendedKeyUsage != null)
          b.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(extendedKeyUsage));
        for (org.bouncycastle.asn1.x509.Extension e : others) b.addExtension(e);
        if (keyIdentifiers) {
          JcaX509ExtensionUtils ids = new JcaX509ExtensionUtils();
          b.addExtension(
              Extension.subjectKeyIdentifier, false, ids.createSubjectKeyIdentifier(key));
          if (!selfSigned)
            b.addExtension(
                Extension.authorityKeyIdentifier,
                false,
                ids.createAuthorityKeyIdentifier(issuerKey));
        }
        return new JcaX509CertificateConverter().getCertificate(b.build(contentSigner()));
      } catch (Exception e) {
        throw new IllegalStateException("Cannot build the certificate for " + subject, e);
      }
    }

    private ContentSigner contentSigner() throws Exception {
      String algorithm =
          signatureAlgorithm != null ? signatureAlgorithm : defaultSignatureAlgorithm(signer);
      if (!algorithm.equals("RSASSA-PSS"))
        return new JcaContentSignerBuilder(algorithm).build(signer);
      // The JDK names RSASSA-PSS with its parameters apart, which JcaContentSignerBuilder cannot
      // ask for: the JDK's signature, with keytool's parameters for a 2048-bit key (SHA-256, MGF1
      // with SHA-256, a 32-byte salt), and the identifier it encodes them as.
      Signature pss = Signature.getInstance("RSASSA-PSS");
      pss.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
      pss.initSign(signer);
      AlgorithmIdentifier id =
          new AlgorithmIdentifier(
              PKCSObjectIdentifiers.id_RSASSA_PSS,
              ASN1Primitive.fromByteArray(pss.getParameters().getEncoded()));
      return new ContentSigner() {
        private final OutputStream out =
            new OutputStream() {
              @Override
              public void write(int b) throws IOException {
                write(new byte[] {(byte) b}, 0, 1);
              }

              @Override
              public void write(byte[] b, int off, int len) throws IOException {
                try {
                  pss.update(b, off, len);
                } catch (SignatureException e) {
                  throw new IOException(e);
                }
              }
            };

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
          return id;
        }

        @Override
        public OutputStream getOutputStream() {
          return out;
        }

        @Override
        public byte[] getSignature() {
          try {
            return pss.sign();
          } catch (SignatureException e) {
            throw new IllegalStateException(e);
          }
        }
      };
    }
  }
}
