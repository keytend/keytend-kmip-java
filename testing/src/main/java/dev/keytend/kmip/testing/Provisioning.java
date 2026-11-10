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

package dev.keytend.kmip.testing;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.net.ssl.X509TrustManager;

/**
 * The provisioning CA of a {@link TlsListener} ({@link TlsListener.Builder#provisioningCa}): it
 * reads the PKCS#10 request of a Re-Provision and issues the replacement client certificate, as
 * keytend-kmip-server does. The request must be self-signed with RSA PKCS#1 v1.5 or ECDSA and
 * SHA-224 to SHA-512, for an RSA key of at least 2048 bits or an EC key on P-256, P-384 or P-521;
 * its subject and extensions are ignored. The certificate has the replaced certificate's subject
 * and subjectAltName, CA false, Key Usage digitalSignature (plus keyEncipherment for RSA), Extended
 * Key Usage clientAuth, a notBefore five minutes back and the listener's validity, cut short when
 * the CA expires earlier, or the notAfter the Re-Provision item asked for, all by the server's
 * clock ({@link InMemoryKmipServer#clock}), which the check of the new certificate uses too. DER is
 * read and written here, strictly, with nothing but the JDK.
 */
final class Provisioning {
  /** keytend-kmip-server's validity of issued certificates. */
  static final Duration DEFAULT_VALIDITY = Duration.ofDays(365);

  private static final Duration BACKDATE = Duration.ofMinutes(5);

  private static final Map<String, String> SIGNATURES =
      Map.of(
          "1.2.840.113549.1.1.14", "SHA224withRSA",
          "1.2.840.113549.1.1.11", "SHA256withRSA",
          "1.2.840.113549.1.1.12", "SHA384withRSA",
          "1.2.840.113549.1.1.13", "SHA512withRSA",
          "1.2.840.10045.4.3.1", "SHA224withECDSA",
          "1.2.840.10045.4.3.2", "SHA256withECDSA",
          "1.2.840.10045.4.3.3", "SHA384withECDSA",
          "1.2.840.10045.4.3.4", "SHA512withECDSA");

  private static final String RSA_KEY = "1.2.840.113549.1.1.1", EC_KEY = "1.2.840.10045.2.1";

  final PrivateKey caKey;
  final X509Certificate ca;
  final Duration validity;

  /** The listener's check of client certificates; null for a listener made from a context. */
  final X509TrustManager verifier;

  private final SecureRandom random = new SecureRandom();

  Provisioning(PrivateKey caKey, X509Certificate ca, Duration validity, X509TrustManager verifier) {
    this.caKey = caKey;
    this.ca = ca;
    this.validity = validity;
    this.verifier = verifier;
  }

  /** keytend-kmip-server's message for a request key of an unsupported or another kind. */
  static final String UNSUPPORTED_KEY =
      "The new key must be of the current certificate's algorithm (and curve): RSA-2048 or more,"
          + " or EC P-256, P-384 or P-521";

  /** Why a request or an issued certificate was refused; its message is the result message. */
  static final class Refused extends Exception {
    private static final long serialVersionUID = 1L;

    Refused(String message) {
      super(message, null, false, false);
    }
  }

  /**
   * The public key of a PKCS#10 request, after checking its structure and its self-signature.
   *
   * <p>An EC key on a named curve other than P-256, P-384 or P-521 is refused as an invalid request
   * before its signature is checked, and one with explicit curve parameters, like an RSA key under
   * 2048 bits, after it, as keytend-kmip-server does.
   *
   * @throws Refused when the request is malformed, weakly signed or for an unsupported key
   */
  static PublicKey requestKey(byte[] der) throws Refused {
    try {
      Reader request = new Reader(der);
      Reader whole = request.enter(0x30);
      if (!request.done()) throw new Refused("Invalid Certificate Request: bytes after it");
      int infoFrom = whole.at;
      Reader info = whole.enter(0x30);
      byte[] infoDer = Arrays.copyOfRange(der, infoFrom, whole.at);
      byte[] version = info.value(0x02);
      if (version.length != 1 || version[0] != 0)
        throw new Refused("Invalid Certificate Request: version");
      info.value(0x30); // subject: ignored
      int keyFrom = info.at;
      Reader spki = info.enter(0x30);
      byte[] spkiDer = Arrays.copyOfRange(der, keyFrom, info.at);
      String keyAlgorithm = oid(spki.enter(0x30).value(0x06));
      String curve = CertificateIssuance.namedCurve(spkiDer);
      if (curve != null && !curve.isEmpty() && !CertificateIssuance.NIST_CURVES.contains(curve))
        throw new Refused("Invalid Certificate Request");
      info.value(0xa0); // attributes: ignored
      if (!info.done()) throw new Refused("Invalid Certificate Request: info");
      Reader algorithm = whole.enter(0x30);
      String signatureAlgorithm = SIGNATURES.get(oid(algorithm.value(0x06)));
      byte[] signature = whole.value(0x03);
      if (!whole.done()) throw new Refused("Invalid Certificate Request: trailing fields");
      if (signatureAlgorithm == null)
        throw new Refused(
            "The Certificate Request must be signed with SHA-224 or stronger (RSA PKCS#1 v1.5 or"
                + " ECDSA)");
      if (signature.length < 2 || signature[0] != 0)
        throw new Refused("Invalid Certificate Request: signature");
      String family =
          switch (keyAlgorithm) {
            case RSA_KEY -> "RSA";
            case EC_KEY -> "EC";
            default -> throw new Refused("The new key must be RSA or EC");
          };
      if (!signatureAlgorithm.endsWith(family.equals("RSA") ? "RSA" : "ECDSA"))
        throw new Refused("Invalid Certificate Request: signature algorithm");
      PublicKey key =
          KeyFactory.getInstance(family).generatePublic(new X509EncodedKeySpec(spkiDer));
      Signature verify = Signature.getInstance(signatureAlgorithm);
      verify.initVerify(key);
      verify.update(infoDer);
      if (!verify.verify(Arrays.copyOfRange(signature, 1, signature.length)))
        throw new Refused("Invalid Certificate Request: its signature does not verify");
      if (!CertificateIssuance.supportedKey(key, spkiDer)) throw new Refused(UNSUPPORTED_KEY);
      return key;
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      throw new Refused("Invalid Certificate Request");
    }
  }

  /** Whether two keys are of one kind: RSA, or EC on one curve. */
  static boolean sameKind(PublicKey a, PublicKey b) {
    if (a instanceof RSAPublicKey && b instanceof RSAPublicKey) return true;
    if (a instanceof ECPublicKey e && b instanceof ECPublicKey f)
      return e.getParams().getCurve().equals(f.getParams().getCurve())
          && e.getParams().getGenerator().equals(f.getParams().getGenerator());
    return false;
  }

  /**
   * Issues the replacement of {@code replaced} for {@code key} at {@code now}, and checks it as the
   * listener would. Its notAfter is {@code requested}, which the caller checked is after {@code
   * now} and not after the CA's notAfter; without one, the listener's validity, cut short at the
   * CA's notAfter.
   *
   * @throws Refused when the listener's check refuses it (a Cryptographic Failure)
   */
  X509Certificate issue(X509Certificate replaced, PublicKey key, Instant now, Instant requested)
      throws Refused, GeneralSecurityException {
    X509Certificate issued =
        sign(
            replaced.getSubjectX500Principal().getEncoded(),
            subjectAltName(replaced),
            key,
            now,
            requested);
    if (verifier != null && !trusted(issued, now))
      throw new Refused("The certificate would not be accepted by the listener");
    return issued;
  }

  /**
   * Why keytend-kmip-server would not start with this provisioning CA and the listener's
   * trust, by its message, or null when it would. Before it serves, the server checks that the CA
   * is one (basicConstraints CA true) that may sign certificates (a Key Usage that allows
   * keyCertSign), that the CA's certificate is strong ({@link #weakness}), that the CA is itself in
   * the listener's trust bundle, byte for byte (its {@code --ca} bundle; here the verifier's
   * accepted issuers), then puts a client certificate the CA issues through its listener's
   * verification ({@link #trusted}) at {@code now}. A verifier that names no issuers has no bundle
   * to look in, so only the sample certificate is checked.
   */
  String startupRefusal(Instant now) throws GeneralSecurityException {
    boolean[] ku = ca.getKeyUsage();
    if (ca.getBasicConstraints() < 0) return "the provisioning CA: Issuer certificate is not a CA";
    if (ku != null && !bit(ku, 5))
      return "the provisioning CA: Issuer key usage does not permit certificate signing";
    if (ku == null) return "the provisioning CA certificate lacks the keyCertSign key usage";
    String weak = weakness(ca);
    if (weak != null) return "the provisioning CA certificate " + weak;
    if (verifier == null) return null;
    X509Certificate[] bundle = verifier.getAcceptedIssuers();
    if (bundle != null && bundle.length > 0 && !inBundle(bundle))
      return "the provisioning CA must also be in the --ca bundle, so that the certificates it"
          + " issues are accepted";
    java.security.KeyPairGenerator g = java.security.KeyPairGenerator.getInstance("EC");
    g.initialize(new java.security.spec.ECGenParameterSpec("secp256r1"));
    X509Certificate sample =
        sign(
            new javax.security.auth.x500.X500Principal("CN=provisioning check").getEncoded(),
            new byte[0],
            g.generateKeyPair().getPublic(),
            now,
            null);
    return trusted(sample, now)
        ? null
        : "a client certificate from the provisioning CA fails the listener's verification";
  }

  /** Whether one of {@code bundle} is the provisioning CA's certificate, DER for DER. */
  private boolean inBundle(X509Certificate[] bundle) throws GeneralSecurityException {
    byte[] der = ca.getEncoded();
    for (X509Certificate c : bundle)
      if (c != null && Arrays.equals(der, c.getEncoded())) return true;
    return false;
  }

  /**
   * A client certificate from the CA for {@code key}, with {@code subject} and {@code
   * subjectAltName} (DER; empty for none), from five minutes before {@code now} until {@code
   * requested}, or the listener's validity, cut short at the CA's notAfter.
   */
  private X509Certificate sign(
      byte[] subject, byte[] subjectAltName, PublicKey key, Instant now, Instant requested)
      throws GeneralSecurityException {
    Instant notBefore = now.minus(BACKDATE);
    Instant caFrom = ca.getNotBefore().toInstant(), caTo = ca.getNotAfter().toInstant();
    if (notBefore.isBefore(caFrom)) notBefore = caFrom;
    Instant notAfter = requested != null ? requested : now.plus(validity);
    if (notAfter.isAfter(caTo)) notAfter = caTo;
    boolean rsa = key instanceof RSAPublicKey;
    String signing = caKey.getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";
    byte[] algorithm =
        signing.endsWith("ECDSA")
            ? Writer.sequence(Writer.oid("1.2.840.10045.4.3.2"))
            : Writer.sequence(Writer.oid("1.2.840.113549.1.1.11"), Writer.nul());
    byte[] serial = new byte[16];
    random.nextBytes(serial);
    byte[] extensions =
        Writer.sequence(
            extension("2.5.29.19", true, Writer.sequence()),
            extension(
                "2.5.29.15",
                true,
                rsa
                    ? new byte[] {0x03, 0x02, 0x05, (byte) 0xa0}
                    : new byte[] {0x03, 0x02, 0x07, (byte) 0x80}),
            extension("2.5.29.37", false, Writer.sequence(Writer.oid("1.3.6.1.5.5.7.3.2"))),
            subjectAltName);
    byte[] tbs =
        Writer.sequence(
            Writer.element(0xa0, Writer.integer(BigInteger.TWO)),
            Writer.integer(new BigInteger(1, serial)),
            algorithm,
            ca.getSubjectX500Principal().getEncoded(),
            Writer.sequence(time(notBefore), time(notAfter)),
            subject,
            key.getEncoded(),
            Writer.element(0xa3, extensions));
    Signature signer = Signature.getInstance(signing);
    signer.initSign(caKey);
    signer.update(tbs);
    byte[] der =
        Writer.sequence(tbs, algorithm, Writer.element(0x03, new byte[] {0}, signer.sign()));
    try {
      return (X509Certificate)
          CertificateFactory.getInstance("X.509")
              .generateCertificate(new ByteArrayInputStream(der));
    } catch (CertificateException e) {
      throw new GeneralSecurityException("The provisioning CA made a malformed certificate", e);
    }
  }

  /**
   * Whether the listener's check of clients accepts {@code issued} at {@code now}, the server's
   * time (keytend-kmip-server checks by its own clock): a PKIX path from it through the
   * provisioning CA, and any of the listener's other CA certificates, to a self-signed one of the
   * verifier's accepted issuers, valid at {@code now}, with at most 4 intermediates and without
   * revocation checks. keytend-kmip-server checks every new certificate with its listener's
   * verification, whose store holds every certificate of its {@code --ca} bundle, so a provisioning
   * CA that is an intermediate is accepted with its root in that bundle too. That verification
   * builds the path up to a self-signed root and takes no partial path: an accepted issuer that is
   * not self-signed is an intermediate of the path, not its end, and the root above it is checked
   * too. The path must also suit a TLS client, as the server's purpose sslclient checks every
   * certificate of it ({@link #sslClient}), and each of its certificates must have a supported
   * curve and be strong ({@link #chainWeakness}). A verifier that names no issuers is asked
   * directly, with the provisioning CA as the chain, at this machine's time, and the purpose,
   * curves and strength are checked on that chain.
   */
  private boolean trusted(X509Certificate issued, Instant now) {
    X509Certificate[] anchors = verifier.getAcceptedIssuers();
    if (anchors == null || anchors.length == 0) {
      try {
        verifier.checkClientTrusted(
            new X509Certificate[] {issued, ca}, issued.getPublicKey().getAlgorithm());
        return sslClient(List.of(issued, ca)) && chainWeakness(List.of(issued, ca)) == null;
      } catch (CertificateException e) {
        return false;
      }
    }
    try {
      java.util.Set<java.security.cert.TrustAnchor> trust = new java.util.HashSet<>();
      for (X509Certificate a : anchors)
        if (selfSigned(a)) trust.add(new java.security.cert.TrustAnchor(a, null));
      if (trust.isEmpty()) return false;
      java.security.cert.X509CertSelector target = new java.security.cert.X509CertSelector();
      target.setCertificate(issued);
      java.security.cert.PKIXBuilderParameters parameters =
          new java.security.cert.PKIXBuilderParameters(trust, target);
      parameters.setRevocationEnabled(false);
      parameters.setDate(java.util.Date.from(now));
      parameters.setMaxPathLength(4);
      List<X509Certificate> known = new java.util.ArrayList<>(List.of(issued, ca));
      known.addAll(Arrays.asList(anchors));
      parameters.addCertStore(
          java.security.cert.CertStore.getInstance(
              "Collection", new java.security.cert.CollectionCertStoreParameters(known)));
      java.security.cert.PKIXCertPathBuilderResult built =
          (java.security.cert.PKIXCertPathBuilderResult)
              java.security.cert.CertPathBuilder.getInstance("PKIX").build(parameters);
      List<X509Certificate> path = new java.util.ArrayList<>();
      for (java.security.cert.Certificate c : built.getCertPath().getCertificates())
        path.add((X509Certificate) c);
      path.add(built.getTrustAnchor().getTrustedCert());
      return sslClient(path) && chainWeakness(path) == null;
    } catch (GeneralSecurityException | RuntimeException e) {
      return false;
    }
  }

  /** Whether {@code c} names itself as its issuer and its own key verifies its signature. */
  private static boolean selfSigned(X509Certificate c) {
    if (!c.getSubjectX500Principal().equals(c.getIssuerX500Principal())) return false;
    try {
      c.verify(c.getPublicKey());
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  /**
   * Why keytend-kmip-server's listener verification refuses {@code path}, the leaf first and the
   * anchor last, after OpenSSL accepted it, by its message, or null when it does not: for each
   * certificate in turn, from depth 0, "depth N: unsupported EC curve" for a curve the server does
   * not implement ({@link #supportedCurve}), or "depth N: " and its {@link #weakness}.
   */
  static String chainWeakness(List<X509Certificate> path) {
    for (int depth = 0; depth < path.size(); depth++) {
      X509Certificate c = path.get(depth);
      if (!supportedCurve(c)) return "depth " + depth + ": unsupported EC curve";
      String weak = weakness(c);
      if (weak != null) return "depth " + depth + ": " + weak;
    }
    return null;
  }

  /** The curves keytend-kmip-server implements: P-224 to P-521, secp256k1, brainpool 256 to 512. */
  private static final java.util.Set<String> IMPLEMENTED_CURVES =
      java.util.Set.of(
          "1.3.132.0.33",
          "1.2.840.10045.3.1.7",
          "1.3.132.0.34",
          "1.3.132.0.35",
          "1.3.132.0.10",
          "1.3.36.3.3.2.8.1.1.7",
          "1.3.36.3.3.2.8.1.1.8",
          "1.3.36.3.3.2.8.1.1.9",
          "1.3.36.3.3.2.8.1.1.10",
          "1.3.36.3.3.2.8.1.1.11",
          "1.3.36.3.3.2.8.1.1.12",
          "1.3.36.3.3.2.8.1.1.13",
          "1.3.36.3.3.2.8.1.1.14");

  /**
   * Whether keytend-kmip-server's {@code supported_curve} accepts {@code c}: a key that is not EC,
   * an EC key whose parameters are not a named curve, or one on a curve the server implements.
   */
  static boolean supportedCurve(X509Certificate c) {
    return supportedCurve(c.getPublicKey().getEncoded());
  }

  /** {@link #supportedCurve(X509Certificate)} for a SubjectPublicKeyInfo, {@code spki}. */
  static boolean supportedCurve(byte[] spki) {
    String curve = CertificateIssuance.namedCurve(spki);
    return curve == null || curve.isEmpty() || IMPLEMENTED_CURVES.contains(curve);
  }

  /**
   * The signature algorithms whose digest keytend-kmip-server's strength check calls weak (the
   * digests MD2, MD4, MD5 and SHA-1), each with the key type that signs with it.
   */
  private static final Map<String, String> WEAK_SIGNATURES =
      Map.of(
          "1.2.840.113549.1.1.2", "RSA",
          "1.2.840.113549.1.1.3", "RSA",
          "1.2.840.113549.1.1.4", "RSA",
          "1.2.840.113549.1.1.5", "RSA",
          "1.3.14.3.2.3", "RSA",
          "1.3.14.3.2.29", "RSA",
          "1.2.840.10040.4.3", "DSA",
          "1.3.14.3.2.27", "DSA",
          "1.2.840.10045.4.1", "EC");

  /**
   * Why keytend-kmip-server's {@code certificate_strength} refuses {@code c}, as the end of its
   * message, or null when it does not: "key has N-bit security, below 112" for a key below 112-bit
   * security ({@link #securityBits}), then, for a certificate that is not self-issued ({@link
   * #selfIssued}), "is signed with a weak digest" for a signature with MD2, MD4, MD5 or SHA-1.
   */
  static String weakness(X509Certificate c) {
    int bits = securityBits(c.getPublicKey());
    if (bits < 112) return "key has " + bits + "-bit security, below 112";
    String signer = WEAK_SIGNATURES.get(c.getSigAlgOID());
    if (signer != null && !selfIssued(c, signer)) return "is signed with a weak digest";
    return null;
  }

  /**
   * The security strength of {@code key} in bits, as OpenSSL 3 rates it: for RSA, the NIST
   * estimate of its modulus size ({@link #rsaSecurityBits}); for EC, by the order of its group (256
   * from 512 bits, 192 from 384, 128 from 256, 112 from 224, 80 from 160, otherwise half of it);
   * for DSA, the smaller of its p size's rating and half its q size; 128 for Ed25519 and X25519,
   * 224 for Ed448 and X448; 0 for any other key.
   */
  static int securityBits(PublicKey key) {
    if (key instanceof RSAPublicKey r) return rsaSecurityBits(r.getModulus().bitLength());
    if (key instanceof ECPublicKey e) {
      int order = e.getParams().getOrder().bitLength();
      if (order >= 512) return 256;
      if (order >= 384) return 192;
      if (order >= 256) return 128;
      if (order >= 224) return 112;
      if (order >= 160) return 80;
      return order / 2;
    }
    if (key instanceof java.security.interfaces.DSAPublicKey d && d.getParams() != null) {
      int p = d.getParams().getP().bitLength(), q = d.getParams().getQ().bitLength() / 2;
      int strength =
          p >= 15360
              ? 256
              : p >= 7680 ? 192 : p >= 3072 ? 128 : p >= 2048 ? 112 : p >= 1024 ? 80 : 0;
      return strength == 0 || q < 80 ? 0 : Math.min(strength, q);
    }
    String name =
        key instanceof java.security.interfaces.EdECKey ed
            ? ed.getParams().getName()
            : key instanceof java.security.interfaces.XECKey x
                    && x.getParams() instanceof java.security.spec.NamedParameterSpec n
                ? n.getName()
                : "";
    return switch (name) {
      case "Ed25519", "X25519" -> 128;
      case "Ed448", "X448" -> 224;
      default -> 0;
    };
  }

  /**
   * OpenSSL 3's security strength of an RSA modulus of {@code n} bits ({@code
   * ossl_ifc_ffc_compute_security_bits}): the canonical value of a common size (112 for 2048, 128
   * for 3072, 152 for 4096, 176 for 6144, 192 for 7680, 200 for 8192, 256 for 15360); otherwise the
   * estimate of SP 800-56B, (1.923 * cbrt(x * ln(x)^2) - 4.69) / ln(2) with x = n * ln(2), in
   * OpenSSL's fixed point (18 fraction bits, unsigned 64-bit), rounded to a multiple of 8 and
   * capped below the next canonical value.
   */
  static int rsaSecurityBits(int n) {
    int canonical =
        switch (n) {
          case 2048 -> 112;
          case 3072 -> 128;
          case 4096 -> 152;
          case 6144 -> 176;
          case 7680 -> 192;
          case 8192 -> 200;
          case 15360 -> 256;
          default -> 0;
        };
    if (canonical != 0) return canonical;
    if (n >= 687737) return 1200;
    if (n < 8) return 0;
    int cap = n <= 7680 ? 192 : n <= 15360 ? 256 : 1200;
    long x = n * LOG_2, lx = logE(x);
    long y =
        Long.divideUnsigned(mul(C1_923, cubeRoot(mul(mul(x, lx), lx))) - C4_690, LOG_2) & 0xffff;
    return (int) Math.min((y + 4) & ~7L, cap);
  }

  /** OpenSSL's fixed point: 1 is 2^18; ln(2), log2(e), 1.923 and 4.69 in it. */
  private static final long SCALE = 1L << 18,
      LOG_2 = 0x02c5c8,
      LOG_E = 0x05c551,
      C1_923 = 0x07b126,
      C4_690 = 0x12c28f;

  private static long mul(long a, long b) {
    return Long.divideUnsigned(a * b, SCALE);
  }

  /** The integer cube root of {@code x}, in the fixed point of a cube root (2^12). */
  private static long cubeRoot(long x) {
    long r = 0;
    for (int s = 63; s >= 0; s -= 3) {
      r <<= 1;
      long b = 3 * r * (r + 1) + 1;
      if (Long.compareUnsigned(x >>> s, b) >= 0) {
        x -= b << s;
        r++;
      }
    }
    return r << 12;
  }

  /** ln({@code v}), both in the fixed point. */
  private static long logE(long v) {
    long r = 0;
    while (Long.compareUnsigned(v, 2 * SCALE) >= 0) {
      v >>>= 1;
      r += SCALE;
    }
    for (long i = SCALE / 2; i != 0; i /= 2) {
      v = mul(v, v);
      if (Long.compareUnsigned(v, 2 * SCALE) >= 0) {
        v >>>= 1;
        r += i;
      }
    }
    return (r & 0xffffffffL) * SCALE / LOG_E;
  }

  /**
   * Whether OpenSSL takes {@code c} as issued by itself ({@code X509_check_issued(c, c)}), as the
   * strength check asks before it looks at the digest: its issuer is its subject; its Authority
   * Key Identifier, where present, matches it (the key identifier its Subject Key Identifier, where
   * both are present; the serial number its own; the first directory name its issuer); its key is
   * of the kind that signs with its signature algorithm ({@code signer}); and its Key Usage, where
   * present, allows keyCertSign.
   */
  private static boolean selfIssued(X509Certificate c, String signer) {
    if (!c.getSubjectX500Principal().equals(c.getIssuerX500Principal())) return false;
    if (!signer.equals(c.getPublicKey().getAlgorithm())) return false;
    boolean[] ku = c.getKeyUsage();
    if (ku != null && !bit(ku, 5)) return false;
    byte[] akid = c.getExtensionValue("2.5.29.35");
    if (akid == null) return true;
    try {
      Reader a = new Reader(new Reader(akid).value(0x04)).enter(0x30);
      byte[] skid = c.getExtensionValue("2.5.29.14");
      while (!a.done()) {
        int tag = a.peek();
        byte[] v = a.value(tag);
        if (tag == 0x80
            && skid != null
            && !Arrays.equals(v, new Reader(new Reader(skid).value(0x04)).value(0x04)))
          return false;
        if (tag == 0x82 && !new BigInteger(v).equals(c.getSerialNumber())) return false;
        if (tag == 0xa1) {
          Reader names = new Reader(v);
          while (!names.done()) {
            int t = names.peek();
            byte[] name = names.value(t);
            if (t == 0xa4) {
              if (!new javax.security.auth.x500.X500Principal(name)
                  .equals(c.getIssuerX500Principal())) return false;
              break;
            }
          }
        }
      }
      return true;
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  private static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2",
      NETSCAPE_CERT_TYPE = "2.16.840.1.113730.1.1";

  /**
   * Whether {@code path}, the leaf first and the trust anchor last, suits a TLS client as
   * OpenSSL's purpose sslclient ({@code X509_PURPOSE_SSL_CLIENT}) has it, which
   * keytend-kmip-server's listener verifier sets: it checks every certificate of the path, the
   * anchor included. An Extended Key Usage, where present, must list clientAuth
   * (anyExtendedKeyUsage alone does not count). The leaf's Key Usage, where present, must allow
   * digitalSignature or keyAgreement, and its Netscape certificate type, where present, SSL
   * client. A CA certificate's Key Usage, where present, must allow keyCertSign, and it must be a
   * CA ({@code check_ca}, then {@code check_ssl_ca}): basicConstraints CA true; without
   * basicConstraints, a version 1 self-signed root, a certificate with a Key Usage (which allows
   * keyCertSign), or one whose Netscape certificate type names SSL CA. A Netscape type that names
   * only another kind of CA makes a CA for OpenSSL, but not one for SSL clients. Where
   * basicConstraints, a version 1 root or a Key Usage decides, the CA's Netscape type is not read.
   */
  static boolean sslClient(List<X509Certificate> path) {
    for (int i = 0; i < path.size(); i++) {
      X509Certificate c = path.get(i);
      List<String> eku;
      try {
        eku = c.getExtendedKeyUsage();
      } catch (java.security.cert.CertificateParsingException e) {
        return false;
      }
      if (eku != null && !eku.contains(CLIENT_AUTH)) return false;
      boolean[] ku = c.getKeyUsage();
      if (i == 0) {
        // digitalSignature (0) or keyAgreement (4).
        if (ku != null && !bit(ku, 0) && !bit(ku, 4)) return false;
        if (c.getExtensionValue(NETSCAPE_CERT_TYPE) != null
            && (netscapeType(c) & NS_SSL_CLIENT) == 0) return false;
        continue;
      }
      // keyCertSign (5).
      if (ku != null && !bit(ku, 5)) return false;
      if (c.getExtensionValue("2.5.29.19") != null) {
        if (c.getBasicConstraints() < 0) return false;
      } else {
        boolean v1Root =
            c.getVersion() == 1 && c.getSubjectX500Principal().equals(c.getIssuerX500Principal());
        if (!v1Root && ku == null && (netscapeType(c) & NS_SSL_CA) == 0) return false;
      }
    }
    return true;
  }

  /** Netscape certificate type bits, as OpenSSL reads them from the first byte. */
  private static final int NS_SSL_CLIENT = 0x80, NS_SSL_CA = 0x04;

  /**
   * The first byte of {@code c}'s Netscape certificate type, as OpenSSL keeps it ({@code
   * ex_nscert}); 0 without the extension, or with no bits.
   */
  private static int netscapeType(X509Certificate c) {
    byte[] type = c.getExtensionValue(NETSCAPE_CERT_TYPE);
    // The BIT STRING inside the extnValue OCTET STRING: its first byte after the unused-bits one.
    return type == null || type.length < 6 ? 0 : type[5] & 0xff;
  }

  private static boolean bit(boolean[] bits, int i) {
    return i < bits.length && bits[i];
  }

  /** The subjectAltName extension of {@code replaced}, copied; empty when it has none. */
  private static byte[] subjectAltName(X509Certificate replaced) {
    byte[] value = replaced.getExtensionValue("2.5.29.17");
    if (value == null) return new byte[0];
    boolean critical =
        replaced.getCriticalExtensionOIDs() != null
            && replaced.getCriticalExtensionOIDs().contains("2.5.29.17");
    // getExtensionValue returns the extnValue OCTET STRING, DER-encoded.
    return critical
        ? Writer.sequence(Writer.oid("2.5.29.17"), new byte[] {0x01, 0x01, (byte) 0xff}, value)
        : Writer.sequence(Writer.oid("2.5.29.17"), value);
  }

  private static byte[] extension(String oid, boolean critical, byte[] value) {
    byte[] wrapped = Writer.element(0x04, value);
    return critical
        ? Writer.sequence(Writer.oid(oid), new byte[] {0x01, 0x01, (byte) 0xff}, wrapped)
        : Writer.sequence(Writer.oid(oid), wrapped);
  }

  private static byte[] time(Instant t) {
    int year = t.atZone(ZoneOffset.UTC).getYear();
    if (year >= 1950 && year < 2050)
      return Writer.element(
          0x17,
          DateTimeFormatter.ofPattern("yyMMddHHmmss'Z'")
              .withZone(ZoneOffset.UTC)
              .format(t)
              .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    return Writer.element(
        0x18,
        DateTimeFormatter.ofPattern("yyyyMMddHHmmss'Z'")
            .withZone(ZoneOffset.UTC)
            .format(t)
            .getBytes(java.nio.charset.StandardCharsets.US_ASCII));
  }

  private static String oid(byte[] v) {
    if (v.length == 0 || (v[v.length - 1] & 0x80) != 0) throw new IllegalArgumentException("OID");
    StringBuilder out = new StringBuilder();
    long arc = 0;
    for (byte b : v) {
      if (arc > (Long.MAX_VALUE >> 7)) throw new IllegalArgumentException("OID");
      arc = (arc << 7) | (b & 0x7f);
      if ((b & 0x80) != 0) continue;
      if (out.length() == 0) {
        long first = Math.min(arc / 40, 2);
        out.append(first).append('.').append(arc - 40 * first);
      } else out.append('.').append(arc);
      arc = 0;
    }
    return out.toString();
  }

  /** A strict reader of definite-length DER with one-byte tags. */
  private static final class Reader {
    final byte[] d;
    int at;
    final int end;

    Reader(byte[] d) {
      this(d, 0, d.length);
    }

    private Reader(byte[] d, int from, int end) {
      this.d = d;
      this.at = from;
      this.end = end;
    }

    boolean done() {
      return at == end;
    }

    /** The tag of the next element. */
    int peek() {
      if (at >= end) throw new IllegalArgumentException("DER: no element");
      return d[at] & 0xff;
    }

    /** The contents of the next element, which must have {@code tag}; moves past it. */
    byte[] value(int tag) {
      int[] span = header(tag);
      at = span[1];
      return Arrays.copyOfRange(d, span[0], span[1]);
    }

    /** A reader of the next element's contents; moves past it. */
    Reader enter(int tag) {
      int[] span = header(tag);
      at = span[1];
      return new Reader(d, span[0], span[1]);
    }

    private int[] header(int tag) {
      int i = at;
      if (end - i < 2 || (d[i++] & 0xff) != tag) throw new IllegalArgumentException("DER tag");
      int length = d[i++] & 0xff;
      if (length >= 0x80) {
        int bytes = length - 0x80;
        if (bytes == 0 || bytes > 4) throw new IllegalArgumentException("DER length");
        length = 0;
        for (int n = 0; n < bytes; n++) {
          if (i >= end || length > (Integer.MAX_VALUE >> 8))
            throw new IllegalArgumentException("DER length");
          length = (length << 8) | (d[i++] & 0xff);
        }
        if (length < 0x80) throw new IllegalArgumentException("DER length not minimal");
      }
      if (length < 0 || length > end - i) throw new IllegalArgumentException("DER length");
      return new int[] {i, i + length};
    }
  }

  /** A DER writer: one-byte tags, shortest definite lengths. */
  private static final class Writer {
    static byte[] element(int tag, byte[]... contents) {
      int n = 0;
      for (byte[] c : contents) n += c.length;
      byte[] length;
      if (n < 0x80) length = new byte[] {(byte) n};
      else {
        int bytes = (Integer.SIZE - Integer.numberOfLeadingZeros(n) + 7) / 8;
        length = new byte[1 + bytes];
        length[0] = (byte) (0x80 | bytes);
        for (int i = bytes, v = n; i >= 1; i--, v >>>= 8) length[i] = (byte) v;
      }
      byte[] out = new byte[1 + length.length + n];
      out[0] = (byte) tag;
      System.arraycopy(length, 0, out, 1, length.length);
      int at = 1 + length.length;
      for (byte[] c : contents) {
        System.arraycopy(c, 0, out, at, c.length);
        at += c.length;
      }
      return out;
    }

    static byte[] sequence(byte[]... parts) {
      return element(0x30, parts);
    }

    static byte[] integer(BigInteger v) {
      return element(0x02, v.toByteArray());
    }

    static byte[] nul() {
      return new byte[] {0x05, 0x00};
    }

    static byte[] oid(String dotted) {
      String[] parts = dotted.split("\\.");
      long[] arcs = Arrays.stream(parts).mapToLong(Long::parseLong).toArray();
      java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
      arc(out, arcs[0] * 40 + arcs[1]);
      for (int i = 2; i < arcs.length; i++) arc(out, arcs[i]);
      return element(0x06, out.toByteArray());
    }

    private static void arc(java.io.ByteArrayOutputStream out, long arc) {
      int groups = Math.max(1, (Long.SIZE - Long.numberOfLeadingZeros(arc) + 6) / 7);
      for (int g = groups - 1; g >= 0; g--)
        out.write((int) (((arc >>> (7 * g)) & 0x7f) | (g == 0 ? 0 : 0x80)));
    }
  }
}
