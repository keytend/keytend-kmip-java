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

import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.TestX509;
import java.io.StringReader;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.edec.EdECObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x9.X9ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PKCS8Generator;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8EncryptorBuilder;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The SDK's PEM and PKCS#8 reading ({@link Pem}, {@link PemIdentity}) against Bouncy Castle as an
 * independent encoder: the files Bouncy Castle writes (PKCS#8 built from the keys' components,
 * encrypted with PBES2 under each PRF and cipher, and with the PKCS#12 PBES1 schemes) give the same
 * keys, and the SDK refuses exactly what its contract refuses: a scheme the JDK does not provide,
 * a wrong password, and the SEC1 {@code EC PRIVATE KEY} and PKCS#1 {@code RSA PRIVATE KEY} labels
 * (with advice to convert to PKCS#8; {@code Keys} reads those forms from KMIP, see {@code
 * model.KeysBouncyCastleTest}). Bouncy Castle is used as a library and, for encryption, as a
 * provider instance; it is never registered, so the SDK decrypts with the JDK alone.
 */
class PemBouncyCastleTest {
  private static final Provider BC = new BouncyCastleProvider();
  private static final char[] PASSWORD = "correct horse battery".toCharArray();
  private static final List<Identity> IDENTITIES = new ArrayList<>();

  /** A key pair from the JDK, its PKCS#8 encoding built by Bouncy Castle, and a certificate. */
  record Identity(String name, KeyPair pair, PrivateKeyInfo info, String chainPem) {}

  @BeforeAll
  static void identities() throws Exception {
    for (String curve : List.of("secp256r1", "secp384r1", "secp521r1")) {
      KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
      g.initialize(new ECGenParameterSpec(curve));
      KeyPair pair = g.generateKeyPair();
      IDENTITIES.add(identity("EC " + curve, pair, ecInfo(pair, curve)));
    }
    for (String algorithm : List.of("RSA", "RSASSA-PSS")) {
      KeyPairGenerator g = KeyPairGenerator.getInstance(algorithm);
      g.initialize(2048);
      KeyPair pair = g.generateKeyPair();
      IDENTITIES.add(
          identity(
              algorithm,
              pair,
              rsaInfo(
                  (RSAPrivateCrtKey) pair.getPrivate(),
                  algorithm.equals("RSA")
                      ? new AlgorithmIdentifier(
                          PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE)
                      : new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS))));
    }
    // Ed25519 made by Bouncy Castle's own generator: only its encodings reach the JDK.
    Ed25519KeyPairGenerator ed = new Ed25519KeyPairGenerator();
    ed.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
    AsymmetricCipherKeyPair bcPair = ed.generateKeyPair();
    byte[] seed = ((Ed25519PrivateKeyParameters) bcPair.getPrivate()).getEncoded();
    PrivateKeyInfo edInfo =
        new PrivateKeyInfo(
            new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519), new DEROctetString(seed));
    KeyFactory edFactory = KeyFactory.getInstance("Ed25519");
    PublicKey edPublic =
        edFactory.generatePublic(
            new X509EncodedKeySpec(
                new SubjectPublicKeyInfo(
                        new AlgorithmIdentifier(EdECObjectIdentifiers.id_Ed25519),
                        ((Ed25519PublicKeyParameters) bcPair.getPublic()).getEncoded())
                    .getEncoded()));
    PrivateKey edPrivate =
        edFactory.generatePrivate(new java.security.spec.PKCS8EncodedKeySpec(edInfo.getEncoded()));
    IDENTITIES.add(identity("Ed25519", new KeyPair(edPublic, edPrivate), edInfo));
  }

  private static Identity identity(String name, KeyPair pair, PrivateKeyInfo info)
      throws Exception {
    // The certificate is signed by a separate EC CA: the identity's own key need not sign.
    KeyPair ca = TestPki.ec();
    var certificate =
        TestX509.certificate(name.replace(' ', '-'), pair.getPublic())
            .issuedBy(
                TestX509.certificate("pem-ca", ca.getPublic()).selfSigned(ca.getPrivate()).build(),
                ca.getPrivate())
            .build();
    return new Identity(
        name, pair, info, pem(new PemObject("CERTIFICATE", certificate.getEncoded())));
  }

  /** PKCS#8 for an EC key as OpenSSL writes it: SEC1 inside, with its curve and public key. */
  private static PrivateKeyInfo ecInfo(KeyPair pair, String curve) throws Exception {
    ASN1ObjectIdentifier oid =
        switch (curve) {
          case "secp256r1" -> X9ObjectIdentifiers.prime256v1;
          case "secp384r1" -> org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp384r1;
          default -> org.bouncycastle.asn1.sec.SECObjectIdentifiers.secp521r1;
        };
    ECPrivateKey key = (ECPrivateKey) pair.getPrivate();
    int bits = key.getParams().getOrder().bitLength();
    byte[] point =
        SubjectPublicKeyInfo.getInstance(pair.getPublic().getEncoded())
            .getPublicKeyData()
            .getBytes();
    return new PrivateKeyInfo(
        new AlgorithmIdentifier(X9ObjectIdentifiers.id_ecPublicKey, oid),
        new org.bouncycastle.asn1.sec.ECPrivateKey(bits, key.getS(), new DERBitString(point), oid));
  }

  private static PrivateKeyInfo rsaInfo(RSAPrivateCrtKey k, AlgorithmIdentifier algorithm)
      throws Exception {
    return new PrivateKeyInfo(
        algorithm,
        new RSAPrivateKey(
            k.getModulus(),
            k.getPublicExponent(),
            k.getPrivateExponent(),
            k.getPrimeP(),
            k.getPrimeQ(),
            k.getPrimeExponentP(),
            k.getPrimeExponentQ(),
            k.getCrtCoefficient()));
  }

  private static String pem(PemObject object) throws Exception {
    StringWriter out = new StringWriter();
    try (PemWriter w = new PemWriter(out)) {
      w.writeObject(object);
    }
    return out.toString();
  }

  /** The key {@link PemIdentity} reads from {@code keyPem}, with the identity's chain. */
  private static PrivateKey read(Path dir, Identity id, String keyPem, char[] password)
      throws Exception {
    Path chain = dir.resolve("chain.pem"), key = dir.resolve("key.pem");
    Files.writeString(chain, id.chainPem());
    Files.writeString(key, keyPem);
    return (PrivateKey)
        PemIdentity.keyStore(chain, key, password, TlsFiles.WHOLE).getKey("identity", new char[0]);
  }

  private static void assertSameKey(Identity id, PrivateKey read) {
    PrivateKey expected = id.pair().getPrivate();
    assertEquals(expected.getAlgorithm(), read.getAlgorithm(), id.name());
    if (expected instanceof RSAPrivateCrtKey e) {
      RSAPrivateCrtKey r = (RSAPrivateCrtKey) read;
      assertEquals(e.getModulus(), r.getModulus(), id.name());
      assertEquals(e.getPrivateExponent(), r.getPrivateExponent(), id.name());
      assertEquals(e.getPrimeP(), r.getPrimeP(), id.name());
      assertEquals(e.getCrtCoefficient(), r.getCrtCoefficient(), id.name());
    } else if (expected instanceof ECPrivateKey e) {
      ECPrivateKey r = (ECPrivateKey) read;
      assertEquals(e.getS(), r.getS(), id.name());
      assertEquals(
          ((ECPublicKey) id.pair().getPublic()).getParams().getOrder(),
          r.getParams().getOrder(),
          id.name());
    } else {
      assertArrayEquals(
          ((EdECPrivateKey) expected).getBytes().orElseThrow(),
          ((EdECPrivateKey) read).getBytes().orElseThrow(),
          id.name());
    }
  }

  private static String refusal(Path dir, Identity id, String keyPem, char[] password) {
    Path key = dir.resolve("key.pem");
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> read(dir, id, keyPem, password));
    assertTrue(e.getMessage().contains(key.toString()), e.getMessage());
    assertNull(e.getCause(), "no parser message can quote the key: " + e);
    if (password != null)
      assertFalse(e.getMessage().contains(new String(password)), e.getMessage());
    return e.getMessage();
  }

  @Test
  void unencryptedPkcs8FromBouncyCastleGivesTheSameKeys(@TempDir Path dir) throws Exception {
    for (Identity id : IDENTITIES) {
      String keyPem = pem(new PemObject("PRIVATE KEY", id.info().getEncoded()));
      assertSameKey(id, read(dir, id, keyPem, null));
      // With the password overload too: an unencrypted key ignores it.
      assertSameKey(id, read(dir, id, keyPem, PASSWORD));
      // The key and its chain in one file, in either order (HAProxy's form).
      Path both = dir.resolve("both.pem");
      for (String text : List.of(keyPem + id.chainPem(), id.chainPem() + keyPem)) {
        Files.writeString(both, text);
        assertSameKey(
            id,
            (PrivateKey)
                PemIdentity.keyStore(both, both, null, TlsFiles.WHOLE)
                    .getKey("identity", new char[0]));
      }
    }
  }

  /**
   * A PBES2 or PBES1 scheme Bouncy Castle writes, and the JDK name the SDK decrypts it with; or,
   * for a scheme the JDK does not provide, the end of the SDK's refusal.
   */
  record Scheme(
      String name,
      ASN1ObjectIdentifier cipher,
      AlgorithmIdentifier prf,
      String jdk,
      String refusal) {
    Scheme(String name, ASN1ObjectIdentifier cipher, AlgorithmIdentifier prf, String jdk) {
      this(name, cipher, prf, jdk, ": the private key is encrypted with an unsupported scheme (");
    }
  }

  /**
   * The JDK's {@code EncryptedPrivateKeyInfo} cannot read PBES2 parameters naming a cipher or PRF
   * its PBES2 does not have, so the SDK calls such a file malformed (on JDK 17, 21 and 25).
   */
  private static final String UNREADABLE_PBES2 = ": the encrypted private key is malformed";

  private static final List<Scheme> SCHEMES =
      List.of(
          new Scheme(
              "PBES2 HMAC-SHA1 AES-128",
              PKCS8Generator.AES_128_CBC,
              PKCS8Generator.PRF_HMACSHA1,
              "PBEWithHmacSHA1AndAES_128"),
          new Scheme(
              "PBES2 HMAC-SHA1 AES-256",
              PKCS8Generator.AES_256_CBC,
              PKCS8Generator.PRF_HMACSHA1,
              "PBEWithHmacSHA1AndAES_256"),
          new Scheme(
              "PBES2 HMAC-SHA224 AES-128",
              PKCS8Generator.AES_128_CBC,
              PKCS8Generator.PRF_HMACSHA224,
              "PBEWithHmacSHA224AndAES_128"),
          new Scheme(
              "PBES2 HMAC-SHA256 AES-128",
              PKCS8Generator.AES_128_CBC,
              PKCS8Generator.PRF_HMACSHA256,
              "PBEWithHmacSHA256AndAES_128"),
          new Scheme(
              "PBES2 HMAC-SHA256 AES-256",
              PKCS8Generator.AES_256_CBC,
              PKCS8Generator.PRF_HMACSHA256,
              "PBEWithHmacSHA256AndAES_256"),
          new Scheme(
              "PBES2 HMAC-SHA384 AES-256",
              PKCS8Generator.AES_256_CBC,
              PKCS8Generator.PRF_HMACSHA384,
              "PBEWithHmacSHA384AndAES_256"),
          new Scheme(
              "PBES2 HMAC-SHA512 AES-256",
              PKCS8Generator.AES_256_CBC,
              PKCS8Generator.PRF_HMACSHA512,
              "PBEWithHmacSHA512AndAES_256"),
          // PBES2 with a cipher or PRF the JDK's PBES2 does not provide.
          new Scheme(
              "PBES2 HMAC-SHA256 AES-192",
              PKCS8Generator.AES_192_CBC,
              PKCS8Generator.PRF_HMACSHA256,
              null,
              UNREADABLE_PBES2),
          new Scheme(
              "PBES2 HMAC-SHA256 DES-EDE3-CBC",
              PKCS8Generator.DES3_CBC,
              PKCS8Generator.PRF_HMACSHA256,
              null,
              UNREADABLE_PBES2),
          new Scheme(
              "PBES2 HMAC-SHA3-256 AES-256",
              PKCS8Generator.AES_256_CBC,
              PKCS8Generator.PRF_HMACSHA3_256,
              null,
              UNREADABLE_PBES2),
          // PKCS#12's PBES1-style schemes.
          new Scheme("PBE-SHA1-3DES", PKCS8Generator.PBE_SHA1_3DES, null, "PBEWithSHA1AndDESede"),
          new Scheme(
              "PBE-SHA1-RC2-128", PKCS8Generator.PBE_SHA1_RC2_128, null, "PBEWithSHA1AndRC2_128"),
          new Scheme(
              "PBE-SHA1-RC2-40", PKCS8Generator.PBE_SHA1_RC2_40, null, "PBEWithSHA1AndRC2_40"),
          new Scheme(
              "PBE-SHA1-RC4-128", PKCS8Generator.PBE_SHA1_RC4_128, null, "PBEWithSHA1AndRC4_128"),
          new Scheme(
              "PBE-SHA1-RC4-40", PKCS8Generator.PBE_SHA1_RC4_40, null, "PBEWithSHA1AndRC4_40"),
          new Scheme("PBE-SHA1-2DES", PKCS8Generator.PBE_SHA1_2DES, null, null));

  /** Whether this JDK provides {@code name} for both key derivation and decryption. */
  private static boolean jdkProvides(String name) {
    if (name == null) return false;
    try {
      SecretKeyFactory.getInstance(name);
      Cipher.getInstance(name);
      return true;
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  private static String encrypted(Identity id, Scheme s, char[] password, int iterations)
      throws Exception {
    JceOpenSSLPKCS8EncryptorBuilder b =
        new JceOpenSSLPKCS8EncryptorBuilder(s.cipher())
            .setProvider(BC)
            .setPassword(password)
            .setIterationCount(iterations);
    if (s.prf() != null) b.setPRF(s.prf());
    return pem(new PKCS8Generator(id.info(), b.build()).generate());
  }

  @Test
  void encryptedPkcs8FromBouncyCastleDecryptsWhereTheJdkProvidesTheScheme(@TempDir Path dir)
      throws Exception {
    int decrypted = 0, refused = 0;
    for (int i = 0; i < SCHEMES.size(); i++) {
      Scheme s = SCHEMES.get(i);
      // Every key type under the first scheme; each other scheme over one key type, in turn.
      List<Identity> ids = i == 0 ? IDENTITIES : List.of(IDENTITIES.get(i % IDENTITIES.size()));
      for (Identity id : ids) {
        String keyPem = encrypted(id, s, PASSWORD, 1024 + i);
        assertTrue(keyPem.startsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----\n"), s.name());
        // PBES2 with AES, and PKCS#12's 3DES, are in every JDK 17 and later; RC2 and RC4 may not
        // be.
        if (s.jdk() != null && (s.name().startsWith("PBES2") || s.name().equals("PBE-SHA1-3DES")))
          assertTrue(jdkProvides(s.jdk()), s.jdk());
        if (jdkProvides(s.jdk())) {
          assertSameKey(id, read(dir, id, keyPem, PASSWORD));
          String wrong = refusal(dir, id, keyPem, "not the password".toCharArray());
          assertTrue(wrong.contains(": wrong password, or the file is corrupt"), wrong);
          String none = refusal(dir, id, keyPem, null);
          assertTrue(none.contains(" holds an encrypted private key: pass its password"), none);
          decrypted++;
        } else {
          String why = refusal(dir, id, keyPem, PASSWORD);
          assertTrue(why.contains(s.refusal()), s.name() + ": " + why);
          refused++;
        }
      }
    }
    assertTrue(decrypted >= 13, "decrypted " + decrypted);
    assertEquals(4, refused);
  }

  @Test
  void pemFromBouncyCastleWithTheIterationCountTheFileAsksFor(@TempDir Path dir) throws Exception {
    Identity id = IDENTITIES.get(0);
    for (int iterations : new int[] {1, 2048, 100_000}) {
      String keyPem = encrypted(id, SCHEMES.get(4), PASSWORD, iterations);
      assertSameKey(id, read(dir, id, keyPem, PASSWORD));
    }
  }

  /**
   * SEC1 {@code EC PRIVATE KEY} and PKCS#1 {@code RSA PRIVATE KEY} blocks, plain or with OpenSSL's
   * legacy {@code Proc-Type: 4,ENCRYPTED} headers, as Bouncy Castle's {@code JcaPEMWriter} writes
   * them, are refused by their label with advice to convert them to PKCS#8, before any decoding.
   */
  @Test
  void sec1AndPkcs1LabelsAreRefusedWithAdvice(@TempDir Path dir) throws Exception {
    int checked = 0;
    for (Identity id : IDENTITIES) {
      String algorithm = id.pair().getPrivate().getAlgorithm();
      if (!algorithm.equals("EC") && !algorithm.equals("RSA")) continue;
      String label = algorithm.equals("EC") ? "EC PRIVATE KEY" : "RSA PRIVATE KEY";
      for (boolean legacyEncrypted : new boolean[] {false, true}) {
        StringWriter out = new StringWriter();
        try (JcaPEMWriter w = new JcaPEMWriter(out)) {
          if (legacyEncrypted)
            w.writeObject(
                id.pair().getPrivate(),
                new JcePEMEncryptorBuilder("AES-256-CBC").setProvider(BC).build(PASSWORD));
          else w.writeObject(id.pair().getPrivate());
        }
        String keyPem = out.toString();
        assertTrue(keyPem.startsWith("-----BEGIN " + label + "-----"), keyPem);
        assertEquals(legacyEncrypted, keyPem.contains("Proc-Type: 4,ENCRYPTED"));
        String why = refusal(dir, id, keyPem, legacyEncrypted ? PASSWORD : null);
        assertTrue(
            why.endsWith(
                " holds a BEGIN "
                    + label
                    + " block, not PKCS#8; convert it with openssl pkcs8 -topk8"
                    + " (add -nocrypt to leave it unencrypted)"),
            why);
        checked++;
      }
    }
    assertEquals(8, checked);
  }

  /**
   * {@link Pem} reads every block Bouncy Castle's {@code PemWriter} writes, of every length around
   * the 48-byte line and 3-byte group boundaries, several to a file, with LF or CRLF line ends,
   * as the bytes Bouncy Castle's {@code PemReader} reads back.
   */
  @Test
  void pemBlocksFromBouncyCastleDecodeToTheSameBytes() throws Exception {
    SecureRandom random = new SecureRandom();
    Path file = Path.of("blocks.pem");
    for (String eol : List.of("\n", "\r\n")) {
      List<byte[]> contents = new ArrayList<>();
      StringBuilder text = new StringBuilder();
      for (int length = 1; length <= 200; length++) {
        byte[] content = new byte[length];
        random.nextBytes(content);
        contents.add(content);
        text.append(pem(new PemObject(length % 2 == 0 ? "CERTIFICATE" : "X509 CRL", content)));
      }
      String file1 = text.toString().replace("\r\n", "\n").replace("\n", eol);
      byte[] bytes = file1.getBytes(US_ASCII);
      List<Pem.Block> blocks = Pem.blocks(bytes, file);
      assertEquals(contents.size(), blocks.size());
      try (PemReader bc = new PemReader(new StringReader(file1))) {
        for (int i = 0; i < blocks.size(); i++) {
          PemObject expected = bc.readPemObject();
          assertEquals(expected.getType(), blocks.get(i).label());
          assertArrayEquals(expected.getContent(), contents.get(i));
          assertArrayEquals(contents.get(i), Pem.decode(bytes, blocks.get(i), file), "block " + i);
        }
        assertNull(bc.readPemObject());
      }
    }
  }

  /**
   * A block with RFC 1421 headers, which Bouncy Castle's {@code PemReader} accepts, is not
   * RFC 7468 PEM: {@link Pem} does not decode it.
   */
  @Test
  void pemHeadersBouncyCastleAcceptsAreNotDecoded() throws Exception {
    PemObject withHeaders =
        new PemObject(
            "CERTIFICATE",
            List.of(new org.bouncycastle.util.io.pem.PemHeader("Comment", "a header")),
            new byte[] {1, 2, 3, 4, 5, 6});
    String text = pem(withHeaders);
    try (PemReader bc = new PemReader(new StringReader(text))) {
      assertArrayEquals(new byte[] {1, 2, 3, 4, 5, 6}, bc.readPemObject().getContent());
    }
    byte[] bytes = text.getBytes(US_ASCII);
    Path file = Path.of("headers.pem");
    List<Pem.Block> blocks = Pem.blocks(bytes, file);
    assertEquals(1, blocks.size());
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> Pem.decode(bytes, blocks.get(0), file));
    assertTrue(e.getMessage().startsWith(file.toString()), e.getMessage());
  }
}
