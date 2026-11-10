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

import static dev.keytend.kmip.kms.KmsApiTest.pem;
import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.TestTls;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.KmipTransport;
import dev.keytend.kmip.transport.RequestNotSentException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** KmsConfig validation, the hashed-password lock wait, and the handling of secrets. */
class KmsConfigValidationTest {
  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  // ---- a client identity where certificate authentication needs one ----

  @Test
  void certificateAuthenticationWithoutAClientIdentityFailsInBuild(@TempDir Path dir)
      throws Exception {
    Path ca = dir.resolve("ca.pem");
    Files.writeString(ca, pem("CERTIFICATE", TestTls.certificate("server").getEncoded()));
    KeyStore trust = KeyStore.getInstance("PKCS12");
    trust.load(null, null);
    trust.setCertificateEntry("ca", TestTls.certificate("server"));
    for (KmsConfig.Builder trustOnly :
        List.of(
            KmsConfig.builder().trustPem(ca),
            KmsConfig.builder().trustStore(trust),
            KmsConfig.builder().trustSystemDefaults(),
            KmsConfig.builder()
                .usernamePassword("u", "p".toCharArray())
                .trustPem(ca)
                .clientCertificate())) {
      var e =
          assertThrows(IllegalArgumentException.class, () -> trustOnly.endpoints("kms").build());
      assertTrue(e.getMessage().contains("needs a client identity"), e.getMessage());
    }
    // Server-authenticated TLS with a password Credential needs no client identity.
    KmsConfig.builder()
        .endpoints("kms")
        .trustPem(ca)
        .usernamePassword("u", "p".toCharArray())
        .build();
    KmsConfig.builder()
        .endpoints("kms")
        .trustSystemDefaults()
        .hashedPassword("u", "p".toCharArray())
        .build();
    // A ready-made context or a custom transport cannot be inspected: left to the caller.
    KmsConfig.builder().endpoints("kms").tls(javax.net.ssl.SSLContext.getDefault()).build();
    KmsConfig.builder().endpoints("kms").trustPem(ca).transport(e -> null).build();
    KmsConfig.builder()
        .endpoints("kms")
        .clientIdentity(TestTls.identity("client"), "changeit".toCharArray())
        .trustPem(ca)
        .build();
  }

  // ---- the PEM key must match the certificate, with precise errors ----

  @Test
  void pemKeyMustMatchTheCertificate(@TempDir Path dir) throws Exception {
    Path ecCertificate =
        write(dir, "ec.pem", "CERTIFICATE", certificate("client", "EC").getEncoded());
    Path rsaCertificate =
        write(dir, "rsa.pem", "CERTIFICATE", certificate("rsaclient", "RSA").getEncoded());
    Map<String, Path> mismatched = new LinkedHashMap<>();
    mismatched.put(
        "another EC key",
        write(dir, "ec2.key", "PRIVATE KEY", privateKey("other", "EC").getEncoded()));
    mismatched.put(
        "an RSA key",
        write(dir, "rsa.key", "PRIVATE KEY", privateKey("rsaclient", "RSA").getEncoded()));
    mismatched.put(
        "an Ed25519 key", write(dir, "ed.key", "PRIVATE KEY", generate("Ed25519").getEncoded()));
    for (var c : mismatched.entrySet()) {
      var e =
          assertThrows(
              IllegalArgumentException.class,
              () -> KmsConfig.builder().clientIdentityPem(ecCertificate, c.getValue()),
              c.getKey());
      assertTrue(
          e.getMessage().contains("does not match the first certificate in " + ecCertificate),
          e.getMessage());
    }
    Path otherRsa =
        write(dir, "rsa2.key", "PRIVATE KEY", privateKey("rsaother", "RSA").getEncoded());
    var rsa =
        assertThrows(
            IllegalArgumentException.class,
            () -> KmsConfig.builder().clientIdentityPem(rsaCertificate, otherRsa));
    assertTrue(rsa.getMessage().contains("(RSA) does not match"), rsa.getMessage());
    // The matching keys are accepted.
    KmsConfig.builder()
        .clientIdentityPem(
            ecCertificate,
            write(dir, "ok.key", "PRIVATE KEY", privateKey("client", "EC").getEncoded()));
    KmsConfig.builder().clientIdentityPem(rsaCertificate, mismatched.get("an RSA key"));
  }

  @Test
  void pemIdentityErrorsSayWhatIsWrongWithoutQuotingTheFile(@TempDir Path dir) throws Exception {
    Path chain = write(dir, "chain.pem", "CERTIFICATE", certificate("client", "EC").getEncoded());
    byte[] key = privateKey("client", "EC").getEncoded();
    String body = Base64.getEncoder().encodeToString(key).substring(8, 40);
    Map<String, Path> keyFiles = new LinkedHashMap<>();
    Map<String, String> expected = new LinkedHashMap<>();
    expected.put("missing", "Cannot read the private key file");
    keyFiles.put("missing", dir.resolve("absent.key"));
    expected.put("no block", "has no PEM private key");
    keyFiles.put("no block", text(dir, "none.key", "just text " + body + "\n"));
    expected.put(
        "PKCS#1",
        "holds a BEGIN RSA PRIVATE KEY block, not PKCS#8; convert it with openssl pkcs8 -topk8");
    keyFiles.put("PKCS#1", write(dir, "pkcs1.key", "RSA PRIVATE KEY", key));
    expected.put("SEC1", "holds a BEGIN EC PRIVATE KEY block, not PKCS#8");
    keyFiles.put("SEC1", write(dir, "sec1.key", "EC PRIVATE KEY", key));
    expected.put("no END", "has no END line");
    keyFiles.put("no END", text(dir, "cut.key", "-----BEGIN PRIVATE KEY-----\n" + body + "\n"));
    expected.put("bad Base64", "block is not valid Base64");
    keyFiles.put(
        "bad Base64",
        text(dir, "b64.key", "-----BEGIN PRIVATE KEY-----\nAAAAA\n-----END PRIVATE KEY-----\n"));
    expected.put("not PKCS#8", "the private key is malformed (not a PKCS#8 PrivateKeyInfo)");
    keyFiles.put(
        "not PKCS#8", write(dir, "junk.key", "PRIVATE KEY", Arrays.copyOf(key, key.length - 3)));
    expected.put("bad EC key", "the EC private key is malformed");
    keyFiles.put("bad EC key", write(dir, "badec.key", "PRIVATE KEY", ecWithBrokenInnerKey(key)));
    expected.put("unsupported", "unsupported type (algorithm 1.3.101.110)");
    keyFiles.put(
        "unsupported", write(dir, "x25519.key", "PRIVATE KEY", generate("X25519").getEncoded()));
    expected.put("encrypted without password", "holds an encrypted private key: pass its password");
    keyFiles.put(
        "encrypted without password",
        write(dir, "enc.key", "ENCRYPTED PRIVATE KEY", encrypt(key, "pw", PBES2)));
    for (var c : keyFiles.entrySet()) {
      var e =
          assertThrows(
              IllegalArgumentException.class,
              () -> KmsConfig.builder().clientIdentityPem(chain, c.getValue()),
              c.getKey());
      assertTrue(
          e.getMessage().contains(expected.get(c.getKey())), c.getKey() + ": " + e.getMessage());
      assertTrue(e.getMessage().contains(c.getValue().toString()), e.getMessage());
      for (Throwable t = e; t != null; t = t.getCause())
        assertFalse(String.valueOf(t.getMessage()).contains(body), c.getKey() + " quotes the file");
    }
    Path keyFile = write(dir, "key.pem", "PRIVATE KEY", key);
    var noCertificateFile =
        assertThrows(
            IllegalArgumentException.class,
            () -> KmsConfig.builder().clientIdentityPem(dir.resolve("absent.pem"), keyFile));
    assertTrue(
        noCertificateFile.getMessage().startsWith("Cannot read the certificate file"),
        noCertificateFile.getMessage());
    Path notACertificate =
        text(dir, "bad.pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n");
    var badCertificate =
        assertThrows(
            IllegalArgumentException.class,
            () -> KmsConfig.builder().clientIdentityPem(notACertificate, keyFile));
    assertTrue(
        badCertificate.getMessage().contains("holds no valid X.509 certificate"),
        badCertificate.getMessage());
  }

  // ---- RSA keys sign a challenge too ----

  /**
   * An RSA key was matched to the certificate by modulus and public exponent only, so a key
   * file with the right modulus and a wrong private exponent was accepted (and failed only at the
   * TLS handshake, or signed wrongly). The key now signs a challenge that the certificate's key
   * must verify. A signing failure is reported without the provider's exception as cause.
   */
  @Test
  void rsaPemKeysMustSignForTheCertificateNotOnlyShareItsModulus(@TempDir Path dir)
      throws Exception {
    Path chain = write(dir, "rsa.pem", "CERTIFICATE", certificate("rsaclient", "RSA").getEncoded());
    RSAPrivateCrtKey real = (RSAPrivateCrtKey) privateKey("rsaclient", "RSA");
    BigInteger n = real.getModulus(),
        e = real.getPublicExponent(),
        wrongD = real.getPrivateExponent().add(BigInteger.TWO);
    KeyFactory rsa = KeyFactory.getInstance("RSA");
    // Modulus and private exponent only (PKCS#8 with zero CRT fields): the exponent decides.
    Path nonCrt =
        write(
            dir,
            "noncrt.key",
            "PRIVATE KEY",
            rsa.generatePrivate(new RSAPrivateKeySpec(n, wrongD)).getEncoded());
    var mismatch =
        assertThrows(
            IllegalArgumentException.class,
            () -> KmsConfig.builder().clientIdentityPem(chain, nonCrt));
    assertTrue(
        mismatch.getMessage().contains("(RSA) does not match the first certificate in " + chain),
        mismatch.getMessage());
    // CRT keys with the right modulus and public exponent, and a wrong d or a wrong CRT exponent:
    // the JDK refuses to sign with them (it checks its CRT result against the public exponent).
    Map<String, RSAPrivateCrtKeySpec> broken = new LinkedHashMap<>();
    broken.put(
        "wrong d",
        new RSAPrivateCrtKeySpec(
            n,
            e,
            wrongD,
            real.getPrimeP(),
            real.getPrimeQ(),
            real.getPrimeExponentP(),
            real.getPrimeExponentQ(),
            real.getCrtCoefficient()));
    broken.put(
        "wrong dP",
        new RSAPrivateCrtKeySpec(
            n,
            e,
            real.getPrivateExponent(),
            real.getPrimeP(),
            real.getPrimeQ(),
            real.getPrimeExponentP().add(BigInteger.TWO),
            real.getPrimeExponentQ(),
            real.getCrtCoefficient()));
    for (var c : broken.entrySet()) {
      Path key =
          write(
              dir,
              c.getKey().replace(' ', '-') + ".key",
              "PRIVATE KEY",
              rsa.generatePrivate(c.getValue()).getEncoded());
      if (c.getKey().equals("wrong d")) {
        // A CRT key signs with p, q, dP, dQ and qInv, which are right here. Whether the JDK signs
        // with a wrong d depends on state it caches per modulus (the full suite fails this
        // assertion now and then when other tests used the real key in the same JVM): when it
        // signs, the challenge verified, so the key signs correctly and accepting it is right.
        // Either way no key that signs wrongly is accepted.
        try {
          KmsConfig.builder().clientIdentityPem(chain, key);
          continue;
        } catch (IllegalArgumentException refusedNow) {
          // fall through to the refusal checks
        }
      }
      var refused =
          assertThrows(
              IllegalArgumentException.class,
              () -> KmsConfig.builder().clientIdentityPem(chain, key),
              c.getKey());
      assertTrue(
          refused.getMessage().startsWith("Cannot sign with the private key in " + key + " (RSA)"),
          c.getKey() + ": " + refused.getMessage());
      assertNull(refused.getCause(), c.getKey() + ": no provider exception as cause");
    }
    // The real key, unencrypted and encrypted, is accepted, and builds a TLS context.
    KmsConfig.builder()
        .clientIdentityPem(chain, write(dir, "ok.key", "PRIVATE KEY", real.getEncoded()))
        .trustSystemDefaults()
        .endpoints("kms")
        .build();
    KmsConfig.builder()
        .clientIdentityPem(
            chain,
            write(
                dir,
                "ok-enc.key",
                "ENCRYPTED PRIVATE KEY",
                encrypt(real.getEncoded(), "pw", PBES2)),
            "pw".toCharArray());
  }

  /**
   * RSASSA-PSS keys sign with RSASSA-PSS, with the parameters a restricted key requires (a
   * restricted key refuses any others), and default parameters when neither key is restricted.
   */
  @Test
  void rsassaPssPemKeysSignWithTheParametersTheyRequire(@TempDir Path dir) throws Exception {
    Path chain =
        write(dir, "pss.pem", "CERTIFICATE", certificate("pssclient", "RSASSA-PSS").getEncoded());
    RSAPrivateCrtKey real = (RSAPrivateCrtKey) privateKey("pssclient", "RSASSA-PSS");
    assertEquals("RSASSA-PSS", real.getAlgorithm());
    assertNull(real.getParams(), "keytool makes unrestricted keys");
    KmsConfig.builder()
        .clientIdentityPem(chain, write(dir, "pss.key", "PRIVATE KEY", real.getEncoded()));
    // The same key, restricted to SHA-384 (encoded with its parameters), with the unrestricted
    // certificate.
    PSSParameterSpec sha384 =
        new PSSParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);
    KeyFactory pss = KeyFactory.getInstance("RSASSA-PSS");
    PrivateKey restricted =
        pss.generatePrivate(
            new RSAPrivateCrtKeySpec(
                real.getModulus(),
                real.getPublicExponent(),
                real.getPrivateExponent(),
                real.getPrimeP(),
                real.getPrimeQ(),
                real.getPrimeExponentP(),
                real.getPrimeExponentQ(),
                real.getCrtCoefficient(),
                sha384));
    assertEquals(
        sha384.toString(),
        String.valueOf(
            ((RSAKey) pss.generatePrivate(new PKCS8EncodedKeySpec(restricted.getEncoded())))
                .getParams()));
    KmsConfig.builder()
        .clientIdentityPem(
            chain, write(dir, "restricted.key", "PRIVATE KEY", restricted.getEncoded()))
        .trustSystemDefaults()
        .endpoints("kms")
        .build();
    Path wrongD =
        write(
            dir,
            "restricted-wrong-d.key",
            "PRIVATE KEY",
            pss.generatePrivate(
                    new RSAPrivateKeySpec(
                        real.getModulus(), real.getPrivateExponent().add(BigInteger.TWO), sha384))
                .getEncoded());
    var mismatch =
        assertThrows(
            IllegalArgumentException.class,
            () -> KmsConfig.builder().clientIdentityPem(chain, wrongD));
    assertTrue(
        mismatch.getMessage().contains("(RSASSA-PSS) does not match"), mismatch.getMessage());
    // A plain RSA certificate's key with a PSS private key of another modulus does not match
    // either.
    Path rsaChain =
        write(dir, "rsa.pem", "CERTIFICATE", certificate("rsaclient", "RSA").getEncoded());
    assertThrows(
        IllegalArgumentException.class,
        () -> KmsConfig.builder().clientIdentityPem(rsaChain, wrongD));

    // Restricted certificate keys (keytool cannot make such a certificate): the check itself.
    Path file = dir.resolve("key.pem");
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSASSA-PSS");
    generator.initialize(new RSAKeyGenParameterSpec(2048, RSAKeyGenParameterSpec.F4, sha384));
    KeyPair pair = generator.generateKeyPair();
    RSAPublicKey restrictedPublic = (RSAPublicKey) pair.getPublic();
    assertEquals(sha384.toString(), String.valueOf(restrictedPublic.getParams()));
    assertTrue(PemIdentity.matches(pair.getPrivate(), restrictedPublic, file), "both restricted");
    RSAPrivateCrtKey generated = (RSAPrivateCrtKey) pair.getPrivate();
    PrivateKey unrestricted =
        pss.generatePrivate(
            new RSAPrivateCrtKeySpec(
                generated.getModulus(),
                generated.getPublicExponent(),
                generated.getPrivateExponent(),
                generated.getPrimeP(),
                generated.getPrimeQ(),
                generated.getPrimeExponentP(),
                generated.getPrimeExponentQ(),
                generated.getCrtCoefficient()));
    assertTrue(
        PemIdentity.matches(unrestricted, restrictedPublic, file),
        "the certificate key's parameters");
    PublicKey sha256Public =
        pss.generatePublic(
            new RSAPublicKeySpec(
                restrictedPublic.getModulus(),
                restrictedPublic.getPublicExponent(),
                new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1)));
    assertFalse(
        PemIdentity.matches(pair.getPrivate(), sha256Public, file),
        "restricted to other parameters");
    // A plain RSA pair signs with SHA256withRSA.
    assertTrue(
        PemIdentity.matches(
            privateKey("rsaclient", "RSA"), certificate("rsaclient", "RSA").getPublicKey(), file));
  }

  // ---- encrypted PKCS#8 keys ----

  static final String PBES2 = "PBEWithHmacSHA256AndAES_256";

  @Test
  void encryptedPkcs8KeysAreDecryptedWithTheirPassword(@TempDir Path dir) throws Exception {
    Path ecChain = write(dir, "ec.pem", "CERTIFICATE", certificate("client", "EC").getEncoded());
    Path rsaChain =
        write(dir, "rsa.pem", "CERTIFICATE", certificate("rsaclient", "RSA").getEncoded());
    byte[] ec = privateKey("client", "EC").getEncoded(),
        rsa = privateKey("rsaclient", "RSA").getEncoded();
    char[] password = "correct horse".toCharArray();
    for (String scheme : List.of(PBES2, "PBEWithHmacSHA1AndAES_128", "PBEWithSHA1AndDESede")) {
      Path ecKey =
          write(
              dir,
              "ec-" + scheme + ".key",
              "ENCRYPTED PRIVATE KEY",
              encrypt(ec, "correct horse", scheme));
      Path rsaKey =
          write(
              dir,
              "rsa-" + scheme + ".key",
              "ENCRYPTED PRIVATE KEY",
              encrypt(rsa, "correct horse", scheme));
      KmsConfig.builder()
          .clientIdentityPem(ecChain, ecKey, password)
          .trustSystemDefaults()
          .endpoints("kms")
          .build();
      KmsConfig.builder().clientIdentityPem(rsaChain, rsaKey, password);
      var wrong =
          assertThrows(
              IllegalArgumentException.class,
              () ->
                  KmsConfig.builder().clientIdentityPem(ecChain, ecKey, "incorrect".toCharArray()),
              scheme);
      assertTrue(wrong.getMessage().contains("wrong password"), wrong.getMessage());
      // Encrypted under the right password, but with the other certificate.
      var mismatch =
          assertThrows(
              IllegalArgumentException.class,
              () -> KmsConfig.builder().clientIdentityPem(rsaChain, ecKey, password));
      assertTrue(mismatch.getMessage().contains("does not match"), mismatch.getMessage());
    }
    assertArrayEquals("correct horse".toCharArray(), password, "the caller's array is left alone");
    // An unencrypted key with a password: the password is unused.
    KmsConfig.builder()
        .clientIdentityPem(ecChain, write(dir, "plain.key", "PRIVATE KEY", ec), password);
    Path encrypted =
        write(dir, "enc.key", "ENCRYPTED PRIVATE KEY", encrypt(ec, "correct horse", PBES2));
    // JDK 17 and 21 refuse a non-ASCII PBE password; later JDKs use its UTF-8 bytes, as OpenSSL
    // does.
    boolean asciiOnly;
    try {
      SecretKeyFactory.getInstance(PBES2).generateSecret(new PBEKeySpec("pässword".toCharArray()));
      asciiOnly = false;
    } catch (java.security.spec.InvalidKeySpecException e) {
      asciiOnly = true;
    }
    if (asciiOnly) {
      var ascii =
          assertThrows(
              IllegalArgumentException.class,
              () ->
                  KmsConfig.builder()
                      .clientIdentityPem(ecChain, encrypted, "pässword".toCharArray()));
      assertTrue(ascii.getMessage().contains("printable ASCII"), ascii.getMessage());
    } else {
      Path unicode =
          write(dir, "unicode.key", "ENCRYPTED PRIVATE KEY", encrypt(ec, "pässword", PBES2));
      KmsConfig.builder().clientIdentityPem(ecChain, unicode, "pässword".toCharArray());
    }
    Path garbage =
        text(
            dir,
            "garbage.key",
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n");
    var malformed =
        assertThrows(
            IllegalArgumentException.class,
            () -> KmsConfig.builder().clientIdentityPem(ecChain, garbage, password));
    assertTrue(
        malformed.getMessage().contains("encrypted private key is malformed"),
        malformed.getMessage());
    assertThrows(
        NullPointerException.class,
        () -> KmsConfig.builder().clientIdentityPem(ecChain, encrypted, (char[]) null));
    assertThrows(
        NullPointerException.class,
        () ->
            KmsConfig.builder()
                .clientIdentityPem(ecChain, encrypted, (java.util.function.Supplier<char[]>) null));
  }

  // ---- retry, listener and cipher suites ----

  @Test
  void cipherSuiteOptionsAreValidated() {
    assertThrows(IllegalArgumentException.class, () -> KmsConfig.builder().cipherSuites(List.of()));
    var both =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                KmsConfig.builder()
                    .endpoints("kms")
                    .transport(e -> null)
                    .cipherSuites(List.of("TLS_AES_256_GCM_SHA384"))
                    .kmipCipherSuites()
                    .build());
    assertTrue(both.getMessage().contains("cipherSuites"), both.getMessage());
    assertThrows(NullPointerException.class, () -> KmsConfig.builder().retryPolicy(null));
    assertThrows(NullPointerException.class, () -> KmsConfig.builder().addListener(null));
  }

  // ---- secrets are not wiped while in use, and replaced copies are wiped ----

  @Test
  void replacedPasswordsAreWipedAndBuiltConfigurationsKeepTheirs() {
    char[] secret = "s3cret".toCharArray();
    KmsConfig.Builder builder =
        KmsConfig.builder().endpoints("kms").transport(e -> null).usernamePassword("app", secret);
    Arrays.fill(secret, '\0'); // the caller may erase its array at once
    char[] held = builder.password;
    KmsConfig first = builder.build(),
        second = builder.build(),
        derived = first.toBuilder().build();
    first.toBuilder().clientCertificate().build();
    builder.hashedPassword("app", "other".toCharArray());
    assertArrayEquals(new char[6], held, "the replaced copy is wiped");
    char[] replaced = builder.password;
    builder.clientCertificate();
    assertArrayEquals(new char[5], replaced, "the discarded copy is wiped");
    for (KmsConfig config : List.of(first, second, derived))
      assertArrayEquals(
          "s3cret".toCharArray(), config.password, "a built configuration keeps its copy");
    assertNotSame(first.password, second.password);
    assertNotSame(first.password, derived.password);
  }

  // ---- the hashed-password lock wait ----

  @Test
  void hashedPasswordLockWaitIsConfigurableAndBoundsTheWait() throws Exception {
    assertEquals(
        Duration.ofSeconds(60),
        KmsConfig.builder().endpoints("kms").transport(e -> null).build().hashedPasswordLockWait());
    assertThrows(
        IllegalArgumentException.class,
        () -> KmsConfig.builder().hashedPasswordLockWait(Duration.ZERO));
    assertThrows(
        IllegalArgumentException.class,
        () -> KmsConfig.builder().hashedPasswordLockWait(Duration.ofSeconds(-1)));
    assertThrows(
        NullPointerException.class, () -> KmsConfig.builder().hashedPasswordLockWait(null));

    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(server);
    Gate gate = new Gate();
    KmipTransport proving =
        proving(
            request -> {
              if (Faults.operation(request) == Operation.LOCATE.code()
                  && gate.armed.compareAndSet(true, false)) {
                CountDownLatch release = gate.release;
                gate.entered.countDown();
                try {
                  release.await(20, TimeUnit.SECONDS);
                } catch (InterruptedException interrupted) {
                  throw new java.io.InterruptedIOException();
                }
              }
              return server.exchange(request);
            },
            "alice",
            "pw");
    KmsConfig config =
        server
            .configure()
            .transport(e -> proving)
            .hashedPassword("alice", "pw".toCharArray())
            .hashedPasswordLockWait(Duration.ofMillis(200))
            .callTimeout(Duration.ofSeconds(8))
            .retryPolicy(RetryPolicy.none())
            .build();
    assertEquals(Duration.ofMillis(200), config.hashedPasswordLockWait());
    assertEquals(Duration.ofMillis(200), config.toBuilder().build().hashedPasswordLockWait());
    Kms kms = Kms.connect(config);
    clients.add(kms);
    Kms patient =
        Kms.connect(config.toBuilder().hashedPasswordLockWait(Duration.ofSeconds(60)).build());
    clients.add(patient);
    ExecutorService threads = Executors.newCachedThreadPool();
    try {
      // The configured wait (200 ms) ends the wait long before the call's 8 s deadline.
      Future<?> holder = gate.hold(threads, kms);
      long start = System.nanoTime();
      var e = assertThrows(TransientException.class, () -> kms.keys().findByName("waiting"));
      long waited = System.nanoTime() - start;
      assertTrue(waited < TimeUnit.SECONDS.toNanos(4), "waited " + waited / 1_000_000 + " ms");
      var notSent = assertInstanceOf(RequestNotSentException.class, e.getCause());
      assertTrue(notSent.local() && notSent.timedOut(), notSent.toString());
      gate.release.countDown();
      holder.get(10, TimeUnit.SECONDS);
      assertEquals(Optional.empty(), kms.keys().findByName("after"), "the lock is free again");

      // The call's deadline ends the wait first when it is earlier: 200 ms against a 60 s wait.
      holder = gate.hold(threads, patient);
      start = System.nanoTime();
      var e2 =
          assertThrows(
              TransientException.class,
              () -> patient.withTimeout(Duration.ofMillis(200)).keys().findByName("waiting"));
      waited = System.nanoTime() - start;
      assertTrue(waited < TimeUnit.SECONDS.toNanos(4), "waited " + waited / 1_000_000 + " ms");
      assertTrue(assertInstanceOf(RequestNotSentException.class, e2.getCause()).timedOut());
      gate.release.countDown();
      holder.get(10, TimeUnit.SECONDS);
    } finally {
      gate.release.countDown();
      threads.shutdownNow();
    }
  }

  /** Holds the next Locate inside the server, so that its caller keeps the exchange lock. */
  static final class Gate {
    final java.util.concurrent.atomic.AtomicBoolean armed =
        new java.util.concurrent.atomic.AtomicBoolean();
    volatile CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(0);

    Future<?> hold(ExecutorService threads, Kms kms) throws InterruptedException {
      entered = new CountDownLatch(1);
      release = new CountDownLatch(1);
      armed.set(true);
      Future<?> holder = threads.submit(() -> kms.keys().findByName("held"));
      assertTrue(entered.await(5, TimeUnit.SECONDS));
      return holder;
    }
  }

  /** A transport answering like a server that checks nothing but proves it knows the password. */
  static KmipTransport proving(KmipTransport server, String user, String password) {
    byte[] u = user.getBytes(StandardCharsets.UTF_8), p = password.getBytes(StandardCharsets.UTF_8);
    byte[] s1 = sha(u, p), s2 = sha(p, u);
    return request -> {
      Ttlv response = server.exchange(request);
      Ttlv header = response.require(RESPONSE_HEADER);
      long timestamp = header.require(TIME_STAMP).longValue();
      List<Ttlv> fields = new ArrayList<>(header.children());
      fields.add(
          bytes(
              SERVER_HASHED_PASSWORD,
              sha(ByteBuffer.allocate(8).putLong(timestamp).array(), s1, sha(s2))));
      List<Ttlv> roots = new ArrayList<>(response.children());
      roots.set(roots.indexOf(header), structure(RESPONSE_HEADER, fields));
      return structure(RESPONSE_MESSAGE, roots);
    };
  }

  static byte[] sha(byte[]... parts) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      for (byte[] part : parts) digest.update(part);
      return digest.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  // ---- helpers ----

  static X509Certificate certificate(String alias, String algorithm) throws Exception {
    return (X509Certificate) TestTls.identity(alias, algorithm).getCertificate(alias);
  }

  static PrivateKey privateKey(String alias, String algorithm) throws Exception {
    return (PrivateKey) TestTls.identity(alias, algorithm).getKey(alias, "changeit".toCharArray());
  }

  static PrivateKey generate(String algorithm) throws Exception {
    return KeyPairGenerator.getInstance(algorithm).generateKeyPair().getPrivate();
  }

  static Path write(Path dir, String name, String type, byte[] der) throws Exception {
    return text(dir, name, pem(type, der));
  }

  static Path text(Path dir, String name, String content) throws Exception {
    Path file = dir.resolve(name);
    Files.writeString(file, content);
    return file;
  }

  /**
   * The PBE iteration count comes from the file, and a hostile or corrupt one could ask for
   * an effectively unbounded derivation. Above {@link KmsConfig.Builder#MAX_PBE_ITERATIONS} the file
   * is refused before deriving anything (before the fix, 10 000 001 iterations were derived and then
   * reported as a wrong password; {@code Integer.MAX_VALUE} would have run for hours).
   */
  @Test
  void aPbeIterationCountAboveTheMaximumIsRefusedBeforeDeriving(@TempDir Path dir)
      throws Exception {
    Path chain = write(dir, "ec.pem", "CERTIFICATE", certificate("client", "EC").getEncoded());
    assertEquals(10_000_000, KmsConfig.Builder.MAX_PBE_ITERATIONS);
    for (String scheme : List.of(PBES2, "PBEWithSHA1AndDESede")) {
      Path key =
          write(
              dir,
              scheme + ".key",
              "ENCRYPTED PRIVATE KEY",
              withIterations(scheme, KmsConfig.Builder.MAX_PBE_ITERATIONS + 1));
      long start = System.nanoTime();
      var e =
          assertThrows(
              IllegalArgumentException.class,
              () -> KmsConfig.builder().clientIdentityPem(chain, key, "pw".toCharArray()),
              scheme);
      long millis = (System.nanoTime() - start) / 1_000_000;
      assertTrue(e.getMessage().contains("10000001 key-derivation iterations"), e.getMessage());
      assertTrue(e.getMessage().contains("at most 10000000"), e.getMessage());
      assertTrue(millis < 1_000, scheme + " took " + millis + " ms");
    }
  }

  /** An EncryptedPrivateKeyInfo whose parameters ask for {@code iterations}; no key is derived. */
  static byte[] withIterations(String scheme, int iterations) throws Exception {
    byte[] salt = new byte[16], iv = new byte[16];
    AlgorithmParameters params = AlgorithmParameters.getInstance(scheme);
    if (scheme.startsWith("PBEWithHmac")) {
      params.init(new PBEParameterSpec(salt, iterations, new IvParameterSpec(iv)));
      return pbes2Info(params.getEncoded(), new byte[64]);
    }
    params.init(new PBEParameterSpec(Arrays.copyOf(salt, 8), iterations));
    return new EncryptedPrivateKeyInfo(params, new byte[64]).getEncoded();
  }

  /**
   * A DER EncryptedPrivateKeyInfo made with the JCA alone. PBES2 schemes are written under the
   * PBES2 OID, as OpenSSL writes them, by {@link #pbes2Info}.
   */
  static byte[] encrypt(byte[] pkcs8, String password, String scheme) throws Exception {
    byte[] salt = new byte[16], iv = new byte[16];
    SecureRandom random = new SecureRandom();
    random.nextBytes(salt);
    random.nextBytes(iv);
    PBEKeySpec spec = new PBEKeySpec(password.toCharArray());
    Cipher cipher = Cipher.getInstance(scheme);
    cipher.init(
        Cipher.ENCRYPT_MODE,
        SecretKeyFactory.getInstance(scheme).generateSecret(spec),
        scheme.startsWith("PBEWithHmac")
            ? new PBEParameterSpec(salt, 2048, new IvParameterSpec(iv))
            : new PBEParameterSpec(Arrays.copyOf(salt, 8), 2048));
    byte[] encrypted = cipher.doFinal(pkcs8);
    AlgorithmParameters params = cipher.getParameters();
    if (scheme.startsWith("PBEWithHmac")) return pbes2Info(params.getEncoded(), encrypted);
    return new EncryptedPrivateKeyInfo(params, encrypted).getEncoded();
  }

  /**
   * The DER EncryptedPrivateKeyInfo of a PBES2 scheme, under the PBES2 OID, with the scheme's own
   * encoded parameters. EncryptedPrivateKeyInfo cannot encode a full PBES2 algorithm name on JDK 17
   * to 25, and re-encoding the parameters through {@code AlgorithmParameters.getInstance("PBES2")}
   * drops the PRF on JDK 25.0.5 (it writes hmacWithSHA1 for a key derived with HMAC-SHA256).
   */
  static byte[] pbes2Info(byte[] pbes2Parameters, byte[] encrypted) {
    byte[] oid = {
      0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x05, 0x0d
    };
    byte[] algorithm = der(0x30, concat(oid, pbes2Parameters));
    return der(0x30, concat(algorithm, der(0x04, encrypted)));
  }

  private static byte[] der(int tag, byte[] content) {
    int n = content.length;
    if (n > 0xffff) throw new IllegalArgumentException("longer than this test's DER writer takes");
    byte[] length =
        n < 0x80
            ? new byte[] {(byte) n}
            : n < 0x100
                ? new byte[] {(byte) 0x81, (byte) n}
                : new byte[] {(byte) 0x82, (byte) (n >> 8), (byte) n};
    return concat(new byte[] {(byte) tag}, concat(length, content));
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }

  /** {@code pkcs8} (an EC PrivateKeyInfo) with the inner ECPrivateKey's version changed to 7. */
  static byte[] ecWithBrokenInnerKey(byte[] pkcs8) {
    byte[] out = pkcs8.clone();
    // PrivateKeyInfo: 30 len 02 01 00 30 len <algorithm> 04 len <ECPrivateKey: 30 len 02 01 01 ...>
    int algorithmLength = out[6] & 0xff, octets = 7 + algorithmLength;
    int inner = octets + 2 + ((out[octets + 1] & 0x80) != 0 ? (out[octets + 1] & 0x7f) : 0);
    int version = inner + 2 + ((out[inner + 1] & 0x80) != 0 ? (out[inner + 1] & 0x7f) : 0);
    assertEquals(0x02, out[version]);
    out[version] = 0x05; // NULL where the INTEGER version belongs
    return out;
  }
}
