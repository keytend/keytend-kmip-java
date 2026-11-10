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
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.InMemoryTlsListenerTest.Pki;
import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.TlsListener;
import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.pkcs.PKCS12PfxPduBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS12SafeBagBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCS12MacCalculatorBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * JKS and PKCS#12 key store files on {@link KmsConfig.Builder}: client identities ({@code
 * clientIdentityKeyStore}, either format), JKS and PKCS#12 trust stores ({@code trustStore(Path, ...)}) and {@link
 * KmsConfig#sslContextFromKeyStores}, over mutual TLS to the in-memory server's {@link
 * TlsListener}; their validation and messages, which never quote a password; passwords as arrays
 * (copied, wiped when replaced) or suppliers (asked at each read, each array wiped); and their
 * reload with {@code reloadOnChange}, as the PEM and PKCS#12 files reload.
 */
class TlsKeyStoreFilesTest {
  static final String SECRET = "store-secret-1";

  static char[] password() {
    return SECRET.toCharArray();
  }

  /** A key store of {@code type} with one key entry per identity, each with its chain to the CA. */
  static byte[] identityStore(String type, char[] password, Issued ca, Issued... identities)
      throws Exception {
    KeyStore store = KeyStore.getInstance(type);
    store.load(null, null);
    int i = 0;
    for (Issued id : identities)
      store.setKeyEntry(
          "id" + i++, id.key(), password, new Certificate[] {id.certificate(), ca.certificate()});
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    store.store(out, password);
    return out.toByteArray();
  }

  /** A trust store of {@code type}, as keytool -importcert makes it: trusted certificate entries. */
  static byte[] trustStore(String type, char[] password, X509Certificate... trusted)
      throws Exception {
    KeyStore store = KeyStore.getInstance(type);
    store.load(null, null);
    int i = 0;
    for (X509Certificate c : trusted) store.setCertificateEntry("ca" + i++, c);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    store.store(out, password);
    return out.toByteArray();
  }

  /** Writes {@code data} under another name and renames it into place, as the guides ask. */
  static Path publish(Path file, byte[] data) throws Exception {
    Path next = file.resolveSibling(file.getFileName() + ".next");
    Files.write(next, data);
    Files.move(next, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    return file;
  }

  static String message(Runnable call) {
    IllegalArgumentException e = assertThrows(IllegalArgumentException.class, call::run);
    assertEquals(IllegalArgumentException.class, e.getClass(), "a plain IllegalArgumentException");
    assertFalse(e.getMessage().contains(SECRET), "never the password: " + e.getMessage());
    return e.getMessage();
  }

  @ParameterizedTest
  @CsvSource({
    "JKS, JKS, array",
    "JKS, PKCS12, supplier",
    "PKCS12, JKS, supplier",
    "PKCS12, PKCS12, array",
    "JKS, PEM, array",
    "PKCS12, PEM, supplier"
  })
  void keyStoreFilesConnectOverMutualTls(
      String identityType, String trustType, String passwords, @TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Path identity =
        publish(
            dir.resolve("client." + identityType),
            identityStore(identityType, password(), pki.ca, pki.client));
    Path trust =
        trustType.equals("PEM")
            ? pki.caPem
            : publish(
                dir.resolve("trust." + trustType),
                trustStore(trustType, password(), pki.ca.certificate()));
    List<char[]> handed = new CopyOnWriteArrayList<>();
    Supplier<char[]> supplier =
        () -> {
          char[] p = password();
          handed.add(p);
          return p;
        };
    boolean supplied = passwords.equals("supplier");
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig.Builder b = tls.configure();
      if (supplied) b.clientIdentityKeyStore(identity, supplier);
      else b.clientIdentityKeyStore(identity, password());
      if (trustType.equals("PEM")) b.trustPem(trust);
      else if (supplied) b.trustStore(trust, supplier);
      else b.trustStore(trust, password());
      KmsConfig config = b.build();
      assertFalse(config.toString().contains(SECRET), config.toString());
      try (Kms kms = Kms.connect(config)) {
        kms.ping();
      }
      assertEquals(List.of(pki.client.certificate()), tls.clientCertificates());
      if (supplied) {
        assertEquals(trustType.equals("PEM") ? 1 : 2, handed.size(), "asked once per file read");
        for (char[] p : handed) assertArrayEquals(new char[p.length], p, "wiped after use");
      }

      // The factory, for a supplier of contexts of your own.
      if (!trustType.equals("PEM")) {
        SSLContext context =
            KmsConfig.sslContextFromKeyStores(identity, password(), trust, password());
        try (Kms kms = Kms.connect(tls.configure().tls(context).build())) {
          kms.ping();
        }
        assertEquals(2, tls.clientCertificates().size());
      }
    }
  }

  @Test
  void theFilesAreValidatedWithMessagesThatNameTheFileAndNeverThePassword(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    Issued second = TestPki.leaf("second", TestPki.ec(), pki.ca);
    Path jks =
        publish(dir.resolve("client.jks"), identityStore("JKS", password(), pki.ca, pki.client));
    Path p12 =
        publish(dir.resolve("client.p12"), identityStore("PKCS12", password(), pki.ca, pki.client));
    Path jksTrust =
        publish(dir.resolve("trust.jks"), trustStore("JKS", password(), pki.ca.certificate()));
    Path p12Trust =
        publish(dir.resolve("trust.p12"), trustStore("PKCS12", password(), pki.ca.certificate()));
    char[] wrong = "not-it".toCharArray();

    // Wrong passwords.
    String m = message(() -> KmsConfig.builder().clientIdentityKeyStore(jks, wrong));
    assertTrue(
        m.contains("Cannot read the JKS key store " + jks) && m.contains("wrong password"), m);
    m = message(() -> KmsConfig.builder().trustStore(jksTrust, wrong));
    assertTrue(
        m.contains("Cannot read the JKS key store " + jksTrust) && m.contains("wrong password"), m);
    m = message(() -> KmsConfig.builder().trustStore(p12Trust, wrong));
    assertTrue(
        m.contains("Cannot read the PKCS#12 file " + p12Trust) && m.contains("wrong password"), m);
    m = message(() -> KmsConfig.builder().clientIdentityKeyStore(p12, wrong));
    assertTrue(m.contains(p12.toString()) && m.contains("wrong password"), m);

    // The format is told from the contents: one method reads either, as trustStore does. The
    // PKCS#12-only sslContextFromPkcs12 names the methods that read a JKS key store.
    KmsConfig.builder().clientIdentityKeyStore(jks, password());
    KmsConfig.builder().clientIdentityKeyStore(p12, password());
    m = message(() -> KmsConfig.sslContextFromPkcs12(jks, password(), pki.caPem));
    assertTrue(
        m.contains(
            jks
                + " is a JKS key store, not a PKCS#12 file: use KmsConfig.sslContextFromKeyStores"
                + " or clientIdentityKeyStore"),
        m);
    m = message(() -> KmsConfig.builder().trustStore(pki.caPem, password()));
    assertTrue(m.contains(pki.caPem + " is a PEM file, not a trust store: use trustPem"), m);
    m = message(() -> KmsConfig.builder().clientIdentityKeyStore(pki.clientKey, password()));
    assertTrue(m.contains("is a PEM file, not a key store: use clientIdentityPem"), m);
    Path jceks =
        publish(dir.resolve("old.jceks"), trustStore("JCEKS", password(), pki.ca.certificate()));
    m = message(() -> KmsConfig.builder().trustStore(jceks, password()));
    assertTrue(m.contains(jceks + " is a JCEKS key store, which is not supported"), m);
    Path garbage =
        publish(
            dir.resolve("garbage"),
            "not a key store at all".getBytes(java.nio.charset.StandardCharsets.US_ASCII));
    m = message(() -> KmsConfig.builder().trustStore(garbage, password()));
    assertTrue(m.contains(garbage + " is neither a JKS key store nor a PKCS#12 file"), m);
    Path missing = dir.resolve("missing.jks");
    m = message(() -> KmsConfig.builder().clientIdentityKeyStore(missing, password()));
    assertTrue(m.contains("Cannot read the key store " + missing), m);

    // What the files hold.
    Path two =
        publish(
            dir.resolve("two.jks"), identityStore("JKS", password(), pki.ca, pki.client, second));
    m = message(() -> KmsConfig.builder().clientIdentityKeyStore(two, password()));
    assertTrue(m.contains(two + " holds 2 private keys; exactly one is needed"), m);
    Path noTrusted =
        publish(
            dir.resolve("keys-only.p12"), identityStore("PKCS12", password(), pki.ca, pki.client));
    m = message(() -> KmsConfig.builder().trustStore(noTrusted, password()));
    assertTrue(m.contains(noTrusted + " holds no trusted certificate entry"), m);
    Path openssl =
        publish(dir.resolve("openssl.p12"), opensslTrustStore(pki.ca.certificate(), password()));
    m = message(() -> KmsConfig.builder().trustStore(openssl, password()));
    assertTrue(m.contains("a PKCS#12 file made by openssl marks none trusted for Java"), m);
    // A key that is not its certificate's.
    KeyStore mismatched = KeyStore.getInstance("JKS");
    mismatched.load(null, null);
    mismatched.setKeyEntry(
        "client", second.key(), password(), new Certificate[] {pki.client.certificate()});
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    mismatched.store(bytes, password());
    Path wrongKey = publish(dir.resolve("mismatch.jks"), bytes.toByteArray());
    m = message(() -> KmsConfig.builder().clientIdentityKeyStore(wrongKey, password()));
    assertTrue(m.contains("does not match the first certificate of its chain"), m);
    // A key under another password than the store's.
    KeyStore other = KeyStore.getInstance("JKS");
    other.load(null, null);
    other.setKeyEntry(
        "client",
        pki.client.key(),
        "key-pw".toCharArray(),
        new Certificate[] {pki.client.certificate()});
    bytes.reset();
    other.store(bytes, password());
    Path keyPassword = publish(dir.resolve("keypw.jks"), bytes.toByteArray());
    m = message(() -> KmsConfig.builder().clientIdentityKeyStore(keyPassword, password()));
    assertTrue(
        m.contains("Cannot use the private key in " + keyPassword + " (wrong password?)"), m);

    // The factory refuses what the builder refuses.
    m = message(() -> KmsConfig.sslContextFromKeyStores(jks, wrong, jksTrust, password()));
    assertTrue(m.contains("wrong password"), m);
    m = message(() -> KmsConfig.sslContextFromKeyStores(jks, password(), noTrusted, password()));
    assertTrue(m.contains("holds no trusted certificate entry"), m);
    assertThrows(
        NullPointerException.class,
        () -> KmsConfig.sslContextFromKeyStores(null, wrong, jksTrust, wrong));
    assertThrows(
        NullPointerException.class,
        () -> KmsConfig.sslContextFromKeyStores(jks, null, jksTrust, wrong));
    assertThrows(
        NullPointerException.class,
        () -> KmsConfig.sslContextFromKeyStores(jks, wrong, null, wrong));
    assertThrows(
        NullPointerException.class,
        () -> KmsConfig.sslContextFromKeyStores(jks, wrong, jksTrust, null));
    assertThrows(
        NullPointerException.class, () -> KmsConfig.builder().trustStore(jksTrust, (char[]) null));
    assertThrows(
        NullPointerException.class,
        () -> KmsConfig.builder().trustStore(jksTrust, (Supplier<char[]>) null));
    assertThrows(
        NullPointerException.class,
        () -> KmsConfig.builder().clientIdentityKeyStore(null, password()));
    assertThrows(
        NullPointerException.class,
        () -> KmsConfig.builder().clientIdentityKeyStore(jks, (char[]) null));
    assertThrows(
        NullPointerException.class,
        () -> KmsConfig.builder().clientIdentityKeyStore(jks, (Supplier<char[]>) null));
    assertThrows(
        NullPointerException.class,
        () -> KmsConfig.builder().clientIdentityKeyStore(p12, (Supplier<char[]>) null));
  }

  /** A PKCS#12 trust store as {@code openssl pkcs12 -export -nokeys} makes it: no Java trust. */
  static byte[] opensslTrustStore(X509Certificate certificate, char[] password) throws Exception {
    PKCS12PfxPduBuilder pfx = new PKCS12PfxPduBuilder();
    pfx.addData(new JcaPKCS12SafeBagBuilder(certificate).build());
    return pfx.build(
            new JcePKCS12MacCalculatorBuilder()
                .setProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider()),
            password)
        .getEncoded(ASN1Encoding.DER);
  }

  /**
   * A key store cut anywhere is not whole: refused as one still being written, never parsed as a
   * smaller store, for a JKS identity and a JKS and a PKCS#12 trust store.
   */
  @Test
  void aKeyStoreCutShortIsRefusedWhereverItIsCut(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    byte[] jks = identityStore("JKS", password(), pki.ca, pki.client);
    byte[] jksTrust = trustStore("JKS", password(), pki.ca.certificate(), pki.server.certificate());
    byte[] p12Trust = trustStore("PKCS12", password(), pki.ca.certificate());
    Path file = dir.resolve("cut");
    for (int length = 0; length < jks.length; length++) {
      publish(file, Arrays.copyOf(jks, length));
      String m = message(() -> KmsConfig.builder().clientIdentityKeyStore(file, password()));
      // Too short to tell the format: a key store; then the format it starts as.
      String what = length < 4 ? "key store" : "JKS key store";
      assertTrue(
          m.equals(file + " is not a whole " + what + " (cut short, or still being written?)"),
          length + ": " + m);
    }
    for (int length = 0; length < jksTrust.length; length++) {
      publish(file, Arrays.copyOf(jksTrust, length));
      String m = message(() -> KmsConfig.builder().trustStore(file, password()));
      assertTrue(m.contains(" is not a whole "), length + ": " + m);
    }
    for (int length = 0; length < p12Trust.length; length++) {
      publish(file, Arrays.copyOf(p12Trust, length));
      String m = message(() -> KmsConfig.builder().trustStore(file, password()));
      assertTrue(m.contains(" is not a whole "), length + ": " + m);
    }
    // Whole, with bytes after it: read as the key store says (JKS ignores them).
    publish(file, Arrays.copyOf(jks, jks.length + 3));
    KmsConfig.builder().clientIdentityKeyStore(file, password());
    assertEquals(jks.length, KeyStoreFiles.jksEnd(jks));
    // A version or entry this walk does not know is left to the key store, which refuses it.
    byte[] version3 = jks.clone();
    version3[7] = 3;
    assertEquals(version3.length, KeyStoreFiles.jksEnd(version3));
    publish(file, version3);
    String m = message(() -> KmsConfig.builder().clientIdentityKeyStore(file, password()));
    assertTrue(m.contains("Cannot read the JKS key store"), m);
  }

  @Test
  void suppliersAreAskedAtEachReadAndTheirFailuresNameTheFileNotTheirMessage(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    Path jks =
        publish(dir.resolve("client.jks"), identityStore("JKS", password(), pki.ca, pki.client));
    IllegalStateException vault = new IllegalStateException("vault says: " + SECRET);
    String m =
        message(
            () ->
                KmsConfig.builder()
                    .clientIdentityKeyStore(
                        jks,
                        () -> {
                          throw vault;
                        }));
    assertEquals(
        "The password supplier for " + jks + " failed (java.lang.IllegalStateException)", m);
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                KmsConfig.builder()
                    .trustStore(
                        jks,
                        () -> {
                          throw vault;
                        }));
    assertSame(vault, e.getCause(), "the supplier's failure is the cause");
    m = message(() -> KmsConfig.builder().clientIdentityKeyStore(jks, () -> null));
    assertEquals("The password supplier for " + jks + " returned null", m);
    Path key = dir.resolve("enc.key");
    Files.writeString(
        key,
        pem(
            "ENCRYPTED PRIVATE KEY",
            KmsConfigValidationTest.encrypt(
                pki.client.key().getEncoded(), SECRET, KmsConfigValidationTest.PBES2)));
    m = message(() -> KmsConfig.builder().clientIdentityPem(pki.clientChain, key, () -> null));
    assertEquals("The password supplier for " + key + " returned null", m);

    // The same array twice: the second read would get it wiped, and is refused.
    char[] fixed = password();
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("localhost:1")
            .clientIdentityKeyStore(jks, () -> fixed)
            .trustPem(pki.caPem)
            .reloadOnChange(Duration.ofMillis(1))
            .build();
    assertArrayEquals(new char[fixed.length], fixed, "wiped after the first read");
    List<String> events = new CopyOnWriteArrayList<>();
    TlsFiles.Reloading reloading = recording(config, events);
    publish(jks, identityStore("JKS", password(), pki.ca, pki.client));
    reloadNow(reloading, events);
    assertEquals(
        List.of(
            "failed: The password supplier for "
                + jks
                + " returned the array it returned before, which was wiped after use: return a"
                + " new array each time"),
        events);

    // An encrypted PEM key with its password from a supplier.
    List<char[]> handed = new CopyOnWriteArrayList<>();
    KmsConfig.Builder b =
        KmsConfig.builder()
            .clientIdentityPem(
                pki.clientChain,
                key,
                () -> {
                  char[] p = password();
                  handed.add(p);
                  return p;
                });
    assertEquals(1, handed.size());
    assertArrayEquals(new char[SECRET.length()], handed.get(0));
    assertNull(b.identityFiles.password(), "a supplier: no copy held");
  }

  /** The events of a reloading source for {@code config}, as {@code reloaded} or {@code failed: why}. */
  static TlsFiles.Reloading recording(KmsConfig config, List<String> events) {
    return config.reloading.start(
        event ->
            event.accept(
                new KmsListener() {
                  @Override
                  public void credentialsReloaded(String files) {
                    events.add("reloaded");
                  }

                  @Override
                  public void credentialsReloadFailed(String files, String why) {
                    events.add("failed: " + why);
                  }

                  @Override
                  public void credentialsStillChanging(String files, Duration changingFor) {
                    events.add("still changing");
                  }
                }));
  }

  /** Checks until the change published is read: the first check may wait for it to settle. */
  static void reloadNow(TlsFiles.Reloading reloading, List<String> events) throws Exception {
    int before = events.size();
    for (int i = 0; i < 10 && events.size() == before; i++) {
      Thread.sleep(5);
      reloading.checkNow();
    }
  }

  @Test
  void jksIdentitiesAndTrustStoresReloadAsPemAndPkcs12Files(@TempDir Path dir) throws Exception {
    Pki pki = new Pki(dir);
    Issued client2 = TestPki.leaf("client2", TestPki.ec(), pki.ca);
    Path jks =
        publish(dir.resolve("client.jks"), identityStore("JKS", password(), pki.ca, pki.client));
    Path trust =
        publish(dir.resolve("trust.p12"), trustStore("PKCS12", password(), pki.ca.certificate()));
    List<char[]> handed = new CopyOnWriteArrayList<>();
    Supplier<char[]> supplier =
        () -> {
          char[] p = password();
          handed.add(p);
          return p;
        };
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TlsListener tls = pki.listener(server).start()) {
      KmsConfig config =
          tls.configure()
              .clientIdentityKeyStore(jks, password())
              .trustStore(trust, supplier)
              .reloadOnChange(Duration.ofMillis(1))
              .build();
      assertEquals(List.of(jks, trust), config.reloading.files());
      assertArrayEquals(password(), config.reloading.identity.password(), "its own copy");
      assertNull(config.reloading.trust.password(), "a supplier: no copy");
      List<String> events = new ArrayList<>();
      TlsFiles.Reloading reloading = recording(config, events);
      SSLContext first = reloading.get();

      // A renewed JKS identity.
      publish(jks, identityStore("JKS", password(), pki.ca, client2));
      reloadNow(reloading, events);
      assertEquals(List.of("reloaded"), events);
      assertNotSame(first, reloading.get());
      try (Kms kms = Kms.connect(tls.configure().tls(reloading).build())) {
        kms.ping();
      }
      assertEquals(List.of(client2.certificate()), tls.clientCertificates());
      for (char[] p : handed) assertArrayEquals(new char[p.length], p, "each wiped after use");
      assertEquals(2, handed.size(), "the trust store's password asked at each whole reload");

      // A trust store cut short is not loaded, nor a whole one with no trusted entry; the context
      // in use stays. A good one then loads.
      SSLContext good = reloading.get();
      byte[] whole = trustStore("PKCS12", password(), pki.ca.certificate(), client2.certificate());
      publish(trust, Arrays.copyOf(whole, whole.length / 2));
      reloadNow(reloading, events);
      assertEquals(
          "failed: " + trust + " is not a whole PKCS#12 file (cut short, or still being written?)",
          events.get(1));
      publish(trust, identityStore("PKCS12", password(), pki.ca, pki.client));
      reloadNow(reloading, events);
      assertTrue(
          events.get(2).contains(trust + " holds no trusted certificate entry"), events.get(2));
      assertSame(good, reloading.get());
      publish(trust, whole);
      reloadNow(reloading, events);
      assertEquals("reloaded", events.get(3));
      for (String event : events) assertFalse(event.contains(SECRET), event);
    }
  }

  /**
   * The builder's copies of the file passwords are its own: the caller may erase its arrays; a
   * replaced one is wiped; a configuration without {@code reloadOnChange} keeps none, and one with
   * it keeps its own, which a later change to the builder does not reach.
   */
  @Test
  void thePasswordCopiesAreWipedWhenReplacedAndKeptOnlyForReloading(@TempDir Path dir)
      throws Exception {
    Pki pki = new Pki(dir);
    Path jks =
        publish(dir.resolve("client.jks"), identityStore("JKS", password(), pki.ca, pki.client));
    Path trust =
        publish(dir.resolve("trust.jks"), trustStore("JKS", password(), pki.ca.certificate()));
    char[] mine = password(), theirs = password();
    KmsConfig.Builder b =
        KmsConfig.builder()
            .endpoints("localhost:1")
            .clientIdentityKeyStore(jks, mine)
            .trustStore(trust, theirs);
    Arrays.fill(mine, '\0');
    Arrays.fill(theirs, '\0');
    KmsConfig fixed = b.build();
    assertNull(fixed.reloading);
    assertNull(fixed.toBuilder().identityFiles, "no file names or password kept");
    KmsConfig kept = b.reloadOnChange().build();
    char[] identityCopy = b.identityFiles.password();
    char[] keptTrust = kept.reloading.trust.password();
    assertArrayEquals(password(), identityCopy);
    assertArrayEquals(password(), keptTrust);
    b.clientIdentityPem(pki.clientChain, pki.clientKey).trustPem(pki.caPem);
    assertArrayEquals(new char[SECRET.length()], identityCopy, "the replaced copy is wiped");
    assertArrayEquals(password(), keptTrust, "the configuration's copy is its own");
    assertArrayEquals(password(), kept.reloading.identity.password());
    // A builder from a reloading configuration keeps its own copy too.
    KmsConfig.Builder again = kept.toBuilder();
    assertNotSame(keptTrust, again.build().reloading.trust.password());
    // The trust store replaced by the system defaults: its copy is wiped.
    KmsConfig.Builder c = KmsConfig.builder().trustStore(trust, password());
    char[] trustCopy = c.trustFile.password();
    assertArrayEquals(password(), trustCopy);
    c.trustSystemDefaults();
    assertArrayEquals(new char[SECRET.length()], trustCopy, "the replaced copy is wiped");
    assertNull(c.trustFile);
  }
}
