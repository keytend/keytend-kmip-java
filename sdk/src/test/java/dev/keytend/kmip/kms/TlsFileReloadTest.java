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
import static dev.keytend.kmip.kms.KmsConfigValidationTest.PBES2;
import static dev.keytend.kmip.kms.KmsConfigValidationTest.encrypt;
import static dev.keytend.kmip.kms.KmsConfigValidationTest.withIterations;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import dev.keytend.kmip.TestAwait;
import dev.keytend.kmip.TestTls;
import dev.keytend.kmip.TestX509;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.TlsListener;
import java.io.OutputStream;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * TLS contexts from PEM and PKCS#12 files: the public factories, which validate as the builder,
 * and {@link KmsConfig.Builder#reloadOnChange}, over real mutual TLS. The server trusts the client
 * certificates {@code client} and {@code client2}; a "renewal" replaces one with the other.
 */
class TlsFileReloadTest {
  private static final char[] STORE_PASSWORD = "changeit".toCharArray();
  private static final Duration EVERY = Duration.ofMillis(100);

  private static SSLContext serverContext() throws Exception {
    return TestTls.context("server", "client", "client2");
  }

  /** The client's files: certificate, key and the CA (the server's self-signed certificate). */
  record Files3(Path chain, Path key, Path ca) {}

  private static Files3 files(Path dir, String identity) throws Exception {
    Files3 f = new Files3(dir.resolve("tls.crt"), dir.resolve("tls.key"), dir.resolve("ca.crt"));
    writeCertificate(f.chain(), identity);
    writeKey(f.key(), identity);
    Files.writeString(f.ca(), pem("CERTIFICATE", TestTls.certificate("server").getEncoded()));
    return f;
  }

  private static void writeCertificate(Path file, String identity) throws Exception {
    Files.writeString(file, pem("CERTIFICATE", TestTls.certificate(identity).getEncoded()));
  }

  private static void writeKey(Path file, String identity) throws Exception {
    Files.writeString(file, pem("PRIVATE KEY", key(identity).getEncoded()));
  }

  private static PrivateKey key(String identity) throws Exception {
    return (PrivateKey) TestTls.identity(identity).getKey(identity, STORE_PASSWORD);
  }

  private static void writePkcs12(Path file, char[] password, String... identities)
      throws Exception {
    KeyStore store = KeyStore.getInstance("PKCS12");
    store.load(null, null);
    for (String id : identities)
      store.setKeyEntry(id, key(id), password, TestTls.identity(id).getCertificateChain(id));
    try (OutputStream out = Files.newOutputStream(file)) {
      store.store(out, password);
    }
  }

  /** The listener events, as {@code reloaded <files>} and {@code failed <files>: <why>}. */
  static final class Events implements KmsListener {
    final List<String> events = new CopyOnWriteArrayList<>();

    @Override
    public void credentialsReloaded(String files) {
      events.add("reloaded " + files);
    }

    @Override
    public void credentialsReloadFailed(String files, String why) {
      events.add("failed " + files + ": " + why);
    }
  }

  /** Makes requests (each one consults the TLS source) until {@code condition} ({@link TestAwait}). */
  private static void requestUntil(Kms kms, BooleanSupplier condition, String what) {
    requestUntil(kms, condition, what, TestAwait.TIMEOUT);
  }

  private static void requestUntil(
      Kms kms, BooleanSupplier condition, String what, Duration within) {
    TestAwait.await(what)
        .atMost(within)
        .until(
            () -> {
              if (condition.getAsBoolean()) return true;
              kms.ping();
              return false;
            });
  }

  private static String message(Runnable call) {
    return assertThrows(IllegalArgumentException.class, call::run).getMessage();
  }

  // ---- the factories ----

  /**
   * The factories accept good PEM files (with an unencrypted and an encrypted key) and a PKCS#12
   * file, and the contexts they make present the client certificate and trust the CA file.
   */
  @Test
  void theFactoriesMakeWorkingContextsFromPemAndPkcs12Files(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    Path encrypted = dir.resolve("enc.key"), p12 = dir.resolve("client.p12");
    Files.writeString(
        encrypted, pem("ENCRYPTED PRIVATE KEY", encrypt(key("client").getEncoded(), "pw", PBES2)));
    writePkcs12(p12, STORE_PASSWORD, "client");
    char[] password = "pw".toCharArray();
    List<SSLContext> contexts =
        List.of(
            KmsConfig.sslContextFromPem(f.chain(), f.key(), f.ca()),
            KmsConfig.sslContextFromPem(f.chain(), encrypted, password, f.ca()),
            KmsConfig.sslContextFromPkcs12(p12, STORE_PASSWORD.clone(), f.ca()));
    Arrays.fill(password, '\0'); // used during the call only
    try (RecordingTlsServer server = new RecordingTlsServer(serverContext())) {
      for (SSLContext context : contexts)
        try (Kms kms =
            Kms.connect(
                KmsConfig.builder().endpoints(server.endpoint()).tls(() -> context).build())) {
          kms.ping();
        }
      assertEquals(List.of("CN=client", "CN=client", "CN=client"), server.peers);
    }
    // The CA file is what is trusted: a server it does not name is refused.
    Path stranger = dir.resolve("stranger.crt");
    writeCertificate(stranger, "stranger");
    SSLContext distrusting = KmsConfig.sslContextFromPem(f.chain(), f.key(), stranger);
    try (RecordingTlsServer server = new RecordingTlsServer(serverContext())) {
      assertThrows(
          PermissionDeniedException.class,
          () ->
              Kms.connect(
                  KmsConfig.builder().endpoints(server.endpoint()).tls(distrusting).build()));
    }
  }

  /**
   * The factories refuse what the builder refuses, with the builder's message: a key that does not
   * match the certificate, an encrypted key without its password or with a PBE iteration count
   * above the cap, a PKCS#12 file with two keys or a wrong password, a missing CA file; and they
   * need every argument (a trust choice included).
   */
  @Test
  void theFactoriesRefuseWhatTheBuilderRefusesWithItsMessages(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    Path otherKey = dir.resolve("other.key"),
        capped = dir.resolve("capped.key"),
        encrypted = dir.resolve("enc.key");
    writeKey(otherKey, "client2");
    Files.writeString(
        capped,
        pem(
            "ENCRYPTED PRIVATE KEY",
            withIterations(PBES2, KmsConfig.Builder.MAX_PBE_ITERATIONS + 1)));
    Files.writeString(
        encrypted, pem("ENCRYPTED PRIVATE KEY", encrypt(key("client").getEncoded(), "pw", PBES2)));
    Path two = dir.resolve("two.p12"), absent = dir.resolve("absent.crt");
    writePkcs12(two, STORE_PASSWORD, "client", "client2");
    char[] pw = "pw".toCharArray();

    String mismatch = message(() -> KmsConfig.sslContextFromPem(f.chain(), otherKey, f.ca()));
    assertTrue(mismatch.contains("does not match the first certificate in " + f.chain()), mismatch);
    assertEquals(
        message(() -> KmsConfig.builder().clientIdentityPem(f.chain(), otherKey)), mismatch);

    String needsPassword = message(() -> KmsConfig.sslContextFromPem(f.chain(), encrypted, f.ca()));
    assertTrue(needsPassword.contains("encrypted private key: pass its password"), needsPassword);
    assertEquals(
        message(() -> KmsConfig.builder().clientIdentityPem(f.chain(), encrypted)), needsPassword);
    String wrongPassword =
        message(
            () -> KmsConfig.sslContextFromPem(f.chain(), encrypted, "nope".toCharArray(), f.ca()));
    assertEquals(
        message(
            () ->
                KmsConfig.builder().clientIdentityPem(f.chain(), encrypted, "nope".toCharArray())),
        wrongPassword);

    long start = System.nanoTime();
    String overCap = message(() -> KmsConfig.sslContextFromPem(f.chain(), capped, pw, f.ca()));
    assertTrue(overCap.contains("10000001 key-derivation iterations"), overCap);
    assertTrue(overCap.contains("at most 10000000"), overCap);
    assertTrue(System.nanoTime() - start < 1_000_000_000L, "refused before deriving");
    assertEquals(
        message(() -> KmsConfig.builder().clientIdentityPem(f.chain(), capped, pw)), overCap);

    String twoKeys = message(() -> KmsConfig.sslContextFromPkcs12(two, STORE_PASSWORD, f.ca()));
    assertEquals(two + " holds 2 private keys; exactly one is needed", twoKeys);
    assertEquals(
        message(() -> KmsConfig.builder().clientIdentityKeyStore(two, STORE_PASSWORD)), twoKeys);
    String badPassword =
        message(() -> KmsConfig.sslContextFromPkcs12(two, "nope".toCharArray(), f.ca()));
    assertTrue(badPassword.contains("Cannot read the PKCS#12 file " + two), badPassword);

    String noCa = message(() -> KmsConfig.sslContextFromPem(f.chain(), f.key(), absent));
    assertEquals(message(() -> KmsConfig.builder().trustPem(absent)), noCa);
    assertTrue(noCa.contains("absent.crt"), noCa);

    for (String m :
        List.of(mismatch, needsPassword, wrongPassword, overCap, twoKeys, badPassword, noCa))
      assertFalse(m.contains("MII") || m.contains("MIG"), "no key material in " + m);

    assertThrows(
        NullPointerException.class, () -> KmsConfig.sslContextFromPem(f.chain(), f.key(), null));
    assertThrows(
        NullPointerException.class,
        () -> KmsConfig.sslContextFromPem(f.chain(), f.key(), null, f.ca()));
    assertThrows(
        NullPointerException.class,
        () -> KmsConfig.sslContextFromPkcs12(two, STORE_PASSWORD, null));
  }

  // ---- reloadOnChange ----

  /**
   * A renewed certificate and key are picked up: the next request after a check connects with the
   * new certificate (the server sees it), the idle connection of the old context is closed, the
   * listener hears of it once, and the new connection is pooled.
   */
  @Test
  void aRenewedCertificateIsUsedByTheNextConnection(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    Events events = new Events();
    try (RecordingTlsServer server = new RecordingTlsServer(serverContext());
        Kms kms =
            Kms.connect(
                KmsConfig.builder()
                    .endpoints(server.endpoint())
                    .clientIdentityPem(f.chain(), f.key())
                    .trustPem(f.ca())
                    .reloadOnChange(EVERY)
                    .addListener(events)
                    .build())) {
      kms.ping();
      kms.ping();
      assertEquals(List.of("CN=client"), server.peers);

      writeCertificate(f.chain(), "client2");
      writeKey(f.key(), "client2");
      requestUntil(kms, () -> server.peers.size() == 2, "the renewed certificate is presented");
      assertEquals(List.of("CN=client", "CN=client2"), server.peers);
      assertEquals(
          List.of("reloaded " + f.chain() + ", " + f.key() + ", " + f.ca()), events.events);
      RecordingTlsServer.await(() -> server.ended.get() == 1, "the old idle connection is closed");

      Thread.sleep(3 * EVERY.toMillis());
      for (int i = 0; i < 5; i++) kms.ping();
      assertEquals(2, server.peers.size(), "the new connection is reused");
      assertEquals(1, events.events.size(), "unchanged files are not loaded again");
    }
  }

  /**
   * cert-manager writes the certificate and the key one after the other. A check that sees the new
   * certificate with the old key fails validation: the previous context stays in use (the pooled
   * connection is reused, nothing new is presented), nothing is reported within the mismatch's
   * grace although the files are read again at each check, and once the key is written too the
   * pair is picked up. The same for a key file only partly written, which is reported. No request
   * fails meanwhile (none is retried). The report of a mismatch that outlasts {@link
   * TlsFiles#MISMATCH_FLOOR}, once, is {@link #aRenewalWrittenOneFileAtATimeIsNotAFailure}'s, on
   * a test clock.
   */
  @Test
  void aMismatchedOrHalfWrittenPairKeepsThePreviousContextUntilBothAreWritten(@TempDir Path dir)
      throws Exception {
    Files3 f = files(dir, "client");
    Events events = new Events();
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("localhost:1")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(EVERY)
            .retryPolicy(RetryPolicy.none()) // a request failing once would show
            .addListener(events)
            .build();
    try (RecordingTlsServer server = new RecordingTlsServer(serverContext());
        Kms kms = Kms.connect(config.toBuilder().endpoints(server.endpoint()).build())) {
      kms.ping();
      // The new certificate, the old key, read at several checks.
      writeCertificate(f.chain(), "client2");
      for (int i = 0; i < 5; i++) {
        Thread.sleep(EVERY.toMillis());
        kms.ping();
      }
      assertEquals(List.of("CN=client"), server.peers, "the previous context is still used");
      assertEquals(List.of(), events.events, "a pair being written is not a failure");

      writeKey(f.key(), "client2");
      requestUntil(kms, () -> server.peers.size() == 2, "the completed pair is picked up");
      assertEquals(List.of("CN=client", "CN=client2"), server.peers);
      assertEquals(
          List.of("reloaded " + f.chain() + ", " + f.key() + ", " + f.ca()), events.events);

      // A key file cut off in the middle of its Base64 (a writer that is not done yet).
      String whole = pem("PRIVATE KEY", key("client").getEncoded());
      writeCertificate(f.chain(), "client");
      Files.writeString(f.key(), whole.substring(0, whole.length() / 2));
      requestUntil(kms, () -> events.events.size() == 2, "the partial key is reported");
      assertTrue(events.events.get(1).startsWith("failed "), events.events.get(1));
      assertFalse(events.events.get(1).contains("MIG"), "no key material: " + events.events.get(1));
      kms.ping();
      assertEquals(2, server.peers.size(), "still the previous context");
      Files.writeString(f.key(), whole);
      requestUntil(kms, () -> server.peers.size() == 3, "the completed key is picked up");
      assertEquals("CN=client", server.peers.get(2));
      assertEquals(3, events.events.size());
    }
  }

  /** A rotated trust bundle is watched too: once it no longer names the server, new connections fail. */
  @Test
  void aRotatedTrustBundleIsUsedForNewConnections(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    Events events = new Events();
    try (RecordingTlsServer server = new RecordingTlsServer(serverContext());
        Kms kms =
            Kms.connect(
                KmsConfig.builder()
                    .endpoints(server.endpoint())
                    .clientIdentity(TestTls.identity("client"), STORE_PASSWORD)
                    .trustPem(f.ca())
                    .reloadOnChange(EVERY)
                    .retryPolicy(RetryPolicy.none())
                    .addListener(events)
                    .build())) {
      kms.ping();
      writeCertificate(f.ca(), "stranger");
      TestAwait.await("a reload is reported")
          .until(
              () -> {
                if (!events.events.isEmpty()) return true;
                try {
                  kms.ping();
                } catch (PermissionDeniedException expected) {
                  // the request that reloaded connected with the new trust
                }
                return false;
              });
      assertEquals(List.of("reloaded " + f.ca()), events.events, "only the trust file is watched");
      assertThrows(PermissionDeniedException.class, kms::ping, "the server is no longer trusted");
    }
  }

  /**
   * A PKCS#12 identity and an encrypted PEM key are reloaded with the builder's own copy of the
   * password, after the caller erased its array.
   */
  @Test
  void pkcs12AndEncryptedPemIdentitiesReloadWithTheBuildersCopyOfThePassword(@TempDir Path dir)
      throws Exception {
    Files3 f = files(dir, "client");
    Path p12 = dir.resolve("client.p12"), encrypted = dir.resolve("enc.key");
    writePkcs12(p12, STORE_PASSWORD, "client");
    Files.writeString(
        encrypted, pem("ENCRYPTED PRIVATE KEY", encrypt(key("client").getEncoded(), "pw", PBES2)));
    char[] p12Password = STORE_PASSWORD.clone(), keyPassword = "pw".toCharArray();
    List<KmsConfig.Builder> builders =
        List.of(
            KmsConfig.builder().clientIdentityKeyStore(p12, p12Password),
            KmsConfig.builder().clientIdentityPem(f.chain(), encrypted, keyPassword));
    Arrays.fill(p12Password, '\0');
    Arrays.fill(keyPassword, '\0');
    try (RecordingTlsServer server = new RecordingTlsServer(serverContext())) {
      for (KmsConfig.Builder b : builders) {
        KmsConfig config =
            b.trustPem(f.ca()).reloadOnChange(EVERY).endpoints(server.endpoint()).build();
        try (Kms kms = Kms.connect(config)) {
          kms.ping();
          if (b == builders.get(0)) writePkcs12(p12, STORE_PASSWORD, "client2");
          else {
            writeCertificate(f.chain(), "client2");
            Files.writeString(
                encrypted,
                pem("ENCRYPTED PRIVATE KEY", encrypt(key("client2").getEncoded(), "pw", PBES2)));
          }
          int before = server.peers.size();
          requestUntil(
              kms, () -> server.peers.size() == before + 1, "the renewed identity is presented");
          assertEquals("CN=client2", server.peers.get(before));
        }
      }
    }
  }

  /**
   * The files are stat-ed at most once per interval, however many requests are made; each part of
   * the stat counts: the modification time alone, the size alone (with the modification time put
   * back), and the file key alone (a file of the same size and time renamed into place).
   */
  @Test
  void theFilesAreCheckedAtMostOncePerIntervalAndEachPartOfTheStatCounts(@TempDir Path dir)
      throws Exception {
    Files3 f = files(dir, "client");
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofMillis(300))
            .build();
    List<String> failures = new ArrayList<>();
    TlsFiles.Reloading source =
        config.reloading.start(
            event ->
                event.accept(
                    new KmsListener() {
                      @Override
                      public void credentialsReloadFailed(String files, String why) {
                        failures.add(why);
                      }
                    }));
    SSLContext initial = config.tls;
    long start = System.nanoTime();
    for (int i = 0; i < 1000; i++) assertSame(initial, source.get());
    long elapsed = System.nanoTime() - start;
    assumeTrue(elapsed < 250_000_000L, "the loop ran within one interval");
    assertEquals(1, source.checks.get(), "one stat round for 1000 requests within the interval");
    assertEquals(0, source.loads.get(), "unchanged files are not read");

    // Same size and file, a new modification time: corrupt the key in place, same length.
    FileTime time = Files.getLastModifiedTime(f.key());
    byte[] good = Files.readAllBytes(f.key());
    byte[] corrupt = good.clone();
    for (int i = 40; i < 80; i++) corrupt[i] = 'A';
    Files.write(f.key(), corrupt);
    Files.setLastModifiedTime(f.key(), FileTime.fromMillis(time.toMillis() + 5_000));
    assertTrue(awaitCheck(source, 2), "a second check after the interval");
    assertEquals(0, source.loads.get(), "a change is read at the next check, if the files stay so");
    assertTrue(awaitCheck(source, 3));
    assertSame(initial, source.get(), "the previous context is kept");
    assertEquals(1, failures.size(), "a changed modification time is seen");

    // Restore, then change only the size, putting the modification time back.
    Files.write(f.key(), good);
    Files.setLastModifiedTime(f.key(), time);
    assertTrue(awaitCheck(source, 5));
    SSLContext restored = source.get();
    assertNotSame(initial, restored, "the restored files load");
    FileTime restoredTime = Files.getLastModifiedTime(f.key());
    Files.write(f.key(), Arrays.copyOf(good, good.length - 30));
    Files.setLastModifiedTime(f.key(), restoredTime);
    assertTrue(awaitCheck(source, 7));
    assertSame(restored, source.get());
    assertEquals(2, failures.size(), "a changed size alone is seen");

    // Restore, then rename a same-size, same-time file into place: only the file key differs.
    Files.write(f.key(), good);
    assertTrue(awaitCheck(source, 9));
    SSLContext again = source.get();
    assertNotSame(restored, again);
    BasicFileAttributes before = Files.readAttributes(f.key(), BasicFileAttributes.class);
    assumeTrue(before.fileKey() != null, "this file system has file keys");
    Path next = dir.resolve("tls.key.next");
    Files.write(next, corrupt);
    Files.setLastModifiedTime(next, before.lastModifiedTime());
    Files.move(next, f.key(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
    assertEquals(before.size(), Files.size(f.key()));
    assertEquals(before.lastModifiedTime(), Files.getLastModifiedTime(f.key()));
    assertTrue(awaitCheck(source, 11));
    assertSame(again, source.get());
    assertEquals(3, failures.size(), "a new file key alone is seen");
  }

  /**
   * A load that failed is tried again at each check although the stat has not changed: a renewed
   * key that its writer made readable only afterwards (a permission change leaves the
   * modification time and size alone) is picked up, and the failure was reported once.
   */
  @Test
  void aFailedLoadIsTriedAgainAtEachCheckUntilItLoads(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    assumeTrue(Files.getFileStore(f.key()).supportsFileAttributeView("posix"), "POSIX permissions");
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(EVERY)
            .build();
    List<String> events = new ArrayList<>();
    TlsFiles.Reloading source =
        config.reloading.start(
            event ->
                event.accept(
                    new KmsListener() {
                      @Override
                      public void credentialsReloaded(String files) {
                        events.add("reloaded");
                      }

                      @Override
                      public void credentialsReloadFailed(String files, String why) {
                        events.add(why);
                      }
                    }));
    source.get();
    writeCertificate(f.chain(), "client2");
    writeKey(f.key(), "client2");
    Set<java.nio.file.attribute.PosixFilePermission> readable =
        Files.getPosixFilePermissions(f.key());
    Files.setPosixFilePermissions(f.key(), Set.of());
    try {
      assumeTrue(!Files.isReadable(f.key()), "not running as root");
      assertTrue(awaitLoads(source, 1)); // read: fails
      assertTrue(awaitLoads(source, 2)); // read again at the next check
      assertEquals(1, events.size(), events.toString());
      assertTrue(
          events.get(0).startsWith("Cannot read the private key file " + f.key()), events.get(0));
      assertEquals(2, source.loads.get(), "read again at the next check, reported once");
    } finally {
      Files.setPosixFilePermissions(f.key(), readable);
    }
    BasicFileAttributes unchanged = Files.readAttributes(f.key(), BasicFileAttributes.class);
    SSLContext before = source.get();
    assertTrue(awaitLoads(source, 3));
    assertEquals(unchanged.lastModifiedTime(), Files.getLastModifiedTime(f.key()));
    assertNotSame(before, source.get(), "loaded once readable, the stat unchanged");
    assertEquals(List.of(events.get(0), "reloaded"), events);
  }

  // ---- PEM files are parsed by their structure, the same on every JDK ----

  /**
   * A leaf's key and its chain of three (leaf, intermediate CA, root CA), as PEM: what keytool's
   * {@code -genkeypair -ext BC:c} (the root), {@code -gencert -ext BC:c} (the intermediate) and
   * {@code -gencert} (the leaf) make, P-256 keys valid for two days with key identifiers. The key
   * store {@link #keytoolListing} lists, {@code chain3.p12} in {@code dir}, has each key with its
   * certificate.
   */
  record Chain3(String key, String leaf, String intermediate, String root) {}

  private static Chain3 chainOfThree(Path dir) throws Exception {
    java.time.Instant now = java.time.Instant.now();
    java.time.Instant until = now.plus(Duration.ofDays(2));
    KeyPair rootKey = TestPki.ec(), caKey = TestPki.ec(), leafKey = TestPki.ec();
    X509Certificate root =
        TestX509.certificate("root", rootKey.getPublic())
            .selfSigned(rootKey.getPrivate())
            .validity(now, until)
            .ca()
            .keyIdentifiers()
            .build();
    X509Certificate intermediate =
        TestX509.certificate("ca", caKey.getPublic())
            .issuedBy(root, rootKey.getPrivate())
            .validity(now, until)
            .ca()
            .keyIdentifiers()
            .build();
    X509Certificate leaf =
        TestX509.certificate("leaf", leafKey.getPublic())
            .issuedBy(intermediate, caKey.getPrivate())
            .validity(now, until)
            .keyIdentifiers()
            .build();
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(null, null);
    ks.setKeyEntry("root", rootKey.getPrivate(), STORE_PASSWORD, new Certificate[] {root});
    ks.setKeyEntry("ca", caKey.getPrivate(), STORE_PASSWORD, new Certificate[] {intermediate});
    ks.setKeyEntry("leaf", leafKey.getPrivate(), STORE_PASSWORD, new Certificate[] {leaf});
    try (OutputStream out = Files.newOutputStream(dir.resolve("chain3.p12"))) {
      ks.store(out, STORE_PASSWORD);
    }
    return new Chain3(
        pem("PRIVATE KEY", leafKey.getPrivate().getEncoded()),
        pem("CERTIFICATE", leaf.getEncoded()),
        pem("CERTIFICATE", intermediate.getEncoded()),
        pem("CERTIFICATE", root.getEncoded()));
  }

  /** The number of lines of {@code text}, which ends with a line end. */
  private static int lines(String text) {
    return (int) text.chars().filter(c -> c == '\n').count();
  }

  /**
   * Whether {@code text} is a whole PEM file: its last line, whitespace and keytool's asterisks
   * aside, is an END line.
   */
  private static boolean endsWithAnEndLine(String text) {
    String t = text.replaceAll("[\\s*]+$", "");
    String last = t.substring(Math.max(t.lastIndexOf('\n'), t.lastIndexOf('\r')) + 1).strip();
    return last.startsWith("-----END ")
        && last.endsWith("-----")
        && last.length() > "-----END -----".length();
  }

  /**
   * {@code keytool -list -rfc} of the key store {@link #chainOfThree} made in {@code dir}: keytool
   * itself, as the file format under test is its output.
   */
  private static String keytoolListing(Path dir) throws Exception {
    String keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString();
    Process p =
        new ProcessBuilder(
                keytool,
                "-list",
                "-rfc",
                "-storetype",
                "PKCS12",
                "-keystore",
                dir.resolve("chain3.p12").toString(),
                "-storepass",
                "changeit")
            .start();
    p.getOutputStream().close();
    String out =
        new String(p.getInputStream().readAllBytes(), java.nio.charset.StandardCharsets.UTF_8);
    assertEquals(0, p.waitFor(), out);
    return out;
  }

  /**
   * A PEM file cut short anywhere is refused by the builder and the
   * factories, on every JDK: a client chain of three certificates, a CA bundle of three with
   * comments before each certificate (as curl's and RHEL's bundles have), and a key file holding
   * the key and its chain, each cut at every position (except where what is left is itself a whole
   * file, ending with an END line). Before, JDK 25's {@code CertificateFactory} returned the
   * certificates before a cut inside a block (17 and 21 threw), and every JDK accepted a bundle cut
   * in the comment before a certificate, and a key file cut inside a certificate after the key.
   */
  @Test
  void aPemFileCutShortIsRefusedWhereverItIsCut(@TempDir Path dir) throws Exception {
    Chain3 c3 = chainOfThree(dir);
    Files3 f = files(dir, "client");
    Files.writeString(f.key(), c3.key());
    Files.writeString(f.chain(), c3.leaf() + c3.intermediate() + c3.root());
    String client = c3.leaf(), stranger = c3.intermediate(), server = c3.root();
    String key = c3.key();
    Map<String, String> wholes = new LinkedHashMap<>();
    wholes.put("chain", client + stranger + server);
    wholes.put(
        "bundle",
        "##\n## CA certificates\n##\n\nStranger CA\n===========\n"
            + stranger
            + "\nServer CA\n=========\n"
            + server
            + "\nClient\n======\n"
            + client);
    wholes.put("key", key + client + stranger);
    Map<String, java.util.function.Function<Path, String>> use =
        Map.of(
            "chain", p -> message(() -> KmsConfig.builder().clientIdentityPem(p, f.key())),
            "bundle", p -> message(() -> KmsConfig.builder().trustPem(p)),
            "key", p -> message(() -> KmsConfig.builder().clientIdentityPem(f.chain(), p)));
    for (var w : wholes.entrySet()) {
      Path file = dir.resolve(w.getKey() + ".pem");
      Files.writeString(file, w.getValue());
      // The whole files are accepted.
      if (w.getKey().equals("bundle")) KmsConfig.builder().trustPem(file);
      else if (w.getKey().equals("chain")) KmsConfig.builder().clientIdentityPem(file, f.key());
      else KmsConfig.builder().clientIdentityPem(f.chain(), file);
      int refused = 0;
      for (int cut = 1; cut < w.getValue().length(); cut++) {
        String part = w.getValue().substring(0, cut);
        if (endsWithAnEndLine(part)) continue;
        Files.writeString(file, part);
        String why = use.get(w.getKey()).apply(file);
        assertTrue(why.startsWith(file.toString()), w.getKey() + " cut at " + cut + ": " + why);
        assertFalse(why.contains("MII") || why.contains("MIG"), "no file contents: " + why);
        refused++;
      }
      assertTrue(refused > 1000, w.getKey() + ": " + refused);
    }

    // The cuts, with their messages, by the builder and the factories.
    Path chain = dir.resolve("chain.pem"),
        bundle = dir.resolve("bundle.pem"),
        keyFile = dir.resolve("key.pem");
    String whole = client + stranger + server;
    Map<String, String> cuts = new LinkedHashMap<>();
    cuts.put("inside the last block", whole.substring(0, whole.length() - 200));
    cuts.put(
        "inside the middle block", whole.substring(0, client.length() + stranger.length() / 2));
    cuts.put("inside the last BEGIN line", client + stranger + "-----BEGIN CERTIF");
    cuts.put("inside the last END line", whole.substring(0, whole.length() - 10));
    Map<String, String> expected =
        Map.of(
            "inside the last block", "has no END line (a file cut short, or still being written?)",
            "inside the middle block",
                "has no END line (a file cut short, or still being written?)",
            "inside the last BEGIN line",
                "is not a whole one (a file cut short, or still being written?)",
            "inside the last END line",
                "is not a whole one (a file cut short, or still being written?)");
    for (var c : cuts.entrySet()) {
      Files.writeString(chain, c.getValue());
      Files.writeString(bundle, c.getValue());
      Files.writeString(keyFile, key + c.getValue());
      String byBuilder = message(() -> KmsConfig.builder().clientIdentityPem(chain, f.key()));
      assertTrue(byBuilder.contains(expected.get(c.getKey())), c.getKey() + ": " + byBuilder);
      assertEquals(
          byBuilder,
          message(() -> KmsConfig.sslContextFromPem(chain, f.key(), f.ca())),
          c.getKey());
      String trust = message(() -> KmsConfig.builder().trustPem(bundle));
      assertTrue(
          trust.startsWith(bundle + ": ") && trust.contains(expected.get(c.getKey())),
          c.getKey() + ": " + trust);
      assertEquals(
          trust,
          message(() -> KmsConfig.sslContextFromPem(f.chain(), f.key(), bundle)),
          c.getKey());
      String keyed = message(() -> KmsConfig.builder().clientIdentityPem(f.chain(), keyFile));
      assertTrue(
          keyed.startsWith(keyFile + ": ") && keyed.contains(expected.get(c.getKey())),
          c.getKey() + ": " + keyed);
    }
    Files.writeString(bundle, stranger + "\nServer CA\n====");
    assertEquals(
        bundle
            + " has data after its last END line (a file cut short, or still being written?); a PEM file ends with"
            + " an END line",
        message(() -> KmsConfig.builder().trustPem(bundle)));
  }

  /**
   * What a PEM file may hold. Refused, each with a message naming the file and the block:
   * a block of another kind (a TRUSTED CERTIFICATE in a CA bundle, which every JDK read as a plain
   * certificate, dropping its trust settings; a private key in a chain; a CRL in a key file), two
   * private keys, an END line with another label or without a BEGIN, a BEGIN inside a block,
   * characters that are not Base64 (the JDK's decoders pass over them),
   * Base64 cut inside a group, data after the last END line, and DER cut short. Accepted: comments
   * before and between blocks, CRLF line ends and trailing blanks, the older {@code X509
   * CERTIFICATE} label, a key file that also holds its chain (either order; as before, a chain
   * file holding the key is refused), and DER certificates back to back.
   */
  @Test
  void aPemFileHoldsOnlyWholeBlocksOfItsKind(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    String client = pem("CERTIFICATE", TestTls.certificate("client").getEncoded());
    String server = pem("CERTIFICATE", TestTls.certificate("server").getEncoded());
    String key = pem("PRIVATE KEY", key("client").getEncoded());
    String otherKey = pem("PRIVATE KEY", key("client2").getEncoded());
    String crl = "-----BEGIN X509 CRL-----\nAAAA\n-----END X509 CRL-----\n";
    // Four characters that are not Base64 in the middle of a body (a MIME decoder passes over
    // them).
    java.util.function.UnaryOperator<String> spoiled =
        p -> p.substring(0, 100) + "!*?." + p.substring(100);
    Map<String, String> bundles = new LinkedHashMap<>(),
        chains = new LinkedHashMap<>(),
        keys = new LinkedHashMap<>();
    Map<String, String> expected = new LinkedHashMap<>();
    bundles.put("trusted", client + server.replace("CERTIFICATE", "TRUSTED CERTIFICATE"));
    int n = lines(client); // the lines of a certificate block; client's and server's are alike
    assertEquals(n, lines(server));
    expected.put(
        "trusted",
        "holds a BEGIN TRUSTED CERTIFICATE block at line "
            + (n + 1)
            + "; a trust file holds only CA certificates, in BEGIN CERTIFICATE blocks");
    chains.put("key in chain", client + key);
    expected.put(
        "key in chain",
        "holds a BEGIN PRIVATE KEY block at line "
            + (n + 1)
            + "; a certificate file holds only BEGIN CERTIFICATE blocks");
    keys.put("crl in key", key + crl);
    expected.put(
        "crl in key",
        "holds a BEGIN X509 CRL block at line "
            + (lines(key) + 1)
            + "; a private key file holds one private key, and may hold certificates");
    keys.put("two keys", key + otherKey);
    expected.put("two keys", "holds 2 private key blocks; exactly one is needed");
    bundles.put(
        "END mismatch", client.replace("-----END CERTIFICATE-----", "-----END X509 CRL-----"));
    expected.put(
        "END mismatch",
        ": the BEGIN CERTIFICATE block at line 1 ends with END X509 CRL at line " + n);
    bundles.put("END alone", client + "-----END CERTIFICATE-----\n");
    expected.put("END alone", ": line " + (n + 1) + " is END CERTIFICATE without a BEGIN line");
    chains.put("BEGIN inside", client.replace("-----END CERTIFICATE-----\n", "") + server);
    expected.put(
        "BEGIN inside",
        ": the BEGIN CERTIFICATE block at line 1 has no END line before the BEGIN CERTIFICATE line at line "
            + n);
    bundles.put("not Base64", spoiled.apply(client));
    expected.put(
        "not Base64",
        ": the CERTIFICATE block is not valid Base64 (the block at line 1; cut short, or not Base64)");
    keys.put("key not Base64", spoiled.apply(key));
    expected.put(
        "key not Base64",
        ": the PRIVATE KEY block is not valid Base64 (the block at line 1; cut short, or not Base64)");
    // The last two characters of the body cut off (a decoder that does not need padding takes it).
    int last = client.indexOf("\n-----END");
    chains.put("group cut", client.substring(0, last - 2) + client.substring(last));
    expected.put(
        "group cut",
        ": the CERTIFICATE block is not valid Base64 (the block at line 1; cut short, or not Base64)");
    chains.put("trailing text", client + "subject=CN = next\n");
    expected.put("trailing text", " has data after its last END line");
    keys.put("key trailing text", key + "x");
    expected.put("key trailing text", " has data after its last END line");
    Path file = dir.resolve("file.pem");
    for (var group : List.of(bundles, chains, keys))
      for (var c : group.entrySet()) {
        Files.writeString(file, c.getValue());
        String why =
            group == bundles
                ? message(() -> KmsConfig.builder().trustPem(file))
                : group == chains
                    ? message(() -> KmsConfig.builder().clientIdentityPem(file, f.key()))
                    : message(() -> KmsConfig.builder().clientIdentityPem(f.chain(), file));
        assertTrue(why.startsWith(file.toString()), c.getKey() + ": " + why);
        assertTrue(why.contains(expected.get(c.getKey())), c.getKey() + ": " + why);
        assertFalse(why.contains("MII") || why.contains("MIG"), "no file contents: " + why);
      }

    // DER: whole certificates back to back; one cut short is refused.
    byte[] der1 = TestTls.certificate("client").getEncoded(),
        der2 = TestTls.certificate("server").getEncoded();
    byte[] ders = Arrays.copyOf(der1, der1.length + der2.length);
    System.arraycopy(der2, 0, ders, der1.length, der2.length);
    Files.write(file, ders);
    KmsConfig.builder().trustPem(file);
    Files.write(file, Arrays.copyOf(ders, ders.length - 1));
    assertEquals(
        file + ": DER certificate 2 (at byte " + der1.length + ") is cut short or malformed",
        message(() -> KmsConfig.builder().trustPem(file)));
    Files.write(file, Arrays.copyOf(der1, der1.length + 1));
    assertTrue(message(() -> KmsConfig.builder().trustPem(file)).contains("DER certificate 2"));

    // Accepted.
    String commented =
        "Bag Attributes\n    friendlyName: client\nsubject=CN = client\n-----not a boundary-----\n\n"
            + client
            + "\n# the server\n"
            + server
            + "\n\n";
    Files.writeString(file, commented);
    KmsConfig.builder().trustPem(file);
    Files.writeString(file, "subject=CN = client\n" + client + "\n");
    KmsConfig.builder().clientIdentityPem(file, f.key());
    Files.writeString(file, commented.replace("\n", "\r\n").replace("-----\r\n", "-----  \r\n"));
    KmsConfig.builder().trustPem(file);
    Files.writeString(file, client.replace("CERTIFICATE", "X509 CERTIFICATE"));
    KmsConfig.builder().trustPem(file);
    Files.writeString(file, key + client + server);
    KmsConfig.builder().clientIdentityPem(f.chain(), file);
    Files.writeString(file, client + "\n" + key);
    KmsConfig.builder().clientIdentityPem(f.chain(), file);
  }

  /**
   * On a reload, a CA bundle cut inside its last block, quiet for an interval, is a failed
   * load (reported, the previous context kept) on every JDK; before, on JDK 25 it loaded and the
   * client trusted one CA fewer. The whole bundle then loads.
   */
  @Test
  void aBundleCutShortIsNotLoadedByAReload(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    String whole =
        pem("CERTIFICATE", TestTls.certificate("stranger").getEncoded())
            + pem("CERTIFICATE", TestTls.certificate("server").getEncoded());
    Files.writeString(f.ca(), whole);
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofMillis(100))
            .build();
    List<String> events = new ArrayList<>();
    TlsFiles.Reloading source = recording(config, events);
    SSLContext first = source.get();
    Files.writeString(f.ca(), whole.substring(0, whole.length() - 300));
    Thread.sleep(250); // quiet for an interval: read at the next check
    source.checkNow();
    assertEquals(1, source.loads.get());
    assertSame(first, source.get(), "the previous context");
    assertEquals(1, events.size(), events.toString());
    assertTrue(
        events
            .get(0)
            .startsWith(
                f.ca()
                    + ": the BEGIN CERTIFICATE block at line "
                    + (lines(whole) / 2 + 1)
                    + " has no END line"),
        events.get(0));
    Files.writeString(f.ca(), whole);
    Thread.sleep(250);
    source.checkNow();
    assertNotSame(first, source.get());
    assertEquals("reloaded", events.get(1));
  }

  /**
   * On a reload, a CA bundle written in place by a writer that is
   * not done, changed again before every check. The read after {@link TlsFiles#MAX_DEFERRALS}
   * checks put off finds it cut inside its second block: not loaded (the previous context kept, on
   * every JDK), and reported as {@code credentialsStillChanging} with how long it has been
   * changing, not as a failure; again after as many checks while the writer goes on. Once the
   * writer stops (here with the file still cut), the next check reads it and that is a failure;
   * the whole bundle then loads. Before, the forced read raised {@code credentialsReloadFailed}
   * on JDK 17 and 21 and published the cut bundle on JDK 25.
   */
  @Test
  void aFileStillBeingWrittenIsReportedAsChangingNotAsAFailure(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    String whole =
        pem("CERTIFICATE", TestTls.certificate("stranger").getEncoded())
            + pem("CERTIFICATE", TestTls.certificate("server").getEncoded());
    Files.writeString(f.ca(), whole);
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofSeconds(30))
            .build();
    List<String> events = new ArrayList<>();
    TlsFiles.Reloading source = recording(config, events);
    SSLContext first = source.get();
    int written = whole.length() / 2 + 40; // inside the second block
    for (int i = 0; i <= TlsFiles.MAX_DEFERRALS; i++) {
      Files.writeString(f.ca(), whole.substring(0, written += 7));
      Thread.sleep(5);
      source.checkNow();
    }
    assertEquals(1, source.loads.get(), "read at the check after the last one put off");
    assertSame(first, source.get(), "the cut bundle is not used");
    assertEquals(1, events.size(), events.toString());
    assertTrue(events.get(0).startsWith("still changing for "), events.toString());
    long firstFor = Long.parseLong(events.get(0).replaceAll("\\D", ""));
    assertTrue(firstFor >= 4 * 5, events.toString());
    // The writer goes on: put off again, then read and reported again.
    for (int i = 0; i <= TlsFiles.MAX_DEFERRALS; i++) {
      Files.writeString(f.ca(), whole.substring(0, written += 7));
      source.checkNow();
    }
    assertEquals(2, source.loads.get());
    assertEquals(2, events.size(), events.toString());
    assertTrue(Long.parseLong(events.get(1).replaceAll("\\D", "")) >= firstFor, events.toString());
    // The writer stops, the file still cut: read at the next check, and now a failure.
    source.checkNow();
    assertEquals(3, source.loads.get());
    assertEquals(3, events.size(), events.toString());
    assertTrue(events.get(2).contains(" has no END line"), events.get(2));
    assertSame(first, source.get());
    // The whole bundle: changed, then settled.
    Files.writeString(f.ca(), whole);
    source.checkNow();
    source.checkNow();
    assertNotSame(first, source.get());
    assertEquals("reloaded", events.get(3));
    assertEquals(4, events.size(), events.toString());
  }

  /**
   * Real files that are whole are accepted:
   * {@code keytool -list -rfc} output (the usual way to dump a Java trust store as PEM, ending with
   * lines of asterisks), a UTF-8 byte order mark (Windows editors), boundary lines indented (a
   * file pasted from YAML), and lone-CR line ends. Each is still refused wherever it is cut,
   * except where what is left is whole. Trailing NUL bytes stay refused (a file preallocated by
   * its writer).
   */
  @Test
  void realWorldPemFilesLoadAndTheirCutsDoNot(@TempDir Path dir) throws Exception {
    Chain3 c3 = chainOfThree(dir);
    String bundle = c3.intermediate() + c3.root();
    Map<String, String> wholes = new LinkedHashMap<>();
    wholes.put("keytool -list -rfc", keytoolListing(dir));
    wholes.put("byte order mark", "﻿" + bundle);
    wholes.put(
        "indented", ("ca: |\n" + bundle).replace("\n-", "\n    -").replace("\nM", "\n    M"));
    wholes.put("lone CR", bundle.replace("\n", "\r"));
    Path file = dir.resolve("bundle.pem");
    for (var w : wholes.entrySet()) {
      Files.writeString(file, w.getValue());
      KmsConfig.builder().trustPem(file);
      int refused = 0;
      // A byte order mark is three bytes: the cuts inside it leave no text to speak of.
      byte[] bytes = w.getValue().getBytes(java.nio.charset.StandardCharsets.UTF_8);
      for (int cut = 4; cut < bytes.length; cut++) {
        byte[] part = Arrays.copyOf(bytes, cut);
        if (endsWithAnEndLine(new String(part, java.nio.charset.StandardCharsets.UTF_8))) continue;
        Files.write(file, part);
        String why = message(() -> KmsConfig.builder().trustPem(file));
        assertTrue(why.startsWith(file.toString()), w.getKey() + " cut at " + cut + ": " + why);
        refused++;
      }
      assertTrue(refused > 500, w.getKey() + ": " + refused);
    }
    Files.writeString(file, bundle + "\0\0\0\0");
    assertTrue(
        message(() -> KmsConfig.builder().trustPem(file))
            .contains(" has data after its last END line"));
  }

  /**
   * A whole file that does not load is a failure also when it keeps
   * changing: a sync job that copies a certificate that does not match the key over the chain file
   * before every check. The read after four checks put off reports {@code credentialsReloadFailed}
   * with the reason, not {@code credentialsStillChanging}; before, it was reported as still
   * changing at every fifth check, forever, and the reason never reached the listener.
   */
  @Test
  void aWholeFileThatDoesNotLoadIsAFailureAlsoWhileItKeepsChanging(@TempDir Path dir)
      throws Exception {
    Files3 f = files(dir, "client");
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofSeconds(30))
            .build();
    List<String> events = new ArrayList<>();
    TlsFiles.Reloading source = recording(config, events);
    SSLContext first = source.get();
    String mismatched = pem("CERTIFICATE", TestTls.certificate("client2").getEncoded());
    for (int i = 0; i <= TlsFiles.MAX_DEFERRALS; i++) {
      Files.writeString(f.chain(), mismatched + "\n".repeat(i)); // whole, and new before each check
      source.checkNow();
    }
    assertEquals(1, source.loads.get());
    assertEquals(1, events.size(), events.toString());
    assertTrue(
        events.get(0).contains("does not match the first certificate in " + f.chain()),
        events.get(0));
    assertSame(first, source.get());
  }

  /**
   * What a forced read takes for a writer not done. A chain file
   * emptied (as {@code cp} does before it writes) and a PKCS#12 file cut short, each changing
   * before every check: {@code credentialsStillChanging}, no failure. A forced read that a write
   * overlaps (the trust file rewritten while the identity is checked): {@code
   * credentialsStillChanging} too; before, nothing was reported, so a writer that never pauses
   * went unreported.
   */
  @Test
  void emptyCutAndOverlappedForcedReadsAreStillChanging(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    KmsConfig pem =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofSeconds(30))
            .build();
    List<String> events = new ArrayList<>();
    TlsFiles.Reloading source = recording(pem, events);
    source.get();
    for (int i = 0; i <= TlsFiles.MAX_DEFERRALS; i++) {
      Files.writeString(f.chain(), "");
      Files.setLastModifiedTime(
          f.chain(), FileTime.fromMillis(System.currentTimeMillis() + i * 1000L));
      source.checkNow();
    }
    assertEquals(
        List.of("still changing"), events.stream().map(e -> e.replaceAll(" for .*", "")).toList());

    Path p12 = dir.resolve("client.p12");
    writePkcs12(p12, STORE_PASSWORD, "client");
    byte[] whole = Files.readAllBytes(p12);
    KmsConfig pkcs12 =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityKeyStore(p12, STORE_PASSWORD)
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofSeconds(30))
            .build();
    List<String> p12Events = new ArrayList<>();
    TlsFiles.Reloading p12Source = recording(pkcs12, p12Events);
    p12Source.get();
    for (int i = 0; i <= TlsFiles.MAX_DEFERRALS; i++) {
      Files.write(p12, Arrays.copyOf(whole, whole.length / 2 + i * 10));
      p12Source.checkNow();
    }
    assertEquals(1, p12Events.size(), p12Events.toString());
    assertTrue(p12Events.get(0).startsWith("still changing"), p12Events.toString());
    assertTrue(
        message(() -> KmsConfig.builder().clientIdentityKeyStore(p12, STORE_PASSWORD))
            .equals(p12 + " is not a whole PKCS#12 file (cut short, or still being written?)"));

    // A forced read that a write overlaps.
    writeCertificate(f.chain(), "client");
    List<String> overlapped = new ArrayList<>();
    TlsFiles.Reloading third = recording(pem, overlapped);
    third.get(); // sees the chain written since the build
    third.checkNow(); // and reads it
    assertEquals(1, third.loads.get());
    overlapped.clear();
    String ca = Files.readString(f.ca());
    withHook(
        () -> {
          for (int i = 1; i <= TlsFiles.MAX_DEFERRALS; i++) {
            Files.writeString(f.ca(), ca + "\n".repeat(i));
            third.checkNow();
          }
          assertEquals(1, third.loads.get(), "put off");
          Files.writeString(f.ca(), ca + "\n".repeat(10));
          HOOK.set(
              () -> {
                try {
                  Files.writeString(f.ca(), ca + "\n".repeat(20));
                } catch (java.io.IOException e) {
                  throw new java.io.UncheckedIOException(e);
                }
              });
          third.checkNow();
          assertNull(HOOK.get(), "the hook ran");
          return null;
        });
    assertEquals(1, third.changedWhileRead.get());
    assertEquals(1, overlapped.size(), overlapped.toString());
    assertTrue(overlapped.get(0).startsWith("still changing"), overlapped.toString());
  }

  /** A reloading source of {@code config} whose events go to {@code events} ("reloaded" or the failure). */
  private static TlsFiles.Reloading recording(KmsConfig config, List<String> events) {
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
                    events.add(why);
                  }

                  @Override
                  public void credentialsStillChanging(String files, Duration changingFor) {
                    events.add("still changing for " + changingFor.toMillis() + " ms");
                  }
                }));
  }

  /**
   * Files that keep failing to load and do not change are read again at the 1st, 2nd, 4th, 8th
   * ... check after the failure, then every 64th, not at every check: an encrypted key that will
   * not decrypt costs its key derivation on a request thread only that often. A change is read at
   * the next check.
   */
  @Test
  void unchangedFilesThatFailAreReadAgainAtEverLongerIntervals(@TempDir Path dir) throws Exception {
    assertTrue(
        TlsFiles.retries(1) && TlsFiles.retries(2) && TlsFiles.retries(4) && TlsFiles.retries(64));
    assertTrue(TlsFiles.retries(128) && TlsFiles.retries(192));
    assertFalse(
        TlsFiles.retries(3)
            || TlsFiles.retries(5)
            || TlsFiles.retries(63)
            || TlsFiles.retries(65)
            || TlsFiles.retries(100));
    Files3 f = files(dir, "client");
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofMillis(1))
            .build();
    List<String> events = new ArrayList<>();
    TlsFiles.Reloading source = recording(config, events);
    SSLContext first = source.get();
    // Not PKCS#8: does not load (not a mismatch, which is first taken for a renewal between files).
    Files.writeString(f.key(), pem("RSA PRIVATE KEY", key("client").getEncoded()));
    assertTrue(awaitLoads(source, 1));
    assertTrue(
        awaitCheck(source, source.checks.get() + 16)); // unchanged: retries at 1, 2, 4, 8, 16
    assertEquals(6, source.loads.get(), "read again at ever longer intervals");
    assertEquals(1, events.size(), events.toString());
    assertSame(first, source.get());
    writeKey(f.key(), "client"); // a change: read once it held for an interval (1 ms)
    assertTrue(awaitLoads(source, 7));
    assertNotSame(first, source.get());
    assertEquals("reloaded", events.get(1));
  }

  /**
   * A watched file grown beyond 1 MiB is not read (a sparse 3 GiB trust file made the request
   * thread throw OutOfMemoryError, unreported and never retried): a reported failure, and the
   * previous context stays.
   */
  @Test
  void anOversizedFileIsAFailureNotARead(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofMillis(1))
            .build();
    List<String> events = new ArrayList<>();
    TlsFiles.Reloading source = recording(config, events);
    SSLContext first = source.get();
    try (java.io.RandomAccessFile raf = new java.io.RandomAccessFile(f.ca().toFile(), "rw")) {
      raf.setLength(3L << 30);
    }
    assertTrue(awaitLoads(source, 1));
    assertSame(first, source.get());
    assertEquals(1, events.size(), events.toString());
    assertEquals(
        "The TLS file " + f.ca() + " has more than the 1048576 bytes a reload reads",
        events.get(0));
  }

  /** Runs {@code hook} once, from the first ECDSA signature made inside PemIdentity once it is set. */
  static final AtomicReference<Runnable> HOOK = new AtomicReference<>();

  /** SHA256withECDSA from SunEC, running {@link #HOOK} inside PemIdentity's key check. */
  public static final class HookedSignature extends java.security.SignatureSpi {
    private final java.security.Signature delegate;

    public HookedSignature() throws Exception {
      delegate = java.security.Signature.getInstance("SHA256withECDSA", "SunEC");
    }

    @Override
    protected void engineInitVerify(java.security.PublicKey k)
        throws java.security.InvalidKeyException {
      delegate.initVerify(k);
    }

    @Override
    protected void engineInitSign(PrivateKey k) throws java.security.InvalidKeyException {
      delegate.initSign(k);
    }

    @Override
    protected void engineUpdate(byte b) throws java.security.SignatureException {
      delegate.update(b);
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len)
        throws java.security.SignatureException {
      delegate.update(b, off, len);
    }

    @Override
    protected byte[] engineSign() throws java.security.SignatureException {
      if (Arrays.stream(Thread.currentThread().getStackTrace())
          .anyMatch(frame -> frame.getClassName().equals(PemIdentity.class.getName()))) {
        Runnable hook = HOOK.getAndSet(null);
        if (hook != null) hook.run();
      }
      return delegate.sign();
    }

    @Override
    protected boolean engineVerify(byte[] signature) throws java.security.SignatureException {
      return delegate.verify(signature);
    }

    @Override
    @Deprecated
    protected void engineSetParameter(String key, Object value) {
      throw new UnsupportedOperationException();
    }

    @Override
    @Deprecated
    protected Object engineGetParameter(String key) {
      throw new UnsupportedOperationException();
    }
  }

  /**
   * Runs {@code body} with {@link HookedSignature} as the preferred SHA256withECDSA, so that a hook
   * set in {@link #HOOK} runs while a reload checks a PEM key against its certificate: after the
   * identity files were read, before the trust file is.
   */
  private static void withHook(java.util.concurrent.Callable<Void> body) throws Exception {
    java.security.Provider provider =
        new java.security.Provider(
            "TlsFileReloadTestHook", "1.0", "runs a hook inside the key check") {};
    provider.put("Signature.SHA256withECDSA", HookedSignature.class.getName());
    java.security.Security.insertProviderAt(provider, 1);
    try {
      body.call();
    } finally {
      java.security.Security.removeProvider(provider.getName());
      HOOK.set(null);
    }
  }

  /**
   * The size cap bounds what is read, not what an earlier stat said: a trust file grown to 2 MiB
   * after the check stat-ed it (while the identity is checked, before the trust file is opened)
   * is not published; before, the reload read and published all of it. That check sees the change and reports nothing; the next one reads at most
   * 1 MiB + 1 bytes and reports the file as too large.
   */
  @Test
  void aTrustFileThatGrowsDuringTheReloadIsNotRead(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofMillis(300))
            .build(); // no check between the asserts
    List<String> events = new ArrayList<>();
    TlsFiles.Reloading source = recording(config, events);
    SSLContext first = source.get();
    String ca = Files.readString(f.ca());
    withHook(
        () -> {
          Files.writeString(
              f.chain(), Files.readString(f.chain()) + "\n"); // a change: the next check reads
          HOOK.set(
              () -> {
                try {
                  Files.writeString(f.ca(), ca + "\n".repeat(2 << 20));
                } catch (java.io.IOException e) {
                  throw new java.io.UncheckedIOException(e);
                }
              });
          assertTrue(awaitLoads(source, 1)); // the hook runs in this read
          assertNull(HOOK.get(), "the hook ran");
          assertSame(first, source.get(), "not published");
          assertEquals(1, source.changedWhileRead.get());
          assertEquals(List.of(), events, "a file changed while read is not reported");
          return null;
        });
    assertTrue(awaitLoads(source, 2));
    assertSame(first, source.get(), "still not published");
    assertEquals(
        List.of("The TLS file " + f.ca() + " has more than the 1048576 bytes a reload reads"),
        events);
  }

  /**
   * A trust bundle rewritten in place while a reload reads the files (here: cut to its first
   * certificate, a valid bundle that no longer names the server, between the reads of the
   * identity and of the trust file) is not published: the files are stat-ed again after they were
   * read and must not have changed. Once the bundle is whole again, it loads.
   */
  @Test
  void aFileRewrittenWhileTheReloadReadsItIsNotPublished(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    String stranger = pem("CERTIFICATE", TestTls.certificate("stranger").getEncoded());
    String whole = stranger + pem("CERTIFICATE", TestTls.certificate("server").getEncoded());
    Files.writeString(f.ca(), whole);
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofMillis(300))
            .build(); // no check between the asserts
    List<String> events = new ArrayList<>();
    TlsFiles.Reloading source = recording(config, events);
    SSLContext first = source.get();
    withHook(
        () -> {
          Files.writeString(f.chain(), Files.readString(f.chain()) + "\n");
          HOOK.set(
              () -> {
                try {
                  Files.writeString(f.ca(), stranger);
                } catch (java.io.IOException e) {
                  throw new java.io.UncheckedIOException(e);
                }
              });
          assertTrue(awaitLoads(source, 1)); // the hook runs in this read
          assertNull(HOOK.get(), "the hook ran");
          assertSame(first, source.get(), "the cut bundle is not published");
          assertEquals(1, source.changedWhileRead.get());
          return null;
        });
    Files.writeString(f.ca(), whole + "\n");
    long loads = source.loads.get();
    TestAwait.await("the whole bundle loads").until(() -> source.get() != first);
    assertNotSame(first, source.get(), "the whole bundle loads");
    assertEquals(List.of("reloaded"), events);
    assertTrue(source.loads.get() > loads);
  }

  /**
   * A PKCS#12 file whose one key is not the key of its certificate (client2's key with client's
   * certificate) is refused by the builder and the factory, and a reload of one keeps the previous
   * context and reports it; before, the reload published it and the next mutual-TLS request
   * failed.
   */
  @Test
  void aPkcs12FileWhoseKeyIsNotItsCertificatesIsRefused(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    Path p12 = dir.resolve("client.p12"), mismatched = dir.resolve("mismatched.p12");
    writePkcs12(p12, STORE_PASSWORD, "client");
    KeyStore bad = KeyStore.getInstance("PKCS12");
    bad.load(null, null);
    bad.setKeyEntry(
        "client",
        key("client2"),
        STORE_PASSWORD,
        TestTls.identity("client").getCertificateChain("client"));
    try (OutputStream out = Files.newOutputStream(mismatched)) {
      bad.store(out, STORE_PASSWORD);
    }
    String expected =
        "The private key in "
            + mismatched
            + " (EC) does not match the first certificate of its chain (EC)";
    assertEquals(
        expected,
        message(() -> KmsConfig.builder().clientIdentityKeyStore(mismatched, STORE_PASSWORD)));
    assertEquals(
        expected,
        message(() -> KmsConfig.sslContextFromPkcs12(mismatched, STORE_PASSWORD, f.ca())));

    Events events = new Events();
    try (RecordingTlsServer server = new RecordingTlsServer(serverContext());
        Kms kms =
            Kms.connect(
                KmsConfig.builder()
                    .endpoints(server.endpoint())
                    .clientIdentityKeyStore(p12, STORE_PASSWORD)
                    .trustPem(f.ca())
                    .reloadOnChange(EVERY)
                    .retryPolicy(RetryPolicy.none()) // a request failing once would show
                    .addListener(events)
                    .build())) {
      kms.ping();
      Files.copy(mismatched, p12, StandardCopyOption.REPLACE_EXISTING);
      requestUntil(kms, () -> !events.events.isEmpty(), "the mismatched store is reported");
      assertEquals(
          List.of(
              "failed "
                  + p12
                  + ", "
                  + f.ca()
                  + ": "
                  + expected.replace(mismatched.toString(), p12.toString())),
          events.events);
      for (int i = 0; i < 3; i++) kms.ping();
      assertEquals(List.of("CN=client"), server.peers, "the previous context is still used");
    }

    // A DSA key (keytool's default, 2048 bits, whose q is too long for SHA1withDSA) that matches
    // its certificate is accepted, as before the check.
    KeyStore dsa = TestTls.identity("dsaclient", "DSA");
    Path dsaFile = dir.resolve("dsa.p12");
    try (OutputStream out = Files.newOutputStream(dsaFile)) {
      dsa.store(out, STORE_PASSWORD);
    }
    assertNotNull(KmsConfig.sslContextFromPkcs12(dsaFile, STORE_PASSWORD, f.ca()));
    KmsConfig.builder().clientIdentityKeyStore(dsaFile, STORE_PASSWORD);
  }

  /**
   * A trust bundle rewritten in place by a writer that pauses after its first certificate (a valid
   * bundle, without the server's CA, the file still open) is not read in the middle: a change is
   * read once the files are the same at the next check. Requests go on with the previous context
   * meanwhile, and the whole bundle is then picked up; before, the check that saw the first
   * certificate published it and the next connection no longer trusted the server.
   */
  @Test
  void aBundleWrittenInPlaceIsReadOnceTheWriterIsDone(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    String stranger = pem("CERTIFICATE", TestTls.certificate("stranger").getEncoded());
    String server = pem("CERTIFICATE", TestTls.certificate("server").getEncoded());
    Files.writeString(f.ca(), stranger + server);
    Duration every = Duration.ofSeconds(1);
    Events events = new Events();
    try (RecordingTlsServer tls = new RecordingTlsServer(serverContext());
        Kms kms =
            Kms.connect(
                KmsConfig.builder()
                    .endpoints(tls.endpoint())
                    .clientIdentityPem(f.chain(), f.key())
                    .trustPem(f.ca())
                    .reloadOnChange(every)
                    .retryPolicy(RetryPolicy.none()) // a request failing once would show
                    .addListener(events)
                    .build())) {
      long start = System.nanoTime();
      kms.ping(); // checks
      sleepUntil(start, 750);
      try (OutputStream writer = Files.newOutputStream(f.ca())) {
        writer.write(stranger.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
        writer.flush();
        sleepUntil(
            start, 1100); // the next request checks, and sees the first certificate, 350 ms old
        kms.ping();
        kms.ping();
        assertEquals(List.of(), events.events, "not read while the writer may still be writing");
        writer.write(server.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
      }
      requestUntil(kms, () -> !events.events.isEmpty(), "the whole bundle is read");
      assertEquals(
          List.of("reloaded " + f.chain() + ", " + f.key() + ", " + f.ca()), events.events);
      kms.ping();
    }
  }

  private static void sleepUntil(long start, long millis) throws InterruptedException {
    long left = start + millis * 1_000_000L - System.nanoTime();
    if (left > 0) Thread.sleep(left / 1_000_000L, (int) (left % 1_000_000L));
  }

  /**
   * After an idle period, a renewal written more than an interval before the next request is read
   * at that request's check (its files are quiet by their modification time), not one check later:
   * with sparse requests and short-lived certificates, the next request may come after the old
   * certificate expired.
   */
  @Test
  void filesQuietForAnIntervalAreReadAtTheFirstCheck(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofMillis(200))
            .build();
    List<String> events = new ArrayList<>();
    TlsFiles.Reloading source = recording(config, events);
    SSLContext first = source.get();
    writeCertificate(f.chain(), "client2");
    writeKey(f.key(), "client2");
    Thread.sleep(400); // idle
    int checks = source.checks.get();
    SSLContext next = source.get();
    assertEquals(checks + 1, source.checks.get());
    assertNotSame(first, next, "read at the first check after the idle period");
    assertEquals(List.of("reloaded"), events);
  }

  /**
   * A watched file whose stat changes before every check (a job copying an unchanged CA bundle
   * over itself) does not keep a renewal off forever: after at most {@link
   * TlsFiles#MAX_DEFERRALS} checks put off, the files are read all the same.
   */
  @Test
  void filesChangedAtEveryCheckAreReadAfterAFewChecks(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofSeconds(30))
            .build();
    List<String> events = new ArrayList<>();
    TlsFiles.Reloading source = recording(config, events);
    SSLContext first = source.get();
    writeCertificate(f.chain(), "client2");
    writeKey(f.key(), "client2");
    String ca = Files.readString(f.ca());
    for (int i = 1; i <= 10 && source.loads.get() == 0; i++) {
      Files.writeString(f.ca(), ca + "\n".repeat(i)); // a new stat, a fresh modification time
      source.checkNow();
    }
    assertEquals(1, source.loads.get());
    assertEquals(
        TlsFiles.MAX_DEFERRALS + 1,
        source.checks.get() - 1,
        "read at the check after the last one put off");
    assertNotSame(first, source.get());
    assertEquals(List.of("reloaded"), events);
  }

  /** A check interval too long for nanoseconds is taken as forever, not an ArithmeticException at connect. */
  @Test
  void aCheckIntervalOfCenturiesIsForever(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofSeconds(Long.MAX_VALUE))
            .build();
    TlsFiles.Reloading source = recording(config, new ArrayList<>());
    assertNotNull(source.get());
    writeCertificate(f.chain(), "client2");
    writeKey(f.key(), "client2");
    source.get();
    assertEquals(1, source.checks.get(), "the first request checks, then never again");
  }

  /**
   * Calls {@code source} until it has read the files {@code loads} times ({@link TestAwait});
   * whether it read them exactly that often.
   */
  private static boolean awaitLoads(TlsFiles.Reloading source, int loads) {
    TestAwait.await("the files read " + loads + " times")
        .until(
            () -> {
              if (source.loads.get() >= loads) return true;
              source.get();
              return false;
            });
    return source.loads.get() == loads;
  }

  /**
   * Calls {@code source} until it has made {@code checks} stat rounds ({@link TestAwait}); whether
   * it made exactly that many.
   */
  private static boolean awaitCheck(TlsFiles.Reloading source, int checks) {
    TestAwait.await(checks + " stat rounds")
        .until(
            () -> {
              if (source.checks.get() >= checks) return true;
              source.get();
              return false;
            });
    return source.checks.get() == checks;
  }

  /**
   * build() refuses reloadOnChange with nothing read from files, with tls(...) and with a custom
   * transport; with files for only one part, only that part is watched; a configuration built
   * without reloadOnChange keeps no file names (its toBuilder() has nothing to watch) or password.
   */
  @Test
  void buildRefusesReloadOnChangeWithoutFilesAndWatchesOnlyWhatCameFromFiles(@TempDir Path dir)
      throws Exception {
    Files3 f = files(dir, "client");
    KeyStore identity = TestTls.identity("client");
    KeyStore trust = KeyStore.getInstance("PKCS12");
    trust.load(null, null);
    trust.setCertificateEntry("ca", TestTls.certificate("server"));
    SSLContext context = TestTls.context("client", "server");
    Supplier<SSLContext> supplier = () -> context;
    Map<String, KmsConfig.Builder> nothing = new LinkedHashMap<>();
    nothing.put(
        "key stores",
        KmsConfig.builder().clientIdentity(identity, STORE_PASSWORD).trustStore(trust));
    nothing.put(
        "system trust",
        KmsConfig.builder().clientIdentity(identity, STORE_PASSWORD).trustSystemDefaults());
    nothing.put(
        "password and system trust",
        KmsConfig.builder().usernamePassword("u", "p".toCharArray()).trustSystemDefaults());
    nothing.put("tls(SSLContext)", KmsConfig.builder().tls(context));
    nothing.put("tls(Supplier)", KmsConfig.builder().tls(supplier));
    nothing.put(
        "replaced by a key store",
        KmsConfig.builder()
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .clientIdentity(identity, STORE_PASSWORD)
            .trustStore(trust));
    for (var c : nothing.entrySet()) {
      String m = message(() -> c.getValue().endpoints("kms").reloadOnChange().build());
      assertTrue(
          m.startsWith("reloadOnChange() needs a TLS setting read from files"),
          c.getKey() + ": " + m);
    }
    assertTrue(
        message(() -> KmsConfig.builder().endpoints("kms").tls(context).reloadOnChange().build())
            .endsWith("(a tls(...) context is not read from files)"));
    String transport =
        message(
            () ->
                KmsConfig.builder()
                    .endpoints("kms")
                    .clientIdentityPem(f.chain(), f.key())
                    .trustPem(f.ca())
                    .transport(e -> null)
                    .reloadOnChange()
                    .build());
    assertTrue(transport.startsWith("reloadOnChange() and transport(...) both set"), transport);
    assertTrue(
        message(
                () ->
                    KmsConfig.builder()
                        .tls(context)
                        .trustPem(f.ca())
                        .reloadOnChange()
                        .endpoints("kms")
                        .build())
            .startsWith("tls(SSLContext) and clientIdentity*/trust* both set"));
    assertThrows(
        IllegalArgumentException.class, () -> KmsConfig.builder().reloadOnChange(Duration.ZERO));
    assertThrows(NullPointerException.class, () -> KmsConfig.builder().reloadOnChange(null));

    // Mixed: only the parts read from files are watched.
    assertEquals(
        List.of(f.chain(), f.key()),
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustSystemDefaults()
            .reloadOnChange()
            .build()
            .reloading
            .files());
    assertEquals(
        List.of(f.ca()),
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentity(identity, STORE_PASSWORD)
            .trustPem(f.ca())
            .reloadOnChange()
            .build()
            .reloading
            .files());
    assertEquals(
        List.of(f.ca()),
        KmsConfig.builder()
            .endpoints("kms")
            .usernamePassword("u", "p".toCharArray())
            .trustPem(f.ca())
            .reloadOnChange()
            .build()
            .reloading
            .files());
    // reloadOnChange may come first; toBuilder() of a reloading configuration still reloads.
    KmsConfig reloading =
        KmsConfig.builder()
            .reloadOnChange()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .build();
    assertEquals(
        List.of(f.chain(), f.key(), f.ca()), reloading.toBuilder().build().reloading.files());

    // Without reloadOnChange: no file names and no password kept by the configuration.
    Path encrypted = dir.resolve("enc.key");
    Files.writeString(
        encrypted, pem("ENCRYPTED PRIVATE KEY", encrypt(key("client").getEncoded(), "pw", PBES2)));
    KmsConfig.Builder builder =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), encrypted, "pw".toCharArray())
            .trustPem(f.ca());
    KmsConfig fixed = builder.build();
    assertNull(fixed.reloading);
    assertNull(fixed.toBuilder().identityFiles, "no file names or password in the configuration");
    String fromFixed = message(() -> fixed.toBuilder().reloadOnChange().build());
    assertTrue(
        fromFixed.startsWith("reloadOnChange() needs a TLS setting read from files"), fromFixed);
    // The builder's own copy of the password is wiped when the identity is replaced.
    char[] held = builder.identityFiles.password();
    assertArrayEquals("pw".toCharArray(), held);
    KmsConfig kept = builder.reloadOnChange().build();
    builder.clientIdentityPem(f.chain(), f.key());
    assertArrayEquals(new char[2], held, "the replaced copy is wiped");
    assertArrayEquals(
        "pw".toCharArray(),
        kept.reloading.identity.password(),
        "a reloading configuration keeps its copy");
  }

  /** The recipe of docs/production.md, "Reload client credentials", as written there. */
  @Test
  void theGuideRecipeRunsAsWritten(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    Path cert = f.chain(), key = f.key(), ca = f.ca();
    // The in-memory server over TLS, presenting "server" and trusting client and client2.
    try (TlsListener server =
        InMemoryKmipServer.of(KmipVersion.V2_1).tlsListener().context(serverContext()).start()) {
      // The SDK watches the files.
      KmsConfig config =
          KmsConfig.builder()
              .endpoints(server.endpoint())
              .clientIdentityPem(cert, key)
              .trustPem(ca)
              .reloadOnChange() // checks the files at most once a second, before a request
              .build();
      try (Kms kms = Kms.connect(config)) {
        kms.ping();
        writeCertificate(cert, "client2");
        writeKey(key, "client2");
        requestUntil(
            kms,
            () -> server.clientCertificates().size() == 2,
            "the default interval picks up the renewal");
        assertEquals(List.of("CN=client", "CN=client2"), subjects(server));
      }
      // A supplier of your own.
      AtomicReference<SSLContext> current =
          new AtomicReference<>(KmsConfig.sslContextFromPem(cert, key, ca));
      KmsConfig supplied =
          KmsConfig.builder().endpoints(server.endpoint()).tls(current::get).build();
      try (Kms kms = Kms.connect(supplied)) {
        kms.ping();
        // when your watcher sees new files:
        writeCertificate(cert, "client");
        try {
          current.set(KmsConfig.sslContextFromPem(cert, key, ca));
        } catch (IllegalArgumentException e) {
          // not complete yet (a key from another renewal): keep the previous context
        }
        kms.ping();
        writeKey(key, "client");
        current.set(KmsConfig.sslContextFromPem(cert, key, ca));
        kms.ping();
      }
      assertEquals(List.of("CN=client", "CN=client2", "CN=client2", "CN=client"), subjects(server));
    }
  }

  /** The subject of each client certificate the listener saw, in handshake order. */
  private static List<String> subjects(TlsListener server) {
    return server.clientCertificates().stream()
        .map(c -> c.getSubjectX500Principal().getName())
        .toList();
  }

  // ---- combined key and chain files, plain refusals, renewals written in place ----

  /**
   * One PEM file holding the key and its chain ({@code openssl pkcs12
   * -nodes} output, HAProxy's form), in either order with OpenSSL's "Bag Attributes", passed as
   * both arguments: the factory and the builder accept it, and the client presents its
   * certificate; a reload reads the file once and loads the renewal. Before, the certificate read
   * refused the file's private key block. Still refused: such a file with no certificate (as a
   * file still being written), with two keys, or whose key does not match its first certificate;
   * and a private key in a chain file that is not also the key file, now with the hint.
   */
  @Test
  void aFileHoldingTheKeyAndItsChainIsBothArguments(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    String client = pem("CERTIFICATE", TestTls.certificate("client").getEncoded());
    String key = pem("PRIVATE KEY", key("client").getEncoded());
    Path combined = dir.resolve("combined.pem");
    String bag = "Bag Attributes\n    localKeyID: 01 00 00 00\nsubject=CN = client\n";
    for (String contents : List.of(bag + key + bag + client, client + "\n" + key)) {
      Files.writeString(combined, contents);
      SSLContext context = KmsConfig.sslContextFromPem(combined, combined, f.ca());
      try (RecordingTlsServer tls = new RecordingTlsServer(serverContext());
          Kms kms =
              Kms.connect(
                  KmsConfig.builder().endpoints(tls.endpoint()).tls(() -> context).build())) {
        kms.ping();
        assertEquals(List.of("CN=client"), tls.peers);
      }
    }
    // The same file named another way (a relative path, a symbolic link) is the same file.
    Path relative = Path.of("").toAbsolutePath().relativize(combined);
    KmsConfig.builder().clientIdentityPem(combined, relative);
    Path link = Files.createSymbolicLink(dir.resolve("link.pem"), combined);
    KmsConfig.builder().clientIdentityPem(link, combined);

    // A reload: the renewal written over the one file loads.
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(combined, combined)
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofMillis(100))
            .build();
    List<String> events = new ArrayList<>();
    TlsFiles.Reloading source = recording(config, events);
    SSLContext first = source.get();
    // Watched once (not listed, and stat-ed, twice), as the builder read it.
    assertEquals(List.of(combined, f.ca()), config.reloading.files());
    source.checkNow();
    assertEquals(0, source.loads.get(), "unchanged: not read again");
    Files.writeString(
        combined,
        pem("PRIVATE KEY", key("client2").getEncoded())
            + pem("CERTIFICATE", TestTls.certificate("client2").getEncoded()));
    Thread.sleep(250);
    source.checkNow();
    assertEquals(List.of("reloaded"), events);
    assertNotSame(first, source.get());

    Files.writeString(combined, key);
    assertEquals(
        combined + " holds a private key and no certificate (PEM BEGIN CERTIFICATE)",
        message(() -> KmsConfig.builder().clientIdentityPem(combined, combined)));
    Files.writeString(combined, key + client + pem("PRIVATE KEY", key("client2").getEncoded()));
    assertTrue(
        message(() -> KmsConfig.builder().clientIdentityPem(combined, combined))
            .contains("holds 2 private key blocks"));
    Files.writeString(combined, pem("PRIVATE KEY", key("client2").getEncoded()) + client);
    assertTrue(
        message(() -> KmsConfig.builder().clientIdentityPem(combined, combined))
            .contains("does not match the first certificate"));
    Files.writeString(combined, key + client);
    String refused = message(() -> KmsConfig.builder().clientIdentityPem(combined, f.key()));
    assertTrue(
        refused.contains(
            "a certificate file holds only BEGIN CERTIFICATE blocks (pass a file holding the key and its chain as both arguments)"),
        refused);
  }

  /**
   * A file that is not whole is refused with a plain {@code
   * IllegalArgumentException} by every public way of reading it (the builder's {@code
   * clientIdentityPem}, {@code clientIdentityKeyStore} and {@code trustPem}, and the three
   * factories), and no package-private class shows in its stack trace; before, it was the SDK's
   * own {@code Pem$Incomplete}. A reload still takes such a file for one still being written
   * ({@code emptyCutAndOverlappedForcedReadsAreStillChanging}).
   */
  @Test
  void aFileThatIsNotWholeIsAPlainIllegalArgumentException(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    String chain = Files.readString(f.chain());
    Path cut = dir.resolve("cut.pem"),
        p12 = dir.resolve("client.p12"),
        cutP12 = dir.resolve("cut.p12");
    Files.writeString(cut, chain.substring(0, chain.length() - 40));
    writePkcs12(p12, STORE_PASSWORD, "client");
    byte[] whole = Files.readAllBytes(p12);
    Files.write(cutP12, Arrays.copyOf(whole, whole.length / 2));
    List<Runnable> reads =
        List.of(
            () -> KmsConfig.builder().clientIdentityPem(cut, f.key()),
            () -> KmsConfig.builder().clientIdentityPem(f.chain(), cut, "pw".toCharArray()),
            () -> KmsConfig.builder().trustPem(cut),
            () -> KmsConfig.builder().clientIdentityKeyStore(cutP12, STORE_PASSWORD),
            () -> KmsConfig.sslContextFromPem(cut, f.key(), f.ca()),
            () -> KmsConfig.sslContextFromPem(f.chain(), f.key(), "pw".toCharArray(), cut),
            () -> KmsConfig.sslContextFromPkcs12(cutP12, STORE_PASSWORD, f.ca()));
    for (Runnable read : reads) {
      IllegalArgumentException e = assertThrows(IllegalArgumentException.class, read::run);
      assertEquals(IllegalArgumentException.class, e.getClass(), e.toString());
      java.io.StringWriter trace = new java.io.StringWriter();
      e.printStackTrace(new java.io.PrintWriter(trace));
      assertFalse(trace.toString().contains("$Incomplete"), trace.toString());
      assertTrue(
          e.getMessage().contains("cut")
              || e.getMessage().contains("no END line")
              || e.getMessage().contains("not a whole"),
          e.getMessage());
    }
  }

  /**
   * A renewal written one file at a time, in place (the certificate, then
   * the key an interval later), read between its files: the key and the certificate do not match,
   * and that is {@code credentialsStillChanging}, not {@code credentialsReloadFailed}; the pair
   * then loads. Before, it was one {@code credentialsReloadFailed}, which paged. A mismatch that
   * stays is still changing at two reads in a row and a failure at the third, two intervals after
   * the first; a change after that report gets the same grace again. One file holding both, whose
   * key does not match, is a failure at once (it is not a pair being written).
   */
  @Test
  void aRenewalWrittenOneFileAtATimeIsNotAFailure(@TempDir Path dir) throws Exception {
    // A long interval: get() does not check, and files changed are read at the second check
    // (the first sees the change; the next finds them the same).
    Files3 f = files(dir, "client");
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofSeconds(30))
            .build();
    List<String> events = new ArrayList<>();
    TlsFiles.Reloading source = recording(config, events);
    // The mismatch grace's clock: moved by hand below.
    java.util.concurrent.atomic.AtomicLong nanos = new java.util.concurrent.atomic.AtomicLong();
    source.nanos = nanos::get;
    SSLContext first = source.get();
    writeCertificate(f.chain(), "client2");
    source.checkNow();
    source.checkNow();
    assertEquals(1, source.loads.get());
    assertEquals(1, events.size(), events.toString());
    assertTrue(events.get(0).startsWith("still changing for "), events.toString());
    assertSame(first, source.get());
    writeKey(f.key(), "client2");
    source.checkNow();
    source.checkNow();
    assertEquals(List.of("reloaded"), events.subList(1, events.size()));
    SSLContext renewed = source.get();
    assertNotSame(first, renewed);

    // A mismatch that stays: still changing, still changing, then a failure (once 10 s passed too).
    writeCertificate(f.chain(), "client");
    for (int i = 0; i < 4; i++) {
      if (i == 3) nanos.addAndGet(TlsFiles.MISMATCH_FLOOR.toNanos());
      source.checkNow();
    }
    assertEquals(5, events.size(), events.toString());
    assertTrue(
        events.get(2).startsWith("still changing for ")
            && events.get(3).startsWith("still changing for "),
        events.toString());
    assertTrue(
        events.get(4).contains("does not match the first certificate in " + f.chain()),
        events.toString());
    assertSame(renewed, source.get(), "the previous context");
    source.checkNow();
    assertEquals(5, events.size(), "reported once: " + events);
    // The next change has the grace again.
    writeKey(f.key(), "stranger");
    source.checkNow();
    source.checkNow();
    assertEquals(6, events.size(), events.toString());
    assertTrue(events.get(5).startsWith("still changing for "), events.toString());
    writeKey(f.key(), "client");
    source.checkNow();
    source.checkNow();
    assertEquals("reloaded", events.get(6), events.toString());

    // One file holding both: no pair to wait for.
    Path combined = dir.resolve("combined.pem");
    Files.writeString(
        combined,
        pem("PRIVATE KEY", key("client").getEncoded())
            + pem("CERTIFICATE", TestTls.certificate("client").getEncoded()));
    KmsConfig one =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(combined, combined)
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofSeconds(30))
            .build();
    List<String> heard = new ArrayList<>();
    TlsFiles.Reloading oneSource = recording(one, heard);
    oneSource.get();
    Files.writeString(
        combined,
        pem("PRIVATE KEY", key("client2").getEncoded())
            + pem("CERTIFICATE", TestTls.certificate("client").getEncoded()));
    oneSource.checkNow();
    oneSource.checkNow();
    assertEquals(1, heard.size(), heard.toString());
    assertTrue(heard.get(0).contains("does not match the first certificate"), heard.toString());
  }

  /**
   * The advice in a refusal of a block that is not a certificate fits the file. The hint "pass a
   * file holding the key and its chain as both arguments" is not given to every chain and trust
   * file (such as a CA bundle in {@code TRUSTED CERTIFICATE} or {@code PKCS7} form): it follows only a private key in a chain file; a trust file
   * is called one, a private key in it is named as not belonging, and the two other forms get the
   * openssl command that converts them, naming the file.
   */
  @Test
  void aRefusedBlockGetsAdviceThatFitsTheFile(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    String client = pem("CERTIFICATE", TestTls.certificate("client").getEncoded());
    String key = pem("PRIVATE KEY", key("client").getEncoded());
    Path file = dir.resolve("bundle.pem");
    String both = "pass a file holding the key and its chain as both arguments";
    Map<String, String> trust = new LinkedHashMap<>(), chain = new LinkedHashMap<>();
    trust.put(
        client.replace("CERTIFICATE", "TRUSTED CERTIFICATE"),
        "a trust file holds only CA certificates, in BEGIN CERTIFICATE blocks (convert it to a plain one: openssl x509 -in "
            + file
            + " -out ca.pem)");
    trust.put(
        client.replace("CERTIFICATE", "PKCS7"),
        "a trust file holds only CA certificates, in BEGIN CERTIFICATE blocks (convert it to CERTIFICATE blocks: openssl pkcs7 -print_certs -in "
            + file
            + " -out ca.pem)");
    trust.put(
        client + key,
        "a trust file holds only CA certificates, in BEGIN CERTIFICATE blocks (a trust file holds no private key)");
    chain.put(
        client + key, "a certificate file holds only BEGIN CERTIFICATE blocks (" + both + ")");
    chain.put(
        client.replace("CERTIFICATE", "PKCS7"),
        "a certificate file holds only BEGIN CERTIFICATE blocks (convert it to CERTIFICATE blocks: openssl pkcs7 -print_certs -in "
            + file
            + " -out chain.pem)");
    for (var c : trust.entrySet()) {
      Files.writeString(file, c.getKey());
      String why = message(() -> KmsConfig.builder().trustPem(file));
      assertTrue(why.endsWith(c.getValue()), why);
      assertFalse(why.contains(both), why);
    }
    for (var c : chain.entrySet()) {
      Files.writeString(file, c.getKey());
      String why = message(() -> KmsConfig.builder().clientIdentityPem(file, f.key()));
      assertTrue(why.endsWith(c.getValue()), why);
    }
  }

  /**
   * The mismatch grace has a time floor. At a one-second interval, two reads are about 3.5 s, so
   * without it a renewal whose key followed its certificate 4.5 s later would still page. A mismatch is a failure only once two reads and 10 s have
   * passed since the first read that found it: the 4.5 s writer is still changing at every read
   * and then loads, and a key that never follows is reported once, at the first read after 10 s.
   */
  @Test
  void theMismatchGraceLastsAtLeastTenSeconds(@TempDir Path dir) throws Exception {
    Files3 f = files(dir, "client");
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms")
            .clientIdentityPem(f.chain(), f.key())
            .trustPem(f.ca())
            .reloadOnChange(Duration.ofSeconds(30))
            .build();
    List<String> events = new ArrayList<>();
    TlsFiles.Reloading source = recording(config, events);
    java.util.concurrent.atomic.AtomicLong nanos = new java.util.concurrent.atomic.AtomicLong();
    source.nanos = nanos::get;
    long second = Duration.ofSeconds(1).toNanos();
    SSLContext first = source.get();
    // The certificate first; the key 4.5 s later. One check a second.
    writeCertificate(f.chain(), "client2");
    source.checkNow(); // sees the change
    for (int t = 1; t <= 4; t++) {
      source.checkNow(); // reads: a mismatch, still changing
      nanos.addAndGet(second);
    }
    assertEquals(4, events.size(), events.toString());
    assertTrue(
        events.stream().allMatch(e -> e.startsWith("still changing for ")), events.toString());
    assertSame(first, source.get());
    writeKey(f.key(), "client2");
    source.checkNow();
    source.checkNow();
    assertEquals("reloaded", events.get(events.size() - 1), events.toString());
    assertTrue(events.stream().noneMatch(e -> e.contains("does not match")), events.toString());

    // A key that never follows: still changing until 10 s have passed, then reported once.
    events.clear();
    writeCertificate(f.chain(), "client");
    source.checkNow();
    for (int t = 0; t < 10; t++) {
      source.checkNow();
      nanos.addAndGet(second);
    }
    assertEquals(10, events.size(), events.toString());
    assertTrue(
        events.stream().allMatch(e -> e.startsWith("still changing for ")), events.toString());
    source.checkNow();
    assertEquals(11, events.size(), events.toString());
    assertTrue(
        events.get(10).contains("does not match the first certificate in " + f.chain()),
        events.toString());
    source.checkNow();
    assertEquals(11, events.size(), "reported once: " + events);
  }
}
