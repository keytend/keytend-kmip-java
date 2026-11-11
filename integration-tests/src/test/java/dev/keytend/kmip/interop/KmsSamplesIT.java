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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.*;
import dev.keytend.kmip.kms.samples.*;
import dev.keytend.kmip.model.ProtocolVersion;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.*;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.images.builder.ImageFromDockerfile;
import org.testcontainers.utility.MountableFile;

/**
 * Runs the application-API sample applications (A1-A7, and the README quickstart) against
 * the real servers: PyKMIP (KMIP 1.2 and 1.4) and PQCToday (3.0 draft). Each
 * result is recorded as PASS, UNSUPPORTED ({@link UnsupportedException}: the server answered
 * Operation/Feature Not Supported, or the negotiated version lacks the feature), SERVER_LIMITATION
 * (a diagnosed server behavior, {@link #LIMITATIONS}) or FAIL, and compared with the
 * expected matrix {@link #EXPECTED}: any difference fails the build. Each server-specific
 * expectation is backed by a limitation of that server, which matches only its server, sample and
 * exact failure. Reports go to {@code integration/reports/kms-samples-*.json}.
 */
class KmsSamplesIT {
  private static final Path ROOT = Path.of(System.getProperty("project.root"));
  private static Path CERTS;

  @BeforeAll
  static void certificates() throws Exception {
    CERTS = Files.createTempDirectory("keytend-kms-samples-");
    Process p =
        new ProcessBuilder(
                "bash", ROOT.resolve("integration/generate-certs.sh").toString(), CERTS.toString())
            .inheritIO()
            .start();
    assertTrue(p.waitFor(30, TimeUnit.SECONDS), "Certificate generation timeout");
    assertEquals(0, p.exitValue());
  }

  @AfterAll
  static void cleanup() throws Exception {
    if (CERTS != null)
      try (var walk = Files.walk(CERTS)) {
        for (Path p : walk.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
      }
  }

  record Outcome(String sample, String outcome, String detail, String operation) {}

  /**
   * The exact chain sample A6 records on PQCToday, with any object identifier: the
   * Get reply declares Object Type Certificate and carries a symmetric key block.
   */
  static final String PQCTODAY_CERTIFICATE_FAILURE =
      "dev\\.keytend\\.kmip\\.kms\\.ProtocolViolationException: asCertificate [^ ]+: invalid response: Get"
          + " response object does not match its ObjectType <- dev\\.keytend\\.kmip\\.client\\.ProtocolException:"
          + " Get response object does not match its ObjectType";

  /**
   * The chain sample A2 records on PyKMIP at KMIP 1.4, where its KEK is created with
   * Extractable false: the Create is refused with Invalid Field.
   */
  static final String PYKMIP_EXTRACTABLE_FAILURE =
      "dev.keytend.kmip.kms.InvalidRequestException: findOrCreate failed: KMIP Create returned"
          + " OperationFailed (1), reason InvalidField (0x00000007)"
          + " (server message: \"The Extractable attribute is unsupported.\")"
          + " <- dev.keytend.kmip.client.KmipException: KMIP Create returned OperationFailed (1),"
          + " reason InvalidField (0x00000007)";

  /**
   * The chain sample A2 records on PQCToday: the KEK made with Extractable false
   * reads back Extractable true, so the SDK leaves it Pre-Active and refuses.
   */
  static final String PQCTODAY_EXTRACTABLE_FAILURE =
      "dev\\.keytend\\.kmip\\.kms\\.PartialCompletionException: findOrCreate: created \\[[^ ]+\\], then the"
          + " server did not keep the protection asked: findOrCreate: [^ ]+ was made with Extractable"
          + " false, but its Extractable is true, not false; .* <- dev\\.keytend\\.kmip\\.kms\\.KeyMismatchException:"
          + " findOrCreate: [^ ]+ was made with Extractable false, but its Extractable is true, not false";

  /**
   * The failure of sample A6 on PyKMIP, as {@code samplesAgainstRealServers} records
   * it (the exception chain, outermost first). It names {@code registerPreActive}, the method the
   * sample calls.
   */
  static final String PYKMIP_CERTIFICATE_FAILURE =
      "dev.keytend.kmip.kms.ServerFailureException: registerPreActive failed: KMIP Register returned"
          + " OperationFailed (1), reason GeneralFailure (0x00000100)"
          + " (server message: \"Operation failed. See the server logs for more information.\")"
          + " <- dev.keytend.kmip.client.KmipException: KMIP Register returned OperationFailed (1),"
          + " reason GeneralFailure (0x00000100)";

  /**
   * A server behavior that excuses a sample on that server only: {@code expected} is the table value
   * it authorizes, SERVER_LIMITATION (the failure must match {@code failure}) or
   * UNSUPPORTED:operation.
   */
  record Limitation(String server, String sample, String expected, String failure, String why) {
    boolean appliesTo(String target, String name) {
      return server.equals(target) && sample.equals(name);
    }
  }

  static final List<Limitation> LIMITATIONS =
      List.of(
          new Limitation(
              "pykmip",
              "A2 EnvelopeEncryption",
              "SERVER_LIMITATION",
              java.util.regex.Pattern.quote(PYKMIP_EXTRACTABLE_FAILURE),
              "PyKMIP refuses a Create carrying the KMIP 1.4 Extractable attribute (Invalid Field),"
                  + " which sample A2 asks for its KEK from 1.4; the SDK never drops it"),
          new Limitation(
              "pqctoday",
              "A2 EnvelopeEncryption",
              "SERVER_LIMITATION",
              PQCTODAY_EXTRACTABLE_FAILURE,
              "PQCToday accepts Extractable false on Create but keeps and reports Extractable true;"
                  + " the SDK's read-back leaves the KEK Pre-Active and refuses"),
          new Limitation(
              "pykmip",
              "A5 LifecycleRotation",
              "UNSUPPORTED:rotate",
              null,
              "PyKMIP does not implement Re-key (Operation Not Supported)"),
          new Limitation(
              "pykmip",
              "A6 CertificateStorage",
              "SERVER_LIMITATION",
              // Exactly the chain observed on PyKMIP (KMIP 1.2 and 1.4): Register fails
              // with General Failure and nothing else; any other failure of the sample is a FAIL.
              java.util.regex.Pattern.quote(PYKMIP_CERTIFICATE_FAILURE),
              "PyKMIP cannot store Cryptographic Algorithm on certificates (server log:"
                  + " 'X509Certificate' object has no attribute 'cryptographic_algorithm'), which"
                  + " KMIP 1.1 Table 129 requires for Certificate Register"),
          new Limitation(
              "pqctoday",
              "A4 RemoteSignVerify",
              "UNSUPPORTED:asPublicKey",
              null,
              "PQCToday returns public keys in a vendor Raw layout the SDK cannot convert to"
                  + " X.509"),
          new Limitation(
              "pqctoday",
              "A6 CertificateStorage",
              "SERVER_LIMITATION",
              PQCTODAY_CERTIFICATE_FAILURE,
              "PQCToday answers Get of a registered certificate with Object Type Certificate but a"
                  + " SymmetricKey key block instead of the Certificate structure (the SDK"
                  + " reports the mismatch as such)"));

  /**
   * Outcomes the SDK itself decides from the negotiated version, whatever the server: the
   * table value, and the first version where it no longer applies.
   */
  static final Map<String, ProtocolVersion> SDK_REFUSALS =
      // AES-GCM needs KMIP 1.4: the SDK refuses it before sending on 1.2, naming the method called.
      Map.of("UNSUPPORTED:encrypt", ProtocolVersion.V1_4, "UNSUPPORTED:seal", ProtocolVersion.V1_4);

  /** The diagnosed limitation a failure matches on this server, if any. */
  static Optional<String> limitation(String server, String sample, String failure) {
    for (Limitation l : LIMITATIONS)
      if (l.appliesTo(server, sample) && l.failure() != null && failure.matches(l.failure()))
        return Optional.of(l.why());
    return Optional.empty();
  }

  @FunctionalInterface
  interface Sample {
    void run(Kms kms, String suffix) throws Exception;
  }

  static final Map<String, Sample> SAMPLES = new LinkedHashMap<>();

  static {
    SAMPLES.put(
        "A1 TdeKeyRetrieval",
        (kms, s) -> {
          kms.keys()
              .createAes(256)
              .named("tde-" + s)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
          var loaded = TdeKeyRetrieval.loadByName(kms, "tde-" + s);
          check(loaded.status() == TdeKeyRetrieval.Status.LOADED, "load: " + loaded.detail());
          check(loaded.key().orElseThrow().getEncoded().length == 32, "256-bit key");
          check(
              TdeKeyRetrieval.loadByName(kms, "absent-" + s).status()
                  == TdeKeyRetrieval.Status.MISSING,
              "missing key reported as MISSING");
        });
    SAMPLES.put(
        "A2 EnvelopeEncryption",
        (kms, s) -> {
          CurrentKey kek = kms.keys().current(EnvelopeEncryption.createKek(kms, "kek-" + s));
          byte[] data = "record".getBytes(StandardCharsets.UTF_8);
          byte[] context = ("record-" + s).getBytes(StandardCharsets.UTF_8);
          byte[] stored = EnvelopeEncryption.seal(kek, data, context);
          check(
              Arrays.equals(data, EnvelopeEncryption.open(kek, stored, context)),
              "unwrapped DEK decrypts");
          check(
              Arrays.equals(data, EnvelopeEncryption.openByName(kms, "kek-" + s, stored, context)),
              "opened by the KEK's name");
          try {
            EnvelopeEncryption.open(kek, stored, "other".getBytes(StandardCharsets.UTF_8));
            check(false, "the wrapped DEK is bound to its record context");
          } catch (CryptographicFailureException expected) {
            // the server's tag check refused the other context
          }
        });
    SAMPLES.put(
        "A3 RemoteAead",
        (kms, s) -> {
          KeyHandle key = RemoteAead.createKey(kms, "aead-" + s);
          byte[] aad = "tenant".getBytes(StandardCharsets.UTF_8),
              p = "secret".getBytes(StandardCharsets.UTF_8);
          byte[] stored = RemoteAead.encryptForStorage(key, p, aad);
          check(Arrays.equals(p, RemoteAead.decryptFromStorage(key, stored, aad)), "round trip");
          Ciphertext c = Ciphertext.fromBytes(stored);
          byte[] flipped = c.data();
          flipped[0] ^= 1;
          check(
              RemoteAead.detectsTampering(
                  key,
                  Ciphertext.builder()
                      .keyId(c.keyId())
                      .specName(c.specName())
                      .iv(c.iv())
                      .tag(c.tag())
                      .data(flipped)
                      .build()
                      .toBytes(),
                  aad),
              "tampering detected");
          byte[] relabeled =
              Ciphertext.builder()
                  .keyId(c.keyId())
                  .specName("AES-CTR")
                  .iv(new byte[16])
                  .data(c.data())
                  .build()
                  .toBytes();
          check(
              RemoteAead.detectsTampering(key, relabeled, aad),
              "a relabeled ciphertext is refused");
        });
    SAMPLES.put(
        "A4 RemoteSignVerify",
        (kms, s) -> {
          KeyPairHandle signer =
              RemoteSignVerify.createSigner(kms, "signer-" + s, KeyPairSpec.rsa(2048));
          byte[] m = "message".getBytes(StandardCharsets.UTF_8);
          byte[] sig = RemoteSignVerify.sign(signer, SignatureSpec.rsaPkcs1(Hash.SHA_256), m);
          check(
              RemoteSignVerify.accept(signer, SignatureSpec.rsaPkcs1(Hash.SHA_256), m, sig),
              "VALID");
          check(
              !RemoteSignVerify.accept(
                  signer, SignatureSpec.rsaPkcs1(Hash.SHA_256), "other".getBytes(UTF_8), sig),
              "INVALID is rejected");
          check(
              RemoteSignVerify.verifyLocally(
                  signer, SignatureSpec.rsaPkcs1(Hash.SHA_256), Expect.rsa(2048), m, sig),
              "local JCA verification");
        });
    SAMPLES.put(
        "A5 LifecycleRotation",
        (kms, s) -> {
          KeyHandle key = LifecycleRotation.create(kms, "life-" + s);
          check(key.attributes().state() == KeyState.ACTIVE, "active");
          byte[] aad = "row".getBytes(StandardCharsets.UTF_8),
              data = "old".getBytes(StandardCharsets.UTF_8);
          Ciphertext old = key.encrypt(CipherSpec.aesGcm(), data, aad);
          var rotation = LifecycleRotation.rotate(kms, key, "life-" + s);
          check(rotation.currentAttributes().state() == KeyState.ACTIVE, "replacement active");
          KeyAttributes revoked = LifecycleRotation.retire(key);
          check(revoked.state() == KeyState.DEACTIVATED, "revoked");
          check(
              Arrays.equals(data, LifecycleRotation.readByName(kms, "life-" + s, old, aad)),
              "decrypt by name after rotation");
          Ciphertext moved = LifecycleRotation.reencrypt(rotation, old, aad);
          check(
              Arrays.equals(data, rotation.current().decrypt(moved, aad)),
              "decrypt after rotation and re-encryption");
          LifecycleRotation.destroyRetired(key);
        });
    SAMPLES.put(
        "A6 CertificateStorage",
        (kms, s) -> {
          X509Certificate ca =
              (X509Certificate)
                  CertificateFactory.getInstance("X.509")
                      .generateCertificate(
                          new ByteArrayInputStream(Files.readAllBytes(CERTS.resolve("ca.pem"))));
          CertificateStorage.store(kms, ca, "cert-" + s);
          check(ca.equals(CertificateStorage.load(kms, "cert-" + s)), "same certificate");
        });
    SAMPLES.put(
        "A7 BringYourOwnKey",
        (kms, s) -> {
          KeyGenerator aes = KeyGenerator.getInstance("AES");
          aes.init(256);
          SecretKey secret = aes.generateKey();
          KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
          rsa.initialize(2048);
          KeyPair pair = rsa.generateKeyPair();
          var imported = BringYourOwnKey.importKeys(kms, secret, pair, "byok-" + s);
          check(
              Arrays.equals(
                  secret.getEncoded(),
                  BringYourOwnKey.readSecret(imported.secret(), 256).getEncoded()),
              "secret key");
          check(
              Arrays.equals(
                  pair.getPublic().getEncoded(),
                  BringYourOwnKey.readPublic(imported.publicKey(), Expect.rsa(2048)).getEncoded()),
              "public key");
        });
  }

  static {
    SAMPLES.put(
        "Q Quickstart",
        (kms, s) -> {
          byte[] orderJson = {1, 2, 3};
          check(Arrays.equals(orderJson, Quickstart.sealAndOpen(kms, orderJson)), "first run");
          check(
              Arrays.equals(orderJson, Quickstart.sealAndOpen(kms, orderJson)),
              "second run reuses the key");
        });
  }

  static void check(boolean condition, String what) {
    if (!condition) throw new AssertionError(what);
  }

  static Map<String, List<ProtocolVersion>> versions() {
    Map<String, List<ProtocolVersion>> m = new LinkedHashMap<>();
    m.put("pykmip", List.of(ProtocolVersion.V1_2, ProtocolVersion.V1_4));
    m.put("pqctoday", List.of(ProtocolVersion.V3_0));
    return m;
  }

  /**
   * The expected outcome of every sample on every server and version. PASS must pass; UNSUPPORTED
   * must fail with {@link UnsupportedException} raised by the named operation (so a regression that
   * makes a sample unsupported for another reason fails the build); SERVER_LIMITATION must match
   * {@link #LIMITATIONS}. Any other result, including an unexpected pass, fails the build: update
   * this table deliberately. A value other than PASS holds only where {@link #expectation} finds an
   * SDK refusal or a {@link Limitation} of that server.
   */
  static final Map<String, Map<String, String>> EXPECTED = expected();

  private static Map<String, Map<String, String>> expected() {
    Map<String, Map<String, String>> m = new LinkedHashMap<>();
    String pass = "PASS";
    // AES-GCM needs KMIP 1.4: refused before sending on 1.2.
    String gcmBefore14 = "UNSUPPORTED:encrypt";
    // The same refusal from seal (A2, Q), which reports the method the application called.
    String sealBefore14 = "UNSUPPORTED:seal";
    // PyKMIP does not implement Re-key (Operation Not Supported).
    String noReKey = "UNSUPPORTED:rotate";
    String limitation = "SERVER_LIMITATION";
    m.put(
        "pykmip 1.2",
        row(pass, sealBefore14, gcmBefore14, pass, gcmBefore14, limitation, pass, sealBefore14));
    // From 1.4 sample A2 asks for a non-extractable KEK, which PyKMIP refuses and PQCToday drops.
    m.put("pykmip 1.4", row(pass, limitation, pass, pass, noReKey, limitation, pass, pass));
    // PQCToday returns public keys in a vendor Raw layout it cannot convert to X.509.
    m.put(
        "pqctoday 3.0",
        row(pass, limitation, pass, "UNSUPPORTED:asPublicKey", pass, limitation, pass, pass));
    return m;
  }

  private static Map<String, String> row(String... outcomes) {
    Map<String, String> r = new LinkedHashMap<>();
    List<String> names = new ArrayList<>(SAMPLES.keySet());
    for (int i = 0; i < names.size(); i++) r.put(names.get(i), outcomes[i]);
    return r;
  }

  /**
   * What a sample must do on this server and version: the table value. A value other than PASS
   * must be an SDK refusal at this version or authorized by a {@link Limitation} of this server;
   * otherwise the table is wrong and this throws. Null when the table has no value.
   */
  static String expectation(String server, ProtocolVersion version, String sample) {
    String cell = EXPECTED.getOrDefault(server + " " + version, Map.of()).get(sample);
    if (cell == null || cell.equals("PASS")) return cell;
    ProtocolVersion lifted = SDK_REFUSALS.get(cell);
    if (lifted != null && !version.atLeast(lifted)) return cell;
    for (Limitation l : LIMITATIONS)
      if (l.appliesTo(server, sample) && l.expected().equals(cell)) return cell;
    throw new IllegalStateException(
        server
            + " "
            + version
            + " "
            + sample
            + ": "
            + cell
            + " is backed by no limitation of this server and no SDK refusal");
  }

  /** The expectation an outcome must meet, or a description of how it differs. */
  static Optional<String> mismatch(String server, ProtocolVersion version, Outcome o) {
    String expected = expectation(server, version, o.sample());
    if (expected == null) return Optional.of("no expectation for " + o.sample());
    String actual =
        o.outcome().equals("UNSUPPORTED") ? "UNSUPPORTED:" + o.operation() : o.outcome();
    return expected.equals(actual)
        ? Optional.empty()
        : Optional.of("expected " + expected + ", got " + actual);
  }

  @Test
  void theExpectationTableCoversEverySampleServerAndVersion() {
    for (var server : versions().entrySet())
      for (ProtocolVersion v : server.getValue())
        assertEquals(
            SAMPLES.keySet(),
            EXPECTED.get(server.getKey() + " " + v).keySet(),
            server.getKey() + " " + v);
  }

  @TestFactory
  Stream<DynamicTest> samplesAgainstRealServers() {
    return versions().entrySet().stream()
        .map(
            entry ->
                DynamicTest.dynamicTest(
                    entry.getKey(),
                    () -> {
                      String server = entry.getKey();
                      var image =
                          new ImageFromDockerfile(
                                  "localhost/keytend-" + server + ":integration", false)
                              .withFileFromPath(".", ROOT.resolve("integration/" + server));
                      try (var container =
                          new GenericContainer<>(image)
                              .withExposedPorts(5696)
                              .withCopyFileToContainer(MountableFile.forHostPath(CERTS), "/certs")
                              .withStartupTimeout(Duration.ofMinutes(2))) {
                        container.start();
                        List<String> failures = new ArrayList<>();
                        for (ProtocolVersion version : entry.getValue()) {
                          List<Outcome> outcomes = new ArrayList<>();
                          try (Kms kms =
                              Kms.connect(
                                  tls(server, KmsConfig.builder())
                                      .addEndpoint(
                                          container.getHost(), container.getMappedPort(5696))
                                      .versions(KmipVersion.fromProtocol(version))
                                      .maximumVersion(KmipVersion.fromProtocol(version))
                                      .minimumVersion(KmipVersion.fromProtocol(version))
                                      .poolSize(2)
                                      .build())) {
                            assertEquals(version, kms.version().protocolValue());
                            for (var sample : SAMPLES.entrySet()) {
                              String suffix = UUID.randomUUID().toString().substring(0, 8);
                              try {
                                sample.getValue().run(kms, suffix);
                                outcomes.add(new Outcome(sample.getKey(), "PASS", "", ""));
                              } catch (UnsupportedException e) {
                                outcomes.add(
                                    new Outcome(
                                        sample.getKey(),
                                        "UNSUPPORTED",
                                        e.getMessage(),
                                        e.operation()));
                              } catch (Throwable e) {
                                StringBuilder chain = new StringBuilder(e.toString());
                                for (Throwable c = e.getCause(); c != null; c = c.getCause())
                                  chain.append(" <- ").append(c);
                                Optional<String> known =
                                    limitation(server, sample.getKey(), chain.toString());
                                if (known.isPresent())
                                  outcomes.add(
                                      new Outcome(
                                          sample.getKey(),
                                          "SERVER_LIMITATION",
                                          known.get() + ": " + chain,
                                          ""));
                                else
                                  outcomes.add(
                                      new Outcome(sample.getKey(), "FAIL", chain.toString(), ""));
                              }
                              Outcome last = outcomes.get(outcomes.size() - 1);
                              mismatch(server, version, last)
                                  .ifPresent(
                                      why ->
                                          failures.add(
                                              server
                                                  + " "
                                                  + version
                                                  + " "
                                                  + last.sample()
                                                  + ": "
                                                  + why
                                                  + (last.detail().isEmpty()
                                                      ? ""
                                                      : " (" + last.detail() + ")")));
                            }
                          }
                          write(server, version, outcomes);
                        }
                        assertEquals(List.of(), failures);
                      }
                    }));
  }

  /**
   * The TLS setup, through the {@link KmsConfig} file options an application uses rather than a
   * ready-made {@code SSLContext}, with each server exercising a different combination: PEM
   * identity and PEM trust (PyKMIP), and PKCS#12 identity and PEM trust (PQCToday).
   */
  static KmsConfig.Builder tls(String server, KmsConfig.Builder b) throws Exception {
    Path ca = CERTS.resolve("ca.pem");
    switch (server) {
      case "pykmip" ->
          b.clientIdentityPem(CERTS.resolve("client.pem"), CERTS.resolve("client-key.pem"))
              .trustPem(ca);
      default ->
          b.clientIdentityKeyStore(CERTS.resolve("client.p12"), "changeit".toCharArray())
              .trustPem(ca);
    }
    return b;
  }

  static void write(String server, ProtocolVersion version, List<Outcome> outcomes)
      throws Exception {
    StringBuilder json =
        new StringBuilder(
            "{\n  \"server\": \""
                + server
                + "\",\n  \"version\": \""
                + version
                + "\",\n  \"jdk\": "
                + Runtime.version().feature()
                + ",\n  \"samples\": [\n");
    for (int i = 0; i < outcomes.size(); i++) {
      Outcome o = outcomes.get(i);
      json.append("    {\"sample\": \"")
          .append(o.sample())
          .append("\", \"outcome\": \"")
          .append(o.outcome())
          .append("\", \"operation\": \"")
          .append(o.operation())
          .append("\", \"detail\": \"")
          .append(o.detail().replace("\\", "\\\\").replace("\"", "'").replace("\n", " "))
          .append("\"}")
          .append(i + 1 < outcomes.size() ? ",\n" : "\n");
    }
    json.append("  ]\n}\n");
    Path out =
        ROOT.resolve(
            "integration/reports/kms-samples-"
                + server
                + "-"
                + version
                + "-jdk"
                + Runtime.version().feature()
                + ".json");
    Files.createDirectories(out.getParent());
    Files.writeString(out, json.toString());
  }
}
