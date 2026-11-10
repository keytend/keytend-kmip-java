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

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.Messages;
import dev.keytend.kmip.client.RequestOptions;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.*;
import java.io.ByteArrayInputStream;
import java.nio.file.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Predicate;
import java.util.regex.*;
import org.junit.jupiter.api.Test;

class CatalogContractTest {
  static {
    // CatalogContainersIT.PROFILES (the server/version lanes) lives in a class that reads this.
    if (System.getProperty("project.root") == null)
      System.setProperty("project.root", Path.of("..").toAbsolutePath().normalize().toString());
  }

  @Test
  void everyCatalogIdentityIsRegisteredAndHasAnExplicitImplementation() throws Exception {
    Path root = Path.of(System.getProperty("project.root", ".."));
    assertEquals(145, Catalog.CASES.size());
    byte[] source = Files.readAllBytes(root.resolve("integration/catalog/catalog.json"));
    String expected =
        new String(
                Catalog.class
                    .getResourceAsStream("/dev/keytend/kmip/catalog/source.sha256")
                    .readAllBytes(),
                UTF_8)
            .trim();
    assertEquals(expected, Catalog.digest(source));
    Set<String> implemented = new HashSet<>();
    Pattern id =
        Pattern.compile(
            "\"((?:ENV|TLS|WIRE|VER|DISC|KEY|ASYM|LIFE|AUTH|CRYPTO|BATCH|RETRY|DB|JAVA|OBS|SV)-[A-Z0-9-]+)\"");
    for (Path file :
        List.of(
            root.resolve(
                "integration-tests/src/main/java/dev/keytend/kmip/interop/CatalogLiveSuite.java"),
            root.resolve(
                "integration-tests/src/test/java/dev/keytend/kmip/interop/CatalogPeerIT.java"))) {
      Matcher m = id.matcher(Files.readString(file));
      while (m.find()) implemented.add(m.group(1));
    }
    for (var c : Catalog.CASES)
      assertTrue(implemented.contains(c.id()), "No explicit handler for " + c.id());
    assertTrue(Catalog.CASES.stream().anyMatch(c -> c.id().equals("DB-12")));
    assertTrue(Catalog.CASES.stream().anyMatch(c -> c.id().equals("SV-KR-02")));
  }

  // ----------------------------------------------------------------------------------------------
  // The whole catalog, dry-run against the in-process peer for every lane the live run targets.

  record Lane(String server, ProtocolVersion version) {}

  /**
   * Every server/version tuple of {@link CatalogContainersIT#PROFILES}, and an in-memory lane for
   * each KMIP version no profile runs (2.1), so every version's requests are still checked offline.
   */
  static List<Lane> lanes() {
    List<Lane> lanes = new ArrayList<>();
    Set<ProtocolVersion> covered = EnumSet.noneOf(ProtocolVersion.class);
    for (var profile : CatalogContainersIT.PROFILES)
      for (ProtocolVersion version : profile.versions()) {
        lanes.add(new Lane(profile.id(), version));
        covered.add(version);
      }
    for (ProtocolVersion version : ProtocolVersion.values())
      if (!covered.contains(version)) lanes.add(new Lane("in-memory", version));
    return List.copyOf(lanes);
  }

  private static Map<Lane, List<Map<String, Object>>> dryRuns;

  /** Records of the full catalog per lane; computed once, lanes in parallel. */
  static synchronized Map<Lane, List<Map<String, Object>>> dryRuns() throws Exception {
    if (dryRuns != null) return dryRuns;
    Path certs = CatalogDryRun.certificates();
    List<Lane> lanes = lanes();
    ExecutorService pool =
        Executors.newFixedThreadPool(
            Math.max(2, Math.min(lanes.size(), Runtime.getRuntime().availableProcessors() / 2)));
    try {
      Map<Lane, Future<List<Map<String, Object>>>> pending = new LinkedHashMap<>();
      for (Lane lane : lanes)
        pending.put(
            lane,
            pool.submit(
                () -> {
                  try (var dry = new CatalogDryRun(lane.server(), lane.version(), certs)) {
                    @SuppressWarnings("unchecked")
                    var records =
                        (List<Map<String, Object>>)
                            new CatalogLiveSuite(dry.fixture).run().get("records");
                    return records;
                  }
                }));
      Map<Lane, List<Map<String, Object>>> result = new LinkedHashMap<>();
      for (var e : pending.entrySet())
        result.put(e.getKey(), e.getValue().get(5, TimeUnit.MINUTES));
      return dryRuns = result;
    } finally {
      pool.shutdownNow();
    }
  }

  static Map<String, Object> recordOf(List<Map<String, Object>> records, String id) {
    return records.stream().filter(r -> r.get("test_id").equals(id)).findFirst().orElseThrow();
  }

  /**
   * Every fixture request in the catalog is built, version-checked and encoded for every
   * version a live lane targets, without a server. A request the SDK refuses to build is a
   * FAIL_CLIENT record (LIFE-06 was one once Create required a usage), so this fails on
   * any of them and names the case.
   */
  @Test
  void everyFixtureRequestBuildsForEveryTargetedVersion() throws Exception {
    List<String> unbuilt = new ArrayList<>();
    for (var e : dryRuns().entrySet())
      for (var r : e.getValue()) {
        @SuppressWarnings("unchecked")
        var evidence = (Map<String, Object>) r.get("case_parameters");
        if (Boolean.TRUE.equals(evidence.get("local_request_construction")))
          unbuilt.add(e.getKey() + " " + r.get("test_id") + ": " + r.get("reason"));
      }
    assertEquals(List.of(), unbuilt);
    // The dry run must reach the requests that matter, not stop early: the read-only role tries
    // all its writes (LIFE-06), and the certificate and wrapping fixtures complete.
    for (var e : dryRuns().entrySet()) {
      for (String id : List.of("LIFE-06", "ASYM-04", "ASYM-05", "KEY-07"))
        assertEquals("PASS", recordOf(e.getValue(), id).get("outcome"), e.getKey() + " " + id);
      if (e.getKey().version().atLeast(ProtocolVersion.V1_2))
        assertEquals("PASS", recordOf(e.getValue(), "ASYM-07").get("outcome"), e.getKey() + "");
    }
  }

  /**
   * Cleanup has 8 s plus 250 ms for each run-owned object, at most 60 s. A 2.x run owns about 90
   * objects; at 45 ms for each Revoke and each Destroy that is about 8 s of work, which the earlier
   * flat 8 s did not cover.
   */
  @Test
  void cleanupBudgetGrowsWithTheOwnedObjectsAndIsBounded() {
    assertEquals(java.time.Duration.ofSeconds(8), CatalogFixture.cleanupBudget(0));
    assertEquals(java.time.Duration.ofMillis(29_500), CatalogFixture.cleanupBudget(86));
    assertTrue(
        CatalogFixture.cleanupBudget(90).compareTo(java.time.Duration.ofMillis(90 * 2 * 45 * 2))
            > 0,
        "twice the work of 90 objects at 45 ms an operation");
    assertEquals(java.time.Duration.ofSeconds(60), CatalogFixture.cleanupBudget(208));
    assertEquals(java.time.Duration.ofSeconds(60), CatalogFixture.cleanupBudget(10_000));
  }

  /** Only a request the SDK refused to build or send is classified as a local failure. */
  @Test
  void onlyRequestConstructionFailuresAreClassifiedAsLocal() throws Exception {
    var unusable =
        assertThrows(
            IllegalArgumentException.class,
            () -> Requests.createSymmetricKey(Enums.CryptographicAlgorithm.AES, 128));
    assertTrue(CatalogLiveSuite.builtLocally(unusable), "builder precondition");
    var wrongVersion =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                Messages.request(
                    ProtocolVersion.V3_0,
                    List.of(
                        Requests.locate()
                            .attribute(
                                Attributes.attribute("Object Group", text(OBJECT_GROUP, "g")))
                            .build()),
                    RequestOptions.DEFAULT));
    assertTrue(CatalogLiveSuite.builtLocally(wrongVersion), "version validation before sending");
    var unconsumable =
        assertThrows(
            RuntimeException.class, () -> Keys.aesKey(structure(RESPONSE_PAYLOAD), "id", 256));
    assertFalse(CatalogLiveSuite.builtLocally(unconsumable), "response consumption");
    assertFalse(
        CatalogLiveSuite.builtLocally(new IllegalArgumentException("fixture's own check")),
        "thrown by the fixture itself");
  }

  // ----------------------------------------------------------------------------------------------

  /** Rejections are attributed as unreviewed, never automatically as server faults. */
  @Test
  void failuresAreNotAttributedToTheServerWithoutReview() {
    assertTrue(
        CatalogLiveSuite.attribution(Catalog.Outcome.FAIL_SERVER, null).startsWith("unreviewed"));
    assertEquals("unreviewed", CatalogLiveSuite.reviewStatus(Catalog.Outcome.FAIL_SERVER));
    assertTrue(CatalogLiveSuite.failureAttribution(7).contains("client or fixture suspected"));
    assertFalse(CatalogLiveSuite.failureAttribution(1).contains("suspected"));
  }

  /**
   * Every record the suite writes carries {@code attribution} and {@code review_status},
   * consistent with its outcome, and the written report keeps them.
   */
  @Test
  void everyRecordCarriesAttributionAndReviewStatus() throws Exception {
    Set<String> outcomes = new TreeSet<>();
    for (var e : dryRuns().entrySet())
      for (var r : e.getValue()) {
        String where = e.getKey() + " " + r.get("test_id");
        assertTrue(r.get("attribution") instanceof String a && !a.isBlank(), where);
        assertTrue(r.get("review_status") instanceof String s && !s.isBlank(), where);
        String outcome = (String) r.get("outcome"), attribution = (String) r.get("attribution");
        outcomes.add(outcome);
        switch (Catalog.Outcome.valueOf(outcome)) {
          case FAIL_SERVER -> {
            assertEquals("unreviewed", r.get("review_status"), where);
            assertTrue(attribution.startsWith("unreviewed"), where);
          }
          case PASS -> assertEquals("none", attribution, where);
          case FAIL_CLIENT -> assertEquals("n/a", r.get("review_status"), where);
          default -> assertEquals("not a fault", attribution, where);
        }
        String json = Catalog.json(r);
        assertTrue(json.contains("\"attribution\":") && json.contains("\"review_status\":"));
      }
    assertTrue(
        outcomes.containsAll(Set.of("PASS", "FAIL_SERVER", "BLOCKED_ENV", "NOT_APPLICABLE")),
        "the dry run exercises the main outcome kinds: " + outcomes);
  }

  // ----------------------------------------------------------------------------------------------
  // Fixture request shapes, checked on the built requests.

  static List<ProtocolVersion> versions() {
    return lanes().stream().map(Lane::version).distinct().sorted().toList();
  }

  static Ttlv payload(Ttlv message, String side) {
    return message
        .require(BATCH_ITEM)
        .require(side.equals("request") ? REQUEST_PAYLOAD : RESPONSE_PAYLOAD);
  }

  static int operation(Ttlv request) {
    return request.require(BATCH_ITEM).require(OPERATION).intValue();
  }

  /**
   * The value of attribute {@code tag} in a Register payload: a 1.x Template-Attribute's
   * Attribute named {@code name}, or the 2.x/3.0 Attributes member.
   */
  static Optional<Ttlv> attribute(Ttlv payload, Tag tag, String name) {
    Optional<Ttlv> legacy = payload.child(TEMPLATE_ATTRIBUTE);
    if (legacy.isPresent())
      return legacy.get().children(ATTRIBUTE).stream()
          .filter(a -> a.require(ATTRIBUTE_NAME).textValue().equals(name))
          .map(a -> a.require(ATTRIBUTE_VALUE))
          .findFirst();
    return payload.child(ATTRIBUTES).flatMap(a -> a.child(tag));
  }

  static CatalogDryRun.Exchange only(
      List<CatalogDryRun.Exchange> exchanges, String what, Predicate<CatalogDryRun.Exchange> test) {
    var found = exchanges.stream().filter(test).toList();
    assertEquals(1, found.size(), what);
    return found.get(0);
  }

  /**
   * The wrapping fixtures register the KEK with a NIST Key Wrap Cryptographic
   * Parameters instance (KMIP 1.4 §2.1.6 requires the requested mode to match one) and request
   * the wrapped Get with Encrypt, that KEK and parameters, and NoEncoding, on every version
   * including 1.1.
   */
  @Test
  void wrappingFixtureStoresAndRequestsNistKeyWrap() throws Exception {
    int wrap =
        UsageMask.of(Enums.CryptographicUsageMask.WRAP_KEY, Enums.CryptographicUsageMask.UNWRAP_KEY)
            .toInt();
    for (ProtocolVersion version : versions())
      try (var dry = new CatalogDryRun("dry-run", version, CatalogDryRun.certificates())) {
        var exchanges = dry.exchangesOf("KEY-07");
        var kek =
            only(
                exchanges,
                version + " KEK Register",
                x ->
                    operation(x.request()) == Operation.REGISTER.code()
                        && attribute(
                                    payload(x.request(), "request"),
                                    CRYPTOGRAPHIC_USAGE_MASK,
                                    "Cryptographic Usage Mask")
                                .map(Ttlv::intValue)
                                .orElse(0)
                            == wrap);
        Ttlv parameters =
            attribute(
                    payload(kek.request(), "request"),
                    CRYPTOGRAPHIC_PARAMETERS,
                    "Cryptographic Parameters")
                .orElseThrow(() -> new AssertionError(version + ": KEK has no parameters"));
        assertEquals(
            Enums.BlockCipherMode.NISTKEY_WRAP.code(),
            parameters.require(BLOCK_CIPHER_MODE).intValue(),
            version + " stored mode");
        String kekId = payload(kek.response(), "response").require(UNIQUE_IDENTIFIER).textValue();
        var get =
            only(
                exchanges,
                version + " wrapped Get",
                x ->
                    operation(x.request()) == Operation.GET.code()
                        && payload(x.request(), "request")
                            .child(KEY_WRAPPING_SPECIFICATION)
                            .isPresent());
        Ttlv spec = payload(get.request(), "request").require(KEY_WRAPPING_SPECIFICATION);
        assertEquals(Enums.WrappingMethod.ENCRYPT.code(), spec.require(WRAPPING_METHOD).intValue());
        Ttlv key = spec.require(ENCRYPTION_KEY_INFORMATION);
        assertEquals(kekId, key.require(UNIQUE_IDENTIFIER).textValue(), version + " KEK id");
        assertEquals(
            Enums.BlockCipherMode.NISTKEY_WRAP.code(),
            key.require(CRYPTOGRAPHIC_PARAMETERS).require(BLOCK_CIPHER_MODE).intValue(),
            version + " requested mode");
        assertEquals(
            Enums.EncodingOption.NO_ENCODING.code(),
            spec.require(ENCODING_OPTION).intValue(),
            version + " NoEncoding (also on 1.1)");
      }
  }

  /**
   * Every certificate the fixtures register carries the Register attributes KMIP 1.1
   * Table 129 lists for certificates: the subject key's algorithm and length, the certificate
   * length, and the usage its X.509 Key Usage grants as KMIP 1.4 Table 96 maps it (certificate
   * and CRL signing for the keyCertSign and cRLSign CA, verification and key wrapping for the
   * digitalSignature and keyEncipherment leaf, verification for the EC certificate without the
   * extension). An EC subject is EC where the version defines it and ECDSA before. The in-memory
   * server refuses a 1.x mask that claims more than the extension grants, so ASYM-04 passing on
   * every lane also checks that.
   */
  @Test
  void certificatesRegisterWithTheRequiredAttributes() throws Exception {
    var factory = CertificateFactory.getInstance("X.509");
    X509Certificate ec;
    try (var in = Files.newInputStream(CatalogDryRun.certificates().resolve("ec.der"))) {
      ec = (X509Certificate) factory.generateCertificate(in);
    }
    for (ProtocolVersion version : versions())
      try (var dry = new CatalogDryRun("dry-run", version, CatalogDryRun.certificates())) {
        var exchanges = new ArrayList<>(dry.exchangesOf("ASYM-04"));
        int before = dry.exchanges.size();
        CatalogObjects.registerCertificate(new CatalogLiveSuite(dry.fixture), ec);
        exchanges.addAll(dry.exchanges.subList(before, dry.exchanges.size()));
        var registers =
            exchanges.stream()
                .map(CatalogDryRun.Exchange::request)
                .filter(r -> operation(r) == Operation.REGISTER.code())
                .map(r -> payload(r, "request"))
                .filter(
                    p -> p.require(OBJECT_TYPE).intValue() == Enums.ObjectType.CERTIFICATE.code())
                .toList();
        assertEquals(3, registers.size(), version + ": leaf, CA and EC subject");
        Set<Boolean> authorities = new HashSet<>();
        for (Ttlv p : registers) {
          byte[] der = p.require(CERTIFICATE).require(CERTIFICATE_VALUE).bytesValue();
          var cert = (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der));
          boolean authority = cert.getBasicConstraints() >= 0;
          authorities.add(authority);
          int algorithm, bits;
          if (cert.getPublicKey() instanceof RSAPublicKey rsa) {
            algorithm = Enums.CryptographicAlgorithm.RSA.code();
            bits = rsa.getModulus().bitLength();
          } else {
            algorithm =
                (version.atLeast(Enums.CryptographicAlgorithm.EC.since())
                        ? Enums.CryptographicAlgorithm.EC
                        : Enums.CryptographicAlgorithm.ECDSA)
                    .code();
            bits =
                ((java.security.interfaces.ECPublicKey) cert.getPublicKey())
                    .getParams()
                    .getCurve()
                    .getField()
                    .getFieldSize();
          }
          String where = version + " " + cert.getSubjectX500Principal();
          assertEquals(
              algorithm, value(p, CRYPTOGRAPHIC_ALGORITHM, "Cryptographic Algorithm"), where);
          assertEquals(bits, value(p, CRYPTOGRAPHIC_LENGTH, "Cryptographic Length"), where);
          assertEquals(der.length, value(p, CERTIFICATE_LENGTH, "Certificate Length"), where);
          assertEquals(
              (authority
                      ? UsageMask.of(
                          Enums.CryptographicUsageMask.CERTIFICATE_SIGN,
                          Enums.CryptographicUsageMask.CRL_SIGN)
                      : cert.getKeyUsage() == null
                          ? UsageMask.of(Enums.CryptographicUsageMask.VERIFY)
                          : UsageMask.of(
                              Enums.CryptographicUsageMask.VERIFY,
                              Enums.CryptographicUsageMask.WRAP_KEY))
                  .toInt(),
              value(p, CRYPTOGRAPHIC_USAGE_MASK, "Cryptographic Usage Mask"),
              where);
        }
        assertEquals(Set.of(true, false), authorities, version + ": a CA and leaves");
      }
  }

  static int value(Ttlv payload, Tag tag, String name) {
    return attribute(payload, tag, name)
        .orElseThrow(() -> new AssertionError("Missing " + name))
        .intValue();
  }

  /**
   * DISC-07 stores its opaque identifier with an Import that restores a real Export
   * (KMIP 1.4 §4.41), not a Register with a chosen ID. The dry run answers the Export with the
   * object and its attributes ({@link CatalogDryRun}), and this checks the Import the fixture sends
   * on every version that has Import: the opaque identifier replaces the exported one; Object
   * Type, Replace Existing=false and the exported object are carried over; the attributes are all
   * of the export's own, as repeated Attribute fields on 1.4 and as one Attributes structure on 2.x
   * and 3.0, with the Unique Identifier attribute set to the opaque identifier and a Short Unique
   * Identifier set to its SHA-256 (KMIP 2.1 §4.56). Before 1.4 nothing is exported or imported.
   */
  @Test
  void opaqueIdentifierImportRestoresAnExport() throws Exception {
    Set<ProtocolVersion> checked = new HashSet<>();
    for (ProtocolVersion version : versions())
      try (var dry = new CatalogDryRun("dry-run", version, CatalogDryRun.certificates())) {
        var exchanges = dry.exchangesOf("DISC-07");
        if (!version.atLeast(ProtocolVersion.V1_4)) {
          assertTrue(
              exchanges.stream()
                  .noneMatch(
                      x ->
                          operation(x.request()) == Operation.EXPORT.code()
                              || operation(x.request()) == Operation.IMPORT.code()),
              version + ": Import needs 1.4");
          continue;
        }
        checked.add(version);
        var export =
            only(
                exchanges,
                version + " Export",
                x -> operation(x.request()) == Operation.EXPORT.code());
        var imported =
            only(
                exchanges,
                version + " Import",
                x -> operation(x.request()) == Operation.IMPORT.code());
        assertTrue(
            exchanges.indexOf(export) < exchanges.indexOf(imported), version + ": export first");
        Ttlv exported = payload(export.response(), "response");
        Ttlv p = payload(imported.request(), "request");
        String source = exported.require(UNIQUE_IDENTIFIER).textValue();
        String uid = p.require(UNIQUE_IDENTIFIER).textValue();
        assertTrue(uid.endsWith(":雪:" + "x".repeat(256)), version + ": opaque identifier " + uid);
        assertNotEquals(source, uid, version + ": not the exported identifier");
        List<Integer> order = p.children().stream().map(Ttlv::tag).toList();
        assertEquals(
            List.of(UNIQUE_IDENTIFIER.code(), OBJECT_TYPE.code(), REPLACE_EXISTING.code()),
            order.subList(0, 3),
            version + ": Import field order");
        assertEquals(exported.require(OBJECT_TYPE), p.require(OBJECT_TYPE), version + ": type");
        assertFalse(p.require(REPLACE_EXISTING).booleanValue(), version + ": no replace");
        Ttlv key = exported.require(SYMMETRIC_KEY);
        assertEquals(
            key, p.children().get(p.children().size() - 1), version + ": exported object last");
        assertTrue(p.child(TEMPLATE_ATTRIBUTE).isEmpty(), version + ": no Template-Attribute");
        if (version.atLeast(ProtocolVersion.V2_0)) {
          assertTrue(p.children(ATTRIBUTE).isEmpty(), version + ": no 1.x Attribute fields");
          assertEquals(1, p.children(ATTRIBUTES).size(), version + ": one Attributes structure");
          List<Ttlv> sent = p.require(ATTRIBUTES).children();
          byte[] shortId =
              java.security.MessageDigest.getInstance("SHA-256")
                  .digest(uid.getBytes(java.nio.charset.StandardCharsets.UTF_8));
          List<Ttlv> expected =
              exported.require(ATTRIBUTES).children().stream()
                  .map(
                      a ->
                          a.tag() == UNIQUE_IDENTIFIER.code()
                              ? (a.type() == Ttlv.Type.IDENTIFIER
                                  ? identifier(UNIQUE_IDENTIFIER, uid)
                                  : text(UNIQUE_IDENTIFIER, uid))
                              : a.tag() == SHORT_UNIQUE_IDENTIFIER.code()
                                  ? bytes(SHORT_UNIQUE_IDENTIFIER, shortId)
                                  : a)
                  .toList();
          assertEquals(expected, sent, version + ": the export's attributes, renamed");
          assertEquals(
              uid, p.require(ATTRIBUTES).require(UNIQUE_IDENTIFIER).textValue(), version + ": UID");
          assertTrue(
              sent.stream().anyMatch(a -> a.tag() == CRYPTOGRAPHIC_ALGORITHM.code()),
              version + ": complete attributes");
        } else {
          assertTrue(p.child(ATTRIBUTES).isEmpty(), version + ": no 2.x Attributes");
          List<Ttlv> sent = p.children(ATTRIBUTE);
          List<Ttlv> expected =
              exported.children(ATTRIBUTE).stream()
                  .map(
                      a ->
                          a.require(ATTRIBUTE_NAME).textValue().equals("Unique Identifier")
                              ? structure(
                                  ATTRIBUTE,
                                  a.children().stream()
                                      .map(
                                          c ->
                                              c.tag() == ATTRIBUTE_VALUE.code()
                                                  ? text(ATTRIBUTE_VALUE, uid)
                                                  : c)
                                      .toList())
                              : a)
                  .toList();
          assertEquals(expected, sent, version + ": the export's attributes, renamed");
          assertTrue(
              sent.stream()
                  .anyMatch(
                      a ->
                          a.require(ATTRIBUTE_NAME).textValue().equals("Unique Identifier")
                              && a.require(ATTRIBUTE_VALUE).textValue().equals(uid)),
              version + ": UID");
          assertTrue(
              sent.stream()
                  .anyMatch(
                      a -> a.require(ATTRIBUTE_NAME).textValue().equals("Cryptographic Algorithm")),
              version + ": complete attributes");
        }
      }
    assertTrue(
        checked.containsAll(
            Set.of(ProtocolVersion.V1_4, ProtocolVersion.V2_0, ProtocolVersion.V2_1)),
        "1.4 and 2.x lanes checked: " + checked);
  }
}
