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

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.TestKmipServer;
import dev.keytend.kmip.TestTls;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.time.Instant;
import java.util.*;
import javax.crypto.KeyGenerator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** The application API: keys, attributes, lookups and lifecycle. */
class KmsApiTest {
  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  Kms connect(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    servers.add(server);
    Kms kms = server.connect();
    clients.add(kms);
    return kms;
  }

  Kms connect(InMemoryKmipServer server, KmipTransport transport) {
    servers.add(server);
    Kms kms = Kms.connect(server.configure().transport(e -> transport).build());
    clients.add(kms);
    return kms;
  }

  InMemoryKmipServer last() {
    return servers.get(servers.size() - 1);
  }

  long sent(Operation op) {
    return last().protocolRequests().stream()
        .flatMap(r -> r.children(Tag.BATCH_ITEM).stream())
        .filter(b -> b.require(Tag.OPERATION).intValue() == op.code())
        .count();
  }

  static KeyHandle aes(Kms kms, String name) {
    return kms.keys()
        .createAes(256)
        .named(name)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .create();
  }

  // ---- TLS settings in KmsConfig ----

  @Test
  void tlsIdentityAndTrustFromPkcs12PemAndKeyStores(@TempDir Path dir) throws Exception {
    InMemoryKmipServer kmip = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (TestKmipServer tls =
        new TestKmipServer(
            "server",
            request -> {
              try {
                return kmip.exchange(request);
              } catch (IOException e) {
                throw new UncheckedIOException(e);
              }
            })) {
      char[] password = "changeit".toCharArray();
      KeyStore client = TestTls.identity("client");
      Path p12 = dir.resolve("client.p12");
      try (OutputStream out = Files.newOutputStream(p12)) {
        client.store(out, password);
      }
      Path chain = dir.resolve("client.pem"),
          key = dir.resolve("client.key"),
          ca = dir.resolve("ca.pem");
      Files.writeString(chain, pem("CERTIFICATE", client.getCertificate("client").getEncoded()));
      Files.writeString(key, pem("PRIVATE KEY", client.getKey("client", password).getEncoded()));
      Files.writeString(ca, pem("CERTIFICATE", TestTls.certificate("server").getEncoded()));
      Path encryptedKey = dir.resolve("client-encrypted.key");
      Files.writeString(
          encryptedKey,
          pem(
              "ENCRYPTED PRIVATE KEY",
              KmsConfigValidationTest.encrypt(
                  client.getKey("client", password).getEncoded(),
                  "key password",
                  KmsConfigValidationTest.PBES2)));
      KeyStore trust = KeyStore.getInstance("PKCS12");
      trust.load(null, null);
      trust.setCertificateEntry("ca", TestTls.certificate("server"));
      List<KmsConfig.Builder> configs =
          List.of(
              KmsConfig.builder().clientIdentityKeyStore(p12, password).trustPem(ca),
              KmsConfig.builder().clientIdentityPem(chain, key).trustPem(ca),
              KmsConfig.builder()
                  .clientIdentityPem(chain, encryptedKey, "key password".toCharArray())
                  .trustPem(ca),
              KmsConfig.builder().clientIdentity(client, password).trustStore(trust));
      for (KmsConfig.Builder b : configs)
        try (Kms kms =
            Kms.connect(
                b.endpoints("localhost:" + tls.port()).maximumVersion(KmipVersion.V2_1).build())) {
          assertEquals(KmipVersion.V2_1, kms.version());
          assertEquals(KeyState.ACTIVE, aes(kms, "tls").attributes().state());
        }
      // The JDK's default trust does not know this test CA: the handshake is refused.
      try (var unused = (AutoCloseable) () -> {}) {
        assertThrows(
            PermissionDeniedException.class,
            () ->
                Kms.connect(
                    KmsConfig.builder()
                        .clientIdentityKeyStore(p12, password)
                        .trustSystemDefaults()
                        .endpoints("localhost:" + tls.port())
                        .build()));
      }
    }
  }

  @Test
  void tlsConfigurationErrorsAreClearAndUnchecked(@TempDir Path dir) throws Exception {
    char[] password = "changeit".toCharArray();
    Path p12 = dir.resolve("client.p12");
    try (OutputStream out = Files.newOutputStream(p12)) {
      TestTls.identity("client").store(out, password);
    }
    var wrong =
        assertThrows(
            IllegalArgumentException.class,
            () -> KmsConfig.builder().clientIdentityKeyStore(p12, "nope".toCharArray()));
    assertTrue(wrong.getMessage().contains(p12.toString()), wrong.getMessage());
    var missing =
        assertThrows(
            IllegalArgumentException.class,
            () -> KmsConfig.builder().trustPem(dir.resolve("absent.pem")));
    assertTrue(missing.getMessage().contains("absent.pem"));
    Path encrypted = dir.resolve("enc.key");
    Files.writeString(
        encrypted,
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n");
    Path chain = dir.resolve("c.pem");
    Files.writeString(chain, pem("CERTIFICATE", TestTls.certificate("client").getEncoded()));
    var pkcs8 =
        assertThrows(
            IllegalArgumentException.class,
            () -> KmsConfig.builder().clientIdentityPem(chain, encrypted));
    assertTrue(
        pkcs8.getMessage().contains("encrypted private key: pass its password"),
        pkcs8.getMessage());
    assertThrows(
        IllegalArgumentException.class,
        () -> KmsConfig.builder().endpoints("kms").build(),
        "no TLS");
  }

  static String pem(String type, byte[] der) {
    return "-----BEGIN "
        + type
        + "-----\n"
        + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII)).encodeToString(der)
        + "\n-----END "
        + type
        + "-----\n";
  }

  // ---- KmsConfig getters, toBuilder and IPv6 endpoints ----

  @Test
  void configurationIsReadableCopyableAndTakesIpv6Endpoints() {
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("[2001:db8::1]:5697", "[::1]", "kms.example.com")
            .transport(e -> null)
            .minimumVersion(KmipVersion.V1_2)
            .callTimeout(java.time.Duration.ofSeconds(7))
            .usernamePassword("app", "secret".toCharArray())
            .build();
    assertEquals(
        List.of(
            new KmsConfig.Endpoint("2001:db8::1", 5697),
            new KmsConfig.Endpoint("::1", 5696),
            new KmsConfig.Endpoint("kms.example.com", 5696)),
        config.endpoints());
    assertEquals("[2001:db8::1]:5697", config.endpoints().get(0).toString());
    assertEquals(KmipVersion.V1_2, config.minimumVersion());
    assertEquals(KmipVersion.V2_1, config.maximumVersion());
    assertEquals(java.time.Duration.ofSeconds(7), config.callTimeout());
    assertEquals(KmsConfig.Authentication.PASSWORD, config.authentication());
    assertEquals(Optional.of("app"), config.username());
    KmsConfig changed = config.toBuilder().callTimeout(java.time.Duration.ofSeconds(9)).build();
    assertEquals(java.time.Duration.ofSeconds(9), changed.callTimeout());
    assertEquals(config.endpoints(), changed.endpoints());
    assertEquals(
        java.time.Duration.ofSeconds(7), config.callTimeout(), "the original is unchanged");
    assertThrows(
        IllegalArgumentException.class, () -> KmsConfig.builder().endpoints("2001:db8::1:5696"));
  }

  // ---- testability ----

  @Test
  void applicationsCanConstructEveryFailureAndUseTheInMemoryServer() {
    List<KmsException> made =
        List.of(
            new NotFoundException("gone"),
            new PermissionDeniedException("no"),
            new InvalidRequestException("bad"),
            new UnsupportedException("old"),
            new StateConflictException("state"),
            new AlreadyExistsException("twice"),
            new CryptographicFailureException(
                "tag", CryptographicFailureException.Kind.AUTHENTICATION_FAILED),
            new KeyMismatchException("other"),
            new ServerFailureException("boom"),
            new TransientException("later", new IOException("x")),
            new OutcomeUnknownException("maybe"),
            new ProtocolViolationException("odd"));
    for (KmsException e : made) {
      assertEquals(e instanceof TransientException, e.retryable());
      assertEquals("", e.operation());
      assertTrue(e.protocolReason().isEmpty());
    }
    Kms kms = connect(KmipVersion.V2_1);
    KeyHandle key = aes(kms, "app");
    var partial = new PartialCompletionException("half", List.of(key), new TransientException("x"));
    assertEquals(List.of(key), partial.created());
  }

  // ---- findByName and retrieval states ----

  @Test
  void findByNameWantsAnActiveKeyAndRetrievalRefusesCompromisedKeys() {
    Kms kms = connect(KmipVersion.V2_1);
    KeyHandle key = aes(kms, "tde");
    long locates = sent(Operation.LOCATE), reads = sent(Operation.GET_ATTRIBUTES);
    assertEquals(Optional.of(key), kms.keys().findByName("tde"));
    assertEquals(locates + 1, sent(Operation.LOCATE), "one state-filtered Locate");
    assertEquals(reads, sent(Operation.GET_ATTRIBUTES), "no attribute reads");
    key.revoke(RevocationReason.keyCompromise("leaked", Instant.parse("2026-10-01T12:00:00.5Z")));
    assertEquals(
        Optional.empty(), kms.keys().findByName("tde"), "a Compromised key is not returned");
    assertEquals(Optional.of(key), kms.keys().findByName("tde", KeyState.COMPROMISED));
    var refused =
        assertThrows(
            StateConflictException.class, () -> key.asSecretKey(Expect.aes(256), LocalUse.DECRYPT));
    assertTrue(refused.getMessage().contains("allowingCompromised"), refused.getMessage());
    // The one opt-in is the handle view, not Expect.
    assertEquals(
        32,
        key.allowingCompromised()
            .asSecretKey(Expect.aes(256), LocalUse.DECRYPT)
            .getEncoded()
            .length);
    assertEquals(
        Optional.of(Instant.parse("2026-10-01T12:00:00Z")),
        last()
            .protocolAttributes(key.id())
            .getOrDefault("Compromise Occurrence Date", List.of())
            .stream()
            .findFirst()
            .map(Ttlv::instantValue),
        "the compromise occurrence date is the caller's");
    // At least one state is a compile-time requirement now; a null state is refused.
    assertThrows(NullPointerException.class, () -> kms.keys().findByName("tde", (KeyState) null));
  }

  // ---- findOrCreate and AlreadyExists ----

  @Test
  void findOrCreateIsIdempotentAndRecoversFromUnknownOutcomes() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    boolean[] loseCreateReply = {false};
    Kms kms =
        connect(
            server,
            request -> {
              Ttlv response = server.exchange(request);
              if (loseCreateReply[0] && Faults.operation(request) == Operation.CREATE.code()) {
                loseCreateReply[0] = false;
                throw new java.net.SocketTimeoutException("reply lost");
              }
              return response;
            });
    KeyCreation creation = kms.keys().createAes(256).named("idem").usages(KeyUsage.ENCRYPT);
    KeyHandle first = creation.findOrCreate();
    KeyHandle second =
        kms.keys().createAes(256).named("idem").usages(KeyUsage.ENCRYPT).findOrCreate();
    assertEquals(first, second);
    assertEquals(1, sent(Operation.CREATE), "running twice creates one key");
    // The Create took effect but its reply was lost: the name is looked up instead of creating
    // again.
    loseCreateReply[0] = true;
    KeyHandle recovered =
        kms.keys().createAes(128).named("lost").usages(KeyUsage.ENCRYPT).findOrCreate();
    assertEquals(2, sent(Operation.CREATE));
    assertEquals(KeyState.ACTIVE, recovered.attributes().state());
    // A Pre-Active leftover is activated rather than duplicated.
    KeyHandle leftover =
        kms.keys().createAes(256).named("leftover").usages(KeyUsage.ENCRYPT).createPreActive();
    assertEquals(
        leftover,
        kms.keys().createAes(256).named("leftover").usages(KeyUsage.ENCRYPT).findOrCreate());
    assertEquals(KeyState.ACTIVE, leftover.attributes().state());
    // A key of another size with the name is not silently used.
    assertThrows(
        KeyMismatchException.class,
        () -> kms.keys().createAes(128).named("idem").usages(KeyUsage.ENCRYPT).findOrCreate());
    assertThrows(
        IllegalArgumentException.class,
        () -> kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).findOrCreate());
  }

  @Test
  void aServerThatEnforcesUniqueNamesReportsAlreadyExists() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Set<String> names = new HashSet<>();
    Kms kms =
        connect(
            server,
            request -> {
              if (Faults.operation(request) == Operation.CREATE.code()) {
                String name = mentions(request, "unique") ? "unique" : null;
                if (name != null && !names.add(name))
                  return Faults.failure(
                      request, Enums.ResultReason.NON_UNIQUE_NAME_ATTRIBUTE, "taken");
              }
              return server.exchange(request);
            });
    aes(kms, "unique");
    var e = assertThrows(AlreadyExistsException.class, () -> aes(kms, "unique"));
    assertInstanceOf(StateConflictException.class, e);
    assertEquals(Optional.of(Enums.ResultReason.NON_UNIQUE_NAME_ATTRIBUTE), e.protocolReason());
    // findOrCreate treats it as "someone else created it" and finds that key.
    assertEquals(
        kms.keys().findByName("unique").orElseThrow(),
        kms.keys()
            .createAes(256)
            .named("unique")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .findOrCreate());
  }

  static boolean mentions(Ttlv t, String text) {
    if (t.type() == Ttlv.Type.STRUCTURE)
      return t.children().stream().anyMatch(c -> mentions(c, text));
    return t.type() == Ttlv.Type.TEXT_STRING && t.textValue().equals(text);
  }

  // ---- Secret Data ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void passwordsAndTokensAreSecretData(KmipVersion version) {
    Kms kms = connect(version);
    char[] password = "pä55wörd".toCharArray();
    KeyHandle stored = kms.keys().registerSecret(password).named("db-password").register();
    Arrays.fill(password, '\0');
    assertEquals(Optional.of(ObjectKind.SECRET_DATA), stored.knownKind());
    try (SecretData secret = kms.keys().findByName("db-password").orElseThrow().asSecretData()) {
      assertEquals(SecretData.Type.PASSWORD, secret.type());
      assertArrayEquals("pä55wörd".toCharArray(), secret.chars());
      secret.destroy();
      assertThrows(IllegalStateException.class, secret::bytes);
    }
    byte[] token = {1, 2, 3, 4};
    KeyHandle t =
        kms.keys()
            .registerSecret(SecretData.Type.PASSWORD, token)
            .named("api-token")
            .registerPreActive();
    try (SecretData secret = t.asSecretData()) {
      assertEquals(SecretData.Type.PASSWORD, secret.type());
      assertArrayEquals(new byte[] {1, 2, 3, 4}, secret.bytes());
    }
    KeyHandle seed =
        kms.keys().registerSecret(SecretData.Type.SEED, token).named("seed").register();
    try (SecretData secret = seed.asSecretData()) {
      assertEquals(SecretData.Type.SEED, secret.type());
    }
    assertThrows(
        IllegalArgumentException.class,
        () -> kms.keys().registerSecret(SecretData.Type.OTHER, token),
        "OTHER");
    assertThrows(
        KeyMismatchException.class,
        () -> t.asSecretKey(Expect.aes(256), LocalUse.DECRYPT),
        "known kind");
  }

  // ---- builders ----

  @Test
  void keyPairsNeedExplicitUsagesAndNamesAndTakeGroupsAndCustomAttributes() throws Exception {
    Kms kms = connect(KmipVersion.V2_1);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            kms.keys()
                .createKeyPair(KeyPairSpec.rsa(2048))
                .privateUsages(KeyUsage.SIGN)
                .createPreActive());
    assertThrows(
        IllegalArgumentException.class,
        () -> kms.keys().createKeyPair(KeyPairSpec.rsa(2048)).named("same", "same"));
    CustomAttribute owner = CustomAttribute.client("Owner");
    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.ec(Curve.P_384))
            .named("signer", "signer-pub")
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .group("signers")
            .custom(owner, "payments")
            .create();
    KeyAttributes priv = pair.privateKey().attributes(), pub = pair.publicKey().attributes();
    assertEquals(List.of("signer"), priv.names());
    assertEquals(List.of("signer-pub"), pub.names());
    for (KeyAttributes a : List.of(priv, pub)) {
      assertEquals(List.of("signers"), a.groups());
      assertEquals("payments", a.custom().get(owner));
    }
    // Registration takes the same options, including custom attributes.
    KeyGenerator aes = KeyGenerator.getInstance("AES");
    aes.init(128);
    KeyHandle registered =
        kms.keys()
            .register(aes.generateKey())
            .named("byok")
            .usages(KeyUsage.ENCRYPT)
            .custom(owner, "imports")
            .registerPreActive();
    assertEquals("imports", registered.attributes().custom().get(owner));
    assertThrows(
        IllegalArgumentException.class,
        () -> kms.keys().register(aes.generateKey()).registerPreActive(),
        "usages");
    assertThrows(
        IllegalArgumentException.class,
        () -> kms.keys().register(aes.generateKey()).ecAlgorithm(Algorithm.ECDSA));
  }

  // ---- discovery ----

  @Test
  void queriesFilterOnCustomAttributesLinksAndDates() {
    Kms kms = connect(KmipVersion.V2_1);
    CustomAttribute tenant = CustomAttribute.client("Tenant");
    Instant before = Instant.now().minusSeconds(5);
    KeyHandle acme =
        kms.keys()
            .createAes(256)
            .named("a")
            .usages(KeyUsage.ENCRYPT)
            .custom(tenant, "acme")
            .create();
    KeyHandle other =
        kms.keys()
            .createAes(256)
            .named("b")
            .usages(KeyUsage.ENCRYPT)
            .custom(tenant, "other")
            .create();
    assertEquals(List.of(acme), kms.keys().list(KeyQuery.all().custom(tenant, "acme")));
    KeyHandle replacement = acme.rotate();
    assertEquals(
        List.of(acme),
        kms.keys().list(KeyQuery.all().linkedTo(LinkKind.REPLACEMENT, replacement.id())));
    Instant after = Instant.now().plusSeconds(5);
    assertEquals(
        Set.of(acme, other, replacement),
        new HashSet<>(kms.keys().list(KeyQuery.all().createdBetween(before, after))));
    assertEquals(
        List.of(), kms.keys().list(KeyQuery.all().createdBetween(after, after.plusSeconds(60))));
    assertEquals(
        2,
        kms.keys()
            .list(KeyQuery.all().activatedBetween(before, after).custom(tenant, "acme"))
            .size(),
        "the replacement copies the custom attribute and is active");
    // The 3.0 draft has no Link structure: its Replacement Object Link attribute is searched.
    Kms draft = connect(KmipVersion.V3_0);
    assertEquals(List.of(), draft.keys().list(KeyQuery.all().linkedTo(LinkKind.REPLACEMENT, "x")));
  }

  @Test
  void locateWithAttributesBatchesGetAttributesPerPage() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(server);
    Kms kms = Kms.connect(server.configure().locatePageSize(4).build());
    clients.add(kms);
    for (int i = 0; i < 10; i++)
      kms.keys().createAes(128).named("many").usages(KeyUsage.ENCRYPT).createPreActive();
    int before = server.exchanges();
    List<KeyAttributes> all = kms.keys().locateWithAttributes(KeyQuery.byName("many")).toList();
    assertEquals(10, all.size());
    assertTrue(all.stream().allMatch(a -> a.names().contains("many")));
    // 3 Locate pages + 1 empty page ends it ... at most 4 Locates and 3 batched Get Attributes.
    assertTrue(
        server.exchanges() - before <= 7,
        "no N+1: " + (server.exchanges() - before) + " exchanges");
    // A server that refuses batches is asked per object.
    InMemoryKmipServer single = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms one =
        connect(
            single,
            request ->
                request.children(Tag.BATCH_ITEM).size() > 1
                    ? Faults.failure(
                        request, Enums.ResultReason.OPERATION_NOT_SUPPORTED, "no batches")
                    : single.exchange(request));
    for (int i = 0; i < 3; i++)
      one.keys().createAes(128).named("few").usages(KeyUsage.ENCRYPT).createPreActive();
    assertEquals(3, one.keys().locateWithAttributes(KeyQuery.byName("few")).count());
  }

  // ---- attribute edits ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1"})
  void attributeEditsAreAtomicAndRemovable(KmipVersion version) {
    Kms kms = connect(version);
    KeyHandle key =
        kms.keys()
            .createAes(256)
            .named("one")
            .named("two")
            .group("g1")
            .group("g2")
            .usages(KeyUsage.ENCRYPT)
            .createPreActive();
    CustomAttribute c = CustomAttribute.client("Stage");
    long before = last().exchanges();
    key.setCustomAttribute(c, "draft");
    key.setCustomAttribute(c, "final");
    assertEquals("final", key.attributes().custom().get(c));
    if (!version.atLeast(KmipVersion.V2_0))
      assertEquals(
          4,
          last().exchanges() - before - 1,
          "1.x: Modify, a read of the real index, Add; then Modify");
    else {
      assertEquals(2, sent(Operation.SET_ATTRIBUTE), "2.x: one Set Attribute per call");
      assertEquals(0, sent(Operation.MODIFY_ATTRIBUTE));
    }
    key.removeName("one");
    key.removeName("absent");
    key.removeFromGroup("g2");
    key.removeCustomAttribute(c);
    KeyAttributes a = key.attributes();
    assertEquals(List.of("two"), a.names());
    assertEquals(List.of("g1"), a.groups());
    assertFalse(a.custom().containsKey(c));
  }

  @Test
  void handlesKnowTheirKindAndBelongToTheirKms() throws Exception {
    Kms kms = connect(KmipVersion.V2_1);
    KeyHandle cert =
        kms.keys()
            .register(TestCertificates.selfSigned("cn=guard", "EC"))
            .named("guard")
            .usages(KeyUsage.VERIFY)
            .register();
    long encrypts = sent(Operation.ENCRYPT);
    assertThrows(KeyMismatchException.class, () -> cert.encrypt(CipherSpec.aesGcm(), new byte[1]));
    assertThrows(KeyMismatchException.class, cert::rotate);
    assertEquals(encrypts, sent(Operation.ENCRYPT), "refused before sending");
    // Without a known kind the server's Illegal Object Type is the same exception.
    KeyHandle unknown = kms.keys().handle(cert.id());
    assertTrue(unknown.knownKind().isEmpty());
    assertThrows(
        KeyMismatchException.class, () -> unknown.encrypt(CipherSpec.aesGcm(), new byte[1]));
    // Equality includes the owning Kms (and its views), not just the identifier.
    assertEquals(cert, kms.withTimeout(java.time.Duration.ofSeconds(1)).keys().handle(cert.id()));
    Kms other = connect(KmipVersion.V2_1);
    assertNotEquals(cert, other.keys().handle(cert.id()));
  }

  @Test
  void parameterizedSignatureSpecsVerifyWithJca() throws Exception {
    Kms kms = connect(KmipVersion.V2_1);
    byte[] message = "transfer".getBytes(StandardCharsets.UTF_8);
    record Case(KeyPairSpec pair, SignatureSpec spec) {}
    for (Case c :
        List.of(
            new Case(KeyPairSpec.rsa(2048), SignatureSpec.rsaPkcs1(Hash.SHA_384)),
            new Case(KeyPairSpec.rsa(2048), SignatureSpec.rsaPkcs1(Hash.SHA_512)),
            new Case(KeyPairSpec.rsa(2048), SignatureSpec.rsaPss(Hash.SHA_384)),
            new Case(KeyPairSpec.ec(Curve.P_384), SignatureSpec.ecdsa(Hash.SHA_384)),
            new Case(KeyPairSpec.ec(Curve.P_521), SignatureSpec.ecdsa(Hash.SHA_512)))) {
      KeyPairHandle signer =
          kms.keys()
              .createKeyPair(c.pair())
              .privateUsages(KeyUsage.SIGN)
              .publicUsages(KeyUsage.VERIFY)
              .create();
      byte[] sig = signer.privateKey().sign(c.spec(), message);
      assertEquals(
          VerifyResult.VALID,
          signer.publicKey().verify(c.spec(), message, sig),
          c.spec().toString());
      Signature jca = Signature.getInstance(c.spec().jcaAlgorithm().orElseThrow());
      if (c.spec().jcaParameters().isPresent()) jca.setParameter(c.spec().jcaParameters().get());
      jca.initVerify(signer.publicKey().asPublicKey(c.pair().expect()));
      jca.update(message);
      assertTrue(jca.verify(sig), c.spec().toString());
    }
    Kms old = connect(KmipVersion.V1_2);
    KeyPairHandle rsa =
        old.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .create();
    assertThrows(
        UnsupportedException.class,
        () -> rsa.privateKey().sign(SignatureSpec.rsaPss(Hash.SHA_256), message));
  }

  @Test
  void eventsHaveTypedOutcomesAndSecretKeysAreDestroyable() {
    List<KmsEvent> events = new ArrayList<>();
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(server);
    Kms kms =
        Kms.connect(
            server
                .configure()
                .addListener(
                    new KmsListener() {
                      @Override
                      public void finished(KmsEvent event) {
                        events.add(event);
                      }
                    })
                .build());
    clients.add(kms);
    KeyHandle key = aes(kms, "events");
    assertThrows(NotFoundException.class, () -> kms.keys().handle("nope").attributes());
    assertTrue(events.stream().anyMatch(e -> e.outcome() == KmsEvent.Outcome.SUCCEEDED));
    KmsEvent failed =
        events.stream()
            .filter(e -> e.outcome() == KmsEvent.Outcome.FAILED)
            .findFirst()
            .orElseThrow();
    assertInstanceOf(NotFoundException.class, failed.failure().orElseThrow());
    DestroyableSecretKey secret = key.asSecretKey(Expect.aes(256), LocalUse.DECRYPT);
    DestroyableSecretKey.destroyQuietly(secret);
    assertTrue(secret.isDestroyed());
  }
}
