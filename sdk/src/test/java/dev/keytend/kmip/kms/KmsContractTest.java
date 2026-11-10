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

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.nio.charset.StandardCharsets;
import java.security.spec.MGF1ParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The kms API's contracts: what activates, Pre-Active keys, builders used once, repeatable terminal
 * calls, exception categories, retry policies, key pairs, ciphertext shapes, lineage links, name
 * choice, stored names and specs, deadlines and paging.
 */
class KmsContractTest {
  static final byte[] PLAIN = "record body".getBytes(StandardCharsets.UTF_8);
  static final byte[] AAD = "record 7".getBytes(StandardCharsets.UTF_8);
  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  Kms connect(InMemoryKmipServer server) {
    return connect(server, server.configure());
  }

  Kms connect(InMemoryKmipServer server, KmsConfig.Builder builder) {
    servers.add(server);
    Kms kms = Kms.connect(builder.build());
    clients.add(kms);
    return kms;
  }

  Kms connect(KmipVersion version) {
    return connect(InMemoryKmipServer.of(version));
  }

  static long sent(InMemoryKmipServer server, Operation op) {
    return server.protocolRequests().stream()
        .flatMap(r -> r.children(Tag.BATCH_ITEM).stream())
        .filter(i -> i.require(Tag.OPERATION).intValue() == op.code())
        .count();
  }

  static KeyHandle aes(Kms kms, String name) {
    return kms.keys()
        .createAes(256)
        .named(name)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .create();
  }

  // ---- create() and register() activate ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void createAndRegisterActivateAndThePreActiveFormsDoNot(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server, server.configure().minimumVersion(KmipVersion.V1_2));
    KeyHandle active = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
    assertEquals(KeyState.ACTIVE, active.attributes().state());
    KeyHandle staged = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).createPreActive();
    assertEquals(KeyState.PRE_ACTIVE, staged.attributes().state());
    KeyGenerator aes = KeyGenerator.getInstance("AES");
    aes.init(128);
    assertEquals(
        KeyState.ACTIVE,
        kms.keys()
            .register(aes.generateKey())
            .usages(KeyUsage.ENCRYPT)
            .register()
            .attributes()
            .state());
    assertEquals(
        KeyState.PRE_ACTIVE,
        kms.keys()
            .register(aes.generateKey())
            .usages(KeyUsage.ENCRYPT)
            .registerPreActive()
            .attributes()
            .state());
    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .create();
    assertEquals(KeyState.ACTIVE, pair.privateKey().attributes().state());
    assertEquals(KeyState.ACTIVE, pair.publicKey().attributes().state());
  }

  @Test
  void usingAPreActiveKeySaysToActivateItFirst() {
    for (KmipVersion version : List.of(KmipVersion.V1_4, KmipVersion.V2_1)) {
      Kms kms = connect(version);
      KeyHandle staged =
          kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
      StateConflictException e =
          assertThrows(
              StateConflictException.class, () -> staged.encrypt(CipherSpec.aesGcm(), PLAIN, null));
      assertTrue(e.getMessage().contains("activate() first"), version + ": " + e.getMessage());
    }
  }

  // ---- builders are single-use once they made their object ----

  @Test
  void aBuilderThatMadeItsObjectRefusesToMakeAnother() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server);
    KeyRegistration secret = kms.keys().registerSecret("hunter2".toCharArray()).named("pw");
    KeyHandle stored = secret.register();
    // Before the fix the second call registered a secret of zeros.
    assertThrows(IllegalStateException.class, secret::register);
    assertThrows(IllegalStateException.class, secret::registerPreActive);
    assertEquals(1, sent(server, Operation.REGISTER));
    try (SecretData read = stored.asSecretData()) {
      assertArrayEquals("hunter2".toCharArray(), read.chars());
    }
    KeyRegistration seed =
        kms.keys().registerSecret(SecretData.Type.SEED, new byte[] {9, 9}).named("seed");
    seed.registerPreActive();
    assertThrows(IllegalStateException.class, seed::register);

    KeyCreation creation = kms.keys().createAes(128).named("once").usages(KeyUsage.ENCRYPT);
    KeyHandle made = creation.create();
    assertThrows(IllegalStateException.class, creation::create);
    assertThrows(IllegalStateException.class, creation::createPreActive);
    assertEquals(made, creation.findOrCreate(), "findOrCreate is idempotent and may be repeated");
    KeyPairCreation pairs =
        kms.keys()
            .createKeyPair(KeyPairSpec.ec(Curve.P_256))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY);
    pairs.createPreActive();
    assertThrows(IllegalStateException.class, pairs::create);
    assertEquals(1, sent(server, Operation.CREATE));
    assertEquals(1, sent(server, Operation.CREATE_KEY_PAIR));
  }

  @Test
  void aFailedTerminalCallMayBeRepeated() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server, server.configure().retryPolicy(RetryPolicy.none()));
    KeyCreation creation = kms.keys().createAes(128).usages(KeyUsage.ENCRYPT);
    server.injectBeforeProcessing(r -> new java.net.ConnectException("refused"));
    assertThrows(KmsException.class, creation::create);
    assertEquals(KeyState.ACTIVE, creation.create().attributes().state());
  }

  // ---- KmsException.category() ----

  @Test
  void everySubtypeHasACategory() {
    Map<KmsException, KmsException.Category> expected = new LinkedHashMap<>();
    expected.put(new TransientException("t"), KmsException.Category.RETRY);
    expected.put(new NotFoundException("n"), KmsException.Category.NOT_FOUND);
    expected.put(new PermissionDeniedException("p"), KmsException.Category.FIX_ACCESS);
    expected.put(new InvalidRequestException("i"), KmsException.Category.FIX_REQUEST);
    expected.put(new UnsupportedException("u"), KmsException.Category.FIX_REQUEST);
    expected.put(new KeyMismatchException("k"), KmsException.Category.FIX_REQUEST);
    expected.put(new StateConflictException("s"), KmsException.Category.STATE);
    expected.put(
        new AlreadyExistsException("a", new RuntimeException("cause")),
        KmsException.Category.STATE);
    expected.put(
        new CryptographicFailureException(
            "c", CryptographicFailureException.Kind.AUTHENTICATION_FAILED),
        KmsException.Category.BAD_DATA);
    expected.put(new OutcomeUnknownException("o"), KmsException.Category.OUTCOME_UNKNOWN);
    expected.put(
        new PartialCompletionException("p", List.of(), new NotFoundException("n")),
        KmsException.Category.PARTIAL);
    expected.put(new ServerFailureException("s"), KmsException.Category.SERVER);
    expected.put(new ProtocolViolationException("v"), KmsException.Category.SERVER);
    expected.forEach((e, c) -> assertEquals(c, e.category(), e.getClass().getSimpleName()));
    // Every permitted subtype is covered.
    Set<Class<?>> covered = new HashSet<>();
    expected.keySet().forEach(e -> covered.add(e.getClass()));
    for (Class<?> c : KmsException.class.getPermittedSubclasses())
      assertTrue(covered.contains(c), c.getName());
    assertEquals(
        "cause",
        new AlreadyExistsException("a", new RuntimeException("cause")).getCause().getMessage());
  }

  // ---- retry policy, events and key pairs ----

  @Test
  void retryPoliciesAreBuiltAndJitterOnlyShortensTheBackoff() {
    RetryPolicy p =
        RetryPolicy.builder()
            .maxAttempts(5)
            .initialBackoff(Duration.ofMillis(400))
            .maxBackoff(Duration.ofSeconds(1))
            .build();
    assertEquals(5, p.maxAttempts());
    assertEquals(0.5, p.jitter());
    Set<Long> seen = new HashSet<>();
    for (int i = 0; i < 200; i++) {
      long first = p.backoff(1).toMillis(), third = p.backoff(3).toMillis();
      assertTrue(first >= 200 && first <= 400, "first " + first);
      assertTrue(third >= 500 && third <= 1000, "capped " + third);
      seen.add(first);
    }
    assertTrue(seen.size() > 10, "jittered");
    RetryPolicy exact = p.toBuilder().jitter(0).build();
    assertEquals(Duration.ofMillis(800), exact.backoff(2));
    assertEquals(p, p.toBuilder().build());
    assertFalse(RetryPolicy.builder().retryCrypto(false).build().retryCrypto());
    assertEquals(1, RetryPolicy.none().maxAttempts());
    assertThrows(IllegalArgumentException.class, () -> RetryPolicy.builder().jitter(1.5));
    assertThrows(IllegalArgumentException.class, () -> RetryPolicy.builder().maxAttempts(0));
    assertThrows(
        IllegalArgumentException.class,
        () -> RetryPolicy.builder().initialBackoff(Duration.ofSeconds(-1)));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            RetryPolicy.builder()
                .initialBackoff(Duration.ofSeconds(9))
                .maxBackoff(Duration.ofSeconds(1))
                .build());
  }

  @Test
  void keyPairsComeOnlyFromTheSdkAndKeyPairChecksBothLinks() throws Exception {
    Kms kms = connect(KmipVersion.V2_1);
    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.DECRYPT)
            .publicUsages(KeyUsage.ENCRYPT)
            .create();
    assertEquals(pair, kms.keys().keyPair(pair.privateKey().id()));
    assertTrue(
        Arrays.stream(KeyPairHandle.class.getConstructors()).findAny().isEmpty(),
        "no public constructor");
    assertThrows(
        KeyMismatchException.class,
        () -> kms.keys().keyPair(pair.publicKey().id()),
        "a public key");
    // A private key whose Public Key link names a public key that does not link back.
    var generator = java.security.KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    var jca = generator.generateKeyPair();
    KeyHandle lonePrivate =
        kms.keys().register(jca.getPrivate()).usages(KeyUsage.DECRYPT).register();
    assertThrows(KeyMismatchException.class, () -> kms.keys().keyPair(lonePrivate.id()), "no link");
    kms.protocol()
        .call(
            dev.keytend.kmip.client.Requests.addAttribute()
                .uniqueIdentifier(lonePrivate.id())
                .attribute(
                    Attributes.attribute(
                        "Link",
                        Ttlv.structure(
                            Tag.LINK,
                            Ttlv.enumeration(Tag.LINK_TYPE, Enums.LinkType.PUBLIC_KEY_LINK),
                            Ttlv.text(Tag.LINKED_OBJECT_IDENTIFIER, pair.publicKey().id()))))
                .build());
    KeyMismatchException e =
        assertThrows(KeyMismatchException.class, () -> kms.keys().keyPair(lonePrivate.id()));
    assertTrue(e.getMessage().contains("does not link back"), e.getMessage());
  }

  @Test
  void aKeyPairWhoseActivationFailedReportsThePair() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server);
    server.injectBeforeProcessing(
        r ->
            r.children(Tag.BATCH_ITEM).get(0).require(Tag.OPERATION).intValue()
                    == Operation.ACTIVATE.code()
                ? new java.net.ConnectException("refused")
                : null);
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () ->
                kms.keys()
                    .createKeyPair(KeyPairSpec.ec(Curve.P_256))
                    .privateUsages(KeyUsage.SIGN)
                    .publicUsages(KeyUsage.VERIFY)
                    .create());
    KeyPairHandle pair = e.createdPair().orElseThrow();
    assertEquals(List.of(pair.privateKey(), pair.publicKey()), e.created());
    assertTrue(e.getMessage().contains("instead of repeating"), e.getMessage());
    KeyHandle single = kms.keys().createAes(128).usages(KeyUsage.ENCRYPT).createPreActive();
    assertTrue(
        new PartialCompletionException("x", List.of(single), new NotFoundException("n"))
            .createdPair()
            .isEmpty());
    assertEquals(
        pair,
        new PartialCompletionException("x", pair, new NotFoundException("n"))
            .createdPair()
            .orElseThrow());
  }

  // ---- specs, ciphertexts, data keys and rotation ----

  @Test
  void specsCiphertextsAndDataKeysHaveOneUnambiguousShape() throws Exception {
    assertEquals("AES-GCM-16", CipherSpec.aesGcm().name());
    assertEquals("AES-GCM-12", CipherSpec.aesGcm(12).name());
    var gcm =
        dev.keytend.kmip.client.CryptoParameters.builder()
            .algorithm(Enums.CryptographicAlgorithm.AES)
            .mode(Enums.BlockCipherMode.GCM)
            .tagLength(16)
            .build();
    assertTrue(CipherSpec.aeadFromProtocol("g", gcm).authenticated());
    assertFalse(CipherSpec.fromProtocol("g", gcm).authenticated());
    Ciphertext c =
        Ciphertext.builder()
            .keyId("k-1")
            .specName("AES-GCM-16")
            .iv(new byte[12])
            .tag(new byte[16])
            .data(new byte[] {1, 2})
            .build();
    assertEquals(c, Ciphertext.fromBytes(c.toBytes()));
    assertArrayEquals(new byte[] {1, 2}, c.data());
    assertEquals(
        0,
        Ciphertext.builder().keyId("k").specName("AES-KW").data(new byte[8]).build().iv().length);
    assertThrows(
        NullPointerException.class,
        () -> Ciphertext.builder().keyId("k").data(new byte[1]).build());
    assertThrows(
        IllegalArgumentException.class,
        () -> Ciphertext.builder().keyId("").specName("x").data(new byte[1]).build());
    assertTrue(
        Arrays.stream(Ciphertext.class.getConstructors()).findAny().isEmpty(),
        "parts go through the builder");

    Kms kms = connect(KmipVersion.V2_1);
    KeyHandle kek = aes(kms, "kek");
    try (DataKey dek = kek.generateDataKey(256, AAD)) {
      DestroyableSecretKey key = dek.key();
      try (DestroyableSecretKey back = kek.unwrapKey(Expect.aes(256), dek.wrapped(), AAD)) {
        assertArrayEquals(key.getEncoded(), back.getEncoded());
      }
      Ciphertext wrapped = kek.wrapKey(CipherSpec.keyWrap(), key, null);
      assertEquals("AES-KW", wrapped.specName());
    }
  }

  // ---- decryption and unwrapping survive rotation ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void theQuickstartDecryptSurvivesRotation(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle kek =
        kms.keys()
            .createAes(256)
            .named("orders-kek")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .findOrCreate();
    byte[] stored = kek.encrypt(CipherSpec.aesGcm(), PLAIN, AAD).toBytes();
    Ciphertext wrapped;
    try (DataKey dek = kek.generateDataKey(256, AAD)) {
      wrapped = dek.wrapped();
    }
    KeyHandle second = kek.rotate();
    KeyHandle third = second.rotate();
    assertEquals(List.of(), server.names(kek.id()), "Re-key moved the name");
    // Before the fix both lookups failed with KeyMismatchException after the first rotation.
    assertArrayEquals(
        PLAIN,
        kms.keys().decrypt(KeyQuery.byName("orders-kek"), Ciphertext.fromBytes(stored), AAD));
    KeyHandle current = kms.keys().findByName("orders-kek").orElseThrow();
    assertEquals(third, current);
    assertArrayEquals(
        PLAIN, current.decrypt(Ciphertext.fromBytes(stored), AAD), "two generations back");
    try (DestroyableSecretKey dek = current.unwrapKey(Expect.aes(256), wrapped, AAD);
        DestroyableSecretKey byName =
            kms.keys().unwrapKey(KeyQuery.byName("orders-kek"), Expect.aes(256), wrapped, AAD)) {
      assertArrayEquals(dek.getEncoded(), byName.getEncoded());
    }
    // A key outside the chain, or a query nothing in the chain matches, is still refused.
    KeyHandle stranger = aes(kms, "stranger");
    assertThrows(
        KeyMismatchException.class, () -> stranger.decrypt(Ciphertext.fromBytes(stored), AAD));
    assertThrows(
        KeyMismatchException.class,
        () -> kms.keys().decrypt(KeyQuery.byName("stranger"), Ciphertext.fromBytes(stored), AAD));
    // Older keys accept their confirmed successors' ciphertexts too (a handle kept from
    // startup, after another instance rotated); they must not be refused.
    Ciphertext fresh = current.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    assertArrayEquals(PLAIN, kek.decrypt(fresh, AAD));
  }

  @Test
  void aReplacementCycleIsAViolationNotALoop() throws Exception {
    Kms kms = connect(KmipVersion.V1_4);
    KeyHandle a = aes(kms, "a"), b = aes(kms, "b");
    Ciphertext stray = aes(kms, "c").encrypt(CipherSpec.aesGcm(), PLAIN, null);
    // A cycle confirmed in both directions (each key replaces and is replaced by the other).
    for (Enums.LinkType type :
        List.of(Enums.LinkType.REPLACED_OBJECT_LINK, Enums.LinkType.REPLACEMENT_OBJECT_LINK))
      for (String[] link : new String[][] {{a.id(), b.id()}, {b.id(), a.id()}})
        link(kms, link[0], type, link[1]);
    assertThrows(ProtocolViolationException.class, () -> a.decrypt(stray, null));
  }

  static void link(Kms kms, String from, Enums.LinkType type, String to) throws Exception {
    kms.protocol()
        .call(
            dev.keytend.kmip.client.Requests.addAttribute()
                .uniqueIdentifier(from)
                .attribute(
                    Attributes.attribute(
                        "Link",
                        Ttlv.structure(
                            Tag.LINK,
                            Ttlv.enumeration(Tag.LINK_TYPE, type),
                            Ttlv.text(Tag.LINKED_OBJECT_IDENTIFIER, to))))
                .build());
  }

  /**
   * Before the fix, an attacker who can create keys made {@code
   * kms.keys().decrypt(KeyQuery.byName(...))} return their own plaintext by giving their key a
   * Replacement Object link to the victim's key. Each step must now be confirmed by the other
   * key's link.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aOneSidedReplacementLinkAttachesNoKeyToALineage(KmipVersion version) throws Exception {
    Kms kms = connect(version);
    KeyHandle victim = aes(kms, "orders-kek");
    KeyHandle attacker =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    link(kms, attacker.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, victim.id());
    byte[] forged = attacker.seal("pay attacker".getBytes(StandardCharsets.UTF_8), AAD);
    Ciphertext c =
        attacker.encrypt(CipherSpec.aesGcm(), "pay attacker".getBytes(StandardCharsets.UTF_8), AAD);
    assertThrows(
        KeyMismatchException.class,
        () -> kms.keys().decrypt(KeyQuery.byName("orders-kek"), c, AAD));
    assertThrows(
        KeyMismatchException.class,
        () -> kms.keys().open(KeyQuery.byName("orders-kek"), forged, AAD));
    // The backward walk likewise needs both links: a Replaced Object link on the handle's key alone
    // does not make the attacker's key its predecessor.
    KeyHandle other = aes(kms, "other");
    link(kms, other.id(), Enums.LinkType.REPLACED_OBJECT_LINK, attacker.id());
    assertThrows(KeyMismatchException.class, () -> other.decrypt(c, AAD));
  }

  @Test
  void tooLongALineageIsALimitNotAMismatch() {
    Kms kms = connect(KmipVersion.V2_1);
    KeyHandle first = aes(kms, "old");
    Ciphertext c = first.encrypt(CipherSpec.aesGcm(), PLAIN, null);
    KeyHandle current = first;
    for (int i = 0; i <= Lineage.LIMIT; i++) current = current.rotate();
    KeyHandle newest = current;
    // Before: KeyMismatchException claiming the key was not in the lineage.
    UnsupportedException e =
        assertThrows(UnsupportedException.class, () -> newest.decrypt(c, null));
    assertTrue(e.getMessage().contains("rotations"), e.getMessage());
    assertThrows(
        UnsupportedException.class, () -> kms.keys().decrypt(KeyQuery.byName("old"), c, null));
  }

  @Test
  void usageChecksDependOnTheSpec() {
    for (KmipVersion version : List.of(KmipVersion.V1_4, KmipVersion.V2_1)) {
      Kms kms = connect(version);
      KeyHandle wrapOnly =
          kms.keys()
              .createAes(256)
              .named("w")
              .usages(KeyUsage.WRAP_KEY, KeyUsage.UNWRAP_KEY)
              .create();
      // AES-GCM through Encrypt needs Encrypt: before, WRAP_KEY hid the mismatch on 1.x.
      assertThrows(
          KeyMismatchException.class, () -> wrapOnly.generateDataKey(256, AAD), version.toString());
      Ciphertext kw =
          wrapOnly.wrapKey(CipherSpec.keyWrap(), new SecretKeySpec(new byte[32], "AES"), null);
      try (DestroyableSecretKey back = wrapOnly.unwrapKey(Expect.aes(256), kw, null)) {
        assertEquals(32, back.getEncoded().length, "AES key wrap accepts the Wrap/Unwrap usages");
      }
      // KmsKeys.decrypt checks suitability as the handle does (before: PermissionDenied on 1.x).
      KeyHandle encryptOnly =
          kms.keys().createAes(256).named("e").usages(KeyUsage.ENCRYPT).create();
      // Such a key no longer encrypts: a ciphertext naming it, made by another key.
      Ciphertext other =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create()
              .encrypt(CipherSpec.aesGcm(), PLAIN, null);
      Ciphertext gcm =
          new Ciphertext(encryptOnly.id(), other.specName(), other.data(), other.iv(), other.tag());
      assertThrows(
          KeyMismatchException.class,
          () -> kms.keys().decrypt(KeyQuery.byName("e"), gcm, null),
          version.toString());
    }
  }

  @Test
  void retryDurationsAreBounded() {
    assertThrows(
        IllegalArgumentException.class,
        () -> RetryPolicy.builder().maxBackoff(Duration.ofSeconds(Long.MAX_VALUE)));
    assertThrows(
        IllegalArgumentException.class, () -> RetryPolicy.builder().cooldown(Duration.ofDays(2)));
    RetryPolicy longest =
        RetryPolicy.builder()
            .initialBackoff(Duration.ofDays(1))
            .maxBackoff(Duration.ofDays(1))
            .build();
    assertEquals(Duration.ofDays(1), longest.toBuilder().jitter(0).build().backoff(30));
  }

  @Test
  void theHandleViewIsTheOneOptInForCompromisedReads() throws Exception {
    Kms kms = connect(KmipVersion.V2_1);
    KeyHandle secret = kms.keys().registerSecret("pw".toCharArray()).named("pw").register();
    secret.revoke(RevocationReason.keyCompromise("leaked", Instant.now()));
    StateConflictException e = assertThrows(StateConflictException.class, secret::asSecretData);
    assertTrue(e.getMessage().contains("allowingCompromised().asSecretData"), e.getMessage());
    // Before, Secret Data and certificates had no opt-in at all.
    try (SecretData read = secret.allowingCompromised().asSecretData()) {
      assertArrayEquals("pw".toCharArray(), read.chars());
    }
  }

  @Test
  void findOrCreateReportsItsKeyWhenTheChosenKeyDoesNotMatch() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server);
    Kms other = connect(server);
    AtomicBoolean once = new AtomicBoolean();
    // Right after this call's Create, another client creates an Active key with the name and
    // different usages. Choosing the Active one would not match; the choice ignores states and
    // this call's earlier key wins. A chosen key that does not match is
    // RotationAndNameChoiceTest.aMismatchFoundAfterCreatingSaysRepeatingWillNotHelp.
    server.injectAfterProcessing(
        r -> {
          if (is(r, Operation.CREATE) && once.compareAndSet(false, true))
            other.keys().createAes(256).named("shared").usages(KeyUsage.MAC_GENERATE).create();
          return null;
        });
    KeyHandle mine =
        kms.keys().createAes(256).named("shared").usages(KeyUsage.ENCRYPT).findOrCreate();
    assertEquals(Optional.of(KeyState.ACTIVE), server.state(mine.id()));
    assertTrue(once.get());
  }

  @Test
  void aSilentEndpointIsLeftEvenWhenEveryCallUsesAShortView() {
    InMemoryKmipServer first = InMemoryKmipServer.of(KmipVersion.V2_1),
        second = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(first);
    servers.add(second);
    AtomicBoolean hang = new AtomicBoolean();
    Kms kms =
        Kms.connect(
            first
                .configure()
                .endpoints("first:5696", "second:5696")
                .callTimeout(Duration.ofMillis(600))
                .retryPolicy(RetryPolicy.none())
                .transport(e -> e.host().equals("first") ? hanging(first, hang) : second)
                .build());
    clients.add(kms);
    Kms view = kms.withTimeout(Duration.ofMillis(100));
    hang.set(true);
    // One short timeout keeps the endpoint ...
    assertThrows(TransientException.class, () -> view.random(8));
    assertEquals(0, second.exchanges(), "the second endpoint was not used");
    // ... but before the fix every short call stayed on the silent endpoint forever.
    long until = System.nanoTime() + Duration.ofSeconds(5).toNanos();
    boolean moved = false;
    while (!moved && System.nanoTime() < until)
      try {
        view.random(8);
        moved = true;
      } catch (TransientException stillSilent) {
        // keep calling
      }
    assertTrue(
        moved, "traffic left the silent endpoint after a whole call timeout without an answer");
  }

  // ---- Compromised and Destroyed keys ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void decryptUnwrapAndVerifyRefuseACompromisedKeyUnlessAllowed(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle kek = aes(kms, "kek");
    Ciphertext c = kek.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    Ciphertext wrapped;
    try (DataKey dek = kek.generateDataKey(128, AAD)) {
      wrapped = dek.wrapped();
    }
    KeyHandle mac =
        kms.keys()
            .createSymmetric(Algorithm.HMAC_SHA256, 256)
            .usages(KeyUsage.MAC_GENERATE, KeyUsage.MAC_VERIFY)
            .create();
    byte[] tag = mac.mac(MacSpec.hmac(Hash.SHA_256), PLAIN);
    KeyPairHandle signer =
        kms.keys()
            .createKeyPair(KeyPairSpec.ec(Curve.P_256))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .create();
    byte[] sig = signer.privateKey().sign(SignatureSpec.ecdsa(Hash.SHA_256), PLAIN);
    Instant when = Instant.now().minusSeconds(60);
    for (KeyHandle k : List.of(kek, mac, signer.publicKey()))
      k.revoke(RevocationReason.keyCompromise("leaked", when));
    long decrypts = sent(server, Operation.DECRYPT);
    // Before the fix all of these succeeded: KMIP allows a Compromised key to decrypt and verify.
    assertCompromised(() -> kek.decrypt(c, AAD));
    // The query paths take the key from the record: their advice does not
    // offer the name as proof.
    assertCompromisedFromRecord(() -> kms.keys().decrypt(KeyQuery.byName("kek"), c, AAD));
    assertCompromised(() -> kek.unwrapKey(Expect.aes(128), wrapped, AAD));
    assertCompromisedFromRecord(
        () -> kms.keys().unwrapKey(KeyQuery.byName("kek"), Expect.aes(128), wrapped, AAD));
    assertCompromised(() -> mac.macVerify(MacSpec.hmac(Hash.SHA_256), PLAIN, tag));
    assertCompromised(
        () -> signer.publicKey().verify(SignatureSpec.ecdsa(Hash.SHA_256), PLAIN, sig));
    assertEquals(decrypts, sent(server, Operation.DECRYPT), "refused before decrypting");
    // The explicit opt-in, for forensic recovery.
    assertArrayEquals(PLAIN, kek.allowingCompromised().decrypt(c, AAD));
    assertArrayEquals(PLAIN, kms.keys().handle(c.keyId()).allowingCompromised().decrypt(c, AAD));
    try (DestroyableSecretKey dek =
        kek.allowingCompromised().unwrapKey(Expect.aes(128), wrapped, AAD)) {
      assertEquals(16, dek.getEncoded().length);
    }
    assertEquals(
        VerifyResult.VALID,
        mac.allowingCompromised().macVerify(MacSpec.hmac(Hash.SHA_256), PLAIN, tag));
    assertEquals(
        VerifyResult.VALID,
        signer
            .publicKey()
            .allowingCompromised()
            .verify(SignatureSpec.ecdsa(Hash.SHA_256), PLAIN, sig));
    assertEquals(kek, kek.allowingCompromised(), "a view of the same key");
  }

  @Test
  void aDestroyedKeyIsRefusedEvenWhenAllowingCompromised() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server);
    KeyHandle kek = aes(kms, "kek");
    Ciphertext c = kek.encrypt(CipherSpec.aesGcm(), PLAIN, null);
    kek.revoke(RevocationReason.keyCompromise("leaked", Instant.now()));
    kek.destroy();
    assertEquals(Optional.of(KeyState.DESTROYED_COMPROMISED), server.state(kek.id()));
    long decrypts = sent(server, Operation.DECRYPT);
    StateConflictException e =
        assertThrows(
            StateConflictException.class, () -> kek.allowingCompromised().decrypt(c, null));
    assertTrue(e.getMessage().contains("DESTROYED"), e.getMessage());
    assertEquals(decrypts, sent(server, Operation.DECRYPT));
  }

  static void assertCompromised(org.junit.jupiter.api.function.Executable call) {
    StateConflictException e = assertThrows(StateConflictException.class, call);
    assertTrue(
        e.getMessage().contains("COMPROMISED") && e.getMessage().contains("allowingCompromised()"),
        e.getMessage());
  }

  static void assertCompromisedFromRecord(org.junit.jupiter.api.function.Executable call) {
    StateConflictException e = assertThrows(StateConflictException.class, call);
    assertTrue(
        e.getMessage().contains("COMPROMISED") && e.getMessage().contains("a name proves nothing"),
        e.getMessage());
  }

  // ---- what RSA-OAEP protects ----

  @Test
  void aStoredRsaOaepBlobCannotSubstituteAKey() throws Exception {
    Kms kms = connect(KmipVersion.V2_1);
    KeyPairHandle kek =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.DECRYPT)
            .publicUsages(KeyUsage.ENCRYPT)
            .create();
    CipherSpec oaep = CipherSpec.rsaOaep(Hash.SHA_256);
    byte[] legitimate = new byte[32];
    Arrays.fill(legitimate, (byte) 7);
    Ciphertext wrapped = kek.encrypt(oaep, legitimate, AAD);
    assertEquals("RSA-OAEP-SHA-256-MGF1-SHA-256-BOUND", wrapped.specName());
    try (DestroyableSecretKey dek =
        kek.privateKey().unwrapKey(oaep, Expect.aes(256), wrapped, AAD)) {
      assertArrayEquals(legitimate, dek.getEncoded());
    }
    // The attack: anyone with the public key mints a blob for their own key.
    byte[] attackers = new byte[32];
    Cipher jca = Cipher.getInstance("RSA/ECB/OAEPPadding");
    jca.init(
        Cipher.ENCRYPT_MODE,
        kek.publicKey().asPublicKey(Expect.rsa(2048)),
        new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
    Ciphertext minted =
        Ciphertext.builder()
            .keyId(kek.publicKey().id())
            .specName("RSA-OAEP-SHA-256-MGF1-SHA-256")
            .data(jca.doFinal(attackers))
            .build();
    // Before the fix the stored-spec path unwrapped it: unwrapKey(wrapped, null, Expect.aes(256)).
    CryptographicFailureException e =
        assertThrows(
            CryptographicFailureException.class,
            () -> kek.privateKey().unwrapKey(Expect.aes(256), minted, null));
    assertEquals(CryptographicFailureException.Kind.INVALID_CIPHERTEXT, e.kind());
    assertThrows(CryptographicFailureException.class, () -> kek.privateKey().decrypt(minted, null));
    // With the expected spec and additional data, an unbound blob is refused, and a bound one made
    // for other additional data does not decrypt (the label is checked by OAEP).
    assertThrows(
        CryptographicFailureException.class,
        () -> kek.privateKey().unwrapKey(oaep, Expect.aes(256), minted, AAD));
    assertThrows(
        CryptographicFailureException.class,
        () ->
            kek.privateKey()
                .unwrapKey(
                    oaep,
                    Expect.aes(256),
                    wrapped,
                    "another record".getBytes(StandardCharsets.UTF_8)));
    // What OAEP cannot stop, as documented: a blob minted with the right label. Only a symmetric
    // KEK (AES-GCM, AES key wrap) shows who wrapped a key.
    jca.init(
        Cipher.ENCRYPT_MODE,
        kek.publicKey().asPublicKey(Expect.rsa(2048)),
        new OAEPParameterSpec(
            "SHA-256",
            "MGF1",
            MGF1ParameterSpec.SHA256,
            new PSource.PSpecified(
                concat(Ciphertext.header(kek.publicKey().id(), wrapped.specName()), AAD))));
    Ciphertext boundForgery =
        Ciphertext.builder()
            .keyId(kek.publicKey().id())
            .specName(wrapped.specName())
            .data(jca.doFinal(attackers))
            .build();
    try (DestroyableSecretKey dek =
        kek.privateKey().unwrapKey(oaep, Expect.aes(256), boundForgery, AAD)) {
      assertArrayEquals(attackers, dek.getEncoded());
    }
  }

  @Test
  void rsaOaepTakesAdditionalDataFromKmip14Only() {
    Kms old = connect(KmipVersion.V1_2);
    KeyPairHandle pair =
        old.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.DECRYPT)
            .publicUsages(KeyUsage.ENCRYPT)
            .create();
    CipherSpec sha1 = CipherSpec.rsaOaep(Hash.SHA_256, Hash.SHA_1);
    assertThrows(UnsupportedException.class, () -> pair.encrypt(sha1, PLAIN, AAD));
    Ciphertext unbound = pair.encrypt(sha1, PLAIN, null);
    assertEquals("RSA-OAEP-SHA-256-MGF1-SHA-1", unbound.specName());
    assertArrayEquals(PLAIN, pair.decrypt(sha1, unbound, null));
    Ciphertext bound =
        Ciphertext.builder()
            .keyId(unbound.keyId())
            .specName(unbound.specName() + "-BOUND")
            .data(unbound.data())
            .build();
    assertThrows(
        UnsupportedException.class,
        () -> pair.decrypt(sha1, bound, null),
        "no P Source before 1.4");
  }

  static byte[] concat(byte[] a, byte[] b) {
    byte[] out = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }

  // ---- migration between servers ----

  @Test
  void aMigratedKeyDecryptsCiphertextsNamingItsOriginalId() throws Exception {
    KeyGenerator aes = KeyGenerator.getInstance("AES");
    aes.init(256);
    javax.crypto.SecretKey material = aes.generateKey();
    Kms before = connect(KmipVersion.V2_1);
    KeyHandle original =
        before
            .keys()
            .register(material)
            .named("kek")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .register();
    Ciphertext c = original.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    Ciphertext wrapped;
    try (DataKey dek = original.generateDataKey(256, AAD)) {
      wrapped = dek.wrapped();
    }
    Kms after = connect(KmipVersion.V2_1);
    aes(after, "padding");
    KeyHandle migrated =
        after
            .keys()
            .register(material)
            .named("kek")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .register();
    assertNotEquals(original.id(), migrated.id());
    assertThrows(
        KeyMismatchException.class, () -> migrated.decrypt(c, AAD), "ciphertexts name the old id");
    KeyHandle accepting = migrated.acceptingOriginalId(original.id());
    assertArrayEquals(PLAIN, accepting.decrypt(c, AAD));
    try (DestroyableSecretKey dek = accepting.unwrapKey(Expect.aes(256), wrapped, AAD)) {
      assertEquals(32, dek.getEncoded().length);
    }
    // The header still binds the original id: relabeling to the new id fails authentication.
    Ciphertext relabeled =
        Ciphertext.builder()
            .keyId(migrated.id())
            .specName(c.specName())
            .iv(c.iv())
            .tag(c.tag())
            .data(c.data())
            .build();
    assertThrows(CryptographicFailureException.class, () -> accepting.decrypt(relabeled, AAD));
  }

  // ---- stored names and expected key sizes ----

  @Test
  void aKeyIdentifierWithAnUnpairedSurrogateIsRefused() {
    // Before the fix the surrogate became '?' in the stored bytes, naming another key.
    assertThrows(
        IllegalArgumentException.class,
        () ->
            Ciphertext.builder()
                .keyId("key-\uD800")
                .specName("AES-GCM-16")
                .data(new byte[1])
                .build());
    assertEquals(
        "key-\uD83D\uDD11",
        Ciphertext.fromBytes(
                Ciphertext.builder()
                    .keyId("key-\uD83D\uDD11")
                    .specName("AES-KW")
                    .data(new byte[8])
                    .build()
                    .toBytes())
            .keyId());
  }

  @Test
  void unwrappedKeysMustBeNonEmptyAndAesKeysAValidSize() {
    Kms kms = connect(KmipVersion.V2_1);
    KeyHandle kek = aes(kms, "kek");
    Ciphertext odd = kek.wrapKey(new SecretKeySpec(new byte[20], "AES"), AAD);
    // Before the fix Expect.of(AES, 0) accepted a 160-bit "AES" key.
    assertThrows(
        KeyMismatchException.class, () -> kek.unwrapKey(Expect.of(Algorithm.AES, 0), odd, AAD));
    Ciphertext empty = kek.encrypt(CipherSpec.aesGcm(), new byte[0], AAD);
    assertThrows(
        KeyMismatchException.class, () -> kek.unwrapKey(Expect.hmac(Hash.SHA_256), empty, AAD));
    try (DestroyableSecretKey any =
        kek.unwrapKey(
            Expect.of(Algorithm.AES, 0),
            kek.wrapKey(new SecretKeySpec(new byte[24], "AES"), AAD),
            AAD)) {
      assertEquals(24, any.getEncoded().length);
    }
  }

  // ---- findOrCreate and partial completion ----

  static boolean is(Ttlv request, Operation op) {
    return request.children(Tag.BATCH_ITEM).stream()
        .anyMatch(i -> i.require(Tag.OPERATION).intValue() == op.code());
  }

  @Test
  void aCreatorWhoseActivationLostTheRaceStillGetsItsActiveKey() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms creator = connect(server);
    Kms other = connect(server);
    AtomicBoolean once = new AtomicBoolean();
    // Another replica's findOrCreate finds the creator's Pre-Active key and activates it first.
    server.injectBeforeProcessing(
        r -> {
          if (is(r, Operation.ACTIVATE) && once.compareAndSet(false, true))
            other.keys().createAes(256).named("shared").usages(KeyUsage.ENCRYPT).findOrCreate();
          return null;
        });
    // Before the fix: PartialCompletionException ("activate or destroy") for a key in use.
    KeyHandle key =
        creator.keys().createAes(256).named("shared").usages(KeyUsage.ENCRYPT).findOrCreate();
    assertEquals(KeyState.ACTIVE, key.attributes().state());
    assertEquals(1, sent(server, Operation.CREATE));
    assertTrue(once.get());
  }

  @Test
  void closingBetweenCreateAndActivateStillReportsTheCreatedKey() {
    for (boolean findOrCreate : new boolean[] {false, true}) {
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      Kms kms = connect(server);
      server.injectAfterProcessing(
          r -> {
            if (is(r, Operation.CREATE)) kms.close();
            return null;
          });
      KeyCreation creation = kms.keys().createAes(256).named("half").usages(KeyUsage.ENCRYPT);
      // Before the fix: IllegalStateException("Kms is closed"), and the created id was lost.
      PartialCompletionException e =
          assertThrows(
              PartialCompletionException.class,
              findOrCreate ? creation::findOrCreate : creation::create);
      assertEquals(1, e.created().size());
      String id = e.created().get(0).id();
      assertTrue(server.exists(id));
      assertInstanceOf(IllegalStateException.class, e.getCause());
      assertTrue(
          e.getMessage().contains(findOrCreate ? "repeat findOrCreate()" : "instead of repeating"),
          e.getMessage());
      if (findOrCreate) {
        // Repeating findOrCreate resumes: it activates the key the first call created.
        Kms again = connect(server);
        KeyHandle resumed =
            again.keys().createAes(256).named("half").usages(KeyUsage.ENCRYPT).findOrCreate();
        assertEquals(id, resumed.id());
        assertEquals(KeyState.ACTIVE, resumed.attributes().state());
      }
    }
  }

  // ---- findOrCreate checks usages, groups and custom attributes ----

  @Test
  void findOrCreateRefusesAKeyThatDoesNotPermitWhatWasAskedFor() {
    Kms kms = connect(KmipVersion.V2_1);
    CustomAttribute tenant = CustomAttribute.client("tenant");
    KeyHandle macOnly =
        kms.keys()
            .createAes(256)
            .named("k")
            .usages(KeyUsage.MAC_GENERATE)
            .group("g")
            .custom(tenant, "acme")
            .create();
    // Before the fix this returned the MAC-only key, and the next encrypt failed.
    KeyMismatchException e =
        assertThrows(
            KeyMismatchException.class,
            () ->
                kms.keys()
                    .createAes(256)
                    .named("k")
                    .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                    .findOrCreate());
    assertTrue(
        e.getMessage().contains("lacks the usages") && e.getMessage().contains("ENCRYPT"),
        e.getMessage());
    assertEquals(
        macOnly,
        kms.keys().createAes(256).named("k").usages(KeyUsage.MAC_GENERATE).findOrCreate(),
        "a subset");
    assertThrows(
        KeyMismatchException.class,
        () ->
            kms.keys()
                .createAes(256)
                .named("k")
                .usages(KeyUsage.MAC_GENERATE)
                .group("other")
                .findOrCreate());
    assertThrows(
        KeyMismatchException.class,
        () ->
            kms.keys()
                .createAes(256)
                .named("k")
                .usages(KeyUsage.MAC_GENERATE)
                .custom(tenant, "evil")
                .findOrCreate());
    assertEquals(
        macOnly,
        kms.keys()
            .createAes(256)
            .named("k")
            .usages(KeyUsage.MAC_GENERATE)
            .group("g")
            .custom(tenant, "acme")
            .findOrCreate());
  }

  // ---- several objects with one name ----

  @Test
  void concurrentFindOrCreateCallersConvergeOnOneKey() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    int callers = 8;
    List<Kms> replicas = new ArrayList<>();
    for (int i = 0; i < callers; i++) replicas.add(connect(server));
    for (int round = 0; round < 5; round++) {
      String name = "race-" + round;
      CyclicBarrier start = new CyclicBarrier(callers);
      ExecutorService pool = Executors.newFixedThreadPool(callers);
      try {
        List<Future<KeyHandle>> results = new ArrayList<>();
        for (Kms replica : replicas)
          results.add(
              pool.submit(
                  () -> {
                    start.await();
                    return replica
                        .keys()
                        .createAes(256)
                        .named(name)
                        .usages(KeyUsage.ENCRYPT)
                        .findOrCreate();
                  }));
        Set<String> chosen = new HashSet<>();
        for (Future<KeyHandle> f : results) chosen.add(f.get(30, TimeUnit.SECONDS).id());
        assertEquals(1, chosen.size(), "every replica uses the same key: " + chosen);
        assertEquals(
            KeyState.ACTIVE,
            replicas.get(0).keys().handle(chosen.iterator().next()).attributes().state());
        // Every later start agrees (before the fix: StateConflictException on every restart).
        assertEquals(
            chosen.iterator().next(),
            replicas
                .get(0)
                .keys()
                .createAes(256)
                .named(name)
                .usages(KeyUsage.ENCRYPT)
                .findOrCreate()
                .id());
      } finally {
        pool.shutdownNow();
      }
    }
  }

  @Test
  void duplicateNamesResolveTheSameWayForEveryCaller() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server);
    KeyHandle first =
        kms.keys().createAes(256).named("dup").usages(KeyUsage.ENCRYPT).createPreActive();
    KeyHandle second =
        kms.keys().createAes(256).named("dup").usages(KeyUsage.ENCRYPT).createPreActive();
    // Before the fix: StateConflictException, with the requested states in the message.
    assertEquals(Optional.of(first), kms.keys().findByName("dup", KeyState.PRE_ACTIVE));
    assertEquals(
        first, kms.keys().createAes(256).named("dup").usages(KeyUsage.ENCRYPT).findOrCreate());
    assertEquals(KeyState.PRE_ACTIVE, second.attributes().state(), "the other one is left alone");
    // The choice ignores states, so the earlier Pre-Active key is chosen over a
    // later Active one (preferring Active keys would let the winner change as activations
    // landed).
    KeyHandle staged =
        kms.keys().createAes(256).named("staged").usages(KeyUsage.ENCRYPT).createPreActive();
    KeyHandle live = kms.keys().createAes(256).named("staged").usages(KeyUsage.ENCRYPT).create();
    assertEquals(
        Optional.of(staged), kms.keys().findByName("staged", KeyState.ACTIVE, KeyState.PRE_ACTIVE));
    assertEquals(
        Optional.of(live),
        kms.keys().findByName("staged"),
        "among Active keys only, the Active one");
    // Keys of one rotation chain that all kept the name: the newest.
    KeyHandle old = aes(kms, "chain");
    KeyHandle middle = old.rotate();
    KeyHandle newest = middle.rotate();
    old.addName("chain");
    middle.addName("chain");
    old.revoke(RevocationReason.superseded("rotated"));
    assertEquals(
        Optional.of(newest), kms.keys().findByName("chain", KeyState.ACTIVE, KeyState.DEACTIVATED));
    // Secrets registered twice: the earlier one, until its name is removed.
    KeyHandle v1 = kms.keys().registerSecret("one".toCharArray()).named("db").register();
    KeyHandle v2 = kms.keys().registerSecret("two".toCharArray()).named("db").register();
    assertEquals(Optional.of(v1), kms.keys().findByName("db"));
    v1.removeName("db");
    assertEquals(Optional.of(v2), kms.keys().findByName("db"));
  }

  // ---- Locates and batches ----

  @Test
  void findByNameSendsOneLocatePerStateWithoutLocatedItems() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms =
        connect(
            server,
            server
                .configure()
                .transport(
                    e -> request -> KmsExecutionTest.stripLocatedItems(server.exchange(request))));
    aes(kms, "single");
    long before = sent(server, Operation.LOCATE);
    assertTrue(kms.keys().findByName("single").isPresent());
    // Before the fix: two Locates (a second page to see the end).
    assertEquals(1, sent(server, Operation.LOCATE) - before);
    before = sent(server, Operation.LOCATE);
    assertTrue(kms.keys().findByName("single", KeyState.ACTIVE, KeyState.PRE_ACTIVE).isPresent());
    assertEquals(2, sent(server, Operation.LOCATE) - before);
  }

  @Test
  void oneFailedBatchDoesNotDisableBatchingForever() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicBoolean fail = new AtomicBoolean(true);
    Kms kms =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request -> {
                          if (request.children(Tag.BATCH_ITEM).size() > 1 && fail.getAndSet(false))
                            throw new dev.keytend.kmip.client.ProtocolException(
                                "garbled reply", null, null);
                          return server.exchange(request);
                        }));
    for (int i = 0; i < 3; i++) aes(kms, "batched");
    assertEquals(
        3,
        kms.keys().locateWithAttributes(KeyQuery.byName("batched")).count(),
        "per object after the failure");
    long batches =
        server.protocolRequests().stream()
            .filter(r -> r.children(Tag.BATCH_ITEM).size() > 1)
            .count();
    assertEquals(3, kms.keys().locateWithAttributes(KeyQuery.byName("batched")).count());
    // Before the fix the failure disabled batching for the life of the Kms.
    assertEquals(
        batches + 1,
        server.protocolRequests().stream()
            .filter(r -> r.children(Tag.BATCH_ITEM).size() > 1)
            .count());
  }

  // ---- one exception type per failure, on every version ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void commonFailuresHaveTheSameTypeOnEveryVersion(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server, server.configure().minimumVersion(KmipVersion.V1_2));
    CipherSpec cbc = CipherSpec.cbc();
    byte[] block = new byte[16];
    // Wrong usage. Before the fix: PermissionDeniedException on 1.x, InvalidRequestException on
    // 2.x.
    KeyHandle macOnly = kms.keys().createAes(256).usages(KeyUsage.MAC_GENERATE).create();
    assertThrows(KeyMismatchException.class, () -> macOnly.encrypt(cbc, block, null));
    KeyHandle encryptOnly = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
    // Such a key no longer encrypts: a ciphertext naming it, made by another key.
    Ciphertext made =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .create()
            .encrypt(cbc, block, null);
    Ciphertext c =
        new Ciphertext(encryptOnly.id(), made.specName(), made.data(), made.iv(), made.tag());
    assertThrows(KeyMismatchException.class, () -> encryptOnly.decrypt(cbc, c, null));
    KeyPairHandle decrypter =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.DECRYPT)
            .publicUsages(KeyUsage.ENCRYPT)
            .create();
    assertThrows(
        KeyMismatchException.class,
        () -> decrypter.privateKey().sign(SignatureSpec.rsaPkcs1(Hash.SHA_256), block));
    // Wrong state.
    KeyHandle staged =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
    assertThrows(StateConflictException.class, () -> staged.encrypt(cbc, block, null));
    // Not found.
    assertThrows(
        NotFoundException.class, () -> kms.keys().handle("missing").encrypt(cbc, block, null));
    assertThrows(NotFoundException.class, () -> kms.keys().handle("missing").decrypt(cbc, c, null));
    // Wrong kind of object, through handles that do not know their kind. Before the fix: Invalid
    // Field (InvalidRequestException) on 1.x.
    String secret = kms.keys().registerSecret(SecretData.Type.SEED, new byte[16]).register().id();
    assertThrows(
        KeyMismatchException.class, () -> kms.keys().handle(secret).encrypt(cbc, block, null));
    assertThrows(
        KeyMismatchException.class,
        () ->
            kms.keys()
                .handle(decrypter.publicKey().id())
                .sign(SignatureSpec.rsaPkcs1(Hash.SHA_256), block));
    assertThrows(
        KeyMismatchException.class,
        () ->
            kms.keys()
                .handle(encryptOnly.id())
                .verify(SignatureSpec.rsaPkcs1(Hash.SHA_256), block, block));
    assertThrows(
        KeyMismatchException.class,
        () -> kms.keys().handle(secret).mac(MacSpec.hmac(Hash.SHA_256), block));
  }

  // ---- removing attributes ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void removingFromAMissingObjectIsNotFound(KmipVersion version) {
    Kms kms = connect(version);
    KeyHandle key = aes(kms, "gone");
    key.removeName("never had it");
    KeyHandle missing = kms.keys().handle("no-such-object");
    // Before the fix all of these succeeded silently on 2.x (Item Not Found read as "attribute
    // absent").
    assertThrows(NotFoundException.class, () -> missing.removeName("gone"));
    assertThrows(NotFoundException.class, () -> missing.removeFromGroup("g"));
    assertThrows(
        NotFoundException.class, () -> missing.removeCustomAttribute(CustomAttribute.client("x")));
    assertThrows(
        NotFoundException.class,
        () -> missing.setCustomAttribute(CustomAttribute.client("x"), "v"));
  }

  @Test
  void twoInstancesWithoutAnAttributeIndexAreAmbiguous() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V1_4);
    Kms kms =
        connect(
            server,
            server
                .configure()
                .transport(
                    e ->
                        request ->
                            KmsExecutionTest.without(
                                server.exchange(request), Tag.ATTRIBUTE_INDEX)));
    KeyHandle key =
        kms.keys().createAes(128).named("A").named("B").usages(KeyUsage.ENCRYPT).create();
    // Before the fix both instances were taken to be index 0 and the wrong one could be deleted.
    assertThrows(ProtocolViolationException.class, () -> key.removeName("B"));
    assertEquals(2, kms.keys().handle(key.id()).attributes().names().size(), "nothing was deleted");
  }

  // ---- the caller's own deadline or interrupt does not move the endpoint ----

  /** A transport that, once {@code hang} is set, holds every request until the call's deadline or an interrupt. */
  static dev.keytend.kmip.transport.KmipTransport hanging(
      InMemoryKmipServer server, AtomicBoolean hang) {
    return new dev.keytend.kmip.transport.KmipTransport() {
      @Override
      public Ttlv exchange(Ttlv request) throws java.io.IOException {
        return server.exchange(request);
      }

      @Override
      public Ttlv exchange(Ttlv request, dev.keytend.kmip.transport.CallContext context)
          throws java.io.IOException {
        context.check();
        if (!hang.get()) return server.exchange(request);
        try {
          Thread.sleep(Math.max(1, context.remainingNanos() / 1_000_000));
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
          throw new java.io.InterruptedIOException("interrupted while waiting for the reply");
        }
        throw new java.net.SocketTimeoutException("no reply before the call deadline");
      }
    };
  }

  @Test
  void aCallersShortTimeoutOrInterruptKeepsTheEndpoint() throws Exception {
    InMemoryKmipServer first = InMemoryKmipServer.of(KmipVersion.V2_1),
        second = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(first);
    servers.add(second);
    AtomicBoolean hang = new AtomicBoolean();
    Kms kms =
        Kms.connect(
            first
                .configure()
                .endpoints("first:5696", "second:5696")
                .callTimeout(Duration.ofSeconds(20))
                .retryPolicy(RetryPolicy.none())
                .transport(e -> e.host().equals("first") ? hanging(first, hang) : second)
                .build());
    clients.add(kms);
    KeyHandle key = aes(kms, "k");
    hang.set(true);
    // A short view times out after the request was sent: the caller's choice, not the endpoint's
    // fault.
    assertThrows(
        TransientException.class,
        () -> kms.withTimeout(Duration.ofMillis(100)).keys().handle(key.id()).attributes());
    // An interrupted call (a canceled task) neither.
    Thread caller = Thread.currentThread();
    ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor();
    try {
      timer.schedule(caller::interrupt, 100, TimeUnit.MILLISECONDS);
      assertThrows(RuntimeException.class, () -> key.attributes());
    } finally {
      Thread.interrupted();
      timer.shutdownNow();
    }
    hang.set(false);
    int before = second.exchanges();
    assertEquals(KeyState.ACTIVE, key.attributes().state());
    // Before the fix the timeout moved every caller to the second endpoint.
    assertEquals(before, second.exchanges(), "traffic stayed on the first endpoint");
  }

  @Test
  void anEndpointSilentForTheWholeCallTimeoutIsLeft() {
    InMemoryKmipServer first = InMemoryKmipServer.of(KmipVersion.V2_1),
        second = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(first);
    servers.add(second);
    AtomicBoolean hang = new AtomicBoolean();
    Kms kms =
        Kms.connect(
            first
                .configure()
                .endpoints("first:5696", "second:5696")
                .callTimeout(Duration.ofMillis(200))
                .retryPolicy(RetryPolicy.none())
                .transport(e -> e.host().equals("first") ? hanging(first, hang) : second)
                .build());
    clients.add(kms);
    hang.set(true);
    assertThrows(TransientException.class, () -> kms.random(8));
    assertEquals(8, kms.random(8).length, "the next call went to the second endpoint");
    assertTrue(second.exchanges() > 0);
  }

  // ---- Data is optional in Encrypt/Decrypt responses from KMIP 2.0 ----

  /** Drops a zero-length Data field from every response, as servers may from 2.0. */
  static Ttlv withoutEmptyData(Ttlv node) {
    if (node.type() != Ttlv.Type.STRUCTURE) return node;
    return Ttlv.structure(
        node.tag(),
        node.children().stream()
            .filter(c -> !(c.tag() == Tag.DATA.code() && c.bytesValue().length == 0))
            .map(KmsContractTest::withoutEmptyData)
            .toList());
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_0", "V2_1", "V3_0"})
  void anEmptyPlaintextMayComeBackWithoutData(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms =
        connect(
            server,
            server
                .configure()
                .transport(e -> request -> withoutEmptyData(server.exchange(request))));
    KeyHandle key = aes(kms, "empty");
    if (!version.atLeast(KmipVersion.V2_0)) {
      // 1.x tables require Data: a reply without it is rejected.
      assertThrows(
          ProtocolViolationException.class,
          () -> key.encrypt(CipherSpec.aesGcm(), new byte[0], AAD));
      return;
    }
    // Before the fix both calls failed with "Response missing Data".
    Ciphertext c = key.encrypt(CipherSpec.aesGcm(), new byte[0], AAD);
    assertEquals(0, c.data().length);
    assertEquals(16, c.tag().length);
    assertArrayEquals(new byte[0], key.decrypt(c, AAD));
  }

  // ---- key pairs, empty data and truncated pages ----

  @Test
  void aKeyPairRefusesACompromisedPrivateKeyToo() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server);
    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.DECRYPT)
            .publicUsages(KeyUsage.ENCRYPT)
            .create();
    CipherSpec oaep = CipherSpec.rsaOaep(Hash.SHA_256);
    Ciphertext c = pair.encrypt(oaep, PLAIN, AAD);
    pair.privateKey().revoke(RevocationReason.keyCompromise("leaked", Instant.now()));
    long decrypts = sent(server, Operation.DECRYPT);
    // Before the fix KeyPairHandle.decrypt skipped the state check.
    assertCompromised(() -> pair.decrypt(oaep, c, AAD));
    assertEquals(decrypts, sent(server, Operation.DECRYPT));
    assertArrayEquals(PLAIN, pair.privateKey().allowingCompromised().decrypt(oaep, c, AAD));
  }

  /** A 2.x reply without Data is "empty" only for empty input. */
  @Test
  void aMissingOrShortDataFieldIsAViolationForNonEmptyInput() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicBoolean strip = new AtomicBoolean(), shorten = new AtomicBoolean();
    Kms kms =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request -> {
                          Ttlv response = server.exchange(request);
                          if (strip.get()) return KmsExecutionTest.without(response, Tag.DATA);
                          if (shorten.get()) return truncatedData(response);
                          return response;
                        }));
    KeyHandle key = aes(kms, "k");
    Ciphertext c = key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    strip.set(true);
    // Before the fix: an empty ciphertext, a sealed container that could never be opened, and an
    // empty plaintext for a non-empty ciphertext.
    assertThrows(
        ProtocolViolationException.class, () -> key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD));
    assertThrows(ProtocolViolationException.class, () -> key.seal(PLAIN, AAD));
    assertThrows(ProtocolViolationException.class, () -> key.decrypt(c, AAD));
    // CBC has no fixed output length, so only the Data rule catches it.
    assertThrows(
        ProtocolViolationException.class, () -> key.encrypt(CipherSpec.cbc(), PLAIN, null));
    strip.set(false);
    shorten.set(true);
    assertThrows(
        ProtocolViolationException.class, () -> key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD));
    assertThrows(ProtocolViolationException.class, () -> key.decrypt(c, AAD));
  }

  /** Drops the last byte of every Data field. */
  static Ttlv truncatedData(Ttlv node) {
    if (node.tag() == Tag.DATA.code() && node.type() == Ttlv.Type.BYTE_STRING) {
      byte[] b = node.bytesValue();
      return Ttlv.bytes(Tag.DATA, Arrays.copyOf(b, Math.max(0, b.length - 1)));
    }
    if (node.type() != Ttlv.Type.STRUCTURE) return node;
    return Ttlv.structure(
        node.tag(), node.children().stream().map(KmsContractTest::truncatedData).toList());
  }

  /** An empty page before Located Items is reached is truncation too. */
  @Test
  void anEmptyPageBeforeTheTotalIsAViolation() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms =
        connect(
            server,
            server
                .configure()
                .locatePageSize(2)
                .transport(
                    e ->
                        request -> {
                          Ttlv response = server.exchange(request);
                          boolean deep =
                              request.children(Tag.BATCH_ITEM).stream()
                                  .flatMap(i -> i.child(Tag.REQUEST_PAYLOAD).stream())
                                  .anyMatch(
                                      pl ->
                                          pl.child(Tag.OFFSET_ITEMS).map(Ttlv::intValue).orElse(0)
                                              >= 2);
                          return deep
                              ? KmsExecutionTest.without(response, Tag.UNIQUE_IDENTIFIER)
                              : response;
                        }));
    for (int i = 0; i < 5; i++)
      kms.keys().createAes(128).named("deep").usages(KeyUsage.ENCRYPT).createPreActive();
    // Before the fix: 2 of 5, silently.
    assertThrows(ProtocolViolationException.class, () -> kms.keys().list(KeyQuery.byName("deep")));
  }
}
