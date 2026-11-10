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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.samples.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.KmipTransport;
import dev.keytend.kmip.transport.RequestNotSentException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.*;
import java.util.function.UnaryOperator;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Acceptance: the seven sample applications run unchanged against a strict in-memory KMIP
 * server negotiated at 1.2, 1.4, 2.0, 2.1 and 3.0. Features a version lacks (AEAD before 1.4)
 * fail with {@link UnsupportedException} before anything is sent. The server records every
 * wire-shape violation; each test asserts there are none.
 */
class SamplesTest {
  static final String NAME = "orders-key";
  InMemoryKmipServer server;
  Kms kms;

  /** Connects to a server that speaks only {@code version}. */
  Kms connect(ProtocolVersion version) {
    return connect(version, t -> t);
  }

  Kms connect(ProtocolVersion version, UnaryOperator<KmipTransport> wrap) {
    server = new InMemoryKmipServer(version);
    kms =
        Kms.connect(
            KmsConfig.builder()
                .endpoints("kms.test:5696")
                .transport(endpoint -> wrap.apply(server))
                .minimumVersion(KmipVersion.V1_2)
                .maximumVersion(KmipVersion.V3_0)
                .build());
    assertEquals(version, kms.version().protocolValue());
    return kms;
  }

  @AfterEach
  void noViolations() {
    if (kms != null) kms.close();
    if (server != null) assertEquals(List.of(), server.violations(), "wire-shape violations");
  }

  long operations(Operation op) {
    return server.protocolRequests().stream()
        .flatMap(r -> r.children(Tag.BATCH_ITEM).stream())
        .filter(b -> b.require(Tag.OPERATION).intValue() == op.code())
        .count();
  }

  // ---- A1 ----

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void a1LoadsTheTdeKeyAndNeverCreatesAReplacement(ProtocolVersion version) {
    Kms kms = connect(version);
    KeyHandle key =
        kms.keys().createAes(256).named("tde").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    var loaded = TdeKeyRetrieval.loadByName(kms, "tde");
    assertEquals(TdeKeyRetrieval.Status.LOADED, loaded.status());
    SecretKey secret = loaded.key().orElseThrow();
    assertEquals("AES", secret.getAlgorithm());
    assertEquals(32, secret.getEncoded().length);
    assertArrayEquals(
        secret.getEncoded(),
        TdeKeyRetrieval.loadById(kms, key.id()).key().orElseThrow().getEncoded());
    assertInstanceOf(DestroyableSecretKey.class, secret);

    long creates = operations(Operation.CREATE) + operations(Operation.REGISTER);
    assertEquals(
        TdeKeyRetrieval.Status.MISSING, TdeKeyRetrieval.loadByName(kms, "absent").status());
    assertEquals(
        TdeKeyRetrieval.Status.MISSING, TdeKeyRetrieval.loadById(kms, "no-such-id").status());
    assertEquals(
        creates,
        operations(Operation.CREATE) + operations(Operation.REGISTER),
        "a failed read never creates a key");
    // A compromised key is reported, not loaded.
    key.revoke(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
    assertEquals(
        TdeKeyRetrieval.Status.MISSING,
        TdeKeyRetrieval.loadByName(kms, "tde").status(),
        "not Active");
    assertEquals(TdeKeyRetrieval.Status.UNUSABLE, TdeKeyRetrieval.loadById(kms, key.id()).status());
  }

  /**
   * The incident procedure after a compromise, end to end, for sealed data and ciphertexts.
   * Before, nothing public exposed the key a sealed record names, so the documented recovery
   * ({@code handle(keyId).allowingCompromised()}) was unreachable without parsing the container.
   */
  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V1_4", "V2_0", "V2_1", "V3_0"})
  void a1TheIncidentProcedureRecoversSealedDataAndCiphertexts(ProtocolVersion version) {
    Kms kms = connect(version);
    KeyHandle key =
        kms.keys().createAes(256).named("tde").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    byte[] aad = "row 7".getBytes(UTF_8), plain = "card 4111".getBytes(UTF_8);
    byte[] sealed = key.seal(plain, aad);
    Ciphertext c = key.encrypt(CipherSpec.aesGcm(), plain, aad);
    assertEquals(key.id(), KmsKeys.sealedKeyId(sealed));

    var replacement =
        TdeKeyRetrieval.replaceCompromised(kms, "tde", java.time.Instant.now().minusSeconds(60));
    assertEquals(KeyState.COMPROMISED, key.attributes().state());
    assertEquals(KeyState.ACTIVE, replacement.current().attributes().state());
    assertEquals(
        Optional.of(replacement.current()),
        kms.keys().findByName("tde"),
        "the name finds the replacement");
    // Neither the replacement nor the name opens the old data any more.
    assertThrows(
        StateConflictException.class,
        () -> replacement.current().allowingCompromised().open(sealed, aad));
    assertThrows(
        StateConflictException.class, () -> kms.keys().open(KeyQuery.byName("tde"), sealed, aad));

    byte[] resealed = TdeKeyRetrieval.reseal(kms, sealed, aad, replacement.current());
    Ciphertext reencrypted = TdeKeyRetrieval.reencrypt(kms, c, aad, replacement.current());
    assertEquals(replacement.current().id(), KmsKeys.sealedKeyId(resealed));
    assertArrayEquals(plain, kms.keys().open(KeyQuery.byName("tde"), resealed, aad));
    assertArrayEquals(plain, kms.keys().decrypt(KeyQuery.byName("tde"), reencrypted, aad));
    assertEquals(TdeKeyRetrieval.Status.LOADED, TdeKeyRetrieval.loadByName(kms, "tde").status());

    CryptographicFailureException bad =
        assertThrows(
            CryptographicFailureException.class,
            () -> KmsKeys.sealedKeyId(new byte[] {'K', 'T', 'E'}));
    assertEquals(CryptographicFailureException.Kind.INVALID_CIPHERTEXT, bad.kind());
  }

  @Test
  void a1DistinguishesDeniedAndUnavailable() {
    boolean[] deny = {false}, down = {false};
    Kms kms =
        connect(
            ProtocolVersion.V2_1,
            mock ->
                new KmipTransport() {
                  @Override
                  public Ttlv exchange(Ttlv request) throws IOException {
                    if (down[0])
                      throw new RequestNotSentException(
                          "not sent", new java.net.ConnectException("Connection refused"));
                    if (deny[0] && Faults.operation(request) == Operation.GET.code())
                      return Faults.failure(request, Enums.ResultReason.PERMISSION_DENIED, "no");
                    return mock.exchange(request);
                  }
                });
    String id =
        kms.keys()
            .createAes(256)
            .named("tde")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .create()
            .id();
    deny[0] = true;
    assertEquals(TdeKeyRetrieval.Status.DENIED, TdeKeyRetrieval.loadById(kms, id).status());
    deny[0] = false;
    down[0] = true;
    assertEquals(TdeKeyRetrieval.Status.UNAVAILABLE, TdeKeyRetrieval.loadById(kms, id).status());
  }

  // ---- A2 ----

  @Test
  void a2NeedsKmip14ForTheDefaultGcmWrap() {
    Kms kms = connect(ProtocolVersion.V1_2);
    KeyHandle kek = EnvelopeEncryption.createKek(kms, "envelope-kek");
    assertThrows(
        UnsupportedException.class,
        () -> EnvelopeEncryption.seal(kms.keys().current(kek), new byte[1], null));
  }

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V1_4", "V2_0", "V2_1", "V3_0"})
  void a2EnvelopeEncryptionRoundTrips(ProtocolVersion version) {
    Kms kms = connect(version);
    KeyHandle handle = EnvelopeEncryption.createKek(kms, "envelope-kek");
    CurrentKey kek = kms.keys().current(handle);
    byte[] data = "customer record".getBytes(StandardCharsets.UTF_8);
    byte[] record7 = "record-7".getBytes(StandardCharsets.UTF_8);
    byte[] record8 = "record-8".getBytes(StandardCharsets.UTF_8);
    long encrypts = operations(Operation.ENCRYPT);
    byte[] stored = EnvelopeEncryption.seal(kek, data, record7);
    assertEquals(encrypts + 1, operations(Operation.ENCRYPT), "one server request to seal");
    assertArrayEquals(data, EnvelopeEncryption.open(kek, stored, record7));
    assertEquals(0, operations(Operation.REGISTER), "the DEK is never stored on the server");

    // The wrapped DEK is bound to the record ...
    var wrongRecord =
        assertThrows(
            CryptographicFailureException.class,
            () -> EnvelopeEncryption.open(kek, stored, record8));
    assertEquals(CryptographicFailureException.Kind.AUTHENTICATION_FAILED, wrongRecord.kind());
    // ... and the data to the wrapped DEK: another record's container with the same additional data
    // does not open with this one's data, nor this one's DEK with that one's data.
    byte[] other =
        EnvelopeEncryption.seal(kek, "another record".getBytes(StandardCharsets.UTF_8), record7);
    int dataStart = stored.length - (data.length + 16);
    byte[] swapped =
        Arrays.copyOf(
            other, other.length - (other.length - dataStart) + (stored.length - dataStart));
    System.arraycopy(stored, dataStart, swapped, dataStart, stored.length - dataStart);
    java.nio.ByteBuffer.wrap(swapped).putInt(dataStart - 4, data.length + 16);
    var mixed =
        assertThrows(
            CryptographicFailureException.class,
            () -> EnvelopeEncryption.open(kek, swapped, record7));
    assertEquals(CryptographicFailureException.Kind.AUTHENTICATION_FAILED, mixed.kind());
    // The container is parsed strictly: truncation, trailing bytes, another format.
    for (byte[] bad :
        List.of(
            new byte[3],
            Arrays.copyOf(stored, stored.length - 1),
            Arrays.copyOf(stored, stored.length + 1),
            handle.encrypt(CipherSpec.aesGcm(), data, record7).toBytes())) {
      var e =
          assertThrows(
              CryptographicFailureException.class,
              () -> EnvelopeEncryption.open(kek, bad, record7));
      assertEquals(CryptographicFailureException.Kind.INVALID_CIPHERTEXT, e.kind());
    }
    // After a rotation the current KEK, and a lookup by name, still open it.
    KeyHandle rotated = handle.rotate();
    assertArrayEquals(data, EnvelopeEncryption.open(kms.keys().current(rotated), stored, record7));
    kek.refresh();
    assertEquals(
        rotated.id(),
        KmsKeys.sealedKeyId(EnvelopeEncryption.seal(kek, data, record7)),
        "sealing follows the rotation");
    assertArrayEquals(data, EnvelopeEncryption.openByName(kms, "envelope-kek", stored, record7));
  }

  // ---- A3 ----

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V1_4", "V2_0", "V2_1", "V3_0"})
  void a3RemoteAeadDetectsTampering(ProtocolVersion version) {
    Kms kms = connect(version);
    KeyHandle key = RemoteAead.createKey(kms, "aead");
    byte[] aad = "tenant-7".getBytes(StandardCharsets.UTF_8);
    byte[] plaintext = "card 4111".getBytes(StandardCharsets.UTF_8);
    byte[] stored = RemoteAead.encryptForStorage(key, plaintext, aad);
    assertArrayEquals(plaintext, RemoteAead.decryptFromStorage(key, stored, aad));
    Ciphertext c = Ciphertext.fromBytes(stored);
    byte[] flipped = c.data();
    flipped[0] ^= 1;
    byte[] tampered = new Ciphertext(c.keyId(), c.specName(), flipped, c.iv(), c.tag()).toBytes();
    assertTrue(RemoteAead.detectsTampering(key, tampered, aad));
    assertTrue(
        RemoteAead.detectsTampering(key, stored, "tenant-8".getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void a3IsUnsupportedBeforeKmip14() {
    Kms kms = connect(ProtocolVersion.V1_2);
    KeyHandle key = RemoteAead.createKey(kms, "aead");
    assertThrows(
        UnsupportedException.class, () -> RemoteAead.encryptForStorage(key, new byte[1], null));
    assertEquals(0, operations(Operation.ENCRYPT), "nothing was sent");
  }

  // ---- A4 ----

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void a4SignAndVerifyReturnTypedVerdicts(ProtocolVersion version) throws Exception {
    Kms kms = connect(version);
    byte[] message = "transfer 100".getBytes(StandardCharsets.UTF_8);
    byte[] other = "transfer 999".getBytes(StandardCharsets.UTF_8);
    for (var c :
        List.of(
            new Object[] {
              KeyPairSpec.ec(256), SignatureSpec.ecdsa(Hash.SHA_256), "SHA256withECDSA"
            },
            new Object[] {
              KeyPairSpec.rsa(2048), SignatureSpec.rsaPkcs1(Hash.SHA_256), "SHA256withRSA"
            })) {
      KeyPairSpec spec = (KeyPairSpec) c[0];
      SignatureSpec sig = (SignatureSpec) c[1];
      KeyPairHandle signer = RemoteSignVerify.createSigner(kms, "signer-" + spec, spec);
      byte[] signature = RemoteSignVerify.sign(signer, sig, message);
      assertTrue(RemoteSignVerify.accept(signer, sig, message, signature));
      assertFalse(
          RemoteSignVerify.accept(signer, sig, other, signature),
          "a completed verify returning INVALID is a rejection");
      assertEquals(VerifyResult.INVALID, signer.publicKey().verify(sig, other, signature));
      assertTrue(RemoteSignVerify.verifyLocally(signer, sig, spec.expect(), message, signature));
    }
  }

  // ---- A5 ----

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void a5LifecycleAndRotation(ProtocolVersion version) {
    Kms kms = connect(version);
    KeyHandle first = LifecycleRotation.create(kms, NAME);
    KeyAttributes attributes = first.attributes();
    assertEquals(KeyState.ACTIVE, attributes.state());
    assertEquals(ObjectKind.SYMMETRIC_KEY, attributes.kind());
    assertEquals(Optional.of(Algorithm.AES), attributes.algorithm());
    assertEquals(256, attributes.length().getAsInt());
    assertEquals(Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), attributes.usages());
    assertTrue(attributes.names().contains(NAME));
    assertTrue(attributes.activationDate().isPresent());

    byte[] aad = "record-1".getBytes(StandardCharsets.UTF_8),
        data = "before".getBytes(StandardCharsets.UTF_8);
    boolean aead = version.atLeast(ProtocolVersion.V1_4);
    Ciphertext old = aead ? first.encrypt(CipherSpec.aesGcm(), data, aad) : null;

    var rotation = LifecycleRotation.rotate(kms, first, NAME);
    assertNotEquals(first, rotation.current());
    assertEquals(KeyState.ACTIVE, rotation.currentAttributes().state());
    assertEquals(Optional.of(first.id()), rotation.currentAttributes().replacedLink());
    assertEquals(Optional.of(rotation.current().id()), first.attributes().replacementLink());
    assertEquals(rotation.current(), first.latest(), "latest() follows the Replacement link");
    assertEquals(rotation.current(), kms.keys().findByName(NAME).orElseThrow());

    // Retiring keeps the old key for decryption; data is re-encrypted before it is destroyed.
    KeyAttributes revoked = LifecycleRotation.retire(first);
    assertEquals(KeyState.DEACTIVATED, revoked.state());
    assertTrue(revoked.deactivationDate().isPresent());
    if (aead) {
      assertArrayEquals(data, first.decrypt(old, aad), "decrypt after rotation");
      // The name moved to the replacement, and old data still decrypts by name.
      assertFalse(first.attributes().names().contains(NAME), "Re-key moved the name");
      assertArrayEquals(data, LifecycleRotation.readByName(kms, NAME, old, aad));
      Ciphertext moved = LifecycleRotation.reencrypt(rotation, old, aad);
      assertEquals(rotation.current().id(), moved.keyId());
      assertArrayEquals(data, rotation.current().decrypt(moved, aad));
    }
    LifecycleRotation.destroyRetired(first);
    assertThrows(
        StateConflictException.class,
        () -> first.asSecretKey(Expect.aes(256), LocalUse.DECRYPT),
        "Destroyed");
  }

  @Test
  void a5DestroyingAnActiveKeyIsAStateConflict() {
    Kms kms = connect(ProtocolVersion.V2_1);
    KeyHandle key = LifecycleRotation.create(kms, NAME);
    assertThrows(StateConflictException.class, key::destroy);
  }

  // ---- A6 ----

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void a6StoresAndRetrievesCertificates(ProtocolVersion version) throws Exception {
    Kms kms = connect(version);
    for (String alg : List.of("EC", "RSA")) {
      X509Certificate cert = TestCertificates.selfSigned("cn=" + alg, alg);
      KeyHandle stored = CertificateStorage.store(kms, cert, "cert-" + alg);
      assertEquals(ObjectKind.CERTIFICATE, stored.attributes().kind());
      assertEquals(cert, CertificateStorage.load(kms, "cert-" + alg));
    }
  }

  // ---- A7 ----

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void a7BringsItsOwnKeys(ProtocolVersion version) throws Exception {
    Kms kms = connect(version);
    KeyGenerator aes = KeyGenerator.getInstance("AES");
    aes.init(256);
    SecretKey secret = aes.generateKey();
    KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
    rsa.initialize(2048);
    KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
    ec.initialize(new ECGenParameterSpec("secp256r1"));
    for (var c :
        List.of(
            new Object[] {rsa.generateKeyPair(), Expect.rsa(2048)},
            new Object[] {ec.generateKeyPair(), Expect.ec(256)})) {
      KeyPair pair = (KeyPair) c[0];
      Expect expect = (Expect) c[1];
      var imported = BringYourOwnKey.importKeys(kms, secret, pair, "byok-" + expect.algorithm());
      assertArrayEquals(
          secret.getEncoded(), BringYourOwnKey.readSecret(imported.secret(), 256).getEncoded());
      assertArrayEquals(
          pair.getPrivate().getEncoded(),
          BringYourOwnKey.readPrivate(imported.privateKey(), expect).getEncoded());
      assertArrayEquals(
          pair.getPublic().getEncoded(),
          BringYourOwnKey.readPublic(imported.publicKey(), expect).getEncoded());
      assertEquals(KeyState.ACTIVE, imported.secret().attributes().state());
      assertEquals(Set.of(KeyUsage.SIGN), imported.privateKey().attributes().usages());
      assertThrows(
          KeyMismatchException.class,
          () -> BringYourOwnKey.readSecret(imported.secret(), 128),
          "a key of another size is refused");
    }
  }

  /**
   * The README quickstart: find or create the named key, then seal and open through the key in
   * force, the same on every version from 1.4; it can run again, and a record sealed before a
   * rotation still opens.
   */
  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V1_4", "V2_0", "V2_1", "V3_0"})
  void quickstartRunsUnchangedOnEveryVersion(ProtocolVersion version) {
    Kms kms = connect(version);
    byte[] orderJson = "{\"id\":1042}".getBytes(StandardCharsets.UTF_8);
    assertArrayEquals(orderJson, Quickstart.sealAndOpen(kms, orderJson));
    assertArrayEquals(
        orderJson, Quickstart.sealAndOpen(kms, orderJson), "the quickstart can run again");
    assertEquals(1, operations(Operation.CREATE), "and it made one key");
    // A record sealed before a rotation still opens through the key in force.
    byte[] orderId = "order-1042".getBytes(StandardCharsets.UTF_8);
    CurrentKey kek = kms.keys().current("orders-kek");
    byte[] sealed = kek.seal(orderJson, orderId);
    kms.keys().findByName("orders-kek").orElseThrow().rotate();
    assertNotEquals(kek.handle(), kek.refresh(), "the follower moved to the new key");
    assertArrayEquals(
        orderJson, kek.open(sealed, orderId), "the old record opens through the new key");
    assertArrayEquals(
        orderJson, Quickstart.sealAndOpen(kms, orderJson), "and it runs on with the rotated key");
    assertEquals(1, operations(Operation.CREATE), "rotation made no new named key");
  }
}
