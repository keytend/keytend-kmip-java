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

import dev.keytend.kmip.client.CryptoParameters;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.*;
import java.util.function.UnaryOperator;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The stored {@link Ciphertext} cannot downgrade, relabel or redirect a decryption
 *, RSA-OAEP round-trips with explicit MGF1, and the cipher
 * parameters carry IV and tag lengths.
 */
class CiphertextSafetyTest {
  static final byte[] AAD = "tenant-7".getBytes(StandardCharsets.UTF_8);
  static final byte[] PLAIN = "card 4111 1111 1111 1111".getBytes(StandardCharsets.UTF_8);
  InMemoryKmipServer server;
  Kms kms;

  Kms connect(ProtocolVersion version) {
    return connect(version, t -> t);
  }

  Kms connect(ProtocolVersion version, UnaryOperator<KmipTransport> wrap) {
    server = new InMemoryKmipServer(version);
    kms =
        Kms.connect(
            KmsConfig.builder()
                .endpoints("kms:5696")
                .transport(e -> wrap.apply(server))
                .minimumVersion(KmipVersion.V1_2)
                .maximumVersion(KmipVersion.V3_0)
                .build());
    return kms;
  }

  @AfterEach
  void noViolations() {
    if (kms != null) kms.close();
    if (server != null) assertEquals(List.of(), server.violations());
  }

  List<Ttlv> sent(Operation op) {
    return server.protocolRequests().stream()
        .flatMap(r -> r.children(Tag.BATCH_ITEM).stream())
        .filter(b -> b.require(Tag.OPERATION).intValue() == op.code())
        .map(b -> b.require(Tag.REQUEST_PAYLOAD))
        .toList();
  }

  KeyHandle aes(String name) {
    return kms.keys()
        .createAes(256)
        .named(name)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .create();
  }

  static Ciphertext relabel(Ciphertext c, String keyId, String spec, byte[] iv, byte[] tag) {
    return new Ciphertext(keyId, spec, c.data(), iv, tag);
  }

  static void assertInvalid(Runnable r) {
    var e = assertThrows(CryptographicFailureException.class, r::run);
    assertEquals(CryptographicFailureException.Kind.INVALID_CIPHERTEXT, e.kind(), e.getMessage());
  }

  // ---- tampering vectors ----

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V1_4", "V2_0", "V2_1", "V3_0"})
  void aStoredCiphertextCannotDowngradeOrRelabelItself(ProtocolVersion version) {
    connect(version);
    KeyHandle key = aes("aead");
    Ciphertext c = key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    assertArrayEquals(PLAIN, key.decrypt(c, AAD));
    int decrypts = sent(Operation.DECRYPT).size();

    // Relabel as AES-CTR with IV = nonce || 00000002 (the GCM keystream): refused locally.
    byte[] counter = ByteBuffer.allocate(16).put(c.iv()).putInt(2).array();
    Ciphertext ctr = relabel(c, c.keyId(), "AES-CTR", counter, null);
    assertInvalid(() -> key.decrypt(ctr, null));
    assertInvalid(() -> key.decrypt(Ciphertext.fromBytes(ctr.toBytes()), null));
    assertInvalid(() -> key.decrypt(CipherSpec.aesGcm(), ctr, AAD));
    // Relabel as AES-CBC (a padding oracle): refused locally.
    Ciphertext cbc = relabel(c, c.keyId(), "AES-CBC", counter, null);
    assertInvalid(() -> key.decrypt(cbc, null));
    // Strip the tag, or change the IV length: refused locally.
    assertInvalid(() -> key.decrypt(relabel(c, c.keyId(), c.specName(), c.iv(), null), AAD));
    assertInvalid(() -> key.decrypt(relabel(c, c.keyId(), c.specName(), counter, c.tag()), AAD));
    // An explicit spec must match the stored one.
    assertInvalid(() -> key.decrypt(CipherSpec.ctr(), c, null));
    assertEquals(decrypts, sent(Operation.DECRYPT).size(), "nothing was sent");

    // Relabel GCM-16 as GCM-12 with a truncated tag: the spec name is in the bound header.
    Ciphertext shortTag = relabel(c, c.keyId(), "AES-GCM-12", c.iv(), Arrays.copyOf(c.tag(), 12));
    var e = assertThrows(CryptographicFailureException.class, () -> key.decrypt(shortTag, AAD));
    assertEquals(CryptographicFailureException.Kind.AUTHENTICATION_FAILED, e.kind());
    // Non-empty additional data with a mode that cannot authenticate it.
    Ciphertext real = key.encrypt(CipherSpec.ctr(), PLAIN);
    assertThrows(IllegalArgumentException.class, () -> key.decrypt(CipherSpec.ctr(), real, AAD));
  }

  @Test
  void aSwappedKeyIdentifierDoesNotRedirectTheDecryption() {
    connect(ProtocolVersion.V2_1);
    KeyHandle a = aes("tenant-a"), b = aes("tenant-b");
    Ciphertext c = a.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    Ciphertext pointedAtB = relabel(c, b.id(), c.specName(), c.iv(), c.tag());
    int decrypts = sent(Operation.DECRYPT).size();
    // A handle refuses another key's ciphertext.
    assertThrows(KeyMismatchException.class, () -> a.decrypt(pointedAtB, AAD));
    // kms.keys().decrypt checks the named key against the caller's expectation first.
    assertThrows(
        KeyMismatchException.class,
        () -> kms.keys().decrypt(KeyQuery.byName("tenant-a"), pointedAtB, AAD));
    assertEquals(decrypts, sent(Operation.DECRYPT).size(), "nothing was sent");
    assertThrows(
        IllegalArgumentException.class,
        () -> kms.keys().decrypt(KeyQuery.all(), c, AAD),
        "no expectation");
    // Even if B is used, the key identifier is in the bound header, so the tag fails.
    var e = assertThrows(CryptographicFailureException.class, () -> b.decrypt(pointedAtB, AAD));
    assertEquals(CryptographicFailureException.Kind.AUTHENTICATION_FAILED, e.kind());
    assertArrayEquals(PLAIN, kms.keys().decrypt(KeyQuery.byName("tenant-a"), c, AAD));
  }

  @Test
  void decryptionAfterRotationWorksWhileTheOldKeyExists() {
    connect(ProtocolVersion.V2_1);
    KeyHandle old =
        kms.keys()
            .createAes(256)
            .named("orders")
            .group("orders")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .create();
    Ciphertext c = old.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    KeyHandle current = old.rotate();
    assertNotEquals(old.id(), current.id());
    assertArrayEquals(PLAIN, old.decrypt(c, AAD));
    assertArrayEquals(PLAIN, kms.keys().decrypt(KeyQuery.all().group("orders"), c, AAD));
    // The replacement decrypts what the key it replaced encrypted.
    assertArrayEquals(PLAIN, current.decrypt(c, AAD));
    assertThrows(KeyMismatchException.class, () -> aes("unrelated").decrypt(c, AAD));
  }

  // ---- the format and the bound header ----

  @Test
  void theHeaderIsBoundIntoTheAadTheServerSees() throws Exception {
    connect(ProtocolVersion.V2_1);
    KeyHandle key = aes("bound");
    Ciphertext c = key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    byte[] header = c.header();
    byte[] expectedAad =
        ByteBuffer.allocate(header.length + AAD.length).put(header).put(AAD).array();
    Ttlv encrypt = sent(Operation.ENCRYPT).get(0);
    assertArrayEquals(
        expectedAad, encrypt.require(Tag.AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA).bytesValue());
    // The documented format decrypts with plain JCA, given the key.
    SecretKey raw = key.asSecretKey(Expect.aes(256), LocalUse.DECRYPT);
    Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
    gcm.init(Cipher.DECRYPT_MODE, raw, new GCMParameterSpec(128, c.iv()));
    gcm.updateAAD(expectedAad);
    assertArrayEquals(
        PLAIN,
        gcm.doFinal(ByteBuffer.allocate(c.data().length + 16).put(c.data()).put(c.tag()).array()));
    // Without additional data the header alone is sent.
    Ciphertext bare = key.encrypt(CipherSpec.aesGcm(), PLAIN);
    assertArrayEquals(
        bare.header(),
        sent(Operation.ENCRYPT)
            .get(1)
            .require(Tag.AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA)
            .bytesValue());
  }

  @Test
  void theStorageFormatIsMagicVersionAndLengthPrefixedFields() {
    byte[] iv = new byte[12], tag = new byte[16], data = {9, 8, 7};
    Arrays.fill(tag, (byte) 0x55);
    Ciphertext c = new Ciphertext("k-1", "AES-GCM-16", data, iv, tag);
    byte[] bytes = c.toBytes();
    ByteBuffer b = ByteBuffer.wrap(bytes);
    assertEquals('K', b.get());
    assertEquals('T', b.get());
    assertEquals('C', b.get());
    assertEquals(1, b.get(), "version");
    assertEquals(3, b.getShort());
    assertEquals("k-1", new String(new byte[] {b.get(), b.get(), b.get()}, StandardCharsets.UTF_8));
    assertEquals(10, b.get());
    b.position(b.position() + 10);
    assertArrayEquals(
        Arrays.copyOf(bytes, b.position()), c.header(), "the header ends after the spec");
    assertEquals(12, b.get());
    b.position(b.position() + 12);
    assertEquals(16, b.get());
    b.position(b.position() + 16);
    assertEquals(3, b.getInt());
    assertEquals(3, b.remaining());
    assertEquals(c, Ciphertext.fromBytes(bytes));
  }

  @Test
  void malformedStoredCiphertextsAreATypedFailure() {
    byte[] good =
        new Ciphertext("k", "AES-GCM-16", new byte[4], new byte[12], new byte[16]).toBytes();
    List<byte[]> bad = new ArrayList<>();
    bad.add(new byte[0]);
    bad.add(Arrays.copyOf(good, 5));
    bad.add(Arrays.copyOf(good, good.length - 1));
    bad.add(Arrays.copyOf(good, good.length + 1));
    byte[] magic = good.clone();
    magic[0] = 1;
    bad.add(magic);
    byte[] version = good.clone();
    version[3] = 2;
    bad.add(version);
    byte[] emptyId = good.clone();
    emptyId[5] = 0;
    bad.add(emptyId);
    byte[] notUtf8 = good.clone();
    notUtf8[6] = (byte) 0xff;
    bad.add(notUtf8);
    byte[] hugeData = good.clone();
    ByteBuffer.wrap(hugeData).putInt(good.length - 8, Integer.MAX_VALUE);
    bad.add(hugeData);
    for (byte[] b : bad) assertInvalid(() -> Ciphertext.fromBytes(b));
    byte[] oldV1 = ByteBuffer.allocate(5).put((byte) 1).putInt(0).array();
    assertInvalid(() -> Ciphertext.fromBytes(oldV1));
    assertInvalid(
        () -> KeyHandle.storedSpec(new Ciphertext("k", "AES-GCM-17", new byte[1], null, null)));
  }

  // ---- RSA-OAEP ----

  @Test
  void rsaOaepStatesBothHashesAndDecryptsWithJca() throws Exception {
    connect(ProtocolVersion.V2_1);
    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.DECRYPT)
            .publicUsages(KeyUsage.ENCRYPT)
            .create();
    CipherSpec oaep = CipherSpec.rsaOaep(Hash.SHA_256);
    assertEquals("RSA-OAEP-SHA-256-MGF1-SHA-256", oaep.name());
    Ciphertext c = pair.encrypt(oaep, PLAIN, null);
    // From 1.4 the header is bound as the OAEP label.
    assertEquals("RSA-OAEP-SHA-256-MGF1-SHA-256-BOUND", c.specName());
    Ttlv parameters = sent(Operation.ENCRYPT).get(0).require(Tag.CRYPTOGRAPHIC_PARAMETERS);
    assertEquals(
        Enums.HashingAlgorithm.SHA_256.code(),
        parameters.require(Tag.MASK_GENERATOR_HASHING_ALGORITHM).intValue());
    assertEquals(
        Enums.MaskGenerator.MGF1.code(), parameters.require(Tag.MASK_GENERATOR).intValue());
    PrivateKey privateKey = pair.privateKey().asPrivateKey(Expect.rsa(2048));
    Cipher jca = Cipher.getInstance("RSA/ECB/OAEPPadding");
    jca.init(
        Cipher.DECRYPT_MODE,
        privateKey,
        new OAEPParameterSpec(
            "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, new PSource.PSpecified(c.header())));
    assertArrayEquals(PLAIN, jca.doFinal(c.data()));
    // The natural round trips (no hand-built ciphertexts), always with the expected spec: a stored
    // RSA-OAEP ciphertext never chooses its spec.
    assertArrayEquals(PLAIN, pair.decrypt(oaep, c, null));
    assertArrayEquals(PLAIN, pair.privateKey().decrypt(oaep, c, null));
    assertInvalid(() -> pair.privateKey().decrypt(c, null));
    assertInvalid(() -> kms.keys().decrypt(KeyQuery.all().kind(ObjectKind.PUBLIC_KEY), c, null));
    // A private key of another pair refuses it.
    KeyPairHandle other =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.DECRYPT)
            .publicUsages(KeyUsage.ENCRYPT)
            .create();
    assertThrows(KeyMismatchException.class, () -> other.privateKey().decrypt(oaep, c, null));
    assertThrows(KeyMismatchException.class, () -> other.decrypt(oaep, c, null));
    // Stored names keep their meaning: SHA-256 with MGF1-SHA-1 is a different spec.
    CipherSpec mixed = CipherSpec.rsaOaep(Hash.SHA_256, Hash.SHA_1);
    Ciphertext m = pair.encrypt(mixed, PLAIN, null);
    assertEquals("RSA-OAEP-SHA-256-MGF1-SHA-1-BOUND", m.specName());
    assertArrayEquals(PLAIN, pair.decrypt(mixed, m, null));
    assertInvalid(() -> pair.decrypt(oaep, m, null));
  }

  @Test
  void beforeKmip14OnlyMgf1Sha1CanBeExpressed() {
    connect(ProtocolVersion.V1_2);
    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.DECRYPT)
            .publicUsages(KeyUsage.ENCRYPT)
            .create();
    assertThrows(
        UnsupportedException.class,
        () -> pair.encrypt(CipherSpec.rsaOaep(Hash.SHA_256), PLAIN, null));
    assertEquals(0, sent(Operation.ENCRYPT).size());
    Ciphertext c = pair.encrypt(CipherSpec.rsaOaep(Hash.SHA_256, Hash.SHA_1), PLAIN, null);
    assertFalse(
        sent(Operation.ENCRYPT)
            .get(0)
            .require(Tag.CRYPTOGRAPHIC_PARAMETERS)
            .child(Tag.MASK_GENERATOR_HASHING_ALGORITHM)
            .isPresent());
    assertArrayEquals(PLAIN, pair.decrypt(CipherSpec.rsaOaep(Hash.SHA_256, Hash.SHA_1), c, null));
  }

  // ---- IV and tag lengths ----

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void variableIvModesSendTheirIvLength(ProtocolVersion version) {
    connect(version);
    KeyHandle key = aes("iv");
    key.decrypt(CipherSpec.ctr(), key.encrypt(CipherSpec.ctr(), PLAIN), null);
    if (version.atLeast(ProtocolVersion.V1_4))
      key.decrypt(key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD), AAD);
    for (Operation op : List.of(Operation.ENCRYPT, Operation.DECRYPT))
      for (Ttlv payload : sent(op)) {
        Ttlv p = payload.require(Tag.CRYPTOGRAPHIC_PARAMETERS);
        int mode = p.require(Tag.BLOCK_CIPHER_MODE).intValue();
        int expected = mode == Enums.BlockCipherMode.GCM.code() ? 96 : 128;
        assertEquals(expected, p.require(Tag.IV_LENGTH).intValue(), op + " " + version);
      }
  }

  @Test
  void theMockFlagsAMissingIvLength() throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer(ProtocolVersion.V2_1);
    var client = new dev.keytend.kmip.client.KmipClient(mock, ProtocolVersion.V2_1);
    String id =
        client.createSymmetricKey(
            Enums.CryptographicAlgorithm.AES,
            256,
            Enums.CryptographicUsageMask.ENCRYPT,
            Enums.CryptographicUsageMask.DECRYPT);
    client.activate(id);
    CryptoParameters noIvLength =
        CryptoParameters.builder()
            .algorithm(Enums.CryptographicAlgorithm.AES)
            .mode(Enums.BlockCipherMode.GCM)
            .tagLength(16)
            .build();
    assertThrows(
        dev.keytend.kmip.client.KmipException.class,
        () ->
            client.call(
                dev.keytend.kmip.client.CryptoRequests.encrypt(id)
                    .parameters(noIvLength)
                    .data(PLAIN)
                    .iv(new byte[12])
                    .build()));
    assertEquals(1, mock.violations().size(), mock.violations().toString());
  }

  @Test
  void aCustomAeadSpecTakesItsTagLengthFromTheParameters() {
    assertThrows(
        IllegalArgumentException.class,
        () ->
            CipherSpec.aeadFromProtocol(
                "gcm-no-tag",
                CryptoParameters.builder()
                    .algorithm(Enums.CryptographicAlgorithm.AES)
                    .mode(Enums.BlockCipherMode.GCM)
                    .build()));
    // A server that appends a 12-byte tag to the data instead of returning it separately.
    connect(ProtocolVersion.V2_1, AppendedTag::new);
    KeyHandle key = aes("custom");
    CipherSpec spec =
        CipherSpec.aeadFromProtocol(
            "gcm-12",
            CryptoParameters.builder()
                .algorithm(Enums.CryptographicAlgorithm.AES)
                .mode(Enums.BlockCipherMode.GCM)
                .ivLength(96)
                .tagLength(12)
                .build());
    Ciphertext c = key.encrypt(spec, PLAIN, AAD);
    assertEquals(12, c.tag().length);
    assertEquals(PLAIN.length, c.data().length);
    assertArrayEquals(PLAIN, key.decrypt(spec, c, AAD));
    assertInvalid(() -> key.decrypt(c, AAD));
  }

  /** Moves the Authenticated Encryption Tag of Encrypt responses to the end of the Data. */
  static final class AppendedTag implements KmipTransport {
    final KmipTransport delegate;

    AppendedTag(KmipTransport delegate) {
      this.delegate = delegate;
    }

    @Override
    public Ttlv exchange(Ttlv request) throws IOException {
      Ttlv response = delegate.exchange(request);
      if (Faults.operation(request) != Operation.ENCRYPT.code()) return response;
      List<Ttlv> top = new ArrayList<>();
      for (Ttlv t : response.children()) {
        if (t.tag() != Tag.BATCH_ITEM.code()) {
          top.add(t);
          continue;
        }
        List<Ttlv> item = new ArrayList<>();
        for (Ttlv f : t.children()) {
          if (f.tag() != Tag.RESPONSE_PAYLOAD.code()) {
            item.add(f);
            continue;
          }
          byte[] tag = f.require(Tag.AUTHENTICATED_ENCRYPTION_TAG).bytesValue();
          byte[] data = f.require(Tag.DATA).bytesValue();
          List<Ttlv> payload = new ArrayList<>();
          for (Ttlv x : f.children())
            if (x.tag() == Tag.DATA.code())
              payload.add(
                  Ttlv.bytes(
                      Tag.DATA,
                      ByteBuffer.allocate(data.length + tag.length).put(data).put(tag).array()));
            else if (x.tag() != Tag.AUTHENTICATED_ENCRYPTION_TAG.code()) payload.add(x);
          item.add(Ttlv.structure(Tag.RESPONSE_PAYLOAD, payload));
        }
        top.add(Ttlv.structure(Tag.BATCH_ITEM, item));
      }
      return Ttlv.structure(Tag.RESPONSE_MESSAGE, top);
    }
  }

  // ---- wrapping with additional data and an expected key ----

  @Test
  void unwrappingChecksTheSpecTheAadAndTheExpectedKey() throws Exception {
    connect(ProtocolVersion.V2_1);
    KeyHandle kek = aes("kek");
    try (DataKey dek = kek.generateDataKey(256, AAD)) {
      assertEquals(CipherSpec.aesGcm().name(), dek.wrapped().specName());
      SecretKey unwrapped = kek.unwrapKey(Expect.aes(256), dek.wrapped(), AAD);
      assertArrayEquals(dek.key().getEncoded(), unwrapped.getEncoded());
      assertThrows(
          KeyMismatchException.class, () -> kek.unwrapKey(Expect.aes(128), dek.wrapped(), AAD));
      var wrongAad =
          assertThrows(
              CryptographicFailureException.class,
              () -> kek.unwrapKey(Expect.aes(256), dek.wrapped(), null));
      assertEquals(CryptographicFailureException.Kind.AUTHENTICATION_FAILED, wrongAad.kind());
      Ciphertext cbcWrapped = kek.wrapKey(CipherSpec.cbc(), dek.key(), null);
      assertInvalid(() -> kek.unwrapKey(Expect.aes(256), cbcWrapped, null));
    }
  }

  // ---- ambiguous server failures are not reported as tampering ----

  @Test
  void genericServerFailuresOnAeadDecryptAreUnconfirmed() {
    Enums.ResultReason[] reason = {null};
    connect(
        ProtocolVersion.V2_1,
        mock ->
            new KmipTransport() {
              @Override
              public Ttlv exchange(Ttlv request) throws IOException {
                if (reason[0] != null && Faults.operation(request) == Operation.DECRYPT.code())
                  return Faults.failure(request, reason[0], "no");
                return mock.exchange(request);
              }
            });
    KeyHandle key = aes("ambiguous");
    Ciphertext c = key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    for (var r : List.of(Enums.ResultReason.INVALID_FIELD, Enums.ResultReason.GENERAL_FAILURE)) {
      reason[0] = r;
      var e = assertThrows(CryptographicFailureException.class, () -> key.decrypt(c, AAD));
      assertEquals(CryptographicFailureException.Kind.UNCONFIRMED, e.kind(), r.toString());
    }
    reason[0] = Enums.ResultReason.CRYPTOGRAPHIC_FAILURE;
    var e = assertThrows(CryptographicFailureException.class, () -> key.decrypt(c, AAD));
    assertEquals(CryptographicFailureException.Kind.AUTHENTICATION_FAILED, e.kind());
    // On a mode that is not tamper-evident a generic reason is just an invalid request.
    reason[0] = null;
    Ciphertext ctr = key.encrypt(CipherSpec.ctr(), PLAIN);
    reason[0] = Enums.ResultReason.INVALID_FIELD;
    assertThrows(InvalidRequestException.class, () -> key.decrypt(CipherSpec.ctr(), ctr, null));
  }
}
