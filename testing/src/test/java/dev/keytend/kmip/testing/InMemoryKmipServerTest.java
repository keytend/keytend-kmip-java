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

package dev.keytend.kmip.testing;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.keytend.kmip.client.CertificateRegistration;
import dev.keytend.kmip.client.CryptoParameters;
import dev.keytend.kmip.client.CryptoRequests;
import dev.keytend.kmip.client.CryptoResult;
import dev.keytend.kmip.client.GetAttributesResult;
import dev.keytend.kmip.client.KeyPairRequest;
import dev.keytend.kmip.client.KeyWrapping;
import dev.keytend.kmip.client.KmipClient;
import dev.keytend.kmip.client.KmipException;
import dev.keytend.kmip.client.LocateRequest;
import dev.keytend.kmip.client.Messages;
import dev.keytend.kmip.client.ObjectViews;
import dev.keytend.kmip.client.ProtocolException;
import dev.keytend.kmip.client.Request;
import dev.keytend.kmip.client.RequestOptions;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.client.Response;
import dev.keytend.kmip.client.Result;
import dev.keytend.kmip.client.SignatureVerifyResult;
import dev.keytend.kmip.client.VersionPolicy;
import dev.keytend.kmip.kms.*;
import dev.keytend.kmip.model.Attributes;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Enums.BlockCipherMode;
import dev.keytend.kmip.model.Enums.CryptographicAlgorithm;
import dev.keytend.kmip.model.Enums.CryptographicUsageMask;
import dev.keytend.kmip.model.Enums.KeyFormatType;
import dev.keytend.kmip.model.Enums.LinkType;
import dev.keytend.kmip.model.Enums.ResultReason;
import dev.keytend.kmip.model.Enums.State;
import dev.keytend.kmip.model.Keys;
import dev.keytend.kmip.model.ManagedObjects;
import dev.keytend.kmip.model.ModernAttributes;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.ProtocolVersion;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.model.UsageMask;
import dev.keytend.kmip.transport.CallContext;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Drives {@link InMemoryKmipServer} through the protocol-layer client at every target version. */
class InMemoryKmipServerTest {
  /** A self-signed EC P-256 certificate made with keytool (CN=keytend-mock). */
  private static final String CERTIFICATE =
      "MIIBRjCB7KADAgECAgkAuCX4sFlA1AQwCgYIKoZIzj0EAwIwFjEUMBIGA1UEAxMLeWFrbWlwLW1vY2swIBcNMjYx"
          + "MDI2MTkyNDM0WhgPMjEyNjEwMDIxOTI0MzRaMBYxFDASBgNVBAMTC3lha21pcC1tb2NrMFkwEwYHKoZIzj0C"
          + "AQYIKoZIzj0DAQcDQgAELjYdbEHqX+mhHBu395QWGVsbYtfRSB9JsG0pb3icUPFfEiTXDSA39NleQS80C7J9"
          + "hXL5bLmyi3DucVFml3gDPqMhMB8wHQYDVR0OBBYEFEfOgJFy+ffzWjKhQEyIq5zfObwIMAoGCCqGSM49BAMC"
          + "A0kAMEYCIQDhwmWsounXYYspD8m9Jpx4CfMKJypyRC4zELbgYEAdswIhAKsBoYNQNawM6jpW2IJng8W/aeIa"
          + "ijuHuxhhzvg2H/Zy";

  private static ResultReason lifecycle(ProtocolVersion v) {
    return v.legacyAttributes()
        ? ResultReason.ILLEGAL_OPERATION
        : ResultReason.WRONG_KEY_LIFECYCLE_STATE;
  }

  private static String createAes(KmipClient client, int bits, String name, Ttlv... extra)
      throws IOException {
    List<Ttlv> attributes =
        new ArrayList<>(
            List.of(
                Attributes.algorithm(CryptographicAlgorithm.AES),
                Attributes.length(bits),
                Attributes.usage(CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT)));
    if (name != null) attributes.add(Attributes.name(name));
    attributes.addAll(List.of(extra));
    return client
        .call(
            Requests.create()
                .add(enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY))
                .template(attributes.toArray(Ttlv[]::new))
                .build())
        .uniqueIdentifier();
  }

  @ParameterizedTest
  @EnumSource(names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void aesGcmRoundTrip(ProtocolVersion v) throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, v);
    String id =
        client.createSymmetricKey(
            CryptographicAlgorithm.AES,
            256,
            CryptographicUsageMask.ENCRYPT,
            CryptographicUsageMask.DECRYPT);
    Result early =
        client.execute(
            CryptoRequests.encrypt(id)
                .parameters(CryptoParameters.aesGcm())
                .data(new byte[1])
                .build());
    // A state refusal of a cryptographic operation is Permission Denied in 1.x (KMIP 1.4 section
    // 11.30), Wrong Key Lifecycle State from 2.0.
    assertTrue(
        early.hasReason(
            v.legacyAttributes()
                ? ResultReason.PERMISSION_DENIED
                : ResultReason.WRONG_KEY_LIFECYCLE_STATE),
        "Pre-Active keys do not encrypt");
    client.activate(id);
    assertEquals(Optional.of(State.ACTIVE), mock.protocolState(id));

    byte[] plaintext = "attack at dawn".getBytes(UTF_8), aad = "header".getBytes(UTF_8);
    boolean aead = v.atLeast(ProtocolVersion.V1_4);
    CryptoRequests.Builder encrypt =
        CryptoRequests.encrypt(id).parameters(CryptoParameters.aesGcm()).data(plaintext);
    if (aead) encrypt.aad(aad);
    CryptoResult sealed = CryptoResult.of(client.call(encrypt.build()));
    byte[] iv = sealed.ivCounterNonce().orElseThrow();
    assertEquals(12, iv.length);
    assertEquals(aead, sealed.authenticatedEncryptionTag().isPresent());

    CryptoRequests.Builder decrypt =
        CryptoRequests.decrypt(id)
            .parameters(CryptoParameters.aesGcm())
            .data(sealed.data().orElseThrow())
            .iv(iv);
    if (aead) decrypt.aad(aad).tag(sealed.authenticatedEncryptionTag().orElseThrow());
    assertArrayEquals(
        plaintext, CryptoResult.of(client.call(decrypt.build())).data().orElseThrow());

    byte[] tampered = sealed.data().orElseThrow();
    tampered[0] ^= 1;
    CryptoRequests.Builder bad =
        CryptoRequests.decrypt(id).parameters(CryptoParameters.aesGcm()).data(tampered).iv(iv);
    if (aead) bad.aad(aad).tag(sealed.authenticatedEncryptionTag().orElseThrow());
    assertTrue(client.execute(bad.build()).hasReason(ResultReason.CRYPTOGRAPHIC_FAILURE));

    CryptoParameters cbc =
        CryptoParameters.builder()
            .algorithm(CryptographicAlgorithm.AES)
            .mode(BlockCipherMode.CBC)
            .padding(Enums.PaddingMethod.PKCS5)
            .build();
    CryptoResult cbcOut =
        CryptoResult.of(
            client.call(CryptoRequests.encrypt(id).parameters(cbc).data(plaintext).build()));
    byte[] cbcPlain =
        CryptoResult.of(
                client.call(
                    CryptoRequests.decrypt(id)
                        .parameters(cbc)
                        .data(cbcOut.data().orElseThrow())
                        .iv(cbcOut.ivCounterNonce().orElseThrow())
                        .build()))
            .data()
            .orElseThrow();
    assertArrayEquals(plaintext, cbcPlain);
    assertEquals(List.of(), mock.violations());
  }

  @ParameterizedTest
  @EnumSource(names = {"V1_2", "V1_4", "V2_0", "V3_0"})
  void usageMaskIsEnforced(ProtocolVersion v) throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, v);
    String id =
        client.createSymmetricKey(CryptographicAlgorithm.AES, 128, CryptographicUsageMask.ENCRYPT);
    client.activate(id);
    Result r =
        client.execute(
            CryptoRequests.decrypt(id)
                .parameters(CryptoParameters.aesGcm())
                .data(new byte[32])
                .iv(new byte[12])
                .build());
    assertTrue(
        r.hasReason(
            v.legacyAttributes()
                ? ResultReason.PERMISSION_DENIED
                : ResultReason.INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK));
    assertEquals(List.of(), mock.violations());
  }

  @ParameterizedTest
  @EnumSource(names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void registerAndGetJcaRsaKeys(ProtocolVersion v) throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, v);
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(2048);
    KeyPair pair = g.generateKeyPair();
    Ttlv privateKey =
        ManagedObjects.privateKey(
            ManagedObjects.keyBlock(
                KeyFormatType.PKCS_8,
                bytes(KEY_MATERIAL, pair.getPrivate().getEncoded()),
                CryptographicAlgorithm.RSA,
                2048));
    Ttlv publicKey =
        ManagedObjects.publicKey(
            ManagedObjects.keyBlock(
                KeyFormatType.X_509,
                bytes(KEY_MATERIAL, pair.getPublic().getEncoded()),
                CryptographicAlgorithm.RSA,
                2048));
    String privateId =
        client.register(
            privateKey,
            Attributes.usage(CryptographicUsageMask.SIGN),
            Attributes.name("rsa-signing"));
    String publicId = client.register(publicKey, Attributes.usage(CryptographicUsageMask.VERIFY));
    assertEquals(List.of("rsa-signing"), mock.names(privateId));

    assertArrayEquals(
        pair.getPublic().getEncoded(),
        Keys.rsaPublicKey(client.get(publicId).requirePayload(), publicId).getEncoded());
    assertArrayEquals(
        pair.getPrivate().getEncoded(),
        Keys.privateKey(
                client.get(privateId).requirePayload(), privateId, CryptographicAlgorithm.RSA, 2048)
            .getEncoded());
    for (KeyFormatType format :
        List.of(KeyFormatType.TRANSPARENT_RSA_PUBLIC_KEY, KeyFormatType.PKCS_1)) {
      Result r =
          client.call(
              Requests.get()
                  .uniqueIdentifier(publicId)
                  .add(enumeration(KEY_FORMAT_TYPE, format))
                  .build());
      assertEquals(
          format.code(),
          r.requirePayload()
              .require(PUBLIC_KEY)
              .require(KEY_BLOCK)
              .require(KEY_FORMAT_TYPE)
              .intValue());
      assertArrayEquals(
          pair.getPublic().getEncoded(),
          Keys.rsaPublicKey(r.requirePayload(), publicId).getEncoded());
    }
    Result pkcs1 =
        client.call(
            Requests.get()
                .uniqueIdentifier(privateId)
                .add(enumeration(KEY_FORMAT_TYPE, KeyFormatType.PKCS_1))
                .build());
    assertArrayEquals(
        pair.getPrivate().getEncoded(),
        Keys.privateKey(pkcs1.requirePayload(), privateId, CryptographicAlgorithm.RSA, 2048)
            .getEncoded());
    assertEquals(List.of(), mock.violations());
  }

  @ParameterizedTest
  @EnumSource(names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void keyPairsSignAndVerify(ProtocolVersion v) throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, v);
    byte[] message = "pay 10 coins".getBytes(UTF_8);

    KeyPairRequest.Ids rsa =
        KeyPairRequest.result(
            client.call(
                KeyPairRequest.rsa(2048)
                    .privateUsage(UsageMask.of(CryptographicUsageMask.SIGN))
                    .publicUsage(UsageMask.of(CryptographicUsageMask.VERIFY))
                    .name("signer")
                    .build()));
    assertEquals(
        Optional.of(rsa.publicKeyId()),
        mock.protocolLink(rsa.privateKeyId(), LinkType.PUBLIC_KEY_LINK));
    assertEquals(
        Optional.of(rsa.privateKeyId()),
        mock.protocolLink(rsa.publicKeyId(), LinkType.PRIVATE_KEY_LINK));
    assertEquals(List.of("signer-public"), mock.names(rsa.publicKeyId()));
    client.activate(rsa.privateKeyId());
    client.activate(rsa.publicKeyId());
    CryptoParameters pkcs1 =
        CryptoParameters.builder()
            .digitalSignature(
                Enums.DigitalSignatureAlgorithm.SHA_256_WITH_RSA_ENCRYPTION_PKCS_1_V1_5)
            .build();
    byte[] signature = sign(client, rsa.privateKeyId(), pkcs1, message);
    PublicKey rsaPublic =
        Keys.rsaPublicKey(client.get(rsa.publicKeyId()).requirePayload(), rsa.publicKeyId());
    Signature local = Signature.getInstance("SHA256withRSA");
    local.initVerify(rsaPublic);
    local.update(message);
    assertTrue(local.verify(signature));
    assertTrue(verify(client, rsa.publicKeyId(), pkcs1, message, signature));
    assertFalse(
        verify(client, rsa.publicKeyId(), pkcs1, "pay 99 coins".getBytes(UTF_8), signature));
    if (v.atLeast(ProtocolVersion.V1_4)) {
      CryptoParameters pss = CryptoParameters.rsaPss(Enums.HashingAlgorithm.SHA_256, 32);
      byte[] pssSignature = sign(client, rsa.privateKeyId(), pss, message);
      assertTrue(verify(client, rsa.publicKeyId(), pss, message, pssSignature));
      assertFalse(verify(client, rsa.publicKeyId(), pss, message, new byte[256]));
    }

    KeyPairRequest.Ids ec =
        KeyPairRequest.result(
            client.call(
                KeyPairRequest.ec(Enums.RecommendedCurve.P_256, CryptographicAlgorithm.EC)
                    .privateUsage(UsageMask.of(CryptographicUsageMask.SIGN))
                    .publicUsage(UsageMask.of(CryptographicUsageMask.VERIFY))
                    .build()));
    client.activate(ec.privateKeyId());
    client.activate(ec.publicKeyId());
    CryptoParameters ecdsa =
        CryptoParameters.builder()
            .digitalSignature(Enums.DigitalSignatureAlgorithm.ECDSA_WITH_SHA256)
            .build();
    byte[] ecSignature = sign(client, ec.privateKeyId(), ecdsa, message);
    PublicKey ecPublic =
        Keys.publicKey(
            client.get(ec.publicKeyId()).requirePayload(),
            ec.publicKeyId(),
            CryptographicAlgorithm.EC,
            256);
    Signature ecLocal = Signature.getInstance("SHA256withECDSA");
    ecLocal.initVerify(ecPublic);
    ecLocal.update(message);
    assertTrue(ecLocal.verify(ecSignature));
    assertTrue(verify(client, ec.publicKeyId(), ecdsa, message, ecSignature));
    assertFalse(verify(client, ec.publicKeyId(), ecdsa, new byte[3], ecSignature));
    assertEquals(List.of(), mock.violations());
  }

  private static byte[] sign(KmipClient client, String id, CryptoParameters p, byte[] data)
      throws IOException {
    return CryptoResult.of(client.call(CryptoRequests.sign(id).parameters(p).data(data).build()))
        .signatureData()
        .orElseThrow();
  }

  private static boolean verify(
      KmipClient client, String id, CryptoParameters p, byte[] data, byte[] signature)
      throws IOException {
    return SignatureVerifyResult.of(
            client.call(
                CryptoRequests.signatureVerify(id)
                    .parameters(p)
                    .data(data)
                    .signature(signature)
                    .build()))
        .valid();
  }

  @ParameterizedTest
  @EnumSource(names = {"V1_2", "V1_4", "V2_0", "V3_0"})
  void macRsaOaepAndRng(ProtocolVersion v) throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, v);
    String hmac =
        client.createSymmetricKey(
            CryptographicAlgorithm.HMAC_SHA256,
            256,
            CryptographicUsageMask.MAC_GENERATE,
            CryptographicUsageMask.MAC_VERIFY);
    client.activate(hmac);
    byte[] data = "ledger".getBytes(UTF_8);
    byte[] mac =
        CryptoResult.of(client.call(CryptoRequests.mac(hmac).data(data).build()))
            .macData()
            .orElseThrow();
    assertEquals(32, mac.length);
    assertTrue(
        CryptoResult.of(client.call(CryptoRequests.macVerify(hmac).data(data).macData(mac).build()))
            .valid());
    mac[0] ^= 1;
    assertFalse(
        CryptoResult.of(client.call(CryptoRequests.macVerify(hmac).data(data).macData(mac).build()))
            .valid());

    KeyPairRequest.Ids rsa =
        KeyPairRequest.result(
            client.call(
                KeyPairRequest.rsa(2048)
                    .privateUsage(UsageMask.of(CryptographicUsageMask.DECRYPT))
                    .publicUsage(UsageMask.of(CryptographicUsageMask.ENCRYPT))
                    .build()));
    client.activate(rsa.privateKeyId());
    client.activate(rsa.publicKeyId());
    CryptoParameters oaep =
        v.atLeast(ProtocolVersion.V1_4)
            ? CryptoParameters.rsaOaep(Enums.HashingAlgorithm.SHA_256)
            : CryptoParameters.builder()
                .algorithm(CryptographicAlgorithm.RSA)
                .padding(Enums.PaddingMethod.OAEP)
                .hashing(Enums.HashingAlgorithm.SHA_256)
                .build();
    byte[] sealed =
        CryptoResult.of(
                client.call(
                    CryptoRequests.encrypt(rsa.publicKeyId()).parameters(oaep).data(data).build()))
            .data()
            .orElseThrow();
    assertArrayEquals(
        data,
        CryptoResult.of(
                client.call(
                    CryptoRequests.decrypt(rsa.privateKeyId())
                        .parameters(oaep)
                        .data(sealed)
                        .build()))
            .data()
            .orElseThrow());

    assertEquals(
        24,
        CryptoResult.of(client.call(CryptoRequests.rngRetrieve(24))).data().orElseThrow().length);
    assertEquals(List.of(), mock.violations());
  }

  @ParameterizedTest
  @EnumSource(names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void locateByNameWithPaging(ProtocolVersion v) throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, v);
    List<String> batch = new ArrayList<>();
    for (int i = 0; i < 5; i++) batch.add(createAes(client, 128, "batch-key"));
    String other = createAes(client, 128, "other");

    LocateRequest byName = LocateRequest.builder().name("batch-key").build();
    assertEquals(batch, LocateRequest.result(client.call(byName.toRequest())).identifiers());
    LocateRequest.Page first = LocateRequest.result(client.call(byName.page(0, 2)));
    assertEquals(batch.subList(0, 2), first.identifiers());
    if (v.atLeast(ProtocolVersion.V1_3)) {
      assertEquals(5, first.locatedItems());
      assertEquals(
          batch.subList(2, 4), LocateRequest.result(client.call(byName.page(2, 2))).identifiers());
      assertEquals(batch, client.locateAll(byName, 2));
    } else assertNull(first.locatedItems());

    LocateRequest combined =
        LocateRequest.builder()
            .objectType(Enums.ObjectType.SYMMETRIC_KEY)
            .state(State.PRE_ACTIVE)
            .algorithm(CryptographicAlgorithm.AES)
            .name("other")
            .build();
    assertEquals(
        List.of(other), LocateRequest.result(client.call(combined.toRequest())).identifiers());
    LocateRequest active = LocateRequest.builder().state(State.ACTIVE).build();
    assertEquals(List.of(), LocateRequest.result(client.call(active.toRequest())).identifiers());
    assertEquals(List.of(), mock.violations());
  }

  /** Normalized attribute names of a Get Attributes result ("cryptographicalgorithm", "xowner"). */
  private static Set<String> names(GetAttributesResult result) {
    return result.attributes().stream()
        .map(
            a -> {
              if (a.tag() != ATTRIBUTE.code()) return Tag.normalize(a.tagName());
              String name = a.require(ATTRIBUTE_NAME).textValue();
              return Tag.normalize(
                  a.child(VENDOR_IDENTIFICATION).map(n -> n.textValue() + "-" + name).orElse(name));
            })
        .collect(Collectors.toSet());
  }

  /**
   * Whether a 1.x Attribute or a 2.x/3.0 direct attribute is the standard attribute {@code tag}.
   */
  private static boolean isAttribute(Ttlv a, Tag tag) {
    if (a.tag() != ATTRIBUTE.code()) return a.tag() == tag.code();
    return Tag.normalize(a.require(ATTRIBUTE_NAME).textValue())
        .equals(Tag.normalize(tag.wireName()));
  }

  @ParameterizedTest
  @EnumSource(names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void getAttributesAllSelectedAndEmpty(ProtocolVersion v) throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, v);
    List<Ttlv> extra = new ArrayList<>(List.of(Attributes.textAttribute("x-Owner", "team-a")));
    if (v != ProtocolVersion.V3_0)
      extra.add(Attributes.attribute("Object Group", text(OBJECT_GROUP, "payments")));
    String id = createAes(client, 256, "attr-key", extra.toArray(Ttlv[]::new));
    client.activate(id);

    GetAttributesResult all =
        GetAttributesResult.of(client.call(Requests.getAttributes().uniqueIdentifier(id).build()));
    Set<String> expected =
        Set.of(
            "uniqueidentifier",
            "objecttype",
            "name",
            "state",
            "cryptographicalgorithm",
            "cryptographiclength",
            "cryptographicusagemask",
            "initialdate",
            "activationdate",
            "xowner");
    assertTrue(names(all).containsAll(expected), names(all).toString());
    assertEquals(v != ProtocolVersion.V3_0, names(all).contains("objectgroup"));
    Ttlv name =
        all.attributes().stream().filter(a -> isAttribute(a, NAME)).findFirst().orElseThrow();
    if (v.legacyAttributes())
      assertEquals(Ttlv.Type.STRUCTURE, name.require(ATTRIBUTE_VALUE).type());
    else if (v == ProtocolVersion.V3_0) assertEquals(Ttlv.Type.TEXT_STRING, name.type());
    else assertEquals("attr-key", name.require(NAME_VALUE).textValue());

    GetAttributesResult selected =
        GetAttributesResult.of(
            client.call(
                Requests.getAttributes()
                    .uniqueIdentifier(id)
                    .add(
                        text(ATTRIBUTE_NAME, "Cryptographic Algorithm"),
                        text(ATTRIBUTE_NAME, "x-Owner"))
                    .build()));
    assertEquals(Set.of("cryptographicalgorithm", "xowner"), names(selected));

    GetAttributesResult empty =
        GetAttributesResult.of(
            client.call(
                Requests.getAttributes()
                    .uniqueIdentifier(id)
                    .add(text(ATTRIBUTE_NAME, "Contact Information"))
                    .build()));
    assertTrue(empty.isEmpty());
    assertEquals(id, empty.uniqueIdentifier());

    Result list = client.call(Requests.getAttributeList().uniqueIdentifier(id).build());
    assertTrue(list.requirePayload().children().size() > expected.size());
    assertEquals(List.of(), mock.violations());
  }

  @ParameterizedTest
  @EnumSource(names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void customAndVendorAttributesCanBeAddedModifiedAndDeleted(ProtocolVersion v) throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, v);
    String id = createAes(client, 128, null);
    client.call(
        Requests.addAttribute()
            .uniqueIdentifier(id)
            .attribute(Attributes.textAttribute("x-Note", "one"))
            .build());
    client.call(
        Requests.modifyAttribute()
            .uniqueIdentifier(id)
            .attribute(Attributes.textAttribute("x-Note", "two"))
            .build());
    assertEquals(List.of(text(ATTRIBUTE_VALUE, "two")), mock.protocolAttributes(id).get("x-Note"));
    client.call(
        Requests.addAttribute()
            .uniqueIdentifier(id)
            .attribute(Attributes.name("second-name"))
            .build());
    assertEquals(List.of("second-name"), mock.names(id));
    if (!v.legacyAttributes()) {
      client.call(
          Requests.addAttribute()
              .uniqueIdentifier(id)
              .newAttribute(ModernAttributes.vendor("acme", "Tier", text(ATTRIBUTE_VALUE, "gold")))
              .build());
      client.call(
          Requests.modifyAttribute()
              .uniqueIdentifier(id)
              .newAttribute(
                  ModernAttributes.vendor("acme", "Tier", text(ATTRIBUTE_VALUE, "platinum")))
              .build());
      assertEquals(
          List.of(text(ATTRIBUTE_VALUE, "platinum")), mock.protocolAttributes(id).get("acme-Tier"));
      client.call(
          Requests.deleteAttribute()
              .uniqueIdentifier(id)
              .add(ModernAttributes.vendorReference("acme", "Tier"))
              .build());
      assertNull(mock.protocolAttributes(id).get("acme-Tier"));
    }
    client.call(
        Requests.deleteAttribute()
            .uniqueIdentifier(id)
            .add(text(ATTRIBUTE_NAME, "x-Note"))
            .build());
    assertNull(mock.protocolAttributes(id).get("x-Note"));
    Result readOnly =
        client.execute(
            Requests.addAttribute()
                .uniqueIdentifier(id)
                .attribute(Attributes.attribute("State", enumeration(STATE, State.ACTIVE)))
                .build());
    assertFalse(readOnly.successful());
    assertEquals(List.of(), mock.violations());
  }

  /**
   * A Key Compromise Revoke with a Compromise Occurrence Date, which KMIP 1.1 and 1.2 require
   *.
   */
  static void compromise(KmipClient client, String id) throws Exception {
    client.call(
        Requests.revoke()
            .uniqueIdentifier(id)
            .add(
                structure(
                    REVOCATION_REASON,
                    enumeration(REVOCATION_REASON_CODE, Enums.RevocationReasonCode.KEY_COMPROMISE),
                    text(REVOCATION_MESSAGE, "leaked")))
            .add(dateTime(COMPROMISE_OCCURRENCE_DATE, Instant.parse("2025-01-01T00:00:00Z")))
            .build());
  }

  /**
   * Deactivates {@code id}: a Revoke with {@code reason} up to 2.1, the Deactivate of the 3.0 draft,
   * where a Revoke compromises (CSD02 §6.1.51).
   */
  static void retire(
      KmipClient client, ProtocolVersion v, String id, Enums.RevocationReasonCode reason)
      throws Exception {
    if (v.atLeast(ProtocolVersion.V3_0))
      client.call(Requests.deactivate().uniqueIdentifier(id).build());
    else client.revoke(id, reason, null);
  }

  @ParameterizedTest
  @EnumSource(names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void revokeAndDestroyFollowTheLifecycle(ProtocolVersion v) throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, v);
    String a = createAes(client, 128, "lifecycle");
    client.activate(a);
    // An Activate of an object that is not Pre-Active is Permission Denied in 1.x (KMIP 1.4 Table
    // 346).
    assertTrue(
        client
            .execute(Requests.activate().uniqueIdentifier(a).build())
            .hasReason(
                v.atLeast(ProtocolVersion.V2_0)
                    ? lifecycle(v)
                    : Enums.ResultReason.PERMISSION_DENIED));
    assertTrue(
        client.execute(Requests.destroy().uniqueIdentifier(a).build()).hasReason(lifecycle(v)));
    compromise(client, a);
    assertEquals(Optional.of(State.COMPROMISED), mock.protocolState(a));
    assertTrue(mock.protocolAttributes(a).containsKey("Compromise Date"));
    client.destroy(a);
    assertEquals(Optional.of(State.DESTROYED_COMPROMISED), mock.protocolState(a));
    assertFalse(mock.exists(a));
    assertFalse(mock.hasMaterial(a));
    assertTrue(
        client
            .execute(Requests.get().uniqueIdentifier(a).build())
            .hasReason(ResultReason.ITEM_NOT_FOUND));
    GetAttributesResult state =
        GetAttributesResult.of(
            client.call(
                Requests.getAttributes()
                    .uniqueIdentifier(a)
                    .add(text(ATTRIBUTE_NAME, "State"))
                    .build()));
    assertEquals(1, state.attributes().size());

    String b = createAes(client, 128, null);
    client.activate(b);
    retire(client, v, b, Enums.RevocationReasonCode.CESSATION_OF_OPERATION);
    assertEquals(Optional.of(State.DEACTIVATED), mock.protocolState(b));
    client.destroy(b);
    assertEquals(Optional.of(State.DESTROYED), mock.protocolState(b));
    assertEquals(
        List.of(),
        LocateRequest.result(
                client.call(LocateRequest.builder().name("lifecycle").build().toRequest()))
            .identifiers());
    assertEquals(List.of(), mock.violations());
  }

  @ParameterizedTest
  @EnumSource(names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void wrappedGetFollowsTheKekParameterRule(ProtocolVersion v) throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, v);
    Ttlv wrapUsage =
        Attributes.usage(CryptographicUsageMask.WRAP_KEY, CryptographicUsageMask.UNWRAP_KEY);
    Ttlv nistParameters =
        Attributes.attribute(
            "Cryptographic Parameters",
            structure(
                CRYPTOGRAPHIC_PARAMETERS,
                enumeration(BLOCK_CIPHER_MODE, BlockCipherMode.NISTKEY_WRAP)));
    String kek = kek(client, wrapUsage, nistParameters);
    String bare = kek(client, wrapUsage);
    String target = createAes(client, 128, null);
    CryptoParameters nist = CryptoParameters.builder().mode(BlockCipherMode.NISTKEY_WRAP).build();

    Ttlv block =
        client
            .call(wrappedGet(target, KeyWrapping.encrypt(kek, nist).noEncoding()))
            .requirePayload()
            .require(SYMMETRIC_KEY)
            .require(KEY_BLOCK);
    assertEquals(Ttlv.Type.BYTE_STRING, block.require(KEY_VALUE).type());
    assertTrue(block.child(KEY_WRAPPING_DATA).isPresent());
    SecretKey kekKey = Keys.aesKey(client.get(kek).requirePayload(), kek, 256);
    Cipher unwrap = Cipher.getInstance("AESWrap");
    unwrap.init(Cipher.DECRYPT_MODE, kekKey);
    assertArrayEquals(
        Keys.aesKey(client.get(target).requirePayload(), target, 128).getEncoded(),
        unwrap.doFinal(block.require(KEY_VALUE).bytesValue()));

    // Without parameters in the request the KEK's stored mode is used.
    assertTrue(
        client
            .execute(wrappedGet(target, KeyWrapping.encrypt(kek, null).noEncoding()))
            .successful());
    // The KEK needs a stored Cryptographic Parameters with the requested mode.
    assertTrue(
        client
            .execute(wrappedGet(target, KeyWrapping.encrypt(bare, nist).noEncoding()))
            .hasReason(ResultReason.INVALID_FIELD));
    assertTrue(
        client
            .execute(wrappedGet(target, KeyWrapping.encrypt(bare, null).noEncoding()))
            .hasReason(ResultReason.INVALID_FIELD));
    CryptoParameters padded =
        CryptoParameters.builder().mode(BlockCipherMode.AESKEY_WRAP_PADDING).build();
    assertTrue(
        client
            .execute(wrappedGet(target, KeyWrapping.encrypt(kek, padded).noEncoding()))
            .hasReason(ResultReason.INVALID_FIELD));
    assertEquals(List.of(), mock.violations());
  }

  private static String kek(KmipClient client, Ttlv... extra) throws IOException {
    List<Ttlv> attributes =
        new ArrayList<>(
            List.of(Attributes.algorithm(CryptographicAlgorithm.AES), Attributes.length(256)));
    attributes.addAll(List.of(extra));
    String id =
        client
            .call(
                Requests.create()
                    .add(enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY))
                    .template(attributes.toArray(Ttlv[]::new))
                    .build())
            .uniqueIdentifier();
    client.activate(id);
    return id;
  }

  private static Request wrappedGet(String id, KeyWrapping spec) {
    return Requests.get().uniqueIdentifier(id).add(spec.toTtlv()).build();
  }

  /** The first stored value of {@code attribute} of {@code id}, as a date. */
  private static Optional<Instant> date(InMemoryKmipServer mock, String id, String attribute) {
    return mock.protocolAttributes(id).getOrDefault(attribute, List.of()).stream()
        .findFirst()
        .map(Ttlv::instantValue);
  }

  /**
   * A Re-key without an Offset copies the old key's Activation, Process Start,
   * Protect Stop and Deactivation Dates, and only the Initial Date is new (KMIP 1.4 §4.4, 2.1
   * §6.1.46); the State follows from the dates: Active for an activated key, also a Compromised
   * one, Deactivated once the Deactivation Date has passed, Pre-Active without an Activation Date.
   * Before, the replacement got new dates, activated now when the old key was Active and left
   * Pre-Active otherwise; {@code freshDatesOnReKey(true)} still does that. With an Offset, the
   * replacement is activated Offset seconds after its Initial Date and the other dates move by
   * as much; an Offset for a key with other dates and no Activation Date is refused (Illegal
   * Operation in 1.x, Wrong Key Lifecycle State from 2.0).
   */
  @ParameterizedTest
  @EnumSource(names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void reKeyCopiesTheLifecycleDates(ProtocolVersion v) throws Exception {
    Instant start = Instant.parse("2026-01-01T00:00:00Z"), later = start.plusSeconds(86_400 * 40);
    InMemoryKmipServer mock = new InMemoryKmipServer();
    mock.clock(Clock.fixed(start, ZoneOffset.UTC));
    KmipClient client = new KmipClient(mock, v);
    Instant processStart = start.plusSeconds(3600), protectStop = start.plusSeconds(86_400 * 300);
    Instant deactivation = start.plusSeconds(86_400 * 400);
    String old =
        createAes(
            client,
            256,
            null,
            Attributes.attribute("Process Start Date", dateTime(PROCESS_START_DATE, processStart)),
            Attributes.attribute("Protect Stop Date", dateTime(PROTECT_STOP_DATE, protectStop)),
            Attributes.attribute("Deactivation Date", dateTime(DEACTIVATION_DATE, deactivation)));
    client.activate(old);
    mock.clock(Clock.fixed(later, ZoneOffset.UTC));
    String next = client.call(Requests.reKey().uniqueIdentifier(old).build()).uniqueIdentifier();
    assertEquals(Optional.of(State.ACTIVE), mock.protocolState(next));
    assertEquals(Optional.of(later), date(mock, next, "Initial Date"), "the one new date");
    assertEquals(Optional.of(start), date(mock, next, "Activation Date"), "copied");
    assertEquals(Optional.of(processStart), date(mock, next, "Process Start Date"));
    assertEquals(Optional.of(protectStop), date(mock, next, "Protect Stop Date"));
    assertEquals(Optional.of(deactivation), date(mock, next, "Deactivation Date"));

    // A Compromised key's replacement is Active (no Compromise Date is copied); a Deactivated
    // key's is Deactivated (its Deactivation Date has passed); a Pre-Active key's is Pre-Active.
    String compromised = createAes(client, 256, null);
    client.activate(compromised);
    compromise(client, compromised);
    String fromCompromised =
        client.call(Requests.reKey().uniqueIdentifier(compromised).build()).uniqueIdentifier();
    assertEquals(Optional.of(State.ACTIVE), mock.protocolState(fromCompromised));
    assertEquals(Optional.empty(), date(mock, fromCompromised, "Compromise Date"));
    String retired = createAes(client, 256, null);
    client.activate(retired);
    retire(client, v, retired, Enums.RevocationReasonCode.CESSATION_OF_OPERATION);
    String fromRetired =
        client.call(Requests.reKey().uniqueIdentifier(retired).build()).uniqueIdentifier();
    assertEquals(Optional.of(State.DEACTIVATED), mock.protocolState(fromRetired));
    String unused = createAes(client, 256, null);
    String fromUnused =
        client.call(Requests.reKey().uniqueIdentifier(unused).build()).uniqueIdentifier();
    assertEquals(Optional.of(State.PRE_ACTIVE), mock.protocolState(fromUnused));
    assertEquals(Optional.empty(), date(mock, fromUnused, "Activation Date"));

    // With an Offset: AT2 = IT2 + Offset, the other dates shifted by AT2 - AT1.
    Instant reKeyed = later.plusSeconds(60);
    mock.clock(Clock.fixed(reKeyed, ZoneOffset.UTC));
    String offset =
        client
            .call(Requests.reKey().uniqueIdentifier(next).add(interval(OFFSET, 3600)).build())
            .uniqueIdentifier();
    Instant activation = reKeyed.plusSeconds(3600);
    long shift = activation.getEpochSecond() - start.getEpochSecond();
    assertEquals(Optional.of(State.PRE_ACTIVE), mock.protocolState(offset), "activated in an hour");
    assertEquals(Optional.of(activation), date(mock, offset, "Activation Date"));
    assertEquals(
        Optional.of(processStart.plusSeconds(shift)), date(mock, offset, "Process Start Date"));
    assertEquals(
        Optional.of(protectStop.plusSeconds(shift)), date(mock, offset, "Protect Stop Date"));
    assertEquals(
        Optional.of(deactivation.plusSeconds(shift)), date(mock, offset, "Deactivation Date"));
    String undated =
        createAes(
            client,
            256,
            null,
            Attributes.attribute("Deactivation Date", dateTime(DEACTIVATION_DATE, deactivation)));
    assertTrue(
        client
            .execute(Requests.reKey().uniqueIdentifier(undated).add(interval(OFFSET, 0)).build())
            .hasReason(
                v.atLeast(ProtocolVersion.V2_0)
                    ? ResultReason.WRONG_KEY_LIFECYCLE_STATE
                    : ResultReason.ILLEGAL_OPERATION));

    // freshDatesOnReKey: a server that gives the replacement fresh dates.
    mock.freshDatesOnReKey(true);
    String fresh =
        client.call(Requests.reKey().uniqueIdentifier(offset).build()).uniqueIdentifier();
    assertEquals(
        Optional.of(State.PRE_ACTIVE), mock.protocolState(fresh), "the old key is not Active");
    assertEquals(Optional.empty(), date(mock, fresh, "Deactivation Date"));
    String freshActive =
        client.call(Requests.reKey().uniqueIdentifier(next).build()).uniqueIdentifier();
    assertEquals(Optional.of(State.ACTIVE), mock.protocolState(freshActive));
    assertEquals(Optional.of(reKeyed), date(mock, freshActive, "Activation Date"), "activated now");
    String freshCompromised =
        client.call(Requests.reKey().uniqueIdentifier(compromised).build()).uniqueIdentifier();
    assertEquals(Optional.of(State.PRE_ACTIVE), mock.protocolState(freshCompromised));
    assertEquals(List.of(), mock.violations());
  }

  @ParameterizedTest
  @EnumSource(names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void reKeyMovesNamesAndLinksBothKeys(ProtocolVersion v) throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, v);
    String old = createAes(client, 256, "rotating");
    client.activate(old);
    String fresh = client.call(Requests.reKey().uniqueIdentifier(old).build()).uniqueIdentifier();
    assertEquals(Optional.of(State.ACTIVE), mock.protocolState(fresh));
    assertEquals(Optional.of(old), mock.protocolLink(fresh, LinkType.REPLACED_OBJECT_LINK));
    assertEquals(Optional.of(fresh), mock.protocolLink(old, LinkType.REPLACEMENT_OBJECT_LINK));
    assertEquals(List.of("rotating"), mock.names(fresh));
    assertEquals(List.of(), mock.names(old));
    assertEquals(
        List.of(fresh),
        LocateRequest.result(
                client.call(LocateRequest.builder().name("rotating").build().toRequest()))
            .identifiers());
    List<Ttlv> links =
        GetAttributesResult.of(
                client.call(Requests.getAttributes().uniqueIdentifier(fresh).build()))
            .attributes()
            .stream()
            .filter(a -> isAttribute(a, v == ProtocolVersion.V3_0 ? REPLACED_OBJECT_LINK : LINK))
            .toList();
    assertEquals(1, links.size());
    assertEquals(List.of(), mock.violations());
  }

  @ParameterizedTest
  @EnumSource(names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void registersCertificates(ProtocolVersion v) throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, v);
    X509Certificate cert = certificate();
    String id =
        client
            .call(
                CertificateRegistration.of(cert, UsageMask.of(CryptographicUsageMask.VERIFY))
                    .ecAlgorithm(CryptographicAlgorithm.ECDSA)
                    .name("tls")
                    .build())
            .uniqueIdentifier();
    assertEquals(cert, ObjectViews.certificate(client.get(id).requirePayload(), id));
    assertEquals(List.of(), mock.violations());
  }

  private static X509Certificate certificate() throws Exception {
    return (X509Certificate)
        CertificateFactory.getInstance("X.509")
            .generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(CERTIFICATE)));
  }

  @ParameterizedTest
  @EnumSource(names = {"V1_2", "V1_4", "V2_0", "V3_0"})
  void batchesUseTheIdPlaceholderAndStopAtFailures(ProtocolVersion v) throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, v);
    // KMIP 1.x and 2.x use the placeholder for an omitted identifier; 3.0 requires the field and
    // names the placeholder with its enumeration (3.0 §6.1.1, §11.60).
    Request activate =
        v == ProtocolVersion.V3_0
            ? Requests.activate()
                .add(enumeration(UNIQUE_IDENTIFIER, Enums.UniqueIdentifier.ID_PLACEHOLDER))
                .build()
            : Requests.activate().build();
    Response created =
        client.batch(
            List.of(
                Requests.createSymmetricKey(
                    CryptographicAlgorithm.AES, 128, CryptographicUsageMask.ENCRYPT),
                activate));
    String id = created.results().get(0).uniqueIdentifier();
    assertTrue(created.results().get(1).successful());
    assertEquals(Optional.of(State.ACTIVE), mock.protocolState(id));

    List<Request> failing =
        List.of(
            Requests.get().uniqueIdentifier("missing").build(),
            Requests.get().uniqueIdentifier(id).build());
    assertEquals(1, client.batch(failing).results().size());
    if (v != ProtocolVersion.V3_0) {
      RequestOptions proceed =
          RequestOptions.builder()
              .batchErrorContinuation(Enums.BatchErrorContinuation.CONTINUE)
              .build();
      assertEquals(2, client.batch(failing, proceed).results().size());
      RequestOptions undo =
          RequestOptions.builder()
              .batchErrorContinuation(Enums.BatchErrorContinuation.UNDO)
              .build();
      Response undone =
          client.batch(
              List.of(
                  Requests.createSymmetricKey(
                      CryptographicAlgorithm.AES, 128, CryptographicUsageMask.ENCRYPT),
                  Requests.get().uniqueIdentifier("missing").build()),
              undo);
      assertEquals(3, undone.results().get(0).status());
      assertEquals(1, mock.ids().size());
    }
    assertEquals(List.of(), mock.violations());
  }

  /** A KMIP 3.0 item that omits a required Unique Identifier fails and is recorded as a violation. */
  @Test
  void aKmip30ItemWithoutItsUniqueIdentifierIsAViolation() throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, ProtocolVersion.V3_0);
    Response r =
        client.batch(
            List.of(
                Requests.createSymmetricKey(
                    CryptographicAlgorithm.AES, 128, CryptographicUsageMask.ENCRYPT),
                Requests.activate().build()));
    assertTrue(r.results().get(0).successful());
    assertTrue(r.results().get(1).hasReason(Enums.ResultReason.MISSING_DATA));
    assertEquals(1, mock.violations().size(), mock.violations().toString());
  }

  /** The message re-labeled with another header version, so it reaches the server unchanged. */
  private static Ttlv relabel(Ttlv message, ProtocolVersion to, boolean dropBatchCount) {
    List<Ttlv> header = new ArrayList<>();
    for (Ttlv f : message.require(REQUEST_HEADER).children())
      if (f.tag() == PROTOCOL_VERSION.code()) header.add(Messages.protocolVersion(to));
      else if (!(dropBatchCount && f.tag() == BATCH_COUNT.code())) header.add(f);
    List<Ttlv> fields = new ArrayList<>();
    for (Ttlv f : message.children())
      fields.add(f.tag() == REQUEST_HEADER.code() ? structure(REQUEST_HEADER, header) : f);
    return structure(REQUEST_MESSAGE, fields);
  }

  private static Result send(
      InMemoryKmipServer mock, ProtocolVersion built, Request r, ProtocolVersion to, boolean drop)
      throws IOException {
    Ttlv message = Messages.request(built, List.of(r), RequestOptions.DEFAULT);
    return Messages.response(mock.exchange(relabel(message, to, drop))).results().get(0);
  }

  @Test
  void wrongShapesAreRejectedAndRecorded() throws Exception {
    Request create =
        Requests.createSymmetricKey(
            CryptographicAlgorithm.AES, 128, CryptographicUsageMask.ENCRYPT);
    // The client itself refuses a 2.x Attributes structure at 1.4.
    assertThrows(
        IllegalArgumentException.class,
        () ->
            Messages.request(
                ProtocolVersion.V1_4,
                List.of(
                    Request.operation(Operation.CREATE)
                        .add(ModernAttributes.of(integer(CRYPTOGRAPHIC_LENGTH, 128)))
                        .build()),
                RequestOptions.DEFAULT));

    InMemoryKmipServer mock = new InMemoryKmipServer();
    Result attributesAt14 = send(mock, ProtocolVersion.V2_0, create, ProtocolVersion.V1_4, false);
    assertTrue(attributesAt14.hasReason(ResultReason.INVALID_MESSAGE));
    assertEquals(1, mock.violations().size());
    assertTrue(mock.violations().get(0).contains("Attributes"), mock.violations().toString());

    mock = new InMemoryKmipServer();
    assertTrue(
        send(mock, ProtocolVersion.V1_4, create, ProtocolVersion.V2_1, false)
            .hasReason(ResultReason.INVALID_MESSAGE));
    assertTrue(
        mock.violations().get(0).contains("TemplateAttribute"), mock.violations().toString());

    mock = new InMemoryKmipServer();
    Request locate = LocateRequest.builder().name("k").build().toRequest();
    assertTrue(
        send(mock, ProtocolVersion.V1_4, locate, ProtocolVersion.V2_0, false)
            .hasReason(ResultReason.INVALID_FIELD));
    assertTrue(
        mock.violations().get(0).contains("top-level 1.x Attribute"), mock.violations().toString());

    mock = new InMemoryKmipServer();
    Request get = Requests.get().uniqueIdentifier("mock-1").build();
    Result batchCount = send(mock, ProtocolVersion.V2_1, get, ProtocolVersion.V3_0, false);
    assertTrue(batchCount.hasReason(ResultReason.INVALID_MESSAGE));
    assertTrue(batchCount.operationCode().isEmpty(), "a header violation fails the whole message");
    assertTrue(mock.violations().get(0).contains("BatchCount"), mock.violations().toString());

    mock = new InMemoryKmipServer();
    assertTrue(
        send(mock, ProtocolVersion.V2_1, get, ProtocolVersion.V3_0, true)
            .hasReason(ResultReason.INVALID_FIELD));
    assertTrue(
        mock.violations().get(0).contains("Identifier or Reference"), mock.violations().toString());

    mock = new InMemoryKmipServer();
    byte[] der = certificate().getEncoded();
    Result noLength =
        new KmipClient(mock, ProtocolVersion.V1_4)
            .execute(
                Requests.registerObject(
                    ManagedObjects.certificate(Enums.CertificateType.X_509, der),
                    Attributes.algorithm(CryptographicAlgorithm.ECDSA),
                    Attributes.length(256),
                    Attributes.usage(CryptographicUsageMask.VERIFY)));
    assertTrue(noLength.hasReason(ResultReason.MISSING_DATA));
    assertTrue(
        mock.violations().get(0).contains("Certificate Length"), mock.violations().toString());

    mock = new InMemoryKmipServer();
    Result badName =
        new KmipClient(mock, ProtocolVersion.V1_4)
            .execute(
                Requests.create()
                    .add(enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY))
                    .template(
                        Attributes.attribute(
                            "CryptographicAlgorithm",
                            enumeration(CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.AES)))
                    .build());
    assertTrue(badName.hasReason(ResultReason.INVALID_FIELD));
    assertTrue(
        mock.violations().get(0).contains("Cryptographic Algorithm"), mock.violations().toString());
  }

  @Test
  void negotiationFallsBackToTheServersMajorVersion() throws Exception {
    InMemoryKmipServer legacy =
        new InMemoryKmipServer(ProtocolVersion.V1_2, ProtocolVersion.V1_3, ProtocolVersion.V1_4);
    try (KmipClient client =
        KmipClient.negotiated(legacy, VersionPolicy.atLeast(ProtocolVersion.V1_2))) {
      assertEquals(ProtocolVersion.V1_4, client.version());
      createAes(client, 128, "after-negotiation");
    }
    assertTrue(legacy.closed());
    List<ProtocolVersion> headers =
        legacy.protocolRequests().stream()
            .map(r -> Messages.version(r.require(REQUEST_HEADER)))
            .toList();
    assertEquals(
        List.of(ProtocolVersion.V2_1, ProtocolVersion.V1_4, ProtocolVersion.V1_4), headers);
    assertThrows(
        ProtocolException.class,
        () -> new KmipClient(legacy, ProtocolVersion.V2_0).discoverVersions(),
        "a 2.0 request is answered in 1.4");
    assertEquals(List.of(), legacy.violations());

    InMemoryKmipServer all = new InMemoryKmipServer();
    assertEquals(
        List.of(
            ProtocolVersion.V3_0,
            ProtocolVersion.V2_1,
            ProtocolVersion.V2_0,
            ProtocolVersion.V1_4,
            ProtocolVersion.V1_3,
            ProtocolVersion.V1_2),
        new KmipClient(all, ProtocolVersion.V3_0).discoverVersions());
    assertEquals(List.of(), all.violations());
  }

  @Test
  void faultHooksAndInspection() throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, ProtocolVersion.V2_1);
    mock.injectBeforeProcessing(request -> new IOException("connection reset"));
    assertThrows(
        IOException.class,
        () ->
            client.createSymmetricKey(
                CryptographicAlgorithm.AES, 128, CryptographicUsageMask.ENCRYPT));
    assertEquals(List.of(), mock.ids());
    String id =
        client.createSymmetricKey(CryptographicAlgorithm.AES, 128, CryptographicUsageMask.ENCRYPT);

    mock.injectAfterProcessing(
        request ->
            request.require(BATCH_ITEM).require(OPERATION).intValue() == Operation.ACTIVATE.code()
                ? new IOException("reply lost")
                : null);
    client.createSymmetricKey(CryptographicAlgorithm.AES, 128, CryptographicUsageMask.ENCRYPT);
    assertThrows(IOException.class, () -> client.activate(id));
    assertEquals(
        Optional.of(State.ACTIVE), mock.protocolState(id), "the lost reply's mutation happened");
    client.call(Requests.get().uniqueIdentifier(id).build());
    assertEquals(5, mock.exchanges());
    assertEquals(5, mock.protocolRequests().size());

    CallContext canceled = CallContext.cancellable();
    canceled.cancel();
    assertThrows(IOException.class, () -> mock.exchange(mock.protocolRequests().get(0), canceled));
    assertFalse(mock.closed());
    client.close();
    assertTrue(mock.closed());
    assertEquals(List.of(), mock.violations());
  }

  /** ProtocolVersions(); identifiers and dates a test controls. */
  @Test
  void identifierSourceAndClockControlNewObjects() throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer(ProtocolVersion.V1_4, ProtocolVersion.V2_1);
    assertEquals(List.of(ProtocolVersion.V2_1, ProtocolVersion.V1_4), mock.protocolVersions());
    KmipClient client = new KmipClient(mock, ProtocolVersion.V2_1);
    assertEquals("mock-1", createAes(client, 128, null), "sequential by default");

    Instant noon = Instant.parse("2026-10-27T12:00:00Z");
    java.util.Iterator<String> ids = List.of("zz", "aa", "aa").iterator();
    mock.identifierSource(ids::next).clock(Clock.fixed(noon.plusMillis(250), ZoneOffset.UTC));
    String first = createAes(client, 128, null);
    String second = createAes(client, 128, null);
    assertEquals(List.of("mock-1", "zz", "aa"), mock.ids());
    assertEquals(List.of("zz", "aa"), List.of(first, second));
    client.activate(second);
    for (String id : List.of(first, second))
      assertEquals(noon, mock.protocolAttributes(id).get("Initial Date").get(0).instantValue());
    assertEquals(
        noon, mock.protocolAttributes(second).get("Activation Date").get(0).instantValue());
    Response answer = client.batch(List.of(Requests.get().uniqueIdentifier(first).build()));
    assertEquals(noon, answer.timestamp());
    KmipException reused = assertThrows(KmipException.class, () -> createAes(client, 128, null));
    assertTrue(reused.result().hasReason(ResultReason.GENERAL_FAILURE), reused.toString());
    assertEquals(3, mock.ids().size());
    assertEquals(1, mock.violations().size());
    assertTrue(
        mock.violations().get(0).contains("aa, which is in use"), mock.violations().toString());
  }

  /** The protocol-level failNext overload, and one armed fault per message. */
  @ParameterizedTest
  @EnumSource(names = {"V1_4", "V2_1"})
  void armedFaultsFailOneMatchingItemPerMessage(ProtocolVersion v) throws Exception {
    InMemoryKmipServer mock = new InMemoryKmipServer();
    KmipClient client = new KmipClient(mock, v);
    mock.failNext(ServerOperation.ACTIVATE, ResultReason.WRONG_KEY_LIFECYCLE_STATE);
    mock.failNext(ServerOperation.ANY, Fault.NOT_FOUND);
    Response created =
        client.batch(
            List.of(
                Requests.createSymmetricKey(
                    CryptographicAlgorithm.AES, 128, CryptographicUsageMask.ENCRYPT),
                Requests.activate().build()));
    // The first armed fault matching an item fires, on that item only; the other stays armed.
    assertTrue(created.results().get(0).successful());
    assertTrue(created.results().get(1).hasReason(lifecycle(v)), "mapped like the server's own");
    String id = created.results().get(0).uniqueIdentifier();
    assertEquals(Optional.of(State.PRE_ACTIVE), mock.protocolState(id), "not processed");
    Result missing = client.execute(Requests.get().uniqueIdentifier(id).build());
    assertTrue(
        missing.hasReason(
            v.legacyAttributes() ? ResultReason.ITEM_NOT_FOUND : ResultReason.OBJECT_NOT_FOUND));
    assertTrue(client.execute(Requests.get().uniqueIdentifier(id).build()).successful());

    mock.failNext(ServerOperation.GET, Fault.MALFORMED_REPLY);
    assertThrows(
        ProtocolException.class, () -> client.call(Requests.get().uniqueIdentifier(id).build()));
    assertEquals(List.of(), mock.violations());
  }
}
