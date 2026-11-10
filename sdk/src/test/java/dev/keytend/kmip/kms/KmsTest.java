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

import dev.keytend.kmip.client.KmipClient;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import dev.keytend.kmip.transport.RequestNotSentException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Application-API behavior beyond the samples: errors, retries, failover, secrets, policy, paging. */
class KmsTest {
  final List<InMemoryKmipServer> servers = new ArrayList<>();
  final List<Kms> clients = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  InMemoryKmipServer server(ProtocolVersion... versions) {
    InMemoryKmipServer s = new InMemoryKmipServer(versions);
    servers.add(s);
    return s;
  }

  Kms connect(KmsConfig.Builder builder) {
    Kms kms =
        Kms.connect(
            builder.minimumVersion(KmipVersion.V1_1).maximumVersion(KmipVersion.V3_0).build());
    clients.add(kms);
    return kms;
  }

  Kms connect(InMemoryKmipServer server) {
    return connect(KmsConfig.builder().endpoints("kms:5696").transport(e -> server));
  }

  static long count(InMemoryKmipServer server, Operation op) {
    return server.protocolRequests().stream()
        .flatMap(r -> r.children(Tag.BATCH_ITEM).stream())
        .filter(b -> b.require(Tag.OPERATION).intValue() == op.code())
        .count();
  }

  /** A transport that refuses connections while {@code down[0]} is set. */
  static KmipTransport switchable(KmipTransport delegate, boolean[] down) {
    return new KmipTransport() {
      @Override
      public Ttlv exchange(Ttlv request) throws IOException {
        if (down[0]) throw new RequestNotSentException("not sent", new ConnectException("refused"));
        return delegate.exchange(request);
      }
    };
  }

  KeyHandle aes(Kms kms, String name) {
    return kms.keys()
        .createAes(256)
        .named(name)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .create();
  }

  @Test
  void readsFailOverAndMutationsAreNeverResent() {
    InMemoryKmipServer server = server(ProtocolVersion.V2_1);
    boolean[] firstDown = {false};
    List<String> unavailable = new CopyOnWriteArrayList<>(), retries = new CopyOnWriteArrayList<>();
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("kms1:5696", "kms2:5696")
                .transport(e -> e.host().equals("kms1") ? switchable(server, firstDown) : server)
                .retryPolicy(RetryPolicy.defaults().toBuilder().maxAttempts(3).build())
                .addListener(
                    new KmsListener() {
                      @Override
                      public void retrying(KmsEvent failed, Duration delay) {
                        retries.add(failed.endpoint());
                      }

                      @Override
                      public void endpointUnavailable(String endpoint, String why) {
                        unavailable.add(endpoint);
                      }
                    }));
    KeyHandle key = aes(kms, "failover");
    firstDown[0] = true;
    assertEquals(KeyState.ACTIVE, key.attributes().state(), "the read failed over to kms2");
    assertEquals(List.of("kms1:5696"), retries);
    assertTrue(unavailable.contains("kms1:5696"));
    // kms1 is cooling down, so the next mutation goes to kms2 directly.
    long revokes = count(server, Operation.REVOKE);
    key.revoke(RevocationReason.superseded("done"));
    assertEquals(revokes + 1, count(server, Operation.REVOKE));
  }

  @Test
  void aMutationThatWasNotSentIsTransientAndNotRetried() {
    InMemoryKmipServer server = server(ProtocolVersion.V2_1);
    Kms kms = connect(server);
    server.injectBeforeProcessing(
        r -> new RequestNotSentException("not sent", new ConnectException("refused")));
    TransientException e =
        assertThrows(
            TransientException.class,
            () -> kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).createPreActive());
    assertTrue(e.retryable());
    assertEquals(List.of(), server.ids(), "nothing was created");
  }

  @Test
  void aLostReplyToAMutationIsOutcomeUnknown() {
    InMemoryKmipServer server = server(ProtocolVersion.V1_4);
    Kms kms = connect(server);
    server.injectAfterProcessing(r -> new SocketTimeoutException("read timed out"));
    OutcomeUnknownException e =
        assertThrows(
            OutcomeUnknownException.class,
            () ->
                kms.keys()
                    .createAes(256)
                    .named("ghost")
                    .usages(KeyUsage.ENCRYPT)
                    .createPreActive());
    assertFalse(e.retryable());
    assertEquals(1, server.ids().size(), "processed exactly once");
    assertEquals(1, kms.keys().locate(KeyQuery.byName("ghost")).count(), "it did take effect");
  }

  @Test
  void transientReadFailuresAreRetried() {
    InMemoryKmipServer server = server(ProtocolVersion.V2_0);
    Kms kms = connect(server);
    KeyHandle key = aes(kms, "retry");
    server.injectBeforeProcessing(r -> new IOException("connection reset"));
    assertEquals("retry", key.attributes().names().get(0));
  }

  @Test
  void invalidResponsesAreRejectedAndCarryNoKeyMaterial() {
    InMemoryKmipServer server = server(ProtocolVersion.V2_1);
    boolean[] lie = {false};
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("kms:5696")
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request -> {
                          Ttlv response = server.exchange(request);
                          return lie[0] ? replaceIdentifier(response, "other-key") : response;
                        }));
    KeyHandle key = aes(kms, "lie");
    lie[0] = true;
    ProtocolViolationException e =
        assertThrows(
            ProtocolViolationException.class,
            () -> key.asSecretKey(Expect.aes(256), LocalUse.DECRYPT));
    Ttlv redacted = e.response().orElseThrow();
    assertTrue(allBytesEmpty(redacted), "no key material in diagnostics");
    lie[0] = false;
    KeyMismatchException mismatch =
        assertThrows(
            KeyMismatchException.class, () -> key.asSecretKey(Expect.aes(128), LocalUse.DECRYPT));
    assertTrue(mismatch.result().isEmpty() && mismatch.response().isEmpty());
  }

  /** The response with every Unique Identifier in its payloads replaced. */
  static Ttlv replaceIdentifier(Ttlv node, String id) {
    if (node.tag() == Tag.UNIQUE_IDENTIFIER.code()) return Ttlv.text(Tag.UNIQUE_IDENTIFIER, id);
    if (node.type() != Ttlv.Type.STRUCTURE) return node;
    return Ttlv.structure(
        node.tag(), node.children().stream().map(c -> replaceIdentifier(c, id)).toList());
  }

  static boolean allBytesEmpty(Ttlv node) {
    if (node.type() == Ttlv.Type.BYTE_STRING) return node.byteLength() == 0;
    if (node.type() != Ttlv.Type.STRUCTURE) return true;
    return node.children().stream().allMatch(KmsTest::allBytesEmpty);
  }

  @Test
  void serverFailuresMapToTypedExceptions() {
    Failures.Call call = new Failures.Call("op", true, "k", false);
    Map<Enums.ResultReason, Class<?>> expected =
        Map.of(
            Enums.ResultReason.ITEM_NOT_FOUND, NotFoundException.class,
            Enums.ResultReason.PERMISSION_DENIED, PermissionDeniedException.class,
            Enums.ResultReason.INVALID_FIELD, InvalidRequestException.class,
            Enums.ResultReason.OPERATION_NOT_SUPPORTED, UnsupportedException.class,
            Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE, StateConflictException.class,
            Enums.ResultReason.CRYPTOGRAPHIC_FAILURE, CryptographicFailureException.class,
            Enums.ResultReason.GENERAL_FAILURE, ServerFailureException.class);
    for (var e : expected.entrySet()) {
      var result =
          new dev.keytend.kmip.client.Result(
              Operation.GET,
              1,
              e.getKey().code(),
              "msg",
              Ttlv.structure(Tag.BATCH_ITEM, List.of()));
      KmsException k = Failures.fromResult(call, "op k", result, null);
      assertInstanceOf(e.getValue(), k, e.getKey().toString());
      assertEquals(Optional.of(e.getKey()), k.protocolReason());
      assertEquals(Optional.of("msg"), k.serverMessage());
      assertEquals(Optional.of("k"), k.objectId());
    }
    var vendor =
        new dev.keytend.kmip.client.Result(
            Operation.GET, 1, 0x80000001, null, Ttlv.structure(Tag.BATCH_ITEM, List.of()));
    KmsException k = Failures.fromResult(call, "op", vendor, null);
    assertInstanceOf(ServerFailureException.class, k);
    assertEquals(Optional.of(0x80000001), k.reasonCode());
  }

  @Test
  void connectEnforcesTheVersionPolicy() {
    InMemoryKmipServer old = server(ProtocolVersion.V1_2);
    assertThrows(
        UnsupportedException.class,
        () ->
            Kms.connect(
                KmsConfig.builder()
                    .endpoints("kms:5696")
                    .transport(e -> old)
                    .minimumVersion(KmipVersion.V1_4)
                    .build()));
    assertEquals(0, count(old, Operation.CREATE));
    // The default minimum is 1.4, so AES-GCM works with every server the default accepts.
    UnsupportedException tooOld =
        assertThrows(
            UnsupportedException.class,
            () ->
                Kms.connect(KmsConfig.builder().endpoints("kms:5696").transport(e -> old).build()));
    assertTrue(tooOld.getMessage().contains("1.4"), tooOld.getMessage());
    assertEquals(
        ProtocolVersion.V2_0,
        KmsConfig.builder()
            .endpoints("kms")
            .tls(defaultContext())
            .hashedPassword("u", "p".toCharArray())
            .build()
            .minimumVersion()
            .protocolValue(),
        "hashed passwords need KMIP 2.0");
  }

  static javax.net.ssl.SSLContext defaultContext() {
    try {
      return javax.net.ssl.SSLContext.getDefault();
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  @Test
  void endpointsMustOfferTheNegotiatedVersion() {
    InMemoryKmipServer modern = server(ProtocolVersion.V2_1), legacy = server(ProtocolVersion.V1_4);
    boolean[] down = {false};
    List<String> why = new CopyOnWriteArrayList<>();
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("a:5696", "b:5696")
                .retryPolicy(RetryPolicy.defaults().toBuilder().maxAttempts(2).build())
                .addListener(
                    new KmsListener() {
                      @Override
                      public void endpointUnavailable(String endpoint, String reason) {
                        why.add(endpoint + " " + reason);
                      }
                    })
                .transport(e -> e.host().equals("a") ? switchable(modern, down) : legacy));
    assertEquals(KmipVersion.V2_1, kms.version());
    down[0] = true;
    assertThrows(TransientException.class, () -> kms.keys().handle("x").attributes());
    assertTrue(
        why.stream().anyMatch(w -> w.startsWith("b:5696") && w.contains("2.1")), why.toString());
  }

  @Test
  void aClosedKmsRefusesWorkAndProtocolViewsDoNotOwnTheConnection() throws Exception {
    InMemoryKmipServer server = server(ProtocolVersion.V2_1);
    Kms kms = connect(server);
    KmipClient view = kms.protocol();
    view.close();
    assertNotNull(view.call(Requests.query().build()), "closing the view left the connection open");
    kms.close();
    assertThrows(IllegalStateException.class, kms::keys);
    assertTrue(server.closed());
  }

  @Test
  void listenerFailuresDoNotChangeOutcomes() {
    InMemoryKmipServer server = server(ProtocolVersion.V2_1);
    List<KmsEvent> events = new CopyOnWriteArrayList<>();
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("kms:5696")
                .transport(e -> server)
                .addListener(
                    new KmsListener() {
                      @Override
                      public void finished(KmsEvent event) {
                        events.add(event);
                        throw new RuntimeException("listener bug");
                      }
                    }));
    KeyHandle key = aes(kms, "listened");
    assertNotNull(key.id(), "the created key's id is not lost");
    KmsEvent create =
        events.stream().filter(e -> e.operation().equals("create")).findFirst().orElseThrow();
    assertEquals(KmsEvent.Outcome.SUCCEEDED, create.outcome());
    assertEquals(KmipVersion.V2_1, create.version());
    assertFalse(create.toString().contains("bytes"), "events carry no data");
  }

  @Test
  void retrievedSecretKeysAreDestroyable() throws Exception {
    Kms kms = connect(server(ProtocolVersion.V2_1));
    DestroyableSecretKey key = aes(kms, "wipe").asSecretKey(Expect.aes(256), LocalUse.DECRYPT);
    key.destroy();
    assertTrue(key.isDestroyed());
    assertThrows(IllegalStateException.class, key::getEncoded);
    var out = new java.io.ByteArrayOutputStream();
    assertThrows(
        java.io.NotSerializableException.class,
        () -> new java.io.ObjectOutputStream(out).writeObject(key));
  }

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void customAttributesReadTheSameOnEveryVersion(ProtocolVersion version) {
    Kms kms = connect(server(version));
    CustomAttribute tenant = CustomAttribute.client("Tenant");
    KeyHandle key =
        kms.keys().createAes(128).usages(KeyUsage.ENCRYPT).custom(tenant, "acme").createPreActive();
    assertEquals("acme", key.attributes().custom().get(tenant));
    key.setCustomAttribute(tenant, "globex");
    assertEquals("globex", key.attributes().custom().get(tenant));
    CustomAttribute vendor = new CustomAttribute("acme", "Region");
    if (version.legacyAttributes())
      assertThrows(UnsupportedException.class, () -> key.setCustomAttribute(vendor, "eu"));
    else {
      key.setCustomAttribute(vendor, "eu");
      assertEquals("eu", key.attributes().custom().get(vendor));
    }
  }

  @Test
  void locatePagesFrom13AndRefusesToTruncateBefore() {
    InMemoryKmipServer v14 = server(ProtocolVersion.V1_4);
    Kms paged = connect(KmsConfig.builder().endpoints("kms").transport(e -> v14).locatePageSize(2));
    for (int i = 0; i < 5; i++) aes(paged, "page");
    assertEquals(5, paged.keys().locate(KeyQuery.byName("page")).count());
    InMemoryKmipServer old = server(ProtocolVersion.V1_2);
    Kms unpaged = connect(KmsConfig.builder().endpoints("kms").transport(e -> old).locateLimit(3));
    for (int i = 0; i < 5; i++) aes(unpaged, "page");
    assertThrows(
        UnsupportedException.class, () -> unpaged.keys().locate(KeyQuery.byName("page")).count());
    assertEquals(
        0, unpaged.keys().locate(KeyQuery.byName("page").state(KeyState.PRE_ACTIVE)).count());
  }

  @Test
  void ambiguousNamesResolveToOneKeyAndGroupsAreVersionAware() {
    Kms kms = connect(server(ProtocolVersion.V2_1));
    KeyHandle first =
        kms.keys().createAes(256).named("twin").usages(KeyUsage.ENCRYPT).createPreActive();
    kms.keys().createAes(256).named("twin").usages(KeyUsage.ENCRYPT).createPreActive();
    // findByName looks for Active keys unless told otherwise.
    assertEquals(Optional.empty(), kms.keys().findByName("twin"));
    // Several keys with the name resolve to the earliest instead of failing.
    assertEquals(Optional.of(first), kms.keys().findByName("twin", KeyState.PRE_ACTIVE));
    kms.keys()
        .createAes(256)
        .named("grouped")
        .group("payments")
        .usages(KeyUsage.ENCRYPT)
        .createPreActive();
    assertEquals(1, kms.keys().locate(KeyQuery.all().group("payments")).count());
    Kms draft = connect(server(ProtocolVersion.V3_0));
    assertThrows(
        UnsupportedException.class, () -> draft.keys().locate(KeyQuery.all().group("payments")));
  }

  @ParameterizedTest
  @EnumSource(
      value = ProtocolVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void otherCryptoRoundTrips(ProtocolVersion version) {
    Kms kms = connect(server(version));
    byte[] data = "sixteen byte msg plus".getBytes(StandardCharsets.UTF_8);
    KeyHandle aes = aes(kms, "modes");
    for (CipherSpec spec : List.of(CipherSpec.cbc(), CipherSpec.ctr())) {
      Ciphertext c = aes.encrypt(spec, data);
      assertArrayEquals(data, aes.decrypt(spec, c, null), spec.toString());
      // A stored ciphertext cannot choose a malleable mode for itself.
      var refused = assertThrows(CryptographicFailureException.class, () -> aes.decrypt(c, null));
      assertEquals(CryptographicFailureException.Kind.INVALID_CIPHERTEXT, refused.kind());
    }
    KeyPairHandle rsa =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.DECRYPT, KeyUsage.SIGN)
            .publicUsages(KeyUsage.ENCRYPT, KeyUsage.VERIFY)
            .create();
    // RSA-OAEP round-trips through the pair and through the private key alone.
    CipherSpec oaep =
        version.atLeast(ProtocolVersion.V1_4)
            ? CipherSpec.rsaOaep(Hash.SHA_256)
            : CipherSpec.rsaOaep(Hash.SHA_256, Hash.SHA_1);
    Ciphertext sealed = rsa.encrypt(oaep, data, null);
    assertEquals(rsa.publicKey().id(), sealed.keyId());
    assertArrayEquals(data, rsa.decrypt(oaep, sealed, null));
    assertArrayEquals(data, rsa.privateKey().decrypt(oaep, sealed, null));
    // A stored RSA-OAEP ciphertext never chooses its spec.
    assertThrows(CryptographicFailureException.class, () -> rsa.privateKey().decrypt(sealed, null));
    if (!version.atLeast(ProtocolVersion.V1_4))
      assertThrows(
          UnsupportedException.class,
          () -> rsa.encrypt(CipherSpec.rsaOaep(Hash.SHA_256), data, null));
    if (version.atLeast(ProtocolVersion.V1_4)) {
      byte[] sig = rsa.privateKey().sign(SignatureSpec.rsaPss(Hash.SHA_256), data);
      assertEquals(
          VerifyResult.VALID,
          rsa.publicKey().verify(SignatureSpec.rsaPss(Hash.SHA_256), data, sig));
    } else
      assertThrows(
          UnsupportedException.class,
          () -> rsa.privateKey().sign(SignatureSpec.rsaPss(Hash.SHA_256), data));
    KeyHandle hmac =
        kms.keys()
            .createSymmetric(Algorithm.HMAC_SHA256, 256)
            .usages(KeyUsage.MAC_GENERATE, KeyUsage.MAC_VERIFY)
            .create();
    byte[] mac = hmac.mac(MacSpec.keyDefault(), data);
    assertEquals(VerifyResult.VALID, hmac.macVerify(MacSpec.keyDefault(), data, mac));
    mac[0] ^= 1;
    assertEquals(VerifyResult.INVALID, hmac.macVerify(MacSpec.keyDefault(), data, mac));
    assertEquals(16, kms.random(16).length);
  }

  /** A server whose default public-key format cannot be converted is asked for X.509 once. */
  @Test
  void publicKeysFallBackToX509WhenTheDefaultFormatCannotBeConverted() {
    InMemoryKmipServer server = server(ProtocolVersion.V2_1);
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("kms")
                .transport(
                    e ->
                        request -> {
                          Ttlv response = server.exchange(request);
                          Ttlv payload =
                              request.require(Tag.BATCH_ITEM).require(Tag.REQUEST_PAYLOAD);
                          boolean defaultGet =
                              Faults.operation(request) == Operation.GET.code()
                                  && payload.child(Tag.KEY_FORMAT_TYPE).isEmpty();
                          return defaultGet ? opaqueRaw(response) : response;
                        }));
    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .create();
    assertEquals(
        2048,
        ((java.security.interfaces.RSAPublicKey) pair.publicKey().asPublicKey(Expect.rsa(2048)))
            .getModulus()
            .bitLength());
  }

  /** Replaces public key material with a vendor-specific Raw byte layout. */
  static Ttlv opaqueRaw(Ttlv node) {
    if (node.tag() == Tag.KEY_FORMAT_TYPE.code())
      return Ttlv.enumeration(Tag.KEY_FORMAT_TYPE, Enums.KeyFormatType.RAW);
    if (node.tag() == Tag.KEY_MATERIAL.code())
      return Ttlv.bytes(Tag.KEY_MATERIAL, new byte[] {0, 1, 2, 3});
    if (node.type() != Ttlv.Type.STRUCTURE) return node;
    return Ttlv.structure(node.tag(), node.children().stream().map(KmsTest::opaqueRaw).toList());
  }

  @Test
  void aPerCallTimeoutBoundsEachCall() {
    InMemoryKmipServer server = server(ProtocolVersion.V2_1);
    AtomicInteger calls = new AtomicInteger();
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("kms")
                .callTimeout(Duration.ofMillis(200))
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        new KmipTransport() {
                          @Override
                          public Ttlv exchange(Ttlv request) throws IOException {
                            return server.exchange(request);
                          }

                          @Override
                          public Ttlv exchange(Ttlv request, CallContext context)
                              throws IOException {
                            // Connect's requests have the deadline too, so only calls
                            // after connect fail.
                            if (calls.get() > 0 && context.hasDeadline())
                              throw new SocketTimeoutException("deadline");
                            return server.exchange(request);
                          }
                        }));
    calls.incrementAndGet();
    assertThrows(TransientException.class, () -> kms.keys().handle("x").attributes());
  }
}
