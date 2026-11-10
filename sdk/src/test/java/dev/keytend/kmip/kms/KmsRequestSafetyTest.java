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

import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.KmipTransport;
import dev.keytend.kmip.transport.RequestNotSentException;
import java.io.IOException;
import java.net.ConnectException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Request safety: retried registrations, legacy name removals, decoy keys, relabeled
 * ciphertexts, concurrent activation, shared deadlines, refused credentials and unopened transports.
 */
class KmsRequestSafetyTest {
  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  Kms connect(InMemoryKmipServer server, KmsConfig.Builder builder) {
    servers.add(server);
    Kms kms = Kms.connect(builder.build());
    clients.add(kms);
    return kms;
  }

  Kms connect(InMemoryKmipServer server, KmipTransport transport) {
    return connect(server, server.configure().transport(e -> transport));
  }

  static long sent(InMemoryKmipServer server, Operation op) {
    return server.protocolRequests().stream()
        .flatMap(r -> r.children(Tag.BATCH_ITEM).stream())
        .filter(b -> b.require(Tag.OPERATION).intValue() == op.code())
        .count();
  }

  static boolean mentions(Ttlv t, String text) {
    if (t.type() == Ttlv.Type.STRUCTURE)
      return t.children().stream().anyMatch(c -> mentions(c, text));
    return t.type() == Ttlv.Type.TEXT_STRING && t.textValue().equals(text);
  }

  /** 1: a Secret Data registration retried after a not-sent failure stores the secret, not zeros. */
  @Test
  void aRetriedSecretRegistrationSendsTheSecretAgain() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    boolean[] refuse = {true};
    Kms kms =
        connect(
            server,
            request -> {
              if (refuse[0] && Faults.operation(request) == Operation.REGISTER.code()) {
                refuse[0] = false;
                throw new RequestNotSentException("not sent", new ConnectException("refused"));
              }
              return server.exchange(request);
            });
    KeyRegistration registration = kms.keys().registerSecret("hunter2".toCharArray()).named("pw");
    var e = assertThrows(TransientException.class, registration::register);
    assertTrue(e.retryable());
    KeyHandle stored = registration.registerPreActive();
    try (SecretData secret = stored.asSecretData()) {
      assertArrayEquals("hunter2".toCharArray(), secret.chars());
    }
  }

  /** 2: on 1.x removals use the Attribute Index the server reports, which is stable. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4"})
  void legacyRemovalsUseTheServersAttributeIndex(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server, server.configure());
    KeyHandle key =
        kms.keys()
            .createAes(128)
            .named("A")
            .named("B")
            .named("C")
            .usages(KeyUsage.ENCRYPT)
            .createPreActive();
    key.removeName("A");
    key.removeName("C");
    assertEquals(List.of("B"), key.attributes().names(), "C, not B, was removed");
    key.removeName("B");
    assertEquals(List.of(), key.attributes().names());
    CustomAttribute stage = CustomAttribute.client("Stage");
    key.setCustomAttribute(stage, "one");
    key.removeCustomAttribute(stage);
    key.setCustomAttribute(stage, "two");
    key.setCustomAttribute(stage, "three");
    long instances =
        key.attributes().protocolAttributes().stream().filter(a -> mentions(a, "Stage")).count();
    assertEquals(1, instances, "set never adds a second instance");
    assertEquals("three", key.attributes().custom().get(stage));
  }

  /** 4: the private key chosen through a public key's link must link back to it. */
  @Test
  void aDecoyPublicKeyCannotRouteDecryptionToAnotherPrivateKey() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server, server.configure());
    KeyPairHandle victim =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.DECRYPT)
            .publicUsages(KeyUsage.ENCRYPT)
            .group("victims")
            .create();
    Ciphertext secret =
        victim.encrypt(
            CipherSpec.rsaOaep(Hash.SHA_256),
            "victim secret".getBytes(StandardCharsets.UTF_8),
            null);
    var generator = java.security.KeyPairGenerator.getInstance("RSA");
    generator.initialize(2048);
    KeyHandle decoy =
        kms.keys()
            .register(generator.generateKeyPair().getPublic())
            .group("orders")
            .usages(KeyUsage.ENCRYPT)
            .register();
    kms.protocol()
        .call(
            Requests.addAttribute()
                .uniqueIdentifier(decoy.id())
                .attribute(
                    Attributes.link(Enums.LinkType.PRIVATE_KEY_LINK, victim.privateKey().id()))
                .build());
    Ciphertext relabeled = new Ciphertext(decoy.id(), secret.specName(), secret.data(), null, null);
    long decrypts = sent(server, Operation.DECRYPT);
    // A stored RSA-OAEP ciphertext never chooses its key or spec at all.
    CryptographicFailureException refused =
        assertThrows(
            CryptographicFailureException.class,
            () -> kms.keys().decrypt(KeyQuery.all().group("orders"), relabeled, null));
    assertEquals(CryptographicFailureException.Kind.INVALID_CIPHERTEXT, refused.kind());
    assertEquals(decrypts, sent(server, Operation.DECRYPT), "nothing was decrypted");
    // 13: a private key never asks the server about the id a ciphertext names.
    Ciphertext bogus = new Ciphertext("nope", secret.specName(), secret.data(), null, null);
    assertThrows(
        KeyMismatchException.class,
        () -> victim.privateKey().decrypt(CipherSpec.rsaOaep(Hash.SHA_256), bogus, null));
    assertTrue(server.protocolRequests().stream().noneMatch(r -> mentions(r, "nope")));
  }

  /** 5: additional data with a relabeled non-AEAD spec is an invalid ciphertext. */
  @Test
  void additionalDataOnARelabelledCiphertextIsAnInvalidCiphertext() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server, server.configure());
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    byte[] aad = {1};
    Ciphertext c = key.encrypt(CipherSpec.aesGcm(), new byte[] {9}, aad);
    Ciphertext asKeyWrap = new Ciphertext(c.keyId(), "AES-KW", c.data(), null, null);
    var e = assertThrows(CryptographicFailureException.class, () -> key.decrypt(asKeyWrap, aad));
    assertEquals(CryptographicFailureException.Kind.INVALID_CIPHERTEXT, e.kind());
    assertThrows(
        IllegalArgumentException.class,
        () -> key.decrypt(CipherSpec.keyWrap(), asKeyWrap, aad),
        "an explicit spec with additional data is still a caller error");
  }

  /** 6: another caller activating the Pre-Active key meanwhile is not a failure. */
  @Test
  void findOrCreateToleratesAConcurrentActivation() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    boolean[] race = {false};
    Kms kms =
        connect(
            server,
            request -> {
              if (race[0] && Faults.operation(request) == Operation.ACTIVATE.code()) {
                race[0] = false;
                server.exchange(request); // the other caller wins
              }
              return server.exchange(request);
            });
    KeyHandle leftover =
        kms.keys().createAes(256).named("raced").usages(KeyUsage.ENCRYPT).createPreActive();
    race[0] = true;
    assertEquals(
        leftover, kms.keys().createAes(256).named("raced").usages(KeyUsage.ENCRYPT).findOrCreate());
  }

  /** 8: views may outlast the configured call timeout, and composite calls share one deadline. */
  @Test
  void compositeCallsShareOneDeadlineAndViewsAreBounded() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    boolean[] slow = {false};
    Kms kms =
        connect(
            server,
            server
                .configure()
                .callTimeout(Duration.ofMillis(250))
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        new KmipTransport() {
                          @Override
                          public Ttlv exchange(Ttlv request) throws IOException {
                            return server.exchange(request);
                          }

                          @Override
                          public Ttlv exchange(
                              Ttlv request, dev.keytend.kmip.transport.CallContext context)
                              throws IOException {
                            // Like the real transports: the call's deadline bounds the exchange.
                            if (slow[0]) sleep(150);
                            context.check();
                            return server.exchange(request);
                          }
                        }));
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
    slow[0] = true;
    key.attributes(); // one request fits
    assertThrows(
        TransientException.class,
        () -> key.asSecretKey(Expect.aes(256), LocalUse.ENCRYPT),
        "two requests do not");
    assertEquals(
        32,
        kms.withTimeout(Duration.ofSeconds(2))
            .keys()
            .handle(key.id())
            .asSecretKey(Expect.aes(256), LocalUse.ENCRYPT)
            .getEncoded()
            .length,
        "a longer view");
    assertThrows(IllegalArgumentException.class, () -> kms.withTimeout(Duration.ofHours(1)));
  }

  static void sleep(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }

  /** 9: a replica that refuses the credentials does not keep the traffic. */
  @Test
  void aReplicaThatRefusesCredentialsDoesNotPinTraffic() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    boolean[] aDown = {false};
    AtomicInteger bProbes = new AtomicInteger();
    Kms kms =
        connect(
            server,
            server
                .configure()
                .endpoints("a", "b")
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        e.host().equals("a")
                            ? KmsTest.switchable(server, aDown)
                            : request -> {
                              bProbes.incrementAndGet();
                              return Faults.failure(
                                  request, Enums.ResultReason.PERMISSION_DENIED, "no");
                            }));
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
    aDown[0] = true;
    assertThrows(TransientException.class, key::attributes);
    assertThrows(PermissionDeniedException.class, key::attributes);
    aDown[0] = false;
    assertEquals(KeyState.ACTIVE, key.attributes().state(), "back on a");
    int probes = bProbes.get();
    key.attributes();
    assertEquals(probes, bProbes.get(), "b is not probed again while it cools down");
  }

  /** 10: a transport that cannot even be opened sent nothing. */
  @Test
  void aTransportThatCannotBeOpenedSentNothing() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    boolean[] aDown = {false};
    Kms kms =
        connect(
            server,
            server
                .configure()
                .endpoints("a", "b")
                .transport(
                    e -> {
                      if (e.host().equals("b")) throw new IOException("no route to b");
                      return KmsTest.switchable(server, aDown);
                    }));
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
    aDown[0] = true;
    assertThrows(TransientException.class, () -> key.addName("first")); // a refuses: cools down
    assertThrows(TransientException.class, () -> key.addName("second")); // b cannot be opened
  }

  /** 11: KMIP 3.0 batches Get Attributes too. */
  @Test
  void locateWithAttributesBatchesOn30() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V3_0);
    Kms kms = connect(server, server.configure());
    for (int i = 0; i < 3; i++)
      kms.keys().createAes(128).named("draft").usages(KeyUsage.ENCRYPT).createPreActive();
    assertEquals(3, kms.keys().locateWithAttributes(KeyQuery.byName("draft")).count());
    assertTrue(
        server.protocolRequests().stream().anyMatch(r -> r.children(Tag.BATCH_ITEM).size() == 3),
        "one batch");
  }

  /** 12: TLS options do not silently replace each other, and endpoints(...) replaces the list. */
  @Test
  void tlsOptionsAreExplicitAndEndpointsReplace() throws Exception {
    var ctx = javax.net.ssl.SSLContext.getDefault();
    var store = dev.keytend.kmip.TestTls.identity("client");
    char[] password = "changeit".toCharArray();
    assertThrows(
        IllegalArgumentException.class,
        () ->
            KmsConfig.builder()
                .endpoints("kms")
                .tls(ctx)
                .clientIdentity(store, password)
                .trustSystemDefaults()
                .build());
    var noTrust =
        assertThrows(
            IllegalArgumentException.class,
            () -> KmsConfig.builder().endpoints("kms").clientIdentity(store, password).build());
    assertTrue(noTrust.getMessage().contains("trust"), noTrust.getMessage());
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("old:1")
            .clientIdentity(store, password)
            .trustSystemDefaults()
            .build();
    assertEquals(
        List.of(new KmsConfig.Endpoint("new", 2)),
        config.toBuilder().endpoints("new:2").build().endpoints());
  }
}
