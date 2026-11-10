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

import static dev.keytend.kmip.kms.TlsIdentityTest.HOURLY;
import static dev.keytend.kmip.kms.TlsIdentityTest.SCHEDULER;
import static dev.keytend.kmip.kms.TlsIdentityTest.assertWhole;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TlsIdentityTest.Pki;
import dev.keytend.kmip.model.Enums.ResultReason;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.KmipTransport;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * KMIP 1.x has no reason for a name in use, and servers differ: Invalid Field (the 1.4 error
 * tables) or Illegal Operation (an earlier keytend-kmip-server build, to Add Attribute). Every path that
 * adds a Name confirms either with a Locate and then treats it as a name in use, so name moves
 * complete; a refusal that a Locate does not confirm, or one for another reason, stands.
 */
class LegacyNameRefusalTest {
  static final String NAME = "cassandra/node1";

  /** Every 1.x version with both 1.x answers, and 2.1 and 3.0 with Non Unique Name. */
  static Stream<Arguments> servers() {
    List<Arguments> out = new ArrayList<>();
    for (KmipVersion v : List.of(KmipVersion.V1_2, KmipVersion.V1_4))
      for (ResultReason r : List.of(ResultReason.INVALID_FIELD, ResultReason.ILLEGAL_OPERATION))
        out.add(Arguments.of(v, r));
    out.add(Arguments.of(KmipVersion.V2_1, null));
    out.add(Arguments.of(KmipVersion.V3_0, null));
    return out.stream();
  }

  /** The 1.x lanes only. */
  static Stream<Arguments> legacy() {
    return servers().filter(a -> a.get()[1] != null);
  }

  static InMemoryKmipServer server(KmipVersion version, ResultReason reason) {
    return InMemoryKmipServer.of(version).uniqueNames(true).legacyNonUniqueNameReason(reason);
  }

  static Kms connect(InMemoryKmipServer server) {
    return Kms.connect(
        server
            .configure()
            .maximumVersion(KmipVersion.V3_0)
            .callTimeout(Duration.ofSeconds(10))
            .build());
  }

  @ParameterizedTest
  @MethodSource("servers")
  void aNameInUseIsAlreadyExistsOnEveryPathThatAddsOne(KmipVersion version, ResultReason reason) {
    InMemoryKmipServer server = server(version, reason);
    try (Kms kms = connect(server)) {
      KeyHandle held =
          kms.keys()
              .createAes(256)
              .named("taken")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
      KeyHandle other =
          kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
      AlreadyExistsException add =
          assertThrows(AlreadyExistsException.class, () -> other.addName("taken"));
      // 1.x: confirmed by a Locate, which names the holder.
      if (reason != null) assertTrue(add.getMessage().contains(held.id()), add.getMessage());
      if (reason != null)
        assertEquals(
            reason.name(),
            add.getCause() instanceof KmsException k ? k.serverReason().orElseThrow().name() : "",
            add.getMessage());
      assertThrows(
          AlreadyExistsException.class,
          () ->
              kms.keys()
                  .createAes(256)
                  .named("taken")
                  .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                  .create());
      assertThrows(
          AlreadyExistsException.class,
          () -> kms.keys().registerSecret("pw".toCharArray()).named("taken").register());
      assertEquals(List.of(), server.names(other.id()));
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void aSecretIsReplacedUnderItsName(KmipVersion version, ResultReason reason) {
    try (Kms kms = connect(server(version, reason))) {
      KeyHandle old =
          kms.keys().registerSecret("old".toCharArray()).named("db-password").register();
      KeyHandle next =
          kms.keys().registerSecret("new".toCharArray()).named("db-password").replace(old);
      assertEquals(Optional.of(next), kms.keys().findByName("db-password"));
      assertEquals(KeyState.ACTIVE, next.attributes().state());
      assertEquals(List.of(), old.attributes().names());
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void aTlsIdentityIsRenewedAndReKeyedUnderItsName(KmipVersion version, ResultReason reason)
      throws Exception {
    InMemoryKmipServer server = server(version, reason);
    Pki pki = new Pki();
    KeyPair k1 = TestPki.ec(), k2 = TestPki.ec();
    try (Kms kms = connect(server)) {
      TlsIdentityHandle h =
          kms.tls().register(k1.getPrivate(), pki.chain(pki.leaf("n", k1))).named(NAME).register();
      assertThrows(
          AlreadyExistsException.class,
          () ->
              kms.tls()
                  .register(k2.getPrivate(), pki.chain(pki.leaf("n", k2)))
                  .named(NAME)
                  .register());
      try (TlsIdentityFollower f = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
        TlsIdentityHandle renewed = h.renew(pki.chain(pki.leaf("n", k1)));
        assertEquals(List.of(NAME), server.names(renewed.certificate().id()));
        assertEquals(List.of(), server.names(h.certificate().id()));
        assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
        assertEquals(renewed.certificate().id(), assertWhole(f).certificateId());
        TlsIdentityHandle rekeyed = renewed.rekey(k2.getPrivate(), pki.chain(pki.leaf("n", k2)));
        assertEquals(List.of(NAME), server.names(rekeyed.certificate().id()));
        assertEquals(List.of(), server.names(renewed.certificate().id()));
        assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
        assertEquals(rekeyed.privateKey().id(), assertWhole(f).privateKeyId());
      }
      // A repeat finds the completed renewal rather than failing the same way.
      assertEquals(Optional.of(NAME), kms.tls().identity(NAME).map(TlsIdentityHandle::name));
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void aCompromisedKeyIsReplacedUnderItsName(KmipVersion version, ResultReason reason) {
    try (Kms kms = connect(server(version, reason))) {
      KeyHandle old =
          kms.keys()
              .createAes(256)
              .named("vault")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
      KeyHandle replacement =
          old.replaceCompromised(RevocationReason.keyCompromise("leaked", Instant.now()));
      assertEquals(Optional.of(replacement), kms.keys().findByName("vault"));
      assertEquals(KeyState.ACTIVE, replacement.attributes().state());
    }
  }

  @ParameterizedTest
  @MethodSource("legacy")
  void aRefusalNoLocateConfirmsStands(KmipVersion version, ResultReason reason) {
    InMemoryKmipServer server = server(version, reason);
    try (Kms kms = connect(server)) {
      KeyHandle key =
          kms.keys()
              .createAes(256)
              .named("mine")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
      // The same reason with the name on no other object: the server's refusal, not a name in use.
      server.failNext(ServerOperation.ADD_ATTRIBUTE, reason);
      KmsException alone = assertThrows(KmsException.class, () -> key.addName("free"));
      assertFalse(alone instanceof AlreadyExistsException, alone.toString());
      assertEquals(reason.name(), alone.serverReason().orElseThrow().name());
      // The object's own name is not someone else's.
      server.failNext(ServerOperation.ADD_ATTRIBUTE, reason);
      KmsException own = assertThrows(KmsException.class, () -> key.addName("mine"));
      assertFalse(own instanceof AlreadyExistsException, own.toString());
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void aRefusalForAnotherReasonStandsAlthoughTheNameIsInUse(
      KmipVersion version, ResultReason reason) {
    InMemoryKmipServer server = server(version, reason);
    try (Kms kms = connect(server)) {
      kms.keys().createAes(256).named("taken").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
      KeyHandle other =
          kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
      server.failNext(ServerOperation.ADD_ATTRIBUTE, ResultReason.PERMISSION_DENIED);
      assertThrows(PermissionDeniedException.class, () -> other.addName("taken"));
      server.failNext(ServerOperation.ADD_ATTRIBUTE, ResultReason.ITEM_NOT_FOUND);
      assertThrows(NotFoundException.class, () -> other.addName("taken"));
      // A request refusal of another reason, of the same type as Invalid Field.
      server.failNext(ServerOperation.ADD_ATTRIBUTE, ResultReason.MISSING_DATA);
      InvalidRequestException missing =
          assertThrows(InvalidRequestException.class, () -> other.addName("taken"));
      assertEquals(KmsReason.MISSING_DATA, missing.serverReason().orElseThrow());
    }
  }

  @ParameterizedTest
  @MethodSource("legacy")
  void aReplaceWhoseNameAdditionIsRefusedForAnotherReasonPutsTheNameBack(
      KmipVersion version, ResultReason reason) {
    InMemoryKmipServer server = server(version, reason);
    // The first Name addition is refused as a name in use (the old secret has it); the one after
    // the
    // name came off the old secret is refused too, with no holder: surfaced, and the name goes
    // back.
    AtomicInteger adds = new AtomicInteger();
    KmipTransport refusing =
        request -> {
          if (LineageTreeTest.addsName(request) && adds.incrementAndGet() == 2)
            server.failNext(ServerOperation.ADD_ATTRIBUTE, reason);
          return server.exchange(request);
        };
    try (Kms kms = TlsSafetyRegressionTest.connect(server, refusing)) {
      KeyHandle old =
          kms.keys().registerSecret("old".toCharArray()).named("db-password").register();
      adds.set(0);
      PartialCompletionException e =
          assertThrows(
              PartialCompletionException.class,
              () ->
                  kms.keys().registerSecret("new".toCharArray()).named("db-password").replace(old));
      assertTrue(e.getMessage().contains("put back on " + old.id()), e.getMessage());
      assertFalse(e.getCause() instanceof AlreadyExistsException, e.getCause().toString());
      assertEquals(List.of("db-password"), server.names(old.id()), e.getMessage());
      assertEquals(Optional.of(old), kms.keys().findByName("db-password"));
    }
  }

  @ParameterizedTest
  @MethodSource("legacy")
  void moveNameTypesARefusalByAThirdHolderAsANameInUse(KmipVersion version, ResultReason reason) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version); // names may be shared here
    try (Kms kms = connect(server)) {
      KeyHandle from =
          kms.keys()
              .createAes(256)
              .named("orders-write")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
      KeyHandle third =
          kms.keys()
              .createAes(256)
              .named("orders-write")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
      KeyHandle to = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
      server.failNext(ServerOperation.ADD_ATTRIBUTE, reason);
      AlreadyExistsException e =
          assertThrows(
              AlreadyExistsException.class,
              () -> kms.keys().moveName("orders-write", from.id(), to.id()));
      assertTrue(e.getMessage().contains(third.id()), e.getMessage());
      assertFalse(
          e.getMessage().contains(from.id() + ";") || e.getMessage().contains("(" + from.id()),
          e.getMessage());
      assertTrue(server.names(from.id()).contains("orders-write"));
      assertEquals(List.of(), server.names(to.id()));
    }
  }

  /** Whether {@code t} holds the text {@code value} exactly. */
  static boolean holds(dev.keytend.kmip.model.Ttlv t, String value) {
    if (t.type() == dev.keytend.kmip.model.Ttlv.Type.TEXT_STRING && value.equals(t.value()))
      return true;
    if (t.type() == dev.keytend.kmip.model.Ttlv.Type.STRUCTURE)
      for (dev.keytend.kmip.model.Ttlv c : t.children()) if (holds(c, value)) return true;
    return false;
  }

  /** A transport refusing the Name additions of {@code name} whose ordinals are in {@code which} with {@code reason}. */
  static KmipTransport refusingAdditionsOf(
      InMemoryKmipServer server, String name, ResultReason reason, int... which) {
    AtomicInteger adds = new AtomicInteger();
    return request -> {
      if (LineageTreeTest.addsName(request) && holds(request, name)) {
        int n = adds.incrementAndGet();
        for (int w : which) if (w == n) server.failNext(ServerOperation.ADD_ATTRIBUTE, reason);
      }
      return server.exchange(request);
    };
  }

  @ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V2_1", "V3_0"})
  void fromKmip20ATlsRegistrationsUnconfirmedNameRefusalStands(KmipVersion version)
      throws Exception {
    // Illegal Operation is reserved from 2.0; Invalid Field there means something else.
    for (ResultReason reason : List.of(ResultReason.INVALID_FIELD)) {
      InMemoryKmipServer server = server(version, null);
      Pki pki = new Pki();
      KeyPair k = TestPki.ec();
      try (Kms kms =
          TlsSafetyRegressionTest.connect(
              server, refusingAdditionsOf(server, NAME, reason, 1, 2, 3, 4, 5, 6))) {
        KmsException e =
            assertThrows(
                KmsException.class,
                () ->
                    kms.tls()
                        .register(k.getPrivate(), pki.chain(pki.leaf("n", k)))
                        .named(NAME)
                        .register());
        assertFalse(e instanceof AlreadyExistsException, reason + ": " + e);
        assertEquals(reason.name(), e.serverReason().map(Enum::name).orElse(""), e.toString());
      }
    }
  }

  @ParameterizedTest
  @MethodSource("legacy")
  void aRotationWhoseSecondNameAdditionIsRefusedGivesTheNameBack(
      KmipVersion version, ResultReason reason) {
    // Names may be shared here, so the first refusal (confirmed only because the old key holds the
    // name) was not about the name: once the old key gave it up, the second is not confirmed.
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    KmipTransport t = refusingAdditionsOf(server, "vault", reason, 1, 2);
    KmipTransport noReKey =
        request -> {
          if (RotationAndNameChoiceTest.isOperation(
              request, dev.keytend.kmip.model.Operation.RE_KEY))
            server.failNext(ServerOperation.RE_KEY, dev.keytend.kmip.testing.Fault.UNSUPPORTED);
          return t.exchange(request);
        };
    try (Kms kms = TlsSafetyRegressionTest.connect(server, noReKey)) {
      KeyHandle old =
          kms.keys()
              .createAes(256)
              .named("vault")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
      KmsException e =
          assertThrows(
              KmsException.class,
              () ->
                  old.replaceCompromised(RevocationReason.keyCompromise("leaked", Instant.now())));
      assertEquals(
          List.of("vault"), server.names(old.id()), "the name is back on the old key: " + e);
      for (String id : server.ids())
        if (!id.equals(old.id())) {
          assertEquals(List.of(), server.names(id), id);
          assertTrue(
              KeyHandle.pendingNames(kms.keys().handle(id).attributes()).isEmpty(),
              "no move record left on " + id);
        }
    }
  }

  @ParameterizedTest
  @MethodSource("legacy")
  void aTlsRenewalWhoseNameAdditionIsRefusedAfterTheNameCameOffGivesItBack(
      KmipVersion version, ResultReason reason) throws Exception {
    InMemoryKmipServer server = server(version, reason);
    Pki pki = new Pki();
    KeyPair k = TestPki.ec();
    // The registration's addition is the first; the renewal's are the second (a name in use) and
    // the third, refused for another reason once the old certificate gave the name up.
    try (Kms kms =
        TlsSafetyRegressionTest.connect(
            server, refusingAdditionsOf(server, NAME, ResultReason.INVALID_FIELD, 3))) {
      TlsIdentityHandle h =
          kms.tls().register(k.getPrivate(), pki.chain(pki.leaf("n", k))).named(NAME).register();
      KmsException e = assertThrows(KmsException.class, () -> h.renew(pki.chain(pki.leaf("n", k))));
      assertEquals(
          List.of(NAME),
          server.names(h.certificate().id()),
          "the name is back on the current certificate: " + e);
      // Still found by its name (lookups follow the old certificate's Replacement link).
      assertTrue(kms.tls().identity(NAME).isPresent());
    }
  }
}
