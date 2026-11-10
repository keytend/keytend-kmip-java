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

import static dev.keytend.kmip.kms.TlsIdentityTest.connect;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.kms.TlsIdentityTest.Pki;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The name of a destroyed identity. On servers that keep the names of destroyed objects
 * (keytend-kmip-server with {@code --destroyed-name-reuse reserve}): registering under it is
 * refused, and nothing it registered is presented. On servers that free them
 * (keytend-kmip-server's default): registering under it succeeds. Either way a destroyed identity
 * is not renewed or re-keyed.
 */
class TlsDestroyedNameTest {
  static final String NAME = "cassandra/node1";

  /** An identity registered, compromised, and its certificate and key destroyed. */
  static TlsIdentityHandle destroyedIdentity(Kms kms, Pki pki) throws Exception {
    KeyPair k = TestPki.ec();
    TlsIdentityHandle h =
        kms.tls().register(k.getPrivate(), pki.chain(pki.leaf("node1", k))).named(NAME).register();
    h.revoke(RevocationReason.keyCompromise("disk stolen", Instant.now()));
    h.certificate().destroy();
    h.privateKey().destroy();
    return h;
  }

  /**
   * As keytend-kmip-server on 2.x and the 3.0 draft: the destroyed objects keep the name, and Locate does
   * not return them, so the name's holder cannot be seen.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void registeringUnderANameADestroyedObjectKeepsIsRefusedWithNothingActive(KmipVersion version)
      throws Exception {
    InMemoryKmipServer server =
        InMemoryKmipServer.of(version).uniqueNames(true).destroyedObjectsKeepNames(true);
    Pki pki = new Pki();
    try (Kms kms = connect(server)) {
      TlsIdentityHandle old = destroyedIdentity(kms, pki);
      assertEquals(
          Optional.empty(), kms.tls().identity(NAME), "Locate passes destroyed objects over");
      KeyPair k = TestPki.ec();
      Issued leaf = pki.leaf("node1", k);
      List<String> before = server.ids();
      AlreadyExistsException refused =
          assertThrows(
              AlreadyExistsException.class,
              () -> kms.tls().register(k.getPrivate(), pki.chain(leaf)).named(NAME).register());
      assertTrue(
          refused.getMessage().contains("although no object it locates has it"),
          refused.getMessage());
      List<String> made = new ArrayList<>(server.ids());
      made.removeAll(before);
      assertEquals(3, made.size(), made.toString());
      // The name is the switch: the objects are Pre-Active, with no name, and never presented.
      for (String id : made) {
        assertEquals(List.of(), server.names(id), id + " is never presented");
        assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(id), id);
        assertTrue(refused.getMessage().contains(id), refused.getMessage());
      }
      assertTrue(refused.getMessage().contains("are left over"), refused.getMessage());
      assertFalse(refused.getMessage().contains("destroy them"), refused.getMessage());
      assertEquals(Optional.empty(), kms.tls().identity(NAME));
      // A repeat starts over, and is refused the same way.
      assertThrows(
          AlreadyExistsException.class,
          () -> kms.tls().register(k.getPrivate(), pki.chain(leaf)).named(NAME).register());
      assertEquals(before.size() + 2 * made.size(), server.ids().size());
      // Under another name it is registered.
      TlsIdentityHandle elsewhere =
          kms.tls()
              .register(k.getPrivate(), pki.chain(pki.leaf("node1", k)))
              .named(NAME + "-2")
              .register();
      assertEquals(KeyState.ACTIVE, elsewhere.certificate().attributes().state());
      assertEquals(
          Optional.of(KeyState.DESTROYED_COMPROMISED), server.state(old.certificate().id()));
      // The handle held is not re-keyed: no certificate has the name, and nothing is registered.
      List<String> beforeRekey = server.ids();
      assertThrows(
          NotFoundException.class,
          () -> old.rekey(k.getPrivate(), pki.chain(pki.leaf("node1", k))));
      assertEquals(beforeRekey, server.ids(), "nothing registered");
      assertEquals(List.of(), server.violations());
    }
  }

  /**
   * As keytend-kmip-server by default ({@code --destroyed-name-reuse allow}): the destroyed
   * objects free the name, so registering under it succeeds and leaves one Active identity; the
   * handle of the destroyed identity is still not re-keyed.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void whereTheServerFreesDestroyedNamesTheNameIsRegisteredAgainAndTheOldIdentityIsNotReKeyed(
      KmipVersion version) throws Exception {
    InMemoryKmipServer server =
        InMemoryKmipServer.of(version).uniqueNames(true).destroyedObjectsKeepNames(false);
    Pki pki = new Pki();
    try (Kms kms = connect(server)) {
      TlsIdentityHandle old = destroyedIdentity(kms, pki);
      assertEquals(
          Optional.empty(), kms.tls().identity(NAME), "Locate passes destroyed objects over");
      KeyPair k = TestPki.ec();
      TlsIdentityHandle again =
          kms.tls()
              .register(k.getPrivate(), pki.chain(pki.leaf("node1", k)))
              .named(NAME)
              .register();
      assertEquals(KeyState.ACTIVE, again.certificate().attributes().state());
      assertEquals(KeyState.ACTIVE, again.privateKey().attributes().state());
      assertEquals(
          List.of(again.certificate().id()),
          kms.keys().list(KeyQuery.byName(NAME).state(KeyState.ACTIVE)).stream()
              .map(KeyHandle::id)
              .toList(),
          "one Active identity under the name");
      assertEquals(
          again.certificate().id(), kms.tls().identity(NAME).orElseThrow().certificate().id());
      List<String> before = server.ids();
      KeyPair k2 = TestPki.ec();
      StateConflictException noRekey =
          assertThrows(
              StateConflictException.class,
              () -> old.rekey(k2.getPrivate(), pki.chain(pki.leaf("node1", k2))));
      assertTrue(
          noRekey.getMessage().contains("is certificate " + again.certificate().id() + " now"),
          noRekey.getMessage());
      assertEquals(before, server.ids(), "nothing registered");
      assertEquals(
          again.certificate().id(), kms.tls().identity(NAME).orElseThrow().certificate().id());
      assertEquals(
          Optional.of(KeyState.DESTROYED_COMPROMISED), server.state(old.certificate().id()));
      assertEquals(List.of(), server.violations());
    }
  }

  /**
   * A registration refused at its first Activate, after its switch (the name on its Pre-Active
   * leaf), is finished by a repeat with the same leaf: the repeat activates the key and then the
   * leaf. Until then readers find the identity with nothing to present.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRegistrationStoppedAtAnActivateIsFinishedByARepeat(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(true);
    Pki pki = new Pki();
    try (Kms kms = connect(server)) {
      KeyPair k = TestPki.ec();
      Issued leaf = pki.leaf("node1", k);
      server.failNext(ServerOperation.ACTIVATE, Fault.PERMISSION_DENIED);
      PartialCompletionException stopped =
          assertThrows(
              PartialCompletionException.class,
              () -> kms.tls().register(k.getPrivate(), pki.chain(leaf)).named(NAME).register());
      String leafId = stopped.created().get(0).id();
      assertEquals(List.of(NAME), server.names(leafId));
      assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(leafId));
      assertTrue(stopped.getMessage().contains("the repeat activates it"), stopped.getMessage());
      StateConflictException notYet =
          assertThrows(
              StateConflictException.class,
              () -> kms.tls().follow(NAME, TlsIdentityTest.HOURLY, TlsIdentityTest.SCHEDULER));
      assertTrue(notYet.getMessage().contains("is PRE_ACTIVE"), notYet.getMessage());
      TlsIdentityHandle h =
          kms.tls().register(k.getPrivate(), pki.chain(leaf)).named(NAME).register();
      assertEquals(leafId, h.certificate().id());
      assertEquals(KeyState.ACTIVE, h.certificate().attributes().state());
      assertEquals(KeyState.ACTIVE, h.privateKey().attributes().state());
      assertEquals(List.of(NAME), h.certificate().attributes().names());
      assertEquals(List.of(), server.violations());
    }
  }

  /**
   * As keytend-kmip-server on 1.4: Locate returns the destroyed certificate for its name. Registering under
   * the name is refused before anything is registered, and the destroyed identity is not re-keyed.
   */
  @Test
  void whereLocateReturnsADestroyedIdentityItIsRefusedBeforeAnythingIsRegistered()
      throws Exception {
    InMemoryKmipServer server =
        InMemoryKmipServer.of(KmipVersion.V1_4).uniqueNames(true).destroyedObjectsKeepNames(true);
    AtomicReference<String> destroyed = new AtomicReference<>();
    KmipTransport returningDestroyed =
        new KmipTransport() {
          @Override
          public Ttlv exchange(Ttlv request) throws IOException {
            return exchange(request, CallContext.NONE);
          }

          @Override
          public Ttlv exchange(Ttlv request, CallContext c) throws IOException {
            Ttlv response = server.exchange(request, c);
            boolean locate =
                request.require(Tag.BATCH_ITEM).require(Tag.OPERATION).intValue()
                    == Operation.LOCATE.code();
            String id = destroyed.get();
            return locate && id != null && names(request, NAME)
                ? withIdentifier(response, id)
                : response;
          }
        };
    Pki pki = new Pki();
    try (Kms kms =
        Kms.connect(
            server
                .configure()
                .transport(e -> returningDestroyed)
                .callTimeout(Duration.ofSeconds(10))
                .build())) {
      TlsIdentityHandle old = destroyedIdentity(kms, pki);
      destroyed.set(old.certificate().id());
      KeyPair k = TestPki.ec();
      List<String> before = server.ids();
      AlreadyExistsException refused =
          assertThrows(
              AlreadyExistsException.class,
              () ->
                  kms.tls()
                      .register(k.getPrivate(), pki.chain(pki.leaf("node1", k)))
                      .named(NAME)
                      .register());
      assertTrue(
          refused.getMessage().contains("which is DESTROYED_COMPROMISED"), refused.getMessage());
      TlsIdentityHandle found = kms.tls().identity(NAME).orElseThrow();
      assertEquals(old.certificate().id(), found.certificate().id());
      StateConflictException noRekey =
          assertThrows(
              StateConflictException.class,
              () -> found.rekey(k.getPrivate(), pki.chain(pki.leaf("node1", k))));
      assertEquals(Optional.of(KeyState.DESTROYED_COMPROMISED), noRekey.observedState());
      assertEquals(before, server.ids(), "nothing registered");
    }
  }

  /** Whether {@code t} holds a Name Value {@code name}. */
  static boolean names(Ttlv t, String name) {
    if (t.tag() == Tag.NAME_VALUE.code() && t.type() == Ttlv.Type.TEXT_STRING)
      return name.equals(t.textValue());
    if (t.type() != Ttlv.Type.STRUCTURE) return false;
    for (Ttlv c : t.children()) if (names(c, name)) return true;
    return false;
  }

  /** {@code response} with {@code id} added to its Locate payload's identifiers, unless it is there. */
  static Ttlv withIdentifier(Ttlv response, String id) {
    if (response.type() != Ttlv.Type.STRUCTURE) return response;
    List<Ttlv> kept = new ArrayList<>();
    boolean payload = response.tag() == Tag.RESPONSE_PAYLOAD.code();
    boolean there = false;
    for (Ttlv c : response.children()) {
      if (payload && c.tag() == Tag.UNIQUE_IDENTIFIER.code() && id.equals(c.textValue()))
        there = true;
      kept.add(payload ? c : withIdentifier(c, id));
    }
    if (payload && !there) kept.add(Ttlv.text(Tag.UNIQUE_IDENTIFIER, id));
    return Ttlv.structure(response.tag(), kept);
  }
}
