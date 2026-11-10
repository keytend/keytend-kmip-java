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

import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link KeyCreation#findOrCreateResult()} says how it got its key, and {@link
 * KeyCreation#refusingExistingName()} and {@link KeyRegistration#refusingExistingName()} refuse a
 * taken name before anything is created.
 */
class FindOrCreateResultTest {
  static final String NAME = "orders-kek";

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    servers.add(s);
    return s;
  }

  Kms connect(InMemoryKmipServer s) {
    return connect(s, r -> {});
  }

  Kms connect(InMemoryKmipServer s, Consumer<Ttlv> before) {
    Kms kms =
        Kms.connect(
            s.configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        r -> {
                          before.accept(r);
                          return s.exchange(r);
                        })
                .build());
    clients.add(kms);
    return kms;
  }

  static KeyCreation aes(Kms kms) {
    return kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named(NAME);
  }

  static int sent(InMemoryKmipServer s, Operation op) {
    return RotationGraceTest.sent(s, op);
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theOutcomeSaysHowTheKeyWasGot(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    FindOrCreateResult created = aes(kms).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.CREATED, created.outcome());
    assertEquals(List.of(created.key()), created.created());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(created.key().id()));

    FindOrCreateResult found = aes(kms).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.FOUND, found.outcome());
    assertEquals(created.key(), found.key());
    assertEquals(List.of(), found.created());
    assertEquals(created.key(), aes(kms).findOrCreate());

    // A staged key with the name: activated by this call, and said so.
    KeyHandle staged =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("staged")
            .createPreActive();
    FindOrCreateResult activated =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("staged")
            .findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.ACTIVATED, activated.outcome());
    assertEquals(staged, activated.key());
    assertEquals(List.of(), activated.created());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(staged.id()));
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aCompromisedKeyReplacedOnRequestIsReplaced(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle old = aes(kms).create();
    old.revoke(RevocationReason.keyCompromise("leaked", Instant.now()));
    FindOrCreateResult r = aes(kms).replacingCompromised().findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.REPLACED, r.outcome());
    assertNotEquals(old, r.key());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(r.key().id()));
    assertEquals(List.of(NAME), s.names(r.key().id()));
  }

  /**
   * Another caller makes the key between this call's Locate and its Create. This call's key loses
   * (the other ranks first), so the result is the other key, FOUND, and {@code created()} names the
   * key this call left behind, Pre-Active.
   */
  @Test
  void aKeyLeftByALostRaceIsListed() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms other = connect(s);
    AtomicBoolean first = new AtomicBoolean(true);
    Kms kms =
        connect(
            s,
            r -> {
              if (RotationAndNameChoiceTest.isOperation(r, Operation.CREATE)
                  && first.getAndSet(false)) aes(other).create();
            });
    FindOrCreateResult r = aes(kms).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.FOUND, r.outcome(), r.toString());
    assertEquals(1, r.created().size());
    KeyHandle left = r.created().get(0);
    assertNotEquals(r.key(), left);
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(left.id()));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(r.key().id()));
    assertEquals(List.of(left), r.key().leftovers());
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aTakenNameIsRefusedBeforeTheCreate(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle holder = aes(kms).create();
    int creates = sent(s, Operation.CREATE);
    AlreadyExistsException refused =
        assertThrows(AlreadyExistsException.class, () -> aes(kms).refusingExistingName().create());
    assertEquals(Optional.of(holder.id()), refused.objectId());
    assertTrue(refused.getMessage().contains("is taken by " + holder.id()), refused.getMessage());
    assertEquals(creates, sent(s, Operation.CREATE), "no Create was sent");
    // Any state but destroyed holds the name: Pre-Active, Deactivated, Compromised.
    holder.deactivate();
    assertThrows(
        AlreadyExistsException.class, () -> aes(kms).refusingExistingName().createPreActive());
    KeyHandle staged =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).named("staged").createPreActive();
    creates = sent(s, Operation.CREATE);
    assertThrows(
        AlreadyExistsException.class,
        () ->
            kms.keys()
                .createAes(256)
                .usages(KeyUsage.ENCRYPT)
                .named("staged")
                .refusingExistingName()
                .create());
    staged.revoke(RevocationReason.keyCompromise(null, Instant.now()));
    assertThrows(
        AlreadyExistsException.class,
        () ->
            kms.keys()
                .createAes(256)
                .usages(KeyUsage.ENCRYPT)
                .named("staged")
                .refusingExistingName()
                .create());
    assertEquals(creates, sent(s, Operation.CREATE));
    // A free name is created as usual.
    KeyHandle fresh =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT)
            .named("fresh")
            .refusingExistingName()
            .create();
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(fresh.id()));
  }

  @Test
  void aDestroyedHolderDoesNotHoldTheName() {
    InMemoryKmipServer s = server(KmipVersion.V2_1).destroyedObjectsKeepNames(true);
    Kms kms = connect(s);
    KeyHandle old = aes(kms).create();
    old.deactivate();
    old.destroy();
    assertEquals(List.of(NAME), s.names(old.id()), "the server keeps the destroyed key's name");
    KeyHandle again = aes(kms).refusingExistingName().create();
    assertNotEquals(old, again);
  }

  /** A holder that cannot be read fails the check: it is not taken for a free name. */
  @Test
  void anUnreadableHolderFailsTheCheck() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    aes(kms).create();
    int creates = sent(s, Operation.CREATE);
    s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
    assertThrows(PermissionDeniedException.class, () -> aes(kms).refusingExistingName().create());
    assertEquals(creates, sent(s, Operation.CREATE));
  }

  /**
   * A second password under a name, and a password under a key's name, are refused; without the
   * option they are registered, as before.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRegistrationRefusesATakenName(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle first = kms.keys().registerSecret("one".toCharArray()).named("db-pass").register();
    int registers = sent(s, Operation.REGISTER);
    AlreadyExistsException refused =
        assertThrows(
            AlreadyExistsException.class,
            () ->
                kms.keys()
                    .registerSecret("two".toCharArray())
                    .named("db-pass")
                    .refusingExistingName()
                    .register());
    assertEquals(Optional.of(first.id()), refused.objectId());
    KeyHandle kek = aes(kms).create();
    assertThrows(
        AlreadyExistsException.class,
        () ->
            kms.keys()
                .registerSecret(SecretData.Type.SEED, "s".getBytes(StandardCharsets.UTF_8))
                .named(NAME)
                .refusingExistingName()
                .registerPreActive());
    assertEquals(registers, sent(s, Operation.REGISTER), "nothing was registered");
    assertTrue(s.exists(kek.id()));
    // Without the option a duplicate is registered, as before.
    kms.keys().registerSecret("two".toCharArray()).named("db-pass").register();
    assertEquals(registers + 1, sent(s, Operation.REGISTER));
  }

  @Test
  void theOptionDoesNotGoWithFindOrCreateOrReplace() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    assertThrows(
        IllegalArgumentException.class, () -> aes(kms).refusingExistingName().findOrCreate());
    assertThrows(
        IllegalArgumentException.class, () -> aes(kms).refusingExistingName().findOrCreateResult());
    KeyHandle old = kms.keys().registerSecret("one".toCharArray()).named("db-pass").register();
    assertThrows(
        IllegalArgumentException.class,
        () ->
            kms.keys()
                .registerSecret("two".toCharArray())
                .named("db-pass")
                .refusingExistingName()
                .replace(old));
    assertEquals(0, sent(s, Operation.CREATE));
  }
}
