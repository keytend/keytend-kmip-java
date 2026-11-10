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
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * A step whose reply was lost and that reading back went past is reported on the success results
 * too ({@code recoveredFrom()}), never as an ordinary find; and a result attributes a change to the
 * call only when its own reply confirmed it.
 */
class RecoveredStepsTest {
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

  /** A client whose requests {@code before} sees first, before the server does. */
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

  static boolean is(Ttlv request, Operation operation) {
    return RotationAndNameChoiceTest.isOperation(request, operation);
  }

  // ---- a lost Activate of a found key ----

  /**
   * The first case: the approved key's Activate is lost, and reading it back finds it Active. This
   * call or another caller activated it: RECOVERED, with the lost Activate, never FOUND.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostActivationOfTheApprovedKeyIsRecoveredNotFound(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle staged = aes(kms).createPreActive();
    KeyCreation creation = aes(kms).refusingPreActive();
    assertThrows(StateConflictException.class, creation::findOrCreateResult);
    s.failNext(ServerOperation.ACTIVATE, Fault.REPLY_LOST);
    FindOrCreateResult r = creation.allowingPreActive(staged).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.RECOVERED, r.outcome(), r.toString());
    assertEquals(staged, r.key());
    assertEquals(List.of(), r.created());
    OutcomeUnknownException lost = r.recoveredFrom().orElseThrow();
    assertEquals(Optional.of(staged.id()), lost.objectId(), "the lost Activate names the key");
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(staged.id()));
  }

  /** The same without approval: a Pre-Active key the name leads to, activated by default. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostActivationOfAFoundKeyIsRecovered(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle staged = aes(kms).createPreActive();
    s.failNext(ServerOperation.ACTIVATE, Fault.REPLY_LOST);
    FindOrCreateResult r = aes(kms).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.RECOVERED, r.outcome());
    assertEquals(Optional.of(staged.id()), r.recoveredFrom().orElseThrow().objectId());
  }

  /**
   * The second case: the approved key's Activate is lost and reading it back is refused. The
   * unknown Activate stands; its objectId() names the key (a lost Create has none), so a caller can
   * tell which step it was.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostActivationWhoseReadBackFailsNamesTheKey(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicBoolean armed = new AtomicBoolean();
    Kms kms =
        connect(
            s,
            r -> {
              if (!is(r, Operation.ACTIVATE) || !armed.getAndSet(false)) return;
              s.failNext(ServerOperation.ACTIVATE, Fault.REPLY_LOST);
              s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
            });
    KeyHandle staged = aes(kms).createPreActive();
    KeyCreation creation = aes(kms).refusingPreActive();
    assertThrows(StateConflictException.class, creation::findOrCreateResult);
    armed.set(true);
    OutcomeUnknownException e =
        assertThrows(
            OutcomeUnknownException.class,
            () -> creation.allowingPreActive(staged).findOrCreateResult());
    assertEquals(Optional.of(staged.id()), e.objectId());
    assertTrue(
        Arrays.stream(e.getSuppressed()).anyMatch(PermissionDeniedException.class::isInstance));
    assertEquals(1, s.ids().size(), "no key was created");
  }

  /** A lost Create still names no key: the two unknown steps are told apart. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRecoveredCreateNamesNoKey(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    s.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
    FindOrCreateResult r = aes(kms).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.RECOVERED, r.outcome());
    assertEquals(Optional.empty(), r.recoveredFrom().orElseThrow().objectId());
  }

  /** The same for a key pair: a lost Activate of a key of a pair it found is RECOVERED. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostActivationOfAFoundPairIsRecovered(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyPairHandle staged = pair(kms).createPreActive();
    s.failNext(ServerOperation.ACTIVATE, Fault.REPLY_LOST);
    FindOrCreatePairResult r = pair(kms).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.RECOVERED, r.outcome(), r.toString());
    assertEquals(staged.privateKey(), r.pair().privateKey());
    assertTrue(r.recoveredFrom().orElseThrow().objectId().isPresent());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(staged.privateKey().id()));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(staged.publicKey().id()));
  }

  static KeyPairCreation pair(Kms kms) {
    return kms.keys()
        .createKeyPair(KeyPairSpec.ec(Curve.P_256))
        .named("signer", "signer.pub")
        .privateUsages(KeyUsage.SIGN)
        .publicUsages(KeyUsage.VERIFY);
  }

  // ---- a rotation's lost Re-key ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRecoveredRotationSaysWhichReKeyWasLost(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms).create();
    s.failNext(ServerOperation.RE_KEY, Fault.REPLY_LOST);
    RotationResult r = key.rotateResult(Rotation.of(RotationDates.COPIED));
    assertEquals(RotationResult.Outcome.RECOVERED, r.outcome(), r.toString());
    assertEquals(Optional.of(key.id()), r.recoveredFrom().orElseThrow().objectId());
    assertEquals(
        Optional.empty(),
        r.current().rotateResult(Rotation.of(RotationDates.COPIED)).recoveredFrom());
  }

  // ---- a secret replacement attributes the deactivation only to its own reply ----

  /**
   * Another caller deactivates the old secret just before this call's request, which the server
   * then refuses. The old secret is Deactivated, but not by this call.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aSecretAnotherCallerRetiredFirstIsNotDeactivatedByThisCall(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms other = connect(s);
    AtomicReference<String> old = new AtomicReference<>();
    AtomicBoolean first = new AtomicBoolean(true);
    ServerOperation retire =
        version == KmipVersion.V3_0 ? ServerOperation.DEACTIVATE : ServerOperation.REVOKE;
    Kms kms =
        connect(
            s,
            r -> {
              if (!(is(r, Operation.REVOKE) || is(r, Operation.DEACTIVATE))
                  || !ConcurrentReplacementInterleavingsTest.uid(r).equals(old.get())
                  || !first.getAndSet(false)) return;
              other.keys().handle(old.get()).deactivate();
              s.failNext(retire, Fault.PERMISSION_DENIED);
            });
    KeyHandle active = ConflictKindTest.secret(kms, "db").register();
    old.set(active.id());
    ReplacementResult r = ConflictKindTest.secret(kms, "db").replaceResult(active);
    assertEquals(KeyState.DEACTIVATED, r.previousState());
    assertFalse(r.deactivatedPrevious(), "another caller retired it");
    assertEquals(Optional.empty(), r.recoveredFrom());
    assertFalse(first.get(), "the race ran");
  }

  /** The request's reply is lost: retired, but whose request did it cannot be told. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aSecretDeactivationWhoseReplyWasLostIsNotClaimed(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle active = ConflictKindTest.secret(kms, "db").register();
    s.failNext(
        version == KmipVersion.V3_0 ? ServerOperation.DEACTIVATE : ServerOperation.REVOKE,
        Fault.REPLY_LOST);
    ReplacementResult r = ConflictKindTest.secret(kms, "db").replaceResult(active);
    assertEquals(KeyState.DEACTIVATED, r.previousState());
    assertFalse(r.deactivatedPrevious());
    assertEquals(Optional.of(active.id()), r.recoveredFrom().orElseThrow().objectId());
  }

  /** Every reply came: the deactivation is this call's, and nothing was recovered. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aSecretDeactivationThisCallMadeIsClaimed(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle active = ConflictKindTest.secret(kms, "db").register();
    ReplacementResult r = ConflictKindTest.secret(kms, "db").replaceResult(active);
    assertTrue(r.deactivatedPrevious());
    assertEquals(Optional.empty(), r.recoveredFrom());
  }

  // ---- each kind of conflict ----

  @Test
  void applicationCodeCanMakeEachKindOfConflict() {
    for (StateConflictException.Conflict kind : StateConflictException.Conflict.values()) {
      StateConflictException e = new StateConflictException("x", kind);
      assertEquals(kind, e.conflict());
      assertEquals("x", e.getMessage());
      assertNull(e.getCause());
    }
    assertThrows(
        NullPointerException.class,
        () -> new StateConflictException("x", (StateConflictException.Conflict) null));
  }
}
