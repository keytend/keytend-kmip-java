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
import java.io.IOException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * An unknown outcome is kept through every recovery step, a key found after one is never reported
 * as created, and an approved Pre-Active key is activated by the find-or-create call itself.
 */
class RecoveryProvenanceTest {
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

  /** A client whose requests {@code before} sees first: another caller acts there. */
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

  static <T extends Throwable> T suppressed(Throwable e, Class<T> type) {
    for (Throwable s : e.getSuppressed()) if (type.isInstance(s)) return type.cast(s);
    return fail("no " + type.getSimpleName() + " suppressed on " + e);
  }

  // ---- find-or-create keeps the unknown Create ----

  /**
   * The Create's reply is lost, and the key it made is Pre-Active under the name. With
   * refusingPreActive() it is not activated, and the call reports the unknown Create, not an
   * ordinary refusal: the refusal is suppressed on it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostCreateWhoseKeyIsPreActiveStaysUnknown(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    s.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
    OutcomeUnknownException e =
        assertThrows(
            OutcomeUnknownException.class, () -> aes(kms).refusingPreActive().findOrCreateResult());
    StateConflictException refusal = suppressed(e, StateConflictException.class);
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), refusal.observedState());
    String made = refusal.objectId().orElseThrow();
    assertEquals(List.of(made), s.ids());
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(made), "not activated");
    assertEquals(0, RotationGraceTest.sent(s, Operation.ACTIVATE));
  }

  /**
   * The Create is lost before the server processed it (nothing changed), and meanwhile another
   * caller staged an unrelated key with the name. Its name proves nothing: the call reports the
   * unknown Create and leaves that key Pre-Active.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anUnrelatedKeyFoundAfterALostRefusalIsNotActivated(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms other = connect(s);
    AtomicBoolean first = new AtomicBoolean(true);
    AtomicReference<KeyHandle> theirs = new AtomicReference<>();
    Kms kms =
        connect(
            s,
            r -> {
              if (!is(r, Operation.CREATE) || !first.getAndSet(false)) return;
              theirs.set(aes(other).createPreActive());
              s.injectBeforeProcessing(
                  q -> is(q, Operation.CREATE) ? new IOException("lost") : null);
            });
    OutcomeUnknownException e =
        assertThrows(
            OutcomeUnknownException.class, () -> aes(kms).refusingPreActive().findOrCreateResult());
    assertEquals(
        theirs.get().id(), suppressed(e, StateConflictException.class).objectId().orElseThrow());
    assertEquals(List.of(theirs.get().id()), s.ids(), "this call's Create made nothing");
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(theirs.get().id()));
  }

  /** The Create's reply is lost and the lookup that would recover it is refused: still unknown. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aFailedRecoveryLookupKeepsTheUnknownCreate(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicBoolean created = new AtomicBoolean();
    Kms kms =
        connect(
            s,
            r -> {
              if (is(r, Operation.CREATE)) created.set(true);
              else if (is(r, Operation.LOCATE) && created.getAndSet(false))
                s.failNext(ServerOperation.LOCATE, Fault.PERMISSION_DENIED);
            });
    s.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
    OutcomeUnknownException e =
        assertThrows(OutcomeUnknownException.class, () -> aes(kms).findOrCreateResult());
    suppressed(e, PermissionDeniedException.class);
    assertEquals(1, s.ids().size(), "the Create took effect");
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(s.ids().iterator().next()));
  }

  /** The same for a key pair: a refused read-back after a lost Create Key Pair stays unknown. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aFailedRecoveryLookupKeepsTheUnknownCreateKeyPair(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicBoolean created = new AtomicBoolean();
    Kms kms =
        connect(
            s,
            r -> {
              if (is(r, Operation.CREATE_KEY_PAIR)) created.set(true);
              else if (is(r, Operation.LOCATE) && created.getAndSet(false))
                s.failNext(ServerOperation.LOCATE, Fault.PERMISSION_DENIED);
            });
    s.failNext(ServerOperation.CREATE_KEY_PAIR, Fault.REPLY_LOST);
    OutcomeUnknownException e =
        assertThrows(
            OutcomeUnknownException.class,
            () ->
                kms.keys()
                    .createKeyPair(KeyPairSpec.ec(Curve.P_256))
                    .named("signer", "signer.pub")
                    .privateUsages(KeyUsage.SIGN)
                    .publicUsages(KeyUsage.VERIFY)
                    .findOrCreateResult());
    suppressed(e, PermissionDeniedException.class);
  }

  // ---- allowingPreActive ----

  /**
   * The approved key is activated by the call itself, so nothing is left between the approval
   * and the result; another Pre-Active key the name leads to is refused as before.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anApprovedPreActiveKeyIsActivatedByTheCall(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle staged = aes(kms).createPreActive();
    KeyCreation creation = aes(kms).refusingPreActive();
    StateConflictException refused =
        assertThrows(StateConflictException.class, creation::findOrCreateResult);
    assertEquals(StateConflictException.Conflict.STATE, refused.conflict());
    assertEquals(Optional.of(staged.id()), refused.objectId());
    FindOrCreateResult r = creation.allowingPreActive(staged).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.ACTIVATED, r.outcome(), r.toString());
    assertEquals(staged, r.key());
    assertEquals(List.of(), r.created());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(staged.id()));
    // Active now: found, not activated again.
    FindOrCreateResult again = aes(kms).allowingPreActive(staged).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.FOUND, again.outcome());

    // Another staged key is not the approved one: refused.
    KeyHandle second =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("second")
            .createPreActive();
    StateConflictException other =
        assertThrows(
            StateConflictException.class,
            () ->
                kms.keys()
                    .createAes(256)
                    .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                    .named("second")
                    .allowingPreActive(staged)
                    .findOrCreateResult());
    assertEquals(Optional.of(second.id()), other.objectId());
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(second.id()));
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anApprovedKeyFromAnotherKmsIsRefused(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s), other = connect(s);
    KeyHandle staged = aes(kms).createPreActive();
    KeyHandle foreign = other.keys().handle(staged.id());
    assertThrows(IllegalArgumentException.class, () -> aes(kms).allowingPreActive(foreign));
    assertThrows(
        IllegalArgumentException.class,
        () -> aes(kms).allowingPreActive(staged).replacingCompromised().findOrCreateResult());
  }

  // ---- a replacement found after a lost Re-key is never reported as created ----

  /**
   * Another caller rotates A to B just before this call's Re-key, which the server refuses; the
   * refusal's reply is lost, and reading back finds B. The next read of B is refused. B is listed
   * as found, with the lost Re-key, and not as created: only the other caller is known to have
   * made it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aFailureAfterARecoveredRotationDoesNotClaimTheReplacement(KmipVersion version) {
    InMemoryKmipServer s = server(version).refuseSecondReKey(true);
    Kms other = connect(s);
    AtomicReference<KeyHandle> a = new AtomicReference<>();
    AtomicReference<String> theirs = new AtomicReference<>();
    AtomicBoolean first = new AtomicBoolean(true);
    AtomicInteger readsOfB = new AtomicInteger();
    Kms kms =
        connect(
            s,
            r -> {
              if (is(r, Operation.RE_KEY) && first.getAndSet(false)) {
                theirs.set(other.keys().handle(a.get().id()).rotate().id());
                s.failNext(ServerOperation.RE_KEY, Fault.REPLY_LOST);
              } else if (is(r, Operation.GET_ATTRIBUTES)
                  && theirs.get() != null
                  && ConcurrentReplacementInterleavingsTest.uid(r).equals(theirs.get())
                  && readsOfB.incrementAndGet() == 2)
                s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
            });
    a.set(aes(kms).create());
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> a.get().rotateResult(Rotation.of(RotationDates.COPIED)));
    assertEquals(List.of(), e.created(), e.getMessage());
    assertEquals(List.of(theirs.get()), RotationGraceTest.ids(e.found()));
    assertTrue(e.recoveredFrom().isPresent());
    assertInstanceOf(PermissionDeniedException.class, e.getCause());
    assertEquals(Optional.of(theirs.get()), e.objectId());
    assertFalse(e.getMessage().contains("created"), e.getMessage());
    assertEquals(2, s.ids().size(), "only the other caller made a key");
  }

  /** The same with a grace period whose date is refused: the replacement is found, not created. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRefusedGraceAfterARecoveredRotationDoesNotClaimTheReplacement(KmipVersion version) {
    InMemoryKmipServer s =
        server(version).refuseSecondReKey(true).refuseClientDeactivationDate(true);
    Kms other = connect(s);
    AtomicReference<KeyHandle> a = new AtomicReference<>();
    AtomicReference<String> theirs = new AtomicReference<>();
    AtomicBoolean first = new AtomicBoolean(true);
    Kms kms =
        connect(
            s,
            r -> {
              if (!is(r, Operation.RE_KEY) || !first.getAndSet(false)) return;
              theirs.set(other.keys().handle(a.get().id()).rotate().id());
              s.failNext(ServerOperation.RE_KEY, Fault.REPLY_LOST);
            });
    a.set(aes(kms).create());
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> a.get().rotateResult(Rotation.grace(Duration.ofDays(7))));
    assertEquals(List.of(), e.created(), e.getMessage());
    assertEquals(List.of(theirs.get()), RotationGraceTest.ids(e.found()));
    assertTrue(e.recoveredFrom().isPresent());
  }
}
