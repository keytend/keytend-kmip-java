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
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * A compromise plan names every key the replacement acts on, and is bound to them; a failure after
 * the Revoke keeps the progress made before it; and a confirmed Revoke stays this call's when a
 * later step is recovered. Faults are armed from the client's transport, as the requests go out, so
 * each case is deterministic.
 */
class CompromiseProgressTest {
  static final String NAME = "orders-kek";
  static final Instant MINE = Instant.parse("2026-10-01T00:00:00Z");
  static final Instant THEIRS = Instant.parse("2026-01-01T00:00:00Z");
  static final Instant LATER = Instant.parse("2026-06-01T00:00:00Z");

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

  static KeyHandle aes(Kms kms) {
    return kms.keys()
        .createAes(256)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .named(NAME)
        .create();
  }

  static RevocationReason compromise(Instant since) {
    return RevocationReason.keyCompromise("leaked", since);
  }

  static boolean is(Ttlv request, Operation operation) {
    return RotationAndNameChoiceTest.isOperation(request, operation);
  }

  static String uid(Ttlv request) {
    return ConcurrentReplacementInterleavingsTest.uid(request);
  }

  static List<String> ids(List<KeyHandle> keys) {
    return keys.stream().map(KeyHandle::id).toList();
  }

  // ---- the plan names the descendant it replaces in turn, and is bound to it ----

  /**
   * The key's replacement is Compromised too. The plan says so (replacedInTurn, creates) instead of
   * "creates nothing", and the result names that key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aCompromisedReplacementIsNamedByThePlanAndReplacedInTurn(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms);
    KeyHandle next = key.rotate();
    key.revoke(compromise(THEIRS));
    next.revoke(compromise(LATER));
    CompromisePlan plan = key.compromisePlan();
    assertEquals(List.of(next.id()), plan.replacementIds());
    assertEquals(Optional.empty(), plan.existingReplacement());
    KeyAttributes inTurn = plan.replacedInTurn().orElseThrow();
    assertEquals(next.id(), inTurn.id());
    assertEquals(Optional.of(LATER), inTurn.compromiseOccurrenceDate());
    assertTrue(plan.creates(), plan.toString());
    int before = s.ids().size();
    CompromiseResult r = key.replaceCompromisedResult(compromise(MINE), plan);
    assertEquals(CompromiseResult.Outcome.COMPLETED, r.outcome(), r.toString());
    assertEquals(List.of(next.id()), ids(r.replacedInTurn()));
    assertEquals(List.of(r.replacement()), r.created());
    assertEquals(before + 1, s.ids().size());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(r.replacement().id()));
    assertTrue(s.names(r.replacement().id()).contains(NAME), "it has the names");
    assertEquals(Optional.of(THEIRS), r.compromiseOccurrenceDate(), "the key's own first date");
  }

  /** An existing Active replacement: the plan finishes with it and creates nothing. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anActiveReplacementIsWhatThePlanFinishesWith(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms);
    KeyHandle next = key.rotate();
    key.revoke(compromise(THEIRS));
    CompromisePlan plan = key.compromisePlan();
    assertEquals(next.id(), plan.existingReplacement().orElseThrow().id());
    assertEquals(Optional.empty(), plan.replacedInTurn());
    assertFalse(plan.creates());
    CompromiseResult r = key.replaceCompromisedResult(compromise(MINE), plan);
    assertEquals(CompromiseResult.Outcome.EXISTING, r.outcome());
    assertEquals(next, r.replacement());
    assertEquals(List.of(), r.replacedInTurn());
    assertEquals(List.of(), r.created());
  }

  /**
   * The second case: the replacement becomes Compromised while the plan waits. The key itself is as
   * planned, but the call would now create a key the plan did not name: NOT_AS_PLANNED, and nothing
   * changes.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aReplacementCompromisedWhileThePlanWaitsIsRefused(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s), other = connect(s);
    KeyHandle key = aes(kms);
    KeyHandle next = key.rotate();
    key.revoke(compromise(THEIRS));
    CompromisePlan plan = key.compromisePlan();
    assertFalse(plan.creates());
    other.keys().handle(next.id()).revoke(compromise(LATER));
    int before = s.ids().size();
    int reKeys = RotationGraceTest.sent(s, Operation.RE_KEY);
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> key.replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(StateConflictException.Conflict.NOT_AS_PLANNED, e.conflict(), e.getMessage());
    assertTrue(e.getMessage().contains(next.id()), e.getMessage());
    assertEquals(before, s.ids().size(), "nothing was created");
    assertEquals(reKeys, RotationGraceTest.sent(s, Operation.RE_KEY));
    assertEquals(List.of(NAME), s.names(next.id()), "the names stay");
  }

  /**
   * The newest key descending from the key is Deactivated, so it cannot be the replacement. The
   * plan refuses, as the change would, and the unbound call refuses before it revokes the key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aDeactivatedNewestDescendantIsRefusedBeforeAnythingChanges(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms);
    KeyHandle next = key.rotate();
    next.deactivate();
    StateConflictException plan = assertThrows(StateConflictException.class, key::compromisePlan);
    assertEquals(StateConflictException.Conflict.STATE, plan.conflict(), plan.getMessage());
    assertEquals(Optional.of(next.id()), plan.objectId());
    assertEquals(Optional.of(KeyState.DEACTIVATED), plan.observedState());
    StateConflictException change =
        assertThrows(StateConflictException.class, () -> key.replaceCompromised(compromise(MINE)));
    assertEquals(
        plan.getMessage().replace("compromisePlan: ", "replaceCompromised: "), change.getMessage());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(key.id()), "not revoked");
  }

  // ---- progress before a failure is kept ----

  /**
   * The first case: the Revoke took effect (its reply confirmed it), and the next read is refused.
   * The key stays Compromised, so the failure is a partial completion that lists it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aFailureAfterAConfirmedRevokeListsTheRevokedKey(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicBoolean first = new AtomicBoolean(true);
    Kms kms =
        connect(
            s,
            r -> {
              if (is(r, Operation.REVOKE) && first.getAndSet(false))
                s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
            });
    KeyHandle key = aes(kms);
    CompromisePlan plan = key.compromisePlan();
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> key.replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(List.of(key.id()), ids(e.deactivated()), e.getMessage());
    assertEquals(List.of(), e.created());
    assertTrue(e.recoveredFrom().isEmpty());
    assertInstanceOf(PermissionDeniedException.class, e.getCause());
    assertTrue(e.getMessage().contains("revoked " + key.id()), e.getMessage());
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(key.id()));
  }

  /**
   * The second case: the Revoke's reply is lost and the read that would settle it is refused. The
   * unknown Revoke stands, with the read's failure on it; it is not replaced by that failure.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostRevokeWhoseReadBackFailsStaysUnknown(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicBoolean first = new AtomicBoolean(true);
    Kms kms =
        connect(
            s,
            r -> {
              if (!is(r, Operation.REVOKE) || !first.getAndSet(false)) return;
              s.failNext(ServerOperation.REVOKE, Fault.REPLY_LOST);
              s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
            });
    KeyHandle key = aes(kms);
    CompromisePlan plan = key.compromisePlan();
    OutcomeUnknownException e =
        assertThrows(
            OutcomeUnknownException.class,
            () -> key.replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(Optional.of(key.id()), e.objectId());
    assertTrue(
        Arrays.stream(e.getSuppressed()).anyMatch(PermissionDeniedException.class::isInstance),
        "the read's failure is suppressed on it");
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(key.id()), "the Revoke took effect");
  }

  /**
   * The third case: the Revoke's reply is lost and read back, the Re-key is confirmed, and then
   * reading the replacement is refused. The inner rotation's partial completion keeps the
   * replacement it created, and the outer call adds the lost Revoke as recoveredFrom().
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostRevokeIsKeptWhenALaterStepFails(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicReference<String> keyId = new AtomicReference<>();
    AtomicBoolean firstRevoke = new AtomicBoolean(true), reKeyed = new AtomicBoolean();
    Kms kms =
        connect(
            s,
            r -> {
              if (is(r, Operation.REVOKE) && firstRevoke.getAndSet(false))
                s.failNext(ServerOperation.REVOKE, Fault.REPLY_LOST);
              else if (is(r, Operation.RE_KEY)) reKeyed.set(true);
              else if (is(r, Operation.GET_ATTRIBUTES)
                  && reKeyed.get()
                  && !uid(r).equals(keyId.get())
                  && reKeyed.getAndSet(false))
                s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
            });
    KeyHandle key = aes(kms);
    keyId.set(key.id());
    CompromisePlan plan = key.compromisePlan();
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> key.replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(1, e.created().size(), e.getMessage());
    String made = e.created().get(0).id();
    assertNotEquals(key.id(), made);
    OutcomeUnknownException lost = e.recoveredFrom().orElseThrow();
    assertEquals(Optional.of(key.id()), lost.objectId(), "the lost Revoke");
    assertEquals(List.of(), e.deactivated(), "not confirmed by this call's reply");
    assertInstanceOf(PermissionDeniedException.class, e.getCause());
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(key.id()));
  }

  // ---- each step's attribution stands on its own ----

  /**
   * The Revoke's reply confirms it; only the Re-key's reply is lost. The plan-bound call stops
   * there (it cannot tell whose Re-key made the key it reads back), but the revocation, with this
   * call's date, is still this call's; a new plan finishes with the key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aConfirmedRevokeStaysThisCallsWhenTheReKeyIsLost(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms);
    CompromisePlan plan = key.compromisePlan();
    s.failNext(ServerOperation.RE_KEY, Fault.REPLY_LOST);
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> key.replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(List.of(key.id()), e.deactivated().stream().map(KeyHandle::id).toList());
    assertEquals(List.of(), e.created(), "the replacement's creation is not confirmed");
    OutcomeUnknownException lost = assertInstanceOf(OutcomeUnknownException.class, e.getCause());
    assertEquals(Optional.of(key.id()), lost.objectId(), "the lost Re-key");
    CompromiseResult r = key.replaceCompromisedResult(compromise(MINE), key.compromisePlan());
    assertEquals(CompromiseResult.Outcome.EXISTING, r.outcome(), r.toString());
    assertFalse(r.revoked(), "revoked by the first call");
    assertEquals(Optional.of(MINE), r.compromiseOccurrenceDate());
  }

  /** Every reply came: nothing was recovered. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aReplacementWithEveryReplyRecoversNothing(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms);
    CompromiseResult r = key.replaceCompromisedResult(compromise(MINE), key.compromisePlan());
    assertEquals(CompromiseResult.Outcome.REPLACED, r.outcome());
    assertEquals(Optional.empty(), r.recoveredFrom());
    assertEquals(List.of(), r.replacedInTurn());
  }
}
