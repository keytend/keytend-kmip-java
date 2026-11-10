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

import static dev.keytend.kmip.kms.RotationGraceTest.ids;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.time.Duration;
import java.time.Instant;
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
 * Plan, then act on exactly the plan: each change of existing keys after an approval refuses, and
 * changes nothing, when the server would change a key the approval did not name. In each race,
 * another caller acts between the plan and the call, through a second connection.
 */
class PlanBoundChangesTest {
  static final RevocationReason ROTATED = RevocationReason.superseded("rotated");
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

  /** Activates {@code id} unless the server's Re-key made it Active already. */
  static void activeOrActivate(Kms kms, InMemoryKmipServer s, String id) {
    if (s.state(id).orElseThrow() == KeyState.PRE_ACTIVE) kms.keys().handle(id).activate();
  }

  static int mutations(InMemoryKmipServer s) {
    return RetirementPlanTest.mutations(s)
        + RotationGraceTest.sent(s, Operation.RE_KEY)
        + RotationGraceTest.sent(s, Operation.ACTIVATE)
        + RotationGraceTest.sent(s, Operation.ADD_ATTRIBUTE)
        + RotationGraceTest.sent(s, Operation.MODIFY_ATTRIBUTE)
        + RotationGraceTest.sent(s, Operation.DELETE_ATTRIBUTE);
  }

  // ---- deactivatePredecessors(reason, plan) ----

  /**
   * P (Pre-Active) -> A (Active) -> N. The plan deactivates A only. Another caller activates P
   * meanwhile: the bound call refuses, and P and A stay Active.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aKeyActivatedAfterThePlanIsNotDeactivated(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle p = aes(kms).createPreActive();
    KeyHandle a = p.rotate();
    KeyHandle n = a.rotate();
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(p.id()));
    RetirementPlan plan = n.retirementPlan();
    assertEquals(List.of(p.id(), a.id()), plan.ids());
    try (Kms other = s.connect()) {
      other.keys().handle(p.id()).activate();
    }
    int before = mutations(s);
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> n.deactivatePredecessors(ROTATED, plan));
    assertTrue(
        e.getMessage().contains("Active now, not when planned: [" + p.id() + "]"), e.getMessage());
    assertEquals(Optional.of(p.id()), e.objectId());
    assertEquals(before, mutations(s), "nothing was changed");
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(p.id()));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(a.id()));
    // A new plan lists both as Active, and deactivates both.
    RetirementPlan again = n.retirementPlan();
    assertEquals(List.of(p.id(), a.id()), ids(n.deactivatePredecessors(ROTATED, again)));
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(p.id()));
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aBoundDeactivationActsOnThePlansActiveKeysOnly(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle p = aes(kms).createPreActive();
    KeyHandle a = p.rotate();
    KeyHandle b = a.rotate();
    KeyHandle n = b.rotate();
    RetirementPlan plan = n.retirementPlan();
    // Deactivated meanwhile by another caller: passed over.
    try (Kms other = s.connect()) {
      other.keys().handle(a.id()).deactivate(ROTATED);
    }
    assertEquals(List.of(b.id()), ids(n.deactivatePredecessors(ROTATED, plan)));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(p.id()), "Pre-Active: passed over");
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(b.id()));
    // A repeat with the same plan does nothing more.
    assertEquals(List.of(), n.deactivatePredecessors(ROTATED, plan));
    // Another caller's rotation meanwhile: the plan's newest key has a newer key now.
    KeyHandle newer = n.rotate();
    assertThrows(StateConflictException.class, () -> n.deactivatePredecessors(ROTATED, plan));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(n.id()));
    assertNotNull(newer);
  }

  @Test
  void aBoundDeactivationRefusesPlansItCannotKeep() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    KeyHandle a = aes(kms).create();
    KeyHandle b = a.rotate();
    KeyHandle n = b.rotate();
    RetirementPlan olderThan = n.retirementPlanOlderThan(b);
    assertThrows(
        IllegalArgumentException.class, () -> n.deactivatePredecessors(ROTATED, olderThan));
    RetirementPlan another =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .create()
            .rotate()
            .retirementPlan();
    assertThrows(IllegalArgumentException.class, () -> n.deactivatePredecessors(ROTATED, another));
    RetirementPlan plan = n.retirementPlan();
    RevocationReason compromise = RevocationReason.keyCompromise("leaked", Instant.now());
    assertThrows(IllegalArgumentException.class, () -> n.deactivatePredecessors(compromise, plan));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(a.id()));
  }

  // ---- retirement from a Compromised key ----

  /** Retirement from a Compromised newest key would destroy the only clean key. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void retirementFromACompromisedKeyIsRefused(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle clean = aes(kms).create();
    KeyHandle newest = clean.rotate();
    RetirementPlan before = newest.retirementPlan();
    newest.revoke(RevocationReason.keyCompromise("leaked", Instant.now()));
    KeyHandle compromised = kms.keys().handle(newest.id()).allowingCompromised();
    for (Runnable call :
        List.<Runnable>of(
            compromised::retirementPlan,
            () -> compromised.retirementPlanOlderThan(clean),
            () -> compromised.retirePredecessors(ROTATED),
            () -> compromised.retirePredecessors(ROTATED, before),
            () -> compromised.retirePredecessorsOlderThan(clean, ROTATED))) {
      StateConflictException e = assertThrows(StateConflictException.class, call::run);
      assertEquals(Optional.of(KeyState.COMPROMISED), e.observedState(), e.getMessage());
      assertTrue(e.getMessage().contains("replaceCompromised"), e.getMessage());
    }
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(clean.id()), "nothing was destroyed");
    // The recovery: replace it, then retire from the replacement.
    KeyHandle replacement =
        compromised.replaceCompromised(RevocationReason.keyCompromise("leaked", Instant.now()));
    assertEquals(List.of(clean.id(), newest.id()), replacement.retirementPlan().ids());
  }

  // ---- reconcile(name, plan) ----

  /**
   * The name leads to R -> A when the plan is made. Meanwhile another caller removes the name from
   * A, gives it to an unrelated key U and rotates U to V. The bound reconcile refuses, and U, V and
   * R are as they were.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aNameMovedToAnotherLineageIsNotReconciled(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle r = aes(kms).create();
    // Another caller's Re-key of R at the same moment: two newest keys.
    KeyHandle a = r.rotate();
    String fork = RotationAndNameChoiceTest.reKey(kms, r.id());
    activeOrActivate(kms, s, fork);
    ReconcilePlan plan = kms.keys().reconcilePlan(NAME).orElseThrow();
    String winner = plan.winner().id();
    assertFalse(plan.changesNothing());
    assertTrue(plan.deactivated().stream().anyMatch(k -> k.id().equals(r.id())), plan.toString());
    String u, v;
    try (Kms other = s.connect()) {
      for (String id : List.of(a.id(), fork))
        for (String n : s.names(id)) other.keys().handle(id).removeName(n);
      KeyHandle unrelated = aes(other).create();
      u = unrelated.id();
      v = unrelated.rotate().id();
    }
    int before = mutations(s);
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> kms.keys().reconcile(NAME, plan));
    assertTrue(e.getMessage().contains("not " + winner), e.getMessage());
    assertEquals(before, mutations(s), "nothing was changed");
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(r.id()));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(u));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(v));
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aBoundReconcileDoesWhatThePlanSays(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle r = aes(kms).create();
    KeyHandle a = r.rotate();
    String fork = RotationAndNameChoiceTest.reKey(kms, r.id());
    activeOrActivate(kms, s, fork);
    ReconcilePlan plan = kms.keys().reconcilePlan(NAME).orElseThrow();
    assertEquals(0, RetirementPlanTest.mutations(s), "a plan changes nothing");
    String winner = plan.winner().id();
    String loser = winner.equals(a.id()) ? fork : a.id();
    assertEquals(List.of(loser), plan.joined().stream().map(KeyAttributes::id).toList());
    assertEquals(
        Set.of(r.id(), loser),
        new HashSet<>(plan.deactivated().stream().map(KeyAttributes::id).toList()));
    assertEquals(NAME, plan.name());
    KeyHandle kept = kms.keys().reconcile(NAME, plan);
    assertEquals(winner, kept.id());
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(r.id()));
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(loser));
    assertEquals(List.of(NAME), s.names(winner));
    assertTrue(kms.keys().reconcilePlan(NAME).orElseThrow().changesNothing());
    // Repeating the same plan does what is left: nothing.
    assertEquals(winner, kms.keys().reconcile(NAME, plan).id());
    assertEquals(Optional.empty(), kms.keys().reconcilePlan("no-such-name"));
    assertThrows(IllegalArgumentException.class, () -> kms.keys().reconcile("another", plan));
  }

  /** A key activated after the plan would be deactivated: refused. */
  @Test
  void aBoundReconcileRefusesAKeyActivatedMeanwhile() throws Exception {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    KeyHandle p = aes(kms).createPreActive();
    KeyHandle a = p.rotate();
    String fork = RotationAndNameChoiceTest.reKey(kms, p.id());
    activeOrActivate(kms, s, fork);
    ReconcilePlan plan = kms.keys().reconcilePlan(NAME).orElseThrow();
    assertFalse(
        plan.deactivated().stream().anyMatch(k -> k.id().equals(p.id())),
        "Pre-Active: not planned");
    kms.keys().handle(p.id()).activate();
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> kms.keys().reconcile(NAME, plan));
    assertTrue(e.getMessage().contains("deactivate [" + p.id() + "]"), e.getMessage());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(a.id()));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(fork));
  }

  /** A winner that is not Active is refused by the plan, before anything is shown. */
  @Test
  void aReconcilePlanRefusesACompromisedWinner() throws Exception {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    KeyHandle r = aes(kms).create();
    KeyHandle a = r.rotate();
    a.revoke(RevocationReason.keyCompromise("leaked", Instant.now()));
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> kms.keys().reconcilePlan(NAME));
    assertEquals(Optional.of(KeyState.COMPROMISED), e.observedState());
    assertEquals(0, RotationGraceTest.sent(s, Operation.ADD_ATTRIBUTE));
  }

  /** A reconcile that stops after a deactivation lists it. */
  @Test
  void aStoppedReconcileListsWhatItDeactivated() throws Exception {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    KeyHandle r = aes(kms).create();
    KeyHandle a = r.rotate();
    a.rotate();
    String fork = RotationAndNameChoiceTest.reKey(kms, a.id());
    activeOrActivate(kms, s, fork);
    ReconcilePlan plan = kms.keys().reconcilePlan(NAME).orElseThrow();
    assertEquals(3, plan.deactivated().size(), plan.toString());
    AtomicReference<Integer> revokes = new AtomicReference<>(0);
    s.injectBeforeProcessing(
        req -> {
          if (!RotationAndNameChoiceTest.isOperation(req, Operation.REVOKE)) return null;
          revokes.set(revokes.get() + 1);
          return revokes.get() == 2 ? new java.net.ConnectException("refused (test)") : null;
        });
    PartialCompletionException e =
        assertThrows(PartialCompletionException.class, () -> kms.keys().reconcile(NAME, plan));
    assertEquals(1, e.deactivated().size(), e.getMessage());
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(e.deactivated().get(0).id()));
    // A new plan resumes.
    s.injectBeforeProcessing(null);
    ReconcilePlan rest = kms.keys().reconcilePlan(NAME).orElseThrow();
    assertEquals(2, rest.deactivated().size(), rest.toString());
    kms.keys().reconcile(NAME, rest);
    assertTrue(kms.keys().reconcilePlan(NAME).orElseThrow().changesNothing());
  }

  // ---- conditional rotation bound to the approved key ----

  /**
   * The approval names A. Another caller rotates A to B meanwhile; with an expected current key the
   * call refuses instead of rotating B and scheduling B's deactivation.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aConditionalRotationBoundToAKeyRefusesAnother(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle a = aes(kms).create();
    KeyHandle b;
    try (Kms other = s.connect()) {
      b = kms.keys().handle(other.keys().handle(a.id()).rotate().id());
    }
    int before = mutations(s);
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> a.rotateIfActiveForResult(Duration.ZERO, Rotation.grace(Duration.ofDays(7)), a));
    assertEquals(Optional.of(b.id()), e.objectId());
    assertEquals(before, mutations(s), "nothing was changed");
    assertEquals(2, s.ids().size(), "nothing was rotated");
    assertEquals(Optional.empty(), b.attributes().deactivationDate());
    assertEquals(Optional.empty(), a.attributes().deactivationDate());
    // Bound to the current key: rotated, and its date set.
    RotationResult r =
        a.rotateIfActiveForResult(Duration.ZERO, Rotation.grace(Duration.ofDays(7)), b);
    assertEquals(RotationResult.Outcome.ROTATED, r.outcome());
    assertEquals(b, r.previous());
    assertEquals(r.previousDeactivationDate(), b.attributes().deactivationDate());
    try (Kms other = s.connect()) {
      KeyHandle foreign = other.keys().handle(b.id());
      assertThrows(
          IllegalArgumentException.class,
          () ->
              a.rotateIfActiveForResult(Duration.ZERO, Rotation.of(RotationDates.COPIED), foreign));
    }
  }

  // ---- RECOVERED ----

  /**
   * Just before this call's Re-key, another caller rotates A to B. The server refuses the second
   * Re-key, and the refusal's reply is lost. Reading back finds B, which this call did not make:
   * RECOVERED, not ROTATED.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aReplacementFoundAfterALostReplyIsRecoveredNotRotated(KmipVersion version) {
    InMemoryKmipServer s = server(version).refuseSecondReKey(true);
    Kms other = connect(s);
    AtomicReference<KeyHandle> a = new AtomicReference<>();
    AtomicReference<String> theirs = new AtomicReference<>();
    AtomicBoolean first = new AtomicBoolean(true);
    Kms kms =
        connect(
            s,
            r -> {
              if (!RotationAndNameChoiceTest.isOperation(r, Operation.RE_KEY)
                  || !first.getAndSet(false)) return;
              theirs.set(other.keys().handle(a.get().id()).rotate().id());
              s.failNext(ServerOperation.RE_KEY, Fault.REPLY_LOST);
            });
    a.set(aes(kms).create());
    RotationResult r = a.get().rotateResult(Rotation.grace(Duration.ofDays(7)));
    assertEquals(RotationResult.Outcome.RECOVERED, r.outcome(), r.toString());
    assertEquals(theirs.get(), r.current().id());
    assertEquals(a.get(), r.previous());
    assertEquals(2, s.ids().size(), "only the other caller made a key");
    assertTrue(r.previousDeactivationDate().isPresent(), "the grace period is still scheduled");
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void rotationResultsSayWhatHappened(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle a = aes(kms).create();
    RotationResult r = a.rotateResult(Rotation.grace(Duration.ofDays(7)));
    assertEquals(RotationResult.Outcome.ROTATED, r.outcome());
    assertEquals(a, r.previous());
    assertEquals(r.previousDeactivationDate(), a.attributes().deactivationDate());
    // An old handle: rotateOrLatestResult follows the replacement.
    RotationResult followed = a.rotateOrLatestResult(Rotation.of(RotationDates.COPIED));
    assertEquals(RotationResult.Outcome.FOLLOWED, followed.outcome());
    assertEquals(r.current(), followed.current());
    // A lost reply of a Re-key that took effect: recovered, this call or another made it.
    s.failNext(ServerOperation.RE_KEY, Fault.REPLY_LOST);
    RotationResult lost = r.current().rotateOrLatestResult(Rotation.of(RotationDates.COPIED));
    assertEquals(RotationResult.Outcome.RECOVERED, lost.outcome());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(lost.current().id()));
    assertThrows(
        StateConflictException.class, () -> a.rotateResult(Rotation.of(RotationDates.COPIED)));
  }

  // ---- findOrCreate with refusingPreActive() ----

  /** A staged key is refused, named, and left Pre-Active; once activated it is found. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aStagedKeyIsNotActivatedWithoutApproval(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle staged = aes(kms).createPreActive();
    StateConflictException e =
        assertThrows(
            StateConflictException.class, () -> aes(kms).refusingPreActive().findOrCreateResult());
    assertEquals(Optional.of(staged.id()), e.objectId());
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), e.observedState());
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(staged.id()));
    assertEquals(0, RotationGraceTest.sent(s, Operation.ACTIVATE));
    assertEquals(1, s.ids().size(), "nothing was created");
    staged.activate();
    FindOrCreateResult r = aes(kms).refusingPreActive().findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.FOUND, r.outcome());
    assertEquals(staged, r.key());
    // No key: created and activated as before.
    FindOrCreateResult created =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("fresh")
            .refusingPreActive()
            .findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.CREATED, created.outcome());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(created.key().id()));
    assertThrows(
        IllegalArgumentException.class,
        () -> aes(kms).refusingPreActive().replacingCompromised().findOrCreateResult());
  }

  /**
   * The race: another caller stages a key with the name between this call's look and its Create.
   * The other key ranks first and is Pre-Active: it is not activated, and the key this call made is
   * reported.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aKeyStagedDuringTheCallIsNotActivated(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms other = connect(s);
    AtomicBoolean first = new AtomicBoolean(true);
    AtomicReference<KeyHandle> staged = new AtomicReference<>();
    Kms kms =
        connect(
            s,
            r -> {
              if (RotationAndNameChoiceTest.isOperation(r, Operation.CREATE)
                  && first.getAndSet(false)) staged.set(aes(other).createPreActive());
            });
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> aes(kms).refusingPreActive().findOrCreateResult());
    StateConflictException cause = assertInstanceOf(StateConflictException.class, e.getCause());
    assertEquals(Optional.of(staged.get().id()), cause.objectId());
    assertEquals(1, e.created().size());
    assertNotEquals(staged.get(), e.created().get(0));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(staged.get().id()), "not activated");
  }

  /** A Create whose reply is lost, then found by name, is RECOVERED. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostCreateReplyIsRecovered(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    s.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
    FindOrCreateResult r = aes(kms).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.RECOVERED, r.outcome(), r.toString());
    assertEquals(List.of(), r.created());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(r.key().id()));
  }
}
