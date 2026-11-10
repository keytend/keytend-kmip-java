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
import static dev.keytend.kmip.kms.ScheduledRotationTest.aes;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link KeyHandle#retirementPlan()}, {@link KeyHandle#retirementPlanOlderThan} and {@link
 * KeyHandle#retirePredecessors(RevocationReason, RetirementPlan)}: the plan is the set the
 * retirement destroys, joined branches included; a retirement bound to a plan refuses a lineage
 * that changed; a failure part-way reports what was done.
 */
class RetirementPlanTest {
  static final RevocationReason ROTATED = RevocationReason.superseded("rotated");

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();
  final Map<InMemoryKmipServer, RotationJobTest.TestClock> clocks = new HashMap<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(RotationJobTest.START);
    s.clock(clock);
    clocks.put(s, clock);
    servers.add(s);
    return s;
  }

  Kms connect(InMemoryKmipServer s) {
    return connect(s, r -> {});
  }

  /** A client whose requests {@code before} sees first (to arm a fault for one of them). */
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
    kms.clock(clocks.get(s));
    clients.add(kms);
    return kms;
  }

  /** {@code first} and {@code n} rotations of it, a day apart, oldest first. */
  List<KeyHandle> lineageOf(InMemoryKmipServer s, KeyHandle first, int n) {
    List<KeyHandle> keys = new ArrayList<>(List.of(first));
    for (int i = 0; i < n; i++) {
      RotationJobTest.TestClock clock = clocks.get(s);
      clock.now = clock.now.plus(Duration.ofDays(1));
      keys.add(keys.get(i).rotate());
    }
    return keys;
  }

  /** Requests that deactivate, revoke or destroy anything. */
  static int mutations(InMemoryKmipServer s) {
    return RotationGraceTest.sent(s, Operation.REVOKE)
        + RotationGraceTest.sent(s, Operation.DEACTIVATE)
        + RotationGraceTest.sent(s, Operation.DESTROY);
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void thePlanIsWhatTheRetirementDestroys(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    List<KeyHandle> k = lineageOf(s, aes(kms).create(), 3);
    KeyHandle newest = k.get(3);
    RetirementPlan plan = newest.retirementPlan();
    assertEquals(0, mutations(s), "a plan changes nothing");
    assertEquals(ids(k.subList(0, 3)), plan.ids(), "oldest first");
    assertEquals(plan.ids(), plan.keys().stream().map(KeyAttributes::id).toList());
    assertEquals(newest.id(), plan.newestId());
    assertEquals(Optional.empty(), plan.keepFromId());
    RetirementPlan partial = newest.retirementPlanOlderThan(k.get(2));
    assertEquals(ids(k.subList(0, 2)), partial.ids());
    assertEquals(Optional.of(k.get(2).id()), partial.keepFromId());
    assertEquals(plan.ids(), newest.retirementPlanOlderThan(newest).ids(), "keepFrom == this");

    assertEquals(ids(k.subList(0, 2)), ids(newest.retirePredecessors(ROTATED, partial)));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(k.get(2).id()));
    RetirementPlan rest = newest.retirementPlan();
    assertEquals(List.of(k.get(2).id()), rest.ids(), "destroyed keys are left out");
    assertEquals(List.of(k.get(2).id()), ids(newest.retirePredecessors(ROTATED, rest)));
    assertEquals(List.of(), newest.retirementPlan().ids());
    assertEquals(List.of(), newest.retirePredecessors(ROTATED, newest.retirementPlan()));
  }

  /**
   * Key k0 forked into a and b, reconcile joined one into the other, and the winner was rotated.
   * Keeping from the winner retires k0 and the joined branch; the plan lists both, in the order
   * they are destroyed.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aJoinedBranchIsInThePlan(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version).linkCardinality(false);
    Kms kms = connect(s);
    KeyHandle k0 = aes(kms).create();
    String a = RotationAndNameChoiceTest.reKey(kms, k0.id());
    String b = RotationAndNameChoiceTest.reKey(kms, k0.id());
    KeyHandle winner = k0.reconcile();
    String loser = winner.id().equals(a) ? b : a;
    KeyHandle newest = winner.rotate();
    RetirementPlan plan = newest.retirementPlanOlderThan(winner);
    assertEquals(Set.of(k0.id(), loser), Set.copyOf(plan.ids()), plan.toString());
    assertEquals(loser, plan.ids().get(0), "the joined branch first");
    assertEquals(plan.ids(), ids(newest.retirePredecessors(ROTATED, plan)));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(winner.id()));
  }

  /** A branch that was not reconciled: the plan is refused, as the retirement is; nothing changes. */
  @Test
  void aPlanIsRefusedWhileTheLineageHasOtherNewestKeys() throws Exception {
    InMemoryKmipServer s = server(KmipVersion.V2_1).linkCardinality(false);
    Kms kms = connect(s);
    KeyHandle k0 = aes(kms).create();
    String a = RotationAndNameChoiceTest.reKey(kms, k0.id());
    RotationAndNameChoiceTest.reKey(kms, k0.id());
    StateConflictException refused =
        assertThrows(StateConflictException.class, () -> kms.keys().handle(a).retirementPlan());
    assertTrue(refused.getMessage().contains("reconcile()"), refused.getMessage());
    assertEquals(0, mutations(s));
  }

  /**
   * A plan whose lineage changed before the retirement: another branch was reconciled into it,
   * so the retirement would destroy a key nobody confirmed. It is refused, and nothing is changed.
   */
  @Test
  void aRetirementRefusesKeysThePlanDoesNotList() throws Exception {
    InMemoryKmipServer s = server(KmipVersion.V2_1).linkCardinality(false);
    Kms kms = connect(s);
    List<KeyHandle> k = lineageOf(s, aes(kms).create(), 2);
    KeyHandle newest = k.get(2);
    RetirementPlan plan = newest.retirementPlan();
    assertEquals(ids(k.subList(0, 2)), plan.ids());
    // Another caller re-keys k1 again, and reconcile joins that key into the newest.
    String fork = RotationAndNameChoiceTest.reKey(kms, k.get(1).id());
    KeyHandle winner = newest.reconcile();
    int before = mutations(s);
    assertEquals(newest, winner, "reconcile keeps the planned newest key here");
    StateConflictException refused =
        assertThrows(StateConflictException.class, () -> newest.retirePredecessors(ROTATED, plan));
    assertTrue(refused.getMessage().contains("not planned: [" + fork + "]"), refused.getMessage());
    assertTrue(refused.getMessage().contains("make a new plan"), refused.getMessage());
    assertEquals(before, mutations(s), "nothing was retired");
    assertTrue(s.exists(k.get(0).id()) && s.hasMaterial(k.get(0).id()));
  }

  /** A plan is bound to the key and the Kms that made it. */
  @Test
  void aPlanFromAnotherKeyOrKmsIsRefused() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    List<KeyHandle> k = lineageOf(s, aes(kms).create(), 2);
    RetirementPlan plan = k.get(2).retirementPlan();
    assertThrows(IllegalArgumentException.class, () -> k.get(1).retirePredecessors(ROTATED, plan));
    Kms other = connect(s);
    assertThrows(
        IllegalArgumentException.class,
        () -> other.keys().handle(k.get(2).id()).retirePredecessors(ROTATED, plan));
    assertEquals(0, mutations(s));
  }

  /**
   * The first key is destroyed, then the next one's Destroy is refused. The failure says what was
   * done: one key destroyed, one deactivated; the cause is the refusal. Repeating with the same
   * plan finishes it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRetirementThatStopsPartWaySaysWhatItDid(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicReference<String> failDestroyOf = new AtomicReference<>();
    Kms kms =
        connect(
            s,
            r -> {
              String id = failDestroyOf.get();
              if (id != null
                  && RotationAndNameChoiceTest.isOperation(r, Operation.DESTROY)
                  && RotationGraceTest.names(r, id)) {
                failDestroyOf.set(null);
                s.failNext(ServerOperation.DESTROY, Fault.PERMISSION_DENIED);
              }
            });
    List<KeyHandle> k = lineageOf(s, aes(kms).create(), 3);
    KeyHandle newest = k.get(3);
    RetirementPlan plan = newest.retirementPlan();
    failDestroyOf.set(k.get(1).id());
    PartialCompletionException partial =
        assertThrows(
            PartialCompletionException.class, () -> newest.retirePredecessors(ROTATED, plan));
    assertInstanceOf(PermissionDeniedException.class, partial.getCause());
    assertEquals(List.of(k.get(0).id()), ids(partial.destroyed()));
    assertEquals(List.of(k.get(1).id()), ids(partial.deactivated()));
    assertEquals(List.of(), partial.created());
    assertEquals(Optional.of(k.get(1).id()), partial.objectId());
    assertEquals(KmsException.Category.PARTIAL, partial.category());
    assertFalse(partial.retryable());
    assertTrue(partial.getMessage().contains("repeat retirePredecessors()"), partial.getMessage());
    assertEquals(Optional.of(KeyState.DESTROYED), s.state(k.get(0).id()));
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(k.get(1).id()));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(k.get(2).id()));

    assertEquals(ids(k.subList(1, 3)), ids(newest.retirePredecessors(ROTATED, plan)));
    assertEquals(Optional.of(KeyState.DESTROYED), s.state(k.get(2).id()));
  }

  /** A failure before any key changed is the failure itself, not a partial completion. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aFailureBeforeAnyChangeIsNotPartial(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    List<KeyHandle> k = lineageOf(s, aes(kms).create(), 2);
    s.failNext(DeactivationTest.retiring(version), Fault.SERVER_FAILURE);
    assertThrows(ServerFailureException.class, () -> k.get(2).retirePredecessors(ROTATED));
    s.failNext(DeactivationTest.retiring(version), Fault.SERVER_FAILURE);
    assertThrows(ServerFailureException.class, () -> k.get(2).deactivatePredecessors());
  }

  /** deactivatePredecessors reports the keys it deactivated before a later one failed. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aDeactivationThatStopsPartWaySaysWhatItDid(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicReference<String> failOf = new AtomicReference<>();
    Operation retiring = DeactivationTest.retiringOperation(version);
    Kms kms =
        connect(
            s,
            r -> {
              String id = failOf.get();
              if (id != null
                  && RotationAndNameChoiceTest.isOperation(r, retiring)
                  && RotationGraceTest.names(r, id)) {
                failOf.set(null);
                s.failNext(DeactivationTest.retiring(version), Fault.SERVER_FAILURE);
              }
            });
    List<KeyHandle> k = lineageOf(s, aes(kms).create(), 2);
    failOf.set(k.get(1).id());
    PartialCompletionException partial =
        assertThrows(PartialCompletionException.class, () -> k.get(2).deactivatePredecessors());
    assertEquals(List.of(k.get(0).id()), ids(partial.deactivated()));
    assertEquals(List.of(), partial.destroyed());
    assertInstanceOf(ServerFailureException.class, partial.getCause());
    assertEquals(List.of(k.get(1).id()), ids(k.get(2).deactivatePredecessors()));
  }

  /**
   * 65 rotations are more than one listing reaches from the newest key, but a plan that keeps from
   * the middle walks from there, as the retirement does.
   */
  @Test
  void aPlanOlderThanAMiddleKeyReachesALongLineage() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    List<KeyHandle> k = lineageOf(s, aes(kms).create(), 65);
    KeyHandle newest = k.get(65);
    assertThrows(UnsupportedException.class, newest::lineage);
    assertThrows(UnsupportedException.class, newest::retirementPlan);
    RetirementPlan plan = newest.retirementPlanOlderThan(k.get(33));
    assertEquals(ids(k.subList(0, 33)), plan.ids());
    assertEquals(plan.ids(), ids(newest.retirePredecessors(ROTATED, plan)));
    assertEquals(ids(k.subList(33, 65)), newest.retirementPlan().ids(), "now within reach");
  }
}
