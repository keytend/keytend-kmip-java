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

import dev.keytend.kmip.model.Enums.ResultReason;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * A plan-bound compromise replacement acts on the keys its plan names and on no other, also when it
 * recovers after a lost reply, and never takes a search that could not tell for "none" (servers
 * that refuse a search, ignore its filter, or cap what they return). Each case builds one shape of
 * lineage (linear or forked; Pre-Active, Active, Compromised or Deactivated newest keys; names on
 * one branch or another), may change it while the plan waits or lose a reply at one step, and then
 * checks every object on the server: an object that changed is one the confirmed plan names, and
 * the call created exactly the keys the plan says. Forks are made with Re-key on a server that does
 * not enforce one link of each kind. Faults are armed from the client's transport as the requests
 * go out, so each case is deterministic.
 */
class CompromiseLineageCasesTest {
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

  /** A server that keeps any number of links of a kind (a fork), whose Re-key leaves Pre-Active keys. */
  InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer s =
        InMemoryKmipServer.of(version).linkCardinality(false).freshDatesOnReKey(true);
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

  static RevocationReason compromise(Instant since) {
    return RevocationReason.keyCompromise("leaked", since);
  }

  static boolean is(Ttlv request, Operation operation) {
    return RotationAndNameChoiceTest.isOperation(request, operation);
  }

  static String uid(Ttlv request) {
    return ConcurrentReplacementInterleavingsTest.uid(request);
  }

  // ---- the lineage shapes ----

  /** One newest key of a lineage: its state and its name (null: none). */
  record Tip(KeyState state, String name) {}

  static Tip tip(KeyState state) {
    return new Tip(state, null);
  }

  static Tip named(KeyState state, String name) {
    return new Tip(state, name);
  }

  /** The key {@code key} and the newest keys descending from it, {@code tips}, as made. */
  record Lineage(KeyHandle key, List<String> tips) {
    String tip(int i) {
      return tips.get(i);
    }
  }

  /**
   * A key named {@link #NAME}, Compromised when {@code compromised} says so (with the date {@link
   * #THEIRS}) and Active otherwise, then re-keyed once per {@code tips} (a fork when there are
   * several), each newest key then given its state and name.
   */
  static Lineage lineage(Kms kms, boolean compromised, Tip... tips) throws Exception {
    KeyHandle key =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named(NAME).create();
    // Revoked first: the server's Re-key of a Compromised key leaves a Pre-Active replacement.
    if (compromised) key.revoke(compromise(THEIRS));
    else if (tips.length > 0) throw new IllegalArgumentException("an Active key with replacements");
    List<String> ids = new ArrayList<>();
    for (int i = 0; i < tips.length; i++) ids.add(RotationAndNameChoiceTest.reKey(kms, key.id()));
    // The names as the case says: off every key first (a server may keep names unique).
    List<String> all = new ArrayList<>(ids);
    all.add(key.id());
    for (String id : all)
      for (String n : kms.keys().handle(id).attributes().names())
        kms.keys().handle(id).removeName(n);
    key.addName(NAME);
    for (int i = 0; i < tips.length; i++) {
      KeyHandle t = kms.keys().handle(ids.get(i));
      if (tips[i].name() != null) t.addName(tips[i].name());
      switch (tips[i].state()) {
        case PRE_ACTIVE -> {}
        case ACTIVE -> t.activate();
        case COMPROMISED -> t.revoke(compromise(LATER));
        case DEACTIVATED -> {
          t.activate();
          t.deactivate();
        }
        default -> throw new IllegalArgumentException(tips[i].toString());
      }
    }
    return new Lineage(key, List.copyOf(ids));
  }

  // ---- the invariant ----

  /** Each object's state and every attribute, as the server holds them. */
  static Map<String, String> objects(InMemoryKmipServer s) {
    Map<String, String> out = new TreeMap<>();
    for (String id : s.ids())
      out.put(
          id, s.state(id).map(Object::toString).orElse("gone") + " " + s.protocolAttributes(id));
    return out;
  }

  /** The keys the plan names as acted on: the only ones the call may change. */
  static Set<String> actedOn(CompromisePlan plan) {
    Set<String> out = new TreeSet<>();
    out.add(plan.key().id());
    plan.existingReplacement().ifPresent(k -> out.add(k.id()));
    plan.replacedInTurn().ifPresent(k -> out.add(k.id()));
    out.addAll(plan.unfinishedNameMoves().keySet());
    return out;
  }

  /**
   * Asserts that of the objects {@code before} lists, only those {@code plan} acts on changed,
   * and that {@code created} objects were added; returns those.
   */
  static Set<String> onlyPlanned(
      InMemoryKmipServer s, Map<String, String> before, CompromisePlan plan, int created) {
    Map<String, String> after = objects(s);
    Set<String> added = new TreeSet<>(after.keySet());
    added.removeAll(before.keySet());
    assertEquals(created, added.size(), "objects created: " + added + "; plan " + plan);
    Set<String> allowed = actedOn(plan);
    for (var e : before.entrySet())
      if (!e.getValue().equals(after.get(e.getKey())))
        assertTrue(
            allowed.contains(e.getKey()),
            e.getKey() + " changed, and the plan does not act on it: " + plan);
    return added;
  }

  static List<String> ids(List<KeyHandle> keys) {
    return keys.stream().map(KeyHandle::id).toList();
  }

  // ---- linear lineages ----

  /** No replacement: the key is revoked and replaced; nothing else exists to change. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anActiveKeyWithoutReplacementIsRevokedAndReplaced(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, false);
    KeyHandle bystander = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
    CompromisePlan plan = l.key().compromisePlan();
    assertTrue(plan.revokes() && plan.creates(), plan.toString());
    assertEquals(List.of(), plan.otherDescendants());
    Map<String, String> before = objects(s);
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), plan);
    assertEquals(CompromiseResult.Outcome.REPLACED, r.outcome());
    Set<String> made = onlyPlanned(s, before, plan, 1);
    assertEquals(Set.of(r.replacement().id()), made);
    assertFalse(actedOn(plan).contains(bystander.id()));
  }

  /** One Active replacement: finished with, nothing created. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void oneActiveReplacementIsFinishedWith(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true, tip(KeyState.ACTIVE));
    CompromisePlan plan = l.key().compromisePlan();
    assertEquals(l.tip(0), plan.existingReplacement().orElseThrow().id());
    Map<String, String> before = objects(s);
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), plan);
    assertEquals(CompromiseResult.Outcome.EXISTING, r.outcome());
    onlyPlanned(s, before, plan, 0);
    assertEquals(List.of(NAME), s.names(l.tip(0)));
  }

  /** One Pre-Active replacement: activated and named, nothing created. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void onePreActiveReplacementIsActivated(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true, tip(KeyState.PRE_ACTIVE));
    CompromisePlan plan = l.key().compromisePlan();
    Map<String, String> before = objects(s);
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), plan);
    assertEquals(CompromiseResult.Outcome.EXISTING, r.outcome());
    onlyPlanned(s, before, plan, 0);
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(l.tip(0)));
  }

  /** One Compromised replacement: replaced in turn, one key created. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void oneCompromisedReplacementIsReplacedInTurn(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true, named(KeyState.COMPROMISED, "b"));
    CompromisePlan plan = l.key().compromisePlan();
    assertEquals(l.tip(0), plan.replacedInTurn().orElseThrow().id());
    assertTrue(plan.creates());
    Map<String, String> before = objects(s);
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), plan);
    assertEquals(List.of(l.tip(0)), ids(r.replacedInTurn()));
    onlyPlanned(s, before, plan, 1);
    assertEquals(Set.of(NAME, "b"), Set.copyOf(s.names(r.replacement().id())));
  }

  /** One Deactivated replacement: refused by the plan, nothing changed. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void oneDeactivatedReplacementIsRefused(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true, tip(KeyState.DEACTIVATED));
    Map<String, String> before = objects(s);
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> l.key().compromisePlan());
    assertEquals(Optional.of(l.tip(0)), e.objectId());
    assertEquals(before, objects(s));
  }

  // ---- forked lineages ----

  /**
   * Two Pre-Active replacements. The plan finishes with the first, and names the second as left
   * alone; the call activates the first only.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void ofTwoPreActiveReplacementsOnlyThePlannedOneIsActivated(KmipVersion version)
      throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true, tip(KeyState.PRE_ACTIVE), tip(KeyState.PRE_ACTIVE));
    CompromisePlan plan = l.key().compromisePlan();
    assertEquals(l.tip(0), plan.existingReplacement().orElseThrow().id(), "the earliest");
    assertEquals(
        List.of(l.tip(1)), plan.otherDescendants().stream().map(KeyAttributes::id).toList());
    Map<String, String> before = objects(s);
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), plan);
    assertEquals(l.tip(0), r.replacement().id());
    onlyPlanned(s, before, plan, 0);
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(l.tip(0)));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(l.tip(1)), "left as it was");
  }

  /** An Active named replacement and a Pre-Active branch; the branch stays Pre-Active. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aPreActiveBranchBesideTheActiveReplacementIsLeftAlone(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true, named(KeyState.ACTIVE, "inc"), tip(KeyState.PRE_ACTIVE));
    CompromisePlan plan = l.key().compromisePlan();
    assertEquals(l.tip(0), plan.existingReplacement().orElseThrow().id());
    assertEquals(l.tip(1), plan.otherDescendants().get(0).id());
    Map<String, String> before = objects(s);
    l.key().replaceCompromisedResult(compromise(MINE), plan);
    onlyPlanned(s, before, plan, 0);
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(l.tip(1)));
  }

  /** The unbound form makes the same choice and activates no other branch either. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theUnboundFormActivatesOnlyTheKeyItFinishesWith(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true, tip(KeyState.PRE_ACTIVE), tip(KeyState.PRE_ACTIVE));
    CompromisePlan plan = l.key().compromisePlan();
    Map<String, String> before = objects(s);
    KeyHandle replacement = l.key().replaceCompromised(compromise(MINE));
    assertEquals(plan.existingReplacement().orElseThrow().id(), replacement.id());
    onlyPlanned(s, before, plan, 0);
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(l.tip(1)));
  }

  /**
   * A name move an earlier call stopped part-way, recorded on the other branch (the name on no
   * key): the plan names it, and the call finishes it, giving the name to its replacement and
   * removing the record; the branch is otherwise left as it is.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aNameMoveRecordedOnAnotherBranchIsInThePlanAndFinished(KmipVersion version)
      throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true, named(KeyState.ACTIVE, "b"), tip(KeyState.PRE_ACTIVE));
    kms.keys().handle(l.tip(1)).setCustomAttribute(KeyHandle.pendingName("stray"), "stray");
    CompromisePlan plan = l.key().compromisePlan();
    assertEquals(l.tip(0), plan.existingReplacement().orElseThrow().id());
    assertEquals(Map.of(l.tip(1), List.of("stray")), plan.unfinishedNameMoves());
    Map<String, String> before = objects(s);
    l.key().replaceCompromisedResult(compromise(MINE), plan);
    onlyPlanned(s, before, plan, 0);
    assertTrue(s.names(l.tip(0)).contains("stray"), "given to the replacement");
    assertEquals(
        List.of(), KeyHandle.pendingNames(kms.keys().handle(l.tip(1)).attributes()), "removed");
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(l.tip(1)), "otherwise as it was");
  }

  /** A name move recorded while the plan waits is not the plan's: refused, nothing changed. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aNameMoveRecordedWhileThePlanWaitsIsRefused(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s), other = connect(s);
    Lineage l = lineage(kms, true, named(KeyState.ACTIVE, "b"), tip(KeyState.PRE_ACTIVE));
    CompromisePlan plan = l.key().compromisePlan();
    assertEquals(Map.of(), plan.unfinishedNameMoves());
    other.keys().handle(l.tip(1)).setCustomAttribute(KeyHandle.pendingName("stray"), "stray");
    Map<String, String> before = objects(s);
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> l.key().replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(StateConflictException.Conflict.NOT_AS_PLANNED, e.conflict(), e.getMessage());
    assertEquals(before, objects(s));
  }

  /** An Active replacement and a Compromised branch: the Active one, the other untouched. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aCompromisedBranchBesideAnActiveReplacementIsNotReplaced(KmipVersion version)
      throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true, named(KeyState.COMPROMISED, "b"), tip(KeyState.ACTIVE));
    CompromisePlan plan = l.key().compromisePlan();
    assertEquals(l.tip(1), plan.existingReplacement().orElseThrow().id(), "Active first");
    assertEquals(Optional.empty(), plan.replacedInTurn());
    Map<String, String> before = objects(s);
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), plan);
    assertEquals(List.of(), r.replacedInTurn());
    onlyPlanned(s, before, plan, 0);
  }

  /** An Active replacement and a Deactivated branch: the Active one, the other untouched. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aDeactivatedBranchBesideAnActiveReplacementIsLeftAlone(KmipVersion version)
      throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true, tip(KeyState.DEACTIVATED), tip(KeyState.ACTIVE));
    CompromisePlan plan = l.key().compromisePlan();
    assertEquals(l.tip(1), plan.existingReplacement().orElseThrow().id());
    Map<String, String> before = objects(s);
    l.key().replaceCompromisedResult(compromise(MINE), plan);
    onlyPlanned(s, before, plan, 0);
  }

  /** Two Compromised replacements: the named one is replaced in turn, the other untouched. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void ofTwoCompromisedReplacementsOnlyThePlannedOneIsReplacedInTurn(KmipVersion version)
      throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true, tip(KeyState.COMPROMISED), named(KeyState.COMPROMISED, "b"));
    CompromisePlan plan = l.key().compromisePlan();
    assertEquals(l.tip(1), plan.replacedInTurn().orElseThrow().id(), "the one with names");
    Map<String, String> before = objects(s);
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), plan);
    assertEquals(List.of(l.tip(1)), ids(r.replacedInTurn()));
    onlyPlanned(s, before, plan, 1);
  }

  /**
   * The second case: a Pre-Active replacement without names and a Compromised one with a name. The
   * plan finishes with the Pre-Active one and creates nothing. Its Activate is refused: the call
   * stops there; it never replaces the Compromised one instead, and creates nothing.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRefusedActivationOfThePlannedKeyStopsTheCall(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    AtomicReference<String> refuse = new AtomicReference<>();
    Kms kms =
        connect(
            s,
            r -> {
              if (is(r, Operation.ACTIVATE) && uid(r).equals(refuse.get()))
                s.failNext(ServerOperation.ACTIVATE, Fault.PERMISSION_DENIED);
            });
    Lineage l = lineage(kms, true, tip(KeyState.PRE_ACTIVE), named(KeyState.COMPROMISED, "c"));
    CompromisePlan plan = l.key().compromisePlan();
    assertEquals(l.tip(0), plan.existingReplacement().orElseThrow().id());
    assertFalse(plan.creates());
    refuse.set(l.tip(0));
    Map<String, String> before = objects(s);
    KmsException e =
        assertThrows(
            KmsException.class, () -> l.key().replaceCompromisedResult(compromise(MINE), plan));
    assertInstanceOf(
        PermissionDeniedException.class,
        e instanceof PartialCompletionException ? e.getCause() : e,
        e.getMessage());
    onlyPlanned(s, before, plan, 0);
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(l.tip(1)));
    assertEquals(List.of("c"), s.names(l.tip(1)));
  }

  // ---- the lineage changes while the plan waits ----

  /**
   * The first case: two Compromised replacements, the plan replacing the named one. The name moves
   * to the other while the plan waits, which would change the choice: refused, nothing changed.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aNameMovedBetweenBranchesWhileThePlanWaitsIsRefused(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s), other = connect(s);
    Lineage l = lineage(kms, true, named(KeyState.COMPROMISED, "b"), tip(KeyState.COMPROMISED));
    CompromisePlan plan = l.key().compromisePlan();
    assertEquals(l.tip(0), plan.replacedInTurn().orElseThrow().id());
    other.keys().handle(l.tip(0)).allowingCompromised().removeName("b");
    other.keys().handle(l.tip(1)).allowingCompromised().addName("b");
    Map<String, String> before = objects(s);
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> l.key().replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(StateConflictException.Conflict.NOT_AS_PLANNED, e.conflict(), e.getMessage());
    assertEquals(before, objects(s), "nothing changed");
  }

  /** A branch activated while the plan waits: its state differs, so the plan is refused. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aBranchActivatedWhileThePlanWaitsIsRefused(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s), other = connect(s);
    Lineage l = lineage(kms, true, named(KeyState.ACTIVE, "b"), tip(KeyState.PRE_ACTIVE));
    CompromisePlan plan = l.key().compromisePlan();
    other.keys().handle(l.tip(1)).activate();
    Map<String, String> before = objects(s);
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> l.key().replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(StateConflictException.Conflict.NOT_AS_PLANNED, e.conflict());
    assertEquals(before, objects(s));
  }

  /** A new branch (another caller's Re-key) while the plan waits: refused, nothing changed. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aForkMadeWhileThePlanWaitsIsRefused(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s), other = connect(s);
    Lineage l = lineage(kms, true, tip(KeyState.ACTIVE));
    CompromisePlan plan = l.key().compromisePlan();
    RotationAndNameChoiceTest.reKey(other, l.key().id());
    Map<String, String> before = objects(s);
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> l.key().replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(StateConflictException.Conflict.NOT_AS_PLANNED, e.conflict());
    assertEquals(before, objects(s));
  }

  /** A name given to the key itself while the plan waits: the call would move it, so it refuses. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aNameGivenToTheKeyWhileThePlanWaitsIsRefused(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s), other = connect(s);
    Lineage l = lineage(kms, true, tip(KeyState.ACTIVE));
    CompromisePlan plan = l.key().compromisePlan();
    other.keys().handle(l.key().id()).allowingCompromised().addName("extra");
    Map<String, String> before = objects(s);
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> l.key().replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(StateConflictException.Conflict.NOT_AS_PLANNED, e.conflict());
    assertTrue(e.getMessage().contains("extra"), e.getMessage());
    assertEquals(before, objects(s));
  }

  /**
   * Another caller re-keys the key after the comparison, between this call's Revoke and its
   * Re-key, on a server that refuses a second Re-key. The bound call stops rather than finish with
   * that key, which the plan does not name; the unbound call finishes with it (documented).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anotherCallersReplacementAfterTheComparisonStopsTheBoundCall(KmipVersion version)
      throws Exception {
    for (boolean bound : List.of(true, false)) {
      InMemoryKmipServer s = server(version).refuseSecondReKey(true);
      Kms other = connect(s);
      AtomicReference<String> target = new AtomicReference<>();
      AtomicReference<String> theirs = new AtomicReference<>();
      AtomicReference<Map<String, String>> theirsThen = new AtomicReference<>();
      Kms kms =
          connect(
              s,
              r -> {
                if (is(r, Operation.RE_KEY) && uid(r).equals(target.get()) && theirs.get() == null)
                  try {
                    theirs.set(RotationAndNameChoiceTest.reKey(other, target.get()));
                    theirsThen.set(Map.of(theirs.get(), objects(s).get(theirs.get())));
                  } catch (Exception e) {
                    throw new IllegalStateException(e);
                  }
              });
      Lineage l = lineage(kms, false);
      CompromisePlan plan = l.key().compromisePlan();
      assertTrue(plan.creates());
      target.set(l.key().id());
      if (bound) {
        Map<String, String> before = objects(s);
        PartialCompletionException e =
            assertThrows(
                PartialCompletionException.class,
                () -> l.key().replaceCompromisedResult(compromise(MINE), plan));
        StateConflictException cause = assertInstanceOf(StateConflictException.class, e.getCause());
        assertEquals(StateConflictException.Conflict.NOT_AS_PLANNED, cause.conflict());
        assertEquals(List.of(l.key().id()), ids(e.deactivated()), e.getMessage());
        assertEquals(List.of(), e.created());
        // Theirs is exactly as their Re-key left it: not activated, not named by this call.
        assertEquals(theirsThen.get().get(theirs.get()), objects(s).get(theirs.get()));
        before.put(theirs.get(), theirsThen.get().get(theirs.get()));
        onlyPlanned(s, before, plan, 0);
      } else {
        KeyHandle r = l.key().replaceCompromised(compromise(MINE));
        assertEquals(theirs.get(), r.id(), "the unbound form finishes with it");
        assertEquals(Optional.of(KeyState.ACTIVE), s.state(theirs.get()));
      }
    }
  }

  // ---- lost replies at each step ----

  /** A lost Revoke reply, read back: recovered; the call still acts only on the planned keys. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostRevokeChangesOnlyThePlannedKeys(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, false);
    CompromisePlan plan = l.key().compromisePlan();
    Map<String, String> before = objects(s);
    s.failNext(ServerOperation.REVOKE, Fault.REPLY_LOST);
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), plan);
    assertEquals(CompromiseResult.Outcome.RECOVERED, r.outcome());
    onlyPlanned(s, before, plan, 1);
  }

  /**
   * A lost Re-key reply. Reading back finds a replacement, which this call's Re-key or another
   * caller's made: the plan-bound call cannot tell which, so it activates, links and names nothing
   * and stops with the unknown outcome (nothing else of its own changed: the keys were Compromised
   * already). A new plan shows the key, and finishes with it once approved.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostReKeyStopsTheBoundCallAndANewPlanShowsTheKey(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true, named(KeyState.COMPROMISED, "b"), tip(KeyState.COMPROMISED));
    CompromisePlan plan = l.key().compromisePlan();
    Map<String, String> before = objects(s);
    s.failNext(ServerOperation.RE_KEY, Fault.REPLY_LOST);
    OutcomeUnknownException e =
        assertThrows(
            OutcomeUnknownException.class,
            () -> l.key().replaceCompromisedResult(compromise(MINE), plan));
    Set<String> made = onlyPlanned(s, before, plan, 1);
    String r = made.iterator().next();
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(r), "not activated");
    assertEquals(List.of("b"), s.names(r), "only the name the server's own Re-key moved");
    assertTrue(e.getMessage().contains(r), e.getMessage());
    assertTrue(e.getMessage().contains("make a new compromisePlan()"), e.getMessage());
    assertEquals(Optional.of(l.tip(0)), e.objectId(), "the key whose Re-key was lost");

    CompromisePlan again = l.key().compromisePlan();
    assertEquals(r, again.existingReplacement().orElseThrow().id(), again.toString());
    Map<String, String> next = objects(s);
    CompromiseResult done = l.key().replaceCompromisedResult(compromise(MINE), again);
    assertEquals(CompromiseResult.Outcome.EXISTING, done.outcome(), done.toString());
    onlyPlanned(s, next, again, 0);
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(r));
  }

  /**
   * The existing replacement's Activate reply is lost, and it reads back Active. The result is
   * RECOVERED from that Activate, which names the replacement; the fork's other branch is left
   * alone.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostActivationOfTheExistingReplacementIsRecovered(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    AtomicReference<String> lose = new AtomicReference<>();
    Kms kms =
        connect(
            s,
            r -> {
              if (is(r, Operation.ACTIVATE) && uid(r).equals(lose.get()))
                s.failNext(ServerOperation.ACTIVATE, Fault.REPLY_LOST);
            });
    Lineage l = lineage(kms, true, tip(KeyState.PRE_ACTIVE), tip(KeyState.PRE_ACTIVE));
    CompromisePlan plan = l.key().compromisePlan();
    lose.set(l.tip(0));
    Map<String, String> before = objects(s);
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), plan);
    assertEquals(CompromiseResult.Outcome.RECOVERED, r.outcome(), r.toString());
    assertEquals(Optional.of(l.tip(0)), r.recoveredFrom().orElseThrow().objectId());
    assertEquals(List.of(), r.created());
    onlyPlanned(s, before, plan, 0);
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(l.tip(1)));
  }

  /**
   * The server refuses Re-key, and a name move's reply is lost (read back): recovered, with the
   * fallback key only.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostLinkReplyChangesOnlyThePlannedKeys(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    AtomicBoolean armed = new AtomicBoolean(), created = new AtomicBoolean();
    AtomicBoolean lost = new AtomicBoolean();
    Kms kms =
        connect(
            s,
            r -> {
              if (!armed.get()) return;
              if (is(r, Operation.CREATE)) created.set(true);
              else if (created.get() && is(r, Operation.ADD_ATTRIBUTE) && !lost.getAndSet(true))
                s.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.REPLY_LOST);
            });
    Lineage l = lineage(kms, true);
    CompromisePlan plan = l.key().compromisePlan();
    armed.set(true);
    Map<String, String> before = objects(s);
    s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), plan);
    assertTrue(lost.get(), "a link's reply was lost");
    onlyPlanned(s, before, plan, 1);
    assertEquals(List.of(r.replacement().id()), s.links(l.key().id(), LinkKind.REPLACEMENT));
  }

  // ---- a lost fallback Create is found, never made twice ----

  /**
   * Re-key refused, and the fallback Create's reply is lost. The key it made is found by the
   * temporary name only this call gave it, and linked in the same call: RECOVERED, one key on the
   * server, not two.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostFallbackCreateIsFoundAndLinked(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, false);
    CompromisePlan plan = l.key().compromisePlan();
    Map<String, String> before = objects(s);
    s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
    s.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), plan);
    assertEquals(CompromiseResult.Outcome.RECOVERED, r.outcome(), r.toString());
    assertTrue(r.revoked());
    assertEquals(List.of(), r.created(), "the Create's reply did not confirm it");
    assertEquals(Optional.empty(), r.recoveredFrom().orElseThrow().objectId());
    Set<String> made = onlyPlanned(s, before, plan, 1);
    assertEquals(Set.of(r.replacement().id()), made);
    assertEquals(List.of(r.replacement().id()), s.links(l.key().id(), LinkKind.REPLACEMENT));
    assertEquals(List.of(NAME), s.names(r.replacement().id()));
  }

  /**
   * Re-key refused, the fallback Create's reply lost, and the search for the key it made fails too.
   * The call stops with the revocation kept and advice that gives the call's token and says to look
   * the key up before repeating. The next plan refuses, naming that key, so a second key is never
   * made beside it; once it is dealt with (destroyed here: it was never activated), a new plan
   * creates the replacement.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aPlanAfterAnUnfoundLostCreateRefusesNamingThatKey(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    AtomicBoolean createLost = new AtomicBoolean(), searching = new AtomicBoolean();
    Kms kms =
        connect(
            s,
            r -> {
              // The Create's reply is lost, then the reply to the search for the key it made.
              if (is(r, Operation.CREATE) && createLost.getAndSet(false)) {
                s.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
                searching.set(true);
              } else if (is(r, Operation.LOCATE) && searching.getAndSet(false))
                s.failNext(ServerOperation.LOCATE, Fault.REPLY_LOST);
            });
    Lineage l = lineage(kms, false);
    CompromisePlan plan = l.key().compromisePlan();
    s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
    createLost.set(true);
    int objects = s.ids().size();
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> l.key().replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(List.of(l.key().id()), ids(e.deactivated()));
    assertEquals(List.of(), e.created());
    assertInstanceOf(OutcomeUnknownException.class, e.getCause());
    assertEquals(objects + 1, s.ids().size(), "the lost Create made a key");
    String orphan =
        s.ids().stream().filter(id -> !id.equals(l.key().id())).reduce((a, b) -> b).orElseThrow();
    String temporary = s.names(orphan).get(0);
    assertTrue(temporary.startsWith(KeyHandle.TEMPORARY), temporary);
    assertTrue(e.getMessage().contains(temporary), e.getMessage());
    assertTrue(e.getMessage().contains("could not be searched"), e.getMessage());
    assertTrue(e.getMessage().contains("before you repeat"), e.getMessage());
    assertFalse(e.getMessage().contains("did not take effect"), e.getMessage());
    assertEquals(List.of(), s.links(l.key().id(), LinkKind.REPLACEMENT), "not linked");

    Map<String, String> before = objects(s);
    StateConflictException refused =
        assertThrows(StateConflictException.class, () -> l.key().compromisePlan());
    assertEquals(StateConflictException.Conflict.UNLINKED_REPLACEMENT, refused.conflict());
    assertEquals(Optional.of(orphan), refused.objectId(), refused.getMessage());
    assertTrue(refused.getMessage().contains("destroy " + orphan), refused.getMessage());
    assertEquals(before, objects(s), "nothing changed");

    kms.keys().handle(orphan).destroy();
    CompromisePlan again = l.key().compromisePlan();
    assertTrue(again.creates());
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), again);
    assertEquals(CompromiseResult.Outcome.COMPLETED, r.outcome(), r.toString());
    assertEquals(List.of(r.replacement().id()), s.links(l.key().id(), LinkKind.REPLACEMENT));
  }

  /**
   * The same with the unbound form on a key Compromised already: nothing else changed, so the lost
   * Create is an unknown outcome, with the same advice and temporary name.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anUnboundLostCreateThatCannotBeFoundGivesItsName(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    AtomicBoolean createLost = new AtomicBoolean(), searching = new AtomicBoolean();
    Kms kms =
        connect(
            s,
            r -> {
              if (is(r, Operation.CREATE) && createLost.getAndSet(false)) {
                s.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
                searching.set(true);
              } else if (is(r, Operation.LOCATE) && searching.getAndSet(false))
                s.failNext(ServerOperation.LOCATE, Fault.REPLY_LOST);
            });
    Lineage l = lineage(kms, true);
    s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
    createLost.set(true);
    OutcomeUnknownException e =
        assertThrows(
            OutcomeUnknownException.class, () -> l.key().replaceCompromised(compromise(MINE)));
    String orphan =
        s.ids().stream().filter(id -> !id.equals(l.key().id())).reduce((a, b) -> b).orElseThrow();
    String temporary = s.names(orphan).get(0);
    assertTrue(temporary.startsWith(KeyHandle.TEMPORARY), temporary);
    assertTrue(e.getMessage().contains(temporary), e.getMessage());
    assertTrue(e.getMessage().contains("an unbound repeat would create another"), e.getMessage());
    assertEquals(Optional.empty(), e.objectId());
  }

  /** An earlier call's unlinked key for the descendant replaced in turn: the plan refuses too. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anUnlinkedKeyForTheDescendantReplacedInTurnIsRefused(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true, named(KeyState.COMPROMISED, "b"));
    KeyHandle orphan =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .custom(KeyHandle.REPLACEMENT_OF, l.tip(0))
            .createPreActive();
    Map<String, String> before = objects(s);
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> l.key().compromisePlan());
    assertEquals(StateConflictException.Conflict.UNLINKED_REPLACEMENT, e.conflict());
    assertEquals(Optional.of(orphan.id()), e.objectId(), e.getMessage());
    assertEquals(before, objects(s));
  }

  /**
   * An unlinked key that appears while the plan waits, which the plan's search did not find:
   * another caller's, being made now, most likely. The bound call refuses as not as planned,
   * nothing changed, and never advises destroying it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anUnlinkedKeyMadeWhileThePlanWaitsIsRefused(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true);
    CompromisePlan plan = l.key().compromisePlan();
    assertTrue(plan.creates());
    kms.keys()
        .createAes(256)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .custom(KeyHandle.REPLACEMENT_OF, l.key().id())
        .createPreActive();
    Map<String, String> before = objects(s);
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> l.key().replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(StateConflictException.Conflict.NOT_AS_PLANNED, e.conflict(), e.getMessage());
    assertFalse(e.getMessage().contains("destroy"), e.getMessage());
    assertTrue(e.getMessage().contains("another caller is likely replacing"), e.getMessage());
    assertEquals(before, objects(s));
  }

  /**
   * An Active unlinked key with the record (the server refused an earlier call's links, which
   * said to use it): the plan refuses and says to use it, never to destroy it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anActiveUnlinkedKeyIsRefusedWithoutAdviceToDestroyIt(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Lineage l = lineage(kms, true);
    KeyHandle used =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .custom(KeyHandle.REPLACEMENT_OF, l.key().id())
            .create();
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> l.key().compromisePlan());
    assertEquals(StateConflictException.Conflict.UNLINKED_REPLACEMENT, e.conflict());
    assertEquals(Optional.of(used.id()), e.objectId());
    assertFalse(e.getMessage().contains("destroy"), e.getMessage());
    assertTrue(e.getMessage().contains("use it as the replacement"), e.getMessage());
  }

  // ---- every recovery after a lost reply keeps to the plan's keys, on every server ----

  /** How a server answers a Locate it cannot serve as asked. */
  enum Search {
    /** It refuses the Locate (PyKMIP answers General Failure to a client-attribute Locate). */
    REFUSES,
    /** It ignores the filter and returns every object (as some servers do for client attributes). */
    IGNORES,
    /** It ignores the filter and returns only its first 32 objects (a server that caps Locate). */
    TRUNCATES
  }

  /**
   * A client of {@code s} whose Locates that name {@code text} the server answers as {@code
   * search} says (null: as asked); every request goes to {@code before} first.
   */
  Kms searching(
      InMemoryKmipServer s, AtomicReference<Search> search, String text, Consumer<Ttlv> before) {
    Kms kms =
        Kms.connect(
            s.configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        r -> {
                          before.accept(r);
                          Search how = search.get();
                          if (how == null
                              || !is(r, Operation.LOCATE)
                              || !LineageTreeTest.names(r, text)) return s.exchange(r);
                          if (how == Search.REFUSES) {
                            s.failNext(ServerOperation.LOCATE, ResultReason.GENERAL_FAILURE);
                            return s.exchange(r);
                          }
                          Ttlv reply = s.exchange(unfiltered(r, text));
                          return how == Search.TRUNCATES ? first(reply, 32) : reply;
                        })
                .build());
    clients.add(kms);
    return kms;
  }

  /**
   * {@code t} without the filters that name {@code text}, keeping the containers (message, batch
   * item, payload, 2.x and 3.0 Attributes): a structure, or a text field (a 3.0 Name), that names
   * it is dropped.
   */
  static Ttlv unfiltered(Ttlv t, String text) {
    if (t.type() != Ttlv.Type.STRUCTURE) return t;
    Set<Integer> containers =
        Set.of(
            Tag.REQUEST_MESSAGE.code(),
            Tag.BATCH_ITEM.code(),
            Tag.REQUEST_PAYLOAD.code(),
            Tag.ATTRIBUTES.code());
    List<Ttlv> kept = new ArrayList<>();
    for (Ttlv c : t.children()) {
      if (!containers.contains(c.tag()) && LineageTreeTest.names(c, text)) continue;
      kept.add(unfiltered(c, text));
    }
    return Ttlv.structure(t.tag(), kept);
  }

  /** {@code reply} with only its first {@code n} Unique Identifiers in each payload. */
  static Ttlv first(Ttlv reply, int n) {
    if (reply.type() != Ttlv.Type.STRUCTURE) return reply;
    List<Ttlv> kept = new ArrayList<>();
    int ids = 0;
    for (Ttlv c : reply.children()) {
      if (reply.tag() == Tag.RESPONSE_PAYLOAD.code()
          && c.tag() == Tag.UNIQUE_IDENTIFIER.code()
          && ids++ >= n) continue;
      kept.add(first(c, n));
    }
    return Ttlv.structure(reply.tag(), kept);
  }

  /** {@code count} unrelated keys, made before the case's own (a server's first objects). */
  static void others(Kms kms, int count) {
    for (int i = 0; i < count; i++)
      kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
  }

  /** Runs {@code work} as another caller would, on its own thread, and waits for it. */
  static <T> T meanwhile(Callable<T> work) {
    return CompletableFuture.supplyAsync(
            () -> {
              try {
                return work.call();
              } catch (Exception e) {
                throw new IllegalStateException(e);
              }
            })
        .join();
  }

  /** Asserts that each object {@code snapshot} lists is as it was then. */
  static void untouched(InMemoryKmipServer s, Map<String, String> snapshot) {
    Map<String, String> now = objects(s);
    for (var e : snapshot.entrySet())
      assertEquals(e.getValue(), now.get(e.getKey()), e.getKey() + " changed");
  }

  /** The key the server made last. */
  static String newest(InMemoryKmipServer s) {
    List<String> ids = s.ids();
    return ids.get(ids.size() - 1);
  }

  /**
   * A server that refuses a client-attribute Locate, ignores that filter, or returns only its first
   * objects. The fallback Create's reply is lost; the call finds its key by its temporary name (a
   * Locate by Name, which those servers serve), links it, and makes no second key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostFallbackCreateIsFoundWhereClientAttributesCannotBeSearched(KmipVersion version)
      throws Exception {
    for (Search how : Search.values()) {
      InMemoryKmipServer s = server(version);
      Kms kms = searching(s, new AtomicReference<>(how), KeyHandle.REPLACEMENT_OF.name(), r -> {});
      others(kms, 40);
      Lineage l = lineage(kms, false);
      CompromisePlan plan = l.key().compromisePlan();
      Map<String, String> before = objects(s);
      s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
      s.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
      CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), plan);
      assertEquals(CompromiseResult.Outcome.RECOVERED, r.outcome(), how + " " + r);
      assertEquals(Set.of(r.replacement().id()), onlyPlanned(s, before, plan, 1), how.name());
      assertEquals(List.of(NAME), s.names(r.replacement().id()), "the temporary name is gone");
      assertEquals(List.of(r.replacement().id()), s.links(l.key().id(), LinkKind.REPLACEMENT));
    }
  }

  /**
   * The search for the lost Create's key by its temporary name is refused, or returns a capped,
   * unfiltered list that does not reach the key. The call never takes that for "none": it stops,
   * keeping the revocation, says the server could not be searched and gives the name, and never
   * says the Create did not take effect. The next plan refuses, naming the key; no second key is
   * made. A server that ignores the filter returns the key among every object, but cannot show it
   * is the only one with the name: the call names it and stops the same way.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostCreateIsNeverTakenForAbsentWhenItsNameCannotBeSearched(KmipVersion version)
      throws Exception {
    for (Search how : Search.values()) {
      InMemoryKmipServer s = server(version);
      Kms kms = searching(s, new AtomicReference<>(how), KeyHandle.TEMPORARY, r -> {});
      others(kms, 40);
      Lineage l = lineage(kms, false);
      CompromisePlan plan = l.key().compromisePlan();
      Map<String, String> before = objects(s);
      s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
      s.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
      PartialCompletionException e =
          assertThrows(
              PartialCompletionException.class,
              () -> l.key().replaceCompromisedResult(compromise(MINE), plan),
              how.name());
      String orphan = onlyPlanned(s, before, plan, 1).iterator().next();
      assertEquals(List.of(l.key().id()), ids(e.deactivated()));
      assertEquals(List.of(), e.created());
      assertTrue(e.getMessage().contains(s.names(orphan).get(0)), e.getMessage());
      assertTrue(
          e.getMessage()
              .contains(
                  how == Search.IGNORES
                      ? orphan + " has its temporary name"
                      : "could not be searched"),
          e.getMessage());
      assertTrue(
          e.getMessage().contains("cannot show it is the only object") == (how == Search.IGNORES),
          e.getMessage());
      assertFalse(e.getMessage().contains("did not take effect"), e.getMessage());
      assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(orphan));

      StateConflictException refused =
          assertThrows(StateConflictException.class, () -> l.key().compromisePlan());
      assertEquals(StateConflictException.Conflict.UNLINKED_REPLACEMENT, refused.conflict());
      assertEquals(Optional.of(orphan), refused.objectId(), refused.getMessage());
    }
  }

  /**
   * A Compromised key, and a key an earlier call created for it and did not link, made after 40
   * others. A server that refuses the client-attribute search, or returns a capped unfiltered list,
   * cannot show the plan that key: the plan says it could not check, and a call bound to it
   * (approved knowing that) leaves that key as it is. A server that ignores the filter but returns
   * every object is read in full: the plan refuses, naming the key. A server that searches, without
   * such a key, checked.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aPlanThatCannotSearchForAnUnlinkedKeySaysSo(KmipVersion version) throws Exception {
    InMemoryKmipServer plain = server(version);
    Lineage clean = lineage(connect(plain), true);
    assertTrue(clean.key().compromisePlan().checkedForUnlinkedKeys());
    for (Search how : Search.values()) {
      InMemoryKmipServer s = server(version);
      Kms kms = searching(s, new AtomicReference<>(how), KeyHandle.REPLACEMENT_OF.name(), r -> {});
      others(kms, 40);
      Lineage l = lineage(kms, true);
      String orphan =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .custom(KeyHandle.REPLACEMENT_OF, l.key().id())
              .createPreActive()
              .id();
      if (how == Search.IGNORES) {
        StateConflictException e =
            assertThrows(StateConflictException.class, () -> l.key().compromisePlan());
        assertEquals(StateConflictException.Conflict.UNLINKED_REPLACEMENT, e.conflict());
        assertEquals(Optional.of(orphan), e.objectId());
        continue;
      }
      CompromisePlan plan = l.key().compromisePlan();
      assertFalse(plan.checkedForUnlinkedKeys(), how.name());
      assertTrue(plan.toString().contains("not checked"), plan.toString());
      Map<String, String> before = objects(s);
      CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), plan);
      assertEquals(CompromiseResult.Outcome.COMPLETED, r.outcome(), r.toString());
      onlyPlanned(s, before, plan, 1);
    }
  }

  /**
   * The plan could search for an unlinked key, and by the time it is approved the search cannot be
   * made: the bound call refuses as not as planned, nothing changed.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aPlanThatCouldSearchRefusesWhenTheSearchCannotBeMadeNow(KmipVersion version)
      throws Exception {
    InMemoryKmipServer s = server(version);
    AtomicReference<Search> how = new AtomicReference<>();
    Kms kms = searching(s, how, KeyHandle.REPLACEMENT_OF.name(), r -> {});
    Lineage l = lineage(kms, true);
    CompromisePlan plan = l.key().compromisePlan();
    assertTrue(plan.checkedForUnlinkedKeys());
    how.set(Search.REFUSES);
    Map<String, String> before = objects(s);
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> l.key().replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(StateConflictException.Conflict.NOT_AS_PLANNED, e.conflict(), e.getMessage());
    assertEquals(before, objects(s));
  }

  /**
   * The fallback Create's reply is lost, and before the call looks for its key another caller
   * re-keys that key (the Re-key moves its temporary name to the new key, and copies its client
   * attributes) and destroys it. The search finds the other caller's key, which is not as the
   * Create left a key: the call stops, keeping its revocation, and changes nothing of that key (no
   * link, name or activation).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aKeyReKeyedFromTheLostCreatesKeyIsNeverAdopted(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms other = connect(s);
    AtomicBoolean armed = new AtomicBoolean();
    AtomicReference<String> theirs = new AtomicReference<>();
    Map<String, String> snapshot = new TreeMap<>();
    Kms kms =
        connect(
            s,
            r -> {
              if (is(r, Operation.LOCATE)
                  && LineageTreeTest.names(r, KeyHandle.TEMPORARY)
                  && armed.getAndSet(false)) {
                String made = newest(s);
                theirs.set(
                    meanwhile(
                        () -> {
                          String c = RotationAndNameChoiceTest.reKey(other, made);
                          // Destroyed as its creator might: Pre-Active, never activated.
                          other
                              .protocol()
                              .call(
                                  dev.keytend.kmip.client.Requests.destroy()
                                      .uniqueIdentifier(made)
                                      .build());
                          return c;
                        }));
                snapshot.putAll(objects(s));
              }
            });
    Lineage l = lineage(kms, false);
    CompromisePlan plan = l.key().compromisePlan();
    Map<String, String> before = objects(s);
    armed.set(true);
    s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
    s.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> l.key().replaceCompromisedResult(compromise(MINE), plan));
    String c = theirs.get();
    assertNotNull(c, "the other caller re-keyed the lost Create's key");
    assertEquals(List.of(l.key().id()), ids(e.deactivated()));
    assertEquals(List.of(), e.created());
    assertEquals(List.of(), e.found());
    assertTrue(e.getMessage().contains(c), e.getMessage());
    assertTrue(e.getMessage().contains("not as the Create left a key"), e.getMessage());
    onlyPlanned(s, before, plan, 2);
    snapshot.remove(l.key().id());
    untouched(s, snapshot);
    assertEquals(List.of(), s.links(l.key().id(), LinkKind.REPLACEMENT));
  }

  /**
   * The multiple-match case: another caller gives the lost Create's temporary name to another key
   * before the call looks. Two keys hold it; the call takes neither, and changes neither.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void twoKeysWithTheLostCreatesNameAreBothLeftAlone(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms other = connect(s);
    String bystander =
        other
            .keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .createPreActive()
            .id();
    AtomicBoolean armed = new AtomicBoolean();
    Map<String, String> snapshot = new TreeMap<>();
    AtomicReference<String> made = new AtomicReference<>();
    Kms kms =
        connect(
            s,
            r -> {
              if (is(r, Operation.LOCATE)
                  && LineageTreeTest.names(r, KeyHandle.TEMPORARY)
                  && armed.getAndSet(false)) {
                made.set(newest(s));
                String temporary = s.names(made.get()).get(0);
                meanwhile(
                    () -> {
                      other.keys().handle(bystander).addName(temporary);
                      return null;
                    });
                snapshot.putAll(objects(s));
              }
            });
    Lineage l = lineage(kms, true);
    CompromisePlan plan = l.key().compromisePlan();
    armed.set(true);
    s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
    s.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
    OutcomeUnknownException e =
        assertThrows(
            OutcomeUnknownException.class,
            () -> l.key().replaceCompromisedResult(compromise(MINE), plan));
    assertTrue(e.getMessage().contains(bystander), e.getMessage());
    assertTrue(e.getMessage().contains(made.get()), e.getMessage());
    untouched(s, snapshot);
  }

  /**
   * Just before this call's Re-key reaches the server, another caller re-keys the key (B); this
   * call's Re-key then makes C, and its reply is lost. Reading back finds B and C, and which one
   * this call made cannot be told: the plan-bound call activates, links and names neither, and
   * stops with its revocation kept. B is as its creator left it; C is Pre-Active and unnamed.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostReKeyBesideAnotherCallersReKeyAdoptsNeither(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms other = connect(s);
    AtomicBoolean armed = new AtomicBoolean();
    AtomicReference<String> theirs = new AtomicReference<>();
    Map<String, String> snapshot = new TreeMap<>();
    AtomicReference<String> key = new AtomicReference<>();
    Kms kms = connect(s, beforeReKey(s, other, armed, key, theirs, snapshot));
    Lineage l = lineage(kms, false);
    key.set(l.key().id());
    CompromisePlan plan = l.key().compromisePlan();
    Map<String, String> before = objects(s);
    armed.set(true);
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> l.key().replaceCompromisedResult(compromise(MINE), plan));
    String b = theirs.get();
    Set<String> made = onlyPlanned(s, before, plan, 2);
    String c = made.stream().filter(id -> !id.equals(b)).findFirst().orElseThrow();
    assertEquals(List.of(l.key().id()), ids(e.deactivated()));
    assertEquals(List.of(), e.created());
    assertEquals(List.of(), e.found());
    assertInstanceOf(OutcomeUnknownException.class, e.getCause());
    assertEquals(Optional.empty(), e.recoveredFrom(), "nothing was gone on with");
    assertTrue(e.getMessage().contains(b) && e.getMessage().contains(c), e.getMessage());
    assertTrue(e.getMessage().contains("did not activate, link or name"), e.getMessage());
    assertEquals(snapshot.get(b), objects(s).get(b), "B as its creator left it");
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(c));
    assertEquals(List.of(), s.names(c));
  }

  /**
   * The unbound form: the same interleaving. It finishes with a replacement another caller makes
   * (documented), and activates only the one it finishes with; the other stays Pre-Active.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theUnboundFormActivatesOneKeyAfterALostReKey(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms other = connect(s);
    AtomicBoolean armed = new AtomicBoolean();
    AtomicReference<String> theirs = new AtomicReference<>();
    AtomicReference<String> key = new AtomicReference<>();
    Kms kms = connect(s, beforeReKey(s, other, armed, key, theirs, new TreeMap<>()));
    Lineage l = lineage(kms, false);
    key.set(l.key().id());
    armed.set(true);
    KeyHandle r = l.key().replaceCompromised(compromise(MINE));
    List<String> replacements = s.links(l.key().id(), LinkKind.REPLACEMENT);
    assertEquals(2, replacements.size(), replacements.toString());
    assertTrue(replacements.contains(r.id()));
    for (String id : replacements)
      assertEquals(
          Optional.of(id.equals(r.id()) ? KeyState.ACTIVE : KeyState.PRE_ACTIVE), s.state(id), id);
  }

  /**
   * A transport hook: when armed, before {@code key}'s Re-key reaches the server, {@code other}
   * re-keys it ({@code theirs}, then {@code snapshot} of every object), and this Re-key's reply is
   * lost.
   */
  static Consumer<Ttlv> beforeReKey(
      InMemoryKmipServer s,
      Kms other,
      AtomicBoolean armed,
      AtomicReference<String> key,
      AtomicReference<String> theirs,
      Map<String, String> snapshot) {
    return r -> {
      if (is(r, Operation.RE_KEY) && armed.getAndSet(false)) {
        theirs.set(meanwhile(() -> RotationAndNameChoiceTest.reKey(other, key.get())));
        snapshot.putAll(objects(s));
        s.failNext(ServerOperation.RE_KEY, Fault.REPLY_LOST);
      }
    };
  }

  /**
   * Two plan-bound callers, X and Y, on one Compromised key; both plans create a key. X creates its
   * key and, before it links it, Y's call reads it: Y refuses as not as planned, with no advice to
   * destroy it, and X finishes with its key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anotherCallersKeyInFlightIsNotAsPlannedForTheSecond(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms y = connect(s);
    AtomicBoolean created = new AtomicBoolean();
    AtomicReference<RuntimeException> refused = new AtomicReference<>();
    AtomicReference<Runnable> second = new AtomicReference<>();
    Kms x =
        connect(
            s,
            r -> {
              if (is(r, Operation.CREATE)) created.set(true);
              else if (created.get() && is(r, Operation.ADD_ATTRIBUTE) && second.get() != null)
                meanwhile(
                    () -> {
                      second.getAndSet(null).run();
                      return null;
                    });
            });
    Lineage l = lineage(x, true);
    CompromisePlan planX = l.key().compromisePlan();
    KeyHandle yKey = y.keys().handle(l.key().id()).allowingCompromised();
    CompromisePlan planY = yKey.compromisePlan();
    assertTrue(planX.creates() && planY.creates());
    second.set(
        () ->
            refused.set(
                assertThrows(
                    StateConflictException.class,
                    () -> yKey.replaceCompromisedResult(compromise(MINE), planY))));
    s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(MINE), planX);
    assertEquals(CompromiseResult.Outcome.COMPLETED, r.outcome(), r.toString());
    StateConflictException e = (StateConflictException) refused.get();
    assertNotNull(e, "Y's call ran while X's key was unlinked");
    assertEquals(StateConflictException.Conflict.NOT_AS_PLANNED, e.conflict(), e.getMessage());
    assertTrue(e.getMessage().contains(r.replacement().id()), e.getMessage());
    assertFalse(e.getMessage().contains("destroy"), e.getMessage());
  }
}
