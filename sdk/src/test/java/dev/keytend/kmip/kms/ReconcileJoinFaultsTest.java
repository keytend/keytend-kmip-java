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

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Reconcile and name moves under faults: two-level joins failing at every link, winners that change
 * between runs, hundreds of newest keys, forged records, servers without client attributes, and the
 * failure sweeps.
 */
class ReconcileJoinFaultsTest {
  static final byte[] PLAIN = NameMoveAndWideForkTest.PLAIN, AAD = NameMoveAndWideForkTest.AAD;
  static final String NAME = NameMoveAndWideForkTest.NAME;

  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
  }

  Kms track(Kms kms) {
    clients.add(kms);
    return kms;
  }

  /**
   * A sweep's failure points, from 1 to {@code last}: every {@code fullStep}-th with {@code
   * -Dkeytend.sweep=full}; otherwise every {@code sample}-th, split between the versions (1.4 the
   * odd ones of that sample, 2.1 the even ones), or all of it on each with {@code
   * -Dkeytend.matrix=full} ({@link TestMatrix}).
   */
  static List<Integer> points(KmipVersion version, int last, int sample, int fullStep) {
    boolean split = !TestMatrix.full() && !"full".equals(System.getProperty("keytend.sweep"));
    int first = split && version != KmipVersion.V1_4 ? 1 + sample : 1;
    int step =
        "full".equals(System.getProperty("keytend.sweep")) ? fullStep : split ? 2 * sample : sample;
    List<Integer> out = new ArrayList<>();
    for (int failAt = first; failAt <= last; failAt += step) out.add(failAt);
    return out;
  }

  static boolean is(Ttlv request, Operation op) {
    return RotationAndNameChoiceTest.isOperation(request, op);
  }

  /** Invariants after reconcile returned {@code w}: link counts, one Active key, latest() from each. */
  static List<String> violations(InMemoryKmipServer s, Kms k, String old, String w) {
    List<String> out = new ArrayList<>();
    for (String id : s.ids()) {
      if (!id.equals(old))
        for (LinkKind kind : LinkKind.values()) {
          int n = new HashSet<>(s.links(id, kind)).size();
          if (n > Lineage.FANOUT) out.add(id + " has " + n + " " + kind);
        }
      if (!id.equals(w) && s.state(id).orElse(null) == KeyState.ACTIVE)
        out.add(id + " still Active");
      try {
        String l = k.keys().handle(id).latest().id();
        if (!l.equals(w)) out.add(id + ".latest() = " + l);
      } catch (KmsException e) {
        out.add(id + ".latest(): " + e);
      }
    }
    return out;
  }

  // ---- Two-level joins: a failure at every link, then repeats ----

  /**
   * A 70-key fork; reconcile fails (Internal Server Error, nothing changed) at the {@code n}-th link
   * addition, for every n ({@code -Dkeytend.sweep=full}; a sample otherwise); then repeats until it
   * succeeds. Checks the shape after.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void twoLevelJoinFailingAtEveryLinkThenRepeated(KmipVersion version) throws Exception {
    List<String> all = new ArrayList<>();
    for (int failAt : points(version, 140, 7, 1)) {
      InMemoryKmipServer s = NameMoveAndWideForkTest.server(version, false);
      Kms admin = track(s.connect());
      KeyHandle old = NameMoveAndWideForkTest.key(admin, NAME);
      byte[] root = old.seal(PLAIN, AAD);
      for (int i = 0; i < 70; i++) RotationAndNameChoiceTest.reKey(admin, old.id());
      AtomicInteger links = new AtomicInteger();
      int f = failAt;
      Kms k =
          track(
              Kms.connect(
                  s.configure()
                      .retryPolicy(RetryPolicy.none())
                      .transport(
                          e ->
                              request -> {
                                if (is(request, Operation.ADD_ATTRIBUTE)
                                    && links.incrementAndGet() == f)
                                  s.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.SERVER_FAILURE);
                                return s.exchange(request);
                              })
                      .build()));
      KeyHandle winner = null;
      for (int attempt = 0; attempt < 4 && winner == null; attempt++)
        try {
          winner = k.keys().handle(old.id()).reconcile();
        } catch (PartialCompletionException interrupted) {
          // repeat
        }
      if (winner == null) {
        all.add(failAt + ": never finished");
        continue;
      }
      for (String v : violations(s, admin, old.id(), winner.id())) all.add(failAt + ": " + v);
      try {
        assertArrayEquals(PLAIN, admin.keys().open(KeyQuery.byName(NAME), root, AAD));
      } catch (KmsException e) {
        all.add(failAt + ": root via KeyQuery " + e);
      }
    }
    assertEquals(List.of(), all.subList(0, Math.min(all.size(), 20)), "total " + all.size());
  }

  /**
   * A 70-key fork; the first reconcile is interrupted half-way, then the operator revokes the
   * winner it chose (or marks it Compromised) before repeating: the repeat chooses another winner.
   * (One Replacement Object link on each joined key, 69 link adds.)
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void twoLevelJoinWhoseWinnerChangesBetweenRuns(KmipVersion version) throws Exception {
    List<String> all = new ArrayList<>();
    for (boolean compromise : new boolean[] {false, true})
      for (int failAt : new int[] {3, 40, 63, 64, 65, 69}) {
        InMemoryKmipServer s = NameMoveAndWideForkTest.server(version, false);
        Kms admin = track(s.connect());
        KeyHandle old = NameMoveAndWideForkTest.key(admin, NAME);
        for (int i = 0; i < 70; i++) RotationAndNameChoiceTest.reKey(admin, old.id());
        AtomicInteger links = new AtomicInteger();
        Kms k =
            track(
                Kms.connect(
                    s.configure()
                        .retryPolicy(RetryPolicy.none())
                        .transport(
                            e ->
                                request -> {
                                  if (is(request, Operation.ADD_ATTRIBUTE)
                                      && links.incrementAndGet() == failAt)
                                    s.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.SERVER_FAILURE);
                                  return s.exchange(request);
                                })
                        .build()));
        String first = old.latest().id();
        assertThrows(PartialCompletionException.class, () -> k.keys().handle(old.id()).reconcile());
        if (compromise)
          admin
              .keys()
              .handle(first)
              .revoke(RevocationReason.keyCompromise("x", NameMoveAndWideForkTest.NOW));
        else admin.keys().handle(first).revoke(RevocationReason.superseded("by hand"));
        KeyHandle winner;
        try {
          winner = k.keys().handle(old.id()).reconcile();
        } catch (KmsException e) {
          all.add(compromise + "/" + failAt + ": " + e);
          continue;
        }
        for (String v : violations(s, admin, old.id(), winner.id()))
          all.add(compromise + "/" + failAt + ": " + v);
        long active =
            s.ids().stream().filter(id -> s.state(id).orElse(null) == KeyState.ACTIVE).count();
        if (active > 1)
          all.add(compromise + "/" + failAt + ": " + active + " Active keys after reconcile");
      }
    assertEquals(List.of(), all);
  }

  // ---- the documented bound: "about a thousand newest keys" ----

  /**
   * A fork of 300 newest keys is more than one walk reads (256 keys): reconcile refuses with STATE
   * and advice, before linking anything (was ProtocolViolationException; the docs said "about a
   * thousand").
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1"})
  void reconcileOfThreeHundredNewestKeys(KmipVersion version) throws Exception {
    InMemoryKmipServer s = NameMoveAndWideForkTest.server(version, false);
    Kms k = track(s.connect());
    KeyHandle old = NameMoveAndWideForkTest.key(k, NAME);
    for (int i = 0; i < 300; i++) RotationAndNameChoiceTest.reKey(k, old.id());
    int before = s.exchanges();
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> k.keys().handle(old.id()).reconcile());
    assertTrue(e.getMessage().contains("choose the key to keep by hand"), e.getMessage());
    for (String id : s.ids()) assertTrue(s.links(id, LinkKind.REPLACED).size() <= 1, id);
    assertTrue(s.exchanges() - before <= Lineage.BUDGET + 2);
  }

  // ---- cost of a forged record ----

  /**
   * A forged record under an attacker's key with 33 bogus links, checked against a victim whose
   * name is on a key of a lineage of 60 keys: BAD_DATA, at the cost of one walk of the victim's
   * lineage (the docs said "a few requests"; they now give the bound).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aForgedRecordCostsAWalkOfTheVictimsLineage(KmipVersion version) throws Exception {
    InMemoryKmipServer s =
        NameMoveAndWideForkTest.server(version, true)
            .linkCardinality(false); // the attacker's links
    Kms k = track(s.connect());
    KeyHandle victim = NameMoveAndWideForkTest.key(k, NAME);
    // 59 concurrent-style Re-keys of the victim's first key (a fork, as many instances rotating).
    for (int i = 0; i < 59; i++) RotationAndNameChoiceTest.reKey(k, victim.id());
    KeyHandle attacker = NameMoveAndWideForkTest.key(k, null);
    for (int i = 0; i < 33; i++)
      KmsContractTest.link(k, attacker.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, "bogus-" + i);
    byte[] forged = attacker.seal(PLAIN, AAD);
    int before = s.exchanges();
    KeyMismatchException e =
        assertThrows(
            KeyMismatchException.class, () -> k.keys().open(KeyQuery.byName(NAME), forged, AAD));
    assertEquals(KmsException.Category.BAD_DATA, e.category());
    int cost = s.exchanges() - before;
    assertTrue(cost <= 60 + 4, "requests for one forged record: " + cost);
  }

  /**
   * The worst case of the forged record: the attacker's own tree spends the first walk's reads; the
   * walk from the victim's key gets only what is left of the one budget (was a second budget: 509
   * requests).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1"})
  void aForgedRecordCanCostTwoBudgets(KmipVersion version) throws Exception {
    InMemoryKmipServer s = NameMoveAndWideForkTest.server(version, false);
    Kms k = track(s.connect());
    KeyHandle victim = NameMoveAndWideForkTest.key(k, NAME);
    for (int i = 0; i < 250; i++) RotationAndNameChoiceTest.reKey(k, victim.id());
    KeyHandle attacker = NameMoveAndWideForkTest.key(k, null);
    // Attacker: one key with 260 confirmed replacements via Re-key (each names it back).
    for (int i = 0; i < 260; i++) RotationAndNameChoiceTest.reKey(k, attacker.id());
    // Seal under one of the attacker's replacements: its walk goes back to the attacker key, then
    // forward
    // through 260 siblings: BUDGET.
    String leaf = s.links(attacker.id(), LinkKind.REPLACEMENT).get(0);
    byte[] forged = k.keys().handle(leaf).seal(PLAIN, AAD);
    int before = s.exchanges();
    KmsException e =
        assertThrows(KmsException.class, () -> k.keys().open(KeyQuery.byName(NAME), forged, AAD));
    int cost = s.exchanges() - before;
    assertTrue(
        cost <= Lineage.BUDGET + 4, "requests for one forged record: " + cost + " (" + e + ")");
  }

  // ---- settledPending propagates; pending() refused is still "recorded" ----

  /**
   * A server without client attributes (refuses writing them, and deleting them too). The record is
   * never written, so nothing is removed, and the replacement that finished every step succeeds (on
   * 2.1 it reported a PartialCompletionException for removing a record that did not exist).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aServerWithoutClientAttributesReportsAFinishedReplacementAsPartial(KmipVersion version) {
    InMemoryKmipServer s = NameMoveAndWideForkTest.server(version, true);
    Kms admin = track(s.connect());
    Kms k =
        track(
            Kms.connect(
                s.configure()
                    .transport(
                        e ->
                            request -> {
                              if (is(request, Operation.RE_KEY))
                                s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
                              if (LineageTreeTest.names(request, "keytend-pending-name")
                                  && !is(request, Operation.GET_ATTRIBUTES)
                                  && !is(request, Operation.LOCATE))
                                for (Operation op :
                                    List.of(
                                        Operation.ADD_ATTRIBUTE,
                                        Operation.MODIFY_ATTRIBUTE,
                                        Operation.SET_ATTRIBUTE,
                                        Operation.DELETE_ATTRIBUTE))
                                  if (is(request, op))
                                    s.failNext(
                                        ServerOperation.valueOf(op.name()),
                                        Fault.PERMISSION_DENIED);
                              return s.exchange(request);
                            })
                    .build()));
    KeyHandle old = NameMoveAndWideForkTest.key(k, NAME);
    KeyHandle replacement;
    try {
      replacement = old.replaceCompromised(NameMoveAndWideForkTest.leaked());
    } catch (PartialCompletionException e) {
      String r = e.created().get(0).id();
      fail(
          "names on the replacement "
              + s.names(r)
              + ", records "
              + KeyHandle.pendingNames(admin.keys().handle(r).attributes())
              + "; yet: "
              + e.getMessage());
      return;
    }
    assertEquals(List.of(NAME), s.names(replacement.id()));
  }

  /**
   * The documented flow around a Compromised newest key: reconcile leaves it, replaceCompromised
   * gives it a replacement, reconcile joins that. Nothing is added to the winner, which keeps its
   * one Replaced Object link, and each joined key names it with its own Replacement Object link.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aFullWinnerStillJoinsOneMoreNewestKey(KmipVersion version) throws Exception {
    // 33 Re-keys, one of them Compromised: reconcile joins the other 31 into the winner.
    InMemoryKmipServer s = NameMoveAndWideForkTest.server(version, false);
    Kms k = track(s.connect());
    KeyHandle old = NameMoveAndWideForkTest.key(k, NAME);
    List<String> tips = new ArrayList<>();
    for (int i = 0; i < 33; i++) tips.add(RotationAndNameChoiceTest.reKey(k, old.id()));
    String bad = tips.get(32);
    k.keys()
        .handle(bad)
        .revoke(RevocationReason.keyCompromise("leaked", NameMoveAndWideForkTest.NOW));
    KeyHandle winner = k.keys().handle(old.id()).reconcile();
    assertEquals(
        List.of(old.id()),
        s.links(winner.id(), LinkKind.REPLACED),
        "nothing is added to the winner");
    for (String t : tips)
      if (!t.equals(winner.id()) && !t.equals(bad))
        assertEquals(List.of(winner.id()), s.links(t, LinkKind.REPLACEMENT), t);
    KeyHandle replacement =
        k.keys().handle(bad).replaceCompromised(NameMoveAndWideForkTest.leaked());
    // The documented next step: reconcile joins the replacement into the winner.
    assertEquals(winner.id(), k.keys().handle(old.id()).reconcile().id());
    assertEquals(List.of(old.id()), s.links(winner.id(), LinkKind.REPLACED));
    assertEquals(List.of(winner.id()), s.links(replacement.id(), LinkKind.REPLACEMENT));
    assertNotEquals(Optional.of(KeyState.ACTIVE), s.state(replacement.id()));
    assertEquals(List.of(), violations(s, k, old.id(), winner.id()));
  }

  /**
   * The documented flow, plainly: 40 instances rotate one key at once, one of their keys is then
   * marked Compromised; reconcile joins the other 38 (two levels, the winner takes 32 links) and
   * leaves the Compromised one; replaceCompromised gives it a replacement; reconcile again, to join
   * that one key, as the javadoc says ("A Compromised one is left for replaceCompromised").
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void reconcileAfterReplacingACompromisedBranchOfAWideFork(KmipVersion version) throws Exception {
    InMemoryKmipServer s = NameMoveAndWideForkTest.server(version, false);
    Kms k = track(s.connect());
    KeyHandle old = NameMoveAndWideForkTest.key(k, NAME);
    List<String> tips = new ArrayList<>();
    for (int i = 0; i < 40; i++) tips.add(RotationAndNameChoiceTest.reKey(k, old.id()));
    String bad = tips.get(39);
    k.keys()
        .handle(bad)
        .revoke(RevocationReason.keyCompromise("leaked", NameMoveAndWideForkTest.NOW));
    KeyHandle winner = k.keys().handle(old.id()).reconcile();
    KeyHandle replacement =
        k.keys().handle(bad).replaceCompromised(NameMoveAndWideForkTest.leaked());
    KeyHandle again;
    try {
      again = k.keys().handle(old.id()).reconcile();
    } catch (KmsException e) {
      fail(
          "winner "
              + winner.id()
              + " has "
              + new HashSet<>(s.links(winner.id(), LinkKind.REPLACED)).size()
              + " Replaced Object links; reconcile of the one replacement "
              + replacement.id()
              + ": "
              + e);
      return;
    }
    assertEquals(winner.id(), again.id());
  }

  /**
   * Pending-record lookup on a server that ignores the pending-record filter, with more
   * than 32 objects of which one cannot be read with these credentials (returned by Locate, Get
   * Attributes denied): it is passed over, and startup creates the key (it failed with a STATE
   * saying 32 objects "have the name").
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void anUnreadableObjectOnAnUnfilteringServerBlocksStartup(KmipVersion version) {
    InMemoryKmipServer s = NameMoveAndWideForkTest.server(version, true);
    Kms setup = track(s.connect());
    String hidden = NameMoveAndWideForkTest.key(setup, "someone-elses").id();
    for (int i = 0; i < Lineage.FANOUT + 8; i++) NameMoveAndWideForkTest.key(setup, "other-" + i);
    Kms kms =
        track(
            Kms.connect(
                s.configure()
                    .transport(
                        e ->
                            request -> {
                              boolean pending =
                                  is(request, Operation.LOCATE)
                                      && LineageTreeTest.names(request, KeyHandle.PENDING_PREFIX);
                              if (is(request, Operation.GET_ATTRIBUTES) && exactly(request, hidden))
                                s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
                              return s.exchange(
                                  pending
                                      ? LineageTreeTest.without(request, KeyHandle.PENDING_PREFIX)
                                      : request);
                            })
                    .build()));
    KeyHandle made;
    try {
      made = NameMoveAndWideForkTest.startup(kms);
    } catch (KmsException e) {
      fail("startup: " + e);
      return;
    }
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(made.id()));
  }

  static boolean exactly(Ttlv t, String text) {
    if (t.type() == Ttlv.Type.TEXT_STRING && String.valueOf(t.value()).equals(text)) return true;
    if (t.type() == Ttlv.Type.STRUCTURE)
      for (Ttlv c : t.children()) if (exactly(c, text)) return true;
    return false;
  }

  /**
   * As {@link #twoLevelJoinFailingAtEveryLinkThenRepeated}, with unique names (the name moves), a lost
   * reply or a hang on the n-th mutation of any kind (links, names, records, revocations).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void twoLevelJoinWithUniqueNamesAndAnyMutationFailing(KmipVersion version) throws Exception {
    List<String> all = new ArrayList<>();
    for (Fault fault : List.of(Fault.REPLY_LOST, Fault.SERVER_FAILURE))
      for (int failAt : points(version, 215, 10, 2)) {
        InMemoryKmipServer s = NameMoveAndWideForkTest.server(version, true);
        Kms admin = track(s.connect());
        KeyHandle old = NameMoveAndWideForkTest.key(admin, NAME);
        byte[] root = old.seal(PLAIN, AAD);
        List<String> tips = new ArrayList<>();
        for (int i = 0; i < 70; i++) tips.add(RotationAndNameChoiceTest.reKey(admin, old.id()));
        // The name on a key that is not the winner (the last one), so reconcile moves it.
        String holder =
            s.ids().stream().filter(id -> s.names(id).contains(NAME)).findFirst().orElseThrow();
        admin.keys().handle(holder).removeName(NAME);
        admin.keys().handle(tips.get(69)).addName(NAME);
        AtomicInteger n = new AtomicInteger();
        int f = failAt;
        Kms k =
            track(
                Kms.connect(
                    s.configure()
                        .retryPolicy(RetryPolicy.none())
                        .transport(
                            e ->
                                request -> {
                                  for (Operation op :
                                      List.of(
                                          Operation.ADD_ATTRIBUTE,
                                          Operation.DELETE_ATTRIBUTE,
                                          Operation.SET_ATTRIBUTE,
                                          Operation.MODIFY_ATTRIBUTE,
                                          Operation.REVOKE))
                                    if (is(request, op) && n.incrementAndGet() == f)
                                      s.failNext(ServerOperation.valueOf(op.name()), fault);
                                  return s.exchange(request);
                                })
                        .build()));
        KeyHandle winner = null;
        String last = null;
        for (int attempt = 0; attempt < 4 && winner == null; attempt++)
          try {
            winner = k.keys().reconcile(NAME).orElseThrow();
          } catch (PartialCompletionException | OutcomeUnknownException interrupted) {
            last = String.valueOf(interrupted);
          }
        if (winner == null) {
          all.add(fault + "/" + failAt + ": never finished: " + last);
          continue;
        }
        for (String v : violations(s, admin, old.id(), winner.id()))
          all.add(fault + "/" + failAt + ": " + v);
        if (!s.names(winner.id()).contains(NAME))
          all.add(fault + "/" + failAt + ": winner without the name");
        for (String id : s.ids())
          if (!KeyHandle.pendingNames(admin.keys().handle(id).attributes()).isEmpty())
            all.add(fault + "/" + failAt + ": record left on " + id);
        try {
          assertArrayEquals(PLAIN, admin.keys().open(KeyQuery.byName(NAME), root, AAD));
          assertEquals(winner.id(), NameMoveAndWideForkTest.startup(admin).id());
        } catch (KmsException e) {
          all.add(fault + "/" + failAt + ": " + e);
        }
      }
    assertEquals(List.of(), all.subList(0, Math.min(all.size(), 20)), "total " + all.size());
  }

  /**
   * A record a stranger wrote on a key of their own that these credentials may read but not change:
   * startup refuses, {@code clearPendingName} is refused; the refusal names the exit that works
   * (create the key under the name by hand), and following it ends the refusal.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aStrangersRecordThatCannotBeChangedHasADocumentedExit(KmipVersion version) {
    InMemoryKmipServer s = NameMoveAndWideForkTest.server(version, true);
    Kms stranger = track(s.connect());
    KeyHandle theirs = NameMoveAndWideForkTest.key(stranger, null);
    theirs.setCustomAttribute(KeyHandle.pendingName(NAME), NAME);
    Kms victim =
        track(
            Kms.connect(
                s.configure()
                    .retryPolicy(RetryPolicy.none())
                    .transport(
                        e ->
                            request -> {
                              if (exactly(request, theirs.id()))
                                for (Operation op :
                                    List.of(
                                        Operation.ADD_ATTRIBUTE,
                                        Operation.DELETE_ATTRIBUTE,
                                        Operation.SET_ATTRIBUTE,
                                        Operation.MODIFY_ATTRIBUTE,
                                        Operation.REVOKE,
                                        Operation.DESTROY))
                                  if (is(request, op))
                                    s.failNext(
                                        ServerOperation.valueOf(op.name()),
                                        Fault.PERMISSION_DENIED);
                              return s.exchange(request);
                            })
                    .build()));
    StateConflictException refused =
        assertThrows(StateConflictException.class, () -> NameMoveAndWideForkTest.startup(victim));
    assertTrue(
        refused.getMessage().contains("create the key under the name by hand"),
        refused.getMessage());
    assertThrows(PermissionDeniedException.class, () -> victim.keys().clearPendingName(NAME));
    KeyHandle made =
        victim
            .keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named(NAME)
            .create();
    assertEquals(made.id(), NameMoveAndWideForkTest.startup(victim).id());
  }
}
