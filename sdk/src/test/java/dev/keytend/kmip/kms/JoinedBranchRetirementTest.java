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

import static dev.keytend.kmip.kms.ScheduledRotationTest.aes;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.KmipTransport;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Retirement and reconcile around a branch that reconcile joined into the winner. */
class JoinedBranchRetirementTest {
  static final byte[] AAD = "aad".getBytes(StandardCharsets.UTF_8);
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
  }

  Kms connect(InMemoryKmipServer s, KmipTransport transport) {
    Kms k =
        Kms.connect(
            s.configure().retryPolicy(RetryPolicy.none()).transport(e -> transport).build());
    clients.add(k);
    return k;
  }

  /** A client of {@code s} that sees the identifiers in {@code purged} as gone (Item Not Found), as after a purge. */
  Kms purging(InMemoryKmipServer s, Set<String> purged) {
    return connect(
        s,
        request -> {
          Optional<String> id = ReplicaFailoverTest.target(request);
          if (id.isPresent() && purged.contains(id.get()))
            return Faults.failure(request, Enums.ResultReason.ITEM_NOT_FOUND, "purged");
          return s.exchange(request);
        });
  }

  /**
   * k0 forked into a and b, each rotated once more (a2, b2); reconcile keeps one of a2
   * and b2 and joins the other. Retirement destroys the joined branch newest first; one that stopped
   * after the first key, on a server that purges destroyed keys, left the branch's middle key
   * naming a replacement that no longer exists, and every walk of the lineage refused (STATE "cannot
   * be followed past"): {@code latest()}, a {@code CurrentKey}'s check, and the retirement's repeat.
   * Now that key, Deactivated with its replacements gone, is the end of a branch being retired, not
   * a newest key, and the repeat retires the rest.
   */
  @Test
  void aRetirementStoppedInAJoinedBranchResumes() throws Exception {
    InMemoryKmipServer s = InMemoryKmipServer.of(KmipVersion.V2_1);
    Set<String> purged = ConcurrentHashMap.newKeySet();
    Kms kms = purging(s, purged);
    KeyHandle k0 = aes(kms).create();
    String a = RotationAndNameChoiceTest.reKey(kms, k0.id()),
        b = RotationAndNameChoiceTest.reKey(kms, k0.id());
    String a2 = RotationAndNameChoiceTest.reKey(kms, a),
        b2 = RotationAndNameChoiceTest.reKey(kms, b);
    KeyHandle winner = k0.reconcile();
    String leaf = winner.id().equals(a2) ? b2 : a2, mid = winner.id().equals(a2) ? b : a;
    // The retirement's first step, then the server purges the key.
    kms.keys().handle(leaf).destroy();
    purged.add(leaf);
    assertEquals(winner, winner.latest());
    assertTrue(winner.isLatest());
    assertEquals(winner, kms.keys().handle(mid).latest());
    List<String> retired =
        winner.retirePredecessors(RevocationReason.superseded("retired")).stream()
            .map(KeyHandle::id)
            .toList();
    assertEquals(Set.of(k0.id(), a, b), Set.copyOf(retired));
    assertEquals(mid, retired.get(0), "the rest of the branch first");
    // A lineage whose only ends are such keys has no newest key in use: STATE, as before.
    InMemoryKmipServer t = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms other = purging(t, purged);
    KeyHandle x0 = aes(other).create();
    KeyHandle x1 = x0.rotate();
    x0.revoke(RevocationReason.superseded("retired"));
    x1.revoke(RevocationReason.superseded("retired"));
    x1.destroy();
    purged.add(x1.id());
    assertThrows(StateConflictException.class, x0::latest);
  }

  /**
   * A newest key rotated by another instance between reconcile's walk and its join: the
   * server refuses the second Replacement Object link. That was an {@link UnsupportedException}
   * advising to join the keys by hand (as for a server that refuses links); it is a race, and a
   * repeat of {@code reconcile()} finishes.
   */
  @Test
  void aJoinRefusedBecauseTheKeyWasReplacedMeanwhileSaysRepeat() throws Exception {
    InMemoryKmipServer s = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms other = connect(s, s::exchange);
    AtomicBoolean armed = new AtomicBoolean();
    Kms kms =
        connect(
            s,
            request -> {
              if (RotationAndNameChoiceTest.isOperation(request, Operation.ADD_ATTRIBUTE)
                  && armed.getAndSet(false))
                try {
                  RotationAndNameChoiceTest.reKey(
                      other, ReplicaFailoverTest.target(request).orElseThrow());
                } catch (Exception x) {
                  throw new IllegalStateException(x);
                }
              return s.exchange(request);
            });
    KeyHandle k0 = aes(kms).create();
    RotationAndNameChoiceTest.reKey(kms, k0.id());
    RotationAndNameChoiceTest.reKey(kms, k0.id());
    armed.set(true);
    PartialCompletionException e = assertThrows(PartialCompletionException.class, k0::reconcile);
    assertTrue(e.getMessage().contains("repeat reconcile()"), e.getMessage());
    assertInstanceOf(StateConflictException.class, e.getCause());
    KeyHandle winner = k0.reconcile();
    assertEquals(winner, k0.latest());
    for (String id : s.ids())
      if (!id.equals(k0.id())) assertTrue(s.links(id, LinkKind.REPLACEMENT).size() <= 1, id);
  }

  /**
   * The lost link race of {@code replaceCompromised}, with the read after the
   * refused link failing once. That read's failure sent the call down the path of a server that
   * refuses links: its own key activated and named, outside the lineage, and "do not repeat". Now
   * nothing is activated, and the advice is to repeat, which finishes with the other caller's
   * replacement.
   */
  @Test
  void aLostLinkRaceWithAFailedReadSaysRepeat() throws Exception {
    InMemoryKmipServer s = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms admin = connect(s, s::exchange);
    KeyHandle k0 = aes(admin).create();
    byte[] record = k0.seal("x".getBytes(StandardCharsets.UTF_8), AAD);
    k0.revoke(RevocationReason.keyCompromise("leaked", Instant.now()));
    Kms a =
        connect(
            s,
            r -> {
              if (RotationAndNameChoiceTest.isOperation(r, Operation.RE_KEY))
                s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
              return s.exchange(r);
            });
    AtomicBoolean ranA = new AtomicBoolean(),
        linked = new AtomicBoolean(),
        failed = new AtomicBoolean();
    KeyHandle[] fromA = new KeyHandle[1];
    Kms b =
        connect(
            s,
            r -> {
              if (RotationAndNameChoiceTest.isOperation(r, Operation.RE_KEY))
                s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
              if (RotationAndNameChoiceTest.isOperation(r, Operation.CREATE)
                  && ranA.compareAndSet(false, true))
                fromA[0] =
                    a.keys()
                        .handle(k0.id())
                        .replaceCompromised(
                            RevocationReason.keyCompromise("leaked", Instant.now()));
              Optional<String> t = ReplicaFailoverTest.target(r);
              if (RotationAndNameChoiceTest.isOperation(r, Operation.ADD_ATTRIBUTE)
                  && t.equals(Optional.of(k0.id()))) linked.set(true);
              if (linked.get()
                  && RotationAndNameChoiceTest.isOperation(r, Operation.GET_ATTRIBUTES)
                  && t.equals(Optional.of(k0.id()))
                  && failed.compareAndSet(false, true))
                return Faults.failure(r, Enums.ResultReason.GENERAL_FAILURE, "busy");
              return s.exchange(r);
            });
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () ->
                b.keys()
                    .handle(k0.id())
                    .replaceCompromised(RevocationReason.keyCompromise("leaked", Instant.now())));
    assertTrue(failed.get());
    assertFalse(e.getMessage().contains("do not repeat"), e.getMessage());
    assertTrue(e.getMessage().contains("repeat replaceCompromised()"), e.getMessage());
    String mine = e.created().get(0).id();
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(mine));
    assertEquals(List.of(), s.names(mine));
    for (String id : s.ids())
      if (s.links(id, LinkKind.REPLACED).isEmpty() && !id.equals(k0.id()))
        assertNotEquals(
            Optional.of(KeyState.ACTIVE),
            s.state(id),
            id + ": an unlinked replacement handed out Active");
    // The advice: repeat; it finishes with A's replacement.
    KeyHandle again =
        b.keys()
            .handle(k0.id())
            .replaceCompromised(RevocationReason.keyCompromise("leaked", Instant.now()));
    assertEquals(fromA[0].id(), again.id());
    assertArrayEquals(
        "x".getBytes(StandardCharsets.UTF_8),
        again.compromisedPredecessors().get(0).open(record, AAD));
  }

  /**
   * Retiring from a key reconcile joined into the winner said the winner was one of
   * "other newest keys" to reconcile; it is a newer key, and the advice is to retire from the key
   * {@code latest()} returns.
   */
  @Test
  void retiringFromAJoinedKeySaysNewerKeys() throws Exception {
    InMemoryKmipServer s = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(s, s::exchange);
    KeyHandle k0 = aes(kms).create();
    String a = RotationAndNameChoiceTest.reKey(kms, k0.id()),
        b = RotationAndNameChoiceTest.reKey(kms, k0.id());
    String a2 = RotationAndNameChoiceTest.reKey(kms, a),
        b2 = RotationAndNameChoiceTest.reKey(kms, b);
    KeyHandle winner = k0.reconcile();
    String loser = winner.id().equals(a2) ? b2 : a2;
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> kms.keys().handle(loser).retirePredecessors(RevocationReason.superseded("x")));
    assertTrue(e.getMessage().contains("newer keys, [" + winner.id() + "]"), e.getMessage());
  }
}
