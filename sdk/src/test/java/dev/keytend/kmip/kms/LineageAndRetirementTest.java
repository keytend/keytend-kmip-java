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
import static dev.keytend.kmip.kms.RotationGraceTest.sent;
import static dev.keytend.kmip.kms.ScheduledRotationTest.NAME;
import static dev.keytend.kmip.kms.ScheduledRotationTest.aes;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
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
 * Lineages and retirement: {@code KeyHandle.lineage()}, {@code retirePredecessorsOlderThan}, retirement past 64 rotations,
 * and opening records older than 64 rotations by an attribute or a manifest ({@code KeyQuery.ids}).
 */
class LineageAndRetirementTest {
  static final CustomAttribute PURPOSE = CustomAttribute.client("purpose");
  static final byte[] PLAIN = "a record kept for a long time".getBytes(StandardCharsets.UTF_8);
  static final byte[] AAD = "record-1".getBytes(StandardCharsets.UTF_8);
  static final RevocationReason ROTATED = RevocationReason.superseded("rotated");

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();
  final Map<InMemoryKmipServer, RotationJobTest.TestClock> clocks = new HashMap<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  InMemoryKmipServer server(KmipVersion version, boolean unique) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version).uniqueNames(unique);
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(RotationJobTest.START);
    s.clock(clock);
    clocks.put(s, clock);
    servers.add(s);
    return s;
  }

  Kms connect(InMemoryKmipServer s) {
    return connect(s, r -> {});
  }

  /** Connects through a hook that sees each request before the server does (to arm a fault for it). */
  Kms connect(InMemoryKmipServer s, Consumer<Ttlv> before) {
    Kms kms =
        Kms.connect(
            s.configure()
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

  /** A day later on {@code s}'s clock, so that keys made after it are created later. */
  void tick(InMemoryKmipServer s) {
    RotationJobTest.TestClock clock = clocks.get(s);
    clock.now = clock.now.plus(Duration.ofDays(1));
  }

  /** {@code key} rotated a day later. */
  KeyHandle rotated(InMemoryKmipServer s, KeyHandle key) {
    tick(s);
    return key.rotate();
  }

  /** {@code first} and {@code n} rotations of it, oldest first. */
  List<KeyHandle> lineageOf(InMemoryKmipServer s, KeyHandle first, int n) {
    List<KeyHandle> keys = new ArrayList<>(List.of(first));
    for (int i = 0; i < n; i++) keys.add(rotated(s, keys.get(i)));
    return keys;
  }

  /** Requests that deactivate, revoke or destroy anything. */
  static int mutations(InMemoryKmipServer s) {
    return sent(s, Operation.REVOKE) + sent(s, Operation.DEACTIVATE) + sent(s, Operation.DESTROY);
  }

  /** The objects the Destroy requests sent to {@code s} named, in order. */
  static List<String> destroyed(InMemoryKmipServer s) {
    return DeactivationTest.payloads(s, Operation.DESTROY).stream()
        .map(p -> p.require(Tag.UNIQUE_IDENTIFIER).textValue())
        .toList();
  }

  static List<String> listed(List<LineageKey> lineage) {
    return lineage.stream().map(LineageKey::id).toList();
  }

  static List<String> newestFirst(List<KeyHandle> keys) {
    List<String> out = new ArrayList<>(ids(keys));
    Collections.reverse(out);
    return out;
  }

  static LineageKey entry(List<LineageKey> lineage, String id) {
    return lineage.stream().filter(k -> k.id().equals(id)).findFirst().orElseThrow();
  }

  static byte[] sealedStream(KeyHandle key) throws IOException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    try (SealingStream sealing = key.sealing(out, AAD)) {
      sealing.write(PLAIN);
      sealing.finish();
    }
    return out.toByteArray();
  }

  // ---- lineage() ----

  /**
   * {@code lineage()} lists the keys of a lineage newest first,
   * the same from every key of it, at one Get Attributes per key; a stranger's key of the same
   * shape, under the same name where the server allows that, is not listed (walking {@code
   * attributes().replacedLink()} by hand would be fooled by a one-sided link).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void lineageListsTheKeysNewestFirst(KmipVersion version) {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer s = server(version, unique);
      Kms kms = connect(s);
      List<KeyHandle> keys = lineageOf(s, aes(kms).create(), 3);
      KeyHandle stranger =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named(unique ? "other" : NAME)
              .create();
      for (KeyHandle from : keys) {
        int before = s.exchanges();
        List<LineageKey> lineage = from.lineage();
        assertEquals(4, s.exchanges() - before, "one Get Attributes per key, from " + from.id());
        assertEquals(newestFirst(keys), listed(lineage), "from " + from.id());
        for (int i = 0; i < 4; i++) {
          LineageKey k = entry(lineage, keys.get(i).id());
          assertEquals(i == 0 ? List.of() : List.of(keys.get(i - 1).id()), k.replaced());
          assertEquals(i == 3 ? List.of() : List.of(keys.get(i + 1).id()), k.replacedBy());
          assertEquals(i == 3, k.newest());
          assertFalse(k.branch());
          assertEquals(List.of(), k.joinedInto());
          assertEquals(KeyState.ACTIVE, k.attributes().state());
        }
        assertFalse(listed(lineage).contains(stranger.id()));
        assertThrows(UnsupportedOperationException.class, () -> lineage.remove(0));
      }
      assertEquals(List.of(), s.violations());
    }
  }

  /**
   * Branches are marked. Three callers re-keyed one key at once (a server that re-keys a
   * key twice): three newest keys, the one {@code latest()} chooses first, the other two on
   * branches. After {@code reconcile()} the two are joined into the winner ({@code joinedInto}),
   * Deactivated, no longer newest, and listed after it, before the key they replaced.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void lineageMarksBranchesAndJoins(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version, false);
    Kms kms = connect(s);
    KeyHandle k0 = aes(kms).create();
    List<String> tips = new ArrayList<>();
    for (int i = 0; i < 3; i++) {
      tick(s);
      tips.add(RotationAndNameChoiceTest.reKey(kms, k0.id()));
    }
    // The server moved the name to the first replacement: latest() chooses it.
    String t1 = tips.get(0), t2 = tips.get(1), t3 = tips.get(2);
    assertEquals(t1, k0.latest().id());
    List<String> order = List.of(t1, t3, t2, k0.id());
    for (boolean reconciled : new boolean[] {false, true}) {
      if (reconciled) assertEquals(t1, k0.reconcile().id());
      for (String from : order) {
        List<LineageKey> lineage = kms.keys().handle(from).lineage();
        assertEquals(order, listed(lineage), "from " + from + (reconciled ? ", reconciled" : ""));
        assertTrue(entry(lineage, t1).newest());
        assertFalse(entry(lineage, t1).branch());
        assertFalse(entry(lineage, k0.id()).branch());
        assertEquals(tips, entry(lineage, k0.id()).replacedBy());
        for (String t : List.of(t2, t3)) {
          LineageKey k = entry(lineage, t);
          assertTrue(k.branch(), t);
          assertEquals(!reconciled, k.newest(), t);
          assertEquals(reconciled ? List.of(t1) : List.of(), k.joinedInto(), t);
          assertEquals(List.of(k0.id()), k.replaced());
          assertEquals(reconciled ? KeyState.DEACTIVATED : KeyState.ACTIVE, k.attributes().state());
        }
      }
    }
    assertEquals(List.of(), s.violations());
  }

  /**
   * The listing's bounds. 65 rotations back is beyond one walk: {@code
   * UnsupportedException} naming {@code retirePredecessorsOlderThan}, within 67 requests; 65 on
   * likewise. Going back the listing stops at a destroyed key: once the oldest keys are retired, it
   * lists the kept keys and the newest destroyed one, one Get Attributes each.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void lineageStopsAt64RotationsAndAtADestroyedKey(KmipVersion version) {
    InMemoryKmipServer s = server(version, false);
    Kms kms = connect(s);
    List<KeyHandle> k = lineageOf(s, aes(kms).create(), 65);
    KeyHandle current = k.get(65);
    int before = s.exchanges();
    UnsupportedException back = assertThrows(UnsupportedException.class, current::lineage);
    assertTrue(s.exchanges() - before <= 67, "requests: " + (s.exchanges() - before));
    assertTrue(back.getMessage().contains("more than 64 rotations behind"), back.getMessage());
    assertTrue(back.getMessage().contains("retirePredecessorsOlderThan"), back.getMessage());
    UnsupportedException on = assertThrows(UnsupportedException.class, k.get(0)::lineage);
    assertTrue(on.getMessage().contains("more than 64 rotations on"), on.getMessage());
    assertEquals(
        ids(k.subList(0, 33)), ids(current.retirePredecessorsOlderThan(k.get(33), ROTATED)));
    before = s.exchanges();
    List<LineageKey> lineage = current.lineage();
    assertEquals(34, s.exchanges() - before);
    assertEquals(newestFirst(k.subList(32, 66)), listed(lineage));
    LineageKey end = lineage.get(33);
    assertEquals(KeyState.DESTROYED, end.attributes().state());
    assertEquals(List.of(), end.replaced(), "a destroyed key's predecessors are not read");
    assertEquals(List.of(k.get(33).id()), end.replacedBy());
  }

  /**
   * A link to a key that exists but cannot be read with these credentials is not passed
   * over (the keys behind it would be left out of a list used to decide what to retire): {@code
   * StateConflictException} naming it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void lineageRefusesALinkToAKeyItCannotRead(KmipVersion version) {
    InMemoryKmipServer s = server(version, false);
    List<KeyHandle> k = lineageOf(s, aes(connect(s)).create(), 2);
    String hidden = k.get(1).id();
    Kms denied =
        connect(
            s,
            r -> {
              if (RotationAndNameChoiceTest.isOperation(r, Operation.GET_ATTRIBUTES)
                  && RotationGraceTest.names(r, hidden))
                s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
            });
    StateConflictException e =
        assertThrows(
            StateConflictException.class, () -> denied.keys().handle(k.get(2).id()).lineage());
    assertTrue(
        e.getMessage().contains("names " + hidden + " (it exists but cannot be read"),
        e.getMessage());
    assertTrue(e.getMessage().contains("nothing was listed"), e.getMessage());
  }

  // ---- retirePredecessorsOlderThan ----

  /**
   * A database's hints keep one old version alive while older ones are free:
   * {@code retirePredecessorsOlderThan(k2)} from k4 retires k0 then k1, and keeps k2, k3 and k4
   * Active, their records opening through k4, the name and their own handles; a stranger's key of
   * the same shape and name is not touched. A repeat changes nothing; {@code keepFrom} equal to the
   * key is {@code retirePredecessors}.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void retiringOlderThanKeepsTheKeyAndTheNewerOnes(KmipVersion version) {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer s = server(version, unique);
      Kms kms = connect(s);
      KeyHandle stranger =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named(unique ? "other" : NAME)
              .create();
      List<KeyHandle> k = lineageOf(s, aes(kms).create(), 4);
      Map<String, byte[]> records = new LinkedHashMap<>();
      for (KeyHandle key : k) records.put(key.id(), key.seal(PLAIN, AAD));
      KeyHandle current = k.get(4);
      int retiring = sent(s, DeactivationTest.retiringOperation(version));
      assertEquals(
          ids(k.subList(0, 2)), ids(current.retirePredecessorsOlderThan(k.get(2), ROTATED)));
      assertEquals(ids(k.subList(0, 2)), destroyed(s), "oldest first");
      assertEquals(retiring + 2, sent(s, DeactivationTest.retiringOperation(version)));
      assertEquals(
          0,
          version == KmipVersion.V3_0 ? sent(s, Operation.REVOKE) : sent(s, Operation.DEACTIVATE));
      for (int i = 0; i < 5; i++)
        assertEquals(
            Optional.of(i < 2 ? KeyState.DESTROYED : KeyState.ACTIVE),
            s.state(k.get(i).id()),
            "k" + i);
      assertEquals(Optional.of(KeyState.ACTIVE), s.state(stranger.id()));
      for (KeyHandle key : k.subList(2, 5)) {
        byte[] sealed = records.get(key.id());
        assertArrayEquals(PLAIN, current.open(sealed, AAD));
        assertArrayEquals(PLAIN, key.open(sealed, AAD));
        assertArrayEquals(PLAIN, kms.keys().open(KeyQuery.byName(NAME), sealed, AAD));
      }
      StateConflictException gone =
          assertThrows(
              StateConflictException.class, () -> current.open(records.get(k.get(0).id()), AAD));
      assertEquals(Optional.of(KeyState.DESTROYED), gone.observedState());
      int mutations = mutations(s);
      assertEquals(List.of(), current.retirePredecessorsOlderThan(k.get(2), ROTATED));
      assertEquals(mutations, mutations(s), "a repeat changes nothing");
      assertEquals(
          ids(k.subList(2, 4)), ids(current.retirePredecessorsOlderThan(current, ROTATED)));
      assertEquals(List.of(), s.violations());
    }
  }

  /**
   * The rules of {@code retirePredecessors} hold: a Pre-Active older key is destroyed with
   * neither a Revoke nor a Deactivate (KMIP has no transition from Pre-Active to Deactivated); a
   * Deactivated one is destroyed without being revoked again; a lost reply is read back and counts
   * when the key is Deactivated; a failure part-way leaves the rest, and the repeat continues in
   * order.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void retiringOlderThanFollowsTheRulesOfRetirePredecessors(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version, false);
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
                s.failNext(ServerOperation.DESTROY, Fault.SERVER_FAILURE);
              }
            });
    KeyHandle k0 = aes(kms).createPreActive();
    KeyHandle k1 = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, k0.id()));
    k1.activate();
    List<KeyHandle> k = new ArrayList<>(List.of(k0));
    k.addAll(lineageOf(s, k1, 4));
    k.get(2).deactivate();
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(k0.id()));
    Operation retiring = DeactivationTest.retiringOperation(version);
    int before = sent(s, retiring);
    // k1's request is the first sent (k0 is Pre-Active): its reply is lost; k2's Destroy fails.
    s.failNext(DeactivationTest.retiring(version), Fault.REPLY_LOST);
    failDestroyOf.set(k.get(2).id());
    // k0 and k1 were destroyed before k2's Destroy failed: a partial completion that says so.
    PartialCompletionException partial =
        assertThrows(
            PartialCompletionException.class,
            () -> k.get(5).retirePredecessorsOlderThan(k.get(4), ROTATED));
    assertInstanceOf(ServerFailureException.class, partial.getCause());
    assertEquals(ids(k.subList(0, 2)), ids(partial.destroyed()));
    assertEquals(List.of(), partial.deactivated(), "k2 was Deactivated before the call");
    assertEquals(Optional.of(k.get(2).id()), partial.objectId());
    assertEquals(ids(k.subList(0, 3)), destroyed(s), "k2's Destroy was sent, and failed");
    assertEquals(Optional.of(KeyState.DESTROYED), s.state(k.get(1).id()));
    assertEquals(before + 1, sent(s, retiring), "k1 only: k0 is Pre-Active, k2 Deactivated");
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(k.get(2).id()));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(k.get(3).id()));
    assertEquals(
        ids(k.subList(2, 4)), ids(k.get(5).retirePredecessorsOlderThan(k.get(4), ROTATED)));
    assertEquals(
        List.of(k0.id(), k.get(1).id(), k.get(2).id(), k.get(2).id(), k.get(3).id()), destroyed(s));
    assertEquals(before + 2, sent(s, retiring));
    for (int i = 0; i < 6; i++)
      assertEquals(
          Optional.of(i < 4 ? KeyState.DESTROYED : KeyState.ACTIVE),
          s.state(k.get(i).id()),
          "k" + i);
    assertEquals(List.of(), s.violations());
  }

  /**
   * A {@code keepFrom} outside the key's lineage is refused before anything changes:
   * another lineage's key of the same shape and name, a key that names one of the lineage with its
   * own Replaced Object link only (no step), as {@link KeyMismatchException} (FIX_REQUEST); a
   * handle of another {@code Kms}, even with an identifier of the lineage, as {@code
   * IllegalArgumentException}.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aKeepFromOutsideTheLineageIsRefusedBeforeAnythingChanges(KmipVersion version)
      throws Exception {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer s = server(version, unique);
      Kms kms = connect(s);
      List<KeyHandle> k = lineageOf(s, aes(kms).create(), 2);
      KeyHandle s0 =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named(unique ? "other" : NAME)
              .create();
      KeyHandle s1 = rotated(s, s0);
      KeyHandle claimant =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named(unique ? "claimant" : NAME)
              .create();
      KmsContractTest.link(kms, claimant.id(), Enums.LinkType.REPLACED_OBJECT_LINK, k.get(1).id());
      int mutations = mutations(s);
      for (KeyHandle keepFrom : List.of(s0, s1, claimant)) {
        KeyMismatchException e =
            assertThrows(
                KeyMismatchException.class,
                () -> k.get(2).retirePredecessorsOlderThan(keepFrom, ROTATED));
        assertEquals(KmsException.Category.FIX_REQUEST, e.category());
        assertTrue(
            e.getMessage()
                .contains(keepFrom.id() + " is not in the rotation lineage of " + k.get(2).id()),
            e.getMessage());
      }
      InMemoryKmipServer elsewhere = server(version, unique);
      KeyHandle sameId = connect(elsewhere).keys().handle(k.get(0).id());
      assertThrows(
          IllegalArgumentException.class,
          () -> k.get(2).retirePredecessorsOlderThan(sameId, ROTATED));
      assertEquals(mutations, mutations(s));
      for (KeyHandle key : k) assertEquals(Optional.of(KeyState.ACTIVE), s.state(key.id()));
    }
  }

  /**
   * Keeping a key whose only confirmed links to the current key pass through the keys
   * retired would cut it off (its records would no longer open through the current key, and a
   * purge would strand it): refused, naming it, before anything changes. k0 was re-keyed twice (a1
   * and b1), a1 rotated to a2, and {@code reconcile()} joined b1 into a2: keeping from a1 or from
   * b1 would retire k0, b1's only step to the lineage. Before reconcile the call refuses as {@code
   * retirePredecessors} does (another newest key).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void keepingAKeyThatWouldBeCutOffIsRefused(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version, false);
    Kms kms = connect(s);
    KeyHandle k0 = aes(kms).create();
    tick(s);
    KeyHandle a1 = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, k0.id()));
    tick(s);
    KeyHandle b1 = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, k0.id()));
    KeyHandle a2 = rotated(s, a1);
    int mutations = mutations(s);
    StateConflictException forked =
        assertThrows(
            StateConflictException.class, () -> a2.retirePredecessorsOlderThan(a1, ROTATED));
    assertTrue(
        forked.getMessage().contains("other newest keys, [" + b1.id() + "]"), forked.getMessage());
    assertEquals(a2, a2.reconcile());
    assertEquals(List.of(a2.id()), entry(a2.lineage(), b1.id()).joinedInto());
    mutations = mutations(s);
    for (KeyHandle keepFrom : List.of(a1, b1)) {
      StateConflictException cut =
          assertThrows(
              StateConflictException.class,
              () -> a2.retirePredecessorsOlderThan(keepFrom, ROTATED));
      assertTrue(
          cut.getMessage().contains("would cut [" + b1.id() + "] off from " + a2.id()),
          cut.getMessage());
    }
    assertEquals(mutations, mutations(s));
    assertEquals(
        List.of(), a2.retirePredecessorsOlderThan(k0, ROTATED), "nothing is older than k0");
    assertEquals(List.of(b1.id(), k0.id(), a1.id()), ids(a2.retirePredecessors(ROTATED)));
  }

  // ---- retirement past 64 rotations ----

  /**
   * On a server that keeps destroyed keys with their links (the in-memory server; keytend-kmip-server
   * keeps destroyed objects), a lineage retired after every rotation stayed retirable only for 64
   * rotations: from the 65th, {@code deactivatePredecessors} and {@code retirePredecessors}
   * refused for good (UnsupportedException, "more than 64 rotations behind it", advising a handle
   * on an older key, which is never the only newest key). Now their walk back stops at a destroyed
   * key: 70 rotations, each followed by both calls, at most 10 requests each time; the listing
   * shows the current key and the newest destroyed one.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void retiringAfterEveryRotationGoesOnPast64Rotations(KmipVersion version) {
    InMemoryKmipServer s = server(version, false);
    Kms kms = connect(s);
    KeyHandle key = aes(kms).create();
    for (int i = 1; i <= 70; i++) {
      KeyHandle next = rotated(s, key);
      int before = s.exchanges();
      assertEquals(List.of(key.id()), ids(next.deactivatePredecessors()), "rotation " + i);
      assertEquals(List.of(key.id()), ids(next.retirePredecessors(ROTATED)), "rotation " + i);
      assertTrue(
          s.exchanges() - before <= 10,
          "rotation " + i + ": " + (s.exchanges() - before) + " requests");
      key = next;
    }
    List<LineageKey> lineage = key.lineage();
    assertEquals(2, lineage.size());
    assertEquals(KeyState.DESTROYED, lineage.get(1).attributes().state());
    assertEquals(List.of(), s.violations());
  }

  /**
   * A destroyed key just past the 64 generations a walk follows ends the walk instead of
   * counting as beyond it: k0 retired after one rotation, then 64 more, so the current key has 64
   * live keys behind it and the destroyed k0 65th. The listing reaches k0 (66 keys, 66 requests) and
   * {@code retirePredecessors} retires the 64 live ones.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aDestroyedKeyJustPastTheLimitEndsTheWalk(KmipVersion version) {
    InMemoryKmipServer s = server(version, false);
    Kms kms = connect(s);
    List<KeyHandle> k = lineageOf(s, aes(kms).create(), 1);
    assertEquals(List.of(k.get(0).id()), ids(k.get(1).retirePredecessors(ROTATED)));
    k = lineageOf(s, k.get(1), 64);
    k.add(0, kms.keys().handle(destroyed(s).get(0)));
    KeyHandle current = k.get(65);
    int before = s.exchanges();
    List<LineageKey> lineage = current.lineage();
    assertEquals(66, s.exchanges() - before);
    assertEquals(newestFirst(k), listed(lineage));
    assertEquals(ids(k.subList(1, 65)), ids(current.retirePredecessors(ROTATED)));
  }

  /**
   * A lineage of 100 rotations never retired is beyond {@code retirePredecessors} (the
   * message now names the way out instead of "a handle on an older key"); {@code
   * retirePredecessorsOlderThan} walks from {@code keepFrom}, so keeping from k60 retires k0 to
   * k59, and then {@code retirePredecessors} the rest. A {@code keepFrom} with more than 64 live
   * keys behind it, or more than 64 rotations before the current key, is refused, nothing sent.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aLineageOfAHundredRotationsIsRetiredInSteps(KmipVersion version) {
    InMemoryKmipServer s = server(version, false);
    Kms kms = connect(s);
    List<KeyHandle> k = lineageOf(s, aes(kms).create(), 100);
    KeyHandle current = k.get(100);
    byte[] record = current.seal(PLAIN, AAD);
    int mutations = mutations(s);
    UnsupportedException all =
        assertThrows(UnsupportedException.class, () -> current.retirePredecessors(ROTATED));
    assertTrue(
        all.getMessage().contains("retirePredecessorsOlderThan(keepFrom, reason)"),
        all.getMessage());
    UnsupportedException behind =
        assertThrows(
            UnsupportedException.class,
            () -> current.retirePredecessorsOlderThan(k.get(90), ROTATED));
    assertTrue(
        behind.getMessage().contains("retire in steps, keeping from an older key first"),
        behind.getMessage());
    UnsupportedException ahead =
        assertThrows(
            UnsupportedException.class,
            () -> current.retirePredecessorsOlderThan(k.get(20), ROTATED));
    assertTrue(
        ahead.getMessage().contains("is not within 64 rotations after " + k.get(20).id()),
        ahead.getMessage());
    assertEquals(mutations, mutations(s));
    assertEquals(
        ids(k.subList(0, 60)), ids(current.retirePredecessorsOlderThan(k.get(60), ROTATED)));
    assertEquals(ids(k.subList(60, 100)), ids(current.retirePredecessors(ROTATED)));
    assertEquals(ids(k.subList(0, 100)), destroyed(s));
    assertArrayEquals(PLAIN, current.open(record, AAD));
  }

  // ---- records older than 64 rotations ----

  /**
   * A record sealed 65 rotations earlier: through the current key's handle, a {@code CurrentKey}
   * and {@code KeyQuery.name} (the name moved on), it is refused within 66 requests, with a message naming
   * the direct paths. Bound to an attribute Re-key copies ({@code KeyQuery.all().custom}) or to a
   * manifest of identifiers ({@code KeyQuery.all().ids}), the record's own key matches: sealed
   * records, ciphertexts and sealed streams open with one Get Attributes and one Decrypt.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRecordSixtyFiveRotationsOldOpensByAnAttributeOrAManifest(KmipVersion version)
      throws Exception {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer s = server(version, unique);
      Kms kms = connect(s);
      KeyHandle first = aes(kms).custom(PURPOSE, "orders").create();
      List<String> manifest = new ArrayList<>(List.of(first.id()));
      byte[] sealed = first.seal(PLAIN, AAD);
      Ciphertext encrypted = first.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
      byte[] stream = sealedStream(first);
      KeyHandle key = first;
      for (int i = 0; i < 65; i++) {
        key = rotated(s, key);
        manifest.add(key.id());
      }
      KeyHandle current = key;
      int before = s.exchanges();
      UnsupportedException refused =
          assertThrows(UnsupportedException.class, () -> current.open(sealed, AAD));
      assertTrue(s.exchanges() - before <= 66, "requests: " + (s.exchanges() - before));
      for (String part :
          List.of(
              "KeyQuery.byIds(", "KeyQuery.all().custom(", "\"Records older than 64 rotations\""))
        assertTrue(refused.getMessage().contains(part), refused.getMessage());
      assertThrows(UnsupportedException.class, () -> current.decrypt(encrypted, AAD));
      assertThrows(UnsupportedException.class, () -> kms.keys().current(NAME).open(sealed, AAD));
      before = s.exchanges();
      UnsupportedException byName =
          assertThrows(
              UnsupportedException.class,
              () -> kms.keys().open(KeyQuery.byName(NAME), sealed, AAD));
      assertTrue(s.exchanges() - before <= 66, "requests: " + (s.exchanges() - before));
      for (String part :
          List.of(
              "KeyQuery.byIds(", "KeyQuery.all().custom(", "\"Records older than 64 rotations\""))
        assertTrue(byName.getMessage().contains(part), byName.getMessage());
      byte[] recent = current.seal(PLAIN, AAD);
      for (KeyQuery bound :
          List.of(KeyQuery.all().custom(PURPOSE, "orders"), KeyQuery.all().ids(manifest))) {
        before = s.exchanges();
        assertArrayEquals(PLAIN, kms.keys().open(bound, sealed, AAD));
        assertEquals(2, s.exchanges() - before, bound + ": one Get Attributes and one Decrypt");
        before = s.exchanges();
        assertArrayEquals(PLAIN, kms.keys().decrypt(bound, encrypted, AAD));
        assertEquals(2, s.exchanges() - before, bound + ": a ciphertext");
        before = s.exchanges();
        try (InputStream in = kms.keys().opening(bound, new ByteArrayInputStream(stream), AAD)) {
          assertArrayEquals(PLAIN, in.readAllBytes());
        }
        assertEquals(2, s.exchanges() - before, bound + ": a stream");
        before = s.exchanges();
        assertArrayEquals(PLAIN, kms.keys().open(bound, recent, AAD));
        assertEquals(2, s.exchanges() - before, bound + ": the current key's record");
      }
      assertEquals(List.of(), s.violations());
    }
  }

  /**
   * The bindings refuse a key of the right shape outside them. A key under the same name
   * without the attribute: {@code BAD_DATA} through the attribute. One that carries the attribute
   * too opens through it (the attribute is only as strong as the access control on it, as the
   * guide says), and is {@code BAD_DATA} through the manifest within one request; so is a key that
   * names a key of the lineage with its own Replaced Object link only. The manifest is never sent:
   * a search with it is {@code UnsupportedException} before any request.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aForeignKeyIsRefusedByTheBinding(KmipVersion version) throws Exception {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer s = server(version, unique);
      Kms kms = connect(s);
      List<KeyHandle> k = lineageOf(s, aes(kms).custom(PURPOSE, "orders").create(), 3);
      KeyQuery attribute = KeyQuery.all().custom(PURPOSE, "orders");
      KeyQuery manifest = KeyQuery.all().ids(ids(k));
      KeyHandle outsider =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named(unique ? "outsider" : NAME)
              .create();
      byte[] foreign = outsider.seal(PLAIN, AAD);
      for (KeyQuery bound : List.of(attribute, manifest)) {
        KeyMismatchException e =
            assertThrows(KeyMismatchException.class, () -> kms.keys().open(bound, foreign, AAD));
        assertEquals(KmsException.Category.BAD_DATA, e.category(), bound.toString());
      }
      KeyHandle lookalike =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named(unique ? "lookalike" : NAME)
              .custom(PURPOSE, "orders")
              .create();
      byte[] forged = lookalike.seal(PLAIN, AAD);
      Ciphertext forgedCiphertext = lookalike.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
      assertArrayEquals(
          PLAIN,
          kms.keys().open(attribute, forged, AAD),
          "whoever may set the attribute is trusted");
      int before = s.exchanges();
      KeyMismatchException notListed =
          assertThrows(KeyMismatchException.class, () -> kms.keys().open(manifest, forged, AAD));
      assertEquals(KmsException.Category.BAD_DATA, notListed.category());
      assertEquals(1, s.exchanges() - before);
      KeyMismatchException notListedCiphertext =
          assertThrows(
              KeyMismatchException.class,
              () -> kms.keys().decrypt(manifest, forgedCiphertext, AAD));
      assertEquals(KmsException.Category.BAD_DATA, notListedCiphertext.category());
      KeyHandle claimant =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named(unique ? "claimant" : NAME)
              .custom(PURPOSE, "orders")
              .create();
      KmsContractTest.link(kms, claimant.id(), Enums.LinkType.REPLACED_OBJECT_LINK, k.get(1).id());
      byte[] claimed = claimant.seal(PLAIN, AAD);
      before = s.exchanges();
      KeyMismatchException noStep =
          assertThrows(KeyMismatchException.class, () -> kms.keys().open(manifest, claimed, AAD));
      assertEquals(KmsException.Category.BAD_DATA, noStep.category());
      assertTrue(s.exchanges() - before <= 3, "requests: " + (s.exchanges() - before));
      before = s.exchanges();
      UnsupportedException search =
          assertThrows(UnsupportedException.class, () -> kms.keys().list(manifest));
      assertTrue(search.getMessage().contains("never searched"), search.getMessage());
      assertThrows(UnsupportedException.class, () -> kms.keys().locate(manifest).findFirst());
      assertThrows(
          UnsupportedException.class, () -> kms.keys().locateWithAttributes(manifest).findFirst());
      assertEquals(before, s.exchanges(), "nothing sent");
    }
  }

  /** The application's own store of its keys' identifiers, as the guide's example uses it. */
  static final class Manifest {
    final List<String> ids = new ArrayList<>();

    void add(String id) {
      ids.add(id);
    }

    List<String> ids() {
      return List.copyOf(ids);
    }
  }

  /**
   * The guide's "Retiring part of a lineage" and "Records older than 64 rotations"
   * (docs/operating-keys.md), as written: a daily-run job rotating every 30 days records each new
   * key in a manifest; after 70 rotations the first record opens through the attribute and the
   * manifest, and not through the current key; a five-rotation lineage is listed and retired up to
   * the oldest key still needed.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theGuideSectionsRunAsWritten(KmipVersion version) {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer s = server(version, unique);
      Kms kms = connect(s);
      CustomAttribute purpose = CustomAttribute.client("purpose");
      KeyHandle kek =
          kms.keys()
              .createAes(256)
              .named("archive-kek")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .custom(purpose, "archive")
              .findOrCreate();
      Manifest manifest = new Manifest();
      manifest.add(kek.id());
      byte[] recordId = "order-1".getBytes(StandardCharsets.UTF_8);
      byte[] sealed = kek.seal(PLAIN, recordId);
      for (int day = 1; day <= 70 * 30; day++) {
        clocks.get(s).now = clocks.get(s).now.plus(Duration.ofDays(1));
        KeyHandle next = kek.rotateIfActiveFor(Duration.ofDays(30));
        if (!next.equals(kek)) manifest.add(next.id());
        kek = next;
      }
      assertEquals(71, manifest.ids().size());
      KeyHandle current = kek;
      assertThrows(UnsupportedException.class, () -> current.open(sealed, recordId));
      assertArrayEquals(
          PLAIN, kms.keys().open(KeyQuery.all().custom(purpose, "archive"), sealed, recordId));
      assertArrayEquals(
          PLAIN, kms.keys().open(KeyQuery.all().ids(manifest.ids()), sealed, recordId));

      // Retiring part of a lineage: something still needs the key two rotations back.
      List<KeyHandle> k = lineageOf(s, aes(kms).create(), 5);
      KeyHandle vault = k.get(5);
      List<LineageKey> versions = vault.lineage();
      String oldestStillNeeded = versions.get(2).id();
      KeyHandle keepFrom = kms.keys().handle(oldestStillNeeded);
      List<KeyHandle> retired =
          vault.retirePredecessorsOlderThan(keepFrom, RevocationReason.superseded("rotated"));
      assertEquals(ids(k.subList(0, 3)), ids(retired));
      assertEquals(
          newestFirst(k.subList(2, 6)),
          listed(vault.lineage()),
          "the kept keys and the newest destroyed one");
    }
  }

  /** {@code KeyQuery.ids} copies a manifest of at least one identifier, none empty. */
  @Test
  void idsTakesAManifest() {
    assertThrows(IllegalArgumentException.class, () -> KeyQuery.all().ids(List.of()));
    assertThrows(IllegalArgumentException.class, () -> KeyQuery.all().ids(List.of("")));
    assertThrows(NullPointerException.class, () -> KeyQuery.all().ids(Arrays.asList("a", null)));
    assertThrows(
        NullPointerException.class, () -> KeyQuery.all().ids((java.util.Collection<String>) null));
    List<String> manifest = new ArrayList<>(List.of("a"));
    KeyQuery query = KeyQuery.byName("n").ids(manifest).state(KeyState.ACTIVE);
    manifest.add("b");
    assertEquals("KeyQuery[name=n, state=ACTIVE, ids=[a]]", query.toString());
    assertFalse(KeyQuery.all().ids(List.of("a")).isEmpty());
    assertEquals(
        "KeyQuery[ids=4 identifiers]", KeyQuery.all().ids(List.of("a", "b", "c", "d")).toString());
    assertEquals(
        "KeyQuery[ids=[b]]", KeyQuery.all().ids(List.of("a")).ids(List.of("b")).toString());
  }

  /**
   * The static {@code KeyQuery.byIds(String...)} starts a manifest query, with the rules of {@code
   * ids(Collection)}, and other filters add to it.
   */
  @Test
  void idsStartsAManifestQuery() {
    assertEquals("KeyQuery[ids=[a, b]]", KeyQuery.byIds("a", "b").toString());
    assertEquals(
        KeyQuery.all().ids(List.of("a", "b")).toString(), KeyQuery.byIds("a", "b", "a").toString());
    assertEquals(
        "KeyQuery[state=ACTIVE, ids=[a]]", KeyQuery.byIds("a").state(KeyState.ACTIVE).toString());
    assertThrows(IllegalArgumentException.class, () -> KeyQuery.byIds());
    assertThrows(IllegalArgumentException.class, () -> KeyQuery.byIds("a", ""));
    assertThrows(NullPointerException.class, () -> KeyQuery.byIds("a", null));
    assertThrows(NullPointerException.class, () -> KeyQuery.byIds((String[]) null));
    String[] manifest = {"a"};
    KeyQuery query = KeyQuery.byIds(manifest);
    manifest[0] = "b";
    assertEquals("KeyQuery[ids=[a]]", query.toString(), "copied");
  }

  /**
   * {@code ids(String...)} and {@code name(String)} called on a query keep its filters. As static
   * methods ({@code KeyQuery.ids(String...)}, {@code KeyQuery.name(String)}), the same call
   * compiled and started a new query, dropping them.
   */
  @Test
  void idsAndNameCalledOnAQueryKeepItsFilters() {
    CustomAttribute family = CustomAttribute.client("family");
    KeyQuery q = KeyQuery.all().group("orders").state(KeyState.ACTIVE).custom(family, "orders");
    KeyQuery withIds = q.ids("a", "b");
    assertEquals(q.ids(List.of("a", "b")).toString(), withIds.toString());
    for (String kept : List.of("group=orders", "state=ACTIVE", "orders", "ids=[a, b]"))
      assertTrue(withIds.toString().contains(kept), withIds + " keeps " + kept);
    KeyQuery named = q.name("n1").name("n2");
    for (String kept : List.of("name=n2", "group=orders", "state=ACTIVE", "orders"))
      assertTrue(named.toString().contains(kept), named + " keeps " + kept);
    assertFalse(named.toString().contains("n1"), "a later name replaces it");
    assertEquals(KeyQuery.all().name("n").toString(), KeyQuery.byName("n").toString());
    assertThrows(NullPointerException.class, () -> q.name(null));
    assertThrows(IllegalArgumentException.class, () -> q.ids());
  }
}
