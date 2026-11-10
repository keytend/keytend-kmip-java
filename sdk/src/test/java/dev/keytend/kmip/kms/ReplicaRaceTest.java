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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Races between two replicas of one KMS, on the in-memory server: lost Activate and rotation races,
 * recovery after a compromise, rewrap results and handles that follow latest(). Each race is staged
 * deterministically: the losing caller's transport lets the winner act first, then sends the
 * loser's request.
 */
class ReplicaRaceTest {
  static final byte[] PLAIN = ConcurrentReplacementChecks.PLAIN,
      AAD = ConcurrentReplacementChecks.AAD;
  static final String NAME = "vault";

  final List<Kms> clients = new CopyOnWriteArrayList<>();
  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    servers.add(s);
    return s;
  }

  Kms connect(InMemoryKmipServer server) {
    Kms kms = server.connect();
    clients.add(kms);
    return kms;
  }

  /**
   * A client whose first request of {@code op} first runs {@code winner} (another caller's move,
   * through another client), then goes to the server.
   */
  Kms losing(InMemoryKmipServer server, Operation op, Runnable winner) {
    return losing(server, op, winner, new KmsListener() {});
  }

  Kms losing(InMemoryKmipServer server, Operation op, Runnable winner, KmsListener listener) {
    boolean[] done = {false};
    Kms kms =
        Kms.connect(
            server
                .configure()
                .addListener(listener)
                .transport(
                    e ->
                        request -> {
                          if (!done[0] && RotationAndNameChoiceTest.isOperation(request, op)) {
                            done[0] = true;
                            winner.run();
                          }
                          return server.exchange(request);
                        })
                .build());
    clients.add(kms);
    return kms;
  }

  static RevocationReason leaked() {
    return RevocationReason.keyCompromise(
        "leaked", java.time.Instant.parse("2026-10-27T10:00:00Z"));
  }

  static KeyCreation aes(Kms kms) {
    return kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named(NAME);
  }

  // ---- a lost Activate race ----

  /**
   * Two replicas start at once and find the same Pre-Active key (its creator, or another starting
   * caller, has not activated it yet); the other activates it first. KMIP 1.x refuses the second
   * Activate with Permission Denied (KMIP 1.4 Table 346); reported as {@code
   * PermissionDeniedException} (FIX_ACCESS), the replica would not start. On 2.x it is Wrong Key
   * Lifecycle State. The state is read after any refusal, and the key, Active, is the result.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void aLostActivateRaceInFindOrCreateReturnsTheKey(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms admin = connect(s);
    KeyHandle left = aes(admin).createPreActive();
    Kms loser = losing(s, Operation.ACTIVATE, () -> admin.keys().handle(left.id()).activate());
    KeyHandle found = aes(loser).findOrCreate();
    assertEquals(left.id(), found.id());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(left.id()));
    if (version.compareTo(KmipVersion.V1_4) >= 0)
      assertArrayEquals(PLAIN, found.open(found.seal(PLAIN, AAD), AAD));
    assertEquals(1, s.ids().size(), "nothing created");
  }

  /**
   * The same for key pairs: {@code KeyPairCreation.findOrCreate()} activates each key the same way.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void aLostActivateRaceInKeyPairFindOrCreateReturnsThePair(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms admin = connect(s);
    KeyPairHandle left = KeyPairsAndSecretsTest.signer(admin).createPreActive();
    Kms loser =
        losing(s, Operation.ACTIVATE, () -> admin.keys().handle(left.privateKey().id()).activate());
    KeyPairHandle found = KeyPairsAndSecretsTest.signer(loser).findOrCreate();
    assertEquals(KeyPairsAndSecretsTest.ids(left), KeyPairsAndSecretsTest.ids(found));
    KeyPairsAndSecretsTest.assertActive(s, found);
  }

  /**
   * The audit of every Activate: {@code activate()} itself gives the same failure the same category
   * on every version. Activating an Active key is STATE naming the state (on 1.x the server's
   * reason stays Permission Denied); a Permission Denied for a key that is still Pre-Active is the
   * server's access policy, and stays FIX_ACCESS.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void activatingAnActiveKeyIsStateOnEveryVersion(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms).create();
    StateConflictException e = assertThrows(StateConflictException.class, key::activate);
    assertTrue(e.getMessage().contains("is ACTIVE, not Pre-Active"), e.getMessage());
    assertEquals(
        Optional.of(
            version.compareTo(KmipVersion.V2_0) < 0
                ? Enums.ResultReason.PERMISSION_DENIED
                : Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE),
        e.protocolReason());

    KeyHandle pre =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
    s.failNext(ServerOperation.ACTIVATE, Fault.PERMISSION_DENIED);
    assertThrows(PermissionDeniedException.class, pre::activate);
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(pre.id()));
  }

  /**
   * An Activate in {@code findOrCreate} whose reply is lost after the server activated the key is
   * read back: the key is Active, so it is the result, not an {@code OutcomeUnknownException}.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aLostActivateReplyInFindOrCreateIsReadBack(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle left = aes(kms).createPreActive();
    s.failNext(ServerOperation.ACTIVATE, Fault.REPLY_LOST);
    KeyHandle found = aes(connect(s)).findOrCreate();
    assertEquals(left.id(), found.id());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(left.id()));
  }

  // ---- a lost rotation race ----

  /** What a listener heard of concurrent replacements: key and replacements, in order. */
  static final class Heard implements KmsListener {
    final List<List<String>> concurrent = new CopyOnWriteArrayList<>();

    @Override
    public void concurrentReplacement(String keyId, List<String> replacements) {
      List<String> e = new ArrayList<>(List.of(keyId));
      e.addAll(replacements);
      concurrent.add(e);
    }
  }

  /**
   * Two instances rotate one key at the same moment on a server that refuses a second Re-key
   * (keytend-kmip-server; KMIP 1.4 Table 331 prescribes Permission Denied). Both pass the check
   * (the key names no replacement), the other's Re-key goes first, and the server refuses this one.
   * Not {@code PermissionDeniedException} (FIX_ACCESS: "fix credentials, do not retry"): the key is
   * read again, and the call is STATE "replaced meanwhile" naming the winner, with the server's
   * refusal as cause, and the listener hears of it. The lineage is not forked.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void aLostRotationRaceIsStateNamingTheWinner(KmipVersion version) {
    InMemoryKmipServer s = server(version).refuseSecondReKey(true);
    Kms admin = connect(s);
    KeyHandle key = aes(admin).create();
    KeyHandle[] won = new KeyHandle[1];
    Heard heard = new Heard();
    Kms loser =
        losing(s, Operation.RE_KEY, () -> won[0] = admin.keys().handle(key.id()).rotate(), heard);
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> loser.keys().handle(key.id()).rotate());
    assertTrue(e.getMessage().contains("was replaced meanwhile by " + won[0].id()), e.getMessage());
    assertTrue(e.getMessage().contains("use latest()"), e.getMessage());
    assertInstanceOf(PermissionDeniedException.class, e.getCause());
    assertEquals(Optional.of(Enums.ResultReason.PERMISSION_DENIED), e.protocolReason());
    assertEquals(KmsException.Category.STATE, e.category());
    assertEquals(List.of(List.of(key.id(), won[0].id())), heard.concurrent);
    assertEquals(List.of(won[0].id()), s.links(key.id(), LinkKind.REPLACEMENT), "not forked");
    assertEquals(won[0].id(), loser.keys().handle(key.id()).latest().id());
  }

  /**
   * {@code rotateOrLatest()}, the call for a scheduled rotation job: a job that fires twice from one
   * key rotates once. The second firing, racing the first on a server that refuses a second Re-key,
   * returns the winner; one that comes later with the same handle returns it without a Re-key. On
   * a server that re-keys twice, the race forks as {@code rotate()} does (each gets its own
   * replacement, the listener hears of the other), and the later firing still returns the current
   * key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void rotateOrLatestRotatesOnceForAJobThatFiresTwice(KmipVersion version) {
    for (boolean refuse : new boolean[] {true, false}) {
      InMemoryKmipServer s = server(version).refuseSecondReKey(refuse);
      Kms admin = connect(s);
      KeyHandle key = aes(admin).create();
      KeyHandle[] won = new KeyHandle[1];
      Heard heard = new Heard();
      Kms loser =
          losing(
              s,
              Operation.RE_KEY,
              () -> won[0] = admin.keys().handle(key.id()).rotateOrLatest(),
              heard);
      KeyHandle second = loser.keys().handle(key.id()).rotateOrLatest();
      assertNotEquals(key.id(), won[0].id());
      assertEquals(Optional.of(KeyState.ACTIVE), s.state(second.id()));
      if (refuse) {
        assertEquals(won[0].id(), second.id(), "the winner");
        assertEquals(List.of(won[0].id()), s.links(key.id(), LinkKind.REPLACEMENT));
      } else {
        assertNotEquals(won[0].id(), second.id(), "a fork, as rotate()");
        assertEquals(2, s.links(key.id(), LinkKind.REPLACEMENT).size());
      }
      assertEquals(1, heard.concurrent.size(), heard.concurrent.toString());
      String current = admin.keys().handle(key.id()).latest().id();
      // A later firing with the same handle: no Re-key.
      int reKeys = reKeys(s);
      assertEquals(current, admin.keys().handle(key.id()).rotateOrLatest().id());
      assertEquals(reKeys, reKeys(s), "no Re-key sent");
      // rotate() on the same handle is refused, as before.
      assertThrows(StateConflictException.class, () -> admin.keys().handle(key.id()).rotate());
    }
  }

  static int reKeys(InMemoryKmipServer s) {
    return (int)
        s.protocolRequests().stream()
            .filter(r -> RotationAndNameChoiceTest.isOperation(r, Operation.RE_KEY))
            .count();
  }

  /**
   * {@code rotateOrLatest()} returns the current key Active: one its creator left Pre-Active is
   * activated, as the creator would next; one that is Compromised is STATE saying to replace it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void rotateOrLatestReturnsTheCurrentKeyActive(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms).create();
    KeyHandle next = aes(kms).createPreActive();
    KmsContractTest.link(kms, key.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, next.id());
    KmsContractTest.link(kms, next.id(), Enums.LinkType.REPLACED_OBJECT_LINK, key.id());
    assertEquals(next.id(), key.rotateOrLatest().id());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(next.id()));
    next.revoke(leaked());
    StateConflictException e = assertThrows(StateConflictException.class, key::rotateOrLatest);
    assertTrue(e.getMessage().contains("replaceCompromised()"), e.getMessage());
  }

  /**
   * A refused Re-key of a key nobody replaced is as the server said, unless the key's state forbids
   * a Re-key: a Permission Denied for an Active key stays FIX_ACCESS; for a key Deactivated after
   * the SDK's read (a key already Deactivated is refused before anything is sent) it is STATE naming the state, the same category as on servers that answer with a
   * lifecycle reason.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aRefusedReKeyOfAKeyNobodyReplacedIsAsTheServerSaid(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms).create();
    s.failNext(ServerOperation.RE_KEY, Fault.PERMISSION_DENIED);
    assertThrows(PermissionDeniedException.class, key::rotate);
    boolean[] revoked = {false};
    Kms racing =
        Kms.connect(
            s.configure()
                .transport(
                    e ->
                        request -> {
                          if (!revoked[0]
                              && RotationAndNameChoiceTest.isOperation(request, Operation.RE_KEY)) {
                            revoked[0] = true;
                            key.revoke(RevocationReason.superseded("retired"));
                            s.failNext(ServerOperation.RE_KEY, Fault.PERMISSION_DENIED);
                          }
                          return s.exchange(request);
                        })
                .build());
    clients.add(racing);
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> racing.keys().handle(key.id()).rotate());
    assertTrue(
        e.getMessage().contains("is DEACTIVATED, so the server refused to re-key it"),
        e.getMessage());
    assertInstanceOf(PermissionDeniedException.class, e.getCause());
    assertEquals(Optional.of(KeyState.DEACTIVATED), e.observedState(), "read back");
    e = assertThrows(StateConflictException.class, key::rotate);
    assertTrue(
        e.getMessage().contains("is DEACTIVATED and names no replacement, so it is not rotated"),
        e.getMessage());
  }

  /**
   * {@code replaceCompromised} is consistent with it: two instances replace one Compromised key at
   * once on a server that refuses a second Re-key; the loser's Re-key is refused, it finds the
   * winner's replacement and finishes with it (no fallback key is created), on every version.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void aLostCompromiseReplacementRaceFinishesWithTheWinner(KmipVersion version) {
    InMemoryKmipServer s = server(version).refuseSecondReKey(true);
    Kms admin = connect(s);
    KeyHandle key = aes(admin).create();
    key.revoke(leaked());
    KeyHandle[] won = new KeyHandle[1];
    Kms loser =
        losing(
            s,
            Operation.RE_KEY,
            () -> won[0] = admin.keys().handle(key.id()).replaceCompromised(leaked()));
    KeyHandle mine = loser.keys().handle(key.id()).replaceCompromised(leaked());
    assertEquals(won[0].id(), mine.id());
    assertEquals(2, s.ids().size(), "no fallback key");
    assertEquals(List.of(NAME), s.names(mine.id()));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(mine.id()));
  }

  /** The fake's mode itself: off by default (a second Re-key forks), on: Permission Denied on every version. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void theFakeRefusesASecondReKeyOnlyWhenAsked(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms).create();
    var client = kms.protocol();
    var reKey = dev.keytend.kmip.client.Requests.reKey().uniqueIdentifier(key.id()).build();
    assertTrue(client.execute(reKey).successful());
    assertTrue(client.execute(reKey).successful(), "off: forks");
    s.refuseSecondReKey(true);
    var refused = client.execute(reKey);
    assertTrue(refused.hasReason(Enums.ResultReason.PERMISSION_DENIED), refused.toString());
    assertEquals(2, s.links(key.id(), LinkKind.REPLACEMENT).size());
    // A key never re-keyed still is.
    KeyHandle other = aes(kms).create();
    assertTrue(
        client
            .execute(dev.keytend.kmip.client.Requests.reKey().uniqueIdentifier(other.id()).build())
            .successful());
  }

  // ---- recovery after a .replacingCompromised() startup ----

  record Rec(String id, byte[] sealed, byte[] aad) {}

  static Rec rec(KeyHandle k, String id) {
    byte[] aad = id.getBytes(java.nio.charset.StandardCharsets.UTF_8);
    return new Rec(
        id, k.seal(("data of " + id).getBytes(java.nio.charset.StandardCharsets.UTF_8), aad), aad);
  }

  /**
   * A process restarts while the key is Compromised and starts with {@code
   * findOrCreate().replacingCompromised()}; it never held the revoked key's handle, and the
   * replacement's handle refuses the old records (STATE, by design). The guide's loop over {@code
   * current.compromisedPredecessors()} re-seals every record of the lineage (the compromised key's,
   * and an older generation's) under the replacement; a stranger's Compromised key that names the
   * replacement with a one-sided link is not among the predecessors, and its record is refused
   * (STATE), not re-sealed.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void recoveryAfterARestartFollowsTheGuide(KmipVersion version) throws Exception {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer s = server(version).uniqueNames(unique);
      Kms before = connect(s);
      KeyHandle k0 = aes(before).findOrCreate();
      List<Rec> store = new ArrayList<>(List.of(rec(k0, "a"), rec(k0, "b")));
      KeyHandle k1 = k0.rotate();
      store.add(rec(k1, "c"));
      k1.revoke(leaked());
      KeyHandle stranger =
          before.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
      Rec forged = rec(stranger, "d");
      stranger.revoke(leaked());
      before.close();

      Kms restarted = connect(s);
      KeyHandle current = aes(restarted).replacingCompromised().findOrCreate();
      assertNotEquals(k1.id(), current.id());
      // The stranger names the replacement as its successor; only its own key has the link.
      KmsContractTest.link(
          restarted, stranger.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, current.id());
      // And a one-sided link on the replacement (half of a link, or written by someone who may):
      // a Compromised key that does not name the replacement back is not a predecessor either.
      KeyHandle other =
          restarted.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
      other.revoke(leaked());
      KmsContractTest.link(
          restarted, current.id(), Enums.LinkType.REPLACED_OBJECT_LINK, other.id());
      // Before recovery the replacement refuses the compromised key's record.
      assertThrows(
          StateConflictException.class,
          () -> current.open(store.get(2).sealed(), store.get(2).aad()));

      List<KeyHandle> predecessors = current.compromisedPredecessors();
      assertEquals(List.of(k1.id()), predecessors.stream().map(KeyHandle::id).toList());
      Map<String, KeyHandle> compromised = new HashMap<>();
      for (KeyHandle k : predecessors) compromised.put(k.id(), k);
      List<Rec> moved = new ArrayList<>();
      for (Rec r : store) {
        KeyHandle from = compromised.getOrDefault(KmsKeys.sealedKeyId(r.sealed()), current);
        moved.add(new Rec(r.id(), from.rewrapTo(current, r.sealed(), r.aad()), r.aad()));
      }
      for (Rec r : moved) {
        assertEquals(current.id(), KmsKeys.sealedKeyId(r.sealed()));
        assertArrayEquals(
            ("data of " + r.id()).getBytes(java.nio.charset.StandardCharsets.UTF_8),
            current.open(r.sealed(), r.aad()));
      }
      // Repeating the loop changes nothing.
      for (Rec r : moved)
        assertSame(
            r.sealed(),
            compromised
                .getOrDefault(KmsKeys.sealedKeyId(r.sealed()), current)
                .rewrapTo(current, r.sealed(), r.aad()));
      // The forged record goes to current, which refuses it: quarantine, not re-seal.
      KeyHandle from = compromised.getOrDefault(KmsKeys.sealedKeyId(forged.sealed()), current);
      assertSame(current, from);
      assertThrows(
          StateConflictException.class,
          () -> from.rewrapTo(current, forged.sealed(), forged.aad()));
    }
  }

  /**
   * Two compromises in a row: both revoked keys are returned, nearest first, each opening its own
   * records; a destroyed compromised key is left out (nothing opens through it); a key that replaced
   * none has none, without a walk.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void compromisedPredecessorsAreEveryRevokedAncestorNearestFirst(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle k0 = aes(kms).create();
    Rec r0 = rec(k0, "zero");
    int before = s.exchanges();
    assertEquals(List.of(), k0.compromisedPredecessors());
    assertEquals(1, s.exchanges() - before, "one Get Attributes");
    KeyHandle k1 = k0.replaceCompromised(leaked());
    Rec r1 = rec(k1, "one");
    KeyHandle k2 = k1.replaceCompromised(leaked());
    KeyHandle k3 = k2.rotate();
    List<KeyHandle> got = k3.compromisedPredecessors();
    assertEquals(List.of(k1.id(), k0.id()), got.stream().map(KeyHandle::id).toList());
    assertArrayEquals(
        "data of one".getBytes(java.nio.charset.StandardCharsets.UTF_8),
        got.get(0).open(r1.sealed(), r1.aad()));
    assertArrayEquals(
        "data of zero".getBytes(java.nio.charset.StandardCharsets.UTF_8),
        got.get(1).open(r0.sealed(), r0.aad()));
    // The view covers its own key only: k1's view refuses k0's record.
    assertThrows(StateConflictException.class, () -> got.get(0).open(r0.sealed(), r0.aad()));
    kms.keys().handle(k0.id()).destroy();
    assertEquals(
        List.of(k1.id()), k3.compromisedPredecessors().stream().map(KeyHandle::id).toList());
  }

  // ---- an explicit rewrap result ----

  /**
   * "unchanged" was signaled only by returning the same array, so a re-sealing job compared
   * references. {@code rewrapRecord} says it: a record one rotation back is changed (re-sealed
   * under the current key, which the result names), one already under it is unchanged with no
   * request and the very array given; {@code rewrapRecordTo} likewise, also for a target of another
   * {@code Kms} that opens the record (unchanged) or not (migrated).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void rewrapRecordSaysWhetherTheRecordChanged(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle old = aes(kms).create();
    Rec r = rec(old, "r");
    KeyHandle kek = old.rotate();
    Rewrapped moved = kek.rewrapRecord(r.sealed(), r.aad());
    assertTrue(moved.changed());
    assertEquals(kek.id(), moved.keyId());
    assertEquals(kek.id(), KmsKeys.sealedKeyId(moved.bytes()));
    assertArrayEquals(
        "data of r".getBytes(java.nio.charset.StandardCharsets.UTF_8),
        kek.open(moved.bytes(), r.aad()));
    int before = s.exchanges();
    Rewrapped again = kek.rewrapRecord(moved.bytes(), r.aad());
    assertFalse(again.changed());
    assertSame(moved.bytes(), again.bytes());
    assertEquals(before, s.exchanges(), "no request");
    // rewrapRecordTo another key of the same Kms, and of another Kms.
    assertTrue(old.rewrapRecordTo(old, moved.bytes(), r.aad()).changed());
    InMemoryKmipServer other = server(version);
    KeyHandle elsewhere = aes(connect(other)).create();
    Rewrapped migrated = kek.rewrapRecordTo(elsewhere, moved.bytes(), r.aad());
    assertTrue(migrated.changed());
    assertEquals(elsewhere.id(), migrated.keyId());
    assertFalse(
        kek.rewrapRecordTo(elsewhere, migrated.bytes(), r.aad()).changed(),
        "the target opens it: unchanged");
  }

  // ---- a handle that follows latest() ----

  /** A clock for {@link CurrentKey}'s check interval. */
  static final class Nanos implements java.util.function.LongSupplier {
    long now = 1_000_000_000L;

    @Override
    public long getAsLong() {
      return now;
    }

    void pass(java.time.Duration d) {
      now += d.toNanos();
    }
  }

  static int getAttributesOf(InMemoryKmipServer s, String id) {
    return (int)
        s.protocolRequests().stream()
            .filter(
                r ->
                    RotationAndNameChoiceTest.isOperation(r, Operation.GET_ATTRIBUTES)
                        && ConcurrentReplacementInterleavingsTest.uid(r).equals(id))
            .count();
  }

  /**
   * On a server that deactivates a replaced key (here: another instance rotates and revokes the old
   * key as superseded), sealing through a kept handle is refused with STATE, which would leave an
   * application an 8-line catch-refresh-retry. {@code CurrentKey.seal} refreshes once ({@code
   * latest()}) and seals under the new key; later seals use it without asking again; it opens
   * records of both keys.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void currentKeyFollowsAReplacedKeyThatWasDeactivated(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms a = connect(s), b = connect(s);
    KeyHandle old = aes(a).findOrCreate();
    CurrentKey kek = b.keys().current(NAME);
    assertEquals(old.id(), kek.handle().id());
    byte[] first = kek.seal(PLAIN, AAD);
    KeyHandle next = old.rotate();
    old.revoke(RevocationReason.superseded("rotated"));
    byte[] second = kek.seal(PLAIN, AAD);
    assertEquals(next.id(), KmsKeys.sealedKeyId(second));
    assertEquals(next.id(), kek.handle().id());
    int reads = getAttributesOf(s, old.id());
    byte[] third = kek.seal(PLAIN, AAD);
    assertEquals(next.id(), KmsKeys.sealedKeyId(third));
    assertEquals(reads, getAttributesOf(s, old.id()), "the old key is not read again");
    for (byte[] r : List.of(first, second, third)) assertArrayEquals(PLAIN, kek.open(r, AAD));
  }

  /**
   * On a server that keeps a replaced key Active nothing is refused: the follower checks {@code
   * latest()} once the interval has passed since its last check, and not more often.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void currentKeyChecksForANewerKeyOncePerInterval(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms a = connect(s), b = connect(s);
    KeyHandle old = aes(a).findOrCreate();
    Nanos clock = new Nanos();
    CurrentKey kek =
        new CurrentKey(b.keys().handle(old.id()), java.time.Duration.ofSeconds(30), clock);
    KeyHandle next = old.rotate();
    int before = getAttributesOf(s, old.id());
    for (int i = 0; i < 5; i++)
      assertEquals(old.id(), KmsKeys.sealedKeyId(kek.seal(PLAIN, AAD)), "within the interval");
    // The first seal reads the key once (its usages); no check meanwhile.
    assertTrue(getAttributesOf(s, old.id()) - before <= 1, "no check within the interval");
    clock.pass(java.time.Duration.ofSeconds(30));
    assertEquals(next.id(), KmsKeys.sealedKeyId(kek.seal(PLAIN, AAD)));
    int after = s.exchanges();
    clock.pass(java.time.Duration.ofSeconds(29));
    kek.seal(PLAIN, AAD);
    assertEquals(after + 1, s.exchanges(), "one Encrypt, no check");
    // refresh() checks now; checkingEvery() rejects a non-positive interval.
    assertEquals(next.id(), kek.refresh().id());
    assertThrows(IllegalArgumentException.class, () -> kek.checkingEvery(java.time.Duration.ZERO));
  }

  /**
   * A check that fails is passed over (the call goes on with the key held, and the next interval
   * tries again); a refusal the newest key cannot help (it is Compromised) is thrown; a refusal
   * about another key (a record's Compromised key, when re-sealing) is thrown without a refresh.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void currentKeyThrowsWhatANewerKeyCannotHelp(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms).findOrCreate();
    Nanos clock = new Nanos();
    CurrentKey kek = new CurrentKey(key, java.time.Duration.ofSeconds(10), clock);
    clock.pass(java.time.Duration.ofSeconds(10));
    s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.SERVER_FAILURE);
    assertEquals(
        key.id(), KmsKeys.sealedKeyId(kek.seal(PLAIN, AAD)), "the failed check passed over");

    KeyHandle stranger =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    byte[] foreign = stranger.seal(PLAIN, AAD);
    stranger.revoke(leaked());
    int before = s.exchanges();
    StateConflictException other =
        assertThrows(StateConflictException.class, () -> kek.rewrapRecord(foreign, AAD));
    assertEquals(Optional.of(stranger.id()), other.objectId());
    assertEquals(key.id(), kek.handle().id());
    assertTrue(s.exchanges() - before <= 2, "no refresh: " + (s.exchanges() - before));

    key.revoke(leaked());
    StateConflictException mine =
        assertThrows(StateConflictException.class, () -> kek.seal(PLAIN, AAD));
    assertTrue(mine.getMessage().contains("COMPROMISED"), mine.getMessage());
  }

  /**
   * Many threads refused at once refresh once: the first finds the newer key, the others use it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void manyThreadsRefusedAtOnceRefreshOnce(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms a = connect(s), b = connect(s);
    KeyHandle old = aes(a).findOrCreate();
    CurrentKey kek = b.keys().current(NAME);
    kek.seal(PLAIN, AAD);
    KeyHandle next = old.rotate();
    old.revoke(RevocationReason.superseded("rotated"));
    int before = getAttributesOf(s, next.id());
    java.util.concurrent.ExecutorService pool =
        java.util.concurrent.Executors.newFixedThreadPool(8);
    try {
      java.util.concurrent.CountDownLatch go = new java.util.concurrent.CountDownLatch(1);
      List<java.util.concurrent.Future<byte[]>> seals = new ArrayList<>();
      for (int i = 0; i < 8; i++)
        seals.add(
            pool.submit(
                () -> {
                  go.await();
                  return kek.seal(PLAIN, AAD);
                }));
      go.countDown();
      for (var f : seals)
        assertEquals(
            next.id(), KmsKeys.sealedKeyId(f.get(10, java.util.concurrent.TimeUnit.SECONDS)));
    } finally {
      pool.shutdownNow();
    }
    // One latest() reads the new key once or twice (the walk, and the seal's usage read).
    assertTrue(
        getAttributesOf(s, next.id()) - before <= 3,
        "one refresh: " + (getAttributesOf(s, next.id()) - before));
  }

  /** {@code current(name)} needs an Active key with the name. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void currentOfANameWithoutAKeyIsNotFound(KmipVersion version) {
    Kms kms = connect(server(version));
    NotFoundException e = assertThrows(NotFoundException.class, () -> kms.keys().current(NAME));
    assertTrue(e.getMessage().contains("findOrCreate"), e.getMessage());
  }
}
