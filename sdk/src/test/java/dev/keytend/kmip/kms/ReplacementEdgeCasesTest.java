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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Edge cases of replacement: which keys a rotation activates, a CurrentKey whose check fails, a
 * concurrent replacement heard once, a refused Re-key of a key with a purged replacement, the cost
 * of compromisedPredecessors, and a stranger's key in either direction.
 */
class ReplacementEdgeCasesTest {
  static final byte[] PLAIN = ConcurrentReplacementChecks.PLAIN,
      AAD = ConcurrentReplacementChecks.AAD;
  final ReplicaRaceTest t = new ReplicaRaceTest();

  @AfterEach
  void cleanUp() {
    t.cleanUp();
  }

  static KeyHandle preActive(Kms kms) {
    return kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
  }

  static KeyHandle plain(Kms kms) {
    return kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
  }

  static void link(Kms kms, KeyHandle older, KeyHandle newer) throws Exception {
    KmsContractTest.link(kms, older.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, newer.id());
    KmsContractTest.link(kms, newer.id(), Enums.LinkType.REPLACED_OBJECT_LINK, older.id());
  }

  /**
   * {@code rotateOrLatest()} activates a Pre-Active key that does not descend from the handle's key
   * (a sibling branch, another caller's replacement of the predecessor).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void p1RotateOrLatestActivatesOnlyDescendants(KmipVersion version) throws Exception {
    InMemoryKmipServer s = t.server(version).linkCardinality(false); // a fork linked by hand
    Kms kms = t.connect(s);
    KeyHandle k0 = plain(kms);
    KeyHandle sibling = preActive(kms); // another caller's replacement of k0, not yet activated
    link(kms, k0, sibling);
    KeyHandle k1 = plain(kms); // this caller's branch
    link(kms, k0, k1);
    KeyHandle k2 = preActive(kms); // k1's replacement, its creator has not activated it yet
    link(kms, k1, k2);
    KeyHandle got = kms.keys().handle(k1.id()).rotateOrLatest();
    assertEquals(
        Optional.of(KeyState.PRE_ACTIVE),
        s.state(sibling.id()),
        "a key that does not descend from " + k1.id() + " was activated; returned " + got.id());
    // Its own descendant was activated, and is the current key for everyone.
    assertEquals(k2.id(), got.id());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(k2.id()));
    assertEquals(k2.id(), kms.keys().handle(k0.id()).latest().id());
  }

  /**
   * A CurrentKey whose interval check finds a newest key that is Pre-Active (a rotation between its
   * Re-key and its Activate, or one that stopped there) moves to it, and sealing then fails, though
   * the key it held is Active.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void p2CurrentKeyCheckDoesNotMoveToAKeyThatCannotSeal(KmipVersion version) throws Exception {
    InMemoryKmipServer s = t.server(version);
    Kms a = t.connect(s), b = t.connect(s);
    KeyHandle k1 = ReplicaRaceTest.aes(a).findOrCreate();
    ReplicaRaceTest.Nanos clock = new ReplicaRaceTest.Nanos();
    CurrentKey kek =
        new CurrentKey(b.keys().handle(k1.id()), java.time.Duration.ofSeconds(30), clock);
    assertEquals(k1.id(), KmsKeys.sealedKeyId(kek.seal(PLAIN, AAD)));
    KeyHandle k2 = preActive(a);
    link(a, k1, k2); // the Re-key made it; its Activate has not happened (yet)
    clock.pass(java.time.Duration.ofSeconds(30));
    byte[] sealed =
        assertDoesNotThrow(
            () -> kek.seal(PLAIN, AAD), "k1 is Active, and sealing under it worked a moment ago");
    assertEquals(k1.id(), KmsKeys.sealedKeyId(sealed));
    assertEquals(k1.id(), kek.refresh().id(), "refresh() does not move to it either");
    // Once the rotation activates it, the next check moves to it.
    a.keys().handle(k2.id()).activate();
    clock.pass(java.time.Duration.ofSeconds(30));
    assertEquals(k2.id(), KmsKeys.sealedKeyId(kek.seal(PLAIN, AAD)));
  }

  /** {@code replaceCompromised}'s loser on a Re-key refusal hears concurrentReplacement twice. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void p3ConcurrentReplacementHeardOnce(KmipVersion version) {
    InMemoryKmipServer s = t.server(version);
    Kms admin = t.connect(s);
    KeyHandle key = ReplicaRaceTest.aes(admin).create();
    key.revoke(ReplicaRaceTest.leaked());
    ReplicaRaceTest.Heard heard = new ReplicaRaceTest.Heard();
    Kms loser =
        t.losing(
            s,
            Operation.RE_KEY,
            () -> {
              var reKey =
                  dev.keytend.kmip.client.Requests.reKey().uniqueIdentifier(key.id()).build();
              try {
                admin.protocol().call(reKey);
                admin.protocol().call(reKey);
              } catch (Exception e) {
                throw new RuntimeException(e);
              }
              s.failNext(ServerOperation.RE_KEY, Fault.PERMISSION_DENIED);
            },
            heard);
    loser.keys().handle(key.id()).replaceCompromised(ReplicaRaceTest.leaked());
    assertEquals(1, heard.concurrent.size(), heard.concurrent.toString());
  }

  /**
   * On a server that refuses a second Re-key, a key whose replacement no longer exists (purged)
   * passes rotate()'s check, the server refuses it, and the caller is told FIX_ACCESS.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void p4RefusedReKeyOfAKeyWithAPurgedReplacement(KmipVersion version) throws Exception {
    InMemoryKmipServer s = t.server(version).refuseSecondReKey(true);
    Kms kms = t.connect(s);
    KeyHandle key = ReplicaRaceTest.aes(kms).create();
    KmsContractTest.link(kms, key.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, "purged-1");
    KmsException e = assertThrows(KmsException.class, key::rotate);
    assertNotEquals(KmsException.Category.FIX_ACCESS, e.category(), e.toString());
    assertInstanceOf(StateConflictException.class, e);
    assertTrue(
        e.getMessage().contains("purged-1") && e.getMessage().contains("findByName"),
        e.getMessage());
    // A Permission Denied for an Active key that names no replacement is still the access policy.
    KeyHandle other = ReplicaRaceTest.aes(kms).create();
    s.failNext(ServerOperation.RE_KEY, Fault.PERMISSION_DENIED);
    assertThrows(PermissionDeniedException.class, other::rotate);
  }

  /**
   * {@code compromisedPredecessors} of a key that replaced none: one Get Attributes, as documented
   * now.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1"})
  void p5CompromisedPredecessorsCost(KmipVersion version) {
    InMemoryKmipServer s = t.server(version);
    Kms kms = t.connect(s);
    KeyHandle k0 = plain(kms);
    int before = s.exchanges();
    k0.compromisedPredecessors();
    assertEquals(1, s.exchanges() - before);
  }

  /**
   * {@code rotateOrLatest}'s later firing costs its check and the walk latest() makes (latest()'s
   * own read of the start is the check's), not one more read of the current key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1"})
  void p6bCounts(KmipVersion version) {
    InMemoryKmipServer s = t.server(version);
    Kms kms = t.connect(s);
    KeyHandle k1 = plain(kms);
    k1.rotate();
    KeyHandle h = kms.keys().handle(k1.id());
    int before = s.exchanges();
    assertThrows(StateConflictException.class, h::rotate);
    int check = s.exchanges() - before;
    before = s.exchanges();
    h.latest();
    int latest = s.exchanges() - before;
    before = s.exchanges();
    h.rotateOrLatest();
    int orLatest = s.exchanges() - before;
    assertEquals(check + latest - 1, orLatest, "check " + check + ", latest " + latest);
  }

  /** A stranger's Compromised key naming the replacement both ways on its own links only. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1"})
  void h1StrangerBothWays(KmipVersion version) throws Exception {
    InMemoryKmipServer s = t.server(version).linkCardinality(false); // the stranger's links
    Kms kms = t.connect(s);
    KeyHandle k0 = plain(kms);
    KeyHandle k1 = k0.replaceCompromised(ReplicaRaceTest.leaked());
    KeyHandle stranger = plain(kms);
    stranger.revoke(ReplicaRaceTest.leaked());
    KmsContractTest.link(kms, stranger.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, k1.id());
    KmsContractTest.link(kms, stranger.id(), Enums.LinkType.REPLACED_OBJECT_LINK, k1.id());
    KmsContractTest.link(kms, stranger.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, k0.id());
    KmsContractTest.link(kms, stranger.id(), Enums.LinkType.REPLACED_OBJECT_LINK, k0.id());
    assertEquals(
        List.of(k0.id()), k1.compromisedPredecessors().stream().map(KeyHandle::id).toList());
  }
}
