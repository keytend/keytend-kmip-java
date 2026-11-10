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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Concurrent rotation is kept safe, not tidy: lineage trees, one
 * choice among several newest keys, no change to another caller's key, and reconcile.
 */
class LineageTreeTest {
  static final byte[] PLAIN = "probe".getBytes(UTF_8), AAD = "aad".getBytes(UTF_8);
  final List<Kms> clients = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
  }

  Kms connect(InMemoryKmipServer server) {
    Kms kms = server.connect();
    clients.add(kms);
    return kms;
  }

  Kms connect(InMemoryKmipServer server, dev.keytend.kmip.transport.KmipTransport transport) {
    Kms kms = Kms.connect(server.configure().transport(e -> transport).build());
    clients.add(kms);
    return kms;
  }

  static KeyCreation vault(Kms kms) {
    return kms.keys().createAes(256).named("vault").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
  }

  // ---- a fork is harmless to reading ----

  /**
   * Two Re-keys of one key (two callers that passed rotate()'s check at once), and one branch
   * rotated on. Before, a record under one branch was BAD_DATA through the other branch's keys,
   * since a key's lineage was its chain (keys it replaced and keys that replaced it). Now every key
   * reached by confirmed links either way belongs: each record opens through every key's handle,
   * findByName and KeyQuery.name.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRecordUnderAnyBranchOpensThroughEveryKeyOfTheTree(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle old = vault(kms).findOrCreate();
    KeyHandle a = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, old.id()));
    KeyHandle b = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, old.id()));
    KeyHandle b2 = b.rotate();
    List<KeyHandle> keys = List.of(old, a, b, b2);
    List<byte[]> records = new ArrayList<>();
    for (KeyHandle k : keys) records.add(k.seal(PLAIN, AAD));
    String where = ConcurrentReplacementChecks.describe(server);
    for (KeyHandle k : keys)
      for (byte[] r : records)
        assertArrayEquals(PLAIN, k.open(r, AAD), k + " opens " + KmsKeys.sealedKeyId(r) + where);
    for (byte[] r : records) {
      assertArrayEquals(PLAIN, kms.keys().open(KeyQuery.byName("vault"), r, AAD), where);
      assertArrayEquals(PLAIN, kms.keys().findByName("vault").orElseThrow().open(r, AAD), where);
    }
    // A ciphertext too, through the other branch.
    Ciphertext c = a.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    assertArrayEquals(PLAIN, b2.decrypt(c, AAD));
  }

  /**
   * A stranger cannot make its key a sibling of the victim's: links on its own keys naming the
   * victim's (a Replaced Object link to the victim's old key, a Replacement Object link to its
   * newest), and a key of its own between them, are not confirmed by the victim's keys, so the
   * stranger's records stay BAD_DATA through every victim handle and query.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aStrangerCannotGraftASiblingOntoTheTree(KmipVersion version) throws Exception {
    InMemoryKmipServer server =
        InMemoryKmipServer.of(version).linkCardinality(false); // the stranger's links
    Kms victim = connect(server), attacker = connect(server);
    KeyHandle old = vault(victim).findOrCreate();
    KeyHandle a = victim.keys().handle(RotationAndNameChoiceTest.reKey(victim, old.id()));
    KeyHandle b = victim.keys().handle(RotationAndNameChoiceTest.reKey(victim, old.id()));
    KeyHandle mine = KmsContractTest.aes(attacker, "theirs"),
        middle = KmsContractTest.aes(attacker, "middle");
    // One-sided links to the victim's keys, and a confirmed step between the attacker's own keys.
    KmsContractTest.link(attacker, mine.id(), Enums.LinkType.REPLACED_OBJECT_LINK, old.id());
    KmsContractTest.link(attacker, mine.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, a.id());
    KmsContractTest.link(attacker, middle.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, mine.id());
    KmsContractTest.link(attacker, mine.id(), Enums.LinkType.REPLACED_OBJECT_LINK, middle.id());
    KmsContractTest.link(attacker, middle.id(), Enums.LinkType.REPLACED_OBJECT_LINK, old.id());
    for (KeyHandle forger : List.of(mine, middle)) {
      byte[] forged = forger.seal(PLAIN, AAD);
      for (KeyHandle k : List.of(old, a, b)) {
        KeyMismatchException e =
            assertThrows(KeyMismatchException.class, () -> k.open(forged, AAD), k.toString());
        assertEquals(KmsException.Category.BAD_DATA, e.category());
      }
      KeyMismatchException e =
          assertThrows(
              KeyMismatchException.class,
              () -> victim.keys().open(KeyQuery.byName("vault"), forged, AAD));
      assertEquals(KmsException.Category.BAD_DATA, e.category());
    }
    // And the tree's choice ignores them.
    assertEquals(old.latest(), a.latest());
    assertNotEquals(mine.id(), old.latest().id());
  }

  /**
   * Nine or more callers that re-key one key at once leave it with more Replacement Object
   * links than a walk followed (8), so latest(), findByName and reading through the replacements
   * failed for good. Walks now follow 32 links on a key, and all of them on the caller's own key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void manyConcurrentReplacementsDoNotWedgeTheKey(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle old = vault(kms).findOrCreate();
    byte[] before = old.seal(PLAIN, AAD);
    List<KeyHandle> tips = new ArrayList<>();
    for (int i = 0; i < 12; i++)
      tips.add(kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, old.id())));
    KeyHandle chosen = old.latest();
    assertEquals(Optional.of(chosen), kms.keys().findByName("vault"));
    for (KeyHandle t : tips) {
      assertEquals(chosen, t.latest(), t.toString());
      assertArrayEquals(PLAIN, t.open(before, AAD), t.toString());
      assertArrayEquals(PLAIN, chosen.open(t.seal(PLAIN, AAD), AAD), t.toString());
    }
    assertEquals(chosen, old.reconcile());
    assertEquals(
        1,
        server.ids().stream().filter(i -> server.state(i).orElse(null) == KeyState.ACTIVE).count());
    assertArrayEquals(PLAIN, chosen.open(before, AAD));
    // More than 32 replacements: still followed from the caller's own key (the walk's start).
    InMemoryKmipServer big = InMemoryKmipServer.of(version);
    Kms k2 = connect(big);
    KeyHandle many = vault(k2).findOrCreate();
    for (int i = 0; i < Lineage.FANOUT + 3; i++) RotationAndNameChoiceTest.reKey(k2, many.id());
    assertEquals(many.latest(), k2.keys().findByName("vault").orElseThrow());
  }

  // ---- one choice among several newest keys ----

  /**
   * Several newest keys: latest() and findByName choose the same one from every key of the tree, in
   * the order Active, holding a name, created first; isLatest() is false on the others and tells the
   * listener which key was chosen; the caller whose rotation was not alone hears of it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theChoiceAmongNewestKeysIsTheSameEverywhere(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    List<String> heard = new CopyOnWriteArrayList<>();
    Kms kms =
        Kms.connect(
            server
                .configure()
                .addListener(
                    new KmsListener() {
                      @Override
                      public void concurrentReplacement(String keyId, List<String> replacements) {
                        heard.add("concurrent " + keyId + " " + replacements);
                      }

                      @Override
                      public void staleHandle(String keyId, List<String> replacements) {
                        heard.add("stale " + keyId + " " + replacements);
                      }
                    })
                .build());
    clients.add(kms);
    KeyHandle old = vault(kms).findOrCreate();
    // Another caller re-keyed it first (Re-key moved the name there); this caller's rotate() passed
    // its check before that, so its Re-key lands second: its own replacement, without the name.
    AtomicBoolean once = new AtomicBoolean();
    String[] first = {null};
    Kms other = connect(server);
    Kms racer =
        Kms.connect(
            server
                .configure()
                .transport(
                    e ->
                        request -> {
                          if (RotationAndNameChoiceTest.isOperation(request, Operation.RE_KEY)
                              && once.compareAndSet(false, true))
                            first[0] = other.keys().handle(old.id()).rotate().id();
                          return server.exchange(request);
                        })
                .addListener(
                    new KmsListener() {
                      @Override
                      public void concurrentReplacement(String keyId, List<String> replacements) {
                        heard.add("concurrent " + keyId + " " + replacements);
                      }
                    })
                .build());
    clients.add(racer);
    KeyHandle mine = racer.keys().handle(old.id()).rotate();
    assertNotEquals(first[0], mine.id());
    assertEquals(
        Optional.of(KeyState.ACTIVE),
        server.state(first[0]),
        "the other caller's key is untouched");
    assertTrue(
        heard.contains("concurrent " + old.id() + " " + List.of(first[0], mine.id())),
        heard.toString());
    KeyHandle named = kms.keys().handle(first[0]);
    for (KeyHandle k : List.of(old, named, kms.keys().handle(mine.id())))
      assertEquals(named, k.latest(), k.toString());
    assertEquals(Optional.of(named), kms.keys().findByName("vault"));
    assertTrue(named.isLatest());
    heard.clear();
    assertFalse(kms.keys().handle(mine.id()).isLatest());
    assertEquals(List.of("stale " + mine.id() + " " + List.of(first[0])), heard);
    // An Active newest key is chosen over one that holds the name but is not Active.
    named.revoke(RevocationReason.superseded("by hand"));
    assertEquals(mine.id(), old.latest().id());
    assertEquals(mine.id(), named.latest().id());
  }

  // ---- findOrCreate ----

  /**
   * FindOrCreate looked for Active, Pre-Active, Compromised and Deactivated keys with one
   * Locate each. A name that moved in between (another instance replacing the Compromised key gives
   * the name to its replacement) was missed by all of them, and a new, unrelated key was created
   * under the name: every record of the old key looked misfiled. One Locate without a state filter
   * now sees the name on one key or the other.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void findOrCreateDoesNotMissANameMovingBetweenItsLooks(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms setup = connect(server);
    KeyHandle old = vault(setup).findOrCreate();
    old.revoke(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
    // Another instance's replacement, made and linked, not yet named.
    KeyHandle replacement = KmsContractTest.aes(setup, "staging");
    replacement.removeName("staging");
    KmsContractTest.link(setup, replacement.id(), Enums.LinkType.REPLACED_OBJECT_LINK, old.id());
    KmsContractTest.link(setup, old.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, replacement.id());
    AtomicBoolean moved = new AtomicBoolean();
    Kms starting =
        connect(
            server,
            request -> {
              var response = server.exchange(request);
              // The name moves right after this instance's first Locate.
              if (RotationAndNameChoiceTest.isOperation(request, Operation.LOCATE)
                  && moved.compareAndSet(false, true)) {
                replacement.addName("vault");
                setup.keys().handle(old.id()).removeName("vault");
              }
              return response;
            });
    int before = server.ids().size();
    KmsException e = assertThrows(KmsException.class, () -> vault(starting).findOrCreate());
    assertInstanceOf(StateConflictException.class, e, e.toString());
    assertTrue(e.getMessage().contains("COMPROMISED"), e.getMessage());
    assertEquals(
        before,
        server.ids().size(),
        "no unrelated key under the name: " + ConcurrentReplacementChecks.describe(server));
    assertEquals(
        replacement.id(),
        vault(starting).findOrCreate().id(),
        "the next look finds the moved name");
  }

  /**
   * A key the lookup found Active and that was revoked before findOrCreate read it again was
   * returned anyway, so the caller's first seal failed. findOrCreate now looks again, and then finds
   * the Compromised key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void findOrCreateDoesNotReturnAKeyRevokedSinceItsLook(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms setup = connect(server);
    KeyHandle old = vault(setup).findOrCreate();
    AtomicBoolean revoked = new AtomicBoolean();
    Kms starting =
        connect(
            server,
            request -> {
              var response = server.exchange(request);
              // Revoked right after the look read it (Active), before findOrCreate reads it again.
              if (RotationAndNameChoiceTest.isOperation(request, Operation.GET_ATTRIBUTES)
                  && revoked.compareAndSet(false, true))
                old.revoke(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
              return response;
            });
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> vault(starting).findOrCreate());
    assertTrue(e.getMessage().contains("COMPROMISED"), e.getMessage());
    KeyHandle replacement = vault(starting).replacingCompromised().findOrCreate();
    assertEquals(Optional.of(KeyState.ACTIVE), server.state(replacement.id()));
  }

  // ---- lost replies are read back ----

  /**
   * Found by the Storm harness: the reply of the Re-key of a Compromised key was lost after
   * the server made the replacement, Pre-Active, and moved the name to it. replaceCompromised threw
   * OutcomeUnknownException; following it (repeating) chose another caller's Active replacement and
   * left the name on the Pre-Active key, so findByName found no key. Now the Re-key's outcome is read
   * back: the call completes with the replacement Active and named.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostReKeyReplyIsReadBack(KmipVersion version) {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
      Kms kms =
          connect(
              server,
              request -> {
                if (RotationAndNameChoiceTest.isOperation(request, Operation.RE_KEY))
                  server.failNext(
                      dev.keytend.kmip.testing.ServerOperation.RE_KEY,
                      dev.keytend.kmip.testing.Fault.REPLY_LOST);
                return server.exchange(request);
              });
      KeyHandle old = vault(kms).findOrCreate();
      KeyHandle replacement =
          old.replaceCompromised(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
      String where = "unique=" + unique + ConcurrentReplacementChecks.describe(server);
      assertEquals(Optional.of(KeyState.ACTIVE), server.state(replacement.id()), where);
      assertEquals(Optional.of(replacement), kms.keys().findByName("vault"), where);
      // rotate() too: the replacement is returned, Active.
      KeyHandle next = replacement.rotate();
      assertEquals(Optional.of(KeyState.ACTIVE), server.state(next.id()), where);
      assertEquals(next, replacement.latest());
    }
  }

  /**
   * The Storm case itself: the Re-key's replacement is Pre-Active with the name (its caller's reply
   * was lost), and another caller's replacement is Active without it. Repeating replaceCompromised,
   * as the advice says, finishes the Pre-Active one: it is activated, chosen (Active, named) and
   * returned, and findByName finds it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRepeatFinishesAReplacementLeftPreActiveWithTheName(KmipVersion version) throws Exception {
    for (boolean unique : new boolean[] {false, true}) {
      // A server that leaves the replacement of a Compromised key Pre-Active (new dates on Re-key).
      InMemoryKmipServer server =
          InMemoryKmipServer.of(version).uniqueNames(unique).freshDatesOnReKey(true);
      Kms kms = connect(server);
      KeyHandle old = vault(kms).findOrCreate();
      old.revoke(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
      String stranded =
          RotationAndNameChoiceTest.reKey(kms, old.id()); // Pre-Active, the name moved to it
      KeyHandle other = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, old.id()));
      other.activate();
      String where = "unique=" + unique + ConcurrentReplacementChecks.describe(server);
      assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(stranded), where);
      assertTrue(server.names(stranded).contains("vault"), where);
      KeyHandle repeated =
          old.replaceCompromised(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
      assertEquals(stranded, repeated.id(), where);
      assertEquals(Optional.of(KeyState.ACTIVE), server.state(stranded), where);
      assertEquals(Optional.of(repeated), kms.keys().findByName("vault"), where);
      assertEquals(repeated, other.latest());
    }
  }

  /** Whether {@code request} adds a Name (1.x: an Attribute named "Name"; 2.x: a Name structure). */
  static boolean addsName(Ttlv request) {
    return RotationAndNameChoiceTest.isOperation(request, Operation.ADD_ATTRIBUTE)
        && mentions(request, Tag.NAME, "Name");
  }

  static boolean mentions(Ttlv t, Tag tag, String attributeName) {
    if (t.tag() == tag.code()) return true;
    if (t.tag() == Tag.ATTRIBUTE_NAME.code() && attributeName.equals(t.value())) return true;
    if (t.type() == Ttlv.Type.STRUCTURE)
      for (Ttlv c : t.children()) if (mentions(c, tag, attributeName)) return true;
    return false;
  }

  /**
   * Whether {@code t} holds a text value that contains {@code name} (an attribute's name, on any
   * version; the pending-name records have one attribute per name).
   */
  static boolean names(Ttlv t, String name) {
    if (t.type() == Ttlv.Type.TEXT_STRING && String.valueOf(t.value()).contains(name)) return true;
    if (t.type() == Ttlv.Type.STRUCTURE)
      for (Ttlv c : t.children()) if (names(c, name)) return true;
    return false;
  }

  /**
   * A transport that refuses the {@code n}-th Name addition (Permission Denied), and when {@code
   * noPending} every write of the pending-name record (a server without client attributes).
   */
  static dev.keytend.kmip.transport.KmipTransport refusingNameAddition(
      InMemoryKmipServer server, int n, boolean refuseReKey, boolean noPending) {
    java.util.concurrent.atomic.AtomicInteger adds =
        new java.util.concurrent.atomic.AtomicInteger();
    return request -> {
      if (refuseReKey && RotationAndNameChoiceTest.isOperation(request, Operation.RE_KEY))
        server.failNext(
            dev.keytend.kmip.testing.ServerOperation.RE_KEY,
            dev.keytend.kmip.testing.Fault.UNSUPPORTED);
      if (addsName(request) && adds.incrementAndGet() == n)
        server.failNext(
            dev.keytend.kmip.testing.ServerOperation.ADD_ATTRIBUTE,
            dev.keytend.kmip.testing.Fault.PERMISSION_DENIED);
      if (noPending
          && names(request, "keytend-pending-name")
          && !RotationAndNameChoiceTest.isOperation(request, Operation.GET_ATTRIBUTES))
        for (Operation op :
            List.of(Operation.ADD_ATTRIBUTE, Operation.MODIFY_ATTRIBUTE, Operation.SET_ATTRIBUTE))
          if (RotationAndNameChoiceTest.isOperation(request, op))
            server.failNext(
                dev.keytend.kmip.testing.ServerOperation.valueOf(op.name()),
                dev.keytend.kmip.testing.Fault.PERMISSION_DENIED);
      return server.exchange(request);
    };
  }

  /**
   * Where names are unique, a name is taken off the old key before the replacement can have it.
   * When giving it then fails, the name is on neither key, and a repeat (which moves only the names
   * the old key still holds) never gave it back: the advice said "repeat replaceCompromised() to
   * resume", which left the replacement nameless (the long Storm run found it, after a hung Name
   * addition). The move is now written down on the replacement first (a client attribute), so the
   * repeat finishes it; where the server refuses that attribute, the advice says to give the name
   * by hand first.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aNameTakenOffButNotGivenIsGivenByTheRepeat(KmipVersion version) {
    for (boolean noPending : new boolean[] {false, true}) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(true);
      Kms kms = connect(server, refusingNameAddition(server, 2, true, noPending));
      KeyHandle old = vault(kms).findOrCreate();
      PartialCompletionException e =
          assertThrows(
              PartialCompletionException.class,
              () ->
                  old.replaceCompromised(
                      RevocationReason.keyCompromise("leaked", java.time.Instant.now())));
      String made = e.created().get(0).id();
      String where =
          "noPending="
              + noPending
              + ": "
              + e.getMessage()
              + ConcurrentReplacementChecks.describe(server);
      assertEquals(List.of(), server.names(old.id()), where);
      assertEquals(List.of(), server.names(made), where);
      assertFalse(e.getMessage().contains("destroy"), where);
      if (noPending) {
        assertTrue(e.getMessage().contains("give " + made + " the names [vault] by hand"), where);
        kms.keys().handle(made).addName("vault");
      } else {
        assertFalse(e.getMessage().contains("by hand"), where);
        assertTrue(e.getMessage().contains("repeat replaceCompromised() to resume"), where);
      }
      // Following the advice completes.
      assertEquals(
          made,
          old.replaceCompromised(RevocationReason.keyCompromise("leaked", java.time.Instant.now()))
              .id(),
          where);
      assertEquals(Optional.of(made), kms.keys().findByName("vault").map(KeyHandle::id), where);
      assertTrue(
          KeyHandle.pendingNames(kms.keys().handle(made).attributes()).isEmpty(),
          "the record is removed");
    }
  }

  /** The same for reconcile, which moves the other newest key's name to the winner. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void reconcileGivesANameTakenOffButNotGiven(KmipVersion version) throws Exception {
    for (boolean noPending : new boolean[] {false, true}) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(true);
      Kms setup = connect(server);
      KeyHandle old = vault(setup).findOrCreate();
      KeyHandle named =
          setup
              .keys()
              .handle(RotationAndNameChoiceTest.reKey(setup, old.id())); // the name moved here
      KeyHandle other = setup.keys().handle(RotationAndNameChoiceTest.reKey(setup, old.id()));
      // The other one wins: the named one is revoked by hand, so the Active one ranks first.
      named.revoke(RevocationReason.superseded("by hand"));
      Kms kms = connect(server, refusingNameAddition(server, 2, false, noPending));
      PartialCompletionException e =
          assertThrows(
              PartialCompletionException.class, () -> kms.keys().handle(old.id()).reconcile());
      String where =
          "noPending="
              + noPending
              + ": "
              + e.getMessage()
              + ConcurrentReplacementChecks.describe(server);
      assertEquals(List.of(), e.created(), where);
      assertEquals(
          noPending,
          e.getMessage().contains("give " + other.id() + " the name vault by hand"),
          where);
      if (noPending) other.addName("vault");
      assertEquals(other.id(), kms.keys().handle(old.id()).reconcile().id(), where);
      assertEquals(
          Optional.of(other.id()), setup.keys().findByName("vault").map(KeyHandle::id), where);
      assertTrue(KeyHandle.pendingNames(other.attributes()).isEmpty(), "the record is removed");
    }
  }

  /**
   * Found by the long Storm run: while a name was on no key (taken off the Compromised key, not yet
   * given to its replacement), a starting instance's findOrCreate found no key and created an
   * unrelated one under the name, which then kept it, so the lineage's records were BAD_DATA by
   * name. The move is written down on the replacement, and findOrCreate refuses (STATE, repeat)
   * rather than create while it is pending (with replacingCompromised() it finishes the move);
   * once the move finishes it finds the replacement.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void findOrCreateDoesNotTakeANameBeingMoved(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(true);
    Kms kms = connect(server, refusingNameAddition(server, 2, true, false));
    KeyHandle old = vault(kms).findOrCreate();
    PartialCompletionException stopped =
        assertThrows(
            PartialCompletionException.class,
            () ->
                old.replaceCompromised(
                    RevocationReason.keyCompromise("leaked", java.time.Instant.now())));
    String made = stopped.created().get(0).id();
    int before = server.ids().size();
    Kms starting = connect(server);
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> vault(starting).findOrCreate());
    assertTrue(e.getMessage().contains("being moved to [" + made + "]"), e.getMessage());
    assertEquals(
        before,
        server.ids().size(),
        "no unrelated key: " + ConcurrentReplacementChecks.describe(server));
    // With the opt-in it finishes the stopped replacement instead.
    assertEquals(made, vault(starting).replacingCompromised().findOrCreate().id());
    assertEquals(before, server.ids().size());
    assertEquals(
        made,
        old.replaceCompromised(RevocationReason.keyCompromise("leaked", java.time.Instant.now()))
            .id());
    assertEquals(made, vault(starting).findOrCreate().id());
  }

  /**
   * Found by the long Storm run: two callers replace one Compromised key at once (Re-key refused,
   * unique names). B finds the name still on the old key, records the move on its replacement and is
   * about to take the name off; A then moves the name to its own replacement. B's addition is refused
   * (A's key has the name), and B returned leaving its record behind; with the name later lost, that
   * stale record made findOrCreate refuse for good and pointed reconcile at the wrong key. Now every
   * exit that sees the name held clears the record.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aMoveOvertakenByAnotherCallerLeavesNoRecord(KmipVersion version) throws Exception {
    InMemoryKmipServer server = CompromiseReplacementTest.server(version, true, false);
    Kms setup = connect(server);
    KeyHandle old = vault(setup).findOrCreate();
    old.revoke(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
    java.util.concurrent.CyclicBarrier create = new java.util.concurrent.CyclicBarrier(2),
        created = new java.util.concurrent.CyclicBarrier(2);
    java.util.concurrent.CountDownLatch bAtRemoval = new java.util.concurrent.CountDownLatch(1),
        aDone = new java.util.concurrent.CountDownLatch(1);
    InMemoryKmipServer ra = server.replica(), rb = server.replica();
    AtomicBoolean aFirst = new AtomicBoolean(), bFirst = new AtomicBoolean();
    dev.keytend.kmip.transport.KmipTransport aMeet =
        CompromiseReplacementTest.meeting(ra, Operation.CREATE, create, created, () -> {});
    dev.keytend.kmip.transport.KmipTransport bMeet =
        CompromiseReplacementTest.meeting(rb, Operation.CREATE, create, created, () -> {});
    Kms a =
        connect(
            ra,
            CompromiseReplacementTest.refusingReKey(
                ra,
                request -> {
                  if (addsName(request) && aFirst.compareAndSet(false, true))
                    CompromiseReplacementTest.await(bAtRemoval, "B never reached its removal");
                  return aMeet.exchange(request);
                }));
    Kms b =
        connect(
            rb,
            CompromiseReplacementTest.refusingReKey(
                rb,
                request -> {
                  // B's first Delete Attribute that is not of the record: taking the name off the
                  // old key.
                  if (RotationAndNameChoiceTest.isOperation(request, Operation.DELETE_ATTRIBUTE)
                      && !names(request, "keytend-pending-name"))
                    if (bFirst.compareAndSet(false, true)) {
                      bAtRemoval.countDown();
                      CompromiseReplacementTest.await(aDone, "A never finished");
                    }
                  return bMeet.exchange(request);
                }));
    java.util.concurrent.ExecutorService pool =
        java.util.concurrent.Executors.newFixedThreadPool(2);
    try {
      var fa =
          pool.submit(
              () -> {
                try {
                  return a.keys()
                      .handle(old.id())
                      .replaceCompromised(
                          RevocationReason.keyCompromise("leaked", java.time.Instant.now()))
                      .id();
                } finally {
                  aDone.countDown();
                }
              });
      var fb =
          pool.submit(
              () ->
                  b.keys()
                      .handle(old.id())
                      .replaceCompromised(
                          RevocationReason.keyCompromise("leaked", java.time.Instant.now()))
                      .id());
      String ra2 = fa.get(30, java.util.concurrent.TimeUnit.SECONDS),
          rb2 = fb.get(30, java.util.concurrent.TimeUnit.SECONDS);
      String where = "A=" + ra2 + " B=" + rb2 + ConcurrentReplacementChecks.describe(server);
      assertTrue(bFirst.get(), "B reached its removal: " + where);
      assertTrue(server.names(ra2).contains("vault"), where);
      for (String id : server.ids())
        assertTrue(
            KeyHandle.pendingNames(setup.keys().handle(id).attributes()).isEmpty(),
            "a record left on " + id + ": " + where);
      ConcurrentReplacementChecks.assertSafe(
          server, setup, old, List.of(ra2, rb2), List.of(a, b), "vault", false);
    } finally {
      pool.shutdownNow();
    }
  }

  /**
   * The name is on no key, and the record of its move is on a replacement that is not the one a
   * repeat chooses (another caller's): the repeated replaceCompromised still finishes the move, to
   * its replacement, and removes the record. And reconcile(name), which finds no object with the
   * name, starts from the key that records it, within one lineage only.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aMoveRecordedOnAnotherReplacementIsFinished(KmipVersion version) throws Exception {
    for (boolean viaReconcile : new boolean[] {false, true}) {
      // Replacements of a Compromised key left Pre-Active (new dates on Re-key), activated below.
      InMemoryKmipServer server =
          InMemoryKmipServer.of(version).uniqueNames(true).freshDatesOnReKey(true);
      Kms kms = connect(server);
      KeyHandle old = vault(kms).findOrCreate();
      old.revoke(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
      KeyHandle first =
          kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, old.id())); // the name moved here
      KeyHandle second = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, old.id()));
      first.activate();
      second.activate();
      // A move to the second that stopped after taking the name off: on no key, recorded on it.
      second.setCustomAttribute(KeyHandle.pendingName("vault"), "vault");
      first.removeName("vault");
      String where = "viaReconcile=" + viaReconcile + ConcurrentReplacementChecks.describe(server);
      assertEquals(Optional.empty(), kms.keys().findByName("vault"), where);
      KeyHandle got =
          viaReconcile
              ? kms.keys().reconcile("vault").orElseThrow()
              : old.replaceCompromised(
                  RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
      assertEquals(Optional.of(got.id()), kms.keys().findByName("vault").map(KeyHandle::id), where);
      for (String id : server.ids())
        assertTrue(
            KeyHandle.pendingNames(kms.keys().handle(id).attributes()).isEmpty(), id + where);
    }
    // Records on keys of two lineages (a stranger can write one on a key of its own): nothing is
    // decided.
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(true);
    Kms kms = connect(server);
    KeyHandle mine = KmsContractTest.aes(kms, "mine"), theirs = KmsContractTest.aes(kms, "theirs");
    mine.setCustomAttribute(KeyHandle.pendingName("vault"), "vault");
    theirs.setCustomAttribute(KeyHandle.pendingName("vault"), "vault");
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> kms.keys().reconcile("vault"));
    assertTrue(e.getMessage().contains("more than one rotation lineage"), e.getMessage());
    assertEquals(List.of(), server.names(mine.id()).stream().filter("vault"::equals).toList());
  }

  /**
   * retirePredecessors on an older key of a plain chain said the lineage had
   * "other newest keys (callers that rotated a key at the same time)" and advised reconcile, which
   * would have deactivated keys for nothing. It now says to retire from the key latest() returns.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void retiringFromAnOlderKeySaysToRetireFromTheLatest(KmipVersion version) {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle k0 = vault(kms).findOrCreate();
    KeyHandle k1 = k0.rotate();
    KeyHandle k2 = k1.rotate();
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> k1.retirePredecessors(RevocationReason.superseded("retire")));
    assertTrue(
        e.getMessage()
            .contains("newer keys, [" + k2.id() + "]: retire from the key latest() returns"),
        e.getMessage());
    assertFalse(
        e.getMessage().contains("callers that rotated a key at the same time"), e.getMessage());
    assertEquals(
        List.of(k0.id(), k1.id()),
        k2.retirePredecessors(RevocationReason.superseded("retire")).stream()
            .map(KeyHandle::id)
            .toList());
  }

  /**
   * {@code t} without the structures that name {@code text}, keeping the containers (message, batch
   * item, payload, 2.x Attributes): a Locate without its filter on that attribute.
   */
  static Ttlv without(Ttlv t, String text) {
    if (t.type() != Ttlv.Type.STRUCTURE) return t;
    Set<Integer> containers =
        Set.of(
            Tag.REQUEST_MESSAGE.code(),
            Tag.BATCH_ITEM.code(),
            Tag.REQUEST_PAYLOAD.code(),
            Tag.ATTRIBUTES.code());
    List<Ttlv> kept = new ArrayList<>();
    for (Ttlv c : t.children()) {
      if (c.type() == Ttlv.Type.STRUCTURE && !containers.contains(c.tag()) && names(c, text))
        continue;
      kept.add(without(c, text));
    }
    return Ttlv.structure(t.tag(), kept);
  }

  /**
   * Found by the integration run against real servers: the Locate by the pending-name
   * record that findOrCreate sends for a name with no key failed with General Failure on PyKMIP, and
   * another server did not filter by it, returning unrelated objects; first startup failed on both. The
   * look is now best effort: a refused Locate finds no record, and what a Locate returns is read and
   * checked. Emulated here: the in-memory server refusing that Locate, and ignoring its filter.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aServerThatCannotSearchTheRecordStillCreates(KmipVersion version) throws Exception {
    for (String behavior : List.of("refuses", "ignores")) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version);
      Kms setup = connect(server);
      // Unrelated objects with a client attribute (what an unfiltered Locate returns).
      for (int i = 0; i < 3; i++)
        KmsContractTest.aes(setup, "other-" + i)
            .setCustomAttribute(CustomAttribute.client("purpose"), "x");
      Kms kms =
          connect(
              server,
              request -> {
                boolean pending =
                    RotationAndNameChoiceTest.isOperation(request, Operation.LOCATE)
                        && names(request, "keytend-pending-name");
                if (pending && behavior.equals("refuses"))
                  server.failNext(
                      dev.keytend.kmip.testing.ServerOperation.LOCATE,
                      dev.keytend.kmip.model.Enums.ResultReason.GENERAL_FAILURE);
                return server.exchange(
                    pending && behavior.equals("ignores")
                        ? without(request, "keytend-pending-name")
                        : request);
              });
      KeyHandle kek = vault(kms).findOrCreate();
      assertEquals(Optional.of(KeyState.ACTIVE), server.state(kek.id()), behavior);
      assertEquals(kek.id(), vault(kms).findOrCreate().id(), behavior);
    }
  }
}
