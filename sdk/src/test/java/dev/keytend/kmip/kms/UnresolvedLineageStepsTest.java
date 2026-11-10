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

import static dev.keytend.kmip.kms.KmsContractTest.AAD;
import static dev.keytend.kmip.kms.KmsContractTest.PLAIN;
import static dev.keytend.kmip.kms.RotationAndNameChoiceTest.orders;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Unresolved steps of lineage walks: malformed or unreadable links, purged keys and leftover candidates. */
class UnresolvedLineageStepsTest {
  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  Kms connect(InMemoryKmipServer server, KmsConfig.Builder builder) {
    servers.add(server);
    Kms kms = Kms.connect(builder.build());
    clients.add(kms);
    return kms;
  }

  Kms connect(InMemoryKmipServer server) {
    return connect(server, server.configure());
  }

  /**
   * A client whose requests naming an identifier in {@code hidden} fail with its reason: Item Not
   * Found for an object destroyed and purged, Permission Denied for one the client may not read.
   */
  Kms hiding(InMemoryKmipServer server, Map<String, Enums.ResultReason> hidden) {
    return connect(
        server,
        server
            .configure()
            .retryPolicy(RetryPolicy.none())
            .transport(
                e ->
                    request -> {
                      for (Ttlv item : request.children(Tag.BATCH_ITEM)) {
                        Optional<String> id =
                            item.child(Tag.REQUEST_PAYLOAD)
                                .flatMap(p -> p.child(Tag.UNIQUE_IDENTIFIER))
                                .map(Ttlv::textValue);
                        if (id.isPresent() && hidden.containsKey(id.get()))
                          return Faults.failure(request, hidden.get(id.get()), "hidden");
                      }
                      return server.exchange(request);
                    }));
  }

  static void assertState(KmsException e, String... mentioned) {
    assertEquals(StateConflictException.class, e.getClass(), "before: " + e);
    assertEquals(KmsException.Category.STATE, e.category());
    for (String m : mentioned) assertTrue(e.getMessage().contains(m), m + " in " + e.getMessage());
  }

  /** The identifier a request's first batch item names, if any. */
  static Optional<String> named(Ttlv request) {
    for (Ttlv item : request.children(Tag.BATCH_ITEM)) {
      Optional<String> id =
          item.child(Tag.REQUEST_PAYLOAD)
              .flatMap(p -> p.child(Tag.UNIQUE_IDENTIFIER))
              .map(Ttlv::textValue);
      if (id.isPresent()) return id;
    }
    return Optional.empty();
  }

  /** {@code node} without any {@code tag} child, at any depth. */
  static Ttlv without(Ttlv node, Tag tag) {
    if (node.type() != Ttlv.Type.STRUCTURE) return node;
    List<Ttlv> children = new ArrayList<>();
    for (Ttlv child : node.children())
      if (child.tag() != tag.code()) children.add(without(child, tag));
    return Ttlv.structure(node.tag(), children);
  }

  // ---- a malformed ancestor reply ----

  /**
   * Victim key, a planted duplicate, the victim's replacement. A Get Attributes
   * reply for the victim's first key without its Unique Identifier made the walk back from the
   * replacement end there as if the lineage started at the replacement, so the earlier planted key
   * took the name. A reply that is not valid now leaves the start open (STATE).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aMalformedAncestorReplyDoesNotEndTheLineage(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Set<String> malformed = ConcurrentHashMap.newKeySet();
    Kms victim =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request -> {
                          Ttlv response = server.exchange(request);
                          Optional<String> id = named(request);
                          return id.isPresent() && malformed.contains(id.get())
                              ? without(response, Tag.UNIQUE_IDENTIFIER)
                              : response;
                        }));
    Kms attacker = connect(server);
    KeyHandle original = orders(victim).create();
    KeyHandle planted = orders(attacker).create();
    KeyHandle rotated = original.rotate();
    assertEquals(Optional.of(rotated), victim.keys().findByName("orders"));

    malformed.add(original.id());
    assertThrows(
        ProtocolViolationException.class, original::attributes, "a direct read refuses the reply");
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> victim.keys().findByName("orders"),
            "before: " + planted);
    assertTrue(
        e.getMessage().contains(original.id()) && e.getMessage().contains("invalid reply"),
        e.getMessage());
    assertThrows(StateConflictException.class, () -> orders(victim).findOrCreate());
  }

  // ---- an unreadable sibling ----

  /**
   * A concurrent rotation left A with two replacements, B and C, and C cannot be
   * read. The forward walk read every replacement of A before testing any, so {@code
   * A.decrypt(B's ciphertext)} failed with C's PermissionDeniedException although B's own handle
   * decrypts it. Each confirmed successor is now tested as it is read; C's failure counts only if
   * nothing is found, and then as STATE.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void anUnreadableSiblingDoesNotBlockAConfirmedSuccessor(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Map<String, Enums.ResultReason> unreadable = new ConcurrentHashMap<>();
    Kms kms = hiding(server, unreadable);
    KeyHandle a = orders(kms).create();
    String c = RotationAndNameChoiceTest.reKey(kms, a.id());
    KeyHandle b =
        new KeyHandle(
            kms.keys(), RotationAndNameChoiceTest.reKey(kms, a.id()), ObjectKind.SYMMETRIC_KEY);
    unreadable.put(c, Enums.ResultReason.PERMISSION_DENIED);
    Ciphertext underB = b.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    assertArrayEquals(PLAIN, b.decrypt(underB, AAD));
    assertArrayEquals(PLAIN, a.decrypt(underB, AAD), "before: PermissionDeniedException for " + c);
    assertArrayEquals(PLAIN, a.open(b.seal(PLAIN, AAD), AAD));

    // Not found by any path: a key of some rotation chain might be behind C, so STATE naming C,
    // not C's PermissionDenied.
    KeyHandle rotatedStranger = KmsContractTest.aes(kms, "stranger").rotate();
    KmsException e =
        assertThrows(
            KmsException.class,
            () -> a.decrypt(rotatedStranger.encrypt(CipherSpec.aesGcm(), PLAIN, AAD), AAD));
    assertState(e, c, "cannot be read");
    // A key with no rotation links belongs to no chain: a proven mismatch.
    KeyHandle stranger = KmsContractTest.aes(kms, "plain stranger");
    assertEquals(
        KmsException.Category.BAD_DATA,
        assertThrows(
                KeyMismatchException.class,
                () -> a.decrypt(stranger.encrypt(CipherSpec.aesGcm(), PLAIN, AAD), AAD))
            .category());
  }

  /**
   * The walk back kept only the gaps of the key it ended at, so an unreadable
   * second Replaced Object link beside a confirmed one was forgotten and its key's ciphertext was
   * BAD_DATA. Gaps are kept for the whole walk.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1"})
  void anUnreadableLinkBesideAConfirmedPredecessorIsKept(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Map<String, Enums.ResultReason> unreadable = new ConcurrentHashMap<>();
    Kms kms = hiding(server, unreadable), other = connect(server);
    KeyHandle a = orders(kms).create();
    KeyHandle b = a.rotate();
    KeyHandle x = KmsContractTest.aes(other, "x").rotate();
    KmsContractTest.link(kms, b.id(), Enums.LinkType.REPLACED_OBJECT_LINK, x.id());
    Ciphertext underX = x.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    unreadable.put(x.id(), Enums.ResultReason.PERMISSION_DENIED);
    assertState(
        assertThrows(KmsException.class, () -> b.decrypt(underX, AAD)), x.id(), "cannot be read");
  }

  /**
   * After the recommended retirement (oldest key purged), every walk back from a
   * handle ends at the purged key, so every foreign ciphertext became STATE. A ciphertext whose key
   * exists and has no rotation links belongs to no chain, so it is BAD_DATA again (one more Get
   * Attributes, on that failure only); a record under the purged key, or under a key that is itself
   * part of a chain, stays STATE.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void afterRetiringTheOldestKeyAStrangersCiphertextIsStillBadData(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Map<String, Enums.ResultReason> purged = new ConcurrentHashMap<>();
    Kms kms = hiding(server, purged);
    KeyHandle a = orders(kms).create();
    Ciphertext underA = a.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    KeyHandle b = a.rotate();
    KeyHandle c = b.rotate();
    a.revoke(RevocationReason.superseded("retired"));
    a.destroy();
    purged.put(a.id(), Enums.ResultReason.ITEM_NOT_FOUND);

    Ciphertext foreign =
        KmsContractTest.aes(kms, "stranger").encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    int before = server.exchanges();
    KeyMismatchException e =
        assertThrows(KeyMismatchException.class, () -> c.decrypt(foreign, AAD), "before: STATE");
    assertEquals(KmsException.Category.BAD_DATA, e.category());
    // c, b and the stranger's key reach the server; the read of the purged a is answered by the
    // client.
    assertEquals(3, server.exchanges() - before);
    assertArrayEquals(PLAIN, c.decrypt(b.encrypt(CipherSpec.aesGcm(), PLAIN, AAD), AAD));
    KmsException gone = assertThrows(KmsException.class, () -> c.decrypt(underA, AAD));
    assertState(gone, a.id(), "no longer exists");
    assertFalse(gone.getMessage().contains("its own handle"), gone.getMessage());

    // A key beyond a gap met walking back would have a Replacement Object link: the newest key of
    // another chain has none, so its ciphertext is BAD_DATA too; an older key of it stays STATE,
    // and
    // the advice is to check the key, not to trust the record's choice.
    KeyHandle theirs = KmsContractTest.aes(kms, "theirs");
    KeyHandle theirsNow = theirs.rotate();
    assertEquals(
        KmsException.Category.BAD_DATA,
        assertThrows(
                KeyMismatchException.class,
                () -> c.decrypt(theirsNow.encrypt(CipherSpec.aesGcm(), PLAIN, AAD), AAD))
            .category());
    KmsException older =
        assertThrows(
            KmsException.class,
            () -> c.decrypt(theirs.encrypt(CipherSpec.aesGcm(), PLAIN, AAD), AAD));
    assertState(older, a.id(), "check that it is one of your keys");
  }

  /**
   * Only Item Not Found, Permission Denied and invalid replies were gaps; a
   * sibling the server refuses otherwise (archived, a lifecycle state, a field) still blocked the
   * confirmed successor, as with an unreadable sibling.
   */
  @ParameterizedTest
  @EnumSource(
      value = Enums.ResultReason.class,
      names = {"OBJECT_ARCHIVED", "WRONG_KEY_LIFECYCLE_STATE", "INVALID_FIELD"})
  void aSiblingRefusedForAnotherReasonDoesNotBlockEither(Enums.ResultReason reason)
      throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Map<String, Enums.ResultReason> refused = new ConcurrentHashMap<>();
    Kms kms = hiding(server, refused);
    KeyHandle a = orders(kms).create();
    String c = RotationAndNameChoiceTest.reKey(kms, a.id());
    KeyHandle b =
        new KeyHandle(
            kms.keys(), RotationAndNameChoiceTest.reKey(kms, a.id()), ObjectKind.SYMMETRIC_KEY);
    refused.put(c, reason);
    assertArrayEquals(
        PLAIN,
        a.decrypt(b.encrypt(CipherSpec.aesGcm(), PLAIN, AAD), AAD),
        "before: " + reason + " for " + c);
  }

  /**
   * A stale handle whose successor is archived lost its old data: the forward
   * walk runs first, and its failure stopped the backward walk that finds the predecessor.
   */
  @org.junit.jupiter.api.Test
  void aStaleHandleWhoseSuccessorIsArchivedKeepsItsOldData() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Map<String, Enums.ResultReason> refused = new ConcurrentHashMap<>();
    Kms kms = hiding(server, refused);
    KeyHandle a0 = orders(kms).create();
    byte[] old = a0.seal(PLAIN, AAD);
    KeyHandle a = a0.rotate();
    KeyHandle b = a.rotate();
    refused.put(b.id(), Enums.ResultReason.OBJECT_ARCHIVED);
    assertArrayEquals(PLAIN, a.open(old, AAD), "before: StateConflictException for " + b.id());
  }

  /** A query matching nothing sent its Locate twice on the gap path. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aQueryMatchingNothingLocatesOnceOnTheGapPath(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Map<String, Enums.ResultReason> purged = new ConcurrentHashMap<>();
    Kms kms = hiding(server, purged);
    KeyHandle a = orders(kms).create();
    KeyHandle b = a.rotate();
    b.rotate();
    Ciphertext underA = a.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    b.revoke(RevocationReason.superseded("rotated"));
    b.destroy();
    purged.put(b.id(), Enums.ResultReason.ITEM_NOT_FOUND);
    long locates = KmsContractTest.sent(server, Operation.LOCATE);
    KeyMismatchException e =
        assertThrows(
            KeyMismatchException.class,
            () -> kms.keys().decrypt(KeyQuery.byName("nope"), underA, AAD));
    assertEquals(KmsException.Category.FIX_REQUEST, e.category());
    assertEquals(1, KmsContractTest.sent(server, Operation.LOCATE) - locates, "before: 2");
  }

  /** A candidate whose reply is not valid is unresolved too, as a malformed or denied one. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aCandidateWithAnInvalidReplyIsState(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Set<String> malformed = ConcurrentHashMap.newKeySet();
    Kms victim =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request -> {
                          Ttlv response = server.exchange(request);
                          for (Ttlv item : request.children(Tag.BATCH_ITEM)) {
                            Optional<String> id =
                                item.child(Tag.REQUEST_PAYLOAD)
                                    .flatMap(p -> p.child(Tag.UNIQUE_IDENTIFIER))
                                    .map(Ttlv::textValue);
                            if (id.isPresent() && malformed.contains(id.get()))
                              return without(response, Tag.UNIQUE_IDENTIFIER);
                          }
                          return response;
                        }));
    Kms other = connect(server);
    orders(victim).create();
    KeyHandle theirs = orders(other).create();
    malformed.add(theirs.id());
    assertState(
        assertThrows(KmsException.class, () -> victim.keys().findByName("orders")),
        theirs.id(),
        "not valid");
  }

  // ---- a purged middle key ----

  /**
   * Rotate A → B → C, keep records under A and C, destroy and purge B. The walks
   * skipped the purged B, so each handle reported the other's record as BAD_DATA (which would
   * quarantine it), and {@code A.latest()} returned A, so the "refresh with latest()" recipe looped.
   * Both are now STATE naming B, and each record still opens with its own key's handle.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aPurgedMiddleKeyIsABrokenChainNotBadData(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Map<String, Enums.ResultReason> purged = new ConcurrentHashMap<>();
    Kms kms = hiding(server, purged);
    KeyHandle a = orders(kms).create();
    KeyHandle b = a.rotate();
    KeyHandle c = b.rotate();
    byte[] underA = a.seal(PLAIN, AAD), underC = c.seal(PLAIN, AAD);
    assertArrayEquals(PLAIN, a.open(underC, AAD));
    assertArrayEquals(PLAIN, c.open(underA, AAD));

    b.revoke(RevocationReason.superseded("rotated"));
    b.destroy();
    purged.put(b.id(), Enums.ResultReason.ITEM_NOT_FOUND);
    assertState(
        assertThrows(KmsException.class, () -> a.open(underC, AAD)),
        b.id(),
        "purged",
        "Retiring keys");
    assertState(assertThrows(KmsException.class, () -> c.open(underA, AAD)), b.id(), "purged");
    assertState(assertThrows(KmsException.class, a::latest), b.id(), "findByName");
    // The query decrypt walks forward from the record's key too: A no longer has the name.
    assertState(
        assertThrows(
            KmsException.class, () -> kms.keys().open(KeyQuery.byName("orders"), underA, AAD)),
        b.id());

    // A query matching nothing stays the caller's to fix.
    assertEquals(
        KmsException.Category.FIX_REQUEST,
        assertThrows(
                KeyMismatchException.class,
                () -> kms.keys().open(KeyQuery.byName("nope"), underA, AAD))
            .category());

    // Each record opens with its own key's handle, and the name still finds C.
    assertArrayEquals(PLAIN, a.open(underA, AAD));
    assertArrayEquals(PLAIN, c.open(underC, AAD));
    assertArrayEquals(PLAIN, kms.keys().open(KeyQuery.byName("orders"), underC, AAD));
    assertEquals(Optional.of(c), kms.keys().findByName("orders"));
    assertEquals(c, c.latest());
  }

  // ---- a findOrCreate leftover, then routine purging ----

  /**
   * Two instances raced findOrCreate and left a Pre-Active key; the key in use was
   * rotated and its first key retired, destroyed and purged. From then on every new instance's
   * findOrCreate was STATE with no hint of the cause. The message now names the leftover and the
   * fix (destroy it), and destroying it ends the error.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aFindOrCreateLeftoverIsNamedInTheStateError(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Map<String, Enums.ResultReason> purged = new ConcurrentHashMap<>();
    Kms kms = hiding(server, purged);
    server.clock(KeyLookupTest.at(0));
    KeyHandle first = orders(kms).findOrCreate();
    server.clock(KeyLookupTest.at(1));
    KeyHandle leftover = orders(kms).createPreActive();
    server.clock(KeyLookupTest.at(10));
    KeyHandle current = first.rotate();
    first.revoke(RevocationReason.superseded("rotated"));
    first.destroy();
    purged.put(first.id(), Enums.ResultReason.ITEM_NOT_FOUND);

    assertEquals(Optional.of(current), kms.keys().findByName("orders"), "Active keys only");
    KmsException e = assertThrows(KmsException.class, () -> orders(kms).findOrCreate());
    assertState(e, leftover.id(), "never activated", "destroy");
    leftover.destroy();
    assertEquals(current, orders(kms).findOrCreate());
  }

  // ---- inside findOrCreate, and an unreadable candidate ----

  /**
   * The name lookup's own failures inside findOrCreate, the STATE of an unresolved candidate and the
   * UnsupportedException of a lineage longer than 64 rotations, reported operation "findByName".
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1"})
  void theLookupsOwnFailuresNameFindOrCreate(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Map<String, Enums.ResultReason> purged = new ConcurrentHashMap<>();
    Kms kms = hiding(server, purged), other = connect(server);
    server.clock(KeyLookupTest.at(0));
    orders(other).create();
    server.clock(KeyLookupTest.at(10));
    KeyHandle first = orders(kms).create();
    KeyHandle key = first.rotate();
    first.revoke(RevocationReason.superseded("rotated"));
    first.destroy();
    purged.put(first.id(), Enums.ResultReason.ITEM_NOT_FOUND);
    StateConflictException state =
        assertThrows(StateConflictException.class, () -> orders(kms).findOrCreate());
    assertEquals("findOrCreate", state.operation(), "before: findByName");
    assertTrue(state.getMessage().startsWith("findOrCreate: "), state.getMessage());
    assertEquals(
        "findByName",
        assertThrows(StateConflictException.class, () -> kms.keys().findByName("orders"))
            .operation());

    purged.clear();
    for (int i = 0; i < Lineage.LIMIT; i++) key = key.rotate();
    UnsupportedException tooLong =
        assertThrows(UnsupportedException.class, () -> orders(kms).findOrCreate());
    assertEquals("findOrCreate", tooLong.operation(), "before: findByName");
    assertTrue(tooLong.getMessage().startsWith("findOrCreate: "), tooLong.getMessage());
  }

  /**
   * A candidate whose Get Attributes is denied made findByName and findOrCreate a
   * PermissionDeniedException, as if the caller's own access were wrong. It is an unresolved
   * candidate: STATE naming it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void anUnreadableCandidateIsStateNotAPermissionFailure(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Map<String, Enums.ResultReason> unreadable = new ConcurrentHashMap<>();
    Kms kms = hiding(server, unreadable), other = connect(server);
    KeyHandle mine = orders(kms).create();
    KeyHandle theirs = orders(other).create();
    unreadable.put(theirs.id(), Enums.ResultReason.PERMISSION_DENIED);
    assertState(
        assertThrows(KmsException.class, () -> kms.keys().findByName("orders")),
        theirs.id(),
        mine.id(),
        "cannot be read");
    KmsException e = assertThrows(KmsException.class, () -> orders(kms).findOrCreate());
    assertState(e, theirs.id());
    assertEquals("findOrCreate", e.operation());
  }
}
