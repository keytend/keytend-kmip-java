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
import static dev.keytend.kmip.kms.KmsContractTest.aes;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Rotation and the choice among keys with one name: the lineage bound, replacements that name the
 * key back, stale handles, lost and concurrent rotations, planted keys, concurrent findOrCreate,
 * deadlines, messages and walks that attackers' links cannot make expensive.
 */
class RotationAndNameChoiceTest {
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

  /** A Re-key sent through the protocol layer, bypassing {@link KeyHandle#rotate()}'s checks. */
  static String reKey(Kms kms, String id) throws Exception {
    return kms.protocol().call(Requests.reKey().uniqueIdentifier(id).build()).uniqueIdentifier();
  }

  static boolean isOperation(Ttlv request, Operation operation) {
    return request.children(Tag.BATCH_ITEM).stream()
        .anyMatch(i -> i.require(Tag.OPERATION).intValue() == operation.code());
  }

  interface Blocking {
    void run() throws InterruptedException;
  }

  /** Runs a blocking step inside a transport, where only I/O exceptions may be thrown. */
  static void await(Blocking step) throws java.io.InterruptedIOException {
    try {
      step.run();
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new java.io.InterruptedIOException("interrupted");
    }
  }

  // ---- the lineage bound ----

  /**
   * Exactly 64 rotations are within the bound. Before, the walks threw after the 64th
   * confirmed step without looking whether the chain went on, and latest() reported a long valid
   * chain as a protocol violation.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void sixtyFourRotationsAreWithinTheBoundAndMoreAreALimit(KmipVersion version) {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle first = aes(kms, "long");
    Ciphertext c = first.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    KeyHandle current = first;
    for (int i = 0; i < Lineage.LIMIT; i++) current = current.rotate();
    KeyHandle sixtyFourth = current;
    assertArrayEquals(PLAIN, sixtyFourth.decrypt(c, AAD), "64 steps back");
    assertArrayEquals(
        PLAIN, kms.keys().decrypt(KeyQuery.byName("long"), c, AAD), "64 steps forward");
    assertEquals(sixtyFourth, first.latest(), "latest() follows 64 replacements");

    KeyHandle sixtyFifth = sixtyFourth.rotate();
    UnsupportedException back =
        assertThrows(UnsupportedException.class, () -> sixtyFifth.decrypt(c, AAD));
    assertTrue(back.getMessage().contains("more than 64"), back.getMessage());
    assertThrows(
        UnsupportedException.class, () -> kms.keys().decrypt(KeyQuery.byName("long"), c, AAD));
    // Before: ProtocolViolationException (category SERVER) for a valid chain.
    UnsupportedException forward = assertThrows(UnsupportedException.class, first::latest);
    assertEquals(KmsException.Category.FIX_REQUEST, forward.category());
    assertEquals(sixtyFifth, sixtyFourth.latest());
  }

  // ---- a key replaced twice ----

  /**
   * A key replaced twice, here by Re-keys sent outside {@link KeyHandle#rotate()},
   * has two Replacement Object links. Before, only the first link of a kind was read, so the second
   * replacement could not decrypt the old key's data, a query matching only the second replacement
   * did not accept it, and latest() took whichever link the server listed first.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void everyConfirmedReplacementBelongsToTheLineage(KmipVersion version) throws Exception {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle old = aes(kms, "forked");
    Ciphertext c = old.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    byte[] sealed = old.seal(PLAIN, AAD);
    KeyHandle first = kms.keys().handle(reKey(kms, old.id()));
    KeyHandle second = kms.keys().handle(reKey(kms, old.id()));
    assertEquals(List.of(first.id(), second.id()), old.attributes().links(LinkKind.REPLACEMENT));
    for (KeyHandle successor : List.of(first, second)) {
      assertArrayEquals(PLAIN, successor.decrypt(c, AAD), successor.toString());
      assertArrayEquals(PLAIN, successor.open(sealed, AAD), successor.toString());
    }
    second.addName("second-branch");
    assertArrayEquals(PLAIN, kms.keys().decrypt(KeyQuery.byName("second-branch"), c, AAD));
    assertArrayEquals(PLAIN, kms.keys().open(KeyQuery.byName("second-branch"), sealed, AAD));
    // latest() follows the replacement created first (Initial Date, then identifier).
    assertEquals(first, old.latest());
  }

  /** latest() follows only replacements that name the key back, and says when none does. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void latestNeedsTheReplacementToNameTheKeyBack(KmipVersion version) throws Exception {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle victim = aes(kms, "victim"), other = aes(kms, "other");
    // A key whose Replacement Object link names a key that does not name it back. Before, latest()
    // returned that key; whoever controls a key can set its links, so it is a server or data fault.
    KmsContractTest.link(kms, other.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, victim.id());
    ProtocolViolationException e = assertThrows(ProtocolViolationException.class, other::latest);
    assertTrue(e.getMessage().contains("none names " + other.id()), e.getMessage());
    assertEquals(victim, victim.latest());
  }

  // ---- rotate() ----

  /**
   * Two replicas hold the same handle and both rotate. Before, the second Re-key forked the
   * chain: the old key had two replacements, and data sealed under the second, which had no name,
   * could not be opened by name. Now the stale rotation is refused before anything is sent.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aStaleHandleCannotForkTheChain(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms replicaA = connect(server), replicaB = connect(server);
    KeyHandle key = aes(replicaA, "orders");
    KeyHandle staleA = replicaA.keys().handle(key.id()), staleB = replicaB.keys().handle(key.id());
    KeyHandle rotated = staleA.rotate();
    long reKeys = KmsContractTest.sent(server, Operation.RE_KEY);
    StateConflictException e = assertThrows(StateConflictException.class, staleB::rotate);
    assertTrue(
        e.getMessage().contains("already replaced by " + rotated.id())
            && e.getMessage().contains("latest()"),
        e.getMessage());
    assertEquals(reKeys, KmsContractTest.sent(server, Operation.RE_KEY), "nothing re-keyed");
    assertEquals(List.of(rotated.id()), key.attributes().links(LinkKind.REPLACEMENT));
    // The documented way on: rotate the current key.
    KeyHandle next = staleB.latest().rotate();
    byte[] sealed = next.seal(PLAIN, AAD);
    assertArrayEquals(PLAIN, replicaA.keys().open(KeyQuery.byName("orders"), sealed, AAD));
    assertArrayEquals(PLAIN, replicaA.keys().handle(key.id()).latest().open(sealed, AAD));
  }

  /**
   * A rotation whose reply was lost may have happened; repeating it is refused. The lost reply is
   * read back first: the rotation returns the replacement it made, and a
   * repeat on the old key is refused. A Re-key that the server never processed (it hung) leaves no
   * replacement: then the outcome stays unknown, and the advice is to repeat rotate().
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aRotationRepeatedAfterAnUnknownOutcomeIsRefused(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .callTimeout(java.time.Duration.ofMillis(500)));
    KeyHandle key = aes(kms, "orders");
    server.failNext(ServerOperation.RE_KEY, Fault.REPLY_LOST);
    KeyHandle rotated = key.rotate();
    String replacement = key.attributes().links(LinkKind.REPLACEMENT).get(0);
    assertEquals(replacement, rotated.id(), "the lost reply is read back");
    StateConflictException e = assertThrows(StateConflictException.class, key::rotate);
    assertTrue(e.getMessage().contains("already replaced by " + replacement), e.getMessage());
    assertEquals(1, key.attributes().links(LinkKind.REPLACEMENT).size(), "one replacement");
    assertEquals(replacement, key.latest().id());

    server.failNext(ServerOperation.RE_KEY, Fault.HANG);
    OutcomeUnknownException unknown = assertThrows(OutcomeUnknownException.class, rotated::rotate);
    assertTrue(unknown.getMessage().contains("repeat rotate()"), unknown.getMessage());
    assertEquals(List.of(), rotated.attributes().links(LinkKind.REPLACEMENT));
    assertEquals(
        Optional.of(KeyState.ACTIVE), server.state(rotated.rotate().id()), "the repeat rotates");
  }

  /**
   * Two rotations at the same moment both pass the check before their Re-key. Neither gives way
   * (no key is folded into the other's): each caller returns its own replacement and neither touches the other's: both are Active newest keys of one
   * tree, every record opens through either, latest() and findByName choose the one Re-key gave the
   * name (from every key of the tree), and reconcile joins them.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void ofTwoConcurrentRotationsBothReturnTheFirstReplacement(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms replicaA = connect(server);
    String keyId = aes(replicaA, "orders").id();
    KeyHandle[] first = new KeyHandle[1];
    // Replica B's Re-key reaches the server only after replica A has rotated completely.
    Kms replicaB =
        connect(
            server,
            server
                .configure()
                .transport(
                    e ->
                        request -> {
                          if (first[0] == null && isOperation(request, Operation.RE_KEY))
                            first[0] = replicaA.keys().handle(keyId).rotate();
                          return server.exchange(request);
                        }));
    KeyHandle second = replicaB.keys().handle(keyId).rotate();
    assertNotEquals(first[0].id(), second.id(), "each caller returns its own replacement");
    assertEquals(
        Optional.of(KeyState.ACTIVE),
        server.state(first[0].id()),
        "the other caller's key is untouched");
    assertEquals(Optional.of(KeyState.ACTIVE), server.state(second.id()));
    assertEquals(
        first[0].id(),
        replicaB.keys().handle(keyId).latest().id(),
        "latest() chooses the one with the name");
    assertEquals(
        first[0].id(),
        replicaB.keys().handle(second.id()).latest().id(),
        "from every key of the tree");
    assertFalse(second.isLatest());
    byte[] sealed = second.seal(PLAIN, AAD);
    assertArrayEquals(PLAIN, first[0].open(sealed, AAD));
    assertArrayEquals(PLAIN, replicaB.keys().open(KeyQuery.byName("orders"), sealed, AAD));
    assertEquals(first[0].id(), replicaB.keys().reconcile("orders").orElseThrow().id());
    assertEquals(
        Optional.of(KeyState.DEACTIVATED),
        server.state(second.id()),
        "reconcile revokes the other as superseded");
    assertArrayEquals(PLAIN, first[0].open(sealed, AAD));
  }

  /**
   * After a compromise the replacement came back Pre-Active (the server does not activate the
   * replacement of a key that is not Active), so findByName did not find it. The replacement is now
   * returned Active, as create() does. (A server that gives the replacement new dates: one that
   * copies them, as KMIP says, makes it Active itself.) rotate() refuses a
   * Compromised key before sending anything, and replaceCompromised is the call; rotate()'s own
   * activation is shown with a Pre-Active key, whose replacement is Pre-Active on every server.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void rotateReturnsAnActiveReplacementAfterACompromise(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).freshDatesOnReKey(true);
    Kms kms = connect(server, server.configure().retryPolicy(RetryPolicy.none()));
    KeyHandle key = aes(kms, "orders");
    key.revoke(RevocationReason.keyCompromise("leaked", Instant.now().minusSeconds(60)));
    assertThrows(StateConflictException.class, key::rotate);
    KeyHandle replacement =
        key.replaceCompromised(RevocationReason.keyCompromise("leaked", Instant.now()));
    assertEquals(KeyState.ACTIVE, replacement.attributes().state());
    assertEquals(Optional.of(replacement), kms.keys().findByName("orders"));

    // A failure once the replacement exists names it.
    KeyHandle other = kms.keys().handle(RotationJobTest.preActive(kms));
    server.failNext(ServerOperation.ACTIVATE, Fault.SERVER_FAILURE);
    PartialCompletionException e = assertThrows(PartialCompletionException.class, other::rotate);
    KeyHandle created = e.created().get(0);
    assertEquals(other.attributes().replacementLink(), Optional.of(created.id()));
    assertEquals(KeyState.PRE_ACTIVE, created.attributes().state());
    assertTrue(
        e.getMessage().contains("activation failed")
            && e.getMessage().contains("activate the replacement"),
        e.getMessage());
  }

  // ---- choosing among keys with one name ----

  static KeyCreation orders(Kms kms) {
    return kms.keys().createAes(256).named("orders").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
  }

  /**
   * A key planted under the victim's name, then the victim rotates.
   * Re-key gives the replacement a new Initial Date, so ranking candidates by their own date chose
   * the planted key, and new data was encrypted under it. Candidates are now ranked by the first
   * key of their lineage.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aKeyPlantedUnderTheNameDoesNotWinAfterTheVictimRotates(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms victim = connect(server), attacker = connect(server);
    KeyHandle original = orders(victim).create();
    KeyHandle planted = orders(attacker).create();
    assertEquals(Optional.of(original), victim.keys().findByName("orders"));
    KeyHandle rotated = original.rotate();
    assertEquals(
        Optional.of(rotated), victim.keys().findByName("orders"), "before: the planted key");
    assertEquals(rotated, orders(victim).findOrCreate());
    Ciphertext c =
        victim.keys().findByName("orders").orElseThrow().encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    assertEquals(rotated.id(), c.keyId());
    assertNotEquals(planted.id(), c.keyId());
  }

  /** Two lineages with one name; rotating either does not move the name to the other. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void rotatingEitherOfTwoLineagesKeepsTheChoice(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms replicaA = connect(server), replicaB = connect(server);
    KeyHandle a = orders(replicaA).create(), b = orders(replicaB).create();
    assertEquals(Optional.of(a), replicaA.keys().findByName("orders"));
    KeyHandle b1 = b.rotate();
    assertEquals(Optional.of(a), replicaA.keys().findByName("orders"));
    KeyHandle a1 = a.rotate();
    assertEquals(Optional.of(a1), replicaA.keys().findByName("orders"), "before: " + b1);
    KeyHandle a2 = a1.rotate();
    b1.rotate();
    assertEquals(Optional.of(a2), replicaA.keys().findByName("orders"));
    assertEquals(a2.id(), orders(replicaB).findOrCreate().id());
  }

  /**
   * The choice does not depend on which keys are Active yet. Before, an Active key was
   * chosen over a Pre-Active one, so the winner changed as other callers' activations landed.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void theChoiceIgnoresWhichKeysAreActiveYet(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms replicaA = connect(server), replicaB = connect(server);
    KeyHandle first = orders(replicaA).createPreActive();
    KeyHandle second = orders(replicaB).create();
    assertEquals(
        Optional.of(first),
        replicaA.keys().findByName("orders", KeyState.ACTIVE, KeyState.PRE_ACTIVE));
    KeyHandle found = orders(replicaB).findOrCreate();
    assertEquals(first.id(), found.id(), "before: " + second);
    assertEquals(KeyState.ACTIVE, first.attributes().state(), "the chosen key was activated");
  }

  /**
   * Concurrent findOrCreate calls in one process. Before, 32 callers left many Pre-Active
   * keys behind; now one call runs and the others wait for its key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void concurrentFindOrCreateCallsInOneProcessMakeOneKey(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    // Each Create takes a while, which before let every caller find nothing and create its own.
    Kms kms =
        connect(
            server,
            server
                .configure()
                .transport(
                    e ->
                        request -> {
                          if (isOperation(request, Operation.CREATE)) await(() -> Thread.sleep(50));
                          return server.exchange(request);
                        }));
    Kms view = kms.withTimeout(Duration.ofSeconds(20));
    int callers = 32;
    ExecutorService pool = Executors.newFixedThreadPool(callers);
    try {
      CountDownLatch start = new CountDownLatch(1);
      List<Future<KeyHandle>> results = new ArrayList<>();
      for (int i = 0; i < callers; i++) {
        Kms through = i % 2 == 0 ? kms : view;
        results.add(
            pool.submit(
                () -> {
                  start.await();
                  return orders(through).findOrCreate();
                }));
      }
      start.countDown();
      Set<String> ids = new HashSet<>();
      for (Future<KeyHandle> f : results) ids.add(f.get(30, TimeUnit.SECONDS).id());
      assertEquals(1, ids.size(), ids.toString());
      assertEquals(1, KmsContractTest.sent(server, Operation.CREATE), "one key created");
    } finally {
      pool.shutdownNow();
    }
  }

  /** A caller waiting for another's findOrCreate gives up at its own deadline. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1"})
  void aWaitingFindOrCreateEndsAtItsDeadline(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    CountDownLatch release = new CountDownLatch(1);
    CountDownLatch creating = new CountDownLatch(1);
    Kms kms =
        connect(
            server,
            server
                .configure()
                .transport(
                    e ->
                        request -> {
                          if (isOperation(request, Operation.CREATE)) {
                            creating.countDown();
                            await(release::await);
                          }
                          return server.exchange(request);
                        }));
    ExecutorService pool = Executors.newSingleThreadExecutor();
    try {
      Future<KeyHandle> slow = pool.submit(() -> orders(kms).findOrCreate());
      assertTrue(creating.await(10, TimeUnit.SECONDS));
      long started = System.nanoTime();
      TransientException e =
          assertThrows(
              TransientException.class,
              () -> orders(kms.withTimeout(Duration.ofMillis(300))).findOrCreate());
      assertTrue(System.nanoTime() - started < TimeUnit.SECONDS.toNanos(5));
      assertTrue(e.getMessage().contains("waiting for another findOrCreate"), e.getMessage());
      release.countDown();
      assertEquals(KeyState.ACTIVE, slow.get(10, TimeUnit.SECONDS).attributes().state());
    } finally {
      release.countDown();
      pool.shutdownNow();
    }
  }

  // ---- findOrCreate's messages ----

  /**
   * After this call created a key, the name turned out to belong to another caller's key
   * that does not match the builder (here: its usages). Before, the message said "then activation
   * failed" and advised repeating findOrCreate(), which fails the same way forever.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aMismatchFoundAfterCreatingSaysRepeatingWillNotHelp(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms other = connect(server);
    boolean[] planted = {false};
    Kms kms =
        connect(
            server,
            server
                .configure()
                .transport(
                    e ->
                        request -> {
                          if (!planted[0] && isOperation(request, Operation.CREATE)) {
                            planted[0] = true;
                            other
                                .keys()
                                .createAes(256)
                                .named("orders")
                                .usages(KeyUsage.MAC_GENERATE)
                                .createPreActive();
                          }
                          return server.exchange(request);
                        }));
    PartialCompletionException e =
        assertThrows(PartialCompletionException.class, () -> orders(kms).findOrCreate());
    assertInstanceOf(KeyMismatchException.class, e.getCause());
    assertFalse(e.getMessage().contains("activation failed"), e.getMessage());
    assertTrue(e.getMessage().contains("will not help"), e.getMessage());
    KeyHandle created = e.created().get(0);
    assertEquals(KeyState.PRE_ACTIVE, created.attributes().state());
    // No advice says to destroy it: another instance may have found it.
    assertFalse(e.getMessage().contains("destroy"), e.getMessage());
    assertTrue(
        e.getMessage().contains(created.id() + ", which this call created, is left"),
        e.getMessage());
  }

  /** A non-key with the name is described as such, not as "null, not AES-256". */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aSecretWithTheNameIsNotDescribedAsANullAlgorithm(KmipVersion version) {
    Kms kms = connect(InMemoryKmipServer.of(version));
    kms.keys()
        .registerSecret("hunter2".toCharArray())
        .named("orders")
        .usages(KeyUsage.DERIVE_KEY)
        .register();
    KeyMismatchException e =
        assertThrows(KeyMismatchException.class, () -> orders(kms).findOrCreate());
    assertTrue(e.getMessage().contains("it is a SECRET_DATA, not a symmetric key"), e.getMessage());
    assertFalse(e.getMessage().contains("null"), e.getMessage());
  }

  // ---- the opt-in covers the named key only ----

  /**
   * {@code j1.allowingCompromised().decrypt(c0)} must not decrypt a ciphertext of the Compromised
   * predecessor j0 when j1 itself is healthy. Recovering j0's data takes j0's own view.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void allowingCompromisedOnTheCurrentKeyDoesNotUnlockAPredecessor(KmipVersion version) {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle j0 = aes(kms, "orders");
    Ciphertext c0 = j0.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    byte[] sealed0 = j0.seal(PLAIN, AAD);
    KeyHandle j1 =
        j0.replaceCompromised(
            RevocationReason.keyCompromise("leaked", Instant.now().minusSeconds(60)));
    for (KeyHandle h : List.of(j1, j1.allowingCompromised())) {
      StateConflictException e =
          assertThrows(StateConflictException.class, () -> h.decrypt(c0, AAD));
      assertTrue(
          e.getMessage().contains("handle(\"" + j0.id() + "\").allowingCompromised()"),
          e.getMessage());
      assertThrows(StateConflictException.class, () -> h.open(sealed0, AAD));
    }
    KeyHandle named = kms.keys().handle(j0.id()).allowingCompromised();
    assertArrayEquals(PLAIN, named.decrypt(c0, AAD));
    assertArrayEquals(PLAIN, named.open(sealed0, AAD));
  }

  // ---- verify after the private key is compromised ----

  /**
   * Verify checked only the public key's state, but it is the private key that gets
   * compromised; a signature checked with the public key of a Compromised private key was VALID.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void verifyRefusesWhenTheLinkedPrivateKeyIsCompromised(KmipVersion version) throws Exception {
    Kms kms = connect(InMemoryKmipServer.of(version));
    SignatureSpec ecdsa = SignatureSpec.ecdsa(Hash.SHA_256);
    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.ec(Curve.P_256))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .create();
    byte[] sig = pair.privateKey().sign(ecdsa, PLAIN);
    pair.privateKey()
        .revoke(RevocationReason.keyCompromise("leaked", Instant.now().minusSeconds(60)));
    for (KeyHandle verifier : List.of(pair.publicKey(), kms.keys().handle(pair.publicKey().id()))) {
      StateConflictException e =
          assertThrows(StateConflictException.class, () -> verifier.verify(ecdsa, PLAIN, sig));
      assertTrue(
          e.getMessage().contains("the private key " + pair.privateKey().id()), e.getMessage());
      assertEquals(VerifyResult.VALID, verifier.allowingCompromised().verify(ecdsa, PLAIN, sig));
    }
    assertEquals(
        KeyState.ACTIVE, pair.publicKey().attributes().state(), "the public key itself is healthy");

    // A private key that was only retired and destroyed does not matter.
    KeyPairHandle retired =
        kms.keys()
            .createKeyPair(KeyPairSpec.ec(Curve.P_256))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .create();
    byte[] old = retired.privateKey().sign(ecdsa, PLAIN);
    retired.privateKey().revoke(RevocationReason.superseded("rotated"));
    retired.privateKey().destroy();
    assertEquals(VerifyResult.VALID, retired.publicKey().verify(ecdsa, PLAIN, old));

    // A public key registered on its own has no private key to check.
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(256);
    KeyPair local = g.generateKeyPair();
    Signature jca = Signature.getInstance("SHA256withECDSA");
    jca.initSign(local.getPrivate());
    jca.update(PLAIN);
    byte[] localSig = jca.sign();
    KeyHandle bare = kms.keys().register(local.getPublic()).usages(KeyUsage.VERIFY).register();
    assertEquals(VerifyResult.VALID, bare.verify(ecdsa, PLAIN, localSig));

    // KeyPairHandle.revoke revokes both halves.
    KeyPairHandle both =
        kms.keys()
            .createKeyPair(KeyPairSpec.ec(Curve.P_256))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .create();
    both.revoke(RevocationReason.keyCompromise("leaked", Instant.now().minusSeconds(60)));
    assertEquals(KeyState.COMPROMISED, both.privateKey().attributes().state());
    assertEquals(KeyState.COMPROMISED, both.publicKey().attributes().state());
  }

  // ---- categories that depend on the case ----

  /**
   * The category came from the subtype only. A 1.x General Failure on an AEAD decrypt
   * (UNCONFIRMED) was BAD_DATA, so an application quarantined good records for a server fault, and
   * a ciphertext naming a key outside the lineage or query was FIX_REQUEST. Each case now has the
   * same category on every version.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_0", "V2_1", "V3_0"})
  void categoriesDependOnTheCaseAndNotOnTheVersion(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server, server.configure().retryPolicy(RetryPolicy.none()));
    KeyHandle key = aes(kms, "orders"), other = aes(kms, "other");
    Ciphertext c = key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);

    // A server fault while decrypting: 1.x says General Failure (UNCONFIRMED), 2.x Internal Server
    // Error (ServerFailureException); both are SERVER.
    server.failNext(ServerOperation.DECRYPT, Fault.SERVER_FAILURE);
    KmsException fault = assertThrows(KmsException.class, () -> key.decrypt(c, AAD));
    assertEquals(KmsException.Category.SERVER, fault.category(), fault.toString());
    if (fault instanceof CryptographicFailureException u)
      assertEquals(CryptographicFailureException.Kind.UNCONFIRMED, u.kind());

    // Tampering is BAD_DATA.
    byte[] data = c.data();
    data[0] ^= 1;
    Ciphertext tampered =
        Ciphertext.builder()
            .keyId(c.keyId())
            .specName(c.specName())
            .iv(c.iv())
            .tag(c.tag())
            .data(data)
            .build();
    assertEquals(
        KmsException.Category.BAD_DATA,
        assertThrows(CryptographicFailureException.class, () -> key.decrypt(tampered, AAD))
            .category());

    // A ciphertext naming a key outside the lineage, the query or the pair is BAD_DATA.
    assertEquals(
        KmsException.Category.BAD_DATA,
        assertThrows(KeyMismatchException.class, () -> other.decrypt(c, AAD)).category());
    assertEquals(
        KmsException.Category.BAD_DATA,
        assertThrows(
                KeyMismatchException.class,
                () -> kms.keys().decrypt(KeyQuery.byName("other"), c, AAD))
            .category());
    byte[] sealed = key.seal(PLAIN, AAD);
    assertEquals(
        KmsException.Category.BAD_DATA,
        assertThrows(KeyMismatchException.class, () -> other.open(sealed, AAD)).category());
    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.DECRYPT)
            .publicUsages(KeyUsage.ENCRYPT)
            .create();
    Ciphertext foreign =
        Ciphertext.builder()
            .keyId(other.id())
            .specName(CipherSpec.rsaOaep(Hash.SHA_256).name())
            .data(new byte[256])
            .build();
    assertEquals(
        KmsException.Category.BAD_DATA,
        assertThrows(
                KeyMismatchException.class,
                () -> pair.decrypt(CipherSpec.rsaOaep(Hash.SHA_256), foreign, null))
            .category());

    // A key of the wrong usages is the caller's to fix, on every version too.
    KeyHandle macOnly =
        kms.keys()
            .createSymmetric(Algorithm.HMAC_SHA256, 256)
            .usages(KeyUsage.MAC_GENERATE)
            .create();
    assertEquals(
        KmsException.Category.FIX_REQUEST,
        assertThrows(
                KeyMismatchException.class, () -> macOnly.encrypt(CipherSpec.aesGcm(), PLAIN, AAD))
            .category());
  }

  // ---- a reply without Data ----

  /** Removes Data from every Encrypt reply while {@code on} is set. */
  static Ttlv withoutData(Ttlv response, boolean on) {
    if (!on) return response;
    List<Ttlv> items = new ArrayList<>();
    for (Ttlv child : response.children()) {
      Optional<Ttlv> payload = child.child(Tag.RESPONSE_PAYLOAD);
      if (child.tag() != Tag.BATCH_ITEM.code()
          || child.require(Tag.OPERATION).intValue() != Operation.ENCRYPT.code()
          || payload.isEmpty()) {
        items.add(child);
        continue;
      }
      List<Ttlv> fields = new ArrayList<>();
      for (Ttlv f : payload.get().children()) if (f.tag() != Tag.DATA.code()) fields.add(f);
      List<Ttlv> rewritten = new ArrayList<>();
      for (Ttlv f : child.children())
        rewritten.add(
            f.tag() == Tag.RESPONSE_PAYLOAD.code()
                ? Ttlv.structure(Tag.RESPONSE_PAYLOAD, fields)
                : f);
      items.add(Ttlv.structure(Tag.BATCH_ITEM, rewritten));
    }
    return Ttlv.structure(response.tag(), items);
  }

  /**
   * KMIP 2.0 lets Encrypt and Decrypt omit Data for an empty result, and any Data-less
   * reply to empty input was taken as one: {@code encrypt(CipherSpec.cbc(), new byte[0], null)}
   * returned 0 bytes where CBC gives 16. Now only a spec whose output is empty (GCM, CTR) may.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_0", "V2_1"})
  void aReplyWithoutDataIsEmptyOutputOnlyWhereTheSpecSaysSo(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    boolean[] strip = {false};
    Kms kms =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(e -> request -> withoutData(server.exchange(request), strip[0])));
    KeyHandle key = aes(kms, "k");
    KeyPairHandle rsa =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.DECRYPT)
            .publicUsages(KeyUsage.ENCRYPT)
            .create();
    CipherSpec ecb =
        CipherSpec.fromProtocol(
            "aes-ecb",
            dev.keytend.kmip.client.CryptoParameters.builder()
                .algorithm(Enums.CryptographicAlgorithm.AES)
                .mode(Enums.BlockCipherMode.ECB)
                .padding(Enums.PaddingMethod.PKCS5)
                .build());
    strip[0] = true;
    assertEquals(
        0, key.encrypt(CipherSpec.aesGcm(), new byte[0], AAD).data().length, "GCM: empty output");
    assertEquals(0, key.encrypt(CipherSpec.ctr(), new byte[0]).data().length, "CTR: empty output");
    assertThrows(
        ProtocolViolationException.class,
        () -> key.encrypt(CipherSpec.cbc(), new byte[0]),
        "CBC pads to a block");
    assertThrows(
        ProtocolViolationException.class,
        () -> key.encrypt(ecb, new byte[0]),
        "a custom spec's length is unknown");
    assertThrows(
        ProtocolViolationException.class,
        () -> rsa.encrypt(CipherSpec.rsaOaep(Hash.SHA_256), new byte[0]),
        "RSA-OAEP output has the modulus size");
  }

  // ---- any answer resets an endpoint's record of unanswered requests ----

  /**
   * Only a successful response cleared the record kept of when requests to an
   * endpoint started going unanswered. So timeout, then Not Found, then (a call timeout after the
   * first) another short timeout moved traffic, although the endpoint had answered in between.
   */
  @org.junit.jupiter.api.Test
  void anAnsweredFailureStartsTheUnansweredRecordAgain() throws Exception {
    InMemoryKmipServer first = InMemoryKmipServer.of(KmipVersion.V2_1),
        second = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(second);
    java.util.concurrent.atomic.AtomicBoolean hang =
        new java.util.concurrent.atomic.AtomicBoolean();
    Kms kms =
        connect(
            first,
            first
                .configure()
                .endpoints("first:5696", "second:5696")
                .callTimeout(Duration.ofMillis(600))
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e -> e.host().equals("first") ? KmsContractTest.hanging(first, hang) : second));
    Kms view = kms.withTimeout(Duration.ofMillis(100));
    hang.set(true);
    assertThrows(TransientException.class, () -> view.random(8));
    hang.set(false);
    assertThrows(NotFoundException.class, () -> view.keys().handle("no-such-key").attributes());
    Thread.sleep(700); // more than a whole call timeout since the first timeout
    hang.set(true);
    assertThrows(TransientException.class, () -> view.random(8));
    hang.set(false);
    view.random(8);
    assertEquals(0, second.exchanges(), "the endpoint answered in between: traffic stays");
  }

  // ---- operations and hints name what the application did ----

  /**
   * Operations built on others reported the inner step: {@code seal} at KMIP 1.2 said {@code
   * encrypt}. The A2 sample's expected outcome at 1.2 ({@code UNSUPPORTED:seal} in KmsSamplesIT) is
   * this {@code operation()}.
   */
  @org.junit.jupiter.api.Test
  void operationsNameThePublicMethodNotTheInnerStep() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V1_2);
    Kms kms = connect(server, server.configure().minimumVersion(KmipVersion.V1_2));
    KeyHandle kek = aes(kms, "kek");
    UnsupportedException seal =
        assertThrows(UnsupportedException.class, () -> kek.seal(PLAIN, AAD));
    assertEquals("seal", seal.operation());
    assertTrue(seal.getMessage().startsWith("seal: "), seal.getMessage());
    assertEquals(
        "generateDataKey",
        assertThrows(UnsupportedException.class, () -> kek.generateDataKey(256, AAD)).operation());
    assertEquals(
        "wrapKey",
        assertThrows(
                UnsupportedException.class,
                () -> kek.wrapKey(new javax.crypto.spec.SecretKeySpec(new byte[16], "AES"), AAD))
            .operation());
    UnsupportedException encrypt =
        assertThrows(
            UnsupportedException.class, () -> kek.encrypt(CipherSpec.aesGcm(), PLAIN, AAD));
    assertEquals("encrypt", encrypt.operation(), "the A3 and A5 samples' UNSUPPORTED:encrypt");
    // The name does not leak into the next call on the thread.
    assertEquals(
        "encrypt",
        assertThrows(UnsupportedException.class, () -> kek.encrypt(CipherSpec.aesGcm(), PLAIN))
            .operation());
  }

  /** Open and unwrapKey say so, also through a query, and their events too. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void openAndUnwrapReportThemselves(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    List<String> events = new ArrayList<>();
    Kms kms =
        connect(
            server,
            server
                .configure()
                .addListener(
                    new KmsListener() {
                      @Override
                      public void finished(KmsEvent e) {
                        events.add(e.operation());
                      }
                    }));
    KeyHandle kek = aes(kms, "kek"), other = aes(kms, "other");
    byte[] sealed = kek.seal(PLAIN, AAD);
    Ciphertext wrapped = kek.wrapKey(new javax.crypto.spec.SecretKeySpec(new byte[32], "AES"), AAD);
    events.clear();
    assertEquals(
        "open",
        assertThrows(KeyMismatchException.class, () -> other.open(sealed, AAD)).operation());
    assertEquals(
        "open",
        assertThrows(
                KeyMismatchException.class,
                () -> kms.keys().open(KeyQuery.byName("other"), sealed, AAD))
            .operation());
    assertEquals(
        "unwrapKey",
        assertThrows(
                KeyMismatchException.class, () -> other.unwrapKey(Expect.aes(256), wrapped, AAD))
            .operation());
    assertEquals(
        "unwrapKey",
        assertThrows(
                KeyMismatchException.class,
                () -> kms.keys().unwrapKey(KeyQuery.byName("other"), Expect.aes(256), wrapped, AAD))
            .operation());
    assertArrayEquals(PLAIN, kek.open(sealed, AAD));
    assertTrue(
        events.stream().allMatch(e -> e.equals("open") || e.equals("unwrapKey")),
        events.toString());
    assertTrue(events.contains("open"), events.toString());
  }

  /**
   * Encrypting with a Deactivated or Compromised key must not say it "needs activate()
   * first"; destroying an Active key gives a hint.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void stateHintsFitTheState(KmipVersion version) {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle retired = aes(kms, "retired");
    retired.revoke(RevocationReason.superseded("rotated"));
    StateConflictException e =
        assertThrows(
            StateConflictException.class, () -> retired.encrypt(CipherSpec.aesGcm(), PLAIN, AAD));
    // The key's state is read, so the hint names it.
    assertTrue(
        e.getMessage().contains("is DEACTIVATED")
            && e.getMessage().contains("Deactivated key no longer encrypts"),
        e.getMessage());
    KeyHandle active = aes(kms, "active");
    StateConflictException d = assertThrows(StateConflictException.class, active::destroy);
    assertTrue(d.getMessage().contains("deactivate it first"), d.getMessage());
  }

  // ---- a lookup by name that needs more than one page ----

  /**
   * FindByName's first Locate has no Maximum Items; when the server returned fewer than its
   * Located Items, the lookup started paging again from offset 0, fetching the first page twice.
   * It now continues from where that Locate stopped.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aLookupThatNeedsMorePagesContinuesAfterTheFirst(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    List<Integer> offsets = new ArrayList<>();
    boolean[] truncate = {false};
    Kms kms =
        connect(
            server,
            server
                .configure()
                .locatePageSize(2)
                .transport(
                    e ->
                        request -> {
                          Ttlv response = server.exchange(request);
                          if (!truncate[0] || !isOperation(request, Operation.LOCATE))
                            return response;
                          Ttlv payload =
                              request.require(Tag.BATCH_ITEM).require(Tag.REQUEST_PAYLOAD);
                          offsets.add(
                              payload.child(Tag.OFFSET_ITEMS).map(Ttlv::intValue).orElse(0));
                          if (payload.child(Tag.MAXIMUM_ITEMS).isPresent()) return response;
                          // The first Locate: the server returns one identifier and says how many
                          // match.
                          return truncated(response);
                        }));
    List<String> made = new ArrayList<>();
    for (int i = 0; i < 5; i++) made.add(orders(kms).createPreActive().id());
    truncate[0] = true;
    assertEquals(
        Optional.of(made.get(0)),
        kms.keys().findByName("orders", KeyState.PRE_ACTIVE).map(KeyHandle::id));
    assertEquals(List.of(0, 1, 3), offsets, "before: 0, 0, 2, 4");
  }

  /** A Locate response cut to its first identifier, with Located Items for all of them. */
  static Ttlv truncated(Ttlv response) {
    List<Ttlv> items = new ArrayList<>();
    for (Ttlv child : response.children()) {
      Optional<Ttlv> payload = child.child(Tag.RESPONSE_PAYLOAD);
      if (child.tag() != Tag.BATCH_ITEM.code() || payload.isEmpty()) {
        items.add(child);
        continue;
      }
      List<Ttlv> ids = payload.get().children(Tag.UNIQUE_IDENTIFIER);
      List<Ttlv> fields = new ArrayList<>(List.of(Ttlv.integer(Tag.LOCATED_ITEMS, ids.size())));
      if (!ids.isEmpty()) fields.add(ids.get(0));
      List<Ttlv> rewritten = new ArrayList<>();
      for (Ttlv f : child.children())
        rewritten.add(
            f.tag() == Tag.RESPONSE_PAYLOAD.code()
                ? Ttlv.structure(Tag.RESPONSE_PAYLOAD, fields)
                : f);
      items.add(Ttlv.structure(Tag.BATCH_ITEM, rewritten));
    }
    return Ttlv.structure(response.tag(), items);
  }

  // ---- what the README says decrypting after rotation costs ----

  /**
   * The README's claims. A name query after N rotations is N+2 requests; a group query
   * matches the key the ciphertext names directly (Re-key copies the group), so it is two.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aGroupQueryAvoidsTheWalkThatANameQueryNeeds(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle key = orders(kms).group("orders").create();
    Ciphertext c = key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    byte[] sealed = key.seal(PLAIN, AAD);
    KeyHandle current = key;
    for (int i = 0; i < 3; i++) current = current.rotate();
    long before = server.exchanges();
    assertArrayEquals(PLAIN, kms.keys().decrypt(KeyQuery.byName("orders"), c, AAD));
    assertEquals(3 + 2, server.exchanges() - before, "N+2 by name");
    before = server.exchanges();
    assertArrayEquals(PLAIN, kms.keys().decrypt(KeyQuery.all().group("orders"), c, AAD));
    assertEquals(2, server.exchanges() - before, "two by group");
    before = server.exchanges();
    assertArrayEquals(PLAIN, kms.keys().open(KeyQuery.all().group("orders"), sealed, AAD));
    assertEquals(2, server.exchanges() - before, "open: two");
    before = server.exchanges();
    assertArrayEquals(PLAIN, current.open(sealed, AAD));
    assertEquals(3 + 2, server.exchanges() - before, "open through the current handle: N+2");
  }

  // ---- walks over attackers' links ----

  /**
   * Links on keys an attacker controls cost the victim a request each: a forged record naming an
   * attacker key with many bogus Replacement links, or a planted duplicate with many Replaced
   * links, made one decrypt or lookup send hundreds of requests. Walks now follow at most 8 links
   * of a kind per key and read at most 128 keys; the forged record is BAD_DATA.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1"})
  void linksOnAnAttackersKeysCannotMakeAWalkExpensive(KmipVersion version) throws Exception {
    InMemoryKmipServer server =
        InMemoryKmipServer.of(version).linkCardinality(false); // the attacker's links
    Kms kms = connect(server);
    KeyHandle victim = orders(kms).create();
    KeyHandle attacker = aes(kms, "attacker");
    for (int i = 0; i < 40; i++) {
      KmsContractTest.link(
          kms, attacker.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, "bogus-" + i);
      KmsContractTest.link(kms, attacker.id(), Enums.LinkType.REPLACED_OBJECT_LINK, "bogus-" + i);
    }
    Ciphertext forged = attacker.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    long before = server.exchanges();
    KeyMismatchException e =
        assertThrows(
            KeyMismatchException.class,
            () -> kms.keys().decrypt(KeyQuery.byName("orders"), forged, AAD));
    assertEquals(KmsException.Category.BAD_DATA, e.category());
    assertTrue(
        server.exchanges() - before <= 3,
        "before: 41 requests; now " + (server.exchanges() - before));
    attacker.addName("orders");
    before = server.exchanges();
    assertEquals(Optional.of(victim), kms.keys().findByName("orders"));
    assertTrue(
        server.exchanges() - before <= 4,
        "before: 42 requests; now " + (server.exchanges() - before));
  }

  /** A forged record whose key's links form a cycle is BAD_DATA, not a server fault. */
  @org.junit.jupiter.api.Test
  void aForgedRecordCannotChooseItsCategoryWithLinks() throws Exception {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    aes(kms, "orders");
    KeyHandle a = aes(kms, "a"), b = aes(kms, "b");
    KmsContractTest.link(kms, a.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, b.id());
    KmsContractTest.link(kms, b.id(), Enums.LinkType.REPLACED_OBJECT_LINK, a.id());
    KmsContractTest.link(kms, b.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, a.id());
    KmsContractTest.link(kms, a.id(), Enums.LinkType.REPLACED_OBJECT_LINK, b.id());
    Ciphertext forged = a.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    KeyMismatchException e =
        assertThrows(
            KeyMismatchException.class,
            () -> kms.keys().decrypt(KeyQuery.byName("orders"), forged, AAD));
    assertEquals(
        KmsException.Category.BAD_DATA, e.category(), "before: ProtocolViolationException, SERVER");
  }

  /**
   * After more than 64 rotations the walk back stopped at a key newer than a duplicate planted
   * later, which then won the name. Now a longer lineage that does not rank first cannot be ranked.
   */
  @org.junit.jupiter.api.Test
  void aLineageTooLongToRankIsALimitNotATakeover() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms victim = connect(server), attacker = connect(server);
    KeyHandle current = orders(victim).create();
    KeyHandle planted = orders(attacker).create();
    for (int i = 0; i < Lineage.LIMIT + 2; i++) current = current.rotate();
    UnsupportedException e =
        assertThrows(UnsupportedException.class, () -> victim.keys().findByName("orders"));
    assertTrue(
        e.getMessage().contains("cannot be ranked"),
        e.getMessage() + " (before: " + planted + " won)");
  }

  /**
   * A Re-key reply carries only an identifier: one naming an unrelated Pre-Active secret made
   * rotate() activate the secret and return it as the replacement.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aReKeyReplyMustNameTheReplacement(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    String[] secret = {null};
    Kms kms =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request ->
                            CreationResponseTypeTest.swap(
                                server.exchange(request),
                                Operation.RE_KEY,
                                Tag.UNIQUE_IDENTIFIER,
                                secret[0])));
    KeyHandle key = aes(kms, "orders");
    secret[0] =
        kms.keys()
            .registerSecret(SecretData.Type.SEED, new byte[] {1, 2, 3})
            .registerPreActive()
            .id();
    OutcomeUnknownException e = assertThrows(OutcomeUnknownException.class, key::rotate);
    assertTrue(e.getMessage().contains("SECRET_DATA"), e.getMessage());
    assertEquals(
        Optional.of(KeyState.PRE_ACTIVE), server.state(secret[0]), "the secret was not activated");
  }

  /**
   * A replacement that no longer exists (destroyed and purged) left the key unrotatable ("already
   * replaced"); it no longer blocks rotate(). latest() cannot tell where the chain went, so until
   * another replacement is confirmed it is STATE, not this key.
   */
  @org.junit.jupiter.api.Test
  void aReplacementThatNoLongerExistsDoesNotCount() throws Exception {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle key = aes(kms, "orders");
    KmsContractTest.link(kms, key.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, "purged-long-ago");
    assertThrows(StateConflictException.class, key::latest);
    KeyHandle next = key.rotate();
    assertEquals(next, key.latest());
  }

  /** AES key wrap has no valid output for a ciphertext under 24 bytes, so no Data is not "empty". */
  @org.junit.jupiter.api.Test
  void aesKeyWrapNeverExpectsAnEmptyResult() {
    assertEquals(-1, CipherSpec.keyWrap().outputLength(8, false));
    assertEquals(-1, CipherSpec.keyWrap().outputLength(16, false));
    assertEquals(16, CipherSpec.keyWrap().outputLength(24, false));
    assertEquals(24, CipherSpec.keyWrap().outputLength(16, true));
  }

  /**
   * A listener runs inside the call that fires it; a call it makes to a Kms got the outer call's
   * operation name and deadline.
   */
  @org.junit.jupiter.api.Test
  void aListenerCallingAKmsGetsItsOwnOperationName() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    List<String> seen = new ArrayList<>();
    Kms[] other = {null};
    boolean[] inside = {false};
    Kms kms =
        connect(
            server,
            server
                .configure()
                .addListener(
                    new KmsListener() {
                      @Override
                      public void started(KmsEvent e) {
                        if (!e.operation().equals("seal") || inside[0] || other[0] == null) return;
                        inside[0] = true;
                        try {
                          other[0].keys().handle("no-such-key").attributes();
                        } catch (NotFoundException n) {
                          seen.add(n.operation());
                        } finally {
                          inside[0] = false;
                        }
                      }
                    }));
    other[0] = connect(server);
    aes(kms, "kek").seal(PLAIN, AAD);
    assertEquals(List.of("attributes"), seen, "before: seal");
  }

  /** A sealed container whose data key has the wrong size is a bad record, not a caller error. */
  @org.junit.jupiter.api.Test
  void aSealedContainerWithAWrongSizeDataKeyIsBadData() {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "kek");
    byte[] wrapped =
        kek.wrapKey(new javax.crypto.spec.SecretKeySpec(new byte[16], "AES"), AAD).toBytes();
    java.nio.ByteBuffer b =
        java.nio.ByteBuffer.allocate(3 + 1 + 2 + wrapped.length + 1 + 12 + 4 + 16);
    b.put(new byte[] {'K', 'T', 'E', 1})
        .putShort((short) wrapped.length)
        .put(wrapped)
        .put((byte) 12)
        .put(new byte[12])
        .putInt(16)
        .put(new byte[16]);
    KeyMismatchException e =
        assertThrows(KeyMismatchException.class, () -> kek.open(b.array(), AAD));
    assertEquals(KmsException.Category.BAD_DATA, e.category(), e.getMessage());
  }
}
