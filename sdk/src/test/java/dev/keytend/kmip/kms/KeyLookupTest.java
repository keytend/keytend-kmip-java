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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Key lookup by name and lineage: planted duplicates, unreadable links, purged keys and single flights. */
class KeyLookupTest {
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

  // ---- unresolved ancestry in name lookup ----

  /**
   * A duplicate planted under the victim's name, the victim rotates,
   * and its first key is destroyed and purged. The walk back from the replacement then stopped at
   * the replacement as if it were a lineage's first key, and its later date lost to the planted
   * key. Now the lookup fails closed.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void purgingTheFirstKeyDoesNotHandTheNameToADuplicate(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Map<String, Enums.ResultReason> purged = new ConcurrentHashMap<>();
    Kms victim = hiding(server, purged), attacker = connect(server);
    KeyHandle original = orders(victim).create();
    KeyHandle planted = orders(attacker).create();
    KeyHandle rotated = original.rotate();
    assertEquals(Optional.of(rotated), victim.keys().findByName("orders"));

    original.revoke(RevocationReason.superseded("rotated"));
    original.destroy();
    purged.put(original.id(), Enums.ResultReason.ITEM_NOT_FOUND);
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> victim.keys().findByName("orders"),
            "before: " + planted);
    assertEquals(KmsException.Category.STATE, e.category());
    assertTrue(
        e.getMessage().contains(planted.id()) && e.getMessage().contains(rotated.id()),
        e.getMessage());
    assertTrue(e.getMessage().contains("removeName"), e.getMessage());
    assertThrows(StateConflictException.class, () -> orders(victim).findOrCreate());

    // Recovery: the name removed from the planted key.
    planted.removeName("orders");
    assertEquals(Optional.of(rotated), victim.keys().findByName("orders"));
  }

  /** Without a duplicate, rotating and then purging the first key keeps working. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void rotatingThenPurgingWithoutADuplicateKeepsTheName(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Map<String, Enums.ResultReason> purged = new ConcurrentHashMap<>();
    Kms kms = hiding(server, purged);
    KeyHandle original = orders(kms).create();
    KeyHandle rotated = original.rotate();
    original.revoke(RevocationReason.superseded("rotated"));
    original.destroy();
    purged.put(original.id(), Enums.ResultReason.ITEM_NOT_FOUND);
    assertEquals(Optional.of(rotated), kms.keys().findByName("orders"));
    assertEquals(rotated, orders(kms).findOrCreate());
    KeyHandle next = rotated.rotate();
    assertEquals(Optional.of(next), kms.keys().findByName("orders"));
  }

  /**
   * An unresolved lineage that already ranks first cannot lose by starting earlier, so the
   * lookup still answers: here the victim's lineage, whose first key was purged, against a
   * duplicate created after its replacement.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void anUnresolvedLineageThatRanksFirstStillWins(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Map<String, Enums.ResultReason> purged = new ConcurrentHashMap<>();
    Kms victim = hiding(server, purged), attacker = connect(server);
    server.clock(at(0));
    KeyHandle original = orders(victim).create();
    KeyHandle rotated = original.rotate();
    server.clock(at(10));
    KeyHandle planted = orders(attacker).create();
    original.revoke(RevocationReason.superseded("rotated"));
    original.destroy();
    purged.put(original.id(), Enums.ResultReason.ITEM_NOT_FOUND);
    assertEquals(Optional.of(rotated), victim.keys().findByName("orders"), "not " + planted);
  }

  /**
   * A duplicate whose Replaced Object link names an object the caller may not
   * read. The walk let the Permission Denied out, so the name lookup failed as FIX_ACCESS, as if
   * the caller's credentials were wrong. The planted key's lineage may start earlier than the
   * victim's, so the lookup fails closed instead.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void anUnreadableLinkIsNotAPermissionFailureOfTheLookup(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Map<String, Enums.ResultReason> unreadable = new ConcurrentHashMap<>();
    Kms victim = hiding(server, unreadable), attacker = connect(server);
    KeyHandle original = orders(victim).create();
    KeyHandle hidden = KmsContractTest.aes(attacker, "attackers-own");
    KeyHandle planted = orders(attacker).create();
    KmsContractTest.link(attacker, planted.id(), Enums.LinkType.REPLACED_OBJECT_LINK, hidden.id());
    unreadable.put(hidden.id(), Enums.ResultReason.PERMISSION_DENIED);
    KmsException e = assertThrows(KmsException.class, () -> victim.keys().findByName("orders"));
    assertEquals(StateConflictException.class, e.getClass(), "before: " + e);
    assertTrue(
        e.getMessage().contains(planted.id()) && e.getMessage().contains(original.id()),
        e.getMessage());
    assertThrows(StateConflictException.class, () -> orders(victim).findOrCreate());
    assertArrayEquals(
        PLAIN,
        original.decrypt(original.encrypt(CipherSpec.aesGcm(), PLAIN, AAD), AAD),
        "the victim's own key is unaffected");
  }

  // ---- a handle kept from startup ----

  /**
   * Two instances keep the handle findOrCreate gave them at
   * startup; instance A rotates and seals under the replacement. Instance B's handle refused the
   * data as BAD_DATA ("neither mock-1 nor a key it replaced"), so a handler keyed on the category
   * quarantined good records. It now accepts the confirmed keys that replaced it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aHandleFromStartupOpensWhatAnotherInstanceSealedAfterRotating(KmipVersion version)
      throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms instanceA = connect(server), instanceB = connect(server);
    KeyHandle kekA = orders(instanceA).findOrCreate(), kekB = orders(instanceB).findOrCreate();
    assertEquals(kekA.id(), kekB.id());

    KeyHandle rotated = kekA.rotate();
    kekA = rotated;
    byte[] sealed = kekA.seal(PLAIN, AAD);
    assertArrayEquals(PLAIN, kekB.open(sealed, AAD), "before: KeyMismatchException [BAD_DATA]");
    Ciphertext c = kekA.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    assertArrayEquals(PLAIN, kekB.decrypt(c, AAD));
    javax.crypto.SecretKey dek = new javax.crypto.spec.SecretKeySpec(new byte[32], "AES");
    assertArrayEquals(
        dek.getEncoded(),
        kekB.unwrapKey(Expect.aes(256), kekA.wrapKey(dek, AAD), AAD).getEncoded());

    // Two rotations behind.
    KeyHandle twice = rotated.rotate();
    byte[] newest = twice.seal(PLAIN, AAD);
    assertArrayEquals(PLAIN, kekB.open(newest, AAD));

    // A key outside the chain in both directions stays BAD_DATA, also one that claims (by its own
    // Replaced Object link only) to have replaced the handle's key.
    KeyHandle other = KmsContractTest.aes(instanceA, "other");
    KmsContractTest.link(instanceA, other.id(), Enums.LinkType.REPLACED_OBJECT_LINK, kekB.id());
    KeyMismatchException e =
        assertThrows(KeyMismatchException.class, () -> kekB.open(other.seal(PLAIN, AAD), AAD));
    assertEquals(KmsException.Category.BAD_DATA, e.category());
    assertTrue(e.getMessage().contains("nor a key that replaced it"), e.getMessage());

    // allowingCompromised() covers the handle's own key only, as for predecessors.
    twice.revoke(
        RevocationReason.keyCompromise("leaked", java.time.Instant.now().minusSeconds(60)));
    StateConflictException compromised =
        assertThrows(
            StateConflictException.class, () -> kekB.allowingCompromised().open(newest, AAD));
    assertTrue(compromised.getMessage().contains(twice.id()), compromised.getMessage());
    assertArrayEquals(PLAIN, kekB.open(sealed, AAD), "a healthy successor still opens");
  }

  /**
   * A handle more than 64 rotations from its lineage's first key still accepts its
   * successor's ciphertext: the backward walk reaching its bound does not end the search.
   */
  @Test
  void aLongLineageDoesNotHideASuccessor() {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle current = orders(kms).create();
    for (int i = 0; i <= Lineage.LIMIT; i++) current = current.rotate();
    KeyHandle stale = current, next = current.rotate();
    assertArrayEquals(PLAIN, stale.decrypt(next.encrypt(CipherSpec.aesGcm(), PLAIN, AAD), AAD));
    KeyHandle stranger = KmsContractTest.aes(kms, "stranger");
    assertThrows(
        UnsupportedException.class,
        () -> stale.decrypt(stranger.encrypt(CipherSpec.aesGcm(), PLAIN, AAD), AAD));
  }

  // ---- a query that matches nothing ----

  /**
   * A query that matches no object (a misspelt name) was BAD_DATA, so every record would
   * have been quarantined for a configuration error. It is FIX_REQUEST; a query that matches keys
   * other than the ciphertext's stays BAD_DATA.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aQueryThatMatchesNothingIsTheCallersToFix(KmipVersion version) {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle key = orders(kms).create();
    KmsContractTest.aes(kms, "other");
    byte[] sealed = key.seal(PLAIN, AAD);
    Ciphertext c = key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);

    KeyMismatchException nope =
        assertThrows(
            KeyMismatchException.class,
            () -> kms.keys().open(KeyQuery.byName("nope"), sealed, AAD));
    assertEquals(KmsException.Category.FIX_REQUEST, nope.category(), "before: BAD_DATA");
    assertTrue(nope.getMessage().contains("no object on the server matches"), nope.getMessage());
    assertEquals("open", nope.operation());
    assertEquals(
        KmsException.Category.FIX_REQUEST,
        assertThrows(
                KeyMismatchException.class,
                () -> kms.keys().decrypt(KeyQuery.byName("nope"), c, AAD))
            .category());

    assertEquals(
        KmsException.Category.BAD_DATA,
        assertThrows(
                KeyMismatchException.class,
                () -> kms.keys().open(KeyQuery.byName("other"), sealed, AAD))
            .category());
    assertArrayEquals(PLAIN, kms.keys().open(KeyQuery.byName("orders"), sealed, AAD));
  }

  // ---- rotate() returns only a usable replacement ----

  /**
   * Rotate() returned a replacement it had read as Compromised (here another client revokes
   * it as soon as the Re-key is answered). Now any state other than Active and Pre-Active is a
   * {@link PartialCompletionException} carrying the replacement, and so is an unknown State.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void rotateDoesNotReturnAReplacementThatIsNotUsable(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms other = connect(server);
    java.util.concurrent.atomic.AtomicReference<RevocationReason> revokeReplacement =
        new java.util.concurrent.atomic.AtomicReference<>();
    java.util.concurrent.atomic.AtomicReference<KmsResponseValidationTest.StateView> view =
        new java.util.concurrent.atomic.AtomicReference<>(
            KmsResponseValidationTest.StateView.AS_SENT);
    Kms kms =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request -> {
                          Ttlv response =
                              KmsResponseValidationTest.rewriteState(
                                  server.exchange(request), view.get());
                          RevocationReason reason = revokeReplacement.get();
                          if (reason != null
                              && RotationAndNameChoiceTest.isOperation(request, Operation.RE_KEY))
                            other
                                .keys()
                                .handle(
                                    response
                                        .require(Tag.BATCH_ITEM)
                                        .require(Tag.RESPONSE_PAYLOAD)
                                        .require(Tag.UNIQUE_IDENTIFIER)
                                        .textValue())
                                .revoke(reason);
                          return response;
                        }));
    java.time.Instant when = java.time.Instant.now().minusSeconds(60);

    revokeReplacement.set(RevocationReason.keyCompromise("leaked", when));
    KeyHandle key = orders(kms).create();
    PartialCompletionException e =
        assertThrows(PartialCompletionException.class, key::rotate, "before: returned");
    KeyHandle created = e.created().get(0);
    assertEquals(Optional.of(KeyState.COMPROMISED), server.state(created.id()));
    assertTrue(
        e.getMessage().contains("COMPROMISED") && e.getMessage().contains("replace it in turn"),
        e.getMessage());
    // The state the client found, on the cause.
    assertEquals(
        Optional.of(KeyState.COMPROMISED),
        assertInstanceOf(StateConflictException.class, e.getCause()).observedState());
    assertInstanceOf(StateConflictException.class, e.getCause());

    revokeReplacement.set(RevocationReason.superseded("by someone else"));
    KeyHandle second = KmsContractTest.aes(kms, "second");
    e = assertThrows(PartialCompletionException.class, second::rotate);
    assertEquals(Optional.of(KeyState.DEACTIVATED), server.state(e.created().get(0).id()));

    revokeReplacement.set(null);
    view.set(KmsResponseValidationTest.StateView.UNKNOWN_VALUE);
    KeyHandle third = KmsContractTest.aes(kms, "third");
    e = assertThrows(PartialCompletionException.class, third::rotate);
    assertInstanceOf(ProtocolViolationException.class, e.getCause());
    view.set(KmsResponseValidationTest.StateView.AS_SENT);

    // The recovery the message gives: the unusable replacement is latest(), and replacing it in
    // turn works (replaceCompromised: rotate() refuses a Compromised key).
    KeyHandle usable =
        key.latest().replaceCompromised(RevocationReason.keyCompromise("leaked", when));
    assertEquals(KeyState.ACTIVE, usable.attributes().state());
  }

  // ---- KeyPairHandle.revoke has one deadline ----

  /**
   * A 220 ms call timeout, each Revoke taking 140 ms: each Revoke must not have a deadline of its
   * own (the call would succeed after about 283 ms). The second Revoke gets what is left of
   * the call's, and a transport that honors it ends the call at the deadline.
   */
  @Test
  void revokingAPairHasOneDeadline() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    List<Long> remaining = new java.util.concurrent.CopyOnWriteArrayList<>();
    java.util.concurrent.atomic.AtomicBoolean slow =
        new java.util.concurrent.atomic.AtomicBoolean();
    Kms kms =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .callTimeout(java.time.Duration.ofMillis(220))
                .transport(
                    e ->
                        new dev.keytend.kmip.transport.KmipTransport() {
                          @Override
                          public Ttlv exchange(Ttlv request) throws java.io.IOException {
                            return server.exchange(request);
                          }

                          @Override
                          public Ttlv exchange(
                              Ttlv request, dev.keytend.kmip.transport.CallContext context)
                              throws java.io.IOException {
                            if (slow.get()
                                && RotationAndNameChoiceTest.isOperation(
                                    request, Operation.REVOKE)) {
                              long left = context.remainingNanos();
                              remaining.add(left);
                              long wait =
                                  Math.min(
                                      java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(140),
                                      Math.max(0, left));
                              RotationAndNameChoiceTest.await(
                                  () -> java.util.concurrent.TimeUnit.NANOSECONDS.sleep(wait));
                              if (wait < java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(140))
                                throw new java.net.SocketTimeoutException("deadline");
                            }
                            return server.exchange(request);
                          }
                        }));
    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.ec(Curve.P_256))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .create();
    slow.set(true);
    KmsException e =
        assertThrows(
            KmsException.class,
            () -> pair.revoke(RevocationReason.superseded("retired")),
            "before: succeeded");
    assertEquals(2, remaining.size(), remaining.toString());
    assertTrue(
        remaining.get(1) < java.util.concurrent.TimeUnit.MILLISECONDS.toNanos(100),
        "the second Revoke had " + remaining);
    assertEquals(pair.publicKey().id(), e.objectId().orElseThrow());
    assertEquals(Optional.of(KeyState.DEACTIVATED), server.state(pair.privateKey().id()));
  }

  // ---- the single-flight key ----

  /**
   * The single-flight key compared byte-array custom values by identity and depended on the
   * order the attributes were set in, so identical concurrent calls each created a key. Callers
   * here set the same two attributes, a fresh byte array each and in either order.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void identicalFindOrCreateCallsShareOneFlight(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms =
        connect(
            server,
            server
                .configure()
                .transport(
                    e ->
                        request -> {
                          if (RotationAndNameChoiceTest.isOperation(request, Operation.CREATE))
                            RotationAndNameChoiceTest.await(() -> Thread.sleep(50));
                          return server.exchange(request);
                        }));
    CustomAttribute tag = CustomAttribute.client("Tag"), tenant = CustomAttribute.client("Tenant");
    int callers = 16;
    java.util.concurrent.ExecutorService pool =
        java.util.concurrent.Executors.newFixedThreadPool(callers);
    try {
      java.util.concurrent.CountDownLatch start = new java.util.concurrent.CountDownLatch(1);
      List<java.util.concurrent.Future<KeyHandle>> results = new ArrayList<>();
      for (int i = 0; i < callers; i++) {
        boolean reversed = i % 2 == 1;
        results.add(
            pool.submit(
                () -> {
                  KeyCreation c = orders(kms);
                  if (reversed) c.custom(tenant, "acme").custom(tag, new byte[] {1, 2, 3});
                  else c.custom(tag, new byte[] {1, 2, 3}).custom(tenant, "acme");
                  start.await();
                  return c.findOrCreate();
                }));
      }
      start.countDown();
      Set<String> ids = new HashSet<>();
      for (var f : results) ids.add(f.get(30, java.util.concurrent.TimeUnit.SECONDS).id());
      assertEquals(1, ids.size(), ids.toString());
      assertEquals(1, KmsContractTest.sent(server, Operation.CREATE), "one key created");
    } finally {
      pool.shutdownNow();
    }
  }

  /** The key is a copy: changing the builder's array afterwards does not change it. */
  @Test
  void theSingleFlightKeyIsImmutable() {
    ObjectOptions options = new ObjectOptions();
    byte[] value = {1, 2, 3};
    options.custom(CustomAttribute.client("Tag"), value);
    Map<CustomAttribute, Object> key = options.customValues();
    options.custom(CustomAttribute.client("Tag"), new byte[] {9});
    options.custom(CustomAttribute.client("Other"), "x");
    assertEquals(1, key.size());
    ObjectOptions same = new ObjectOptions();
    same.custom(CustomAttribute.client("Tag"), new byte[] {1, 2, 3});
    assertEquals(same.customValues(), key);
    assertThrows(
        UnsupportedOperationException.class, () -> key.put(CustomAttribute.client("New"), "y"));
  }

  // ---- application tests construct every category ----

  /**
   * An application could not construct a BAD_DATA {@link KeyMismatchException} to test its
   * handler: the public constructors always gave FIX_REQUEST. Every category the SDK produces now
   * has a public way to construct it.
   */
  @Test
  void applicationTestsCanConstructEveryCategoryTheSdkProduces() {
    assertEquals(
        KmsException.Category.BAD_DATA,
        new KeyMismatchException("misfiled", KmsException.Category.BAD_DATA).category());
    assertEquals(
        KmsException.Category.FIX_REQUEST,
        new KeyMismatchException("wrong usages", KmsException.Category.FIX_REQUEST).category());
    assertThrows(
        IllegalArgumentException.class,
        () -> new KeyMismatchException("x", KmsException.Category.STATE));
    assertThrows(
        NullPointerException.class,
        () -> new KeyMismatchException("x", (KmsException.Category) null));
    KeyMismatchException e = new KeyMismatchException("misfiled", KmsException.Category.BAD_DATA);
    assertEquals("misfiled", e.getMessage());
    assertEquals("", e.operation());
    assertEquals(Optional.empty(), e.objectId());

    Set<KmsException.Category> constructed = EnumSet.noneOf(KmsException.Category.class);
    for (KmsException k :
        List.of(
            new TransientException("t"),
            new NotFoundException("n"),
            new PermissionDeniedException("p"),
            new InvalidRequestException("i"),
            new KeyMismatchException("k", KmsException.Category.BAD_DATA),
            new StateConflictException("s"),
            new CryptographicFailureException("c", CryptographicFailureException.Kind.UNCONFIRMED),
            new OutcomeUnknownException("o"),
            new PartialCompletionException("pc", List.of(), new ServerFailureException("cause")),
            new ServerFailureException("sf"))) constructed.add(k.category());
    assertEquals(EnumSet.allOf(KmsException.Category.class), constructed);
  }

  // ---- a listener re-entering findOrCreate ----

  /**
   * A listener calling findOrCreate for the key the observed findOrCreate is making waited
   * for itself until its deadline. It now fails at once, and the outer call is unaffected.
   */
  @Test
  void aListenerCallingFindOrCreateForTheSameKeyDoesNotWaitForItself() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    List<Throwable> seen = new java.util.concurrent.CopyOnWriteArrayList<>();
    Kms[] self = {null};
    java.util.concurrent.atomic.AtomicBoolean inside =
        new java.util.concurrent.atomic.AtomicBoolean();
    self[0] =
        connect(
            server,
            server
                .configure()
                .callTimeout(java.time.Duration.ofSeconds(3))
                .addListener(
                    new KmsListener() {
                      @Override
                      public void started(KmsEvent e) {
                        if (!e.operation().equals("findOrCreate")
                            || !inside.compareAndSet(false, true)) return;
                        long t = System.nanoTime();
                        try {
                          orders(self[0]).findOrCreate();
                        } catch (Throwable thrown) {
                          seen.add(thrown);
                        }
                        seen.add(
                            new AssertionError(
                                "took " + (System.nanoTime() - t) / 1_000_000 + " ms"));
                      }
                    }));
    KeyHandle key = orders(self[0]).findOrCreate();
    assertEquals(KeyState.ACTIVE, key.attributes().state());
    assertEquals(2, seen.size(), seen.toString());
    assertInstanceOf(
        IllegalStateException.class, seen.get(0), "before: TransientException after the deadline");
    long took = Long.parseLong(seen.get(1).getMessage().replaceAll("\\D", ""));
    assertTrue(took < 1000, seen.toString());
  }

  // ---- the in-memory server's default version, and 3.0 group refusals ----

  /**
   * A Kms from the default in-memory server negotiated the 3.0 draft, which production never
   * does by default, so groups failed there. It now negotiates what production would (2.1); a
   * server that speaks only 3.0 still negotiates 3.0.
   */
  @Test
  void theDefaultInMemoryServerNegotiatesWhatProductionWould() {
    InMemoryKmipServer server = InMemoryKmipServer.of();
    Kms kms = connect(server);
    assertEquals(KmipVersion.V2_1, kms.version(), "before: V3_0");
    kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).group("g").create();
    assertEquals(KmipVersion.V3_0, connect(InMemoryKmipServer.of(KmipVersion.V3_0)).version());
    assertEquals(
        KmipVersion.V3_0,
        connect(server, server.configure().maximumVersion(KmipVersion.V3_0)).version(),
        "a test that wants 3.0 asks for it");
  }

  /** On 3.0, the group refusal of create() and createKeyPair() named "register". */
  @Test
  void aGroupRefusalOn30NamesTheMethodCalled() throws Exception {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V3_0));
    UnsupportedException create =
        assertThrows(
            UnsupportedException.class,
            () -> kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).group("g").create());
    assertEquals("create", create.operation(), create.getMessage());
    UnsupportedException pair =
        assertThrows(
            UnsupportedException.class,
            () ->
                kms.keys()
                    .createKeyPair(KeyPairSpec.ec(Curve.P_256))
                    .privateUsages(KeyUsage.SIGN)
                    .publicUsages(KeyUsage.VERIFY)
                    .group("g")
                    .create());
    assertEquals("createKeyPair", pair.operation(), pair.getMessage());
    UnsupportedException register =
        assertThrows(
            UnsupportedException.class,
            () ->
                kms.keys()
                    .registerSecret(SecretData.Type.SEED, new byte[] {1})
                    .group("g")
                    .register());
    assertEquals("register", register.operation());
  }

  // ---- rotating something that is not a symmetric key ----

  /**
   * {@code handle(secretId).rotate()} was InvalidRequestException at 1.4 and
   * KeyMismatchException at 2.1 (the servers' Re-key refusals differ). It is KeyMismatchException
   * on every version, and no Re-key is sent.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void rotatingSomethingOtherThanASymmetricKeyIsOneMismatch(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    String secret =
        kms.keys().registerSecret(SecretData.Type.SEED, new byte[] {1, 2, 3}).register().id();
    KeyMismatchException e =
        assertThrows(KeyMismatchException.class, () -> kms.keys().handle(secret).rotate());
    assertEquals(KmsException.Category.FIX_REQUEST, e.category());
    assertTrue(e.getMessage().contains("SECRET_DATA"), e.getMessage());
    assertEquals(0, KmsContractTest.sent(server, Operation.RE_KEY));
  }

  // ---- errors name the public method ----

  /**
   * The read inside register() and createKeyPair() reported "locateWithAttributes", the
   * keyPair() check and the name-lookup walk "attributes": inner steps the application never
   * called. They name the public method now.
   */
  @Test
  void errorsInsideAMethodNameThatMethod() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Map<String, Enums.ResultReason> failing = new ConcurrentHashMap<>();
    Kms kms = hiding(server, failing), other = connect(server);

    server.failNext(
        dev.keytend.kmip.testing.ServerOperation.GET_ATTRIBUTES,
        dev.keytend.kmip.testing.Fault.PERMISSION_DENIED);
    PartialCompletionException registered =
        assertThrows(
            PartialCompletionException.class,
            () -> kms.keys().registerSecret(SecretData.Type.SEED, new byte[] {1}).register());
    assertEquals(
        "register", ((KmsException) registered.getCause()).operation(), "before: attributes");

    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.ec(Curve.P_256))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .create();
    server.failNext(
        dev.keytend.kmip.testing.ServerOperation.GET_ATTRIBUTES,
        dev.keytend.kmip.testing.Fault.PERMISSION_DENIED);
    assertEquals(
        "keyPair",
        assertThrows(
                PermissionDeniedException.class, () -> kms.keys().keyPair(pair.privateKey().id()))
            .operation(),
        "before: attributes");

    orders(kms).create();
    KeyHandle planted = orders(other).create();
    KmsContractTest.link(other, planted.id(), Enums.LinkType.REPLACED_OBJECT_LINK, "broken");
    failing.put("broken", Enums.ResultReason.GENERAL_FAILURE);
    KmsException lookup = assertThrows(KmsException.class, () -> kms.keys().findByName("orders"));
    assertEquals("findByName", lookup.operation(), "before: attributes");
    assertTrue(lookup.getMessage().startsWith("findByName"), lookup.getMessage());
  }

  static java.time.Clock at(int seconds) {
    return java.time.Clock.fixed(
        java.time.Instant.parse("2026-10-27T00:00:00Z").plusSeconds(seconds),
        java.time.ZoneOffset.UTC);
  }

  // ---- lineage starts and purged keys ----

  /**
   * An unresolved lineage whose start shares its Initial Date with another lineage's start does not
   * rank first for certain: the purged key's identifier, which broke the tie, is unknown. Before,
   * the purge moved the name silently from the duplicate (k5) to the victim (k1).
   */
  @Test
  void anUnresolvedLineageThatTiesOnTheDateFailsClosed() {
    Deque<String> ids = new ArrayDeque<>(List.of("k9", "k5", "k1"));
    InMemoryKmipServer server =
        InMemoryKmipServer.of(KmipVersion.V2_1).clock(at(0)).identifierSource(ids::removeFirst);
    Map<String, Enums.ResultReason> purged = new ConcurrentHashMap<>();
    Kms victim = hiding(server, purged), other = connect(server);
    KeyHandle original = orders(victim).create();
    KeyHandle duplicate = orders(other).create();
    original.rotate();
    assertEquals(duplicate.id(), victim.keys().findByName("orders").orElseThrow().id());
    original.revoke(RevocationReason.superseded("rotated"));
    original.destroy();
    purged.put(original.id(), Enums.ResultReason.ITEM_NOT_FOUND);
    assertThrows(
        StateConflictException.class, () -> victim.keys().findByName("orders"), "before: k1");
  }

  /**
   * A predecessor that can be read but no longer names its replacement (a server that drops a
   * destroyed key's links) left the replacement looking like a lineage's first key, and the name
   * moved silently to the duplicate, as in the planted-duplicate case above. A link the walk does
   * not follow now leaves the start open.
   */
  @Test
  void aPredecessorThatNoLongerLinksBackLeavesTheStartOpen() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Set<String> stripped = ConcurrentHashMap.newKeySet();
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
                            if (id.isPresent() && stripped.contains(id.get()))
                              return withoutLinks(response);
                          }
                          return response;
                        }));
    Kms attacker = connect(server);
    KeyHandle original = orders(victim).create();
    KeyHandle planted = orders(attacker).create();
    KeyHandle rotated = original.rotate();
    original.revoke(RevocationReason.superseded("rotated"));
    original.destroy();
    assertEquals(Optional.of(rotated), victim.keys().findByName("orders"), "destroyed, links kept");
    stripped.add(original.id());
    assertThrows(
        StateConflictException.class,
        () -> victim.keys().findByName("orders"),
        "before: " + planted);
  }

  static Ttlv withoutLinks(Ttlv node) {
    if (node.type() != Ttlv.Type.STRUCTURE) return node;
    List<Ttlv> children = new ArrayList<>();
    for (Ttlv child : node.children())
      if (child.tag() != Tag.LINK.code()) children.add(withoutLinks(child));
    return Ttlv.structure(node.tag(), children);
  }

  /**
   * A stale handle walked back through its key's whole history before looking forward: with 30
   * predecessors, opening a record sealed one rotation later took 33 requests. The forward walk now
   * runs first: Get Attributes of the handle's key and of the newer key, and the Decrypt.
   */
  @Test
  void aStaleHandlePaysForTheRotationsItIsBehindNotForItsHistory() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms a = connect(server), b = connect(server);
    KeyHandle key = orders(a).create();
    byte[] old = key.seal(PLAIN, AAD);
    for (int i = 0; i < 30; i++) key = key.rotate();
    KeyHandle stale = orders(b).findOrCreate();
    KeyHandle next = key.rotate();
    byte[] sealed = next.seal(PLAIN, AAD);
    int before = server.exchanges();
    assertArrayEquals(PLAIN, stale.open(sealed, AAD));
    assertEquals(3, server.exchanges() - before, "before: 33");
    before = server.exchanges();
    assertArrayEquals(PLAIN, next.open(sealed, AAD));
    assertEquals(2, server.exchanges() - before);
    // Data older than the handle's key: one more for the successor read first, then the walk back.
    before = server.exchanges();
    assertArrayEquals(PLAIN, stale.open(old, AAD));
    assertEquals(2 + 1 + 30, server.exchanges() - before);
  }

  /**
   * On 3.0 a query with a link filter cannot be searched, so the Locate that tells "nothing
   * matches" apart failed, and a record outside a query that does match keys was FIX_REQUEST. It is
   * BAD_DATA again.
   */
  @Test
  void aQueryTheServerCannotSearchStaysBadData() {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V3_0));
    KeyHandle first = orders(kms).create();
    KeyHandle second = first.rotate();
    KeyHandle stranger = KmsContractTest.aes(kms, "stranger");
    KeyQuery query = KeyQuery.all().linkedTo(LinkKind.REPLACED, first.id());
    assertArrayEquals(
        PLAIN, kms.keys().decrypt(query, second.encrypt(CipherSpec.aesGcm(), PLAIN, AAD), AAD));
    KeyMismatchException e =
        assertThrows(
            KeyMismatchException.class,
            () -> kms.keys().decrypt(query, stranger.encrypt(CipherSpec.aesGcm(), PLAIN, AAD), AAD),
            "before: UnsupportedException");
    assertEquals(KmsException.Category.BAD_DATA, e.category());
  }

  /** Every step of findOrCreate reports findOrCreate (before: findByName, create, activate). */
  @Test
  void findOrCreateReportsItself() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    List<String> operations = new java.util.concurrent.CopyOnWriteArrayList<>();
    Kms kms =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .addListener(
                    new KmsListener() {
                      @Override
                      public void started(KmsEvent e) {
                        operations.add(e.operation());
                      }
                    }));
    orders(kms).findOrCreate();
    assertEquals(Set.of("findOrCreate"), new HashSet<>(operations), operations.toString());
    server.failNext(
        dev.keytend.kmip.testing.ServerOperation.LOCATE,
        dev.keytend.kmip.testing.Fault.PERMISSION_DENIED);
    assertEquals(
        "findOrCreate",
        assertThrows(PermissionDeniedException.class, () -> orders(kms).findOrCreate())
            .operation());
  }
}
