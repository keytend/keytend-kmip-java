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

import static dev.keytend.kmip.kms.SlowEndpointFailoverTest.*;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.KmipTransport;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * A rotate race's loser and the winner: retirement, a winner replaced or compromised meanwhile,
 * records under the loser, policy denials of a Deactivated key, and hung endpoints.
 */
class FoldedLoserTest {
  /** Probe output, kept for debugging. */
  static void log(String line) {}

  final List<Kms> clients = new ArrayList<>();
  final ExecutorService pool = Executors.newCachedThreadPool();

  @AfterEach
  void cleanUp() {
    pool.shutdownNow();
    clients.forEach(Kms::close);
  }

  Kms connect(InMemoryKmipServer server, KmipTransport transport) {
    Kms kms = Kms.connect(server.configure().transport(e -> transport).build());
    clients.add(kms);
    return kms;
  }

  Kms connect(InMemoryKmipServer server) {
    return connect(server, server);
  }

  Kms connect(KmsConfig.Builder b) {
    Kms kms = Kms.connect(b.build());
    clients.add(kms);
    return kms;
  }

  static final byte[] PLAIN = "probe".getBytes(UTF_8), AAD = "aad".getBytes(UTF_8);
  static final Instant NOW = Instant.parse("2026-10-27T10:00:00Z");

  static KeyCreation vault(Kms kms) {
    return kms.keys().createAes(256).named("vault").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
  }

  static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments> versionsAndNames() {
    return CompromiseReplacementTest.versionsAndNames();
  }

  static String uid(Ttlv request) {
    for (Ttlv item : request.children(Tag.BATCH_ITEM))
      return item.child(Tag.REQUEST_PAYLOAD)
          .flatMap(p -> p.child(Tag.UNIQUE_IDENTIFIER))
          .map(Ttlv::textValue)
          .orElse(null);
    return null;
  }

  Object get(Future<String> f) throws Exception {
    try {
      return f.get(30, TimeUnit.SECONDS);
    } catch (ExecutionException e) {
      return e.getCause();
    }
  }

  record Race(
      Object a,
      Object b,
      InMemoryKmipServer server,
      Kms setup,
      String oldId,
      byte[] underLoser,
      String state) {}

  /**
   * Two rotate() callers: A re-keys first (its key gets the name, Re-key moves it), B second (a
   * lower identifier in the same second: B's key wins). {@code midFold} runs on the main thread
   * after B returned while A is paused just after reading its own key in retireLoser (before
   * moving names); null for no pause.
   */
  Race race(
      KmipVersion version,
      boolean unique,
      java.util.function.BiConsumer<Kms, String> midFold,
      boolean sealUnderLoser)
      throws Exception {
    InMemoryKmipServer server = CompromiseReplacementTest.server(version, unique, true);
    Kms setup = connect(server);
    KeyHandle old = vault(setup).findOrCreate();
    String oldId = old.id();
    CyclicBarrier reKey = new CyclicBarrier(2);
    CountDownLatch aReKeyed = new CountDownLatch(1),
        bReKeyed = new CountDownLatch(1),
        aReadL = new CountDownLatch(1),
        resumeA = new CountDownLatch(1),
        sealed = new CountDownLatch(1);
    if (midFold == null) {
      aReadL.countDown();
      resumeA.countDown();
    }
    if (!sealUnderLoser) sealed.countDown();
    InMemoryKmipServer ra = server.replica(), rb = server.replica();
    AtomicInteger aStep = new AtomicInteger();
    AtomicReference<String> mine = new AtomicReference<>();
    AtomicInteger mineReads = new AtomicInteger();
    Kms a =
        connect(
            ra,
            ThreeWayRaceTest.hooked(
                ra,
                request -> {
                  if (ThreeWayRaceTest.is(request, Operation.RE_KEY) && aStep.compareAndSet(0, 1)) {
                    ThreeWayRaceTest.await(reKey);
                    return aReKeyed::countDown;
                  }
                  if (aStep.get() == 1 && ThreeWayRaceTest.is(request, Operation.GET_ATTRIBUTES)) {
                    String id = uid(request);
                    if (mine.get() == null) {
                      mine.set(id);
                      mineReads.incrementAndGet();
                      return null;
                    }
                    if (id.equals(oldId)) {
                      ThreeWayRaceTest.await(bReKeyed, "B never re-keyed");
                      ThreeWayRaceTest.await(sealed, "never sealed");
                      return null;
                    }
                    if (id.equals(mine.get())
                        && mineReads.incrementAndGet() == 2
                        && aStep.compareAndSet(1, 2))
                      return () -> {
                        aReadL.countDown();
                        try {
                          resumeA.await(20, TimeUnit.SECONDS);
                        } catch (InterruptedException e) {
                          Thread.currentThread().interrupt();
                        }
                      };
                  }
                  return null;
                }));
    AtomicInteger bStep = new AtomicInteger();
    Kms b =
        connect(
            rb,
            ThreeWayRaceTest.hooked(
                rb,
                request -> {
                  if (ThreeWayRaceTest.is(request, Operation.RE_KEY) && bStep.compareAndSet(0, 1)) {
                    ThreeWayRaceTest.await(reKey);
                    ThreeWayRaceTest.await(aReKeyed, "A never re-keyed");
                    return bReKeyed::countDown;
                  }
                  if (bStep.get() == 1 && bStep.compareAndSet(1, 2)) {
                    ThreeWayRaceTest.await(sealed, "never sealed");
                    ThreeWayRaceTest.await(aReadL, "A never read its key");
                  }
                  return null;
                }));
    Future<String> fa = pool.submit(() -> a.keys().handle(oldId).rotate().id());
    Future<String> fb = pool.submit(() -> b.keys().handle(oldId).rotate().id());
    byte[] record = null;
    if (sealUnderLoser) {
      assertTrue(aReKeyed.await(10, TimeUnit.SECONDS));
      // The loser is the only replacement now: latest() hands it out.
      KeyHandle current = setup.keys().handle(oldId).latest();
      record = current.seal(PLAIN, AAD);
      sealed.countDown();
    }
    Object rB = get(fb);
    if (midFold != null) {
      assertTrue(aReadL.await(10, TimeUnit.SECONDS));
      midFold.accept(setup, (String) rB);
      resumeA.countDown();
    }
    Object rA = get(fa);
    String state =
        version
            + " unique="
            + unique
            + ": A="
            + rA
            + " B="
            + rB
            + CompromiseReplacementTest.describe(server);
    return new Race(rA, rB, server, setup, oldId, record, state);
  }

  // ---- (1) retirePredecessors after a race ----

  /**
   * After a two-way rotate race nothing is folded into the winner: both
   * replacements stay newest keys, so retirePredecessors refuses (it would cut the other's records
   * off) and destroys nothing until reconcile joins them; then it retires the old key and the joined
   * one: the joined one first, which reaches the winner only through the old key
   *, then the old key.
   */
  @ParameterizedTest
  @MethodSource("versionsAndNames")
  void retirePredecessorsOfTheWinnerAlsoRetiresTheFoldedLoser(KmipVersion version, boolean unique)
      throws Exception {
    Race r = race(version, unique, null, false);
    assertInstanceOf(String.class, r.a(), r.state());
    assertInstanceOf(String.class, r.b(), r.state());
    assertNotEquals(r.a(), r.b(), r.state());
    for (Object mine : List.of(r.a(), r.b())) {
      StateConflictException e =
          assertThrows(
              StateConflictException.class,
              () ->
                  r.setup()
                      .keys()
                      .handle((String) mine)
                      .retirePredecessors(RevocationReason.superseded("retire")),
              r.state());
      assertTrue(e.getMessage().contains("reconcile"), e.getMessage());
    }
    for (String id : r.server().ids())
      assertNotEquals(Optional.of(KeyState.DESTROYED), r.server().state(id), r.state());
    KeyHandle winner = r.setup().keys().reconcile("vault").orElseThrow();
    String loser = winner.id().equals(r.a()) ? (String) r.b() : (String) r.a();
    List<String> retired =
        winner.retirePredecessors(RevocationReason.superseded("retire")).stream()
            .map(KeyHandle::id)
            .toList();
    String after = CompromiseReplacementTest.describe(r.server());
    assertEquals(Set.of(r.oldId(), loser), Set.copyOf(retired), after);
    assertEquals(List.of(loser, r.oldId()), retired, "the joined branch first: " + after);
    assertEquals(Optional.of(KeyState.DESTROYED), r.server().state(loser), after);
    assertEquals(Optional.of(KeyState.ACTIVE), r.server().state(winner.id()), after);
  }

  // ---- (3) one of the newest keys is compromised and replaced ----

  /**
   * The winner is compromised and replaced during the race. Nothing is folded: after the race
   * one replacement is compromised and replaced in turn; the other caller's key is untouched, every
   * record still opens, everyone chooses the same key, and reconcile leaves one.
   */
  @ParameterizedTest
  @MethodSource("versionsAndNames")
  void aLoserFoldedAfterTheWinnerWasReplacedEndsOnTheCurrentKey(KmipVersion version, boolean unique)
      throws Exception {
    Race r = race(version, unique, null, false);
    assertInstanceOf(String.class, r.a(), r.state());
    assertInstanceOf(String.class, r.b(), r.state());
    KeyHandle w = r.setup().keys().handle((String) r.b());
    byte[] underW = w.seal(PLAIN, AAD);
    String w2 = w.replaceCompromised(RevocationReason.keyCompromise("leaked", NOW)).id();
    String state = r.state() + "\n  W2=" + w2 + CompromiseReplacementTest.describe(r.server());
    assertEquals(
        Optional.of(KeyState.ACTIVE),
        r.server().state((String) r.a()),
        "the other caller's key is untouched: " + state);
    KeyHandle chosen = r.setup().keys().handle(r.oldId()).latest();
    assertEquals(chosen, r.setup().keys().handle(w2).latest(), state);
    assertEquals(chosen, r.setup().keys().handle((String) r.a()).latest(), state);
    assertEquals(Optional.of(chosen), r.setup().keys().findByName("vault"), state);
    byte[] underA = r.setup().keys().handle((String) r.a()).seal(PLAIN, AAD);
    for (String h : List.of((String) r.a(), w2, chosen.id()))
      assertArrayEquals(PLAIN, r.setup().keys().handle(h).open(underA, AAD), state);
    assertArrayEquals(
        PLAIN, r.setup().keys().handle(w.id()).allowingCompromised().open(underW, AAD), state);
    KeyHandle winner = r.setup().keys().reconcile("vault").orElseThrow();
    assertEquals(chosen, winner, state);
    for (String h : List.of((String) r.a(), w2))
      assertArrayEquals(PLAIN, r.setup().keys().handle(h).open(underA, AAD), state);
    assertArrayEquals(PLAIN, r.setup().keys().open(KeyQuery.byName("vault"), underA, AAD), state);
  }

  // ---- (1b) records under the loser through the winner after more rotations ----

  /**
   * A record sealed under the key latest() handed out while it was the only replacement opens, after
   * the race, through every handle of the tree, after another rotation, by name, and after
   * reconcile and retirement of the older keys (once the record is re-sealed: retirement destroys).
   */
  @ParameterizedTest
  @MethodSource("versionsAndNames")
  void aRecordUnderTheLoserOpensThroughEveryLaterHandleAndAfterRetiringOlderKeys(
      KmipVersion version, boolean unique) throws Exception {
    Race r = race(version, unique, null, true);
    String state = r.state();
    assertInstanceOf(String.class, r.a(), state);
    assertInstanceOf(String.class, r.b(), state);
    for (Object h : List.of(r.a(), r.b()))
      assertArrayEquals(
          PLAIN, r.setup().keys().handle((String) h).open(r.underLoser(), AAD), state);
    KeyHandle w = r.setup().keys().handle(r.oldId()).latest();
    KeyHandle w2 = w.rotate();
    assertArrayEquals(PLAIN, w2.open(r.underLoser(), AAD), state);
    assertArrayEquals(
        PLAIN, r.setup().keys().open(KeyQuery.byName("vault"), r.underLoser(), AAD), state);
    assertEquals(w2.id(), r.setup().keys().handle(r.oldId()).latest().id());
    assertTrue(w2.isLatest());
    KeyHandle winner = r.setup().keys().reconcile("vault").orElseThrow();
    assertEquals(w2, winner);
    byte[] moved = winner.rewrap(r.underLoser(), AAD);
    winner.retirePredecessors(RevocationReason.superseded("retire"));
    assertArrayEquals(
        PLAIN, winner.open(moved, AAD), CompromiseReplacementTest.describe(r.server()));
  }

  // ---- (5) stateRefusal turning an access denial into STATE ----

  static java.util.stream.Stream<KmipVersion> versions() {
    return java.util.stream.Stream.of(KmipVersion.V1_4, KmipVersion.V2_1);
  }

  /**
   * A Deactivated key may decrypt (KMIP: Deactivated objects may process protected data), so a
   * Permission Denied for its Decrypt is the server's access policy, not its state.
   */
  @ParameterizedTest
  @MethodSource("versions")
  void aDecryptDeniedByPolicyForADeactivatedKeyIsAPermissionFailure(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    byte[] record = key.seal(PLAIN, AAD);
    Ciphertext c = key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    key.revoke(RevocationReason.superseded("rotated"));
    assertArrayEquals(
        PLAIN, key.decrypt(CipherSpec.aesGcm(), c, AAD), "a Deactivated key decrypts");
    server.failNext(ServerOperation.DECRYPT, Fault.PERMISSION_DENIED);
    KmsException e =
        assertThrows(KmsException.class, () -> key.decrypt(CipherSpec.aesGcm(), c, AAD));
    assertEquals(PermissionDeniedException.class, e.getClass(), version + ": " + e);
  }

  @ParameterizedTest
  @MethodSource("versions")
  void aMacVerifyDeniedByPolicyForADeactivatedKeyIsAPermissionFailure(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle hmac =
        kms.keys()
            .createSymmetric(Algorithm.HMAC_SHA256, 256)
            .usages(KeyUsage.MAC_GENERATE, KeyUsage.MAC_VERIFY)
            .create();
    byte[] tag = hmac.mac(MacSpec.keyDefault(), PLAIN);
    hmac.revoke(RevocationReason.superseded("rotated"));
    assertEquals(
        VerifyResult.VALID,
        hmac.macVerify(MacSpec.keyDefault(), PLAIN, tag),
        "a Deactivated key verifies");
    server.failNext(ServerOperation.MAC_VERIFY, Fault.PERMISSION_DENIED);
    KmsException e =
        assertThrows(KmsException.class, () -> hmac.macVerify(MacSpec.keyDefault(), PLAIN, tag));
    assertEquals(PermissionDeniedException.class, e.getClass(), version + ": " + e);
  }

  /** Control: an Active key's Permission Denied stays a permission failure. */
  @ParameterizedTest
  @MethodSource("versions")
  void controlActiveKeyDenialStaysPermission(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    Ciphertext c = key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    server.failNext(ServerOperation.DECRYPT, Fault.PERMISSION_DENIED);
    KmsException e =
        assertThrows(KmsException.class, () -> key.decrypt(CipherSpec.aesGcm(), c, AAD));
    assertEquals(PermissionDeniedException.class, e.getClass(), version + ": " + e);
  }

  // ---- (5) a cut does not use up an attempt: two hung endpoints before a healthy one ----

  @Test
  void twoHungEndpointsBeforeAHealthyOneWithTwoAttempts() {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica(), c = a.replica();
    AtomicBoolean connected = new AtomicBoolean();
    AtomicInteger aHung = new AtomicInteger(), bHung = new AtomicInteger();
    KmipTransport hungA = slow(a, r -> connected.get(), Duration.ofSeconds(60), aHung);
    KmipTransport hungB = slow(b, r -> true, Duration.ofSeconds(60), bHung);
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("a:5696", "b:5696", "c:5696")
                .transport(e -> e.host().equals("a") ? hungA : e.host().equals("b") ? hungB : c)
                .versions(KmipVersion.V2_1)
                .callTimeout(Duration.ofMillis(900))
                // An explicit attempt timeout: the default (half the deadline with two attempts)
                // leaves no room for a second cut (Known limitations).
                .retryPolicy(
                    noBackoff().maxAttempts(2).attemptTimeout(Duration.ofMillis(300)).build()));
    connected.set(true);
    int atC = c.exchanges();
    long start = System.nanoTime();
    try {
      kms.ping();
    } catch (KmsException e) {
      fail(
          "after "
              + millisSince(start)
              + " ms, A hung "
              + aHung.get()
              + ", B hung "
              + bHung.get()
              + ", C got "
              + (c.exchanges() - atC)
              + ": "
              + e);
    }
  }

  // ---- (2) the creator destroys its loser on a stale Pre-Active read after another instance
  // activated and sealed ----

  /**
   * Re-key refused. B makes L first, A makes W (same second, lower identifier: W wins). A starting
   * instance C finds L (the only replacement then) through findOrCreate().replacingCompromised()
   * and is about to activate it; B loses, reads L (Pre-Active, never activated), links it into W
   * and is about to destroy it. C activates L and seals under it; A's sweep then reads L Active and
   * revokes it (Deactivated); B's Destroy, decided on its stale read, then succeeds on the
   * Deactivated key: C's record is lost.
   */
  @ParameterizedTest
  @MethodSource("versionsAndNames")
  void aLoserActivatedAndUsedAfterItsCreatorsReadIsNeverDestroyed(
      KmipVersion version, boolean unique) throws Exception {
    InMemoryKmipServer server = CompromiseReplacementTest.server(version, unique, true);
    Kms setup = connect(server), reader;
    KeyHandle old = vault(setup).findOrCreate();
    old.revoke(RevocationReason.keyCompromise("leaked", NOW));
    String oldId = old.id();
    CountDownLatch aAtCreate = new CountDownLatch(1),
        bCreated = new CountDownLatch(1),
        bLinked = new CountDownLatch(1),
        cAtActivate = new CountDownLatch(1),
        aLinked = new CountDownLatch(1),
        bAtDestroy = new CountDownLatch(1),
        cSealed = new CountDownLatch(1),
        aSwept = new CountDownLatch(1);
    InMemoryKmipServer ra = server.replica(), rb = server.replica(), rc = server.replica();
    AtomicInteger aAdds = new AtomicInteger(),
        aOldReads = new AtomicInteger(),
        bAdds = new AtomicInteger();
    AtomicBoolean bWaited = new AtomicBoolean(),
        aCreated = new AtomicBoolean(),
        cOnce = new AtomicBoolean(),
        bDestroyOnce = new AtomicBoolean();
    Kms a =
        connect(
            ra,
            CompromiseReplacementTest.refusingReKey(
                ra,
                ThreeWayRaceTest.hooked(
                    ra,
                    request -> {
                      if (ThreeWayRaceTest.is(request, Operation.CREATE)
                          && aCreated.compareAndSet(false, true)) {
                        aAtCreate.countDown();
                        ThreeWayRaceTest.await(bCreated, "B never created");
                        return null;
                      }
                      if (ThreeWayRaceTest.is(request, Operation.ADD_ATTRIBUTE)) {
                        int n = aAdds.incrementAndGet();
                        if (n == 1) ThreeWayRaceTest.await(cAtActivate, "C never reached Activate");
                        if (n == 2) return aLinked::countDown;
                        return null;
                      }
                      if (aAdds.get() >= 2
                          && ThreeWayRaceTest.targets(request, Operation.GET_ATTRIBUTES, oldId)
                          && aOldReads.incrementAndGet() == 2)
                        ThreeWayRaceTest.await(cSealed, "C never sealed");
                      return null;
                    })));
    Kms b =
        connect(
            rb,
            CompromiseReplacementTest.refusingReKey(
                rb,
                ThreeWayRaceTest.hooked(
                    rb,
                    request -> {
                      if (ThreeWayRaceTest.is(request, Operation.CREATE)
                          && bCreated.getCount() > 0) {
                        ThreeWayRaceTest.await(aAtCreate, "A never reached Create");
                        return bCreated::countDown;
                      }
                      if (ThreeWayRaceTest.is(request, Operation.ADD_ATTRIBUTE)
                          && bAdds.incrementAndGet() == 2) return bLinked::countDown;
                      if (bAdds.get() == 2 && bWaited.compareAndSet(false, true))
                        ThreeWayRaceTest.await(aLinked, "A never linked");
                      // Hold B at any step that would retire its loser: a Destroy or a Revoke.
                      if ((ThreeWayRaceTest.is(request, Operation.DESTROY)
                              || ThreeWayRaceTest.is(request, Operation.REVOKE)
                              || ThreeWayRaceTest.is(request, Operation.DEACTIVATE))
                          && bDestroyOnce.compareAndSet(false, true)) {
                        bAtDestroy.countDown();
                        ThreeWayRaceTest.await(aSwept, "A never swept");
                      }
                      return null;
                    })));
    reader =
        connect(
            rc,
            ThreeWayRaceTest.hooked(
                rc,
                request -> {
                  if (ThreeWayRaceTest.is(request, Operation.ACTIVATE)
                      && cOnce.compareAndSet(false, true)) {
                    cAtActivate.countDown();
                    // B must not reach a Destroy or Revoke of its key here: it touches nothing.
                    try {
                      if (!bAtDestroy.await(500, TimeUnit.MILLISECONDS))
                        log("B revoked and destroyed nothing");
                    } catch (InterruptedException e) {
                      throw new java.io.InterruptedIOException();
                    }
                  }
                  return null;
                }));
    Future<String> fa =
        pool.submit(
            () ->
                a.keys()
                    .handle(oldId)
                    .replaceCompromised(RevocationReason.keyCompromise("leaked", NOW))
                    .id());
    Future<String> fb =
        pool.submit(
            () ->
                b.keys()
                    .handle(oldId)
                    .replaceCompromised(RevocationReason.keyCompromise("leaked", NOW))
                    .id());
    assertTrue(bLinked.await(10, TimeUnit.SECONDS), "B never linked");
    Future<String> fc = pool.submit(() -> vault(reader).replacingCompromised().findOrCreate().id());
    Object rC = get(fc);
    byte[] record = null;
    String sealedUnder = null;
    if (rC instanceof String c) {
      sealedUnder = c;
      record = reader.keys().handle(c).seal(PLAIN, AAD);
    }
    cSealed.countDown();
    Object rA = get(fa);
    aSwept.countDown();
    Object rB = get(fb);
    String state =
        version + " unique=" + unique + ": A=" + rA + " B=" + rB + " C=" + rC + describe(server);
    assertInstanceOf(String.class, rC, state);
    assertNotEquals(
        Optional.of(KeyState.DESTROYED),
        server.state(sealedUnder),
        "C sealed under "
            + sealedUnder
            + " (findOrCreate returned it, Active), which was then destroyed: "
            + state);
    assertArrayEquals(PLAIN, setup.keys().open(KeyQuery.byName("vault"), record, AAD), state);
    assertEquals(
        0,
        bAtDestroy.getCount() == 0 ? 1 : 0,
        "no caller revokes or destroys another's key: " + state);
  }

  static String describe(InMemoryKmipServer server) {
    return CompromiseReplacementTest.describe(server);
  }
}
