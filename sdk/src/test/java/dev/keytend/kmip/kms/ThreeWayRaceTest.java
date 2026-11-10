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
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.KmipTransport;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Three-way and fallback races of rotation, findOrCreate and name moves. Each section's comment
 * says what the test guards against.
 */
class ThreeWayRaceTest {
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

  static final byte[] PLAIN = "probe".getBytes(UTF_8), AAD = "aad".getBytes(UTF_8);
  static final Instant NOW = Instant.parse("2026-10-27T10:00:00Z");

  static KeyCreation vault(Kms kms) {
    return kms.keys().createAes(256).named("vault").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
  }

  static RevocationReason leaked() {
    return RevocationReason.keyCompromise("leaked", NOW);
  }

  static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments> versionsAndNames() {
    return CompromiseReplacementTest.versionsAndNames();
  }

  static InMemoryKmipServer server(KmipVersion version, boolean unique, boolean descending) {
    return CompromiseReplacementTest.server(version, unique, descending);
  }

  static boolean is(Ttlv request, Operation op) {
    return CompromiseReplacementTest.is(request, op);
  }

  /** Whether the request is {@code op} on object {@code id}. */
  static boolean targets(Ttlv request, Operation op, String id) {
    for (Ttlv item : request.children(Tag.BATCH_ITEM)) {
      if (item.require(Tag.OPERATION).intValue() != op.code()) continue;
      Optional<String> uid =
          item.child(Tag.REQUEST_PAYLOAD)
              .flatMap(p -> p.child(Tag.UNIQUE_IDENTIFIER))
              .map(Ttlv::textValue);
      if (uid.map(id::equals).orElse(false)) return true;
    }
    return false;
  }

  static void await(CountDownLatch latch, String what) throws java.io.IOException {
    CompromiseReplacementTest.await(latch, what);
  }

  static void await(CyclicBarrier barrier) throws java.io.IOException {
    CompromiseReplacementTest.await(barrier);
  }

  interface Hook {
    /** Runs before the request; returns a runnable to run after the reply, or null. */
    Runnable before(Ttlv request) throws java.io.IOException;
  }

  static KmipTransport hooked(InMemoryKmipServer server, Hook hook) {
    return request -> {
      Runnable after = hook.before(request);
      Ttlv response = server.exchange(request);
      if (after != null) after.run();
      return response;
    };
  }

  static String describe(InMemoryKmipServer server) {
    return CompromiseReplacementTest.describe(server);
  }

  /** Probe output, kept for debugging. */
  static void log(String line) {}

  Object get(Future<String> f) throws Exception {
    try {
      return f.get(30, TimeUnit.SECONDS);
    } catch (ExecutionException e) {
      return e.getCause();
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Guarded against: three rotate() callers. C loses to B's key and returns it; B then loses its
  // second check to A's key (same second, lower identifier) and destroys the key C returned. The
  // name C gave to B's key is destroyed with it.
  // ---------------------------------------------------------------------------------------------

  record Run(
      Object a,
      Object b,
      Object c,
      InMemoryKmipServer server,
      Kms setup,
      String state,
      KeyHandle old,
      List<Kms> instances) {}

  static java.util.stream.Stream<org.junit.jupiter.params.provider.Arguments> modes() {
    return versionsAndNames()
        .flatMap(
            a ->
                java.util.stream.Stream.of("rotate", "replaceCompromised", "findOrCreate")
                    .map(
                        m ->
                            org.junit.jupiter.params.provider.Arguments.of(
                                a.get()[0], a.get()[1], m)));
  }

  String call(Kms k, String oldId, String mode) {
    return switch (mode) {
      case "rotate" -> k.keys().handle(oldId).rotate().id();
      case "replaceCompromised" -> k.keys().handle(oldId).replaceCompromised(leaked()).id();
      default -> vault(k).replacingCompromised().findOrCreate().id();
    };
  }

  Run threeWay(KmipVersion version, boolean unique, String mode) throws Exception {
    InMemoryKmipServer server = server(version, unique, true);
    Kms setup = connect(server);
    KeyHandle old = vault(setup).findOrCreate();
    if (!mode.equals("rotate")) old.revoke(leaked());
    String oldId = old.id();
    CyclicBarrier reKey = new CyclicBarrier(3);
    CountDownLatch cReKeyed = new CountDownLatch(1),
        bReKeyed = new CountDownLatch(1),
        bMine = new CountDownLatch(1),
        cReturned = new CountDownLatch(1),
        aReKeyed = new CountDownLatch(1),
        bReturned = new CountDownLatch(1);
    InMemoryKmipServer ra = server.replica(), rb = server.replica(), rc = server.replica();

    AtomicInteger cStep = new AtomicInteger();
    Kms c =
        connect(
            rc,
            hooked(
                rc,
                request -> {
                  if (is(request, Operation.RE_KEY) && cStep.compareAndSet(0, 1)) {
                    await(reKey);
                    return cReKeyed::countDown;
                  }
                  if (cStep.compareAndSet(1, 2)) await(bMine, "B never read its key");
                  return null;
                }));
    AtomicInteger bStep = new AtomicInteger(), bOldReads = new AtomicInteger();
    Kms b =
        connect(
            rb,
            hooked(
                rb,
                request -> {
                  if (is(request, Operation.RE_KEY) && bStep.compareAndSet(0, 1)) {
                    await(reKey);
                    await(cReKeyed, "C never re-keyed");
                    return bReKeyed::countDown;
                  }
                  if (bStep.get() == 1 && bStep.compareAndSet(1, 2))
                    return bMine::countDown; // Get Attributes of its key
                  if (bStep.get() == 2
                      && targets(request, Operation.GET_ATTRIBUTES, oldId)
                      && bOldReads.incrementAndGet() == 2) await(aReKeyed, "A never re-keyed");
                  return null;
                }));
    AtomicInteger aStep = new AtomicInteger();
    Kms a =
        connect(
            ra,
            hooked(
                ra,
                request -> {
                  if (is(request, Operation.RE_KEY) && aStep.compareAndSet(0, 1)) {
                    await(reKey);
                    await(cReturned, "C never returned");
                    return aReKeyed::countDown;
                  }
                  if (aStep.compareAndSet(1, 2)) await(bReturned, "B never returned");
                  return null;
                }));

    Future<String> fc =
        pool.submit(
            () -> {
              try {
                return call(c, oldId, mode);
              } finally {
                cReturned.countDown();
              }
            });
    Future<String> fb =
        pool.submit(
            () -> {
              try {
                return call(b, oldId, mode);
              } finally {
                bReturned.countDown();
              }
            });
    Future<String> fa = pool.submit(() -> call(a, oldId, mode));
    Object rA = get(fa), rB = get(fb), rC = get(fc);
    String state =
        mode
            + " "
            + version
            + " unique="
            + unique
            + ": A="
            + rA
            + " B="
            + rB
            + " C="
            + rC
            + describe(server);
    log("three rotate() callers " + state);
    return new Run(rA, rB, rC, server, setup, state, old, List.of(a, b, c));
  }

  @ParameterizedTest
  @MethodSource("modes")
  void aKeyAnotherCallerReturnedIsNeverDestroyedInAThreeWayRace(
      KmipVersion version, boolean unique, String mode) throws Exception {
    Run r = threeWay(version, unique, mode);
    assertInstanceOf(String.class, r.c(), r.state());
    assertNotEquals(
        Optional.of(KeyState.DESTROYED),
        r.server().state((String) r.c()),
        "C returned " + r.c() + ", which another caller then destroyed: " + r.state());
  }

  /**
   * Each of the three callers keeps its own replacement; nothing is lost, every
   * record opens everywhere, everyone chooses the same key, and the name ends on it once {@code
   * reconcile} has run ({@link ConcurrentReplacementChecks#assertSafe}).
   */
  @ParameterizedTest
  @MethodSource("modes")
  void theNameEndsOnTheWinnerInAThreeWayRace(KmipVersion version, boolean unique, String mode)
      throws Exception {
    Run r = threeWay(version, unique, mode);
    ConcurrentReplacementChecks.assertSafe(
        r.server(),
        r.setup(),
        r.old(),
        List.of(r.a(), r.b(), r.c()),
        r.instances(),
        "vault",
        false);
  }

  // ---------------------------------------------------------------------------------------------
  // Guarded against: two plain rotate() callers and an application instance that polls latest()
  // (the pattern isLatest()'s Javadoc gives) between the two Re-keys. It seals a record under the
  // key latest() returned; that key then loses the tie and its creator destroys it: the record is
  // lost.
  // ---------------------------------------------------------------------------------------------

  @ParameterizedTest
  @MethodSource("modes")
  void aRecordSealedUnderAKeyLatestReturnedStillOpensAfterItLoses(
      KmipVersion version, boolean unique, String mode) throws Exception {
    // In the compromise modes, a server that leaves A's replacement Pre-Active (new dates on
    // Re-key).
    InMemoryKmipServer server =
        server(version, unique, true).freshDatesOnReKey(!mode.equals("rotate"));
    Kms setup = connect(server), reader = connect(server.replica());
    KeyHandle old = vault(setup).findOrCreate();
    if (!mode.equals("rotate")) old.revoke(leaked());
    String oldId = old.id();
    CyclicBarrier reKey = new CyclicBarrier(2);
    CountDownLatch aReKeyed = new CountDownLatch(1),
        aActive = new CountDownLatch(1),
        readerDone = new CountDownLatch(1);
    InMemoryKmipServer ra = server.replica(), rb = server.replica();
    AtomicInteger aStep = new AtomicInteger();
    Kms a =
        connect(
            ra,
            hooked(
                ra,
                request -> {
                  if (is(request, Operation.RE_KEY)
                      && aStep.compareAndSet(0, mode.equals("rotate") ? 2 : 1)) {
                    await(reKey);
                    return aReKeyed::countDown;
                  }
                  // In the compromise modes A's key is Pre-Active until A activates it: let A get
                  // that far.
                  if (aStep.get() == 1
                      && is(request, Operation.ACTIVATE)
                      && aStep.compareAndSet(1, 2)) return aActive::countDown;
                  if (aStep.get() == 2
                      && targets(request, Operation.GET_ATTRIBUTES, oldId)
                      && aStep.compareAndSet(2, 3)) await(readerDone, "reader");
                  return null;
                }));
    AtomicBoolean bOnce = new AtomicBoolean();
    Kms b =
        connect(
            rb,
            hooked(
                rb,
                request -> {
                  if (is(request, Operation.RE_KEY) && bOnce.compareAndSet(false, true)) {
                    await(reKey);
                    await(readerDone, "reader");
                  }
                  return null;
                }));
    Future<String> fa = pool.submit(() -> call(a, oldId, mode));
    Future<String> fb = pool.submit(() -> call(b, oldId, mode));
    assertTrue(aReKeyed.await(10, TimeUnit.SECONDS));
    if (!mode.equals("rotate")) assertTrue(aActive.await(10, TimeUnit.SECONDS));
    // The application: notices the rotation and moves to the current key, as isLatest() advises.
    KeyHandle current = reader.keys().handle(oldId).latest();
    Optional<KeyHandle> byName = reader.keys().findByName("vault");
    byte[] record = current.seal(PLAIN, AAD);
    readerDone.countDown();
    Object rA = get(fa), rB = get(fb);
    String state =
        mode
            + " "
            + version
            + " unique="
            + unique
            + ": reader used "
            + current.id()
            + " (findByName "
            + byName.map(KeyHandle::id)
            + ") A="
            + rA
            + " B="
            + rB
            + describe(server);
    log("polling reader " + state);
    byte[] opened;
    try {
      opened = setup.keys().open(KeyQuery.byName("vault"), record, AAD);
    } catch (KmsException e) {
      throw new AssertionError(
          "the record sealed under the key latest() returned cannot be opened: " + e + "\n" + state,
          e);
    }
    assertArrayEquals(PLAIN, opened);
  }

  // ---------------------------------------------------------------------------------------------
  // Guarded against: findOrCreate's discardLoser destroys a Pre-Active key a third instance has
  // just found and is about to activate: that instance's findOrCreate fails with STATE
  // (undocumented).
  // ---------------------------------------------------------------------------------------------

  @ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aThirdStartupFollowsTheWinnerWhenTheKeyItFoundIsDestroyed(KmipVersion version)
      throws Exception {
    InMemoryKmipServer server = server(version, false, true);
    Kms setup = connect(server);
    CountDownLatch aAtCreate = new CountDownLatch(1),
        bCreated = new CountDownLatch(1),
        cFound = new CountDownLatch(1),
        aCreated = new CountDownLatch(1),
        bDone = new CountDownLatch(1);
    InMemoryKmipServer ra = server.replica(), rb = server.replica(), rc = server.replica();
    AtomicInteger aStep = new AtomicInteger(),
        bStep = new AtomicInteger(),
        cStep = new AtomicInteger();
    Kms a =
        connect(
            ra,
            hooked(
                ra,
                request -> {
                  if (is(request, Operation.CREATE) && aStep.compareAndSet(0, 1)) {
                    aAtCreate.countDown();
                    await(cFound, "C never found B's key");
                    return aCreated::countDown;
                  }
                  return null;
                }));
    Kms b =
        connect(
            rb,
            hooked(
                rb,
                request -> {
                  if (is(request, Operation.CREATE) && bStep.compareAndSet(0, 1)) {
                    await(aAtCreate, "A never reached Create");
                    return bCreated::countDown;
                  }
                  if (bStep.compareAndSet(1, 2)) await(aCreated, "A never created");
                  return null;
                }));
    Kms c =
        connect(
            rc,
            hooked(
                rc,
                request -> {
                  if (is(request, Operation.ACTIVATE) && cStep.compareAndSet(0, 1)) {
                    cFound.countDown();
                    await(bDone, "B never returned");
                  }
                  return null;
                }));
    Future<String> fa = pool.submit(() -> vault(a).findOrCreate().id());
    Future<String> fb =
        pool.submit(
            () -> {
              try {
                return vault(b).findOrCreate().id();
              } finally {
                bDone.countDown();
              }
            });
    assertTrue(bCreated.await(10, TimeUnit.SECONDS));
    Future<String> fc = pool.submit(() -> vault(c).findOrCreate().id());
    Object rA = get(fa), rB = get(fb), rC = get(fc);
    String state = version + ": A=" + rA + " B=" + rB + " C=" + rC + describe(server);
    log("discardLoser " + state);
    assertInstanceOf(String.class, rC, "a third instance's findOrCreate failed: " + state);
  }

  // ---------------------------------------------------------------------------------------------
  // Guarded against: removeName on 2.x confirms an ambiguous Item Not Found with a Get Attributes
  // that runs after the call's scope closed (deleting(): catch of the try-with-resources).
  // ---------------------------------------------------------------------------------------------

  @Test
  void removeNameDiagnosesWithinTheCallDeadline() {
    java.time.Duration timeout = java.time.Duration.ofMillis(600);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    KmipTransport slowNotFound =
        new KmipTransport() {
          @Override
          public Ttlv exchange(Ttlv request) throws java.io.IOException {
            throw new UnsupportedOperationException();
          }

          @Override
          public Ttlv exchange(Ttlv request, dev.keytend.kmip.transport.CallContext context)
              throws java.io.IOException {
            if (is(request, Operation.DELETE_ATTRIBUTE)) {
              try {
                Thread.sleep(400);
              } catch (InterruptedException e) {
                throw new java.io.InterruptedIOException();
              }
              server.failNext(ServerOperation.DELETE_ATTRIBUTE, Enums.ResultReason.ITEM_NOT_FOUND);
              server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.HANG);
            }
            return server.exchange(request, context);
          }
        };
    Kms kms =
        Kms.connect(
            server
                .configure()
                .callTimeout(timeout)
                .retryPolicy(RetryPolicy.none())
                .transport(e -> slowNotFound)
                .build());
    clients.add(kms);
    KeyHandle key = vault(kms).create();
    long start = System.nanoTime();
    Throwable t = assertThrows(Throwable.class, () -> key.removeName("vault"));
    long ms = (System.nanoTime() - start) / 1_000_000;
    log("removeName took " + ms + " ms: " + t);
    assertTrue(ms < 850, "removeName took " + ms + " ms with a 600 ms call timeout: " + t);
  }

  // ---------------------------------------------------------------------------------------------
  // Guarded against: one lineage whose first key was retired and purged: two of its Compromised
  // keys with the name are taken for "different lineages", so replacingCompromised() refuses, with
  // a message that says a stranger's key may be involved (rather than replacing the newest).
  // ---------------------------------------------------------------------------------------------

  @ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void oneLineageWithAPurgedStartIsStillOneLineage(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    server.clock(CompromiseReplacementTest.ticking());
    AtomicReference<String> purged = new AtomicReference<>();
    Kms kms =
        connect(
            server,
            CompromiseReplacementTest.refusingReKey(
                server,
                request -> {
                  String gone = purged.get();
                  if (gone != null && targets(request, Operation.GET_ATTRIBUTES, gone))
                    server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.NOT_FOUND);
                  return server.exchange(request);
                }));
    KeyHandle k1 = vault(kms).findOrCreate();
    KeyHandle k2 = k1.replaceCompromised(leaked());
    KeyHandle k3 = k2.replaceCompromised(leaked());
    k3.revoke(leaked());
    k1.destroy(); // retired ...
    purged.set(k1.id()); // ... and purged by the server
    String state = describe(server);
    log(
        "purged lineage "
            + version
            + state
            + "\n  findByName(vault, COMPROMISED) ranks "
            + kms.keys().findByName("vault", KeyState.COMPROMISED).map(KeyHandle::id));
    KeyHandle k4;
    try {
      k4 = vault(kms).replacingCompromised().findOrCreate();
    } catch (KmsException e) {
      throw new AssertionError(
          "one lineage (" + k2.id() + " -> " + k3.id() + ") refused: " + e.getMessage() + state, e);
    }
    assertEquals(List.of(k3.id()), server.links(k4.id(), LinkKind.REPLACED));
  }

  // ---------------------------------------------------------------------------------------------
  // Held up: findOrCreate of an existing Active key costs 3 requests.
  // ---------------------------------------------------------------------------------------------

  @ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void findOrCreateOfAnExistingKeyIsStillThreeRequests(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms setup = connect(server);
    vault(setup).findOrCreate();
    Kms kms = connect(server);
    kms.keys().findByName("nothing");
    int before = server.exchanges();
    vault(kms).findOrCreate();
    assertEquals(3, server.exchanges() - before);
  }

  // ---------------------------------------------------------------------------------------------
  // Guarded against: Re-key refused; while instance A had linked the old key to its new key but not
  // yet the new key back, instance B replaced the same key and failed with
  // ProtocolViolationException on A's one-sided link. The replacement's link now comes first, so B
  // does not see A's half-made link; if A links last and its key ranks first, B's key is folded
  // into A's (Deactivated, linked, its records open through A's key).
  // ---------------------------------------------------------------------------------------------

  @ParameterizedTest
  @MethodSource("modes")
  void aConcurrentFallbackDoesNotFailOnAnotherInstancesHalfMadeLink(
      KmipVersion version, boolean unique, String mode) throws Exception {
    if (mode.equals("rotate")) return;
    InMemoryKmipServer server = server(version, unique, false);
    Kms setup = connect(server);
    KeyHandle old = vault(setup).findOrCreate();
    old.revoke(leaked());
    String oldId = old.id();
    CountDownLatch half = new CountDownLatch(1), bDone = new CountDownLatch(1);
    InMemoryKmipServer ra = server.replica(), rb = server.replica();
    AtomicInteger adds = new AtomicInteger();
    Kms a =
        connect(
            ra,
            CompromiseReplacementTest.refusingReKey(
                ra,
                hooked(
                    ra,
                    request -> {
                      if (is(request, Operation.ADD_ATTRIBUTE)) {
                        int n = adds.incrementAndGet();
                        if (n == 1) return half::countDown; // one of the two links made
                        if (n == 2) await(bDone, "B never returned");
                      }
                      return null;
                    })));
    Kms b = connect(rb, CompromiseReplacementTest.refusingReKey(rb, rb));
    Future<String> fa = pool.submit(() -> call(a, oldId, mode));
    assertTrue(half.await(10, TimeUnit.SECONDS));
    Future<String> fb =
        pool.submit(
            () -> {
              try {
                return call(b, oldId, mode);
              } finally {
                bDone.countDown();
              }
            });
    Object rB = get(fb), rA = get(fa);
    String state =
        mode + " " + version + " unique=" + unique + ": A=" + rA + " B=" + rB + describe(server);
    assertInstanceOf(String.class, rB, "B failed: " + state);
    assertInstanceOf(String.class, rA, "A failed: " + state);
    // Neither key is folded into the other: both stay Active in one tree.
    ConcurrentReplacementChecks.assertSafe(
        server, setup, old, List.of(rA, rB), List.of(a, b), "vault", false);
  }

  // ---------------------------------------------------------------------------------------------
  // Guarded against: the winner's name sweep (settle, second check) fails with an unknown outcome
  // while taking the name off the loser: rotate()/replaceCompromised throw a raw
  // OutcomeUnknownException after the replacement was created and activated, not a
  // PartialCompletionException naming it.
  // ---------------------------------------------------------------------------------------------

  @ParameterizedTest
  @MethodSource("modes")
  void aLostReplyInTheNameSweepIsReadBack(KmipVersion version, boolean unique, String mode)
      throws Exception {
    if (!unique || mode.equals("findOrCreate")) return;
    InMemoryKmipServer server = server(version, true, true);
    Kms setup = connect(server);
    KeyHandle old = vault(setup).findOrCreate();
    if (!mode.equals("rotate")) old.revoke(leaked());
    String oldId = old.id();
    CyclicBarrier reKey = new CyclicBarrier(2);
    CountDownLatch aReKeyed = new CountDownLatch(1), bDone = new CountDownLatch(1);
    InMemoryKmipServer ra = server.replica(), rb = server.replica();
    AtomicInteger aStep = new AtomicInteger();
    Kms a =
        connect(
            ra,
            hooked(
                ra,
                request -> {
                  if (is(request, Operation.RE_KEY) && aStep.compareAndSet(0, 1)) {
                    await(reKey);
                    return aReKeyed::countDown;
                  }
                  if (aStep.compareAndSet(1, 2)) await(bDone, "B never returned");
                  return null;
                }));
    AtomicBoolean bOnce = new AtomicBoolean(), lose = new AtomicBoolean();
    Kms b =
        connect(
            rb,
            hooked(
                rb,
                request -> {
                  if (is(request, Operation.RE_KEY) && bOnce.compareAndSet(false, true)) {
                    await(reKey);
                    await(aReKeyed, "A never re-keyed");
                  }
                  if (is(request, Operation.DELETE_ATTRIBUTE) && lose.compareAndSet(false, true))
                    rb.failNext(ServerOperation.DELETE_ATTRIBUTE, Fault.REPLY_LOST);
                  return null;
                }));
    Future<String> fa = pool.submit(() -> call(a, oldId, mode));
    Future<String> fb =
        pool.submit(
            () -> {
              try {
                return call(b, oldId, mode);
              } finally {
                bDone.countDown();
              }
            });
    Object rB = get(fb), rA = get(fa);
    String state = mode + " " + version + ": A=" + rA + " B=" + rB + describe(server);
    log("name sweep " + state);
    // The lost reply is read back, and the call goes on. Each caller keeps its
    // own replacement (Re-key moved the name, so no name is moved by B).
    assertInstanceOf(String.class, rB, "B made and activated a replacement, then: " + state);
    ConcurrentReplacementChecks.assertSafe(
        server, setup, old, List.of(rA, rB), List.of(a, b), "vault", false);
  }

  // ---------------------------------------------------------------------------------------------
  // Guarded against: the polling reader's race above, on the fallback path (Re-key refused). A's
  // new key is created Active and named, and linked; a starting instance's findOrCreate() returns
  // it and seals under it; B's key, made in the same second with a lower identifier, then wins and
  // A destroys the key the reader uses. A creates only once B has passed its checks and reached its
  // own Create: had B checked after A linked, B would take A's key, never link its own, and A would
  // wait for it in vain.
  // ---------------------------------------------------------------------------------------------

  @ParameterizedTest
  @MethodSource("versionsAndNames")
  void aFallbackLoserThatFindOrCreateReturnedKeepsItsRecords(KmipVersion version, boolean unique)
      throws Exception {
    InMemoryKmipServer server = server(version, unique, true);
    Kms setup = connect(server), reader = connect(server.replica());
    KeyHandle old = vault(setup).findOrCreate();
    old.revoke(leaked());
    String oldId = old.id();
    CountDownLatch aLinked = new CountDownLatch(1),
        readerDone = new CountDownLatch(1),
        bAtCreate = new CountDownLatch(1),
        bLinked = new CountDownLatch(1);
    InMemoryKmipServer ra = server.replica(), rb = server.replica();
    AtomicInteger aAdds = new AtomicInteger(), bAdds = new AtomicInteger();
    AtomicBoolean aHeld = new AtomicBoolean(), aCreating = new AtomicBoolean();
    AtomicBoolean bHeld = new AtomicBoolean();
    Kms a =
        connect(
            ra,
            CompromiseReplacementTest.refusingReKey(
                ra,
                hooked(
                    ra,
                    request -> {
                      if (is(request, Operation.CREATE) && aCreating.compareAndSet(false, true))
                        await(bAtCreate, "B never reached Create");
                      if (aLinked.getCount() == 0 && aHeld.compareAndSet(false, true))
                        await(bLinked, "B never linked");
                      if (is(request, Operation.ADD_ATTRIBUTE) && aAdds.incrementAndGet() == 2)
                        return aLinked::countDown;
                      return null;
                    })));
    Kms b =
        connect(
            rb,
            CompromiseReplacementTest.refusingReKey(
                rb,
                hooked(
                    rb,
                    request -> {
                      if (is(request, Operation.CREATE) && bHeld.compareAndSet(false, true)) {
                        bAtCreate.countDown();
                        await(readerDone, "reader");
                      }
                      if (is(request, Operation.ADD_ATTRIBUTE) && bAdds.incrementAndGet() == 2)
                        return bLinked::countDown;
                      return null;
                    })));
    Future<String> fa = pool.submit(() -> a.keys().handle(oldId).replaceCompromised(leaked()).id());
    Future<String> fb = pool.submit(() -> b.keys().handle(oldId).replaceCompromised(leaked()).id());
    assertTrue(aLinked.await(10, TimeUnit.SECONDS));
    // A starting instance, as the guide recommends, and the old key's latest().
    KeyHandle started = vault(reader).replacingCompromised().findOrCreate();
    String latest = reader.keys().handle(oldId).latest().id();
    byte[] record = started.seal(PLAIN, AAD);
    readerDone.countDown();
    Object rA = get(fa), rB = get(fb);
    String state =
        version
            + " unique="
            + unique
            + ": reader's findOrCreate "
            + started.id()
            + ", latest() "
            + latest
            + "; A="
            + rA
            + " B="
            + rB
            + describe(server);
    log("fallback polling reader " + state);
    assertEquals(0, bLinked.getCount(), "B linked its key while A was held: " + state);
    try {
      assertArrayEquals(PLAIN, setup.keys().open(KeyQuery.byName("vault"), record, AAD));
    } catch (KmsException e) {
      throw new AssertionError(
          "the record sealed under the key findOrCreate returned is lost: " + e + "\n" + state, e);
    }
  }
}
