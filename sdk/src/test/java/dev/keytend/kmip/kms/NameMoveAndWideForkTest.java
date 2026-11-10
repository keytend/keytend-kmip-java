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
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Name moves and wide forks, staged with exact interleavings (PendingOverwrite, MoreProbes,
 * NewProbes, LiveReconcile): pending-name records, many concurrent rotations, reconcile of wide
 * forks and one-sided links. Each test's Javadoc says what an earlier design did instead.
 * Unique names and a fixed clock (every key created in the same second).
 */
class NameMoveAndWideForkTest {
  static final byte[] PLAIN = ConcurrentReplacementChecks.PLAIN,
      AAD = ConcurrentReplacementChecks.AAD;
  static final String NAME = "vault";
  static final Instant NOW = Instant.parse("2026-10-27T10:00:00Z");

  final List<Kms> clients = new CopyOnWriteArrayList<>();
  final ExecutorService pool = Executors.newCachedThreadPool();

  @AfterEach
  void cleanUp() throws InterruptedException {
    pool.shutdownNow();
    pool.awaitTermination(10, TimeUnit.SECONDS);
    clients.forEach(Kms::close);
  }

  Kms track(Kms kms) {
    clients.add(kms);
    return kms;
  }

  Kms connect(InMemoryKmipServer server) {
    return track(server.connect());
  }

  /** The test server: unique names (or not), every key created at {@link #NOW}. */
  static InMemoryKmipServer server(KmipVersion version, boolean unique) {
    return InMemoryKmipServer.of(version)
        .uniqueNames(unique)
        .clock(Clock.fixed(NOW, ZoneOffset.UTC));
  }

  static KeyHandle key(Kms kms, String name) {
    KeyCreation b = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
    if (name != null) b.named(name);
    return b.create();
  }

  /** The documented startup call. */
  static KeyHandle startup(Kms kms) {
    return kms.keys()
        .createAes(256)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .named(NAME)
        .findOrCreate();
  }

  static RevocationReason leaked() {
    return RevocationReason.keyCompromise("leaked", NOW);
  }

  static boolean is(Ttlv request, Operation op) {
    return RotationAndNameChoiceTest.isOperation(request, op);
  }

  static String uid(Ttlv request) {
    return ConcurrentReplacementInterleavingsTest.uid(request);
  }

  /** Whether {@code request} adds the Name {@code name}. */
  static boolean addsName(Ttlv request, String name) {
    return LineageTreeTest.addsName(request) && LineageTreeTest.names(request, name);
  }

  // ---- concurrent name moves to one key ----

  /**
   * PendingOverwrite: two retries of {@code replaceCompromised} finish one linked
   * replacement. B reads the replacement's records (none), and pauses; A records {@code vault},
   * takes it off the Compromised key and hangs giving it; B, resumed, skips the absent {@code vault}
   * and moves {@code alias}. With one pending-name attribute holding one name, B's record of
   * {@code alias} overwrote A's of {@code vault}, and B's cleanup removed it; A's advised repeat
   * then succeeded with {@code vault} on no key, startup created an unrelated key under it, and
   * {@code KeyQuery.byName("vault")} refused the replacement's record. Now each name has its own
   * record, B removes only its own, and A's repeat gives {@code vault} to the replacement.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void movesOfTwoNamesToOneKeyKeepEachOthersRecord(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version, true);
    Kms admin = connect(s);
    KeyHandle old = key(admin, NAME);
    old.addName("alias");
    old.revoke(leaked());
    KeyHandle target = key(admin, null);
    KmsContractTest.link(admin, old.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, target.id());
    KmsContractTest.link(admin, target.id(), Enums.LinkType.REPLACED_OBJECT_LINK, old.id());
    byte[] record = target.seal(PLAIN, AAD);

    CountDownLatch paused = new CountDownLatch(1),
        go = new CountDownLatch(1),
        hanging = new CountDownLatch(1);
    AtomicInteger reads = new AtomicInteger(), adds = new AtomicInteger();
    AtomicBoolean sawNoRecord = new AtomicBoolean();
    InMemoryKmipServer r1 = s.replica(), r2 = s.replica();
    // B pauses at its fifth read of the replacement (the move of vault, after B's look for
    // records).
    Kms b =
        track(
            Kms.connect(
                r2.configure()
                    .transport(
                        e ->
                            request -> {
                              if (is(request, Operation.GET_ATTRIBUTES)
                                  && uid(request).equals(target.id())
                                  && reads.incrementAndGet() == 5) {
                                sawNoRecord.set(
                                    KeyHandle.pendingNames(
                                            admin.keys().handle(target.id()).attributes())
                                        .isEmpty());
                                paused.countDown();
                                CompromiseReplacementTest.await(go, "go");
                              }
                              return r2.exchange(request);
                            })
                    .build()));
    // A hangs at its second addition of vault (the first is refused: the old key still holds it).
    Kms a =
        track(
            Kms.connect(
                r1.configure()
                    .callTimeout(Duration.ofMillis(800))
                    .retryPolicy(RetryPolicy.none())
                    .transport(
                        e ->
                            ConcurrentReplacementInterleavingsTest.transport(
                                (request, context) -> {
                                  if (addsName(request, NAME) && adds.incrementAndGet() == 2) {
                                    hanging.countDown();
                                    r1.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.HANG);
                                  }
                                  return r1.exchange(request, context);
                                }))
                    .build()));
    Future<KeyHandle> bf =
        pool.submit(() -> b.keys().handle(old.id()).replaceCompromised(leaked()));
    assertTrue(paused.await(10, TimeUnit.SECONDS), "B paused");
    Future<KeyHandle> af =
        pool.submit(() -> a.keys().handle(old.id()).replaceCompromised(leaked()));
    assertTrue(hanging.await(10, TimeUnit.SECONDS), "A hanging");
    // The interleaving: vault is off the old key, recorded on the replacement.
    assertFalse(s.names(old.id()).contains(NAME));
    assertEquals(
        List.of(NAME), KeyHandle.pendingNames(admin.keys().handle(target.id()).attributes()));
    assertTrue(sawNoRecord.get(), "B looked before A recorded vault");
    go.countDown();
    assertEquals(target.id(), bf.get(10, TimeUnit.SECONDS).id());
    ExecutionException stopped =
        assertThrows(ExecutionException.class, () -> af.get(10, TimeUnit.SECONDS));
    assertInstanceOf(PartialCompletionException.class, stopped.getCause());
    assertTrue(
        stopped.getCause().getMessage().contains("repeat replaceCompromised() to resume"),
        stopped.getCause().getMessage());
    // B moved alias and removed only its own record.
    assertEquals(List.of("alias"), s.names(target.id()));
    assertEquals(
        List.of(NAME), KeyHandle.pendingNames(admin.keys().handle(target.id()).attributes()));
    // The advised repeat gives vault to the replacement and removes its record.
    assertEquals(target, old.replaceCompromised(leaked()));
    assertTrue(s.names(target.id()).contains(NAME), s.names(target.id()).toString());
    assertTrue(KeyHandle.pendingNames(admin.keys().handle(target.id()).attributes()).isEmpty());
    assertEquals(Optional.of(target), admin.keys().findByName(NAME));
    assertEquals(target, startup(admin));
    assertArrayEquals(PLAIN, admin.keys().open(KeyQuery.byName(NAME), record, AAD));
  }

  /**
   * The record's form: one client attribute per name, whose value is the name, so a key can
   * record several names at once; a copy of a key's attributes (the hand-made replacement of the
   * Re-key fallback) does not copy them.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void eachNameHasItsOwnRecord(KmipVersion version) {
    InMemoryKmipServer s = server(version, true);
    Kms kms = connect(s);
    KeyHandle k = key(kms, null);
    k.setCustomAttribute(KeyHandle.pendingName("a"), "a");
    k.setCustomAttribute(KeyHandle.pendingName("b"), "b");
    // A record whose value is not the name it is for is not one.
    k.setCustomAttribute(KeyHandle.pendingName("c"), "d");
    assertEquals(Set.of("a", "b"), new HashSet<>(KeyHandle.pendingNames(k.attributes())));
    k.removeCustomAttribute(KeyHandle.pendingName("a"));
    assertEquals(List.of("b"), KeyHandle.pendingNames(k.attributes()));
    assertNotEquals(KeyHandle.pendingName("a"), KeyHandle.pendingName("b"));
    // The fallback's replacement copies the old key's client attributes, but not these records.
    KeyHandle old = key(kms, NAME);
    old.setCustomAttribute(CustomAttribute.client("purpose"), "kek");
    old.setCustomAttribute(KeyHandle.pendingName(NAME), NAME);
    Kms refusing =
        track(
            Kms.connect(
                s.configure()
                    .transport(
                        e ->
                            request -> {
                              if (is(request, Operation.RE_KEY))
                                s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
                              return s.exchange(request);
                            })
                    .build()));
    KeyHandle replacement = refusing.keys().handle(old.id()).replaceCompromised(leaked());
    KeyAttributes made = replacement.attributes();
    assertEquals("kek", made.custom().get(CustomAttribute.client("purpose")));
    assertTrue(KeyHandle.pendingNames(made).isEmpty(), made.custom().toString());
  }

  // ---- more records than the look's first read ----

  /**
   * MoreProbes.pendingOverflow: 33 instances replace one Compromised key at once, Re-key
   * refused (the hand-linked fallback), held at barriers so that all 33 record the name on their
   * replacement before one takes it off the old key, then all hang giving it. An earlier look for
   * pending moves read more than FANOUT (32) records as "the server did not filter" and found none:
   * startup created an unrelated key under the name, and a record sealed by a branch meanwhile was
   * BAD_DATA by name and through {@code KeyQuery}, for good (neither {@code reconcile(name)} nor a
   * repeat restored the name). Now the 33 records are read, startup refuses (STATE) and creates
   * nothing, and {@code reconcile(name)} gives the name to one branch, through which the record opens.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void manyPendingMovesAreNotTakenForNone(KmipVersion version) throws Exception {
    int n = Lineage.FANOUT + 1;
    InMemoryKmipServer s =
        server(version, true)
            .linkCardinality(
                false); // a server that allows several Replacement Object links, so each caller
    // links its own key
    Kms admin = connect(s);
    KeyHandle old = key(admin, NAME);
    old.revoke(leaked());
    CyclicBarrier created = new CyclicBarrier(n),
        removing = new CyclicBarrier(n),
        naming = new CyclicBarrier(n);
    CountDownLatch blocked = new CountDownLatch(n);
    List<Future<KeyHandle>> calls = new ArrayList<>();
    for (int i = 0; i < n; i++) {
      InMemoryKmipServer r = s.replica();
      AtomicBoolean firstName = new AtomicBoolean(true);
      Kms c =
          track(
              Kms.connect(
                  r.configure()
                      .callTimeout(Duration.ofSeconds(3))
                      .retryPolicy(RetryPolicy.none())
                      .transport(
                          e ->
                              ConcurrentReplacementInterleavingsTest.transport(
                                  (request, context) -> {
                                    if (is(request, Operation.RE_KEY))
                                      r.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
                                    if (is(request, Operation.CREATE))
                                      CompromiseReplacementTest.await(created);
                                    if (LineageTreeTest.addsName(request)
                                        && firstName.compareAndSet(true, false))
                                      CompromiseReplacementTest.await(naming);
                                    if (is(request, Operation.DELETE_ATTRIBUTE)
                                        && uid(request).equals(old.id()))
                                      CompromiseReplacementTest.await(removing);
                                    if (LineageTreeTest.addsName(request)
                                        && s.names(old.id()).isEmpty()) {
                                      blocked.countDown();
                                      r.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.HANG);
                                    }
                                    return r.exchange(request, context);
                                  }))
                      .build()));
      calls.add(pool.submit(() -> c.keys().handle(old.id()).replaceCompromised(leaked())));
    }
    assertTrue(blocked.await(20, TimeUnit.SECONDS), "every instance hangs giving the name");
    KeyHandle during = admin.keys().handle(s.links(old.id(), LinkKind.REPLACEMENT).get(0));
    byte[] record = during.seal(PLAIN, AAD);
    for (Future<KeyHandle> f : calls) {
      ExecutionException stopped =
          assertThrows(ExecutionException.class, () -> f.get(20, TimeUnit.SECONDS));
      assertInstanceOf(PartialCompletionException.class, stopped.getCause());
    }
    List<String> recording =
        s.ids().stream()
            .filter(
                id -> KeyHandle.pendingNames(admin.keys().handle(id).attributes()).contains(NAME))
            .toList();
    assertEquals(n, recording.size(), ConcurrentReplacementChecks.describe(s));
    assertTrue(s.names(old.id()).isEmpty());
    // Startup refuses while the moves are pending, and creates nothing.
    int objects = s.ids().size();
    StateConflictException refused =
        assertThrows(StateConflictException.class, () -> startup(admin));
    assertTrue(refused.getMessage().contains("is being moved to"), refused.getMessage());
    assertTrue(refused.getMessage().contains("and 25 more"), refused.getMessage());
    assertEquals(objects, s.ids().size());
    // The operator finishes the moves: one branch gets the name, and every record opens.
    KeyHandle winner = admin.keys().reconcile(NAME).orElseThrow();
    assertEquals(Optional.of(winner), admin.keys().findByName(NAME));
    assertArrayEquals(PLAIN, admin.keys().findByName(NAME).orElseThrow().open(record, AAD));
    assertArrayEquals(PLAIN, admin.keys().open(KeyQuery.byName(NAME), record, AAD));
    assertEquals(winner.id(), startup(admin).id());
    assertEquals(objects, s.ids().size());
  }

  /**
   * The best-effort side: a server that ignores the filter returns more than
   * 32 objects, none of the first 32 with a record: none is pending, and startup creates the key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void manyUnfilteredObjectsAreStillNone(KmipVersion version) {
    InMemoryKmipServer s = server(version, true);
    Kms setup = connect(s);
    for (int i = 0; i < Lineage.FANOUT + 8; i++) key(setup, "other-" + i);
    AtomicInteger looks = new AtomicInteger();
    Kms kms =
        track(
            Kms.connect(
                s.configure()
                    .transport(
                        e ->
                            request -> {
                              boolean pending =
                                  is(request, Operation.LOCATE)
                                      && LineageTreeTest.names(request, KeyHandle.PENDING_PREFIX);
                              if (pending) looks.incrementAndGet();
                              return s.exchange(
                                  pending
                                      ? LineageTreeTest.without(request, KeyHandle.PENDING_PREFIX)
                                      : request);
                            })
                    .build()));
    KeyHandle made = startup(kms);
    assertEquals(1, looks.get());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(made.id()));
  }

  // ---- no advice destroys a key ----

  /**
   * MoreProbes.advice: a registration pauses before reading back what it registered; another
   * instance finds the key by name, activates it, seals a record and supersedes it; then the
   * registration's read fails. A {@code PartialCompletionException} that advised "or destroy
   * them", naming that key, would make the record unreadable (DESTROYED) when followed. The
   * advice keeps the key (DestroyAdviceTest lists every such text), and the record opens.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aFailedRegistrationDoesNotAdviseDestroyingTheKey(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version, true);
    CountDownLatch at = new CountDownLatch(1), go = new CountDownLatch(1);
    AtomicBoolean registered = new AtomicBoolean();
    Kms observer = connect(s);
    Kms k =
        track(
            Kms.connect(
                s.configure()
                    .retryPolicy(RetryPolicy.none())
                    .transport(
                        e ->
                            request -> {
                              if (is(request, Operation.GET_ATTRIBUTES) && registered.get()) {
                                at.countDown();
                                CompromiseReplacementTest.await(go, "go");
                                s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.SERVER_FAILURE);
                              }
                              Ttlv reply = s.exchange(request);
                              if (is(request, Operation.REGISTER)) registered.set(true);
                              return reply;
                            })
                    .build()));
    Future<KeyHandle> f =
        pool.submit(
            () ->
                k.keys()
                    .register(new javax.crypto.spec.SecretKeySpec(new byte[32], "AES"))
                    .named(NAME)
                    .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                    .register());
    assertTrue(at.await(10, TimeUnit.SECONDS));
    KeyHandle used = startup(observer);
    byte[] record = used.seal(PLAIN, AAD);
    used.revoke(RevocationReason.superseded("retired after seal"));
    go.countDown();
    ExecutionException failed =
        assertThrows(ExecutionException.class, () -> f.get(10, TimeUnit.SECONDS));
    PartialCompletionException partial =
        assertInstanceOf(PartialCompletionException.class, failed.getCause());
    assertEquals(List.of(used.id()), partial.created().stream().map(KeyHandle::id).toList());
    assertFalse(
        partial.getMessage().toLowerCase(Locale.ROOT).contains("destroy"), partial.getMessage());
    assertTrue(partial.getMessage().contains("keep them"), partial.getMessage());
    assertArrayEquals(PLAIN, used.open(record, AAD));
  }

  // ---- a record left behind ----

  /** A connection whose removals of pending-name records the server refuses while {@code refuse} is set. */
  Kms refusingRecordRemoval(InMemoryKmipServer s, AtomicBoolean refuse) {
    return track(
        Kms.connect(
            s.configure()
                .transport(
                    e ->
                        request -> {
                          if (is(request, Operation.RE_KEY))
                            s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
                          if (refuse.get()
                              && is(request, Operation.DELETE_ATTRIBUTE)
                              && LineageTreeTest.names(request, KeyHandle.PENDING_PREFIX))
                            s.failNext(ServerOperation.DELETE_ATTRIBUTE, Fault.UNSUPPORTED);
                          return s.exchange(request);
                        })
                .build()));
  }

  /**
   * NewProbes.stalePending: the server refuses to remove the pending-name record after the
   * replacement got the name. Were the failure passed over and the call to succeed, once
   * the replacement was retired as {@code findOrCreate}'s docs prescribe (its name removed, revoked),
   * startup would refuse for good ("the name is being moved"), and the advised {@code reconcile(name)}
   * would refuse too (the lineage's newest key is Deactivated), with no way out. The call reports the
   * unfinished cleanup ({@code PartialCompletionException}, repeat to resume), the repeat removes the
   * record, and when the record is left anyway, startup and {@code reconcile(name)} name {@link
   * KmsKeys#clearPendingName}, after which startup creates the key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRecordLeftBehindIsReportedAndCanBeCleared(KmipVersion version) {
    InMemoryKmipServer s = server(version, true);
    Kms admin = connect(s);
    AtomicBoolean refuse = new AtomicBoolean(true);
    Kms k = refusingRecordRemoval(s, refuse);
    KeyHandle old = key(k, NAME);
    PartialCompletionException reported =
        assertThrows(PartialCompletionException.class, () -> old.replaceCompromised(leaked()));
    assertTrue(reported.getMessage().contains("the name has arrived"), reported.getMessage());
    assertTrue(
        reported.getMessage().contains("repeat replaceCompromised() to remove it"),
        reported.getMessage());
    KeyHandle replacement = reported.created().get(0);
    assertEquals(List.of(NAME), s.names(replacement.id()));
    assertEquals(List.of(NAME), KeyHandle.pendingNames(replacement.attributes()));
    // The repeat removes the record.
    refuse.set(false);
    assertEquals(replacement, old.replaceCompromised(leaked()));
    assertTrue(KeyHandle.pendingNames(replacement.attributes()).isEmpty());

    // Left behind anyway (the server kept refusing; the caller went on), then the lineage retired.
    InMemoryKmipServer s2 = server(version, true);
    Kms admin2 = connect(s2);
    Kms k2 = refusingRecordRemoval(s2, new AtomicBoolean(true));
    KeyHandle old2 = key(k2, NAME);
    PartialCompletionException left =
        assertThrows(PartialCompletionException.class, () -> old2.replaceCompromised(leaked()));
    KeyHandle retired = admin2.keys().handle(left.created().get(0).id());
    retired.removeName(NAME);
    retired.revoke(RevocationReason.superseded("retired"));
    for (int i = 0; i < 2; i++) {
      StateConflictException refused =
          assertThrows(StateConflictException.class, () -> startup(admin2));
      assertTrue(
          refused.getMessage().contains("kms.keys().clearPendingName(\"vault\")"),
          refused.getMessage());
    }
    StateConflictException noTip =
        assertThrows(StateConflictException.class, () -> admin2.keys().reconcile(NAME));
    assertTrue(
        noTip.getMessage().contains("kms.keys().clearPendingName(\"vault\")"), noTip.getMessage());
    assertTrue(noTip.getMessage().contains("DEACTIVATED"), noTip.getMessage());
    assertEquals(List.of(retired.id()), admin2.keys().clearPendingName(NAME));
    assertEquals(List.of(), admin2.keys().clearPendingName(NAME));
    KeyHandle fresh = startup(admin2);
    assertNotEquals(retired.id(), fresh.id());
    assertEquals(Optional.of(KeyState.ACTIVE), s2.state(fresh.id()));
  }

  /**
   * In {@code reconcile}: a record whose removal fails while reconcile moves a name is reported
   * (repeat reconcile), and the repeat removes it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void reconcileReportsARecordItCouldNotRemove(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version, true);
    Kms admin = connect(s);
    KeyHandle old = key(admin, NAME);
    RotationAndNameChoiceTest.reKey(admin, old.id());
    RotationAndNameChoiceTest.reKey(admin, old.id());
    // The tip with the name revoked: reconcile keeps the other, and moves the name to it.
    String named = admin.keys().findByName(NAME).orElseThrow().id();
    admin.keys().handle(named).revoke(RevocationReason.superseded("retired by hand"));
    AtomicBoolean refuse = new AtomicBoolean(true);
    Kms k = refusingRecordRemoval(s, refuse);
    PartialCompletionException reported =
        assertThrows(PartialCompletionException.class, () -> k.keys().reconcile(NAME));
    assertTrue(reported.getMessage().contains("repeat reconcile()"), reported.getMessage());
    refuse.set(false);
    KeyHandle winner = k.keys().reconcile(NAME).orElseThrow();
    assertNotEquals(named, winner.id());
    assertEquals(List.of(NAME), s.names(winner.id()));
    for (String id : s.ids())
      assertTrue(KeyHandle.pendingNames(admin.keys().handle(id).attributes()).isEmpty(), id);
    assertEquals(winner.id(), startup(admin).id());
  }

  // ---- wide forks ----

  /**
   * NewProbes.fanout: {@code n} instances {@code rotate()} one key at once, each on its own replica,
   * all past their checks before any Re-key. Checks every record (the old key's and each
   * replacement's) by name and through {@code KeyQuery.name}, before and after {@code reconcile},
   * and each replacement's handle through the documented recovery (seal, STATE, {@code latest()},
   * seal again) after it.
   */
  void wideFork(KmipVersion version, int n) throws Exception {
    InMemoryKmipServer s = server(version, true);
    Kms k = connect(s);
    KeyHandle old = key(k, NAME);
    byte[] root = old.seal(PLAIN, AAD);
    CyclicBarrier bar = new CyclicBarrier(n);
    List<Future<KeyHandle>> calls = new ArrayList<>();
    for (int i = 0; i < n; i++) {
      InMemoryKmipServer r = s.replica();
      Kms c =
          track(
              Kms.connect(
                  r.configure()
                      .callTimeout(Duration.ofSeconds(20))
                      .transport(
                          e ->
                              request -> {
                                if (is(request, Operation.RE_KEY))
                                  CompromiseReplacementTest.await(bar);
                                return r.exchange(request);
                              })
                      .build()));
      calls.add(pool.submit(() -> c.keys().handle(old.id()).rotate()));
    }
    List<KeyHandle> tips = new ArrayList<>();
    for (Future<KeyHandle> f : calls) tips.add(k.keys().handle(f.get(30, TimeUnit.SECONDS).id()));
    assertEquals(n, s.links(old.id(), LinkKind.REPLACEMENT).size());
    List<byte[]> records = new ArrayList<>();
    for (KeyHandle t : tips) records.add(t.seal(PLAIN, AAD));
    assertArrayEquals(
        PLAIN, k.keys().findByName(NAME).orElseThrow().open(root, AAD), "root by name");
    assertArrayEquals(
        PLAIN, k.keys().open(KeyQuery.byName(NAME), root, AAD), "root through KeyQuery");
    KeyHandle winner = old.reconcile();
    assertArrayEquals(
        PLAIN,
        k.keys().open(KeyQuery.byName(NAME), root, AAD),
        "root through KeyQuery after reconcile");
    List<String> failures = new ArrayList<>();
    for (int i = 0; i < n; i++) {
      KeyHandle t = tips.get(i);
      try {
        try {
          t.seal(PLAIN, AAD);
        } catch (StateConflictException stale) {
          t.latest().seal(PLAIN, AAD);
        }
        assertEquals(winner, t.latest());
        assertArrayEquals(PLAIN, k.keys().findByName(NAME).orElseThrow().open(records.get(i), AAD));
        assertArrayEquals(PLAIN, k.keys().open(KeyQuery.byName(NAME), records.get(i), AAD));
      } catch (KmsException | AssertionError e) {
        failures.add(t.id() + ": " + e);
      }
    }
    assertEquals(List.of(), failures);
    assertEquals(winner, old.reconcile());
  }

  /**
   * 33 concurrent rotations. An earlier {@code KeyQuery.name} refused the old key's record as
   * BAD_DATA ("33 REPLACEMENT links, more than the 32 a rotation lineage follows"), before and after
   * {@code reconcile}, while it opened by name. Now the walk is made again from the key that matches
   * the query, and every record opens both ways.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRecordOfAForkWiderThan32OpensThroughKeyQuery(KmipVersion version) throws Exception {
    wideFork(version, Lineage.FANOUT + 1);
  }

  /**
   * The attack side: a record forged under a key of the caller's own with more than 32
   * bogus links is still refused fast (BAD_DATA), now by a walk from the key that matches; when the
   * keys that match cannot be walked either, the answer is STATE, never BAD_DATA.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aWideKeyOutsideTheLineageIsStillRefusedFast(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version, false).linkCardinality(false); // the attacker's links
    Kms k = connect(s);
    KeyHandle victim = key(k, NAME);
    KeyHandle attacker = key(k, null);
    for (int i = 0; i < 40; i++)
      KmsContractTest.link(k, attacker.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, "bogus-" + i);
    byte[] forged = attacker.seal(PLAIN, AAD);
    int before = s.exchanges();
    KeyMismatchException e =
        assertThrows(
            KeyMismatchException.class, () -> k.keys().open(KeyQuery.byName(NAME), forged, AAD));
    assertEquals(KmsException.Category.BAD_DATA, e.category());
    assertTrue(s.exchanges() - before <= 4, "requests: " + (s.exchanges() - before));
    // The key that matches is as wide (a stranger's planted duplicate): cannot be decided.
    for (int i = 0; i < 40; i++)
      KmsContractTest.link(k, victim.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, "bogus-v" + i);
    StateConflictException undecided =
        assertThrows(
            StateConflictException.class, () -> k.keys().open(KeyQuery.byName(NAME), forged, AAD));
    assertTrue(undecided.getMessage().contains("findByName"), undecided.getMessage());
  }

  /**
   * 70 concurrent rotations, then {@code reconcile}. An earlier reconcile joined more than 32
   * newest keys in a chain, each into the one joined before it: the path from the first ones to the
   * winner was longer than {@code latest()} follows (64), and five handles failed the documented
   * recovery (seal: STATE, {@code latest()}: UnsupportedException), also after a repeat. Now the
   * joined keys are at most two steps from the winner, with at most 32 links on any key, and every
   * handle recovers.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void reconcilingAForkWiderThan64KeepsLatestWorking(KmipVersion version) throws Exception {
    wideFork(version, 70);
  }

  /**
   * The shape: after reconciling 70 newest keys, no key but the old one has more than 32 links of a kind,
   * every key reaches the winner in at most three confirmed steps, and a second run changes nothing.
   * A link whose reply is lost is read back. No key but the old one (the
   * fork's Re-keys) has more than one link of a kind, the winner keeps its one Replaced Object link,
   * and each other newest key names the winner with its Replacement Object link.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void reconcileJoinsAWideForkInTwoLevels(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version, false);
    Kms admin = connect(s);
    KeyHandle old = key(admin, NAME);
    for (int i = 0; i < 70; i++) RotationAndNameChoiceTest.reKey(admin, old.id());
    AtomicInteger links = new AtomicInteger();
    Kms k =
        track(
            Kms.connect(
                s.configure()
                    .retryPolicy(RetryPolicy.none())
                    .transport(
                        e ->
                            request -> {
                              if (ConcurrentReplacementInterleavingsTest.isLinkAdd(
                                      request, Enums.LinkType.REPLACEMENT_OBJECT_LINK)
                                  && links.incrementAndGet() == 40)
                                s.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.REPLY_LOST);
                              return s.exchange(request);
                            })
                    .build()));
    KeyHandle winner;
    try {
      winner = k.keys().handle(old.id()).reconcile();
    } catch (PartialCompletionException interrupted) {
      winner = k.keys().handle(old.id()).reconcile();
    }
    String w = winner.id();
    assertEquals(
        List.of(old.id()), s.links(w, LinkKind.REPLACED), "nothing is added to the winner");
    for (String id : s.ids()) {
      // Reconcile gives no key a second link of a kind (the old key has its 70 from the fork
      // itself).
      for (LinkKind kind : List.of(LinkKind.REPLACEMENT, LinkKind.REPLACED))
        if (!id.equals(old.id()))
          assertTrue(s.links(id, kind).size() <= 1, id + " " + kind + " " + s.links(id, kind));
      if (!id.equals(w) && !id.equals(old.id()))
        assertEquals(List.of(w), s.links(id, LinkKind.REPLACEMENT), id);
      if (!id.equals(w)) {
        assertNotEquals(Optional.of(KeyState.ACTIVE), s.state(id), id);
        assertEquals(w, admin.keys().handle(id).latest().id(), id);
      }
    }
    assertEquals(w, k.keys().handle(old.id()).reconcile().id());
    assertEquals(
        List.of(w),
        s.ids().stream().filter(id -> s.state(id).orElse(null) == KeyState.ACTIVE).toList());
  }

  // ---- properties that held ----

  /**
   * NewProbes.unconfirmed: links one key sets on its own, without the other
   * key's link back, make no membership: a stranger's key that claims to replace the victim's, or to
   * be replaced by it, opens none of the victim's records, and the victim's handle and {@code
   * KeyQuery.name} open none of the stranger's.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void oneSidedLinksMakeNoMembership(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version, false);
    Kms k = connect(s);
    KeyHandle victim = key(k, NAME), one = key(k, null), two = key(k, null);
    KmsContractTest.link(k, one.id(), Enums.LinkType.REPLACED_OBJECT_LINK, victim.id());
    KmsContractTest.link(k, two.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, victim.id());
    byte[] a = one.seal(PLAIN, AAD), b = two.seal(PLAIN, AAD), v = victim.seal(PLAIN, AAD);
    assertThrows(KeyMismatchException.class, () -> victim.open(a, AAD));
    assertThrows(KeyMismatchException.class, () -> victim.open(b, AAD));
    assertThrows(KeyMismatchException.class, () -> k.keys().open(KeyQuery.byName(NAME), a, AAD));
    assertThrows(KeyMismatchException.class, () -> k.keys().open(KeyQuery.byName(NAME), b, AAD));
    assertThrows(KeyMismatchException.class, () -> one.open(v, AAD));
    assertThrows(KeyMismatchException.class, () -> two.open(v, AAD));
  }

  /**
   * LiveReconcile: four instances seal continuously, each through a cached
   * handle on one of four newest keys, while an operator reconciles; the first Revoke hangs (the
   * call is interrupted) and the next one's reply is lost (read back). Each instance whose key was
   * revoked moves to {@code latest()} on STATE and goes on; every record opens by name, through the
   * old key's {@code latest()} and through {@code KeyQuery.name}.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void sealingGoesOnWhileReconcileRuns(KmipVersion version) throws Exception {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer s = server(version, unique);
      Kms admin = connect(s);
      KeyHandle old = key(admin, NAME);
      List<String> ids = new ArrayList<>();
      for (int i = 0; i < 4; i++) ids.add(RotationAndNameChoiceTest.reKey(admin, old.id()));
      InMemoryKmipServer replica = s.replica();
      AtomicInteger revokes = new AtomicInteger();
      Kms operator =
          track(
              Kms.connect(
                  replica
                      .configure()
                      .callTimeout(Duration.ofMillis(300))
                      .retryPolicy(RetryPolicy.none())
                      .transport(
                          e ->
                              ConcurrentReplacementInterleavingsTest.transport(
                                  (request, context) -> {
                                    // Retiring is a Revoke up to 2.1 and a Deactivate on 3.0.
                                    if (is(request, DeactivationTest.retiringOperation(version))) {
                                      int n = revokes.incrementAndGet();
                                      if (n == 1)
                                        replica.failNext(
                                            DeactivationTest.retiring(version), Fault.HANG);
                                      if (n == 2)
                                        replica.failNext(
                                            DeactivationTest.retiring(version), Fault.REPLY_LOST);
                                    }
                                    return replica.exchange(request, context);
                                  }))
                      .build()));
      AtomicBoolean stop = new AtomicBoolean();
      AtomicInteger refreshed = new AtomicInteger();
      CountDownLatch ready = new CountDownLatch(4);
      Queue<Throwable> errors = new ConcurrentLinkedQueue<>();
      Queue<byte[]> records = new ConcurrentLinkedQueue<>();
      List<Future<?>> sealers = new ArrayList<>();
      for (int i = 0; i < 4; i++) {
        Kms c = track(s.replica().connect());
        String id = ids.get(i);
        sealers.add(
            pool.submit(
                () -> {
                  KeyHandle cached = c.keys().handle(id);
                  ready.countDown();
                  while (!stop.get()) {
                    try {
                      records.add(cached.seal(PLAIN, AAD));
                      Thread.sleep(2);
                    } catch (StateConflictException stale) {
                      try {
                        cached = cached.latest();
                        refreshed.incrementAndGet();
                      } catch (RuntimeException e) {
                        errors.add(e);
                        return;
                      }
                    } catch (InterruptedException e) {
                      return;
                    } catch (RuntimeException e) {
                      errors.add(e);
                      return;
                    }
                  }
                }));
      }
      assertTrue(ready.await(10, TimeUnit.SECONDS));
      int partial = 0;
      for (int attempt = 0; ; attempt++)
        try {
          var unused = operator.keys().reconcile(NAME).orElseThrow();
          break;
        } catch (PartialCompletionException interrupted) {
          partial++;
          if (attempt == 2) throw interrupted;
        }
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
      while (refreshed.get() < 3 && System.nanoTime() < deadline) Thread.sleep(2);
      stop.set(true);
      for (Future<?> f : sealers) f.get(10, TimeUnit.SECONDS);
      String where = version + (unique ? " unique" : " duplicate");
      assertEquals(List.of(), List.copyOf(errors), where);
      assertEquals(1, partial, where);
      assertEquals(3, refreshed.get(), where);
      KeyHandle current = admin.keys().findByName(NAME).orElseThrow();
      for (byte[] r : records) {
        assertArrayEquals(PLAIN, current.open(r, AAD), where);
        assertArrayEquals(PLAIN, old.latest().open(r, AAD), where);
        assertArrayEquals(PLAIN, admin.keys().open(KeyQuery.byName(NAME), r, AAD), where);
      }
    }
  }
}
