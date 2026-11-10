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
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Concurrent replacements staged with exact interleavings (NameOnLoser, NameRace, LostFoldLink,
 * Fanout, StartupDestroy, FoldProbes: latches, held requests, injected faults), asserting the
 * concurrency guarantees: nothing is lost, nothing becomes unreadable, no call changes another
 * caller's key, every instance makes the same choice, and {@code reconcile} leaves one newest key.
 * Each test's Javadoc says what a design that folded the loser into the winner did instead.
 */
class ConcurrentReplacementInterleavingsTest {
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

  Kms connect(InMemoryKmipServer server, Step step) {
    return track(Kms.connect(server.configure().transport(e -> transport(step)).build()));
  }

  static KeyCreation vault(Kms kms) {
    return kms.keys().createAes(256).named(NAME).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
  }

  static RevocationReason leaked() {
    return RevocationReason.keyCompromise("leaked", NOW);
  }

  static Clock fixed(Instant at) {
    return Clock.fixed(at, ZoneOffset.UTC);
  }

  // ---- transports and requests ----

  /** One exchange of a test transport, with the call's context (so a HANG ends at the deadline). */
  interface Step {
    Ttlv exchange(Ttlv request, CallContext context) throws IOException;
  }

  static KmipTransport transport(Step step) {
    return new KmipTransport() {
      @Override
      public Ttlv exchange(Ttlv request) throws IOException {
        return step.exchange(request, CallContext.NONE);
      }

      @Override
      public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
        return step.exchange(request, context);
      }
    };
  }

  static boolean is(Ttlv request, Operation op) {
    return CompromiseReplacementTest.is(request, op);
  }

  static List<Ttlv> find(Ttlv t, Tag tag) {
    List<Ttlv> out = new ArrayList<>();
    if (t.tag() == tag.code()) out.add(t);
    if (t.type() == Ttlv.Type.STRUCTURE) for (Ttlv c : t.children()) out.addAll(find(c, tag));
    return out;
  }

  static boolean hasText(Ttlv t, String s) {
    if (t.tag() == Tag.ATTRIBUTE_NAME.code() && s.equals(t.value())) return true;
    if (t.type() == Ttlv.Type.STRUCTURE) for (Ttlv c : t.children()) if (hasText(c, s)) return true;
    return false;
  }

  /** An Add Attribute of a Name (2.1: a Name structure; 1.x: Attribute Name "Name"). */
  static boolean isNameAdd(Ttlv request) {
    if (!is(request, Operation.ADD_ATTRIBUTE)) return false;
    Ttlv item = request.require(Tag.BATCH_ITEM);
    return !find(item, Tag.NAME).isEmpty() || hasText(item, "Name");
  }

  /** An Add Attribute of a Link of {@code type}. */
  static boolean isLinkAdd(Ttlv request, Enums.LinkType type) {
    if (!is(request, Operation.ADD_ATTRIBUTE)) return false;
    return find(request.require(Tag.BATCH_ITEM), Tag.LINK_TYPE).stream()
        .anyMatch(t -> t.intValue() == type.code());
  }

  /** The Unique Identifier the request names. */
  static String uid(Ttlv request) {
    List<Ttlv> ids =
        find(request.require(Tag.BATCH_ITEM).require(Tag.REQUEST_PAYLOAD), Tag.UNIQUE_IDENTIFIER);
    return ids.isEmpty() ? "" : ids.get(0).textValue();
  }

  /**
   * Waits for {@code latch} at most 5 seconds and goes on either way, like the probes (each test
   * then checks that its interleaving happened, so a latch that never opened fails the test
   * rather than hanging it).
   */
  static void hold(CountDownLatch latch) throws IOException {
    try {
      latch.await(5, TimeUnit.SECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new java.io.InterruptedIOException("interrupted");
    }
  }

  static void assertOpened(CountDownLatch latch, String what) throws InterruptedException {
    assertTrue(latch.await(10, TimeUnit.SECONDS), "the probe's interleaving happened: " + what);
  }

  interface Call {
    KeyHandle run() throws Exception;
  }

  /** The call's key, or what it threw. */
  static Object attempt(Call call) {
    try {
      return call.run();
    } catch (Throwable t) {
      return t;
    }
  }

  Future<Object> submit(Call call) {
    return pool.submit(() -> attempt(call));
  }

  static Object get(Future<Object> f) throws Exception {
    return f.get(30, TimeUnit.SECONDS);
  }

  static String stack(Throwable t) {
    java.io.StringWriter w = new java.io.StringWriter();
    t.printStackTrace(new java.io.PrintWriter(w));
    return w.toString();
  }

  static boolean destroyed(InMemoryKmipServer server, String id) {
    KeyState s = server.state(id).orElse(null);
    return s == null || s == KeyState.DESTROYED || s == KeyState.DESTROYED_COMPROMISED;
  }

  static Map<String, String> states(InMemoryKmipServer server) {
    Map<String, String> out = new TreeMap<>();
    for (String id : server.ids())
      out.put(id, server.state(id).orElse(null) + " " + server.names(id));
    return out;
  }

  // ---- what a scenario left, and the concurrency guarantees ----

  /** What a probe's scenario left behind, for the shared checks. */
  static final class Scene {
    final InMemoryKmipServer server;
    final Kms setup;
    final KeyHandle old;
    final List<Kms> instances;

    /** The instances that open every record (all by default; fewer where there are many). */
    List<Kms> openers;

    /** The keys the calls returned (after following their advice). */
    final List<String> returned = new ArrayList<>();

    /** Keys the test itself revoked: the only keys allowed to be other than Active or Pre-Active. */
    final Set<String> revokedByTest = new LinkedHashSet<>();

    /** Records under keys that are not Compromised ({@link #PLAIN}, {@link #AAD}). */
    final List<byte[]> records = new ArrayList<>();

    /** Records under keys the test compromised. */
    final List<byte[]> compromisedRecords = new ArrayList<>();

    Scene(InMemoryKmipServer server, Kms setup, KeyHandle old, List<Kms> instances) {
      this.server = server;
      this.setup = setup;
      this.old = old;
      this.instances = instances;
      this.openers = instances;
    }

    String where() {
      return ConcurrentReplacementChecks.describe(server);
    }

    List<String> ids() {
      return returned.stream().distinct().toList();
    }

    Set<String> sealed() {
      Set<String> out = new HashSet<>();
      for (byte[] r : records) out.add(KmsKeys.sealedKeyId(r));
      for (byte[] r : compromisedRecords) out.add(KmsKeys.sealedKeyId(r));
      return out;
    }
  }

  /** No message containing "destroy" names a key that is Active or sealed data. */
  static void assertNoDestroyAdvice(Throwable failure, Scene s) {
    Set<String> live = new HashSet<>(s.sealed());
    for (String id : s.server.ids())
      if (s.server.state(id).orElse(null) == KeyState.ACTIVE) live.add(id);
    for (Throwable t = failure; t != null; t = t.getCause()) {
      String m = t.getMessage();
      if (m == null || !m.toLowerCase(Locale.ROOT).contains("destroy")) continue;
      for (String id : live)
        assertFalse(
            Pattern.compile("(?<![\\w-])" + Pattern.quote(id) + "(?![\\w-])").matcher(m).find(),
            "advice mentioning destruction names the live key " + id + ": " + m + s.where());
    }
  }

  /**
   * The key {@code outcome} is, or the key its advice leads to: a failure must be a {@link
   * PartialCompletionException} or {@link OutcomeUnknownException} saying "repeat {@code repeat}",
   * naming no live key for destruction and never destroying what it created; {@code byHand} does
   * any other step the advice asks for, then the call is repeated (at most three times).
   */
  static KeyHandle followed(
      Scene s,
      Object outcome,
      String repeat,
      Call again,
      java.util.function.Consumer<Throwable> byHand) {
    Object o = outcome;
    for (int i = 0; o instanceof Throwable t; i++) {
      assertTrue(i < 3, "following the advice completes: " + stack(t));
      assertTrue(
          t instanceof PartialCompletionException || t instanceof OutcomeUnknownException,
          "a call succeeds or fails with advice to follow: " + stack(t) + s.where());
      assertNoDestroyAdvice(t, s);
      assertTrue(
          String.valueOf(t.getMessage()).contains("repeat " + repeat),
          "the advice is to repeat " + repeat + ": " + t.getMessage());
      if (t instanceof PartialCompletionException p)
        for (KeyHandle c : p.created())
          assertFalse(
              destroyed(s.server, c.id()), "what the call created is kept: " + c + s.where());
      if (byHand != null) byHand.accept(t);
      o = attempt(again);
    }
    assertInstanceOf(KeyHandle.class, o);
    return (KeyHandle) o;
  }

  /**
   * Guarantees 1–4 before reconcile: every returned key is Active and descends from the old key; no
   * key is other than Active or Pre-Active but the ones the test revoked (nothing revoked,
   * deactivated or destroyed by the SDK); every instance chooses the same key from the old key, from
   * every returned key and by name, and {@code isLatest()} is true only on it; records sealed by
   * every instance through a returned key and through {@code findByName} open everywhere.
   *
   * @return the chosen key
   */
  static String assertSafeBefore(Scene s) {
    String where = s.where();
    List<String> ids = s.ids();
    for (String id : ids) {
      assertEquals(
          Optional.of(KeyState.ACTIVE),
          s.server.state(id),
          "a returned key is Active: " + id + where);
      assertTrue(
          ConcurrentReplacementChecks.descends(s.server, id, s.old.id()),
          id + " is in the tree of " + s.old.id() + where);
    }
    for (String id : s.server.ids()) {
      if (s.revokedByTest.contains(id)) continue;
      KeyState state = s.server.state(id).orElse(null);
      assertTrue(
          state == KeyState.ACTIVE || state == KeyState.PRE_ACTIVE,
          "no key was revoked, deactivated or destroyed by the SDK: "
              + id
              + " is "
              + state
              + where);
    }
    for (String id : s.server.ids())
      if (s.server.state(id).orElse(null) == KeyState.COMPROMISED)
        assertTrue(
            s.revokedByTest.contains(id),
            "the only Compromised key is one the test revoked: " + id + where);
    String chosen = ConcurrentReplacementChecks.choice(s.instances, s.old, ids, NAME, where);
    assertEquals(
        Optional.of(KeyState.ACTIVE), s.server.state(chosen), "the chosen key is Active" + where);
    Set<String> latest = new LinkedHashSet<>(ids);
    latest.add(chosen);
    for (String id : latest)
      assertEquals(
          id.equals(chosen), s.setup.keys().handle(id).isLatest(), id + ".isLatest()" + where);
    for (int i = 0; i < s.instances.size(); i++) {
      Kms k = s.instances.get(i);
      if (!ids.isEmpty()) s.records.add(k.keys().handle(ids.get(i % ids.size())).seal(PLAIN, AAD));
      s.records.add(k.keys().findByName(NAME).orElseThrow().seal(PLAIN, AAD));
    }
    assertAllOpen(s, where);
    return chosen;
  }

  /**
   * Guarantee 1: every record opens through {@code findByName}, {@code latest()} of the old key,
   * {@code KeyQuery.name} and every returned key's handle (and the old key's, unless Compromised);
   * a record under a key the test compromised opens through that key's handle allowing it, and
   * through the chosen key's.
   */
  static void assertAllOpen(Scene s, String where) {
    boolean oldCompromised =
        s.server.state(s.old.id()).map(st -> st == KeyState.COMPROMISED).orElse(false);
    List<String> ids = s.ids();
    for (Kms k : s.openers) {
      for (byte[] r : s.records) {
        String why = "record under " + KmsKeys.sealedKeyId(r) + where;
        assertArrayEquals(
            PLAIN, k.keys().findByName(NAME).orElseThrow().open(r, AAD), "by name: " + why);
        assertArrayEquals(
            PLAIN, k.keys().handle(s.old.id()).latest().open(r, AAD), "latest(): " + why);
        assertArrayEquals(
            PLAIN, k.keys().open(KeyQuery.byName(NAME), r, AAD), "KeyQuery.name: " + why);
        for (String id : ids)
          assertArrayEquals(PLAIN, k.keys().handle(id).open(r, AAD), id + "'s handle: " + why);
        if (!oldCompromised)
          assertArrayEquals(
              PLAIN, k.keys().handle(s.old.id()).open(r, AAD), "the old key's handle: " + why);
      }
      for (byte[] r : s.compromisedRecords) {
        String keyId = KmsKeys.sealedKeyId(r),
            why = "record under the Compromised " + keyId + where;
        assertArrayEquals(
            PLAIN,
            k.keys().handle(keyId).allowingCompromised().open(r, AAD),
            "its own handle: " + why);
        // Through another key's handle the opt-in does not cover it (allowingCompromised(): "it
        // covers
        // this object only"): STATE, naming the Compromised key's own view, which opens it (above).
        StateConflictException refused =
            assertThrows(
                StateConflictException.class,
                () -> k.keys().findByName(NAME).orElseThrow().allowingCompromised().open(r, AAD),
                why);
        assertTrue(
            refused.getMessage().contains("handle(\"" + keyId + "\").allowingCompromised()"),
            refused.getMessage());
      }
    }
  }

  /**
   * Guarantee 5 for {@code winner}, what reconcile returned: the key everyone chose before; the only
   * Active key of its tree and the only Active key with the name; nothing destroyed; everyone
   * chooses it; everything still opens; a second reconcile (by name and from the old key) changes
   * nothing.
   */
  static KeyHandle assertReconciled(Scene s, String chosen, KeyHandle winner) {
    String after = s.where();
    assertEquals(chosen, winner.id(), "reconcile keeps the key everyone chose" + after);
    for (String id : ConcurrentReplacementChecks.tree(s.server, winner.id()))
      if (!id.equals(winner.id()))
        assertNotEquals(
            Optional.of(KeyState.ACTIVE),
            s.server.state(id),
            "after reconcile only the winner is Active: " + id + after);
    List<String> named =
        s.server.ids().stream()
            .filter(
                i ->
                    s.server.names(i).contains(NAME)
                        && s.server.state(i).orElse(null) == KeyState.ACTIVE)
            .toList();
    assertEquals(List.of(winner.id()), named, "one Active key with the name" + after);
    for (String id : s.server.ids())
      assertFalse(destroyed(s.server, id), "reconcile destroys nothing: " + id + after);
    assertEquals(
        winner.id(),
        ConcurrentReplacementChecks.choice(s.instances, s.old, s.ids(), NAME, after),
        "everyone chooses the winner" + after);
    assertAllOpen(s, after);
    String snapshot = s.where();
    assertEquals(winner.id(), s.setup.keys().reconcile(NAME).orElseThrow().id());
    assertEquals(winner.id(), s.setup.keys().handle(s.old.id()).reconcile().id());
    assertEquals(snapshot, s.where(), "a second reconcile changes nothing");
    return winner;
  }

  /**
   * Reconciles through {@code s.setup} and checks guarantee 5, then retires from the winner: it
   * destroys exactly the other keys of the tree, and the winner keeps working by name.
   */
  static KeyHandle assertReconcilesAndRetires(Scene s, String chosen) {
    KeyHandle winner = assertReconciled(s, chosen, s.setup.keys().reconcile(NAME).orElseThrow());
    assertRetires(s, winner);
    return winner;
  }

  /** {@code retirePredecessors} from the reconciled winner works: the rest of the tree is destroyed. */
  static void assertRetires(Scene s, KeyHandle winner) {
    Set<String> others = new TreeSet<>(ConcurrentReplacementChecks.tree(s.server, winner.id()));
    others.remove(winner.id());
    List<KeyHandle> retired =
        s.setup
            .keys()
            .handle(winner.id())
            .retirePredecessors(RevocationReason.superseded("retired after reconcile"));
    String after = s.where();
    assertEquals(
        others,
        new TreeSet<>(retired.stream().map(KeyHandle::id).toList()),
        "retirePredecessors retires the rest of the tree" + after);
    for (String id : others) assertTrue(destroyed(s.server, id), id + " is destroyed" + after);
    assertEquals(Optional.of(KeyState.ACTIVE), s.server.state(winner.id()), after);
    KeyHandle byName = s.setup.keys().findByName(NAME).orElseThrow();
    assertEquals(winner.id(), byName.id());
    byte[] fresh = byName.seal(PLAIN, AAD);
    assertArrayEquals(PLAIN, s.setup.keys().open(KeyQuery.byName(NAME), fresh, AAD));
  }

  /**
   * A reconcile whose requests matching {@code target} get {@code fault} (at most {@code times}):
   * it either completes, or throws a {@link PartialCompletionException} that creates nothing, says
   * to repeat reconcile(), and deactivates nothing before every other newest key is linked into
   * the winner (both links confirmed); everything opens in between; the repeat (faults off)
   * completes. A lost reply ({@link Fault#REPLY_LOST}) is read back, so the call completes.
   *
   * @return the winner
   */
  KeyHandle faultedReconcile(
      Scene s, String chosen, Fault fault, java.util.function.Predicate<Ttlv> target, int times) {
    InMemoryKmipServer replica = s.server.replica();
    AtomicInteger hits = new AtomicInteger();
    AtomicBoolean on = new AtomicBoolean(true);
    Kms reconciler =
        track(
            Kms.connect(
                replica
                    .configure()
                    .callTimeout(Duration.ofMillis(800))
                    .transport(
                        e ->
                            transport(
                                (q, c) -> {
                                  if (on.get() && target.test(q) && hits.incrementAndGet() <= times)
                                    replica.failNext(ServerOperation.ADD_ATTRIBUTE, fault);
                                  return replica.exchange(q, c);
                                }))
                    .build()));
    Set<String> tree = ConcurrentReplacementChecks.tree(s.server, s.old.id());
    List<String> otherTips =
        tree.stream()
            .filter(id -> !id.equals(chosen))
            .filter(
                id ->
                    s.server.links(id, LinkKind.REPLACEMENT).stream()
                        .noneMatch(n -> s.server.links(n, LinkKind.REPLACED).contains(id)))
            .filter(id -> s.server.state(id).orElse(null) != KeyState.COMPROMISED)
            .toList();
    Map<String, String> before = states(s.server);
    KeyHandle winner;
    try {
      winner = reconciler.keys().reconcile(NAME).orElseThrow();
    } catch (PartialCompletionException e) {
      String where = s.where();
      assertNotEquals(Fault.REPLY_LOST, fault, "a lost reply is read back: " + stack(e) + where);
      assertTrue(e.getMessage().contains("repeat reconcile()"), e.getMessage());
      assertEquals(List.of(), e.created(), "reconcile creates nothing");
      assertNoDestroyAdvice(e, s);
      boolean joined =
          otherTips.stream()
              .allMatch(t -> s.server.links(t, LinkKind.REPLACEMENT).contains(chosen));
      if (!joined)
        assertEquals(
            before,
            states(s.server),
            "nothing is deactivated or renamed before the links are confirmed" + where);
      assertAllOpen(s, where);
      on.set(false);
      winner = s.setup.keys().reconcile(NAME).orElseThrow();
    }
    assertTrue(hits.get() > 0, "the fault hit reconcile's link adds" + s.where());
    return winner;
  }

  // =============================================================================================
  // V: NameOnLoser
  // =============================================================================================

  static Stream<Arguments> nameOnLoserLanes() {
    return Stream.of(KmipVersion.V1_4, KmipVersion.V2_1)
        .flatMap(
            v ->
                Stream.of(true, false)
                    .flatMap(u -> Stream.of(true, false).map(fb -> Arguments.of(v, u, fb))));
  }

  /**
   * NameOnLoser: two instances replace one Compromised key at once (Re-key refused, so each
   * creates and links a key by hand). A creates first but is held at its first link; B creates,
   * links and reaches its name step, which is held until A reaches its own name step; A's waits
   * until B has finished. On the fold-into-winner code, A's sweep folded B's key (read with no
   * names yet) and revoked it, then B gave the name to that revoked key: the name ended on a
   * Deactivated key, findByName found nothing and findOrCreate().replacingCompromised() failed for
   * good (1–9% of fault-free races on unique-name servers).
   *
   * <p>Now each caller returns its own key, Active, and neither touches the other's; the name never
   * ends on a non-Active key, findByName and latest() agree, the advice (repeat replaceCompromised)
   * returns the existing replacement without making another, startup's
   * findOrCreate().replacingCompromised() returns that Active key, the record sealed before the
   * compromise opens allowing it, and reconcile leaves one. Also with Re-key allowed (the probe's
   * "rekey" argument: no hand-made links, so the probe's holds do not apply; A's Re-key is held
   * until B's is sent instead, so both pass their checks) and duplicate names.
   */
  @ParameterizedTest(name = "{0} unique={1} fallback={2}")
  @MethodSource("nameOnLoserLanes")
  void nameOnLoserTheNameNeverEndsOnARevokedKey(
      KmipVersion version, boolean unique, boolean fallback) throws Exception {
    InMemoryKmipServer s =
        InMemoryKmipServer.of(version)
            .uniqueNames(unique)
            .clock(fixed(NOW))
            .linkCardinality(
                false); // a server that allows several Replacement Object links, so each caller
    // links its own key
    Kms admin = connect(s);
    KeyHandle old = vault(admin).findOrCreate();
    byte[] before = old.seal(PLAIN, AAD);
    CountDownLatch aCreated = new CountDownLatch(1),
        bAtName = new CountDownLatch(1),
        aAtName = new CountDownLatch(1),
        bNamed = new CountDownLatch(1),
        bAtRekey = new CountDownLatch(1),
        aAtRekey = new CountDownLatch(1);
    InMemoryKmipServer ra = s.replica(), rb = s.replica();
    AtomicBoolean aFirstLink = new AtomicBoolean(true), bFirstName = new AtomicBoolean(true);
    Kms ka =
        track(
            Kms.connect(
                ra.configure()
                    .callTimeout(Duration.ofSeconds(20))
                    .transport(
                        e ->
                            transport(
                                (q, c) -> {
                                  if (fallback && is(q, Operation.RE_KEY))
                                    ra.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
                                  // Both must reach the mutation boundary before either reply can
                                  // create a replacement.
                                  // A one-way latch allowed B to finish before A's second
                                  // attributes check; returning B's
                                  // existing replacement is then valid, but is not the
                                  // two-created-keys race tested here.
                                  if (!fallback && is(q, Operation.RE_KEY)) {
                                    aAtRekey.countDown();
                                    hold(bAtRekey);
                                  }
                                  if (is(q, Operation.ADD_ATTRIBUTE)
                                      && aFirstLink.compareAndSet(true, false)) {
                                    aCreated.countDown();
                                    hold(bAtName);
                                  }
                                  if (isNameAdd(q)) {
                                    aAtName.countDown();
                                    hold(bNamed);
                                  }
                                  return ra.exchange(q, c);
                                }))
                    .build()));
    Kms kb =
        track(
            Kms.connect(
                rb.configure()
                    .callTimeout(Duration.ofSeconds(20))
                    .transport(
                        e ->
                            transport(
                                (q, c) -> {
                                  if (fallback && is(q, Operation.RE_KEY))
                                    rb.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
                                  if (!fallback && is(q, Operation.RE_KEY)) {
                                    bAtRekey.countDown();
                                    hold(aAtRekey);
                                  }
                                  if (is(q, Operation.CREATE)) hold(aCreated);
                                  if (isNameAdd(q) && bFirstName.compareAndSet(true, false)) {
                                    bAtName.countDown();
                                    hold(aAtName);
                                  }
                                  return rb.exchange(q, c);
                                }))
                    .build()));
    old.revoke(leaked());
    Scene scene = new Scene(s, admin, old, List.of(admin, ka, kb));
    scene.revokedByTest.add(old.id());
    scene.compromisedRecords.add(before);
    Call a = () -> ka.keys().handle(old.id()).replaceCompromised(leaked());
    Call b = () -> kb.keys().handle(old.id()).replaceCompromised(leaked());
    Future<Object> fa = submit(a);
    Future<Object> fb =
        pool.submit(
            () -> {
              try {
                return attempt(b);
              } finally {
                bNamed.countDown();
              }
            });
    Object x = get(fa), y = get(fb);
    if (fallback)
      for (CountDownLatch l : List.of(aCreated, bAtName, aAtName, bNamed))
        assertOpened(l, "A held at its link, B at its name, A at its name");
    else {
      assertOpened(aAtRekey, "A passed its checks and sent Re-key");
      assertOpened(bAtRekey, "B passed its checks and sent Re-key");
    }
    KeyHandle hx = followed(scene, x, "replaceCompromised()", a, null),
        hy = followed(scene, y, "replaceCompromised()", b, null);
    assertNotEquals(hx.id(), hy.id(), "each caller returns its own replacement" + scene.where());
    scene.returned.addAll(List.of(hx.id(), hy.id()));
    String where = scene.where();
    // The name is never left on a key that is not Active.
    for (String id : s.ids())
      if (s.names(id).contains(NAME))
        assertEquals(
            Optional.of(KeyState.ACTIVE),
            s.state(id),
            "the name is on an Active key only: " + id + where);
    KeyHandle chosen =
        admin
            .keys()
            .findByName(NAME)
            .orElseThrow(() -> new AssertionError("no Active key named" + where));
    assertEquals(chosen.id(), admin.keys().handle(old.id()).latest().id());
    // The advice and startup: the existing replacement, no new key.
    int keys = s.ids().size();
    assertEquals(
        chosen.id(),
        ka.keys().handle(old.id()).replaceCompromised(leaked()).id(),
        "repeating returns the existing replacement" + where);
    assertEquals(
        chosen.id(),
        vault(admin).replacingCompromised().findOrCreate().id(),
        "startup findOrCreate().replacingCompromised() returns the Active replacement"
            + scene.where());
    assertEquals(keys, s.ids().size(), "nothing new was created" + scene.where());
    byte[] rec = chosen.seal(PLAIN, AAD);
    assertArrayEquals(PLAIN, admin.keys().open(KeyQuery.byName(NAME), rec, AAD));
    scene.records.add(rec);
    String picked = assertSafeBefore(scene);
    assertEquals(chosen.id(), picked);
    assertReconcilesAndRetires(scene, picked);
  }

  // =============================================================================================
  // V: NameRace
  // =============================================================================================

  static Stream<Arguments> nameRaceLanes() {
    return Stream.of(KmipVersion.V1_4, KmipVersion.V2_1)
        .flatMap(
            v ->
                Stream.of(false, true)
                    .flatMap(
                        u ->
                            Stream.of("rotate", "rc", "rcfb", "foc", "mix")
                                .map(how -> Arguments.of(v, u, how))));
  }

  /**
   * NameRace: n instances (on replicas, with 0–2 ms of jitter per request while they race) start at a barrier
   * and each rotate, replaceCompromised (Re-key allowed, or refused: rcfb), or revoke and start
   * with findOrCreate().replacingCompromised() (foc), or a mix (Re-key refused in every other
   * trial). Three trials per lane: ascending identifiers with two instances, descending with three,
   * random with four (one fixed second). On the fold-into-winner code, some races ended with no
   * Active key named "vault" (the name on a revoked loser) and some calls returned a key that was
   * then revoked.
   *
   * <p>Now every call returns an Active key in the old key's tree (rotate may refuse, changing
   * nothing, when another caller's replacement already landed: "already replaced; use latest()",
   * and latest() then works), some Active key holds the name, every instance chooses the same key,
   * every record opens everywhere, and reconcile leaves one.
   */
  @ParameterizedTest(name = "{0} unique={1} {2}")
  @MethodSource("nameRaceLanes")
  void nameRaceAlwaysLeavesAnActiveNamedKeyAndOneChoice(
      KmipVersion version, boolean unique, String how) throws Exception {
    String[] orders = {"asc", "desc", "rand"};
    for (int t = 0; t < 3; t++) {
      String ids = orders[t];
      int n = 2 + t;
      InMemoryKmipServer s = InMemoryKmipServer.of(version).uniqueNames(unique).clock(fixed(NOW));
      AtomicLong counter = new AtomicLong(ids.equals("desc") ? 999_999 : 100_000);
      Random random = new Random(t);
      Set<String> used = new HashSet<>();
      s.identifierSource(
          () -> {
            if (ids.equals("asc")) return "k" + counter.incrementAndGet();
            if (ids.equals("desc")) return "k" + counter.decrementAndGet();
            synchronized (used) {
              String x;
              do x = "k" + (100_000 + random.nextInt(900_000));
              while (!used.add(x));
              return x;
            }
          });
      Kms admin = connect(s);
      KeyHandle old = vault(admin).findOrCreate();
      byte[] before = old.seal(PLAIN, AAD);
      boolean fb = how.equals("rcfb") || (how.equals("mix") && t % 2 == 0);
      AtomicBoolean racing = new AtomicBoolean(true);
      List<Kms> ks = new ArrayList<>();
      for (int i = 0; i < n; i++) {
        InMemoryKmipServer rep = s.replica();
        Random jitter = new Random(t * 7L + i);
        ks.add(
            connect(
                rep,
                (q, c) -> {
                  if (fb && is(q, Operation.RE_KEY))
                    rep.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
                  try {
                    if (racing.get()) Thread.sleep(jitter.nextInt(3));
                  } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new java.io.InterruptedIOException();
                  }
                  return rep.exchange(q, c);
                }));
      }
      List<Kms> instances = new ArrayList<>(List.of(admin));
      instances.addAll(ks);
      Scene scene = new Scene(s, admin, old, instances);
      CyclicBarrier bar = new CyclicBarrier(n);
      List<String> kinds = new ArrayList<>();
      List<Call> calls = new ArrayList<>();
      List<Future<Object>> fs = new ArrayList<>();
      for (int i = 0; i < n; i++) {
        Kms k = ks.get(i);
        String h = how.equals("mix") ? (i % 3 == 0 ? "rotate" : i % 3 == 1 ? "rc" : "foc") : how;
        String hh = fb && h.equals("rotate") ? "rc" : h;
        kinds.add(hh);
        Call call =
            switch (hh) {
              case "rotate" -> () -> k.keys().handle(old.id()).rotate();
              case "rc", "rcfb" -> () -> k.keys().handle(old.id()).replaceCompromised(leaked());
              default ->
                  () -> {
                    try {
                      k.keys().handle(old.id()).revoke(leaked());
                    } catch (KmsException e) {
                      // Another instance revoked it.
                    }
                    return vault(k).replacingCompromised().findOrCreate();
                  };
            };
        calls.add(call);
        fs.add(
            pool.submit(
                () -> {
                  CompromiseReplacementTest.await(bar);
                  return attempt(call);
                }));
      }
      List<Object> results = new ArrayList<>();
      for (Future<Object> f : fs) results.add(get(f));
      racing.set(false);
      if (!kinds.stream().allMatch("rotate"::equals)) scene.revokedByTest.add(old.id());
      if (s.state(old.id()).orElse(null) == KeyState.COMPROMISED)
        scene.compromisedRecords.add(before);
      else scene.records.add(before);
      String lane =
          " [trial "
              + t
              + " ids="
              + ids
              + " n="
              + n
              + " kinds="
              + kinds
              + " results="
              + results
              + "]";
      for (int i = 0; i < n; i++) {
        Object r = results.get(i);
        if (kinds.get(i).equals("rotate")
            && r instanceof StateConflictException refused
            && refused.getMessage().contains("was already replaced")) {
          // Came after another caller's Re-key: nothing changed; the advice is latest().
          assertNoDestroyAdvice(refused, scene);
          assertEquals(
              Optional.of(KeyState.ACTIVE),
              s.state(ks.get(i).keys().handle(old.id()).latest().id()),
              lane);
          continue;
        }
        if (kinds.get(i).equals("rotate")
            && r instanceof StateConflictException refused
            && refused.getMessage().contains(old.id() + " is COMPROMISED, so it is not rotated")) {
          // Came after another caller revoked it: nothing sent, the advice is
          // replaceCompromised, which the other callers run.
          assertNoDestroyAdvice(refused, scene);
          assertTrue(
              refused.getMessage().contains("replaceCompromised"), refused.getMessage() + lane);
          continue;
        }
        String repeat =
            kinds.get(i).equals("rotate")
                ? "rotate()"
                : kinds.get(i).equals("foc") ? "findOrCreate()" : "replaceCompromised()";
        scene.returned.add(followed(scene, r, repeat, calls.get(i), null).id());
      }
      String where = scene.where() + lane;
      assertFalse(scene.returned.isEmpty(), "some call returned a key" + where);
      List<String> activeNamed =
          s.ids().stream()
              .filter(i -> s.names(i).contains(NAME) && s.state(i).orElse(null) == KeyState.ACTIVE)
              .toList();
      assertFalse(activeNamed.isEmpty(), "never no Active key named " + NAME + where);
      assertTrue(admin.keys().findByName(NAME).isPresent(), where);
      String chosen = assertSafeBefore(scene);
      assertReconcilesAndRetires(scene, chosen);
    }
  }

  // =============================================================================================
  // V: LostFoldLink
  // =============================================================================================

  static Stream<Arguments> lostFoldLinkLanes() {
    return Stream.of(KmipVersion.V1_4, KmipVersion.V2_1)
        .flatMap(
            v ->
                Stream.of(Fault.HANG, Fault.UNREACHABLE, Fault.REPLY_LOST)
                    .map(f -> Arguments.of(v, f)));
  }

  /**
   * LostFoldLink: two instances rotate one key at once (Re-key; descending identifiers, one
   * second; both pass rotate()'s check before either Re-key lands). A's Re-key lands first and gets
   * the name; C finds the key by name and seals under it; then B's Re-key lands and ranks first
   * (lower identifier). Every Add Attribute of a Replacement Object link (the fold's link on the
   * loser) hangs or is unreachable. On the fold-into-winner code the fold of A's key (C's key) into
   * B's could not be linked, which silently forked a key that had sealed data, and following the
   * advice (latest()) looped.
   *
   * <p>Now there is no fold: rotate adds no links, so the fault hits nothing during the race (the
   * test checks it was never triggered). Both rotations succeed, C's key keeps the name and stays
   * Active, C keeps sealing under it, and C's record (and the old key's) opens everywhere. The
   * fault then hits reconcile's link adds (the other newest key's Replacement Object link to the
   * winner, on every attempt): with REPLY_LOST it is read back and reconcile completes; with HANG
   * or UNREACHABLE reconcile completes or throws PartialCompletionException ("repeat reconcile()")
   * having deactivated nothing; the repeat completes; everything opens throughout.
   */
  @ParameterizedTest(name = "{0} {1}")
  @MethodSource("lostFoldLinkLanes")
  void lostFoldLinkNoForkAndReconcileSurvivesTheFault(KmipVersion version, Fault fault)
      throws Exception {
    InMemoryKmipServer s = InMemoryKmipServer.of(version).clock(fixed(NOW));
    AtomicInteger counter = new AtomicInteger(1000);
    s.identifierSource(() -> "k" + counter.decrementAndGet());
    Kms admin = connect(s);
    KeyHandle kek = vault(admin).findOrCreate();
    byte[] kekRecord = kek.seal(PLAIN, AAD);
    InMemoryKmipServer ra = s.replica(), rb = s.replica();
    CountDownLatch aRekeyed = new CountDownLatch(1),
        cSealed = new CountDownLatch(1),
        bRekeyed = new CountDownLatch(1),
        bAtRekey = new CountDownLatch(1);
    AtomicInteger faulted = new AtomicInteger();
    Kms A =
        track(
            Kms.connect(
                ra.configure()
                    .callTimeout(Duration.ofSeconds(2))
                    .transport(
                        e ->
                            transport(
                                (q, c) -> {
                                  if (isLinkAdd(q, Enums.LinkType.REPLACEMENT_OBJECT_LINK)) {
                                    faulted.incrementAndGet();
                                    ra.failNext(ServerOperation.ADD_ATTRIBUTE, fault);
                                  }
                                  // Both callers pass rotate()'s check before either Re-key lands
                                  // (the probe left this to
                                  // chance: a check after A's Re-key refuses, "already replaced").
                                  if (is(q, Operation.RE_KEY)) hold(bAtRekey);
                                  Ttlv r = ra.exchange(q, c);
                                  if (is(q, Operation.RE_KEY)) {
                                    aRekeyed.countDown();
                                    hold(bRekeyed);
                                  }
                                  return r;
                                }))
                    .build()));
    Kms B =
        track(
            Kms.connect(
                rb.configure()
                    .callTimeout(Duration.ofSeconds(2))
                    .transport(
                        e ->
                            transport(
                                (q, c) -> {
                                  if (isLinkAdd(q, Enums.LinkType.REPLACEMENT_OBJECT_LINK)) {
                                    faulted.incrementAndGet();
                                    rb.failNext(ServerOperation.ADD_ATTRIBUTE, fault);
                                  }
                                  if (is(q, Operation.RE_KEY)) {
                                    bAtRekey.countDown();
                                    hold(cSealed);
                                  }
                                  Ttlv r = rb.exchange(q, c);
                                  if (is(q, Operation.RE_KEY)) bRekeyed.countDown();
                                  return r;
                                }))
                    .build()));
    Kms C = connect(s);
    Call ca = () -> A.keys().handle(kek.id()).rotate(),
        cb = () -> B.keys().handle(kek.id()).rotate();
    Future<Object> fa = submit(ca), fb = submit(cb);
    assertOpened(aRekeyed, "A's Re-key landed first");
    KeyHandle cKey = C.keys().findByName(NAME).orElseThrow();
    byte[] cRecord = cKey.seal(PLAIN, AAD);
    cSealed.countDown();
    Object x = get(fa), y = get(fb);
    assertOpened(bRekeyed, "B's Re-key landed after C sealed");
    Scene scene = new Scene(s, admin, kek, List.of(admin, A, B, C));
    scene.records.addAll(List.of(kekRecord, cRecord));
    assertInstanceOf(KeyHandle.class, x, () -> "A.rotate succeeds: " + x + scene.where());
    assertInstanceOf(KeyHandle.class, y, () -> "B.rotate succeeds: " + y + scene.where());
    String a = ((KeyHandle) x).id(), b = ((KeyHandle) y).id();
    assertEquals(a, cKey.id(), "C found A's key, which Re-key gave the name");
    assertTrue(
        Lineage.IDENTIFIERS.compare(b, a) < 0, "B's key ranks first by identifier: " + b + " " + a);
    scene.returned.addAll(List.of(a, b));
    String where = scene.where();
    assertEquals(
        Optional.of(KeyState.ACTIVE), s.state(cKey.id()), "C's key is not revoked" + where);
    scene.records.add(cKey.seal(PLAIN, AAD));
    assertTrue(C.keys().handle(cKey.id()).isLatest(), "C's key is the chosen one" + where);
    for (Kms k : scene.instances) {
      assertArrayEquals(
          PLAIN, k.keys().findByName(NAME).orElseThrow().open(cRecord, AAD), "by name" + where);
      assertArrayEquals(
          PLAIN, k.keys().open(KeyQuery.byName(NAME), cRecord, AAD), "KeyQuery.name" + where);
      assertArrayEquals(
          PLAIN, k.keys().handle(kek.id()).latest().open(cRecord, AAD), "kek.latest()" + where);
    }
    assertEquals(
        0,
        faulted.get(),
        "rotate adds no Replacement Object link, so the fault hits nothing" + where);
    String chosen = assertSafeBefore(scene);
    assertEquals(a, chosen);
    KeyHandle winner =
        faultedReconcile(
            scene,
            chosen,
            fault,
            q -> isLinkAdd(q, Enums.LinkType.REPLACEMENT_OBJECT_LINK),
            Integer.MAX_VALUE);
    assertReconciled(scene, chosen, winner);
    // C keeps sealing under its key, the winner.
    scene.records.add(cKey.seal(PLAIN, AAD));
    assertAllOpen(scene, scene.where());
    assertRetires(scene, winner);
  }

  // =============================================================================================
  // V: Fanout
  // =============================================================================================

  static Stream<Arguments> fanoutLanes() {
    return Stream.of(KmipVersion.V1_4, KmipVersion.V2_1)
        .flatMap(
            v ->
                Stream.of(9, 12)
                    .flatMap(
                        n ->
                            Stream.of("rotate", "rc", "rcfb").map(how -> Arguments.of(v, n, how))));
  }

  /**
   * Fanout: n instances pass rotate()'s (or replaceCompromised's) checks, then all
   * Re-key at once, held at a barrier (rcfb: Re-key refused, all Create at once). On the
   * fold-into-winner code, nine or more replacements gave a key more links than the walk's FANOUT
   * (8): latest(), findByName and reading through the winner failed for good (the key was wedged).
   *
   * <p>Now each instance returns its own replacement, and everything the probe printed works:
   * latest() from the old key, findByName (the same key), the old record through the chosen key
   * (allowing the compromise), the advice (repeat replaceCompromised: the existing replacement, no
   * new key), startup findOrCreate().replacingCompromised() (the same key), reconcile, and
   * retirePredecessors from the winner after it.
   */
  @ParameterizedTest(name = "{0} n={1} {2}")
  @MethodSource("fanoutLanes")
  void fanoutManyConcurrentReplacementsStayUsable(KmipVersion version, int n, String how)
      throws Exception {
    // A server that allows several Replacement Object links, so each caller links its own key.
    InMemoryKmipServer s =
        InMemoryKmipServer.of(version)
            .clock(fixed(Instant.parse("2026-10-20T10:00:00Z")))
            .linkCardinality(false);
    Kms admin = connect(s);
    KeyHandle kek = vault(admin).findOrCreate();
    byte[] rec = kek.seal(PLAIN, AAD);
    s.clock(fixed(NOW));
    CyclicBarrier atMutation = new CyclicBarrier(n);
    AtomicInteger arrived = new AtomicInteger();
    boolean fb = how.equals("rcfb");
    Operation gate = fb ? Operation.CREATE : Operation.RE_KEY;
    List<Kms> ks = new ArrayList<>();
    for (int i = 0; i < n; i++) {
      InMemoryKmipServer r = s.replica();
      AtomicBoolean once = new AtomicBoolean(true);
      ks.add(
          track(
              Kms.connect(
                  r.configure()
                      .callTimeout(Duration.ofSeconds(20))
                      .transport(
                          e ->
                              transport(
                                  (q, c) -> {
                                    if (fb && is(q, Operation.RE_KEY))
                                      r.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
                                    if (is(q, gate) && once.compareAndSet(true, false)) {
                                      arrived.incrementAndGet();
                                      try {
                                        atMutation.await(10, TimeUnit.SECONDS);
                                      } catch (InterruptedException
                                          | BrokenBarrierException
                                          | TimeoutException ignored) {
                                        // Go on, like the probe; the test checks every instance
                                        // arrived.
                                      }
                                    }
                                    return r.exchange(q, c);
                                  }))
                      .build())));
    }
    boolean rotate = how.equals("rotate");
    List<Kms> instances = new ArrayList<>(List.of(admin));
    instances.addAll(ks);
    Scene scene = new Scene(s, admin, kek, instances);
    // Opening every record from every one of 13 instances would take long; the first, a racer and
    // the last.
    scene.openers = List.of(admin, ks.get(0), ks.get(n - 1));
    if (!rotate) {
      kek.revoke(leaked());
      scene.revokedByTest.add(kek.id());
      scene.compromisedRecords.add(rec);
    } else scene.records.add(rec);
    List<Call> calls = new ArrayList<>();
    List<Future<Object>> fs = new ArrayList<>();
    for (Kms k : ks) {
      Call call =
          rotate
              ? () -> k.keys().handle(kek.id()).rotate()
              : () -> k.keys().handle(kek.id()).replaceCompromised(leaked());
      calls.add(call);
      fs.add(submit(call));
    }
    List<String> results = new ArrayList<>();
    for (int i = 0; i < n; i++)
      results.add(
          followed(
                  scene,
                  get(fs.get(i)),
                  rotate ? "rotate()" : "replaceCompromised()",
                  calls.get(i),
                  null)
              .id());
    assertEquals(
        n, arrived.get(), "every instance passed its checks before any replacement was made");
    assertEquals(
        n,
        new HashSet<>(results).size(),
        "each instance returns its own replacement: " + results + scene.where());
    scene.returned.addAll(results);
    String where = scene.where();
    KeyHandle w =
        admin.keys().findByName(NAME).orElseThrow(() -> new AssertionError("findByName" + where));
    assertEquals(
        w.id(), admin.keys().handle(kek.id()).latest().id(), "latest() from the old key" + where);
    if (rotate)
      assertArrayEquals(PLAIN, w.open(rec, AAD), "the old record through the chosen key" + where);
    else {
      // The probe opened it through w.allowingCompromised(); the opt-in covers that key only, so it
      // is STATE naming the Compromised key's own view, and that view opens it.
      StateConflictException refused =
          assertThrows(StateConflictException.class, () -> w.allowingCompromised().open(rec, AAD));
      assertTrue(
          refused.getMessage().contains("handle(\"" + kek.id() + "\").allowingCompromised()"),
          refused.getMessage());
      assertArrayEquals(
          PLAIN,
          admin.keys().handle(kek.id()).allowingCompromised().open(rec, AAD),
          "the old record" + where);
    }
    if (!rotate) {
      int keys = s.ids().size();
      assertEquals(
          w.id(),
          admin.keys().handle(kek.id()).replaceCompromised(leaked()).id(),
          "repeat replaceCompromised (the advice)" + where);
      assertEquals(
          w.id(),
          vault(admin).replacingCompromised().findOrCreate().id(),
          "startup findOrCreate().replacingCompromised()" + where);
      assertEquals(keys, s.ids().size(), "nothing new was created" + scene.where());
    }
    String chosen = assertSafeBefore(scene);
    assertEquals(w.id(), chosen);
    assertReconcilesAndRetires(scene, chosen);
  }

  // =============================================================================================
  // S: StartupDestroy
  // =============================================================================================

  /**
   * StartupDestroy: on a duplicate-name server, creator W is held just before its Create
   * (after its empty lookup); creator L creates and its reply is held. A third instance's
   * findOrCreate finds L's Pre-Active key, activates it, seals under it, and an operator then
   * revokes it as superseded. W creates (a lower identifier, the same second) and L goes on. On
   * the fold-into-winner code L chose W's key and destroyed its own (the server allowed it once
   * revoked): the "used" key was DESTROYED, without material, and its record failed with STATE.
   *
   * <p>Now findOrCreate never destroys anything (no Destroy request is sent at all): the used key
   * stays Deactivated with its material and its record opens from every instance, and both racing
   * creators return the same Active key, the one the name chooses.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void startupDestroyNeverDestroysAUsedKey(KmipVersion version) throws Exception {
    AtomicInteger counter = new AtomicInteger(100);
    InMemoryKmipServer s =
        InMemoryKmipServer.of(version)
            .clock(fixed(NOW))
            .identifierSource(() -> "k" + counter.getAndDecrement());
    CountDownLatch winnerAtCreate = new CountDownLatch(1),
        allowWinner = new CountDownLatch(1),
        loserCreated = new CountDownLatch(1),
        allowLoser = new CountDownLatch(1);
    Kms winner =
        connect(
            s,
            (r, c) -> {
              if (is(r, Operation.CREATE)) {
                winnerAtCreate.countDown();
                hold(allowWinner);
              }
              return s.exchange(r, c);
            });
    Kms loser =
        connect(
            s,
            (r, c) -> {
              Ttlv result = s.exchange(r, c);
              if (is(r, Operation.CREATE)) {
                loserCreated.countDown();
                hold(allowLoser);
              }
              return result;
            });
    Kms observer = connect(s);
    try {
      Future<Object> wf = submit(() -> vault(winner).findOrCreate());
      assertOpened(winnerAtCreate, "W is held at its Create");
      Future<Object> lf = submit(() -> vault(loser).findOrCreate());
      assertOpened(loserCreated, "L created its key");
      KeyHandle used = vault(observer).findOrCreate();
      byte[] record = used.seal(PLAIN, AAD);
      used.revoke(RevocationReason.superseded("operator retires duplicate after use"));
      assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(used.id()));
      assertTrue(s.hasMaterial(used.id()));
      assertArrayEquals(PLAIN, used.open(record, AAD), "opens before the creators go on");
      allowWinner.countDown();
      Object w = get(wf);
      allowLoser.countDown();
      Object l = get(lf);
      String where = ConcurrentReplacementChecks.describe(s);
      assertInstanceOf(KeyHandle.class, w, () -> "the held creator returns a key: " + w + where);
      assertInstanceOf(KeyHandle.class, l, () -> "the other creator returns a key: " + l + where);
      KeyHandle byName = observer.keys().findByName(NAME).orElseThrow();
      assertEquals(byName.id(), ((KeyHandle) w).id(), where);
      assertEquals(byName.id(), ((KeyHandle) l).id(), where);
      assertEquals(Optional.of(KeyState.ACTIVE), s.state(byName.id()), where);
      assertEquals(
          Optional.of(KeyState.DEACTIVATED),
          s.state(used.id()),
          "the used key is never destroyed" + where);
      assertTrue(s.hasMaterial(used.id()), "the used key keeps its material" + where);
      for (Kms k : List.of(observer, winner, loser))
        assertArrayEquals(
            PLAIN,
            k.keys().handle(used.id()).open(record, AAD),
            "the record sealed before losing opens" + where);
      for (String id : s.ids()) assertFalse(destroyed(s, id), id + where);
      assertTrue(
          s.protocolRequests().stream().noneMatch(r -> is(r, Operation.DESTROY)),
          "findOrCreate sends no Destroy" + where);
    } finally {
      allowWinner.countDown();
      allowLoser.countDown();
    }
  }

  // =============================================================================================
  // S: FoldProbes
  // =============================================================================================

  enum Lane {
    REPLY_LOST,
    HANG,
    DESCENDANT;

    Fault fault() {
      return this == REPLY_LOST ? Fault.REPLY_LOST : this == HANG ? Fault.HANG : null;
    }
  }

  static Stream<Arguments> foldLanes() {
    return Stream.of(KmipVersion.V1_4, KmipVersion.V2_1)
        .flatMap(
            v ->
                Stream.of(false, true)
                    .flatMap(
                        u ->
                            Stream.of(false, true)
                                .flatMap(
                                    fb ->
                                        Stream.of(Lane.values())
                                            .map(l -> Arguments.of(v, u, fb, l)))));
  }

  /**
   * FoldProbes: the delayed caller W is held just before its Re-key (fallback: its
   * Create) of the old key; meanwhile another instance's call completes with L, which seals a
   * record; in the DESCENDANT lanes L is then rotated to C, which seals too. W resumes with a
   * lower identifier in the same second. On the fold-into-winner code W folded L into its key: a
   * lost reply (REPLY_LOST) or a hang (HANG) on W's Replaced Object link to L left L Deactivated
   * or Active but unlinked, so L's records were BAD_DATA through W, by name and after repeating the
   * replacement; with a descendant, C stayed a live fork whose records W could not open.
   *
   * <p>No fold links exist any more, so the probe's fault, aimed at W's Replaced Object link to L,
   * now hits: in the fallback lanes, W's own first link (its replacement's Replaced Object link to
   * the old key; REPLY_LOST is read back, HANG makes W report a PartialCompletionException whose
   * advice, adding the links by hand and repeating, is followed); in the Re-key lanes nothing
   * during the race (the test checks it never fired); and in all REPLY_LOST and HANG lanes,
   * reconcile's first link add, the other newest key's Replacement Object link to the winner
   * (reconcile adds nothing to the winner). Asserted: W and L succeed or report advice that completes when
   * followed; L, W and C stay Active; L's and C's records open through W's handle, by name, through
   * latest() and KeyQuery.name; C keeps sealing and W rewraps C's record; a repeated
   * old.replaceCompromised returns the existing chosen replacement and makes no key; reconcile
   * leaves one Active newest key and everything opens.
   */
  @ParameterizedTest(name = "{0} unique={1} fallback={2} {3}")
  @MethodSource("foldLanes")
  void foldProbesEveryBranchStaysReadableAndReconciles(
      KmipVersion version, boolean unique, boolean fallback, Lane lane) throws Exception {
    AtomicInteger counter = new AtomicInteger(100);
    InMemoryKmipServer s =
        InMemoryKmipServer.of(version)
            .uniqueNames(unique)
            .clock(fixed(NOW))
            .identifierSource(() -> "k" + counter.getAndDecrement())
            .linkCardinality(false); // several Replacement Object links, so the fallback lanes fork
    Kms setup = connect(s);
    KeyHandle old =
        setup.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named(NAME).create();
    if (fallback) old.revoke(leaked());
    CountDownLatch atRekey = new CountDownLatch(1), go = new CountDownLatch(1);
    AtomicInteger triggered = new AtomicInteger();
    Fault fault = lane.fault();
    InMemoryKmipServer rw = s.replica(), rb = s.replica();
    Kms delayed =
        track(
            Kms.connect(
                rw.configure()
                    .callTimeout(Duration.ofMillis(1500))
                    .retryPolicy(RetryPolicy.none())
                    .transport(
                        e ->
                            transport(
                                (r, c) -> {
                                  if (fallback && is(r, Operation.RE_KEY))
                                    rw.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
                                  if ((fallback && is(r, Operation.CREATE))
                                      || (!fallback
                                          && is(r, Operation.RE_KEY)
                                          && uid(r).equals(old.id()))) {
                                    atRekey.countDown();
                                    hold(go);
                                  }
                                  if (fault != null
                                      && isLinkAdd(r, Enums.LinkType.REPLACED_OBJECT_LINK)
                                      && triggered.incrementAndGet() == 1)
                                    rw.failNext(ServerOperation.ADD_ATTRIBUTE, fault);
                                  return rw.exchange(r, c);
                                }))
                    .build()));
    Kms b =
        connect(
            rb,
            (r, c) -> {
              if (fallback && is(r, Operation.RE_KEY))
                rb.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
              return rb.exchange(r, c);
            });
    Scene scene = new Scene(s, setup, old, List.of(setup, delayed, b));
    if (fallback) scene.revokedByTest.add(old.id());
    Call w =
        () ->
            fallback
                ? delayed.keys().handle(old.id()).replaceCompromised(leaked())
                : delayed.keys().handle(old.id()).rotate();
    Future<Object> f = submit(w);
    KeyHandle loser, child = null;
    byte[] record, childRecord = null;
    try {
      assertOpened(atRekey, "W is held before its Re-key or Create");
      loser =
          fallback
              ? b.keys().handle(old.id()).replaceCompromised(leaked())
              : b.keys().handle(old.id()).rotate();
      record = loser.seal(PLAIN, AAD);
      if (lane == Lane.DESCENDANT) {
        child = setup.keys().handle(loser.id()).rotate();
        childRecord = child.seal(PLAIN, AAD);
      }
    } finally {
      go.countDown();
    }
    scene.records.add(record);
    if (childRecord != null) scene.records.add(childRecord);
    Object outcome = get(f);
    // W's advice, followed: on an unsettled link, add the links by hand, then repeat.
    KeyHandle winner =
        followed(
            scene,
            outcome,
            fallback ? "replaceCompromised()" : "rotate()",
            w,
            t -> {
              if (!(t instanceof PartialCompletionException p)
                  || !t.getMessage().contains("add the links by hand")) return;
              for (KeyHandle mine : p.created()) {
                try {
                  if (!s.links(mine.id(), LinkKind.REPLACED).contains(old.id()))
                    KmsContractTest.link(
                        setup, mine.id(), Enums.LinkType.REPLACED_OBJECT_LINK, old.id());
                  if (!s.links(old.id(), LinkKind.REPLACEMENT).contains(mine.id()))
                    KmsContractTest.link(
                        setup, old.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, mine.id());
                } catch (Exception e) {
                  throw new AssertionError(e);
                }
              }
            });
    String where = scene.where();
    for (KeyHandle k : child == null ? List.of(winner, loser) : List.of(winner, loser, child))
      assertEquals(Optional.of(KeyState.ACTIVE), s.state(k.id()), k + " stays Active" + where);
    if (outcome instanceof PartialCompletionException p)
      for (KeyHandle mine : p.created()) assertFalse(destroyed(s, mine.id()), where);
    for (Kms k : scene.instances) {
      KeyHandle wk = k.keys().handle(winner.id());
      for (byte[] r : scene.records) {
        String why = " opens the record under " + KmsKeys.sealedKeyId(r) + where;
        assertArrayEquals(PLAIN, wk.open(r, AAD), "W's handle" + why);
        assertArrayEquals(
            PLAIN, k.keys().findByName(NAME).orElseThrow().open(r, AAD), "by name" + why);
        assertArrayEquals(
            PLAIN, k.keys().handle(loser.id()).latest().open(r, AAD), "L.latest()" + why);
        assertArrayEquals(
            PLAIN, k.keys().open(KeyQuery.byName(NAME), r, AAD), "KeyQuery.name" + why);
      }
    }
    if (child != null) {
      scene.records.add(child.seal(PLAIN, AAD));
      byte[] rewrapped = setup.keys().handle(winner.id()).rewrap(childRecord, AAD);
      assertEquals(winner.id(), KmsKeys.sealedKeyId(rewrapped), "W rewraps C's record under W");
      scene.records.add(rewrapped);
    }
    // The repeated compromise replacement returns an existing replacement and does not fork.
    String chosenBefore = setup.keys().handle(old.id()).latest().id();
    int keys = s.ids().size();
    KeyHandle repeat = setup.keys().handle(old.id()).replaceCompromised(leaked());
    scene.revokedByTest.add(old.id());
    assertEquals(
        chosenBefore,
        repeat.id(),
        "the repeat returns the chosen existing replacement" + scene.where());
    assertEquals(keys, s.ids().size(), "the repeat makes no key" + scene.where());
    scene.returned.add(winner.id());
    scene.returned.add(loser.id());
    if (child != null) scene.returned.add(child.id());
    String chosen = assertSafeBefore(scene);
    KeyHandle reconciled =
        fault == null
            ? setup.keys().reconcile(NAME).orElseThrow()
            : faultedReconcile(
                scene, chosen, fault, q -> isLinkAdd(q, Enums.LinkType.REPLACEMENT_OBJECT_LINK), 1);
    assertReconciled(scene, chosen, reconciled);
    assertRetires(scene, reconciled);
    assertEquals(
        fallback && fault != null ? 1 : 0,
        triggered.get(),
        "where the probe's race fault landed (W's own link adds only)");
  }
}
