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

import static dev.keytend.kmip.kms.TlsIdentityTest.HOURLY;
import static dev.keytend.kmip.kms.TlsIdentityTest.SCHEDULER;
import static dev.keytend.kmip.kms.TlsIdentityTest.assertWhole;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.TestX509;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.Attributes;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * A TLS identity's call never reads, changes or links to what an earlier call left, and a plain
 * repeat finishes whatever stopped the earlier one. Before its switch (the old certificate's
 * Replacement Object link to the new leaf, or a registration's name), a call's objects are its own,
 * under a temporary name only it uses: a repeat starts over, and they are left over, never
 * presented. After the switch, the new leaf is the identity's certificate: a repeat finishes with
 * it, and writes to nothing else of the earlier call. Stops are made from the client's transport:
 * an error before a write is sent, or after the server processed it, with no reply, read back or
 * clean-up, and the repeat runs on a new client; or the request fails before the server sees it, or
 * its reply is lost, and the call goes on. The other caller acts between calls, or from the
 * transport as a request goes out; nothing depends on timing.
 */
class TlsRepeatTest {
  static final String NAME = TlsIdentityFaultsTest.NAME;

  /** The identity a registration in these tests makes. */
  static final String OTHER = "other/node";

  enum Op {
    RENEW,
    REKEY
  }

  /** BEFORE: the request fails and is not processed; AFTER: it is processed and its reply is lost. */
  enum Cut {
    BEFORE,
    AFTER
  }

  /**
   * The calls stopped and repeated. CORRECTED: a registration of three certificates stops once its
   * objects are registered, and is then made with both issuers re-issued.
   */
  enum Call {
    REGISTER,
    RENEW,
    REKEY,
    CORRECTED
  }

  static Stream<Arguments> servers() {
    return TlsIdentityTest.servers();
  }

  static Stream<Arguments> cases() {
    List<Arguments> out = new ArrayList<>();
    for (Arguments s : TlsIdentityTest.servers().toList())
      for (Op op : Op.values()) out.add(Arguments.of(s.get()[0], s.get()[1], op));
    return out.stream();
  }

  static Stream<Arguments> calls() {
    List<Arguments> out = new ArrayList<>();
    for (Arguments s : TlsIdentityTest.servers().toList())
      for (Call c : Call.values()) out.add(Arguments.of(s.get()[0], s.get()[1], c));
    return out.stream();
  }

  /**
   * A client's transport. Its {@code at}th request, counted from {@link #count}, is cut as {@code
   * cut} says; a request {@code failIf} accepts fails; {@code hook} sees each request first. While
   * {@code counting}, the writes are recorded, and the {@code stopAt}th stops the call dead ({@link
   * TlsOwnershipTest.Stop}), before the server sees it or after, as {@code stopCut} says.
   */
  static final class Transport {
    volatile int at;
    volatile Cut cut = Cut.BEFORE;
    final AtomicInteger seen = new AtomicInteger();
    volatile Predicate<Ttlv> failIf = r -> false;
    volatile java.util.function.Consumer<Ttlv> hook = r -> {};
    volatile boolean counting;
    volatile int stopAt;
    volatile Cut stopCut = Cut.BEFORE;
    final List<TlsOwnershipTest.Write> writes = new CopyOnWriteArrayList<>();

    void count() {
      seen.set(0);
    }
  }

  /** The certificates of one test: the same on a fresh server for each stop. */
  static final class Material {
    final TlsIdentityTest.Pki pki = new TlsIdentityTest.Pki();
    final KeyPair k1 = TestPki.ec(), k2 = TestPki.ec(), k3 = TestPki.ec();
    final TestPki.Issued first = pki.leaf("node1", k1);
    final X509Certificate reissued = reissue("Test Issuing CA", pki.ca, pki.root);
    final X509Certificate reissuedRoot = reissue("Test Root", pki.root, null);
    final TestPki.Issued mineRenewed = pki.leaf("node1", k1), mineRekeyed = pki.leaf("node1", k2);
    final TestPki.Issued theirsRenewed = pki.leaf("node1", k1),
        theirsRekeyed = pki.leaf("node1", k3);
    final TestPki.Issued stranger = pki.leaf("foreign", TestPki.ec());

    Material() throws Exception {}

    X509Certificate mine(Op op) {
      return (op == Op.RENEW ? mineRenewed : mineRekeyed).certificate();
    }

    /** This job's call: to its leaf, with a re-issued intermediate. */
    TlsIdentityHandle job(TlsIdentityHandle from, Op op) {
      return op == Op.RENEW
          ? from.renew(mine(op), reissued)
          : from.rekey(k2.getPrivate(), mine(op), reissued);
    }

    /** The other caller's call, which moves the identity on. */
    TlsIdentityHandle theirs(TlsIdentityHandle from, Op op) {
      return op == Op.RENEW
          ? from.renew(pki.chain(theirsRenewed))
          : from.rekey(k3.getPrivate(), pki.chain(theirsRekeyed));
    }

    /** The chain {@code call} gives, leaf first. */
    List<X509Certificate> chain(Call call) {
      return switch (call) {
        case REGISTER -> List.of(mineRekeyed.certificate(), pki.ca.certificate());
        case RENEW -> List.of(mineRenewed.certificate(), reissued);
        case REKEY -> List.of(mineRekeyed.certificate(), reissued);
        case CORRECTED -> List.of(mineRekeyed.certificate(), reissued, reissuedRoot);
      };
    }
  }

  /** A server with the identity registered, this job's client (with its transport), and another caller. */
  static final class Scenario implements AutoCloseable {
    final InMemoryKmipServer server;
    final Transport t = new Transport();
    final Kms other;
    Kms kms;
    final TlsIdentityHandle start;
    final Material m;

    Scenario(KmipVersion version, boolean unique, Material m) {
      this.m = m;
      server = InMemoryKmipServer.of(version).uniqueNames(unique);
      kms = client();
      other = TlsIdentityTest.connect(server);
      start = kms.tls().register(m.k1.getPrivate(), m.pki.chain(m.first)).named(NAME).register();
    }

    private Kms client() {
      return Kms.connect(
          server
              .configure()
              .maximumVersion(KmipVersion.V3_0)
              .retryPolicy(RetryPolicy.none())
              .transport(e -> this::exchange)
              .build());
    }

    private Ttlv exchange(Ttlv r) throws IOException {
      t.hook.accept(r);
      if (t.failIf.test(r)) throw new IOException("stopped");
      TlsOwnershipTest.Write w = t.counting ? TlsOwnershipTest.write(r) : null;
      int written = t.writes.size() + 1;
      if (w != null && written == t.stopAt && t.stopCut == Cut.BEFORE)
        throw new TlsOwnershipTest.Stop();
      if (w != null) t.writes.add(w);
      int n = t.seen.incrementAndGet();
      if (n == t.at && t.cut == Cut.BEFORE) throw new IOException("cut at " + n);
      Ttlv reply = server.exchange(r);
      if (w != null && written == t.stopAt) throw new TlsOwnershipTest.Stop();
      if (n == t.at) throw new SocketTimeoutException("reply " + n + " lost");
      return reply;
    }

    /** A new client for the repeat: the stopped one is left as the stop left it. */
    void reconnect() {
      try {
        kms.close();
      } catch (RuntimeException ignored) {
        // Stopped dead: closing it may fail.
      }
      kms = client();
    }

    /** Stops the job's call to its leaf just before it links the old certificate to the new one. */
    PartialCompletionException stopBeforeTheReplacementLink(Op op) {
      String old = start.certificate().id();
      t.failIf = r -> TlsIdentityLifecycleTest.addsReplacementLink(r, old);
      PartialCompletionException e =
          assertThrows(PartialCompletionException.class, () -> m.job(start, op));
      t.failIf = r -> false;
      return e;
    }

    /** Stops a registration of three certificates dead once its four objects are registered. */
    void stopTheFirstAttemptOnceRegistered() {
      int[] registers = {0};
      t.hook =
          r -> {
            if (is(r, Operation.REGISTER)) registers[0]++;
            else if (registers[0] == 4 && is(r, Operation.ADD_ATTRIBUTE))
              throw new TlsOwnershipTest.Stop();
          };
      assertThrows(
          TlsOwnershipTest.Stop.class,
          () ->
              kms.tls()
                  .register(m.k2.getPrivate(), m.mineRekeyed.chain(m.pki.ca, m.pki.root))
                  .named(OTHER)
                  .register());
      t.hook = r -> {};
      assertEquals(4, registers[0]);
      reconnect();
    }

    /** {@code call}, from the identity as it is now. */
    TlsIdentityHandle call(Call call) {
      X509Certificate[] chain = m.chain(call).toArray(X509Certificate[]::new);
      return switch (call) {
        case REGISTER, CORRECTED ->
            kms.tls().register(m.k2.getPrivate(), chain).named(OTHER).register();
        case RENEW -> kms.tls().identity(NAME).orElseThrow().renew(chain);
        case REKEY -> kms.tls().identity(NAME).orElseThrow().rekey(m.k2.getPrivate(), chain);
      };
    }

    /**
     * What the stopped call's switch made the identity's, among {@code left}: the leaf the old
     * certificate names as its replacement (for a registration, the leaf with the name), first,
     * then its private key and its chain; empty before the switch.
     */
    Set<String> switched(String name, Set<String> left) {
      List<String> leaves =
          name.equals(NAME)
              ? server.links(start.certificate().id(), LinkKind.REPLACEMENT)
              : left.stream().filter(id -> server.names(id).contains(name)).toList();
      Set<String> out = new LinkedHashSet<>();
      if (leaves.size() != 1 || !left.contains(leaves.get(0))) return out;
      String c = leaves.get(0);
      out.add(c);
      out.addAll(server.links(c, LinkKind.PRIVATE_KEY));
      while (!server.links(c, LinkKind.CERTIFICATE).isEmpty() && out.size() < 10) {
        c = server.links(c, LinkKind.CERTIFICATE).get(0);
        out.add(c);
      }
      out.retainAll(left);
      return out;
    }

    /** The certificate the identity {@code name} presents now, if any. */
    Optional<String> current(String name) {
      return other.tls().identity(name).map(h -> h.certificate().id());
    }

    /**
     * {@code call} finished with {@code done}: its leaf and chain, the name on the leaf alone,
     * linked after the identity's first certificate (which is deactivated and has no name), the
     * temporary names and the record of the name being moved off the identity's objects, and a
     * follower presents it.
     */
    void assertFinished(Call call, TlsIdentityHandle done, String when) throws Exception {
      String name = call == Call.REGISTER || call == Call.CORRECTED ? OTHER : NAME;
      List<X509Certificate> chain = m.chain(call);
      assertEquals(chain.size(), done.chain().size(), when);
      for (int i = 0; i < chain.size(); i++)
        assertArrayEquals(
            chain.get(i).getEncoded(),
            TlsIdentities.certificate(other, done.chain().get(i).id()).getEncoded(),
            when + ": certificate " + i);
      assertEquals(List.of(name), server.names(done.certificate().id()), when);
      if (name.equals(NAME)) {
        String old = start.certificate().id();
        assertEquals(List.of(old), server.links(done.certificate().id(), LinkKind.REPLACED), when);
        assertEquals(
            List.of(done.certificate().id()), server.links(old, LinkKind.REPLACEMENT), when);
        assertEquals(Optional.of(KeyState.DEACTIVATED), server.state(old), when);
        assertEquals(List.of(), server.names(old), when);
        assertEquals(
            Optional.of(call == Call.REKEY ? KeyState.DEACTIVATED : KeyState.ACTIVE),
            server.state(start.privateKey().id()),
            when);
      }
      try (TlsIdentityFollower f = other.tls().follow(name, HOURLY, SCHEDULER)) {
        assertEquals(chain.get(0), assertWhole(f).certificate(), when);
      }
      List<String> objects = new ArrayList<>(List.of(done.privateKey().id()));
      for (KeyHandle c : done.chain()) objects.add(c.id());
      for (String id : objects) {
        assertTrue(
            server.names(id).stream().noneMatch(n -> n.contains(".issuing-")),
            when + ": " + id + " " + server.names(id));
        assertTrue(
            server.protocolAttributes(id).keySet().stream().noneMatch(a -> a.contains("pending")),
            when + ": " + id);
        assertEquals(Optional.of(KeyState.ACTIVE), server.state(id), when + ": " + id);
      }
      assertEquals(List.of(), server.violations(), when);
    }

    @Override
    public void close() {
      try {
        kms.close();
      } catch (RuntimeException ignored) {
        // As reconnect.
      }
      other.close();
      server.close();
    }
  }

  /**
   * Every call, stopped dead at each of its writes, before the server sees it or after, then
   * repeated on a new client: the repeat finishes. It sends nothing to an object the stopped call
   * (or, for CORRECTED, the first attempt) left, except the new leaf, its key and its chain when
   * the stopped call had made its switch, and leaves each of them as it was. Those it does not
   * finish with are never presented: they are Pre-Active, they have no name but a temporary one,
   * and the identity's certificate links only to the repeat's leaf. With a corrected chain of two
   * issuers, nothing of the first attempt is read or set aside: the corrected issuers are
   * registered as given.
   */
  @ParameterizedTest
  @MethodSource("calls")
  void aCallStoppedAtAnyWriteIsFinishedByARepeatThatLeavesWhatItLeft(
      KmipVersion version, boolean unique, Call call) throws Exception {
    Material m = new Material();
    int n;
    try (Scenario s = new Scenario(version, unique, m)) {
      if (call == Call.CORRECTED) s.stopTheFirstAttemptOnceRegistered();
      s.t.counting = true;
      s.assertFinished(call, s.call(call), "no stop");
      n = s.t.writes.size();
    }
    assertTrue(n > 10, "writes: " + n);
    for (Cut cut : Cut.values())
      for (int k = 1; k <= n; k++) {
        String when = call + " " + cut + " write " + k + " of " + n;
        try (Scenario s = new Scenario(version, unique, m)) {
          Set<String> before = Set.copyOf(s.server.ids());
          if (call == Call.CORRECTED) s.stopTheFirstAttemptOnceRegistered();
          s.t.counting = true;
          s.t.stopAt = k;
          s.t.stopCut = cut;
          assertThrows(TlsOwnershipTest.Stop.class, () -> s.call(call), when);
          s.t.stopAt = 0;
          Set<String> left = new LinkedHashSet<>(s.server.ids());
          left.removeAll(before);
          String name = call == Call.REGISTER || call == Call.CORRECTED ? OTHER : NAME;
          Set<String> published = s.switched(name, left);
          String switched = published.isEmpty() ? null : published.iterator().next();
          Map<String, String> was = snapshot(s.server, left);
          s.reconnect();
          s.t.writes.clear();
          TlsIdentityHandle done = assertDoesNotThrow(() -> s.call(call), when);
          s.assertFinished(call, done, when);
          if (switched != null) assertEquals(switched, done.certificate().id(), when);
          Set<String> kept = new LinkedHashSet<>();
          kept.add(done.certificate().id());
          kept.add(done.privateKey().id());
          for (KeyHandle c : done.chain()) kept.add(c.id());
          for (String x : left) {
            for (TlsOwnershipTest.Write w : s.t.writes)
              if (!published.contains(x))
                assertFalse(
                    w.mentions(x),
                    when
                        + ": the repeat sent "
                        + Operation.fromCode(w.operation())
                        + " "
                        + w.target()
                        + ", naming "
                        + x
                        + ", which the stopped call left");
            if (published.contains(x)) continue;
            assertEquals(was.get(x), snapshot(s.server, Set.of(x)).get(x), when + ": " + x);
            assertEquals(
                Optional.of(KeyState.PRE_ACTIVE), s.server.state(x), when + ": leftover " + x);
            if (kept.contains(x)) continue;
            assertTrue(
                s.server.names(x).stream()
                    .allMatch(v -> v.startsWith(TlsIdentities.temporaryPrefix(name))),
                when + ": a leftover " + x + " has the names " + s.server.names(x));
          }
        }
      }
  }

  /**
   * This job's re-key (or renewal) stops just before it links the old certificate to its new one;
   * another caller then moves the identity on. The job, repeated from the identity as it is now,
   * starts over and makes its leaf the identity's; that repeat is itself cut at each of its
   * requests, and one more repeat finishes. None of them sends the first attempt's objects
   * anything.
   */
  @ParameterizedTest
  @MethodSource("cases")
  void aRepeatAfterTheIdentityMovedOnIsCutAnywhereAndTheNextFinishes(
      KmipVersion version, boolean unique, Op op) throws Exception {
    Material m = new Material();
    Call call = op == Op.RENEW ? Call.RENEW : Call.REKEY;
    int n;
    try (Scenario s = new Scenario(version, unique, m)) {
      s.stopBeforeTheReplacementLink(op);
      m.theirs(s.other.tls().identity(NAME).orElseThrow(), op);
      n = requests(s, () -> s.call(call));
    }
    assertTrue(n > 10, "requests: " + n);
    for (Cut cut : Cut.values())
      for (int k = 1; k <= n; k++) {
        String when = op + " " + cut + " request " + k + " of " + n;
        try (Scenario s = new Scenario(version, unique, m)) {
          List<String> first = ids(s.stopBeforeTheReplacementLink(op).created());
          TlsIdentityHandle now = m.theirs(s.other.tls().identity(NAME).orElseThrow(), op);
          Map<String, String> was = snapshot(s.server, first);
          s.t.counting = true;
          TlsIdentityHandle done = cutThenRepeat(s, () -> s.call(call), k, cut, when);
          assertEquals(
              List.of(now.certificate().id()),
              s.server.links(done.certificate().id(), LinkKind.REPLACED),
              when);
          assertArrayEquals(
              m.mine(op).getEncoded(),
              TlsIdentities.certificate(s.other, done.certificate().id()).getEncoded(),
              when);
          try (TlsIdentityFollower f = s.other.tls().follow(NAME, HOURLY, SCHEDULER)) {
            assertEquals(m.mine(op), assertWhole(f).certificate(), when);
          }
          assertNothingSent(s, first, when);
          assertEquals(was, snapshot(s.server, first), when);
          assertEquals(List.of(), s.server.violations(), when);
        }
      }
  }

  /**
   * This job's re-key (or renewal) loses its race: another caller's call to the same identity runs
   * as the job's goes to link the old certificate to its new one, and the server refuses the
   * second replacement. The job's call is cut at each of its requests. Its objects are never
   * presented, and it makes no more changes after the refusal. A repeat from the identity as it is
   * now starts over and finishes, sending the lost call's objects nothing.
   */
  @ParameterizedTest
  @MethodSource("cases")
  void aCallCutAtAnyRequestOfALostRaceIsFinishedByARepeat(
      KmipVersion version, boolean unique, Op op) throws Exception {
    Material m = new Material();
    Call call = op == Op.RENEW ? Call.RENEW : Call.REKEY;
    int n;
    try (Scenario s = new Scenario(version, unique, m)) {
      TlsIdentityHandle[] won = race(s, op);
      s.t.count();
      StateConflictException lost =
          assertThrows(StateConflictException.class, () -> m.job(s.start, op));
      n = s.t.seen.get();
      assertEquals(StateConflictException.Conflict.REPLACED, lost.conflict(), lost.getMessage());
      assertTrue(
          lost.getMessage().contains("are left over: it activated none of them"),
          lost.getMessage());
      assertNotNull(won[0], "the other call ran");
    }
    assertTrue(n > 10, "requests: " + n);
    for (Cut cut : Cut.values())
      for (int k = 1; k <= n; k++) {
        String when = op + " " + cut + " request " + k + " of " + n;
        try (Scenario s = new Scenario(version, unique, m)) {
          Set<String> before = Set.copyOf(s.server.ids());
          TlsIdentityHandle[] won = race(s, op);
          s.t.count();
          s.t.cut = cut;
          s.t.at = k;
          try {
            m.job(s.start, op);
            fail(when + ": the call lost its race");
          } catch (PartialCompletionException
              | OutcomeUnknownException
              | TransientException
              | StateConflictException stopped) {
            assertTrue(
                !(stopped instanceof StateConflictException conflict)
                    || conflict.conflict() == StateConflictException.Conflict.REPLACED,
                when + ": " + stopped.getMessage());
          }
          s.t.at = 0;
          s.t.hook = r -> {};
          if (won[0] == null) won[0] = m.theirs(s.other.tls().identity(NAME).orElseThrow(), op);
          Set<String> left = new LinkedHashSet<>(s.server.ids());
          left.removeAll(before);
          left.remove(won[0].certificate().id());
          left.remove(won[0].privateKey().id());
          for (KeyHandle c : won[0].chain()) left.remove(c.id());
          Map<String, String> was = snapshot(s.server, left);
          s.t.counting = true;
          TlsIdentityHandle done = assertDoesNotThrow(() -> s.call(call), when);
          assertEquals(
              List.of(won[0].certificate().id()),
              s.server.links(done.certificate().id(), LinkKind.REPLACED),
              when);
          try (TlsIdentityFollower f = s.other.tls().follow(NAME, HOURLY, SCHEDULER)) {
            assertEquals(m.mine(op), assertWhole(f).certificate(), when);
          }
          assertNothingSent(s, left, when);
          assertEquals(was, snapshot(s.server, left), when);
          assertEquals(List.of(), s.server.violations(), when);
        }
      }
  }

  /** Arms the other caller's call, run as the job's call goes to link the old certificate. */
  private static TlsIdentityHandle[] race(Scenario s, Op op) {
    TlsIdentityHandle[] won = {null};
    String old = s.start.certificate().id();
    s.t.hook =
        r -> {
          if (won[0] == null && TlsIdentityLifecycleTest.addsReplacementLink(r, old))
            won[0] = s.m.theirs(s.other.tls().identity(NAME).orElseThrow(), op);
        };
    return won;
  }

  /** The requests {@code call} sends when nothing is cut. */
  static int requests(Scenario s, java.util.function.Supplier<TlsIdentityHandle> call) {
    s.t.count();
    assertNotNull(call.get(), "the call finishes when nothing is cut");
    return s.t.seen.get();
  }

  /** Runs {@code call} with its {@code k}th request cut, then repeats it until it is not cut. */
  static TlsIdentityHandle cutThenRepeat(
      Scenario s,
      java.util.function.Supplier<TlsIdentityHandle> call,
      int k,
      Cut cut,
      String when) {
    s.t.count();
    s.t.cut = cut;
    s.t.at = k;
    TlsIdentityHandle done = null;
    try {
      done = call.get();
    } catch (PartialCompletionException | OutcomeUnknownException | TransientException stopped) {
      assertTrue(
          !(stopped instanceof PartialCompletionException)
              || stopped.getMessage().contains("repeat "),
          when + ": " + stopped.getMessage());
    }
    s.t.at = 0;
    return done != null ? done : assertDoesNotThrow(call::get, when);
  }

  /** How another caller changes an earlier attempt's objects before the repeat. */
  enum Meddling {
    /** A registration stopped at its switch, the name; its leaf is taken, named and activated for another identity. */
    LEAF_TAKEN_FOR_ANOTHER_IDENTITY,
    /** A registration of three certificates stopped at its switch; its intermediate is named and issues a second identity. */
    INTERMEDIATE_SHARED,
    /** A registration stopped before its links; its intermediate is linked to a named root. */
    INTERMEDIATE_LINKED,
    /** A re-key stopped before its switch, then the identity moved on; its intermediate is linked to an unnamed, Pre-Active root. */
    INTERMEDIATE_LINKED_TO_AN_UNNAMED_ROOT,
    /** As the last, its key is linked to the identity's current key. */
    KEY_LINKED
  }

  /**
   * An earlier attempt stops; another caller changes one of its objects; the repeat, with the same
   * leaf (and for a registration, a corrected chain), finishes. It sends none of the earlier
   * attempt's objects, or the other caller's, anything, and leaves every one of them as the other
   * caller left it: a resume used to relink, rename or set some of these aside.
   */
  @ParameterizedTest
  @MethodSource("meddlings")
  void aRepeatSendsNothingToAnEarlierAttemptsObjectsAnotherCallerChanged(
      KmipVersion version, Meddling meddling) throws Exception {
    Material m = new Material();
    try (Scenario s = new Scenario(version, true, m)) {
      Set<String> before = Set.copyOf(s.server.ids());
      Call call;
      List<String> attempt;
      switch (meddling) {
        case LEAF_TAKEN_FOR_ANOTHER_IDENTITY -> {
          call = Call.REGISTER;
          attempt =
              ids(stopRegistration(s, m.mineRekeyed.chain(m.pki.ca), TlsRepeatTest::namesOther));
          String leaf = attempt.get(0), key = attempt.get(1), ca = attempt.get(2);
          s.other.keys().handle(leaf).addName("borrowed-identity");
          s.other.keys().handle(key).activate();
          s.other.keys().handle(ca).activate();
          s.other.keys().handle(leaf).activate();
          assertEquals(
              List.of(leaf, ca),
              chainIds(s.other.tls().identity("borrowed-identity").orElseThrow()));
        }
        case INTERMEDIATE_SHARED -> {
          call = Call.CORRECTED;
          attempt =
              ids(
                  stopRegistration(
                      s, m.mineRekeyed.chain(m.pki.ca, m.pki.root), TlsRepeatTest::namesOther));
          String ca = attempt.get(2);
          s.other.keys().handle(ca).addName("shared-issuer");
          String second =
              s.other
                  .tls()
                  .register(m.k3.getPrivate(), m.theirsRekeyed.certificate())
                  .named("second")
                  .register()
                  .certificate()
                  .id();
          link(s.other, second, Enums.LinkType.CERTIFICATE_LINK, ca);
          assertEquals(
              List.of(second, ca, attempt.get(3)),
              chainIds(s.other.tls().identity("second").orElseThrow()));
        }
        case INTERMEDIATE_LINKED -> {
          call = Call.REGISTER;
          attempt =
              ids(stopRegistration(s, m.mineRekeyed.chain(m.pki.ca), Operation.ADD_ATTRIBUTE, 1));
          String root =
              s.other.keys().register(m.pki.root.certificate()).named("kept-root").register().id();
          link(s.other, attempt.get(2), Enums.LinkType.CERTIFICATE_LINK, root);
        }
        case INTERMEDIATE_LINKED_TO_AN_UNNAMED_ROOT, KEY_LINKED -> {
          call = Call.REKEY;
          attempt = ids(s.stopBeforeTheReplacementLink(Op.REKEY).created());
          TlsIdentityHandle now = m.theirs(s.other.tls().identity(NAME).orElseThrow(), Op.REKEY);
          if (meddling == Meddling.KEY_LINKED)
            link(
                s.other,
                attempt.get(1),
                Enums.LinkType.DERIVATION_BASE_OBJECT_LINK,
                now.privateKey().id());
          else {
            KeyHandle root = s.other.keys().register(m.pki.root.certificate()).registerPreActive();
            link(s.other, attempt.get(2), Enums.LinkType.CERTIFICATE_LINK, root.id());
          }
        }
        default -> throw new IllegalArgumentException(meddling.name());
      }
      Set<String> left = new LinkedHashSet<>(s.server.ids());
      left.removeAll(before);
      if (call == Call.REKEY) {
        TlsIdentityHandle now = s.other.tls().identity(NAME).orElseThrow();
        left.remove(now.certificate().id());
        left.remove(now.privateKey().id());
        for (KeyHandle c : now.chain()) left.remove(c.id());
      }
      assertTrue(left.containsAll(attempt), left + " " + attempt);
      Map<String, String> was = snapshot(s.server);
      s.t.counting = true;
      TlsIdentityHandle done =
          call == Call.REGISTER
              ? s.kms
                  .tls()
                  .register(m.k2.getPrivate(), m.mineRekeyed.certificate(), m.reissued)
                  .named(OTHER)
                  .register()
              : s.call(call);
      assertArrayEquals(
          m.mineRekeyed.certificate().getEncoded(),
          TlsIdentities.certificate(s.other, done.certificate().id()).getEncoded());
      assertNothingSent(s, left, meddling.name());
      Map<String, String> after = snapshot(s.server);
      for (String x : left) assertEquals(was.get(x), after.get(x), meddling + ": " + x);
      for (String x : attempt) assertFalse(chainIds(done).contains(x), meddling + ": " + x);
    }
  }

  static Stream<Arguments> meddlings() {
    List<Arguments> out = new ArrayList<>();
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0))
      for (Meddling md : Meddling.values()) out.add(Arguments.of(v, md));
    return out.stream();
  }

  /**
   * A registration of {@code OTHER} with {@code chain}, stopped at its {@code nth} request of
   * {@code operation}: it and its resends fail before the server sees them. The call's objects,
   * leaf first.
   */
  private static List<KeyHandle> stopRegistration(
      Scenario s, X509Certificate[] chain, Operation operation, int nth) {
    int[] seen = {0};
    return stopRegistration(s, chain, r -> is(r, operation) && ++seen[0] >= nth);
  }

  /** Whether {@code request} gives an object the name {@link #OTHER}: a registration's switch. */
  static boolean namesOther(Ttlv request) {
    return is(request, Operation.ADD_ATTRIBUTE)
        && TlsOwnershipTest.write(request).texts().contains(OTHER);
  }

  /** A registration of {@code OTHER} with {@code chain}, stopped at each request {@code stop} accepts. */
  private static List<KeyHandle> stopRegistration(
      Scenario s, X509Certificate[] chain, Predicate<Ttlv> stop) {
    s.t.failIf = stop;
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> s.kms.tls().register(s.m.k2.getPrivate(), chain).named(OTHER).register());
    s.t.failIf = r -> false;
    assertTrue(e.getMessage().contains("starts over"), e.getMessage());
    return e.created();
  }

  /**
   * After a lost Register reply, the call looks its object up by its own temporary name. Another
   * caller activates that object before the lookup: it is not as the Register left it, so the call
   * stops, and does not link or name it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostRegistersCertificateAnotherCallerActivatedIsNotTaken(KmipVersion version)
      throws Exception {
    Material m = new Material();
    try (Scenario s = new Scenario(version, false, m)) {
      AtomicInteger registers = new AtomicInteger();
      boolean[] activated = {false};
      Map<String, String> before = new TreeMap<>();
      String prefix = TlsIdentities.temporaryPrefix(OTHER);
      s.t.hook =
          r -> {
            if (is(r, Operation.REGISTER) && registers.incrementAndGet() == 3)
              s.server.failNext(ServerOperation.REGISTER, Fault.REPLY_LOST);
            else if (registers.get() == 3 && is(r, Operation.LOCATE) && !activated[0]) {
              activated[0] = true;
              s.other.keys().handle(named(s.server, prefix, ".ca1")).activate();
              // What the call finds, the other caller's change included.
              before.putAll(snapshot(s.server));
            }
          };
      assertThrows(
          KmsException.class,
          () ->
              s.kms
                  .tls()
                  .register(m.k2.getPrivate(), m.mineRekeyed.chain(m.pki.ca))
                  .named(OTHER)
                  .register());
      assertTrue(activated[0], "another caller activated it before the lookup");
      String caId = named(s.server, prefix, ".ca1");
      assertEquals(1, s.server.names(caId).size());
      for (String id : s.server.ids())
        assertFalse(
            s.server.links(id, LinkKind.CERTIFICATE).contains(caId), id + " links to " + caId);
      assertEquals(
          before, snapshot(s.server), "nothing was changed after the other caller's change");
    }
  }

  /** The link whose first send loses its request, after another caller changed its target. */
  enum Resent {
    /** A re-key's leaf to its new key: Private Key link. */
    NEW_KEY,
    /** A renewal's kept key to the new leaf: Certificate link. */
    KEPT_KEY,
    /** The old certificate to a re-key's new leaf: Replacement Object link. */
    PREDECESSOR
  }

  static Stream<Arguments> resent() {
    List<Arguments> out = new ArrayList<>();
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0))
      for (Resent r : Resent.values()) out.add(Arguments.of(v, r));
    return out.stream();
  }

  /**
   * As a link goes out, another caller gives its target another name, and the request is lost
   * before the server sees it. The call read that the source has no such link, and used to send it
   * again without reading the target. Now it reads the target before each send: it stops, naming
   * it, and links nothing to it.
   */
  @ParameterizedTest
  @MethodSource("resent")
  void aLinkIsNotSentAgainToATargetAnotherCallerChanged(KmipVersion version, Resent resent)
      throws Exception {
    Material m = new Material();
    try (Scenario s = new Scenario(version, true, m)) {
      String old = s.start.certificate().id(), keptKey = s.start.privateKey().id();
      Predicate<Ttlv> isTheLink =
          switch (resent) {
            case NEW_KEY -> r -> addsLink(r, Enums.LinkType.PRIVATE_KEY_LINK, Tag.PRIVATE_KEY_LINK);
            case KEPT_KEY ->
                r ->
                    addsLink(r, Enums.LinkType.CERTIFICATE_LINK, Tag.CERTIFICATE_LINK)
                        && keptKey.equals(TlsOwnershipTest.write(r).target());
            case PREDECESSOR -> r -> TlsIdentityLifecycleTest.addsReplacementLink(r, old);
          };
      String[] target = {null};
      String[] state = {null};
      List<Ttlv> sent = new CopyOnWriteArrayList<>();
      s.t.hook =
          r -> {
            if (!isTheLink.test(r)) return;
            sent.add(r);
            if (target[0] != null) return;
            TlsOwnershipTest.Write w = TlsOwnershipTest.write(r);
            for (String x : w.texts())
              if (x.startsWith("mock-") && !x.equals(w.target())) target[0] = x;
            s.other.keys().handle(target[0]).addName("foreign-use");
            state[0] = TlsOwnershipTest.stateOf(s.server, target[0]);
          };
      s.t.failIf = r -> isTheLink.test(r) && sent.size() == 1;
      KmsException e =
          assertThrows(
              KmsException.class,
              () -> m.job(s.start, resent == Resent.KEPT_KEY ? Op.RENEW : Op.REKEY));
      assertNotNull(target[0], "the link went out");
      StateConflictException refusal =
          e instanceof StateConflictException c
              ? c
              : assertInstanceOf(StateConflictException.class, e.getCause(), e.getMessage());
      assertEquals(Optional.of(target[0]), refusal.objectId(), refusal.getMessage());
      assertEquals(StateConflictException.Conflict.NAME, refusal.conflict());
      assertEquals(1, sent.size(), "the link was sent again after its target changed");
      assertEquals(state[0], TlsOwnershipTest.stateOf(s.server, target[0]));
      // The kept key is linked after the switch, so the switch is made then; the identity still
      // presents the old pair.
      assertEquals(
          resent == Resent.KEPT_KEY ? List.of(target[0]) : List.of(),
          s.server.links(old, LinkKind.REPLACEMENT));
      assertEquals(Optional.of(old), s.current(NAME), "nothing presented changed");
    }
  }

  /** Whether {@code request} adds a link of {@code type} (a Link structure, or the 3.0 attribute {@code tag}). */
  static boolean addsLink(Ttlv request, Enums.LinkType type, Tag tag) {
    return TlsIdentityLifecycleTest.adds(
            request, "enum:" + Tag.LINK_TYPE.code() + "=" + type.code())
        || TlsIdentityLifecycleTest.adds(request, "tag:" + tag.code());
  }

  /**
   * A renewal stops dead just after it activates its leaf: the old certificate links to the new
   * leaf, which is current, and the name has not moved. Another caller then makes the renewal's new
   * intermediate the issuer of an Active certificate of another identity. The repeat finds the
   * leaf current and finishes: it moves the name and deactivates the old certificate, and sends
   * the shared intermediate nothing. A repeat used to check the intermediate, refuse, and advise a
   * fresh registration, which did not finish either.
   */
  @ParameterizedTest
  @MethodSource("servers")
  void aRepeatAfterTheSwitchFinishesAndLeavesAnIssuerAnotherIdentityUses(
      KmipVersion version, boolean unique) throws Exception {
    Material m = new Material();
    try (Scenario s = new Scenario(version, unique, m)) {
      String leaf = stopAfterTheActivation(s, Op.RENEW);
      String ca = s.server.links(leaf, LinkKind.CERTIFICATE).get(0);
      String foreign =
          s.other.keys().register(m.stranger.certificate()).named("foreign/node").register().id();
      link(s.other, foreign, Enums.LinkType.CERTIFICATE_LINK, ca);
      String was = TlsOwnershipTest.stateOf(s.server, ca);
      s.reconnect();
      s.t.counting = true;
      TlsIdentityHandle done = assertDoesNotThrow(() -> s.call(Call.RENEW));
      assertEquals(leaf, done.certificate().id());
      s.assertFinished(Call.RENEW, done, "after the switch");
      assertNothingSent(s, List.of(ca), "the shared issuer");
      assertEquals(was, TlsOwnershipTest.stateOf(s.server, ca));
    }
  }

  /**
   * A renewal stops dead just after it activates its leaf; another caller gives the new leaf, now
   * the identity's certificate, another name. The repeat stops before it changes the leaf, with
   * nothing changed, and says the identity presents the leaf, and what is left to do by hand.
   * Done so, the identity is finished, and a repeat returns it without a change. Undoing the
   * change instead, then repeating, finishes too.
   */
  @ParameterizedTest
  @MethodSource("servers")
  void aRefusalAfterTheSwitchSaysHowToFinishAndFollowingItFinishes(
      KmipVersion version, boolean unique) throws Exception {
    Material m = new Material();
    for (boolean byHand : new boolean[] {true, false})
      try (Scenario s = new Scenario(version, unique, m)) {
        String old = s.start.certificate().id();
        String leaf = stopAfterTheActivation(s, Op.RENEW);
        s.other.keys().handle(leaf).addName("foreign-use");
        Map<String, String> was = snapshot(s.server);
        s.reconnect();
        StateConflictException e =
            assertThrows(StateConflictException.class, () -> s.call(Call.RENEW));
        assertEquals(Optional.of(leaf), e.objectId(), e.getMessage());
        assertEquals(StateConflictException.Conflict.NAME, e.conflict());
        assertTrue(e.getMessage().contains("nothing was changed"), e.getMessage());
        assertTrue(e.getMessage().contains("presents " + leaf + " already"), e.getMessage());
        assertTrue(
            e.getMessage()
                .contains(
                    "take the name "
                        + NAME
                        + " off the certificates "
                        + leaf
                        + " replaced and give it to "
                        + leaf),
            e.getMessage());
        assertTrue(
            e.getMessage().contains("deactivate the certificates it replaced"), e.getMessage());
        assertFalse(e.getMessage().contains("temporary"), e.getMessage());
        assertEquals(was, snapshot(s.server), "nothing was changed");
        if (byHand) {
          s.other.keys().handle(old).removeName(NAME);
          s.other.keys().handle(leaf).addName(NAME);
          s.other.keys().handle(old).deactivate(RevocationReason.superseded("by hand"));
          try (TlsIdentityFollower f = s.other.tls().follow(NAME, HOURLY, SCHEDULER)) {
            assertEquals(m.mine(Op.RENEW), assertWhole(f).certificate());
          }
          assertEquals(Optional.of(KeyState.DEACTIVATED), s.server.state(old));
          s.t.counting = true;
          TlsIdentityHandle done = assertDoesNotThrow(() -> s.call(Call.RENEW));
          assertEquals(leaf, done.certificate().id());
          assertEquals(List.of(), s.t.writes, "nothing is left to change");
        } else {
          s.other.keys().handle(leaf).removeName("foreign-use");
          TlsIdentityHandle done = assertDoesNotThrow(() -> s.call(Call.RENEW));
          s.assertFinished(Call.RENEW, done, "undone, then repeated");
        }
      }
  }

  /**
   * A renewal stops dead just after its switch, before it activates anything; another caller gives
   * the renewal's new intermediate, still Pre-Active, a name. The repeat stops before any change,
   * naming it, and says what is left to do by hand: link the key, activate, move the name and
   * deactivate. Done so, the identity is finished, and a repeat returns it without a change.
   * Undoing the change instead, then repeating, finishes too.
   */
  @ParameterizedTest
  @MethodSource("servers")
  void aRefusalBetweenTheSwitchAndTheActivationSaysHowToFinishAndFollowingItFinishes(
      KmipVersion version, boolean unique) throws Exception {
    Material m = new Material();
    for (boolean byHand : new boolean[] {true, false})
      try (Scenario s = new Scenario(version, unique, m)) {
        String old = s.start.certificate().id(), key = s.start.privateKey().id();
        String leaf = stopAfterTheSwitch(s, Op.RENEW);
        String ca = s.server.links(leaf, LinkKind.CERTIFICATE).get(0);
        s.other.keys().handle(ca).addName("foreign-use");
        Map<String, String> was = snapshot(s.server);
        s.reconnect();
        s.t.counting = true;
        StateConflictException e =
            assertThrows(StateConflictException.class, () -> s.call(Call.RENEW));
        assertEquals(Optional.of(ca), e.objectId(), e.getMessage());
        assertEquals(StateConflictException.Conflict.NAME, e.conflict());
        assertTrue(e.getMessage().contains("nothing was changed"), e.getMessage());
        assertTrue(
            e.getMessage().contains(old + " names " + leaf + " as its replacement"),
            e.getMessage());
        assertTrue(
            e.getMessage().contains("activate the Pre-Active private key and certificates"),
            e.getMessage());
        assertEquals(List.of(), s.t.writes);
        assertEquals(was, snapshot(s.server), "nothing was changed");
        if (byHand) {
          link(s.other, key, Enums.LinkType.CERTIFICATE_LINK, leaf);
          s.other.keys().handle(ca).activate();
          s.other.keys().handle(leaf).activate();
          s.other.keys().handle(old).removeName(NAME);
          s.other.keys().handle(leaf).addName(NAME);
          s.other.keys().handle(old).deactivate(RevocationReason.superseded("by hand"));
          try (TlsIdentityFollower f = s.other.tls().follow(NAME, HOURLY, SCHEDULER)) {
            assertEquals(m.mine(Op.RENEW), assertWhole(f).certificate());
          }
          s.t.writes.clear();
          TlsIdentityHandle done = assertDoesNotThrow(() -> s.call(Call.RENEW));
          assertEquals(leaf, done.certificate().id());
          assertEquals(List.of(), s.t.writes, "nothing is left to change");
        } else {
          s.other.keys().handle(ca).removeName("foreign-use");
          TlsIdentityHandle done = assertDoesNotThrow(() -> s.call(Call.RENEW));
          assertEquals(leaf, done.certificate().id());
          s.assertFinished(Call.RENEW, done, "undone, then repeated");
        }
      }
  }

  /**
   * The server refuses the switch: a renewal's or re-key's Replacement Object link (Missing Data),
   * or a registration's name (Permission Denied). The call knows the switch was not made: its
   * message says the repeat starts over and its objects are left over, not that the switch may have
   * been made. A plain repeat finishes.
   */
  @ParameterizedTest
  @MethodSource("servers")
  void aSwitchTheServerRefusesIsSaidNotToBeMadeAndARepeatFinishes(
      KmipVersion version, boolean unique) throws Exception {
    Material m = new Material();
    for (Call call : new Call[] {Call.REGISTER, Call.RENEW, Call.REKEY})
      try (Scenario s = new Scenario(version, unique, m)) {
        String old = s.start.certificate().id();
        boolean[] armed = {false};
        s.t.hook =
            r -> {
              boolean theSwitch =
                  call == Call.REGISTER
                      ? namesOther(r)
                      : TlsIdentityLifecycleTest.addsReplacementLink(r, old);
              if (theSwitch && !armed[0]) {
                armed[0] = true;
                s.server.failNext(
                    ServerOperation.ADD_ATTRIBUTE,
                    call == Call.REGISTER ? Fault.PERMISSION_DENIED : Fault.INVALID_REQUEST);
              }
            };
        PartialCompletionException e =
            assertThrows(PartialCompletionException.class, () -> s.call(call));
        s.t.hook = r -> {};
        assertTrue(armed[0]);
        assertEquals(
            List.of(),
            call == Call.REGISTER
                ? s.server.ids().stream().filter(id -> s.server.names(id).contains(OTHER)).toList()
                : s.server.links(old, LinkKind.REPLACEMENT),
            "the switch was not made");
        assertFalse(e.getMessage().contains("may have been made"), e.getMessage());
        assertTrue(e.getMessage().contains("it starts over"), e.getMessage());
        assertTrue(
            e.getMessage().contains("are left over: it activated none of them"), e.getMessage());
        TlsIdentityHandle done = assertDoesNotThrow(() -> s.call(call));
        s.assertFinished(call, done, "repeated");
      }
  }

  /**
   * A renewal's switch takes effect and its reply is lost, and the reads that would show it fail
   * too. The call cannot tell whether it made the switch; it says so, rather than that its objects
   * are left over, and a plain repeat finishes with its leaf.
   */
  @ParameterizedTest
  @MethodSource("servers")
  void aSwitchWhoseOutcomeIsUnknownIsSaidToBeUnknownAndARepeatFinishesIt(
      KmipVersion version, boolean unique) throws Exception {
    Material m = new Material();
    try (Scenario s = new Scenario(version, unique, m)) {
      String old = s.start.certificate().id();
      boolean[] sent = {false};
      s.t.hook =
          r -> {
            if (TlsIdentityLifecycleTest.addsReplacementLink(r, old) && !sent[0]) {
              sent[0] = true;
              s.server.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.REPLY_LOST);
            }
          };
      s.t.failIf = r -> sent[0] && TlsOwnershipTest.write(r) == null;
      PartialCompletionException e =
          assertThrows(PartialCompletionException.class, () -> m.job(s.start, Op.RENEW));
      s.t.hook = r -> {};
      s.t.failIf = r -> false;
      List<String> next = s.server.links(old, LinkKind.REPLACEMENT);
      assertEquals(1, next.size(), "the switch took effect");
      assertTrue(e.getMessage().contains("may have been made"), e.getMessage());
      assertFalse(e.getMessage().contains("nothing of the identity links"), e.getMessage());
      s.reconnect();
      TlsIdentityHandle done = assertDoesNotThrow(() -> s.call(Call.RENEW));
      assertEquals(next.get(0), done.certificate().id());
      s.assertFinished(Call.RENEW, done, "repeated");
    }
  }

  /**
   * Another caller links the identity's certificate to a Pre-Active certificate, both ways, as a
   * call that is still making it current would. A renewal used to link its leaf after that
   * certificate, which it did not make. Now it stops before it registers anything, naming that
   * certificate; once the link is taken off, as the advice says, a repeat finishes.
   */
  @ParameterizedTest
  @MethodSource("servers")
  void aNewerCertificateNotActiveYetStopsARenewalBeforeAnyChange(
      KmipVersion version, boolean unique) throws Exception {
    Material m = new Material();
    try (Scenario s = new Scenario(version, unique, m)) {
      String old = s.start.certificate().id();
      String newer =
          s.other.keys().register(m.theirsRenewed.certificate()).registerPreActive().id();
      link(s.other, newer, Enums.LinkType.REPLACED_OBJECT_LINK, old);
      link(s.other, old, Enums.LinkType.REPLACEMENT_OBJECT_LINK, newer);
      Map<String, String> was = snapshot(s.server);
      StateConflictException e =
          assertThrows(StateConflictException.class, () -> m.job(s.start, Op.RENEW));
      assertEquals(Optional.of(newer), e.objectId(), e.getMessage());
      assertEquals(StateConflictException.Conflict.REPLACED, e.conflict());
      assertEquals(Optional.of(KeyState.PRE_ACTIVE), e.observedState());
      assertTrue(
          e.getMessage().contains("take the Replacement Object link to " + newer + " off " + old),
          e.getMessage());
      assertEquals(was, snapshot(s.server), "nothing was changed");
      s.other
          .keys()
          .handle(old)
          .removeLink("by hand", Enums.LinkType.REPLACEMENT_OBJECT_LINK, newer);
      assertEquals(List.of(), s.server.links(old, LinkKind.REPLACEMENT));
      s.assertFinished(Call.RENEW, assertDoesNotThrow(() -> m.job(s.start, Op.RENEW)), "after");
    }
  }

  /**
   * Stops the job's {@code op} dead just after its switch: the old certificate names the new leaf,
   * still Pre-Active, as its replacement, and readers present the old pair.
   */
  static String stopAfterTheSwitch(Scenario s, Op op) {
    String old = s.start.certificate().id();
    boolean[] switched = {false};
    s.t.hook =
        r -> {
          if (switched[0] && TlsOwnershipTest.write(r) != null) throw new TlsOwnershipTest.Stop();
          if (TlsIdentityLifecycleTest.addsReplacementLink(r, old)) switched[0] = true;
        };
    assertThrows(TlsOwnershipTest.Stop.class, () -> s.m.job(s.start, op));
    s.t.hook = r -> {};
    List<String> next = s.server.links(old, LinkKind.REPLACEMENT);
    assertEquals(1, next.size());
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(next.get(0)));
    assertEquals(Optional.of(old), s.current(NAME), "readers present the old pair");
    assertEquals(List.of(NAME), s.server.names(old), "the name has not moved");
    return next.get(0);
  }

  /**
   * Stops the job's {@code op} dead just before it activates its leaf: the new leaf is Pre-Active,
   * and the new key (re-key) and the re-issued intermediate are Active already; a renewal's kept key
   * links to the leaf. Readers present the old pair.
   */
  static String stopBeforeTheLeafsActivation(Scenario s, Op op) {
    String old = s.start.certificate().id();
    s.t.hook =
        r -> {
          List<String> next = s.server.links(old, LinkKind.REPLACEMENT);
          if (is(r, Operation.ACTIVATE)
              && !next.isEmpty()
              && next.get(0).equals(TlsOwnershipTest.write(r).target()))
            throw new TlsOwnershipTest.Stop();
        };
    assertThrows(TlsOwnershipTest.Stop.class, () -> s.m.job(s.start, op));
    s.t.hook = r -> {};
    List<String> next = s.server.links(old, LinkKind.REPLACEMENT);
    assertEquals(1, next.size());
    String leaf = next.get(0);
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(leaf));
    String key = s.server.links(leaf, LinkKind.PRIVATE_KEY).get(0);
    String ca = s.server.links(leaf, LinkKind.CERTIFICATE).get(0);
    assertEquals(Optional.of(KeyState.ACTIVE), s.server.state(key));
    assertEquals(Optional.of(KeyState.ACTIVE), s.server.state(ca));
    assertTrue(s.server.links(key, LinkKind.CERTIFICATE).contains(leaf));
    assertEquals(Optional.of(old), s.current(NAME), "readers present the old pair");
    return leaf;
  }

  /** Stops the job's {@code op} dead just after it activates its leaf: the new leaf, current. */
  static String stopAfterTheActivation(Scenario s, Op op) {
    String old = s.start.certificate().id();
    boolean[] active = {false};
    s.t.hook =
        r -> {
          if (active[0] && TlsOwnershipTest.write(r) != null) throw new TlsOwnershipTest.Stop();
          List<String> next = s.server.links(old, LinkKind.REPLACEMENT);
          if (is(r, Operation.ACTIVATE)
              && !next.isEmpty()
              && next.get(0).equals(TlsOwnershipTest.write(r).target())) active[0] = true;
        };
    assertThrows(TlsOwnershipTest.Stop.class, () -> s.m.job(s.start, op));
    s.t.hook = r -> {};
    List<String> next = s.server.links(old, LinkKind.REPLACEMENT);
    assertEquals(1, next.size());
    assertEquals(Optional.of(next.get(0)), s.current(NAME), "the new leaf is current");
    assertEquals(List.of(NAME), s.server.names(old), "the name has not moved");
    return next.get(0);
  }

  /** No write the call sent since {@code counting} names one of {@code objects}. */
  private static void assertNothingSent(
      Scenario s, java.util.Collection<String> objects, String when) {
    for (TlsOwnershipTest.Write w : s.t.writes)
      for (String x : objects)
        assertFalse(
            w.mentions(x),
            when
                + ": sent "
                + Operation.fromCode(w.operation())
                + " "
                + w.target()
                + ", naming "
                + x);
  }

  static boolean is(Ttlv request, Operation operation) {
    return RotationAndNameChoiceTest.isOperation(request, operation);
  }

  /** Every object's state, names and links. */
  static Map<String, String> snapshot(InMemoryKmipServer s) {
    return snapshot(s, s.ids());
  }

  /** The state, names and links of each of {@code ids}, and the objects linked to it. */
  static Map<String, String> snapshot(InMemoryKmipServer s, java.util.Collection<String> ids) {
    Map<String, String> out = new TreeMap<>();
    for (String id : ids) out.put(id, TlsOwnershipTest.stateOf(s, id));
    return out;
  }

  /** The only object with a name that begins with {@code prefix} and ends with {@code suffix}. */
  static String named(InMemoryKmipServer s, String prefix, String suffix) {
    List<String> ids =
        s.ids().stream()
            .filter(
                id ->
                    s.names(id).stream().anyMatch(n -> n.startsWith(prefix) && n.endsWith(suffix)))
            .toList();
    assertEquals(1, ids.size(), prefix + "…" + suffix + ": " + ids);
    return ids.get(0);
  }

  /** A re-issue of {@code issued}: the same subject and key, another serial. */
  static X509Certificate reissue(String subject, TestPki.Issued issued, TestPki.Issued by) {
    try {
      TestX509.Builder b = TestX509.certificate(subject, issued.certificate().getPublicKey());
      X509Certificate c =
          (by == null ? b.selfSigned(issued.key()) : b.issuedBy(by.certificate(), by.key()))
              .ca()
              .build();
      assertFalse(Arrays.equals(c.getEncoded(), issued.certificate().getEncoded()));
      return c;
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  static List<String> ids(List<KeyHandle> handles) {
    return handles.stream().map(KeyHandle::id).toList();
  }

  static List<String> chainIds(TlsIdentityHandle h) {
    return ids(h.chain());
  }

  static void link(Kms kms, String from, Enums.LinkType type, String to) throws IOException {
    kms.protocol()
        .call(
            Requests.addAttribute()
                .uniqueIdentifier(from)
                .attribute(Attributes.link(type, to))
                .build());
  }
}
