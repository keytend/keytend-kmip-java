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

import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.IOException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * A TLS identity's call never changes an object other than the identity's own once another caller
 * has changed it. Generated: for each call (a registration, a renewal, a re-key, a call after an
 * earlier attempt stopped before its switch and the identity moved on, a call that loses its race),
 * at each of the call's changes in turn, another caller changes one property of one object the call
 * changes from there on: a link of each kind to an unrelated certificate, another name, an
 * activation, a revocation, or a link to it from an unrelated certificate. Either the call is
 * stopped dead there, with no reply, read back or clean-up, and then repeated ({@link
 * When#STOPPED}); or it goes on ({@link When#MEANWHILE}). Afterwards the call sends that object
 * nothing, and leaves it as the other caller left it. The call may finish (an object it is done
 * with, or one a repeat starts over without), or stop.
 *
 * <p>Left out is the call's own next change to that object, made by another caller: an activation
 * just before the call's own. Nothing a call can read tells the two apart. The other caller acts
 * between calls, or from the transport as the call's change goes out; nothing depends on timing.
 */
class TlsOwnershipTest {
  static final String NAME = TlsRepeatTest.NAME;

  /** The calls, on a server whose names are unique, except the NOT_UNIQUE ones. */
  enum Call {
    REGISTER,
    RENEW,
    REKEY,
    RENEW_NOT_UNIQUE,
    REKEY_NOT_UNIQUE,
    AFTER_ATTEMPT_RENEW,
    AFTER_ATTEMPT_REKEY,
    LOST_RENEW,
    LOST_REKEY;

    TlsRepeatTest.Op op() {
      return name().contains("REKEY") ? TlsRepeatTest.Op.REKEY : TlsRepeatTest.Op.RENEW;
    }

    boolean unique() {
      return !name().endsWith("NOT_UNIQUE");
    }
  }

  /** STOPPED: the call stops dead before its change, then is repeated; MEANWHILE: it goes on. */
  enum When {
    STOPPED,
    MEANWHILE
  }

  /** One property another caller changes: {@code what}, with the link kind for a link. */
  record Change(String what, LinkKind link) {
    static List<Change> all() {
      List<Change> out = new ArrayList<>();
      for (LinkKind k : LinkKind.values()) if (k != LinkKind.OTHER) out.add(new Change("link", k));
      out.add(new Change("name", null));
      out.add(new Change("activate", null));
      out.add(new Change("revoke", null));
      out.add(new Change("linked from", null));
      return out;
    }

    @Override
    public String toString() {
      return link == null ? what : what + " " + link;
    }
  }

  static Stream<Arguments> cases() {
    List<Arguments> out = new ArrayList<>();
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0))
      for (Call c : Call.values())
        for (When w : When.values())
          // A call that loses its race stops itself; a repeat starts over without its objects.
          if (!(w == When.STOPPED && c.name().startsWith("LOST"))) out.add(Arguments.of(v, c, w));
    return out.stream();
  }

  /** Thrown from the transport: the call stops dead, with no reply, read back or clean-up. */
  static final class Stop extends Error {
    private static final long serialVersionUID = 1L;

    Stop() {
      super("stopped", null, false, false);
    }
  }

  private static final Set<Integer> CHANGES =
      Set.of(
          Operation.REGISTER.code(),
          Operation.ADD_ATTRIBUTE.code(),
          Operation.MODIFY_ATTRIBUTE.code(),
          Operation.DELETE_ATTRIBUTE.code(),
          Operation.SET_ATTRIBUTE.code(),
          Operation.ACTIVATE.code(),
          Operation.REVOKE.code(),
          Operation.DEACTIVATE.code(),
          Operation.DESTROY.code(),
          Operation.RE_KEY.code(),
          Operation.CREATE_KEY_PAIR.code(),
          Operation.CERTIFY.code(),
          Operation.RE_CERTIFY.code());

  /**
   * A request that changes an object: its operation, its object (null for a Register), and every
   * text it carries (the objects it links to among them).
   */
  record Write(int operation, String target, Set<String> texts) {
    boolean mentions(String id) {
      return id.equals(target) || texts.contains(id);
    }
  }

  static Write write(Ttlv request) {
    Ttlv item = request.require(Tag.BATCH_ITEM);
    int op = item.require(Tag.OPERATION).intValue();
    if (!CHANGES.contains(op)) return null;
    Ttlv payload = item.child(Tag.REQUEST_PAYLOAD).orElse(null);
    String target =
        payload == null
            ? null
            : payload.child(Tag.UNIQUE_IDENTIFIER).map(Ttlv::textValue).orElse(null);
    Set<String> texts = new java.util.HashSet<>();
    if (payload != null) texts(payload, texts);
    return new Write(op, target, texts);
  }

  private static void texts(Ttlv t, Set<String> out) {
    if (t.type() == Ttlv.Type.STRUCTURE) for (Ttlv c : t.children()) texts(c, out);
    else if (t.type() == Ttlv.Type.TEXT_STRING
        || t.type() == Ttlv.Type.IDENTIFIER
        || t.type() == Ttlv.Type.REFERENCE) out.add(t.textValue());
  }

  /** One server, the identity registered, the call's client, and another caller. */
  static final class World implements AutoCloseable {
    final InMemoryKmipServer server;
    final TlsRepeatTest.Material m;
    final KeyPair strangerKey;
    final Call call;
    final Kms other;
    Kms kms;
    final List<Write> writes = new CopyOnWriteArrayList<>();
    final Set<String> identity = new LinkedHashSet<>();
    final TlsIdentityHandle start;
    volatile boolean counting;
    volatile int stopAt, hookAt;
    volatile Runnable hook;
    volatile Predicate<Ttlv> failIf = r -> false;
    volatile java.util.function.Consumer<Ttlv> race = r -> {};
    volatile TlsIdentityHandle won;

    World(KmipVersion version, Call call, TlsRepeatTest.Material m, KeyPair strangerKey) {
      this.m = m;
      this.call = call;
      this.strangerKey = strangerKey;
      server = InMemoryKmipServer.of(version).uniqueNames(call.unique());
      other = TlsIdentityTest.connect(server);
      kms = client();
      start = kms.tls().register(m.k1.getPrivate(), m.pki.chain(m.first)).named(NAME).register();
      own(start);
      String old = start.certificate().id();
      TlsRepeatTest.Op op = call.op();
      if (call.name().startsWith("AFTER_ATTEMPT")) {
        // The job's first attempt stops before its replacement link; the identity moves on.
        failIf = r -> TlsIdentityLifecycleTest.addsReplacementLink(r, old);
        assertThrows(PartialCompletionException.class, () -> m.job(start, op));
        failIf = r -> false;
        own(m.theirs(other.tls().identity(NAME).orElseThrow(), op));
      } else if (call.name().startsWith("LOST"))
        race =
            r -> {
              if (won == null && TlsIdentityLifecycleTest.addsReplacementLink(r, old)) {
                won = m.theirs(other.tls().identity(NAME).orElseThrow(), op);
                own(won);
              }
            };
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
      race.accept(r);
      if (failIf.test(r)) throw new IOException("stopped");
      Write w = counting ? write(r) : null;
      if (w != null) {
        int n = writes.size() + 1;
        Runnable h = hook;
        if (n == hookAt && h != null) {
          hook = null;
          h.run();
        }
        if (n == stopAt) throw new Stop();
        writes.add(w);
      }
      return server.exchange(r);
    }

    void own(TlsIdentityHandle h) {
      identity.add(h.certificate().id());
      identity.add(h.privateKey().id());
      for (KeyHandle c : h.chain()) identity.add(c.id());
    }

    /** The call, from the identity as it is now (a call that loses its race: from the start). */
    TlsIdentityHandle run() {
      TlsRepeatTest.Op op = call.op();
      return switch (call) {
        case REGISTER ->
            kms.tls()
                .register(m.k2.getPrivate(), m.mineRekeyed.chain(m.pki.ca))
                .named("other/node")
                .register();
        case LOST_RENEW, LOST_REKEY -> m.job(kms.tls().identity(NAME).orElseThrow(), op);
        default -> m.job(kms.tls().identity(NAME).orElseThrow(), op);
      };
    }

    /** Runs the call; a refusal or a stop is an outcome too. */
    void attempt() {
      try {
        run();
      } catch (KmsException | Stop ended) {
        // Finished or stopped: what it sent is in writes.
      }
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

    /** Another caller's change to {@code x}. */
    void change(String x, Change c) throws Exception {
      switch (c.what()) {
        case "link" -> TlsRepeatTest.link(other, x, c.link().protocolValue(), stranger(m.pki.root));
        case "name" -> other.keys().handle(x).addName("another-name-" + x);
        case "activate" -> other.keys().handle(x).activate();
        case "revoke" ->
            other
                .keys()
                .handle(x)
                .revoke(
                    RevocationReason.of(
                        RevocationReason.Kind.KEY_COMPROMISE, "another caller", null));
        case "linked from" ->
            // A certificate another caller registers takes it for its issuer, or for its key.
            TlsRepeatTest.link(
                other,
                other
                    .keys()
                    .register(m.pki.leaf("stranger", strangerKey).certificate())
                    .registerPreActive()
                    .id(),
                server.kind(x).orElse(null) == ObjectKind.PRIVATE_KEY
                    ? Enums.LinkType.PRIVATE_KEY_LINK
                    : Enums.LinkType.CERTIFICATE_LINK,
                x);
        default -> throw new IllegalArgumentException(c.what());
      }
    }

    private String stranger(TestPki.Issued issued) {
      return other.keys().register(issued.certificate()).registerPreActive().id();
    }

    String state(String x) {
      return stateOf(server, x);
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

  @ParameterizedTest
  @MethodSource("cases")
  void aCallNeverChangesAnObjectAfterAnotherCallerChangedIt(
      KmipVersion version, Call call, When when) throws Exception {
    TlsRepeatTest.Material m = new TlsRepeatTest.Material();
    KeyPair stranger = TestPki.ec();
    List<Write> ref;
    Set<String> identity;
    try (World w = new World(version, call, m, stranger)) {
      w.counting = true;
      w.attempt();
      ref = List.copyOf(w.writes);
      identity = Set.copyOf(w.identity);
    }
    assertTrue(ref.size() > 5, "writes: " + ref);
    List<String> failures = new ArrayList<>();
    int checked = 0;
    int last = when == When.STOPPED ? ref.size() + 1 : ref.size();
    for (int k = 1; k <= last; k++) {
      // The objects the call changes from its kth change on.
      Set<String> touched = new LinkedHashSet<>();
      for (Write w : ref.subList(k - 1, ref.size())) touched.addAll(objects(w, identity));
      if (when == When.STOPPED && k == ref.size() + 1)
        for (Write w : ref) touched.addAll(objects(w, identity));
      Write next = k <= ref.size() ? ref.get(k - 1) : null;
      for (String x : touched)
        for (Change c : Change.all()) {
          // The call's own next change to x, made by another caller: indistinguishable.
          if (c.what().equals("activate")
              && next != null
              && next.operation() == Operation.ACTIVATE.code()
              && x.equals(next.target())) continue;
          String when1 =
              call + " " + when + " at change " + k + " of " + ref.size() + ", " + x + ": " + c;
          String outcome =
              when == When.STOPPED
                  ? stopped(version, call, m, stranger, k, x, c)
                  : meanwhile(version, call, m, stranger, k, x, c);
          if (outcome == null) continue;
          checked++;
          if (!outcome.isEmpty()) failures.add(when1 + ": " + outcome);
        }
    }
    System.out.println(
        version + " " + call + " " + when + ": " + checked + " cases, " + ref.size() + " changes");
    assertTrue(checked > 0, "no case applied");
    assertEquals(
        List.of(),
        failures.subList(0, Math.min(20, failures.size())),
        failures.size() + " of " + checked + " cases");
  }

  /**
   * A renewal stops dead just after it activates its leaf, before it moves the name. Another caller
   * links the renewal's intermediate, the last of its chain, to the intermediate the identity had:
   * an object of the identity's own chain. The repeat finds the leaf current with a chain that is
   * not the one given, and stops with nothing changed. Once the link is taken off, as the refusal
   * says, a repeat finishes; it sends that intermediate nothing.
   */
  @ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anIssuerAnotherCallerLinkedIntoTheIdentitysChainIsLeftAsItIs(KmipVersion version)
      throws Exception {
    TlsRepeatTest.Material m = new TlsRepeatTest.Material();
    KeyPair stranger = TestPki.ec();
    List<Write> ref;
    String old, refLeaf;
    try (World w = new World(version, Call.RENEW, m, stranger)) {
      w.counting = true;
      w.attempt();
      ref = List.copyOf(w.writes);
      old = w.start.certificate().id();
      refLeaf = w.server.links(old, LinkKind.REPLACEMENT).get(0);
    }
    int afterActivation = 0;
    for (int i = 0; i < ref.size(); i++)
      if (ref.get(i).operation() == Operation.ACTIVATE.code()
          && refLeaf.equals(ref.get(i).target())) afterActivation = i + 2;
    assertTrue(afterActivation > 0, "the leaf's Activate: " + ref);
    try (World w = new World(version, Call.RENEW, m, stranger)) {
      w.counting = true;
      w.stopAt = afterActivation;
      w.attempt();
      w.stopAt = 0;
      String leaf = w.server.links(old, LinkKind.REPLACEMENT).get(0);
      String ca = w.server.links(leaf, LinkKind.CERTIFICATE).get(0);
      String kept = w.start.chain().get(1).id();
      assertEquals(List.of(), w.server.links(ca, LinkKind.CERTIFICATE));
      TlsRepeatTest.link(w.other, ca, Enums.LinkType.CERTIFICATE_LINK, kept);
      String before = w.state(ca);
      Map<String, String> was = new java.util.TreeMap<>();
      for (String id : w.server.ids()) was.put(id, w.state(id));
      w.reconnect();
      w.writes.clear();
      // The leaf's chain is not the one given any more: the repeat stops, with nothing changed.
      StateConflictException e = assertThrows(StateConflictException.class, w::run);
      assertEquals(StateConflictException.Conflict.LINEAGE, e.conflict(), e.getMessage());
      assertTrue(e.getMessage().contains("nothing was changed"), e.getMessage());
      assertEquals(List.of(), w.writes);
      for (String id : w.server.ids()) assertEquals(was.get(id), w.state(id), id);
      // Undone, as the refusal says, the repeat finishes, and sends that intermediate nothing.
      w.other.keys().handle(ca).removeLink("by hand", Enums.LinkType.CERTIFICATE_LINK, kept);
      before = w.state(ca);
      TlsIdentityHandle done = assertDoesNotThrow(w::run);
      assertEquals(leaf, done.certificate().id());
      assertEquals(List.of(NAME), w.server.names(leaf));
      assertEquals(java.util.Optional.of(KeyState.DEACTIVATED), w.server.state(old));
      assertEquals("", verdict(w, w.writes, ca, before, ""));
    }
  }

  /** {@code x}'s state, names and links, and the objects with a link to it. */
  static String stateOf(InMemoryKmipServer server, String x) {
    StringBuilder b = new StringBuilder();
    b.append(server.state(x).orElse(null)).append(' ').append(new TreeSet<>(server.names(x)));
    for (LinkKind kind : LinkKind.values()) {
      if (kind == LinkKind.OTHER) continue;
      if (!server.links(x, kind).isEmpty())
        b.append(' ').append(kind).append(new TreeSet<>(server.links(x, kind)));
      Set<String> to = new TreeSet<>();
      for (String id : server.ids()) if (server.links(id, kind).contains(x)) to.add(id);
      if (!to.isEmpty()) b.append(" from ").append(kind).append(to);
    }
    return b.toString();
  }

  /** The objects other than the identity's own that {@code w} changes or links to. */
  private static Set<String> objects(Write w, Set<String> identity) {
    Set<String> out = new LinkedHashSet<>();
    if (w.target() != null && !identity.contains(w.target())) out.add(w.target());
    for (String t : w.texts()) if (t.startsWith("mock-") && !identity.contains(t)) out.add(t);
    return out;
  }

  /**
   * The call stopped dead before its {@code k}th change, another caller's change {@code c} to
   * {@code x}, then a repeat: "" when the repeat sent {@code x} nothing and left it so; null when the
   * case does not apply ({@code x} does not exist yet, or the server refuses the change).
   */
  private static String stopped(
      KmipVersion version,
      Call call,
      TlsRepeatTest.Material m,
      KeyPair stranger,
      int k,
      String x,
      Change c) {
    try (World w = new World(version, call, m, stranger)) {
      w.counting = true;
      w.stopAt = k;
      w.attempt();
      w.stopAt = 0;
      if (!w.server.exists(x)) return null;
      try {
        w.change(x, c);
      } catch (Exception refused) {
        return null;
      }
      String before = w.state(x);
      w.reconnect();
      w.writes.clear();
      String thrown = "";
      try {
        w.run();
      } catch (KmsException e) {
        thrown = " (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")";
      }
      return verdict(w, w.writes, x, before, thrown);
    }
  }

  /**
   * Another caller's change {@code c} to {@code x} as the call's {@code k}th change goes out, the
   * call going on: "" when it sent {@code x} nothing after that change; null when the case does
   * not apply.
   */
  private static String meanwhile(
      KmipVersion version,
      Call call,
      TlsRepeatTest.Material m,
      KeyPair stranger,
      int k,
      String x,
      Change c) {
    try (World w = new World(version, call, m, stranger)) {
      String[] before = {null};
      boolean[] applies = {false};
      w.counting = true;
      w.hookAt = k;
      w.hook =
          () -> {
            if (!w.server.exists(x)) return;
            try {
              w.change(x, c);
            } catch (Exception refused) {
              return;
            }
            applies[0] = true;
            before[0] = w.state(x);
          };
      String thrown = "";
      try {
        w.run();
      } catch (KmsException e) {
        thrown = " (" + e.getClass().getSimpleName() + ": " + e.getMessage() + ")";
      }
      if (!applies[0]) return null;
      // The kth change was on its way: it went out after the other caller's change.
      boolean kthToX = w.writes.get(k - 1).mentions(x);
      return verdict(w, w.writes.subList(k, w.writes.size()), x, kthToX ? null : before[0], thrown);
    }
  }

  private static String verdict(
      World w, List<Write> after, String x, String before, String thrown) {
    List<Write> toX = after.stream().filter(a -> a.mentions(x)).toList();
    if (!toX.isEmpty())
      return "sent "
          + toX.stream().map(a -> Operation.fromCode(a.operation()) + " " + a.target()).toList()
          + thrown;
    if (before != null && !before.equals(w.state(x)))
      return "changed from " + before + " to " + w.state(x) + thrown;
    return "";
  }
}
