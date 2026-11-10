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

import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.KmipTransport;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Predicate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Reconcile and replacement races: reconcile racing a rotation of its winner, a Compromised tip,
 * more replacements than the walk's fan-out, many replicas starting after a compromise, forged
 * siblings, planted pending names, concurrent reconciles and request counts; the advice each
 * failure gives leads somewhere.
 */
class ReconcileRaceTest {
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

  /** A client whose requests matching {@code when} run {@code hook} once, before being sent. */
  Kms hooked(InMemoryKmipServer server, Predicate<Ttlv> when, Runnable hook) {
    AtomicBoolean once = new AtomicBoolean();
    KmipTransport t =
        request -> {
          if (when.test(request) && once.compareAndSet(false, true)) hook.run();
          return server.exchange(request);
        };
    Kms kms = Kms.connect(server.configure().transport(e -> t).build());
    clients.add(kms);
    return kms;
  }

  static KeyCreation vault(Kms kms) {
    return kms.keys().createAes(256).named("vault").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
  }

  static String dump(InMemoryKmipServer s) {
    return ConcurrentReplacementChecks.describe(s);
  }

  // ---- reconcile concurrently with a rotation of its winner ----

  /**
   * Two tips A (named) and B. The operator's reconcile chooses A; while it links B into A, another
   * instance rotates A (A'). reconcile then deactivates every Active key of the tree but A, A'
   * included (a key NEWER than its winner), and moves A''s name back to A. Afterwards the only
   * newest key, A', is Deactivated: latest() returns a key that cannot seal, findByName returns A,
   * and a second reconcile refuses ("activate it, or replace it").
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void reconcileRacingARotationOfItsWinner(KmipVersion version) throws Exception {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
      Kms kms = connect(server), other = connect(server);
      KeyHandle old = vault(kms).findOrCreate();
      KeyHandle a = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, old.id()));
      KeyHandle b = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, old.id()));
      assertEquals(a, old.latest());
      String[] rotated = {null};
      byte[][] underRotated = {null};
      Kms operator =
          hooked(
              server,
              r -> RotationAndNameChoiceTest.isOperation(r, Operation.ADD_ATTRIBUTE),
              () -> {
                KeyHandle r = other.keys().handle(a.id()).rotate();
                rotated[0] = r.id();
                underRotated[0] = r.seal(PLAIN, AAD);
              });
      KeyHandle winner;
      try {
        winner = operator.keys().handle(old.id()).reconcile();
      } catch (PartialCompletionException resumable) {
        winner = kms.keys().reconcile("vault").orElseThrow(); // following its advice
      }
      String where = " unique=" + unique + dump(server);
      assertNotNull(rotated[0]);
      assertArrayEquals(PLAIN, kms.keys().open(KeyQuery.byName("vault"), underRotated[0], AAD));
      KeyHandle latest = kms.keys().handle(old.id()).latest();
      System.out.println(
          "ROTATION-RACE unique="
              + unique
              + " winner="
              + winner.id()
              + " rotated="
              + rotated[0]
              + " latest="
              + latest.id()
              + " findByName="
              + kms.keys().findByName("vault").map(KeyHandle::id)
              + where);
      try {
        System.out.println("ROTATION-RACE second reconcile: " + kms.keys().reconcile("vault"));
      } catch (KmsException e) {
        System.out.println("ROTATION-RACE second reconcile: " + e);
      }
      try {
        System.out.println(
            "ROTATION-RACE seal via latest(): " + KmsKeys.sealedKeyId(latest.seal(PLAIN, AAD)));
      } catch (KmsException e) {
        System.out.println("ROTATION-RACE seal via latest(): " + e);
      }
      assertEquals(
          Optional.of(KeyState.ACTIVE),
          server.state(latest.id()),
          "latest() returns an Active key" + where);
      assertEquals(
          kms.keys().findByName("vault").map(KeyHandle::id),
          Optional.of(latest.id()),
          "findByName agrees with latest()" + where);
    }
  }

  // ---- a Compromised tip, reconcile, then retirePredecessors ----

  /**
   * Two tips A (named, Active) and B; B is found compromised and revoked by the operator (not yet
   * replaced). reconcile() leaves B unjoined (by design: a Compromised tip is left for
   * replaceCompromised); retirePredecessors() from the winner then refused, saying only to
   * reconcile first, which changes nothing. The advice now says to replace the Compromised key
   * first, and following it completes.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aCompromisedTipAndRetirement(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle old = vault(kms).findOrCreate();
    KeyHandle a = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, old.id()));
    KeyHandle b = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, old.id()));
    byte[] underB = b.seal(PLAIN, AAD);
    b.revoke(RevocationReason.keyCompromise("leak", java.time.Instant.now()));
    KeyHandle w = kms.keys().reconcile("vault").orElseThrow();
    KeyHandle winner = w;
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> winner.retirePredecessors(RevocationReason.superseded("retire")));
    assertTrue(e.getMessage().contains("replace it first with replaceCompromised"), e.getMessage());
    // Following it: replace B, re-seal its records, reconcile, retire.
    KeyHandle bNext =
        b.replaceCompromised(RevocationReason.keyCompromise("leak", java.time.Instant.now()));
    byte[] moved = b.allowingCompromised().rewrapTo(bNext, underB, AAD);
    w = kms.keys().reconcile("vault").orElseThrow();
    byte[] moved2 = w.rewrap(moved, AAD);
    List<KeyHandle> retired = w.retirePredecessors(RevocationReason.superseded("retire"));
    assertTrue(
        retired.stream().map(KeyHandle::id).toList().containsAll(List.of(old.id(), b.id())),
        retired + dump(server));
    assertArrayEquals(PLAIN, w.open(moved2, AAD));
    assertTrue(w.isLatest());
  }

  // ---- at FANOUT + 1: many concurrent replacements ----

  static void attempt(String what, java.util.function.Supplier<Object> f, List<String> failures) {
    try {
      Object o = f.get();
      System.out.println("FANOUT ok   " + what + " -> " + o);
    } catch (RuntimeException e) {
      System.out.println("FANOUT FAIL " + what + " -> " + e);
      failures.add(what + ": " + e.getClass().getSimpleName());
    }
  }

  /**
   * 33 callers re-key one key at once (a deployment's startup findOrCreate().replacingCompromised(), which
   * the docs say may run on every instance). From the old key's handle all is well (FANOUT exempt at
   * the start); from any replacement's handle the walk reaches the old key, which is not the start.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void moreThanFanoutReplacements(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle old = vault(kms).findOrCreate();
    byte[] before = old.seal(PLAIN, AAD);
    List<KeyHandle> tips = new ArrayList<>();
    for (int i = 0; i < Lineage.FANOUT + 1; i++)
      tips.add(kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, old.id())));
    KeyHandle t0 = tips.get(0), t1 = tips.get(5);
    byte[] under1 = t1.seal(PLAIN, AAD);
    List<String> failures = new ArrayList<>();
    attempt("old.latest()", () -> old.latest().id(), failures);
    attempt("findByName", () -> kms.keys().findByName("vault").map(KeyHandle::id), failures);
    attempt("t1.latest()", () -> t1.latest().id(), failures);
    attempt("t1.isLatest()", () -> t1.isLatest(), failures);
    attempt("t0.open(record of t1)", () -> new String(t0.open(under1, AAD), UTF_8), failures);
    attempt("t1.open(record of old)", () -> new String(t1.open(before, AAD), UTF_8), failures);
    attempt(
        "open(name, record of t1)",
        () -> new String(kms.keys().open(KeyQuery.byName("vault"), under1, AAD), UTF_8),
        failures);
    attempt("reconcile(name)", () -> kms.keys().reconcile("vault").map(KeyHandle::id), failures);
    attempt("old.reconcile()", () -> old.reconcile().id(), failures);
    assertEquals(List.of(), failures);
  }

  /**
   * 48 replicas starting at once after a compromise, each with the documented startup
   * call findOrCreate().replacingCompromised() (the startup findOrCreate is not a single-actor
   * job). How many replacements of the Compromised key are made, and does every replica's key still
   * work through latest(), isLatest() and by name?
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void manyReplicasStartingAfterACompromise(KmipVersion version) throws Exception {
    int n = 48;
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms admin = connect(server);
    KeyHandle old = vault(admin).findOrCreate();
    byte[] before = old.seal(PLAIN, AAD);
    old.revoke(RevocationReason.keyCompromise("leak", java.time.Instant.now()));
    List<Kms> instances = new ArrayList<>();
    for (int i = 0; i < n; i++) {
      InMemoryKmipServer r = server.replica();
      KmipTransport slow =
          request -> {
            RotationAndNameChoiceTest.await(() -> Thread.sleep(10)); // a LAN round trip
            return r.exchange(request);
          };
      Kms k = Kms.connect(r.configure().transport(e -> slow).build());
      clients.add(k);
      instances.add(k);
    }
    java.util.concurrent.CyclicBarrier bar = new java.util.concurrent.CyclicBarrier(n);
    java.util.concurrent.ExecutorService pool =
        java.util.concurrent.Executors.newFixedThreadPool(n);
    List<java.util.concurrent.Future<String>> got = new ArrayList<>();
    for (Kms k : instances)
      got.add(
          pool.submit(
              () -> {
                bar.await();
                return vault(k).replacingCompromised().findOrCreate().id();
              }));
    Set<String> keys = new TreeSet<>();
    List<String> failures = new ArrayList<>();
    for (var f : got)
      try {
        keys.add(f.get());
      } catch (java.util.concurrent.ExecutionException e) {
        failures.add(String.valueOf(e.getCause()));
      }
    pool.shutdown();
    int replacements = server.links(old.id(), LinkKind.REPLACEMENT).size();
    System.out.println(
        "REPLICAS-AFTER-COMPROMISE "
            + version
            + " distinct keys returned="
            + keys.size()
            + " replacements of old="
            + replacements
            + " failures="
            + failures.size()
            + (failures.isEmpty() ? "" : " first=" + failures.get(0)));
    for (String id : keys) {
      KeyHandle h = admin.keys().handle(id);
      attempt("latest() from " + id, () -> h.latest().id(), failures);
      byte[] r;
      try {
        r = h.seal(PLAIN, AAD);
      } catch (KmsException e) {
        failures.add("seal " + id + ": " + e);
        continue;
      }
      attempt(
          "open by name record of " + id,
          () -> new String(admin.keys().open(KeyQuery.byName("vault"), r, AAD), UTF_8),
          failures);
    }
    attempt("reconcile(name)", () -> admin.keys().reconcile("vault").map(KeyHandle::id), failures);
    assertEquals(List.of(), failures);
  }

  // ---- forged siblings (the attacker touches only keys it created) ----

  static String snapshot(InMemoryKmipServer s, List<String> ids) {
    StringBuilder b = new StringBuilder();
    for (String i : ids)
      b.append(i)
          .append(' ')
          .append(s.state(i).orElse(null))
          .append(s.names(i))
          .append(s.links(i, LinkKind.REPLACEMENT))
          .append(s.links(i, LinkKind.REPLACED))
          .append(s.hasMaterial(i))
          .append(';');
    return b.toString();
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void forgedSiblings(KmipVersion version) throws Exception {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer server =
          InMemoryKmipServer.of(version).uniqueNames(unique).linkCardinality(false);
      Kms victim = connect(server), attacker = connect(server);
      KeyHandle r = vault(victim).findOrCreate();
      KeyHandle a = victim.keys().handle(RotationAndNameChoiceTest.reKey(victim, r.id()));
      KeyHandle b = victim.keys().handle(RotationAndNameChoiceTest.reKey(victim, r.id()));
      KeyHandle a2 = a.rotate();
      List<KeyHandle> mine = List.of(r, a, b, a2);
      List<byte[]> records = new ArrayList<>();
      for (KeyHandle k : List.of(a, b, a2)) records.add(k.seal(PLAIN, AAD));
      String chosenBefore = r.latest().id();
      Optional<String> namedBefore = victim.keys().findByName("vault").map(KeyHandle::id);
      // The attacker's keys: S1 named like the victim's where the server allows it, S2 a Re-key of
      // S1
      // (a confirmed step of its own), S3 with many and dangling links, S4 Active named, created
      // later.
      String nm = unique ? "theirs" : "vault";
      KeyHandle s1 =
          attacker
              .keys()
              .createAes(256)
              .named(nm)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
      KeyHandle s2 = attacker.keys().handle(RotationAndNameChoiceTest.reKey(attacker, s1.id()));
      KeyHandle s3 = KmsContractTest.aes(attacker, "s3");
      KeyHandle s4 = KmsContractTest.aes(attacker, unique ? "s4" : "vault");
      for (KeyHandle v : mine) {
        KmsContractTest.link(attacker, s1.id(), Enums.LinkType.REPLACED_OBJECT_LINK, v.id());
        KmsContractTest.link(attacker, s1.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, v.id());
        KmsContractTest.link(attacker, s2.id(), Enums.LinkType.REPLACED_OBJECT_LINK, v.id());
        KmsContractTest.link(attacker, s3.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, v.id());
        KmsContractTest.link(attacker, s4.id(), Enums.LinkType.REPLACED_OBJECT_LINK, v.id());
      }
      KmsContractTest.link(attacker, s3.id(), Enums.LinkType.REPLACED_OBJECT_LINK, s3.id());
      KmsContractTest.link(attacker, s3.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, s2.id());
      KmsContractTest.link(attacker, s2.id(), Enums.LinkType.REPLACED_OBJECT_LINK, s3.id());
      for (int i = 0; i < 5; i++)
        KmsContractTest.link(
            attacker, s3.id(), Enums.LinkType.REPLACED_OBJECT_LINK, "nonexistent-" + i);
      s1.setCustomAttribute(KeyHandle.pendingName("vault"), "vault");
      s4.setCustomAttribute(KeyHandle.pendingName("vault"), "vault");
      List<KeyHandle> theirs = List.of(s1, s2, s3, s4);
      List<String> theirIds = theirs.stream().map(KeyHandle::id).toList();
      String before = snapshot(server, theirIds);
      List<String> breaches = new ArrayList<>();
      for (KeyHandle s : theirs) {
        byte[] forged = s.seal(PLAIN, AAD);
        List<KeyHandle> through = new ArrayList<>(mine);
        through.add(r.latest());
        try {
          victim.keys().findByName("vault").ifPresent(through::add);
        } catch (StateConflictException dos) {
          // the duplicate-name DoS, pre-existing
        }
        for (KeyHandle k : through)
          try {
            victim.keys().handle(k.id()).open(forged, AAD);
            breaches.add(s.id() + "'s record opens through " + k.id());
          } catch (KmsException expected) {
          }
        try {
          victim.keys().open(KeyQuery.byName("vault"), forged, AAD);
          // documented on duplicate-name servers: the attacker's own lineage holds the name
          if (unique) breaches.add(s.id() + "'s record opens by KeyQuery.name");
        } catch (KmsException expected) {
        }
      }
      String where = " unique=" + unique + dump(server);
      if (!r.latest().id().equals(chosenBefore))
        breaches.add("latest() changed to " + r.latest().id());
      Optional<String> namedNow;
      try {
        namedNow = victim.keys().findByName("vault").map(KeyHandle::id);
        if (!namedNow.equals(namedBefore)
            && !(namedNow.isPresent() && !theirIds.contains(namedNow.get())))
          breaches.add("findByName changed to " + namedNow);
      } catch (KmsException e) {
        System.out.println(
            "FORGED-SIBLINGS findByName refuses (DoS) unique=" + unique + ": " + e.getMessage());
      }
      for (KeyHandle k : mine) {
        try {
          String w = victim.keys().handle(k.id()).reconcile().id();
          if (theirIds.contains(w)) breaches.add("reconcile from " + k.id() + " chose " + w);
        } catch (KmsException e) {
          breaches.add("reconcile from " + k.id() + " failed: " + e);
        }
      }
      try {
        Optional<String> w = victim.keys().reconcile("vault").map(KeyHandle::id);
        if (w.isPresent() && theirIds.contains(w.get())) breaches.add("reconcile(name) chose " + w);
      } catch (KmsException e) {
        System.out.println(
            "FORGED-SIBLINGS reconcile(name) refuses unique=" + unique + ": " + e.getMessage());
      }
      KeyHandle winner = r.latest();
      for (byte[] rec : records) assertArrayEquals(PLAIN, winner.open(rec, AAD));
      List<KeyHandle> retired = winner.retirePredecessors(RevocationReason.superseded("retire"));
      for (KeyHandle k : retired) if (theirIds.contains(k.id())) breaches.add("retired " + k.id());
      if (!snapshot(server, theirIds).equals(before))
        breaches.add("attacker keys changed: " + before + " -> " + snapshot(server, theirIds));
      System.out.println("FORGED-SIBLINGS unique=" + unique + " breaches=" + breaches);
      assertEquals(List.of(), breaches, where);
    }
  }

  /**
   * A stranger records a pending move of a name nobody holds yet onto its own key. The victim's
   * first startup findOrCreate refuses (as taking the free name could have blocked it anyway), and
   * its advice now says to check that the recording key is the caller's before reconcile(name),
   * which would give that key the name.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aPlantedPendingNameAndTheAdvice(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(true);
    Kms victim = connect(server), attacker = connect(server);
    KeyHandle s = KmsContractTest.aes(attacker, "theirs");
    s.removeName("theirs");
    s.setCustomAttribute(KeyHandle.pendingName("vault"), "vault");
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> vault(victim).findOrCreate());
    assertTrue(e.getMessage().contains("check that [" + s.id() + "] is yours"), e.getMessage());
    assertEquals(1, server.ids().size(), "nothing created");
  }

  // ---- two reconciles at once ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void twoReconcilesAtOnce(KmipVersion version) throws Exception {
    List<String> problems = new ArrayList<>();
    for (boolean unique : new boolean[] {false, true})
      for (Operation at :
          List.of(
              Operation.ADD_ATTRIBUTE,
              Operation.DELETE_ATTRIBUTE,
              Operation.REVOKE,
              Operation.GET_ATTRIBUTES,
              Operation.LOCATE))
        for (int skip = 0; skip < 4; skip++) {
          InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
          Kms kms = connect(server), other = connect(server);
          KeyHandle old = vault(kms).findOrCreate();
          List<KeyHandle> tips = new ArrayList<>();
          for (int i = 0; i < 3; i++)
            tips.add(kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, old.id())));
          tips.get(1).addName("alias");
          tips.get(2).addName("other");
          List<byte[]> recs = new ArrayList<>();
          for (KeyHandle t : tips) recs.add(t.seal(PLAIN, AAD));
          int[] seen = {0};
          String[] second = {null};
          int sk = skip;
          AtomicBoolean once = new AtomicBoolean();
          KmipTransport t =
              request -> {
                if (RotationAndNameChoiceTest.isOperation(request, at)
                    && seen[0]++ == sk
                    && once.compareAndSet(false, true))
                  try {
                    second[0] = other.keys().reconcile("vault").map(KeyHandle::id).orElse("none");
                  } catch (KmsException e) {
                    second[0] = e.toString();
                  }
                return server.exchange(request);
              };
          Kms first = Kms.connect(server.configure().transport(e -> t).build());
          clients.add(first);
          String one;
          try {
            one = first.keys().reconcile("vault").map(KeyHandle::id).orElse("none");
          } catch (KmsException e) {
            one = e.toString();
          }
          String label =
              "unique="
                  + unique
                  + " at="
                  + at
                  + "#"
                  + skip
                  + " first="
                  + one
                  + " second="
                  + second[0];
          try {
            KeyHandle chosen = kms.keys().handle(old.id()).latest();
            if (server.state(chosen.id()).orElse(null) != KeyState.ACTIVE)
              problems.add(label + ": latest() not Active");
            if (!kms.keys().findByName("vault").equals(Optional.of(chosen)))
              problems.add(label + ": findByName != latest()");
            long active =
                server.ids().stream()
                    .filter(i -> server.state(i).orElse(null) == KeyState.ACTIVE)
                    .count();
            if (active != 1) problems.add(label + ": " + active + " Active keys");
            for (String n : List.of("vault", "alias", "other"))
              if (!server.names(chosen.id()).contains(n))
                problems.add(label + ": chosen lacks " + n + dump(server));
            for (byte[] r : recs) chosen.open(r, AAD);
          } catch (KmsException e) {
            problems.add(label + ": " + e);
          }
        }
    problems.forEach(x -> System.out.println("TWO-RECONCILES " + x));
    assertEquals(List.of(), problems);
  }

  // ---- cost ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1"})
  void requestCounts(KmipVersion version) throws Exception {
    for (int n : new int[] {1, 8, 32, 64, 100}) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version);
      Kms kms = connect(server);
      KeyHandle k = vault(kms).findOrCreate();
      KeyHandle first = k;
      byte[] oldest = k.seal(PLAIN, AAD);
      for (int i = 0; i < n; i++)
        k = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, k.id()));
      byte[] newest = k.seal(PLAIN, AAD);
      KeyHandle tip = kms.keys().handle(k.id());
      StringBuilder b = new StringBuilder("PROBE-COST n=" + n);
      int e0 = server.exchanges();
      try {
        tip.isLatest();
      } catch (KmsException e) {
        b.append(" isLatest:" + e.getClass().getSimpleName());
      }
      int e1 = server.exchanges();
      try {
        tip.latest();
      } catch (KmsException e) {
        b.append(" latest:" + e.getClass().getSimpleName());
      }
      int e2 = server.exchanges();
      try {
        kms.keys().handle(tip.id()).open(newest, AAD);
      } catch (KmsException e) {
        b.append(" openNew:" + e.getClass().getSimpleName());
      }
      int e3 = server.exchanges();
      try {
        kms.keys().handle(tip.id()).open(oldest, AAD);
      } catch (KmsException e) {
        b.append(" openOld:" + e.getClass().getSimpleName());
      }
      int e4 = server.exchanges();
      try {
        kms.keys().open(KeyQuery.byName("vault"), oldest, AAD);
      } catch (KmsException e) {
        b.append(" openByName:" + e.getClass().getSimpleName());
      }
      int e5 = server.exchanges();
      try {
        kms.keys().findByName("vault");
      } catch (KmsException e) {
        b.append(" findByName:" + e.getClass().getSimpleName());
      }
      int e6 = server.exchanges();
      b.append(
          " isLatest="
              + (e1 - e0)
              + " latest="
              + (e2 - e1)
              + " openNewest="
              + (e3 - e2)
              + " openOldest="
              + (e4 - e3)
              + " openOldestByName="
              + (e5 - e4)
              + " findByName="
              + (e6 - e5));
      System.out.println(b);
    }
  }

  /** The FANOUT exemption for the walk's start: an attacker's key as the start of an own=true walk (reconcile(name)'s pending fallback). */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1"})
  void anOwnWalkFromAnAttackersKey(KmipVersion version) throws Exception {
    InMemoryKmipServer server =
        InMemoryKmipServer.of(version).uniqueNames(true).linkCardinality(false);
    Kms victim = connect(server), attacker = connect(server);
    KeyHandle s = KmsContractTest.aes(attacker, "theirs");
    for (int i = 0; i < 400; i++)
      KmsContractTest.link(attacker, s.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, "ghost-" + i);
    s.setCustomAttribute(KeyHandle.pendingName("vault"), "vault");
    int e0 = server.exchanges();
    String out;
    try {
      out = String.valueOf(victim.keys().reconcile("vault"));
    } catch (KmsException e) {
      out = e.toString();
    }
    int cost = server.exchanges() - e0;
    e0 = server.exchanges();
    try {
      victim.keys().handle(s.id()).latest();
    } catch (KmsException e) {
    }
    int cost2 = server.exchanges() - e0;
    System.out.println(
        "PROBE-FANOUT-START reconcile(name) cost="
            + cost
            + " -> "
            + out.substring(0, Math.min(200, out.length()))
            + "; handle(attacker).latest() cost="
            + cost2);
  }

  /**
   * Found by the extended Storm (seed 22, 2.1, unique names, replace, desc): a startup
   * findOrCreate().replacingCompromised() whose fallback name move stops after the name was taken off
   * the Compromised key (recorded as pending on the replacement) says to repeat findOrCreate(); the
   * repeat no longer finds the Compromised key by name and refuses (STATE), and keeps refusing until
   * an operator runs reconcile(name). Meanwhile no key has the name.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aStartupReplacementStoppedMidMoveDoesNotResume(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(true);
    Kms kms =
        Kms.connect(
            server
                .configure()
                .transport(e -> LineageTreeTest.refusingNameAddition(server, 2, true, false))
                .build());
    clients.add(kms);
    KeyHandle old = vault(kms).findOrCreate();
    byte[] rec = old.seal(PLAIN, AAD);
    old.revoke(RevocationReason.keyCompromise("leak", java.time.Instant.now()));
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> vault(kms).replacingCompromised().findOrCreate());
    System.out.println("PROBE-FOC first: " + e.getMessage() + dump(server));
    List<String> after = new ArrayList<>();
    for (int i = 0; i < 3; i++)
      try {
        after.add("ok " + vault(kms).replacingCompromised().findOrCreate().id());
        break;
      } catch (KmsException again) {
        after.add(again.getClass().getSimpleName() + ": " + again.getMessage());
      }
    after.forEach(x -> System.out.println("PROBE-FOC repeat: " + x));
    System.out.println("PROBE-FOC findByName during: " + kms.keys().findByName("vault"));
    try {
      kms.keys().open(KeyQuery.byName("vault"), rec, AAD);
      System.out.println("PROBE-FOC open by name during: ok");
    } catch (KmsException x) {
      System.out.println(
          "PROBE-FOC open by name during: "
              + x.getClass().getSimpleName()
              + " "
              + x.category()
              + ": "
              + x.getMessage());
    }
    assertTrue(
        after.get(after.size() - 1).startsWith("ok"),
        "following the advice (repeat findOrCreate) resumes" + dump(server));
  }

  /**
   * Found by the storm harness (seed 15, 1.4, desc): an instance's latest() that runs while the
   * operator's reconcile joins a tip into the winner reads the winner before its new Replaced
   * Object link and the tip after its new Replacement Object link, and fails with
   * ProtocolViolationException ("names the winner as its replacement, but none names it back"),
   * although the store is consistent at every moment (the winner's link is written first).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aReaderDuringReconcileSeesAProtocolViolation(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms admin = connect(server);
    KeyHandle old = vault(admin).findOrCreate();
    KeyHandle a = admin.keys().handle(RotationAndNameChoiceTest.reKey(admin, old.id()));
    KeyHandle b = admin.keys().handle(RotationAndNameChoiceTest.reKey(admin, old.id()));
    int[] reads = {0};
    String[] rec = {null};
    KmipTransport t =
        request -> {
          if (RotationAndNameChoiceTest.isOperation(request, Operation.GET_ATTRIBUTES)
              && ++reads[0] == 2)
            rec[0] =
                admin
                    .keys()
                    .handle(old.id())
                    .reconcile()
                    .id(); // the operator, elsewhere, at this moment
          return server.exchange(request);
        };
    Kms reader = Kms.connect(server.configure().transport(e -> t).build());
    clients.add(reader);
    String got;
    try {
      got = reader.keys().handle(a.id()).latest().id();
    } catch (KmsException e) {
      got = e.getClass().getSimpleName() + " (" + e.category() + "): " + e.getMessage();
    }
    System.out.println(
        "PROBE-READER reconcile=" + rec[0] + " concurrent latest() -> " + got + dump(server));
    assertEquals(a.id(), got);
  }

  /** KMIP 3.0 draft: two Re-keys of one key (concurrent rotation), then reading across branches, the choice, reconcile. */
  @org.junit.jupiter.api.Test
  void concurrentRotationOn30() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V3_0);
    Kms kms = connect(server);
    KeyHandle old =
        kms.keys()
            .createAes(256)
            .named("vault")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .findOrCreate();
    KeyHandle a = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, old.id()));
    KeyHandle b = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, old.id()));
    byte[] ra = a.seal(PLAIN, AAD), rb = b.seal(PLAIN, AAD);
    List<String> out = new ArrayList<>();
    attempt("b.open(ra)", () -> new String(b.open(ra, AAD), UTF_8), out);
    attempt("a.open(rb)", () -> new String(a.open(rb, AAD), UTF_8), out);
    attempt("latest", () -> old.latest().id() + "/" + a.latest().id() + "/" + b.latest().id(), out);
    attempt("findByName", () -> kms.keys().findByName("vault").map(KeyHandle::id), out);
    attempt(
        "open by name rb",
        () -> new String(kms.keys().open(KeyQuery.byName("vault"), rb, AAD), UTF_8),
        out);
    attempt("isLatest b", () -> b.isLatest(), out);
    // reconcile joins them with 3.0's own link attributes, and the lineage can then be retired
    // from the winner.
    KeyHandle winner = kms.keys().reconcile("vault").orElseThrow();
    assertArrayEquals(PLAIN, winner.open(ra, AAD));
    assertArrayEquals(PLAIN, winner.open(rb, AAD));
    attempt(
        "retire from the winner",
        () -> winner.retirePredecessors(RevocationReason.superseded("r")),
        out);
    System.out.println("PROBE-30 failures " + out + dump(server));
    assertEquals(List.of(), out);
  }
}
