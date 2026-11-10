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
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** {@code KeyPairCreation.findOrCreate()} and {@code KeyRegistration.replace(old)}. */
class KeyPairsAndSecretsTest {
  static final String NAME = "signer", PUBLIC = "signer-public", SECRET = "db-password";

  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  InMemoryKmipServer server(KmipVersion version, boolean uniqueNames) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(uniqueNames);
    servers.add(server);
    return server;
  }

  Kms connect(KmsConfig.Builder builder) {
    Kms kms = Kms.connect(builder.build());
    clients.add(kms);
    return kms;
  }

  Kms connect(InMemoryKmipServer server) {
    return connect(server.configure());
  }

  /** A client whose every request first runs {@code before} with the request's operation code. */
  Kms intercepted(InMemoryKmipServer server, Function<Ttlv, Ttlv> before) {
    return connect(
        server
            .configure()
            .transport(
                e ->
                    request -> {
                      Ttlv answer = before.apply(request);
                      return answer != null ? answer : server.exchange(request);
                    }));
  }

  static KeyPairCreation signer(Kms kms) {
    return kms.keys()
        .createKeyPair(KeyPairSpec.ec(Curve.P_256))
        .named(NAME, PUBLIC)
        .privateUsages(KeyUsage.SIGN)
        .publicUsages(KeyUsage.VERIFY);
  }

  static List<String> ids(KeyPairHandle pair) {
    return List.of(pair.privateKey().id(), pair.publicKey().id());
  }

  static void assertActive(InMemoryKmipServer server, KeyPairHandle pair) {
    assertEquals(Optional.of(KeyState.ACTIVE), server.state(pair.privateKey().id()));
    assertEquals(Optional.of(KeyState.ACTIVE), server.state(pair.publicKey().id()));
  }

  // ---- KeyPairCreation.findOrCreate() ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void findOrCreateCreatesOnceAndFindsThePairInFourRequests(KmipVersion version) {
    InMemoryKmipServer server = server(version, false);
    KeyPairHandle created = signer(connect(server)).findOrCreate();
    assertActive(server, created);
    assertEquals(List.of(NAME), server.names(created.privateKey().id()));
    assertEquals(List.of(PUBLIC), server.names(created.publicKey().id()));
    // Another instance starting later finds it: two Locates and a Get Attributes of each key.
    Kms later = connect(server);
    int before = server.exchanges();
    KeyPairHandle found = signer(later).findOrCreate();
    assertEquals(4, server.exchanges() - before);
    assertEquals(ids(created), ids(found));
    assertEquals(2, server.ids().size());
    byte[] signature =
        found.privateKey().sign(SignatureSpec.ecdsa(Hash.SHA_256), new byte[] {1, 2, 3});
    assertEquals(
        VerifyResult.VALID,
        created
            .publicKey()
            .verify(SignatureSpec.ecdsa(Hash.SHA_256), new byte[] {1, 2, 3}, signature));
  }

  @Test
  void concurrentCallsThroughOneKmsMakeOnePair() throws Exception {
    InMemoryKmipServer server = server(KmipVersion.V2_1, false);
    AtomicInteger creates = new AtomicInteger();
    // The first Create Key Pair is held, so callers that do not wait for it would create their own.
    Kms kms =
        intercepted(
            server,
            request -> {
              if (Faults.operation(request) == Operation.CREATE_KEY_PAIR.code()
                  && creates.getAndIncrement() == 0) sleep(300);
              return null;
            });
    ExecutorService pool = Executors.newFixedThreadPool(6);
    try {
      CountDownLatch start = new CountDownLatch(1);
      List<Future<KeyPairHandle>> calls = new ArrayList<>();
      for (int i = 0; i < 6; i++)
        calls.add(
            pool.submit(
                () -> {
                  start.await();
                  return signer(kms).findOrCreate();
                }));
      start.countDown();
      Set<KeyPairHandle> pairs = new HashSet<>();
      for (Future<KeyPairHandle> f : calls) pairs.add(f.get(10, TimeUnit.SECONDS));
      assertEquals(1, pairs.size());
      assertEquals(1, creates.get());
      assertEquals(2, server.ids().size());
    } finally {
      pool.shutdownNow();
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aSecondInstanceRacingOnAUniqueNameServerGetsTheWinnersPair(KmipVersion version) {
    InMemoryKmipServer server = server(version, true);
    Kms other = connect(server);
    List<KeyPairHandle> winner = new ArrayList<>();
    // The other instance creates the pair between this one's lookup and its Create Key Pair.
    Kms kms =
        intercepted(
            server,
            request -> {
              if (Faults.operation(request) == Operation.CREATE_KEY_PAIR.code() && winner.isEmpty())
                winner.add(signer(other).create());
              return null;
            });
    KeyPairHandle mine = signer(kms).findOrCreate();
    assertEquals(ids(winner.get(0)), ids(mine));
    assertEquals(2, server.ids().size());
    assertActive(server, mine);
  }

  @Test
  void aSecondInstanceRacingOnADuplicateNameServerFollowsTheFirstPair() {
    InMemoryKmipServer server = server(KmipVersion.V2_1, false);
    Kms other = connect(server);
    List<KeyPairHandle> winner = new ArrayList<>();
    Kms kms =
        intercepted(
            server,
            request -> {
              if (Faults.operation(request) == Operation.CREATE_KEY_PAIR.code() && winner.isEmpty())
                winner.add(signer(other).create());
              return null;
            });
    KeyPairHandle mine = signer(kms).findOrCreate();
    assertEquals(ids(winner.get(0)), ids(mine));
    // The pair this instance created lost (its private key ranks second) and stays unused.
    List<String> leftovers = new ArrayList<>(server.ids());
    leftovers.removeAll(List.of(mine.privateKey().id(), mine.publicKey().id()));
    assertEquals(2, leftovers.size());
    for (String id : leftovers) assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(id));
  }

  @Test
  void aPairThatDoesNotMatchTheBuilderIsKeyMismatch() {
    InMemoryKmipServer server = server(KmipVersion.V2_1, false);
    Kms kms = connect(server);
    KeyPairHandle pair = signer(kms).create();
    List<KeyPairCreation> others =
        List.of(
            kms.keys()
                .createKeyPair(KeyPairSpec.ec(Curve.P_384))
                .named(NAME, PUBLIC)
                .privateUsages(KeyUsage.SIGN)
                .publicUsages(KeyUsage.VERIFY),
            kms.keys()
                .createKeyPair(KeyPairSpec.rsa(2048))
                .named(NAME, PUBLIC)
                .privateUsages(KeyUsage.SIGN)
                .publicUsages(KeyUsage.VERIFY),
            signer(kms).privateUsages(KeyUsage.DECRYPT),
            signer(kms).publicUsages(KeyUsage.ENCRYPT),
            kms.keys()
                .createKeyPair(KeyPairSpec.ec(Curve.P_256))
                .named(NAME, "other-public")
                .privateUsages(KeyUsage.SIGN)
                .publicUsages(KeyUsage.VERIFY));
    List<String> expected =
        List.of(
            "EC-P_384",
            "RSA-2048",
            "it lacks the usages [DECRYPT]",
            "lacks the usages [ENCRYPT]",
            "not named other-public");
    for (int i = 0; i < others.size(); i++) {
      KeyPairCreation builder = others.get(i);
      KeyMismatchException e = assertThrows(KeyMismatchException.class, builder::findOrCreate);
      assertTrue(e.getMessage().contains(pair.privateKey().id()), e.getMessage());
      assertTrue(
          e.getMessage().contains(expected.get(i)), expected.get(i) + " in " + e.getMessage());
    }
    assertEquals(2, server.ids().size(), "nothing was created");
  }

  @Test
  void aPreActivePairIsActivated() {
    InMemoryKmipServer server = server(KmipVersion.V1_4, false);
    Kms kms = connect(server);
    KeyPairHandle staged = signer(kms).createPreActive();
    KeyPairHandle found = signer(kms).findOrCreate();
    assertEquals(staged, found);
    assertActive(server, found);
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aNameWhoseOnlyPairIsRevokedIsRefused(KmipVersion version) {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer server = server(version, unique);
      Kms kms = connect(server);
      KeyPairHandle pair = signer(kms).findOrCreate();
      pair.revoke(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
      List<String> ids = server.ids();
      StateConflictException e =
          assertThrows(StateConflictException.class, () -> signer(connect(server)).findOrCreate());
      assertEquals(KmsException.Category.STATE, e.category());
      assertTrue(
          e.getMessage().contains(pair.privateKey().id() + "] is COMPROMISED"), e.getMessage());
      assertTrue(e.getMessage().contains("removeName"), e.getMessage());
      assertEquals(ids, server.ids(), "no pair was created");
      // Removing the names lets a new pair have them; a Deactivated (retired) pair is refused too.
      pair.privateKey().removeName(NAME);
      pair.publicKey().removeName(PUBLIC);
      KeyPairHandle retired = signer(kms).findOrCreate();
      assertNotEquals(pair, retired);
      assertActive(server, retired);
      retired.revoke(RevocationReason.cessationOfOperation("retired"));
      e = assertThrows(StateConflictException.class, () -> signer(kms).findOrCreate());
      assertTrue(
          e.getMessage().contains(retired.privateKey().id() + "] is DEACTIVATED"), e.getMessage());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aFailedActivationIsAPartialCompletionThatARepeatResumes(KmipVersion version) {
    InMemoryKmipServer server = server(version, false);
    Kms kms = connect(server);
    server.failNext(ServerOperation.ACTIVATE, Fault.SERVER_FAILURE);
    PartialCompletionException e =
        assertThrows(PartialCompletionException.class, () -> signer(kms).findOrCreate());
    KeyPairHandle created = e.createdPair().orElseThrow();
    assertEquals(List.of(created.privateKey(), created.publicKey()), e.created());
    assertTrue(e.getMessage().contains("repeat findOrCreate()"), e.getMessage());
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(created.privateKey().id()));
    KeyPairHandle resumed = signer(kms).findOrCreate();
    assertEquals(created, resumed);
    assertActive(server, resumed);
    assertEquals(2, server.ids().size());
  }

  @Test
  void findOrCreateNeedsTheNames() {
    Kms kms = connect(server(KmipVersion.V2_1, false));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            kms.keys()
                .createKeyPair(KeyPairSpec.ec(Curve.P_256))
                .privateUsages(KeyUsage.SIGN)
                .publicUsages(KeyUsage.VERIFY)
                .findOrCreate());
  }

  // ---- KeyRegistration.replace(old) ----

  static String value(KeyHandle h) {
    try (SecretData data = h.asSecretData()) {
      return new String(data.chars());
    }
  }

  static KeyHandle store(Kms kms, String password) {
    return kms.keys().registerSecret(password.toCharArray()).named(SECRET).register();
  }

  /**
   * Replaces {@code old}, which may have been stored through another {@code Kms} of the same server:
   * a handle of another {@code Kms} is refused, so it is named by identifier on this one.
   */
  static KeyHandle replace(Kms kms, KeyHandle old, String password) {
    return kms.keys()
        .registerSecret(password.toCharArray())
        .named(SECRET)
        .replace(kms.keys().handle(old.id()));
  }

  /** No object holds a temporary name. */
  static void noTemporaryName(InMemoryKmipServer server) {
    for (String id : server.ids())
      for (String n : server.names(id))
        assertFalse(n.contains(".replacing-"), id + " is named " + n);
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void replaceMovesTheNameOnBothKindsOfServer(KmipVersion version) {
    boolean legacy = version.protocolValue().major() == 1;
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer server = server(version, unique);
      Kms kms = connect(server);
      KeyHandle old = store(kms, "hunter2");
      int before = server.exchanges();
      KeyHandle replacement = replace(kms, old, "correct horse");
      // 8 requests; each name removal reads the index first on 1.x; on a server with unique names
      // a refused Add Attribute, and on 1.x the Locate that confirms the refusal.
      assertEquals(
          8 + (legacy ? 2 : 0) + (unique ? (legacy ? 2 : 1) : 0),
          server.exchanges() - before,
          version + " unique=" + unique);
      assertEquals(Optional.of(replacement), kms.keys().findByName(SECRET));
      assertEquals("correct horse", value(kms.keys().findByName(SECRET).orElseThrow()));
      assertEquals(Optional.of(KeyState.DEACTIVATED), server.state(old.id()));
      assertEquals(List.of(), server.names(old.id()));
      assertEquals(List.of(SECRET), server.names(replacement.id()));
      assertEquals(Optional.of(KeyState.ACTIVE), server.state(replacement.id()));
      assertEquals(2, server.ids().size());
      noTemporaryName(server);
      // A repeat is refused before anything is registered: the old secret is no longer the one
      // named.
      StateConflictException again =
          assertThrows(StateConflictException.class, () -> replace(kms, old, "x"));
      assertTrue(again.getMessage().contains("is not named " + SECRET), again.getMessage());
      assertEquals(Optional.of(KeyState.DEACTIVATED), again.observedState());
      assertEquals(2, server.ids().size());
    }
  }

  /**
   * An object that is not Active gives up its name the same way and keeps its state: Pre-Active (no
   * transition to Deactivated), Deactivated and Compromised. One request fewer than for an Active
   * object: there is nothing to deactivate.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void replaceTakesTheNameFromAnObjectThatIsNotActive(KmipVersion version) {
    boolean legacy = version.protocolValue().major() == 1;
    for (boolean unique : new boolean[] {false, true})
      for (KeyState state :
          new KeyState[] {KeyState.PRE_ACTIVE, KeyState.DEACTIVATED, KeyState.COMPROMISED}) {
        String context = version + " unique=" + unique + " " + state;
        InMemoryKmipServer server = server(version, unique);
        Kms kms = connect(server);
        KeyHandle old =
            state == KeyState.PRE_ACTIVE
                ? kms.keys()
                    .registerSecret("hunter2".toCharArray())
                    .named(SECRET)
                    .registerPreActive()
                : store(kms, "hunter2");
        if (state == KeyState.DEACTIVATED) old.deactivate();
        if (state == KeyState.COMPROMISED)
          old.revoke(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
        int before = server.exchanges();
        KeyHandle replacement = replace(kms, old, "correct horse");
        assertEquals(
            7 + (legacy ? 2 : 0) + (unique ? (legacy ? 2 : 1) : 0),
            server.exchanges() - before,
            context);
        assertEquals(Optional.of(state), server.state(old.id()), context + ": unchanged");
        assertEquals(List.of(), server.names(old.id()), context);
        assertEquals(List.of(SECRET), server.names(replacement.id()), context);
        assertEquals(Optional.of(KeyState.ACTIVE), server.state(replacement.id()), context);
        assertEquals(Optional.of(replacement), kms.keys().findByName(SECRET), context);
        assertEquals("correct horse", value(replacement), context);
        assertEquals(2, server.ids().size(), context);
        noTemporaryName(server);
        // The old object is no longer the one named: a repeat is refused, and registers nothing.
        StateConflictException again =
            assertThrows(StateConflictException.class, () -> replace(kms, old, "x"), context);
        assertEquals(Optional.of(state), again.observedState(), context);
        assertEquals(2, server.ids().size(), context);
      }
  }

  /**
   * A failure removing the name from an old object that is not Active leaves both named, and the
   * advice says the name finds the new, Active one and does not ask to deactivate the old one.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aFailedNameRemovalFromAnObjectNotActiveSaysWhichOneTheNameFinds(KmipVersion version) {
    InMemoryKmipServer server = server(version, false);
    Kms plain = connect(server);
    KeyHandle old = store(plain, "hunter2");
    old.deactivate();
    AtomicInteger removals = new AtomicInteger();
    Kms kms =
        intercepted(
            server,
            request ->
                Faults.operation(request) == Operation.DELETE_ATTRIBUTE.code()
                        && removals.incrementAndGet() == 2
                    ? Faults.failure(request, Enums.ResultReason.GENERAL_FAILURE, "injected")
                    : null);
    PartialCompletionException e =
        assertThrows(PartialCompletionException.class, () -> replace(kms, old, "new"));
    KeyHandle created = e.created().get(0);
    assertTrue(
        e.getMessage().contains("lookups of Active objects find " + created.id()), e.getMessage());
    assertTrue(e.getMessage().contains(old.id() + " is DEACTIVATED"), e.getMessage());
    assertFalse(e.getMessage().contains("and deactivate()"), e.getMessage());
    assertEquals(List.of(SECRET), server.names(old.id()));
    assertEquals(List.of(SECRET), server.names(created.id()));
    assertEquals(Optional.of(KeyState.DEACTIVATED), server.state(old.id()));
    assertEquals("new", value(plain.keys().findByName(SECRET).orElseThrow()));
  }

  /**
   * {@code replace(old, planned)} acts on the plan made from {@code planned}: when another caller
   * changed {@code old}'s state (here activated a Pre-Active object, or deactivated an Active one)
   * the call is refused before anything is registered, and {@code old} keeps its name and its new
   * state. In the state planned it replaces as {@code replace(old)} does.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void replaceBoundToAStateRefusesAnotherBeforeRegistering(KmipVersion version) {
    InMemoryKmipServer server = server(version, false);
    Kms kms = connect(server);
    KeyHandle staged =
        kms.keys().registerSecret("one".toCharArray()).named(SECRET).registerPreActive();
    KeyAttributes planned = staged.attributes();
    staged.activate(); // another caller, after the plan showed it Pre-Active
    int objects = server.ids().size();
    StateConflictException refused =
        assertThrows(
            StateConflictException.class,
            () ->
                kms.keys()
                    .registerSecret("two".toCharArray())
                    .named(SECRET)
                    .replace(staged, planned));
    assertEquals(Optional.of(KeyState.ACTIVE), refused.observedState());
    assertEquals(Optional.of(staged.id()), refused.objectId());
    assertTrue(refused.getMessage().contains("not PRE_ACTIVE"), refused.getMessage());
    assertTrue(refused.getMessage().endsWith("nothing was registered"), refused.getMessage());
    assertEquals(objects, server.ids().size(), "nothing was registered");
    assertEquals(List.of(SECRET), server.names(staged.id()));
    assertEquals(Optional.of(KeyState.ACTIVE), server.state(staged.id()), "not deactivated");

    KeyAttributes active = staged.attributes();
    staged.deactivate(); // and again, after a plan showed it Active
    assertThrows(
        StateConflictException.class,
        () -> kms.keys().registerSecret("two".toCharArray()).named(SECRET).replace(staged, active));
    assertEquals(objects, server.ids().size(), "nothing was registered");

    KeyHandle replacement =
        kms.keys()
            .registerSecret("two".toCharArray())
            .named(SECRET)
            .replace(staged, staged.attributes());
    assertEquals(List.of(SECRET), server.names(replacement.id()));
    assertEquals(Optional.of(KeyState.DEACTIVATED), server.state(staged.id()));
  }

  /**
   * The Activation Date is part of the plan too: a Pre-Active {@code old} with none stays
   * Pre-Active, one with a date is deactivated if that date makes it Active. Another caller adds a
   * date (or moves or removes it) while the plan waits, the state unchanged: the call is refused
   * before anything is registered, so the plan to leave {@code old} alone cannot become one that
   * deactivates it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void replaceBoundToAPlanRefusesAnotherActivationDateBeforeRegistering(KmipVersion version)
      throws java.io.IOException {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(RotationJobTest.START);
    InMemoryKmipServer server = server(version, false);
    server.clock(clock);
    Kms kms = connect(server);
    KeyHandle staged =
        kms.keys().registerSecret("one".toCharArray()).named(SECRET).registerPreActive();
    KeyAttributes planned = staged.attributes();
    assertEquals(Optional.empty(), planned.activationDate());
    java.time.Instant date = clock.now.plus(java.time.Duration.ofHours(1));
    activationDate(kms, staged.id(), date); // another caller, while the plan waits
    int objects = server.ids().size();
    StateConflictException refused =
        assertThrows(
            StateConflictException.class,
            () ->
                kms.keys()
                    .registerSecret("two".toCharArray())
                    .named(SECRET)
                    .replace(staged, planned));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), refused.observedState());
    assertTrue(
        refused
            .getMessage()
            .contains("has the Activation Date " + date + ", not no Activation Date"),
        refused.getMessage());
    assertTrue(refused.getMessage().endsWith("nothing was registered"), refused.getMessage());
    assertEquals(objects, server.ids().size(), "nothing was registered");
    assertEquals(List.of(SECRET), server.names(staged.id()));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(staged.id()));

    KeyAttributes dated = staged.attributes();
    activationDate(kms, staged.id(), date.plus(java.time.Duration.ofHours(1))); // moved
    assertThrows(
        StateConflictException.class,
        () -> kms.keys().registerSecret("two".toCharArray()).named(SECRET).replace(staged, dated));
    assertEquals(objects, server.ids().size(), "nothing was registered");

    // Removed: the plan "may activate, then deactivate it" must not become "leave it alone".
    KeyAttributes moved = staged.attributes();
    java.time.Instant last = moved.activationDate().orElseThrow();
    Ttlv lastDate = Ttlv.dateTime(dev.keytend.kmip.model.Tag.ACTIVATION_DATE, last);
    kms.protocol()
        .call(
            kms.protocolVersion().legacyAttributes()
                ? dev.keytend.kmip.client.Requests.deleteAttribute()
                    .uniqueIdentifier(staged.id())
                    .add(Ttlv.text(dev.keytend.kmip.model.Tag.ATTRIBUTE_NAME, "Activation Date"))
                    .add(Ttlv.integer(dev.keytend.kmip.model.Tag.ATTRIBUTE_INDEX, 0))
                    .build()
                : dev.keytend.kmip.client.Requests.deleteAttribute()
                    .uniqueIdentifier(staged.id())
                    .attribute(
                        dev.keytend.kmip.model.Attributes.attribute("Activation Date", lastDate))
                    .build());
    assertEquals(Optional.empty(), staged.attributes().activationDate(), "the date was removed");
    StateConflictException removed =
        assertThrows(
            StateConflictException.class,
            () ->
                kms.keys()
                    .registerSecret("two".toCharArray())
                    .named(SECRET)
                    .replace(staged, moved));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), removed.observedState());
    assertTrue(
        removed.getMessage().contains("has no Activation Date, not the Activation Date " + last),
        removed.getMessage());
    assertEquals(objects, server.ids().size(), "nothing was registered");
    assertEquals(List.of(SECRET), server.names(staged.id()));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(staged.id()));
  }

  /**
   * The plan is {@code old}'s: another object's attributes, or those of a state {@code replace}
   * refuses, are refused before anything is sent.
   */
  @Test
  void replaceBoundToAPlanRefusesAnotherObjectsOrANeverReplacedState() {
    InMemoryKmipServer server = server(KmipVersion.V2_1, true).destroyedObjectsKeepNames(true);
    Kms kms = connect(server);
    KeyHandle old = store(kms, "one");
    KeyHandle other = kms.keys().registerSecret("x".toCharArray()).named("other").register();
    IllegalArgumentException another =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                kms.keys()
                    .registerSecret("two".toCharArray())
                    .named(SECRET)
                    .replace(old, other.attributes()));
    assertTrue(another.getMessage().contains("attributes of " + other.id()), another.getMessage());
    other.deactivate();
    other.destroy();
    KeyAttributes destroyed = other.attributes();
    assertThrows(
        IllegalArgumentException.class,
        () ->
            kms.keys().registerSecret("y".toCharArray()).named("other").replace(other, destroyed));
  }

  /** Gives {@code id} an Activation Date, as another caller may (Modify Attribute). */
  private static void activationDate(Kms kms, String id, java.time.Instant date)
      throws java.io.IOException {
    boolean has = kms.keys().handle(id).attributes().activationDate().isPresent();
    Ttlv attribute =
        dev.keytend.kmip.model.Attributes.attribute(
            "Activation Date", Ttlv.dateTime(dev.keytend.kmip.model.Tag.ACTIVATION_DATE, date));
    kms.protocol()
        .call(
            has
                ? dev.keytend.kmip.client.Requests.modifyAttribute()
                    .uniqueIdentifier(id)
                    .attribute(attribute)
                    .build()
                : dev.keytend.kmip.client.Requests.addAttribute()
                    .uniqueIdentifier(id)
                    .attribute(attribute)
                    .build());
  }

  /**
   * A Pre-Active old object with an Activation Date becomes Active by itself. When its date passes
   * during the replacement (here while the new object is activated), it is Active once the name has
   * moved, and is deactivated as superseded; with a later date it stays Pre-Active, unnamed.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aPreActiveObjectActivatedByItsDateDuringTheReplacementIsDeactivated(KmipVersion version)
      throws java.io.IOException {
    for (boolean passes : new boolean[] {true, false}) {
      String context = version + (passes ? " the date passes" : " a later date");
      RotationJobTest.TestClock clock = new RotationJobTest.TestClock(RotationJobTest.START);
      InMemoryKmipServer server = server(version, false);
      server.clock(clock);
      Kms plain = connect(server);
      KeyHandle old =
          plain.keys().registerSecret("hunter2".toCharArray()).named(SECRET).registerPreActive();
      plain
          .protocol()
          .call(
              dev.keytend.kmip.client.Requests.addAttribute()
                  .uniqueIdentifier(old.id())
                  .attribute(
                      dev.keytend.kmip.model.Attributes.attribute(
                          "Activation Date",
                          Ttlv.dateTime(
                              dev.keytend.kmip.model.Tag.ACTIVATION_DATE,
                              clock.now.plus(java.time.Duration.ofHours(1)))))
                  .build());
      assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(old.id()), context);
      Kms kms =
          intercepted(
              server,
              request -> {
                if (passes && Faults.operation(request) == Operation.ACTIVATE.code())
                  clock.now = clock.now.plus(java.time.Duration.ofHours(2));
                return null;
              });
      KeyHandle replacement =
          kms.keys()
              .registerSecret("correct horse".toCharArray())
              .named(SECRET)
              .replace(kms.keys().handle(old.id()), old.attributes());
      assertEquals(
          Optional.of(passes ? KeyState.DEACTIVATED : KeyState.PRE_ACTIVE),
          server.state(old.id()),
          context);
      assertEquals(List.of(), server.names(old.id()), context);
      assertEquals(List.of(SECRET), server.names(replacement.id()), context);
      assertEquals(Optional.of(KeyState.ACTIVE), server.state(replacement.id()), context);
    }
  }

  /**
   * A Destroyed (or Destroyed Compromised) object is refused before anything is registered, even
   * while it keeps its name, and the refusal names its state.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void replaceRefusesADestroyedObject(KmipVersion version) {
    for (boolean compromised : new boolean[] {false, true}) {
      InMemoryKmipServer server = server(version, true).destroyedObjectsKeepNames(true);
      Kms kms = connect(server);
      KeyHandle old = store(kms, "hunter2");
      if (compromised)
        old.revoke(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
      else old.deactivate();
      old.destroy();
      KeyState destroyed = compromised ? KeyState.DESTROYED_COMPROMISED : KeyState.DESTROYED;
      assertEquals(Optional.of(destroyed), server.state(old.id()));
      int objects = server.ids().size();
      StateConflictException refused =
          assertThrows(StateConflictException.class, () -> replace(kms, old, "correct horse"));
      assertEquals(Optional.of(destroyed), refused.observedState());
      assertEquals(Optional.of(old.id()), refused.objectId());
      assertTrue(refused.getMessage().contains("is " + destroyed), refused.getMessage());
      assertTrue(refused.getMessage().contains("register()"), refused.getMessage());
      assertTrue(refused.getMessage().endsWith("nothing was registered"), refused.getMessage());
      assertEquals(objects, server.ids().size(), "nothing was registered");
      assertEquals(List.of(SECRET), server.names(old.id()), "the name stays where it was");
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aReaderFindsAnActiveSecretThroughoutTheReplacement(KmipVersion version) {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer server = server(version, unique);
      Kms reader = connect(server);
      List<String> seen = new CopyOnWriteArrayList<>();
      java.util.concurrent.atomic.AtomicBoolean armed =
          new java.util.concurrent.atomic.AtomicBoolean();
      // Before each request of the replacement, another instance reads the secret by name.
      Kms kms =
          intercepted(
              server,
              request -> {
                if (!armed.get()) return null;
                Optional<KeyHandle> found = reader.keys().findByName(SECRET);
                seen.add(found.map(KeyPairsAndSecretsTest::value).orElse("<none>"));
                return null;
              });
      KeyHandle old = store(connect(server), "hunter2");
      armed.set(true);
      replace(kms, old, "correct horse");
      seen.add(value(reader.keys().findByName(SECRET).orElseThrow()));
      assertEquals("hunter2", seen.get(0));
      assertEquals("correct horse", seen.get(seen.size() - 1));
      // KMIP cannot move a name atomically where names are unique: exactly one lookup, made between
      // the removal and the addition, finds nothing. Elsewhere, never.
      assertEquals(
          unique ? 1 : 0,
          Collections.frequency(seen, "<none>"),
          version + " unique=" + unique + ": " + seen);
    }
  }

  /** A step of the replacement made to fail, and what the failure must leave. */
  record Failing(String what, Operation op, int nth, boolean partial, boolean newHasName) {}

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void aFailureAtAnyStepLeavesTheNameOnAUsableSecret(KmipVersion version) {
    for (boolean unique : new boolean[] {false, true}) {
      List<Failing> steps =
          List.of(
              new Failing("register", Operation.REGISTER, 1, false, false),
              new Failing("temporary name removal", Operation.DELETE_ATTRIBUTE, 1, true, false),
              new Failing("activation", Operation.ACTIVATE, 1, true, false),
              // Where names are unique the first Add Attribute is refused anyway; fail the second.
              new Failing("name addition", Operation.ADD_ATTRIBUTE, unique ? 2 : 1, true, false),
              new Failing("name removal", Operation.DELETE_ATTRIBUTE, 2, true, !unique),
              new Failing("revocation", Operation.REVOKE, 1, true, true));
      for (Failing step : steps) {
        String context = version + " unique=" + unique + " " + step.what();
        InMemoryKmipServer server = server(version, unique);
        Kms plain = connect(server);
        KeyHandle old = store(plain, "hunter2");
        AtomicInteger matching = new AtomicInteger();
        Kms kms =
            intercepted(
                server,
                request ->
                    Faults.operation(request) == step.op().code()
                            && matching.incrementAndGet() == step.nth()
                        ? Faults.failure(request, Enums.ResultReason.GENERAL_FAILURE, "injected")
                        : null);
        KmsException e =
            assertThrows(KmsException.class, () -> replace(kms, old, "correct horse"), context);
        List<String> created = new ArrayList<>(server.ids());
        created.remove(old.id());
        if (step.partial()) {
          PartialCompletionException p =
              assertInstanceOf(PartialCompletionException.class, e, context);
          assertEquals(created, p.created().stream().map(KeyHandle::id).toList(), context);
          assertEquals("replace", p.operation(), context);
        } else {
          assertInstanceOf(ServerFailureException.class, e, context);
          assertEquals(List.of(), created, context);
        }
        // Whatever failed, the name finds a usable secret: the new one only once it has the name.
        KeyHandle found =
            plain
                .keys()
                .findByName(SECRET)
                .orElseThrow(() -> new AssertionError(context + ": no secret"));
        String expected =
            step.newHasName() && !step.what().equals("name removal") ? "correct horse" : null;
        if (expected != null) assertEquals(expected, value(found), context);
        else if (step.newHasName())
          assertTrue(List.of("hunter2", "correct horse").contains(value(found)), context);
        else assertEquals("hunter2", value(found), context);
        if (!step.newHasName()) {
          assertEquals(Optional.of(KeyState.ACTIVE), server.state(old.id()), context);
          assertEquals(List.of(SECRET), server.names(old.id()), context);
        }
        if (!step.what().equals("temporary name removal")) noTemporaryName(server);
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aFailedAdditionWhereNamesAreUniquePutsTheNameBack(KmipVersion version) {
    InMemoryKmipServer server = server(version, true);
    Kms plain = connect(server);
    KeyHandle old = store(plain, "hunter2");
    AtomicInteger adds = new AtomicInteger();
    Kms kms =
        intercepted(
            server,
            request ->
                Faults.operation(request) == Operation.ADD_ATTRIBUTE.code()
                        && adds.incrementAndGet() == 2
                    ? Faults.failure(request, Enums.ResultReason.GENERAL_FAILURE, "injected")
                    : null);
    PartialCompletionException e =
        assertThrows(PartialCompletionException.class, () -> replace(kms, old, "new"));
    assertTrue(e.getMessage().contains("put back on " + old.id()), e.getMessage());
    assertEquals(3, adds.get(), "the name was added back to the old secret");
    assertEquals(List.of(SECRET), server.names(old.id()));
    KeyHandle created = e.created().get(0);
    assertEquals(List.of(), server.names(created.id()));
    assertEquals(Optional.of(old), plain.keys().findByName(SECRET));
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void lostRepliesAreReconciled(KmipVersion version) {
    for (boolean unique : new boolean[] {false, true})
      for (ServerOperation op :
          List.of(ServerOperation.REGISTER, ServerOperation.ACTIVATE, ServerOperation.REVOKE)) {
        String context = version + " unique=" + unique + " " + op;
        InMemoryKmipServer server = server(version, unique);
        Kms kms = connect(server.configure().retryPolicy(RetryPolicy.none()));
        KeyHandle old = store(kms, "hunter2");
        server.failNext(op, Fault.REPLY_LOST);
        KeyHandle replacement = replace(kms, old, "correct horse");
        assertEquals(Optional.of(replacement), kms.keys().findByName(SECRET), context);
        assertEquals(Optional.of(KeyState.DEACTIVATED), server.state(old.id()), context);
        assertEquals(2, server.ids().size(), context);
        noTemporaryName(server);
      }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aStepWhoseCheckCannotBeReadIsReportedNotAssumed(KmipVersion version) {
    InMemoryKmipServer server = server(version, false);
    Kms plain = connect(server);
    KeyHandle old = store(plain, "hunter2");
    java.util.concurrent.atomic.AtomicBoolean deleteFailed =
        new java.util.concurrent.atomic.AtomicBoolean();
    // The temporary name's removal fails, and so does the Get Attributes that checks it.
    Kms kms =
        intercepted(
            server,
            request -> {
              int op = Faults.operation(request);
              if (op == Operation.DELETE_ATTRIBUTE.code()
                  && deleteFailed.compareAndSet(false, true))
                return Faults.failure(request, Enums.ResultReason.GENERAL_FAILURE, "injected");
              if (op == Operation.GET_ATTRIBUTES.code() && deleteFailed.get())
                return Faults.failure(request, Enums.ResultReason.GENERAL_FAILURE, "injected");
              return null;
            });
    PartialCompletionException e =
        assertThrows(PartialCompletionException.class, () -> replace(kms, old, "new"));
    assertTrue(e.getMessage().contains("removing the temporary name"), e.getMessage());
    assertEquals(Optional.of(old), plain.keys().findByName(SECRET));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(e.created().get(0).id()));
  }

  @Test
  void replaceChecksTheOldObjectBeforeRegistering() {
    InMemoryKmipServer server = server(KmipVersion.V2_1, false);
    Kms kms = connect(server);
    KeyHandle old = store(kms, "hunter2");
    KeyHandle unnamed = kms.keys().registerSecret("x".toCharArray()).register();
    KeyHandle key =
        kms.keys().createAes(256).named(SECRET + "-key").usages(KeyUsage.ENCRYPT).create();
    int objects = server.ids().size();
    StateConflictException notNamed =
        assertThrows(StateConflictException.class, () -> replace(kms, unnamed, "y"));
    assertTrue(notNamed.getMessage().contains("is not named " + SECRET), notNamed.getMessage());
    KeyMismatchException kind =
        assertThrows(
            KeyMismatchException.class,
            () -> kms.keys().registerSecret("y".toCharArray()).named(SECRET + "-key").replace(key));
    assertTrue(kind.getMessage().contains("SYMMETRIC_KEY"), kind.getMessage());
    assertThrows(
        IllegalArgumentException.class,
        () -> kms.keys().registerSecret("y".toCharArray()).replace(old));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            kms.keys().registerSecret("y".toCharArray()).named(SECRET).named("other").replace(old));
    assertEquals(objects, server.ids().size(), "nothing was registered");
    // Not only secrets: a registered key replaces another the same way.
    KeyHandle byok =
        kms.keys()
            .register(new SecretKeySpec(new byte[32], "AES"))
            .named("byok")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .register();
    KeyHandle next =
        kms.keys()
            .register(
                new SecretKeySpec(
                    new byte[] {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}, "AES"))
            .named("byok")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .replace(byok);
    assertEquals(Optional.of(next), kms.keys().findByName("byok"));
  }

  static void sleep(long millis) {
    try {
      Thread.sleep(millis);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
    }
  }
}
