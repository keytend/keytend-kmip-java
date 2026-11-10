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
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** The compromise-replacement and retirement regressions. */
class CompromiseReplacementTest {
  final List<Kms> clients = new ArrayList<>();
  final ExecutorService pool = Executors.newCachedThreadPool();

  @AfterEach
  void cleanUp() {
    pool.shutdownNow();
    clients.forEach(Kms::close);
  }

  Kms connect(
      InMemoryKmipServer server,
      java.util.function.UnaryOperator<dev.keytend.kmip.transport.KmipTransport> wrap) {
    Kms kms = Kms.connect(server.configure().transport(e -> wrap.apply(server)).build());
    clients.add(kms);
    return kms;
  }

  Kms connect(InMemoryKmipServer server) {
    return connect(server, t -> t);
  }

  static final byte[] PLAIN = "probe".getBytes(UTF_8), AAD = "aad".getBytes(UTF_8);
  static final Instant NOW = Instant.parse("2026-10-27T10:00:00Z");

  static KeyCreation vault(Kms kms) {
    return kms.keys().createAes(256).named("vault").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
  }

  static RevocationReason leaked() {
    return RevocationReason.keyCompromise("leaked", NOW);
  }

  static boolean is(Ttlv request, Operation op) {
    return request.children(Tag.BATCH_ITEM).stream()
        .anyMatch(i -> i.require(Tag.OPERATION).intValue() == op.code());
  }

  /** KMIP 1.4 and 2.1, duplicate and unique names. */
  static Stream<Arguments> versionsAndNames() {
    return Stream.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0)
        .flatMap(v -> Stream.of(Arguments.of(v, false), Arguments.of(v, true)));
  }

  /** A server whose objects all have one Initial Date, and whose later objects get lower identifiers when {@code descending}. */
  static InMemoryKmipServer server(KmipVersion version, boolean unique, boolean descending) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    server.clock(Clock.fixed(NOW, ZoneOffset.UTC));
    if (descending) {
      AtomicInteger n = new AtomicInteger(1000);
      server.identifierSource(() -> "k" + n.decrementAndGet());
    }
    return server;
  }

  /** Waits for {@code latch}, or fails the exchange (so a test cannot hang). */
  static void await(CountDownLatch latch, String what) throws java.io.IOException {
    try {
      if (!latch.await(10, TimeUnit.SECONDS)) throw new java.io.IOException(what);
    } catch (InterruptedException e) {
      throw new java.io.InterruptedIOException(what);
    }
  }

  /** Waits at {@code barrier}, or fails the exchange (so a test cannot hang). */
  static void await(CyclicBarrier barrier) throws java.io.IOException {
    try {
      barrier.await(10, TimeUnit.SECONDS);
    } catch (InterruptedException | BrokenBarrierException | TimeoutException e) {
      throw new java.io.IOException("barrier: " + e, e);
    }
  }

  /**
   * A transport that holds the first request of {@code op} until the other instance reaches its own
   * (so both passed every check before), and holds its reply until the other's was processed too.
   */
  static dev.keytend.kmip.transport.KmipTransport meeting(
      InMemoryKmipServer server,
      Operation op,
      CyclicBarrier before,
      CyclicBarrier after,
      Runnable beforeExchange) {
    AtomicBoolean done = new AtomicBoolean();
    return request -> {
      boolean meet = is(request, op) && done.compareAndSet(false, true);
      if (meet) {
        await(before);
        beforeExchange.run();
      }
      Ttlv response = server.exchange(request);
      if (meet) await(after);
      return response;
    };
  }

  Object[] race(Callable<String> a, Callable<String> b) throws Exception {
    Future<String> fa = pool.submit(a), fb = pool.submit(b);
    Object[] out = new Object[2];
    for (int i = 0; i < 2; i++)
      try {
        out[i] = (i == 0 ? fa : fb).get(30, TimeUnit.SECONDS);
      } catch (ExecutionException e) {
        out[i] = e.getCause();
      }
    return out;
  }

  /**
   * What instances that replaced {@code old} at once must leave. That is not necessarily one
   * replacement: each caller keeps its own, nothing of another caller's is revoked, the
   * same key is chosen everywhere, every record opens everywhere, and {@code reconcile} leaves one
   * ({@link ConcurrentReplacementChecks#assertSafe}).
   */
  void assertOneReplacement(
      InMemoryKmipServer server, Kms setup, KeyHandle old, Object[] results, List<Kms> instances) {
    ConcurrentReplacementChecks.assertSafe(
        server, setup, old, Arrays.asList(results), instances, "vault", false);
  }

  /** A key a lost findOrCreate race left: Pre-Active, unlinked. */
  static boolean leftover(InMemoryKmipServer server, String id) {
    return server.state(id).orElse(null) == KeyState.PRE_ACTIVE
        && server.links(id, LinkKind.REPLACEMENT).isEmpty()
        && server.links(id, LinkKind.REPLACED).isEmpty();
  }

  static String describe(InMemoryKmipServer server) {
    StringBuilder b = new StringBuilder();
    for (String i : server.ids())
      b.append("\n  ")
          .append(i)
          .append(' ')
          .append(server.state(i).orElse(null))
          .append(" names=")
          .append(server.names(i))
          .append(" replacement=")
          .append(server.links(i, LinkKind.REPLACEMENT))
          .append(" replaced=")
          .append(server.links(i, LinkKind.REPLACED));
    return b.toString();
  }

  // ---- one winner rule for every replacement path ----

  /**
   * Two instances re-key one Compromised key in the same second (a fixed clock), both
   * after passing every check. Neither yields (a rule such as "created no later than" would make
   * both throw PartialCompletionException, one advising to destroy the key latest() and findByName
   * return): each returns its own replacement and neither touches the other's; the key
   * Re-key gave the name is the one everyone chooses (Active, then named), with ascending and
   * descending identifiers.
   */
  @ParameterizedTest
  @MethodSource("versionsAndNames")
  void concurrentReKeysInOneSecondEndWithOneReplacement(KmipVersion version, boolean unique)
      throws Exception {
    for (boolean descending : new boolean[] {false, true}) {
      InMemoryKmipServer server = server(version, unique, descending);
      Kms setup = connect(server);
      KeyHandle old = vault(setup).findOrCreate();
      byte[] before = old.seal(PLAIN, AAD);
      old.revoke(leaked());
      CyclicBarrier reKey = new CyclicBarrier(2), reKeyed = new CyclicBarrier(2);
      Kms a =
          connect(
              server.replica(),
              s -> meeting((InMemoryKmipServer) s, Operation.RE_KEY, reKey, reKeyed, () -> {}));
      Kms b =
          connect(
              server.replica(),
              s -> meeting((InMemoryKmipServer) s, Operation.RE_KEY, reKey, reKeyed, () -> {}));
      Object[] results =
          race(
              () -> a.keys().handle(old.id()).replaceCompromised(leaked()).id(),
              () -> b.keys().handle(old.id()).replaceCompromised(leaked()).id());
      assertNotEquals(
          results[0], results[1], "each caller returns its own replacement: " + describe(server));
      String named =
          server.links(old.id(), LinkKind.REPLACEMENT).stream()
              .filter(i -> server.names(i).contains("vault"))
              .findFirst()
              .orElseThrow();
      assertEquals(
          named,
          setup.keys().handle(old.id()).latest().id(),
          "the replacement with the name is chosen");
      assertOneReplacement(server, setup, old, results, List.of(a, b));
      assertArrayEquals(PLAIN, a.keys().handle(old.id()).allowingCompromised().open(before, AAD));
    }
  }

  /**
   * Plain rotate() at once, same second: no PartialCompletionException. Each caller returns its
   * own replacement, safely ({@link ConcurrentReplacementChecks#assertSafe}).
   */
  @ParameterizedTest
  @MethodSource("versionsAndNames")
  void concurrentRotationsInOneSecondReturnTheSameKey(KmipVersion version, boolean unique)
      throws Exception {
    for (boolean descending : new boolean[] {false, true}) {
      InMemoryKmipServer server = server(version, unique, descending);
      Kms setup = connect(server);
      KeyHandle old = vault(setup).findOrCreate();
      CyclicBarrier reKey = new CyclicBarrier(2), reKeyed = new CyclicBarrier(2);
      Kms a =
          connect(
              server.replica(),
              s -> meeting((InMemoryKmipServer) s, Operation.RE_KEY, reKey, reKeyed, () -> {}));
      Kms b =
          connect(
              server.replica(),
              s -> meeting((InMemoryKmipServer) s, Operation.RE_KEY, reKey, reKeyed, () -> {}));
      Object[] results =
          race(
              () -> a.keys().handle(old.id()).rotate().id(),
              () -> b.keys().handle(old.id()).rotate().id());
      // The old key stays Active after a rotation: count it out.
      assertOneReplacement(server, setup, old, results, List.of(a, b));
    }
  }

  /**
   * The server refuses to re-key a Compromised key, so both instances create a successor
   * and link it by hand at the same moment. Neither instance's records may be BAD_DATA
   * through the other's key: both keys stay Active in one tree, so every record
   * opens through either, and reconcile joins them.
   */
  @ParameterizedTest
  @MethodSource("versionsAndNames")
  void concurrentFallbackReplacementsEndWithOneReplacement(KmipVersion version, boolean unique)
      throws Exception {
    for (boolean descending : new boolean[] {false, true}) {
      InMemoryKmipServer server = server(version, unique, descending);
      Kms setup = connect(server);
      KeyHandle old = vault(setup).findOrCreate();
      old.revoke(leaked());
      CyclicBarrier create = new CyclicBarrier(2), created = new CyclicBarrier(2);
      InMemoryKmipServer ra = server.replica(), rb = server.replica();
      Kms a =
          connect(
              ra, s -> refusingReKey(ra, meeting(ra, Operation.CREATE, create, created, () -> {})));
      Kms b =
          connect(
              rb, s -> refusingReKey(rb, meeting(rb, Operation.CREATE, create, created, () -> {})));
      Object[] results =
          race(
              () -> a.keys().handle(old.id()).replaceCompromised(leaked()).id(),
              () -> b.keys().handle(old.id()).replaceCompromised(leaked()).id());
      assertOneReplacement(server, setup, old, results, List.of(a, b));
    }
  }

  /** A transport to {@code server} through {@code next} whose Re-key requests the server refuses. */
  static dev.keytend.kmip.transport.KmipTransport refusingReKey(
      InMemoryKmipServer server, dev.keytend.kmip.transport.KmipTransport next) {
    return request -> {
      if (is(request, Operation.RE_KEY)) server.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
      return next.exchange(request);
    };
  }

  /**
   * Instance B passes its checks first but its Re-key is held; instance A re-keys, finds only
   * its own replacement, and while A activates it, B's Re-key lands in the same second, with a
   * replacement that sorts first (descending identifiers). Neither gives way: both keep their own,
   * and everyone chooses the same one. The server gives a replacement fresh dates, so A's is
   * Pre-Active and A activates it (with the copied dates of the default it would be Active, A would
   * never send the Activate this race holds, and B's Re-key would only land after A returned).
   */
  @ParameterizedTest
  @MethodSource("versionsAndNames")
  void aWinnerChecksAgainAfterActivating(KmipVersion version, boolean unique) throws Exception {
    InMemoryKmipServer server = server(version, unique, true).freshDatesOnReKey(true);
    Kms setup = connect(server);
    KeyHandle old = vault(setup).findOrCreate();
    old.revoke(leaked());
    CountDownLatch bReady = new CountDownLatch(1),
        aActivating = new CountDownLatch(1),
        bReKeyed = new CountDownLatch(1);
    InMemoryKmipServer ra = server.replica(), rb = server.replica();
    Kms b =
        connect(
            rb,
            s ->
                request -> {
                  boolean reKey = is(request, Operation.RE_KEY);
                  if (reKey) {
                    bReady.countDown();
                    await(aActivating, "A never activated");
                  }
                  Ttlv response = rb.exchange(request);
                  if (reKey) bReKeyed.countDown();
                  return response;
                });
    AtomicBoolean once = new AtomicBoolean();
    Kms a =
        connect(
            ra,
            s ->
                request -> {
                  if (is(request, Operation.ACTIVATE) && once.compareAndSet(false, true)) {
                    aActivating.countDown();
                    await(bReKeyed, "B never re-keyed");
                  }
                  return ra.exchange(request);
                });
    Future<String> fb =
        pool.submit(() -> b.keys().handle(old.id()).replaceCompromised(leaked()).id());
    assertTrue(bReady.await(10, TimeUnit.SECONDS));
    Future<String> fa =
        pool.submit(() -> a.keys().handle(old.id()).replaceCompromised(leaked()).id());
    Object[] results = new Object[2];
    for (int i = 0; i < 2; i++)
      try {
        results[i] = (i == 0 ? fa : fb).get(30, TimeUnit.SECONDS);
      } catch (ExecutionException e) {
        results[i] = e.getCause();
      }
    // The race ran as described: B's Re-key was held until A activated, and landed before A's
    // Activate was answered.
    assertEquals(0, aActivating.getCount(), "A activated its replacement");
    assertEquals(0, bReKeyed.getCount(), "B re-keyed while A activated");
    assertOneReplacement(server, setup, old, results, List.of(a, b));
  }

  /**
   * The same through findOrCreate().replacingCompromised(), which the guide recommends at startup:
   * three instances at once, five times per version and kind of server. The runs never fail, and
   * never lose or strand a record.
   */
  @ParameterizedTest
  @MethodSource("versionsAndNames")
  void concurrentStartupsReplacingCompromisedConverge(KmipVersion version, boolean unique)
      throws Exception {
    for (int rep = 0; rep < 5; rep++) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
      Kms setup = connect(server);
      KeyHandle old = vault(setup).findOrCreate();
      old.revoke(leaked());
      List<Kms> instances = new ArrayList<>();
      for (int i = 0; i < 3; i++) instances.add(connect(server.replica()));
      CyclicBarrier start = new CyclicBarrier(3);
      List<Future<String>> futures = new ArrayList<>();
      for (Kms k : instances)
        futures.add(
            pool.submit(
                () -> {
                  start.await(10, TimeUnit.SECONDS);
                  return vault(k).replacingCompromised().findOrCreate().id();
                }));
      Object[] results = new Object[3];
      for (int i = 0; i < 3; i++)
        try {
          results[i] = futures.get(i).get(30, TimeUnit.SECONDS);
        } catch (ExecutionException e) {
          results[i] = e.getCause();
        }
      assertOneReplacement(server, setup, old, results, instances);
    }
  }

  // ---- a lost link reply is settled before success is reported ----

  /**
   * Re-key refused, so the replacement is linked by hand; the {@code which}-th Add Attribute (1:
   * the old key's link, 2: the replacement's) takes effect but its reply is lost. Before, the lost
   * reply of the first was taken for a refusal: success with a one-sided link, after which latest()
   * and a repeat threw ProtocolViolationException.
   */
  @ParameterizedTest
  @MethodSource("versionsAndNames")
  void aLostLinkReplyIsReadBackBeforeSuccess(KmipVersion version, boolean unique) {
    for (int which = 1; which <= 2; which++) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
      AtomicInteger adds = new AtomicInteger();
      int lose = which;
      Kms kms =
          connect(
              server,
              s ->
                  refusingReKey(
                      server,
                      request -> {
                        if (is(request, Operation.ADD_ATTRIBUTE) && adds.incrementAndGet() == lose)
                          server.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.REPLY_LOST);
                        return server.exchange(request);
                      }));
      KeyHandle old = vault(kms).create();
      KeyHandle replacement = old.replaceCompromised(leaked());
      assertEquals(
          List.of(replacement.id()),
          server.links(old.id(), LinkKind.REPLACEMENT),
          "lost reply " + which);
      assertEquals(List.of(old.id()), server.links(replacement.id(), LinkKind.REPLACED));
      assertEquals(replacement.id(), old.latest().id());
      int before = server.ids().size();
      assertEquals(replacement.id(), old.replaceCompromised(leaked()).id(), "a repeat resumes");
      assertEquals(before, server.ids().size(), "and makes nothing");
      assertEquals(
          Optional.of(replacement.id()), kms.keys().findByName("vault").map(KeyHandle::id));
    }
  }

  /**
   * The old key's link had an unknown outcome and the key cannot be read to settle it, or the link
   * was not sent at all: a PartialCompletionException naming the replacement and how to finish, not
   * an unlinked replacement reported as success (which a repeat would replace again), and no
   * advice to destroy anything.
   */
  @ParameterizedTest
  @MethodSource("versionsAndNames")
  void aLinkThatCannotBeSettledIsAPartialCompletion(KmipVersion version, boolean unique) {
    for (Fault fault : new Fault[] {Fault.REPLY_LOST, Fault.UNREACHABLE}) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
      AtomicBoolean armed = new AtomicBoolean();
      Kms kms =
          connect(
              server,
              s ->
                  refusingReKey(
                      server,
                      request -> {
                        if (is(request, Operation.ADD_ATTRIBUTE)
                            && armed.compareAndSet(false, true)) {
                          server.failNext(ServerOperation.ADD_ATTRIBUTE, fault);
                          server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
                        }
                        return server.exchange(request);
                      }));
      KeyHandle old = vault(kms).create();
      PartialCompletionException e =
          assertThrows(
              PartialCompletionException.class,
              () -> old.replaceCompromised(leaked()),
              fault.toString());
      String made = e.created().get(0).id();
      assertNotEquals(old.id(), made);
      assertTrue(e.getMessage().contains("add the links by hand"), e.getMessage());
      assertFalse(e.getMessage().contains("destroy"), e.getMessage());
      // The replacement's link comes first, so the old key's chain is untouched either way.
      assertEquals(List.of(), server.links(old.id(), LinkKind.REPLACEMENT));
      assertEquals(
          fault == Fault.REPLY_LOST ? List.of(old.id()) : List.of(),
          server.links(made, LinkKind.REPLACED));
    }
  }

  // ---- retirement never destroys objects outside the confirmed chain ----

  /** A clock that moves ten seconds on each reading, so every object has its own Initial Date. */
  static Clock ticking() {
    java.util.concurrent.atomic.AtomicLong seconds = new java.util.concurrent.atomic.AtomicLong();
    return new Clock() {
      @Override
      public java.time.ZoneId getZone() {
        return ZoneOffset.UTC;
      }

      @Override
      public Clock withZone(java.time.ZoneId zone) {
        return this;
      }

      @Override
      public Instant instant() {
        return NOW.plusSeconds(seconds.getAndAdd(10));
      }
    };
  }

  /**
   * A legitimate Pre-Active secret with the key's name, created earlier, must not be
   * destroyed by retirePredecessors (a never-activated, unlinked, older object with the name is
   * not a findOrCreate leftover). Nothing outside the confirmed chain is destroyed; the
   * secret, a same-name HMAC key, a same-name AES-128 key and a same-name AES-256 key all survive,
   * and leftovers() lists only the last, which matches the key's kind, algorithm and length.
   */
  @ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void retirementNeverDestroysObjectsOutsideTheChain(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    server.clock(ticking());
    Kms kms = connect(server);
    List<KeyHandle> strangers = new ArrayList<>();
    KeyHandle secret =
        kms.keys().registerSecret("abc".toCharArray()).named("vault").registerPreActive();
    KeyHandle hmac =
        kms.keys()
            .createSymmetric(Algorithm.HMAC_SHA256, 256)
            .named("vault")
            .usages(KeyUsage.MAC_GENERATE)
            .createPreActive();
    KeyHandle aes128 =
        kms.keys()
            .createAes(128)
            .named("vault")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .createPreActive();
    KeyHandle leftover = vault(kms).createPreActive();
    strangers.addAll(List.of(secret, hmac, aes128, leftover));
    KeyHandle a = vault(kms).create();
    KeyHandle b = a.rotate();
    List<KeyHandle> retired = b.retirePredecessors(RevocationReason.superseded("rotated"));
    assertEquals(List.of(a.id()), retired.stream().map(KeyHandle::id).toList());
    for (KeyHandle k : strangers)
      assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(k.id()), k + " is not destroyed");
    assertTrue(server.hasMaterial(secret.id()));
    assertEquals(List.of(leftover.id()), b.leftovers().stream().map(KeyHandle::id).toList());
  }

  /**
   * Two instances create at the same moment (a fixed clock, so the lowest identifier ranks first) on
   * a server with duplicate names: both end with one key. findOrCreate never destroys the losing
   * creator's key (another instance may have activated and used the key after any read), so it
   * stays Pre-Active, and leftovers() lists it.
   */
  @ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aFindOrCreateRaceLoserKeepsItsOwnKey(KmipVersion version) throws Exception {
    InMemoryKmipServer server = server(version, false, false);
    Kms setup = connect(server);
    CyclicBarrier create = new CyclicBarrier(2), created = new CyclicBarrier(2);
    InMemoryKmipServer ra = server.replica(), rb = server.replica();
    Kms a = connect(ra, s -> meeting(ra, Operation.CREATE, create, created, () -> {}));
    Kms b = connect(rb, s -> meeting(rb, Operation.CREATE, create, created, () -> {}));
    Object[] results = race(() -> vault(a).findOrCreate().id(), () -> vault(b).findOrCreate().id());
    assertEquals(results[0], results[1], "both end with one key");
    String loser =
        server.ids().stream().filter(i -> !i.equals(results[0])).findFirst().orElseThrow();
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(loser), describe(server));
    assertTrue(server.hasMaterial(loser));
    assertEquals(Optional.of(results[0]), setup.keys().findByName("vault").map(KeyHandle::id));
    assertEquals(
        List.of(loser),
        setup.keys().handle((String) results[0]).leftovers().stream().map(KeyHandle::id).toList());
  }

  // ---- the duplicate-name diagnosis stays inside the call's deadline ----

  /**
   * On a 1.x server with unique names, a refusal that arrives late (SLOW)
   * is confirmed with a Locate that hangs. addName closed its deadline scope before the Locate,
   * which then had a whole call timeout of its own (a 300 ms call took 487 ms). Now every path
   * that confirms a 1.x Invalid Field (addName, create, createPreActive, register, createKeyPair)
   * ends at the call's deadline.
   */
  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.ValueSource(
      strings = {"addName", "create", "createPreActive", "register", "createKeyPair"})
  void aNameInUseIsDiagnosedWithinTheCallDeadline(String path) {
    java.time.Duration timeout = java.time.Duration.ofMillis(600);
    InMemoryKmipServer server =
        InMemoryKmipServer.of(KmipVersion.V1_4)
            .uniqueNames(true)
            .slowReplyDelay(java.time.Duration.ofMillis(400));
    Kms kms =
        Kms.connect(
            server.configure().callTimeout(timeout).retryPolicy(RetryPolicy.none()).build());
    clients.add(kms);
    vault(kms).create();
    kms.keys()
        .createKeyPair(KeyPairSpec.ec(Curve.P_256))
        .named("vault-sig", "vault-pub")
        .privateUsages(KeyUsage.SIGN)
        .publicUsages(KeyUsage.VERIFY)
        .create();
    KeyHandle unnamed =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    ServerOperation slow =
        switch (path) {
          case "addName" -> ServerOperation.ADD_ATTRIBUTE;
          case "register" -> ServerOperation.REGISTER;
          case "createKeyPair" -> ServerOperation.CREATE_KEY_PAIR;
          default -> ServerOperation.CREATE;
        };
    server.failNext(slow, Fault.SLOW);
    server.failNext(ServerOperation.LOCATE, Fault.HANG);
    long start = System.nanoTime();
    KmsException e =
        assertThrows(
            KmsException.class,
            () -> {
              switch (path) {
                case "addName" -> unnamed.addName("vault");
                case "create" -> vault(kms).create();
                case "createPreActive" -> vault(kms).createPreActive();
                case "register" ->
                    kms.keys().registerSecret("x".toCharArray()).named("vault").register();
                default ->
                    kms.keys()
                        .createKeyPair(KeyPairSpec.ec(Curve.P_256))
                        .named("vault-sig", "other-pub")
                        .privateUsages(KeyUsage.SIGN)
                        .publicUsages(KeyUsage.VERIFY)
                        .create();
              }
            });
    long ms = (System.nanoTime() - start) / 1_000_000;
    // The Locate could not confirm the name in time, so the Invalid Field stands.
    assertInstanceOf(InvalidRequestException.class, e, e.toString());
    assertTrue(
        ms < 850, path + " took " + ms + " ms with a 600 ms call timeout (before: about 1000 ms)");
  }

  // ---- no name-trusting advice on the query path ----

  /**
   * An attacker's key named like the victim's, a record sealed under it, the
   * key revoked as compromised. Through the handle the advice already said a name proves nothing;
   * through kms.keys().open(KeyQuery.byName(...)), which the record's key matches by name, it said
   * "use handle(X).allowingCompromised() ... to recover data". Every query path now gives the
   * advice that does not trust the name: open, decrypt, unwrapKey and opening.
   */
  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theQueryPathDoesNotTrustTheNameOfACompromisedKey(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms victim = connect(server), attacker = connect(server);
    vault(victim).findOrCreate();
    KeyHandle evil = vault(attacker).create();
    byte[] forged = evil.seal("FORGED".getBytes(UTF_8), AAD);
    Ciphertext encrypted = evil.encrypt(CipherSpec.aesGcm(), new byte[32], AAD);
    java.io.ByteArrayOutputStream stream = new java.io.ByteArrayOutputStream();
    try (SealingStream out = evil.sealing(stream, AAD)) {
      out.write("FORGED".getBytes(UTF_8));
      out.finish();
    }
    evil.revoke(leaked());
    KeyQuery byName = KeyQuery.byName("vault");
    List<org.junit.jupiter.api.function.Executable> paths =
        List.of(
            () -> victim.keys().open(byName, forged, AAD),
            () -> victim.keys().decrypt(byName, encrypted, AAD),
            () -> victim.keys().unwrapKey(byName, Expect.aes(256), encrypted, AAD),
            () ->
                victim
                    .keys()
                    .opening(byName, new java.io.ByteArrayInputStream(stream.toByteArray()), AAD));
    for (var path : paths) {
      KmsException e = assertThrows(KmsException.class, path);
      assertEquals(KmsException.Category.STATE, e.category(), e.getMessage());
      assertTrue(
          e.getMessage().contains("a name proves nothing") && e.getMessage().contains("forged"),
          e.getMessage());
      assertFalse(e.getMessage().contains("for example to recover data"), e.getMessage());
    }
  }

  // ---- findOrCreate names (and replaces) the ranked Compromised key ----

  /**
   * The victim's key and, in the same second, an attacker's key named
   * like it (identifiers descending, so the attacker's sorts first), both Compromised. Before,
   * replacingCompromised() re-keyed whichever ranked first, here the decoy. Two lineages have the
   * name, so nothing is replaced and both are named; without the opt-in the advice names both too.
   */
  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void compromisedKeysOfTwoLineagesAreNotGuessedBetween(KmipVersion version) {
    InMemoryKmipServer server = server(version, false, true);
    Kms victim = connect(server), attacker = connect(server);
    KeyHandle kek = vault(victim).findOrCreate();
    kek.revoke(leaked());
    KeyHandle decoy = vault(attacker).create();
    decoy.revoke(leaked());
    int objects = server.ids().size();
    for (boolean opt : new boolean[] {false, true}) {
      KeyCreation b = vault(victim);
      if (opt) b.replacingCompromised();
      StateConflictException e = assertThrows(StateConflictException.class, b::findOrCreate);
      assertTrue(
          e.getMessage().contains(kek.id()) && e.getMessage().contains(decoy.id()), e.getMessage());
      assertTrue(e.getMessage().contains("a name proves nothing"), e.getMessage());
      assertEquals(objects, server.ids().size(), "nothing created");
      assertEquals(
          List.of(), server.links(decoy.id(), LinkKind.REPLACEMENT), "the decoy was not re-keyed");
    }
    // Replacing the right one by its handle works, and the name then finds its replacement.
    KeyHandle replacement = victim.keys().handle(kek.id()).replaceCompromised(leaked());
    assertEquals(replacement.id(), vault(victim).findOrCreate().id());
  }

  /**
   * One lineage, two Compromised keys with the name (a duplicate-name server: the name was added to
   * the replacement and stayed on the old key, then the replacement was compromised too). The
   * advice names the ranked key, the newest, not the first in Locate order.
   */
  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theAdviceNamesTheRankedCompromisedKey(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    server.clock(ticking());
    Kms kms = connect(server, s -> refusingReKey(server, server));
    KeyHandle a = vault(kms).findOrCreate();
    KeyHandle b = a.replaceCompromised(leaked());
    // The name is taken off the old key on duplicate-name servers too: put it back.
    a.addName("vault");
    assertTrue(
        server.names(a.id()).contains("vault") && server.names(b.id()).contains("vault"),
        describe(server));
    b.revoke(leaked());
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> vault(kms).findOrCreate());
    assertTrue(
        e.getMessage().contains("handle(\"" + b.id() + "\").replaceCompromised"), e.getMessage());
    assertEquals(b.id(), e.objectId().orElseThrow());
    KeyHandle c = vault(kms).replacingCompromised().findOrCreate();
    assertEquals(
        List.of(b.id()), server.links(c.id(), LinkKind.REPLACED), "the newest key was replaced");
  }

  // ---- decrypt, verify and MAC verify refused for a key's state ----

  /**
   * KMIP 1.x servers (and the in-memory server) answer Permission Denied for a
   * decrypt, signature verify or MAC verify with a key whose state does not allow it, a Pre-Active
   * one; 2.x answers Wrong Key Lifecycle State. Encrypt, sign and MAC already read the key's state
   * on that failure; the other three were FIX_ACCESS on 1.x and STATE on 2.x. Now STATE on every
   * version, with the server's reason kept.
   */
  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void decryptAndVerifyWithAKeyThatCannotBeUsedAreStateOnEveryVersion(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    CipherSpec spec = version == KmipVersion.V1_2 ? CipherSpec.cbc() : CipherSpec.aesGcm();
    KeyHandle active =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    KeyHandle preActive =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
    // A ciphertext that names the Pre-Active key (identifiers of one length: mock-1, mock-2).
    byte[] aad = spec.authenticated() ? AAD : null;
    byte[] bytes = active.encrypt(spec, new byte[32], aad).toBytes();
    byte[] from = active.id().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    byte[] to = preActive.id().getBytes(java.nio.charset.StandardCharsets.UTF_8);
    for (int i = 0; i + from.length <= bytes.length; i++)
      if (Arrays.equals(Arrays.copyOfRange(bytes, i, i + from.length), from))
        System.arraycopy(to, 0, bytes, i, to.length);
    Ciphertext named = Ciphertext.fromBytes(bytes);
    assertEquals(preActive.id(), named.keyId());
    List<org.junit.jupiter.api.function.Executable> calls = new ArrayList<>();
    calls.add(() -> preActive.decrypt(spec, named, aad));
    KeyHandle hmac =
        kms.keys()
            .createSymmetric(Algorithm.HMAC_SHA256, 256)
            .usages(KeyUsage.MAC_GENERATE, KeyUsage.MAC_VERIFY)
            .createPreActive();
    calls.add(() -> hmac.macVerify(MacSpec.keyDefault(), new byte[3], new byte[32]));
    if (version != KmipVersion.V1_2) {
      KeyPairHandle pair =
          kms.keys()
              .createKeyPair(KeyPairSpec.rsa(2048))
              .privateUsages(KeyUsage.SIGN)
              .publicUsages(KeyUsage.VERIFY)
              .createPreActive();
      calls.add(
          () ->
              pair.publicKey()
                  .verify(SignatureSpec.rsaPss(Hash.SHA_256), new byte[3], new byte[256]));
    }
    for (var call : calls) {
      KmsException e = assertThrows(KmsException.class, call);
      assertEquals(StateConflictException.class, e.getClass(), version + ": " + e);
      assertTrue(
          e.getMessage().contains("PRE_ACTIVE") && e.getMessage().contains("activate()"),
          e.getMessage());
      assertEquals(
          Optional.of(
              version == KmipVersion.V2_1
                  ? Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE
                  : Enums.ResultReason.PERMISSION_DENIED),
          e.protocolReason(),
          e.toString());
    }
  }
}
