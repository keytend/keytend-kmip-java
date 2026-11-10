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

import dev.keytend.kmip.TestKmipServer;
import dev.keytend.kmip.TestTls;
import dev.keytend.kmip.client.Messages;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Replicas that hang or refuse: failover within one call, attempt timeouts, mutations never resent,
 * names in use, keys that cannot be used, and restarts during a compromise.
 */
class ReplicaFailoverTest {
  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();
  final List<AutoCloseable> closeables = new ArrayList<>();

  /** Released at the end of each test, so replicas that hang do not keep their threads. */
  final CountDownLatch release = new CountDownLatch(1);

  @AfterEach
  void cleanUp() throws Exception {
    release.countDown();
    clients.forEach(Kms::close);
    for (AutoCloseable c : closeables) c.close();
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  Kms connect(InMemoryKmipServer server, KmsConfig.Builder builder) {
    servers.add(server);
    Kms kms = Kms.connect(builder.build());
    clients.add(kms);
    return kms;
  }

  static Set<Operation> operations(Ttlv request) {
    Set<Operation> out = EnumSet.noneOf(Operation.class);
    for (Ttlv item : request.children(Tag.BATCH_ITEM))
      out.add(Operation.fromCode(item.require(Tag.OPERATION).intValue()));
    return out;
  }

  /** Records listener events. */
  static final class Recorder implements KmsListener {
    final List<String> unavailable = new CopyOnWriteArrayList<>();
    final List<KmsEvent> retries = new CopyOnWriteArrayList<>();

    @Override
    public void endpointUnavailable(String endpoint, String why) {
      unavailable.add(endpoint);
    }

    @Override
    public void retrying(KmsEvent failed, Duration delay) {
      retries.add(failed);
    }
  }

  // ---- a hung replica fails over within one call ----

  /**
   * A real mutual-TLS replica in front of {@code store}: while {@code hang} says so for a request,
   * it reads the request and never answers (the connection stays open), as a stalled replica does.
   */
  TestKmipServer replica(InMemoryKmipServer store, java.util.function.Predicate<Ttlv> hang)
      throws Exception {
    TestKmipServer tls =
        new TestKmipServer(
            "server",
            request -> {
              if (hang.test(request))
                try {
                  release.await(60, TimeUnit.SECONDS);
                } catch (InterruptedException e) {
                  Thread.currentThread().interrupt();
                }
              try {
                return store.exchange(request);
              } catch (IOException e) {
                throw new UncheckedIOException(e);
              }
            });
    closeables.add(tls);
    return tls;
  }

  KmsConfig.Builder replicas(TestKmipServer... endpoints) throws Exception {
    KmsConfig.Builder b =
        KmsConfig.builder().tls(TestTls.context("client", "server")).versions(KmipVersion.V2_1);
    List<String> hostPorts = new ArrayList<>();
    for (TestKmipServer e : endpoints) hostPorts.add("localhost:" + e.port());
    return b.endpoints(hostPorts.toArray(String[]::new));
  }

  @Test
  void aHungReplicaFailsOverWithinOneCall() throws Exception {
    InMemoryKmipServer store = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicBoolean hang = new AtomicBoolean();
    TestKmipServer a =
        replica(store, r -> hang.get() && !operations(r).contains(Operation.DISCOVER_VERSIONS));
    TestKmipServer b = replica(store, r -> false);
    Recorder events = new Recorder();
    Kms kms = connect(store, replicas(a, b).callTimeout(Duration.ofSeconds(3)).addListener(events));
    KeyHandle key =
        kms.keys()
            .createAes(256)
            .named("vault")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .create();
    hang.set(true);
    long start = System.nanoTime();
    assertEquals(KeyState.ACTIVE, key.attributes().state());
    long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
    // The default attempt timeout is the call timeout divided by the 3 attempts: 1 s, then B.
    assertTrue(millis >= 950 && millis < 2500, "failed over after " + millis + " ms");
    assertEquals(List.of("localhost:" + a.port()), events.unavailable);
    assertEquals(1, events.retries.size());
    assertTrue(
        events.retries.get(0).failure().orElseThrow().getMessage().contains("attempt timeout"));
    // Traffic moved: the next read goes to B at once.
    int before = b.exchangeCount();
    start = System.nanoTime();
    key.attributes();
    assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 900);
    assertEquals(before + 1, b.exchangeCount());
  }

  @Test
  void anExplicitAttemptTimeoutBoundsEachAttempt() throws Exception {
    InMemoryKmipServer store = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicBoolean hang = new AtomicBoolean();
    TestKmipServer a =
        replica(store, r -> hang.get() && !operations(r).contains(Operation.DISCOVER_VERSIONS));
    TestKmipServer b = replica(store, r -> false);
    RetryPolicy policy = RetryPolicy.builder().attemptTimeout(Duration.ofMillis(300)).build();
    Kms kms =
        connect(store, replicas(a, b).callTimeout(Duration.ofSeconds(20)).retryPolicy(policy));
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    hang.set(true);
    long start = System.nanoTime();
    key.attributes();
    long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
    assertTrue(millis >= 280 && millis < 1500, "failed over after " + millis + " ms");
  }

  @Test
  void aHungMutationIsOutcomeUnknownAtTheCallDeadlineAndNotResent() throws Exception {
    InMemoryKmipServer store = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicBoolean hang = new AtomicBoolean();
    TestKmipServer a =
        replica(store, r -> hang.get() && !operations(r).contains(Operation.DISCOVER_VERSIONS));
    TestKmipServer b = replica(store, r -> false);
    Kms kms = connect(store, replicas(a, b).callTimeout(Duration.ofMillis(1500)));
    hang.set(true);
    int atB = b.exchangeCount();
    long start = System.nanoTime();
    OutcomeUnknownException e =
        assertThrows(
            OutcomeUnknownException.class,
            () ->
                kms.keys()
                    .createAes(256)
                    .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                    .createPreActive());
    long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
    // Not cut at the 500 ms attempt timeout: a mutation gets the whole deadline, and is never
    // re-sent.
    assertTrue(millis >= 1400, "gave up after " + millis + " ms: " + e);
    assertEquals(atB, b.exchangeCount());
  }

  @Test
  void aShortViewDoesNotMoveTrafficButTheAttemptTimeoutDoes() throws Exception {
    InMemoryKmipServer store = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicBoolean hang = new AtomicBoolean();
    TestKmipServer a =
        replica(store, r -> hang.get() && !operations(r).contains(Operation.DISCOVER_VERSIONS));
    TestKmipServer b = replica(store, r -> false);
    Recorder events = new Recorder();
    // No cool-down, so only the shared current endpoint decides where the next call goes.
    RetryPolicy policy = RetryPolicy.builder().cooldown(Duration.ZERO).build();
    Kms kms =
        connect(
            store,
            replicas(a, b)
                .callTimeout(Duration.ofSeconds(3))
                .addListener(events)
                .retryPolicy(policy));
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    hang.set(true);
    // The view's own 400 ms ends before the 1 s attempt timeout: the caller's choice, nothing
    // moves.
    KeyHandle quick = kms.withTimeout(Duration.ofMillis(400)).keys().handle(key.id());
    assertThrows(TransientException.class, quick::attributes);
    assertEquals(List.of(), events.unavailable);
    // A view shorter than the call timeout but longer than the attempt timeout meets the attempt
    // timeout first: the endpoint did not answer within it, so traffic moves to B.
    kms.withTimeout(Duration.ofMillis(2500)).keys().handle(key.id()).attributes();
    assertEquals(List.of("localhost:" + a.port()), events.unavailable);
    int before = b.exchangeCount();
    long start = System.nanoTime();
    key.attributes();
    assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 900);
    assertEquals(before + 1, b.exchangeCount());
  }

  @Test
  void aHungInMemoryReplicaFailsOverWithinOneCall() {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V1_4, KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica();
    servers.add(b);
    Recorder events = new Recorder();
    Kms kms =
        connect(a, a.configureReplicas(b).callTimeout(Duration.ofSeconds(3)).addListener(events));
    KeyHandle key =
        kms.keys()
            .createAes(256)
            .named("vault")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .create();
    byte[] sealed = key.seal(new byte[] {1, 2, 3}, null);
    a.failNext(
        dev.keytend.kmip.testing.ServerOperation.GET_ATTRIBUTES,
        dev.keytend.kmip.testing.Fault.HANG);
    long start = System.nanoTime();
    assertArrayEquals(new byte[] {1, 2, 3}, key.open(sealed, null));
    long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
    assertTrue(millis >= 950 && millis < 2500, "opened after " + millis + " ms");
    assertEquals(List.of("in-memory:5696"), events.unavailable);
    // A hung mutation is not re-sent: unknown outcome at the call deadline, and B never saw it.
    int atB = b.exchanges();
    b.failNext(
        dev.keytend.kmip.testing.ServerOperation.CREATE, dev.keytend.kmip.testing.Fault.HANG);
    Kms quick = kms.withTimeout(Duration.ofMillis(600));
    assertThrows(
        OutcomeUnknownException.class,
        () -> quick.keys().createAes(256).usages(KeyUsage.ENCRYPT).createPreActive());
    assertEquals(atB + 1, b.exchanges());
  }

  @Test
  void connectSkipsAReplicaThatAcceptsButNeverAnswers() throws Exception {
    InMemoryKmipServer store = InMemoryKmipServer.of(KmipVersion.V2_1);
    TestKmipServer a = replica(store, r -> true);
    TestKmipServer b = replica(store, r -> false);
    Recorder events = new Recorder();
    long start = System.nanoTime();
    Kms kms = connect(store, replicas(a, b).callTimeout(Duration.ofSeconds(3)).addListener(events));
    long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
    assertTrue(millis >= 950 && millis < 2500, "connected after " + millis + " ms");
    assertEquals(List.of("localhost:" + a.port()), events.unavailable);
    kms.ping();
  }

  @Test
  void pingIsOneDiscoverVersions() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V1_4, KmipVersion.V2_1);
    Kms kms = connect(server, server.configure());
    int before = server.exchanges();
    kms.ping();
    assertEquals(before + 1, server.exchanges());
    List<Ttlv> requests = server.protocolRequests();
    assertEquals(
        EnumSet.of(Operation.DISCOVER_VERSIONS), operations(requests.get(requests.size() - 1)));
  }

  @Test
  void theAttemptTimeoutIsPartOfThePolicy() {
    RetryPolicy derived = RetryPolicy.defaults();
    assertEquals(Optional.empty(), derived.attemptTimeout());
    assertEquals(Duration.ofSeconds(10).toNanos(), derived.attemptNanos(Duration.ofSeconds(30)));
    RetryPolicy explicit = RetryPolicy.builder().attemptTimeout(Duration.ofSeconds(2)).build();
    assertEquals(Optional.of(Duration.ofSeconds(2)), explicit.attemptTimeout());
    assertEquals(Duration.ofSeconds(2).toNanos(), explicit.attemptNanos(Duration.ofSeconds(30)));
    assertNotEquals(derived, explicit);
    assertEquals(explicit, explicit.toBuilder().build());
    assertEquals(derived, explicit.toBuilder().defaultAttemptTimeout().build());
    assertTrue(explicit.toString().contains("attempt timeout PT2S"));
    assertThrows(
        IllegalArgumentException.class, () -> RetryPolicy.builder().attemptTimeout(Duration.ZERO));
    assertThrows(
        IllegalArgumentException.class,
        () -> RetryPolicy.builder().attemptTimeout(Duration.ofDays(2)));
  }

  // ---- the same failure has the same category on every version ----

  static final KmipVersion[] CROSS_VERSIONS = {
    KmipVersion.V1_2, KmipVersion.V1_4, KmipVersion.V2_0, KmipVersion.V2_1, KmipVersion.V3_0
  };

  /** The Name values a request sets (a Name structure's Name Value, or 3.0's text Name). */
  static List<String> names(Ttlv t) {
    List<String> out = new ArrayList<>();
    if (t.tag() == Tag.NAME_VALUE.code() && t.type() == Ttlv.Type.TEXT_STRING)
      out.add(t.textValue());
    else if (t.tag() == Tag.NAME.code() && t.type() == Ttlv.Type.TEXT_STRING)
      out.add(t.textValue());
    else if (t.type() == Ttlv.Type.STRUCTURE) for (Ttlv c : t.children()) out.addAll(names(c));
    return out;
  }

  static Optional<String> target(Ttlv request) {
    try {
      return request
          .require(Tag.BATCH_ITEM)
          .child(Tag.REQUEST_PAYLOAD)
          .flatMap(p -> p.child(Tag.UNIQUE_IDENTIFIER))
          .map(Ttlv::textValue);
    } catch (RuntimeException notText) {
      return Optional.empty();
    }
  }

  /**
   * A spec-correct server in front of {@code server}: it refuses a Create, Register or Add Attribute
   * whose Name another existing object has (KMIP 1.x: Invalid Field, KMIP 1.4 Table 328; 2.x:
   * Non Unique Name Attribute). (A key that is not Active needs no front: the in-memory server
   * refuses it with Permission Denied on 1.x, as keytend-kmip-server does.) {@code beforeCreate} runs before
   * each Create is checked (another process racing).
   */
  KmsConfig.Builder specCorrect(InMemoryKmipServer server, Runnable beforeCreate) {
    return server
        .configure()
        .transport(
            e ->
                request -> {
                  boolean legacy =
                      Messages.version(request.require(Tag.REQUEST_HEADER)).major() == 1;
                  int op = Faults.operation(request);
                  if (op == Operation.CREATE.code()) beforeCreate.run();
                  if (op == Operation.CREATE.code()
                      || op == Operation.REGISTER.code()
                      || op == Operation.ADD_ATTRIBUTE.code()
                      || op == Operation.CREATE_KEY_PAIR.code())
                    for (String n : names(request))
                      for (String id : server.ids())
                        if (server.exists(id) && server.names(id).contains(n))
                          return Faults.failure(
                              request,
                              legacy
                                  ? Enums.ResultReason.INVALID_FIELD
                                  : Enums.ResultReason.NON_UNIQUE_NAME_ATTRIBUTE,
                              "Name is not unique in this key management server");
                  return server.exchange(request);
                });
  }

  @Test
  void aNameInUseIsAlreadyExistsOnEveryVersion() {
    for (KmipVersion v : CROSS_VERSIONS) {
      InMemoryKmipServer server = InMemoryKmipServer.of(v);
      Kms kms = connect(server, specCorrect(server, () -> {}));
      KeyHandle first =
          kms.keys()
              .createAes(256)
              .named("vault")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
      KmsException create =
          assertThrows(
              KmsException.class,
              () -> kms.keys().createAes(256).named("vault").usages(KeyUsage.ENCRYPT).create());
      assertEquals(AlreadyExistsException.class, create.getClass(), v + ": " + create);
      assertEquals(KmsException.Category.STATE, create.category());
      if (v.protocolValue().major() == 1)
        assertTrue(create.getMessage().contains(first.id()), create.getMessage());
      KmsException register =
          assertThrows(
              KmsException.class,
              () -> kms.keys().registerSecret("hunter2".toCharArray()).named("vault").register());
      assertEquals(AlreadyExistsException.class, register.getClass(), v + ": " + register);
      KeyHandle other = kms.keys().createAes(256).named("other").usages(KeyUsage.ENCRYPT).create();
      KmsException add = assertThrows(KmsException.class, () -> other.addName("vault"));
      assertEquals(AlreadyExistsException.class, add.getClass(), v + ": " + add);
      // Another Invalid Field (no object has the name) stays FIX_REQUEST.
      server.failNext(
          dev.keytend.kmip.testing.ServerOperation.CREATE, Enums.ResultReason.INVALID_FIELD);
      KmsException invalid =
          assertThrows(
              KmsException.class,
              () -> kms.keys().createAes(256).named("fresh").usages(KeyUsage.ENCRYPT).create());
      assertEquals(InvalidRequestException.class, invalid.getClass(), v + ": " + invalid);
    }
  }

  @Test
  void anInvalidFieldIsOnlyReadAsANameInUseOn1x() {
    // On 2.x a name in use has its own reason, so an Invalid Field means something else, even when
    // an object happens to have the name (here on a server that allows duplicates).
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server, server.configure());
    kms.keys().createAes(256).named("vault").usages(KeyUsage.ENCRYPT).create();
    server.failNext(
        dev.keytend.kmip.testing.ServerOperation.CREATE, Enums.ResultReason.INVALID_FIELD);
    KmsException e =
        assertThrows(
            KmsException.class,
            () -> kms.keys().createAes(256).named("vault").usages(KeyUsage.ENCRYPT).create());
    assertEquals(InvalidRequestException.class, e.getClass());
  }

  @Test
  void findOrCreateConvergesWhenAnotherProcessWinsOnAUniqueNameServer() {
    for (KmipVersion v : CROSS_VERSIONS) {
      InMemoryKmipServer server = InMemoryKmipServer.of(v);
      Kms other = connect(server, server.configure());
      List<KeyHandle> winner = new ArrayList<>();
      Runnable race =
          () -> {
            if (winner.isEmpty())
              winner.add(
                  other
                      .keys()
                      .createAes(256)
                      .named("vault")
                      .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                      .create());
          };
      Kms kms = connect(server, specCorrect(server, race));
      KeyHandle mine =
          kms.keys()
              .createAes(256)
              .named("vault")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .findOrCreate();
      assertEquals(winner.get(0).id(), mine.id(), v.toString());
      assertEquals(1, server.ids().size(), v.toString());
    }
  }

  @Test
  void aKeyThatCannotBeUsedIsStateOnEveryVersion() {
    Set<String> messages = new HashSet<>();
    for (KmipVersion v : CROSS_VERSIONS) {
      // The plain in-memory server: Permission Denied on 1.x, Wrong Key Lifecycle State from 2.0.
      InMemoryKmipServer server = InMemoryKmipServer.of(v);
      Kms kms = connect(server, server.configure());
      KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
      key.revoke(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
      CipherSpec spec =
          v.protocolValue().atLeast(ProtocolVersion.V1_4) ? CipherSpec.aesGcm() : CipherSpec.cbc();
      KmsException e = assertThrows(KmsException.class, () -> key.encrypt(spec, new byte[16]));
      assertEquals(StateConflictException.class, e.getClass(), v + ": " + e);
      assertTrue(e.getMessage().contains("COMPROMISED"), e.getMessage());
      messages.add(e.getMessage());
      if (v.protocolValue().atLeast(ProtocolVersion.V1_4)) {
        KmsException sealed = assertThrows(KmsException.class, () -> key.seal(new byte[3], null));
        assertEquals(StateConflictException.class, sealed.getClass(), v + ": " + sealed);
        assertEquals("seal", sealed.operation());
      }
      KeyHandle preActive =
          kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
      KmsException pre =
          assertThrows(KmsException.class, () -> preActive.encrypt(spec, new byte[16]));
      assertEquals(StateConflictException.class, pre.getClass(), v + ": " + pre);
      assertTrue(pre.getMessage().contains("activate()"), pre.getMessage());
    }
    // One message on every version, whatever the server's reason.
    assertEquals(1, messages.size(), messages.toString());
  }

  @Test
  void aPermissionDeniedForAnActiveKeyStaysFixAccess() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V1_4);
    Kms kms = connect(server, server.configure().retryPolicy(RetryPolicy.none()));
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    server.failNext(
        dev.keytend.kmip.testing.ServerOperation.ENCRYPT,
        dev.keytend.kmip.testing.Fault.PERMISSION_DENIED);
    KmsException e =
        assertThrows(KmsException.class, () -> key.encrypt(CipherSpec.aesGcm(), new byte[16]));
    assertEquals(PermissionDeniedException.class, e.getClass());
  }

  // ---- never quarantine good data during a compromise ----

  static final byte[] PLAIN = KmsContractTest.PLAIN, AAD = KmsContractTest.AAD;

  static KeyCreation vault(Kms kms) {
    return kms.keys().createAes(256).named("vault").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
  }

  static RevocationReason leaked() {
    return RevocationReason.keyCompromise("leaked", java.time.Instant.now());
  }

  static void assertState(KmsException e, String... mentioned) {
    assertEquals(StateConflictException.class, e.getClass(), "was: " + e);
    assertEquals(KmsException.Category.STATE, e.category());
    for (String m : mentioned) assertTrue(e.getMessage().contains(m), m + " in " + e.getMessage());
  }

  /** An application restarted during a compromise. */
  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aRestartDuringACompromiseDoesNotQuarantineGoodData(KmipVersion version) {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
      Kms before = connect(server, server.configure());
      KeyHandle kek = vault(before).findOrCreate();
      byte[] record = kek.seal(PLAIN, AAD);
      kek.revoke(leaked());
      // The service restarts before anyone ran the compromise procedure.
      Kms after = connect(server, server.configure());
      List<String> ids = server.ids();
      StateConflictException refused =
          assertThrows(StateConflictException.class, () -> vault(after).findOrCreate());
      assertState(refused, kek.id(), "COMPROMISED", "replacingCompromised", "replaceCompromised");
      assertEquals(ids, server.ids(), "no key was created");
      // Opting in replaces it; the replacement has the name, and refuses the old records as STATE.
      KeyHandle replacement = vault(after).replacingCompromised().findOrCreate();
      assertNotEquals(kek.id(), replacement.id());
      assertEquals(Optional.of(KeyState.ACTIVE), server.state(replacement.id()));
      assertTrue(server.names(replacement.id()).contains("vault"), version + " unique=" + unique);
      assertState(
          assertThrows(KmsException.class, () -> replacement.open(record, AAD)),
          kek.id(),
          "COMPROMISED");
      assertState(
          assertThrows(
              KmsException.class, () -> after.keys().open(KeyQuery.byName("vault"), record, AAD)),
          kek.id(),
          "COMPROMISED");
      assertArrayEquals(
          PLAIN, after.keys().handle(kek.id()).allowingCompromised().open(record, AAD));
      // The next restart finds the replacement.
      assertEquals(replacement.id(), vault(after).findOrCreate().id());
    }
  }

  @Test
  void anUnlinkedReplacementStillRefusesOldRecordsAsState() {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1).uniqueNames(unique);
      Kms kms = connect(server, server.configure());
      KeyHandle kek = vault(kms).findOrCreate();
      byte[] record = kek.seal(PLAIN, AAD);
      Ciphertext c = kek.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
      kek.revoke(leaked());
      // A server that refuses to re-key a Compromised key and to add links to it.
      server.failNext(
          dev.keytend.kmip.testing.ServerOperation.RE_KEY,
          dev.keytend.kmip.testing.Fault.STATE_CONFLICT);
      server.failNext(
          dev.keytend.kmip.testing.ServerOperation.ADD_ATTRIBUTE,
          dev.keytend.kmip.testing.Fault.PERMISSION_DENIED);
      // Not returned: a PartialCompletionException naming both keys, its replacement finished.
      PartialCompletionException unlinked =
          assertThrows(
              PartialCompletionException.class,
              () -> vault(kms).replacingCompromised().findOrCreate());
      KeyHandle replacement = unlinked.created().get(0);
      assertTrue(
          unlinked.getMessage().contains(kek.id())
              && unlinked.getMessage().contains("do not repeat"),
          unlinked.getMessage());
      assertEquals(Optional.of(KeyState.ACTIVE), server.state(replacement.id()));
      assertEquals(List.of("vault"), server.names(replacement.id()));
      assertEquals(List.of(), server.links(replacement.id(), LinkKind.REPLACED));
      // The name is taken off the old key on duplicate-name servers too.
      assertEquals(List.of(), server.names(kek.id()), "unique=" + unique);
      // Not in the replacement's chain, but under an existing Compromised key: STATE, not BAD_DATA.
      assertState(
          assertThrows(KmsException.class, () -> replacement.open(record, AAD)),
          kek.id(),
          "COMPROMISED",
          "revoked yourself");
      assertState(
          assertThrows(KmsException.class, () -> replacement.decrypt(c, AAD)),
          kek.id(),
          "COMPROMISED");
      // By name too: with unique names the old key lost the name, and nothing links it to a key
      // that has it.
      assertState(
          assertThrows(
              KmsException.class, () -> kms.keys().open(KeyQuery.byName("vault"), record, AAD)),
          kek.id(),
          "COMPROMISED");
      // A stranger's record stays BAD_DATA, on both paths.
      byte[] strangers =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create()
              .seal(PLAIN, AAD);
      KeyMismatchException bad =
          assertThrows(KeyMismatchException.class, () -> replacement.open(strangers, AAD));
      assertEquals(KmsException.Category.BAD_DATA, bad.category());
      bad =
          assertThrows(
              KeyMismatchException.class,
              () -> kms.keys().open(KeyQuery.byName("vault"), strangers, AAD));
      assertEquals(KmsException.Category.BAD_DATA, bad.category());
    }
  }

  @Test
  void aNameWhoseKeysAreOnlyDeactivatedIsRefusedToo() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server, server.configure());
    KeyHandle kek = vault(kms).findOrCreate();
    kek.revoke(RevocationReason.cessationOfOperation("retired"));
    assertState(
        assertThrows(KmsException.class, () -> vault(kms).replacingCompromised().findOrCreate()),
        kek.id(),
        "DEACTIVATED",
        "removeName");
    kek.removeName("vault");
    assertNotEquals(kek.id(), vault(kms).findOrCreate().id());
  }

  // ---- retirement and compromise recovery as operations ----

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void replaceCompromisedRevokesReplacesAndCanBeRepeated(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server, server.configure().maximumVersion(KmipVersion.V3_0));
    KeyHandle kek = vault(kms).findOrCreate();
    byte[] record = kek.seal(PLAIN, AAD);
    KeyHandle replacement = kek.replaceCompromised(leaked());
    assertEquals(Optional.of(KeyState.COMPROMISED), server.state(kek.id()));
    assertEquals(Optional.of(KeyState.ACTIVE), server.state(replacement.id()));
    assertEquals(List.of(kek.id()), server.links(replacement.id(), LinkKind.REPLACED));
    assertTrue(server.names(replacement.id()).contains("vault"));
    assertEquals(replacement.id(), kms.keys().findByName("vault").orElseThrow().id());
    // Repeating revokes nothing and makes nothing.
    List<String> ids = server.ids();
    assertEquals(replacement.id(), kek.replaceCompromised(leaked()).id());
    assertEquals(ids, server.ids());
    // Old records: refused by the replacement, readable with the compromised key named explicitly.
    assertState(
        assertThrows(KmsException.class, () -> replacement.open(record, AAD)),
        kek.id(),
        "COMPROMISED");
    assertArrayEquals(PLAIN, kek.allowingCompromised().open(record, AAD));
    assertThrows(
        IllegalArgumentException.class,
        () -> replacement.replaceCompromised(RevocationReason.superseded("no")));
  }

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void replaceCompromisedFallsBackToALinkedNewKeyWhenReKeyIsRefused(KmipVersion version) {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
      Kms kms = connect(server, server.configure());
      KeyHandle kek = vault(kms).findOrCreate();
      kek.setCustomAttribute(CustomAttribute.client("Owner"), "vault-service");
      byte[] record = kek.seal(PLAIN, AAD);
      server.failNext(
          dev.keytend.kmip.testing.ServerOperation.RE_KEY,
          dev.keytend.kmip.testing.Fault.STATE_CONFLICT);
      KeyHandle replacement = kek.replaceCompromised(leaked());
      KeyAttributes a = replacement.attributes();
      assertEquals(KeyState.ACTIVE, a.state());
      assertEquals(Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), a.usages());
      assertEquals("vault-service", a.custom().get(CustomAttribute.client("Owner")));
      assertEquals(List.of("vault"), a.names(), version + " unique=" + unique);
      // Linked by hand: the chain is followed, so the old record is refused as Compromised.
      assertEquals(List.of(kek.id()), server.links(replacement.id(), LinkKind.REPLACED));
      assertEquals(List.of(replacement.id()), server.links(kek.id(), LinkKind.REPLACEMENT));
      assertState(
          assertThrows(KmsException.class, () -> replacement.open(record, AAD)),
          kek.id(),
          "COMPROMISED");
      assertEquals(
          replacement.id(), kek.replaceCompromised(leaked()).id(), "repeatable once linked");
    }
  }

  @Test
  void retirePredecessorsRetiresOldestFirstAndNothingElse() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    java.time.Instant t0 = java.time.Instant.parse("2026-10-01T00:00:00Z");
    java.util.concurrent.atomic.AtomicLong seconds = new java.util.concurrent.atomic.AtomicLong();
    server.clock(
        new java.time.Clock() {
          @Override
          public java.time.ZoneId getZone() {
            return java.time.ZoneOffset.UTC;
          }

          @Override
          public java.time.Clock withZone(java.time.ZoneId zone) {
            return this;
          }

          @Override
          public java.time.Instant instant() {
            return t0.plusSeconds(seconds.getAndAdd(10));
          }
        });
    Kms kms = connect(server, server.configure());
    KeyHandle a = vault(kms).findOrCreate();
    KeyHandle leftover =
        vault(kms).createPreActive(); // a findOrCreate race lost on another instance
    KeyHandle b = a.rotate();
    KeyHandle c = b.rotate();
    KeyHandle later =
        vault(kms).createPreActive(); // a findOrCreate race lost later: a leftover too
    byte[] record = c.seal(PLAIN, AAD);
    int before = server.protocolRequests().size();
    List<KeyHandle> retired = c.retirePredecessors(RevocationReason.superseded("rotated"));
    // Only the confirmed chain: a leftover is listed by leftovers(), not destroyed.
    assertEquals(List.of(a.id(), b.id()), retired.stream().map(KeyHandle::id).toList());
    // Destroyed in that order: oldest first.
    List<String> destroyed = new ArrayList<>();
    for (Ttlv r : server.protocolRequests().subList(before, server.protocolRequests().size()))
      if (operations(r).contains(Operation.DESTROY)) destroyed.add(target(r).orElseThrow());
    assertEquals(List.of(a.id(), b.id()), destroyed);
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(leftover.id()));
    // findOrCreate leaves the key it lost with, created at any time: listed too.
    assertEquals(
        List.of(leftover.id(), later.id()), c.leftovers().stream().map(KeyHandle::id).toList());
    for (KeyHandle k : List.of(a, b))
      assertEquals(Optional.of(KeyState.DESTROYED), server.state(k.id()));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(later.id()));
    assertEquals(Optional.of(KeyState.ACTIVE), server.state(c.id()));
    assertArrayEquals(PLAIN, c.open(record, AAD));
    // Idempotent.
    assertEquals(List.of(), c.retirePredecessors(RevocationReason.superseded("rotated")));
  }

  @Test
  void retirePredecessorsStopsAtAKeyThatExistsButCannotBeRead() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms owner = connect(server, server.configure());
    KeyHandle a = vault(owner).findOrCreate();
    KeyHandle b = a.rotate();
    KeyHandle c = b.rotate();
    // This client may not read A: B and C cannot be retired without risking a middle key.
    Map<String, Enums.ResultReason> hidden = Map.of(a.id(), Enums.ResultReason.PERMISSION_DENIED);
    Kms kms =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request -> {
                          Optional<String> id = target(request);
                          if (id.isPresent() && hidden.containsKey(id.get()))
                            return Faults.failure(request, hidden.get(id.get()), "hidden");
                          return server.exchange(request);
                        }));
    assertState(
        assertThrows(
            KmsException.class,
            () -> kms.keys().handle(c.id()).retirePredecessors(RevocationReason.superseded("x"))),
        a.id(),
        "nothing was retired");
    assertEquals(Optional.of(KeyState.ACTIVE), server.state(b.id()));
    // Once A is gone (destroyed and purged: Item Not Found), retiring continues from B.
    Map<String, Enums.ResultReason> purged = Map.of(a.id(), Enums.ResultReason.ITEM_NOT_FOUND);
    Kms later =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request -> {
                          Optional<String> id = target(request);
                          if (id.isPresent() && purged.containsKey(id.get()))
                            return Faults.failure(request, purged.get(id.get()), "purged");
                          return server.exchange(request);
                        }));
    assertEquals(
        List.of(b.id()),
        later.keys().handle(c.id()).retirePredecessors(RevocationReason.superseded("x")).stream()
            .map(KeyHandle::id)
            .toList());
  }

  // ---- a key that cannot decrypt does not seal ----

  static long sentOf(InMemoryKmipServer server, Operation op) {
    return server.protocolRequests().stream().filter(r -> operations(r).contains(op)).count();
  }

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aKeyWithoutDecryptRefusesToEncryptOrSeal(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server, server.configure());
    KeyHandle encryptOnly = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
    int before = server.exchanges();
    List<org.junit.jupiter.api.function.Executable> uses =
        List.of(
            () -> encryptOnly.seal(PLAIN, AAD),
            () -> encryptOnly.encrypt(CipherSpec.aesGcm(), PLAIN, AAD),
            () ->
                encryptOnly.wrapKey(new javax.crypto.spec.SecretKeySpec(new byte[32], "AES"), AAD),
            () -> encryptOnly.generateDataKey(256, AAD),
            () -> encryptOnly.sealing(new java.io.ByteArrayOutputStream(), AAD));
    for (var use : uses) {
      KeyMismatchException e = assertThrows(KeyMismatchException.class, use);
      assertEquals(KmsException.Category.FIX_REQUEST, e.category());
      assertTrue(e.getMessage().contains("DECRYPT"), e.getMessage());
    }
    // Known from its creation: nothing was sent.
    assertEquals(before, server.exchanges());
    // A handle that does not know the key reads it once, and still encrypts nothing.
    KeyHandle unknown = kms.keys().handle(encryptOnly.id());
    assertThrows(KeyMismatchException.class, () -> unknown.seal(PLAIN, AAD));
    assertEquals(0, sentOf(server, Operation.ENCRYPT));
    // AES key wrap is undone by Unwrap Key too.
    KeyHandle wrapper =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.UNWRAP_KEY).create();
    wrapper.encrypt(CipherSpec.keyWrap(), new byte[32], null);
    assertThrows(
        KeyMismatchException.class, () -> wrapper.encrypt(CipherSpec.aesGcm(), PLAIN, null));
  }

  @Test
  void theUsagesAreReadOncePerHandle() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server, server.configure());
    String id = vault(kms).findOrCreate().id();
    KeyHandle fresh = kms.keys().handle(id);
    int before = server.exchanges();
    fresh.seal(PLAIN, AAD);
    assertEquals(before + 2, server.exchanges(), "Get Attributes, then Encrypt");
    fresh.seal(PLAIN, AAD);
    fresh.allowingCompromised().seal(PLAIN, AAD);
    assertEquals(
        before + 4, server.exchanges(), "one Encrypt each; the view shares what the handle read");
    // Handles that already read the key, or made it, know it.
    before = server.exchanges();
    vault(kms).findOrCreate().seal(PLAIN, AAD);
    assertEquals(before + 4, server.exchanges(), "findOrCreate's three requests, then Encrypt");
    // A public key encrypts with Encrypt alone, as it should.
    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.DECRYPT)
            .publicUsages(KeyUsage.ENCRYPT)
            .create();
    kms.keys().handle(pair.publicKey().id()).encrypt(CipherSpec.rsaOaep(Hash.SHA_256), PLAIN, null);
  }

  @Test
  void aClientThatMayNotReadTheKeyStillEncrypts() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms owner = connect(server, server.configure());
    String id = vault(owner).findOrCreate().id();
    java.util.concurrent.atomic.AtomicInteger denied =
        new java.util.concurrent.atomic.AtomicInteger();
    Kms encryptOnly =
        connect(
            server,
            server
                .configure()
                .transport(
                    e ->
                        request -> {
                          if (!operations(request).contains(Operation.GET_ATTRIBUTES))
                            return server.exchange(request);
                          denied.incrementAndGet();
                          return Faults.failure(
                              request, Enums.ResultReason.PERMISSION_DENIED, "encrypt only");
                        }));
    KeyHandle key = encryptOnly.keys().handle(id);
    key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    assertEquals(1, denied.get(), "the refused read is not repeated");
  }

  // ---- rewrap ----

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void rewrapMovesASealedRecordToTheCurrentKey(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server, server.configure());
    KeyHandle old = vault(kms).findOrCreate();
    byte[] record = old.seal(PLAIN, AAD);
    KeyHandle current = old.rotate();
    long decrypts = sentOf(server, Operation.DECRYPT), encrypts = sentOf(server, Operation.ENCRYPT);
    byte[] moved = current.rewrap(record, AAD);
    assertEquals(current.id(), KmsKeys.sealedKeyId(moved));
    assertEquals(decrypts + 1, sentOf(server, Operation.DECRYPT));
    assertEquals(encrypts + 1, sentOf(server, Operation.ENCRYPT));
    assertArrayEquals(PLAIN, current.open(moved, AAD));
    // Wrapped by the current key now.
    assertNotEquals(
        Envelopes.parse(record).wrappedKey().keyId(), Envelopes.parse(moved).wrappedKey().keyId());
    // Already the current key's: unchanged, nothing sent.
    int before = server.exchanges();
    assertSame(moved, current.rewrap(moved, AAD));
    assertEquals(before, server.exchanges());
    // The additional data still binds: a wrong one fails and nothing is sealed.
    encrypts = sentOf(server, Operation.ENCRYPT);
    assertThrows(
        CryptographicFailureException.class, () -> current.rewrap(record, "other".getBytes(UTF_8)));
    assertEquals(encrypts, sentOf(server, Operation.ENCRYPT));
    // Once moved, the old key can be retired and the record still opens.
    current.retirePredecessors(RevocationReason.superseded("rotated"));
    assertArrayEquals(PLAIN, current.open(moved, AAD));
  }

  @Test
  void rewrapToRecoversRecordsAfterACompromiseAndWipesThePlaintext() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server, server.configure());
    KeyHandle first = vault(kms).findOrCreate();
    byte[] older = first.seal(PLAIN, AAD);
    KeyHandle kek = first.rotate();
    byte[] record = kek.seal(PLAIN, AAD);
    KeyHandle replacement = kek.replaceCompromised(leaked());
    KeyHandle compromised = kek.allowingCompromised();
    List<byte[]> wiped = new CopyOnWriteArrayList<>();
    KeyHandle.beforeWipe = wiped::add;
    try {
      for (byte[] r : List.of(record, older)) {
        byte[] moved = compromised.rewrapTo(replacement, r, AAD);
        assertEquals(replacement.id(), KmsKeys.sealedKeyId(moved));
        assertArrayEquals(PLAIN, replacement.open(moved, AAD));
        assertSame(moved, compromised.rewrapTo(replacement, moved, AAD), "repeatable");
      }
    } finally {
      KeyHandle.beforeWipe = null;
    }
    assertEquals(2, wiped.size());
    for (byte[] w : wiped) {
      assertEquals(PLAIN.length, w.length);
      assertArrayEquals(new byte[PLAIN.length], w, "wiped after use");
    }
    // Without the opt-in the compromised record is refused, and a target that cannot decrypt is
    // refused before anything is opened.
    assertState(
        assertThrows(KmsException.class, () -> replacement.rewrap(record, AAD)),
        kek.id(),
        "COMPROMISED");
    KeyHandle encryptOnly = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
    long decrypts = sentOf(server, Operation.DECRYPT);
    assertThrows(KeyMismatchException.class, () -> compromised.rewrapTo(encryptOnly, record, AAD));
    assertEquals(decrypts, sentOf(server, Operation.DECRYPT));
  }

  @Test
  void rewrapKeyMovesAWrappedDataKeyWithItsSpec() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server, server.configure());
    KeyHandle old = vault(kms).findOrCreate();
    KeyHandle current = old.rotate();
    List<byte[]> wiped = new CopyOnWriteArrayList<>();
    KeyHandle.beforeWipe = wiped::add;
    try (DataKey dk = old.generateDataKey(256, AAD)) {
      Ciphertext moved = current.rewrapKey(dk.wrapped(), AAD);
      assertEquals(current.id(), moved.keyId());
      assertEquals(dk.wrapped().specName(), moved.specName());
      try (DestroyableSecretKey back = current.unwrapKey(Expect.aes(256), moved, AAD)) {
        assertArrayEquals(dk.key().getEncoded(), back.getEncoded());
      }
      assertSame(moved, current.rewrapKey(moved, AAD));
      KeyHandle wrapping =
          kms.keys().createAes(256).usages(KeyUsage.WRAP_KEY, KeyUsage.UNWRAP_KEY).create();
      Ciphertext kw = wrapping.wrapKey(CipherSpec.keyWrap(), dk.key(), null);
      KeyHandle next =
          kms.keys().createAes(256).usages(KeyUsage.WRAP_KEY, KeyUsage.UNWRAP_KEY).create();
      Ciphertext kwMoved = wrapping.rewrapKeyTo(next, kw, null);
      assertEquals(kw.specName(), kwMoved.specName());
      assertArrayEquals(
          dk.key().getEncoded(), next.unwrapKey(Expect.aes(256), kwMoved, null).getEncoded());
    } finally {
      KeyHandle.beforeWipe = null;
    }
    assertEquals(2, wiped.size());
    for (byte[] w : wiped) assertArrayEquals(new byte[32], w);
  }

  // ---- a stale handle can tell ----

  @Test
  void aStaleHandleCanTellAndTheListenerHears() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms first = connect(server, server.configure());
    Map<String, List<String>> stale = new java.util.concurrent.ConcurrentHashMap<>();
    KmsListener listener =
        new KmsListener() {
          @Override
          public void staleHandle(String keyId, List<String> replacements) {
            stale.put(keyId, replacements);
          }
        };
    Kms second = connect(server, server.configure().addListener(listener));
    KeyHandle mine = vault(first).findOrCreate();
    KeyHandle theirs = vault(second).findOrCreate();
    assertEquals(mine.id(), theirs.id());
    int before = server.exchanges();
    assertTrue(theirs.isLatest());
    assertEquals(before + 1, server.exchanges(), "one Get Attributes");
    assertEquals(Map.of(), stale);
    // The first instance rotates; the second keeps sealing under the old key without an error...
    KeyHandle current = mine.rotate();
    byte[] record = theirs.seal(PLAIN, AAD);
    assertEquals(mine.id(), KmsKeys.sealedKeyId(record));
    assertEquals(Map.of(), stale, "sealing reads nothing");
    // ...until it asks, or reads its key for another reason.
    assertFalse(theirs.isLatest());
    assertEquals(Map.of(mine.id(), List.of(current.id())), stale);
    stale.clear();
    theirs.open(current.seal(PLAIN, AAD), AAD);
    assertEquals(Map.of(mine.id(), List.of(current.id())), stale);
    stale.clear();
    KeyHandle refreshed = theirs.latest();
    assertTrue(refreshed.isLatest());
    refreshed.open(record, AAD);
    assertEquals(Map.of(), stale);
  }

  // ---- the README's advice runs on every version ----

  @Test
  void aCustomAttributeQueryReplacesGroupsOnEveryVersion() {
    for (KmipVersion v : CROSS_VERSIONS) {
      InMemoryKmipServer server = InMemoryKmipServer.of(v);
      Kms kms =
          connect(
              server,
              server.configure().minimumVersion(KmipVersion.V1_2).maximumVersion(KmipVersion.V3_0));
      CustomAttribute purpose = CustomAttribute.client("purpose");
      KeyHandle kek =
          kms.keys()
              .createAes(256)
              .named("orders-kek")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .custom(purpose, "orders")
              .findOrCreate();
      CipherSpec spec =
          v.protocolValue().atLeast(ProtocolVersion.V1_4) ? CipherSpec.aesGcm() : CipherSpec.cbc();
      Ciphertext old = kek.encrypt(spec, PLAIN, null);
      KeyHandle current = kek.rotate().rotate();
      KeyQuery orders = KeyQuery.all().custom(purpose, "orders");
      int before = server.exchanges();
      byte[] back =
          spec.authenticated()
              ? kms.keys().decrypt(orders, old, null)
              : kms.keys().handle(current.id()).decrypt(spec, old, null);
      assertArrayEquals(PLAIN, back, v.toString());
      if (spec.authenticated())
        assertEquals(before + 2, server.exchanges(), v + ": the named key matches directly");
      // Groups stay unavailable on the 3.0 draft, and the refusal names the alternative.
      if (v == KmipVersion.V3_0) {
        UnsupportedException e =
            assertThrows(
                UnsupportedException.class,
                () -> kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).group("orders").create());
        assertTrue(e.getMessage().contains("custom attribute"), e.getMessage());
      }
    }
  }
}
