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
import dev.keytend.kmip.transport.RequestNotSentException;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Predicate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** Failover when a probe hangs, and the rest of the deadline for a cut-off endpoint. */
class SlowEndpointFailoverTest {
  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  Kms connect(KmsConfig.Builder builder) {
    Kms kms = Kms.connect(builder.build());
    clients.add(kms);
    return kms;
  }

  static final String A = "in-memory:5696", B = "in-memory-2:5696", C = "in-memory-3:5696";

  /** Records listener events. */
  static final class Recorder implements KmsListener {
    final List<String> unavailable = new CopyOnWriteArrayList<>();
    final List<String> why = new CopyOnWriteArrayList<>();
    final List<KmsEvent> retries = new CopyOnWriteArrayList<>();

    @Override
    public void endpointUnavailable(String endpoint, String reason) {
      unavailable.add(endpoint);
      why.add(reason);
    }

    @Override
    public void retrying(KmsEvent failed, Duration delay) {
      retries.add(failed);
    }
  }

  static boolean is(Ttlv request, Operation op) {
    return Faults.operation(request) == op.code();
  }

  /**
   * {@code inner}, except that a request {@code slow} matches is answered after {@code delay}; when
   * the exchange's deadline comes first it fails there with a read timeout, as the TLS transport
   * does. An interrupt ends the wait ({@link InterruptedIOException}, the flag kept).
   */
  static KmipTransport slow(
      KmipTransport inner, Predicate<Ttlv> slow, Duration delay, AtomicInteger seen) {
    return new KmipTransport() {
      @Override
      public Ttlv exchange(Ttlv request) throws IOException {
        return exchange(request, CallContext.NONE);
      }

      @Override
      public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
        if (slow.test(request)) {
          seen.incrementAndGet();
          long wait =
              Math.min(
                  delay.toNanos(),
                  context.hasDeadline() ? context.remainingNanos() : Long.MAX_VALUE);
          try {
            if (wait > 0) TimeUnit.NANOSECONDS.sleep(wait);
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException("interrupted");
          }
          if (wait < delay.toNanos()) throw new SocketTimeoutException("Read timed out");
        }
        return inner.exchange(request, context);
      }
    };
  }

  /** A transport whose every connection is refused. */
  static KmipTransport refused(AtomicInteger seen) {
    return request -> {
      seen.incrementAndGet();
      throw new RequestNotSentException(
          "refused", new ConnectException("Connection refused"), false);
    };
  }

  static RetryPolicy.Builder noBackoff() {
    return RetryPolicy.builder().initialBackoff(Duration.ZERO).maxBackoff(Duration.ZERO).jitter(0);
  }

  static long millisSince(long start) {
    return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
  }

  // ---- a hung version discovery ----

  /**
   * A hangs on a read, B (never contacted) hangs on the Discover Versions
   * probe sent before the first request, C is healthy. The read must reach C within its deadline,
   * and B count as unhealthy like A.
   */
  @Test
  void aHungDiscoveryFailsOverToTheNextReplica() {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica(), c = a.replica();
    servers.addAll(List.of(a, b, c));
    AtomicInteger bProbes = new AtomicInteger();
    KmipTransport hungProbe =
        slow(b, r -> is(r, Operation.DISCOVER_VERSIONS), Duration.ofSeconds(60), bProbes);
    Recorder events = new Recorder();
    Kms kms =
        connect(
            a.configureReplicas(b, c)
                .transport(
                    e ->
                        e.host().equals("in-memory-2")
                            ? hungProbe
                            : e.host().equals("in-memory") ? a : c)
                .callTimeout(Duration.ofMillis(600))
                .retryPolicy(noBackoff().attemptTimeout(Duration.ofMillis(100)).build())
                .addListener(events));
    KeyHandle key =
        kms.keys().createAes(256).named("x").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    a.failNext(ServerOperation.GET_ATTRIBUTES, Fault.HANG);
    int atC = c.exchanges();
    long start = System.nanoTime();
    assertEquals(KeyState.ACTIVE, key.attributes().state());
    long millis = millisSince(start);
    assertTrue(millis >= 190 && millis < 550, "answered after " + millis + " ms");
    assertEquals(1, bProbes.get());
    // B's silence is ill-health like A's: reported, cooled down, and traffic moved past it.
    assertEquals(List.of(A, B), events.unavailable);
    assertTrue(events.why.get(1).contains("attempt timeout"), events.why.get(1));
    assertTrue(c.exchanges() > atC);
    int before = c.exchanges();
    start = System.nanoTime();
    key.attributes();
    assertTrue(millisSince(start) < 90);
    assertEquals(before + 1, c.exchanges());
    assertEquals(1, bProbes.get());
  }

  /**
   * A probe that times out in a view shorter than the call timeout is the caller's choice: B is not
   * reported or cooled down and traffic stays there. Once B's probes have gone unanswered for
   * a whole configured call timeout, the next timeout moves traffic, still without an event.
   */
  @Test
  void aShortViewsProbeTimeoutStaysLocalUntilTheEndpointIsSilentForACallTimeout() {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica();
    servers.addAll(List.of(a, b));
    AtomicInteger bProbes = new AtomicInteger();
    KmipTransport hungProbe =
        slow(b, r -> is(r, Operation.DISCOVER_VERSIONS), Duration.ofSeconds(60), bProbes);
    Recorder events = new Recorder();
    Kms kms =
        connect(
            a.configureReplicas(b)
                .transport(e -> e.host().equals("in-memory-2") ? hungProbe : a)
                .callTimeout(Duration.ofMillis(600))
                .retryPolicy(noBackoff().maxAttempts(2).cooldown(Duration.ZERO).build())
                .addListener(events));
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    // A refuses once: traffic moves to B, whose probe hangs past the 150 ms view's deadline.
    a.failNext(ServerOperation.GET_ATTRIBUTES, Fault.UNREACHABLE);
    KeyHandle quick = kms.withTimeout(Duration.ofMillis(150)).keys().handle(key.id());
    long start = System.nanoTime();
    assertThrows(TransientException.class, quick::attributes);
    assertEquals(List.of(A), events.unavailable);
    assertEquals(1, bProbes.get());
    // Traffic stayed on B: the next quick call probes B again (A would have answered).
    assertThrows(TransientException.class, quick::attributes);
    assertEquals(2, bProbes.get());
    // Unanswered for a whole call timeout (600 ms): a later timeout moves traffic back to A.
    int failures = 2;
    while (true) {
      try {
        quick.attributes();
        break;
      } catch (TransientException stillOnB) {
        failures++;
        assertTrue(failures < 10, "never left B");
      }
    }
    assertTrue(millisSince(start) >= 590, "left B after " + millisSince(start) + " ms");
    assertEquals(List.of(A), events.unavailable);
  }

  /** The caller's interrupt during a probe says nothing about the endpoint. */
  @Test
  void anInterruptDuringAProbeStaysLocal() throws Exception {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica();
    servers.addAll(List.of(a, b));
    CountDownLatch probing = new CountDownLatch(1);
    AtomicInteger bProbes = new AtomicInteger();
    KmipTransport hungProbe =
        slow(
            b,
            r -> {
              if (!is(r, Operation.DISCOVER_VERSIONS)) return false;
              probing.countDown();
              return true;
            },
            Duration.ofSeconds(60),
            bProbes);
    Recorder events = new Recorder();
    Kms kms =
        connect(
            a.configureReplicas(b)
                .transport(e -> e.host().equals("in-memory-2") ? hungProbe : a)
                .callTimeout(Duration.ofSeconds(5))
                .retryPolicy(noBackoff().maxAttempts(2).cooldown(Duration.ZERO).build())
                .addListener(events));
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    a.failNext(ServerOperation.GET_ATTRIBUTES, Fault.UNREACHABLE);
    Thread caller = Thread.currentThread();
    Thread interrupter =
        new Thread(
            () -> {
              try {
                if (probing.await(5, TimeUnit.SECONDS)) caller.interrupt();
              } catch (InterruptedException ignored) {
              }
            });
    interrupter.start();
    long start = System.nanoTime();
    try {
      assertThrows(TransientException.class, key::attributes);
    } finally {
      interrupter.join();
      Thread.interrupted();
    }
    assertTrue(millisSince(start) < 4000);
    assertEquals(List.of(A), events.unavailable, "B is not reported for the caller's interrupt");
    assertEquals(1, bProbes.get());
  }

  // ---- a cut-off endpoint gets the rest of the deadline when nothing else works ----

  /** A answers Discover Versions slowly but within the deadline, B refuses. */
  @Test
  void connectGivesASlowFirstEndpointTheRestWhenTheOthersFail() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(server);
    AtomicInteger aProbes = new AtomicInteger(), bTries = new AtomicInteger();
    KmipTransport slowA =
        slow(server, r -> is(r, Operation.DISCOVER_VERSIONS), Duration.ofMillis(450), aProbes);
    KmipTransport refusedB = refused(bTries);
    Recorder events = new Recorder();
    long start = System.nanoTime();
    // 900 ms call timeout: A first gets 300 ms (900 / 3 attempts), then the rest after B refuses.
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("a:5696", "b:5696")
                .transport(e -> e.host().equals("a") ? slowA : refusedB)
                .versions(KmipVersion.V2_1)
                .callTimeout(Duration.ofMillis(900))
                .addListener(events));
    long millis = millisSince(start);
    assertTrue(millis >= 700 && millis < 900, "connected after " + millis + " ms");
    assertEquals(2, aProbes.get());
    assertEquals(1, bTries.get());
    assertEquals(List.of("a:5696", "b:5696"), events.unavailable);
    kms.ping();
  }

  /**
   * After connect, A answers slowly; B (never contacted) refuses. With two
   * attempts, the first is cut at the attempt timeout because B was untried; when B fails, A gets
   * the rest of the deadline instead of the call failing with time left.
   */
  @Test
  void aReadGivesACutOffEndpointTheRestWhenTheOthersFail() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(server);
    AtomicBoolean connected = new AtomicBoolean();
    AtomicInteger aSlow = new AtomicInteger(), bTries = new AtomicInteger();
    KmipTransport slowA = slow(server, r -> connected.get(), Duration.ofMillis(450), aSlow);
    KmipTransport refusedB = refused(bTries);
    Recorder events = new Recorder();
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("a:5696", "b:5696")
                .transport(e -> e.host().equals("a") ? slowA : refusedB)
                .versions(KmipVersion.V2_1)
                .callTimeout(Duration.ofMillis(900))
                .retryPolicy(
                    noBackoff().maxAttempts(2).attemptTimeout(Duration.ofMillis(300)).build())
                .addListener(events));
    connected.set(true);
    long start = System.nanoTime();
    kms.ping();
    long millis = millisSince(start);
    assertTrue(millis >= 700 && millis < 900, "answered after " + millis + " ms");
    // One extra request beyond maxAttempts(2), to the endpoint that was cut off.
    assertEquals(2, aSlow.get());
    assertEquals(1, bTries.get());
    assertEquals(List.of("a:5696", "b:5696"), events.unavailable);
    assertEquals(2, events.retries.size());
  }

  /**
   * The read above, cut off at its attempt timeout, with the default attempt timeout (half the
   * deadline at two attempts) and A hanging: the resumed attempt cannot succeed, but the call now
   * uses its deadline instead of failing at half of it, A is sent the read exactly once more, and
   * nothing is resent after that.
   */
  @Test
  void aCutOffEndpointIsResumedOnceAndTheCallEndsAtItsDeadline() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(server);
    AtomicBoolean connected = new AtomicBoolean();
    AtomicInteger aHung = new AtomicInteger(), bTries = new AtomicInteger();
    KmipTransport hungA = slow(server, r -> connected.get(), Duration.ofSeconds(60), aHung);
    KmipTransport refusedB = refused(bTries);
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("a:5696", "b:5696")
                .transport(e -> e.host().equals("a") ? hungA : refusedB)
                .versions(KmipVersion.V2_1)
                .callTimeout(Duration.ofMillis(600))
                .retryPolicy(noBackoff().maxAttempts(2).build()));
    connected.set(true);
    long start = System.nanoTime();
    assertThrows(TransientException.class, kms::ping);
    long millis = millisSince(start);
    assertTrue(millis >= 570, "gave up after " + millis + " ms");
    assertEquals(2, aHung.get());
    assertEquals(1, bTries.get());
  }

  /**
   * An endpoint cut off and then tried again in full within the call (here with three attempts and
   * every endpoint cooling down, so the third goes back to A) is not resumed a second time.
   */
  @Test
  void anEndpointTriedAgainInFullIsNotResumedAsWell() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(server);
    AtomicBoolean connected = new AtomicBoolean();
    AtomicInteger aRequests = new AtomicInteger(),
        bTries = new AtomicInteger(),
        hung = new AtomicInteger();
    KmipTransport hangOnce =
        slow(server, r -> connected.get() && aRequests.get() == 1, Duration.ofSeconds(60), hung);
    KmipTransport aWithDeadline =
        new KmipTransport() {
          @Override
          public Ttlv exchange(Ttlv request) throws IOException {
            return exchange(request, CallContext.NONE);
          }

          @Override
          public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
            if (!connected.get()) return server.exchange(request, context);
            if (aRequests.incrementAndGet() > 1)
              throw new RequestNotSentException(
                  "refused", new ConnectException("Connection refused"), false);
            return hangOnce.exchange(request, context);
          }
        };
    KmipTransport refusedB = refused(bTries);
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("a:5696", "b:5696")
                .transport(e -> e.host().equals("a") ? aWithDeadline : refusedB)
                .versions(KmipVersion.V2_1)
                .callTimeout(Duration.ofMillis(900))
                .retryPolicy(noBackoff().maxAttempts(3).build()));
    connected.set(true);
    long start = System.nanoTime();
    assertThrows(TransientException.class, kms::ping);
    assertTrue(millisSince(start) < 700, "gave up after " + millisSince(start) + " ms");
    assertEquals(1, hung.get());
    assertEquals(2, aRequests.get(), "cut off, then refused; not resumed after the refusal");
    assertEquals(1, bTries.get());
  }

  /** A hung first replica with a healthy second still fails over at the attempt timeout. */
  @Test
  void aHungFirstReplicaStillFailsOverAtTheAttemptTimeout() {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica();
    servers.addAll(List.of(a, b));
    Recorder events = new Recorder();
    Kms kms =
        connect(a.configureReplicas(b).callTimeout(Duration.ofMillis(900)).addListener(events));
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    a.failNext(ServerOperation.GET_ATTRIBUTES, Fault.HANG);
    int atA = a.exchanges();
    long start = System.nanoTime();
    key.attributes();
    long millis = millisSince(start);
    assertTrue(millis >= 290 && millis < 600, "failed over after " + millis + " ms");
    assertEquals(List.of(A), events.unavailable);
    assertEquals(atA + 1, a.exchanges(), "A is not sent the read again");
  }

  // ---- Discover Versions can be failed on purpose ----

  @Test
  void pingFailsWithTheDocumentedCategoryWhenDiscoverVersionsFails() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(server);
    Kms kms = connect(server.configure().retryPolicy(RetryPolicy.none()));
    server.failNext(ServerOperation.DISCOVER_VERSIONS, Fault.UNREACHABLE);
    TransientException down = assertThrows(TransientException.class, kms::ping);
    assertEquals(KmsException.Category.RETRY, down.category());
    assertEquals("ping", down.operation());
    server.failNext(ServerOperation.DISCOVER_VERSIONS, Fault.PERMISSION_DENIED);
    PermissionDeniedException refused = assertThrows(PermissionDeniedException.class, kms::ping);
    assertEquals(KmsException.Category.FIX_ACCESS, refused.category());
    kms.ping();
    // ANY still means the application's own requests: it does not fail a ping.
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    server.failNext(ServerOperation.ANY, Fault.NOT_FOUND);
    kms.ping();
    assertThrows(NotFoundException.class, key::attributes);
  }

  @Test
  void connectFailsOverWhenTheFirstReplicasDiscoverVersionsFails() {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica();
    servers.addAll(List.of(a, b));
    a.failNext(ServerOperation.DISCOVER_VERSIONS, Fault.UNREACHABLE);
    Recorder events = new Recorder();
    Kms kms = connect(a.configureReplicas(b).addListener(events));
    assertEquals(List.of(A), events.unavailable);
    int atB = b.exchanges();
    kms.ping();
    assertEquals(atB + 1, b.exchanges(), "connected through B");
    // A hung negotiation is cut at the attempt timeout (600 ms / 3) like a hung read.
    a.failNext(ServerOperation.DISCOVER_VERSIONS, Fault.HANG);
    Recorder hung = new Recorder();
    long start = System.nanoTime();
    connect(a.configureReplicas(b).callTimeout(Duration.ofMillis(600)).addListener(hung));
    long millis = millisSince(start);
    assertTrue(millis >= 190 && millis < 550, "connected after " + millis + " ms");
    assertEquals(List.of(A), hung.unavailable);
  }

  // ---- the fake refuses a key that cannot be used as a 1.x server does ----

  /** On 1.x the in-memory server answers Permission Denied, and the SDK still reports STATE. */
  @Test
  void aKeyThatCannotBeUsedIsPermissionDeniedOn1xAndStateInTheApi() {
    for (KmipVersion v : List.of(KmipVersion.V1_2, KmipVersion.V1_4, KmipVersion.V2_1)) {
      boolean legacy = v.protocolValue().major() == 1;
      Enums.ResultReason refusal =
          legacy
              ? Enums.ResultReason.PERMISSION_DENIED
              : Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE;
      InMemoryKmipServer server = InMemoryKmipServer.of(v);
      servers.add(server);
      Kms kms = connect(server.configure());
      CipherSpec spec =
          v.protocolValue().atLeast(ProtocolVersion.V1_4) ? CipherSpec.aesGcm() : CipherSpec.cbc();
      KeyHandle aes =
          kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
      assertRefused(
          refusal,
          v,
          assertThrows(KmsException.class, () -> aes.encrypt(spec, new byte[16])),
          "activate()");
      KeyHandle hmac =
          kms.keys()
              .createSymmetric(Algorithm.HMAC_SHA256, 256)
              .usages(KeyUsage.MAC_GENERATE, KeyUsage.MAC_VERIFY)
              .create();
      hmac.revoke(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
      assertRefused(
          refusal,
          v,
          assertThrows(KmsException.class, () -> hmac.mac(MacSpec.keyDefault(), new byte[3])),
          "COMPROMISED");
      if (v.protocolValue().atLeast(ProtocolVersion.V1_4)) {
        KeyPairHandle rsa =
            kms.keys()
                .createKeyPair(KeyPairSpec.rsa(2048))
                .privateUsages(KeyUsage.SIGN)
                .publicUsages(KeyUsage.VERIFY)
                .createPreActive();
        assertRefused(
            refusal,
            v,
            assertThrows(
                KmsException.class,
                () -> rsa.privateKey().sign(SignatureSpec.rsaPss(Hash.SHA_256), new byte[3])),
            "activate()");
      }
    }
  }

  static void assertRefused(
      Enums.ResultReason server, KmipVersion v, KmsException e, String remedy) {
    assertEquals(StateConflictException.class, e.getClass(), v + ": " + e);
    assertTrue(e.getMessage().contains(remedy), e.getMessage());
    // The server's own answer is kept.
    assertEquals(Optional.of(server), e.protocolReason(), v + ": " + e);
  }

  /** The protocol answer itself, also for the operations the SDK checks before sending. */
  @Test
  void everyCryptographicStateRefusalIsPermissionDeniedOn1x() throws Exception {
    for (ProtocolVersion v :
        List.of(
            ProtocolVersion.V1_2,
            ProtocolVersion.V1_4,
            ProtocolVersion.V2_0,
            ProtocolVersion.V3_0)) {
      Enums.ResultReason refusal =
          v.major() == 1
              ? Enums.ResultReason.PERMISSION_DENIED
              : Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE;
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.fromProtocol(v));
      servers.add(server);
      dev.keytend.kmip.client.KmipClient client = new dev.keytend.kmip.client.KmipClient(server, v);
      String id =
          client.createSymmetricKey(
              Enums.CryptographicAlgorithm.AES,
              256,
              Enums.CryptographicUsageMask.ENCRYPT,
              Enums.CryptographicUsageMask.DECRYPT);
      for (dev.keytend.kmip.client.Request r :
          List.of(
              dev.keytend.kmip.client.CryptoRequests.encrypt(id).data(new byte[16]).build(),
              dev.keytend.kmip.client.CryptoRequests.decrypt(id).data(new byte[16]).build())) {
        dev.keytend.kmip.client.Result result = client.execute(r);
        assertTrue(result.hasReason(refusal), v + " " + r.operation() + ": " + result);
      }
    }
  }
}
