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

package dev.keytend.kmip.testing;

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.*;
import dev.keytend.kmip.model.Enums.ResultReason;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.transport.CallContext;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * The in-memory server's {@link Fault#HANG} and {@link Fault#SLOW},
 * replicas sharing one store, and unique-name mode. Timing bounds are generous upward (a loaded
 * machine) and exact downward (the server measures its waits with {@code System.nanoTime()}).
 */
class InMemoryReplicasTest {
  final List<Kms> clients = new ArrayList<>();
  final ExecutorService pool = Executors.newCachedThreadPool();

  @AfterEach
  void cleanUp() {
    pool.shutdownNow();
    clients.forEach(Kms::close);
  }

  Kms connect(KmsConfig.Builder config) {
    Kms kms = Kms.connect(config.build());
    clients.add(kms);
    return kms;
  }

  Kms connect(InMemoryKmipServer server, Duration callTimeout) {
    return connect(server.configure().retryPolicy(RetryPolicy.none()).callTimeout(callTimeout));
  }

  static KeyHandle aes(Kms kms) {
    return kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
  }

  static long millisSince(long start) {
    return TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
  }

  /** Waits until {@code server} has received {@code count} requests. */
  static void awaitExchanges(InMemoryKmipServer server, int count) throws InterruptedException {
    long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (server.exchanges() < count) {
      assertTrue(System.nanoTime() < end, "the request did not arrive");
      Thread.sleep(5);
    }
  }

  @Test
  void aHungReadFailsAtTheDeadlineWhileTheServerKeepsAnsweringOthers() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms other = connect(server, Duration.ofSeconds(10));
    KeyHandle key = aes(other);
    Kms hung = connect(server, Duration.ofMillis(500));
    int before = server.exchanges();

    server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.HANG);
    long start = System.nanoTime();
    Future<KmsException> read =
        pool.submit(
            () -> assertThrows(TransientException.class, hung.keys().handle(key.id())::attributes));
    awaitExchanges(server, before + 1);
    // The hung request does not hold the server: another client is answered meanwhile.
    assertEquals(KeyState.ACTIVE, key.attributes().state());
    assertFalse(read.isDone(), "answered while the other request hangs");

    KmsException e = read.get(5, TimeUnit.SECONDS);
    long elapsed = millisSince(start);
    assertEquals(KmsException.Category.RETRY, e.category());
    assertTrue(elapsed >= 480 && elapsed < 2500, elapsed + " ms");
    assertEquals(KeyState.ACTIVE, key.attributes().state(), "the next read is answered");
    assertEquals(List.of(), server.violations());
  }

  @Test
  void aHungMutationIsOutcomeUnknownAtTheDeadlineAndChangesNothing() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V1_4);
    Kms kms = connect(server, Duration.ofMillis(300));
    aes(kms);
    List<String> ids = server.ids();

    server.failNext(ServerOperation.CREATE, Fault.HANG);
    long start = System.nanoTime();
    assertThrows(OutcomeUnknownException.class, () -> aes(kms));
    long elapsed = millisSince(start);
    assertTrue(elapsed >= 280 && elapsed < 2000, elapsed + " ms");
    assertEquals(ids, server.ids(), "nothing was processed");
    assertEquals(List.of(), server.violations());
  }

  /** At the transport: a hung exchange ends on cancellation, and on interruption (flag kept). */
  @Test
  void aHungExchangeEndsWhenCanceledOrInterrupted() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server, Duration.ofSeconds(10));
    aes(kms).attributes();
    List<Ttlv> sent = server.protocolRequests();
    Ttlv getAttributes = sent.get(sent.size() - 1);

    server.failNext(ServerOperation.ANY, Fault.HANG);
    CallContext context = CallContext.cancellable();
    long start = System.nanoTime();
    pool.submit(
        () -> {
          Thread.sleep(150);
          context.cancel();
          return null;
        });
    InterruptedIOException canceled =
        assertThrows(InterruptedIOException.class, () -> server.exchange(getAttributes, context));
    assertFalse(canceled instanceof SocketTimeoutException);
    long elapsed = millisSince(start);
    assertTrue(elapsed >= 140 && elapsed < 2000, elapsed + " ms");

    server.failNext(ServerOperation.ANY, Fault.HANG);
    Thread caller = Thread.currentThread();
    pool.submit(
        () -> {
          awaitExchanges(server, sent.size() + 2);
          Thread.sleep(50);
          caller.interrupt();
          return null;
        });
    try {
      assertThrows(InterruptedIOException.class, () -> server.exchange(getAttributes));
      assertTrue(Thread.currentThread().isInterrupted(), "the interrupt flag is kept");
    } finally {
      Thread.interrupted();
    }

    server.failNext(ServerOperation.ANY, Fault.HANG);
    SocketTimeoutException timedOut =
        assertThrows(
            SocketTimeoutException.class,
            () -> server.exchange(getAttributes, CallContext.withTimeout(Duration.ofMillis(100))));
    assertEquals("KMIP exchange deadline exceeded", timedOut.getMessage());
    assertEquals(List.of(), server.violations());
  }

  @Test
  void aSlowReplyArrivesAfterTheDelayOrIsLostAtAnEarlierDeadline() {
    InMemoryKmipServer server =
        InMemoryKmipServer.of(KmipVersion.V2_1).slowReplyDelay(Duration.ofMillis(400));
    Kms patient = connect(server, Duration.ofSeconds(5));
    KeyHandle key = aes(patient);

    server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.SLOW);
    long start = System.nanoTime();
    assertEquals(KeyState.ACTIVE, key.attributes().state());
    long elapsed = millisSince(start);
    assertTrue(elapsed >= 400 && elapsed < 2500, elapsed + " ms");

    // A deadline shorter than the delay: the mutation was processed, its reply lost.
    String id = patient.keys().createAes(128).usages(KeyUsage.ENCRYPT).createPreActive().id();
    KeyHandle staged = patient.withTimeout(Duration.ofMillis(150)).keys().handle(id);
    server.failNext(ServerOperation.ACTIVATE, Fault.SLOW);
    start = System.nanoTime();
    assertThrows(OutcomeUnknownException.class, staged::activate);
    elapsed = millisSince(start);
    assertTrue(elapsed >= 140 && elapsed < 400, elapsed + " ms: the deadline came first");
    assertEquals(Optional.of(KeyState.ACTIVE), server.state(id), "it did take effect");

    assertThrows(
        IllegalArgumentException.class, () -> server.slowReplyDelay(Duration.ofMillis(-1)));
    assertThrows(
        IllegalArgumentException.class, () -> server.slowReplyDelay(Duration.ofMinutes(2)));
    assertEquals(List.of(), server.violations());
  }

  @Test
  void replicasShareObjectsButNotFaultsOrRequestLogs() {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica();
    InMemoryKmipServer c = b.replica();
    Kms viaA = connect(a, Duration.ofSeconds(10));
    Kms viaB = connect(b, Duration.ofSeconds(10));

    KeyHandle key = aes(viaA);
    KeyHandle seen = viaB.keys().handle(key.id());
    assertEquals(KeyState.ACTIVE, seen.attributes().state(), "created through A, read through B");
    KeyHandle second = aes(viaB);
    assertEquals(List.of(key.id(), second.id()), a.ids(), "one identifier sequence");
    assertEquals(a.ids(), c.ids(), "a replica of a replica shares the store");
    assertTrue(c.exists(second.id()));

    a.failNext(ServerOperation.GET_ATTRIBUTES, Fault.NOT_FOUND);
    assertEquals(KeyState.ACTIVE, seen.attributes().state(), "A's fault does not fire on B");
    assertThrows(NotFoundException.class, key::attributes, "it fires on A");

    List<Ttlv> logA = a.protocolRequests(), logB = b.protocolRequests();
    assertEquals(a.exchanges(), logA.size());
    assertEquals(b.exchanges(), logB.size());
    assertFalse(logB.isEmpty());
    for (Ttlv request : logB) assertTrue(logA.stream().noneMatch(r -> r == request));
    assertEquals(0, c.exchanges());

    // Settings are the store's: unique names set on C hold on A.
    c.uniqueNames(true);
    aesNamed(viaA, "shared");
    assertThrows(AlreadyExistsException.class, () -> aesNamed(viaB, "shared"));

    assertThrows(
        IllegalArgumentException.class,
        () -> a.configureReplicas(InMemoryKmipServer.of(KmipVersion.V2_1)));
    assertThrows(IllegalArgumentException.class, () -> a.configureReplicas(b, b));
    assertThrows(IllegalArgumentException.class, () -> a.configureReplicas(a));
    assertEquals(List.of(), a.violations());
    assertEquals(List.of(), b.violations());
  }

  @Test
  void configureReplicasGivesOneEndpointPerReplicaAndReadsFailOver() {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V1_4, KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica();
    List<String> unavailable = new CopyOnWriteArrayList<>();
    List<String> answeredBy = new CopyOnWriteArrayList<>();
    KmsListener listener =
        new KmsListener() {
          @Override
          public void endpointUnavailable(String endpoint, String why) {
            unavailable.add(endpoint);
          }

          @Override
          public void finished(KmsEvent event) {
            if (event.outcome() == KmsEvent.Outcome.SUCCEEDED) answeredBy.add(event.endpoint());
          }
        };
    Kms kms =
        connect(
            a.configureReplicas(b)
                .retryPolicy(
                    RetryPolicy.builder().maxAttempts(2).initialBackoff(Duration.ZERO).build())
                .addListener(listener));
    assertEquals(KmipVersion.V2_1, kms.version(), "configure()'s version range");
    KeyHandle key = aes(kms);
    assertEquals(0, b.exchanges(), "the first endpoint is this server");

    a.failNext(ServerOperation.GET_ATTRIBUTES, Fault.UNREACHABLE);
    assertEquals(KeyState.ACTIVE, key.attributes().state());
    assertEquals(List.of("in-memory:5696"), unavailable);
    assertEquals("in-memory-2:5696", answeredBy.get(answeredBy.size() - 1));
    assertTrue(b.exchanges() > 0, "the second endpoint is the replica");
    assertEquals(List.of(), a.violations());
    assertEquals(List.of(), b.violations());
  }

  static KeyHandle aesNamed(Kms kms, String name) {
    return kms.keys().createAes(256).named(name).usages(KeyUsage.ENCRYPT).create();
  }

  @Test
  void uniqueNamesAreRefusedAsA1xServerDoes() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V1_4).uniqueNames(true);
    Kms kms = connect(server, Duration.ofSeconds(10));
    KeyHandle first = aesNamed(kms, "orders");
    List<String> ids = server.ids();

    KmsException create = assertThrows(KmsException.class, () -> aesNamed(kms, "orders"));
    // KMIP 1.x answers Invalid Field; the SDK confirms with a Locate and reports AlreadyExists.
    assertInstanceOf(AlreadyExistsException.class, create);
    assertEquals(Optional.of(ResultReason.INVALID_FIELD), create.protocolReason());
    assertEquals(Optional.of("Name is not unique: orders"), create.serverMessage());
    assertEquals(ids, server.ids(), "nothing was created");

    KeyHandle other = aesNamed(kms, "other");
    KmsException add = assertThrows(KmsException.class, () -> other.addName("orders"));
    assertEquals(Optional.of(ResultReason.INVALID_FIELD), add.protocolReason());
    assertEquals(List.of("other"), server.names(other.id()));
    other.addName("other-2");
    assertEquals(List.of("other", "other-2"), server.names(other.id()));
    assertEquals(List.of("orders"), server.names(first.id()));
    assertEquals(List.of(), server.violations(), "a refusal is not a violation");
  }

  @Test
  void uniqueNamesAreRefusedAsA2xServerDoes() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1).uniqueNames(true);
    Kms kms = connect(server, Duration.ofSeconds(10));
    KeyHandle first = aesNamed(kms, "orders");
    List<String> ids = server.ids();

    AlreadyExistsException create =
        assertThrows(AlreadyExistsException.class, () -> aesNamed(kms, "orders"));
    assertEquals(Optional.of(ResultReason.NON_UNIQUE_NAME_ATTRIBUTE), create.protocolReason());
    assertEquals(Optional.of("Name is not unique: orders"), create.serverMessage());
    AlreadyExistsException register =
        assertThrows(
            AlreadyExistsException.class,
            () ->
                kms.keys()
                    .register(new SecretKeySpec(new byte[32], "AES"))
                    .named("orders")
                    .usages(KeyUsage.ENCRYPT)
                    .register());
    assertEquals(Optional.of(ResultReason.NON_UNIQUE_NAME_ATTRIBUTE), register.protocolReason());
    // Either half of a key pair: here the public key's name.
    assertThrows(
        AlreadyExistsException.class,
        () ->
            kms.keys()
                .createKeyPair(KeyPairSpec.rsa(2048))
                .named("signer", "orders")
                .privateUsages(KeyUsage.SIGN)
                .publicUsages(KeyUsage.VERIFY)
                .create());
    assertEquals(ids, server.ids(), "nothing was created");

    // Re-key moves the name to the replacement: not a conflict.
    KeyHandle next = first.rotate();
    assertEquals(List.of("orders"), server.names(next.id()));
    assertEquals(List.of(), server.names(first.id()));

    // A destroyed object's name may be used again.
    KeyHandle doomed = aesNamed(kms, "doomed");
    doomed.revoke(RevocationReason.cessationOfOperation("retired"));
    assertThrows(
        AlreadyExistsException.class, () -> aesNamed(kms, "doomed"), "revoked still holds it");
    doomed.destroy();
    KeyHandle reborn = aesNamed(kms, "doomed");
    assertEquals(List.of("doomed"), server.names(reborn.id()));
    assertEquals(List.of(), server.violations(), "a refusal is not a violation");

    // Off (the default), names may be shared.
    InMemoryKmipServer lax = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms laxKms = connect(lax, Duration.ofSeconds(10));
    aesNamed(laxKms, "orders");
    aesNamed(laxKms, "orders");
    assertEquals(2, lax.ids().size());
  }

  /** The replicas of a store share one lock: B waits while A is processing a request. */
  @Test
  void replicasProcessOneRequestAtATimeBetweenThem() throws Exception {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica();
    Kms viaA = connect(a, Duration.ofSeconds(10));
    CountDownLatch inside = new CountDownLatch(1), release = new CountDownLatch(1);
    a.identifierSource(
        () -> {
          inside.countDown();
          try {
            assertTrue(release.await(5, TimeUnit.SECONDS));
          } catch (InterruptedException e) {
            throw new IllegalStateException(e);
          }
          return "key-1";
        });
    Future<KeyHandle> create = pool.submit(() -> aes(viaA));
    assertTrue(inside.await(5, TimeUnit.SECONDS));
    Future<List<String>> inspect = pool.submit(b::ids);
    assertThrows(TimeoutException.class, () -> inspect.get(200, TimeUnit.MILLISECONDS));
    release.countDown();
    assertEquals("key-1", create.get(5, TimeUnit.SECONDS).id());
    assertEquals(List.of("key-1"), inspect.get(5, TimeUnit.SECONDS), "B saw A's finished request");
  }

  @Test
  void replicasCreatingConcurrentlyKeepTheStoreConsistent() throws Exception {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica();
    Kms viaA = connect(a, Duration.ofSeconds(30));
    Kms viaB = connect(b, Duration.ofSeconds(30));
    int each = 200;
    CyclicBarrier start = new CyclicBarrier(2);
    List<Future<List<String>>> runs = new ArrayList<>();
    for (Kms kms : List.of(viaA, viaB))
      runs.add(
          pool.submit(
              () -> {
                start.await();
                List<String> ids = new ArrayList<>();
                for (int i = 0; i < each; i++)
                  ids.add(
                      kms.keys().createAes(128).usages(KeyUsage.ENCRYPT).createPreActive().id());
                return ids;
              }));
    Set<String> created = new HashSet<>();
    for (Future<List<String>> run : runs) created.addAll(run.get(60, TimeUnit.SECONDS));
    assertEquals(2 * each, created.size(), "distinct identifiers");
    assertEquals(created, new HashSet<>(a.ids()));
    assertEquals(2 * each, a.ids().size());
    assertEquals(List.of(), a.violations());
    assertEquals(List.of(), b.violations());
  }
}
