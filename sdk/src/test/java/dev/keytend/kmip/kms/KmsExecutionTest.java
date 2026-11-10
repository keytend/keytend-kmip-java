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

import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.*;
import java.io.IOException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.UnaryOperator;
import javax.net.ssl.SSLHandshakeException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Malformed acknowledgments, partial creation, paging, endpoint probing and
 * failover, deadlines, and the classification of local and busy failures.
 */
class KmsExecutionTest {
  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  InMemoryKmipServer server() {
    InMemoryKmipServer s = new InMemoryKmipServer(ProtocolVersion.V2_1);
    servers.add(s);
    return s;
  }

  Kms connect(KmsConfig.Builder b) {
    Kms kms = Kms.connect(b.maximumVersion(KmipVersion.V3_0).build());
    clients.add(kms);
    return kms;
  }

  Kms connect(KmipTransport transport) {
    return connect(KmsConfig.builder().endpoints("kms").transport(e -> transport));
  }

  /** A transport that rewrites the response to operation {@code op}. */
  static KmipTransport rewriting(
      KmipTransport server, Operation op, UnaryOperator<Ttlv> change, boolean[] on) {
    return request -> {
      Ttlv response = server.exchange(request);
      return on[0] && Faults.operation(request) == op.code() ? change.apply(response) : response;
    };
  }

  /** The response with every batch item's payload replaced by {@code payload} (null: removed). */
  static Ttlv withPayload(Ttlv response, Ttlv payload) {
    List<Ttlv> top = new ArrayList<>();
    for (Ttlv t : response.children()) {
      if (t.tag() != Tag.BATCH_ITEM.code()) {
        top.add(t);
        continue;
      }
      List<Ttlv> item = new ArrayList<>();
      for (Ttlv f : t.children()) if (f.tag() != Tag.RESPONSE_PAYLOAD.code()) item.add(f);
      if (payload != null) item.add(payload);
      top.add(Ttlv.structure(Tag.BATCH_ITEM, item));
    }
    return Ttlv.structure(Tag.RESPONSE_MESSAGE, top);
  }

  static KeyHandle aes(Kms kms) {
    return kms.keys()
        .createAes(256)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.MAC_GENERATE)
        .create();
  }

  // ---- malformed acknowledgments ----

  @Test
  void malformedAcknowledgmentsAreViolationsForReadsAndUnknownForMutations() {
    InMemoryKmipServer server = server();
    boolean[] lie = {false};
    KmipTransport t =
        request -> {
          Ttlv response = server.exchange(request);
          if (!lie[0]) return response;
          int op = Faults.operation(request);
          if (op == Operation.MAC_VERIFY.code())
            return KmsTest.replaceIdentifier(response, "another-key");
          if (op == Operation.DESTROY.code() || op == Operation.REVOKE.code())
            return withPayload(response, null);
          return response;
        };
    Kms kms = connect(t);
    KeyHandle hmac =
        kms.keys()
            .createSymmetric(Algorithm.HMAC_SHA256, 256)
            .usages(KeyUsage.MAC_GENERATE, KeyUsage.MAC_VERIFY)
            .create();
    byte[] data = {1, 2, 3};
    byte[] mac = hmac.mac(MacSpec.keyDefault(), data);
    lie[0] = true;
    // A VALID verdict naming another key is not accepted.
    assertThrows(
        ProtocolViolationException.class, () -> hmac.macVerify(MacSpec.keyDefault(), data, mac));
    // Revoke and Destroy answered Success without a payload: the outcome is unknown.
    assertThrows(OutcomeUnknownException.class, () -> hmac.revoke(RevocationReason.unspecified()));
    assertThrows(OutcomeUnknownException.class, hmac::destroy);
  }

  // ---- partial creation ----

  @Test
  void aCreatedKeyWhoseActivationFailedIsAPartialCompletionNotARetry() {
    InMemoryKmipServer server = server();
    boolean[] refuse = {false};
    KmipTransport t =
        request -> {
          if (refuse[0] && Faults.operation(request) == Operation.ACTIVATE.code())
            throw new RequestNotSentException("not sent", new java.net.ConnectException("refused"));
          return server.exchange(request);
        };
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("kms")
                .transport(e -> t)
                .retryPolicy(RetryPolicy.defaults()));
    refuse[0] = true;
    long creates = KmsTest.count(server, Operation.CREATE);
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create());
    assertFalse(e.retryable(), "repeating the call would create a second key");
    assertInstanceOf(TransientException.class, e.getCause());
    assertEquals(creates + 1, KmsTest.count(server, Operation.CREATE));
    KeyHandle created = e.created().get(0);
    assertEquals(Optional.of(created.id()), e.objectId());
    refuse[0] = false;
    assertEquals(KeyState.PRE_ACTIVE, created.attributes().state());
    created.activate();
    assertEquals(KeyState.ACTIVE, created.attributes().state());

    // A key pair: the public key's activation fails after the private key's succeeded.
    boolean[] refusePublic = {false};
    String[] publicId = {null};
    KmipTransport t2 =
        request -> {
          if (refusePublic[0]
              && Faults.operation(request) == Operation.ACTIVATE.code()
              && request
                  .require(Tag.BATCH_ITEM)
                  .require(Tag.REQUEST_PAYLOAD)
                  .child(Tag.UNIQUE_IDENTIFIER)
                  .map(Ttlv::textValue)
                  .orElse("")
                  .equals(publicId[0]))
            return Faults.failure(request, Enums.ResultReason.PERMISSION_DENIED, "no");
          Ttlv response = server.exchange(request);
          if (Faults.operation(request) == Operation.CREATE_KEY_PAIR.code())
            publicId[0] =
                response
                    .require(Tag.BATCH_ITEM)
                    .require(Tag.RESPONSE_PAYLOAD)
                    .require(Tag.PUBLIC_KEY_UNIQUE_IDENTIFIER)
                    .textValue();
          return response;
        };
    Kms pairs = connect(t2);
    refusePublic[0] = true;
    PartialCompletionException p =
        assertThrows(
            PartialCompletionException.class,
            () ->
                pairs
                    .keys()
                    .createKeyPair(KeyPairSpec.ec(256))
                    .privateUsages(KeyUsage.SIGN)
                    .publicUsages(KeyUsage.VERIFY)
                    .create());
    assertEquals(2, p.created().size());
    assertInstanceOf(PermissionDeniedException.class, p.getCause());
    assertEquals(publicId[0], p.created().get(1).id());
  }

  // ---- undecodable responses ----

  @Test
  void undecodableResponsesAreViolationsAndLeakNoValues() throws Exception {
    String secret = "SECRET-4b1d00f5-key-material";
    InMemoryKmipServer server = server();
    boolean[] garble = {false};
    TtlvCodec codec = new TtlvCodec();
    List<KmsEvent> events = new CopyOnWriteArrayList<>();
    KmipTransport t =
        request -> {
          Ttlv response = server.exchange(request);
          if (!garble[0]) return response;
          // A Text String whose bytes are not UTF-8, next to the secret: the decoder must fail
          // without quoting either.
          byte[] bytes =
              codec.encode(
                  Ttlv.structure(Tag.RESPONSE_MESSAGE, Ttlv.text(Tag.RESULT_MESSAGE, secret)));
          bytes[bytes.length - 1 - (8 - (secret.length() % 8)) % 8] = (byte) 0xff;
          return codec.decode(bytes);
        };
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("kms")
                .transport(e -> t)
                .addListener(
                    new KmsListener() {
                      @Override
                      public void finished(KmsEvent event) {
                        events.add(event);
                      }
                    }));
    KeyHandle key = aes(kms);
    garble[0] = true;
    var read = assertThrows(ProtocolViolationException.class, key::attributes);
    var write = assertThrows(OutcomeUnknownException.class, () -> key.addName("n"));
    for (Throwable failure : List.of(read, write))
      for (Throwable c = failure; c != null; c = c.getCause()) {
        assertFalse(String.valueOf(c.getMessage()).contains(secret), c.toString());
        assertFalse(c.toString().contains(secret));
      }
    for (KmsEvent e : events) assertFalse(e.toString().contains(secret));
  }

  // ---- paging ----

  @Test
  void pagingContinuesPastShortPagesAndUsesLocatedItems() {
    InMemoryKmipServer server = server();
    int[] cap = {3};
    boolean[] dropLocatedItems = {true};
    KmipTransport capping =
        request -> {
          Ttlv response = server.exchange(capMaximumItems(request, cap[0]));
          return dropLocatedItems[0] ? stripLocatedItems(response) : response;
        };
    Kms kms =
        connect(KmsConfig.builder().endpoints("kms").locatePageSize(5).transport(e -> capping));
    for (int i = 0; i < 11; i++)
      kms.keys().createAes(128).named("paged").usages(KeyUsage.ENCRYPT).createPreActive();
    // The server returns at most 3 per page although 5 were asked for: nothing is lost.
    assertEquals(11, kms.keys().locate(KeyQuery.byName("paged")).count());
    dropLocatedItems[0] = false;
    assertEquals(11, kms.keys().locate(KeyQuery.byName("paged")).count());
    // A server that ignores Maximum Items returns everything at once: complete, no second page.
    long before = KmsTest.count(server, Operation.LOCATE);
    KmipTransport ignoring = request -> server.exchange(without(request, Tag.MAXIMUM_ITEMS));
    Kms all =
        connect(KmsConfig.builder().endpoints("kms").locatePageSize(5).transport(e -> ignoring));
    long beforeAll = KmsTest.count(server, Operation.LOCATE);
    assertEquals(11, all.keys().locate(KeyQuery.byName("paged")).count());
    assertEquals(beforeAll + 1, KmsTest.count(server, Operation.LOCATE));
    assertTrue(before > 0);
  }

  @Test
  void listGivesEachPageItsOwnCallDeadlineAsLocateDoes() {
    InMemoryKmipServer server = server();
    boolean[] slow = {false};
    // Each request takes 40% of the call timeout: one page fits in it, the whole listing does not.
    Duration timeout = Duration.ofSeconds(1);
    KmipTransport held =
        request -> {
          if (slow[0])
            try {
              Thread.sleep(timeout.toMillis() * 4 / 10);
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
              throw new java.io.InterruptedIOException();
            }
          return server.exchange(request);
        };
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("kms")
                .locatePageSize(1)
                .callTimeout(timeout)
                .transport(e -> held));
    for (int i = 0; i < 4; i++)
      kms.keys().createAes(128).named("listed").usages(KeyUsage.ENCRYPT).createPreActive();
    slow[0] = true;
    long start = System.nanoTime();
    assertEquals(4, kms.keys().list(KeyQuery.byName("listed")).size());
    assertTrue(
        System.nanoTime() - start > timeout.toNanos(), "the listing took longer than one timeout");
    assertEquals(4, kms.keys().locate(KeyQuery.byName("listed")).toList().size());
  }

  @Test
  void aShortRepeatedPageEndsPagingOnlyWithoutATotalAndAFullOneIsAViolation() {
    InMemoryKmipServer server = server();
    KmipTransport ignoringOffset =
        request ->
            stripLocatedItems(server.exchange(KmsFailureHandlingTest.withoutOffset(request)));
    Kms kms =
        connect(
            KmsConfig.builder().endpoints("kms").locatePageSize(5).transport(e -> ignoringOffset));
    for (int i = 0; i < 3; i++)
      kms.keys().createAes(128).named("few").usages(KeyUsage.ENCRYPT).createPreActive();
    // Three matches, page size five: the repeated short page is the end, not an error.
    assertEquals(3, kms.keys().locate(KeyQuery.byName("few")).count());
    for (int i = 0; i < 4; i++)
      kms.keys().createAes(128).named("many").usages(KeyUsage.ENCRYPT).createPreActive();
    Kms small =
        connect(
            KmsConfig.builder().endpoints("kms").locatePageSize(2).transport(e -> ignoringOffset));
    assertThrows(
        ProtocolViolationException.class,
        () -> small.keys().locate(KeyQuery.byName("many")).count());
    // A short page repeated while Located Items says more exist is truncation.
    // This server caps pages at 2 and ignores Offset Items, but reports Located Items 4; before the
    // fix the stream silently ended after 2 of the 4 keys.
    KmipTransport capped =
        request ->
            server.exchange(capMaximumItems(KmsFailureHandlingTest.withoutOffset(request), 2));
    Kms truncating =
        connect(KmsConfig.builder().endpoints("kms").locatePageSize(5).transport(e -> capped));
    ProtocolViolationException e =
        assertThrows(
            ProtocolViolationException.class,
            () -> truncating.keys().locate(KeyQuery.byName("many")).count());
    assertTrue(e.getMessage().contains("Located Items"), e.getMessage());
  }

  static Ttlv capMaximumItems(Ttlv node, int cap) {
    if (node.type() != Ttlv.Type.STRUCTURE) return node;
    List<Ttlv> out = new ArrayList<>();
    for (Ttlv c : node.children())
      out.add(
          c.tag() == Tag.MAXIMUM_ITEMS.code()
              ? Ttlv.integer(Tag.MAXIMUM_ITEMS, Math.min(cap, c.intValue()))
              : capMaximumItems(c, cap));
    return Ttlv.structure(node.tag(), out);
  }

  static Ttlv without(Ttlv node, Tag tag) {
    if (node.type() != Ttlv.Type.STRUCTURE) return node;
    return Ttlv.structure(
        node.tag(),
        node.children().stream()
            .filter(c -> c.tag() != tag.code())
            .map(c -> without(c, tag))
            .toList());
  }

  static Ttlv stripLocatedItems(Ttlv node) {
    if (node.type() != Ttlv.Type.STRUCTURE) return node;
    return Ttlv.structure(
        node.tag(),
        node.children().stream()
            .filter(c -> c.tag() != Tag.LOCATED_ITEMS.code())
            .map(KmsExecutionTest::stripLocatedItems)
            .toList());
  }

  // ---- endpoint probing ----

  @Test
  void probingAReplicaHonorsTheDeadlineAndDoesNotBlockClose() throws Exception {
    InMemoryKmipServer server = server();
    boolean[] firstDown = {false};
    CountDownLatch release = new CountDownLatch(1);
    KmipTransport hanging =
        request -> {
          if (Faults.operation(request) == Operation.DISCOVER_VERSIONS.code())
            try {
              release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
              throw new java.io.InterruptedIOException("interrupted");
            }
          return server.exchange(request);
        };
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("a", "b")
                .callTimeout(Duration.ofMillis(300))
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        e.host().equals("a")
                            ? KmsTest.switchable(server, firstDown)
                            : new KmipTransport() {
                              @Override
                              public Ttlv exchange(Ttlv request) throws IOException {
                                return hanging.exchange(request);
                              }

                              @Override
                              public Ttlv exchange(Ttlv request, CallContext context)
                                  throws IOException {
                                // Honor the call's deadline the way the real transports do.
                                var f =
                                    CompletableFuture.supplyAsync(
                                        () -> {
                                          try {
                                            return hanging.exchange(request);
                                          } catch (IOException x) {
                                            throw new CompletionException(x);
                                          }
                                        });
                                try {
                                  return f.get(
                                      Math.max(1, context.remainingNanos()), TimeUnit.NANOSECONDS);
                                } catch (TimeoutException x) {
                                  throw new java.net.SocketTimeoutException("deadline");
                                } catch (InterruptedException | ExecutionException x) {
                                  throw new IOException(x);
                                }
                              }
                            }));
    KeyHandle key = aes(kms);
    firstDown[0] = true;
    // Two callers reach b while its probe hangs: each is bounded by its own deadline.
    ExecutorService pool = Executors.newFixedThreadPool(2);
    long start = System.nanoTime();
    Future<?> one = pool.submit(() -> assertThrows(TransientException.class, key::attributes));
    Future<?> two = pool.submit(() -> assertThrows(TransientException.class, key::attributes));
    one.get(5, TimeUnit.SECONDS);
    two.get(5, TimeUnit.SECONDS);
    assertTrue(
        System.nanoTime() - start < TimeUnit.MILLISECONDS.toNanos(2000),
        "bounded by the call timeout");
    // close() does not wait for a probe in flight.
    Future<?> probing = pool.submit(() -> assertThrows(RuntimeException.class, key::attributes));
    Thread.sleep(50);
    long closing = System.nanoTime();
    kms.close();
    assertTrue(
        System.nanoTime() - closing < TimeUnit.MILLISECONDS.toNanos(200), "close does not block");
    probing.get(5, TimeUnit.SECONDS);
    release.countDown();
    pool.shutdown();
  }

  // ---- failover ----

  @Test
  void aDefiniteFailureDoesNotMoveTrafficToAnotherEndpoint() {
    InMemoryKmipServer server = server();
    AtomicInteger a = new AtomicInteger(), b = new AtomicInteger();
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("a", "b")
                .transport(
                    e ->
                        request -> {
                          (e.host().equals("a") ? a : b).incrementAndGet();
                          return server.exchange(request);
                        }));
    KeyHandle key = aes(kms);
    assertThrows(NotFoundException.class, () -> kms.keys().handle("missing").attributes());
    assertThrows(StateConflictException.class, key::destroy);
    Ciphertext c = key.encrypt(CipherSpec.aesGcm(), new byte[1]);
    assertThrows(CryptographicFailureException.class, () -> key.decrypt(CipherSpec.cbc(), c, null));
    key.attributes();
    assertEquals(0, b.get(), "every call stayed on a");
  }

  // ---- local and busy failures ----

  @Test
  void localAndBusyFailuresAreClassifiedForWhatTheyAre() throws Exception {
    InMemoryKmipServer server = server();
    Enums.ResultReason[] busy = {null};
    boolean[] internalError = {false};
    AtomicInteger gets = new AtomicInteger();
    KmipTransport t =
        request -> {
          if (internalError[0]) throw new IllegalStateException("bug in a transport");
          if (busy[0] != null) {
            if (Faults.operation(request) == Operation.GET_ATTRIBUTES.code()
                && gets.getAndIncrement() == 0) return Faults.failure(request, busy[0], "busy");
            if (Faults.operation(request) == Operation.ADD_ATTRIBUTE.code())
              return Faults.failure(request, busy[0], "busy");
          }
          return server.exchange(request);
        };
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("kms")
                .transport(e -> t)
                .retryPolicy(RetryPolicy.defaults().toBuilder().maxAttempts(3).build()));
    KeyHandle key = aes(kms);
    // Busy reads are transient and retried; a busy mutation is a server failure, never re-sent.
    busy[0] = Enums.ResultReason.SERVER_LIMIT_EXCEEDED;
    assertEquals(KeyState.ACTIVE, key.attributes().state());
    assertEquals(2, gets.get(), "retried once");
    assertThrows(ServerFailureException.class, () -> key.addName("x"));
    busy[0] = null;
    // An unexpected IllegalStateException inside a call is not "unsupported".
    internalError[0] = true;
    assertThrows(ProtocolViolationException.class, key::attributes);
    assertThrows(OutcomeUnknownException.class, () -> key.addName("x"));
    internalError[0] = false;
    // A request the version cannot express is unsupported, before anything is sent.
    Kms old =
        connect(
            KmsConfig.builder()
                .endpoints("old")
                .minimumVersion(KmipVersion.V1_2)
                .transport(e -> new InMemoryKmipServer(ProtocolVersion.V1_2)));
    KeyPairHandle pair =
        old.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.DECRYPT)
            .publicUsages(KeyUsage.ENCRYPT)
            .create();
    var e =
        assertThrows(
            UnsupportedException.class,
            () -> pair.encrypt(CipherSpec.rsaOaep(Hash.SHA3_256, Hash.SHA_1), new byte[1], null));
    assertTrue(e.getMessage().contains("KMIP 1.2"), e.getMessage());
  }

  @Test
  void aCallRacingCloseIsAnIllegalStateException() throws Exception {
    InMemoryKmipServer server = server();
    CountDownLatch inCall = new CountDownLatch(1), closed = new CountDownLatch(1);
    boolean[] block = {false};
    KmipTransport t =
        new KmipTransport() {
          @Override
          public Ttlv exchange(Ttlv request) throws IOException {
            if (block[0]) {
              inCall.countDown();
              try {
                closed.await(5, TimeUnit.SECONDS);
              } catch (InterruptedException ignored) {
              }
              throw new IOException("transport closed");
            }
            return server.exchange(request);
          }
        };
    Kms kms = connect(t);
    KeyHandle key = aes(kms);
    block[0] = true;
    ExecutorService pool = Executors.newSingleThreadExecutor();
    Future<Throwable> call =
        pool.submit(
            () -> {
              try {
                key.addName("racing");
                return null;
              } catch (Throwable x) {
                return x;
              }
            });
    inCall.await(5, TimeUnit.SECONDS);
    kms.close();
    closed.countDown();
    Throwable failure = call.get(5, TimeUnit.SECONDS);
    IllegalStateException ise = assertInstanceOf(IllegalStateException.class, failure);
    assertInstanceOf(
        OutcomeUnknownException.class, ise.getCause(), "the cause says it may have been sent");
    assertThrows(IllegalStateException.class, key::attributes);
    pool.shutdown();
  }

  // ---- random bytes ----

  @Test
  void randomBytesMustHaveTheRequestedLength() {
    InMemoryKmipServer server = server();
    KmipTransport shortening =
        request -> {
          Ttlv response = server.exchange(request);
          if (Faults.operation(request) != Operation.RNG_RETRIEVE.code()) return response;
          return withPayload(
              response, Ttlv.structure(Tag.RESPONSE_PAYLOAD, Ttlv.bytes(Tag.DATA, new byte[3])));
        };
    Kms kms = connect(shortening);
    assertThrows(ProtocolViolationException.class, () -> kms.random(16));
  }

  // ---- deadlines ----

  @Test
  void theCallTimeoutCoversEveryAttemptAndViewsOverrideIt() {
    InMemoryKmipServer server = server();
    boolean[] slow = {false};
    AtomicInteger attempts = new AtomicInteger();
    KmipTransport t =
        request -> {
          if (slow[0] && Faults.operation(request) == Operation.GET_ATTRIBUTES.code()) {
            attempts.incrementAndGet();
            try {
              Thread.sleep(120);
            } catch (InterruptedException ignored) {
            }
            throw new java.net.SocketTimeoutException("slow");
          }
          return server.exchange(request);
        };
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("kms")
                .transport(e -> t)
                .callTimeout(Duration.ofMillis(400))
                .retryPolicy(RetryPolicy.defaults().toBuilder().maxAttempts(20).build()));
    KeyHandle key = aes(kms);
    slow[0] = true;
    long start = System.nanoTime();
    assertThrows(TransientException.class, key::attributes);
    long elapsed = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
    assertTrue(
        elapsed < 800, "one deadline for all attempts and back-off, took " + elapsed + " ms");
    assertTrue(attempts.get() < 20, "attempts were cut short by the deadline");

    Kms quick = kms.withTimeout(Duration.ofMillis(100));
    assertEquals(Duration.ofMillis(100), quick.callTimeout());
    attempts.set(0);
    start = System.nanoTime();
    assertThrows(TransientException.class, () -> quick.keys().handle(key.id()).attributes());
    assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 400);
    assertEquals(1, attempts.get());
    quick.close();
    slow[0] = false;
    assertEquals(KeyState.ACTIVE, key.attributes().state(), "closing a view leaves the Kms open");
  }

  // ---- untrusted replicas ----

  @Test
  void aReplicaWithAnUntrustedCertificateIsSkippedAtConnect() {
    InMemoryKmipServer server = server();
    KmipTransport untrusted =
        request -> {
          throw new RequestNotSentException(
              "handshake failed",
              new SSLHandshakeException("PKIX path building failed") {
                {
                  initCause(
                      new java.security.cert.CertificateException(
                          "unable to find valid certification path"));
                }
              });
        };
    Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("a", "b")
                .transport(e -> e.host().equals("a") ? untrusted : server));
    assertEquals(KmipVersion.V2_1, kms.version());

    // All endpoints untrusted: the certificate failure is reported, not "unreachable".
    assertThrows(
        PermissionDeniedException.class,
        () -> connect(KmsConfig.builder().endpoints("a", "b").transport(e -> untrusted)));

    // The server refusing this client's certificate stops at once: every replica would.
    AtomicInteger tried = new AtomicInteger();
    KmipTransport refusing =
        request -> {
          tried.incrementAndGet();
          throw new RequestNotSentException(
              "handshake failed",
              new SSLHandshakeException("Received fatal alert: certificate_required"));
        };
    assertThrows(
        PermissionDeniedException.class,
        () -> connect(KmsConfig.builder().endpoints("a", "b").transport(e -> refusing)));
    assertEquals(1, tried.get());
  }
}
