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

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.*;
import java.io.IOException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/**
 * Failure handling: no key material in causes or events, paging against servers that ignore
 * offsets, refused credentials at connect, retried reads, and waits that honor the call deadline.
 */
class KmsFailureHandlingTest {
  static Kms connect(KmsConfig.Builder b) {
    return Kms.connect(b.maximumVersion(KmipVersion.V3_0).build());
  }

  /** Every protocol object reachable from an exception is redacted. */
  static void assertNoKeyMaterial(Throwable t) {
    for (Throwable c = t; c != null; c = c.getCause()) {
      if (c instanceof ProtocolException p && p.response() != null)
        assertTrue(KmsTest.allBytesEmpty(p.response()), "cause " + c);
      if (c instanceof KmipException k) assertTrue(KmsTest.allBytesEmpty(k.result().batchItem()));
      if (c instanceof KmsException k) {
        k.response().ifPresent(r -> assertTrue(KmsTest.allBytesEmpty(r)));
        k.result().ifPresent(r -> assertTrue(KmsTest.allBytesEmpty(r.batchItem())));
      }
    }
  }

  @Test
  void causeChainsAndListenerEventsCarryNoKeyMaterial() {
    InMemoryKmipServer server = new InMemoryKmipServer(ProtocolVersion.V2_1);
    boolean[] lie = {false};
    List<KmsEvent> events = new CopyOnWriteArrayList<>();
    try (Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("kms")
                .retryPolicy(RetryPolicy.none())
                .addListener(
                    new KmsListener() {
                      @Override
                      public void finished(KmsEvent event) {
                        events.add(event);
                      }
                    })
                .transport(
                    e ->
                        request -> {
                          Ttlv response = server.exchange(request);
                          return lie[0] ? KmsTest.replaceIdentifier(response, "other") : response;
                        }))) {
      KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
      lie[0] = true;
      ProtocolViolationException e =
          assertThrows(
              ProtocolViolationException.class,
              () -> key.asSecretKey(Expect.aes(256), LocalUse.DECRYPT));
      assertNoKeyMaterial(e);
      events.stream()
          .flatMap(ev -> ev.failure().stream())
          .forEach(KmsFailureHandlingTest::assertNoKeyMaterial);
    }
  }

  @Test
  void pagingStopsWhenTheServerIgnoresOffsetItems() throws Exception {
    InMemoryKmipServer server = new InMemoryKmipServer(ProtocolVersion.V1_4);
    KmipTransport ignoringOffset = request -> server.exchange(withoutOffset(request));
    try (Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("kms")
                .locatePageSize(2)
                .transport(e -> ignoringOffset))) {
      for (int i = 0; i < 4; i++)
        kms.keys().createAes(128).named("same").usages(KeyUsage.ENCRYPT).createPreActive();
      assertThrows(
          ProtocolViolationException.class,
          () -> kms.keys().locate(KeyQuery.byName("same")).count());
      KmipClient raw = kms.protocol();
      assertThrows(
          ProtocolException.class,
          () -> raw.locateAll(LocateRequest.builder().name("same").build(), 2));
    }
  }

  static Ttlv withoutOffset(Ttlv node) {
    if (node.type() != Ttlv.Type.STRUCTURE) return node;
    return Ttlv.structure(
        node.tag(),
        node.children().stream()
            .filter(c -> c.tag() != Tag.OFFSET_ITEMS.code())
            .map(KmsFailureHandlingTest::withoutOffset)
            .toList());
  }

  @Test
  void refusedCredentialsAtConnectArePermissionDeniedAndNotRepeated() {
    AtomicInteger discovers = new AtomicInteger();
    KmipTransport refusing =
        request -> {
          discovers.incrementAndGet();
          return Faults.failure(request, Enums.ResultReason.AUTHENTICATION_NOT_SUCCESSFUL, "bad");
        };
    assertThrows(
        PermissionDeniedException.class,
        () -> connect(KmsConfig.builder().endpoints("a", "b").transport(e -> refusing)));
    assertEquals(1, discovers.get(), "one attempt, no other headers or endpoints");
  }

  @Test
  void aRetriedReadGoesToTheNextEndpoint() {
    InMemoryKmipServer server = new InMemoryKmipServer(ProtocolVersion.V2_1);
    AtomicInteger first = new AtomicInteger(), second = new AtomicInteger();
    boolean[] stall = {false};
    try (Kms kms =
        connect(
            KmsConfig.builder()
                .endpoints("a", "b")
                .transport(
                    e ->
                        request -> {
                          if (e.host().equals("a")) {
                            first.incrementAndGet();
                            if (stall[0])
                              throw new java.net.SocketTimeoutException("read timed out");
                          } else second.incrementAndGet();
                          return server.exchange(request);
                        }))) {
      KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
      stall[0] = true;
      int before = first.get();
      assertEquals(KeyState.ACTIVE, key.attributes().state());
      assertEquals(before + 1, first.get(), "a was tried once");
      assertTrue(second.get() > 0, "the retry went to b");
    }
  }

  @Test
  void waitingForAPooledConnectionIsInterruptibleAndNotSent() throws Exception {
    try (var server = dev.keytend.kmip.TestKmipServer.answeringQueries()) {
      server.delay(1000);
      try (var t =
          TlsTransport.builder(
                  "localhost", server.port(), dev.keytend.kmip.TestTls.context("client", "server"))
              .pool(1, Duration.ofSeconds(30))
              .build()) {
        Ttlv query =
            Messages.request(
                ProtocolVersion.V1_4, List.of(Requests.query().build()), RequestOptions.DEFAULT);
        ExecutorService pool = Executors.newFixedThreadPool(2);
        pool.submit(() -> t.exchange(query));
        Thread.sleep(200);
        Future<?> waiting = pool.submit(() -> t.exchange(query));
        Thread.sleep(200);
        pool.shutdownNow();
        var e = assertThrows(ExecutionException.class, waiting::get);
        RequestNotSentException notSent =
            assertInstanceOf(RequestNotSentException.class, e.getCause());
        assertTrue(notSent.local());
      }
    }
  }

  @Test
  void hashedPasswordLockWaitHonorsTheCallDeadline() throws Exception {
    CountDownLatch release = new CountDownLatch(1);
    var hashed =
        new HashedPasswordTransport(
            request -> {
              try {
                release.await(5, TimeUnit.SECONDS);
              } catch (InterruptedException ignored) {
              }
              throw new IOException("done");
            },
            "u",
            "p".toCharArray());
    Ttlv query =
        Messages.request(
            ProtocolVersion.V2_1, List.of(Requests.query().build()), RequestOptions.DEFAULT);
    ExecutorService pool = Executors.newSingleThreadExecutor();
    pool.submit(() -> hashed.exchange(query));
    Thread.sleep(100);
    long start = System.nanoTime();
    var e =
        assertThrows(
            RequestNotSentException.class,
            () -> hashed.exchange(query, CallContext.withTimeout(Duration.ofMillis(200))));
    assertTrue(e.local());
    assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(2));
    release.countDown();
    pool.shutdown();
  }
}
