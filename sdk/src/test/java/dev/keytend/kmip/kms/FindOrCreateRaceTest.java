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

import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Two replicas calling {@code findOrCreate()} for one name at the same moment, on a
 * server with random identifiers, settle on one key. Each replica is its own {@link Kms}, so
 * nothing shared inside one {@code Kms} can serialize them; their requests are interleaved by
 * pausing each replica's transport.
 */
class FindOrCreateRaceTest {
  static final String NAME = "orders-key";
  static final byte[] PLAIN = "race".getBytes(StandardCharsets.UTF_8);

  /** Random-looking identifiers; the second sorts before the first. */
  static final List<String> IDS =
      List.of("f47ac10b-58cc-4372-a567-0e02b2c3d479", "0e02b2c3-a567-4372-58cc-f47ac10bd479");

  final List<AutoCloseable> resources = new ArrayList<>();
  final List<Replica> replicas = new ArrayList<>();
  final ExecutorService pool = Executors.newFixedThreadPool(2);

  @AfterEach
  void cleanUp() throws Exception {
    replicas.forEach(r -> r.go.release(100)); // never leave a replica blocked
    pool.shutdownNow();
    for (AutoCloseable r : resources) r.close();
  }

  /**
   * One replica's transport to the shared server. It pauses before the first request carrying
   * each operation in {@code pauseBefore}, and before the request that follows an Activate, until
   * the test releases it.
   */
  static final class Replica implements KmipTransport {
    final String name;
    final InMemoryKmipServer server;
    final Set<Operation> pauseBefore;
    final LinkedBlockingQueue<String> paused = new LinkedBlockingQueue<>();
    final Semaphore go = new Semaphore(0);
    private boolean afterActivate;

    Replica(String name, InMemoryKmipServer server, Set<Operation> pauseBefore) {
      this.name = name;
      this.server = server;
      this.pauseBefore = EnumSet.copyOf(pauseBefore);
    }

    @Override
    public Ttlv exchange(Ttlv request) throws IOException {
      Set<Operation> ops = operations(request);
      boolean pause;
      synchronized (this) {
        pause = afterActivate || ops.stream().anyMatch(pauseBefore::remove);
        afterActivate = false;
      }
      if (pause) {
        paused.add(ops.toString());
        go.acquireUninterruptibly();
      }
      Ttlv response = server.exchange(request);
      if (ops.contains(Operation.ACTIVATE))
        synchronized (this) {
          afterActivate = true;
        }
      return response;
    }

    @Override
    public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
      return exchange(request);
    }

    private static Set<Operation> operations(Ttlv request) {
      Set<Operation> out = EnumSet.noneOf(Operation.class);
      for (Ttlv item : request.children(Tag.BATCH_ITEM))
        item.child(Tag.OPERATION)
            .ifPresent(
                o -> {
                  for (Operation op : Operation.values())
                    if (op.code() == o.intValue()) out.add(op);
                });
      return out;
    }

    /**
     * Waits until this replica pauses, and returns the operations of the request it holds, or
     * returns null if {@code call} finishes first (it sent no further request).
     */
    String awaitPause(Future<?> call) throws InterruptedException {
      long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
      while (System.nanoTime() < deadline) {
        String ops = paused.poll(10, TimeUnit.MILLISECONDS);
        if (ops != null) return ops;
        if (call.isDone()) return null;
      }
      throw new AssertionError("replica " + name + " neither paused nor finished");
    }

    void release() {
      go.release();
    }
  }

  Kms connect(Replica replica) {
    Kms kms =
        Kms.connect(
            replica
                .server
                .configure()
                .transport(endpoint -> replica)
                .retryPolicy(RetryPolicy.none())
                .build());
    resources.add(kms);
    return kms;
  }

  Future<KeyHandle> findOrCreate(Kms kms) {
    return pool.submit(
        () ->
            kms.keys()
                .createAes(256)
                .named(NAME)
                .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                .findOrCreate());
  }

  /**
   * A creates kA and looks the name up again, seeing only kA. Then B creates kB, whose identifier
   * sorts first and whose Initial Date is the same second, and looks it up again, seeing both
   * Pre-Active. Then both activate their own key before either looks again. Whichever key wins,
   * both replicas must end with the same one.
   */
  @Test
  void replicasThatEachActivateTheirOwnKeySettleOnOne() throws Exception {
    Iterator<String> ids = IDS.iterator();
    InMemoryKmipServer server =
        InMemoryKmipServer.of(KmipVersion.V2_1)
            .identifierSource(ids::next)
            .clock(Clock.fixed(Instant.parse("2026-10-27T12:00:00Z"), ZoneOffset.UTC));
    Set<Operation> gates = EnumSet.of(Operation.CREATE, Operation.ACTIVATE);
    Replica a = new Replica("A", server, gates);
    Replica b = new Replica("B", server, gates);
    replicas.add(a);
    replicas.add(b);
    Kms kmsA = connect(a);
    Kms kmsB = connect(b);

    Future<KeyHandle> callA = findOrCreate(kmsA);
    Future<KeyHandle> callB = findOrCreate(kmsB);
    // Both looked the name up and found nothing.
    assertEquals("[CREATE]", a.awaitPause(callA));
    assertEquals("[CREATE]", b.awaitPause(callB));
    // A creates kA, sees only kA, and holds its Activate.
    a.release();
    assertEquals("[ACTIVATE]", a.awaitPause(callA));
    assertEquals(List.of(IDS.get(0)), server.ids());
    // B creates kB (sorts first, same Initial Date), sees both Pre-Active, and holds its Activate.
    b.release();
    assertNotNull(b.awaitPause(callB), "B goes on to activate a key");
    assertEquals(IDS, server.ids(), "both replicas created a key: the race window is open");
    // Both activate before either looks again.
    a.release();
    a.awaitPause(callA);
    b.release();
    b.awaitPause(callB);
    a.release();
    b.release();
    KeyHandle keyA = callA.get(10, TimeUnit.SECONDS);
    KeyHandle keyB = callB.get(10, TimeUnit.SECONDS);

    assertEquals(
        kmsA.keys().handle(IDS.get(0)).attributes().creationDate(),
        kmsA.keys().handle(IDS.get(1)).attributes().creationDate(),
        "created in the same second");
    assertEquals(keyA.id(), keyB.id(), "both replicas use one key");
    Ciphertext sealed = keyA.encrypt(CipherSpec.aesGcm(), PLAIN, null);
    assertArrayEquals(PLAIN, keyB.decrypt(sealed, null));
    assertArrayEquals(PLAIN, keyA.decrypt(keyB.encrypt(CipherSpec.aesGcm(), PLAIN, null), null));
    assertEquals(List.of(), server.violations());
  }
}
