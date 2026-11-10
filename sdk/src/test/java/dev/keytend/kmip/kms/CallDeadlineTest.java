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

import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * A {@link CurrentKey} call has one deadline across its
 * check, its call, and the check and repeated call after a refusal, and waits for another thread's
 * check within it: a step never opens a deadline of its own, so a 200 ms call timeout bounds
 * {@code seal}, and a caller queued behind a long check does not wait for all of it before its own
 * call timeout begins.
 */
class CallDeadlineTest {
  static final byte[] PLAIN = {1, 2, 3};
  static final byte[] AAD = "record".getBytes(StandardCharsets.UTF_8);

  /**
   * How long the recording transport holds the first request after {@link #oneDeadline} starts
   * recording: a later step with a deadline of its own opens it at least this much later.
   */
  static final long PAUSE_MS = 40;

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  /** The deadline ({@code System.nanoTime()}) each request was sent with, in order. */
  final List<Long> deadlines = new CopyOnWriteArrayList<>();

  @TempDir Path dir;

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  InMemoryKmipServer server() {
    InMemoryKmipServer s = InMemoryKmipServer.of(KmipVersion.V2_1);
    servers.add(s);
    return s;
  }

  /**
   * A {@code Kms} whose transport records each request's deadline, holding the first one recorded
   * {@link #PAUSE_MS}.
   */
  Kms recording(InMemoryKmipServer s) {
    KmipTransport transport =
        new KmipTransport() {
          @Override
          public Ttlv exchange(Ttlv request) throws IOException {
            return exchange(request, CallContext.NONE);
          }

          @Override
          public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
            boolean first = deadlines.isEmpty();
            deadlines.add(context.deadlineBefore(Long.MAX_VALUE));
            if (first)
              try {
                Thread.sleep(PAUSE_MS);
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
              }
            return s.exchange(request, context);
          }
        };
    Kms kms =
        Kms.connect(
            s.configure()
                .callTimeout(Duration.ofSeconds(20))
                .retryPolicy(RetryPolicy.none())
                .transport(e -> transport)
                .build());
    clients.add(kms);
    return kms;
  }

  /** Runs {@code call} and asserts it sent {@code atLeast} requests or more, all with one deadline. */
  <T> T oneDeadline(String what, int atLeast, java.util.function.Supplier<T> call) {
    deadlines.clear();
    T result = call.get();
    List<Long> seen = new ArrayList<>(deadlines);
    assertTrue(
        seen.size() >= atLeast,
        what + ": " + seen.size() + " requests, expected at least " + atLeast);
    long spread =
        seen.stream().mapToLong(Long::longValue).max().orElseThrow()
            - seen.stream().mapToLong(Long::longValue).min().orElseThrow();
    // Exactly one: the transport gets the call's deadline itself, never one rebuilt from the time
    // left (which a pause between two clock reads would move).
    assertEquals(
        0,
        spread,
        () ->
            what
                + ": the "
                + seen.size()
                + " requests' deadlines are "
                + Duration.ofNanos(spread)
                + " apart, not one deadline");
    return result;
  }

  static KeyCreation aes(Kms kms) {
    return kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
  }

  /** A due check (Get Attributes) and the Encrypt of the seal share one deadline; so does open's. */
  @Test
  void aDueCheckAndTheCallShareOneDeadline() throws IOException {
    Kms kms = recording(server());
    KeyHandle key = aes(kms).create();
    long[] clock = {0};
    CurrentKey kek =
        new CurrentKey(kms.keys().handle(key.id()), Duration.ofMinutes(1), () -> clock[0]);
    kek.seal(PLAIN, AAD); // reads the usages: not part of what is measured below
    long minute = Duration.ofMinutes(1).toNanos();

    clock[0] += minute;
    byte[] sealed = oneDeadline("seal", 2, () -> kek.seal(PLAIN, AAD));
    clock[0] += minute;
    assertArrayEquals(PLAIN, oneDeadline("open", 3, () -> kek.open(sealed, AAD)));
    clock[0] += minute;
    oneDeadline("handle", 1, kek::handle);
    clock[0] += minute;
    // The record is under the key held: the check only.
    oneDeadline("rewrapRecord", 1, () -> kek.rewrapRecord(sealed, AAD));

    Path file = dir.resolve("sealed");
    clock[0] += minute;
    oneDeadline(
        "sealTo", 2, () -> io(() -> kek.sealTo(file, new ByteArrayInputStream(PLAIN), AAD)));
    clock[0] += minute;
    oneDeadline("openTo", 3, () -> io(() -> kek.openTo(file, dir.resolve("plain"), AAD)));
    assertArrayEquals(PLAIN, Files.readAllBytes(dir.resolve("plain")));
    clock[0] += minute;
    oneDeadline(
        "sealTo CONTENT_ONLY",
        2,
        () ->
            io(
                () ->
                    kek.sealTo(
                        file, new ByteArrayInputStream(PLAIN), AAD, FileDurability.CONTENT_ONLY)));
    clock[0] += minute;
    oneDeadline(
        "openTo CONTENT_ONLY",
        3,
        () -> io(() -> kek.openTo(file, dir.resolve("plain"), AAD, FileDurability.CONTENT_ONLY)));

    // The data-key operations. The check, then Encrypt; or the check, Get Attributes, Decrypt.
    javax.crypto.SecretKey local = new javax.crypto.spec.SecretKeySpec(new byte[32], "AES");
    clock[0] += minute;
    DataKey dk = oneDeadline("generateDataKey", 2, () -> kek.generateDataKey(256, AAD));
    clock[0] += minute;
    Ciphertext wrapped = oneDeadline("wrapKey", 2, () -> kek.wrapKey(local, AAD));
    clock[0] += minute;
    oneDeadline("wrapKey with a spec", 2, () -> kek.wrapKey(CipherSpec.aesGcm(), local, AAD));
    clock[0] += minute;
    assertArrayEquals(
        dk.key().getEncoded(),
        oneDeadline("unwrapKey", 3, () -> kek.unwrapKey(Expect.aes(256), dk.wrapped(), AAD))
            .getEncoded());
    clock[0] += minute;
    oneDeadline("rewrapKey of a key under the key held", 1, () -> kek.rewrapKey(wrapped, AAD));
    Ciphertext older = key.wrapKey(local, AAD);
    KeyHandle newer = kms.keys().handle(key.id()).rotate();
    clock[0] += minute;
    // The check (two Get Attributes, it moves), then Get Attributes, Decrypt and Encrypt.
    assertEquals(
        newer.id(),
        oneDeadline("rewrapKey of an older key", 4, () -> kek.rewrapKey(older, AAD)).keyId());

    // The chunked delegations: the check, then Encrypt; the check, Get Attributes and Decrypt; the
    // check only for a header under the key held.
    byte[] fileId = "file-1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    clock[0] += minute;
    byte[] header;
    try (ChunkedSealer sealer = oneDeadline("chunkedSealer", 2, () -> kek.chunkedSealer(fileId))) {
      header = sealer.header();
    }
    clock[0] += minute;
    oneDeadline("chunkedOpener", 3, () -> kek.chunkedOpener(header, fileId)).close();
    clock[0] += minute;
    assertSame(
        header,
        oneDeadline(
            "rewrapHeader of a header under the key held",
            1,
            () -> kek.rewrapHeader(header, fileId)));
  }

  /**
   * A seal refused because the key held was deactivated, the check that finds its replacement and
   * the repeated seal share one deadline, for {@code seal} and {@code sealTo}.
   */
  @Test
  void aRefusalTheRefreshAndTheRepeatedCallShareOneDeadline() {
    Kms kms = recording(server());
    javax.crypto.SecretKey local = new javax.crypto.spec.SecretKeySpec(new byte[32], "AES");
    for (String call :
        List.of(
            "seal",
            "sealTo",
            "sealTo CONTENT_ONLY",
            "generateDataKey",
            "wrapKey",
            "rewrapKey",
            "chunkedSealer",
            "rewrapHeader")) {
      KeyHandle older = aes(kms).create();
      Ciphertext underOlder = older.wrapKey(local, AAD);
      byte[] headerUnderOlder;
      try (ChunkedSealer sealer = older.chunkedSealer(AAD)) {
        headerUnderOlder = sealer.header();
      }
      KeyHandle old = older.rotate();
      CurrentKey kek = new CurrentKey(kms.keys().handle(old.id()), Duration.ofHours(1), () -> 0);
      kek.seal(PLAIN, AAD);
      KeyHandle replacement = old.rotate();
      old.deactivate();
      Path file = dir.resolve(call);
      // Encrypt (refused), Get Attributes of the old key and of its replacement, Encrypt.
      oneDeadline(
          call,
          4,
          () ->
              switch (call) {
                case "seal" -> kek.seal(PLAIN, AAD);
                case "sealTo" -> io(() -> kek.sealTo(file, new ByteArrayInputStream(PLAIN), AAD));
                case "sealTo CONTENT_ONLY" ->
                    io(
                        () ->
                            kek.sealTo(
                                file,
                                new ByteArrayInputStream(PLAIN),
                                AAD,
                                FileDurability.CONTENT_ONLY));
                case "generateDataKey" -> kek.generateDataKey(256, AAD);
                case "wrapKey" -> kek.wrapKey(local, AAD);
                case "chunkedSealer" -> kek.chunkedSealer(AAD);
                case "rewrapHeader" -> kek.rewrapHeader(headerUnderOlder, AAD);
                default -> kek.rewrapKey(underOlder, AAD);
              });
      assertEquals(replacement.id(), kek.handle().id(), call);
    }
  }

  /**
   * A scheduled check ({@code refreshingEvery}) has one deadline of its own, a call timeout
   * from when it starts, across its lineage walk; the next check gets a new one. Calls on the follower send only their own request.
   */
  @Test
  void aScheduledCheckHasOneDeadlineOfItsOwn() {
    Kms kms = recording(server());
    KeyHandle key = aes(kms).create();
    CurrentKeyFollowerTest.Manual executor = new CurrentKeyFollowerTest.Manual();
    try {
      CurrentKey kek = kms.keys().current(key).refreshingEvery(Duration.ofMinutes(1), executor);
      kek.seal(PLAIN, AAD);
      kms.keys().handle(key.id()).rotate();
      long start = System.nanoTime();
      // Get Attributes of the key held and of its replacement.
      oneDeadline(
          "scheduled check",
          2,
          () -> {
            executor.check();
            return null;
          });
      long deadline = deadlines.get(0);
      long timeout = Duration.ofSeconds(20).toNanos();
      assertTrue(
          deadline - start >= timeout
              && deadline - start < timeout + TimeUnit.MILLISECONDS.toNanos(PAUSE_MS),
          "the check's own call timeout: " + Duration.ofNanos(deadline - start));
      oneDeadline("seal", 1, () -> kek.seal(PLAIN, AAD));
      oneDeadline(
          "the next check",
          2,
          () -> {
            executor.check();
            return null;
          });
      assertTrue(deadlines.get(0) > deadline, "a new deadline");
    } finally {
      executor.shutdownNow();
    }
  }

  /**
   * A 200 ms call timeout, no retries, a due check and an Encrypt each answered
   * after 130 ms. The seal now fails with a timeout within its 200 ms (plus a margin for the
   * scheduler); before, the Encrypt had a deadline of its own and the seal succeeded in 289 ms.
   */
  @Test
  void theReviewsProbeTimesOutWithinItsBudget() {
    InMemoryKmipServer s = server().slowReplyDelay(Duration.ofMillis(130));
    Kms kms =
        Kms.connect(
            s.configure()
                .callTimeout(Duration.ofMillis(200))
                .retryPolicy(RetryPolicy.none())
                .build());
    clients.add(kms);
    KeyHandle key = aes(kms).create();
    CurrentKey kek = kms.keys().current(key).checkingEvery(Duration.ofNanos(1));
    s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.SLOW);
    s.failNext(ServerOperation.ENCRYPT, Fault.SLOW);
    long start = System.nanoTime();
    TransientException e = assertThrows(TransientException.class, () -> kek.seal(PLAIN, AAD));
    long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
    assertTrue(took < 200 + 80, "seal took " + took + " ms with a 200 ms call timeout");
    assertEquals(KmsException.Category.RETRY, e.category());
    assertTrue(timedOut(e), "a timeout: " + e);
  }

  /**
   * A caller whose check is due while another thread's check runs waits for it within its own call
   * timeout and then fails as a timed-out call, not after the other check ends. Here a listener
   * holds the other thread inside its check until the queued call is over; before, the queued
   * call waited on the monitor until then, and then sealed with a whole call timeout of its own.
   * An interrupted wait fails at once, keeping the interrupt flag.
   */
  @Test
  void aCallQueuedBehindAnotherThreadsCheckTimesOutWithinItsBudget() throws Exception {
    InMemoryKmipServer s = server();
    Thread[] holder = new Thread[1];
    CountDownLatch inCheck = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    Kms kms =
        Kms.connect(
            s.configure()
                .callTimeout(Duration.ofMillis(200))
                .retryPolicy(RetryPolicy.none())
                .addListener(
                    new KmsListener() {
                      @Override
                      public void started(KmsEvent event) {
                        if (Thread.currentThread() != holder[0]) return;
                        inCheck.countDown();
                        try {
                          release.await(10, TimeUnit.SECONDS);
                        } catch (InterruptedException e) {
                          Thread.currentThread().interrupt();
                        }
                      }
                    })
                .build());
    clients.add(kms);
    KeyHandle key = aes(kms).create();
    long[] clock = {0};
    CurrentKey kek =
        new CurrentKey(kms.keys().handle(key.id()), Duration.ofMinutes(1), () -> clock[0]);
    kek.seal(PLAIN, AAD);
    clock[0] += Duration.ofMinutes(1).toNanos();

    AtomicReference<Throwable> held = new AtomicReference<>();
    holder[0] =
        new Thread(
            () -> {
              try {
                kek.handle(); // its check stays in the listener until released
              } catch (Throwable t) {
                held.set(t);
              }
            });
    holder[0].start();
    try {
      assertTrue(inCheck.await(5, TimeUnit.SECONDS));
      for (Consumer<CurrentKey> call :
          List.<Consumer<CurrentKey>>of(
              k -> k.seal(PLAIN, AAD),
              CurrentKey::handle,
              CurrentKey::refresh,
              k -> k.moveTo(key))) {
        long start = System.nanoTime();
        TransientException e = assertThrows(TransientException.class, () -> call.accept(kek));
        long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
        assertTrue(took >= 190 && took < 200 + 80, "the queued call failed after " + took + " ms");
        assertEquals(KmsException.Category.RETRY, e.category());
        assertTrue(timedOut(e), "a timeout: " + e);
        assertTrue(e.getMessage().contains("waiting for another call through"), e.getMessage());
      }

      Thread.currentThread().interrupt();
      try {
        long start = System.nanoTime();
        TransientException e = assertThrows(TransientException.class, () -> kek.seal(PLAIN, AAD));
        assertTrue(Thread.currentThread().isInterrupted(), "the interrupt flag is kept");
        assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 100);
        assertInstanceOf(java.io.InterruptedIOException.class, e.getCause());
      } finally {
        Thread.interrupted();
      }
    } finally {
      release.countDown();
      holder[0].join(5_000);
    }
    assertNull(held.get());
    assertEquals(
        key.id(), KmsKeys.sealedKeyId(kek.seal(PLAIN, AAD)), "the object works afterwards");
  }

  /**
   * A queued call that was refused waits for the refresh within its deadline too: the refusal is
   * thrown (as when the refresh fails), with the timeout suppressed on it.
   */
  @Test
  void aRefusedCallQueuedBehindAnotherThreadsCheckGivesUpWithinItsBudget() throws Exception {
    InMemoryKmipServer s = server();
    Thread[] holder = new Thread[1];
    CountDownLatch inCheck = new CountDownLatch(1);
    CountDownLatch release = new CountDownLatch(1);
    Kms kms =
        Kms.connect(
            s.configure()
                .callTimeout(Duration.ofMillis(200))
                .retryPolicy(RetryPolicy.none())
                .addListener(
                    new KmsListener() {
                      @Override
                      public void started(KmsEvent event) {
                        if (Thread.currentThread() != holder[0]) return;
                        inCheck.countDown();
                        try {
                          release.await(10, TimeUnit.SECONDS);
                        } catch (InterruptedException e) {
                          Thread.currentThread().interrupt();
                        }
                      }
                    })
                .build());
    clients.add(kms);
    KeyHandle old = aes(kms).create();
    CurrentKey kek = new CurrentKey(kms.keys().handle(old.id()), Duration.ofHours(1), () -> 0);
    kek.seal(PLAIN, AAD);
    old.rotate();
    old.deactivate();

    holder[0] =
        new Thread(
            () -> {
              try {
                kek.refresh(); // held past its own deadline in the listener: it fails, as it should
              } catch (TransientException expected) {
              }
            });
    holder[0].start();
    try {
      assertTrue(inCheck.await(5, TimeUnit.SECONDS));
      long start = System.nanoTime();
      StateConflictException e =
          assertThrows(StateConflictException.class, () -> kek.seal(PLAIN, AAD));
      long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
      assertTrue(took < 200 + 80, "the refused call gave up after " + took + " ms");
      assertEquals(1, e.getSuppressed().length);
      assertInstanceOf(TransientException.class, e.getSuppressed()[0]);
    } finally {
      release.countDown();
      holder[0].join(5_000);
    }
  }

  /**
   * The audit of the other facades: calls that send several requests send them with one deadline
   * (rotations, recovery, retirement, lineage walks, rewrapping, lookups by name and query).
   */
  @Test
  void otherFacadeCallsThatSendSeveralRequestsShareOneDeadline() throws IOException {
    Kms kms = recording(server());
    KeyHandle first = oneDeadline("findOrCreate", 2, () -> aes(kms).named("audit").findOrCreate());
    byte[] sealed = first.seal(PLAIN, AAD);
    KeyHandle second =
        oneDeadline("rotateIfActiveFor", 3, () -> first.rotateIfActiveFor(Duration.ZERO));
    KeyHandle third = oneDeadline("rotateOrLatest", 2, second::rotateOrLatest);
    KeyHandle fourth =
        oneDeadline("rotate with grace", 2, () -> third.rotate(Rotation.grace(Duration.ofDays(1))));
    oneDeadline("latest", 2, () -> kms.keys().handle(first.id()).latest());
    oneDeadline("isLatest", 2, () -> kms.keys().handle(fourth.id()).isLatest());
    oneDeadline(
        "open through the lineage", 3, () -> kms.keys().handle(fourth.id()).open(sealed, AAD));
    oneDeadline("rewrap", 3, () -> kms.keys().handle(fourth.id()).rewrap(sealed, AAD));
    oneDeadline("findByName", 1, () -> kms.keys().findByName("audit"));
    oneDeadline("reconcile by name", 1, () -> kms.keys().reconcile("audit"));
    oneDeadline("current by name", 1, () -> kms.keys().current("audit"));
    KeyQuery query = KeyQuery.byName("audit");
    oneDeadline("open by query", 3, () -> kms.keys().open(query, sealed, AAD));
    Path file = dir.resolve("audit");
    io(() -> fourth.sealTo(file, new ByteArrayInputStream(PLAIN), AAD));
    oneDeadline(
        "openTo by query",
        2,
        () -> io(() -> kms.keys().openTo(query, file, dir.resolve("audit-plain"), AAD)));
    oneDeadline(
        "compromisedPredecessors",
        2,
        () -> kms.keys().handle(fourth.id()).compromisedPredecessors());
    oneDeadline("leftovers", 2, () -> kms.keys().handle(fourth.id()).leftovers());
    oneDeadline(
        "deactivatePredecessors", 2, () -> kms.keys().handle(fourth.id()).deactivatePredecessors());
    oneDeadline(
        "retirePredecessors",
        2,
        () -> kms.keys().handle(fourth.id()).retirePredecessors(RevocationReason.unspecified()));
    byte[] late = fourth.seal(PLAIN, AAD);
    KeyHandle replacement =
        oneDeadline(
            "replaceCompromised",
            3,
            () ->
                kms.keys()
                    .handle(fourth.id())
                    .replaceCompromised(
                        RevocationReason.keyCompromise("audit", java.time.Instant.now())));
    oneDeadline(
        "rewrapTo",
        3,
        () ->
            kms.keys().handle(fourth.id()).allowingCompromised().rewrapTo(replacement, late, AAD));

    // Retrieval and streams on handles that know nothing of their key yet.
    oneDeadline(
        "asSecretKey",
        2,
        () -> kms.keys().handle(replacement.id()).asSecretKey(Expect.aes(256), LocalUse.DECRYPT));
    java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
    oneDeadline(
        "sealing",
        2,
        () ->
            io(
                () -> {
                  try (SealingStream sealing =
                      kms.keys().handle(replacement.id()).sealing(out, AAD)) {
                    sealing.write(PLAIN);
                    sealing.finish();
                  }
                }));
    oneDeadline(
        "opening",
        2,
        () ->
            io(
                () -> {
                  try (java.io.InputStream in =
                      kms.keys()
                          .handle(replacement.id())
                          .opening(new ByteArrayInputStream(out.toByteArray()), AAD)) {
                    assertArrayEquals(PLAIN, in.readAllBytes());
                  }
                }));
    oneDeadline(
        "register and replace",
        3,
        () ->
            kms.keys()
                .register(new javax.crypto.spec.SecretKeySpec(new byte[32], "AES"))
                .named("audit")
                .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                .replace(kms.keys().handle(replacement.id())));
    KeyPairHandle pair =
        oneDeadline(
            "createKeyPair findOrCreate",
            2,
            () ->
                kms.keys()
                    .createKeyPair(KeyPairSpec.ec(Curve.P_256))
                    .named("audit-private", "audit-public")
                    .privateUsages(KeyUsage.SIGN)
                    .publicUsages(KeyUsage.VERIFY)
                    .findOrCreate());
    oneDeadline("keyPair", 2, () -> kms.keys().keyPair(pair.privateKey().id()));
  }

  /** Whether {@code e}'s causes include a timeout. */
  static boolean timedOut(Throwable e) {
    for (Throwable t = e; t != null; t = t.getCause())
      if (t instanceof SocketTimeoutException) return true;
    return false;
  }

  interface IoCall {
    void run() throws IOException;
  }

  static Object io(IoCall call) {
    try {
      call.run();
      return null;
    } catch (IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
  }
}
