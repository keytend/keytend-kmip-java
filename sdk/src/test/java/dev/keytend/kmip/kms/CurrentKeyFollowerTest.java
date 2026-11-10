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
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * A {@link CurrentKey} that checks on a caller's executor, so no
 * call waits for a lineage walk ({@code refreshingEvery}); {@code onChange} for every change of the
 * key held; {@code close}. (Raw keys go through {@link LocalKeys}.)
 */
class CurrentKeyFollowerTest {
  static final byte[] PLAIN = {1, 2, 3};
  static final byte[] AAD = "record".getBytes(StandardCharsets.UTF_8);

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();
  final List<ScheduledThreadPoolExecutor> executors = new CopyOnWriteArrayList<>();
  final Heard heard = new Heard();

  @AfterEach
  void cleanUp() {
    executors.forEach(ScheduledThreadPoolExecutor::shutdownNow);
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) {
      assertEquals(List.of(), s.violations());
      s.close();
    }
  }

  /** What the {@link KmsListener} heard. */
  static final class Heard implements KmsListener {
    final List<String> checkFailed = new CopyOnWriteArrayList<>();

    /** Set to hold the thread whose request starts while it is set, until released. */
    volatile Thread hold;

    final CountDownLatch held = new CountDownLatch(1);
    final CountDownLatch release = new CountDownLatch(1);

    @Override
    public void started(KmsEvent event) {
      if (Thread.currentThread() != hold) return;
      held.countDown();
      try {
        release.await(10, TimeUnit.SECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
    }

    @Override
    public void currentKeyCheckFailed(String keyId, int failuresInARow, KmsException failure) {
      checkFailed.add(keyId + " " + failuresInARow);
    }
  }

  /** An executor whose fixed-delay tasks run only when the test says ({@link #check()}). */
  static final class Manual extends ScheduledThreadPoolExecutor {
    final List<Runnable> tasks = new CopyOnWriteArrayList<>();
    final List<ScheduledFuture<?>> futures = new CopyOnWriteArrayList<>();
    final List<Long> delays = new CopyOnWriteArrayList<>();

    Manual() {
      super(1);
    }

    @Override
    public ScheduledFuture<?> scheduleWithFixedDelay(
        Runnable command, long initialDelay, long delay, TimeUnit unit) {
      tasks.add(command);
      delays.add(unit.toNanos(initialDelay));
      delays.add(unit.toNanos(delay));
      ScheduledFuture<?> f = super.schedule(() -> {}, 365, TimeUnit.DAYS);
      futures.add(f);
      return f;
    }

    /** Runs the scheduled check(s) now, on this thread. */
    void check() {
      tasks.forEach(Runnable::run);
    }
  }

  Manual manual() {
    Manual m = new Manual();
    executors.add(m);
    return m;
  }

  InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    servers.add(s);
    return s;
  }

  Kms connect(InMemoryKmipServer s) {
    Kms kms = Kms.connect(s.configure().retryPolicy(RetryPolicy.none()).addListener(heard).build());
    clients.add(kms);
    return kms;
  }

  static KeyHandle aes(Kms kms) {
    return kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
  }

  /** A follower of {@code key} on a clock that only the test moves. */
  static CurrentKey following(Kms kms, KeyHandle key, long[] clock) {
    return new CurrentKey(kms.keys().handle(key.id()), Duration.ofMinutes(1), () -> clock[0]);
  }

  static int sent(InMemoryKmipServer s, Operation operation) {
    return RotationGraceTest.sent(s, operation);
  }

  /**
   * A refreshing follower never checks on a caller's thread, also long after its interval: seal,
   * open and handle send no Get Attributes, and do not wait while a scheduled check is held inside
   * its first request. The check, run on another thread, moves it to the key another instance made,
   * and the next seal goes under that key. The schedule is a fixed delay of the interval.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRefreshingFollowerNeverChecksOnTheCallersThread(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms);
    long[] clock = {0};
    Manual executor = manual();
    CurrentKey kek = following(kms, key, clock).refreshingEvery(Duration.ofMinutes(1), executor);
    long minute = Duration.ofMinutes(1).toNanos();
    assertEquals(List.of(minute, minute), executor.delays);
    byte[] sealed = kek.seal(PLAIN, AAD);
    KeyHandle replacement = kms.keys().handle(key.id()).rotate();

    clock[0] += Duration.ofHours(1).toNanos();
    int reads = sent(s, Operation.GET_ATTRIBUTES);
    assertEquals(key.id(), KmsKeys.sealedKeyId(kek.seal(PLAIN, AAD)));
    assertArrayEquals(PLAIN, kek.open(sealed, AAD));
    assertEquals(key.id(), kek.handle().id());
    // open reads the record's key once (the handle's own attributes); no check walks the lineage.
    assertTrue(sent(s, Operation.GET_ATTRIBUTES) - reads <= 1, "no check on the caller's thread");

    heard.hold = new Thread(executor::check);
    heard.hold.start();
    assertTrue(heard.held.await(5, TimeUnit.SECONDS));
    try {
      long start = System.nanoTime();
      assertEquals(
          key.id(),
          KmsKeys.sealedKeyId(kek.seal(PLAIN, AAD)),
          "sealing goes on while the check runs");
      assertEquals(key.id(), kek.handle().id());
      assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 2_000);
    } finally {
      heard.release.countDown();
      heard.hold.join(5_000);
    }
    assertEquals(replacement.id(), kek.handle().id());
    assertEquals(replacement.id(), KmsKeys.sealedKeyId(kek.seal(PLAIN, AAD)));
  }

  /**
   * A scheduled check that fails is told to the listener (1, then 2 in a row) and passed over; the
   * schedule goes on and the next check moves the key. A check that throws something else (here a
   * listener that throws an Error) does not end it either.
   */
  @Test
  void aFailedScheduledCheckIsToldAndTheNextOneMoves() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    KeyHandle key = aes(kms);
    Manual executor = manual();
    CurrentKey kek = kms.keys().current(key).refreshingEvery(Duration.ofSeconds(30), executor);
    KeyHandle replacement = kms.keys().handle(key.id()).rotate();
    s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.SERVER_FAILURE);
    executor.check();
    s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.SERVER_FAILURE);
    executor.check();
    assertEquals(List.of(key.id() + " 1", key.id() + " 2"), heard.checkFailed);
    assertEquals(key.id(), kek.handle().id());
    kek.onChange(
        k -> {
          throw new AssertionError("a listener's Error");
        });
    executor.check();
    assertEquals(replacement.id(), kek.handle().id());
    KeyHandle third = kms.keys().handle(replacement.id()).rotate();
    executor.check();
    assertEquals(third.id(), kek.handle().id(), "the schedule goes on");
  }

  /** The schedule, on a real executor: a rotation elsewhere is followed without any call. */
  @Test
  void aRealExecutorFollowsARotation() throws Exception {
    Kms kms = connect(server(KmipVersion.V2_1));
    KeyHandle key = aes(kms);
    ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(1);
    executor.setRemoveOnCancelPolicy(true);
    executors.add(executor);
    CurrentKey kek = kms.keys().current(key).refreshingEvery(Duration.ofMillis(10), executor);
    CountDownLatch moved = new CountDownLatch(1);
    AtomicReference<String> to = new AtomicReference<>();
    kek.onChange(
        k -> {
          to.set(k.id());
          moved.countDown();
        });
    KeyHandle replacement = kms.keys().handle(key.id()).rotate();
    assertTrue(moved.await(10, TimeUnit.SECONDS));
    assertEquals(replacement.id(), to.get());
    kek.close();
    // A run that had just ended when close() canceled it is queued once more, canceled, and the
    // executor drops it when it is due (a few milliseconds).
    RecordingTlsServer.await(() -> executor.getQueue().isEmpty(), "close canceled the task");
  }

  /**
   * {@code close()} cancels the scheduled task; a check that runs after it sends nothing and moves
   * nothing, while the object goes on working and still follows a refusal. Idempotent; nothing on a
   * follower that schedules nothing.
   */
  @Test
  void closeStopsTheChecksOnly() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    KeyHandle k0 = aes(kms);
    Manual executor = manual();
    CurrentKey sync = kms.keys().current(k0);
    sync.close();
    CurrentKey kek = sync.refreshingEvery(Duration.ofMinutes(1), executor);
    kek.seal(PLAIN, AAD);
    kek.close();
    kek.close();
    assertTrue(executor.futures.get(0).isCancelled());
    KeyHandle k1 = kms.keys().handle(k0.id()).rotate();
    long before = s.exchanges();
    executor.check();
    assertEquals(before, s.exchanges());
    assertEquals(k0.id(), kek.handle().id());
    kms.keys().handle(k0.id()).deactivate();
    assertEquals(k1.id(), KmsKeys.sealedKeyId(kek.seal(PLAIN, AAD)), "a refusal is still followed");
    assertEquals(k1.id(), KmsKeys.sealedKeyId(sync.seal(PLAIN, AAD)));
  }

  /** Arguments are checked before anything is scheduled. */
  @Test
  void refreshingEveryChecksItsArguments() {
    Kms kms = connect(server(KmipVersion.V2_1));
    CurrentKey kek = kms.keys().current(aes(kms));
    Manual executor = manual();
    assertThrows(
        IllegalArgumentException.class, () -> kek.refreshingEvery(Duration.ZERO, executor));
    assertThrows(
        IllegalArgumentException.class,
        () -> kek.refreshingEvery(Duration.ofSeconds(-1), executor));
    assertThrows(
        NullPointerException.class, () -> kek.refreshingEvery(Duration.ofSeconds(1), null));
    assertThrows(NullPointerException.class, () -> kek.refreshingEvery(null, executor));
    assertEquals(List.of(), executor.tasks);
    executor.shutdown();
    assertThrows(
        java.util.concurrent.RejectedExecutionException.class,
        () ->
            kek.refreshingEvery(
                Duration.ofSeconds(1),
                new ScheduledThreadPoolExecutor(1) {
                  {
                    shutdown();
                  }
                }));
  }
}
