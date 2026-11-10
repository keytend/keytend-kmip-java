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

import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;

/**
 * Call-level events: one {@link KmsListener#callStarted} and one {@link KmsListener#callFinished}
 * per application call, around all its steps and attempts, with one call identifier that every
 * attempt event of the call carries; nothing for a call that sends no request.
 */
class KmsCallEventsTest {
  static final CustomAttribute FAMILY = CustomAttribute.client("call-events-family");

  /** Every call and attempt event, in order. */
  static final class Recorder implements KmsListener {
    final List<KmsEvent> events = new CopyOnWriteArrayList<>();
    volatile Consumer<KmsEvent> onCallFinished = e -> {};

    @Override
    public void callStarted(KmsEvent call) {
      events.add(call);
    }

    @Override
    public void callFinished(KmsEvent call) {
      events.add(call);
      onCallFinished.accept(call);
    }

    @Override
    public void started(KmsEvent event) {
      events.add(event);
    }

    @Override
    public void finished(KmsEvent event) {
      events.add(event);
    }

    void clear() {
      events.clear();
    }

    /** The calls finished, in order. */
    List<KmsEvent> finishedCalls() {
      List<KmsEvent> out = new ArrayList<>();
      for (KmsEvent e : events)
        if (e.kind() == KmsEvent.Kind.CALL && e.outcome() != KmsEvent.Outcome.STARTED) out.add(e);
      return out;
    }

    /** The attempts started, by call. */
    Map<Long, List<KmsEvent>> attemptsByCall() {
      Map<Long, List<KmsEvent>> out = new LinkedHashMap<>();
      for (KmsEvent e : events)
        if (e.kind() == KmsEvent.Kind.ATTEMPT && e.outcome() == KmsEvent.Outcome.STARTED)
          out.computeIfAbsent(e.callId(), id -> new ArrayList<>()).add(e);
      return out;
    }

    /**
     * Checks the rules every sequence obeys: each call starts before its first attempt and
     * finishes after its last, once each; every attempt belongs to a started call; ids are unique
     * and positive; a finished call counts its attempts.
     */
    void checkWellFormed() {
      Map<Long, Integer> attempts = new LinkedHashMap<>();
      Map<Long, String> operations = new LinkedHashMap<>();
      Set<Long> open = new HashSet<>(), done = new HashSet<>();
      for (KmsEvent e : events) {
        assertTrue(e.callId() > 0, "every event has a call id: " + e);
        if (e.kind() == KmsEvent.Kind.CALL && e.outcome() == KmsEvent.Outcome.STARTED) {
          assertTrue(open.add(e.callId()) && !done.contains(e.callId()), "started once: " + e);
          assertEquals(0, e.attempt());
          assertEquals(Duration.ZERO, e.latency());
          assertEquals(e.operation(), e.step());
          attempts.put(e.callId(), 0);
          operations.put(e.callId(), e.operation());
        } else if (e.kind() == KmsEvent.Kind.CALL) {
          assertTrue(open.remove(e.callId()), "finished after it started: " + e);
          done.add(e.callId());
          assertEquals(attempts.get(e.callId()), e.attempt(), "attempts counted: " + e);
          assertEquals(operations.get(e.callId()), e.operation(), "one name: " + e);
          if (e.failure().isPresent()) assertEquals(KmsEvent.Outcome.FAILED, e.outcome());
        } else {
          assertTrue(open.contains(e.callId()), "an attempt within its call: " + e);
          assertEquals(
              operations.get(e.callId()), e.operation(), "an attempt has its call's name: " + e);
          if (e.outcome() == KmsEvent.Outcome.STARTED) attempts.merge(e.callId(), 1, Integer::sum);
        }
      }
      assertEquals(Set.of(), open, "every call finished");
    }
  }

  static KeyHandle create(Kms kms, String name) {
    return kms.keys()
        .createAes(256)
        .named(name)
        .extractable(true)
        .custom(FAMILY, "orders")
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .create();
  }

  @Test
  void aSingleStepCallIsOneCallWithOneAttempt() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    try (Kms kms = Kms.connect(server.configure().addListener(r).build())) {
      KeyHandle key = create(kms, "single");
      r.clear();
      KeyAttributes read = key.attributes();
      assertEquals(key.id(), read.id());
    }
    r.checkWellFormed();
    List<KmsEvent> calls = r.finishedCalls();
    assertEquals(1, calls.size(), r.events.toString());
    KmsEvent call = calls.get(0);
    assertEquals(KmsEvent.Outcome.SUCCEEDED, call.outcome());
    assertEquals(1, call.attempt());
    assertEquals("in-memory:5696", call.endpoint());
    assertEquals(KmipVersion.V2_1, call.version());
    assertTrue(call.toString().startsWith("KmsEvent[call " + call.callId()), call.toString());
    KmsEvent start = r.events.get(0);
    assertEquals(KmsEvent.Kind.CALL, start.kind());
    assertEquals(KmsEvent.Outcome.STARTED, start.outcome());
    assertEquals(call.callId(), start.callId());
    assertEquals(call.operation(), start.operation());
  }

  @Test
  void aMultiStepCallIsOneCall() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    try (Kms kms = Kms.connect(server.configure().addListener(r).build())) {
      KeyHandle created =
          kms.keys()
              .createAes(256)
              .named("multi")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .findOrCreate();
      r.checkWellFormed();
      List<KmsEvent> calls = r.finishedCalls();
      assertEquals(1, calls.size(), r.events.toString());
      KmsEvent call = calls.get(0);
      assertEquals("findOrCreate", call.operation());
      assertEquals(KmsEvent.Outcome.SUCCEEDED, call.outcome());
      List<KmsEvent> attempts = r.attemptsByCall().get(call.callId());
      assertTrue(attempts.size() >= 2, "several steps: " + attempts);
      Set<String> steps = new HashSet<>();
      for (KmsEvent a : attempts) {
        assertEquals("findOrCreate", a.operation());
        steps.add(a.step());
      }
      assertTrue(steps.size() >= 2, "several steps: " + steps);
      assertFalse(call.latency().isNegative());

      // Again: it finds the key, another call with a new id.
      r.clear();
      assertEquals(
          created.id(),
          kms.keys()
              .createAes(256)
              .named("multi")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .findOrCreate()
              .id());
      r.checkWellFormed();
      List<KmsEvent> again = r.finishedCalls();
      assertEquals(1, again.size());
      assertTrue(again.get(0).callId() > call.callId(), "ids grow");
    }
  }

  @Test
  void aRegistrationIsOneCallUnderItsDeadline() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    try (Kms kms = Kms.connect(server.configure().addListener(r).build())) {
      kms.keys()
          .register(new javax.crypto.spec.SecretKeySpec(new byte[32], "AES"))
          .named("registered")
          .usages(KeyUsage.ENCRYPT)
          .register();
    }
    r.checkWellFormed();
    List<KmsEvent> calls = r.finishedCalls();
    assertEquals(1, calls.size(), r.events.toString());
    assertEquals("register", calls.get(0).operation());
    assertTrue(calls.get(0).attempt() >= 3, "register, read back, activate: " + r.events);
  }

  @Test
  void aLocalKeysLoadIsOneCallAndAHitIsNone() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    try (Kms admin = server.connect();
        Kms kms = Kms.connect(server.configure().addListener(r).build())) {
      KeyHandle key = create(admin, "local-keys-call");
      try (LocalKeys cache =
          kms.keys()
              .localKeys("local-keys-call")
              .scope(KeyQuery.all().custom(FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(Duration.ofMinutes(10))
              .open()) {
        r.clear();
        try (LocalKeys.Use use = cache.forEncrypt()) {
          assertEquals(key.id(), use.id());
        }
        r.checkWellFormed();
        List<KmsEvent> calls = r.finishedCalls();
        assertEquals(1, calls.size(), "one call with all of the load's steps: " + r.events);
        assertEquals("localKeys", calls.get(0).operation());
        assertTrue(calls.get(0).attempt() >= 2, calls.toString());
        assertEquals(KmsEvent.Outcome.SUCCEEDED, calls.get(0).outcome());
        r.clear();
        try (LocalKeys.Use use = cache.forEncrypt()) {
          assertEquals(key.id(), use.id());
        }
        assertEquals(List.of(), r.events, "a call served from the cache sends nothing");
      }
    }
  }

  @Test
  void retriesAreAttemptsOfOneCallAndAFailureThenSuccessSucceeds() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    RetryPolicy retry =
        RetryPolicy.builder().maxAttempts(3).initialBackoff(Duration.ofMillis(1)).build();
    try (Kms kms = Kms.connect(server.configure().retryPolicy(retry).addListener(r).build())) {
      KeyHandle key = create(kms, "retried");
      r.clear();
      server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.SERVER_BUSY);
      key.attributes();
    }
    r.checkWellFormed();
    List<KmsEvent> calls = r.finishedCalls();
    assertEquals(1, calls.size(), r.events.toString());
    assertEquals(2, calls.get(0).attempt());
    assertEquals(KmsEvent.Outcome.SUCCEEDED, calls.get(0).outcome());
    assertTrue(calls.get(0).failure().isEmpty(), "the later success clears the failure");
  }

  @Test
  void aFailoverIsOneCallEndingAtTheLastEndpoint() {
    InMemoryKmipServer first = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer second = first.replica();
    Recorder r = new Recorder();
    RetryPolicy retry =
        RetryPolicy.builder().maxAttempts(3).initialBackoff(Duration.ofMillis(1)).build();
    try (Kms kms =
        Kms.connect(first.configureReplicas(second).retryPolicy(retry).addListener(r).build())) {
      KeyHandle key = create(kms, "failover");
      r.clear();
      first.unreachable(true);
      key.attributes();
    }
    r.checkWellFormed();
    List<KmsEvent> calls = r.finishedCalls();
    assertEquals(1, calls.size(), r.events.toString());
    KmsEvent call = calls.get(0);
    assertEquals(2, call.attempt());
    assertEquals("in-memory-2:5696", call.endpoint());
    assertEquals(KmsEvent.Outcome.SUCCEEDED, call.outcome());
    assertEquals("in-memory:5696", r.events.get(0).endpoint(), "started at the first endpoint");
  }

  @Test
  void aCallThatFailsFinishesWithItsFailure() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    try (Kms kms = Kms.connect(server.configure().addListener(r).build())) {
      assertThrows(NotFoundException.class, () -> kms.keys().handle("no-such-key").attributes());
    }
    r.checkWellFormed();
    List<KmsEvent> calls = r.finishedCalls();
    assertEquals(1, calls.size());
    assertEquals(KmsEvent.Outcome.FAILED, calls.get(0).outcome());
    assertInstanceOf(NotFoundException.class, calls.get(0).failure().orElseThrow());
    assertEquals("no-such-key", calls.get(0).objectId().orElseThrow());
  }

  /** The attempts that finished, in order. */
  static List<KmsEvent> finishedAttempts(Recorder r) {
    return r.events.stream()
        .filter(e -> e.kind() == KmsEvent.Kind.ATTEMPT && e.outcome() != KmsEvent.Outcome.STARTED)
        .toList();
  }

  @Test
  void aCallTheSdkRefusesAfterItsRequestsSucceededFailsWithTheRefusal() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    try (Kms kms = Kms.connect(server.configure().addListener(r).build())) {
      KeyHandle key =
          kms.keys()
              .createAes(256)
              .named("decrypt-only")
              .extractable(true)
              .usages(KeyUsage.DECRYPT)
              .create();
      r.clear();
      assertThrows(
          KeyMismatchException.class, () -> key.asSecretKey(Expect.aes(256), LocalUse.ENCRYPT));
    }
    r.checkWellFormed();
    List<KmsEvent> calls = r.finishedCalls();
    assertEquals(1, calls.size(), r.events.toString());
    KmsEvent call = calls.get(0);
    assertEquals("asSecretKey", call.operation(), "named after the method, not its first step");
    assertEquals(KmsEvent.Outcome.FAILED, call.outcome());
    assertInstanceOf(KeyMismatchException.class, call.failure().orElseThrow());
    List<KmsEvent> attempts = finishedAttempts(r);
    assertFalse(attempts.isEmpty());
    for (KmsEvent attempt : attempts) {
      assertEquals(KmsEvent.Outcome.SUCCEEDED, attempt.outcome(), "its requests succeeded");
      assertEquals("asSecretKey", attempt.operation());
    }
    assertEquals("attributes", attempts.get(0).step());
  }

  @Test
  void anExportIsOneCallNamedAfterTheMethod() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    try (Kms kms = Kms.connect(server.configure().addListener(r).build())) {
      KeyHandle key = create(kms, "exported");
      r.clear();
      key.asSecretKey(Expect.aes(256), LocalUse.ENCRYPT).destroy();
    }
    r.checkWellFormed();
    List<KmsEvent> calls = r.finishedCalls();
    assertEquals(1, calls.size(), r.events.toString());
    assertEquals("asSecretKey", calls.get(0).operation());
    assertEquals(KmsEvent.Outcome.SUCCEEDED, calls.get(0).outcome());
  }

  @Test
  void aCallThatHandlesAFailedRequestAndReturnsSucceeds() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    try (Kms kms = Kms.connect(server.configure().addListener(r).build())) {
      KeyHandle key = create(kms, "handled");
      CurrentKey kek = kms.keys().current(key).checkingEvery(Duration.ofNanos(1));
      r.clear();
      server.unreachable(true);
      // The check due fails and is passed over: the method returns the key held.
      assertEquals(key.id(), kek.handle().id());
    }
    r.checkWellFormed();
    List<KmsEvent> calls = r.finishedCalls();
    assertEquals(1, calls.size(), r.events.toString());
    assertEquals("handle", calls.get(0).operation());
    assertEquals(KmsEvent.Outcome.SUCCEEDED, calls.get(0).outcome());
    assertTrue(calls.get(0).failure().isEmpty());
    assertEquals(KmsEvent.Outcome.FAILED, finishedAttempts(r).get(0).outcome());
  }

  @Test
  void aCurrentKeysCallsAreNamedAfterTheirMethodsAlsoWhenACheckIsDue() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    try (Kms kms = Kms.connect(server.configure().addListener(r).build())) {
      KeyHandle key = create(kms, "current-due");
      // Every call is due a check, whose first request is a Get Attributes.
      CurrentKey kek = kms.keys().current(key).checkingEvery(Duration.ofNanos(1));
      Map<String, Runnable> methods = new LinkedHashMap<>();
      byte[][] sealed = {null};
      methods.put("seal", () -> sealed[0] = kek.seal(new byte[] {1, 2, 3}, null));
      methods.put("open", () -> assertArrayEquals(new byte[] {1, 2, 3}, kek.open(sealed[0], null)));
      methods.put("handle", () -> assertEquals(key.id(), kek.handle().id()));
      methods.put("refresh", () -> assertEquals(key.id(), kek.refresh().id()));
      methods.put("latest", () -> assertEquals(key.id(), key.latest().id()));
      for (Map.Entry<String, Runnable> method : methods.entrySet()) {
        r.clear();
        method.getValue().run();
        r.checkWellFormed();
        List<KmsEvent> calls = r.finishedCalls();
        assertEquals(1, calls.size(), method.getKey() + ": " + r.events);
        assertEquals(method.getKey(), calls.get(0).operation(), r.events.toString());
        assertEquals(KmsEvent.Outcome.SUCCEEDED, calls.get(0).outcome());
        assertEquals("attributes", finishedAttempts(r).get(0).step(), "the check's first step");
      }
    }
  }

  @Test
  void aScheduledCheckThatFailsIsAFailedCall() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    java.util.concurrent.CompletableFuture<KmsEvent> finished =
        new java.util.concurrent.CompletableFuture<>();
    java.util.concurrent.ScheduledExecutorService scheduler =
        java.util.concurrent.Executors.newSingleThreadScheduledExecutor();
    try (Kms kms = Kms.connect(server.configure().addListener(r).build())) {
      KeyHandle key = create(kms, "scheduled");
      server.unreachable(true);
      r.clear();
      r.onCallFinished = finished::complete;
      CurrentKey kek = kms.keys().current(key).refreshingEvery(Duration.ofMillis(10), scheduler);
      try {
        KmsEvent call = finished.get(10, java.util.concurrent.TimeUnit.SECONDS);
        assertEquals("refresh", call.operation());
        assertEquals(KmsEvent.Outcome.FAILED, call.outcome(), "the check failed");
        assertInstanceOf(TransientException.class, call.failure().orElseThrow());
        assertEquals(key.id(), kek.handle().id(), "and was passed over");
      } finally {
        kek.close();
      }
    } finally {
      scheduler.shutdownNow();
    }
    r.onCallFinished = e -> {};
    for (KmsEvent e : r.events)
      if (e.callId() == finished.get().callId())
        assertEquals("refresh", e.operation(), "its attempts too: " + e);
  }

  /** A rotation's public methods, each with a grace period the server refuses to set. */
  static Map<String, Consumer<KeyHandle>> graceRotations() {
    Rotation grace = Rotation.grace(Duration.ofDays(1));
    Map<String, Consumer<KeyHandle>> out = new LinkedHashMap<>();
    out.put("rotate", k -> k.rotate(grace));
    out.put("rotateResult", k -> k.rotateResult(grace));
    out.put("rotateOrLatest", k -> k.rotateOrLatest(grace));
    out.put("rotateOrLatestResult", k -> k.rotateOrLatestResult(grace));
    out.put("rotateIfActiveFor", k -> k.rotateIfActiveFor(Duration.ZERO, grace));
    out.put("rotateIfActiveForResult", k -> k.rotateIfActiveForResult(Duration.ZERO, grace));
    out.put("CurrentKey.rotateOrLatest", k -> k.kms.keys().current(k).rotateOrLatest(grace));
    out.put(
        "CurrentKey.rotateIfActiveFor",
        k -> k.kms.keys().current(k).rotateIfActiveFor(Duration.ZERO, grace));
    return out;
  }

  @org.junit.jupiter.params.ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRotationWhoseGracePeriodWasNotScheduledIsAFailedCall(KmipVersion version) {
    for (Map.Entry<String, Consumer<KeyHandle>> method : graceRotations().entrySet()) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version).refuseClientDeactivationDate(true);
      Recorder r = new Recorder();
      try (Kms kms = Kms.connect(server.configure().addListener(r).build())) {
        KeyHandle key = create(kms, "grace-" + method.getKey().replace('.', '-'));
        r.clear();
        PartialCompletionException thrown =
            assertThrows(
                PartialCompletionException.class,
                () -> method.getValue().accept(key),
                method.getKey());
        r.checkWellFormed();
        List<KmsEvent> calls = r.finishedCalls();
        assertEquals(1, calls.size(), method.getKey() + ": " + r.events);
        KmsEvent call = calls.get(0);
        String name = method.getKey().replace("CurrentKey.", "").replace("Result", "");
        assertEquals(name, call.operation(), method.getKey());
        assertEquals(KmsEvent.Outcome.FAILED, call.outcome(), method.getKey());
        assertSame(thrown, call.failure().orElseThrow(), method.getKey());
      }
    }
  }

  @Test
  void aCallThroughTwoConfigurationsTellsASharedListenerOnce() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder shared = new Recorder();
    Recorder second = new Recorder();
    try (TestLogs.Capture logs = TestLogs.capture();
        Kms first = Kms.connect(server.configure().addListener(shared).build());
        Kms other =
            Kms.connect(server.configure().addListener(shared).addListener(second).build())) {
      KeyHandle old = create(first, "migrate-from");
      KeyHandle target = create(other, "migrate-to");
      byte[] sealed = old.seal(new byte[] {4, 5}, null);
      shared.clear();
      second.clear();
      // Migration through another Kms: one call with attempts through both configurations.
      old.rewrapTo(target, sealed, null);
      shared.checkWellFormed();
      List<KmsEvent> calls = shared.finishedCalls();
      assertEquals(1, calls.size(), shared.events.toString());
      assertEquals("rewrapTo", calls.get(0).operation());
      assertEquals(1, second.finishedCalls().size(), "the other configuration's own listener");
      assertEquals(calls.get(0).callId(), second.finishedCalls().get(0).callId());
      long id = calls.get(0).callId();
      List<TestLogs.Event> lines =
          logs.events(
              e ->
                  e.logger().equals(LoggingListener.CALLS)
                      && e.message().matches("Call " + id + " rewrapTo (started|succeeded) .*"));
      assertEquals(2, lines.size(), "the SDK logs it once, started and finished: " + lines);
    }
  }

  @Test
  void everyListenerOfACallHearsTheSameStartAlsoWhenFirstToldByAnotherConfiguration() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder shared = new Recorder();
    Recorder second = new Recorder();
    try (Kms first =
            Kms.connect(
                KmsConfig.builder()
                    .endpoints("source")
                    .transport(e -> server)
                    .addListener(shared)
                    .build());
        Kms other =
            Kms.connect(
                KmsConfig.builder()
                    .endpoints("destination")
                    .transport(e -> server)
                    .addListener(shared)
                    .addListener(second)
                    .build())) {
      KeyHandle old = create(first, "start-from");
      KeyHandle target = create(other, "start-to");
      byte[] sealed = old.seal(new byte[] {4, 5}, null);
      shared.clear();
      second.clear();
      old.rewrapTo(target, sealed, null);
    }
    KmsEvent start = startOf(shared), late = startOf(second);
    assertEquals(start.callId(), late.callId());
    assertEquals("source:5696", start.endpoint(), "the call's first attempt's");
    assertSame(start, late, "one start event for the call");
  }

  static KmsEvent startOf(Recorder r) {
    List<KmsEvent> starts = new ArrayList<>();
    for (KmsEvent e : r.events)
      if (e.kind() == KmsEvent.Kind.CALL && e.outcome() == KmsEvent.Outcome.STARTED) starts.add(e);
    assertEquals(1, starts.size(), r.events.toString());
    return starts.get(0);
  }

  @Test
  void aCallThatThrowsSomethingElseFailsWithoutAFailure() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    try (Kms kms = Kms.connect(server.configure().addListener(r).build())) {
      KeyHandle key = create(kms, "misused");
      r.clear();
      assertThrows(
          IllegalStateException.class,
          () ->
              kms.run(
                  "misuse",
                  () -> {
                    key.attributes();
                    throw new IllegalStateException("misused");
                  }));
    }
    r.checkWellFormed();
    List<KmsEvent> calls = r.finishedCalls();
    assertEquals(1, calls.size(), r.events.toString());
    assertEquals(KmsEvent.Outcome.FAILED, calls.get(0).outcome());
    assertTrue(calls.get(0).failure().isEmpty());
  }

  @Test
  void aCallAListenerMakesIsACallOfItsOwn() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    try (Kms kms = Kms.connect(server.configure().addListener(r).build())) {
      KeyHandle key = create(kms, "listener-call");
      AtomicBoolean once = new AtomicBoolean();
      KmsListener calling =
          new KmsListener() {
            @Override
            public void started(KmsEvent event) {
              // In the middle of the observed call: its own call, not an attempt of this one.
              if (once.compareAndSet(false, true)) key.attributes();
            }
          };
      r.clear();
      try (Kms observed =
          Kms.connect(server.configure().addListener(calling).addListener(r).build())) {
        observed.keys().handle(key.id()).attributes();
      }
    }
    r.checkWellFormed();
    List<KmsEvent> calls = r.finishedCalls();
    assertEquals(2, calls.size(), r.events.toString());
    Map<Long, List<KmsEvent>> attempts = r.attemptsByCall();
    for (KmsEvent call : calls) {
      assertEquals(1, call.attempt(), call.toString());
      assertEquals(1, attempts.get(call.callId()).size());
    }
    assertNotEquals(calls.get(0).callId(), calls.get(1).callId());
  }

  @Test
  void aCallFromCallFinishedIsItsOwnToo() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder r = new Recorder();
    try (Kms kms = Kms.connect(server.configure().addListener(r).build())) {
      KeyHandle key = create(kms, "after-call");
      AtomicBoolean once = new AtomicBoolean();
      r.onCallFinished =
          e -> {
            if (once.compareAndSet(false, true)) key.attributes();
          };
      r.clear();
      key.attributes();
    }
    r.checkWellFormed();
    List<KmsEvent> calls = r.finishedCalls();
    assertEquals(2, calls.size(), r.events.toString());
    assertNotEquals(calls.get(0).callId(), calls.get(1).callId());
  }
}
