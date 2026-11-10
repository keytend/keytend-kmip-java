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
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link KmsEvent#step()} keeps the step an attempt belongs to while {@link KmsEvent#operation()}
 * keeps naming the application call, and the {@link LocalKeys} listener callbacks are dispatched
 * outside the call, with the listener's failures ignored.
 */
class KmsEventStepTest {
  /** Every event a listener heard, as {@code kind operation/step outcome}. */
  static final class Recorder implements KmsListener {
    final List<String> heard = new CopyOnWriteArrayList<>();
    final List<KmsEvent> events = new CopyOnWriteArrayList<>();
    final List<KmsEvent> retried = new CopyOnWriteArrayList<>();

    @Override
    public void started(KmsEvent e) {
      record("started", e);
    }

    @Override
    public void finished(KmsEvent e) {
      record("finished", e);
    }

    @Override
    public void retrying(KmsEvent e, Duration delay) {
      retried.add(e);
      record("retrying", e);
    }

    private void record(String kind, KmsEvent e) {
      events.add(e);
      heard.add(kind + " " + e.operation() + "/" + e.step() + " " + e.outcome());
    }

    List<String> steps(String kind) {
      List<String> steps = new ArrayList<>();
      for (String h : heard)
        if (h.startsWith(kind + " "))
          steps.add(h.substring(h.indexOf('/') + 1, h.lastIndexOf(' ')));
      return steps;
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void localKeysLoadNamesEachStepUnderItsOneOperation(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Recorder recorder = new Recorder();
    try (Kms admin = server.connect();
        Kms client = Kms.connect(server.configure().addListener(recorder).build())) {
      KeyCreation creation =
          admin
              .keys()
              .createAes(256)
              .custom(LocalKeysTest.FAMILY, "orders")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named("orders-write");
      if (version.compareTo(KmipVersion.V1_4) >= 0) creation.extractable(true);
      KeyHandle key = creation.create();
      server.leaseTime(Duration.ofSeconds(60));
      try (LocalKeys cache =
          client
              .keys()
              .localKeys("orders-write")
              .scope(KeyQuery.all().custom(LocalKeysTest.FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(Duration.ofSeconds(10))
              .open()) {
        recorder.heard.clear();
        recorder.events.clear();
        try (LocalKeys.Use use = cache.forEncrypt()) {
          assertEquals(key.id(), use.id());
        }
        assertFalse(recorder.events.isEmpty());
        for (KmsEvent e : recorder.events) assertEquals("localKeys", e.operation(), e.toString());
        List<String> started = recorder.steps("started");
        // The steps actually executed, in their order: the name is located, the candidate's
        // attributes read, its lease obtained, then its material fetched.
        assertTrue(started.contains("locate"), started.toString());
        assertTrue(started.contains("attributes"), started.toString());
        assertTrue(started.contains("obtainLease"), started.toString());
        assertTrue(started.contains("asSecretKey"), started.toString());
        assertTrue(started.indexOf("locate") < started.indexOf("attributes"), started.toString());
        assertTrue(
            started.lastIndexOf("attributes") < started.indexOf("obtainLease"), started.toString());
        assertTrue(
            started.indexOf("obtainLease") < started.indexOf("asSecretKey"), started.toString());
        // Each started attempt finished under the same step.
        assertEquals(started, recorder.steps("finished"));
        assertTrue(
            recorder.events.stream().anyMatch(e -> e.toString().contains("localKeys/obtainLease")),
            recorder.events.toString());
      }
    }
  }

  @Test
  void aRetriedAttemptKeepsItsStep() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder recorder = new Recorder();
    RetryPolicy retry =
        RetryPolicy.defaults().toBuilder()
            .maxAttempts(3)
            .initialBackoff(Duration.ofMillis(1))
            .maxBackoff(Duration.ofMillis(1))
            .build();
    try (Kms admin = server.connect();
        Kms client =
            Kms.connect(server.configure().retryPolicy(retry).addListener(recorder).build())) {
      KeyHandle key =
          admin
              .keys()
              .createAes(256)
              .custom(LocalKeysTest.FAMILY, "orders")
              .extractable(true)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named("orders-write")
              .create();
      server.leaseTime(Duration.ofSeconds(60));
      try (LocalKeys cache =
          client
              .keys()
              .localKeys("orders-write")
              .scope(KeyQuery.all().custom(LocalKeysTest.FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(Duration.ofSeconds(10))
              .open()) {
        recorder.heard.clear();
        recorder.events.clear();
        server.failNext(ServerOperation.GET, Fault.SERVER_BUSY);
        try (LocalKeys.Use use = cache.forDecrypt(key.id())) {
          assertEquals(key.id(), use.id());
        }
        List<KmsEvent> retried = recorder.retried;
        assertEquals(1, retried.size(), recorder.heard.toString());
        assertEquals("localKeys", retried.get(0).operation());
        assertEquals("asSecretKey", retried.get(0).step());
        assertEquals(KmsEvent.Outcome.FAILED, retried.get(0).outcome());
        // The failed and the retried attempt of the Get both say so, numbered 1 and 2.
        List<String> gets = new ArrayList<>();
        for (String h : recorder.heard) if (h.contains("/asSecretKey ")) gets.add(h);
        assertEquals(
            List.of(
                "started localKeys/asSecretKey STARTED",
                "finished localKeys/asSecretKey FAILED",
                "retrying localKeys/asSecretKey FAILED",
                "started localKeys/asSecretKey STARTED",
                "finished localKeys/asSecretKey SUCCEEDED"),
            gets);
      }
    }
  }

  @Test
  void aOneStepCallsStepIsItsOperationAndANamedCallKeepsItsInnerStep() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Recorder recorder = new Recorder();
    try (Kms kms = Kms.connect(server.configure().addListener(recorder).build())) {
      recorder.events.clear();
      kms.ping();
      for (KmsEvent e : recorder.events) {
        assertEquals("ping", e.operation());
        assertEquals("ping", e.step());
        assertFalse(e.toString().contains("/"), e.toString());
      }
      recorder.events.clear();
      kms.keys()
          .createAes(256)
          .named("steps")
          .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
          .findOrCreate();
      assertFalse(recorder.events.isEmpty());
      for (KmsEvent e : recorder.events) assertEquals("findOrCreate", e.operation(), e.toString());
      List<String> steps = recorder.steps("started");
      assertTrue(steps.contains("locate") && steps.contains("create"), steps.toString());
    }
  }

  @Test
  void localKeyCallbacksRunOutsideTheCallAndCannotChangeIt() {
    AtomicReference<String> selected = new AtomicReference<>();
    AtomicReference<Duration> remaining = new AtomicReference<>();
    AtomicReference<Long> callerScopeSeen = new AtomicReference<>(-1L);
    KmsListener listener =
        new KmsListener() {
          @Override
          public void localKeySelected(String name, String previousId, String newId) {
            selected.set(name + ":" + previousId + "->" + newId);
            // A callback gets its own deadline, not the remainder of the caller's.
            callerScopeSeen.set(Kms.callRemaining(Duration.ofHours(1)));
            throw new IllegalStateException("listener failure");
          }

          @Override
          public void localKeyRefreshFailed(
              String name,
              String keyId,
              LocalUse purpose,
              KmsException failure,
              Duration remainingValidity) {
            remaining.set(remainingValidity);
            throw new IllegalStateException("listener failure");
          }
        };
    // An unreachable endpoint: dispatching from the configuration never connects.
    KmsConfig config =
        KmsConfig.builder()
            .endpoints("kms.invalid:5696")
            .transport(
                e ->
                    request -> {
                      throw new AssertionError("no request may be sent");
                    })
            .addListener(listener)
            .build();
    Kms.run(
        Duration.ofMillis(50),
        "localKeys",
        () -> {
          Kms.localKeySelected(config, "orders-write", null, "k2");
          assertEquals("orders-write:null->k2", selected.get());
          assertTrue(
              callerScopeSeen.get() > Duration.ofMinutes(59).toNanos(),
              "callback saw the caller's deadline");
          // The caller's own scope and operation are restored afterwards.
          assertTrue(Kms.callRemaining(Duration.ofHours(1)) <= Duration.ofMillis(50).toNanos());
          assertEquals("localKeys", Kms.named("get"));
          KmsException failure =
              new TransientException("down", null, "localKeys", "k1", null, null);
          Kms.localKeyRefreshFailed(
              config, "orders-write", "k1", LocalUse.ENCRYPT, failure, Duration.ofSeconds(-3));
          assertEquals(Duration.ZERO, remaining.get());
          Kms.localKeyRefreshFailed(config, "orders-write", null, LocalUse.ENCRYPT, failure, null);
          assertEquals(Duration.ZERO, remaining.get());
          Kms.localKeyRefreshFailed(
              config, "orders-write", "k1", LocalUse.DECRYPT, failure, Duration.ofSeconds(4));
          assertEquals(Duration.ofSeconds(4), remaining.get());
        });
    // A listener that overrides nothing ignores both.
    KmsConfig quiet =
        KmsConfig.builder()
            .endpoints("kms.invalid:5696")
            .transport(
                e ->
                    request -> {
                      throw new AssertionError();
                    })
            .build();
    Kms.localKeySelected(quiet, "n", "a", "b");
    Kms.localKeyRefreshFailed(quiet, "n", "a", LocalUse.DECRYPT, null, Duration.ZERO);
  }
}
