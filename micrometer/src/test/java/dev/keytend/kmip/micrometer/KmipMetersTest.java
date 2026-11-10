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
package dev.keytend.kmip.micrometer;

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.CustomAttribute;
import dev.keytend.kmip.kms.Expect;
import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyMismatchException;
import dev.keytend.kmip.kms.KeyQuery;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.kms.KmsEvent;
import dev.keytend.kmip.kms.KmsListener;
import dev.keytend.kmip.kms.LocalKeys;
import dev.keytend.kmip.kms.LocalUse;
import dev.keytend.kmip.kms.NotFoundException;
import dev.keytend.kmip.kms.RetryPolicy;
import dev.keytend.kmip.kms.TlsIdentityFollower;
import dev.keytend.kmip.kms.TlsTrustFollower;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The meters, with a {@link SimpleMeterRegistry}, against the in-memory KMIP server: the
 * listener's timers and counters with bounded tags only, the binders' gauges and function counters,
 * and their removal.
 */
class KmipMetersTest {
  static final CustomAttribute FAMILY = CustomAttribute.client("meters-family");

  static KmsConfig.Builder replicas(InMemoryKmipServer first, InMemoryKmipServer second) {
    return first
        .configureReplicas(second)
        .retryPolicy(
            RetryPolicy.builder()
                .maxAttempts(3)
                .initialBackoff(Duration.ofMillis(1))
                .cooldown(Duration.ZERO)
                .build());
  }

  static double available(SimpleMeterRegistry registry, String endpoint) {
    return registry.get("kmip.client.endpoint.available").tag("endpoint", endpoint).gauge().value();
  }

  @Test
  void theListenerTimesCallsAndAttemptsAndCountsRetriesAndFailovers() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    InMemoryKmipServer first = InMemoryKmipServer.of(KmipVersion.V2_1), second = first.replica();
    List<String> ids = new ArrayList<>();
    try (Kms kms =
        Kms.connect(replicas(first, second).addListener(KmipMeters.listener(registry)).build())) {
      KeyHandle key = kms.keys().createAes(256).named("metered").usages(KeyUsage.ENCRYPT).create();
      ids.add(key.id());
      key.attributes();
      assertEquals(1, available(registry, "in-memory:5696"));

      first.unreachable(true);
      key.attributes(); // fails over
      assertEquals(0, available(registry, "in-memory:5696"));
      assertEquals(1, available(registry, "in-memory-2:5696"));
      first.unreachable(false);
      second.unreachable(true);
      key.attributes(); // back to the first
      assertEquals(1, available(registry, "in-memory:5696"));
      assertEquals(0, available(registry, "in-memory-2:5696"));
      second.unreachable(false);
      assertThrows(NotFoundException.class, () -> kms.keys().handle("no-such").attributes());
      ids.add("no-such");
    }
    assertEquals(
        3,
        registry
            .get("kmip.client.calls")
            .tags("operation", "attributes", "outcome", "success", "category", "none")
            .timer()
            .count());
    assertEquals(
        1,
        registry
            .get("kmip.client.calls")
            .tags("operation", "attributes", "outcome", "failure")
            .tags("category", "not_found", "reason", "not_found")
            .timer()
            .count());
    assertTrue(
        registry
                .get("kmip.client.attempts")
                .tags("endpoint", "in-memory:5696", "version", "2.1", "outcome", "failure")
                .timer()
                .count()
            >= 1);
    assertEquals(
        2,
        registry
            .get("kmip.client.retries")
            .tags("operation", "attributes", "category", "retry")
            .counter()
            .count());
    assertEquals(
        1,
        registry
            .get("kmip.client.failovers")
            .tags("operation", "attributes", "from", "in-memory:5696", "to", "in-memory-2:5696")
            .counter()
            .count());
    assertEquals(
        1,
        registry
            .get("kmip.client.failovers")
            .tags("from", "in-memory-2:5696", "to", "in-memory:5696")
            .counter()
            .count());
    for (Meter m : registry.getMeters())
      for (Tag t : m.getId().getTags())
        for (String id : ids)
          assertFalse(t.getValue().contains(id), "an identifier as a tag: " + m.getId());
  }

  @Test
  void eachEventHasItsMeter() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    KmsListener l = KmipMeters.listener(registry);
    l.leaseGranted("k-1", Duration.ofMinutes(1), false);
    l.leaseGranted("k-1", Duration.ofMinutes(1), true);
    l.leaseGranted("k-1", Duration.ofMinutes(1), true);
    l.leaseNotGranted("k-2", Duration.ofMinutes(1));
    l.credentialsReloaded("/etc/kms/client.pem");
    l.credentialsReloadFailed("/etc/kms/client.pem", "cut short");
    l.credentialsStillChanging("/etc/kms/client.pem", Duration.ofSeconds(4));
    l.clientCertificateRenewed("aa", "bb", java.time.Instant.EPOCH);
    l.clientCertificateRenewalFailed("bb", "refused");
    l.clientCertificateMayBeLockedOut("bb", "lost");
    l.clientCertificateRenewalWarning("bb", "within renewBefore already");
    l.keyStateChanged("k-1", KeyState.ACTIVE, KeyState.COMPROMISED);
    l.staleHandle("k-1", List.of("k-3"));
    l.concurrentReplacement("k-1", List.of("k-3", "k-4"));
    l.concurrentReplacement("k-5", List.of("k-6"));
    l.concurrentReplacement("k-7", List.of("k-8"));
    l.currentKeyCheckFailed("k-1", 1, notFound());
    l.localKeySelected("tde", null, "k-1");
    l.localKeyLoaded("tde", "k-1", LocalUse.ENCRYPT, Duration.ofMillis(5));
    l.localKeyRefreshFailed("tde", "k-1", LocalUse.DECRYPT, notFound(), Duration.ZERO);
    assertEquals(1, registry.get("kmip.leases").tag("result", "granted").counter().count());
    assertEquals(2, registry.get("kmip.leases").tag("result", "renewed").counter().count());
    assertEquals(1, registry.get("kmip.leases").tag("result", "not_granted").counter().count());
    for (String result : List.of("success", "failure", "still_changing"))
      assertEquals(1, registry.get("kmip.tls.reloads").tag("outcome", result).counter().count());
    for (String result : List.of("success", "failure", "locked_out"))
      assertEquals(1, registry.get("kmip.tls.renewals").tag("outcome", result).counter().count());
    // A warning is not an outcome: the renewals stay one per attempt.
    assertEquals(
        3.0,
        registry.get("kmip.tls.renewals").counters().stream()
            .mapToDouble(io.micrometer.core.instrument.Counter::count)
            .sum());
    assertEquals(1, registry.get("kmip.tls.renewal.warnings").counter().count());
    assertEquals(
        1,
        registry
            .get("kmip.keys.state.changes")
            .tags("from", "active", "to", "compromised")
            .counter()
            .count());
    assertEquals(1, registry.get("kmip.keys.stale.handles").counter().count());
    assertEquals(
        1,
        registry.get("kmip.keys.concurrent.replacements").tag("kind", "several").counter().count());
    assertEquals(
        2,
        registry
            .get("kmip.keys.concurrent.replacements")
            .tag("kind", "another_caller")
            .counter()
            .count());
    assertEquals(1, registry.get("kmip.currentkey.check.failures").counter().count());
    assertEquals(
        1, registry.get("kmip.localkeys.selections").tag("cache", "tde").counter().count());
    assertEquals(
        5,
        registry
            .get("kmip.localkeys.loads")
            .tags("cache", "tde", "purpose", "encrypt")
            .timer()
            .totalTime(TimeUnit.MILLISECONDS),
        0.001);
    assertEquals(
        1,
        registry
            .get("kmip.localkeys.refresh.failures")
            .tags("cache", "tde", "purpose", "decrypt")
            .counter()
            .count());
    for (Meter m : registry.getMeters())
      for (Tag t : m.getId().getTags())
        assertFalse(
            t.getValue().startsWith("k-") || t.getValue().contains("/etc/"),
            "an identifier or a file as a tag: " + m.getId());
  }

  @Test
  void theConnectionsBinderReadsEachEndpointAndIsRemovedOnClose() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    InMemoryKmipServer first = InMemoryKmipServer.of(KmipVersion.V2_1), second = first.replica();
    try (Kms kms = Kms.connect(replicas(first, second).build());
        KmipMeterBinder binder = KmipMeters.connections(kms)) {
      binder.bindTo(registry);
      binder.bindTo(registry); // once per registry
      assertEquals(10, binder.meters(registry).size(), "five meters per endpoint");
      kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
      // The in-memory server is not the SDK's TLS transport: nothing measured.
      assertTrue(
          Double.isNaN(
              registry
                  .get("kmip.client.connections")
                  .tags("endpoint", "in-memory:5696", "state", "open")
                  .gauge()
                  .value()));
      assertEquals(
          0,
          registry
              .get("kmip.client.connections.opened")
              .tag("endpoint", "in-memory-2:5696")
              .functionCounter()
              .count());
      assertEquals(
          0,
          registry
              .get("kmip.client.pool.wait")
              .tag("endpoint", "in-memory:5696")
              .functionTimer()
              .count());
      binder.close();
      assertTrue(registry.find("kmip.client.connections").meters().isEmpty(), "removed");
      assertTrue(registry.find("kmip.client.pool.wait").meters().isEmpty());
      assertThrows(IllegalStateException.class, () -> binder.bindTo(registry));
    }
  }

  /** A shared KMS's connection meters exist before it connects, and read it once connected. */
  @Test
  void theConnectionsOfASharedKmsAreMeteredBeforeAndAfterItConnects() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    CustomAttribute family = CustomAttribute.client("family");
    try (Kms admin = server.connect()) {
      admin
          .keys()
          .createAes(256)
          .extractable(true)
          .custom(family, "orders")
          .named("orders-write")
          .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
          .create();
    }
    try (LocalKeys.SharedKms shared = LocalKeys.sharedKms(server.configure().build());
        KmipMeterBinder binder = KmipMeters.connections(shared, Tags.of("pool", "shared"))) {
      binder.bindTo(registry);
      assertEquals(5, binder.meters(registry).size(), "five meters for the endpoint");
      assertEquals(
          0,
          registry
              .get("kmip.client.connections.opened")
              .tags("endpoint", "in-memory:5696", "pool", "shared")
              .functionCounter()
              .count(),
          "not connected");
      try (LocalKeys cache =
              shared
                  .localKeys("orders-write")
                  .scope(KeyQuery.all().custom(family, "orders"))
                  .expect(Expect.aes(256))
                  .open();
          LocalKeys.Use ignored = cache.forEncrypt()) {
        // The in-memory server is not the SDK's TLS transport: nothing measured.
        assertTrue(
            Double.isNaN(
                registry
                    .get("kmip.client.connections")
                    .tags("endpoint", "in-memory:5696", "state", "open")
                    .gauge()
                    .value()));
      }
    }
  }

  @Test
  void aBinderRefusesMetersAnotherSourceRegisteredAndClosesOnlyItsOwn() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = Kms.connect(server.configure().build());
        KmipMeterBinder first = KmipMeters.connections(kms);
        KmipMeterBinder same = KmipMeters.connections(kms.withTimeout(Duration.ofSeconds(5)));
        KmipMeterBinder tagged = KmipMeters.connections(kms, Tags.of("client", "second"))) {
      first.bindTo(registry);
      int count = registry.getMeters().size();
      assertEquals(5, count);
      IllegalStateException refused =
          assertThrows(IllegalStateException.class, () -> same.bindTo(registry));
      assertTrue(refused.getMessage().contains("kmip.client."), refused.getMessage());
      assertEquals(count, registry.getMeters().size(), "the refused binder left nothing");
      assertEquals(List.of(), same.meters(registry));
      same.close();
      assertEquals(count, registry.getMeters().size(), "its close removed none of the first's");
      tagged.bindTo(registry);
      assertEquals(2 * count, registry.getMeters().size(), "tags of its own: meters of its own");
      first.close();
      assertEquals(count, registry.getMeters().size());
      assertEquals(
          0,
          registry
              .get("kmip.client.connections.opened")
              .tags("endpoint", "in-memory:5696", "client", "second")
              .functionCounter()
              .count());
    }
  }

  @Test
  void twoBindersBindingAtOnceDoNotShareMeters() throws Exception {
    // Each bind looks at the registry's meters before it registers its own: both look first.
    java.util.concurrent.CyclicBarrier bothLooked = new java.util.concurrent.CyclicBarrier(2);
    SimpleMeterRegistry registry =
        new SimpleMeterRegistry() {
          @Override
          public List<Meter> getMeters() {
            List<Meter> meters = super.getMeters();
            try {
              bothLooked.await(200, TimeUnit.MILLISECONDS);
            } catch (Exception alone) {
              // The other bind waits for this one: it looks alone.
              bothLooked.reset();
            }
            return meters;
          }
        };
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    java.util.concurrent.ExecutorService pool = Executors.newFixedThreadPool(2);
    try (Kms kms = Kms.connect(server.configure().build());
        KmipMeterBinder a = KmipMeters.connections(kms);
        KmipMeterBinder b = KmipMeters.connections(kms)) {
      java.util.concurrent.Future<?> fa = pool.submit(() -> a.bindTo(registry));
      java.util.concurrent.Future<?> fb = pool.submit(() -> b.bindTo(registry));
      int refused = 0;
      for (java.util.concurrent.Future<?> f : List.of(fa, fb))
        try {
          f.get(10, TimeUnit.SECONDS);
        } catch (java.util.concurrent.ExecutionException e) {
          assertInstanceOf(IllegalStateException.class, e.getCause());
          refused++;
        }
      assertEquals(1, refused, "the second bind sees the first's meters");
      assertEquals(5, a.meters(registry).size() + b.meters(registry).size());
      KmipMeterBinder owner = a.meters(registry).isEmpty() ? b : a;
      KmipMeterBinder other = owner == a ? b : a;
      other.close();
      assertEquals(5, registry.getMeters().size(), "the refused one removes nothing");
      owner.close();
      assertEquals(0, registry.getMeters().size());
    } finally {
      pool.shutdownNow();
    }
  }

  @Test
  void closingABinderLeavesTheMetersThatReplacedItsOwn() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = Kms.connect(server.configure().build());
        KmipMeterBinder first = KmipMeters.connections(kms);
        KmipMeterBinder replacement = KmipMeters.connections(kms)) {
      first.bindTo(registry);
      registry.clear();
      replacement.bindTo(registry);
      assertEquals(5, registry.getMeters().size());
      first.close();
      assertEquals(5, registry.getMeters().size(), "the replacement's meters stay");
      for (Meter m : replacement.meters(registry))
        assertTrue(registry.getMeters().stream().anyMatch(held -> held == m), m.getId().toString());
      assertEquals(
          0,
          registry
              .get("kmip.client.connections.opened")
              .tag("endpoint", "in-memory:5696")
              .functionCounter()
              .count(),
          "and read the Kms");
      replacement.close();
      assertEquals(List.of(), registry.getMeters());
    }
  }

  @Test
  void closingABinderLeavesAMeterTheApplicationPutInPlaceOfOneOfItsOwn() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = Kms.connect(server.configure().build());
        KmipMeterBinder binder = KmipMeters.connections(kms)) {
      binder.bindTo(registry);
      Meter opened =
          registry
              .get("kmip.client.connections.opened")
              .tag("endpoint", "in-memory:5696")
              .functionCounter();
      registry.remove(opened);
      io.micrometer.core.instrument.FunctionCounter mine =
          io.micrometer.core.instrument.FunctionCounter.builder(
                  "kmip.client.connections.opened", this, t -> 7)
              .tag("endpoint", "in-memory:5696")
              .register(registry);
      binder.close();
      assertEquals(List.of(mine), registry.getMeters(), "only the application's meter");
    }
  }

  @Test
  void aFilterThatMakesTwoOfABindersMetersOneIsRefused() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    registry
        .config()
        .meterFilter(io.micrometer.core.instrument.config.MeterFilter.ignoreTags("endpoint"));
    InMemoryKmipServer first = InMemoryKmipServer.of(KmipVersion.V2_1), second = first.replica();
    try (Kms kms = Kms.connect(replicas(first, second).build());
        KmipMeterBinder binder = KmipMeters.connections(kms)) {
      IllegalStateException refused =
          assertThrows(IllegalStateException.class, () -> binder.bindTo(registry));
      assertTrue(refused.getMessage().contains("filters"), refused.getMessage());
      assertEquals(List.of(), registry.getMeters(), "nothing left behind");
      assertEquals(List.of(), binder.meters(registry));
    }
  }

  @Test
  void aBindTheRegistryRefusesPartWayLeavesNothingAndKeepsWhatWasThere() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = Kms.connect(server.configure().build());
        KmipMeterBinder binder = KmipMeters.connections(kms)) {
      // The application's counter, of another type than the binder's function counter.
      io.micrometer.core.instrument.Counter mine =
          registry.counter("kmip.client.connections.opened", "endpoint", "in-memory:5696");
      assertThrows(IllegalArgumentException.class, () -> binder.bindTo(registry));
      assertEquals(List.of(mine), registry.getMeters(), "only the application's meter");
      assertEquals(List.of(), binder.meters(registry));
      registry.remove(mine);
      binder.bindTo(registry);
      assertEquals(5, registry.getMeters().size(), "bound once the conflict is gone");
      binder.close();
      assertEquals(0, registry.getMeters().size());
    }
  }

  @Test
  void listenersWhoseTagsAFilterMakesOneShareTheGauge() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    registry
        .config()
        .meterFilter(io.micrometer.core.instrument.config.MeterFilter.ignoreTags("client"));
    KmsListener a = KmipMeters.listener(registry, Tags.of("client", "a"));
    KmsListener b = KmipMeters.listener(registry, Tags.of("client", "b"));
    a.endpointUnavailable("shared:5696", "refused");
    assertEquals(0, available(registry, "shared:5696"));
    b.endpointAvailable("shared:5696");
    assertEquals(1, available(registry, "shared:5696"), "the last event either told");
    a.endpointUnavailable("shared:5696", "refused");
    assertEquals(0, available(registry, "shared:5696"));
  }

  @Test
  void anEndpointGaugeRemovedFromTheRegistryComesBack() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    KmsListener l = KmipMeters.listener(registry);
    l.endpointUnavailable("gone:5696", "refused");
    registry.remove(registry.get("kmip.client.endpoint.available").gauge());
    assertNull(registry.find("kmip.client.endpoint.available").gauge());
    l.endpointAvailable("gone:5696");
    assertEquals(1, available(registry, "gone:5696"));
    KmsListener later = KmipMeters.listener(registry);
    registry.clear();
    later.endpointUnavailable("gone:5696", "refused");
    assertEquals(0, available(registry, "gone:5696"), "a new listener registers it too");
  }

  @Test
  void anotherGaugeRemovedCostsTheNextEventNoReadOfTheRegistry() {
    AtomicInteger reads = new AtomicInteger();
    SimpleMeterRegistry registry =
        new SimpleMeterRegistry() {
          @Override
          public List<Meter> getMeters() {
            reads.incrementAndGet();
            return super.getMeters();
          }
        };
    KmsListener l = KmipMeters.listener(registry);
    l.endpointUnavailable("kept:5696", "refused");
    // The application's gauges come and go, as a connection pool's would.
    for (int i = 0; i < 3; i++)
      registry.remove(
          Gauge.builder("app.pool.size", () -> 1).tag("pool", "p" + i).register(registry));
    reads.set(0);
    l.endpointAvailable("kept:5696");
    assertEquals(0, reads.get(), "the event read no list of the registry's meters");
    assertEquals(1, available(registry, "kept:5696"));
  }

  @Test
  void anEndpointGaugeRemovedBeforeTheListenerHeldItComesBack() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    KmsListener l = KmipMeters.listener(registry);
    MeterListener.Gauges gauges = MeterListener.gauges(registry);
    Tags tags = Tags.of("endpoint", "brief:5696");
    AtomicInteger value = new AtomicInteger(0);
    // An event's registration, the gauge removed after the registry returned it and before the
    // listener put it in its maps: the window a removal by another thread can fall into.
    synchronized (gauges) {
      gauges.register(
          tags,
          () -> {
            Gauge g =
                Gauge.builder("kmip.client.endpoint.available", value, AtomicInteger::get)
                    .tags(tags)
                    .register(registry);
            registry.remove(g);
            return g;
          },
          value);
    }
    assertNull(registry.find("kmip.client.endpoint.available").gauge());
    l.endpointAvailable("brief:5696");
    assertEquals(1, available(registry, "brief:5696"), "registered again by the next event");
  }

  @Test
  void aMeterRemovedWhileAnEventRegistersAGaugeDeadlocksNothing() throws Exception {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    io.micrometer.core.instrument.Counter app = registry.counter("app.requests");
    java.util.concurrent.CountDownLatch inRemoval = new java.util.concurrent.CountDownLatch(1);
    java.util.concurrent.CountDownLatch release = new java.util.concurrent.CountDownLatch(1);
    // Called before the listener's own removal callback, inside the registry's lock: it holds the
    // removing thread there until the event's thread waits for that lock.
    registry
        .config()
        .onMeterRemoved(
            m -> {
              if (m != app) return;
              inRemoval.countDown();
              try {
                release.await(10, TimeUnit.SECONDS);
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
              }
            });
    KmsListener l = KmipMeters.listener(registry);
    Thread remover = new Thread(() -> registry.remove(app), "remover");
    Thread event = new Thread(() -> l.endpointAvailable("new:5696"), "event");
    remover.setDaemon(true);
    event.setDaemon(true);
    remover.start();
    assertTrue(inRemoval.await(10, TimeUnit.SECONDS));
    // A first event for an endpoint registers its gauge, which needs the registry's lock.
    event.start();
    long until = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (event.getState() != Thread.State.BLOCKED) {
      assertTrue(System.nanoTime() < until, "the event waits for the remover's lock");
      Thread.sleep(1);
    }
    release.countDown();
    remover.join(TimeUnit.SECONDS.toMillis(10));
    event.join(TimeUnit.SECONDS.toMillis(10));
    assertFalse(
        remover.isAlive() || event.isAlive(),
        "deadlocked: remover " + remover.getState() + ", event " + event.getState());
    assertEquals(1, available(registry, "new:5696"));
  }

  @Test
  void theCallersTagsMayNotUseTheModulesKeys() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    assertThrows(
        IllegalArgumentException.class,
        () -> KmipMeters.listener(registry, Tags.of("endpoint", "mine")));
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = Kms.connect(server.configure().build())) {
      assertThrows(
          IllegalArgumentException.class,
          () -> KmipMeters.connections(kms, Tags.of("outcome", "mine")));
    }
  }

  @Test
  void listenersOfOneRegistryShareTheEndpointGaugeUnlessTagged() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    KmsListener a = KmipMeters.listener(registry), b = KmipMeters.listener(registry);
    a.endpointUnavailable("shared:5696", "refused");
    assertEquals(0, available(registry, "shared:5696"));
    b.endpointAvailable("shared:5696");
    assertEquals(1, available(registry, "shared:5696"), "the last event either told");
    a.endpointUnavailable("shared:5696", "refused");
    assertEquals(0, available(registry, "shared:5696"));
    KmsListener own = KmipMeters.listener(registry, Tags.of("client", "own"));
    own.endpointAvailable("shared:5696");
    own.endpointUnavailable("shared:5696", "refused");
    own.endpointAvailable("shared:5696");
    assertEquals(
        1,
        registry
            .get("kmip.client.endpoint.available")
            .tags("endpoint", "shared:5696", "client", "own")
            .gauge()
            .value());
    assertEquals(
        0,
        registry.getMeters().stream()
            .filter(m -> m.getId().getName().equals("kmip.client.endpoint.available"))
            .filter(m -> m.getId().getTags().equals(List.of(Tag.of("endpoint", "shared:5696"))))
            .findFirst()
            .orElseThrow()
            .measure()
            .iterator()
            .next()
            .getValue(),
        "the untagged gauge is apart");
  }

  @Test
  void aCallTheSdkRefusesAfterItsRequestsIsAFailure() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms =
        Kms.connect(server.configure().addListener(KmipMeters.listener(registry)).build())) {
      KeyHandle key =
          kms.keys()
              .createAes(256)
              .named("decrypt-only")
              .extractable(true)
              .usages(KeyUsage.DECRYPT)
              .create();
      assertThrows(
          KeyMismatchException.class, () -> key.asSecretKey(Expect.aes(256), LocalUse.ENCRYPT));
    }
    assertEquals(
        1,
        registry
            .get("kmip.client.calls")
            .tags("operation", "asSecretKey", "outcome", "failure")
            .timer()
            .count());
    assertNull(
        registry
            .find("kmip.client.calls")
            .tags("operation", "asSecretKey", "outcome", "success")
            .timer());
  }

  @Test
  void theLocalKeysBinderReadsTheCache() {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms =
        Kms.connect(server.configure().addListener(KmipMeters.listener(registry)).build())) {
      KeyHandle key =
          kms.keys()
              .createAes(256)
              .named("metered-cache")
              .extractable(true)
              .custom(FAMILY, "orders")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
      try (LocalKeys cache =
              kms.keys()
                  .localKeys("metered-cache")
                  .scope(KeyQuery.all().custom(FAMILY, "orders"))
                  .expect(Expect.aes(256))
                  .ttl(Duration.ofMinutes(10))
                  .open();
          KmipMeterBinder binder = KmipMeters.localKeys(cache)) {
        binder.bindTo(registry);
        for (int i = 0; i < 3; i++)
          try (LocalKeys.Use use = cache.forEncrypt()) {
            assertEquals(key.id(), use.id());
          }
        LocalKeys.Stats stats = cache.stats();
        assertEquals(
            (double) stats.encryptHits(),
            registry
                .get("kmip.localkeys.requests")
                .tags("cache", "metered-cache", "purpose", "encrypt", "result", "hit")
                .functionCounter()
                .count());
        assertEquals(
            (double) stats.encryptMisses(),
            registry
                .get("kmip.localkeys.requests")
                .tags("purpose", "encrypt", "result", "miss")
                .functionCounter()
                .count());
        assertEquals(stats.size(), registry.get("kmip.localkeys.size").gauge().value());
        double usable = registry.get("kmip.localkeys.usable").timeGauge().value(TimeUnit.SECONDS);
        assertTrue(usable > 500 && usable <= 600, "within the TTL: " + usable);
        assertEquals(0, registry.get("kmip.localkeys.write.failing").gauge().value());
        assertEquals(
            1,
            registry
                .get("kmip.localkeys.selections")
                .tag("cache", "metered-cache")
                .counter()
                .count());
        assertEquals(
            1,
            registry
                .get("kmip.client.calls")
                .tags("operation", "localKeys", "outcome", "success")
                .timer()
                .count(),
            "one load, then hits");
      }
      assertTrue(registry.find("kmip.localkeys.usable").meters().isEmpty(), "removed on close");
    }
  }

  @Test
  void theTlsIdentityBinderReadsTheExpiryOfThePresentedCertificate(@TempDir Path dir)
      throws Exception {
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
    try (Kms kms = server.connect()) {
      KeyStore store = selfSigned(dir, 30);
      kms.tls()
          .register(
              (PrivateKey) store.getKey("node", PASSWORD),
              (X509Certificate) store.getCertificate("node"))
          .named("metered-node")
          .register();
      try (TlsIdentityFollower follower =
              kms.tls().follow("metered-node", Duration.ofHours(1), executor);
          KmipMeterBinder binder = KmipMeters.tlsIdentity(follower)) {
        binder.bindTo(registry);
        double days =
            registry
                    .get("kmip.tls.certificate.expiry")
                    .tag("identity", "metered-node")
                    .timeGauge()
                    .value(TimeUnit.SECONDS)
                / 86_400;
        assertTrue(days > 29 && days <= 30.01, "about 30 days: " + days);
        follower.close();
        assertTrue(
            Double.isNaN(
                registry
                    .get("kmip.tls.certificate.expiry")
                    .tag("identity", "metered-node")
                    .timeGauge()
                    .value()),
            "nothing presented once closed");
      }
      assertTrue(registry.find("kmip.tls.certificate.expiry").meters().isEmpty(), "removed");
    } finally {
      executor.shutdownNow();
    }
  }

  /**
   * A check of an unknown peer whose read of the KMS ends after the check's timeout is refused for
   * that timeout: the call's timer counts it as a failure, as the handshake saw it.
   */
  @Test
  void aPeerCheckThatReadsTheKmsAfterItsTimeoutIsTimedAsAFailure(@TempDir Path dir)
      throws Exception {
    X509Certificate[] chain = issued(dir);
    SimpleMeterRegistry registry = new SimpleMeterRegistry();
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicBoolean holding = new AtomicBoolean();
    // Holds the check's Locate, which succeeds, past the check's timeout of 1 s.
    KmsListener late =
        new KmsListener() {
          @Override
          public void finished(KmsEvent attempt) {
            if (attempt.step().equals("locate")
                && attempt.outcome() == KmsEvent.Outcome.SUCCEEDED
                && holding.getAndSet(false)) {
              try {
                TimeUnit.MILLISECONDS.sleep(1_200);
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
              }
            }
          }
        };
    CustomAttribute tag = CustomAttribute.client("metered-trust");
    ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
    try (Kms kms =
        Kms.connect(
            server
                .configure()
                .addListener(KmipMeters.listener(registry))
                .addListener(late)
                .build())) {
      kms.keys().register(chain[1]).usages(KeyUsage.VERIFY).custom(tag, "ca").register();
      try (TlsTrustFollower trust =
          kms.tls()
              .trustAnchors(
                  KeyQuery.all().custom(tag, "ca"),
                  KeyQuery.all().custom(tag, "peer"),
                  Duration.ofHours(1),
                  executor)
              .unknownPeerCheck(Duration.ofSeconds(1))
              .unknownPeerCheckInHandshake(true)) {
        holding.set(true);
        CertificateException refused =
            assertThrows(
                CertificateException.class,
                () -> trust.trustManager().checkClientTrusted(chain, "EC"));
        assertFalse(holding.get(), "the Locate was held");
        assertTrue(
            refused.getMessage().endsWith("(the check's timeout passed while reading the KMS)"),
            refused.getMessage());
      }
    } finally {
      executor.shutdownNow();
    }
    assertEquals(
        1,
        registry
            .get("kmip.client.calls")
            .tags("operation", "trustAnchors", "outcome", "failure")
            .timer()
            .count(),
        "the check");
    assertEquals(
        1,
        registry
            .get("kmip.client.calls")
            .tags("operation", "trustAnchors", "outcome", "success")
            .timer()
            .count(),
        "the start");
  }

  /** A real failure: the SDK's exceptions are made only by the SDK. */
  static NotFoundException notFound() {
    try (Kms kms = InMemoryKmipServer.of(KmipVersion.V2_1).connect()) {
      return assertThrows(NotFoundException.class, () -> kms.keys().handle("gone").attributes());
    }
  }

  static final char[] PASSWORD = "changeit".toCharArray();

  /** A self-signed EC certificate valid {@code days} days, and its key, from the JDK's keytool. */
  static KeyStore selfSigned(Path dir, int days) throws Exception {
    Path file = dir.resolve("node.p12");
    keytool(genkeypair(file, "node", "CN=metered-node", days));
    KeyStore store = KeyStore.getInstance("PKCS12");
    try (var in = Files.newInputStream(file)) {
      store.load(in, PASSWORD);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return store;
  }

  /** keytool's arguments that make a key pair {@code alias} in {@code file}, self-signed. */
  static String[] genkeypair(Path file, String alias, String dname, int days, String... more) {
    List<String> args =
        new ArrayList<>(
            List.of(
                "-genkeypair",
                "-alias",
                alias,
                "-keyalg",
                "EC",
                "-groupname",
                "secp256r1",
                "-sigalg",
                "SHA256withECDSA",
                "-dname",
                dname,
                "-validity",
                String.valueOf(days)));
    args.addAll(List.of(more));
    args.addAll(store(file));
    return args.toArray(String[]::new);
  }

  static List<String> store(Path file) {
    return List.of(
        "-storetype",
        "PKCS12",
        "-keystore",
        file.toString(),
        "-storepass",
        new String(PASSWORD),
        "-keypass",
        new String(PASSWORD));
  }

  /** Runs the JDK's keytool with {@code args}; what it wrote. */
  static byte[] keytool(String... args) throws Exception {
    List<String> command = new ArrayList<>();
    command.add(Path.of(System.getProperty("java.home"), "bin", "keytool").toString());
    command.addAll(List.of(args));
    Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
    byte[] out = p.getInputStream().readAllBytes();
    assertTrue(p.waitFor(60, TimeUnit.SECONDS), "keytool hung");
    assertEquals(0, p.exitValue(), new String(out, java.nio.charset.StandardCharsets.UTF_8));
    return out;
  }

  /** A root CA and a peer it issued, from the JDK's keytool: the chain, the peer first. */
  static X509Certificate[] issued(Path dir) throws Exception {
    Path file = dir.resolve("pki.p12"), request = dir.resolve("peer.csr");
    Path peer = dir.resolve("peer.cer");
    keytool(genkeypair(file, "root", "CN=metered-root", 2, "-ext", "bc:c"));
    keytool(genkeypair(file, "peer", "CN=unknown-peer", 2));
    List<String> args = new ArrayList<>(List.of("-certreq", "-alias", "peer", "-file"));
    args.add(request.toString());
    args.addAll(store(file));
    keytool(args.toArray(String[]::new));
    args = new ArrayList<>(List.of("-gencert", "-alias", "root", "-validity", "2", "-rfc"));
    args.addAll(List.of("-infile", request.toString(), "-outfile", peer.toString()));
    args.addAll(store(file));
    keytool(args.toArray(String[]::new));
    KeyStore store = KeyStore.getInstance("PKCS12");
    try (var in = Files.newInputStream(file)) {
      store.load(in, PASSWORD);
    }
    try (var in = Files.newInputStream(peer)) {
      return new X509Certificate[] {
        (X509Certificate)
            java.security.cert.CertificateFactory.getInstance("X.509").generateCertificate(in),
        (X509Certificate) store.getCertificate("root")
      };
    }
  }
}
