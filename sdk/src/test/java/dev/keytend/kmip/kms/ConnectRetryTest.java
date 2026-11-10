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

import dev.keytend.kmip.TestTls;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.io.InterruptedIOException;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import javax.net.ssl.SSLContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link KmsConfig.Builder#connectRetry(Duration)} lets {@link
 * Kms#connect} wait for a KMS that is down at startup: RETRY failures are tried again with the
 * retry policy's back-off within the duration; anything else, and an interrupt, fails at once; by
 * default nothing is retried. The outage is {@link InMemoryKmipServer#unreachable(boolean)},
 * switched off by a listener hook on the connecting thread (deterministic: no timing).
 */
class ConnectRetryTest {
  /** A back-off below the 100 ms floor, without jitter: every wait is the floor. */
  static final RetryPolicy QUICK =
      RetryPolicy.builder()
          .initialBackoff(Duration.ofMillis(1))
          .maxBackoff(Duration.ofMillis(1))
          .jitter(0)
          .build();

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();
  final List<String> unavailable = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    Thread.interrupted();
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    servers.add(s);
    return s;
  }

  /** A listener that records each unavailable endpoint, then runs {@code hook} with the count. */
  KmsListener listener(Consumer<Integer> hook) {
    return new KmsListener() {
      @Override
      public void endpointUnavailable(String endpoint, String why) {
        unavailable.add(endpoint);
        hook.accept(unavailable.size());
      }
    };
  }

  Kms connect(KmsConfig config) {
    Kms kms = Kms.connect(config);
    clients.add(kms);
    return kms;
  }

  /**
   * A KMS that comes up during the retry (here after the third failed attempt) is connected to,
   * and the Kms works; each failed attempt told {@code endpointUnavailable}, as without the retry.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aKmsThatComesUpWithinTheDurationIsConnectedTo(KmipVersion version) {
    InMemoryKmipServer s = server(version).unreachable(true);
    KmsConfig config =
        s.configure()
            .maximumVersion(KmipVersion.V3_0)
            .retryPolicy(QUICK)
            .connectRetry(Duration.ofSeconds(30))
            .addListener(
                listener(
                    n -> {
                      if (n == 3) s.unreachable(false);
                    }))
            .build();
    long start = System.nanoTime();
    Kms kms = connect(config);
    long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
    assertEquals(version, kms.version());
    assertEquals(3, unavailable.size());
    assertTrue(took >= 3 * 100 - 10, "three back-offs of at least 100 ms: " + took + " ms");
    kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    assertEquals(List.of(), s.violations());
  }

  /** The default is no retry: one attempt, its failure as it was. */
  @Test
  void byDefaultConnectFailsAtTheFirstAttempt() {
    InMemoryKmipServer s = server(KmipVersion.V2_1).unreachable(true);
    KmsConfig config =
        s.configure().retryPolicy(QUICK).addListener(listener(n -> s.unreachable(false))).build();
    assertEquals(Duration.ZERO, config.connectRetry());
    TransientException e = assertThrows(TransientException.class, () -> Kms.connect(config));
    assertEquals(KmsException.Category.RETRY, e.category());
    assertEquals(1, unavailable.size());
    assertEquals(0, e.getSuppressed().length);
  }

  /**
   * A KMS that stays down: attempts start until the next one would start after the duration, each
   * at least 100 ms apart even with {@link RetryPolicy#none()} (no spinning); the last failure is
   * thrown with the earlier attempts' failures suppressed, the latest 16 of them.
   */
  @Test
  void aKmsThatStaysDownFailsAfterTheDurationWithTheEarlierFailures() {
    InMemoryKmipServer s = server(KmipVersion.V2_1).unreachable(true);
    KmsConfig config =
        s.configure()
            .retryPolicy(RetryPolicy.none())
            .connectRetry(Duration.ofMillis(3_500))
            .addListener(listener(n -> {}))
            .build();
    long start = System.nanoTime();
    TransientException e = assertThrows(TransientException.class, () -> Kms.connect(config));
    long took = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
    int attempts = unavailable.size();
    assertTrue(attempts > 17 && attempts <= 36, attempts + " attempts in " + took + " ms");
    assertTrue(took >= 3_500 - 100 - 50 && took < 3_500 + 1_000, "took " + took + " ms");
    assertEquals(16, e.getSuppressed().length);
    for (Throwable earlier : e.getSuppressed()) assertInstanceOf(TransientException.class, earlier);

    unavailable.clear();
    KmsConfig short_ = config.toBuilder().connectRetry(Duration.ofMillis(350)).build();
    TransientException e2 = assertThrows(TransientException.class, () -> Kms.connect(short_));
    assertEquals(
        unavailable.size() - 1, e2.getSuppressed().length, "every earlier attempt's failure");
    assertTrue(
        unavailable.size() >= 3 && unavailable.size() <= 4, unavailable.size() + " attempts");
  }

  /**
   * Failures that are not RETRY fail at once, whatever the duration: the server offering no
   * acceptable version, the server refusing this client (KMIP authentication), this client
   * refusing the server's certificate, and the server refusing this client's certificate.
   */
  @Test
  void configurationAndAccessFailuresFailAtOnce() throws Exception {
    InMemoryKmipServer old = server(KmipVersion.V1_4);
    long start = System.nanoTime();
    assertThrows(
        UnsupportedException.class,
        () ->
            Kms.connect(
                old.configure()
                    .minimumVersion(KmipVersion.V2_1)
                    .maximumVersion(KmipVersion.V2_1)
                    .connectRetry(Duration.ofSeconds(30))
                    .retryPolicy(QUICK)
                    .build()));

    InMemoryKmipServer refusing = server(KmipVersion.V2_1);
    refusing.failNext(ServerOperation.DISCOVER_VERSIONS, Fault.PERMISSION_DENIED);
    PermissionDeniedException denied =
        assertThrows(
            PermissionDeniedException.class,
            () ->
                Kms.connect(
                    refusing
                        .configure()
                        .connectRetry(Duration.ofSeconds(30))
                        .retryPolicy(QUICK)
                        .build()));
    assertEquals(0, denied.getSuppressed().length);

    SSLContext client = TestTls.context("client", "server");
    try (RecordingTlsServer impostor =
            new RecordingTlsServer(TestTls.context("stranger", "client"));
        RecordingTlsServer good = new RecordingTlsServer(TestTls.context("server", "client"))) {
      PermissionDeniedException untrusted =
          assertThrows(
              PermissionDeniedException.class,
              () ->
                  Kms.connect(
                      KmsConfig.builder()
                          .endpoints(impostor.endpoint())
                          .tls(client)
                          .connectRetry(Duration.ofSeconds(30))
                          .retryPolicy(QUICK)
                          .build()));
      assertTrue(Failures.serverNotTrusted(untrusted.getCause()));
      assertThrows(
          PermissionDeniedException.class,
          () ->
              Kms.connect(
                  KmsConfig.builder()
                      .endpoints(good.endpoint())
                      .tls(TestTls.context("stranger", "server"))
                      .connectRetry(Duration.ofSeconds(30))
                      .retryPolicy(QUICK)
                      .build()));
    }
    assertTrue(
        TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 10_000,
        "none waited for the 30 s");
  }

  /**
   * An interrupt fails at once and keeps the flag: one set when an attempt fails, one that arrives
   * in the back-off (from another thread, after the first failure), and one a transport reports
   * as an {@link InterruptedIOException} after clearing the flag.
   */
  @Test
  void anInterruptFailsAtOnceAndKeepsTheFlag() throws Exception {
    InMemoryKmipServer s = server(KmipVersion.V2_1).unreachable(true);
    KmsConfig.Builder b = s.configure().retryPolicy(QUICK).connectRetry(Duration.ofSeconds(30));

    // Interrupted while the attempt fails.
    KmsConfig self = b.addListener(listener(n -> Thread.currentThread().interrupt())).build();
    assertThrows(TransientException.class, () -> Kms.connect(self));
    assertTrue(Thread.interrupted(), "the flag is kept");
    assertEquals(1, unavailable.size());

    // Interrupted by another thread, in the back-off or the next attempt.
    unavailable.clear();
    CountDownLatch failedOnce = new CountDownLatch(1);
    KmsConfig other = b.addListener(listener(n -> failedOnce.countDown())).build();
    AtomicReference<Throwable> thrown = new AtomicReference<>();
    AtomicBoolean flag = new AtomicBoolean();
    Thread connecting =
        new Thread(
            () -> {
              try {
                Kms.connect(other).close();
              } catch (Throwable t) {
                thrown.set(t);
                flag.set(Thread.currentThread().isInterrupted());
              }
            });
    long start = System.nanoTime();
    connecting.start();
    assertTrue(failedOnce.await(5, TimeUnit.SECONDS));
    connecting.interrupt();
    connecting.join(5_000);
    assertInstanceOf(TransientException.class, thrown.get());
    assertTrue(flag.get(), "the flag is kept");
    assertTrue(TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start) < 5_000);
    assertTrue(unavailable.size() <= 2, unavailable.size() + " attempts");

    // A transport that cleared the flag and reports the interrupt.
    AtomicInteger exchanges = new AtomicInteger();
    KmsConfig clearing =
        b.addListener(new KmsListener() {})
            .transport(
                e ->
                    r -> {
                      exchanges.incrementAndGet();
                      throw new InterruptedIOException("interrupted while connecting");
                    })
            .build();
    assertThrows(TransientException.class, () -> Kms.connect(clearing));
    assertTrue(Thread.interrupted(), "the flag is set again");
    assertEquals(1, exchanges.get(), "not tried again");
  }

  /** The setting: zero or positive, kept by {@code toBuilder()}. */
  @Test
  void theSettingIsCheckedAndCopied() {
    KmsConfig.Builder b = server(KmipVersion.V2_1).configure();
    assertThrows(IllegalArgumentException.class, () -> b.connectRetry(Duration.ofMillis(-1)));
    assertThrows(NullPointerException.class, () -> b.connectRetry(null));
    KmsConfig config = b.connectRetry(Duration.ofMinutes(2)).build();
    assertEquals(Duration.ofMinutes(2), config.connectRetry());
    assertEquals(Duration.ofMinutes(2), config.toBuilder().build().connectRetry());
    assertEquals(Duration.ZERO, b.connectRetry(Duration.ZERO).build().connectRetry());
  }
}
