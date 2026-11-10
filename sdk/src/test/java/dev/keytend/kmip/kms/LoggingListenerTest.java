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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.slf4j.event.Level;

/**
 * The SDK's own logging ({@link LoggingListener}): each event at its logger and level, WARN lines
 * at most once per minute per key with the count suppressed, installed in every configuration, and
 * never a password, key material or plaintext in any line.
 */
class LoggingListenerTest {
  static final Duration MINUTE = Duration.ofMinutes(1);
  static final CustomAttribute FAMILY = CustomAttribute.client("logging-family");

  static KmsEvent attempt(long callId, KmsEvent.Outcome outcome, KmsException failure) {
    return new KmsEvent(
        KmsEvent.Kind.ATTEMPT,
        callId,
        "findOrCreate",
        "locate",
        "logging-test:5696",
        1,
        KmipVersion.V2_1,
        "key-1",
        Duration.ofMillis(outcome == KmsEvent.Outcome.STARTED ? 0 : 3),
        outcome,
        failure);
  }

  static KmsEvent call(long callId, KmsEvent.Outcome outcome, KmsException failure) {
    return new KmsEvent(
        KmsEvent.Kind.CALL,
        callId,
        "findOrCreate",
        "findOrCreate",
        "logging-test:5696",
        outcome == KmsEvent.Outcome.STARTED ? 0 : 2,
        KmipVersion.V2_1,
        null,
        Duration.ofMillis(outcome == KmsEvent.Outcome.STARTED ? 0 : 7),
        outcome,
        failure);
  }

  /** The one event {@code fire} logs on a fresh listener: its logger, level and message. */
  static TestLogs.Event only(Consumer<LoggingListener> fire) {
    LoggingListener l = new LoggingListener(new AtomicLong(1)::get);
    try (TestLogs.Capture logs = TestLogs.capture()) {
      fire.accept(l);
      List<TestLogs.Event> events = logs.events(e -> e.logger().startsWith("dev.keytend.kmip."));
      assertEquals(1, events.size(), events.toString());
      assertNull(events.get(0).thrown(), "no stack trace, no causes");
      return events.get(0);
    }
  }

  static void logs(String logger, Level level, Consumer<LoggingListener> fire, String... parts) {
    TestLogs.Event e = only(fire);
    assertEquals(logger, e.logger(), e.toString());
    assertEquals(level, e.level(), e.toString());
    for (String p : parts) assertTrue(e.message().contains(p), e + " has " + p);
  }

  @Test
  void eachEventLogsAtItsLoggerAndLevel() {
    KmsException notFound =
        new NotFoundException("get key-1: not found", null, "get", "key-1", null, null);
    String calls = "dev.keytend.kmip.kms.Calls";
    logs(calls, Level.DEBUG, l -> l.callStarted(call(41, KmsEvent.Outcome.STARTED, null)), "41");
    logs(
        calls,
        Level.DEBUG,
        l -> l.callFinished(call(41, KmsEvent.Outcome.FAILED, notFound)),
        "41",
        "failed",
        "NotFoundException");
    logs(
        calls,
        Level.DEBUG,
        l -> l.started(attempt(41, KmsEvent.Outcome.STARTED, null)),
        "findOrCreate/locate",
        "key-1");
    logs(
        calls, Level.DEBUG, l -> l.finished(attempt(41, KmsEvent.Outcome.SUCCEEDED, null)), "3 ms");
    logs(
        calls,
        Level.DEBUG,
        l -> l.retrying(attempt(41, KmsEvent.Outcome.FAILED, notFound), Duration.ofMillis(20)),
        "20 ms");

    String endpoints = "dev.keytend.kmip.kms.Endpoints";
    logs(endpoints, Level.WARN, l -> l.endpointUnavailable("kms-9:5696", "refused"), "kms-9:5696");
    logs(endpoints, Level.INFO, l -> l.endpointAvailable("kms-9:5696"), "kms-9:5696");

    String tls = "dev.keytend.kmip.kms.Tls";
    logs(tls, Level.INFO, l -> l.credentialsReloaded("/etc/kms/client.pem"), "/etc/kms/client.pem");
    logs(tls, Level.ERROR, l -> l.credentialsReloadFailed("/etc/kms/client.pem", "cut short"));
    logs(
        tls,
        Level.WARN,
        l -> l.credentialsStillChanging("/etc/kms/client.pem", Duration.ofSeconds(5)),
        "5 s");

    String localKeys = "dev.keytend.kmip.kms.LocalKeys";
    logs(localKeys, Level.INFO, l -> l.localKeySelected("tde", null, "key-1"), "tde", "key-1");
    logs(localKeys, Level.INFO, l -> l.localKeySelected("tde", "key-1", "key-2"), "key-2");
    logs(
        localKeys,
        Level.DEBUG,
        l -> l.localKeyLoaded("tde", "key-1", LocalUse.ENCRYPT, Duration.ofMillis(12)),
        "12 ms");
    logs(
        localKeys,
        Level.WARN,
        l ->
            l.localKeyRefreshFailed(
                "tde", "key-1", LocalUse.DECRYPT, notFound, Duration.ofSeconds(30)),
        "30 s",
        "decryption");

    String leases = "dev.keytend.kmip.kms.Leases";
    logs(leases, Level.WARN, l -> l.leaseNotGranted("key-1", Duration.ofSeconds(60)), "60 s");
    logs(
        leases, Level.DEBUG, l -> l.leaseGranted("key-1", Duration.ofSeconds(60), true), "renewed");

    String keys = "dev.keytend.kmip.kms.Keys";
    logs(keys, Level.INFO, l -> l.keyStateChanged("key-1", KeyState.ACTIVE, KeyState.DEACTIVATED));
    logs(keys, Level.WARN, l -> l.keyStateChanged("key-1", KeyState.ACTIVE, KeyState.COMPROMISED));
    logs(
        keys,
        Level.WARN,
        l -> l.keyStateChanged("key-1", KeyState.DEACTIVATED, KeyState.DESTROYED));
    logs(keys, Level.INFO, l -> l.staleHandle("key-1", List.of("key-2")), "key-2");
    logs(
        keys,
        Level.WARN,
        l -> l.concurrentReplacement("key-1", List.of("key-2", "key-3")),
        "reconcile()");
    logs(
        keys,
        Level.INFO,
        l -> l.concurrentReplacement("key-1", List.of("key-2")),
        "another caller",
        "latest()");
    logs(keys, Level.WARN, l -> l.currentKeyCheckFailed("key-1", 2, notFound), "2 checks");
  }

  @Test
  void aWarningIsLoggedOncePerKeyPerMinuteWithTheCountSuppressed() {
    AtomicLong now = new AtomicLong(1_000);
    LoggingListener l = new LoggingListener(now::get);
    try (TestLogs.Capture logs = TestLogs.capture()) {
      for (int i = 0; i < 5; i++) l.endpointUnavailable("limited-a:5696", "refused");
      l.endpointUnavailable("limited-b:5696", "refused");
      now.addAndGet(TimeUnit.SECONDS.toNanos(59));
      l.endpointUnavailable("limited-a:5696", "refused");
      now.addAndGet(TimeUnit.SECONDS.toNanos(2));
      l.endpointUnavailable("limited-a:5696", "refused");
      l.endpointUnavailable("limited-a:5696", "refused");
      now.addAndGet(MINUTE.toNanos());
      l.endpointUnavailable("limited-a:5696", "refused");
      List<String> lines = logs.messages("dev.keytend.kmip.kms.Endpoints", Level.WARN);
      List<String> a = new ArrayList<>(), b = new ArrayList<>();
      for (String line : lines) {
        if (line.contains("limited-a")) a.add(line);
        if (line.contains("limited-b")) b.add(line);
      }
      assertEquals(1, b.size(), "another key is limited on its own");
      assertEquals(3, a.size(), a.toString());
      assertFalse(a.get(0).contains("suppressed"), a.get(0));
      assertTrue(a.get(1).endsWith("(5 similar lines suppressed since the last one)"), a.get(1));
      assertTrue(a.get(2).endsWith("(1 similar lines suppressed since the last one)"), a.get(2));
    }
  }

  @Test
  void theLimiterForgetsKeysBeyondItsBound() {
    LogLimiter limiter = new LogLimiter(MINUTE.toNanos(), () -> 5);
    for (int i = 0; i < LogLimiter.MAX_KEYS; i++) assertEquals(0, limiter.permit("key " + i));
    assertEquals(LogLimiter.SUPPRESSED, limiter.permit("key 0"));
    assertEquals(0, limiter.permit("one key too many"), "a new key is still logged");
    assertEquals(0, limiter.permit("key 0"), "the others were forgotten");
  }

  @Test
  void anUnavailableEndpointClaimsNoOtherEndpoint() {
    String line = only(l -> l.endpointUnavailable("solo:5696", "refused")).message();
    assertTrue(line.contains("unless no other endpoint is available"), line);
    assertFalse(line.contains("other endpoints are used"), line);
  }

  @Test
  void aListenerThatThrowsIsWarnedOfOncePerClass() {
    KmsListener failing =
        new KmsListener() {
          @Override
          public void endpointAvailable(String endpoint) {
            throw new IllegalStateException("a defect\nforged line");
          }
        };
    try (TestLogs.Capture logs = TestLogs.capture()) {
      KmsListener all = KmsListener.all(failing);
      all.endpointAvailable("e:1");
      all.endpointAvailable("e:1");
      List<TestLogs.Event> events =
          logs.events(
              e ->
                  e.logger().equals("dev.keytend.kmip.kms.KmsListener")
                      && e.message().contains(failing.getClass().getName()));
      assertEquals(3, events.size(), events.toString());
      TestLogs.Event warn = events.get(0);
      assertEquals(Level.WARN, warn.level());
      // The line that threw, not the exception's message (the application's text).
      assertTrue(warn.message().contains("IllegalStateException at "), warn.message());
      assertTrue(warn.message().contains("LoggingListenerTest"), warn.message());
      assertFalse(warn.message().contains("a defect"), warn.message());
      assertNull(warn.thrown());
      // Each failure at DEBUG, with its stack trace.
      for (TestLogs.Event debug : events.subList(1, 3)) {
        assertEquals(Level.DEBUG, debug.level());
        assertInstanceOf(IllegalStateException.class, debug.thrown());
      }
    }
  }

  @Test
  void theLineThatThrewIsTheListenersNotTheJdks() {
    KmsListener failing =
        new KmsListener() {
          @Override
          public void endpointAvailable(String endpoint) {
            java.util.Objects.requireNonNull(
                System.getProperty("kmip.no.such.property"), "a defect");
          }
        };
    try {
      failing.endpointAvailable("e:1");
      fail("threw");
    } catch (NullPointerException thrown) {
      assertTrue(thrown.getStackTrace()[0].getClassName().startsWith("java."), "the JDK's at top");
      String where = KmsListeners.where(failing, thrown);
      assertTrue(where.contains(failing.getClass().getName() + ".endpointAvailable("), where);
    }
    // Without a frame of the listener's class: the first outside the JDK.
    IllegalStateException deep = new IllegalStateException();
    deep.setStackTrace(
        new StackTraceElement[] {
          new StackTraceElement("java.util.Objects", "requireNonNull", "Objects.java", 1),
          new StackTraceElement("com.example.Helper", "check", "Helper.java", 7)
        });
    assertEquals("com.example.Helper.check(Helper.java:7)", KmsListeners.where(failing, deep));
    deep.setStackTrace(new StackTraceElement[0]);
    assertEquals("an unknown line", KmsListeners.where(failing, deep));
  }

  /**
   * Two replicas under endpoint labels of their own ({@code tag-1:5696}, {@code tag-2:5696}): the
   * SDK's rate limit is per endpoint label across the JVM, and other tests use the default labels.
   */
  static KmsConfig.Builder replicas(
      String tag, InMemoryKmipServer first, InMemoryKmipServer second) {
    return first
        .configure()
        .endpoints(tag + "-1:5696", tag + "-2:5696")
        .transport(e -> e.host().endsWith("-1") ? first : second);
  }

  @Test
  void everyConfigurationLogsWhateverItsListeners() {
    InMemoryKmipServer first = InMemoryKmipServer.of(KmipVersion.V2_1), second = first.replica();
    KmsListener own = new KmsListener() {};
    KmsConfig config =
        replicas("logging-installed", first, second)
            .retryPolicy(
                RetryPolicy.builder()
                    .initialBackoff(Duration.ofMillis(1))
                    .cooldown(Duration.ZERO)
                    .build())
            .addListener(own)
            .build();
    assertEquals(List.of(own), config.listeners(), "not the SDK's own");
    try (TestLogs.Capture logs = TestLogs.capture();
        Kms kms = Kms.connect(config)) {
      first.unreachable(true);
      assertThrows(
          NotFoundException.class, () -> kms.keys().handle("logging-missing").attributes());
      first.unreachable(false);
      second.unreachable(true);
      assertThrows(
          NotFoundException.class, () -> kms.keys().handle("logging-missing").attributes());
      List<TestLogs.Event> endpointLines =
          logs.events(e -> e.logger().equals("dev.keytend.kmip.kms.Endpoints"));
      assertTrue(
          endpointLines.stream()
              .anyMatch(
                  e -> e.level() == Level.INFO && e.message().contains("logging-installed-1:5696")),
          endpointLines.toString());
      List<TestLogs.Event> callLines =
          logs.events(
              e ->
                  e.logger().equals("dev.keytend.kmip.kms.Calls")
                      && e.message().contains("logging-missing"));
      assertFalse(callLines.isEmpty());
      for (TestLogs.Event e : callLines) assertEquals(Level.DEBUG, e.level(), "no log-and-throw");
      for (TestLogs.Event e : logs.events())
        if (e.message().contains("NotFoundException"))
          assertEquals(Level.DEBUG, e.level(), "what the caller gets is at most DEBUG: " + e);
    }
  }

  @Test
  void noLineHasThePasswordKeyMaterialOrPlaintext() {
    InMemoryKmipServer first = InMemoryKmipServer.of(KmipVersion.V2_1), second = first.replica();
    String user = "log-user-7Qx", password = "pw-Secret-91zq", stored = "stored-Secret-44kv";
    byte[] material = new byte[32];
    for (int i = 0; i < material.length; i++) material[i] = (byte) (0xA0 + i);
    byte[] plaintext = "PLAINTEXT-marker-0193".getBytes(UTF_8);
    List<String> secrets =
        List.of(
            user,
            password,
            stored,
            new String(plaintext, UTF_8),
            HexFormat.of().formatHex(material),
            HexFormat.of().formatHex(material).toUpperCase(Locale.ROOT),
            Base64.getEncoder().encodeToString(material),
            HexFormat.of().formatHex(plaintext),
            Base64.getEncoder().encodeToString(plaintext));
    KmsConfig config =
        replicas("logging-secrets", first, second)
            .usernamePassword(user, password.toCharArray())
            .retryPolicy(
                RetryPolicy.builder()
                    .initialBackoff(Duration.ofMillis(1))
                    .cooldown(Duration.ZERO)
                    .build())
            .build();
    List<TestLogs.Event> events;
    try (TestLogs.Capture logs = TestLogs.capture()) {
      try (Kms kms = Kms.connect(config)) {
        KeyHandle key =
            kms.keys()
                .register(new SecretKeySpec(material, "AES"))
                .named("logging-secrets")
                .custom(FAMILY, "logging")
                .extractable(true)
                .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                .register();
        first.unreachable(true); // a failover: WARN and retry lines
        Ciphertext sealed = key.encrypt(CipherSpec.aesGcm(), plaintext, new byte[] {1});
        first.unreachable(false);
        second.unreachable(true); // the first is back: INFO
        assertArrayEquals(plaintext, key.decrypt(sealed, new byte[] {1}));
        second.unreachable(false);
        try (DestroyableSecretKey copy = key.asSecretKey(Expect.aes(), LocalUse.DECRYPT)) {
          assertArrayEquals(material, copy.getEncoded());
        }
        kms.keys().registerSecret(stored.toCharArray()).named("logging-stored").register();
        try (LocalKeys cache =
            kms.keys()
                .localKeys("logging-secrets")
                .scope(KeyQuery.all().custom(FAMILY, "logging"))
                .expect(Expect.aes(256))
                .open()) {
          try (LocalKeys.Use use = cache.forEncrypt()) {
            assertEquals(key.id(), use.id());
          }
        }
        assertThrows(
            NotFoundException.class, () -> kms.keys().handle("logging-secrets-gone").attributes());
      }
      events = logs.events();
    }
    assertTrue(
        events.stream().anyMatch(e -> e.logger().equals("dev.keytend.kmip.kms.Endpoints")),
        "the run logged an endpoint going down: " + events);
    assertTrue(events.size() > 10, "the run logged: " + events);
    for (TestLogs.Event e : events) {
      List<String> text = new ArrayList<>(List.of(e.message()));
      for (Throwable t = e.thrown(); t != null; t = t.getCause()) text.add(String.valueOf(t));
      for (String line : text)
        for (String secret : secrets) assertFalse(line.contains(secret), secret + " in " + e);
    }
  }
}
