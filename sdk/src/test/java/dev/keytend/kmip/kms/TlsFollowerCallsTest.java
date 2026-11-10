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

import dev.keytend.kmip.kms.KmsCallEventsTest.Recorder;
import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.kms.TlsIdentityTest.Pki;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * A TLS follower's calls ({@link KmsListener#callFinished}) have the outcome the application saw:
 * a start that throws is one FAILED call with what it threw, also when the reads it made were
 * handled first; a scheduled refresh, or a check of an unknown peer, that fails is a FAILED call
 * (background work); a {@code refresh()} by the application returns its failure, and SUCCEEDS. A
 * check that reads the KMS but past its timeout is refused for the timeout, and its call is FAILED
 * with that timeout.
 */
class TlsFollowerCallsTest {
  static final CustomAttribute TAG = CustomAttribute.client("follower-calls");
  static final Duration HOURLY = Duration.ofHours(1);

  private final CurrentKeyFollowerTest.Manual manual = new CurrentKeyFollowerTest.Manual();
  private final TlsBackgroundPeerCheckTest.Held held = new TlsBackgroundPeerCheckTest.Held();

  @AfterEach
  void shutDown() {
    manual.shutdownNow();
    held.shutdownNow();
  }

  static Kms connect(InMemoryKmipServer server, Recorder r) {
    return Kms.connect(
        server
            .configure()
            .maximumVersion(KmipVersion.V3_0)
            .retryPolicy(RetryPolicy.none())
            .addListener(r)
            .build());
  }

  /** The one call {@code r} heard, well formed and named {@code operation}. */
  static KmsEvent onlyCall(Recorder r, String operation) {
    r.checkWellFormed();
    List<KmsEvent> calls = r.finishedCalls();
    assertEquals(1, calls.size(), r.events.toString());
    assertEquals(operation, calls.get(0).operation());
    return calls.get(0);
  }

  /** The one call {@code r} heard is {@code operation}, FAILED with {@code thrown}. */
  static void failed(Recorder r, String operation, RuntimeException thrown) {
    KmsEvent call = onlyCall(r, operation);
    assertEquals(KmsEvent.Outcome.FAILED, call.outcome(), r.events.toString());
    assertSame(thrown, call.failure().orElseThrow(), r.events.toString());
  }

  static void succeeded(Recorder r, String operation) {
    KmsEvent call = onlyCall(r, operation);
    assertEquals(KmsEvent.Outcome.SUCCEEDED, call.outcome(), r.events.toString());
    assertTrue(call.failure().isEmpty());
  }

  /** Registers the identity {@code "node"} and the root CA as an anchor, tagged {@code "ca"}. */
  static Pki identityAndAnchor(Kms kms) throws Exception {
    Pki pki = new Pki();
    KeyPair key = TestPki.ec();
    kms.tls().register(key.getPrivate(), pki.chain(pki.leaf("node", key))).named("node").register();
    kms.keys()
        .register(pki.root.certificate())
        .usages(KeyUsage.VERIFY)
        .custom(TAG, "ca")
        .register();
    return pki;
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aStartThatThrowsIsAFailedCall(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Recorder r = new Recorder();
    try (Kms kms = connect(server, r)) {
      identityAndAnchor(kms);
      KeyQuery anchors = KeyQuery.all().custom(TAG, "ca");
      // The reads succeed and find nothing: the start throws after them.
      r.clear();
      NotFoundException missing =
          assertThrows(NotFoundException.class, () -> kms.tls().follow("missing", HOURLY, manual));
      failed(r, "follow", missing);
      // The reads fail and are handled: the start throws what they found.
      server.unreachable(true);
      r.clear();
      KmsException down =
          assertThrows(KmsException.class, () -> kms.tls().follow("node", HOURLY, manual));
      failed(r, "follow", down);
      r.clear();
      KmsException anchorsDown =
          assertThrows(KmsException.class, () -> kms.tls().trustAnchors(anchors, HOURLY, manual));
      failed(r, "trustAnchors", anchorsDown);
      r.clear();
      KmsException peersDown =
          assertThrows(
              KmsException.class, () -> kms.tls().trustAnchors(anchors, anchors, HOURLY, manual));
      failed(r, "trustAnchors", peersDown);
      assertEquals(List.of(), manual.tasks, "nothing scheduled");
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aScheduledRefreshThatFailsIsAFailedCall(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Recorder r = new Recorder();
    try (Kms kms = connect(server, r)) {
      identityAndAnchor(kms);
      try (TlsIdentityFollower identity = kms.tls().follow("node", HOURLY, manual);
          TlsTrustFollower trust =
              kms.tls().trustAnchors(KeyQuery.all().custom(TAG, "ca"), HOURLY, manual)) {
        assertEquals(2, manual.tasks.size());
        Runnable identityRefresh = manual.tasks.get(0), trustRefresh = manual.tasks.get(1);
        r.clear();
        identityRefresh.run();
        succeeded(r, "follow");
        r.clear();
        trustRefresh.run();
        succeeded(r, "trustAnchors");

        server.unreachable(true);
        r.clear();
        identityRefresh.run();
        assertEquals(TlsIdentityFollower.Status.STALE, identity.status());
        failed(r, "follow", identity.state().failure().orElseThrow());
        r.clear();
        trustRefresh.run();
        failed(r, "trustAnchors", trust.failure().orElseThrow());

        // The application's own refresh returns what it found: the call returned.
        r.clear();
        assertEquals(TlsIdentityFollower.Status.STALE, identity.refresh().status());
        succeeded(r, "follow");
        r.clear();
        assertFalse(trust.refresh());
        assertTrue(trust.failure().isPresent());
        succeeded(r, "trustAnchors");
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aCheckOfAnUnknownPeerThatFailsIsAFailedCall(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Recorder r = new Recorder();
    try (Kms kms = connect(server, r)) {
      Pki pki = identityAndAnchor(kms);
      KeyQuery anchors = KeyQuery.all().custom(TAG, "ca"),
          peers = KeyQuery.all().custom(TAG, "peer");
      try (TlsTrustFollower trust = kms.tls().trustAnchors(anchors, peers, HOURLY, held)) {
        // A peer whose chain validates but which the follower has not read: a check is queued.
        Issued unknown = pki.leaf("unknown", TestPki.ec());
        server.unreachable(true);
        assertThrows(
            CertificateException.class,
            () -> trust.trustManager().checkServerTrusted(pki.chain(unknown), "ECDHE_ECDSA"));
        r.clear();
        held.runAll();
        KmsEvent call = onlyCall(r, "trustAnchors");
        assertEquals(KmsEvent.Outcome.FAILED, call.outcome(), r.events.toString());
        assertInstanceOf(KmsException.class, call.failure().orElseThrow());
      }
    }
  }

  /**
   * Holds the next successful attempt of step {@code step} in its {@code finished} callback for
   * {@link #HOLD}: what follows that attempt in its call happens after that time, whatever the
   * scheduler does.
   */
  static final class Late implements KmsListener {
    static final Duration HOLD = Duration.ofMillis(1_200);
    volatile String step;

    @Override
    public void finished(KmsEvent attempt) {
      if (attempt.step().equals(step) && attempt.outcome() == KmsEvent.Outcome.SUCCEEDED) {
        step = null;
        try {
          TimeUnit.NANOSECONDS.sleep(HOLD.toNanos());
        } catch (InterruptedException e) {
          Thread.currentThread().interrupt();
        }
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aCheckThatReadsTheKmsAfterItsTimeoutIsAFailedCall(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Recorder r = new Recorder();
    Late late = new Late();
    try (Kms kms =
        Kms.connect(
            server
                .configure()
                .maximumVersion(KmipVersion.V3_0)
                .retryPolicy(RetryPolicy.none())
                .addListener(r)
                .addListener(late)
                .build())) {
      Pki pki = identityAndAnchor(kms);
      KeyQuery anchors = KeyQuery.all().custom(TAG, "ca"),
          peers = KeyQuery.all().custom(TAG, "peer");
      try (TlsTrustFollower trust =
          kms.tls()
              .trustAnchors(anchors, peers, HOURLY, held)
              .unknownPeerCheck(Duration.ofSeconds(1))
              .unknownPeerCheckInHandshake(true)) {
        // A peer whose chain validates and that no allowed peer matches. The check's one Locate
        // succeeds and finds nothing, but its call goes on only after the check's timeout.
        X509Certificate[] chain = pki.chain(pki.leaf("unknown-peer", TestPki.ec()));
        r.clear();
        late.step = "locate";
        CertificateException refused =
            assertThrows(
                CertificateException.class,
                () -> trust.trustManager().checkClientTrusted(chain, "EC"));
        assertNull(late.step, "the Locate was held");
        assertTrue(
            refused.getMessage().endsWith("(the check's timeout passed while reading the KMS)"),
            refused.getMessage());
        KmsEvent call = onlyCall(r, "trustAnchors");
        assertEquals(KmsEvent.Outcome.FAILED, call.outcome(), r.events.toString());
        KmsException failure = call.failure().orElseThrow();
        assertInstanceOf(TransientException.class, failure);
        assertTrue(failure.getMessage().contains("passed its timeout"), failure.getMessage());
        assertNull(failure.getCause(), "the KMS was read");
        List<KmsEvent> attempts =
            r.events.stream().filter(e -> e.kind() == KmsEvent.Kind.ATTEMPT).toList();
        assertEquals("locate", attempts.get(attempts.size() - 1).step(), "the Locate was the last");
        assertTrue(trust.failure().isEmpty(), "a failed check is not a failure of the follower");
      }
    }
  }
}
