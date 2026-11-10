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

import static dev.keytend.kmip.kms.LocalKeysTest.FAMILY;
import static dev.keytend.kmip.kms.LocalKeysTest.NAME;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** A lease observation supersedes unleased publications, expired grants fetch nothing, and refusals keep their type. */
class LocalKeysLeaseObservationTest {
  private static void use(LocalKeys c, String id, boolean encrypt) {
    try (LocalKeys.Use u = encrypt ? c.forEncrypt() : c.forDecrypt(id)) {
      assertEquals(id, u.id());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void newLeaseObservationMustSupersedeAnUnleasedWritePublication(KmipVersion version) {
    obligationObservedDuringGet(version, true);
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void newLeaseObservationMustSupersedeAnUnleasedReadPublication(KmipVersion version) {
    obligationObservedDuringGet(version, false);
  }

  private void obligationObservedDuringGet(KmipVersion version, boolean outerEncrypt) {
    try (LocalKeysLeaseTest.Fixture f = new LocalKeysLeaseTest.Fixture(version)) {
      String id = f.key().id();
      LocalKeys c = f.cache();
      AtomicBoolean interleave = new AtomicBoolean();
      f.leasing.beforeEach =
          request -> {
            if (LocalKeysTest.is(request, Operation.GET) && interleave.compareAndSet(false, true)) {
              // The outer flight has checked attributes with no Lease Time, but not received Get.
              // A concurrent purpose now observes the new obligation and gets a six-second lease.
              f.leasing.leaseTimes.put(id, 6L);
              use(c, id, !outerEncrypt);
            }
          };
      try {
        use(c, id, outerEncrypt);
      } catch (TransientException superseded) {
        // Discarding the stale flight and asking its caller to retry is a valid resolution.
      }
      assertTrue(interleave.get());
      assertTrue(f.leasing.obtainRequests.get() >= 1);
      f.leasing.beforeEach = request -> {};
      // The observation must not discard the other purpose's newly granted lease.
      use(c, id, !outerEncrypt);
      f.server.unreachable(true);
      f.leasing.dropObtains = true;
      f.advance(6);
      // Neither the newer lease nor any unleased snapshot may authorize this handout.
      assertThrows(
          TransientException.class,
          () -> use(c, id, outerEncrypt),
          "An in-flight pre-obligation snapshot resurrected an unleased entry");
      assertTrue(c.currentWriteId().isEmpty());
      // A newly required lease is not a negative ID entry: both purposes recover on revalidation.
      f.server.unreachable(false);
      f.leasing.dropObtains = false;
      f.advance(1);
      use(c, id, outerEncrypt);
      use(c, id, !outerEncrypt);
    }
  }

  @Test
  void twoThreadsCannotPublishAnUnleasedWriteAfterHistoricalLeaseObservation() throws Exception {
    try (LocalKeysLeaseTest.Fixture f = new LocalKeysLeaseTest.Fixture(KmipVersion.V2_1)) {
      String id = f.key().id();
      LocalKeys c = f.cache();
      CountDownLatch entered = new CountDownLatch(1), release = new CountDownLatch(1);
      AtomicBoolean first = new AtomicBoolean(true);
      f.leasing.beforeEach =
          request -> {
            if (LocalKeysTest.is(request, Operation.GET) && first.getAndSet(false)) {
              entered.countDown();
              try {
                assertTrue(release.await(3, TimeUnit.SECONDS));
              } catch (InterruptedException e) {
                throw new AssertionError(e);
              }
            }
          };
      var pool = Executors.newSingleThreadExecutor();
      try {
        var pending =
            pool.submit(
                () -> {
                  try {
                    use(c, id, true);
                  } catch (TransientException superseded) {
                    /* Valid to discard an obsolete flight. */
                  }
                });
        assertTrue(entered.await(3, TimeUnit.SECONDS));
        f.leasing.leaseTimes.put(id, 6L);
        use(c, id, false);
        release.countDown();
        pending.get(3, TimeUnit.SECONDS);
        f.server.unreachable(true);
        f.leasing.dropObtains = true;
        f.advance(6);
        assertThrows(TransientException.class, c::forEncrypt);
        assertTrue(c.currentWriteId().isEmpty());
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aGrantAlreadyExpiredWhenItsAnswerArrivesMustNotFetchMaterial(KmipVersion version) {
    try (LocalKeysLeaseTest.Fixture f = new LocalKeysLeaseTest.Fixture(version)) {
      String id = f.key().id();
      f.leasing.leaseTimes.put(id, 6L);
      f.leasing.onObtain = () -> f.advance(6);
      LocalKeys c = f.cache();
      assertThrows(TransientException.class, () -> c.forDecrypt(id));
      assertEquals(0, f.gets(), "No lease still runs when the grant is received; do not send Get");
    }
  }

  @Test
  void localTlsDistrustOnObtainRetainsOldGrantButCredentialRefusalEvictsIt() {
    for (boolean distrust : new boolean[] {true, false}) {
      try (LocalKeysLeaseTest.Fixture f = new LocalKeysLeaseTest.Fixture(KmipVersion.V2_1)) {
        String id = f.key().id();
        f.leasing.leaseTimes.put(id, 6L);
        AtomicBoolean fail = new AtomicBoolean();
        try (Kms client =
            Kms.connect(
                f.server
                    .configure()
                    .retryPolicy(RetryPolicy.none())
                    .transport(
                        endpoint ->
                            request -> {
                              if (fail.get() && LocalKeysLeaseTest.obtainLease(request)) {
                                if (distrust)
                                  throw LocalKeysRefreshFailureTest.serverCertificateExpired();
                                throw new javax.net.ssl.SSLHandshakeException(
                                    "Received fatal alert: bad_certificate");
                              }
                              return f.leasing.exchange(request);
                            })
                    .build())) {
          LocalKeys.Builder b =
              client
                  .keys()
                  .localKeys(NAME)
                  .scope(KeyQuery.all().custom(FAMILY, "orders"))
                  .expect(Expect.aes(256))
                  .ttl(Duration.ofSeconds(20))
                  .refreshExecutor(f.executor);
          b.ticker = f.time::get;
          LocalKeys c = b.open();
          f.caches.add(c);
          use(c, id, true);
          fail.set(true);
          f.advance(3);
          use(c, id, false);
          f.executor.run();
          if (distrust) {
            use(c, id, false);
            assertTrue(c.currentWriteId().isPresent());
            f.advance(3);
            assertTrue(c.currentWriteId().isEmpty());
            assertThrows(KmsException.class, () -> c.forDecrypt(id));
          } else {
            assertTrue(c.currentWriteId().isEmpty());
            PermissionDeniedException denied =
                assertThrows(PermissionDeniedException.class, () -> c.forDecrypt(id));
            assertEquals(id, denied.objectId().orElseThrow());
            assertEquals(
                "localKeys", denied.operation(), "TLS has no lease result to contextualize");
            assertTrue(denied.result().isEmpty(), "TLS credential rejection has no KMIP result");
          }
          c.close();
        }
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void lazyNegotiationDoesNotAgeAuthorizationAndDelayedLeaseAnswerDoes(KmipVersion version) {
    try (LocalKeysLeaseTest.Fixture f = new LocalKeysLeaseTest.Fixture(version)) {
      String id = f.key().id();
      f.leasing.leaseTimes.put(id, 6L);
      AtomicBoolean negotiating = new AtomicBoolean(true);
      f.leasing.beforeEach =
          request -> {
            if (LocalKeysTest.is(request, Operation.DISCOVER_VERSIONS)
                && negotiating.getAndSet(false)) f.advance(100);
          };
      f.leasing.onObtain = () -> f.advance(2);
      LocalKeys.Builder b =
          LocalKeys.builder(
                  f.server
                      .configure()
                      .transport(e -> f.leasing)
                      .retryPolicy(RetryPolicy.none())
                      .build(),
                  NAME)
              .scope(KeyQuery.all().custom(FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(Duration.ofSeconds(20))
              .refreshExecutor(f.executor);
      b.ticker = f.time::get;
      LocalKeys c = b.open();
      f.caches.add(c);
      use(c, id, true);
      assertFalse(negotiating.get());
      assertEquals(1, f.leasing.obtainRequests.get());
      f.server.unreachable(true);
      f.leasing.dropObtains = true;
      f.advance(3.999);
      use(c, id, true);
      f.advance(0.001);
      assertTrue(c.currentWriteId().isEmpty());
      assertThrows(TransientException.class, () -> c.forDecrypt(id));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void duplicateOrWronglyTypedIdentifiersNeverGrantAndNeverFetch(KmipVersion version) {
    List<Function<String, List<Ttlv>>> payloads =
        List.of(
            id ->
                List.of(
                    Ttlv.text(Tag.UNIQUE_IDENTIFIER, id),
                    Ttlv.text(Tag.UNIQUE_IDENTIFIER, id),
                    Ttlv.interval(Tag.LEASE_TIME, 6)),
            id ->
                List.of(Ttlv.integer(Tag.UNIQUE_IDENTIFIER, 42), Ttlv.interval(Tag.LEASE_TIME, 6)),
            id ->
                List.of(Ttlv.text(Tag.UNIQUE_IDENTIFIER, id), Ttlv.enumeration(Tag.LEASE_TIME, 6)));
    for (var payload : payloads) {
      try (LocalKeysLeaseTest.Fixture f = new LocalKeysLeaseTest.Fixture(version)) {
        String id = f.key().id();
        f.leasing.leaseTimes.put(id, 6L);
        f.leasing.answer = ignored -> new LeasingTransport.Malformed(payload);
        LocalKeys c = f.cache();
        assertThrows(ProtocolViolationException.class, () -> c.forDecrypt(id));
        assertEquals(0, f.gets());
        assertTrue(c.currentWriteId().isEmpty());
      }
    }
  }

  @Test
  void longLeaseCannotExtendShortTtlOrSeededRead() {
    try (LocalKeysLeaseTest.Fixture f = new LocalKeysLeaseTest.Fixture(KmipVersion.V2_1)) {
      String id = f.key().id();
      f.leasing.leaseTimes.put(id, 100L);
      LocalKeys c = f.builder().ttl(Duration.ofSeconds(2)).open();
      f.caches.add(c);
      use(c, id, true);
      f.server.unreachable(true);
      f.leasing.dropObtains = true;
      f.advance(2);
      assertTrue(c.currentWriteId().isEmpty());
      assertThrows(TransientException.class, c::forEncrypt);
      assertThrows(TransientException.class, () -> c.forDecrypt(id));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void stateRefusalKeepsItsExceptionTypePurposeAndWireResult(KmipVersion version) {
    try (LocalKeysLeaseTest.Fixture f = new LocalKeysLeaseTest.Fixture(version)) {
      String id = f.key().id();
      f.leasing.leaseTimes.put(id, 6L);
      f.leasing.answer =
          ignored -> new LeasingTransport.Refuse(Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE);
      StateConflictException e =
          assertThrows(StateConflictException.class, () -> f.cache().forDecrypt(id));
      assertEquals("obtainLease", e.operation());
      assertEquals(id, e.objectId().orElseThrow());
      assertTrue(e.getMessage().contains("for DECRYPT"));
      assertEquals(Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE, e.protocolReason().orElseThrow());
      assertEquals("lease refused for " + id, e.serverMessage().orElseThrow());
      assertTrue(e.result().isPresent());
      assertEquals(0, f.gets());
    }
  }
}
