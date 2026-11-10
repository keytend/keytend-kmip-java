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

import dev.keytend.kmip.kms.LeasingTransport.Grant;
import dev.keytend.kmip.kms.LeasingTransport.Refuse;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.security.KeyPair;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * One lease rule for every path that hands key material to the application: a key whose
 * Get Attributes states a Lease Time (zero too) is read only after Obtain Lease grants it, a
 * refusal hands out nothing and says why.
 */
class RawKeyLeaseTest {
  static final class Fixture implements AutoCloseable {
    final InMemoryKmipServer server;
    final LeasingTransport leasing;
    final Kms admin, client;
    final KmipVersion version;

    Fixture(KmipVersion version) {
      this.version = version;
      server = InMemoryKmipServer.of(version);
      leasing = new LeasingTransport(server);
      admin = server.connect();
      client =
          Kms.connect(
              server
                  .configure()
                  .retryPolicy(RetryPolicy.none())
                  .callTimeout(Duration.ofSeconds(5))
                  .transport(e -> leasing)
                  .build());
    }

    KeyHandle key(String name) {
      KeyCreation c =
          admin.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named(name);
      if (version.compareTo(KmipVersion.V1_4) >= 0) c.extractable(true);
      return client.keys().handle(c.create().id());
    }

    /** The operations sent for {@code id}, in order. */
    List<String> ops(String id) {
      return leasing.trace.stream()
          .filter(t -> t.endsWith(" " + id))
          .map(t -> t.substring(0, t.indexOf(' ')))
          .toList();
    }

    @Override
    public void close() {
      client.close();
      admin.close();
      server.close();
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void everyOneShotReadObtainsTheLeaseBeforeItsGet(KmipVersion version) throws Exception {
    try (Fixture f = new Fixture(version)) {
      f.server.leaseTime(Duration.ofHours(1)); // the server's own leases, passed through and traced
      KeyHandle key = f.key("tde");
      f.leasing.reset();
      key.asSecretKey(Expect.aes(256), LocalUse.DECRYPT).destroy();
      assertEquals(List.of("GetAttributes", "ObtainLease", "Get"), f.ops(key.id()));
      f.leasing.reset();
      key.asSecretKey(Expect.aes(), LocalUse.ENCRYPT).destroy();
      assertEquals(List.of("GetAttributes", "ObtainLease", "Get"), f.ops(key.id()));
      KeyHandle secret =
          f.client
              .keys()
              .handle(
                  f.admin.keys().registerSecret("pw".toCharArray()).named("pw").register().id());
      f.leasing.reset();
      secret.asSecretData().destroy();
      assertEquals(List.of("GetAttributes", "ObtainLease", "Get"), f.ops(secret.id()));
      KeyPair pair = TestPki.ec();
      KeyHandle priv =
          f.client
              .keys()
              .handle(
                  f.admin
                      .keys()
                      .register(pair.getPrivate())
                      .usages(KeyUsage.SIGN)
                      .named("p")
                      .register()
                      .id());
      f.leasing.reset();
      assertNotNull(priv.asPrivateKey(Expect.ec(256)));
      assertEquals(List.of("GetAttributes", "ObtainLease", "Get"), f.ops(priv.id()));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aKeyWithoutLeaseTimeIsAskedForNoLeaseAndZeroIsStillALease(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key("tde");
      f.leasing.reset();
      key.asSecretKey(Expect.aes(), LocalUse.DECRYPT).destroy();
      assertEquals(List.of("GetAttributes", "Get"), f.ops(key.id()));
      // Lease Time 0 (keytend-kmip-server with --max-lease-seconds 0): an obligation all the same;
      // its
      // grant decides the limit, whether zero (none) or positive.
      f.leasing.everyObject = 0L;
      for (long grant : new long[] {0, 30}) {
        f.leasing.answer = id -> new Grant(grant);
        f.leasing.reset();
        key.asSecretKey(Expect.aes(), LocalUse.DECRYPT).destroy();
        assertEquals(
            List.of("GetAttributes", "ObtainLease", "Get"), f.ops(key.id()), "grant " + grant);
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRefusedLeaseHandsOutNothingAndSaysWhy(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      f.leasing.everyObject = 3600L;
      KeyHandle key = f.key("tde");
      // As keytend-kmip-server --lease-states active: only Active objects get a lease.
      f.leasing.answer = id -> new Refuse(Enums.ResultReason.PERMISSION_DENIED);
      f.leasing.reset();
      PermissionDeniedException active =
          assertThrows(
              PermissionDeniedException.class,
              () -> key.asSecretKey(Expect.aes(), LocalUse.ENCRYPT));
      assertEquals("obtainLease", active.operation());
      assertTrue(active.getMessage().contains("refused to lease " + key.id()), active.getMessage());
      assertTrue(
          active.getMessage().contains("lease refused for " + key.id()),
          "the server's message: " + active.getMessage());
      assertEquals(KmsReason.PERMISSION_DENIED, active.serverReason().orElseThrow());
      // Read as Active: its State is read once more, and it is still Active.
      assertEquals(List.of("GetAttributes", "ObtainLease", "GetAttributes"), f.ops(key.id()));
      f.admin.keys().handle(key.id()).deactivate();
      f.leasing.reset();
      StateConflictException deactivated =
          assertThrows(
              StateConflictException.class, () -> key.asSecretKey(Expect.aes(), LocalUse.DECRYPT));
      assertEquals(KmsException.Category.STATE, deactivated.category());
      assertEquals(KeyState.DEACTIVATED, deactivated.observedState().orElseThrow());
      assertEquals("obtainLease", deactivated.operation());
      assertEquals(KmsReason.PERMISSION_DENIED, deactivated.serverReason().orElseThrow());
      assertTrue(deactivated.getMessage().contains("Active"), deactivated.getMessage());
      assertTrue(
          deactivated.getMessage().contains("lease refused for " + key.id()),
          deactivated.getMessage());
      assertEquals(List.of("GetAttributes", "ObtainLease"), f.ops(key.id()));
      // An outage grants nothing: no value without a lease.
      f.leasing.answer = id -> new Grant(3600);
      f.leasing.dropObtains = true;
      f.leasing.reset();
      assertThrows(KmsException.class, () -> key.asSecretKey(Expect.aes(), LocalUse.DECRYPT));
      assertFalse(f.ops(key.id()).contains("Get"), f.ops(key.id()).toString());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void localKeysReportsALeaseRefusedForADeactivatedKeyAsItsState(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      f.server
          .leaseTime(Duration.ofHours(1))
          .leasesOnlyForActive(true); // as keytend-kmip-server --lease-states active
      KeyCreation c =
          f.admin
              .keys()
              .createAes(256)
              .custom(LocalKeysTest.FAMILY, "orders")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named(LocalKeysTest.NAME);
      if (version.compareTo(KmipVersion.V1_4) >= 0) c.extractable(true);
      KeyHandle key = c.create();
      key.deactivate();
      try (LocalKeys keys =
          f.client
              .keys()
              .localKeys(LocalKeysTest.NAME)
              .scope(KeyQuery.all().custom(LocalKeysTest.FAMILY, "orders"))
              .expect(Expect.aes(256))
              .open()) {
        StateConflictException e =
            assertThrows(StateConflictException.class, () -> keys.forDecrypt(key.id()));
        assertEquals(KeyState.DEACTIVATED, e.observedState().orElseThrow());
        assertEquals("obtainLease", e.operation());
        assertTrue(
            e.getMessage().contains("Only active objects may receive a lease"), e.getMessage());
      }
    }
  }

  /**
   * A key read as Active and changed before its Obtain Lease (deactivated, compromised, destroyed by
   * another caller): the refusal is reported by the state read once more, not as an access refusal.
   * The change is made between the two requests, so the race is the same on every run.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLeaseRefusedInALifecycleRaceIsReportedByTheStateReadAgain(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      f.server.leaseTime(Duration.ofHours(1)).leasesOnlyForActive(true);
      for (KeyState to : new KeyState[] {KeyState.DEACTIVATED, KeyState.COMPROMISED}) {
        KeyHandle key = f.key("race-" + to);
        f.leasing.onObtain = once(f, () -> change(f.admin.keys().handle(key.id()), to));
        f.leasing.reset();
        StateConflictException e =
            assertThrows(
                StateConflictException.class,
                () -> key.asSecretKey(Expect.aes(), LocalUse.DECRYPT),
                to.toString());
        assertEquals(KmsException.Category.STATE, e.category());
        assertEquals(to, e.observedState().orElseThrow());
        assertEquals("obtainLease", e.operation());
        assertEquals(key.id(), e.objectId().orElseThrow());
        assertEquals(KmsReason.PERMISSION_DENIED, e.serverReason().orElseThrow());
        assertTrue(e.getMessage().contains("read again after the refusal"), e.getMessage());
        assertTrue(
            e.getMessage().contains("Only active objects may receive a lease"), e.getMessage());
        assertEquals(List.of("GetAttributes", "ObtainLease", "GetAttributes"), f.ops(key.id()));
      }
      // Destroyed meanwhile: Item Not Found says so already, and nothing is read again.
      KeyHandle gone = f.key("race-destroyed");
      f.leasing.onObtain =
          once(
              f,
              () -> {
                KeyHandle admin = f.admin.keys().handle(gone.id());
                admin.deactivate();
                admin.destroy();
              });
      f.leasing.reset();
      assertThrows(NotFoundException.class, () -> gone.asSecretKey(Expect.aes(), LocalUse.DECRYPT));
      assertEquals(List.of("GetAttributes", "ObtainLease"), f.ops(gone.id()));
    }
  }

  /**
   * A refusal of a key that is still Active when read again is the server's own answer (an access
   * policy): its type is kept. When the second read fails, the refusal is reported as it was, with
   * that failure suppressed on it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLeaseRefusedForAKeyStillActiveKeepsItsTypeAndAFailedReadIsSuppressed(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      f.leasing.everyObject = 3600L;
      f.leasing.answer = id -> new Refuse(Enums.ResultReason.PERMISSION_DENIED);
      KeyHandle key = f.key("still-active");
      f.leasing.reset();
      PermissionDeniedException denied =
          assertThrows(
              PermissionDeniedException.class,
              () -> key.asSecretKey(Expect.aes(), LocalUse.DECRYPT));
      assertEquals("obtainLease", denied.operation());
      assertEquals(0, denied.getSuppressed().length);
      assertEquals(List.of("GetAttributes", "ObtainLease", "GetAttributes"), f.ops(key.id()));
      f.leasing.onObtain =
          once(
              f,
              () ->
                  f.server.failNext(
                      dev.keytend.kmip.testing.ServerOperation.GET_ATTRIBUTES,
                      dev.keytend.kmip.testing.Fault.SERVER_FAILURE));
      f.leasing.reset();
      PermissionDeniedException unread =
          assertThrows(
              PermissionDeniedException.class,
              () -> key.asSecretKey(Expect.aes(), LocalUse.DECRYPT));
      assertEquals(
          1, unread.getSuppressed().length, java.util.Arrays.toString(unread.getSuppressed()));
      assertInstanceOf(ServerFailureException.class, unread.getSuppressed()[0]);
    }
  }

  /** {@link LocalKeys} reports the same race by the state read again. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void localKeysReportsALeaseRefusedInALifecycleRaceByTheStateReadAgain(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      f.server.leaseTime(Duration.ofHours(1)).leasesOnlyForActive(true);
      KeyCreation c =
          f.admin
              .keys()
              .createAes(256)
              .custom(LocalKeysTest.FAMILY, "orders")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named(LocalKeysTest.NAME);
      if (version.compareTo(KmipVersion.V1_4) >= 0) c.extractable(true);
      KeyHandle key = c.create();
      try (LocalKeys keys =
          f.client
              .keys()
              .localKeys(LocalKeysTest.NAME)
              .scope(KeyQuery.all().custom(LocalKeysTest.FAMILY, "orders"))
              .expect(Expect.aes(256))
              .open()) {
        f.leasing.onObtain = once(f, () -> f.admin.keys().handle(key.id()).deactivate());
        f.leasing.reset();
        StateConflictException e =
            assertThrows(StateConflictException.class, () -> keys.forDecrypt(key.id()));
        assertEquals(KeyState.DEACTIVATED, e.observedState().orElseThrow());
        assertEquals("obtainLease", e.operation());
        assertTrue(e.getMessage().contains("read again after the refusal"), e.getMessage());
        assertEquals(List.of("GetAttributes", "ObtainLease", "GetAttributes"), f.ops(key.id()));
      }
    }
  }

  /**
   * The leases the TLS followers obtain ({@link Leases#obtain}) settle the same race: the first
   * refusal of an object whose State is now a known state other than Active is reported by it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theFollowersLeasesReportARefusalInALifecycleRaceByTheStateReadAgain(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      f.server.leaseTime(Duration.ofHours(1)).leasesOnlyForActive(true);
      KeyHandle key = f.key("tls-race");
      f.leasing.onObtain = once(f, () -> f.admin.keys().handle(key.id()).deactivate());
      Leases leases = new Leases();
      java.util.Map<String, Duration> times = java.util.Map.of(key.id(), Duration.ofHours(1));
      f.leasing.reset();
      Leases.Outcome outcome = leases.obtain(f.client, times, true);
      StateConflictException e = assertInstanceOf(StateConflictException.class, outcome.refused());
      assertEquals(KeyState.DEACTIVATED, e.observedState().orElseThrow());
      assertEquals("obtainLease", e.operation());
      assertEquals(KmsReason.PERMISSION_DENIED, e.serverReason().orElseThrow());
      assertFalse(leases.usable(key.id()));
      assertEquals(List.of("ObtainLease", "GetAttributes"), f.ops(key.id()));
      // Refused while Active: the server's answer as it was.
      KeyHandle other = f.key("tls-denied");
      f.leasing.leaseTimes.put(other.id(), 3600L);
      f.leasing.answer = id -> new Refuse(Enums.ResultReason.PERMISSION_DENIED);
      f.leasing.reset();
      Leases.Outcome denied =
          leases.obtain(f.client, java.util.Map.of(other.id(), Duration.ofHours(1)), true);
      assertInstanceOf(PermissionDeniedException.class, denied.refused());
      assertEquals(List.of("ObtainLease", "GetAttributes"), f.ops(other.id()));
    }
  }

  /** {@code action}, run at the next Obtain Lease only. */
  private static Runnable once(Fixture f, Runnable action) {
    return () -> {
      f.leasing.onObtain = () -> {};
      action.run();
    };
  }

  private static void change(KeyHandle key, KeyState to) {
    if (to == KeyState.DEACTIVATED) key.deactivate();
    else key.revoke(RevocationReason.keyCompromise("race", java.time.Instant.now()));
  }

  @org.junit.jupiter.api.Test
  void theServersMessageInALeaseRefusalIsOneShortLine() {
    String sanitized =
        KmsException.sanitized("a\nb\u2028c\u2029d\u202Ee\"f\u0007" + "x".repeat(300));
    assertEquals(-1, sanitized.indexOf('\n'));
    for (char c : new char[] {'\u2028', '\u2029', '\u202E', '"', '\u0007'})
      assertEquals(-1, sanitized.indexOf(c), Integer.toHexString(c));
    assertTrue(sanitized.startsWith("a b c d e f "), sanitized);
    assertEquals(203, sanitized.length(), "200 characters and an ellipsis");
    // Neither a reason nor a message: no empty parentheses.
    KmsException bare =
        Leases.refused(
            new PermissionDeniedException("refused"), "k1", "asSecretKey", KeyState.ACTIVE);
    assertEquals("asSecretKey: the server refused to lease k1", bare.getMessage());
  }
}
