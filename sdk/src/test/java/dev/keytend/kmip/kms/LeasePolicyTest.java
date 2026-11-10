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

import dev.keytend.kmip.kms.LeasingTransport.NotUnderstood;
import dev.keytend.kmip.kms.LeasingTransport.Refuse;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link LeasePolicy#HONOR_IF_SUPPORTED}: a server that states a Lease Time and does not
 * implement Obtain Lease (its answer, confirmed by its Query Operations) is used under the stated
 * Lease Time as a hard local bound; every other refusal stays one, and {@link LeasePolicy#REQUIRE},
 * the default, refuses it too.
 */
class LeasePolicyTest {
  static final class Fixture implements AutoCloseable {
    final InMemoryKmipServer server;
    final LeasingTransport leasing;
    final Kms admin, client;
    final KmipVersion version;
    final List<String> told = new CopyOnWriteArrayList<>();

    Fixture(KmipVersion version, LeasePolicy policy) {
      this.version = version;
      server = InMemoryKmipServer.of(version);
      leasing = new LeasingTransport(server);
      admin = server.connect();
      KmsConfig.Builder b =
          server
              .configure()
              .retryPolicy(RetryPolicy.none())
              .callTimeout(Duration.ofSeconds(5))
              .transport(e -> leasing)
              .addListener(
                  new KmsListener() {
                    @Override
                    public void leaseNotGranted(String keyId, Duration bound) {
                      told.add(keyId + " " + bound);
                    }
                  });
      if (policy != null) b.leases(policy);
      client = Kms.connect(b.build());
      leasing.everyObject = 3600L;
    }

    KeyHandle key(String name) {
      KeyCreation c =
          admin
              .keys()
              .createAes(256)
              .custom(LocalKeysTest.FAMILY, "orders")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named(name);
      if (version.compareTo(KmipVersion.V1_4) >= 0) c.extractable(true);
      return client.keys().handle(c.create().id());
    }

    @Override
    public void close() {
      client.close();
      admin.close();
      server.close();
    }
  }

  static final Refuse UNSUPPORTED = new Refuse(Enums.ResultReason.OPERATION_NOT_SUPPORTED);

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void requireIsTheDefaultAndRefusesAServerWithoutObtainLease(KmipVersion version) {
    try (Fixture f = new Fixture(version, null)) {
      assertEquals(LeasePolicy.REQUIRE, f.client.config.leases());
      f.leasing.answer = id -> UNSUPPORTED;
      KeyHandle key = f.key("tde");
      assertThrows(
          UnsupportedException.class, () -> key.asSecretKey(Expect.aes(), LocalUse.DECRYPT));
      f.leasing.answer = id -> new NotUnderstood();
      assertThrows(
          InvalidRequestException.class, () -> key.asSecretKey(Expect.aes(), LocalUse.DECRYPT));
      assertEquals(0, f.leasing.queries.get(), "REQUIRE asks nothing more");
      assertEquals(List.of(), f.told);
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aServerThatDoesNotImplementObtainLeaseIsUsedUnderTheStatedLeaseTime(KmipVersion version) {
    for (LeasingTransport.Answer answer : List.of(UNSUPPORTED, new NotUnderstood()))
      try (Fixture f = new Fixture(version, LeasePolicy.HONOR_IF_SUPPORTED)) {
        f.leasing.answer = id -> answer;
        KeyHandle a = f.key("a"), b = f.key("b");
        a.asSecretKey(Expect.aes(), LocalUse.DECRYPT).destroy();
        a.asSecretKey(Expect.aes(), LocalUse.DECRYPT).destroy();
        b.asSecretKey(Expect.aes(), LocalUse.ENCRYPT).destroy();
        assertEquals(
            1, f.leasing.queries.get(), answer + ": the server's operations are read once per Kms");
        assertEquals(
            List.of(a.id() + " PT1H", b.id() + " PT1H"), f.told, answer + ": once per key");
      }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void everyOtherRefusalStaysARefusal(KmipVersion version) {
    try (Fixture f = new Fixture(version, LeasePolicy.HONOR_IF_SUPPORTED)) {
      KeyHandle key = f.key("tde");
      f.leasing.answer = id -> new Refuse(Enums.ResultReason.PERMISSION_DENIED);
      assertThrows(
          PermissionDeniedException.class, () -> key.asSecretKey(Expect.aes(), LocalUse.DECRYPT));
      // An item-level Invalid Message is a refusal of this request, not an operation not
      // understood.
      f.leasing.answer = id -> new Refuse(Enums.ResultReason.INVALID_MESSAGE);
      assertThrows(
          InvalidRequestException.class, () -> key.asSecretKey(Expect.aes(), LocalUse.DECRYPT));
      f.admin.keys().handle(key.id()).deactivate();
      f.leasing.answer = id -> new Refuse(Enums.ResultReason.PERMISSION_DENIED);
      assertThrows(
          StateConflictException.class, () -> key.asSecretKey(Expect.aes(), LocalUse.DECRYPT));
      assertEquals(List.of(), f.told);
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aServerThatListsObtainLeaseOrStatesZeroIsNotExcused(KmipVersion version) {
    try (Fixture f = new Fixture(version, LeasePolicy.HONOR_IF_SUPPORTED)) {
      f.leasing.listsObtainLease = true; // it does implement it, and refuses
      f.leasing.answer = id -> UNSUPPORTED;
      KeyHandle key = f.key("tde");
      assertThrows(
          UnsupportedException.class, () -> key.asSecretKey(Expect.aes(), LocalUse.DECRYPT));
      assertThrows(
          UnsupportedException.class, () -> key.asSecretKey(Expect.aes(), LocalUse.DECRYPT));
      assertEquals(1, f.leasing.queries.get(), "the answer is kept");
    }
    try (Fixture f = new Fixture(version, LeasePolicy.HONOR_IF_SUPPORTED)) {
      f.leasing.everyObject = 0L; // a stated zero bounds nothing
      f.leasing.answer = id -> UNSUPPORTED;
      KeyHandle key = f.key("tde");
      assertThrows(
          UnsupportedException.class, () -> key.asSecretKey(Expect.aes(), LocalUse.DECRYPT));
      assertEquals(List.of(), f.told);
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void localKeysHoldsACopyNoLongerThanTheStatedLeaseTime(KmipVersion version) {
    try (Fixture f = new Fixture(version, LeasePolicy.HONOR_IF_SUPPORTED)) {
      f.leasing.everyObject = 6L;
      f.leasing.answer = id -> new NotUnderstood();
      KeyHandle key = f.key(LocalKeysTest.NAME);
      AtomicLong time = new AtomicLong(100);
      LocalKeys.Builder b =
          f.client
              .keys()
              .localKeys(LocalKeysTest.NAME)
              .scope(KeyQuery.all().custom(LocalKeysTest.FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(Duration.ofSeconds(60))
              .refreshExecutor(Runnable::run);
      b.ticker = time::get;
      try (LocalKeys keys = b.open()) {
        keys.forDecrypt(key.id()).close();
        assertEquals(List.of(key.id() + " PT6S"), f.told);
        // The stated six seconds end the copy, whatever the TTL: with the KMS gone, refused.
        f.leasing.dropObtains = true;
        f.server.unreachable(true);
        time.addAndGet(TimeUnit.SECONDS.toNanos(7));
        assertThrows(KmsException.class, () -> keys.forDecrypt(key.id()));
      }
    }
  }
}
