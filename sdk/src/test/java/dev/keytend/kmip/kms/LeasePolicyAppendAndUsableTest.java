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

import static dev.keytend.kmip.kms.TlsIdentityTest.HOURLY;
import static dev.keytend.kmip.kms.TlsIdentityTest.SCHEDULER;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.LeasingTransport.Refuse;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.security.KeyPair;
import java.time.Duration;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link LocalKeys#forAppend(String)} and the {@code usableFor()} diagnostics under {@link
 * LeasePolicy}: against a server that states a Lease Time and does not implement Obtain Lease,
 * {@link LeasePolicy#REQUIRE} hands nothing out, and {@link LeasePolicy#HONOR_IF_SUPPORTED} uses
 * the stated Lease Time as the bound an exact key is handed out under and that {@code usableFor()}
 * reports.
 */
class LeasePolicyAppendAndUsableTest {
  static final Refuse UNSUPPORTED = new Refuse(Enums.ResultReason.OPERATION_NOT_SUPPORTED);
  static final String NAME = "orders-write";

  static final class Fixture implements AutoCloseable {
    final InMemoryKmipServer server;
    final LeasingTransport leasing;
    final Kms admin, client;
    final KmipVersion version;
    final AtomicLong time = new AtomicLong(100);

    Fixture(KmipVersion version, LeasePolicy policy, long statedSeconds) {
      this.version = version;
      server = InMemoryKmipServer.of(version);
      leasing = new LeasingTransport(server);
      leasing.everyObject = statedSeconds;
      leasing.answer = id -> UNSUPPORTED; // the server does not implement Obtain Lease
      admin = server.connect();
      client =
          Kms.connect(
              server
                  .configure()
                  .maximumVersion(KmipVersion.V3_0)
                  .retryPolicy(RetryPolicy.none())
                  .callTimeout(Duration.ofSeconds(5))
                  .transport(e -> leasing)
                  .leases(policy)
                  .build());
    }

    KeyHandle key(String name) {
      KeyCreation c =
          admin
              .keys()
              .createAes(256)
              .custom(LocalKeysTest.FAMILY, "orders")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
      if (name != null) c.named(name);
      if (version.compareTo(KmipVersion.V1_4) >= 0) c.extractable(true);
      return c.create();
    }

    LocalKeys cache() {
      LocalKeys.Builder b =
          client
              .keys()
              .localKeys(NAME)
              .scope(KeyQuery.all().custom(LocalKeysTest.FAMILY, "orders"))
              .expect(Expect.aes(256))
              .ttl(Duration.ofSeconds(60))
              .refreshAfter(Duration.ofSeconds(50))
              .refreshExecutor(r -> {});
      b.ticker = time::get;
      return b.open();
    }

    void advance(long seconds) {
      time.addAndGet(TimeUnit.SECONDS.toNanos(seconds));
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
  void requireHandsOutNoExactKeyFromAServerWithoutObtainLease(KmipVersion version) {
    try (Fixture f = new Fixture(version, LeasePolicy.REQUIRE, 8);
        LocalKeys keys = f.cache()) {
      KeyHandle open = f.key(null);
      assertThrows(UnsupportedException.class, () -> keys.forAppend(open.id()));
      assertEquals(Optional.of(Duration.ZERO), keys.usableFor());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void honorIfSupportedBoundsAnOpenFilesKeyAndUsableForByTheStatedLeaseTime(KmipVersion version) {
    try (Fixture f = new Fixture(version, LeasePolicy.HONOR_IF_SUPPORTED, 8);
        LocalKeys keys = f.cache()) {
      KeyHandle write = f.key(NAME), open = f.key(null);
      try (LocalKeys.Use use = keys.forEncrypt()) {
        assertEquals(write.id(), use.id());
      }
      assertEquals(
          Optional.of(Duration.ofSeconds(8)),
          keys.usableFor(),
          "the stated Lease Time, shorter than the TTL");
      try (LocalKeys.Use use = keys.forAppend(open.id())) {
        assertEquals(open.id(), use.id());
      }
      f.server.unreachable(true);
      f.advance(7);
      try (LocalKeys.Use use = keys.forAppend(open.id())) {
        assertEquals(open.id(), use.id());
      }
      assertEquals(Optional.of(Duration.ofSeconds(1)), keys.usableFor());
      f.advance(2);
      assertThrows(TransientException.class, () -> keys.forAppend(open.id()), "the bound is hard");
      assertThrows(TransientException.class, () -> keys.forAppend(write.id()));
      assertEquals(Optional.of(Duration.ZERO), keys.usableFor());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theTlsFollowersReportTheStatedLeaseTimeAsTheirBound(KmipVersion version) throws Exception {
    for (LeasePolicy policy : LeasePolicy.values())
      try (Fixture f = new Fixture(version, policy, 300)) {
        TlsIdentityTest.Pki pki = new TlsIdentityTest.Pki();
        KeyPair k = TestPki.ec();
        f.admin
            .tls()
            .register(k.getPrivate(), pki.chain(pki.leaf("node", k)))
            .named("node")
            .register();
        if (policy == LeasePolicy.REQUIRE) {
          assertThrows(
              UnsupportedException.class, () -> f.client.tls().follow("node", HOURLY, SCHEDULER));
          continue;
        }
        try (TlsIdentityFollower follower = f.client.tls().follow("node", HOURLY, SCHEDULER)) {
          AtomicLong now = new AtomicLong(System.nanoTime());
          follower.leases.clock = now::get;
          Duration left = follower.usableFor().orElseThrow();
          assertTrue(
              left.compareTo(Duration.ofSeconds(299)) > 0
                  && left.compareTo(Duration.ofSeconds(300)) <= 0,
              left.toString());
          now.addAndGet(TimeUnit.SECONDS.toNanos(301));
          assertEquals(Optional.of(Duration.ZERO), follower.usableFor());
          assertTrue(follower.identity().isEmpty(), "the bound is hard");
        }
      }
  }
}
