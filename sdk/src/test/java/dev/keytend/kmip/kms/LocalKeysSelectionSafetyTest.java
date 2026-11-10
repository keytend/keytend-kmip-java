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

import static dev.keytend.kmip.kms.LocalKeysTest.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.LeasingTransport.Grant;
import java.time.Instant;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Named write selection is preserved: the name is part of the operator contract, so withdrawal,
 * ambiguity and refusal are observed at validation and never hidden; historical reads use exact IDs
 * within their own TTL and lease.
 */
class LocalKeysSelectionSafetyTest {
  private static String encrypt(LocalKeys c) {
    try (LocalKeys.Use u = c.forEncrypt()) {
      return u.id();
    }
  }

  private static String decrypt(LocalKeys c, String id) {
    try (LocalKeys.Use u = c.forDecrypt(id)) {
      return u.id();
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aMissingNameIsARefusalEvenWithEligibleUnnamedOrForeignKeys(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle unnamed = f.key(256, "orders", null, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
      f.key(256, "elsewhere", NAME, KeyUsage.ENCRYPT, KeyUsage.DECRYPT); // named, outside the scope
      LocalKeys c = f.cache();
      assertThrows(NotFoundException.class, c::forEncrypt);
      assertTrue(c.currentWriteId().isEmpty());
      assertEquals(unnamed.id(), decrypt(c, unnamed.id())); // exact-ID history is unaffected
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anAmbiguityWhereThePriorKeyIsNoLongerACandidateFailsInsteadOfGuessing(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle x = f.key();
      LocalKeys c = f.cache();
      assertEquals(x.id(), encrypt(c));
      x.removeName(NAME);
      KeyHandle y = f.key(), z = f.key();
      f.advance(5);
      encrypt(c);
      f.executor.run();
      assertTrue(c.currentWriteId().isEmpty(), "the withdrawn prior selection is not kept");
      StateConflictException ambiguous = assertThrows(StateConflictException.class, c::forEncrypt);
      assertTrue(
          ambiguous.getMessage().contains(y.id()) && ambiguous.getMessage().contains(z.id()));
      assertFalse(ambiguous.getMessage().contains(x.id()));
      assertEquals(x.id(), decrypt(c, x.id()));
      f.advance(2); // after the selector's short backoff it is still ambiguous, not resolved by age
      assertThrows(StateConflictException.class, c::forEncrypt);
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void nameRemovalTogetherWithARefusalStopsWritesAndTheRefusalReachesHistoricalReads(
      KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle x = f.key();
      LocalKeys c = f.cache();
      assertEquals(x.id(), encrypt(c));
      assertEquals(x.id(), decrypt(c, x.id()));
      x.removeName(NAME);
      x.revoke(RevocationReason.keyCompromise("test", Instant.now()));
      f.advance(5);
      encrypt(c);
      decrypt(c, x.id());
      f.executor.run();
      f.executor.run();
      assertThrows(NotFoundException.class, c::forEncrypt);
      StateConflictException compromised =
          assertThrows(StateConflictException.class, () -> c.forDecrypt(x.id()));
      assertEquals(KeyState.COMPROMISED, compromised.observedState().orElseThrow());
      f.server.unreachable(true); // a remembered refusal does not turn into an outage-retained copy
      assertThrows(StateConflictException.class, () -> c.forDecrypt(x.id()));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anOldLeasedKeysHistoricalCopyEndsAtItsLeaseDuringAnOutageAfterRotation(KmipVersion version) {
    try (LocalKeysLeaseTest.Fixture f = new LocalKeysLeaseTest.Fixture(version)) {
      f.leasing.everyObject = 6L;
      f.leasing.answer = id -> new Grant(6);
      KeyHandle x = f.key();
      LocalKeys c = f.cache();
      assertEquals(x.id(), encrypt(c)); // t=0: x and its seeded Decrypt copy leased until t=6
      x.removeName(NAME);
      KeyHandle y = f.key();
      f.advance(3);
      assertEquals(x.id(), encrypt(c)); // half the lease: revalidation queued
      f.executor.run();
      assertEquals(y.id(), encrypt(c)); // y leased from t=3
      assertEquals(x.id(), decrypt(c, x.id())); // renewal of x's historical copy queued
      f.server.unreachable(true);
      f.leasing.dropObtains = true;
      f.executor.run(); // no new lease
      f.advance(2.999);
      assertEquals(x.id(), decrypt(c, x.id()));
      f.advance(0.001);
      assertThrows(TransientException.class, () -> c.forDecrypt(x.id())); // old lease ended
      assertEquals(y.id(), encrypt(c));
      f.advance(3);
      assertThrows(TransientException.class, c::forEncrypt);
    }
  }
}
