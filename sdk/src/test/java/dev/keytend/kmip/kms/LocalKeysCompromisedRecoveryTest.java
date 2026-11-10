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

import java.time.Duration;
import java.time.Instant;
import java.util.AbstractList;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.slf4j.event.Level;

/**
 * Files under a key revoked as Compromised: refused by default; {@link
 * LocalKeys.Builder#allowCompromisedForDecrypt()}, a separately configured maintenance setting,
 * decrypts with such a key where the server still allows it, never encrypts with it, and warns.
 */
class LocalKeysCompromisedRecoveryTest {
  /** The warnings the cache logs while open (logger {@code dev.keytend.kmip.kms.LocalKeys}). */
  static final class Warnings implements AutoCloseable {
    private final TestLogs.Capture capture = TestLogs.capture();
    final List<String> messages =
        new AbstractList<>() {
          @Override
          public String get(int index) {
            return all().get(index);
          }

          @Override
          public int size() {
            return all().size();
          }
        };

    List<String> all() {
      return capture.messages(LocalKeys.class.getName(), Level.WARN);
    }

    @Override
    public void close() {
      capture.close();
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void onlyTheMaintenanceSettingDecryptsWithACompromisedKeyAndItNeverEncrypts(KmipVersion version) {
    try (Fixture f = new Fixture(version);
        Warnings warnings = new Warnings()) {
      KeyHandle key = f.key();
      key.revoke(RevocationReason.keyCompromise("node disk stolen", Instant.now()));
      LocalKeys normal = f.cache();
      assertEquals(
          KeyState.COMPROMISED,
          assertThrows(StateConflictException.class, () -> normal.forDecrypt(key.id()))
              .observedState()
              .orElseThrow());
      assertEquals(List.of(), warnings.messages, "nothing to warn of");

      LocalKeys recovery = f.keep(f.builder().allowCompromisedForDecrypt().open());
      assertEquals(1, warnings.messages.size(), "warned at open: " + warnings.messages);
      assertTrue(warnings.messages.get(0).contains("maintenance"), warnings.messages.get(0));
      try (LocalKeys.Use use = recovery.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
      assertEquals(2, warnings.messages.size(), warnings.messages.toString());
      assertTrue(warnings.messages.get(1).contains(key.id()), warnings.messages.get(1));
      try (LocalKeys.Use use = recovery.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
      assertEquals(2, warnings.messages.size(), "once per validation, not per handout");
      recovery.invalidate(key.id());
      try (LocalKeys.Use use = recovery.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
      assertEquals(2, warnings.messages.size(), "a validation again within the minute: counted");
      // Never for encryption, and refusing that does not end the recovery's decryption.
      assertEquals(
          KeyState.COMPROMISED,
          assertThrows(StateConflictException.class, () -> recovery.forAppend(key.id()))
              .observedState()
              .orElseThrow());
      assertThrows(NotFoundException.class, recovery::forEncrypt, "no Active key to write under");
      try (LocalKeys.Use use = recovery.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
      // Destroyed is still refused.
      KeyHandle other = f.key(256, "orders", null, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
      other.revoke(RevocationReason.keyCompromise("gone", Instant.now()));
      other.destroy();
      assertThrows(StateConflictException.class, () -> recovery.forDecrypt(other.id()));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aServerThatLeasesOnlyActiveKeysStillDecidesForTheRecovery(KmipVersion version) {
    try (Fixture f = new Fixture(version);
        Warnings warnings = new Warnings()) {
      f.server
          .leaseTime(Duration.ofHours(1))
          .leasesOnlyForActive(true); // as keytend-kmip-server --lease-states active
      KeyHandle key = f.key();
      key.revoke(RevocationReason.keyCompromise("node disk stolen", Instant.now()));
      LocalKeys recovery = f.keep(f.builder().allowCompromisedForDecrypt().open());
      StateConflictException refused =
          assertThrows(StateConflictException.class, () -> recovery.forDecrypt(key.id()));
      assertEquals("obtainLease", refused.operation(), "the server's lease policy decides");
      assertEquals(KeyState.COMPROMISED, refused.observedState().orElseThrow());
      f.server.leasesOnlyForActive(false);
      recovery.invalidate(key.id());
      try (LocalKeys.Use use = recovery.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aCompromiseOneEncryptValidationSeesEndsEveryEncryptSlotOfTheKey(KmipVersion version)
      throws Exception {
    try (Fixture f = new Fixture(version);
        Warnings warnings = new Warnings()) {
      KeyHandle key = f.key();
      LocalKeys recovery = f.keep(f.builder().allowCompromisedForDecrypt().open());
      java.util.concurrent.ExecutorService pool =
          java.util.concurrent.Executors.newFixedThreadPool(2);
      try {
        java.util.concurrent.atomic.AtomicReference<Thread> exact =
            new java.util.concurrent.atomic.AtomicReference<>();
        java.util.concurrent.atomic.AtomicBoolean once =
            new java.util.concurrent.atomic.AtomicBoolean();
        // While forAppend(id) validates, another caller selects the same key as the write key; then
        // the key is compromised, and the exact validation reads it so.
        f.before.set(
            request -> {
              if (Thread.currentThread() != exact.get()
                  || !is(request, dev.keytend.kmip.model.Operation.GET_ATTRIBUTES)
                  || !once.compareAndSet(false, true)) return;
              try {
                try (LocalKeys.Use use = pool.submit(() -> recovery.forEncrypt()).get()) {
                  assertEquals(key.id(), use.id());
                }
              } catch (Exception e) {
                throw new AssertionError(e);
              }
              f.admin
                  .keys()
                  .handle(key.id())
                  .revoke(RevocationReason.keyCompromise("leaked", Instant.now()));
            });
        java.util.concurrent.Future<?> run =
            pool.submit(
                () -> {
                  exact.set(Thread.currentThread());
                  return assertThrows(
                      StateConflictException.class, () -> recovery.forAppend(key.id()));
                });
        run.get();
        f.before.set(r -> {});
        assertThrows(
            KmsException.class, recovery::forEncrypt, "the write slot no longer encrypts with it");
        assertTrue(recovery.currentWriteId().isEmpty());
        try (LocalKeys.Use use = recovery.forDecrypt(key.id())) {
          assertEquals(key.id(), use.id(), "still recovers");
        }
      } finally {
        pool.shutdownNow();
      }
    }
  }
}
