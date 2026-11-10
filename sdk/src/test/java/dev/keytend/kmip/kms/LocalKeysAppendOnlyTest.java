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

import dev.keytend.kmip.model.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link LocalKeys#forAppend(String)}: an append-only file (a commit-log segment, a hints file)
 * asks for its own key before each chunk, and gets it only while that key is still eligible for
 * Encrypt (Active, in scope, permitting Encrypt, before its protection deadline, leased), whether
 * or not it is still the write selection.
 */
class LocalKeysAppendOnlyTest {
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anOpenFileKeepsItsKeyAcrossARotationUntilTheKeyIsNoLongerEligible(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle first = f.key();
      LocalKeys c = f.cache();
      String segment;
      try (LocalKeys.Use use = c.forEncrypt()) {
        segment = use.id();
      }
      assertEquals(first.id(), segment);
      // The write selection serves its own key: per-chunk checks send nothing.
      int exchanges = f.server.exchanges();
      for (int i = 0; i < 100; i++)
        try (LocalKeys.Use use = c.forAppend(segment)) {
          assertEquals(segment, use.id());
        }
      assertEquals(exchanges, f.server.exchanges(), "served from the write selection");

      // An external rotation: the name moves, the old key stays Active (a leasing server's rule).
      first.removeName(NAME);
      KeyHandle second = f.key();
      f.advance(10);
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(second.id(), use.id(), "new files use the new key");
      }
      // The open segment keeps its key, validated for Encrypt by identifier, then from the cache.
      try (LocalKeys.Use use = c.forAppend(segment)) {
        assertEquals(segment, use.id());
      }
      exchanges = f.server.exchanges();
      for (int i = 0; i < 100; i++)
        try (LocalKeys.Use use = c.forAppend(segment)) {
          assertEquals(segment, use.id());
        }
      assertEquals(exchanges, f.server.exchanges(), "a valid exact entry is a hit");

      // Deactivated: still decrypts, no longer encrypts, from the first validation after it.
      first.deactivate();
      f.advance(5);
      try (LocalKeys.Use use = c.forAppend(segment)) {
        assertEquals(segment, use.id(), "within its TTL");
      }
      f.executor.run(); // the refresh that the access queued
      StateConflictException refused =
          assertThrows(StateConflictException.class, () -> c.forAppend(segment));
      assertEquals(KeyState.DEACTIVATED, refused.observedState().orElseThrow());
      exchanges = f.server.exchanges();
      assertThrows(StateConflictException.class, () -> c.forAppend(segment));
      assertEquals(exchanges, f.server.exchanges(), "the refusal is remembered for the TTL");
      try (LocalKeys.Use use = c.forDecrypt(segment)) {
        assertEquals(segment, use.id(), "the file stays readable");
      }
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(second.id(), use.id());
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void onlyAKeyEligibleForEncryptIsHandedOut(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle other = f.key(256, "payments", null, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
      KeyHandle decryptOnly = f.key(256, "orders", null, KeyUsage.DECRYPT);
      KeyHandle unnamed = f.key(256, "orders", null, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
      KeyHandle preActive =
          f.admin
              .keys()
              .handle(
                  f.admin
                      .keys()
                      .createAes(256)
                      .extractable(true)
                      .custom(FAMILY, "orders")
                      .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                      .createPreActive()
                      .id());
      LocalKeys c = f.cache();
      assertThrows(KeyMismatchException.class, () -> c.forAppend(other.id()), "outside the scope");
      assertThrows(
          KeyMismatchException.class, () -> c.forAppend(decryptOnly.id()), "no Encrypt usage");
      try (LocalKeys.Use use = c.forDecrypt(decryptOnly.id())) {
        assertEquals(decryptOnly.id(), use.id());
      }
      assertEquals(
          KeyState.PRE_ACTIVE,
          assertThrows(StateConflictException.class, () -> c.forAppend(preActive.id()))
              .observedState()
              .orElseThrow());
      assertThrows(NotFoundException.class, () -> c.forAppend("no-such-key"));
      // Neither the write name nor a link is needed: the scope and the key's own state decide.
      try (LocalKeys.Use use = c.forAppend(unnamed.id())) {
        assertEquals(unnamed.id(), use.id());
      }
      assertThrows(IllegalArgumentException.class, () -> c.forAppend(""));
      assertThrows(NullPointerException.class, () -> c.forAppend(null));
      unnamed.revoke(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
      c.invalidate(unnamed.id());
      assertEquals(
          KeyState.COMPROMISED,
          assertThrows(StateConflictException.class, () -> c.forAppend(unnamed.id()))
              .observedState()
              .orElseThrow());
      c.close();
      assertThrows(IllegalStateException.class, () -> c.forAppend(unnamed.id()));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theProtectionDeadlineEndsAnOpenFilesWrites(KmipVersion version) {
    for (boolean written : new boolean[] {true, false})
      try (Fixture f = new Fixture(version)) {
        // written: the file's key is the write key (served from the selection); else by identifier.
        KeyHandle key =
            written ? f.key() : f.key(256, "orders", null, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
        RotationJobTest.TestClock clock =
            new RotationJobTest.TestClock(LocalKeysProtectionStopTest.START);
        LocalKeysProtectionStopTest.dates(
            f,
            key.id(),
            Ttlv.dateTime(Tag.PROTECT_STOP_DATE, LocalKeysProtectionStopTest.START.plusSeconds(3)));
        LocalKeys c = LocalKeysProtectionStopTest.cache(f, clock);
        if (written)
          try (LocalKeys.Use use = c.forEncrypt()) {
            assertEquals(key.id(), use.id());
          }
        try (LocalKeys.Use use = c.forAppend(key.id())) {
          assertEquals(key.id(), use.id());
        }
        LocalKeysProtectionStopTest.advance(f, clock, 2);
        try (LocalKeys.Use use = c.forAppend(key.id())) {
          assertEquals(key.id(), use.id());
        }
        LocalKeysProtectionStopTest.advance(f, clock, 1);
        assertThrows(
            StateConflictException.class, () -> c.forAppend(key.id()), "written=" + written);
        try (LocalKeys.Use use = c.forDecrypt(key.id())) {
          assertEquals(key.id(), use.id());
        }
      }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aDeadlineAnotherValidationReadsAlsoBoundsTheCachedEncryptEntry(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key(256, "orders", null, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
      RotationJobTest.TestClock clock =
          new RotationJobTest.TestClock(LocalKeysProtectionStopTest.START);
      LocalKeys c = LocalKeysProtectionStopTest.cache(f, clock);
      try (LocalKeys.Use use = c.forAppend(key.id())) {
        assertEquals(key.id(), use.id());
      }
      // A Protect Stop Date appears; a historical read observes it, not the encrypt entry's own
      // refresh.
      LocalKeysProtectionStopTest.dates(
          f,
          key.id(),
          Ttlv.dateTime(Tag.PROTECT_STOP_DATE, LocalKeysProtectionStopTest.START.plusSeconds(2)));
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
      f.server.unreachable(true);
      try (LocalKeys.Use use = c.forAppend(key.id())) {
        assertEquals(key.id(), use.id());
      }
      LocalKeysProtectionStopTest.advance(f, clock, 2);
      assertThrows(
          TransientException.class,
          () -> c.forAppend(key.id()),
          "the observed deadline ends the cached entry");
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anOpenFilesKeyIsLeasedAndStopsWhenItsLeaseEnds(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      f.server.leaseTime(Duration.ofSeconds(8)).leasesOnlyForActive(true);
      List<String> sent = new CopyOnWriteArrayList<>();
      f.before.set(
          request -> {
            for (Ttlv item : request.children(Tag.BATCH_ITEM))
              sent.add(
                  WireEnums.fromCode(Operation.class, item.require(Tag.OPERATION).intValue())
                      .map(Operation::wireName)
                      .orElse("?"));
          });
      KeyHandle key = f.key(256, "orders", null, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
      LocalKeys c =
          f.builder().ttl(Duration.ofSeconds(60)).refreshAfter(Duration.ofSeconds(50)).open();
      f.keep(c);
      try (LocalKeys.Use use = c.forAppend(key.id())) {
        assertEquals(key.id(), use.id());
      }
      assertTrue(
          sent.contains("ObtainLease") && sent.indexOf("ObtainLease") < sent.indexOf("Get"),
          sent.toString());
      // An outage: the copy is handed out only while its lease runs, whatever the TTL.
      f.server.unreachable(true);
      f.advance(7);
      try (LocalKeys.Use use = c.forAppend(key.id())) {
        assertEquals(key.id(), use.id());
      }
      f.advance(2);
      assertThrows(TransientException.class, () -> c.forAppend(key.id()));
      f.server.unreachable(false);
      c.invalidate(key.id());
      try (LocalKeys.Use use = c.forAppend(key.id())) {
        assertEquals(key.id(), use.id());
      }
      // The server leases only Active keys: once Deactivated, the open file stops encrypting.
      key.deactivate();
      c.invalidate(key.id());
      assertThrows(StateConflictException.class, () -> c.forAppend(key.id()));
    }
  }

  @Test
  void invalidatingAnIdentifierDropsItsEncryptEntryToo() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key(256, "orders", null, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
      LocalKeys c = f.cache();
      try (LocalKeys.Use use = c.forAppend(key.id())) {
        assertEquals(key.id(), use.id());
      }
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
      assertEquals(2, c.historicalSlots(), "one entry per purpose");
      int exchanges = f.server.exchanges();
      c.invalidate(key.id());
      assertEquals(0, c.historicalSlots());
      try (LocalKeys.Use use = c.forAppend(key.id())) {
        assertEquals(key.id(), use.id());
      }
      assertTrue(f.server.exchanges() > exchanges, "validated again");
    }
  }

  /**
   * The per-chunk call is {@code forAppend(id)}, not an overload of {@code
   * forEncrypt}, so {@code keys::forEncrypt} names one method (with an overload, {@code
   * executor.submit(keys::forEncrypt)} would be ambiguous between {@code Callable} and {@code Runnable}).
   * Adding a one-argument {@code forEncrypt} back fails to compile here.
   */
  @Test
  void forEncryptHasOneFormAndItsMethodReferenceIsUnambiguous() throws Exception {
    assertThrows(
        NoSuchMethodException.class, () -> LocalKeys.class.getMethod("forEncrypt", String.class));
    assertEquals(
        LocalKeys.Use.class, LocalKeys.class.getMethod("forAppend", String.class).getReturnType());
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      LocalKeys c = f.cache();
      ExecutorService executor = Executors.newSingleThreadExecutor();
      try {
        Future<LocalKeys.Use> next = executor.submit(c::forEncrypt);
        try (LocalKeys.Use use = next.get()) {
          assertEquals(key.id(), use.id());
        }
      } finally {
        executor.shutdownNow();
      }
    }
  }
}
