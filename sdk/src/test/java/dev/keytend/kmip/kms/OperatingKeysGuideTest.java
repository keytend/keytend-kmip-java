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

import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The flows of docs/operating-keys.md, in the order and with the calls the guide shows, after the
 * startup of docs/getting-started.md, the readiness check of docs/production.md and the sealing of
 * docs/envelope-encryption.md.
 */
class OperatingKeysGuideTest {
  record Record(String id, byte[] sealed, byte[] aad) {}

  /** A record store, as in the guide. */
  static final class Store {
    final Map<String, Record> records = new LinkedHashMap<>();

    Collection<Record> all() {
      return List.copyOf(records.values());
    }

    void put(String id, byte[] sealed) {
      records.put(id, new Record(id, sealed, records.get(id).aad()));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theGuideRunsAsWritten(KmipVersion version) throws Exception {
    for (boolean unique : new boolean[] {false, true}) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
      try (Kms kms =
          Kms.connect(
              server
                  .configure()
                  .maximumVersion(KmipVersion.V3_0)
                  .callTimeout(Duration.ofSeconds(10))
                  .build())) {
        // Startup.
        KeyHandle kek =
            kms.keys()
                .createAes(256)
                .named("vault-kek")
                .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                .custom(CustomAttribute.client("purpose"), "vault")
                .findOrCreate();
        // Readiness.
        kms.withTimeout(Duration.ofSeconds(2)).ping();
        // Sealing records, and a stream.
        Store store = new Store();
        for (int i = 0; i < 3; i++) {
          byte[] recordId = ("order-" + i).getBytes(StandardCharsets.UTF_8);
          store.records.put(
              "order-" + i,
              new Record(
                  "order-" + i,
                  kek.seal(("record " + i).getBytes(StandardCharsets.UTF_8), recordId),
                  recordId));
        }
        byte[] streamId = "backup".getBytes(StandardCharsets.UTF_8);
        Path dir = Files.createTempDirectory("guide");
        Path export = Files.write(dir.resolve("export"), new byte[100_000]);
        Path backup = dir.resolve("backup"), restored = dir.resolve("restored");
        try (InputStream source = Files.newInputStream(export)) {
          kek.sealTo(backup, source, streamId);
        }
        kek.openTo(backup, restored, streamId);
        assertArrayEquals(new byte[100_000], Files.readAllBytes(restored));
        // Not a file: sealing and opening, staged by the caller.
        ByteArrayOutputStream file = new ByteArrayOutputStream();
        try (SealingStream out = kek.sealing(file, streamId)) {
          new ByteArrayInputStream(new byte[100_000]).transferTo(out);
          out.finish();
        }
        // Rotation: move the records, then retire the old key.
        KeyHandle previous = kek;
        kek = kek.rotate();
        int written = 0;
        for (Record r : store.all()) {
          Rewrapped moved = kek.rewrapRecord(r.sealed(), r.aad());
          if (moved.changed()) {
            store.put(r.id(), moved.bytes());
            written++;
          }
        }
        assertEquals(3, written);
        for (Record r : store.all())
          assertFalse(kek.rewrapRecord(r.sealed(), r.aad()).changed(), "a repeat writes nothing");
        for (Record r : store.all()) assertEquals(kek.id(), KmsKeys.sealedKeyId(r.sealed()));
        // Several instances: a CurrentKey made before the rotation follows it once sealing is
        // refused.
        CurrentKey follower = kms.keys().current(previous);
        previous.revoke(RevocationReason.superseded("rotated"));
        byte[] underCurrent = follower.seal("follower".getBytes(StandardCharsets.UTF_8), null);
        assertEquals(kek.id(), KmsKeys.sealedKeyId(underCurrent));
        assertArrayEquals(
            "follower".getBytes(StandardCharsets.UTF_8), follower.open(underCurrent, null));
        // A handle kept from before the rotation can tell.
        assertFalse(previous.isLatest());
        assertEquals(kek.id(), previous.latest().id());
        // The rotation job fired twice from the same key: the second firing rotates nothing.
        assertEquals(kek.id(), previous.rotateOrLatest().id());
        // The guide's job, fired again from either handle: the current key is too new to rotate.
        assertEquals(kek.id(), previous.rotateIfActiveFor(java.time.Duration.ofDays(30)).id());
        assertEquals(kek.id(), kek.rotateIfActiveFor(java.time.Duration.ofDays(30)).id());
        // Re-seal the stream under the current key, then retire.
        ByteArrayOutputStream moved = new ByteArrayOutputStream();
        try (InputStream in = kek.opening(new ByteArrayInputStream(file.toByteArray()), streamId);
            SealingStream out = kek.sealing(moved, streamId)) {
          in.transferTo(out);
          out.finish();
        }
        kek.openTo(backup, restored, streamId); // the old key's file opens through the new key
        try (var files = Files.list(dir)) {
          assertEquals(
              Set.of(export, backup, restored), files.collect(java.util.stream.Collectors.toSet()));
        }
        for (Path p : List.of(export, backup, restored)) Files.delete(p);
        Files.delete(dir);
        List<KeyHandle> retired = kek.retirePredecessors(RevocationReason.superseded("rotated"));
        assertEquals(List.of(previous.id()), retired.stream().map(KeyHandle::id).toList());
        // Several newest keys: two callers rotated the current key at once (Re-keys sent directly).
        KeyHandle mine = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, kek.id()));
        KeyHandle theirs = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, kek.id()));
        byte[] underTheirs = theirs.seal("theirs".getBytes(StandardCharsets.UTF_8), null);
        assertEquals(mine.latest(), theirs.latest(), "one choice everywhere");
        assertArrayEquals("theirs".getBytes(StandardCharsets.UTF_8), mine.open(underTheirs, null));
        // On every version, the 3.0 draft included (its own link attributes).
        kek = kms.keys().reconcile("vault-kek").orElseThrow();
        assertEquals(kek, mine.latest());
        assertTrue(kek.isLatest());
        assertArrayEquals("theirs".getBytes(StandardCharsets.UTF_8), kek.open(underTheirs, null));
        for (Record r : store.all()) assertNotNull(kek.open(r.sealed(), r.aad()));
        // A compromised key.
        KeyHandle replacement =
            kek.replaceCompromised(RevocationReason.keyCompromise("leaked", Instant.now()));
        KeyHandle compromised = kek.allowingCompromised();
        for (Record r : store.all())
          store.put(r.id(), compromised.rewrapTo(replacement, r.sealed(), r.aad()));
        kek = replacement;
        for (Record r : store.all()) assertNotNull(kek.open(r.sealed(), r.aad()));
        // A restart finds the replacement.
        assertEquals(
            kek.id(),
            kms.keys()
                .createAes(256)
                .named("vault-kek")
                .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                .custom(CustomAttribute.client("purpose"), "vault")
                .findOrCreate()
                .id());
        // After a restart: the key is compromised again, and a process that never held its handle
        // replaces it at startup and re-seals through the replacement's compromisedPredecessors().
        kek.revoke(RevocationReason.keyCompromise("leaked again", Instant.now()));
        try (Kms restarted =
            Kms.connect(server.configure().maximumVersion(KmipVersion.V3_0).build())) {
          KeyHandle current =
              restarted
                  .keys()
                  .createAes(256)
                  .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                  .custom(CustomAttribute.client("purpose"), "vault")
                  .named("vault-kek")
                  .replacingCompromised()
                  .findOrCreate();
          Map<String, KeyHandle> revoked = new HashMap<>();
          for (KeyHandle k : current.compromisedPredecessors()) revoked.put(k.id(), k);
          for (Record r : store.all()) {
            KeyHandle from = revoked.getOrDefault(KmsKeys.sealedKeyId(r.sealed()), current);
            store.put(r.id(), from.rewrapTo(current, r.sealed(), r.aad()));
          }
          // Nearest first: the key just compromised, then the one compromised before.
          List<String> nearest =
              current.compromisedPredecessors().stream().map(KeyHandle::id).toList();
          assertEquals(List.of(kek.id(), compromised.id()), nearest);
          for (Record r : store.all()) assertEquals(current.id(), KmsKeys.sealedKeyId(r.sealed()));
          for (Record r : store.all()) assertNotNull(current.open(r.sealed(), r.aad()));
          kek = kms.keys().handle(current.id());
        }
        // Replacing a secret.
        KeyHandle first =
            kms.keys().registerSecret("hunter2".toCharArray()).named("db-password").register();
        KeyHandle old = kms.keys().findByName("db-password").orElseThrow();
        assertEquals(first.id(), old.id());
        KeyHandle current =
            kms.keys()
                .registerSecret("correct horse".toCharArray())
                .named("db-password")
                .replace(old);
        assertEquals(current.id(), kms.keys().findByName("db-password").orElseThrow().id());
        try (SecretData s = current.asSecretData()) {
          assertArrayEquals("correct horse".toCharArray(), s.chars());
        }
        // Key pairs.
        KeyPairHandle signer =
            kms.keys()
                .createKeyPair(KeyPairSpec.ec(Curve.P_256))
                .named("manifest-signer", "manifest-signer-public")
                .privateUsages(KeyUsage.SIGN)
                .publicUsages(KeyUsage.VERIFY)
                .findOrCreate();
        assertEquals(
            signer.privateKey().id(),
            kms.keys()
                .createKeyPair(KeyPairSpec.ec(Curve.P_256))
                .named("manifest-signer", "manifest-signer-public")
                .privateUsages(KeyUsage.SIGN)
                .publicUsages(KeyUsage.VERIFY)
                .findOrCreate()
                .privateKey()
                .id());
      }
      assertEquals(List.of(), server.violations());
    }
  }

  /**
   * "Rotation with a grace period" as written: the rotation job with {@code
   * Rotation.grace}, the re-wrap job and the retirement after the grace period, and on a server
   * that will not schedule the date (keytend-kmip-server), the rotation without a grace and the explicit
   * {@code deactivatePredecessors()} after it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theGracePeriodSectionRunsAsWritten(KmipVersion version) throws Exception {
    for (boolean refusing : new boolean[] {false, true}) {
      RotationJobTest.TestClock clock = new RotationJobTest.TestClock(RotationJobTest.START);
      InMemoryKmipServer server =
          InMemoryKmipServer.of(version).refuseClientDeactivationDate(refusing);
      server.clock(clock);
      try (Kms kms = Kms.connect(server.configure().maximumVersion(KmipVersion.V3_0).build())) {
        kms.clock(clock);
        KeyHandle first =
            kms.keys()
                .createAes(256)
                .named("vault-kek")
                .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                .findOrCreate();
        Store store = new Store();
        byte[] recordId = "order".getBytes(StandardCharsets.UTF_8);
        store.records.put(
            "order",
            new Record(
                "order",
                first.seal("record".getBytes(StandardCharsets.UTF_8), recordId),
                recordId));
        clock.now = clock.now.plus(Duration.ofDays(30));
        final Rotation POLICY = Rotation.grace(Duration.ofDays(7));
        KeyHandle current;
        if (!refusing) {
          // the rotation job, daily: a new key every 30 days; each old key stops encrypting 7 days
          // later
          kms.keys()
              .findByName("vault-kek")
              .orElseThrow()
              .rotateIfActiveFor(Duration.ofDays(30), POLICY);
          current = kms.keys().findByName("vault-kek").orElseThrow(); // the re-wrap job's lookup
        } else {
          PartialCompletionException told =
              assertThrows(
                  PartialCompletionException.class,
                  () ->
                      kms.keys()
                          .findByName("vault-kek")
                          .orElseThrow()
                          .rotateIfActiveFor(Duration.ofDays(30), POLICY));
          current = told.created().get(0);
          assertEquals(current, kms.keys().findByName("vault-kek").orElseThrow());
        }
        assertNotEquals(first, current);
        clock.now = clock.now.plus(Duration.ofDays(7));
        // a later job, once the grace period is over (on a server that will not schedule it)
        if (refusing)
          assertEquals(
              List.of(first),
              kms.keys().findByName("vault-kek").orElseThrow().deactivatePredecessors());
        assertEquals(Optional.of(KeyState.DEACTIVATED), server.state(first.id()));
        // the re-wrap job, after the grace period: move the records, then destroy the old keys
        for (Record r : store.all()) {
          Rewrapped moved = current.rewrapRecord(r.sealed(), r.aad());
          if (moved.changed()) store.put(r.id(), moved.bytes());
        }
        current.retirePredecessors(RevocationReason.superseded("rotated"));
        assertEquals(Optional.of(KeyState.DESTROYED), server.state(first.id()));
        for (Record r : store.all())
          assertArrayEquals(
              "record".getBytes(StandardCharsets.UTF_8), current.open(r.sealed(), r.aad()));
        // The fallback: rotate without a grace, and deactivate explicitly in a later job.
        KeyHandle kek = current;
        clock.now = clock.now.plus(Duration.ofDays(30));
        KeyHandle next = kek.rotateIfActiveFor(Duration.ofDays(30)); // day 0, 30, 60, ...
        assertNotEquals(kek, next);
        assertEquals(
            Optional.of(KeyState.ACTIVE),
            server.state(kek.id()),
            "no grace: the old key stays Active");
        clock.now = clock.now.plus(Duration.ofDays(7));
        // a later job, once the grace period after the last rotation is over:
        kms.keys().findByName("vault-kek").orElseThrow().deactivatePredecessors();
        assertEquals(Optional.of(KeyState.DEACTIVATED), server.state(kek.id()));
      }
      assertEquals(List.of(), server.violations());
    }
  }
}
