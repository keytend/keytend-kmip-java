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
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Scheduled encryption stops bound writes, independently of refresh and historical reads. */
class LocalKeysProtectionStopTest {
  static final Instant START = Instant.parse("2026-10-29T12:00:00Z");
  private static final List<Tag> DATES = List.of(Tag.DEACTIVATION_DATE, Tag.PROTECT_STOP_DATE);

  static LocalKeys cache(Fixture f, RotationJobTest.TestClock clock) {
    LocalKeys.Builder builder = f.builder();
    builder.clock = clock;
    return f.keep(builder.open());
  }

  static void advance(Fixture f, RotationJobTest.TestClock clock, long seconds) {
    f.advance(seconds);
    clock.now = clock.now.plusSeconds(seconds);
  }

  /** Inject dates without changing server state, including into each candidate of a batch. */
  static void dates(Fixture f, String id, Ttlv... dates) {
    f.after.set(
        (request, reply) ->
            !is(request, Operation.GET_ATTRIBUTES)
                ? reply
                : KeyPolicyTest.rewrite(
                    reply,
                    node -> {
                      if (node.tag() != Tag.RESPONSE_PAYLOAD.code()
                          || !node.child(Tag.UNIQUE_IDENTIFIER)
                              .map(Ttlv::textValue)
                              .orElse("")
                              .equals(id)) return node;
                      List<Ttlv> fields = new ArrayList<>(node.children());
                      Optional<Ttlv> modern = node.child(Tag.ATTRIBUTES);
                      if (modern.isPresent()) {
                        List<Ttlv> attributes = new ArrayList<>(modern.get().children());
                        attributes.addAll(List.of(dates));
                        fields.set(
                            fields.indexOf(modern.get()),
                            Ttlv.structure(Tag.ATTRIBUTES, attributes));
                      } else
                        for (Ttlv date : dates)
                          fields.add(
                              Attributes.attribute(
                                  date.tag() == Tag.DEACTIVATION_DATE.code()
                                      ? "Deactivation Date"
                                      : "Protect Stop Date",
                                  date));
                      return Ttlv.structure(Tag.RESPONSE_PAYLOAD, fields);
                    }));
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void futureStopsAllowEncryptionButOutageAndStalledRefreshCannotCrossThem(KmipVersion version) {
    for (Tag date : DATES)
      try (Fixture f = new Fixture(version)) {
        KeyHandle key = f.key();
        RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
        dates(f, key.id(), Ttlv.dateTime(date, START.plusSeconds(7)));
        LocalKeys c = cache(f, clock);
        try (LocalKeys.Use use = c.forEncrypt()) {
          assertEquals(key.id(), use.id());
        }
        advance(f, clock, 5);
        try (LocalKeys.Use ignored = c.forEncrypt()) {}
        assertEquals(1, f.executor.queue.size()); // Leave the refresh queued.
        f.server.unreachable(true);
        advance(f, clock, 1);
        try (LocalKeys.Use use = c.forEncrypt()) {
          assertEquals(key.id(), use.id());
        }
        advance(f, clock, 1);
        assertTrue(c.currentWriteId().isEmpty());
        assertThrows(TransientException.class, c::forEncrypt);
        // The write validation's seeded Decrypt copy is bounded by TTL, not the protection stop.
        try (LocalKeys.Use use = c.forDecrypt(key.id())) {
          assertEquals(key.id(), use.id());
        }
        advance(f, clock, 3);
        assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
      }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theEarlierDateWinsAndAnExpiredActiveCandidateDoesNotHideItsReplacement(KmipVersion version) {
    for (Tag first : DATES)
      try (Fixture f = new Fixture(version)) {
        KeyHandle old = f.key();
        RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
        Tag second = first == Tag.DEACTIVATION_DATE ? Tag.PROTECT_STOP_DATE : Tag.DEACTIVATION_DATE;
        dates(
            f,
            old.id(),
            Ttlv.dateTime(first, START.plusSeconds(3)),
            Ttlv.dateTime(second, START.plusSeconds(8)));
        LocalKeys c = cache(f, clock);
        try (LocalKeys.Use ignored = c.forEncrypt()) {}
        KeyHandle next = f.key(); // Both remain Active and share the write name; no links.
        advance(f, clock, 2);
        try (LocalKeys.Use use = c.forEncrypt()) {
          assertEquals(old.id(), use.id());
        }
        advance(f, clock, 1);
        assertTrue(c.currentWriteId().isEmpty());
        try (LocalKeys.Use use = c.forEncrypt()) {
          assertEquals(next.id(), use.id());
        }
        try (LocalKeys.Use use = c.forDecrypt(old.id())) {
          assertEquals(old.id(), use.id());
        }
      }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anAlreadyReachedStopRefusesWritesBeforeGetButAllowsHistoricalReads(KmipVersion version) {
    for (Tag date : DATES)
      for (long offset : new long[] {-1, 0})
        try (Fixture f = new Fixture(version)) {
          KeyHandle key = f.key();
          RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
          dates(f, key.id(), Ttlv.dateTime(date, START.plusSeconds(offset)));
          AtomicInteger gets = new AtomicInteger();
          f.before.set(
              request -> {
                if (is(request, Operation.GET)) gets.incrementAndGet();
              });
          LocalKeys c = cache(f, clock);
          assertThrows(NotFoundException.class, c::forEncrypt);
          assertEquals(0, gets.get());
          assertTrue(c.currentWriteId().isEmpty());
          try (LocalKeys.Use use = c.forDecrypt(key.id())) {
            assertEquals(key.id(), use.id());
          }
          assertEquals(1, gets.get());
        }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aGetThatCrossesTheDeadlineCannotPublishOrSeedMaterial(KmipVersion version) {
    for (Tag date : DATES)
      try (Fixture f = new Fixture(version)) {
        KeyHandle key = f.key();
        RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
        dates(f, key.id(), Ttlv.dateTime(date, START.plusSeconds(3)));
        LocalKeys c = cache(f, clock);
        f.before.set(
            request -> {
              if (is(request, Operation.GET)) advance(f, clock, 3);
            });
        assertThrows(TransientException.class, c::forEncrypt);
        assertTrue(c.currentWriteId().isEmpty());
        f.server.unreachable(true);
        assertThrows(TransientException.class, () -> c.forDecrypt(key.id()));
      }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLaterProtectionStopDoesNotExtendTtl(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
      dates(f, key.id(), Ttlv.dateTime(Tag.PROTECT_STOP_DATE, START.plusSeconds(100)));
      LocalKeys c = cache(f, clock);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.server.unreachable(true);
      advance(f, clock, 10);
      assertTrue(c.currentWriteId().isEmpty());
      assertThrows(TransientException.class, c::forEncrypt);
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aSuccessfulRefreshCannotMoveTheScheduledStop(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
      dates(f, key.id(), Ttlv.dateTime(Tag.PROTECT_STOP_DATE, START.plusSeconds(7)));
      LocalKeys c = cache(f, clock);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      advance(f, clock, 5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.executor.run();
      advance(f, clock, 2);
      assertTrue(c.currentWriteId().isEmpty());
      assertThrows(NotFoundException.class, c::forEncrypt);
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aHistoricalObservationShortensTheHeldWriteDeadlineEvenWhenGetFails(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
      LocalKeys c = cache(f, clock);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      advance(f, clock, 5);
      dates(f, key.id(), Ttlv.dateTime(Tag.PROTECT_STOP_DATE, START.plusSeconds(7)));
      f.before.set(
          request -> {
            if (is(request, Operation.GET)) throw new TransientException("Get outage");
          });
      try (LocalKeys.Use ignored = c.forDecrypt(key.id())) {}
      f.executor.run();
      advance(f, clock, 1);
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(key.id(), use.id());
      }
      f.server.unreachable(true);
      advance(f, clock, 1);
      assertTrue(c.currentWriteId().isEmpty());
      assertThrows(TransientException.class, c::forEncrypt);
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aHistoricalObservationAlsoBoundsAnUnpublishedWriteLoad(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle key = f.key();
      RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
      dates(f, key.id(), Ttlv.dateTime(Tag.PROTECT_STOP_DATE, START.plusSeconds(8)));
      LocalKeys c = cache(f, clock);
      AtomicBoolean interleaved = new AtomicBoolean();
      f.before.set(
          request -> {
            if (is(request, Operation.GET) && interleaved.compareAndSet(false, true)) {
              // The write loader has checked +8 but not received its key. A separate read sees +3.
              dates(f, key.id(), Ttlv.dateTime(Tag.PROTECT_STOP_DATE, START.plusSeconds(3)));
              try (LocalKeys.Use use = c.forDecrypt(key.id())) {
                assertEquals(key.id(), use.id());
              }
            }
          });
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(key.id(), use.id());
      }
      assertTrue(interleaved.get());
      advance(f, clock, 3);
      f.server.unreachable(true);
      assertTrue(c.currentWriteId().isEmpty());
      assertThrows(TransientException.class, c::forEncrypt);
      try (LocalKeys.Use use = c.forDecrypt(key.id())) {
        assertEquals(key.id(), use.id());
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void cachedStopsAreBoundedByBothWallAndMonotonicClocks(KmipVersion version) {
    for (boolean wallForward : new boolean[] {false, true})
      try (Fixture f = new Fixture(version)) {
        KeyHandle key = f.key();
        RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
        dates(f, key.id(), Ttlv.dateTime(Tag.PROTECT_STOP_DATE, START.plusSeconds(7)));
        LocalKeys c = cache(f, clock);
        try (LocalKeys.Use ignored = c.forEncrypt()) {}
        f.server.unreachable(true);
        if (wallForward) clock.now = START.plusSeconds(7);
        else {
          f.advance(7);
          clock.now = START.minusSeconds(60); // Rollback cannot extend the cached grant.
        }
        assertTrue(c.currentWriteId().isEmpty());
        assertThrows(TransientException.class, c::forEncrypt);
        try (LocalKeys.Use use = c.forDecrypt(key.id())) {
          assertEquals(key.id(), use.id());
        }
      }
  }
}
