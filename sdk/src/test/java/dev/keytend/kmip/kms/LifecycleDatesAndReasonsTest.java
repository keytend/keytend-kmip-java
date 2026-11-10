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

import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.Attributes;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The lifecycle dates {@link KeyAttributes} models, and revocation reasons built from their kind.
 */
class LifecycleDatesAndReasonsTest {
  static final Instant LATER = Instant.parse("2030-01-01T00:00:00Z");

  static void add(Kms kms, String id, String name, Ttlv value) throws Exception {
    kms.protocol()
        .call(
            Requests.addAttribute()
                .uniqueIdentifier(id)
                .attribute(Attributes.attribute(name, value))
                .build());
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theCryptoperiodDatesAreRead(KmipVersion version) throws Exception {
    try (InMemoryKmipServer s = InMemoryKmipServer.of(version);
        Kms kms = s.connect()) {
      KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
      KeyAttributes before = key.attributes();
      assertEquals(Optional.empty(), before.processStartDate());
      assertEquals(Optional.empty(), before.protectStopDate());
      assertEquals(Optional.empty(), before.compromiseOccurrenceDate());
      Instant start = LATER.minus(1, ChronoUnit.DAYS);
      add(kms, key.id(), "Process Start Date", Ttlv.dateTime(Tag.PROCESS_START_DATE, start));
      add(kms, key.id(), "Protect Stop Date", Ttlv.dateTime(Tag.PROTECT_STOP_DATE, LATER));
      KeyAttributes a = key.attributes();
      assertEquals(Optional.of(start), a.processStartDate());
      assertEquals(Optional.of(LATER), a.protectStopDate());
      // A Re-key copies them to the replacement, as the guides say.
      KeyAttributes next = key.rotate().attributes();
      assertEquals(Optional.of(LATER), next.protectStopDate());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aCompromiseRecordsWhenItHappened(KmipVersion version) {
    try (InMemoryKmipServer s = InMemoryKmipServer.of(version);
        Kms kms = s.connect()) {
      KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
      Instant occurred = Instant.parse("2026-10-01T00:00:00Z");
      key.revoke(RevocationReason.of(RevocationReason.Kind.KEY_COMPROMISE, "leaked", occurred));
      KeyAttributes a = key.allowingCompromised().attributes();
      assertEquals(Optional.of(occurred), a.compromiseOccurrenceDate());
      assertTrue(a.compromiseDate().isPresent());
      assertTrue(a.compromiseDate().get().isAfter(occurred), "recorded later than it happened");
    }
  }

  @Test
  void aReasonIsBuiltFromItsKind() {
    Instant at = Instant.parse("2026-10-01T00:00:00.750Z");
    for (RevocationReason.Kind kind : RevocationReason.Kind.values()) {
      RevocationReason r = RevocationReason.of(kind, "why", kind.compromise() ? at : null);
      assertEquals(kind, r.kind());
      assertEquals(Optional.of("why"), r.message());
      assertEquals(kind.compromise(), r.compromise());
      assertEquals(
          kind.compromise() ? Optional.of(at.truncatedTo(ChronoUnit.SECONDS)) : Optional.empty(),
          r.compromiseOccurred());
      assertEquals(
          Optional.empty(),
          RevocationReason.of(kind, null, kind.compromise() ? at : null).message());
    }
    assertEquals(
        Set.of(RevocationReason.Kind.KEY_COMPROMISE, RevocationReason.Kind.CA_COMPROMISE),
        EnumSet.copyOf(
            Arrays.stream(RevocationReason.Kind.values())
                .filter(RevocationReason.Kind::compromise)
                .toList()));
    // The same values as the named factories.
    assertEquals(
        RevocationReason.superseded("x"),
        RevocationReason.of(RevocationReason.Kind.SUPERSEDED, "x", null));
    assertEquals(
        RevocationReason.keyCompromise("x", at),
        RevocationReason.of(RevocationReason.Kind.KEY_COMPROMISE, "x", at));
    assertEquals(RevocationReason.unspecified(), RevocationReason.unspecified(null));
    assertEquals(Optional.of("x"), RevocationReason.unspecified("x").message());
    assertThrows(
        IllegalArgumentException.class,
        () -> RevocationReason.of(RevocationReason.Kind.KEY_COMPROMISE, "x", null));
    assertThrows(
        IllegalArgumentException.class,
        () -> RevocationReason.of(RevocationReason.Kind.SUPERSEDED, "x", at));
    assertThrows(NullPointerException.class, () -> RevocationReason.of(null, "x", null));
  }

  /** Up to 2.1 a deactivation records the code and the message, also Unspecified's message. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void anUnspecifiedReasonCarriesItsMessage(KmipVersion version) {
    try (InMemoryKmipServer s = InMemoryKmipServer.of(version);
        Kms kms = s.connect()) {
      KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
      key.deactivate(RevocationReason.unspecified("key switch"));
      Ttlv revoke = DeactivationTest.payloads(s, dev.keytend.kmip.model.Operation.REVOKE).get(0);
      Ttlv reason = revoke.require(Tag.REVOCATION_REASON);
      assertEquals("key switch", reason.require(Tag.REVOCATION_MESSAGE).textValue());
      assertEquals(KeyState.DEACTIVATED, key.attributes().state());
    }
  }
}
