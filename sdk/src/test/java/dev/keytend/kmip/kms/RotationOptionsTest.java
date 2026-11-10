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

import static dev.keytend.kmip.kms.RotationGraceTest.ids;
import static dev.keytend.kmip.kms.RotationGraceTest.sent;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * One rotation options form. {@code replaceCompromised(reason, Rotation)}: the same dates, the
 * protection a {@link Rotation} asks for, and no grace period (a Compromised key is revoked at
 * once).
 */
class RotationOptionsTest {
  static final Instant START = RotationJobTest.START;
  static final RevocationReason LEAKED =
      RevocationReason.keyCompromise("leaked", START.plus(Duration.ofDays(19)));

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  InMemoryKmipServer server(KmipVersion version, RotationJobTest.TestClock clock) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    s.clock(clock);
    servers.add(s);
    return s;
  }

  Kms connect(InMemoryKmipServer server, RotationJobTest.TestClock clock) {
    Kms kms = Kms.connect(server.configure().build());
    kms.clock(clock);
    clients.add(kms);
    return kms;
  }

  /**
   * The Rotation form gives a compromise replacement the dates the deprecated form gives it
   * (RotationGraceTest.replaceCompromisedTakesTheDatesTheCallerAsksFor): a key retired by hand a week
   * after activation gets a new key without dates for {@code Rotation.of(COPIED)} (no Re-key), and
   * the span however short for {@code Rotation.of(SHIFTED)}; a live key is re-keyed without an
   * Offset for {@code COPIED}.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void replaceCompromisedTakesTheDatesOfARotation(KmipVersion version) {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    Duration week = Duration.ofDays(7), hour = Duration.ofHours(1);
    Function<Duration, KeyHandle> retiredAfter =
        span -> {
          clock.now = START;
          KeyHandle k =
              kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
          clock.now = START.plus(span);
          k.revoke(RevocationReason.superseded("retired by hand"));
          clock.now = START.plus(Duration.ofDays(20));
          return k;
        };
    Instant recovery = START.plus(Duration.ofDays(20));

    int reKeys = sent(s, Operation.RE_KEY);
    KeyHandle byHand = retiredAfter.apply(week);
    KeyHandle fresh = byHand.replaceCompromised(LEAKED, Rotation.of(RotationDates.COPIED));
    assertEquals(reKeys, sent(s, Operation.RE_KEY), "a new key, not a Re-key");
    assertEquals(Optional.empty(), fresh.attributes().deactivationDate());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(fresh.id()));
    assertEquals(List.of(byHand.id()), ids(fresh.compromisedPredecessors()));

    KeyHandle shifted =
        retiredAfter.apply(hour).replaceCompromised(LEAKED, Rotation.of(RotationDates.SHIFTED));
    assertEquals(
        Optional.of(recovery.plus(hour)),
        shifted.attributes().deactivationDate(),
        "the span, however short");

    KeyHandle live = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    reKeys = sent(s, Operation.RE_KEY);
    KeyHandle copied = live.replaceCompromised(LEAKED, Rotation.of(RotationDates.COPIED));
    assertEquals(reKeys + 1, sent(s, Operation.RE_KEY));
    assertEquals(Optional.empty(), copied.attributes().deactivationDate());
    assertEquals(List.of(), s.violations());
  }

  /** A grace period is refused before anything is sent: the key stays Active and unrevoked. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V3_0"})
  void aGracePeriodIsRefusedBeforeAnythingIsSent(KmipVersion version) {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    int before = s.exchanges();
    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () -> key.replaceCompromised(LEAKED, Rotation.grace(Duration.ofDays(1))));
    assertTrue(e.getMessage().contains("a grace period does not apply"), e.getMessage());
    assertEquals(before, s.exchanges(), "nothing sent");
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(key.id()));
    assertThrows(NullPointerException.class, () -> key.replaceCompromised(LEAKED, (Rotation) null));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            key.replaceCompromised(
                RevocationReason.superseded("x"), Rotation.of(RotationDates.COPIED)));
    assertEquals(before, s.exchanges(), "nothing sent");
  }

  /**
   * The protection a Rotation asks for goes to the replacement: with the Re-key, and to the new key
   * made where the server refuses the Re-key, each read back. Below KMIP 1.4 it is refused before
   * anything is sent.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void replaceCompromisedGivesTheRotationsProtection(KmipVersion version) {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    KeyHandle k0 = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    assertNotEquals(Optional.of(false), k0.attributes().extractable());
    KeyHandle byReKey =
        k0.replaceCompromised(LEAKED, Rotation.of(RotationDates.COPIED).extractable(false));
    assertEquals(Optional.of(false), byReKey.attributes().extractable());

    KeyHandle other = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).named("other").create();
    s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
    int reKeys = sent(s, Operation.RE_KEY);
    KeyHandle successor =
        other.replaceCompromised(LEAKED, Rotation.of(RotationDates.COPIED).sensitive(true));
    assertEquals(reKeys + 1, sent(s, Operation.RE_KEY), "the Re-key was refused");
    assertNotEquals(other, successor);
    assertEquals(
        Optional.of(true),
        successor.attributes().sensitive(),
        "a new key, given the Rotation's Sensitive");
    assertEquals(List.of(other.id()), s.links(successor.id(), LinkKind.REPLACED));
    assertEquals(List.of(), s.violations());
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_3"})
  void aProtectionBelow14IsRefusedBeforeAnythingIsSent(KmipVersion version) {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    int before = s.exchanges();
    UnsupportedException e =
        assertThrows(
            UnsupportedException.class,
            () ->
                key.replaceCompromised(
                    LEAKED, Rotation.of(RotationDates.COPIED).extractable(false)));
    assertTrue(e.getMessage().contains("needs KMIP 1.4 or later"), e.getMessage());
    assertEquals(before, s.exchanges(), "nothing sent");
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(key.id()));
  }
}
