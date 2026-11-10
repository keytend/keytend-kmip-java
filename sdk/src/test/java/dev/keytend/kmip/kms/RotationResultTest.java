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

import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link KeyHandle#rotateIfActiveForResult}: rotated, not due, or followed another caller's
 * rotation, with the Deactivation Date the grace period left on the key considered.
 */
class RotationResultTest {
  static final Duration MONTH = Duration.ofDays(30), WEEK = Duration.ofDays(7);

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    servers.add(s);
    return s;
  }

  Kms connect(InMemoryKmipServer s, Consumer<Ttlv> before) {
    Kms kms =
        Kms.connect(
            s.configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        r -> {
                          before.accept(r);
                          return s.exchange(r);
                        })
                .build());
    clients.add(kms);
    return kms;
  }

  /** A key of {@code kms} made {@code ago} by the server's clock. */
  static KeyHandle made(InMemoryKmipServer s, Kms kms, Duration ago) {
    return ScheduledRotationTest.ago(s, ago, () -> ScheduledRotationTest.aes(kms).create());
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aDueKeyIsRotatedAndItsDateReported(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s, r -> {});
    KeyHandle old = made(s, kms, MONTH.plusDays(1));
    Instant before = Instant.now();
    RotationResult r = old.rotateIfActiveForResult(MONTH, Rotation.grace(WEEK));
    assertEquals(RotationResult.Outcome.ROTATED, r.outcome());
    assertEquals(old, r.previous());
    assertNotEquals(old, r.current());
    Instant date = r.previousDeactivationDate().orElseThrow();
    assertEquals(date.truncatedTo(ChronoUnit.SECONDS), date, "whole seconds");
    assertFalse(date.isBefore(before.plus(WEEK).truncatedTo(ChronoUnit.SECONDS)), date.toString());
    assertEquals(Optional.of(date), old.attributes().deactivationDate());
    assertEquals(r.current(), old.latest());
    // The same call again: the new key is not due, and nothing but reads is sent.
    int reKeys = RotationGraceTest.sent(s, Operation.RE_KEY);
    RotationResult again = old.rotateIfActiveForResult(MONTH, Rotation.grace(WEEK));
    assertEquals(RotationResult.Outcome.NOT_DUE, again.outcome());
    assertEquals(r.current(), again.previous(), "the key considered is the one old led to");
    assertEquals(again.previous(), again.current());
    assertEquals(Optional.empty(), again.previousDeactivationDate());
    assertEquals(reKeys, RotationGraceTest.sent(s, Operation.RE_KEY));
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anEarlierDateIsKeptAndReported(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s, r -> {});
    KeyHandle old = made(s, kms, MONTH.plusDays(1));
    Instant sooner = Instant.now().plus(2, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
    old.deactivateAt(sooner);
    RotationResult r = old.rotateIfActiveForResult(MONTH, Rotation.grace(WEEK));
    assertEquals(RotationResult.Outcome.ROTATED, r.outcome());
    assertEquals(Optional.of(sooner), r.previousDeactivationDate());
  }

  /**
   * Another caller rotates the key between this call's reads and its Re-key, and the server refuses
   * the second Re-key. This call follows that replacement: FOLLOWED, nothing created, and the grace
   * period still scheduled on the key it considered.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anotherCallersRotationIsFollowed(KmipVersion version) {
    InMemoryKmipServer s = server(version).refuseSecondReKey(true);
    Kms other = connect(s, r -> {});
    AtomicReference<KeyHandle> rotateFirst = new AtomicReference<>();
    AtomicReference<KeyHandle> theirs = new AtomicReference<>();
    Kms kms =
        connect(
            s,
            r -> {
              if (!RotationAndNameChoiceTest.isOperation(r, Operation.RE_KEY)) return;
              KeyHandle k = rotateFirst.getAndSet(null);
              if (k != null) theirs.set(other.keys().handle(k.id()).rotate());
            });
    KeyHandle old = made(s, kms, MONTH.plusDays(1));
    rotateFirst.set(old);
    int keys = s.ids().size();
    RotationResult r = old.rotateIfActiveForResult(MONTH, Rotation.grace(WEEK));
    assertEquals(RotationResult.Outcome.FOLLOWED, r.outcome(), r.toString());
    assertEquals(old, r.previous());
    assertEquals(theirs.get().id(), r.current().id());
    assertEquals(keys + 1, s.ids().size(), "only the other caller's key was made");
    assertEquals(old.attributes().deactivationDate(), r.previousDeactivationDate());
    assertTrue(r.previousDeactivationDate().isPresent());
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aKeyThatIsNotDueIsReturnedAsItIs(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s, r -> {});
    KeyHandle fresh = ScheduledRotationTest.aes(kms).create();
    RotationResult r = fresh.rotateIfActiveForResult(MONTH, Rotation.grace(WEEK));
    assertEquals(RotationResult.Outcome.NOT_DUE, r.outcome());
    assertEquals(fresh, r.previous());
    assertEquals(fresh, r.current());
    assertEquals(Optional.empty(), r.previousDeactivationDate());
    assertEquals(Optional.empty(), fresh.attributes().deactivationDate());
    // Zero is always due; without a grace period nothing is scheduled.
    RotationResult now =
        fresh.rotateIfActiveForResult(Duration.ZERO, Rotation.of(RotationDates.COPIED));
    assertEquals(RotationResult.Outcome.ROTATED, now.outcome());
    assertEquals(Optional.empty(), now.previousDeactivationDate());
    assertEquals(KeyState.ACTIVE, fresh.attributes().state());
  }
}
