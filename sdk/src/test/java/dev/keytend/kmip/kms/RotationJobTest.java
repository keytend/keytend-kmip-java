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

import static dev.keytend.kmip.kms.ReplicaRaceTest.reKeys;
import static dev.keytend.kmip.kms.ScheduledRotationTest.NAME;
import static dev.keytend.kmip.kms.ScheduledRotationTest.aes;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Rotation jobs: one rotation per period wherever the job fires, and refusal of a compromised key. */
class RotationJobTest {
  static final Duration MONTH = Duration.ofDays(30);
  static final Instant START = Instant.parse("2026-01-01T00:00:00Z");

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  /** A clock the test moves: the server's dates and the clients' "now" read the same one. */
  static final class TestClock extends Clock {
    volatile Instant now;

    TestClock(Instant now) {
      this.now = now;
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }

  InMemoryKmipServer server(KmipVersion version, TestClock clock) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    if (clock != null) s.clock(clock);
    servers.add(s);
    return s;
  }

  Kms connect(InMemoryKmipServer server, TestClock clock) {
    return connect(server, clock, UnaryOperator.identity());
  }

  /** A client of {@code server} on {@code clock} whose responses pass through {@code reply}. */
  Kms connect(InMemoryKmipServer server, TestClock clock, UnaryOperator<Ttlv> reply) {
    Kms kms =
        Kms.connect(
            server
                .configure()
                .transport(e -> request -> reply.apply(server.exchange(request)))
                .build());
    if (clock != null) kms.clock(clock);
    clients.add(kms);
    return kms;
  }

  // ---- the due time of a replacement ----

  /**
   * A rotation job that fires five
   * times a period, from five places (the handle it started with, a fresh {@code findByName}, a
   * shared {@code CurrentKey}, another instance's lookup, and the key the last firing returned),
   * rotates exactly once a period over twelve periods, and at the first firing of each. On a
   * server that copies the old key's Activation Date to the replacement, as KMIP Re-key without an
   * Offset does (the fake's default; keytend-kmip-server), and on one that gives it new dates. On
   * the first kind, measuring the replacement from its lineage's first Activation Date would rotate
   * at every firing after the first period (399 keys in 84 periods).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aJobFiredOverManyPeriodsRotatesOncePerPeriod(KmipVersion version) {
    for (boolean freshDates : new boolean[] {false, true})
      for (boolean refuse : new boolean[] {true, false}) {
        String where = "freshDates=" + freshDates + " refuseSecondReKey=" + refuse;
        TestClock clock = new TestClock(START);
        InMemoryKmipServer s =
            server(version, clock).freshDatesOnReKey(freshDates).refuseSecondReKey(refuse);
        InMemoryKmipServer replica = s.replica();
        Kms job = connect(s, clock), other = connect(replica, clock);
        KeyHandle first = aes(job).create();
        CurrentKey shared = job.keys().current(NAME);
        KeyHandle last = first;
        List<String> lineage = new ArrayList<>(List.of(first.id()));
        int periods = 12;
        Duration[] firings = {
          Duration.ofMinutes(1),
          Duration.ofHours(1),
          Duration.ofDays(1),
          Duration.ofDays(10),
          Duration.ofDays(29)
        };
        for (int period = 1; period <= periods; period++)
          for (int f = 0; f < firings.length; f++) {
            clock.now = START.plus(MONTH.multipliedBy(period)).plus(firings[f]);
            KeyHandle got =
                switch ((period + f) % 5) {
                  case 0 -> job.keys().handle(first.id()).rotateIfActiveFor(MONTH);
                  case 1 -> job.keys().findByName(NAME).orElseThrow().rotateIfActiveFor(MONTH);
                  case 2 -> shared.rotateIfActiveFor(MONTH);
                  case 3 -> other.keys().findByName(NAME).orElseThrow().rotateIfActiveFor(MONTH);
                  default -> last.rotateIfActiveFor(MONTH);
                };
            String at = where + " period " + period + " firing " + f;
            if (f == 0) lineage.add(got.id());
            assertEquals(
                lineage.get(period),
                got.id(),
                "rotated at the first firing of the period only: " + at);
            assertEquals(Optional.of(KeyState.ACTIVE), s.state(got.id()), at);
            last = got;
          }
        assertEquals(periods, reKeys(s) + reKeys(replica), "once a period: " + where);
        assertEquals(periods + 1, new HashSet<>(lineage).size(), where);
        assertEquals(
            lineage.get(periods),
            shared.handle().id(),
            "the shared CurrentKey holds the current key: " + where);
        if (!freshDates)
          assertEquals(
              first.attributes().activationDate(),
              last.attributes().activationDate(),
              "the server copied the Activation Date along the lineage: " + where);
      }
  }

  /**
   * The due time is the later of the Activation and Initial Dates. A key made Pre-Active and
   * activated 20 days later is measured from its activation (not due for 30 days 40 days after it
   * was made). A reply without an Activation Date: from the Initial Date; without an Initial Date:
   * from the Activation Date. A reply with neither cannot be measured: {@code
   * ProtocolViolationException}, with nothing sent but the read (before, such a key was rotated).
   * {@code Duration.ZERO} needs no date.
   */
  @Test
  void theDueTimeIsTheLaterOfTheActivationAndInitialDates() throws Exception {
    TestClock clock = new TestClock(START);
    InMemoryKmipServer s = server(KmipVersion.V2_1, clock);
    Kms kms = connect(s, clock);
    String id = preActive(kms);
    clock.now = START.plus(Duration.ofDays(20));
    kms.keys().handle(id).activate();
    clock.now = START.plus(Duration.ofDays(40));
    int reKeys = reKeys(s);
    assertEquals(id, kms.keys().handle(id).rotateIfActiveFor(MONTH).id(), "Active for 20 days");
    assertEquals(reKeys, reKeys(s));

    // Made 40 days ago, activated 20 days ago: by the Initial Date alone it is due.
    Kms noActivation =
        connect(s, clock, r -> UnresolvedLineageStepsTest.without(r, Tag.ACTIVATION_DATE));
    assertTrue(noActivation.keys().handle(id).attributes().activationDate().isEmpty());
    KeyHandle rotated = noActivation.keys().handle(id).rotateIfActiveFor(MONTH);
    assertNotEquals(id, rotated.id());
    assertEquals(reKeys + 1, reKeys(s));

    // The replacement, made now (Initial Date) with the copied Activation Date of 20 days ago: not
    // due for 15 days by both dates, due by the Activation Date alone.
    Duration fortnight = Duration.ofDays(15);
    assertEquals(
        rotated.id(),
        kms.keys().handle(rotated.id()).rotateIfActiveFor(fortnight).id(),
        "made just now");
    Kms noInitial = connect(s, clock, r -> UnresolvedLineageStepsTest.without(r, Tag.INITIAL_DATE));
    assertTrue(noInitial.keys().handle(rotated.id()).attributes().creationDate().isEmpty());
    KeyHandle again = noInitial.keys().handle(rotated.id()).rotateIfActiveFor(fortnight);
    assertNotEquals(
        rotated.id(), again.id(), "measured from the copied Activation Date of 20 days ago");

    Kms neither =
        connect(
            s,
            clock,
            r ->
                UnresolvedLineageStepsTest.without(
                    UnresolvedLineageStepsTest.without(r, Tag.ACTIVATION_DATE), Tag.INITIAL_DATE));
    int requests = s.protocolRequests().size();
    ProtocolViolationException e =
        assertThrows(
            ProtocolViolationException.class,
            () -> neither.keys().handle(again.id()).rotateIfActiveFor(MONTH));
    assertTrue(
        e.getMessage().contains("neither an Activation Date nor an Initial Date for " + again.id()),
        e.getMessage());
    assertEquals(again.id(), e.objectId().orElseThrow());
    assertEquals(requests + 1, s.protocolRequests().size(), "nothing sent but the read");
    assertEquals(reKeys + 2, reKeys(s));
    KeyHandle zero = neither.keys().handle(again.id()).rotateIfActiveFor(Duration.ZERO);
    assertNotEquals(again.id(), zero.id(), "zero needs no date");
  }

  /** A key of the fake made Pre-Active, through the protocol: {@code create()} activates. */
  static String preActive(Kms kms) throws Exception {
    return kms.protocol()
        .call(
            Requests.create()
                .add(Ttlv.enumeration(Tag.OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY))
                .template(
                    Attributes.algorithm(Enums.CryptographicAlgorithm.AES),
                    Attributes.length(256),
                    Attributes.usage(
                        Enums.CryptographicUsageMask.ENCRYPT, Enums.CryptographicUsageMask.DECRYPT))
                .build())
        .uniqueIdentifier();
  }

  /**
   * {@code rotate()} activates a replacement the server left
   * Pre-Active, also when the Re-key's reply was lost, on a server that copies the dates and on one
   * that gives new ones. Since the fake copies the dates, the replacement of a revoked key is Active
   * at once, so the tests that reach this activation through a Compromised key do not; this test
   * catches a missing Activate after the Re-key on both kinds. A Pre-Active key's replacement is Pre-Active
   * on both kinds of server.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aReplacementLeftPreActiveIsActivatedOnEitherKindOfServer(KmipVersion version)
      throws Exception {
    for (boolean freshDates : new boolean[] {false, true})
      for (boolean lost : new boolean[] {false, true}) {
        String where = "freshDates=" + freshDates + " replyLost=" + lost;
        InMemoryKmipServer s = server(version, null).freshDatesOnReKey(freshDates);
        Kms kms = connect(s, null);
        String id = preActive(kms);
        if (lost) s.failNext(ServerOperation.RE_KEY, Fault.REPLY_LOST);
        KeyHandle next = kms.keys().handle(id).rotate();
        assertNotEquals(id, next.id(), where);
        assertEquals(List.of(next.id()), s.links(id, LinkKind.REPLACEMENT), where);
        assertEquals(Optional.of(KeyState.ACTIVE), s.state(next.id()), "activated: " + where);
      }
  }

  // ---- a Compromised key is not rotated as routine ----

  /** The calls of a rotation job, each on a fresh handle of {@code id} (or the shared {@code CurrentKey}). */
  static List<java.util.function.Function<KeyHandle, KeyHandle>> rotations(CurrentKey shared) {
    return List.of(
        k -> k.rotateIfActiveFor(MONTH),
        k -> k.rotateIfActiveFor(Duration.ZERO),
        KeyHandle::rotateOrLatest,
        KeyHandle::rotate,
        k -> shared.rotateIfActiveFor(MONTH),
        k -> shared.rotateOrLatest());
  }

  /**
   * An operator revokes the running
   * instance's key as compromised. {@code rotateIfActiveFor} (with a period and with zero), {@code
   * rotateOrLatest}, {@code rotate} and the {@code CurrentKey} forms each refuse it with {@code
   * StateConflictException} (STATE) naming the key and {@code replaceCompromised}, with nothing
   * sent but reads, and the shared {@code CurrentKey} keeps holding it; before, each sent a Re-key,
   * the server (KMIP allows it) made an Active replacement, and the instance moved on to it without
   * a word. {@code replaceCompromised} is not refused; after it, the job's calls from the
   * Compromised key's handle return the replacement with no Re-key. A Deactivated key is refused
   * the same way (its replacement would copy its Deactivation Date).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aRotationJobRefusesACompromisedKey(KmipVersion version) {
    InMemoryKmipServer s = server(version, null);
    Kms kms = connect(s, null);
    KeyHandle key = aes(kms).create();
    CurrentKey shared = kms.keys().current(NAME);
    key.revoke(RevocationReason.keyCompromise("leaked", Instant.now()));
    int reKeys = reKeys(s);
    for (var rotation : rotations(shared)) {
      StateConflictException e =
          assertThrows(
              StateConflictException.class, () -> rotation.apply(kms.keys().handle(key.id())));
      assertEquals(KmsException.Category.STATE, e.category());
      assertEquals(Optional.of(key.id()), e.objectId());
      assertTrue(
          e.getMessage().contains(key.id() + " is COMPROMISED")
              && e.getMessage().contains("replaceCompromised"),
          e.getMessage());
      assertEquals(reKeys, reKeys(s), "no Re-key: " + e.getMessage());
      assertEquals(key.id(), shared.handle().id(), "the CurrentKey still holds it");
    }
    KeyHandle replacement =
        shared.moveTo(
            shared
                .handle()
                .replaceCompromised(RevocationReason.keyCompromise("leaked", Instant.now())));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(replacement.id()));
    assertEquals(
        reKeys + 1, reKeys(s), "replaceCompromised re-keys it (not the fallback of a new key)");
    int after = reKeys(s);
    assertEquals(replacement.id(), kms.keys().handle(key.id()).rotateIfActiveFor(MONTH).id());
    assertEquals(replacement.id(), kms.keys().handle(key.id()).rotateOrLatest().id());
    assertEquals(after, reKeys(s), "the replacement is current and new");

    KeyHandle retired =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("retired")
            .create();
    retired.revoke(RevocationReason.cessationOfOperation("retired"));
    CurrentKey held = kms.keys().current(retired);
    for (var rotation : rotations(held)) {
      StateConflictException e =
          assertThrows(
              StateConflictException.class, () -> rotation.apply(kms.keys().handle(retired.id())));
      assertTrue(
          e.getMessage().contains(retired.id() + " is DEACTIVATED and names no replacement"),
          e.getMessage());
      assertTrue(e.getMessage().contains("otherwise create a new key"), e.getMessage());
    }
    assertEquals(after, reKeys(s));
  }

  /**
   * A key retired (Deactivated), then found compromised. A Re-key
   * without an Offset copies its Deactivation Date, which has passed, so on a server that follows
   * KMIP the replacement was born Deactivated: {@code replaceCompromised} failed with {@code
   * PartialCompletionException}, and its repeat and its advice led nowhere ({@code rotate()} refuses
   * a Deactivated key). It now makes a new key, linked to the old one as where Re-key is refused,
   * with no Re-key: Active, given the name, found by name, listing the old key among its
   * Compromised predecessors. And {@code rotate()} of a key whose Deactivation Date has passed (a
   * server policy's date) is refused, the key being Deactivated (the fake derives State from the
   * dates); one whose date passes between the check and the Re-key reports the
   * Deactivated replacement with advice that works.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aKeyRetiredThenCompromisedIsReplacedByANewKey(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version, null);
    Kms kms = connect(s, null);
    KeyHandle key = aes(kms).create();
    key.revoke(RevocationReason.cessationOfOperation("retired"));
    key.revoke(RevocationReason.keyCompromise("an old backup leaked", Instant.now()));
    int reKeys = reKeys(s);
    KeyHandle replacement =
        key.replaceCompromised(
            RevocationReason.keyCompromise("an old backup leaked", Instant.now()));
    assertEquals(reKeys, reKeys(s), "no Re-key: it would copy the past Deactivation Date");
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(replacement.id()));
    assertEquals(List.of(replacement.id()), s.links(key.id(), LinkKind.REPLACEMENT));
    assertEquals(Optional.of(replacement), kms.keys().findByName(NAME));
    assertEquals(
        List.of(key.id()),
        replacement.compromisedPredecessors().stream().map(KeyHandle::id).toList());
    assertEquals(
        replacement.id(),
        key.replaceCompromised(RevocationReason.keyCompromise("again", Instant.now())).id(),
        "a repeat finishes with it");

    // A key whose Deactivation Date has passed (a server policy's date) is Deactivated (on the
    // fake,
    // as on keytend-kmip-server), so rotate() refuses it before any Re-key.
    TestClock clock =
        new TestClock(Instant.now().truncatedTo(java.time.temporal.ChronoUnit.SECONDS));
    java.util.concurrent.atomic.AtomicBoolean arm = new java.util.concurrent.atomic.AtomicBoolean();
    InMemoryKmipServer t = server(version, clock);
    Kms onClock =
        connect(
            t,
            clock,
            reply -> {
              // The date passes between rotate()'s check and its Re-key.
              if (RotationAndNameChoiceTest.isOperation(reply, Operation.GET_ATTRIBUTES)
                  && arm.getAndSet(false)) clock.now = clock.now.plusSeconds(120);
              return reply;
            });
    String past = dated(onClock, clock.now.minusSeconds(60));
    StateConflictException refused =
        assertThrows(StateConflictException.class, () -> onClock.keys().handle(past).rotate());
    assertEquals(Optional.of(KeyState.DEACTIVATED), refused.observedState());
    assertEquals(0, reKeys(t));
    // rotate() of an Active key whose Deactivation Date passes meanwhile: the replacement is
    // Deactivated.
    String dated = dated(onClock, clock.now.plusSeconds(60));
    arm.set(true);
    PartialCompletionException e =
        assertThrows(PartialCompletionException.class, () -> onClock.keys().handle(dated).rotate());
    assertEquals(Optional.of(KeyState.DEACTIVATED), t.state(e.created().get(0).id()));
    assertTrue(
        e.getMessage()
            .contains(
                "a new key when it is Deactivated, since a Re-key copies "
                    + dated
                    + "'s Deactivation Date"),
        e.getMessage());
  }

  /** An Active AES key with the Deactivation Date {@code at}. */
  static String dated(Kms kms, Instant at) throws Exception {
    String id =
        kms.protocol()
            .call(
                Requests.create()
                    .add(Ttlv.enumeration(Tag.OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY))
                    .template(
                        Attributes.algorithm(Enums.CryptographicAlgorithm.AES),
                        Attributes.length(256),
                        Attributes.usage(
                            Enums.CryptographicUsageMask.ENCRYPT,
                            Enums.CryptographicUsageMask.DECRYPT),
                        Attributes.attribute(
                            "Deactivation Date", Ttlv.dateTime(Tag.DEACTIVATION_DATE, at)))
                    .build())
            .uniqueIdentifier();
    kms.keys().handle(id).activate();
    return id;
  }
}
