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
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Scheduled rotation: {@code rotateIfActiveFor} rotates once a period however the job fires, a
 * shared {@code CurrentKey} rotates and moves, its failed checks are reported, and a server's
 * reason is its own word. PEM files and reloads are in {@link TlsFileReloadTest}.
 */
class ScheduledRotationTest {
  static final String NAME = "vault";
  static final Duration MONTH = Duration.ofDays(30);

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

  Kms connect(InMemoryKmipServer server) {
    Kms kms = server.connect();
    clients.add(kms);
    return kms;
  }

  /**
   * A client whose first request of {@code op} first runs {@code winner} (another caller's move,
   * through another client), then goes to the server.
   */
  Kms losing(InMemoryKmipServer server, Operation op, Runnable winner) {
    boolean[] done = {false};
    Kms kms =
        Kms.connect(
            server
                .configure()
                .transport(
                    e ->
                        request -> {
                          if (!done[0] && RotationAndNameChoiceTest.isOperation(request, op)) {
                            done[0] = true;
                            winner.run();
                          }
                          return server.exchange(request);
                        })
                .build());
    clients.add(kms);
    return kms;
  }

  static KeyCreation aes(Kms kms) {
    return kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named(NAME);
  }

  /** Runs {@code step} with the server's clock {@code ago} in the past, then back on the system clock. */
  static <T> T ago(InMemoryKmipServer s, Duration ago, java.util.function.Supplier<T> step) {
    s.clock(Clock.fixed(Instant.now().minus(ago), ZoneOffset.UTC));
    try {
      return step.get();
    } finally {
      s.clock(Clock.systemUTC());
    }
  }

  // ---- rotateIfActiveFor ----

  /**
   * A rotation job that fires again, from the same handle, from an old
   * handle or from a fresh lookup by name, rotates once a period. A key Active for 40 days is not
   * rotated for a 60-day period (one Get Attributes, no Re-key), and is for a 30-day one; firing
   * again from {@code findByName} and from the replaced key's handle returns the new key with no
   * Re-key (a fresh lookup must not rotate again when the job fires twice); {@code Duration.ZERO} rotates as {@code rotateOrLatest()}.
   * On servers that refuse a second Re-key and on those that fork.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void rotateIfActiveForRotatesOnceAPeriodHoweverTheJobFires(KmipVersion version) {
    for (boolean refuse : new boolean[] {true, false}) {
      InMemoryKmipServer s = server(version).refuseSecondReKey(refuse);
      Kms kms = connect(s);
      KeyHandle key = ago(s, Duration.ofDays(40), () -> aes(kms).create());
      int reKeys = reKeys(s), requests = s.protocolRequests().size();
      assertEquals(
          key.id(), kms.keys().handle(key.id()).rotateIfActiveFor(Duration.ofDays(60)).id());
      assertEquals(reKeys, reKeys(s), "not due: no Re-key");
      assertEquals(requests + 1, s.protocolRequests().size(), "one Get Attributes");

      KeyHandle next = kms.keys().handle(key.id()).rotateIfActiveFor(MONTH);
      assertNotEquals(key.id(), next.id());
      assertEquals(Optional.of(KeyState.ACTIVE), s.state(next.id()));
      assertEquals(List.of(next.id()), s.links(key.id(), LinkKind.REPLACEMENT));
      assertEquals(reKeys + 1, reKeys(s));
      // Fired again: from a fresh lookup, from the old handle, from the new one.
      assertEquals(
          next.id(), kms.keys().findByName(NAME).orElseThrow().rotateIfActiveFor(MONTH).id());
      assertEquals(next.id(), kms.keys().handle(key.id()).rotateIfActiveFor(MONTH).id());
      assertEquals(next.id(), next.rotateIfActiveFor(MONTH).id());
      assertEquals(reKeys + 1, reKeys(s), "rotated once");

      KeyHandle third = next.rotateIfActiveFor(Duration.ZERO);
      assertNotEquals(next.id(), third.id());
      assertEquals(List.of(third.id()), s.links(next.id(), LinkKind.REPLACEMENT));
    }
  }

  /**
   * The period is the current key's, not the handle's. A handle on a key replaced 40 days
   * ago (the replacement Active since): not due for 60 days (the current key returned, no Re-key),
   * due for 30, and then the current key is rotated, not the handle's (which {@code
   * rotateOrLatest()} would only follow).
   */
  @Test
  void rotateIfActiveForMeasuresTheCurrentKey() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    KeyHandle first = ago(s, Duration.ofDays(100), () -> aes(kms).create());
    KeyHandle second = ago(s, Duration.ofDays(40), first::rotate);
    int reKeys = reKeys(s);
    assertEquals(
        second.id(), kms.keys().handle(first.id()).rotateIfActiveFor(Duration.ofDays(60)).id());
    assertEquals(reKeys, reKeys(s));
    KeyHandle third = kms.keys().handle(first.id()).rotateIfActiveFor(MONTH);
    assertEquals(
        List.of(third.id()), s.links(second.id(), LinkKind.REPLACEMENT), "the current key rotated");
    assertEquals(reKeys + 1, reKeys(s));
  }

  /**
   * Two firings at once for a due key, on a server that refuses a second Re-key: the second
   * returns the first's replacement (rotateOrLatest's semantics), and the key is rotated once.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V2_1"})
  void rotateIfActiveForFiredTwiceAtOnceRotatesOnce(KmipVersion version) {
    InMemoryKmipServer s = server(version).refuseSecondReKey(true);
    Kms admin = connect(s);
    KeyHandle key = ago(s, Duration.ofDays(40), () -> aes(admin).create());
    KeyHandle[] won = new KeyHandle[1];
    Kms loser =
        losing(
            s,
            Operation.RE_KEY,
            () -> won[0] = admin.keys().handle(key.id()).rotateIfActiveFor(MONTH));
    KeyHandle second = loser.keys().handle(key.id()).rotateIfActiveFor(MONTH);
    assertEquals(won[0].id(), second.id());
    assertEquals(List.of(won[0].id()), s.links(key.id(), LinkKind.REPLACEMENT));
  }

  /**
   * {@code Duration.ZERO} rotates also when the server's clock is ahead of this machine's (the
   * key's Activation Date is in this machine's future): the key is due, not returned unchanged.
   */
  @Test
  void aZeroPeriodRotatesWhateverTheClocks() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    KeyHandle key = ago(s, Duration.ofMinutes(-2), () -> aes(kms).create());
    KeyHandle next = key.rotateIfActiveFor(Duration.ZERO);
    assertNotEquals(key.id(), next.id());
    assertEquals(List.of(next.id()), s.links(key.id(), LinkKind.REPLACEMENT));
  }

  /** A negative period is refused before anything is sent; null is a NullPointerException. */
  @Test
  void rotateIfActiveForNeedsAPeriod() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    KeyHandle key = aes(kms).create();
    int requests = s.protocolRequests().size();
    assertThrows(
        IllegalArgumentException.class, () -> key.rotateIfActiveFor(Duration.ofSeconds(-1)));
    assertThrows(NullPointerException.class, () -> key.rotateIfActiveFor(null));
    assertEquals(requests, s.protocolRequests().size());
    // A period no key reaches, which Instant.plus cannot add: never due.
    assertEquals(key.id(), key.rotateIfActiveFor(Duration.ofSeconds(Long.MAX_VALUE)).id());
  }

  // ---- a CurrentKey rotates and moves itself ----

  static final byte[] PLAIN = "record".getBytes(java.nio.charset.StandardCharsets.UTF_8), AAD = {1};

  /**
   * Components share one {@code CurrentKey}; the rotation job rotates
   * through it, and the next seal of every component is under the new key, without a new object
   * or a refused seal. Not due: nothing sent but the read, the key held unchanged. Due: rotated and
   * held. {@code rotateOrLatest()}: rotated again and held. Records sealed before still open.
   */
  @Test
  void aCurrentKeyRotatesItself() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    KeyHandle first = ago(s, Duration.ofDays(40), () -> aes(kms).create());
    CurrentKey shared = kms.keys().current(NAME);
    byte[] old = shared.seal(PLAIN, AAD);
    int reKeys = reKeys(s);
    assertEquals(first.id(), shared.rotateIfActiveFor(Duration.ofDays(60)).id());
    assertEquals(reKeys, reKeys(s));
    KeyHandle second = shared.rotateIfActiveFor(MONTH);
    assertNotEquals(first.id(), second.id());
    assertEquals(second.id(), shared.handle().id(), "held");
    int requests = s.protocolRequests().size();
    byte[] sealed = shared.seal(PLAIN, AAD);
    assertEquals(second.id(), KmsKeys.sealedKeyId(sealed), "the next seal is under the new key");
    assertEquals(requests + 1, s.protocolRequests().size(), "one Encrypt, no refusal, no check");
    KeyHandle third = shared.rotateOrLatest();
    assertEquals(List.of(third.id()), s.links(second.id(), LinkKind.REPLACEMENT));
    assertEquals(third.id(), KmsKeys.sealedKeyId(shared.seal(PLAIN, AAD)));
    assertArrayEquals(PLAIN, shared.open(old, AAD));
    assertArrayEquals(PLAIN, shared.open(sealed, AAD));
  }

  /**
   * {@code moveTo} holds any key of the same {@code Kms}, without a request: the replacement
   * {@code replaceCompromised} returned, or a key made without links that following could never
   * reach. A handle of another {@code Kms} is refused (a view of the same one is not). A failed
   * rotation leaves the key held as it was.
   */
  @Test
  void aCurrentKeyMovesToTheKeyItIsGiven() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    KeyHandle first = aes(kms).create();
    CurrentKey shared = kms.keys().current(first);
    KeyHandle replacement =
        shared.handle().replaceCompromised(CredentialRefusalReadBackTest.leaked());
    int requests = s.protocolRequests().size();
    assertSame(replacement, shared.moveTo(replacement));
    assertEquals(requests, s.protocolRequests().size(), "no request");
    assertEquals(replacement.id(), KmsKeys.sealedKeyId(shared.seal(PLAIN, AAD)));

    KeyHandle unlinked =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    shared.moveTo(unlinked);
    assertEquals(unlinked.id(), KmsKeys.sealedKeyId(shared.seal(PLAIN, AAD)));
    shared.moveTo(kms.withTimeout(Duration.ofSeconds(5)).keys().handle(replacement.id()));
    assertEquals(replacement.id(), shared.handle().id());

    Kms other = connect(s.replica());
    KeyHandle foreign = other.keys().handle(unlinked.id());
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> shared.moveTo(foreign));
    assertTrue(
        e.getMessage().startsWith("moveTo: " + unlinked.id() + " is a handle of another Kms"),
        e.getMessage());
    assertEquals(replacement.id(), shared.handle().id());
    assertThrows(NullPointerException.class, () -> shared.moveTo(null));

    // A rotation that fails (the server refuses the Re-key) leaves the key held as it was.
    s.failNext(
        dev.keytend.kmip.testing.ServerOperation.RE_KEY,
        Enums.ResultReason.OPERATION_NOT_SUPPORTED);
    assertThrows(UnsupportedException.class, shared::rotateOrLatest);
    s.failNext(
        dev.keytend.kmip.testing.ServerOperation.RE_KEY,
        Enums.ResultReason.OPERATION_NOT_SUPPORTED);
    assertThrows(UnsupportedException.class, () -> shared.rotateIfActiveFor(Duration.ZERO));
    assertEquals(replacement.id(), shared.handle().id());
  }

  // ---- a CurrentKey says when its check fails ----

  /**
   * A {@code CurrentKey} whose check fails (here its key's read refused
   * with Permission Denied) goes on sealing under the key it holds, and the listener hears of it
   * once per failed check, with the count of failures in a row: no second event before the next
   * check is due, 2 at the next failed check, none for a check that succeeds, and 1 again after it.
   * A listener that seals through the same object from the callback does not set off another
   * check. Before, the failure was passed over without a word.
   */
  @Test
  void aCurrentKeyReportsChecksThatFail() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    List<String> heard = new CopyOnWriteArrayList<>();
    CurrentKey[] current = new CurrentKey[1];
    Kms kms =
        Kms.connect(
            s.configure()
                .retryPolicy(RetryPolicy.none())
                .addListener(
                    new KmsListener() {
                      @Override
                      public void currentKeyCheckFailed(
                          String keyId, int failuresInARow, KmsException failure) {
                        heard.add(keyId + " " + failuresInARow + " " + failure.category());
                        current[0].seal(PLAIN, AAD); // re-entering: not a check
                      }
                    })
                .build());
    clients.add(kms);
    KeyHandle key = aes(kms).create();
    long[] clock = {0};
    long minute = Duration.ofMinutes(1).toNanos();
    current[0] = new CurrentKey(kms.keys().handle(key.id()), Duration.ofMinutes(1), () -> clock[0]);
    current[0].seal(PLAIN, AAD); // the first seal reads the key
    Runnable refuseNextRead =
        () ->
            s.failNext(
                dev.keytend.kmip.testing.ServerOperation.GET_ATTRIBUTES,
                Enums.ResultReason.PERMISSION_DENIED);

    clock[0] += minute;
    refuseNextRead.run();
    assertEquals(key.id(), KmsKeys.sealedKeyId(current[0].seal(PLAIN, AAD)), "sealing goes on");
    assertEquals(List.of(key.id() + " 1 FIX_ACCESS"), heard);
    current[0].seal(PLAIN, AAD);
    clock[0] += minute / 2;
    current[0].seal(PLAIN, AAD);
    assertEquals(1, heard.size(), "at most once per interval");

    clock[0] += minute;
    refuseNextRead.run();
    current[0].seal(PLAIN, AAD);
    assertEquals(List.of(key.id() + " 1 FIX_ACCESS", key.id() + " 2 FIX_ACCESS"), heard);

    clock[0] += minute;
    current[0].seal(PLAIN, AAD); // the check succeeds
    assertEquals(2, heard.size());
    clock[0] += minute;
    refuseNextRead.run();
    current[0].seal(PLAIN, AAD);
    assertEquals(
        key.id() + " 1 FIX_ACCESS", heard.get(2), "counted afresh after a check succeeded");
    assertEquals(3, heard.size());
  }

  // ---- KmsReason is the server's word ----

  /**
   * A 1.x server's Illegal Operation is {@code ILLEGAL_OPERATION}, not
   * {@code WRONG_LIFECYCLE_STATE} (the server's word; the category is still STATE), and Usage
   * Limit Exceeded is {@code USAGE_LIMIT_EXCEEDED}, not {@code OTHER} (a quota, which a service
   * tells apart; STATE). The full table is {@link KmsReasonTest}.
   */
  @Test
  void theServersReasonIsItsOwnWord() {
    InMemoryKmipServer v14 = server(KmipVersion.V1_4);
    KeyHandle old = aes(connect(v14)).create();
    v14.failNext(
        dev.keytend.kmip.testing.ServerOperation.ENCRYPT, Enums.ResultReason.ILLEGAL_OPERATION);
    KmsException illegal =
        assertThrows(KmsException.class, () -> old.encrypt(CipherSpec.aesGcm(), PLAIN));
    assertEquals(
        Optional.of(KmsReason.ILLEGAL_OPERATION), illegal.serverReason(), illegal.toString());
    assertEquals(KmsException.Category.STATE, illegal.category());

    InMemoryKmipServer v21 = server(KmipVersion.V2_1);
    KeyHandle key = aes(connect(v21)).create();
    v21.failNext(
        dev.keytend.kmip.testing.ServerOperation.ENCRYPT, Enums.ResultReason.USAGE_LIMIT_EXCEEDED);
    KmsException used =
        assertThrows(StateConflictException.class, () -> key.encrypt(CipherSpec.aesGcm(), PLAIN));
    assertEquals(Optional.of(KmsReason.USAGE_LIMIT_EXCEEDED), used.serverReason(), used.toString());
    v21.failNext(
        dev.keytend.kmip.testing.ServerOperation.ENCRYPT,
        Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE);
    KmsException wrong =
        assertThrows(StateConflictException.class, () -> key.encrypt(CipherSpec.aesGcm(), PLAIN));
    assertEquals(Optional.of(KmsReason.WRONG_LIFECYCLE_STATE), wrong.serverReason());
  }
}
