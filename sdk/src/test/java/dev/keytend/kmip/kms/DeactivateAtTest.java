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

import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link KeyHandle#deactivateAt}: the Deactivation Date through the application API, with the SDK's
 * failover, classification and read-back, on every version.
 */
class DeactivateAtTest {
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

  Kms connect(InMemoryKmipServer s) {
    return connect(s, r -> {});
  }

  Kms connect(InMemoryKmipServer s, Consumer<Ttlv> before) {
    return connect(
        s.configure()
            .retryPolicy(RetryPolicy.none())
            .transport(
                e ->
                    r -> {
                      before.accept(r);
                      return s.exchange(r);
                    }));
  }

  Kms connect(KmsConfig.Builder config) {
    Kms kms = Kms.connect(config.build());
    clients.add(kms);
    return kms;
  }

  static KeyHandle key(Kms kms) {
    return kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
  }

  static Instant inDays(int days) {
    return Instant.now().plus(days, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS);
  }

  static int sent(InMemoryKmipServer s, Operation op) {
    return RotationGraceTest.sent(s, op);
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void setsTheDateAndNeverPostponesOne(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = key(kms);
    Instant at = inDays(10);
    // Rounded up to a whole second.
    assertEquals(at, key.deactivateAt(at.minusMillis(400)));
    assertEquals(Optional.of(at), key.attributes().deactivationDate());
    assertEquals(KeyState.ACTIVE, key.attributes().state());
    assertEquals(1, sent(s, Operation.ADD_ATTRIBUTE));
    // An earlier date replaces it, with Modify Attribute.
    Instant earlier = at.minus(1, ChronoUnit.DAYS);
    assertEquals(earlier, key.deactivateAt(earlier));
    assertEquals(1, sent(s, Operation.MODIFY_ATTRIBUTE));
    assertEquals(Optional.of(earlier), key.attributes().deactivationDate());
    // A later one is not set: the earlier date stays, and nothing is sent.
    assertEquals(earlier, key.deactivateAt(at));
    assertEquals(1, sent(s, Operation.ADD_ATTRIBUTE));
    assertEquals(1, sent(s, Operation.MODIFY_ATTRIBUTE));
    assertEquals(Optional.of(earlier), key.attributes().deactivationDate());
    // Never a lifecycle operation, on 3.0 either.
    assertEquals(0, sent(s, Operation.REVOKE) + sent(s, Operation.DEACTIVATE));
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aPreActiveKeyGetsTheDateAndStaysPreActive(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle staged =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
    Instant at = inDays(3);
    assertEquals(at, staged.deactivateAt(at));
    KeyAttributes a = staged.attributes();
    assertEquals(KeyState.PRE_ACTIVE, a.state());
    assertEquals(Optional.of(at), a.deactivationDate());
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void keysThatNoLongerEncryptAreRefusedOrKeepTheirDate(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle compromised = key(kms);
    compromised.revoke(RevocationReason.keyCompromise("leaked", Instant.now()));
    StateConflictException refused =
        assertThrows(StateConflictException.class, () -> compromised.deactivateAt(inDays(1)));
    assertEquals(Optional.of(KeyState.COMPROMISED), refused.observedState());
    // A Deactivated key has a Deactivation Date already, no later than any future date.
    KeyHandle deactivated = key(kms);
    deactivated.deactivate();
    Instant had = deactivated.attributes().deactivationDate().orElseThrow();
    int before = sent(s, Operation.ADD_ATTRIBUTE) + sent(s, Operation.MODIFY_ATTRIBUTE);
    assertEquals(had, deactivated.deactivateAt(inDays(1)));
    assertEquals(before, sent(s, Operation.ADD_ATTRIBUTE) + sent(s, Operation.MODIFY_ATTRIBUTE));
  }

  @Test
  void aDateInThePastIsRefusedBeforeAnythingIsSent() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    KeyHandle key = key(kms);
    int before = s.exchanges();
    assertThrows(
        IllegalArgumentException.class, () -> key.deactivateAt(Instant.now().minusSeconds(60)));
    assertEquals(before, s.exchanges());
  }

  /**
   * A server that does not let clients set the attribute: UNSUPPORTED, not a state conflict, from
   * KMIP 2.0 (Attribute Read Only). KMIP 1.x has no such reason: its servers answer Permission
   * Denied, which the read-back cannot tell from an access refusal.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1", "V3_0"})
  void aReadOnlyDeactivationDateIsUnsupported(KmipVersion version) {
    InMemoryKmipServer s = server(version).refuseClientDeactivationDate(true);
    Kms kms = connect(s);
    KeyHandle key = key(kms);
    UnsupportedException e =
        assertThrows(UnsupportedException.class, () -> key.deactivateAt(inDays(1)));
    assertEquals(KmsException.Category.FIX_REQUEST, e.category());
    assertEquals(Optional.of(key.id()), e.objectId());
    assertTrue(e.getMessage().contains("deactivate it at that time instead"), e.getMessage());
  }

  @Test
  void onKmip14AReadOnlyDeactivationDateIsAPermissionRefusal() {
    InMemoryKmipServer s = server(KmipVersion.V1_4).refuseClientDeactivationDate(true);
    Kms kms = connect(s);
    KeyHandle key = key(kms);
    assertThrows(PermissionDeniedException.class, () -> key.deactivateAt(inDays(1)));
    assertEquals(KeyState.ACTIVE, key.attributes().state());
  }

  /** Each failure keeps the SDK's classification. */
  @Test
  void failuresAreClassifiedAsEverywhereElse() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    KeyHandle key = key(kms);
    // Not sent: unavailable, not an unknown outcome.
    s.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.UNREACHABLE);
    assertThrows(TransientException.class, () -> key.deactivateAt(inDays(1)));
    assertEquals(Optional.empty(), key.attributes().deactivationDate());
    // The client's credentials refused: access, not a state conflict and not a server failure.
    s.failNext(ServerOperation.ADD_ATTRIBUTE, Enums.ResultReason.AUTHENTICATION_NOT_SUCCESSFUL);
    PermissionDeniedException denied =
        assertThrows(PermissionDeniedException.class, () -> key.deactivateAt(inDays(1)));
    assertEquals(KmsException.Category.FIX_ACCESS, denied.category());
    // A lost reply is read back: the date is there, so it is done.
    s.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.REPLY_LOST);
    Instant at = inDays(2);
    assertEquals(at, key.deactivateAt(at));
    assertEquals(Optional.of(at), key.attributes().deactivationDate());
  }

  @Test
  void aHungRequestWhoseDateIsNotThereIsAnUnknownOutcome() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms =
        connect(s.configure().retryPolicy(RetryPolicy.none()).callTimeout(Duration.ofSeconds(1)));
    KeyHandle key = key(kms);
    s.failNext(ServerOperation.MODIFY_ATTRIBUTE, Fault.HANG);
    key.deactivateAt(inDays(5));
    s.failNext(ServerOperation.MODIFY_ATTRIBUTE, Fault.HANG);
    OutcomeUnknownException unknown =
        assertThrows(OutcomeUnknownException.class, () -> key.deactivateAt(inDays(4)));
    assertEquals(Optional.of(key.id()), unknown.objectId());
  }

  /**
   * Another caller revoked the key between the read and the write: the server refuses the date
   * for the key's state, and the read-back finds a Deactivation Date no later than asked, so the
   * call is done.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aKeyDeactivatedMeanwhileCountsAsDone(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicReference<KeyHandle> revokeFirst = new AtomicReference<>();
    Kms other = connect(s);
    Kms kms =
        connect(
            s,
            r -> {
              if (!RotationAndNameChoiceTest.isOperation(r, Operation.ADD_ATTRIBUTE)) return;
              KeyHandle k = revokeFirst.getAndSet(null);
              if (k != null) other.keys().handle(k.id()).deactivate();
            });
    KeyHandle key = key(kms);
    revokeFirst.set(key);
    Instant at = inDays(1);
    Instant set = key.deactivateAt(at);
    assertFalse(set.isAfter(at), set + " is no later than " + at);
    assertEquals(KeyState.DEACTIVATED, key.attributes().state());
  }

  /** A read and a mutation of the application API: failed over, and told to the listener. */
  @Test
  void itFailsOverAndIsReported() {
    InMemoryKmipServer a = server(KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica();
    servers.add(b);
    List<KmsEvent> events = new CopyOnWriteArrayList<>();
    Kms kms =
        connect(
            a.configureReplicas(b)
                .addListener(
                    new KmsListener() {
                      @Override
                      public void finished(KmsEvent event) {
                        events.add(event);
                      }
                    }));
    KeyHandle key = key(kms);
    a.unreachable(true);
    Instant at = inDays(7);
    assertEquals(at, key.deactivateAt(at));
    assertEquals(Optional.of(at), key.attributes().deactivationDate());
    assertTrue(
        events.stream().anyMatch(e -> e.operation().equals("deactivateAt")), events.toString());
  }
}
