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
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link StateConflictException#conflict()} says which refusal a conflict is, so callers do not
 * guess from {@code observedState()} and {@code objectId()}; and {@link
 * KeyRegistration#replaceResult} says what became of the old object, so callers do not read it
 * again.
 */
class ConflictKindTest {
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
    Kms kms = Kms.connect(s.configure().retryPolicy(RetryPolicy.none()).build());
    clients.add(kms);
    return kms;
  }

  static KeyHandle aes(Kms kms, String name) {
    return kms.keys()
        .createAes(256)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .named(name)
        .create();
  }

  static StateConflictException.Conflict kind(Runnable call) {
    return assertThrows(StateConflictException.class, call::run).conflict();
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void eachRefusalSaysWhichConflictItIs(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s), other = connect(s);
    KeyHandle a = aes(kms, "kek");
    // Rotated already: REPLACED.
    a.rotate();
    assertEquals(StateConflictException.Conflict.REPLACED, kind(a::rotate));
    // The lineage's current key is not the one approved: NOT_AS_PLANNED.
    assertEquals(
        StateConflictException.Conflict.NOT_AS_PLANNED,
        kind(
            () -> a.rotateIfActiveForResult(Duration.ZERO, Rotation.grace(Duration.ofDays(1)), a)));
    // A deactivation plan the lineage no longer matches: NOT_AS_PLANNED.
    KeyHandle p =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("staged")
            .createPreActive();
    KeyHandle n = p.rotate().rotate();
    RetirementPlan plan = n.retirementPlan();
    other.keys().handle(p.id()).activate();
    assertEquals(
        StateConflictException.Conflict.NOT_AS_PLANNED,
        kind(() -> n.deactivatePredecessors(RevocationReason.superseded("old"), plan)));
    // A taken name: NAME, an AlreadyExistsException.
    StateConflictException taken =
        assertThrows(
            AlreadyExistsException.class,
            () ->
                kms.keys()
                    .createAes(256)
                    .usages(KeyUsage.ENCRYPT)
                    .named("kek")
                    .refusingExistingName()
                    .create());
    assertEquals(StateConflictException.Conflict.NAME, taken.conflict());
    // A Compromised key is not rotated as routine: STATE, with its state.
    KeyHandle c = aes(kms, "leaked");
    c.revoke(RevocationReason.keyCompromise("leaked", Instant.now()));
    StateConflictException compromised =
        assertThrows(StateConflictException.class, () -> c.allowingCompromised().rotate());
    assertEquals(StateConflictException.Conflict.STATE, compromised.conflict());
    assertEquals(Optional.of(KeyState.COMPROMISED), compromised.observedState());
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aSecretReplacementSaysWhatBecameOfTheOldOne(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s), other = connect(s);
    KeyHandle active = secret(kms, "db").register();
    ReplacementResult r = secret(kms, "db").replaceResult(active, active.attributes());
    assertEquals(active, r.previous());
    assertEquals(KeyState.DEACTIVATED, r.previousState());
    assertTrue(r.deactivatedPrevious());
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(active.id()));
    assertEquals(List.of("db"), s.names(r.replacement().id()));

    // A Pre-Active one is left as it is.
    KeyHandle staged = secret(kms, "staged").registerPreActive();
    ReplacementResult left = secret(kms, "staged").replaceResult(staged, staged.attributes());
    assertEquals(KeyState.PRE_ACTIVE, left.previousState());
    assertFalse(left.deactivatedPrevious());

    // A Deactivated one too: not deactivated by this call.
    KeyHandle retired = secret(kms, "retired").register();
    retired.deactivate();
    ReplacementResult kept = secret(kms, "retired").replaceResult(retired);
    assertEquals(KeyState.DEACTIVATED, kept.previousState());
    assertFalse(kept.deactivatedPrevious());

    // Changed while the plan waited: NOT_AS_PLANNED, nothing registered.
    KeyHandle raced = secret(kms, "raced").registerPreActive();
    KeyAttributes planned = raced.attributes();
    other.keys().handle(raced.id()).activate();
    int before = s.ids().size();
    StateConflictException e =
        assertThrows(
            StateConflictException.class, () -> secret(kms, "raced").replaceResult(raced, planned));
    assertEquals(StateConflictException.Conflict.NOT_AS_PLANNED, e.conflict());
    assertEquals(before, s.ids().size());
    // An object without the name: NAME.
    assertEquals(
        StateConflictException.Conflict.NAME,
        kind(() -> secret(kms, "other-name").replaceResult(active)));
  }

  static KeyRegistration secret(Kms kms, String name) {
    return kms.keys()
        .registerSecret(SecretData.Type.PASSWORD, "s3cret".getBytes(StandardCharsets.UTF_8))
        .named(name);
  }

  @Test
  void applicationCodesExceptionsHaveTheDefaultKinds() {
    assertEquals(StateConflictException.Conflict.STATE, new StateConflictException("x").conflict());
    assertEquals(StateConflictException.Conflict.NAME, new AlreadyExistsException("x").conflict());
  }
}
