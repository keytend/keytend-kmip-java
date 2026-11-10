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
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * A replacement after a compromise bound to the plan an operator approved, and a result that says
 * what it did and which compromise date is in effect.
 */
class CompromisePlanTest {
  static final String NAME = "orders-kek";
  static final Instant MINE = Instant.parse("2026-10-01T00:00:00Z");
  static final Instant THEIRS = Instant.parse("2026-01-01T00:00:00Z");

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

  static KeyHandle aes(Kms kms) {
    return kms.keys()
        .createAes(256)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .named(NAME)
        .create();
  }

  static RevocationReason compromise(Instant since) {
    return RevocationReason.keyCompromise("leaked", since);
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anActiveKeyIsRevokedAndReplaced(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms);
    CompromisePlan plan = key.compromisePlan();
    assertTrue(plan.revokes());
    assertEquals(List.of(), plan.replacementIds());
    assertEquals(KeyState.ACTIVE, plan.attributes().state());
    int before = s.ids().size();
    CompromiseResult r = key.replaceCompromisedResult(compromise(MINE), plan);
    assertEquals(CompromiseResult.Outcome.REPLACED, r.outcome(), r.toString());
    assertTrue(r.revoked());
    assertEquals(Optional.of(MINE), r.compromiseOccurrenceDate());
    assertEquals(List.of(r.replacement()), r.created());
    assertEquals(key, r.compromised());
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(key.id()));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(r.replacement().id()));
    assertEquals(before + 1, s.ids().size());
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aCompromisedKeyKeepsItsFirstDateAndAnExistingReplacementIsReused(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms);
    key.revoke(compromise(THEIRS));
    CompromisePlan plan = key.compromisePlan();
    assertFalse(plan.revokes());
    assertEquals(Optional.of(THEIRS), plan.compromiseOccurrenceDate());
    CompromiseResult r = key.replaceCompromisedResult(compromise(MINE), plan);
    assertEquals(CompromiseResult.Outcome.COMPLETED, r.outcome(), r.toString());
    assertFalse(r.revoked());
    assertEquals(Optional.of(THEIRS), r.compromiseOccurrenceDate(), "the first compromise's date");
    assertEquals(List.of(r.replacement()), r.created());

    // Again: the replacement exists, and nothing is created.
    CompromisePlan again = key.compromisePlan();
    assertEquals(List.of(r.replacement().id()), again.replacementIds());
    int before = s.ids().size();
    CompromiseResult existing = key.replaceCompromisedResult(compromise(MINE), again);
    assertEquals(CompromiseResult.Outcome.EXISTING, existing.outcome());
    assertEquals(r.replacement(), existing.replacement());
    assertEquals(List.of(), existing.created());
    assertEquals(before, s.ids().size());
  }

  /**
   * The first race: another responder replaces the key, with its own compromise date, while the
   * plan waits. The call refuses, so the operator's date is not silently dropped, and nothing
   * changes.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anotherRespondersReplacementWhileThePlanWaitsIsRefused(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s), other = connect(s);
    KeyHandle key = aes(kms);
    CompromisePlan plan = key.compromisePlan();
    KeyHandle theirs =
        other.keys().handle(key.id()).allowingCompromised().replaceCompromised(compromise(THEIRS));
    int before = s.ids().size();
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> key.replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(StateConflictException.Conflict.NOT_AS_PLANNED, e.conflict(), e.getMessage());
    assertEquals(Optional.of(KeyState.COMPROMISED), e.observedState());
    assertEquals(before, s.ids().size(), "nothing was created");
    assertEquals(
        Optional.of(THEIRS),
        key.allowingCompromised().attributes().compromiseOccurrenceDate(),
        "the other responder's date stays");
    // A new plan shows it: the key is Compromised and replaced, and the call creates nothing.
    CompromisePlan fresh = key.compromisePlan();
    assertEquals(List.of(theirs.id()), fresh.replacementIds());
    CompromiseResult r = key.replaceCompromisedResult(compromise(MINE), fresh);
    assertEquals(CompromiseResult.Outcome.EXISTING, r.outcome());
    assertFalse(r.revoked());
    assertEquals(Optional.of(THEIRS), r.compromiseOccurrenceDate());
  }

  /** The second race: another caller rotates the key while the plan waits. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRotationWhileThePlanWaitsIsRefused(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s), other = connect(s);
    KeyHandle key = aes(kms);
    CompromisePlan plan = key.compromisePlan();
    other.keys().handle(key.id()).rotate();
    StateConflictException e =
        assertThrows(
            StateConflictException.class,
            () -> key.replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(StateConflictException.Conflict.NOT_AS_PLANNED, e.conflict(), e.getMessage());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(key.id()), "not revoked");
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aPlanOfAnotherKeyOrADestroyedKeyIsRefused(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms);
    KeyHandle second = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).named("second").create();
    CompromisePlan plan = second.compromisePlan();
    assertThrows(
        IllegalArgumentException.class, () -> key.replaceCompromisedResult(compromise(MINE), plan));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            key.replaceCompromisedResult(
                RevocationReason.superseded("not a compromise"), key.compromisePlan()));
    assertThrows(
        IllegalArgumentException.class,
        () ->
            key.replaceCompromisedResult(
                compromise(MINE),
                Rotation.grace(java.time.Duration.ofDays(1)),
                key.compromisePlan()));
    second.revoke(RevocationReason.superseded("retired"));
    second.destroy();
    StateConflictException e = assertThrows(StateConflictException.class, second::compromisePlan);
    assertEquals(StateConflictException.Conflict.STATE, e.conflict());
    assertEquals(Optional.of(KeyState.DESTROYED), e.observedState());
    assertEquals(0, RotationGraceTest.sent(s, Operation.RE_KEY));
  }

  /**
   * The rule for compromise replacements: a failure while finishing a replacement another call made
   * lists it as found, not as created.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aFailureWhileFinishingAnExistingReplacementDoesNotClaimIt(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms);
    KeyHandle next = key.rotate();
    key.revoke(compromise(THEIRS));
    key.allowingCompromised().addName("extra");
    CompromisePlan plan = key.compromisePlan();
    s.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.PERMISSION_DENIED);
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> key.replaceCompromisedResult(compromise(MINE), plan));
    assertEquals(List.of(), e.created(), e.getMessage());
    assertEquals(List.of(next), e.found());
    assertTrue(e.recoveredFrom().isEmpty());
  }

  /**
   * A Replacement Object link to an object that does not name the key back proves nothing: the
   * plan refuses it (LINEAGE), before anything is changed, rather than show either a replacement
   * that is not one or a new one the call could not link.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aOneSidedReplacementLinkIsRefusedByThePlan(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms);
    KeyHandle stranger =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).named("stranger").create();
    Ttlv link =
        Ttlv.structure(
            Tag.LINK,
            Ttlv.enumeration(Tag.LINK_TYPE, Enums.LinkType.REPLACEMENT_OBJECT_LINK),
            Ttlv.text(Tag.LINKED_OBJECT_IDENTIFIER, stranger.id()));
    kms.protocol()
        .call(
            Requests.addAttribute()
                .uniqueIdentifier(key.id())
                .attribute(Attributes.attribute("Link", link))
                .build());
    StateConflictException e = assertThrows(StateConflictException.class, key::compromisePlan);
    assertEquals(StateConflictException.Conflict.LINEAGE, e.conflict(), e.getMessage());
    assertTrue(e.getMessage().contains(stranger.id()), e.getMessage());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(key.id()));
  }
}
