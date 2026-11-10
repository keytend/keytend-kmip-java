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
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link KeyPairCreation#findOrCreateResult()} says how it got its pair, as {@link
 * KeyCreation#findOrCreateResult()} does for a key, through the same races: a pair another caller
 * makes between this call's look and its Create Key Pair, and a Create Key Pair whose reply is lost.
 * Each race is made at a fixed request, so it is the same on every run.
 */
class FindOrCreatePairResultTest {
  static final String PRIVATE = "signer", PUBLIC = "signer-public";

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

  static KeyPairCreation pair(Kms kms) {
    return kms.keys()
        .createKeyPair(KeyPairSpec.ec(Curve.P_256))
        .named(PRIVATE, PUBLIC)
        .privateUsages(KeyUsage.SIGN)
        .publicUsages(KeyUsage.VERIFY);
  }

  /** {@code before} for a client: runs {@code race} at this client's first Create Key Pair only. */
  static Consumer<Ttlv> atFirstCreate(Runnable race) {
    AtomicBoolean first = new AtomicBoolean(true);
    return r -> {
      if (RotationAndNameChoiceTest.isOperation(r, Operation.CREATE_KEY_PAIR)
          && first.getAndSet(false)) race.run();
    };
  }

  static List<String> ids(KeyPairHandle p) {
    return List.of(p.privateKey().id(), p.publicKey().id());
  }

  static void assertActive(InMemoryKmipServer s, KeyPairHandle p) {
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(p.privateKey().id()));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(p.publicKey().id()));
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theOutcomeSaysHowThePairWasGot(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    FindOrCreatePairResult created = pair(kms).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.CREATED, created.outcome());
    assertEquals(List.of(created.pair()), created.created());
    assertActive(s, created.pair());
    assertTrue(
        created.toString().startsWith("FindOrCreatePairResult[CREATED, "), created.toString());

    FindOrCreatePairResult found = pair(kms).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.FOUND, found.outcome());
    assertEquals(created.pair(), found.pair());
    assertEquals(List.of(), found.created());
    assertEquals(created.pair(), pair(kms).findOrCreate());

    // A staged pair with the names: activated by this call, and said so.
    KeyPairHandle staged =
        kms.keys()
            .createKeyPair(KeyPairSpec.ec(Curve.P_256))
            .named("staged", "staged-public")
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .createPreActive();
    FindOrCreatePairResult activated =
        kms.keys()
            .createKeyPair(KeyPairSpec.ec(Curve.P_256))
            .named("staged", "staged-public")
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.ACTIVATED, activated.outcome());
    assertEquals(staged, activated.pair());
    assertEquals(List.of(), activated.created());
    assertActive(s, staged);
  }

  /**
   * Another caller makes a pair under the names between this call's look and its Create Key Pair,
   * on a server without unique names. That pair ranks first, so the result is it, FOUND, and
   * {@code created()} names the pair this call left behind, Pre-Active.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aPairLeftByALostRaceIsListed(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms other = connect(s);
    AtomicReference<KeyPairHandle> theirs = new AtomicReference<>();
    Kms kms = connect(s, atFirstCreate(() -> theirs.set(pair(other).create())));
    FindOrCreatePairResult r = pair(kms).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.FOUND, r.outcome(), r.toString());
    assertEquals(ids(theirs.get()), ids(r.pair()), "the other caller's pair");
    assertEquals(1, r.created().size());
    KeyPairHandle left = r.created().get(0);
    assertNotEquals(r.pair(), left);
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(left.privateKey().id()));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(left.publicKey().id()));
    assertActive(s, r.pair());
  }

  /**
   * The same race on a server with unique names: this call's Create Key Pair is refused, the
   * other pair is found, and this call created nothing.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRaceLostToAUniqueNameFindsTheOtherPair(KmipVersion version) {
    InMemoryKmipServer s = server(version).uniqueNames(true);
    Kms other = connect(s);
    AtomicReference<KeyPairHandle> theirs = new AtomicReference<>();
    Kms kms = connect(s, atFirstCreate(() -> theirs.set(pair(other).createPreActive())));
    FindOrCreatePairResult r = pair(kms).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.ACTIVATED, r.outcome(), r.toString());
    assertEquals(ids(theirs.get()), ids(r.pair()), "the other caller's pair");
    assertEquals(List.of(), r.created());
    assertActive(s, r.pair());
    assertEquals(2, s.ids().size(), "one pair: " + s.ids());
  }

  /** A Create Key Pair whose reply is lost, then found by the private name, is RECOVERED. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostCreateKeyPairReplyIsRecovered(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    s.failNext(ServerOperation.CREATE_KEY_PAIR, Fault.REPLY_LOST);
    FindOrCreatePairResult r = pair(kms).findOrCreateResult();
    assertEquals(FindOrCreateResult.Outcome.RECOVERED, r.outcome(), r.toString());
    assertEquals(List.of(), r.created());
    assertActive(s, r.pair());
    assertEquals(FindOrCreateResult.Outcome.FOUND, pair(kms).findOrCreateResult().outcome());
  }

  /** The refusals are those of {@code findOrCreate()}, and nothing is created. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theRefusalsAreThoseOfFindOrCreate(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            kms.keys()
                .createKeyPair(KeyPairSpec.ec(Curve.P_256))
                .privateUsages(KeyUsage.SIGN)
                .publicUsages(KeyUsage.VERIFY)
                .findOrCreateResult());
    KeyPairHandle old = pair(kms).create();
    old.privateKey().deactivate();
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> pair(kms).findOrCreateResult());
    assertEquals(Optional.of(old.privateKey().id()), e.objectId());
    assertEquals(2, s.ids().size(), "nothing created");
  }
}
