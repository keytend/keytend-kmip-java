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
import static dev.keytend.kmip.kms.RotationGraceTest.names;
import static dev.keytend.kmip.kms.RotationGraceTest.sent;
import static dev.keytend.kmip.kms.ScheduledRotationTest.NAME;
import static dev.keytend.kmip.kms.ScheduledRotationTest.aes;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Deactivation on every version: on the KMIP 3.0 draft a Revoke makes an object Compromised
 * whatever its reason (CSD02 §6.1.51), and the Deactivate operation deactivates it.
 */
class DeactivationTest {
  static final byte[] AAD = "record".getBytes(StandardCharsets.UTF_8);
  static final Instant START = RotationJobTest.START;

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  /** The request that retires a key without compromising it: a Revoke up to 2.1, a Deactivate on 3.0. */
  static ServerOperation retiring(KmipVersion version) {
    return version == KmipVersion.V3_0 ? ServerOperation.DEACTIVATE : ServerOperation.REVOKE;
  }

  /** {@link #retiring} as a protocol operation. */
  static Operation retiringOperation(KmipVersion version) {
    return version == KmipVersion.V3_0 ? Operation.DEACTIVATE : Operation.REVOKE;
  }

  InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    s.clock(new RotationJobTest.TestClock(START));
    servers.add(s);
    return s;
  }

  Kms connect(InMemoryKmipServer server, UnaryOperator<Ttlv> request) {
    Kms kms =
        Kms.connect(
            server.configure().transport(e -> r -> server.exchange(request.apply(r))).build());
    clients.add(kms);
    return kms;
  }

  Kms connect(InMemoryKmipServer server) {
    return connect(server, UnaryOperator.identity());
  }

  static byte[] utf8(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  /** The payloads of the requests {@code s} received for {@code operation}. */
  static List<Ttlv> payloads(InMemoryKmipServer s, Operation operation) {
    List<Ttlv> out = new ArrayList<>();
    for (Ttlv r : s.protocolRequests())
      for (Ttlv item : r.children(Tag.BATCH_ITEM))
        if (item.require(Tag.OPERATION).intValue() == operation.code())
          out.add(item.require(Tag.REQUEST_PAYLOAD));
    return out;
  }

  // ---- a version-aware deactivate, and revoke never compromises unasked ----

  /**
   * {@code KeyHandle.deactivate()} deactivates on every version, so applications need not
   * branch on it: a Revoke (Unspecified, or the reason given)
   * up to 2.1, the draft's Deactivate on 3.0, carrying only the identifier (keytend-kmip-server refuses a
   * Deactivation Reason, Feature Not Supported). The key still decrypts and opens, refuses to
   * seal (DEACTIVATED), and is not Compromised. A compromise reason is refused before anything is
   * sent; on 3.0 a Pre-Active key cannot be deactivated (the draft has no such transition).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void deactivateIsOneVerbOnEveryVersion(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    boolean draft = version == KmipVersion.V3_0;
    KeyHandle key = aes(kms).create();
    Ciphertext wrapped = key.encrypt(CipherSpec.keyWrap(), RotationGraceTest.WRAPPABLE);
    key.deactivate();
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(key.id()));
    assertArrayEquals(
        RotationGraceTest.WRAPPABLE,
        key.decrypt(wrapped, null),
        "a Deactivated key still decrypts");
    StateConflictException refused =
        assertThrows(
            StateConflictException.class,
            () -> key.encrypt(CipherSpec.keyWrap(), RotationGraceTest.WRAPPABLE));
    assertEquals(Optional.of(KeyState.DEACTIVATED), refused.observedState());
    if (draft) {
      assertEquals(0, sent(s, Operation.REVOKE), "no Revoke on 3.0: it compromises");
      Ttlv payload = payloads(s, Operation.DEACTIVATE).get(0);
      assertEquals(
          List.of(Tag.UNIQUE_IDENTIFIER.code()),
          payload.children().stream().map(Ttlv::tag).toList());
    } else {
      assertEquals(0, sent(s, Operation.DEACTIVATE));
      Ttlv payload = payloads(s, Operation.REVOKE).get(0);
      assertEquals(
          Enums.RevocationReasonCode.UNSPECIFIED.code(),
          payload.require(Tag.REVOCATION_REASON).require(Tag.REVOCATION_REASON_CODE).intValue());
      assertTrue(payload.child(Tag.COMPROMISE_OCCURRENCE_DATE).isEmpty());
    }

    // With a reason: recorded up to 2.1, not sent on 3.0.
    KeyHandle other =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("other")
            .create();
    other.deactivate(RevocationReason.superseded("retired"));
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(other.id()));
    if (!draft)
      assertEquals(
          Enums.RevocationReasonCode.SUPERSEDED.code(),
          payloads(s, Operation.REVOKE)
              .get(1)
              .require(Tag.REVOCATION_REASON)
              .require(Tag.REVOCATION_REASON_CODE)
              .intValue());
    else assertEquals(2, sent(s, Operation.DEACTIVATE));

    // A compromise is not a deactivation: refused before anything is sent.
    KeyHandle third =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("third")
            .create();
    int before = s.exchanges();
    IllegalArgumentException compromise =
        assertThrows(
            IllegalArgumentException.class,
            () -> third.deactivate(RevocationReason.keyCompromise("leak", START)));
    assertTrue(compromise.getMessage().contains("replaceCompromised"), compromise.getMessage());
    assertEquals(before, s.exchanges());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(third.id()));

    if (draft) {
      KeyHandle pending =
          kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
      StateConflictException preActive =
          assertThrows(StateConflictException.class, pending::deactivate);
      assertEquals(
          Optional.of(Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE), preActive.protocolReason());
      assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(pending.id()));
    }
    assertEquals(List.of(), s.violations());
  }

  /**
   * keytend-kmip-server answers a 3.0 Deactivate of a key that is not Active with
   * Permission Denied, which is not an access failure (FIX_ACCESS). A refused
   * deactivation that may be about the key's state is read back, as {@code activate()} does: on
   * 3.0 a Pre-Active key (saying the draft cannot deactivate one), and on every version one
   * Deactivated already, is STATE with {@code observedState()}; an Active key's refusal is the
   * server's access answer, unchanged. A Pre-Active key's refusal is STATE PRE_ACTIVE on every
   * version.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1", "V3_0"})
  void aRefusedDeactivationSaysTheKeysState(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle pending =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
    s.failNext(retiring(version), Fault.PERMISSION_DENIED);
    // On every version: KMIP has no transition from Pre-Active to Deactivated.
    StateConflictException preActive =
        assertThrows(StateConflictException.class, pending::deactivate);
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), preActive.observedState());
    assertTrue(
        preActive.getMessage().contains("no transition from Pre-Active to Deactivated"),
        preActive.getMessage());

    KeyHandle retired = aes(kms).create();
    retired.deactivate();
    s.failNext(retiring(version), Fault.PERMISSION_DENIED);
    StateConflictException again =
        assertThrows(
            StateConflictException.class,
            () -> retired.revoke(RevocationReason.superseded("again")));
    assertEquals(Optional.of(KeyState.DEACTIVATED), again.observedState());

    KeyHandle active =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named("a").create();
    s.failNext(retiring(version), Fault.PERMISSION_DENIED);
    assertThrows(PermissionDeniedException.class, active::deactivate);
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(active.id()));
    assertEquals(List.of(), s.violations());
  }

  /**
   * The high-level {@code revoke(reason)} with a reason that is not a
   * compromise deactivates on 3.0 too (a Deactivate), not a Revoke that a CSD02 server
   * makes Compromised; a compromise reason is still a Revoke, with its occurrence date, on every
   * version. A key pair's {@code revoke} follows. The low-level {@code Requests.revoke} keeps its
   * protocol meaning.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void revokeCompromisesOnlyForACompromise(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms).create();
    byte[] record = key.seal(utf8("r"), AAD);
    key.revoke(RevocationReason.superseded("retired"));
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(key.id()));
    assertArrayEquals(
        utf8("r"),
        kms.keys().handle(key.id()).open(record, AAD),
        "opens without allowingCompromised()");
    for (RevocationReason other :
        List.of(
            RevocationReason.cessationOfOperation("c"), RevocationReason.affiliationChanged("a"),
            RevocationReason.privilegeWithdrawn("p"), RevocationReason.unspecified())) {
      KeyHandle k =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named("o-" + other.kind())
              .create();
      k.revoke(other);
      assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(k.id()), other.toString());
    }
    assertEquals(version == KmipVersion.V3_0 ? 0 : 5, sent(s, Operation.REVOKE));
    assertEquals(version == KmipVersion.V3_0 ? 5 : 0, sent(s, Operation.DEACTIVATE));

    KeyHandle leaked =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("leaked")
            .create();
    leaked.revoke(RevocationReason.keyCompromise("leak", START.minusSeconds(60)));
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(leaked.id()));
    Ttlv revoke = payloads(s, Operation.REVOKE).get(version == KmipVersion.V3_0 ? 0 : 5);
    assertEquals(
        START.minusSeconds(60), revoke.require(Tag.COMPROMISE_OCCURRENCE_DATE).instantValue());

    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .create();
    byte[] signature = pair.privateKey().sign(SignatureSpec.rsaPkcs1(Hash.SHA_256), utf8("m"));
    pair.revoke(RevocationReason.superseded("rotated"));
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(pair.privateKey().id()));
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(pair.publicKey().id()));
    assertEquals(
        VerifyResult.VALID,
        pair.publicKey().verify(SignatureSpec.rsaPkcs1(Hash.SHA_256), utf8("m"), signature));
    assertEquals(List.of(), s.violations());
  }

  // ---- every high-level retirement deactivates on 3.0 ----

  /**
   * {@code deactivatePredecessors}, {@code reconcile} (a linear
   * lineage and a fork), {@code retirePredecessors} and the secret replacement retire with a
   * Deactivate on 3.0 and send no Revoke: the old keys are Deactivated, not Compromised, every record
   * opens through the current key, {@code findByName}, a {@code KeyQuery} and the old keys' own
   * handles without {@code allowingCompromised()}, and retirement ends in DESTROYED, not DESTROYED
   * COMPROMISED. Up to 2.1 the same calls send Revoke and no Deactivate.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void retiringKeysNeverCompromisesThem(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    Operation compromising = version == KmipVersion.V3_0 ? Operation.REVOKE : Operation.DEACTIVATE;

    // deactivatePredecessors, then retirePredecessors.
    KeyHandle k0 = aes(kms).create();
    byte[] r0 = k0.seal(utf8("r0"), AAD);
    KeyHandle k1 = k0.rotate();
    byte[] r1 = k1.seal(utf8("r1"), AAD);
    KeyHandle k2 = k1.rotate();
    assertEquals(List.of(k0.id(), k1.id()), ids(k2.deactivatePredecessors()));
    for (KeyHandle k : List.of(k0, k1))
      assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(k.id()));
    KeyHandle byName = kms.keys().findByName(NAME).orElseThrow();
    for (KeyHandle through :
        List.of(k2, byName, kms.keys().handle(k0.id()), kms.keys().handle(k1.id()))) {
      assertArrayEquals(utf8("r0"), through.open(r0, AAD));
      assertArrayEquals(utf8("r1"), through.open(r1, AAD));
    }
    assertArrayEquals(utf8("r0"), kms.keys().open(KeyQuery.byName(NAME), r0, AAD));
    byte[] moved0 = k2.rewrapRecord(r0, AAD).bytes(), moved1 = k2.rewrapRecord(r1, AAD).bytes();
    assertEquals(
        List.of(k0.id(), k1.id()),
        ids(k2.retirePredecessors(RevocationReason.superseded("retired"))));
    for (KeyHandle k : List.of(k0, k1))
      assertEquals(Optional.of(KeyState.DESTROYED), s.state(k.id()));
    assertArrayEquals(utf8("r0"), k2.open(moved0, AAD));
    assertArrayEquals(utf8("r1"), k2.open(moved1, AAD));

    // retirePredecessors straight from Active keys.
    KeyHandle j0 =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named("j").create();
    KeyHandle j2 = j0.rotate().rotate();
    List<KeyHandle> gone = j2.retirePredecessors(RevocationReason.superseded("retired"));
    assertEquals(2, gone.size());
    for (KeyHandle k : gone) assertEquals(Optional.of(KeyState.DESTROYED), s.state(k.id()));

    // reconcile: a linear lineage, from its oldest key.
    KeyHandle m0 =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named("m").create();
    byte[] rm = m0.seal(utf8("m0"), AAD);
    KeyHandle m1 = m0.rotate();
    KeyHandle m2 = m1.rotate();
    // A cached handle on m0 that another instance re-keyed: reconcile switches the older keys off.
    assertEquals(m2, m0.reconcile());
    for (KeyHandle k : List.of(m0, m1))
      assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(k.id()));
    assertArrayEquals(utf8("m0"), kms.keys().findByName("m").orElseThrow().open(rm, AAD));
    assertArrayEquals(utf8("m0"), kms.keys().handle(m0.id()).open(rm, AAD));

    // reconcile: a fork the server made.
    KeyHandle f0 =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named("f").create();
    byte[] rf = f0.seal(utf8("f0"), AAD);
    String a = RotationAndNameChoiceTest.reKey(kms, f0.id());
    String b = RotationAndNameChoiceTest.reKey(kms, f0.id());
    byte[] ra = kms.keys().handle(a).seal(utf8("fa"), AAD),
        rb = kms.keys().handle(b).seal(utf8("fb"), AAD);
    KeyHandle winner = f0.reconcile();
    String loser = winner.id().equals(a) ? b : a;
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(f0.id()));
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(loser));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(winner.id()));
    KeyHandle current = kms.keys().findByName("f").orElseThrow();
    for (byte[] r : List.of(rf, ra, rb)) {
      assertNotNull(current.open(r, AAD));
      assertNotNull(kms.keys().open(KeyQuery.byName("f"), r, AAD));
    }

    // The secret replacement.
    KeyHandle secret = kms.keys().registerSecret("hunter2".toCharArray()).named("db").register();
    KeyHandle next =
        kms.keys().registerSecret("correct horse".toCharArray()).named("db").replace(secret);
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(secret.id()));
    assertEquals(Optional.of(next), kms.keys().findByName("db"));

    assertEquals(0, sent(s, compromising), "nothing compromised a key: " + compromising);
    for (String id : s.ids()) {
      assertNotEquals(Optional.of(KeyState.COMPROMISED), s.state(id), id);
      assertNotEquals(Optional.of(KeyState.DESTROYED_COMPROMISED), s.state(id), id);
    }
    assertEquals(List.of(), s.violations());
  }

  /**
   * A retirement whose reply is lost is read back and settled only by a Deactivated key, not
   * by any key that is not Active: a key another caller compromised meanwhile is not this call's
   * deactivation. In {@code deactivatePredecessors} the call reports the unknown outcome (it does
   * not count the key as deactivated) and a repeat passes the key over; in
   * {@code reconcile} it is a {@code PartialCompletionException} whose repeat finishes. A lost reply
   * of a Deactivate that took effect still counts.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostRetirementIsSettledOnlyByADeactivatedKey(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms other = connect(s);
    AtomicReference<String> compromiseFirst = new AtomicReference<>();
    Kms kms =
        connect(
            s,
            r -> {
              String id = compromiseFirst.get();
              if (id != null
                  && RotationAndNameChoiceTest.isOperation(r, retiringOperation(version))
                  && names(r, id)) {
                compromiseFirst.set(null);
                // Another caller finds the key compromised just before this call's request reaches
                // it.
                other.keys().handle(id).revoke(RevocationReason.keyCompromise("leak", START));
                s.failNext(retiring(version), Fault.REPLY_LOST);
              }
              return r;
            });
    KeyHandle k0 = aes(kms).create();
    KeyHandle k1 = k0.rotate();
    KeyHandle k2 = k1.rotate();
    compromiseFirst.set(k0.id());
    assertThrows(OutcomeUnknownException.class, k2::deactivatePredecessors);
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(k0.id()));
    assertEquals(
        List.of(k1.id()),
        ids(k2.deactivatePredecessors()),
        "the repeat passes the Compromised key over");

    // A lost reply of a request that took effect counts.
    KeyHandle j0 =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named("j").create();
    KeyHandle j1 = j0.rotate();
    s.failNext(retiring(version), Fault.REPLY_LOST);
    assertEquals(List.of(j0.id()), ids(j1.deactivatePredecessors()));
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(j0.id()));

    // reconcile.
    KeyHandle m0 =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named("m").create();
    KeyHandle m1 = m0.rotate();
    KeyHandle m2 = m1.rotate();
    compromiseFirst.set(m0.id());
    PartialCompletionException interrupted =
        assertThrows(PartialCompletionException.class, m2::reconcile);
    assertTrue(interrupted.getMessage().contains("repeat reconcile()"), interrupted.getMessage());
    assertEquals(m2, m2.reconcile());
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(m0.id()));
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(m1.id()));
    s.failNext(retiring(version), Fault.REPLY_LOST);
    KeyHandle n0 =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named("n").create();
    KeyHandle n1 = n0.rotate();
    assertEquals(n1, n0.reconcile(), "a lost reply of a Deactivate that took effect settles");
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(n0.id()));
    assertEquals(List.of(), s.violations());
  }

  /**
   * On 3.0, which has no transition from Pre-Active to Deactivated (CSD02 §4.67, transition 6;
   * keytend-kmip-server refuses a Deactivate of a Pre-Active key), {@code deactivatePredecessors} passes a
   * Pre-Active older key over and {@code retirePredecessors} destroys it without a Deactivate or a
   * Revoke (transition 2), so it ends DESTROYED. The same up to 2.1, which
   * has no such transition either (KMIP 1.4 §3.22, 2.1 §4.57): no Revoke is sent.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aPreActiveOlderKeyIsDestroyedOnTheDraft(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle k0 =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named(NAME)
            .createPreActive();
    KeyHandle k1 = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, k0.id()));
    k1.activate();
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(k0.id()));
    assertEquals(List.of(), ids(k1.deactivatePredecessors()));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(k0.id()));
    assertEquals(
        List.of(k0.id()), ids(k1.retirePredecessors(RevocationReason.superseded("retired"))));
    assertEquals(Optional.of(KeyState.DESTROYED), s.state(k0.id()));
    assertEquals(0, sent(s, Operation.REVOKE));
    assertEquals(0, sent(s, Operation.DEACTIVATE));
    assertEquals(List.of(), s.violations());
  }

  // ---- the fake follows the 3.0 Revoke and the 1.1/1.2 occurrence date ----

  static Optional<Instant> stored(InMemoryKmipServer s, String id, String attribute) {
    return Optional.ofNullable(s.protocolAttributes(id).get(attribute))
        .map(v -> v.get(0).instantValue());
  }

  /**
   * The in-memory server's Revoke follows the version, as keytend-kmip-server's does. On 3.0 every
   * Revoke makes the key Compromised: Superseded, Cessation of Operation, and none at all (an
   * omitted reason is Unspecified); the Compromise Occurrence Date the request omits is the key's
   * Initial Date (the SHOULD of CSD02 §6.1.51, from 1.3 on every version), one given is kept. Up to
   * 2.1 Superseded deactivates. On 1.2 a Key Compromise without a Compromise Occurrence Date is
   * Missing Data and changes nothing (1.2 Table 185). On 3.0 Deactivate deactivates, from Active
   * only (Wrong Key Lifecycle State otherwise), with the Deactivation Date the request gives.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_3", "V1_4", "V2_0", "V2_1", "V3_0"})
  void theFakeRevokesAsTheVersionSays(KmipVersion version) throws Exception {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version);
    s.clock(clock);
    Kms kms = connect(s);
    boolean draft = version == KmipVersion.V3_0;
    KeyHandle superseded = aes(kms).create();
    clock.now = START.plusSeconds(3600);
    kms.protocol()
        .call(
            dev.keytend.kmip.client.Requests.revoke(
                superseded.id(), Enums.RevocationReasonCode.SUPERSEDED, "low level"));
    assertEquals(
        Optional.of(draft ? KeyState.COMPROMISED : KeyState.DEACTIVATED), s.state(superseded.id()));
    assertEquals(
        draft ? stored(s, superseded.id(), "Initial Date") : Optional.empty(),
        stored(s, superseded.id(), "Compromise Occurrence Date"));

    // A Key Compromise without the date.
    KeyHandle leaked =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("leaked")
            .create();
    dev.keytend.kmip.client.Request noDate =
        dev.keytend.kmip.client.Requests.revoke(
            leaked.id(), Enums.RevocationReasonCode.KEY_COMPROMISE, null);
    if (version == KmipVersion.V1_2) {
      dev.keytend.kmip.client.KmipException missing =
          assertThrows(
              dev.keytend.kmip.client.KmipException.class, () -> kms.protocol().call(noDate));
      assertEquals(Optional.of(Enums.ResultReason.MISSING_DATA), missing.reason());
      assertEquals(Optional.of(KeyState.ACTIVE), s.state(leaked.id()));
      assertEquals(1, s.violations().size(), "a required field is missing");
      // With the date it is accepted.
      leaked.revoke(RevocationReason.keyCompromise("leak", START.plusSeconds(60)));
      assertEquals(
          Optional.of(START.plusSeconds(60)), stored(s, leaked.id(), "Compromise Occurrence Date"));
    } else {
      kms.protocol().call(noDate);
      assertEquals(
          stored(s, leaked.id(), "Initial Date"),
          stored(s, leaked.id(), "Compromise Occurrence Date"));
    }
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(leaked.id()));

    if (draft) {
      // No reason at all, and Cessation of Operation: Compromised.
      KeyHandle bare =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named("bare")
              .create();
      kms.protocol()
          .call(dev.keytend.kmip.client.Requests.revoke().uniqueIdentifier(bare.id()).build());
      assertEquals(Optional.of(KeyState.COMPROMISED), s.state(bare.id()));
      KeyHandle ceased =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named("ceased")
              .create();
      kms.protocol()
          .call(
              dev.keytend.kmip.client.Requests.revoke(
                  ceased.id(), Enums.RevocationReasonCode.CESSATION_OF_OPERATION, null));
      assertEquals(Optional.of(KeyState.COMPROMISED), s.state(ceased.id()));
      // A Deactivated key revoked is Compromised too (transition 8).
      KeyHandle retired =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named("retired")
              .create();
      retired.deactivate();
      kms.protocol()
          .call(
              dev.keytend.kmip.client.Requests.revoke(
                  retired.id(), Enums.RevocationReasonCode.SUPERSEDED, null));
      assertEquals(Optional.of(KeyState.COMPROMISED), s.state(retired.id()));

      // Deactivate: from Active only, with the request's date.
      KeyHandle dated =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named("dated")
              .create();
      kms.protocol()
          .call(
              dev.keytend.kmip.client.Requests.deactivate()
                  .uniqueIdentifier(dated.id())
                  .add(Ttlv.dateTime(Tag.DEACTIVATION_DATE, START.plusSeconds(1800)))
                  .build());
      assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(dated.id()));
      assertEquals(
          Optional.of(START.plusSeconds(1800)), stored(s, dated.id(), "Deactivation Date"));
      dev.keytend.kmip.client.KmipException again =
          assertThrows(
              dev.keytend.kmip.client.KmipException.class,
              () ->
                  kms.protocol()
                      .call(
                          dev.keytend.kmip.client.Requests.deactivate()
                              .uniqueIdentifier(dated.id())
                              .build()));
      assertEquals(Optional.of(Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE), again.reason());
      KeyHandle pending =
          kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
      assertThrows(
          dev.keytend.kmip.client.KmipException.class,
          () ->
              kms.protocol()
                  .call(
                      dev.keytend.kmip.client.Requests.deactivate()
                          .uniqueIdentifier(pending.id())
                          .build()));
      assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(pending.id()));
    }
    assertEquals(
        version == KmipVersion.V1_2 ? 1 : 0, s.violations().size(), s.violations().toString());
  }

  /**
   * Every compromise path of the SDK sends a Compromise Occurrence Date, so it works on the
   * 1.2 server that requires one for a Key Compromise (and on 1.1, whose rule is the same; the fake
   * speaks 1.2 and up): {@code revoke(keyCompromise)}, {@code replaceCompromised} (its Revoke, then
   * the replacement), a key pair's {@code revoke}, and a CA Compromise. The server finds no request
   * malformed.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V3_0"})
  void everyCompromiseSendsItsOccurrenceDate(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle k0 = aes(kms).create();
    KeyHandle replacement =
        k0.replaceCompromised(RevocationReason.keyCompromise("leak", START.minusSeconds(5)));
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(k0.id()));
    assertEquals(
        Optional.of(START.minusSeconds(5)), stored(s, k0.id(), "Compromise Occurrence Date"));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(replacement.id()));
    KeyHandle other =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named("o").create();
    other.revoke(RevocationReason.caCompromise("ca", START.minusSeconds(7)));
    assertEquals(
        Optional.of(START.minusSeconds(7)), stored(s, other.id(), "Compromise Occurrence Date"));
    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .create();
    pair.revoke(RevocationReason.keyCompromise("leak", START.minusSeconds(9)));
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(pair.privateKey().id()));
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(pair.publicKey().id()));
    for (Ttlv revoke : payloads(s, Operation.REVOKE))
      assertTrue(revoke.child(Tag.COMPROMISE_OCCURRENCE_DATE).isPresent(), revoke.toString());
    assertEquals(4, payloads(s, Operation.REVOKE).size());
    assertEquals(List.of(), s.violations());
  }

  // ---- lineages an older client left Compromised on 3.0 ----

  /**
   * What a client that retires with a Revoke as superseded leaves on a 3.0 CSD02 server (from
   * reconcile and the secret replacement): a lineage whose older keys the Revoke made Compromised.
   * The SDK does not take the lineage for broken: {@code findByName}, {@code latest()} from every key, a {@code CurrentKey},
   * {@code findOrCreate} (also {@code replacingCompromised()}) and {@code reconcile} return the
   * current key, Active, and make nothing; {@code replaceCompromised} from such a key returns the
   * current key. Records under the Compromised keys open only through {@code allowingCompromised()}
   * (STATE, COMPROMISED, naming the key); the guide's recovery loop ("After a restart":
   * {@code compromisedPredecessors()}, then {@code rewrapTo(current)}) moves them, after which
   * everything opens through every normal path, and {@code retirePredecessors} destroys the old
   * keys without a Revoke (DESTROYED_COMPROMISED: KMIP has no way back from Compromised). Nothing
   * in it un-compromises a key.
   */
  @org.junit.jupiter.api.Test
  void aLineageRevokedAsSupersededOnTheDraftRecovers() throws Exception {
    InMemoryKmipServer s = server(KmipVersion.V3_0);
    Kms kms = connect(s);
    KeyHandle k0 = aes(kms).create();
    byte[] r0 = k0.seal(utf8("r0"), AAD);
    KeyHandle k1 = k0.rotate();
    byte[] r1 = k1.seal(utf8("r1"), AAD);
    KeyHandle k2 = k1.rotate();
    byte[] r2 = k2.seal(utf8("r2"), AAD);
    // Such a client's reconcile(): a Revoke as superseded of each older key, which the draft
    // compromises.
    for (KeyHandle k : List.of(k0, k1))
      kms.protocol()
          .call(
              dev.keytend.kmip.client.Requests.revoke(
                  k.id(), Enums.RevocationReasonCode.SUPERSEDED, "reconciled into " + k2.id()));
    for (KeyHandle k : List.of(k0, k1))
      assertEquals(Optional.of(KeyState.COMPROMISED), s.state(k.id()));
    int keys = s.ids().size();

    assertEquals(Optional.of(k2), kms.keys().findByName(NAME));
    for (KeyHandle k : List.of(k0, k1, k2))
      assertEquals(k2, kms.keys().handle(k.id()).latest(), k.id());
    CurrentKey current = kms.keys().current(NAME);
    assertEquals(k2, current.handle());
    assertArrayEquals(utf8("n"), current.open(current.seal(utf8("n"), AAD), AAD));
    assertEquals(k2, aes(kms).findOrCreate());
    assertEquals(k2, aes(kms).replacingCompromised().findOrCreate());
    assertEquals(k2, k2.reconcile());
    assertEquals(k2, kms.keys().handle(k0.id()).reconcile());
    assertEquals(
        k2,
        kms.keys()
            .handle(k0.id())
            .replaceCompromised(RevocationReason.keyCompromise("by mistake", START)));
    assertEquals(List.of(), k2.deactivatePredecessors());
    assertEquals(keys, s.ids().size(), "nothing was created");
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(k2.id()));

    // Records under the Compromised keys: refused through every normal path, naming the key.
    for (KeyHandle through :
        List.of(k2, kms.keys().findByName(NAME).orElseThrow(), kms.keys().handle(k0.id()))) {
      StateConflictException refused =
          assertThrows(StateConflictException.class, () -> through.open(r0, AAD));
      assertEquals(Optional.of(KeyState.COMPROMISED), refused.observedState());
      assertTrue(
          refused.getMessage().contains(k0.id())
              && refused.getMessage().contains("allowingCompromised"),
          refused.getMessage());
    }
    assertThrows(StateConflictException.class, () -> current.open(r1, AAD));
    assertArrayEquals(utf8("r0"), kms.keys().handle(k0.id()).allowingCompromised().open(r0, AAD));
    assertArrayEquals(utf8("r2"), k2.open(r2, AAD));

    // The guide's recovery loop ("A compromised key", "After a restart").
    assertEquals(List.of(k1.id(), k0.id()), ids(k2.compromisedPredecessors()));
    Map<String, KeyHandle> compromised = new HashMap<>();
    for (KeyHandle k : k2.compromisedPredecessors()) compromised.put(k.id(), k);
    List<byte[]> moved = new ArrayList<>();
    for (byte[] r : List.of(r0, r1, r2)) {
      KeyHandle from = compromised.getOrDefault(KmsKeys.sealedKeyId(r), k2);
      moved.add(from.rewrapTo(k2, r, AAD));
    }
    for (byte[] r : moved) {
      assertEquals(k2.id(), KmsKeys.sealedKeyId(r));
      assertNotNull(current.open(r, AAD));
      assertNotNull(kms.keys().open(KeyQuery.byName(NAME), r, AAD));
      assertNotNull(kms.keys().handle(k0.id()).latest().open(r, AAD));
    }
    int revokes = sent(s, Operation.REVOKE);
    assertEquals(
        List.of(k0.id(), k1.id()),
        ids(k2.retirePredecessors(RevocationReason.superseded("retired"))));
    assertEquals(revokes, sent(s, Operation.REVOKE));
    assertEquals(0, sent(s, Operation.DEACTIVATE));
    for (KeyHandle k : List.of(k0, k1))
      assertEquals(Optional.of(KeyState.DESTROYED_COMPROMISED), s.state(k.id()));
    assertEquals(Optional.of(k2), kms.keys().findByName(NAME));

    // Such a client's secret replacement: the old secret Compromised, the new one found by name.
    KeyHandle old = kms.keys().registerSecret("hunter2".toCharArray()).named("db").register();
    KeyHandle next =
        kms.keys().registerSecret("correct horse".toCharArray()).named("db").replace(old);
    kms.protocol()
        .call(
            dev.keytend.kmip.client.Requests.revoke(
                old.id(), Enums.RevocationReasonCode.SUPERSEDED, "older client"));
    assertEquals(Optional.of(next), kms.keys().findByName("db"));

    // The guide's loop meets a record under a key outside the lineage, which anyone may revoke as
    // compromised: rewrapTo refuses it with one of the two exceptions the loop quarantines on.
    KeyHandle stranger =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    byte[] forged = stranger.seal(utf8("forged"), AAD);
    stranger.revoke(RevocationReason.keyCompromise("a stranger's key", START));
    KeyHandle from = compromised.getOrDefault(KmsKeys.sealedKeyId(forged), k2);
    RuntimeException refused =
        assertThrows(RuntimeException.class, () -> from.rewrapTo(k2, forged, AAD));
    assertTrue(
        refused instanceof StateConflictException || refused instanceof KeyMismatchException,
        refused.toString());
    assertEquals(List.of(), s.violations());
  }
}
