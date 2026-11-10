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

import static dev.keytend.kmip.kms.DeactivationTest.payloads;
import static dev.keytend.kmip.kms.DeactivationTest.retiring;
import static dev.keytend.kmip.kms.RotationGraceTest.ids;
import static dev.keytend.kmip.kms.RotationGraceTest.sent;
import static dev.keytend.kmip.kms.ScheduledRotationTest.NAME;
import static dev.keytend.kmip.kms.ScheduledRotationTest.aes;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Compromise races and key states: CBC ciphertexts opened by query, key pairs deactivated on every
 * version, two callers compromising one key at once, Pre-Active keys refused as STATE, the guide's
 * Lease Time snippet and the testing package's tier.
 */
class CompromiseRaceTest {
  static final Instant START = RotationJobTest.START;
  static final byte[] PLAIN = "a record of 32 bytes, CBC-sized.".getBytes(StandardCharsets.UTF_8);

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    s.clock(new RotationJobTest.TestClock(START));
    servers.add(s);
    return s;
  }

  Kms connect(InMemoryKmipServer server) {
    return connect(server, null, Exchange.NONE);
  }

  /** Runs around each exchange of one client: before the request is sent, and after its reply. */
  interface Exchange {
    Exchange NONE = new Exchange() {};

    default void before(Ttlv request) throws Exception {}

    default void after(Ttlv request) throws Exception {}
  }

  Kms connect(InMemoryKmipServer server, KmsListener listener, Exchange around) {
    KmsConfig.Builder b =
        server
            .configure()
            .transport(
                e ->
                    r -> {
                      try {
                        around.before(r);
                        Ttlv reply = server.exchange(r);
                        around.after(r);
                        return reply;
                      } catch (RuntimeException | java.io.IOException x) {
                        throw x;
                      } catch (Exception x) {
                        throw new IllegalStateException(x);
                      }
                    });
    if (listener != null) b.addListener(listener);
    Kms kms = Kms.connect(b.build());
    clients.add(kms);
    return kms;
  }

  static boolean revoking(Ttlv request) {
    return RotationAndNameChoiceTest.isOperation(request, Operation.REVOKE);
  }

  static String reason(InMemoryKmipServer s, String id) {
    return s.protocolAttributes(id)
        .get("Revocation Reason")
        .get(0)
        .require(Tag.REVOCATION_MESSAGE)
        .textValue();
  }

  // ---- decrypt(KeyQuery, CipherSpec, Ciphertext, aad) ----

  /**
   * Below KMIP 1.4 a server encrypts with AES-CBC, AES-CTR
   * or AES key wrap, and a stored ciphertext may not choose CBC or CTR, and {@code KmsKeys.decrypt(KeyQuery, Ciphertext, aad)} had no
   * spec: a CBC ciphertext under a Deactivated key opened through every handle but not through a
   * {@code KeyQuery}. The new overload names the spec: it opens through the query after a rotation
   * and a deactivation, refuses another spec, additional data CBC cannot take and RSA-OAEP before
   * anything is sent, and keeps the query's key rules (a stranger's key is BAD_DATA).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_3", "V1_4", "V2_1"})
  void aCbcCiphertextOpensThroughAQueryWithItsSpec(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle k0 = aes(kms).create();
    Ciphertext stored = Ciphertext.fromBytes(k0.encrypt(CipherSpec.cbc(), PLAIN).toBytes());
    KeyHandle k1 = k0.rotate();
    assertEquals(List.of(k0.id()), ids(k1.deactivatePredecessors()));
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(k0.id()));

    CryptographicFailureException chosen =
        assertThrows(
            CryptographicFailureException.class,
            () -> kms.keys().decrypt(KeyQuery.byName(NAME), stored, null));
    assertEquals(CryptographicFailureException.Kind.INVALID_CIPHERTEXT, chosen.kind());
    assertTrue(
        chosen.getMessage().contains("decrypt it with the expected CipherSpec"),
        chosen.getMessage());
    assertArrayEquals(
        PLAIN, kms.keys().decrypt(KeyQuery.byName(NAME), CipherSpec.cbc(), stored, null));

    int before = s.exchanges();
    CryptographicFailureException other =
        assertThrows(
            CryptographicFailureException.class,
            () -> kms.keys().decrypt(KeyQuery.byName(NAME), CipherSpec.ctr(), stored, null));
    assertEquals(CryptographicFailureException.Kind.INVALID_CIPHERTEXT, other.kind());
    assertThrows(
        IllegalArgumentException.class,
        () -> kms.keys().decrypt(KeyQuery.byName(NAME), CipherSpec.cbc(), stored, new byte[] {1}));
    IllegalArgumentException oaep =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                kms.keys()
                    .decrypt(
                        KeyQuery.byName(NAME), CipherSpec.rsaOaep(Hash.SHA_256), stored, null));
    assertTrue(oaep.getMessage().contains("private key"), oaep.getMessage());
    assertThrows(
        IllegalArgumentException.class,
        () -> kms.keys().decrypt(KeyQuery.all(), CipherSpec.cbc(), stored, null));
    assertEquals(before, s.exchanges(), "nothing sent for a refused argument");

    // A stranger's key: the query's rules, not the spec, decide.
    KeyHandle stranger =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    Ciphertext foreign = stranger.encrypt(CipherSpec.cbc(), PLAIN);
    KeyMismatchException mismatch =
        assertThrows(
            KeyMismatchException.class,
            () -> kms.keys().decrypt(KeyQuery.byName(NAME), CipherSpec.cbc(), foreign, null));
    assertEquals(KmsException.Category.BAD_DATA, mismatch.category());
    assertEquals(List.of(), s.violations());
  }

  // ---- KeyPairHandle.deactivate ----

  /**
   * {@code KeyPairHandle.deactivate()} and {@code
   * deactivate(reason)}, the guide's one verb for retiring, as {@code KeyHandle.deactivate}: the
   * private key first, a Revoke up to 2.1 and a Deactivate on 3.0, never a compromise; a compromise
   * reason is refused before anything is sent; the pair still verifies and no longer signs.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void aPairIsDeactivatedOnEveryVersion(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    boolean draft = version == KmipVersion.V3_0;
    KeyPairHandle pair = KeyPairsAndSecretsTest.signer(kms).create();
    SignatureSpec spec = SignatureSpec.ecdsa(Hash.SHA_256);
    byte[] signature = pair.privateKey().sign(spec, PLAIN);

    int before = s.exchanges();
    IllegalArgumentException compromise =
        assertThrows(
            IllegalArgumentException.class,
            () -> pair.deactivate(RevocationReason.keyCompromise("leak", START)));
    assertTrue(compromise.getMessage().contains("revoke(reason)"), compromise.getMessage());
    assertEquals(before, s.exchanges());

    pair.deactivate();
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(pair.privateKey().id()));
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(pair.publicKey().id()));
    List<Ttlv> requests = payloads(s, draft ? Operation.DEACTIVATE : Operation.REVOKE);
    assertEquals(2, requests.size());
    assertEquals(
        pair.privateKey().id(), requests.get(0).require(Tag.UNIQUE_IDENTIFIER).textValue());
    assertEquals(pair.publicKey().id(), requests.get(1).require(Tag.UNIQUE_IDENTIFIER).textValue());
    assertEquals(0, sent(s, draft ? Operation.REVOKE : Operation.DEACTIVATE));
    if (!draft)
      assertEquals(
          Enums.RevocationReasonCode.UNSPECIFIED.code(),
          requests
              .get(0)
              .require(Tag.REVOCATION_REASON)
              .require(Tag.REVOCATION_REASON_CODE)
              .intValue());
    assertEquals(
        VerifyResult.VALID,
        pair.publicKey().verify(spec, PLAIN, signature),
        "a Deactivated pair verifies");
    StateConflictException refused =
        assertThrows(StateConflictException.class, () -> pair.privateKey().sign(spec, PLAIN));
    assertEquals(Optional.of(KeyState.DEACTIVATED), refused.observedState());

    // With a reason, recorded up to 2.1; a second deactivation is read back as STATE (Deactivated).
    KeyPairHandle other =
        kms.keys()
            .createKeyPair(KeyPairSpec.ec(Curve.P_256))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .create();
    other.deactivate(RevocationReason.superseded("retired"));
    if (!draft)
      assertEquals(
          Enums.RevocationReasonCode.SUPERSEDED.code(),
          payloads(s, Operation.REVOKE)
              .get(2)
              .require(Tag.REVOCATION_REASON)
              .require(Tag.REVOCATION_REASON_CODE)
              .intValue());
    StateConflictException again = assertThrows(StateConflictException.class, other::deactivate);
    assertEquals(Optional.of(KeyState.DEACTIVATED), again.observedState());
    assertEquals(List.of(), s.violations());
  }

  // ---- a concurrent replaceCompromised whose Revoke is refused ----

  /**
   * Two callers compromise one key, the first order: both callers read the key Active; the
   * first then compromises it and replaces it entirely before the second's Revoke reaches the
   * server, which refuses that Revoke (Permission Denied on 1.x, Wrong Key Lifecycle State from 2.0,
   * as keytend-kmip-server). The second call does not end with that refusal: it reads the key back, finds it
   * Compromised, sends no second Revoke and finishes with the first caller's replacement, telling
   * {@code concurrentReplacement}; the first compromise's reason and dates stay.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aSecondReplacementWhoseRevokeIsRefusedJoinsTheFirst(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms first = connect(s);
    KeyHandle k0 = aes(first).create();
    Instant firstAt = START.minusSeconds(3600), secondAt = START.minusSeconds(60);
    KeyHandle[] firstResult = new KeyHandle[1];
    List<List<String>> told = new CopyOnWriteArrayList<>();
    boolean[] fired = new boolean[1];
    Kms second =
        connect(
            s,
            new KmsListener() {
              @Override
              public void concurrentReplacement(String keyId, List<String> replacements) {
                told.add(List.of(keyId, String.join(",", replacements)));
              }
            },
            new Exchange() {
              @Override
              public void before(Ttlv request) {
                if (!revoking(request) || fired[0]) return;
                fired[0] = true;
                // The second caller has read the key Active; the first replaces it now.
                firstResult[0] =
                    first
                        .keys()
                        .handle(k0.id())
                        .replaceCompromised(RevocationReason.keyCompromise("first", firstAt));
              }
            });
    KeyHandle secondResult =
        second
            .keys()
            .handle(k0.id())
            .replaceCompromised(RevocationReason.keyCompromise("second", secondAt));

    assertTrue(fired[0]);
    assertEquals(firstResult[0].id(), secondResult.id(), "one replacement");
    assertEquals(2, s.ids().size(), "no second replacement: " + s.ids());
    assertEquals(List.of(List.of(k0.id(), secondResult.id())), told);
    assertEquals(
        2,
        sent(s, Operation.REVOKE),
        "the second caller sent one Revoke, which was refused, and no other");
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(k0.id()));
    assertEquals("first", reason(s, k0.id()));
    assertEquals(
        Optional.of(firstAt), DeactivationTest.stored(s, k0.id(), "Compromise Occurrence Date"));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(secondResult.id()));
    assertEquals(secondResult.id(), first.keys().findByName(NAME).orElseThrow().id());
    assertEquals(List.of(), s.violations());
  }

  /**
   * The other order: both callers read the key Active and stop before their Revoke; the
   * first's Revoke is done, then the second runs to the end (its Revoke refused, read back, and it
   * makes the replacement), then the first goes on, and finishes with the second's replacement.
   * Held by latches, so the order is the same on every run.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRefusedRevokeBetweenTheOthersStepsMakesOneReplacement(KmipVersion version)
      throws Exception {
    InMemoryKmipServer s = server(version);
    KeyHandle k0 = aes(connect(s)).create();
    CountDownLatch secondAtRevoke = new CountDownLatch(1),
        firstRevoked = new CountDownLatch(1),
        secondDone = new CountDownLatch(1);
    boolean[] firstHeld = new boolean[1], secondHeld = new boolean[1];
    Kms first =
        connect(
            s,
            null,
            new Exchange() {
              @Override
              public void before(Ttlv request) throws Exception {
                if (revoking(request) && !firstHeld[0])
                  assertTrue(secondAtRevoke.await(10, TimeUnit.SECONDS));
              }

              @Override
              public void after(Ttlv request) throws Exception {
                if (!revoking(request) || firstHeld[0]) return;
                firstHeld[0] = true;
                firstRevoked.countDown();
                assertTrue(secondDone.await(10, TimeUnit.SECONDS));
              }
            });
    Kms second =
        connect(
            s,
            null,
            new Exchange() {
              @Override
              public void before(Ttlv request) throws Exception {
                if (!revoking(request) || secondHeld[0]) return;
                secondHeld[0] = true;
                secondAtRevoke.countDown();
                assertTrue(firstRevoked.await(10, TimeUnit.SECONDS));
              }
            });
    Instant firstAt = START.minusSeconds(3600);
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      Future<KeyHandle> a =
          pool.submit(
              () ->
                  first
                      .keys()
                      .handle(k0.id())
                      .replaceCompromised(RevocationReason.keyCompromise("first", firstAt)));
      Future<KeyHandle> b =
          pool.submit(
              () ->
                  second
                      .keys()
                      .handle(k0.id())
                      .replaceCompromised(RevocationReason.keyCompromise("second", START)));
      KeyHandle secondResult = b.get(20, TimeUnit.SECONDS);
      secondDone.countDown();
      KeyHandle firstResult = a.get(20, TimeUnit.SECONDS);
      assertEquals(secondResult.id(), firstResult.id(), "one replacement");
    } finally {
      secondDone.countDown();
      pool.shutdownNow();
    }
    assertEquals(2, s.ids().size(), "no second replacement: " + s.ids());
    assertEquals(2, sent(s, Operation.REVOKE));
    assertEquals("first", reason(s, k0.id()));
    assertEquals(
        Optional.of(firstAt), DeactivationTest.stored(s, k0.id(), "Compromise Occurrence Date"));
    assertEquals(List.of(), s.violations());
  }

  /**
   * The key was rotated routinely before (still Active,
   * a grace period), and an operator compromises it between this call's read and its Revoke. The
   * call finishes with the routine successor, as it would without the race, and tells {@code
   * concurrentReplacement} nothing: that successor was linked before this call read the key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRoutineSuccessorIsNotReportedAsConcurrent(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms operator = connect(s);
    KeyHandle k0 = aes(operator).create();
    KeyHandle k1 = k0.rotate();
    List<List<String>> told = new CopyOnWriteArrayList<>();
    boolean[] fired = new boolean[1];
    Kms app =
        connect(
            s,
            new KmsListener() {
              @Override
              public void concurrentReplacement(String keyId, List<String> replacements) {
                told.add(List.of(keyId, String.join(",", replacements)));
              }
            },
            new Exchange() {
              @Override
              public void before(Ttlv request) {
                if (!revoking(request) || fired[0]) return;
                fired[0] = true;
                operator
                    .keys()
                    .handle(k0.id())
                    .revoke(RevocationReason.keyCompromise("operator", START));
              }
            });
    KeyHandle got =
        app.keys().handle(k0.id()).replaceCompromised(RevocationReason.keyCompromise("app", START));
    assertTrue(fired[0]);
    assertEquals(k1.id(), got.id());
    assertEquals(List.of(), told);
    assertEquals("operator", reason(s, k0.id()));
  }

  /**
   * Documented rather than prevented: when the first
   * caller has revoked the key but not yet replaced it, the second finds no replacement after its
   * refused Revoke and makes its own, so the lineage forks, as for two callers that replace a key
   * Compromised already (a single-actor job). Both calls succeed, both callers are told of both
   * replacements, nothing is lost, and {@code reconcile} joins them.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aRefusedRevokeBeforeTheOthersReKeyForksAndReconciles(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms admin = connect(s);
    KeyHandle k0 = aes(admin).create();
    CountDownLatch secondAtRevoke = new CountDownLatch(1), firstRevoked = new CountDownLatch(1);
    CountDownLatch secondAtReKey = new CountDownLatch(1), firstAtReKey = new CountDownLatch(1);
    boolean[] firstHeld = new boolean[2], secondHeld = new boolean[2];
    List<List<String>> told = new CopyOnWriteArrayList<>();
    KmsListener listener =
        new KmsListener() {
          @Override
          public void concurrentReplacement(String keyId, List<String> replacements) {
            told.add(List.of(keyId, String.join(",", replacements)));
          }
        };
    Kms first =
        connect(
            s,
            listener,
            new Exchange() {
              @Override
              public void before(Ttlv request) throws Exception {
                if (revoking(request) && !firstHeld[0]) {
                  firstHeld[0] = true;
                  assertTrue(secondAtRevoke.await(10, TimeUnit.SECONDS));
                }
                if (RotationAndNameChoiceTest.isOperation(request, Operation.RE_KEY)
                    && !firstHeld[1]) {
                  firstHeld[1] = true;
                  firstAtReKey.countDown();
                  assertTrue(secondAtReKey.await(10, TimeUnit.SECONDS));
                }
              }

              @Override
              public void after(Ttlv request) {
                if (revoking(request)) firstRevoked.countDown();
              }
            });
    Kms second =
        connect(
            s,
            listener,
            new Exchange() {
              @Override
              public void before(Ttlv request) throws Exception {
                if (revoking(request) && !secondHeld[0]) {
                  secondHeld[0] = true;
                  secondAtRevoke.countDown();
                  assertTrue(firstRevoked.await(10, TimeUnit.SECONDS));
                }
                if (RotationAndNameChoiceTest.isOperation(request, Operation.RE_KEY)
                    && !secondHeld[1]) {
                  secondHeld[1] = true;
                  secondAtReKey.countDown();
                  assertTrue(firstAtReKey.await(10, TimeUnit.SECONDS));
                }
              }
            });
    ExecutorService pool = Executors.newFixedThreadPool(2);
    KeyHandle a, b;
    try {
      Future<KeyHandle> fa =
          pool.submit(
              () ->
                  first
                      .keys()
                      .handle(k0.id())
                      .replaceCompromised(RevocationReason.keyCompromise("first", START)));
      Future<KeyHandle> fb =
          pool.submit(
              () ->
                  second
                      .keys()
                      .handle(k0.id())
                      .replaceCompromised(RevocationReason.keyCompromise("second", START)));
      a = fa.get(20, TimeUnit.SECONDS);
      b = fb.get(20, TimeUnit.SECONDS);
    } finally {
      pool.shutdownNow();
    }
    assertNotEquals(a.id(), b.id(), "a fork: " + s.ids());
    assertEquals(3, s.ids().size());
    assertEquals(2, sent(s, Operation.REVOKE));
    assertEquals("first", reason(s, k0.id()));
    String both = String.join(",", new TreeSet<>(List.of(a.id(), b.id())));
    assertFalse(told.isEmpty());
    for (List<String> t : told) {
      assertEquals(k0.id(), t.get(0));
      assertEquals(both, String.join(",", new TreeSet<>(List.of(t.get(1).split(",")))));
    }
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(a.id()));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(b.id()));
    KeyHandle kept = admin.keys().reconcile(NAME).orElseThrow();
    assertTrue(List.of(a.id(), b.id()).contains(kept.id()));
    assertEquals(List.of(), s.violations());
  }

  // ---- a pending-name record removed while its move is still taking the name off ----

  /**
   * The Storm's {@code storm[8]} (2.1, unique names, Re-key refused): two callers finish one
   * replacement of a Compromised key. A records the name on the replacement and is held before
   * taking it off the Compromised key; B, finishing the moves earlier calls stopped in, finds that
   * record and Locates the name: the Compromised key still holds it. Before, B took that for "the
   * move finished, or another replacement took the name" and removed A's record; A then took the
   * name off, its addition hung until the deadline, and A's advised repeat found neither the name
   * nor the record: it succeeded with the name on no key, so {@code findByName} found nothing and
   * the next startup made an unrelated key under it. Now a record whose name is held by the key the
   * call moves names from stays (that move has not taken it off yet), and A's repeat gives the name.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRecordIsKeptWhileItsMoveHasNotTakenTheNameOff(KmipVersion version) throws Exception {
    recordKeptWhileItsMoveRuns(
        version,
        (b, old) -> b.keys().handle(old).replaceCompromised(NameMoveAndWideForkTest.leaked()));
  }

  /**
   * The same with {@code reconcile} as B, an operator's run while A's move is held: it moves the
   * names of the keys older than its winner, so a record whose name one of them still holds is kept
   * too. Before, it removed A's record and A's repeat left the name on no key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void reconcileKeepsARecordWhileItsMoveHasNotTakenTheNameOff(KmipVersion version)
      throws Exception {
    recordKeptWhileItsMoveRuns(version, (b, old) -> b.keys().handle(old).reconcile());
  }

  interface Finisher {
    KeyHandle finish(Kms b, String old);
  }

  void recordKeptWhileItsMoveRuns(KmipVersion version, Finisher finisher) throws Exception {
    InMemoryKmipServer s = NameMoveAndWideForkTest.server(version, true);
    servers.add(s);
    Kms admin = connect(s);
    KeyHandle old = NameMoveAndWideForkTest.key(admin, NAME);
    old.revoke(NameMoveAndWideForkTest.leaked());
    KeyHandle target = NameMoveAndWideForkTest.key(admin, null);
    KmsContractTest.link(admin, old.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, target.id());
    KmsContractTest.link(admin, target.id(), Enums.LinkType.REPLACED_OBJECT_LINK, old.id());
    byte[] record = target.seal(PLAIN, NameMoveAndWideForkTest.AAD);

    CountDownLatch aRecorded = new CountDownLatch(1), aGo = new CountDownLatch(1);
    CountDownLatch bLooked = new CountDownLatch(1), bGo = new CountDownLatch(1);
    int[] adds = new int[1], locates = new int[1];
    InMemoryKmipServer ra = s.replica(), rb = s.replica();
    // A: held before it takes the name off the Compromised key (its record is written); its second
    // addition of the name hangs until the call's deadline.
    Kms a =
        Kms.connect(
            ra.configure()
                .callTimeout(Duration.ofMillis(1500))
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        ConcurrentReplacementInterleavingsTest.transport(
                            (request, context) -> {
                              if (NameMoveAndWideForkTest.is(request, Operation.DELETE_ATTRIBUTE)
                                  && NameMoveAndWideForkTest.uid(request).equals(old.id())
                                  && aRecorded.getCount() > 0) {
                                aRecorded.countDown();
                                CompromiseReplacementTest.await(aGo, "A's go");
                              }
                              if (NameMoveAndWideForkTest.addsName(request, NAME) && ++adds[0] == 2)
                                ra.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.HANG);
                              return ra.exchange(request, context);
                            }))
                .build());
    clients.add(a);
    // B: held once its Locate of the name has answered (the Compromised key holds it).
    Kms b =
        Kms.connect(
            rb.configure()
                .transport(
                    e ->
                        ConcurrentReplacementInterleavingsTest.transport(
                            (request, context) -> {
                              Ttlv reply = rb.exchange(request, context);
                              if (NameMoveAndWideForkTest.is(request, Operation.LOCATE)
                                  && LineageTreeTest.names(request, NAME)
                                  && ++locates[0] == 1) {
                                bLooked.countDown();
                                CompromiseReplacementTest.await(bGo, "B's go");
                              }
                              return reply;
                            }))
                .build());
    clients.add(b);
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      Future<KeyHandle> af =
          pool.submit(
              () -> a.keys().handle(old.id()).replaceCompromised(NameMoveAndWideForkTest.leaked()));
      assertTrue(aRecorded.await(10, TimeUnit.SECONDS), "A recorded the move");
      assertEquals(
          List.of(NAME), KeyHandle.pendingNames(admin.keys().handle(target.id()).attributes()));
      assertEquals(List.of(NAME), s.names(old.id()));
      Future<KeyHandle> bf = pool.submit(() -> finisher.finish(b, old.id()));
      assertTrue(bLooked.await(10, TimeUnit.SECONDS), "B looked for the name's holders");
      // B found A's record and the Compromised key holding the name: the move has not taken it off.
      assertEquals(
          List.of(NAME), KeyHandle.pendingNames(admin.keys().handle(target.id()).attributes()));
      aGo.countDown();
      ExecutionException stopped =
          assertThrows(ExecutionException.class, () -> af.get(20, TimeUnit.SECONDS));
      assertInstanceOf(PartialCompletionException.class, stopped.getCause());
      assertTrue(
          stopped.getCause().getMessage().contains("repeat replaceCompromised() to resume"),
          stopped.getCause().getMessage());
      assertEquals(List.of(), s.names(old.id()));
      bGo.countDown();
      assertEquals(target.id(), bf.get(20, TimeUnit.SECONDS).id());
    } finally {
      aGo.countDown();
      bGo.countDown();
      pool.shutdownNow();
    }
    // The name is on no key, and the move stays written down on the replacement.
    assertEquals(List.of(), s.names(target.id()));
    assertEquals(
        List.of(NAME), KeyHandle.pendingNames(admin.keys().handle(target.id()).attributes()));
    // A's advised repeat gives it, and removes the record.
    assertEquals(target.id(), old.replaceCompromised(NameMoveAndWideForkTest.leaked()).id());
    assertEquals(List.of(NAME), s.names(target.id()));
    assertEquals(List.of(), KeyHandle.pendingNames(admin.keys().handle(target.id()).attributes()));
    assertEquals(Optional.of(target.id()), admin.keys().findByName(NAME).map(KeyHandle::id));
    assertEquals(target.id(), NameMoveAndWideForkTest.startup(admin).id());
    assertArrayEquals(
        PLAIN, admin.keys().open(KeyQuery.byName(NAME), record, NameMoveAndWideForkTest.AAD));
    assertEquals(2, s.ids().size(), "nothing created: " + s.ids());
  }

  /**
   * When the read-back of the refused Revoke is itself refused (the caller may not read the
   * key), the server's refusal stands unchanged: Permission Denied on 1.x (an access refusal is
   * never reinterpreted), Wrong Key Lifecycle State from 2.0, with the read-back's failure
   * suppressed; nothing is replaced by this call and the first compromise stays.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anUnreadableRefusedRevokeStandsAsTheServerSaidIt(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms first = connect(s);
    KeyHandle k0 = aes(first).create();
    boolean[] fired = new boolean[1];
    Kms second =
        connect(
            s,
            null,
            new Exchange() {
              @Override
              public void before(Ttlv request) {
                if (!revoking(request) || fired[0]) return;
                fired[0] = true;
                first
                    .keys()
                    .handle(k0.id())
                    .replaceCompromised(RevocationReason.keyCompromise("first", START));
                s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
              }
            });
    KmsException e =
        assertThrows(
            KmsException.class,
            () ->
                second
                    .keys()
                    .handle(k0.id())
                    .replaceCompromised(RevocationReason.keyCompromise("second", START)));
    if (version == KmipVersion.V1_4) {
      assertInstanceOf(PermissionDeniedException.class, e);
      assertEquals(Optional.of(Enums.ResultReason.PERMISSION_DENIED), e.protocolReason());
    } else {
      assertInstanceOf(StateConflictException.class, e);
      assertEquals(Optional.empty(), ((StateConflictException) e).observedState());
      assertEquals(Optional.of(Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE), e.protocolReason());
    }
    assertEquals(1, e.getSuppressed().length, "the refused read-back");
    assertInstanceOf(PermissionDeniedException.class, e.getSuppressed()[0]);
    assertEquals(2, s.ids().size());
    assertEquals("first", reason(s, k0.id()));
  }

  /**
   * The fake: a second Revoke of a Compromised object is refused on every version and
   * changes nothing (KMIP lists no transition out of Compromised but Destroy, 1.4 §3.22); the
   * high-level {@code revoke} reads the refusal back as STATE, {@code observedState()} COMPROMISED,
   * keeping the server's reason.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void aSecondCompromiseIsRefusedAndKeepsTheFirst(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle k = aes(kms).create();
    Instant at = START.minusSeconds(10);
    k.revoke(RevocationReason.keyCompromise("first", at));
    StateConflictException again =
        assertThrows(
            StateConflictException.class,
            () -> k.revoke(RevocationReason.keyCompromise("second", START)));
    assertEquals(Optional.of(KeyState.COMPROMISED), again.observedState());
    assertEquals(
        Optional.of(
            version.atLeast(KmipVersion.V2_0)
                ? Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE
                : Enums.ResultReason.PERMISSION_DENIED),
        again.protocolReason());
    assertTrue(
        again.getMessage().contains("first compromise's reason and dates"), again.getMessage());
    assertEquals("first", reason(s, k.id()));
    assertEquals(Optional.of(at), DeactivationTest.stored(s, k.id(), "Compromise Occurrence Date"));
    assertEquals(List.of(), s.violations());
  }

  // ---- a Pre-Active key is not deactivated, on any version ----

  /**
   * KMIP 1.4 §3.22 and 2.1 §4.57 list no transition from
   * Pre-Active to Deactivated ("Only the transitions described above are permitted"), as CSD02
   * §4.67 does not; the fake refuses a Revoke that is not a compromise of a Pre-Active object
   * up to 2.1, as keytend-kmip-server does (Permission Denied on 1.x, Wrong Key Lifecycle State
   * from 2.0). The server's refusal is not rethrown as it is (FIX_ACCESS on 1.x, STATE without a
   * state on 2.x): {@code deactivate()}, {@code revoke(superseded)} and a pair's {@code deactivate()}
   * are STATE with {@code observedState()} PRE_ACTIVE on every version, keeping the server's reason;
   * {@code deactivatePredecessors} passes the key over and {@code retirePredecessors} destroys it
   * without a prior request, as on 3.0.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void aPreActiveKeyIsStateOnEveryVersion(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle pending =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
    Enums.ResultReason expected =
        version.atLeast(KmipVersion.V2_0)
            ? Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE
            : Enums.ResultReason.PERMISSION_DENIED;
    for (Runnable call :
        List.<Runnable>of(
            pending::deactivate, () -> pending.revoke(RevocationReason.superseded("x")))) {
      StateConflictException e = assertThrows(StateConflictException.class, call::run);
      assertEquals(Optional.of(KeyState.PRE_ACTIVE), e.observedState());
      assertEquals(Optional.of(expected), e.protocolReason(), "the server's reason is kept");
      assertTrue(
          e.getMessage().contains("no transition from Pre-Active to Deactivated"), e.getMessage());
    }
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(pending.id()));
    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.ec(Curve.P_256))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .createPreActive();
    StateConflictException pairRefused =
        assertThrows(StateConflictException.class, pair::deactivate);
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), pairRefused.observedState());
    assertEquals(Optional.of(expected), pairRefused.protocolReason());
    assertTrue(
        pairRefused.getMessage().contains("no transition from Pre-Active to Deactivated"),
        pairRefused.getMessage());

    // An Active key's refusal is the server's answer, unchanged.
    KeyHandle active =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    s.failNext(retiring(version), Fault.PERMISSION_DENIED);
    assertThrows(PermissionDeniedException.class, active::deactivate);
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(active.id()));

    // A compromise is still a transition from Pre-Active (transition 3).
    pending.revoke(RevocationReason.keyCompromise("leak", START));
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(pending.id()));
    assertEquals(List.of(), s.violations());
  }

  // ---- a key's Lease Time, read as docs/local-keys.md shows ----

  /**
   * The guide reads a key's Lease Time with the typed {@code KeyAttributes.leaseTime()}; the
   * guide's snippet finds it in a KMIP 1.x
   * Get Attributes reply (normalized to the 2.x form, as every reply is) and in a 2.x one, and finds
   * nothing on a key without one, on every version.
   */
  @org.junit.jupiter.api.Test
  void theGuidesLeaseTimeSnippetReadsIt() throws java.io.IOException {
    Ttlv legacy =
        Ttlv.structure(
            Tag.RESPONSE_PAYLOAD,
            Ttlv.text(Tag.UNIQUE_IDENTIFIER, "k1"),
            Attributes.attribute(
                "Object Type", Ttlv.enumeration(Tag.OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY)),
            Attributes.attribute("State", Ttlv.enumeration(Tag.STATE, Enums.State.ACTIVE)),
            Attributes.attribute("Lease Time", Ttlv.interval(Tag.LEASE_TIME, 3600)));
    assertEquals(Optional.of(Duration.ofHours(1)), lease(AttributeReader.read(legacy)));
    // The 2.x and 3.0 form: the attribute under Attributes.
    Ttlv modern =
        Ttlv.structure(
            Tag.RESPONSE_PAYLOAD,
            Ttlv.text(Tag.UNIQUE_IDENTIFIER, "k2"),
            Ttlv.structure(
                Tag.ATTRIBUTES,
                Ttlv.enumeration(Tag.OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY),
                Ttlv.interval(Tag.LEASE_TIME, 90)));
    assertEquals(Optional.of(Duration.ofSeconds(90)), lease(AttributeReader.read(modern)));
    // The guide's snippet is the typed accessor; protocolAttributes() still holds the attribute.
    assertTrue(
        AttributeReader.read(modern).protocolAttributes().stream()
            .anyMatch(a -> a.tag() == Tag.LEASE_TIME.code()));

    for (KmipVersion version :
        List.of(KmipVersion.V1_2, KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0)) {
      InMemoryKmipServer s = server(version);
      KeyHandle plain = aes(connect(s)).create();
      assertEquals(Optional.empty(), lease(plain.attributes()), version + ": no lease set");
    }
  }

  /** The snippet of docs/local-keys.md, "Keys taken out of the KMS". */
  static Optional<Duration> lease(KeyAttributes attributes) {
    return attributes.leaseTime();
  }
}
