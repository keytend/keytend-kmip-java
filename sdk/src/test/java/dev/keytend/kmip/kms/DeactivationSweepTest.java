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
import static dev.keytend.kmip.kms.ScheduledRotationTest.NAME;
import static dev.keytend.kmip.kms.ScheduledRotationTest.aes;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Deactivation and retirement edge cases: a secret compromised during its replacement, refused
 * deactivations read back, Pre-Active keys, sweeps of reconcile and retirement on the KMIP 3.0
 * draft, and what retirePredecessors' Javadoc promises.
 */
class DeactivationSweepTest {
  static final byte[] AAD = "record".getBytes(StandardCharsets.UTF_8);
  static final Instant START = RotationJobTest.START;

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

  static ServerOperation retiring(KmipVersion version) {
    return DeactivationTest.retiring(version);
  }

  static Operation retiringOperation(KmipVersion version) {
    return DeactivationTest.retiringOperation(version);
  }

  /**
   * The secret replacement. Another caller compromises the old secret just before this call's
   * deactivation reaches it. Requiring DEACTIVATED would end the call in a
   * PartialCompletionException whose advice ("finish with ...deactivate()") could never succeed;
   * the step is done once the old object is out of use: the call returns the new secret.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1", "V3_0"})
  void replaceWhoseOldSecretWasCompromisedMeanwhile(KmipVersion version) {
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
                other.keys().handle(id).revoke(RevocationReason.keyCompromise("leak", START));
              }
              return r;
            });
    KeyHandle secret = kms.keys().registerSecret("hunter2".toCharArray()).named("db").register();
    compromiseFirst.set(secret.id());
    KeyHandle next = null;
    PartialCompletionException partial = null;
    try {
      next = kms.keys().registerSecret("correct horse".toCharArray()).named("db").replace(secret);
    } catch (PartialCompletionException e) {
      partial = e;
    }
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(secret.id()));
    if (partial != null) {
      // Follow the advice: it cannot succeed.
      String advice = partial.getMessage();
      StateConflictException again =
          assertThrows(
              StateConflictException.class, () -> kms.keys().handle(secret.id()).deactivate());
      fail(
          "replace ended in PartialCompletionException although the old object is not Active any more; its advice"
              + " fails forever ("
              + again.observedState()
              + "): "
              + advice);
    }
    assertNotNull(next);
    assertEquals(Optional.of(next), kms.keys().findByName("db"));
    assertEquals(List.of(), s.violations());
  }

  /**
   * deactivatePredecessors where the server refuses (Permission Denied, as keytend-kmip-server
   * answers) the deactivation of a key another caller deactivated meanwhile: retire() reads the key
   * back (StateConflictException with the server's Result), and revokedOrRetired reads it back
   * again because that exception still carries the server's Permission Denied: two Get Attributes
   * for one refusal, where one settles it. Now the second uses the first's observedState().
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1", "V3_0"})
  void aRefusedDeactivationIsReadBackTwice(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicReference<String> deactivateFirst = new AtomicReference<>();
    Kms other = connect(s);
    Kms kms =
        connect(
            s,
            r -> {
              String id = deactivateFirst.get();
              if (id != null
                  && RotationAndNameChoiceTest.isOperation(r, retiringOperation(version))
                  && names(r, id)) {
                deactivateFirst.set(null);
                other.keys().handle(id).deactivate();
                s.failNext(retiring(version), Fault.PERMISSION_DENIED);
              }
              return r;
            });
    KeyHandle k0 = aes(kms).create();
    KeyHandle k1 = k0.rotate();
    deactivateFirst.set(k0.id());
    assertEquals(List.of(), ids(k1.deactivatePredecessors()));
    // Count the Get Attributes of k0 after the refused request.
    int afterRefusal = 0;
    boolean seen = false;
    for (Ttlv r : s.protocolRequests()) {
      if (RotationAndNameChoiceTest.isOperation(r, retiringOperation(version)) && names(r, k0.id()))
        seen = true;
      else if (seen
          && RotationAndNameChoiceTest.isOperation(r, Operation.GET_ATTRIBUTES)
          && names(r, k0.id())) afterRefusal++;
    }
    assertEquals(
        1, afterRefusal, "Get Attributes of " + k0.id() + " after the refused deactivation");
  }

  /**
   * KMIP 1.4 and 2.1 list no transition from Pre-Active to Deactivated, as 3.0 does not; the fake
   * and keytend-kmip-server refuse it, and a refusal read back as Pre-Active is STATE on every
   * version, keeping the server's reason; a refusal whose read-back is itself refused stays the
   * server's access answer.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void anAccessRefusalOfAPreActiveKeyUpTo21IsReportedAsState(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle pending =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
    s.failNext(ServerOperation.REVOKE, Fault.PERMISSION_DENIED);
    StateConflictException e =
        assertThrows(
            StateConflictException.class, () -> pending.revoke(RevocationReason.superseded("x")));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), e.observedState());
    assertEquals(Optional.of(Enums.ResultReason.PERMISSION_DENIED), e.protocolReason());
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(pending.id()));
    // The read-back refused too: the server's access refusal stands.
    s.failNext(ServerOperation.REVOKE, Fault.PERMISSION_DENIED);
    s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
    KmsException denied =
        assertThrows(KmsException.class, () -> pending.revoke(RevocationReason.superseded("x")));
    assertInstanceOf(
        PermissionDeniedException.class, denied, "an access refusal on " + version + ": " + denied);
    assertEquals(1, denied.getSuppressed().length);
  }

  /**
   * Reconcile's sweep on 3.0 (the 1.4/2.1 sweep of ReconcileJoinFaultsTest covers no Deactivate): a
   * lost reply or server failure at each mutation, including Deactivate, then repeat.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V3_0"})
  void reconcileSweepOnTheDraft(KmipVersion version) throws Exception {
    List<String> all = new ArrayList<>();
    for (Fault fault : List.of(Fault.REPLY_LOST, Fault.SERVER_FAILURE))
      for (int failAt = 1; failAt <= 40; failAt++) {
        InMemoryKmipServer s = InMemoryKmipServer.of(version).uniqueNames(true);
        servers.add(s);
        Kms admin = connect(s);
        KeyHandle old = aes(admin).create();
        byte[] root = old.seal("r".getBytes(UTF_8), AAD);
        List<String> tips = new ArrayList<>();
        for (int i = 0; i < 4; i++) tips.add(RotationAndNameChoiceTest.reKey(admin, old.id()));
        String holder =
            s.ids().stream().filter(id -> s.names(id).contains(NAME)).findFirst().orElseThrow();
        admin.keys().handle(holder).removeName(NAME);
        admin.keys().handle(tips.get(3)).addName(NAME);
        AtomicInteger n = new AtomicInteger();
        int f = failAt;
        Kms k =
            connect(
                s,
                request -> {
                  for (Operation op :
                      List.of(
                          Operation.ADD_ATTRIBUTE,
                          Operation.DELETE_ATTRIBUTE,
                          Operation.SET_ATTRIBUTE,
                          Operation.MODIFY_ATTRIBUTE,
                          Operation.REVOKE,
                          Operation.DEACTIVATE))
                    if (RotationAndNameChoiceTest.isOperation(request, op)
                        && n.incrementAndGet() == f)
                      s.failNext(ServerOperation.valueOf(op.name()), fault);
                  return request;
                });
        KeyHandle winner = null;
        String last = null;
        for (int attempt = 0; attempt < 4 && winner == null; attempt++)
          try {
            winner = k.keys().reconcile(NAME).orElseThrow();
          } catch (PartialCompletionException | OutcomeUnknownException interrupted) {
            last = String.valueOf(interrupted);
          } catch (KmsException other) {
            last = String.valueOf(other);
            break;
          }
        if (winner == null) {
          all.add(fault + "/" + failAt + ": never finished: " + last);
          continue;
        }
        for (String id : s.ids()) {
          if (id.equals(winner.id())) continue;
          if (s.state(id).orElseThrow() != KeyState.DEACTIVATED)
            all.add(fault + "/" + failAt + ": " + id + " is " + s.state(id).orElseThrow());
        }
        if (!s.names(winner.id()).contains(NAME))
          all.add(fault + "/" + failAt + ": winner without the name");
        try {
          assertArrayEquals(
              "r".getBytes(UTF_8), admin.keys().open(KeyQuery.byName(NAME), root, AAD));
        } catch (KmsException e) {
          all.add(fault + "/" + failAt + ": " + e);
        }
        if (!s.violations().isEmpty())
          all.add(fault + "/" + failAt + ": violations " + s.violations());
      }
    assertEquals(List.of(), all.subList(0, Math.min(all.size(), 20)), "total " + all.size());
  }

  /**
   * deactivatePredecessors then retirePredecessors on every version with a lost reply or server
   * failure at the n-th retiring request or Destroy, then repeated: always finishes, never
   * compromises a key on any version.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void retirementSweep(KmipVersion version) throws Exception {
    List<String> all = new ArrayList<>();
    for (Fault fault : List.of(Fault.REPLY_LOST, Fault.SERVER_FAILURE, Fault.PERMISSION_DENIED))
      for (int failAt = 1; failAt <= 8; failAt++) {
        InMemoryKmipServer s = server(version);
        AtomicInteger n = new AtomicInteger();
        int f = failAt;
        Kms k =
            connect(
                s,
                request -> {
                  for (Operation op :
                      List.of(Operation.REVOKE, Operation.DEACTIVATE, Operation.DESTROY))
                    if (RotationAndNameChoiceTest.isOperation(request, op)
                        && n.incrementAndGet() == f)
                      s.failNext(ServerOperation.valueOf(op.name()), fault);
                  return request;
                });
        KeyHandle k0 = aes(k).create();
        KeyHandle k1 = k0.rotate();
        KeyHandle k2 = k1.rotate();
        KeyHandle k3 = k2.rotate();
        String last = null;
        boolean done = false;
        for (int attempt = 0; attempt < 4 && !done; attempt++)
          try {
            k3.deactivatePredecessors();
            done = true;
          } catch (KmsException e) {
            last = String.valueOf(e);
          }
        if (!done) all.add(fault + "/" + failAt + ": deactivate never finished: " + last);
        done = false;
        for (int attempt = 0; attempt < 4 && !done; attempt++)
          try {
            k3.retirePredecessors(RevocationReason.superseded("retired"));
            done = true;
          } catch (KmsException e) {
            last = String.valueOf(e);
          }
        if (!done) all.add(fault + "/" + failAt + ": retire never finished: " + last);
        for (KeyHandle h : List.of(k0, k1, k2))
          if (s.state(h.id()).orElse(KeyState.DESTROYED) != KeyState.DESTROYED)
            all.add(fault + "/" + failAt + ": " + h.id() + " " + s.state(h.id()));
        if (!s.violations().isEmpty())
          all.add(fault + "/" + failAt + ": violations " + s.violations());
      }
    assertEquals(List.of(), all, "total " + all.size());
  }

  /**
   * retirePredecessors' Javadoc said a Revoke whose outcome is unknown is read back and "a key no
   * longer Active or Pre-Active is destroyed"; a key another caller compromised meanwhile is not
   * destroyed, the call ends in the OutcomeUnknownException instead, and the repeat destroys it.
   * This pins what the Javadoc says.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1", "V3_0"})
  void retirePredecessorsJavadocOnALostReply(KmipVersion version) {
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
                other.keys().handle(id).revoke(RevocationReason.keyCompromise("leak", START));
                s.failNext(retiring(version), Fault.REPLY_LOST);
              }
              return r;
            });
    KeyHandle k0 = aes(kms).create();
    KeyHandle k1 = k0.rotate();
    compromiseFirst.set(k0.id());
    assertThrows(
        OutcomeUnknownException.class,
        () -> k1.retirePredecessors(RevocationReason.superseded("retired")));
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(k0.id()));
    List<KeyHandle> gone = k1.retirePredecessors(RevocationReason.superseded("retired"));
    assertEquals(List.of(k0.id()), ids(gone));
    assertEquals(Optional.of(KeyState.DESTROYED_COMPROMISED), s.state(k0.id()));
  }

  /** The fake's Deactivate on 3.0: Deactivation Reason rendered, Locate by state finds it. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V3_0"})
  void theFakesDeactivateIsVisible(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle k = aes(kms).create();
    k.deactivate();
    assertTrue(
        s.protocolAttributes(k.id()).containsKey("Deactivation Reason"),
        s.protocolAttributes(k.id()).keySet().toString());
    assertEquals(KeyState.DEACTIVATED, k.attributes().state());
    assertEquals(List.of(k), kms.keys().list(KeyQuery.byName(NAME).state(KeyState.DEACTIVATED)));
    assertEquals(List.of(), s.violations());
  }
}
