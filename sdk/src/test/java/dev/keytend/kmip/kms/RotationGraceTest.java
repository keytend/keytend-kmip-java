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

import static dev.keytend.kmip.kms.ScheduledRotationTest.NAME;
import static dev.keytend.kmip.kms.ScheduledRotationTest.aes;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.KmipException;
import dev.keytend.kmip.client.Request;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/** Rotation with a grace period: deactivating predecessors, reconcile within KMIP's link cardinality, and scheduled deactivation. */
class RotationGraceTest {
  static final byte[] AAD = "record".getBytes(StandardCharsets.UTF_8);
  static final Instant START = RotationJobTest.START;
  static final Duration DAY = Duration.ofDays(1);

  /** Sixteen bytes: what AES key wrap takes, on every version. */
  static final byte[] WRAPPABLE = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  InMemoryKmipServer server(KmipVersion version, RotationJobTest.TestClock clock) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    s.clock(clock);
    servers.add(s);
    return s;
  }

  /** A client of {@code server} on {@code clock}, with {@code listener}, whose requests pass through {@code request}. */
  Kms connect(
      InMemoryKmipServer server,
      RotationJobTest.TestClock clock,
      KmsListener listener,
      UnaryOperator<Ttlv> request) {
    KmsConfig.Builder config =
        server.configure().transport(e -> r -> server.exchange(request.apply(r)));
    if (listener != null) config.addListener(listener);
    Kms kms = Kms.connect(config.build());
    kms.clock(clock);
    clients.add(kms);
    return kms;
  }

  Kms connect(InMemoryKmipServer server, RotationJobTest.TestClock clock) {
    return connect(server, clock, null, UnaryOperator.identity());
  }

  /** Sets {@code id}'s Deactivation Date through the protocol: Add Attribute in 1.x (Modify when it has one), Set Attribute from 2.0. */
  static void deactivationDate(Kms kms, String id, Instant at, boolean has) throws Exception {
    Ttlv attribute =
        Attributes.attribute("Deactivation Date", Ttlv.dateTime(Tag.DEACTIVATION_DATE, at));
    Request.Builder b =
        !kms.protocolVersion().legacyAttributes()
            ? Request.operation(Operation.SET_ATTRIBUTE)
            : has ? Requests.modifyAttribute() : Requests.addAttribute();
    kms.protocol().call(b.uniqueIdentifier(id).attribute(attribute).build());
  }

  // ---- The fake: State from dates ----

  /**
   * The in-memory server gives an object the State its dates give it as time passes, as
   * keytend-kmip-server does (KMIP 1.4 §3.22, transition 6): an Active key whose Deactivation Date has come
   * is Deactivated, so it still decrypts but no longer encrypts. A fake that kept the State it
   * stored would hide the old key switching off from a test of a grace period. A client may set the date while the key is Active, not once it is
   * Deactivated, and never delete it (KMIP 1.4 Table 114); a Pre-Active key whose Activation Date
   * comes is Active (transition 4).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void theFakeDeactivatesAKeyWhenItsDeactivationDateComes(KmipVersion version) throws Exception {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    KeyHandle key = aes(kms).create();
    Ciphertext before = key.encrypt(CipherSpec.keyWrap(), WRAPPABLE);
    deactivationDate(kms, key.id(), START.plus(DAY), false);
    clock.now = START.plus(DAY).minusSeconds(1);
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(key.id()));
    assertNotNull(key.encrypt(CipherSpec.keyWrap(), WRAPPABLE));

    clock.now = START.plus(DAY);
    assertEquals(KeyState.DEACTIVATED, kms.keys().handle(key.id()).attributes().state());
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(key.id()));
    assertArrayEquals(WRAPPABLE, key.decrypt(before, null), "a Deactivated key still decrypts");
    StateConflictException refused =
        assertThrows(
            StateConflictException.class, () -> key.encrypt(CipherSpec.keyWrap(), WRAPPABLE));
    assertEquals(Optional.of(KeyState.DEACTIVATED), refused.observedState());

    // Only while Pre-Active or Active: not once the date has come.
    KmipException changed =
        assertThrows(
            KmipException.class,
            () -> deactivationDate(kms, key.id(), START.plus(DAY.multipliedBy(9)), true));
    assertEquals(
        Optional.of(
            version.atLeast(KmipVersion.V2_0)
                ? Enums.ResultReason.WRONG_KEY_LIFECYCLE_STATE
                : Enums.ResultReason.ILLEGAL_OPERATION),
        changed.reason());
    // Never deleted by a client.
    KeyHandle other = aes(kms).create();
    deactivationDate(kms, other.id(), START.plus(DAY.multipliedBy(9)), false);
    Request delete =
        kms.protocolVersion().legacyAttributes()
            ? Requests.deleteAttribute()
                .uniqueIdentifier(other.id())
                .add(Ttlv.text(Tag.ATTRIBUTE_NAME, "Deactivation Date"))
                .add(Ttlv.integer(Tag.ATTRIBUTE_INDEX, 0))
                .build()
            : Requests.deleteAttribute()
                .uniqueIdentifier(other.id())
                .attribute(
                    Attributes.attribute(
                        "Deactivation Date",
                        Ttlv.dateTime(Tag.DEACTIVATION_DATE, START.plus(DAY.multipliedBy(9)))))
                .build();
    assertThrows(KmipException.class, () -> kms.protocol().call(delete));
    assertEquals(
        Optional.of(START.plus(DAY.multipliedBy(9))), other.attributes().deactivationDate());

    // A Pre-Active key whose Activation Date comes is Active.
    String later =
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
                            "Activation Date",
                            Ttlv.dateTime(Tag.ACTIVATION_DATE, clock.now.plus(DAY))))
                    .build())
            .uniqueIdentifier();
    assertEquals(KeyState.PRE_ACTIVE, kms.keys().handle(later).attributes().state());
    clock.now = clock.now.plus(DAY);
    assertEquals(KeyState.ACTIVE, kms.keys().handle(later).attributes().state());

    // As keytend-kmip-server: a client never sets a Deactivation Date.
    s.refuseClientDeactivationDate(true);
    KeyHandle third = aes(kms).create();
    KmipException readOnly =
        assertThrows(
            KmipException.class,
            () -> deactivationDate(kms, third.id(), clock.now.plus(DAY), false));
    assertEquals(
        Optional.of(
            version.atLeast(KmipVersion.V2_0)
                ? Enums.ResultReason.ATTRIBUTE_READ_ONLY
                : Enums.ResultReason.PERMISSION_DENIED),
        readOnly.reason());
    assertEquals(Optional.empty(), third.attributes().deactivationDate());
    assertEquals(List.of(), s.violations());
  }

  /** The number of requests to {@code s} with an item for {@code operation}. */
  static int sent(InMemoryKmipServer s, Operation operation) {
    return (int)
        s.protocolRequests().stream()
            .filter(r -> RotationAndNameChoiceTest.isOperation(r, operation))
            .count();
  }

  /** Whether {@code node} or a node below it is the Text String {@code id}. */
  static boolean names(Ttlv node, String id) {
    if (node.type() == Ttlv.Type.STRUCTURE)
      return node.children().stream().anyMatch(c -> names(c, id));
    return EnumSet.of(Ttlv.Type.TEXT_STRING, Ttlv.Type.IDENTIFIER, Ttlv.Type.REFERENCE)
            .contains(node.type())
        && node.textValue().equals(id);
  }

  static List<String> ids(List<KeyHandle> keys) {
    return keys.stream().map(KeyHandle::id).toList();
  }

  // ---- deactivatePredecessors ----

  /**
   * {@code deactivatePredecessors()} revokes the older keys of the lineage as superseded,
   * oldest first, and destroys nothing: they are Deactivated with their material, every record
   * still opens (through the current key, the old key's own handle and the name), and sealing
   * under an old key is refused, STATE, DEACTIVATED. A repeat does nothing and sends no Revoke;
   * {@code retirePredecessors} then destroys them without revoking them again.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_0", "V2_1", "V3_0"})
  void deactivatePredecessorsSwitchesTheOldKeysOffAndDestroysNothing(KmipVersion version) {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    KeyHandle k0 = aes(kms).create();
    byte[] r0 = k0.seal("r0".getBytes(StandardCharsets.UTF_8), AAD);
    KeyHandle k1 = k0.rotate();
    byte[] r1 = k1.seal("r1".getBytes(StandardCharsets.UTF_8), AAD);
    KeyHandle k2 = k1.rotate();

    List<KeyHandle> deactivated = k2.deactivatePredecessors();
    assertEquals(List.of(k0.id(), k1.id()), ids(deactivated), "oldest first");
    for (KeyHandle k : List.of(k0, k1)) {
      assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(k.id()));
      assertTrue(s.hasMaterial(k.id()), "not destroyed");
    }
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(k2.id()));
    KeyHandle byName = kms.keys().findByName(NAME).orElseThrow();
    assertEquals(k2, byName);
    for (KeyHandle through : List.of(k2, k0, k1, byName)) {
      assertArrayEquals("r0".getBytes(StandardCharsets.UTF_8), through.open(r0, AAD));
      assertArrayEquals("r1".getBytes(StandardCharsets.UTF_8), through.open(r1, AAD));
    }
    StateConflictException refused =
        assertThrows(
            StateConflictException.class,
            () -> kms.keys().handle(k0.id()).seal(new byte[] {1}, AAD));
    assertEquals(Optional.of(KeyState.DEACTIVATED), refused.observedState());

    // Deactivating is a Revoke up to 2.1 and a Deactivate on 3.0.
    Operation retiring = DeactivationTest.retiringOperation(version);
    int revokes = sent(s, retiring);
    assertEquals(2, revokes);
    assertEquals(List.of(), k2.deactivatePredecessors(), "a repeat does nothing");
    assertEquals(revokes, sent(s, retiring));
    // The last step destroys them, without revoking them again.
    assertEquals(
        List.of(k0.id(), k1.id()),
        ids(k2.retirePredecessors(RevocationReason.superseded("retired"))));
    assertEquals(revokes, sent(s, retiring), "a Deactivated key is not revoked again");
    assertEquals(0, sent(s, version == KmipVersion.V3_0 ? Operation.REVOKE : Operation.DEACTIVATE));
    for (KeyHandle k : List.of(k0, k1))
      assertEquals(Optional.of(KeyState.DESTROYED), s.state(k.id()));
    assertEquals(List.of(), s.violations());
  }

  /**
   * The scope rules of {@code retirePredecessors}: refused, nothing deactivated, from a key
   * that is not the newest, on a lineage with several newest keys (reconcile first), and from a
   * newest key that is not Active (the lineage would have nothing to seal under); a compromise
   * reason is refused before anything is sent. Keys outside the confirmed lineage are not touched.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void deactivatePredecessorsKeepsToTheConfirmedLineage(KmipVersion version) throws Exception {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    KeyHandle k0 = aes(kms).create();
    KeyHandle k1 = k0.rotate();

    assertThrows(
        IllegalArgumentException.class,
        () -> k1.deactivatePredecessors(RevocationReason.keyCompromise("leaked", clock.now)));
    StateConflictException notNewest =
        assertThrows(StateConflictException.class, k0::deactivatePredecessors);
    assertTrue(
        notNewest.getMessage().contains("newer keys, [" + k1.id() + "]"), notNewest.getMessage());
    assertTrue(notNewest.getMessage().endsWith("Nothing was deactivated"), notNewest.getMessage());

    // Two callers rotated k1 at once: refused until reconcile (which itself revokes the others).
    String a = RotationAndNameChoiceTest.reKey(kms, k1.id()),
        b = RotationAndNameChoiceTest.reKey(kms, k1.id());
    StateConflictException forked =
        assertThrows(
            StateConflictException.class, () -> kms.keys().handle(a).deactivatePredecessors());
    assertTrue(forked.getMessage().contains("reconcile()"), forked.getMessage());
    for (String k : List.of(k0.id(), k1.id(), a, b))
      assertEquals(Optional.of(KeyState.ACTIVE), s.state(k), "nothing deactivated");
    KeyHandle joined = kms.keys().handle(a).reconcile();
    assertEquals(List.of(), joined.deactivatePredecessors());

    // A key with the name, outside the lineage, is not touched.
    KeyHandle s0 =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("other")
            .create();
    KeyHandle stranger =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("other")
            .create();
    KeyHandle s1 = s0.rotate();
    assertEquals(List.of(s0.id()), ids(s1.deactivatePredecessors()));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(stranger.id()), "outside the lineage");

    // A newest key that is not Active.
    joined.revoke(RevocationReason.superseded("by hand"));
    StateConflictException inactive =
        assertThrows(StateConflictException.class, joined::deactivatePredecessors);
    assertEquals(Optional.of(KeyState.DEACTIVATED), inactive.observedState());
    assertTrue(Set.of(a, b).contains(joined.id()));
    assertEquals(List.of(), s.violations());
  }

  /**
   * Idempotent and resumable. A Revoke that fails stops the call, and the repeat finishes;
   * a Revoke whose reply is lost is read back and counts; a Revoke the server refuses because the
   * key's Deactivation Date came meanwhile (the end of a grace period, reached between the call's
   * read and its Revoke) is read back and passed over, in {@code deactivatePredecessors} and in
   * {@code retirePredecessors}, which goes on to destroy the key. Before, such a refusal stopped
   * {@code retirePredecessors} with STATE.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void deactivatingIsResumableAndReadsBackWhatItCannotTell(KmipVersion version) throws Exception {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    java.util.concurrent.atomic.AtomicReference<String> passOn =
        new java.util.concurrent.atomic.AtomicReference<>();
    Kms kms =
        connect(
            s,
            clock,
            null,
            r -> {
              // The key's Deactivation Date comes just before its Revoke.
              if (RotationAndNameChoiceTest.isOperation(
                      r, DeactivationTest.retiringOperation(version))
                  && passOn.get() != null
                  && names(r, passOn.get())) {
                clock.now = clock.now.plus(DAY.multipliedBy(2));
                passOn.set(null);
              }
              return r;
            });
    KeyHandle k0 = aes(kms).create();
    KeyHandle k1 = k0.rotate();
    KeyHandle k2 = k1.rotate();
    KeyHandle k3 = k2.rotate();

    s.failNext(DeactivationTest.retiring(version), Fault.SERVER_FAILURE);
    assertThrows(ServerFailureException.class, k3::deactivatePredecessors);
    s.failNext(DeactivationTest.retiring(version), Fault.REPLY_LOST);
    // k0's Revoke fails, then k0's Revoke reply is lost: read back, it counts.
    assertEquals(List.of(k0.id(), k1.id(), k2.id()), ids(k3.deactivatePredecessors()));
    for (KeyHandle k : List.of(k0, k1, k2))
      assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(k.id()));

    // A new lineage whose middle key's Deactivation Date comes between the call's read and its
    // Revoke.
    KeyHandle j0 =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("other")
            .create();
    KeyHandle j1 = j0.rotate();
    KeyHandle j2 = j1.rotate();
    deactivationDate(kms, j1.id(), clock.now.plus(DAY), false);
    passOn.set(j1.id());
    assertEquals(
        List.of(j0.id()), ids(j2.deactivatePredecessors()), "j1 deactivated itself meanwhile");
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(j1.id()));

    KeyHandle m0 =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("third")
            .create();
    KeyHandle m1 = m0.rotate();
    deactivationDate(kms, m0.id(), clock.now.plus(DAY), false);
    passOn.set(m0.id());
    assertEquals(
        List.of(m0.id()), ids(m1.retirePredecessors(RevocationReason.superseded("retired"))));
    assertEquals(Optional.of(KeyState.DESTROYED), s.state(m0.id()));
    assertEquals(List.of(), s.violations());
  }

  // ---- through Deactivated keys ----

  /** A listener that keeps the {@code staleHandle} events, as "keyId -> replacements". */
  static final class Stale implements KmsListener {
    final List<String> events = new CopyOnWriteArrayList<>();

    @Override
    public void staleHandle(String keyId, List<String> replacements) {
      events.add(keyId + " -> " + replacements);
    }
  }

  static byte[] utf8(String s) {
    return s.getBytes(StandardCharsets.UTF_8);
  }

  /**
   * A record sealed (from 1.4) and a ciphertext made (on every version) under a key that is
   * Deactivated since (rotated, then {@code deactivatePredecessors}) open on every path: the
   * current key's handle, {@code findByName}, a {@code KeyQuery}, a {@code CurrentKey} made before
   * the rotation (it still holds the old key), another instance that starts after it, the old
   * key's own handle, and re-wrapping ({@code rewrapRecord}, {@code rewrapKey}, and a {@code
   * CurrentKey}'s {@code rewrapRecord} once it moved), which moves them to the current key. KMIP
   * 1.2 has no AES-GCM, so no sealed records there: the ciphertext is AES key wrap.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void aRecordUnderADeactivatedPredecessorOpensOnEveryPath(KmipVersion version) {
    boolean sealing = version.atLeast(KmipVersion.V1_4);
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    KeyHandle k0 = aes(kms).create();
    CurrentKey current = kms.keys().current(NAME);
    byte[] record = sealing ? k0.seal(utf8("record"), AAD) : null;
    Ciphertext wrapped = k0.encrypt(CipherSpec.keyWrap(), WRAPPABLE);
    KeyHandle k1 = k0.rotate();
    assertEquals(List.of(k0.id()), ids(k1.deactivatePredecessors()));
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(k0.id()));

    Kms restarted = connect(s, clock);
    KeyQuery query = KeyQuery.byName(NAME);
    List<KeyHandle> handles =
        List.of(
            k1,
            kms.keys().findByName(NAME).orElseThrow(),
            current.handle(),
            restarted.keys().findByName(NAME).orElseThrow(),
            k0);
    assertEquals(
        k0, current.handle(), "a CurrentKey made before the rotation still holds the old key");
    for (KeyHandle h : handles) {
      assertArrayEquals(WRAPPABLE, h.decrypt(wrapped, null), h.toString());
      if (sealing) assertArrayEquals(utf8("record"), h.open(record, AAD), h.toString());
    }
    assertArrayEquals(WRAPPABLE, kms.keys().decrypt(query, wrapped, null));
    assertArrayEquals(WRAPPABLE, restarted.keys().decrypt(query, wrapped, null));
    Ciphertext moved = k1.rewrapKey(wrapped, null);
    assertEquals(k1.id(), moved.keyId());
    assertArrayEquals(WRAPPABLE, k1.decrypt(moved, null));
    if (sealing) {
      assertArrayEquals(utf8("record"), kms.keys().open(query, record, AAD));
      assertArrayEquals(utf8("record"), current.open(record, AAD));
      Rewrapped r = k1.rewrapRecord(record, AAD);
      assertTrue(r.changed());
      assertEquals(k1.id(), KmsKeys.sealedKeyId(r.bytes()));
      assertArrayEquals(
          utf8("record"), restarted.keys().findByName(NAME).orElseThrow().open(r.bytes(), AAD));
      // The CurrentKey moves on its first refused seal; then it re-wraps to the current key too.
      assertEquals(k1.id(), KmsKeys.sealedKeyId(current.seal(utf8("new"), AAD)));
      Rewrapped viaCurrent = current.rewrapRecord(record, AAD);
      assertTrue(viaCurrent.changed());
      assertEquals(k1.id(), KmsKeys.sealedKeyId(viaCurrent.bytes()));
    }
    assertEquals(List.of(), s.violations());
  }

  /**
   * Protecting under a Deactivated key is refused, STATE, {@code observedState()}
   * DEACTIVATED, naming the replacement: sealing (to bytes, a file and a stream), encrypting,
   * wrapping and making a data key, from a handle kept from before the rotation. That handle's
   * listener hears {@code staleHandle} from the refusal, although it knew its key's usages already,
   * and the refusal names the replacement. A {@code CurrentKey} that holds
   * the old key moves to the current key on the refusal and seals there, also to a file.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void protectingUnderADeactivatedKeyIsRefusedAndFollowed(KmipVersion version) throws Exception {
    boolean sealing = version.atLeast(KmipVersion.V1_4);
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Stale stale = new Stale();
    Kms kms = connect(s, clock, stale, UnaryOperator.identity());
    KeyHandle k0 = aes(kms).create();
    CurrentKey current = kms.keys().current(k0);
    k0.encrypt(CipherSpec.keyWrap(), WRAPPABLE); // the handle reads its usages once, now
    Kms other = connect(s, clock);
    KeyHandle k1 = other.keys().handle(k0.id()).rotate();
    other.keys().handle(k1.id()).deactivatePredecessors();
    assertEquals(List.of(), stale.events);

    List<org.junit.jupiter.api.function.Executable> protecting = new ArrayList<>();
    protecting.add(() -> k0.encrypt(CipherSpec.keyWrap(), WRAPPABLE));
    if (sealing) {
      protecting.add(() -> k0.seal(utf8("x"), AAD));
      protecting.add(
          () -> k0.wrapKey(new javax.crypto.spec.SecretKeySpec(new byte[32], "AES"), AAD));
      protecting.add(() -> k0.generateDataKey(256, AAD).close());
      protecting.add(() -> k0.sealing(new java.io.ByteArrayOutputStream(), AAD));
    }
    for (org.junit.jupiter.api.function.Executable call : protecting) {
      StateConflictException refused = assertThrows(StateConflictException.class, call);
      assertEquals(Optional.of(KeyState.DEACTIVATED), refused.observedState());
      assertEquals(Optional.of(k0.id()), refused.objectId());
      assertTrue(
          refused.getMessage().contains(k0.id() + " names " + k1.id() + " as its replacement"),
          refused.getMessage());
    }
    assertEquals(k0.id() + " -> [" + k1.id() + "]", stale.events.get(0));
    assertEquals(Set.of(k0.id() + " -> [" + k1.id() + "]"), Set.copyOf(stale.events));

    if (sealing) {
      assertEquals(k0, current.handle());
      assertEquals(k1.id(), KmsKeys.sealedKeyId(current.seal(utf8("x"), AAD)));
      assertEquals(k1.id(), current.handle().id());
      java.nio.file.Path dir = java.nio.file.Files.createTempDirectory("r16");
      try {
        java.nio.file.Path file = dir.resolve("sealed");
        CurrentKey another = kms.keys().current(k0);
        another.sealTo(file, new java.io.ByteArrayInputStream(utf8("file")), AAD);
        assertEquals(k1.id(), another.handle().id());
        java.nio.file.Path plain = dir.resolve("plain");
        k0.openTo(file, plain, AAD);
        assertArrayEquals(utf8("file"), java.nio.file.Files.readAllBytes(plain));
        java.nio.file.Files.delete(plain);
        java.nio.file.Files.delete(file);
      } finally {
        java.nio.file.Files.delete(dir);
      }
    }
    assertEquals(List.of(), s.violations());
  }

  /**
   * A Deactivated key verifies: a key pair revoked as superseded still verifies a signature
   * it made and refuses to sign (STATE, DEACTIVATED); an HMAC key verifies a MAC and refuses to
   * compute one. The fake follows KMIP 1.4 §3.22 here, and the SDK refuses neither.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void aDeactivatedKeyVerifiesAndDoesNotSign(KmipVersion version) {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .create();
    SignatureSpec spec = SignatureSpec.rsaPkcs1(Hash.SHA_256);
    byte[] signature = pair.privateKey().sign(spec, utf8("manifest"));
    KeyHandle mac =
        kms.keys()
            .createSymmetric(Algorithm.HMAC_SHA256, 256)
            .usages(KeyUsage.MAC_GENERATE, KeyUsage.MAC_VERIFY)
            .create();
    byte[] tag = mac.mac(MacSpec.keyDefault(), utf8("manifest"));
    pair.revoke(RevocationReason.superseded("rotated"));
    mac.revoke(RevocationReason.superseded("rotated"));
    for (String k : List.of(pair.privateKey().id(), pair.publicKey().id(), mac.id()))
      assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(k));

    assertEquals(VerifyResult.VALID, pair.publicKey().verify(spec, utf8("manifest"), signature));
    assertEquals(VerifyResult.INVALID, pair.publicKey().verify(spec, utf8("forged"), signature));
    assertEquals(
        VerifyResult.VALID,
        kms.keys().handle(pair.publicKey().id()).verify(spec, utf8("manifest"), signature));
    assertEquals(VerifyResult.VALID, mac.macVerify(MacSpec.keyDefault(), utf8("manifest"), tag));
    StateConflictException sign =
        assertThrows(StateConflictException.class, () -> pair.privateKey().sign(spec, utf8("x")));
    assertEquals(Optional.of(KeyState.DEACTIVATED), sign.observedState());
    StateConflictException macRefused =
        assertThrows(StateConflictException.class, () -> mac.mac(MacSpec.keyDefault(), utf8("x")));
    assertEquals(Optional.of(KeyState.DEACTIVATED), macRefused.observedState());
    assertEquals(List.of(), s.violations());
  }

  // ---- reconcile gives no key a second Replaced or Replacement Object link ----

  /**
   * {@code reconcile()} joins the other newest keys into the winner without giving any key a
   * second Replaced Object or Replacement Object link, which KMIP does not allow (one replacement
   * object, 1.4 §3.35, 2.1 §4.30, 3.0 §4.35.18; 3.0's Replaced Object Link is single-instance) and
   * keytend-kmip-server refuses. Adding a Replaced Object link to the winner for each key it
   * joined would work on 3.0 only on servers that do not enforce that. Each joined key gets its own Replacement Object link to the winner and the
   * winner nothing; every walk takes the joined key for no newest key, so everything else is as
   * before: everyone chooses the winner, the joined keys are Deactivated and still decrypt, a stale
   * handle on one names the winner, and the lineage deactivates and retires from the winner.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void reconcileGivesNoKeyASecondLink(KmipVersion version) throws Exception {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Stale stale = new Stale();
    Kms kms = connect(s, clock, stale, UnaryOperator.identity());
    KeyHandle k0 = aes(kms).create();
    Map<String, Ciphertext> under = new LinkedHashMap<>();
    under.put(k0.id(), k0.encrypt(CipherSpec.keyWrap(), WRAPPABLE));
    // Three callers rotated k0 at once, on a server that re-keys a key twice.
    List<String> tips = new ArrayList<>();
    for (int i = 0; i < 3; i++) tips.add(RotationAndNameChoiceTest.reKey(kms, k0.id()));
    for (String t : tips)
      under.put(t, kms.keys().handle(t).encrypt(CipherSpec.keyWrap(), WRAPPABLE));
    KeyHandle winner = k0.reconcile();
    for (String id : s.ids())
      if (!id.equals(k0.id())) // its three are the server's own Re-keys
      for (LinkKind kind : List.of(LinkKind.REPLACEMENT, LinkKind.REPLACED))
          assertTrue(
              s.links(id, kind).size() <= 1, id + " has " + kind + " links " + s.links(id, kind));
    assertEquals(
        List.of(k0.id()),
        s.links(winner.id(), LinkKind.REPLACED),
        "nothing is added to the winner");
    assertEquals(List.of(), s.links(winner.id(), LinkKind.REPLACEMENT));
    List<String> joined = tips.stream().filter(t -> !t.equals(winner.id())).toList();
    assertEquals(2, joined.size());
    for (String t : joined) {
      assertEquals(
          List.of(winner.id()), s.links(t, LinkKind.REPLACEMENT), t + " is joined into the winner");
      assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(t));
      KeyHandle loser = kms.keys().handle(t);
      assertEquals(winner, loser.latest());
      assertFalse(loser.isLatest());
      assertTrue(stale.events.contains(t + " -> [" + winner.id() + "]"), stale.events.toString());
      StateConflictException again = assertThrows(StateConflictException.class, loser::rotate);
      assertTrue(
          again.getMessage().contains("already replaced by " + winner.id()), again.getMessage());
      assertEquals(winner, loser.rotateOrLatest());
    }
    assertEquals(winner, k0.latest());
    assertTrue(winner.isLatest());
    assertEquals(Optional.of(winner), kms.keys().findByName(NAME));
    for (Ciphertext c : under.values()) {
      assertArrayEquals(WRAPPABLE, winner.decrypt(c, null));
      assertArrayEquals(WRAPPABLE, kms.keys().decrypt(KeyQuery.byName(NAME), c, null));
      for (String t : joined) assertArrayEquals(WRAPPABLE, kms.keys().handle(t).decrypt(c, null));
    }
    // A repeat adds nothing.
    int adds = sent(s, Operation.ADD_ATTRIBUTE);
    assertEquals(winner, k0.reconcile());
    assertEquals(adds, sent(s, Operation.ADD_ATTRIBUTE));
    // The rest of the lifecycle, from the winner: reconcile deactivated the older keys already.
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(k0.id()));
    assertEquals(List.of(), ids(winner.deactivatePredecessors()));
    List<KeyHandle> retired = winner.retirePredecessors(RevocationReason.superseded("retired"));
    // The joined keys first (they reach the winner only through k0), then k0.
    assertEquals(Set.copyOf(joined), Set.copyOf(ids(retired.subList(0, 2))));
    assertEquals(k0.id(), retired.get(2).id());
    assertEquals(List.of(), s.violations());
  }

  /** Adds a link of {@code type} from {@code from} to {@code to} by hand, in the version's form. */
  static void link(Kms kms, String from, Enums.LinkType type, String to) throws Exception {
    if (kms.protocolVersion() != ProtocolVersion.V3_0) {
      KmsContractTest.link(kms, from, type, to);
      return;
    }
    Tag tag = ModernAttributes.linkAttribute(type.code()).orElseThrow();
    kms.protocol()
        .call(
            Requests.addAttribute()
                .uniqueIdentifier(from)
                .newAttribute(Ttlv.reference(tag, to))
                .build());
  }

  /**
   * The fake: like keytend-kmip-server, the in-memory server refuses a client's second Replacement
   * Object link on every version (Invalid Field in 1.x, Attribute Single Valued from 2.0) and, in
   * 3.0, a second link of any single-instance type, the Replaced Object Link included (Attribute
   * Single Valued); before 3.0 a second Replaced Object link is accepted, as there.
   * {@code linkCardinality(false)} adds every link.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void theFakeRefusesASecondSingleInstanceLink(KmipVersion version) throws Exception {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    KeyHandle k = aes(kms).create();
    KeyHandle a = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create(),
        b = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
    Enums.ResultReason single =
        version.atLeast(KmipVersion.V2_0)
            ? Enums.ResultReason.ATTRIBUTE_SINGLE_VALUED
            : Enums.ResultReason.INVALID_FIELD;
    link(kms, k.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, a.id());
    KmipException second =
        assertThrows(
            KmipException.class,
            () -> link(kms, k.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, b.id()));
    assertEquals(Optional.of(single), second.reason());
    assertEquals(List.of(a.id()), s.links(k.id(), LinkKind.REPLACEMENT));
    link(kms, k.id(), Enums.LinkType.REPLACED_OBJECT_LINK, a.id());
    if (version == KmipVersion.V3_0) {
      KmipException replaced =
          assertThrows(
              KmipException.class,
              () -> link(kms, k.id(), Enums.LinkType.REPLACED_OBJECT_LINK, b.id()));
      assertEquals(Optional.of(Enums.ResultReason.ATTRIBUTE_SINGLE_VALUED), replaced.reason());
      assertEquals(List.of(a.id()), s.links(k.id(), LinkKind.REPLACED));
    } else {
      link(kms, k.id(), Enums.LinkType.REPLACED_OBJECT_LINK, b.id());
      assertEquals(List.of(a.id(), b.id()), s.links(k.id(), LinkKind.REPLACED));
    }
    s.linkCardinality(false);
    link(kms, k.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, b.id());
    assertEquals(List.of(a.id(), b.id()), s.links(k.id(), LinkKind.REPLACEMENT));
    assertEquals(List.of(), s.violations());
  }

  /**
   * A lineage an older client joined, with several Replaced Object links on the winner, is
   * read as any other, on a server that enforces the cardinality: every key's {@code latest()}
   * and {@code findByName} choose the winner, every record decrypts through every key, {@code
   * reconcile()} adds nothing, and {@code retirePredecessors} retires the old key and the joined
   * ones (they are keys the winner replaced, confirmed by both links), oldest first.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aLineageAnEarlierVersionJoinedStillReads(KmipVersion version) throws Exception {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock).linkCardinality(false);
    Kms kms = connect(s, clock);
    KeyHandle k0 = aes(kms).create();
    String a = RotationAndNameChoiceTest.reKey(kms, k0.id()),
        b = RotationAndNameChoiceTest.reKey(kms, k0.id()),
        c = RotationAndNameChoiceTest.reKey(kms, k0.id());
    Map<String, Ciphertext> under = new LinkedHashMap<>();
    for (String id : List.of(k0.id(), a, b, c))
      under.put(id, kms.keys().handle(id).encrypt(CipherSpec.keyWrap(), WRAPPABLE));
    // Such a client's reconcile: the winner's Replaced Object link first, then the joined key's
    // link back.
    for (String joined : List.of(b, c)) {
      KmsContractTest.link(kms, a, Enums.LinkType.REPLACED_OBJECT_LINK, joined);
      KmsContractTest.link(kms, joined, Enums.LinkType.REPLACEMENT_OBJECT_LINK, a);
      kms.keys().handle(joined).revoke(RevocationReason.superseded("reconciled into " + a));
    }
    assertEquals(3, s.links(a, LinkKind.REPLACED).size());
    s.linkCardinality(true);
    Kms later = connect(s, clock);
    for (String id : List.of(k0.id(), a, b, c)) {
      assertEquals(a, later.keys().handle(id).latest().id(), id);
      for (Ciphertext ct : under.values())
        assertArrayEquals(WRAPPABLE, later.keys().handle(id).decrypt(ct, null));
    }
    assertEquals(a, later.keys().findByName(NAME).orElseThrow().id());
    int adds = sent(s, Operation.ADD_ATTRIBUTE);
    assertEquals(a, later.keys().handle(k0.id()).reconcile().id());
    assertEquals(adds, sent(s, Operation.ADD_ATTRIBUTE), "nothing is added to old data");
    List<KeyHandle> retired =
        later.keys().handle(a).retirePredecessors(RevocationReason.superseded("retired"));
    assertEquals(k0.id(), retired.get(0).id(), "oldest first");
    assertEquals(Set.of(k0.id(), b, c), Set.copyOf(ids(retired)));
    assertEquals(List.of(), s.violations());
  }

  /**
   * {@code findByName} takes a key joined into another key of its lineage for no newest
   * key, as {@code latest()} does, also before reconcile has moved the names: two newest keys
   * with the name, the one created first joined into the other, and both lookups choose the other
   * (by Initial Date and identifier alone the joined one would rank first).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void findByNameAgreesWithLatestOnAJoinedKey(KmipVersion version) throws Exception {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    KeyHandle k0 = aes(kms).create();
    KeyHandle first = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, k0.id()));
    KeyHandle second = kms.keys().handle(RotationAndNameChoiceTest.reKey(kms, k0.id()));
    second.addName(NAME);
    assertEquals(first, k0.latest());
    assertEquals(Optional.of(first), kms.keys().findByName(NAME));
    link(kms, first.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, second.id());
    assertEquals(second, k0.latest());
    assertEquals(second, first.latest());
    assertEquals(Optional.of(second), kms.keys().findByName(NAME));
    assertEquals(List.of(), s.violations());
  }

  /**
   * A key reconcile joined in that is later found compromised is recovered through the
   * winner: {@code compromisedPredecessors()} of the winner lists it, and its {@code
   * replaceCompromised} finishes with the winner, the newest key descending from it through the
   * join, without a Re-key or a new key (also for a join of two links).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aJoinedKeyFoundCompromisedIsRecoveredThroughTheWinner(KmipVersion version) throws Exception {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    KeyHandle k0 = aes(kms).create();
    String a = RotationAndNameChoiceTest.reKey(kms, k0.id()),
        b = RotationAndNameChoiceTest.reKey(kms, k0.id());
    Map<String, byte[]> records =
        Map.of(
            a,
            kms.keys().handle(a).seal(utf8("a"), AAD),
            b,
            kms.keys().handle(b).seal(utf8("b"), AAD));
    KeyHandle winner = k0.reconcile();
    String loser = winner.id().equals(a) ? b : a;
    kms.keys().handle(loser).revoke(RevocationReason.keyCompromise("leaked", clock.now));
    assertEquals(List.of(loser), ids(winner.compromisedPredecessors()));
    int reKeys = sent(s, Operation.RE_KEY), creates = sent(s, Operation.CREATE);
    assertEquals(
        winner,
        kms.keys()
            .handle(loser)
            .replaceCompromised(RevocationReason.keyCompromise("leaked", clock.now)));
    assertEquals(reKeys, sent(s, Operation.RE_KEY));
    assertEquals(creates, sent(s, Operation.CREATE));
    KeyHandle view = winner.compromisedPredecessors().get(0);
    assertArrayEquals(utf8(loser.equals(a) ? "a" : "b"), view.open(records.get(loser), AAD));
    assertThrows(StateConflictException.class, () -> winner.open(records.get(loser), AAD));
    assertEquals(List.of(), s.violations());
  }

  /**
   * Two instances replace one
   * Compromised key at once on a server that refuses its Re-key (each creates a key and links it by
   * hand) and allows one Replacement Object link, as KMIP does. The second caller's link to the old
   * key is refused because the first caller's is there. Reporting that as a server that refuses
   * links ({@code PartialCompletionException}, "do not repeat") would leave its own key Active,
   * named and unlinked: two current keys, one outside the lineage (records the Storm could not open
   * by name). It is a lost race, as a refused second Re-key: the second caller finishes with the
   * first caller's replacement and returns it, the listener hears of it, and its own key stays
   * Pre-Active, unnamed and unlinked (it never encrypted; nothing is destroyed).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aCompromiseReplacementThatLosesTheLinkRaceUsesTheWinners(KmipVersion version)
      throws Exception {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock).uniqueNames(true);
    Kms admin = connect(s, clock);
    KeyHandle k0 = aes(admin).create();
    byte[] record = k0.seal(utf8("record"), AAD);
    k0.revoke(RevocationReason.keyCompromise("leaked", clock.now));
    java.util.concurrent.CountDownLatch bAtCreate = new java.util.concurrent.CountDownLatch(1),
        aDone = new java.util.concurrent.CountDownLatch(1);
    List<String> heard = new CopyOnWriteArrayList<>();
    KmsListener listener =
        new KmsListener() {
          @Override
          public void concurrentReplacement(String keyId, List<String> replacements) {
            heard.add(keyId + " -> " + replacements);
          }
        };
    Kms a =
        connect(
            s,
            clock,
            null,
            r -> {
              if (RotationAndNameChoiceTest.isOperation(r, Operation.RE_KEY))
                s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
              return r;
            });
    Kms b =
        connect(
            s,
            clock,
            listener,
            r -> {
              if (RotationAndNameChoiceTest.isOperation(r, Operation.RE_KEY))
                s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
              if (RotationAndNameChoiceTest.isOperation(r, Operation.CREATE)) {
                bAtCreate.countDown();
                try {
                  assertTrue(aDone.await(20, java.util.concurrent.TimeUnit.SECONDS));
                } catch (InterruptedException e) {
                  throw new IllegalStateException(e);
                }
              }
              return r;
            });
    java.util.concurrent.ExecutorService pool =
        java.util.concurrent.Executors.newSingleThreadExecutor();
    try {
      java.util.concurrent.Future<KeyHandle> fb =
          pool.submit(
              () ->
                  b.keys()
                      .handle(k0.id())
                      .replaceCompromised(RevocationReason.keyCompromise("leaked", clock.now)));
      assertTrue(bAtCreate.await(20, java.util.concurrent.TimeUnit.SECONDS));
      KeyHandle ra =
          a.keys()
              .handle(k0.id())
              .replaceCompromised(RevocationReason.keyCompromise("leaked", clock.now));
      aDone.countDown();
      KeyHandle rb = fb.get(20, java.util.concurrent.TimeUnit.SECONDS);
      assertEquals(
          ra.id(), rb.id(), "the second caller finishes with the first caller's replacement");
      assertEquals(List.of(k0.id() + " -> [" + ra.id() + "]"), heard);
      assertEquals(List.of(ra.id()), s.links(k0.id(), LinkKind.REPLACEMENT));
      assertEquals(List.of(k0.id()), s.links(ra.id(), LinkKind.REPLACED));
      assertEquals(Optional.of(KeyState.ACTIVE), s.state(ra.id()));
      assertEquals(List.of(NAME), s.names(ra.id()));
      List<String> others =
          s.ids().stream().filter(id -> !id.equals(k0.id()) && !id.equals(ra.id())).toList();
      assertEquals(1, others.size(), "the second caller's own key");
      String left = others.get(0);
      assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(left));
      assertEquals(List.of(), s.names(left));
      assertEquals(List.of(), s.links(left, LinkKind.REPLACED));
      assertEquals(List.of(), s.links(left, LinkKind.REPLACEMENT));
      assertEquals(Optional.of(ra.id()), admin.keys().findByName(NAME).map(KeyHandle::id));
      assertArrayEquals(utf8("record"), ra.compromisedPredecessors().get(0).open(record, AAD));
    } finally {
      aDone.countDown();
      pool.shutdownNow();
    }
    assertEquals(List.of(), s.violations());
  }

  // ---- the DEACTIVATED refusal says what the requested dates would do ----

  /**
   * A routine rotation of a Deactivated key is refused before any Re-key, and the message
   * matches the dates requested: "a Re-key copies its Deactivation Date, so the replacement
   * would be Deactivated too" is the copied form's reason, not that of {@code RotationDates.SHIFTED},
   * whose Offset moves that date forward instead, and which says so.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void theDeactivatedRefusalSaysWhatTheRequestedDatesWouldDo(KmipVersion version) {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    KeyHandle key = aes(kms).create();
    key.revoke(RevocationReason.superseded("retired by hand"));
    String copies = "a Re-key copies its Deactivation Date";
    List<org.junit.jupiter.api.function.Executable> copied =
        List.of(key::rotate, key::rotateOrLatest, () -> key.rotateIfActiveFor(Duration.ZERO));
    List<org.junit.jupiter.api.function.Executable> shifted =
        List.of(
            () -> key.rotate(Rotation.of(RotationDates.SHIFTED)),
            () -> key.rotateOrLatest(Rotation.of(RotationDates.SHIFTED)),
            () -> key.rotateIfActiveFor(Duration.ZERO, Rotation.of(RotationDates.SHIFTED)),
            () -> kms.keys().current(key).rotateOrLatest(Rotation.of(RotationDates.SHIFTED)));
    for (org.junit.jupiter.api.function.Executable call : copied) {
      StateConflictException e = assertThrows(StateConflictException.class, call);
      assertEquals(Optional.of(KeyState.DEACTIVATED), e.observedState());
      assertTrue(e.getMessage().contains(copies), e.getMessage());
    }
    for (org.junit.jupiter.api.function.Executable call : shifted) {
      StateConflictException e = assertThrows(StateConflictException.class, call);
      assertEquals(Optional.of(KeyState.DEACTIVATED), e.observedState());
      assertFalse(e.getMessage().contains(copies), e.getMessage());
      assertTrue(
          e.getMessage()
              .contains(
                  "RotationDates.SHIFTED sends would move "
                      + key.id()
                      + "'s Deactivation Date forward"),
          e.getMessage());
    }
    assertEquals(0, sent(s, Operation.RE_KEY));
    assertEquals(List.of(), s.violations());
  }

  // ---- a scheduled grace period ----

  /** Whether {@code request} sets a Deactivation Date, in any version's form. */
  static boolean setsDeactivationDate(Ttlv request) {
    return (RotationAndNameChoiceTest.isOperation(request, Operation.ADD_ATTRIBUTE)
            || RotationAndNameChoiceTest.isOperation(request, Operation.MODIFY_ATTRIBUTE)
            || RotationAndNameChoiceTest.isOperation(request, Operation.SET_ATTRIBUTE))
        && carries(request, Tag.DEACTIVATION_DATE);
  }

  static boolean carries(Ttlv node, Tag tag) {
    if (node.tag() == tag.code()) return true;
    if (node.type() == Ttlv.Type.TEXT_STRING
        && node.textValue().equals("Deactivation Date")
        && tag == Tag.DEACTIVATION_DATE) return true;
    return node.type() == Ttlv.Type.STRUCTURE
        && node.children().stream().anyMatch(c -> carries(c, tag));
  }

  /** The operations sent to {@code s} since request number {@code from}, in order. */
  static List<String> operations(InMemoryKmipServer s, int from) {
    List<String> out = new ArrayList<>();
    List<Ttlv> all = s.protocolRequests();
    for (Ttlv r : all.subList(from, all.size()))
      for (Ttlv item : r.children(Tag.BATCH_ITEM)) {
        Operation op = Operation.fromCode(item.require(Tag.OPERATION).intValue());
        out.add(
            op == Operation.RE_KEY
                ? "ReKey"
                : setsDeactivationDate(r) ? "SetDeactivation" : op.name());
      }
    return out;
  }

  /**
   * {@code rotate(Rotation.grace(...))} rotates, then gives the old key, and only it, a
   * Deactivation Date of now plus the grace period: the old key keeps encrypting until the second
   * before, and is Deactivated from then on (it still decrypts); the replacement has no
   * Deactivation Date from it, or exactly the one its {@code RotationDates} gives it (a policy's
   * date copied, or moved forward by an Offset). The date is set after the Re-key, which copies
   * dates. A grace never extends a key's life: an old key whose own date comes sooner keeps it,
   * and nothing is sent.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void aRotationWithAGracePeriodDeactivatesTheOldKeyWhenItEnds(KmipVersion version)
      throws Exception {
    Duration week = Duration.ofDays(7);
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    KeyHandle k0 = aes(kms).create();
    Ciphertext before = k0.encrypt(CipherSpec.keyWrap(), WRAPPABLE);
    int from = s.protocolRequests().size();
    KeyHandle k1 = k0.rotate(Rotation.grace(week));
    List<String> sent = operations(s, from);
    assertTrue(
        sent.contains("ReKey") && sent.indexOf("ReKey") < sent.indexOf("SetDeactivation"),
        sent.toString());
    assertEquals(1, Collections.frequency(sent, "SetDeactivation"), sent.toString());
    assertEquals(Optional.of(START.plus(week)), k0.attributes().deactivationDate());
    assertEquals(
        Optional.empty(),
        k1.attributes().deactivationDate(),
        "the replacement copies no grace date");
    clock.now = START.plus(week).minusSeconds(1);
    assertNotNull(
        k0.encrypt(CipherSpec.keyWrap(), WRAPPABLE), "fully Active during the grace period");
    clock.now = START.plus(week);
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(k0.id()));
    assertArrayEquals(WRAPPABLE, k1.decrypt(before, null));
    StateConflictException refused =
        assertThrows(
            StateConflictException.class, () -> k0.encrypt(CipherSpec.keyWrap(), WRAPPABLE));
    assertEquals(Optional.of(KeyState.DEACTIVATED), refused.observedState());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(k1.id()));

    // A key with a policy's Deactivation Date 90 days on: the replacement gets its own as the
    // dates ask, the old key the grace date.
    clock.now = START;
    for (RotationDates dates : RotationDates.values()) {
      KeyHandle p0 = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
      deactivationDate(kms, p0.id(), START.plus(Duration.ofDays(90)), false);
      clock.now = START.plus(DAY);
      KeyHandle p1;
      try {
        p1 = p0.rotate(Rotation.grace(week).dates(dates));
      } catch (KmsException e) {
        // KMIP 1.2 has no Offset
        assertEquals(RotationDates.SHIFTED, dates, e.toString());
        assertEquals(KmipVersion.V1_2, version, e.toString());
        clock.now = START;
        continue;
      }
      assertEquals(
          Optional.of(START.plus(DAY).plus(week)),
          p0.attributes().deactivationDate(),
          dates.toString());
      assertEquals(
          Optional.of(
              dates == RotationDates.COPIED
                  ? START.plus(Duration.ofDays(90))
                  : START.plus(DAY).plus(Duration.ofDays(90))),
          p1.attributes().deactivationDate(),
          dates.toString());
      clock.now = START;
    }

    // An old key whose own date comes sooner keeps it, and nothing is sent.
    KeyHandle soon = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    deactivationDate(kms, soon.id(), START.plus(Duration.ofDays(3)), false);
    from = s.protocolRequests().size();
    soon.rotate(Rotation.grace(week));
    assertFalse(operations(s, from).contains("SetDeactivation"), operations(s, from).toString());
    assertEquals(Optional.of(START.plus(Duration.ofDays(3))), soon.attributes().deactivationDate());
    assertEquals(List.of(), s.violations());
  }

  /**
   * The grace works with every rotation form: {@code rotateOrLatest}, {@code
   * rotateIfActiveFor} (only when it rotates), and the {@code CurrentKey} forms. A repeat of {@code
   * rotateOrLatest} from the old key's handle schedules the old key when an earlier call did not
   * (and sends nothing when it did); {@code Rotation.grace(ZERO)} deactivates the old key at once.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void theGraceWorksWithEveryRotationForm(KmipVersion version) throws Exception {
    Duration week = Duration.ofDays(7), month = Duration.ofDays(30);
    Rotation policy = Rotation.grace(week);
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    KeyHandle k0 = aes(kms).create();
    // rotateIfActiveFor: not due, nothing; due, rotated and the old key scheduled.
    int from = s.protocolRequests().size();
    assertEquals(k0, k0.rotateIfActiveFor(month, policy));
    assertFalse(operations(s, from).contains("SetDeactivation"));
    clock.now = START.plus(month);
    KeyHandle k1 = k0.rotateIfActiveFor(month, policy);
    assertNotEquals(k0.id(), k1.id());
    assertEquals(Optional.of(START.plus(month).plus(week)), k0.attributes().deactivationDate());
    // rotateOrLatest from k0 again: rotated already, and scheduled already: no Re-key, no date.
    from = s.protocolRequests().size();
    assertEquals(k1.id(), k0.rotateOrLatest(policy).id());
    assertFalse(operations(s, from).contains("ReKey"));
    assertFalse(operations(s, from).contains("SetDeactivation"));
    // A rotation made without the grace is finished by a repeat with it.
    KeyHandle k2 = k1.rotate();
    assertEquals(Optional.empty(), k1.attributes().deactivationDate());
    assertEquals(k2.id(), k1.rotateOrLatest(policy).id());
    assertEquals(Optional.of(START.plus(month).plus(week)), k1.attributes().deactivationDate());
    // The CurrentKey forms hold the replacement.
    CurrentKey current = kms.keys().current(k2);
    clock.now = START.plus(month).plus(month);
    KeyHandle k3 = current.rotateIfActiveFor(month, policy);
    assertEquals(k3, current.handle());
    assertEquals(Optional.of(clock.now.plus(week)), k2.attributes().deactivationDate());
    KeyHandle k4 = current.rotateOrLatest(Rotation.grace(Duration.ZERO));
    assertEquals(k4, current.handle());
    assertEquals(
        Optional.of(KeyState.DEACTIVATED), s.state(k3.id()), "a grace of zero deactivates at once");
    assertThrows(IllegalArgumentException.class, () -> Rotation.grace(Duration.ofSeconds(-1)));
    assertEquals(
        Rotation.grace(week).dates(RotationDates.SHIFTED),
        Rotation.grace(week).dates(RotationDates.SHIFTED));
    assertEquals(Optional.empty(), Rotation.of(RotationDates.COPIED).gracePeriod());
    assertEquals(List.of(), s.violations());
  }

  /**
   * On a server that does not let a client set a Deactivation Date (keytend-kmip-server: Attribute
   * Read Only, Permission Denied in 1.x; {@code refuseClientDeactivationDate(true)}), a rotation
   * with a grace period is not a silent success: the rotation is made, the old key stays Active with
   * no date, and the call ends in a {@code PartialCompletionException} whose {@code created()} is
   * the replacement and whose message says to run {@code deactivatePredecessors()} from it once the
   * grace period is over, which then works. A {@code CurrentKey} holds the replacement before it
   * throws.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void aServerThatWillNotScheduleTheGraceSaysSo(KmipVersion version) throws Exception {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock).refuseClientDeactivationDate(true);
    Kms kms = connect(s, clock);
    KeyHandle k0 = aes(kms).create();
    PartialCompletionException e =
        assertThrows(PartialCompletionException.class, () -> k0.rotate(Rotation.grace(DAY)));
    assertEquals(1, e.created().size());
    KeyHandle k1 = e.created().get(0);
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(k1.id()));
    assertEquals(List.of(k0.id()), s.links(k1.id(), LinkKind.REPLACED));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(k0.id()));
    assertEquals(Optional.empty(), k0.attributes().deactivationDate());
    assertEquals(
        Optional.of(
            version.atLeast(KmipVersion.V2_0)
                ? Enums.ResultReason.ATTRIBUTE_READ_ONLY
                : Enums.ResultReason.PERMISSION_DENIED),
        e.protocolReason());
    assertTrue(
        e.getMessage().contains("did not let this client set " + k0.id() + "'s Deactivation Date"),
        e.getMessage());
    assertTrue(
        e.getMessage().contains("run deactivatePredecessors() from " + k1.id()), e.getMessage());
    assertEquals(KmsException.Category.PARTIAL, e.category());
    // The CurrentKey form holds the new key all the same.
    CurrentKey current = kms.keys().current(k1);
    PartialCompletionException again =
        assertThrows(
            PartialCompletionException.class,
            () -> current.rotateIfActiveFor(Duration.ZERO, Rotation.grace(DAY)));
    KeyHandle k2 = again.created().get(0);
    assertEquals(k2, current.handle());
    // What the message says to do instead, after the grace period.
    clock.now = START.plus(DAY);
    assertEquals(List.of(k0.id(), k1.id()), ids(k2.deactivatePredecessors()));
    assertEquals(List.of(), s.violations());
  }

  /**
   * A lost reply of the date's request is read back, and the rotation succeeds; a
   * failure that is not a refusal (Server Failure) ends in a {@code PartialCompletionException}
   * saying to repeat {@code rotateOrLatest} from the old key's handle, which then schedules it
   * without a second Re-key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostOrFailedScheduleIsReadBackOrResumed(KmipVersion version) throws Exception {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms =
        connect(
            s,
            clock,
            null,
            r -> {
              if (setsDeactivationDate(r) && lose.get() != null)
                s.failNext(ServerOperation.ADD_ATTRIBUTE, lose.getAndSet(null));
              return r;
            });
    KeyHandle k0 = aes(kms).create();
    lose.set(Fault.REPLY_LOST);
    KeyHandle k1 = k0.rotate(Rotation.grace(DAY));
    assertEquals(Optional.of(START.plus(DAY)), k0.attributes().deactivationDate());
    lose.set(Fault.SERVER_FAILURE);
    PartialCompletionException e =
        assertThrows(PartialCompletionException.class, () -> k1.rotate(Rotation.grace(DAY)));
    KeyHandle k2 = e.created().get(0);
    assertTrue(
        e.getMessage().contains("repeat rotateOrLatest(rotation) from " + k1.id() + "'s handle"),
        e.getMessage());
    assertEquals(Optional.empty(), k1.attributes().deactivationDate());
    int reKeys = sent(s, Operation.RE_KEY);
    assertEquals(k2.id(), k1.rotateOrLatest(Rotation.grace(DAY)).id());
    assertEquals(reKeys, sent(s, Operation.RE_KEY));
    assertEquals(Optional.of(START.plus(DAY)), k1.attributes().deactivationDate());
    assertEquals(List.of(), s.violations());
  }

  final java.util.concurrent.atomic.AtomicReference<Fault> lose =
      new java.util.concurrent.atomic.AtomicReference<>();

  // ---- replaceCompromised with the dates the caller asks for ----

  /**
   * A key retired by hand a week after activation, then found compromised. {@code
   * replaceCompromised(reason)} takes the week for a policy's cryptoperiod (a span of a day or
   * more) and gives the replacement a Deactivation Date a week from the recovery, which nobody set;
   * the server cannot say it was a revocation (keytend-kmip-server keeps no Revocation Reason).
   * {@code replaceCompromised(reason, COPIED)} makes a new key without dates instead (no Re-key,
   * linked by hand, Active, no Deactivation Date), and {@code SHIFTED} carries the span whatever it
   * is, also for a key retired within the hour. A key not retired is re-keyed without an Offset with
   * {@code COPIED}.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void replaceCompromisedTakesTheDatesTheCallerAsksFor(KmipVersion version) {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock);
    Kms kms = connect(s, clock);
    Duration week = Duration.ofDays(7), hour = Duration.ofHours(1);
    java.util.function.Function<Duration, KeyHandle> retiredAfter =
        span -> {
          clock.now = START;
          KeyHandle k =
              kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
          clock.now = START.plus(span);
          k.revoke(RevocationReason.superseded("retired by hand"));
          clock.now = START.plus(Duration.ofDays(20));
          return k;
        };
    RevocationReason leaked =
        RevocationReason.keyCompromise("leaked", START.plus(Duration.ofDays(19)));
    Instant recovery = START.plus(Duration.ofDays(20));

    KeyHandle guessed = retiredAfter.apply(week).replaceCompromised(leaked);
    assertEquals(
        Optional.of(recovery.plus(week)),
        guessed.attributes().deactivationDate(),
        "the guessed date, kept");

    int reKeys = sent(s, Operation.RE_KEY);
    KeyHandle byHand = retiredAfter.apply(week);
    KeyHandle fresh = byHand.replaceCompromised(leaked, Rotation.of(RotationDates.COPIED));
    assertEquals(reKeys, sent(s, Operation.RE_KEY), "a new key, not a Re-key");
    assertEquals(Optional.empty(), fresh.attributes().deactivationDate());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(fresh.id()));
    assertEquals(List.of(byHand.id()), s.links(fresh.id(), LinkKind.REPLACED));
    assertEquals(List.of(byHand.id()), ids(fresh.compromisedPredecessors()));

    KeyHandle shifted =
        retiredAfter.apply(hour).replaceCompromised(leaked, Rotation.of(RotationDates.SHIFTED));
    assertEquals(
        Optional.of(recovery.plus(hour)),
        shifted.attributes().deactivationDate(),
        "the span, however short");

    KeyHandle live = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    reKeys = sent(s, Operation.RE_KEY);
    KeyHandle copied = live.replaceCompromised(leaked, Rotation.of(RotationDates.COPIED));
    assertEquals(reKeys + 1, sent(s, Operation.RE_KEY));
    assertEquals(Optional.empty(), copied.attributes().deactivationDate());
    assertEquals(List.of(live.id()), ids(copied.compromisedPredecessors()));
    assertEquals(List.of(), s.violations());
  }

  // ---- the whole lifecycle ----

  static java.util.stream.Stream<Arguments> lifecycles() {
    return java.util.stream.Stream.of(
            KmipVersion.V1_4, KmipVersion.V2_0, KmipVersion.V2_1, KmipVersion.V3_0)
        .flatMap(v -> java.util.stream.Stream.of(Arguments.of(v, false), Arguments.of(v, true)));
  }

  /**
   * The lifecycle of docs/operating-keys.md, "Rotation with a grace period", on a clock the
   * test moves, with a rotation job and two application instances: A follows the key with a {@code
   * CurrentKey}, B holds a handle it looked up at startup and never refreshes on its own; C starts
   * after the rotation. (1) Day 30: the job rotates with a 7-day grace. (2) During the grace period
   * A and B still seal under the old key, C under the new one, and every record opens everywhere.
   * (3) Day 37: the old key is Deactivated, by its date (or, on a server that refused to schedule
   * it, by the job's {@code deactivatePredecessors()}, as the {@code PartialCompletionException}
   * said), while A and B seal on two threads: A's {@code CurrentKey} moves on its first refused
   * seal, B's refused handle names the replacement and fires {@code staleHandle}, and B follows
   * with {@code latest()}; nothing sealed is lost and the old records open. (4) The job re-wraps
   * every record and retires the old key. (5) Everything re-wrapped opens through every instance,
   * and an old record not re-wrapped does not.
   */
  @ParameterizedTest(name = "{0} refusing={1}")
  @MethodSource("lifecycles")
  void theWholeGraceLifecycle(KmipVersion version, boolean refusing) throws Exception {
    Duration week = Duration.ofDays(7), month = Duration.ofDays(30);
    Rotation policy = Rotation.grace(week);
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(START);
    InMemoryKmipServer s = server(version, clock).refuseClientDeactivationDate(refusing);
    Kms job = connect(s, clock), a = connect(s, clock);
    Stale stale = new Stale();
    Kms b = connect(s, clock, stale, UnaryOperator.identity());
    KeyHandle k0 = aes(job).create();
    CurrentKey ka = a.keys().current(NAME);
    KeyHandle kb = b.keys().findByName(NAME).orElseThrow();
    Map<String, byte[]> records = new java.util.concurrent.ConcurrentHashMap<>();
    records.put("a0", ka.seal(utf8("a0"), AAD));
    records.put("b0", kb.seal(utf8("b0"), AAD));

    // (1) Day 30: the scheduled job rotates.
    clock.now = START.plus(month).minusSeconds(1);
    assertEquals(
        k0,
        job.keys().findByName(NAME).orElseThrow().rotateIfActiveFor(month, policy),
        "not due before day 30");
    clock.now = START.plus(month);
    KeyHandle k1;
    if (!refusing) {
      k1 = job.keys().findByName(NAME).orElseThrow().rotateIfActiveFor(month, policy);
      assertEquals(Optional.of(clock.now.plus(week)), k0.attributes().deactivationDate());
    } else {
      PartialCompletionException e =
          assertThrows(
              PartialCompletionException.class,
              () -> job.keys().findByName(NAME).orElseThrow().rotateIfActiveFor(month, policy));
      k1 = e.created().get(0);
      assertEquals(Optional.empty(), k0.attributes().deactivationDate());
    }
    assertNotEquals(k0.id(), k1.id());
    Instant end = clock.now.plus(week);

    // (2) The grace period: everyone seals; the old key still encrypts for those that hold it.
    clock.now = START.plus(month).plus(DAY);
    Kms c = connect(s, clock);
    records.put("a1", ka.seal(utf8("a1"), AAD));
    records.put("b1", kb.seal(utf8("b1"), AAD));
    records.put("c1", c.keys().findByName(NAME).orElseThrow().seal(utf8("c1"), AAD));
    assertEquals(k0.id(), KmsKeys.sealedKeyId(records.get("a1")), "A has not checked yet");
    assertEquals(k0.id(), KmsKeys.sealedKeyId(records.get("b1")));
    assertEquals(k1.id(), KmsKeys.sealedKeyId(records.get("c1")));
    assertEquals(List.of(), stale.events, "sealing reads nothing");
    opensEverywhere(records, ka, kb, c);
    // Opening through B's handle reads its key, which names the replacement: B is told.
    assertTrue(stale.events.contains(k0.id() + " -> [" + k1.id() + "]"), stale.events.toString());
    stale.events.clear();

    // (3) The grace period ends while A and B seal on two threads.
    java.util.concurrent.ExecutorService pool =
        java.util.concurrent.Executors.newFixedThreadPool(2);
    java.util.concurrent.atomic.AtomicBoolean flipped =
        new java.util.concurrent.atomic.AtomicBoolean();
    java.util.concurrent.atomic.AtomicReference<KeyHandle> bHandle =
        new java.util.concurrent.atomic.AtomicReference<>(kb);
    java.util.concurrent.CountDownLatch going = new java.util.concurrent.CountDownLatch(2);
    List<String> bRefusals = new CopyOnWriteArrayList<>();
    try {
      java.util.concurrent.Future<?> fa =
          pool.submit(
              () -> {
                going.countDown();
                for (int i = 0; i < 40; i++) records.put("a-" + i, ka.seal(utf8("a-" + i), AAD));
                return null;
              });
      java.util.concurrent.Future<?> fb =
          pool.submit(
              () -> {
                going.countDown();
                for (int i = 0; i < 40; i++) {
                  KeyHandle h = bHandle.get();
                  try {
                    records.put("b-" + i, h.seal(utf8("b-" + i), AAD));
                  } catch (StateConflictException refused) {
                    assertEquals(Optional.of(KeyState.DEACTIVATED), refused.observedState());
                    assertTrue(
                        refused
                            .getMessage()
                            .contains(k0.id() + " names " + k1.id() + " as its replacement"),
                        refused.getMessage());
                    bRefusals.add(refused.getMessage());
                    bHandle.set(h.latest()); // what the staleHandle listener of an application does
                    records.put("b-" + i, bHandle.get().seal(utf8("b-" + i), AAD));
                  }
                }
                return null;
              });
      assertTrue(going.await(10, java.util.concurrent.TimeUnit.SECONDS));
      if (refusing) {
        clock.now = end;
        assertEquals(
            List.of(k0.id()),
            ids(job.keys().findByName(NAME).orElseThrow().deactivatePredecessors()));
      } else clock.now = end;
      flipped.set(true);
      fa.get(20, java.util.concurrent.TimeUnit.SECONDS);
      fb.get(20, java.util.concurrent.TimeUnit.SECONDS);
    } finally {
      pool.shutdownNow();
    }
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(k0.id()));
    // After the deactivation, both instances seal under the new key.
    records.put("a2", ka.seal(utf8("a2"), AAD));
    assertEquals(
        k1.id(), KmsKeys.sealedKeyId(records.get("a2")), "A's CurrentKey moved on a refused seal");
    if (bRefusals.isEmpty()) { // B's thread finished before the date came: its next seal is refused
      assertThrows(StateConflictException.class, () -> bHandle.get().seal(utf8("b2"), AAD));
      bHandle.set(bHandle.get().latest());
    }
    records.put("b2", bHandle.get().seal(utf8("b2"), AAD));
    assertEquals(k1.id(), KmsKeys.sealedKeyId(records.get("b2")));
    assertTrue(stale.events.contains(k0.id() + " -> [" + k1.id() + "]"), stale.events.toString());
    assertEquals(84 + 3, records.size());
    opensEverywhere(records, ka, bHandle.get(), c);
    for (String r : List.of("a0", "a1", "b0", "b1"))
      assertArrayEquals(utf8(r), kb.open(records.get(r), AAD), "the old key's own handle");

    // (4) Re-wrap everything, then retire the old key.
    KeyHandle current = job.keys().findByName(NAME).orElseThrow();
    assertEquals(k1, current);
    byte[] before = records.get("a0");
    for (Map.Entry<String, byte[]> r : records.entrySet()) {
      Rewrapped w = current.rewrapRecord(r.getValue(), AAD);
      assertEquals(k1.id(), KmsKeys.sealedKeyId(w.bytes()));
      r.setValue(w.bytes());
    }
    assertEquals(
        List.of(k0.id()), ids(current.retirePredecessors(RevocationReason.superseded("rotated"))));
    assertEquals(Optional.of(KeyState.DESTROYED), s.state(k0.id()));

    // (5) Everything opens, through every instance; what was not re-wrapped does not.
    opensEverywhere(records, ka, bHandle.get(), c);
    records.put("a3", ka.seal(utf8("a3"), AAD));
    assertArrayEquals(utf8("a3"), c.keys().open(KeyQuery.byName(NAME), records.get("a3"), AAD));
    assertThrows(
        KmsException.class, () -> c.keys().findByName(NAME).orElseThrow().open(before, AAD));
    assertEquals(List.of(), s.violations());
  }

  /** Every record opens through A's {@code CurrentKey}, B's handle, C's name lookup and C's {@code KeyQuery}. */
  static void opensEverywhere(Map<String, byte[]> records, CurrentKey a, KeyHandle b, Kms c) {
    KeyHandle byName = c.keys().findByName(NAME).orElseThrow();
    for (Map.Entry<String, byte[]> r : records.entrySet()) {
      byte[] plain = utf8(r.getKey());
      assertArrayEquals(plain, a.open(r.getValue(), AAD), r.getKey() + " through A");
      assertArrayEquals(plain, b.open(r.getValue(), AAD), r.getKey() + " through B");
      assertArrayEquals(plain, byName.open(r.getValue(), AAD), r.getKey() + " by name");
      assertArrayEquals(
          plain,
          c.keys().open(KeyQuery.byName(NAME), r.getValue(), AAD),
          r.getKey() + " by KeyQuery");
    }
  }
}
