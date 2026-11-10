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

import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.UnaryOperator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Retired keys found compromised, reconcile and links on the KMIP 3.0 draft, Re-key with an Offset
 * after a cryptoperiod, unlinked replacements, server policies' Deactivation Dates, and refusals
 * that say which state they found.
 */
class RetiredKeyReplacementTest {
  static final byte[] AAD = "record".getBytes(StandardCharsets.UTF_8);

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
    return connect(server, UnaryOperator.identity());
  }

  /** A client of {@code server} whose requests pass through {@code request} on their way. */
  Kms connect(InMemoryKmipServer server, UnaryOperator<Ttlv> request) {
    Kms kms =
        Kms.connect(
            server.configure().transport(e -> r -> server.exchange(request.apply(r))).build());
    clients.add(kms);
    return kms;
  }

  /** {@code node} with every node below it (and itself) passed through {@code change}. */
  static Ttlv rewrite(Ttlv node, UnaryOperator<Ttlv> change) {
    if (node.type() != Ttlv.Type.STRUCTURE) return change.apply(node);
    List<Ttlv> children = new ArrayList<>();
    for (Ttlv c : node.children()) children.add(rewrite(c, change));
    return change.apply(Ttlv.structure(node.tag(), children));
  }

  static RevocationReason leaked() {
    return RevocationReason.keyCompromise("an old backup leaked", Instant.now());
  }

  // ---- a retired key found compromised ----

  /**
   * A vault's current key is
   * retired (revoked as superseded, no replacement), then found compromised, and the documented
   * recovery runs: {@code replaceCompromised}, then re-sealing from {@code
   * compromisedPredecessors()} and destroying them. At KMIP 3.0 a replacement made without links
   * (the 1.x/2.x Link structure refused before it is sent, and taken for the server refusing links)
   * would leave {@code compromisedPredecessors()} empty: the records quarantined and the compromised
   * key left. The links are 3.0's own attributes, on every version the recovery finds the old key, also from a process that only
   * finds the replacement by name, and every record is re-sealed.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRetiredKeyFoundCompromisedIsRecoveredByTheRunbook(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms).create();
    Map<String, byte[]> records = new LinkedHashMap<>();
    for (String r : List.of("r0", "r1"))
      records.put(r, key.seal(r.getBytes(StandardCharsets.UTF_8), AAD));
    key.revoke(RevocationReason.superseded("retired"));

    int reKeys = ReplicaRaceTest.reKeys(s);
    KeyHandle replacement = kms.keys().handle(key.id()).replaceCompromised(leaked());

    // Retired seconds after it was activated: a Re-key with an Offset would give a replacement
    // retired as soon, so a new key, linked by hand.
    assertEquals(reKeys, ReplicaRaceTest.reKeys(s));
    assertNotEquals(key.id(), replacement.id());
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(replacement.id()));
    assertEquals(List.of(key.id()), s.links(replacement.id(), LinkKind.REPLACED), "not linked");
    assertEquals(
        List.of(replacement.id()), s.links(key.id(), LinkKind.REPLACEMENT), "not linked back");
    assertEquals(Optional.of(replacement), kms.keys().findByName(NAME));
    // A process that restarted: it finds the replacement by name, and the compromised key from it.
    Kms restarted = connect(s);
    KeyHandle found = restarted.keys().findByName(NAME).orElseThrow();
    assertEquals(
        List.of(key.id()), found.compromisedPredecessors().stream().map(KeyHandle::id).toList());
    // The documented re-seal (operating-keys.md, "A compromised key"), then the old key goes.
    Map<String, KeyHandle> compromised = new HashMap<>();
    for (KeyHandle k : found.compromisedPredecessors()) compromised.put(k.id(), k);
    int resealed = 0;
    for (Map.Entry<String, byte[]> r : records.entrySet()) {
      KeyHandle from = compromised.getOrDefault(KmsKeys.sealedKeyId(r.getValue()), found);
      r.setValue(from.rewrapTo(found, r.getValue(), AAD));
      resealed++;
    }
    for (KeyHandle k : compromised.values()) k.destroy();
    assertEquals(2, resealed);
    for (Map.Entry<String, byte[]> r : records.entrySet()) {
      assertEquals(replacement.id(), KmsKeys.sealedKeyId(r.getValue()));
      assertArrayEquals(r.getKey().getBytes(StandardCharsets.UTF_8), found.open(r.getValue(), AAD));
    }
    assertEquals(Optional.of(KeyState.DESTROYED_COMPROMISED), s.state(key.id()));
  }

  /**
   * {@code reconcile()} on the KMIP 3.0 draft joins the newest keys of a forked lineage
   * with 3.0's link attributes, not the 1.x/2.x Link structure, which does not exist in 3.0.
   */
  @Test
  void reconcileJoinsTheNewestKeysOnKmip30() throws Exception {
    InMemoryKmipServer s = server(KmipVersion.V3_0);
    Kms kms = connect(s);
    KeyHandle old = aes(kms).create();
    byte[] sealed = old.seal(new byte[] {1, 2, 3}, AAD);
    String a = RotationAndNameChoiceTest.reKey(kms, old.id()),
        b = RotationAndNameChoiceTest.reKey(kms, old.id());
    KeyHandle winner = old.reconcile();
    String other = winner.id().equals(a) ? b : a;
    assertTrue(Set.of(a, b).contains(winner.id()));
    // Joined by its own Replacement Object Link only: 3.0's Replaced Object Link is
    // single-instance,
    // and the winner has one.
    assertEquals(
        List.of(old.id()), s.links(winner.id(), LinkKind.REPLACED), "nothing added to the winner");
    assertEquals(
        List.of(winner.id()), s.links(other, LinkKind.REPLACEMENT), "joined into the winner");
    assertEquals(Optional.of(KeyState.DEACTIVATED), s.state(other));
    assertEquals(winner, kms.keys().handle(other).latest());
    assertEquals(Optional.of(winner), kms.keys().findByName(NAME));
    assertArrayEquals(new byte[] {1, 2, 3}, winner.open(sealed, AAD));
    // A search by link finds the keys the winner replaced, on 3.0 too.
    assertEquals(
        Set.of(old, kms.keys().handle(other)),
        new HashSet<>(kms.keys().list(KeyQuery.all().linkedTo(LinkKind.REPLACEMENT, winner.id()))));
  }

  /**
   * On the KMIP 3.0 draft a Link structure becomes the link type's own attribute (as a
   * Name structure becomes its text), in Add Attribute, in Delete Attribute's Current Attribute and
   * in templates; on 2.1 it stays a Link. The fake carries 3.0's attributes as keytend-kmip-server does:
   * added, reported and deleted as the typed attribute, and a Link structure refused.
   */
  @Test
  void aLinkIsSentAsTheLinkTypesOwnAttributeOnKmip30() throws Exception {
    Ttlv link = Attributes.link(Enums.LinkType.REPLACED_OBJECT_LINK, "k-1");
    assertEquals(
        Ttlv.reference(Tag.REPLACED_OBJECT_LINK, "k-1"),
        ModernAttributes.fromLegacy(link, ProtocolVersion.V3_0));
    assertEquals(
        Ttlv.reference(Tag.REPLACEMENT_OBJECT_LINK, "k-2"),
        ModernAttributes.fromLegacy(
            Attributes.link(Enums.LinkType.REPLACEMENT_OBJECT_LINK, "k-2"), ProtocolVersion.V3_0));
    assertEquals(Tag.LINK.code(), ModernAttributes.fromLegacy(link, ProtocolVersion.V2_1).tag());
    assertEquals(
        Optional.of(Tag.DERIVATION_OBJECT_LINK),
        ModernAttributes.linkAttribute(Enums.LinkType.DERIVATION_BASE_OBJECT_LINK.code()));

    InMemoryKmipServer s = server(KmipVersion.V3_0);
    Kms kms = connect(s);
    KeyHandle a = aes(kms).create(),
        b = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
    kms.protocol()
        .call(
            Requests.addAttribute()
                .uniqueIdentifier(b.id())
                .attribute(Attributes.link(Enums.LinkType.REPLACED_OBJECT_LINK, a.id()))
                .build());
    assertEquals(List.of(a.id()), b.attributes().links(LinkKind.REPLACED));
    assertEquals(List.of(a.id()), s.links(b.id(), LinkKind.REPLACED));
    kms.protocol()
        .call(
            Requests.deleteAttribute()
                .uniqueIdentifier(b.id())
                .attribute(Attributes.link(Enums.LinkType.REPLACED_OBJECT_LINK, a.id()))
                .build());
    assertEquals(List.of(), s.links(b.id(), LinkKind.REPLACED));
    // A Link structure, as a client that does not convert it would send: refused by the 3.0 fake.
    Kms unconverted =
        connect(
            s,
            r ->
                rewrite(
                    r,
                    n ->
                        n.tag() == Tag.REPLACED_OBJECT_LINK.code()
                            ? Ttlv.structure(
                                Tag.LINK,
                                Ttlv.enumeration(
                                    Tag.LINK_TYPE, Enums.LinkType.REPLACED_OBJECT_LINK),
                                Ttlv.text(Tag.LINKED_OBJECT_IDENTIFIER, n.textValue()))
                            : n));
    dev.keytend.kmip.client.KmipException refused =
        assertThrows(
            dev.keytend.kmip.client.KmipException.class,
            () ->
                unconverted
                    .protocol()
                    .call(
                        Requests.addAttribute()
                            .uniqueIdentifier(b.id())
                            .attribute(Attributes.link(Enums.LinkType.REPLACED_OBJECT_LINK, a.id()))
                            .build()));
    assertTrue(refused.getMessage().contains("InvalidMessage"), refused.getMessage());
    assertEquals(List.of(), s.links(b.id(), LinkKind.REPLACED));
    // The typed attribute is an identifier, a Reference as 3.0's Unique Identifier is (as servers
    // send it); the fake refuses it as a Text String.
    Kms asText =
        connect(
            s,
            r ->
                rewrite(
                    r,
                    n ->
                        n.tag() == Tag.REPLACED_OBJECT_LINK.code()
                            ? Ttlv.text(Tag.REPLACED_OBJECT_LINK, n.textValue())
                            : n));
    dev.keytend.kmip.client.KmipException text =
        assertThrows(
            dev.keytend.kmip.client.KmipException.class,
            () ->
                asText
                    .protocol()
                    .call(
                        Requests.addAttribute()
                            .uniqueIdentifier(b.id())
                            .attribute(Attributes.link(Enums.LinkType.REPLACED_OBJECT_LINK, a.id()))
                            .build()));
    assertTrue(text.getMessage().contains("InvalidField"), text.getMessage());
    assertEquals(List.of(), s.links(b.id(), LinkKind.REPLACED));
  }

  /** Whether {@code request} is a Re-key carrying an Offset. */
  static boolean offsetReKey(Ttlv request) {
    return RotationAndNameChoiceTest.isOperation(request, Operation.RE_KEY)
        && has(request, Tag.OFFSET);
  }

  static boolean has(Ttlv node, Tag tag) {
    if (node.tag() == tag.code()) return true;
    return node.type() == Ttlv.Type.STRUCTURE
        && node.children().stream().anyMatch(c -> has(c, tag));
  }

  /** A server and a client on one clock the test moves, starting at {@code RotationJobTest.START}. */
  Kms onClock(InMemoryKmipServer s, RotationJobTest.TestClock clock, UnaryOperator<Ttlv> request) {
    s.clock(clock);
    Kms kms = connect(s, request);
    kms.clock(clock);
    return kms;
  }

  /**
   * A key that was Active for 30 days, then retired, and found compromised 10 days later
   * is re-keyed with an Offset of 0: the server links the keys, activates the replacement now and
   * moves the copied Deactivation Date forward by as much, so the replacement is Active for the
   * 30 days the old key had, on every version, rather than a new key linked by hand.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aKeyRetiredAfterACryptoperiodIsReKeyedWithAnOffsetOfZero(KmipVersion version) {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(RotationJobTest.START);
    InMemoryKmipServer s = server(version);
    List<Ttlv> offsets = new CopyOnWriteArrayList<>();
    Kms kms =
        onClock(
            s,
            clock,
            r -> {
              if (offsetReKey(r)) offsets.add(r);
              return r;
            });
    KeyHandle key = aes(kms).create();
    byte[] record = key.seal(new byte[] {7}, AAD);
    clock.now = clock.now.plus(Duration.ofDays(30));
    key.revoke(RevocationReason.superseded("retired"));
    clock.now = clock.now.plus(Duration.ofDays(10));

    KeyHandle replacement = key.replaceCompromised(leaked());

    assertEquals(1, offsets.size(), "one Re-key, with an Offset");
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(replacement.id()));
    KeyAttributes a = replacement.attributes();
    assertEquals(Optional.of(clock.now), a.activationDate());
    assertEquals(
        Optional.of(clock.now.plus(Duration.ofDays(30))),
        a.deactivationDate(),
        "the cryptoperiod carried");
    assertEquals(List.of(key.id()), s.links(replacement.id(), LinkKind.REPLACED));
    assertEquals(List.of(replacement.id()), s.links(key.id(), LinkKind.REPLACEMENT));
    assertEquals(Optional.of(replacement), kms.keys().findByName(NAME));
    List<KeyHandle> compromised = replacement.compromisedPredecessors();
    assertEquals(List.of(key.id()), compromised.stream().map(KeyHandle::id).toList());
    assertArrayEquals(
        new byte[] {7},
        replacement.open(compromised.get(0).rewrapTo(replacement, record, AAD), AAD));
    assertEquals(
        replacement.id(), key.replaceCompromised(leaked()).id(), "a repeat finishes with it");
  }

  /**
   * Where the server refuses the Re-key with an Offset, the call falls back to a new key
   * linked by hand, as where Re-key is refused: Active, with no Deactivation Date, linked
   * both ways, also on 3.0. And a key whose Protect Stop Date came an hour after its activation
   * is not re-keyed with an Offset (its replacement would stop protecting an hour later), whatever
   * its Deactivation Date.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRetiredKeyGetsALinkedNewKeyWhereTheOffsetIsRefusedOrWouldNotKeepACryptoperiod(
      KmipVersion version) throws Exception {
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(RotationJobTest.START);
    InMemoryKmipServer s = server(version);
    List<Ttlv> offsets = new CopyOnWriteArrayList<>();
    Kms kms =
        onClock(
            s,
            clock,
            r -> {
              if (offsetReKey(r)) {
                offsets.add(r);
                s.failNext(ServerOperation.RE_KEY, Enums.ResultReason.INVALID_FIELD);
              }
              return r;
            });
    KeyHandle key = aes(kms).create();
    clock.now = clock.now.plus(Duration.ofDays(30));
    key.revoke(RevocationReason.superseded("retired"));
    clock.now = clock.now.plus(Duration.ofDays(10));
    KeyHandle replacement = key.replaceCompromised(leaked());
    assertEquals(1, offsets.size(), "the Offset was tried first");
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(replacement.id()));
    assertEquals(Optional.empty(), replacement.attributes().deactivationDate());
    assertEquals(List.of(key.id()), s.links(replacement.id(), LinkKind.REPLACED));
    assertEquals(List.of(replacement.id()), s.links(key.id(), LinkKind.REPLACEMENT));
    assertEquals(
        List.of(key.id()),
        replacement.compromisedPredecessors().stream().map(KeyHandle::id).toList());

    // A Protect Stop Date an hour after activation: no Offset, a new key.
    offsets.clear();
    KeyHandle stops =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("stops")
            .create();
    kms.protocol()
        .call(
            Requests.addAttribute()
                .uniqueIdentifier(stops.id())
                .attribute(
                    Attributes.attribute(
                        "Protect Stop Date",
                        Ttlv.dateTime(Tag.PROTECT_STOP_DATE, clock.now.plus(Duration.ofHours(1)))))
                .build());
    clock.now = clock.now.plus(Duration.ofDays(30));
    stops.revoke(RevocationReason.superseded("retired"));
    int reKeys = ReplicaRaceTest.reKeys(s);
    KeyHandle next = stops.replaceCompromised(leaked());
    assertEquals(reKeys, ReplicaRaceTest.reKeys(s), "no Re-key");
    assertEquals(
        List.of(stops.id()), next.compromisedPredecessors().stream().map(KeyHandle::id).toList());
  }

  /** Whether {@code request} adds a link of {@code type}, in either version's form. */
  static boolean addsLink(Ttlv request, Enums.LinkType type) {
    if (!RotationAndNameChoiceTest.isOperation(request, Operation.ADD_ATTRIBUTE)) return false;
    Tag typed = ModernAttributes.linkAttribute(type.code()).orElseThrow();
    return has(request, typed) || linkOfType(request, type.code());
  }

  static boolean linkOfType(Ttlv node, int type) {
    if (node.tag() == Tag.LINK.code() && node.type() == Ttlv.Type.STRUCTURE)
      return node.child(Tag.LINK_TYPE).map(Ttlv::intValue).orElse(0) == type;
    if (node.tag() == Tag.ATTRIBUTE_VALUE.code() && node.type() == Ttlv.Type.STRUCTURE)
      return node.child(Tag.LINK_TYPE).map(Ttlv::intValue).orElse(0) == type;
    return node.type() == Ttlv.Type.STRUCTURE
        && node.children().stream().anyMatch(c -> linkOfType(c, type));
  }

  /**
   * A retired-then-compromised key on a server that refuses the links (the
   * replacement's Replaced Object link, or the old key's Replacement Object link, which the call
   * then takes back). Returning the unlinked replacement as if all were well would leave the runbook
   * that follows no Compromised predecessor to find. The replacement is finished (Active, given the name) and the call throws {@link
   * PartialCompletionException} naming both keys, with the advice to re-seal from the old key's own
   * handle and not to repeat; following it re-seals every record. No link is left on either key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anUnlinkedReplacementIsAPartialCompletionNamingBothKeys(KmipVersion version) {
    for (Enums.LinkType refusedType :
        List.of(Enums.LinkType.REPLACED_OBJECT_LINK, Enums.LinkType.REPLACEMENT_OBJECT_LINK)) {
      InMemoryKmipServer s = server(version);
      Kms kms =
          Kms.connect(
              s.configure()
                  .transport(
                      e ->
                          r ->
                              addsLink(r, refusedType)
                                  ? Faults.failure(
                                      r, Enums.ResultReason.PERMISSION_DENIED, "no links here")
                                  : s.exchange(r))
                  .build());
      clients.add(kms);
      KeyHandle key = aes(kms).create();
      byte[] record = key.seal(new byte[] {9}, AAD);
      key.revoke(RevocationReason.superseded("retired"));
      int before = s.ids().size();
      PartialCompletionException e =
          assertThrows(
              PartialCompletionException.class,
              () -> key.replaceCompromised(leaked()),
              refusedType.toString());
      assertEquals(before + 1, s.ids().size(), "one key made");
      KeyHandle replacement = e.created().get(0);
      String m = e.getMessage();
      assertTrue(
          m.contains(
              "the server refused the links between "
                  + key.id()
                  + " and its replacement "
                  + replacement.id()),
          m);
      assertTrue(m.contains("not linked to the Compromised key " + key.id()), m);
      assertTrue(
          m.contains("kms.keys().handle(\"" + key.id() + "\").allowingCompromised().rewrapTo("), m);
      assertTrue(m.contains("do not repeat replaceCompromised()"), m);
      assertFalse(m.contains("destroy"), m);
      // The cause is the server's refusal of the link.
      assertInstanceOf(PermissionDeniedException.class, e.getCause());
      assertEquals(Optional.of(KeyState.ACTIVE), s.state(replacement.id()));
      assertEquals(Optional.of(replacement), kms.keys().findByName(NAME));
      assertEquals(List.of(), s.links(replacement.id(), LinkKind.REPLACED), "no one-sided link");
      assertEquals(List.of(), s.links(key.id(), LinkKind.REPLACEMENT));
      // The replacement's handle refuses the old key's record: STATE, the old key COMPROMISED.
      StateConflictException under =
          assertThrows(StateConflictException.class, () -> replacement.open(record, AAD));
      assertEquals(Optional.of(KeyState.COMPROMISED), under.observedState());
      // The advice works.
      byte[] moved =
          kms.keys().handle(key.id()).allowingCompromised().rewrapTo(replacement, record, AAD);
      assertArrayEquals(new byte[] {9}, replacement.open(moved, AAD));
    }
  }

  // ---- rotation with an Offset ----

  /** A named key created with a Deactivation Date {@code cryptoperiod} after now (a server policy's), then activated now. */
  static KeyHandle withCryptoperiod(Kms kms, Instant now, Duration cryptoperiod) throws Exception {
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
                        Attributes.name(NAME),
                        Attributes.attribute(
                            "Deactivation Date",
                            Ttlv.dateTime(Tag.DEACTIVATION_DATE, now.plus(cryptoperiod))))
                    .build())
            .uniqueIdentifier();
    KeyHandle key = kms.keys().handle(id);
    key.activate();
    return key;
  }

  /**
   * A server policy deactivates keys 8 days after activation, and a job
   * fires daily for 40 days with a 7-day period. With {@code RotationDates.SHIFTED} every Re-key
   * carries an Offset of 0, each replacement is Active with a Deactivation Date 8 days after it was
   * made, and the job rotates exactly on days 7, 14, 21, 28 and 35, through a shared {@code
   * CurrentKey} too; sealing never stops. With the default ({@code COPIED}) the replacement copies
   * the first key's Deactivation Date, so from day 8 the current key is Deactivated (on keytend-kmip-server,
   * and on the fake) and the job is refused: the lineage stops, as documented.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aShiftedRotationCarriesAPolicysCryptoperiodForward(KmipVersion version) throws Exception {
    Duration week = Duration.ofDays(7), cryptoperiod = Duration.ofDays(8);
    for (boolean shared : new boolean[] {false, true}) {
      RotationJobTest.TestClock clock = new RotationJobTest.TestClock(RotationJobTest.START);
      InMemoryKmipServer s = server(version);
      List<Ttlv> reKeys = new CopyOnWriteArrayList<>();
      Kms kms =
          onClock(
              s,
              clock,
              r -> {
                if (RotationAndNameChoiceTest.isOperation(r, Operation.RE_KEY)) reKeys.add(r);
                return r;
              });
      KeyHandle key = withCryptoperiod(kms, clock.now, cryptoperiod);
      CurrentKey current = kms.keys().current(key);
      List<Integer> rotatedOn = new ArrayList<>();
      for (int day = 1; day <= 40; day++) {
        clock.now = RotationJobTest.START.plus(Duration.ofDays(day));
        int before = reKeys.size();
        KeyHandle now =
            shared
                ? current.rotateIfActiveFor(week, Rotation.of(RotationDates.SHIFTED))
                : kms.keys()
                    .findByName(NAME)
                    .orElseThrow()
                    .rotateIfActiveFor(week, Rotation.of(RotationDates.SHIFTED));
        if (reKeys.size() > before) rotatedOn.add(day);
        KeyAttributes a = now.attributes();
        assertEquals(KeyState.ACTIVE, a.state(), "day " + day);
        assertTrue(a.deactivationDate().orElseThrow().isAfter(clock.now), "day " + day);
        assertArrayEquals(new byte[] {1}, now.open(now.seal(new byte[] {1}, AAD), AAD));
      }
      assertEquals(List.of(7, 14, 21, 28, 35), rotatedOn, "shared=" + shared);
      assertTrue(
          reKeys.stream().allMatch(r -> has(r, Tag.OFFSET)), "every Re-key carries the Offset");
      KeyAttributes last = kms.keys().findByName(NAME).orElseThrow().attributes();
      assertEquals(
          Optional.of(RotationJobTest.START.plus(Duration.ofDays(35))), last.activationDate());
      assertEquals(
          Optional.of(RotationJobTest.START.plus(Duration.ofDays(35)).plus(cryptoperiod)),
          last.deactivationDate());
    }

    // The default copies the first key's Deactivation Date: the lineage stops at it.
    RotationJobTest.TestClock clock = new RotationJobTest.TestClock(RotationJobTest.START);
    InMemoryKmipServer s = server(version);
    List<Ttlv> offsets = new CopyOnWriteArrayList<>();
    Kms kms =
        onClock(
            s,
            clock,
            r -> {
              if (offsetReKey(r)) offsets.add(r);
              return r;
            });
    withCryptoperiod(kms, clock.now, cryptoperiod);
    clock.now = RotationJobTest.START.plus(Duration.ofDays(7));
    KeyHandle copied = kms.keys().findByName(NAME).orElseThrow().rotateIfActiveFor(week);
    assertEquals(
        Optional.of(RotationJobTest.START.plus(cryptoperiod)),
        copied.attributes().deactivationDate());
    // From day 8 it is Deactivated (as on keytend-kmip-server; the fake keeps State with the
    // dates),
    // and the job is refused.
    clock.now = RotationJobTest.START.plus(cryptoperiod);
    assertEquals(KeyState.DEACTIVATED, copied.attributes().state());
    StateConflictException stopped =
        assertThrows(
            StateConflictException.class,
            () -> kms.keys().handle(copied.id()).rotateIfActiveFor(week));
    assertEquals(Optional.of(KeyState.DEACTIVATED), stopped.observedState());
    assertEquals(List.of(), offsets, "no Offset unless asked");
    clock.now = RotationJobTest.START.plus(Duration.ofDays(9));
    // rotate(SHIFTED) and rotateOrLatest(SHIFTED) send it too.
    KeyHandle fresh = withCryptoperiod(kms, clock.now, cryptoperiod);
    fresh.removeName(NAME);
    clock.now = clock.now.plus(Duration.ofDays(1));
    KeyHandle r1 = fresh.rotate(Rotation.of(RotationDates.SHIFTED));
    KeyHandle r2 = r1.rotateOrLatest(Rotation.of(RotationDates.SHIFTED));
    assertEquals(2, offsets.size());
    assertEquals(Optional.of(clock.now.plus(cryptoperiod)), r2.attributes().deactivationDate());
  }

  // ---- the state a refusal is about ----

  /**
   * A rotation job's refusal says which state it found, so the job can
   * start the compromise runbook for a Compromised key and page for a Deactivated one without
   * parsing the message. The other refusals about a key's
   * state the client read carry it too: opening a record under a Compromised key, replacing a
   * destroyed one, a key that is not Compromised for {@code replaceCompromised} without a reason
   * (the startup path), a Pre-Active key used to encrypt. A refusal that is about no state has
   * none, and {@code serverReason()} stays the server's word: empty for refusals made before
   * sending.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aStateRefusalSaysWhichStateItFound(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle compromised = aes(kms).create();
    byte[] record = compromised.seal(new byte[] {1}, AAD);
    compromised.revoke(leaked());
    KeyHandle deactivated =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    deactivated.revoke(RevocationReason.superseded("retired"));
    for (java.util.function.Function<KeyHandle, KeyHandle> job :
        List.<java.util.function.Function<KeyHandle, KeyHandle>>of(
            KeyHandle::rotate,
            KeyHandle::rotateOrLatest,
            k -> k.rotateIfActiveFor(Duration.ofDays(30)),
            k -> kms.keys().current(k).rotateIfActiveFor(Duration.ZERO))) {
      StateConflictException c =
          assertThrows(
              StateConflictException.class, () -> job.apply(kms.keys().handle(compromised.id())));
      assertEquals(Optional.of(KeyState.COMPROMISED), c.observedState());
      assertEquals(Optional.empty(), c.serverReason(), "refused before sending");
      StateConflictException d =
          assertThrows(
              StateConflictException.class, () -> job.apply(kms.keys().handle(deactivated.id())));
      assertEquals(Optional.of(KeyState.DEACTIVATED), d.observedState());
    }
    KeyHandle replacement = compromised.replaceCompromised(leaked());
    StateConflictException open =
        assertThrows(StateConflictException.class, () -> replacement.open(record, AAD));
    assertEquals(Optional.of(KeyState.COMPROMISED), open.observedState());
    assertEquals(Optional.of(compromised.id()), open.objectId());
    StateConflictException read =
        assertThrows(
            StateConflictException.class,
            () -> kms.keys().handle(compromised.id()).open(record, AAD));
    assertEquals(Optional.of(KeyState.COMPROMISED), read.observedState());
    KeyHandle preActive =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
    StateConflictException early =
        assertThrows(StateConflictException.class, () -> preActive.seal(new byte[] {1}, AAD));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), early.observedState());
    KeyHandle gone = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).createPreActive();
    gone.destroy();
    StateConflictException destroyed =
        assertThrows(StateConflictException.class, () -> gone.replaceCompromised(leaked()));
    assertTrue(
        destroyed.observedState().orElseThrow().name().startsWith("DESTROYED"),
        destroyed.observedState().toString());
    StateConflictException notCompromised =
        assertThrows(
            StateConflictException.class,
            () -> replacement.replaceCompromised(replacement.attributes(), null, null));
    assertEquals(Optional.of(KeyState.ACTIVE), notCompromised.observedState());
    StateConflictException material =
        assertThrows(
            StateConflictException.class,
            () ->
                kms.keys().handle(compromised.id()).asSecretKey(Expect.aes(256), LocalUse.DECRYPT));
    assertEquals(Optional.of(KeyState.COMPROMISED), material.observedState());
    StateConflictException again =
        assertThrows(StateConflictException.class, replacement::activate);
    assertEquals(
        Optional.of(KeyState.ACTIVE), again.observedState(), "read back after the server refused");
    // rotateOrLatest from a replaced key whose current key is Compromised.
    KeyHandle first = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create(),
        next = first.rotate();
    next.revoke(leaked());
    StateConflictException current =
        assertThrows(StateConflictException.class, first::rotateOrLatest);
    assertEquals(Optional.of(KeyState.COMPROMISED), current.observedState());
    assertEquals(Optional.of(next.id()), current.objectId());
    // replaceCompromised of a key whose replacement is Deactivated; reconcile with a Deactivated
    // newest key.
    KeyHandle old = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create(),
        retired = old.rotate();
    retired.revoke(RevocationReason.superseded("retired"));
    StateConflictException reconciled = assertThrows(StateConflictException.class, old::reconcile);
    assertEquals(Optional.of(KeyState.DEACTIVATED), reconciled.observedState());
    old.revoke(leaked());
    StateConflictException newest =
        assertThrows(StateConflictException.class, () -> old.replaceCompromised(leaked()));
    assertEquals(Optional.of(KeyState.DEACTIVATED), newest.observedState());
    assertEquals(Optional.of(retired.id()), newest.objectId());
    // About no state: a name taken.
    if (version != KmipVersion.V1_4) {
      s.uniqueNames(true);
      StateConflictException taken =
          assertThrows(StateConflictException.class, () -> aes(kms).create());
      assertEquals(Optional.empty(), taken.observedState());
    }
  }

  /**
   * The links refused, and then finishing the replacement
   * fails too: its activation, or giving it a name. Before, the activation's own exception said
   * "repeat replaceCompromised() to resume", and repeating made a second unlinked key; a failed
   * name gave no re-seal advice and lost the link refusal. Now both are the unlinked exception:
   * both keys named, the refusal as cause and the finishing failure suppressed, the advice to
   * activate and name the replacement by hand, re-seal from the old key's handle, and not repeat.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1", "V3_0"})
  void anUnlinkedReplacementWhoseFinishingFailsStillSaysNotToRepeat(KmipVersion version) {
    for (Operation failing : List.of(Operation.ACTIVATE, Operation.ADD_ATTRIBUTE)) {
      InMemoryKmipServer s = server(version);
      java.util.concurrent.atomic.AtomicBoolean armed =
          new java.util.concurrent.atomic.AtomicBoolean();
      Kms kms =
          Kms.connect(
              s.configure()
                  .transport(
                      e ->
                          r -> {
                            if (addsLink(r, Enums.LinkType.REPLACED_OBJECT_LINK)) {
                              armed.set(true);
                              return Faults.failure(
                                  r, Enums.ResultReason.PERMISSION_DENIED, "no links here");
                            }
                            if (armed.get()
                                && RotationAndNameChoiceTest.isOperation(r, failing)
                                && !has(r, Tag.REPLACEMENT_OBJECT_LINK)
                                && armed.compareAndSet(true, false))
                              return Faults.failure(r, Enums.ResultReason.GENERAL_FAILURE, "busy");
                            return s.exchange(r);
                          })
                  .build());
      clients.add(kms);
      KeyHandle key = aes(kms).create();
      key.revoke(RevocationReason.superseded("retired"));
      int before = s.ids().size();
      PartialCompletionException e =
          assertThrows(
              PartialCompletionException.class,
              () -> key.replaceCompromised(leaked()),
              failing.toString());
      KeyHandle replacement = e.created().get(0);
      String m = e.getMessage();
      assertTrue(
          m.contains(
              "the server refused the links between "
                  + key.id()
                  + " and its replacement "
                  + replacement.id()),
          m);
      assertTrue(m.contains("finishing " + replacement.id() + " failed too"), m);
      assertTrue(
          m.contains(
              "activate "
                  + replacement.id()
                  + " if it is Pre-Active and give it the names ["
                  + NAME
                  + "]"),
          m);
      assertTrue(m.contains("do not repeat replaceCompromised()"), m);
      assertFalse(m.contains("to resume"), m);
      assertInstanceOf(PermissionDeniedException.class, e.getCause());
      assertEquals(1, e.getSuppressed().length, failing.toString());
      assertEquals(before + 1, s.ids().size());
    }
  }
}
