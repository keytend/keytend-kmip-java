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

import static dev.keytend.kmip.kms.TlsRepeatTest.link;
import static dev.keytend.kmip.kms.TlsRepeatTest.snapshot;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TlsRepeatTest.Call;
import dev.keytend.kmip.kms.TlsRepeatTest.Material;
import dev.keytend.kmip.kms.TlsRepeatTest.Op;
import dev.keytend.kmip.kms.TlsRepeatTest.Scenario;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * A repeat that finds the switch made (the new leaf the identity's certificate, or the replacement
 * being made current) finishes only with the chain and key it was given. It compares each
 * certificate of the leaf's chain, by DER encoding, and, for a re-key or a registration, the key
 * the leaf links to, with its arguments. When one differs (a corrected chain, or another caller's
 * change to the leaf's links) it stops with nothing changed, says how to finish, and doing so
 * finishes. A repeat used to take the chain and key from the server, report success, and present
 * the old chain, or another caller's certificate.
 */
class TlsRepeatArgumentsTest {
  static final String NAME = TlsRepeatTest.NAME;
  static final String OTHER = TlsRepeatTest.OTHER;

  /**
   * SWITCHED: stopped just after the switch, everything of the call Pre-Active; ACTIVATING: just
   * before the leaf's Activate, its key (re-key) and new intermediate Active, and a renewal's kept
   * key linked to it; ACTIVE: just after the leaf's Activate.
   */
  enum Phase {
    SWITCHED,
    ACTIVATING,
    ACTIVE
  }

  static Stream<Arguments> cases() {
    List<Arguments> out = new ArrayList<>();
    for (Arguments s : TlsIdentityTest.servers().toList())
      for (Op op : Op.values())
        for (Phase p : Phase.values()) out.add(Arguments.of(s.get()[0], s.get()[1], op, p));
    return out.stream();
  }

  static Stream<Arguments> phases() {
    List<Arguments> out = new ArrayList<>();
    for (Arguments s : TlsIdentityTest.servers().toList())
      for (Phase p : Phase.values()) out.add(Arguments.of(s.get()[0], s.get()[1], p));
    return out.stream();
  }

  /** Stops the job's {@code op} as {@code phase} says, and reconnects: its new leaf. */
  static String stop(Scenario s, Op op, Phase phase) {
    String leaf =
        switch (phase) {
          case SWITCHED -> TlsRepeatTest.stopAfterTheSwitch(s, op);
          case ACTIVATING -> TlsRepeatTest.stopBeforeTheLeafsActivation(s, op);
          case ACTIVE -> TlsRepeatTest.stopAfterTheActivation(s, op);
        };
    s.reconnect();
    s.t.counting = true;
    s.t.writes.clear();
    return leaf;
  }

  /** {@code op} with the identity's original intermediate instead of the job's re-issued one. */
  static TlsIdentityHandle corrected(Scenario s, Op op) {
    TlsIdentityHandle h = s.kms.tls().identity(NAME).orElseThrow();
    X509Certificate[] chain = s.m.pki.chain(op == Op.RENEW ? s.m.mineRenewed : s.m.mineRekeyed);
    return op == Op.RENEW ? h.renew(chain) : h.rekey(s.m.k2.getPrivate(), chain);
  }

  /** The refusal of a repeat that changed nothing: no write, every object as {@code was}. */
  static StateConflictException assertRefused(
      Scenario s, Map<String, String> was, java.util.function.Supplier<TlsIdentityHandle> call) {
    StateConflictException e = assertThrows(StateConflictException.class, call::get);
    assertEquals(StateConflictException.Conflict.LINEAGE, e.conflict(), e.getMessage());
    assertTrue(e.getMessage().contains("nothing was changed"), e.getMessage());
    assertEquals(List.of(), s.t.writes, "the refused repeat sent a change");
    assertEquals(was, snapshot(s.server), "nothing was changed");
    return e;
  }

  /**
   * A renewal or re-key with a re-issued intermediate stops after its switch; the operator repeats
   * it with the original intermediate. The repeat is refused, naming the intermediate that
   * differs, and says to repeat with the first chain. Done so, it finishes with that chain, and a
   * renewal with a new certificate under the original intermediate then presents it. While nothing
   * the stopped call made is Active, the refusal also offers to take the Replacement Object link
   * off; done so, the corrected call starts over and finishes with the chain it gives, and what the
   * stopped call made is left Pre-Active, with nothing of the identity linking to it. Once its key
   * or intermediate is Active (stopped just before the leaf's Activate), the refusal does not offer
   * that, which would leave them Active and, for a renewal, the identity's key linked to the
   * abandoned leaf; it names them instead.
   */
  @ParameterizedTest
  @MethodSource("cases")
  void aRepeatWithACorrectedChainAfterTheSwitchIsRefusedAndTheAdviceFinishes(
      KmipVersion version, boolean unique, Op op, Phase phase) throws Exception {
    Material m = new Material();
    for (boolean undo :
        phase == Phase.SWITCHED ? new boolean[] {false, true} : new boolean[] {false})
      try (Scenario s = new Scenario(version, unique, m)) {
        String old = s.start.certificate().id();
        String kept = s.start.privateKey().id();
        String leaf = stop(s, op, phase);
        String key = s.server.links(leaf, LinkKind.PRIVATE_KEY).get(0);
        String ca = s.server.links(leaf, LinkKind.CERTIFICATE).get(0);
        StateConflictException e = assertRefused(s, snapshot(s.server), () -> corrected(s, op));
        assertEquals(Optional.of(ca), e.objectId(), e.getMessage());
        assertTrue(e.getMessage().contains("repeat it with the chain"), e.getMessage());
        assertFalse(
            e.getMessage().contains(". .") || e.getMessage().contains("over When"), e.getMessage());
        boolean offered =
            e.getMessage().contains("take the Replacement Object link to it off " + old);
        assertEquals(phase == Phase.SWITCHED, offered, e.getMessage());
        if (phase == Phase.ACTIVATING) {
          // What taking the switch off would leave, named; finishing is the advice.
          assertTrue(
              e.getMessage().contains("Do not take the switch to " + leaf + " off"),
              e.getMessage());
          assertTrue(e.getMessage().contains(ca + " (ACTIVE)"), e.getMessage());
          assertTrue(
              e.getMessage()
                  .contains(
                      op == Op.RENEW
                          ? "the identity's private key " + kept + " linked to " + leaf
                          : key + " (ACTIVE)"),
              e.getMessage());
        }
        Call call = op == Op.RENEW ? Call.RENEW : Call.REKEY;
        if (!undo) {
          TlsIdentityHandle done = assertDoesNotThrow(() -> s.call(call));
          assertEquals(leaf, done.certificate().id());
          s.assertFinished(call, done, "repeated with the first chain");
          // Then, as the refusal says, a renewal with a new certificate under the chain wanted.
          TestPki.Issued next = m.pki.leaf("node1", op == Op.RENEW ? m.k1 : m.k2);
          TlsIdentityHandle renewed = assertDoesNotThrow(() -> done.renew(m.pki.chain(next)));
          assertArrayEquals(
              m.pki.ca.certificate().getEncoded(),
              TlsIdentities.certificate(s.other, renewed.chain().get(1).id()).getEncoded());
          assertEquals(
              renewed.certificate().id(),
              s.other.tls().identity(NAME).orElseThrow().certificate().id());
          assertEquals(
              List.of(),
              s.server.ids().stream()
                  .filter(id -> s.server.state(id).equals(Optional.of(KeyState.PRE_ACTIVE)))
                  .toList(),
              "nothing is left over");
        } else {
          s.other
              .keys()
              .handle(old)
              .removeLink("by hand", Enums.LinkType.REPLACEMENT_OBJECT_LINK, leaf);
          TlsIdentityHandle done = assertDoesNotThrow(() -> corrected(s, op));
          assertNotEquals(leaf, done.certificate().id());
          assertArrayEquals(
              m.pki.ca.certificate().getEncoded(),
              TlsIdentities.certificate(s.other, done.chain().get(1).id()).getEncoded());
          assertEquals(
              done.certificate().id(),
              s.other.tls().identity(NAME).orElseThrow().certificate().id());
          // What the stopped call made is left over as the guide says: Pre-Active, unlinked.
          List<String> left = new ArrayList<>(List.of(leaf, ca));
          if (op == Op.REKEY) left.add(key);
          for (String id : left)
            assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(id), id);
          for (String id : s.server.ids())
            if (!left.contains(id))
              for (LinkKind k : LinkKind.values())
                assertFalse(s.server.links(id, k).contains(leaf), id + " links to " + leaf);
        }
        assertEquals(List.of(), s.server.violations());
      }
  }

  /** How another caller replaces the leaf's issuer link: by a named root, an unnamed one, or none. */
  enum Relink {
    NAMED_ROOT,
    UNNAMED_ROOT,
    REMOVED
  }

  /**
   * After the switch, another caller takes the new leaf's Certificate link off its intermediate
   * and links it to an Active certificate of another subject, named or not, or to nothing. The
   * plain repeat is refused, naming that certificate, and gives the leaf nothing (no name, no
   * record of it); undone, a repeat finishes with the chain it was given. Just after the switch,
   * nothing the stopped call made is Active, and the refusal also offers to take the switch off,
   * whatever the leaf now links to; done so, a repeat starts over and finishes, the stopped call's
   * objects are left over, Pre-Active, and the other certificate is as it was. The refusal never
   * names the named certificate as something an undo would leave; an unnamed one linked only from
   * the leaf, once the call's key or kept key's link is made, is as the call's own issuer would be.
   */
  @ParameterizedTest
  @MethodSource("cases")
  void aRepeatAfterAnotherCallerChangedTheLeafsIssuerLinkIsRefused(
      KmipVersion version, boolean unique, Op op, Phase phase) throws Exception {
    Material m = new Material();
    for (Relink relink : Relink.values())
      for (boolean undo :
          phase == Phase.SWITCHED ? new boolean[] {false, true} : new boolean[] {false})
        try (Scenario s = new Scenario(version, unique, m)) {
          String old = s.start.certificate().id();
          String leaf = stop(s, op, phase);
          String key = s.server.links(leaf, LinkKind.PRIVATE_KEY).get(0);
          String ca = s.server.links(leaf, LinkKind.CERTIFICATE).get(0);
          KeyRegistration r = s.other.keys().register(m.pki.root.certificate());
          String root = (relink == Relink.NAMED_ROOT ? r.named("foreign-root") : r).register().id();
          s.other.keys().handle(leaf).removeLink("by hand", Enums.LinkType.CERTIFICATE_LINK, ca);
          if (relink != Relink.REMOVED) link(s.other, leaf, Enums.LinkType.CERTIFICATE_LINK, root);
          Map<String, String> theirs = snapshot(s.server, List.of(root));
          Call call = op == Op.RENEW ? Call.RENEW : Call.REKEY;
          StateConflictException e = assertRefused(s, snapshot(s.server), () -> s.call(call));
          String msg = e.getMessage();
          assertEquals(Optional.of(relink == Relink.REMOVED ? leaf : root), e.objectId(), msg);
          assertTrue(msg.contains("undo that, then repeat"), msg);
          boolean offered = msg.contains("take the Replacement Object link to it off " + old);
          assertEquals(phase == Phase.SWITCHED, offered, msg);
          if (phase == Phase.ACTIVATING)
            assertTrue(msg.contains("Do not take the switch to " + leaf + " off"), msg);
          if (phase == Phase.SWITCHED || relink == Relink.NAMED_ROOT)
            assertFalse(msg.contains(root + " ("), msg);
          if (undo) {
            // As the refusal offers: the switch off, then the repeat starts over.
            s.other
                .keys()
                .handle(old)
                .removeLink("by hand", Enums.LinkType.REPLACEMENT_OBJECT_LINK, leaf);
            TlsIdentityHandle done = assertDoesNotThrow(() -> s.call(call));
            assertNotEquals(leaf, done.certificate().id());
            s.assertFinished(call, done, "the switch taken off, then repeated");
            assertLeftOver(s, op == Op.REKEY ? List.of(leaf, ca, key) : List.of(leaf, ca), leaf);
            assertEquals(theirs, snapshot(s.server, List.of(root)), "the other certificate");
          } else {
            if (relink != Relink.REMOVED)
              s.other
                  .keys()
                  .handle(leaf)
                  .removeLink("by hand", Enums.LinkType.CERTIFICATE_LINK, root);
            link(s.other, leaf, Enums.LinkType.CERTIFICATE_LINK, ca);
            TlsIdentityHandle done = assertDoesNotThrow(() -> s.call(call));
            assertEquals(leaf, done.certificate().id());
            s.assertFinished(call, done, "undone, then repeated");
          }
          assertEquals(Optional.of(KeyState.ACTIVE), s.server.state(root));
          assertEquals(
              relink == Relink.NAMED_ROOT ? List.of("foreign-root") : List.of(),
              s.server.names(root));
        }
  }

  /**
   * After a re-key's switch, another caller links the new leaf to a private key of other material
   * instead, both ways. The repeat reads that key, finds it is not the key it was given, and is
   * refused, naming it.
   */
  @ParameterizedTest
  @MethodSource("phases")
  void aRepeatOfAReKeyWhoseLeafLinksToAnotherKeyIsRefused(
      KmipVersion version, boolean unique, Phase phase) throws Exception {
    Material m = new Material();
    try (Scenario s = new Scenario(version, unique, m)) {
      String leaf = stop(s, Op.REKEY, phase);
      String key = s.server.links(leaf, LinkKind.PRIVATE_KEY).get(0);
      String foreign =
          s.other.keys().register(m.k3.getPrivate()).usages(KeyUsage.SIGN).registerPreActive().id();
      if (phase == Phase.ACTIVE) s.other.keys().handle(foreign).activate();
      s.other.keys().handle(leaf).removeLink("by hand", Enums.LinkType.PRIVATE_KEY_LINK, key);
      link(s.other, leaf, Enums.LinkType.PRIVATE_KEY_LINK, foreign);
      link(s.other, foreign, Enums.LinkType.CERTIFICATE_LINK, leaf);
      StateConflictException e = assertRefused(s, snapshot(s.server), () -> s.call(Call.REKEY));
      assertEquals(Optional.of(foreign), e.objectId(), e.getMessage());
      assertTrue(e.getMessage().contains("is not the key given"), e.getMessage());
    }
  }

  /**
   * A registration with the identity's intermediate finishes, or stops after its switch (the name
   * on its Pre-Active leaf). Registering the same leaf again under the name, with a re-issued
   * intermediate, is refused, naming the intermediate, rather than returning the first chain.
   * After the stop, a repeat with the first chain finishes; or, as the refusal says, taking the
   * name off the Pre-Active leaf lets the registration with the other chain start over.
   */
  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void aRegistrationRepeatedWithAnotherChainIsRefused(KmipVersion version, boolean unique)
      throws Exception {
    Material m = new Material();
    for (int variant = 0; variant < 3; variant++)
      try (Scenario s = new Scenario(version, unique, m)) {
        X509Certificate[] first = m.mineRekeyed.chain(m.pki.ca);
        X509Certificate[] second = {m.mineRekeyed.certificate(), m.reissued};
        String leaf;
        if (variant == 0)
          leaf =
              s.kms
                  .tls()
                  .register(m.k2.getPrivate(), first)
                  .named(OTHER)
                  .register()
                  .certificate()
                  .id();
        else {
          boolean[] named = {false};
          s.t.hook =
              r -> {
                if (named[0] && TlsRepeatTest.is(r, Operation.ACTIVATE))
                  throw new TlsOwnershipTest.Stop();
                if (TlsRepeatTest.namesOther(r)) named[0] = true;
              };
          assertThrows(
              TlsOwnershipTest.Stop.class,
              () -> s.kms.tls().register(m.k2.getPrivate(), first).named(OTHER).register());
          s.t.hook = r -> {};
          leaf =
              s.server.ids().stream()
                  .filter(id -> s.server.names(id).contains(OTHER))
                  .findFirst()
                  .orElseThrow();
          assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(leaf));
          s.reconnect();
        }
        String ca = s.server.links(leaf, LinkKind.CERTIFICATE).get(0);
        s.t.counting = true;
        s.t.writes.clear();
        StateConflictException e =
            assertRefused(
                s,
                snapshot(s.server),
                () -> s.kms.tls().register(m.k2.getPrivate(), second).named(OTHER).register());
        assertEquals(Optional.of(ca), e.objectId(), e.getMessage());
        if (variant == 1) {
          TlsIdentityHandle done =
              assertDoesNotThrow(
                  () -> s.kms.tls().register(m.k2.getPrivate(), first).named(OTHER).register());
          assertEquals(leaf, done.certificate().id());
          assertEquals(Optional.of(KeyState.ACTIVE), s.server.state(leaf));
          assertEquals(Optional.of(KeyState.ACTIVE), s.server.state(done.privateKey().id()));
        } else if (variant == 2) {
          assertTrue(e.getMessage().contains("take the name " + OTHER + " off it"), e.getMessage());
          s.other.keys().handle(leaf).removeName(OTHER);
          TlsIdentityHandle done =
              assertDoesNotThrow(
                  () -> s.kms.tls().register(m.k2.getPrivate(), second).named(OTHER).register());
          assertNotEquals(leaf, done.certificate().id());
          assertArrayEquals(
              m.reissued.getEncoded(),
              TlsIdentities.certificate(s.other, done.chain().get(1).id()).getEncoded());
        }
        assertEquals(List.of(), s.server.violations());
      }
  }

  static Stream<Arguments> ops() {
    return TlsRepeatTest.cases();
  }

  /**
   * {@code leaf}, {@code ca} and, for a re-key, {@code key}, which a stopped call made and whose
   * switch was taken off, are left over as the guide says: Pre-Active, and nothing else links to
   * the leaf.
   */
  static void assertLeftOver(Scenario s, List<String> left, String leaf) {
    for (String id : left) assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(id), id);
    for (String id : s.server.ids())
      if (!left.contains(id))
        for (LinkKind k : LinkKind.values())
          assertFalse(s.server.links(id, k).contains(leaf), id + " links to " + leaf);
  }

  static List<String> preActive(Scenario s) {
    return s.server.ids().stream()
        .filter(id -> s.server.state(id).equals(Optional.of(KeyState.PRE_ACTIVE)))
        .toList();
  }

  /**
   * The job's renewal or re-key stops after its switch; another renewal or re-key of the identity,
   * to another leaf, is refused with nothing changed (`REPLACED`). While nothing of the stopped call
   * is Active, the refusal offers to take its Replacement Object link off; done so, the other call
   * finishes, and the stopped call's objects are left Pre-Active and unlinked. Once its key or
   * intermediate is Active (stopped just before the leaf's Activate), it does not, and names what
   * that would leave; finishing the stopped call, as it says, then repeating the other, finishes
   * both with nothing left over.
   */
  @ParameterizedTest
  @MethodSource("ops")
  void anotherCallIsOfferedToTakeAStoppedSwitchOffOnlyWhileNothingOfItIsActive(
      KmipVersion version, boolean unique, Op op) throws Exception {
    Material m = new Material();
    for (Phase phase : new Phase[] {Phase.SWITCHED, Phase.ACTIVATING})
      try (Scenario s = new Scenario(version, unique, m)) {
        String old = s.start.certificate().id();
        String kept = s.start.privateKey().id();
        String leaf = stop(s, op, phase);
        String key = s.server.links(leaf, LinkKind.PRIVATE_KEY).get(0);
        String ca = s.server.links(leaf, LinkKind.CERTIFICATE).get(0);
        Map<String, String> was = snapshot(s.server);
        StateConflictException e =
            assertThrows(
                StateConflictException.class,
                () -> m.theirs(s.kms.tls().identity(NAME).orElseThrow(), op));
        assertEquals(StateConflictException.Conflict.REPLACED, e.conflict(), e.getMessage());
        assertEquals(Optional.of(leaf), e.objectId(), e.getMessage());
        assertEquals(List.of(), s.t.writes, "the refused call sent a change");
        assertEquals(was, snapshot(s.server), "nothing was changed");
        boolean offered =
            e.getMessage()
                .contains("otherwise take the Replacement Object link to " + leaf + " off " + old);
        assertEquals(phase == Phase.SWITCHED, offered, e.getMessage());
        if (phase == Phase.SWITCHED) {
          s.other
              .keys()
              .handle(old)
              .removeLink("by hand", Enums.LinkType.REPLACEMENT_OBJECT_LINK, leaf);
          TlsIdentityHandle done =
              assertDoesNotThrow(() -> m.theirs(s.kms.tls().identity(NAME).orElseThrow(), op));
          assertEquals(
              done.certificate().id(),
              s.other.tls().identity(NAME).orElseThrow().certificate().id());
          assertLeftOver(s, op == Op.REKEY ? List.of(leaf, ca, key) : List.of(leaf, ca), leaf);
        } else {
          assertTrue(
              e.getMessage()
                  .contains("Do not take the Replacement Object link to " + leaf + " off"),
              e.getMessage());
          assertTrue(e.getMessage().contains(ca + " (ACTIVE)"), e.getMessage());
          assertTrue(
              e.getMessage()
                  .contains(
                      op == Op.RENEW
                          ? "the identity's private key " + kept + " linked to " + leaf
                          : key + " (ACTIVE)"),
              e.getMessage());
          Call call = op == Op.RENEW ? Call.RENEW : Call.REKEY;
          TlsIdentityHandle finished = assertDoesNotThrow(() -> s.call(call));
          s.assertFinished(call, finished, "the stopped call finished");
          TlsIdentityHandle done =
              assertDoesNotThrow(() -> m.theirs(s.kms.tls().identity(NAME).orElseThrow(), op));
          assertEquals(
              done.certificate().id(),
              s.other.tls().identity(NAME).orElseThrow().certificate().id());
          assertEquals(List.of(), preActive(s), "nothing is left over");
        }
        assertEquals(List.of(), s.server.violations());
      }
  }

  /**
   * A registration stops after its name, at the Activate of its key (nothing Active) or of its
   * leaf (its key and intermediate Active). A registration of another leaf under the name is
   * refused with nothing changed. In the first case the refusal offers to take the name off; done
   * so, the other registration finishes, and the stopped one's objects are left Pre-Active and
   * unlinked. In the second it does not, and names what that would leave; finishing the stopped
   * registration, then re-keying the identity to the other leaf, as it says, leaves nothing over.
   */
  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void anotherRegistrationIsOfferedToTakeTheNameOffOnlyWhileNothingOfTheStoppedOneIsActive(
      KmipVersion version, boolean unique) throws Exception {
    Material m = new Material();
    for (boolean activating : new boolean[] {false, true})
      try (Scenario s = new Scenario(version, unique, m)) {
        X509Certificate[] first = m.mineRekeyed.chain(m.pki.ca);
        X509Certificate[] theirs = m.theirsRekeyed.chain(m.pki.ca);
        boolean[] named = {false};
        s.t.hook =
            r -> {
              if (named[0]
                  && TlsRepeatTest.is(r, Operation.ACTIVATE)
                  && (!activating
                      || s.server.names(TlsOwnershipTest.write(r).target()).contains(OTHER)))
                throw new TlsOwnershipTest.Stop();
              if (TlsRepeatTest.namesOther(r)) named[0] = true;
            };
        assertThrows(
            TlsOwnershipTest.Stop.class,
            () -> s.kms.tls().register(m.k2.getPrivate(), first).named(OTHER).register());
        s.t.hook = r -> {};
        s.reconnect();
        String leaf =
            s.server.ids().stream()
                .filter(id -> s.server.names(id).contains(OTHER))
                .findFirst()
                .orElseThrow();
        String key = s.server.links(leaf, LinkKind.PRIVATE_KEY).get(0);
        String ca = s.server.links(leaf, LinkKind.CERTIFICATE).get(0);
        assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(leaf));
        assertEquals(
            Optional.of(activating ? KeyState.ACTIVE : KeyState.PRE_ACTIVE), s.server.state(ca));
        s.t.counting = true;
        s.t.writes.clear();
        Map<String, String> was = snapshot(s.server);
        AlreadyExistsException e =
            assertThrows(
                AlreadyExistsException.class,
                () -> s.kms.tls().register(m.k3.getPrivate(), theirs).named(OTHER).register());
        assertEquals(Optional.of(leaf), e.objectId(), e.getMessage());
        assertEquals(List.of(), s.t.writes, "the refused call sent a change");
        assertEquals(was, snapshot(s.server), "nothing was changed");
        boolean offered = e.getMessage().contains("otherwise take the name off " + leaf);
        assertEquals(!activating, offered, e.getMessage());
        if (!activating) {
          s.other.keys().handle(leaf).removeName(OTHER);
          TlsIdentityHandle done =
              assertDoesNotThrow(
                  () -> s.kms.tls().register(m.k3.getPrivate(), theirs).named(OTHER).register());
          assertNotEquals(leaf, done.certificate().id());
          assertLeftOver(s, List.of(leaf, ca, key), leaf);
        } else {
          assertTrue(e.getMessage().contains("Do not take the name off " + leaf), e.getMessage());
          assertTrue(e.getMessage().contains(key + " (ACTIVE)"), e.getMessage());
          assertTrue(e.getMessage().contains(ca + " (ACTIVE)"), e.getMessage());
          TlsIdentityHandle finished =
              assertDoesNotThrow(
                  () -> s.kms.tls().register(m.k2.getPrivate(), first).named(OTHER).register());
          assertEquals(leaf, finished.certificate().id());
          TlsIdentityHandle done =
              assertDoesNotThrow(() -> finished.rekey(m.k3.getPrivate(), theirs));
          assertEquals(
              done.certificate().id(),
              s.other.tls().identity(OTHER).orElseThrow().certificate().id());
          assertEquals(List.of(), preActive(s), "nothing is left over");
        }
        assertEquals(List.of(), s.server.violations());
      }
  }

  /**
   * A renewal stops after its switch, before (nothing Active) or just before its leaf's Activate
   * (its intermediate Active, the kept key linked to the leaf); then another caller revokes the key
   * it keeps. A repeat cannot finish, and says, with nothing changed, how to take the switch off
   * so that nothing is left Active or linked from the identity: the Replacement Object link, the
   * kept key's Certificate link to the leaf, and the revocation of what is Active. Done so, a
   * re-key finishes, and the renewal's objects are left over, none Active, none linked to.
   */
  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void aRepeatOfARenewalWhoseKeptKeyWasRevokedSaysHowToTakeTheSwitchOffLeavingNothingActive(
      KmipVersion version, boolean unique) throws Exception {
    Material m = new Material();
    for (Phase phase : new Phase[] {Phase.SWITCHED, Phase.ACTIVATING})
      try (Scenario s = new Scenario(version, unique, m)) {
        String old = s.start.certificate().id();
        String kept = s.start.privateKey().id();
        String leaf = stop(s, Op.RENEW, phase);
        String ca = s.server.links(leaf, LinkKind.CERTIFICATE).get(0);
        s.other.keys().handle(kept).revoke(RevocationReason.cessationOfOperation("retired"));
        s.t.writes.clear();
        Map<String, String> was = snapshot(s.server);
        StateConflictException e =
            assertThrows(StateConflictException.class, () -> s.call(Call.RENEW));
        assertEquals(Optional.of(kept), e.objectId(), e.getMessage());
        assertEquals(List.of(), s.t.writes, "the refused repeat sent a change");
        assertEquals(was, snapshot(s.server), "nothing was changed");
        String msg = e.getMessage();
        assertTrue(
            msg.contains("take the Replacement Object link to " + leaf + " off " + old), msg);
        boolean activating = phase == Phase.ACTIVATING;
        assertEquals(
            activating,
            msg.contains(", and the Certificate link to " + leaf + " off " + kept),
            msg);
        assertEquals(
            activating,
            msg.contains("then revoke " + ca + " (ACTIVE). The next call starts over"),
            msg);
        assertEquals(!activating, msg.contains("left over, Pre-Active."), msg);
        assertEquals(activating, msg.contains("left over, none Active."), msg);
        // As it says.
        s.other
            .keys()
            .handle(old)
            .removeLink("by hand", Enums.LinkType.REPLACEMENT_OBJECT_LINK, leaf);
        if (activating) {
          s.other.keys().handle(kept).removeLink("by hand", Enums.LinkType.CERTIFICATE_LINK, leaf);
          s.other.keys().handle(ca).revoke(RevocationReason.cessationOfOperation("left over"));
        }
        TlsIdentityHandle done =
            assertDoesNotThrow(
                () ->
                    s.kms
                        .tls()
                        .identity(NAME)
                        .orElseThrow()
                        .rekey(m.k3.getPrivate(), m.pki.chain(m.theirsRekeyed)));
        assertEquals(
            done.certificate().id(), s.other.tls().identity(NAME).orElseThrow().certificate().id());
        for (String id : List.of(leaf, ca))
          assertNotEquals(Optional.of(KeyState.ACTIVE), s.server.state(id), id);
        assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(leaf));
        for (String id : s.server.ids())
          for (LinkKind k : LinkKind.values())
            assertFalse(s.server.links(id, k).contains(leaf), id + " links to " + leaf);
        assertEquals(List.of(), s.server.violations());
      }
  }

  /**
   * A re-key stops after its switch, just before its intermediate's Activate (its key Active) or
   * just before its leaf's (both Active); then another caller names its key. A repeat with a
   * corrected chain is refused with nothing changed. The named key counts as another caller's, so
   * the undo is offered, but the refusal does not say that nothing of the stopped call is Active:
   * it names the key, Active, and says the undo leaves it and the leaf's issuers as they are. Done
   * so, the corrected re-key finishes, and the key and intermediate are as they were.
   */
  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void anUndoPastAnActiveKeyOfTheCallThatAnotherCallerNamedSaysItLeavesThatKeyActive(
      KmipVersion version, boolean unique) throws Exception {
    Material m = new Material();
    for (boolean caActive : new boolean[] {false, true})
      try (Scenario s = new Scenario(version, unique, m)) {
        String old = s.start.certificate().id();
        String leaf;
        if (caActive) leaf = TlsRepeatTest.stopBeforeTheLeafsActivation(s, Op.REKEY);
        else {
          s.t.hook =
              r -> {
                List<String> next = s.server.links(old, LinkKind.REPLACEMENT);
                if (TlsRepeatTest.is(r, Operation.ACTIVATE)
                    && !next.isEmpty()
                    && s.server
                        .links(next.get(0), LinkKind.CERTIFICATE)
                        .contains(TlsOwnershipTest.write(r).target()))
                  throw new TlsOwnershipTest.Stop();
              };
          assertThrows(TlsOwnershipTest.Stop.class, () -> m.job(s.start, Op.REKEY));
          s.t.hook = r -> {};
          leaf = s.server.links(old, LinkKind.REPLACEMENT).get(0);
        }
        String key = s.server.links(leaf, LinkKind.PRIVATE_KEY).get(0);
        String ca = s.server.links(leaf, LinkKind.CERTIFICATE).get(0);
        assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(leaf));
        assertEquals(Optional.of(KeyState.ACTIVE), s.server.state(key));
        assertEquals(
            Optional.of(caActive ? KeyState.ACTIVE : KeyState.PRE_ACTIVE), s.server.state(ca));
        s.other.keys().handle(key).addName("their-key");
        s.reconnect();
        s.t.counting = true;
        s.t.writes.clear();
        StateConflictException e =
            assertRefused(s, snapshot(s.server), () -> corrected(s, Op.REKEY));
        String msg = "intermediate Active " + caActive + ": " + e.getMessage();
        assertTrue(
            msg.contains(" Or take the Replacement Object link to it off " + old + ", then repeat"),
            msg);
        assertTrue(
            msg.contains(
                key
                    + " (ACTIVE) has a name or links that call does not give it, so it counts as"
                    + " another caller's: the undo leaves it, and the issuers of "
                    + leaf
                    + ", as they are."),
            msg);
        assertFalse(msg.contains("nothing that call made is Active"), msg);
        assertFalse(msg.contains("left over, Pre-Active"), msg);
        assertFalse(msg.contains("Do not take"), msg);
        // As it says.
        Map<String, String> before = snapshot(s.server, List.of(key, ca));
        s.other
            .keys()
            .handle(old)
            .removeLink("by hand", Enums.LinkType.REPLACEMENT_OBJECT_LINK, leaf);
        TlsIdentityHandle done = assertDoesNotThrow(() -> corrected(s, Op.REKEY));
        assertNotEquals(leaf, done.certificate().id());
        assertEquals(
            done.certificate().id(), s.other.tls().identity(NAME).orElseThrow().certificate().id());
        assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(leaf));
        assertEquals(before, snapshot(s.server, List.of(key, ca)), msg);
        assertEquals(List.of(), s.server.violations());
      }
  }

  /**
   * What another caller's Pre-Active certificate links to. OWN_CA: the identity's own intermediate
   * (for a registration, another identity's); NAMED_CA and UNNAMED_CA: an Active certificate,
   * named or not, linked only from it; NAMED_KEY: also an Active private key of its own, named,
   * linked both ways; SHARED_KEY: an Active unnamed key, linked both ways, that another
   * certificate links to as well. None of those is as a call leaves the objects it makes.
   * UNNAMED_KEY: an Active unnamed key linked both ways, and the unnamed CA, exactly as a stopped
   * call's own would be, which therefore count.
   */
  enum Foreign {
    OWN_CA,
    NAMED_CA,
    UNNAMED_CA,
    NAMED_KEY,
    SHARED_KEY,
    UNNAMED_KEY
  }

  /**
   * Another caller's Pre-Active certificate, linked as {@code foreign} says: its identifier, then
   * the objects of that caller it links to.
   */
  static List<String> foreign(Scenario s, Foreign foreign) throws Exception {
    Material m = s.m;
    String cert = s.other.keys().register(m.stranger.certificate()).registerPreActive().id();
    List<String> out = new ArrayList<>(List.of(cert));
    String ca;
    if (foreign == Foreign.OWN_CA) ca = s.start.chain().get(1).id();
    else {
      KeyRegistration r = s.other.keys().register(m.reissuedRoot);
      ca = (foreign == Foreign.NAMED_CA ? r.named("their-ca") : r).register().id();
      out.add(ca);
    }
    link(s.other, cert, Enums.LinkType.CERTIFICATE_LINK, ca);
    if (foreign == Foreign.NAMED_KEY
        || foreign == Foreign.SHARED_KEY
        || foreign == Foreign.UNNAMED_KEY) {
      KeyRegistration r = s.other.keys().register(m.k3.getPrivate()).usages(KeyUsage.SIGN);
      KeyHandle key = (foreign == Foreign.NAMED_KEY ? r.named("their-key") : r).registerPreActive();
      key.activate();
      link(s.other, cert, Enums.LinkType.PRIVATE_KEY_LINK, key.id());
      link(s.other, key.id(), Enums.LinkType.CERTIFICATE_LINK, cert);
      out.add(key.id());
      if (foreign == Foreign.SHARED_KEY) {
        String also =
            s.other.keys().register(m.theirsRekeyed.certificate()).registerPreActive().id();
        link(s.other, also, Enums.LinkType.PRIVATE_KEY_LINK, key.id());
        out.add(also);
      }
    }
    return out;
  }

  /**
   * Another caller links the identity's certificate to its own Pre-Active certificate, both ways,
   * that links to Active objects of its own ({@link Foreign}), and may also link the identity's
   * key to it. A renewal or re-key is refused with nothing changed (`REPLACED`), and offers to take
   * the Replacement Object link off, and the key's Certificate link, which leaves those objects as
   * they were: nothing of a call is Active. It used to forbid that, the only remedy, saying it
   * would leave the other caller's Active objects. Where they are exactly as a stopped call's own
   * would be (UNNAMED_KEY), it says not to, as for a stopped call, and to take the links off
   * instead if another caller made them. Done so, the call finishes, and the other caller's objects
   * are as they were.
   */
  @ParameterizedTest
  @MethodSource("ops")
  void anotherCallersNewerCertificateIsOfferedToBeUnlinkedWhateverActiveObjectsItLinksTo(
      KmipVersion version, boolean unique, Op op) throws Exception {
    Material m = new Material();
    for (Foreign foreign : Foreign.values())
      for (boolean keyLinked : new boolean[] {false, true})
        try (Scenario s = new Scenario(version, unique, m)) {
          String old = s.start.certificate().id();
          String kept = s.start.privateKey().id();
          List<String> theirs = foreign(s, foreign);
          String newer = theirs.get(0);
          link(s.other, newer, Enums.LinkType.REPLACED_OBJECT_LINK, old);
          link(s.other, old, Enums.LinkType.REPLACEMENT_OBJECT_LINK, newer);
          if (keyLinked) link(s.other, kept, Enums.LinkType.CERTIFICATE_LINK, newer);
          s.t.counting = true;
          s.t.writes.clear();
          Map<String, String> was = snapshot(s.server);
          StateConflictException e =
              assertThrows(StateConflictException.class, () -> m.job(s.start, op));
          String msg = foreign + ", key linked " + keyLinked + ": " + e.getMessage();
          assertEquals(StateConflictException.Conflict.REPLACED, e.conflict(), msg);
          assertEquals(Optional.of(newer), e.objectId(), msg);
          assertEquals(List.of(), s.t.writes, "the refused call sent a change");
          assertEquals(was, snapshot(s.server), "nothing was changed");
          String keyOff = ", and the Certificate link to " + newer + " off " + kept;
          if (foreign == Foreign.UNNAMED_KEY) {
            assertTrue(
                msg.contains("Do not take the Replacement Object link to " + newer + " off"), msg);
            assertTrue(
                msg.contains(
                    "If another caller made "
                        + newer
                        + " and what it links to, take the link off instead"
                        + (keyLinked ? keyOff : "")
                        + ", then repeat: that leaves them as they were"),
                msg);
          } else {
            assertTrue(
                msg.contains(
                    "otherwise take the Replacement Object link to "
                        + newer
                        + " off "
                        + old
                        + (keyLinked ? keyOff : "")
                        + ", then repeat"),
                msg);
            assertFalse(msg.contains("Do not take"), msg);
          }
          assertEquals(keyLinked, msg.contains(keyOff), msg);
          // As it says.
          s.other
              .keys()
              .handle(old)
              .removeLink("by hand", Enums.LinkType.REPLACEMENT_OBJECT_LINK, newer);
          if (keyLinked)
            s.other
                .keys()
                .handle(kept)
                .removeLink("by hand", Enums.LinkType.CERTIFICATE_LINK, newer);
          Map<String, String> before = snapshot(s.server, theirs);
          TlsIdentityHandle done = assertDoesNotThrow(() -> m.job(s.start, op));
          s.assertFinished(op == Op.RENEW ? Call.RENEW : Call.REKEY, done, msg);
          assertEquals(before, snapshot(s.server, theirs), msg);
        }
  }

  /**
   * Another caller puts a registration's name on its own Pre-Active certificate, which links to
   * Active objects of its own ({@link Foreign}). The registration is refused with nothing changed,
   * and offers to take the name off, which leaves those objects as they were. It used to forbid
   * that, the only remedy. Where they are exactly as a stopped registration's own would be
   * (UNNAMED_KEY), it says not to, and to take the name off instead if another caller made them.
   * Done so, the registration finishes, and the other caller's objects are as they were.
   */
  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void aRegistrationsNameOnAnotherCallersCertificateIsOfferedToBeTakenOffWhateverItLinksTo(
      KmipVersion version, boolean unique) throws Exception {
    Material m = new Material();
    for (Foreign foreign : Foreign.values())
      try (Scenario s = new Scenario(version, unique, m)) {
        List<String> theirs = foreign(s, foreign);
        String named = theirs.get(0);
        s.other.keys().handle(named).addName(OTHER);
        s.t.counting = true;
        s.t.writes.clear();
        Map<String, String> was = snapshot(s.server);
        AlreadyExistsException e =
            assertThrows(AlreadyExistsException.class, () -> s.call(Call.REGISTER));
        String msg = foreign + ": " + e.getMessage();
        assertEquals(Optional.of(named), e.objectId(), msg);
        assertEquals(List.of(), s.t.writes, "the refused call sent a change");
        assertEquals(was, snapshot(s.server), "nothing was changed");
        if (foreign == Foreign.UNNAMED_KEY) {
          assertTrue(msg.contains("Do not take the name off " + named), msg);
          assertTrue(
              msg.contains(
                  "If another caller made "
                      + named
                      + " and what it links to, take the name off instead, then register: that"
                      + " leaves them as they were"),
              msg);
        } else {
          assertTrue(msg.contains("otherwise take the name off " + named + ", then register"), msg);
          assertFalse(msg.contains("Do not take"), msg);
        }
        // As it says.
        s.other.keys().handle(named).removeName(OTHER);
        Map<String, String> before = snapshot(s.server, theirs);
        TlsIdentityHandle done = assertDoesNotThrow(() -> s.call(Call.REGISTER));
        s.assertFinished(Call.REGISTER, done, msg);
        assertEquals(before, snapshot(s.server, theirs), msg);
      }
  }
}
