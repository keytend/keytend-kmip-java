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

import static dev.keytend.kmip.kms.TlsIdentityTest.HOURLY;
import static dev.keytend.kmip.kms.TlsIdentityTest.SCHEDULER;
import static dev.keytend.kmip.kms.TlsIdentityTest.assertWhole;
import static dev.keytend.kmip.kms.TlsIdentityTest.connect;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.kms.TlsIdentityFollower.Status;
import dev.keytend.kmip.kms.TlsIdentityTest.Pki;
import dev.keytend.kmip.model.Attributes;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/** Revocation, compromise, outages and tampering, as a follower sees them. */
class TlsIdentityLifecycleTest {
  static final String NAME = "cassandra/node1";

  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void aRevokedCertificateIsNoLongerPresentedAndARenewalRecovers(
      KmipVersion version, boolean unique) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    Pki pki = new Pki();
    KeyPair k = TestPki.ec();
    try (Kms kms = connect(server)) {
      TlsIdentityHandle h =
          kms.tls().register(k.getPrivate(), pki.chain(pki.leaf("n", k))).named(NAME).register();
      try (TlsIdentityFollower f = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
        String alias = f.keyManager().chooseServerAlias("EC", null, null);
        h.revoke(RevocationReason.cessationOfOperation("node retired"));
        assertEquals(KeyState.DEACTIVATED, server.state(h.certificate().id()).orElseThrow());
        assertEquals(KeyState.ACTIVE, server.state(h.privateKey().id()).orElseThrow());
        h.revoke(RevocationReason.cessationOfOperation("again: passed over"));
        // Until the next refresh the pair is presented; from it on, nothing.
        assertNotNull(f.keyManager().chooseServerAlias("EC", null, null));
        TlsIdentityFollower.State s = f.refresh();
        assertEquals(Status.REVOKED, s.status(), s.toString());
        assertTrue(s.detail().contains(h.certificate().id()), s.detail());
        assertTrue(f.identity().isEmpty());
        assertNull(f.keyManager().chooseServerAlias("EC", null, null));
        assertNull(f.keyManager().chooseClientAlias(new String[] {"EC"}, null, null));
        assertNull(f.keyManager().getPrivateKey(alias));
        assertNull(f.keyManager().getCertificateChain(alias));
        assertThrows(StateConflictException.class, () -> kms.tls().follow(NAME, HOURLY, SCHEDULER));
        // The key is still Active: renewing recovers, from the identity looked up again.
        TlsIdentityHandle again = kms.tls().identity(NAME).orElseThrow();
        assertEquals(h.certificate().id(), again.certificate().id());
        TlsIdentityHandle renewed = again.renew(pki.chain(pki.leaf("n", k)));
        assertEquals(Status.CURRENT, f.refresh().status());
        assertEquals(renewed.certificate().id(), assertWhole(f).certificateId());
        assertEquals(KeyState.DEACTIVATED, server.state(h.certificate().id()).orElseThrow());
        assertEquals(
            List.of(renewed.certificate().id()),
            server.links(h.certificate().id(), LinkKind.REPLACEMENT));
      }
    }
  }

  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void aCompromisedIdentityIsReplacedUnderItsNameAlsoWhereNamesAreUnique(
      KmipVersion version, boolean unique) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    Pki pki = new Pki();
    KeyPair k1 = TestPki.ec(), k2 = TestPki.ec();
    try (Kms kms = connect(server)) {
      TlsIdentityHandle h =
          kms.tls().register(k1.getPrivate(), pki.chain(pki.leaf("n", k1))).named(NAME).register();
      try (TlsIdentityFollower f = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
        h.revoke(RevocationReason.keyCompromise("key leaked", Instant.now()));
        assertEquals(KeyState.COMPROMISED, server.state(h.certificate().id()).orElseThrow());
        assertEquals(KeyState.COMPROMISED, server.state(h.privateKey().id()).orElseThrow());
        assertEquals(
            List.of(NAME), server.names(h.certificate().id()), "a revoked object keeps its name");
        assertEquals(Status.REVOKED, f.refresh().status());
        assertNull(f.keyManager().chooseServerAlias("EC", null, null));
        // Not with the compromised key, and not as a new registration under the name.
        TlsIdentityHandle dead = kms.tls().identity(NAME).orElseThrow();
        StateConflictException keep =
            assertThrows(
                StateConflictException.class, () -> dead.renew(pki.chain(pki.leaf("n", k1))));
        assertTrue(keep.getMessage().contains("rekey"), keep.getMessage());
        assertThrows(
            AlreadyExistsException.class,
            () ->
                kms.tls()
                    .register(k2.getPrivate(), pki.chain(pki.leaf("n", k2)))
                    .named(NAME)
                    .register());
        // A re-key replaces it: the name moves off the compromised certificate, which links to the
        // new one.
        TlsIdentityHandle replaced = dead.rekey(k2.getPrivate(), pki.chain(pki.leaf("n", k2)));
        assertEquals(List.of(NAME), server.names(replaced.certificate().id()));
        assertEquals(List.of(), server.names(h.certificate().id()));
        assertEquals(KeyState.COMPROMISED, server.state(h.certificate().id()).orElseThrow());
        assertEquals(
            List.of(replaced.certificate().id()),
            server.links(h.certificate().id(), LinkKind.REPLACEMENT));
        assertEquals(
            List.of(h.certificate().id()),
            server.links(replaced.certificate().id(), LinkKind.REPLACED));
        assertEquals(Status.CURRENT, f.refresh().status());
        assertEquals(replaced.privateKey().id(), assertWhole(f).privateKeyId());
      }
    }
  }

  @Test
  void aCaCompromiseRevokesTheCertificateAndKeepsTheKey() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1).uniqueNames(true);
    Pki pki = new Pki();
    KeyPair k = TestPki.ec();
    try (Kms kms = connect(server)) {
      TlsIdentityHandle h =
          kms.tls().register(k.getPrivate(), pki.chain(pki.leaf("n", k))).named(NAME).register();
      h.revoke(RevocationReason.caCompromise("issuing CA compromised", Instant.now()));
      assertEquals(KeyState.COMPROMISED, server.state(h.certificate().id()).orElseThrow());
      assertEquals(KeyState.ACTIVE, server.state(h.privateKey().id()).orElseThrow());
      Pki other = new Pki();
      TlsIdentityHandle renewed = h.renew(other.chain(other.leaf("n", k)));
      assertEquals(h.privateKey().id(), renewed.privateKey().id());
      try (TlsIdentityFollower f = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
        assertEquals(other.ca.certificate(), assertWhole(f).chain().get(1));
      }
    }
  }

  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void whileTheKmsIsUnreachableTheLastPairStays(KmipVersion version, boolean unique)
      throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    InMemoryKmipServer other = server.replica();
    Pki pki = new Pki();
    KeyPair k = TestPki.ec();
    try (Kms kms = connect(server);
        Kms operator = connect(other)) {
      TlsIdentityHandle h =
          kms.tls().register(k.getPrivate(), pki.chain(pki.leaf("n", k))).named(NAME).register();
      try (TlsIdentityFollower f = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
        List<TlsIdentityFollower.State> changes = new ArrayList<>();
        f.onChange(changes::add);
        TlsIdentity before = assertWhole(f);
        server.unreachable(true);
        TlsIdentityFollower.State s = f.refresh();
        assertEquals(Status.STALE, s.status());
        assertInstanceOf(TransientException.class, s.failure().orElseThrow());
        assertEquals(before, assertWhole(f));
        assertThrows(TransientException.class, () -> kms.tls().follow(NAME, HOURLY, SCHEDULER));
        // Revoked meanwhile, through a replica this instance cannot reach: not known until it can.
        operator
            .tls()
            .identity(NAME)
            .orElseThrow()
            .revoke(RevocationReason.keyCompromise("leak", Instant.now()));
        assertEquals(Status.STALE, f.refresh().status());
        assertEquals(before, assertWhole(f));
        server.unreachable(false);
        assertEquals(Status.REVOKED, f.refresh().status());
        assertTrue(f.identity().isEmpty());
        assertEquals(
            List.of(Status.STALE, Status.REVOKED),
            changes.stream().map(TlsIdentityFollower.State::status).toList());
        assertEquals(h.certificate().id(), before.certificateId());
      }
    }
  }

  @Test
  void aRefreshThatFailsAfterSeeingTheHeldPairNonActivePresentsNothing() throws Exception {
    for (boolean compromise : new boolean[] {false, true}) {
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      Pki pki = new Pki();
      KeyPair k1 = TestPki.ec(), k2 = TestPki.ec();
      try (Kms kms = connect(server)) {
        TlsIdentityHandle h1 =
            kms.tls()
                .register(k1.getPrivate(), pki.chain(pki.leaf("n", k1)))
                .named(NAME)
                .register();
        try (TlsIdentityFollower f = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
          h1.rekey(k2.getPrivate(), pki.chain(pki.leaf("n", k2)));
          if (compromise)
            h1.privateKey()
                .allowingCompromised()
                .revoke(RevocationReason.keyCompromise("leak", Instant.now()));
          // The new pair's material cannot be read (every attempt of the Get fails).
          for (int i = 0; i < 3; i++) server.failNext(ServerOperation.GET, Fault.UNREACHABLE);
          TlsIdentityFollower.State s = f.refresh();
          assertEquals(Status.STALE, s.status(), s.toString());
          // Neither a Deactivated nor a Compromised key may sign behind an unreadable replacement.
          assertTrue(f.identity().isEmpty(), s.toString());
          assertEquals(Status.CURRENT, f.refresh().status());
        }
      }
    }
  }

  @Test
  void aCertificateWhoseKeyDoesNotLinkBackOrMatchIsNotAnIdentity() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Pki pki = new Pki();
    KeyPair k1 = TestPki.ec(), k2 = TestPki.ec();
    try (Kms kms = connect(server)) {
      // A certificate named as an identity, linked to the key it is for, which does not link back.
      KeyHandle c =
          kms.keys()
              .register(pki.leaf("n", k1).certificate())
              .named("one-sided")
              .usages(KeyUsage.VERIFY)
              .register();
      KeyHandle key1 = kms.keys().register(k1.getPrivate()).usages(KeyUsage.SIGN).register();
      link(kms, c, Enums.LinkType.PRIVATE_KEY_LINK, key1);
      assertThrows(StateConflictException.class, () -> kms.tls().identity("one-sided"));
      StateConflictException e =
          assertThrows(
              StateConflictException.class, () -> kms.tls().follow("one-sided", HOURLY, SCHEDULER));
      assertTrue(e.getMessage().contains("and back"), e.getMessage());
      // Linked both ways to a key it is not for.
      KeyHandle d =
          kms.keys()
              .register(pki.leaf("n", k1).certificate())
              .named("mismatched")
              .usages(KeyUsage.VERIFY)
              .register();
      KeyHandle key2 = kms.keys().register(k2.getPrivate()).usages(KeyUsage.SIGN).register();
      link(kms, d, Enums.LinkType.PRIVATE_KEY_LINK, key2);
      link(kms, key2, Enums.LinkType.CERTIFICATE_LINK, d);
      e =
          assertThrows(
              StateConflictException.class,
              () -> kms.tls().follow("mismatched", HOURLY, SCHEDULER));
      assertTrue(e.getMessage().contains("is not the one"), e.getMessage());
      // Linked both ways to a key of another type (RSA for an EC certificate): not a pair either.
      KeyHandle e2 =
          kms.keys()
              .register(pki.leaf("n", k1).certificate())
              .named("other-type")
              .usages(KeyUsage.VERIFY)
              .register();
      KeyHandle rsa =
          kms.keys().register(TestPki.rsa().getPrivate()).usages(KeyUsage.SIGN).register();
      link(kms, e2, Enums.LinkType.PRIVATE_KEY_LINK, rsa);
      link(kms, rsa, Enums.LinkType.CERTIFICATE_LINK, e2);
      e =
          assertThrows(
              StateConflictException.class,
              () -> kms.tls().follow("other-type", HOURLY, SCHEDULER));
      assertTrue(e.getMessage().contains("is not the one"), e.getMessage());
      // The same pair with the key it is for: an identity.
      link(kms, key1, Enums.LinkType.CERTIFICATE_LINK, c);
      try (TlsIdentityFollower f = kms.tls().follow("one-sided", HOURLY, SCHEDULER)) {
        assertEquals(key1.id(), assertWhole(f).privateKeyId());
      }
    }
  }

  static void link(Kms kms, KeyHandle from, Enums.LinkType type, KeyHandle to) throws Exception {
    kms.protocol()
        .call(
            Requests.addAttribute()
                .uniqueIdentifier(from.id())
                .attribute(Attributes.link(type, to.id()))
                .build());
  }

  @Test
  void anAliasAlwaysNamesOnePairAndOnlyTheLastTwoWithAnActiveKeyAreKept() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V1_4);
    Pki pki = new Pki();
    KeyPair k1 = TestPki.ec();
    Issued l1 = pki.leaf("n", k1);
    try (Kms kms = connect(server)) {
      TlsIdentityHandle h =
          kms.tls().register(k1.getPrivate(), pki.chain(l1)).named(NAME).register();
      try (TlsIdentityFollower f = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
        // A handshake chose the alias, then the identity changed before it read the key and chain.
        String a1 = f.keyManager().chooseEngineServerAlias("EC", null, null);
        h = h.renew(pki.chain(pki.leaf("n", k1)));
        f.refresh();
        String a2 = f.keyManager().chooseEngineClientAlias(new String[] {"RSA", "EC"}, null, null);
        assertNotEquals(a1, a2);
        assertEquals(l1.certificate(), f.keyManager().getCertificateChain(a1)[0]);
        assertTrue(
            TlsIdentities.matches(
                f.keyManager().getPrivateKey(a1), l1.certificate().getPublicKey()));
        assertTrue(
            TlsIdentities.matches(
                f.keyManager().getPrivateKey(a2),
                f.keyManager().getCertificateChain(a2)[0].getPublicKey()));
        assertArrayEquals(new String[] {a2}, f.keyManager().getServerAliases("EC", null));
        assertNull(
            f.keyManager().getServerAliases("RSA", null), "an EC pair is not offered for RSA");
        h.renew(pki.chain(pki.leaf("n", k1)));
        f.refresh();
        assertNull(f.keyManager().getPrivateKey(a1));
        assertNotNull(f.keyManager().getPrivateKey(a2));
        f.close();
        assertNull(f.keyManager().chooseServerAlias("EC", null, null));
        assertNull(f.keyManager().getPrivateKey(a2));
        int before = server.exchanges();
        f.refresh();
        assertEquals(before, server.exchanges(), "a closed follower reads nothing");
      }
    }
  }

  /** Every text value in {@code t}, and every tag, as text. */
  static List<String> contents(dev.keytend.kmip.model.Ttlv t) {
    List<String> out = new ArrayList<>();
    out.add("tag:" + t.tag());
    if (t.type() == dev.keytend.kmip.model.Ttlv.Type.STRUCTURE)
      for (dev.keytend.kmip.model.Ttlv c : t.children()) out.addAll(contents(c));
    else if (t.type() == dev.keytend.kmip.model.Ttlv.Type.TEXT_STRING
        || t.type() == dev.keytend.kmip.model.Ttlv.Type.IDENTIFIER
        || t.type() == dev.keytend.kmip.model.Ttlv.Type.REFERENCE
        || t.type() == dev.keytend.kmip.model.Ttlv.Type.NAME_REFERENCE) out.add(t.textValue());
    else if (t.type() == dev.keytend.kmip.model.Ttlv.Type.ENUMERATION)
      out.add("enum:" + t.tag() + "=" + t.intValue());
    return out;
  }

  /** Whether {@code request} is an Add Attribute whose payload holds every one of {@code parts}. */
  static boolean adds(dev.keytend.kmip.model.Ttlv request, String... parts) {
    dev.keytend.kmip.model.Ttlv item = request.require(dev.keytend.kmip.model.Tag.BATCH_ITEM);
    if (item.require(dev.keytend.kmip.model.Tag.OPERATION).intValue()
        != dev.keytend.kmip.model.Operation.ADD_ATTRIBUTE.code()) return false;
    List<String> c = contents(item.require(dev.keytend.kmip.model.Tag.REQUEST_PAYLOAD));
    for (String part : parts) if (!c.contains(part)) return false;
    return true;
  }

  /** Whether {@code request} adds a Replacement Object link (a Link structure, or the 3.0 attribute). */
  static boolean addsReplacementLink(dev.keytend.kmip.model.Ttlv request, String id) {
    return adds(
            request,
            id,
            "enum:"
                + dev.keytend.kmip.model.Tag.LINK_TYPE.code()
                + "="
                + Enums.LinkType.REPLACEMENT_OBJECT_LINK.code())
        || adds(request, id, "tag:" + dev.keytend.kmip.model.Tag.REPLACEMENT_OBJECT_LINK.code());
  }

  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void aNameBeingMovedIsAReplacementAndANameRemovedIsGone(KmipVersion version, boolean unique)
      throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    Pki pki = new Pki();
    KeyPair k = TestPki.ec();
    // Every attempt to give the name to the new certificate is lost before the server: where names
    // are unique it is then on no object, recorded as being moved to the new certificate.
    boolean[] cutting = {false};
    String[] old = {null};
    dev.keytend.kmip.transport.KmipTransport cut =
        new dev.keytend.kmip.transport.KmipTransport() {
          @Override
          public dev.keytend.kmip.model.Ttlv exchange(dev.keytend.kmip.model.Ttlv request)
              throws java.io.IOException {
            return exchange(request, dev.keytend.kmip.transport.CallContext.NONE);
          }

          @Override
          public dev.keytend.kmip.model.Ttlv exchange(
              dev.keytend.kmip.model.Ttlv request, dev.keytend.kmip.transport.CallContext c)
              throws java.io.IOException {
            // Where names are unique, once the name is off the old certificate.
            if (cutting[0]
                && adds(request, NAME)
                && (!unique || !server.names(old[0]).contains(NAME)))
              throw new java.io.IOException("cut");
            return server.exchange(request, c);
          }
        };
    try (Kms kms =
        Kms.connect(
            server.configure().transport(e -> cut).maximumVersion(KmipVersion.V3_0).build())) {
      TlsIdentityHandle h =
          kms.tls().register(k.getPrivate(), pki.chain(pki.leaf("n", k))).named(NAME).register();
      old[0] = h.certificate().id();
      try (TlsIdentityFollower f = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
        Issued next = pki.leaf("n", k);
        cutting[0] = true;
        assertThrows(PartialCompletionException.class, () -> h.renew(pki.chain(next)));
        cutting[0] = false;
        TlsIdentityFollower.State s = f.refresh();
        if (unique) {
          assertEquals(List.of(), server.names(h.certificate().id()));
          assertEquals(Status.REPLACING, s.status(), s.toString());
        }
        assertEquals(next.certificate(), assertWhole(f).certificate(), s.toString());
        try (TlsIdentityFollower cold = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
          assertEquals(next.certificate(), assertWhole(cold).certificate());
          if (unique) assertEquals(Status.REPLACING, cold.status());
        }
        // The repeat finishes the move.
        TlsIdentityHandle renewed = h.renew(pki.chain(next));
        assertEquals(Status.CURRENT, f.refresh().status());
        // The name taken off by hand, with no move under way: gone, nothing presented.
        renewed.certificate().removeName(NAME);
        s = f.refresh();
        assertEquals(Status.GONE, s.status(), s.toString());
        assertTrue(f.identity().isEmpty());
        assertNull(f.keyManager().chooseServerAlias("EC", null, null));
      }
    }
  }

  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void ofTwoRenewalsAtOnceOneWinsAndTheOtherPresentsNothing(KmipVersion version, boolean unique)
      throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    Pki pki = new Pki();
    KeyPair k = TestPki.ec(), k2 = TestPki.ec();
    try (Kms other = connect(server)) {
      TlsIdentityHandle h =
          other.tls().register(k.getPrivate(), pki.chain(pki.leaf("n", k))).named(NAME).register();
      Issued mine = pki.leaf("n", k), theirs = pki.leaf("n", k2);
      TlsIdentityHandle[] won = new TlsIdentityHandle[1];
      // Just before this call links the old certificate to its new one, another renewal runs to the
      // end.
      dev.keytend.kmip.transport.KmipTransport racing =
          new dev.keytend.kmip.transport.KmipTransport() {
            boolean raced;

            @Override
            public dev.keytend.kmip.model.Ttlv exchange(dev.keytend.kmip.model.Ttlv request)
                throws java.io.IOException {
              return exchange(request, dev.keytend.kmip.transport.CallContext.NONE);
            }

            @Override
            public dev.keytend.kmip.model.Ttlv exchange(
                dev.keytend.kmip.model.Ttlv request, dev.keytend.kmip.transport.CallContext c)
                throws java.io.IOException {
              if (!raced && addsReplacementLink(request, h.certificate().id())) {
                raced = true;
                won[0] =
                    other
                        .tls()
                        .identity(NAME)
                        .orElseThrow()
                        .rekey(k2.getPrivate(), pki.chain(theirs));
              }
              return server.exchange(request, c);
            }
          };
      try (Kms kms =
          Kms.connect(
              server.configure().transport(e -> racing).maximumVersion(KmipVersion.V3_0).build())) {
        TlsIdentityHandle mineHandle = kms.tls().identity(NAME).orElseThrow();
        StateConflictException lost =
            assertThrows(StateConflictException.class, () -> mineHandle.renew(pki.chain(mine)));
        assertFalse(lost instanceof AlreadyExistsException);
        assertTrue(
            lost.getMessage().contains("replaced meanwhile by " + won[0].certificate().id()),
            lost.getMessage());
        try (TlsIdentityFollower f = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
          assertEquals(theirs.certificate(), assertWhole(f).certificate());
        }
        // The loser's new certificate is never presented: it has no name, and the old
        // certificate does not link to it.
        List<String> loser =
            kms.tls().certificates(KeyQuery.all()).entrySet().stream()
                .filter(e -> e.getValue().equals(mine.certificate()))
                .map(java.util.Map.Entry::getKey)
                .toList();
        assertEquals(1, loser.size());
        assertEquals(List.of(), server.names(loser.get(0)));
        assertEquals(
            List.of(won[0].certificate().id()),
            server.links(h.certificate().id(), LinkKind.REPLACEMENT));
        assertTrue(lost.getMessage().contains(loser.get(0)), lost.getMessage());
        // The loser's job, repeated after the winner: it re-keys the identity as it now is.
        TlsIdentityHandle after =
            kms.tls().identity(NAME).orElseThrow().rekey(k.getPrivate(), pki.chain(mine));
        assertEquals(
            List.of(won[0].certificate().id()),
            server.links(after.certificate().id(), LinkKind.REPLACED));
        try (TlsIdentityFollower f = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
          assertEquals(mine.certificate(), assertWhole(f).certificate());
        }
      }
    }
  }

  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void aRepeatAfterTheIdentityMovedOnStartsOver(KmipVersion version, boolean unique)
      throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    Pki pki = new Pki();
    KeyPair k = TestPki.ec(), k2 = TestPki.ec();
    Issued mine = pki.leaf("n", k), theirs = pki.leaf("n", k2);
    String[] old = {null};
    boolean[] cutting = {false};
    // This call stops just before linking the old certificate to its new one.
    dev.keytend.kmip.transport.KmipTransport cut =
        new dev.keytend.kmip.transport.KmipTransport() {
          @Override
          public dev.keytend.kmip.model.Ttlv exchange(dev.keytend.kmip.model.Ttlv request)
              throws java.io.IOException {
            return exchange(request, dev.keytend.kmip.transport.CallContext.NONE);
          }

          @Override
          public dev.keytend.kmip.model.Ttlv exchange(
              dev.keytend.kmip.model.Ttlv request, dev.keytend.kmip.transport.CallContext c)
              throws java.io.IOException {
            if (cutting[0] && addsReplacementLink(request, old[0]))
              throw new java.io.IOException("cut");
            return server.exchange(request, c);
          }
        };
    try (Kms other = connect(server);
        Kms kms =
            Kms.connect(
                server.configure().transport(e -> cut).maximumVersion(KmipVersion.V3_0).build())) {
      TlsIdentityHandle h =
          kms.tls().register(k.getPrivate(), pki.chain(pki.leaf("n", k))).named(NAME).register();
      old[0] = h.certificate().id();
      cutting[0] = true;
      assertThrows(
          PartialCompletionException.class, () -> h.rekey(k.getPrivate(), pki.chain(mine)));
      cutting[0] = false;
      // Meanwhile the identity is re-keyed elsewhere; this job's repeat finds it moved on.
      TlsIdentityHandle won =
          other.tls().identity(NAME).orElseThrow().rekey(k2.getPrivate(), pki.chain(theirs));
      assertThrows(StateConflictException.class, () -> h.rekey(k.getPrivate(), pki.chain(mine)));
      // Repeated from the identity as it is: it starts over, and its new certificate follows the
      // current one; the earlier one is left as it was.
      TlsIdentityHandle after =
          kms.tls().identity(NAME).orElseThrow().rekey(k.getPrivate(), pki.chain(mine));
      assertEquals(
          List.of(won.certificate().id()),
          server.links(after.certificate().id(), LinkKind.REPLACED));
      try (TlsIdentityFollower f = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
        assertEquals(mine.certificate(), assertWhole(f).certificate());
      }
      for (String id : server.ids())
        assertTrue(
            server.names(id).stream().noneMatch(n -> n.contains(".issuing-")),
            id + " " + server.names(id));
    }
  }

  @Test
  void theScheduledRefreshFollowsARenewalAndTellsTheListenersOnce() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Pki pki = new Pki();
    KeyPair k = TestPki.ec();
    try (Kms kms = connect(server)) {
      TlsIdentityHandle h =
          kms.tls().register(k.getPrivate(), pki.chain(pki.leaf("n", k))).named(NAME).register();
      try (TlsIdentityFollower f = kms.tls().follow(NAME, Duration.ofMillis(20), SCHEDULER)) {
        CountDownLatch changed = new CountDownLatch(1);
        List<TlsIdentityFollower.State> seen = new java.util.concurrent.CopyOnWriteArrayList<>();
        f.onChange(
            s -> {
              throw new IllegalStateException("a listener that fails is passed over");
            });
        f.onChange(
            s -> {
              seen.add(s);
              changed.countDown();
            });
        Thread.sleep(100);
        assertEquals(List.of(), seen, "unchanged refreshes tell nobody");
        TlsIdentityHandle renewed = h.renew(pki.chain(pki.leaf("n", k)));
        assertTrue(changed.await(10, TimeUnit.SECONDS));
        assertEquals(
            renewed.certificate().id(), seen.get(0).identity().orElseThrow().certificateId());
        Thread.sleep(100);
        assertEquals(1, seen.size(), seen.toString());
      }
    }
  }

  /**
   * A re-key runs to its end between a cold reader's read of the certificate and its read of
   * the key (as {@code TlsIdentityRaceTest} once found under load: "private key ... is
   * DEACTIVATED"): the reader reads again and presents the new pair, CURRENT. A certificate
   * deactivated with no replacement is still REVOKED after the second read.
   */
  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void aReKeyBetweenAReadersCertificateAndKeyReadsIsReadAgain(KmipVersion version, boolean unique)
      throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    Pki pki = new Pki();
    KeyPair k1 = TestPki.ec(), k2 = TestPki.ec();
    Issued second = pki.leaf("n", k2);
    try (Kms writer = connect(server)) {
      TlsIdentityHandle h =
          writer
              .tls()
              .register(k1.getPrivate(), pki.chain(pki.leaf("n", k1)))
              .named(NAME)
              .register();
      String oldKey = h.privateKey().id();
      TlsIdentityHandle[] rekeyed = new TlsIdentityHandle[1];
      dev.keytend.kmip.transport.KmipTransport between =
          new dev.keytend.kmip.transport.KmipTransport() {
            @Override
            public dev.keytend.kmip.model.Ttlv exchange(dev.keytend.kmip.model.Ttlv request)
                throws java.io.IOException {
              return exchange(request, dev.keytend.kmip.transport.CallContext.NONE);
            }

            @Override
            public dev.keytend.kmip.model.Ttlv exchange(
                dev.keytend.kmip.model.Ttlv request, dev.keytend.kmip.transport.CallContext c)
                throws java.io.IOException {
              boolean getAttributes =
                  request
                          .require(dev.keytend.kmip.model.Tag.BATCH_ITEM)
                          .require(dev.keytend.kmip.model.Tag.OPERATION)
                          .intValue()
                      == dev.keytend.kmip.model.Operation.GET_ATTRIBUTES.code();
              if (rekeyed[0] == null && getAttributes && names(request, oldKey))
                rekeyed[0] = h.rekey(k2.getPrivate(), pki.chain(second));
              return server.exchange(request, c);
            }
          };
      try (Kms reader =
              Kms.connect(
                  server
                      .configure()
                      .transport(e -> between)
                      .maximumVersion(KmipVersion.V3_0)
                      .build());
          TlsIdentityFollower f = reader.tls().follow(NAME, HOURLY, SCHEDULER)) {
        assertNotNull(rekeyed[0], "the re-key ran between the reads");
        assertEquals(KeyState.DEACTIVATED, server.state(oldKey).orElseThrow());
        assertEquals(second.certificate(), assertWhole(f).certificate());
        assertEquals(rekeyed[0].privateKey().id(), f.identity().orElseThrow().privateKeyId());
      }
      rekeyed[0].revoke(RevocationReason.cessationOfOperation("retired"));
      try (Kms reader = connect(server)) {
        assertThrows(
            StateConflictException.class, () -> reader.tls().follow(NAME, HOURLY, SCHEDULER));
      }
    }
  }

  /**
   * A transport to {@code server} that runs {@code action[0]} once, at the {@code at}th Get
   * Attributes request naming {@code watched[0]} ({@code seen[0]} counts them): before the request
   * reaches the server, or once it has answered ({@code afterReply}); sets {@code ran[0]} when it
   * has.
   */
  static dev.keytend.kmip.transport.KmipTransport aroundGetAttributes(
      InMemoryKmipServer server,
      String[] watched,
      int[] seen,
      int at,
      boolean afterReply,
      Runnable[] action,
      boolean[] ran) {
    return new dev.keytend.kmip.transport.KmipTransport() {
      @Override
      public dev.keytend.kmip.model.Ttlv exchange(dev.keytend.kmip.model.Ttlv request)
          throws java.io.IOException {
        return exchange(request, dev.keytend.kmip.transport.CallContext.NONE);
      }

      @Override
      public dev.keytend.kmip.model.Ttlv exchange(
          dev.keytend.kmip.model.Ttlv request, dev.keytend.kmip.transport.CallContext c)
          throws java.io.IOException {
        boolean getAttributes =
            request
                    .require(dev.keytend.kmip.model.Tag.BATCH_ITEM)
                    .require(dev.keytend.kmip.model.Tag.OPERATION)
                    .intValue()
                == dev.keytend.kmip.model.Operation.GET_ATTRIBUTES.code();
        if (!ran[0]
            && watched[0] != null
            && getAttributes
            && names(request, watched[0])
            && ++seen[0] == at) {
          ran[0] = true;
          if (!afterReply) action[0].run();
          else {
            dev.keytend.kmip.model.Ttlv response = server.exchange(request, c);
            action[0].run();
            return response;
          }
        }
        return server.exchange(request, c);
      }
    };
  }

  /**
   * A re-key runs to its end after a reader read the private key Active, before the key's loader
   * reads its attributes again (as {@code TlsIdentityRaceTest} found under load: "STALE: ...
   * private key ... is DEACTIVATED; signing requires Active; presenting nothing"): the reader reads
   * again and presents the new pair, CURRENT, both when it follows the identity already and when
   * it starts.
   */
  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void aReKeyBeforeAReadersKeyLoaderIsReadAgain(KmipVersion version, boolean unique)
      throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    Pki pki = new Pki();
    KeyPair k1 = TestPki.ec(), k2 = TestPki.ec(), k3 = TestPki.ec(), k4 = TestPki.ec();
    Issued second = pki.leaf("n", k2), third = pki.leaf("n", k3), fourth = pki.leaf("n", k4);
    String[] watched = {null};
    Runnable[] action = {null};
    boolean[] ran = {false};
    int[] seen = {0};
    try (Kms writer = connect(server);
        Kms reader =
            Kms.connect(
                server
                    .configure()
                    .transport(
                        e -> aroundGetAttributes(server, watched, seen, 2, false, action, ran))
                    .maximumVersion(KmipVersion.V3_0)
                    .build())) {
      TlsIdentityHandle h1 =
          writer
              .tls()
              .register(k1.getPrivate(), pki.chain(pki.leaf("n", k1)))
              .named(NAME)
              .register();
      try (TlsIdentityFollower f = reader.tls().follow(NAME, HOURLY, SCHEDULER)) {
        // Following: the reader holds the first pair; a re-key to the second ran to its end, and
        // the third replaces the second while the reader loads the second's key.
        TlsIdentityHandle h2 = h1.rekey(k2.getPrivate(), pki.chain(second));
        TlsIdentityHandle[] h3 = {null};
        watched[0] = h2.privateKey().id();
        action[0] = () -> h3[0] = h2.rekey(k3.getPrivate(), pki.chain(third));
        TlsIdentityFollower.State s = f.refresh();
        assertTrue(ran[0], "the re-key ran before the loader's read");
        assertEquals(KeyState.DEACTIVATED, server.state(h2.privateKey().id()).orElseThrow());
        assertEquals(Status.CURRENT, s.status(), s.toString());
        assertEquals(third.certificate(), assertWhole(f).certificate());
        assertEquals(h3[0].privateKey().id(), f.identity().orElseThrow().privateKeyId());

        // Starting: the fourth replaces the third while a new follower loads the third's key.
        TlsIdentityHandle[] h4 = {null};
        ran[0] = false;
        seen[0] = 0;
        watched[0] = h3[0].privateKey().id();
        action[0] = () -> h4[0] = h3[0].rekey(k4.getPrivate(), pki.chain(fourth));
        try (TlsIdentityFollower started = reader.tls().follow(NAME, HOURLY, SCHEDULER)) {
          assertTrue(ran[0], "the re-key ran before the loader's read");
          assertEquals(KeyState.DEACTIVATED, server.state(h3[0].privateKey().id()).orElseThrow());
          assertEquals(Status.CURRENT, started.status(), started.state().toString());
          assertEquals(fourth.certificate(), assertWhole(started).certificate());
          assertEquals(h4[0].privateKey().id(), started.identity().orElseThrow().privateKeyId());
        }
      }
    }
  }

  /**
   * The walk outruns the key read with the held pair (as {@code TlsIdentityRaceTest} found under
   * load: "no private key links to certificate ... and back"): a follower holding the first pair
   * reads it (the key with its Certificate links) while a renewal to the second is under way, the
   * second Active and linked, the name still on the first. Before the walk reads the second, that
   * renewal finishes and another makes the third current, linking the same key to it. The key read
   * with the held pair names neither; it is read again, and the third pair is presented, CURRENT.
   */
  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void aKeyReadBeforeARenewalLinkedItIsReadAgain(KmipVersion version, boolean unique)
      throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    Pki pki = new Pki();
    KeyPair k = TestPki.ec();
    Issued second = pki.leaf("n", k), third = pki.leaf("n", k);
    String[] watched = {null};
    Runnable[] action = {null};
    boolean[] ran = {false};
    int[] seen = {0};
    boolean[] cutName = {false};
    dev.keytend.kmip.transport.KmipTransport cutting =
        new dev.keytend.kmip.transport.KmipTransport() {
          @Override
          public dev.keytend.kmip.model.Ttlv exchange(dev.keytend.kmip.model.Ttlv request)
              throws java.io.IOException {
            return exchange(request, dev.keytend.kmip.transport.CallContext.NONE);
          }

          @Override
          public dev.keytend.kmip.model.Ttlv exchange(
              dev.keytend.kmip.model.Ttlv request, dev.keytend.kmip.transport.CallContext c)
              throws java.io.IOException {
            boolean addAttribute =
                request
                        .require(dev.keytend.kmip.model.Tag.BATCH_ITEM)
                        .require(dev.keytend.kmip.model.Tag.OPERATION)
                        .intValue()
                    == dev.keytend.kmip.model.Operation.ADD_ATTRIBUTE.code();
            if (cutName[0] && addAttribute && names(request, NAME))
              throw new java.io.IOException("cut");
            return server.exchange(request, c);
          }
        };
    try (Kms writer =
            Kms.connect(
                server
                    .configure()
                    .transport(e -> cutting)
                    .retryPolicy(RetryPolicy.none())
                    .maximumVersion(KmipVersion.V3_0)
                    .build());
        Kms reader =
            Kms.connect(
                server
                    .configure()
                    .transport(
                        e -> aroundGetAttributes(server, watched, seen, 1, true, action, ran))
                    .maximumVersion(KmipVersion.V3_0)
                    .build())) {
      TlsIdentityHandle h1 =
          writer.tls().register(k.getPrivate(), pki.chain(pki.leaf("n", k))).named(NAME).register();
      try (TlsIdentityFollower f = reader.tls().follow(NAME, HOURLY, SCHEDULER)) {
        // The renewal to the second pair stops at the name: the second is Active and linked.
        cutName[0] = true;
        assertThrows(KmsException.class, () -> h1.renew(pki.chain(second)));
        cutName[0] = false;
        assertEquals(List.of(NAME), server.names(h1.certificate().id()));
        TlsIdentityHandle[] h3 = {null};
        watched[0] = h1.privateKey().id();
        action[0] =
            () -> {
              TlsIdentityHandle h2 = h1.renew(pki.chain(second));
              h3[0] = h2.renew(pki.chain(third));
            };
        TlsIdentityFollower.State s = f.refresh();
        assertTrue(ran[0], "the renewals ran after the held pair was read");
        assertEquals(Status.CURRENT, s.status(), s.toString());
        assertEquals(third.certificate(), assertWhole(f).certificate());
        assertEquals(h3[0].certificate().id(), f.identity().orElseThrow().certificateId());
      }
    }
  }

  /** Whether {@code t} or a value inside it is the identifier {@code id}. */
  static boolean names(dev.keytend.kmip.model.Ttlv t, String id) {
    switch (t.type()) {
      case STRUCTURE:
        for (dev.keytend.kmip.model.Ttlv c : t.children()) if (names(c, id)) return true;
        return false;
      case TEXT_STRING, IDENTIFIER, REFERENCE:
        // KMIP 3.0 sends a Unique Identifier as a Reference.
        return id.equals(t.textValue());
      default:
        return false;
    }
  }
}
