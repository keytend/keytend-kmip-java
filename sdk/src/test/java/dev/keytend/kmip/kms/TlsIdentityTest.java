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

import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** TLS identities: registering, renewing, re-keying, revoking, and following them. */
class TlsIdentityTest {
  static final ScheduledExecutorService SCHEDULER =
      Executors.newSingleThreadScheduledExecutor(
          r -> {
            Thread t = new Thread(r, "tls-follower-test");
            t.setDaemon(true);
            return t;
          });

  /** Long enough that tests refresh by hand (the scheduler's daemon thread is shared by the TLS tests). */
  static final Duration HOURLY = Duration.ofHours(1);

  /** KMIP 1.4, 2.1 and the 3.0 draft, each with and without unique names. */
  static Stream<Arguments> servers() {
    List<Arguments> out = new ArrayList<>();
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0))
      for (boolean unique : new boolean[] {false, true}) out.add(Arguments.of(v, unique));
    return out.stream();
  }

  static Kms connect(InMemoryKmipServer server) {
    return Kms.connect(
        server
            .configure()
            .maximumVersion(KmipVersion.V3_0)
            .callTimeout(Duration.ofSeconds(10))
            .build());
  }

  /** A CA, an intermediate CA and keys to issue from them. */
  static final class Pki {
    final Issued root, ca;

    Pki() throws Exception {
      root = TestPki.ca("Test Root");
      ca = TestPki.intermediate("Test Issuing CA", root);
    }

    Issued leaf(String name, KeyPair key) throws Exception {
      return TestPki.leaf(name, key, ca);
    }

    X509Certificate[] chain(Issued leaf) {
      return leaf.chain(ca);
    }
  }

  /** The pair the key manager presents is whole: its key signs what its leaf verifies. */
  static TlsIdentity assertWhole(TlsIdentityFollower f) {
    String alias = f.keyManager().chooseServerAlias("EC", null, null);
    assertNotNull(alias, "a pair is presented: " + f.state());
    PrivateKey key = f.keyManager().getPrivateKey(alias);
    X509Certificate[] chain = f.keyManager().getCertificateChain(alias);
    assertTrue(TlsIdentities.matches(key, chain[0].getPublicKey()), "the key is the certificate's");
    TlsIdentity identity = f.identity().orElseThrow();
    assertEquals(identity.certificate(), chain[0]);
    return identity;
  }

  static List<String> allNames(InMemoryKmipServer server) {
    List<String> names = new ArrayList<>();
    for (String id : server.ids()) names.addAll(server.names(id));
    return names;
  }

  @ParameterizedTest
  @MethodSource("servers")
  void registerRenewAndRekeyLinkThePairAndMoveTheName(KmipVersion version, boolean unique)
      throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    Pki pki = new Pki();
    KeyPair k1 = TestPki.ec();
    Issued l1 = pki.leaf("node1", k1);
    try (Kms kms = connect(server)) {
      TlsIdentityHandle h1 =
          kms.tls()
              .register(k1.getPrivate(), pki.chain(l1))
              .named("cassandra/node1")
              .custom(CustomAttribute.client("tls-role"), "identity")
              .register();
      String c1 = h1.certificate().id(), key1 = h1.privateKey().id();
      // The shape: only the leaf is named; the pair and the chain are linked.
      assertEquals(List.of("cassandra/node1"), server.names(c1));
      assertEquals(List.of(), server.names(key1));
      assertEquals(KeyState.ACTIVE, server.state(c1).orElseThrow());
      assertEquals(KeyState.ACTIVE, server.state(key1).orElseThrow());
      assertEquals(List.of(key1), server.links(c1, LinkKind.PRIVATE_KEY));
      assertEquals(List.of(c1), server.links(key1, LinkKind.CERTIFICATE));
      assertEquals(2, h1.chain().size());
      String ca = h1.chain().get(1).id();
      assertEquals(List.of(ca), server.links(c1, LinkKind.CERTIFICATE));
      assertEquals(KeyState.ACTIVE, server.state(ca).orElseThrow());
      assertEquals(
          "identity",
          h1.certificate().attributes().custom().get(CustomAttribute.client("tls-role")));
      assertTrue(
          allNames(server).stream().noneMatch(n -> n.contains(".issuing-")),
          allNames(server).toString());

      try (TlsIdentityFollower follower = kms.tls().follow("cassandra/node1", HOURLY, SCHEDULER)) {
        assertEquals(TlsIdentityFollower.Status.CURRENT, follower.status());
        TlsIdentity presented = assertWhole(follower);
        assertEquals(c1, presented.certificateId());
        assertEquals(List.of(l1.certificate(), pki.ca.certificate()), presented.chain());

        // Renewal: the same key, a new certificate; the issuer is not registered again.
        Issued l1b = pki.leaf("node1", k1);
        TlsIdentityHandle h2 = h1.renew(pki.chain(l1b));
        String c2 = h2.certificate().id();
        assertNotEquals(c1, c2);
        assertEquals(key1, h2.privateKey().id());
        assertEquals(ca, h2.chain().get(1).id());
        assertEquals(List.of("cassandra/node1"), server.names(c2));
        assertEquals(List.of(), server.names(c1));
        assertEquals(KeyState.DEACTIVATED, server.state(c1).orElseThrow());
        assertEquals(KeyState.ACTIVE, server.state(key1).orElseThrow());
        assertEquals(List.of(c1), server.links(c2, LinkKind.REPLACED));
        assertEquals(List.of(c2), server.links(c1, LinkKind.REPLACEMENT));
        assertEquals(List.of(c1, c2), server.links(key1, LinkKind.CERTIFICATE));
        assertEquals(
            "identity",
            h2.certificate().attributes().custom().get(CustomAttribute.client("tls-role")));
        assertEquals(TlsIdentityFollower.Status.CURRENT, follower.refresh().status());
        assertEquals(c2, assertWhole(follower).certificateId());

        // Re-key: both new; the old pair deactivated, not destroyed.
        KeyPair k2 = TestPki.ec();
        Issued l2 = pki.leaf("node1", k2);
        TlsIdentityHandle h3 = h2.rekey(k2.getPrivate(), pki.chain(l2));
        String c3 = h3.certificate().id(), key2 = h3.privateKey().id();
        assertNotEquals(key1, key2);
        assertEquals(List.of("cassandra/node1"), server.names(c3));
        assertEquals(KeyState.DEACTIVATED, server.state(c2).orElseThrow());
        assertEquals(KeyState.DEACTIVATED, server.state(key1).orElseThrow());
        assertTrue(server.hasMaterial(key1), "deactivated, not destroyed");
        assertEquals(List.of(c3), server.links(key2, LinkKind.CERTIFICATE));
        assertEquals(TlsIdentityFollower.Status.CURRENT, follower.refresh().status());
        TlsIdentity now = assertWhole(follower);
        assertEquals(c3, now.certificateId());
        assertEquals(key2, now.privateKeyId());

        // The identity, looked up again.
        TlsIdentityHandle found = kms.tls().identity("cassandra/node1").orElseThrow();
        assertEquals(c3, found.certificate().id());
        assertEquals(key2, found.privateKey().id());
        assertTrue(
            allNames(server).stream().noneMatch(n -> n.contains(".issuing-")),
            allNames(server).toString());
        for (String id : server.ids())
          assertTrue(
              server.protocolAttributes(id).keySet().stream().noneMatch(a -> a.contains("pending")),
              id);
      }
      assertEquals(List.of(), server.violations());
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void aRepeatAfterSuccessReturnsTheIdentityAndChangesNothing(KmipVersion version, boolean unique)
      throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    Pki pki = new Pki();
    KeyPair k1 = TestPki.ec();
    Issued l1 = pki.leaf("node1", k1);
    try (Kms kms = connect(server)) {
      TlsIdentityHandle h1 =
          kms.tls().register(k1.getPrivate(), pki.chain(l1)).named("n").register();
      int objects = server.ids().size();
      TlsIdentityHandle again =
          kms.tls().register(k1.getPrivate(), pki.chain(l1)).named("n").register();
      assertEquals(h1.certificate().id(), again.certificate().id());
      Issued l1b = pki.leaf("node1", k1);
      TlsIdentityHandle h2 = h1.renew(pki.chain(l1b));
      assertEquals(objects + 1, server.ids().size(), "the issuer is reused");
      // The renewal repeated from the old handle: the identity is that certificate already.
      assertEquals(h2.certificate().id(), h1.renew(pki.chain(l1b)).certificate().id());
      assertEquals(objects + 1, server.ids().size());
    }
  }

  @Test
  void refusalsChangeNothing() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1).uniqueNames(true);
    Pki pki = new Pki();
    KeyPair k1 = TestPki.ec(), k2 = TestPki.ec();
    Issued l1 = pki.leaf("node1", k1);
    try (Kms kms = connect(server)) {
      // Local checks: nothing is sent.
      int before = server.exchanges();
      assertThrows(
          IllegalArgumentException.class, () -> kms.tls().register(k2.getPrivate(), pki.chain(l1)));
      assertThrows(
          IllegalArgumentException.class,
          () -> kms.tls().register(k1.getPrivate(), pki.ca.certificate(), l1.certificate()));
      assertThrows(IllegalArgumentException.class, () -> kms.tls().register(k1.getPrivate()));
      assertThrows(
          IllegalStateException.class,
          () -> kms.tls().register(k1.getPrivate(), pki.chain(l1)).register());
      assertEquals(before, server.exchanges());

      TlsIdentityHandle h1 =
          kms.tls().register(k1.getPrivate(), pki.chain(l1)).named("n").register();
      int objects = server.ids().size();
      // Another identity under the name.
      Issued other = pki.leaf("other", k2);
      AlreadyExistsException taken =
          assertThrows(
              AlreadyExistsException.class,
              () -> kms.tls().register(k2.getPrivate(), pki.chain(other)).named("n").register());
      assertTrue(taken.getMessage().contains("rekey"), taken.getMessage());
      // A name another kind of object has: refused before anything is registered.
      kms.keys().createAes(256).named("taken").usages(KeyUsage.ENCRYPT).create();
      int keys = server.ids().size();
      AlreadyExistsException other2 =
          assertThrows(
              AlreadyExistsException.class,
              () ->
                  kms.tls().register(k2.getPrivate(), pki.chain(other)).named("taken").register());
      assertTrue(other2.getMessage().contains("not a TLS identity"), other2.getMessage());
      assertEquals(keys, server.ids().size());
      objects = keys;
      // A renewal for another key.
      assertThrows(KeyMismatchException.class, () -> h1.renew(pki.chain(other)));
      // A re-key whose leaf is not for the new key.
      assertThrows(
          IllegalArgumentException.class, () -> h1.rekey(k1.getPrivate(), pki.chain(other)));
      assertEquals(objects, server.ids().size());
      // A handle the identity has moved on from.
      TlsIdentityHandle h2 = h1.renew(pki.chain(pki.leaf("node1", k1)));
      int after = server.ids().size();
      StateConflictException stale =
          assertThrows(
              StateConflictException.class, () -> h1.renew(pki.chain(pki.leaf("node1", k1))));
      assertEquals(h1.certificate().id(), stale.objectId().orElseThrow());
      assertTrue(
          stale.observedState().isEmpty(),
          "the current certificate's state is not the old handle's state");
      assertTrue(stale.getMessage().contains(h2.certificate().id()), stale.getMessage());
      assertEquals(after, server.ids().size());
      // Renewing, or following, a name nobody has.
      assertEquals(java.util.Optional.empty(), kms.tls().identity("nobody"));
      assertThrows(NotFoundException.class, () -> kms.tls().follow("nobody", HOURLY, SCHEDULER));
      assertThrows(
          IllegalArgumentException.class, () -> kms.tls().follow("n", Duration.ZERO, SCHEDULER));
    }
  }

  /**
   * A {@code byte[]} custom value is copied by {@code custom(...)}, as {@link KeyCreation}'s
   * and {@link KeyQuery}'s are: a change the caller makes before {@code register()} is not
   * registered.
   */
  @Test
  void aByteArrayCustomValueIsCopiedWhenSet() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Pki pki = new Pki();
    KeyPair k1 = TestPki.ec();
    Issued l1 = pki.leaf("node1", k1);
    byte[] tag = {1, 2, 3};
    try (Kms kms = connect(server)) {
      TlsIdentityRegistration registration =
          kms.tls()
              .register(k1.getPrivate(), pki.chain(l1))
              .named("cassandra/node1")
              .custom(CustomAttribute.client("tls-tag"), tag);
      tag[0] = 9;
      TlsIdentityHandle h = registration.register();
      assertArrayEquals(
          new byte[] {1, 2, 3},
          (byte[]) h.certificate().attributes().custom().get(CustomAttribute.client("tls-tag")));
    }
  }
}
