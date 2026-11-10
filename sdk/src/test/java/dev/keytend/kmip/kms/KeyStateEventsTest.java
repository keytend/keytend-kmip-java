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
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Followers tell {@link KmsListener#keyStateChanged} when they
 * read a key or certificate they use in another state, so a revocation is heard of without the
 * application polling: a {@link CurrentKey} for the key it holds, a {@link TlsIdentityFollower} for
 * its certificate and private key.
 */
class KeyStateEventsTest {
  static final byte[] PLAIN = {1, 2, 3};
  static final byte[] AAD = "record".getBytes(StandardCharsets.UTF_8);

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();
  final List<CurrentKeyFollowerTest.Manual> executors = new CopyOnWriteArrayList<>();

  /** What {@code keyStateChanged} heard: "id FROM->TO". */
  final List<String> changes = new CopyOnWriteArrayList<>();

  /** A follower whose lock must not be held while the listener runs. */
  final AtomicReference<CurrentKey> watching = new AtomicReference<>();

  final List<String> toldLocked = new CopyOnWriteArrayList<>();

  final KmsListener listener =
      new KmsListener() {
        @Override
        public void keyStateChanged(String id, KeyState from, KeyState to) {
          CurrentKey k = watching.get();
          if (k != null && k.locked()) toldLocked.add(id);
          changes.add(id + " " + from + "->" + to);
          throw new IllegalStateException("a listener's failure is passed over");
        }
      };

  @AfterEach
  void cleanUp() {
    executors.forEach(CurrentKeyFollowerTest.Manual::shutdownNow);
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) {
      assertEquals(List.of(), s.violations());
      s.close();
    }
  }

  InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    servers.add(s);
    return s;
  }

  Kms connect(InMemoryKmipServer s) {
    Kms kms =
        Kms.connect(s.configure().maximumVersion(KmipVersion.V3_0).addListener(listener).build());
    clients.add(kms);
    return kms;
  }

  static String change(String id, KeyState from, KeyState to) {
    return id + " " + from + "->" + to;
  }

  /**
   * A refreshing {@link CurrentKey} found by name: a scheduled check that reads the key held
   * Compromised (no replacement, so it stays) tells Active to Compromised, once; the next check
   * tells nothing. Outside the follower's lock; a listener that throws is passed over.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aScheduledCheckTellsARevocationOfTheKeyHeld(KmipVersion version) {
    Kms kms = connect(server(version));
    KeyHandle k0 =
        kms.keys()
            .createAes(256)
            .named("tde-key")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .create();
    CurrentKeyFollowerTest.Manual executor = new CurrentKeyFollowerTest.Manual();
    executors.add(executor);
    CurrentKey kek = kms.keys().current("tde-key").refreshingEvery(Duration.ofMinutes(1), executor);
    watching.set(kek);
    k0.revoke(RevocationReason.keyCompromise("stolen", Instant.now()));
    executor.check();
    assertEquals(List.of(change(k0.id(), KeyState.ACTIVE, KeyState.COMPROMISED)), changes);
    executor.check();
    assertEquals(1, changes.size(), "told once");
    assertEquals(k0.id(), kek.handle().id());
    assertEquals(List.of(), toldLocked);
  }

  /**
   * A {@link CurrentKey} given a handle: its first check reads the key's state and tells nothing;
   * the refresh after a refusal tells Active to Deactivated of the key it moves away from; {@code
   * refresh()} tells the next key's compromise. A key it was moved to is not told until a check
   * read it once.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void everyCheckPathTellsTheKeyHeldsChanges(KmipVersion version) {
    Kms kms = connect(server(version));
    KeyHandle k1 = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    CurrentKey kek = new CurrentKey(kms.keys().handle(k1.id()), Duration.ofHours(1), () -> 0);
    watching.set(kek);
    kek.refresh();
    assertEquals(List.of(), changes, "the first read is the reference");

    KeyHandle k2 = kms.keys().handle(k1.id()).rotate();
    kms.keys().handle(k1.id()).deactivate();
    assertEquals(k2.id(), KmsKeys.sealedKeyId(kek.seal(PLAIN, AAD)));
    assertEquals(List.of(change(k1.id(), KeyState.ACTIVE, KeyState.DEACTIVATED)), changes);

    kms.keys().handle(k2.id()).revoke(RevocationReason.keyCompromise("stolen", Instant.now()));
    kek.refresh();
    assertEquals(change(k2.id(), KeyState.ACTIVE, KeyState.COMPROMISED), changes.get(1));

    KeyHandle k3 = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    kek.moveTo(k3);
    kms.keys().handle(k3.id()).deactivate();
    kek.refresh();
    assertEquals(2, changes.size(), "a key moved to: its first read is the reference");
    assertEquals(List.of(), toldLocked);
  }

  /**
   * A {@link TlsIdentityFollower}: a renewal tells the old certificate's deactivation at the
   * refresh that finds it; a refresh that fails tells nothing and keeps what it watches; a
   * compromise of the renewed identity is told for its certificate and its key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anIdentityFollowerTellsItsCertificateAndKeysChanges(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    TlsIdentityTest.Pki pki = new TlsIdentityTest.Pki();
    KeyPair k1 = TestPki.ec();
    Issued l1 = pki.leaf("node1", k1);
    TlsIdentityHandle h1 =
        kms.tls().register(k1.getPrivate(), pki.chain(l1)).named("cassandra/node1").register();
    String c1 = h1.certificate().id(), key1 = h1.privateKey().id();
    try (TlsIdentityFollower follower =
        kms.tls().follow("cassandra/node1", TlsIdentityTest.HOURLY, TlsIdentityTest.SCHEDULER)) {
      follower.refresh();
      assertEquals(List.of(), changes);

      TlsIdentityHandle h2 = h1.renew(pki.chain(pki.leaf("node1", k1)));
      String c2 = h2.certificate().id();
      assertEquals(TlsIdentityFollower.Status.CURRENT, follower.refresh().status());
      assertEquals(List.of(change(c1, KeyState.ACTIVE, KeyState.DEACTIVATED)), changes);

      s.unreachable(true);
      assertEquals(TlsIdentityFollower.Status.STALE, follower.refresh().status());
      s.unreachable(false);
      assertEquals(1, changes.size());

      h2.revoke(RevocationReason.keyCompromise("stolen", Instant.now()));
      assertEquals(TlsIdentityFollower.Status.REVOKED, follower.refresh().status());
      assertEquals(3, changes.size(), changes.toString());
      assertEquals(
          java.util.Set.of(
              change(c2, KeyState.ACTIVE, KeyState.COMPROMISED),
              change(key1, KeyState.ACTIVE, KeyState.COMPROMISED)),
          java.util.Set.copyOf(changes.subList(1, 3)));
      follower.refresh();
      assertEquals(3, changes.size(), "told once");
    }
  }
}
