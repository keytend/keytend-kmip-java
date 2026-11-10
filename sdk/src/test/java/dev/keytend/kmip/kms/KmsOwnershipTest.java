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

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** An identifier names an object only on its own server; handles of another Kms. */
class KmsOwnershipTest {
  static final byte[] AAD = "order-1042".getBytes(StandardCharsets.UTF_8);
  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  Kms connect(InMemoryKmipServer server) {
    servers.add(server);
    Kms kms = Kms.connect(server.configure().build());
    clients.add(kms);
    return kms;
  }

  static KeyHandle aes(Kms kms, String name) {
    return kms.keys()
        .createAes(256)
        .named(name)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .create();
  }

  // ---- replace refuses a handle of another Kms ----

  /**
   * A secret on server A and an unrelated secret on server B with the same
   * identifier and name. B's builder replacing A's handle is IllegalArgumentException before
   * anything is sent; both secrets stay Active with their names, and B has no new object. Before,
   * it read and deactivated B's unrelated secret. A handle from a withTimeout view (either way
   * round) is the same Kms and is accepted.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void replaceRefusesAHandleOfAnotherKms(KmipVersion version) {
    InMemoryKmipServer a = InMemoryKmipServer.of(version), b = InMemoryKmipServer.of(version);
    Kms x = connect(a), y = connect(b);
    KeyHandle old = x.keys().registerSecret("old-A".toCharArray()).named("secret").register();
    KeyHandle unrelated = y.keys().registerSecret("old-B".toCharArray()).named("secret").register();
    assertEquals(old.id(), unrelated.id(), "the identifiers collide");
    assertNotEquals(old, unrelated);
    int before = b.exchanges(), beforeA = a.exchanges();
    KeyRegistration builder = y.keys().registerSecret("new".toCharArray()).named("secret");
    IllegalArgumentException e =
        assertThrows(IllegalArgumentException.class, () -> builder.replace(old));
    assertTrue(
        e.getMessage().startsWith("replace: ") && e.getMessage().contains("another Kms"),
        e.getMessage());
    assertEquals(before, b.exchanges(), "nothing sent to B");
    assertEquals(beforeA, a.exchanges(), "nothing sent to A");
    assertEquals(KeyState.ACTIVE, unrelated.attributes().state());
    assertEquals(KeyState.ACTIVE, old.attributes().state());
    assertEquals(unrelated.id(), y.keys().findByName("secret").orElseThrow().id());
    assertEquals(1, y.keys().list(KeyQuery.all()).size(), "nothing registered on B");

    // A view of the same Kms is the same Kms, either way round.
    Kms view = y.withTimeout(Duration.ofSeconds(20));
    KeyHandle throughView = view.keys().findByName("secret").orElseThrow();
    KeyHandle next =
        y.keys().registerSecret("next".toCharArray()).named("secret").replace(throughView);
    assertEquals(KeyState.DEACTIVATED, unrelated.attributes().state());
    KeyHandle last = view.keys().registerSecret("last".toCharArray()).named("secret").replace(next);
    assertEquals(last.id(), y.keys().findByName("secret").orElseThrow().id());
  }

  // ---- rewrap to a handle of another Kms ----

  /**
   * A record sealed by key mock-1 on server A, moved to key mock-1 on server
   * B. The record is migrated (the result names B's key and B opens it to the same plaintext)
   * instead of coming back unchanged, which B could not open. Repeating the migration returns the
   * migrated record unchanged after B authenticated it, sending nothing to A. The same for a
   * wrapped data key with rewrapKeyTo.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void rewrapToAnotherKmsWithACollidingIdentifierMigrates(KmipVersion version) {
    InMemoryKmipServer a = InMemoryKmipServer.of(version), b = InMemoryKmipServer.of(version);
    Kms x = connect(a), y = connect(b);
    KeyHandle old = aes(x, "a");
    KeyHandle target = aes(y, "b");
    assertEquals(old.id(), target.id(), "the identifiers collide");
    byte[] plain = {42, 43};
    byte[] sealed = old.seal(plain, AAD);

    byte[] moved = old.rewrapTo(target, sealed, AAD);
    assertNotSame(sealed, moved);
    assertArrayEquals(plain, target.open(moved, AAD), "B opens the migrated record");
    assertThrows(KmsException.class, () -> target.open(sealed, AAD), "B cannot open A's record");
    int beforeA = a.exchanges();
    assertSame(
        moved,
        old.rewrapTo(target, moved, AAD),
        "a repeated migration returns the record unchanged");
    assertEquals(beforeA, a.exchanges(), "A is not asked about a record B opens");

    try (DataKey dk = old.generateDataKey(256, AAD)) {
      Ciphertext wrapped = dk.wrapped();
      Ciphertext movedKey = old.rewrapKeyTo(target, wrapped, AAD);
      assertNotSame(wrapped, movedKey);
      try (DestroyableSecretKey back = target.unwrapKey(Expect.aes(256), movedKey, AAD)) {
        assertArrayEquals(dk.key().getEncoded(), back.getEncoded());
      }
      beforeA = a.exchanges();
      assertSame(movedKey, old.rewrapKeyTo(target, movedKey, AAD));
      assertEquals(beforeA, a.exchanges());
    }
  }

  /**
   * Without a collision too: a record of A's key moves to a key of B with another identifier, and a
   * repeat is unchanged; a record that B does not open (other additional data) is then opened
   * through the source, which refuses it (KeyMismatchException), and nothing is sealed.
   */
  @Test
  void rewrapToAnotherKmsMigratesAndCanBeRepeated() {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1),
        b = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms x = connect(a), y = connect(b);
    KeyHandle old = aes(x, "a");
    aes(y, "other");
    KeyHandle target = aes(y, "b");
    assertNotEquals(old.id(), target.id());
    byte[] sealed = old.seal(new byte[] {7}, AAD);
    byte[] moved = old.rewrapTo(target, sealed, AAD);
    assertEquals(target.id(), KmsKeys.sealedKeyId(moved));
    assertArrayEquals(new byte[] {7}, target.open(moved, AAD));
    assertSame(moved, old.rewrapTo(target, moved, AAD));

    // The target's record with other additional data: B does not open it, so A is asked, which
    // does not know the key; nothing is sealed.
    int beforeB = b.exchanges();
    KeyMismatchException e =
        assertThrows(
            KeyMismatchException.class,
            () -> old.rewrapTo(target, moved, "other".getBytes(StandardCharsets.UTF_8)));
    assertTrue(e.getMessage().contains(target.id()), e.getMessage());
    assertEquals(2, b.exchanges() - beforeB, "B's Get Attributes and Decrypt, and no Encrypt");
  }

  /**
   * A target of the same Kms, also through a withTimeout view, keeps the unchanged return without a
   * request; only another Kms loses it.
   */
  @Test
  void aViewOfTheSameKmsKeepsTheUnchangedReturn() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server);
    KeyHandle key = aes(kms, "k");
    byte[] sealed = key.seal(new byte[] {1}, AAD);
    KeyHandle viewed = kms.withTimeout(Duration.ofSeconds(20)).keys().handle(key.id());
    try (DataKey dk = key.generateDataKey(256, AAD)) {
      Ciphertext wrapped = dk.wrapped();
      int before = server.exchanges();
      assertSame(sealed, key.rewrapTo(viewed, sealed, AAD));
      assertSame(sealed, viewed.rewrap(sealed, AAD));
      assertSame(sealed, viewed.rewrapTo(key, sealed, AAD));
      assertSame(wrapped, key.rewrapKeyTo(viewed, wrapped, AAD));
      assertEquals(before, server.exchanges(), "nothing sent");
    }
  }
}
