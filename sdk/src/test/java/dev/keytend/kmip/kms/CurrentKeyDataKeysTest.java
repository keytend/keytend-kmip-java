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

import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link CurrentKey} has the data-key operations, so envelope
 * users need not fall back to {@code current.handle()} and lose the repeat after a refusal:
 * {@code generateDataKey}, {@code wrapKey} and {@code rewrapKey} work under the current key and
 * are repeated once under the newer key when the key held is refused; {@code unwrapKey} goes
 * through the lineage as {@code open} does.
 */
class CurrentKeyDataKeysTest {
  static final byte[] AAD = "file-7".getBytes(StandardCharsets.UTF_8);
  static final byte[] SECRET = "a 256-bit data key, 32 bytes....".getBytes(StandardCharsets.UTF_8);

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
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
    Kms kms = s.connect();
    clients.add(kms);
    return kms;
  }

  static KeyHandle aes(Kms kms) {
    return kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
  }

  /** A follower of {@code key} whose interval never passes: only a refusal moves it. */
  static CurrentKey following(Kms kms, KeyHandle key) {
    return new CurrentKey(kms.keys().handle(key.id()), Duration.ofHours(1), () -> 0);
  }

  static SecretKeySpec secret() {
    return new SecretKeySpec(SECRET, "AES");
  }

  /**
   * The key held is deactivated after another instance rotated it: {@code generateDataKey}, both
   * {@code wrapKey}s and {@code rewrapKey} are refused once, follow the replacement and are repeated
   * under it (two Encrypts each); what they return names the replacement and unwraps through the
   * follower to the same key.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRefusedKeyIsFollowedAndTheCallRepeatedOnce(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    List<String> calls = List.of("generateDataKey", "wrapKey", "wrapKey with a spec", "rewrapKey");
    for (String call : calls) {
      KeyHandle oldest = aes(kms);
      KeyHandle held = oldest.rotate();
      Ciphertext underOldest = oldest.wrapKey(secret(), AAD);
      CurrentKey kek = following(kms, held);
      KeyHandle replacement = held.rotate();
      held.deactivate();

      int encrypts = RotationGraceTest.sent(s, Operation.ENCRYPT);
      Function<CurrentKey, Ciphertext> run =
          switch (call) {
            case "generateDataKey" ->
                k -> {
                  try (DataKey dk = k.generateDataKey(256, AAD)) {
                    assertArrayEquals(
                        dk.key().getEncoded(),
                        k.unwrapKey(Expect.aes(256), dk.wrapped(), AAD).getEncoded());
                    return dk.wrapped();
                  }
                };
            case "wrapKey" -> k -> k.wrapKey(secret(), AAD);
            case "wrapKey with a spec" -> k -> k.wrapKey(CipherSpec.aesGcm(), secret(), AAD);
            default -> k -> k.rewrapKey(underOldest, AAD);
          };
      Ciphertext wrapped = run.apply(kek);
      assertEquals(replacement.id(), wrapped.keyId(), call);
      assertEquals(replacement.id(), kek.handle().id(), call);
      assertEquals(
          2,
          RotationGraceTest.sent(s, Operation.ENCRYPT) - encrypts,
          call + ": the refused Encrypt and the repeat");
      if (!call.equals("generateDataKey"))
        assertArrayEquals(SECRET, kek.unwrapKey(Expect.aes(256), wrapped, AAD).getEncoded(), call);
    }
  }

  /**
   * {@code unwrapKey} opens keys wrapped by any key of the lineage: an older one, and a newer one
   * another instance made since the follower last checked (the follower does not move for it).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void unwrapKeyGoesThroughTheLineage(KmipVersion version) {
    Kms kms = connect(server(version));
    KeyHandle first = aes(kms);
    Ciphertext byFirst = first.wrapKey(secret(), AAD);
    KeyHandle second = first.rotate();
    CurrentKey kek = following(kms, second);
    assertArrayEquals(SECRET, kek.unwrapKey(Expect.aes(256), byFirst, AAD).getEncoded());

    KeyHandle third = kms.keys().handle(second.id()).rotate();
    Ciphertext byThird = third.wrapKey(secret(), AAD);
    assertArrayEquals(SECRET, kek.unwrapKey(Expect.aes(256), byThird, AAD).getEncoded());
    assertEquals(second.id(), kek.handle().id(), "unwrapping does not move the follower");

    KeyHandle stranger = aes(kms);
    Ciphertext byStranger = stranger.wrapKey(secret(), AAD);
    assertThrows(KeyMismatchException.class, () -> kek.unwrapKey(Expect.aes(256), byStranger, AAD));
  }

  /**
   * {@code rewrapKey} returns a wrapped key already under the key held unchanged, without a request;
   * moves one under an older key to the key held; and throws a refusal of the older key (Compromised)
   * as it is, without following anything.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void rewrapKeyMovesOlderKeysOnly(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle first = aes(kms);
    Ciphertext byFirst = first.wrapKey(secret(), AAD);
    KeyHandle second = first.rotate();
    CurrentKey kek = following(kms, second);
    Ciphertext bySecond = kek.wrapKey(secret(), AAD);

    long before = s.exchanges();
    assertSame(bySecond, kek.rewrapKey(bySecond, AAD));
    assertEquals(before, s.exchanges(), "no request for a key already under the key held");

    Ciphertext moved = kek.rewrapKey(byFirst, AAD);
    assertEquals(second.id(), moved.keyId());
    assertArrayEquals(SECRET, kek.unwrapKey(Expect.aes(256), moved, AAD).getEncoded());

    first.revoke(RevocationReason.keyCompromise("test", Instant.now()));
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> kek.rewrapKey(byFirst, AAD));
    assertEquals(first.id(), e.objectId().orElseThrow());
    assertEquals(second.id(), kek.handle().id());
  }

  /**
   * The chunked delegations: a sealer refused under the key held follows the replacement (two
   * Encrypts) and seals under it; an opener reads a header under an older key of the lineage; and
   * {@code rewrapHeader} moves that header to the key held, its chunks still opening, while a
   * header already under the key held comes back as the same array, without a request.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theChunkedCallsFollowTheCurrentKey(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle oldest = aes(kms);
    byte[] chunk = "chunk zero".getBytes(StandardCharsets.UTF_8);
    byte[] oldHeader;
    byte[] sealedUnderOldest;
    try (ChunkedSealer sealer = oldest.chunkedSealer(AAD)) {
      oldHeader = sealer.header();
      sealedUnderOldest = sealer.seal(0, chunk);
    }
    KeyHandle held = oldest.rotate();
    CurrentKey kek = following(kms, held);
    KeyHandle replacement = held.rotate();
    held.deactivate();

    int encrypts = RotationGraceTest.sent(s, Operation.ENCRYPT);
    try (ChunkedSealer sealer = kek.chunkedSealer(AAD)) {
      assertEquals(replacement.id(), sealer.keyId());
      byte[] header = sealer.header();
      byte[] sealed = sealer.seal(3, chunk);
      try (ChunkedOpener opener = kek.chunkedOpener(header, AAD)) {
        assertArrayEquals(chunk, opener.open(3, sealed));
      }
      int before = s.exchanges();
      assertSame(header, kek.rewrapHeader(header, AAD));
      assertEquals(before, s.exchanges());
    }
    assertEquals(
        encrypts + 2, RotationGraceTest.sent(s, Operation.ENCRYPT), "one refused, one repeated");
    assertEquals(replacement.id(), kek.handle().id());

    try (ChunkedOpener opener = kek.chunkedOpener(oldHeader, AAD)) {
      assertEquals(oldest.id(), opener.keyId());
      assertArrayEquals(chunk, opener.open(0, sealedUnderOldest));
    }
    byte[] moved = kek.rewrapHeader(oldHeader, AAD);
    assertEquals(replacement.id(), KmsKeys.chunkedHeaderKeyId(moved));
    try (ChunkedOpener opener = kek.chunkedOpener(moved, AAD)) {
      assertArrayEquals(chunk, opener.open(0, sealedUnderOldest));
    }
  }
}
