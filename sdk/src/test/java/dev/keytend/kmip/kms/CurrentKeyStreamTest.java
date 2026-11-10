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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link CurrentKey#sealing} and {@link CurrentKey#opening}: streams under the current key, with
 * the key check and the refusal handling of {@link CurrentKey#seal}. A refused key is followed and
 * the call repeated into the same output, which nothing was written to before the data key was
 * wrapped; the output is closed once, only when the call fails.
 */
class CurrentKeyStreamTest {
  static final byte[] AAD = "backup-2026-11-05".getBytes(StandardCharsets.UTF_8);

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

  static KeyHandle aes(Kms kms, KeyUsage... usages) {
    return kms.keys()
        .createAes(256)
        .usages(usages.length == 0 ? new KeyUsage[] {KeyUsage.ENCRYPT, KeyUsage.DECRYPT} : usages)
        .create();
  }

  /** A follower of {@code key} whose interval never passes: only a refusal moves it. */
  static CurrentKey following(Kms kms, KeyHandle key) {
    return CurrentKeyDataKeysTest.following(kms, key);
  }

  /** Data of three and a half chunks, so the stream has several. */
  static byte[] data() {
    byte[] d = new byte[StreamEnvelopes.CHUNK * 3 + StreamEnvelopes.CHUNK / 2];
    for (int i = 0; i < d.length; i++) d[i] = (byte) (i * 31 + 7);
    return d;
  }

  /** An output that counts its closes and the bytes written. */
  static final class Output extends ByteArrayOutputStream {
    final AtomicInteger closes = new AtomicInteger();

    @Override
    public void close() throws IOException {
      closes.incrementAndGet();
      super.close();
    }
  }

  /** Seals {@code data} through {@code kek.sealing} into {@code out}, finished and closed. */
  static byte[] seal(CurrentKey kek, Output out, byte[] data) throws IOException {
    try (SealingStream s = kek.sealing(out, AAD)) {
      s.write(data);
      s.finish();
    }
    assertEquals(1, out.closes.get(), "closed once, by the stream");
    return out.toByteArray();
  }

  static byte[] open(InputStream plain) throws IOException {
    try (plain) {
      return plain.readAllBytes();
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aStreamSealedUnderTheCurrentKeyOpensThroughEveryEntryPoint(
      KmipVersion version, @TempDir Path dir) throws IOException {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms);
    CurrentKey kek = kms.keys().current(key);
    byte[] data = data();
    int before = s.exchanges();
    byte[] sealed = seal(kek, new Output(), data);
    // One Encrypt (the handle knows its usages from the Create): none per chunk.
    assertEquals(1, s.exchanges() - before);
    assertEquals(key.id(), KmsKeys.sealedStreamKeyId(new ByteArrayInputStream(sealed)));
    assertArrayEquals(data, open(kek.opening(new ByteArrayInputStream(sealed), AAD)));
    assertArrayEquals(data, open(key.opening(new ByteArrayInputStream(sealed), AAD)));
    assertArrayEquals(
        data,
        open(kms.keys().opening(KeyQuery.byIds(key.id()), new ByteArrayInputStream(sealed), AAD)));
    // The format of sealTo: a file sealed there opens as a stream, and the other way round.
    Path file = dir.resolve("sealed");
    kek.sealTo(file, new ByteArrayInputStream(data), AAD);
    assertArrayEquals(data, open(kek.opening(Files.newInputStream(file), AAD)));
    Files.write(dir.resolve("streamed"), sealed);
    kek.openTo(dir.resolve("streamed"), dir.resolve("plain"), AAD);
    assertArrayEquals(data, Files.readAllBytes(dir.resolve("plain")));
    // Another additional data: the data key does not open.
    assertThrows(
        CryptographicFailureException.class,
        () ->
            kek.opening(
                new ByteArrayInputStream(sealed), "other".getBytes(StandardCharsets.UTF_8)));
  }

  /**
   * The key held was rotated by another instance and deactivated: the first Encrypt is refused,
   * the follower moves to the replacement and the call is repeated into the same output, which is
   * still open and empty. The stream names the replacement and opens through the follower and
   * through the old key's lineage.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRefusedKeyIsFollowedAndTheStreamStartedUnderTheReplacement(KmipVersion version)
      throws IOException {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle held = aes(kms);
    CurrentKey kek = following(kms, held);
    kek.handle(); // reads nothing: the interval has not passed
    KeyHandle replacement = held.rotate();
    held.deactivate();
    int encrypts = RotationGraceTest.sent(s, Operation.ENCRYPT);
    Output out = new Output();
    SealingStream stream = kek.sealing(out, AAD);
    assertEquals(0, out.closes.get(), "the repeat writes to the same, open output");
    assertEquals(0, out.size(), "nothing is written before the first chunk");
    assertEquals(2, RotationGraceTest.sent(s, Operation.ENCRYPT) - encrypts, "refused, repeated");
    assertEquals(replacement.id(), kek.handle().id());
    byte[] data = data();
    try (stream) {
      stream.write(data);
      stream.finish();
    }
    byte[] sealed = out.toByteArray();
    assertEquals(replacement.id(), KmsKeys.sealedStreamKeyId(new ByteArrayInputStream(sealed)));
    assertArrayEquals(data, open(kek.opening(new ByteArrayInputStream(sealed), AAD)));
    assertArrayEquals(data, open(held.opening(new ByteArrayInputStream(sealed), AAD)));
  }

  /**
   * A refused key with no newer Active key: {@code StateConflictException}, and the output closed
   * once. A key that could not decrypt what it would seal is refused before anything is sent.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRefusalWithoutANewerKeyAndAKeyThatCannotDecryptCloseTheOutput(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle held = aes(kms);
    CurrentKey kek = following(kms, held);
    held.deactivate();
    Output out = new Output();
    StateConflictException refused =
        assertThrows(StateConflictException.class, () -> kek.sealing(out, AAD));
    assertEquals(held.id(), refused.objectId().orElseThrow());
    assertEquals(1, out.closes.get());
    assertEquals(0, out.size());

    CurrentKey encryptOnly = kms.keys().current(aes(kms, KeyUsage.ENCRYPT));
    int before = s.exchanges(), encrypts = RotationGraceTest.sent(s, Operation.ENCRYPT);
    Output other = new Output();
    assertThrows(KeyMismatchException.class, () -> encryptOnly.sealing(other, AAD));
    assertEquals(1, other.closes.get());
    assertEquals(encrypts, RotationGraceTest.sent(s, Operation.ENCRYPT), "nothing was encrypted");
    assertTrue(s.exchanges() - before <= 1, "at most the usages were read");
    assertThrows(NullPointerException.class, () -> kek.sealing(null, AAD));
  }

  /** A due check moves to the newer key before the stream starts: one Encrypt, under it. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aDueCheckMovesToTheNewerKeyFirst(KmipVersion version) throws IOException {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle held = aes(kms);
    CurrentKey kek = kms.keys().current(held).checkingEvery(Duration.ofNanos(1));
    KeyHandle replacement = held.rotate();
    int encrypts = RotationGraceTest.sent(s, Operation.ENCRYPT);
    byte[] sealed = seal(kek, new Output(), new byte[] {1, 2, 3});
    assertEquals(1, RotationGraceTest.sent(s, Operation.ENCRYPT) - encrypts);
    assertEquals(replacement.id(), KmsKeys.sealedStreamKeyId(new ByteArrayInputStream(sealed)));
  }

  /** {@code opening} closes its input when it throws, also for a malformed header. */
  @Test
  void openingClosesItsInputWhenItThrows() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms = connect(s);
    CurrentKey kek = kms.keys().current(aes(kms));
    AtomicInteger closes = new AtomicInteger();
    InputStream junk =
        new ByteArrayInputStream(new byte[64]) {
          @Override
          public void close() {
            closes.incrementAndGet();
          }
        };
    assertThrows(CryptographicFailureException.class, () -> kek.opening(junk, AAD));
    assertTrue(closes.get() >= 1, "closed");
    assertThrows(NullPointerException.class, () -> kek.opening(null, AAD));
  }

  /** Before KMIP 1.4 there is no AES-GCM Encrypt: refused, the output closed. */
  @Test
  void beforeKmip14ItIsUnsupported() {
    InMemoryKmipServer s = server(KmipVersion.V1_2);
    Kms kms = connect(s);
    CurrentKey kek = kms.keys().current(aes(kms));
    Output out = new Output();
    assertThrows(UnsupportedException.class, () -> kek.sealing(out, AAD));
    assertEquals(1, out.closes.get());
    assertTrue(Arrays.equals(new byte[0], out.toByteArray()));
  }
}
