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

import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Random;
import javax.crypto.spec.SecretKeySpec;

/**
 * The persisted-format fixtures of {@link PersistedFormatsTest}: a KEK of known bytes under a known
 * identifier, registered in an {@link InMemoryKmipServer}, and the data each format holds. {@link
 * #main} writes one file per format ({@link ChunkedFormatFixtures} the KTR files), so the same
 * source, compiled against a release's JAR, writes that release's fixtures. {@code
 * KeyHandle.seal} is package-private ({@code CurrentKey} seals): this class reaches it because it
 * is in the same package, {@code dev.keytend.kmip.kms}, on the class path; keep it there, or move
 * it to {@code CurrentKey.seal} if that call goes:
 *
 * <pre>
 * cp=keytend-kmip-X.Y.Z.jar:keytend-kmip-testing-X.Y.Z.jar
 * javac -cp $cp -d out FormatFixtures.java ChunkedFormatFixtures.java
 * java -cp $cp:out dev.keytend.kmip.kms.FormatFixtures sdk/src/test/resources/formats/X.Y.Z
 * java -cp $cp:out dev.keytend.kmip.kms.ChunkedFormatFixtures sdk/src/test/resources/formats/X.Y.Z
 * </pre>
 *
 * Never regenerate the fixtures of a released version: they are what that version wrote.
 */
public final class FormatFixtures {
  /** The KEK's identifier on the fixture server. */
  public static final String KEK_ID = "keytend-kmip-format-fixture-kek";

  /** The additional data of every fixture that takes it. */
  public static final byte[] AAD = "persisted-format-fixture".getBytes(StandardCharsets.UTF_8);

  /** The size of the KTS fixture's plaintext: two whole 64 KiB chunks and a part. */
  public static final int STREAM_SIZE = 2 * 64 * 1024 + 100;

  private FormatFixtures() {}

  /** The KEK's bytes: 0x00 to 0x1f. */
  public static byte[] kekBytes() {
    byte[] k = new byte[32];
    for (int i = 0; i < k.length; i++) k[i] = (byte) i;
    return k;
  }

  /** The data key the {@code ktc-aes-kw} fixture wraps: 0x20 to 0x3f. */
  public static byte[] wrappedKeyBytes() {
    byte[] k = new byte[32];
    for (int i = 0; i < k.length; i++) k[i] = (byte) (0x20 + i);
    return k;
  }

  /** A plaintext of {@code size} bytes from a fixed seed. */
  public static byte[] plaintext(int size) {
    byte[] b = new byte[size];
    new Random(20261029L).nextBytes(b);
    return b;
  }

  /** A server (KMIP 2.1) holding only the fixture KEK, Active, under {@link #KEK_ID}. */
  static InMemoryKmipServer server() {
    return server(KmipVersion.V2_1);
  }

  /** {@link #server()} at {@code version}. */
  static InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    server.identifierSource(() -> KEK_ID);
    try (Kms kms = server.connect()) {
      KeyHandle kek =
          kms.keys()
              .register(new SecretKeySpec(kekBytes(), "AES"))
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.WRAP_KEY, KeyUsage.UNWRAP_KEY)
              .register();
      if (!kek.id().equals(KEK_ID))
        throw new IllegalStateException("The fixture KEK is " + kek.id());
    }
    return server;
  }

  /** Writes {@code ktc-aes-gcm.bin}, {@code ktc-aes-cbc.bin}, {@code ktc-aes-kw.bin}, {@code kte.bin} and {@code kts.bin} into {@code args[0]}. */
  public static void main(String[] args) throws IOException {
    Path out = Files.createDirectories(Path.of(args[0]));
    InMemoryKmipServer server = server();
    try (Kms kms = server.connect()) {
      KeyHandle kek = kms.keys().handle(KEK_ID);
      Files.write(
          out.resolve("ktc-aes-gcm.bin"),
          kek.encrypt(CipherSpec.aesGcm(), plaintext(100), AAD).toBytes());
      Files.write(
          out.resolve("ktc-aes-cbc.bin"), kek.encrypt(CipherSpec.cbc(), plaintext(48)).toBytes());
      Files.write(
          out.resolve("ktc-aes-kw.bin"),
          kek.wrapKey(CipherSpec.keyWrap(), new SecretKeySpec(wrappedKeyBytes(), "AES"), null)
              .toBytes());
      Files.write(out.resolve("kte.bin"), kek.seal(plaintext(1000), AAD));
      ByteArrayOutputStream stream = new ByteArrayOutputStream();
      try (SealingStream s = kek.sealing(stream, AAD)) {
        s.write(plaintext(STREAM_SIZE));
        s.finish();
      }
      Files.write(out.resolve("kts.bin"), stream.toByteArray());
    } finally {
      server.close();
    }
  }
}
