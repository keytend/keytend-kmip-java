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
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.*;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** A sealing job that fails leaves nothing that opens, and the streams own what they are given. */
class StreamFailureTest {
  static final byte[] AAD = "backup".getBytes(StandardCharsets.UTF_8);
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

  /** A source of {@code plain} that fails with "source failed" once {@code failAt} bytes were read. */
  static InputStream failingAt(byte[] plain, int failAt) {
    return new FilterInputStream(new ByteArrayInputStream(plain)) {
      int served;

      @Override
      public int read(byte[] b, int off, int len) throws IOException {
        if (served >= failAt) throw new IOException("source failed");
        int n = super.read(b, off, Math.min(len, failAt - served));
        served += Math.max(n, 0);
        return n;
      }
    };
  }

  /** The guide's pattern: seal everything {@code source} gives, then finish. */
  static void sealJob(KeyHandle kek, InputStream source, OutputStream file) throws IOException {
    try (SealingStream out = kek.sealing(file, AAD)) {
      source.transferTo(out);
      out.finish();
    }
  }

  /** An input that records whether it was closed. */
  static final class TrackedInput extends FilterInputStream {
    int closes;

    TrackedInput(byte[] data) {
      super(new ByteArrayInputStream(data));
    }

    @Override
    public void close() throws IOException {
      closes++;
      super.close();
    }
  }

  /** An output that records whether it was closed. */
  static class TrackedOutput extends ByteArrayOutputStream {
    int closes;

    @Override
    public void close() {
      closes++;
    }
  }

  // ---- a failed job's output does not open ----

  /**
   * With the guide's pattern, a source failing after 150,000 of 300,000
   * bytes makes the job throw (the source's error, with close's "without finish()" suppressed), and
   * its output does not open: reading it fails before the end, after only authentic, in-order
   * plaintext. A source failing before the first chunk leaves an empty output, which fails at once.
   * The same job with a source that does not fail opens completely. Before, close() wrote the last
   * chunk and the 150,000-byte prefix opened as a complete stream.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aSealingJobWhoseSourceFailsLeavesOutputThatDoesNotOpen(KmipVersion version)
      throws IOException {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle kek = aes(kms, "k");
    byte[] plain = new byte[300_000];
    new Random(1).nextBytes(plain);

    for (int failAt : new int[] {150_000, 1000, 0}) {
      ByteArrayOutputStream file = new ByteArrayOutputStream();
      IOException failed =
          assertThrows(IOException.class, () -> sealJob(kek, failingAt(plain, failAt), file));
      assertEquals("source failed", failed.getMessage());
      assertEquals(1, failed.getSuppressed().length);
      assertTrue(
          failed.getSuppressed()[0].getMessage().contains("without finish()"),
          failed.getSuppressed()[0].getMessage());

      ByteArrayOutputStream seen = new ByteArrayOutputStream();
      KmsException e =
          assertThrows(
              KmsException.class,
              () -> {
                try (InputStream in =
                    kek.opening(new ByteArrayInputStream(file.toByteArray()), AAD)) {
                  for (int n; (n = in.read()) >= 0; ) seen.write(n);
                }
              },
              "the output of a job failing at " + failAt + " must not open");
      assertEquals(KmsException.Category.BAD_DATA, e.category());
      assertEquals(
          failAt < StreamEnvelopes.CHUNK
              ? CryptographicFailureException.Kind.INVALID_CIPHERTEXT
              : CryptographicFailureException.Kind.AUTHENTICATION_FAILED,
          ((CryptographicFailureException) e).kind());
      assertTrue(seen.size() < failAt || seen.size() == 0);
      assertArrayEquals(
          Arrays.copyOf(plain, seen.size()), seen.toByteArray(), "what was released is authentic");
    }

    ByteArrayOutputStream file = new ByteArrayOutputStream();
    sealJob(kek, new ByteArrayInputStream(plain), file);
    try (InputStream in = kek.opening(new ByteArrayInputStream(file.toByteArray()), AAD)) {
      assertArrayEquals(plain, in.readAllBytes());
    }
  }

  /**
   * A block that returns normally without finish() (a forgotten finish(), an early return) gets an
   * IOException from close, after the target was closed, and its output does not open; closing again
   * does nothing. A finished stream closes quietly.
   */
  @Test
  void closingWithoutFinishThrowsAndWritesNoEnd() throws IOException {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "k");
    TrackedOutput file = new TrackedOutput();
    SealingStream out = kek.sealing(file, AAD);
    out.write(new byte[200_000]);
    int before = file.size();
    IOException e = assertThrows(IOException.class, out::close);
    assertTrue(
        e.getMessage().startsWith("seal: ") && e.getMessage().contains("cannot be opened"),
        e.getMessage());
    assertEquals(before, file.size(), "no end is written");
    assertEquals(1, file.closes);
    out.close();
    assertEquals(1, file.closes);
    assertThrows(IOException.class, out::finish);
    assertEquals(
        CryptographicFailureException.Kind.AUTHENTICATION_FAILED,
        assertThrows(
                CryptographicFailureException.class,
                () -> kek.opening(new ByteArrayInputStream(file.toByteArray()), AAD).readAllBytes())
            .kind());

    TrackedOutput good = new TrackedOutput();
    SealingStream finished = kek.sealing(good, AAD);
    finished.write(new byte[200_000]);
    finished.finish();
    finished.close();
    assertEquals(1, good.closes);
    assertArrayEquals(
        new byte[200_000],
        kek.opening(new ByteArrayInputStream(good.toByteArray()), AAD).readAllBytes());
  }

  /**
   * A finish whose flush of the target fails leaves a failed stream: finishing again refuses
   * ("failed earlier") instead of writing a second end, and close reports the output unusable.
   */
  @Test
  void aFinishWhoseFlushFailsLeavesAFailedStream() throws IOException {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "k");
    TrackedOutput file =
        new TrackedOutput() {
          @Override
          public void flush() throws IOException {
            throw new IOException("flush failed");
          }
        };
    SealingStream out = kek.sealing(file, AAD);
    out.write(new byte[1000]);
    assertEquals("flush failed", assertThrows(IOException.class, out::finish).getMessage());
    int size = file.size();
    assertTrue(
        assertThrows(IOException.class, out::finish).getMessage().contains("failed earlier"));
    assertEquals(size, file.size(), "no second end");
    assertTrue(
        assertThrows(IOException.class, out::close).getMessage().contains("cannot be opened"));
    assertEquals(1, file.closes);
  }

  /**
   * The guide's temporary-file recipe: a failed job leaves the previous file in place and no
   * partial file; a successful one replaces the file atomically.
   */
  @Test
  void theTemporaryFileRecipeKeepsThePreviousFileOnFailure(@TempDir Path dir) throws IOException {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "k");
    Path path = dir.resolve("backup.kts");
    byte[] first = new byte[100_000], second = new byte[150_000];
    new Random(2).nextBytes(first);
    new Random(3).nextBytes(second);
    recipe(kek, new ByteArrayInputStream(first), path);
    assertThrows(IOException.class, () -> recipe(kek, failingAt(second, 90_000), path));
    try (Stream<Path> files = Files.list(dir)) {
      assertEquals(List.of(path), files.toList(), "no partial file is left");
    }
    try (InputStream in = kek.opening(Files.newInputStream(path), AAD)) {
      assertArrayEquals(first, in.readAllBytes(), "the previous file is untouched");
    }
    recipe(kek, new ByteArrayInputStream(second), path);
    try (InputStream in = kek.opening(Files.newInputStream(path), AAD)) {
      assertArrayEquals(second, in.readAllBytes());
    }
  }

  /** The recipe as docs/envelope-encryption.md ("Stream large data") shows it. */
  static void recipe(KeyHandle kek, InputStream source, Path path) throws IOException {
    byte[] recordId = AAD;
    Path partial = path.resolveSibling(path.getFileName() + ".partial");
    try {
      try (SealingStream out = kek.sealing(Files.newOutputStream(partial), recordId)) {
        source.transferTo(out);
        out.finish();
      }
      Files.move(partial, path, StandardCopyOption.ATOMIC_MOVE);
    } finally {
      Files.deleteIfExists(partial);
    }
  }

  // ---- the streams own what they are given ----

  /**
   * opening closes its input whenever it throws: other additional data (the server refuses to
   * unwrap), a malformed or truncated header, an error of the input while the header is read, a
   * query the key does not match, and a null query. On success the input stays open until the
   * returned stream is closed. Before, every failure left the input open.
   */
  @Test
  void openingClosesItsInputWhenItThrows() throws IOException {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "k");
    ByteArrayOutputStream file = new ByteArrayOutputStream();
    sealJob(kek, new ByteArrayInputStream(new byte[10_000]), file);
    byte[] good = file.toByteArray();

    TrackedInput otherAad = new TrackedInput(good);
    assertThrows(
        KmsException.class, () -> kek.opening(otherAad, "other".getBytes(StandardCharsets.UTF_8)));
    assertEquals(1, otherAad.closes, "a refused unwrap");

    TrackedInput malformed = new TrackedInput("not a stream".getBytes(StandardCharsets.UTF_8));
    assertThrows(CryptographicFailureException.class, () -> kek.opening(malformed, AAD));
    assertEquals(1, malformed.closes, "a malformed header");

    TrackedInput truncated = new TrackedInput(Arrays.copyOf(good, 20));
    assertThrows(
        CryptographicFailureException.class,
        () -> kms.keys().opening(KeyQuery.byName("k"), truncated, AAD));
    assertEquals(1, truncated.closes, "a truncated header, through KmsKeys");

    boolean[] closed = {false};
    InputStream broken =
        new InputStream() {
          @Override
          public int read() throws IOException {
            throw new IOException("disk error");
          }

          @Override
          public void close() throws IOException {
            closed[0] = true;
            throw new IOException("close failed too");
          }
        };
    IOException io = assertThrows(IOException.class, () -> kek.opening(broken, AAD));
    assertEquals("disk error", io.getMessage());
    assertTrue(closed[0], "an error of the input");
    assertEquals("close failed too", io.getSuppressed()[0].getMessage());

    aes(kms, "another");
    TrackedInput mismatch = new TrackedInput(good);
    assertThrows(
        KeyMismatchException.class,
        () -> kms.keys().opening(KeyQuery.byName("another"), mismatch, AAD));
    assertEquals(1, mismatch.closes, "a query the key does not match");

    TrackedInput noQuery = new TrackedInput(good);
    assertThrows(NullPointerException.class, () -> kms.keys().opening(null, noQuery, AAD));
    assertEquals(1, noQuery.closes, "a null query");

    TrackedInput fine = new TrackedInput(good);
    InputStream in = kek.opening(fine, AAD);
    assertEquals(0, fine.closes);
    assertArrayEquals(new byte[10_000], in.readAllBytes());
    in.close();
    assertEquals(1, fine.closes);
  }

  /**
   * sealing writes nothing to its target before the key checks pass, and closes it when it throws:
   * a Deactivated key (StateConflictException), a key without Decrypt (KeyMismatchException) and
   * KMIP 1.2 (UnsupportedException). Before, the target was left open.
   */
  @Test
  void sealingClosesItsTargetAndWritesNothingWhenItThrows() {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle revoked = aes(kms, "revoked");
    revoked.revoke(RevocationReason.superseded("test"));
    TrackedOutput a = new TrackedOutput();
    assertThrows(StateConflictException.class, () -> revoked.sealing(a, AAD));
    assertEquals(0, a.size());
    assertEquals(1, a.closes, "a Deactivated key");

    KeyHandle encryptOnly = kms.keys().createAes(256).named("e").usages(KeyUsage.ENCRYPT).create();
    TrackedOutput b = new TrackedOutput();
    assertThrows(KeyMismatchException.class, () -> encryptOnly.sealing(b, AAD));
    assertEquals(0, b.size());
    assertEquals(1, b.closes, "a key without Decrypt");

    Kms old = connect(InMemoryKmipServer.of(KmipVersion.V1_2));
    KeyHandle kek12 = aes(old, "k");
    TrackedOutput c = new TrackedOutput();
    assertThrows(UnsupportedException.class, () -> kek12.sealing(c, AAD));
    assertEquals(0, c.size());
    assertEquals(1, c.closes, "KMIP 1.2");

    KeyHandle kek = aes(kms, "k");
    TrackedOutput d = new TrackedOutput();
    SealingStream s = kek.sealing(d, AAD);
    assertEquals(0, d.size(), "nothing is written before the first chunk");
    assertEquals(0, d.closes);
    assertThrows(IOException.class, s::close);
  }
}
