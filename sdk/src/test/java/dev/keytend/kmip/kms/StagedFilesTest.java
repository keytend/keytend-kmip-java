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

import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Sealing into a file and opening a sealed file: the target is replaced only by a complete, verified
 * file, through a temporary file that a failure deletes.
 */
class StagedFilesTest {
  static final byte[] AAD = "backup".getBytes(StandardCharsets.UTF_8);
  static final int C = StreamEnvelopes.CHUNK;
  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();
  @TempDir Path dir;

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

  static byte[] data(int size, long seed) {
    byte[] b = new byte[size];
    new Random(seed).nextBytes(b);
    return b;
  }

  /** The names in {@link #dir}. */
  Set<String> listing() throws IOException {
    try (var files = Files.list(dir)) {
      return files
          .map(p -> p.getFileName().toString())
          .collect(Collectors.toCollection(TreeSet::new));
    }
  }

  static boolean posix(Path p) {
    return p.getFileSystem().supportedFileAttributeViews().contains("posix");
  }

  static final Set<PosixFilePermission> OWNER_ONLY = PosixFilePermissions.fromString("rw-------");

  /** A source that records how much was read from it and whether it was closed. */
  static class Source extends FilterInputStream {
    int served, closes;

    Source(byte[] data) {
      super(new ByteArrayInputStream(data));
    }

    @Override
    public int read() throws IOException {
      int b = super.read();
      if (b >= 0) served++;
      return b;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
      int n = super.read(b, off, len);
      served += Math.max(n, 0);
      return n;
    }

    @Override
    public void close() throws IOException {
      closes++;
      super.close();
    }
  }

  /** A source of {@code plain} that fails with "source failed" once {@code failAt} bytes were read. */
  static InputStream failingAt(byte[] plain, int failAt) {
    return StreamFailureTest.failingAt(plain, failAt);
  }

  /**
   * sealTo and openTo round-trip data of any size into files, with the requests of sealing (1) and
   * opening (2); the plaintext source is read to its end and not closed; an existing target is
   * replaced; the result opens with opening too, and the query form opens it with the query's
   * rules; nothing but the targets is left in the directory, and on POSIX the files are owner-only.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void sealToAndOpenToRoundTripThroughFiles(KmipVersion version) throws IOException {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server);
    KeyHandle kek = aes(kms, "k");
    kek.seal(new byte[1], AAD); // the handle learns its key's usages
    Path sealed = dir.resolve("blob.kts"), plainOut = dir.resolve("blob");
    Files.write(sealed, "an older sealed file".getBytes(StandardCharsets.UTF_8));
    Files.write(plainOut, "an older plaintext".getBytes(StandardCharsets.UTF_8));
    for (int size : new int[] {0, 1, C, 2 * C + 5, 300_000}) {
      byte[] plain = data(size, size);
      Source source = new Source(plain);
      int before = server.exchanges();
      kek.sealTo(sealed, source, AAD);
      assertEquals(1, server.exchanges() - before, "sealTo, size " + size);
      assertEquals(size, source.served, "read to its end");
      assertEquals(-1, source.read(), "read to its end");
      assertEquals(0, source.closes, "the caller owns the source");

      before = server.exchanges();
      kek.openTo(sealed, plainOut, AAD);
      assertEquals(2, server.exchanges() - before, "openTo, size " + size);
      assertArrayEquals(plain, Files.readAllBytes(plainOut), "size " + size);
      try (InputStream in = kek.opening(Files.newInputStream(sealed), AAD)) {
        assertArrayEquals(plain, in.readAllBytes(), "opening reads what sealTo wrote");
      }
      assertEquals(Set.of("blob", "blob.kts"), listing(), "no temporary file is left");
    }

    Path byQuery = dir.resolve("by-query");
    kms.keys().openTo(KeyQuery.byName("k"), sealed, byQuery, AAD);
    assertArrayEquals(data(300_000, 300_000), Files.readAllBytes(byQuery));
    assertThrows(
        KeyMismatchException.class,
        () -> kms.keys().openTo(KeyQuery.byName("another"), sealed, dir.resolve("x"), AAD));
    assertThrows(
        NullPointerException.class, () -> kms.keys().openTo(null, sealed, dir.resolve("x"), AAD));
    assertEquals(Set.of("blob", "blob.kts", "by-query"), listing());

    if (posix(dir)) {
      for (String name : listing())
        assertEquals(
            OWNER_ONLY, Files.getPosixFilePermissions(dir.resolve(name)), name + " is owner-only");
    }

    // A file opens in place.
    kek.openTo(sealed, sealed, AAD);
    assertArrayEquals(data(300_000, 300_000), Files.readAllBytes(sealed));
  }

  /**
   * A source that fails part-way (in the middle, before the first chunk was written, at once)
   * makes sealTo throw the source's error, leaves an existing target byte for byte as it was (a
   * missing one missing), and deletes the temporary file.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aSourceFailingPartWayLeavesTheOldTargetAndNoTemporaryFile(KmipVersion version)
      throws IOException {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle kek = aes(kms, "k");
    Path target = dir.resolve("backup");
    byte[] old = data(100_000, 7);
    kek.sealTo(target, new ByteArrayInputStream(old), AAD);
    byte[] oldFile = Files.readAllBytes(target);
    byte[] plain = data(300_000, 1);
    for (int failAt : new int[] {150_000, 1000, 0}) {
      IOException e =
          assertThrows(IOException.class, () -> kek.sealTo(target, failingAt(plain, failAt), AAD));
      assertEquals("source failed", e.getMessage());
      assertArrayEquals(oldFile, Files.readAllBytes(target), "fail at " + failAt);
      assertEquals(Set.of("backup"), listing(), "fail at " + failAt);

      Path fresh = dir.resolve("fresh");
      assertThrows(IOException.class, () -> kek.sealTo(fresh, failingAt(plain, failAt), AAD));
      assertEquals(Set.of("backup"), listing(), "fail at " + failAt);
    }
    // The old file still opens to the old data.
    Path out = dir.resolve("out");
    kek.openTo(target, out, AAD);
    assertArrayEquals(old, Files.readAllBytes(out));

    // An unchecked failure of the source too.
    InputStream throwing =
        new InputStream() {
          int n;

          @Override
          public int read() {
            if (++n > 70_000) throw new IllegalStateException("source broke");
            return 1;
          }
        };
    assertEquals(
        "source broke",
        assertThrows(IllegalStateException.class, () -> kek.sealTo(target, throwing, AAD))
            .getMessage());
    assertArrayEquals(oldFile, Files.readAllBytes(target));
    assertEquals(Set.of("backup", "out"), listing());
  }

  /**
   * A sealed file that was cut (in a chunk, at a chunk boundary, in the header), changed (in the
   * last chunk, which fails only at the end of the stream, after all other plaintext was released
   * and written; in the wrapped key) or opened with other additional data fails openTo as BAD_DATA,
   * leaves the old target byte for byte as it was, and leaves no plaintext file behind.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aTamperedOrTruncatedSealedFileLeavesTheOldTargetAndNoPlaintext(KmipVersion version)
      throws IOException {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle kek = aes(kms, "k");
    byte[] plain = data(300_000, 3);
    Path good = dir.resolve("good");
    kek.sealTo(good, new ByteArrayInputStream(plain), AAD);
    byte[] stream = Files.readAllBytes(good);
    int header = StreamEnvelopes.readHeader(new ByteArrayInputStream(stream)).bytes().length;
    byte[] lastByteChanged = stream.clone();
    lastByteChanged[stream.length - 1] ^= 1;
    byte[] keyChanged = stream.clone();
    keyChanged[header - 20] ^= 1;
    Map<String, byte[]> bad = new LinkedHashMap<>();
    bad.put("cut in a chunk", Arrays.copyOf(stream, header + C + 16 + 100));
    bad.put("cut at a chunk boundary", Arrays.copyOf(stream, header + 2 * (C + 16)));
    bad.put("cut in the header", Arrays.copyOf(stream, header - 3));
    bad.put("the last byte changed", lastByteChanged);
    bad.put("the wrapped key changed", keyChanged);

    Path target = dir.resolve("plain");
    byte[] old = "the previous plaintext".getBytes(StandardCharsets.UTF_8);
    Files.write(target, old);
    Path sealed = dir.resolve("sealed");
    for (Map.Entry<String, byte[]> e : bad.entrySet()) {
      Files.write(sealed, e.getValue());
      KmsException failed =
          assertThrows(KmsException.class, () -> kek.openTo(sealed, target, AAD), e.getKey());
      assertInstanceOf(CryptographicFailureException.class, failed, e.getKey());
      assertEquals(KmsException.Category.BAD_DATA, failed.category(), e.getKey());
      assertArrayEquals(old, Files.readAllBytes(target), e.getKey());
      assertEquals(Set.of("good", "plain", "sealed"), listing(), e.getKey());
      Path fresh = dir.resolve("fresh");
      assertThrows(
          CryptographicFailureException.class, () -> kek.openTo(sealed, fresh, AAD), e.getKey());
      assertEquals(Set.of("good", "plain", "sealed"), listing(), e.getKey());
    }
    // Other additional data.
    assertThrows(
        CryptographicFailureException.class,
        () -> kek.openTo(good, target, "other".getBytes(StandardCharsets.UTF_8)));
    assertArrayEquals(old, Files.readAllBytes(target));
    assertEquals(Set.of("good", "plain", "sealed"), listing());
    // The intact file opens.
    kek.openTo(good, target, AAD);
    assertArrayEquals(plain, Files.readAllBytes(target));
  }

  /**
   * A key that is not Active (Deactivated, Compromised) or cannot decrypt fails sealTo before the
   * source is read and before any file is created: an existing target is untouched and no file
   * appears. A key opening refuses (Compromised, another key's query) fails openTo the same way.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aRefusedKeyCreatesNoFileAndLeavesTheTarget(KmipVersion version) throws IOException {
    Kms kms = connect(InMemoryKmipServer.of(version));
    KeyHandle kek = aes(kms, "k");
    Path target = dir.resolve("target"), sealed = dir.resolve("sealed");
    byte[] old = "the previous file".getBytes(StandardCharsets.UTF_8);
    Files.write(target, old);
    kek.sealTo(sealed, new ByteArrayInputStream(data(100_000, 5)), AAD);
    byte[] sealedBytes = Files.readAllBytes(sealed);

    KeyHandle revoked = aes(kms, "revoked");
    revoked.revoke(RevocationReason.superseded("test"));
    KeyHandle encryptOnly = kms.keys().createAes(256).named("e").usages(KeyUsage.ENCRYPT).create();
    Map<Class<? extends KmsException>, KeyHandle> refused = new LinkedHashMap<>();
    refused.put(StateConflictException.class, revoked);
    refused.put(KeyMismatchException.class, encryptOnly);
    for (Map.Entry<Class<? extends KmsException>, KeyHandle> e : refused.entrySet()) {
      Source source = new Source(data(10, 1));
      assertThrows(e.getKey(), () -> e.getValue().sealTo(target, source, AAD));
      assertThrows(e.getKey(), () -> e.getValue().sealTo(dir.resolve("new"), source, AAD));
      assertEquals(0, source.served, "the source is not read");
      assertEquals(0, source.closes);
      assertArrayEquals(old, Files.readAllBytes(target));
      assertEquals(Set.of("sealed", "target"), listing());
    }

    assertThrows(
        KeyMismatchException.class,
        () -> kms.keys().openTo(KeyQuery.byName("e"), sealed, target, AAD));
    kek.revoke(RevocationReason.keyCompromise("leaked", Instant.now().minusSeconds(60)));
    assertThrows(StateConflictException.class, () -> kek.openTo(sealed, target, AAD));
    assertThrows(StateConflictException.class, () -> kek.openTo(sealed, dir.resolve("new"), AAD));
    assertArrayEquals(old, Files.readAllBytes(target));
    assertArrayEquals(sealedBytes, Files.readAllBytes(sealed));
    assertEquals(Set.of("sealed", "target"), listing());
    // Named explicitly, a Compromised key still opens it.
    kek.allowingCompromised().openTo(sealed, target, AAD);
    assertArrayEquals(data(100_000, 5), Files.readAllBytes(target));
  }

  /**
   * A target that is a directory, has no file name, or whose directory is missing or a file, and a
   * sealed file that is missing, are refused before anything is sent or created.
   */
  @Test
  void badPathsAreRefusedBeforeAnyRequest() throws IOException {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server);
    KeyHandle kek = aes(kms, "k");
    Path sealed = dir.resolve("sealed");
    kek.sealTo(sealed, new ByteArrayInputStream(new byte[10]), AAD);
    Path sub = Files.createDirectory(dir.resolve("sub"));
    Path aFile = dir.resolve("sealed");
    int before = server.exchanges();

    FileSystemException isDir =
        assertThrows(
            FileSystemException.class, () -> kek.sealTo(sub, InputStream.nullInputStream(), AAD));
    assertTrue(isDir.getMessage().contains("is a directory"), isDir.getMessage());
    assertThrows(
        NoSuchFileException.class,
        () -> kek.sealTo(dir.resolve("missing/x"), InputStream.nullInputStream(), AAD));
    assertThrows(
        NotDirectoryException.class,
        () -> kek.sealTo(aFile.resolve("x"), InputStream.nullInputStream(), AAD));
    assertThrows(
        IllegalArgumentException.class,
        () -> kek.sealTo(dir.getRoot(), InputStream.nullInputStream(), AAD));
    assertThrows(
        NullPointerException.class, () -> kek.sealTo(null, InputStream.nullInputStream(), AAD));
    assertThrows(NullPointerException.class, () -> kek.sealTo(dir.resolve("x"), null, AAD));

    assertThrows(FileSystemException.class, () -> kek.openTo(sealed, sub, AAD));
    assertThrows(
        NoSuchFileException.class, () -> kek.openTo(sealed, dir.resolve("missing/x"), AAD));
    assertThrows(
        NoSuchFileException.class, () -> kek.openTo(dir.resolve("no-such"), dir.resolve("x"), AAD));
    assertThrows(
        NoSuchFileException.class,
        () ->
            kms.keys().openTo(KeyQuery.byName("k"), dir.resolve("no-such"), dir.resolve("x"), AAD));
    assertThrows(NullPointerException.class, () -> kek.openTo(null, dir.resolve("x"), AAD));

    assertEquals(before, server.exchanges(), "nothing was sent");
    assertEquals(Set.of("sealed", "sub"), listing());
    try (var files = Files.list(sub)) {
      assertEquals(0, files.count());
    }

    // A relative target is written in the working directory's terms (here resolved against dir).
    Path relative = Path.of("").toAbsolutePath().relativize(dir.resolve("relative"));
    kek.sealTo(relative, new ByteArrayInputStream(new byte[3]), AAD);
    kek.openTo(relative, dir.resolve("relative.out"), AAD);
    assertArrayEquals(new byte[3], Files.readAllBytes(dir.resolve("relative.out")));
  }

  /**
   * Two sealTo calls for one target at once each stage their own temporary file (both exist, owner
   * only, while both are half-way), and the target ends as one complete file that opens to one of
   * the two plaintexts; no temporary file is left. Repeated, either may win.
   */
  @Test
  void concurrentSealsOfOneTargetLeaveOneCompleteFile() throws Exception {
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "k");
    Path target = dir.resolve("target");
    byte[] a = data(300_000, 1), b = data(250_000, 2);
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      for (int round = 0; round < 4; round++) {
        CyclicBarrier halfway = new CyclicBarrier(3);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<?>> jobs = new ArrayList<>();
        for (byte[] plain : List.of(a, b))
          jobs.add(
              pool.submit(
                  () -> {
                    kek.sealTo(target, pausingAt(plain, 150_000, halfway, go), AAD);
                    return null;
                  }));
        halfway.await(10, TimeUnit.SECONDS);
        Set<String> staged = listing();
        staged.remove("target");
        assertEquals(2, staged.size(), "each call stages its own file: " + staged);
        for (String name : staged) {
          assertTrue(name.startsWith(".target.") && name.endsWith(".partial"), name);
          if (posix(dir))
            assertEquals(OWNER_ONLY, Files.getPosixFilePermissions(dir.resolve(name)), name);
        }
        go.countDown();
        for (Future<?> f : jobs) f.get(30, TimeUnit.SECONDS);
        assertEquals(Set.of("target"), listing(), "round " + round);
        Path out = dir.resolve("out");
        kek.openTo(target, out, AAD);
        byte[] got = Files.readAllBytes(out);
        assertTrue(
            Arrays.equals(a, got) || Arrays.equals(b, got),
            "round " + round + ": one complete file");
        Files.delete(out);
      }
    } finally {
      pool.shutdownNow();
    }
  }

  /** A source of {@code plain} that waits at {@code halfway}, then for {@code go}, after {@code at} bytes. */
  static InputStream pausingAt(byte[] plain, int at, CyclicBarrier halfway, CountDownLatch go) {
    return new FilterInputStream(new ByteArrayInputStream(plain)) {
      int served;
      boolean paused;

      @Override
      public int read(byte[] buf, int off, int len) throws IOException {
        if (served >= at && !paused) {
          paused = true;
          try {
            halfway.await(10, TimeUnit.SECONDS);
            go.await(10, TimeUnit.SECONDS);
          } catch (Exception e) {
            throw new IOException(e);
          }
        }
        int n = super.read(buf, off, paused ? len : Math.min(len, at - served));
        served += Math.max(n, 0);
        return n;
      }
    };
  }

  /**
   * The plaintext file openTo writes is owner-only on POSIX, also when the target it replaces was
   * readable by everyone, and whatever the process's umask lets a plain new file have.
   */
  @Test
  void theOpenedPlaintextIsOwnerOnly() throws IOException {
    org.junit.jupiter.api.Assumptions.assumeTrue(posix(dir), "POSIX permissions");
    Kms kms = connect(InMemoryKmipServer.of(KmipVersion.V2_1));
    KeyHandle kek = aes(kms, "k");
    Path sealed = dir.resolve("sealed"), target = dir.resolve("plain");
    kek.sealTo(sealed, new ByteArrayInputStream(data(70_000, 9)), AAD);
    Files.write(target, new byte[1]);
    Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-r--r--"));
    kek.openTo(sealed, target, AAD);
    assertEquals(OWNER_ONLY, Files.getPosixFilePermissions(target));
    assertArrayEquals(data(70_000, 9), Files.readAllBytes(target));
  }
}
