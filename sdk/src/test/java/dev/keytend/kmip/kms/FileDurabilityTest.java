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
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * The file helpers force the target's directory after the move by
 * default ({@link FileDurability#DURABLE}), so a new target survives a crash once the call
 * returns; {@link FileDurability#CONTENT_ONLY} forces the content only. The directory forces are
 * observed through {@link StagedFiles#directorySync}.
 */
class FileDurabilityTest {
  static final byte[] AAD = "backup".getBytes(StandardCharsets.UTF_8);
  static final byte[] DATA = StagedFilesTest.data(3 * StreamEnvelopes.CHUNK + 5, 18);

  @TempDir Path dir;
  InMemoryKmipServer server;
  Kms kms;
  KeyHandle kek;

  /** Each force: the directory, and what the target held at that moment (null: no target). */
  final List<Map.Entry<Path, byte[]>> forces = new ArrayList<>();

  Path watched;
  IOException failWith;

  /** Forces that saw a temporary file in the directory. */
  int partialsAtForce;

  @BeforeEach
  void setUp() {
    server = InMemoryKmipServer.of(KmipVersion.V2_1);
    kms = Kms.connect(server.configure().build());
    kek = StagedFilesTest.aes(kms, "kek");
    StagedFiles.directorySync =
        d -> {
          forces.add(Map.entry(d, Files.exists(watched) ? Files.readAllBytes(watched) : null));
          if (!partials().isEmpty()) partialsAtForce++;
          if (failWith != null) throw failWith;
        };
  }

  @AfterEach
  void tearDown() {
    StagedFiles.directorySync = StagedFiles::forceDirectory;
    kms.close();
    assertEquals(List.of(), server.violations());
    server.close();
  }

  Set<String> partials() throws IOException {
    try (var files = Files.list(dir)) {
      return files
          .map(p -> p.getFileName().toString())
          .filter(n -> n.endsWith(StagedFiles.SUFFIX))
          .collect(Collectors.toSet());
    }
  }

  void sealTo(Path target, FileDurability durability) throws IOException {
    try (InputStream in = new ByteArrayInputStream(DATA)) {
      if (durability == null) kek.sealTo(target, in, AAD);
      else kek.sealTo(target, in, AAD, durability);
    }
  }

  /**
   * The default forces the directory once, after the move: the force sees the new target, complete
   * (it opens), and no temporary file; for {@code sealTo}, the handle's and the query's {@code
   * openTo}, and a {@link CurrentKey}'s {@code sealTo}, which delegates to the handle.
   */
  @Test
  void theDefaultForcesTheDirectoryAfterTheMove() throws IOException {
    Path sealed = dir.resolve("backup.kts");
    watched = sealed;
    sealTo(sealed, null);
    assertEquals(1, forces.size());
    assertEquals(sealed.toAbsolutePath().getParent(), forces.get(0).getKey());
    assertArrayEquals(
        Files.readAllBytes(sealed), forces.get(0).getValue(), "forced after the move");
    assertEquals(Set.of(), partials());

    Path restored = dir.resolve("restored");
    watched = restored;
    kek.openTo(sealed, restored, AAD);
    assertArrayEquals(DATA, forces.get(1).getValue());
    watched = dir.resolve("again");
    kms.keys().openTo(KeyQuery.byName("kek"), sealed, watched, AAD);
    assertEquals(3, forces.size());
    assertArrayEquals(DATA, forces.get(2).getValue());

    watched = dir.resolve("current.kts");
    try (InputStream in = new ByteArrayInputStream(DATA)) {
      kms.keys().current(kek).sealTo(watched, in, AAD);
    }
    assertEquals(4, forces.size());
    assertArrayEquals(Files.readAllBytes(watched), forces.get(3).getValue());
    for (Map.Entry<Path, byte[]> f : forces) assertEquals(dir.toAbsolutePath(), f.getKey());
    assertEquals(0, partialsAtForce, "every force came after the move");
  }

  /** {@link FileDurability#CONTENT_ONLY}: no directory force. */
  @Test
  void contentOnlyDoesNotForceTheDirectory() throws IOException {
    Path sealed = dir.resolve("backup.kts");
    watched = sealed;
    sealTo(sealed, FileDurability.CONTENT_ONLY);
    kek.openTo(sealed, dir.resolve("a"), AAD, FileDurability.CONTENT_ONLY);
    kms.keys()
        .openTo(KeyQuery.byName("kek"), sealed, dir.resolve("b"), AAD, FileDurability.CONTENT_ONLY);
    assertEquals(List.of(), forces);
    assertArrayEquals(DATA, Files.readAllBytes(dir.resolve("b")));
    kek.openTo(sealed, dir.resolve("c"), AAD, FileDurability.DURABLE);
    assertEquals(1, forces.size());
  }

  /**
   * A file system that refuses every directory force: every default call fails, the
   * second as the first (the SDK never downgrades on its own), each message naming the remedy,
   * and {@link FileDurability#CONTENT_ONLY} works there without forcing anything.
   */
  @Test
  void aFileSystemThatNeverForcesDirectoriesFailsEveryDefaultCallClosed() throws IOException {
    failWith = new IOException("EINVAL");
    for (String name : List.of("one.kts", "two.kts")) {
      Path target = dir.resolve(name);
      watched = target;
      FileSystemException e = assertThrows(FileSystemException.class, () -> sealTo(target, null));
      assertTrue(e.getMessage().contains(name + " was replaced by the new file"), e.getMessage());
      assertTrue(e.getMessage().contains("use FileDurability.CONTENT_ONLY"), e.getMessage());
    }
    assertEquals(2, forces.size(), "the second call forced, and failed, again");
    watched = dir.resolve("three.kts");
    sealTo(watched, FileDurability.CONTENT_ONLY);
    assertEquals(2, forces.size());
    assertEquals(Set.of(), partials());
  }

  /**
   * A {@link CurrentKey}'s {@code sealTo} and {@code openTo} take the durability too
   * ({@link FileDurability#CONTENT_ONLY} forces nothing, the three-argument forms force once); a
   * null durability is refused before anything is sent.
   */
  @Test
  void aCurrentKeysFileHelpersTakeTheDurability() throws IOException {
    CurrentKey current = kms.keys().current(kek);
    Path sealed = dir.resolve("current.kts");
    watched = sealed;
    try (InputStream in = new ByteArrayInputStream(DATA)) {
      current.sealTo(sealed, in, AAD, FileDurability.CONTENT_ONLY);
    }
    current.openTo(sealed, dir.resolve("a"), AAD, FileDurability.CONTENT_ONLY);
    assertEquals(List.of(), forces);
    assertArrayEquals(DATA, Files.readAllBytes(dir.resolve("a")));
    watched = dir.resolve("b");
    current.openTo(sealed, watched, AAD);
    assertEquals(1, forces.size());
    assertArrayEquals(DATA, forces.get(0).getValue());
    current.openTo(sealed, dir.resolve("c"), AAD, FileDurability.DURABLE);
    assertEquals(2, forces.size());

    long before = server.exchanges();
    assertThrows(
        NullPointerException.class,
        () -> current.sealTo(dir.resolve("d"), new ByteArrayInputStream(DATA), AAD, null));
    assertThrows(
        NullPointerException.class, () -> current.openTo(sealed, dir.resolve("e"), AAD, null));
    assertEquals(before, server.exchanges());
    assertFalse(Files.exists(dir.resolve("d")));
  }

  /**
   * A directory that cannot be forced after the move: the call fails with a {@link
   * FileSystemException} naming the directory and saying the target was replaced, as it was (the
   * new file, complete); no temporary file is left. A null durability is refused before anything
   * is sent.
   */
  @Test
  void aFailedForceSaysTheTargetWasReplaced() throws IOException {
    Path sealed = dir.resolve("backup.kts");
    watched = sealed;
    Files.write(sealed, "old".getBytes(StandardCharsets.UTF_8));
    failWith = new IOException("EIO");
    FileSystemException e =
        assertThrows(FileSystemException.class, () -> sealTo(sealed, FileDurability.DURABLE));
    assertEquals(dir.toAbsolutePath().toString(), e.getFile());
    assertTrue(e.getMessage().contains("backup.kts was replaced by the new file"), e.getMessage());
    assertSame(failWith, e.getCause());
    assertEquals(Set.of(), partials());
    failWith = null;
    Path restored = dir.resolve("restored");
    kek.openTo(sealed, restored, AAD);
    assertArrayEquals(DATA, Files.readAllBytes(restored), "the target is the new sealed file");

    int before = server.exchanges();
    assertThrows(
        NullPointerException.class,
        () -> kek.sealTo(dir.resolve("x"), new ByteArrayInputStream(DATA), AAD, nullDurability()));
    assertThrows(
        NullPointerException.class,
        () -> kek.openTo(sealed, dir.resolve("y"), AAD, nullDurability()));
    assertEquals(before, server.exchanges());
  }

  static FileDurability nullDurability() {
    return null;
  }

  /**
   * The real {@link StagedFiles#forceDirectory}: forces a directory it can open, and does nothing,
   * without an exception, for one it cannot (here a directory without read permission, as on
   * Windows for every directory), so a seal into it still succeeds.
   */
  @Test
  void anUnopenableDirectoryIsNotForcedAndTheCallSucceeds() throws IOException {
    StagedFiles.directorySync = StagedFiles::forceDirectory;
    StagedFiles.forceDirectory(dir);
    Assumptions.assumeTrue(StagedFilesTest.posix(dir), "POSIX permissions");
    Path writeOnly = Files.createDirectory(dir.resolve("write-only"));
    Files.setPosixFilePermissions(writeOnly, PosixFilePermissions.fromString("-wx------"));
    try {
      Assumptions.assumeFalse(Files.isReadable(writeOnly), "not root");
      StagedFiles.forceDirectory(writeOnly);
      Path sealed = writeOnly.resolve("backup.kts");
      sealTo(sealed, FileDurability.DURABLE);
      assertTrue(Files.exists(sealed));
    } finally {
      Files.setPosixFilePermissions(writeOnly, PosixFilePermissions.fromString("rwx------"));
    }
  }
}
