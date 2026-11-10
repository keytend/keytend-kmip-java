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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.file.FileSystemException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.NotDirectoryException;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;

/**
 * Sealing into a file and opening a sealed file ({@link CurrentKey#sealTo}, {@link
 * KeyHandle#openTo}, {@link KmsKeys#openTo}): the output goes to a temporary file in the target's
 * directory, created only once the key was accepted, forced to the device when complete and moved
 * onto the target atomically; on any failure the temporary file is deleted and the target is not
 * touched. With {@link FileDurability#DURABLE} the directory is forced after the move.
 */
final class StagedFiles {
  /** The suffix of temporary files; their prefix is {@code .<the target's name>.}. */
  static final String SUFFIX = ".partial";

  /** The most characters of the target's name in a temporary file's name. */
  private static final int NAME_CHARS = 32;

  private static final int BUFFER = 64 * 1024;

  private StagedFiles() {}

  /** Forces a directory's entries to the device: {@link #forceDirectory}, or a test's recorder. */
  interface DirectorySync {
    void force(Path dir) throws IOException;
  }

  /** The seam tests replace to observe directory forces. */
  static volatile DirectorySync directorySync = StagedFiles::forceDirectory;

  /**
   * Forces {@code dir}'s entries (a name just moved into it) to the device, where the platform can
   * open a directory: on Linux and macOS an fsync of the directory. Where it cannot (Windows, whose
   * file channels do not open directories; a directory without read permission; a file system
   * provider that does not support it), nothing is done: the move's durability is then the file
   * system's. A directory that opens but cannot be forced is an {@link IOException}.
   */
  static void forceDirectory(Path dir) throws IOException {
    FileChannel channel;
    try {
      channel = FileChannel.open(dir, StandardOpenOption.READ);
    } catch (IOException | UnsupportedOperationException cannotOpen) {
      return;
    }
    try (channel) {
      channel.force(true);
    }
  }

  /**
   * After the move onto {@code target}: forces {@code dir} for {@link FileDurability#DURABLE}. A
   * failure says that {@code target} was replaced, as it was.
   */
  private static void publish(Path dir, Path target, FileDurability durability) throws IOException {
    if (durability == FileDurability.CONTENT_ONLY) return;
    try {
      directorySync.force(dir);
    } catch (IOException e) {
      FileSystemException failed =
          new FileSystemException(
              dir.toString(),
              null,
              target.getFileName()
                  + " was replaced by the new file, but the directory could not be forced to the"
                  + " storage device, so after a crash it may be the old file again (or absent); on a file system"
                  + " that cannot force directories, use FileDurability.CONTENT_ONLY: "
                  + e);
      failed.initCause(e);
      throw failed;
    }
  }

  /** Opens a sealed stream with the key rules of the caller's entry point (owns {@code in}). */
  interface Opener {
    InputStream open(InputStream in) throws IOException;
  }

  /**
   * Seals {@code plaintext} (read to its end, not closed) with the stream {@code sealing} makes
   * around the temporary file, then moves the file onto {@code target}.
   */
  static void sealTo(
      Path target,
      InputStream plaintext,
      FileDurability durability,
      Function<OutputStream, SealingStream> sealing)
      throws IOException {
    Path dir = directoryOf(target);
    Objects.requireNonNull(plaintext, "plaintext");
    Objects.requireNonNull(durability, "durability");
    Staging staging = new Staging(dir, target.getFileName().toString());
    try {
      try (SealingStream out = sealing.apply(staging)) {
        copy(plaintext, out);
        out.finish();
        staging.force();
      }
      staging.moveOnto(target);
      publish(dir, target, durability);
    } catch (Throwable e) {
      staging.discard(e);
      throw e;
    }
  }

  /**
   * Opens {@code sealed} with {@code opening}, copies the plaintext to the temporary file to the
   * end of the stream, then moves the file onto {@code target}.
   */
  static void openTo(Path sealed, Path target, FileDurability durability, Opener opening)
      throws IOException {
    Objects.requireNonNull(sealed, "sealed");
    Path dir = directoryOf(target);
    Objects.requireNonNull(durability, "durability");
    Staging staging = new Staging(dir, target.getFileName().toString());
    try {
      try (InputStream plain = opening.open(Files.newInputStream(sealed));
          OutputStream out = staging) {
        copy(plain, out);
        staging.force();
      }
      staging.moveOnto(target);
      publish(dir, target, durability);
    } catch (Throwable e) {
      staging.discard(e);
      throw e;
    }
  }

  /**
   * Writes {@code content} to {@code target} as {@link #sealTo} does, durably ({@link
   * FileDurability#DURABLE}): a temporary file in the target's directory, read and write for the
   * owner only, forced to the device, moved onto the target atomically, then the directory forced.
   * With {@code permissions} (where the file system has POSIX permissions) the file gets those
   * before the move instead, such as the permissions of the file it replaces.
   */
  static void write(Path target, byte[] content, Set<PosixFilePermission> permissions)
      throws IOException {
    Path dir = directoryOf(target);
    Staging staging = new Staging(dir, target.getFileName().toString());
    try {
      try (OutputStream out = staging) {
        out.write(content);
        staging.force();
      }
      if (permissions != null
          && dir.getFileSystem().supportedFileAttributeViews().contains("posix"))
        staging.permissions(permissions);
      staging.moveOnto(target);
      publish(dir, target, FileDurability.DURABLE);
    } catch (Throwable e) {
      staging.discard(e);
      throw e;
    }
  }

  /** Deletes {@code file} if it exists, and forces its directory to the device. */
  static void delete(Path file) throws IOException {
    if (Files.deleteIfExists(file)) {
      Path dir = file.toAbsolutePath().getParent();
      if (dir != null) directorySync.force(dir);
    }
  }

  /**
   * The directory {@code target} is to be written in, checked before anything is sent or created.
   *
   * @throws IllegalArgumentException when {@code target} has no file name (a root)
   * @throws FileSystemException when {@code target} is a directory ({@link NoSuchFileException} or
   *     {@link NotDirectoryException} for the directory of {@code target})
   */
  private static Path directoryOf(Path target) throws IOException {
    Objects.requireNonNull(target, "target");
    if (target.getFileName() == null)
      throw new IllegalArgumentException("The target " + target + " has no file name");
    if (Files.isDirectory(target))
      throw new FileSystemException(target.toString(), null, "The target is a directory");
    Path dir = target.toAbsolutePath().getParent();
    if (!Files.isDirectory(dir)) {
      if (Files.exists(dir)) throw new NotDirectoryException(dir.toString());
      throw new NoSuchFileException(
          dir.toString(), null, "The directory of the target does not exist");
    }
    return dir;
  }

  /** Copies {@code in} to its end into {@code out}, wiping the buffer. */
  private static void copy(InputStream in, OutputStream out) throws IOException {
    byte[] buffer = new byte[BUFFER];
    try {
      for (int n; (n = in.read(buffer)) >= 0; ) out.write(buffer, 0, n);
    } finally {
      Arrays.fill(buffer, (byte) 0);
    }
  }

  /**
   * The temporary file: created at the first write (or {@link #force()}), so a sealing stream
   * refused before it writes anything leaves no file behind.
   */
  private static final class Staging extends OutputStream {
    private final Path dir;
    private final String prefix;
    private Path temp;
    private FileChannel channel;
    private OutputStream out;
    private boolean closed;

    Staging(Path dir, String name) {
      this.dir = dir;
      int end = Math.min(name.length(), NAME_CHARS);
      if (end < name.length() && Character.isHighSurrogate(name.charAt(end - 1))) end--;
      this.prefix = "." + name.substring(0, end) + ".";
    }

    private OutputStream out() throws IOException {
      if (closed) throw new IOException("The temporary file is closed");
      if (out == null) {
        temp = Files.createTempFile(dir, prefix, SUFFIX, ownerOnly(dir));
        channel = FileChannel.open(temp, StandardOpenOption.WRITE);
        out = Channels.newOutputStream(channel);
      }
      return out;
    }

    /** Read and write for the owner only, where the file system has POSIX permissions. */
    private static FileAttribute<?>[] ownerOnly(Path dir) {
      if (!dir.getFileSystem().supportedFileAttributeViews().contains("posix"))
        return new FileAttribute<?>[0];
      return new FileAttribute<?>[] {
        PosixFilePermissions.asFileAttribute(
            EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))
      };
    }

    @Override
    public void write(int b) throws IOException {
      out().write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
      out().write(b, off, len);
    }

    @Override
    public void flush() throws IOException {
      if (out != null && !closed) out.flush();
    }

    /** Creates the file if nothing was written, and forces its content to the device. */
    void force() throws IOException {
      out();
      channel.force(true);
    }

    @Override
    public void close() throws IOException {
      closed = true;
      if (channel != null) channel.close();
    }

    /** Sets the complete, closed file's POSIX permissions. */
    void permissions(Set<PosixFilePermission> permissions) throws IOException {
      if (temp == null || !closed) throw new IllegalStateException("Nothing complete to set");
      Files.setPosixFilePermissions(temp, permissions);
    }

    /** Moves the complete, closed file onto {@code target}, which it replaces atomically. */
    void moveOnto(Path target) throws IOException {
      if (temp == null || !closed) throw new IllegalStateException("Nothing complete to move");
      Files.move(temp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
      temp = null;
    }

    /** After {@code failure}: closes and deletes the file, adding any error to {@code failure}. */
    void discard(Throwable failure) {
      StreamEnvelopes.closing(this, failure);
      if (temp == null) return;
      try {
        Files.deleteIfExists(temp);
      } catch (Throwable e) {
        failure.addSuppressed(e);
      }
    }
  }
}
