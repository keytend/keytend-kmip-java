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

/**
 * What a file helper ({@link CurrentKey#sealTo}, {@link CurrentKey#openTo}, {@link KeyHandle#openTo}, {@link KmsKeys#openTo})
 * forces to the storage device before it returns. Both write a temporary file next to the target,
 * force its content, and move it onto the target atomically, so readers see the old file or the
 * new one, never part of one; they differ in whether the move itself survives a crash.
 *
 * @since 0.10.0
 */
public enum FileDurability {
  /**
   * The default. After the move the target's directory is forced too (an fsync of the directory on
   * Linux and macOS), so once the call returns the new file is the target after a crash as well, as
   * far as the platform's fsync goes (on macOS it does not flush the drive's own cache, which
   * {@code F_FULLFSYNC} would): delete the source of {@code sealTo} only now. Where the platform cannot open a
   * directory to force it (Windows; a directory without read permission; a file system provider
   * that does not support it) the directory is not forced and the call returns normally: the
   * move's durability is then the file system's. A directory that opens but cannot be forced ends
   * the call in an {@link java.io.IOException} that says the target was replaced already; some
   * file systems (certain network or FUSE ones) refuse every fsync of a directory, so there every
   * call fails that way: use {@link #CONTENT_ONLY} on them, and make the files durable another way.
   */
  DURABLE,

  /**
   * Forces the file's content only, the SDK's earliest behavior: after a crash soon after the call returns, the
   * target may be the old file, or no file if there was none, as well as the new one, and a
   * temporary {@code .<name>.<random>.partial} file may be left behind. For writing many files to
   * one directory: force the directory once afterwards (or make the files durable another way)
   * before relying on them, for example before deleting their sources.
   */
  CONTENT_ONLY
}
