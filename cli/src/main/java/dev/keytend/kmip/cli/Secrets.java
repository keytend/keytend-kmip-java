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

package dev.keytend.kmip.cli;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CharsetEncoder;
import java.nio.charset.CoderResult;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

/**
 * Reads secrets from where a configuration or command line points: a file, an environment
 * variable or the console. A secret is never a command-line value or a configuration value.
 */
final class Secrets {
  /** Where a secret comes from: its kind, and the file or variable ({@code ""} for the console). */
  record Source(Kind kind, String where) {
    /** The kinds of source. */
    enum Kind {
      /** A file that holds the secret. */
      FILE,
      /** An environment variable. */
      ENV,
      /** A question at the console. */
      PROMPT
    }

    static Source file(Path path) {
      return new Source(Kind.FILE, path.toString());
    }

    static Source env(String variable) {
      return new Source(Kind.ENV, variable);
    }

    static Source prompt() {
      return new Source(Kind.PROMPT, "");
    }

    /**
     * Where the secret is read from, for people: never the secret.
     *
     * @return for example {@code file /etc/kms/p12.pass}
     */
    String describe() {
      return switch (kind) {
        case FILE -> "file " + where;
        case ENV -> "environment variable " + where;
        case PROMPT -> "console prompt";
      };
    }
  }

  private final Map<String, String> environment;
  private final Terminal terminal;
  private final PrintStream err;

  Secrets(Map<String, String> environment, Terminal terminal, PrintStream err) {
    this.environment = environment;
    this.terminal = terminal;
    this.err = err;
  }

  /**
   * Checks that the secret can be read, without reading it: the file is a readable regular file,
   * the environment variable is set, or there is a console to ask at. Run before a confirmation, so
   * that a wrong source is refused before the operator approves anything.
   *
   * @param source where it is
   * @param what what it is, for messages
   * @throws CliException (exit 2) when it cannot be read
   */
  void check(Source source, String what) {
    switch (source.kind()) {
      case FILE -> {
        Path file = Path.of(source.where());
        if (!Files.isRegularFile(file) || !Files.isReadable(file))
          throw CliException.usage(what + ": cannot read " + file + ": not a readable file");
      }
      case ENV -> {
        String value = environment.get(source.where());
        if (value == null || value.isEmpty())
          throw CliException.usage(
              what + ": the environment variable " + source.where() + " is not set");
      }
      case PROMPT -> {
        if (!terminal.interactive())
          throw CliException.usage(
              what + ": no console to ask for it; read it from a file or an environment variable");
      }
    }
  }

  /**
   * Reads a secret as characters. A file's content is UTF-8, and one final line break is dropped.
   *
   * @param source where it is
   * @param what what it is, for messages and the prompt
   * @return the secret; the caller wipes it
   */
  char[] chars(Source source, String what) {
    return switch (source.kind()) {
      case FILE -> fileChars(source, what);
      case ENV -> {
        String value = environment.get(source.where());
        if (value == null || value.isEmpty())
          throw CliException.usage(
              what + ": the environment variable " + source.where() + " is not set");
        yield value.toCharArray();
      }
      case PROMPT -> {
        if (!terminal.interactive())
          throw CliException.usage(
              what + ": no console to ask for it; read it from a file or an environment variable");
        char[] typed = terminal.readPassword(what + ": ");
        if (typed == null) throw CliException.usage(what + ": nothing was entered");
        yield typed;
      }
    };
  }

  /** A file's content as UTF-8 characters, without one final line break. */
  private char[] fileChars(Source source, String what) {
    byte[] bytes = readFile(Path.of(source.where()), what);
    try {
      CharBuffer decoded =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(bytes));
      int end = decoded.limit();
      if (end > 0 && decoded.get(end - 1) == '\n') end--;
      if (end > 0 && decoded.get(end - 1) == '\r') end--;
      char[] out = new char[end];
      decoded.get(out, 0, end);
      Arrays.fill(decoded.array(), '\0');
      return out;
    } catch (CharacterCodingException e) {
      throw CliException.usage(what + ": " + source.where() + " is not UTF-8 text");
    } finally {
      Arrays.fill(bytes, (byte) 0);
    }
  }

  /**
   * Reads a secret as bytes: a file's exact content, an environment variable's or a typed value's
   * UTF-8 encoding.
   *
   * @param source where it is
   * @param what what it is, for messages and the prompt
   * @return the secret; the caller wipes it
   */
  byte[] bytes(Source source, String what) {
    if (source.kind() == Source.Kind.FILE) return readFile(Path.of(source.where()), what);
    char[] chars = chars(source, what);
    // Three bytes per UTF-16 unit is enough for UTF-8; a buffer of our own, so it can be wiped.
    ByteBuffer encoded = ByteBuffer.allocate(chars.length * 3);
    try {
      CharsetEncoder encoder =
          StandardCharsets.UTF_8
              .newEncoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT);
      CoderResult result = encoder.encode(CharBuffer.wrap(chars), encoded, true);
      if (!result.isUnderflow()) throw CliException.usage(what + ": not valid text");
      encoder.flush(encoded);
    } finally {
      Arrays.fill(chars, '\0');
    }
    byte[] out = Arrays.copyOf(encoded.array(), encoded.position());
    Arrays.fill(encoded.array(), (byte) 0);
    return out;
  }

  private byte[] readFile(Path file, String what) {
    try {
      warnIfShared(file, what);
      return Files.readAllBytes(file);
    } catch (IOException e) {
      throw CliException.usage(
          what + ": cannot read " + file + ": " + e.getClass().getSimpleName());
    }
  }

  /** Warns when others than the owner may read a secret file (POSIX file systems only). */
  private void warnIfShared(Path file, String what) throws IOException {
    Set<PosixFilePermission> permissions;
    try {
      permissions = Files.getPosixFilePermissions(file);
    } catch (UnsupportedOperationException notPosix) {
      return;
    }
    if (permissions.contains(PosixFilePermission.GROUP_READ)
        || permissions.contains(PosixFilePermission.OTHERS_READ))
      err.println(
          "warning: "
              + what
              + ": "
              + file
              + " can be read by other users (chmod 600 "
              + file
              + ")");
  }
}
