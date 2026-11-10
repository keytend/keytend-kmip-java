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

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * The blocks of a PEM file (RFC 7468), found by the file's structure, the same on every JDK: a
 * file the JDK's parsers would cut short or read past is refused here, not left to them (JDK 25's
 * {@code CertificateFactory} drops a final block cut short without a word).
 *
 * <p>A file is a sequence of blocks, each a {@code -----BEGIN label-----} line, Base64 lines and a
 * {@code -----END label-----} line with the same label. Text before and between blocks (the
 * comments of CA bundles, OpenSSL's "Bag Attributes", keytool's listing) is passed over; after the
 * last END line only whitespace may follow (and the lines of asterisks that end {@code keytool
 * -list -rfc}), so a file cut anywhere after its first block is refused. Lines end with LF, CRLF or
 * a lone CR; a UTF-8 byte order mark and blanks around boundary lines are allowed. A line starting
 * with {@code -----BEGIN} or {@code -----END} that is not a whole BEGIN or END line, a BEGIN inside a block, an END without
 * its BEGIN or with another label, and a block without its END line are refused. Messages name the
 * file, the line and the label, never the contents.
 */
final class Pem {
  private Pem() {}

  /**
   * A file that is not whole: cut short, still being written, or empty (a failure of its structure,
   * not of what it holds). A reload that reads files still changing takes this for a writer that
   * is not done ({@link KmsListener#credentialsStillChanging}), any other failure for a failure.
   */
  static final class Incomplete extends IllegalArgumentException {
    Incomplete(String message) {
      super(message);
    }
  }

  /**
   * {@code e} as callers of the public API see it: a plain {@link IllegalArgumentException} with
   * the same message, cause, suppressed exceptions and stack trace. {@link Incomplete} (and any
   * other subclass of this package's) only tells a reload what a failure means; its package-private
   * class must not show in {@code getClass()} or a stack trace.
   */
  static IllegalArgumentException plain(IllegalArgumentException e) {
    if (e.getClass() == IllegalArgumentException.class
        || !e.getClass().getPackageName().equals(Pem.class.getPackageName())) return e;
    IllegalArgumentException p = new IllegalArgumentException(e.getMessage(), e.getCause());
    p.setStackTrace(e.getStackTrace());
    for (Throwable s : e.getSuppressed()) p.addSuppressed(s);
    return p;
  }

  /** One block: its label, the line of its BEGIN line, and its Base64 as offsets into the file. */
  record Block(String label, int line, int from, int to) {}

  private static final byte[] BEGIN_WORD = ascii("-----BEGIN"), END_WORD = ascii("-----END");
  private static final byte[] BEGIN = ascii("-----BEGIN "),
      END = ascii("-----END "),
      DASHES = ascii("-----");

  /** The longest label taken for one: RFC 7468's are at most 23 characters. */
  private static final int MAX_LABEL = 64;

  /**
   * The blocks of {@code text}, in file order; none when it has no BEGIN line.
   *
   * @throws IllegalArgumentException naming {@code file} when the file is not a whole PEM file
   */
  static List<Block> blocks(byte[] text, Path file) {
    List<Block> out = new ArrayList<>();
    String open = null;
    int openLine = 0, bodyFrom = 0, lastEnd = 0, line = 0;
    // A UTF-8 byte order mark (Windows editors) is not part of the first line.
    int from =
        text.length >= 3
                && (text[0] & 0xff) == 0xEF
                && (text[1] & 0xff) == 0xBB
                && (text[2] & 0xff) == 0xBF
            ? 3
            : 0;
    for (int at = from; at < text.length; ) {
      // Lines end with LF, CRLF or a lone CR.
      int eol = at;
      while (eol < text.length && text[eol] != '\n' && text[eol] != '\r') eol++;
      int next =
          eol < text.length && text[eol] == '\r' && eol + 1 < text.length && text[eol + 1] == '\n'
              ? eol + 2
              : eol + 1;
      // Blanks before and after a boundary are allowed (a file indented in YAML, say).
      int start = at, end = eol;
      while (start < end && (text[start] == ' ' || text[start] == '\t')) start++;
      while (end > start && (text[end - 1] == ' ' || text[end - 1] == '\t')) end--;
      line++;
      boolean begin = startsWith(text, start, end, BEGIN_WORD);
      if (begin || startsWith(text, start, end, END_WORD)) {
        byte[] prefix = begin ? BEGIN : END;
        int labelFrom = start + prefix.length;
        String label =
            startsWith(text, start, end, prefix) && endsWith(text, labelFrom, end, DASHES)
                ? label(text, labelFrom, end - DASHES.length)
                : null;
        if (label == null)
          throw new Incomplete(
              file
                  + ": line "
                  + line
                  + " starts like a PEM BEGIN or END line but is not a whole one"
                  + " (a file cut short, or still being written?)");
        if (begin) {
          if (open != null)
            throw new Incomplete(
                file
                    + ": the BEGIN "
                    + open
                    + " block at line "
                    + openLine
                    + " has no END line before the"
                    + " BEGIN "
                    + label
                    + " line at line "
                    + line);
          open = label;
          openLine = line;
          bodyFrom = Math.min(next, text.length);
        } else {
          if (open == null)
            throw new Incomplete(
                file + ": line " + line + " is END " + label + " without a BEGIN line");
          if (!label.equals(open))
            throw new Incomplete(
                file
                    + ": the BEGIN "
                    + open
                    + " block at line "
                    + openLine
                    + " ends with END "
                    + label
                    + " at line "
                    + line);
          out.add(new Block(open, openLine, bodyFrom, at));
          open = null;
          lastEnd = eol;
        }
      }
      at = next;
    }
    if (open != null)
      throw new Incomplete(
          file
              + ": the BEGIN "
              + open
              + " block at line "
              + openLine
              + " has no END line (a file cut short,"
              + " or still being written?)");
    // After the last END line: whitespace, and the lines of asterisks that end keytool -list -rfc.
    if (!out.isEmpty())
      for (int i = lastEnd; i < text.length; i++)
        if (!whitespace(text[i]) && text[i] != '*')
          throw new Incomplete(
              file
                  + " has data after its last END line (a file cut short, or still being written?);"
                  + " a PEM file ends with an END line");
    return out;
  }

  /**
   * The bytes {@code block}'s Base64 encodes; the caller wipes them. The Base64 must be complete:
   * only the Base64 alphabet and whitespace, a multiple of four characters, padding only at the
   * end.
   *
   * @throws IllegalArgumentException naming {@code file} and the block, never quoting it
   */
  static byte[] decode(byte[] text, Block block, Path file) {
    byte[] compact = new byte[block.to() - block.from()];
    try {
      int n = 0, padding = 0;
      for (int i = block.from(); i < block.to(); i++) {
        byte b = text[i];
        if (whitespace(b)) continue;
        if (b == '=') padding++;
        else if (padding > 0 || !alphabet(b)) throw invalid(block, file);
        compact[n++] = b;
      }
      if (n == 0 || n % 4 != 0 || padding > 2) throw invalid(block, file);
      byte[] exact = Arrays.copyOf(compact, n);
      try {
        return Base64.getDecoder().decode(exact);
      } catch (IllegalArgumentException e) {
        throw invalid(block, file);
      } finally {
        Arrays.fill(exact, (byte) 0);
      }
    } finally {
      Arrays.fill(compact, (byte) 0);
    }
  }

  private static IllegalArgumentException invalid(Block block, Path file) {
    return new Incomplete(
        file
            + ": the "
            + block.label()
            + " block is not valid Base64 (the block at line "
            + block.line()
            + "; cut short, or not Base64)");
  }

  /**
   * The end of the one DER element (definite length) at {@code from} in {@code der}, or -1 when no
   * whole element starts there.
   */
  static int derElementEnd(byte[] der, int from) {
    int i = from;
    if (der.length - i < 2) return -1;
    i++; // the tag: one byte for the universal SEQUENCE every caller expects
    int length = der[i++] & 0xff;
    if (length > 0x80 && length <= 0x84) {
      int bytes = length - 0x80;
      length = 0;
      for (int n = 0; n < bytes; n++) {
        if (i >= der.length || length > (Integer.MAX_VALUE >> 8)) return -1;
        length = (length << 8) | (der[i++] & 0xff);
      }
    } else if (length >= 0x80) return -1;
    return length > der.length - i ? -1 : i + length;
  }

  /** The label between {@code from} and {@code to}, or null when it is not one. */
  private static String label(byte[] text, int from, int to) {
    if (to <= from || to - from > MAX_LABEL) return null;
    // RFC 7468: printable characters; a hyphen or a space only between two others.
    for (int i = from; i < to; i++) {
      byte b = text[i];
      if (b < 0x20 || b > 0x7e) return null;
      if ((b == '-' || b == ' ')
          && (i == from || i == to - 1 || text[i - 1] == '-' || text[i - 1] == ' ')) return null;
    }
    return new String(text, from, to - from, StandardCharsets.US_ASCII);
  }

  private static boolean alphabet(byte b) {
    return (b >= 'A' && b <= 'Z')
        || (b >= 'a' && b <= 'z')
        || (b >= '0' && b <= '9')
        || b == '+'
        || b == '/';
  }

  private static boolean whitespace(byte b) {
    return b == ' ' || b == '\t' || b == '\r' || b == '\n';
  }

  private static boolean startsWith(byte[] text, int from, int to, byte[] prefix) {
    if (to - from < prefix.length) return false;
    for (int i = 0; i < prefix.length; i++) if (text[from + i] != prefix[i]) return false;
    return true;
  }

  private static boolean endsWith(byte[] text, int from, int to, byte[] suffix) {
    if (to - from < suffix.length) return false;
    for (int i = 0; i < suffix.length; i++)
      if (text[to - suffix.length + i] != suffix[i]) return false;
    return true;
  }

  private static byte[] ascii(String s) {
    return s.getBytes(StandardCharsets.US_ASCII);
  }
}
