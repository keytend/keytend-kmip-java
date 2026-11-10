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

import java.math.BigInteger;
import java.util.Arrays;

/**
 * A small, strict DER writer for the structures the SDK makes itself: the PKCS#10 request of a
 * client certificate renewal ({@link Pkcs10}) and an encrypted PKCS#8 key ({@link RenewalFiles}).
 * Every element has a one-byte tag and a definite length in its shortest form; an INTEGER is the
 * shortest two's complement; an OBJECT IDENTIFIER is checked arc by arc. An element given whole
 * ({@link #whole}) must be exactly one DER element. Failures are {@link IllegalArgumentException}s:
 * every input is the SDK's own.
 */
final class Der {
  private Der() {}

  /** One element: {@code tag} (a low tag number, one byte) and the contents, concatenated. */
  static byte[] element(int tag, byte[]... contents) {
    if (tag < 0 || tag > 0xff || (tag & 0x1f) == 0x1f)
      throw new IllegalArgumentException("Not a one-byte DER tag: " + tag);
    int n = 0;
    for (byte[] c : contents) n = Math.addExact(n, c.length);
    byte[] length = length(n);
    byte[] out = new byte[Math.addExact(1 + length.length, n)];
    out[0] = (byte) tag;
    System.arraycopy(length, 0, out, 1, length.length);
    int at = 1 + length.length;
    for (byte[] c : contents) {
      System.arraycopy(c, 0, out, at, c.length);
      at += c.length;
    }
    return out;
  }

  /** A definite length in its shortest form. */
  static byte[] length(int n) {
    if (n < 0) throw new IllegalArgumentException("Negative DER length");
    if (n < 0x80) return new byte[] {(byte) n};
    int bytes = (Integer.SIZE - Integer.numberOfLeadingZeros(n) + 7) / 8;
    byte[] out = new byte[1 + bytes];
    out[0] = (byte) (0x80 | bytes);
    for (int i = bytes; i >= 1; i--, n >>>= 8) out[i] = (byte) n;
    return out;
  }

  static byte[] sequence(byte[]... parts) {
    return element(0x30, parts);
  }

  /** {@code [n]}, constructed: an explicit tag, or an IMPLICIT SET OF or SEQUENCE OF. */
  static byte[] context(int n, byte[]... parts) {
    if (n < 0 || n > 30) throw new IllegalArgumentException("Context tag out of range: " + n);
    return element(0xa0 | n, parts);
  }

  static byte[] integer(BigInteger value) {
    return element(0x02, value.toByteArray());
  }

  static byte[] integer(long value) {
    return integer(BigInteger.valueOf(value));
  }

  static byte[] nul() {
    return new byte[] {0x05, 0x00};
  }

  static byte[] octetString(byte[] value) {
    return element(0x04, value);
  }

  /** A BIT STRING of whole bytes (no unused bits). */
  static byte[] bitString(byte[] value) {
    return element(0x03, new byte[] {0}, value);
  }

  /** An OBJECT IDENTIFIER from its dotted form, such as {@code 1.2.840.113549.1.1.11}. */
  static byte[] oid(String dotted) {
    String[] parts = dotted.split("\\.", -1);
    if (parts.length < 2) throw new IllegalArgumentException("Not an OID: " + dotted);
    long[] arcs = new long[parts.length];
    for (int i = 0; i < parts.length; i++) {
      if (parts[i].isEmpty() || (parts[i].length() > 1 && parts[i].charAt(0) == '0'))
        throw new IllegalArgumentException("Not an OID: " + dotted);
      try {
        arcs[i] = Long.parseLong(parts[i]);
      } catch (NumberFormatException e) {
        throw new IllegalArgumentException("Not an OID: " + dotted, e);
      }
      if (arcs[i] < 0) throw new IllegalArgumentException("Not an OID: " + dotted);
    }
    if (arcs[0] > 2 || (arcs[0] < 2 && arcs[1] > 39))
      throw new IllegalArgumentException("Not an OID: " + dotted);
    byte[] out = new byte[parts.length * 10];
    int at = arc(out, 0, Math.addExact(arcs[0] * 40, arcs[1]));
    for (int i = 2; i < arcs.length; i++) at = arc(out, at, arcs[i]);
    return element(0x06, Arrays.copyOf(out, at));
  }

  /** Writes {@code arc} base 128, most significant group first, at {@code at}; returns the end. */
  private static int arc(byte[] out, int at, long arc) {
    int groups = Math.max(1, (Long.SIZE - Long.numberOfLeadingZeros(arc) + 6) / 7);
    for (int g = groups - 1; g >= 0; g--)
      out[at++] = (byte) (((arc >>> (7 * g)) & 0x7f) | (g == 0 ? 0 : 0x80));
    return at;
  }

  /**
   * {@code encoded}, which must be exactly one whole DER element with a definite length (a
   * certificate's encoded name, an encoded public key).
   */
  static byte[] whole(byte[] encoded) {
    if (encoded == null
        || encoded.length < 2
        || (encoded[0] & 0x1f) == 0x1f
        || Pem.derElementEnd(encoded, 0) != encoded.length)
      throw new IllegalArgumentException("Not one whole DER element");
    return encoded;
  }
}
