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

package dev.keytend.kmip.codec;

import dev.keytend.kmip.model.Ttlv;
import java.io.*;
import java.math.BigInteger;
import java.nio.*;
import java.nio.charset.*;
import java.util.*;

/**
 * The KMIP binary encoding (TTLV), with bounded framing and nesting, strict padding and strict
 * UTF-8. {@link dev.keytend.kmip.transport.TlsTransport} uses it. A codec is immutable and can be
 * shared between threads.
 *
 * @since 0.10.0
 */
public final class TtlvCodec {
  /** The default largest message: 16 MiB. */
  public static final int DEFAULT_MAX_BYTES = 16 * 1024 * 1024;

  /** The default deepest nesting of structures: 64. */
  public static final int DEFAULT_MAX_DEPTH = 64;

  /** The default largest number of values in one message: 65,536. */
  public static final int DEFAULT_MAX_ELEMENTS = 65536;

  private final int maxBytes, maxDepth, maxElements;

  /** A codec with the default limits ({@link #DEFAULT_MAX_BYTES} and the others). */
  public TtlvCodec() {
    this(DEFAULT_MAX_BYTES, DEFAULT_MAX_DEPTH);
  }

  /**
   * A codec with these limits and {@link #DEFAULT_MAX_ELEMENTS}; see {@link #TtlvCodec(int, int,
   * int)}.
   *
   * @param maxBytes the largest message, in bytes; at least 8
   * @param maxDepth the deepest nesting of structures; at least 1
   */
  public TtlvCodec(int maxBytes, int maxDepth) {
    this(maxBytes, maxDepth, DEFAULT_MAX_ELEMENTS);
  }

  /**
   * A codec with these limits, which apply when encoding and when decoding.
   *
   * @param maxBytes the largest message, in bytes; at least 8
   * @param maxDepth the deepest nesting of structures; at least 1
   * @param maxElements the most values in one message; at least 1
   * @throws IllegalArgumentException if a limit is below its minimum
   */
  public TtlvCodec(int maxBytes, int maxDepth, int maxElements) {
    if (maxBytes < 8 || maxDepth < 1 || maxElements < 1)
      throw new IllegalArgumentException("Invalid decoder limits");
    this.maxBytes = maxBytes;
    this.maxDepth = maxDepth;
    this.maxElements = maxElements;
  }

  /**
   * Encodes one TTLV value.
   *
   * @param value the value, usually a request or response message
   * @return the encoded bytes, a new array
   * @throws IllegalArgumentException if {@code value} exceeds this codec's limits
   */
  public byte[] encode(Ttlv value) {
    long size = size(value, 0, new int[] {0});
    if (size > maxBytes) throw new IllegalArgumentException("TTLV exceeds message limit");
    ByteBuffer out = ByteBuffer.allocate((int) size).order(ByteOrder.BIG_ENDIAN);
    write(out, value, 0);
    return out.array();
  }

  /**
   * Decodes one complete TTLV value.
   *
   * @param bytes exactly one encoded value, with no trailing data
   * @return the value
   * @throws DecodeException for malformed or oversized input; its message names at most a type,
   *     never a value
   */
  public Ttlv decode(byte[] bytes) throws IOException {
    if (bytes.length > maxBytes) throw new DecodeException("TTLV exceeds message limit");
    ByteBuffer in = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN);
    Ttlv n = read(in, 0, new int[] {0});
    if (in.hasRemaining()) throw new DecodeException("Trailing data after TTLV");
    return n;
  }

  /**
   * Reads exactly one frame. No read-ahead, so persistent connections remain aligned. The buffer
   * starts at 64 KiB and doubles as bytes arrive, up to the declared frame length, so a header
   * that declares a large frame and then stalls does not reserve the whole declared size, and a
   * large frame is copied O(n) rather than O(n²) times. Every buffer, including the final frame, is
   * zeroed once it is no longer needed (the decoded {@link Ttlv} holds its own copies).
   *
   * @param input the stream to read one frame from
   * @return the value
   * @throws EOFException when the stream ends before the frame is complete
   * @throws DecodeException for an oversized or malformed frame
   */
  public Ttlv read(InputStream input) throws IOException {
    byte[] header = new byte[8];
    for (int filled = 0; filled < 8; ) {
      int n = input.read(header, filled, 8 - filled);
      if (n < 0) throw new EOFException("Truncated TTLV header");
      filled += n;
    }
    long length = Integer.toUnsignedLong(ByteBuffer.wrap(header, 4, 4).getInt());
    long total = 8 + align(length);
    if (total > maxBytes) throw new DecodeException("TTLV frame exceeds limit");
    byte[] frame = Arrays.copyOf(header, (int) Math.min(total, 8 + READ_CHUNK));
    Arrays.fill(header, (byte) 0);
    try {
      int filled = 8;
      while (filled < total) {
        if (filled == frame.length) {
          byte[] grown = Arrays.copyOf(frame, (int) Math.min(total, 2L * frame.length));
          Arrays.fill(frame, (byte) 0);
          frame = grown;
        }
        int n = input.read(frame, filled, frame.length - filled);
        if (n < 0) throw new EOFException("Truncated TTLV body");
        filled += n;
      }
      return decode(frame);
    } finally {
      Arrays.fill(frame, (byte) 0);
    }
  }

  private static final int READ_CHUNK = 64 * 1024;

  private static long align(long n) {
    return (n + 7) & ~7L;
  }

  private long size(Ttlv n, int depth, int[] elements) {
    if (++elements[0] > maxElements) throw new IllegalArgumentException("TTLV element limit");
    if (depth >= maxDepth) throw new IllegalArgumentException("TTLV nesting limit");
    long length =
        switch (n.type()) {
          case STRUCTURE -> {
            long sum = 0;
            for (Ttlv c : n.children()) {
              sum += size(c, depth + 1, elements);
              if (sum > maxBytes) throw new IllegalArgumentException("TTLV exceeds limit");
            }
            yield sum;
          }
          case INTEGER, ENUMERATION, INTERVAL -> 4;
          case LONG_INTEGER, BOOLEAN, DATE_TIME, DATE_TIME_EXTENDED -> 8;
          case BIG_INTEGER -> align(n.bigIntegerValue().toByteArray().length);
          case TEXT_STRING, IDENTIFIER, REFERENCE, NAME_REFERENCE -> utf8(n.textValue()).length;
          case BYTE_STRING -> n.byteLength();
        };
    return 8 + align(length);
  }

  private static byte[] utf8(String s) {
    try {
      ByteBuffer b =
          StandardCharsets.UTF_8
              .newEncoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .encode(java.nio.CharBuffer.wrap(s));
      byte[] a = new byte[b.remaining()];
      b.get(a);
      return a;
    } catch (CharacterCodingException e) {
      throw new IllegalArgumentException("Invalid Unicode string", e);
    }
  }

  private void write(ByteBuffer out, Ttlv n, int depth) {
    out.put((byte) (n.tag() >>> 16))
        .put((byte) (n.tag() >>> 8))
        .put((byte) n.tag())
        .put((byte) n.type().code());
    int lengthAt = out.position();
    out.putInt(0);
    int start = out.position();
    switch (n.type()) {
      case STRUCTURE -> {
        for (Ttlv child : n.children()) write(out, child, depth + 1);
      }
      case INTEGER, ENUMERATION -> out.putInt(n.intValue());
      case INTERVAL -> out.putInt((int) n.longValue());
      case LONG_INTEGER, DATE_TIME, DATE_TIME_EXTENDED -> out.putLong(n.longValue());
      case BOOLEAN -> out.putLong(n.booleanValue() ? 1 : 0);
      case BIG_INTEGER -> {
        byte[] b = n.bigIntegerValue().toByteArray();
        for (int i = 0; i < align(b.length) - b.length; i++) out.put((byte) (b[0] < 0 ? 0xff : 0));
        out.put(b);
      }
      case TEXT_STRING, IDENTIFIER, REFERENCE, NAME_REFERENCE -> out.put(utf8(n.textValue()));
      case BYTE_STRING -> n.withBytes(out::put);
    }
    int length = out.position() - start;
    out.putInt(lengthAt, length);
    while ((out.position() - start) % 8 != 0) out.put((byte) 0);
  }

  private Ttlv read(ByteBuffer in, int depth, int[] elements) throws IOException {
    if (++elements[0] > maxElements) throw new DecodeException("TTLV element limit");
    if (depth >= maxDepth) throw new DecodeException("TTLV nesting limit");
    if (in.remaining() < 8) throw new DecodeException("Truncated TTLV item header");
    int tag =
        (Byte.toUnsignedInt(in.get()) << 16)
            | (Byte.toUnsignedInt(in.get()) << 8)
            | Byte.toUnsignedInt(in.get());
    int type = Byte.toUnsignedInt(in.get());
    long length = Integer.toUnsignedLong(in.getInt());
    if (align(length) > in.remaining())
      throw new DecodeException("TTLV item length exceeds enclosing structure");
    int end = in.position() + (int) length;
    try {
      Ttlv.Type t = Ttlv.Type.of(type);
      switch (t) {
        case INTEGER, ENUMERATION, INTERVAL -> {
          if (length != 4) throw new DecodeException("Expected 4-byte " + t);
        }
        case LONG_INTEGER, DATE_TIME, DATE_TIME_EXTENDED, BOOLEAN -> {
          if (length != 8) throw new DecodeException("Expected 8-byte " + t);
        }
        case STRUCTURE, BIG_INTEGER -> {
          if (length % 8 != 0 || (t == Ttlv.Type.BIG_INTEGER && length == 0))
            throw new DecodeException("Invalid " + t + " length");
        }
        default -> {}
      }
      Object value =
          switch (t) {
            case STRUCTURE -> {
              List<Ttlv> children = new ArrayList<>();
              ByteBuffer sub = in.slice().order(ByteOrder.BIG_ENDIAN);
              sub.limit((int) length);
              while (sub.hasRemaining()) children.add(read(sub, depth + 1, elements));
              in.position(end);
              yield children;
            }
            case INTEGER, ENUMERATION -> in.getInt();
            case INTERVAL -> Integer.toUnsignedLong(in.getInt());
            case LONG_INTEGER, DATE_TIME, DATE_TIME_EXTENDED -> in.getLong();
            case BOOLEAN -> {
              long b = in.getLong();
              if (b != 0 && b != 1) throw new DecodeException("Noncanonical KMIP Boolean");
              yield b == 1;
            }
            case BIG_INTEGER -> {
              byte[] b = new byte[(int) length];
              in.get(b);
              try {
                yield new BigInteger(b);
              } finally {
                Arrays.fill(b, (byte) 0);
              }
            }
            case TEXT_STRING, IDENTIFIER, REFERENCE, NAME_REFERENCE -> {
              ByteBuffer sub = in.slice();
              sub.limit((int) length);
              String s =
                  StandardCharsets.UTF_8
                      .newDecoder()
                      .onMalformedInput(CodingErrorAction.REPORT)
                      .onUnmappableCharacter(CodingErrorAction.REPORT)
                      .decode(sub)
                      .toString();
              in.position(end);
              yield s;
            }
            case BYTE_STRING -> {
              byte[] b = new byte[(int) length];
              in.get(b);
              yield b;
            }
          };
      try {
        for (long p = length; p < align(length); p++)
          if (in.get() != 0) throw new DecodeException("Nonzero TTLV padding");
        return Ttlv.of(tag, t, value);
      } finally {
        // Ttlv keeps its own copy of a Byte String; wipe the decoded one.
        if (value instanceof byte[] bytes) Arrays.fill(bytes, (byte) 0);
      }
    } catch (CharacterCodingException e) {
      throw new DecodeException("Invalid UTF-8 in TTLV text", e);
    } catch (IllegalArgumentException | BufferUnderflowException e) {
      // Ttlv.of and Type.of report structure problems; their messages are not passed on.
      throw new DecodeException("Malformed TTLV", e);
    }
  }
}
