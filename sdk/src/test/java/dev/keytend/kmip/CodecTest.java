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

package dev.keytend.kmip;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.codec.*;
import dev.keytend.kmip.model.*;
import java.io.*;
import java.math.BigInteger;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;

class CodecTest {
  private final TtlvCodec codec = new TtlvCodec();

  @Test
  void independentlySpecifiedBinaryVector() throws Exception {
    // KMIP 9.1: 3-byte tag, one-byte type, 4-byte length, big endian values and 8-byte alignment.
    byte[] expected =
        HexFormat.of()
            .parseHex(
                "420069010000002042006a0200000004000000010000000042006b02000000040000000400000000");
    Ttlv node =
        structure(
            PROTOCOL_VERSION,
            integer(PROTOCOL_VERSION_MAJOR, 1),
            integer(PROTOCOL_VERSION_MINOR, 4));
    assertArrayEquals(expected, codec.encode(node));
    assertEquals(node, codec.decode(expected));
  }

  @Test
  void everyTypeAndBoundaryAcrossAllEncodings() throws Exception {
    List<Ttlv> nodes =
        new ArrayList<>(
            List.of(
                structure(REQUEST_PAYLOAD),
                integer(BATCH_COUNT, Integer.MIN_VALUE),
                integer(BATCH_COUNT, Integer.MAX_VALUE),
                enumeration(OPERATION, 0x80000001),
                longInteger(USAGE_LIMITS_COUNT, Long.MIN_VALUE),
                longInteger(USAGE_LIMITS_COUNT, Long.MAX_VALUE),
                bool(BATCH_ORDER_OPTION, true),
                bool(BATCH_ORDER_OPTION, false),
                text(NAME_VALUE, "quotes \" slash \\ newline\n snow ☃ music 𝄞"),
                text(NAME_VALUE, ""),
                bytes(DATA, new byte[] {0, -1, 1}),
                bytes(DATA, new byte[0]),
                interval(LEASE_TIME, 0xffff_ffffL),
                dateTime(TIME_STAMP, Instant.ofEpochSecond(-12345)),
                Ttlv.of(0x54abcd, Ttlv.Type.TEXT_STRING, "extension")));
    for (int bits : new int[] {0, 1, 7, 8, 63, 64, 65, 127, 128, 2048})
      for (int sign : new int[] {-1, 1})
        nodes.add(
            bigInteger(MODULUS, BigInteger.ONE.shiftLeft(bits).multiply(BigInteger.valueOf(sign))));
    var xml = new XmlCodec();
    var json = new JsonCodec();
    for (Ttlv node : nodes) {
      assertEquals(node, codec.decode(codec.encode(node)));
      assertEquals(node, xml.decode(xml.encode(node)));
      assertEquals(node, json.decode(json.encode(node)));
    }
    Ttlv tree = structure(REQUEST_MESSAGE, nodes);
    assertEquals(tree, codec.decode(codec.encode(tree)));
    assertEquals(tree, json.decode(json.encode(tree)));
  }

  /**
   * The frame buffer grows geometrically (a 1 MiB frame used to take 17 buffers and copy
   * about 9 MiB) and every buffer the reader filled is zeroed once the frame is decoded.
   */
  @Test
  void frameBuffersGrowGeometricallyAndAreWiped() throws Exception {
    byte[] secret = new byte[1 << 20];
    Arrays.fill(secret, (byte) 0x5A);
    byte[] frame = codec.encode(bytes(KEY_MATERIAL, secret));
    List<byte[]> buffers = new ArrayList<>();
    InputStream trickle =
        new InputStream() {
          int pos;

          @Override
          public int read() {
            return pos < frame.length ? frame[pos++] & 0xff : -1;
          }

          @Override
          public int read(byte[] b, int off, int len) {
            if (buffers.stream().noneMatch(seen -> seen == b)) buffers.add(b);
            if (pos >= frame.length) return -1;
            int n = Math.min(Math.min(len, 4096), frame.length - pos);
            System.arraycopy(frame, pos, b, off, n);
            pos += n;
            return n;
          }
        };
    assertArrayEquals(secret, codec.read(trickle).bytesValue());
    assertTrue(buffers.size() <= 6, buffers.size() + " buffers");
    for (byte[] b : buffers) {
      for (byte x : b) assertEquals(0, x, "a frame buffer still holds key bytes");
    }
    // Also on failure: a frame cut short still has its partial buffers wiped.
    buffers.clear();
    byte[] truncated = Arrays.copyOf(frame, frame.length / 2);
    InputStream cut =
        new InputStream() {
          int pos;

          @Override
          public int read() {
            return pos < truncated.length ? truncated[pos++] & 0xff : -1;
          }

          @Override
          public int read(byte[] b, int off, int len) {
            if (buffers.stream().noneMatch(seen -> seen == b)) buffers.add(b);
            if (pos >= truncated.length) return -1;
            int n = Math.min(len, truncated.length - pos);
            System.arraycopy(truncated, pos, b, off, n);
            pos += n;
            return n;
          }
        };
    assertThrows(EOFException.class, () -> codec.read(cut));
    for (byte[] b : buffers) for (byte x : b) assertEquals(0, x);
  }

  @Test
  void malformedBinaryRejectedBeforeAllocation() {
    for (String hex :
        List.of(
            "4200690100000008",
            "42006a02000000080000000000000000",
            "42006901000000014200000000000000",
            "42006a02000000040000000100000001",
            "42000d06000000080000000000000002",
            "4200300700000002c080000000000000",
            "420069010000000842006a0200000004",
            "4200300b000000000000000000000000",
            "4200300400000000",
            "420030080000000100000000000000000000000000000000"))
      assertThrows(DecodeException.class, () -> codec.decode(HexFormat.of().parseHex(hex)), hex);
    byte[] giant = HexFormat.of().parseHex("42007801000000007fffffff00000000");
    ByteBuffer.wrap(giant).putInt(4, Integer.MAX_VALUE);
    assertThrows(DecodeException.class, () -> codec.read(new ByteArrayInputStream(giant)));
  }

  @Test
  void nestingAndSizeLimits() {
    Ttlv n = integer(BATCH_COUNT, 1);
    for (int i = 0; i < 70; i++) n = structure(REQUEST_MESSAGE, n);
    Ttlv deep = n;
    assertThrows(IllegalArgumentException.class, () -> codec.encode(deep));
    assertThrows(
        IllegalArgumentException.class,
        () -> new TtlvCodec(16, 4).encode(bytes(DATA, new byte[17])));
    assertThrows(IllegalArgumentException.class, () -> interval(LEASE_TIME, -1));
    assertThrows(
        IllegalArgumentException.class, () -> dateTime(TIME_STAMP, Instant.ofEpochSecond(1, 1)));
    assertThrows(IllegalArgumentException.class, () -> codec.encode(text(NAME_VALUE, "\ud800")));
  }

  @Test
  void streamFramingHandlesPartialReadsAndLeavesNextMessage() throws Exception {
    byte[] message = codec.encode(bytes(DATA, new byte[13]));
    byte[] both = new byte[message.length * 2];
    System.arraycopy(message, 0, both, 0, message.length);
    System.arraycopy(message, 0, both, message.length, message.length);
    InputStream fragmented =
        new FilterInputStream(new ByteArrayInputStream(both)) {
          @Override
          public int read(byte[] b, int off, int len) throws IOException {
            return super.read(b, off, Math.min(len, 1));
          }
        };
    assertEquals(bytes(DATA, new byte[13]), codec.read(fragmented));
    assertEquals(bytes(DATA, new byte[13]), codec.read(fragmented));
    assertEquals(-1, fragmented.read());
    assertThrows(
        EOFException.class,
        () -> codec.read(new ByteArrayInputStream(Arrays.copyOf(message, message.length - 1))));
  }

  @Test
  void xmlSecurityAndJsonValidation() throws Exception {
    String entity =
        "<!DOCTYPE x [<!ENTITY secret SYSTEM 'file:///etc/passwd'>]><Data type='TextString'"
            + " value='&secret;'/ >";
    assertThrows(
        IOException.class, () -> new XmlCodec().decode(entity.getBytes(StandardCharsets.UTF_8)));
    for (String input :
        List.of(
            "{\"tag\":\"Data\",\"type\":\"Integer\",\"value\":1.5}",
            "{\"tag\":\"Data\",\"tag\":\"Data\",\"value\":[]}",
            "{\"tag\":\"Data\",\"type\":\"TextString\",\"value\":\"\\ud800\"}",
            "{\"tag\":\"Data\",\"type\":\"Integer\",\"value\":01}",
            "{} trailing"))
      assertThrows(
          IOException.class, () -> new JsonCodec().decode(input.getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void immutableBytesAndRedactedLogs() {
    byte[] input = {1, 2, 3};
    Ttlv value = bytes(DATA, input);
    input[0] = 99;
    byte[] copy = value.bytesValue();
    copy[0] = 88;
    assertArrayEquals(new byte[] {1, 2, 3}, value.bytesValue());
    assertFalse(text(PASSWORD, "secret-password").toString().contains("secret-password"));
  }

  @Test
  void standardRegistryIsUniqueAndComplete() {
    assertEquals(431, Tag.values().length);
    assertEquals(66, Operation.values().length);
    assertEquals(
        Tag.values().length, Arrays.stream(Tag.values()).map(Tag::code).distinct().count());
    for (Tag tag : Tag.values()) {
      assertEquals(tag, Tag.fromCode(tag.code()).orElseThrow());
      assertEquals(tag, Tag.fromName(tag.wireName()));
    }
  }
}
