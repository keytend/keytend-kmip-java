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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import java.io.ByteArrayInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Assume;
import net.jqwik.api.Combinators;
import net.jqwik.api.Example;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.Tuple;
import net.jqwik.api.constraints.IntRange;
import net.jqwik.api.statistics.Statistics;

/**
 * Properties of the three codecs over generated {@link Ttlv} trees (jqwik): every value of every
 * type, standard and extension tags, structures up to five deep. TTLV, JSON and XML give back the
 * tree they encoded (XML refuses, with an {@link IOException}, exactly the trees holding a
 * character XML 1.0 cannot carry); TTLV frames read whole however the stream splits them; and
 * mutated or arbitrary input makes the decoders throw only what they document, {@link
 * DecodeException} (and {@link EOFException} for a stream that ends early), whose message never
 * holds a value of the input. jqwik shrinks a failing tree and replays its seed; a fixed regression
 * then belongs in {@code CodecTest}.
 */
class CodecPropertiesTest {
  /** A text value in some trees: no decoder's message may quote it. */
  private static final String MARKER = "MARKER-value-7f3a";

  private static final TtlvCodec TTLV = new TtlvCodec();
  private static final JsonCodec JSON = new JsonCodec();
  private static final XmlCodec XML = new XmlCodec();

  // ---- Generators ----

  @Provide
  Arbitrary<Ttlv> trees() {
    return Arbitraries.recursive(this::scalar, this::structure, 0, 4);
  }

  /** A structure, as its outermost value: what a message is. */
  @Provide
  Arbitrary<Ttlv> messages() {
    return structure(trees());
  }

  private Arbitrary<Integer> tags() {
    return Arbitraries.frequencyOf(
        Tuple.of(6, Arbitraries.of(Tag.values()).map(Tag::code)),
        Tuple.of(1, Arbitraries.integers().between(0x420000, 0x42ffff)),
        Tuple.of(1, Arbitraries.integers().between(0x540000, 0x54ffff)));
  }

  private Arbitrary<Ttlv> structure(Arbitrary<Ttlv> child) {
    Arbitrary<Integer> tags = tags().filter(t -> t != Tag.ATTRIBUTE_NAME.code());
    return Combinators.combine(tags, child.list().ofMaxSize(4))
        .as((tag, children) -> Ttlv.structure(tag, children));
  }

  /**
   * Text of any Unicode scalar values, weighted to ASCII, now and then the edges of what XML 1.0
   * carries and the marker.
   */
  private Arbitrary<String> texts() {
    Arbitrary<Integer> codePoints =
        Arbitraries.frequencyOf(
            Tuple.of(8, Arbitraries.integers().between(0x20, 0x7e)),
            Tuple.of(1, Arbitraries.integers().between(0, 0x1f)),
            Tuple.of(1, Arbitraries.of(0xfffd, 0xfffe, 0xffff, 0x10000, 0x10ffff)),
            Tuple.of(
                2,
                Arbitraries.integers()
                    .between(0x80, 0x10ffff)
                    .filter(cp -> cp < 0xd800 || cp > 0xdfff)));
    Arbitrary<String> text =
        codePoints
            .list()
            .ofMaxSize(16)
            .map(
                cps -> {
                  StringBuilder b = new StringBuilder();
                  cps.forEach(b::appendCodePoint);
                  return b.toString();
                });
    return Arbitraries.frequencyOf(Tuple.of(9, text), Tuple.of(1, Arbitraries.just(MARKER)));
  }

  /**
   * A scalar of any type, except that an Attribute Name is a Text String (and never a structure):
   * the textual profiles read it to name the Attribute Value's enumeration, and refuse a structure
   * whose Attribute Name is of another type (which they nevertheless encode; TTLV carries it).
   */
  private Arbitrary<Ttlv> scalar() {
    Arbitrary<Ttlv.Type> types =
        Arbitraries.of(Ttlv.Type.class).filter(t -> t != Ttlv.Type.STRUCTURE);
    return Combinators.combine(tags(), types)
        .flatAs(
            (tag, type) -> {
              Ttlv.Type t = tag == Tag.ATTRIBUTE_NAME.code() ? Ttlv.Type.TEXT_STRING : type;
              return value(t).map(v -> Ttlv.of(tag, t, v));
            });
  }

  private Arbitrary<?> value(Ttlv.Type type) {
    return switch (type) {
      case INTEGER, ENUMERATION -> Arbitraries.integers();
      case LONG_INTEGER, DATE_TIME, DATE_TIME_EXTENDED -> Arbitraries.longs();
      case INTERVAL -> Arbitraries.longs().between(0, 0xffff_ffffL);
      case BIG_INTEGER ->
          Arbitraries.bigIntegers()
              .between(BigInteger.ONE.shiftLeft(256).negate(), BigInteger.ONE.shiftLeft(256));
      case BOOLEAN -> Arbitraries.of(true, false);
      case TEXT_STRING, IDENTIFIER, REFERENCE, NAME_REFERENCE -> texts();
      case BYTE_STRING -> Arbitraries.bytes().array(byte[].class).ofMaxSize(40);
      case STRUCTURE -> throw new AssertionError();
    };
  }

  /** One change to an encoding: a byte flipped, set, inserted or removed, a cut, a slice repeated. */
  record Mutation(int kind, int at, int length, byte value) {
    byte[] apply(byte[] in) {
      if (in.length == 0) return new byte[] {value};
      int i = Math.floorMod(at, in.length);
      return switch (kind) {
        case 0 -> {
          byte[] out = in.clone();
          out[i] ^= (byte) (1 << Math.floorMod(value, 8));
          yield out;
        }
        case 1 -> {
          byte[] out = in.clone();
          out[i] = value;
          yield out;
        }
        case 2 -> {
          byte[] out = new byte[in.length + 1];
          System.arraycopy(in, 0, out, 0, i);
          out[i] = value;
          System.arraycopy(in, i, out, i + 1, in.length - i);
          yield out;
        }
        case 3 -> {
          int n = Math.min(length, in.length - i);
          byte[] out = new byte[in.length - n];
          System.arraycopy(in, 0, out, 0, i);
          System.arraycopy(in, i + n, out, i, in.length - i - n);
          yield out;
        }
        case 4 -> Arrays.copyOf(in, i);
        default -> {
          int n = Math.min(length, in.length - i);
          byte[] out = new byte[in.length + n];
          System.arraycopy(in, 0, out, 0, i + n);
          System.arraycopy(in, i, out, i + n, in.length - i);
          yield out;
        }
      };
    }
  }

  @Provide
  Arbitrary<List<Mutation>> mutations() {
    return Combinators.combine(
            Arbitraries.integers().between(0, 5),
            Arbitraries.integers().greaterOrEqual(0),
            Arbitraries.integers().between(1, 16),
            Arbitraries.bytes())
        .as(Mutation::new)
        .list()
        .ofMinSize(1)
        .ofMaxSize(3);
  }

  // ---- Round trips ----

  @Property
  void ttlvGivesBackTheTreeAndTheSameBytes(@ForAll("trees") Ttlv tree) throws IOException {
    byte[] encoded = TTLV.encode(tree);
    Ttlv decoded = TTLV.decode(encoded);
    assertEquals(tree, decoded);
    assertArrayEquals(encoded, TTLV.encode(decoded));
    Statistics.collect(tree.type());
  }

  @Property
  void jsonGivesBackTheTree(@ForAll("trees") Ttlv tree) throws IOException {
    byte[] encoded = JSON.encode(tree);
    assertEquals(tree, decodeOrFail(JSON::decode, encoded), () -> new String(encoded, UTF_8));
    Statistics.collect(tree.type());
  }

  /** {@code decoder}'s value, or a failure showing the document it refused (generated data). */
  private static Object decodeOrFail(Decoder decoder, byte[] encoded) {
    try {
      return decoder.decode(encoded);
    } catch (IOException e) {
      throw new AssertionError(e + " for " + new String(encoded, UTF_8), e);
    }
  }

  @Property
  void xmlGivesBackTheTreeOrRefusesWhatXmlCannotCarry(@ForAll("trees") Ttlv tree) {
    xmlGivesBackOrRefuses(tree);
  }

  /** The edges of XML 1.0's characters, each alone in a text, through the same check. */
  @Example
  void xmlCharacterEdges() {
    int[] edges = {
      0, 8, 9, 10, 11, 13, 0x1f, 0x20, 0xd7ff, 0xe000, 0xfffd, 0xfffe, 0xffff, 0x10000, 0x10ffff
    };
    for (int cp : edges) xmlGivesBackOrRefuses(Ttlv.text(Tag.NAME_VALUE, Character.toString(cp)));
    assertFalse(xmlRepresentable(Ttlv.text(Tag.NAME_VALUE, "\ufffe")));
    assertFalse(xmlRepresentable(Ttlv.text(Tag.NAME_VALUE, "\uffff")));
    assertTrue(xmlRepresentable(Ttlv.text(Tag.NAME_VALUE, "\ufffd\ud7ff\ue000\udbff\udfff")));
  }

  private static void xmlGivesBackOrRefuses(Ttlv tree) {
    boolean representable = xmlRepresentable(tree);
    try {
      byte[] encoded = XML.encode(tree);
      assertTrue(representable, "encoded a value XML 1.0 cannot carry");
      assertEquals(tree, decodeOrFail(XML::decode, encoded), () -> new String(encoded, UTF_8));
    } catch (IOException e) {
      assertFalse(representable, () -> "refused a representable tree: " + e);
      assertEquals("Value cannot be represented in XML 1.0", e.getMessage());
    }
    Statistics.collect(representable ? "XML" : "not XML");
  }

  /**
   * Whether every text of {@code n} is XML 1.0 characters (the other types' text always is): the
   * production Char, #x9, #xA, #xD, [#x20-#xD7FF], [#xE000-#xFFFD] and [#x10000-#x10FFFF].
   */
  private static boolean xmlRepresentable(Ttlv n) {
    if (n.type() == Ttlv.Type.STRUCTURE)
      return n.children().stream().allMatch(CodecPropertiesTest::xmlRepresentable);
    return switch (n.type()) {
      case TEXT_STRING, IDENTIFIER, REFERENCE, NAME_REFERENCE ->
          n.textValue().codePoints().allMatch(CodecPropertiesTest::xmlChar);
      default -> true;
    };
  }

  private static boolean xmlChar(int cp) {
    return cp == 9
        || cp == 10
        || cp == 13
        || (cp >= 0x20 && cp <= 0xd7ff)
        || (cp >= 0xe000 && cp <= 0xfffd)
        || (cp >= 0x10000 && cp <= 0x10ffff);
  }

  /** A stream that hands out at most {@code chunk} bytes a read. */
  private static InputStream trickle(byte[] bytes, int chunk) {
    return new ByteArrayInputStream(bytes) {
      @Override
      public synchronized int read(byte[] b, int off, int len) {
        return super.read(b, off, Math.min(len, chunk));
      }
    };
  }

  @Property
  void ttlvFramesReadWholeHoweverTheStreamSplitsThem(
      @ForAll("messages") Ttlv first,
      @ForAll("messages") Ttlv second,
      @ForAll @IntRange(min = 1, max = 64) int chunk)
      throws IOException {
    byte[] a = TTLV.encode(first), b = TTLV.encode(second);
    byte[] both = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, both, a.length, b.length);
    InputStream in = trickle(both, chunk);
    assertEquals(first, TTLV.read(in));
    assertEquals(second, TTLV.read(in));
    assertEquals(-1, in.read());
  }

  // ---- Malformed input ----

  /** {@code decoder} returns a value or throws a DecodeException that quotes nothing; nothing else. */
  private static void decodesOrRefuses(byte[] input, Decoder decoder) {
    try {
      decoder.decode(input);
    } catch (DecodeException e) {
      String message = String.valueOf(e.getMessage());
      assertFalse(message.contains(MARKER), message);
      for (Throwable c = e.getCause(); c != null; c = c.getCause())
        assertFalse(String.valueOf(c.getMessage()).contains(MARKER), String.valueOf(c));
    } catch (Throwable other) {
      throw new AssertionError("not a DecodeException: " + other, other);
    }
  }

  @FunctionalInterface
  interface Decoder {
    Object decode(byte[] input) throws IOException;
  }

  private static byte[] mutate(byte[] encoded, List<Mutation> mutations) {
    byte[] out = encoded;
    for (Mutation m : mutations) out = m.apply(out);
    return out;
  }

  @Property
  void mutatedTtlvIsDecodedOrRefusedWithADecodeException(
      @ForAll("messages") Ttlv tree, @ForAll("mutations") List<Mutation> mutations) {
    byte[] input = mutate(TTLV.encode(tree), mutations);
    decodesOrRefuses(input, TTLV::decode);
    // The stream reader also ends early (EOFException, documented) when the frame is cut.
    try {
      TTLV.read(new ByteArrayInputStream(input));
    } catch (EOFException | DecodeException expected) {
      assertFalse(String.valueOf(expected.getMessage()).contains(MARKER));
    } catch (Throwable other) {
      throw new AssertionError("not a DecodeException or EOFException: " + other, other);
    }
  }

  @Property
  void mutatedJsonIsDecodedOrRefusedWithADecodeException(
      @ForAll("messages") Ttlv tree, @ForAll("mutations") List<Mutation> mutations)
      throws IOException {
    decodesOrRefuses(mutate(JSON.encode(tree), mutations), JSON::decode);
  }

  @Property
  void mutatedXmlIsDecodedOrRefusedWithADecodeException(
      @ForAll("messages") Ttlv tree, @ForAll("mutations") List<Mutation> mutations)
      throws IOException {
    Assume.that(xmlRepresentable(tree));
    byte[] input = mutate(XML.encode(tree), mutations);
    decodesOrRefuses(input, XML::decode);
    decodesOrRefuses(input, XML::decodeAll);
  }

  @Property
  void arbitraryBytesAreDecodedOrRefusedWithADecodeException(@ForAll("bytes") byte[] input) {
    decodesOrRefuses(input, TTLV::decode);
    decodesOrRefuses(input, JSON::decode);
    decodesOrRefuses(input, XML::decode);
  }

  /** Arbitrary bytes, and text that looks like each profile's start. */
  @Provide
  Arbitrary<byte[]> bytes() {
    Arbitrary<byte[]> raw = Arbitraries.bytes().array(byte[].class).ofMaxSize(64);
    Arbitrary<byte[]> prefixed =
        Combinators.combine(
                Arbitraries.of("B\u0000", "{\"tag\":", "<RequestMessage", "[", "<?xml "),
                Arbitraries.bytes().array(byte[].class).ofMaxSize(48))
            .as(
                (prefix, rest) -> {
                  byte[] p = prefix.getBytes(UTF_8);
                  byte[] out = Arrays.copyOf(p, p.length + rest.length);
                  System.arraycopy(rest, 0, out, p.length, rest.length);
                  return out;
                });
    return Arbitraries.oneOf(raw, prefixed);
  }
}
