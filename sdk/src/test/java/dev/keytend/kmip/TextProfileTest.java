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
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import org.junit.jupiter.api.Test;

/** XML/JSON profile conformance and decoder bounds. */
class TextProfileTest {
  private static final XmlCodec XML = new XmlCodec();
  private static final JsonCodec JSON = new JsonCodec();

  private static Ttlv xml(String s) throws IOException {
    return XML.decode(s.getBytes(StandardCharsets.UTF_8));
  }

  private static Ttlv json(String s) throws IOException {
    return JSON.decode(s.getBytes(StandardCharsets.UTF_8));
  }

  private static String xmlText(Ttlv n) throws IOException {
    return new String(XML.encode(n), StandardCharsets.UTF_8);
  }

  private static String jsonText(Ttlv n) throws IOException {
    return new String(JSON.encode(n), StandardCharsets.UTF_8);
  }

  @Test
  void jsonExponentFormCannotInflateABigInteger() throws Exception {
    long start = System.nanoTime();
    assertThrows(
        IOException.class,
        () -> json("{\"tag\":\"Modulus\",\"type\":\"BigInteger\",\"value\":1e100000}"));
    assertThrows(
        IOException.class,
        () -> json("{\"tag\":\"Modulus\",\"type\":\"BigInteger\",\"value\":1e9}"));
    assertTrue(System.nanoTime() - start < 1_000_000_000L);
    assertEquals(
        java.math.BigInteger.valueOf(12345),
        json("{\"tag\":\"Modulus\",\"type\":\"BigInteger\",\"value\":12345}").bigIntegerValue());
  }

  /** KMIP Profiles 2.0 §5.4.1.6.13 (XML xsd:long) and §5.5.1.6.13 (JSON Number or hex string). */
  @Test
  void dateTimeExtendedUsesMicrosecondsInXmlAndHexOrNumberInJson() throws Exception {
    Ttlv dte = dateTimeExtended(ACTIVATION_DATE, Instant.parse("2020-01-01T00:00:00.123456Z"));
    assertTrue(xmlText(dte).contains("value=\"1577836800123456\""), xmlText(dte));
    assertTrue(jsonText(dte).contains("\"value\":\"0x00059B08C1FC2240\""), jsonText(dte));
    assertEquals(
        dte, xml("<ActivationDate type=\"DateTimeExtended\" value=\"1577836800123456\"/>"));
    assertEquals(
        dte,
        json(
            "{\"tag\":\"ActivationDate\",\"type\":\"DateTimeExtended\",\"value\":1577836800123456}"));
    assertEquals(
        dte,
        json(
            "{\"tag\":\"ActivationDate\",\"type\":\"DateTimeExtended\",\"value\":\"0x00059B08C1FC2240\"}"));
    // ISO text stays accepted as a lenient input but is no longer emitted.
    assertEquals(
        dte,
        xml("<ActivationDate type=\"DateTimeExtended\" value=\"2020-01-01T00:00:00.123456Z\"/>"));
    Ttlv min = Ttlv.of(ACTIVATION_DATE.code(), Ttlv.Type.DATE_TIME_EXTENDED, Long.MIN_VALUE);
    assertEquals(min, XML.decode(XML.encode(min)));
    assertEquals(min, JSON.decode(JSON.encode(min)));
  }

  @Test
  void xmlAndJsonDecodersHaveAnElementLimit() {
    StringBuilder xml = new StringBuilder("<RequestMessage>");
    StringBuilder json = new StringBuilder("{\"tag\":\"RequestMessage\",\"value\":[");
    for (int i = 0; i < 70_000; i++) {
      xml.append("<Comment type=\"TextString\" value=\"\"/>");
      json.append(i == 0 ? "" : ",")
          .append("{\"tag\":\"Comment\",\"type\":\"TextString\",\"value\":\"\"}");
    }
    xml.append("</RequestMessage>");
    json.append("]}");
    var x = assertThrows(IOException.class, () -> xml(xml.toString()));
    assertTrue(x.getMessage().contains("element limit"), x.getMessage());
    var j = assertThrows(IOException.class, () -> json(json.toString()));
    assertTrue(j.getMessage().contains("element limit"), j.getMessage());
    assertThrows(
        IOException.class,
        () ->
            new XmlCodec(1 << 20, 8, 2)
                .decode(
                    "<A><Comment type=\"TextString\" value=\"\"/><Comment type=\"TextString\" value=\"\"/></A>"
                        .replace("A>", "RequestMessage>")
                        .getBytes(StandardCharsets.UTF_8)));
  }

  @Test
  void textIntegersAreRangeChecked() throws Exception {
    assertThrows(
        IOException.class,
        () -> xml("<CryptographicLength type=\"Integer\" value=\"4294967168\"/>"));
    assertThrows(
        IOException.class,
        () -> xml("<CryptographicAlgorithm type=\"Enumeration\" value=\"-1\"/>"));
    assertThrows(
        IOException.class, () -> xml("<CryptographicLength type=\"Integer\" value=\"64 128\"/>"));
    assertEquals(
        -1, xml("<CryptographicLength type=\"Integer\" value=\"0xFFFFFFFF\"/>").intValue());
    assertEquals(-5, xml("<CryptographicLength type=\"Integer\" value=\"-5\"/>").intValue());
  }

  @Test
  void dateTimesOutsideTheIsoRangeUseHex() throws Exception {
    for (long seconds :
        new long[] {Long.MAX_VALUE, 253402300800L, 31556889864403199L, -62135596801L}) {
      Ttlv n = Ttlv.of(ACTIVATION_DATE.code(), Ttlv.Type.DATE_TIME, seconds);
      String x = xmlText(n), j = jsonText(n);
      assertTrue(x.contains(String.format("value=\"0x%016X\"", seconds)), x);
      assertFalse(x.contains("+"), x);
      assertTrue(j.contains(String.format("\"0x%016X\"", seconds)), j);
      assertEquals(n, XML.decode(XML.encode(n)));
      assertEquals(n, JSON.decode(JSON.encode(n)));
    }
    Ttlv y9999 = dateTime(ACTIVATION_DATE, Instant.parse("9999-12-31T23:59:59Z"));
    assertTrue(xmlText(y9999).contains("9999-12-31T23:59:59Z"));
  }

  @Test
  void reservedIsNotASymbolicValue() {
    assertThrows(
        IOException.class,
        () -> xml("<CryptographicUsageMask type=\"Integer\" value=\"Encrypt Reserved\"/>"));
    assertThrows(
        IOException.class, () -> xml("<ResultReason type=\"Enumeration\" value=\"Reserved\"/>"));
  }

  @Test
  void unicodeEscapesNeedFourHexDigits_rfc8259Section7() throws Exception {
    assertThrows(
        IOException.class,
        () -> json("{\"tag\":\"Comment\",\"type\":\"TextString\",\"value\":\"\\u-041\"}"));
    assertThrows(
        IOException.class,
        () -> json("{\"tag\":\"Comment\",\"type\":\"TextString\",\"value\":\"\\u+041\"}"));
    assertEquals(
        "A",
        json("{\"tag\":\"Comment\",\"type\":\"TextString\",\"value\":\"\\u0041\"}").textValue());
  }

  /** An {@code xsd:list} allows an empty sequence; OVH kmip-go sends it for a zero mask. */
  @Test
  void emptyMaskListDecodesAsZero_profiles21Section5_4_1_6_4() throws Exception {
    assertEquals(0, xml("<CryptographicUsageMask type=\"Integer\" value=\"\"/>").intValue());
    assertEquals(
        0,
        json("{\"tag\":\"CryptographicUsageMask\",\"type\":\"Integer\",\"value\":\"\"}")
            .intValue());
    assertEquals(
        12,
        xml("<CryptographicUsageMask type=\"Integer\" value=\"Encrypt | Decrypt\"/>").intValue());
    assertThrows(
        IOException.class,
        () -> xml("<CryptographicUsageMask type=\"Integer\" value=\"Encrypt||Decrypt\"/>"));
    assertThrows(
        IOException.class, () -> xml("<CryptographicLength type=\"Integer\" value=\"\"/>"));
  }

  /** Strict ASCII numbers with an unsigned bit-length check, and strict mask lists. */
  @Test
  void textNumbersAreStrictAsciiWithAnUnsignedBitLimit() throws Exception {
    // Bit 63 set used to pass the 32-bit check and decode as 0 (Success).
    assertThrows(
        DecodeException.class,
        () -> xml("<ResultStatus type=\"Enumeration\" value=\"0x8000000000000000\"/>"));
    assertThrows(
        DecodeException.class,
        () ->
            json(
                "{\"tag\":\"ResultStatus\",\"type\":\"Enumeration\",\"value\":\"0x8000000000000000\"}"));
    assertThrows(
        DecodeException.class,
        () -> xml("<CryptographicLength type=\"Integer\" value=\"0x8000000000000080\"/>"));
    // Hex takes no sign.
    assertThrows(
        DecodeException.class,
        () -> xml("<CryptographicLength type=\"Integer\" value=\"0x+80\"/>"));
    assertThrows(
        DecodeException.class,
        () -> xml("<CryptographicAlgorithm type=\"Enumeration\" value=\"0x-1\"/>"));
    assertThrows(
        DecodeException.class,
        () ->
            json(
                "{\"tag\":\"ServerCorrelationValue\",\"type\":\"LongInteger\",\"value\":\"0x+1\"}"));
    // Only ASCII digits: Arabic-Indic 128 and full-width hex digits are not numbers.
    assertThrows(
        DecodeException.class,
        () -> xml("<CryptographicLength type=\"Integer\" value=\"\u0661\u0662\u0668\"/>"));
    assertThrows(
        DecodeException.class,
        () -> xml("<CryptographicLength type=\"Integer\" value=\"0x\uFF18\uFF10\"/>"));
    assertThrows(
        DecodeException.class,
        () -> xml("<ServerCorrelationValue type=\"LongInteger\" value=\"\u0661\u0662\u0668\"/>"));
    // RFC 8259 §7: the four escape digits are ASCII hex (Character.digit took full-width ones).
    assertThrows(
        DecodeException.class,
        () ->
            json(
                "{\"tag\":\"Comment\",\"type\":\"TextString\",\"value\":\"\\u\uFF10\uFF10\uFF14\uFF11\"}"));
    // A trailing separator is an empty component, like a leading or doubled one.
    for (String list : new String[] {"Encrypt|", "Encrypt |", "Encrypt | ", "|Encrypt"})
      assertThrows(
          DecodeException.class,
          () -> xml("<CryptographicUsageMask type=\"Integer\" value=\"" + list + "\"/>"),
          list);
    // Still accepted: leading zeros, the 32-bit two's-complement form, 64-bit hex patterns.
    assertEquals(
        1, xml("<ResultStatus type=\"Enumeration\" value=\"0x0000000000000001\"/>").intValue());
    assertEquals(
        -1, xml("<CryptographicLength type=\"Integer\" value=\"0xFFFFFFFF\"/>").intValue());
    assertEquals(
        -1L,
        json("{\"tag\":\"ServerCorrelationValue\",\"type\":\"LongInteger\",\"value\":\"0xFFFFFFFFFFFFFFFF\"}")
            .longValue());
    assertEquals(
        Long.MIN_VALUE,
        xml("<ServerCorrelationValue type=\"LongInteger\" value=\"-9223372036854775808\"/>")
            .longValue());
    assertThrows(
        DecodeException.class,
        () -> xml("<ServerCorrelationValue type=\"LongInteger\" value=\"9223372036854775808\"/>"));
    assertEquals(
        "J",
        json("{\"tag\":\"Comment\",\"type\":\"TextString\",\"value\":\"\\u004a\"}").textValue());
  }

  /** "Reserved" never decodes, also where a group has only one Reserved value. */
  @Test
  void reservedIsRejectedEvenWhereItIsUnambiguous() {
    assertThrows(
        DecodeException.class, () -> xml("<ObjectType type=\"Enumeration\" value=\"Reserved\"/>"));
    assertThrows(
        DecodeException.class,
        () ->
            json(
                "{\"tag\":\"CertificateRequestType\",\"type\":\"Enumeration\",\"value\":\"Reserved\"}"));
  }

  private static final String SECRET = "SECRET-4b1d9e0f00112233";

  static void assertScrubbed(Throwable e) {
    for (Throwable t = e; t != null; t = t.getCause()) {
      assertFalse(String.valueOf(t.getMessage()).contains("4b1d"), t.toString());
      assertFalse(t.toString().contains("4b1d"), t.toString());
    }
  }

  /** Decode failures are DecodeExceptions whose messages and causes hold no input value. */
  @Test
  void decodeErrorsNeverEchoInputValues() throws Exception {
    String[] xmlCases = {
      "<ResultStatus type=\"Enumeration\" value=\"" + SECRET + "\"/>",
      "<ActivationDate type=\"DateTime\" value=\"" + SECRET + "\"/>",
      "<ServerCorrelationValue type=\"LongInteger\" value=\"" + SECRET + "\"/>",
      "<KeyMaterial type=\"ByteString\" value=\"4b1d9e0f0011223z\"/>",
      "<Modulus type=\"BigInteger\" value=\"4b1d9e0f00112\"/>",
      "<" + SECRET + " type=\"Integer\" value=\"1\"/>",
      "<TTLV tag=\"0x4b1d\" type=\"Integer\" value=\"1\"/>",
      "<CryptographicLength type=\"" + SECRET + "\" value=\"1\"/>",
      "<Attribute><AttributeName type=\"TextString\" value=\"x-"
          + SECRET
          + "\"/><AttributeValue type=\"Enumeration\" value=\"Bogus\"/></Attribute>",
      "<Comment type=\"TextString\" value=\"" + SECRET + "\">" + SECRET + "</Comment>",
      "<Comment type=\"TextString\" value=\"" + SECRET + "\"",
    };
    for (String c : xmlCases) assertScrubbed(assertThrows(DecodeException.class, () -> xml(c), c));
    String[] jsonCases = {
      "{\"tag\":\"ResultStatus\",\"type\":\"Enumeration\",\"value\":\"" + SECRET + "\"}",
      "{\"tag\":\"ActivationDate\",\"type\":\"DateTime\",\"value\":\"" + SECRET + "\"}",
      "{\"tag\":\"KeyMaterial\",\"type\":\"ByteString\",\"value\":\"4b1d9e0f0011223z\"}",
      "{\"tag\":\"" + SECRET + "\",\"type\":\"Integer\",\"value\":1}",
      "{\"tag\":\"Comment\",\"type\":\"TextString\",\"value\":\"" + SECRET + "\"",
      "{\"tag\":\"CryptographicLength\",\"type\":\"Integer\",\"value\":4b1d}",
    };
    for (String c : jsonCases)
      assertScrubbed(assertThrows(DecodeException.class, () -> json(c), c));
    // TTLV: a Text String holding the secret, then a Boolean that is neither 0 nor 1.
    byte[] ttlv = malformedTtlvWithSecret();
    assertScrubbed(assertThrows(DecodeException.class, () -> new TtlvCodec().decode(ttlv)));
    assertScrubbed(
        assertThrows(
            DecodeException.class,
            () -> new TtlvCodec().read(new java.io.ByteArrayInputStream(ttlv))));
  }

  static byte[] malformedTtlvWithSecret() {
    byte[] text = SECRET.getBytes(StandardCharsets.UTF_8);
    int padded = (text.length + 7) & ~7;
    java.nio.ByteBuffer b = java.nio.ByteBuffer.allocate(8 + 8 + padded + 16);
    b.put(new byte[] {0x42, 0x00, 0x7B, 0x01}).putInt(8 + padded + 16); // ResponseMessage
    b.put(new byte[] {0x42, 0x00, 0x41, 0x07}).putInt(text.length).put(text); // Comment
    while (b.position() % 8 != 0) b.put((byte) 0);
    b.put(new byte[] {0x42, 0x00, 0x08, 0x06}).putInt(8).putLong(2); // Boolean 2
    return b.array();
  }

  /** Decoding rejects precision the KMIP type cannot hold instead of truncating it. */
  @Test
  void fractionalSecondsAreRejectedNotTruncated() throws Exception {
    assertThrows(
        IOException.class,
        () ->
            json(
                "{\"tag\":\"ActivationDate\",\"type\":\"DateTime\",\"value\":\"2020-01-01T00:00:00.999Z\"}"));
    assertThrows(
        IOException.class,
        () ->
            xml(
                "<ActivationDate type=\"DateTimeExtended\" value=\"2020-01-01T00:00:00.0000009Z\"/>"));
    assertEquals(
        Instant.parse("2020-01-01T00:00:00Z"),
        xml("<ActivationDate type=\"DateTime\" value=\"2020-01-01T00:00:00.000Z\"/>")
            .instantValue());
  }

  /**
   * The codec uses the JDK's StAX, never one the system properties or the class path name: a
   * factory named that does not exist would make {@code newFactory()} fail.
   */
  @Test
  void xmlUsesTheJdksStaxWhateverTheSystemPropertiesName() throws Exception {
    String in = "javax.xml.stream.XMLInputFactory", out = "javax.xml.stream.XMLOutputFactory";
    String oldIn = System.getProperty(in), oldOut = System.getProperty(out);
    System.setProperty(in, "no.such.XmlInputFactory");
    System.setProperty(out, "no.such.XmlOutputFactory");
    try {
      Ttlv name = text(UNIQUE_IDENTIFIER, "k-1");
      assertEquals(name, XML.decode(XML.encode(name)));
    } finally {
      if (oldIn == null) System.clearProperty(in);
      else System.setProperty(in, oldIn);
      if (oldOut == null) System.clearProperty(out);
      else System.setProperty(out, oldOut);
    }
  }
}
