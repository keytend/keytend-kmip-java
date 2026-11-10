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

package dev.keytend.kmip.testing;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.Set;

/**
 * The in-memory server's Certify ({@link InMemoryKmipServer}): reads a PKCS#10 request (RFC 2986)
 * and issues an X.509 v3 end-entity certificate from it, as keytend-kmip-server does: the request's
 * subject and subject alternative names (DNS, email, URI and IP), critical basicConstraints
 * CA:FALSE and a critical keyUsage from the usage mask, signed with SHA-256 by an RSA CA, or by an
 * EC CA with SHA-256, SHA-384 or SHA-512 for P-256, P-384 or P-521. Test support: the DER is read
 * and written here, with no third-party library.
 */
final class CertificateIssuance {
  private CertificateIssuance() {}

  /**
   * Why a request is refused: not a signed request, a name of a kind not issued ({@code names}), or
   * an EC key on a curve other than P-256, P-384 or P-521 ({@code curve}).
   */
  static final class Refused extends Exception {
    private static final long serialVersionUID = 1L;
    final boolean names;
    final boolean curve;

    Refused(String message, boolean names) {
      this(message, names, false);
    }

    private Refused(String message, boolean names, boolean curve) {
      super(message, null, false, false);
      this.names = names;
      this.curve = curve;
    }
  }

  /** The namedCurve OIDs of P-256, P-384 and P-521. */
  static final Set<String> NIST_CURVES =
      Set.of("1.2.840.10045.3.1.7", "1.3.132.0.34", "1.3.132.0.35");

  private static final String EC_PUBLIC_KEY = "1.2.840.10045.2.1";

  /**
   * The namedCurve OID of an EC SubjectPublicKeyInfo, the empty string when it has other (explicit)
   * parameters, and null when it is not an EC key or cannot be read.
   */
  static String namedCurve(byte[] spki) {
    try {
      Der whole = Der.read(spki, 0);
      Der algorithm = Der.read(spki, whole.start);
      if (whole.tag != 0x30 || algorithm.tag != 0x30) return null;
      Der type = Der.read(spki, algorithm.start);
      if (!EC_PUBLIC_KEY.equals(oid(spki, type)) || type.end >= algorithm.end) return null;
      Der parameters = Der.read(spki, type.end);
      return parameters.tag == 0x06 ? oid(spki, parameters) : "";
    } catch (IndexOutOfBoundsException | IllegalArgumentException e) {
      return null;
    }
  }

  /**
   * Whether keytend-kmip-server issues a certificate for {@code key}, whose SubjectPublicKeyInfo is
   * {@code spki}: RSA of 2048 bits or more, or EC on P-256, P-384 or P-521 named by its OID.
   */
  static boolean supportedKey(PublicKey key, byte[] spki) {
    if (key instanceof RSAKey r) return r.getModulus().bitLength() >= 2048;
    return key instanceof ECKey && NIST_CURVES.contains(namedCurve(spki));
  }

  /**
   * A verified request: the subject Name and SubjectPublicKeyInfo as encoded in it, the key, and
   * the GeneralNames of its subjectAltName extension (null when it has none).
   */
  record Request(byte[] subject, byte[] publicKeyInfo, PublicKey publicKey, byte[] altNames) {
    boolean emptySubject() {
      return subject.length == 2;
    }
  }

  private static final String EXTENSION_REQUEST = "1.2.840.113549.1.9.14";
  private static final String SUBJECT_ALT_NAME = "2.5.29.17";
  private static final Map<String, String> SIGNATURES =
      Map.of(
          "1.2.840.113549.1.1.11", "SHA256withRSA",
          "1.2.840.113549.1.1.12", "SHA384withRSA",
          "1.2.840.113549.1.1.13", "SHA512withRSA",
          "1.2.840.10045.4.3.2", "SHA256withECDSA",
          "1.2.840.10045.4.3.3", "SHA384withECDSA",
          "1.2.840.10045.4.3.4", "SHA512withECDSA");

  /** A PEM request's DER, or {@code value} itself when it is not PEM. */
  static byte[] fromPem(byte[] value) throws Refused {
    String text = new String(value, StandardCharsets.US_ASCII);
    int begin = text.indexOf("-----BEGIN CERTIFICATE REQUEST-----");
    int end = text.indexOf("-----END CERTIFICATE REQUEST-----");
    if (begin < 0 || end < begin) throw new Refused("Not a PEM certificate request", false);
    String body = text.substring(begin + 35, end).replaceAll("\\s", "");
    try {
      return Base64.getDecoder().decode(body);
    } catch (IllegalArgumentException e) {
      throw new Refused("Not a PEM certificate request", false);
    }
  }

  /**
   * Reads and verifies a DER PKCS#10 request.
   *
   * @throws Refused when it is malformed, its signature does not verify, its key is EC on a named
   *     curve other than P-256, P-384 or P-521, or it asks for a subject alternative name of a kind
   *     other than DNS, email, URI or IP
   */
  static Request parse(byte[] der) throws Refused {
    try {
      Der outer = Der.read(der, 0);
      if (outer.tag != 0x30 || outer.end != der.length) throw new Refused("Not a request", false);
      Der info = Der.read(der, outer.start);
      Der algorithm = Der.read(der, info.end);
      Der signature = Der.read(der, algorithm.end);
      if (info.tag != 0x30 || algorithm.tag != 0x30 || signature.tag != 0x03)
        throw new Refused("Not a request", false);
      Der version = Der.read(der, info.start);
      Der subject = Der.read(der, version.end);
      Der spki = Der.read(der, subject.end);
      if (version.tag != 0x02 || subject.tag != 0x30 || spki.tag != 0x30)
        throw new Refused("Not a request", false);
      byte[] altNames = null;
      if (spki.end < info.end) {
        Der attributes = Der.read(der, spki.end);
        if (attributes.tag != 0xa0) throw new Refused("Not a request", false);
        for (int at = attributes.start; at < attributes.end; ) {
          Der attribute = Der.read(der, at);
          at = attribute.end;
          Der type = Der.read(der, attribute.start);
          if (!EXTENSION_REQUEST.equals(oid(der, type))) continue;
          Der values = Der.read(der, type.end);
          Der extensions = Der.read(der, values.start);
          for (int e = extensions.start; e < extensions.end; ) {
            Der extension = Der.read(der, e);
            e = extension.end;
            Der id = Der.read(der, extension.start);
            if (!SUBJECT_ALT_NAME.equals(oid(der, id))) continue;
            Der value = Der.read(der, id.end);
            if (value.tag == 0x01) value = Der.read(der, value.end);
            Der names = Der.read(der, value.start);
            altNames = Arrays.copyOfRange(der, names.offset, names.end);
            for (int n = names.start; n < names.end; ) {
              Der name = Der.read(der, n);
              n = name.end;
              int choice = name.tag & 0x1f;
              if ((name.tag & 0xe0) != 0x80
                  || (choice != 1 && choice != 2 && choice != 6 && choice != 7))
                throw new Refused("Unsupported requested subject alternative name", true);
            }
          }
        }
      }
      // keytend-kmip-server refuses another named curve from the DER, before reading the key.
      String curve = namedCurve(Arrays.copyOfRange(der, spki.offset, spki.end));
      if (curve != null && !curve.isEmpty() && !NIST_CURVES.contains(curve))
        throw new Refused("Unsupported EC curve", false, true);
      PublicKey key = publicKey(Arrays.copyOfRange(der, spki.offset, spki.end));
      Der algorithmId = Der.read(der, algorithm.start);
      String name = SIGNATURES.get(oid(der, algorithmId));
      if (name == null) throw new Refused("Unsupported request signature algorithm", false);
      Signature verifier = Signature.getInstance(name);
      verifier.initVerify(key);
      verifier.update(der, info.offset, info.end - info.offset);
      if (der[signature.start] != 0
          || !verifier.verify(Arrays.copyOfRange(der, signature.start + 1, signature.end)))
        throw new Refused("The request's signature does not verify", false);
      return new Request(
          Arrays.copyOfRange(der, subject.offset, subject.end),
          Arrays.copyOfRange(der, spki.offset, spki.end),
          key,
          altNames);
    } catch (GeneralSecurityException | IndexOutOfBoundsException | IllegalArgumentException e) {
      throw new Refused("Not a signed request: " + e.getMessage(), false);
    }
  }

  private static PublicKey publicKey(byte[] spki) throws GeneralSecurityException {
    GeneralSecurityException last = null;
    for (String algorithm : new String[] {"RSA", "EC"})
      try {
        return KeyFactory.getInstance(algorithm).generatePublic(new X509EncodedKeySpec(spki));
      } catch (GeneralSecurityException e) {
        last = e;
      }
    throw last;
  }

  /**
   * Issues the certificate for {@code request}, signed by {@code caKey} as {@code ca}, valid from
   * {@code notBefore} to {@code notAfter}, with the keyUsage bits {@code keyUsage} (bit n is RFC
   * 5280's bit n; none: no keyUsage extension).
   */
  static byte[] issue(
      Request request,
      X509Certificate ca,
      PrivateKey caKey,
      Instant notBefore,
      Instant notAfter,
      int keyUsage,
      SecureRandom random)
      throws GeneralSecurityException {
    String signatureName;
    byte[] algorithm;
    if ("RSA".equals(caKey.getAlgorithm())) {
      signatureName = "SHA256withRSA";
      algorithm = seq(oidBytes("1.2.840.113549.1.1.11"), tlv(0x05));
    } else {
      int bits = ((ECKey) caKey).getParams().getCurve().getField().getFieldSize();
      String hash = bits > 384 ? "512" : bits > 256 ? "384" : "256";
      signatureName = "SHA" + hash + "withECDSA";
      algorithm =
          seq(
              oidBytes(
                  bits > 384
                      ? "1.2.840.10045.4.3.4"
                      : bits > 256 ? "1.2.840.10045.4.3.3" : "1.2.840.10045.4.3.2"));
    }
    ByteArrayOutputStream extensions = new ByteArrayOutputStream();
    // basicConstraints, critical, CA:FALSE (the empty sequence).
    extensions.writeBytes(seq(oidBytes("2.5.29.19"), TRUE, tlv(0x04, seq())));
    if (keyUsage != 0) {
      int highest = 31 - Integer.numberOfLeadingZeros(keyUsage);
      byte[] bits = new byte[highest / 8 + 1];
      for (int b = 0; b <= highest; b++)
        if ((keyUsage & (1 << b)) != 0) bits[b / 8] |= (byte) (0x80 >>> (b % 8));
      int unused = 7 - highest % 8;
      byte[] content = new byte[bits.length + 1];
      content[0] = (byte) unused;
      System.arraycopy(bits, 0, content, 1, bits.length);
      extensions.writeBytes(seq(oidBytes("2.5.29.15"), TRUE, tlv(0x04, tlv(0x03, content))));
    }
    if (request.altNames() != null)
      extensions.writeBytes(
          request.emptySubject()
              ? seq(oidBytes(SUBJECT_ALT_NAME), TRUE, tlv(0x04, request.altNames()))
              : seq(oidBytes(SUBJECT_ALT_NAME), tlv(0x04, request.altNames())));
    byte[] tbs =
        seq(
            tlv(0xa0, tlv(0x02, new byte[] {2})),
            tlv(0x02, new BigInteger(159, random).setBit(158).toByteArray()),
            algorithm,
            ca.getSubjectX500Principal().getEncoded(),
            seq(time(notBefore), time(notAfter)),
            request.subject(),
            request.publicKeyInfo(),
            tlv(0xa3, seq(extensions.toByteArray())));
    Signature signer = Signature.getInstance(signatureName);
    signer.initSign(caKey);
    signer.update(tbs);
    byte[] signature = signer.sign();
    byte[] bitString = new byte[signature.length + 1];
    System.arraycopy(signature, 0, bitString, 1, signature.length);
    return seq(tbs, algorithm, tlv(0x03, bitString));
  }

  private static final byte[] TRUE = {0x01, 0x01, (byte) 0xff};

  /** UTCTime through 2049, GeneralizedTime from 2050 (RFC 5280, 4.1.2.5). */
  private static byte[] time(Instant t) {
    java.time.ZonedDateTime z = t.atZone(ZoneOffset.UTC);
    boolean utc = z.getYear() < 2050;
    String text =
        DateTimeFormatter.ofPattern(utc ? "yyMMddHHmmss'Z'" : "yyyyMMddHHmmss'Z'").format(z);
    return tlv(utc ? 0x17 : 0x18, text.getBytes(StandardCharsets.US_ASCII));
  }

  private static String oid(byte[] der, Der element) {
    if (element.tag != 0x06) return null;
    StringBuilder out = new StringBuilder();
    long arc = 0;
    boolean first = true;
    for (int i = element.start; i < element.end; i++) {
      arc = (arc << 7) | (der[i] & 0x7f);
      if ((der[i] & 0x80) != 0) continue;
      if (first) {
        int top = arc < 80 ? (int) (arc / 40) : 2;
        out.append(top).append('.').append(arc - 40L * top);
        first = false;
      } else out.append('.').append(arc);
      arc = 0;
    }
    return out.toString();
  }

  private static byte[] oidBytes(String dotted) {
    String[] arcs = dotted.split("\\.");
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    long[] values = new long[arcs.length - 1];
    values[0] = Long.parseLong(arcs[0]) * 40 + Long.parseLong(arcs[1]);
    for (int i = 2; i < arcs.length; i++) values[i - 1] = Long.parseLong(arcs[i]);
    for (long v : values) {
      int groups = 1;
      for (long x = v >>> 7; x != 0; x >>>= 7) groups++;
      for (int g = groups - 1; g >= 0; g--) {
        int b = (int) ((v >>> (7 * g)) & 0x7f);
        out.write(g == 0 ? b : b | 0x80);
      }
    }
    return tlv(0x06, out.toByteArray());
  }

  private static byte[] seq(byte[]... parts) {
    return tlv(0x30, parts);
  }

  private static byte[] tlv(int tag, byte[]... contents) {
    int n = 0;
    for (byte[] c : contents) n += c.length;
    ByteArrayOutputStream out = new ByteArrayOutputStream(n + 6);
    out.write(tag);
    if (n < 0x80) out.write(n);
    else {
      int bytes = 0;
      for (int v = n; v != 0; v >>>= 8) bytes++;
      out.write(0x80 | bytes);
      for (int i = bytes - 1; i >= 0; i--) out.write(n >>> (8 * i));
    }
    for (byte[] c : contents) out.writeBytes(c);
    return out.toByteArray();
  }

  /**
   * One DER element of a buffer: its tag, where it begins, and where its contents begin and end.
   */
  private record Der(int tag, int offset, int start, int end) {
    static Der read(byte[] b, int at) {
      int tag = b[at] & 0xff;
      if ((tag & 0x1f) == 0x1f) throw new IllegalArgumentException("high tag number");
      int first = b[at + 1] & 0xff;
      int length, start;
      if (first < 0x80) {
        length = first;
        start = at + 2;
      } else {
        int count = first & 0x7f;
        if (count == 0 || count > 3) throw new IllegalArgumentException("length");
        length = 0;
        for (int i = 0; i < count; i++) length = (length << 8) | (b[at + 2 + i] & 0xff);
        start = at + 2 + count;
      }
      if (start + length > b.length) throw new IllegalArgumentException("truncated");
      return new Der(tag, at, start, start + length);
    }
  }
}
