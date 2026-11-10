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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * {@link Provisioning#sslClient}: OpenSSL's purpose sslclient, which keytend-kmip-server's listener
 * verifier checks on every certificate of a new client certificate's path.
 */
class ProvisioningPurposeTest {
  static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2",
      SERVER_AUTH = "1.3.6.1.5.5.7.3.1",
      ANY = "2.5.29.37.0";

  /** Key Usage bits, as RFC 5280 numbers them. */
  static final int DIGITAL_SIGNATURE = 0,
      KEY_ENCIPHERMENT = 2,
      KEY_AGREEMENT = 4,
      KEY_CERT_SIGN = 5,
      CRL_SIGN = 6;

  final KeyPair root = ec(), client = ec();

  @Test
  void theLeafMaySignOrAgreeAndBeAClient() throws Exception {
    X509Certificate ca = ca(ca(true), keyUsage(KEY_CERT_SIGN));
    assertTrue(path(leaf(), ca));
    assertTrue(path(leaf(eku(CLIENT_AUTH)), ca));
    assertTrue(path(leaf(eku(SERVER_AUTH, CLIENT_AUTH)), ca));
    // An Extended Key Usage without clientAuth; anyExtendedKeyUsage alone does not count.
    assertFalse(path(leaf(eku(SERVER_AUTH)), ca));
    assertFalse(path(leaf(eku(ANY)), ca));
    assertTrue(path(leaf(keyUsage(DIGITAL_SIGNATURE)), ca));
    assertTrue(path(leaf(keyUsage(KEY_AGREEMENT)), ca));
    assertFalse(path(leaf(keyUsage(KEY_ENCIPHERMENT)), ca));
    // A Netscape certificate type must name an SSL client.
    assertTrue(path(leaf(netscape(0x80)), ca));
    assertFalse(path(leaf(netscape(0x40)), ca));
  }

  @Test
  void eachCaOfThePathMustBeACaForClients() throws Exception {
    X509Certificate leaf = leaf();
    assertTrue(path(leaf, ca(ca(true), keyUsage(KEY_CERT_SIGN))));
    assertTrue(path(leaf, ca(ca(true), keyUsage(KEY_CERT_SIGN), eku(CLIENT_AUTH))));
    assertFalse(path(leaf, ca(ca(true), keyUsage(KEY_CERT_SIGN), eku(SERVER_AUTH))));
    assertFalse(path(leaf, ca(ca(true), keyUsage(KEY_CERT_SIGN), eku(ANY))));
    assertFalse(path(leaf, ca(ca(true), keyUsage(CRL_SIGN))));
    assertFalse(path(leaf, ca(ca(false), keyUsage(KEY_CERT_SIGN))));
    // Without basicConstraints: a certificate with a Key Usage that allows keyCertSign passes.
    assertTrue(path(leaf, ca(keyUsage(KEY_CERT_SIGN))));
    assertFalse(path(leaf, ca()));
    // Without basicConstraints or a Key Usage, a Netscape certificate type that names SSL CA
    // makes a CA for clients; one that names only another kind of CA, or no CA, does not.
    assertTrue(path(leaf, ca(netscape(0x04))));
    assertTrue(path(leaf, ca(netscape(0x07))));
    assertFalse(path(leaf, ca(netscape(0x02))));
    assertFalse(path(leaf, ca(netscape(0x01))));
    assertFalse(path(leaf, ca(netscape(0x80))));
    // Where basicConstraints or a Key Usage decides, the CA's Netscape type is not read.
    assertTrue(path(leaf, ca(ca(true), keyUsage(KEY_CERT_SIGN), netscape(0x02))));
    assertTrue(path(leaf, ca(keyUsage(KEY_CERT_SIGN), netscape(0x80))));
    assertFalse(path(leaf, ca(ca(false), netscape(0x04))));
    // Every CA of the path, the anchor included.
    X509Certificate good = ca(ca(true), keyUsage(KEY_CERT_SIGN));
    assertFalse(path(leaf, good, ca(ca(true), keyUsage(KEY_CERT_SIGN), eku(SERVER_AUTH))));
  }

  private static boolean path(X509Certificate... certificates) {
    return Provisioning.sslClient(List.of(certificates));
  }

  private X509Certificate leaf(byte[]... extensions) throws Exception {
    return certificate("client", client.getPublic(), "Root", root.getPrivate(), extensions);
  }

  private X509Certificate ca(byte[]... extensions) throws Exception {
    return certificate("Root", root.getPublic(), "Root", root.getPrivate(), extensions);
  }

  // ---- a minimal certificate writer: DER, ecdsa-with-SHA256 ----

  private static KeyPair ec() {
    try {
      KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
      g.initialize(256);
      return g.generateKeyPair();
    } catch (java.security.GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private static X509Certificate certificate(
      String subject, PublicKey key, String issuer, PrivateKey signer, byte[]... extensions)
      throws Exception {
    byte[] algorithm = sequence(oid("1.2.840.10045.4.3.2"));
    List<byte[]> tbs = new ArrayList<>();
    tbs.add(element(0xa0, integer(BigInteger.TWO)));
    tbs.add(integer(BigInteger.valueOf(System.nanoTime() & 0xffffffL)));
    tbs.add(algorithm);
    tbs.add(name(issuer));
    tbs.add(sequence(utc("250101000000Z"), utc("491231235959Z")));
    tbs.add(name(subject));
    tbs.add(key.getEncoded());
    if (extensions.length > 0) tbs.add(element(0xa3, sequence(extensions)));
    byte[] body = sequence(tbs.toArray(byte[][]::new));
    Signature s = Signature.getInstance("SHA256withECDSA");
    s.initSign(signer);
    s.update(body);
    byte[] der = sequence(body, algorithm, element(0x03, new byte[] {0}, s.sign()));
    return (X509Certificate)
        CertificateFactory.getInstance("X.509").generateCertificate(new ByteArrayInputStream(der));
  }

  static byte[] ca(boolean ca) {
    return extension(
        "2.5.29.19", true, ca ? sequence(new byte[] {0x01, 0x01, (byte) 0xff}) : sequence());
  }

  static byte[] keyUsage(int bit) {
    return extension("2.5.29.15", true, new byte[] {0x03, 0x02, 0x00, (byte) (0x80 >> bit)});
  }

  private static byte[] eku(String... oids) {
    List<byte[]> purposes = new ArrayList<>();
    for (String o : oids) purposes.add(oid(o));
    return extension("2.5.29.37", false, sequence(purposes.toArray(byte[][]::new)));
  }

  private static byte[] netscape(int bits) {
    return extension("2.16.840.1.113730.1.1", false, new byte[] {0x03, 0x02, 0x00, (byte) bits});
  }

  static byte[] extension(String oid, boolean critical, byte[] value) {
    byte[] wrapped = element(0x04, value);
    return critical
        ? sequence(oid(oid), new byte[] {0x01, 0x01, (byte) 0xff}, wrapped)
        : sequence(oid(oid), wrapped);
  }

  static byte[] name(String cn) {
    return sequence(
        element(
            0x31, sequence(oid("2.5.4.3"), element(0x0c, cn.getBytes(StandardCharsets.UTF_8)))));
  }

  static byte[] utc(String time) {
    return element(0x17, time.getBytes(StandardCharsets.US_ASCII));
  }

  static byte[] integer(BigInteger v) {
    return element(0x02, v.toByteArray());
  }

  static byte[] oid(String dotted) {
    String[] arcs = dotted.split("\\.");
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(Integer.parseInt(arcs[0]) * 40 + Integer.parseInt(arcs[1]));
    for (int i = 2; i < arcs.length; i++) {
      long arc = Long.parseLong(arcs[i]);
      int n = 0;
      byte[] base128 = new byte[10];
      do {
        base128[n++] = (byte) (arc & 0x7f);
        arc >>>= 7;
      } while (arc > 0);
      for (int j = n - 1; j >= 0; j--) out.write(base128[j] | (j > 0 ? 0x80 : 0));
    }
    return element(0x06, out.toByteArray());
  }

  static byte[] sequence(byte[]... parts) {
    return element(0x30, parts);
  }

  static byte[] element(int tag, byte[]... contents) {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    for (byte[] c : contents) body.writeBytes(c);
    int length = body.size();
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(tag);
    if (length < 0x80) out.write(length);
    else {
      byte[] l = BigInteger.valueOf(length).toByteArray();
      int skip = l[0] == 0 ? 1 : 0;
      out.write(0x80 | (l.length - skip));
      out.write(l, skip, l.length - skip);
    }
    out.writeBytes(body.toByteArray());
    return out.toByteArray();
  }
}
