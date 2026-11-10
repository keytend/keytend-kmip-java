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

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.List;
import javax.security.auth.x500.X500Principal;

/**
 * A PKCS#10 certification request (RFC 2986) in DER: the subject, the public key, and, when there
 * are subject alternative names, an extensionRequest attribute (PKCS#9) holding one
 * subjectAltName extension (RFC 5280), critical when the subject is empty. It is signed with the
 * private key using SHA-256: RSA PKCS#1 v1.5 (sha256WithRSAEncryption), or ECDSA
 * (ecdsa-with-SHA256). Built in-house, as docs/dependencies.md ("Kept in-house") says; the tests
 * check it against Bouncy Castle.
 */
final class Pkcs10 {
  static final String SHA256_WITH_RSA = "1.2.840.113549.1.1.11";
  static final String ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";
  static final String EXTENSION_REQUEST = "1.2.840.113549.1.9.14";
  static final String SUBJECT_ALT_NAME = "2.5.29.17";

  private Pkcs10() {}

  /**
   * A subject alternative name: its GeneralName choice ({@link #EMAIL}, {@link #DNS}, {@link
   * #URI} or {@link #IP}, the context tag numbers of RFC 5280) and its value as text (an IP
   * address as a literal).
   */
  record AltName(int type, String value) {
    static final int EMAIL = 1, DNS = 2, URI = 6, IP = 7;
  }

  /**
   * The DER request for {@code pair}'s public key, signed with its private key, with no
   * attributes.
   *
   * @throws GeneralSecurityException when the key is neither RSA nor EC, or cannot sign
   */
  static byte[] request(X500Principal subject, KeyPair pair) throws GeneralSecurityException {
    return request(subject, pair.getPublic(), pair.getPrivate(), List.of());
  }

  /**
   * The DER request for {@code publicKey} with {@code names} as its subject alternative names,
   * signed with {@code privateKey}, the private half of {@code publicKey}.
   *
   * @throws GeneralSecurityException when the key is neither RSA nor EC, or cannot sign
   * @throws IllegalArgumentException when an IP address is not a literal IPv4 or IPv6 address
   */
  static byte[] request(
      X500Principal subject, PublicKey publicKey, PrivateKey privateKey, List<AltName> names)
      throws GeneralSecurityException {
    if (!"X.509".equals(publicKey.getFormat()))
      throw new GeneralSecurityException("The public key has no X.509 encoding");
    String algorithm;
    byte[] signatureAlgorithm;
    switch (publicKey.getAlgorithm()) {
      case "RSA" -> {
        algorithm = "SHA256withRSA";
        signatureAlgorithm = Der.sequence(Der.oid(SHA256_WITH_RSA), Der.nul());
      }
      case "EC" -> {
        algorithm = "SHA256withECDSA";
        signatureAlgorithm = Der.sequence(Der.oid(ECDSA_WITH_SHA256));
      }
      default ->
          throw new GeneralSecurityException(
              "A certificate request is made for RSA and EC keys, not " + publicKey.getAlgorithm());
    }
    byte[] subjectDer = subject.getEncoded();
    // attributes [0] IMPLICIT SET OF Attribute.
    byte[] attributes =
        names.isEmpty()
            ? Der.element(0xa0)
            : Der.element(
                0xa0,
                Der.sequence(
                    Der.oid(EXTENSION_REQUEST),
                    Der.element(0x31, Der.sequence(altNames(names, isEmptyName(subjectDer))))));
    byte[] info =
        Der.sequence(
            Der.integer(0), Der.whole(subjectDer), Der.whole(publicKey.getEncoded()), attributes);
    Signature signer = Signature.getInstance(algorithm);
    signer.initSign(privateKey);
    signer.update(info);
    return Der.sequence(info, signatureAlgorithm, Der.bitString(signer.sign()));
  }

  /** The subjectAltName extension; critical when the subject is empty (RFC 5280, 4.2.1.6). */
  private static byte[] altNames(List<AltName> names, boolean critical) {
    ByteArrayOutputStream general = new ByteArrayOutputStream();
    for (AltName n : names) {
      byte[] value =
          n.type() == AltName.IP
              ? ipAddress(n.value())
              : n.value().getBytes(StandardCharsets.US_ASCII);
      general.writeBytes(Der.element(0x80 | n.type(), value));
    }
    byte[] generalNames = Der.element(0x30, general.toByteArray());
    return critical
        ? Der.sequence(
            Der.oid(SUBJECT_ALT_NAME),
            Der.element(0x01, new byte[] {(byte) 0xff}),
            Der.octetString(generalNames))
        : Der.sequence(Der.oid(SUBJECT_ALT_NAME), Der.octetString(generalNames));
  }

  /** Whether a DER Name is the empty sequence. */
  private static boolean isEmptyName(byte[] name) {
    return name.length == 2 && name[0] == 0x30 && name[1] == 0;
  }

  /**
   * The octets of a literal IPv4 or IPv6 address. Only literals are taken, so that no name is
   * looked up.
   *
   * @throws IllegalArgumentException otherwise
   */
  static byte[] ipAddress(String literal) {
    boolean v4 = literal.matches("\\d{1,3}(\\.\\d{1,3}){3}");
    boolean v6 = literal.indexOf(':') >= 0 && literal.matches("[0-9A-Fa-f:.]+");
    if (!v4 && !v6) throw new IllegalArgumentException("Not an IP address literal: " + literal);
    if (v4)
      for (String part : literal.split("\\.", -1))
        if (Integer.parseInt(part) > 255)
          throw new IllegalArgumentException("Not an IP address literal: " + literal);
    try {
      // A literal is parsed, never looked up.
      return java.net.InetAddress.getByName(literal).getAddress();
    } catch (java.net.UnknownHostException e) {
      throw new IllegalArgumentException("Not an IP address literal: " + literal, e);
    }
  }
}
