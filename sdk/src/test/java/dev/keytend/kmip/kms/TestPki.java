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

import dev.keytend.kmip.TestX509;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;

/**
 * A small certificate authority for tests ({@link TestX509}), so tests can issue many CA-signed
 * certificates for one key quickly. Every certificate is valid from a day ago for 30 days and has a
 * new serial number. A CA has a critical Basic Constraints extension (CA, no path length
 * constraint); a leaf has the Subject Alternative Names {@code dns:localhost} and {@code
 * ip:127.0.0.1}. Either has a critical Key Usage extension only when bits are given, and no other
 * extension.
 */
final class TestPki {
  /** A certificate and the private key it is for. */
  record Issued(X509Certificate certificate, PrivateKey key) {
    X509Certificate[] chain(Issued... issuers) {
      X509Certificate[] out = new X509Certificate[issuers.length + 1];
      out[0] = certificate;
      for (int i = 0; i < issuers.length; i++) out[i + 1] = issuers[i].certificate;
      return out;
    }
  }

  private TestPki() {}

  static KeyPair ec() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec("secp256r1"));
    return g.generateKeyPair();
  }

  static KeyPair rsa() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
    g.initialize(2048);
    return g.generateKeyPair();
  }

  /** RFC 5280 Key Usage bits, for {@code keyUsage}. */
  static final int DIGITAL_SIGNATURE = TestX509.DIGITAL_SIGNATURE,
      KEY_ENCIPHERMENT = TestX509.KEY_ENCIPHERMENT,
      KEY_AGREEMENT = TestX509.KEY_AGREEMENT,
      KEY_CERT_SIGN = TestX509.KEY_CERT_SIGN,
      CRL_SIGN = TestX509.CRL_SIGN;

  /** A self-signed CA; with {@code keyUsage} bits, a critical Key Usage extension granting them. */
  static Issued ca(String name, int... keyUsage) throws Exception {
    KeyPair k = ec();
    return new Issued(
        TestX509.certificate(name, k.getPublic())
            .selfSigned(k.getPrivate())
            .ca()
            .keyUsage(keyUsage)
            .build(),
        k.getPrivate());
  }

  /** An intermediate CA issued by {@code issuer}; {@code keyUsage} as for {@link #ca}. */
  static Issued intermediate(String name, Issued issuer, int... keyUsage) throws Exception {
    KeyPair k = ec();
    return new Issued(
        TestX509.certificate(name, k.getPublic())
            .issuedBy(issuer.certificate, issuer.key)
            .ca()
            .keyUsage(keyUsage)
            .build(),
        k.getPrivate());
  }

  /** A leaf for {@code key} issued by {@code issuer}, with a new serial number each time; {@code keyUsage} as for {@link #ca}. */
  static Issued leaf(String name, KeyPair key, Issued issuer, int... keyUsage) throws Exception {
    return new Issued(
        TestX509.certificate(name, key.getPublic())
            .issuedBy(issuer.certificate, issuer.key)
            .localhost()
            .keyUsage(keyUsage)
            .build(),
        key.getPrivate());
  }
}
