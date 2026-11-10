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

import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import javax.net.ssl.*;

/**
 * Self-signed test identities ({@link TestX509}), each in a PKCS#12 key store under its name with
 * the password {@code changeit}. Each certificate is what {@code keytool -genkeypair -ext
 * SAN=dns:localhost,ip:127.0.0.1 -validity 2} makes: {@code CN=name}, valid from now for two days,
 * for {@code localhost} and {@code 127.0.0.1}, with a Subject Key Identifier and no other
 * extension, signed with the algorithm keytool chooses for the key.
 */
public final class TestTls {
  private static final char[] PASSWORD = "changeit".toCharArray();
  private static final Map<String, KeyStore> STORES = new HashMap<>();

  private TestTls() {}

  public static KeyStore identity(String name) throws Exception {
    return identity(name, "EC");
  }

  /**
   * {@code keyAlgorithm} is EC (P-256), RSA or RSASSA-PSS (2048-bit), or DSA (the JDK's default
   * size, 2048 bits).
   */
  public static synchronized KeyStore identity(String name, String keyAlgorithm) throws Exception {
    KeyStore cached = STORES.get(name);
    if (cached != null) return cached;
    KeyPairGenerator g = KeyPairGenerator.getInstance(keyAlgorithm);
    switch (keyAlgorithm) {
      case "EC" -> g.initialize(new ECGenParameterSpec("secp256r1"));
      case "RSA", "RSASSA-PSS" -> g.initialize(2048);
      default -> {}
    }
    KeyPair pair = g.generateKeyPair();
    Instant now = Instant.now();
    X509Certificate certificate =
        TestX509.certificate(name, pair.getPublic())
            .selfSigned(pair.getPrivate())
            .validity(now, now.plus(Duration.ofDays(2)))
            .localhost()
            .keyIdentifiers()
            .build();
    KeyStore made = KeyStore.getInstance("PKCS12");
    made.load(null, null);
    made.setKeyEntry(name, pair.getPrivate(), PASSWORD, new Certificate[] {certificate});
    // Stored and read back, as from a file: the entries are what a PKCS#12 file decodes to.
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    made.store(bytes, PASSWORD);
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(new ByteArrayInputStream(bytes.toByteArray()), PASSWORD);
    STORES.put(name, ks);
    return ks;
  }

  public static X509Certificate certificate(String name) throws Exception {
    return (X509Certificate) identity(name).getCertificate(name);
  }

  /** A context presenting {@code self} and trusting every certificate in {@code trusted}. */
  public static SSLContext context(String self, String... trusted) throws Exception {
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(identity(self), PASSWORD);
    KeyStore trust = KeyStore.getInstance("PKCS12");
    trust.load(null, null);
    for (String t : trusted) trust.setCertificateEntry(t, certificate(t));
    TrustManagerFactory tmf =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(trust);
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
    return context;
  }
}
