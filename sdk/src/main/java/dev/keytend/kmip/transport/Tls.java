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

package dev.keytend.kmip.transport;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import javax.net.ssl.*;

/**
 * Builds the {@link SSLContext} for a {@link TlsTransport}: the client's identity from a PKCS#12
 * keystore, and trust from a PEM CA bundle.
 *
 * <pre>{@code
 * SSLContext ssl = Tls.context(Path.of("client.p12"), password, Path.of("ca.pem"));
 * KmipTransport transport = new TlsTransport("kms.example.com", 5696, ssl);
 * }</pre>
 *
 * <p>{@code client.p12} holds the client's private key and certificate chain, and {@code password}
 * is its password. {@code ca.pem} holds the CA certificates that signed the server's certificate.
 * {@link #KMIP_CIPHER_SUITES} lists the suites of the KMIP profiles.
 *
 * @since 0.10.0
 */
public final class Tls {
  private Tls() {}

  /**
   * The KMIP Basic Authentication cipher suites (KMIP Profiles 2.1 §3.1.2), in JSSE names: the two
   * TLS 1.3 suites, the two mandatory TLS 1.2 suites, then the optional TLS 1.2 suites. Transports
   * use the JDK defaults unless a builder is given this list (see {@link #kmipCipherSuites}),
   * because the profile excludes suites the JDK prefers.
   *
   * <p>JDK 24 and later disable {@code TLS_RSA_*} key exchange through {@code
   * jdk.tls.disabledAlgorithms}, so the two mandatory TLS 1.2 suites are unavailable there unless
   * that property is changed. A profile-conformant server also offers TLS 1.3, which is
   * unaffected; a legacy TLS 1.2-only, TLS_RSA-only server needs the property adjusted.
   */
  public static final List<String> KMIP_CIPHER_SUITES =
      List.of(
          "TLS_AES_256_GCM_SHA384",
          "TLS_CHACHA20_POLY1305_SHA256",
          "TLS_RSA_WITH_AES_256_CBC_SHA256",
          "TLS_RSA_WITH_AES_128_CBC_SHA256",
          "TLS_RSA_WITH_AES_128_CBC_SHA",
          "TLS_RSA_WITH_AES_256_CBC_SHA",
          "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
          "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
          "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
          "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
          "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
          "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
          "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
          "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
          "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
          "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
          "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
          "TLS_PSK_WITH_AES_128_CBC_SHA",
          "TLS_PSK_WITH_AES_256_CBC_SHA",
          "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
          "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");

  /**
   * The profile suites that {@code context} has enabled on this JDK, in profile order.
   *
   * @param context the TLS context
   * @return the suites, for {@link TlsTransport.Builder#cipherSuites}
   * @throws IllegalStateException when none is enabled
   */
  public static List<String> kmipCipherSuites(SSLContext context) {
    Set<String> enabled = Set.of(context.getDefaultSSLParameters().getCipherSuites());
    List<String> suites = new ArrayList<>();
    for (String suite : KMIP_CIPHER_SUITES) if (enabled.contains(suite)) suites.add(suite);
    if (suites.isEmpty())
      throw new IllegalStateException("No KMIP profile cipher suite is enabled on this JDK");
    return List.copyOf(suites);
  }

  /**
   * A TLS context with the keystore's one private key as the client identity, trusting only the
   * certificates in {@code caPem}. The JDK's default trust store is not used. See {@link
   * #context(Path, char[], Path, String)} to choose a key from a keystore that holds several.
   *
   * @param clientPkcs12 a PKCS#12 keystore with exactly one private-key entry; null for a context
   *     without a client identity
   * @param password the keystore password, also used for the key; not used when {@code
   *     clientPkcs12} is null
   * @param caPem one or more PEM X.509 certificates to trust; required
   * @return a new context
   * @throws KeyStoreException if the keystore holds no private key, or more than one
   * @throws CertificateException if {@code caPem} holds no certificate or cannot be parsed
   * @throws GeneralSecurityException for another key or certificate problem
   * @throws IOException if a file cannot be read, or the keystore cannot be loaded (for example
   *     with a wrong password)
   * @throws NullPointerException if {@code caPem} is null
   */
  public static SSLContext context(Path clientPkcs12, char[] password, Path caPem)
      throws GeneralSecurityException, IOException {
    return context(clientPkcs12, password, caPem, null);
  }

  /**
   * {@link #context(Path, char[], Path)} with the client identity chosen by alias. Use it when the
   * keystore holds more than one private key.
   *
   * @param clientPkcs12 a PKCS#12 keystore; null for a context without a client identity
   * @param password the keystore password, also used for the key; not used when {@code
   *     clientPkcs12} is null
   * @param caPem one or more PEM X.509 certificates to trust; required
   * @param alias the alias of the private-key entry to use; null to require exactly one
   * @return a new context
   * @throws KeyStoreException if {@code alias} names no private-key entry, or, with a null alias,
   *     the keystore holds no private key or more than one
   * @throws CertificateException if {@code caPem} holds no certificate or cannot be parsed
   * @throws GeneralSecurityException for another key or certificate problem
   * @throws IOException if a file cannot be read, or the keystore cannot be loaded (for example
   *     with a wrong password)
   * @throws NullPointerException if {@code caPem} is null
   */
  public static SSLContext context(Path clientPkcs12, char[] password, Path caPem, String alias)
      throws GeneralSecurityException, IOException {
    Objects.requireNonNull(caPem, "An explicit CA bundle is required");
    KeyManager[] keys = null;
    if (clientPkcs12 != null) {
      KeyStore store = KeyStore.getInstance("PKCS12");
      try (InputStream in = Files.newInputStream(clientPkcs12)) {
        store.load(in, password);
      }
      List<String> identities = new ArrayList<>();
      for (String entry : Collections.list(store.aliases()))
        if (store.isKeyEntry(entry)) identities.add(entry);
      String chosen = alias;
      if (chosen == null) {
        if (identities.size() != 1)
          throw new KeyStoreException(
              "PKCS12 must contain one private identity or specify an alias");
        chosen = identities.get(0);
      }
      if (!store.isKeyEntry(chosen))
        throw new KeyStoreException("Requested private-key alias is absent");
      KeyStore selected = KeyStore.getInstance("PKCS12");
      selected.load(null, null);
      selected.setKeyEntry(
          "identity", store.getKey(chosen, password), password, store.getCertificateChain(chosen));
      KeyManagerFactory kmf =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(selected, password);
      keys = kmf.getKeyManagers();
    }
    KeyStore trust = KeyStore.getInstance("PKCS12");
    trust.load(null, null);
    try (InputStream in = Files.newInputStream(caPem)) {
      Collection<? extends java.security.cert.Certificate> certs =
          CertificateFactory.getInstance("X.509").generateCertificates(in);
      if (certs.isEmpty()) throw new CertificateException("Empty CA bundle");
      int i = 0;
      for (java.security.cert.Certificate cert : certs)
        trust.setCertificateEntry("ca-" + i++, cert);
    }
    TrustManagerFactory tmf =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(trust);
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(keys, tmf.getTrustManagers(), null);
    return context;
  }
}
