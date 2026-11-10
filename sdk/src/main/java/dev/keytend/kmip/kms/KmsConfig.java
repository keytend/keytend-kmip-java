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

import dev.keytend.kmip.client.VersionPolicy;
import dev.keytend.kmip.model.ProtocolVersion;
import dev.keytend.kmip.transport.HashedPasswordTransport;
import dev.keytend.kmip.transport.KmipTransport;
import dev.keytend.kmip.transport.TlsTransport;
import java.io.IOException;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.*;
import java.util.function.Supplier;
import javax.net.ssl.*;

/**
 * Settings for {@link Kms#connect(KmsConfig)}. Build with {@link #builder()}; immutable.
 *
 * <pre>{@code
 * KmsConfig config = KmsConfig.builder()
 *     .endpoints("kms1.example.com:5696", "kms2.example.com:5696")
 *     .clientIdentityKeyStore(Path.of("client.p12"), password)
 *     .trustPem(Path.of("ca.pem"))
 *     .poolSize(8)
 *     .build();
 * }</pre>
 *
 * <p>{@code password} is the PKCS#12 file's password, a {@code char[]}. Several endpoints must be
 * replicas of one logical KMS, with the same objects and identifiers, because reads fail over
 * between them.
 *
 * <p>Configuration problems are {@link IllegalArgumentException}s from the builder method or from
 * {@link Builder#build()}. Examples are an unreadable key store, a wrong password, or a private key
 * that does not match its certificate. The message names the file or the setting, and never quotes
 * key material or file contents.
 *
 * <p>A {@code KmsConfig} is immutable and may be shared. A {@link Builder} is not thread-safe. See
 * <a href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/getting-started.md#connect-to-your-kms">Connect
 * to your KMS</a>.
 *
 * @since 0.10.0
 */
public final class KmsConfig {
  /**
   * A {@code host:port} the client connects to.
   *
   * @param host the host name or IP address (an IPv6 address without brackets), not empty
   * @param port the port, 1 to 65535
   */
  public record Endpoint(String host, int port) {
    /**
     * Checks the components.
     *
     * @param host the host name or IP address, not empty
     * @param port the port, 1 to 65535
     * @throws IllegalArgumentException when the host is empty or the port is out of range
     */
    public Endpoint {
      Objects.requireNonNull(host, "host");
      if (host.isEmpty() || port < 1 || port > 65535)
        throw new IllegalArgumentException("Invalid endpoint " + host + ":" + port);
    }

    /** {@code host:port}, with an IPv6 address in brackets. */
    @Override
    public String toString() {
      return (host.contains(":") ? "[" + host + "]" : host) + ":" + port;
    }
  }

  /** Opens the transport for an endpoint; replaces the default mutual-TLS transport. */
  @FunctionalInterface
  public interface TransportFactory {
    /**
     * Opens a transport to {@code endpoint}; the {@link Kms} closes it when it is done with it.
     *
     * @param endpoint the endpoint to connect to
     * @return a new transport
     * @throws IOException when the transport cannot be opened
     */
    KmipTransport open(Endpoint endpoint) throws IOException;
  }

  /** How the client authenticates. */
  public enum Authentication {
    /** The TLS client certificate only. */
    CLIENT_CERTIFICATE,
    /** A username/password Credential in every request, in addition to TLS. */
    PASSWORD,
    /** KMIP 2.0+ hashed-password credentials. */
    HASHED_PASSWORD
  }

  final List<Endpoint> endpoints;
  final SSLContext tls;

  /** The {@link Builder#tls(Supplier)} source; then {@link #tls} is null. */
  final Supplier<SSLContext> tlsSource;

  /**
   * The files {@link Builder#reloadOnChange(Duration)} watches, or null; {@link #tls} is then the
   * context {@link Builder#build()} made from them, where each {@link Kms} starts.
   */
  final TlsFiles.Watch reloading;

  /** The renewal of the client certificate ({@link Builder#clientCertificateRenewal}), or null. */
  final ClientRenewal renewal;

  final Authentication auth;
  final String username;
  final char[] password;
  final VersionPolicy versions;
  final int poolSize;
  final Duration idleTimeout, connectTimeout, callTimeout;

  /** Idle at least this long, a pooled connection is probed (1 ms) before reuse. */
  final Duration validateAfterIdle;

  /** How long {@link Kms#connect} retries an unreachable KMS; zero: not at all. */
  final Duration connectRetry;

  /** Whether a server that does not implement Obtain Lease may be used under the stated Lease Time. */
  final LeasePolicy leases;

  final RetryPolicy retry;

  /** The SDK's logging ({@link LoggingListener}) first, then the listeners added: what the SDK calls. */
  final KmsListener listener;

  /**
   * {@link #listener}'s listeners, those of {@link KmsListener#all} flattened: a call told through
   * several configurations tells each of them once ({@link Kms.Call}).
   */
  final List<KmsListener> callListeners;

  /** The listeners added, in order: {@link #listeners()}. */
  private final List<KmsListener> added;

  final List<String> cipherSuites;
  final boolean kmipCipherSuites;
  final TransportFactory transport;
  final int pageSize, locateLimit;
  final Duration hashedPasswordLockWait;
  private final Builder source;

  private KmsConfig(Builder b, SSLContext tls) {
    source = b.copy();
    endpoints = List.copyOf(b.endpoints);
    this.tls = tls;
    tlsSource = b.tlsSource;
    if (b.reloadEvery != null)
      // The snapshot's copy of the password, for the life of the configuration (never changed;
      // toBuilder() clones it).
      reloading =
          new TlsFiles.Watch(
              source.identityFiles, b.identity, source.trustFile, b.trust, tls, b.reloadEvery);
    else {
      // Without reloadOnChange the files are not read again: keep no file names or password,
      // except the identity's when a renewal rewrites it.
      reloading = null;
      if (b.renewal == null) {
        if (source.identityFiles != null) source.identityFiles.wipe();
        source.identityFiles = null;
      }
      if (source.trustFile != null) source.trustFile.wipe();
      source.trustFile = null;
    }
    // The configuration's own copy of the identity files and their password, for its life. The
    // identity the builder loaded tells which renewal of the files in this process it holds.
    renewal =
        b.renewal == null
            ? null
            : new ClientRenewal(b.renewal, source.identityFiles, b.trust, b.identityLeaf);
    auth = b.auth;
    username = b.username;
    // One copy for the life of the configuration, shared with the private snapshot (never changed;
    // toBuilder() clones it), so a later change to the builder cannot reach it.
    password = source.password;
    VersionPolicy policy = b.policy();
    if (auth == Authentication.HASHED_PASSWORD && policy.minimum().legacyAttributes())
      policy = new VersionPolicy(ProtocolVersion.V2_0, policy.maximum(), policy.allowed());
    versions = policy;
    poolSize = b.poolSize;
    idleTimeout = b.idleTimeout;
    validateAfterIdle = b.validateAfterIdle;
    connectTimeout = b.connectTimeout;
    callTimeout = b.callTimeout;
    connectRetry = b.connectRetry;
    leases = b.leases;
    retry = b.retry;
    added = List.copyOf(b.listeners);
    List<KmsListener> all = new ArrayList<>(b.listeners.size() + 1);
    all.add(LoggingListener.INSTANCE);
    all.addAll(b.listeners);
    // Each listener once by identity, for every event: one added twice (or also inside a
    // KmsListener.all) hears each call and each attempt once.
    KmsListeners each = new KmsListeners(all);
    listener = each;
    callListeners = each.listeners();
    cipherSuites = b.cipherSuites;
    kmipCipherSuites = b.kmipCipherSuites;
    transport = b.transport;
    pageSize = b.pageSize;
    locateLimit = b.locateLimit;
    hashedPasswordLockWait = b.hashedPasswordLockWait;
  }

  /**
   * A new builder, with the defaults its methods state.
   *
   * @return a new builder
   */
  public static Builder builder() {
    return new Builder();
  }

  /**
   * A builder holding these settings, to derive a changed configuration.
   *
   * @return a new builder; this configuration is unchanged
   */
  public Builder toBuilder() {
    Builder b = source.copy();
    // The identity a renewal of this configuration made, not the one it was built with.
    Keys renewed = renewal == null ? null : renewal.renewedIdentity();
    if (renewed != null) {
      b.identity = renewed.managers();
      b.identityLeaf = renewed.leaf();
    }
    return b;
  }

  /**
   * The renewal of the client certificate, when {@link Builder#clientCertificateRenewal} set it.
   *
   * @return the renewal setting; empty without one
   * @since 0.10.0
   */
  public Optional<CertificateRenewal> clientCertificateRenewal() {
    return Optional.ofNullable(renewal == null ? null : renewal.options);
  }

  /**
   * The endpoints, in failover order.
   *
   * @return the endpoints, unmodifiable, never empty
   */
  public List<Endpoint> endpoints() {
    return endpoints;
  }

  /**
   * How the client authenticates.
   *
   * @return the authentication
   */
  public Authentication authentication() {
    return auth;
  }

  /**
   * The username for password authentication.
   *
   * @return the username; empty for {@link Authentication#CLIENT_CERTIFICATE}
   */
  public Optional<String> username() {
    return Optional.ofNullable(username);
  }

  /**
   * The lowest acceptable version, after adjustments (hashed passwords need KMIP 2.0).
   *
   * @return the lowest version
   */
  public KmipVersion minimumVersion() {
    return KmipVersion.of(versions.minimum());
  }

  /**
   * The highest version to offer.
   *
   * @return the highest version
   */
  public KmipVersion maximumVersion() {
    return KmipVersion.of(versions.maximum());
  }

  /**
   * The versions allowed explicitly; empty when every version in the range is.
   *
   * @return the versions, unmodifiable; empty when every version in the range is allowed
   */
  public Set<KmipVersion> allowedVersions() {
    Set<KmipVersion> out = EnumSet.noneOf(KmipVersion.class);
    for (ProtocolVersion v : versions.allowed()) out.add(KmipVersion.of(v));
    return Collections.unmodifiableSet(out);
  }

  /**
   * Protocol-layer view of the version policy.
   *
   * @return the version policy
   */
  public VersionPolicy protocolVersionPolicy() {
    return versions;
  }

  /**
   * Connections kept open per endpoint (0: one per call).
   *
   * @return the pool size
   */
  public int poolSize() {
    return poolSize;
  }

  /**
   * How long an idle pooled connection is kept.
   *
   * @return the idle timeout
   */
  public Duration idleTimeout() {
    return idleTimeout;
  }

  /**
   * How long a pooled connection may be idle before it is probed before reuse ({@link
   * Builder#validateAfterIdle}); never null.
   *
   * @return the idle time before a probe
   * @since 0.10.0
   */
  public Duration validateAfterIdle() {
    return validateAfterIdle;
  }

  /**
   * The TCP and TLS connection timeout.
   *
   * @return the connection timeout
   */
  public Duration connectTimeout() {
    return connectTimeout;
  }

  /**
   * The deadline of each call, and of {@link Kms#connect} across all endpoints.
   *
   * @return the call timeout
   */
  public Duration callTimeout() {
    return callTimeout;
  }

  /**
   * How long {@link Kms#connect} goes on trying a KMS it cannot reach ({@link
   * Builder#connectRetry(Duration)}); zero, the default, when it does not.
   *
   * @return how long {@code connect} goes on trying; zero when it does not
   * @since 0.10.0
   */
  public Duration connectRetry() {
    return connectRetry;
  }

  /**
   * What the SDK does with a key that states a Lease Time ({@link Builder#leases}).
   *
   * @return the lease policy; {@link LeasePolicy#REQUIRE} unless set
   * @since 0.10.0
   */
  public LeasePolicy leases() {
    return leases;
  }

  /**
   * How read-only operations are retried.
   *
   * @return the retry policy
   */
  public RetryPolicy retryPolicy() {
    return retry;
  }

  /**
   * The listeners added ({@link Builder#addListener}), in the order they are called; empty when
   * none was added. The SDK's own logging, which runs before them, is not among them.
   *
   * @return the listeners, unmodifiable
   * @since 0.10.0
   */
  public List<KmsListener> listeners() {
    return added;
  }

  /**
   * Identifiers fetched per Locate request when paging.
   *
   * @return the page size
   */
  public int locatePageSize() {
    return pageSize;
  }

  /**
   * The most matches a Locate reads before KMIP 1.3, which cannot page.
   *
   * @return the limit
   */
  public int locateLimit() {
    return locateLimit;
  }

  /**
   * The longest a call waits for the hashed-password exchange lock of an endpoint.
   *
   * @return the longest wait
   */
  public Duration hashedPasswordLockWait() {
    return hashedPasswordLockWait;
  }

  /** Credentials are redacted. */
  @Override
  public String toString() {
    return "KmsConfig[endpoints="
        + endpoints
        + ", auth="
        + auth
        + ", versions="
        + versions.minimum()
        + ".."
        + versions.maximum()
        + ", pool="
        + poolSize
        + "]";
  }

  // ---- TLS contexts from files ----

  /**
   * A TLS context from PEM files, validated as {@link Builder#clientIdentityPem(Path, Path)} and
   * {@link Builder#trustPem} validate them: the client's certificate chain (leaf first), its
   * unencrypted PKCS#8 private key, which must match the first certificate, and the CA
   * certificates to trust. For a {@link Builder#tls(Supplier)} supplier that decides itself when to
   * reload; {@link Builder#reloadOnChange()} needs none. Reads the files; sends nothing.
   *
   * @param certificateChain the client's certificate chain, leaf first
   * @param privateKey the client's unencrypted PKCS#8 private key
   * @param trustPem the CA certificates to trust
   * @return a new TLS context
   * @throws IllegalArgumentException naming the file, as the builder methods, when a file cannot
   *     be read or used or the key does not match the certificate; never quoting key material
   */
  public static SSLContext sslContextFromPem(
      Path certificateChain, Path privateKey, Path trustPem) {
    Objects.requireNonNull(certificateChain, "certificateChain");
    Objects.requireNonNull(privateKey, "privateKey");
    Objects.requireNonNull(trustPem, "trustPem");
    return context(pemIdentity(certificateChain, privateKey, null), pemTrust(trustPem));
  }

  /**
   * A TLS context from PEM files, validated as {@link Builder#clientIdentityPem(Path, Path,
   * char[])} and {@link Builder#trustPem} validate them: as {@link #sslContextFromPem(Path, Path,
   * Path)}, with a private key that may be encrypted (at most {@value
   * Builder#MAX_PBE_ITERATIONS} PBE iterations). The password is used during this call only, so the
   * caller may erase its array afterwards.
   *
   * @param certificateChain the client's certificate chain, leaf first
   * @param privateKey the client's PKCS#8 private key, encrypted or not
   * @param keyPassword the private key's password; not kept
   * @param trustPem the CA certificates to trust
   * @return a new TLS context
   * @throws IllegalArgumentException as {@link Builder#clientIdentityPem(Path, Path, char[])} and
   *     {@link Builder#trustPem}
   */
  public static SSLContext sslContextFromPem(
      Path certificateChain, Path privateKey, char[] keyPassword, Path trustPem) {
    Objects.requireNonNull(certificateChain, "certificateChain");
    Objects.requireNonNull(privateKey, "privateKey");
    Objects.requireNonNull(keyPassword, "keyPassword");
    Objects.requireNonNull(trustPem, "trustPem");
    return context(pemIdentity(certificateChain, privateKey, keyPassword), pemTrust(trustPem));
  }

  /**
   * A TLS context from a PKCS#12 file holding exactly one private key and its certificate chain,
   * and a PEM file of CA certificates to trust, validated as {@link
   * Builder#clientIdentityKeyStore(Path, char[])} and {@link Builder#trustPem} validate them (a JKS
   * key store is refused: use {@link #sslContextFromKeyStores}). The password is used during this call only.
   *
   * @param pkcs12 the PKCS#12 file
   * @param password the file's password; not kept
   * @param trustPem the CA certificates to trust
   * @return a new TLS context
   * @throws IllegalArgumentException as {@link Builder#clientIdentityKeyStore(Path, char[])} and
   *     {@link Builder#trustPem}
   */
  public static SSLContext sslContextFromPkcs12(Path pkcs12, char[] password, Path trustPem) {
    Objects.requireNonNull(pkcs12, "pkcs12");
    Objects.requireNonNull(password, "password");
    Objects.requireNonNull(trustPem, "trustPem");
    return context(pkcs12Identity(pkcs12, password), pemTrust(trustPem));
  }

  /**
   * A TLS context from key store files: a JKS or PKCS#12 key store holding exactly one private key
   * and its certificate chain, and a JKS or PKCS#12 trust store, each told from its contents and
   * validated as {@link Builder#clientIdentityKeyStore(Path, char[])} and {@link
   * Builder#trustStore(Path, char[])} validate them. For a {@link Builder#tls(Supplier)} supplier
   * that decides itself when to reload. The passwords are used during this call only, so the
   * caller may erase its arrays afterwards.
   *
   * @param keyStore the client's JKS or PKCS#12 key store
   * @param keyStorePassword its password, also the key's; not kept
   * @param trustStore the JKS or PKCS#12 trust store
   * @param trustStorePassword its password; not kept
   * @return a new TLS context
   * @throws IllegalArgumentException as those builder methods, naming the file
   * @since 0.10.0
   */
  public static SSLContext sslContextFromKeyStores(
      Path keyStore, char[] keyStorePassword, Path trustStore, char[] trustStorePassword) {
    Objects.requireNonNull(keyStore, "keyStore");
    Objects.requireNonNull(keyStorePassword, "keyStorePassword");
    Objects.requireNonNull(trustStore, "trustStore");
    Objects.requireNonNull(trustStorePassword, "trustStorePassword");
    return context(
        keyStoreIdentity(keyStore, keyStorePassword), storeTrust(trustStore, trustStorePassword));
  }

  /**
   * The key managers for the one private key in a PKCS#12 file, after checking that the key signs
   * for the first certificate of its chain, as for PEM files ({@link PemIdentity#matches}).
   */
  static KeyManager[] pkcs12Identity(Path file, char[] password) {
    try {
      return pkcs12Identity(file, password, TlsFiles.WHOLE);
    } catch (IllegalArgumentException e) {
      throw Pem.plain(e);
    }
  }

  /** {@link #pkcs12Identity(Path, char[])}, the file read once by {@code reader}. */
  static KeyManager[] pkcs12Identity(Path file, char[] password, TlsFiles.Reader reader) {
    return KeyStoreFiles.identity(file, KeyStoreFiles.Type.PKCS12, password, reader);
  }

  /**
   * The key managers for the one private key in a JKS or PKCS#12 key store file, whichever it is,
   * checked as {@link #pkcs12Identity(Path, char[])}.
   */
  static KeyManager[] keyStoreIdentity(Path file, char[] password) {
    try {
      KeyStore store = KeyStoreFiles.read(file, null, password, TlsFiles.WHOLE, "key store");
      return keyManagers(store, password, file.toString(), file);
    } catch (IllegalArgumentException e) {
      throw Pem.plain(e);
    }
  }

  /** Trust managers for the trusted certificates of a JKS or PKCS#12 trust store file. */
  static TrustManager[] storeTrust(Path trustStore, char[] password) {
    try {
      return KeyStoreFiles.trust(trustStore, password, TlsFiles.WHOLE);
    } catch (IllegalArgumentException e) {
      throw Pem.plain(e);
    }
  }

  /** The key managers for a PEM chain and its PKCS#8 key, checked to match ({@link PemIdentity}). */
  static KeyManager[] pemIdentity(Path certificateChain, Path privateKey, char[] keyPassword) {
    try {
      return pemIdentity(certificateChain, privateKey, keyPassword, TlsFiles.WHOLE);
    } catch (IllegalArgumentException e) {
      throw Pem.plain(e);
    }
  }

  /** {@link #pemIdentity(Path, Path, char[])}, each file read once by {@code reader}. */
  static KeyManager[] pemIdentity(
      Path certificateChain, Path privateKey, char[] keyPassword, TlsFiles.Reader reader) {
    return pemIdentityKeys(certificateChain, privateKey, keyPassword, reader).managers();
  }

  /** {@link #pemIdentity(Path, Path, char[], TlsFiles.Reader)}, with the leaf certificate. */
  static Keys pemIdentityKeys(
      Path certificateChain, Path privateKey, char[] keyPassword, TlsFiles.Reader reader) {
    // PemIdentity checked that the key matches.
    return identityKeys(
        PemIdentity.keyStore(certificateChain, privateKey, keyPassword, reader),
        new char[0],
        privateKey.toString(),
        null);
  }

  /**
   * The key managers for the one private key entry of {@code store}. When {@code checked} is the
   * file the store was read from, the key must sign for the first certificate of its chain; a key
   * store the caller made ({@link Builder#clientIdentity(KeyStore, char[])}, perhaps backed by a
   * token) is used as given.
   */
  static KeyManager[] keyManagers(KeyStore store, char[] password, String source, Path checked) {
    return identityKeys(store, password, source, checked).managers();
  }

  /**
   * Key managers and the leaf certificate they present: the builder keeps the leaf beside them, so
   * nothing needs the alias names a key manager gives its entries, which depend on its algorithm
   * ({@code ssl.KeyManagerFactory.algorithm}: SunX509 or PKIX).
   *
   * @param leaf the first certificate of the chain; null when it is not an X.509 certificate
   */
  record Keys(KeyManager[] managers, X509Certificate leaf) {}

  /** {@link #keyManagers(KeyStore, char[], String, Path)}, with the leaf certificate. */
  static Keys identityKeys(KeyStore store, char[] password, String source, Path checked) {
    try {
      List<String> keys = new ArrayList<>();
      for (String alias : Collections.list(store.aliases()))
        if (store.isKeyEntry(alias)) keys.add(alias);
      if (keys.size() != 1)
        throw new IllegalArgumentException(
            source + " holds " + keys.size() + " private keys; exactly one is needed");
      Key key = store.getKey(keys.get(0), password);
      java.security.cert.Certificate[] chain = store.getCertificateChain(keys.get(0));
      if (checked != null) {
        if (!(key instanceof PrivateKey privateKey) || chain == null || chain.length == 0)
          throw new IllegalArgumentException(
              source + " holds a private key without its certificate chain");
        PublicKey leaf = chain[0].getPublicKey();
        if (!PemIdentity.matches(privateKey, leaf, checked))
          throw new IllegalArgumentException(
              "The private key in "
                  + source
                  + " ("
                  + privateKey.getAlgorithm()
                  + ") does not match the first certificate of its chain ("
                  + leaf.getAlgorithm()
                  + ")");
      }
      // In memory under no password, so the key managers keep no copy of the file's.
      char[] none = new char[0];
      KeyStore one = KeyStore.getInstance("PKCS12");
      one.load(null, null);
      one.setKeyEntry("identity", key, none, chain);
      KeyManagerFactory kmf =
          KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
      kmf.init(one, none);
      return new Keys(
          kmf.getKeyManagers(),
          chain != null && chain.length > 0 && chain[0] instanceof X509Certificate x ? x : null);
    } catch (IOException | GeneralSecurityException e) {
      throw new IllegalArgumentException(
          "Cannot use the private key in " + source + " (wrong password?)", e);
    }
  }

  /** The key managers for {@code key} and its {@code chain}, held in memory under no password. */
  static KeyManager[] keyManagers(PrivateKey key, List<X509Certificate> chain) {
    try {
      KeyStore store = KeyStore.getInstance("PKCS12");
      store.load(null, null);
      store.setKeyEntry(
          "identity", key, new char[0], chain.toArray(java.security.cert.Certificate[]::new));
      return keyManagers(store, new char[0], "the renewed identity", null);
    } catch (IOException | GeneralSecurityException e) {
      throw new IllegalArgumentException("Cannot use the renewed identity", e);
    }
  }

  /** Trust managers for the CA certificates in a PEM file. */
  static TrustManager[] pemTrust(Path caCertificates) {
    try {
      return pemTrust(caCertificates, TlsFiles.WHOLE);
    } catch (IllegalArgumentException e) {
      throw Pem.plain(e);
    }
  }

  /** {@link #pemTrust(Path)}, the file read once by {@code reader}. */
  static TrustManager[] pemTrust(Path caCertificates, TlsFiles.Reader reader) {
    try {
      KeyStore store = KeyStore.getInstance("PKCS12");
      store.load(null, null);
      int i = 0;
      for (X509Certificate c : PemIdentity.trustCertificates(caCertificates, reader))
        store.setCertificateEntry("ca-" + i++, c);
      return storeTrust(store);
    } catch (IOException | GeneralSecurityException e) {
      throw new IllegalArgumentException("Cannot use the CA certificates in " + caCertificates, e);
    }
  }

  /** Trust managers for the certificates in a key store. */
  static TrustManager[] storeTrust(KeyStore trustStore) {
    try {
      TrustManagerFactory tmf =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      tmf.init(trustStore);
      return tmf.getTrustManagers();
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("Cannot use the trust store", e);
    }
  }

  /** A TLS context; null trust managers trust the JDK's defaults. */
  static SSLContext context(KeyManager[] identity, TrustManager[] trust) {
    try {
      SSLContext context = SSLContext.getInstance("TLS");
      context.init(identity, trust, null);
      return context;
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("Cannot build the TLS context", e);
    }
  }

  /** Builder for {@link KmsConfig}; not thread-safe. */
  public static final class Builder {
    private final List<Endpoint> endpoints = new ArrayList<>();
    private SSLContext tls;
    private Supplier<SSLContext> tlsSource;
    private KeyManager[] identity;

    /**
     * The leaf certificate {@link #identity} presents, kept beside it; null when not known (a key
     * store given whose first certificate is not X.509).
     */
    private X509Certificate identityLeaf;

    /** Where {@link #identity} was read from; null for {@link #clientIdentity(KeyStore, char[])}. */
    TlsFiles.Identity identityFiles;

    private TrustManager[] trust;

    /**
     * The file {@link #trust} was read from; null for a key store or the system defaults.
     * Package-private for tests.
     */
    TlsFiles.Trust trustFile;

    private boolean systemTrust;

    /** How often {@link #reloadOnChange(Duration)} checks the files; null when it is not set. */
    private Duration reloadEvery;

    /** The renewal of the client certificate; null when it is not set. */
    private CertificateRenewal renewal;

    private Authentication auth = Authentication.CLIENT_CERTIFICATE;
    private String username;

    /**
     * Never shared (the setters and {@link #copy()} clone), so a replaced value is wiped.
     * Package-private for tests.
     */
    char[] password;

    private ProtocolVersion minimum = ProtocolVersion.V1_4, maximum;
    private Set<ProtocolVersion> allowed = Set.of();
    private VersionPolicy policy;
    private int poolSize = 4, pageSize = 100, locateLimit = 1000;
    private Duration idleTimeout = Duration.ofSeconds(30),
        connectTimeout = Duration.ofSeconds(10),
        callTimeout = Duration.ofSeconds(30),
        connectRetry = Duration.ZERO,
        validateAfterIdle = TlsTransport.DEFAULT_VALIDATE_AFTER_IDLE;
    private RetryPolicy retry = RetryPolicy.defaults();
    private LeasePolicy leases = LeasePolicy.REQUIRE;
    private final List<KmsListener> listeners = new ArrayList<>();
    private List<String> cipherSuites;
    private boolean kmipCipherSuites;
    private TransportFactory transport;
    private Duration hashedPasswordLockWait = Duration.ofSeconds(60);

    private Builder() {}

    private Builder copy() {
      Builder b = new Builder();
      b.endpoints.addAll(endpoints);
      b.tls = tls;
      b.tlsSource = tlsSource;
      b.identity = identity;
      b.identityLeaf = identityLeaf;
      b.identityFiles = identityFiles == null ? null : identityFiles.copy();
      b.trust = trust;
      b.trustFile = trustFile == null ? null : trustFile.copy();
      b.systemTrust = systemTrust;
      b.reloadEvery = reloadEvery;
      b.renewal = renewal;
      b.auth = auth;
      b.username = username;
      b.password = password == null ? null : password.clone();
      b.minimum = minimum;
      b.maximum = maximum;
      b.allowed = allowed;
      b.policy = policy;
      b.poolSize = poolSize;
      b.pageSize = pageSize;
      b.locateLimit = locateLimit;
      b.idleTimeout = idleTimeout;
      b.validateAfterIdle = validateAfterIdle;
      b.connectTimeout = connectTimeout;
      b.callTimeout = callTimeout;
      b.connectRetry = connectRetry;
      b.leases = leases;
      b.retry = retry;
      b.listeners.addAll(listeners);
      b.cipherSuites = cipherSuites;
      b.kmipCipherSuites = kmipCipherSuites;
      b.transport = transport;
      b.hashedPasswordLockWait = hashedPasswordLockWait;
      return b;
    }

    /**
     * The endpoints as {@code host:port} (port 5696 if omitted), in failover order, replacing any
     * set before. IPv6 addresses go in brackets: {@code [2001:db8::1]:5696}.
     *
     * @param hostPorts the endpoints, at least one for {@link #build()}
     * @return this builder
     */
    public Builder endpoints(String... hostPorts) {
      List<Endpoint> parsed = new ArrayList<>();
      for (String hp : hostPorts) parsed.add(parse(Objects.requireNonNull(hp, "endpoint")));
      endpoints.clear();
      endpoints.addAll(parsed);
      return this;
    }

    private static Endpoint parse(String hp) {
      try {
        if (hp.startsWith("[")) {
          int close = hp.indexOf(']');
          if (close < 0) throw new IllegalArgumentException("Invalid endpoint " + hp);
          String host = hp.substring(1, close), rest = hp.substring(close + 1);
          if (rest.isEmpty()) return new Endpoint(host, 5696);
          if (!rest.startsWith(":")) throw new IllegalArgumentException("Invalid endpoint " + hp);
          return new Endpoint(host, Integer.parseInt(rest.substring(1)));
        }
        int colon = hp.lastIndexOf(':');
        if (colon < 0) return new Endpoint(hp, 5696);
        if (hp.indexOf(':') != colon)
          throw new IllegalArgumentException("Put an IPv6 address in brackets: [" + hp + "]:5696");
        return new Endpoint(hp.substring(0, colon), Integer.parseInt(hp.substring(colon + 1)));
      } catch (NumberFormatException e) {
        throw new IllegalArgumentException("Invalid endpoint " + hp, e);
      }
    }

    /**
     * Adds an endpoint after the ones already set ({@link #endpoints(String...)} replaces them).
     *
     * @param host the host name or IP address
     * @param port the port, 1 to 65535
     * @return this builder
     */
    public Builder addEndpoint(String host, int port) {
      endpoints.add(new Endpoint(host, port));
      return this;
    }

    // ---- TLS ----

    /**
     * The client's TLS identity from a key store file, PKCS#12 or JKS (told from its contents, as
     * {@link #trustStore(Path, char[])} tells), holding exactly one private key and its
     * certificate chain, the key under the store's password ({@code keytool -keypasswd} changes a
     * JKS key's). The builder keeps its own copy of the password, for {@link #reloadOnChange()},
     * so the caller may erase its array once this returns; a configuration built without {@code
     * reloadOnChange()} keeps none.
     *
     * @param file the PKCS#12 or JKS key store
     * @param password the store's password, also the key's; copied
     * @return this builder
     * @throws IllegalArgumentException naming the file when it cannot be read or is not a whole
     *     PKCS#12 or JKS key store (a PEM file is refused with the method that reads it), the
     *     password is wrong, it holds no key or several, or the key does not match the first
     *     certificate of its chain (checked as for {@link #clientIdentityPem(Path, Path)})
     * @since 0.10.0
     */
    public Builder clientIdentityKeyStore(Path file, char[] password) {
      Objects.requireNonNull(password, "password");
      return storeIdentity(file, TlsFiles.Password.copyOf(password));
    }

    /**
     * {@link #clientIdentityKeyStore(Path, char[])} with the password from {@code password}, asked
     * each time the file is read: now, and at each reload ({@link #reloadOnChange()}). Neither the
     * builder nor the configuration holds a copy. Each array the supplier returns is wiped after
     * that read, so return a new one each time: the same array returned twice is refused. The
     * supplier is called on the thread that reads the file (with {@code reloadOnChange}, a
     * request's), so it must be thread-safe and quick, and a failure it throws fails that read
     * with a message naming the file, not the supplier's message.
     *
     * @param file the PKCS#12 or JKS key store
     * @param password the store's password, a new array at each call
     * @return this builder
     * @throws IllegalArgumentException as {@link #clientIdentityKeyStore(Path, char[])}, and when
     *     the supplier throws, returns null or returns the array it returned before
     * @since 0.10.0
     */
    public Builder clientIdentityKeyStore(Path file, Supplier<char[]> password) {
      Objects.requireNonNull(password, "password");
      return storeIdentity(file, TlsFiles.Password.from(password));
    }

    private Builder storeIdentity(Path file, TlsFiles.Password password) {
      Objects.requireNonNull(file, "file");
      TlsFiles.Identity files =
          new TlsFiles.Identity(
              TlsFiles.IdentityKind.KEY_STORE, file, null, null, password, TlsFiles.stamps(file));
      Keys loaded;
      try {
        RenewalFiles.finishBeforeLoad(files);
        loaded = files.loadKeys(TlsFiles.WHOLE);
      } catch (IllegalArgumentException e) {
        files.wipe();
        throw Pem.plain(e);
      }
      return identity(loaded, files);
    }

    /**
     * The client's TLS identity from PEM files: the certificate chain (leaf first) and an
     * unencrypted PKCS#8 private key ({@code BEGIN PRIVATE KEY}). For an encrypted key use {@link
     * #clientIdentityPem(Path, Path, char[])}. Convert a legacy {@code BEGIN RSA PRIVATE KEY} or
     * {@code BEGIN EC PRIVATE KEY} file with {@code openssl pkcs8 -topk8}. A file that holds both
     * the key and the chain is passed as both arguments, {@code clientIdentityPem(file, file)}, and
     * read once.
     *
     * @param certificateChain the certificate chain file, leaf first
     * @param privateKey the private key file; may be the same file as {@code certificateChain}
     * @return this builder
     * @throws IllegalArgumentException when a file cannot be read or is not a whole PEM file (see
     *     {@link #trustPem}), holds no certificate or no PKCS#8 private key, the key is encrypted,
     *     malformed or not RSA, RSASSA-PSS, EC, Ed25519 or Ed448, or the key does not sign a random
     *     challenge that the first certificate's key verifies
     */
    public Builder clientIdentityPem(Path certificateChain, Path privateKey) {
      return pemFiles(certificateChain, privateKey, null);
    }

    /**
     * The client's TLS identity from PEM files: the certificate chain (leaf first) and a PKCS#8
     * private key, encrypted ({@code BEGIN ENCRYPTED PRIVATE KEY}, decrypted with {@code
     * keyPassword}) or not ({@code keyPassword} is then unused). PBES2 (OpenSSL's default) and the
     * PBES1 schemes the JDK provides are supported, with at most {@value #MAX_PBE_ITERATIONS}
     * key-derivation iterations, so a hostile file cannot make this call derive for minutes. JDK 17
     * and 21 accept only printable ASCII passwords for them. The builder keeps its own copy of the
     * password, for {@link #reloadOnChange()}, so the caller may erase its array once this returns.
     * A configuration built without {@code reloadOnChange()} keeps none. The derived key and the
     * decrypted key bytes are wiped after use, as far as Java allows.
     *
     * @param certificateChain the certificate chain file, leaf first
     * @param privateKey the private key file; may be the same file as {@code certificateChain}
     * @param keyPassword the private key's password; copied
     * @return this builder
     * @throws IllegalArgumentException as {@link #clientIdentityPem(Path, Path)}, and when the
     *     password is wrong, the encryption scheme is not supported, or the file asks for more than
     *     {@value #MAX_PBE_ITERATIONS} iterations
     */
    public Builder clientIdentityPem(Path certificateChain, Path privateKey, char[] keyPassword) {
      return pemIdentity(
          certificateChain, privateKey, Objects.requireNonNull(keyPassword, "keyPassword"));
    }

    /**
     * {@link #clientIdentityPem(Path, Path, char[])} with the key's password from {@code
     * keyPassword}, asked each time the key file is read: now, and at each reload ({@link
     * #reloadOnChange()}), as {@link #clientIdentityKeyStore(Path, Supplier)}. Neither the builder
     * nor the configuration holds a copy, and each array returned is wiped after that read.
     *
     * @param certificateChain the certificate chain file, leaf first
     * @param privateKey the private key file; may be the same file as {@code certificateChain}
     * @param keyPassword the private key's password, a new array at each call
     * @return this builder
     * @throws IllegalArgumentException as {@link #clientIdentityPem(Path, Path, char[])}, and when
     *     the supplier throws, returns null or returns the array it returned before
     */
    public Builder clientIdentityPem(
        Path certificateChain, Path privateKey, Supplier<char[]> keyPassword) {
      return pemFiles(
          certificateChain,
          privateKey,
          TlsFiles.Password.from(Objects.requireNonNull(keyPassword, "keyPassword")));
    }

    private Builder pemIdentity(Path certificateChain, Path privateKey, char[] keyPassword) {
      return pemFiles(
          certificateChain,
          privateKey,
          keyPassword == null ? null : TlsFiles.Password.copyOf(keyPassword));
    }

    private Builder pemFiles(
        Path certificateChain, Path privateKey, TlsFiles.Password keyPassword) {
      Objects.requireNonNull(certificateChain, "certificateChain");
      Objects.requireNonNull(privateKey, "privateKey");
      List<TlsFiles.Stamp> read =
          TlsFiles.stamps(
              TlsFiles.Identity.pemFiles(certificateChain, privateKey).toArray(Path[]::new));
      TlsFiles.Identity files =
          new TlsFiles.Identity(
              TlsFiles.IdentityKind.PEM, null, certificateChain, privateKey, keyPassword, read);
      Keys loaded;
      try {
        RenewalFiles.finishBeforeLoad(files);
        loaded = files.loadKeys(TlsFiles.WHOLE);
      } catch (IllegalArgumentException e) {
        files.wipe();
        throw Pem.plain(e);
      }
      return identity(loaded, files);
    }

    /**
     * The client's TLS identity from a key store holding exactly one private key entry. The key
     * store is used as given: unlike the identities read from files, the key is not checked
     * against its certificate (the store may be backed by a token).
     *
     * @param keyStore the key store
     * @param password the key's password
     * @return this builder
     */
    public Builder clientIdentity(KeyStore keyStore, char[] password) {
      return identity(
          identityKeys(
              Objects.requireNonNull(keyStore, "keyStore"),
              Objects.requireNonNull(password, "password"),
              "the key store",
              null),
          null);
    }

    /** Sets the identity and where it was read from, wiping the password of the one it replaces. */
    private Builder identity(Keys loaded, TlsFiles.Identity files) {
      if (identityFiles != null) identityFiles.wipe();
      identity = loaded.managers();
      identityLeaf = loaded.leaf();
      identityFiles = files;
      return this;
    }

    /**
     * Trust the CA certificates in a PEM file: one or more {@code BEGIN CERTIFICATE} blocks, or DER
     * certificates back to back. Text before and between the blocks, such as a bundle's comments,
     * is ignored.
     *
     * <p>The file must be whole, read the same on every JDK. Each block needs its END line and
     * complete Base64, and only whitespace may follow the last END line. A block of another kind,
     * such as OpenSSL's {@code TRUSTED CERTIFICATE} or {@code PKCS7}, is refused with the openssl
     * command that converts it. Client chain files ({@link #clientIdentityPem(Path, Path)}) are
     * read the same way.
     *
     * @param caCertificates the PEM file
     * @return this builder
     * @throws IllegalArgumentException naming the file (and the line), when it cannot be read, holds
     *     no certificate or is not whole as above
     */
    public Builder trustPem(Path caCertificates) {
      Objects.requireNonNull(caCertificates, "caCertificates");
      List<TlsFiles.Stamp> read = TlsFiles.stamps(caCertificates);
      return trust(pemTrust(caCertificates), new TlsFiles.Trust(caCertificates, null, read));
    }

    /**
     * Trust the certificates in a key store (for example a JKS or PKCS#12 trust store). For a trust
     * store file, {@link #trustStore(Path, char[])} reads it, validates it and, with {@link
     * #reloadOnChange()}, reads it again when it changes.
     *
     * @param trustStore the trust store
     * @return this builder
     */
    public Builder trustStore(KeyStore trustStore) {
      return trust(storeTrust(Objects.requireNonNull(trustStore, "trustStore")), null);
    }

    /**
     * Trust the certificates of a JKS or PKCS#12 trust store file: its trusted certificate entries
     * ({@code keytool -importcert} makes them), at least one. Its private key entries, if any, are
     * not trusted. The format is told from the file's contents, never its name; a JCEKS store or a
     * PEM file is refused with what to use instead. The file must be whole, as for {@link
     * #trustPem}, and is read again when it changes with {@link #reloadOnChange()}. The builder
     * keeps its own copy of the password, for {@code reloadOnChange()}, so the caller may erase its
     * array once this returns; a configuration built without {@code reloadOnChange()} keeps none.
     *
     * <p>The password checks the file's integrity. A PKCS#12 file made by openssl marks no
     * certificate trusted for Java: make the trust store with {@code keytool -importcert}, or use
     * {@link #trustPem} with the certificates.
     *
     * @param file the JKS or PKCS#12 trust store
     * @param password the store's password, which checks its integrity, so never null (the JDK's
     *     {@code cacerts} has {@code changeit}); copied
     * @return this builder
     * @throws IllegalArgumentException naming the file when it cannot be read, is not a whole JKS
     *     or PKCS#12 key store, the password is wrong, or it holds no trusted certificate entry
     */
    public Builder trustStore(Path file, char[] password) {
      Objects.requireNonNull(password, "password");
      return trustStoreFile(file, TlsFiles.Password.copyOf(password));
    }

    /**
     * {@link #trustStore(Path, char[])} with the password from {@code password}, asked each time
     * the file is read: now, and at each reload ({@link #reloadOnChange()}), as {@link
     * #clientIdentityKeyStore(Path, Supplier)}. Neither the builder nor the configuration holds a
     * copy, and each array returned is wiped after that read.
     *
     * @param file the JKS or PKCS#12 trust store
     * @param password the store's password, a new array at each call
     * @return this builder
     * @throws IllegalArgumentException as {@link #trustStore(Path, char[])}, and when the supplier
     *     throws, returns null or returns the array it returned before
     */
    public Builder trustStore(Path file, Supplier<char[]> password) {
      Objects.requireNonNull(password, "password");
      return trustStoreFile(file, TlsFiles.Password.from(password));
    }

    private Builder trustStoreFile(Path file, TlsFiles.Password password) {
      Objects.requireNonNull(file, "file");
      TlsFiles.Trust files = new TlsFiles.Trust(file, password, TlsFiles.stamps(file));
      TrustManager[] loaded;
      try {
        loaded = files.load(TlsFiles.WHOLE);
      } catch (IllegalArgumentException e) {
        files.wipe();
        throw Pem.plain(e);
      }
      return trust(loaded, files);
    }

    /**
     * Trust the JDK's default CA certificates (the {@code cacerts} store, public CAs). A KMS usually
     * has a private CA: prefer {@link #trustPem} or {@link #trustStore}. Some trust choice is
     * required with a client identity.
     *
     * @return this builder
     */
    public Builder trustSystemDefaults() {
      trust(null, null);
      systemTrust = true;
      return this;
    }

    /** Sets the trust and the file it was read from, wiping the password of the one it replaces. */
    private Builder trust(TrustManager[] loaded, TlsFiles.Trust file) {
      if (trustFile != null) trustFile.wipe();
      trust = loaded;
      systemTrust = false;
      trustFile = file;
      return this;
    }

    /**
     * Re-read the TLS files when they change, checking at most once a second: {@link
     * #reloadOnChange(Duration)} with one second.
     *
     * @return this builder
     */
    public Builder reloadOnChange() {
      return reloadOnChange(Duration.ofSeconds(1));
    }

    /**
     * Re-read the TLS files when they change, for short-lived client certificates (for example
     * from cert-manager or SPIFFE) and rotated trust bundles. The files of {@link
     * #clientIdentityPem}, {@link #clientIdentityKeyStore(Path, char[])}, {@link
     * #trustPem} and {@link #trustStore(Path, char[])} are watched, whichever are set. Settings not
     * read from files, such as {@link #trustStore(KeyStore)}, stay as they are.
     *
     * <p>Before a request is sent, at most once per {@code checkEvery}, the calling thread checks
     * each file's modification time, size and file key. No thread is started, and other threads
     * never wait. Once a changed file has stayed unchanged for {@code checkEvery}, the whole TLS
     * context is built again, at most 1 MiB per file, with the builder methods' validation. When it
     * loads, {@link KmsListener#credentialsReloaded} is called and new connections use it, as with
     * {@link #tls(Supplier)}. When it does not, the previous context stays in use and {@link
     * KmsListener#credentialsReloadFailed} is called, or {@link
     * KmsListener#credentialsStillChanging} while a writer is not done.
     *
     * <p>Publish the files atomically: write each under another name and rename it into place, or
     * swap a directory, as Kubernetes secret volumes do. A file rewritten in place within one
     * timestamp tick at the same size is not seen. The configuration keeps its own copy of each
     * file password given as a {@code char[]}, for its life. A configuration built without
     * this keeps no file names, so on a builder from {@link KmsConfig#toBuilder()} name the files
     * again first. See <a
     * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/production.md#reload-client-credentials">Reload
     * client credentials</a>.
     *
     * @param checkEvery the least time between two checks of the files, positive
     * @return this builder
     * @throws IllegalArgumentException when {@code checkEvery} is not positive; {@link #build()}
     *     throws it when no TLS setting is read from a file, or with {@link #tls(SSLContext)},
     *     {@link #tls(Supplier)} or {@link #transport}
     */
    public Builder reloadOnChange(Duration checkEvery) {
      reloadEvery = positive(Objects.requireNonNull(checkEvery, "checkEvery"));
      return this;
    }

    /**
     * Renew the client certificate through KMIP Re-Provision (KMIP 2.0 and later): on demand with
     * {@link Kms#renewClientCertificate()}, and with {@link CertificateRenewal#automatic} also
     * before it expires. The default is no renewal.
     *
     * <p>The identity must be read from files the SDK can rewrite: {@link #clientIdentityPem} or
     * {@link #clientIdentityKeyStore}. A renewal replaces those files (the same paths), so {@link
     * #reloadOnChange()} and later starts use the new certificate, and every {@link Kms} of this
     * configuration uses it at once, with or without {@code reloadOnChange}. The configuration
     * keeps the file names and its own copy of a password given as a {@code char[]} for its life,
     * as {@code reloadOnChange} does. The server must offer Re-Provision (keytend-kmip-server with
     * a provisioning CA) and refuses the old certificate on new connections once it issues the new
     * one: see <a
     * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/production.md#renew-the-client-certificate">Renew
     * the client certificate</a>.
     *
     * <p>When an earlier renewal's certificate was issued and saved but its files were not all
     * switched (the process stopped between them), the identity methods above finish the switch
     * before they read the files. When a renewal in this process issued a certificate that it
     * could not write to the files ({@link RenewalNotSavedException}), a configuration of the same
     * files built later in the process uses that certificate, not the retired one the files hold.
     *
     * @param renewal how to renew; replaces a renewal set before
     * @return this builder
     * @throws NullPointerException when {@code renewal} is null; {@link #build()} throws {@link
     *     IllegalArgumentException} when the identity is not read from files ({@link
     *     #clientIdentity(KeyStore, char[])}, {@link #tls(SSLContext)}, {@link #tls(Supplier)}),
     *     with a {@link #transport}, or with several endpoints unless {@link
     *     CertificateRenewal#endpointsShareOneStore()}
     * @since 0.10.0
     */
    public Builder clientCertificateRenewal(CertificateRenewal renewal) {
      this.renewal = Objects.requireNonNull(renewal, "renewal");
      return this;
    }

    /**
     * Expert: a ready-made TLS context (trust anchors and, for certificate authentication, the
     * client identity), instead of the other TLS options; {@link #build()} refuses both. Replaces
     * a {@link #tls(Supplier)} set before. The context is used for the life of the {@link Kms}:
     * for credentials that change, use {@link #reloadOnChange()} or {@link #tls(Supplier)}.
     *
     * @param context the TLS context
     * @return this builder
     */
    public Builder tls(SSLContext context) {
      tls = Objects.requireNonNull(context, "tls");
      tlsSource = null;
      return this;
    }

    /**
     * Expert: TLS contexts that change over time, instead of the other TLS options; {@link
     * #build()} refuses both. Replaces a {@link #tls(SSLContext)} set before. For PEM or PKCS#12
     * files, {@link #reloadOnChange()} does this without a supplier of your own. A supplier can
     * build each context with {@link KmsConfig#sslContextFromPem(Path, Path, Path)} or {@link
     * KmsConfig#sslContextFromPkcs12}, which validate as the builder does.
     *
     * <p>{@code source} is called before each request is sent, on the calling thread, with no SDK
     * lock held, so it must be thread-safe and quick. A pooled connection is reused only while
     * {@code source} returns the instance that opened it. Return the same instance until the
     * credentials change, because a new instance on every call disables pooling. After a change,
     * new requests open new connections, idle old ones are closed when next taken, and busy ones
     * after their request.
     *
     * <p>When {@code source} throws a {@code RuntimeException} or returns null, that attempt fails
     * before anything is sent, with a {@link TransientException}. It is retried like any transient
     * failure of a read, and is never an {@link OutcomeUnknownException}. While new certificate
     * files are only partly written, return the previous context rather than throw.
     *
     * @param source the TLS contexts; called before each request
     * @return this builder
     */
    public Builder tls(Supplier<SSLContext> source) {
      tlsSource = Objects.requireNonNull(source, "tls");
      tls = null;
      return this;
    }

    /**
     * The most PBE key-derivation iterations an encrypted PKCS#8 key may ask for. The count comes
     * from the file; ten million is several seconds of PBKDF2 and far above common settings
     * (OpenSSL 2048, current PBKDF2-HMAC-SHA256 guidance about 600 000).
     */
    public static final int MAX_PBE_ITERATIONS = 10_000_000;

    // ---- authentication ----

    /**
     * Authenticate with the TLS client certificate only (the default). Without {@link #tls} or a
     * {@link #transport}, {@link #build()} then requires a client identity ({@code
     * clientIdentityKeyStore}, {@code clientIdentityPem} or {@code
     * clientIdentity}). Discards (and
     * wipes) a password set before.
     *
     * @return this builder
     */
    public Builder clientCertificate() {
      auth = Authentication.CLIENT_CERTIFICATE;
      username = null;
      replacePassword(null);
      return this;
    }

    /**
     * Send a username/password Credential with every request, in addition to TLS. A client identity
     * is optional: with only a trust choice, TLS authenticates the server and the Credential the
     * client (when the server accepts that; many require mutual TLS as well). KMIP carries the
     * password as text, so it lives as a {@code String} for the life of the {@link Kms}. The
     * builder keeps its own copy, so the caller may erase its array once this returns.
     *
     * @param user the username
     * @param secret the password; copied
     * @return this builder
     */
    public Builder usernamePassword(String user, char[] secret) {
      Objects.requireNonNull(secret, "password");
      auth = Authentication.PASSWORD;
      username = Objects.requireNonNull(user, "user");
      replacePassword(secret.clone());
      return this;
    }

    /**
     * KMIP 2.0+ hashed-password credentials with server-proof verification. Raises the minimum
     * version to 2.0. Exchanges per endpoint are serialized, so the pool size has no effect; a call
     * waits for its turn at most {@link #hashedPasswordLockWait} or until its own deadline, whichever
     * is earlier. A client identity is optional, as with {@link #usernamePassword}. The builder keeps
     * its own copy of the password, so the caller may erase its array once this returns.
     *
     * @param user the username
     * @param secret the password; copied
     * @return this builder
     */
    public Builder hashedPassword(String user, char[] secret) {
      Objects.requireNonNull(secret, "password");
      auth = Authentication.HASHED_PASSWORD;
      username = Objects.requireNonNull(user, "user");
      replacePassword(secret.clone());
      return this;
    }

    /**
     * The longest a call waits for an endpoint's hashed-password exchange lock (default 60 s); the
     * call's own deadline ({@link #callTimeout}, {@link Kms#withTimeout}) ends the wait earlier when
     * it is sooner. A call that gives up waiting was not sent and fails with a {@link
     * TransientException}. Used only with {@link #hashedPassword}; see {@link
     * HashedPasswordTransport}.
     *
     * @param maxWait the longest wait, positive
     * @return this builder
     */
    public Builder hashedPasswordLockWait(Duration maxWait) {
      hashedPasswordLockWait = positive(Objects.requireNonNull(maxWait, "maxWait"));
      return this;
    }

    /** Wipes the builder's own copy before letting go of it: no one else holds it. */
    private void replacePassword(char[] secret) {
      if (password != null) Arrays.fill(password, '\0');
      password = secret;
    }

    // ---- versions ----

    /**
     * The lowest acceptable version (default 1.4, the first with authenticated encryption, so that
     * {@link CipherSpec#aesGcm()} works on every server the default accepts). Lower it to reach older
     * servers; AEAD then fails with {@link UnsupportedException} before anything is sent.
     *
     * @param v the lowest version
     * @return this builder
     */
    public Builder minimumVersion(KmipVersion v) {
      minimum = Objects.requireNonNull(v, "version").protocolValue();
      policy = null;
      return this;
    }

    /**
     * The highest version to offer (default 2.1, or the minimum if that is higher; set 3.0 to allow
     * the 3.0 draft).
     *
     * @param v the highest version
     * @return this builder
     */
    public Builder maximumVersion(KmipVersion v) {
      maximum = Objects.requireNonNull(v, "version").protocolValue();
      policy = null;
      return this;
    }

    /**
     * Only these versions are acceptable.
     *
     * @param v the versions
     * @return this builder
     */
    public Builder versions(KmipVersion... v) {
      Set<ProtocolVersion> s = new HashSet<>();
      for (KmipVersion k : v) s.add(k.protocolValue());
      allowed = Set.copyOf(s);
      policy = null;
      return this;
    }

    /**
     * Protocol-layer escape hatch: the whole version policy.
     *
     * @param p the version policy
     * @return this builder
     */
    public Builder protocolVersionPolicy(VersionPolicy p) {
      policy = Objects.requireNonNull(p);
      return this;
    }

    // ---- connections and calls ----

    /**
     * Connections kept open per endpoint (default 4; 0 opens one per call).
     *
     * @param size the number of connections, not negative
     * @return this builder
     */
    public Builder poolSize(int size) {
      if (size < 0) throw new IllegalArgumentException("Invalid pool size");
      poolSize = size;
      return this;
    }

    /**
     * How long an idle pooled connection is kept (default 30 s).
     *
     * @param d the idle timeout, positive
     * @return this builder
     */
    public Builder idleTimeout(Duration d) {
      idleTimeout = positive(d);
      return this;
    }

    /**
     * How long a pooled connection may sit idle before it is probed before reuse (default 2 s,
     * {@link TlsTransport#DEFAULT_VALIDATE_AFTER_IDLE}). The probe is a read that waits 1 ms. A
     * connection used more recently is checked without waiting, which still sees a close that has
     * arrived. A connection found closed is discarded and the request goes on a new one, so a
     * connection the server closed while idle does not fail the call. {@link Duration#ZERO} probes
     * before every reuse, which adds about 1 ms to every pooled request. Only for the built-in TLS
     * transport.
     *
     * @param idle the idle time before a probe
     * @return this builder
     * @throws IllegalArgumentException when {@code idle} is negative
     * @since 0.10.0
     */
    public Builder validateAfterIdle(Duration idle) {
      Objects.requireNonNull(idle, "validateAfterIdle");
      if (idle.isNegative())
        throw new IllegalArgumentException("validateAfterIdle must not be negative: " + idle);
      validateAfterIdle = idle;
      return this;
    }

    /**
     * The TCP and TLS connection timeout (default 10 s): opening one connection, the TCP connect and
     * the TLS handshake together, ends after this long. A call's own deadline can end it sooner.
     *
     * @param d the connection timeout, positive
     * @return this builder
     */
    public Builder connectTimeout(Duration d) {
      connectTimeout = positive(d);
      return this;
    }

    /**
     * The deadline of each call, across every attempt and back-off and including waiting for a
     * pooled connection (default 30 s), and of {@link Kms#connect} across all endpoints. {@link
     * Kms#withTimeout} overrides it per call site. With several endpoints, an attempt of a read
     * waits at most the {@link RetryPolicy#attemptTimeout() attempt timeout}, so a replica that
     * hangs leaves time for the next one.
     *
     * @param d the call timeout, positive
     * @return this builder
     */
    public Builder callTimeout(Duration d) {
      callTimeout = positive(d);
      return this;
    }

    /**
     * Lets {@link Kms#connect} wait up to {@code d} for a KMS that cannot be reached yet, for an
     * application that may start while the KMS is briefly down. The default, zero, makes one
     * attempt.
     *
     * <p>A connect that fails with a {@link TransientException} (no endpoint reachable, timeouts,
     * refused connections) is made again after the {@link #retryPolicy} back-off, at least 100 ms.
     * Each attempt has a call timeout of its own, and a new one starts only within {@code d} of the
     * first, so connect takes at most about {@code d} plus one call timeout. The last failure is
     * thrown, with up to 16 earlier ones suppressed on it. Configuration, authentication, access
     * and version failures, and an interrupted thread, still fail at once.
     *
     * <pre>{@code
     * KmsConfig config = KmsConfig.builder()
     *     .endpoints("kms1:5696", "kms2:5696")
     *     .clientIdentityKeyStore(Path.of("client.p12"), password)
     *     .trustPem(Path.of("ca.pem"))
     *     .connectRetry(Duration.ofMinutes(2))
     *     .build();
     * }</pre>
     *
     * @param d how long to go on trying, not negative; zero for one attempt
     * @return this builder
     * @throws IllegalArgumentException when {@code d} is negative
     * @since 0.10.0
     */
    public Builder connectRetry(Duration d) {
      Objects.requireNonNull(d, "connectRetry");
      if (d.isNegative())
        throw new IllegalArgumentException("connectRetry must not be negative: " + d);
      connectRetry = d;
      return this;
    }

    /**
     * What the SDK requires before it hands out the material of a key whose attributes state a
     * KMIP Lease Time ({@code asSecretKey}, {@code asPrivateKey}, {@code asSecretData}, {@link
     * LocalKeys}, the TLS followers). The default, {@link LeasePolicy#REQUIRE}, needs a lease the
     * server granted. {@link LeasePolicy#HONOR_IF_SUPPORTED} lets a server that does not
     * implement Obtain Lease be used under the stated Lease Time instead. Set it only for such a
     * server, after qualifying it. See <a
     * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/local-keys.md#leases">Leases</a>.
     *
     * @param policy the lease policy; not null
     * @return this builder
     * @since 0.10.0
     */
    public Builder leases(LeasePolicy policy) {
      leases = Objects.requireNonNull(policy, "leases");
      return this;
    }

    /**
     * How read-only operations are retried after a {@link TransientException}, and how long an
     * endpoint that refused a connection is skipped (default {@link RetryPolicy#defaults()}: 3
     * attempts, 100 ms back-off doubling up to 2 s, 5 s cool-down, attempt timeout the call timeout
     * divided by the attempts). Every attempt and back-off stays within the call's deadline ({@link
     * #callTimeout}); mutations are never re-sent, whatever the policy. {@link RetryPolicy#none()}
     * makes one attempt per call.
     *
     * @param policy the retry policy
     * @return this builder
     */
    public Builder retryPolicy(RetryPolicy policy) {
      retry = Objects.requireNonNull(policy, "policy");
      return this;
    }

    /**
     * Adds {@code l} after the listeners added so far (default: none). A listener receives an event
     * as each call and attempt starts and finishes, before each retry, when an endpoint goes down
     * or comes back, and for the other {@link KmsListener} events, for metrics, tracing or alerts.
     * Each is called in turn, isolated from the others, on the calling thread, so keep them quick;
     * what one throws, an {@link Error} included, is ignored. An application listener and a metrics
     * adapter can so run together. The SDK's own logging runs whatever the listeners. A listener
     * added twice (also inside a {@link KmsListener#all}) hears each event once. Events carry
     * identifiers and outcomes, never key material.
     *
     * @param l the listener
     * @return this builder
     * @since 0.10.0
     */
    public Builder addListener(KmsListener l) {
      listeners.add(Objects.requireNonNull(l, "listener"));
      return this;
    }

    /**
     * Restrict TLS to the KMIP Profiles cipher suites ({@link
     * dev.keytend.kmip.transport.Tls#KMIP_CIPHER_SUITES}) that this JDK enables. Connecting fails
     * when it enables none of them. Cannot be combined with {@link #cipherSuites}.
     *
     * @return this builder
     */
    public Builder kmipCipherSuites() {
      kmipCipherSuites = true;
      return this;
    }

    /**
     * Restrict TLS to these cipher suites (JSSE names, in preference order) instead of the JDK's
     * defaults, which are used when neither this nor {@link #kmipCipherSuites()} is set. Suites the
     * JDK has disabled stay disabled. Applies to the built-in TLS transport, with {@link #tls} too;
     * a custom {@link #transport} ignores it. {@link #build()} refuses it together with {@link
     * #kmipCipherSuites()}.
     *
     * @param suites the cipher suites, in preference order, not empty; copied
     * @return this builder
     * @throws IllegalArgumentException when {@code suites} is empty
     */
    public Builder cipherSuites(List<String> suites) {
      List<String> copy = List.copyOf(suites);
      if (copy.isEmpty()) throw new IllegalArgumentException("No cipher suites");
      cipherSuites = copy;
      return this;
    }

    /**
     * A custom transport per endpoint (HTTPS, a test double); TLS settings are then optional.
     *
     * @param factory the transport factory
     * @return this builder
     */
    public Builder transport(TransportFactory factory) {
      transport = Objects.requireNonNull(factory);
      return this;
    }

    /**
     * Identifiers fetched per Locate request when paging (KMIP 1.3+; default 100).
     *
     * @param size the page size, positive
     * @return this builder
     */
    public Builder locatePageSize(int size) {
      if (size < 1) throw new IllegalArgumentException("Invalid page size");
      pageSize = size;
      return this;
    }

    /**
     * Before KMIP 1.3 a Locate cannot page: at most this many matches are read (default 1000), and
     * more fail with {@link UnsupportedException}.
     *
     * @param limit the limit, positive
     * @return this builder
     */
    public Builder locateLimit(int limit) {
      if (limit < 1) throw new IllegalArgumentException("Invalid limit");
      locateLimit = limit;
      return this;
    }

    private VersionPolicy policy() {
      if (policy != null) return policy;
      ProtocolVersion max =
          maximum != null
              ? maximum
              : minimum.atLeast(ProtocolVersion.V2_1) ? minimum : ProtocolVersion.V2_1;
      return new VersionPolicy(minimum, max, allowed);
    }

    private static Duration positive(Duration d) {
      if (d.isNegative() || d.isZero())
        throw new IllegalArgumentException("Duration must be positive");
      return d;
    }

    /**
     * Builds an immutable configuration. The builder is unchanged and can build again or be changed
     * further. A later change to the builder does not reach a configuration already built.
     *
     * @return the configuration
     * @throws IllegalArgumentException when no endpoint is set; no TLS setting and no transport is
     *     set; {@code tls(SSLContext)} or {@code tls(Supplier)} is combined with {@code
     *     clientIdentity*}/{@code trust*}; a client identity has no trust choice; certificate
     *     authentication (the default) has a trust choice but no client identity (without {@code
     *     tls(...)} or a transport, which cannot be inspected); {@code cipherSuites} is combined with {@code
     *     kmipCipherSuites}; {@code reloadOnChange} is set without a TLS setting read from a file
     *     ({@code clientIdentityPem}, {@code clientIdentityKeyStore},
     *     {@code trustPem}, {@code trustStore(Path, ...)}), or with
     *     {@code tls(...)} or a transport; or the version settings are contradictory
     */
    public KmsConfig build() {
      if (endpoints.isEmpty()) throw new IllegalArgumentException("No endpoints");
      boolean pieces = identity != null || trust != null || systemTrust;
      if (tls != null && pieces)
        throw new IllegalArgumentException(
            "tls(SSLContext) and clientIdentity*/trust* both set: use one or the other");
      if (tlsSource != null && pieces)
        throw new IllegalArgumentException(
            "tls(Supplier) and clientIdentity*/trust* both set: use one or the other");
      if (identity != null && trust == null && !systemTrust)
        throw new IllegalArgumentException(
            "A client identity needs a trust choice: trustPem, trustStore or trustSystemDefaults");
      if (cipherSuites != null && kmipCipherSuites)
        throw new IllegalArgumentException(
            "cipherSuites(...) and kmipCipherSuites() both set: use one or the other");
      if (reloadEvery != null && transport != null)
        throw new IllegalArgumentException(
            "reloadOnChange() and transport(...) both set: a custom transport does not use the TLS settings");
      if (reloadEvery != null && identityFiles == null && trustFile == null)
        throw new IllegalArgumentException(
            "reloadOnChange() needs a TLS setting read from files (clientIdentityPem,"
                + " clientIdentityKeyStore, trustPem or trustStore(Path, ...));"
                + " there is nothing to watch"
                + (tls != null || tlsSource != null
                    ? " (a tls(...) context is not read from files)"
                    : ""));
      if (tls == null && tlsSource == null && transport == null) {
        if (!pieces)
          throw new IllegalArgumentException(
              "No TLS settings: set a trust choice (trustPem, trustStore, trustSystemDefaults) and, for"
                  + " certificate authentication, clientIdentityKeyStore or"
                  + " clientIdentityPem; or tls(...)");
        // The server would refuse the handshake (or the request) at connect: say so now.
        if (identity == null && auth == Authentication.CLIENT_CERTIFICATE)
          throw new IllegalArgumentException(
              "Certificate authentication needs a client identity: clientIdentityKeyStore,"
                  + " clientIdentityPem or clientIdentity; or authenticate with"
                  + " usernamePassword or"
                  + " hashedPassword");
      }
      if (renewal != null) {
        if (transport != null)
          throw new IllegalArgumentException(
              "clientCertificateRenewal(...) and transport(...) both set: renewal needs the SDK's"
                  + " TLS transport");
        if (identityFiles == null)
          throw new IllegalArgumentException(
              "clientCertificateRenewal(...) needs a client identity read from files the SDK can"
                  + " rewrite: clientIdentityPem or clientIdentityKeyStore; an identity given as"
                  + " tls(SSLContext), tls(Supplier) or clientIdentity(KeyStore, ...) cannot be"
                  + " renewed");
        if (endpoints.size() > 1 && !renewal.sharesOneStore())
          throw new IllegalArgumentException(
              "clientCertificateRenewal(...) with "
                  + endpoints.size()
                  + " endpoints: a renewal through one endpoint would leave the old certificate"
                  + " valid on the others, or the new one unknown there. Configure one endpoint,"
                  + " or state that they share one store with"
                  + " CertificateRenewal.endpointsShareOneStore()");
      }
      SSLContext context = tls;
      if (context == null && pieces) context = context(identity, trust);
      policy();
      return new KmsConfig(this, context);
    }
  }
}
