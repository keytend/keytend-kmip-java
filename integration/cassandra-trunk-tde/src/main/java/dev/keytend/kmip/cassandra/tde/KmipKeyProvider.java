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

package dev.keytend.kmip.cassandra.tde;

import dev.keytend.kmip.kms.CustomAttribute;
import dev.keytend.kmip.kms.Expect;
import dev.keytend.kmip.kms.KeyQuery;
import dev.keytend.kmip.kms.KmsException;
import dev.keytend.kmip.kms.LocalKeys;
import java.io.IOException;
import java.security.Key;
import java.time.Duration;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.cassandra.config.TransparentDataEncryptionOptions;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.security.KeyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Commit log and hints keys from a KMIP server, through the SDK's {@link LocalKeys}: the {@code
 * key_provider} of {@code transparent_data_encryption_options}. It needs the Cassandra patches of
 * this integration ({@code keysMayBeCached}, {@code keyForNewFile}, {@code keyForAppend}).
 *
 * <p>{@code key_alias} is the KMIP Name of an AES key. The operator rotates it ({@code KmipTool
 * key-rotate}: a KMIP Re-key moves the name to the new key), so the name alone cannot tell which
 * key encrypted a file. Each new commit log segment or hints file therefore records {@code
 * <name>#<unique identifier>} as its alias ({@link #keyForNewFile}), and is decrypted with exactly
 * that key later, whatever the name points to by then. Keys outside the scope (custom attribute
 * {@value #FAMILY} equal to {@code kmip_key_family}) are never used, whatever a file header names.
 *
 * <p>Keys are authorized for a limited time: the cache's TTL, and the key's KMIP lease where the
 * server states one. So {@link #keysMayBeCached()} is false: Cassandra asks for the key of each
 * file, and initializes the file's cipher with it at once. A segment or hints file still being
 * written asks for its own key again before each section or flush ({@link #keyForAppend}, the
 * SDK's {@link LocalKeys#forAppend}), which hands it out only while it may still encrypt (Active,
 * leased, in scope, before its protection deadline), whether or not it is still the write key.
 * Nothing here creates, rotates or retires a key. The gauges of {@link KmipMetrics} say how long
 * new files can still get their key without the KMS, and whether the write key's last validation
 * failed.
 *
 * <p>Parameters, besides the connection parameters of {@link KmipConnections}:
 *
 * <ul>
 *   <li>{@code key_bits}: AES key length; any AES length when absent;
 *   <li>{@code kmip_key_family}: the scope of the keys files may name, default {@code key_alias};
 *   <li>{@code key_cache_ttl}: how long a key is used without the KMS confirming it, default
 *       {@code 10m};
 *   <li>{@code key_cache_refresh}: when a used key is confirmed in the background, default half
 *       the TTL;
 *   <li>{@code key_cache_capacity}: keys kept, the write key included, default 64.
 * </ul>
 */
public class KmipKeyProvider implements KeyProvider {
  private static final Logger logger = LoggerFactory.getLogger(KmipKeyProvider.class);

  public static final String KEY_BITS = "key_bits";
  public static final String KEY_FAMILY = "kmip_key_family";
  public static final String CACHE_TTL = "key_cache_ttl";
  public static final String CACHE_REFRESH = "key_cache_refresh";
  public static final String CACHE_CAPACITY = "key_cache_capacity";

  /** The custom attribute naming the family a key belongs to ({@code x-cassandra-tde} on the wire). */
  public static final String FAMILY = "cassandra-tde";

  public static final CustomAttribute FAMILY_ATTRIBUTE = CustomAttribute.client(FAMILY);

  /** Separates the key's name from its unique identifier in a file's alias. */
  public static final char SEPARATOR = '#';

  /** One cache per configuration in the process, shared by every provider instance. */
  private static final Map<String, LocalKeys> caches = new ConcurrentHashMap<>();

  private final String name;
  private final LocalKeys keys;

  /** Made by Cassandra's {@code CipherFactory}, reflectively, with this constructor. */
  public KmipKeyProvider(TransparentDataEncryptionOptions options) {
    name = options.key_alias;
    if (name == null || name.isEmpty() || name.indexOf(SEPARATOR) >= 0)
      throw new ConfigurationException(
          "key_alias must be the KMIP name of the key, without '" + SEPARATOR + "': " + name);
    Map<String, String> parameters = options.key_provider.parameters;
    keys = caches.computeIfAbsent(name + '|' + parameters, ignored -> open(name, parameters));
  }

  private static LocalKeys open(String name, Map<String, String> parameters) {
    String bits = KmipConnections.get(parameters, KEY_BITS, null);
    Duration ttl = KmipConnections.duration(parameters, CACHE_TTL, "10m");
    String refresh = KmipConnections.get(parameters, CACHE_REFRESH, null);
    LocalKeys keys;
    try {
      LocalKeys.Builder builder =
          LocalKeys.builder(KmipConnections.config(parameters), name)
              .scope(scope(KmipConnections.get(parameters, KEY_FAMILY, name)))
              .expect(bits == null ? Expect.aes() : Expect.aes(Integer.parseInt(bits)))
              .ttl(ttl)
              .capacity(Integer.parseInt(KmipConnections.get(parameters, CACHE_CAPACITY, "64")));
      if (refresh != null) builder.refreshAfter(KmipConnections.duration(parameters, CACHE_REFRESH, refresh));
      keys = builder.open();
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new ConfigurationException(
          "Invalid KMIP key provider configuration for " + name + ": " + e.getMessage(), e);
    }
    KmipMetrics.register(name, keys);
    logger.info("KMIP keys for {}: TTL {}, refreshed after {}", name, keys.ttl(), keys.refreshAfter());
    return keys;
  }

  /** The scope of a key family: the keys whose custom attribute {@value #FAMILY} is {@code family}. */
  public static KeyQuery scope(String family) {
    return KeyQuery.all().custom(FAMILY_ATTRIBUTE, family);
  }

  @Override
  public boolean keysMayBeCached() {
    return false;
  }

  @Override
  public KeyForFile keyForNewFile(String configuredAlias) throws IOException {
    checkName(configuredAlias);
    try {
      // the key passes to the caller, which initializes the file's cipher with it and destroys it
      LocalKeys.Use use = keys.forEncrypt();
      return new KeyForFile(alias(name, use.id()), use.key());
    } catch (KmsException e) {
      throw new IOException("No KMIP key for new files under " + name + " (" + KmipConnections.describe(e) + ')', e);
    }
  }

  /** The key of a segment or hints file still being written, only while it may still encrypt. */
  @Override
  public Key keyForAppend(String alias) throws IOException {
    String id = idOf(alias);
    try {
      return keys.forAppend(id).key();
    } catch (KmsException e) {
      throw new IOException("KMIP key " + id + " may no longer encrypt (" + KmipConnections.describe(e) + ')', e);
    }
  }

  /** Refused: an alias without its key could outlive the key's authorization (use keyForNewFile). */
  @Override
  public String currentAlias(String configuredAlias) {
    throw new UnsupportedOperationException(
        "use keyForNewFile: an alias without its key could outlive the key's authorization");
  }

  /** The key a file's header names, to read it: {@link LocalKeys#forDecrypt} of its identifier. */
  @Override
  public Key getSecretKey(String alias) throws IOException {
    String id = idOf(alias);
    try {
      return keys.forDecrypt(id).key();
    } catch (KmsException e) {
      throw new IOException("Cannot use KMIP key " + id + " (" + KmipConnections.describe(e) + ')', e);
    }
  }

  private String idOf(String alias) throws IOException {
    String id = keyId(alias);
    if (id == null || id.isEmpty())
      throw new IOException("Key alias " + alias + " names no KMIP key; files under " + name + " record <name>#<id>");
    String named = alias.substring(0, alias.lastIndexOf(SEPARATOR));
    if (!name.equals(named))
      throw new IOException("Key alias " + alias + " names key " + named + "; this provider serves " + name);
    return id;
  }

  private void checkName(String configured) {
    if (!name.equals(configured))
      throw new IllegalArgumentException("This provider serves key " + name + ", not " + configured);
  }

  /**
   * How long new files can still get their key without the KMS (the earliest of the write key's
   * TTL, lease and protection deadline), from memory; zero when no write key is cached. A metric,
   * never an authorization.
   */
  public Optional<Duration> usableFor() {
    return keys.usableFor();
  }

  /**
   * The failure of the write key's last validation; empty when it succeeded or none has run. With
   * {@link #usableFor()}, it tells a failing KMS from a node that has written nothing for a TTL.
   */
  public Optional<RuntimeException> writeFailure() {
    return keys.writeFailure();
  }

  /** The key new files go under now, as far as this node's cache knows, without asking the KMS. */
  public Optional<String> currentWriteId() {
    return keys.currentWriteId();
  }

  /**
   * Closes every cache in the process. For tests and embedders only: Cassandra gives key providers
   * no shutdown call, and a node's commit log still asks for keys while it shuts down.
   */
  public static void closeAll() {
    caches.values().forEach(LocalKeys::close);
    caches.clear();
    KmipMetrics.clear();
  }

  static String alias(String name, String id) {
    return name + SEPARATOR + id;
  }

  /** The unique identifier in an alias recorded in a file header, or null if it names no version. */
  public static String keyId(String alias) {
    int separator = alias.lastIndexOf(SEPARATOR);
    return separator < 0 ? null : alias.substring(separator + 1);
  }
}
