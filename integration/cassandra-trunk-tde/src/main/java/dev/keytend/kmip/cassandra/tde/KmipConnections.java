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

import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.kms.KmsException;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Function;
import org.apache.cassandra.config.DurationSpec;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The KMS connection settings of the key provider, read from the {@code parameters} of the {@code
 * key_provider} in {@code transparent_data_encryption_options}. {@link #config} builds the {@link
 * KmsConfig} that each {@code LocalKeys} cache owns and connects at its first use; {@link #get} is
 * the shared, connected {@link Kms} of the operator's tool. Cassandra makes key providers
 * reflectively and repeatedly and never closes them, so neither lives in a provider instance.
 * Parameters:
 *
 * <ul>
 *   <li>{@code kmip_endpoints}: comma separated {@code host:port}, replicas of one KMS (required);
 *   <li>{@code kmip_client_certificate}, {@code kmip_client_key}: PEM files of the node's KMS
 *       client identity (required; the same file twice for a combined PEM), and {@code
 *       kmip_client_key_password} for an encrypted key;
 *   <li>{@code kmip_trust_certificates}: PEM file of the KMS server's CA (required);
 *   <li>{@code kmip_min_version}, {@code kmip_max_version}: {@code 1.4}, {@code 2.1}, {@code 3.0}...;
 *   <li>{@code kmip_call_timeout}: deadline of one KMS call, default {@code 10s};
 *   <li>{@code kmip_reload_credentials}: re-read the client identity files when they change,
 *       default {@code true};
 *   <li>{@code kmip_startup_timeout}: how long to keep trying an unreachable KMS when connecting,
 *       default {@code 0s}.
 * </ul>
 */
public final class KmipConnections {
  private static final Logger logger = LoggerFactory.getLogger(KmipConnections.class);

  public static final String ENDPOINTS = "kmip_endpoints";
  public static final String CLIENT_CERTIFICATE = "kmip_client_certificate";
  public static final String CLIENT_KEY = "kmip_client_key";
  public static final String CLIENT_KEY_PASSWORD = "kmip_client_key_password";
  public static final String TRUST_CERTIFICATES = "kmip_trust_certificates";
  public static final String MIN_VERSION = "kmip_min_version";
  public static final String MAX_VERSION = "kmip_max_version";
  public static final String CALL_TIMEOUT = "kmip_call_timeout";
  public static final String RELOAD_CREDENTIALS = "kmip_reload_credentials";
  public static final String STARTUP_TIMEOUT = "kmip_startup_timeout";

  private static final List<String> CONNECTION_KEYS =
      List.of(ENDPOINTS, CLIENT_CERTIFICATE, CLIENT_KEY, CLIENT_KEY_PASSWORD, TRUST_CERTIFICATES, MIN_VERSION,
              MAX_VERSION, CALL_TIMEOUT, RELOAD_CREDENTIALS, STARTUP_TIMEOUT);

  private static final Map<Map<String, String>, Kms> connections = new ConcurrentHashMap<>();

  /**
   * Tests only: when set, makes the base configuration (endpoints and transport) instead of the
   * TLS settings above, for {@code dev.keytend.kmip.testing.InMemoryKmipServer#configure()}.
   */
  public static volatile Function<Map<String, String>, KmsConfig.Builder> testConfig;

  private KmipConnections() {}

  /**
   * The shared {@link Kms} for these parameters, connected on first use.
   *
   * @throws ConfigurationException when the parameters are invalid or the KMS cannot be reached
   */
  public static Kms get(Map<String, ?> parameters) {
    return connections.computeIfAbsent(connectionParameters(parameters), KmipConnections::connect);
  }

  /** Closes and forgets every shared connection. */
  public static void closeAll() {
    connections.values().forEach(Kms::close);
    connections.clear();
  }

  static Map<String, String> connectionParameters(Map<String, ?> parameters) {
    Map<String, String> key = new TreeMap<>();
    for (String name : CONNECTION_KEYS) {
      String value = get(parameters, name, null);
      if (value != null) key.put(name, value);
    }
    return key;
  }

  static String get(Map<String, ?> parameters, String name, String defaultValue) {
    Object value = parameters == null ? null : parameters.get(name);
    return value == null ? defaultValue : value.toString().trim();
  }

  static String require(Map<String, ?> parameters, String name) {
    String value = get(parameters, name, null);
    if (value == null || value.isEmpty()) throw new ConfigurationException("KMIP parameter " + name + " is required");
    return value;
  }

  /** A Cassandra duration ({@code 60s}, {@code 500ms}, {@code 2m}...). */
  static Duration duration(Map<String, ?> parameters, String name, String defaultValue) {
    String value = get(parameters, name, defaultValue);
    try {
      return Duration.ofMillis(new DurationSpec.LongMillisecondsBound(value).toMilliseconds());
    } catch (IllegalArgumentException e) {
      throw new ConfigurationException("KMIP parameter " + name + " is not a duration: " + value, e);
    }
  }

  private static Kms connect(Map<String, String> parameters) {
    KmsConfig config = config(parameters);
    try {
      Kms kms = Kms.connect(config);
      logger.info("Connected to KMS {} at KMIP {}", config.endpoints(), kms.version());
      return kms;
    } catch (KmsException e) {
      throw new ConfigurationException("Cannot connect to KMS " + config.endpoints() + " (" + describe(e) + ')', e);
    }
  }

  /** The KMS configuration these parameters describe; nothing is connected. */
  public static KmsConfig config(Map<String, ?> parameters) {
    KmsConfig.Builder builder;
    Function<Map<String, String>, KmsConfig.Builder> test = testConfig;
    if (test != null) {
      builder = test.apply(connectionParameters(parameters));
    } else {
      builder = KmsConfig.builder().endpoints(require(parameters, ENDPOINTS).split("\\s*,\\s*"));
      Path certificate = Path.of(require(parameters, CLIENT_CERTIFICATE));
      Path key = Path.of(require(parameters, CLIENT_KEY));
      String password = get(parameters, CLIENT_KEY_PASSWORD, null);
      if (password == null) builder.clientIdentityPem(certificate, key);
      else builder.clientIdentityPem(certificate, key, password.toCharArray());
      builder.trustPem(Path.of(require(parameters, TRUST_CERTIFICATES)));
      if (Boolean.parseBoolean(get(parameters, RELOAD_CREDENTIALS, "true"))) builder.reloadOnChange();
    }
    String min = get(parameters, MIN_VERSION, null);
    if (min != null) builder.minimumVersion(version(min));
    String max = get(parameters, MAX_VERSION, null);
    if (max != null) builder.maximumVersion(version(max));
    builder.callTimeout(duration(parameters, CALL_TIMEOUT, "10s"));
    builder.connectRetry(duration(parameters, STARTUP_TIMEOUT, "0s"));
    try {
      return builder.build();
    } catch (IllegalArgumentException e) {
      throw new ConfigurationException("Invalid KMIP configuration: " + e.getMessage(), e);
    }
  }

  static KmipVersion version(String value) {
    for (KmipVersion v : KmipVersion.values())
      if (v.toString().equals(value) || v.name().equals(value) || v.name().equals("V" + value.replace('.', '_')))
        return v;
    throw new ConfigurationException("Unknown KMIP version " + value);
  }

  static String describe(RuntimeException e) {
    String what = Objects.toString(e.getMessage(), e.getClass().getSimpleName());
    return e instanceof KmsException k ? k.category() + ": " + what : what;
  }
}
