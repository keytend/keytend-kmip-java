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

package dev.keytend.kmip.cli;

import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.KmsConfig;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A named connection profile from the configuration file: the endpoints of one KMS (tried in
 * order), the client identity, the trust, the timeouts and the KMIP version bounds. Passwords are
 * referenced ({@link Secrets.Source}), never held.
 */
record ServerGroup(
    String name,
    String description,
    List<String> endpoints,
    Identity identity,
    Trust trust,
    Duration timeout,
    Duration connectTimeout,
    KmipVersion minimumVersion,
    KmipVersion maximumVersion,
    List<String> cipherSuites) {

  /** The kinds of client identity. */
  enum IdentityType {
    /** A PKCS#12 key store. */
    PKCS12,
    /** A Java key store. */
    JKS,
    /** A PEM certificate chain and private key. */
    PEM
  }

  /** The kinds of trust. */
  enum TrustType {
    /** A PEM file of CA certificates. */
    PEM,
    /** A PKCS#12 trust store. */
    PKCS12,
    /** A Java key store as trust store. */
    JKS,
    /** The JDK's default CAs. */
    SYSTEM
  }

  /**
   * The client identity: {@link IdentityType#PKCS12} or {@link IdentityType#JKS} (a key store
   * {@code file} and its {@code password}), or {@link IdentityType#PEM} (a {@code certificate} chain, a {@code key} and, for an
   * encrypted key, its {@code password}).
   */
  record Identity(
      IdentityType type, Path file, Path certificate, Path key, Secrets.Source password) {
    String describe() {
      String where =
          type == IdentityType.PEM
              ? "certificate " + certificate + ", key " + key
              : file.toString();
      return Values.token(type)
          + " "
          + where
          + (password == null ? "" : ", password from " + password.describe());
    }
  }

  /**
   * The trusted CAs: {@link TrustType#PEM} (a {@code file} of CA certificates), {@link
   * TrustType#PKCS12} or {@link TrustType#JKS} (a trust store {@code file}, with an optional
   * {@code password}), or {@link TrustType#SYSTEM} (the JDK's default CAs).
   */
  record Trust(TrustType type, Path file, Secrets.Source password) {
    String describe() {
      if (type == TrustType.SYSTEM) return "system (the JDK's default CAs)";
      return Values.token(type)
          + " "
          + file
          + (password == null ? "" : ", password from " + password.describe());
    }
  }

  ServerGroup {
    endpoints = List.copyOf(endpoints);
    cipherSuites = List.copyOf(cipherSuites);
  }

  /**
   * This group with another call timeout.
   *
   * @param callTimeout the timeout
   * @return a copy
   */
  ServerGroup withTimeout(Duration callTimeout) {
    return new ServerGroup(
        name,
        description,
        endpoints,
        identity,
        trust,
        callTimeout,
        connectTimeout,
        minimumVersion,
        maximumVersion,
        cipherSuites);
  }

  /**
   * Applies the settings that do not concern TLS: timeouts and version bounds.
   *
   * @param builder the builder
   * @return {@code builder}
   */
  KmsConfig.Builder settings(KmsConfig.Builder builder) {
    if (timeout != null) builder.callTimeout(timeout);
    if (connectTimeout != null) builder.connectTimeout(connectTimeout);
    if (minimumVersion != null) builder.minimumVersion(minimumVersion);
    if (maximumVersion != null) builder.maximumVersion(maximumVersion);
    return builder;
  }

  /**
   * Applies the endpoints, the client identity, the trust and the cipher suites, reading the
   * passwords; each password is wiped once the builder has its copy.
   *
   * @param builder the builder
   * @param secrets where passwords are read from
   * @return {@code builder}
   */
  KmsConfig.Builder tls(KmsConfig.Builder builder, Secrets secrets) {
    try {
      builder.endpoints(endpoints.toArray(String[]::new));
      if (!cipherSuites.isEmpty()) builder.cipherSuites(cipherSuites);
      switch (identity.type()) {
        case PEM -> {
          if (identity.password() == null) {
            builder.clientIdentityPem(identity.certificate(), identity.key());
          } else {
            char[] password = secrets.chars(identity.password(), name + ": the PEM key's password");
            try {
              builder.clientIdentityPem(identity.certificate(), identity.key(), password);
            } finally {
              Arrays.fill(password, '\0');
            }
          }
        }
        case PKCS12 -> {
          char[] password = secrets.chars(identity.password(), name + ": the PKCS#12 password");
          try {
            builder.clientIdentityKeyStore(identity.file(), password);
          } finally {
            Arrays.fill(password, '\0');
          }
        }
        case JKS -> {
          char[] password = secrets.chars(identity.password(), name + ": the key store password");
          try {
            builder.clientIdentityKeyStore(identity.file(), password);
          } finally {
            Arrays.fill(password, '\0');
          }
        }
      }
      switch (trust.type()) {
        case SYSTEM -> builder.trustSystemDefaults();
        case PEM -> builder.trustPem(trust.file());
        case PKCS12, JKS -> {
          char[] password =
              trust.password() == null
                  ? null
                  : secrets.chars(trust.password(), name + ": the trust store password");
          try {
            builder.trustStore(load(Values.token(trust.type()), trust.file(), password));
          } finally {
            if (password != null) Arrays.fill(password, '\0');
          }
        }
      }
      return builder;
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new CliException(ExitCode.USAGE, "server group " + name + ": " + e.getMessage());
    }
  }

  private KeyStore load(String type, Path file, char[] password) {
    try (InputStream in = Files.newInputStream(file)) {
      KeyStore store = KeyStore.getInstance(type.toUpperCase(Locale.ROOT));
      store.load(in, password);
      return store;
    } catch (IOException | GeneralSecurityException e) {
      throw new CliException(
          ExitCode.USAGE,
          "server group "
              + name
              + ": cannot load the "
              + type
              + " store "
              + file
              + ": "
              + e.getMessage());
    }
  }

  /**
   * The group as shown by {@code servers}: no password, only where each is read from. A setting
   * left to its default is null.
   *
   * @param isDefault whether it is the default group
   * @return the fields, in order
   */
  Map<String, Object> describe(boolean isDefault) {
    Map<String, Object> out = new LinkedHashMap<>();
    out.put("name", name);
    out.put("default", isDefault);
    out.put("description", description);
    out.put("endpoints", endpoints);
    out.put("identity", identity.describe());
    out.put("trust", trust.describe());
    out.put("timeout", timeout == null ? null : timeout.toString());
    out.put("connectTimeout", connectTimeout == null ? null : connectTimeout.toString());
    out.put("minimumVersion", minimumVersion == null ? null : minimumVersion.toString());
    out.put("maximumVersion", maximumVersion == null ? null : maximumVersion.toString());
    out.put("cipherSuites", cipherSuites.isEmpty() ? null : cipherSuites);
    return out;
  }
}
