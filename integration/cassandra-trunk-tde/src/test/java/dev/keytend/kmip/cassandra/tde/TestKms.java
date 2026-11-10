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

import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import org.apache.cassandra.config.ParameterizedClass;
import org.apache.cassandra.config.TransparentDataEncryptionOptions;

/**
 * An in-memory KMS of two replicas with an outage switch per replica, installed as {@link
 * KmipConnections#testConfig} (the provider connects to it without TLS files).
 */
final class TestKms implements AutoCloseable {
  final InMemoryKmipServer a;
  final InMemoryKmipServer b;
  private final KmipVersion version;

  TestKms(KmipVersion version) {
    this.version = version;
    a = InMemoryKmipServer.of(version);
    b = a.replica();
    KmipConnections.testConfig = parameters -> config();
  }

  KmsConfig.Builder config() {
    KmsConfig.Builder builder = a.configureReplicas(b);
    if (version == KmipVersion.V3_0) builder.maximumVersion(KmipVersion.V3_0);
    return builder.callTimeout(Duration.ofSeconds(2));
  }

  /** Switches replica A, B, or both off ({@code true}) or on. */
  void down(boolean a, boolean b) {
    this.a.unreachable(a);
    this.b.unreachable(b);
  }

  /** A separate administrative connection, as the operator's tool has. */
  Kms admin() {
    return Kms.connect(config().build());
  }

  /** The deployment's key, as {@code KmipTool key-create} makes it. */
  KeyHandle createKey(Kms kms, String name) {
    return kms.keys().createAes(256).named(name).custom(KmipKeyProvider.FAMILY_ATTRIBUTE, name)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).extractable(true).findOrCreate();
  }

  /** The node's options: the provider, endpoints the test seam ignores, and {@code parameters}. */
  static TransparentDataEncryptionOptions tdeOptions(String name, String... parameters) {
    Map<String, String> map = new HashMap<>();
    map.put(KmipConnections.ENDPOINTS, "in-memory:5696");
    for (int i = 0; i < parameters.length; i += 2) map.put(parameters[i], parameters[i + 1]);
    return new TransparentDataEncryptionOptions(true, "AES/CBC/PKCS5Padding", name,
        new ParameterizedClass(KmipKeyProvider.class.getName(), map));
  }

  KeyState state(String id) {
    return a.state(id).orElseThrow();
  }

  @Override
  public void close() {
    KmipKeyProvider.closeAll();
    KmipConnections.closeAll();
    KmipConnections.testConfig = null;
    a.close();
  }
}
