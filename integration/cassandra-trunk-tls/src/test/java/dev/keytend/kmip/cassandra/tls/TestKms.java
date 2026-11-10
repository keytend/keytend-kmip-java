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

package dev.keytend.kmip.cassandra.tls;

import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.time.Duration;

/**
 * An in-memory KMS of two replicas with an outage switch, installed as {@link
 * KmipConnections#testConfig} (the material connects to it without TLS files).
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

  /** Switches both replicas off ({@code true}) or on. */
  void down(boolean down) {
    a.unreachable(down);
    b.unreachable(down);
  }

  /** A separate administrative connection, as the operator's tool has. */
  Kms admin() {
    return Kms.connect(config().build());
  }

  @Override
  public void close() {
    KmipTlsMaterial.closeAll();
    KmipConnections.testConfig = null;
    a.close();
  }
}
