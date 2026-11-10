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

import dev.keytend.kmip.kms.CertificateRenewal;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.kms.KmsListener;

/** Connects to a server group. Tests replace it to connect to an in-memory server. */
interface Connector {
  /**
   * Connects to {@code group}.
   *
   * @param group the server group
   * @param secrets where the group's passwords are read from
   * @param listener the command's listener, which the configuration adds
   * @return a connected {@code Kms}, which the caller closes
   */
  Kms connect(ServerGroup group, Secrets secrets, KmsListener listener);

  /**
   * Connects to {@code group} as {@link #connect} does, with {@code renewal} of the client
   * certificate ({@code renew-certificate}). A connector without TLS cannot renew: the SDK refuses
   * the configuration ({@link IllegalArgumentException}).
   *
   * @param group the server group
   * @param secrets where the group's passwords are read from
   * @param listener the command's listener, which the configuration adds
   * @param renewal the renewal setting
   * @return a connected {@code Kms}, which the caller closes
   */
  default Kms connectRenewing(
      ServerGroup group, Secrets secrets, KmsListener listener, CertificateRenewal renewal) {
    throw new IllegalArgumentException(
        "renewing the client certificate needs the TLS connection to the server group");
  }

  /** The real connection: the group's endpoints, TLS identity, trust and settings. */
  static Connector tls() {
    return new Connector() {
      @Override
      public Kms connect(ServerGroup group, Secrets secrets, KmsListener listener) {
        return Kms.connect(
            group.settings(group.tls(KmsConfig.builder(), secrets)).addListener(listener).build());
      }

      @Override
      public Kms connectRenewing(
          ServerGroup group, Secrets secrets, KmsListener listener, CertificateRenewal renewal) {
        return Kms.connect(
            group
                .settings(group.tls(KmsConfig.builder(), secrets))
                .clientCertificateRenewal(renewal)
                .addListener(listener)
                .build());
      }
    };
  }
}
