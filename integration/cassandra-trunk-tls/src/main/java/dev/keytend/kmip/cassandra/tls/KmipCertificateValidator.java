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

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.concurrent.TimeUnit;
import org.apache.cassandra.auth.SpiffeCertificateValidator;
import org.apache.cassandra.utils.NoSpamLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A certificate chain is valid while a {@link KmipTlsMaterial} of this node that requires
 * registered peers trusts it now: it validates against the KMS trust anchors and its certificate is
 * an Active registered peer ({@code cassandra-tls=<domain>:identity}), from memory, with their
 * leases. Its identity is its SPIFFE ID, as {@link SpiffeCertificateValidator}'s. Use it as {@code
 * validator_class_name} of {@code MutualTlsAuthenticator} and {@code
 * MutualTlsInternodeAuthenticator}: a certificate revoked or compromised in the KMS is refused at
 * its next connection after the node's next refresh. Materials with {@code
 * kmip_tls_require_registered_peers: false} check only the anchors, which a revoked certificate
 * still chains to, so they are never consulted here; with none that requires registered peers,
 * every chain is refused.
 */
public class KmipCertificateValidator extends SpiffeCertificateValidator {
  private static final Logger logger = LoggerFactory.getLogger(KmipCertificateValidator.class);
  private static final NoSpamLogger noSpam = NoSpamLogger.getLogger(logger, 1, TimeUnit.MINUTES);

  @Override
  public boolean isValidCertificate(Certificate[] clientCertificateChain) {
    if (clientCertificateChain == null || clientCertificateChain.length == 0) return false;
    X509Certificate[] chain = new X509Certificate[clientCertificateChain.length];
    for (int i = 0; i < chain.length; i++) {
      if (!(clientCertificateChain[i] instanceof X509Certificate c)) return false;
      chain[i] = c;
    }
    for (KmipTlsMaterial material : KmipTlsMaterial.all())
      if (material.requiresRegisteredPeers() && material.allows(chain)) return true;
    noSpam.warn("Refused certificate {} (serial {}): not trusted by the KMS TLS material of this node",
                chain[0].getSubjectX500Principal(), chain[0].getSerialNumber().toString(16));
    return false;
  }
}
