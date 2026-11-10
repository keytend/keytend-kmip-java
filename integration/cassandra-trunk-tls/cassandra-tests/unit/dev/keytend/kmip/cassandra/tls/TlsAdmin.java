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

import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.RevocationReason;
import dev.keytend.kmip.kms.TlsIdentityHandle;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

/**
 * Test only: the operator's side, as the README's runbook does it with the SDK, from one place
 * with the operator's KMS credential (never from the nodes).
 */
public final class TlsAdmin {
  private final Kms kms;

  public TlsAdmin(Kms kms) {
    this.kms = kms;
  }

  /** A trust anchor; its usages come from its Key Usage extension (keyCertSign, cRLSign). */
  public KeyHandle addCa(String domain, X509Certificate ca) {
    return kms.keys().register(ca).custom(KmipTlsMaterial.TAG, domain + ":ca").register();
  }

  /** A node identity: its key and chain under its name, the leaf tagged as a registered peer. */
  public TlsIdentityHandle addIdentity(String domain, String name, PrivateKey key, X509Certificate... chain) {
    return kms.tls().register(key, chain).named(name).custom(KmipTlsMaterial.TAG, domain + ":identity").register();
  }

  /** A client certificate allowed to connect. */
  public KeyHandle addPeer(String domain, X509Certificate certificate) {
    return kms.keys().register(certificate).custom(KmipTlsMaterial.TAG, domain + ":identity").register();
  }

  /** A new certificate for the identity's key (the tag is copied to the new leaf). */
  public TlsIdentityHandle renew(String name, X509Certificate... chain) {
    return identity(name).renew(chain);
  }

  /** A new key and certificate; also the recovery of a revoked or compromised identity, under its name. */
  public TlsIdentityHandle rekey(String name, PrivateKey key, X509Certificate... chain) {
    return identity(name).rekey(key, chain);
  }

  public void revokeIdentity(String name, boolean compromised) {
    identity(name).revoke(compromised
        ? RevocationReason.keyCompromise("TLS key compromised", Instant.now().minusSeconds(60))
        : RevocationReason.cessationOfOperation("TLS identity revoked"));
  }

  /** Revokes the Active registered peer whose certificate is {@code certificate}. */
  public void revokePeer(String domain, X509Certificate certificate) throws CertificateEncodingException {
    byte[] der = certificate.getEncoded();
    Map<String, X509Certificate> peers =
        kms.tls().certificates(KmipTlsMaterial.tagged(domain, "identity").state(KeyState.ACTIVE));
    for (Map.Entry<String, X509Certificate> e : peers.entrySet()) {
      if (Arrays.equals(e.getValue().getEncoded(), der)) {
        kms.keys().handle(e.getKey()).revoke(RevocationReason.cessationOfOperation("TLS certificate revoked"));
        return;
      }
    }
    throw new IllegalArgumentException("No Active registered peer " + certificate.getSubjectX500Principal());
  }

  private TlsIdentityHandle identity(String name) {
    return kms.tls().identity(name).orElseThrow(() -> new IllegalArgumentException("No TLS identity named " + name));
  }
}
