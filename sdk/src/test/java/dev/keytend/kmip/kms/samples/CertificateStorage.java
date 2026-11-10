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

package dev.keytend.kmip.kms.samples;

import dev.keytend.kmip.kms.*;
import java.security.cert.X509Certificate;

/**
 * A6. Certificate storage: register a JCA certificate with an explicit usage policy (the SDK
 * derives the algorithm, key length and certificate length the KMIP Register needs), then
 * retrieve it as an {@link X509Certificate}. Retrieval checks identity and encoding only; trust
 * decisions stay with the application's PKIX validation.
 */
public final class CertificateStorage {
  private CertificateStorage() {}

  /** Registers the certificate; it stays Pre-Active, as stored certificates often do. */
  public static KeyHandle store(Kms kms, X509Certificate certificate, String name) {
    return kms.keys().register(certificate).named(name).usages(KeyUsage.VERIFY).registerPreActive();
  }

  /** Loads the certificate named {@code name}, whether Pre-Active or Active. */
  public static X509Certificate load(Kms kms, String name) {
    return kms.keys()
        .findByName(name, KeyState.PRE_ACTIVE, KeyState.ACTIVE)
        .orElseThrow()
        .asCertificate();
  }
}
