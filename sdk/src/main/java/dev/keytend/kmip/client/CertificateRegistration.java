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

package dev.keytend.kmip.client;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.model.*;
import java.security.cert.*;
import java.security.interfaces.*;
import java.util.*;

/**
 * A typed Register request for a JCA {@link X509Certificate}. Certificate Register requires
 * Cryptographic Algorithm, Cryptographic Length, Certificate Length and Cryptographic Usage Mask
 * (KMIP 1.1 Table 129, 2.1 Table 293); this builder derives the first three from the certificate's
 * subject public key and its DER encoding and requires an explicit usage. The algorithm describes
 * the subject key, not the issuer's signature algorithm.
 *
 * <p>A KMIP 1.x server may refuse a usage that the certificate's X.509 Key Usage extension does not
 * grant (KMIP 1.0 §3.14, 1.1 to 1.4 §3.19, 1.4 Table 96), such as Verify on a CA certificate that
 * has only keyCertSign and cRLSign. {@link dev.keytend.kmip.kms.KmsKeys#register(X509Certificate)}
 * derives the usage from the extension.
 *
 * <p>For an EC subject key the caller must state the algorithm: {@code EC}, or {@code ECDSA},
 * {@code ECDH} or {@code ECMQV} (the key's purpose, which a 1.x server without generic EC needs).
 *
 * <pre>{@code
 * Request register = CertificateRegistration.of(cert, UsageMask.of(VERIFY))
 *     .ecAlgorithm(Enums.CryptographicAlgorithm.ECDSA).name("tls-server").build();
 * }</pre>
 *
 * @since 0.10.0
 */
public final class CertificateRegistration {
  private final X509Certificate certificate;
  private final UsageMask usage;
  private final byte[] der;
  private Enums.CryptographicAlgorithm algorithm;
  private Integer bits;
  private final List<Ttlv> attributes = new ArrayList<>();

  private CertificateRegistration(X509Certificate certificate, UsageMask usage) {
    this.certificate = Objects.requireNonNull(certificate, "certificate");
    this.usage = Objects.requireNonNull(usage, "usage");
    if (usage.isEmpty()) throw new IllegalArgumentException("An explicit usage is required");
    try {
      der = certificate.getEncoded();
    } catch (CertificateEncodingException e) {
      throw new IllegalArgumentException("Certificate cannot be encoded", e);
    }
    if (certificate.getPublicKey() instanceof RSAPublicKey rsa) {
      algorithm = Enums.CryptographicAlgorithm.RSA;
      bits = rsa.getModulus().bitLength();
    } else if (certificate.getPublicKey() instanceof ECPublicKey ec) {
      bits = ec.getParams().getCurve().getField().getFieldSize();
    }
  }

  public static CertificateRegistration of(X509Certificate certificate, UsageMask usage) {
    return new CertificateRegistration(certificate, usage);
  }

  /** Required for an EC subject key: EC, ECDSA, ECDH or ECMQV. */
  public CertificateRegistration ecAlgorithm(Enums.CryptographicAlgorithm value) {
    if (!(certificate.getPublicKey() instanceof ECPublicKey))
      throw new IllegalStateException("The subject key is not an EC key");
    if (value != Enums.CryptographicAlgorithm.EC
        && value != Enums.CryptographicAlgorithm.ECDSA
        && value != Enums.CryptographicAlgorithm.ECDH
        && value != Enums.CryptographicAlgorithm.ECMQV)
      throw new IllegalArgumentException("Not an EC algorithm: " + value);
    algorithm = value;
    return this;
  }

  /** For other key types: the subject key's algorithm and size, stated by the caller. */
  public CertificateRegistration subjectKey(Enums.CryptographicAlgorithm value, int keyBits) {
    algorithm = Objects.requireNonNull(value);
    bits = keyBits;
    return this;
  }

  public CertificateRegistration name(String name) {
    attributes.add(Attributes.name(name));
    return this;
  }

  /** Any other 1.x Attribute. */
  public CertificateRegistration attribute(Ttlv attribute) {
    attributes.add(attribute);
    return this;
  }

  public Request build() {
    if (algorithm == null || bits == null)
      throw new IllegalStateException(
          certificate.getPublicKey() instanceof ECPublicKey
              ? "State the EC algorithm with ecAlgorithm(...)"
              : "State the subject key with subjectKey(...)");
    List<Ttlv> all = new ArrayList<>();
    all.add(Attributes.algorithm(algorithm));
    all.add(Attributes.length(bits));
    all.add(Attributes.attribute("Certificate Length", integer(CERTIFICATE_LENGTH, der.length)));
    all.add(Attributes.attribute("Cryptographic Usage Mask", usage.toTtlv()));
    all.addAll(attributes);
    return Requests.registerObject(
        ManagedObjects.certificate(Enums.CertificateType.X_509, der), all.toArray(Ttlv[]::new));
  }
}
