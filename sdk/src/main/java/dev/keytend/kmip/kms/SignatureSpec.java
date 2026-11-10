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

package dev.keytend.kmip.kms;

import dev.keytend.kmip.client.CryptoParameters;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.ProtocolVersion;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Objects;
import java.util.Optional;

/**
 * How the server signs; the same spec verifies. Each spec also names the JCA algorithm (and
 * parameters) that verifies its signatures locally. Immutable.
 *
 * <pre>{@code
 * byte[] sig = signer.privateKey().sign(SignatureSpec.ecdsa(Hash.SHA_384), message);
 * }</pre>
 *
 * @since 0.10.0
 */
public final class SignatureSpec {
  private final String name;
  private final CryptoParameters parameters;
  private final String jcaName;
  private final AlgorithmParameterSpec jcaParameters;
  private final ProtocolVersion since;

  private SignatureSpec(
      String name,
      CryptoParameters parameters,
      String jcaName,
      AlgorithmParameterSpec jcaParameters,
      ProtocolVersion since) {
    this.name = name;
    this.parameters = parameters;
    this.jcaName = jcaName;
    this.jcaParameters = jcaParameters;
    this.since = since;
  }

  /**
   * RSA PKCS#1 v1.5 with {@code hash} (SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512; JCA
   * "SHA256withRSA" and so on). The Digital Signature Algorithm is sent together with the
   * equivalent algorithm, padding and hashing fields, which some servers require.
   *
   * @param hash the hash: SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512
   * @return the spec
   * @throws IllegalArgumentException for a SHA-3 hash
   */
  public static SignatureSpec rsaPkcs1(Hash hash) {
    Enums.DigitalSignatureAlgorithm algorithm =
        switch (Objects.requireNonNull(hash, "hash")) {
          case SHA_1 -> Enums.DigitalSignatureAlgorithm.SHA_1_WITH_RSA_ENCRYPTION_PKCS_1_V1_5;
          case SHA_224 -> Enums.DigitalSignatureAlgorithm.SHA_224_WITH_RSA_ENCRYPTION_PKCS_1_V1_5;
          case SHA_256 -> Enums.DigitalSignatureAlgorithm.SHA_256_WITH_RSA_ENCRYPTION_PKCS_1_V1_5;
          case SHA_384 -> Enums.DigitalSignatureAlgorithm.SHA_384_WITH_RSA_ENCRYPTION_PKCS_1_V1_5;
          case SHA_512 -> Enums.DigitalSignatureAlgorithm.SHA_512_WITH_RSA_ENCRYPTION_PKCS_1_V1_5;
          default ->
              throw new IllegalArgumentException(
                  "RSA PKCS#1 v1.5 with " + hash + " is not offered");
        };
    String jca = jcaDigest(hash) + "withRSA";
    return new SignatureSpec(
        jca,
        CryptoParameters.builder()
            .digitalSignature(algorithm)
            .algorithm(Enums.CryptographicAlgorithm.RSA)
            .padding(Enums.PaddingMethod.PKCS1_V1_5)
            .hashing(hash.protocolValue())
            .build(),
        jca,
        null,
        ProtocolVersion.V1_1);
  }

  /**
   * RSA-PSS with {@code hash}, MGF1 over the same hash and a salt as long as the digest (JCA
   * "RSASSA-PSS" with {@link #jcaParameters()}). Needs KMIP 1.4: before it, the MGF1 hash and salt
   * length cannot be stated, so the signature could not be verified with these parameters.
   *
   * @param hash the hash
   * @return the spec
   */
  public static SignatureSpec rsaPss(Hash hash) {
    Objects.requireNonNull(hash, "hash");
    int salt =
        switch (hash) {
          case SHA_1 -> 20;
          case SHA_224 -> 28;
          case SHA_256, SHA3_256 -> 32;
          case SHA_384, SHA3_384 -> 48;
          case SHA_512, SHA3_512 -> 64;
        };
    return new SignatureSpec(
        "RSASSA-PSS/" + hash.jcaName(),
        CryptoParameters.rsaPss(hash.protocolValue(), salt),
        "RSASSA-PSS",
        new PSSParameterSpec(
            hash.jcaName(), "MGF1", new MGF1ParameterSpec(hash.jcaName()), salt, 1),
        ProtocolVersion.V1_4);
  }

  /**
   * ECDSA with {@code hash} (JCA "SHA256withECDSA" and so on, DER-encoded signature).
   *
   * @param hash the hash: SHA-1, SHA-224, SHA-256, SHA-384 or SHA-512
   * @return the spec
   * @throws IllegalArgumentException for a SHA-3 hash
   */
  public static SignatureSpec ecdsa(Hash hash) {
    Enums.DigitalSignatureAlgorithm algorithm =
        switch (Objects.requireNonNull(hash, "hash")) {
          case SHA_1 -> Enums.DigitalSignatureAlgorithm.ECDSA_WITH_SHA_1;
          case SHA_224 -> Enums.DigitalSignatureAlgorithm.ECDSA_WITH_SHA224;
          case SHA_256 -> Enums.DigitalSignatureAlgorithm.ECDSA_WITH_SHA256;
          case SHA_384 -> Enums.DigitalSignatureAlgorithm.ECDSA_WITH_SHA384;
          case SHA_512 -> Enums.DigitalSignatureAlgorithm.ECDSA_WITH_SHA512;
          default -> throw new IllegalArgumentException("ECDSA with " + hash + " is not offered");
        };
    String jca = jcaDigest(hash) + "withECDSA";
    return new SignatureSpec(
        jca,
        CryptoParameters.builder().digitalSignature(algorithm).build(),
        jca,
        null,
        ProtocolVersion.V1_1);
  }

  private static String jcaDigest(Hash hash) {
    return hash.jcaName().replace("-", "");
  }

  /**
   * Protocol-layer escape hatch: any other Cryptographic Parameters. It names no JCA algorithm.
   *
   * @param name a name for the spec, which {@link #toString()} returns
   * @param parameters the Cryptographic Parameters to send
   * @return the spec
   */
  public static SignatureSpec fromProtocol(String name, CryptoParameters parameters) {
    return new SignatureSpec(
        Objects.requireNonNull(name, "name"),
        Objects.requireNonNull(parameters, "parameters"),
        null,
        null,
        ProtocolVersion.V1_1);
  }

  CryptoParameters parameters() {
    return parameters;
  }

  void requireVersion(ProtocolVersion version, String operation, String keyId) {
    if (!version.atLeast(since))
      throw new UnsupportedException(
          operation + ": " + name + " needs KMIP " + since + "; this connection uses " + version,
          null,
          operation,
          keyId,
          null,
          null);
  }

  /**
   * The JCA signature algorithm name for verifying locally, when there is one.
   *
   * @return the JCA algorithm name; empty for {@link #fromProtocol}
   */
  public Optional<String> jcaAlgorithm() {
    return Optional.ofNullable(jcaName);
  }

  /**
   * The JCA parameters to pass to {@code Signature.setParameter}, for RSA-PSS.
   *
   * @return the JCA parameters; empty for specs other than RSA-PSS
   */
  public Optional<AlgorithmParameterSpec> jcaParameters() {
    return Optional.ofNullable(jcaParameters);
  }

  @Override
  public String toString() {
    return name;
  }
}
