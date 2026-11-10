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
import java.util.*;

/**
 * A typed Create Key Pair request. Attributes are given in the portable 1.x form and converted to
 * Common/Private/Public Key Attributes for 2.x and 3.0. Read the identifiers with {@link
 * #result(Result)}.
 *
 * <pre>{@code
 * Request create = KeyPairRequest.ec(Enums.RecommendedCurve.P_256, Enums.CryptographicAlgorithm.EC)
 *     .privateUsage(UsageMask.of(SIGN)).publicUsage(UsageMask.of(VERIFY)).name("signer").build();
 * KeyPairRequest.Ids ids = KeyPairRequest.result(client.call(create));
 * }</pre>
 *
 * @since 0.10.0
 */
public final class KeyPairRequest {
  private final List<Ttlv> common = new ArrayList<>(),
      privateKey = new ArrayList<>(),
      publicKey = new ArrayList<>();

  private KeyPairRequest(Ttlv... commonAttributes) {
    common.addAll(List.of(commonAttributes));
  }

  /** An RSA key pair with a {@code bits}-bit modulus. */
  public static KeyPairRequest rsa(int bits) {
    return new KeyPairRequest(
        Attributes.algorithm(Enums.CryptographicAlgorithm.RSA), Attributes.length(bits));
  }

  /**
   * An EC key pair on {@code curve}. {@code algorithm} is EC (1.3+), or ECDSA, ECDH or ECMQV to
   * state the key's purpose to a 1.x server that has no generic EC algorithm.
   */
  public static KeyPairRequest ec(
      Enums.RecommendedCurve curve, Enums.CryptographicAlgorithm algorithm) {
    int bits =
        switch (curve) {
          case P_256 -> 256;
          case P_384 -> 384;
          case P_521 -> 521;
          default -> throw new IllegalArgumentException("Unsupported curve " + curve);
        };
    return new KeyPairRequest(
        Attributes.algorithm(algorithm),
        Attributes.length(bits),
        Attributes.attribute(
            "Cryptographic Domain Parameters",
            structure(CRYPTOGRAPHIC_DOMAIN_PARAMETERS, enumeration(RECOMMENDED_CURVE, curve))));
  }

  public KeyPairRequest privateUsage(UsageMask usage) {
    privateKey.add(usage(usage));
    return this;
  }

  public KeyPairRequest publicUsage(UsageMask usage) {
    publicKey.add(usage(usage));
    return this;
  }

  private static Ttlv usage(UsageMask usage) {
    if (usage.isEmpty()) throw new IllegalArgumentException("At least one usage is required");
    return Attributes.attribute("Cryptographic Usage Mask", usage.toTtlv());
  }

  /** Names the private key {@code name} and the public key {@code name + "-public"}. */
  public KeyPairRequest name(String name) {
    privateKey.add(Attributes.name(name));
    publicKey.add(Attributes.name(name + "-public"));
    return this;
  }

  /** A 1.x Attribute for both keys. */
  public KeyPairRequest commonAttribute(Ttlv attribute) {
    common.add(attribute);
    return this;
  }

  public KeyPairRequest privateAttribute(Ttlv attribute) {
    privateKey.add(attribute);
    return this;
  }

  public KeyPairRequest publicAttribute(Ttlv attribute) {
    publicKey.add(attribute);
    return this;
  }

  public Request build() {
    Request.Builder b = Requests.createKeyPair().add(structure(COMMON_TEMPLATE_ATTRIBUTE, common));
    if (!privateKey.isEmpty()) b.add(structure(PRIVATE_KEY_TEMPLATE_ATTRIBUTE, privateKey));
    if (!publicKey.isEmpty()) b.add(structure(PUBLIC_KEY_TEMPLATE_ATTRIBUTE, publicKey));
    return b.build();
  }

  /** The identifiers of a created key pair. */
  public record Ids(String privateKeyId, String publicKeyId) {}

  /**
   * @throws KmipException when the result is not Success
   * @throws ProtocolException when an identifier is missing
   */
  public static Ids result(Result result) throws ProtocolException {
    result.requireSuccess();
    try {
      Ttlv p = result.payload().orElseThrow(() -> new IllegalArgumentException("no payload"));
      return new Ids(
          p.require(PRIVATE_KEY_UNIQUE_IDENTIFIER).textValue(),
          p.require(PUBLIC_KEY_UNIQUE_IDENTIFIER).textValue());
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new ProtocolException(
          "Malformed Create Key Pair response: " + e.getMessage(), result.batchItem(), e);
    }
  }
}
