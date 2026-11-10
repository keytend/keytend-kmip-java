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
import java.util.Objects;

/**
 * How the server computes a MAC. Immutable.
 *
 * @since 0.10.0
 */
public final class MacSpec {
  private final CryptoParameters parameters;
  private final String name;

  private MacSpec(String name, CryptoParameters parameters) {
    this.name = name;
    this.parameters = parameters;
  }

  /**
   * HMAC with the key's own algorithm (an HMAC-SHA* key).
   *
   * @return the spec
   */
  public static MacSpec keyDefault() {
    return new MacSpec("HMAC", null);
  }

  /**
   * HMAC over {@code hash}, stated explicitly.
   *
   * @param hash the hash function
   * @return the spec
   */
  public static MacSpec hmac(Hash hash) {
    Algorithm algorithm = Algorithm.hmac(Objects.requireNonNull(hash, "hash"));
    return new MacSpec(
        algorithm.jcaName(),
        CryptoParameters.builder().algorithm(algorithm.protocolValue()).build());
  }

  /**
   * Protocol-layer escape hatch: any other Cryptographic Parameters.
   *
   * @param name a name for the spec, which {@link #toString()} returns
   * @param parameters the Cryptographic Parameters to send
   * @return the spec
   */
  public static MacSpec fromProtocol(String name, CryptoParameters parameters) {
    return new MacSpec(
        Objects.requireNonNull(name, "name"), Objects.requireNonNull(parameters, "parameters"));
  }

  CryptoParameters parameters() {
    return parameters;
  }

  @Override
  public String toString() {
    return name;
  }
}
