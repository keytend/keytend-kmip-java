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

import dev.keytend.kmip.model.Enums;

/**
 * A hash function, for RSA-OAEP, signatures and MACs.
 *
 * @since 0.10.0
 */
public enum Hash {
  /** SHA-1, which is not collision-resistant: avoid it for new signatures. */
  SHA_1(Enums.HashingAlgorithm.SHA_1, "SHA-1"),
  /** SHA-224. */
  SHA_224(Enums.HashingAlgorithm.SHA_224, "SHA-224"),
  /** SHA-256. */
  SHA_256(Enums.HashingAlgorithm.SHA_256, "SHA-256"),
  /** SHA-384. */
  SHA_384(Enums.HashingAlgorithm.SHA_384, "SHA-384"),
  /** SHA-512. */
  SHA_512(Enums.HashingAlgorithm.SHA_512, "SHA-512"),
  /** SHA3-256. */
  SHA3_256(Enums.HashingAlgorithm.SHA_3_256, "SHA3-256"),
  /** SHA3-384. */
  SHA3_384(Enums.HashingAlgorithm.SHA_3_384, "SHA3-384"),
  /** SHA3-512. */
  SHA3_512(Enums.HashingAlgorithm.SHA_3_512, "SHA3-512");

  private final Enums.HashingAlgorithm wire;
  private final String jcaName;

  Hash(Enums.HashingAlgorithm wire, String jcaName) {
    this.wire = wire;
    this.jcaName = jcaName;
  }

  /**
   * The JCA standard name, for example {@code "SHA-256"}.
   *
   * @return the JCA name
   */
  public String jcaName() {
    return jcaName;
  }

  /**
   * The KMIP Hashing Algorithm (protocol layer).
   *
   * @return the KMIP value
   */
  public Enums.HashingAlgorithm protocolValue() {
    return wire;
  }

  @Override
  public String toString() {
    return jcaName;
  }
}
