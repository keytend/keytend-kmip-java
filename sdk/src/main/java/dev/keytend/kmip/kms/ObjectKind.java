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
 * The kind of managed object (KMIP Object Type).
 *
 * @since 0.10.0
 */
public enum ObjectKind {
  /** A symmetric key. */
  SYMMETRIC_KEY(Enums.ObjectType.SYMMETRIC_KEY),
  /** The public key of a key pair. */
  PUBLIC_KEY(Enums.ObjectType.PUBLIC_KEY),
  /** The private key of a key pair. */
  PRIVATE_KEY(Enums.ObjectType.PRIVATE_KEY),
  /** An X.509 certificate. */
  CERTIFICATE(Enums.ObjectType.CERTIFICATE),
  /** Secret data, such as a password or a seed. */
  SECRET_DATA(Enums.ObjectType.SECRET_DATA),
  /** An opaque object, which the server does not interpret. */
  OPAQUE_OBJECT(Enums.ObjectType.OPAQUE_OBJECT),
  /** A split key (a part of a key). */
  SPLIT_KEY(Enums.ObjectType.SPLIT_KEY),
  /** A PGP key. */
  PGP_KEY(Enums.ObjectType.PGP_KEY),
  /** A certificate request. */
  CERTIFICATE_REQUEST(Enums.ObjectType.CERTIFICATE_REQUEST),
  /** Any other or vendor object type. */
  OTHER(null);

  private final Enums.ObjectType wire;

  ObjectKind(Enums.ObjectType wire) {
    this.wire = wire;
  }

  /**
   * The KMIP Object Type (protocol layer), or null for {@link #OTHER}.
   *
   * @return the KMIP value, or null for {@link #OTHER}
   */
  public Enums.ObjectType protocolValue() {
    return wire;
  }

  static ObjectKind of(int code) {
    for (ObjectKind k : values()) if (k.wire != null && k.wire.code() == code) return k;
    return OTHER;
  }
}
