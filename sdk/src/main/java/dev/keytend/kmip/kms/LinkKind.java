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
 * The kind of a {@link Link} between managed objects.
 *
 * @since 0.10.0
 */
public enum LinkKind {
  /** To the certificate of a public key (KMIP Certificate Link). */
  CERTIFICATE(Enums.LinkType.CERTIFICATE_LINK),
  /** To the public key of a private key or certificate (KMIP Public Key Link). */
  PUBLIC_KEY(Enums.LinkType.PUBLIC_KEY_LINK),
  /** To the private key of a public key (KMIP Private Key Link). */
  PRIVATE_KEY(Enums.LinkType.PRIVATE_KEY_LINK),
  /** On a derived key: the object it was derived from (KMIP Derivation Base Object Link). */
  DERIVATION_BASE(Enums.LinkType.DERIVATION_BASE_OBJECT_LINK),
  /** On a derivation base: a key derived from it (KMIP Derived Key Link). */
  DERIVED_KEY(Enums.LinkType.DERIVED_KEY_LINK),
  /** On a key that was re-keyed: its replacement. */
  REPLACEMENT(Enums.LinkType.REPLACEMENT_OBJECT_LINK),
  /** On a replacement key: the key it replaced. */
  REPLACED(Enums.LinkType.REPLACED_OBJECT_LINK),
  /** To a parent object, such as the issuer of a certificate (KMIP Parent Link). */
  PARENT(Enums.LinkType.PARENT_LINK),
  /** To a child object (KMIP Child Link). */
  CHILD(Enums.LinkType.CHILD_LINK),
  /** To the previous object in a sequence (KMIP Previous Link). */
  PREVIOUS(Enums.LinkType.PREVIOUS_LINK),
  /** To the next object in a sequence (KMIP Next Link). */
  NEXT(Enums.LinkType.NEXT_LINK),
  /** Any other or vendor link type ({@link Link#rawType()} has the code). */
  OTHER(null);

  private final Enums.LinkType wire;

  LinkKind(Enums.LinkType wire) {
    this.wire = wire;
  }

  /**
   * The KMIP Link Type (protocol layer), or null for {@link #OTHER}.
   *
   * @return the KMIP value, or null for {@link #OTHER}
   */
  public Enums.LinkType protocolValue() {
    return wire;
  }

  static LinkKind of(int code) {
    for (LinkKind k : values()) if (k.wire != null && k.wire.code() == code) return k;
    return OTHER;
  }
}
