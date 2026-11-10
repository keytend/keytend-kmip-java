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

package dev.keytend.kmip.model;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import java.util.*;

/**
 * Constructors for every managed object; nested TTLV supports all transparent and wrapped formats.
 *
 * @since 0.10.0
 */
public final class ManagedObjects {
  private ManagedObjects() {}

  public static Ttlv keyBlock(
      Enums.KeyFormatType format,
      Ttlv material,
      Enums.CryptographicAlgorithm algorithm,
      Integer bits,
      Ttlv... wrappingOrCompression) {
    List<Ttlv> fields = new ArrayList<>();
    fields.add(enumeration(KEY_FORMAT_TYPE, format));
    for (Ttlv f : wrappingOrCompression) if (f.tag() == KEY_COMPRESSION_TYPE.code()) fields.add(f);
    fields.add(
        material.tag() == KEY_VALUE.code()
            ? material
            : structure(KEY_VALUE, material.retag(KEY_MATERIAL)));
    if (algorithm != null) fields.add(enumeration(CRYPTOGRAPHIC_ALGORITHM, algorithm));
    if (bits != null) fields.add(integer(CRYPTOGRAPHIC_LENGTH, bits));
    for (Ttlv f : wrappingOrCompression) if (f.tag() != KEY_COMPRESSION_TYPE.code()) fields.add(f);
    return structure(KEY_BLOCK, fields);
  }

  public static Ttlv symmetricKey(Ttlv block) {
    return structure(SYMMETRIC_KEY, block);
  }

  public static Ttlv publicKey(Ttlv block) {
    return structure(PUBLIC_KEY, block);
  }

  public static Ttlv privateKey(Ttlv block) {
    return structure(PRIVATE_KEY, block);
  }

  public static Ttlv rawSymmetricKey(byte[] key, Enums.CryptographicAlgorithm algorithm) {
    return symmetricKey(
        keyBlock(Enums.KeyFormatType.RAW, bytes(KEY_MATERIAL, key), algorithm, key.length * 8));
  }

  public static Ttlv certificate(Enums.CertificateType type, byte[] der) {
    return structure(
        CERTIFICATE, enumeration(CERTIFICATE_TYPE, type), bytes(CERTIFICATE_VALUE, der));
  }

  public static Ttlv secretData(Enums.SecretDataType type, Ttlv keyBlock) {
    return structure(SECRET_DATA, enumeration(SECRET_DATA_TYPE, type), keyBlock);
  }

  public static Ttlv opaque(int type, byte[] value) {
    return structure(
        OPAQUE_OBJECT, enumeration(OPAQUE_DATA_TYPE, type), bytes(OPAQUE_DATA_VALUE, value));
  }

  public static Ttlv template(Ttlv... namesAndAttributes) {
    return structure(TEMPLATE, namesAndAttributes);
  }

  public static Ttlv splitKey(
      int parts,
      int partId,
      int threshold,
      Enums.SplitKeyMethod method,
      Ttlv primeFieldSize,
      Ttlv keyBlock) {
    List<Ttlv> fields =
        new ArrayList<>(
            List.of(
                integer(SPLIT_KEY_PARTS, parts),
                integer(KEY_PART_IDENTIFIER, partId),
                integer(SPLIT_KEY_THRESHOLD, threshold),
                enumeration(SPLIT_KEY_METHOD, method)));
    if (primeFieldSize != null) fields.add(primeFieldSize.retag(PRIME_FIELD_SIZE));
    fields.add(keyBlock);
    return structure(SPLIT_KEY, fields);
  }

  public static Enums.ObjectType objectType(Ttlv object) {
    return switch (Tag.fromCode(object.tag())
        .orElseThrow(
            () -> new IllegalArgumentException("Not a managed object: " + object.tagName()))) {
      case CERTIFICATE_REQUEST -> Enums.ObjectType.CERTIFICATE_REQUEST;
      case CERTIFICATE -> Enums.ObjectType.CERTIFICATE;
      case SYMMETRIC_KEY -> Enums.ObjectType.SYMMETRIC_KEY;
      case PUBLIC_KEY -> Enums.ObjectType.PUBLIC_KEY;
      case PRIVATE_KEY -> Enums.ObjectType.PRIVATE_KEY;
      case SPLIT_KEY -> Enums.ObjectType.SPLIT_KEY;
      case TEMPLATE -> Enums.ObjectType.TEMPLATE;
      case SECRET_DATA -> Enums.ObjectType.SECRET_DATA;
      case OPAQUE_OBJECT -> Enums.ObjectType.OPAQUE_OBJECT;
      case PGP_KEY -> Enums.ObjectType.PGP_KEY;
      default -> throw new IllegalArgumentException("Not a managed object: " + object.tagName());
    };
  }

  public static Ttlv certificateRequest(Enums.CertificateRequestType type, byte[] encoded) {
    return structure(
        CERTIFICATE_REQUEST,
        enumeration(CERTIFICATE_REQUEST_TYPE, type),
        bytes(CERTIFICATE_REQUEST_VALUE, encoded));
  }

  public static Ttlv pgpKey(int version, Ttlv keyBlock) {
    return structure(PGP_KEY, integer(PGP_KEY_VERSION, version), keyBlock);
  }
}
