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

import static dev.keytend.kmip.model.Tag.*;

import dev.keytend.kmip.model.*;
import java.security.*;
import java.util.*;

/** Validated conversion of Get payloads to JCA keys. */
final class KeyReader {
  private KeyReader() {}

  /** The JCA name for a symmetric key of the expected algorithm. */
  static String jcaSecretName(Expect expect) {
    if (!expect.algorithm().symmetric())
      throw new IllegalArgumentException("Not a symmetric key algorithm: " + expect.algorithm());
    return expect.algorithm().jcaName();
  }

  /** A symmetric key: identity, type, algorithm, size, format and wrapping are checked. */
  static DestroyableSecretKey secretKey(Ttlv payload, String id, Expect expect)
      throws GeneralSecurityException {
    try {
      if (!payload.require(UNIQUE_IDENTIFIER).textValue().equals(id))
        throw new InvalidKeyException("The server returned a different object");
      if (payload.require(OBJECT_TYPE).intValue() != Enums.ObjectType.SYMMETRIC_KEY.code())
        throw new InvalidKeyException("Not a symmetric key");
      Ttlv block = payload.require(SYMMETRIC_KEY).require(KEY_BLOCK);
      Ttlv value = block.require(KEY_VALUE);
      if (value.type() != Ttlv.Type.STRUCTURE || block.child(KEY_WRAPPING_DATA).isPresent())
        throw new InvalidKeyException("The key is wrapped");
      int algorithm = block.require(CRYPTOGRAPHIC_ALGORITHM).intValue();
      if (algorithm != expect.algorithm().requireWire().code())
        throw new InvalidKeyException(
            "Expected " + expect.algorithm() + ", the key is " + Algorithm.of(algorithm));
      int format = block.require(KEY_FORMAT_TYPE).intValue();
      Ttlv material = value.require(KEY_MATERIAL);
      if (format == Enums.KeyFormatType.TRANSPARENT_SYMMETRIC_KEY.code())
        material = material.require(KEY);
      else if (format != Enums.KeyFormatType.RAW.code())
        throw new InvalidKeyException("Unsupported symmetric key format " + format);
      int bits = material.byteLength() * 8;
      if (expect.bits() != 0 && bits != expect.bits())
        throw new InvalidKeyException("Expected " + expect.bits() + " bits, the key has " + bits);
      // Any AES size (Expect.aes()) is one of AES's three, never whatever the material has.
      if (expect.algorithm() == Algorithm.AES && bits != 128 && bits != 192 && bits != 256)
        throw new InvalidKeyException(
            "Expected an AES key of 128, 192 or 256 bits, the key has " + bits);
      Optional<Ttlv> declared = block.child(CRYPTOGRAPHIC_LENGTH);
      if (declared.isPresent() && declared.get().intValue() != bits)
        throw new InvalidKeyException("Declared length does not match the key material");
      String jca = jcaSecretName(expect);
      return material.withBytes(bytes -> new DestroyableSecretKey(bytes, jca));
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw (InvalidKeyException)
          new InvalidKeyException("Malformed key: " + e.getMessage()).initCause(e);
    }
  }

  /** The algorithm the server declared, when it is in the expected family. */
  static Enums.CryptographicAlgorithm declared(Ttlv payload, Tag object, Expect expect)
      throws InvalidKeyException {
    try {
      int code =
          payload.require(object).require(KEY_BLOCK).require(CRYPTOGRAPHIC_ALGORITHM).intValue();
      Algorithm actual = Algorithm.of(code);
      if (actual == expect.algorithm() || (expect.ecFamily() && actual.ellipticCurve()))
        return actual.protocolValue();
      throw new InvalidKeyException("Expected " + expect.algorithm() + ", the key is " + actual);
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw (InvalidKeyException)
          new InvalidKeyException("Malformed key: " + e.getMessage()).initCause(e);
    }
  }

  /** Secret Data: identity, type, format and wrapping are checked. */
  static SecretData secretData(Ttlv payload, String id) throws GeneralSecurityException {
    try {
      if (!payload.require(UNIQUE_IDENTIFIER).textValue().equals(id))
        throw new InvalidKeyException("The server returned a different object");
      if (payload.require(OBJECT_TYPE).intValue() != Enums.ObjectType.SECRET_DATA.code())
        throw new InvalidKeyException("Not Secret Data");
      Ttlv object = payload.require(SECRET_DATA);
      Ttlv block = object.require(KEY_BLOCK);
      Ttlv value = block.require(KEY_VALUE);
      if (value.type() != Ttlv.Type.STRUCTURE || block.child(KEY_WRAPPING_DATA).isPresent())
        throw new InvalidKeyException("The secret is wrapped");
      int format = block.require(KEY_FORMAT_TYPE).intValue();
      if (format != Enums.KeyFormatType.OPAQUE.code() && format != Enums.KeyFormatType.RAW.code())
        throw new InvalidKeyException("Unsupported Secret Data format " + format);
      SecretData.Type type = SecretData.Type.of(object.require(SECRET_DATA_TYPE).intValue());
      return value.require(KEY_MATERIAL).withBytes(bytes -> new SecretData(type, bytes));
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new InvalidKeyException("Malformed Secret Data");
    }
  }
}
