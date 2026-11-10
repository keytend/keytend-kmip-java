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

import dev.keytend.kmip.model.*;
import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.cert.*;
import java.util.*;

/**
 * Typed views of Get response payloads for Certificate, Opaque and PGP Key objects. Each checks
 * the payload's Unique Identifier and Object Type before reading the object.
 *
 * <p>All three report a payload that is not the expected object (another identifier or object
 * type, or a missing or mistyped field) with a checked {@link GeneralSecurityException}, as
 * {@link Keys} does for keys: {@link CertificateException} for certificates, {@link
 * InvalidKeyException} for PGP keys and {@link GeneralSecurityException} for opaque objects.
 *
 * @since 0.10.0
 */
public final class ObjectViews {
  private ObjectViews() {}

  /**
   * The X.509 certificate in a Get payload. The DER must parse and re-encode to exactly the
   * received bytes. This is a decoding check only: no chain, validity period, revocation or trust
   * is evaluated.
   *
   * @throws CertificateException for a wrong identity, type or encoding
   */
  public static X509Certificate certificate(Ttlv payload, String expectedIdentifier)
      throws CertificateException {
    try {
      Ttlv object = object(payload, expectedIdentifier, Enums.ObjectType.CERTIFICATE, CERTIFICATE);
      if (object.require(CERTIFICATE_TYPE).intValue() != Enums.CertificateType.X_509.code())
        throw new CertificateException("Not an X.509 certificate");
      byte[] der = object.require(CERTIFICATE_VALUE).bytesValue();
      X509Certificate cert =
          (X509Certificate)
              CertificateFactory.getInstance("X.509")
                  .generateCertificate(new ByteArrayInputStream(der));
      if (!Arrays.equals(cert.getEncoded(), der))
        throw new CertificateException("Certificate is not in exact DER form");
      return cert;
    } catch (GeneralSecurityException e) {
      throw e instanceof CertificateException c ? c : new CertificateException(e.getMessage(), e);
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new CertificateException("Malformed certificate payload", e);
    }
  }

  /**
   * An Opaque Object: its Opaque Data Type and value. An empty value is an empty array; an absent
   * value is {@code Optional.empty()}.
   */
  public record Opaque(int dataType, Optional<byte[]> value) {
    @Override
    public Optional<byte[]> value() {
      return value.map(byte[]::clone);
    }

    @Override
    public String toString() {
      return "Opaque[dataType=" + dataType + "]";
    }
  }

  /**
   * @throws GeneralSecurityException when the payload is not the expected Opaque Object
   */
  public static Opaque opaque(Ttlv payload, String expectedIdentifier)
      throws GeneralSecurityException {
    try {
      Ttlv object =
          object(payload, expectedIdentifier, Enums.ObjectType.OPAQUE_OBJECT, OPAQUE_OBJECT);
      return new Opaque(
          object.require(OPAQUE_DATA_TYPE).intValue(),
          object.child(OPAQUE_DATA_VALUE).map(Ttlv::bytesValue));
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new GeneralSecurityException("Malformed Opaque Object payload", e);
    }
  }

  /** A PGP Key (KMIP 1.2+): its PGP Key Version and Key Block. */
  public record PgpKey(int version, Ttlv keyBlock) {
    /** The Key Format Type of the key block. */
    public int keyFormat() {
      return keyBlock.require(KEY_FORMAT_TYPE).intValue();
    }

    /** Whether the key block is wrapped (it carries Key Wrapping Data). */
    public boolean wrapped() {
      return keyBlock.child(KEY_WRAPPING_DATA).isPresent();
    }

    /**
     * The raw key material when it is an unwrapped byte string (for example an OpenPGP
     * transferable key); empty for a {@link #wrapped()} key block, whose Key Value holds
     * ciphertext (or a MAC-protected value) rather than the key.
     */
    public Optional<byte[]> material() {
      if (wrapped()) return Optional.empty();
      Ttlv value = keyBlock.require(KEY_VALUE);
      Ttlv material = value.type() == Ttlv.Type.STRUCTURE ? value.require(KEY_MATERIAL) : value;
      return material.type() == Ttlv.Type.BYTE_STRING
          ? Optional.of(material.bytesValue())
          : Optional.empty();
    }
  }

  /**
   * @throws InvalidKeyException when the payload is not the expected PGP Key
   */
  public static PgpKey pgpKey(Ttlv payload, String expectedIdentifier) throws InvalidKeyException {
    try {
      Ttlv object = object(payload, expectedIdentifier, Enums.ObjectType.PGP_KEY, PGP_KEY);
      Ttlv block = object.require(KEY_BLOCK);
      block.require(KEY_VALUE);
      return new PgpKey(object.require(PGP_KEY_VERSION).intValue(), block);
    } catch (GeneralSecurityException e) {
      throw (InvalidKeyException) new InvalidKeyException(e.getMessage()).initCause(e);
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw (InvalidKeyException) new InvalidKeyException("Malformed PGP Key payload").initCause(e);
    }
  }

  private static Ttlv object(Ttlv payload, String id, Enums.ObjectType type, Tag tag)
      throws GeneralSecurityException {
    if (!payload.require(UNIQUE_IDENTIFIER).textValue().equals(id))
      throw new GeneralSecurityException("Unexpected object identifier");
    if (payload.require(OBJECT_TYPE).intValue() != type.code())
      throw new GeneralSecurityException("Unexpected object type, expected " + type.wireName());
    return payload.require(tag);
  }
}
