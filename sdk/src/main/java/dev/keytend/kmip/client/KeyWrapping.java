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
 * A typed Key Wrapping Specification for Get and Export (KMIP 1.4 §2.1.6 and 2.1 §2.1.6): wrap
 * the returned key with a server-held key encryption key.
 *
 * <p>The server checks that the requested mode matches a Cryptographic Parameters instance stored
 * on the wrapping key, so register or create the KEK with matching parameters (for example AES
 * with Block Cipher Mode NISTKeyWrap) and Wrap Key / Unwrap Key usage.
 *
 * <pre>{@code
 * KeyWrapping spec = KeyWrapping.encrypt(kekId, CryptoParameters.builder()
 *     .mode(Enums.BlockCipherMode.NISTKEY_WRAP).build()).noEncoding();
 * Result wrapped = client.call(Requests.get().uniqueIdentifier(keyId).add(spec.toTtlv()).build());
 * }</pre>
 *
 * <p>Wrapping methods: {@link #encrypt} alone is Encrypt; {@link #macOrSign} added to it is
 * Encrypt-then-MAC/sign; {@link #macSign} alone is MAC/sign (the key is authenticated, not
 * encrypted). Attributes named with {@link #wrapAttribute} are sent as Attribute Name up to 2.1
 * and converted to Attribute Reference for 3.0 when the request is encoded.
 *
 * @since 0.10.0
 */
public final class KeyWrapping {
  private final Ttlv encryptionKey; // null for MAC/sign-only wrapping
  private Ttlv macKey;
  private Enums.EncodingOption encoding;
  private final List<String> attributeNames = new ArrayList<>();

  private KeyWrapping(Ttlv encryptionKey) {
    this.encryptionKey = encryptionKey;
  }

  /** Encrypt-only wrapping with {@code kekId}; {@code parameters} may be null. */
  public static KeyWrapping encrypt(String kekId, CryptoParameters parameters) {
    List<Ttlv> fields = new ArrayList<>(List.of(text(UNIQUE_IDENTIFIER, kekId)));
    if (parameters != null) fields.add(parameters.toTtlv());
    return new KeyWrapping(structure(ENCRYPTION_KEY_INFORMATION, fields));
  }

  /**
   * MAC/sign-only wrapping (Wrapping Method MAC/sign) with {@code keyId}: the key is returned
   * in the clear with a MAC or signature over it. {@code parameters} may be null.
   */
  public static KeyWrapping macSign(String keyId, CryptoParameters parameters) {
    return new KeyWrapping(null).macOrSign(keyId, parameters);
  }

  /**
   * Adds MAC/signature key information: on an {@link #encrypt} specification the wrapping method
   * becomes Encrypt-then-MAC/sign; on a {@link #macSign} specification it replaces the key.
   */
  public KeyWrapping macOrSign(String keyId, CryptoParameters parameters) {
    List<Ttlv> fields =
        new ArrayList<>(List.of(text(UNIQUE_IDENTIFIER, Objects.requireNonNull(keyId, "keyId"))));
    if (parameters != null) fields.add(parameters.toTtlv());
    macKey = structure(MAC_SIGNATURE_KEY_INFORMATION, fields);
    return this;
  }

  /** Encoding Option No Encoding: wrap the raw key bytes rather than a TTLV Key Value. */
  public KeyWrapping noEncoding() {
    encoding = Enums.EncodingOption.NO_ENCODING;
    return this;
  }

  public KeyWrapping encoding(Enums.EncodingOption option) {
    encoding = option;
    return this;
  }

  /**
   * Attributes to wrap together with the key, by 1.x name (for example "Cryptographic Usage
   * Mask", or an {@code x-}/{@code y-} custom name). KMIP 3.0 selects them by Attribute
   * Reference; the conversion happens when the request is encoded for 3.0.
   */
  public KeyWrapping wrapAttribute(String name) {
    attributeNames.add(Objects.requireNonNull(name));
    return this;
  }

  public Ttlv toTtlv() {
    List<Ttlv> fields = new ArrayList<>();
    fields.add(
        enumeration(
            WRAPPING_METHOD,
            encryptionKey == null
                ? Enums.WrappingMethod.MAC_SIGN
                : macKey == null
                    ? Enums.WrappingMethod.ENCRYPT
                    : Enums.WrappingMethod.ENCRYPT_THEN_MAC_SIGN));
    if (encryptionKey != null) fields.add(encryptionKey);
    if (macKey != null) fields.add(macKey);
    for (String name : attributeNames) fields.add(text(ATTRIBUTE_NAME, name));
    if (encoding != null) fields.add(enumeration(ENCODING_OPTION, encoding));
    return Structures.structure(KEY_WRAPPING_SPECIFICATION, fields.toArray(Ttlv[]::new));
  }
}
