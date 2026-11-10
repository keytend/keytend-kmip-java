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

/**
 * Credential choices and vendor message extensions. Authentication is independent of TLS identity.
 *
 * @since 0.10.0
 */
public final class Credentials {
  private Credentials() {}

  /** The Credential Value fields are emitted in the Credential Type's table order. */
  public static Ttlv credential(Enums.CredentialType type, Ttlv... fields) {
    return structure(
        CREDENTIAL,
        enumeration(CREDENTIAL_TYPE, type),
        Structures.credentialValue(type, java.util.List.of(fields)));
  }

  public static Ttlv usernamePassword(String username, String password) {
    return credential(
        Enums.CredentialType.USERNAME_AND_PASSWORD,
        text(USERNAME, username),
        text(PASSWORD, password));
  }

  /**
   * A username/password Credential from a {@code char[]}. KMIP's Password is a Text String, so the
   * value becomes a {@code String} inside the Credential and cannot be wiped; this overload only
   * avoids a {@code String} in the caller's code.
   */
  public static Ttlv usernamePassword(String username, char[] password) {
    return usernamePassword(username, new String(password));
  }

  public static Ttlv device(Ttlv... identifiers) {
    return credential(Enums.CredentialType.DEVICE, identifiers);
  }

  public static Ttlv attestation(Ttlv... nonceAndAttestationFields) {
    return credential(Enums.CredentialType.ATTESTATION, nonceAndAttestationFields);
  }

  public static Ttlv authentication(Ttlv... credentials) {
    return structure(AUTHENTICATION, credentials);
  }

  public static Ttlv extension(String vendor, boolean critical, Ttlv... vendorFields) {
    return structure(
        MESSAGE_EXTENSION,
        text(VENDOR_IDENTIFICATION, vendor),
        bool(CRITICALITY_INDICATOR, critical),
        structure(VENDOR_EXTENSION, vendorFields));
  }
}
