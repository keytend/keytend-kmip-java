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

package dev.keytend.kmip.testing;

import dev.keytend.kmip.model.Operation;

/**
 * A request the {@link InMemoryKmipServer} receives, for {@link InMemoryKmipServer#failNext}: the
 * KMIP operation an application call sends, named without protocol types. One application call
 * may send several (for example {@code create()} sends Create, then Activate; retrieving key
 * material reads its attributes, then sends Get).
 *
 * <p>Test support, outside the compatibility promises, like the rest of this package (<a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/compatibility.md#the-testing-package">The
 * testing package</a>).
 *
 * @since 0.10.0
 */
public enum ServerOperation {
  /**
   * Any request below except {@link #DISCOVER_VERSIONS} (arm that one explicitly) and the Query the
   * SDK sends on its own.
   */
  ANY(null),
  /** Create: creating a symmetric key. */
  CREATE(Operation.CREATE),
  /** Create Key Pair: creating a key pair. */
  CREATE_KEY_PAIR(Operation.CREATE_KEY_PAIR),
  /** Register: registering a key, certificate or secret. */
  REGISTER(Operation.REGISTER),
  /** Re-key ({@code rotate()}). */
  RE_KEY(Operation.RE_KEY),
  /** Get: reading key material, a certificate or secret data. */
  GET(Operation.GET),
  /** Get Attributes: {@code attributes()}, the state check before Get, and most lookups. */
  GET_ATTRIBUTES(Operation.GET_ATTRIBUTES),
  /** Get Attribute List. */
  GET_ATTRIBUTE_LIST(Operation.GET_ATTRIBUTE_LIST),
  /** Locate: finding objects by name, group or other attributes. */
  LOCATE(Operation.LOCATE),
  /** Add Attribute. */
  ADD_ATTRIBUTE(Operation.ADD_ATTRIBUTE),
  /** Modify Attribute. */
  MODIFY_ATTRIBUTE(Operation.MODIFY_ATTRIBUTE),
  /** Set Attribute (KMIP 2.0 and later). */
  SET_ATTRIBUTE(Operation.SET_ATTRIBUTE),
  /** Delete Attribute. */
  DELETE_ATTRIBUTE(Operation.DELETE_ATTRIBUTE),
  /** Activate. */
  ACTIVATE(Operation.ACTIVATE),
  /** Revoke: revoking or (up to KMIP 2.1) deactivating an object. */
  REVOKE(Operation.REVOKE),
  /** Deactivate (KMIP 3.0: {@code KeyHandle.deactivate()}, and retiring keys there). */
  DEACTIVATE(Operation.DEACTIVATE),
  /** Destroy. */
  DESTROY(Operation.DESTROY),
  /** Encrypt, also for wrapping a key. */
  ENCRYPT(Operation.ENCRYPT),
  /** Decrypt, also for unwrapping a key. */
  DECRYPT(Operation.DECRYPT),
  /** Sign. */
  SIGN(Operation.SIGN),
  /** Signature Verify. */
  VERIFY(Operation.SIGNATURE_VERIFY),
  /** MAC: computing a MAC. */
  MAC(Operation.MAC),
  /** MAC Verify. */
  MAC_VERIFY(Operation.MAC_VERIFY),
  /** RNG Retrieve ({@code kms.random(n)}). */
  RANDOM(Operation.RNG_RETRIEVE),
  /**
   * Obtain Lease: what a raw-key or TLS read sends after Get Attributes and before Get, for an
   * object that states a Lease Time ({@link InMemoryKmipServer#leaseTime}).
   *
   * @since 0.10.0
   */
  OBTAIN_LEASE(Operation.OBTAIN_LEASE),
  /**
   * Certify: what {@code kms.tls().issue(name)} and a reissue send to have the KMS issue a
   * certificate.
   *
   * @since 0.10.0
   */
  CERTIFY(Operation.CERTIFY),
  /**
   * Discover Versions: {@code kms.ping()}, the version negotiation of {@code Kms.connect}, and the
   * probe a {@code Kms} sends to an endpoint before its first request there, so a test can make a
   * readiness check fail or {@code connect} fail over. Not included in {@link #ANY}, so that
   * arming {@code ANY} still fails the application's next request.
   */
  DISCOVER_VERSIONS(Operation.DISCOVER_VERSIONS),

  /**
   * Query: {@code kms.serverInfo()}, and the SDK's own capability checks. Not included in {@link
   * #ANY}, as Discover Versions is not.
   *
   * @since 0.10.0
   */
  QUERY(Operation.QUERY),

  /**
   * Re-Provision: a client certificate renewal ({@code renewClientCertificate()}), through a
   * {@link TlsListener} with a provisioning CA.
   *
   * @since 0.10.0
   */
  RE_PROVISION(Operation.RE_PROVISION);

  private final Operation protocol;

  ServerOperation(Operation protocol) {
    this.protocol = protocol;
  }

  /** Whether a request item with operation {@code op} is one of these. */
  boolean matches(Operation op) {
    if (this == ANY) return op != Operation.DISCOVER_VERSIONS && op != Operation.QUERY;
    return op == protocol;
  }
}
