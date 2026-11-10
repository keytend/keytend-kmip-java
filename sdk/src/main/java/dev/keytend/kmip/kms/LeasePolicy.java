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

/**
 * What the SDK does with a key whose Get Attributes states a KMIP Lease Time (1.4 §3.20, 2.1
 * §4.30) before it hands the key's material to the application ({@link KmsConfig.Builder#leases}).
 *
 * @since 0.10.0
 */
public enum LeasePolicy {
  /**
   * The default: the material is used only under a lease the server granted (Obtain Lease, 1.4
   * §4.17, 2.1 §6.1.35). Any refusal, also from a server that does not implement Obtain Lease,
   * hands nothing out.
   */
  REQUIRE,
  /**
   * As {@link #REQUIRE} where the server implements Obtain Lease. A server that states a Lease Time
   * and does not implement Obtain Lease gives the client no way to obtain one: there, and only
   * there, the stated Lease Time is used as a hard local bound instead, counted from before the
   * Obtain Lease was sent and never extended without another attempt. That the server does not
   * implement it is decided by its answer (Operation Not Supported, or a message-level Invalid
   * Message, the request not being understood at all) confirmed by its own list of operations
   * (Query Operations, read once per {@link Kms} and kept): a server that lists Obtain Lease, or
   * answers it otherwise (Permission Denied, a state refusal, an outage), is treated as under
   * {@link #REQUIRE}. A stated Lease Time of zero, or a malformed one, gives no bound and stays
   * refused. Each key used this way is told once to {@link KmsListener#leaseNotGranted}.
   *
   * <p>This is an operator's decision for one server, not KMIP: such a server cannot recall a copy,
   * and the SDK cannot learn of a revocation before the bound ends (keep the bound short, or the
   * {@link LocalKeys} TTL shorter).
   *
   * @since 0.10.0
   */
  HONOR_IF_SUPPORTED
}
