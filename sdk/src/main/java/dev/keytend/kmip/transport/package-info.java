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

/**
 * Connections to a KMIP server. {@link dev.keytend.kmip.transport.KmipTransport} sends one request
 * message and returns the response. {@link dev.keytend.kmip.transport.TlsTransport} does this over
 * mutually authenticated TLS, with an {@code SSLContext} from {@link
 * dev.keytend.kmip.transport.Tls}. {@link dev.keytend.kmip.transport.HttpsTransport} uses the KMIP
 * HTTPS profile, and {@link dev.keytend.kmip.transport.HashedPasswordTransport} adds
 * hashed-password credentials to another transport.
 *
 * <p>Pass a transport to {@link dev.keytend.kmip.client.KmipClient#negotiated(KmipTransport,
 * dev.keytend.kmip.client.VersionPolicy)}, which then owns it. {@link dev.keytend.kmip.kms.Kms}
 * builds its own transports, unless {@code KmsConfig.Builder.transport} supplies one per endpoint.
 *
 * <p>A {@link dev.keytend.kmip.transport.CallContext} bounds or cancels one call. {@link
 * dev.keytend.kmip.transport.RequestNotSentException} means nothing was sent, so a repeat is safe.
 * After any other {@code IOException}, the request may have reached the server.
 *
 * <p>This package is in the <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/compatibility.md#api-compatibility">protocol
 * tier</a>. Guide: <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/protocol-layer.md">Protocol layer</a>.
 */
package dev.keytend.kmip.transport;
