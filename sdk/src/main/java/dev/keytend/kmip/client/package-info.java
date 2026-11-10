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
 * The KMIP protocol client: {@link dev.keytend.kmip.client.KmipClient}, the request builders in
 * {@link dev.keytend.kmip.client.Requests}, and the results it returns. Use it for exact control
 * of the wire, or for operations that {@link dev.keytend.kmip.kms.Kms} does not cover. For
 * ordinary key management, use {@code Kms}.
 *
 * <pre>{@code
 * SSLContext ssl = Tls.context(Path.of("client.p12"), password, Path.of("ca.pem"));
 * try (KmipClient client = KmipClient.negotiated(
 *     new TlsTransport("kms.example.com", 5696, ssl),
 *     VersionPolicy.atLeast(ProtocolVersion.V1_4))) {
 *   Result result = client.call(Requests.query().build());
 * }
 * }</pre>
 *
 * <p>{@code password} is the keystore password, a {@code char[]} you own. The negotiated client
 * owns the transport, so closing the client closes the transport. {@link
 * dev.keytend.kmip.kms.Kms#protocol()} instead returns a non-owning client on the current endpoint
 * of a {@code Kms}.
 *
 * <p>Errors: {@code call} throws the unchecked {@link dev.keytend.kmip.client.KmipException} when
 * the server answers with a failure. I/O and protocol problems are checked {@link
 * java.io.IOException}s. After one, the outcome of a mutation is unknown. Nothing is retried.
 *
 * <p>This package is in the <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/compatibility.md#api-compatibility">protocol
 * tier</a>. Guide: <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/protocol-layer.md">Protocol layer</a>.
 */
package dev.keytend.kmip.client;
