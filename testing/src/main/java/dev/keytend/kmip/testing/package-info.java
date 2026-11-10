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
 * Test support, in its own artifact {@code keytend-kmip-testing} (a test dependency, never needed
 * at run time): {@link dev.keytend.kmip.testing.InMemoryKmipServer}, a strict
 * in-memory KMIP server that a real {@link dev.keytend.kmip.kms.Kms} connects to, with
 * application-level inspection and {@link dev.keytend.kmip.testing.Fault fault injection}, and
 * {@link dev.keytend.kmip.testing.TlsListener}, which serves it over TLS.
 *
 * <pre>{@code
 * InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
 * try (Kms kms = server.connect()) {
 *   // ... code under test ...
 * }
 * }</pre>
 *
 * <p>This package is outside the compatibility promises of the SDK's other packages (<a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/compatibility.md#the-testing-package">The
 * testing package</a>). Any minor release may change it, and the release notes list each change.
 * The application-level methods change least. Where practical, they are deprecated for one minor
 * release first. The protocol-level hooks may change in any release: those named {@code
 * protocol...} or {@code inject...}, or taking KMIP types.
 *
 * <p>The server is not a key manager: never give it real keys.
 */
package dev.keytend.kmip.testing;
