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
 * KMIP values and the specification's vocabulary. {@link dev.keytend.kmip.model.Ttlv} is one
 * TTLV value, a tree of tagged fields. {@link dev.keytend.kmip.model.Tag}, {@link
 * dev.keytend.kmip.model.Enums} and {@link dev.keytend.kmip.model.Operation} list the standard
 * codes, and {@link dev.keytend.kmip.model.ProtocolVersion} the wire versions.
 *
 * <p>Static helpers build common structures: {@link dev.keytend.kmip.model.Attributes} and {@link
 * dev.keytend.kmip.model.ModernAttributes} for attributes, {@link
 * dev.keytend.kmip.model.ManagedObjects} for keys, certificates and secrets, and {@link
 * dev.keytend.kmip.model.Credentials} for request authentication. {@link
 * dev.keytend.kmip.model.Keys} checks a Get payload and turns it into a JCA key.
 *
 * <p>The application API ({@link dev.keytend.kmip.kms}) names a few of these types in its
 * signatures, such as {@code ProtocolVersion} and some {@code Enums}. Values are immutable and
 * safe to share between threads.
 * Byte strings are copied in and out, so they cannot be wiped (see <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/protocol-layer.md#secret-lifetime">Secret
 * lifetime</a>).
 *
 * <p>This package is in the <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/compatibility.md#api-compatibility">protocol
 * tier</a>.
 */
package dev.keytend.kmip.model;
