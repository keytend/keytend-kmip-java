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
 * A listener for messages that a KMIP server sends to the client: Notify, Put and Query. {@link
 * dev.keytend.kmip.server.CallbackServer} accepts mutually authenticated TLS connections and passes
 * each request to a {@link dev.keytend.kmip.server.CallbackHandler}, or to a {@link
 * dev.keytend.kmip.server.ContextualCallbackHandler} that also sees the peer. {@link
 * dev.keytend.kmip.server.CallbackMessages} builds the protocol-correct responses.
 *
 * <p>Create a listener with {@link dev.keytend.kmip.server.CallbackServer#builder}. It is separate
 * from {@link dev.keytend.kmip.kms.Kms} and {@link dev.keytend.kmip.client.KmipClient}, and most
 * applications do not need it. Close it to stop listening.
 *
 * <p>Every peer that the listener's trust store accepts can push keys and state changes to the
 * handler. Give it a trust store that accepts only the KMIP server's certificate or CA.
 *
 * <p>This package is in the <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/compatibility.md#api-compatibility">protocol
 * tier</a>.
 */
package dev.keytend.kmip.server;
