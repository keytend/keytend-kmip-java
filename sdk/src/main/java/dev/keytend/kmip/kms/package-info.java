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
 * The application API: keys, certificates and server-side cryptography with JCA types, typed
 * records and one exception hierarchy, the same on every negotiated KMIP version.
 *
 * <h2>Getting started</h2>
 *
 * <pre>{@code
 * KmsConfig config = KmsConfig.builder()
 *     .endpoints("kms1:5696", "kms2:5696")
 *     .clientIdentityKeyStore(Path.of("client.p12"), password)
 *     .trustPem(Path.of("ca.pem"))
 *     .build();
 * try (Kms kms = Kms.connect(config)) {
 *   kms.keys().createAes(256).named("orders-kek")
 *       .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).findOrCreate();
 *   CurrentKey kek = kms.keys().current("orders-kek");
 *   byte[] sealed = kek.seal(orderJson, orderId);
 *   byte[] opened = kek.open(sealed, orderId);
 * }
 * }</pre>
 *
 * <p>A key name is not an access-control boundary. Anyone who may create keys on the server can
 * create one with your name. Where that matters, keep and use the key's handle, use a server that
 * enforces unique names, or select keys by an attribute only you can set.
 *
 * <p>{@code password} is the PKCS#12 file's password, a {@code char[]}. {@code orderJson} is the
 * record and {@code orderId} its identifier, both {@code byte[]}. {@code seal} binds the
 * identifier as additional data, so the record opens only with it. See <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/getting-started.md#connect-to-your-kms">Getting
 * started</a>.
 *
 * <h2>Main types</h2>
 *
 * <ul>
 *   <li>{@link dev.keytend.kmip.kms.Kms}: the connection to the KMS, and the entry point.
 *   <li>{@link dev.keytend.kmip.kms.KmsKeys}: creates, registers and finds keys and other objects.
 *   <li>{@link dev.keytend.kmip.kms.CurrentKey}: the newest key of a lineage, to seal, open and
 *       rotate with.
 *   <li>{@link dev.keytend.kmip.kms.KeyHandle}: one server object, with its attributes, lifecycle
 *       and cryptography.
 *   <li>{@link dev.keytend.kmip.kms.LocalKeys}: a cache of raw keys taken out of the KMS.
 *   <li>{@link dev.keytend.kmip.kms.KmsTls}: TLS identities and trust anchors kept in the KMS.
 * </ul>
 *
 * <p>{@link dev.keytend.kmip.kms.Kms#protocol()} reaches the protocol layer for operations this API
 * does not cover. <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md">Choosing an
 * API</a> says which entry point fits each job.
 *
 * <h2>Errors</h2>
 *
 * Every failure the server or the network causes is a {@link dev.keytend.kmip.kms.KmsException}
 * subtype. Read-only operations are retried on the next endpoint after a {@link
 * dev.keytend.kmip.kms.TransientException}. A mutation is never re-sent, and one whose outcome is
 * unknown raises {@link dev.keytend.kmip.kms.OutcomeUnknownException}. Misuse throws {@code
 * NullPointerException}, {@code IllegalArgumentException} or {@code IllegalStateException}. A
 * feature the negotiated version lacks raises {@link dev.keytend.kmip.kms.UnsupportedException}
 * before anything is sent (see <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/compatibility.md#kmip-versions">KMIP
 * versions</a>). See <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/getting-started.md#handle-failures">Handle
 * failures</a>.
 *
 * <h2>Conventions</h2>
 *
 * Every member of this package follows these rules unless its own documentation says otherwise.
 *
 * <ul>
 *   <li><b>Null.</b> Parameters must not be null: passing null is misuse, reported with a {@code
 *       NullPointerException}. A parameter that accepts null says so, and what null means. Methods
 *       do not return null. A value that may be absent is an {@code Optional}, an empty collection
 *       or array, or documented as "or null" (for example {@link
 *       dev.keytend.kmip.kms.Algorithm#protocolValue()}).
 *   <li><b>Arrays.</b> An array argument is read during the call, and copied if it is kept, so the
 *       caller may reuse or wipe it once the call returns. A returned array is a new one, owned by
 *       the caller. Exceptions to this rule say so, for example {@link
 *       dev.keytend.kmip.kms.Rewrapped#bytes()}.
 *   <li><b>Resources.</b> The caller owns what a method returns, and closes or destroys it. That
 *       covers a {@link dev.keytend.kmip.kms.Kms}, the secrets ({@link
 *       dev.keytend.kmip.kms.DestroyableSecretKey}, {@link dev.keytend.kmip.kms.DataKey}, {@link
 *       dev.keytend.kmip.kms.SecretData}), the envelope streams, sealers and openers, and the TLS
 *       followers. Handles ({@link dev.keytend.kmip.kms.KeyHandle}, {@link
 *       dev.keytend.kmip.kms.KeyPairHandle}) hold no resource. They name server objects and work
 *       while their {@code Kms} is open. A {@link dev.keytend.kmip.kms.CurrentKey} holds one only
 *       once {@link dev.keytend.kmip.kms.CurrentKey#refreshingEvery} schedules a task, which {@link
 *       dev.keytend.kmip.kms.CurrentKey#close()} cancels. A stream passed in stays the caller's,
 *       except where the method says the stream it returns owns it ({@code sealing} and {@code
 *       opening}).
 *   <li><b>Threads.</b> {@code Kms}, {@code KmsKeys}, {@code KmsTls} and the handles are
 *       thread-safe. Values (records, enums, exceptions, {@link dev.keytend.kmip.kms.Ciphertext},
 *       {@link dev.keytend.kmip.kms.CipherSpec}, {@link dev.keytend.kmip.kms.KeyAttributes}, {@link
 *       dev.keytend.kmip.kms.KeyQuery} and the other specs) are immutable. Builders are not
 *       thread-safe. A type that differs says so in its own documentation.
 *   <li><b>Secrets.</b> {@code destroy()} on a secret zeroes the SDK's copy, and the SDK keeps no
 *       other. The SDK also wipes the temporary key bytes it creates while registering, wrapping
 *       and unwrapping. Arrays passed to or returned by this API, JCA key objects and copies made
 *       by the JDK are not wiped (<a
 *       href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/kms-design.md#secrets">the
 *       full list</a>). No {@code toString()} prints key material. Zeroization in Java is
 *       best-effort, so destroy keys promptly.
 * </ul>
 *
 * <h2>Testing</h2>
 *
 * Tests connect a real {@code Kms} to {@code dev.keytend.kmip.testing.InMemoryKmipServer}, from the
 * test dependency {@code keytend-kmip-testing} (see <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/getting-started.md#test-without-a-server">Test
 * without a server</a>).
 */
package dev.keytend.kmip.kms;
