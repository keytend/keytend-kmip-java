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
 * Encoders and decoders for KMIP messages: {@link dev.keytend.kmip.codec.TtlvCodec} for the binary
 * TTLV encoding, and {@link dev.keytend.kmip.codec.XmlCodec} and {@link
 * dev.keytend.kmip.codec.JsonCodec} for the OASIS XML and JSON profiles. Most applications never
 * use them directly: the transports in {@link dev.keytend.kmip.transport} choose and apply one.
 *
 * <p>Create a codec with {@code new}. The no-argument constructor uses the default limits; the
 * others set the maximum message size, nesting depth and element count. A codec is immutable and
 * can be shared between threads.
 *
 * <p>Malformed input fails with {@link dev.keytend.kmip.codec.DecodeException}. Its message is
 * fixed text that never quotes a decoded value, because values can be key material.
 *
 * <p>This package is in the <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/compatibility.md#api-compatibility">protocol
 * tier</a>.
 */
package dev.keytend.kmip.codec;
