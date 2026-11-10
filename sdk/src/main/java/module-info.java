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
 * keytend-kmip: a KMIP client for Java 17 and later.
 *
 * <p><b>Experimental: not for production use</b>, in every release.
 *
 * <p>Applications start with {@link dev.keytend.kmip.kms}. The protocol layer is {@link
 * dev.keytend.kmip.client} and the packages it uses: {@link dev.keytend.kmip.model}, {@link
 * dev.keytend.kmip.codec}, {@link dev.keytend.kmip.transport} and {@link dev.keytend.kmip.server}.
 * The in-memory KMIP server for tests is in its own module, {@code dev.keytend.kmip.testing}
 * (the {@code keytend-kmip-testing} artifact, a test dependency).
 *
 * <p>Each group of packages has its own <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/compatibility.md#api-compatibility">compatibility
 * tier</a>.
 */
module dev.keytend.kmip {
  requires java.net.http;
  requires java.xml;
  // Logging, by logger name (docs/production.md); no SLF4J type is in the API.
  requires org.slf4j;
  // Caches. The JAR bundles Caffeine, relocated into dev.keytend.kmip.internal.shaded.caffeine;
  // its descriptor is this one without the next line (sdk/pom.xml, "The bundled Caffeine").
  requires com.github.benmanes.caffeine;

  exports dev.keytend.kmip.kms;
  exports dev.keytend.kmip.client;
  exports dev.keytend.kmip.model;
  exports dev.keytend.kmip.codec;
  exports dev.keytend.kmip.transport;
  exports dev.keytend.kmip.server;
}
