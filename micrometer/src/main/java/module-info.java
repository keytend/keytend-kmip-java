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
 * keytend-kmip-micrometer: Micrometer meters for keytend-kmip, opt-in. {@link
 * dev.keytend.kmip.micrometer.KmipMeters} has a listener for a {@code KmsConfig} and binders for a
 * {@code Kms}, a {@code LocalKeys} cache and a TLS identity follower.
 *
 * <p><b>Experimental: not for production use</b>, in every release.
 */
// micrometer.core is an automatic module (its JAR has no module-info, only an
// Automatic-Module-Name), which javac's requires-automatic and requires-transitive-automatic lints
// warn of, and -Werror would fail on. Suppressed here only, on this descriptor, for that one
// requirement: the API shows MeterRegistry, so it is required transitively. Lint stays on
// everywhere else.
@SuppressWarnings({"requires-automatic", "requires-transitive-automatic"})
module dev.keytend.kmip.micrometer {
  requires transitive dev.keytend.kmip;
  requires transitive micrometer.core;

  exports dev.keytend.kmip.micrometer;
}
