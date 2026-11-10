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
 * keytend-kmip-testing: {@link dev.keytend.kmip.testing.InMemoryKmipServer}, an in-memory KMIP
 * server for tests and for trying the SDK out. Add it in test scope; it is never needed at run
 * time, and never holds real keys.
 *
 * <p><b>Experimental: not for production use</b>, in every release.
 */
module dev.keytend.kmip.testing {
  requires transitive dev.keytend.kmip;

  exports dev.keytend.kmip.testing;
}
