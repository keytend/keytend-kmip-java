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

package dev.keytend.kmip.client;

import dev.keytend.kmip.model.ProtocolVersion;
import java.io.IOException;
import java.util.List;

/**
 * Discover Versions succeeded, but the server offers no version the policy accepts.
 *
 * @since 0.10.0
 */
public final class VersionNegotiationException extends IOException {
  private final List<ProtocolVersion> offered;

  public VersionNegotiationException(List<ProtocolVersion> offered, VersionPolicy policy) {
    super(
        "No KMIP version acceptable to the policy ("
            + policy.minimum()
            + " to "
            + policy.maximum()
            + (policy.allowed().isEmpty() ? "" : ", only " + policy.allowed())
            + "); the server offered "
            + offered);
    this.offered = List.copyOf(offered);
  }

  /** The versions the server offered. */
  public List<ProtocolVersion> offered() {
    return offered;
  }
}
