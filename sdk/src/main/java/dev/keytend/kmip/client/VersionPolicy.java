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
import java.util.*;

/**
 * Which protocol versions a client may negotiate. A version is acceptable when it lies between
 * {@code minimum} and {@code maximum} and, if {@code allowed} is non-empty, is in {@code allowed}.
 * Negotiation picks the highest acceptable version the server offers and fails, before any other
 * request is sent, when there is none.
 *
 * @since 0.10.0
 */
public record VersionPolicy(
    ProtocolVersion minimum, ProtocolVersion maximum, Set<ProtocolVersion> allowed) {
  /** Every supported version, 1.1 through the 3.0 draft. */
  public static final VersionPolicy ANY =
      new VersionPolicy(ProtocolVersion.V1_1, ProtocolVersion.V3_0, Set.of());

  public VersionPolicy {
    Objects.requireNonNull(minimum, "minimum");
    Objects.requireNonNull(maximum, "maximum");
    allowed = Set.copyOf(allowed);
    if (minimum.code() > maximum.code())
      throw new IllegalArgumentException("Minimum version is above the maximum");
    if (!allowed.isEmpty()
        && allowed.stream().noneMatch(v -> v.atLeast(minimum) && maximum.atLeast(v)))
      throw new IllegalArgumentException("No allowed version lies between minimum and maximum");
  }

  /** {@code minimum} up to 2.1 (the newest final specification). */
  public static VersionPolicy atLeast(ProtocolVersion minimum) {
    return between(minimum, minimum.atLeast(ProtocolVersion.V2_1) ? minimum : ProtocolVersion.V2_1);
  }

  public static VersionPolicy between(ProtocolVersion minimum, ProtocolVersion maximum) {
    return new VersionPolicy(minimum, maximum, Set.of());
  }

  public static VersionPolicy only(ProtocolVersion... versions) {
    if (versions.length == 0) throw new IllegalArgumentException("No versions");
    ProtocolVersion min = versions[0], max = versions[0];
    for (ProtocolVersion v : versions) {
      if (!v.atLeast(min)) min = v;
      if (v.atLeast(max)) max = v;
    }
    return new VersionPolicy(min, max, Set.of(versions));
  }

  public boolean accepts(ProtocolVersion version) {
    return version.atLeast(minimum)
        && maximum.atLeast(version)
        && (allowed.isEmpty() || allowed.contains(version));
  }

  /** The highest offered version this policy accepts. */
  public Optional<ProtocolVersion> choose(Collection<ProtocolVersion> offered) {
    return offered.stream()
        .filter(this::accepts)
        .max(Comparator.comparingInt(ProtocolVersion::code));
  }

  /** The same policy with its maximum lowered to {@code cap} (when that is lower). */
  public VersionPolicy capAt(ProtocolVersion cap) {
    ProtocolVersion max = cap.atLeast(maximum) ? maximum : cap;
    if (max.code() < minimum.code())
      throw new IllegalArgumentException("Version cap " + cap + " is below the minimum " + minimum);
    return new VersionPolicy(minimum, max, allowed);
  }

  /** The highest version this policy accepts. */
  public ProtocolVersion highest() {
    ProtocolVersion best = null;
    for (ProtocolVersion v : ProtocolVersion.values()) if (accepts(v)) best = v;
    return best;
  }
}
