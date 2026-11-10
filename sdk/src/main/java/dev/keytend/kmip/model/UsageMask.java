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

package dev.keytend.kmip.model;

import java.util.*;

/**
 * A Cryptographic Usage Mask: an Integer bit mask, not an Enumeration (encode it with {@link
 * #toTtlv()} or {@link Attributes#usage}, never with {@code Ttlv.enumeration}).
 *
 * <p>Some flags exist only in some versions: Unrestricted, the FPE and PQC flags arrived in 2.0 or
 * later, and 2.0 turned several 1.x flags (Export, Content Commitment, the Translate flags, ...)
 * into Reserved bits. {@link #requireDefinedIn} checks each flag against a version before the
 * set is reduced to an integer, which would lose that information. A permissive mask does not
 * grant capability, ownership or policy on the server.
 *
 * @since 0.10.0
 */
public final class UsageMask {
  private final EnumSet<Enums.CryptographicUsageMask> flags;

  private UsageMask(EnumSet<Enums.CryptographicUsageMask> flags) {
    this.flags = flags;
  }

  public static UsageMask of(Enums.CryptographicUsageMask... flags) {
    EnumSet<Enums.CryptographicUsageMask> set = EnumSet.noneOf(Enums.CryptographicUsageMask.class);
    set.addAll(Arrays.asList(flags));
    return new UsageMask(set);
  }

  public static UsageMask of(Collection<Enums.CryptographicUsageMask> flags) {
    return of(flags.toArray(Enums.CryptographicUsageMask[]::new));
  }

  /** The known flags in a wire value; unknown bits are dropped (see {@link #unknownBits}). */
  public static UsageMask fromInt(int mask) {
    EnumSet<Enums.CryptographicUsageMask> set = EnumSet.noneOf(Enums.CryptographicUsageMask.class);
    for (Enums.CryptographicUsageMask f : Enums.CryptographicUsageMask.values())
      if (Integer.bitCount(f.code()) == 1 && (mask & f.code()) != 0) set.add(f);
    return new UsageMask(set);
  }

  /** Bits of {@code mask} that no known flag defines (vendor or future bits). */
  public static int unknownBits(int mask) {
    return mask & ~fromInt(mask).toInt();
  }

  /**
   * @throws IllegalArgumentException naming the first flag {@code version} does not define: one
   *     introduced later, or one that version lists as Reserved (Export, Content Commitment, the
   *     Cryptogram and Translate flags from 2.0)
   */
  public UsageMask requireDefinedIn(ProtocolVersion version) {
    for (Enums.CryptographicUsageMask f : flags)
      if (!version.atLeast(f.since()))
        throw new IllegalArgumentException(
            "CryptographicUsageMask " + f.wireName() + " requires KMIP " + f.since());
      else if (!f.definedIn(version))
        throw new IllegalArgumentException(
            "CryptographicUsageMask " + f.wireName() + " is Reserved in KMIP " + version);
    return this;
  }

  public Set<Enums.CryptographicUsageMask> flags() {
    return Collections.unmodifiableSet(flags);
  }

  public boolean isEmpty() {
    return flags.isEmpty();
  }

  public int toInt() {
    int mask = 0;
    for (Enums.CryptographicUsageMask f : flags) mask |= f.code();
    return mask;
  }

  /** The modern (2.x/3.0) attribute: an Integer tagged Cryptographic Usage Mask. */
  public Ttlv toTtlv() {
    return Ttlv.integer(Tag.CRYPTOGRAPHIC_USAGE_MASK, toInt());
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof UsageMask m && m.flags.equals(flags);
  }

  @Override
  public int hashCode() {
    return flags.hashCode();
  }

  @Override
  public String toString() {
    return "UsageMask" + flags;
  }
}
