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
 * Lookups between wire codes, enumeration constants and the tags that carry them.
 *
 * <p>Standard tags whose value is an enumeration, or an Integer mask, map to their {@link Enums}
 * group: {@code CryptographicAlgorithm} to {@link Enums.CryptographicAlgorithm}, {@code
 * CryptographicUsageMask} to {@link Enums.CryptographicUsageMask}, and so on. Unknown codes
 * (vendor values in the {@code 0x8XXXXXXX} range, or values from a newer specification) have no
 * constant; use the raw {@code int}.
 *
 * @since 0.10.0
 */
public final class WireEnums {
  private WireEnums() {}

  private static final Map<String, Class<? extends WireEnum>> GROUPS = groups();
  private static final Map<Class<?>, Map<Integer, WireEnum>> BY_CODE = new HashMap<>();

  private static Map<String, Class<? extends WireEnum>> groups() {
    Map<String, Class<? extends WireEnum>> groups = new HashMap<>();
    for (Class<?> c : Enums.class.getDeclaredClasses())
      if (WireEnum.class.isAssignableFrom(c) && c.isEnum())
        groups.put(Tag.normalize(c.getSimpleName()), c.asSubclass(WireEnum.class));
    groups.put("operation", Operation.class);
    // Tags whose names differ from their enumeration group.
    Map<String, String> aliases =
        Map.of(
            "batcherrorcontinuationoption", "batcherrorcontinuation",
            "objectgroupmember", "objectgroupmemberoption",
            "maskgeneratorhashingalgorithm", "hashingalgorithm",
            "profilename", "profilenametype",
            "destroyaction", "destroyactiontype",
            "fips186variant", "fips186variation");
    aliases.forEach((tag, group) -> groups.put(tag, groups.get(group)));
    return Map.copyOf(groups);
  }

  /** The constant for {@code code}, or empty for a vendor, future or invalid value. */
  public static <E extends Enum<E> & WireEnum> Optional<E> fromCode(Class<E> type, int code) {
    return Optional.ofNullable(type.cast(index(type).get(code)));
  }

  /** The constant for {@code code}; {@link IllegalArgumentException} names the group and code. */
  public static <E extends Enum<E> & WireEnum> E requireCode(Class<E> type, int code) {
    return fromCode(type, code)
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "Unknown "
                        + type.getSimpleName()
                        + " value: "
                        + String.format("0x%08X", code)));
  }

  /** The enumeration or mask group carried by a standard tag, if it has one. */
  public static Optional<Class<? extends WireEnum>> forTag(Tag tag) {
    return Optional.ofNullable(GROUPS.get(Tag.normalize(tag.wireName())));
  }

  /** The group for a KMIP 1.x attribute name such as {@code "Cryptographic Usage Mask"}. */
  public static Optional<Class<? extends WireEnum>> forAttributeName(String name) {
    return Optional.ofNullable(GROUPS.get(Tag.normalize(name)));
  }

  /** True for Integer bit masks (Cryptographic Usage Mask, Storage Status Mask, ...). */
  public static boolean isMask(Class<? extends WireEnum> group) {
    return group.getSimpleName().endsWith("Mask");
  }

  /** The known constant of an arbitrary group, without a type parameter. */
  public static Optional<WireEnum> constant(Class<? extends WireEnum> group, int code) {
    return Optional.ofNullable(index(group).get(code));
  }

  private static Map<Integer, WireEnum> index(Class<?> type) {
    synchronized (BY_CODE) {
      return BY_CODE.computeIfAbsent(
          type,
          t -> {
            Map<Integer, WireEnum> map = new HashMap<>();
            for (Object constant : t.getEnumConstants()) {
              WireEnum e = (WireEnum) constant;
              map.putIfAbsent(e.code(), e);
            }
            return Map.copyOf(map);
          });
    }
  }
}
