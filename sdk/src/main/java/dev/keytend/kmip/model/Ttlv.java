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

import java.math.BigInteger;
import java.time.Instant;
import java.util.*;

/**
 * Immutable, lossless KMIP value. Repeated fields and unknown extension tags are retained.
 *
 * <p><b>Secret lifetime.</b> Byte strings are copied when a value is built and again by every
 * {@link #bytesValue()} call, so wiping the array you passed in, or one you got back, does not
 * wipe the copy this object holds. Values cannot be wiped; they become garbage when no longer
 * referenced, and the JVM may have copied them (garbage collection, encoding buffers, {@code
 * String}s for XML/JSON) without any way to zero those copies. Do not keep or log response trees
 * that carry key material, and prefer {@link #withBytes} to read key bytes: its temporary copy is
 * zeroed when the reader returns.
 *
 * @since 0.10.0
 */
public final class Ttlv {
  public enum Type {
    STRUCTURE(1),
    INTEGER(2),
    LONG_INTEGER(3),
    BIG_INTEGER(4),
    ENUMERATION(5),
    BOOLEAN(6),
    TEXT_STRING(7),
    BYTE_STRING(8),
    DATE_TIME(9),
    INTERVAL(10),
    DATE_TIME_EXTENDED(11),
    IDENTIFIER(12),
    REFERENCE(13),
    NAME_REFERENCE(14);
    private final int code;

    Type(int code) {
      this.code = code;
    }

    public int code() {
      return code;
    }

    public static Type of(int code) {
      return Arrays.stream(values())
          .filter(t -> t.code == code)
          .findFirst()
          .orElseThrow(() -> new IllegalArgumentException("Unknown TTLV type: " + code));
    }
  }

  private final int tag;
  private final Type type;
  private final Object value;

  private Ttlv(int tag, Type type, Object value) {
    if ((tag >>> 16) != 0x42 && (tag >>> 16) != 0x54)
      throw new IllegalArgumentException("Invalid KMIP tag: " + Integer.toHexString(tag));
    this.tag = tag;
    this.type = Objects.requireNonNull(type, "type");
    if (value == null) throw new NullPointerException(tagName() + " value is null");
    Class<?> expected =
        switch (type) {
          case STRUCTURE -> List.class;
          case INTEGER, ENUMERATION -> Integer.class;
          case LONG_INTEGER, DATE_TIME, DATE_TIME_EXTENDED, INTERVAL -> Long.class;
          case BIG_INTEGER -> BigInteger.class;
          case BOOLEAN -> Boolean.class;
          case TEXT_STRING, IDENTIFIER, REFERENCE, NAME_REFERENCE -> String.class;
          case BYTE_STRING -> byte[].class;
        };
    if (!expected.isInstance(value))
      throw new IllegalArgumentException(
          tagName()
              + " "
              + type
              + " needs a "
              + expected.getSimpleName()
              + " value, not "
              + value.getClass().getSimpleName());
    this.value =
        switch (type) {
          case STRUCTURE -> List.copyOf(castChildren(value));
          case INTEGER, ENUMERATION -> (Integer) value;
          case LONG_INTEGER, DATE_TIME, DATE_TIME_EXTENDED -> (Long) value;
          case INTERVAL -> {
            long n = (Long) value;
            if (n < 0 || n > 0xffff_ffffL)
              throw new IllegalArgumentException("Interval is unsigned 32-bit");
            yield n;
          }
          case BIG_INTEGER -> (BigInteger) value;
          case BOOLEAN -> (Boolean) value;
          case TEXT_STRING, IDENTIFIER, REFERENCE, NAME_REFERENCE -> {
            String text = (String) value;
            for (int i = 0; i < text.length(); i++) {
              char c = text.charAt(i);
              if (Character.isHighSurrogate(c)) {
                if (++i >= text.length() || !Character.isLowSurrogate(text.charAt(i)))
                  throw new IllegalArgumentException("Invalid Unicode string");
              } else if (Character.isLowSurrogate(c))
                throw new IllegalArgumentException("Invalid Unicode string");
            }
            yield text;
          }
          case BYTE_STRING -> ((byte[]) value).clone();
        };
  }

  @SuppressWarnings("unchecked")
  private static List<Ttlv> castChildren(Object v) {
    List<?> list = (List<?>) v;
    if (list.stream().anyMatch(x -> !(x instanceof Ttlv)))
      throw new IllegalArgumentException("Structure contains a non-TTLV value");
    return (List<Ttlv>) list;
  }

  public static Ttlv of(int tag, Type type, Object value) {
    return new Ttlv(tag, type, value);
  }

  public static Ttlv structure(Tag tag, Ttlv... children) {
    return structure(tag.code(), List.of(children));
  }

  public static Ttlv structure(Tag tag, List<Ttlv> children) {
    return structure(tag.code(), children);
  }

  public static Ttlv structure(int tag, List<Ttlv> children) {
    return of(tag, Type.STRUCTURE, children);
  }

  public static Ttlv integer(Tag tag, int n) {
    return of(tag.code(), Type.INTEGER, n);
  }

  public static Ttlv longInteger(Tag tag, long n) {
    return of(tag.code(), Type.LONG_INTEGER, n);
  }

  public static Ttlv bigInteger(Tag tag, BigInteger n) {
    return of(tag.code(), Type.BIG_INTEGER, n);
  }

  public static Ttlv enumeration(Tag tag, int n) {
    return of(tag.code(), Type.ENUMERATION, n);
  }

  /**
   * An Enumeration whose constant must belong to the tag's enumeration group (for example {@code
   * PaddingMethod} for {@link Tag#PADDING_METHOD}); a constant from another group would silently
   * send a different value. Tags without a standard group, and constants that are not generated
   * {@link Enums} values, are not checked. A mask tag (Cryptographic Usage Mask, ...) is refused:
   * masks are Integers. The {@code int} overload is never checked here; {@link VersionValidator}
   * refuses an Enumeration-typed mask before it is sent.
   */
  public static Ttlv enumeration(Tag tag, WireEnum n) {
    WireEnums.forTag(tag)
        .filter(WireEnums::isMask)
        .ifPresent(
            group -> {
              throw new IllegalArgumentException(
                  tag.wireName()
                      + " is an Integer bit mask, not an Enumeration (use UsageMask or Ttlv.integer)");
            });
    if (n.getClass().getEnclosingClass() == Enums.class || n instanceof Operation)
      WireEnums.forTag(tag)
          .filter(group -> !group.isInstance(n))
          // Some groups were renamed between versions (Object Group Member Option in 1.x is
          // Object Group Member in 2.x); a group named after the tag is also accepted.
          .filter(
              group ->
                  !Tag.normalize(n.getClass().getSimpleName())
                      .equals(Tag.normalize(tag.wireName())))
          .ifPresent(
              group -> {
                throw new IllegalArgumentException(
                    tag.wireName()
                        + " takes "
                        + group.getSimpleName()
                        + " values, not "
                        + n.getClass().getSimpleName()
                        + "."
                        + n);
              });
    return enumeration(tag, n.code());
  }

  public static Ttlv bool(Tag tag, boolean n) {
    return of(tag.code(), Type.BOOLEAN, n);
  }

  public static Ttlv text(Tag tag, String n) {
    return of(tag.code(), Type.TEXT_STRING, n);
  }

  public static Ttlv bytes(Tag tag, byte[] n) {
    return of(tag.code(), Type.BYTE_STRING, n);
  }

  public static Ttlv dateTime(Tag tag, Instant n) {
    if (n.getNano() != 0) throw new IllegalArgumentException("KMIP DateTime has second precision");
    return of(tag.code(), Type.DATE_TIME, n.getEpochSecond());
  }

  public static Ttlv interval(Tag tag, long seconds) {
    return of(tag.code(), Type.INTERVAL, seconds);
  }

  public static Ttlv identifier(Tag tag, String value) {
    return of(tag.code(), Type.IDENTIFIER, value);
  }

  public static Ttlv reference(Tag tag, String value) {
    return of(tag.code(), Type.REFERENCE, value);
  }

  public static Ttlv nameReference(Tag tag, String value) {
    return of(tag.code(), Type.NAME_REFERENCE, value);
  }

  public static Ttlv dateTimeExtended(Tag tag, Instant value) {
    if (value.getNano() % 1000 != 0)
      throw new IllegalArgumentException("Extended DateTime has microsecond precision");
    return of(
        tag.code(),
        Type.DATE_TIME_EXTENDED,
        Math.addExact(
            Math.multiplyExact(value.getEpochSecond(), 1_000_000L), value.getNano() / 1000));
  }

  public int tag() {
    return tag;
  }

  public Optional<Tag> standardTag() {
    return Tag.fromCode(tag);
  }

  public String tagName() {
    return standardTag().map(Tag::wireName).orElse(String.format("0x%06X", tag));
  }

  public Type type() {
    return type;
  }

  public Object value() {
    return type == Type.BYTE_STRING ? ((byte[]) value).clone() : value;
  }

  public List<Ttlv> children() {
    require(Type.STRUCTURE);
    return castChildren(value);
  }

  public int intValue() {
    if (type != Type.INTEGER && type != Type.ENUMERATION) throw badType();
    return (Integer) value;
  }

  public long longValue() {
    if (type != Type.LONG_INTEGER
        && type != Type.DATE_TIME
        && type != Type.INTERVAL
        && type != Type.DATE_TIME_EXTENDED) throw badType();
    return (Long) value;
  }

  public BigInteger bigIntegerValue() {
    require(Type.BIG_INTEGER);
    return (BigInteger) value;
  }

  public boolean booleanValue() {
    require(Type.BOOLEAN);
    return (Boolean) value;
  }

  public String textValue() {
    if (type != Type.TEXT_STRING
        && type != Type.IDENTIFIER
        && type != Type.REFERENCE
        && type != Type.NAME_REFERENCE) throw badType();
    return (String) value;
  }

  public byte[] bytesValue() {
    require(Type.BYTE_STRING);
    return ((byte[]) value).clone();
  }

  /** The length of a Byte String, without copying it. */
  public int byteLength() {
    require(Type.BYTE_STRING);
    return ((byte[]) value).length;
  }

  /**
   * Passes a temporary copy of a Byte String to {@code reader} and zeroes that copy afterwards.
   * The reader must not keep the array.
   */
  public <T> T withBytes(java.util.function.Function<byte[], T> reader) {
    byte[] copy = bytesValue();
    try {
      return reader.apply(copy);
    } finally {
      Arrays.fill(copy, (byte) 0);
    }
  }

  public Instant instantValue() {
    if (type == Type.DATE_TIME_EXTENDED)
      return Instant.ofEpochSecond(
          Math.floorDiv((Long) value, 1_000_000L), Math.floorMod((Long) value, 1_000_000L) * 1000);
    require(Type.DATE_TIME);
    return Instant.ofEpochSecond((Long) value);
  }

  public Optional<Ttlv> child(Tag tag) {
    return child(tag.code());
  }

  public Optional<Ttlv> child(int tag) {
    return children().stream().filter(n -> n.tag == tag).findFirst();
  }

  public Ttlv require(Tag tag) {
    return child(tag)
        .orElseThrow(() -> new IllegalArgumentException(tagName() + " missing " + tag.wireName()));
  }

  public List<Ttlv> children(Tag tag) {
    return children().stream().filter(n -> n.tag == tag.code()).toList();
  }

  public Ttlv retag(Tag tag) {
    return of(tag.code(), type, value);
  }

  public Ttlv retag(int tag) {
    return of(tag, type, value);
  }

  private void require(Type expected) {
    if (type != expected) throw badType();
  }

  private IllegalStateException badType() {
    return new IllegalStateException(tagName() + " is " + type);
  }

  @Override
  public boolean equals(Object other) {
    if (!(other instanceof Ttlv n) || n.tag != tag || n.type != type) return false;
    return type == Type.BYTE_STRING
        ? Arrays.equals((byte[]) value, (byte[]) n.value)
        : value.equals(n.value);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        tag, type, type == Type.BYTE_STRING ? Arrays.hashCode((byte[]) value) : value);
  }

  /** Avoids revealing key material, credentials, or other payload values in logs. */
  @Override
  public String toString() {
    return tagName()
        + "("
        + type
        + (type == Type.STRUCTURE ? ", " + children().size() + " children" : "")
        + ")";
  }
}
