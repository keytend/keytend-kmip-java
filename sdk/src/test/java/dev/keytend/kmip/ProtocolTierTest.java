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

package dev.keytend.kmip;

import static org.junit.jupiter.api.Assertions.*;

import java.lang.reflect.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import org.junit.jupiter.api.Test;

/**
 * The protocol tier's fixed points (docs/compatibility.md "API compatibility"):
 * every protocol-tier type an application-tier ({@code kms}) signature names is listed there, so
 * a new one is a decision, not an accident; and the interfaces applications implement exist as
 * listed.
 */
class ProtocolTierTest {
  static final Path COMPATIBILITY = Path.of("../docs/compatibility.md");

  /** The protocol-tier types the published {@code kms} signatures name, as listed in the docs. */
  static final List<String> ANCHORED =
      List.of(
          "client.CryptoParameters",
          "client.KmipClient",
          "client.Result",
          "client.VersionPolicy",
          "model.Enums$CryptographicAlgorithm",
          "model.Enums$CryptographicUsageMask",
          "model.Enums$HashingAlgorithm",
          "model.Enums$LinkType",
          "model.Enums$ObjectType",
          "model.Enums$RecommendedCurve",
          "model.Enums$ResultReason",
          "model.Enums$RevocationReasonCode",
          "model.Enums$SecretDataType",
          "model.Enums$State",
          "model.ProtocolVersion",
          "model.Ttlv",
          "transport.KmipTransport");

  static final List<String> IMPLEMENTED =
      List.of(
          "transport.KmipTransport",
          "server.CallbackHandler",
          "server.ContextualCallbackHandler",
          "transport.CallContext",
          "server.CallbackContext");

  /**
   * The protocol-tier types (any {@code dev.keytend.kmip} subpackage but {@code kms}) that the
   * published signatures of {@code classes} name, by the names {@link #ANCHORED} uses:
   * superclass and interfaces, the type parameters of the class, of each method and of each
   * constructor (their bounds), return, parameter, exception and field types, and through each of
   * them type arguments, owner types, wildcard upper and lower bounds, type-variable bounds and
   * array components.
   */
  static Set<String> anchored(Collection<Class<?>> classes) {
    Set<String> found = new TreeSet<>();
    Set<TypeVariable<?>> seen = new HashSet<>();
    for (Class<?> c : classes) {
      named(c.getGenericSuperclass(), found, seen);
      for (Type i : c.getGenericInterfaces()) named(i, found, seen);
      for (Type v : c.getTypeParameters()) named(v, found, seen);
      for (Method m : c.getDeclaredMethods())
        if (PublicSurfaceTest.published(m) && !m.isBridge()) {
          for (Type v : m.getTypeParameters()) named(v, found, seen);
          named(m.getGenericReturnType(), found, seen);
          for (Type t : m.getGenericParameterTypes()) named(t, found, seen);
          for (Type t : m.getGenericExceptionTypes()) named(t, found, seen);
        }
      for (Constructor<?> k : c.getDeclaredConstructors())
        if (PublicSurfaceTest.published(k)) {
          for (Type v : k.getTypeParameters()) named(v, found, seen);
          for (Type t : k.getGenericParameterTypes()) named(t, found, seen);
          for (Type t : k.getGenericExceptionTypes()) named(t, found, seen);
        }
      for (Field f : c.getDeclaredFields())
        if (PublicSurfaceTest.published(f)) named(f.getGenericType(), found, seen);
    }
    return found;
  }

  /** Adds the protocol-tier types {@code t} names; a type variable's bounds once ({@code seen}). */
  private static void named(Type t, Set<String> out, Set<TypeVariable<?>> seen) {
    if (t instanceof Class<?> c) {
      while (c.isArray()) c = c.getComponentType();
      String n = c.getName();
      if (c.getPackageName().startsWith("dev.keytend.kmip.")
          && !c.getPackageName().startsWith("dev.keytend.kmip.kms"))
        out.add(n.substring("dev.keytend.kmip.".length()));
    } else if (t instanceof ParameterizedType p) {
      named(p.getRawType(), out, seen);
      if (p.getOwnerType() != null) named(p.getOwnerType(), out, seen);
      for (Type a : p.getActualTypeArguments()) named(a, out, seen);
    } else if (t instanceof WildcardType w) {
      for (Type b : w.getUpperBounds()) named(b, out, seen);
      for (Type b : w.getLowerBounds()) named(b, out, seen);
    } else if (t instanceof GenericArrayType g) {
      named(g.getGenericComponentType(), out, seen);
    } else if (t instanceof TypeVariable<?> v) {
      // <T extends Comparable<T>> names itself: each variable's bounds once.
      if (seen.add(v)) for (Type b : v.getBounds()) named(b, out, seen);
    }
  }

  @Test
  void theAnchoredTypesAreThoseTheApplicationTierNames() throws Exception {
    List<Class<?>> kms = new ArrayList<>();
    for (Class<?> c : PublicSurfaceTest.current())
      if (c.getPackageName().equals("dev.keytend.kmip.kms") && PublicSurfaceTest.visible(c))
        kms.add(c);
    assertEquals(
        new TreeSet<>(ANCHORED),
        anchored(kms),
        "add a new one to docs/compatibility.md and here, or keep it out of kms");
  }

  /**
   * Fixtures: each published element hides one protocol-tier type where only a full walk of its
   * generic signature finds it (the comment names the place), and {@link Hidden#notPublished}
   * names one where it does not count.
   */
  // The unused type parameters and the inner class are what the test looks for.
  @SuppressWarnings({"UnusedTypeParameter", "TypeParameterUnusedInFormals", "ClassCanBeStatic"})
  public static final class Hidden {
    private Hidden() {}

    /** A class type parameter's bound, unused by any member. */
    public static final class ClassBound<T extends dev.keytend.kmip.model.Ttlv> {}

    /** A method type parameter's bound, unused by the signature. */
    public static <T extends dev.keytend.kmip.client.Result> void methodBound() {}

    /** A wildcard's lower bound. */
    public static void lower(List<? super dev.keytend.kmip.model.ProtocolVersion> sink) {}

    /** A wildcard's upper bound, in a field. */
    public static List<? extends dev.keytend.kmip.model.Enums.State> upper;

    /** A generic array's component's type argument. */
    public static List<dev.keytend.kmip.model.Tag>[] arrays() {
      return null;
    }

    /** A recursive bound, and a second bound of an intersection. */
    public static <T extends Comparable<T> & dev.keytend.kmip.transport.KmipTransport>
        void recursive() {}

    /** A bound of a bound. */
    public static <A extends dev.keytend.kmip.model.Operation, B extends List<A>> B nested() {
      return null;
    }

    /** A method's exception type variable's bound. */
    public static <E extends dev.keytend.kmip.client.KmipException> void raises() throws E {}

    /** A method's exception type. */
    public static void fails() throws dev.keytend.kmip.transport.RequestNotSentException {}

    /** A constructor's type parameter bound, and a constructor's exception type. */
    public static final class Built {
      public <T extends dev.keytend.kmip.server.CallbackHandler> Built() {}

      public Built(int x) throws dev.keytend.kmip.codec.DecodeException {}
    }

    /** A type argument of an owner type. */
    public static final class Outer<T> {
      public final class Inner {}
    }

    public static Outer<dev.keytend.kmip.codec.TtlvCodec>.Inner owned;

    /** Not published: names nothing. */
    static <T extends dev.keytend.kmip.model.Attributes> void notPublished() {}
  }

  @Test
  void typesBehindBoundsAndArgumentsAreFound() {
    List<Class<?>> fixtures =
        List.of(
            Hidden.class,
            Hidden.ClassBound.class,
            Hidden.Built.class,
            Hidden.Outer.class,
            Hidden.Outer.Inner.class);
    assertEquals(
        new TreeSet<>(
            List.of(
                "model.Ttlv",
                "client.Result",
                "model.ProtocolVersion",
                "model.Enums$State",
                "model.Tag",
                "transport.KmipTransport",
                "model.Operation",
                "server.CallbackHandler",
                "client.KmipException",
                "transport.RequestNotSentException",
                "codec.DecodeException",
                "codec.TtlvCodec")),
        anchored(fixtures));
  }

  @Test
  void theCompatibilityPageListsTheFixedPoints() throws Exception {
    String page = Files.readString(COMPATIBILITY).replaceAll("\\s+", " ");
    for (String a : ANCHORED) {
      String simple = a.contains("$") ? a.substring(a.indexOf('$') + 1) : a;
      assertTrue(
          page.contains("`" + simple + "`") || page.contains("`" + a.replace('$', '.') + "`"), a);
    }
    for (String i : IMPLEMENTED) {
      Class<?> c = Class.forName("dev.keytend.kmip." + i);
      assertTrue(page.contains("`" + c.getSimpleName() + "`"), i);
    }
  }
}
