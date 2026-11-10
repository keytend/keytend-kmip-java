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

package dev.keytend.kmip.kms;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * The ownership predicate of a TLS identity's call ({@link TlsIssue}). Before each change to an
 * object the call registered (or, after the switch, to the new leaf, key and issuers a repeat finds
 * switched in), and before each send of a change that links to one, the call reads the object and
 * compares it with what it expects, exactly: its kind, its state, its set of names, its set of
 * links (kind and target), and the set of objects linked to it (to a certificate by Certificate
 * links, as to an issuer; to a private key by Private Key links; to a public key by Public Key
 * links), where the server and the credentials let a Locate by link show them. Any difference, an
 * extra link or name included, means another caller changed it: the call stops there.
 */
final class TlsOwnership {
  private TlsOwnership() {}

  /**
   * What an object must be, exactly. {@code links} holds {@link #link} strings. {@code from}
   * holds the objects with a link of its {@link #toIt} kind to it.
   */
  record Expected(
      ObjectKind kind, KeyState state, Set<String> names, Set<String> links, Set<String> from) {
    Expected {
      names = Set.copyOf(names);
      links = Set.copyOf(links);
      from = Set.copyOf(from);
    }

    /** As a Register under {@code name} leaves an object: nothing links to it yet. */
    static Expected registered(ObjectKind kind, String name) {
      return new Expected(kind, KeyState.PRE_ACTIVE, Set.of(name), Set.of(), Set.of());
    }

    /** {@code a} as it is, with {@code from} the objects linked to it. */
    static Expected of(KeyAttributes a, Set<String> from) {
      return new Expected(a.kind(), a.state(), Set.copyOf(a.names()), TlsOwnership.links(a), from);
    }

    Expected named(String name) {
      Set<String> n = new LinkedHashSet<>(names);
      n.add(name);
      return new Expected(kind, state, n, links, from);
    }

    Expected unnamed(String name) {
      Set<String> n = new LinkedHashSet<>(names);
      n.remove(name);
      return new Expected(kind, state, n, links, from);
    }

    Expected linked(LinkKind linkKind, String target) {
      Set<String> l = new LinkedHashSet<>(links);
      l.add(link(linkKind, linkKind.protocolValue().code(), target));
      return new Expected(kind, state, names, l, from);
    }

    Expected in(KeyState s) {
      return new Expected(kind, s, names, links, from);
    }

    /** With {@code object}'s link of the {@link #toIt} kind to it. */
    Expected linkedFrom(String object) {
      Set<String> f = new LinkedHashSet<>(from);
      f.add(object);
      return new Expected(kind, state, names, links, f);
    }

    /** Whether {@code a} has this kind, state, names and links (the incoming links aside). */
    boolean sameAs(KeyAttributes a) {
      return a != null && mismatch(this, a, null) == null;
    }
  }

  /** Why an object is not as expected: the conflict, the state read (for STATE), and a clause. */
  record Mismatch(StateConflictException.Conflict conflict, KeyState observed, String why) {}

  /**
   * The kind of the links to an object of {@code kind} that the predicate compares: Certificate
   * links to a certificate (it is their issuer, or their certificate for a key), Private Key links
   * to a private key, Public Key links to a public key.
   */
  static LinkKind toIt(ObjectKind kind) {
    return switch (kind) {
      case PRIVATE_KEY -> LinkKind.PRIVATE_KEY;
      case PUBLIC_KEY -> LinkKind.PUBLIC_KEY;
      default -> LinkKind.CERTIFICATE;
    };
  }

  /** A link as {@link Expected} holds it: its kind (the raw type for another kind) and target. */
  static String link(LinkKind kind, int rawType, String target) {
    return (kind == LinkKind.OTHER ? "LINK(" + rawType + ")" : kind.name()) + "->" + target;
  }

  /** {@code a}'s links, as {@link #link} strings. */
  static Set<String> links(KeyAttributes a) {
    Set<String> out = new LinkedHashSet<>();
    for (Link l : a.links()) out.add(link(l.kind(), l.rawType(), l.targetId()));
    return out;
  }

  /**
   * Why {@code a} (null: gone) is not {@code e}; null when it is. {@code linkedFrom}, the objects
   * a Locate found with a link of the {@link #toIt} kind to it (null: not searched), must be {@code
   * e.from()} when the search was complete, and within it otherwise (what the server lets the call
   * see).
   */
  static Mismatch mismatch(Expected e, KeyAttributes a, KmsKeys.Search linkedFrom) {
    if (a == null) return new Mismatch(StateConflictException.Conflict.STATE, null, "it is gone");
    if (a.kind() != e.kind())
      return new Mismatch(StateConflictException.Conflict.LINEAGE, null, "it is a " + a.kind());
    if (a.state() != e.state())
      return new Mismatch(
          StateConflictException.Conflict.STATE,
          a.state(),
          "it is " + a.state() + ", not " + e.state());
    if (!Set.copyOf(a.names()).equals(e.names()))
      return new Mismatch(
          StateConflictException.Conflict.NAME,
          null,
          "it has the names " + sorted(a.names()) + ", not " + sorted(e.names()));
    Set<String> links = links(a);
    if (!links.equals(e.links()))
      return new Mismatch(
          StateConflictException.Conflict.LINEAGE,
          null,
          "it has the links " + sorted(links) + ", not " + sorted(e.links()));
    if (linkedFrom != null) {
      Set<String> seen = new TreeSet<>();
      for (KeyAttributes c : linkedFrom.found()) seen.add(c.id());
      boolean as =
          linkedFrom.complete() ? seen.equals(new TreeSet<>(e.from())) : e.from().containsAll(seen);
      if (!as)
        return new Mismatch(
            StateConflictException.Conflict.LINEAGE,
            null,
            "the objects with a "
                + toIt(e.kind())
                + " link to it are "
                + seen
                + ", not "
                + sorted(e.from()));
    }
    return null;
  }

  private static List<String> sorted(java.util.Collection<String> c) {
    return List.copyOf(new TreeSet<>(c));
  }
}
