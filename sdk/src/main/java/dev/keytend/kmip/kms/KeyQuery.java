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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

/**
 * Locate filters, of which every one given must match. Start from {@link #all()}, {@link
 * #byName(String)} or {@link #byIds(String...)} and add filters. Each method returns a new query;
 * the three starting points are the only static ones.
 *
 * <pre>{@code
 * Instant now = Instant.now();
 * List<KeyHandle> recent = kms.keys().list(KeyQuery.all()
 *     .custom(CustomAttribute.client("tenant"), "acme")
 *     .createdBetween(now.minus(Duration.ofDays(7)), now));
 * }</pre>
 *
 * <p>Calling a single-valued filter again replaces its value. That covers {@link #name}, {@link
 * #group}, {@link #state}, {@link #kind}, {@link #algorithm}, the date ranges, {@link #ids}, and
 * {@link #custom} for the same attribute. {@link #custom} for another attribute and {@link #linkedTo} add a
 * filter. The same query states what {@link KmsKeys#decrypt(KeyQuery, Ciphertext, byte[])}
 * expects of the key a ciphertext names, checked against that key's attributes.
 *
 * <p>A {@code KeyQuery} is immutable and thread-safe.
 *
 * @since 0.10.0
 */
public final class KeyQuery {
  record LinkFilter(LinkKind kind, String targetId) {}

  final String name, group;
  final KeyState state;
  final ObjectKind kind;
  final Algorithm algorithm;
  final Map<CustomAttribute, Object> custom;
  final List<LinkFilter> links;
  final Instant createdFrom, createdTo, activatedFrom, activatedTo;

  /** The identifiers {@link #ids} allows, or null for any. */
  final Set<String> ids;

  private KeyQuery(
      String name,
      String group,
      KeyState state,
      ObjectKind kind,
      Algorithm algorithm,
      Map<CustomAttribute, Object> custom,
      List<LinkFilter> links,
      Instant createdFrom,
      Instant createdTo,
      Instant activatedFrom,
      Instant activatedTo,
      Set<String> ids) {
    this.name = name;
    this.group = group;
    this.state = state;
    this.kind = kind;
    this.algorithm = algorithm;
    this.custom = Collections.unmodifiableMap(new LinkedHashMap<>(custom));
    this.links = List.copyOf(links);
    this.createdFrom = createdFrom;
    this.createdTo = createdTo;
    this.activatedFrom = activatedFrom;
    this.activatedTo = activatedTo;
    this.ids = ids;
  }

  private KeyQuery with(
      String name,
      String group,
      KeyState state,
      ObjectKind kind,
      Algorithm algorithm,
      Map<CustomAttribute, Object> custom,
      List<LinkFilter> links,
      Instant createdFrom,
      Instant createdTo,
      Instant activatedFrom,
      Instant activatedTo) {
    return new KeyQuery(
        name,
        group,
        state,
        kind,
        algorithm,
        custom,
        links,
        createdFrom,
        createdTo,
        activatedFrom,
        activatedTo,
        ids);
  }

  /**
   * Matches every object the client may see.
   *
   * @return the query
   */
  public static KeyQuery all() {
    return new KeyQuery(
        null, null, null, null, null, Map.of(), List.of(), null, null, null, null, null);
  }

  /**
   * Objects with this name: {@code KeyQuery.all().name(name)}, the usual starting point of a query
   * ({@code KeyQuery.byName("orders").state(KeyState.ACTIVE)}).
   *
   * @param name the name
   * @return the query
   * @since 0.10.0
   */
  public static KeyQuery byName(String name) {
    return all().name(name);
  }

  /**
   * Objects whose Unique Identifier is one of {@code ids}: {@code KeyQuery.all().ids(ids)}, the
   * starting point of a manifest of the keys the application trusts ({@link #ids(Collection)}).
   * Add other filters to it: {@code KeyQuery.byIds(previous, current).kind(ObjectKind.SYMMETRIC_KEY)}.
   *
   * @param ids the identifiers, at least one; none null or empty. Copied
   * @return the query
   * @throws IllegalArgumentException when {@code ids} is empty or holds an empty identifier
   * @since 0.10.0
   */
  public static KeyQuery byIds(String... ids) {
    return all().ids(ids);
  }

  /**
   * Objects with this name. KMIP objects can have several names, and a query names one: calling
   * it again replaces the name.
   *
   * @param value the name
   * @return a copy of this query with the filter
   * @since 0.10.0
   */
  public KeyQuery name(String value) {
    return with(
        Objects.requireNonNull(value, "name"),
        group,
        state,
        kind,
        algorithm,
        custom,
        links,
        createdFrom,
        createdTo,
        activatedFrom,
        activatedTo);
  }

  /**
   * Objects in a group. The KMIP 3.0 draft has no Object Group, so where 3.0 may be negotiated
   * use a custom attribute, which every version supports.
   *
   * @param value the group's name (one group per query: a later call replaces it)
   * @return a new query; this one is unchanged
   */
  public KeyQuery group(String value) {
    return with(
        name,
        Objects.requireNonNull(value, "group"),
        state,
        kind,
        algorithm,
        custom,
        links,
        createdFrom,
        createdTo,
        activatedFrom,
        activatedTo);
  }

  /**
   * Objects in this state (one state per query: a later call replaces it).
   *
   * @param value the state, not {@link KeyState#UNKNOWN}
   * @return a new query; this one is unchanged
   * @throws IllegalArgumentException for {@link KeyState#UNKNOWN}
   */
  public KeyQuery state(KeyState value) {
    if (value == KeyState.UNKNOWN) throw new IllegalArgumentException("Not a queryable state");
    return with(
        name,
        group,
        Objects.requireNonNull(value, "state"),
        kind,
        algorithm,
        custom,
        links,
        createdFrom,
        createdTo,
        activatedFrom,
        activatedTo);
  }

  /**
   * Objects of this kind (one kind per query: a later call replaces it).
   *
   * @param value the kind, not {@link ObjectKind#OTHER}
   * @return a new query; this one is unchanged
   * @throws IllegalArgumentException for {@link ObjectKind#OTHER}
   */
  public KeyQuery kind(ObjectKind value) {
    if (value == ObjectKind.OTHER) throw new IllegalArgumentException("Not a queryable kind");
    return with(
        name,
        group,
        state,
        Objects.requireNonNull(value, "kind"),
        algorithm,
        custom,
        links,
        createdFrom,
        createdTo,
        activatedFrom,
        activatedTo);
  }

  /**
   * Objects with this Cryptographic Algorithm (one algorithm per query: a later call replaces it).
   *
   * @param value the algorithm, not {@link Algorithm#OTHER}
   * @return a new query; this one is unchanged
   * @throws IllegalArgumentException for {@link Algorithm#OTHER}
   */
  public KeyQuery algorithm(Algorithm value) {
    if (Objects.requireNonNull(value, "algorithm") == Algorithm.OTHER)
      throw new IllegalArgumentException("Not a queryable algorithm");
    return with(
        name,
        group,
        state,
        kind,
        value,
        custom,
        links,
        createdFrom,
        createdTo,
        activatedFrom,
        activatedTo);
  }

  /**
   * Objects whose custom attribute {@code attribute} has {@code value} (see {@link KeyAttributes}
   * for the value types). Several custom filters must all match.
   *
   * @param attribute the attribute
   * @param value its value, of a type {@link KeyAttributes} lists (a {@code byte[]} is copied)
   * @return a new query; this one is unchanged
   * @throws IllegalArgumentException when the value is not of one of those types
   */
  public KeyQuery custom(CustomAttribute attribute, Object value) {
    Objects.requireNonNull(attribute, "attribute");
    AttributeReader.encode(Objects.requireNonNull(value, "value"));
    Map<CustomAttribute, Object> c = new LinkedHashMap<>(custom);
    c.put(attribute, value instanceof byte[] b ? b.clone() : value);
    return with(
        name,
        group,
        state,
        kind,
        algorithm,
        c,
        links,
        createdFrom,
        createdTo,
        activatedFrom,
        activatedTo);
  }

  /**
   * Objects with a link of {@code kind} to {@code targetId}; for example {@code
   * linkedTo(LinkKind.REPLACEMENT, current.id())} finds the key {@code current} replaced. On the
   * 3.0 draft, which has no Link structure, the link type's own attribute is searched (Replacement
   * Object Link, ...).
   *
   * @param kind the link kind, not {@link LinkKind#OTHER}
   * @param targetId the linked object's identifier
   * @return a new query; this one is unchanged
   * @throws IllegalArgumentException for {@link LinkKind#OTHER}
   */
  public KeyQuery linkedTo(LinkKind kind, String targetId) {
    if (Objects.requireNonNull(kind, "kind") == LinkKind.OTHER)
      throw new IllegalArgumentException("Not a queryable link kind");
    List<LinkFilter> l = new ArrayList<>(links);
    l.add(new LinkFilter(kind, Objects.requireNonNull(targetId, "targetId")));
    return with(
        name,
        group,
        state,
        this.kind,
        algorithm,
        custom,
        l,
        createdFrom,
        createdTo,
        activatedFrom,
        activatedTo);
  }

  /**
   * Objects created or registered (Initial Date) between {@code from} and {@code to}, inclusive.
   *
   * @param from the start, inclusive (truncated to whole seconds)
   * @param to the end, inclusive (rounded up to whole seconds)
   * @return a new query; this one is unchanged
   * @throws IllegalArgumentException when {@code to} is before {@code from}
   */
  public KeyQuery createdBetween(Instant from, Instant to) {
    Instant[] r = range(from, to);
    return with(
        name, group, state, kind, algorithm, custom, links, r[0], r[1], activatedFrom, activatedTo);
  }

  /**
   * Objects activated (Activation Date) between {@code from} and {@code to}, inclusive. A key made
   * by a KMIP Re-key without an Offset ({@link KeyHandle#rotate()}) has the Activation Date of the
   * key it replaced, so this finds it by its predecessor's date: {@link #createdBetween} finds keys
   * by when they were made.
   *
   * @param from the start, inclusive (truncated to whole seconds)
   * @param to the end, inclusive (rounded up to whole seconds)
   * @return a new query; this one is unchanged
   * @throws IllegalArgumentException when {@code to} is before {@code from}
   */
  public KeyQuery activatedBetween(Instant from, Instant to) {
    Instant[] r = range(from, to);
    return with(
        name, group, state, kind, algorithm, custom, links, createdFrom, createdTo, r[0], r[1]);
  }

  /**
   * Objects whose Unique Identifier is one of {@code ids}: a manifest of the keys the application
   * trusts. Use it to open records more than 64 rotations back, which a {@link KeyHandle} cannot
   * walk to (see <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#records-older-than-64-rotations">Records
   * older than 64 rotations</a>).
   *
   * <p>The identifiers must come from where only the application can change them, such as its
   * own configuration or a store it protects. Record each key {@link KeyHandle#rotate()} returns,
   * or what {@link KeyHandle#lineage()} lists at a time you trust, and never read them from the
   * records. A manifest is only as good as the server's promise never to reuse an identifier.
   *
   * <p>It is checked against the key a record names, as {@link KmsKeys#decrypt(KeyQuery,
   * Ciphertext, byte[])} and the other forms that take an expected key do. A record under a listed
   * key opens with one Get Attributes and the decryption. KMIP has no search by identifier, so
   * {@link KmsKeys#locate} and the other searches refuse a query with it ({@link
   * UnsupportedException}, nothing sent). A record outside the query is therefore always {@code
   * BAD_DATA}. Calling it again replaces the identifiers.
   *
   * @param ids the identifiers, at least one; none null or empty. Copied: changing the collection
   *     afterwards does not change the query
   * @return a copy of this query with the filter
   * @throws IllegalArgumentException when {@code ids} is empty or holds an empty identifier
   * @since 0.10.0
   */
  public KeyQuery ids(Collection<String> ids) {
    return withIds(ids);
  }

  /**
   * Objects whose Unique Identifier is one of {@code ids}, with the rules of {@link
   * #ids(Collection)}: {@code query.ids(previous, current)} keeps every other filter of {@code
   * query}.
   *
   * @param ids the identifiers, at least one; none null or empty. Copied
   * @return a copy of this query with the filter
   * @throws IllegalArgumentException when {@code ids} is empty or holds an empty identifier
   * @since 0.10.0
   */
  public KeyQuery ids(String... ids) {
    return withIds(Arrays.asList(Objects.requireNonNull(ids, "ids")));
  }

  private KeyQuery withIds(Collection<String> ids) {
    Objects.requireNonNull(ids, "ids");
    Set<String> copy = new LinkedHashSet<>();
    for (String id : ids) {
      if (Objects.requireNonNull(id, "an identifier in ids").isEmpty())
        throw new IllegalArgumentException("Empty key identifier");
      copy.add(id);
    }
    if (copy.isEmpty())
      throw new IllegalArgumentException("No identifiers: a manifest lists at least one key");
    return new KeyQuery(
        name,
        group,
        state,
        kind,
        algorithm,
        custom,
        links,
        createdFrom,
        createdTo,
        activatedFrom,
        activatedTo,
        Collections.unmodifiableSet(copy));
  }

  /** KMIP dates have whole seconds: the range is widened to them. */
  private static Instant[] range(Instant from, Instant to) {
    Objects.requireNonNull(from, "from");
    Objects.requireNonNull(to, "to");
    if (to.isBefore(from)) throw new IllegalArgumentException("The range ends before it starts");
    Instant end = to.truncatedTo(ChronoUnit.SECONDS);
    if (end.isBefore(to)) end = end.plusSeconds(1);
    return new Instant[] {from.truncatedTo(ChronoUnit.SECONDS), end};
  }

  boolean isEmpty() {
    return name == null
        && group == null
        && state == null
        && kind == null
        && algorithm == null
        && custom.isEmpty()
        && links.isEmpty()
        && createdFrom == null
        && activatedFrom == null
        && ids == null;
  }

  /** Whether {@code a} satisfies every filter (locally, as a Locate would). */
  boolean matches(KeyAttributes a) {
    if (ids != null && !ids.contains(a.id())) return false;
    if (name != null && !a.names().contains(name)) return false;
    if (group != null && !a.groups().contains(group)) return false;
    if (state != null && a.state() != state) return false;
    if (kind != null && a.kind() != kind) return false;
    if (algorithm != null) {
      Algorithm actual = a.algorithm().orElse(null);
      boolean same =
          actual == algorithm
              || (algorithm.ellipticCurve() && actual != null && actual.ellipticCurve());
      if (!same) return false;
    }
    if (!matchesCustom(a)) return false;
    for (LinkFilter l : links)
      if (a.links().stream()
          .noneMatch(x -> x.kind() == l.kind() && x.targetId().equals(l.targetId()))) return false;
    if (createdFrom != null && !within(a.creationDate(), createdFrom, createdTo)) return false;
    if (activatedFrom != null && !within(a.activationDate(), activatedFrom, activatedTo))
      return false;
    return true;
  }

  /** Custom values compared as KMIP stores them: byte contents and whole-second DateTimes. */
  boolean matchesCustom(KeyAttributes a) {
    for (var e : custom.entrySet()) {
      Object have = a.custom().get(e.getKey());
      Object want = e.getValue();
      if (want instanceof Instant i) want = i.truncatedTo(ChronoUnit.SECONDS);
      boolean equal =
          (have instanceof byte[] h && want instanceof byte[] w)
              ? Arrays.equals(h, w)
              : Objects.equals(have, want);
      if (!equal) return false;
    }
    return true;
  }

  private static boolean within(Optional<Instant> date, Instant from, Instant to) {
    return date.map(d -> !d.isBefore(from) && !d.isAfter(to)).orElse(false);
  }

  @Override
  public String toString() {
    StringJoiner j = new StringJoiner(", ", "KeyQuery[", "]");
    if (name != null) j.add("name=" + name);
    if (group != null) j.add("group=" + group);
    if (state != null) j.add("state=" + state);
    if (kind != null) j.add("kind=" + kind);
    if (algorithm != null) j.add("algorithm=" + algorithm);
    for (CustomAttribute c : custom.keySet()) j.add(c + "=...");
    for (LinkFilter l : links) j.add(l.kind() + "->" + l.targetId());
    if (createdFrom != null) j.add("created " + createdFrom + ".." + createdTo);
    if (activatedFrom != null) j.add("activated " + activatedFrom + ".." + activatedTo);
    if (ids != null)
      j.add("ids=" + (ids.size() <= 3 ? ids.toString() : ids.size() + " identifiers"));
    return j.toString();
  }
}
