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

import java.util.List;
import java.util.Objects;

/**
 * One key of a rotation lineage, as {@link KeyHandle#lineage()} lists it: its attributes as read,
 * and where it stands in the lineage.
 *
 * <p>A rotation lineage is a key and the keys that replaced it or that it replaced, by rotation or
 * by compromise replacement. Records sealed under one key of a lineage open through the others
 * while those keys exist and lie within 64 rotations. A lineage is usually a chain from the first
 * key to the current one. It becomes a tree when callers rotated one key at the same time.
 *
 * <p>The links a {@code LineageKey} reports are the steps the SDK follows, each confirmed by both
 * keys: the newer key's Replaced Object link and the older key's Replacement Object link. {@link
 * KeyAttributes#replacedLink()} and {@link KeyAttributes#replacementLink()} are one key's raw links instead,
 * and prove nothing about the lineage.
 *
 * <p>A key is on a <em>branch</em> when it is neither the newest key {@link KeyHandle#latest()}
 * chooses nor a key that one descends from. Callers that rotated one key at the same time leave a
 * branch (see {@link KeyHandle#rotate()}). {@link KeyHandle#reconcile()} then joins it into the
 * lineage ({@link #joinedInto()} names the key), or leaves it as another newest key ({@link
 * #newest()}): a Compromised one, or one not reconciled yet. A branch's records reach the current
 * key only through the key the branch replaced.
 *
 * <p>Immutable, so thread-safe: a snapshot of what the walk read, never refreshed.
 *
 * @since 0.10.0
 */
public final class LineageKey {
  private final KeyAttributes attributes;
  private final List<String> replaced, replacedBy, joinedInto;
  private final boolean newest, branch;

  LineageKey(
      KeyAttributes attributes,
      List<String> replaced,
      List<String> replacedBy,
      List<String> joinedInto,
      boolean newest,
      boolean branch) {
    this.attributes = Objects.requireNonNull(attributes, "attributes");
    this.replaced = List.copyOf(replaced);
    this.replacedBy = List.copyOf(replacedBy);
    this.joinedInto = List.copyOf(joinedInto);
    this.newest = newest;
    this.branch = branch;
  }

  /**
   * The key's attributes, as the walk read them (one Get Attributes; never null).
   *
   * @return the attributes
   * @since 0.10.0
   */
  public KeyAttributes attributes() {
    return attributes;
  }

  /**
   * The key's identifier: {@code attributes().id()}.
   *
   * @return the identifier
   * @since 0.10.0
   */
  public String id() {
    return attributes.id();
  }

  /**
   * The keys of the lineage this key replaced, each step confirmed by both keys' links, lowest
   * identifier first. Empty for the oldest key listed, and for a destroyed key, whose predecessors
   * the listing does not read ({@link KeyHandle#lineage()}). Normally one key: several only where a
   * key has more than one Replaced Object link, which this SDK does not make. Unmodifiable, never
   * null.
   *
   * @return the identifiers this key replaced, unmodifiable
   * @since 0.10.0
   */
  public List<String> replaced() {
    return replaced;
  }

  /**
   * The keys of the lineage that replaced this key, each step confirmed by both keys' links,
   * lowest identifier first: empty for a newest key, several when callers rotated it at the same
   * time. Unmodifiable, never null.
   *
   * @return the identifiers that replaced this key, unmodifiable
   * @since 0.10.0
   */
  public List<String> replacedBy() {
    return replacedBy;
  }

  /**
   * The keys of the lineage {@link KeyHandle#reconcile()} joined this key into: it names them with
   * its Replacement Object link, and they do not name it back, so this is no step of the lineage,
   * only a mark that the key is not a newest key. Empty for a key never joined. Unmodifiable,
   * never null.
   *
   * @return the identifiers this key was joined into, unmodifiable
   * @since 0.10.0
   */
  public List<String> joinedInto() {
    return joinedInto;
  }

  /**
   * Whether this is a newest key of the lineage: no confirmed replacement, and not joined into
   * another key. One key is, unless callers rotated at the same time and {@link
   * KeyHandle#reconcile()} has not joined their keys yet (or left a Compromised one).
   *
   * @return whether this is a newest key
   * @since 0.10.0
   */
  public boolean newest() {
    return newest;
  }

  /**
   * Whether this key is on a branch: neither the newest key {@link KeyHandle#latest()} chooses nor
   * a key that one descends from by confirmed steps (see the class description).
   *
   * @return whether this key is on a branch
   * @since 0.10.0
   */
  public boolean branch() {
    return branch;
  }

  @Override
  public String toString() {
    return "LineageKey["
        + id()
        + ", "
        + attributes.state()
        + (newest ? ", newest" : "")
        + (branch ? ", branch" : "")
        + (joinedInto.isEmpty() ? "" : ", joined into " + joinedInto)
        + "]";
  }
}
