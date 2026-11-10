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
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * What replacing a key after a compromise would do, as {@link KeyHandle#compromisePlan()} read it.
 * The call acts on the keys the plan names and on no other:
 *
 * <ul>
 *   <li>{@link #key()}: revoked first when the plan {@link #revokes()}; its names move to the
 *       replacement.
 *   <li>{@link #existingReplacement()}: the newest key descending from it, finished with
 *       (activated if Pre-Active, given the names); nothing is created.
 *   <li>{@link #replacedInTurn()}: that newest key, Compromised too, replaced as well by a key the
 *       call creates, which takes both keys' names.
 *   <li>{@link #creates()}: whether the call creates a key.
 *   <li>{@link #unfinishedNameMoves()}: name moves an earlier call stopped part-way, recorded on
 *       replacements of the key: finished, and their records removed.
 * </ul>
 *
 * <p>Other newest keys descending from the key, in a forked lineage ({@link #otherDescendants()}),
 * are left as they are: {@link KeyHandle#reconcile()} joins them afterwards. Show the plan, have it
 * approved, then call {@link KeyHandle#replaceCompromisedResult(RevocationReason, CompromisePlan)}.
 * Before its first change, that call makes the plan again from what it reads and refuses with
 * {@link StateConflictException} ({@link StateConflictException.Conflict#NOT_AS_PLANNED}),
 * changing nothing, when the plan differs: the key's state, Compromise Occurrence Date, names or
 * replacements, the newest keys descending from it with their states and names, the unfinished
 * name moves, or an unlinked key created to replace it that the plan did not see. So another
 * responder's revocation, rotation or name move while the plan waited is never reported as this
 * call's, and never changes which key the call finishes with.
 *
 * <pre>{@code
 * CompromisePlan plan = key.compromisePlan();
 * plan.existingReplacement().ifPresent(r -> show("finishes with " + r.id()));
 * plan.replacedInTurn().ifPresent(d -> show(d.id() + " is Compromised too, and is replaced as well"));
 * if (plan.creates()) show("creates an Active replacement");
 * plan.otherDescendants().forEach(o -> show(o.id() + " also replaced it, and is left as it is"));
 * if (!plan.checkedForUnlinkedKeys()) show("could not search for an earlier attempt's key");
 * plan.unreadableCandidates().forEach(u -> show("have " + u + " read: it may be that key"));
 * }</pre>
 *
 * <p>KMIP has no transactions: the call checks each key against the plan as it reads it, but a
 * change another caller makes to a key after that read is not detected, so handle a compromise from
 * one place at a time.
 *
 * <p>Immutable, so thread-safe: a snapshot of what was read, never refreshed.
 *
 * @since 0.10.0
 */
public final class CompromisePlan {
  /**
   * The client attribute, {@code x-keytend-replacement-of}, in which a key created to replace
   * another records that key's identifier: what {@link #checkedForUnlinkedKeys()} searches by.
   * Where the plan could not search, look for such a key among the Pre-Active symmetric keys (and
   * the Active ones, which is where an earlier call whose links the server refused leaves it):
   *
   * <pre>{@code
   * try (Stream<KeyAttributes> staged =
   *     kms.keys().locateWithAttributes(
   *         KeyQuery.all().kind(ObjectKind.SYMMETRIC_KEY).state(KeyState.PRE_ACTIVE))) {
   *   unlinked = staged
   *       .filter(a -> key.id().equals(a.custom().get(CompromisePlan.REPLACEMENT_RECORD)))
   *       .toList();
   * }
   * }</pre>
   *
   * <p>A key keeps it once linked, as the record of the key it was made to replace.
   *
   * @since 0.10.0
   */
  public static final CustomAttribute REPLACEMENT_RECORD =
      CustomAttribute.client("keytend-replacement-of");

  /**
   * How the temporary name begins that a call gives the key it creates to replace another, where
   * the server refuses Re-key: {@code keytend-replacing-}, then the identifier of the key it
   * replaces, {@code -} and a random suffix, so that only that call uses the name. The call removes
   * the name before it links the key, so a key an earlier call left unlinked has that name or none.
   *
   * <pre>{@code
   * boolean earlierAttempt =
   *     a.names().stream().anyMatch(n -> n.startsWith(TEMPORARY_NAME_PREFIX + key.id() + "-"));
   * }</pre>
   *
   * @since 0.10.0
   */
  public static final String TEMPORARY_NAME_PREFIX = "keytend-replacing-";

  private final Object owner;
  private final KeyHandle key;
  private final KeyAttributes attributes;
  private final List<String> replacementIds;
  private final List<KeyAttributes> descendants;
  private final KeyAttributes newest;
  private final Map<String, List<String>> moves;
  private final boolean checked;
  private final List<String> unreadable;

  CompromisePlan(
      Object owner,
      KeyHandle key,
      KeyAttributes attributes,
      List<String> replacementIds,
      List<KeyAttributes> descendants,
      KeyAttributes newest,
      Map<String, List<String>> moves,
      boolean checked,
      List<String> unreadable) {
    this.checked = checked;
    this.unreadable = List.copyOf(unreadable);
    this.moves = java.util.Collections.unmodifiableMap(new java.util.LinkedHashMap<>(moves));
    this.owner = owner;
    this.key = key;
    this.attributes = attributes;
    this.replacementIds = List.copyOf(replacementIds);
    this.descendants = List.copyOf(descendants);
    this.newest = newest;
  }

  /** The newest descendant the call finishes with or replaces in turn; null when there is none. */
  KeyAttributes newest() {
    return newest;
  }

  /** The {@code Kms} the plan was read through. */
  Object owner() {
    return owner;
  }

  /**
   * The newest keys descending from the key, as read (the tips of its lineage past it), in the
   * order the call chooses among them: the call compares their identifiers, states and names with
   * what it reads again.
   */
  List<KeyAttributes> descendants() {
    return descendants;
  }

  /**
   * The key to replace, as an {@link KeyHandle#allowingCompromised()} view.
   *
   * @return the key
   */
  public KeyHandle key() {
    return key;
  }

  /**
   * The key's attributes as read for the plan: show these.
   *
   * @return the attributes
   */
  public KeyAttributes attributes() {
    return attributes;
  }

  /**
   * Whether the replacement revokes the key first, with the caller's reason and dates: true when it
   * is not Compromised yet. A Compromised key keeps its first compromise's reason and dates.
   *
   * @return whether the key is revoked
   */
  public boolean revokes() {
    return attributes.state() != KeyState.COMPROMISED;
  }

  /**
   * The key's Compromise Occurrence Date as read: the one a Compromised key keeps.
   *
   * @return the date; empty when the key is not Compromised, or has none
   */
  public Optional<Instant> compromiseOccurrenceDate() {
    return attributes.compromiseOccurrenceDate();
  }

  /**
   * The identifiers of the key's replacements, each confirmed by the links of both keys: an
   * earlier call's replacement, another caller's, or a rotation's. A link only the key has (an
   * object that does not name it back) is not one. What the call does with them is {@link
   * #existingReplacement()} and {@link #replacedInTurn()}.
   *
   * @return the identifiers, unmodifiable; empty when the key has no replacement
   */
  public List<String> replacementIds() {
    return replacementIds;
  }

  /**
   * The existing key the call finishes with, as read: the newest key descending from the key, when
   * it is Active or Pre-Active, chosen among several (a forked lineage) as {@link
   * KeyHandle#latest()} chooses, a Pre-Active one ranking as an Active one: Active or Pre-Active
   * first, then one with names, then the earliest created. The call activates it if it is
   * Pre-Active (that key only) and gives it the key's names, and creates nothing.
   *
   * @return the key; empty when the key has no replacement, or its newest descendant is Compromised
   *     ({@link #replacedInTurn()})
   */
  public Optional<KeyAttributes> existingReplacement() {
    return newest != null && newest.state() != KeyState.COMPROMISED
        ? Optional.of(newest)
        : Optional.empty();
  }

  /**
   * The key the call replaces in turn, as read: the newest key descending from the key, when it is
   * Compromised too. The call then creates a replacement of that key (it keeps its own first
   * compromise's reason and dates), which takes that key's names and the key's.
   *
   * @return the Compromised descendant; empty when there is none
   */
  public Optional<KeyAttributes> replacedInTurn() {
    return newest != null && newest.state() == KeyState.COMPROMISED
        ? Optional.of(newest)
        : Optional.empty();
  }

  /**
   * Name moves an earlier call stopped part-way, as read: a replacement of the key records a name
   * as being moved to it, a name the key gave up. The call finishes each such move: it gives the
   * name to its replacement when no object has the name, and removes the record. That removal is
   * the one change it makes to a replacement it otherwise leaves as it is ({@link
   * #otherDescendants()}).
   *
   * @return each replacement's identifier and the names it records, unmodifiable; empty in the
   *     usual case
   */
  public Map<String, List<String>> unfinishedNameMoves() {
    return moves;
  }

  /**
   * The other newest keys descending from the key, as read, when its lineage forked (callers
   * replaced or rotated it at the same time, or an earlier attempt's reply was lost): those that
   * are neither {@link #existingReplacement()} nor {@link #replacedInTurn()}. The call leaves them
   * as they are, Pre-Active ones included, except for finishing a name move one of them records
   * ({@link #unfinishedNameMoves()}): join them with {@link KeyHandle#reconcile()} afterwards, from
   * the replacement.
   *
   * @return the keys, unmodifiable, in the order the call ranks them; empty when the lineage has
   *     one newest key
   */
  public List<KeyAttributes> otherDescendants() {
    return descendants.stream().filter(d -> newest == null || !d.id().equals(newest.id())).toList();
  }

  /**
   * Whether the plan could tell that no key an earlier call created to replace the key (or the
   * descendant replaced in turn) is left unlinked; {@link KeyHandle#compromisePlan()} refuses when
   * it finds one, since a second replacement would leave that key unaccounted for. The search is a
   * Locate by the client attribute {@code x-keytend-replacement-of} that such a key records.
   *
   * <p>False when the server could not be searched that way: it refused the Locate (PyKMIP does),
   * did not filter by the attribute (some servers return other objects), returned more objects than
   * one search reads (256), or returned an object that cannot be read ({@link
   * #unreadableCandidates()}, which may be such a key). On PyKMIP it is false on every
   * plan for a Compromised key without a replacement. An earlier call that stopped before its
   * links, or whose fallback Create reply was lost and not found, may then have left such a key:
   * it is Pre-Active, linked to nothing, named {@link #TEMPORARY_NAME_PREFIX} or not at all, and
   * records {@link #REPLACEMENT_RECORD}; one whose links the server refused is Active instead, with
   * the names the key had. Look for it before you approve the plan. True when the
   * call creates nothing, or the key it would replace is not Compromised yet (a call revokes a key
   * before it creates its replacement, so no earlier call made one). A transient failure of the
   * search is not reported here: {@link KeyHandle#compromisePlan()} throws it.
   *
   * <p>The plan-bound call searches again before its first change, and refuses ({@link
   * StateConflictException.Conflict#NOT_AS_PLANNED}) when the plan could search and it cannot now.
   * A transient failure of that search is thrown as it is, nothing changed.
   *
   * @return whether the search could tell there is no such key
   * @since 0.10.0
   */
  public boolean checkedForUnlinkedKeys() {
    return checked;
  }

  /**
   * The objects the search for an earlier call's unlinked key ({@link #checkedForUnlinkedKeys()})
   * located and could not read: these credentials may not read them, or the server's reply for
   * them was not valid. Any of them may be such a key, so {@link #checkedForUnlinkedKeys()} is
   * false while this is not empty: have them read with credentials that can before you approve
   * the plan. On a server that filters the search, an object here most likely records the key; on
   * one that ignores the filter, it may be any object the server holds.
   *
   * <p>Empty when the search read every object it located, and when the server could not be
   * searched at all (then nothing was located). The plan-bound call does not compare it: a plan
   * that could not check is approved as one that could not check.
   *
   * @return the identifiers, unmodifiable, in the order the server returned them; empty when there
   *     are none
   * @since 0.10.0
   */
  public List<String> unreadableCandidates() {
    return unreadable;
  }

  /**
   * Whether the call creates a key: true when it has no existing replacement to finish with, so
   * when the key has no replacement or one is replaced in turn ({@link #replacedInTurn()}).
   *
   * @return whether a key is created
   */
  public boolean creates() {
    return existingReplacement().isEmpty();
  }

  @Override
  public String toString() {
    return "CompromisePlan["
        + key.id()
        + ", "
        + attributes.state()
        + (replacementIds.isEmpty() ? "" : ", replaced by " + replacementIds)
        + (newest == null
            ? ""
            : newest.state() == KeyState.COMPROMISED
                ? ", replaces " + newest.id() + " in turn"
                : ", finishes with " + newest.id())
        + (descendants.size() > 1
            ? ", leaves " + otherDescendants().stream().map(KeyAttributes::id).toList()
            : "")
        + (checked
            ? ""
            : ", not checked for unlinked keys"
                + (unreadable.isEmpty() ? "" : " (cannot read " + unreadable + ")"))
        + "]";
  }
}
