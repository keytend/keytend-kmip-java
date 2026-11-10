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

import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * What {@link KmsKeys#reconcile(String)} would change now, as {@link KmsKeys#reconcilePlan(String)}
 * reads it: the newest key it keeps, the other newest keys it joins into that key, the names it
 * moves, and the keys it deactivates. Show it, have it approved, then reconcile exactly this with
 * {@link KmsKeys#reconcile(String, ReconcilePlan)}, which refuses when the name or its lineage
 * changed meanwhile.
 *
 * <pre>{@code
 * ReconcilePlan plan = kms.keys().reconcilePlan("invoices-kek").orElseThrow();
 * // show plan.winner(), plan.joined(), plan.namesMoved() and plan.deactivated(), ask, then:
 * kms.keys().reconcile("invoices-kek", plan);
 * }</pre>
 *
 * <p>Immutable, so thread-safe: a snapshot of what was read, never refreshed.
 *
 * @since 0.10.0
 */
public final class ReconcilePlan {
  private final Object owner;
  private final String name;
  private final KeyAttributes winner;
  private final List<KeyAttributes> joined, deactivated;
  private final Map<String, List<String>> namesMoved;
  private final Set<String> lineage;

  ReconcilePlan(
      Object owner,
      String name,
      KeyAttributes winner,
      List<KeyAttributes> joined,
      Map<String, List<String>> namesMoved,
      List<KeyAttributes> deactivated,
      Set<String> lineage) {
    this.owner = owner;
    this.name = name;
    this.winner = winner;
    this.joined = List.copyOf(joined);
    Map<String, List<String>> names = new LinkedHashMap<>();
    namesMoved.forEach((k, v) -> names.put(k, List.copyOf(v)));
    this.namesMoved = java.util.Collections.unmodifiableMap(names);
    this.deactivated = List.copyOf(deactivated);
    this.lineage = Set.copyOf(lineage);
  }

  /** The {@code Kms} the plan was read through. */
  Object owner() {
    return owner;
  }

  /** The identifiers of the lineage's keys as read: the only keys a bound reconcile changes. */
  Set<String> lineage() {
    return lineage;
  }

  /**
   * The name the plan was made for.
   *
   * @return the name
   */
  public String name() {
    return name;
  }

  /**
   * The key kept as the lineage's newest key, Active, as read. Afterwards it has the names, and
   * {@link KmsKeys#findByName(String)} returns it.
   *
   * @return the winner
   */
  public KeyAttributes winner() {
    return winner;
  }

  /**
   * The other newest keys that get a Replacement Object link to the winner, so they are newest keys
   * no longer. A Compromised newest key is not joined: it is left for {@link
   * KeyHandle#replaceCompromised}.
   *
   * @return the keys, as read, unmodifiable; empty when the lineage has one newest key
   */
  public List<KeyAttributes> joined() {
    return joined;
  }

  /**
   * The names that move to the winner: for each other key of the lineage that has names, those
   * names.
   *
   * @return from the key's identifier to its names, unmodifiable; empty when only the winner has
   *     names
   */
  public Map<String, List<String>> namesMoved() {
    return namesMoved;
  }

  /**
   * The other Active keys of the lineage, which are deactivated (superseded) last.
   *
   * @return the keys, as read, unmodifiable
   */
  public List<KeyAttributes> deactivated() {
    return deactivated;
  }

  /**
   * Whether the reconcile has nothing to do: one newest key, which has every name, and no other
   * Active key.
   *
   * @return true when nothing would change
   */
  public boolean changesNothing() {
    return joined.isEmpty() && namesMoved.isEmpty() && deactivated.isEmpty();
  }

  /** What {@code now} would do that this plan does not list; empty when it is within the plan. */
  List<String> beyond(ReconcilePlan now) {
    List<String> out = new ArrayList<>();
    if (!now.winner.id().equals(winner.id()))
      out.add("the newest key is " + now.winner.id() + ", not " + winner.id());
    List<String> joins = outside(ids(now.joined), ids(joined));
    if (!joins.isEmpty()) out.add("it would join " + joins);
    for (Map.Entry<String, List<String>> e : now.namesMoved.entrySet()) {
      List<String> names = outside(e.getValue(), namesMoved.getOrDefault(e.getKey(), List.of()));
      if (!names.isEmpty()) out.add("it would move " + names + " from " + e.getKey());
    }
    List<String> off = outside(ids(now.deactivated), ids(deactivated));
    if (!off.isEmpty()) out.add("it would deactivate " + off);
    return out;
  }

  private static List<String> ids(List<KeyAttributes> keys) {
    return keys.stream().map(KeyAttributes::id).toList();
  }

  private static List<String> outside(List<String> some, List<String> planned) {
    Set<String> in = new HashSet<>(planned);
    return some.stream().filter(s -> !in.contains(s)).toList();
  }

  @Override
  public String toString() {
    return "ReconcilePlan["
        + name
        + ": keeps "
        + winner.id()
        + ", joins "
        + ids(joined)
        + ", moves names from "
        + namesMoved.keySet()
        + ", deactivates "
        + ids(deactivated)
        + "]";
  }
}
