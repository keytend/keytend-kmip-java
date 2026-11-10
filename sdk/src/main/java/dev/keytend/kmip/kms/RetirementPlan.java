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
import java.util.Optional;

/**
 * The keys a retirement would destroy, in the order it destroys them, as {@link
 * KeyHandle#retirementPlan()} and {@link KeyHandle#retirementPlanOlderThan} read them. Show it, have
 * it approved, then retire exactly these keys with {@link
 * KeyHandle#retirePredecessors(RevocationReason, RetirementPlan)}, which refuses when the lineage
 * changed meanwhile. {@link KeyHandle#deactivatePredecessors(RevocationReason, RetirementPlan)}
 * takes the same plan and deactivates the keys it lists as Active.
 *
 * <p>The keys are compared with the plan once, before the first change, and only the planned keys
 * are acted on. KMIP has no transactions: a change another caller makes after that comparison is
 * not detected, so change a lineage from one place at a time.
 *
 * <p>Immutable, so thread-safe: a snapshot of what was read, never refreshed.
 *
 * @since 0.10.0
 */
public final class RetirementPlan {
  private final Object owner;
  private final String newestId;
  private final String keepFromId;
  private final List<KeyAttributes> keys;
  private final List<String> ids;

  RetirementPlan(Object owner, String newestId, String keepFromId, List<KeyAttributes> keys) {
    this.owner = owner;
    this.newestId = newestId;
    this.keepFromId = keepFromId;
    this.keys = List.copyOf(keys);
    this.ids = this.keys.stream().map(KeyAttributes::id).toList();
  }

  /** The {@code Kms} the plan was read through. */
  Object owner() {
    return owner;
  }

  /**
   * The identifier of the lineage's newest key, which the plan was made from and which the
   * retirement keeps.
   *
   * @return the identifier
   */
  public String newestId() {
    return newestId;
  }

  /**
   * The identifier of the oldest key kept, for a plan from {@link
   * KeyHandle#retirementPlanOlderThan}.
   *
   * @return the identifier; empty for a plan of the whole lineage
   */
  public Optional<String> keepFromId() {
    return Optional.ofNullable(keepFromId);
  }

  /**
   * The keys to retire, as read, in the order they are retired: first the keys of branches {@link
   * KeyHandle#reconcile()} joined in, each before the keys it replaced; then the keys the newest key
   * descends from, oldest first. Keys already destroyed are left out. Each is revoked first if it
   * is Active, then destroyed.
   *
   * @return the keys, unmodifiable; empty when there is nothing to retire
   */
  public List<KeyAttributes> keys() {
    return keys;
  }

  /**
   * The identifiers of {@link #keys()}, in the same order.
   *
   * @return the identifiers, unmodifiable
   */
  public List<String> ids() {
    return ids;
  }

  @Override
  public String toString() {
    return "RetirementPlan[from "
        + newestId
        + (keepFromId == null ? "" : ", keeping from " + keepFromId)
        + ", retires "
        + ids
        + "]";
  }
}
