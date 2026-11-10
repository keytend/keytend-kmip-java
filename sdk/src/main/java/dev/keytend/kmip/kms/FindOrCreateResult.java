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
 * What {@link KeyCreation#findOrCreateResult()} did: the key it returns, and how it got it.
 *
 * <pre>{@code
 * FindOrCreateResult r = kms.keys().createAes(256).named("orders-kek")
 *     .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).findOrCreateResult();
 * if (r.outcome() == FindOrCreateResult.Outcome.CREATED) {
 *   log.warn("created a new KEK {}", r.key().id());
 * }
 * }</pre>
 *
 * <p>Immutable, so thread-safe.
 *
 * @since 0.10.0
 */
public final class FindOrCreateResult {
  /** How the call got its key. */
  public enum Outcome {
    /**
     * An Active key had the name. Also when this call waited for another call through the same
     * {@link Kms} that found or created the key.
     */
    FOUND,
    /** A Pre-Active key had the name, and this call activated it. */
    ACTIVATED,
    /** No key had the name, and this call created and activated one. */
    CREATED,
    /**
     * With {@link KeyCreation#replacingCompromised()}: the name's key was Compromised, and this call
     * replaced it, or finished a replacement an earlier call had started.
     */
    REPLACED,
    /**
     * A step of this call had an unknown outcome (its reply was lost: {@link #recoveredFrom()}), and
     * reading back went past it. Either this call's Create, after which the key was found by its
     * name: this call or another caller made it, and it may have been activated by this call. Or
     * this call's Activate of a Pre-Active key the name led to, which was then read back Active:
     * this call or another caller activated it. Which one cannot be told. Count it apart from
     * {@link #CREATED} and {@link #ACTIVATED}, or check the server's audit log.
     */
    RECOVERED
  }

  private final KeyHandle key;
  private final Outcome outcome;
  private final List<KeyHandle> created;
  private final OutcomeUnknownException recoveredFrom;

  FindOrCreateResult(
      KeyHandle key,
      Outcome outcome,
      List<KeyHandle> created,
      OutcomeUnknownException recoveredFrom) {
    this.key = key;
    this.outcome = outcome;
    this.created = List.copyOf(created);
    this.recoveredFrom = recoveredFrom;
  }

  /**
   * The key, Active: what {@link KeyCreation#findOrCreate()} returns.
   *
   * @return the key
   */
  public KeyHandle key() {
    return key;
  }

  /**
   * How the call got the key.
   *
   * @return the outcome
   */
  public Outcome outcome() {
    return outcome;
  }

  /**
   * The keys this call is known to have created and left on the server: {@link #key()} when {@link
   * Outcome#CREATED}, and a key it created but did not return because another caller's key with the
   * name ranked first (a lost race). Such a key may be Pre-Active, and then {@link
   * KeyHandle#leftovers()} lists it, or Active already, when the other key was found after this
   * call activated its own: check its state before doing anything with it, since an Active key may
   * be in use. Empty for {@link Outcome#REPLACED}, whose replacement this call may have made or only
   * finished, and for {@link Outcome#RECOVERED}.
   *
   * @return the keys, unmodifiable
   */
  public List<KeyHandle> created() {
    return created;
  }

  /**
   * The step whose reply was lost, which reading back went past ({@link Outcome#RECOVERED}): this
   * call's Create, whose {@link KmsException#objectId()} is empty, or its Activate of {@link
   * #key()}, whose {@code objectId()} names the key.
   *
   * @return the step whose outcome was unknown; empty when every reply came
   * @since 0.10.0
   */
  public Optional<OutcomeUnknownException> recoveredFrom() {
    return Optional.ofNullable(recoveredFrom);
  }

  @Override
  public String toString() {
    return "FindOrCreateResult["
        + outcome
        + ", "
        + key.id()
        + ", created "
        + created.stream().map(KeyHandle::id).toList()
        + "]";
  }
}
