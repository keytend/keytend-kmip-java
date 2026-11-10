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
 * What {@link KeyPairCreation#findOrCreateResult()} did: the key pair it returns, and how it got
 * it. It is {@link FindOrCreateResult} for key pairs, with the same outcomes.
 *
 * <pre>{@code
 * FindOrCreatePairResult r = kms.keys().createKeyPair(KeyPairSpec.ec(Curve.P_256))
 *     .named("signer", "signer-public")
 *     .privateUsages(KeyUsage.SIGN).publicUsages(KeyUsage.VERIFY)
 *     .findOrCreateResult();
 * if (r.outcome() == FindOrCreateResult.Outcome.CREATED) {
 *   log.warn("created a new signer {}", r.pair());
 * }
 * }</pre>
 *
 * <p>Immutable, so thread-safe.
 *
 * @since 0.10.0
 */
public final class FindOrCreatePairResult {
  private final KeyPairHandle pair;
  private final FindOrCreateResult.Outcome outcome;
  private final List<KeyPairHandle> created;
  private final OutcomeUnknownException recoveredFrom;

  FindOrCreatePairResult(
      KeyPairHandle pair,
      FindOrCreateResult.Outcome outcome,
      List<KeyPairHandle> created,
      OutcomeUnknownException recoveredFrom) {
    this.pair = pair;
    this.outcome = outcome;
    this.created = List.copyOf(created);
    this.recoveredFrom = recoveredFrom;
  }

  /**
   * The key pair, both keys Active: what {@link KeyPairCreation#findOrCreate()} returns.
   *
   * @return the pair
   */
  public KeyPairHandle pair() {
    return pair;
  }

  /**
   * How the call got the pair: {@link FindOrCreateResult.Outcome#FOUND} (both keys were Active, or
   * another call through the same {@link Kms} found or created them), {@link
   * FindOrCreateResult.Outcome#ACTIVATED} (this call activated a Pre-Active key of a pair it found),
   * {@link FindOrCreateResult.Outcome#CREATED} or {@link FindOrCreateResult.Outcome#RECOVERED} (the
   * Create Key Pair's reply was lost, and the pair was then found by its private name; or the reply
   * to this call's Activate of a key of a pair it found was lost, and the key was read back Active:
   * {@link #recoveredFrom()}). Never
   * {@link FindOrCreateResult.Outcome#REPLACED}: a key pair's builder replaces nothing.
   *
   * @return the outcome
   */
  public FindOrCreateResult.Outcome outcome() {
    return outcome;
  }

  /**
   * The pairs this call is known to have created and left on the server: {@link #pair()} when
   * {@link FindOrCreateResult.Outcome#CREATED}, and a pair it created but did not return because
   * another caller's private key with the name ranked first (a lost race). Such a pair may be
   * Pre-Active, or Active already when the other pair was found after this call activated its own:
   * check its state before doing anything with it, since an Active key may be in use. Empty for
   * {@link FindOrCreateResult.Outcome#RECOVERED}.
   *
   * @return the pairs, unmodifiable
   */
  public List<KeyPairHandle> created() {
    return created;
  }

  /**
   * The step whose reply was lost, which reading back went past ({@link
   * FindOrCreateResult.Outcome#RECOVERED}): this call's Create Key Pair, whose {@link
   * KmsException#objectId()} is empty, or its Activate of a key of {@link #pair()}, whose {@code
   * objectId()} names that key.
   *
   * @return the step whose outcome was unknown; empty when every reply came
   * @since 0.10.0
   */
  public Optional<OutcomeUnknownException> recoveredFrom() {
    return Optional.ofNullable(recoveredFrom);
  }

  @Override
  public String toString() {
    return "FindOrCreatePairResult["
        + outcome
        + ", "
        + pair.privateKey().id()
        + "/"
        + pair.publicKey().id()
        + ", created "
        + created.stream().map(p -> p.privateKey().id() + "/" + p.publicKey().id()).toList()
        + "]";
  }
}
