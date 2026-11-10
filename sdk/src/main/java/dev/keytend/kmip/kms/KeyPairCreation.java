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

import java.util.*;

/**
 * Creates an asymmetric key pair on the server. The usages of both keys are required, and names
 * are given for both keys explicitly. Groups and custom attributes apply to both keys. {@link
 * #create()} returns both keys Active; {@link #createPreActive()} leaves them Pre-Active. A builder
 * is not thread-safe and makes one pair: once a terminal method has made it, both throw {@link
 * IllegalStateException}. {@link #findOrCreate()} is idempotent and may be repeated.
 *
 * <pre>{@code
 * KeyPairHandle signer = kms.keys().createKeyPair(KeyPairSpec.ec(Curve.P_256))
 *     .named("signer", "signer-public")
 *     .privateUsages(KeyUsage.SIGN).publicUsages(KeyUsage.VERIFY)
 *     .create();
 * }</pre>
 *
 * @since 0.10.0
 */
public final class KeyPairCreation {
  private final KmsKeys keys;
  private final KeyPairSpec spec;
  private final Set<KeyUsage> privateUsages = EnumSet.noneOf(KeyUsage.class),
      publicUsages = EnumSet.noneOf(KeyUsage.class);
  private String privateName, publicName;
  private final ObjectOptions common = new ObjectOptions();
  private boolean consumed;

  KeyPairCreation(KmsKeys keys, KeyPairSpec spec) {
    this.keys = keys;
    this.spec = spec;
  }

  /**
   * Names the private key {@code privateName} and the public key {@code publicName}.
   *
   * @param privateName the private key's name
   * @param publicName the public key's name
   * @return this builder
   */
  public KeyPairCreation named(String privateName, String publicName) {
    this.privateName = Objects.requireNonNull(privateName, "privateName");
    this.publicName = Objects.requireNonNull(publicName, "publicName");
    if (privateName.equals(publicName))
      throw new IllegalArgumentException("The two keys need different names");
    return this;
  }

  /**
   * The private key's usages (required), for example {@code SIGN} or {@code DECRYPT}.
   *
   * @param values the usages, added to those already given
   * @return this builder
   */
  public KeyPairCreation privateUsages(KeyUsage... values) {
    for (KeyUsage u : values) privateUsages.add(Objects.requireNonNull(u, "usage"));
    return this;
  }

  /**
   * The public key's usages (required), for example {@code VERIFY} or {@code ENCRYPT}.
   *
   * @param values the usages, added to those already given
   * @return this builder
   */
  public KeyPairCreation publicUsages(KeyUsage... values) {
    for (KeyUsage u : values) publicUsages.add(Objects.requireNonNull(u, "usage"));
    return this;
  }

  /**
   * Adds both keys to a group (not available with the 3.0 draft, which has no Object Group: where 3.0 may be negotiated, use a custom attribute, which every version supports).
   *
   * @param group the group's name
   * @return this builder
   */
  public KeyPairCreation group(String group) {
    common.group(group);
    return this;
  }

  /**
   * Sets a custom attribute on both keys.
   *
   * @param name the attribute
   * @param value its value, of a type {@link KeyAttributes} lists (a {@code byte[]} is copied)
   * @return this builder
   * @throws IllegalArgumentException when the value is not of one of those types
   */
  public KeyPairCreation custom(CustomAttribute name, Object value) {
    common.custom(name, value);
    return this;
  }

  /**
   * Creates the pair and activates both keys.
   *
   * @return the pair, both keys Active
   * @throws PartialCompletionException when the pair was created but not both keys were activated
   *     (do not repeat this call: activate {@link PartialCompletionException#createdPair()}
   *     instead)
   * @throws IllegalStateException when this builder already made a pair
   */
  public KeyPairHandle create() {
    return keys.kms()
        .call(
            "create",
            () -> {
              KeyPairHandle pair = createPreActive();
              keys.activateCreated("createKeyPair", pair);
              return pair;
            });
  }

  /**
   * Creates the pair, Pre-Active. KMIP Create Key Pair replies carry only identifiers, so the two
   * objects they name are read (one batched Get Attributes) and must be a private and a public key.
   *
   * @return the pair, both keys Pre-Active
   * @throws OutcomeUnknownException when the reply names objects of other kinds, or none
   * @throws PartialCompletionException when the pair was created but could not be read
   * @throws IllegalStateException when this builder already made a pair
   */
  public KeyPairHandle createPreActive() {
    if (consumed)
      throw new IllegalStateException("This builder already made a pair; use a new one");
    requireUsages();
    return keys.kms()
        .call(
            "createPreActive",
            () -> {
              return createOnly("createKeyPair");
            });
  }

  private void requireUsages() {
    if (privateUsages.isEmpty() || publicUsages.isEmpty())
      throw new IllegalArgumentException("The usages of both keys are required");
  }

  private KeyPairHandle createOnly(String operation) {
    KeyPairHandle pair =
        keys.createPair(spec, privateUsages, publicUsages, privateName, publicName, common);
    consumed = true;
    keys.checkCreated(operation, List.of(pair.privateKey(), pair.publicKey()), pair);
    return pair;
  }

  /**
   * Returns the Active key pair whose private key has this builder's private name, creating and
   * activating one if there is none. It is {@link KeyCreation#findOrCreate()} for key pairs, and
   * {@link #named(String, String)} is required. Call it once at startup and keep the handle. On an
   * existing pair it sends four requests: two Locates and a Get Attributes of each key.
   *
   * <p>An existing pair must match the builder. Its private key's Public Key link must name a public
   * key that links back to it. Both keys must have this builder's algorithm and size, where any
   * elliptic-curve algorithm matches EC and the size tells the curves apart. Each key must have its
   * requested usages, the public key the public name, and both keys every requested group and custom
   * attribute value. Pre-Active keys are activated. When several private keys have the name, the
   * one {@link KmsKeys#findByName(String, KeyState, KeyState...)} chooses is used.
   *
   * <p>Concurrent calls, and the limits on ranking keys with the name, are as for {@link
   * KeyCreation#findOrCreate()}. On a server without unique names, a lost race leaves a Pre-Active
   * pair under both names. {@code findByName(publicName)} finds Active keys only, so it does not see
   * the leftover public key. Find and destroy such leftovers as <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/kms-design.md#duplicate-names">Duplicate
   * names</a> describes. This method never destroys a key.
   *
   * <p>When the name's only private keys are Compromised or Deactivated, this throws instead of
   * creating an unrelated pair, which would break whatever finds the old pair by name. Finding that
   * out costs two more Locates. Remove both names from the old pair ({@link KeyHandle#removeName})
   * before creating a new pair under them.
   *
   * @return the pair, both keys Active
   * @throws IllegalArgumentException when the names or either key's usages are missing
   * @throws KeyMismatchException when a private key with the name exists but the pair does not
   *     match this builder; the message names the difference, and repeating will not help
   * @throws StateConflictException when the name's only private keys are Compromised or Deactivated,
   *     or the found private key's public key is neither Active nor Pre-Active
   * @throws PartialCompletionException when this call created a pair and a later step failed;
   *     {@link PartialCompletionException#createdPair()} is the pair, and the message says whether
   *     repeating {@code findOrCreate()} resumes
   */
  public KeyPairHandle findOrCreate() {
    return findOrCreateResult().pair();
  }

  /**
   * {@link #findOrCreate()}, saying how it got the pair: found it, activated a Pre-Active key of
   * it, created it, or found it after a Create Key Pair whose reply was lost ({@link
   * FindOrCreatePairResult#outcome()}), and which pairs this call created and left. Same requests,
   * concurrency, refusals and failures, as {@link KeyCreation#findOrCreateResult()} is for {@link
   * KeyCreation#findOrCreate()}. Log or count a creation: at startup it usually means a new pair
   * where one was expected.
   *
   * <pre>{@code
   * FindOrCreatePairResult r = kms.keys().createKeyPair(KeyPairSpec.ec(Curve.P_256))
   *     .named("signer", "signer-public")
   *     .privateUsages(KeyUsage.SIGN).publicUsages(KeyUsage.VERIFY)
   *     .findOrCreateResult();
   * KeyPairHandle signer = r.pair();
   * }</pre>
   *
   * @return the pair and how it was got
   * @throws KmsException as {@link #findOrCreate()}
   * @throws IllegalArgumentException as {@link #findOrCreate()}
   * @since 0.10.0
   */
  public FindOrCreatePairResult findOrCreateResult() {
    if (privateName == null)
      throw new IllegalArgumentException("findOrCreate needs named(privateName, publicName)");
    requireUsages();
    Object flight =
        List.of(
            "keyPair",
            privateName,
            publicName,
            spec,
            Set.copyOf(privateUsages),
            Set.copyOf(publicUsages),
            Set.copyOf(common.groups),
            common.customValues());
    return keys.kms()
        .call(
            "findOrCreate",
            () -> {
              return keys.singleFlightPair(flight, this::findOrCreatePair);
            });
  }

  private FindOrCreatePairResult findOrCreatePair() {
    KeyCreation.Activation activated = new KeyCreation.Activation();
    Optional<KeyHandle> existing =
        keys.findByName(privateName, KeyState.ACTIVE, KeyState.PRE_ACTIVE);
    if (existing.isPresent()) return found(usable(existing.get(), activated), activated, List.of());
    refuseRevoked();
    KeyPairHandle created;
    try {
      created = createOnly("findOrCreate");
    } catch (OutcomeUnknownException | AlreadyExistsException e) {
      KeyPairHandle pair;
      try {
        Optional<KeyHandle> found =
            keys.findByName(privateName, KeyState.ACTIVE, KeyState.PRE_ACTIVE);
        if (found.isEmpty()) throw e;
        pair = usable(found.get(), activated);
      } catch (KmsException | IllegalStateException recovery) {
        // After a lost reply the unknown Create Key Pair stands: a failed read-back proves nothing.
        if (recovery == e || !(e instanceof OutcomeUnknownException)) throw recovery;
        e.addSuppressed(recovery);
        throw e;
      }
      // A lost reply: this call's Create Key Pair, or another caller's, made the pair found.
      if (e instanceof OutcomeUnknownException unknown) {
        if (activated.lost != null) unknown.addSuppressed(activated.lost);
        return new FindOrCreatePairResult(
            pair, FindOrCreateResult.Outcome.RECOVERED, List.of(), unknown);
      }
      return found(pair, activated, List.of());
    } catch (PartialCompletionException e) {
      // The pair exists but could not be read: repeating findOrCreate finds it by name and checks
      // it.
      throw PartialCompletionException.of(
          "findOrCreate",
          e.created(),
          e.createdPair().orElse(null),
          "reading the created keys failed",
          "repeat findOrCreate() to resume",
          (RuntimeException) e.getCause());
    }
    KeyHandle mine = created.privateKey();
    // Every failure from here on reports the pair this call created.
    try {
      KeyHandle chosen =
          keys.findByName(privateName, KeyState.ACTIVE, KeyState.PRE_ACTIVE).orElse(mine);
      if (!chosen.equals(mine))
        return found(usable(chosen, activated), activated, List.of(created));
      keys.activateCreated("findOrCreate", created);
      // A pair another process created at the same moment, which ranks before this one but was not
      // yet visible, may be in use there: look once more, and follow it if it now wins.
      KeyHandle settled =
          keys.findByName(privateName, KeyState.ACTIVE, KeyState.PRE_ACTIVE).orElse(mine);
      return settled.equals(mine)
          ? new FindOrCreatePairResult(
              created, FindOrCreateResult.Outcome.CREATED, List.of(created), null)
          : found(usable(settled, activated), activated, List.of(created));
    } catch (PartialCompletionException e) {
      throw e;
    } catch (KeyMismatchException e) {
      throw PartialCompletionException.of(
          "findOrCreate",
          List.of(created.privateKey(), created.publicKey()),
          created,
          "the key pair another caller made with the names was found not to match this builder",
          "repeating findOrCreate() will not help: change the builder or the other pair; "
              + created.privateKey().id()
              + " and "
              + created.publicKey().id()
              + ", which this call created, are"
              + " left as they are (another instance may have found them)",
          e);
    } catch (KmsException | IllegalStateException e) {
      throw PartialCompletionException.of(
          "findOrCreate",
          List.of(created.privateKey(), created.publicKey()),
          created,
          "finding the key pair the name settles on failed",
          "repeat findOrCreate() to resume",
          e);
    }
  }

  /** A pair found with the name, and what this call's Activates did to its keys. */
  private static FindOrCreatePairResult found(
      KeyPairHandle pair, KeyCreation.Activation activated, List<KeyPairHandle> created) {
    return new FindOrCreatePairResult(pair, activated.outcome(), created, activated.lost);
  }

  /**
   * No Active or Pre-Active private key has the name: refuses when Compromised or Deactivated ones
   * do, since a new, unrelated pair under the names would break whatever finds the old pair by name.
   */
  private void refuseRevoked() {
    List<String> compromised = keys.namedIn(privateName, KeyState.COMPROMISED);
    List<String> deactivated = keys.namedIn(privateName, KeyState.DEACTIVATED);
    if (compromised.isEmpty() && deactivated.isEmpty()) return;
    List<String> all = new ArrayList<>(compromised);
    all.addAll(deactivated);
    throw new StateConflictException(
        "findOrCreate: no Active private key is named "
            + privateName
            + ", but "
            + (compromised.isEmpty()
                ? ""
                : compromised + (compromised.size() == 1 ? " is" : " are") + " COMPROMISED")
            + (!compromised.isEmpty() && !deactivated.isEmpty() ? " and " : "")
            + (deactivated.isEmpty()
                ? ""
                : deactivated + (deactivated.size() == 1 ? " is" : " are") + " DEACTIVATED")
            + "; a new key pair under the names would make signatures made with "
            + (all.size() == 1 ? "it" : "them")
            + " fail to verify, and data encrypted to "
            + (all.size() == 1 ? "its" : "their")
            + " public key fail to decrypt, when the keys are found by"
            + " name, so none was created. To create a new pair under the names, remove them from the old"
            + " pair first (KeyHandle.removeName on the private key and on its public key)",
        null,
        "findOrCreate",
        all.get(0),
        null,
        null);
  }

  /**
   * An existing private key with the name: it and its public key are checked against this builder,
   * and activated if Pre-Active; {@code activated} records what this call's Activates did.
   */
  private KeyPairHandle usable(KeyHandle found, KeyCreation.Activation activated) {
    String id = found.id();
    KeyAttributes mine = found.attributes();
    if (mine.kind() != ObjectKind.PRIVATE_KEY)
      throw mismatch(id, "it is a " + mine.kind() + ", not a private key");
    String publicId =
        mine.link(LinkKind.PUBLIC_KEY).orElseThrow(() -> mismatch(id, "it has no Public Key link"));
    KeyAttributes theirs = keys.handle(publicId).attributes();
    if (theirs.kind() != ObjectKind.PUBLIC_KEY
        || !theirs.link(LinkKind.PRIVATE_KEY).map(id::equals).orElse(false))
      throw mismatch(id, "its public key " + publicId + " does not link back to it");
    List<String> differences = new ArrayList<>();
    check(mine, privateUsages, "it", differences);
    check(theirs, publicUsages, "its public key " + publicId, differences);
    if (!theirs.names().contains(publicName))
      differences.add("its public key " + publicId + " is not named " + publicName);
    if (!differences.isEmpty()) throw mismatch(id, String.join("; ", differences));
    if (theirs.state() != KeyState.ACTIVE && theirs.state() != KeyState.PRE_ACTIVE)
      throw new StateConflictException(
          "findOrCreate: the private key named "
              + privateName
              + " ("
              + id
              + ") is "
              + mine.state()
              + ", but its public key "
              + publicId
              + " is "
              + theirs.state()
              + ", so the pair cannot be used;"
              + " revoke the private key too, and remove the names from both keys to create a new pair",
          null,
          "findOrCreate",
          publicId,
          null,
          null);
    KeyPairHandle pair =
        new KeyPairHandle(
            new KeyHandle(keys, id, ObjectKind.PRIVATE_KEY),
            new KeyHandle(keys, publicId, ObjectKind.PUBLIC_KEY));
    activate(pair.privateKey(), mine, activated);
    activate(pair.publicKey(), theirs, activated);
    return pair;
  }

  private KeyMismatchException mismatch(String id, String difference) {
    return new KeyMismatchException(
        "findOrCreate: a private key named "
            + privateName
            + " exists ("
            + id
            + ") but "
            + difference,
        null,
        "findOrCreate",
        id,
        null,
        null);
  }

  /** The differences between one key of the pair and this builder. */
  private void check(
      KeyAttributes a, Set<KeyUsage> usages, String which, List<String> differences) {
    Algorithm actual = a.algorithm().orElse(null);
    boolean family =
        actual != null
            && (spec.curve() != null ? actual.ellipticCurve() : actual == spec.algorithm());
    if (!family || a.length().orElse(-1) != spec.bits())
      differences.add(
          which
              + " is "
              + (actual == null ? "of no known algorithm" : actual)
              + (a.length().isPresent() ? "-" + a.length().getAsInt() : "")
              + ", not "
              + spec);
    Set<KeyUsage> missing = EnumSet.copyOf(usages);
    missing.removeAll(a.usages());
    if (!missing.isEmpty()) differences.add(which + " lacks the usages " + missing);
    for (String g : common.groups)
      if (!a.groups().contains(g)) differences.add(which + " is not in group " + g);
    for (var e : common.custom.entrySet())
      if (!KeyQuery.all().custom(e.getKey(), e.getValue()).matches(a))
        differences.add(which + ": its " + e.getKey() + " differs");
  }

  /**
   * Activates one key of an existing pair if it is Pre-Active; another caller may do so meanwhile.
   * {@code activated} records what this call's Activate did.
   */
  private static void activate(KeyHandle key, KeyAttributes a, KeyCreation.Activation activated) {
    if (a.state() != KeyState.PRE_ACTIVE) return;
    try {
      key.activate();
      activated.activated = true;
    } catch (KmsException e) {
      // Any refusal (or an unknown outcome) is checked against the key's state: another caller may
      // have activated it meanwhile, which KMIP 1.x servers refuse with Permission Denied. This
      // call did not create the key, so a failure here is not a partial completion. Not when the
      // server refused this client's credentials.
      if (Failures.credentialsRefused(e)) throw e;
      KeyState now;
      try {
        now = key.attributes().state();
      } catch (KmsException | IllegalStateException unreadable) {
        e.addSuppressed(unreadable);
        throw e;
      }
      if (now == KeyState.ACTIVE) {
        // After a lost reply this call's Activate, or another caller's, took effect.
        if (e instanceof OutcomeUnknownException unknown) activated.lost(unknown);
        return;
      }
      if (now == KeyState.PRE_ACTIVE) throw e;
      throw new StateConflictException(
          "findOrCreate: " + key.id() + " is " + now + " now, not Active; repeat findOrCreate()",
          e,
          "findOrCreate",
          key.id(),
          null,
          null);
    }
  }
}
