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
 * Creates a symmetric key on the server: {@code kms.keys().createAes(256).named("orders")
 * .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create()}. Usages are required. {@link #create()}
 * returns an Active key, ready to use; {@link #createPreActive()} leaves it Pre-Active for staged
 * use. A builder is not thread-safe and makes one key: once {@code create()} or {@code
 * createPreActive()} has made it, they throw {@link IllegalStateException} (after a failure that
 * made nothing they may be called again). {@link #findOrCreate()} is idempotent and may be
 * repeated.
 *
 * @since 0.10.0
 */
public final class KeyCreation {
  private final KmsKeys keys;
  private final Algorithm algorithm;
  private final int bits;
  private final ObjectOptions options = new ObjectOptions();
  private boolean consumed, replacingCompromised, refusingExistingName, refusingPreActive;

  /** The one Pre-Active key {@link #allowingPreActive} lets the call activate; or null. */
  private KeyHandle approved;

  KeyCreation(KmsKeys keys, Algorithm algorithm, int bits) {
    this.keys = keys;
    this.algorithm = algorithm;
    this.bits = bits;
  }

  /**
   * Adds a name (objects may have several).
   *
   * @param name the name
   * @return this builder
   */
  public KeyCreation named(String name) {
    options.name(name);
    return this;
  }

  /**
   * The usages the key permits; at least one is required.
   *
   * @param values the usages, added to those already given
   * @return this builder
   */
  public KeyCreation usages(KeyUsage... values) {
    options.usages(values);
    return this;
  }

  /**
   * Adds the key to a group (not available with the 3.0 draft, which has no Object Group: where 3.0 may be negotiated, use a custom attribute, which every version supports).
   *
   * @param group the group's name
   * @return this builder
   */
  public KeyCreation group(String group) {
    options.group(group);
    return this;
  }

  /**
   * Sets a custom attribute; see {@link KeyAttributes} for the value types.
   *
   * @param name the attribute
   * @param value its value, of a type {@link KeyAttributes} lists (a {@code byte[]} is copied)
   * @return this builder
   * @throws IllegalArgumentException when the value is not of one of those types
   */
  public KeyCreation custom(CustomAttribute name, Object value) {
    options.custom(name, value);
    return this;
  }

  /**
   * Sets the key's KMIP Extractable attribute (KMIP 1.4 §3.50, 2.1 §4.23).
   *
   * <ul>
   *   <li>{@code false}: the server refuses to return the key's value with Get, wrapped or not,
   *       while Extractable remains false. A key-encryption key wants this. Its operations, such as
   *       {@link CurrentKey#seal} and {@link CurrentKey#wrapKey(javax.crypto.SecretKey, byte[])},
   *       run on the server and never need the value.
   *   <li>{@code true}: the key can be retrieved, as a key used outside the KMS needs ({@link
   *       KeyHandle#asSecretKey}, a database's transparent data encryption). This is KMIP's
   *       default, stated explicitly.
   *   <li>Not set: the server's default (true). Nothing is checked.
   * </ul>
   *
   * <p>KMIP 1.4 introduced the attribute. Below 1.4, a builder with it set is refused ({@link
   * UnsupportedException}) before anything is sent. The key is never created without it.
   *
   * <p>When it is set, the value the server states is checked. A key this builder creates ({@link
   * #create()}, {@link #createPreActive()}, {@link #findOrCreate()}) is read back with one more Get
   * Attributes before it is activated. If it does not state the value asked, or states another, it
   * is neither activated nor returned: {@link PartialCompletionException}, with a {@link
   * KeyMismatchException} as the cause. An existing key that {@code findOrCreate} finds is checked
   * the same way, and a mismatch throws {@link KeyMismatchException}.
   *
   * <p>The server enforces the attribute. On KMIP 1.4 to 2.1, a client allowed to modify the key can
   * set it back to true, so grant that right narrowly.
   *
   * @param extractable the Extractable attribute to set
   * @return this builder
   * @since 0.10.0
   */
  public KeyCreation extractable(boolean extractable) {
    options.extractable = extractable;
    return this;
  }

  /**
   * Sets the key's KMIP Sensitive attribute (KMIP 1.4 §3.48, 2.1 §4.55). {@code true} makes the
   * server refuse to return the key's value with Get unless it is wrapped by another key, so {@link
   * KeyHandle#asSecretKey} (which asks for it unwrapped) is refused; {@code false} is KMIP's default,
   * stated explicitly. Checked and refused below KMIP 1.4 as {@link #extractable(boolean)}.
   *
   * @param sensitive the Sensitive attribute to set
   * @return this builder
   * @since 0.10.0
   */
  public KeyCreation sensitive(boolean sensitive) {
    options.sensitive = sensitive;
    return this;
  }

  /**
   * Lets {@link #findOrCreate()} replace a Compromised key instead of refusing. When the name's only
   * keys are Compromised, or Compromised and Deactivated, {@code findOrCreate} replaces the
   * Compromised key the name ranks first ({@link KmsKeys#findByName(String, KeyState, KeyState...)})
   * as {@link KeyHandle#replaceCompromised} does, and returns the replacement. The replacement gets
   * the Extractable and Sensitive values set on this builder. Where none is set, it keeps the
   * Compromised key's Extractable false and Sensitive true.
   *
   * <p>When Compromised keys of more than one rotation lineage have the name, none is replaced and
   * {@code findOrCreate} throws {@link StateConflictException} naming them all. A name proves
   * nothing about which key is yours, so replace the right one with {@link
   * KeyHandle#replaceCompromised}. Afterwards, re-seal the old records through the replacement's
   * {@link KeyHandle#compromisedPredecessors()}, as <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#a-compromised-key">A
   * compromised key</a> describes. No effect on {@link #create()}.
   *
   * @return this builder
   */
  public KeyCreation replacingCompromised() {
    replacingCompromised = true;
    return this;
  }

  /**
   * Makes {@link #create()} and {@link #createPreActive()} refuse a name that an object not
   * destroyed has already, instead of creating a second object with it. Before the Create, each
   * name is looked up (one Locate, without a state filter, and Get Attributes of what it finds).
   * When an object that is not destroyed has it, the call throws {@link AlreadyExistsException}
   * naming that object, and creates nothing. An object found that cannot be read fails the call.
   *
   * <p>Use it where the server does not enforce unique names, so that a second key with a name is
   * not made by mistake: lookups by name keep choosing the first ({@link KmsKeys#findByName}). It
   * is a check made by this client, so two callers creating the same name at the same moment can
   * both pass it. Only a server that enforces unique names prevents that. Not with {@link
   * #findOrCreate()}, which returns the key that has the name.
   *
   * @return this builder
   * @since 0.10.0
   */
  public KeyCreation refusingExistingName() {
    refusingExistingName = true;
    return this;
  }

  /**
   * Makes {@link #findOrCreate()} and {@link #findOrCreateResult()} refuse to activate a Pre-Active
   * key that the call did not create, instead of activating it. Use it where activating an existing
   * key needs approval, such as an operator's tool: the refusal names the key, which can be shown,
   * approved and activated ({@link KeyHandle#activate()}), and the call repeated.
   *
   * <pre>{@code
   * KeyCreation creation = kms.keys().createAes(256).named("orders-kek")
   *     .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).refusingPreActive();
   * try {
   *   return creation.findOrCreateResult();
   * } catch (StateConflictException e) {
   *   if (e.conflict() != StateConflictException.Conflict.STATE
   *       || e.observedState().orElse(null) != KeyState.PRE_ACTIVE) throw e;
   *   KeyHandle staged = kms.keys().handle(e.objectId().orElseThrow());
   *   // show staged, ask for approval, then (a refusal made no key, so the builder is reused):
   *   return creation.allowingPreActive(staged).findOrCreateResult();
   * }
   * }</pre>
   *
   * <p>An Active key with the name is returned as before, and a key the call creates is activated
   * as before. A key an earlier call created and left Pre-Active, such as one cut short, is refused
   * too. So is a Pre-Active key found after this call's Create had an unknown outcome: it may be
   * this call's or another caller's, so the call throws that {@link OutcomeUnknownException}, with
   * the refusal suppressed on it. Not with {@link #replacingCompromised()}, whose procedure finishes
   * a replacement it finds.
   *
   * @return this builder
   * @since 0.10.0
   */
  public KeyCreation refusingPreActive() {
    refusingPreActive = true;
    return this;
  }

  /**
   * {@link #refusingPreActive()}, except that {@code approved}, a Pre-Active key someone approved
   * activating, is activated by the call when the name leads to it. Another Pre-Active key the name
   * leads to is refused as before. Use it to repeat a call that {@link #refusingPreActive()}
   * refused, once its key was shown and approved: the call activates exactly that key and returns
   * it ({@link FindOrCreateResult.Outcome#ACTIVATED}; {@link FindOrCreateResult.Outcome#FOUND}
   * when another caller activated it first; {@link FindOrCreateResult.Outcome#RECOVERED} when the
   * reply to its Activate was lost and the key was read back Active), so nothing is left to do
   * between the approval and the result. The key is checked against this builder as any other.
   *
   * @param approved the Pre-Active key whose activation was approved, a handle of the same {@link
   *     Kms}
   * @return this builder
   * @throws IllegalArgumentException when {@code approved} is a handle of another {@link Kms}
   * @since 0.10.0
   */
  public KeyCreation allowingPreActive(KeyHandle approved) {
    Objects.requireNonNull(approved, "approved");
    if (!approved.sameKms(keys.kms()))
      throw new IllegalArgumentException(
          "allowingPreActive: "
              + approved
              + " is a handle of another Kms; an identifier names an object only on its own"
              + " server");
    refusingPreActive = true;
    this.approved = approved;
    return this;
  }

  /**
   * Creates the key and activates it.
   *
   * @return the key, Active
   * @throws PartialCompletionException when the key was created but not activated. Do not repeat
   *     this call. Do as the message says: after a failed activation it says to activate {@link
   *     PartialCompletionException#created()}. When the server did not keep the requested
   *     Extractable or Sensitive, it says not to, and when reading them back failed, it says to
   *     check them first
   * @throws AlreadyExistsException with {@link #refusingExistingName()}, when an object that is not
   *     destroyed has a name of this builder; nothing was created
   * @throws IllegalStateException when this builder already made a key
   */
  public KeyHandle create() {
    unconsumed();
    return keys.kms()
        .call(
            "create",
            () -> {
              KeyHandle key = createOnly();
              keys.activateCreated("create", List.of(key));
              return key;
            });
  }

  /**
   * Creates the key, Pre-Active: it cannot be used until {@link KeyHandle#activate()}.
   *
   * @return the key, Pre-Active
   * @throws PartialCompletionException when the server did not keep the requested Extractable or
   *     Sensitive, or reading them back failed; the key stays Pre-Active, and the message says what
   *     to do
   * @throws AlreadyExistsException as {@link #create()}
   * @throws IllegalStateException when this builder already made a key
   */
  public KeyHandle createPreActive() {
    unconsumed();
    return keys.kms().call("createPreActive", this::createOnly);
  }

  private KeyHandle createOnly() {
    options.requireUsages();
    if (refusingExistingName) keys.refuseExistingNames("create", options.names);
    KeyHandle key = keys.createSymmetric(algorithm, bits, options).knowing(options.usages);
    consumed = true;
    return key;
  }

  private void unconsumed() {
    if (consumed) throw new IllegalStateException("This builder already made a key; use a new one");
  }

  /**
   * Returns the Active key with this builder's name, creating and activating one if there is none.
   * Exactly one name is required. Call it once at startup and keep the handle. On an existing key it
   * sends three requests: one Locate and two Get Attributes.
   *
   * <p>An existing key must match the builder: algorithm and size, every requested usage, group and
   * custom attribute value, and any Extractable or Sensitive value set here. A Pre-Active one is
   * activated. When several keys have the name, the one {@link KmsKeys#findByName(String, KeyState,
   * KeyState...)} chooses is used. A key this call creates is checked the same way before it is
   * activated.
   *
   * <p>Every instance may call it at startup at the same time. Concurrent calls through one {@link
   * Kms} get the same key. Across processes, callers get the same key only on a server that
   * enforces unique names. Elsewhere a lost race leaves a Pre-Active key under the name, which
   * {@link KeyHandle#leftovers()} lists. This method never destroys a key. Destroy leftovers that are
   * yours before retiring old keys, or this method fails once the lineage's oldest key is purged.
   * See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/kms-design.md#findorcreate">findOrCreate</a>
   * and <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/kms-design.md#duplicate-names">Duplicate
   * names</a>.
   *
   * <p>When the name's only keys are Compromised or Deactivated, this throws instead of creating an
   * unrelated key, which would make every record sealed under the old keys look misfiled. Replace a
   * Compromised key first ({@link KeyHandle#replaceCompromised}), or opt in with {@link
   * #replacingCompromised()}. A name whose keys are only Deactivated was retired on purpose. Remove
   * the name from them ({@link KeyHandle#removeName}) before creating a new key under it.
   *
   * <p>When no key has the name, the name may be moving between two keys of a lineage (a compromise
   * replacement or a reconcile, perhaps one that stopped); the move is recorded on the key that
   * gets it, and this call refuses while it finds such a record. Finding it needs a search by a
   * client attribute: a server that cannot make that search (PyKMIP) shows none, and one that
   * ignores the filter is read only as far as its first objects. There a stopped move is
   * not seen and this call creates a new key under the name, so finish a stopped replacement
   * ({@link KeyHandle#replaceCompromised}, {@link KmsKeys#reconcile(String)}) before instances
   * start.
   *
   * @return the key, Active
   * @throws IllegalArgumentException when the builder does not have exactly one name, or no usages
   * @throws KeyMismatchException when a key with the name exists but does not match this builder;
   *     the message names the difference, and repeating will not help
   * @throws StateConflictException when the name's only keys are Compromised (without {@link
   *     #replacingCompromised()}) or Deactivated, or the keys with the name cannot be ranked
   * @throws UnsupportedException below KMIP 1.4 when Extractable or Sensitive is set, or when a key
   *     with the name has more than 64 rotations behind it and other keys have the name too
   * @throws StateConflictException with {@link #refusingPreActive()}, when the key the name leads
   *     to is Pre-Active and this call did not create it: {@link
   *     StateConflictException#objectId()} names it and {@link
   *     StateConflictException#observedState()} is Pre-Active; nothing was activated. When this call
   *     had created a key already, that refusal is the cause of a {@link
   *     PartialCompletionException} that lists it
   * @throws OutcomeUnknownException when this call's Create had an unknown outcome and reading back
   *     did not end in a usable key: the lookup failed, the key found does not match, or (with
   *     {@link #refusingPreActive()}) it is Pre-Active. The failure of that read-back is suppressed
   *     on it. A key with the name may exist, made by this call or another caller. Its {@link
   *     KmsException#objectId()} is empty. Also when this call's Activate of an existing Pre-Active
   *     key had an unknown outcome and reading the key back failed: then {@code objectId()} names
   *     that key, which may be Active now, and no key was created by this call
   * @throws PartialCompletionException when this call created a key and a later step failed; the
   *     message says which step, and whether repeating {@code findOrCreate()} resumes
   */
  public KeyHandle findOrCreate() {
    return findOrCreateResult().key();
  }

  /**
   * {@link #findOrCreate()}, saying how it got the key: found it, activated a Pre-Active one,
   * created it, or replaced a Compromised one ({@link FindOrCreateResult.Outcome}). Same requests,
   * refusals and failures. Log or count a creation: at startup it usually means a new key where one
   * was expected.
   *
   * <pre>{@code
   * FindOrCreateResult r = kms.keys().createAes(256).named("orders-kek")
   *     .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).findOrCreateResult();
   * KeyHandle kek = r.key();
   * }</pre>
   *
   * @return the key and how it was got
   * @throws KmsException as {@link #findOrCreate()}
   * @throws IllegalArgumentException as {@link #findOrCreate()}, with {@link
   *     #refusingExistingName()}, and with both {@link #refusingPreActive()} and {@link
   *     #replacingCompromised()}
   * @since 0.10.0
   */
  public FindOrCreateResult findOrCreateResult() {
    if (options.names.size() != 1)
      throw new IllegalArgumentException("findOrCreate needs exactly one name");
    if (refusingExistingName)
      throw new IllegalArgumentException(
          "findOrCreate returns the key that has the name, so refusingExistingName() does not go"
              + " with it");
    if (refusingPreActive && replacingCompromised)
      throw new IllegalArgumentException(
          "replacingCompromised() finishes a replacement it finds, activating it, so"
              + " refusingPreActive() does not go with it");
    options.requireUsages();
    options.protection().require(keys.kms().protocolVersion(), "findOrCreate");
    String name = options.names.get(0);
    Object flight =
        List.of(
            name,
            algorithm,
            bits,
            Set.copyOf(options.usages),
            Set.copyOf(options.groups),
            options.customValues(),
            replacingCompromised,
            refusingPreActive,
            approved == null ? "" : approved.id(),
            options.protection());
    return keys.kms()
        .call(
            "findOrCreate",
            () -> {
              return keys.singleFlightResult(flight, () -> findOrCreate(name));
            });
  }

  private FindOrCreateResult findOrCreate(String name) {
    // Each look is one Locate by name, without a state filter, and one Get Attributes of what it
    // found: a snapshot. Looks per state could each miss a key whose name or state moved between
    // them (another instance replacing a Compromised key gives the name to its replacement), and
    // then a new, unrelated key would be created under the name.
    for (int look = 1; ; look++) {
      List<KeyAttributes> named = keys.named(name);
      Optional<KeyHandle> existing = live(named);
      Activation activated = new Activation();
      if (existing.isPresent()) {
        KeyHandle key = usable(existing.get(), name, activated);
        if (key != null) return found(key, activated, List.of());
      } else {
        KeyHandle replacement = revoked(name, named);
        if (replacement == null) break;
        KeyHandle key = usable(replacement, name, activated);
        if (key != null) return replaced(key);
      }
      // The key changed state since the look (revoked, destroyed): look again.
      if (look == 3)
        throw new StateConflictException(
            "findOrCreate: the keys named "
                + name
                + " kept changing state while being read; repeat findOrCreate()",
            null,
            "findOrCreate",
            existing.map(KeyHandle::id).orElse(null),
            null,
            null);
    }
    // Where names are unique, a name being moved between keys (a compromise replacement, a
    // reconcile) is on neither for a moment; the move is written down on the key that gets it
    // first,
    // and a new key under the name now would take it from the lineage.
    List<String> moving = keys.pendingName(name);
    // A compromise replacement (perhaps this call's, cut short) that stopped between taking the
    // name off the Compromised key and giving it: with replacingCompromised(), finish it as a
    // repeated replaceCompromised would.
    if (!moving.isEmpty() && replacingCompromised) {
      KeyHandle resumed = resumeReplacement(moving);
      if (resumed != null) {
        KeyHandle key = usable(resumed, name, new Activation());
        if (key != null) return replaced(key);
      }
    }
    if (!moving.isEmpty()) {
      String to =
          moving.size() <= 8
              ? moving.toString()
              : moving.subList(0, 8) + " and " + (moving.size() - 8) + " more";
      throw new StateConflictException(
              "findOrCreate: no key is named "
                  + name
                  + " right now, but the name is being moved to "
                  + to
                  + " (a compromise replacement or reconcile in progress, or one that stopped); repeat findOrCreate()"
                  + " in a moment; if it stays so, check that "
                  + to
                  + " is yours (anyone can write that record"
                  + " on a key of their own) and finish the move: kms.keys().reconcile(\""
                  + name
                  + "\"); if it is"
                  + " not, or its lineage was retired on purpose, remove the record: kms.keys().clearPendingName(\""
                  + name
                  + "\"); where it cannot be removed (a key these credentials may not change), create the key"
                  + " under the name by hand (create() with the same builder): a name holder ends this refusal",
              null,
              "findOrCreate",
              moving.get(0),
              null,
              null)
          .because(StateConflictException.Conflict.NAME);
    }
    KeyHandle created;
    try {
      created = createOnly();
    } catch (OutcomeUnknownException | AlreadyExistsException e) {
      Activation activated = new Activation();
      KeyHandle key;
      try {
        Optional<KeyHandle> found = live(keys.named(name));
        key = found.isEmpty() ? null : usable(found.get(), name, activated);
      } catch (KmsException | IllegalStateException recovery) {
        // After a lost reply the unknown Create stands: a failed lookup, or a key that cannot be
        // used or (refusingPreActive) activated, proves nothing about what the Create did.
        if (!(e instanceof OutcomeUnknownException)) throw recovery;
        e.addSuppressed(recovery);
        throw e;
      }
      if (key == null) throw e;
      // A lost reply: this call's Create, or another caller's, made the key found.
      if (e instanceof OutcomeUnknownException unknown) {
        if (activated.lost != null) unknown.addSuppressed(activated.lost);
        return new FindOrCreateResult(
            key, FindOrCreateResult.Outcome.RECOVERED, List.of(), unknown);
      }
      return found(key, activated, List.of());
    }
    // Every failure from here on reports the key this call created. It is never destroyed: once
    // another instance can have found it, no read shows that nothing used it; a key that
    // loses stays Pre-Active, and KeyHandle.leftovers() lists it.
    try {
      KeyHandle chosen = live(keys.named(name)).orElse(created);
      Activation activated = new Activation();
      if (!chosen.equals(created)) {
        KeyHandle key = usable(chosen, name, activated);
        if (key != null) return found(key, activated, List.of(created));
      }
      keys.activateCreated("findOrCreate", List.of(created));
      FindOrCreateResult mine =
          new FindOrCreateResult(
              created, FindOrCreateResult.Outcome.CREATED, List.of(created), null);
      // A key another process created at the same moment, which ranks before this one but was not
      // yet visible, may be in use there: look once more, and follow it if it now wins.
      KeyHandle settled = live(keys.named(name)).orElse(created);
      if (settled.equals(created)) return mine;
      KeyHandle key = usable(settled, name, activated);
      return key != null ? found(key, activated, List.of(created)) : mine;
    } catch (PartialCompletionException e) {
      throw e;
    } catch (StateConflictException e) {
      if (!refusal(e)) throw unsettled(created, e);
      throw PartialCompletionException.of(
          "findOrCreate",
          List.of(created),
          null,
          "another caller's key with the name, "
              + e.objectId().orElse("")
              + ", ranks first and is Pre-Active, and refusingPreActive() does not activate it",
          "activate it once that is approved (or let its creator do so), then repeat"
              + " findOrCreate(); "
              + created.id()
              + ", which this call created, is left as it is (KeyHandle.leftovers() lists it while"
              + " it is Pre-Active)",
          e);
    } catch (KeyMismatchException e) {
      throw PartialCompletionException.of(
          "findOrCreate",
          List.of(created),
          null,
          "the key another caller made with the name was found not to match this builder",
          "repeating findOrCreate() will not help: change the builder or the other key; "
              + created.id()
              + ", which this call created, is left as it is (KeyHandle.leftovers() lists it while it is"
              + " Pre-Active)",
          e);
    } catch (KmsException | IllegalStateException e) {
      throw unsettled(created, e);
    }
  }

  /** After this call's {@code created}, finding the key the name settles on failed with {@code e}. */
  private static PartialCompletionException unsettled(KeyHandle created, RuntimeException e) {
    return PartialCompletionException.of(
        "findOrCreate",
        List.of(created),
        null,
        "finding the key the name settles on failed",
        "repeat findOrCreate() to resume",
        e);
  }

  /** Whether {@code e} is {@link #usable}'s refusal of a Pre-Active key ({@link #refusingPreActive()}). */
  private boolean refusal(StateConflictException e) {
    return refusingPreActive && e.observedState().orElse(null) == KeyState.PRE_ACTIVE;
  }

  /** A key found with the name, and what this call's Activate did to it ({@code activated}). */
  private static FindOrCreateResult found(
      KeyHandle key, Activation activated, List<KeyHandle> created) {
    return new FindOrCreateResult(key, activated.outcome(), created, activated.lost);
  }

  /** The replacement of a Compromised key with the name, made or finished by this call. */
  private static FindOrCreateResult replaced(KeyHandle key) {
    return new FindOrCreateResult(key, FindOrCreateResult.Outcome.REPLACED, List.of(), null);
  }

  /**
   * What a find-or-create's Activate did to an existing key it returns (of a pair, to either key):
   * activated it, its reply confirming it, or had an unknown outcome that reading back went past,
   * the key being Active. Neither when the key was Active already, or another caller's activation
   * came first (this call's Activate refused).
   */
  static final class Activation {
    /** This call's Activate took effect, its reply confirming it. */
    boolean activated;

    /** An Activate whose reply was lost, the key read back Active; or null. */
    OutcomeUnknownException lost;

    /** Records {@code e}, the first unknown Activate that reading back went past. */
    void lost(OutcomeUnknownException e) {
      if (lost == null) lost = e;
    }

    /**
     * {@link FindOrCreateResult.Outcome#RECOVERED} after a lost reply, {@link
     * FindOrCreateResult.Outcome#ACTIVATED} or {@link FindOrCreateResult.Outcome#FOUND}.
     */
    FindOrCreateResult.Outcome outcome() {
      return lost != null
          ? FindOrCreateResult.Outcome.RECOVERED
          : activated ? FindOrCreateResult.Outcome.ACTIVATED : FindOrCreateResult.Outcome.FOUND;
    }
  }

  /**
   * The replacement of the one Compromised key whose confirmed replacements record the name as
   * pending ({@code moving}), finished by its {@code replaceCompromised} procedure; null when the
   * records are not all on replacements of one Compromised key (a name proves nothing, and neither
   * does a record: a stranger can write one on a key of its own; then nothing is done here).
   */
  private KeyHandle resumeReplacement(List<String> moving) {
    Set<String> olds = new HashSet<>();
    KeyAttributes old = null;
    for (String id : moving) {
      KeyAttributes r = keys.read(id).orElse(null);
      if (r == null) return null;
      List<KeyAttributes> confirmed = new ArrayList<>();
      for (String p : r.links(LinkKind.REPLACED))
        keys.read(p)
            .filter(o -> Lineage.replaced(r, o) && KeyHandle.compromised(o))
            .ifPresent(confirmed::add);
      if (confirmed.size() != 1) return null;
      olds.add(confirmed.get(0).id());
      old = confirmed.get(0);
    }
    if (olds.size() != 1
        || old.state() != KeyState.COMPROMISED
        || old.kind() != ObjectKind.SYMMETRIC_KEY) return null;
    ObjectOptions fresh = new ObjectOptions();
    fresh.usages.addAll(options.usages);
    fresh.names.addAll(options.names);
    fresh.groups.addAll(options.groups);
    fresh.custom.putAll(options.custom);
    fresh.protection(options.protection());
    return keys.handle(old.id()).replaceCompromised(old, null, fresh);
  }

  /**
   * The Active or Pre-Active key among {@code named} that the name chooses ({@link
   * KmsKeys#findByName(String, KeyState, KeyState...)} for those states).
   */
  private Optional<KeyHandle> live(List<KeyAttributes> named) {
    return keys.chooseAmongRead(
        named.stream()
            .filter(a -> a.state() == KeyState.ACTIVE || a.state() == KeyState.PRE_ACTIVE)
            .toList());
  }

  /**
   * No Active or Pre-Active key has the name: refuses when Compromised or Deactivated ones do
   * (creating an unrelated key would quarantine their records), or, with {@link
   * #replacingCompromised()}, replaces the Compromised one. Null when the name is free. The
   * Compromised key named in the advice, and replaced, is the one the name ranks first ({@link
   * KmsKeys#findByName(String, KeyState, KeyState...)}); when the Compromised keys with the name
   * belong to more than one rotation lineage, a name proves nothing about which is the caller's (a
   * stranger can name a key like it and revoke it), so they are all named and none is replaced.
   */
  private KeyHandle revoked(String name, List<KeyAttributes> named) {
    List<KeyAttributes> compromisedKeys =
        named.stream().filter(a -> a.state() == KeyState.COMPROMISED).toList();
    List<String> compromised =
        compromisedKeys.stream().map(KeyAttributes::id).sorted(Lineage.IDENTIFIERS).toList();
    List<String> deactivated =
        named.stream()
            .filter(a -> a.state() == KeyState.DEACTIVATED)
            .map(KeyAttributes::id)
            .sorted(Lineage.IDENTIFIERS)
            .toList();
    if (compromised.isEmpty() && deactivated.isEmpty()) return null;
    Optional<KeyHandle> ranked = Optional.empty();
    boolean ambiguous = false;
    if (!compromised.isEmpty()) {
      ambiguous = !oneLineage(compromised);
      if (!ambiguous) ranked = keys.chooseAmongRead(compromisedKeys);
    }
    if (replacingCompromised && !compromised.isEmpty() && !ambiguous) {
      KeyHandle chosen = ranked.orElseThrow();
      ObjectOptions fresh = new ObjectOptions();
      fresh.usages.addAll(options.usages);
      fresh.names.addAll(options.names);
      fresh.groups.addAll(options.groups);
      fresh.custom.putAll(options.custom);
      fresh.protection(options.protection());
      KeyAttributes current = chosen.attributes();
      if (current.kind() != ObjectKind.SYMMETRIC_KEY)
        throw new KeyMismatchException(
            "findOrCreate: the Compromised object named "
                + name
                + " ("
                + chosen.id()
                + ") is a "
                + current.kind()
                + ", not a symmetric key, so it is not replaced",
            null,
            "findOrCreate",
            chosen.id(),
            null,
            null);
      return chosen.replaceCompromised(current, null, fresh);
    }
    List<String> all = new ArrayList<>(compromised);
    all.addAll(deactivated);
    String recover =
        compromised.isEmpty()
            ? ""
            : ambiguous
                ? "Compromised keys of different lineages have the name, and a name proves nothing about which"
                    + " is yours (anyone who can create keys can name one like yours and revoke it), so none was"
                    + " replaced: replace the one you revoked yourself, kms.keys().handle(id).replaceCompromised(...)"
                    + " (docs/operating-keys.md, \"A compromised key\"), and remove the name from the others"
                : "Recover first: kms.keys().handle(\""
                    + ranked.orElseThrow().id()
                    + "\").replaceCompromised(...)"
                    + " gives the name a replacement and re-seals nothing by itself (docs/operating-keys.md, \"A"
                    + " compromised key\"); or call findOrCreate with replacingCompromised()";
    throw new StateConflictException(
        "findOrCreate: no Active key is named "
            + name
            + ", but "
            + (compromised.isEmpty()
                ? ""
                : compromised + (compromised.size() == 1 ? " is" : " are") + " COMPROMISED")
            + (!compromised.isEmpty() && !deactivated.isEmpty() ? " and " : "")
            + (deactivated.isEmpty()
                ? ""
                : deactivated + (deactivated.size() == 1 ? " is" : " are") + " DEACTIVATED")
            + "; a new key under the name would make every record sealed under "
            + (all.size() == 1 ? "it" : "them")
            + " look misfiled, so none was created. "
            + (compromised.isEmpty()
                ? "If the name was retired on purpose, remove it from "
                    + (deactivated.size() == 1 ? "that key" : "those keys")
                    + " (KeyHandle.removeName) first"
                : recover),
        null,
        "findOrCreate",
        ranked.map(KeyHandle::id).orElse(all.get(0)),
        null,
        null);
  }

  /**
   * Whether the keys {@code ids} all belong to one rotation lineage: the keys each one's walk back
   * (along links both keys confirm) reaches overlap, so a purged first key does not split a
   * lineage; false when walks that do not meet cannot be followed back to their start.
   */
  private boolean oneLineage(List<String> ids) {
    if (ids.size() <= 1) return true;
    List<Set<String>> walks = new ArrayList<>();
    try {
      for (String id : ids) {
        Optional<KeyAttributes> a = keys.read(id);
        if (a.isEmpty()) continue;
        Lineage.Back back = Lineage.back(a.get(), keys::read);
        Set<String> walk = new HashSet<>();
        for (KeyAttributes k : back.keys()) walk.add(k.id());
        walks.add(walk);
      }
    } catch (KmsException | IllegalStateException unreadable) {
      return false;
    }
    // Merge walks that share a key; one group left is one lineage.
    List<Set<String>> groups = new ArrayList<>();
    for (Set<String> w : walks) {
      Set<String> merged = new HashSet<>(w);
      for (java.util.Iterator<Set<String>> it = groups.iterator(); it.hasNext(); ) {
        Set<String> g = it.next();
        if (!java.util.Collections.disjoint(g, merged)) {
          merged.addAll(g);
          it.remove();
        }
      }
      groups.add(merged);
    }
    return groups.size() <= 1;
  }

  /**
   * An existing key with the name: checked against this builder, and activated if Pre-Active; null
   * when it is no longer Active or Pre-Active (revoked or destroyed since the look), so the caller
   * looks again rather than return a key that cannot be used. {@code activated} records what this
   * call's Activate did.
   */
  private KeyHandle usable(KeyHandle key, String name, Activation activated) {
    KeyAttributes a;
    try {
      a = key.attributes();
    } catch (NotFoundException gone) {
      return null;
    }
    key.knowing(a);
    List<String> differences = new ArrayList<>();
    Algorithm actual = a.algorithm().orElse(null);
    if (a.kind() != ObjectKind.SYMMETRIC_KEY && a.kind() != ObjectKind.OTHER)
      differences.add("it is a " + a.kind() + ", not a symmetric key");
    else if (actual == null)
      differences.add("it has no Cryptographic Algorithm, not " + algorithm + "-" + bits);
    else if (actual != algorithm || a.length().orElse(-1) != bits)
      differences.add(
          "it is "
              + actual
              + (a.length().isPresent() ? "-" + a.length().getAsInt() : "")
              + ", not "
              + algorithm
              + "-"
              + bits);
    Set<KeyUsage> missing = EnumSet.copyOf(options.usages);
    missing.removeAll(a.usages());
    if (!missing.isEmpty()) differences.add("it lacks the usages " + missing);
    for (String g : options.groups)
      if (!a.groups().contains(g)) differences.add("it is not in group " + g);
    for (var e : options.custom.entrySet())
      if (!KeyQuery.all().custom(e.getKey(), e.getValue()).matches(a))
        differences.add("its " + e.getKey() + " differs");
    // Never relaxed: a key that does not state the protection asked (the attribute absent) is no
    // more accepted than one that states another.
    differences.addAll(options.protection().differences(a));
    if (!differences.isEmpty())
      throw new KeyMismatchException(
          "findOrCreate: a key named "
              + name
              + " exists ("
              + key.id()
              + ") but "
              + String.join("; ", differences),
          null,
          "findOrCreate",
          key.id(),
          null,
          null);
    if (a.state() == KeyState.PRE_ACTIVE && refusingPreActive && !key.equals(approved))
      throw new StateConflictException(
              "findOrCreate: the key named "
                  + name
                  + ", "
                  + key.id()
                  + ", is Pre-Active, and refusingPreActive() does not activate a key this call did"
                  + " not create; nothing was activated: once activating "
                  + key.id()
                  + " is approved, repeat findOrCreate() with allowingPreActive(handle) for it",
              null,
              "findOrCreate",
              key.id(),
              null,
              null)
          .observed(KeyState.PRE_ACTIVE);
    if (a.state() == KeyState.PRE_ACTIVE)
      try {
        key.activate();
        activated.activated = true;
      } catch (KmsException e) {
        // Any refusal (or an unknown outcome) is checked against the key's state: another caller
        // may have activated it meanwhile, which KMIP 1.x servers refuse with Permission Denied.
        // Still Pre-Active is a real refusal; another state means look again. This call did not
        // create the key, so a failure here is not a partial completion.
        // Not when the server refused this client's credentials.
        if (Failures.credentialsRefused(e)) throw e;
        KeyState now;
        try {
          now = key.attributes().state();
        } catch (NotFoundException gone) {
          return null;
        } catch (KmsException | IllegalStateException unreadable) {
          e.addSuppressed(unreadable);
          throw e;
        }
        if (now == KeyState.ACTIVE) {
          // After a lost reply, this call's Activate or another caller's took effect: which one
          // cannot be told, so the result says RECOVERED, not FOUND.
          if (e instanceof OutcomeUnknownException unknown) activated.lost(unknown);
          return key;
        }
        if (now == KeyState.PRE_ACTIVE) throw e;
        return null;
      }
    else if (a.state() != KeyState.ACTIVE) return null;
    return key;
  }
}
