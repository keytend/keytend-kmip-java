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
 * Registers a key, certificate or secret made outside the KMS, in the style of {@link
 * KeyCreation}: {@code kms.keys().register(secretKey).named("byok").usages(KeyUsage.ENCRYPT,
 * KeyUsage.DECRYPT).register()}. Usages are required for keys and optional for Secret Data. A
 * certificate registered without them takes them from its X.509 Key Usage extension ({@link
 * KmsKeys#register(java.security.cert.X509Certificate)}). {@link #register()} returns an Active
 * object, and {@link #registerPreActive()} leaves it Pre-Active. The key or secret must stay usable
 * until the terminal method returns. The caller may destroy it afterwards.
 *
 * <p>A builder is not thread-safe and registers one object. Once a terminal method has registered
 * it, both throw {@link IllegalStateException}, because the builder's copy of a secret is wiped
 * then. After a failure that registered nothing they may be called again, and send the secret
 * again.
 *
 * <p><b>When the outcome is unknown.</b> Registration is not repeated automatically. An {@link
 * OutcomeUnknownException} means the reply was lost. The object may exist, Pre-Active, because the
 * Activate was never sent. {@link KmsKeys#findByName(String)} finds Active objects only, so it does
 * not see it, and registering again makes a duplicate. So stop, and leave the decision to someone
 * who can reconcile:
 *
 * <pre>{@code
 * try {
 *   secret = kms.keys().registerSecret(SecretData.Type.PASSWORD, bytes).named("db-password").register();
 * } catch (OutcomeUnknownException e) {
 *   throw new IllegalStateException("db-password may be registered, Pre-Active: reconcile", e);
 * }
 * }</pre>
 *
 * <p>The catch block sends no request, because the server whose reply was lost may still be
 * unreachable. To reconcile once it answers, list the Pre-Active candidates with {@code
 * kms.keys().list(KeyQuery.byName("db-password").state(KeyState.PRE_ACTIVE))}.
 *
 * <p>A name proves nothing about who registered an object. A Pre-Active candidate may be another
 * caller's, registered under the same name at the same moment. Activate a candidate ({@link
 * KeyHandle#activate()}) only when independent evidence shows this registration made it, such as
 * the server's audit record of your identity's Register. Destroy one only when that evidence also
 * shows nothing uses it. Otherwise leave it in place. The <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#advanced-keys-left-by-findorcreate-races">Key
 * lifecycle</a> guide applies the same rule to keys left by {@code findOrCreate}.
 *
 * <p><b>Replacing an object.</b> {@link #replace(KeyHandle)} registers the object as the
 * replacement of one that has the builder's name, such as a new password for a secret, and moves
 * the name to it.
 *
 * @since 0.10.0
 */
public final class KeyRegistration {
  private final KmsKeys keys;
  private final KmsKeys.Registrable object;
  private final ObjectOptions options = new ObjectOptions();
  private Algorithm ecAlgorithm;
  private boolean consumed, refusingExistingName;

  /** Whether {@link #requireUsages()} added the certificate's own usages, which a later {@link #usages} replaces. */
  private boolean defaulted;

  KeyRegistration(KmsKeys keys, KmsKeys.Registrable object) {
    this.keys = keys;
    this.object = object;
  }

  /**
   * Adds a name (objects may have several).
   *
   * @param name the name
   * @return this builder
   */
  public KeyRegistration named(String name) {
    options.name(name);
    return this;
  }

  /** Usages are required except for Secret Data; a certificate without them takes its own. */
  private void requireUsages() {
    if (options.usages.isEmpty() && !object.defaultUsages().isEmpty()) {
      options.usages.addAll(object.defaultUsages());
      defaulted = true;
    }
    if (object.kind() != ObjectKind.SECRET_DATA) options.requireUsages();
  }

  /**
   * The usages the object permits.
   *
   * @param values the usages, added to those already given
   * @return this builder
   */
  public KeyRegistration usages(KeyUsage... values) {
    if (defaulted) options.usages.clear(); // a failed attempt's defaults give way to the caller's
    defaulted = false;
    options.usages(values);
    return this;
  }

  /**
   * Adds the object to a group (not available with the 3.0 draft, which has no Object Group: where 3.0 may be negotiated, use a custom attribute, which every version supports).
   *
   * @param group the group's name
   * @return this builder
   */
  public KeyRegistration group(String group) {
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
  public KeyRegistration custom(CustomAttribute name, Object value) {
    options.custom(name, value);
    return this;
  }

  /**
   * Sets the object's KMIP Extractable attribute (KMIP 1.4 §3.50, 2.1 §4.23), as {@link
   * KeyCreation#extractable(boolean)} does for a created key. With {@code false}, the server
   * refuses to return the object's value with Get while Extractable remains false. The caller keeps
   * whatever copy it registered from.
   *
   * <p>Below KMIP 1.4 the builder is refused ({@link UnsupportedException}) before anything is
   * sent. The registered object is read back, as {@link #registerPreActive()} says. If it does not
   * state the value asked, or states another, it is not activated: {@link
   * PartialCompletionException}, with a {@link KeyMismatchException} as the cause.
   *
   * @param extractable the Extractable attribute to set
   * @return this builder
   * @since 0.10.0
   */
  public KeyRegistration extractable(boolean extractable) {
    options.extractable = extractable;
    return this;
  }

  /**
   * Sets the object's KMIP Sensitive attribute (KMIP 1.4 §3.48, 2.1 §4.55): {@code true}, the
   * server returns its value only wrapped by another key; see {@link KeyCreation#sensitive(boolean)}
   * and, for the checks, {@link #extractable(boolean)}.
   *
   * @param sensitive the Sensitive attribute to set
   * @return this builder
   * @since 0.10.0
   */
  public KeyRegistration sensitive(boolean sensitive) {
    options.sensitive = sensitive;
    return this;
  }

  /**
   * The algorithm recorded for an EC key or certificate: EC (the default from KMIP 1.2), or
   * ECDSA, ECDH or ECMQV to state its purpose.
   *
   * @param algorithm EC, ECDSA, ECDH or ECMQV
   * @return this builder
   * @throws IllegalArgumentException for a non-EC algorithm or object
   */
  public KeyRegistration ecAlgorithm(Algorithm algorithm) {
    if (!Objects.requireNonNull(algorithm, "algorithm").ellipticCurve())
      throw new IllegalArgumentException(algorithm + " is not an elliptic-curve algorithm");
    if (!object.ellipticCurve())
      throw new IllegalArgumentException("Not an elliptic-curve key or certificate");
    ecAlgorithm = algorithm;
    return this;
  }

  /**
   * Makes {@link #register()} and {@link #registerPreActive()} refuse a name that an object not
   * destroyed has already, instead of registering a second object with it: as {@link
   * KeyCreation#refusingExistingName()}. A second password under a name is the usual mistake it
   * prevents, since readers that look the name up keep getting the first. To give a name a new
   * value, use {@link #replace(KeyHandle)}, which this does not go with.
   *
   * @return this builder
   * @since 0.10.0
   */
  public KeyRegistration refusingExistingName() {
    refusingExistingName = true;
    return this;
  }

  /**
   * Registers the object and activates it.
   *
   * @return the object, Active
   * @throws PartialCompletionException when the object was registered but not activated. Do not
   *     repeat this call. Do as the message says: after a failed activation it says to activate
   *     {@link PartialCompletionException#created()}. When the server did not keep the requested
   *     Extractable or Sensitive, it says not to, and when reading the object back failed, it says
   *     what to check first
   * @throws AlreadyExistsException with {@link #refusingExistingName()}, when an object that is not
   *     destroyed has a name of this builder; nothing was registered
   * @throws IllegalStateException when this builder already registered its object
   */
  public KeyHandle register() {
    return keys.kms()
        .call(
            "register",
            () -> {
              KeyHandle handle = registerPreActive();
              keys.activateCreated("register", List.of(handle));
              return handle;
            });
  }

  /**
   * Registers the object, Pre-Active: it cannot be used until {@link KeyHandle#activate()}. KMIP
   * Register replies carry only an identifier, so the object it names is read (one Get Attributes)
   * and must be of the kind registered.
   *
   * @return the object, Pre-Active
   * @throws OutcomeUnknownException when the reply names an object of another kind, or none
   * @throws PartialCompletionException when the object was registered but could not be read back,
   *     or the server did not keep the requested Extractable or Sensitive; it stays Pre-Active, and
   *     the message says what to do
   * @throws AlreadyExistsException as {@link #register()}
   * @throws IllegalStateException when this builder already registered its object
   */
  public KeyHandle registerPreActive() {
    if (consumed)
      throw new IllegalStateException("This builder already registered its object; use a new one");
    requireUsages();
    return keys.kms()
        .call(
            "registerPreActive",
            () -> {
              if (refusingExistingName) keys.refuseExistingNames("register", options.names);
              KeyHandle handle = keys.registerObject(object, options, ecAlgorithm);
              consumed = true;
              List<KeyAttributes> read =
                  keys.checkCreated("register", List.of(handle), null, options.protection());
              keys.checkProtection("register", handle, read.get(0), options.protection());
              return handle;
            });
  }

  /**
   * Registers the object as the replacement of {@code old}, moves {@code old}'s name to it, and
   * returns it Active. Use it for a new password or token, for example {@code
   * kms.keys().registerSecret(newPassword).named("db-password").replace(old)}.
   *
   * <p>Exactly one name is required. {@code old} must be a handle of this builder's {@link Kms}, of
   * the same kind, and have that name. Usages, groups and custom attributes are this builder's, not
   * copied from {@code old}.
   *
   * <p>The new object is registered under a temporary name and activated. Then the name moves from
   * {@code old} to it. What happens to {@code old} depends on its state, as read at the start of the
   * call; this call changes nothing else about it:
   *
   * <ul>
   *   <li><b>Active:</b> it is deactivated as superseded (a Revoke up to KMIP 2.1, Deactivate on the
   *       3.0 draft).
   *   <li><b>Pre-Active</b> (never used, such as a registration whose reply was lost): it stays
   *       Pre-Active, since KMIP has no transition from Pre-Active to Deactivated. Destroy it if it
   *       is not to be kept. One with an Activation Date becomes Active by itself at that date: it
   *       is read again once the name has moved, and deactivated as superseded if it is Active by
   *       then. A later date leaves an unnamed object that activates at it, unless destroyed.
   *   <li><b>Deactivated</b> (a secret past its Deactivation Date, say) or <b>Compromised:</b> it
   *       stays in that state, still readable by identifier for what it protected.
   *   <li><b>Destroyed</b> or <b>Destroyed Compromised:</b> refused, nothing registered. It has no
   *       value to supersede, and servers that keep a destroyed object's name refuse to change it.
   *       Register the new object under the name ({@link #register()}) instead.
   * </ul>
   *
   * <p>A step whose outcome is unknown is checked by reading the object, and a failure after the
   * registration says how to finish. It sends eight requests, the last the Revoke (Deactivate on
   * the 3.0 draft) of an Active {@code old}, which an {@code old} in another state does not get;
   * two more on KMIP 1.x, and one more where the server enforces unique names (two on 1.x). A
   * Pre-Active {@code old} with an Activation Date is read once more. {@code
   * old} can still be read by identifier, but {@link KmsKeys#findByName(String)} no longer finds it.
   * Instances holding {@code old} should look the name up again.
   *
   * <p>KMIP cannot move a name atomically. On a server that enforces unique names, a lookup during
   * the move finds nothing, so retry it. Elsewhere it finds the old or the new object. Run one
   * replacement of a name at a time. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#replacing-a-secret">Replacing
   * a secret</a>. To act only on the plan a confirmation showed, use {@link #replace(KeyHandle,
   * KeyAttributes)}.
   *
   * @param old the object that has this builder's name now, a handle from the same {@code Kms}
   * @return the new object, Active
   * @throws IllegalArgumentException when the builder does not have exactly one name, lacks the
   *     usages a key or certificate needs, has {@link #refusingExistingName()}, or {@code old} comes
   *     from another {@link Kms}; nothing was sent
   * @throws UnsupportedException below KMIP 1.4 when Extractable or Sensitive is set; nothing was sent
   * @throws KeyMismatchException when {@code old} is of another kind; nothing was registered
   * @throws StateConflictException when {@code old} is Destroyed, Destroyed Compromised or in a
   *     state the server does not report, or does not have the name, for example because it was
   *     replaced already; nothing was registered. {@link StateConflictException#observedState()} is
   *     the state read
   * @throws OutcomeUnknownException when the registration's outcome is unknown and the object it
   *     made cannot be confirmed by its temporary name (<a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/kms-design.md#a-lost-create-or-register-reply">A
   *     lost Create or Register reply</a>); nothing else changed, and {@code old} keeps the name.
   *     The message names the temporary name and any object found; {@link KmsException#objectId()}
   *     is that object when it is the only one found or located
   * @throws PartialCompletionException when the new object was registered but a later step failed;
   *     {@link PartialCompletionException#created()} is the new object, and the message says which
   *     object has the name now and how to finish or undo
   * @throws IllegalStateException when this builder already registered its object
   */
  public KeyHandle replace(KeyHandle old) {
    return replacing(old, null).replacement();
  }

  /**
   * {@link #replace(KeyHandle)}, saying what it did with {@code old}: whether it deactivated it.
   * Same requests, refusals and failures.
   *
   * @param old the object that has this builder's name now, a handle from the same {@code Kms}
   * @return the new object and what became of {@code old}
   * @throws KmsException as {@link #replace(KeyHandle)}
   * @throws IllegalArgumentException as {@link #replace(KeyHandle)}
   * @throws IllegalStateException when this builder already registered its object
   * @since 0.10.0
   */
  public ReplacementResult replaceResult(KeyHandle old) {
    return replacing(old, null);
  }

  /**
   * {@link #replace(KeyHandle)}, bound to the plan made from {@code planned}: the attributes of
   * {@code old} read to show a plan, such as the one an operator confirmed. The steps taken for
   * {@code old} follow from two of them, its state and its Activation Date (a Pre-Active object
   * with one is deactivated if that date makes it Active during the call). When the call reads
   * {@code old} in another state, or with another Activation Date (one added, moved or removed), it
   * is refused before anything is registered. So a change by another caller while the plan waited
   * (a Pre-Active {@code old} activated, or given an Activation Date, say) cannot make this call
   * deactivate an object the plan said it would leave alone. KMIP cannot make the read and the steps
   * atomic: a change after the read is another caller's.
   *
   * @param old the object that has this builder's name now, a handle from the same {@code Kms}
   * @param planned the attributes of {@code old} the plan was made from ({@link
   *     KeyHandle#attributes()}): Active, Pre-Active, Deactivated or Compromised
   * @return the new object, Active
   * @throws IllegalArgumentException as {@link #replace(KeyHandle)} does, when {@code planned} are
   *     another object's attributes, and when they are of a state {@code replace} refuses; nothing
   *     was sent
   * @throws UnsupportedException below KMIP 1.4 when Extractable or Sensitive is set; nothing was sent
   * @throws KeyMismatchException when {@code old} is of another kind; nothing was registered
   * @throws StateConflictException ({@link StateConflictException.Conflict#NOT_AS_PLANNED}) when
   *     {@code old} is not in {@code planned}'s state or has
   *     another Activation Date, or as {@link #replace(KeyHandle)} says; nothing was registered.
   *     {@link StateConflictException#observedState()} is the state read
   * @throws OutcomeUnknownException as {@link #replace(KeyHandle)} says
   * @throws PartialCompletionException as {@link #replace(KeyHandle)} says
   * @throws IllegalStateException when this builder already registered its object
   * @since 0.10.0
   */
  public KeyHandle replace(KeyHandle old, KeyAttributes planned) {
    return replaceResult(old, planned).replacement();
  }

  /**
   * {@link #replace(KeyHandle, KeyAttributes)}, saying what it did with {@code old}: whether it
   * deactivated it, also when a Pre-Active {@code old} became Active at its Activation Date during
   * the call. Same requests, refusals and failures. Report the result from it, without reading
   * {@code old} again.
   *
   * @param old the object that has this builder's name now, a handle from the same {@code Kms}
   * @param planned the attributes of {@code old} the plan was made from
   * @return the new object and what became of {@code old}
   * @throws KmsException as {@link #replace(KeyHandle, KeyAttributes)}
   * @throws IllegalArgumentException as {@link #replace(KeyHandle, KeyAttributes)}
   * @throws IllegalStateException when this builder already registered its object
   * @since 0.10.0
   */
  public ReplacementResult replaceResult(KeyHandle old, KeyAttributes planned) {
    Objects.requireNonNull(old, "old");
    Objects.requireNonNull(planned, "planned");
    if (!planned.id().equals(old.id()))
      throw new IllegalArgumentException(
          "replace: the plan was made from the attributes of "
              + planned.id()
              + ", not of "
              + old.id()
              + "; nothing was sent");
    if (!replaceable(planned.state()))
      throw new IllegalArgumentException(
          "replace: an object in state "
              + planned.state()
              + " is never replaced; nothing was sent");
    return replacing(old, planned);
  }

  /** {@link #replace(KeyHandle, KeyAttributes)}, or {@link #replace(KeyHandle)} for no plan. */
  private ReplacementResult replacing(KeyHandle old, KeyAttributes planned) {
    Objects.requireNonNull(old, "old");
    if (consumed)
      throw new IllegalStateException("This builder already registered its object; use a new one");
    if (options.names.size() != 1)
      throw new IllegalArgumentException(
          "replace needs exactly one name: the one that moves from the old object");
    if (refusingExistingName)
      throw new IllegalArgumentException(
          "replace moves the name from the old object, which has it, so refusingExistingName() does"
              + " not go with it");
    requireUsages();
    String name = options.names.get(0);
    if (!old.sameKms(keys.kms()))
      throw new IllegalArgumentException(
          "replace: "
              + old
              + " comes from another Kms, and an identifier names an object only on its own"
              + " server, so this would replace whatever this server holds as "
              + old.id()
              + "; pass a handle"
              + " from this Kms: kms.keys().findByName(\""
              + name
              + "\"), or kms.keys().handle(\""
              + old.id()
              + "\") if both reach the same server; nothing was registered");
    return keys.kms()
        .call(
            "replace",
            () -> {
              options.protection().require(keys.kms().protocolVersion(), "replace");
              KeyHandle previous = new KeyHandle(keys, old.id(), object.kind());
              KeyAttributes before = previous.attributes();
              if (before.kind() != object.kind())
                throw new KeyMismatchException(
                    "replace: "
                        + old.id()
                        + " is a "
                        + before.kind()
                        + ", not a "
                        + object.kind()
                        + "; nothing was registered",
                    null,
                    "replace",
                    old.id(),
                    null,
                    null);
              KeyState state = before.state();
              if (!replaceable(state))
                throw new StateConflictException(
                        "replace: "
                            + old.id()
                            + " is "
                            + state
                            + (state == KeyState.UNKNOWN
                                ? " (the server reports no State this client knows)"
                                : ": it has no value to supersede, and servers that keep a"
                                    + " destroyed object's name refuse to change it; register the"
                                    + " new object under the name instead (register())")
                            + "; nothing was registered",
                        null,
                        "replace",
                        old.id(),
                        null,
                        null)
                    .observed(state);
              if (!before.names().contains(name))
                throw new StateConflictException(
                        "replace: "
                            + old.id()
                            + " is not named "
                            + name
                            + ", so it is not the object to replace (was it replaced already? kms.keys().findByName(\""
                            + name
                            + "\") finds the current one); nothing was registered",
                        null,
                        "replace",
                        old.id(),
                        null,
                        null)
                    .because(StateConflictException.Conflict.NAME)
                    .observed(state);
              if (planned != null) {
                String changed =
                    state != planned.state()
                        ? " is " + state + ", not " + planned.state()
                        : !before.activationDate().equals(planned.activationDate())
                            ? " has " + activationDate(before) + ", not " + activationDate(planned)
                            : null;
                if (changed != null)
                  throw new StateConflictException(
                          "replace: "
                              + old.id()
                              + changed
                              + " as the plan it was to follow showed: another caller changed it;"
                              + " nothing was registered",
                          null,
                          "replace",
                          old.id(),
                          null,
                          null)
                      .because(StateConflictException.Conflict.NOT_AS_PLANNED)
                      .observed(state);
              }
              return new Replacement(
                      previous,
                      name,
                      state,
                      state == KeyState.PRE_ACTIVE && before.activationDate().isPresent(),
                      options.protection().keeping(before))
                  .run();
            });
  }

  /** The steps of {@link #replace}, and what a failure at each one leaves. */
  private final class Replacement {
    private final KeyHandle old;
    private final String name, temporary;

    /** {@code old}'s state when the call read it: only an Active one is deactivated. */
    private final KeyState oldState;

    /** Whether {@code old} was Pre-Active with an Activation Date, so may activate meanwhile. */
    private final boolean activates;

    /** The builder's protection, and the old object's where the builder sets none. */
    private final Protection protection;

    private KeyHandle created;
    private boolean active;

    /** The first step whose reply was lost and whose effect reading back confirmed; or null. */
    private OutcomeUnknownException lost;

    /** The last step whose reply was lost and that reading back went past; or null. */
    private OutcomeUnknownException lostStep;

    Replacement(
        KeyHandle old, String name, KeyState oldState, boolean activates, Protection protection) {
      this.old = old;
      this.name = name;
      this.oldState = oldState;
      this.activates = activates;
      this.protection = protection;
      this.temporary = name + ".replacing-" + UUID.randomUUID();
    }

    ReplacementResult run() {
      created = registerTemporary();
      try {
        List<KeyAttributes> read = keys.checkCreated("replace", List.of(created), null, protection);
        keys.checkProtection("replace", created, read.get(0), protection);
      } catch (PartialCompletionException e) {
        throw partial(
            e.getCause() instanceof KeyMismatchException
                ? "the server did not keep the protection asked"
                : "reading it failed",
            untouched(),
            (RuntimeException) e.getCause());
      }
      step(
          () -> created.removeName(temporary),
          () -> !named(created, temporary, true),
          "removing the temporary name " + temporary,
          untouched());
      step(
          created::activate,
          () -> created.attributes().state() == KeyState.ACTIVE,
          "activating it",
          untouched());
      active = true;
      moveName();
      // An object that was not Active keeps its state: Pre-Active has no transition to Deactivated,
      // and a Deactivated or Compromised one is out of use already. A Pre-Active one with an
      // Activation Date becomes Active by itself, and is then superseded as an Active one is.
      if (oldState != KeyState.ACTIVE && !(activates && activatedMeanwhile()))
        return new ReplacementResult(created, old, oldState, false, lost, null);
      // Done once the old object is out of use: Deactivated by this step, or Compromised or
      // destroyed by another caller meanwhile, which this step cannot undo and need not.
      KeyState[] after = {KeyState.DEACTIVATED};
      // Attributed to this call only when its own request's reply confirmed it: a state read back
      // after a refusal (another caller retired it) or a lost reply proves nothing about who did
      // it.
      lostStep = null;
      boolean confirmed =
          step(
              () -> old.deactivate(RevocationReason.superseded("replaced by " + created.id())),
              () -> retired(after[0] = old.attributes().state()),
              "deactivating the old object " + old.id(),
              "the name moved to "
                  + created.id()
                  + ", which is Active and is the secret now; finish with"
                  + " kms.keys().handle(\""
                  + old.id()
                  + "\").deactivate()");
      // Its own lost reply, even after an earlier one: which caller deactivated it is open.
      return new ReplacementResult(created, old, after[0], confirmed, lost, lostStep);
    }

    /**
     * Whether the Pre-Active {@code old} is Active now, its Activation Date passed. A failed read
     * is a partial completion: the name moved, and {@code old} may be Active.
     */
    private boolean activatedMeanwhile() {
      try {
        return old.attributes().state() == KeyState.ACTIVE;
      } catch (KmsException | IllegalStateException e) {
        throw partial(
            "reading the old object " + old.id() + " (it activates at its Activation Date) failed",
            "the name moved to "
                + created.id()
                + ", which is Active and is the secret now; if "
                + old.id()
                + " is Active, finish with kms.keys().handle(\""
                + old.id()
                + "\").deactivate()",
            e);
      }
    }

    /** Registers under the temporary name; an unknown outcome is reconciled by looking that name up. */
    private KeyHandle registerTemporary() {
      ObjectOptions registering = new ObjectOptions();
      registering.usages.addAll(options.usages);
      registering.groups.addAll(options.groups);
      registering.custom.putAll(options.custom);
      registering.protection(protection);
      registering.names.add(temporary);
      try {
        KeyHandle handle = keys.registerObject(object, registering, ecAlgorithm);
        consumed = true;
        return handle;
      } catch (OutcomeUnknownException e) {
        // Taken as this call's only when the search can tell it is the only object with the name
        // and it is as the Register left it: the rule the compromise procedure's lost
        // Create keeps, in the same helper.
        KmsKeys.Made found = keys.madeUnder(temporary, object.kind(), a -> true, e);
        if (found.made().isEmpty()) {
          List<String> ids = found.holders();
          String unchanged =
              "nothing else changed, and " + old.id() + " keeps the name " + name + ". ";
          throw new OutcomeUnknownException(
              "replace: registering the new object under the temporary name "
                  + temporary
                  + " had an unknown outcome, and "
                  + found.described(temporary, "the Register left its object", "")
                  + ": "
                  + unchanged
                  + (found.none()
                      ? "Repeat with a new builder; if an object named "
                          + temporary
                          + " appears later, destroy it"
                      : !ids.isEmpty()
                          ? "This call changed none of them: check "
                              + String.join(", ", ids)
                              + " (attributes()) before you repeat with a new builder"
                          : "The Register may have made an object with that name. Look for it"
                              + " (kms.keys().list(KeyQuery.byName(\""
                              + temporary
                              + "\"))) before you repeat with a new builder"),
              e,
              "replace",
              // The one object found (or located and unreadable), so that a caller can look at it
              // without reading the message.
              found.concerned().orElse(null),
              null,
              null);
        }
        object.registered();
        consumed = true;
        // The only object with the name only this call uses, as the Register left it: its own.
        lost = e;
        return new KeyHandle(keys, found.made().get().id(), object.kind());
      }
    }

    /** Adds the name to the new object, removing it from the old one first where names are unique. */
    private void moveName() {
      boolean unique = false;
      try {
        created.addName(name);
      } catch (AlreadyExistsException e) {
        unique = true;
      } catch (KmsException | IllegalStateException e) {
        if (!named(created, name, false))
          throw partial("adding the name " + name + " to it failed", untouched(), e);
      }
      if (!unique) {
        // Both have the name; lookups find one of them until it is removed from the old one.
        step(
            () -> old.removeName(name),
            () -> !named(old, name, true),
            "removing the name " + name + " from the old object " + old.id(),
            (oldState == KeyState.ACTIVE
                    ? "both objects are Active and have the name, and lookups find either"
                    : "both objects have the name, and lookups of Active objects find "
                        + created.id()
                        + " ("
                        + old.id()
                        + " is "
                        + oldState
                        + ")")
                + "; finish with"
                + " kms.keys().handle(\""
                + old.id()
                + "\").removeName(\""
                + name
                + "\")"
                + (oldState == KeyState.ACTIVE ? " and deactivate()" : "")
                + ", or undo by"
                + " removing the name from "
                + created.id()
                + " and deactivating it (another instance may have found it by the name meanwhile: it still decrypts)");
        return;
      }
      // A server with unique names: the name is on neither object between these two requests.
      step(
          () -> old.removeName(name),
          () -> !named(old, name, true),
          "removing the name "
              + name
              + " from the old object "
              + old.id()
              + " (the server refuses a name in use)",
          "it is not known whether "
              + old.id()
              + " still has the name "
              + name
              + ": check with"
              + " kms.keys().list(KeyQuery.byName(\""
              + name
              + "\")); if no object has it, add it to "
              + created.id()
              + " (KeyHandle.addName) to finish, or back to "
              + old.id()
              + " to undo; then"
              + (oldState == KeyState.ACTIVE
                  ? " deactivate the one without it"
                  : " deactivate " + created.id() + " if it is the one without it"));
      try {
        created.addName(name);
      } catch (KmsException | IllegalStateException e) {
        if (named(created, name, false)) return;
        try {
          old.addName(name);
        } catch (KmsException | IllegalStateException again) {
          if (!named(old, name, false)) {
            e.addSuppressed(again);
            throw partial(
                "adding the name "
                    + name
                    + " to it failed, and so did putting the name back on "
                    + old.id(),
                "the name may be on neither object (another replacement may have taken it): check with"
                    + " kms.keys().list(KeyQuery.byName(\""
                    + name
                    + "\")) and add it to "
                    + created.id()
                    + " (KeyHandle.addName) to finish, or to "
                    + old.id()
                    + " to undo",
                e);
          }
        }
        throw partial(
            "adding the name " + name + " to it failed (the name was put back on " + old.id() + ")",
            untouched(),
            e);
      }
    }

    /**
     * The advice while {@code old} still has the name and nothing else changed: {@code created}
     * never had the name, so no name lookup found it; no advice destroys an object.
     */
    private String untouched() {
      return old.id()
          + " keeps the name "
          + name
          + " and nothing else changed: "
          + created.id()
          + " never had the name"
          + (active ? "; deactivate it if it is not to be kept" : "")
          + ", then repeat with a new builder";
    }

    /**
     * Runs {@code action}; a failure stands unless {@code done} (read afterwards) shows that the
     * action took effect anyway, and becomes a partial completion with {@code advice}. Whether the
     * action's own reply confirmed it: false when reading back went past its failure (a lost reply,
     * recorded in {@link #lost}, or a refusal after another caller made the change).
     */
    private boolean step(
        Runnable action, java.util.function.BooleanSupplier done, String what, String advice) {
      try {
        action.run();
        return true;
      } catch (KmsException | IllegalStateException e) {
        boolean tookEffect;
        try {
          tookEffect = done.getAsBoolean();
        } catch (KmsException | IllegalStateException unknown) {
          tookEffect = false;
        }
        if (!tookEffect) throw partial(what + " failed", advice, e);
        if (e instanceof OutcomeUnknownException unknown) {
          lostStep = unknown;
          if (lost == null) lost = unknown;
        }
        return false;
      }
    }

    /**
     * A failure after {@code created} was registered; an earlier step whose reply was lost ({@link
     * #lost}) is kept on it.
     */
    private PartialCompletionException partial(String step, String advice, RuntimeException cause) {
      return PartialCompletionException.of(
          "replace", List.of(created), null, step, advice, lost, cause);
    }
  }

  /** {@code attributes}' Activation Date, for a message. */
  private static String activationDate(KeyAttributes attributes) {
    return attributes
        .activationDate()
        .map(d -> "the Activation Date " + d)
        .orElse("no Activation Date");
  }

  /**
   * Whether {@link #replace} takes the name from an object in {@code state}: one that exists and is
   * not destroyed (Pre-Active, Active, Deactivated, Compromised).
   */
  private static boolean replaceable(KeyState state) {
    return state == KeyState.PRE_ACTIVE
        || state == KeyState.ACTIVE
        || state == KeyState.DEACTIVATED
        || state == KeyState.COMPROMISED;
  }

  /** Whether an object in {@code state} is out of use: neither Active nor Pre-Active (nor unknown). */
  private static boolean retired(KeyState state) {
    return state != KeyState.ACTIVE && state != KeyState.PRE_ACTIVE && state != KeyState.UNKNOWN;
  }

  /**
   * Whether {@code key} has {@code name} now (one Get Attributes); {@code unknown} when it cannot be
   * read, so a check never concludes that a step took effect without having seen it.
   */
  private static boolean named(KeyHandle key, String name, boolean unknown) {
    try {
      return key.attributes().names().contains(name);
    } catch (KmsException | IllegalStateException e) {
      return unknown;
    }
  }
}
