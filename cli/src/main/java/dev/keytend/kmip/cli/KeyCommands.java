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

package dev.keytend.kmip.cli;

import dev.keytend.kmip.kms.Algorithm;
import dev.keytend.kmip.kms.AlreadyExistsException;
import dev.keytend.kmip.kms.CustomAttribute;
import dev.keytend.kmip.kms.FindOrCreateResult;
import dev.keytend.kmip.kms.KeyAttributes;
import dev.keytend.kmip.kms.KeyCreation;
import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyMismatchException;
import dev.keytend.kmip.kms.KeyQuery;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmsException;
import dev.keytend.kmip.kms.KmsKeys;
import dev.keytend.kmip.kms.LineageKey;
import dev.keytend.kmip.kms.ObjectKind;
import dev.keytend.kmip.kms.OutcomeUnknownException;
import dev.keytend.kmip.kms.PartialCompletionException;
import dev.keytend.kmip.kms.Rotation;
import dev.keytend.kmip.kms.RotationDates;
import dev.keytend.kmip.kms.RotationResult;
import dev.keytend.kmip.kms.StateConflictException;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

/** The commands that read keys, create them and rotate them: list, show, lineage, create, rotate. */
final class KeyCommands {
  private KeyCommands() {}

  static void list(Context c) {
    c.args.none();
    KeyQuery query = c.args.value("--name").map(KeyQuery::byName).orElse(KeyQuery.all());
    Optional<KeyState> state = c.args.get("--state", KeyState.class);
    if (state.isPresent()) query = query.state(state.get());
    Optional<ObjectKind> kind = c.args.get("--kind", ObjectKind.class);
    if (kind.isPresent()) query = query.kind(kind.get());
    Optional<Algorithm> algorithm = c.args.get("--algorithm", Algorithm.class);
    if (algorithm.isPresent()) query = query.algorithm(algorithm.get());
    Optional<String> group = c.args.value("--object-group");
    if (group.isPresent()) query = query.group(group.get());
    for (String custom : c.args.values("--custom")) {
      Map.Entry<CustomAttribute, String> e = Render.customOption(custom);
      query = query.custom(e.getKey(), e.getValue());
    }
    List<KeyAttributes> found;
    try (Stream<KeyAttributes> located = c.kms().keys().locateWithAttributes(query)) {
      found = located.toList();
    }
    List<Map<String, Object>> objects = new ArrayList<>();
    for (KeyAttributes a : found) objects.add(Render.json(a));
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("group", c.group().name());
    result.put("count", found.size());
    result.put("objects", objects);
    c.emit(
        result,
        () -> {
          Table t =
              new Table(
                  "ID",
                  "NAME",
                  "KIND",
                  "CIPHER",
                  "STATE",
                  "ACTIVATION DATE",
                  "CREATION DATE",
                  "PROTECT STOP DATE",
                  "DEACTIVATION DATE",
                  "OBJECT GROUP");
          for (KeyAttributes a : found)
            t.row(
                a.id(),
                Render.names(a),
                Render.kind(a),
                Render.cipher(a),
                Render.state(a),
                Render.date(a.activationDate()),
                Render.date(a.creationDate()),
                Render.date(a.protectStopDate()),
                Render.date(a.deactivationDate()),
                String.join(", ", a.groups()));
          if (t.isEmpty()) c.out.println("No objects match.");
          else t.print(c.out);
        });
  }

  static void show(Context c) {
    String id = c.args.single("an object identifier");
    c.targetId = id;
    KeyHandle handle = c.kms().keys().handle(id).allowingCompromised();
    KeyAttributes a = handle.attributes();
    List<LineageKey> lineage = null;
    String lineageError = null;
    boolean key =
        a.kind() == ObjectKind.SYMMETRIC_KEY
            || a.kind() == ObjectKind.PRIVATE_KEY
            || a.kind() == ObjectKind.PUBLIC_KEY;
    if (key && !c.args.flag("--no-lineage")) {
      try {
        lineage = handle.lineage();
      } catch (KmsException e) {
        lineageError = e.getMessage();
      }
    }
    Map<String, Object> result = Render.json(a);
    result.put("lineage", lineage == null ? null : Render.lineageJson(lineage));
    result.put("lineageError", lineageError);
    List<LineageKey> shown = lineage;
    String error = lineageError;
    c.emit(
        result,
        () -> {
          Map<String, String> more = new LinkedHashMap<>();
          if (shown != null && shown.size() == 1) more.put("Lineage", "not rotated");
          if (error != null) more.put("Lineage", "not read: " + error);
          Render.text(a, more, c.out);
          if (shown != null && shown.size() > 1) {
            c.out.println();
            c.out.println("Lineage, newest first:");
            Render.lineageTable(shown).print(c.out);
          }
        });
  }

  static void lineage(Context c) {
    KmsKeys keys = c.kms().keys();
    KeyHandle start;
    Optional<String> id = c.args.value("--id");
    if (id.isPresent()) {
      c.args.none();
      c.targetId = id.get();
      start = keys.handle(id.get()).allowingCompromised();
    } else {
      String name = c.args.single("a key name, or --id ID");
      start =
          keys.findByName(
                  name,
                  KeyState.ACTIVE,
                  KeyState.DEACTIVATED,
                  KeyState.COMPROMISED,
                  KeyState.PRE_ACTIVE)
              .orElseThrow(
                  () ->
                      new CliException(
                          ExitCode.NOT_FOUND,
                          "no object named " + name + " that is not destroyed"));
    }
    List<LineageKey> lineage = start.lineage();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("keys", Render.lineageJson(lineage));
    c.emit(result, () -> Render.lineageTable(lineage).print(c.out));
  }

  static void create(Context c) {
    c.args.none();
    Optional<String> name = c.args.value("--name");
    boolean ifAbsent = c.args.flag("--if-absent");
    boolean preActive = c.args.flag("--pre-active");
    if (ifAbsent && preActive)
      throw CliException.usage("--if-absent and --pre-active do not go together");
    if (ifAbsent && name.isEmpty()) throw CliException.usage("--if-absent needs --name");
    boolean allowDuplicate = c.args.flag("--allow-duplicate-name");
    if (allowDuplicate && (ifAbsent || name.isEmpty()))
      throw CliException.usage("--allow-duplicate-name goes only with --name, without --if-absent");
    Algorithm algorithm = c.args.get("--algorithm", Algorithm.class).orElse(Algorithm.AES);
    int bits = c.args.get("--bits", Integer.class).orElse(256);
    KeyUsage[] usages =
        c.args
            .get("--usage", KeyUsage[].class)
            .orElse(new KeyUsage[] {KeyUsage.ENCRYPT, KeyUsage.DECRYPT});
    List<Map.Entry<CustomAttribute, String>> custom = new ArrayList<>();
    for (String option : c.args.values("--custom")) custom.add(Render.customOption(option));
    List<String> groups = c.args.values("--object-group");

    KmsKeys keys = c.kms().keys();
    KeyCreation creation =
        Context.argument(
            () -> {
              KeyCreation k = keys.createSymmetric(algorithm, bits).usages(usages);
              name.ifPresent(k::named);
              for (String group : groups) k.group(group);
              for (Map.Entry<CustomAttribute, String> e : custom)
                k.custom(e.getKey(), e.getValue());
              return k;
            });
    c.targetName = name.orElse(null);
    if (ifAbsent) {
      createIfAbsent(c, keys, creation, name.get());
      return;
    }
    // A second key with a taken name is a duplicate that name lookups do not choose.
    if (name.isPresent() && !allowDuplicate) creation.refusingExistingName();
    c.hints(
        e -> {
          if (e instanceof AlreadyExistsException)
            return "use --if-absent to get the Active key with the name, rotate "
                + Values.shell(name.orElse("NAME"))
                + " to replace it, or --allow-duplicate-name to make another key with the name";
          if (e instanceof PartialCompletionException p && !p.created().isEmpty())
            return "activate the key with: "
                + c.suggest("activate", p.created().get(0).id())
                + "; do not repeat create, which would make another key";
          return null;
        });
    KeyHandle key = preActive ? creation.createPreActive() : creation.create();
    c.targetId = key.id();
    c.done("created key " + key.id() + (preActive ? ", Pre-Active" : ", Active"));
    created(c, keys, key, FindOrCreateResult.Outcome.CREATED, List.of(key.id()), null, null);
  }

  /**
   * create --if-absent: finds or creates the key. The SDK refuses to activate a Pre-Active key with
   * the name ({@link KeyCreation#refusingPreActive()}): then this shows that key and asks for
   * confirmation, because activation starts its cryptoperiod, and repeats the call allowing exactly
   * that key ({@link KeyCreation#allowingPreActive}), which the SDK activates in the same call.
   * Another Pre-Active key found then is refused again, unconfirmed.
   */
  private static void createIfAbsent(Context c, KmsKeys keys, KeyCreation creation, String name) {
    // The key approved for activation, once there is one: the hint then says what the second call
    // may have done.
    KeyHandle[] approved = new KeyHandle[1];
    c.hints(e -> ifAbsentHint(c, name, approved[0], e));
    creation.refusingPreActive();
    FindOrCreateResult r;
    KeyHandle staged = null;
    try {
      r = creation.findOrCreateResult();
    } catch (StateConflictException e) {
      if (!stagedRefusal(e)) throw e;
      staged = keys.handle(e.objectId().get());
      c.confirm(
          List.of(
              "create --if-absent "
                  + name
                  + ": no Active key has the name, but a Pre-Active one does:",
              "  activates " + Render.summary(staged.attributes()) + " and returns it.",
              "  Activation starts its cryptoperiod: it encrypts from now on. KMIP has no way"
                  + " back to Pre-Active."));
      c.targetId = staged.id();
      approved[0] = staged;
      r = creation.allowingPreActive(staged).findOrCreateResult();
    }
    KeyHandle key = r.key();
    c.targetId = key.id();
    List<String> made = ids(r.created());
    if (r.outcome() != FindOrCreateResult.Outcome.FOUND || !made.isEmpty())
      c.done(Values.token(r.outcome()) + " key " + key.id());
    String moved =
        staged != null && !key.equals(staged)
            ? staged.id()
                + " was confirmed but not activated: the name leads to "
                + key.id()
                + " now (another caller's key ranks first); check both with show"
            : null;
    created(c, keys, key, r.outcome(), made, moved, r.recoveredFrom().orElse(null));
  }

  /** Whether {@code e} is the SDK's refusal to activate a Pre-Active key that has the name. */
  private static boolean stagedRefusal(StateConflictException e) {
    return e.conflict() == StateConflictException.Conflict.STATE
        && e.observedState().orElse(null) == KeyState.PRE_ACTIVE
        && e.objectId().isPresent();
  }

  /**
   * The hint for a failure of create --if-absent; {@code approved}: the Pre-Active key whose
   * activation was confirmed, once there is one.
   */
  private static String ifAbsentHint(Context c, String name, KeyHandle approved, KmsException e) {
    // The SDK's contract: an unknown Activate names its key, an unknown Create names none.
    if (e instanceof OutcomeUnknownException && e.objectId().isPresent())
      return "the reply to the activation of "
          + e.objectId().get()
          + " was lost, and reading it back failed, so it may be Active now (no key was created):"
          + " check it with "
          + c.suggest("show", e.objectId().get())
          + ", then repeat "
          + c.suggest("create", "--name", name, "--if-absent");
    if (e instanceof OutcomeUnknownException)
      return "the Create's reply was lost, so this call may have made a key with the name"
          + (approved == null
              ? ", and nothing was activated"
              : ", and may have activated " + approved.id() + " after it")
          + ": check the keys with "
          + c.suggest("list", "--name", name)
          + "; activate a Pre-Active one only if it is yours ("
          + c.suggest("activate", "ID")
          + "), then repeat "
          + c.suggest("create", "--name", name, "--if-absent");
    if (e instanceof PartialCompletionException p
        && p.getCause() instanceof StateConflictException s
        && stagedRefusal(s)) {
      String theirs = s.objectId().get();
      return "another caller's key with the name, "
          + theirs
          + ", is Pre-Active and ranks first, so it was not activated; "
          + String.join(", ", ids(p.created()))
          + ", which this call created, is left as it is. Check both with: "
          + c.suggest("list", "--name", name)
          + "; if "
          + theirs
          + " is yours, activate it with "
          + c.suggest("activate", theirs)
          + ", then repeat create --if-absent";
    }
    if (e instanceof PartialCompletionException)
      return "repeat "
          + c.suggest("create", "--name", name, "--if-absent")
          + ": it resumes, and activates the key it created";
    if (e instanceof StateConflictException s && stagedRefusal(s))
      return "another Pre-Active key with the name, "
          + s.objectId().get()
          + ", appeared while waiting for the confirmation, and was not activated: repeat "
          + c.suggest("create", "--name", name, "--if-absent")
          + " to see it";
    if (e instanceof StateConflictException s
        && s.conflict() == StateConflictException.Conflict.NAME)
      return "the name is being moved between keys (a replacement or reconcile in progress, or one"
          + " that stopped): repeat in a moment, or see "
          + c.suggest("list", "--name", name);
    if (e instanceof StateConflictException)
      return "see the objects with the name: "
          + c.suggest("list", "--name", name)
          + ". Replace a Compromised key with replace-compromised ID. A name whose keys are"
          + " only Deactivated was retired: create the new key under another name";
    if (e instanceof KeyMismatchException)
      return "a key with the name exists and differs from the options given: see it with "
          + c.suggest("show", e.objectId().orElse("ID"))
          + ", and give matching options or another name";
    return null;
  }

  private static List<String> ids(List<KeyHandle> keys) {
    return keys.stream().map(KeyHandle::id).toList();
  }

  /**
   * Prints the result of create: the identifier on standard output, a summary on standard error.
   * The summary needs one more read; when that read fails, the key still exists, so the result is
   * printed with a warning and the command succeeds.
   */
  private static void created(
      Context c,
      KmsKeys keys,
      KeyHandle key,
      FindOrCreateResult.Outcome outcome,
      List<String> made,
      String moved,
      OutcomeUnknownException lost) {
    KeyAttributes a = null;
    List<String> warnings = new ArrayList<>();
    if (moved != null) warnings.add(moved);
    try {
      a = key.attributes();
    } catch (KmsException e) {
      warnings.add(
          key.id()
              + " is "
              + (outcome == FindOrCreateResult.Outcome.FOUND ? "the existing key" : "made")
              + ", but reading it back to show it failed: "
              + e.getMessage());
    }
    for (String other : made) if (!other.equals(key.id())) warnings.add(lost(c, keys, key, other));
    if (outcome == FindOrCreateResult.Outcome.RECOVERED)
      warnings.add(
          (lost != null && lost.objectId().isPresent()
                  ? "the reply to this call's activation of "
                      + key.id()
                      + " was lost, and it was read back Active: this call or another caller"
                      + " activated it."
                  : "the reply to this call's Create was lost, and "
                      + key.id()
                      + " was found by the name: this call or another caller made it.")
              + " Check the server's audit log if it matters which");
    String warning = warnings.isEmpty() ? null : String.join("; ", warnings);
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("action", Values.token(outcome));
    result.put("id", key.id());
    result.put("created", made);
    result.put("key", a == null ? null : Render.json(a));
    result.put("warning", warning);
    result.put("recoveredFrom", Cli.Failure.step(lost));
    KeyAttributes shown = a;
    c.emit(
        result,
        () -> {
          c.out.println(key.id());
          String verb =
              switch (outcome) {
                case FOUND -> "Found existing ";
                case ACTIVATED -> "Activated existing ";
                case CREATED -> "Created ";
                case REPLACED -> "Replaced the compromised key with ";
                case RECOVERED -> "Found, after a reply was lost, ";
              };
          c.err.println(verb + (shown == null ? key.id() : Render.summary(shown)));
          for (String w : warnings) c.warn(w);
        });
  }

  /**
   * The warning about {@code other}, a key this call created that lost to {@code key}: what to do
   * depends on its state now, since a key that is Active may be in use.
   */
  private static String lost(Context c, KmsKeys keys, KeyHandle key, String other) {
    String state;
    try {
      state = Values.token(keys.handle(other).attributes().state());
    } catch (KmsException e) {
      state = null;
    }
    String start =
        "this call also created "
            + other
            + ", which lost to the key another caller made, "
            + key.id();
    if (state == null)
      return start + "; its state could not be read: check it with " + c.suggest("show", other);
    if (state.equals(Values.token(KeyState.PRE_ACTIVE)))
      return start
          + "; it is left Pre-Active: check it with "
          + c.suggest("show", other)
          + ", and destroy it if it is yours";
    return start
        + "; it is "
        + state
        + ", so something may use it: do not destroy it; move what it protects to "
        + key.id()
        + " first (see "
        + c.suggest("show", other)
        + ")";
  }

  static void rotate(Context c) {
    String name = c.args.single("a key name");
    Optional<String> ifActiveText = c.args.value("--if-active-for");
    Optional<Duration> ifActiveFor = c.args.get("--if-active-for", Duration.class);
    Optional<String> graceText = c.args.value("--grace");
    Optional<Duration> grace = c.args.get("--grace", Duration.class);
    Rotation rotation =
        grace.isPresent() ? Rotation.grace(grace.get()) : Rotation.of(RotationDates.COPIED);
    if (c.args.flag("--shifted-dates")) rotation = rotation.dates(RotationDates.SHIFTED);
    KeyHandle current =
        c.kms()
            .keys()
            .findByName(name)
            .orElseThrow(() -> new CliException(ExitCode.NOT_FOUND, "no Active key named " + name));
    c.targetId = current.id();
    Instant planned = grace.map(g -> c.now().plus(g).truncatedTo(ChronoUnit.SECONDS)).orElse(null);
    // The grace period changes the old key: it schedules its deactivation. Confirm it first.
    if (grace.isPresent())
      c.confirm(rotationPlan(name, current, ifActiveText, graceText.get(), grace.get(), planned));
    c.hints(e -> rotateHint(c, name, current.id(), planned, e));
    RotationResult r;
    if (ifActiveFor.isPresent())
      // The confirmed plan names the current key: bound to it, the call refuses another one.
      r =
          grace.isPresent()
              ? current.rotateIfActiveForResult(ifActiveFor.get(), rotation, current)
              : current.rotateIfActiveForResult(ifActiveFor.get(), rotation);
    else r = current.rotateResult(rotation);
    rotationReport(c, name, r, ifActiveText, graceText);
  }

  /** What rotate --grace will do, for its confirmation. */
  private static List<String> rotationPlan(
      String name,
      KeyHandle current,
      Optional<String> ifActiveText,
      String graceText,
      Duration grace,
      Instant planned) {
    KeyAttributes a = current.attributes();
    List<String> plan = new ArrayList<>();
    plan.add(
        "rotate "
            + name
            + ": "
            + Render.summary(a)
            + ifActiveText
                .map(d -> ", if it has been Active for " + d + " (otherwise nothing changes)")
                .orElse(""));
    plan.add("  creates a new Active key that takes the name, and");
    plan.add(
        grace.isZero()
            ? "  deactivates " + current.id() + " at once (its Deactivation Date is now):"
            : "  sets the Deactivation Date of "
                + current.id()
                + " to about "
                + planned
                + " ("
                + graceText
                + " from now), unless it has an earlier one. From then:");
    plan.addAll(Plans.DEACTIVATED);
    return plan;
  }

  /** The hint for a failure of rotate, by the kind of refusal the SDK reports. */
  private static String rotateHint(
      Context c, String name, String old, Instant planned, KmsException e) {
    if (e instanceof PartialCompletionException p) return graceHint(c, name, old, planned, p);
    if (e instanceof StateConflictException s)
      return switch (s.conflict()) {
        case NOT_AS_PLANNED ->
            "another caller rotated "
                + name
                + " while waiting for the confirmation: see "
                + c.suggest("lineage", name)
                + ", and repeat the command for a new plan";
        case REPLACED ->
            "another caller rotated "
                + name
                + " meanwhile: see "
                + c.suggest("lineage", name)
                + "; the name leads to the new key";
        case STATE ->
            s.observedState().orElse(null) == KeyState.COMPROMISED
                ? "a Compromised key is not rotated: replace it with "
                    + c.suggest(
                        "replace-compromised", s.objectId().orElse(old), "--compromised-at", "TIME")
                : null;
        default -> null;
      };
    if (e instanceof KeyMismatchException)
      return name
          + " names "
          + old
          + ", which is not a symmetric key: rotate replaces keys. Give a secret a new value with "
          + c.suggest("register-secret", "--name", name, "--value-file", "FILE", "--replace", old);
    return null;
  }

  /** Prints what a rotation did. */
  private static void rotationReport(
      Context c,
      String name,
      RotationResult r,
      Optional<String> ifActiveText,
      Optional<String> graceText) {
    RotationResult.Outcome outcome = r.outcome();
    String previous = r.previous().id();
    String next = r.current().id();
    Instant deactivation = r.previousDeactivationDate().orElse(null);
    String warning =
        outcome == RotationResult.Outcome.RECOVERED
            ? "the reply to the Re-key of "
                + previous
                + " was lost, and "
                + next
                + " was found as its replacement: this call or another caller made it"
            : null;
    if (outcome == RotationResult.Outcome.ROTATED || outcome == RotationResult.Outcome.RECOVERED)
      c.done("rotated " + name + ": " + previous + " -> " + next);
    else if (deactivation != null)
      c.done("set the Deactivation Date of " + previous + " to " + deactivation);
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("name", name);
    result.put("action", Values.token(outcome));
    // Unknown (null) when a replacement was found after a lost reply.
    result.put(
        "rotated",
        outcome == RotationResult.Outcome.RECOVERED
            ? null
            : outcome == RotationResult.Outcome.ROTATED);
    result.put("previous", previous);
    result.put("current", next);
    result.put("ifActiveFor", ifActiveText.orElse(null));
    result.put("grace", graceText.orElse(null));
    result.put("previousDeactivationDate", deactivation);
    result.put("warning", warning);
    result.put("recoveredFrom", Cli.Failure.step(r.recoveredFrom().orElse(null)));
    c.emit(
        result,
        () -> {
          c.out.println(
              switch (outcome) {
                case NOT_DUE ->
                    "Not due: "
                        + previous
                        + " has been Active for less than "
                        + ifActiveText.orElse("")
                        + "; nothing changed.";
                case FOLLOWED ->
                    "Not rotated: another caller replaced "
                        + previous
                        + " with "
                        + next
                        + " already; "
                        + next
                        + " is the current key.";
                case ROTATED -> "Rotated " + name + ": " + previous + " -> " + next;
                case RECOVERED ->
                    "Rotated "
                        + name
                        + ", by this call or another caller: "
                        + previous
                        + " -> "
                        + next;
              });
          if (outcome == RotationResult.Outcome.NOT_DUE) return;
          if (deactivation != null)
            c.out.println(
                previous
                    + " stays Active until "
                    + deactivation
                    + ", then the server deactivates it.");
          else if (graceText.isPresent()) c.out.println(previous + " has no Deactivation Date.");
          else if (outcome != RotationResult.Outcome.FOLLOWED)
            c.out.println(
                previous
                    + " stays Active: it still encrypts and decrypts. Expire it when nothing"
                    + " should seal under it.");
          if (warning != null) c.warn(warning);
        });
  }

  /**
   * The hint for a rotation that stopped after its Re-key. A refusal whose {@link
   * KmsException#objectId()} names the old key is the server refusing a request about it after the
   * Re-key: its Deactivation Date, or reading it. Then {@code expire --at} may be refused too, so
   * the old key is deactivated once the grace period is over. Any other failure, such as reading or
   * activating the new key, came before the date was asked for: the hint says to look at the old
   * key and set the date if it is missing. The new key is the one this call created, or the one it
   * found after a lost reply.
   */
  private static String graceHint(
      Context c, String name, String old, Instant planned, PartialCompletionException p) {
    String made =
        !p.created().isEmpty()
            ? p.created().get(0).id()
            : !p.found().isEmpty() ? p.found().get(0).id() : null;
    String check =
        made == null
            ? "see the new key with: " + c.suggest("lineage", name)
            : "check the new key with: "
                + c.suggest("show", made)
                + "; if it is Pre-Active, activate it with: "
                + c.suggest("activate", made);
    if (planned == null) return check + ". Do not repeat rotate, which would rotate the new key";
    String current = made == null ? "NEW_ID" : made;
    // A refusal (by its documented category, not by subclass) of a request about OLD.
    boolean dateRefused =
        p.getCause() instanceof KmsException k
            && k.objectId().filter(old::equals).isPresent()
            && switch (k.category()) {
              case FIX_ACCESS, FIX_REQUEST, STATE -> true;
              default -> false;
            };
    if (dateRefused)
      return check
          + "; the server refused a request about "
          + old
          + " after the rotation (its Deactivation Date, or reading it), so it may refuse"
          + " expire --at too: once the grace period is over, run "
          + c.suggest("deactivate-predecessors", current)
          + ". Do not repeat rotate, which would rotate the new key";
    return check
        + ". Then see whether "
        + old
        + " has a Deactivation Date with: "
        + c.suggest("show", old)
        + "; if it has none, set it with: "
        + c.suggest("expire", old, "--at", planned.toString())
        + "; if the server refuses that, run "
        + c.suggest("deactivate-predecessors", current)
        + " once the grace period is over. Do not repeat rotate, which would rotate the new key";
  }
}
