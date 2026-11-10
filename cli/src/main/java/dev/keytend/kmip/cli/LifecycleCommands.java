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

import dev.keytend.kmip.kms.CompromisePlan;
import dev.keytend.kmip.kms.CompromiseResult;
import dev.keytend.kmip.kms.KeyAttributes;
import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyMismatchException;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.KmsException;
import dev.keytend.kmip.kms.KmsKeys;
import dev.keytend.kmip.kms.OutcomeUnknownException;
import dev.keytend.kmip.kms.PartialCompletionException;
import dev.keytend.kmip.kms.PermissionDeniedException;
import dev.keytend.kmip.kms.ReconcilePlan;
import dev.keytend.kmip.kms.RetirementPlan;
import dev.keytend.kmip.kms.RevocationReason;
import dev.keytend.kmip.kms.Rotation;
import dev.keytend.kmip.kms.RotationDates;
import dev.keytend.kmip.kms.StateConflictException;
import dev.keytend.kmip.kms.UnsupportedException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The commands that change a key's lifecycle: activate, expire, revoke, replace-compromised,
 * destroy, deactivate-predecessors, retire-predecessors and reconcile. Each prints its plan and
 * needs a confirmation; all but reconcile act on an identifier.
 */
final class LifecycleCommands {
  private LifecycleCommands() {}

  static void activate(Context c) {
    String id = c.args.single("an object identifier");
    c.targetId = id;
    KeyHandle key = c.kms().keys().handle(id);
    KeyAttributes a = key.attributes();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("id", id);
    if (a.state() == KeyState.ACTIVE) {
      nothingToDo(c, result, a, "is Active already");
      return;
    }
    if (a.state() != KeyState.PRE_ACTIVE)
      throw new CliException(
          ExitCode.STATE_CONFLICT,
          id + " is " + Render.state(a) + ", not Pre-Active, so it cannot be activated",
          "KMIP has no way back to Active: use another key, or create one");
    c.confirm(
        List.of(
            "activate " + Render.summary(a),
            "  makes it Active: it encrypts from now on, and its cryptoperiod starts.",
            "  KMIP has no way back to Pre-Active."));
    try {
      key.activate();
    } catch (StateConflictException e) {
      if (e.conflict() != StateConflictException.Conflict.STATE
          || e.observedState().orElse(null) != KeyState.ACTIVE) throw e;
      // Another caller activated it while the confirmation waited: what was asked is done.
      String warning = "another caller activated " + id + " while the confirmation waited";
      result.put("action", "none");
      result.put("state", Values.token(KeyState.ACTIVE));
      result.put("deactivationDate", a.deactivationDate().orElse(null));
      result.put("warning", warning);
      c.emit(
          result,
          () -> {
            c.out.println(id + " is Active already; nothing changed.");
            c.warn(warning);
          });
      return;
    }
    c.done("activated " + id);
    result.put("action", "activated");
    readBack(c, key, result);
    c.emit(result, () -> c.out.println("Activated " + id + "."));
  }

  static void expire(Context c) {
    String id = c.args.single("a key identifier");
    c.targetId = id;
    RevocationReason.Kind kind =
        c.args
            .get("--reason", RevocationReason.Kind.class)
            .orElse(RevocationReason.Kind.UNSPECIFIED);
    if (kind.compromise())
      throw new CliException(
          ExitCode.USAGE,
          "expire does not compromise a key",
          "use revoke --reason " + Values.token(kind) + " for a compromise");
    String message = c.args.value("--message").orElse(null);
    Optional<Instant> at = c.args.get("--at", Instant.class);
    if (at.isPresent() && (message != null || c.args.value("--reason").isPresent()))
      throw new CliException(
          ExitCode.USAGE,
          "expire --at records no reason or message: it sets only the Deactivation Date",
          "leave out --reason and --message, or expire the key without --at when the time comes");
    if (at.isPresent()) expireAt(c, id, at.get());
    else expireNow(c, id, kind, message);
  }

  /** expire without --at: deactivates the key now. */
  private static void expireNow(Context c, String id, RevocationReason.Kind kind, String message) {
    KeyHandle key = c.kms().keys().handle(id);
    KmipVersion version = c.kms().version();
    requireMessageVersion(version, kind, message);
    RevocationReason reason = reason(kind, message, null);
    KeyAttributes a = key.attributes();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("id", id);
    if (a.state() == KeyState.DEACTIVATED) {
      nothingToDo(c, result, a, "is Deactivated already");
      return;
    }
    if (a.state() == KeyState.PRE_ACTIVE) throw Plans.preActive(a, c);
    if (a.state() != KeyState.ACTIVE)
      throw new CliException(
          ExitCode.STATE_CONFLICT,
          id + " is " + Render.state(a) + ", not Active, so it cannot be expired");
    List<String> plan = new ArrayList<>();
    plan.add("expire " + Render.summary(a));
    plan.add(
        "  deactivates it now"
            + (version.atLeast(KmipVersion.V3_0)
                ? " (KMIP 3.0: the Deactivate operation; the reason is not recorded)"
                : " (KMIP " + version + ": a Revoke with reason " + Values.token(kind) + ")")
            + ":");
    plan.addAll(Plans.DEACTIVATED);
    plan.add("  It is not compromised, and no re-encryption is needed.");
    c.confirm(plan);
    key.deactivate(reason);
    c.done("deactivated " + id);
    result.put("action", "deactivated");
    readBack(c, key, result);
    c.emit(
        result,
        () ->
            c.out.println(
                "Expired " + id + ": Deactivated. It still decrypts where the server allows."));
  }

  /**
   * expire --at: sets the Deactivation Date after the confirmation, through {@link
   * KeyHandle#deactivateAt}, which reads the key again then and never postpones an earlier date.
   */
  private static void expireAt(Context c, String id, Instant at) {
    Instant date = at.truncatedTo(ChronoUnit.SECONDS);
    if (date.isBefore(at)) date = date.plusSeconds(1);
    if (!date.isAfter(c.now()))
      throw new CliException(
          ExitCode.USAGE,
          "--at " + date + " is not in the future",
          "to expire the key now, leave out --at");
    KeyHandle key = c.kms().keys().handle(id);
    KeyAttributes a = key.attributes();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("id", id);
    Optional<Instant> existing = a.deactivationDate();
    if (existing.isPresent() && !existing.get().isAfter(date)) {
      result.put("deactivationDate", existing.get());
      nothingToDo(
          c,
          result,
          a,
          "has the Deactivation Date " + existing.get() + " already, no later than " + date);
      return;
    }
    if (a.state() != KeyState.ACTIVE && a.state() != KeyState.PRE_ACTIVE) {
      result.put("deactivationDate", existing.orElse(null));
      nothingToDo(c, result, a, "is " + Render.state(a) + " already, so it encrypts nothing");
      return;
    }
    List<String> plan = new ArrayList<>();
    plan.add("expire " + Render.summary(a));
    plan.add(
        "  sets its Deactivation Date to "
            + date
            + (existing.isPresent() ? " (it is " + existing.get() + " now)" : "")
            + ", unless it has an earlier one by then. From that date:");
    plan.addAll(Plans.DEACTIVATED);
    if (a.state() == KeyState.PRE_ACTIVE) {
      plan.add("  It is Pre-Active: the date takes effect once it is Active. What a server does");
      plan.add("  when the date passes while the key is still Pre-Active is its own.");
    } else {
      plan.add("  Applications sealing through the SDK move to its replacement.");
    }
    c.confirm(plan);
    if (!date.isAfter(c.now()))
      throw new CliException(
          ExitCode.USAGE,
          "--at " + date + " passed while waiting for the confirmation; nothing was changed",
          "run " + c.suggest("expire", id) + " to expire the key now, or give a later --at");
    boolean v1 = !c.kms().version().atLeast(KmipVersion.V2_0);
    c.hints(
        e -> {
          if (e instanceof UnsupportedException)
            return "this server does not let clients set the Deactivation Date: run "
                + c.suggest("expire", id)
                + " when the time comes";
          if (e instanceof PermissionDeniedException && v1)
            return "on KMIP 1.x, a server that does not let clients set the Deactivation Date"
                + " answers Permission Denied too: if the client identity of this server group is"
                + " right, run "
                + c.suggest("expire", id)
                + " when the time comes";
          return null;
        });
    Instant effective = key.deactivateAt(date);
    boolean set = effective.equals(date);
    if (set) c.done("set the Deactivation Date of " + id + " to " + effective);
    result.put("action", set ? "scheduled" : "none");
    result.put("deactivationDate", effective);
    readBack(c, key, result);
    Instant shown = date;
    c.emit(
        result,
        () ->
            c.out.println(
                set
                    ? "Expires at " + shown + ": " + id + "'s Deactivation Date is set."
                    : id
                        + " has the earlier Deactivation Date "
                        + effective
                        + " now, which was kept; nothing changed."));
  }

  /** A reason built from the command line's values: refused values are a usage error. */
  private static RevocationReason reason(
      RevocationReason.Kind kind, String message, Instant compromised) {
    return Context.argument(() -> RevocationReason.of(kind, message, compromised));
  }

  /**
   * Refuses a message that the request would drop: on KMIP 3.0 a deactivation is the Deactivate
   * operation, which records no reason or message.
   */
  private static void requireMessageVersion(
      KmipVersion version, RevocationReason.Kind kind, String message) {
    if (message != null && !kind.compromise() && version.atLeast(KmipVersion.V3_0))
      throw new CliException(
          ExitCode.USAGE,
          "--message is not recorded on KMIP "
              + version
              + ": a key is deactivated with the Deactivate operation, which takes no reason or"
              + " message",
          "leave out --message");
  }

  private static void nothingToDo(
      Context c, Map<String, Object> result, KeyAttributes a, String why) {
    result.put("action", "none");
    result.put("state", Values.token(a.state()));
    result.putIfAbsent("deactivationDate", a.deactivationDate().orElse(null));
    result.put("warning", null);
    c.emit(result, () -> c.out.println(a.id() + " " + why + "; nothing changed."));
  }

  /**
   * Reads the key back after a change, for the result's {@code state} and {@code
   * deactivationDate}. The change was made, so a failed read is a warning: both are then null.
   *
   * @return the attributes read, or null when the read failed
   */
  private static KeyAttributes readBack(Context c, KeyHandle key, Map<String, Object> result) {
    try {
      KeyAttributes after = key.allowingCompromised().attributes();
      result.put("state", Values.token(after.state()));
      result.putIfAbsent("deactivationDate", after.deactivationDate().orElse(null));
      result.put("warning", null);
      return after;
    } catch (KmsException e) {
      String warning =
          "the change was made, but " + key.id() + " could not be read back: " + e.getMessage();
      result.put("state", null);
      result.putIfAbsent("deactivationDate", null);
      result.put("warning", warning);
      c.warn(warning);
      return null;
    }
  }

  static void revoke(Context c) {
    String id = c.args.single("a key identifier");
    c.targetId = id;
    RevocationReason.Kind kind =
        c.args
            .get("--reason", RevocationReason.Kind.class)
            .orElseThrow(() -> CliException.usage("revoke needs --reason (see revoke --help)"));
    boolean compromise = kind.compromise();
    Optional<Instant> since = c.args.get("--compromised-at", Instant.class);
    if (compromise && since.isEmpty())
      throw CliException.usage(
          "--reason "
              + Values.token(kind)
              + " needs --compromised-at: when the key may first have been exposed");
    if (!compromise && since.isPresent())
      throw CliException.usage("--compromised-at goes only with a compromise reason");
    String message = c.args.value("--message").orElse(null);
    RevocationReason reason = reason(kind, message, since.orElse(null));
    KeyHandle key = c.kms().keys().handle(id).allowingCompromised();
    KmipVersion version = c.kms().version();
    requireMessageVersion(version, kind, message);
    KeyAttributes a = key.attributes();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("id", id);
    result.put("reason", Values.token(kind));
    if (Plans.destroyed(a.state()))
      throw new CliException(ExitCode.STATE_CONFLICT, id + " is " + Render.state(a) + " already");
    if (compromise && a.state() == KeyState.COMPROMISED) {
      nothingToDo(c, result, a, "is Compromised already");
      return;
    }
    if (!compromise && a.state() == KeyState.COMPROMISED)
      throw new CliException(
          ExitCode.STATE_CONFLICT,
          id + " is Compromised; it cannot be deactivated",
          "destroy it once its data is re-encrypted under another key: "
              + c.suggest("destroy", id));
    if (!compromise && a.state() == KeyState.DEACTIVATED) {
      nothingToDo(c, result, a, "is Deactivated already");
      return;
    }
    if (!compromise && a.state() == KeyState.PRE_ACTIVE) throw Plans.preActive(a, c);
    List<String> plan = new ArrayList<>();
    plan.add("revoke " + Render.summary(a) + " with reason " + Values.token(kind));
    if (compromise) {
      plan.add(
          "  makes it Compromised, from "
              + since.get().truncatedTo(ChronoUnit.SECONDS)
              + ". This cannot be undone.");
      plan.add(
          "  It no longer encrypts. The SDK opens data under it only when the application asks for"
              + " a");
      plan.add(
          "  compromised key explicitly, to move that data; whether the server decrypts with it is"
              + " its policy.");
      if (!a.names().isEmpty())
        plan.add(
            "  Applications that find it by name fail until a replacement has the name: see"
                + " replace-compromised.");
      plan.add("  Next: re-encrypt the data under a replacement, then destroy this key.");
    } else {
      plan.add(
          "  deactivates it"
              + (version.atLeast(KmipVersion.V3_0)
                  ? " (KMIP 3.0: the Deactivate operation, without the reason)"
                  : "")
              + ":");
      plan.addAll(Plans.DEACTIVATED);
    }
    c.confirm(plan);
    key.revoke(reason);
    c.done("revoked " + id);
    result.put("action", "revoked");
    KeyAttributes after = readBack(c, key, result);
    c.emit(
        result,
        () ->
            c.out.println(
                "Revoked " + id + (after == null ? "." : ": " + Render.state(after) + ".")));
  }

  static void replaceCompromised(Context c) {
    String id = c.args.single("a key identifier");
    c.targetId = id;
    Instant since =
        c.args
            .get("--compromised-at", Instant.class)
            .orElseThrow(() -> CliException.usage("replace-compromised needs --compromised-at"));
    boolean shifted = c.args.flag("--shifted-dates");
    boolean copied = c.args.flag("--copied-dates");
    if (shifted && copied)
      throw CliException.usage("give --shifted-dates or --copied-dates, not both");
    Rotation rotation =
        shifted
            ? Rotation.of(RotationDates.SHIFTED)
            : copied ? Rotation.of(RotationDates.COPIED) : null;
    RevocationReason reason =
        reason(RevocationReason.Kind.KEY_COMPROMISE, c.args.value("--message").orElse(null), since);
    KeyHandle key = c.kms().keys().handle(id).allowingCompromised();
    c.hints(e -> compromiseHint(c, id, e));
    // The SDK's plan: its refusals (a destroyed key, another kind) come before anything is shown.
    CompromisePlan plan = key.compromisePlan();
    boolean replaced = !plan.replacementIds().isEmpty();
    String successors = String.join(", ", plan.replacementIds());
    if (replaced && plan.revokes())
      throw new CliException(
          ExitCode.STATE_CONFLICT,
          id
              + " is not the newest key of its lineage: "
              + successors
              + " replaced it, so replace-compromised refuses it",
          "revoke it with: "
              + c.suggest(
                  "revoke",
                  id,
                  "--reason",
                  "key-compromise",
                  "--compromised-at",
                  since.truncatedTo(ChronoUnit.SECONDS).toString())
              + "; the name already leads to a newer key (see "
              + c.suggest("lineage", "--id", id)
              + ")");
    c.confirm(compromisePlanLines(c, plan, since));
    // Bound to the plan: a revocation, replacement or rotation by another caller while the
    // confirmation waited is refused, with nothing changed.
    CompromiseResult r =
        rotation == null
            ? key.replaceCompromisedResult(reason, plan)
            : key.replaceCompromisedResult(reason, rotation, plan);
    String replacement = r.replacement().id();
    String action = Values.token(r.outcome());
    // Done whenever the call changed a key: finishing with an existing replacement still
    // activates, links or names it when the plan says so, or finishes a name move.
    boolean changed =
        r.outcome() != CompromiseResult.Outcome.EXISTING
            || r.revoked()
            || plan.existingReplacement().map(e -> e.state() == KeyState.PRE_ACTIVE).orElse(false)
            || !plan.attributes().names().isEmpty()
            || !plan.unfinishedNameMoves().isEmpty();
    if (changed) c.done("replaced compromised key " + id + " with " + replacement);
    Instant occurrence = r.compromiseOccurrenceDate().orElse(null);
    List<String> also = r.replacedInTurn().stream().map(KeyHandle::id).toList();
    List<String> warnings = compromiseWarnings(c, plan, r, since);
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("compromised", id);
    result.put("replacement", replacement);
    result.put("action", action);
    result.put("revoked", r.revoked());
    result.put("compromiseOccurrenceDate", occurrence);
    result.put("replacedInTurn", also);
    result.put("created", r.created().stream().map(KeyHandle::id).toList());
    result.put(
        "otherDescendants", plan.otherDescendants().stream().map(KeyAttributes::id).toList());
    result.put("checkedForUnlinkedKeys", plan.checkedForUnlinkedKeys());
    result.put("unreadableCandidates", plan.unreadableCandidates());
    result.put("warning", warnings.isEmpty() ? null : String.join("; ", warnings));
    result.put("recoveredFrom", Cli.Failure.step(r.recoveredFrom().orElse(null)));
    c.emit(
        result,
        () -> {
          c.out.println(replacement);
          c.err.println(
              switch (r.outcome()) {
                case EXISTING ->
                    (r.revoked()
                            ? "Revoked " + id + " as compromised; "
                            : id + " was Compromised already; ")
                        + replacement
                        + " replaced it before, and nothing was created.";
                case COMPLETED ->
                    id + " was Compromised already; its replacement is " + replacement + ".";
                case RECOVERED -> id + " is Compromised; its replacement is " + replacement + ".";
                case REPLACED ->
                    "Revoked " + id + " as compromised; its replacement is " + replacement + ".";
              });
          plan.replacedInTurn()
              .filter(d -> also.contains(d.id()))
              .ifPresent(
                  d ->
                      c.err.println(
                          "Also replaced "
                              + d.id()
                              + ", which replaced "
                              + id
                              + " and was Compromised"
                              + d.compromiseOccurrenceDate().map(t -> " from " + t).orElse("")
                              + ": re-encrypt its data under "
                              + replacement
                              + " too."));
          for (String w : warnings) c.warn(w);
        });
  }

  /** The warnings of a replacement after a compromise: what this call cannot claim, and leftovers. */
  private static List<String> compromiseWarnings(
      Context c, CompromisePlan plan, CompromiseResult r, Instant since) {
    String id = r.compromised().id();
    String replacement = r.replacement().id();
    List<String> warnings = new ArrayList<>();
    if (r.outcome() == CompromiseResult.Outcome.RECOVERED) {
      // Only the steps no reply confirmed are uncertain.
      List<String> unsure = new ArrayList<>();
      if (plan.revokes() && !r.revoked()) unsure.add(id + " was revoked");
      // The replacement's own step: an existing one's Activate, or the Re-key or Create that made
      // it. The lost step's objectId() names the replacement for that Activate, and for the
      // removal of the temporary name from the key this call created.
      boolean onReplacement =
          r.recoveredFrom().flatMap(KmsException::objectId).filter(replacement::equals).isPresent();
      boolean own = r.created().contains(r.replacement());
      if (onReplacement && !own) unsure.add(replacement + " was activated");
      else if (!own) unsure.add(replacement + " was made as its replacement");
      if (unsure.isEmpty() && onReplacement)
        warnings.add(
            "a reply was lost while removing the temporary name from "
                + replacement
                + ", which this call created, and reading back found the name gone");
      else
        warnings.add(
            "a reply was lost, and reading back found that "
                + (unsure.isEmpty() ? "the replacement went ahead" : String.join(" and ", unsure))
                + ": this call or another caller did that. Check the server's audit log if it"
                + " matters which");
    }
    Instant occurrence = r.compromiseOccurrenceDate().orElse(null);
    Instant asked = since.truncatedTo(ChronoUnit.SECONDS);
    if (!r.revoked() && occurrence != null && !occurrence.equals(asked))
      warnings.add(
          id
              + " keeps its first compromise's date, "
              + occurrence
              + ", not "
              + asked
              + ": treat data sealed under it since the earlier of the two as possibly an"
              + " attacker's");
    // A forked lineage: the other newest keys are left as they are.
    for (KeyAttributes other : plan.otherDescendants())
      warnings.add(
          other.id()
              + " also replaced "
              + id
              + " ("
              + Render.state(other)
              + ") and was left as it is: join the branches with "
              + c.suggest("reconcile", replacement));
    // The plan could not search for an earlier attempt's unlinked key. (A key this
    // call made that lost to another caller's is a stop in the plan-bound form, never a success.)
    if (!plan.checkedForUnlinkedKeys()) warnings.add(uncheckedForUnlinked(c, plan, id));
    return warnings;
  }

  /**
   * Why the plan could not tell that no earlier attempt left an unlinked key to replace the key it
   * would replace, and what to do: the objects the search located and could not read, when it
   * located any; otherwise how to find such a key ({@link #lookForUnlinked}).
   */
  private static String uncheckedForUnlinked(Context c, CompromisePlan plan, String id) {
    String replaced = plan.replacedInTurn().map(KeyAttributes::id).orElse(id);
    List<String> unreadable = plan.unreadableCandidates();
    if (unreadable.isEmpty())
      return "the server could not be searched for a key an earlier attempt created to replace "
          + replaced
          + " and did not link: "
          + lookForUnlinked(c, replaced);
    boolean one = unreadable.size() == 1;
    List<String> shown = unreadable.subList(0, Math.min(unreadable.size(), SHOWN));
    return "the search for a key an earlier attempt created to replace "
        + replaced
        + " and did not link found "
        + String.join(", ", shown)
        + (shown.size() < unreadable.size()
            ? " and " + (unreadable.size() - shown.size()) + " more (see --json)"
            : "")
        + ", which these credentials cannot read: "
        + (one ? "it" : "any of them")
        + " may be such a key. Have "
        + (one ? "it" : "them")
        + " checked with credentials that can read "
        + (one ? "it" : "them")
        + " ("
        + c.suggest("show", shown.get(0))
        + ")";
  }

  /** How many unreadable candidates the plan line and the warning name; --json has every one. */
  private static final int SHOWN = 5;

  /**
   * How to find a key an earlier replace-compromised created to replace {@code replaced} and did
   * not link: among the Pre-Active symmetric keys, by its temporary name ({@link
   * CompromisePlan#TEMPORARY_NAME_PREFIX}) or none, or Active with the names the key had where the
   * server refused its links; either way show gives it the SDK's record ({@link
   * CompromisePlan#REPLACEMENT_RECORD}).
   */
  static String lookForUnlinked(Context c, String replaced) {
    return "if one exists, it is in "
        + c.suggest("list", "--kind", "symmetric-key", "--state", "pre-active")
        + ", named "
        + Values.safe(CompromisePlan.TEMPORARY_NAME_PREFIX + replaced + "-…")
        + " or with no name, or Active with the names "
        + replaced
        + " had if the server refused its links (lineage does not show it); show gives it "
        + CompromisePlan.REPLACEMENT_RECORD
        + " "
        + replaced;
  }

  /** What replace-compromised will do, from the SDK's plan. */
  private static List<String> compromisePlanLines(Context c, CompromisePlan plan, Instant since) {
    KeyAttributes a = plan.attributes();
    String id = a.id();
    List<String> lines = new ArrayList<>();
    lines.add("replace-compromised " + Render.summary(a));
    if (plan.revokes())
      lines.add(
          "  revokes it as compromised from "
              + since.truncatedTo(ChronoUnit.SECONDS)
              + " (this cannot be undone).");
    else
      lines.add(
          "  it is Compromised already: its first compromise's date"
              + plan.compromiseOccurrenceDate().map(d -> " (" + d + ")").orElse("")
              + " and message stay, and --compromised-at and --message are not recorded.");
    // The SDK's decision, which the call is bound to: every key it acts on, and the
    // keys of a forked lineage it leaves alone.
    plan.existingReplacement()
        .ifPresent(
            r ->
                lines.add(
                    "  "
                        + r.id()
                        + " replaced it: this finishes with that key"
                        + (r.state() == KeyState.PRE_ACTIVE ? ", activating it," : "")
                        + " and creates nothing."));
    plan.replacedInTurn()
        .ifPresent(
            d ->
                lines.add(
                    "  "
                        + d.id()
                        + " replaced it and is Compromised too"
                        + d.compromiseOccurrenceDate().map(t -> " (from " + t + ")").orElse("")
                        + ": this replaces "
                        + d.id()
                        + " as well, creating an Active key that takes both keys' names."));
    if (plan.creates() && plan.replacedInTurn().isEmpty())
      lines.add("  It creates an Active replacement with its names, linked to it.");
    plan.unfinishedNameMoves()
        .forEach(
            (holder, names) ->
                lines.add(
                    "  An earlier attempt stopped moving "
                        + Values.safe(String.join(", ", names))
                        + " to "
                        + holder
                        + ": this finishes the move to the replacement and removes that record."));
    for (KeyAttributes other : plan.otherDescendants())
      lines.add(
          "  "
              + other.id()
              + " also replaced it ("
              + Render.state(other)
              + (other.names().isEmpty() ? ", no name" : ", names: " + Render.names(other))
              + "): the lineage forked; this leaves that key as it is (join them with reconcile"
              + " afterwards).");
    lines.add(
        "  Re-encrypt the data under the replacement, then destroy "
            + id
            + plan.replacedInTurn().map(d -> " and " + d.id()).orElse("")
            + ".");
    if (!plan.checkedForUnlinkedKeys() && plan.unreadableCandidates().isEmpty())
      lines.add(
          "  The server could not be searched for a key an earlier attempt created to replace "
              + plan.replacedInTurn().map(KeyAttributes::id).orElse(id)
              + " and did not link: look before you confirm, since a second key beside it would"
              + " leave it unaccounted for ("
              + lookForUnlinked(c, plan.replacedInTurn().map(KeyAttributes::id).orElse(id))
              + ").");
    else if (!plan.checkedForUnlinkedKeys()) {
      String why = uncheckedForUnlinked(c, plan, id);
      lines.add(
          "  "
              + Character.toUpperCase(why.charAt(0))
              + why.substring(1)
              + " before you confirm, since a second key beside such a key would leave it"
              + " unaccounted for.");
    }
    lines.add(
        "  If another caller revokes, replaces, rotates or renames these keys while this waits,"
            + " nothing is changed.");
    return lines;
  }

  /** The hint for a failure of replace-compromised. */
  private static String compromiseHint(Context c, String id, KmsException e) {
    if (e instanceof PartialCompletionException || e instanceof OutcomeUnknownException)
      return "check the keys with: "
          + c.suggest("lineage", "--id", id)
          // The object the stop names, which lineage may not show: an unlinked key.
          + e.objectId()
              .filter(other -> !other.equals(id))
              .map(other -> ", and " + other + " with: " + c.suggest("show", other))
              .orElse("")
          + "; repeat replace-compromised only when the message says so (it shows a new plan"
          + " first)";
    if (e instanceof StateConflictException s
        && s.conflict() == StateConflictException.Conflict.NOT_AS_PLANNED)
      return "another caller changed "
          + id
          + " or a key descending from it while the confirmation waited (revoked, replaced,"
          + " rotated, renamed or compromised it, or is replacing it now), so nothing was changed:"
          + " see "
          + c.suggest("lineage", "--id", id)
          + ", and repeat the command for a new plan";
    if (e instanceof StateConflictException s
        && s.conflict() == StateConflictException.Conflict.STATE
        && s.observedState().map(Plans::destroyed).orElse(false))
      return "nothing is left to replace: find the key the name leads to with: "
          + c.suggest("list", "--name", "NAME");
    if (e instanceof StateConflictException s
        && s.conflict() == StateConflictException.Conflict.STATE
        && s.objectId().filter(other -> !other.equals(id)).isPresent())
      // The newest key descending from it cannot be the replacement: refused before any change.
      return "the newest key descending from "
          + id
          + ", "
          + s.objectId().get()
          + ", is "
          + s.observedState().map(Values::token).orElse("in another state")
          + ", so nothing was changed: see "
          + c.suggest("lineage", "--id", id)
          + ", and find the key the name leads to with "
          + c.suggest("list", "--name", "NAME");
    if (e instanceof StateConflictException s
        && s.conflict() == StateConflictException.Conflict.UNLINKED_REPLACEMENT
        && s.objectId().isPresent())
      // A key an earlier attempt created and did not link: refused before any change.
      return "nothing was changed: see "
          + s.objectId().get()
          + " with "
          + c.suggest("show", s.objectId().get())
          + "; when it is Pre-Active, still unlinked a few minutes after its creation date, and no"
          + " other replace-compromised of "
          + id
          + " is running, destroy it with "
          + c.suggest("destroy", s.objectId().get())
          + " (it was never activated), then repeat the command; when it is Active, use it as"
          + " the replacement";
    if (e instanceof KeyMismatchException)
      return "replace-compromised replaces symmetric keys: see what "
          + id
          + " is with "
          + c.suggest("show", id);
    return null;
  }

  static void destroy(Context c) {
    String id = c.args.single("a key identifier");
    c.targetId = id;
    KeyHandle key = c.kms().keys().handle(id).allowingCompromised();
    KeyAttributes a = key.attributes();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("id", id);
    if (Plans.destroyed(a.state())) {
      nothingToDo(c, result, a, "is " + Render.state(a) + " already");
      return;
    }
    if (a.state() == KeyState.ACTIVE)
      throw new CliException(
          ExitCode.STATE_CONFLICT,
          id + " is Active, so destroy refuses it",
          "expire or revoke it first, re-encrypt what it protects under another key, then destroy"
              + " it");
    List<String> plan = new ArrayList<>();
    plan.add("destroy " + Render.summary(a));
    plan.add("  destroys its key material. THIS CANNOT BE UNDONE.");
    plan.add(
        "  Everything still encrypted under it becomes unreadable, including backups, snapshots and"
            + " replicas.");
    plan.add("  Re-encrypt that data under another key first.");
    if (!a.names().isEmpty())
      plan.add(
          "  Applications that open data by the name "
              + Values.safe(Render.names(a))
              + " can no longer use this key.");
    c.confirm(plan, id, "Type the identifier " + id + " to go ahead: ");
    key.destroy();
    c.done("destroyed " + id);
    result.put("action", "destroyed");
    readBack(c, key, result);
    c.emit(result, () -> c.out.println("Destroyed " + id + "."));
  }

  /**
   * The hints of the commands that act on a lineage from its newest key: deactivate-predecessors
   * and retire-predecessors.
   */
  private static void lineageHints(Context c, String id, KeyAttributes newest, String... repeat) {
    boolean retiring = repeat.length > 0 && repeat[0].equals("retire-predecessors");
    String name = newest.names().isEmpty() ? "NAME" : newest.names().get(0);
    c.hints(
        e -> {
          if (e instanceof PartialCompletionException)
            return "repeat the command to continue where it stopped: " + c.suggest(repeat);
          if (e instanceof StateConflictException)
            return "see the lineage with: "
                + c.suggest("lineage", "--id", id)
                + ", and run the command again for a new plan. Act from the lineage's newest key;"
                + " when it has several, join them first with: "
                + c.suggest("reconcile", name);
          if (e instanceof UnsupportedException) {
            String find =
                " Listing it from the newest key is refused too; list it from an older key with: "
                    + c.suggest("lineage", "--id", "OLDER_KEY_ID")
                    + ". To find one, "
                    + c.suggest("list")
                    + " gives each key's ID and Creation Date, and in "
                    + c.suggest("show", id)
                    + " the link replaced -> ID names the key it replaced";
            return retiring
                ? "the lineage is too long to act on at once: retire it in steps, with"
                    + " --keep-from a key at most 64 rotations from each end. Two steps reach 128"
                    + " rotations; for a longer lineage, retire its oldest keys by hand first."
                    + find
                : "the lineage is too long to act on at once: deactivate the older keys one at a"
                    + " time with "
                    + c.suggest("expire", "KEY_ID")
                    + ". Or, once nothing needs the oldest keys, retire them with "
                    + c.suggest("retire-predecessors", id, "--keep-from", "KEEP_ID")
                    + " and repeat this command."
                    + find;
          }
          return null;
        });
  }

  static void retirePredecessors(Context c) {
    String id = c.args.single("the identifier of the lineage's newest key");
    c.targetId = id;
    Optional<String> message = c.args.value("--message");
    Optional<String> keepFrom = c.args.value("--keep-from");
    KmsKeys keys = c.kms().keys();
    KeyHandle newest = keys.handle(id);
    requireMessageVersion(
        c.kms().version(), RevocationReason.Kind.SUPERSEDED, message.orElse(null));
    KeyAttributes a = newest.attributes();
    if (a.state() == KeyState.COMPROMISED)
      throw new CliException(
          ExitCode.STATE_CONFLICT,
          id
              + " is Compromised, so the keys before it are not retired: they may be the lineage's"
              + " only keys that are not compromised",
          "replace it first with "
              + c.suggest("replace-compromised", id, "--compromised-at", "TIME")
              + ", re-encrypt its data under the replacement, then retire from the replacement");
    List<String> repeat = new ArrayList<>(List.of("retire-predecessors", id));
    keepFrom.ifPresent(k -> repeat.addAll(List.of("--keep-from", k)));
    lineageHints(c, id, a, repeat.toArray(String[]::new));
    RetirementPlan planned;
    if (keepFrom.isPresent()) {
      try {
        planned = newest.retirementPlanOlderThan(keys.handle(keepFrom.get()));
      } catch (KeyMismatchException notInLineage) {
        throw new CliException(
            ExitCode.USAGE,
            "--keep-from " + keepFrom.get() + " is not in the lineage of " + id,
            "see the lineage with: " + c.suggest("lineage", "--id", id),
            notInLineage);
      }
    } else {
      planned = newest.retirementPlan();
    }
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("newest", id);
    result.put("keepFrom", keepFrom.orElse(null));
    result.put("planned", planned.ids());
    if (planned.keys().isEmpty()) {
      result.put("destroyed", List.of());
      c.emit(
          result,
          () ->
              c.out.println("Nothing to retire: the lineage of " + id + " has no older key left."));
      return;
    }
    int count = planned.keys().size();
    List<String> plan = new ArrayList<>();
    plan.add(
        "retire-predecessors of "
            + Render.summary(a)
            + keepFrom.map(k -> ", keeping " + k + " and newer").orElse(""));
    plan.add(
        "  destroys "
            + (count == 1 ? "this key" : "these " + count + " keys, in this order")
            + ":");
    for (KeyAttributes k : planned.keys())
      plan.add(
          "    "
              + Render.summary(k)
              + (k.state() == KeyState.ACTIVE ? ": deactivate, then destroy" : ": destroy"));
    plan.add(
        "  THIS CANNOT BE UNDONE. Data, backups and snapshots still encrypted under them become"
            + " unreadable.");
    plan.add("  Re-encrypt everything under " + keepFrom.orElse(id) + " or newer first.");
    plan.add(
        "  Before its first change it reads the lineage again: if the keys differ from these,"
            + " nothing");
    plan.add(
        "  is destroyed. It acts on these keys only. Make no other change to the lineage while it"
            + " runs.");
    c.confirm(
        plan,
        String.valueOf(count),
        "Type the number of keys to destroy, " + count + ", to go ahead: ");
    RevocationReason reason =
        reason(RevocationReason.Kind.SUPERSEDED, message.orElse("retired"), null);
    List<String> ids =
        newest.retirePredecessors(reason, planned).stream().map(KeyHandle::id).toList();
    if (!ids.isEmpty()) c.done("destroyed " + String.join(", ", ids));
    result.put("destroyed", ids);
    c.emit(
        result,
        () -> {
          for (String k : ids) c.out.println("Destroyed " + k);
          if (ids.isEmpty()) c.out.println("Nothing was destroyed.");
        });
  }

  static void deactivatePredecessors(Context c) {
    String id = c.args.single("the identifier of the lineage's newest key");
    c.targetId = id;
    RevocationReason.Kind kind =
        c.args
            .get("--reason", RevocationReason.Kind.class)
            .orElse(RevocationReason.Kind.SUPERSEDED);
    if (kind.compromise())
      throw new CliException(
          ExitCode.USAGE,
          "deactivate-predecessors does not compromise keys",
          "revoke a compromised key with revoke --reason " + Values.token(kind));
    String message = c.args.value("--message").orElse(null);
    KeyHandle newest = c.kms().keys().handle(id);
    requireMessageVersion(c.kms().version(), kind, message);
    RevocationReason reason = reason(kind, message, null);
    KeyAttributes a = newest.attributes();
    lineageHints(c, id, a, "deactivate-predecessors", id);
    if (a.state() != KeyState.ACTIVE)
      throw new CliException(
          ExitCode.STATE_CONFLICT,
          id
              + " is "
              + Render.state(a)
              + ": deactivate-predecessors starts from the lineage's newest key, which is Active");
    RetirementPlan planned = newest.retirementPlan();
    List<KeyAttributes> active =
        planned.keys().stream().filter(k -> k.state() == KeyState.ACTIVE).toList();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("newest", id);
    if (active.isEmpty()) {
      result.put("deactivated", List.of());
      c.emit(
          result,
          () ->
              c.out.println(
                  "Nothing to deactivate: no older key of the lineage of " + id + " is Active."));
      return;
    }
    List<String> plan = new ArrayList<>();
    plan.add("deactivate-predecessors of " + Render.summary(a));
    plan.add("  deactivates the older Active keys of its lineage:");
    for (KeyAttributes k : active) plan.add("    " + Render.summary(k));
    plan.add("  From then:");
    plan.addAll(Plans.DEACTIVATED);
    plan.add(
        "  Nothing is destroyed. If another key of the lineage is Active by then, nothing is"
            + " deactivated.");
    c.confirm(plan);
    List<String> ids =
        newest.deactivatePredecessors(reason, planned).stream().map(KeyHandle::id).toList();
    if (!ids.isEmpty()) c.done("deactivated " + String.join(", ", ids));
    result.put("deactivated", ids);
    c.emit(
        result,
        () -> {
          for (String k : ids) c.out.println("Deactivated " + k);
          if (ids.isEmpty()) c.out.println("Nothing was deactivated.");
        });
  }

  static void reconcile(Context c) {
    String name = c.args.single("a key name");
    c.targetName = name;
    KmsKeys keys = c.kms().keys();
    String shown = Values.safe(name);
    c.hints(e -> reconcileHint(c, name, e));
    ReconcilePlan planned =
        keys.reconcilePlan(name)
            .orElseThrow(
                () ->
                    new CliException(
                        ExitCode.NOT_FOUND,
                        "no object has the name "
                            + shown
                            + ", and no key records a move of it; nothing changed"));
    String winner = planned.winner().id();
    Map<String, Object> result = new LinkedHashMap<>();
    result.put("name", name);
    result.put("winner", winner);
    result.put("joined", ids(planned.joined()));
    result.put("namesMoved", planned.namesMoved());
    result.put("deactivated", ids(planned.deactivated()));
    if (planned.changesNothing()) {
      result.put("action", "none");
      c.emit(
          result,
          () ->
              c.out.println(
                  "Nothing to reconcile: "
                      + winner
                      + " is the only newest and the only Active key of "
                      + shown
                      + "'s lineage, and has its names; nothing changed."));
      return;
    }
    c.confirm(reconcilePlanLines(name, planned));
    KeyHandle kept = keys.reconcile(name, planned);
    c.targetId = kept.id();
    c.done("reconciled " + name + " into " + kept.id());
    result.put("action", "reconciled");
    c.emit(
        result,
        () ->
            c.out.println(
                "Reconciled "
                    + shown
                    + ": "
                    + kept.id()
                    + " is the lineage's newest key and has its names."));
  }

  /** What reconcile will do, from the SDK's plan. */
  private static List<String> reconcilePlanLines(String name, ReconcilePlan planned) {
    String winner = planned.winner().id();
    List<String> plan = new ArrayList<>();
    plan.add("reconcile " + name + ": keeps " + Render.summary(planned.winner()));
    plan.add("  as the lineage's newest key.");
    boolean pending =
        !planned.winner().names().contains(name)
            && planned.namesMoved().values().stream().noneMatch(n -> n.contains(name));
    if (pending) {
      plan.add(
          "  No object has the name now: a key of this lineage records it as being moved to "
              + winner
              + ".");
      plan.add(
          "  Anyone can write that record on a key of their own: check " + winner + " is yours.");
    }
    if (!planned.joined().isEmpty()) {
      plan.add("  Joins these other newest keys into it:");
      for (KeyAttributes k : planned.joined()) plan.add("    " + Render.summary(k));
    }
    if (!planned.namesMoved().isEmpty()) {
      plan.add("  Moves these names to it:");
      planned
          .namesMoved()
          .forEach(
              (k, names) ->
                  plan.add("    " + names.stream().map(Values::safe).toList() + " from " + k));
    }
    if (!planned.deactivated().isEmpty()) {
      plan.add("  Then deactivates the other Active keys of the lineage:");
      for (KeyAttributes k : planned.deactivated()) plan.add("    " + Render.summary(k));
      plan.addAll(Plans.DEACTIVATED);
    }
    plan.add("  Nothing is destroyed, and everything sealed under the lineage still opens.");
    plan.add("  If the name or its lineage changes before the first change, nothing is changed.");
    return plan;
  }

  /** The hint for a failure of reconcile, by the kind of refusal the SDK reports. */
  private static String reconcileHint(Context c, String name, KmsException e) {
    if (e instanceof PartialCompletionException)
      return "repeat " + c.suggest("reconcile", name) + ": it resumes where it stopped";
    if (e instanceof UnsupportedException)
      return "the server refuses the links reconcile needs: expire the other newest keys by hand"
          + " once nothing seals under them (see "
          + c.suggest("lineage", name)
          + ")";
    if (!(e instanceof StateConflictException s)) return null;
    String key = s.objectId().orElse("ID");
    KeyState state = s.observedState().orElse(null);
    if (s.conflict() == StateConflictException.Conflict.STATE && state == KeyState.COMPROMISED)
      return "the newest key "
          + key
          + " is Compromised: replace it first with "
          + c.suggest("replace-compromised", key, "--compromised-at", "TIME")
          + ", then reconcile";
    if (s.conflict() == StateConflictException.Conflict.STATE && state != null)
      return "the newest key "
          + key
          + " is "
          + Values.token(state)
          + ", not Active: activate it ("
          + c.suggest("activate", key)
          + ") if it is Pre-Active, then reconcile";
    return "see the lineage with "
        + c.suggest("lineage", name)
        + ", and run "
        + c.suggest("reconcile", name)
        + " again for a new plan";
  }

  private static List<String> ids(List<KeyAttributes> keys) {
    return keys.stream().map(KeyAttributes::id).toList();
  }
}
