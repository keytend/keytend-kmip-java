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

import static dev.keytend.kmip.cli.Commands.Kind.FLAG;
import static dev.keytend.kmip.cli.Commands.Kind.REPEATED;
import static dev.keytend.kmip.cli.Commands.Kind.VALUE;

import dev.keytend.kmip.cli.Cli.Command;
import dev.keytend.kmip.kms.Algorithm;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.ObjectKind;
import dev.keytend.kmip.kms.RevocationReason;
import dev.keytend.kmip.kms.SecretData;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import picocli.CommandLine;
import picocli.CommandLine.Help;
import picocli.CommandLine.IHelpSectionRenderer;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Model.OptionSpec;
import picocli.CommandLine.Model.PositionalParamSpec;
import picocli.CommandLine.Model.UsageMessageSpec;

/**
 * The command table, and the picocli model built from it: the commands, their options, how each
 * option's value is converted, and the help text.
 */
final class Commands {
  private Commands() {}

  /** The tool's name, in the help. */
  static final String TOOL = "keytend-kmip-cli";

  /** How an option is used. */
  enum Kind {
    /** Present or not. */
    FLAG,
    /** Takes one value, given once. */
    VALUE,
    /** Takes one value, and may be given several times. */
    REPEATED
  }

  /**
   * Converts an option's value while the command line is parsed, with a function of {@link
   * Values}: a value it refuses is a usage error ({@link CliException}).
   */
  @FunctionalInterface
  interface Conversion {
    /**
     * Converts a value.
     *
     * @param text the value
     * @param option the option's name, for the error message
     * @param zone the zone of a local date and time
     * @return the value
     */
    Object convert(String text, String option, ZoneId zone);
  }

  /**
   * One option.
   *
   * @param names its names; the first, the long one, is the one messages use
   * @param kind how it is used
   * @param conversion how its value is converted, or null for text
   * @param label its value in the help, such as {@code NAME}; null for a flag
   * @param help what it does, in one sentence for the help
   */
  record Option(List<String> names, Kind kind, Conversion conversion, String label, String help) {
    String name() {
      return names.get(0);
    }
  }

  static final Conversion DURATION = (text, option, zone) -> Values.duration(text, option);
  static final Conversion DATE_TIME = (text, option, zone) -> Values.dateTime(text, zone, option);
  static final Conversion NUMBER = (text, option, zone) -> Values.number(text, option);
  static final Conversion USAGES = (text, option, zone) -> Render.usageOption(text);

  static <E extends Enum<E>> Conversion constant(Class<E> type) {
    return (text, option, zone) -> Values.constant(type, text, option);
  }

  static Option flag(String name, String help) {
    return new Option(List.of(name), FLAG, null, null, help);
  }

  static Option value(String name, String label, String help) {
    return new Option(List.of(name), VALUE, null, label, help);
  }

  static Option value(String name, String label, Conversion conversion, String help) {
    return new Option(List.of(name), VALUE, conversion, label, help);
  }

  static Option repeated(String name, String label, String help) {
    return new Option(List.of(name), REPEATED, null, label, help);
  }

  /** The options every command takes, before or after its name. */
  static final List<Option> GLOBAL =
      List.of(
          new Option(
              List.of("--config", "-c"),
              VALUE,
              null,
              "FILE",
              "The configuration file; else $KEYTEND_KMIP_CLI_CONFIG, else"
                  + " ~/.config/keytend-kmip/cli.properties."),
          new Option(
              List.of("--group", "-g"),
              VALUE,
              null,
              "NAME",
              "The server group; else the file's default-group."),
          new Option(
              List.of("--json"), FLAG, null, null, "Print one JSON object on standard output."),
          new Option(
              List.of("--yes", "-y"),
              FLAG,
              null,
              null,
              "Go ahead after showing the plan, without asking."),
          new Option(
              List.of("--timeout"),
              VALUE,
              DURATION,
              "DURATION",
              "The call timeout for this command, such as 30s; else the group's."),
          new Option(List.of("--help", "-h"), FLAG, null, null, "Show this help."));

  /** The option that prints the version: alone, without a command. */
  static final String VERSION = "--version";

  static final List<Command> ALL =
      List.of(
          new Command(
              "servers",
              List.of("groups"),
              "servers [NAME]",
              "List the configured server groups. Passwords are never shown, only where each is"
                  + " read from.",
              "Sends nothing to any server. With --json, a setting left to its default is null.",
              List.of(),
              ServerCommands::servers),
          new Command(
              "info",
              List.of("ping"),
              "info",
              "Connect and show the negotiated KMIP version and the server's Discover Versions and"
                  + " Query answers.",
              "Fails with exit code 8 when no endpoint can be reached. A server that does not"
                  + " answer Discover Versions "
                  + "or Query is reported, not treated as a failure.",
              List.of(),
              ServerCommands::info),
          new Command(
              "list",
              List.of("ls"),
              "list [--name NAME] [--state STATE] [--kind KIND] [--algorithm ALG] [--object-group"
                  + " GROUP] [--custom NAME=VALUE]...",
              "List objects with their names, state, algorithm and dates. Also a connectivity"
                  + " check.",
              "STATE: pre-active, active, deactivated, compromised, destroyed,"
                  + " destroyed-compromised.\n"
                  + "KIND: symmetric-key, secret-data, private-key, public-key, certificate, ...\n"
                  + "--custom matches a custom attribute: x-NAME (client), y-NAME (server) or"
                  + " VENDOR:NAME; a bare NAME means x-NAME.",
              List.of(
                  value("--name", "NAME", "Only objects with this name."),
                  value(
                      "--state", "STATE", constant(KeyState.class), "Only objects in this state."),
                  value("--kind", "KIND", constant(ObjectKind.class), "Only objects of this kind."),
                  value(
                      "--algorithm",
                      "ALG",
                      constant(Algorithm.class),
                      "Only keys of this algorithm, such as aes or hmac-sha256."),
                  value("--object-group", "GROUP", "Only objects in this object group."),
                  repeated(
                      "--custom",
                      "NAME=VALUE",
                      "Only objects with this custom attribute value; repeat it for more.")),
              KeyCommands::list),
          new Command(
              "show",
              List.of(),
              "show ID [--no-lineage]",
              "Show the attributes of one object and, for a key, its rotation lineage.",
              "Shown: kind, state, names, cipher, usages, object groups, custom attributes, every"
                  + " lifecycle date, "
                  + "the Lease Time, links, and the extractable and sensitive flags; with --json also"
                  + " the raw protocol codes.\n"
                  + "A lineage that cannot be read is reported, and the attributes are still shown.",
              List.of(
                  flag(
                      "--no-lineage",
                      "Do not read the key's rotation lineage (one more read per key of it).")),
              KeyCommands::show),
          new Command(
              "lineage",
              List.of(),
              "lineage NAME | lineage --id ID",
              "Show the rotation lineage of a key, newest first.",
              "By NAME it starts from the key the name leads to (Active first); --id starts from"
                  + " that key.\n"
                  + "BRANCH marks a key another caller's rotation left beside the main line; JOINED"
                  + " INTO names the key "
                  + "reconcile joined it into.",
              List.of(value("--id", "ID", "Start from this key instead of a name.")),
              KeyCommands::lineage),
          new Command(
              "create",
              List.of(),
              "create --name NAME [--algorithm AES] [--bits 256] [--usage encrypt,decrypt]"
                  + " [--if-absent | --pre-active] [--allow-duplicate-name] [--object-group"
                  + " GROUP]... [--custom NAME=VALUE]...",
              "Create a symmetric key and print its identifier. It is Active unless --pre-active.",
              "--if-absent returns the Active key with the name when there is one. Otherwise it"
                  + " activates a Pre-Active "
                  + "key with the name, after showing that plan and a confirmation (--yes), or"
                  + " creates a key. It refuses "
                  + "a name whose keys are only Deactivated or Compromised (exit 6).\n"
                  + "Without it, a name that an object not destroyed has already is refused (exit 6);"
                  + " --allow-duplicate-name "
                  + "makes another key with the name anyway.\n"
                  + "--usage defaults to encrypt,decrypt.",
              List.of(
                  value("--name", "NAME", "The key's name; needed with --if-absent."),
                  value(
                      "--algorithm",
                      "ALG",
                      constant(Algorithm.class),
                      "The algorithm: aes (default) or another symmetric one, such as hmac-sha256."),
                  value("--bits", "BITS", NUMBER, "The key's length in bits; 256 by default."),
                  value(
                      "--usage",
                      "USAGES",
                      USAGES,
                      "Comma-separated usages, such as encrypt,decrypt (the default) or"
                          + " wrap-key,unwrap-key."),
                  flag(
                      "--if-absent",
                      "Return the Active key with the name if there is one; create it otherwise."),
                  flag("--pre-active", "Leave the new key Pre-Active: activate it later."),
                  flag(
                      "--allow-duplicate-name",
                      "Create the key even when an object not destroyed has the name."),
                  repeated(
                      "--object-group", "GROUP", "Put the key in this object group; repeatable."),
                  repeated(
                      "--custom",
                      "NAME=VALUE",
                      "Give the key this custom attribute (x-NAME by default); repeatable.")),
              KeyCommands::create),
          new Command(
              "activate",
              List.of(),
              "activate ID",
              "Activate a Pre-Active object: it encrypts from now on.",
              "Shows its plan and needs --yes or a confirmation. An Active object is reported,"
                  + " with nothing changed.",
              List.of(),
              LifecycleCommands::activate),
          new Command(
              "rotate",
              List.of(),
              "rotate NAME [--if-active-for DURATION] [--grace DURATION] [--shifted-dates]",
              "Rotate the key the name leads to: a new Active key, linked to it, takes the name.",
              "The old key stays Active (it still encrypts and decrypts) unless --grace schedules"
                  + " its deactivation that long after the rotation.\n"
                  + "--grace changes the old key, so it shows its plan and needs --yes or a"
                  + " confirmation; --grace 0s deactivates it at once.\n"
                  + "--if-active-for rotates only a key that has been Active that long. The current"
                  + " key is resolved when the command runs, so a successor another caller made is"
                  + " checked too, and rotated if it is due (0s always is). Action followed means a"
                  + " rotation landed between the check and the Re-key; with --grace that is"
                  + " refused (exit 6).\n"
                  + "--shifted-dates moves the old key's server-set dates forward for the new key.",
              List.of(
                  value(
                      "--if-active-for",
                      "DURATION",
                      DURATION,
                      "Rotate only if the current key has been Active this long, such as 90d."),
                  value(
                      "--grace",
                      "DURATION",
                      DURATION,
                      "Deactivate the old key this long after the rotation; 0s deactivates it"
                          + " at once."),
                  flag(
                      "--shifted-dates",
                      "Move the old key's server-set dates forward for the new key.")),
              KeyCommands::rotate),
          new Command(
              "expire",
              List.of(),
              "expire ID [--at DATETIME] [--reason REASON] [--message TEXT]",
              "Stop a key from encrypting, now or at a date, while it still decrypts where the"
                  + " server allows.",
              "Without --at the key is deactivated now. With --at its Deactivation Date is set, and"
                  + " the server deactivates it then;\n"
                  + "an earlier date the key has by then is kept. Change a key's lifecycle from one"
                  + " place at a time.\n"
                  + "DATETIME: ISO-8601, such as 2026-12-01T00:00:00Z, or a local '2026-12-01"
                  + " 00:00:00'.\n"
                  + "REASON (recorded up to KMIP 2.1): unspecified (default), superseded,"
                  + " cessation-of-operation, affiliation-changed, privilege-withdrawn.\n"
                  + "--message is refused with --at and on KMIP 3.0, which record no message.",
              List.of(
                  value(
                      "--at",
                      "DATETIME",
                      DATE_TIME,
                      "Set the Deactivation Date instead of deactivating now."),
                  value(
                      "--reason",
                      "REASON",
                      constant(RevocationReason.Kind.class),
                      "Why, recorded up to KMIP 2.1; unspecified by default."),
                  value("--message", "TEXT", "A message recorded with the reason.")),
              LifecycleCommands::expire),
          new Command(
              "revoke",
              List.of(),
              "revoke ID --reason REASON [--message TEXT] [--compromised-at DATETIME]",
              "Revoke a key. A compromise reason makes it Compromised; any other reason deactivates"
                  + " it.",
              "REASON: key-compromise, ca-compromise (both need --compromised-at), superseded,"
                  + " cessation-of-operation, affiliation-changed, privilege-withdrawn,"
                  + " unspecified.\n"
                  + "--message is refused on KMIP 3.0 for a reason that is not a compromise.\n"
                  + "A Compromised key cannot be deactivated, and a Pre-Active one only destroyed or"
                  + " activated (exit 6).\n"
                  + "To replace the compromised key a name leads to, see replace-compromised. For an"
                  + " older key of the lineage, revoke with key-compromise; the name already leads"
                  + " to a newer key. If that key is compromised too, replace it with"
                  + " replace-compromised.",
              List.of(
                  value(
                      "--reason",
                      "REASON",
                      constant(RevocationReason.Kind.class),
                      "Why the key is revoked; needed."),
                  value("--message", "TEXT", "A message recorded with the reason."),
                  value(
                      "--compromised-at",
                      "DATETIME",
                      DATE_TIME,
                      "When the compromise happened; needed with a compromise reason.")),
              LifecycleCommands::revoke),
          new Command(
              "replace-compromised",
              List.of(),
              "replace-compromised ID --compromised-at DATETIME [--message TEXT] [--shifted-dates |"
                  + " --copied-dates]",
              "Revoke a key as compromised and create an Active replacement that takes its names.",
              "Use it for the key a name leads to. It refuses a key that a rotation replaced"
                  + " already: revoke that one with --reason key-compromise instead. For a key that"
                  + " is Compromised already and was replaced, it finishes with that replacement and"
                  + " creates nothing; when that replacement is Compromised too, it replaces it as"
                  + " well, creating one key that takes both keys' names. It refuses while a key an"
                  + " earlier attempt created is not linked, naming it, and the plan says when the"
                  + " server cannot be searched for one (on PyKMIP, always): then look"
                  + " in list --kind symmetric-key --state pre-active. When the search finds a key"
                  + " this client cannot read, the plan names it. In a forked lineage it acts"
                  + " on one newest"
                  + " key and leaves the others for reconcile. The plan names every key it acts on,"
                  + " and nothing changes if another caller changes them first. After a lost reply"
                  + " it goes on only with a key it can tell is its own, and otherwise stops. Then"
                  + " re-encrypt the data under the replacement before you destroy the compromised"
                  + " keys.\n"
                  + "--shifted-dates keeps the key's cryptoperiod from now; --copied-dates copies its"
                  + " dates, or makes a key "
                  + "without dates when its Deactivation Date has passed. Without either, the SDK"
                  + " chooses.",
              List.of(
                  value(
                      "--compromised-at",
                      "DATETIME",
                      DATE_TIME,
                      "When the compromise happened; needed."),
                  value("--message", "TEXT", "A message recorded with the compromise."),
                  flag("--shifted-dates", "Give the replacement the key's cryptoperiod from now."),
                  flag(
                      "--copied-dates",
                      "Copy the key's dates, or make a key without dates when they have passed.")),
              LifecycleCommands::replaceCompromised),
          new Command(
              "destroy",
              List.of(),
              "destroy ID",
              "Destroy a key's material. Nothing it protected can be decrypted afterwards, backups"
                  + " included.",
              "Refuses an Active key: expire or revoke it first, and re-encrypt its data. At the"
                  + " console it asks for the "
                  + "identifier to be typed.",
              List.of(),
              LifecycleCommands::destroy),
          new Command(
              "deactivate-predecessors",
              List.of(),
              "deactivate-predecessors ID [--reason REASON] [--message TEXT]",
              "Deactivate the older Active keys of a lineage, from its newest key ID. Nothing is"
                  + " destroyed.",
              "The step after a rotation's grace period, where the server would not schedule it."
                  + " REASON defaults "
                  + "to superseded; --message is refused on KMIP 3.0. Only the keys the plan lists are"
                  + " deactivated:\n"
                  + "when another is Active by then, nothing is.",
              List.of(
                  value(
                      "--reason",
                      "REASON",
                      constant(RevocationReason.Kind.class),
                      "Why, recorded up to KMIP 2.1; superseded by default."),
                  value("--message", "TEXT", "A message recorded with the reason.")),
              LifecycleCommands::deactivatePredecessors),
          new Command(
              "retire-predecessors",
              List.of(),
              "retire-predecessors ID [--keep-from KEEP_ID] [--message TEXT]",
              "Deactivate and destroy the older keys of a lineage, from its newest key ID.",
              "The plan lists exactly the keys that will be destroyed; at the console you type"
                  + " their number. When the "
                  + "lineage differs from the plan before the first change, nothing is destroyed.\n"
                  + "--keep-from keeps that key and every newer one, and retires only the keys before"
                  + " it.\n"
                  + "--message is refused on KMIP 3.0, where keys are deactivated without one.",
              List.of(
                  value(
                      "--keep-from",
                      "KEEP_ID",
                      "Keep this key and every newer one; retire only the keys before it."),
                  value("--message", "TEXT", "A message recorded with the deactivations.")),
              LifecycleCommands::retirePredecessors),
          new Command(
              "reconcile",
              List.of(),
              "reconcile NAME",
              "Join the newest keys of a name's lineage into one, after callers rotated it at the"
                  + " same time.",
              "The other newest keys are joined into the one kept, the lineage's names move to it,"
                  + " and the other Active "
                  + "keys are deactivated. Nothing is destroyed. Shows its plan and needs --yes or a"
                  + " confirmation;\n"
                  + "when the name or its lineage differs from the plan by then, nothing is changed.",
              List.of(),
              LifecycleCommands::reconcile),
          new Command(
              "register-secret",
              List.of(),
              "register-secret --name NAME (--value-file FILE | --value-env VARIABLE |"
                  + " --value-prompt) [--type password|seed] [--replace OLD_ID |"
                  + " --allow-duplicate-name]",
              "Register a password or seed as Secret Data and print its identifier.",
              "The value is never a command-line argument. A password file's final line break is"
                  + " dropped; a seed file is read as it is.\n"
                  + "A name that an object not destroyed has already is refused (exit 6): --replace"
                  + " moves the name from OLD_ID to the new secret and deactivates OLD_ID if it is"
                  + " Active; --allow-duplicate-name registers another secret with the name. After"
                  + " a lost reply, --replace goes on only with the secret it can tell it"
                  + " registered, and otherwise stops (exit 3), naming any object it found under"
                  + " the temporary name.",
              List.of(
                  value("--name", "NAME", "The secret's name; needed."),
                  value("--value-file", "FILE", "Read the value from this file."),
                  value(
                      "--value-env", "VARIABLE", "Read the value from this environment variable."),
                  flag("--value-prompt", "Ask for the value at the console, twice for a password."),
                  value(
                      "--type",
                      "TYPE",
                      constant(SecretData.Type.class),
                      "password (default) or seed."),
                  value(
                      "--replace",
                      "OLD_ID",
                      "Move the name from this secret to the new one, and deactivate it if it is"
                          + " Active."),
                  flag(
                      "--allow-duplicate-name",
                      "Register the secret even when an object not destroyed has the name.")),
              SecretCommands::register),
          new Command(
              "get-secret",
              List.of(),
              "get-secret ID (--out FILE | --stdout)",
              "Write a secret's value to a new file, or to standard output.",
              "It refuses a file that exists, a symbolic link included. On a POSIX file system the"
                  + " file is created "
                  + "readable only by its owner (mode 0600). Elsewhere it gets the permissions of its"
                  + " directory: write it "
                  + "to a directory only you can read.",
              List.of(
                  value("--out", "FILE", "Write the value to this new file."),
                  flag("--stdout", "Write the raw value to standard output (not with --json).")),
              SecretCommands::get),
          new Command(
              "renew-certificate",
              List.of(),
              "renew-certificate [--valid-for DURATION] [--shared-store]",
              "Renew the group's own client certificate with KMIP Re-Provision, and replace its"
                  + " identity files.",
              "Needs a server that offers Re-Provision (keytend-kmip-server with a provisioning CA)"
                  + " and KMIP 2.0 or later. The new private key is written beside the key file"
                  + " (FILE.renewal) before anything is sent. The server refuses the old"
                  + " certificate on new connections once it issues the new one: then add the new"
                  + " fingerprint to its policy under the same name. Exit code 3 means the client"
                  + " may be locked out: follow the message.",
              List.of(
                  value(
                      "--valid-for",
                      "DURATION",
                      DURATION,
                      "Ask for this validity, such as 90d (keytend-kmip-server takes it;"
                          + " a server that does not take it refuses the renewal, and the"
                          + " current certificate stays)."),
                  flag(
                      "--shared-store",
                      "State that the group's endpoints share one store; needed with several.")),
              ServerCommands::renewCertificate));

  static Command find(String name) {
    for (Command c : ALL) if (c.name().equals(name) || c.aliases().contains(name)) return c;
    return null;
  }

  private static final String TOOL_SYNOPSIS =
      TOOL + " [--config FILE] [--group NAME] [--json] [--yes] [--timeout DURATION] COMMAND ...";

  private static final String TOOL_DESCRIPTION = "Manage keys on a KMIP server. Commands:";

  private static final String TOOL_FOOTER =
      """
      Run keytend-kmip-cli COMMAND --help for a command's options. activate, expire, revoke,
      replace-compromised, destroy, deactivate-predecessors and retire-predecessors act on identifiers.
      They, reconcile, rotate --grace, create --if-absent on a Pre-Active key and register-secret
      --replace show what they will do, and need --yes or a confirmation at the console.
      Exit codes: 0 done, 1 failed, 2 usage or configuration, 3 outcome unknown, 4 not found,
      5 permission denied, 6 state conflict, 7 partly done, 8 server unavailable, 9 not confirmed.""";

  /** The help section that names a command's aliases. */
  private static final String SECTION_ALIASES = "aliases";

  /** The help section that lists a command's own options. */
  private static final String SECTION_OPTIONS = "options";

  /** The help section that lists the global options. */
  private static final String SECTION_GLOBAL_OPTIONS = "globalOptions";

  /** The width the help is wrapped at. */
  static final int WIDTH = 100;

  /**
   * The picocli model of the tool: the global options and {@value #VERSION}, and a subcommand for
   * each command with its own options, the global options again (they may follow the command) and
   * its arguments. A new one for each command line, because picocli keeps the parsed values in it.
   *
   * <p>The parser is set up to keep the tool's syntax: no {@code @file} expansion, no clustered
   * short options, an option's value may look like an option ({@code --message --json}), unknown
   * options are collected and reported by {@link Cli} (so the messages never repeat a value), and
   * errors are collected rather than thrown, so that {@code --json} is still known for a command
   * line that does not parse. The help is plain text, without ANSI colors.
   *
   * @param zone the zone of a local date and time in an option's value
   * @return the command line parser
   */
  static CommandLine commandLine(ZoneId zone) {
    CommandSpec tool = CommandSpec.create().name(TOOL);
    for (Option o : GLOBAL) tool.addOption(spec(o, zone));
    tool.addOption(
        OptionSpec.builder(VERSION).arity("0").type(boolean.class).versionHelp(true).build());
    help(tool.usageMessage(), List.of(TOOL_SYNOPSIS), TOOL_DESCRIPTION, TOOL_FOOTER, true);
    for (Command c : ALL) {
      CommandSpec command = CommandSpec.create().name(c.name());
      command.aliases(c.aliases().toArray(String[]::new));
      for (Option o : c.options()) command.addOption(spec(o, zone));
      for (Option o : GLOBAL) command.addOption(spec(o, zone));
      command.addPositional(
          PositionalParamSpec.builder()
              .arity("0..*")
              .type(List.class)
              .auxiliaryTypes(String.class)
              .paramLabel("ARGUMENT")
              .build());
      help(
          command.usageMessage(),
          List.of(TOOL + " " + c.synopsis()),
          c.summary(),
          c.details(),
          false);
      tool.addSubcommand(c.name(), command);
    }
    CommandLine line = new CommandLine(tool);
    line.setExpandAtFiles(false);
    line.setPosixClusteredShortOptionsAllowed(false);
    line.setAbbreviatedOptionsAllowed(false);
    line.setAllowOptionsAsOptionParameters(true);
    line.setUnmatchedOptionsAllowedAsOptionParameters(true);
    line.setUnmatchedArgumentsAllowed(true);
    line.setUnmatchedOptionsArePositionalParams(false);
    line.setOverwrittenOptionsAllowed(false);
    line.setStopAtPositional(false);
    line.setStopAtUnmatched(false);
    line.setToggleBooleanFlags(false);
    line.setTrimQuotes(false);
    line.setEndOfOptionsDelimiter("--");
    line.setInterpolateVariables(false);
    line.setColorScheme(Help.defaultColorScheme(Help.Ansi.OFF));
    tool.parser().collectErrors(true);
    for (CommandLine command : line.getSubcommands().values())
      command.getCommandSpec().parser().collectErrors(true);
    return line;
  }

  private static OptionSpec spec(Option o, ZoneId zone) {
    OptionSpec.Builder b = OptionSpec.builder(o.names().toArray(String[]::new));
    Class<?> type = o.conversion() == null ? String.class : Object.class;
    switch (o.kind()) {
      case FLAG -> b.arity("0").type(boolean.class);
      case VALUE -> b.arity("1").type(type);
      case REPEATED -> b.arity("1").type(List.class).auxiliaryTypes(type);
    }
    if (o.conversion() != null) b.converters(text -> o.conversion().convert(text, o.name(), zone));
    if (o.name().equals("--help")) b.usageHelp(true);
    return b.build();
  }

  /**
   * Sets the help: a synopsis, a description, the details or the tool's notes, and for a command
   * its aliases and the global options. The text is printed as it is, with its own line breaks.
   */
  private static void help(
      UsageMessageSpec usage,
      List<String> synopsis,
      String description,
      String footer,
      boolean tool) {
    usage.customSynopsis(synopsis.toArray(String[]::new));
    usage.description(description);
    usage.footer(footer.isEmpty() ? new String[0] : footer.split("\n", -1));
    Map<String, IHelpSectionRenderer> sections = new LinkedHashMap<>();
    sections.put(
        UsageMessageSpec.SECTION_KEY_SYNOPSIS,
        h -> wrap("usage: " + h.commandSpec().usageMessage().customSynopsis()[0], "    "));
    sections.put(
        UsageMessageSpec.SECTION_KEY_DESCRIPTION,
        h -> "\n" + wrap(h.commandSpec().usageMessage().description()[0], ""));
    if (tool) sections.put(UsageMessageSpec.SECTION_KEY_COMMAND_LIST, Commands::commandList);
    sections.put(
        UsageMessageSpec.SECTION_KEY_FOOTER,
        h -> paragraph(h.commandSpec().usageMessage().footer(), tool));
    if (!tool) {
      sections.put(
          SECTION_ALIASES,
          h -> {
            String[] aliases = h.commandSpec().aliases();
            return aliases.length == 0 ? "" : "\nalso: " + String.join(", ", aliases) + "\n";
          });
      sections.put(
          SECTION_OPTIONS,
          h -> {
            Command c = find(h.commandSpec().name());
            return c == null || c.options().isEmpty()
                ? ""
                : "\noptions:\n" + optionList(c.options());
          });
      sections.put(SECTION_GLOBAL_OPTIONS, h -> "\nglobal options:\n" + optionList(GLOBAL));
    }
    usage.sectionKeys(List.copyOf(sections.keySet()));
    usage.sectionMap(sections);
  }

  /** The commands, each with the first sentence of its summary. */
  private static String commandList(Help help) {
    List<CommandSpec> commands =
        help.subcommands().values().stream().map(Help::commandSpec).toList();
    int width = commands.stream().mapToInt(c -> c.name().length()).max().orElse(0);
    StringBuilder b = new StringBuilder();
    for (CommandSpec c : commands) {
      String summary = c.usageMessage().description()[0];
      int stop = summary.indexOf(". ");
      if (stop > 0) summary = summary.substring(0, stop + 1);
      String head = "  " + c.name() + " ".repeat(width - c.name().length() + 2);
      b.append(wrap(head + summary, " ".repeat(head.length())));
    }
    return b.toString();
  }

  /** Options, one per entry: names and value, then the description, wrapped. */
  private static String optionList(List<Option> options) {
    List<String> heads = new ArrayList<>();
    for (Option o : options) {
      String names =
          o.names().size() > 1
              ? o.names().get(1) + ", " + o.name()
              : o.name().length() > 2 ? "    " + o.name() : o.name();
      heads.add("  " + names + (o.label() == null ? "" : " " + o.label()));
    }
    int width = Math.min(34, heads.stream().mapToInt(String::length).max().orElse(0) + 2);
    StringBuilder b = new StringBuilder();
    for (int i = 0; i < options.size(); i++) {
      String head = heads.get(i);
      String indent = " ".repeat(width);
      b.append(
          head.length() + 2 > width
              ? head + "\n" + wrap(indent + options.get(i).help(), indent)
              : wrap(head + " ".repeat(width - head.length()) + options.get(i).help(), indent));
    }
    return b.toString();
  }

  /**
   * {@code text} wrapped at {@link #WIDTH} columns at spaces, each line after the first starting
   * with {@code indent}; ends with a line break.
   */
  static String wrap(String text, String indent) {
    StringBuilder b = new StringBuilder();
    String line = text;
    while (line.length() > WIDTH) {
      int cut = cut(line, indent.length());
      if (cut < 0) break;
      b.append(line, 0, cut).append('\n');
      line = indent + line.substring(cut + 1).stripLeading();
    }
    return b.append(line).append('\n').toString();
  }

  /**
   * Where to break {@code line}: the last space within {@link #WIDTH} that is outside {@code [...]}
   * and {@code (...)} and not before a lone {@code ...}, so a synopsis's option groups stay whole,
   * when that leaves at least half a line; otherwise the last space within the width past {@code
   * from}, else the first one after it; -1 when there is none.
   */
  private static int cut(String line, int from) {
    int best = -1, depth = 0;
    for (int i = 0; i <= WIDTH && i < line.length(); i++) {
      char c = line.charAt(i);
      if (c == '[' || c == '(') depth++;
      else if ((c == ']' || c == ')') && depth > 0) depth--;
      else if (c == ' ' && depth == 0 && !line.startsWith("...", i + 1)) best = i;
    }
    if (best > from + WIDTH / 2) return best;
    int cut = line.lastIndexOf(' ', WIDTH);
    return cut <= from ? line.indexOf(' ', WIDTH) : cut;
  }

  /** Lines, each ended with a line break. */
  private static String lines(String[] lines) {
    StringBuilder b = new StringBuilder();
    for (String line : lines) b.append(line).append('\n');
    return b.toString();
  }

  /**
   * Lines after an empty line, each wrapped at {@link #WIDTH} (a command's details; the tool's
   * notes are wrapped by hand already); nothing when there are none.
   */
  private static String paragraph(String[] lines, boolean asIs) {
    if (lines.length == 0) return "";
    if (asIs) return "\n" + lines(lines);
    StringBuilder b = new StringBuilder("\n");
    for (String line : lines) b.append(wrap(line, ""));
    return b.toString();
  }
}
