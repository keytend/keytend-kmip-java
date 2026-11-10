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

import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsException;
import dev.keytend.kmip.kms.KmsListener;
import java.io.PrintStream;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * What a running command uses: its arguments, the configuration and server group, the
 * connection (made on first use, closed at the end), output and confirmation, and what the error
 * report needs to know: the object acted on, the change made so far, and the command's own hints.
 */
final class Context {
  final Cli cli;
  final Cli.Command command;
  final Args args;
  final boolean json;
  final PrintStream out;
  final PrintStream err;

  /** The identifier of the object the command acts on, once known; null before. */
  String targetId;

  /**
   * The name of the object a command creates or registers, before the server gave it an
   * identifier; null when there is none.
   */
  String targetName;

  /** What the command changed, once it did, such as {@code "created key 12"}; null before. */
  private String done;

  /** The command's hint for a failure of the SDK, or null for the default hint. */
  private Function<KmsException, String> hints = e -> null;

  private Config config;
  private ServerGroup group;
  private Kms kms;

  /**
   * The endpoints the SDK found unavailable during the command, each with why, in order; an
   * endpoint that answered again since is dropped. The SDK's own WARN line for them is off in the
   * CLI (simplelogger.properties): a command that fails says why in its error, one that succeeds
   * prints these as warnings.
   */
  private final Map<String, String> unavailable = new LinkedHashMap<>();

  private final KmsListener endpoints =
      new KmsListener() {
        @Override
        public void endpointUnavailable(String endpoint, String why) {
          synchronized (unavailable) {
            unavailable.putIfAbsent(endpoint, why);
          }
        }

        @Override
        public void endpointAvailable(String endpoint) {
          synchronized (unavailable) {
            unavailable.remove(endpoint);
          }
        }
      };

  Context(Cli cli, Cli.Command command, Args args) {
    this.cli = cli;
    this.command = command;
    this.args = args;
    this.json = args.flag("--json");
    // Text for people is escaped as it is printed; JSON escapes the same characters itself.
    this.out = json ? cli.out : Values.terminal(cli.out);
    this.err = Values.terminal(cli.err);
  }

  Config config() {
    if (config == null) config = Config.load(cli.configPath(args.value("--config").orElse(null)));
    return config;
  }

  ServerGroup group() {
    if (group == null) {
      ServerGroup chosen = config().group(args.value("--group").orElse(null));
      Optional<Duration> timeout = args.get("--timeout", Duration.class);
      if (timeout.isPresent()) chosen = chosen.withTimeout(timeout.get());
      group = chosen;
    }
    return group;
  }

  /**
   * The server group's name, once it has been chosen.
   *
   * @return the name, or null before {@link #group()}
   */
  String groupName() {
    return group == null ? null : group.name();
  }

  /**
   * The connection to the server group, made on first use. A setting the SDK refuses while it
   * connects ({@link IllegalArgumentException}) is a configuration error.
   *
   * @return the connected {@code Kms}
   */
  Kms kms() {
    if (kms == null) {
      ServerGroup g = group();
      try {
        kms = cli.connector.connect(g, secrets(), endpoints);
      } catch (IllegalArgumentException e) {
        throw new CliException(
            ExitCode.USAGE, "server group " + g.name() + ": " + e.getMessage(), null, e);
      }
    }
    return kms;
  }

  /**
   * Runs SDK code that only takes the command line's values, such as a builder call, before
   * anything is sent: an {@link IllegalArgumentException} from it is a usage error.
   *
   * @param code the code
   * @param <T> what it returns
   * @return what it returns
   */
  static <T> T argument(Supplier<T> code) {
    try {
      return code.get();
    } catch (IllegalArgumentException e) {
      throw new CliException(ExitCode.USAGE, e.getMessage(), null, e);
    }
  }

  /**
   * The connection to the server group with {@code renewal} of its client certificate, made now;
   * closed at the end as {@link #kms()} is. A setting the SDK refuses is a configuration error.
   *
   * @param renewal the renewal setting
   * @return the connected {@code Kms}
   */
  Kms renewingKms(dev.keytend.kmip.kms.CertificateRenewal renewal) {
    if (kms != null) throw new IllegalStateException("connected already");
    ServerGroup g = group();
    try {
      kms = cli.connector.connectRenewing(g, secrets(), endpoints, renewal);
    } catch (IllegalArgumentException e) {
      throw new CliException(
          ExitCode.USAGE, "server group " + g.name() + ": " + e.getMessage(), null, e);
    }
    return kms;
  }

  Secrets secrets() {
    return new Secrets(cli.environment, cli.terminal, err);
  }

  Instant now() {
    return cli.clock.instant();
  }

  ZoneId zone() {
    return cli.zone;
  }

  /**
   * Records what the command changed, for the error report when a later step, or printing the
   * result, fails.
   *
   * @param change for example {@code "created key 12"}
   */
  void done(String change) {
    done = change;
  }

  /**
   * What the command changed.
   *
   * @return the change, or null when it changed nothing yet
   */
  String done() {
    return done;
  }

  /**
   * Sets this command's hints: for a failure of the SDK, the recovery to suggest, as commands of
   * this tool. The function returns null where the default hint applies.
   *
   * @param hints from the failure to the hint, or null
   */
  void hints(Function<KmsException, String> hints) {
    this.hints = hints;
  }

  /**
   * This command's hint for {@code e}.
   *
   * @param e the failure
   * @return the hint, or null for the default one
   */
  String hint(KmsException e) {
    return hints.apply(e);
  }

  /**
   * A command line of this tool to suggest, with this command's {@code --config} and {@code
   * --group} when they were given, and each value quoted for a POSIX shell where needed.
   *
   * @param words the command and its arguments
   * @return for example {@code keytend-kmip-cli --group prod show 12}
   */
  String suggest(String... words) {
    List<String> all = new ArrayList<>();
    all.add("keytend-kmip-cli");
    args.value("--config").ifPresent(v -> all.addAll(List.of("--config", Values.shell(v))));
    args.value("--group").ifPresent(v -> all.addAll(List.of("--group", Values.shell(v))));
    for (String w : words) all.add(Values.shell(w));
    return String.join(" ", all);
  }

  /**
   * Prints the result: {@code value} as JSON with --json, otherwise the text {@code human} prints.
   *
   * @param value the JSON value
   * @param human prints the text form
   */
  void emit(Object value, Runnable human) {
    if (json) out.println(Json.write(value));
    else human.run();
  }

  /**
   * Prints a warning: to standard error, as {@code warning: ...}; with --json the result carries
   * it instead.
   *
   * @param text the warning
   */
  void warn(String text) {
    if (!json) err.println("warning: " + text);
  }

  /**
   * Shows what a change will do and asks for {@code yes}: see {@link #confirm(List, String,
   * String)}.
   *
   * @param plan the lines that say what will be done, printed to standard error
   */
  void confirm(List<String> plan) {
    confirm(plan, "yes", "Type yes to go ahead: ");
  }

  /**
   * Shows what a change will do and asks for confirmation: with --yes it goes ahead; at a console
   * the operator types {@code token}; otherwise it refuses. The prompt is escaped as every other
   * line is ({@link Values#safe}), and so is the token: an identifier with a control or bidi
   * character is confirmed by typing the escaped form the prompt shows. The request keeps the
   * exact identifier.
   *
   * @param plan the lines that say what will be done, printed to standard error
   * @param token what the operator types to confirm: {@code yes}, an identifier or a number
   * @param prompt the question
   * @throws CliException ({@link ExitCode#NOT_CONFIRMED}) when not confirmed; nothing was changed
   */
  void confirm(List<String> plan, String token, String prompt) {
    for (String line : plan) err.println(line);
    String typed = Values.safe(token);
    if (args.flag("--yes")) return;
    if (!cli.terminal.interactive())
      throw new CliException(
          ExitCode.NOT_CONFIRMED,
          command.name() + " was not confirmed, so nothing was changed",
          "check the plan above, then repeat the command with --yes, or run it at a console to"
              + " confirm");
    if (!typed.equals(token))
      err.println("  The identifier holds control characters, shown escaped: type it as shown.");
    String answer = cli.terminal.readLine(Values.safe(prompt));
    if (answer == null || !answer.trim().equals(typed))
      throw new CliException(ExitCode.NOT_CONFIRMED, "not confirmed, so nothing was changed");
  }

  /**
   * The warnings of a command that succeeded: one for each endpoint that was unavailable and has
   * not answered since.
   *
   * @return the lines, without the {@code warning: } prefix
   */
  List<String> warnings() {
    synchronized (unavailable) {
      List<String> lines = new ArrayList<>();
      unavailable.forEach(
          (endpoint, why) ->
              lines.add(
                  "KMS endpoint "
                      + Values.safe(endpoint)
                      + " was unavailable; another endpoint served the command: "
                      + Values.safe(why)));
      return lines;
    }
  }

  void close() {
    if (kms != null) kms.close();
  }
}
