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

import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyMismatchException;
import dev.keytend.kmip.kms.KmsException;
import dev.keytend.kmip.kms.NotFoundException;
import dev.keytend.kmip.kms.OutcomeUnknownException;
import dev.keytend.kmip.kms.PartialCompletionException;
import dev.keytend.kmip.kms.PermissionDeniedException;
import dev.keytend.kmip.kms.StateConflictException;
import dev.keytend.kmip.kms.TransientException;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Clock;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import picocli.CommandLine;
import picocli.CommandLine.MaxValuesExceededException;
import picocli.CommandLine.MissingParameterException;
import picocli.CommandLine.Model.ArgSpec;
import picocli.CommandLine.Model.OptionSpec;
import picocli.CommandLine.OverwrittenOptionException;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.ParseResult;

/**
 * Runs one command line: parses it with picocli ({@link #parse}), runs the command, checks that its
 * output was written, and maps every failure to a message, a hint and an {@link ExitCode}. JSON
 * mode comes from the parsed options, also for a command line with a mistake.
 */
final class Cli {
  /** The environment variable that names the configuration file when --config is not given. */
  static final String CONFIG_VARIABLE = "KEYTEND_KMIP_CLI_CONFIG";

  final PrintStream out;
  final PrintStream err;
  final Terminal terminal;
  final Map<String, String> environment;
  final Clock clock;
  final ZoneId zone;
  final Connector connector;

  Cli(
      PrintStream out,
      PrintStream err,
      Terminal terminal,
      Map<String, String> environment,
      Clock clock,
      ZoneId zone,
      Connector connector) {
    this.out = out;
    this.err = err;
    this.terminal = terminal;
    this.environment = Map.copyOf(environment);
    this.clock = clock;
    this.zone = zone;
    this.connector = connector;
  }

  /**
   * The tool as the process runs it: standard output and error in UTF-8, the console, the
   * process environment, the system clock and time zone, and real TLS connections.
   *
   * @return the tool
   */
  static Cli system() {
    return new Cli(
        new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8),
        new PrintStream(new FileOutputStream(FileDescriptor.err), true, StandardCharsets.UTF_8),
        Terminal.system(),
        System.getenv(),
        Clock.systemUTC(),
        ZoneId.systemDefault(),
        Connector.tls());
  }

  /**
   * The configuration file: {@code --config}, else {@value #CONFIG_VARIABLE}, else {@code
   * ~/.config/keytend-kmip/cli.properties}.
   *
   * @param option the --config option, or null
   * @return the path
   */
  Path configPath(String option) {
    if (option != null) return Path.of(option);
    String variable = environment.get(CONFIG_VARIABLE);
    if (variable != null && !variable.isEmpty()) return Path.of(variable);
    String home = environment.getOrDefault("HOME", System.getProperty("user.home"));
    return Path.of(home, ".config", "keytend-kmip", "cli.properties");
  }

  /**
   * Runs a command line.
   *
   * @param argv the arguments
   * @return the exit code
   */
  int run(String[] argv) {
    boolean json = false;
    Context context = null;
    try {
      Line line = parse(argv);
      json = line.json();
      if (line.error() != null) throw line.error();
      if (line.command() == null) {
        if (line.version()) {
          out.println(
              json ? Json.write(Map.of("version", version())) : "keytend-kmip-cli " + version());
          return finish(null, ExitCode.OK);
        }
        out.print(line.parser().getUsageMessage());
        return finish(null, line.help() ? ExitCode.OK : ExitCode.USAGE);
      }
      if (line.help()) {
        out.print(line.parser().getSubcommands().get(line.command().name()).getUsageMessage());
        return finish(null, ExitCode.OK);
      }
      context = new Context(this, line.command(), line.args());
      line.command().runner().run(context);
      for (String warning : context.warnings()) context.err.println("warning: " + warning);
      return finish(context, ExitCode.OK);
    } catch (RuntimeException e) {
      Failure failure = Failure.of(e, context);
      report(failure, json);
      return failure.exit().code;
    } finally {
      if (context != null) context.close();
    }
  }

  /**
   * A command line as parsed.
   *
   * @param parser the parser, which prints the help
   * @param command the command, or null when none was given
   * @param args the command's arguments, or null without a command
   * @param json whether {@code --json} was given as an option, also on a line with a mistake
   * @param help whether {@code --help} was given
   * @param version whether {@code --version} was given
   * @param error the command line's mistake, or null
   */
  record Line(
      CommandLine parser,
      Command command,
      Args args,
      boolean json,
      boolean help,
      boolean version,
      CliException error) {}

  /**
   * Parses a command line with picocli ({@link Commands#commandLine}). Its mistakes are usage
   * errors whose messages name an option but never repeat a value: an unknown command, then an
   * unknown option, a missing or unwanted value, an option given twice, and last a value its
   * conversion refuses, which {@code --help} overrides. An argument that starts with {@code -}
   * before {@code --} is an unknown option, as {@code -5} is. {@code --version} without a command
   * prints the version whatever else is on the line.
   *
   * @param argv the arguments
   * @return the parsed line
   */
  Line parse(String... argv) {
    CommandLine parser = Commands.commandLine(zone);
    ParseResult tool;
    try {
      tool = parser.parseArgs(argv);
    } catch (ParameterException e) {
      return new Line(
          parser,
          null,
          null,
          false,
          false,
          false,
          CliException.usage("cannot read the command line"));
    }
    ParseResult sub = tool.subcommand();
    Command command = sub == null ? null : Commands.find(sub.commandSpec().name());
    List<ParseResult> results = sub == null ? List.of(tool) : List.of(tool, sub);
    boolean json = results.stream().anyMatch(r -> r.hasMatchedOption("--json"));
    boolean help = results.stream().anyMatch(ParseResult::isUsageHelpRequested);
    boolean version = tool.isVersionHelpRequested();
    List<String> positionals =
        sub == null
            ? List.of()
            : sub.commandSpec().positionalParameters().get(0).originalStringValues();
    CliException error = unknownCommand(tool.unmatched());
    int end = Arrays.asList(argv).indexOf("--");
    if (sub == null && end >= 0 && end + 1 < argv.length) {
      // -- before the command's name: the next word is the command's name, and -- ends its
      // options. picocli leaves the words after -- unmatched here, after the ones before it.
      List<String> unmatched = tool.unmatched();
      int after = argv.length - end - 1;
      if (unknownCommand(unmatched.subList(0, Math.max(0, unmatched.size() - after))) == null) {
        String word = argv[end + 1];
        if (Commands.find(word) == null)
          return new Line(parser, null, null, json, help, version, unknownCommand(word));
        List<String> moved = new ArrayList<>(Arrays.asList(argv));
        moved.remove(end + 1);
        moved.add(end, word);
        return parse(moved.toArray(String[]::new));
      }
    }
    if (error == null && command == null && version)
      return new Line(parser, null, null, json, help, true, null);
    if (error == null) error = mistake(argv, results, positionals);
    if (error == null && command != null && !help) error = refusedValue(results);
    Args args = command == null ? null : Args.of(positionals, results);
    return new Line(parser, command, args, json, help, version, error);
  }

  /**
   * The first word where the command's name should be, when it is not a command; null when an
   * unknown option comes first ({@code -yg x list}), which is the mistake to name.
   */
  private static CliException unknownCommand(List<String> unmatched) {
    if (unmatched.isEmpty()) return null;
    String word = unmatched.get(0);
    return !word.startsWith("-") || word.equals("-") ? unknownCommand(word) : null;
  }

  private static CliException unknownCommand(String word) {
    return new CliException(
        ExitCode.USAGE, "unknown command " + word, "run keytend-kmip-cli --help for the commands");
  }

  private static CliException mistake(
      String[] argv, List<ParseResult> results, List<String> positionals) {
    for (ParseResult r : results)
      for (String option : r.unmatched())
        return CliException.usage("unknown option " + name(option));
    ParseResult tool = results.get(0);
    if (results.size() > 1 && tool.isVersionHelpRequested())
      return CliException.usage("unknown option " + Commands.VERSION);
    // picocli takes an argument that reads as a number, such as -5, for a positional argument.
    int end = Arrays.asList(argv).indexOf("--");
    int afterEnd = end < 0 ? 0 : argv.length - end - 1;
    for (int i = 0; i < positionals.size() - afterEnd; i++) {
      String p = positionals.get(i);
      if (p.length() > 1 && p.startsWith("-"))
        return CliException.usage("unknown option " + name(p));
    }
    for (ParseResult r : results)
      for (Exception e : r.errors())
        if (!(e.getCause() instanceof CliException))
          return CliException.usage(describe(e, argv, results));
    if (results.size() > 1)
      for (Commands.Option o : Commands.GLOBAL)
        if (tool.hasMatchedOption(o.name()) && results.get(1).hasMatchedOption(o.name()))
          return CliException.usage(o.name() + " was given more than once");
    return null;
  }

  /** The first value an option's conversion refused. */
  private static CliException refusedValue(List<ParseResult> results) {
    for (ParseResult r : results)
      for (Exception e : r.errors()) if (e.getCause() instanceof CliException c) return c;
    return null;
  }

  /** What picocli found wrong, without the values on the command line. */
  private static String describe(Exception e, String[] argv, List<ParseResult> results) {
    if (e instanceof OverwrittenOptionException o)
      return name(o.getOverwritten()) + " was given more than once";
    if (e instanceof MissingParameterException m && !m.getMissing().isEmpty())
      return name(m.getMissing().get(0)) + " needs a value";
    if (e instanceof MaxValuesExceededException) {
      // An option that takes no value, given one: --yes=no.
      for (String token : argv) {
        if (token.equals("--")) break;
        int equals = token.indexOf('=');
        if (!token.startsWith("-") || equals < 0) continue;
        for (ParseResult r : results) {
          OptionSpec o = r.commandSpec().findOption(token.substring(0, equals));
          if (o != null && o.arity().max() == 0) return o.longestName() + " takes no value";
        }
      }
      return "an option that takes no value was given one";
    }
    return "cannot read the command line";
  }

  /** An option's name as given, without a value attached with {@code =}. */
  private static String name(String option) {
    int equals = option.indexOf('=');
    return equals > 0 ? option.substring(0, equals) : option;
  }

  private static String name(ArgSpec arg) {
    return arg instanceof OptionSpec o ? o.longestName() : arg.paramLabel();
  }

  /**
   * Checks that the output was written: a {@link PrintStream} keeps its errors to itself. When it
   * failed, the command fails with exit code 1 and says on standard error what it changed.
   */
  private int finish(Context context, ExitCode exit) {
    if (!out.checkError()) return exit.code;
    PrintStream err = Values.terminal(this.err);
    err.println("error: could not write the output: standard output failed");
    String done = context == null ? null : context.done();
    if (done != null)
      err.println(
          "hint: the change was made ("
              + done
              + "); check it before you repeat the command, which would not be safe");
    return ExitCode.FAILED.code;
  }

  private void report(Failure failure, boolean json) {
    if (json) {
      Map<String, Object> error = new LinkedHashMap<>();
      error.put("exitCode", failure.exit().code);
      error.put("status", Values.token(failure.exit()));
      error.put("message", failure.message());
      error.put("hint", failure.hint());
      error.putAll(failure.details());
      Map<String, Object> top = new LinkedHashMap<>();
      top.put("error", error);
      out.println(Json.write(top));
      if (!out.checkError()) return;
    }
    // The message and the hint may carry text from the server: escaped for the terminal.
    PrintStream err = Values.terminal(this.err);
    err.println("error: " + failure.message());
    if (failure.hint() != null) err.println("hint: " + failure.hint());
  }

  static String version() {
    String v = Cli.class.getPackage().getImplementationVersion();
    return v == null ? "(development build)" : v;
  }

  /** A failure as reported: exit code, message, hint and extra JSON fields. */
  record Failure(ExitCode exit, String message, String hint, Map<String, Object> details) {
    static Failure of(RuntimeException e, Context context) {
      Map<String, Object> details = new LinkedHashMap<>();
      if (e instanceof CliException c) {
        if (c.details != null) details.putAll(c.details);
        return new Failure(c.exit, c.getMessage(), c.hint, details);
      }
      if (e instanceof KmsException k) return of(k, context, details);
      // An IllegalArgumentException while the command line and the configuration are read, or
      // while connecting, is a CliException (exit 2) by then; one from a later step is a failure.
      if (e instanceof IllegalArgumentException)
        return new Failure(ExitCode.FAILED, e.getMessage(), null, details);
      if (e instanceof UncheckedIOException io)
        return new Failure(
            ExitCode.FAILED,
            io.getCause().getClass().getSimpleName() + ": " + io.getCause().getMessage(),
            null,
            details);
      return new Failure(
          ExitCode.FAILED,
          e.getClass().getSimpleName() + (e.getMessage() == null ? "" : ": " + e.getMessage()),
          null,
          details);
    }

    private static Failure of(KmsException k, Context context, Map<String, Object> details) {
      details.put("category", k.category().name());
      details.put("exception", k.getClass().getSimpleName());
      details.put("operation", k.operation().isEmpty() ? null : k.operation());
      details.put("objectId", k.objectId().orElse(null));
      details.put("serverReason", k.serverReason().map(Object::toString).orElse(null));
      String own = context == null ? null : context.hint(k);
      if (k instanceof OutcomeUnknownException)
        return new Failure(
            ExitCode.OUTCOME_UNKNOWN,
            "outcome unknown: " + k.getMessage(),
            own != null
                ? own
                : "the change may or may not have been made; "
                    + check(k, context)
                    + ", then decide whether to repeat it",
            details);
      if (k instanceof PartialCompletionException p) {
        List<String> created = ids(p.created());
        List<String> found = ids(p.found());
        List<String> deactivated = ids(p.deactivated());
        List<String> destroyed = ids(p.destroyed());
        details.put("created", created);
        details.put("found", found);
        details.put("deactivated", deactivated);
        details.put("destroyed", destroyed);
        // The failed step: an unknown outcome may have taken effect; a refusal did not.
        Throwable cause = p.getCause();
        details.put("outcomeUnknown", cause instanceof OutcomeUnknownException);
        details.put("cause", cause == null ? null : cause(cause));
        // An earlier step whose outcome was unknown, read back past: found is not this call's.
        details.put("recoveredFrom", p.recoveredFrom().map(Failure::cause).orElse(null));
        List<String> parts = new ArrayList<>();
        if (!created.isEmpty()) parts.add("created " + String.join(", ", created));
        if (!found.isEmpty())
          parts.add(
              (p.recoveredFrom().isPresent()
                      ? "found, after a reply was lost (this call or another caller made it): "
                      : "went on with, made by another call: ")
                  + String.join(", ", found));
        if (!deactivated.isEmpty()) parts.add("deactivated " + String.join(", ", deactivated));
        if (!destroyed.isEmpty()) parts.add("destroyed " + String.join(", ", destroyed));
        String progress = parts.isEmpty() ? "" : String.join("; ", parts) + ". ";
        return new Failure(
            ExitCode.PARTIAL,
            "partly done: " + p.getMessage(),
            progress
                + sentence(
                    progress,
                    own != null ? own : "follow the message; do not simply repeat the command"),
            details);
      }
      if (k instanceof NotFoundException)
        return new Failure(ExitCode.NOT_FOUND, k.getMessage(), own, details);
      if (k instanceof PermissionDeniedException)
        return new Failure(
            ExitCode.PERMISSION_DENIED,
            k.getMessage(),
            own != null
                ? own
                : "check the client identity of server group "
                    + (context == null || context.groupName() == null
                        ? "(this group)"
                        : context.groupName())
                    + " and the object's access policy on the server",
            details);
      if (k instanceof KeyMismatchException && k.category() == KmsException.Category.FIX_REQUEST)
        // The object is of another kind than the command takes: checked before any change.
        return new Failure(
            ExitCode.USAGE,
            k.getMessage(),
            own != null ? own : "check the identifier or name: " + check(k, context),
            details);
      if (k instanceof StateConflictException s) {
        details.put("conflict", Values.token(s.conflict()));
        details.put("observedState", s.observedState().map(Values::token).orElse(null));
        return new Failure(ExitCode.STATE_CONFLICT, s.getMessage(), own, details);
      }
      if (k instanceof TransientException)
        return new Failure(
            ExitCode.UNAVAILABLE,
            k.getMessage(),
            own != null
                ? own
                : "check the endpoints, the network and the server; reads were retried, changes are"
                    + " never re-sent",
            details);
      return new Failure(ExitCode.FAILED, k.getMessage(), own, details);
    }

    /** {@code text}, with a capital first letter when it follows the sentence {@code before}. */
    private static String sentence(String before, String text) {
      return before.isEmpty() || text.isEmpty()
          ? text
          : Character.toUpperCase(text.charAt(0)) + text.substring(1);
    }

    /**
     * A step whose reply was lost and that reading back went past, as the JSON results show it
     * (their {@code recoveredFrom}, the same object as an error's); null for none.
     */
    static Map<String, Object> step(OutcomeUnknownException lost) {
      return lost == null ? null : cause(lost);
    }

    /** The failed step of a partial completion, as JSON. */
    private static Map<String, Object> cause(Throwable cause) {
      Map<String, Object> out = new LinkedHashMap<>();
      out.put("exception", cause.getClass().getSimpleName());
      KmsException k = cause instanceof KmsException e ? e : null;
      out.put("category", k == null ? null : k.category().name());
      out.put("operation", k == null || k.operation().isEmpty() ? null : k.operation());
      out.put("objectId", k == null ? null : k.objectId().orElse(null));
      out.put(
          "serverReason", k == null ? null : k.serverReason().map(Object::toString).orElse(null));
      out.put("message", cause.getMessage());
      return out;
    }

    private static List<String> ids(List<KeyHandle> keys) {
      return keys.stream().map(KeyHandle::id).toList();
    }

    /** How to check what a change did: the object by identifier, else the objects with the name. */
    private static String check(KmsException k, Context context) {
      String id = k.objectId().orElse(context == null ? null : context.targetId);
      if (context == null) return "check the server's state with keytend-kmip-cli list";
      if (id != null) return "check the object with: " + context.suggest("show", id);
      if (context.targetName != null)
        return "look for the object with: "
            + context.suggest("list", "--name", context.targetName)
            + ", then show it with: "
            + context.suggest("show", "ID");
      return "check the server's state with: " + context.suggest("list");
    }
  }

  /**
   * One command: its names, help text, options and code.
   *
   * @param name its name
   * @param aliases its other names
   * @param synopsis its usage line, after the tool's name
   * @param summary what it does, in a sentence or two; the first sentence is in the tool's help
   * @param details more of its help, with its own line breaks; empty for none
   * @param options its own options, besides {@link Commands#GLOBAL}
   * @param runner its code
   */
  record Command(
      String name,
      List<String> aliases,
      String synopsis,
      String summary,
      String details,
      List<Commands.Option> options,
      Runner runner) {}

  /** A command's code. */
  @FunctionalInterface
  interface Runner {
    void run(Context context);
  }
}
