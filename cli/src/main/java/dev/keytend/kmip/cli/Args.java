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

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import picocli.CommandLine.Model.OptionSpec;
import picocli.CommandLine.ParseResult;

/**
 * A command's parsed arguments: its positional arguments, and the options given before or after
 * its name, each as text and as its {@link Commands.Conversion} made it. picocli parses the command
 * line ({@link Cli#parse}); the commands read it from here.
 */
final class Args {
  private final List<String> positionals;
  private final Map<String, List<String>> text;
  private final Map<String, Object> values;

  private Args(
      List<String> positionals, Map<String, List<String>> text, Map<String, Object> values) {
    this.positionals = List.copyOf(positionals);
    this.text = text;
    this.values = values;
  }

  /**
   * The options matched in {@code results}, by their long names.
   *
   * @param positionals the command's arguments
   * @param results the tool's and the command's parse results
   * @return the arguments
   */
  static Args of(List<String> positionals, List<ParseResult> results) {
    Map<String, List<String>> text = new LinkedHashMap<>();
    Map<String, Object> values = new LinkedHashMap<>();
    for (ParseResult result : results)
      for (OptionSpec o : result.matchedOptions()) {
        text.putIfAbsent(o.longestName(), List.copyOf(o.originalStringValues()));
        Object value = o.getValue();
        if (value != null) values.putIfAbsent(o.longestName(), value);
      }
    return new Args(positionals, text, values);
  }

  List<String> positionals() {
    return positionals;
  }

  boolean flag(String name) {
    return text.containsKey(name);
  }

  /**
   * An option's value as it was given.
   *
   * @param name the option's long name
   * @return the value, or empty when the option was not given
   */
  Optional<String> value(String name) {
    List<String> given = text.get(name);
    return given == null || given.isEmpty() ? Optional.empty() : Optional.of(given.get(0));
  }

  /**
   * A repeated option's values as they were given.
   *
   * @param name the option's long name
   * @return the values, in their order; empty when the option was not given
   */
  List<String> values(String name) {
    return text.getOrDefault(name, List.of());
  }

  /**
   * An option's value as its conversion made it.
   *
   * @param name the option's long name
   * @param type the value's type
   * @param <T> the value's type
   * @return the value, or empty when the option was not given
   */
  <T> Optional<T> get(String name, Class<T> type) {
    return Optional.ofNullable(values.get(name)).map(type::cast);
  }

  /**
   * The only positional argument.
   *
   * @param what what it is, for the error message (for example "a key identifier")
   * @return the argument
   * @throws CliException when there is not exactly one
   */
  String single(String what) {
    if (positionals.size() != 1)
      throw CliException.usage(
          positionals.isEmpty()
              ? "expected " + what
              : "expected only " + what + ", got " + positionals);
    return positionals.get(0);
  }

  /**
   * Refuses positional arguments.
   *
   * @throws CliException when there are any
   */
  void none() {
    if (!positionals.isEmpty())
      throw CliException.usage("unexpected argument " + positionals.get(0));
  }
}
