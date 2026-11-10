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

import java.io.PrintStream;
import java.util.List;
import java.util.function.IntSupplier;

/**
 * The entry point of keytend-kmip-cli. Run {@code keytend-kmip-cli --help} for the commands; the
 * module's README documents them, the configuration file and the exit codes.
 */
public final class Main {
  /**
   * One class of each runtime library the JAR's manifest names (Class-Path, lib/ beside it): each
   * is looked for before a command runs, so that a missing JAR is said before anything is sent.
   */
  static final List<String> RUNTIME =
      List.of(
          "picocli.CommandLine",
          "tools.jackson.core.json.JsonFactory",
          "org.slf4j.LoggerFactory",
          "org.slf4j.simple.SimpleLogger",
          "dev.keytend.kmip.kms.Kms");

  private Main() {}

  /**
   * Runs one command and exits with its exit code.
   *
   * @param args the command line
   */
  public static void main(String[] args) {
    System.exit(run(RUNTIME, () -> Cli.system().run(args), System.err));
  }

  /**
   * Runs {@code command} once each class of {@code runtime} is found; exit code 2 (nothing sent)
   * when one is not. A class missing later (a JAR of lib/ that is incomplete) stops the command
   * where it is, maybe after a change: exit code 1, as for a failure to write the output.
   */
  static int run(List<String> runtime, IntSupplier command, PrintStream err) {
    String missing = missing(runtime);
    if (missing != null) {
      err.println(
          "keytend-kmip-cli: a runtime JAR is missing ("
              + missing
              + " not found); the CLI JAR's manifest names them, in lib/ beside it. Nothing was"
              + " sent");
      return ExitCode.USAGE.code;
    }
    try {
      return command.getAsInt();
    } catch (NoClassDefFoundError late) {
      err.println(
          "keytend-kmip-cli: a runtime JAR in lib/ is incomplete ("
              + late.getMessage()
              + " not found). The command stopped part-way: a change it makes may have been made;"
              + " check with list before repeating it");
      return ExitCode.FAILED.code;
    }
  }

  /** The first class of {@code runtime} that cannot be loaded, or null when all can. */
  static String missing(List<String> runtime) {
    ClassLoader loader = Main.class.getClassLoader();
    for (String name : runtime)
      try {
        Class.forName(name, false, loader);
      } catch (ClassNotFoundException | LinkageError e) {
        return name;
      }
    return null;
  }
}
