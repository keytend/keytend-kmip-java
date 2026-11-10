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

import java.io.Console;
import java.util.Optional;

/** The operator's console, for confirmations and secrets typed by hand; absent when not interactive. */
interface Terminal {
  /**
   * Whether a person can answer: a console is attached.
   *
   * @return true when {@link #readLine} and {@link #readPassword} can ask
   */
  boolean interactive();

  /**
   * Asks for a line.
   *
   * @param prompt the question
   * @return the answer, or null at the end of input
   */
  String readLine(String prompt);

  /**
   * Asks for a secret without echoing it.
   *
   * @param prompt the question
   * @return the secret, or null at the end of input; the caller wipes it
   */
  char[] readPassword(String prompt);

  /**
   * The JVM's console when the process runs at a terminal, or a terminal that is not interactive.
   *
   * @return the terminal
   */
  static Terminal system() {
    Optional<Console> console = Optional.ofNullable(System.console()).filter(Terminal::isTerminal);
    return new Terminal() {
      @Override
      public boolean interactive() {
        return console.isPresent();
      }

      @Override
      public String readLine(String prompt) {
        // Escaped here too, at the boundary: no prompt carries a control to the terminal.
        return console.map(c -> c.readLine("%s", Values.safe(prompt))).orElse(null);
      }

      @Override
      public char[] readPassword(String prompt) {
        return console.map(c -> c.readPassword("%s", Values.safe(prompt))).orElse(null);
      }
    };
  }

  /**
   * Whether the console is a terminal. From JDK 22 a console exists without one, and {@code
   * Console.isTerminal()} tells; before, a console exists only at a terminal.
   */
  private static boolean isTerminal(Console console) {
    try {
      return Boolean.TRUE.equals(Console.class.getMethod("isTerminal").invoke(console));
    } catch (NoSuchMethodException beforeJdk22) {
      return true;
    } catch (ReflectiveOperationException | RuntimeException e) {
      return false;
    }
  }
}
