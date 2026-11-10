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

import java.util.Locale;

/**
 * Text for a log line. Key names, identifiers and messages can come from a server or a file, so
 * every argument the SDK logs passes through {@link #safe}: a value with a line break cannot
 * forge a second log line, nor one with control or bidi characters change how the line reads.
 */
final class LogText {
  private LogText() {}

  /**
   * {@code value}'s text with C0 and C1 control characters (CR and LF among them), DEL, the line
   * and paragraph separators and the bidi format characters written as {@code \}{@code uXXXX}.
   *
   * @param value the value, or null
   * @return the escaped text; {@code "null"} for null
   */
  static String safe(Object value) {
    String text = String.valueOf(value);
    StringBuilder out = null;
    for (int i = 0; i < text.length(); i++) {
      char c = text.charAt(i);
      boolean unsafe = unsafe(c);
      if (unsafe && out == null) out = new StringBuilder(text.length() + 8).append(text, 0, i);
      if (unsafe) out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
      else if (out != null) out.append(c);
    }
    return out == null ? text : out.toString();
  }

  private static boolean unsafe(char c) {
    return c < 0x20
        || (c >= 0x7F && c <= 0x9F)
        || c == 0x200E
        || c == 0x200F
        || c == 0x2028
        || c == 0x2029
        || (c >= 0x202A && c <= 0x202E)
        || (c >= 0x2066 && c <= 0x2069);
  }
}
