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

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/** A logged value cannot start a new log line or reorder the line it is in. */
class LogTextTest {
  @Test
  void lineBreaksControlsAndBidiCharactersAreEscaped() {
    assertEquals("orders-kek", LogText.safe("orders-kek"));
    assertEquals("null", LogText.safe(null));
    assertEquals("a\\u000d\\u000aWARN forged", LogText.safe("a\r\nWARN forged"));
    assertEquals("\\u001b[31mred", LogText.safe("\u001b[31mred"));
    assertEquals(
        "x\\u2028y\\u202ez\\u2066",
        LogText.safe(
            // Built from code points: the characters themselves would hide code in an editor.
            "x" + (char) 0x2028 + "y" + (char) 0x202e + "z" + (char) 0x2066));
    assertEquals("\\u007f\\u0085", LogText.safe("\u007f\u0085"));
    assertEquals("ключ", LogText.safe("ключ"), "other text is kept");
  }
}
