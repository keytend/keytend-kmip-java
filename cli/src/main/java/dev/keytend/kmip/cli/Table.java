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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A plain-text table with a header row, columns padded to their widest cell. Cells hold text from
 * the server, so control and bidi format characters in them are escaped ({@link Values#safe}).
 */
final class Table {
  private final List<String[]> rows = new ArrayList<>();
  private final int columns;

  Table(String... headers) {
    columns = headers.length;
    rows.add(headers.clone());
  }

  /**
   * Adds a row; null cells print as empty, and the others are escaped for the terminal.
   *
   * @param cells one per column
   * @return this table
   */
  Table row(String... cells) {
    if (cells.length != columns)
      throw new IllegalArgumentException("expected " + columns + " cells");
    String[] copy = Arrays.copyOf(cells, cells.length);
    for (int i = 0; i < copy.length; i++) copy[i] = copy[i] == null ? "" : Values.safe(copy[i]);
    rows.add(copy);
    return this;
  }

  /**
   * Whether only the header row is present.
   *
   * @return true when no row was added
   */
  boolean isEmpty() {
    return rows.size() == 1;
  }

  void print(PrintStream out) {
    int[] widths = new int[columns];
    for (String[] row : rows)
      for (int i = 0; i < columns; i++) widths[i] = Math.max(widths[i], row[i].length());
    for (String[] row : rows) {
      StringBuilder line = new StringBuilder();
      for (int i = 0; i < columns; i++) {
        if (i > 0) line.append("  ");
        line.append(row[i]);
        if (i < columns - 1) line.append(" ".repeat(widths[i] - row[i].length()));
      }
      out.println(line.toString().stripTrailing());
    }
  }
}
