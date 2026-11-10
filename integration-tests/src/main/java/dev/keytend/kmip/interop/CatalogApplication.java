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

package dev.keytend.kmip.interop;

import dev.keytend.kmip.model.ProtocolVersion;
import java.nio.file.*;
import java.util.*;

/** Runs the same research catalog on a configured external fixture, without Testcontainers. */
public final class CatalogApplication {
  public static void main(String[] args) throws Exception {
    if (args.length < 5)
      throw new IllegalArgumentException(
          "Usage: CatalogApplication <server> <host> <port> <cert-dir> <version> [report-dir]");
    Path root = Path.of(System.getProperty("project.root", ".")).toAbsolutePath();
    String[] v = args[4].split("\\.");
    ProtocolVersion version = ProtocolVersion.of(Integer.parseInt(v[0]), Integer.parseInt(v[1]));
    Path reports = Path.of(args.length > 5 ? args[5] : "integration/reports/catalog");
    try (var f =
        new CatalogFixture(
            root,
            args[0],
            args[1],
            Integer.parseInt(args[2]),
            Path.of(args[3]),
            version,
            System.getProperty("kmip.server.build", "unverified"),
            System.getProperty("kmip.server.image", "unverified"),
            System.getProperty("kmip.client.commit", "uncommitted"),
            Catalog.digest(Files.readAllBytes(root.resolve("integration/catalog/catalog.json"))))) {
      var report = new CatalogLiveSuite(f).run();
      f.close();
      report.put("cleanup", Map.of("remaining_run_owned_ids", List.copyOf(f.owned)));
      Catalog.write(
          reports.resolve(args[0] + "-" + version + "-jdk" + Runtime.version().feature() + ".json"),
          report);
      @SuppressWarnings("unchecked")
      var records = (List<Map<String, Object>>) report.get("records");
      Map<Object, Long> counts = new LinkedHashMap<>();
      for (var r : records) counts.merge(r.get("outcome"), 1L, Long::sum);
      System.out.println(Catalog.json(counts));
      boolean failed = records.stream().anyMatch(r -> r.get("outcome").equals("FAIL_CLIENT"));
      if (Boolean.getBoolean("kmip.catalog.strict"))
        failed |= !(Boolean) ((Map<?, ?>) report.get("qualification")).get("qualified");
      if (failed)
        throw new AssertionError("Catalog qualification failed; inspect structured report");
    }
  }
}
