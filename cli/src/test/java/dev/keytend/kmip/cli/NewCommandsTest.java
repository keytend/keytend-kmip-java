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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.IOException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** activate, deactivate-predecessors and reconcile. */
class NewCommandsTest {
  @TempDir Path dir;

  @Test
  void activateShowsItsPlanAndActivatesAPreActiveKey() throws IOException {
    Harness h = new Harness(dir);
    String id = h.create("staged", "--pre-active");
    assertEquals(ExitCode.NOT_CONFIRMED.code, h.run("activate", id));
    assertTrue(h.err().contains("activate " + id), h.err());
    assertTrue(h.err().contains("its cryptoperiod starts"), h.err());
    assertEquals(KeyState.PRE_ACTIVE, h.server.state(id).orElseThrow());
    Map<String, Object> json = h.json("activate", id, "--yes");
    assertEquals("activated", json.get("action"));
    assertEquals("active", json.get("state"));
    assertEquals(KeyState.ACTIVE, h.server.state(id).orElseThrow());
    assertTrue(h.ok("activate", id, "--yes").contains("is Active already; nothing changed."));
    h.ok("expire", id, "--yes");
    assertEquals(ExitCode.STATE_CONFLICT.code, h.run("activate", id, "--yes"));
    assertTrue(h.err().contains("not Pre-Active"), h.err());
    assertEquals(ExitCode.NOT_FOUND.code, h.run("activate", "no-such-id", "--yes"));
  }

  @Test
  void deactivatePredecessorsDeactivatesOlderActiveKeysAndDestroysNothing() throws IOException {
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0)) {
      Harness h = new Harness(dir, InMemoryKmipServer.of(v));
      String first = h.create("orders-kek");
      String second = h.rotate("orders-kek");
      String third = h.rotate("orders-kek");
      assertEquals(ExitCode.NOT_CONFIRMED.code, h.run("deactivate-predecessors", third));
      assertTrue(h.err().contains("    " + first + " ("), h.err());
      assertTrue(h.err().contains("    " + second + " ("), h.err());
      assertTrue(h.err().contains("Nothing is destroyed."), h.err());
      assertEquals(KeyState.ACTIVE, h.server.state(first).orElseThrow());
      Map<String, Object> json = h.json("deactivate-predecessors", third, "--yes");
      List<Object> deactivated = Harness.list(json, "deactivated");
      assertTrue(deactivated.containsAll(List.of(first, second)), json.toString());
      for (String id : List.of(first, second))
        assertEquals(KeyState.DEACTIVATED, h.server.state(id).orElseThrow(), v + " " + id);
      assertEquals(KeyState.ACTIVE, h.server.state(third).orElseThrow());
      assertFalse(LifecycleCommandsTest.sent(h, Operation.DESTROY), "nothing was destroyed");
      assertTrue(h.ok("deactivate-predecessors", third, "--yes").contains("Nothing to deactivate"));
      if (v == KmipVersion.V3_0)
        assertTrue(LifecycleCommandsTest.sent(h, Operation.DEACTIVATE), "Deactivate on 3.0");
      assertEquals(
          ExitCode.USAGE.code,
          h.run("deactivate-predecessors", third, "--reason", "key-compromise", "--yes"));
    }
  }

  @Test
  void deactivatePredecessorsStartsFromTheNewestKey() throws IOException {
    Harness h = new Harness(dir);
    String first = h.create("orders-kek");
    h.rotate("orders-kek");
    assertEquals(ExitCode.STATE_CONFLICT.code, h.run("deactivate-predecessors", first, "--yes"));
    assertEquals(KeyState.ACTIVE, h.server.state(first).orElseThrow());
  }

  @Test
  void reconcileJoinsTheNewestKeys() throws IOException {
    Harness h = new Harness(dir);
    String root = h.create("k");
    String second = h.rotate("k");
    String branch;
    try (Kms kms = h.server.connect()) {
      branch = KeyCommandsTest.reKey(kms, root);
    }
    assertEquals(ExitCode.NOT_CONFIRMED.code, h.run("reconcile", "k"));
    assertTrue(h.err().contains("Joins these other newest keys into it:"), h.err());
    assertTrue(h.err().contains("Nothing is destroyed"), h.err());
    Map<String, Object> json = h.json("reconcile", "k", "--yes");
    assertEquals("reconciled", json.get("action"));
    String winner = (String) json.get("winner");
    String loser = winner.equals(second) ? branch : second;
    assertEquals(KeyState.ACTIVE, h.server.state(winner).orElseThrow());
    assertEquals(KeyState.DEACTIVATED, h.server.state(loser).orElseThrow());
    assertEquals(List.of("k"), h.server.names(winner));
    // The lineage table shows the join.
    String table = h.ok("lineage", "--id", winner);
    assertTrue(table.contains("JOINED INTO"), table);
    assertTrue(table.matches("(?s).*" + loser + "\\s+Deactivated\\s+.*" + winner + ".*"), table);
    // Now there is nothing to do.
    assertEquals("none", h.json("reconcile", "k", "--yes").get("action"));
    assertEquals(ExitCode.NOT_FOUND.code, h.run("reconcile", "no-such-name", "--yes"));
  }
}
