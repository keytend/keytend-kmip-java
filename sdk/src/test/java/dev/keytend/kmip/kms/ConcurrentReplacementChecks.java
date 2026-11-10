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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.util.*;

/**
 * What callers that rotated or replaced one key at the same time must leave:
 * nothing lost, nothing unreadable, nothing of another caller's revoked, the same choice for
 * everyone, and one newest key after {@link KeyHandle#reconcile()}.
 */
final class ConcurrentReplacementChecks {
  static final byte[] PLAIN = "probe".getBytes(UTF_8), AAD = "aad".getBytes(UTF_8);

  private ConcurrentReplacementChecks() {}

  /** The keys reached from {@code id} by links both keys confirm, either way, as the server holds them. */
  static Set<String> tree(InMemoryKmipServer server, String id) {
    Set<String> seen = new LinkedHashSet<>(List.of(id));
    Deque<String> queue = new ArrayDeque<>(seen);
    while (!queue.isEmpty()) {
      String k = queue.poll();
      for (String n : server.links(k, LinkKind.REPLACEMENT))
        if (server.links(n, LinkKind.REPLACED).contains(k) && seen.add(n)) queue.add(n);
      for (String p : server.links(k, LinkKind.REPLACED))
        if (server.links(p, LinkKind.REPLACEMENT).contains(k) && seen.add(p)) queue.add(p);
    }
    return seen;
  }

  /** Whether {@code id} descends from {@code ancestor} by confirmed links. */
  static boolean descends(InMemoryKmipServer server, String id, String ancestor) {
    Deque<String> queue = new ArrayDeque<>(List.of(ancestor));
    Set<String> seen = new HashSet<>(queue);
    while (!queue.isEmpty()) {
      String k = queue.poll();
      if (k.equals(id)) return true;
      for (String n : server.links(k, LinkKind.REPLACEMENT))
        if (server.links(n, LinkKind.REPLACED).contains(k) && seen.add(n)) queue.add(n);
    }
    return false;
  }

  static String describe(InMemoryKmipServer server) {
    StringBuilder b = new StringBuilder();
    for (String i : server.ids())
      b.append("\n  ")
          .append(i)
          .append(' ')
          .append(server.state(i).orElse(null))
          .append(" names=")
          .append(server.names(i))
          .append(" repl=")
          .append(server.links(i, LinkKind.REPLACEMENT))
          .append(" repld=")
          .append(server.links(i, LinkKind.REPLACED));
    return b.toString();
  }

  /**
   * The checks for callers that replaced {@code old} at once and returned {@code returned} (a
   * {@link Throwable} among them fails the check unless {@code failuresAllowed}): each returned key
   * is Active and descends from {@code old}; no key descending from {@code old} was revoked or
   * destroyed (the SDK touches no other caller's key); every instance chooses the same key through
   * {@code latest()} from {@code old} and from every returned key and through {@code findByName};
   * records sealed under every returned key and under the chosen one open through every instance's
   * chosen handle, {@code latest()}, {@code KeyQuery.name} and every returned key's handle (and
   * {@code old}'s, unless it is Compromised). Then {@code reconcile} from {@code setup}: it returns
   * the chosen key, which is then the only Active key of the tree and the only Active one named
   * {@code name}, and everything still opens.
   *
   * @return the reconciled key
   */
  static KeyHandle assertSafe(
      InMemoryKmipServer server,
      Kms setup,
      KeyHandle old,
      List<?> returned,
      List<Kms> instances,
      String name,
      boolean failuresAllowed) {
    String where = describe(server);
    List<String> ids = new ArrayList<>();
    for (Object r : returned) {
      if (r instanceof String s) ids.add(s);
      else if (r instanceof KeyHandle h) ids.add(h.id());
      else if (!failuresAllowed)
        throw new AssertionError(
            "an instance failed: " + r + where, r instanceof Throwable t ? t : null);
    }
    for (String id : ids) {
      assertEquals(
          Optional.of(KeyState.ACTIVE),
          server.state(id),
          "a returned key is Active: " + id + where);
      assertTrue(descends(server, id, old.id()), id + " descends from " + old.id() + where);
    }
    for (String id : server.ids())
      if (!id.equals(old.id()) && descends(server, id, old.id())) {
        KeyState s = server.state(id).orElse(null);
        assertTrue(
            s == KeyState.ACTIVE || s == KeyState.PRE_ACTIVE,
            "no replacement of "
                + old.id()
                + " is revoked or destroyed by the SDK: "
                + id
                + " is "
                + s
                + where);
      }
    boolean oldCompromised =
        server.state(old.id()).map(s -> s == KeyState.COMPROMISED).orElse(false);
    String chosen = choice(instances, old, ids, name, where);
    assertEquals(
        Optional.of(KeyState.ACTIVE), server.state(chosen), "the chosen key is Active" + where);
    List<byte[]> records = new ArrayList<>();
    for (Kms k : instances) {
      for (String id : ids) records.add(k.keys().handle(id).seal(PLAIN, AAD));
      records.add(k.keys().findByName(name).orElseThrow().seal(PLAIN, AAD));
    }
    assertOpen(instances, old, ids, name, records, oldCompromised, where);
    for (String id : ids) {
      boolean latest = setup.keys().handle(id).isLatest();
      assertEquals(id.equals(chosen), latest, id + ".isLatest()" + where);
    }

    KeyHandle winner = setup.keys().reconcile(name).orElseThrow();
    String after = describe(server);
    assertEquals(chosen, winner.id(), "reconcile keeps the key everyone chose" + after);
    for (String id : tree(server, winner.id()))
      if (!id.equals(winner.id()))
        assertNotEquals(
            Optional.of(KeyState.ACTIVE),
            server.state(id),
            "after reconcile only the winner is Active: " + id + after);
    List<String> named =
        server.ids().stream()
            .filter(
                i ->
                    server.names(i).contains(name)
                        && server.state(i).orElse(null) == KeyState.ACTIVE)
            .toList();
    assertEquals(List.of(winner.id()), named, "one Active key with the name" + after);
    assertEquals(
        winner.id(),
        choice(instances, old, ids, name, after),
        "everyone chooses the winner" + after);
    assertOpen(instances, old, ids, name, records, oldCompromised, after);
    // Idempotent.
    assertEquals(winner, setup.keys().handle(old.id()).reconcile());
    return winner;
  }

  /** The key every instance chooses, checked to be the same everywhere. */
  static String choice(
      List<Kms> instances, KeyHandle old, List<String> ids, String name, String where) {
    String chosen = null;
    for (Kms k : instances) {
      List<String> seen = new ArrayList<>();
      seen.add(k.keys().handle(old.id()).latest().id());
      for (String id : ids) seen.add(k.keys().handle(id).latest().id());
      seen.add(k.keys().findByName(name).map(KeyHandle::id).orElse("none"));
      for (String s : seen) {
        if (chosen == null) chosen = s;
        assertEquals(chosen, s, "every instance chooses the same key everywhere: " + seen + where);
      }
    }
    return chosen;
  }

  static void assertOpen(
      List<Kms> instances,
      KeyHandle old,
      List<String> ids,
      String name,
      List<byte[]> records,
      boolean oldCompromised,
      String where) {
    for (Kms k : instances)
      for (byte[] r : records) {
        String why = "record under " + KmsKeys.sealedKeyId(r) + where;
        assertArrayEquals(
            PLAIN, k.keys().findByName(name).orElseThrow().open(r, AAD), "by name: " + why);
        assertArrayEquals(
            PLAIN, k.keys().handle(old.id()).latest().open(r, AAD), "latest(): " + why);
        assertArrayEquals(
            PLAIN, k.keys().open(KeyQuery.byName(name), r, AAD), "KeyQuery.name: " + why);
        for (String id : ids)
          assertArrayEquals(PLAIN, k.keys().handle(id).open(r, AAD), id + "'s handle: " + why);
        if (!oldCompromised)
          assertArrayEquals(
              PLAIN, k.keys().handle(old.id()).open(r, AAD), "old key's handle: " + why);
      }
  }
}
