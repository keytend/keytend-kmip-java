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

import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.kms.TlsRepeatTest.Material;
import dev.keytend.kmip.kms.TlsRepeatTest.Scenario;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.ServerOperation;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * A TLS identity's call removes an attribute instance of an object it changes with one Delete
 * Attribute per read of that object: on KMIP 1.x it deletes by the Attribute Index of the first
 * instance of its own value, never every instance under one check. Another caller adds a second
 * instance of the attribute; as the call's first Delete goes out, the other caller gives the object
 * another name. The call sends no second Delete: it reads the object again first, and stops when
 * the read shows the name. An instance of another value is not the call's, and is left. Covered:
 * the record of the name being moved (where names are unique), both when the move finishes and
 * when it is rolled back, and a temporary name.
 */
class TlsOneDeletePerReadTest {
  static final String NAME = TlsRepeatTest.NAME;

  /** What the other caller adds, and where. */
  enum Extra {
    /** An instance of the record of the name being moved, of another value. */
    RECORD_OF_ANOTHER_VALUE,
    /** A second instance of that record, of the same value. */
    RECORD_OF_THE_SAME_VALUE,
    /** An instance of another value, as the move is rolled back (its second name is refused). */
    RECORD_ON_ROLLBACK,
    /** A second instance of the leaf's temporary name, on a server whose names are not unique. */
    TEMPORARY_NAME
  }

  static Stream<Arguments> cases() {
    List<Arguments> out = new ArrayList<>();
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0))
      for (Extra e : Extra.values()) out.add(Arguments.of(v, e));
    return out.stream();
  }

  @ParameterizedTest
  @MethodSource("cases")
  void aCallSendsOneDeletePerReadAndNoneAfterAnotherCallersChange(KmipVersion version, Extra extra)
      throws Exception {
    Material m = new Material();
    boolean unique = extra != Extra.TEMPORARY_NAME;
    try (Scenario s = new Scenario(version, unique, m)) {
      String old = s.start.certificate().id();
      String pending = KeyHandle.pendingName(NAME).name();
      String[] leaf = {null}, temporary = {null};
      boolean[] added = {false}, changed = {false};
      int[] addNames = {0};
      List<String> deletes = new CopyOnWriteArrayList<>();
      List<String> afterTheChange = new CopyOnWriteArrayList<>();
      s.t.hook =
          r -> {
            TlsOwnershipTest.Write w = TlsOwnershipTest.write(r);
            if (w == null) return;
            if (changed[0] && w.mentions(leaf[0]))
              afterTheChange.add(Operation.fromCode(w.operation()) + " " + w.target());
            boolean add = TlsRepeatTest.is(r, Operation.ADD_ATTRIBUTE);
            boolean delete = TlsRepeatTest.is(r, Operation.DELETE_ATTRIBUTE);
            if (extra == Extra.TEMPORARY_NAME) {
              // The leaf's Replaced Object link, just before its temporary name comes off.
              if (!added[0] && add && w.texts().contains(old) && !old.equals(w.target())) {
                leaf[0] = w.target();
                temporary[0] =
                    s.server.names(leaf[0]).stream()
                        .filter(n -> n.startsWith(TlsIdentities.temporaryPrefix(NAME)))
                        .findFirst()
                        .orElseThrow();
                s.other.keys().handle(leaf[0]).addName(temporary[0]);
                assertEquals(2, s.server.names(leaf[0]).size(), "the server took the second name");
                added[0] = true;
              } else if (added[0] && delete && leaf[0].equals(w.target())) {
                // The leaf's only Delete before the switch: its temporary name, by value on 2.x and
                // by Attribute Index on 1.x.
                deletes.add(w.target());
                if (!changed[0]) {
                  s.other.keys().handle(leaf[0]).addName("foreign-use");
                  changed[0] = true;
                }
              }
              return;
            }
            List<String> next = s.server.links(old, LinkKind.REPLACEMENT);
            if (leaf[0] == null && !next.isEmpty()) leaf[0] = next.get(0);
            if (leaf[0] == null) return;
            if (extra == Extra.RECORD_ON_ROLLBACK
                && add
                && leaf[0].equals(w.target())
                && w.texts().contains(NAME)
                && w.texts().stream().noneMatch(t -> t.contains(pending))
                && ++addNames[0] == 2)
              s.server.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.INVALID_REQUEST);
            if (!added[0] && delete && old.equals(w.target())) {
              // As the name comes off the old certificate: the second instance.
              addRecord(
                  s, leaf[0], extra == Extra.RECORD_OF_THE_SAME_VALUE ? NAME : "another value");
              added[0] = true;
            } else if (delete
                && leaf[0].equals(w.target())
                && w.texts().stream().anyMatch(t -> t.contains(pending) || t.equals(NAME))) {
              deletes.add(w.target());
              if (!changed[0]) {
                s.other.keys().handle(leaf[0]).addName("foreign-use");
                changed[0] = true;
              }
            }
          };
      TlsIdentityHandle done = null;
      KmsException stopped = null;
      try {
        done = s.start.renew(m.pki.chain(m.mineRenewed));
      } catch (KmsException e) {
        stopped = e;
      }
      s.t.hook = r -> {};
      assertTrue(added[0], "the other caller added the second instance");
      assertTrue(changed[0], "the call sent a Delete");
      assertEquals(1, deletes.size(), "Deletes after the other caller's change: " + deletes);
      assertEquals(
          List.of(), afterTheChange, "the call changed the object after the other caller's change");
      if (extra == Extra.RECORD_OF_ANOTHER_VALUE) {
        assertNotNull(done, String.valueOf(stopped));
        assertEquals(leaf[0], done.certificate().id());
      }
      if (extra == Extra.RECORD_OF_ANOTHER_VALUE || extra == Extra.RECORD_ON_ROLLBACK)
        assertTrue(
            records(s, leaf[0]).contains("another value"),
            "the other caller's instance is left: " + records(s, leaf[0]));
      if (extra == Extra.RECORD_ON_ROLLBACK) {
        assertNotNull(stopped, "the second name was refused");
        assertEquals(List.of(NAME), s.server.names(old), "the name went back");
      }
      if (stopped != null) {
        StateConflictException refusal =
            stopped instanceof StateConflictException c
                ? c
                : stopped.getCause() instanceof StateConflictException c ? c : null;
        if (refusal != null) assertEquals(Optional.of(leaf[0]), refusal.objectId());
      }
      assertTrue(s.server.names(leaf[0]).contains("foreign-use"));
      assertEquals(List.of(), s.server.violations());
    }
  }

  /** Adds an instance of the record that {@link #NAME} is being moved, of {@code value}, to {@code id}. */
  static void addRecord(Scenario s, String id, String value) {
    try {
      s.other
          .protocol()
          .call(
              Requests.addAttribute()
                  .uniqueIdentifier(id)
                  .attribute(s.other.keys().custom(KeyHandle.pendingName(NAME), value))
                  .build());
    } catch (java.io.IOException e) {
      throw new IllegalStateException(e);
    }
  }

  /** The text values of the records of a name being moved on {@code id}. */
  static List<String> records(Scenario s, String id) {
    List<String> out = new ArrayList<>();
    s.server
        .protocolAttributes(id)
        .forEach(
            (attribute, values) -> {
              if (attribute.contains(KeyHandle.PENDING_PREFIX)) for (Ttlv v : values) texts(v, out);
            });
    return out;
  }

  private static void texts(Ttlv t, List<String> out) {
    if (t.type() == Ttlv.Type.STRUCTURE) for (Ttlv c : t.children()) texts(c, out);
    else if (t.type() == Ttlv.Type.TEXT_STRING) out.add(t.textValue());
  }
}
