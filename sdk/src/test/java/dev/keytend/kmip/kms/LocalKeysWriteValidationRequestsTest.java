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

import static dev.keytend.kmip.kms.LocalKeysTest.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * A write validation reads the write key's attributes once: the selection's Get Attributes
 * serves the key's own checks, so the validation is Locate, Get Attributes, Obtain Lease (for a key
 * that states a Lease Time) and Get. When another validation applied an observation while the
 * selection ran, the attributes are read again, so a newer obligation is not lost.
 */
class LocalKeysWriteValidationRequestsTest {
  /** Each batch item sent, as "Operation id" (no id: Locate). */
  static List<String> record(Fixture f) {
    List<String> sent = new CopyOnWriteArrayList<>();
    f.before.set(
        request -> {
          for (Ttlv item : request.children(Tag.BATCH_ITEM)) {
            int code = item.require(Tag.OPERATION).intValue();
            String op =
                Arrays.stream(Operation.values())
                    .filter(o -> o.code() == code)
                    .findFirst()
                    .map(Enum::name)
                    .orElse("0x" + Integer.toHexString(code));
            String id =
                item.child(Tag.REQUEST_PAYLOAD)
                    .flatMap(p -> p.child(Tag.UNIQUE_IDENTIFIER))
                    .map(Ttlv::textValue)
                    .orElse("");
            sent.add(id.isEmpty() ? op : op + " " + id);
          }
        });
    return sent;
  }

  static long count(List<String> sent, String entry) {
    return sent.stream().filter(entry::equals).count();
  }

  static Stream<Arguments> cases() {
    return Stream.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0)
        .flatMap(
            v ->
                Stream.of(false, true)
                    .flatMap(
                        lease -> Stream.of(false, true).map(two -> Arguments.of(v, lease, two))));
  }

  /**
   * Cold and on revalidation, with one candidate (an unbatched Get Attributes) and with two (a
   * batch, where the previous selection is kept), with and without a Lease Time.
   */
  @ParameterizedTest
  @MethodSource("cases")
  void aWriteValidationSendsOneGetAttributesForTheWriteKey(
      KmipVersion version, boolean lease, boolean two) {
    try (Fixture f = new Fixture(version)) {
      if (lease) f.server.leaseTime(Duration.ofHours(1));
      KeyHandle write = f.key();
      LocalKeys c = f.cache();
      List<String> sent = record(f);
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(write.id(), use.id());
      }
      List<String> expected = new ArrayList<>(List.of("LOCATE", "GET_ATTRIBUTES " + write.id()));
      if (lease) expected.add("OBTAIN_LEASE " + write.id());
      expected.add("GET " + write.id());
      assertEquals(expected, List.copyOf(sent), "cold validation");

      KeyHandle second =
          two ? f.key() : null; // Same name, Active: the warm selection keeps the first.
      sent.clear();
      f.advance(5);
      try (LocalKeys.Use ignored = c.forEncrypt()) {}
      f.executor.run(); // The revalidation.
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(write.id(), use.id());
      }
      assertEquals(1, count(sent, "GET_ATTRIBUTES " + write.id()), "revalidation: " + sent);
      if (two)
        assertEquals(
            1, count(sent, "GET_ATTRIBUTES " + second.id()), "the other candidate: " + sent);
      assertEquals(lease ? 1 : 0, count(sent, "OBTAIN_LEASE " + write.id()));
      assertEquals(1, count(sent, "GET " + write.id()));
      assertEquals((two ? 3 : 2) + (lease ? 1 : 0) + 1, sent.size(), "every request: " + sent);
    }
  }

  /**
   * After the selection read the write key's attributes, and before the write validation could
   * receive other validations' observations, the server starts stating a Lease Time and a
   * historical validation of the same key observes it. The write validation reads the attributes
   * again and obtains its own lease, rather than publishing an unleased copy from the older read.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anObservationDuringTheSelectionIsNotLostToItsOlderRead(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle write = f.key();
      LocalKeys c = f.cache();
      List<String> sent = record(f);
      AtomicBoolean fired = new AtomicBoolean();
      f.after.set(
          (request, reply) -> {
            if (is(request, Operation.GET_ATTRIBUTES)
                && write.id().equals(id(request))
                && fired.compareAndSet(false, true)) {
              f.server.leaseTime(Duration.ofHours(1));
              try (LocalKeys.Use use = c.forDecrypt(write.id())) {
                assertEquals(write.id(), use.id());
              }
            }
            return reply;
          });
      try (LocalKeys.Use use = c.forEncrypt()) {
        assertEquals(write.id(), use.id());
      }
      assertTrue(fired.get());
      // The historical validation's lease, then the write validation's own, each before its Get.
      assertEquals(2, count(sent, "OBTAIN_LEASE " + write.id()), "every request: " + sent);
      assertEquals(
          3,
          count(sent, "GET_ATTRIBUTES " + write.id()),
          "the write validation read again: " + sent);
      int last = sent.lastIndexOf("GET " + write.id());
      assertEquals("OBTAIN_LEASE " + write.id(), sent.get(last - 1), "every request: " + sent);
    }
  }

  /**
   * The key is deactivated and invalidated while the selection's Get Attributes is on its way back:
   * the write validation must not hand it out on the attributes read before the invalidation. It
   * reads them again (the invalidation moved the epoch), finds the key Deactivated, and refuses:
   * invalidate(id) reaches a selection in flight.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anInvalidationDuringTheSelectionIsNotUndoneByItsOlderRead(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle write = f.key();
      LocalKeys c = f.cache();
      AtomicBoolean fired = new AtomicBoolean();
      f.after.set(
          (request, reply) -> {
            if (is(request, Operation.GET_ATTRIBUTES)
                && write.id().equals(id(request))
                && fired.compareAndSet(false, true)) {
              f.admin.keys().handle(write.id()).deactivate();
              c.invalidate(write.id());
            }
            return reply;
          });
      assertThrows(
          KmsException.class, c::forEncrypt, "nothing is handed out after invalidate() returned");
      assertTrue(fired.get());
      assertTrue(c.currentWriteId().isEmpty(), "no write selection on the stale read");
    }
  }

  /**
   * After the selection read the write key's attributes, the server stops letting this client read
   * them, and a historical validation of the key is refused (a refusal without attributes). The
   * write validation reads them again, is refused too, and hands nothing out.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRefusalDuringTheSelectionIsNotLostToItsOlderRead(KmipVersion version) {
    try (Fixture f = new Fixture(version)) {
      KeyHandle write = f.key();
      LocalKeys c = f.cache();
      AtomicBoolean denied = new AtomicBoolean();
      f.before.set(
          request -> {
            if (denied.get()
                && is(request, Operation.GET_ATTRIBUTES)
                && write.id().equals(id(request)))
              throw new PermissionDeniedException("Get Attributes of " + write.id() + " removed");
          });
      f.after.set(
          (request, reply) -> {
            if (is(request, Operation.GET_ATTRIBUTES)
                && write.id().equals(id(request))
                && denied.compareAndSet(false, true))
              assertThrows(PermissionDeniedException.class, () -> c.forDecrypt(write.id()));
            return reply;
          });
      assertThrows(PermissionDeniedException.class, c::forEncrypt);
      assertTrue(denied.get());
      assertTrue(c.currentWriteId().isEmpty());
    }
  }
}
