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

import static dev.keytend.kmip.kms.CompromiseLineageCasesTest.compromise;
import static dev.keytend.kmip.kms.CompromiseLineageCasesTest.ids;
import static dev.keytend.kmip.kms.CompromiseLineageCasesTest.is;
import static dev.keytend.kmip.kms.CompromiseLineageCasesTest.lineage;
import static dev.keytend.kmip.kms.CompromiseLineageCasesTest.meanwhile;
import static dev.keytend.kmip.kms.CompromiseLineageCasesTest.newest;
import static dev.keytend.kmip.kms.CompromiseLineageCasesTest.objects;
import static dev.keytend.kmip.kms.CompromiseLineageCasesTest.untouched;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * A located object that cannot be read leaves a search unable to tell, never "none"; a recovery
 * after a lost Register goes on only with the object it proves its own and unchanged, as the
 * compromise procedure's lost Create does; a transient failure of the unlinked-key search is thrown
 * as it is; a lost reply to the removal of the temporary name is reported. Faults and other
 * callers' changes are armed from the client's transport as each request goes out, so each case is
 * deterministic.
 */
class RecoveryCandidatesTest {
  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  /** A server as {@link CompromiseLineageCasesTest#server} makes it. */
  InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer s =
        InMemoryKmipServer.of(version).linkCardinality(false).freshDatesOnReKey(true);
    servers.add(s);
    return s;
  }

  /** A client whose requests {@code before} sees first, before the server does. */
  Kms connect(InMemoryKmipServer s, Consumer<Ttlv> before) {
    Kms kms =
        Kms.connect(
            s.configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        r -> {
                          before.accept(r);
                          return s.exchange(r);
                        })
                .build());
    clients.add(kms);
    return kms;
  }

  Kms connect(InMemoryKmipServer s) {
    return connect(s, r -> {});
  }

  /**
   * Whether {@code t} has a field that is exactly {@code id}: a Text String, or a KMIP 3.0
   * Identifier or Reference.
   */
  static boolean refers(Ttlv t, String id) {
    if (t.type() == Ttlv.Type.TEXT_STRING
        || t.type() == Ttlv.Type.IDENTIFIER
        || t.type() == Ttlv.Type.REFERENCE) return id.equals(String.valueOf(t.value()));
    if (t.type() == Ttlv.Type.STRUCTURE) for (Ttlv c : t.children()) if (refers(c, id)) return true;
    return false;
  }

  /**
   * Refuses (object-level Permission Denied) every Get Attributes of the object {@code hidden}
   * names, while it is set: a key these credentials may not read.
   */
  static Consumer<Ttlv> hiding(InMemoryKmipServer s, AtomicReference<String> hidden) {
    return r -> {
      String id = hidden.get();
      if (id != null && is(r, Operation.GET_ATTRIBUTES) && refers(r, id))
        s.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
    };
  }

  // ---- a located object that cannot be read ----

  /**
   * Re-key is refused, the fallback Create's reply is lost, and the key it made (B) is found by its
   * temporary name but cannot be read. The call never takes that for "none": it stops, keeping its
   * revocation, says the server could not be searched and names B, and never advises a repeat. A
   * new plan, B still unreadable, says it could not check; once B can be read, the plan refuses,
   * naming it. No second key is made.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostCreatesKeyThatCannotBeReadIsNeverTakenForAbsent(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    AtomicReference<String> hidden = new AtomicReference<>();
    AtomicBoolean armed = new AtomicBoolean();
    Consumer<Ttlv> hide = hiding(s, hidden);
    Kms kms =
        connect(
            s,
            r -> {
              if (armed.get()
                  && is(r, Operation.LOCATE)
                  && LineageTreeTest.names(r, KeyHandle.TEMPORARY)) hidden.set(newest(s));
              hide.accept(r);
            });
    CompromiseLineageCasesTest.Lineage l = lineage(kms, false);
    CompromisePlan plan = l.key().compromisePlan();
    Map<String, String> before = objects(s);
    armed.set(true);
    s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
    s.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> l.key().replaceCompromisedResult(compromise(Instant.now()), plan));
    String b = hidden.get();
    assertNotNull(b, "the search ran");
    assertEquals(Set.of(b), CompromiseLineageCasesTest.onlyPlanned(s, before, plan, 1));
    assertEquals(List.of(l.key().id()), ids(e.deactivated()));
    assertEquals(List.of(), e.created());
    assertTrue(e.getMessage().contains("could not be searched"), e.getMessage());
    assertTrue(
        e.getMessage().contains("it found " + b + ", which could not be read"), e.getMessage());
    // Not said to be the credentials, which a reply that is not valid also gives.
    assertTrue(
        e.getMessage().contains("access was refused, or the server's reply was not valid"),
        e.getMessage());
    assertFalse(e.getMessage().contains("did not take effect"), e.getMessage());
    assertFalse(e.getMessage().contains("to resume"), e.getMessage());
    // The stop names the one object it concerns.
    assertEquals(Optional.of(b), e.objectId());
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(b));
    assertEquals(List.of(), plan.unreadableCandidates());

    CompromisePlan unchecked = l.key().compromisePlan();
    assertFalse(unchecked.checkedForUnlinkedKeys(), "B cannot be read: the plan cannot tell");
    // The plan names B, rather than only saying it could not check.
    assertEquals(List.of(b), unchecked.unreadableCandidates());
    hidden.set(null);
    StateConflictException refused =
        assertThrows(StateConflictException.class, () -> l.key().compromisePlan());
    assertEquals(StateConflictException.Conflict.UNLINKED_REPLACEMENT, refused.conflict());
    assertEquals(Optional.of(b), refused.objectId());
    // The record the plan searches by, public, is what B carries.
    assertEquals("x-keytend-replacement-of", CompromisePlan.REPLACEMENT_RECORD.toString());
    assertEquals(
        l.key().id(),
        kms.keys().handle(b).attributes().custom().get(CompromisePlan.REPLACEMENT_RECORD));
  }

  /**
   * The secret replacement: the Register's reply is lost, and the object it made is found by its
   * temporary name but cannot be read. The unknown outcome says the server could not be searched
   * and names the object, and never "repeat"; the old secret keeps the name.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostRegistersObjectThatCannotBeReadIsNeverTakenForAbsent(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicReference<String> hidden = new AtomicReference<>();
    AtomicBoolean armed = new AtomicBoolean();
    Consumer<Ttlv> hide = hiding(s, hidden);
    Kms kms =
        connect(
            s,
            r -> {
              if (armed.get() && is(r, Operation.REGISTER))
                s.failNext(ServerOperation.REGISTER, Fault.REPLY_LOST);
              if (armed.get() && is(r, Operation.LOCATE) && LineageTreeTest.names(r, ".replacing-"))
                hidden.set(newest(s));
              hide.accept(r);
            });
    KeyHandle old = ConflictKindTest.secret(kms, "db").register();
    armed.set(true);
    OutcomeUnknownException e =
        assertThrows(
            OutcomeUnknownException.class,
            () -> ConflictKindTest.secret(kms, "db").replaceResult(old));
    String b = hidden.get();
    assertNotNull(b, "the search ran");
    assertTrue(e.getMessage().contains("could not be searched"), e.getMessage());
    assertTrue(
        e.getMessage().contains("it found " + b + ", which could not be read"), e.getMessage());
    assertFalse(e.getMessage().contains("Repeat with a new builder"), e.getMessage());
    // The stop names the one object it concerns.
    assertEquals(Optional.of(b), e.objectId());
    assertEquals(List.of("db"), s.names(old.id()));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(b));
  }

  // ---- a lost Register's object, changed by another caller ----

  /**
   * The first case: a symmetric key is registered to replace the key named {@code byok}. The
   * Register's reply is lost; before the call looks for its object (B), another caller re-keys B to
   * C (the Re-key moves the temporary name to C and links C to B) and destroys B. C is not as the
   * Register left its object: the call stops with the unknown outcome, names C, and changes nothing
   * (C is not activated or named; the old key stays Active and named). Both the unbound and the
   * plan-bound form.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aKeyReKeyedFromALostRegistersKeyIsNeverAdopted(KmipVersion version) throws Exception {
    for (boolean bound : new boolean[] {false, true}) {
      InMemoryKmipServer s = server(version);
      Kms other = connect(s);
      AtomicBoolean armed = new AtomicBoolean();
      AtomicReference<String> theirs = new AtomicReference<>();
      Map<String, String> snapshot = new TreeMap<>();
      Kms kms =
          connect(
              s,
              r -> {
                if (armed.get() && is(r, Operation.REGISTER))
                  s.failNext(ServerOperation.REGISTER, Fault.REPLY_LOST);
                if (is(r, Operation.LOCATE)
                    && LineageTreeTest.names(r, ".replacing-")
                    && armed.getAndSet(false)) {
                  String made = newest(s);
                  theirs.set(
                      meanwhile(
                          () -> {
                            String c = RotationAndNameChoiceTest.reKey(other, made);
                            other
                                .protocol()
                                .call(
                                    dev.keytend.kmip.client.Requests.destroy()
                                        .uniqueIdentifier(made)
                                        .build());
                            return c;
                          }));
                  snapshot.putAll(objects(s));
                }
              });
      KeyHandle old =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named("byok")
              .create();
      KeyAttributes planned = old.attributes();
      KeyRegistration supplied =
          kms.keys()
              .register(new SecretKeySpec(new byte[32], "AES"))
              .named("byok")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
      armed.set(true);
      OutcomeUnknownException e =
          assertThrows(
              OutcomeUnknownException.class,
              () -> {
                if (bound) supplied.replaceResult(old, planned);
                else supplied.replaceResult(old);
              });
      String c = theirs.get();
      assertNotNull(c, "the other caller re-keyed the lost Register's key");
      assertTrue(e.getMessage().contains(c), e.getMessage());
      assertTrue(e.getMessage().contains("not as the Register left its object"), e.getMessage());
      untouched(s, snapshot);
      assertEquals(Optional.of(KeyState.ACTIVE), s.state(old.id()));
      assertEquals(List.of("byok"), s.names(old.id()));
      assertFalse(s.names(c).contains("byok"));
    }
  }

  /**
   * The second case: a secret is replaced with the value {@code wanted}. The Register's reply is
   * lost; before the call looks for its object (B), another caller uses the ordinary API to replace
   * B with its own secret C under B's temporary name (C is Active and has that name), then destroys
   * B. The call never adopts C: it stops with the unknown outcome naming C, leaves C as the other
   * caller left it, and the old secret keeps its name and stays Active.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anotherCallersSecretUnderTheTemporaryNameIsNeverAdopted(KmipVersion version) {
    for (boolean bound : new boolean[] {false, true}) {
      InMemoryKmipServer s = server(version);
      Kms other = connect(s);
      AtomicBoolean armed = new AtomicBoolean();
      AtomicReference<String> theirs = new AtomicReference<>();
      Map<String, String> snapshot = new TreeMap<>();
      Kms kms =
          connect(
              s,
              r -> {
                if (armed.get() && is(r, Operation.REGISTER))
                  s.failNext(ServerOperation.REGISTER, Fault.REPLY_LOST);
                if (is(r, Operation.LOCATE)
                    && LineageTreeTest.names(r, ".replacing-")
                    && armed.getAndSet(false)) {
                  String made = newest(s);
                  String temporary = s.names(made).get(0);
                  theirs.set(
                      meanwhile(
                          () -> {
                            KeyHandle b = other.keys().handle(made);
                            String c =
                                other
                                    .keys()
                                    .registerSecret(
                                        SecretData.Type.PASSWORD,
                                        "someone-else".getBytes(StandardCharsets.UTF_8))
                                    .named(temporary)
                                    .replace(b)
                                    .id();
                            other
                                .protocol()
                                .call(
                                    dev.keytend.kmip.client.Requests.destroy()
                                        .uniqueIdentifier(made)
                                        .build());
                            return c;
                          }));
                  snapshot.putAll(objects(s));
                }
              });
      KeyHandle old = ConflictKindTest.secret(kms, "db").register();
      KeyAttributes planned = old.attributes();
      KeyRegistration wanted =
          kms.keys()
              .registerSecret(SecretData.Type.PASSWORD, "wanted".getBytes(StandardCharsets.UTF_8))
              .named("db");
      armed.set(true);
      OutcomeUnknownException e =
          assertThrows(
              OutcomeUnknownException.class,
              () -> {
                if (bound) wanted.replaceResult(old, planned);
                else wanted.replaceResult(old);
              });
      String c = theirs.get();
      assertNotNull(c, "the other caller replaced the lost Register's object");
      assertTrue(e.getMessage().contains(c), e.getMessage());
      assertEquals(Optional.of(c), e.objectId(), "the stop names the object it concerns");
      untouched(s, snapshot);
      assertEquals(Optional.of(KeyState.ACTIVE), s.state(c));
      assertFalse(s.names(c).contains("db"));
      assertEquals(Optional.of(KeyState.ACTIVE), s.state(old.id()));
      assertEquals(List.of("db"), s.names(old.id()));
    }
  }

  // ---- a transient failure of the unlinked-key search ----

  /**
   * The reply to the search for an earlier call's unlinked key is lost. At the plan, and at the
   * plan-bound call before its first change, that is a transient failure, thrown as it is: never a
   * server that cannot be searched, and never NOT_AS_PLANNED. Nothing is changed.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostReplyToTheUnlinkedKeySearchIsTransient(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    AtomicBoolean armed = new AtomicBoolean();
    Kms kms =
        connect(
            s,
            r -> {
              if (is(r, Operation.LOCATE)
                  && LineageTreeTest.names(r, KeyHandle.REPLACEMENT_OF.name())
                  && armed.getAndSet(false)) s.failNext(ServerOperation.LOCATE, Fault.REPLY_LOST);
            });
    CompromiseLineageCasesTest.Lineage l = lineage(kms, true);
    armed.set(true);
    assertThrows(TransientException.class, () -> l.key().compromisePlan());
    CompromisePlan plan = l.key().compromisePlan();
    assertTrue(plan.checkedForUnlinkedKeys(), "a served search can tell");
    Map<String, String> before = objects(s);
    armed.set(true);
    TransientException e =
        assertThrows(
            TransientException.class,
            () -> l.key().replaceCompromisedResult(compromise(Instant.now()), plan));
    assertEquals(before, objects(s));
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(Instant.now()), plan);
    assertEquals(CompromiseResult.Outcome.COMPLETED, r.outcome(), r.toString());
  }

  // ---- a lost reply to the removal of the temporary name ----

  /**
   * Re-key is refused, the fallback Create's reply comes, and the reply to the removal of its
   * temporary name is lost. Reading back finds the name gone: the call completes, and reports that
   * step as recovered from, naming the replacement it created.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostRemovalOfTheTemporaryNameIsRecoveredFrom(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    AtomicBoolean armed = new AtomicBoolean();
    AtomicBoolean created = new AtomicBoolean();
    Kms kms =
        connect(
            s,
            r -> {
              // The first Delete Attribute after the fallback Create is the temporary name's (KMIP
              // 1.4 removes a name by its index, so the request does not hold the name).
              if (armed.get() && is(r, Operation.CREATE)) created.set(true);
              if (created.get() && is(r, Operation.DELETE_ATTRIBUTE) && armed.getAndSet(false))
                s.failNext(ServerOperation.DELETE_ATTRIBUTE, Fault.REPLY_LOST);
            });
    CompromiseLineageCasesTest.Lineage l = lineage(kms, true);
    CompromisePlan plan = l.key().compromisePlan();
    armed.set(true);
    s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
    CompromiseResult r = l.key().replaceCompromisedResult(compromise(Instant.now()), plan);
    assertFalse(armed.get(), "the removal's reply was lost");
    assertEquals(CompromiseResult.Outcome.RECOVERED, r.outcome(), r.toString());
    assertEquals(List.of(r.replacement()), r.created());
    assertEquals(
        Optional.of(r.replacement().id()), r.recoveredFrom().flatMap(KmsException::objectId));
    assertEquals(List.of(CompromiseLineageCasesTest.NAME), s.names(r.replacement().id()));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(r.replacement().id()));
  }
}
