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

import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Secret replacement: a step recovered before a later one fails stays on the partial completion,
 * and the old object's deactivation is reported as recovered from even after an earlier lost reply.
 * Faults are armed from the client's transport as the requests go out.
 */
class SecretReplacementRecoveryTest {
  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
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

  static boolean is(Ttlv request, Operation operation) {
    return RotationAndNameChoiceTest.isOperation(request, operation);
  }

  static ServerOperation retire(KmipVersion version) {
    return version == KmipVersion.V3_0 ? ServerOperation.DEACTIVATE : ServerOperation.REVOKE;
  }

  /**
   * The Register's reply is lost (the new object is found by its temporary name), then its Activate
   * is refused. The partial completion lists the new object, its cause is the refusal, and the lost
   * Register is still recoveredFrom(), suppressed on it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRecoveredRegisterIsKeptWhenTheActivationFails(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicBoolean armed = new AtomicBoolean();
    Kms kms =
        connect(
            s,
            r -> {
              if (!armed.get()) return;
              if (is(r, Operation.REGISTER)) s.failNext(ServerOperation.REGISTER, Fault.REPLY_LOST);
              else if (is(r, Operation.ACTIVATE))
                s.failNext(ServerOperation.ACTIVATE, Fault.PERMISSION_DENIED);
            });
    KeyHandle old = ConflictKindTest.secret(kms, "db").register();
    armed.set(true);
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> ConflictKindTest.secret(kms, "db").replaceResult(old));
    assertEquals(1, e.created().size(), e.getMessage());
    assertInstanceOf(PermissionDeniedException.class, e.getCause());
    OutcomeUnknownException lost = e.recoveredFrom().orElseThrow();
    assertTrue(Arrays.asList(e.getSuppressed()).contains(lost), "suppressed on it too");
    assertEquals(List.of("db"), s.names(old.id()), "the old object keeps the name");
  }

  /**
   * The Activate's reply is lost (read back Active), then adding the name is refused. The lost
   * Activate stays on the partial completion.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRecoveredActivationIsKeptWhenTheNameMoveFails(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicBoolean armed = new AtomicBoolean(), activated = new AtomicBoolean();
    Kms kms =
        connect(
            s,
            r -> {
              if (!armed.get()) return;
              if (is(r, Operation.ACTIVATE) && !activated.getAndSet(true))
                s.failNext(ServerOperation.ACTIVATE, Fault.REPLY_LOST);
              else if (activated.get() && is(r, Operation.ADD_ATTRIBUTE))
                s.failNext(ServerOperation.ADD_ATTRIBUTE, Fault.PERMISSION_DENIED);
            });
    KeyHandle old = ConflictKindTest.secret(kms, "db").register();
    armed.set(true);
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> ConflictKindTest.secret(kms, "db").replaceResult(old));
    assertInstanceOf(PermissionDeniedException.class, e.getCause(), e.getMessage());
    OutcomeUnknownException lost = e.recoveredFrom().orElseThrow();
    assertEquals(Optional.of(e.created().get(0).id()), lost.objectId(), "the lost Activate");
  }

  /**
   * The Register's reply and the deactivation's are both lost. recoveredFrom() is the first (the
   * Register); deactivationRecoveredFrom() is the deactivation, naming the old object.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostDeactivationIsReportedAfterALostRegister(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicBoolean armed = new AtomicBoolean();
    Kms kms =
        connect(
            s,
            r -> {
              if (!armed.get()) return;
              if (is(r, Operation.REGISTER)) s.failNext(ServerOperation.REGISTER, Fault.REPLY_LOST);
              else if (is(r, Operation.REVOKE) || is(r, Operation.DEACTIVATE))
                s.failNext(retire(version), Fault.REPLY_LOST);
            });
    KeyHandle old = ConflictKindTest.secret(kms, "db").register();
    armed.set(true);
    ReplacementResult r = ConflictKindTest.secret(kms, "db").replaceResult(old);
    assertEquals(KeyState.DEACTIVATED, r.previousState());
    assertFalse(r.deactivatedPrevious());
    assertEquals(Optional.empty(), r.recoveredFrom().orElseThrow().objectId(), "the Register");
    assertEquals(Optional.of(old.id()), r.deactivationRecoveredFrom().orElseThrow().objectId());
  }

  /** Every reply came, or only the Register's was lost: no deactivation was recovered from. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aConfirmedDeactivationIsNotRecoveredFrom(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    AtomicBoolean armed = new AtomicBoolean();
    Kms kms =
        connect(
            s,
            r -> {
              if (armed.get() && is(r, Operation.REGISTER))
                s.failNext(ServerOperation.REGISTER, Fault.REPLY_LOST);
            });
    KeyHandle old = ConflictKindTest.secret(kms, "db").register();
    armed.set(true);
    ReplacementResult r = ConflictKindTest.secret(kms, "db").replaceResult(old);
    assertTrue(r.deactivatedPrevious());
    assertTrue(r.recoveredFrom().isPresent());
    assertEquals(Optional.empty(), r.deactivationRecoveredFrom());
  }

  /**
   * The rule for secret replacement: a lost Register's reply is settled by its temporary name, and
   * a search that cannot tell (refused, or an unfiltered list capped before the object) is never
   * taken for "none". The message then says the server could not be searched and gives the name,
   * and never that no object was found. A server that ignores the name filter returns the object
   * among every object, but cannot show it is the only one with the name: the call names it and
   * stops, leaving it as it is.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aLostRegisterIsNeverTakenForAbsentWhenItsNameCannotBeSearched(KmipVersion version) {
    for (CompromiseLineageCasesTest.Search how : CompromiseLineageCasesTest.Search.values()) {
      InMemoryKmipServer s = server(version);
      AtomicBoolean armed = new AtomicBoolean();
      AtomicReference<CompromiseLineageCasesTest.Search> search = new AtomicReference<>(how);
      Kms kms =
          searchingClient(
              s,
              search,
              ".replacing-",
              r -> {
                if (armed.get() && is(r, Operation.REGISTER) && armed.getAndSet(false))
                  s.failNext(ServerOperation.REGISTER, Fault.REPLY_LOST);
              });
      for (int i = 0; i < 40; i++) ConflictKindTest.secret(kms, "other-" + i).register();
      KeyHandle old = ConflictKindTest.secret(kms, "db").register();
      armed.set(true);
      boolean ignores = how == CompromiseLineageCasesTest.Search.IGNORES;
      OutcomeUnknownException e =
          assertThrows(
              OutcomeUnknownException.class,
              () -> ConflictKindTest.secret(kms, "db").replaceResult(old),
              how.name());
      String made = s.ids().get(s.ids().size() - 1);
      String temporary = s.names(made).get(0);
      assertTrue(temporary.startsWith("db.replacing-"), temporary);
      assertTrue(e.getMessage().contains(temporary), e.getMessage());
      assertTrue(
          e.getMessage()
              .contains(ignores ? made + " has its temporary name" : "could not be searched"),
          e.getMessage());
      assertFalse(e.getMessage().contains("no object has"), e.getMessage());
      assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(made), "left as it is");
      assertEquals(List.of("db"), s.names(old.id()), "the old object keeps the name");
    }
  }

  /** {@link CompromiseLineageCasesTest#searching}, for this class's servers. */
  Kms searchingClient(
      InMemoryKmipServer s,
      AtomicReference<CompromiseLineageCasesTest.Search> search,
      String text,
      Consumer<Ttlv> before) {
    CompromiseLineageCasesTest cases = new CompromiseLineageCasesTest();
    Kms kms = cases.searching(s, search, text, before);
    clients.add(kms);
    return kms;
  }
}
