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

import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.Attributes;
import dev.keytend.kmip.model.Enums;
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
 * A lost request's object is taken as the request's own only when it is linked to nothing, as the
 * request left it; a stop names the one object it concerns ({@link KmsException#objectId()}) and
 * says every property it checked; an object the plan's search located and could not read is named
 * by the plan, past the first objects a search reads too. Other callers' changes and faults are
 * armed from the client's transport as each request goes out, so each case is deterministic.
 */
class RecoveryEvidenceTest {
  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

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
   * A symmetric key is registered to replace the key named {@code byok}, and the Register's reply
   * is lost. Before the call looks for its object (B), another caller links B to another object (a
   * Derivation Base Object link, which is neither a Replacement nor a Replaced Object link). B is
   * not as the Register left it, linked to nothing: the call stops with the unknown outcome, names
   * B (also as its objectId()), and changes nothing (B is not activated or named; the old key stays
   * Active and named). Both the unbound and the plan-bound form.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anObjectAnotherCallerLinkedIsNeverAdopted(KmipVersion version) {
    for (boolean bound : new boolean[] {false, true}) {
      InMemoryKmipServer s = server(version);
      Kms other = connect(s);
      AtomicBoolean armed = new AtomicBoolean();
      AtomicReference<String> linked = new AtomicReference<>();
      AtomicReference<String> base = new AtomicReference<>();
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
                  meanwhile(
                      () ->
                          other
                              .protocol()
                              .call(
                                  Requests.addAttribute()
                                      .uniqueIdentifier(made)
                                      .attribute(
                                          Attributes.link(
                                              Enums.LinkType.DERIVATION_BASE_OBJECT_LINK,
                                              base.get()))
                                      .build()));
                  linked.set(made);
                  snapshot.putAll(objects(s));
                }
              });
      KeyHandle old =
          kms.keys()
              .createAes(256)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named("byok")
              .create();
      base.set(old.id());
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
      String b = linked.get();
      assertNotNull(b, "the other caller linked the lost Register's key");
      assertEquals(List.of(old.id()), s.links(b, LinkKind.DERIVATION_BASE));
      assertTrue(e.getMessage().contains(b), e.getMessage());
      assertTrue(e.getMessage().contains("not as the Register left its object"), e.getMessage());
      assertEquals(Optional.of(b), e.objectId(), "the stop names the object it concerns");
      untouched(s, snapshot);
      assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(b));
      assertFalse(s.names(b).contains("byok"));
      assertEquals(Optional.of(KeyState.ACTIVE), s.state(old.id()));
      assertEquals(List.of("byok"), s.names(old.id()));
    }
  }

  /**
   * Re-key is refused and the fallback Create's reply is lost. Before the call looks for its key
   * (B), another caller removes B's record of the key it replaces, so B fails only that check. The
   * stop says the record was required ("recording" the key), names B as its objectId(), keeps its
   * revocation, and changes nothing of B.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aHolderWithoutTheRecordIsToldApartByTheRecord(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms other = connect(s);
    AtomicBoolean armed = new AtomicBoolean();
    AtomicReference<String> changed = new AtomicReference<>();
    Map<String, String> snapshot = new TreeMap<>();
    Kms kms =
        connect(
            s,
            r -> {
              if (is(r, Operation.LOCATE)
                  && LineageTreeTest.names(r, KeyHandle.TEMPORARY)
                  && armed.getAndSet(false)) {
                String made = newest(s);
                meanwhile(
                    () -> {
                      other
                          .keys()
                          .handle(made)
                          .removeCustomAttribute(CompromisePlan.REPLACEMENT_RECORD);
                      return made;
                    });
                changed.set(made);
                snapshot.putAll(objects(s));
              }
            });
    CompromiseLineageCasesTest.Lineage l = lineage(kms, false);
    CompromisePlan plan = l.key().compromisePlan();
    armed.set(true);
    s.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
    s.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> l.key().replaceCompromisedResult(compromise(Instant.now()), plan));
    String b = changed.get();
    assertNotNull(b, "the other caller changed the lost Create's key");
    assertEquals(List.of(l.key().id()), ids(e.deactivated()));
    assertEquals(List.of(), e.created());
    assertTrue(e.getMessage().contains("not as the Create left a key"), e.getMessage());
    assertTrue(
        e.getMessage().contains("with that name alone, recording " + l.key().id()), e.getMessage());
    assertEquals(Optional.of(b), e.objectId(), "the stop names the object it concerns");
    snapshot.remove(l.key().id());
    untouched(s, snapshot);
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(b));
  }

  /**
   * The plan's search for an earlier call's unlinked key locates more objects than its first read
   * takes ({@link Lineage#FANOUT}): 40 objects record the key, and the last cannot be read. The
   * search cannot tell, so the plan says it could not check, and names that object ({@link
   * CompromisePlan#unreadableCandidates()}). Once it can be read, the plan checks.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anUnreadableObjectPastTheFirstReadIsNamedByThePlan(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    AtomicReference<String> hidden = new AtomicReference<>();
    Kms kms = connect(s, RecoveryCandidatesTest.hiding(s, hidden));
    CompromiseLineageCasesTest.Lineage l = lineage(kms, true);
    // Objects that record the key but are not keys made to replace it (Secret Data): read, matched
    // by the search, and passed over by the plan.
    List<String> recording = new ArrayList<>();
    for (int i = 0; i < Lineage.FANOUT + 8; i++)
      recording.add(
          kms.keys()
              .registerSecret(SecretData.Type.PASSWORD, ("s" + i).getBytes(StandardCharsets.UTF_8))
              .custom(CompromisePlan.REPLACEMENT_RECORD, l.key().id())
              .register()
              .id());
    String last = recording.get(recording.size() - 1);
    hidden.set(last);
    CompromisePlan plan = l.key().compromisePlan();
    assertFalse(plan.checkedForUnlinkedKeys(), plan.toString());
    assertEquals(List.of(last), plan.unreadableCandidates());
    assertTrue(plan.toString().contains("cannot read [" + last + "]"), plan.toString());

    hidden.set(null);
    CompromisePlan readable = l.key().compromisePlan();
    assertTrue(readable.checkedForUnlinkedKeys(), readable.toString());
    assertEquals(List.of(), readable.unreadableCandidates());
  }
}
