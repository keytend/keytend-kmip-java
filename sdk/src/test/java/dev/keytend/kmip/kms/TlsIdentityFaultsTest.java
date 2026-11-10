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

import static dev.keytend.kmip.kms.TlsIdentityTest.HOURLY;
import static dev.keytend.kmip.kms.TlsIdentityTest.SCHEDULER;
import static dev.keytend.kmip.kms.TlsIdentityTest.assertWhole;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.kms.TlsIdentityTest.Pki;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * TLS identity calls cut at every request, and every reply lost: readers always present a whole
 * pair, the new one exactly from the new leaf's Activate, which comes after the switch (the old
 * certificate's Replacement link to the new one, or a registration's name), and a repeat finishes
 * the call. What a call cut before its switch registered is left over, Pre-Active and never
 * presented.
 */
class TlsIdentityFaultsTest {
  static final String NAME = "cassandra/node1";

  enum Op {
    REGISTER,
    RENEW,
    REKEY
  }

  /** BEFORE: the request fails and is not processed; AFTER: it is processed and its reply is lost. */
  enum Cut {
    BEFORE,
    AFTER
  }

  static final Set<Operation> MUTATIONS =
      EnumSet.of(
          Operation.REGISTER,
          Operation.ACTIVATE,
          Operation.ADD_ATTRIBUTE,
          Operation.MODIFY_ATTRIBUTE,
          Operation.DELETE_ATTRIBUTE,
          Operation.SET_ATTRIBUTE,
          Operation.REVOKE,
          Operation.DEACTIVATE);

  static Stream<Arguments> cases() {
    List<Arguments> out = new ArrayList<>();
    for (Arguments s : TlsIdentityTest.servers().toList())
      for (Op op : Op.values()) out.add(Arguments.of(s.get()[0], s.get()[1], op));
    return out.stream();
  }

  /** The material of one test: the same certificates on a fresh server for each cut. */
  static final class Material {
    final Pki pki = new Pki();
    final KeyPair k1 = TestPki.ec(), k2 = TestPki.ec();
    final Issued first = pki.leaf("node1", k1),
        renewed = pki.leaf("node1", k1),
        rekeyed = pki.leaf("node1", k2);

    Material() throws Exception {}

    Issued next(Op op) {
      return switch (op) {
        case REGISTER -> first;
        case RENEW -> renewed;
        case REKEY -> rekeyed;
      };
    }
  }

  /** A server with the identity registered (unless the call is the registration), and a writer and a reader. */
  static final class Scenario implements AutoCloseable {
    final InMemoryKmipServer server, replica;
    final Kms writer, reader;
    final TlsIdentityHandle start;
    final TlsIdentityFollower warm;
    final Material m;
    final Op op;

    /** Run before each of the writer's requests, when set. */
    volatile Runnable beforeEachRequest;

    Scenario(KmipVersion version, boolean unique, Material m, Op op, RetryPolicy retry) {
      this.m = m;
      this.op = op;
      server = InMemoryKmipServer.of(version).uniqueNames(unique);
      replica = server.replica();
      dev.keytend.kmip.transport.KmipTransport probed =
          new dev.keytend.kmip.transport.KmipTransport() {
            @Override
            public Ttlv exchange(Ttlv request) throws IOException {
              return exchange(request, dev.keytend.kmip.transport.CallContext.NONE);
            }

            @Override
            public Ttlv exchange(Ttlv request, dev.keytend.kmip.transport.CallContext context)
                throws IOException {
              Runnable r = beforeEachRequest;
              if (r != null) r.run();
              return server.exchange(request, context);
            }
          };
      writer =
          Kms.connect(
              server
                  .configure()
                  .transport(e -> probed)
                  .maximumVersion(KmipVersion.V3_0)
                  .retryPolicy(retry)
                  .callTimeout(Duration.ofSeconds(10))
                  .build());
      reader =
          Kms.connect(
              replica
                  .configure()
                  .maximumVersion(KmipVersion.V3_0)
                  .callTimeout(Duration.ofSeconds(10))
                  .build());
      start =
          op == Op.REGISTER
              ? null
              : writer
                  .tls()
                  .register(m.k1.getPrivate(), m.pki.chain(m.first))
                  .named(NAME)
                  .register();
      warm = op == Op.REGISTER ? null : reader.tls().follow(NAME, HOURLY, SCHEDULER);
    }

    TlsIdentityHandle run() {
      return switch (op) {
        case REGISTER ->
            writer.tls().register(m.k1.getPrivate(), m.pki.chain(m.first)).named(NAME).register();
        case RENEW -> start.renew(m.pki.chain(m.renewed));
        case REKEY -> start.rekey(m.k2.getPrivate(), m.pki.chain(m.rekeyed));
      };
    }

    /**
     * Whether the new leaf is presented: the switch is made (the old certificate links to a new
     * one, which only the call links; for a registration, a certificate has the name), and that
     * certificate is Active.
     */
    boolean presented() {
      List<String> next =
          op != Op.REGISTER
              ? server.links(start.certificate().id(), LinkKind.REPLACEMENT)
              : server.ids().stream().filter(id -> server.names(id).contains(NAME)).toList();
      return next.stream().anyMatch(id -> server.state(id).orElse(null) == KeyState.ACTIVE);
    }

    /**
     * Readers present a whole pair: the new one from the new leaf's Activate, the old one before. A
     * registration's identity is found once the leaf has the name, which it is given Pre-Active:
     * until its Activate a follower cannot start (StateConflictException).
     */
    void assertReaders(String when) {
      boolean fresh = presented();
      X509Certificate expected =
          fresh ? m.next(op).certificate() : op == Op.REGISTER ? null : m.first.certificate();
      if (warm != null) {
        TlsIdentityFollower.State s = warm.refresh();
        assertTrue(
            s.status() == TlsIdentityFollower.Status.CURRENT
                || s.status() == TlsIdentityFollower.Status.REPLACING,
            when + ": " + s);
        assertEquals(expected, assertWhole(warm).certificate(), when + ": " + s);
      }
      try (TlsIdentityFollower cold = reader.tls().follow(NAME, HOURLY, SCHEDULER)) {
        assertEquals(expected, assertWhole(cold).certificate(), when + ": " + cold.state());
      } catch (NotFoundException none) {
        assertEquals(Op.REGISTER, op, when + ": " + none.getMessage());
        assertFalse(fresh, when);
      } catch (StateConflictException notYet) {
        assertEquals(Op.REGISTER, op, when + ": " + notYet.getMessage());
        assertFalse(fresh, when);
        assertTrue(
            notYet.getMessage().contains("is PRE_ACTIVE"), when + ": " + notYet.getMessage());
      }
    }

    /**
     * After the call finished: the new pair, the old one retired, no temporary name or record of
     * the name being moved on the identity's objects. When {@code once}, nothing else was
     * registered; otherwise what a cut call registered is left over: Pre-Active, never presented,
     * with no name but a temporary one, and not linked from the old certificate.
     */
    void assertFinished(TlsIdentityHandle done, String when, boolean once) {
      assertEquals(
          m.next(op).certificate(),
          TlsIdentities.certificate(reader, done.certificate().id()),
          when);
      assertReaders(when);
      if (warm != null)
        assertEquals(done.certificate().id(), warm.identity().orElseThrow().certificateId(), when);
      if (op != Op.REGISTER) {
        assertEquals(
            KeyState.DEACTIVATED, server.state(start.certificate().id()).orElseThrow(), when);
        assertEquals(
            op == Op.REKEY ? KeyState.DEACTIVATED : KeyState.ACTIVE,
            server.state(start.privateKey().id()).orElseThrow(),
            when);
        assertEquals(List.of(), server.names(start.certificate().id()), when);
      }
      assertEquals(List.of(NAME), server.names(done.certificate().id()), when);
      if (op != Op.REGISTER)
        assertEquals(
            List.of(done.certificate().id()),
            server.links(start.certificate().id(), LinkKind.REPLACEMENT),
            when);
      long sameLeaf =
          reader.tls().certificates(KeyQuery.all()).values().stream()
              .filter(m.next(op).certificate()::equals)
              .count();
      if (once) assertEquals(1, sameLeaf, when + ": the new leaf was registered once");
      java.util.Set<String> identity = new java.util.HashSet<>();
      identity.add(done.privateKey().id());
      for (KeyHandle c : done.chain()) identity.add(c.id());
      if (start != null) {
        identity.add(start.privateKey().id());
        for (KeyHandle c : start.chain()) identity.add(c.id());
      }
      for (String id : server.ids()) {
        assertTrue(
            server.protocolAttributes(id).keySet().stream().noneMatch(a -> a.contains("pending")),
            when + ": " + id);
        if (identity.contains(id)) {
          assertTrue(
              server.names(id).stream().noneMatch(n -> n.contains(".issuing-")),
              when + ": " + server.names(id));
          continue;
        }
        assertFalse(once, when + ": " + id + " was left over");
        assertEquals(
            java.util.Optional.of(KeyState.PRE_ACTIVE),
            server.state(id),
            when + ": the leftover " + id + " is Pre-Active");
        assertTrue(
            server.names(id).stream().allMatch(n -> n.startsWith(NAME + ".issuing-")),
            when + ": the leftover " + id + " has the names " + server.names(id));
      }
      assertEquals(List.of(), server.violations(), when);
    }

    @Override
    public void close() {
      if (warm != null) warm.close();
      writer.close();
      reader.close();
    }
  }

  /** The requests the call sends when nothing fails. */
  static int requests(KmipVersion version, boolean unique, Material m, Op op) {
    try (Scenario s = new Scenario(version, unique, m, op, RetryPolicy.none())) {
      int before = s.server.exchanges();
      s.assertFinished(s.run(), "no fault", true);
      return s.server.exchanges() - before;
    }
  }

  @ParameterizedTest
  @MethodSource("cases")
  void aCallCutAtAnyRequestLeavesReadersAWholePairAndARepeatFinishesIt(
      KmipVersion version, boolean unique, Op op) throws Exception {
    Material m = new Material();
    int n = requests(version, unique, m, op);
    assertTrue(n > 5, "requests: " + n);
    for (Cut cut : Cut.values())
      for (int k = 1; k <= n; k++) {
        String when = op + " " + cut + " request " + k + " of " + n;
        try (Scenario s = new Scenario(version, unique, m, op, RetryPolicy.none())) {
          int[] seen = {0};
          int at = k;
          Function<Ttlv, IOException> fault =
              r ->
                  ++seen[0] == at
                      ? (cut == Cut.BEFORE
                          ? new IOException("cut at " + at)
                          : new SocketTimeoutException("reply " + at + " lost"))
                      : null;
          if (cut == Cut.BEFORE) s.server.injectBeforeProcessing(fault);
          else s.server.injectAfterProcessing(fault);
          TlsIdentityHandle done = null;
          try {
            done = s.run();
          } catch (PartialCompletionException
              | OutcomeUnknownException
              | TransientException stopped) {
            assertTrue(
                !(stopped instanceof PartialCompletionException)
                    || stopped
                        .getMessage()
                        .contains("repeat " + op.name().toLowerCase(Locale.ROOT)),
                when + ": " + stopped.getMessage());
          }
          s.server.injectBeforeProcessing(null);
          s.server.injectAfterProcessing(null);
          s.assertReaders(when);
          if (done == null) done = s.run();
          s.assertFinished(done, when, false);
        }
      }
  }

  /**
   * Readers between any two requests of the call: the old pair until the new certificate's
   * Activate, the new one from it on, whole each time, never nothing.
   */
  @ParameterizedTest
  @MethodSource("cases")
  void aReaderBetweenAnyTwoRequestsOfTheCallPresentsAWholePair(
      KmipVersion version, boolean unique, Op op) throws Exception {
    Material m = new Material();
    try (Scenario s = new Scenario(version, unique, m, op, RetryPolicy.none())) {
      int[] probes = {0};
      s.beforeEachRequest = probe(s, probes, op);
      TlsIdentityHandle done = s.run();
      s.beforeEachRequest = null;
      assertTrue(probes[0] > 5, "probes: " + probes[0]);
      s.assertFinished(done, op + " after", true);
    }
  }

  /** The probe that checks the readers and re-arms itself (it is off while the readers read). */
  private Runnable probe(Scenario s, int[] probes, Op op) {
    return () -> {
      s.beforeEachRequest = null;
      try {
        s.assertReaders(op + " before request " + ++probes[0]);
      } finally {
        s.beforeEachRequest = probe(s, probes, op);
      }
    };
  }

  @ParameterizedTest
  @MethodSource("cases")
  void everyLostReplyIsReadBackWithinTheCall(KmipVersion version, boolean unique, Op op)
      throws Exception {
    Material m = new Material();
    int mutations;
    try (Scenario s = new Scenario(version, unique, m, op, RetryPolicy.defaults())) {
      int before = s.server.protocolRequests().size();
      s.run();
      mutations =
          (int)
              s
                  .server
                  .protocolRequests()
                  .subList(before, s.server.protocolRequests().size())
                  .stream()
                  .filter(TlsIdentityFaultsTest::mutation)
                  .count();
    }
    for (int k = 1; k <= mutations; k++) {
      String when = op + " mutation " + k + " of " + mutations;
      try (Scenario s = new Scenario(version, unique, m, op, RetryPolicy.defaults())) {
        int[] seen = {0};
        int at = k;
        s.server.injectAfterProcessing(
            r -> mutation(r) && ++seen[0] == at ? new SocketTimeoutException("reply lost") : null);
        TlsIdentityHandle done = assertDoesNotThrow(s::run, when);
        s.server.injectAfterProcessing(null);
        s.assertFinished(done, when, true);
      }
    }
  }

  static boolean mutation(Ttlv request) {
    int code = Faults.operation(request);
    return MUTATIONS.stream().anyMatch(o -> o.code() == code);
  }
}
