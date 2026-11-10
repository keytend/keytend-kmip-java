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

import static dev.keytend.kmip.kms.TlsIssueTest.NAME;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Predicate;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * An issue or reissue stopped dead at each of its writes, before the server sees the write or
 * after it processed it, and repeated from a new client, as {@code register}, {@code renew} and
 * {@code rekey} are ({@link TlsRepeatTest}): the repeat finishes with an identity that holds what
 * was asked, and leaves nothing of the stopped call Active. And a lost race, refused as a renewal's
 * is.
 */
class TlsIssueRepeatTest {
  enum Op {
    ISSUE,
    REISSUE,
    REISSUE_NEW_KEY
  }

  static Stream<Arguments> cases() {
    List<Arguments> out = new ArrayList<>();
    for (Arguments s : TlsIdentityTest.servers().toList())
      for (Op op : Op.values())
        for (boolean after : new boolean[] {false, true})
          out.add(Arguments.of(s.get()[0], s.get()[1], op, after));
    return out.stream();
  }

  /** A server with an issuer (and, for a reissue, an issued identity), and a client that stops. */
  static final class Scenario implements AutoCloseable {
    final InMemoryKmipServer server;
    final Kms setup;
    final TlsIssuer issuer;
    final TlsIdentityHandle start;
    final Set<String> issuerObjects = new HashSet<>();
    volatile int stopAt;
    volatile boolean stopAfter;
    volatile Predicate<Ttlv> hook = r -> false;
    volatile Runnable onHook = () -> {};
    int writes;

    Scenario(KmipVersion version, boolean unique, TlsIssueTest.Ca ca, boolean issued) {
      server = InMemoryKmipServer.of(version).uniqueNames(unique);
      setup = TlsIdentityTest.connect(server);
      issuer = TlsIssueTest.register(setup, ca);
      issuerObjects.addAll(
          List.of(issuer.certificate().id(), issuer.publicKey().id(), issuer.privateKey().id()));
      start = issued ? TlsIssueTest.request(setup, issuer).issue() : null;
    }

    Kms stopping() {
      return Kms.connect(
          server
              .configure()
              .maximumVersion(KmipVersion.V3_0)
              .retryPolicy(RetryPolicy.none())
              .transport(e -> this::exchange)
              .build());
    }

    private Ttlv exchange(Ttlv r) throws IOException {
      if (hook.test(r)) {
        hook = x -> false;
        onHook.run();
      }
      boolean write = TlsOwnershipTest.write(r) != null;
      if (write && ++writes == stopAt && !stopAfter) throw new TlsOwnershipTest.Stop();
      Ttlv reply = server.exchange(r);
      if (write && writes == stopAt) throw new TlsOwnershipTest.Stop();
      return reply;
    }

    /** {@code op} on {@code kms}: from {@link #start}'s objects for a reissue. */
    TlsIdentityHandle run(Kms kms, Op op) {
      if (op == Op.ISSUE) return TlsIssueTest.request(kms, issuer).issue();
      TlsIdentityHandle from =
          new TlsIdentityHandle(
              kms.tls(),
              NAME,
              kms.keys().handle(start.certificate().id()),
              kms.keys().handle(start.privateKey().id()),
              start.chain());
      return op == Op.REISSUE ? from.reissue() : from.reissueWithNewKey();
    }

    @Override
    public void close() {
      setup.close();
    }
  }

  @ParameterizedTest
  @MethodSource("cases")
  void aRepeatAfterAStopAtEachWriteFinishes(
      KmipVersion version, boolean unique, Op op, boolean after) throws Exception {
    TlsIssueTest.Ca ca = TlsIssueTest.Ca.ec("Issuing CA");
    int stops = 0;
    for (int n = 1; ; n++) {
      try (Scenario s = new Scenario(version, unique, ca, op != Op.ISSUE)) {
        s.stopAt = n;
        s.stopAfter = after;
        boolean stopped;
        try (Kms job = s.stopping()) {
          s.run(job, op);
          stopped = false;
        } catch (TlsOwnershipTest.Stop stop) {
          stopped = true;
        }
        if (!stopped) break;
        stops++;
        TlsIdentityHandle done;
        try (Kms repeat = TlsIdentityTest.connect(s.server)) {
          try {
            done = s.run(repeat, op);
          } catch (KmsException e) {
            throw new AssertionError("stop at write " + n + (after ? " (after)" : ""), e);
          }
          TlsIdentityHandle current = repeat.tls().identity(NAME).orElseThrow();
          assertEquals(done.toString(), current.toString(), "write " + n);
          assertEquals(KeyState.ACTIVE, s.server.state(done.certificate().id()).orElseThrow());
          X509Certificate leaf = TlsIdentities.certificate(repeat, done.certificate().id());
          assertEquals("CN=node1,O=cluster1", leaf.getSubjectX500Principal().getName());
          leaf.verify(ca.certificate.getPublicKey());
          if (s.start != null) {
            assertEquals(
                KeyState.DEACTIVATED,
                s.server.state(s.start.certificate().id()).orElseThrow(),
                "write " + n);
            assertEquals(
                op == Op.REISSUE,
                done.privateKey().id().equals(s.start.privateKey().id()),
                "write " + n);
          }
          // Nothing of the stopped call is Active but what the identity is now, and a new private
          // key it activated to sign its request, which no Active certificate certifies.
          Set<String> allowed = new HashSet<>(s.issuerObjects);
          allowed.add(done.certificate().id());
          allowed.add(done.privateKey().id());
          allowed.addAll(s.server.links(done.privateKey().id(), LinkKind.PUBLIC_KEY));
          Set<String> active = TlsIssueTest.active(s.server);
          active.removeAll(allowed);
          for (String id : Set.copyOf(active))
            if (s.server.kind(id).orElseThrow() == ObjectKind.PRIVATE_KEY
                && !id.equals(s.start == null ? null : s.start.privateKey().id())
                && s.server.links(id, LinkKind.PUBLIC_KEY).stream()
                    .allMatch(p -> s.server.state(p).orElseThrow() != KeyState.ACTIVE)
                && s.server.ids().stream()
                    .filter(c -> s.server.kind(c).orElseThrow() == ObjectKind.CERTIFICATE)
                    .filter(
                        c ->
                            s.server.links(c, LinkKind.PRIVATE_KEY).contains(id)
                                || s.server
                                    .links(c, LinkKind.PUBLIC_KEY)
                                    .containsAll(s.server.links(id, LinkKind.PUBLIC_KEY)))
                    .allMatch(c -> s.server.state(c).orElseThrow() != KeyState.ACTIVE))
              active.remove(id);
          assertEquals(Set.of(), active, "write " + n + (after ? " (after)" : ""));
          // The identity's objects keep no temporary name.
          for (String id : allowed)
            if (s.server.state(id).orElseThrow() == KeyState.ACTIVE)
              assertTrue(
                  s.server.names(id).stream().noneMatch(x -> x.contains(".issuing-")),
                  id + " " + s.server.names(id));
          // Certify linked the public key to each certificate it issued for it, the stopped call's
          // too: those it links to besides the leaf and what it replaced are not Active.
          for (String pub : s.server.links(done.privateKey().id(), LinkKind.PUBLIC_KEY))
            for (String c : s.server.links(pub, LinkKind.CERTIFICATE))
              if (!c.equals(done.certificate().id())
                  && (s.start == null || !c.equals(s.start.certificate().id())))
                assertNotEquals(
                    KeyState.ACTIVE, s.server.state(c).orElseThrow(), "write " + n + ": " + c);
          assertEquals(List.of(), s.server.violations());
          // The identity stays usable: a later reissue of it succeeds.
          TlsIdentityHandle next =
              op == Op.REISSUE_NEW_KEY ? done.reissueWithNewKey() : done.reissue();
          assertEquals(
              next.certificate().id(),
              repeat.tls().identity(NAME).orElseThrow().certificate().id(),
              "write " + n);
        }
      }
      assertTrue(n < 80, "the call ends");
    }
    assertTrue(stops > 8, "stops: " + stops);
  }

  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void aLostRaceIsRefusedAsARenewalsIs(KmipVersion version, boolean unique) throws Exception {
    TlsIssueTest.Ca ca = TlsIssueTest.Ca.ec("Issuing CA");
    try (Scenario s = new Scenario(version, unique, ca, true)) {
      String old = s.start.certificate().id();
      // Another reissue finishes first, from the same handle: this one is refused at once.
      TlsIdentityHandle theirs = s.start.reissue();
      try (Kms job = TlsIdentityTest.connect(s.server)) {
        TlsIdentityHandle mine =
            new TlsIdentityHandle(
                job.tls(),
                NAME,
                job.keys().handle(old),
                job.keys().handle(s.start.privateKey().id()),
                s.start.chain());
        // From the old handle, a same-key reissue returns the identity it finds made.
        assertEquals(theirs.certificate().id(), mine.reissue().certificate().id());
        StateConflictException replaced =
            assertThrows(StateConflictException.class, mine::reissueWithNewKey);
        assertEquals(StateConflictException.Conflict.REPLACED, replaced.conflict());
        assertTrue(
            replaced.getMessage().contains("it was renewed or re-keyed meanwhile"),
            replaced.getMessage());
      }
    }
    try (Scenario s = new Scenario(version, unique, ca, true)) {
      String old = s.start.certificate().id();
      // Another reissue switches in just before this one's switch: this one loses the race.
      s.hook = r -> TlsIdentityLifecycleTest.addsReplacementLink(r, old);
      s.onHook = () -> s.start.reissueWithNewKey();
      try (Kms job = s.stopping()) {
        int before = s.server.ids().size();
        StateConflictException lost =
            assertThrows(StateConflictException.class, () -> s.run(job, Op.REISSUE_NEW_KEY));
        assertEquals(StateConflictException.Conflict.REPLACED, lost.conflict());
        assertTrue(lost.getMessage().contains("was replaced meanwhile by"), lost.getMessage());
        assertTrue(lost.getMessage().contains("are left over"), lost.getMessage());
        String winner = s.server.links(old, LinkKind.REPLACEMENT).get(0);
        assertEquals(winner, job.tls().identity(NAME).orElseThrow().certificate().id());
        // This call's three objects, and the winner's three: this call's are not Active.
        List<String> made = new ArrayList<>(s.server.ids().subList(before, s.server.ids().size()));
        assertEquals(6, made.size(), made.toString());
        for (String id : made.subList(0, 3)) {
          assertTrue(lost.getMessage().contains(id), lost.getMessage());
          // The private key, activated to sign the request; the public key and the leaf.
          assertEquals(
              id.equals(made.get(0)) ? KeyState.ACTIVE : KeyState.PRE_ACTIVE,
              s.server.state(id).orElseThrow(),
              id);
        }
      }
    }
  }
}
