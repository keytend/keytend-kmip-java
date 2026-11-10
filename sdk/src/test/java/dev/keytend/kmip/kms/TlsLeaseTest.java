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
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.LeasingTransport.Grant;
import dev.keytend.kmip.kms.LeasingTransport.Hang;
import dev.keytend.kmip.kms.LeasingTransport.Malformed;
import dev.keytend.kmip.kms.LeasingTransport.Refuse;
import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.kms.TlsIdentityTest.Pki;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.net.ConnectException;
import java.net.Socket;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Delayed;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * KMIP Lease Time and the TLS followers (M-A2): every object a follower keeps for use
 * that states a Lease Time is used only while a lease Obtain Lease granted runs, measured from the
 * request's send time on a clock the test moves; checked at each use without a request or a lock.
 */
class TlsLeaseTest {
  static final long SECOND = 1_000_000_000L;
  static final CustomAttribute TAG = CustomAttribute.client("tls-lease");
  static final String NAME = "lease/node";

  /** A leasing server (none stated unless a test says so), a CA with an intermediate, a fake clock. */
  static final class Fixture implements AutoCloseable {
    final InMemoryKmipServer server;
    final LeasingTransport leasing;
    final Kms kms;
    final Pki pki = new Pki();
    final AtomicLong now = new AtomicLong();
    final List<String> changes = new CopyOnWriteArrayList<>();
    final List<AutoCloseable> closing = new ArrayList<>();

    Fixture(KmipVersion version, boolean unique) throws Exception {
      server = InMemoryKmipServer.of(version).uniqueNames(unique);
      leasing = new LeasingTransport(server);
      KmsListener listener =
          new KmsListener() {
            @Override
            public void keyStateChanged(String id, KeyState from, KeyState to) {
              changes.add(id + " " + from + "->" + to);
            }
          };
      kms =
          Kms.connect(
              server
                  .configure()
                  .maximumVersion(KmipVersion.V3_0)
                  .callTimeout(Duration.ofSeconds(10))
                  .retryPolicy(RetryPolicy.none())
                  .transport(e -> leasing)
                  .addListener(listener)
                  .build());
    }

    TlsIdentityHandle register(String name, KeyPair key) throws Exception {
      return kms.tls()
          .register(key.getPrivate(), pki.chain(pki.leaf("node", key)))
          .named(name)
          .register();
    }

    /** Follows {@code name} and moves its leases to the test's clock (just after the real one). */
    TlsIdentityFollower follow(String name, ScheduledExecutorService executor) {
      TlsIdentityFollower f = kms.tls().follow(name, HOURLY, executor);
      closing.add(f);
      now.set(System.nanoTime());
      f.leases.clock = now::get;
      return f;
    }

    TlsIdentityFollower follow(String name) {
      return follow(name, SCHEDULER);
    }

    TlsTrustFollower trust(ScheduledExecutorService executor) {
      TlsTrustFollower t =
          kms.tls()
              .trustAnchors(
                  KeyQuery.all().custom(TAG, "ca"),
                  KeyQuery.all().custom(TAG, "peer"),
                  HOURLY,
                  executor);
      closing.add(t);
      now.set(System.nanoTime());
      t.leases.clock = now::get;
      t.unknownPeerCheck(Duration.ZERO);
      return t;
    }

    KeyHandle anchor(Issued ca) {
      return kms.keys()
          .register(ca.certificate())
          .usages(KeyUsage.VERIFY)
          .custom(TAG, "ca")
          .register();
    }

    KeyHandle peer(Issued leaf) {
      return kms.keys()
          .register(leaf.certificate())
          .usages(KeyUsage.VERIFY)
          .custom(TAG, "peer")
          .register();
    }

    void advance(long seconds) {
      now.addAndGet(seconds * SECOND);
    }

    @Override
    public void close() throws Exception {
      for (AutoCloseable c : closing) c.close();
      kms.close();
    }
  }

  static Stream<Arguments> servers() {
    return TlsIdentityTest.servers();
  }

  /** The identifiers of the identity's chain (leaf first) and its private key. */
  static List<String> objects(TlsIdentityHandle h) {
    List<String> ids = new ArrayList<>();
    for (KeyHandle c : h.chain()) ids.add(c.id());
    ids.add(h.privateKey().id());
    return ids;
  }

  /** The alias presented now, checked with no exchange with the KMS. */
  static String alias(Fixture fx, TlsIdentityFollower f) {
    int before = fx.server.exchanges();
    String alias = f.keyManager().chooseServerAlias("EC", null, null);
    assertEquals(before, fx.server.exchanges(), "a handshake's check of the lease sends nothing");
    return alias;
  }

  /** Every key-manager path offers nothing, and finds nothing for {@code aliases}; no exchange. */
  static void assertNothing(Fixture fx, TlsIdentityFollower f, String... aliases) {
    int before = fx.server.exchanges();
    X509ExtendedKeyManager km = f.keyManager();
    assertNull(km.chooseServerAlias("EC", null, null), f.state().toString());
    assertNull(km.chooseClientAlias(new String[] {"EC"}, null, null));
    assertNull(km.chooseEngineServerAlias("EC", null, (SSLEngine) null));
    assertNull(km.chooseEngineClientAlias(new String[] {"EC"}, null, (SSLEngine) null));
    assertNull(km.getServerAliases("EC", null));
    assertNull(km.getClientAliases("EC", null));
    for (String a : aliases) {
      assertNull(km.getPrivateKey(a), a);
      assertNull(km.getCertificateChain(a), a);
    }
    assertTrue(f.identity().isEmpty());
    assertEquals(TlsIdentityFollower.Status.STALE, f.status(), f.state().toString());
    assertTrue(f.state().identity().isEmpty());
    assertEquals(before, fx.server.exchanges(), "no exchange at use");
  }

  static void assertPresented(TlsIdentityFollower f, String alias) {
    assertEquals(alias, f.keyManager().chooseServerAlias("EC", null, null), f.state().toString());
    assertNotNull(f.keyManager().getPrivateKey(alias));
    assertNotNull(f.keyManager().getCertificateChain(alias));
    assertTrue(f.identity().isPresent());
  }

  // ---- no Lease Time; a lease of zero ----

  @ParameterizedTest
  @MethodSource("servers")
  void withoutALeaseTimeNoObtainLeaseIsSentAndNothingExpires(KmipVersion version, boolean unique)
      throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      Issued peer = fx.pki.leaf("peer", TestPki.ec());
      fx.anchor(fx.pki.root);
      fx.peer(peer);
      fx.register(NAME, TestPki.ec());
      TlsIdentityFollower f = fx.follow(NAME);
      TlsTrustFollower t = fx.trust(SCHEDULER);
      String alias = alias(fx, f);
      assertNotNull(alias);
      assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
      t.refresh();
      fx.advance(10L * 365 * 24 * 3600);
      assertPresented(f, alias);
      t.trustManager().checkClientTrusted(fx.pki.chain(peer), "EC");
      assertEquals(0, fx.leasing.obtainRequests.get(), "no Obtain Lease without a Lease Time");
      assertEquals(TlsIdentityFollower.Status.CURRENT, f.status());
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void aLeaseOfZeroHasNoLimit(KmipVersion version, boolean unique) throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      fx.leasing.everyObject = 300L;
      fx.leasing.answer = id -> new Grant(0);
      // Named as the request named it: on 3.0 the draft's Reference type (elsewhere
      // keytend-kmip-server's Identifier).
      fx.leasing.echoIdentifier = true;
      Issued peer = fx.pki.leaf("peer", TestPki.ec());
      KeyHandle anchor = fx.anchor(fx.pki.root);
      KeyHandle allowed = fx.peer(peer);
      TlsIdentityHandle h = fx.register(NAME, TestPki.ec());
      TlsIdentityFollower f = fx.follow(NAME);
      TlsTrustFollower t = fx.trust(SCHEDULER);
      assertTrue(
          fx.leasing.obtained.containsAll(objects(h)),
          fx.leasing.obtained + " covers " + objects(h));
      assertTrue(fx.leasing.obtained.containsAll(List.of(anchor.id(), allowed.id())));
      String alias = alias(fx, f);
      fx.advance(10L * 365 * 24 * 3600);
      assertPresented(f, alias);
      t.trustManager().checkClientTrusted(fx.pki.chain(peer), "EC");
      assertEquals(Set.of(anchor.id()), t.anchors().keySet());
    }
  }

  // ---- a finite lease: obtained for every object, renewed, enforced at use ----

  @ParameterizedTest
  @MethodSource("servers")
  void aFiniteLeaseIsObtainedForEveryHeldObjectAndEndsAtUse(KmipVersion version, boolean unique)
      throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      fx.server.leaseTime(Duration.ofMinutes(5));
      TlsIdentityHandle h = fx.register(NAME, TestPki.ec());
      TlsIdentityFollower f = fx.follow(NAME);
      List<String> objects = objects(h);
      assertEquals(3, objects.size(), "leaf, intermediate and key");
      assertEquals(
          Set.copyOf(objects),
          Set.copyOf(fx.leasing.obtained),
          "a lease for the key and the whole chain");
      assertEquals(1, fx.leasing.obtainRequests.get(), "one batched Obtain Lease");
      String alias = alias(fx, f);
      assertNotNull(alias);
      fx.advance(299);
      assertPresented(f, alias);
      fx.advance(2);
      assertNothing(fx, f, alias);
      assertTrue(f.state().failure().isPresent());
      // A refresh renews: presented again.
      fx.leasing.reset();
      assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
      assertEquals(Set.copyOf(objects), Set.copyOf(fx.leasing.obtained));
      assertPresented(f, alias);
      // Measured from the request's send time, not its answer: a reply 100 s late gives no more.
      fx.leasing.onObtain = () -> fx.advance(100);
      assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
      fx.leasing.onObtain = () -> {};
      fx.advance(199);
      assertPresented(f, alias);
      fx.advance(2);
      assertNothing(fx, f, alias);
      // Across the wrap of the monotonic clock.
      fx.now.set(Long.MAX_VALUE - 150 * SECOND);
      assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
      fx.advance(299);
      assertTrue(fx.now.get() < 0, "wrapped");
      assertPresented(f, alias);
      fx.advance(2);
      assertNothing(fx, f, alias);
      assertTrue(fx.changes.isEmpty(), "a lease is no lifecycle event: " + fx.changes);
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRetryNeverLengthensALease(KmipVersion version) throws Exception {
    try (var server = InMemoryKmipServer.of(version)) {
      LeasingTransport leasing = new LeasingTransport(server);
      leasing.everyObject = 300L;
      AtomicLong now = new AtomicLong(System.nanoTime());
      AtomicBoolean drop = new AtomicBoolean();
      dev.keytend.kmip.transport.KmipTransport dropping =
          new dev.keytend.kmip.transport.KmipTransport() {
            @Override
            public Ttlv exchange(Ttlv request) throws java.io.IOException {
              return exchange(request, dev.keytend.kmip.transport.CallContext.NONE);
            }

            @Override
            public Ttlv exchange(Ttlv request, dev.keytend.kmip.transport.CallContext context)
                throws java.io.IOException {
              boolean obtain =
                  request.require(Tag.BATCH_ITEM).require(Tag.OPERATION).intValue()
                      == dev.keytend.kmip.model.Operation.OBTAIN_LEASE.code();
              if (obtain && drop.compareAndSet(true, false)) {
                now.addAndGet(100 * SECOND);
                throw new ConnectException("first attempt lost");
              }
              return leasing.exchange(request, context);
            }
          };
      try (Kms kms =
          Kms.connect(
              server
                  .configure()
                  .maximumVersion(KmipVersion.V3_0)
                  .retryPolicy(
                      RetryPolicy.builder()
                          .maxAttempts(3)
                          .initialBackoff(Duration.ofMillis(1))
                          .maxBackoff(Duration.ofMillis(1))
                          .cooldown(Duration.ZERO)
                          .build())
                  .transport(e -> dropping)
                  .build())) {
        Pki pki = new Pki();
        KeyPair key = TestPki.ec();
        kms.tls()
            .register(key.getPrivate(), pki.chain(pki.leaf("node", key)))
            .named(NAME)
            .register();
        try (TlsIdentityFollower f = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
          now.set(System.nanoTime());
          f.leases.clock = now::get;
          String alias = f.keyManager().chooseServerAlias("EC", null, null);
          drop.set(true);
          leasing.reset();
          assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
          assertFalse(drop.get(), "the first attempt was lost");
          assertEquals(1, leasing.obtainRequests.get(), "the retry answered");
          now.addAndGet(199 * SECOND);
          assertNotNull(f.keyManager().getPrivateKey(alias));
          now.addAndGet(2 * SECOND);
          assertNull(f.keyManager().getPrivateKey(alias), "300 s from the first attempt's send");
        }
      }
    }
  }

  // ---- outages, refusals, malformed answers ----

  @ParameterizedTest
  @MethodSource("servers")
  void anOutageKeepsThePairOnlyUntilItsLeaseEnds(KmipVersion version, boolean unique)
      throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      fx.server.leaseTime(Duration.ofMinutes(5));
      fx.register(NAME, TestPki.ec());
      TlsIdentityFollower f = fx.follow(NAME);
      String alias = alias(fx, f);
      fx.advance(100);
      fx.server.unreachable(true);
      TlsIdentityFollower.State s = f.refresh();
      assertEquals(TlsIdentityFollower.Status.STALE, s.status());
      assertTrue(s.identity().isPresent(), "within its lease the pair stays: " + s);
      assertPresented(f, alias);
      fx.advance(201);
      assertNothing(fx, f, alias);
      s = f.refresh();
      assertEquals(TlsIdentityFollower.Status.STALE, s.status());
      assertTrue(s.identity().isEmpty(), s.toString());
      assertNothing(fx, f, alias);
      // The KMS back: a new lease restores the pair.
      fx.server.unreachable(false);
      assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
      assertPresented(f, alias);
      assertTrue(fx.changes.isEmpty(), fx.changes.toString());
    }
  }

  static Stream<Arguments> refusals() {
    List<Arguments> out = new ArrayList<>();
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0))
      for (Enums.ResultReason r :
          List.of(
              Enums.ResultReason.PERMISSION_DENIED,
              Enums.ResultReason.OPERATION_NOT_SUPPORTED,
              Enums.ResultReason.ITEM_NOT_FOUND))
        for (int target : new int[] {0, 1, 2}) out.add(Arguments.of(v, r, target));
    return out.stream();
  }

  /** A refusal of any of the objects (leaf, intermediate, key) stops the pair at once. */
  @ParameterizedTest
  @MethodSource("refusals")
  void aRefusedLeaseStopsUseAtOnce(KmipVersion version, Enums.ResultReason reason, int target)
      throws Exception {
    try (Fixture fx = new Fixture(version, false)) {
      fx.leasing.everyObject = 300L;
      TlsIdentityHandle h = fx.register(NAME, TestPki.ec());
      TlsIdentityFollower f = fx.follow(NAME);
      String alias = alias(fx, f);
      String refused = objects(h).get(target);
      fx.leasing.answer = id -> id.equals(refused) ? new Refuse(reason) : new Grant(300);
      TlsIdentityFollower.State s = f.refresh();
      assertEquals(TlsIdentityFollower.Status.STALE, s.status(), s.toString());
      KmsException failure = assertInstanceOf(KmsException.class, s.failure().orElseThrow());
      assertEquals(reason, failure.protocolReason().orElseThrow());
      assertNothing(fx, f, alias);
      // An outage does not bring it back.
      fx.server.unreachable(true);
      f.refresh();
      assertNothing(fx, f, alias);
      // A new grant does.
      fx.server.unreachable(false);
      fx.leasing.answer = id -> new Grant(300);
      assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
      assertNotNull(alias(fx, f));
      assertTrue(fx.changes.isEmpty(), "no lifecycle event from a refusal: " + fx.changes);
      // A follower cannot start on a refused lease.
      fx.leasing.answer = id -> id.equals(refused) ? new Refuse(reason) : new Grant(300);
      assertThrows(KmsException.class, () -> fx.kms.tls().follow(NAME, HOURLY, SCHEDULER));
    }
  }

  static Stream<Arguments> malformed() {
    List<Arguments> out = new ArrayList<>();
    java.util.function.Function<String, List<Ttlv>> otherId =
        id ->
            List.of(
                Ttlv.text(Tag.UNIQUE_IDENTIFIER, id + "-other"),
                Ttlv.interval(Tag.LEASE_TIME, 300),
                changed());
    java.util.function.Function<String, List<Ttlv>> noId =
        id -> List.of(Ttlv.interval(Tag.LEASE_TIME, 300), changed());
    java.util.function.Function<String, List<Ttlv>> noLease =
        id -> List.of(Ttlv.text(Tag.UNIQUE_IDENTIFIER, id), changed());
    java.util.function.Function<String, List<Ttlv>> negative =
        id ->
            List.of(
                Ttlv.text(Tag.UNIQUE_IDENTIFIER, id),
                Ttlv.of(Tag.LEASE_TIME.code(), Ttlv.Type.INTEGER, -5),
                changed());
    java.util.function.Function<String, List<Ttlv>> twice =
        id ->
            List.of(
                Ttlv.text(Tag.UNIQUE_IDENTIFIER, id),
                Ttlv.interval(Tag.LEASE_TIME, 300),
                Ttlv.interval(Tag.LEASE_TIME, 9000),
                changed());
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0)) {
      out.add(Arguments.of(v, "another identifier", otherId));
      out.add(Arguments.of(v, "no identifier", noId));
      out.add(Arguments.of(v, "no Lease Time", noLease));
      out.add(Arguments.of(v, "a negative Integer", negative));
      out.add(Arguments.of(v, "two Lease Times", twice));
    }
    return out.stream();
  }

  static Ttlv changed() {
    return Ttlv.dateTime(Tag.LAST_CHANGE_DATE, Instant.ofEpochSecond(1_700_000_000L));
  }

  @ParameterizedTest(name = "{0} {1}")
  @MethodSource("malformed")
  void aMalformedAnswerGrantsNothing(
      KmipVersion version, String what, java.util.function.Function<String, List<Ttlv>> payload)
      throws Exception {
    try (Fixture fx = new Fixture(version, false)) {
      fx.leasing.everyObject = 300L;
      TlsIdentityHandle h = fx.register(NAME, TestPki.ec());
      String key = h.privateKey().id();
      fx.leasing.answer = id -> id.equals(key) ? new Malformed(payload) : new Grant(300);
      assertThrows(
          ProtocolViolationException.class,
          () -> fx.kms.tls().follow(NAME, HOURLY, SCHEDULER),
          what);
      // With a lease held: a malformed renewal is no refusal; the lease runs out as granted.
      fx.leasing.answer = id -> new Grant(300);
      TlsIdentityFollower f = fx.follow(NAME);
      String alias = alias(fx, f);
      fx.advance(100);
      fx.leasing.answer = id -> id.equals(key) ? new Malformed(payload) : new Grant(300);
      TlsIdentityFollower.State s = f.refresh();
      assertEquals(TlsIdentityFollower.Status.STALE, s.status(), s.toString());
      assertInstanceOf(ProtocolViolationException.class, s.failure().orElseThrow());
      assertPresented(f, alias);
      fx.advance(201);
      assertNothing(fx, f, alias);
    }
  }

  // ---- the previous pair and the chain ----

  @ParameterizedTest
  @MethodSource("servers")
  void aPreviousAliasEndsWithItsOwnLeaseAndNeverReturns(KmipVersion version, boolean unique)
      throws Exception {
    for (boolean rekey : new boolean[] {false, true}) {
      try (Fixture fx = new Fixture(version, unique)) {
        fx.leasing.everyObject = 300L;
        KeyPair key = TestPki.ec();
        TlsIdentityHandle h = fx.register(NAME, key);
        TlsIdentityFollower f = fx.follow(NAME);
        String old = alias(fx, f);
        String oldCertificate = h.certificate().id(), oldKey = h.privateKey().id();
        fx.advance(100);
        KeyPair next = TestPki.ec();
        TlsIdentityHandle renewed =
            rekey
                ? h.rekey(next.getPrivate(), fx.pki.chain(fx.pki.leaf("node", next)))
                : h.renew(fx.pki.chain(fx.pki.leaf("node", key)));
        // The server refuses leases of what the renewal deactivated, as keytend-kmip-server does
        // under
        // --lease-states active.
        fx.leasing.answer =
            id ->
                id.equals(oldCertificate) || (rekey && id.equals(oldKey))
                    ? new Refuse(Enums.ResultReason.PERMISSION_DENIED)
                    : new Grant(300);
        fx.leasing.reset();
        assertEquals(
            TlsIdentityFollower.Status.CURRENT,
            f.refresh().status(),
            "a refused previous object does not touch the current pair");
        assertFalse(
            fx.leasing.obtained.contains(oldCertificate),
            "the previous pair's leases are not renewed");
        String current = alias(fx, f);
        assertNotEquals(old, current);
        if (rekey)
          assertNull(
              f.keyManager().getPrivateKey(old),
              "a Deactivated signing key cannot serve an in-flight alias");
        else
          assertNotNull(
              f.keyManager().getPrivateKey(old), "an Active key stays available within its lease");
        fx.advance(201);
        assertNull(f.keyManager().getPrivateKey(old), "the previous pair's lease ran out");
        assertNull(f.keyManager().getCertificateChain(old));
        assertPresented(f, current);
        fx.advance(10);
        assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
        assertNull(f.keyManager().getPrivateKey(old), "never served again");
        assertPresented(f, current);
        assertTrue(objects(renewed).stream().allMatch(fx.leasing.obtained::contains));
      }
    }
  }

  /**
   * The pair check signs with the private key, which is a use of it (KMIP 1.4 §3.20): every object
   * of a new pair is leased before any of it is fetched, the leases still run when the key signs,
   * and a refused, failed or lapsed lease means the key is neither fetched nor signed with. Watched
   * at the follower's signing seam and on the wire.
   */
  @ParameterizedTest
  @MethodSource("servers")
  void aKeyIsLeasedBeforeItIsFetchedOrSignsAndNeverSignsWithoutALease(
      KmipVersion version, boolean unique) throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      fx.leasing.everyObject = 300L;
      List<String> signed = new CopyOnWriteArrayList<>();
      KeyPair first = TestPki.ec();
      TlsIdentityHandle h = fx.register(NAME, first);
      String key = h.privateKey().id();
      // follow(): Obtain Lease of the pair before the key's Get, then one signature with a lease
      // running.
      fx.leasing.reset();
      TlsIdentityFollower f = fx.follow(NAME);
      List<String> trace = List.copyOf(fx.leasing.trace);
      assertTrue(
          trace.contains("ObtainLease " + key)
              && trace.indexOf("ObtainLease " + key) < trace.indexOf("Get " + key),
          trace.toString());
      for (String id : objects(h))
        assertTrue(
            trace.indexOf("ObtainLease " + id) < trace.indexOf("Get " + id)
                || !trace.contains("Get " + id),
            id + " " + trace);
      assertEquals(1, fx.leasing.obtainRequests.get(), "the load's grant is not asked for twice");
      f.signing = id -> signed.add(id + (f.leases.usable(id) ? " leased" : " UNLEASED"));
      // A re-key whose new key is refused: never fetched, never signed with; the old pair stays
      // within its lease.
      KeyPair second = TestPki.ec();
      TlsIdentityHandle next =
          h.rekey(second.getPrivate(), fx.pki.chain(fx.pki.leaf("node", second)));
      String newKey = next.privateKey().id();
      fx.leasing.answer =
          id ->
              id.equals(newKey) ? new Refuse(Enums.ResultReason.PERMISSION_DENIED) : new Grant(300);
      fx.leasing.reset();
      TlsIdentityFollower.State s = f.refresh();
      assertEquals(TlsIdentityFollower.Status.STALE, s.status(), s.toString());
      assertFalse(
          fx.leasing.trace.contains("Get " + newKey),
          "a refused key is not fetched: " + fx.leasing.trace);
      assertTrue(signed.isEmpty(), "a refused key never signs: " + signed);
      // Unobtained: Obtain Lease cannot be answered.
      fx.leasing.answer = id -> new Grant(300);
      fx.leasing.dropObtains = true;
      fx.leasing.reset();
      f.refresh();
      fx.leasing.dropObtains = false;
      assertFalse(fx.leasing.trace.contains("Get " + newKey), fx.leasing.trace.toString());
      assertTrue(signed.isEmpty(), "no lease, no signature: " + signed);
      // Lapsed between the grant and the use: the 300 s grant has run out by the time the key
      // arrives.
      fx.leasing.beforeEach =
          request -> {
            if (request.require(Tag.BATCH_ITEM).require(Tag.OPERATION).intValue()
                    == dev.keytend.kmip.model.Operation.GET.code()
                && request
                    .require(Tag.BATCH_ITEM)
                    .require(Tag.REQUEST_PAYLOAD)
                    .require(Tag.UNIQUE_IDENTIFIER)
                    .textValue()
                    .equals(newKey)) fx.advance(301);
          };
      f.refresh();
      fx.leasing.beforeEach = request -> {};
      assertTrue(signed.isEmpty(), "a lease that ran out before the use: no signature: " + signed);
      assertNotEquals(newKey, f.identity().map(TlsIdentity::privateKeyId).orElse(null));
      // Granted: leased first, then one signature while it runs, then presented.
      fx.leasing.reset();
      assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
      assertEquals(List.of(newKey + " leased"), signed);
      trace = List.copyOf(fx.leasing.trace);
      assertTrue(
          trace.indexOf("ObtainLease " + newKey) < trace.indexOf("Get " + newKey),
          trace.toString());
      assertEquals(newKey, f.identity().orElseThrow().privateKeyId());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anIntermediatesLeaseBindsThePair(KmipVersion version) throws Exception {
    try (Fixture fx = new Fixture(version, false)) {
      fx.leasing.everyObject = 300L;
      TlsIdentityHandle h = fx.register(NAME, TestPki.ec());
      String intermediate = h.chain().get(1).id();
      fx.leasing.leaseTimes.put(intermediate, 100L);
      TlsIdentityFollower f = fx.follow(NAME);
      String alias = alias(fx, f);
      fx.advance(99);
      assertPresented(f, alias);
      fx.advance(2);
      assertNothing(fx, f, alias);
      assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
      // A grant longer than the object's own Lease Time is held to that.
      fx.leasing.answer = id -> new Grant(id.equals(intermediate) ? 5000 : 300);
      f.refresh();
      fx.advance(101);
      assertNothing(fx, f, alias);
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void unsafeEvidenceStillWinsOverARunningLease(KmipVersion version, boolean unique)
      throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      fx.server.leaseTime(Duration.ofMinutes(5));
      TlsIdentityHandle h = fx.register(NAME, TestPki.ec());
      TlsIdentityFollower f = fx.follow(NAME);
      String alias = alias(fx, f);
      h.revoke(RevocationReason.keyCompromise("exposed", Instant.now()));
      assertEquals(TlsIdentityFollower.Status.REVOKED, f.refresh().status());
      assertNull(f.keyManager().getPrivateKey(alias));
      fx.server.unreachable(true);
      f.refresh();
      assertNull(f.keyManager().getPrivateKey(alias));
      assertNull(f.keyManager().chooseServerAlias("EC", null, null));
    }
  }

  // ---- a stalled refresh, a delayed or shut-down executor ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aStalledRefreshCannotExtendALease(KmipVersion version) throws Exception {
    try (Fixture fx = new Fixture(version, false)) {
      fx.server.leaseTime(Duration.ofMinutes(5));
      Issued peer = fx.pki.leaf("peer", TestPki.ec());
      fx.anchor(fx.pki.root);
      fx.peer(peer);
      fx.register(NAME, TestPki.ec());
      TlsIdentityFollower f = fx.follow(NAME);
      TlsTrustFollower t = fx.trust(SCHEDULER);
      String alias = alias(fx, f);
      CountDownLatch inside = new CountDownLatch(2), release = new CountDownLatch(1);
      // Each refresh's first request (its Locate) waits in the network until the test releases it.
      fx.leasing.beforeEach =
          request -> {
            if (request.require(Tag.BATCH_ITEM).require(Tag.OPERATION).intValue()
                == dev.keytend.kmip.model.Operation.LOCATE.code()) {
              inside.countDown();
              try {
                release.await(30, TimeUnit.SECONDS);
              } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
              }
            }
          };
      ExecutorService pool = Executors.newFixedThreadPool(2);
      try {
        Future<?> a = pool.submit(() -> f.refresh());
        Future<?> b = pool.submit(() -> t.refresh());
        // Both refreshes hold their followers' locks, waiting in the network.
        assertTrue(inside.await(10, TimeUnit.SECONDS));
        fx.advance(301);
        assertTimeoutPreemptively(
            Duration.ofSeconds(2),
            () -> {
              assertNull(f.keyManager().chooseServerAlias("EC", null, null));
              assertNull(f.keyManager().getPrivateKey(alias));
              assertTrue(f.identity().isEmpty());
              assertEquals(TlsIdentityFollower.Status.STALE, f.status());
              assertTrue(t.anchors().isEmpty());
              assertTrue(t.allowedPeers().orElseThrow().isEmpty());
              assertEquals(0, t.trustManager().getAcceptedIssuers().length);
              assertThrows(
                  CertificateException.class,
                  () -> t.trustManager().checkClientTrusted(fx.pki.chain(peer), "EC"));
            });
        fx.leasing.beforeEach = request -> {};
        release.countDown();
        a.get(30, TimeUnit.SECONDS);
        b.get(30, TimeUnit.SECONDS);
      } finally {
        release.countDown();
        pool.shutdownNow();
      }
    }
  }

  /** A scheduler that records what it is given and never runs it, as a stalled executor. */
  static final class Stalled extends java.util.concurrent.AbstractExecutorService
      implements ScheduledExecutorService {
    record Task(long delayNanos, boolean periodic, ScheduledFuture<?> future) {}

    final List<Task> tasks = new CopyOnWriteArrayList<>();
    volatile boolean refusePeriodic, refuseOneShot;

    static final class Never implements ScheduledFuture<Object> {
      final long delay;
      volatile boolean canceled;

      Never(long delay) {
        this.delay = delay;
      }

      @Override
      public long getDelay(TimeUnit unit) {
        return unit.convert(delay, TimeUnit.NANOSECONDS);
      }

      @Override
      public int compareTo(Delayed o) {
        return Long.compare(delay, o.getDelay(TimeUnit.NANOSECONDS));
      }

      @Override
      public boolean cancel(boolean interrupt) {
        canceled = true;
        return true;
      }

      @Override
      public boolean isCancelled() {
        return canceled;
      }

      @Override
      public boolean isDone() {
        return canceled;
      }

      @Override
      public Object get() {
        throw new UnsupportedOperationException();
      }

      @Override
      public Object get(long timeout, TimeUnit unit) {
        throw new UnsupportedOperationException();
      }
    }

    private ScheduledFuture<?> add(long delay, TimeUnit unit, boolean periodic) {
      if (periodic ? refusePeriodic : refuseOneShot)
        throw new RejectedExecutionException("shut down");
      Never n = new Never(unit.toNanos(delay));
      tasks.add(new Task(unit.toNanos(delay), periodic, n));
      return n;
    }

    @Override
    public ScheduledFuture<?> schedule(Runnable command, long delay, TimeUnit unit) {
      return add(delay, unit, false);
    }

    @Override
    public <V> ScheduledFuture<V> schedule(Callable<V> callable, long delay, TimeUnit unit) {
      throw new UnsupportedOperationException();
    }

    @Override
    public ScheduledFuture<?> scheduleAtFixedRate(
        Runnable command, long initialDelay, long period, TimeUnit unit) {
      return add(initialDelay, unit, true);
    }

    @Override
    public ScheduledFuture<?> scheduleWithFixedDelay(
        Runnable command, long initialDelay, long delay, TimeUnit unit) {
      return add(initialDelay, unit, true);
    }

    @Override
    public void execute(Runnable command) {}

    @Override
    public void shutdown() {}

    @Override
    public List<Runnable> shutdownNow() {
      return List.of();
    }

    @Override
    public boolean isShutdown() {
      return false;
    }

    @Override
    public boolean isTerminated() {
      return false;
    }

    @Override
    public boolean awaitTermination(long timeout, TimeUnit unit) {
      return true;
    }

    List<Task> oneShots() {
      return tasks.stream().filter(x -> !x.periodic()).toList();
    }

    boolean allCanceled() {
      return tasks.stream().allMatch(x -> x.future().isCancelled());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aStalledExecutorCannotExtendALeaseAndRenewalsArePlannedAndCanceled(KmipVersion version)
      throws Exception {
    try (Fixture fx = new Fixture(version, false)) {
      fx.server.leaseTime(Duration.ofMinutes(5));
      Issued peer = fx.pki.leaf("peer", TestPki.ec());
      fx.anchor(fx.pki.root);
      fx.peer(peer);
      fx.register(NAME, TestPki.ec());
      Stalled stalled = new Stalled(), trustStalled = new Stalled();
      TlsIdentityFollower f = fx.follow(NAME, stalled);
      TlsTrustFollower t = fx.trust(trustStalled);
      // The interval (an hour) is longer than the lease: a renewal is planned at about half of it.
      for (Stalled s : List.of(stalled, trustStalled)) {
        assertEquals(1, s.oneShots().size(), s.tasks.toString());
        long delay = s.oneShots().get(0).delayNanos();
        assertTrue(delay >= Leases.FLOOR_NANOS && delay <= 150 * SECOND, "renewal in " + delay);
      }
      String alias = alias(fx, f);
      fx.advance(301);
      assertNothing(fx, f, alias);
      assertThrows(
          CertificateException.class,
          () -> t.trustManager().checkClientTrusted(fx.pki.chain(peer), "EC"));
      // Each refresh replaces the planned renewal; a refused one (shut down) changes nothing else.
      f.refresh();
      assertTrue(stalled.oneShots().get(0).future().isCancelled());
      stalled.refuseOneShot = true;
      assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
      assertNotNull(alias(fx, f));
      f.close();
      t.close();
      assertTrue(stalled.allCanceled(), "close cancels the interval and every planned renewal");
      assertTrue(trustStalled.allCanceled());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aStartThatCannotScheduleCancelsItsPlannedRenewal(KmipVersion version) throws Exception {
    try (Fixture fx = new Fixture(version, false)) {
      fx.leasing.everyObject = 300L;
      fx.anchor(fx.pki.root);
      fx.register(NAME, TestPki.ec());
      for (boolean trust : new boolean[] {false, true}) {
        Stalled s = new Stalled();
        s.refusePeriodic = true;
        assertThrows(
            RejectedExecutionException.class,
            () -> {
              if (trust) fx.kms.tls().trustAnchors(KeyQuery.all().custom(TAG, "ca"), HOURLY, s);
              else fx.kms.tls().follow(NAME, HOURLY, s);
            });
        assertEquals(1, s.oneShots().size());
        assertTrue(s.allCanceled(), "the renewal the first refresh planned is canceled");
      }
      // A lease longer than twice the interval plans nothing.
      fx.leasing.everyObject = 10_000L;
      Stalled s = new Stalled();
      try (TlsIdentityFollower f = fx.kms.tls().follow(NAME, HOURLY, s)) {
        assertTrue(s.oneShots().isEmpty());
      }
    }
  }

  // ---- trust: partial expiry, every overload, the unknown-peer check ----

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void trustUsesOnlyAnchorsAndPeersWhoseLeasesRun(KmipVersion version) throws Exception {
    try (Fixture fx = new Fixture(version, false)) {
      fx.leasing.everyObject = 300L;
      Issued rootA = TestPki.ca("Root A"), rootB = TestPki.ca("Root B");
      Issued leafA = TestPki.leaf("a", TestPki.ec(), rootA),
          leafB = TestPki.leaf("b", TestPki.ec(), rootB);
      Issued leafB2 = TestPki.leaf("b2", TestPki.ec(), rootB);
      KeyHandle a = fx.anchor(rootA), b = fx.anchor(rootB);
      fx.peer(leafA);
      fx.peer(leafB);
      KeyHandle b2 = fx.peer(leafB2);
      fx.leasing.leaseTimes.put(a.id(), 100L);
      fx.leasing.leaseTimes.put(b2.id(), 200L);
      TlsTrustFollower t = fx.trust(SCHEDULER);
      X509ExtendedTrustManager tm = t.trustManager();
      accepted(tm, leafA.chain());
      accepted(tm, leafB.chain());
      accepted(tm, leafB2.chain());
      fx.advance(101);
      int before = fx.server.exchanges();
      assertEquals(
          Set.of(b.id()), t.anchors().keySet(), "the anchor whose lease ran out is no anchor");
      assertEquals(List.of(rootB.certificate()), List.of(tm.getAcceptedIssuers()));
      refused(tm, leafA.chain());
      accepted(tm, leafB.chain());
      fx.advance(100);
      assertFalse(
          t.allowedPeers().orElseThrow().containsKey(b2.id()),
          "an allowed peer whose lease ran out");
      refused(tm, leafB2.chain());
      accepted(tm, leafB.chain());
      assertEquals(before, fx.server.exchanges(), "no exchange at use");
      // A refresh renews them.
      t.refresh();
      assertEquals(Set.of(a.id(), b.id()), t.anchors().keySet());
      accepted(tm, leafA.chain());
      accepted(tm, leafB2.chain());
      // A refusal removes one at once; the others stay.
      fx.leasing.answer =
          id ->
              id.equals(b.id()) ? new Refuse(Enums.ResultReason.PERMISSION_DENIED) : new Grant(300);
      t.refresh();
      assertInstanceOf(PermissionDeniedException.class, t.failure().orElseThrow());
      assertEquals(Set.of(a.id()), t.anchors().keySet());
      refused(tm, leafB.chain());
      accepted(tm, leafA.chain());
      // An outage keeps a lease until it ends.
      fx.server.unreachable(true);
      t.refresh();
      accepted(tm, leafA.chain());
      fx.advance(301);
      refused(tm, leafA.chain());
      assertTrue(t.anchors().isEmpty());
      assertTrue(fx.changes.isEmpty());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRefreshThatFailsAfterReadingTheAnchorsChangesNothing(KmipVersion version) throws Exception {
    try (Fixture fx = new Fixture(version, false)) {
      fx.server.leaseTime(Duration.ofMinutes(5));
      Issued rootB = TestPki.ca("Root B");
      Issued leafB = TestPki.leaf("b", TestPki.ec(), rootB);
      KeyHandle a = fx.anchor(fx.pki.root);
      fx.peer(fx.pki.leaf("p", TestPki.ec()));
      TlsTrustFollower t = fx.trust(SCHEDULER);
      List<String> told = new CopyOnWriteArrayList<>();
      t.onChange(() -> told.add("changed"));
      fx.anchor(rootB);
      fx.peer(leafB);
      // The anchors' Locate is answered; the allowed peers' fails.
      java.util.concurrent.atomic.AtomicInteger locates =
          new java.util.concurrent.atomic.AtomicInteger();
      fx.server.injectBeforeProcessing(
          request ->
              request.require(Tag.BATCH_ITEM).require(Tag.OPERATION).intValue()
                          == dev.keytend.kmip.model.Operation.LOCATE.code()
                      && locates.incrementAndGet() == 2
                  ? new ConnectException("allowed peers unavailable")
                  : null);
      assertFalse(t.refresh());
      assertTrue(t.failure().isPresent());
      assertEquals(2, locates.get());
      assertEquals(Set.of(a.id()), t.anchors().keySet());
      assertTrue(t.toString().startsWith("TlsTrustFollower[1 anchors"), t.toString());
      assertTrue(told.isEmpty(), "a failed refresh changes nothing: " + told);
      refused(t.trustManager(), leafB.chain());
      fx.server.injectBeforeProcessing(null);
      assertTrue(t.refresh());
      accepted(t.trustManager(), leafB.chain());
    }
  }

  /** All six checks accept {@code chain}, as client and as server. */
  static void accepted(X509ExtendedTrustManager tm, X509Certificate[] chain) throws Exception {
    tm.checkClientTrusted(chain, "EC");
    tm.checkServerTrusted(chain, "ECDHE_ECDSA");
    tm.checkClientTrusted(chain, "EC", (Socket) null);
    tm.checkServerTrusted(chain, "ECDHE_ECDSA", (Socket) null);
    tm.checkClientTrusted(chain, "EC", (SSLEngine) null);
    tm.checkServerTrusted(chain, "ECDHE_ECDSA", (SSLEngine) null);
  }

  /** All six checks refuse {@code chain}. */
  static void refused(X509ExtendedTrustManager tm, X509Certificate[] chain) {
    assertThrows(CertificateException.class, () -> tm.checkClientTrusted(chain, "EC"));
    assertThrows(CertificateException.class, () -> tm.checkServerTrusted(chain, "ECDHE_ECDSA"));
    assertThrows(
        CertificateException.class, () -> tm.checkClientTrusted(chain, "EC", (Socket) null));
    assertThrows(
        CertificateException.class,
        () -> tm.checkServerTrusted(chain, "ECDHE_ECDSA", (Socket) null));
    assertThrows(
        CertificateException.class, () -> tm.checkClientTrusted(chain, "EC", (SSLEngine) null));
    assertThrows(
        CertificateException.class,
        () -> tm.checkServerTrusted(chain, "ECDHE_ECDSA", (SSLEngine) null));
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anUnknownPeersCheckObtainsItsLeaseWithinTheCheck(KmipVersion version) throws Exception {
    try (Fixture fx = new Fixture(version, false)) {
      fx.leasing.everyObject = 300L;
      fx.anchor(fx.pki.root);
      fx.peer(fx.pki.leaf("p0", TestPki.ec()));
      TlsTrustFollower t = fx.trust(SCHEDULER);
      t.ticker = fx.now::get;
      t.unknownPeerCheck(Duration.ofSeconds(2)).unknownPeerCheckInHandshake(true);
      X509ExtendedTrustManager tm = t.trustManager();
      // A new allowed peer: the check leases it, and only it.
      Issued n1 = fx.pki.leaf("n1", TestPki.ec());
      KeyHandle h1 = fx.peer(n1);
      fx.advance(2);
      fx.leasing.reset();
      tm.checkClientTrusted(fx.pki.chain(n1), "EC");
      assertEquals(
          List.of(h1.id()), fx.leasing.obtained, "the check asks for the new peer's lease only");
      // Refused: the peer is not accepted.
      Issued n2 = fx.pki.leaf("n2", TestPki.ec());
      KeyHandle h2 = fx.peer(n2);
      fx.leasing.answer =
          id ->
              id.equals(h2.id())
                  ? new Refuse(Enums.ResultReason.PERMISSION_DENIED)
                  : new Grant(300);
      fx.advance(2);
      CertificateException e =
          assertThrows(
              CertificateException.class, () -> tm.checkClientTrusted(fx.pki.chain(n2), "EC"));
      assertTrue(
          e.getMessage().contains("ObtainLease") && e.getMessage().contains("PermissionDenied"),
          e.getMessage());
      // A lease request that hangs is cut by the check's own deadline.
      Issued n3 = fx.pki.leaf("n3", TestPki.ec());
      KeyHandle h3 = fx.peer(n3);
      fx.leasing.answer = id -> id.equals(h3.id()) ? new Hang() : new Grant(300);
      t.unknownPeerCheck(Duration.ofMillis(300));
      fx.advance(2);
      long started = System.nanoTime();
      assertThrows(CertificateException.class, () -> tm.checkClientTrusted(fx.pki.chain(n3), "EC"));
      long took = System.nanoTime() - started;
      assertTrue(took < 3 * SECOND, "the check stayed within its bound: " + Duration.ofNanos(took));
      fx.leasing.answer = id -> new Grant(300);
      // A known peer whose lease ran out is refused without waiting when the check is off.
      t.unknownPeerCheck(Duration.ZERO);
      fx.advance(301);
      assertThrows(CertificateException.class, () -> tm.checkClientTrusted(fx.pki.chain(n1), "EC"));
    }
  }

  // ---- the tracker itself ----

  @org.junit.jupiter.api.Test
  void theTrackerMeasuresFromTheSendTimeAcrossClockWrapAndRefusesUnknownObjects() {
    Leases leases = new Leases();
    AtomicLong now = new AtomicLong(Long.MAX_VALUE - 100 * SECOND);
    leases.clock = now::get;
    assertFalse(leases.usable("unknown"));
    assertTrue(leases.usable(List.of()));
    assertTrue(Leases.refusal(new UnsupportedException("no")));
    assertFalse(Leases.refusal(new TransientException("down")));
    assertFalse(
        Leases.refusal(new PermissionDeniedException("TLS refused")),
        "a refusal that is not the server's answer (no Result Reason) is not one");
    assertEquals(Long.MAX_VALUE, leases.renewalDelay(List.of("unknown")));
    Collection<String> none = List.of();
    assertEquals(Long.MAX_VALUE, leases.renewalDelay(none));
    // Map.of() never needs a request.
    assertSame(Leases.Outcome.OK, leases.obtain(null, Map.of(), true));
    java.util.Map<String, Duration> notLeased = new java.util.HashMap<>();
    notLeased.put("a", null);
    assertSame(Leases.Outcome.OK, leases.obtain(null, notLeased, true));
    assertTrue(leases.usable("a"));
    now.addAndGet(Long.MAX_VALUE);
    assertTrue(leases.usable("a"), "no Lease Time, no limit");
  }
}
