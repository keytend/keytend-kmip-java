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

import static dev.keytend.kmip.kms.TlsIdentityTest.SCHEDULER;
import static dev.keytend.kmip.kms.TlsLeaseTest.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.ServerOperation;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/** Observed signing restrictions, inactive pairs and lease decisions fail closed. */
class TlsPolicySafetyTest {
  static Stream<Arguments> servers() {
    return TlsLeaseTest.servers();
  }

  @ParameterizedTest
  @MethodSource("servers")
  void anUnreadableRenewalDropsTheHeldCertificateEvenWhileItsSharedKeyIsActive(
      KmipVersion version, boolean unique) throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      java.security.KeyPair pair = TestPki.ec();
      TlsIdentityHandle h = fx.register(NAME, pair);
      TlsIdentityFollower f = fx.follow(NAME);
      String held = alias(fx, f);
      TlsIdentityHandle next = h.renew(fx.pki.chain(fx.pki.leaf("renewed", pair)));
      assertEquals(KeyState.DEACTIVATED, h.certificate().attributes().state());
      assertEquals(KeyState.ACTIVE, h.privateKey().attributes().state());
      fx.server.failNext(ServerOperation.GET, Fault.UNREACHABLE);
      assertInstanceOf(TransientException.class, f.refresh().failure().orElseThrow());
      assertNothing(fx, f, held);
      fx.server.unreachable(true);
      f.refresh();
      assertNothing(fx, f, held);
      fx.server.unreachable(false);
      assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
      assertEquals(next.certificate().id(), f.identity().orElseThrow().certificateId());
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void aRenewalCannotSignAfterItsLeaseExpiresDuringGet(KmipVersion version, boolean unique)
      throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      java.security.KeyPair pair = TestPki.ec();
      TlsIdentityHandle h = fx.register(NAME, pair);
      String id = h.privateKey().id();
      X509Certificate[] next = fx.pki.chain(fx.pki.leaf("renewed", pair));
      long objects = fx.kms.keys().locate(KeyQuery.all()).count();
      fx.leasing.leaseTimes.put(id, 300L);
      fx.leasing.answer = ignored -> new LeasingTransport.Grant(1);
      java.util.concurrent.atomic.AtomicBoolean delayed =
          new java.util.concurrent.atomic.AtomicBoolean();
      fx.leasing.beforeEach =
          request -> {
            for (var item : request.children(Tag.BATCH_ITEM)) {
              if (item.require(Tag.OPERATION).intValue() == Operation.GET.code()
                  && item.require(Tag.REQUEST_PAYLOAD)
                      .require(Tag.UNIQUE_IDENTIFIER)
                      .textValue()
                      .equals(id)) {
                delayed.set(true);
                try {
                  // The writer uses the monotonic system clock; delay this real Get past its
                  // one-second grant.
                  TimeUnit.MILLISECONDS.sleep(1500);
                } catch (InterruptedException interrupted) {
                  Thread.currentThread().interrupt();
                  throw new AssertionError(interrupted);
                }
              }
            }
          };
      TransientException expired = assertThrows(TransientException.class, () -> h.renew(next));
      assertTrue(expired.getMessage().contains("ended before its pair check"), expired.toString());
      assertTrue(delayed.get());
      assertEquals(objects, fx.kms.keys().locate(KeyQuery.all()).count(), "nothing registered");
      assertEquals(
          h.certificate().id(), fx.kms.tls().identity(NAME).orElseThrow().certificate().id());
      fx.leasing.beforeEach = ignored -> {};
      assertNotEquals(
          h.certificate().id(), h.renew(next).certificate().id(), "a running grant still renews");
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void usageLimitedKeysAreNeverFetchedOrSigned(KmipVersion version, boolean unique)
      throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      TlsIdentityHandle h = fx.register(NAME, TestPki.ec());
      String id = h.privateKey().id();
      fx.leasing.usageLimited.add(id);
      fx.leasing.reset();
      UnsupportedException e = assertThrows(UnsupportedException.class, () -> fx.follow(NAME));
      assertTrue(e.getMessage().contains("Usage Limits"), e.toString());
      assertEquals(id, e.objectId().orElseThrow());
      assertFalse(fx.leasing.trace.contains("Get " + id), fx.leasing.trace.toString());
      assertTrue(fx.changes.isEmpty(), "refusing unsupported protection is no lifecycle event");
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void aNewUsageRestrictionDropsHeldAndSharedPreviousAliasesAcrossOutages(
      KmipVersion version, boolean unique) throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      java.security.KeyPair pair = TestPki.ec();
      TlsIdentityHandle h = fx.register(NAME, pair);
      TlsIdentityFollower f = fx.follow(NAME);
      String old = alias(fx, f);
      h.renew(fx.pki.chain(fx.pki.leaf("renewed", pair)));
      assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
      String current = alias(fx, f);
      assertNotEquals(old, current);
      assertNotNull(f.keyManager().getPrivateKey(old));
      fx.changes.clear();
      fx.leasing.usageLimited.add(h.privateKey().id());
      assertInstanceOf(UnsupportedException.class, f.refresh().failure().orElse(null));
      assertNothing(fx, f, old, current);
      fx.server.unreachable(true);
      f.refresh();
      assertNothing(fx, f, old, current);
      assertTrue(fx.changes.isEmpty());
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void aRestrictedReplacementCannotKeepADeactivatedPair(KmipVersion version, boolean unique)
      throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      TlsIdentityHandle h = fx.register(NAME, TestPki.ec());
      TlsIdentityFollower f = fx.follow(NAME);
      String held = alias(fx, f);
      java.security.KeyPair pair = TestPki.ec();
      TlsIdentityHandle replacement =
          h.rekey(pair.getPrivate(), fx.pki.chain(fx.pki.leaf("replacement", pair)));
      String id = replacement.privateKey().id();
      fx.leasing.usageLimited.add(id);
      fx.leasing.reset();
      List<String> signed = new ArrayList<>();
      f.signing = signed::add;
      assertInstanceOf(UnsupportedException.class, f.refresh().failure().orElse(null));
      assertNothing(fx, f, held);
      assertFalse(fx.leasing.trace.contains("Get " + id));
      assertTrue(signed.isEmpty());
      fx.server.unreachable(true);
      f.refresh();
      assertNothing(fx, f, held);
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void theLoadersLaterAttributesCannotHideAUsageRestriction(KmipVersion version, boolean unique)
      throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      fx.leasing.everyObject = 300L;
      TlsIdentityHandle h = fx.register(NAME, TestPki.ec());
      String id = h.privateKey().id();
      // Discovery finds an unrestricted key; its loader then observes Usage Limits.
      fx.leasing.onObtain = () -> fx.leasing.usageLimited.add(id);
      fx.leasing.reset();
      assertThrows(UnsupportedException.class, () -> fx.follow(NAME));
      assertTrue(fx.leasing.obtained.contains(id));
      assertFalse(fx.leasing.trace.contains("Get " + id), fx.leasing.trace.toString());
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void mistypedLeaseTimeStillRequiresAGrantForBothFollowers(KmipVersion version, boolean unique)
      throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      fx.leasing.everyObject = 300L;
      fx.leasing.integerLeaseTime = true;
      TlsIdentityHandle h = fx.register(NAME, TestPki.ec());
      assertThrows(ProtocolViolationException.class, () -> h.privateKey().attributes().leaseTime());
      Issued peer = fx.pki.leaf("peer", TestPki.ec());
      KeyHandle anchor = fx.anchor(fx.pki.root), allowed = fx.peer(peer);
      TlsIdentityFollower f = fx.follow(NAME);
      TlsTrustFollower t = fx.trust(SCHEDULER);
      assertTrue(fx.leasing.obtained.containsAll(objects(h)));
      assertTrue(fx.leasing.obtained.containsAll(List.of(anchor.id(), allowed.id())));
      String a = alias(fx, f);
      t.trustManager().checkClientTrusted(fx.pki.chain(peer), "EC");
      fx.server.unreachable(true);
      fx.advance(301);
      assertNothing(fx, f, a);
      assertTrue(t.anchors().isEmpty());
      assertTrue(t.allowedPeers().orElseThrow().isEmpty());
      assertThrows(
          CertificateException.class,
          () -> t.trustManager().checkClientTrusted(fx.pki.chain(peer), "EC"));
      fx.server.unreachable(false);
      fx.leasing.answer =
          id ->
              new LeasingTransport.Refuse(
                  dev.keytend.kmip.model.Enums.ResultReason.PERMISSION_DENIED);
      f.refresh();
      t.refresh();
      assertNothing(fx, f, a);
      assertTrue(t.anchors().isEmpty(), "a malformed attribute cannot bypass a refused grant");
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void signingMustBePermittedByTheKeysUsageMaskAtDiscoveryAndLoad(
      KmipVersion version, boolean unique) throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      TlsIdentityHandle h = fx.register(NAME, TestPki.ec());
      String id = h.privateKey().id();
      fx.leasing.signingForbidden.add(id);
      fx.leasing.reset();
      UnsupportedException e = assertThrows(UnsupportedException.class, () -> fx.follow(NAME));
      assertTrue(e.getMessage().contains("does not permit SIGN"), e.toString());
      assertFalse(fx.leasing.trace.contains("Get " + id));
      fx.leasing.signingForbidden.clear();
      TlsIdentityFollower f = fx.follow(NAME);
      String alias = alias(fx, f);
      fx.leasing.signingForbidden.add(id);
      assertInstanceOf(UnsupportedException.class, f.refresh().failure().orElse(null));
      assertNothing(fx, f, alias);
      fx.server.unreachable(true);
      f.refresh();
      assertNothing(fx, f, alias);
      fx.server.unreachable(false);
      fx.leasing.everyObject = 300L;
      TlsIdentityHandle later = fx.register("later", TestPki.ec());
      String other = later.privateKey().id();
      fx.leasing.onObtain = () -> fx.leasing.signingForbidden.add(other);
      fx.leasing.reset();
      assertThrows(UnsupportedException.class, () -> fx.follow("later"));
      assertFalse(fx.leasing.trace.contains("Get " + other));
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void aRestrictedReplacementStillKeepsAHeldPairThatRemainsActive(
      KmipVersion version, boolean unique) throws Exception {
    for (boolean limits : new boolean[] {true, false}) {
      try (Fixture fx = new Fixture(version, unique)) {
        TlsIdentityHandle h = fx.register(NAME, TestPki.ec());
        TlsIdentityFollower f = fx.follow(NAME);
        String held = alias(fx, f);
        TlsIdentityHandle next = fx.register("other", TestPki.ec());
        h.certificate().removeName(NAME);
        next.certificate().removeName("other");
        next.certificate().addName(NAME);
        if (limits) fx.leasing.usageLimited.add(next.privateKey().id());
        else fx.leasing.signingForbidden.add(next.privateKey().id());
        assertEquals(KeyState.ACTIVE, h.certificate().attributes().state());
        assertEquals(KeyState.ACTIVE, h.privateKey().attributes().state());
        assertInstanceOf(UnsupportedException.class, f.refresh().failure().orElse(null));
        assertPresented(f, held);
        fx.server.unreachable(true);
        f.refresh();
        assertPresented(f, held);
      }
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void aSuccessfulRekeyDropsAnAliasWhoseSigningKeyWasDeactivated(
      KmipVersion version, boolean unique) throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      TlsIdentityHandle h = fx.register(NAME, TestPki.ec());
      TlsIdentityFollower f = fx.follow(NAME);
      String old = alias(fx, f);
      java.security.KeyPair next = TestPki.ec();
      h.rekey(next.getPrivate(), fx.pki.chain(fx.pki.leaf("next", next)));
      assertEquals(KeyState.DEACTIVATED, h.privateKey().attributes().state());
      assertEquals(TlsIdentityFollower.Status.CURRENT, f.refresh().status());
      String current = alias(fx, f);
      assertNotEquals(old, current);
      assertNull(f.keyManager().getPrivateKey(old));
      assertNull(f.keyManager().getCertificateChain(old));
      assertPresented(f, current);
      fx.server.unreachable(true);
      f.refresh();
      assertNull(f.keyManager().getPrivateKey(old));
      assertPresented(f, current);
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void renewalPairChecksRefuseUsageLimitsAndMissingSignBeforeFetching(
      KmipVersion version, boolean unique) throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      java.security.KeyPair pair = TestPki.ec();
      TlsIdentityHandle h = fx.register(NAME, pair);
      String id = h.privateKey().id();
      for (boolean limits : new boolean[] {true, false}) {
        fx.leasing.usageLimited.clear();
        fx.leasing.signingForbidden.clear();
        if (limits) fx.leasing.usageLimited.add(id);
        else fx.leasing.signingForbidden.add(id);
        fx.leasing.reset();
        assertThrows(
            UnsupportedException.class, () -> h.renew(fx.pki.chain(fx.pki.leaf("renewal", pair))));
        assertFalse(fx.leasing.trace.contains("Get " + id));
        assertEquals(
            h.certificate().id(), fx.kms.tls().identity(NAME).orElseThrow().certificate().id());
      }
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void renewalLeasesTheKeyAndChecksItsLoadersLaterRestriction(KmipVersion version, boolean unique)
      throws Exception {
    try (Fixture fx = new Fixture(version, unique)) {
      fx.leasing.everyObject = 300L;
      java.security.KeyPair pair = TestPki.ec();
      TlsIdentityHandle first = fx.register(NAME, pair);
      String id = first.privateKey().id();
      fx.leasing.reset();
      TlsIdentityHandle renewed = first.renew(fx.pki.chain(fx.pki.leaf("renewed", pair)));
      List<String> trace = List.copyOf(fx.leasing.trace);
      assertTrue(
          trace.contains("ObtainLease " + id)
              && trace.indexOf("ObtainLease " + id) < trace.indexOf("Get " + id),
          trace.toString());
      assertEquals(1, fx.leasing.obtainRequests.get());
      fx.leasing.onObtain = () -> fx.leasing.usageLimited.add(id);
      fx.leasing.reset();
      assertThrows(
          UnsupportedException.class,
          () -> renewed.renew(fx.pki.chain(fx.pki.leaf("restricted", pair))));
      assertFalse(fx.leasing.trace.contains("Get " + id));
      fx.leasing.usageLimited.clear();
      fx.leasing.onObtain = () -> {};
      fx.leasing.answer =
          ignored ->
              new LeasingTransport.Refuse(
                  dev.keytend.kmip.model.Enums.ResultReason.PERMISSION_DENIED);
      fx.leasing.reset();
      assertThrows(
          PermissionDeniedException.class,
          () -> renewed.renew(fx.pki.chain(fx.pki.leaf("denied", pair))));
      assertFalse(fx.leasing.trace.contains("Get " + id));
    }
  }

  @ParameterizedTest
  @MethodSource("servers")
  void aLoaderCannotSignWithAKeyItSeesDeactivated(KmipVersion version, boolean unique)
      throws Exception {
    for (boolean writer : new boolean[] {true, false}) {
      try (Fixture fx = new Fixture(version, unique)) {
        fx.leasing.everyObject = 300L;
        java.security.KeyPair pair = TestPki.ec();
        TlsIdentityHandle h = fx.register(NAME, pair);
        String id = h.privateKey().id();
        fx.leasing.onObtain = () -> h.privateKey().deactivate();
        fx.leasing.reset();
        StateConflictException e =
            assertThrows(
                StateConflictException.class,
                () -> {
                  if (writer) h.renew(fx.pki.chain(fx.pki.leaf("later", pair)));
                  else fx.follow(NAME);
                });
        assertEquals(KeyState.DEACTIVATED, e.observedState().orElseThrow());
        assertFalse(fx.leasing.trace.contains("Get " + id));
      }
    }
  }

  static void check(X509ExtendedTrustManager tm, X509Certificate[] chain, int overload)
      throws CertificateException {
    switch (overload) {
      case 0 -> tm.checkClientTrusted(chain, "EC");
      case 1 -> tm.checkServerTrusted(chain, "ECDHE_ECDSA");
      case 2 -> tm.checkClientTrusted(chain, "EC", (Socket) null);
      case 3 -> tm.checkServerTrusted(chain, "ECDHE_ECDSA", (Socket) null);
      case 4 -> tm.checkClientTrusted(chain, "EC", (SSLEngine) null);
      case 5 -> tm.checkServerTrusted(chain, "ECDHE_ECDSA", (SSLEngine) null);
      default -> throw new AssertionError(overload);
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anAnchorExpiringDuringUnknownPeerAdmissionIsRevalidatedInEveryOverload(KmipVersion version)
      throws Exception {
    try (Fixture fx = new Fixture(version, false)) {
      fx.leasing.everyObject = 300L;
      KeyHandle anchor = fx.anchor(fx.pki.root);
      fx.leasing.leaseTimes.put(anchor.id(), 100L);
      TlsTrustFollower t = fx.trust(SCHEDULER);
      t.unknownPeerCheck(Duration.ofSeconds(2)).unknownPeerCheckInHandshake(true);
      t.ticker = fx.now::get;
      for (int overload = 0; overload < 6; overload++) {
        t.refresh();
        Issued peer = fx.pki.leaf("peer" + overload, TestPki.ec());
        fx.peer(peer);
        fx.advance(2);
        fx.leasing.onObtain = () -> fx.advance(150);
        int n = overload;
        assertThrows(
            CertificateException.class,
            () -> check(t.trustManager(), fx.pki.chain(peer), n),
            "overload " + n);
        assertTrue(t.anchors().isEmpty());
        fx.leasing.onObtain = () -> {};
      }
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void unknownPeerChecksKeepAnEarlierRenewalButCanScheduleASoonerOne(KmipVersion version)
      throws Exception {
    try (Fixture fx = new Fixture(version, false)) {
      fx.leasing.everyObject = 300L;
      fx.anchor(fx.pki.root);
      Stalled scheduler = new Stalled();
      TlsTrustFollower t = fx.trust(scheduler);
      t.unknownPeerCheck(Duration.ofSeconds(2)).unknownPeerCheckInHandshake(true);
      t.ticker = fx.now::get;
      Stalled.Task first = scheduler.oneShots().get(0);
      for (int i = 0; i < 4; i++) {
        Issued stranger = fx.pki.leaf("stranger" + i, TestPki.ec());
        fx.advance(2);
        assertThrows(
            CertificateException.class,
            () -> t.trustManager().checkClientTrusted(fx.pki.chain(stranger), "EC"));
        assertFalse(first.future().isCancelled(), "an unknown peer cannot postpone the renewal");
        assertEquals(1, scheduler.oneShots().size());
      }
      Issued peer = fx.pki.leaf("short", TestPki.ec());
      KeyHandle id = fx.peer(peer);
      fx.leasing.leaseTimes.put(id.id(), 10L);
      fx.advance(2);
      t.trustManager().checkClientTrusted(fx.pki.chain(peer), "EC");
      assertTrue(first.future().isCancelled(), "a shorter new lease advances the renewal");
      assertEquals(2, scheduler.oneShots().size());
      assertTrue(scheduler.oneShots().get(1).delayNanos() <= TimeUnit.SECONDS.toNanos(5));
    }
  }
}
