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

import dev.keytend.kmip.kms.TlsRepeatTest.Call;
import dev.keytend.kmip.kms.TlsRepeatTest.Material;
import dev.keytend.kmip.kms.TlsRepeatTest.Scenario;
import dev.keytend.kmip.model.Ttlv;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * What a TLS identity's call leaves when it stops before its switch is never trusted and never
 * usable: its objects are Pre-Active, so a trust follower, whose anchors and allowed peers are the
 * Active certificates its queries match, never reads them, even when they carry the attribute an
 * allowed-peers query matches; and a leftover private key, a copy of the identity's key, cannot be
 * used. Revoking the identity's certificate after a repeat finished therefore ends the trust in it:
 * no second Active object holds the same certificate. The call stops dead at its switch, with no
 * reply, read back or clean-up, and is repeated on a new client.
 */
class TlsLeftoverTrustTest {
  static final String NAME = TlsRepeatTest.NAME;
  static final String OTHER = TlsRepeatTest.OTHER;
  static final CustomAttribute ROLE = CustomAttribute.client("tls-role");

  /** How the identity's certificate is revoked after the repeat. */
  enum Revocation {
    CESSATION,
    KEY_COMPROMISE;

    RevocationReason reason() {
      return this == CESSATION
          ? RevocationReason.cessationOfOperation("retired")
          : RevocationReason.keyCompromise(
              "leaked", java.time.Instant.parse("2026-11-01T00:00:00Z"));
    }
  }

  static Stream<Arguments> cases() {
    List<Arguments> out = new ArrayList<>();
    for (Arguments s : TlsIdentityTest.servers().toList())
      for (Call c : List.of(Call.REGISTER, Call.RENEW, Call.REKEY))
        for (Revocation r : Revocation.values())
          out.add(Arguments.of(s.get()[0], s.get()[1], c, r));
    return out.stream();
  }

  /** Whether {@code request} is {@code call}'s switch in {@code s}. */
  static boolean isTheSwitch(Scenario s, Call call, Ttlv request) {
    return call == Call.REGISTER
        ? TlsRepeatTest.namesOther(request)
        : TlsIdentityLifecycleTest.addsReplacementLink(request, s.start.certificate().id());
  }

  /**
   * A call stops dead just before its switch. Its leaf, which carries the allowed-peers attribute,
   * is Pre-Active and is not an allowed peer; its key and issuers are Pre-Active. A repeat
   * finishes, and the leaf is allowed; once the identity's certificate is revoked, it is not, and
   * the trust manager refuses it.
   */
  @ParameterizedTest
  @MethodSource("cases")
  void aStoppedCallsObjectsAreNeverTrustedAndRevokingTheIdentityEndsTheTrust(
      KmipVersion version, boolean unique, Call call, Revocation revocation) throws Exception {
    Material m = new Material();
    try (Scenario s = new Scenario(version, unique, m)) {
      s.other.keys().handle(s.start.certificate().id()).setCustomAttribute(ROLE, "peer");
      s.other.keys().register(m.pki.root.certificate()).custom(ROLE, "anchor").register();
      String name = call == Call.REGISTER ? OTHER : NAME;
      try (TlsTrustFollower trust =
          s.other
              .tls()
              .trustAnchors(
                  KeyQuery.all().custom(ROLE, "anchor"),
                  KeyQuery.all().custom(ROLE, "peer"),
                  HOURLY,
                  SCHEDULER)) {
        X509Certificate[] chain = chain(m, call);
        Set<String> before = Set.copyOf(s.server.ids());
        s.t.hook =
            r -> {
              if (isTheSwitch(s, call, r)) throw new TlsOwnershipTest.Stop();
            };
        assertThrows(TlsOwnershipTest.Stop.class, () -> run(s, call, chain));
        s.t.hook = r -> {};
        Set<String> left = new LinkedHashSet<>(s.server.ids());
        left.removeAll(before);
        assertFalse(left.isEmpty());
        for (String id : left)
          assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(id), "the leftover " + id);
        if (call == Call.RENEW)
          for (String id : left)
            assertFalse(
                s.server.links(s.start.privateKey().id(), LinkKind.CERTIFICATE).contains(id),
                "the identity's key links to the leftover " + id);
        trust.refresh();
        assertFalse(trust.allows(chain), "a leftover is an allowed peer");
        assertFalse(
            trust.allowedPeers().orElseThrow().containsValue(chain[0]),
            "a leftover is an allowed peer");

        s.reconnect();
        TlsIdentityHandle done = assertDoesNotThrow(() -> run(s, call, chain));
        assertFalse(left.contains(done.certificate().id()), "the repeat started over");
        trust.refresh();
        assertTrue(trust.allows(chain), "the identity's certificate is an allowed peer");

        s.other.tls().identity(name).orElseThrow().revoke(revocation.reason());
        trust.refresh();
        assertFalse(trust.allows(chain), "the revoked certificate is still allowed");
        assertFalse(trust.allowedPeers().orElseThrow().containsValue(chain[0]));
        X509Certificate[] presented = chain;
        assertThrows(
            CertificateException.class,
            () -> trust.trustManager().checkClientTrusted(presented, "EC"));
        for (String id : left)
          assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(id), "the leftover " + id);
        assertEquals(List.of(), s.server.violations());
      }
    }
  }

  /**
   * A re-key stops dead just before its switch; the repeat finishes, and the identity is re-keyed
   * once more. The stopped call's private key, a copy of the key it was given, is Pre-Active all
   * along: no Active object holds that key apart from the identity's own, which the second re-key
   * deactivates.
   */
  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void aStoppedReKeysPrivateKeyIsNeverActive(KmipVersion version, boolean unique) throws Exception {
    Material m = new Material();
    try (Scenario s = new Scenario(version, unique, m)) {
      Set<String> before = Set.copyOf(s.server.ids());
      s.t.hook =
          r -> {
            if (isTheSwitch(s, Call.REKEY, r)) throw new TlsOwnershipTest.Stop();
          };
      assertThrows(TlsOwnershipTest.Stop.class, () -> s.call(Call.REKEY));
      s.t.hook = r -> {};
      Set<String> left = new LinkedHashSet<>(s.server.ids());
      left.removeAll(before);
      List<String> leftKeys =
          left.stream()
              .filter(id -> s.server.kind(id).orElse(null) == ObjectKind.PRIVATE_KEY)
              .toList();
      assertEquals(1, leftKeys.size(), left.toString());
      s.reconnect();
      TlsIdentityHandle done = assertDoesNotThrow(() -> s.call(Call.REKEY));
      assertFalse(left.contains(done.privateKey().id()));
      TlsIdentityHandle again = done.rekey(m.k3.getPrivate(), m.pki.chain(m.theirsRekeyed));
      assertEquals(Optional.of(KeyState.DEACTIVATED), s.server.state(done.privateKey().id()));
      assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(leftKeys.get(0)));
      assertNotEquals(done.privateKey().id(), again.privateKey().id());
      assertEquals(List.of(), s.server.violations());
    }
  }

  private static X509Certificate[] chain(Material m, Call call) {
    return switch (call) {
      case REGISTER -> m.mineRekeyed.chain(m.pki.ca);
      case RENEW -> m.pki.chain(m.mineRenewed);
      case REKEY -> m.pki.chain(m.mineRekeyed);
      default -> throw new IllegalArgumentException(call.name());
    };
  }

  private static TlsIdentityHandle run(Scenario s, Call call, X509Certificate[] chain) {
    return switch (call) {
      case REGISTER ->
          s.kms
              .tls()
              .register(s.m.k2.getPrivate(), chain)
              .custom(ROLE, "peer")
              .named(OTHER)
              .register();
      case RENEW -> s.kms.tls().identity(NAME).orElseThrow().renew(chain);
      case REKEY -> s.kms.tls().identity(NAME).orElseThrow().rekey(s.m.k2.getPrivate(), chain);
      default -> throw new IllegalArgumentException(call.name());
    };
  }
}
