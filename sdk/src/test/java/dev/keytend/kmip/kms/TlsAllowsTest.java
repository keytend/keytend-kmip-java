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

import dev.keytend.kmip.kms.TestPki.Issued;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * {@link TlsTrustFollower#allows}: what a validator that runs after the handshake asks. From memory:
 * the chain validates against the anchors whose leases run, and its leaf is an allowed peer whose
 * lease runs; the KMS is never asked.
 */
class TlsAllowsTest {
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aChainIsAllowedOnlyWhileItsAnchorAndItsLeafAreInUse(KmipVersion version) throws Exception {
    try (TlsLeaseTest.Fixture fx = new TlsLeaseTest.Fixture(version, false)) {
      fx.server.leaseTime(Duration.ofMinutes(5));
      fx.leasing.leaseTimes.put(fx.anchor(fx.pki.root).id(), 100L); // the anchor's lease ends first
      Issued peer = fx.pki.leaf("peer", TestPki.ec()), other = fx.pki.leaf("other", TestPki.ec());
      KeyHandle registered = fx.peer(peer);
      TlsTrustFollower t = fx.trust(SCHEDULER);
      X509Certificate[] chain = fx.pki.chain(peer);
      assertTrue(t.allows(chain));
      // Chains to the anchors but is not an allowed peer: refused, and nothing asked or queued.
      t.unknownPeerCheck(Duration.ofSeconds(2));
      fx.peer(other); // registered, but not read by this follower yet
      int exchanges = fx.server.exchanges();
      assertFalse(t.allows(fx.pki.chain(other)));
      assertEquals(exchanges, fx.server.exchanges(), "allows never asks the KMS");
      // Not chained to an anchor; empty; null; a chain without its leaf.
      TlsIdentityTest.Pki foreign = new TlsIdentityTest.Pki();
      assertFalse(t.allows(foreign.chain(foreign.leaf("peer", TestPki.ec()))));
      assertFalse(t.allows(new X509Certificate[0]));
      assertFalse(t.allows(null));
      assertFalse(
          t.allows(new X509Certificate[] {fx.pki.ca.certificate(), fx.pki.root.certificate()}));
      // The caller's array is not changed.
      X509Certificate first = chain[0];
      t.allows(chain);
      assertSame(first, chain[0]);
      // Leases: a lease that ended ends the trust, from memory: the anchor's first, then the
      // peer's.
      fx.advance(101);
      assertFalse(t.allows(chain), "the anchor's lease ended, the peer's runs");
      t.refresh();
      assertTrue(t.allows(chain), "renewed");
      fx.advance(301);
      assertFalse(t.allows(chain));
      t.refresh();
      assertTrue(t.allows(chain));
      // A revoked allowed peer is no longer located at the next refresh.
      registered.revoke(RevocationReason.keyCompromise("leaked", Instant.now()));
      t.refresh();
      assertFalse(t.allows(chain));
      t.close();
      assertFalse(t.allows(fx.pki.chain(other)));
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_1"})
  void withoutAnAllowlistTheAnchorsDecide(KmipVersion version) throws Exception {
    try (TlsLeaseTest.Fixture fx = new TlsLeaseTest.Fixture(version, false)) {
      fx.anchor(fx.pki.root);
      try (TlsTrustFollower t =
          fx.kms
              .tls()
              .trustAnchors(KeyQuery.all().custom(TlsLeaseTest.TAG, "ca"), HOURLY, SCHEDULER)) {
        assertTrue(t.allows(fx.pki.chain(fx.pki.leaf("anyone", TestPki.ec()))));
        TlsIdentityTest.Pki foreign = new TlsIdentityTest.Pki();
        assertFalse(t.allows(foreign.chain(foreign.leaf("stranger", TestPki.ec()))));
      }
    }
  }
}
