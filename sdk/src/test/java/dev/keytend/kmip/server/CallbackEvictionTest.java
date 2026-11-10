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

package dev.keytend.kmip.server;

import static org.junit.jupiter.api.Assertions.*;

import java.net.InetAddress;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Which pending handshake a full handshake pool evicts. The
 * holders are the connections holding a handshake thread, oldest first, plus the arrival; only
 * those still in their TLS handshake can be evicted.
 */
class CallbackEvictionTest {
  record Holder(String name, InetAddress peer, boolean handshaking) {}

  static Holder pending(String name, String address) throws Exception {
    return new Holder(name, InetAddress.getByName(address), true);
  }

  /** Its handshake has finished (or failed), but it still holds its thread. */
  static Holder finished(String name, String address) throws Exception {
    return new Holder(name, InetAddress.getByName(address), false);
  }

  static Holder victim(List<Holder> holders, Holder arriving) {
    return CallbackServer.victim(holders, Holder::handshaking, arriving, Holder::peer);
  }

  /**
   * With no repeat address the oldest pending handshake goes, so connections from many
   * addresses cannot keep the KMIP server's callback out (rather than evicting nothing and dropping it).
   */
  @Test
  void withEveryHolderFromADifferentAddressTheOldestPendingHandshakeIsEvicted() throws Exception {
    Holder a = pending("a", "127.0.0.2"), b = pending("b", "127.0.0.3");
    Holder c = pending("c", "127.0.0.4"), kms = pending("kms", "127.0.0.1");
    assertEquals(a, victim(List.of(a, b, c, kms), kms));
    assertEquals(a, victim(List.of(a, kms), kms), "a pool of one");
    // A holder whose handshake has finished is not evictable; the next oldest goes.
    Holder done = finished("done", "127.0.0.5");
    assertEquals(b, victim(List.of(done, b, c, kms), kms));
    assertNull(victim(List.of(done, kms), kms));
    assertNull(victim(List.of(kms), kms), "never the arrival itself");
  }

  /**
   * An address with repeat connections evicts its own oldest pending handshake, and
   * evicts nothing when none of its own is pending, even if the KMIP server's is.
   */
  @Test
  void aRepeatAddressEvictsOnlyItsOwnAndNeverTheKmipServersSingleHandshake() throws Exception {
    Holder kms = pending("kms", "127.0.0.1");
    Holder f1 = pending("f1", "127.0.0.2"), f2 = pending("f2", "127.0.0.2");
    Holder f3 = pending("f3", "127.0.0.2");
    assertEquals(f1, victim(List.of(kms, f1, f2, f3), f3));
    // A race: the flood's earlier handshakes have failed but their threads are not
    // free yet. They still count for the flood's address, so the KMIP server's handshake stays.
    Holder d1 = finished("d1", "127.0.0.2"), d2 = finished("d2", "127.0.0.2");
    assertNull(victim(List.of(kms, d1, d2, f3), f3));
    assertEquals(f2, victim(List.of(kms, d1, f2, f3), f3));
  }

  @Test
  void otherwiseTheBusiestAddressLosesItsOldestWithTheArrivalsOwnAddressFirstOnATie()
      throws Exception {
    Holder kms = pending("kms", "127.0.0.1");
    Holder f1 = pending("f1", "127.0.0.2"), f2 = pending("f2", "127.0.0.2");
    Holder other = pending("other", "127.0.0.3");
    assertEquals(f1, victim(List.of(kms, f1, f2, other), other));
    // The busiest address has nothing pending: nothing is evicted, its threads are freeing.
    Holder d1 = finished("d1", "127.0.0.2"), d2 = finished("d2", "127.0.0.2");
    assertNull(victim(List.of(kms, d1, d2, other), other));
    // Two addresses tie for the most and one is the arrival's: its own oldest goes.
    Holder a1 = pending("a1", "127.0.0.4"), a2 = pending("a2", "127.0.0.4");
    assertEquals(a1, victim(List.of(f1, a1, f2, a2), a2));
    // Two addresses tie and neither is the arrival's: the oldest of either.
    assertEquals(f1, victim(List.of(f1, a1, f2, a2, other), other));
  }
}
