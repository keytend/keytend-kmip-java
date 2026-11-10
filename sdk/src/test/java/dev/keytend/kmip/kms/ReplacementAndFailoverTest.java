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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Concurrent compromise replacement, deadlines of slow single endpoints, failed first encrypts,
 * refused back links, retirement blocked by strangers' objects, listeners, and leftovers.
 */
class ReplacementAndFailoverTest {
  final List<Kms> clients = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
  }

  Kms connect(KmsConfig.Builder builder) {
    Kms kms = Kms.connect(builder.build());
    clients.add(kms);
    return kms;
  }

  static final byte[] PLAIN = "probe".getBytes(UTF_8), AAD = "aad".getBytes(UTF_8);

  static void noop(String s) {}

  static KeyCreation vault(Kms kms) {
    return kms.keys().createAes(256).named("vault").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
  }

  static RevocationReason leaked() {
    return RevocationReason.keyCompromise("leaked", java.time.Instant.now());
  }

  // ---- two instances replacing one compromised key at once fork the chain ----

  /**
   * Instance 2 calls replaceCompromised on a key that is already Compromised. Between its own check
   * for an existing replacement and rotate()'s pre-check, instance 1 re-keys the key (it is running
   * replaceCompromised too). rotate() then throws "already replaced" (a StateConflictException with
   * nothing sent), which replaceCompromised takes for a server refusal of Re-key, so it creates a
   * second, hand-linked replacement.
   */
  @Test
  void concurrentReplaceCompromisedDoesNotForkTheChain() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms one = connect(server.configure());
    KeyHandle kek = vault(one).findOrCreate();
    byte[] record = kek.seal(PLAIN, AAD);
    kek.revoke(leaked());
    AtomicInteger readsOfKek = new AtomicInteger();
    AtomicBoolean raced = new AtomicBoolean();
    List<String> firstReplacement = new ArrayList<>();
    Kms two =
        connect(
            server
                .configure()
                .transport(
                    e ->
                        request -> {
                          if (RotationAndNameChoiceTest.isOperation(
                                  request, Operation.GET_ATTRIBUTES)
                              && readsOfKek.incrementAndGet() == 2
                              && raced.compareAndSet(false, true)) {
                            // Instance 1 wins the race: its replaceCompromised re-keys now.
                            firstReplacement.add(
                                one.keys().handle(kek.id()).replaceCompromised(leaked()).id());
                          }
                          return server.exchange(request);
                        }));
    KeyHandle mine = two.keys().handle(kek.id()).replaceCompromised(leaked());
    assertTrue(raced.get());
    List<String> replacements = server.links(kek.id(), LinkKind.REPLACEMENT);
    noop(
        "fork: first="
            + firstReplacement
            + " second="
            + mine.id()
            + " kek replacements="
            + replacements);
    // Expected: both instances end with the same replacement and the chain is not forked.
    assertEquals(
        firstReplacement.get(0), mine.id(), "the two instances seal under different replacements");
    assertEquals(
        1, replacements.size(), "the compromised key has two replacements: " + replacements);
  }

  /** Both instances end with one replacement, and each opens what the other seals under it. */
  @Test
  void concurrentReplacementsConvergeOnOneKey() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms one = connect(server.configure());
    KeyHandle kek = vault(one).findOrCreate();
    kek.revoke(leaked());
    AtomicInteger readsOfKek = new AtomicInteger();
    List<KeyHandle> first = new ArrayList<>();
    Kms two =
        connect(
            server
                .configure()
                .transport(
                    e ->
                        request -> {
                          if (RotationAndNameChoiceTest.isOperation(
                                  request, Operation.GET_ATTRIBUTES)
                              && readsOfKek.incrementAndGet() == 2)
                            first.add(one.keys().handle(kek.id()).replaceCompromised(leaked()));
                          return server.exchange(request);
                        }));
    KeyHandle second = two.keys().handle(kek.id()).replaceCompromised(leaked());
    assertEquals(first.get(0).id(), second.id());
    assertArrayEquals(PLAIN, first.get(0).open(second.seal(PLAIN, AAD), AAD));
    assertEquals(second.id(), one.keys().findByName("vault").orElseThrow().id());
  }

  // ---- a slow but healthy endpoint never answers within the deadline ----

  /** A transport whose every Get Attributes is answered after {@code delay}, honoring the deadline. */
  static KmipTransport slowReads(InMemoryKmipServer server, AtomicInteger processed) {
    return new KmipTransport() {
      @Override
      public Ttlv exchange(Ttlv request) throws IOException {
        return exchange(request, CallContext.NONE);
      }

      @Override
      public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
        if (RotationAndNameChoiceTest.isOperation(request, Operation.GET_ATTRIBUTES)) {
          processed.incrementAndGet();
          server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.SLOW);
        }
        return server.exchange(request, context);
      }
    };
  }

  /**
   * One endpoint answering every read in 1.3 s, a 3 s call timeout, the default policy: before the
   * attempt timeout the read succeeded at 1.3 s. Now every attempt is cut at 1 s (3 s / 3) and the
   * last one gets only what is left (about 0.7 s), so the read can never succeed, and the server
   * processes it three times. The rule is that the last attempt gets the rest of the deadline, so a
   * slow answer is still taken.
   */
  @Test
  void aSlowButHealthySingleEndpointAnswersWithinTheDeadline() {
    InMemoryKmipServer server =
        InMemoryKmipServer.of(KmipVersion.V2_1).slowReplyDelay(Duration.ofMillis(1300));
    Kms setup = connect(server.configure());
    String id = vault(setup).create().id();
    AtomicInteger processed = new AtomicInteger();
    List<String> unavailable = new java.util.concurrent.CopyOnWriteArrayList<>();
    Kms kms =
        connect(
            server
                .configure()
                .callTimeout(Duration.ofSeconds(3))
                .addListener(
                    new KmsListener() {
                      @Override
                      public void endpointUnavailable(String endpoint, String why) {
                        unavailable.add(why);
                      }
                    })
                .transport(e -> slowReads(server, processed)));
    long start = System.nanoTime();
    KmsException failure = null;
    try {
      kms.keys().handle(id).attributes();
    } catch (KmsException e) {
      failure = e;
    }
    long ms = (System.nanoTime() - start) / 1_000_000;
    noop(
        "slow endpoint: after "
            + ms
            + " ms, "
            + processed.get()
            + " Get Attributes processed, unavailable="
            + unavailable
            + ", failure="
            + failure);
    assertNull(failure, "a 1.3 s read with a 3 s deadline on the only endpoint failed: " + failure);
  }

  /** The same with RetryPolicy.none(): the read succeeds (the behavior before the attempt timeout). */
  @Test
  void theSameReadSucceedsWithoutRetries() {
    InMemoryKmipServer server =
        InMemoryKmipServer.of(KmipVersion.V2_1).slowReplyDelay(Duration.ofMillis(1300));
    Kms setup = connect(server.configure());
    String id = vault(setup).create().id();
    AtomicInteger processed = new AtomicInteger();
    Kms kms =
        connect(
            server
                .configure()
                .callTimeout(Duration.ofSeconds(3))
                .retryPolicy(RetryPolicy.none())
                .transport(e -> slowReads(server, processed)));
    kms.keys().handle(id).attributes();
    assertEquals(1, processed.get());
  }

  // ---- the first encrypt's usage read names itself "attributes" ----

  @Test
  void aFailedFirstEncryptNamesAttributesNotEncrypt() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server.configure());
    KmsException e =
        assertThrows(
            KmsException.class,
            () -> kms.keys().handle("no-such-key").encrypt(CipherSpec.aesGcm(), PLAIN, AAD));
    noop(
        "usage read: "
            + e.getClass().getSimpleName()
            + " operation="
            + e.operation()
            + " msg="
            + e.getMessage());
    assertEquals("encrypt", e.operation());
  }

  // ---- replaceCompromised hands out a Compromised "replacement" ----

  /**
   * A stale handle on A (another instance rotated A to B); B is then revoked as compromised by an
   * operator. A.replaceCompromised(...) revokes A, finds B through A's link, and returns B, which is
   * Compromised, as "the replacement, Active", moving A's names onto it.
   */
  @Test
  void replaceCompromisedReplacesACompromisedSuccessorInTurn() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server.configure());
    KeyHandle a = vault(kms).findOrCreate();
    KeyHandle b = a.rotate();
    b.revoke(leaked());
    KeyHandle replacement = a.replaceCompromised(leaked());
    noop(
        "compromised replacement: a="
            + a.id()
            + " b="
            + b.id()
            + " replacement="
            + replacement.id()
            + " state="
            + server.state(replacement.id()));
    assertEquals(
        Optional.of(KeyState.ACTIVE),
        server.state(replacement.id()),
        "replaceCompromised returned a key that is not Active");
    assertNotEquals(b.id(), replacement.id());
    assertEquals(
        List.of(b.id()),
        server.links(replacement.id(), LinkKind.REPLACED),
        "B was replaced in turn");
    assertEquals(replacement.id(), kms.keys().findByName("vault").orElseThrow().id());
  }

  static boolean hasLinkType(Ttlv t, int type) {
    if (t.tag() == Tag.LINK_TYPE.code() && t.type() == Ttlv.Type.ENUMERATION)
      return t.intValue() == type;
    if (t.type() != Ttlv.Type.STRUCTURE) return false;
    for (Ttlv c : t.children()) if (hasLinkType(c, type)) return true;
    return false;
  }

  // ---- a refused second link makes the documented repeat fail ----

  /**
   * Re-key refused, the old key's Replacement Object link accepted, the new key's Replaced Object link
   * refused: the first call returned the replacement (linked=false). Repeating, as the Javadoc said
   * one could, followed the one-sided link and failed. The call ends in a
   * PartialCompletionException naming both keys, after taking the first link back.
   */
  @Test
  void aRefusedBackLinkLeavesNoOneSidedLink() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicBoolean refuseReplacedLink = new AtomicBoolean(true);
    Kms kms =
        connect(
            server
                .configure()
                .transport(
                    e ->
                        request -> {
                          if (refuseReplacedLink.get()
                              && RotationAndNameChoiceTest.isOperation(
                                  request, Operation.ADD_ATTRIBUTE)
                              && hasLinkType(request, 0x107)) {
                            refuseReplacedLink.set(false);
                            return Faults.failure(
                                request,
                                Enums.ResultReason.PERMISSION_DENIED,
                                "no links on new keys");
                          }
                          return server.exchange(request);
                        }));
    KeyHandle kek = vault(kms).findOrCreate();
    server.failNext(ServerOperation.RE_KEY, Fault.STATE_CONFLICT);
    // Unlinked: a PartialCompletionException naming both keys, not a replacement returned.
    PartialCompletionException unlinked =
        assertThrows(PartialCompletionException.class, () -> kek.replaceCompromised(leaked()));
    KeyHandle replacement = unlinked.created().get(0);
    assertTrue(
        unlinked.getMessage().contains("not linked to the Compromised key " + kek.id()),
        unlinked.getMessage());
    noop(
        "refused link: refusal used="
            + !refuseReplacedLink.get()
            + " kek REPLACEMENT links="
            + server.links(kek.id(), LinkKind.REPLACEMENT)
            + " replacement REPLACED links="
            + server.links(replacement.id(), LinkKind.REPLACED));
    // The refused back link leaves no one-sided link: the old key's chain still reads.
    assertEquals(List.of(), server.links(kek.id(), LinkKind.REPLACEMENT));
    assertEquals(kek.id(), kek.latest().id());
    assertEquals(Optional.of(KeyState.ACTIVE), server.state(replacement.id()));
    assertEquals(replacement.id(), kms.keys().findByName("vault").orElseThrow().id());
  }

  // ---- a Pre-Active object the caller may not destroy blocks retirement for good ----

  @Test
  void anUndestroyablePreActiveObjectWithTheNameDoesNotBlockRetirement() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    java.time.Instant t0 = java.time.Instant.parse("2026-10-01T00:00:00Z");
    java.util.concurrent.atomic.AtomicLong seconds = new java.util.concurrent.atomic.AtomicLong();
    server.clock(
        new java.time.Clock() {
          @Override
          public java.time.ZoneId getZone() {
            return java.time.ZoneOffset.UTC;
          }

          @Override
          public java.time.Clock withZone(java.time.ZoneId zone) {
            return this;
          }

          @Override
          public java.time.Instant instant() {
            return t0.plusSeconds(seconds.getAndAdd(10));
          }
        });
    Kms other = connect(server.configure());
    List<String> foreign = new ArrayList<>();
    Kms kms =
        connect(
            server
                .configure()
                .transport(
                    e ->
                        request -> {
                          if (RotationAndNameChoiceTest.isOperation(request, Operation.DESTROY)
                              && ReplicaFailoverTest.target(request)
                                  .map(foreign::contains)
                                  .orElse(false))
                            return Faults.failure(
                                request, Enums.ResultReason.PERMISSION_DENIED, "not yours");
                          return server.exchange(request);
                        }));
    KeyHandle a = vault(kms).findOrCreate();
    // Another tenant (same name, its own credentials) has a Pre-Active object named "vault".
    foreign.add(
        other
            .keys()
            .createAes(256)
            .named("vault")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .createPreActive()
            .id());
    KeyHandle b = a.rotate();
    KmsException e = null;
    try {
      b.retirePredecessors(RevocationReason.superseded("rotated"));
    } catch (KmsException x) {
      e = x;
    }
    noop("undestroyable: " + e + "; a is " + server.state(a.id()));
    assertNull(e, "retirement fails before retiring anything: " + e);
  }

  // ---- a listener that checks isLatest() on staleHandle recurses without bound ----

  @Test
  void aListenerCheckingIsLatestDoesNotRecurse() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicInteger depth = new AtomicInteger();
    List<KeyHandle> holder = new java.util.concurrent.CopyOnWriteArrayList<>();
    Kms kms =
        connect(
            server
                .configure()
                .addListener(
                    new KmsListener() {
                      @Override
                      public void staleHandle(String keyId, List<String> replacements) {
                        if (depth.incrementAndGet() > 50)
                          return; // stop the probe before the stack ends
                        KeyHandle k = holder.get(0);
                        if (!k.isLatest()) holder.set(0, k.latest());
                      }
                    }));
    KeyHandle kek = vault(kms).findOrCreate();
    holder.add(kek);
    kek.rotate();
    kek.isLatest();
    noop("listener recursion: staleHandle ran " + depth.get() + " times for one isLatest()");
    assertTrue(depth.get() <= 2, "re-entered " + depth.get() + " times");
  }

  // ---- the guide's readiness probe (a 2 s view) never fails over from a hung replica ----

  @Test
  void theGuidesReadinessProbeFailsOver() {
    InMemoryKmipServer a = InMemoryKmipServer.of(KmipVersion.V2_1);
    InMemoryKmipServer b = a.replica();
    AtomicBoolean hangA = new AtomicBoolean();
    KmipTransport hungA =
        new KmipTransport() {
          @Override
          public Ttlv exchange(Ttlv request) throws IOException {
            return exchange(request, CallContext.NONE);
          }

          @Override
          public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
            if (!hangA.get()) return a.exchange(request, context);
            try {
              Thread.sleep(Math.max(0, context.remainingNanos() / 1_000_000));
            } catch (InterruptedException e) {
              throw new java.io.InterruptedIOException();
            }
            throw new java.net.SocketTimeoutException("KMIP exchange deadline exceeded");
          }
        };
    KmsConfig.Builder builder = a.configureReplicas(b);
    Kms kms =
        connect(
            builder.transport(
                e -> e.host().equals("in-memory") ? hungA : b)); // default 30 s, as in the guide
    hangA.set(true);
    int failures = 0;
    long start = System.nanoTime();
    for (int i = 0; i < 3; i++) {
      try {
        kms.withTimeout(Duration.ofSeconds(15))
            .ping(); // docs/production.md, "Readiness": above the attempt timeout
      } catch (TransientException e) {
        failures++;
      }
    }
    noop(
        "readiness: "
            + failures
            + " of 3 probes failed in "
            + (System.nanoTime() - start) / 1_000_000
            + " ms while replica B was healthy");
    assertEquals(0, failures, "the readiness probe failed although B answers");
  }

  // ---- the STATE advice for a record under a Compromised key launders a forged record ----

  /**
   * Duplicate-name server, an attacker who may create keys, set names and links on their own
   * keys, and put a record in the victim's store. The attacker seals a record under their own key X
   * named like the victim's, then revokes X as compromised. The victim's open must not be
   * BAD_DATA (quarantine): it is STATE whose message says: if X is yours ("check its name with
   * ...attributes()"), recover with handle(X).allowingCompromised() and rewrapTo the current key.
   * The name check passes (X is named "vault"), and following the advice turns the forged record
   * into an authentic record under the victim's key.
   */
  @Test
  void theCompromisedRecordAdviceDoesNotTrustTheName() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms victim = connect(server.configure());
    Kms attacker = connect(server.configure());
    KeyHandle kek = vault(victim).findOrCreate();
    KeyHandle x = vault(attacker).create(); // the attacker's own key, named like the victim's
    byte[] forged = x.seal("pay mallory".getBytes(UTF_8), AAD);
    x.revoke(leaked());
    KmsException e = assertThrows(KmsException.class, () -> kek.open(forged, AAD));
    noop(
        "STATE advice: "
            + e.getClass().getSimpleName()
            + " "
            + e.category()
            + ": "
            + e.getMessage());
    assertEquals(KmsException.Category.STATE, e.category());
    assertFalse(e.getMessage().contains("check its name"), e.getMessage());
    assertTrue(
        e.getMessage().contains("a name proves nothing") && e.getMessage().contains("forged"),
        e.getMessage());
  }

  /** Leftovers are found also for a key that was never rotated (listed, not destroyed). */
  @Test
  void leftoversAreListedAlsoForANeverRotatedKey() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    java.time.Instant t0 = java.time.Instant.parse("2026-10-01T00:00:00Z");
    java.util.concurrent.atomic.AtomicLong seconds = new java.util.concurrent.atomic.AtomicLong();
    server.clock(
        new java.time.Clock() {
          @Override
          public java.time.ZoneId getZone() {
            return java.time.ZoneOffset.UTC;
          }

          @Override
          public java.time.Clock withZone(java.time.ZoneId zone) {
            return this;
          }

          @Override
          public java.time.Instant instant() {
            return t0.plusSeconds(seconds.getAndAdd(10));
          }
        });
    Kms kms = connect(server.configure());
    KeyHandle leftover = vault(kms).createPreActive();
    KeyHandle current = vault(kms).create();
    assertEquals(List.of(), current.retirePredecessors(RevocationReason.superseded("x")));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(leftover.id()));
    assertEquals(List.of(leftover.id()), current.leftovers().stream().map(KeyHandle::id).toList());
  }
}
