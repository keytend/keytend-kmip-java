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
import dev.keytend.kmip.kms.TlsIdentityTest.Pki;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.LockSupport;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The property: readers racing renewals and re-keys never present a mismatched pair, never present
 * nothing, and never go back to an older pair. Every request of the writer and of the readers is
 * delayed by a random time under a millisecond, so the readers' requests fall between the writer's
 * at random; some of the writer's calls are cut at a random request (the request not processed, or
 * processed and its reply lost) and repeated until they finish.
 */
class TlsIdentityRaceTest {
  static final String NAME = "node";
  static final int CALLS = 40;

  /** A transport to {@code server} that waits up to {@code maxNanos} before each exchange. */
  static KmipTransport jittered(InMemoryKmipServer server, long maxNanos) {
    return new KmipTransport() {
      @Override
      public Ttlv exchange(Ttlv request) throws IOException {
        return exchange(request, CallContext.NONE);
      }

      @Override
      public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
        LockSupport.parkNanos(ThreadLocalRandom.current().nextLong(maxNanos));
        return server.exchange(request, context);
      }
    };
  }

  static Kms connect(InMemoryKmipServer server, RetryPolicy retry) {
    KmipTransport t = jittered(server, 500_000);
    return Kms.connect(
        server
            .configure()
            .transport(e -> t)
            .maximumVersion(KmipVersion.V3_0)
            .retryPolicy(retry)
            .callTimeout(Duration.ofSeconds(10))
            .build());
  }

  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void readersRacingRenewalsAlwaysPresentAWholeCurrentPair(KmipVersion version, boolean unique)
      throws Exception {
    long seed = new Random().nextLong();
    Random random = new Random(seed);
    InMemoryKmipServer server = InMemoryKmipServer.of(version).uniqueNames(unique);
    InMemoryKmipServer replica = server.replica();
    Pki pki = new Pki();
    Map<X509Certificate, Integer> order = new ConcurrentHashMap<>();
    Queue<String> failures = new ConcurrentLinkedQueue<>();
    AtomicBoolean done = new AtomicBoolean();
    AtomicInteger observed = new AtomicInteger(), cuts = new AtomicInteger();
    try (Kms writer = connect(server, RetryPolicy.none());
        Kms reader = connect(replica, RetryPolicy.defaults())) {
      KeyPair key = TestPki.ec();
      Issued first = pki.leaf("node", key);
      order.put(first.certificate(), 0);
      TlsIdentityHandle identity =
          writer.tls().register(key.getPrivate(), pki.chain(first)).named(NAME).register();
      Runnable warm =
          () -> {
            int last = -1;
            try (TlsIdentityFollower f = reader.tls().follow(NAME, HOURLY, SCHEDULER)) {
              while (!done.get()) {
                TlsIdentityFollower.State s = f.refresh();
                last = check(f, s, order, last, "warm", failures);
                observed.incrementAndGet();
              }
            } catch (RuntimeException e) {
              failures.add("warm: " + e);
            }
          };
      Runnable cold =
          () -> {
            int last = -1;
            while (!done.get()) {
              try (TlsIdentityFollower f = reader.tls().follow(NAME, HOURLY, SCHEDULER)) {
                last = check(f, f.state(), order, last, "cold", failures);
                observed.incrementAndGet();
              } catch (RuntimeException e) {
                // A re-key that deactivates the pair a starting follower read, before or after
                // its loader read the key, is read again: starting is never refused.
                failures.add("cold: " + e);
              }
            }
          };
      Thread a = new Thread(warm), b = new Thread(cold);
      a.start();
      b.start();
      try {
        for (int i = 1; i <= CALLS && failures.isEmpty(); i++) {
          boolean rekey = random.nextBoolean();
          if (rekey) key = TestPki.ec();
          Issued next = pki.leaf("node", key);
          order.put(next.certificate(), i);
          if (random.nextInt(3) == 0) {
            // Cut this call at a random request: not processed, or processed and its reply lost.
            int at = 1 + random.nextInt(24);
            boolean after = random.nextBoolean();
            int[] seen = {0};
            if (after)
              server.injectAfterProcessing(
                  r -> ++seen[0] == at ? new SocketTimeoutException("lost") : null);
            else
              server.injectBeforeProcessing(r -> ++seen[0] == at ? new IOException("cut") : null);
            cuts.incrementAndGet();
          }
          TlsIdentityHandle result = null;
          for (int attempt = 1; result == null; attempt++) {
            try {
              result =
                  rekey
                      ? identity.rekey(key.getPrivate(), pki.chain(next))
                      : identity.renew(pki.chain(next));
            } catch (PartialCompletionException
                | OutcomeUnknownException
                | TransientException stopped) {
              server.injectBeforeProcessing(null);
              server.injectAfterProcessing(null);
              assertTrue(attempt < 3, "seed " + seed + ": " + stopped);
            }
          }
          server.injectBeforeProcessing(null);
          server.injectAfterProcessing(null);
          identity = result;
        }
      } finally {
        done.set(true);
        a.join();
        b.join();
      }
      assertEquals(List.of(), List.copyOf(failures), "seed " + seed);
      assertTrue(observed.get() > CALLS, "seed " + seed + ": " + observed.get() + " reads");
      assertEquals(List.of(), server.violations());
    }
  }

  /** The pair presented is whole, the newest seen so far or a newer one; returns its place in the order. */
  static int check(
      TlsIdentityFollower f,
      TlsIdentityFollower.State s,
      Map<X509Certificate, Integer> order,
      int last,
      String who,
      Queue<String> failures) {
    if (s.status() != TlsIdentityFollower.Status.CURRENT
        && s.status() != TlsIdentityFollower.Status.REPLACING) {
      failures.add(who + ": " + s);
      return last;
    }
    String alias = f.keyManager().chooseServerAlias("EC", null, null);
    if (alias == null) {
      failures.add(who + ": no alias, " + s);
      return last;
    }
    PrivateKey k = f.keyManager().getPrivateKey(alias);
    X509Certificate[] chain = f.keyManager().getCertificateChain(alias);
    if (k == null || chain == null || !TlsIdentities.matches(k, chain[0].getPublicKey())) {
      failures.add(who + ": mismatched pair " + s);
      return last;
    }
    Integer at = order.get(chain[0]);
    if (at == null || at < last)
      failures.add(who + ": went back from " + last + " to " + at + ", " + s);
    return at == null ? last : at;
  }
}
