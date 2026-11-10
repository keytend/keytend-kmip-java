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

package dev.keytend.kmip;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpsServer;
import dev.keytend.kmip.kms.CustomAttribute;
import dev.keytend.kmip.kms.Expect;
import dev.keytend.kmip.kms.KeyCreation;
import dev.keytend.kmip.kms.KeyQuery;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.LocalKeys;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.HttpsTransport;
import dev.keytend.kmip.transport.TlsTransport;
import java.net.URL;
import java.net.URLClassLoader;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import org.junit.jupiter.api.Test;

/**
 * The threads the SDK starts belong to none of its callers: an application (a database node
 * in an in-JVM test cluster, say) that connects first must not find an SDK thread in its thread
 * group, nor have its class loader held by one, and every SDK thread ends once its owner is closed
 * (or, for the shared deadline and body pools, soon after the last exchange).
 */
class SdkThreadsTest {
  /**
   * The SDK threads alive now: those in its thread group, and any named as its threads are. The
   * JDK's common fork-join pool is the JVM's, not the SDK's (the JDK's HTTP client hands work to
   * it, which may start a worker in the group of the SDK thread that did): left out.
   */
  static Set<Thread> sdkThreads() {
    Set<Thread> out = new HashSet<>();
    for (Thread t : Thread.getAllStackTraces().keySet()) {
      if (t instanceof java.util.concurrent.ForkJoinWorkerThread w
          && w.getPool() == java.util.concurrent.ForkJoinPool.commonPool()) continue;
      ThreadGroup g = t.getThreadGroup();
      String n = t.getName();
      if ((g != null && g.getName().equals("keytend-kmip"))
          || n.startsWith("kmip-")
          || n.startsWith("keytend-")
          || n.startsWith("HttpClient-")) out.add(t);
    }
    return out;
  }

  /** Runs {@code work} on a thread of a caller's own group with its own context class loader. */
  static void asACaller(ThreadGroup group, ClassLoader loader, Callable<?> work) throws Exception {
    Exception[] failed = {null};
    Error[] error = {null};
    Thread t =
        new Thread(
            group,
            () -> {
              try {
                work.call();
              } catch (Exception e) {
                failed[0] = e;
              } catch (Error e) {
                error[0] = e;
              }
            },
            "caller");
    t.setContextClassLoader(loader);
    t.start();
    t.join();
    if (error[0] != null) throw error[0];
    if (failed[0] != null) throw failed[0];
  }

  /** None of {@code threads} is in {@code group} (or under it) or holds {@code loader}. */
  static void assertNotTheCallers(Set<Thread> threads, ThreadGroup group, ClassLoader loader) {
    List<String> wrong = new ArrayList<>();
    for (Thread t : threads) {
      for (ThreadGroup g = t.getThreadGroup(); g != null; g = g.getParent())
        if (g == group) wrong.add(t.getName() + " is in the caller's group");
      if (t.getContextClassLoader() == loader)
        wrong.add(t.getName() + " holds the caller's class loader");
    }
    assertEquals(List.of(), wrong);
  }

  /** Every thread of {@code started} ends within a few seconds. */
  static void assertEnd(Set<Thread> started) throws InterruptedException {
    long until = System.nanoTime() + Duration.ofSeconds(10).toNanos();
    for (Thread t : started) t.join(Math.max(1, (until - System.nanoTime()) / 1_000_000));
    List<String> alive = started.stream().filter(Thread::isAlive).map(Thread::getName).toList();
    assertEquals(List.of(), alive, "SDK threads left behind");
  }

  @Test
  void transportThreadsAreNotTheFirstCallersAndEndAfterUse() throws Exception {
    ThreadGroup node = new ThreadGroup("node1");
    ClassLoader loader = new URLClassLoader(new URL[0]);
    // An earlier test's shared watchdog or body thread ends a second after its last exchange: wait
    // for it, so that this test's caller starts them afresh.
    assertEnd(
        sdkThreads().stream()
            .filter(
                t ->
                    t.getName().startsWith("kmip-transport-")
                        || t.getName().startsWith("kmip-https-"))
            .collect(java.util.stream.Collectors.toSet()));
    Set<Thread> before = sdkThreads();
    Set<Thread> during = new HashSet<>();
    HttpsServer https = TransportTest.https(TransportTest.answering());
    try (TestKmipServer tlsServer = TestKmipServer.answeringQueries()) {
      asACaller(
          node,
          loader,
          () -> {
            try (TlsTransport tls = TransportTest.client(tlsServer).build();
                HttpsTransport h =
                    new HttpsTransport(
                        TransportTest.uri(https),
                        TestTls.context("client", "server"),
                        HttpsTransport.Encoding.TTLV)) {
              assertNotNull(tls.exchange(TransportTest.query()));
              assertNotNull(h.exchange(TransportTest.query()));
              during.addAll(sdkThreads());
              assertNotTheCallers(
                  during, node, loader); // while they run: an ended thread has no group
            }
            return null;
          });
    } finally {
      https.stop(0);
    }
    during.removeAll(before);
    assertTrue(
        during.stream().anyMatch(t -> t.getName().equals("kmip-transport-deadlines")),
        during.toString());
    assertTrue(
        during.stream().anyMatch(t -> t.getName().startsWith("kmip-https")), during.toString());
    assertEnd(during);
  }

  @Test
  void aLocalKeysCachesRefreshWorkerIsNotTheCallersAndEndsWithIt() throws Exception {
    ThreadGroup node = new ThreadGroup("node2");
    ClassLoader loader = new URLClassLoader(new URL[0]);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    CustomAttribute family = CustomAttribute.client("family");
    Set<Thread> before = sdkThreads();
    Set<Thread> during = new HashSet<>();
    try (Kms kms = server.connect()) {
      KeyCreation c =
          kms.keys()
              .createAes(256)
              .custom(family, "orders")
              .extractable(true)
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named("orders-write");
      c.create();
      asACaller(
          node,
          loader,
          () -> {
            try (LocalKeys keys =
                kms.keys()
                    .localKeys("orders-write")
                    .scope(KeyQuery.all().custom(family, "orders"))
                    .expect(Expect.aes(256))
                    .ttl(Duration.ofSeconds(30))
                    .refreshAfter(Duration.ofMillis(1))
                    .open()) {
              keys.forEncrypt().close();
              Thread.sleep(5);
              keys.forEncrypt().close(); // queues a refresh on the cache's own worker
              for (int i = 0;
                  i < 200
                      && sdkThreads().stream()
                          .noneMatch(t -> t.getName().equals("keytend-local-keys-refresh"));
                  i++) Thread.sleep(5);
              during.addAll(sdkThreads());
              assertNotTheCallers(
                  during, node, loader); // while they run: an ended thread has no group
            }
            return null;
          });
    }
    during.removeAll(before);
    assertTrue(
        during.stream().anyMatch(t -> t.getName().equals("keytend-local-keys-refresh")),
        during.toString());
    assertEnd(during);
  }

  /**
   * A thread made by any of the SDK's three thread factories
   * ({@code kms}, {@code transport}, {@code server}) does not inherit the creating thread's {@link
   * InheritableThreadLocal} values, such as a logging context, which a shared thread would otherwise
   * keep alive for as long as it runs.
   */
  @Test
  void sdkThreadsDoNotInheritTheCallersInheritableThreadLocals() throws Exception {
    InheritableThreadLocal<Object> context = new InheritableThreadLocal<>();
    for (String factory :
        List.of(
            "dev.keytend.kmip.kms.SdkThreads",
            "dev.keytend.kmip.transport.SdkThreads",
            "dev.keytend.kmip.server.SdkThreads")) {
      java.lang.reflect.Method daemon =
          Class.forName(factory).getDeclaredMethod("daemon", Runnable.class, String.class);
      daemon.setAccessible(true);
      Object[] seen = {"not run"};
      Object value = new Object();
      context.set(value);
      try {
        Thread t =
            (Thread)
                daemon.invoke(
                    null, (Runnable) () -> seen[0] = context.get(), "keytend-inheritance-probe");
        t.start();
        t.join(10_000);
        assertFalse(t.isAlive());
        assertNull(seen[0], factory + ": the creating thread's inheritable value");
        assertTrue(t.isDaemon(), factory);
        assertNull(t.getContextClassLoader(), factory);
      } finally {
        context.remove();
      }
    }
  }
}
