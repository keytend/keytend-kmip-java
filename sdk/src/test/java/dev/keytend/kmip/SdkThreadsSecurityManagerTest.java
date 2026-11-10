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
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import dev.keytend.kmip.kms.CustomAttribute;
import dev.keytend.kmip.kms.Expect;
import dev.keytend.kmip.kms.KeyCreation;
import dev.keytend.kmip.kms.KeyQuery;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.LocalKeys;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.Permission;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;

/**
 * The SDK's threads under a SecurityManager, each case in a JVM of its own, since a
 * SecurityManager cannot be removed once installed: one that refuses the SDK's thread group (a
 * child of the root group needs {@code modifyThreadGroup}) fails no class initialization, and the
 * SDK's threads are made in the caller's group instead, still daemons without a context class
 * loader; one that also refuses clearing the context class loader leaves the caller's; one that
 * allows everything gets the one {@code keytend-kmip} group. From Java 24 a SecurityManager
 * cannot be enabled (JEP 486): those cases are skipped there, and the group's own cases run.
 */
class SdkThreadsSecurityManagerTest {
  static final List<String> PACKAGES = List.of("kms", "transport", "server");

  private static Path location(Class<?> type) {
    try {
      return Path.of(type.getProtectionDomain().getCodeSource().getLocation().toURI());
    } catch (java.net.URISyntaxException e) {
      throw new AssertionError(e);
    }
  }

  /** Runs {@link Child} with {@code mode} in a new JVM on this one's JDK; its output. */
  static String child(String mode, boolean securityManager)
      throws IOException, InterruptedException {
    String java = Path.of(System.getProperty("java.home"), "bin", "java").toString();
    // The SDK, the tests, and the libraries the SDK runs with (slf4j-api, Caffeine), as this JVM
    // loaded them; and the tests' SLF4J provider.
    String classpath =
        Path.of("target/classes").toAbsolutePath()
            + File.pathSeparator
            + Path.of("target/test-classes").toAbsolutePath()
            + File.pathSeparator
            + location(org.slf4j.LoggerFactory.class)
            + File.pathSeparator
            + location(com.github.benmanes.caffeine.cache.Caffeine.class);
    List<String> command = new ArrayList<>(List.of(java));
    command.add("-Dslf4j.provider=dev.keytend.kmip.kms.TestLogs");
    if (securityManager) command.add("-Djava.security.manager=allow");
    command.addAll(List.of("-cp", classpath, Child.class.getName(), mode));
    Process p = new ProcessBuilder(command).redirectErrorStream(true).start();
    p.getOutputStream().close();
    boolean ended = p.waitFor(60, TimeUnit.SECONDS);
    if (!ended) p.destroyForcibly();
    String out = new String(p.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
    assertTrue(ended, "the child JVM hung: " + out);
    assertEquals(0, p.exitValue(), out);
    return out;
  }

  static void assumeSecurityManager() {
    assumeTrue(
        Runtime.version().feature() < 24,
        "a SecurityManager cannot be enabled from Java 24 (JEP 486)");
  }

  @Test
  void refusingTheGroupFailsNothingAndLeavesTheThreadsDaemonsWithoutALoader() throws Exception {
    assumeSecurityManager();
    String out = child("deny-group", true);
    for (String pkg : PACKAGES)
      assertTrue(out.contains(pkg + ": group=caller's daemon=true loader=none"), out);
    assertTrue(out.contains("refresh worker: group=caller's daemon=true loader=none"), out);
    assertTrue(out.contains("OK"), out);
  }

  @Test
  void refusingTheLoaderTooLeavesTheCallersLoader() throws Exception {
    assumeSecurityManager();
    String out = child("deny-loader", true);
    for (String pkg : PACKAGES)
      assertTrue(out.contains(pkg + ": group=caller's daemon=true loader=caller's"), out);
    assertTrue(out.contains("refresh worker: group=caller's daemon=true loader=caller's"), out);
  }

  @Test
  void aSecurityManagerThatAllowsItGetsTheSdksGroup() throws Exception {
    assumeSecurityManager();
    String out = child("allow", true);
    for (String pkg : PACKAGES)
      assertTrue(
          out.contains(pkg + ": group=keytend-kmip under root daemon=true loader=none"), out);
    assertTrue(
        out.contains("refresh worker: group=keytend-kmip under root daemon=true loader=none"), out);
    assertTrue(out.contains("one group: true"), out);
  }

  @Test
  void aDestroyedGroupIsMadeAgain() throws Exception {
    // ThreadGroup.destroy() does nothing from Java 19.
    assumeTrue(Runtime.version().feature() < 19, "a thread group cannot be destroyed from Java 19");
    String out = child("destroyed", false);
    for (String pkg : PACKAGES)
      assertTrue(
          out.contains(pkg + ": group=keytend-kmip under root daemon=true loader=none"), out);
    assertTrue(out.contains("one group: true"), out);
  }

  @Test
  void oneGroupServesTheWholeSdk() throws Exception {
    // In this JVM: no SecurityManager, so the SDK's own group, the same for each package.
    List<ThreadGroup> groups = new ArrayList<>();
    for (String pkg : PACKAGES) groups.add(Child.probe(pkg).getThreadGroup());
    assertEquals("keytend-kmip", groups.get(0).getName());
    assertNull(groups.get(0).getParent().getParent(), "under the root group");
    for (ThreadGroup g : groups) assertSame(groups.get(0), g);
  }

  /** The child JVM: installs the SecurityManager {@code args[0]} asks for, then uses the SDK. */
  public static final class Child {
    /**
     * A policy that grants this build's code (the SDK's classes and the tests') every permission
     * but the runtime permissions named, and the JDK's everything: the default SecurityManager then
     * checks the SDK as a real policy would (the JDK's privileged actions pass).
     */
    @SuppressWarnings("removal")
    static final class Refusing extends java.security.Policy {
      final Set<String> refused;

      Refusing(Set<String> refused) {
        this.refused = refused;
      }

      @Override
      public boolean implies(java.security.ProtectionDomain domain, Permission p) {
        java.security.CodeSource source = domain.getCodeSource();
        boolean ours =
            source != null
                && source.getLocation() != null
                && source.getLocation().toString().contains("/target/");
        return !(ours && p instanceof RuntimePermission && refused.contains(p.getName()));
      }
    }

    static ThreadGroup callers;
    static ClassLoader loader;

    /** A thread from {@code pkg}'s {@code SdkThreads.daemon}, not started. */
    static Thread probe(String pkg) throws ReflectiveOperationException {
      Method daemon =
          Class.forName("dev.keytend.kmip." + pkg + ".SdkThreads")
              .getDeclaredMethod("daemon", Runnable.class, String.class);
      daemon.setAccessible(true);
      return (Thread) daemon.invoke(null, (Runnable) () -> {}, "probe-" + pkg);
    }

    static String describe(Thread t) {
      ThreadGroup g = t.getThreadGroup();
      // (Reading the root group needs modifyThreadGroup: only where it is not the caller's.)
      String group =
          g == callers
              ? "caller's"
              : g.getName()
                  + (g.getParent() != null && g.getParent().getParent() == null
                      ? " under root"
                      : "");
      ClassLoader l = t.getContextClassLoader();
      return "group="
          + group
          + " daemon="
          + t.isDaemon()
          + " loader="
          + (l == null ? "none" : l == loader ? "caller's" : l);
    }

    @SuppressWarnings("removal")
    public static void main(String[] args) throws Exception {
      callers = Thread.currentThread().getThreadGroup();
      loader = Thread.currentThread().getContextClassLoader();
      String mode = args[0];
      Set<String> refused =
          switch (mode) {
            case "deny-group" -> Set.of("modifyThreadGroup");
            // Not modifyThread: closing any executor needs it (ThreadPoolExecutor.shutdown checks
            // it).
            case "deny-loader" -> Set.of("modifyThreadGroup", "setContextClassLoader");
            default -> Set.of();
          };
      // Before any SDK class is initialized.
      if (!mode.equals("destroyed")) {
        java.security.Policy.setPolicy(new Refusing(refused));
        System.setSecurityManager(new SecurityManager());
      }
      List<ThreadGroup> groups = new ArrayList<>();
      for (String pkg : PACKAGES) {
        Thread t = probe(pkg);
        if (mode.equals("destroyed") && pkg.equals("kms")) {
          t.getThreadGroup().destroy(); // no thread has started in it
          t = probe(pkg); // a new group
        }
        groups.add(t.getThreadGroup());
        System.out.println(pkg + ": " + describe(t));
      }
      if (mode.equals("destroyed")) groups.add(probe("kms").getThreadGroup());
      System.out.println("one group: " + (groups.stream().distinct().count() == 1));
      if (!mode.equals("destroyed")) System.out.println("refresh worker: " + refreshWorker());
      System.out.println("OK");
    }

    /** A {@link LocalKeys} cache's refresh worker, seen by the transport its refresh uses. */
    static String refreshWorker() throws Exception {
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      AtomicReference<String> worker = new AtomicReference<>();
      KmipTransport seeing =
          new KmipTransport() {
            @Override
            public Ttlv exchange(Ttlv request) throws IOException {
              return exchange(request, CallContext.NONE);
            }

            @Override
            public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
              // Seen while it runs: an ended thread has no group.
              if (Thread.currentThread().getName().equals("keytend-local-keys-refresh"))
                worker.compareAndSet(null, describe(Thread.currentThread()));
              return server.exchange(request, context);
            }
          };
      CustomAttribute family = CustomAttribute.client("family");
      try (Kms kms = Kms.connect(server.configure().transport(e -> seeing).build())) {
        KeyCreation c =
            kms.keys()
                .createAes(256)
                .custom(family, "orders")
                .extractable(true)
                .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                .named("orders-write");
        c.create();
        try (LocalKeys keys =
            kms.keys()
                .localKeys("orders-write")
                .scope(KeyQuery.all().custom(family, "orders"))
                .expect(Expect.aes(256))
                .ttl(Duration.ofSeconds(30))
                .refreshAfter(Duration.ofMillis(1))
                .open()) {
          keys.forEncrypt().close();
          for (int i = 0; i < 400 && worker.get() == null; i++) {
            Thread.sleep(5);
            keys.forEncrypt().close(); // queues a refresh on the cache's own worker
          }
        }
      }
      if (worker.get() == null) throw new AssertionError("no refresh ran on the cache's worker");
      return worker.get();
    }
  }
}
