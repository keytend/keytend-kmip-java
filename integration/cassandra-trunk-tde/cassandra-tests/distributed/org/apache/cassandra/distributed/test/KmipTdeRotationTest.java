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

package org.apache.cassandra.distributed.test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.keytend.kmip.cassandra.tde.KmipKeyProvider;
import dev.keytend.kmip.cassandra.tde.KmipTool;
import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.RevocationReason;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.db.commitlog.CommitLog;
import org.apache.cassandra.distributed.Cluster;
import org.apache.cassandra.distributed.api.ConsistencyLevel;
import org.apache.cassandra.distributed.api.Feature;
import org.apache.cassandra.distributed.api.IInvokableInstance;
import org.apache.cassandra.hints.HintsService;
import org.apache.cassandra.metrics.CassandraMetricsRegistry;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Commit log and hints encrypted under a key held in a real KMIP server (keytend-kmip-server, a
 * replica and its standby, a KMIP Lease Time on every key; {@link LiveKms}), on a two-node cluster:
 * write, rotate, lose the KMS replica to its standby, reload the KMS client credentials, restart and
 * replay through both keys, deliver hints written under the old key, retire it. Then the negative
 * control: a key deactivated under an open hints file and undelivered hints; the open file is closed
 * and the hints go on under the current key. The undelivered ones are then delivered, on a server
 * that leases Deactivated keys (keytend-kmip-server's default), or kept and not taken for corrupt,
 * on one that leases only Active keys ({@code KEYTEND_SERVER_LEASE_STATES=active}). Each KMIP
 * version named by {@code KEYTEND_SERVER_VERSIONS} runs in turn.
 */
public class KmipTdeRotationTest extends TestBaseImpl {
  private static final Logger logger = LoggerFactory.getLogger(KmipTdeRotationTest.class);
  private static final int TTL_SECONDS = 10;
  /** The nodes' own loopback addresses (127.0.7.x), so that other in-JVM dtests on the machine (127.0.0.x) do not collide. */
  private static final int SUBNET = 7;

  @Test
  public void rotateRestartReplay() throws Throwable {
    LiveKms live = LiveKms.fromEnvironment();
    for (String version : LiveKms.versions()) run(live, version);
  }

  private void run(LiveKms live, String version) throws Throwable {
    logger.info("=== KMIP {} ===", version);
    String name = "cassandra-tde-" + version + '-' + System.currentTimeMillis();
    Path credentials = Files.createTempDirectory("kmip-node1-credentials");
    Map<String, String> node1Kms = live.reloadableParameters(version, "node1", credentials);
    Map<String, String> node2Kms = live.parameters(version, "node2");
    try (Kms admin = live.admin(version)) {
      // created once, from the deployment, before any node starts
      KmipTool.run(admin, "key-create", List.of(name));
      KeyHandle first = admin.keys().findByName(name).orElseThrow();
      String firstAlias = name + '#' + first.id();

      try (Cluster cluster = init(Cluster.build(2)
          .withSubnet(SUBNET)
          .withConfig(c -> c.with(Feature.NETWORK, Feature.GOSSIP)
              .set("commitlog_segment_size", "1MiB")
              .set("hinted_handoff_enabled", true)
              .set("max_hint_window", "1h")
              .set("hinted_handoff_throttle", "64MiB")
              .set("transparent_data_encryption_options", tde(name, c.num() == 1 ? node1Kms : node2Kms)))
          .start())) {
        IInvokableInstance node1 = cluster.get(1);
        IInvokableInstance node2 = cluster.get(2);
        cluster.schemaChange(withKeyspace("CREATE TABLE %s.t (k int PRIMARY KEY, v blob) "
            + "WITH compaction = {'class': 'SizeTieredCompactionStrategy', 'enabled': 'false'}"));

        write(cluster, 0, 50, ConsistencyLevel.ALL);
        assertThat(aliases(node1)).contains(firstAlias);
        // how long new files can still get their key without the KMS: at most the TTL (shorter than the lease).
        // An idle write key is not refreshed, so after a cluster start longer than the TTL it reads 0 until a new
        // segment asks for it: write rows outside the keys checked below until one does.
        int filler = 10_000;
        long fillDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while (gauge(node1, "KeyUsableForSeconds", name) == 0) {
          assertThat(System.nanoTime()).as("a new segment asks for the write key").isLessThan(fillDeadline);
          write(cluster, filler, filler + 50, ConsistencyLevel.ALL);
          filler += 50;
        }
        assertThat(gauge(node1, "KeyUsableForSeconds", name)).isBetween(1L, (long) TTL_SECONDS);
        assertThat(gauge(node1, "WriteKeyFailing", name)).isZero();

        // node2 down: node1 keeps hints for it, encrypted under the first key
        node2.shutdown().get(1, TimeUnit.MINUTES);
        write(cluster, 50, 100, ConsistencyLevel.ONE);
        node1.runOnInstance(() -> HintsService.instance.flushAndFsyncBlockingly());
        assertThat(hintAliases(node1)).containsExactly(firstAlias);

        // rotate from one place, without a grace period: the old key stays Active, so open files under it may
        // still append
        KmipTool.run(admin, "key-rotate", List.of(name));
        KeyHandle second = admin.keys().findByName(name).orElseThrow();
        String secondAlias = name + '#' + second.id();
        assertThat(admin.keys().handle(first.id()).attributes().state()).isEqualTo(KeyState.ACTIVE);

        // the KMS replica fails and its standby takes the store over: the node goes on with it
        live.kill("a");
        live.start("b");
        // and its KMS client certificate is renewed on disk (same principal, same key), published atomically
        Files.copy(live.pki.resolve("node1-renewed.pem"), credentials.resolve("client.pem.tmp"),
            StandardCopyOption.REPLACE_EXISTING);
        Files.move(credentials.resolve("client.pem.tmp"), credentials.resolve("client.pem"),
            StandardCopyOption.ATOMIC_MOVE);

        // new segments move to the new key at a cache refresh, without a restart
        int k = 100;
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while (!aliases(node1).contains(secondAlias)) {
          assertThat(System.nanoTime()).as("new segments under " + secondAlias).isLessThan(deadline);
          write(cluster, k, k + 50, ConsistencyLevel.ONE);
          k += 50;
        }
        // the renewed credentials are read before the next request: keep writing, so that keys are used
        deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
        while (node1.logs().grep("Reloaded the TLS credentials").getResult().isEmpty()) {
          assertThat(System.nanoTime()).as("credential reload logged").isLessThan(deadline);
          write(cluster, k, k + 50, ConsistencyLevel.ONE);
          k += 50;
        }
        int last = k - 1;
        assertThat(aliases(node1)).contains(firstAlias, secondAlias);
        // the segment opened under the first key went on growing after the rotation: each section asked for
        // that key again (forAppend), granted while it is Active
        logger.info("Segments of node1 after the rotation: {}", aliases(node1));

        // restart node1 without flushing: everything replays from segments under both keys, each leased again
        node1.shutdown(false).get(1, TimeUnit.MINUTES);
        live.kill("b");
        live.start("a");
        node1.startup();
        assertThat(node1.logs().grep("Log replay complete, \\d+ replayed mutations").getResult()).isNotEmpty();
        for (int key : new int[] {0, 75, 120, last})
          assertThat(node1.executeInternal(withKeyspace("SELECT k FROM %s.t WHERE k = ?"), key).length).isEqualTo(1);

        // node2 back: hints written under the first key (still Active) are delivered
        node2.startup();
        await(() -> hintAliases(node1).isEmpty(), true, 180);
        for (int key : new int[] {50, 99, 120, last})
          assertThat(node2.executeInternal(withKeyspace("SELECT k FROM %s.t WHERE k = ?"), key).length).isEqualTo(1);

        // retirement: refused while a file still needs the first key ...
        Set<String> inUse = LiveKms.union(List.of(aliases(node1), hintAliases(node1), aliases(node2), hintAliases(node2)));
        logger.info("Keys referenced before the recycle: {}", inUse);
        if (inUse.contains(firstAlias)) {
          KmipTool.run(admin, "key-retire", List.of(name, writeScan(inUse).toString()));
          assertThat(admin.keys().handle(first.id()).attributes().state()).isEqualTo(KeyState.ACTIVE);
        }
        // ... and done once the segments under it are recycled
        cluster.forEach(i -> i.runOnInstance(() -> CommitLog.instance.forceRecycleAllSegments()));
        Set<String> after = LiveKms.union(List.of(aliases(node1), hintAliases(node1), aliases(node2), hintAliases(node2)));
        logger.info("Keys referenced after the recycle: {}", after);
        assertThat(after).doesNotContain(firstAlias);
        KmipTool.run(admin, "key-retire", List.of(name, writeScan(after).toString()));
        awaitState(admin, first.id(), KeyState.DESTROYED);
        write(cluster, 1000, 1010, ConsistencyLevel.ALL);

        // negative control: hints under a key deactivated before they are delivered
        node2.shutdown().get(1, TimeUnit.MINUTES);
        write(cluster, 2000, 2050, ConsistencyLevel.ONE);
        node1.runOnInstance(() -> HintsService.instance.flushAndFsyncBlockingly());
        assertThat(hintAliases(node1)).containsExactly(secondAlias);
        node1.runOnInstance(() -> HintsService.instance.pauseDispatch());
        KmipTool.run(admin, "key-rotate", List.of(name));
        String thirdAlias = name + '#' + admin.keys().findByName(name).orElseThrow().id();
        // node2 restarts (replaying its segments under the second key, still Active), moves to the third key and
        // recycles its segments: on a server that leases only Active keys, a node whose own commit log names a
        // deactivated key cannot start
        node2.startup();
        node2.runOnInstance(() -> CommitLog.instance.forceRecycleAllSegments());
        assertThat(aliases(node2)).doesNotContain(secondAlias).contains(thirdAlias);
        // node1 too: its segments are checked per section, so an open segment under the second key would stop
        // its commit log (commit_failure_policy) once the key is deactivated
        await(() -> {
          node1.runOnInstance(() -> CommitLog.instance.forceRecycleAllSegments());
          return !aliases(node1).contains(secondAlias);
        }, true);
        node2.shutdown().get(1, TimeUnit.MINUTES);
        admin.keys().handle(second.id())
            .revoke(RevocationReason.cessationOfOperation("deactivated before the hints were delivered"));
        // the node's authorization of the key ends at its next check, at the latest its TTL
        TimeUnit.SECONDS.sleep(TTL_SECONDS + 2);
        // node1's hints file for node2 is still open under the second key: the next flush closes it and goes on in
        // a new file under the third key, instead of appending under a key that may no longer encrypt
        write(cluster, 2050, 2100, ConsistencyLevel.ONE);
        node1.runOnInstance(() -> HintsService.instance.flushAndFsyncBlockingly());
        assertThat(node1.logs().grep("Closing hints file .*, which can no longer be appended to").getResult()).isNotEmpty();
        assertThat(hintAliases(node1)).containsExactlyInAnyOrder(secondAlias, thirdAlias);
        node2.startup();
        write(cluster, 2100, 2110, ConsistencyLevel.ALL); // the commit log goes on under the third key
        node1.runOnInstance(() -> HintsService.instance.resumeDispatch());
        if (LiveKms.leasesDeactivated()) {
          // the server leases the Deactivated key, which may still decrypt: the hints under it are delivered
          await(() -> hintAliases(node1).isEmpty(), true, 180);
          for (int key : new int[] {2000, 2049, 2050, 2099})
            assertThat(node2.executeInternal(withKeyspace("SELECT k FROM %s.t WHERE k = ?"), key).length).isEqualTo(1);
          assertThat(node1.logs().grep("Cannot dispatch hints file .* now").getResult()).isEmpty();
        } else {
          // the server refuses the Deactivated key a lease: the file under it cannot be read, and is kept
          await(() -> !node1.logs().grep("Cannot dispatch hints file .* now").getResult().isEmpty(), true);
          // the SDK's message carries the server's own reason
          assertThat(node1.logs().grep("refused to lease it .*A Deactivated object cannot receive a lease").getResult())
              .isNotEmpty();
          assertThat(hintAliases(node1)).contains(secondAlias);
        }
        assertThat(node1.logs().grep("file is corrupted").getResult()).isEmpty();
        node1.runOnInstance(() -> HintsService.instance.deleteAllHints());
        assertThatThrownBy(() -> KmipTool.run(admin, "key-status", List.of("no-such-key-" + version)))
            .isInstanceOf(IllegalArgumentException.class);
        // the nodes shut down with their key providers open, as in production (Cassandra has no plugin
        // lifecycle): the commit log's last sections, written during shutdown, still get their key, and the
        // SDK's threads (outside the node's thread group, ending when idle) pass the shutdown thread check
      }
    }
  }

  private static long gauge(IInvokableInstance node, String metric, String name) {
    return node.callOnInstance(() -> CassandraMetricsRegistry.Metrics
        .getGauges((n, m) -> n.contains(metric) && n.contains(name))
        .values().stream().mapToLong(g -> (Long) g.getValue()).min().orElseThrow());
  }

  private static Map<String, Object> tde(String name, Map<String, String> parameters) {
    Map<String, String> p = new HashMap<>(parameters);
    p.put(KmipKeyProvider.CACHE_TTL, TTL_SECONDS + "s");
    p.put(KmipKeyProvider.CACHE_REFRESH, "1s");
    return Map.of("enabled", true,
        "cipher", "AES/CBC/PKCS5Padding",
        "key_alias", name,
        "key_provider", List.of(Map.of("class_name", KmipKeyProvider.class.getName(), "parameters", List.of(p))));
  }

  private static void write(Cluster cluster, int from, int to, ConsistencyLevel cl) {
    byte[] value = new byte[10 * 1024];
    new Random(from).nextBytes(value);
    for (int k = from; k < to; k++)
      cluster.coordinator(1).execute(withKeyspace("INSERT INTO %s.t (k, v) VALUES (?, ?)"), cl, k, ByteBuffer.wrap(value));
  }

  private static Set<String> aliases(IInvokableInstance node) {
    return node.callOnInstance(() -> scan(DatabaseDescriptor.getCommitLogLocation()));
  }

  private static Set<String> hintAliases(IInvokableInstance node) {
    return node.callOnInstance(() -> scan(DatabaseDescriptor.getHintsDirectory().toString()));
  }

  private static Set<String> scan(String directory) {
    try {
      return new TreeSet<>(KmipTool.scan(List.of(directory)));
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private static Path writeScan(Set<String> aliases) throws IOException {
    Path file = Files.createTempFile("key-scan", ".txt");
    Files.write(file, aliases);
    return file;
  }

  private static void awaitState(Kms admin, String id, KeyState state) throws InterruptedException {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(60);
    while (admin.keys().handle(id).allowingCompromised().attributes().state() != state) {
      if (System.nanoTime() > deadline) throw new AssertionError(id + " is not " + state);
      Thread.sleep(500);
    }
  }

  private static <T> void await(Callable<T> probe, T expected) throws Exception {
    await(probe, expected, 60);
  }

  private static <T> void await(Callable<T> probe, T expected, int seconds) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds);
    T last;
    while (!(last = probe.call()).equals(expected)) {
      if (System.nanoTime() > deadline) throw new AssertionError("expected " + expected + " but was " + last);
      Thread.sleep(250);
    }
  }
}
