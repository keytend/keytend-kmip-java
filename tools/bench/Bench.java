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

import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.kms.ChunkedOpener;
import dev.keytend.kmip.kms.ChunkedSealer;
import dev.keytend.kmip.kms.CurrentKey;
import dev.keytend.kmip.kms.CustomAttribute;
import dev.keytend.kmip.kms.DestroyableSecretKey;
import dev.keytend.kmip.kms.Expect;
import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyQuery;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.kms.KmsEvent;
import dev.keytend.kmip.kms.KmsException;
import dev.keytend.kmip.kms.KmsListener;
import dev.keytend.kmip.kms.LocalKeys;
import dev.keytend.kmip.kms.LocalUse;
import dev.keytend.kmip.kms.SealingStream;
import dev.keytend.kmip.kms.TlsIdentityFollower;
import dev.keytend.kmip.kms.TlsTrustFollower;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.locks.LockSupport;
import java.util.function.Supplier;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Opt-in measurement of the application paths of the kms layer: pinned lookups, raw-key reads
 * (cache miss and repeated), seal and open (records and streams), reads through rotations,
 * CurrentKey.handle() while checks run, concurrent callers against the connection pool, endpoint
 * failover, a client-certificate reload, LocalKeys (hits, misses, renewals), TLS handshakes
 * through the TLS identity and trust followers, chunked envelopes and moveName. Not part of the
 * build or the tests, and uses only the SDK jar (plus the JDK). Run it with
 * {@code tools/bench/run.sh} (see the README next to this file), or by hand:
 *
 * <pre>
 * java -Xms1g -Xmx1g -cp keytend-kmip.jar tools/bench/Bench.java --topology inmemory
 * java -cp keytend-kmip.jar tools/bench/Bench.java --topology inmemory [--pki /path/to/pki]
 * java -cp keytend-kmip.jar tools/bench/Bench.java --topology inmemory-tls --pki /path/to/pki
 * java -cp keytend-kmip.jar tools/bench/Bench.java --topology live --pki /path/to/pki \
 *     --endpoints 127.0.0.1:5696,127.0.0.1:5697 \
 *     [--kill-command 'COMMAND STOPPING THE FIRST' | --kill-pid PID_OF_THE_FIRST] [--version 2.1]
 * </pre>
 *
 * The failover scenario stops the first endpoint's server: with {@code --kill-command}, a shell
 * command ({@code sh -c}) that returns once that server is gone ({@code run.sh} passes
 * {@code tools/kmip-server/run-server.sh stop <container>}); with {@code --kill-pid}, the server's
 * process (SIGTERM, then the bench waits for it to exit).
 *
 * Topologies: {@code inmemory} calls an {@link InMemoryKmipServer} through its in-process
 * transport (no sockets, no TLS, no pool: the SDK's own cost); {@code inmemory-tls} puts the same
 * server behind a loopback TLS listener in this JVM, so the SDK's TLS transport and connection pool
 * are used; {@code live} calls real servers. Each scenario of an in-memory topology gets a fresh
 * server (the in-memory server keeps every request it receives).
 *
 * <p>Latencies come from {@code System.nanoTime()} around each call, recorded in a log-linear
 * histogram (1024 sub-buckets per power of two: values are exact below 2048 ns and within 0.1%
 * above). Percentiles are nearest-rank. Request counts are the SDK's own {@link
 * KmsListener#started} attempts; allocation is the calling thread's allocated bytes
 * ({@code com.sun.management.ThreadMXBean}), so it does not count other threads.
 */
public final class Bench {
  private static final byte[] AAD = "bench-record-0001".getBytes(StandardCharsets.UTF_8);
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final Counter COUNTER = new Counter();
  private static final List<String> ROWS = new ArrayList<>();
  private static final String RUN = UUID.randomUUID().toString().substring(0, 8);

  private static String topology;
  private static KmipVersion version;
  private static Path pki;
  private static Path work;
  private static List<String> endpoints = List.of();
  private static long killPid = -1;
  private static String killCommand;
  private static double scale = 1;
  private static int keys;
  /** The thread counts of the localkeys scenario's concurrent hits ({@code --localkeys-threads}). */
  private static int[] localKeysThreads = {1, 4, 16, 64};
  /** Sink for results the JIT must not drop. */
  static volatile long sink;

  interface Op {
    void run(int i) throws Exception;
  }

  public static void main(String[] args) throws Exception {
    Map<String, String> a = parse(args);
    topology = a.getOrDefault("topology", "inmemory");
    if (!Set.of("inmemory", "inmemory-tls", "live").contains(topology))
      throw new IllegalArgumentException("--topology inmemory|inmemory-tls|live");
    String v = a.getOrDefault("version", "2.1");
    version = KmipVersion.valueOf("V" + v.replace('.', '_'));
    // In process, the PKI is only needed by tls-handshake (skipped without it).
    if (!topology.equals("inmemory") || a.containsKey("pki")) pki = Path.of(need(a, "pki"));
    if (topology.equals("live")) endpoints = Arrays.asList(need(a, "endpoints").split(","));
    killPid = Long.parseLong(a.getOrDefault("kill-pid", "-1"));
    killCommand = a.get("kill-command");
    scale = Double.parseDouble(a.getOrDefault("scale", "1"));
    keys = Integer.parseInt(a.getOrDefault("keys", "1000"));
    if (a.containsKey("localkeys-threads"))
      localKeysThreads = Arrays.stream(a.get("localkeys-threads").split(",")).mapToInt(n -> Integer.parseInt(n.trim())).toArray();
    work = Files.createDirectories(Path.of(a.getOrDefault("work", System.getProperty("java.io.tmpdir")))
        .resolve("bench-" + RUN));

    Map<String, Op> scenarios = new LinkedHashMap<>();
    scenarios.put("pinned", i -> pinned());
    scenarios.put("miss", i -> miss());
    scenarios.put("pooled", i -> pooled());
    scenarios.put("seal-open", i -> sealOpen());
    scenarios.put("streams", i -> streams());
    scenarios.put("rotations", i -> rotations());
    scenarios.put("current-check", i -> currentCheck());
    scenarios.put("concurrency", i -> concurrency());
    scenarios.put("reload", i -> reload());
    scenarios.put("localkeys", i -> localKeys());
    scenarios.put("tls-handshake", i -> tlsHandshake());
    scenarios.put("chunked", i -> chunked());
    scenarios.put("movename", i -> moveName());
    scenarios.put("failover", i -> failover());
    List<String> chosen =
        a.getOrDefault("scenarios", "all").equals("all")
            ? new ArrayList<>(scenarios.keySet())
            : Arrays.asList(a.get("scenarios").split(","));

    environment();
    header();
    for (String name : chosen) {
      Op s = scenarios.get(name.trim());
      if (s == null) throw new IllegalArgumentException("unknown scenario " + name);
      System.out.println();
      System.out.println("## " + name + "   (load " + load() + ")");
      Resources before = Resources.take();
      try {
        s.run(0);
      } catch (Throwable t) {
        System.out.println("SCENARIO FAILED: " + t);
        t.printStackTrace(System.out);
      }
      Resources after = Resources.take();
      System.out.println("resources " + name + ": heap after GC " + before.heapMiB + " -> " + after.heapMiB
          + " MiB, threads " + before.threads + " -> " + after.threads + ", fds " + before.fds + " -> "
          + after.fds + " (before the scenario -> after it, its Kms closed); load " + load());
    }
    System.out.println();
    System.out.println("## all rows (" + topology + ", KMIP " + v + ")");
    header();
    ROWS.forEach(System.out::println);
    System.exit(0);
  }

  // ---------------------------------------------------------------------------------------------
  // Scenarios

  /** Hot path: an application map of raw keys, CurrentKey.handle() with no check due, local GCM. */
  static void pinned() throws Exception {
    try (Target t = target(); Kms kms = t.connect(4, "pinned")) {
      int n = 256;
      Map<String, DestroyableSecretKey> map = new ConcurrentHashMap<>();
      String[] ids = new String[n];
      for (int i = 0; i < n; i++) {
        KeyHandle k = aes(kms, null);
        ids[i] = k.id();
        map.put(k.id(), k.asSecretKey(Expect.aes(256), LocalUse.DECRYPT));
      }
      KeyHandle first = kms.keys().handle(ids[0]);
      CurrentKey current = kms.keys().current(first).checkingEvery(Duration.ofHours(1));
      int iters = scaled(2_000_000);
      measure("pinned", "timer only (nanoTime pair)", iters / 2, iters, 10, i -> {});
      measure("pinned", "map.get(id) of 256 raw keys", iters / 2, iters, 10,
          i -> sink += map.get(ids[i & (n - 1)]).hashCode());
      batched("pinned", "map.get(id), mean of batches of 1000", iters / 1000,
          i -> sink += map.get(ids[i & (n - 1)]).hashCode());
      measure("pinned", "CurrentKey.handle(), no check due", iters / 2, iters, 10,
          i -> sink += current.handle().hashCode());
      batched("pinned", "CurrentKey.handle(), mean of batches of 1000", iters / 1000,
          i -> sink += current.handle().hashCode());
      // What the write path does with the pinned key: local AES-GCM of a 4 KiB record.
      byte[] record = random(4096);
      byte[] iv = new byte[12];
      Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
      measure("pinned", "map.get + local AES-GCM encrypt 4 KiB (JCA)", scaled(50_000), scaled(200_000), 10,
          i -> {
            RANDOM.nextBytes(iv);
            gcm.init(Cipher.ENCRYPT_MODE, map.get(ids[i & (n - 1)]), new GCMParameterSpec(128, iv));
            sink += gcm.doFinal(record).length;
          });
      // The background refresh a write path relies on instead of calling the KMS.
      measure("pinned", "CurrentKey.refresh() (background check, 0 rotations)", scaled(200), scaled(2000), 10,
          i -> sink += current.refresh().hashCode());
      for (DestroyableSecretKey k : map.values()) k.destroy();
    }
  }

  /** asSecretKey of identifiers not read before, on a warm pool; and the first call of a new Kms. */
  static void miss() throws Exception {
    try (Target t = target()) {
      List<String> ids = new ArrayList<>();
      try (Kms kms = t.connect(4, "miss")) {
        long start = System.nanoTime();
        for (int i = 0; i < keys + 50; i++) ids.add(aes(kms, null).id());
        System.out.printf("created %d keys in %.1f s%n", ids.size(), (System.nanoTime() - start) / 1e9);
        for (int i = 0; i < 20; i++) kms.keys().handle(ids.get(keys + (i % 50))).asSecretKey(Expect.aes(256), LocalUse.DECRYPT).destroy();
        measure("miss", "asSecretKey, id not read before (new handle)", 0, keys, 60,
            i -> {
              try (DestroyableSecretKey k = kms.keys().handle(ids.get(i)).asSecretKey(Expect.aes(256), LocalUse.DECRYPT)) {
                sink += k.hashCode();
              }
            });
      }
      int rounds = scaled(20);
      Histogram build = new Histogram(), connect = new Histogram(), first = new Histogram();
      long reqConnect = 0, reqFirst = 0;
      for (int r = 0; r < rounds; r++) {
        long t0 = System.nanoTime();
        KmsConfig config = t.builder().poolSize(4).addListener(COUNTER).build();
        long t1 = System.nanoTime();
        long req0 = COUNTER.started.sum();
        try (Kms kms = Kms.connect(config)) {
          long t2 = System.nanoTime();
          long req1 = COUNTER.started.sum();
          try (DestroyableSecretKey k = kms.keys().handle(ids.get(r)).asSecretKey(Expect.aes(256), LocalUse.DECRYPT)) {
            sink += k.hashCode();
          }
          long t3 = System.nanoTime();
          build.record(t1 - t0);
          connect.record(t2 - t1);
          first.record(t3 - t2);
          reqConnect += req1 - req0;
          reqFirst += COUNTER.started.sum() - req1;
        }
      }
      row("miss", "KmsConfig.build() (reads the PEM files, builds the TLS context)", build, rounds, 0, -1, -1);
      row("miss", "Kms.connect (new Kms: connection, TLS handshake, Discover Versions)", connect, rounds, 0,
          reqConnect / (double) rounds, -1);
      row("miss", "first asSecretKey on that new Kms", first, rounds, 0, reqFirst / (double) rounds, -1);
    }
  }

  /** Repeated asSecretKey of one key on a warm pool. */
  static void pooled() throws Exception {
    try (Target t = target(); Kms kms = t.connect(4, "pooled")) {
      KeyHandle k = aes(kms, null);
      measure("pooled", "asSecretKey, same handle, repeated", scaled(2000), scaled(20_000), 20,
          i -> {
            try (DestroyableSecretKey s = k.asSecretKey(Expect.aes(256), LocalUse.DECRYPT)) {
              sink += s.hashCode();
            }
          });
      measure("pooled", "asSecretKey, new handle of a key read before", scaled(500), scaled(10_000), 20,
          i -> {
            try (DestroyableSecretKey s = kms.keys().handle(k.id()).asSecretKey(Expect.aes(256), LocalUse.DECRYPT)) {
              sink += s.hashCode();
            }
          });
      measure("pooled", "attributes() (one Get Attributes)", scaled(500), scaled(10_000), 20,
          i -> sink += k.attributes().hashCode());
    }
  }

  /** seal and open of small records. */
  static void sealOpen() throws Exception {
    try (Target t = target(); Kms kms = t.connect(4, "seal-open")) {
      KeyHandle k = aes(kms, null);
      CurrentKey current = kms.keys().current(k);
      for (int size : new int[] {100, 4096}) {
        byte[] plain = random(size);
        String label = size == 100 ? "100 B" : "4 KiB";
        measure("seal-open", "seal " + label, scaled(1000), scaled(10_000), 20,
            i -> sink += current.seal(plain, AAD).length);
        byte[][] sealed = new byte[64][];
        for (int i = 0; i < sealed.length; i++) sealed[i] = current.seal(plain, AAD);
        System.out.println("sealed size of a " + label + " record: " + sealed[0].length + " B");
        measure("seal-open", "open " + label + " (same handle)", scaled(1000), scaled(10_000), 20,
            i -> sink += k.open(sealed[i & 63], AAD).length);
      }
    }
  }

  /** sealing/opening streams of 1 MiB and 64 MiB, and JCA AES-GCM over the same chunks. */
  static void streams() throws Exception {
    try (Target t = target(); Kms kms = t.connect(4, "streams")) {
      KeyHandle k = aes(kms, null);
      byte[] chunk = random(64 * 1024);
      for (int mib : new int[] {1, 64}) {
        long size = mib * 1024L * 1024;
        int n = mib == 1 ? scaled(40) : Math.max(3, scaled(5));
        int warm = mib == 1 ? 10 : 1;
        String label = mib + " MiB";
        Row seal = measure("streams", "sealing " + label + " (to a null sink)", warm, n, 120,
            i -> {
              try (SealingStream out = k.sealing(OutputStream.nullOutputStream(), AAD)) {
                for (long w = 0; w < size; w += chunk.length) out.write(chunk);
                out.finish();
              }
            });
        mibPerSecond(seal, size);
        ByteArrayOutputStream buffer = new ByteArrayOutputStream((int) size + (1 << 20));
        try (SealingStream out = k.sealing(buffer, AAD)) {
          for (long w = 0; w < size; w += chunk.length) out.write(chunk);
          out.finish();
        }
        byte[] sealed = buffer.toByteArray();
        buffer = null;
        System.out.printf("sealed size of %s: %d B (+%d B)%n", label, sealed.length, sealed.length - size);
        byte[] into = new byte[64 * 1024];
        Row open = measure("streams", "opening " + label + " (from memory)", warm, n, 120,
            i -> {
              try (InputStream in = k.opening(new ByteArrayInputStream(sealed), AAD)) {
                long total = 0;
                for (int r; (r = in.read(into)) != -1; ) total += r;
                if (total != size) throw new IllegalStateException("read " + total);
              }
            });
        mibPerSecond(open, size);
      }
      // Reference: JCA AES-256-GCM over 64 KiB chunks with a fresh IV each, no KMS, no framing.
      try (DestroyableSecretKey raw = k.asSecretKey(Expect.aes(256), LocalUse.DECRYPT)) {
        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        long size = 64L * 1024 * 1024;
        Row ref = measure("streams", "reference: JCA AES-GCM 64 MiB in 64 KiB chunks", 1, Math.max(3, scaled(5)), 120,
            i -> {
              for (long w = 0; w < size; w += chunk.length) {
                RANDOM.nextBytes(iv);
                gcm.init(Cipher.ENCRYPT_MODE, raw, new GCMParameterSpec(128, iv));
                sink += gcm.doFinal(chunk).length;
              }
            });
        mibPerSecond(ref, size);
      }
    }
  }

  /** Opening, through the current handle, a record sealed 0, 1, 32 and 64 rotations earlier. */
  static void rotations() throws Exception {
    try (Target t = target(); Kms kms = t.connect(4, "rotations")) {
      String name = "bench-" + RUN + "-rotations";
      byte[] plain = random(100);
      KeyHandle[] lineage = new KeyHandle[65];
      byte[][] sealed = new byte[65][];
      lineage[0] = aes(kms, name);
      sealed[0] = kms.keys().current(lineage[0]).seal(plain, AAD);
      Histogram rotate = new Histogram();
      long req0 = COUNTER.started.sum();
      for (int i = 1; i <= 64; i++) {
        long t0 = System.nanoTime();
        lineage[i] = lineage[i - 1].rotate();
        rotate.record(System.nanoTime() - t0);
        sealed[i] = kms.keys().current(lineage[i]).seal(plain, AAD);
      }
      row("rotations", "rotate() (64 in a row, each then sealed once)", rotate, 64, 0,
          (COUNTER.started.sum() - req0) / 64.0 - 1, -1);
      KeyHandle head = lineage[64];
      CurrentKey current = kms.keys().current(name);
      System.out.println("current key " + current.handle().id() + ", newest rotated " + head.id());
      for (int n : new int[] {0, 1, 32, 64}) {
        byte[] record = sealed[64 - n];
        String label = "record sealed " + n + " rotation" + (n == 1 ? "" : "s") + " earlier";
        measure("rotations", "open " + label + ", new handle of the newest key", 0, scaled(n >= 32 ? 50 : 200), 30,
            i -> sink += kms.keys().handle(head.id()).open(record, AAD).length);
        measure("rotations", "open " + label + ", same handle, repeated", scaled(20), scaled(n >= 32 ? 200 : 1000), 30,
            i -> sink += head.open(record, AAD).length);
        measure("rotations", "open " + label + ", CurrentKey.open", scaled(20), scaled(n >= 32 ? 200 : 1000), 30,
            i -> sink += current.open(record, AAD).length);
      }
      measure("rotations", "CurrentKey.refresh() after 64 rotations", scaled(20), scaled(200), 30,
          i -> sink += current.refresh().hashCode());
    }
  }

  /**
   * CurrentKey.handle() on 16 threads while checks run: inline (a check due every second, which
   * the calls wait for) and in the background (no check due on the calling threads; another thread
   * calls refresh() every second), on a lineage of 1 key and of 65 keys.
   */
  static void currentCheck() throws Exception {
    try (Target t = target(); Kms kms = t.connect(4, "current-check")) {
      String name = "bench-" + RUN + "-current";
      KeyHandle key = aes(kms, name);
      for (int rotations : new int[] {0, 64}) {
        for (int i = 0; i < rotations; i++) key = key.rotate();
        String lineage = ", lineage of " + (rotations + 1) + " key" + (rotations == 0 ? "" : "s") + ", 16 threads";
        CurrentKey inline = kms.keys().current(key).checkingEvery(Duration.ofSeconds(1));
        Histogram h = concurrent("current-check", "CurrentKey.handle(), check due every 1 s, inline" + lineage,
            16, 1.0, 6.0, t, i -> sink += inline.handle().hashCode());
        System.out.println("  calls over 1 ms: " + h.above(1_000_000) + ", over 10 ms: " + h.above(10_000_000));
        CurrentKey background = kms.keys().current(key).checkingEvery(Duration.ofHours(1));
        LongAdder refreshes = new LongAdder();
        Histogram refresh = new Histogram();
        Thread refresher = new Thread(() -> {
          try {
            for (;;) {
              long t0 = System.nanoTime();
              background.refresh();
              synchronized (refresh) {
                refresh.record(System.nanoTime() - t0);
              }
              refreshes.increment();
              Thread.sleep(1000);
            }
          } catch (InterruptedException | RuntimeException stop) {
            // done
          }
        });
        refresher.setDaemon(true);
        refresher.start();
        h = concurrent("current-check", "CurrentKey.handle(), no check due, refresh() every 1 s in the background"
                + lineage, 16, 1.0, 6.0, t, i -> sink += background.handle().hashCode());
        refresher.interrupt();
        refresher.join();
        System.out.println("  calls over 1 ms: " + h.above(1_000_000) + ", over 10 ms: " + h.above(10_000_000));
        synchronized (refresh) {
          row("current-check", "the background refresh() calls" + lineage.replace(", 16 threads", ""), refresh,
              refresh.count, 0, -1, -1);
        }
      }
    }
  }

  /** Concurrent asSecretKey callers against the default pool of 4 and a pool of 16. */
  static void concurrency() throws Exception {
    int[] pools = topology.equals("inmemory") ? new int[] {4} : new int[] {4, 16};
    for (int pool : pools) {
      try (Target t = target(); Kms kms = t.connect(pool, "concurrency, pool " + pool)) {
        KeyHandle k = aes(kms, null);
        k.asSecretKey(Expect.aes(256), LocalUse.DECRYPT).destroy();
        for (int threads : new int[] {1, 4, 16, 64}) {
          concurrent("concurrency", "asSecretKey, " + threads + " threads, pool "
                  + (topology.equals("inmemory") ? "n/a (in-process)" : pool),
              threads, 1.0, 4.0, t,
              i -> {
                try (DestroyableSecretKey s = k.asSecretKey(Expect.aes(256), LocalUse.DECRYPT)) {
                  sink += s.hashCode();
                }
              });
        }
      }
    }
  }

  /** Calls through a client-certificate reload (reloadOnChange): live and inmemory-tls only. */
  static void reload() throws Exception {
    if (topology.equals("inmemory")) {
      System.out.println("SKIP reload: the in-process transport has no TLS (run inmemory-tls or live)");
      return;
    }
    Path ids = Files.createDirectories(work.resolve("identities"));
    for (String[] id : new String[][] {{"a", "client"}, {"b", "client2"}}) {
      Path dir = Files.createDirectories(ids.resolve(id[0]));
      Files.copy(pki.resolve(id[1] + ".pem"), dir.resolve("client.pem"), StandardCopyOption.REPLACE_EXISTING);
      Files.copy(pki.resolve(id[1] + ".key"), dir.resolve("client.key"), StandardCopyOption.REPLACE_EXISTING);
    }
    swap(ids, "a");
    Thread.sleep(1100); // the files must be older than the check interval before the swaps
    try (Target t = target()) {
      KmsConfig.Builder b = t.builder();
      b.clientIdentityPem(ids.resolve("current/client.pem"), ids.resolve("current/client.key")).reloadOnChange();
      try (Kms kms = t.connect(b, 4, "reload, reloadOnChange() (1 s)")) {
        KeyHandle k = aes(kms, null);
        int threads = 4;
        double seconds = Math.max(6, 12 * scale);
        long[] swaps = new long[2];
        CopyOnWriteArrayList<long[]> calls = new CopyOnWriteArrayList<>();
        long reloads0 = COUNTER.reloaded.sum();
        COUNTER.reloadTimes.clear();
        long start = System.nanoTime();
        Thread swapper = new Thread(() -> {
          try {
            Thread.sleep((long) (seconds * 1000 / 3));
            swaps[0] = System.nanoTime();
            swap(ids, "b");
            Thread.sleep((long) (seconds * 1000 / 3));
            swaps[1] = System.nanoTime();
            swap(ids, "a");
          } catch (Exception e) {
            throw new IllegalStateException(e);
          }
        });
        LongAdder errors = new LongAdder();
        List<Thread> workers = new ArrayList<>();
        long end = start + (long) (seconds * 1e9);
        for (int w = 0; w < threads; w++) {
          Thread th = new Thread(() -> {
            long[] buf = new long[1 << 16];
            int used = 0;
            while (System.nanoTime() < end) {
              long t0 = System.nanoTime();
              try (DestroyableSecretKey s = k.asSecretKey(Expect.aes(256), LocalUse.DECRYPT)) {
                sink += s.hashCode();
              } catch (Exception e) {
                errors.increment();
              }
              long t1 = System.nanoTime();
              if (used + 2 > buf.length) buf = Arrays.copyOf(buf, buf.length * 2);
              buf[used++] = t0;
              buf[used++] = t1 - t0;
            }
            calls.add(Arrays.copyOf(buf, used));
          });
          workers.add(th);
        }
        swapper.start();
        workers.forEach(Thread::start);
        for (Thread th : workers) th.join();
        swapper.join();
        long window = 2_000_000_000L;
        Histogram steady = new Histogram(), around = new Histogram(), all = new Histogram();
        long maxAt = 0, max = -1;
        for (long[] c : calls)
          for (int i = 0; i < c.length; i += 2) {
            long at = c[i], lat = c[i + 1];
            boolean near = (at >= swaps[0] && at < swaps[0] + window) || (at >= swaps[1] && at < swaps[1] + window);
            (near ? around : steady).record(lat);
            all.record(lat);
            if (lat > max) {
              max = lat;
              maxAt = at;
            }
          }
        double wall = seconds;
        row("reload", "asSecretKey, " + threads + " threads, calls outside the reload windows", steady, steady.count, wall, -1, -1);
        row("reload", "asSecretKey, " + threads + " threads, calls within 2 s after each swap", around, around.count, wall, -1, -1);
        row("reload", "asSecretKey, " + threads + " threads, all calls", all, all.count, wall, -1, -1);
        StringBuilder when = new StringBuilder();
        for (long r : COUNTER.reloadTimes) when.append(String.format(" %.0f ms", (r - swaps[r >= swaps[1] ? 1 : 0]) / 1e6));
        System.out.printf("swaps at %.1f s and %.1f s; credentialsReloaded %d time(s), after the swap by:%s;"
                + " reload failures %d; call errors %d; slowest call %.1f ms at %.0f ms after the nearest earlier swap%n",
            (swaps[0] - start) / 1e9, (swaps[1] - start) / 1e9, COUNTER.reloaded.sum() - reloads0, when,
            COUNTER.reloadFailed.sum(), errors.sum(), max / 1e6,
            (maxAt - (maxAt >= swaps[1] ? swaps[1] : swaps[0])) / 1e6);
        t.describeConnections();
      }
    }
  }

  /** The client attribute the new scenarios scope their objects with. */
  private static final CustomAttribute BENCH_TAG = CustomAttribute.client("keytend-bench");

  /**
   * LocalKeys: hits of forEncrypt() and forDecrypt(id) on 1 thread and on each of {@code
   * --localkeys-threads} (default 1, 4, 16 and 64), forDecrypt(id) of 32 identifiers and of one, a miss (invalidate,
   * then load), and the access at which a renewal is due. A renewal is asynchronous: the row of the
   * access is what its caller waits for; the row of the renewal runs from that access to the
   * answer of the renewal's Get on the refresh thread, as the KmsListener sees it. In process with
   * no Lease Time and with one on every object; live, the server's own.
   */
  static void localKeys() throws Exception {
    List<Duration> leases = topology.equals("live") ? Arrays.asList((Duration) null) : Arrays.asList(null, Duration.ofHours(1));
    for (Duration lease : leases) {
      try (Target t = target(lease); Kms kms = t.connect(4, "localkeys, " + leaseLabel(lease))) {
        String tag = "bench-" + RUN + "-lk-" + (lease == null ? "default" : lease.getSeconds());
        String name = tag + "-write";
        KeyHandle write = scoped(kms, tag, name);
        String[] ids = new String[32];
        for (int i = 0; i < ids.length; i++) ids[i] = scoped(kms, tag, null).id();
        String v = ", " + stated(write);
        System.out.println("objects: Lease Time " + write.attributes().leaseTime().map(Duration::toString).orElse("none")
            + "; LocalKeys ttl 1 h, capacity 64, 1 write key and 32 historical keys");
        try (LocalKeys keys = localKeys(kms, name, tag, null)) {
          try (LocalKeys.Use u = keys.forEncrypt()) {
            if (!u.id().equals(write.id())) throw new IllegalStateException("selected " + u.id() + ", not " + write.id());
          }
          for (String id : ids) keys.forDecrypt(id).close();
          int iters = scaled(1_000_000);
          measure("localkeys", "forEncrypt() hit, 1 thread" + v, iters / 2, iters, 10,
              i -> {
                try (LocalKeys.Use u = keys.forEncrypt()) {
                  sink += u.id().length();
                }
              });
          batched("localkeys", "forEncrypt() hit, mean of batches of 1000" + v, iters / 1000,
              i -> {
                try (LocalKeys.Use u = keys.forEncrypt()) {
                  sink += u.id().length();
                }
              });
          measure("localkeys", "forDecrypt(id) hit, 32 ids, 1 thread" + v, iters / 2, iters, 10,
              i -> {
                try (LocalKeys.Use u = keys.forDecrypt(ids[i & 31])) {
                  sink += u.id().length();
                }
              });
          batched("localkeys", "forDecrypt(id) hit, mean of batches of 1000" + v, iters / 1000,
              i -> {
                try (LocalKeys.Use u = keys.forDecrypt(ids[i & 31])) {
                  sink += u.id().length();
                }
              });
          for (int threads : localKeysThreads) {
            String on = ", " + threads + (threads == 1 ? " thread" : " threads") + v;
            concurrent("localkeys", "forEncrypt() hit" + on, threads, 1.0, 4.0, t,
                i -> {
                  try (LocalKeys.Use u = keys.forEncrypt()) {
                    sink += u.id().length();
                  }
                });
            concurrent("localkeys", "forDecrypt(id) hit, 32 ids" + on, threads, 1.0, 4.0, t,
                i -> {
                  try (LocalKeys.Use u = keys.forDecrypt(ids[(int) (Thread.currentThread().getId() + i) & 31])) {
                    sink += u.id().length();
                  }
                });
            // Every thread on one historical key: its slot's reservation count is then shared.
            concurrent("localkeys", "forDecrypt(id) hit, 1 id" + on, threads, 1.0, 4.0, t,
                i -> {
                  try (LocalKeys.Use u = keys.forDecrypt(ids[3])) {
                    sink += u.id().length();
                  }
                });
          }
          measure("localkeys", "forDecrypt(id) miss: invalidate(id), then forDecrypt(id)" + v, scaled(200), scaled(5000), 15,
              i -> {
                keys.invalidate(ids[0]);
                try (LocalKeys.Use u = keys.forDecrypt(ids[0])) {
                  sink += u.id().length();
                }
              });
          measure("localkeys", "forEncrypt() miss: invalidate(write id), then forEncrypt()" + v, scaled(200), scaled(5000), 15,
              i -> {
                keys.invalidate(write.id());
                try (LocalKeys.Use u = keys.forEncrypt()) {
                  sink += u.id().length();
                }
              });
          // Renewal: refreshAfter(20 ms) makes every access 20 ms after the last validation the one
          // that queues it. With a Lease Time, a revalidation obtains a new lease: it is the renewal.
          // The control is a hit on the cache above (no renewal due) after the same pause.
          Duration every = Duration.ofMillis(20);
          int samples = topology.equals("live") ? scaled(100) : scaled(300);
          try (LocalKeys renewing = localKeys(kms, name, tag, every)) {
            renewal("forDecrypt(id), refreshAfter 20 ms" + v, () -> keys.forDecrypt(ids[2]),
                () -> renewing.forDecrypt(ids[1]), samples, every);
            renewal("forEncrypt(), refreshAfter 20 ms" + v, keys::forEncrypt, renewing::forEncrypt, samples, every);
          }
        }
      }
    }
    if (topology.equals("live")) return;
    // In process, also the renewal the lease itself makes due: at half the granted lease.
    Duration shortLease = Duration.ofSeconds(2);
    try (Target t = target(shortLease); Kms kms = t.connect(4, "localkeys, " + leaseLabel(shortLease))) {
      String tag = "bench-" + RUN + "-lk-2";
      KeyHandle write = scoped(kms, tag, tag + "-write");
      KeyHandle old = scoped(kms, tag, null);
      try (LocalKeys keys = localKeys(kms, tag + "-write", tag, null)) {
        renewal("forDecrypt(id), due at half the lease (Lease Time 2 s)", null, () -> keys.forDecrypt(old.id()),
            Math.max(3, scaled(8)), Duration.ofMillis(1020));
        sink += write.id().length();
      }
    }
  }

  static KeyHandle scoped(Kms kms, String tag, String name) {
    var c = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).custom(BENCH_TAG, tag);
    if (name != null) c = c.named(name);
    return c.create();
  }

  static LocalKeys localKeys(Kms kms, String name, String tag, Duration refreshAfter) {
    LocalKeys.Builder b = kms.keys().localKeys(name).scope(KeyQuery.all().custom(BENCH_TAG, tag))
        .expect(Expect.aes(256)).ttl(Duration.ofHours(1)).capacity(64);
    if (refreshAfter != null) b.refreshAfter(refreshAfter);
    return b.open();
  }

  /** "Lease Time 3600 s" or "no Lease Time", as the object's attributes state it. */
  static String stated(KeyHandle k) {
    return k.attributes().leaseTime().map(d -> "Lease Time " + d.getSeconds() + " s").orElse("no Lease Time");
  }

  static String leaseLabel(Duration lease) {
    if (topology.equals("live")) return "server's own Lease Time";
    return lease == null ? "server states no Lease Time" : "server states Lease Time " + lease.getSeconds() + " s";
  }

  /**
   * {@code samples} renewals (after 2 unrecorded): waits {@code wait} after the last renewal, times
   * the access that finds the entry due (the caller's latency), then waits for the refresh thread's
   * Get to be answered (the renewal, from the start of that access). With a {@code control}, each
   * sample first pauses as long and times a hit with no renewal due: what a pause alone costs.
   */
  static void renewal(String what, Supplier<LocalKeys.Use> control, Supplier<LocalKeys.Use> access, int samples,
      Duration wait) throws Exception {
    try (LocalKeys.Use u = access.get()) {
      sink += u.id().length(); // the first load, on this thread
    }
    Histogram caller = new Histogram(), renewal = new Histogram(), paused = new Histogram();
    long callerReq = 0, renewalReq = 0, controlReq = 0, failed0 = COUNTER.renewalFailed.sum();
    for (int s = -2; s < samples; s++) {
      if (control != null) {
        Thread.sleep(wait.toMillis());
        long req0 = COUNTER.started.sum();
        long t0 = System.nanoTime();
        try (LocalKeys.Use u = control.get()) {
          sink += u.id().length();
        }
        long t1 = System.nanoTime();
        if (s >= 0) {
          paused.record(t1 - t0);
          controlReq += COUNTER.started.sum() - req0;
        }
      }
      Thread.sleep(wait.toMillis());
      long done0 = COUNTER.renewed.sum(), mine0 = COUNTER.renewalStarted.sum(), all0 = COUNTER.started.sum();
      long t0 = System.nanoTime();
      try (LocalKeys.Use u = access.get()) {
        sink += u.id().length();
      }
      long t1 = System.nanoTime();
      while (COUNTER.renewed.sum() == done0) {
        if (System.nanoTime() - t1 > 30_000_000_000L) throw new IllegalStateException("no renewal within 30 s: " + what);
        LockSupport.parkNanos(20_000);
      }
      long end = COUNTER.renewedAt;
      long mine = COUNTER.renewalStarted.sum() - mine0;
      if (s < 0) continue;
      caller.record(t1 - t0);
      renewal.record(end - t0);
      renewalReq += mine;
      callerReq += COUNTER.started.sum() - all0 - mine;
    }
    if (control != null)
      row("localkeys", "renewal due, " + what + ": control, a hit after the same pause, none due", paused, samples, 0,
          controlReq / (double) samples, -1);
    row("localkeys", "renewal due, " + what + ": the caller's access", caller, samples, 0, callerReq / (double) samples, -1);
    row("localkeys", "renewal due, " + what + ": the renewal (access to its Get's answer, refresh thread)", renewal,
        samples, 0, renewalReq / (double) samples, -1);
    long failed = COUNTER.renewalFailed.sum() - failed0;
    if (failed > 0) System.out.println("  renewals failed: " + failed);
  }

  /**
   * Full JSSE TLS 1.3 handshakes on loopback with client authentication: the server's key and
   * trust managers are a TlsIdentityFollower's and a TlsTrustFollower's (with an allowed-peers
   * query, the client's certificate already an allowed peer), or the JDK's static ones from the
   * same PKI files. Also each manager's per-call cost and each follower's refresh().
   */
  static void tlsHandshake() throws Exception {
    if (pki == null) {
      System.out.println("SKIP tls-handshake: needs --pki (run.sh passes it)");
      return;
    }
    X509Certificate ca = certificate("ca.pem"), serverCert = certificate("server.pem"), clientCert = certificate("client.pem");
    PrivateKey serverKey = privateKey("server.key"), clientKey = privateKey("client.key");
    X509ExtendedKeyManager staticKm = keyManager(serverKey, serverCert);
    X509ExtendedTrustManager staticTm = trustManager(ca);
    SSLContext client = SSLContext.getInstance("TLSv1.3");
    client.init(new KeyManager[] {keyManager(clientKey, clientCert)}, new TrustManager[] {trustManager(ca)}, null);
    client.getClientSessionContext().setSessionCacheSize(16); // every connection has its own host name
    X509Certificate[] clientChain = {clientCert};
    ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
      Thread th = new Thread(r, "bench-tls-followers");
      th.setDaemon(true);
      return th;
    });
    List<Duration> leases = topology.equals("live") ? Arrays.asList((Duration) null) : Arrays.asList(null, Duration.ofHours(1));
    try {
      for (Duration lease : leases) {
        try (Target t = target(lease); Kms kms = t.connect(4, "tls-handshake, " + leaseLabel(lease))) {
          String tag = "bench-" + RUN + "-tls-" + (lease == null ? "default" : lease.getSeconds());
          // The usages the CA certificate's keyUsage states: keytend-kmip-server refuses others at
          // KMIP 1.4.
          KeyHandle anchor = kms.keys().register(ca).usages(KeyUsage.CERTIFICATE_SIGN, KeyUsage.CRL_SIGN)
              .custom(BENCH_TAG, tag + ":ca").register();
          kms.tls().register(serverKey, serverCert).named(tag + "-server").custom(BENCH_TAG, tag + ":peer").register();
          kms.keys().register(clientCert).usages(KeyUsage.VERIFY).custom(BENCH_TAG, tag + ":peer").register();
          String v = ", " + stated(anchor);
          Duration hourly = Duration.ofHours(1);
          try (TlsIdentityFollower identity = kms.tls().follow(tag + "-server", hourly, scheduler);
              TlsTrustFollower trust = kms.tls().trustAnchors(KeyQuery.all().custom(BENCH_TAG, tag + ":ca"),
                  KeyQuery.all().custom(BENCH_TAG, tag + ":peer"), hourly, scheduler)) {
            System.out.println("followers: identity " + identity.status() + ", anchors " + trust.anchors().size()
                + ", allowed peers " + trust.allowedPeers().orElseThrow().size());
            X509ExtendedKeyManager followKm = identity.keyManager();
            X509ExtendedTrustManager followTm = trust.trustManager();
            int calls = scaled(200_000);
            for (X509ExtendedKeyManager km : List.of(staticKm, followKm))
              measure("tls-handshake", "key manager: chooseServerAlias + getCertificateChain + getPrivateKey, "
                      + (km == staticKm ? "static JDK (SunX509)" : "TlsIdentityFollower") + v, calls / 2, calls, 5,
                  i -> {
                    String alias = km.chooseServerAlias("RSA", null, null);
                    sink += km.getCertificateChain(alias).length + System.identityHashCode(km.getPrivateKey(alias));
                  });
            for (X509ExtendedTrustManager tm : List.of(staticTm, followTm))
              measure("tls-handshake", "trust manager: checkClientTrusted(client chain), "
                      + (tm == staticTm ? "static JDK (PKIX)" : "TlsTrustFollower with allowed peers") + v,
                  scaled(5000), scaled(50_000), 5, i -> tm.checkClientTrusted(clientChain, "RSA"));
            try (HandshakeServer jdk = new HandshakeServer(staticKm, staticTm);
                HandshakeServer followers = new HandshakeServer(followKm, followTm)) {
              // One thread, the two servers alternating handshake by handshake, so drift hits both.
              int n = scaled(3000);
              for (int i = 0; i < scaled(300); i++) {
                handshake(client, jdk);
                handshake(client, followers);
              }
              Histogram hj = new Histogram(), hf = new Histogram();
              long start = System.nanoTime(), limit = start + 30_000_000_000L;
              int done = 0;
              for (; done < n && (System.nanoTime() < limit || done < 20); done++) {
                long t0 = System.nanoTime();
                handshake(client, jdk);
                long t1 = System.nanoTime();
                handshake(client, followers);
                long t2 = System.nanoTime();
                hj.record(t1 - t0);
                hf.record(t2 - t1);
              }
              // ops/s: each server's handshakes over its own share of the wall time.
              double wall = (System.nanoTime() - start) / 1e9;
              row("tls-handshake", "full TLS 1.3 handshake, 1 thread, server with static JDK managers" + v, hj, done,
                  wall * hj.sum / (hj.sum + hf.sum), -1, -1);
              row("tls-handshake", "full TLS 1.3 handshake, 1 thread, server with the followers' managers" + v, hf, done,
                  wall * hf.sum / (hj.sum + hf.sum), -1, -1);
              System.out.printf(Locale.ROOT, "  followers minus static, per handshake: %+.1f us at the mean, %+.1f us at p50%n",
                  (hf.sum / hf.count - hj.sum / hj.count) / 1e3, (hf.percentile(50) - hj.percentile(50)) / 1e3);
              for (HandshakeServer s : List.of(jdk, followers))
                concurrent("tls-handshake", "full TLS 1.3 handshake, 8 threads, server with "
                    + (s == jdk ? "static JDK managers" : "the followers' managers") + v, 8, 1.0, 4.0, t,
                    i -> handshake(client, s));
              System.out.println("  server, static managers: " + jdk.describe());
              System.out.println("  server, followers' managers: " + followers.describe());
            }
            measure("tls-handshake", "TlsIdentityFollower.refresh(), nothing new" + v, scaled(20), scaled(1000), 15,
                i -> sink += identity.refresh().hashCode());
            measure("tls-handshake", "TlsTrustFollower.refresh(), nothing new (anchors and allowed peers)" + v, scaled(20),
                scaled(1000), 15, i -> sink += trust.refresh() ? 1 : 0);
            if (trust.failure().isPresent()) System.out.println("  trust follower failure: " + trust.failure().get());
            System.out.println("followers after: identity " + identity.state());
          }
        }
      }
    } finally {
      scheduler.shutdownNow();
    }
  }

  private static final AtomicLong CONNECTIONS = new AtomicLong();

  /**
   * One full handshake with client authentication, then one application byte. The JDK client keys
   * its TLS 1.3 resumption cache by host and port, and invalidating the session after each
   * handshake did not stop every resumption in a trial; so each connection gets a host name of its
   * own (sent as SNI, which the server ignores), and nothing is resumed. The server counts the
   * client chains it checked, to show it.
   */
  static void handshake(SSLContext client, HandshakeServer server) throws IOException {
    try (Socket plain = new Socket()) {
      plain.setTcpNoDelay(true); // without it, Nagle and delayed ACKs add tens of ms on loopback
      plain.setSoLinger(true, 0); // no TIME_WAIT: tens of thousands of connections
      plain.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), server.port()));
      String host = "c" + CONNECTIONS.incrementAndGet() + ".bench.invalid";
      try (SSLSocket s = (SSLSocket) client.getSocketFactory().createSocket(plain, host, server.port(), true)) {
        s.setEnabledProtocols(new String[] {"TLSv1.3"});
        s.startHandshake();
        // TLS 1.3: the server checks the client's certificate after the client's Finished; a
        // refusal arrives as an alert instead of this byte.
        if (s.getInputStream().read() != 1) throw new IOException("the server refused the handshake");
      }
    }
  }

  static X509Certificate certificate(String file) throws IOException, CertificateException {
    try (InputStream in = Files.newInputStream(pki.resolve(file))) {
      return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
    }
  }

  /** An unencrypted PKCS#8 RSA key, as {@code openssl req -nodes} writes it. */
  static PrivateKey privateKey(String file) throws Exception {
    String pem = Files.readString(pki.resolve(file));
    String body = pem.replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "").replaceAll("\\s", "");
    return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
  }

  static X509ExtendedKeyManager keyManager(PrivateKey key, X509Certificate cert) throws Exception {
    KeyStore ks = KeyStore.getInstance("PKCS12");
    ks.load(null, null);
    char[] password = "bench".toCharArray();
    ks.setKeyEntry("identity", key, password, new Certificate[] {cert});
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(ks, password);
    return (X509ExtendedKeyManager) kmf.getKeyManagers()[0];
  }

  static X509ExtendedTrustManager trustManager(X509Certificate ca) throws Exception {
    KeyStore ts = KeyStore.getInstance("PKCS12");
    ts.load(null, null);
    ts.setCertificateEntry("ca", ca);
    TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
    tmf.init(ts);
    return (X509ExtendedTrustManager) tmf.getTrustManagers()[0];
  }

  /**
   * A loopback TLS 1.3 server that requires client authentication, completes each handshake, sends
   * one byte and waits for the client to close. Counts the client chains its trust manager checked,
   * which shows that every handshake was a full one.
   */
  static final class HandshakeServer implements AutoCloseable {
    final SSLServerSocket socket;
    final ExecutorService pool = Executors.newCachedThreadPool(r -> {
      Thread th = new Thread(r, "bench-handshake-server");
      th.setDaemon(true);
      return th;
    });
    final LongAdder handshakes = new LongAdder(), failures = new LongAdder();
    final CountingTrust trust;
    volatile String session = "none";

    HandshakeServer(X509ExtendedKeyManager km, X509ExtendedTrustManager tm) throws Exception {
      trust = new CountingTrust(tm);
      SSLContext ctx = SSLContext.getInstance("TLSv1.3");
      ctx.init(new KeyManager[] {km}, new TrustManager[] {trust}, null);
      socket = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0, 1024, InetAddress.getLoopbackAddress());
      socket.setNeedClientAuth(true);
      socket.setEnabledProtocols(new String[] {"TLSv1.3"});
      Thread accept = new Thread(() -> {
        try {
          for (;;) {
            SSLSocket s = (SSLSocket) socket.accept();
            pool.execute(() -> serve(s));
          }
        } catch (IOException closed) {
          // done
        }
      }, "bench-handshake-accept");
      accept.setDaemon(true);
      accept.start();
    }

    int port() {
      return socket.getLocalPort();
    }

    void serve(SSLSocket s) {
      try (s) {
        s.setSoTimeout(10_000);
        s.setTcpNoDelay(true);
        s.setSoLinger(true, 0);
        s.startHandshake();
        session = s.getSession().getProtocol() + " " + s.getSession().getCipherSuite();
        OutputStream out = s.getOutputStream();
        out.write(1);
        out.flush();
        handshakes.increment();
        s.getInputStream().read(); // until the client closes
      } catch (IOException e) {
        if (!socket.isClosed() && !String.valueOf(e.getMessage()).contains("reset")) failures.increment();
      }
    }

    String describe() {
      return handshakes.sum() + " handshakes, " + trust.checks.sum() + " client chains checked, " + failures.sum()
          + " failed, session " + session;
    }

    @Override
    public void close() throws IOException {
      socket.close();
      pool.shutdownNow();
    }
  }

  /** Delegates to a trust manager and counts the client chains checked. */
  static final class CountingTrust extends X509ExtendedTrustManager {
    final X509ExtendedTrustManager d;
    final LongAdder checks = new LongAdder();

    CountingTrust(X509ExtendedTrustManager d) {
      this.d = d;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
      checks.increment();
      d.checkClientTrusted(chain, authType, socket);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
      checks.increment();
      d.checkClientTrusted(chain, authType, engine);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
      checks.increment();
      d.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
      d.checkServerTrusted(chain, authType, socket);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
      d.checkServerTrusted(chain, authType, engine);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
      d.checkServerTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return d.getAcceptedIssuers();
    }
  }

  /**
   * chunkedSealer/chunkedOpener: the per-file header (the one KMS call of each), one 64 KiB chunk,
   * and a 64 MiB file of 1024 chunks of 64 KiB (sealer and opener made before the timing), with
   * sealing the same 64 MiB as a stream for reference.
   */
  static void chunked() throws Exception {
    try (Target t = target(); Kms kms = t.connect(4, "chunked")) {
      CurrentKey kek = kms.keys().current(aes(kms, null));
      int size = 64 * 1024, count = 1024;
      long total = (long) size * count;
      byte[] plain = random(size);
      byte[] fileId = ("bench-" + RUN + "-chunked-file").getBytes(StandardCharsets.UTF_8);
      measure("chunked", "chunkedSealer(fileId): new data key, wrapped by the KMS; header; close()",
          scaled(50), scaled(5000), 15,
          i -> {
            try (ChunkedSealer s = kek.chunkedSealer(("file-" + i).getBytes(StandardCharsets.UTF_8))) {
              sink += s.header().length;
            }
          });
      byte[][] sealed = new byte[count][];
      byte[] header;
      try (ChunkedSealer s = kek.chunkedSealer(fileId)) {
        header = s.header();
        for (int c = 0; c < count; c++) sealed[c] = c == count - 1 ? s.sealFinal(c, plain) : s.seal(c, plain);
      }
      System.out.println("header " + header.length + " B; sealed chunk " + sealed[0].length + " B (+"
          + (sealed[0].length - size) + " B)");
      measure("chunked", "chunkedOpener(header, fileId): data key unwrapped by the KMS; close()",
          scaled(50), scaled(5000), 15,
          i -> {
            try (ChunkedOpener o = kek.chunkedOpener(header, fileId)) {
              sink += o.keyId().length();
            }
          });
      try (ChunkedSealer s = kek.chunkedSealer(("bench-" + RUN + "-chunks").getBytes(StandardCharsets.UTF_8));
          ChunkedOpener o = kek.chunkedOpener(header, fileId)) {
        measure("chunked", "seal one 64 KiB chunk", scaled(2000), scaled(20_000), 15, i -> sink += s.seal(i, plain).length);
        measure("chunked", "open one 64 KiB chunk", scaled(2000), scaled(20_000), 15,
            i -> sink += o.open(i & (count - 1), sealed[i & (count - 1)]).length);
      }
      int files = Math.max(3, scaled(5));
      ChunkedSealer[] sealers = new ChunkedSealer[files + 1];
      for (int f = 0; f < sealers.length; f++)
        sealers[f] = kek.chunkedSealer(("bench-" + RUN + "-file-" + f).getBytes(StandardCharsets.UTF_8));
      Row seal = measure("chunked", "seal a 64 MiB file, 1024 chunks of 64 KiB (sealer made before)", 1, files, 120,
          i -> {
            ChunkedSealer s = sealers[i];
            for (int c = 0; c < count; c++) sink += (c == count - 1 ? s.sealFinal(c, plain) : s.seal(c, plain)).length;
            s.close();
          });
      mibPerSecond(seal, total);
      try (ChunkedOpener o = kek.chunkedOpener(header, fileId)) {
        Row open = measure("chunked", "open a 64 MiB file, 1024 chunks of 64 KiB (opener made before)", 1, files, 120,
            i -> {
              for (int c = 0; c < count; c++)
                sink += (c == count - 1 ? o.openFinal(c, sealed[c]) : o.open(c, sealed[c])).length;
            });
        mibPerSecond(open, total);
      }
      Row stream = measure("chunked", "reference: sealing 64 MiB as a stream (to a null sink)", 1, files, 120,
          i -> {
            try (SealingStream out = kek.handle().sealing(OutputStream.nullOutputStream(), AAD)) {
              for (int c = 0; c < count; c++) out.write(plain);
              out.finish();
            }
          });
      mibPerSecond(stream, total);
    }
  }

  /** kms.keys().moveName: the reads, the ordered batch with Undo and the reads after. */
  static void moveName() throws Exception {
    try (Target t = target(); Kms kms = t.connect(4, "movename")) {
      String name = "bench-" + RUN + "-move";
      String[] ids = {aes(kms, name).id(), aes(kms, null).id()};
      // Even calls move the name from the first key to the second, odd ones back.
      measure("movename", "moveName(name, from, to), back and forth between two keys", scaled(20), scaled(2000), 20,
          i -> kms.keys().moveName(name, ids[i & 1], ids[(i + 1) & 1]));
      String holder = kms.keys().findByName(name).orElseThrow().id();
      System.out.println("after: the name is on " + (holder.equals(ids[0]) ? "the first" : holder.equals(ids[1]) ? "the second" : "another")
          + " key; names of the first " + kms.keys().handle(ids[0]).attributes().names() + ", of the second "
          + kms.keys().handle(ids[1]).attributes().names());
    }
  }

  /**
   * A two-endpoint Kms whose first endpoint stops answering: (1) while connected (the first call
   * after, and the calls after it), (2) refused at connect, (3) silent at connect (accepts TCP,
   * never answers TLS). The call measured is findByName (one Locate) of a key that each server has
   * under the same name, so that it works on live servers with independent stores.
   */
  static void failover() throws Exception {
    try (Target t = target()) {
      String name = "bench-" + RUN + "-failover";
      t.createEverywhere(name);
      Op find = i -> sink += kms(i).keys().findByName(name).orElseThrow().hashCode();
      int rounds = topology.equals("live") ? 1 : 5;
      Histogram first = new Histogram();
      long firstReq = 0;
      Row steady = null;
      for (int r = 0; r < rounds; r++) {
        try (Failover f = t.failover("dies")) {
          try (Kms kms = t.connect(f.builder, 4, r == 0 ? "failover, first endpoint dies while connected" : null)) {
            CURRENT.set(kms);
            for (int i = 0; i < 200; i++) find.run(i);
            f.kill();
            long req0 = COUNTER.started.sum();
            List<String> trace = COUNTER.tracing();
            long t0 = System.nanoTime();
            find.run(0);
            first.record(System.nanoTime() - t0);
            COUNTER.trace = null;
            firstReq += COUNTER.started.sum() - req0;
            if (r == 0) {
              System.out.println("first call after the first endpoint died, as the listener saw it:");
              trace.forEach(System.out::println);
            }
            if (r == rounds - 1)
              steady = measure("failover", "dies while connected: findByName, the calls after the first (8 s)", 0,
                  Integer.MAX_VALUE, 8, find);
          }
        }
      }
      row("failover", "dies while connected: findByName, first call after", first, rounds, 0, firstReq / (double) rounds, -1);
      String[] kinds = topology.equals("inmemory") ? new String[] {"refused"} : new String[] {"refused", "silent"};
      for (String kind : kinds) {
        int n = kind.equals("silent") ? 2 : 5;
        Histogram connect = new Histogram(), call = new Histogram();
        long req = 0;
        for (int r = 0; r < n; r++) {
          try (Failover f = t.failover(kind)) {
            KmsConfig config = t.config(f.builder, 4, r == 0 ? "failover, first endpoint " + kind + " at connect" : null);
            List<String> trace = r == 0 ? COUNTER.tracing() : null;
            long t0 = System.nanoTime();
            try (Kms kms = Kms.connect(config)) {
              long t1 = System.nanoTime();
              long req0 = COUNTER.started.sum();
              CURRENT.set(kms);
              find.run(0);
              call.record(System.nanoTime() - t1);
              connect.record(t1 - t0);
              if (trace != null) {
                COUNTER.trace = null;
                System.out.printf("connect (%.1f ms) and first call with the first endpoint %s, as the listener saw them:%n",
                    (t1 - t0) / 1e6, kind);
                trace.forEach(System.out::println);
              }
              req += COUNTER.started.sum() - req0;
              if (r == n - 1)
                measure("failover", kind + " at connect: findByName, the calls after the first (8 s)", 0,
                    Integer.MAX_VALUE, 8, find);
            }
          }
        }
        row("failover", kind + " at connect: Kms.connect (config built before)", connect, n, 0, -1, -1);
        row("failover", kind + " at connect: findByName, first call", call, n, 0, req / (double) n, -1);
      }
      System.out.println("endpointUnavailable events so far: " + COUNTER.unavailable.sum() + ", retries: " + COUNTER.retries.sum());
    } finally {
      CURRENT.remove(); // the last Kms would keep its in-memory server (and every request it kept)
    }
  }

  /** The Kms the failover scenario's calls go to. */
  private static final ThreadLocal<Kms> CURRENT = new ThreadLocal<>();

  static Kms kms(int ignored) {
    return CURRENT.get();
  }

  // ---------------------------------------------------------------------------------------------
  // Targets: where the Kms connects

  static Target target() throws Exception {
    return target(null);
  }

  /** {@code lease}: the Lease Time an in-memory server states on every object (null: none). */
  static Target target(Duration lease) throws Exception {
    Target t = switch (topology) {
      case "inmemory" -> new Direct();
      case "inmemory-tls" -> new Front();
      default -> new Live();
    };
    t.leaseTime(lease);
    return t;
  }

  abstract static class Target implements AutoCloseable {
    abstract KmsConfig.Builder builder() throws Exception;

    abstract Failover failover(String kind) throws Exception;

    Kms connect(int pool, String describe) throws Exception {
      return connect(builder(), pool, describe);
    }

    Kms connect(KmsConfig.Builder b, int pool, String describe) {
      return Kms.connect(config(b, pool, describe));
    }

    KmsConfig config(KmsConfig.Builder b, int pool, String describe) {
      KmsConfig config = b.poolSize(pool).addListener(COUNTER).build();
      if (describe != null)
        System.out.println("config (" + describe + "): " + topology + ", endpoints " + config.endpoints()
            + ", pool " + config.poolSize() + ", call timeout " + config.callTimeout() + ", connect timeout "
            + config.connectTimeout() + ", idle timeout " + config.idleTimeout() + ", retry "
            + config.retryPolicy().maxAttempts() + " attempts, cooldown " + config.retryPolicy().cooldown()
            + ", KMIP " + config.minimumVersion() + ".." + config.maximumVersion());
      return config;
    }

    void describeConnections() {}

    /** In memory: the Lease Time the server states on every object. A live server keeps its own. */
    void leaseTime(Duration lease) {}

    /** Creates a key named {@code name} that every endpoint can find. */
    void createEverywhere(String name) throws Exception {
      try (Kms kms = connect(4, null)) {
        aes(kms, name);
      }
    }

    @Override
    public void close() throws Exception {}
  }

  /** A first endpoint that goes away (or never answers) and a working second one. */
  static final class Failover implements AutoCloseable {
    final KmsConfig.Builder builder;
    final AutoCloseable kill, cleanup;

    Failover(KmsConfig.Builder builder, AutoCloseable kill, AutoCloseable cleanup) {
      this.builder = builder;
      this.kill = kill;
      this.cleanup = cleanup;
    }

    void kill() throws Exception {
      if (kill != null) kill.close();
    }

    @Override
    public void close() throws Exception {
      if (cleanup != null) cleanup.close();
    }
  }

  static KmsConfig.Builder tls(String... at) {
    return KmsConfig.builder()
        .endpoints(at)
        .clientIdentityPem(pki.resolve("client.pem"), pki.resolve("client.key"))
        .trustPem(pki.resolve("ca.pem"))
        .minimumVersion(version)
        .maximumVersion(version);
  }

  /** The in-memory server through its in-process transport. */
  static final class Direct extends Target {
    final InMemoryKmipServer server = InMemoryKmipServer.of(version);

    @Override
    KmsConfig.Builder builder() {
      return server.configure();
    }

    @Override
    void leaseTime(Duration lease) {
      server.leaseTime(lease);
    }

    @Override
    Failover failover(String kind) {
      InMemoryKmipServer first = server.replica(), second = server.replica();
      KmsConfig.Builder b = first.configureReplicas(second);
      return switch (kind) {
        case "dies" -> new Failover(b, () -> first.unreachable(true), null);
        case "refused" -> new Failover(first.unreachable(true).configureReplicas(second), null, null);
        // The in-process transport cannot hang a TLS handshake: the silent case needs sockets.
        default -> throw new IllegalArgumentException("no silent endpoint without sockets");
      };
    }
  }

  /** The in-memory server behind a loopback TLS listener in this JVM. */
  static final class Front extends Target {
    final InMemoryKmipServer server = InMemoryKmipServer.of(version);
    final TlsFront front;

    Front() throws Exception {
      front = new TlsFront(server);
    }

    @Override
    void leaseTime(Duration lease) {
      server.leaseTime(lease);
    }

    @Override
    KmsConfig.Builder builder() {
      return tls("127.0.0.1:" + front.port());
    }

    @Override
    Failover failover(String kind) throws Exception {
      return switch (kind) {
        case "dies" -> {
          TlsFront first = new TlsFront(server.replica());
          yield new Failover(tls("127.0.0.1:" + first.port(), "127.0.0.1:" + front.port()), first, first);
        }
        case "refused" -> new Failover(tls("127.0.0.1:" + closedPort(), "127.0.0.1:" + front.port()), null, null);
        default -> {
          Silent s = new Silent();
          yield new Failover(tls("127.0.0.1:" + s.port(), "127.0.0.1:" + front.port()), null, s);
        }
      };
    }

    @Override
    void describeConnections() {
      System.out.println("in-process TLS listener: connections accepted by client certificate " + front.byClient
          + ", first session " + front.session);
    }

    @Override
    public void close() throws Exception {
      front.close();
    }
  }

  /**
   * Real servers, each with its own store (keytend-kmip-server is a single-server design); the
   * first endpoint's server can be stopped for the failover scenario ({@code --kill-command} or
   * {@code --kill-pid}).
   */
  static final class Live extends Target {
    @Override
    void createEverywhere(String name) {
      for (String endpoint : endpoints)
        try (Kms kms = Kms.connect(tls(endpoint).addListener(COUNTER).build())) {
          aes(kms, name);
        }
    }

    @Override
    KmsConfig.Builder builder() {
      return tls(endpoints.toArray(String[]::new));
    }

    @Override
    Failover failover(String kind) throws Exception {
      String second = endpoints.get(endpoints.size() - 1);
      return switch (kind) {
        case "dies" -> new Failover(tls(endpoints.toArray(String[]::new)), () -> {
          if (killCommand != null) {
            Process p = new ProcessBuilder("sh", "-c", killCommand).inheritIO().start();
            int exit = p.waitFor();
            if (exit != 0) throw new IllegalStateException("--kill-command exited " + exit + ": " + killCommand);
            System.out.println("stopped the first endpoint's server: " + killCommand);
            return;
          }
          if (killPid <= 0)
            throw new IllegalStateException("--kill-command or --kill-pid: how to stop the first endpoint's server");
          ProcessHandle p = ProcessHandle.of(killPid).orElseThrow();
          p.destroy();
          p.onExit().get();
          System.out.println("killed the first endpoint's server, pid " + killPid);
        }, null);
        case "refused" -> new Failover(tls(endpoints.get(0), second), null, null);
        default -> {
          Silent s = new Silent();
          yield new Failover(tls("127.0.0.1:" + s.port(), second), null, s);
        }
      };
    }
  }

  // ---------------------------------------------------------------------------------------------
  // In-process servers

  /** A loopback TLS listener that hands each TTLV request to an in-memory server. */
  static final class TlsFront implements AutoCloseable {
    final InMemoryKmipServer server;
    final SSLServerSocket socket;
    final Set<Socket> open = ConcurrentHashMap.newKeySet();
    final Map<String, LongAdder> byClient = new ConcurrentHashMap<>();
    volatile String session = "none";
    volatile boolean closed;

    TlsFront(InMemoryKmipServer server) throws Exception {
      this.server = server;
      SSLContext ctx = KmsConfig.sslContextFromPem(pki.resolve("server.pem"), pki.resolve("server.key"), pki.resolve("ca.pem"));
      socket = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0, 1024, InetAddress.getLoopbackAddress());
      socket.setNeedClientAuth(true);
      Thread accept = new Thread(this::accept, "tls-front-accept");
      accept.setDaemon(true);
      accept.start();
    }

    int port() {
      return socket.getLocalPort();
    }

    void accept() {
      while (!closed) {
        try {
          SSLSocket s = (SSLSocket) socket.accept();
          open.add(s);
          Thread th = new Thread(() -> serve(s), "tls-front-conn");
          th.setDaemon(true);
          th.start();
        } catch (IOException e) {
          if (!closed) System.out.println("tls front accept: " + e);
        }
      }
    }

    void serve(SSLSocket s) {
      TtlvCodec codec = new TtlvCodec();
      try (s) {
        s.startHandshake();
        String who = s.getSession().getPeerPrincipal().getName();
        byClient.computeIfAbsent(who, w -> new LongAdder()).increment();
        session = s.getSession().getProtocol() + " " + s.getSession().getCipherSuite();
        InputStream in = new BufferedInputStream(s.getInputStream());
        OutputStream out = new BufferedOutputStream(s.getOutputStream());
        for (;;) {
          Ttlv request = codec.read(in);
          out.write(codec.encode(server.exchange(request)));
          out.flush();
        }
      } catch (IOException endOrError) {
        // The client closed the connection (or this listener was closed).
      } finally {
        open.remove(s);
      }
    }

    @Override
    public void close() throws IOException {
      closed = true;
      socket.close();
      for (Socket s : open) s.close();
    }
  }

  /** Accepts TCP connections and never answers: a hung server or a black-holed TLS handshake. */
  static final class Silent implements AutoCloseable {
    final ServerSocket socket = new ServerSocket(0, 64, InetAddress.getLoopbackAddress());
    final List<Socket> held = new CopyOnWriteArrayList<>();

    Silent() throws IOException {
      Thread th = new Thread(() -> {
        try {
          for (;;) held.add(socket.accept());
        } catch (IOException closed) {
          // done
        }
      }, "silent-accept");
      th.setDaemon(true);
      th.start();
    }

    int port() {
      return socket.getLocalPort();
    }

    @Override
    public void close() throws IOException {
      socket.close();
      for (Socket s : held) s.close();
    }
  }

  static int closedPort() throws IOException {
    try (ServerSocket s = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
      return s.getLocalPort();
    }
  }

  static void swap(Path ids, String to) throws IOException {
    Path tmp = ids.resolve("current.tmp");
    Files.deleteIfExists(tmp);
    Files.createSymbolicLink(tmp, Path.of(to));
    Files.move(tmp, ids.resolve("current"), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
  }

  // ---------------------------------------------------------------------------------------------
  // Measurement

  static final class Counter implements KmsListener {
    final LongAdder started = new LongAdder(), retries = new LongAdder(), unavailable = new LongAdder();
    final LongAdder reloaded = new LongAdder(), reloadFailed = new LongAdder();
    final List<Long> reloadTimes = new CopyOnWriteArrayList<>();
    /** LocalKeys renewals: requests sent on its refresh thread, renewals ended (and when), failures. */
    final LongAdder renewalStarted = new LongAdder(), renewed = new LongAdder(), renewalFailed = new LongAdder();
    volatile long renewedAt;

    static boolean onRefreshThread() {
      return Thread.currentThread().getName().startsWith("keytend-local-keys-refresh");
    }
    /** While set, what the SDK reports, with the time since {@link #traceFrom}. */
    volatile List<String> trace;
    volatile long traceFrom;

    void trace(String what) {
      List<String> t = trace;
      if (t != null) t.add(String.format(Locale.ROOT, "  +%7.1f ms %s", (System.nanoTime() - traceFrom) / 1e6, what));
    }

    List<String> tracing() {
      traceFrom = System.nanoTime();
      List<String> t = new CopyOnWriteArrayList<>();
      trace = t;
      return t;
    }

    @Override
    public void started(KmsEvent event) {
      started.increment();
      if (onRefreshThread()) renewalStarted.increment();
      trace("started " + event.operation() + " attempt " + event.attempt() + " at " + event.endpoint());
    }

    @Override
    public void finished(KmsEvent event) {
      // A LocalKeys validation ends with its Get (step asSecretKey).
      if (onRefreshThread() && "asSecretKey".equals(event.step())) {
        renewedAt = System.nanoTime();
        if (event.outcome() == KmsEvent.Outcome.FAILED) renewalFailed.increment();
        renewed.increment();
      }
      trace("finished " + event.operation() + " attempt " + event.attempt() + " at " + event.endpoint() + ": "
          + event.outcome() + " after " + event.latency().toNanos() / 1e6 + " ms"
          + event.failure().map(f -> " (" + f.getClass().getSimpleName() + ": " + f.getMessage() + ")").orElse(""));
    }

    @Override
    public void retrying(KmsEvent failed, Duration delay) {
      retries.increment();
      trace("retrying after " + delay.toNanos() / 1e6 + " ms");
    }

    @Override
    public void endpointUnavailable(String endpoint, String why) {
      unavailable.increment();
      trace("endpointUnavailable " + endpoint + ": " + why);
    }

    @Override
    public void localKeyRefreshFailed(
        String name, String keyId, LocalUse purpose, KmsException failure, Duration remainingValidity) {
      System.out.println("localKeyRefreshFailed " + keyId + ": " + failure);
      renewedAt = System.nanoTime();
      renewalFailed.increment();
      renewed.increment();
    }

    @Override
    public void credentialsReloaded(String files) {
      reloaded.increment();
      reloadTimes.add(System.nanoTime());
    }

    @Override
    public void credentialsReloadFailed(String files, String why) {
      reloadFailed.increment();
      System.out.println("credentialsReloadFailed: " + why);
    }
  }

  /**
   * Log-linear histogram of nanosecond values: exact below 2048, then 1024 sub-buckets per power of
   * two (relative error below 0.1%). Not thread-safe; merge per-thread ones with {@link #add}.
   */
  static final class Histogram {
    static final int SUB = 1024;
    final long[] counts = new long[SUB * 54];
    long count, max, min = Long.MAX_VALUE;
    double sum;

    void record(long v) {
      if (v < 0) v = 0;
      counts[index(v)]++;
      count++;
      sum += v;
      if (v > max) max = v;
      if (v < min) min = v;
    }

    static int index(long v) {
      if (v < 2 * SUB) return (int) v;
      int shift = 64 - Long.numberOfLeadingZeros(v) - 11;
      return SUB * shift + (int) (v >>> shift);
    }

    /** The highest value that falls in bucket {@code i}. */
    static long highest(int i) {
      if (i < 2 * SUB) return i;
      int shift = i / SUB - 1;
      long q = i - (long) SUB * shift;
      return ((q + 1) << shift) - 1;
    }

    long percentile(double p) {
      if (count == 0) return 0;
      long rank = Math.max(1, (long) Math.ceil(p / 100.0 * count));
      long seen = 0;
      for (int i = 0; i < counts.length; i++) {
        seen += counts[i];
        if (seen >= rank) return Math.min(highest(i), max);
      }
      return max;
    }

    /** How many values were above {@code v} (to the histogram's precision). */
    long above(long v) {
      long n = 0;
      for (int i = index(v) + 1; i < counts.length; i++) n += counts[i];
      return n;
    }

    void add(Histogram o) {
      for (int i = 0; i < counts.length; i++) counts[i] += o.counts[i];
      count += o.count;
      sum += o.sum;
      max = Math.max(max, o.max);
      min = Math.min(min, o.min);
    }
  }

  record Row(Histogram h, long ops, double seconds) {}

  /** Runs {@code op} warm-up times, then up to {@code max} times or {@code seconds} (at least 20). */
  static Row measure(String scenario, String what, int warmup, int max, double seconds, Op op) throws Exception {
    for (int i = 0; i < warmup; i++) op.run(i);
    Histogram h = new Histogram();
    long req0 = COUNTER.started.sum();
    long alloc0 = allocated();
    long start = System.nanoTime();
    long limit = start + (long) (seconds * 1e9);
    int i = 0;
    for (; i < max; i++) {
      long t0 = System.nanoTime();
      op.run(warmup + i);
      long t1 = System.nanoTime();
      h.record(t1 - t0);
      if (t1 > limit && i >= 20) {
        i++;
        break;
      }
    }
    double wall = (System.nanoTime() - start) / 1e9;
    long alloc = allocated() - alloc0;
    row(scenario, what, h, i, wall, (COUNTER.started.sum() - req0) / (double) i, alloc / (double) i);
    return new Row(h, i, wall);
  }

  /** {@code batches} batches of 1000 calls; records each batch's mean per call. */
  static void batched(String scenario, String what, int batches, Op op) throws Exception {
    for (int w = 0; w < batches / 2; w++) for (int i = 0; i < 1000; i++) op.run(i);
    Histogram h = new Histogram();
    long req0 = COUNTER.started.sum();
    long alloc0 = allocated();
    long start = System.nanoTime();
    for (int b = 0; b < batches; b++) {
      long t0 = System.nanoTime();
      for (int i = 0; i < 1000; i++) op.run(b * 1000 + i);
      h.record((System.nanoTime() - t0) / 1000);
    }
    double wall = (System.nanoTime() - start) / 1e9;
    long ops = batches * 1000L;
    row(scenario, what, h, ops, wall, (COUNTER.started.sum() - req0) / (double) ops,
        (allocated() - alloc0) / (double) ops);
  }

  /** {@code threads} threads calling {@code op} for warm-up and then measured seconds. */
  static Histogram concurrent(String scenario, String what, int threads, double warm, double seconds, Target t, Op op)
      throws Exception {
    AtomicLong phase = new AtomicLong();
    Histogram[] hs = new Histogram[threads];
    LongAdder errors = new LongAdder();
    List<Thread> workers = new ArrayList<>();
    CountDownLatch ready = new CountDownLatch(threads);
    for (int w = 0; w < threads; w++) {
      Histogram h = hs[w] = new Histogram();
      Thread th = new Thread(() -> {
        ready.countDown();
        int i = 0;
        for (long p; (p = phase.get()) < 2; i++) {
          long t0 = System.nanoTime();
          try {
            op.run(i);
          } catch (Exception e) {
            errors.increment();
            if (errors.sum() < 3) System.out.println("call failed: " + e);
          }
          long t1 = System.nanoTime();
          if (p == 1 && phase.get() == 1) h.record(t1 - t0);
        }
      });
      workers.add(th);
      th.start();
    }
    ready.await();
    Thread.sleep((long) (warm * 1000));
    long req0 = COUNTER.started.sum();
    long start = System.nanoTime();
    phase.set(1);
    Thread.sleep((long) (seconds * 1000 / 2));
    Resources mid = Resources.take(false);
    Thread.sleep((long) (seconds * 1000 / 2));
    phase.set(2);
    double wall = (System.nanoTime() - start) / 1e9;
    long req = COUNTER.started.sum() - req0;
    for (Thread th : workers) th.join();
    Histogram all = new Histogram();
    for (Histogram h : hs) all.add(h);
    row(scenario, what, all, all.count, wall, req / (double) all.count, -1);
    System.out.println("  during: threads " + mid.threads + ", fds " + mid.fds + ", errors " + errors.sum()
        + ", load " + load());
    return all;
  }

  static void mibPerSecond(Row r, long size) {
    double mean = r.h.sum / r.h.count / 1e9;
    double p50 = r.h.percentile(50) / 1e9;
    System.out.printf("  throughput: %.0f MiB/s at the mean, %.0f MiB/s at p50%n",
        size / 1048576.0 / mean, size / 1048576.0 / p50);
  }

  static void header() {
    System.out.println("| scenario | measurement | n | p50 us | p90 us | p99 us | p99.9 us | max us | ops/s | req/op | B/op |");
    System.out.println("|---|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|");
  }

  static void row(String scenario, String what, Histogram h, long ops, double seconds, double reqPerOp, double bytesPerOp) {
    String line = String.format(Locale.ROOT, "| %s | %s | %d | %s | %s | %s | %s | %s | %s | %s | %s |",
        scenario, what, ops, us(h.percentile(50)), us(h.percentile(90)), us(h.percentile(99)), us(h.percentile(99.9)),
        us(h.max), seconds > 0 ? String.format(Locale.ROOT, "%.0f", ops / seconds) : "-",
        reqPerOp >= 0 ? String.format(Locale.ROOT, "%.2f", reqPerOp) : "-",
        bytesPerOp >= 0 ? String.format(Locale.ROOT, "%.0f", bytesPerOp) : "-");
    System.out.println(line);
    ROWS.add(line);
  }

  static String us(long nanos) {
    double u = nanos / 1000.0;
    if (u < 10) return String.format(Locale.ROOT, "%.3f", u);
    if (u < 1000) return String.format(Locale.ROOT, "%.1f", u);
    return String.format(Locale.ROOT, "%.0f", u);
  }

  static long allocated() {
    var bean = ManagementFactory.getThreadMXBean();
    if (bean instanceof com.sun.management.ThreadMXBean sun) return sun.getCurrentThreadAllocatedBytes();
    return 0;
  }

  record Resources(long heapMiB, int threads, long fds) {
    static Resources take() throws Exception {
      return take(true);
    }

    static Resources take(boolean gc) throws Exception {
      if (gc) {
        System.gc();
        Thread.sleep(100);
        System.gc();
        Thread.sleep(100);
      }
      long heap = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed() >> 20;
      long fds;
      try (Stream<Path> s = Files.list(Path.of("/proc/self/fd"))) {
        fds = s.count() - 1; // the directory stream's own descriptor
      } catch (IOException noProc) {
        fds = -1;
      }
      return new Resources(heap, ManagementFactory.getThreadMXBean().getThreadCount(), fds);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Environment and helpers

  static void environment() throws IOException {
    Runtime rt = Runtime.getRuntime();
    String cpu = "?";
    try (Stream<String> lines = Files.lines(Path.of("/proc/cpuinfo"))) {
      cpu = lines.filter(l -> l.startsWith("model name")).findFirst().map(l -> l.replaceFirst(".*:\\s*", "")).orElse("?");
    } catch (IOException ignored) {
      // not Linux
    }
    List<String> gcs = new ArrayList<>();
    for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) gcs.add(gc.getName());
    System.out.println("# keytend-kmip bench, run " + RUN);
    System.out.println("topology  " + topology + (topology.equals("live") ? " " + endpoints : "") + ", KMIP " + version);
    System.out.println("jdk       " + System.getProperty("java.vm.vendor") + " " + System.getProperty("java.vm.name")
        + " " + System.getProperty("java.runtime.version"));
    System.out.println("os        " + System.getProperty("os.name") + " " + System.getProperty("os.version") + " "
        + System.getProperty("os.arch"));
    System.out.println("cpu       " + cpu + ", " + rt.availableProcessors() + " processors");
    System.out.println("heap      max " + (rt.maxMemory() >> 20) + " MiB, GC " + gcs + ", JVM flags "
        + ManagementFactory.getRuntimeMXBean().getInputArguments());
    System.out.println("sdk       " + Kms.class.getProtectionDomain().getCodeSource().getLocation());
    System.out.println("load      " + load() + " (1, 5, 15 min)");
    System.out.println("scale     " + scale + ", keys for the miss scenario " + keys);
  }

  static String load() {
    try {
      String[] f = Files.readString(Path.of("/proc/loadavg")).trim().split("\\s+");
      return f[0] + " " + f[1] + " " + f[2];
    } catch (IOException e) {
      return "?";
    }
  }

  static KeyHandle aes(Kms kms, String name) {
    var c = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
    if (name != null) c = c.named(name);
    return c.create();
  }

  static byte[] random(int n) {
    byte[] b = new byte[n];
    RANDOM.nextBytes(b);
    return b;
  }

  static int scaled(int n) {
    return Math.max(1, (int) (n * scale));
  }

  private static Map<String, String> parse(String[] args) {
    Map<String, String> m = new LinkedHashMap<>();
    for (int i = 0; i < args.length; i++) {
      if (!args[i].startsWith("--") || i + 1 >= args.length)
        throw new IllegalArgumentException("arguments are --name value pairs: " + args[i]);
      m.put(args[i].substring(2), args[++i]);
    }
    return m;
  }

  private static String need(Map<String, String> a, String key) {
    String v = a.get(key);
    if (v == null) throw new IllegalArgumentException("--" + key + " is required");
    return v;
  }
}
