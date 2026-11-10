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

import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * The concurrent replacement "Storm": several {@link
 * Kms} instances, each on its own {@link InMemoryKmipServer#replica() replica} of one store, rotate
 * or replace one key named {@code "vault"} at the same moment while a sealing thread per instance
 * keeps sealing records with it. Mutations of each instance's operator thread meet injected HANG and
 * REPLY_LOST faults; failures are recovered by following the exception's advice. After each round
 * (quiescent: no faults, sealers stopped) and after each reconcile, the concurrency guarantees are
 * checked: concurrent rotations never lose data and never break reading; only {@code reconcile}
 * deactivates tips; no advice names a live key for destruction; nothing loops; deadlines hold.
 *
 * <p>Problem categories ({@link Result#counts}): {@code RECORD}, {@code DESTROYED}, {@code
 * SDK-REVOKED}, {@code DESTROY-ADVICE}, {@code LOOP}, {@code DEADLINE}, {@code DIVERGE}, {@code
 * RECONCILE}, {@code NONKMS}, {@code RETURNED} (a key an operation returned cannot seal, though the
 * harness did not compromise it: a call returns its own key, Active),
 * {@code RECOVERY} (following the advice ended in an exception that gives no advice to repeat) and
 * {@code REFRESH} (a key the SDK returned could not seal, and {@code latest()} gave no key that
 * could); and {@code CATEGORY} (an operation failed as FIX_ACCESS or FIX_REQUEST, which no injected
 * fault calls for).
 *
 * <p>Deterministic as far as threads allow: the round plan, fault draws and identifiers come from
 * the seed; interleavings do not. No state is shared between runs, so runs may go in parallel.
 */
final class StormHarness {
  static final String NAME = "vault";
  static final byte[] AAD = "aad".getBytes(StandardCharsets.UTF_8);

  /** Mutations that meet injected faults (only on an instance's operator or reconcile thread). */
  private static final Set<Operation> FAULTABLE =
      EnumSet.of(
          Operation.CREATE,
          Operation.RE_KEY,
          Operation.ACTIVATE,
          Operation.REVOKE,
          Operation.ADD_ATTRIBUTE,
          Operation.DELETE_ATTRIBUTE,
          Operation.MODIFY_ATTRIBUTE);

  /** Repeats allowed when following advice (a 4th need is a LOOP). */
  static final int MAX_REPEATS = 3;

  /** Repeats allowed of a reconcile that did not finish (a 6th need is a LOOP). */
  static final int MAX_RECONCILE_REPEATS = 5;

  /** An operation, recovery or reconcile not finished after this long is a LOOP. */
  static final long FINISH_SECONDS = 20;

  /** A single call may overrun the call timeout by this much before it is a DEADLINE problem. */
  static final long DEADLINE_SLACK_MS = 500;

  /**
   * Whether, after a reconcile, every other Active key of the winner's tree is a RECONCILE problem
   * (the brief: reconcile deactivates "the other Active keys of the tree"), or only the other tips
   * (keys without a Replacement link). Rotation by Re-key leaves the replaced key Active, so with
   * true a reconcile must retire the replaced keys too.
   */
  static final boolean RECONCILE_RETIRES_REPLACED = true;

  /** Examples kept per category. */
  static final int EXAMPLES = 3;

  /**
   * One storm.
   *
   * @param version 1.4 or 2.1
   * @param instances the number of {@code Kms} instances (3–5 is the usual range)
   * @param mode {@code rotate} (every instance rotates), {@code replace} (every instance replaces
   *     the key as compromised: {@code replaceCompromised}, or one in three revokes it and calls
   *     {@code findOrCreate().replacingCompromised()}), {@code mixed} (each round one of the two), or
   *     {@code grace} (every instance calls {@code rotateOrLatest(Rotation.grace(ZERO))},
   *     so the round's key is Deactivated while the sealers still hold it)
   * @param ids identifier order: {@code asc}, {@code desc} or {@code rand}
   * @param faultP the probability that a faultable mutation of an operator meets a fault
   * @param hangShare the share of faults that are HANG (the rest are REPLY_LOST)
   * @param fallback when Re-key is refused in replace rounds (the documented fallback): {@code
   *     none}, {@code always} or {@code rand} (a coin per round)
   * @param callTimeout each instance's call timeout (HANG waits that long)
   * @param reconcileEvery reconcile after every this many rounds (0: only at the end); without a
   *     reconcile hook, never
   * @param reconcileUnderFaults whether the reconcile's mutations meet faults too
   * @param sealPauseMs the sealers' pause between seals
   * @param refuseSecondReKey whether the server refuses to re-key a key that was re-keyed already
   *     ({@link InMemoryKmipServer#refuseSecondReKey}), as keytend-kmip-server does: rotations never fork
   */
  record Config(
      KmipVersion version,
      boolean uniqueNames,
      int instances,
      String mode,
      String ids,
      double faultP,
      double hangShare,
      int rounds,
      long seed,
      String fallback,
      Duration callTimeout,
      int reconcileEvery,
      boolean reconcileUnderFaults,
      int sealPauseMs,
      boolean refuseSecondReKey) {
    Config {
      if (version != KmipVersion.V1_4 && version != KmipVersion.V2_1)
        throw new IllegalArgumentException("version: 1.4 or 2.1");
      if (instances < 2 || instances > 16) throw new IllegalArgumentException("instances: 2..16");
      if (!Set.of("rotate", "replace", "mixed", "grace").contains(mode))
        throw new IllegalArgumentException("mode " + mode);
      if (!Set.of("asc", "desc", "rand").contains(ids))
        throw new IllegalArgumentException("ids " + ids);
      if (!Set.of("none", "always", "rand").contains(fallback))
        throw new IllegalArgumentException("fallback " + fallback);
      if (faultP < 0 || faultP > 1 || hangShare < 0 || hangShare > 1)
        throw new IllegalArgumentException("probability");
      if (rounds < 1 || reconcileEvery < 0 || sealPauseMs < 0)
        throw new IllegalArgumentException("rounds");
      Objects.requireNonNull(callTimeout, "callTimeout");
    }

    /** The defaults: HANG share 0.3, fallback rand, call timeout 700 ms, reconcile at the end only, under faults. */
    static Config of(
        KmipVersion version,
        boolean unique,
        int instances,
        String mode,
        String ids,
        double faultP,
        int rounds,
        long seed) {
      return new Config(
          version,
          unique,
          instances,
          mode,
          ids,
          faultP,
          0.3,
          rounds,
          seed,
          "rand",
          Duration.ofMillis(700),
          0,
          true,
          1,
          false);
    }

    Config withCallTimeout(Duration d) {
      return new Config(
          version,
          uniqueNames,
          instances,
          mode,
          ids,
          faultP,
          hangShare,
          rounds,
          seed,
          fallback,
          d,
          reconcileEvery,
          reconcileUnderFaults,
          sealPauseMs,
          refuseSecondReKey);
    }

    Config withHangShare(double share) {
      return new Config(
          version,
          uniqueNames,
          instances,
          mode,
          ids,
          faultP,
          share,
          rounds,
          seed,
          fallback,
          callTimeout,
          reconcileEvery,
          reconcileUnderFaults,
          sealPauseMs,
          refuseSecondReKey);
    }

    Config withFallback(String f) {
      return new Config(
          version,
          uniqueNames,
          instances,
          mode,
          ids,
          faultP,
          hangShare,
          rounds,
          seed,
          f,
          callTimeout,
          reconcileEvery,
          reconcileUnderFaults,
          sealPauseMs,
          refuseSecondReKey);
    }

    Config withReconcile(int every, boolean underFaults) {
      return new Config(
          version,
          uniqueNames,
          instances,
          mode,
          ids,
          faultP,
          hangShare,
          rounds,
          seed,
          fallback,
          callTimeout,
          every,
          underFaults,
          sealPauseMs,
          refuseSecondReKey);
    }

    Config withSealPause(int ms) {
      return new Config(
          version,
          uniqueNames,
          instances,
          mode,
          ids,
          faultP,
          hangShare,
          rounds,
          seed,
          fallback,
          callTimeout,
          reconcileEvery,
          reconcileUnderFaults,
          ms,
          refuseSecondReKey);
    }

    Config withRefuseSecondReKey(boolean refuse) {
      return new Config(
          version,
          uniqueNames,
          instances,
          mode,
          ids,
          faultP,
          hangShare,
          rounds,
          seed,
          fallback,
          callTimeout,
          reconcileEvery,
          reconcileUnderFaults,
          sealPauseMs,
          refuse);
    }

    String label() {
      return String.format(
              Locale.ROOT,
              "v=%s uniq=%s n=%d mode=%s ids=%s p=%.2f hang=%.2f rounds=%d seed=%d fb=%s timeout=%dms",
              version == KmipVersion.V1_4 ? "1.4" : "2.1",
              uniqueNames,
              instances,
              mode,
              ids,
              faultP,
              hangShare,
              rounds,
              seed,
              fallback,
              callTimeout.toMillis())
          + (refuseSecondReKey ? " refuse2" : "");
    }

    @Override
    public String toString() {
      return label();
    }
  }

  /** What a storm found. */
  static final class Result {
    final Config config;

    /** Problems by category. */
    final Map<String, Integer> counts = new TreeMap<>();

    /** The first {@link #EXAMPLES} problems of each category. */
    final Map<String, List<String>> examples = new TreeMap<>();

    /** Informative counters (operations by outcome, sealer refreshes, links, message histogram). */
    final Map<String, Long> stats = new TreeMap<>();

    int records, faults, hangs, lost, reconciles, reconcileRepeats;
    long maxCallMs, elapsedMs;

    Result(Config config) {
      this.config = config;
    }

    synchronized void add(String category, String text) {
      counts.merge(category, 1, Integer::sum);
      List<String> l = examples.computeIfAbsent(category, c -> new ArrayList<>());
      if (l.size() < EXAMPLES)
        l.add(text.length() > 4000 ? text.substring(0, 4000) + " ..." : text);
    }

    synchronized int problems() {
      return counts.values().stream().mapToInt(Integer::intValue).sum();
    }

    synchronized int count(String category) {
      return counts.getOrDefault(category, 0);
    }

    synchronized String summary() {
      return String.format(
          Locale.ROOT,
          "STORM %s : problems=%d %s records=%d faults=%d (hang %d lost %d) maxCall=%dms reconciles=%d (repeats %d) %.1fs",
          config.label(),
          problems(),
          counts,
          records,
          faults,
          hangs,
          lost,
          maxCallMs,
          reconciles,
          reconcileRepeats,
          elapsedMs / 1000.0);
    }

    synchronized String report() {
      StringBuilder b = new StringBuilder(summary());
      for (var e : examples.entrySet())
        for (String x : e.getValue())
          b.append("\n  ").append(e.getKey()).append(": ").append(x.replace("\n", "\n    "));
      b.append("\n  stats ").append(stats);
      return b.toString();
    }
  }

  private record Rec(int inst, String key, byte[] data, int round, String how) {}

  private record Outcome(KeyHandle got, KmsException failure) {}

  private final Config cfg;
  private final Function<Kms, KeyHandle> reconcile;
  private final Result res;
  private final ThreadLocal<Boolean> faulty = ThreadLocal.withInitial(() -> false);
  private volatile boolean faultsOn, refuseRekey, jitter;
  private final AtomicInteger faults = new AtomicInteger(),
      hangs = new AtomicInteger(),
      lost = new AtomicInteger();
  private final AtomicLong maxCall = new AtomicLong();
  private final Map<String, AtomicLong> stats = new ConcurrentSkipListMap<>();
  private final List<String> messages = Collections.synchronizedList(new ArrayList<>());
  private final List<Rec> recs = Collections.synchronizedList(new ArrayList<>());
  private final Set<String> sealedKeys = ConcurrentHashMap.newKeySet();

  /** Keys the harness itself compromised (each replace round's {@code cur}). */
  private final Set<String> harnessCompromised = ConcurrentHashMap.newKeySet();

  /** The keys a grace round rotated with a grace of zero: their deactivation is the round's purpose. */
  private final Set<String> graceRetired = ConcurrentHashMap.newKeySet();

  /** For each key, the number of reconciles started before it was first seen. */
  private final Map<String, Integer> firstSeenEpoch = new HashMap<>();

  /** Keys already reported, so that a key is reported once per category. */
  private final Set<String> reported = new HashSet<>();

  private int reconcilesStarted;

  /** The round plan (modes, operations, fallback, reconciling instance). */
  private final Random rnd;

  /** The checks' choices (which instance opens a record), apart so that the plan does not depend on timing. */
  private final Random checkRnd;

  /**
   * @param reconcile the operator's reconcile, run from one instance (for example {@code k ->
   *     k.keys().reconcile("vault").orElseThrow()}); null skips the reconcile phase
   */
  StormHarness(Config cfg, Function<Kms, KeyHandle> reconcile) {
    this.cfg = cfg;
    this.reconcile = reconcile;
    this.res = new Result(cfg);
    this.rnd = new Random(cfg.seed());
    this.checkRnd = new Random(cfg.seed() ^ 0x5eedL);
  }

  /** Runs the storm; every wait is bounded, and every thread and {@code Kms} is closed at the end. */
  Result run() throws InterruptedException {
    long t0 = System.nanoTime();
    AtomicInteger threads = new AtomicInteger();
    ExecutorService pool =
        Executors.newCachedThreadPool(
            r -> {
              Thread t = new Thread(r, "storm-" + cfg.seed() + "-" + threads.incrementAndGet());
              t.setDaemon(true);
              return t;
            });
    List<Kms> opened = new ArrayList<>();
    try {
      storm(pool, opened);
    } finally {
      faultsOn = false;
      pool.shutdownNow();
      for (Kms k : opened)
        try {
          k.close();
        } catch (RuntimeException ignored) {
          // closing is best effort
        }
      pool.awaitTermination(10, TimeUnit.SECONDS);
      res.records = recs.size();
      res.faults = faults.get();
      res.hangs = hangs.get();
      res.lost = lost.get();
      res.maxCallMs = maxCall.get();
      synchronized (res) {
        stats.forEach((k, v) -> res.stats.put(k, v.get()));
      }
      res.elapsedMs = (System.nanoTime() - t0) / 1_000_000;
    }
    return res;
  }

  private void storm(ExecutorService pool, List<Kms> opened) throws InterruptedException {
    int n = cfg.instances();
    InMemoryKmipServer srv =
        InMemoryKmipServer.of(cfg.version())
            .uniqueNames(cfg.uniqueNames())
            .refuseSecondReKey(cfg.refuseSecondReKey());
    srv.clock(Clock.fixed(Instant.parse("2026-10-27T10:00:00Z"), ZoneOffset.UTC));
    AtomicLong idc = new AtomicLong(cfg.ids().equals("desc") ? 999_999 : 100_000);
    Random idr = new Random(cfg.seed() ^ 77);
    Set<String> used = new HashSet<>();
    srv.identifierSource(
        () -> {
          if (cfg.ids().equals("asc")) return "k" + idc.incrementAndGet();
          if (cfg.ids().equals("desc")) return "k" + idc.decrementAndGet();
          synchronized (used) {
            String s;
            do s = "k" + (100_000 + idr.nextInt(900_000));
            while (!used.add(s));
            return s;
          }
        });
    Kms admin = srv.connect();
    opened.add(admin);
    List<Kms> inst = new ArrayList<>();
    for (int i = 0; i < n; i++) {
      InMemoryKmipServer r = srv.replica();
      KmipTransport t = faulting(r, new Random(cfg.seed() * 31 + i));
      Kms k = Kms.connect(r.configure().transport(e -> t).callTimeout(cfg.callTimeout()).build());
      // The server's clock: a grace period is counted from this machine's now.
      k.clock(Clock.fixed(Instant.parse("2026-10-27T10:00:00Z"), ZoneOffset.UTC));
      opened.add(k);
      inst.add(k);
    }
    srv.clock(Clock.fixed(Instant.parse("2026-10-20T10:00:00Z"), ZoneOffset.UTC));
    KeyHandle first =
        admin
            .keys()
            .createAes(256)
            .named(NAME)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .findOrCreate();
    srv.clock(Clock.fixed(Instant.parse("2026-10-27T10:00:00Z"), ZoneOffset.UTC));
    String start = first.id();
    boolean reconciledLast = false;
    for (int round = 0; round < cfg.rounds(); round++) {
      String cur;
      try {
        cur =
            admin
                .keys()
                .findByName(NAME)
                .map(KeyHandle::id)
                .orElseGet(() -> admin.keys().handle(start).latest().id());
      } catch (KmsException e) {
        res.add("DIVERGE", "r" + round + " the round's key cannot be found: " + e + dump(srv));
        cur = start;
      }
      String m =
          cfg.mode().equals("mixed") ? (rnd.nextBoolean() ? "rotate" : "replace") : cfg.mode();
      boolean fb =
          cfg.fallback().equals("always") || (cfg.fallback().equals("rand") && rnd.nextBoolean());
      refuseRekey = fb && m.equals("replace");
      if (m.equals("grace")) graceRetired.add(cur);
      else if (!m.equals("rotate")) harnessCompromised.add(cur);
      String[] how = new String[n];
      for (int i = 0; i < n; i++)
        how[i] = m.equals("rotate") || m.equals("grace") ? m : (rnd.nextInt(3) == 0 ? "foc" : "rc");
      runRound(pool, srv, inst, round, m, cur, how);
      refuseRekey = false;
      check(
          srv,
          admin,
          inst,
          round,
          m + (fb && m.equals("replace") ? ",fallback" : ""),
          cur,
          start,
          null);
      reconciledLast = false;
      if (reconcile != null
          && cfg.reconcileEvery() > 0
          && (round + 1) % cfg.reconcileEvery() == 0) {
        reconcilePhase(pool, srv, admin, inst, round, cur, start);
        reconciledLast = true;
      }
    }
    if (reconcile != null && !reconciledLast) {
      String cur;
      try {
        cur = admin.keys().findByName(NAME).map(KeyHandle::id).orElse(start);
      } catch (KmsException e) {
        cur = start;
      }
      reconcilePhase(pool, srv, admin, inst, cfg.rounds(), cur, start);
    }
  }

  /** The instance's transport: faults on the operator's mutations, Re-key refused for the fallback, some jitter. */
  private KmipTransport faulting(InMemoryKmipServer r, Random fr) {
    return new KmipTransport() {
      @Override
      public Ttlv exchange(Ttlv q) throws IOException {
        return exchange(q, CallContext.NONE);
      }

      @Override
      public Ttlv exchange(Ttlv q, CallContext c) throws IOException {
        Operation o = op(q);
        if (o == Operation.RE_KEY && refuseRekey)
          r.failNext(ServerOperation.RE_KEY, Fault.UNSUPPORTED);
        else if (faultsOn && faulty.get() && o != null && FAULTABLE.contains(o)) {
          double x, h;
          synchronized (fr) {
            x = fr.nextDouble();
            h = fr.nextDouble();
          }
          if (x < cfg.faultP()) {
            faults.incrementAndGet();
            ServerOperation so = ServerOperation.valueOf(o.name());
            if (h < cfg.hangShare()) {
              hangs.incrementAndGet();
              r.failNext(so, Fault.HANG);
            } else {
              lost.incrementAndGet();
              r.failNext(so, Fault.REPLY_LOST);
            }
          }
        }
        if (jitter) {
          int ms;
          synchronized (fr) {
            ms = fr.nextInt(3);
          }
          try {
            Thread.sleep(ms);
          } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new InterruptedIOException();
          }
        }
        return r.exchange(q, c);
      }
    };
  }

  private static Operation op(Ttlv r) {
    try {
      return Operation.fromCode(r.require(Tag.BATCH_ITEM).require(Tag.OPERATION).intValue());
    } catch (RuntimeException e) {
      return null;
    }
  }

  // ---- a round: operators and sealers, then recovery ----

  private void runRound(
      ExecutorService pool,
      InMemoryKmipServer srv,
      List<Kms> inst,
      int round,
      String m,
      String cur,
      String[] how)
      throws InterruptedException {
    int n = inst.size();
    CyclicBarrier bar = new CyclicBarrier(n);
    AtomicBoolean stop = new AtomicBoolean();
    List<Future<Outcome>> ops = new ArrayList<>();
    List<Future<?>> sealers = new ArrayList<>();
    jitter = true;
    faultsOn = cfg.faultP() > 0;
    for (int i = 0; i < n; i++) {
      int me = i;
      Kms k = inst.get(i);
      String h = how[i];
      ops.add(pool.submit(() -> operator(k, me, round, h, cur, bar, srv)));
      sealers.add(pool.submit(() -> sealer(k, me, round, cur, stop)));
    }
    Outcome[] out = new Outcome[n];
    for (int i = 0; i < n; i++) {
      try {
        out[i] = ops.get(i).get(FINISH_SECONDS, TimeUnit.SECONDS);
      } catch (TimeoutException te) {
        res.add(
            "LOOP",
            "r"
                + round
                + " i"
                + i
                + " "
                + how[i]
                + " did not finish within "
                + FINISH_SECONDS
                + " s"
                + threads());
        ops.get(i).cancel(true);
      } catch (ExecutionException ee) {
        res.add("NONKMS", "r" + round + " i" + i + " operator thread failed: " + ee.getCause());
      }
    }
    faultsOn = false;
    for (int i = 0; i < n; i++) {
      if (out[i] == null || out[i].failure() == null) continue;
      stat("recovery");
      recover(inst.get(i), i, round, how[i], cur, out[i].failure(), srv);
    }
    Thread.sleep(5);
    stop.set(true);
    for (Future<?> f : sealers) {
      try {
        f.get(10, TimeUnit.SECONDS);
      } catch (TimeoutException te) {
        res.add("LOOP", "r" + round + " a sealer is stuck" + threads());
        f.cancel(true);
      } catch (ExecutionException ee) {
        res.add("NONKMS", "r" + round + " sealer thread failed: " + ee.getCause());
      }
    }
    jitter = false;
  }

  private Outcome operator(
      Kms k, int me, int round, String h, String cur, CyclicBarrier bar, InMemoryKmipServer srv)
      throws Exception {
    bar.await(10, TimeUnit.SECONDS);
    KeyHandle got = null;
    faulty.set(true);
    try {
      got = timed(round, "i" + me + " " + h, () -> op(k, h, cur));
      stat("op-ok-" + h);
    } catch (KmsException e) {
      stat("op-fail-" + h + "-" + e.getClass().getSimpleName());
      note(round, me, h, e);
      category(round, me, h, e);
      return new Outcome(null, e);
    } catch (RuntimeException e) {
      res.add("NONKMS", "r" + round + " i" + me + " " + h + " non-KMS exception " + e);
      return new Outcome(null, null);
    } finally {
      faulty.set(false);
    }
    sealReturned(k, got, me, round, "op", h, srv);
    return new Outcome(got, null);
  }

  /** The round's operation: rotate, replaceCompromised, or revoke then findOrCreate().replacingCompromised(). */
  private static KeyHandle op(Kms k, String how, String cur) {
    RevocationReason r =
        RevocationReason.keyCompromise("leak", Instant.parse("2026-10-27T09:00:00Z"));
    switch (how) {
      case "rotate":
        return k.keys().handle(cur).rotate();
      case "grace":
        // The old key is Deactivated at once; a repeat (the advice of a schedule that failed)
        // resumes.
        return k.keys().handle(cur).rotateOrLatest(Rotation.grace(Duration.ZERO));
      case "rc":
        return k.keys().handle(cur).replaceCompromised(r);
      default:
        // as the guide says: compromise the key, then findOrCreate replacing it
        KeyHandle h = k.keys().handle(cur);
        try {
          if (h.attributes().state() == KeyState.ACTIVE) h.revoke(r);
        } catch (StateConflictException already) {
          // another instance compromised or replaced it first
        }
        return k.keys()
            .createAes(256)
            .named(NAME)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .replacingCompromised()
            .findOrCreate();
    }
  }

  /** Seals with a key an operation returned; when it cannot seal, refreshes through latest(). */
  private void sealReturned(
      Kms k, KeyHandle got, int me, int round, String how, String op, InMemoryKmipServer srv) {
    try {
      seal(k, got, me, round, how);
    } catch (StateConflictException se) {
      stat("returned-key-not-active-" + op + (refuseRekey ? "-fallback" : ""));
      note(round, me, how + "-seal", se);
      // A call returns its own key, Active; only a key the harness compromised since may refuse.
      if (!harnessCompromised.contains(got.id()))
        res.add(
            "RETURNED",
            "r"
                + round
                + " i"
                + me
                + " "
                + op
                + " returned "
                + got.id()
                + ", which cannot seal: "
                + se
                + dump(srv));
      try {
        KeyHandle fresh = timed(round, "i" + me + " refresh", got::latest);
        seal(k, fresh, me, round, how + "-refreshed");
      } catch (KmsException e2) {
        note(round, me, how + "-refresh", e2);
        res.add(
            "REFRESH",
            "r"
                + round
                + " i"
                + me
                + " "
                + op
                + " returned "
                + got.id()
                + ", which cannot seal, and refreshing through latest() failed: "
                + e2
                + dump(srv));
      }
    } catch (KmsException e) {
      note(round, me, how + "-seal", e);
      stat("returned-key-seal-fail-" + e.getClass().getSimpleName());
    } catch (RuntimeException e) {
      res.add(
          "NONKMS",
          "r" + round + " i" + me + " sealing with the returned key: non-KMS exception " + e);
    }
  }

  private void sealer(Kms k, int me, int round, String cur, AtomicBoolean stop) {
    // In a grace round, a handle kept from before the rotation: refused once the key is
    // Deactivated.
    KeyHandle cached = graceRetired.contains(cur) ? k.keys().handle(cur) : null;
    int j = 0;
    while (!stop.get() && !Thread.currentThread().isInterrupted()) {
      try {
        int pick = j++ % 3;
        if (pick == 0) {
          Optional<KeyHandle> h =
              timed(round, "sealer i" + me + " findByName", () -> k.keys().findByName(NAME));
          if (h.isPresent()) seal(k, h.get(), me, round, "byname");
          else stat("sealer-no-name");
        } else if (pick == 1) {
          seal(
              k,
              timed(round, "sealer i" + me + " latest", () -> k.keys().handle(cur).latest()),
              me,
              round,
              "latest");
        } else {
          if (cached == null) {
            cached = timed(round, "sealer i" + me + " latest", () -> k.keys().handle(cur).latest());
          } else if (j % 9 == 2) {
            KeyHandle c = cached;
            if (!timed(round, "sealer i" + me + " isLatest", c::isLatest)) {
              stat("sealer-refresh-not-latest");
              cached = timed(round, "sealer i" + me + " latest", c::latest);
            }
          }
          try {
            seal(k, cached, me, round, "cached");
          } catch (StateConflictException se) {
            stat("sealer-refresh-stale");
            KeyHandle c = cached;
            cached = timed(round, "sealer i" + me + " latest", c::latest);
          }
        }
      } catch (KmsException e) {
        stat("sealer-" + e.getClass().getSimpleName());
        note(round, me, "sealer", e);
      } catch (RuntimeException e) {
        res.add("NONKMS", "r" + round + " i" + me + " sealer: non-KMS exception " + e);
      }
      try {
        Thread.sleep(cfg.sealPauseMs());
      } catch (InterruptedException e) {
        return;
      }
    }
  }

  private void seal(Kms k, KeyHandle h, int me, int round, String how) {
    byte[] d =
        timed(
            round,
            "i" + me + " seal",
            () -> h.seal(("r" + round + "i" + me + how).getBytes(StandardCharsets.UTF_8), AAD));
    String kid = KmsKeys.sealedKeyId(d);
    sealedKeys.add(kid);
    recs.add(new Rec(me, kid, d, round, how));
    stat("sealed-" + how);
  }

  /** Follows the failure's advice: repeat the operation, or for rotate use latest(); at most MAX_REPEATS times. */
  private void recover(
      Kms k,
      int me,
      int round,
      String how,
      String cur,
      KmsException failure,
      InMemoryKmipServer srv) {
    KmsException last = failure;
    long t0 = System.nanoTime();
    for (int attempt = 1; ; attempt++) {
      if (attempt > MAX_REPEATS) {
        res.add(
            "LOOP",
            "r"
                + round
                + " i"
                + me
                + " recovery of "
                + how
                + " needs more than "
                + MAX_REPEATS
                + " repeats; last: "
                + last
                + dump(srv));
        return;
      }
      if (System.nanoTime() - t0 > TimeUnit.SECONDS.toNanos(FINISH_SECONDS)) {
        res.add(
            "LOOP",
            "r"
                + round
                + " i"
                + me
                + " recovery of "
                + how
                + " did not finish within "
                + FINISH_SECONDS
                + " s");
        return;
      }
      // A rotate is repeated only when the advice says so; "use latest()" (a repeat refused because
      // the lost Re-key took effect) is followed with latest().
      boolean repeat =
          !how.equals("rotate") || (advisesRepeat(last, "rotate") && !advisesLatest(last));
      String what = repeat ? how : "latest";
      try {
        KeyHandle got =
            timed(
                round,
                "i" + me + " recovery " + what,
                () -> repeat ? op(k, how, cur) : k.keys().handle(cur).latest());
        stat("recovery-ok-" + what);
        sealReturned(k, got, me, round, "recovered", how, srv);
        return;
      } catch (KmsException e) {
        stat("recovery-fail-" + what + "-" + e.getClass().getSimpleName());
        note(round, me, how + "-recovery", e);
        category(round, me, how + " recovery", e);
        if (!(e instanceof PartialCompletionException
            || e instanceof OutcomeUnknownException
            || e instanceof TransientException
            || (how.equals("rotate") && advisesLatest(e)))) {
          res.add(
              "RECOVERY",
              "r"
                  + round
                  + " i"
                  + me
                  + " following the advice of "
                  + last.getClass().getSimpleName()
                  + " ("
                  + what
                  + ") failed with "
                  + e
                  + dump(srv));
          return;
        }
        last = e;
      } catch (RuntimeException e) {
        res.add("NONKMS", "r" + round + " i" + me + " recovery: non-KMS exception " + e);
        return;
      }
    }
  }

  /**
   * CATEGORY: the harness injects only hangs and lost replies (and Re-key refusals the SDK's
   * fallback handles), so no failure of an operation is the caller's to fix: an access or request
   * category means a race was mislabeled (as a lost rotation race was FIX_ACCESS on servers that
   * refuse a second Re-key).
   */
  private void category(int round, int me, String what, KmsException e) {
    if (e.category() == KmsException.Category.FIX_ACCESS
        || e.category() == KmsException.Category.FIX_REQUEST)
      res.add(
          "CATEGORY",
          "r" + round + " i" + me + " " + what + " failed as " + e.category() + ": " + e);
  }

  /** Whether the message of a refused rotate says to use latest() instead. */
  private static boolean advisesLatest(KmsException e) {
    return e instanceof StateConflictException
        && String.valueOf(e.getMessage()).contains("use latest()");
  }

  /** Whether the message advises repeating {@code op} (and does not say "do not repeat"). */
  private static boolean advisesRepeat(KmsException e, String op) {
    String m = String.valueOf(e.getMessage());
    return m.contains("repeat " + op + "()") && !m.contains("do not repeat");
  }

  // ---- reconcile ----

  private void reconcilePhase(
      ExecutorService pool,
      InMemoryKmipServer srv,
      Kms admin,
      List<Kms> inst,
      int round,
      String cur,
      String start)
      throws InterruptedException {
    int who = rnd.nextInt(inst.size());
    Kms k = inst.get(who);
    reconcilesStarted++;
    res.reconciles++;
    boolean underFaults = cfg.reconcileUnderFaults() && cfg.faultP() > 0;
    faultsOn = underFaults;
    Future<String> f =
        pool.submit(
            () -> {
              faulty.set(underFaults);
              try {
                for (int attempt = 0; ; attempt++) {
                  try {
                    KeyHandle w = timed(round, "i" + who + " reconcile", () -> reconcile.apply(k));
                    stat("reconcile-ok");
                    return w.id();
                  } catch (PartialCompletionException
                      | OutcomeUnknownException
                      | TransientException e) {
                    stat("reconcile-fail-" + e.getClass().getSimpleName());
                    note(round, who, "reconcile", e);
                    if (attempt >= MAX_RECONCILE_REPEATS) {
                      res.add(
                          "LOOP",
                          "r"
                              + round
                              + " i"
                              + who
                              + " reconcile needs more than "
                              + MAX_RECONCILE_REPEATS
                              + " repeats; last: "
                              + e
                              + dump(srv));
                      return null;
                    }
                    synchronized (res) {
                      res.reconcileRepeats++;
                    }
                  } catch (KmsException e) {
                    note(round, who, "reconcile", e);
                    res.add(
                        "RECONCILE",
                        "r" + round + " i" + who + " reconcile failed: " + e + dump(srv));
                    return null;
                  } catch (NoSuchElementException e) {
                    res.add(
                        "RECONCILE",
                        "r" + round + " i" + who + " reconcile found no key: " + e + dump(srv));
                    return null;
                  } catch (RuntimeException e) {
                    res.add(
                        "NONKMS", "r" + round + " i" + who + " reconcile: non-KMS exception " + e);
                    return null;
                  }
                }
              } finally {
                faulty.set(false);
              }
            });
    String winner = null;
    try {
      winner = f.get(FINISH_SECONDS, TimeUnit.SECONDS);
    } catch (TimeoutException te) {
      res.add(
          "LOOP",
          "r" + round + " reconcile did not finish within " + FINISH_SECONDS + " s" + threads());
      f.cancel(true);
    } catch (ExecutionException ee) {
      res.add("NONKMS", "r" + round + " reconcile thread failed: " + ee.getCause());
    } finally {
      faultsOn = false;
    }
    check(srv, admin, inst, round, "reconcile", cur, start, winner == null ? "" : winner);
  }

  // ---- invariants (quiescent) ----

  /**
   * @param reconciled null after a round; after a reconcile, the winner it returned ("" when it failed)
   */
  private void check(
      InMemoryKmipServer srv,
      Kms admin,
      List<Kms> inst,
      int round,
      String mode,
      String cur,
      String start,
      String reconciled) {
    String p = "r" + round + " (" + mode + "): ";
    List<String> ids = srv.ids();
    for (String id : ids) firstSeenEpoch.putIfAbsent(id, reconcilesStarted);
    linkStats(srv, ids, start);

    // DESTROYED and SDK-REVOKED: keys that sealed data
    for (String kid : sealedKeys) {
      KeyState s = srv.state(kid).orElse(null);
      if ((s == KeyState.DESTROYED || s == KeyState.DESTROYED_COMPROMISED || !srv.hasMaterial(kid))
          && reported.add("DESTROYED " + kid))
        res.add(
            "DESTROYED",
            p
                + "key that sealed data is "
                + s
                + (srv.hasMaterial(kid) ? "" : " without material")
                + ": "
                + kid
                + dump(srv));
      if ((s == KeyState.DEACTIVATED || s == KeyState.COMPROMISED)
          && !harnessCompromised.contains(kid)
          && !(s == KeyState.DEACTIVATED && graceRetired.contains(kid))
          && firstSeenEpoch.getOrDefault(kid, reconcilesStarted) >= reconcilesStarted
          && reported.add("SDK-REVOKED " + kid))
        res.add(
            "SDK-REVOKED",
            p
                + "key that sealed data is "
                + s
                + " although the harness did not revoke it and no reconcile ran since it was made: "
                + kid
                + dump(srv));
    }

    // DIVERGE: every instance chooses the same key by name and by latest() from every start
    Map<String, List<String>> chosen = new TreeMap<>();
    List<String> from = new ArrayList<>(List.of(start, cur));
    for (String kid : new TreeSet<>(sealedKeys)) if (!from.contains(kid)) from.add(kid);
    for (int i = 0; i < inst.size(); i++) {
      Kms k = inst.get(i);
      chosen
          .computeIfAbsent(
              view(() -> k.keys().findByName(NAME).map(KeyHandle::id).orElse("<none>")),
              x -> new ArrayList<>())
          .add("i" + i + ":byName");
      for (String f : from)
        chosen
            .computeIfAbsent(view(() -> k.keys().handle(f).latest().id()), x -> new ArrayList<>())
            .add("i" + i + ":latest(" + f + ")");
    }
    String agreed = chosen.size() == 1 ? chosen.keySet().iterator().next() : null;
    if (chosen.size() != 1) {
      StringBuilder b = new StringBuilder(p + "instances choose differently:");
      chosen.forEach(
          (id, who) ->
              b.append("\n  ")
                  .append(id)
                  .append(" <- ")
                  .append(who.size() > 12 ? who.subList(0, 12) + " ..." : who));
      res.add("DIVERGE", b + dump(srv));
    }

    // RECORD: every record opens by name, by latest() from start and cur, and by KeyQuery, from a
    // random instance
    records(srv, inst, p, cur, start);

    // DESTROY-ADVICE, and the message histogram
    synchronized (messages) {
      for (String m : messages) {
        if (!m.toLowerCase(Locale.ROOT).contains("destroy")) continue;
        for (String id : ids) {
          KeyState s = srv.state(id).orElse(null);
          if ((s == KeyState.ACTIVE || sealedKeys.contains(id))
              && Pattern.compile("\\b" + Pattern.quote(id) + "\\b").matcher(m).find())
            res.add(
                "DESTROY-ADVICE",
                p
                    + "a message with 'destroy' names "
                    + (s == KeyState.ACTIVE ? "Active" : "sealing")
                    + " key "
                    + id
                    + ": "
                    + m);
        }
      }
      for (String m : messages) {
        String norm = m.replaceAll("\\bk\\d+\\b", "K").replaceAll("^r\\d+ i\\d+ ", "");
        stat("msg: " + norm.substring(0, Math.min(150, norm.length())));
      }
      messages.clear();
    }

    // RECONCILE
    if (reconciled != null) reconciled(srv, inst, p, reconciled, agreed, start);
  }

  private void records(InMemoryKmipServer srv, List<Kms> inst, String p, String cur, String start) {
    int n = inst.size();
    List<Optional<KeyHandle>> byName = new ArrayList<>();
    List<KeyHandle> fromStart = new ArrayList<>(), fromCur = new ArrayList<>();
    List<String> lookupFail = new ArrayList<>();
    for (int i = 0; i < n; i++) {
      Kms k = inst.get(i);
      byName.add(
          lookup(() -> k.keys().findByName(NAME), lookupFail, "i" + i + " findByName")
              .flatMap(o -> o));
      fromStart.add(
          lookup(() -> k.keys().handle(start).latest(), lookupFail, "i" + i + " latest(start)")
              .orElse(null));
      fromCur.add(
          lookup(() -> k.keys().handle(cur).latest(), lookupFail, "i" + i + " latest(cur)")
              .orElse(null));
    }
    List<Rec> all;
    synchronized (recs) {
      all = new ArrayList<>(recs);
    }
    int bad = 0;
    String firstBad = null;
    for (Rec r : all) {
      int i = checkRnd.nextInt(n);
      Kms k = inst.get(i);
      List<String> failed = new ArrayList<>();
      if (harnessCompromised.contains(r.key())
          && srv.state(r.key()).orElse(null) == KeyState.COMPROMISED) {
        tryOpen(
            failed,
            "allowingCompromised",
            () -> k.keys().handle(r.key()).allowingCompromised().open(r.data(), AAD));
      } else {
        Optional<KeyHandle> bn = byName.get(i);
        KeyHandle ls = fromStart.get(i), lc = fromCur.get(i);
        if (bn.isEmpty()) failed.add("findByName: no key");
        else tryOpen(failed, "findByName " + bn.get().id(), () -> bn.get().open(r.data(), AAD));
        if (ls == null) failed.add("latest(start): failed");
        else tryOpen(failed, "latest(start) " + ls.id(), () -> ls.open(r.data(), AAD));
        if (lc == null) failed.add("latest(cur): failed");
        else tryOpen(failed, "latest(cur) " + lc.id(), () -> lc.open(r.data(), AAD));
        tryOpen(failed, "KeyQuery.name", () -> k.keys().open(KeyQuery.byName(NAME), r.data(), AAD));
      }
      if (!failed.isEmpty()) {
        bad++;
        if (firstBad == null)
          firstBad =
              "record of i"
                  + r.inst()
                  + " ("
                  + r.how()
                  + ", round "
                  + r.round()
                  + ") under "
                  + r.key()
                  + " opened through i"
                  + i
                  + " fails: "
                  + failed;
      }
    }
    stat("record-opens-checked", all.size());
    if (bad > 0) {
      stat("record-opens-failed", bad);
      res.add(
          "RECORD",
          p
              + bad
              + " of "
              + all.size()
              + " records do not open"
              + (lookupFail.isEmpty() ? "" : " (lookups failed: " + lookupFail + ")")
              + "; first: "
              + firstBad
              + dump(srv));
    } else if (!lookupFail.isEmpty()) {
      res.add("RECORD", p + "lookups failed: " + lookupFail + dump(srv));
    }
  }

  private void reconciled(
      InMemoryKmipServer srv,
      List<Kms> inst,
      String p,
      String winner,
      String agreed,
      String start) {
    if (winner.isEmpty()) return; // reported as RECONCILE, LOOP or NONKMS already
    List<String> activeNamed = new ArrayList<>();
    for (String id : srv.ids())
      if (srv.names(id).contains(NAME) && srv.state(id).orElse(null) == KeyState.ACTIVE)
        activeNamed.add(id);
    if (!activeNamed.equals(List.of(winner)))
      res.add(
          "RECONCILE",
          p
              + "Active keys named "
              + NAME
              + ": "
              + activeNamed
              + ", reconcile returned "
              + winner
              + dump(srv));
    if (!winner.equals(agreed))
      res.add(
          "RECONCILE",
          p
              + "findByName and latest() choose "
              + (agreed == null ? "differently (DIVERGE)" : agreed)
              + ", reconcile returned "
              + winner
              + dump(srv));
    Set<String> tree = tree(srv, start);
    tree.addAll(tree(srv, winner));
    List<String> otherActive = new ArrayList<>();
    for (String id : tree)
      if (!id.equals(winner) && srv.state(id).orElse(null) == KeyState.ACTIVE) {
        boolean tip = srv.links(id, LinkKind.REPLACEMENT).isEmpty();
        if (tip || RECONCILE_RETIRES_REPLACED)
          otherActive.add(id + (tip ? " (tip)" : " (replaced)"));
      }
    if (!otherActive.isEmpty())
      res.add(
          "RECONCILE",
          p
              + "keys of the tree still Active after reconcile (winner "
              + winner
              + "): "
              + otherActive
              + dump(srv));
  }

  /** The keys reachable from {@code id} through Replacement or Replaced links, followed either way. */
  private static Set<String> tree(InMemoryKmipServer srv, String id) {
    Map<String, Set<String>> adj = new HashMap<>();
    for (String y : srv.ids())
      for (LinkKind kind : List.of(LinkKind.REPLACEMENT, LinkKind.REPLACED))
        for (String z : srv.links(y, kind)) {
          adj.computeIfAbsent(y, x -> new HashSet<>()).add(z);
          adj.computeIfAbsent(z, x -> new HashSet<>()).add(y);
        }
    Set<String> seen = new TreeSet<>();
    Deque<String> todo = new ArrayDeque<>(List.of(id));
    while (!todo.isEmpty()) {
      String x = todo.pop();
      if (seen.add(x)) todo.addAll(adj.getOrDefault(x, Set.of()));
    }
    return seen;
  }

  private void linkStats(InMemoryKmipServer srv, List<String> ids, String start) {
    long maxRepl = 0, maxRepld = 0, oneSided = 0;
    for (String id : ids) {
      List<String> repl = srv.links(id, LinkKind.REPLACEMENT),
          repld = srv.links(id, LinkKind.REPLACED);
      maxRepl = Math.max(maxRepl, repl.size());
      maxRepld = Math.max(maxRepld, repld.size());
      for (String x : repl) if (!srv.links(x, LinkKind.REPLACED).contains(id)) oneSided++;
      for (String x : repld) if (!srv.links(x, LinkKind.REPLACEMENT).contains(id)) oneSided++;
    }
    long tips =
        tree(srv, start).stream()
            .filter(id -> srv.state(id).orElse(null) == KeyState.ACTIVE)
            .count();
    long named =
        ids.stream()
            .filter(
                id -> srv.names(id).contains(NAME) && srv.state(id).orElse(null) == KeyState.ACTIVE)
            .count();
    statMax("max-REPLACEMENT-links", maxRepl);
    statMax("max-REPLACED-links", maxRepld);
    statMax("max-one-sided-links", oneSided);
    statMax("max-active-in-tree", tips);
    statMax("max-active-named", named);
  }

  // ---- helpers ----

  /** Runs one SDK call, recording its duration; a call over the call timeout plus slack is a DEADLINE problem. */
  private <T> T timed(int round, String what, Supplier<T> call) {
    long t0 = System.nanoTime();
    try {
      return call.get();
    } finally {
      long ms = (System.nanoTime() - t0) / 1_000_000;
      maxCall.accumulateAndGet(ms, Math::max);
      if (ms > cfg.callTimeout().toMillis() + DEADLINE_SLACK_MS)
        res.add(
            "DEADLINE",
            "r"
                + round
                + " "
                + what
                + " took "
                + ms
                + " ms (call timeout "
                + cfg.callTimeout().toMillis()
                + " ms)");
    }
  }

  private String view(Supplier<String> s) {
    try {
      return s.get();
    } catch (KmsException e) {
      return "<" + e.getClass().getSimpleName() + ": " + e.getMessage() + ">";
    } catch (RuntimeException e) {
      res.add("NONKMS", "lookup: non-KMS exception " + e);
      return "<" + e + ">";
    }
  }

  private <T> Optional<T> lookup(Supplier<T> s, List<String> failures, String what) {
    try {
      return Optional.of(s.get());
    } catch (KmsException e) {
      failures.add(what + ": " + e);
      return Optional.empty();
    } catch (RuntimeException e) {
      res.add("NONKMS", what + ": non-KMS exception " + e);
      failures.add(what + ": " + e);
      return Optional.empty();
    }
  }

  private void tryOpen(List<String> failed, String how, Supplier<byte[]> open) {
    try {
      byte[] unused = open.get();
    } catch (KmsException e) {
      failed.add(how + ": " + e);
    } catch (RuntimeException e) {
      res.add("NONKMS", "open " + how + ": non-KMS exception " + e);
      failed.add(how + ": " + e);
    }
  }

  private void note(int round, int me, String how, KmsException e) {
    StringBuilder m =
        new StringBuilder(
            "r"
                + round
                + " i"
                + me
                + " "
                + how
                + ": "
                + e.getClass().getSimpleName()
                + ": "
                + e.getMessage());
    for (Throwable c = e.getCause(); c != null && c != c.getCause(); c = c.getCause())
      m.append(" | cause ")
          .append(c.getClass().getSimpleName())
          .append(": ")
          .append(c.getMessage());
    messages.add(m.toString());
  }

  private void stat(String k) {
    stat(k, 1);
  }

  private void stat(String k, long by) {
    stats.computeIfAbsent(k, x -> new AtomicLong()).addAndGet(by);
  }

  private void statMax(String k, long v) {
    stats.computeIfAbsent(k, x -> new AtomicLong()).accumulateAndGet(v, Math::max);
  }

  static String dump(InMemoryKmipServer s) {
    StringBuilder b = new StringBuilder("\n      store:");
    for (String id : s.ids())
      b.append("\n       ")
          .append(id)
          .append(' ')
          .append(s.state(id).orElse(null))
          .append(" names=")
          .append(s.names(id))
          .append(" repl=")
          .append(s.links(id, LinkKind.REPLACEMENT))
          .append(" repld=")
          .append(s.links(id, LinkKind.REPLACED));
    return b.toString();
  }

  private static String threads() {
    StringBuilder b = new StringBuilder();
    for (var e : Thread.getAllStackTraces().entrySet()) {
      if (!e.getKey().getName().startsWith("storm-")) continue;
      b.append("\n    THREAD ").append(e.getKey().getName());
      StackTraceElement[] st = e.getValue();
      for (int i = 0; i < Math.min(12, st.length); i++) b.append("\n       ").append(st[i]);
    }
    return b.toString();
  }
}
