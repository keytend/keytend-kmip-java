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

import static org.junit.jupiter.api.Assertions.*;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Function;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfSystemProperty;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The {@link StormHarness} (several instances rotating or replacing one key
 * at once, sealing all the while, with HANG and REPLY_LOST faults) must find no problem: concurrent
 * rotations never lose data and never break reading; only reconcile deactivates tips; no advice
 * names a live key for destruction; following advice terminates; deadlines hold; after reconcile one
 * Active named tip remains.
 *
 * <p>The CI matrix below is small and seeded. The long run is opt-in: {@code ./mvnw -o test -pl sdk
 * -Dtest=ConcurrentRotationStormTest -Dkeytend.storm=long} with optional {@code -Dkeytend.storm.seeds=1-3}
 * (or a count), {@code .rounds=5}, {@code .instances=5}, {@code .p=0,0.03,0.10}, {@code
 * .hangShare=0.3}, {@code .callTimeoutMs=700}, {@code .reconcileEvery=0}, {@code .parallel=4}.
 */
class ConcurrentRotationStormTest {
  /**
   * The operator's reconcile, run by the harness after every {@link #RECONCILE_EVERY} rounds and at
   * the end, then checked (one Active named tip, which findByName and latest() choose, no other
   * Active key in its tree). Null skips the reconcile phase.
   */
  static final Function<Kms, KeyHandle> RECONCILE = k -> k.keys().reconcile("vault").orElseThrow();

  static final int RECONCILE_EVERY = 2;
  static final long SEED = 20261027L;

  /**
   * 18 cases: fault rates 0, 0.03 and 0.10 on KMIP 1.4 and 2.1, with and without unique names; the
   * modes, identifier orders and instance counts spread across them; four on a server that
   * refuses a second Re-key; and two of rotations with a grace period of zero. A HANG waits for the call
   * deadline, hence the short call timeout.
   */
  static Stream<Arguments> ciMatrix() {
    String[] modes = {"rotate", "replace", "mixed"};
    String[] ids = {"asc", "rand", "desc"};
    List<Arguments> cases = new ArrayList<>();
    int i = 0;
    for (double p : new double[] {0, 0.03, 0.10})
      for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1))
        for (boolean unique : new boolean[] {false, true}) {
          StormHarness.Config c =
              StormHarness.Config.of(
                      v, unique, 3 + (i / 3) % 3, modes[i % 3], ids[(i / 2) % 3], p, 6, SEED + i)
                  .withCallTimeout(Duration.ofMillis(350))
                  .withSealPause(2)
                  .withReconcile(RECONCILE_EVERY, true);
          cases.add(Arguments.of(c));
          i++;
        }
    // A server that refuses a second Re-key (keytend-kmip-server): rotations never fork, and the
    // losers are
    // told to use latest().
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1))
      for (boolean unique : new boolean[] {false, true}) {
        StormHarness.Config c =
            StormHarness.Config.of(v, unique, 4, modes[i % 3], ids[i % 3], 0.03, 6, SEED + i)
                .withCallTimeout(Duration.ofMillis(350))
                .withSealPause(2)
                .withReconcile(RECONCILE_EVERY, true)
                .withRefuseSecondReKey(true);
        cases.add(Arguments.of(c));
        i++;
      }
    // Rotations with a grace of zero, the old key Deactivated while sealers hold it.
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1)) {
      StormHarness.Config c =
          StormHarness.Config.of(
                  v, v == KmipVersion.V2_1, 4, "grace", ids[i % 3], 0.03, 6, SEED + i)
              .withCallTimeout(Duration.ofMillis(350))
              .withSealPause(2)
              .withReconcile(RECONCILE_EVERY, true);
      cases.add(Arguments.of(c));
      i++;
    }
    return cases.stream();
  }

  @ParameterizedTest(name = "{0}")
  @MethodSource("ciMatrix")
  void storm(StormHarness.Config config) throws InterruptedException {
    StormHarness.Result r = new StormHarness(config, RECONCILE).run();
    System.out.println(r.summary());
    assertEquals(0, r.problems(), r.report());
    assertTrue(r.records > 0, "nothing was sealed: " + r.report());
    if (config.mode().equals("grace")) {
      // The old keys were deactivated under the sealers: a cached handle was refused and followed.
      assertTrue(r.stats.getOrDefault("op-ok-grace", 0L) > 0, r.stats.toString());
      assertTrue(r.stats.getOrDefault("sealer-refresh-stale", 0L) > 0, r.stats.toString());
    }
  }

  /** The full matrix: seeds × fault rates × modes × versions × unique names × identifier orders. */
  @Test
  @EnabledIfSystemProperty(named = "keytend.storm", matches = "long")
  void longStorm() throws Exception {
    List<Long> seeds = seeds(System.getProperty("keytend.storm.seeds", "1"));
    int rounds = Integer.getInteger("keytend.storm.rounds", 5);
    int instances = Integer.getInteger("keytend.storm.instances", 5);
    int parallel = Integer.getInteger("keytend.storm.parallel", 4);
    int every = Integer.getInteger("keytend.storm.reconcileEvery", 0);
    long timeout = Long.getLong("keytend.storm.callTimeoutMs", 700);
    double hang = Double.parseDouble(System.getProperty("keytend.storm.hangShare", "0.3"));
    // false, true, or both (each configuration once with each)
    String refuse = System.getProperty("keytend.storm.refuseSecondReKey", "false");
    List<Boolean> refusing =
        refuse.equals("both") ? List.of(false, true) : List.of(Boolean.parseBoolean(refuse));
    List<Double> ps = new ArrayList<>();
    for (String s : System.getProperty("keytend.storm.p", "0,0.03,0.10").split(","))
      ps.add(Double.parseDouble(s.trim()));
    List<StormHarness.Config> configs = new ArrayList<>();
    for (long seed : seeds)
      for (double p : ps)
        for (String mode : List.of("rotate", "replace", "mixed", "grace"))
          for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1))
            for (boolean unique : new boolean[] {false, true})
              for (String ids : List.of("asc", "desc", "rand"))
                for (boolean r : refusing)
                  configs.add(
                      StormHarness.Config.of(v, unique, instances, mode, ids, p, rounds, seed)
                          .withCallTimeout(Duration.ofMillis(timeout))
                          .withHangShare(hang)
                          .withReconcile(every, true)
                          .withRefuseSecondReKey(r));
    ExecutorService runner = Executors.newFixedThreadPool(parallel);
    try {
      List<Future<StormHarness.Result>> futures = new ArrayList<>();
      for (StormHarness.Config c : configs)
        futures.add(runner.submit(() -> new StormHarness(c, RECONCILE).run()));
      Map<String, Integer> totals = new TreeMap<>();
      List<String> failed = new ArrayList<>();
      int records = 0;
      for (Future<StormHarness.Result> f : futures) {
        StormHarness.Result r = f.get(30, TimeUnit.MINUTES);
        System.out.println(r.problems() > 0 ? r.report() : r.summary());
        records += r.records;
        r.counts.forEach((k, n) -> totals.merge(k, n, Integer::sum));
        if (r.problems() > 0) failed.add(r.report());
      }
      System.out.println(
          "STORM-LONG runs="
              + configs.size()
              + " failing="
              + failed.size()
              + " records="
              + records
              + " problems="
              + totals);
      assertTrue(
          failed.isEmpty(),
          failed.size()
              + " of "
              + configs.size()
              + " runs found problems "
              + totals
              + "\n"
              + String.join("\n", failed.subList(0, Math.min(5, failed.size()))));
    } finally {
      runner.shutdownNow();
    }
  }

  /** "1-3" (a range), "1,5,9" (a list) or "4" (seeds 1 to 4). */
  static List<Long> seeds(String spec) {
    List<Long> out = new ArrayList<>();
    if (spec.contains("-")) {
      String[] a = spec.split("-");
      for (long s = Long.parseLong(a[0].trim()); s <= Long.parseLong(a[1].trim()); s++) out.add(s);
    } else if (spec.contains(",")) {
      for (String s : spec.split(",")) out.add(Long.parseLong(s.trim()));
    } else {
      for (long s = 1; s <= Long.parseLong(spec.trim()); s++) out.add(s);
    }
    return out;
  }
}
