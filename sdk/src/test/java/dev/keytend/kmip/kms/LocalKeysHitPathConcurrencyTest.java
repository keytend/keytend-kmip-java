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

import static dev.keytend.kmip.kms.LocalKeysTest.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import java.net.SocketTimeoutException;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import java.util.function.*;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The hit path takes no shared lock: {@code forEncrypt()}, {@code forAppend(id)} and
 * {@code forDecrypt(id)} hits copy the key optimistically. Explicit invalidation, the TTL, the
 * lease and the protection deadline still bound every handout, a hit's reservation still keeps
 * its slot, and the capacity counts return to idle. First single-threaded interleavings, placed by
 * the injectable ticker and clock at the exact reads that matter; then many threads hitting while
 * another ends what they hit.
 */
class LocalKeysHitPathConcurrencyTest {
  private static final List<KmipVersion> VERSIONS =
      List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0);
  private static final Instant START = Instant.parse("2026-10-29T12:00:00Z");

  /**
   * The hit paths, the method that reads the tick their validity check uses, and where their first
   * tick after the reservation (the sweep's; for the write slot by ID, the check's own) is read.
   */
  enum Path {
    DECRYPT("hit", "sweep", "hit"),
    ENCRYPT_BY_ID("hit", "sweep", "hit"),
    WRITE("access", "sweep", "access"),
    WRITE_BY_ID("writeHit", "writeHit");
    final String reader;
    final String[] reserved;

    Path(String reader, String... reserved) {
      this.reader = reader;
      this.reserved = reserved;
    }
  }

  /** The LocalKeys methods on the calling thread's stack, innermost first. */
  static List<String> frames() {
    return StackWalker.getInstance()
        .walk(
            s ->
                s.filter(f -> f.getClassName().equals(LocalKeys.class.getName()))
                    .map(StackWalker.StackFrame::getMethodName)
                    .toList());
  }

  /**
   * Runs an action once, on the calling thread, at the first tick (or instant) that LocalKeys reads
   * from the given frames, innermost first (null: any). The value returned is read before the
   * action, unless {@code fresh}: so the action happens between the read and what the cache does
   * with it, as another thread's would.
   */
  static final class Hook {
    private volatile List<String> at;
    private volatile Runnable action;
    private volatile boolean fresh;

    void arm(Runnable action, boolean fresh, String... at) {
      this.at = at.length == 0 ? null : List.of(at);
      this.fresh = fresh;
      this.action = action;
    }

    /** The current value, after running the armed action when this read is its place. */
    <T> T read(Supplier<T> current) {
      T value = current.get();
      Runnable armed = action;
      if (armed == null) return value;
      List<String> where = at, stack = frames();
      if (where != null
          && (stack.size() < where.size() || !stack.subList(0, where.size()).equals(where)))
        return value;
      action = null;
      armed.run();
      return fresh ? current.get() : value;
    }

    boolean fired() {
      return action == null;
    }
  }

  static final class HookClock extends Clock {
    volatile Instant now = START;
    final Hook hook = new Hook();

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return hook.read(() -> now);
    }
  }

  /** A cache over a write key, an unnamed key that encrypts by ID and a historical key. */
  static final class Setup implements AutoCloseable {
    final Fixture f;
    final KeyHandle write, other, history;
    final List<KeyHandle> extra = new ArrayList<>();
    final Hook ticks = new Hook();
    final HookClock clock = new HookClock();
    final Map<String, byte[]> material = new ConcurrentHashMap<>();
    final AtomicReference<Instant> stop = new AtomicReference<>();
    final Set<String> denied = ConcurrentHashMap.newKeySet();
    final LocalKeys cache;

    Setup(KmipVersion version, int capacity, Duration lease, int extraKeys) {
      f = new Fixture(version);
      if (lease != null) f.server.leaseTime(lease);
      write = f.key();
      other = f.key(256, "orders", null, KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
      history = f.key(256, "orders", null, KeyUsage.DECRYPT);
      for (int i = 0; i < extraKeys; i++) extra.add(f.key(256, "orders", null, KeyUsage.DECRYPT));
      for (KeyHandle k : keys())
        try (DestroyableSecretKey key = k.asSecretKey(Expect.aes(256), LocalUse.DECRYPT)) {
          material.put(k.id(), key.getEncoded());
        }
      f.before.set(
          r -> {
            String target =
                is(r, Operation.GET_ATTRIBUTES)
                        || is(r, Operation.OBTAIN_LEASE)
                        || is(r, Operation.GET)
                    ? id(r)
                    : null;
            if (target != null && denied.contains(target))
              throw new PermissionDeniedException("Access to " + target + " removed");
          });
      // A Protect Stop Date on the keys that encrypt, when set, injected into their attributes.
      f.after.set(
          (request, reply) ->
              stop.get() == null || !is(request, Operation.GET_ATTRIBUTES)
                  ? reply
                  : KeyPolicyTest.rewrite(
                      reply,
                      node -> {
                        if (node.tag() != Tag.RESPONSE_PAYLOAD.code()) return node;
                        String target =
                            node.child(Tag.UNIQUE_IDENTIFIER).map(Ttlv::textValue).orElse("");
                        if (!target.equals(write.id()) && !target.equals(other.id())) return node;
                        Ttlv date = Ttlv.dateTime(Tag.PROTECT_STOP_DATE, stop.get());
                        List<Ttlv> fields = new ArrayList<>(node.children());
                        Optional<Ttlv> modern = node.child(Tag.ATTRIBUTES);
                        if (modern.isPresent()) {
                          List<Ttlv> attributes = new ArrayList<>(modern.get().children());
                          attributes.add(date);
                          fields.set(
                              fields.indexOf(modern.get()),
                              Ttlv.structure(Tag.ATTRIBUTES, attributes));
                        } else fields.add(Attributes.attribute("Protect Stop Date", date));
                        return Ttlv.structure(Tag.RESPONSE_PAYLOAD, fields);
                      }));
      LocalKeys.Builder builder = f.builder().capacity(capacity);
      builder.ticker = () -> ticks.read(f.time::get);
      builder.clock = clock;
      cache = f.keep(builder.open());
    }

    List<KeyHandle> keys() {
      List<KeyHandle> all = new ArrayList<>(List.of(write, other, history));
      all.addAll(extra);
      return all;
    }

    String target(Path path) {
      return switch (path) {
        case DECRYPT -> history.id();
        case ENCRYPT_BY_ID -> other.id();
        case WRITE, WRITE_BY_ID -> write.id();
      };
    }

    LocalKeys.Use use(Path path) {
      return switch (path) {
        case DECRYPT -> cache.forDecrypt(history.id());
        case ENCRYPT_BY_ID -> cache.forAppend(other.id());
        case WRITE -> cache.forEncrypt();
        case WRITE_BY_ID -> cache.forAppend(write.id());
      };
    }

    /** Takes a use of {@code path} and checks it is the whole key of the expected identifier. */
    String check(Path path) {
      try (LocalKeys.Use use = use(path)) {
        assertEquals(target(path), use.id());
        assertArrayEquals(
            material.get(use.id()), use.key().getEncoded(), "a whole copy of the key");
        return use.id();
      }
    }

    void warm() {
      for (Path path : Path.values()) check(path);
    }

    @Override
    public void close() {
      f.close();
    }
  }

  static Stream<Arguments> pathsAndVersions() {
    return VERSIONS.stream()
        .flatMap(v -> Arrays.stream(Path.values()).map(p -> Arguments.of(v, p)));
  }

  /**
   * An invalidation between a hit's reservation and its copy, or between the copy and the
   * handout, cancels the hit: the copy is not handed out and nothing is loaded again (the write
   * selection by ID makes a validation of its own, which the server refuses here).
   */
  @ParameterizedTest
  @MethodSource("pathsAndVersions")
  void anInvalidationRacingAHitCancelsIt(KmipVersion version, Path path) {
    for (boolean inCopy : new boolean[] {false, true})
      try (Setup s = new Setup(version, 64, null, 0)) {
        s.warm();
        String target = s.target(path);
        s.ticks.arm(
            () -> {
              s.denied.add(target);
              s.cache.invalidate(target);
            },
            false,
            inCopy ? new String[] {"copy"} : path.reserved);
        int exchanges = s.f.server.exchanges();
        KmsException failure = assertThrows(KmsException.class, () -> s.check(path));
        assertTrue(s.ticks.fired());
        if (path == Path.WRITE_BY_ID) assertInstanceOf(PermissionDeniedException.class, failure);
        else {
          assertInstanceOf(TransientException.class, failure);
          assertTrue(failure.getMessage().contains("invalidated"), failure.toString());
          assertEquals(exchanges, s.f.server.exchanges(), "the canceled call loads nothing");
        }
        assertIdle(s);
      }
  }

  enum Bound {
    TTL,
    LEASE,
    PROTECTION
  }

  static Stream<Arguments> boundsAndPaths() {
    return VERSIONS.stream()
        .flatMap(
            v ->
                Arrays.stream(Bound.values())
                    .flatMap(
                        b ->
                            Arrays.stream(Path.values())
                                .filter(
                                    p ->
                                        b != Bound.PROTECTION
                                            || p
                                                != Path
                                                    .DECRYPT) // Decrypt copies have no protection
                                // deadline.
                                .map(p -> Arguments.of(v, b, p))));
  }

  /**
   * The TTL, the lease or the protection deadline passes after the hit's validity check and
   * before its copy, with the KMS unreachable: the copy is checked again and not handed out.
   */
  @ParameterizedTest
  @MethodSource("boundsAndPaths")
  void aBoundPassingBetweenTheCheckAndTheCopyStopsTheHandout(
      KmipVersion version, Bound bound, Path path) {
    try (Setup s = new Setup(version, 64, bound == Bound.LEASE ? Duration.ofSeconds(4) : null, 0)) {
      if (bound == Bound.PROTECTION) s.stop.set(START.plusSeconds(7));
      s.warm();
      Runnable pass =
          () -> {
            s.f.server.unreachable(true);
            switch (bound) {
              case TTL -> s.f.advance(TTL.toSeconds());
              case LEASE -> s.f.advance(4);
              case PROTECTION -> s.clock.now = START.plusSeconds(7);
            }
          };
      // The tick (or instant) the hit's own check reads, before the copy.
      if (bound == Bound.PROTECTION) s.clock.hook.arm(pass, false, "valid", path.reader);
      else s.ticks.arm(pass, false, path.reader);
      assertThrows(KmsException.class, () -> s.check(path));
      assertTrue(bound == Bound.PROTECTION ? s.clock.hook.fired() : s.ticks.fired());
      assertIdle(s);
    }
  }

  /**
   * A hit that reserved its slot before the ID was refused, and resumes after the refusal's TTL and
   * a new validation published a fresh copy in the same slot, is told of the refusal: what it
   * reserved was displaced, so it neither takes the newer copy nor loads.
   */
  @ParameterizedTest
  @EnumSource(
      value = Path.class,
      names = {"DECRYPT", "ENCRYPT_BY_ID"})
  void aHitDisplacedByARefusalIsToldOfItEvenAfterARevalidation(Path path) {
    for (KmipVersion version : VERSIONS)
      try (Setup s = new Setup(version, 64, null, 0)) {
        s.warm();
        String target = s.target(path);
        Path other = path == Path.DECRYPT ? null : Path.DECRYPT;
        s.ticks.arm(
            () -> {
              // Another purpose's validation of the same ID is refused: every copy of the ID goes.
              s.denied.add(target);
              assertThrows(
                  PermissionDeniedException.class,
                  () -> {
                    if (other == null) s.cache.forAppend(target).close();
                    else s.cache.forDecrypt(target).close();
                  });
              s.denied.remove(target);
              s.f.advance(TTL.toSeconds() + 1);
              assertEquals(target, s.check(path)); // A later call revalidates into the same slot.
            },
            false,
            "sweep",
            "hit");
        assertThrows(PermissionDeniedException.class, () -> s.check(path));
        assertTrue(s.ticks.fired());
        assertEquals(target, s.check(path));
        assertIdle(s);
      }
  }

  /**
   * The write selection is invalidated after a call's displacement check, and its copy then fails
   * its protection deadline: the call reports the invalidation without selecting again.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anInvalidationFoundUnderTheSlotLockIsReportedNotLoaded(KmipVersion version) {
    try (Setup s = new Setup(version, 64, null, 0)) {
      s.stop.set(START.plusSeconds(7));
      s.warm();
      s.clock.hook.arm(
          () -> {
            s.cache.invalidate(s.write.id());
            s.clock.now = START.plusSeconds(7);
          },
          true,
          "valid",
          "access");
      int exchanges = s.f.server.exchanges();
      TransientException failure =
          assertThrows(TransientException.class, () -> s.check(Path.WRITE));
      assertTrue(failure.getMessage().contains("invalidated"), failure.toString());
      assertEquals(exchanges, s.f.server.exchanges(), "no selection after the invalidation");
    }
  }

  enum Event {
    INVALIDATE,
    TTL,
    LEASE,
    PROTECTION,
    CAPACITY
  }

  static Stream<Arguments> eventsAndVersions() {
    return VERSIONS.stream()
        .flatMap(v -> Arrays.stream(Event.values()).map(e -> Arguments.of(v, e)));
  }

  /**
   * Eight threads hit every path while this thread, round after round, invalidates one key, lets
   * the TTL or the lease pass in an outage, passes the protection deadline, or fills the capacity
   * with other keys. A call begun after the event never hands out what it ended; every copy is
   * the whole key; afterwards no slot stays reserved, no call waits and no admission remains.
   */
  @ParameterizedTest
  @MethodSource("eventsAndVersions")
  void hitsOnManyThreadsNeverOutliveWhatEndsThem(KmipVersion version, Event event)
      throws Exception {
    int capacity = event == Event.CAPACITY ? 6 : 64; // Five historical slots under pressure.
    try (Setup s =
        new Setup(
            version,
            capacity,
            event == Event.LEASE ? Duration.ofSeconds(4) : null,
            event == Event.CAPACITY ? 8 : 0)) {
      if (event == Event.PROTECTION) s.stop.set(START.plusSeconds(7));
      int threads = 8, rounds = 12;
      ExecutorService pool = Executors.newFixedThreadPool(threads);
      List<String> problems = new CopyOnWriteArrayList<>();
      AtomicInteger checkedAfter = new AtomicInteger();
      try {
        for (int round = 0; round < rounds; round++) {
          s.warm();
          Set<Path> affected = EnumSet.noneOf(Path.class);
          String target = null;
          switch (event) {
            case INVALIDATE -> {
              Path chosen = List.of(Path.DECRYPT, Path.ENCRYPT_BY_ID, Path.WRITE).get(round % 3);
              target = s.target(chosen);
              for (Path p : Path.values()) if (s.target(p).equals(target)) affected.add(p);
            }
            case TTL, LEASE -> affected.addAll(EnumSet.allOf(Path.class));
            case PROTECTION ->
                affected.addAll(EnumSet.of(Path.ENCRYPT_BY_ID, Path.WRITE, Path.WRITE_BY_ID));
            case CAPACITY -> {}
          }
          AtomicBoolean running = new AtomicBoolean(true),
              begun = new AtomicBoolean(),
              ended = new AtomicBoolean();
          CountDownLatch started = new CountDownLatch(threads);
          List<Future<?>> hitting = new ArrayList<>();
          for (int t = 0; t < threads; t++) {
            int seed = round * threads + t;
            hitting.add(
                pool.submit(
                    () -> {
                      Random random = new Random(seed);
                      started.countDown();
                      while (running.get()) {
                        Path path = Path.values()[random.nextInt(Path.values().length)];
                        boolean after = ended.get();
                        try {
                          s.check(path);
                          if (after && affected.contains(path))
                            problems.add(event + " round: " + path + " handed out after the event");
                        } catch (TransientException e) {
                          boolean deadline =
                              event == Event.CAPACITY
                                  && e.getCause() instanceof SocketTimeoutException;
                          if (!deadline && !(affected.contains(path) && begun.get()))
                            problems.add(path + ": " + e);
                          if (after) checkedAfter.incrementAndGet();
                        } catch (KmsException e) {
                          if (!(affected.contains(path) && begun.get()))
                            problems.add(path + ": " + e);
                          if (after) checkedAfter.incrementAndGet();
                        } catch (Throwable e) {
                          problems.add(path + ": " + e);
                        }
                      }
                    }));
          }
          started.await();
          Thread.sleep(10);
          begun.set(true);
          switch (event) {
            case INVALIDATE -> {
              s.denied.add(target); // So that nothing can be authorized again.
              s.cache.invalidate(target);
            }
            case TTL -> {
              s.f.server.unreachable(true);
              s.f.advance(TTL.toSeconds());
            }
            case LEASE -> {
              s.f.server.unreachable(true);
              s.f.advance(4);
            }
            case PROTECTION -> s.clock.now = s.stop.get();
            case CAPACITY -> {
              long until = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(30);
              while (System.nanoTime() < until)
                for (KeyHandle k : s.extra)
                  try (LocalKeys.Use u = s.cache.forDecrypt(k.id())) {
                    assertArrayEquals(s.material.get(k.id()), u.key().getEncoded());
                  } catch (TransientException e) {
                    if (!(e.getCause() instanceof SocketTimeoutException))
                      problems.add("pressure: " + e);
                  }
            }
          }
          ended.set(true);
          Thread.sleep(10);
          running.set(false);
          for (Future<?> h : hitting) h.get(30, TimeUnit.SECONDS);
          assertEquals(List.of(), problems, version + " " + event + " round " + round);
          assertIdle(s);
          // Restore: what the round ended is authorized again.
          s.denied.clear();
          s.f.server.unreachable(false);
          if (event == Event.PROTECTION) s.stop.set(s.clock.now.plusSeconds(7));
          s.cache.invalidateAll();
        }
      } finally {
        pool.shutdownNow();
      }
      if (event != Event.CAPACITY)
        assertTrue(checkedAfter.get() > 0, "calls began after the events");
    }
  }

  /** No slot reserved, no capacity waiter, no admission, retention within capacity. */
  @SuppressWarnings("unchecked")
  static void assertIdle(Setup s) {
    try {
      assertEquals(0, s.cache.capacityWaiters());
      for (Object slot : ((Map<?, ?>) field(s.cache, "reads")).values())
        assertEquals(
            0, ((AtomicInteger) field(slot, "pins")).get(), "a retained slot stays reserved");
      synchronized (field(s.cache, "admissionLock")) {
        assertEquals(Map.of(), Map.copyOf((Map<String, Object>) field(s.cache, "admissions")));
      }
    } catch (ReflectiveOperationException e) {
      throw new AssertionError(e);
    }
  }

  private static Object field(Object owner, String name) throws ReflectiveOperationException {
    var field = owner.getClass().getDeclaredField(name);
    field.setAccessible(true);
    return field.get(owner);
  }
}
