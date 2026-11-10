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

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.LongSupplier;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509ExtendedTrustManager;

/**
 * Follows trust anchors kept in the KMS, and optionally the peer certificates allowed to connect.
 * Its trust manager checks each peer against them from memory. Get one from {@link
 * KmsTls#trustAnchors}.
 *
 * <pre>{@code
 * TlsTrustFollower trust = kms.tls().trustAnchors(
 *     KeyQuery.all().custom(TLS_ROLE, "cluster1:ca"),         // the anchors
 *     KeyQuery.all().custom(TLS_ROLE, "cluster1:identity"),   // who may connect
 *     Duration.ofSeconds(60), scheduler);
 * ssl.init(keyManagers, new TrustManager[] {trust.trustManager()}, null);
 * }</pre>
 *
 * <p>{@code TLS_ROLE} is a {@link CustomAttribute}, {@code scheduler} your {@code
 * ScheduledExecutorService}, {@code ssl} your {@code SSLContext} and {@code keyManagers} your key
 * managers.
 *
 * <p>The trust manager validates the peer's chain against the anchors with the JDK's PKIX trust
 * manager. It does no revocation checking, because revocation is the KMS state. With an
 * allowed-peers query, the peer's own certificate must also be an allowed peer, compared by DER
 * encoding. Only Active certificates the queries match are used, so a certificate revoked,
 * compromised, deactivated or destroyed in the KMS is no longer trusted after the next
 * {@link #refresh()}. A certificate is also trusted only while its lease runs; see {@link
 * #usableFor()}. With no anchors, or after {@link #close()}, every peer is refused. A peer that has
 * just renewed is refused until its new certificate is read; see {@link #unknownPeerCheck(Duration)}
 * and its rate limits.
 *
 * <p>A follower is thread-safe, and by default a handshake never waits for the KMS. Close it at
 * shutdown: {@link #close()} cancels its task, not your executor. See <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/tls-identities.md">TLS
 * identities</a>.
 *
 * @since 0.10.0
 */
public final class TlsTrustFollower implements AutoCloseable {
  /**
   * What a handshake checks against: replaced as a whole when a refresh changes it. {@code
   * fingerprints}: each allowed peer's identifier by its certificate's fingerprint; {@code leases}:
   * each certificate's Lease Time as last read, null for none.
   */
  private record Trust(
      Map<String, X509Certificate> anchors,
      Map<String, X509Certificate> peers,
      Map<String, String> fingerprints,
      X509ExtendedTrustManager pkix,
      Map<String, Duration> leases) {}

  /** A trust manager of the anchors whose leases ran at the time, for {@code trust}. */
  private record Leased(Trust trust, Set<String> anchors, X509ExtendedTrustManager pkix) {}

  /** The default of {@link #unknownPeerCheckPerCertificate(Duration)}. */
  static final Duration PER_CERTIFICATE = Duration.ofSeconds(30);

  /** The default of {@link #unknownPeerCheckGap(Duration)}. */
  static final Duration GAP = Duration.ofSeconds(1);

  /** How many certificates the per-certificate limit remembers (the oldest is forgotten first). */
  static final int REMEMBERED = 1024;

  /** The default of {@link #unknownPeerCheckQueue(int)}. */
  static final int QUEUED = 64;

  /** The default bound on a handshake's wait for a check of an unknown peer. */
  static final Duration CHECK_TIMEOUT = Duration.ofSeconds(2);

  /** Set while this thread checks an unknown peer: a handshake nested in that check is refused. */
  private static final ThreadLocal<Boolean> CHECKING = new ThreadLocal<>();

  private final KmsKeys keys;
  private final KeyQuery anchorsQuery, peersQuery;

  /** One refresh or check at a time; a handshake waits for it with a bound. */
  private final ReentrantLock lock = new ReentrantLock();

  private final List<Runnable> listeners = new CopyOnWriteArrayList<>();
  private final TrustManagerImpl trustManager = new TrustManagerImpl();
  private volatile Trust trust;
  private volatile RuntimeException failure;
  private volatile boolean closed;
  private volatile ScheduledFuture<?> task;
  private volatile ScheduledExecutorService executor;
  private long everyNanos = Long.MAX_VALUE;

  /** The leases of the anchors and allowed peers held; package-private for tests (its clock). */
  final Leases leases = new Leases();

  /** The last trust manager made of the anchors whose leases run, when some do not. */
  private volatile Leased leased;

  /** Guards {@link #renewal}, apart from the lock a refresh holds while it reads the KMS. */
  private final Object plans = new Object();

  /** A refresh planned before the next interval, to renew a lease that ends sooner. */
  private ScheduledFuture<?> renewal;

  /** Due on the lease clock, so a peers-only refresh cannot postpone an earlier renewal. */
  private long renewalDue;

  /** Under the lock: which anchors and allowed peers might be used at the end of the last refresh. */
  private Set<String> usable = Set.of();

  private volatile long checkTimeoutNanos = CHECK_TIMEOUT.toNanos();

  /** {@link #unknownPeerCheckPerCertificate(Duration)}, in nanoseconds. */
  private volatile long perCertificateNanos = PER_CERTIFICATE.toNanos();

  /** {@link #unknownPeerCheckGap(Duration)}, in nanoseconds. */
  private volatile long gapNanos = GAP.toNanos();

  /** {@link #unknownPeerCheckQueue(int)}. */
  private volatile int queueLimit = QUEUED;

  /** Whether a handshake waits for the check of an unknown peer, rather than queue it and refuse. */
  private volatile boolean checkInHandshake;

  /** The fingerprints whose check is queued or running on the executor, by when queued; guarded by itself. */
  private final Map<String, Long> queued = new LinkedHashMap<>();

  /** A queued entry older than this is forgotten (an executor that dropped the task without running it). */
  static final long QUEUED_EXPIRY_NANOS = TimeUnit.SECONDS.toNanos(60);

  /** The clock of the checks' bounds and limits; tests set it. */
  volatile LongSupplier ticker = System::nanoTime;

  /**
   * Under the lock: why the last check of an unknown peer could not read the KMS, or that it passed
   * its timeout while reading it; null when it read the KMS in time.
   */
  private RuntimeException checkFailure;

  /** Under the lock: when the last check of an unknown peer began, and each certificate's last check. */
  private long lastCheck;

  private boolean checkedOnce;
  private final Map<String, Long> checked =
      new LinkedHashMap<>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Long> eldest) {
          return size() > REMEMBERED;
        }
      };

  private TlsTrustFollower(KmsKeys keys, KeyQuery anchors, KeyQuery peers) {
    this.keys = keys;
    this.anchorsQuery = anchors.kind(ObjectKind.CERTIFICATE).state(KeyState.ACTIVE);
    this.peersQuery =
        peers == null ? null : peers.kind(ObjectKind.CERTIFICATE).state(KeyState.ACTIVE);
    this.trust = new Trust(Map.of(), peers == null ? null : Map.of(), Map.of(), null, Map.of());
  }

  static TlsTrustFollower start(
      KmsKeys keys,
      KeyQuery anchors,
      KeyQuery peers,
      Duration every,
      ScheduledExecutorService executor) {
    long nanos = TlsIdentityFollower.interval(every);
    // One call around the first read and what the start decides of it: a start that throws is a
    // FAILED call with what it threw.
    return keys.kms()
        .call(
            "trustAnchors",
            () -> {
              TlsTrustFollower f = new TlsTrustFollower(keys, anchors, peers);
              f.executor = executor;
              f.everyNanos = nanos;
              try {
                f.refresh();
                if (f.failure != null) throw f.failure;
                f.task =
                    executor.scheduleWithFixedDelay(
                        f::refreshQuietly, nanos, nanos, TimeUnit.NANOSECONDS);
                return f;
              } catch (RuntimeException e) {
                // Cancels a renewal the first refresh planned.
                f.close();
                throw e;
              }
            });
  }

  /**
   * The trust manager that checks peers against the current anchors (and allowed peers), the same
   * object each time.
   *
   * @return the trust manager, the same object each time
   * @since 0.10.0
   */
  public X509ExtendedTrustManager trustManager() {
    return trustManager;
  }

  /**
   * The current trust anchors, by identifier: those whose lease runs now.
   *
   * @return the anchors by object identifier, an unmodifiable snapshot of the last successful
   *     refresh, without those whose lease does not run now
   * @since 0.10.0
   */
  public Map<String, X509Certificate> anchors() {
    return leased(trust.anchors);
  }

  /** {@code certificates} without those whose lease does not run now. */
  private Map<String, X509Certificate> leased(Map<String, X509Certificate> certificates) {
    if (leases.usable(certificates.keySet())) return certificates;
    Map<String, X509Certificate> out = new LinkedHashMap<>(certificates);
    out.keySet().removeIf(id -> !leases.usable(id));
    return Collections.unmodifiableMap(out);
  }

  /** Whether {@code fingerprint} is an allowed peer of {@code t} whose lease runs now. */
  private boolean allowedNow(Trust t, String fingerprint) {
    String id = t.fingerprints.get(fingerprint);
    return id != null && leases.usable(id);
  }

  /**
   * The current allowed peers, by identifier; empty when this follower has no allowed-peers query.
   *
   * @return the allowed peers by object identifier, an unmodifiable snapshot without those whose
   *     lease does not run now; empty when there is no allowed-peers query
   * @since 0.10.0
   */
  public Optional<Map<String, X509Certificate>> allowedPeers() {
    Map<String, X509Certificate> peers = trust.peers;
    return peers == null ? Optional.empty() : Optional.of(leased(peers));
  }

  /**
   * Whether {@code chain} is trusted now, as the trust manager accepts a client's, from memory: it
   * validates against the anchors whose leases run (the JDK's PKIX trust manager, no revocation
   * checking: revocation is the KMS state), and, with an allowed-peers query, its first
   * certificate is an allowed peer whose lease runs (compared by DER encoding). For checks that
   * run after the handshake, such as an application's certificate validator or authenticator.
   * Never asks the KMS, and never queues a check: a certificate this follower has not read yet
   * is not allowed (the handshake's check of a peer not allowed yet admits it).
   *
   * @param chain the peer's chain, its own certificate first; null or empty is not trusted
   * @return whether the chain is trusted now; false after {@link #close()}
   * @since 0.10.0
   */
  public boolean allows(X509Certificate[] chain) {
    if (chain == null || chain.length == 0 || closed) return false;
    Trust t = trust;
    if (t.pkix == null) return false;
    try {
      trustManager
          .pkix(t)
          .checkClientTrusted(chain.clone(), chain[0].getPublicKey().getAlgorithm());
    } catch (CertificateException | IllegalArgumentException untrusted) {
      return false;
    }
    return t.peers == null || allowedNow(t, TlsIdentities.fingerprint(chain[0]));
  }

  /**
   * How long what this follower trusts now stays usable without another successful refresh, read
   * from memory. Where the KMS gives an anchor or allowed peer a KMIP Lease Time, each refresh
   * obtains a lease of it. The certificate is trusted only while its lease runs, counted from when
   * Obtain Lease was sent. Under {@link LeasePolicy#HONOR_IF_SUPPORTED}, on a server confirmed not
   * to implement Obtain Lease, a positive stated Lease Time is used as the local bound instead. The
   * trust manager checks the leases at each handshake, with no request.
   * A refused lease ends that certificate's use at once, and the others stay. While the KMS cannot
   * be reached, each lease runs out as granted. A lease that ends before the next interval is
   * renewed early. Once the last anchor's lease has run out, every peer is refused. Use this figure
   * for metrics and alerts, not as an authorization. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/tls-identities.md#leases">Leases</a>.
   *
   * @return empty when no anchor or allowed peer in use has a limited lease (none states a Lease
   *     Time, or the server granted zero); {@link Duration#ZERO} when no anchor may be used now (or
   *     after {@link #close()}); otherwise the time left of the earliest lease
   * @since 0.10.0
   */
  public Optional<Duration> usableFor() {
    Trust t = trust;
    if (closed) return Optional.of(Duration.ZERO);
    Set<String> inUse = new HashSet<>(leased(t.anchors).keySet());
    if (inUse.isEmpty()) return Optional.of(Duration.ZERO);
    if (t.peers != null) inUse.addAll(leased(t.peers).keySet());
    return Leases.usableFor(leases.remaining(inUse));
  }

  /**
   * The failure of the last refresh (a {@link KmsException}, or an {@link IllegalStateException}
   * when the {@link Kms} was closed or the anchors cannot make a trust manager), or of its Obtain
   * Lease; empty when it succeeded.
   *
   * @return the last refresh's failure; empty after a successful refresh
   * @since 0.10.0
   */
  public Optional<RuntimeException> failure() {
    return Optional.ofNullable(failure);
  }

  /**
   * Adds a listener told, on the refreshing thread, of each refresh that changed the anchors or the
   * allowed peers, and, on the executor, of each check of an unknown peer that changed the allowed
   * peers.
   *
   * @param listener the listener; an exception it throws is ignored
   * @return this follower
   * @since 0.10.0
   */
  public TlsTrustFollower onChange(Runnable listener) {
    listeners.add(Objects.requireNonNull(listener, "listener"));
    return this;
  }

  /**
   * Refreshes now, on the caller's thread, one at a time with the scheduled refreshes. A refresh
   * locates the Active certificates each query matches, whatever state and kind the query names.
   * It checks each one against the query itself, since some servers ignore filters on client
   * attributes, and fetches only certificates it has not read before. It then renews the leases.
   * That costs one Locate per query, one batched Get Attributes, one batched Get for new
   * certificates, and one batched Obtain Lease where certificates have a Lease Time. When a refresh
   * fails, what was read before stays in use while its leases run. Never throws for the KMS: see
   * {@link #failure()}.
   *
   * @return whether the anchors or allowed peers changed
   * @since 0.10.0
   */
  public boolean refresh() {
    return refreshed(null);
  }

  /**
   * {@link #refresh()}, giving {@code failed[0]} (unless null) the refresh's {@link #failure},
   * read under the lock.
   */
  private boolean refreshed(RuntimeException[] failed) {
    lock.lock();
    try {
      boolean changed = refresh(keys, false);
      if (failed != null) failed[0] = failure;
      return changed;
    } finally {
      lock.unlock();
      leases.tell(keys.kms().config); // outside the lock, as the KmsListener's other callbacks
    }
  }

  /**
   * Under the lock: reads the anchors (unless {@code peersOnly}) and the allowed peers through
   * {@code via}, and replaces what changed. A check of an unknown peer ({@code peersOnly}) leaves
   * {@link #failure} alone and tells the listeners on the executor, not the handshake's thread.
   */
  private boolean refresh(KmsKeys via, boolean peersOnly) {
    if (closed) return false;
    Trust was = trust;
    Read read =
        via.kms()
            .call(
                "trustAnchors",
                () -> {
                  RuntimeException readFailure = null;
                  Map<String, Duration> times = new LinkedHashMap<>();
                  Map<String, X509Certificate> anchors = was.anchors, peers = was.peers;
                  try {
                    if (!peersOnly) anchors = read(via, anchorsQuery, was.anchors, times);
                    if (peersQuery != null) peers = read(via, peersQuery, was.peers, times);
                    if (peersOnly)
                      for (String id : anchors.keySet()) times.put(id, was.leases.get(id));
                  } catch (KmsException | IllegalStateException e) {
                    if (peersOnly) {
                      checkFailure = e;
                      return null;
                    }
                    // Keeps both sets as they were (also when the anchors were read before the
                    // failure), and renews what it holds, while it may: a lease runs out as
                    // granted when the KMS cannot be read.
                    readFailure = e;
                    anchors = was.anchors;
                    peers = was.peers;
                    times = was.leases;
                  }
                  boolean changed =
                      !anchors.keySet().equals(was.anchors.keySet())
                          || (peers != null && !peers.keySet().equals(was.peers.keySet()));
                  Trust next =
                      changed
                          ? trust(anchors, peers, times)
                          : new Trust(was.anchors, was.peers, was.fingerprints, was.pkix, times);
                  // Within the refresh's (or the check's) deadline. A check asks only for leases
                  // that do not run.
                  Leases.Outcome lease =
                      leases.obtain(via.kms(), peersOnly ? peersOf(next) : times, !peersOnly);
                  return new Read(next, lease, readFailure);
                });
    if (read == null) return false;
    Trust next = read.next();
    Leases.Outcome lease = read.lease();
    RuntimeException readFailure = read.failure();
    leases.retain(next.leases.keySet());
    RuntimeException leaseFailure = lease.refused() != null ? lease.refused() : lease.failed();
    if (peersOnly) checkFailure = leaseFailure;
    else failure = readFailure != null ? readFailure : leaseFailure;
    Set<String> now = new HashSet<>();
    for (String id : next.leases.keySet()) if (leases.usable(id)) now.add(id);
    boolean changed = next.anchors != was.anchors || next.peers != was.peers || !now.equals(usable);
    usable = Set.copyOf(now);
    trust = next;
    plan(peersOnly);
    if (!changed) return false;
    if (peersOnly) {
      ScheduledExecutorService e = executor;
      try {
        if (e != null) {
          e.execute(this::tell);
          return true;
        }
      } catch (RejectedExecutionException shutDown) {
        // told here instead
      }
    }
    tell();
    return true;
  }

  /**
   * What {@link #refresh} read in its call: the trust to hold, the leases obtained, and the failure
   * to read, if any.
   */
  private record Read(Trust next, Leases.Outcome lease, RuntimeException failure) {}

  /** The Lease Times of {@code t}'s allowed peers. */
  private static Map<String, Duration> peersOf(Trust t) {
    Map<String, Duration> out = new LinkedHashMap<>();
    if (t.peers != null) for (String id : t.peers.keySet()) out.put(id, t.leases.get(id));
    return out;
  }

  /**
   * When a lease of an anchor or allowed peer ends (or, not running, may be granted again) before
   * the next interval, plans one refresh at about half the time it has left, at least {@link
   * Leases#FLOOR_NANOS} away.
   */
  private void plan(boolean keepEarlier) {
    synchronized (plans) {
      ScheduledExecutorService e = executor;
      if (closed || e == null) return;
      long delay = leases.renewalDelay(trust.leases.keySet());
      long now = leases.clock.getAsLong();
      if (keepEarlier && renewal != null && !renewal.isDone() && renewalDue - now <= delay) return;
      if (renewal != null) renewal.cancel(false);
      renewal = null;
      if (delay >= everyNanos) return;
      try {
        renewalDue = now + delay;
        renewal = e.schedule(this::refreshQuietly, delay, TimeUnit.NANOSECONDS);
      } catch (RejectedExecutionException shutDown) {
        // The executor is shut down: no renewal, and each lease ends as granted.
      }
    }
  }

  private void tell() {
    for (Runnable l : listeners)
      try {
        // Outside the call: a listener that calls a Kms makes calls of its own.
        Kms.outsideCall(l);
      } catch (RuntimeException ignored) {
        // a listener's failure is its own
      }
  }

  /**
   * Sets how long the check of a peer not allowed yet may wait for the KMS. Such a peer, typically
   * one that has just renewed, has a chain that validates against the anchors and a certificate
   * this follower has not read. The check reads the allowed peers again, as a refresh does, and
   * admits the peer only if its certificate is now an Active one the query matches, leased where it
   * has a Lease Time. By default the handshake is refused at once and the check runs on the
   * executor, so give the follower an executor with a thread to spare. The peer's next handshake is
   * accepted once the check admits it. A check that waited in the queue longer than the timeout is
   * dropped. Whatever stops a check leaves the peer refused until a later check or refresh reads it.
   * A failed check is not a {@link #failure()}.
   *
   * <p>Rate limits bound how often the checks read the KMS, whoever connects: a certificate is
   * checked at most once per {@link #unknownPeerCheckPerCertificate(Duration) interval} (30
   * seconds by default), no check begins within a {@link #unknownPeerCheckGap(Duration) gap} of
   * the end of the last (1 second), and at most {@link #unknownPeerCheckQueue(int) a number of}
   * checks wait in the queue (64).
   *
   * <p>The default is 2 seconds, and the wait is at most the {@link Kms#callTimeout() call
   * timeout} of the {@code Kms}. {@link Duration#ZERO} turns the check off, so such a peer is
   * refused until a refresh reads its certificate.
   *
   * @param timeout the longest wait, not negative; {@link Duration#ZERO} turns the check off
   * @return this follower
   * @throws IllegalArgumentException when {@code timeout} is negative
   * @since 0.10.0
   */
  public TlsTrustFollower unknownPeerCheck(Duration timeout) {
    Objects.requireNonNull(timeout, "timeout");
    if (timeout.isNegative())
      throw new IllegalArgumentException("timeout must not be negative: " + timeout);
    long nanos;
    try {
      nanos = timeout.toNanos();
    } catch (ArithmeticException tooLong) {
      nanos = Long.MAX_VALUE;
    }
    checkTimeoutNanos = nanos;
    return this;
  }

  /**
   * Sets how often the check of a peer not allowed yet ({@link #unknownPeerCheck(Duration)}) may
   * read the KMS for one certificate: a certificate checked less than {@code interval} ago is
   * refused without a check. The default is 30 seconds, so one certificate is checked at most
   * twice a minute. The limit holds for the {@value #REMEMBERED} certificates checked last.
   *
   * <p>{@link Duration#ZERO} lifts this limit, leaving the {@linkplain #unknownPeerCheckGap gap}
   * between checks. A peer refused within the interval is admitted by a later check of another
   * certificate, since each check reads every allowed peer, or by the next refresh.
   *
   * @param interval the least time between two checks of one certificate, not negative
   * @return this follower
   * @throws IllegalArgumentException when {@code interval} is negative
   * @since 0.10.0
   */
  public TlsTrustFollower unknownPeerCheckPerCertificate(Duration interval) {
    perCertificateNanos = nanos(interval, "interval");
    return this;
  }

  /**
   * Sets the least time from the end of one check of a peer not allowed yet ({@link
   * #unknownPeerCheck(Duration)}) to the start of the next, whichever certificates they are for: a
   * check asked for sooner is refused without reading the KMS. 1 second by default, which bounds
   * what any number of different certificates that chain to the anchors cost the KMS to about one
   * check (a Locate, a batched Get Attributes, and a Get of what is new) per second per follower.
   * Each check reads every allowed peer, so a gap delays only the peers renewed after the last
   * check, not all those renewed at once.
   *
   * <p>{@link Duration#ZERO} lifts this limit: checks still run one at a time, each certificate
   * within its {@linkplain #unknownPeerCheckPerCertificate interval}.
   *
   * @param gap the least time between two checks, not negative
   * @return this follower
   * @throws IllegalArgumentException when {@code gap} is negative
   * @since 0.10.0
   */
  public TlsTrustFollower unknownPeerCheckGap(Duration gap) {
    gapNanos = nanos(gap, "gap");
    return this;
  }

  /**
   * Sets how many checks of peers not allowed yet ({@link #unknownPeerCheck(Duration)}) may wait
   * for the follower's executor at a time, one per certificate. A handshake that would queue
   * another is refused without a check. 64 by default: more than the certificates the {@linkplain
   * #unknownPeerCheckGap gap} lets the checks read in a timeout, so a burst of renewed peers is not
   * refused for the queue's sake, while a flood of certificates cannot fill a shared executor.
   * Lowered below the checks already queued, it refuses new ones until enough of those have run or
   * been dropped. It has no effect
   * when the handshake waits for the check ({@link #unknownPeerCheckInHandshake(boolean)}).
   *
   * @param limit the most checks queued at a time, positive
   * @return this follower
   * @throws IllegalArgumentException when {@code limit} is not positive
   * @since 0.10.0
   */
  public TlsTrustFollower unknownPeerCheckQueue(int limit) {
    if (limit < 1) throw new IllegalArgumentException("limit must be positive: " + limit);
    queueLimit = limit;
    return this;
  }

  /** {@code d} in nanoseconds, saturated; IllegalArgumentException when negative. */
  private static long nanos(Duration d, String what) {
    Objects.requireNonNull(d, what);
    if (d.isNegative()) throw new IllegalArgumentException(what + " must not be negative: " + d);
    try {
      return d.toNanos();
    } catch (ArithmeticException tooLong) {
      return Long.MAX_VALUE;
    }
  }

  /** {@code nanos} for a refusal: in whole seconds or milliseconds where it is one. */
  static String human(long nanos) {
    if (nanos % 1_000_000_000L == 0) return nanos / 1_000_000_000L + " s";
    if (nanos % 1_000_000L == 0) return nanos / 1_000_000L + " ms";
    return Duration.ofNanos(nanos).toString();
  }

  /**
   * Sets whether a handshake waits for the check of a peer not allowed yet, described at {@link
   * #unknownPeerCheck(Duration)}. False, the default, refuses the peer at once and runs the check
   * on the follower's executor, so a handshake never waits for the KMS. True makes the handshake
   * wait for the check, at most its timeout, and accept the peer in that same handshake. Use true
   * only where handshakes run on threads that may block, never on an event loop.
   *
   * @param wait whether the handshake waits for the check
   * @return this follower
   * @since 0.10.0
   */
  public TlsTrustFollower unknownPeerCheckInHandshake(boolean wait) {
    checkInHandshake = wait;
    return this;
  }

  /**
   * Queues the check of an unknown peer on the executor, unless one is queued already, the queue
   * is full, checks are off or the executor refuses it; never waits. Says what it did, for the
   * handshake's refusal.
   */
  private String queue(String fingerprint) {
    if (checkTimeoutNanos <= 0) return "the check of unknown peers is off";
    ScheduledExecutorService e = executor;
    if (closed || e == null) return "the KMS trust follower is closed";
    long at = System.nanoTime();
    synchronized (queued) {
      queued.values().removeIf(t -> at - t > QUEUED_EXPIRY_NANOS);
      if (queued.containsKey(fingerprint))
        return "a check of the KMS for it is under way; retry the connection";
      if (queued.size() >= queueLimit) return "too many checks of unknown peers are waiting";
      queued.put(fingerprint, at);
    }
    try {
      e.execute(
          () -> {
            try {
              // A check that waited longer than its own bound is dropped: the peer reconnects and
              // asks again, and a backlog never keeps a shared executor from its refreshes for
              // long.
              if (System.nanoTime() - at <= checkTimeoutNanos) check(fingerprint);
            } catch (RuntimeException | Error ignored) {
              // check never throws for the KMS; anything else leaves the peer refused
            } finally {
              synchronized (queued) {
                queued.remove(fingerprint);
              }
            }
          });
    } catch (RejectedExecutionException refused) {
      synchronized (queued) {
        queued.remove(fingerprint);
      }
      return "the follower's executor refused the check";
    }
    return "a check of the KMS was queued; retry the connection";
  }

  /**
   * Checks the KMS for an unknown peer whose chain validated: null when its certificate is now an
   * allowed peer, else why it is refused. Waits for the lock and the KMS at most the check's
   * timeout; never throws.
   */
  private String check(String fingerprint) {
    long timeout =
        Math.min(
            checkTimeoutNanos,
            Math.min(keys.kms().callTimeout().toNanos(), keys.kms().remainingNanos()));
    if (timeout <= 0) return "the check of unknown peers is off";
    if (CHECKING.get() != null) return "a handshake within a check of the KMS is not checked";
    long deadline = System.nanoTime() + timeout;
    LongSupplier clock = ticker;
    long arrived = clock.getAsLong();
    try {
      if (!lock.tryLock(timeout, TimeUnit.NANOSECONDS))
        return "a refresh of the allowed peers took longer than the check's timeout";
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return "interrupted while waiting to check the KMS";
    }
    try {
      if (closed) return "the KMS trust follower is closed";
      if (deadline - System.nanoTime() <= 0) return "the check's timeout passed while waiting";
      // A refresh or check while this handshake waited may have read it.
      if (allowedNow(trust, fingerprint)) return null;
      long now = clock.getAsLong();
      Long last = checked.get(fingerprint);
      long perCertificate = perCertificateNanos, gap = gapNanos;
      if (last != null && now - last < perCertificate)
        return "it was checked less than " + human(perCertificate) + " ago";
      if (checkedOnce && now - lastCheck < gap)
        return "another unknown peer was checked less than " + human(gap) + " ago";
      long left = timeout - (now - arrived);
      if (left <= 0) return "the check's timeout passed while waiting";
      checked.put(fingerprint, now);
      lastCheck = now;
      checkedOnce = true;
      CHECKING.set(Boolean.TRUE);
      // Background work, FAILED with why the check refuses for the KMS: what kept it from reading
      // the KMS, or its timeout. Both are decided in the call, before it finishes, and the refusal
      // below gives the decision the call reported.
      boolean[] late = {false};
      try {
        checkFailure = null;
        Kms.background(
            deadline,
            "trustAnchors",
            () -> {
              refresh(keys.kms().withTimeout(Duration.ofNanos(left)).keys(), true);
              if (deadline - System.nanoTime() <= 0) {
                late[0] = true;
                checkFailure =
                    new TransientException(
                        "trustAnchors: the check of an unknown peer passed its timeout while"
                            + " reading the KMS",
                        checkFailure,
                        "trustAnchors",
                        null,
                        null,
                        null);
              }
              return checkFailure;
            });
      } catch (RuntimeException e) {
        checkFailure = e;
      } finally {
        CHECKING.remove();
        lastCheck = clock.getAsLong(); // the gap runs from the end of a check, however long it took
      }
      if (late[0]) return "the check's timeout passed while reading the KMS";
      if (allowedNow(trust, fingerprint)) return null;
      RuntimeException e = checkFailure;
      return e == null
          ? "the KMS has no such allowed peer"
          : "the check of the KMS failed: " + e.getMessage();
    } finally {
      lock.unlock();
      leases.tell(keys.kms().config);
    }
  }

  /**
   * A scheduled refresh (or a lease renewal): background work, the call {@code "trustAnchors"},
   * FAILED with the refresh's {@link #failure}.
   */
  private void refreshQuietly() {
    try {
      Kms.background(
          keys.kms().callTimeout(),
          "trustAnchors",
          () -> {
            RuntimeException[] failed = {null};
            refreshed(failed);
            return failed[0];
          });
    } catch (RuntimeException | Error e) {
      // Never ends the schedule.
    }
  }

  /**
   * The certificates {@code query} locates: those of {@code known} kept, the new ones read; each
   * one's Lease Time, as its Get Attributes states it, goes to {@code leaseTimes} (null for none).
   */
  private static Map<String, X509Certificate> read(
      KmsKeys keys,
      KeyQuery query,
      Map<String, X509Certificate> known,
      Map<String, Duration> leaseTimes) {
    List<KeyAttributes> located = TlsIdentities.locatedAttributes(keys, query);
    List<String> ids = located.stream().map(KeyAttributes::id).toList();
    for (KeyAttributes a : located) leaseTimes.put(a.id(), a.leaseToObtain());
    List<String> fresh = ids.stream().filter(id -> !known.containsKey(id)).toList();
    Map<String, X509Certificate> read =
        fresh.isEmpty() ? Map.of() : TlsIdentities.certificates(keys.kms(), fresh);
    Map<String, X509Certificate> out = new LinkedHashMap<>();
    for (String id : ids) {
      X509Certificate c = known.containsKey(id) ? known.get(id) : read.get(id);
      if (c != null) out.put(id, c);
    }
    return Collections.unmodifiableMap(out);
  }

  private static Trust trust(
      Map<String, X509Certificate> anchors,
      Map<String, X509Certificate> peers,
      Map<String, Duration> leases) {
    Map<String, String> fingerprints = new java.util.HashMap<>();
    if (peers != null)
      peers.forEach((id, c) -> fingerprints.putIfAbsent(TlsIdentities.fingerprint(c), id));
    return new Trust(
        anchors, peers, Map.copyOf(fingerprints), anchors.isEmpty() ? null : pkix(anchors), leases);
  }

  /** The JDK's PKIX trust manager for {@code anchors}. */
  private static X509ExtendedTrustManager pkix(Map<String, X509Certificate> anchors) {
    try {
      KeyStore store = KeyStore.getInstance("PKCS12");
      store.load(null, null);
      int i = 0;
      for (X509Certificate a : anchors.values()) store.setCertificateEntry("anchor-" + i++, a);
      TrustManagerFactory factory = TrustManagerFactory.getInstance("PKIX");
      factory.init(store);
      for (TrustManager tm : factory.getTrustManagers())
        if (tm instanceof X509ExtendedTrustManager x) return x;
      throw new IllegalStateException(
          "The JDK's PKIX trust manager factory made no X509ExtendedTrustManager");
    } catch (GeneralSecurityException | java.io.IOException e) {
      throw new IllegalStateException(
          "Cannot make a trust manager of the KMS's trust anchors: " + e.getMessage(), e);
    }
  }

  /**
   * Stops refreshing. It cancels the scheduled task but leaves the executor, which is the
   * caller's. The trust manager refuses every peer from now on. Idempotent.
   *
   * @since 0.10.0
   */
  @Override
  public void close() {
    closed = true;
    ScheduledFuture<?> t = task;
    if (t != null) t.cancel(false);
    synchronized (plans) {
      // A refresh that planned a renewal before this saw closed did so under this monitor.
      if (renewal != null) renewal.cancel(false);
      renewal = null;
    }
  }

  @Override
  public String toString() {
    Trust t = trust;
    return "TlsTrustFollower["
        + t.anchors.size()
        + " anchors"
        + (t.peers == null ? "" : ", " + t.peers.size() + " allowed peers")
        + (failure == null ? "" : ", stale")
        + "]";
  }

  private final class TrustManagerImpl extends X509ExtendedTrustManager {
    private Trust current() throws CertificateException {
      Trust t = trust;
      if (closed) throw new CertificateException("The KMS trust follower is closed");
      if (t.pkix == null)
        throw new CertificateException("The KMS has no Active trust anchor that the query matches");
      return t;
    }

    /**
     * The JDK's PKIX trust manager of {@code t}'s anchors whose leases run now: {@code t}'s own
     * when all do, else one made of those (and kept while they are the same), never one holding an
     * anchor whose lease ran out. No request, and no wait for a refresh.
     */
    private X509ExtendedTrustManager pkix(Trust t) throws CertificateException {
      if (leases.usable(t.anchors.keySet())) return t.pkix;
      Map<String, X509Certificate> anchors = leased(t.anchors);
      if (anchors.isEmpty())
        throw new CertificateException(
            "No trust anchor of the KMS has a lease that runs (KMIP Lease Time)");
      Leased l = leased;
      if (l != null && l.trust == t && l.anchors.equals(anchors.keySet())) return l.pkix;
      try {
        l = new Leased(t, Set.copyOf(anchors.keySet()), TlsTrustFollower.pkix(anchors));
      } catch (IllegalStateException e) {
        throw new CertificateException(e.getMessage(), e);
      }
      leased = l;
      return l.pkix;
    }

    /** After the chain validated: the peer's own certificate is an allowed peer, now or after a check of the KMS. */
    private boolean allowed(Trust t, X509Certificate[] chain) throws CertificateException {
      if (t.peers == null) return false;
      if (chain == null || chain.length == 0)
        throw new CertificateException(
            "The peer presented no certificate, and only allowed peers are accepted");
      String fingerprint = TlsIdentities.fingerprint(chain[0]);
      if (allowedNow(t, fingerprint)) return false;
      boolean wait = checkInHandshake;
      // A check that ended since this handshake read the trust may have admitted it.
      if (!wait && allowedNow(trust, fingerprint)) return true;
      String refused = wait ? check(fingerprint) : queue(fingerprint);
      if (!wait)
        throw new CertificateException(
            "The peer's certificate "
                + chain[0].getSubjectX500Principal()
                + " is not an allowed peer of the KMS"
                + " yet ("
                + refused
                + ")");
      if (refused != null)
        throw new CertificateException(
            "The peer's certificate "
                + chain[0].getSubjectX500Principal()
                + " is not an Active certificate of the KMS"
                + " that the allowed-peers query matches ("
                + refused
                + ")");
      return true;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException {
      Trust t = current();
      pkix(t).checkClientTrusted(chain, authType, socket);
      if (allowed(t, chain)) pkix(current()).checkClientTrusted(chain, authType, socket);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
        throws CertificateException {
      Trust t = current();
      pkix(t).checkServerTrusted(chain, authType, socket);
      if (allowed(t, chain)) pkix(current()).checkServerTrusted(chain, authType, socket);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException {
      Trust t = current();
      pkix(t).checkClientTrusted(chain, authType, engine);
      if (allowed(t, chain)) pkix(current()).checkClientTrusted(chain, authType, engine);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
        throws CertificateException {
      Trust t = current();
      pkix(t).checkServerTrusted(chain, authType, engine);
      if (allowed(t, chain)) pkix(current()).checkServerTrusted(chain, authType, engine);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
      Trust t = current();
      pkix(t).checkClientTrusted(chain, authType);
      if (allowed(t, chain)) pkix(current()).checkClientTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
      Trust t = current();
      pkix(t).checkServerTrusted(chain, authType);
      if (allowed(t, chain)) pkix(current()).checkServerTrusted(chain, authType);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return leased(trust.anchors).values().toArray(X509Certificate[]::new);
    }
  }
}
