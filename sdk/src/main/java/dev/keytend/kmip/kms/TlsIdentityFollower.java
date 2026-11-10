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
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
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
import java.util.function.Consumer;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedKeyManager;

/**
 * Follows a TLS identity in the KMS. Its key manager presents the current private key and
 * certificate chain at each handshake, from memory, so a handshake never waits for the KMS. Get
 * one from {@link KmsTls#follow}.
 *
 * <pre>{@code
 * TlsIdentityFollower identity =
 *     kms.tls().follow("cassandra/node1", Duration.ofSeconds(60), scheduler);
 * ssl.init(new KeyManager[] {identity.keyManager()}, trustManagers, null);
 * }</pre>
 *
 * <p>{@code scheduler} is your {@code ScheduledExecutorService}, {@code ssl} your {@code
 * SSLContext} and {@code trustManagers} your trust managers. Each {@link #refresh()} sets the
 * {@link #status()}, which says what is presented:
 *
 * <ul>
 *   <li>{@link Status#CURRENT}: the current pair.
 *   <li>{@link Status#REPLACING}: the current pair when it is whole, otherwise nothing. A renewal
 *       or re-key is under way.
 *   <li>{@link Status#STALE}: the pair read before while its leases run, otherwise nothing. The
 *       refresh failed.
 *   <li>{@link Status#REVOKED}: nothing. The certificate or key is not Active, or they do not match.
 *   <li>{@link Status#GONE}: nothing. No certificate has the name.
 * </ul>
 *
 * <p>New handshakes are never offered a certificate or key a refresh read as not Active, such as a
 * revoked, compromised or destroyed one, nor a pair whose lease ran out ({@link #usableFor()}). A
 * handshake that chose a pair just before a change may finish with it while its key is Active and
 * neither object is compromised, destroyed or missing. Validity dates are left to peers.
 *
 * <p>A follower is thread-safe. Close it at shutdown: {@link #close()} cancels its task, not your
 * executor, and drops its private keys. See <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/tls-identities.md#follow-it-on-the-node">Follow
 * it on the node</a>.
 *
 * @since 0.10.0
 */
public final class TlsIdentityFollower implements AutoCloseable {
  /**
   * What a follower presents, and why.
   *
   * @since 0.10.0
   */
  public enum Status {
    /** Presenting the identity's current pair, read at the last refresh. */
    CURRENT,
    /**
     * A renewal or re-key is under way (the name is moving, or a newer certificate is linked and not
     * yet Active): presenting the current pair when it is whole, otherwise nothing.
     */
    REPLACING,
    /**
     * The last refresh failed: presenting the pair read before, if any, while its leases run; or a
     * lease of the pair was refused, or ran out without renewal: presenting nothing.
     */
    STALE,
    /**
     * The identity's current certificate or its private key is not Active, or the two do not link
     * to or match each other: presenting nothing.
     */
    REVOKED,
    /** No certificate has the name, and none records it as being moved to it: presenting nothing. */
    GONE
  }

  /**
   * What a refresh found: the status, the pair presented and, when the refresh failed, the
   * failure. Immutable.
   *
   * @since 0.10.0
   */
  public static final class State {
    private final Status status;
    private final TlsIdentity identity;
    private final RuntimeException failure;
    private final String detail;

    State(Status status, TlsIdentity identity, RuntimeException failure, String detail) {
      this.status = status;
      this.identity = identity;
      this.failure = failure;
      this.detail = detail;
    }

    /**
     * Why the pair is presented, or not.
     *
     * @return the status
     * @since 0.10.0
     */
    public Status status() {
      return status;
    }

    /**
     * The pair presented; empty when nothing is.
     *
     * @return the pair presented; empty when nothing is
     * @since 0.10.0
     */
    public Optional<TlsIdentity> identity() {
      return Optional.ofNullable(identity);
    }

    /**
     * The failure of the refresh, for {@link Status#STALE}: a {@link KmsException}, or an {@link
     * IllegalStateException} when the {@link Kms} was closed.
     *
     * @return the refresh's failure; empty unless the status is {@link Status#STALE}
     * @since 0.10.0
     */
    public Optional<RuntimeException> failure() {
      return Optional.ofNullable(failure);
    }

    /**
     * A sentence saying what was found, for logs.
     *
     * @return the sentence
     * @since 0.10.0
     */
    public String detail() {
      return detail;
    }

    @Override
    public String toString() {
      return status + ": " + detail;
    }
  }

  /** A state change a refresh read, told outside the lock. */
  private record Change(String id, KeyState from, KeyState to) {}

  /**
   * A pair as presented: what JSSE gets for its alias; {@code leases}: the Lease Time each of its
   * objects (the chain's certificates and the private key) stated when it was read, null for none.
   */
  private record Presented(
      TlsIdentity identity,
      PrivateKey key,
      X509Certificate[] chain,
      String alias,
      Map<String, Duration> leases) {}

  private final KmsKeys keys;
  private final String name;
  private final Object lock = new Object();
  private final List<Consumer<State>> listeners = new CopyOnWriteArrayList<>();
  private final KeyManager keyManager = new KeyManager();

  /** Certificates read, by identifier (they do not change); guarded by {@link #lock}. */
  private final Map<String, X509Certificate> certificates = new HashMap<>();

  private volatile Presented presented, previous;

  /**
   * The states the last refresh read of the identity's certificate and private key, by identifier,
   * for {@link KmsListener#keyStateChanged}; guarded by {@link #lock}.
   */
  private Map<String, KeyState> watched = Map.of();

  /** The identity's certificate and private key the last {@link #read} found (null: none); guarded by {@link #lock}. */
  private String foundCertificate, foundKey;

  private volatile State state;
  private volatile boolean closed;
  private volatile ScheduledFuture<?> task;

  /** The leases of the objects of the pairs held; package-private for tests (its clock). */
  final Leases leases = new Leases();

  private volatile ScheduledExecutorService executor;
  private long everyNanos = Long.MAX_VALUE;

  /** A refresh planned before the next interval, to renew a lease that ends sooner; guarded by {@link #lock}. */
  private ScheduledFuture<?> renewal;

  /** Why the last refresh could not renew the presented pair's leases; null when it could. */
  private volatile RuntimeException leaseFailure;

  /** Under the lock: whether the last {@link #read} read everything and is stale for a lease only. */
  private boolean leaseOnly;

  /** Told the private key's identifier just before the key signs the pair check; tests set it. */
  volatile Consumer<String> signing = id -> {};

  private TlsIdentityFollower(KmsKeys keys, String name) {
    this.keys = keys;
    this.name = name;
  }

  /**
   * {@link KmsTls#follow}: one call, {@code "follow"}, around the first read and what the start
   * decides of it, so that a start that throws is a FAILED call with what it threw.
   */
  static TlsIdentityFollower start(
      KmsKeys keys, String name, Duration every, ScheduledExecutorService executor) {
    long nanos = interval(every);
    return keys.kms().call("follow", () -> start(keys, name, nanos, executor));
  }

  private static TlsIdentityFollower start(
      KmsKeys keys, String name, long nanos, ScheduledExecutorService executor) {
    TlsIdentityFollower f = new TlsIdentityFollower(keys, name);
    f.executor = executor;
    f.everyNanos = nanos;
    try {
      State first = f.refresh();
      if (first.status == Status.STALE) throw first.failure;
      if (f.presented == null) {
        if (first.status == Status.GONE)
          throw new NotFoundException("follow: " + first.detail, null, "follow", null, null, null);
        throw new StateConflictException(
            "follow: " + first.detail, null, "follow", null, null, null);
      }
      f.task =
          executor.scheduleWithFixedDelay(f::refreshQuietly, nanos, nanos, TimeUnit.NANOSECONDS);
      return f;
    } catch (RuntimeException e) {
      // Cancels a renewal the first refresh planned, and drops what it read.
      f.close();
      throw e;
    }
  }

  static long interval(Duration every) {
    Objects.requireNonNull(every, "refreshEvery");
    if (every.isZero() || every.isNegative())
      throw new IllegalArgumentException("refreshEvery must be positive: " + every);
    try {
      return every.toNanos();
    } catch (ArithmeticException tooLong) {
      return Long.MAX_VALUE;
    }
  }

  /**
   * The identity's name.
   *
   * @return the name
   * @since 0.10.0
   */
  public String name() {
    return name;
  }

  /**
   * The key manager that presents the current pair, the same object each time. It offers one alias
   * at a time, the presented pair's, for client and server handshakes of the pair's key type
   * ("RSA" or "EC"), whatever issuers the peer asks for; the certificate chain and private key of
   * an alias are always those of one pair. With no pair presented (or after {@link #close()}) it
   * offers none, and the handshake fails: a server cannot complete it, and a client sends no
   * certificate.
   *
   * @return the key manager, the same object each time
   * @since 0.10.0
   */
  public X509ExtendedKeyManager keyManager() {
    return keyManager;
  }

  /**
   * The pair presented now; empty when nothing is. Its {@link TlsIdentity#certificate()}'s {@code
   * getNotAfter()} is when the presented leaf expires, for a metric or an alert (read from memory).
   *
   * @return the pair presented now; empty when nothing is
   * @since 0.10.0
   */
  public Optional<TlsIdentity> identity() {
    Presented p = presented;
    return p == null || !leased(p) ? Optional.empty() : Optional.of(p.identity);
  }

  /**
   * What the last refresh found; once the lease of an object of the pair it presents has run out
   * since, {@link Status#STALE} presenting nothing, with the failure of the last renewal (or a
   * {@link TransientException} when no refresh tried in time).
   *
   * @return the last refresh's state
   * @since 0.10.0
   */
  public State state() {
    State s = state;
    Presented p = presented;
    if (s == null || s.identity == null || p == null || !p.identity.equals(s.identity) || leased(p))
      return s;
    String detail =
        name
            + ": the lease of "
            + p.identity
            + " ran out before a refresh renewed it; presenting nothing";
    RuntimeException why = leaseFailure;
    return new State(
        Status.STALE, null, why != null ? why : new TransientException(detail), detail);
  }

  /**
   * How long the pair presented now stays usable without another successful refresh, read from
   * memory. Where the KMS gives the pair's objects a KMIP Lease Time, each refresh obtains a lease
   * of the private key and each certificate of the chain. The pair is presented only while every
   * lease runs, counted from when Obtain Lease was sent. Under {@link
   * LeasePolicy#HONOR_IF_SUPPORTED}, on a server confirmed not to implement Obtain Lease, a
   * positive stated Lease Time is used as that object's local bound instead. The key manager checks
   * the leases at each handshake, so a pair stops when a lease ends even if no refresh runs. A
   * refused lease stops the pair at once. A lease that ends before the next interval is renewed
   * early. A new pair's private key is neither fetched nor used without a lease or that bound. Use
   * this figure for metrics and alerts, not as an authorization. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/tls-identities.md#leases">Leases</a>.
   *
   * @return empty when no lease limits the pair: none of its objects states a Lease Time, or the
   *     server granted zero. {@link Duration#ZERO} when nothing is presented, or after {@link
   *     #close()}. Otherwise the time left of the earliest lease.
   * @since 0.10.0
   */
  public Optional<Duration> usableFor() {
    Presented p = presented;
    if (p == null || closed) return Optional.of(Duration.ZERO);
    return Leases.usableFor(leases.remaining(p.leases.keySet()));
  }

  /** Whether every object of {@code p} may be used now: a map lookup and a clock read, no request, no lock. */
  private boolean leased(Presented p) {
    return leases.usable(p.leases.keySet());
  }

  /**
   * {@code state().status()}.
   *
   * @return the status of {@link #state()}
   * @since 0.10.0
   */
  public Status status() {
    return state().status;
  }

  /**
   * Adds a listener told of each refresh that changed the pair presented or the status. Listeners
   * run on the refreshing thread, one at a time. They must not wait for another thread that
   * refreshes this follower. After them, the {@link Kms}'s {@link KmsListener#keyStateChanged}
   * hears of each state change a refresh read of the identity's certificate or private key. A
   * lease is not a state change.
   *
   * @param listener the listener; an exception it throws is ignored
   * @return this follower
   * @since 0.10.0
   */
  public TlsIdentityFollower onChange(Consumer<State> listener) {
    listeners.add(Objects.requireNonNull(listener, "listener"));
    return this;
  }

  /**
   * Refreshes now, on the caller's thread, one at a time with the scheduled refreshes. A refresh
   * reads what the name leads to, renews the pair's leases and sets the {@link Status}. So a pair
   * the KMS revokes stops being presented within one interval, plus the time a refresh takes, while
   * the KMS can be reached. A new pair is presented only once its key is shown to match its
   * certificate. A renewal or re-key that runs to its end while a refresh reads deactivates what
   * the refresh read; the refresh then reads again and presents the new pair, up to four reads
   * while each finds a newer certificate. A private key without Sign in its usage mask, or with
   * Usage Limits, is refused before it is fetched: {@link Status#STALE} with an {@link
   * UnsupportedException}. A renewal whose
   * new pair cannot be loaded presents nothing until the next successful refresh. A refresh that
   * finds nothing new costs one Locate and one batched Get Attributes, plus one batched Obtain Lease
   * when the objects have a Lease Time. Never throws for the KMS: a failure is {@link Status#STALE}.
   *
   * @return what it found
   * @since 0.10.0
   */
  public State refresh() {
    List<Change> changes = new ArrayList<>();
    State next;
    synchronized (lock) {
      if (closed) return state;
      State was = state;
      Reads read = new Reads();
      next = keys.kms().call("follow", () -> read(read));
      // Retaining an alias for an in-flight handshake never retains material known unsafe.
      if (read.unusable(previous) || read.nonActiveSigningKey(previous)) previous = null;
      Presented p = presented, q = previous;
      Set<String> held = new HashSet<>();
      if (p != null) held.addAll(p.leases.keySet());
      if (q != null) held.addAll(q.leases.keySet());
      leases.retain(held);
      plan(p);
      observe(read, next.status != Status.STALE || leaseOnly, changes);
      state = next;
      if (was == null || was.status != next.status || !Objects.equals(was.identity, next.identity))
        for (Consumer<State> l : listeners)
          try {
            // Outside the call: a listener that calls a Kms makes calls of its own.
            Kms.outsideCall(() -> l.accept(next));
          } catch (RuntimeException ignored) {
            // a listener's failure is its own
          }
    }
    // Outside the lock, as the KmsListener's other callbacks.
    leases.tell(keys.kms().config);
    for (Change c : changes) keys.kms().keyStateChanged(c.id, c.from, c.to);
    return next;
  }

  /**
   * Adds to {@code changes} each certificate or private key watched whose state {@code read} has
   * changed, then watches the identity's certificate and key as this refresh found them ({@code
   * whole}: it did not fail part-way; otherwise the ones watched stay, with the states read).
   */
  private void observe(Reads read, boolean whole, List<Change> changes) {
    Map<String, KeyState> next = new HashMap<>();
    for (Map.Entry<String, KeyState> w : watched.entrySet()) {
      KeyState state = read.stateOf(w.getKey());
      if (state != null && state != w.getValue())
        changes.add(new Change(w.getKey(), w.getValue(), state));
      if (!whole) next.put(w.getKey(), state != null ? state : w.getValue());
    }
    if (whole)
      for (String id : new String[] {foundCertificate, foundKey}) {
        KeyState state = id == null ? null : read.stateOf(id);
        if (state != null) next.put(id, state);
      }
    watched = next;
  }

  /**
   * A scheduled refresh (or a lease renewal): background work, the call {@code "follow"}, FAILED
   * with the failure of a refresh that found the follower {@link Status#STALE}.
   */
  private void refreshQuietly() {
    try {
      Kms.background(
          keys.kms().callTimeout(),
          "follow",
          () -> {
            State s = refresh();
            return s != null && s.status == Status.STALE ? s.failure : null;
          });
    } catch (RuntimeException | Error e) {
      // Never ends the schedule: the next interval tries again.
    }
  }

  /**
   * Under the lock: when a lease of {@code p} ends (or, not running, may be granted again) before
   * the next interval, plans one refresh at about half the time it has left, at least {@link
   * Leases#FLOOR_NANOS} away. The previous pair's leases are not renewed: it is kept for in-flight
   * handshakes only, until they run out.
   */
  private void plan(Presented p) {
    if (renewal != null) renewal.cancel(false);
    renewal = null;
    ScheduledExecutorService e = executor;
    if (closed || p == null || e == null) return;
    long delay = leases.renewalDelay(p.leases.keySet());
    if (delay >= everyNanos) return;
    try {
      renewal = e.schedule(this::refreshQuietly, delay, TimeUnit.NANOSECONDS);
    } catch (RejectedExecutionException shutDown) {
      // The executor is shut down: no renewal, and each lease ends as granted.
    }
  }

  /**
   * Under the lock: renews the leases of {@code p}'s objects (their Lease Time as {@code read} now
   * states it, else as read with the pair), so that it may be presented.
   */
  private Leases.Outcome lease(Presented p, Map<String, KeyAttributes> read) {
    Map<String, Duration> times = new LinkedHashMap<>();
    for (Map.Entry<String, Duration> e : p.leases.entrySet()) {
      KeyAttributes a = read.get(e.getKey());
      times.put(e.getKey(), a != null ? a.leaseToObtain() : e.getValue());
    }
    Leases.Outcome outcome = leases.obtain(keys.kms(), times, true);
    leaseFailure = outcome.refused() != null ? outcome.refused() : outcome.failed();
    return outcome;
  }

  /**
   * Presents {@code p} once its leases are renewed ({@code loaded}: it was just loaded, under leases
   * {@link #load} obtained), with the state {@code ok} when they run: what a refresh that found
   * {@code p} ends with.
   */
  private State presentLeased(
      Presented p, Map<String, KeyAttributes> read, boolean loaded, State ok) {
    Leases.Outcome lease = loaded ? Leases.Outcome.OK : lease(p, read);
    if (loaded) leaseFailure = null;
    leaseOnly = true;
    if (lease.refused() != null) {
      // The server will not lease it: drop it, as material it says is not to be used.
      present(null);
      return new State(
          Status.STALE,
          null,
          lease.refused(),
          name
              + ": the KMS refused a lease of "
              + p.identity
              + " ("
              + lease.refused().getMessage()
              + "); presenting nothing");
    }
    present(p);
    if (!leased(p)) {
      RuntimeException why =
          lease.failed() != null
              ? lease.failed()
              : new TransientException(name + ": no lease of " + p.identity + " runs");
      return new State(
          Status.STALE,
          null,
          why,
          name
              + ": no lease of "
              + p.identity
              + " runs ("
              + why.getMessage()
              + "); presenting nothing until one is granted");
    }
    if (lease.failed() != null)
      return new State(
          Status.STALE,
          p.identity,
          lease.failed(),
          name
              + ": cannot renew the lease of "
              + p.identity
              + " ("
              + lease.failed().getMessage()
              + "); presenting it until its lease runs out");
    return ok;
  }

  /** The most reads of what the name leads to that one refresh makes ({@link #read(Reads, int, String)}). */
  static final int READS = 4;

  /** One refresh's reads (kept in {@code read}) and decision; sets {@link #presented}. */
  private State read(Reads read) {
    return read(read, 1, null);
  }

  /**
   * {@link #read(Reads)}, the {@code n}th read of this refresh; {@code superseded}: the certificate
   * the read before found Deactivated (null for the first read). A renewal or re-key that ran to
   * its end during a read has deactivated what the read found: between its read of the certificate
   * and of its key, or before the key's loader reads the key's attributes again (then read again
   * only when the certificate, read once more, names a replacement). It linked the old certificate
   * to the new one before activating the new pair, so another read finds the new pair.
   * The refresh reads again while each read finds a newer certificate than the read before, at
   * most {@link #READS} reads: a pair deactivated without a replacement is read twice, and
   * renewals that keep running to their end during each read leave the last read's outcome.
   */
  private State read(Reads read, int n, String superseded) {
    Presented before = presented;
    leaseOnly = false;
    foundCertificate = null;
    foundKey = null;
    try {
      List<String> hint =
          before == null
              ? List.of()
              : List.of(before.identity.certificateId(), before.identity.privateKeyId());
      Optional<TlsIdentities.Found> found =
          TlsIdentities.find(
              keys, name, hint, before == null ? null : before.identity.certificateId(), read);
      if (found.isEmpty()) {
        present(null);
        return new State(
            Status.GONE,
            null,
            null,
            "no certificate has the name " + name + ", and none records it as being moved to it");
      }
      TlsIdentities.Found f = found.get();
      KeyAttributes leaf = f.current();
      KeyAttributes key = TlsIdentities.keyOf(keys, leaf, f.read);
      foundCertificate = leaf.id();
      foundKey = key == null ? null : key.id();
      if (key != null && read.signingRefusals.containsKey(key.id()))
        throw read.signingRefusals.get(key.id());
      String unusable =
          leaf.state() != KeyState.ACTIVE
              ? "certificate " + leaf.id() + " is " + leaf.state()
              : key == null
                  ? "no private key links to certificate " + leaf.id() + " and back"
                  : key.state() != KeyState.ACTIVE
                      ? "private key " + key.id() + " is " + key.state()
                      : null;
      String replacing =
          f.replacing() ? "; a replacement is under way (" + f.newest().id() + ")" : "";
      boolean again = n < READS && !leaf.id().equals(superseded);
      if (unusable != null
          && again
          && (leaf.state() == KeyState.DEACTIVATED
              || (key != null && key.state() == KeyState.DEACTIVATED))) {
        read.clear();
        return read(read, n + 1, leaf.id());
      }
      if (unusable != null) {
        present(null);
        return new State(
            f.replacing() ? Status.REPLACING : Status.REVOKED,
            null,
            null,
            name + ": " + unusable + replacing);
      }
      Presented p;
      boolean held =
          before != null
              && before.identity.certificateId().equals(leaf.id())
              && before.identity.privateKeyId().equals(key.id());
      try {
        p = held ? before : load(leaf, key, f.read);
      } catch (KeyMismatchException | IllegalArgumentException notAPair) {
        // The linked key is of another type or size than the certificate's, or the certificate's
        // key is of an algorithm TLS identities do not take: not a pair.
        p = null;
      } catch (StateConflictException refused) {
        // The loader read the key (or the certificate) Deactivated after discovery read it Active.
        // When a newer certificate replaces the leaf, a re-key ran to its end meanwhile: read
        // again. Otherwise (deactivated, not replaced) the refusal is the refresh's failure.
        boolean deactivated =
            refused.observedState().orElse(null) == KeyState.DEACTIVATED
                && refused
                    .objectId()
                    .map(id -> id.equals(leaf.id()) || id.equals(key.id()))
                    .orElse(false);
        if (!again || !deactivated || !replaced(leaf.id())) throw refused;
        read.refused(refused);
        read.clear();
        return read(read, n + 1, leaf.id());
      }
      if (p == null) {
        present(null);
        return new State(
            Status.REVOKED,
            null,
            null,
            name
                + ": the private key "
                + key.id()
                + " is not the one certificate "
                + leaf.id()
                + " is for");
      }
      if (read.unusable(p)) {
        present(null);
        return new State(
            Status.REVOKED,
            null,
            null,
            name + ": this refresh found the pair missing, compromised or destroyed");
      }
      return presentLeased(
          p,
          read,
          !held,
          new State(
              f.replacing() ? Status.REPLACING : Status.CURRENT,
              p.identity,
              null,
              name + ": " + p.identity + replacing));
    } catch (KmsException | IllegalStateException e) {
      // Material loaders read state again after discovery; their refusal is evidence too.
      read.refused(e);
      // Keeps the pair, unless this refresh found its certificate or key missing or unsafe
      // before failing. A pair this refresh read as non-Active cannot sign behind a failed
      // replacement.
      if (read.unusable(before) || read.nonActive(before)) present(null);
      Presented kept = presented;
      if (kept != null) {
        // Renewed while it may be: a lease runs out as granted when the KMS cannot be reached.
        Leases.Outcome lease = lease(kept, read);
        if (lease.refused() != null) present(null);
        kept = presented;
        if (kept != null && !leased(kept))
          return new State(
              Status.STALE,
              null,
              e,
              name
                  + ": cannot read the identity ("
                  + e.getMessage()
                  + "); no lease of "
                  + kept.identity
                  + " runs; presenting nothing");
      }
      return new State(
          Status.STALE,
          kept == null ? null : kept.identity,
          e,
          name
              + ": cannot read the identity ("
              + e.getMessage()
              + ")"
              + (kept == null
                  ? "; presenting nothing"
                  : "; presenting " + kept.identity + " as before"));
    }
  }

  /**
   * Whether the certificate {@code id}, read now (one Get Attributes), names a replacement; false
   * when it cannot be read.
   */
  private boolean replaced(String id) {
    try {
      return keys.read(id).map(a -> !a.links(LinkKind.REPLACEMENT).isEmpty()).orElse(false);
    } catch (KmsException | IllegalStateException unread) {
      return false;
    }
  }

  private static boolean unsafe(KeyState state) {
    return state == KeyState.COMPROMISED
        || state == KeyState.DESTROYED
        || state == KeyState.DESTROYED_COMPROMISED;
  }

  /** A fresh lookup cache; observed state restrictions, absences and signing refusals survive {@code clear()}. */
  private static final class Reads extends HashMap<String, KeyAttributes> {
    final Map<String, KeyState> unsafe = new HashMap<>();
    final Set<String> missing = new HashSet<>();
    final Set<String> inactive = new HashSet<>();
    final Map<String, UnsupportedException> signingRefusals = new HashMap<>();

    @Override
    public KeyAttributes put(String id, KeyAttributes attributes) {
      if (attributes == null) missing.add(id);
      else if (TlsIdentityFollower.unsafe(attributes.state())) unsafe.put(id, attributes.state());
      if (attributes != null && attributes.state() != KeyState.ACTIVE) inactive.add(id);
      if (attributes != null && attributes.kind() == ObjectKind.PRIVATE_KEY) {
        UnsupportedException refusal = TlsIdentities.signingRefusal(attributes, "follow");
        if (refusal != null) signingRefusals.put(id, refusal);
      }
      return super.put(id, attributes);
    }

    @Override
    public void putAll(Map<? extends String, ? extends KeyAttributes> attributes) {
      attributes.forEach(this::put);
    }

    void refused(RuntimeException failure) {
      if (failure instanceof NotFoundException gone) gone.objectId().ifPresent(missing::add);
      if (failure instanceof StateConflictException conflict) {
        KeyState state = conflict.observedState().orElse(null);
        if (TlsIdentityFollower.unsafe(state))
          conflict.objectId().ifPresent(id -> unsafe.put(id, state));
        if (state != null && state != KeyState.ACTIVE) conflict.objectId().ifPresent(inactive::add);
      }
    }

    KeyState stateOf(String id) {
      KeyState state = unsafe.get(id);
      KeyAttributes attributes = get(id);
      return state != null ? state : attributes == null ? null : attributes.state();
    }

    boolean unusable(Presented pair) {
      return pair != null
          && (unusable(pair.identity.certificateId())
              || unusable(pair.identity.privateKeyId())
              || signingRefusals.containsKey(pair.identity.privateKeyId()));
    }

    boolean nonActive(Presented pair) {
      return pair != null
          && (inactive.contains(pair.identity.certificateId())
              || inactive.contains(pair.identity.privateKeyId()));
    }

    boolean nonActiveSigningKey(Presented pair) {
      return pair != null && inactive.contains(pair.identity.privateKeyId());
    }

    private boolean unusable(String id) {
      return unsafe.containsKey(id) || missing.contains(id);
    }
  }

  /**
   * The pair {@code leaf} and {@code key} name, read; null when the key does not match. Every object
   * of the pair is leased before any of it is fetched, and the leases still run when the private
   * key first signs (the pair check is a use of the key, KMIP 1.4 §3.20): a refusal, or no lease
   * running, is thrown, and nothing is fetched or signed.
   */
  private Presented load(KeyAttributes leaf, KeyAttributes key, Map<String, KeyAttributes> read) {
    UnsupportedException refusal = TlsIdentities.signingRefusal(key, "follow");
    if (refusal != null) throw refusal;
    // The chain's certificates (by their attributes, nothing fetched yet) and the key.
    List<String> chainIds = TlsIdentities.chainIds(keys, leaf, read);
    Map<String, Duration> leaseTimes = new LinkedHashMap<>();
    for (String id : chainIds) {
      KeyAttributes a = read.get(id);
      leaseTimes.put(id, a == null ? null : a.leaseToObtain());
    }
    leaseTimes.put(key.id(), key.leaseToObtain());
    Leases.Outcome lease = leases.obtain(keys.kms(), leaseTimes, true);
    leaseFailure = lease.refused() != null ? lease.refused() : lease.failed();
    if (lease.refused() != null) throw lease.refused();
    requireLeased(leaseTimes.keySet(), lease, leaf.id());
    X509Certificate certificate = TlsIdentities.cached(keys.kms(), certificates, leaf.id());
    List<X509Certificate> chain = TlsIdentities.chain(keys, leaf, certificate, certificates, read);
    PrivateKey privateKey =
        keys.handle(key.id())
            .asPrivateKey(
                TlsIdentities.expect(certificate.getPublicKey()),
                a -> {
                  read.put(a.id(), a);
                  TlsIdentities.requireActiveSigningKey(a, "follow");
                  UnsupportedException restricted = TlsIdentities.signingRefusal(a, "follow");
                  if (restricted != null) throw restricted;
                  Map<String, Duration> time = new LinkedHashMap<>();
                  time.put(a.id(), a.leaseToObtain());
                  Leases.Outcome checked = leases.obtain(keys.kms(), time, false);
                  if (checked.refused() != null) throw checked.refused();
                  requireLeased(time.keySet(), checked, leaf.id());
                  leaseTimes.put(a.id(), a.leaseToObtain());
                });
    // Only this chain's certificates stay cached.
    certificates.values().retainAll(chain);
    requireLeased(leaseTimes.keySet(), lease, leaf.id());
    signing.accept(key.id());
    if (!TlsIdentities.matches(privateKey, certificate.getPublicKey())) return null;
    TlsIdentity identity = new TlsIdentity(name, leaf.id(), key.id(), chain);
    // The certificates chain() followed, as far as it went, and the key.
    Map<String, Duration> held = new LinkedHashMap<>();
    for (String id : chainIds.subList(0, chain.size())) held.put(id, leaseTimes.get(id));
    held.put(key.id(), leaseTimes.get(key.id()));
    return new Presented(
        identity,
        privateKey,
        chain.toArray(X509Certificate[]::new),
        leaf.id() + "/" + key.id(),
        java.util.Collections.unmodifiableMap(held));
  }

  /** Throws why the leases of {@code ids} do not all run now: the Obtain Lease failure, else their end. */
  private void requireLeased(java.util.Collection<String> ids, Leases.Outcome lease, String leaf) {
    if (leases.usable(ids)) return;
    if (lease.failed() != null) throw lease.failed();
    throw new TransientException(
        name
            + ": the lease of the pair of certificate "
            + leaf
            + " ran out before it could be used");
  }

  private void present(Presented p) {
    if (p == presented) return;
    previous = p == null ? null : presented;
    presented = p;
  }

  /**
   * Stops refreshing and presenting. It cancels the scheduled task but leaves the executor, which
   * is the caller's. The key manager offers no alias from now on, and the follower drops the
   * private keys it holds. A JDK {@link PrivateKey} cannot be wiped, and neither are the bytes it
   * was decoded from. Native TLS providers that copy the key keep their own copy. Idempotent.
   *
   * @since 0.10.0
   */
  @Override
  public void close() {
    closed = true;
    ScheduledFuture<?> t = task;
    if (t != null) t.cancel(false);
    synchronized (lock) {
      // A refresh that planned a renewal before this saw closed holds the lock until it has.
      if (renewal != null) renewal.cancel(false);
      renewal = null;
      presented = null;
      previous = null;
      leases.clear();
    }
  }

  @Override
  public String toString() {
    return "TlsIdentityFollower[" + name + ", " + state + "]";
  }

  /** Presents {@link #presented}, and finds the pair of an alias it gave out just before a change. */
  private final class KeyManager extends X509ExtendedKeyManager {
    private String choose(String... keyTypes) {
      Presented p = presented;
      if (p == null || closed || !leased(p)) return null;
      String algorithm = p.key.getAlgorithm();
      for (String t : keyTypes)
        if (t != null && (t.equals(algorithm) || t.startsWith(algorithm + "_"))) return p.alias;
      return null;
    }

    private Presented find(String alias) {
      if (alias == null || closed) return null;
      Presented p = presented, q = previous;
      // Each alias's own objects' leases, checked at each use: an alias whose lease ran out (or
      // was refused) is never served, whatever another alias holds.
      if (p != null && p.alias.equals(alias)) return leased(p) ? p : null;
      if (q != null && q.alias.equals(alias)) return leased(q) ? q : null;
      return null;
    }

    @Override
    public String[] getClientAliases(String keyType, Principal[] issuers) {
      String a = choose(keyType);
      return a == null ? null : new String[] {a};
    }

    @Override
    public String chooseClientAlias(String[] keyType, Principal[] issuers, Socket socket) {
      return keyType == null ? null : choose(keyType);
    }

    @Override
    public String chooseEngineClientAlias(String[] keyType, Principal[] issuers, SSLEngine engine) {
      return keyType == null ? null : choose(keyType);
    }

    @Override
    public String[] getServerAliases(String keyType, Principal[] issuers) {
      return getClientAliases(keyType, issuers);
    }

    @Override
    public String chooseServerAlias(String keyType, Principal[] issuers, Socket socket) {
      return choose(keyType);
    }

    @Override
    public String chooseEngineServerAlias(String keyType, Principal[] issuers, SSLEngine engine) {
      return choose(keyType);
    }

    @Override
    public X509Certificate[] getCertificateChain(String alias) {
      Presented p = find(alias);
      return p == null ? null : p.chain.clone();
    }

    @Override
    public PrivateKey getPrivateKey(String alias) {
      Presented p = find(alias);
      return p == null ? null : p.key;
    }
  }
}
