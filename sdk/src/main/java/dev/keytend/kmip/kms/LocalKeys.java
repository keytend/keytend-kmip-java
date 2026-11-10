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

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.github.benmanes.caffeine.cache.Policy;
import com.github.benmanes.caffeine.cache.RemovalCause;
import dev.keytend.kmip.client.Request;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.transport.CallContext;
import java.io.InterruptedIOException;
import java.net.SocketTimeoutException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicLongFieldUpdater;
import java.util.concurrent.atomic.LongAdder;
import java.util.concurrent.locks.StampedLock;
import java.util.function.BiConsumer;
import java.util.function.LongSupplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Raw symmetric keys taken out of the KMS for local encryption and for decrypting older data,
 * cached with a hard TTL and refreshed ahead of expiry. External tools own the keys' lifecycle:
 * this cache never creates, rotates, deactivates or destroys a server object. Get one from {@link
 * KmsKeys#localKeys(String)}, from {@link #builder(KmsConfig, String)} for a cache that owns its
 * connection, or from {@link #sharedKms(KmsConfig)} for the caches of several key families that
 * share one.
 *
 * <pre>{@code
 * try (LocalKeys keys = kms.keys().localKeys("orders-write")
 *     .scope(KeyQuery.all().custom(CustomAttribute.client("family"), "orders"))
 *     .expect(Expect.aes(256)).ttl(Duration.ofMinutes(5)).open()) {
 *   try (LocalKeys.Use use = keys.forEncrypt()) {
 *     // Initialize the local cipher with use.key(); store use.id() with the encrypted data.
 *   }
 *   try (LocalKeys.Use use = keys.forDecrypt(storedId)) {
 *     // Initialize the decrypting cipher with this exact key.
 *   }
 * }
 * }</pre>
 *
 * <p>{@code storedId} is the key identifier stored with the data. {@link #forEncrypt()} selects
 * the write key by name. {@link #forDecrypt(String)} reads the exact key recorded with older data,
 * within the configured {@link Builder#scope(KeyQuery) scope}, so the moving write name never
 * authorizes old data. Under the default {@link LeasePolicy#REQUIRE}, a key that states a KMIP
 * Lease Time is handed out only under a lease the server granted. {@link
 * LeasePolicy#HONOR_IF_SUPPORTED} uses the stated Lease Time as a local bound instead, on a server
 * confirmed not to implement Obtain Lease (see {@link Use}).
 *
 * <p>A {@code LocalKeys} is thread-safe. Share one instance per configuration, write name, scope
 * and policy on each node, across tables. Node credentials must not be able to modify the
 * scope's attributes or groups. The cache owns its retained copies, and each {@link Use} owns a
 * separate copy. Close a cache from {@code kms.keys()} before that {@code Kms}. A cache from
 * {@link #builder(KmsConfig, String)} closes its own connection; one from a {@link SharedKms} leaves
 * it to the others. See <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/local-keys.md">Local
 * keys</a>.
 *
 * @since 0.10.0
 */
public final class LocalKeys implements AutoCloseable {
  /**
   * Configures a cache that owns a lazily connected KMS. Neither this method nor {@link
   * Builder#open()} sends a request. The first key use connects, once for all identifiers and
   * purposes, and a failed connection gets the cache's short backoff ({@link Builder#ttl}).
   * Connecting, configured connect retries and key validation share one call timeout. So a longer
   * wait at startup needs both a long enough call timeout and connect-retry window. Closing the
   * cache cancels connecting and closes any connection it opened.
   *
   * @param config immutable connection configuration; not null
   * @param writeKeyName the external write-name selector; not null or empty
   * @return a builder; scope and expectation are required
   * @throws IllegalArgumentException when the name is empty
   * @since 0.10.0
   */
  public static Builder builder(KmsConfig config, String writeKeyName) {
    return new Builder(
        new Connection(Objects.requireNonNull(config, "config")), true, writeKeyName);
  }

  /**
   * One lazily connected KMS for the caches of several key families: their first key use
   * connects, once for all of them, as {@link #builder(KmsConfig, String)} does for one cache.
   * Sends no request. Build each cache with {@link SharedKms#localKeys(String)}.
   *
   * <pre>{@code
   * try (LocalKeys.SharedKms shared = LocalKeys.sharedKms(config);
   *     LocalKeys orders = shared.localKeys("orders-write")
   *         .scope(KeyQuery.all().custom(CustomAttribute.client("family"), "orders"))
   *         .expect(Expect.aes(256)).open();
   *     LocalKeys users = shared.localKeys("users-write")
   *         .scope(KeyQuery.all().custom(CustomAttribute.client("family"), "users"))
   *         .expect(Expect.aes(256)).open()) {
   *   // Both caches use one Kms, connected at the first key use of either.
   * }
   * }</pre>
   *
   * @param config immutable connection configuration; not null
   * @return the shared KMS, not yet connected, owned by the caller
   * @since 0.10.0
   */
  public static SharedKms sharedKms(KmsConfig config) {
    return new SharedKms(new Connection(Objects.requireNonNull(config, "config")));
  }

  /**
   * A lazily connected KMS shared by the {@code LocalKeys} caches of several key families ({@link
   * #sharedKms(KmsConfig)}). The first key use of any of its caches connects, once for all of
   * them; concurrent first uses share that attempt, within the deadline of the call that started
   * it. After a failed attempt, each cache waits its own backoff ({@link Builder#ttl}) before it
   * starts another, and fails fast meanwhile. {@link LocalKeys#invalidate} and {@link
   * LocalKeys#invalidateAll()} on any of them clear that backoff for all.
   *
   * <p>Thread-safe. Closing a cache leaves the KMS to the others. Close the caches before this,
   * as for a {@code Kms} of your own: closing it cancels a connection attempt in progress and
   * closes the connections, and the caches' later calls throw {@link IllegalStateException}.
   *
   * @since 0.10.0
   */
  public static final class SharedKms implements AutoCloseable {
    private final Connection connection;

    private SharedKms(Connection connection) {
      this.connection = connection;
    }

    /**
     * Configures a cache that uses this KMS. Neither this method nor {@link Builder#open()} sends a
     * request.
     *
     * @param writeKeyName the external write-name selector; not null or empty
     * @return a builder; scope and expectation are required
     * @throws IllegalArgumentException when the name is empty
     * @throws IllegalStateException when this is closed
     */
    public Builder localKeys(String writeKeyName) {
      connection.ensureOpen();
      return new Builder(connection, false, writeKeyName);
    }

    /**
     * The connections of each configured endpoint, as {@link Kms#connectionStats()} reports them
     * once connected; before, every endpoint with nothing opened. For connection metrics: the
     * Micrometer and OpenTelemetry modules' {@code connections(SharedKms)} read it. From memory, no
     * request; also after {@link #close()}.
     *
     * @return one entry per configured endpoint, in configured order; unmodifiable
     * @since 0.10.0
     */
    public List<Kms.ConnectionStats> connectionStats() {
      return connection.connectionStats();
    }

    /**
     * Cancels a connection attempt in progress and closes the KMS's connections; idempotent. The
     * caches built from this are not closed: close them first.
     */
    @Override
    public void close() {
      connection.close("Shared KMS closed");
    }

    /** The configuration's endpoints are not named: only whether it is connected or closed. */
    @Override
    public String toString() {
      return "LocalKeys.SharedKms[" + connection.state() + "]";
    }
  }

  /**
   * The lazily connected KMS of {@link #builder(KmsConfig, String)} (one cache owns it) or of a
   * {@link SharedKms} (its caches share it): one connection attempt at a time, its failure and
   * when it happened, and the KMS once connected. Guarded by its own monitor, a leaf lock.
   */
  private static final class Connection {
    final KmsConfig config;
    private CompletableFuture<Kms> connecting;
    private CallContext context;
    private RuntimeException failure;
    private boolean failureDefinite;
    private long failedAt;
    private volatile Kms kms;
    private volatile boolean closed;
    private String closedWhy;

    Connection(KmsConfig config) {
      this.config = config;
    }

    boolean closed() {
      return closed;
    }

    void ensureOpen() {
      if (closed)
        synchronized (this) {
          throw new IllegalStateException(closedWhy);
        }
    }

    synchronized void clearFailure() {
      failure = null;
    }

    /** The KMS's connections once connected; before, every endpoint with nothing opened. */
    List<Kms.ConnectionStats> connectionStats() {
      Kms ready = kms;
      return ready != null ? ready.connectionStats() : Kms.unconnectedStats(config);
    }

    synchronized String state() {
      return closed
          ? "closed"
          : kms != null ? "connected" : connecting != null ? "connecting" : "not connected";
    }

    /** Cancels an attempt in progress and closes the KMS; idempotent. */
    void close(String why) {
      CallContext cancel;
      Kms ready;
      synchronized (this) {
        if (closed) return;
        closed = true;
        closedWhy = why;
        cancel = context;
        ready = kms;
        if (connecting != null) connecting.completeExceptionally(new IllegalStateException(why));
      }
      if (cancel != null) cancel.cancel();
      if (ready != null) ready.close();
    }
  }

  /**
   * Configures one cache. Builders are not thread-safe; each open creates an independent cache.
   * @since 0.10.0
   */
  public static final class Builder {
    private final KmsKeys keys;
    private final Connection connection; // null for a cache of a caller's Kms
    private final boolean ownsConnection;
    private final String name;
    private KeyQuery scope;
    private Expect expect;
    private Duration ttl = Duration.ofMinutes(5), refreshAfter;
    private int capacity = 64;
    private Executor executor;
    private boolean compromisedForDecrypt;
    LongSupplier ticker = System::nanoTime;
    Clock clock = Clock.systemUTC();

    /** Tests: told each retained copy's identifier and own bytes, to check when they are wiped. */
    BiConsumer<String, byte[]> retained = (id, key) -> {};

    Builder(KmsKeys keys, String name) {
      this.keys = keys;
      this.connection = null;
      this.ownsConnection = false;
      this.name = Objects.requireNonNull(name, "writeKeyName");
      if (name.isEmpty()) throw new IllegalArgumentException("Empty write key name");
    }

    private Builder(Connection connection, boolean owns, String name) {
      this.keys = null;
      this.connection = connection;
      this.ownsConnection = owns;
      this.name = Objects.requireNonNull(name, "writeKeyName");
      if (name.isEmpty()) throw new IllegalArgumentException("Empty write key name");
    }

    /**
     * Sets the required stable scope, checked locally on every load as well as in Locate.
     * It must include a group, custom attribute or explicit ID set, and cannot include a name
     * or state: those change during rotation. Use a custom attribute where KMIP 3.0 is enabled.
     *
     * @param value the scope; not null
     * @return this builder
     * @throws IllegalArgumentException when the scope lacks an identity boundary or contains name/state
     */
    public Builder scope(KeyQuery value) {
      Objects.requireNonNull(value, "scope");
      if (value.name != null
          || value.state != null
          || (value.group == null && value.custom.isEmpty() && value.ids == null))
        throw new IllegalArgumentException(
            "Local key scope needs a stable group, custom attribute or ID set, without name/state");
      scope = value;
      return this;
    }

    /**
     * Sets the required algorithm/size expectation for all retrieved keys.
     *
     * @param value the expectation; not null
     * @return this builder
     */
    public Builder expect(Expect value) {
      expect = Objects.requireNonNull(value, "expect");
      return this;
    }

    /**
     * Sets the hard authorization TTL (default five minutes). A copy is handed out only within
     * the TTL of its validation, whose age starts before the validation's first request. Hits do
     * not extend it.
     *
     * <p>At expiry a caller waits, within its call deadline, for a running refresh, or loads the
     * key itself. Through an outage a value is kept only until its TTL, its lease end or, for
     * encryption, its protection deadline. A definite refusal invalidates the affected copies at
     * once, also another purpose's copy of the same identifier. Validation sends Get Attributes
     * and Get, so removing Get permission is seen even if attributes stay readable. Changed
     * material for a retained identifier is refused. Expired material is wiped lazily, on a later
     * access or at close, and never handed out.
     *
     * <p>After a transient failure, new validations wait {@code min(1 second, ttl / 8)}. During
     * that backoff a cold or expired use fails fast with a {@link TransientException}, and a valid
     * entry stays usable until its TTL. The backoff never renews authorization. A definite refusal
     * of an exact identifier is remembered for the TTL. See <a
     * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/local-keys.md#refresh-and-expiry">Refresh
     * and expiry</a>.
     *
     * @param value the TTL, at least two nanoseconds, representable as nanoseconds
     * @return this builder
     * @throws IllegalArgumentException when outside that range
     */
    public Builder ttl(Duration value) {
      duration(value, "ttl");
      ttl = value;
      return this;
    }

    /**
     * Sets the age at which an access queues asynchronous revalidation; default half the TTL.
     * The first access after this age queues one refresh and returns the still-valid value at
     * once. Other callers share that refresh. This is an update interval, not a second
     * authorization lifetime. Idle entries are not polled.
     *
     * @param value positive and shorter than TTL (checked at open)
     * @return this builder
     * @throws IllegalArgumentException when not positive or too long
     */
    public Builder refreshAfter(Duration value) {
      duration(value, "refreshAfter");
      refreshAfter = value;
      return this;
    }

    /**
     * Bounds retained historical entries, negative answers and the pinned write slot. An
     * identifier asked for with {@link LocalKeys#forAppend(String)} that is not the write key takes
     * a historical entry. When every historical entry is busy, a new identifier waits within its
     * call deadline for one to become idle. Nothing beyond capacity is retained, so a working set
     * larger than capacity costs reloads and waits, and can exhaust a deadline even with a healthy
     * KMS.
     *
     * @param value capacity, at least two; default 64
     * @return this builder
     * @throws IllegalArgumentException when less than two
     */
    public Builder capacity(int value) {
      if (value < 2) throw new IllegalArgumentException("Capacity must be at least two");
      capacity = value;
      return this;
    }

    /**
     * Uses a caller-owned executor for refresh-ahead work, instead of the cache's own bounded
     * one. It must run work asynchronously, because a direct executor would make the requesting
     * thread perform the refresh. It must outlive this cache, which never shuts it down, and should
     * have a bounded queue. Cold or expired loads run on the caller instead.
     *
     * @param value the executor; not null
     * @return this builder
     */
    public Builder refreshExecutor(Executor value) {
      executor = Objects.requireNonNull(value, "refreshExecutor");
      return this;
    }

    /**
     * A maintenance setting, for recovering files encrypted under a key that has since been
     * revoked as Compromised, such as a commit log to replay before re-encrypting. {@link
     * #forDecrypt} then also hands out a Compromised key, where the server still lets it be read
     * and, for a key that states a Lease Time, grants it a lease. keytend-kmip-server leases no
     * Compromised key, so there it changes nothing. Encryption never uses a Compromised key.
     *
     * <p>Off by default, and not for normal operation. Data under a compromised key may have been
     * read or forged, so recover it from replicas where you can, and re-encrypt what you recover.
     * The cache logs a warning (SLF4J logger {@code dev.keytend.kmip.kms.LocalKeys}) when it
     * opens, and at each validation that accepts a Compromised key.
     *
     * @return this builder
     * @since 0.10.0
     */
    public Builder allowCompromisedForDecrypt() {
      compromisedForDecrypt = true;
      return this;
    }

    /**
     * Opens the configured cache, without making a request. Scope and expectation are required.
     *
     * @return a new cache, owned by the caller
     * @throws IllegalStateException when scope/expectation is missing or the KMS is closed
     * @throws IllegalArgumentException when the update interval is not shorter than TTL
     */
    public LocalKeys open() {
      if (scope == null || expect == null)
        throw new IllegalStateException("Set scope and expect before open");
      if (connection != null) connection.ensureOpen();
      if (keys != null) {
        keys.kms().keys();
        if (scope.group != null) keys.requireGroups("localKeys");
      }
      long life = duration(ttl, "ttl");
      long update = refreshAfter == null ? life / 2 : duration(refreshAfter, "refreshAfter");
      if (life < 2 || update >= life)
        throw new IllegalArgumentException(
            "Refresh interval must be positive and shorter than TTL");
      return new LocalKeys(this, life, update);
    }
  }

  /**
   * An immutable identifier and its caller-owned material, taken from the same validated snapshot.
   * Closing destroys the copy. A provider returning {@link #key()} to a caller that initializes
   * its cipher later must transfer ownership without closing this use. That recipient owns the
   * returned key and should destroy it when finished; otherwise its memory is reclaimed by GC,
   * without a guarantee that the bytes are wiped.
   *
   * <p>The cache bounds authorization (TTL, lease, protection deadline) only when it hands a use
   * out. It does not recall or expire a use, its key or a cipher initialized from it afterwards.
   * Request a new use immediately before each bounded cryptographic operation, and do not retain
   * the key or an initialized cipher across operations. A file that stays open and grows asks with
   * {@link LocalKeys#forAppend(String)} before each chunk.
   *
   * <p><b>Leases.</b> Under the default {@link LeasePolicy#REQUIRE}, a key whose Get Attributes
   * states a KMIP Lease Time, even zero or malformed, is fetched only after Obtain Lease grants it a
   * lease. A copy is handed out only while that lease runs, counted from before Obtain Lease was
   * first sent. A grant of zero means no lease limit. Get, Get Attributes and Locate never grant or
   * renew a lease. Revalidation, which obtains a new lease, is queued after half the lease or the
   * update interval, whichever comes first. A definite refusal of the lease invalidates every
   * cached copy of the identifier, and is thrown with {@code operation()} {@code obtainLease}. A
   * Deactivated key decrypts only where the server grants it a lease. No setting extends a lease.
   * {@link LeasePolicy#HONOR_IF_SUPPORTED} differs only where the SDK has confirmed that the server
   * does not implement Obtain Lease: there a positive stated Lease Time bounds each copy locally,
   * as a grant of it would. It does not excuse a refusal for permission or state, or an outage.
   * Keys with Usage Limits are refused, because this cache obtains no usage allocation. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/local-keys.md#leases">Leases</a>.
   *
   * @since 0.10.0
   */
  public static final class Use implements AutoCloseable {
    private final String id;
    private final DestroyableSecretKey key;

    private Use(String id, DestroyableSecretKey key) {
      this.id = id;
      this.key = key;
    }

    /**
     * The exact server identifier to record with the data, never a moving name.
     *
     * @return the identifier
     */
    public String id() {
      return id;
    }

    /**
     * This use's material; each use receives its own copy. Closing this use destroys it.
     * When handing the key to a caller that has not yet initialized its cipher, leave the use
     * open and transfer ownership of the key to that caller.
     *
     * @return the key, owned by this use
     */
    public DestroyableSecretKey key() {
      return key;
    }

    /** Wipes this use's copy; idempotent. Copies already made by a cipher remain its own. */
    @Override
    public void close() {
      key.destroy();
    }

    /** The identifier only, never key material. */
    @Override
    public String toString() {
      return "LocalKeys.Use[" + id + "]";
    }
  }

  private static final String OP = "localKeys";

  /** The maintenance setting's warnings, among others (docs/production.md, "Logging"). */
  private static final Logger log = LoggerFactory.getLogger(LocalKeys.class);

  /** The rate limit of the accepted-Compromised-key warning: once a minute per key. */
  private final LogLimiter compromisedWarnings;

  /** {@link Builder#allowCompromisedForDecrypt()}: a maintenance setting. */
  private final boolean compromisedForDecrypt;

  private volatile KmsKeys keys;
  private volatile Kms kms;
  private final Duration callTimeout;

  /** The lazily connected KMS this cache owns or shares; null for a cache of a caller's Kms. */
  private final Connection connection;

  private final boolean ownsConnection;

  /** Completed at {@link #close()}: a call waiting for a shared connection attempt stops then. */
  private final CompletableFuture<Kms> closing = new CompletableFuture<>();

  private final String name;
  private final KeyQuery scope;
  private final Expect expect;
  private final long ttl, update, backoff;
  private final int capacity;
  private final LongSupplier nanos;
  private final Clock clock;
  private final BiConsumer<String, byte[]> retained; // Builder#retained
  private final Executor executor;
  private final ExecutorService owned;

  /**
   * Exact-identifier slots, for decryption ({@link #forDecrypt}) and encryption ({@link
   * #forAppend(String)}), held by Caffeine (bundled, relocated). Its size bound, capacity less the
   * write slot, is never reached by Caffeine's own eviction: admission ({@link #admit}) makes room
   * first, under membership, by evicting the coldest idle slot in Caffeine's eviction order
   * ({@link #evictIdle}), because only this cache knows which slots a call has reserved. Hits read
   * it without a lock and record their access in Caffeine's buffers.
   */
  private final Cache<SlotKey, Slot> readCache;

  /** {@link #readCache}'s policy: quiet reads, the eviction order. */
  private final Policy<SlotKey, Slot> readPolicy;

  /** {@link #readCache} as a map: exact sizes, conditional removal, iteration. */
  private final ConcurrentMap<SlotKey, Slot> reads;

  /**
   * One timer per published entry (the write slot's too), in Caffeine's timer wheel: it expires
   * when the entry's TTL, lease or protection deadline ends. Caffeine reads {@link #timerTime},
   * the latest time this cache read, never the ticker itself. Its listener only queues the entry
   * ({@link #expired}); the sweep wipes it under its slot's lock, so no cache lock is taken inside
   * Caffeine.
   */
  private final Cache<Entry, Slot> timers;

  private final Queue<Expired> expired = new ConcurrentLinkedQueue<>();

  /** Slots Caffeine evicted itself, which admission never lets happen ({@link #retireOverflowed}). */
  private final Queue<Slot> overflowed = new ConcurrentLinkedQueue<>();

  private final AtomicLong timerTime = new AtomicLong();

  /**
   * No timer ends before this time (in the ticker's nanoseconds), so a sweep before it asks
   * Caffeine nothing: lowered by every {@link #schedule}, set from Caffeine's soonest timer by each
   * sweep that ran.
   */
  private final AtomicLong nextTimer = new AtomicLong();

  private record Expired(Entry entry, Slot slot) {}

  private final Slot write = new Slot(null, LocalUse.ENCRYPT);
  private final AtomicLong nextSweep = new AtomicLong();
  private final Object membership = new Object();
  // Only active historical calls are tracked: no retained per-ID invalidation tombstones.
  private final Object admissionLock = new Object(); // Leaf: no cache locks taken while held.
  private final Map<String, Admission> admissions = new HashMap<>();

  private static final class Admission {
    int callers; // guarded by admissionLock
    volatile boolean invalidated;
  }

  // Capacity waits: a leaf monitor, never held while taking another lock. Version changes when a
  // reservation ends, a validation finishes or entries are removed; waiters then recheck admission.
  private final Object progress = new Object();
  private volatile long progressVersion;
  private final AtomicInteger capacityWaiters = new AtomicInteger();
  // stats(): each as Stats documents it.
  private final LongAdder encryptHits = new LongAdder(), encryptMisses = new LongAdder();
  private final LongAdder decryptHits = new LongAdder(), decryptMisses = new LongAdder();
  private final LongAdder loads = new LongAdder(), loadFailures = new LongAdder();
  private final LongAdder evictions = new LongAdder(), capacityWaits = new LongAdder();
  private final KmsConfig listenerConfig;
  private String
      selectedId; // guarded by write: the last committed write selection, for its listener
  // Guarded by membership: moved by every observation or refusal a historical validation applies
  // and by every invalidation, which tells a write validation that the attributes its selection
  // read may be stale: an invalidate(id) during the selection must not be undone by them.
  private long attributeEpoch;
  private volatile boolean closed;
  // The failure of the write key's last validation; null once one succeeds (writeFailure()).
  private volatile RuntimeException writeFailure;

  /**
   * A validated copy of a key. Hits read it without a lock: {@link #encoded()} copies the bytes
   * under an optimistic stamp and validates it afterwards, and {@link #destroy()} write-locks the
   * stamp, never to release it, before wiping. A copy is therefore the whole key, taken before the
   * entry was destroyed, or nothing.
   */
  private static final class Entry {
    final String id;
    final String algorithm;
    private final byte[] key; // Wiped by destroy(); read only through encoded().
    private final StampedLock wiping = new StampedLock();
    final long validatedAt;
    final Instant validatedWall;
    final Lease lease;
    volatile Protection protection;

    /** Takes ownership of {@code material}: keeps a copy of it and destroys it. */
    Entry(
        String id,
        DestroyableSecretKey material,
        long validatedAt,
        Instant validatedWall,
        Lease lease,
        Protection protection) {
      this(
          id,
          material.getEncoded(),
          material.getAlgorithm(),
          validatedAt,
          validatedWall,
          lease,
          protection);
      material.destroy();
    }

    /** Keeps {@code key} itself, which the caller no longer uses. */
    Entry(
        String id,
        byte[] key,
        String algorithm,
        long validatedAt,
        Instant validatedWall,
        Lease lease,
        Protection protection) {
      this.id = id;
      this.key = key;
      this.algorithm = algorithm;
      this.validatedAt = validatedAt;
      this.validatedWall = validatedWall;
      this.lease = lease;
      this.protection = protection;
    }

    /** A copy of the key bytes, which the caller wipes; null once destroyed. Takes no lock. */
    byte[] encoded() {
      long stamp = wiping.tryOptimisticRead();
      if (stamp == 0) return null;
      byte[] bytes = key.clone();
      if (wiping.validate(stamp)) return bytes;
      Arrays.fill(bytes, (byte) 0); // destroy() began during the copy: it may be partly wiped
      return null;
    }

    /** A caller-owned copy of the key; null once destroyed. Takes no lock. */
    DestroyableSecretKey copy() {
      byte[] bytes = encoded();
      if (bytes == null) return null;
      try {
        return new DestroyableSecretKey(bytes, algorithm);
      } finally {
        Arrays.fill(bytes, (byte) 0);
      }
    }

    /** Idempotent. The write lock is never released, so every later copy fails. */
    void destroy() {
      if (wiping.tryWriteLock() != 0) Arrays.fill(key, (byte) 0);
    }
  }

  private record Protection(Instant deadline, long lifetime) {}

  /**
   * The KMIP lease a validation obtained before its Get: granted for {@code nanos} from the tick
   * before Obtain Lease was first sent ({@link Long#MAX_VALUE}: no lease limit, the grant was zero).
   * {@link #NONE}: the key stated no Lease Time, so no lease was needed.
   */
  private record Lease(boolean required, long sent, long nanos) {
    static final Lease NONE = new Lease(false, 0, Long.MAX_VALUE);

    boolean runs(long now) {
      return nanos == Long.MAX_VALUE || now - sent < nanos;
    }

    /** Renewal is due once half the granted lease has run. */
    boolean due(long now) {
      return nanos != Long.MAX_VALUE && now - sent >= nanos / 2;
    }
  }

  /**
   * Why a slot's entry and validation were superseded. Only {@link #CAPACITY} is internal pressure
   * that a displaced call may retry; the others are reported to the calls they displace.
   */
  private enum Cause {
    CAPACITY,
    INVALIDATED,
    REFUSED,
    CLOSED
  }

  private static final class Flight {
    final Slot owner;
    final long generation;
    final boolean refresh; // renews an entry this slot published; its failure is reported as such
    final CompletableFuture<Void> done = new CompletableFuture<>();
    volatile boolean started;
    RuntimeException policyRefusal;
    Instant protectionStop; // guarded by membership; only for the write load's exact loadingId
    boolean leaseRequired; // guarded by membership; an observed obligation survives older snapshots
    Duration grant; // the lease the server granted this validation; only its loader uses it

    Flight(Slot owner) { // under the owner's lock
      this.owner = owner;
      this.generation = owner.generation;
      this.refresh = owner.published;
    }
  }

  private record SlotKey(String id, LocalUse purpose) {}

  private static final class Slot {
    final String id; // null means the write-name selection
    final LocalUse purpose;
    volatile Entry entry;
    volatile RuntimeException failure;
    boolean failureDefinite;
    volatile long retryAt;
    volatile Flight flight;
    volatile String loadingId;
    volatile boolean retired;
    long generation;
    volatile Stamp fingerprint;
    // Historical calls between reservation and copying (or exit), hits included; -1 once evicted,
    // never pinned again.
    final AtomicInteger pins = new AtomicInteger();
    // When a hit last told Caffeine of an access (recordHit), 0 if none has; historical slots.
    volatile long recorded;
    volatile Cause cause;
    volatile RuntimeException displacedBy;
    volatile int displaced; // explicit invalidations, closes and (historical) refusals
    boolean published; // guarded by this: holds or held a validated entry, not since
    // Guarded by membership: the identifier whose lease grant this slot last committed, so that a
    // later grant for it is reported as a renewal (KmsListener#leaseGranted). Per retained slot
    // only: the cache keeps no per-identifier history beyond its capacity.
    String leased;

    // refused/invalidated

    Slot(String id, LocalUse purpose) {
      this.id = id;
      this.purpose = purpose;
    }

    SlotKey key() {
      return new SlotKey(id, purpose);
    }
  }

  /** How often, at most, hits on one slot are told to Caffeine's eviction order. */
  private static final long RECORD_EVERY = TimeUnit.MILLISECONDS.toNanos(1);

  private static final AtomicLongFieldUpdater<Slot> RECORDED =
      AtomicLongFieldUpdater.newUpdater(Slot.class, "recorded");

  /** Tests: the hits told to Caffeine ({@link #recordHit}). */
  private final LongAdder hitsRecorded = new LongAdder();

  /**
   * Tells Caffeine of a hit on {@code slot}, at most once a millisecond per slot: Caffeine's
   * recency and frequency then order the slot for eviction, and a key many threads hit is not one
   * write to Caffeine's buffers per hit. The hit itself reads the slot quietly ({@link #exact}).
   * The hit that tells claims the millisecond with a compare-and-set, so concurrent hits never
   * tell twice; no lock, no allocation.
   */
  private void recordHit(Slot slot, long now) {
    long last = slot.recorded;
    if (last != 0 && now - last < RECORD_EVERY)
      return; // 0: never told (the ticker may be negative)
    if (!RECORDED.compareAndSet(slot, last, now)) return; // Another hit told, this millisecond.
    hitsRecorded.increment();
    // The read is the record. A slot no longer cached is not timed: its next hit, if any, tells.
    if (readCache.getIfPresent(slot.key()) != slot) RECORDED.compareAndSet(slot, now, 0);
  }

  private record Stamp(String id, byte[] digest) {}

  private LocalKeys(Builder b, long ttl, long update) {
    keys = b.keys;
    kms = keys != null ? keys.kms() : null;
    connection = b.connection;
    ownsConnection = b.ownsConnection;
    callTimeout = kms != null ? kms.callTimeout() : connection.config.callTimeout();
    listenerConfig = kms != null ? kms.config : connection.config;
    name = b.name;
    scope = b.scope;
    expect = b.expect;
    this.ttl = ttl;
    this.update = update;
    backoff = Math.max(1, Math.min(TimeUnit.SECONDS.toNanos(1), ttl / 8));
    capacity = b.capacity;
    compromisedForDecrypt = b.compromisedForDecrypt;
    if (compromisedForDecrypt)
      log.warn(
          "LocalKeys for {} in {} hands out Compromised keys for decryption"
              + " (allowCompromisedForDecrypt): a maintenance setting for recovering data, not for"
              + " normal operation; never for encryption",
          LogText.safe(name),
          LogText.safe(scope));
    nanos = b.ticker;
    compromisedWarnings = new LogLimiter(LoggingListener.WINDOW_NANOS, nanos);
    clock = b.clock;
    retained = b.retained;
    long opened = nanos.getAsLong();
    nextSweep.set(opened);
    timerTime.set(opened);
    nextTimer.set(opened + Long.MAX_VALUE / 4);
    readCache =
        Caffeine.newBuilder()
            .maximumSize(capacity - 1)
            .executor(Runnable::run) // Maintenance in the calling thread: the SDK starts no pool.
            .evictionListener(
                (SlotKey key, Slot slot, RemovalCause cause) -> {
                  // Never expected: admission keeps the map below Caffeine's bound. The slot is
                  // never pinned again, and queued: the admission that made the cache overflow, or
                  // the next one, wipes it under its lock, never taken inside Caffeine.
                  if (slot != null) {
                    slot.pins.set(-1);
                    overflowed.add(slot);
                  }
                })
            .build();
    reads = readCache.asMap();
    readPolicy = readCache.policy();
    timers =
        Caffeine.newBuilder()
            .executor(Runnable::run)
            .ticker(timerTime::get)
            .expireAfter(
                new Expiry<Entry, Slot>() {
                  @Override
                  public long expireAfterCreate(Entry entry, Slot slot, long now) {
                    return remainingNanos(entry, now);
                  }

                  @Override
                  public long expireAfterUpdate(Entry entry, Slot slot, long now, long current) {
                    return remainingNanos(entry, now);
                  }

                  @Override
                  public long expireAfterRead(Entry entry, Slot slot, long now, long current) {
                    return current;
                  }
                })
            .evictionListener(
                (Entry entry, Slot slot, RemovalCause cause) -> {
                  if (entry != null && slot != null) expired.add(new Expired(entry, slot));
                })
            .build();
    if (b.executor != null) {
      owned = null;
      executor = b.executor;
    } else {
      ThreadPoolExecutor worker =
          new ThreadPoolExecutor(
              1,
              1,
              30,
              TimeUnit.SECONDS,
              new ArrayBlockingQueue<>(capacity),
              r -> SdkThreads.daemon(r, "keytend-local-keys-refresh"),
              new ThreadPoolExecutor.AbortPolicy());
      worker.allowCoreThreadTimeOut(true);
      owned = worker;
      executor = owned;
    }
  }

  /**
   * The hard authorization lifetime in force, unaffected by cache hits.
   * @return the configured TTL
   */
  public Duration ttl() {
    return Duration.ofNanos(ttl);
  }

  /**
   * The age at which an access queues refresh work; no periodic idle refresh is performed.
   * @return the configured update interval, defaulting to half the TTL
   */
  public Duration refreshAfter() {
    return Duration.ofNanos(update);
  }

  /**
   * Selects an Active write key by the write name and returns its identifier and material as one
   * snapshot. A valid hit sends no request. A due update is asynchronous, and a miss or expired
   * value waits within the call deadline. Nothing is created.
   *
   * <p>The name is looked up again at each validation, and replacement links are not needed. One
   * eligible Active key in the scope is selected. With several, a key selected before that is
   * still eligible is kept, and a cold or invalidated cache fails rather than guessing. Candidates
   * these credentials may not use are skipped. A key with a future Deactivation Date or Protect
   * Stop Date is used until the earlier date, checked on every use, so keep the clock accurate.
   *
   * @return a caller-owned use, which the caller closes after initializing its cipher
   * @throws KmsException when selection, policy or material validation fails
   * @throws IllegalStateException when this cache or its KMS is closed
   */
  public Use forEncrypt() {
    ensureOpen();
    return Kms.call(
        callTimeout,
        OP,
        () -> {
          return access(write);
        });
  }

  /**
   * Loads only the exact ID recorded with the data, within the stable scope. Active and
   * Deactivated keys permitting Decrypt are accepted (a key stating a Lease Time only while the
   * server grants it one, or under the local bound of {@link LeasePolicy#HONOR_IF_SUPPORTED});
   * Compromised keys are refused unless {@link
   * Builder#allowCompromisedForDecrypt()} is configured, and Destroyed keys always.
   * The moving write name and replacement links do not participate.
   *
   * @param id the exact identifier; not null or empty
   * @return a caller-owned use, which the caller closes after initializing its cipher
   * @throws KmsException when access, state, scope or material validation fails
   * @throws IllegalArgumentException when id is empty
   * @throws IllegalStateException when this cache or its KMS is closed
   */
  public Use forDecrypt(String id) {
    Objects.requireNonNull(id, "id");
    if (id.isEmpty()) throw new IllegalArgumentException("Empty key identifier");
    ensureOpen();
    // One deadline from before admission: capacity waits, loads and any retry all share it.
    return Kms.call(
        callTimeout,
        OP,
        () -> {
          return exact(id, LocalUse.DECRYPT);
        });
  }

  /**
   * Hands out this exact key for appending to a file already encrypted under it, while the key may
   * still encrypt. The checks are those of {@link #forEncrypt()}: Active, in the scope, permitting
   * Encrypt, before its protection deadline, and under a lease where one is required. The key need
   * not be the current write key. An append-only file keeps the key it started with, and asks
   * again before each chunk, so a key that is no longer eligible stops the file's writes within
   * one TTL. A new file asks {@link #forEncrypt()}, never this.
   *
   * <p>Once this fails with a definite refusal, close the file and start a new one under {@link
   * #forEncrypt()}. The data already written stays readable through {@link #forDecrypt} while the
   * key may still decrypt. A writer that cannot start a new file stops writing: the refusal is the
   * bound, not a fault to retry around (see <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/local-keys.md#append-only-files">Append-only
   * files</a>). An identifier that is not the write key has its own entry, cached like a
   * historical one.
   *
   * @param id the identifier recorded with the open file; not null or empty
   * @return a caller-owned use, which the caller closes after initializing its cipher
   * @throws KmsException when access, state, scope, protection deadline, lease or material
   *     validation fails
   * @throws IllegalArgumentException when id is empty
   * @throws IllegalStateException when this cache or its KMS is closed
   * @since 0.10.0
   */
  public Use forAppend(String id) {
    Objects.requireNonNull(id, "id");
    if (id.isEmpty()) throw new IllegalArgumentException("Empty key identifier");
    ensureOpen();
    return Kms.call(
        callTimeout,
        OP,
        () -> {
          Use use = writeHit(id);
          return use != null ? use : exact(id, LocalUse.ENCRYPT);
        });
  }

  /**
   * The write selection's copy when it holds {@code id} within its TTL, lease and protection
   * deadline (queueing its due refresh as {@link #forEncrypt()} does); null otherwise.
   */
  private Use writeHit(String id) {
    Entry value = write.entry;
    long now = nanos.getAsLong();
    if (value == null || !value.id.equals(id) || !valid(value, now)) return null;
    if ((now - value.validatedAt >= update || value.lease.due(now)) && retryDue(write, now))
      refresh(write);
    value = write.entry; // an immediately executed refresh may already have refused it
    return value == null || !value.id.equals(id)
        ? null
        : handedOut(write, copy(write, value, null), false);
  }

  /** {@link #forDecrypt} and {@link #forAppend(String)}: the exact ID's slot for {@code purpose}, within the call's deadline. */
  private Use exact(String id, LocalUse purpose) {
    // Quietly: hit() tells Caffeine of the access, at most once a millisecond (recordHit).
    Slot cached = readPolicy.getIfPresentQuietly(new SlotKey(id, purpose));
    if (cached != null && pin(cached)) {
      int displaced = cached.displaced;
      Use use;
      try {
        use = hit(cached, displaced);
      } catch (RuntimeException | Error failure) {
        unpin(cached);
        throw failure;
      }
      if (use != null) {
        unpin(cached);
        return use;
      }
      return admitted(id, purpose, cached, displaced); // Keeps the reservation and what it saw.
    }
    return admitted(id, purpose, null, 0);
  }

  /**
   * A hit on a slot this call has reserved, without the admission lock: the copy of its valid entry
   * (queueing a due refresh, as {@link #access} does), or null when the call must continue on the
   * admitted path, which loads, waits or reports a displacement.
   *
   * <p>Why a hit needs no admission. {@link #invalidate} and {@link #clear} (under membership) mark
   * the admissions, remove the slots from {@link #reads}, then retire each one under its lock:
   * entry cleared, entry destroyed, then (historical) {@code retired} and {@code displaced} set.
   * The hit's handout takes effect when its copy's stamp validates ({@link Entry#encoded}). If that
   * precedes the destruction, the handout precedes the invalidation, which has not returned yet.
   * Otherwise the copy fails and the call continues with this reservation and the {@code displaced}
   * it read before reading the entry: the admitted path sees the new count or {@code retired} at
   * the latest under the slot's lock, which the retirement holds throughout, and throws the
   * displacement without loading (a slot already retired when the count was read is refused for
   * {@code retired}). A call that no longer finds the slot in {@link #reads} begins after the
   * invalidation, as one admitted after it does. Eviction cannot take a pinned slot; expiry, the
   * lease and the protection deadline are checked after the copy ({@link #copy}).
   */
  private Use hit(Slot slot, int displaced) {
    checkProgress();
    sweep(false);
    ensureOpen();
    checkProgress();
    long now = nanos.getAsLong();
    if (slot.displaced != displaced || slot.retired) return null;
    Entry value = slot.entry;
    if (!valid(value, now)) return null;
    recordHit(slot, now);
    if ((now - value.validatedAt >= update || value.lease.due(now)) && retryDue(slot, now))
      refresh(slot);
    return handedOut(slot, copy(slot, slot.entry, null), false);
  }

  /** The admitted path of {@link #exact}, starting with the slot a failed hit reserved, if any. */
  private Use admitted(String id, LocalUse purpose, Slot reserved, int displaced) {
    Admission admission;
    try {
      synchronized (admissionLock) {
        ensureOpen();
        admission = admissions.computeIfAbsent(id, ignored -> new Admission());
        admission.callers++;
      }
    } catch (RuntimeException | Error closed) {
      if (reserved != null) unpin(reserved); // as exact() does: a pin is never left behind
      throw closed;
    }
    try {
      for (; ; ) {
        Slot slot = reserved != null ? reserved : admit(id, purpose, admission);
        int seen = reserved != null ? displaced : slot.displaced;
        reserved = null;
        Use use;
        try {
          use = access(slot, admission, seen);
        } finally {
          unpin(slot);
        }
        if (use != null) return use;
        checkProgress(); // Capacity pressure displaced the reservation: same deadline.
      }
    } finally {
      synchronized (admissionLock) {
        if (--admission.callers == 0) admissions.remove(id, admission);
      }
    }
  }

  private void checkAdmission(Admission admission) {
    checkProgress();
    if (admission != null && admission.invalidated)
      throw transientFailure(
          "Local key call was invalidated while waiting or loading; retry", null);
  }

  /**
   * Reserves the ID's historical slot, so that it cannot be evicted until this call copies its use
   * or exits. When every slot is reserved or validating, waits for one to become idle, outside the
   * cache's locks and within the call deadline. Another ID's result only wakes this call.
   */
  private Slot admit(String id, LocalUse purpose, Admission admission) {
    SlotKey key = new SlotKey(id, purpose);
    boolean waiting = false, waited = false;
    try {
      for (; ; ) {
        ensureOpen();
        checkAdmission(admission);
        Slot slot = readCache.getIfPresent(key);
        if (slot != null && pin(slot)) return slot;
        long seen = progressVersion;
        synchronized (membership) {
          ensureOpen();
          checkAdmission(admission);
          slot = reads.get(key);
          if (slot != null) {
            if (pin(slot)) return slot; // A slot still in the map was not evicted.
          } else {
            sweep(true);
            if (reads.size() < capacity - 1 || evictIdle()) {
              slot = new Slot(id, purpose);
              slot.pins.set(1);
              readCache.put(key, slot);
              retireOverflowed();
              return slot;
            }
          }
        }
        if (!waiting) { // Register, then recheck once before the first wait.
          capacityWaiters.incrementAndGet();
          waiting = true;
          continue;
        }
        if (!waited) capacityWaits.increment();
        waited = true;
        awaitProgress(seen);
      }
    } finally {
      if (waiting) capacityWaiters.decrementAndGet();
    }
  }

  private static boolean pin(Slot slot) {
    for (; ; ) {
      int pins = slot.pins.get();
      if (pins < 0) return false;
      if (slot.pins.compareAndSet(pins, pins + 1)) return true;
    }
  }

  private void unpin(Slot slot) {
    if (slot.pins.decrementAndGet() == 0) signalProgress();
  }

  /**
   * Under membership: evicts the first historical slot, in Caffeine's eviction order (coldest
   * first), that no call has reserved and that has no running validation (a queued refresh that
   * has not started is superseded). The victim is wiped, and its calls displaced, before this
   * returns, so before the slot that needed the room is handed out.
   */
  private boolean evictIdle() {
    Policy.Eviction<SlotKey, Slot> order = readPolicy.eviction().orElseThrow();
    // A slot not yet in Caffeine's order (its insertion still buffered) is found in the map.
    return evictFirstIdle(order.coldest(capacity).values()) || evictFirstIdle(reads.values());
  }

  private boolean evictFirstIdle(Collection<Slot> candidates) {
    for (Slot victim : candidates) {
      if (!victim.pins.compareAndSet(0, -1)) continue;
      synchronized (victim) {
        Flight running = victim.flight;
        if (running != null && running.started) {
          victim.pins.set(0);
          continue;
        }
        if (!reads.remove(victim.key(), victim)) continue; // Already gone; never pinned again.
        if (victim.entry != null) evictions.increment();
        retire(victim, Cause.CAPACITY, null, null);
      }
      return true;
    }
    return false;
  }

  /**
   * Under membership: wipes the slots Caffeine evicted itself, which admission never lets happen,
   * and displaces their calls as by capacity. Its listener only queues them, so that no slot lock
   * is taken inside Caffeine's eviction, which {@link #evictFirstIdle} takes in the other order.
   */
  private void retireOverflowed() {
    for (Slot slot; (slot = overflowed.poll()) != null; )
      synchronized (slot) {
        if (slot.entry != null) evictions.increment();
        retire(slot, Cause.CAPACITY, null, null);
      }
  }

  private void signalProgress() {
    if (capacityWaiters.get() == 0) return;
    synchronized (progress) {
      progressVersion++;
      progress.notifyAll();
    }
  }

  private void awaitProgress(long seen) {
    synchronized (progress) {
      checkProgress();
      while (progressVersion == seen && !closed) {
        long remaining = Kms.callRemaining(callTimeout);
        if (remaining <= 0)
          throw deadlinePassed("Call deadline passed waiting for local key cache capacity", null);
        try {
          TimeUnit.NANOSECONDS.timedWait(progress, remaining);
        } catch (InterruptedException e) {
          throw interrupted(e);
        }
      }
    }
  }

  /** Every admission, access and handout shares the original deadline and interruption. */
  private void checkProgress() {
    if (Thread.currentThread().isInterrupted()) throw interrupted(null);
    if (Kms.callRemaining(callTimeout) <= 0)
      throw deadlinePassed("Call deadline passed waiting for local key", null);
  }

  /**
   * Null only when capacity pressure retired the reserved slot; an explicit invalidation, close or
   * historical refusal during the call is reported to it instead of loading again.
   */
  private Use access(Slot slot) {
    return access(slot, null, slot.displaced);
  }

  /** {@code displaced}: the slot's count when this call reserved it (or, for the write slot, began). */
  private Use access(Slot slot, Admission admission, int displaced) {
    checkAdmission(admission);
    sweep(false);
    boolean loaded = false; // whether this call waited for a load (Stats: a miss)
    for (; ; ) {
      ensureOpen();
      checkAdmission(admission);
      long now = nanos.getAsLong();
      if (slot.displaced != displaced || slot.retired) {
        if (slot.displaced == displaced && slot.cause == Cause.CAPACITY) return null;
        throw displacement(slot);
      }
      Entry value = slot.entry;
      if (valid(value, now)) {
        if ((now - value.validatedAt >= update || value.lease.due(now)) && retryDue(slot, now))
          refresh(slot);
        value = slot.entry; // an immediately executed refresh may already have refused it
        Use use = copy(slot, value, admission);
        if (use != null) return handedOut(slot, use, loaded);
        continue;
      }
      Flight pending;
      boolean load = false;
      synchronized (slot) {
        // A retirement that a failed copy saw begin has finished: report it rather than load.
        if (slot.displaced != displaced || slot.retired) continue;
        value = slot.entry;
        now = nanos.getAsLong();
        if (valid(value, now)) continue;
        if (value != null) {
          discard(value);
          slot.entry = null;
          evictions.increment(); // Expired: its TTL, lease or protection deadline ended.
        }
        if (slot.failure != null && !retryDue(slot, now))
          throw slot.failureDefinite
              ? slot.failure
              : duringBackoff(slot.failure, slot.id, slot.retryAt, "key-load");
        pending = slot.flight;
        if (pending != null && !pending.started) {
          slot.generation++;
          slot.flight = null;
          pending.done.completeExceptionally(
              transientFailure("Expired key load superseded a queued refresh", null));
          pending = null;
        }
        if (pending == null) {
          pending = new Flight(slot);
          pending.started = true;
          slot.failure = null; // The negative answer's TTL ended; this is a new validation.
          slot.failureDefinite = false;
          slot.flight = pending;
          load = true;
        }
      }
      if (load) load(slot, pending);
      loaded = true;
      await(pending);
    }
  }

  /** What a call displaced by an explicit invalidation, close or refusal is told. */
  private RuntimeException displacement(Slot slot) {
    ensureOpen();
    RuntimeException reason = slot.displacedBy;
    if (slot.cause == Cause.REFUSED && reason != null)
      return slot == write
          ? transientFailure(
              "Write-key selection refused during this call; reselect and retry", reason)
          : reason;
    return transientFailure(
        slot == write
            ? "Write-key selection invalidated during this call; reselect and retry"
            : "Local key entry was invalidated during this call; retry",
        null);
  }

  private boolean valid(Entry value, long now) {
    if (value == null) return false;
    Protection p = value.protection;
    return now - value.validatedAt < p.lifetime()
        && value.lease.runs(now)
        && (p.deadline() == null || clock.instant().isBefore(p.deadline()));
  }

  private Protection protection(Instant start, Instant deadline) {
    if (deadline == null) return new Protection(null, ttl);
    Duration remaining = Duration.between(start, deadline);
    long lifetime =
        remaining.isNegative()
            ? 0
            : remaining.compareTo(Duration.ofNanos(ttl)) >= 0 ? ttl : remaining.toNanos();
    return new Protection(deadline, lifetime);
  }

  private boolean retryDue(Slot slot, long now) {
    return slot.failure == null || now - slot.retryAt >= 0;
  }

  /**
   * Hands out a copy of {@code value}, taking no lock; null when it is no longer the slot's valid
   * entry. The checks follow the copy, so the copy is of an entry not yet destroyed (invalidated,
   * evicted, refused, swept or closed) and its TTL, lease and protection deadline still held when
   * it was taken.
   */
  private Use copy(Slot slot, Entry value, Admission admission) {
    if (value == null) return null;
    DestroyableSecretKey key = value.copy();
    if (key == null) return null;
    boolean handedOut = false;
    try {
      // Validity first: what ends the entry during its tick or instant is then still seen here.
      if (!valid(value, nanos.getAsLong()) || closed || slot.entry != value) return null;
      checkAdmission(admission); // Also after a slow copy or validity check.
      handedOut = true;
      return new Use(value.id, key);
    } finally {
      if (!handedOut) key.destroy();
    }
  }

  /** Counts a handout ({@link Stats}): a hit, or a miss when the call waited for a load first. */
  private Use handedOut(Slot slot, Use use, boolean loaded) {
    if (use != null)
      (slot.purpose == LocalUse.ENCRYPT
              ? loaded ? encryptMisses : encryptHits
              : loaded ? decryptMisses : decryptHits)
          .increment();
    return use;
  }

  private void refresh(Slot slot) {
    if (slot.flight != null) return; // Already queued or running: hits take no lock for it.
    Flight pending;
    synchronized (slot) {
      if (closed || slot.retired || slot.flight != null || !retryDue(slot, nanos.getAsLong()))
        return;
      pending = new Flight(slot);
      slot.failure = null;
      slot.failureDefinite = false;
      slot.flight = pending;
    }
    try {
      executor.execute(() -> load(slot, pending));
    } catch (RuntimeException rejected) {
      failed(slot, pending, transientFailure("Local key refresh executor refused work", rejected));
    }
  }

  private void load(Slot slot, Flight pending) {
    // The entry loaded until it is published: destroyed when the load fails after reading it.
    Entry[] loaded = {null};
    long began = nanos.getAsLong();
    try {
      Kms.call(
          callTimeout,
          OP,
          () -> {
            String previousSelection = null, selection = null;
            boolean renewal = false;
            synchronized (slot) {
              ensureCurrent(slot, pending);
              pending.started = true;
            }
            connectIfNeeded();
            ensureCurrent(slot, pending);
            // Negotiation consumes the call deadline, but makes no key authorization observation.
            Instant startWall = clock.instant();
            long start = nanos.getAsLong();
            if (scope.group != null) keys.requireGroups(OP);
            long seen;
            synchronized (membership) {
              seen = attributeEpoch;
            }
            Selected selected = slot.id == null ? select(slot, pending) : null;
            String id = selected != null ? selected.id() : slot.id;
            // The write key's attributes from the selection serve its validation too (one Get
            // Attributes),
            // unless another validation's observation, or an invalidation, applied since they were
            // requested: it could be newer, and could not reach this flight before its loadingId
            // was
            // set,
            // so read them again.
            KeyAttributes read = selected != null ? selected.attributes() : null;
            synchronized (membership) {
              synchronized (slot) {
                ensureCurrent(slot, pending);
                slot.loadingId = id;
                if (attributeEpoch != seen) read = null;
              }
            }
            LocalUse purpose = slot.purpose;
            KeyHandle handle =
                compromisedForDecrypt && purpose == LocalUse.DECRYPT
                    ? keys.handle(id).allowingCompromised()
                    : keys.handle(id);
            boolean[] compromised = {false};
            DestroyableSecretKey material;
            boolean[] passedPolicy = {false};
            boolean[] decryptAllowed = {false};
            Instant[] stop = {null};
            Lease[] lease = {Lease.NONE};
            try {
              material =
                  handle.asSecretKey(
                      expect,
                      purpose,
                      read,
                      attributes -> {
                        ensureCurrent(slot, pending);
                        if (!id.equals(attributes.id())) {
                          KeyMismatchException mismatch =
                              new KeyMismatchException(
                                  "Attributes name another local key", null, OP, id, null, null);
                          rejectId(id, mismatch, pending);
                          throw mismatch;
                        }
                        observed(id, attributes, pending);
                        checkedPolicy(attributes, purpose, pending);
                        compromised[0] = attributes.state() == KeyState.COMPROMISED;
                        if (purpose == LocalUse.ENCRYPT) {
                          stop[0] = protectionStop(attributes);
                          try {
                            check(attributes, LocalUse.DECRYPT);
                            decryptAllowed[0] = true;
                          } catch (KmsException notForDecrypt) {
                            decryptAllowed[0] = false;
                          }
                        }
                        lease[0] = lease(attributes, purpose, slot, pending);
                        synchronized (membership) {
                          ensureCurrent(slot, pending);
                          checkObservedLease(id, pending, lease[0]);
                        }
                        passedPolicy[0] = true;
                      });
            } catch (KmsException refused) {
              ensureCurrent(slot, pending); // A superseded reply cannot poison a newer validation.
              // A Deactivated write key can still decrypt. Purpose-specific observations above
              // already removed exactly the purposes they forbid; absence/access denial forbids
              // both.
              if (refused instanceof NotFoundException
                  || definiteDenial(refused)
                  || (passedPolicy[0] && definite(refused, pending))
                  || (refused instanceof StateConflictException state
                      && state.observedState().isPresent()
                      && state.observedState().orElseThrow() != KeyState.DEACTIVATED
                      && !(compromisedForDecrypt
                          && state.observedState().orElseThrow() == KeyState.COMPROMISED)))
                rejectId(id, refused, pending);
              else if (compromisedForDecrypt
                  && refused instanceof StateConflictException state
                  && state.observedState().orElse(null) == KeyState.COMPROMISED)
                // The maintenance setting keeps its Decrypt copies, but no slot may encrypt with
                // it.
                rejectId(id, refused, pending, LocalUse.ENCRYPT);
              throw refused;
            }
            loaded[0] =
                new Entry(id, material, start, startWall, lease[0], protection(startWall, stop[0]));
            retained.accept(id, loaded[0].key);
            byte[] fingerprint = fingerprint(loaded[0]);
            synchronized (membership) {
              synchronized (slot) {
                ensureCurrent(slot, pending);
                checkObservedLease(id, pending, loaded[0].lease);
                if (pending.protectionStop != null
                    && (stop[0] == null || pending.protectionStop.isBefore(stop[0])))
                  loaded[0].protection = protection(startWall, pending.protectionStop);
                if (!valid(loaded[0], nanos.getAsLong()))
                  throw transientFailure(
                      "Key validation reached the authorization TTL, lease end or protection deadline",
                      null);
                for (Slot retained : slots()) {
                  Stamp known = retained.fingerprint;
                  if (known != null
                      && id.equals(known.id())
                      && !MessageDigest.isEqual(fingerprint, known.digest()))
                    throw new KeyMismatchException(
                        "Key material changed for retained identifier " + id,
                        null,
                        OP,
                        id,
                        null,
                        null);
                }
                Entry previous = slot.entry;
                slot.fingerprint = new Stamp(id, fingerprint);
                slot.entry = loaded[0];
                loaded[0] = null;
                slot.failure = null;
                slot.failureDefinite = false;
                slot.flight = null;
                slot.loadingId = null;
                slot.published = true;
                if (slot == write) writeFailure = null;
                if (previous != null) discard(previous);
                schedule(slot.entry, slot);
                if (slot == write && !id.equals(selectedId)) {
                  previousSelection = selectedId;
                  selection = selectedId = id;
                }
                if (slot == write && decryptAllowed[0]) seedRead(slot.entry, fingerprint);
                if (pending.grant != null) {
                  for (Slot s : slots()) renewal |= id.equals(s.leased);
                  slot.leased = id;
                }
              }
            }
            loads.increment();
            pending.done.complete(null);
            signalProgress();
            // Only a committed load or change; after the cache's locks are released.
            if (pending.grant != null) Kms.leaseGranted(listenerConfig, id, pending.grant, renewal);
            if (selection != null)
              Kms.localKeySelected(listenerConfig, name, previousSelection, selection);
            Kms.localKeyLoaded(
                listenerConfig,
                name,
                id,
                slot.purpose,
                Duration.ofNanos(Math.max(0, nanos.getAsLong() - began)));
            if (compromised[0] && log.isWarnEnabled()) {
              long suppressed = compromisedWarnings.permit(slot.id);
              if (suppressed != LogLimiter.SUPPRESSED)
                log.warn(
                    LoggingListener.withSuppressed(
                        "LocalKeys for {} accepted Compromised key {} for decryption"
                            + " (allowCompromisedForDecrypt); data under it may have been read or"
                            + " forged",
                        suppressed),
                    suppressed == 0
                        ? new Object[] {LogText.safe(name), LogText.safe(slot.id)}
                        : new Object[] {LogText.safe(name), LogText.safe(slot.id), suppressed});
            }
            return null;
          });
    } catch (RuntimeException failure) {
      if (failure instanceof Kms.Superseded) failure = transientFailure(failure.getMessage(), null);
      if (loaded[0] != null) {
        if (definite(failure, pending)) rejectId(loaded[0].id, failure, pending);
        loaded[0].destroy();
      }
      failed(slot, pending, failure);
    } catch (Error fatal) {
      if (loaded[0] != null) loaded[0].destroy();
      synchronized (slot) {
        if (slot.flight == pending) {
          slot.flight = null;
          slot.loadingId = null;
        }
      }
      pending.done.completeExceptionally(fatal);
      signalProgress();
      throw fatal;
    }
  }

  /** Called under membership and write locks; never displaces a running historical validation. */
  private void seedRead(Entry source, byte[] digest) {
    SlotKey key = new SlotKey(source.id, LocalUse.DECRYPT);
    Slot target = reads.get(key);
    if (target == null) {
      // Reserved or validating slots are never evicted for a seed; the write still succeeds.
      if (reads.size() >= capacity - 1 && !evictIdle()) return;
      target = new Slot(source.id, LocalUse.DECRYPT);
      readCache.put(key, target);
      retireOverflowed();
    }
    synchronized (target) {
      if (target.retired || target.flight != null) return;
      Entry previous = target.entry;
      if (previous != null && previous.validatedAt - source.validatedAt >= 0) return;
      byte[] bytes = source.encoded(); // Published under the locks held here: not destroyed.
      if (bytes == null) return;
      target.entry =
          new Entry(
              source.id,
              bytes,
              source.algorithm,
              source.validatedAt,
              source.validatedWall,
              source.lease,
              protection(source.validatedWall, null));
      retained.accept(source.id, target.entry.key);
      target.fingerprint = new Stamp(source.id, digest);
      target.failure = null;
      target.failureDefinite = false;
      target.published = true;
      if (previous != null) discard(previous);
      schedule(target.entry, target);
    }
  }

  /**
   * Before Get: obtains the lease of a key whose attributes state a Lease Time (zero and malformed
   * values too, KMIP 1.4 §3.20, 2.1 §4.30). Timed from the tick before the first send, so a retry or
   * a late answer never lengthens it. A grant of zero is no lease limit (1.4 §4.17, 2.1 §6.1.35); a
   * positive grant is held to a positive stated maximum. The server's definite refusal ends every
   * copy of the ID, and is thrown as the same type, naming the ID and purpose, with the server's
   * reason and message; another failure grants nothing and keeps earlier copies to their own ends.
   */
  private Lease lease(KeyAttributes attributes, LocalUse purpose, Slot slot, Flight pending) {
    Duration stated = attributes.leaseToObtain();
    if (stated == null) return Lease.NONE;
    String id = attributes.id();
    Request request = Requests.obtainLease().uniqueIdentifier(id).build();
    long sent = nanos.getAsLong();
    long seconds;
    try {
      seconds =
          keys.kms()
              .execute("obtainLease", Kms.Kind.READ, id, s -> Leases.granted(s.call(request), id));
    } catch (KmsException failure) {
      ensureCurrent(slot, pending); // A superseded reply cannot refuse a newer validation's copies.
      // A server that does not implement Obtain Lease, under LeasePolicy.HONOR_IF_SUPPORTED:
      // the stated Lease Time bounds this validation's copies, as a grant of it would.
      long bound = Leases.unsupportedBound(keys.kms(), failure, id, stated);
      if (bound > 0) return new Lease(true, sent, TimeUnit.SECONDS.toNanos(bound));
      if (!Leases.refusal(failure)) throw failure;
      KmsException refused =
          Leases.refused(
              keys.kms(), failure, id, "Local key " + id + " for " + purpose, attributes.state());
      pending.policyRefusal = refused;
      rejectId(id, refused, pending);
      throw refused;
    }
    ensureCurrent(slot, pending);
    pending.grant = Duration.ofSeconds(seconds); // Reported once the validation is committed.
    if (seconds == 0) return new Lease(true, sent, Long.MAX_VALUE);
    long granted = TimeUnit.SECONDS.toNanos(seconds), maximum = stated.toNanos();
    return new Lease(true, sent, maximum > 0 ? Math.min(granted, maximum) : granted);
  }

  /** Under membership, before Get and publication: a newer observation cannot be undone. */
  private void checkObservedLease(String id, Flight pending, Lease lease) {
    if (pending.leaseRequired && !lease.required())
      throw transientFailure("Local key " + id + " now requires a lease; retry validation", null);
    if (!lease.runs(nanos.getAsLong()))
      throw transientFailure("Local key " + id + " lease ended during validation", null);
  }

  /** A write selection: the key, and its attributes as read when they can serve its validation. */
  private record Selected(String id, KeyAttributes attributes) {}

  private Selected select(Slot source, Flight pending) {
    List<String> ids;
    if (scope.ids != null) ids = List.copyOf(scope.ids);
    else
      try (var found =
          keys.locate(scope.name(name).state(KeyState.ACTIVE).kind(ObjectKind.SYMMETRIC_KEY))) {
        ids = found.map(KeyHandle::id).distinct().limit(257).toList();
      }
    if (ids.size() > 256)
      throw new UnsupportedException("Too many local write-key candidates (limit 256)");
    List<KeyAttributes> candidates =
        keys.attributesOf(
            ids,
            (id, a) -> {
              ensureCurrent(source, pending);
              if (a == null)
                rejectId(id, new NotFoundException("Local key is absent: " + id), pending);
              else observed(id, a, pending);
            },
            (id, denied) -> {
              ensureCurrent(source, pending);
              rejectId(id, denied, pending);
            });
    Map<String, KeyAttributes> read = new LinkedHashMap<>();
    for (KeyAttributes a : candidates)
      if (a.state() == KeyState.ACTIVE
          && a.kind() == ObjectKind.SYMMETRIC_KEY
          && a.names().contains(name)
          && scope.matches(a)
          && beforeProtectionStop(a)) read.putIfAbsent(a.id(), a);
    List<String> eligible = List.copyOf(read.keySet());
    if (eligible.isEmpty())
      throw new NotFoundException("No Active local write key named " + name + " in " + scope);
    String chosen = eligible.size() == 1 ? eligible.get(0) : null;
    if (chosen == null) {
      String previous;
      synchronized (source) {
        previous = source.fingerprint == null ? null : source.fingerprint.id();
      }
      if (previous != null && eligible.contains(previous)) chosen = previous;
    }
    // Attributes answered for an identifier not asked for are not reused: the key is read again.
    if (chosen != null) return new Selected(chosen, ids.contains(chosen) ? read.get(chosen) : null);
    StateConflictException ambiguity =
        new StateConflictException(
                "Ambiguous Active local write keys named " + name + ": " + eligible)
            .because(StateConflictException.Conflict.NAME);
    pending.policyRefusal = ambiguity;
    throw ambiguity;
  }

  private void check(KeyAttributes a, LocalUse purpose) {
    String id = a.id();
    String label = "Local key " + id + " for " + purpose;
    if (!scope.matches(a))
      throw new KeyMismatchException(label + " is outside " + scope, null, OP, id, null, null);
    if (a.kind() != ObjectKind.SYMMETRIC_KEY
        || a.algorithm().orElse(null) != expect.algorithm()
        || (expect.bits() != 0 && a.length().orElse(0) != expect.bits()))
      throw new KeyMismatchException(
          label + " does not match the expected algorithm/size", null, OP, id, null, null);
    if (a.usageLimited())
      throw new UnsupportedException(
          label + " has Usage Limits; this cache requires keys configured without Usage Limits",
          null,
          OP,
          id,
          null,
          null);
    if (!purpose.states().contains(a.state())
        || (a.state() == KeyState.COMPROMISED
            && !(compromisedForDecrypt && purpose == LocalUse.DECRYPT)))
      throw new StateConflictException(
              label + " is " + a.state() + ", so it cannot " + purpose, null, OP, id, null, null)
          .observed(a.state());
    if (!a.usages().contains(purpose.usage()))
      throw new KeyMismatchException(
          label + " does not permit " + purpose.usage(), null, OP, id, null, null);
    if (purpose.protecting() && !beforeProtectionStop(a))
      throw new StateConflictException(
          label + " has reached its protection deadline", null, OP, id, null, null);
  }

  private boolean beforeProtectionStop(KeyAttributes a) {
    Instant stop = protectionStop(a);
    return stop == null || clock.instant().isBefore(stop);
  }

  private Instant protectionStop(KeyAttributes a) {
    Instant stop = a.deactivationDate().orElse(null);
    for (Ttlv attribute : a.protocolAttributes()) {
      if (attribute.tag() != Tag.PROTECT_STOP_DATE.code()
          && attribute.tag() != Tag.DEACTIVATION_DATE.code()) continue;
      if (attribute.type() != Ttlv.Type.DATE_TIME
          && attribute.type() != Ttlv.Type.DATE_TIME_EXTENDED)
        throw new UnsupportedException(
            "Local key " + a.id() + " has a malformed protection deadline",
            null,
            OP,
            a.id(),
            null,
            null);
      Instant date = attribute.instantValue();
      if (stop == null || date.isBefore(stop)) stop = date;
    }
    return stop;
  }

  /** Checks observations even on a partial candidate batch or a later failed loader. */
  private void observed(String id, KeyAttributes attributes, Flight origin) {
    synchronized (membership) {
      if (!current(origin)) return;
      if (origin.owner != write) attributeEpoch++;
      Map<Slot, RuntimeException> refused = new LinkedHashMap<>();
      for (Slot s : slots()) {
        Entry e = s.entry;
        if (!id.equals(s.id) && !id.equals(s.loadingId) && (e == null || !e.id.equals(id)))
          continue;
        try {
          checkedPolicy(attributes, s.purpose, origin);
          if (s.purpose == LocalUse.ENCRYPT) {
            Instant stop = protectionStop(attributes);
            Flight loading = s.flight;
            if (stop != null
                && loading != null
                && id.equals(s.loadingId)
                && (loading.protectionStop == null || stop.isBefore(loading.protectionStop)))
              loading.protectionStop = stop;
            if (e != null && id.equals(e.id)) {
              boolean earlier = false;
              synchronized (e) {
                Protection previous = e.protection;
                if (stop != null
                    && (previous.deadline() == null || stop.isBefore(previous.deadline()))) {
                  e.protection = protection(e.validatedWall, stop);
                  earlier = true;
                }
              }
              if (earlier)
                synchronized (s) {
                  if (s.entry == e) schedule(e, s); // Its timer now ends at the earlier deadline.
                }
            }
          }
        } catch (KmsException refusal) {
          refused.put(s, refusal);
          continue;
        }
        // Carry an obligation into unpublished flights too. Publication and seeding use this
        // same lock, so an older attribute snapshot cannot resurrect an unleased copy.
        if (attributes.leaseToObtain() != null) {
          Flight loading = s.flight;
          if (loading != null && id.equals(s.loadingId)) loading.leaseRequired = true;
        }
        // A copy taken without a lease cannot be used once its key states a Lease Time.
        if (e != null
            && id.equals(e.id)
            && !e.lease.required()
            && attributes.leaseToObtain() != null)
          synchronized (s) {
            if (s.entry == e) {
              s.entry = null;
              discard(e);
            }
          }
      }
      refuse(refused, origin);
    }
  }

  private void rejectId(String id, RuntimeException reason, Flight origin) {
    rejectId(id, reason, origin, null);
  }

  /** As {@link #rejectId(String, RuntimeException, Flight)}, for the slots of {@code purpose} only (null: all). */
  private void rejectId(String id, RuntimeException reason, Flight origin, LocalUse purpose) {
    synchronized (membership) {
      if (!current(origin)) return;
      if (origin.owner != write) attributeEpoch++;
      Map<Slot, RuntimeException> refused = new LinkedHashMap<>();
      for (Slot s : slots()) {
        Entry e = s.entry;
        if ((purpose == null || s.purpose == purpose)
            && (id.equals(s.id) || id.equals(s.loadingId) || (e != null && e.id.equals(id))))
          refused.put(s, reason);
      }
      refuse(refused, origin);
    }
  }

  /**
   * Under membership: retires each slot as refused, for its reason. Every copy is dropped first.
   * A retired slot shows its refusal to its calls at once, without membership. So a call that has
   * received the refusal from one slot can find no copy of the key in a slot not yet retired.
   * Publication and seeding wait for membership, so no copy comes back in between.
   */
  private void refuse(Map<Slot, RuntimeException> refused, Flight origin) {
    for (Slot s : refused.keySet())
      synchronized (s) {
        Entry value = s.entry;
        s.entry = null;
        if (value != null) discard(value);
      }
    refused.forEach((s, reason) -> retire(s, Cause.REFUSED, reason, origin));
  }

  // Membership serializes cross-purpose refusals with publication and write-to-read seeding.
  // A reply to a superseded flight cannot invalidate a newer authorization.
  private boolean current(Flight flight) {
    return !closed && !flight.owner.retired && flight.owner.flight == flight;
  }

  private void failed(Slot slot, Flight pending, RuntimeException error) {
    RuntimeException result = error;
    String keyId;
    Duration remaining;
    synchronized (slot) {
      if (slot.flight != pending
          || slot.generation != pending.generation
          || slot.retired
          || closed) {
        pending.done.completeExceptionally(error); // Superseded: not this flight's refresh failure.
        return;
      }
      loadFailures.increment();
      // A definite observation already evicted this value during the same failed refresh.
      if (!definite(error, pending) && slot.failure != null && slot.failureDefinite)
        result = slot.failure;
      boolean refused =
          definite(result, pending) || (result == slot.failure && slot.failureDefinite);
      if (refused) {
        Entry previous = slot.entry;
        slot.entry = null;
        slot.published = false;
        if (previous != null) discard(previous);
      }
      keyId = slot.id != null ? slot.id : slot.loadingId;
      remaining = refused ? Duration.ZERO : remainingValidity(slot.entry);
      if (slot == write) writeFailure = result;
      slot.failure = result;
      slot.failureDefinite = refused;
      slot.retryAt = nanos.getAsLong() + (refused && slot != write ? ttl : backoff);
      slot.flight = null;
      slot.loadingId = null;
    }
    pending.done.completeExceptionally(result);
    signalProgress();
    if (pending.refresh && result instanceof KmsException failure)
      Kms.localKeyRefreshFailed(listenerConfig, name, keyId, slot.purpose, failure, remaining);
  }

  /** Diagnostic only: how much longer {@code value} may be handed out, zero if it cannot. */
  private Duration remainingValidity(Entry value) {
    return Duration.ofNanos(remainingNanos(value, nanos.getAsLong()));
  }

  /**
   * How long after {@code now} {@code value} may still be handed out, in nanoseconds: the earliest
   * of its TTL end, lease end and protection deadline; zero if it cannot be now.
   */
  private long remainingNanos(Entry value, long now) {
    if (!valid(value, now)) return 0;
    long left = value.protection.lifetime() - (now - value.validatedAt);
    if (value.lease.nanos() != Long.MAX_VALUE)
      left = Math.min(left, value.lease.nanos() - (now - value.lease.sent()));
    Instant deadline = value.protection.deadline();
    if (deadline != null) {
      Duration untilDeadline = Duration.between(clock.instant(), deadline);
      if (untilDeadline.compareTo(Duration.ofNanos(left)) < 0)
        left = untilDeadline.isNegative() ? 0 : untilDeadline.toNanos();
    }
    return Math.max(0, left);
  }

  private void ensureCurrent(Slot slot, Flight pending) {
    ensureOpen();
    if (slot.retired || slot.flight != pending || slot.generation != pending.generation)
      throw new Kms.Superseded("Key cache was invalidated during validation; retry");
  }

  private void await(Flight flight) {
    await(flight.done);
  }

  private <T> T await(CompletableFuture<T> future) {
    try {
      return future.get(Math.max(1, Kms.callRemaining(callTimeout)), TimeUnit.NANOSECONDS);
    } catch (InterruptedException e) {
      throw interrupted(e);
    } catch (TimeoutException e) {
      throw deadlinePassed("Call deadline passed waiting for local key", e.getMessage());
    } catch (ExecutionException e) {
      if (e.getCause() instanceof RuntimeException failure) throw failure;
      if (e.getCause() instanceof Error fatal) throw fatal;
      throw transientFailure("Local key validation failed", e.getCause());
    }
  }

  /**
   * Discards every cached purpose for an exact identifier and supersedes its validations in
   * progress. A call for that identifier still in progress fails with a {@link
   * TransientException}, and may be retried. Invalidating the selected write key also makes the
   * next {@link #forEncrypt()} select again. It also clears the cached failure and connection
   * backoff.
   *
   * @param id the exact identifier; not null
   * @throws IllegalStateException when closed
   */
  public void invalidate(String id) {
    Objects.requireNonNull(id, "id");
    ensureOpen();
    if (connection != null) connection.clearFailure();
    synchronized (membership) {
      attributeEpoch++;
      synchronized (admissionLock) {
        Admission admission = admissions.remove(id);
        if (admission != null) admission.invalidated = true;
      }
      for (LocalUse purpose : List.of(LocalUse.DECRYPT, LocalUse.ENCRYPT)) {
        Slot exact = reads.remove(new SlotKey(id, purpose));
        if (exact != null) retire(exact, Cause.INVALIDATED, null, null);
      }
      synchronized (write) {
        if ((write.fingerprint != null && id.equals(write.fingerprint.id()))
            || id.equals(write.loadingId)) {
          write.fingerprint = null;
          retire(write, Cause.INVALIDATED, null, null);
        }
      }
    }
    signalProgress(); // The invalidated ID may have only a capacity waiter, no slot yet.
  }

  /** Clears all entries, negative answers and selections, and supersedes all in-flight loads. */
  public void invalidateAll() {
    ensureOpen();
    if (connection != null) connection.clearFailure();
    clear(Cause.INVALIDATED);
  }

  /**
   * The write identifier currently cached within its TTL and protection deadline, without sending a request or
   * starting a refresh. Empty before a successful selection, after expiry or after refusal.
   * This is a diagnostic snapshot, not a barrier proving all nodes selected a replacement.
   *
   * @return the cached identifier, if valid
   * @throws IllegalStateException when closed
   */
  public Optional<String> currentWriteId() {
    ensureOpen();
    Entry value = write.entry;
    return valid(value, nanos.getAsLong()) ? Optional.of(value.id) : Optional.empty();
  }

  /**
   * The write key name this cache selects by, as its {@link KmsListener} events name it ({@link
   * KmsListener#localKeySelected}).
   *
   * @return the name
   * @since 0.10.0
   */
  public String name() {
    return name;
  }

  /**
   * How long {@link #forEncrypt()} can still hand out the write key it holds without the KMS: the
   * earliest of its TTL end, its lease end and its protection deadline. Sends no request and
   * starts no refresh. A diagnostic for metrics and alerts, never an authorization.
   *
   * <p>A cache in use renews the write key at {@link Builder#refreshAfter(Duration)}, or at half
   * its lease if sooner. Once refreshes fail the figure falls, and writes stop at zero. An unused
   * cache is not refreshed, so its figure also runs down, without any failure. Alarm when it falls
   * below the time you need to restore the KMS while {@link #writeFailure()} is present (see
   * <a href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/local-keys.md#alarms-before-keys-stop">Alarms
   * before keys stop</a>). The result is an {@code Optional}, never empty, only to match the other
   * {@code usableFor()} methods.
   *
   * @return the time left, never empty; {@link Duration#ZERO} when no valid write key is cached,
   *     after {@link #close()} or once the {@link Kms} it uses is closed
   * @since 0.10.0
   */
  public Optional<Duration> usableFor() {
    Kms ready = kms;
    if (closed || (connection != null && connection.closed()) || (ready != null && ready.closed()))
      return Optional.of(Duration.ZERO);
    return Optional.of(remainingValidity(write.entry));
  }

  /**
   * The failure of the write key's last validation, a background refresh or a load at {@link
   * #forEncrypt()}, as its caller or {@link KmsListener#localKeyRefreshFailed} saw it. Read from
   * memory, without a request. Empty before the first validation, once a later one succeeds, and after {@link
   * #invalidate} of the write key, {@link #invalidateAll()} or {@link #close()}.
   *
   * <p>Poll it beside {@link #usableFor()}. On a cache nobody uses, {@code usableFor()} runs down
   * while this stays empty. Retries suppressed by the backoff do not change it. Historical entries
   * ({@link #forDecrypt}, {@link #forAppend}) are not reflected here. A diagnostic, never an
   * authorization.
   *
   * @return the write key's last validation failure (usually a {@link KmsException}); empty when
   *     the last one succeeded or none has run
   * @since 0.10.0
   */
  public Optional<RuntimeException> writeFailure() {
    return Optional.ofNullable(writeFailure);
  }

  /**
   * A {@link LocalKeys} cache's counters since it opened, for metrics: SDK-owned values, read from
   * memory without a request, cheap enough to poll. Each counter only grows; {@link #size()} is a
   * snapshot. Only the SDK creates them. Immutable.
   *
   * @since 0.10.0
   */
  public static final class Stats {
    private final long encryptHits, encryptMisses, decryptHits, decryptMisses;
    private final long loads, loadFailures, evictions, capacityWaits;
    private final int size;

    Stats(
        long encryptHits,
        long encryptMisses,
        long decryptHits,
        long decryptMisses,
        long loads,
        long loadFailures,
        long evictions,
        long capacityWaits,
        int size) {
      this.encryptHits = encryptHits;
      this.encryptMisses = encryptMisses;
      this.decryptHits = decryptHits;
      this.decryptMisses = decryptMisses;
      this.loads = loads;
      this.loadFailures = loadFailures;
      this.evictions = evictions;
      this.capacityWaits = capacityWaits;
      this.size = size;
    }

    /**
     * Handouts for encryption ({@link #forEncrypt()}, {@link #forAppend}) served from a valid
     * cached entry.
     *
     * @return the count
     */
    public long encryptHits() {
      return encryptHits;
    }

    /**
     * Handouts for encryption that had to load first, or wait for a load already running.
     *
     * @return the count
     */
    public long encryptMisses() {
      return encryptMisses;
    }

    /**
     * Handouts for {@link #forDecrypt} served from a valid cached entry.
     *
     * @return the count
     */
    public long decryptHits() {
      return decryptHits;
    }

    /**
     * Handouts for {@link #forDecrypt} that had to load first, or wait for a load already running.
     *
     * @return the count
     */
    public long decryptMisses() {
      return decryptMisses;
    }

    /**
     * Loads that succeeded: first loads, background refreshes and renewals ({@link
     * KmsListener#localKeyLoaded}).
     *
     * @return the count
     */
    public long loads() {
      return loads;
    }

    /**
     * Loads that failed: refreshes ({@link KmsListener#localKeyRefreshFailed}), and first loads
     * whose caller got the failure.
     *
     * @return the count
     */
    public long loadFailures() {
      return loadFailures;
    }

    /**
     * Cached keys removed for the capacity bound, or because their TTL, lease or protection
     * deadline ended before a refresh renewed them. Removals for an invalidation, a refusal, a
     * replacement or {@link #close()} are not counted.
     *
     * @return the count
     */
    public long evictions() {
      return evictions;
    }

    /**
     * Calls that waited for capacity ({@link Builder#capacity}).
     *
     * @return the count
     */
    public long capacityWaits() {
      return capacityWaits;
    }

    /**
     * The cached keys held now, the write key's included; remembered refusals are not counted.
     *
     * @return the number of cached keys
     */
    public int size() {
      return size;
    }

    @Override
    public String toString() {
      return "LocalKeys.Stats[encrypt "
          + encryptHits
          + " hits/"
          + encryptMisses
          + " misses, decrypt "
          + decryptHits
          + "/"
          + decryptMisses
          + ", loads "
          + loads
          + ", failures "
          + loadFailures
          + ", evictions "
          + evictions
          + ", capacity waits "
          + capacityWaits
          + ", size "
          + size
          + "]";
    }
  }

  /**
   * This cache's counters since it opened ({@link Stats}). Sends no request; also after {@link
   * #close()}, which keeps the counters and holds no entries.
   *
   * @return the counters now
   * @since 0.10.0
   */
  public Stats stats() {
    int size = 0;
    for (Slot s : slots()) if (s.entry != null) size++;
    return new Stats(
        encryptHits.sum(),
        encryptMisses.sum(),
        decryptHits.sum(),
        decryptMisses.sum(),
        loads.sum(),
        loadFailures.sum(),
        evictions.sum(),
        capacityWaits.sum(),
        size);
  }

  /** Tests: calls waiting for historical capacity. */
  int capacityWaiters() {
    return capacityWaiters.get();
  }

  /** Tests: the hits told to Caffeine's eviction order, at most one per slot a millisecond. */
  long hitsRecorded() {
    return hitsRecorded.sum();
  }

  /** Tests: the historical slots' identifiers in Caffeine's eviction order, coldest first. */
  List<String> evictionOrder() {
    List<String> ids = new ArrayList<>();
    for (SlotKey k : readPolicy.eviction().orElseThrow().coldest(capacity).keySet())
      ids.add(k.id());
    return ids;
  }

  /** Tests: running expiry timers, one per published entry. */
  long timers() {
    return timers.estimatedSize();
  }

  /** Tests: retained historical and negative entries, excluding the write slot. */
  int historicalSlots() {
    return reads.size();
  }

  private void clear(Cause cause) {
    synchronized (membership) {
      attributeEpoch++;
      synchronized (admissionLock) {
        for (Admission admission : admissions.values()) admission.invalidated = true;
        admissions.clear();
      }
      synchronized (write) {
        write.fingerprint = null;
        retire(write, cause, null, null);
      }
      for (Slot s : reads.values()) retire(s, cause, null, null);
      reads.clear();
    }
    signalProgress();
  }

  /**
   * Drops the slot's entry and supersedes any validation other than {@code origin}. Historical
   * slots leave the cache unless refused; a refusal (non-null {@code reason}) is cached for the TTL,
   * except for the write selection, which reselects by name.
   */
  private void retire(Slot slot, Cause cause, RuntimeException reason, Flight origin) {
    synchronized (slot) {
      Entry value = slot.entry;
      slot.entry = null;
      if (value != null) discard(value);
      slot.retired |= slot != write && cause != Cause.REFUSED;
      slot.published = false;
      slot.cause = cause;
      slot.displacedBy = reason;
      // Calls in progress see these; a write refusal only makes them reselect by name.
      if (cause != Cause.CAPACITY && (slot != write || cause != Cause.REFUSED)) slot.displaced++;
      // An ID's refusal invalidates the write selection; the next call must reselect by name.
      slot.failure = slot == write ? null : reason;
      slot.failureDefinite = reason != null && slot != write;
      // An explicit invalidation or close starts over: no validation has failed since
      // (writeFailure()).
      if (slot == write && (cause == Cause.INVALIDATED || cause == Cause.CLOSED))
        writeFailure = null;
      if (reason != null && slot != write) slot.retryAt = nanos.getAsLong() + ttl;
      if (slot.flight == null || slot.flight != origin) {
        slot.generation++;
        Flight flight = slot.flight;
        slot.flight = null;
        slot.loadingId = null;
        if (flight != null)
          flight.done.completeExceptionally(
              cause == Cause.CLOSED
                  ? new IllegalStateException("Local key cache closed")
                  : slot == write
                      ? transientFailure(
                          "Write-key selection invalidated during validation; reselect and retry",
                          reason)
                      : reason != null
                          ? reason
                          : transientFailure(
                              "Local key entry invalidated during validation; retry", null));
      }
    }
    signalProgress();
  }

  private List<Slot> slots() {
    List<Slot> all = new ArrayList<>(reads.values());
    all.add(write);
    return all;
  }

  /**
   * Wipes the entries whose TTL, lease or protection deadline has ended, at most once per update
   * interval or second (always when {@code force}): Caffeine's timer wheel names them ({@link
   * #timers}), so the cost is the expired entries, not every slot.
   */
  private void sweep(boolean force) {
    long now = nanos.getAsLong(), due = nextSweep.get();
    if (!force
        && (now - due < 0
            || !nextSweep.compareAndSet(due, now + Math.min(update, TimeUnit.SECONDS.toNanos(1)))))
      return;
    if (now - nextTimer.get() < 0 && expired.isEmpty()) return; // No timer can have ended.
    timerTime.accumulateAndGet(now, Math::max);
    nextTimer.set(now + Long.MAX_VALUE / 4); // Lowered by any schedule from here on.
    timers.cleanUp();
    // The soonest timer still running. One started since is in Caffeine's order or lowered it.
    Policy.VarExpiration<Entry, Slot> order = timers.policy().expireVariably().orElseThrow();
    for (Entry next : order.oldest(1).keySet())
      order
          .getExpiresAfter(next, TimeUnit.NANOSECONDS)
          .ifPresent(left -> nextTimer.accumulateAndGet(now + left, Math::min));
    for (Expired x; (x = expired.poll()) != null; ) {
      Slot s = x.slot();
      Entry e = x.entry();
      synchronized (s) {
        if (s.entry != e) continue; // Already replaced or retired, and discarded then.
        if (valid(e, now)) {
          schedule(e, s); // Not yet: its wall-clock deadline moved, say.
          continue;
        }
        discard(e);
        s.entry = null;
        evictions.increment();
      }
    }
  }

  /** Under the slot's lock: (re)starts {@code entry}'s timer, at the time this cache last read. */
  private void schedule(Entry entry, Slot slot) {
    long now = timerTime.accumulateAndGet(nanos.getAsLong(), Math::max);
    // The timer first, then the bound: a sweep that raised the bound before this lowers it either
    // sees the timer in Caffeine's order or is followed by the lowering. The other order let a
    // sweep raise the bound after it was lowered, before the timer was in the order, so no later
    // sweep looked until another schedule: the expired key stayed unwiped.
    timers.put(entry, slot);
    nextTimer.accumulateAndGet(now + remainingNanos(entry, now), Math::min);
  }

  /** Wipes a published entry and stops its timer. */
  private void discard(Entry entry) {
    entry.destroy();
    timers.invalidate(entry);
  }

  private void ensureOpen() {
    if (closed) throw new IllegalStateException("Local key cache closed");
    if (connection != null) connection.ensureOpen();
    Kms ready = kms;
    if (ready != null) ready.ensureOpen();
  }

  private void connectIfNeeded() {
    if (kms != null) {
      ensureOpen();
      return;
    }
    Connection c = connection;
    CompletableFuture<Kms> pending;
    CallContext context;
    boolean open = false;
    synchronized (c) {
      ensureOpen();
      Kms ready = c.kms;
      if (ready != null) { // Another cache of a SharedKms connected it.
        connected(ready);
        return;
      }
      if (c.failure != null
          && nanos.getAsLong() - c.failedAt - (c.failureDefinite ? ttl : backoff) < 0) {
        long retryAt = c.failedAt + (c.failureDefinite ? ttl : backoff);
        throw c.failureDefinite ? c.failure : duringBackoff(c.failure, null, retryAt, "connection");
      }
      pending = c.connecting;
      if (pending == null) {
        pending = new CompletableFuture<>();
        c.connecting = pending;
        c.context = Kms.callContext(callTimeout);
        open = true;
      }
      context = c.context;
    }
    if (open) {
      Kms opened = null;
      try {
        opened = Kms.connectForCall(c.config, context);
        synchronized (c) {
          c.ensureOpen();
          c.kms = opened;
          c.connecting = null;
          c.context = null;
          c.failure = null;
        }
        pending.complete(opened);
        opened = null;
      } catch (RuntimeException failure) {
        if (opened != null) opened.close();
        synchronized (c) {
          if (!c.closed) {
            c.failure = failure;
            c.failureDefinite = definite(failure, null) || failure instanceof UnsupportedException;
            c.failedAt = nanos.getAsLong();
            c.connecting = null;
            c.context = null;
          }
        }
        pending.completeExceptionally(failure);
      } catch (Error fatal) {
        if (opened != null) opened.close();
        synchronized (c) {
          c.connecting = null;
          c.context = null;
        }
        pending.completeExceptionally(fatal);
        throw fatal;
      }
    }
    // This cache's close() also ends the wait, without ending a shared attempt.
    await(pending.applyToEither(closing, ready -> ready));
    ensureOpen();
    connected(pending.join());
  }

  private void connected(Kms ready) {
    keys = ready.keys();
    kms = ready;
    ensureOpen();
  }

  /**
   * Wipes retained material, supersedes loads and stops the owned refresh executor; idempotent.
   * A cache built from configuration also cancels negotiation and closes its owned KMS.
   * A caller-owned KMS, a {@link SharedKms} or a refresh executor is left open; a call of this
   * cache waiting for a {@code SharedKms}'s connection attempt stops, and the attempt goes on. Copies already handed out in a {@link
   * Use}, or taken by a JCA cipher, are not wiped.
   */
  @Override
  public void close() {
    closed = true;
    closing.completeExceptionally(new IllegalStateException("Local key cache closed"));
    if (ownsConnection) connection.close("Local key cache closed");
    clear(Cause.CLOSED);
    if (owned != null) owned.shutdownNow();
  }

  private static long duration(Duration value, String name) {
    Objects.requireNonNull(value, name);
    try {
      long result = value.toNanos();
      if (result <= 0 || result > Long.MAX_VALUE / 4)
        throw new IllegalArgumentException(name + " is outside the supported positive range");
      return result;
    } catch (ArithmeticException e) {
      throw new IllegalArgumentException(name + " is too long", e);
    }
  }

  /** Of an entry not yet published, so not destroyed. */
  private static byte[] fingerprint(Entry entry) {
    byte[] bytes = entry.encoded();
    try {
      return MessageDigest.getInstance("SHA-256").digest(bytes);
    } catch (NoSuchAlgorithmException impossible) {
      throw new AssertionError(impossible);
    } finally {
      Arrays.fill(bytes, (byte) 0);
    }
  }

  /** Keeps the thread's interrupt status. */
  private static TransientException interrupted(InterruptedException e) {
    Thread.currentThread().interrupt();
    InterruptedIOException cause = new InterruptedIOException("Interrupted waiting for local key");
    if (e != null) cause.initCause(e);
    return transientFailure(cause.getMessage(), cause);
  }

  private static TransientException deadlinePassed(String message, String detail) {
    return transientFailure(message, new SocketTimeoutException(detail != null ? detail : message));
  }

  private static TransientException transientFailure(String message, Throwable cause) {
    return new TransientException(message, cause, OP, null, null, null);
  }

  private RuntimeException duringBackoff(
      RuntimeException failure, String id, long retryAt, String target) {
    Duration remaining = Duration.ofNanos(Math.max(0, retryAt - nanos.getAsLong()));
    return new TransientException(
        "Failing fast during "
            + target
            + " retry backoff (remaining "
            + remaining
            + "); last failure: "
            + failure.getMessage(),
        failure,
        OP,
        id,
        failure instanceof KmsException k ? k.result().orElse(null) : null,
        failure instanceof KmsException k ? k.response().orElse(null) : null);
  }

  private void checkedPolicy(KeyAttributes attributes, LocalUse purpose, Flight origin) {
    try {
      check(attributes, purpose);
    } catch (KmsException refusal) {
      origin.policyRefusal = refusal;
      throw refusal;
    }
  }

  private static boolean definite(RuntimeException error, Flight origin) {
    return error instanceof NotFoundException
        || definiteDenial(error)
        || error instanceof KeyMismatchException
        || (error instanceof StateConflictException s && s.observedState().isPresent())
        || (origin != null && error == origin.policyRefusal);
  }

  private static boolean definiteDenial(RuntimeException error) {
    return error instanceof PermissionDeniedException denied
        && !(denied.result().isEmpty() && Failures.serverNotTrusted(denied));
  }
}
