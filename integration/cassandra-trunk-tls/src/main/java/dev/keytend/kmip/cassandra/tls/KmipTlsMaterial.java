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

package dev.keytend.kmip.cassandra.tls;

import dev.keytend.kmip.kms.CustomAttribute;
import dev.keytend.kmip.kms.KeyQuery;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.TlsIdentity;
import dev.keytend.kmip.kms.TlsIdentityFollower;
import dev.keytend.kmip.kms.TlsTrustFollower;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509ExtendedTrustManager;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.utils.NoSpamLogger;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A node's TLS material held in a KMIP server, followed in the background by the SDK ({@code
 * kms.tls()}):
 *
 * <ul>
 *   <li>its identity: the TLS identity named {@code kmip_tls_identity} (a private key and its
 *       certificate chain, registered, renewed and re-keyed as one);
 *   <li>trust anchors: every Active certificate whose custom attribute {@value #TAG_NAME} is {@code
 *       <domain>:ca};
 *   <li>registered peers: every Active certificate whose {@value #TAG_NAME} is {@code
 *       <domain>:identity}, node identities included. With {@code
 *       kmip_tls_require_registered_peers} (default true) only those are accepted.
 * </ul>
 *
 * The SDK's key and trust managers read the current material at each handshake, from memory, so a
 * change takes effect for new connections without a new context; {@link #version()} also tells
 * Cassandra's hot reloading to rebuild its cached contexts. While the KMS cannot be reached, the
 * last material stays in use while its KMIP leases run: {@link #usableFor()} says for how long.
 *
 * <p><b>Lifecycle.</b> Cassandra gives SSL context factories and certificate validators no
 * shutdown call, so the material lives in a static registry, one per distinct configuration, with
 * its own daemon refresh threads. {@link #closeAll()} closes everything (embedders, tests);
 * otherwise it ends with the JVM. The refresh threads are the sample's, not the caller's, as the
 * SDK's own threads are: they are in the {@value #THREAD_GROUP} thread group (under the root group,
 * not in the group of whichever Cassandra thread first loads the material), have no context class
 * loader, and do not inherit the caller's inheritable thread-locals.
 */
public final class KmipTlsMaterial {
  private static final Logger logger = LoggerFactory.getLogger(KmipTlsMaterial.class);
  private static final NoSpamLogger noSpam = NoSpamLogger.getLogger(logger, 1, TimeUnit.MINUTES);

  public static final String IDENTITY = "kmip_tls_identity";
  public static final String DOMAIN = "kmip_tls_domain";
  public static final String REFRESH_INTERVAL = "kmip_tls_refresh_interval";
  public static final String REQUIRE_REGISTERED_PEERS = "kmip_tls_require_registered_peers";
  public static final String UNKNOWN_PEER_CHECK = "kmip_tls_unknown_peer_check";
  public static final String UNKNOWN_PEER_CHECK_IN_HANDSHAKE = "kmip_tls_unknown_peer_check_in_handshake";
  public static final String UNKNOWN_PEER_CHECK_PER_CERTIFICATE = "kmip_tls_unknown_peer_check_per_certificate";
  public static final String UNKNOWN_PEER_CHECK_GAP = "kmip_tls_unknown_peer_check_gap";
  public static final String UNKNOWN_PEER_CHECK_QUEUE = "kmip_tls_unknown_peer_check_queue";
  public static final String USABLE_WARN = "kmip_tls_usable_warn";
  private static final List<String> KEYS =
      List.of(IDENTITY, DOMAIN, REFRESH_INTERVAL, REQUIRE_REGISTERED_PEERS, UNKNOWN_PEER_CHECK,
              UNKNOWN_PEER_CHECK_IN_HANDSHAKE, UNKNOWN_PEER_CHECK_PER_CERTIFICATE, UNKNOWN_PEER_CHECK_GAP,
              UNKNOWN_PEER_CHECK_QUEUE, USABLE_WARN);

  public static final String TAG_NAME = "cassandra-tls";
  public static final CustomAttribute TAG = CustomAttribute.client(TAG_NAME);

  private static final Map<Map<String, String>, KmipTlsMaterial> registry = new ConcurrentHashMap<>();

  /** The refresh threads' group, a child of the root group. */
  static final String THREAD_GROUP = "keytend-kmip-cassandra-tls";
  private static ThreadGroup threads; // guarded by the class

  /**
   * The {@value #THREAD_GROUP} group, found by name among the root group's subgroups (so class
   * loaders that each load this class, as in-JVM dtest nodes do, share one) or made there at the
   * first refresh thread; null, which gives a thread the group a SecurityManager chooses, where one
   * refuses it.
   */
  private static synchronized ThreadGroup threadGroup() {
    if (threads != null) return threads;
    try {
      ThreadGroup root = Thread.currentThread().getThreadGroup();
      while (root.getParent() != null) root = root.getParent();
      synchronized (root) {
        ThreadGroup[] groups = new ThreadGroup[root.activeGroupCount() + 8];
        int n = root.enumerate(groups, false);
        for (int i = 0; i < n && threads == null; i++)
          if (THREAD_GROUP.equals(groups[i].getName())) threads = groups[i];
        if (threads == null) threads = new ThreadGroup(root, THREAD_GROUP);
      }
    } catch (SecurityException refused) {
      return null;
    }
    return threads;
  }

  /**
   * A refresh thread: a daemon in {@link #THREAD_GROUP}, with no context class loader and none of
   * the creating thread's inheritable thread-locals, so a node's thread group, class loader and
   * logging context are not held by it (an in-JVM dtest checks that a node leaves no thread in its
   * group).
   */
  static Thread refreshThread(Runnable r, String name) {
    Thread t = new Thread(threadGroup(), r, name, 0, false);
    t.setDaemon(true);
    t.setContextClassLoader(null);
    return t;
  }

  private final String identityName;
  private final ScheduledThreadPoolExecutor refresher;
  private final TlsIdentityFollower identity;
  private final TlsTrustFollower trust;
  private final boolean registeredOnly;
  private final AtomicLong version = new AtomicLong();
  private final Duration warnBelow; // null: a quarter of the longest usableFor seen
  private volatile Optional<TlsIdentity> presented;
  private Duration longest = Duration.ZERO; // guarded by this
  private volatile boolean warning;

  private KmipTlsMaterial(Map<String, ?> parameters) {
    identityName = KmipConnections.require(parameters, IDENTITY);
    String domain = KmipConnections.require(parameters, DOMAIN);
    registeredOnly = Boolean.parseBoolean(KmipConnections.get(parameters, REQUIRE_REGISTERED_PEERS, "true"));
    Duration interval = KmipConnections.duration(parameters, REFRESH_INTERVAL, "60s");
    Duration check = KmipConnections.duration(parameters, UNKNOWN_PEER_CHECK, "2s");
    boolean checkInHandshake =
        Boolean.parseBoolean(KmipConnections.get(parameters, UNKNOWN_PEER_CHECK_IN_HANDSHAKE, "false"));
    // The SDK's defaults, named here so the README's table is what runs.
    Duration perCertificate = KmipConnections.duration(parameters, UNKNOWN_PEER_CHECK_PER_CERTIFICATE, "30s");
    Duration gap = KmipConnections.duration(parameters, UNKNOWN_PEER_CHECK_GAP, "1s");
    String queueValue = KmipConnections.get(parameters, UNKNOWN_PEER_CHECK_QUEUE, "64");
    int queue;
    try {
      queue = Integer.parseInt(queueValue);
    } catch (NumberFormatException e) {
      throw new ConfigurationException("KMIP parameter " + UNKNOWN_PEER_CHECK_QUEUE + " is not a number: " + queueValue, e);
    }
    if (queue < 1)
      throw new ConfigurationException("KMIP parameter " + UNKNOWN_PEER_CHECK_QUEUE + " must be positive: " + queueValue);
    warnBelow = KmipConnections.get(parameters, USABLE_WARN, null) == null
        ? null : KmipConnections.duration(parameters, USABLE_WARN, null);
    Kms kms = KmipConnections.get(parameters);
    // Two threads, so that a check of an unknown peer does not queue behind a slow identity refresh.
    refresher = new ScheduledThreadPoolExecutor(2, r -> refreshThread(r, "KmipTlsRefresh:" + identityName));
    refresher.setRemoveOnCancelPolicy(true);
    TlsIdentityFollower id = null;
    try {
      id = kms.tls().follow(identityName, interval, refresher);
      KeyQuery anchors = tagged(domain, "ca");
      trust = registeredOnly
          ? kms.tls().trustAnchors(anchors, tagged(domain, "identity"), interval, refresher)
          : kms.tls().trustAnchors(anchors, interval, refresher);
    } catch (RuntimeException e) { // a KmsException, or IllegalStateException when the Kms was closed
      if (id != null) id.close();
      refresher.shutdownNow();
      throw new ConfigurationException(
          "Cannot load TLS identity " + identityName + " from the KMS: " + KmipConnections.describe(e), e);
    }
    identity = id;
    if (trust.anchors().isEmpty()) {
      close();
      throw new ConfigurationException("The KMS has no Active trust anchor tagged " + TAG_NAME + '=' + domain + ":ca");
    }
    // In the background by default: a handshake (on a Netty event loop) never waits for the KMS.
    trust.unknownPeerCheck(check).unknownPeerCheckInHandshake(checkInHandshake)
        .unknownPeerCheckPerCertificate(perCertificate).unknownPeerCheckGap(gap).unknownPeerCheckQueue(queue);
    presented = identity.identity();
    logger.info("TLS material of {} loaded: {}", identityName, this);
    identity.onChange(state -> {
      if (!state.identity().equals(presented)) {
        presented = state.identity();
        version.incrementAndGet();
      } // else a status change alone (a KMS outage: STALE) needs no new context
      logger.info("TLS identity {} is now {}; usable for {} without the KMS", identityName, state,
                  usable(identityUsableFor()));
      checkUsable();
    });
    trust.onChange(() -> {
      version.incrementAndGet();
      logger.info("TLS trust anchors or registered peers of {} changed; {}", domain, this);
      checkUsable();
    });
    long every = Math.max(1000, Math.min(interval.toMillis(), 10_000));
    refresher.scheduleWithFixedDelay(this::checkUsable, every, every, TimeUnit.MILLISECONDS);
    checkUsable();
  }

  static KeyQuery tagged(String domain, String role) {
    return KeyQuery.all().custom(TAG, domain + ':' + role);
  }

  /** The shared material for these parameters, loading it on first use. */
  public static KmipTlsMaterial get(Map<String, ?> parameters) {
    Map<String, String> key = new TreeMap<>(KmipConnections.connectionParameters(parameters));
    for (String name : KEYS) {
      String value = KmipConnections.get(parameters, name, null);
      if (value != null) key.put(name, value);
    }
    return registry.computeIfAbsent(key, ignored -> new KmipTlsMaterial(parameters));
  }

  /** Every material loaded in this process (for the certificate validator, and metrics). */
  public static Collection<KmipTlsMaterial> all() {
    return registry.values();
  }

  /**
   * The least {@link #usableFor()} of every material loaded: how long until the first TLS material
   * of this node stops being usable if the KMS stays unreachable. A metric for operators; empty
   * when no lease limits any of it (or nothing is loaded).
   */
  public static Optional<Duration> minUsableFor() {
    return all().stream().map(KmipTlsMaterial::usableFor).flatMap(Optional::stream).min(Duration::compareTo);
  }

  /** Closes every material and the shared KMS connections; factories made before then present nothing. */
  public static void closeAll() {
    registry.values().forEach(KmipTlsMaterial::close);
    registry.clear();
    KmipConnections.closeAll();
  }

  private void close() {
    if (identity != null) identity.close();
    if (trust != null) trust.close();
    refresher.shutdownNow();
  }

  /** Changes each time the identity presented, the trust anchors or the registered peers change. */
  public long version() {
    return version.get();
  }

  public Optional<X509Certificate> certificate() {
    return identity.identity().map(TlsIdentity::certificate);
  }

  public TlsIdentityFollower.Status status() {
    return identity.status();
  }

  public X509ExtendedKeyManager keyManager() {
    return identity.keyManager();
  }

  public X509ExtendedTrustManager trustManager() {
    return trust.trustManager();
  }

  /**
   * Whether {@code chain} is trusted now, from memory: it validates against the trust anchors, and
   * (with registered peers required) its first certificate is an Active registered peer.
   */
  public boolean allows(X509Certificate[] chain) {
    return trust.allows(chain);
  }

  /** Whether only registered peers are accepted ({@code kmip_tls_require_registered_peers}). */
  public boolean requiresRegisteredPeers() {
    return registeredOnly;
  }

  /** How long the identity presented now stays usable without the KMS; empty: no lease limits it. */
  public Optional<Duration> identityUsableFor() {
    return identity.usableFor();
  }

  /** How long the anchors and registered peers trusted now stay usable without the KMS; empty: no limit. */
  public Optional<Duration> trustUsableFor() {
    return trust.usableFor();
  }

  /**
   * The lesser of {@link #identityUsableFor()} and {@link #trustUsableFor()}, with the SDK's meaning:
   * empty when neither is limited, zero when nothing is usable now.
   */
  public Optional<Duration> usableFor() {
    Optional<Duration> a = identityUsableFor(), b = trustUsableFor();
    if (a.isEmpty()) return b;
    return b.isEmpty() || a.get().compareTo(b.get()) <= 0 ? a : b;
  }

  /** Whether {@link #usableFor()} was below {@code kmip_tls_usable_warn} at the last check. */
  public boolean usableWarning() {
    return warning;
  }

  /** The warning threshold in force: as configured, else a quarter of the longest usableFor seen. */
  public synchronized Duration usableWarnThreshold() {
    return warnBelow != null ? warnBelow : longest.dividedBy(4);
  }

  /** Reads the identity, anchors and registered peers from the KMS now (tests, operator tools). */
  public void refresh() {
    identity.refresh();
    trust.refresh();
  }

  /** Warns, at most once a minute, while the material would stop within the threshold. */
  synchronized void checkUsable() {
    Optional<Duration> left = usableFor();
    left.filter(d -> d.compareTo(longest) > 0).ifPresent(d -> longest = d);
    Duration threshold = usableWarnThreshold();
    boolean below = left.isPresent() && !threshold.isZero() && left.get().compareTo(threshold) < 0;
    if (below)
      noSpam.warn("TLS material of {} is usable for only {} more without the KMS (warning below {}): {}",
                  identityName, left.get(), threshold, this);
    else if (warning) logger.info("TLS material of {} is usable again: {}", identityName, this);
    warning = below;
  }

  @Override
  public String toString() {
    TlsIdentityFollower.State s = identity.state();
    String presenting = s.identity().map(i -> "serial " + i.certificate().getSerialNumber().toString(16)).orElse("nothing");
    return "identity " + identityName + " " + s.status() + " presenting " + presenting + ", usable for "
        + usable(identityUsableFor()) + "; trust " + trust + ", usable for " + usable(trustUsableFor())
        + trust.failure().map(f -> " (last refresh failed: " + KmipConnections.describe(f) + ')').orElse("");
  }

  private static String usable(Optional<Duration> d) {
    return d.map(Duration::toString).orElse("no lease limit");
  }
}
