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

import static dev.keytend.kmip.kms.samples.TdeKeyProvider.decryptSegment;
import static dev.keytend.kmip.kms.samples.TdeKeyProvider.encryptSegment;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.LeasingTransport.Grant;
import dev.keytend.kmip.kms.LocalKeysTest.QueueExecutor;
import dev.keytend.kmip.kms.samples.TdeKeyProvider;
import dev.keytend.kmip.kms.samples.TdeKeyProvider.AliasCodec;
import dev.keytend.kmip.kms.samples.TdeKeyProvider.KeyForFile;
import dev.keytend.kmip.kms.samples.TdeKeyProvider.KeyProvider;
import dev.keytend.kmip.kms.samples.TdeKeyProvider.KeyUnavailableException;
import dev.keytend.kmip.kms.samples.TdeKeyProvider.KmipKeyProvider;
import dev.keytend.kmip.kms.samples.TdeKeyProvider.NodeKeys;
import dev.keytend.kmip.kms.samples.TdeKeyProvider.Replay;
import dev.keytend.kmip.kms.samples.TdeKeyProvider.Segment;
import dev.keytend.kmip.kms.samples.TdeKeyProvider.Settings;
import dev.keytend.kmip.kms.samples.TdeKeyProvider.TdeOptions;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Sample A8, {@link TdeKeyProvider}: a Cassandra-style {@code KeyProvider} on {@link LocalKeys},
 * on KMIP 1.4, 2.1 and 3.0, through {@link LeasingTransport}, which states Lease Times and answers
 * Obtain Lease as keytend-kmip-server does. Each node's cache runs on the test's ticker, and its refresh
 * work only when the test runs it.
 */
class TdeKeyProviderTest {
  static final String NAME = "cassandra-tde";
  static final byte[] A = "segment under the first key".getBytes(StandardCharsets.UTF_8);
  static final byte[] B = "segment under the second key".getBytes(StandardCharsets.UTF_8);

  /** A back-off below the 100 ms floor, without jitter: every wait is the floor. */
  static final RetryPolicy QUICK =
      RetryPolicy.builder()
          .initialBackoff(Duration.ofMillis(1))
          .maxBackoff(Duration.ofMillis(1))
          .jitter(0)
          .build();

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();
  final List<NodeKeys> nodes = new CopyOnWriteArrayList<>();
  final AtomicLong time = new AtomicLong(100);
  final QueueExecutor refresh = new QueueExecutor();

  @AfterEach
  void cleanUp() {
    nodes.forEach(NodeKeys::stop);
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) {
      assertEquals(List.of(), s.violations());
      s.close();
    }
  }

  InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    servers.add(s);
    return s;
  }

  /** The coordinator's own connection, straight to the server: provisioning, rotation, retirement. */
  Kms coordinator(InMemoryKmipServer s) {
    Kms kms = s.connect();
    clients.add(kms);
    return kms;
  }

  /** A node's connection configuration: through {@code leasing}. */
  static KmsConfig.Builder nodeConfig(LeasingTransport leasing) {
    return leasing
        .server
        .configure()
        .retryPolicy(RetryPolicy.none())
        .callTimeout(Duration.ofSeconds(5))
        .transport(endpoint -> leasing);
  }

  /** {@link NodeKeys#start(String, KmsConfig, Settings)}, with the test's ticker and refresh executor. */
  NodeKeys start(String node, KmsConfig config) {
    LocalKeys.Builder b = Settings.of(NAME).localKeys(config).refreshExecutor(refresh);
    b.ticker = time::get;
    NodeKeys keys = NodeKeys.start(node, NAME, b.open());
    nodes.add(keys);
    return keys;
  }

  NodeKeys start(String node, LeasingTransport leasing) {
    return start(node, nodeConfig(leasing).build());
  }

  void advance(long seconds) {
    time.addAndGet(TimeUnit.SECONDS.toNanos(seconds));
  }

  /** Runs the refresh work the cache queued. */
  void runRefreshes() {
    while (!refresh.queue.isEmpty()) refresh.run();
  }

  /** A provider as the database makes one: reflectively, from its options. */
  static KeyProvider provider(String node, String configuredAlias)
      throws ReflectiveOperationException {
    TdeOptions options = new TdeOptions(configuredAlias, Map.of(KmipKeyProvider.NODE_KEYS, node));
    try {
      return KmipKeyProvider.class.getConstructor(TdeOptions.class).newInstance(options);
    } catch (java.lang.reflect.InvocationTargetException e) {
      if (e.getCause() instanceof RuntimeException r) throw r;
      throw e;
    }
  }

  static KeyProvider provider(String node) throws ReflectiveOperationException {
    return provider(node, NAME);
  }

  static Segment write(KeyProvider provider, byte[] plaintext) throws Exception {
    return encryptSegment(provider, NAME, plaintext);
  }

  static List<String> ids(List<KeyHandle> keys) {
    return keys.stream().map(KeyHandle::id).toList();
  }

  /** How the server leases, as the four configurations of keytend-kmip-server and a server without leases. */
  enum Leases {
    /** No Lease Time stated: no Obtain Lease is sent. */
    NONE,
    /** Lease Time 0, granted 0 (no limit): keytend-kmip-server with {@code --max-lease-seconds 0}. */
    ZERO,
    /** Lease Time 0, granted 30 s: keytend-kmip-server with no limit, capping a lease at a scheduled date. */
    ZERO_STATED_POSITIVE_GRANT,
    /** Lease Time 3600 s, granted so: keytend-kmip-server's default. */
    HOUR;

    void apply(LeasingTransport leasing) {
      switch (this) {
        case NONE -> {}
        case ZERO -> leasing.server.leaseTime(Duration.ZERO);
        case ZERO_STATED_POSITIVE_GRANT -> {
          leasing.everyObject = 0L;
          leasing.answer = id -> new Grant(30);
        }
        case HOUR -> leasing.server.leaseTime(Duration.ofHours(1));
      }
    }
  }

  static Stream<Arguments> versionsAndLeases() {
    List<Arguments> all = new ArrayList<>();
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0))
      for (Leases l : Leases.values()) all.add(Arguments.of(v, l));
    return all.stream();
  }

  /**
   * Every lease configuration: keys are obtained under a lease where one is stated (also a stated
   * 0), and only there; a 30-second grant under a stated 0 is a lease of 30 seconds, renewed at the
   * next use after it ends; rotation moves new files to the new key at the first use after the
   * refresh interval, not before; the old key stays Active and its files still read, also after a
   * restart.
   */
  @ParameterizedTest
  @MethodSource("versionsAndLeases")
  void writesReadsAndFollowsRotationUnderEveryLeasePolicy(KmipVersion version, Leases leases)
      throws Exception {
    InMemoryKmipServer s = server(version);
    Kms coordinator = coordinator(s);
    KeyHandle first = TdeKeyProvider.provision(coordinator, NAME, NAME);
    assertEquals(Optional.of(true), first.attributes().extractable());
    LeasingTransport leasing = new LeasingTransport(s);
    leases.apply(leasing);
    start("node1", leasing);
    KeyProvider provider = provider("node1");

    Segment a = write(provider, A);
    assertEquals(
        AliasCodec.encode(first.id()), a.alias(), "the alias is the write key's identifier");
    assertArrayEquals(A, decryptSegment(provider, a));
    if (leases == Leases.NONE) assertEquals(List.of(), leasing.obtained, "no Lease Time, no lease");
    else
      assertTrue(leasing.obtained.contains(first.id()), "leased before use: " + leasing.obtained);

    int obtains = leasing.obtainRequests.get();
    advance(31);
    assertEquals(a.alias(), write(provider, A).alias());
    if (leases == Leases.ZERO_STATED_POSITIVE_GRANT)
      assertTrue(
          leasing.obtainRequests.get() > obtains,
          "the 30-second lease ended: a new one is obtained");
    else assertEquals(obtains, leasing.obtainRequests.get(), "nothing due yet");

    KeyHandle second = TdeKeyProvider.rotate(coordinator, NAME, Duration.ZERO);
    assertNotEquals(first.id(), second.id());
    assertEquals(
        Optional.of(KeyState.ACTIVE), s.state(first.id()), "rotation leaves the old key Active");
    assertEquals(a.alias(), write(provider, A).alias(), "followed at the refresh, not before");
    advance(61);
    write(provider, A);
    runRefreshes();
    Segment b = write(provider, B);
    assertEquals(AliasCodec.encode(second.id()), b.alias(), "moved within the refresh interval");
    assertArrayEquals(A, decryptSegment(provider, a), "the old alias still names the old key");

    nodes.forEach(NodeKeys::stop);
    leasing.reset();
    start("node1", leasing);
    Replay replay = TdeKeyProvider.replay(provider("node1"), List.of(a, b));
    assertEquals(List.of(), replay.kept());
    assertEquals(List.of(), replay.corrupt());
    assertArrayEquals(A, replay.read().get(0));
    assertArrayEquals(B, replay.read().get(1));
    if (leases != Leases.NONE)
      assertTrue(
          leasing.trace.contains("ObtainLease " + first.id())
              && leasing.trace.indexOf("ObtainLease " + first.id())
                  < leasing.trace.indexOf("Get " + first.id()),
          "after a restart the old key is leased before its Get: " + leasing.trace);
  }

  /**
   * An append-only file (a commit log segment, a hints file) asks for its own key again before each
   * chunk: it keeps writing under the old key across a rotation, while new files move to the new
   * key, and stops (closed, nothing written) once its key may no longer encrypt. What it wrote
   * stays readable by its alias.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void anOpenFileAsksForItsOwnKeyPerChunkAndStopsWhenItMayNoLongerEncrypt(KmipVersion version)
      throws Exception {
    InMemoryKmipServer s = server(version);
    s.leaseTime(
        Duration.ofHours(1)); // leases every key that is not destroyed, Deactivated ones too
    Kms coordinator = coordinator(s);
    KeyHandle first = TdeKeyProvider.provision(coordinator, NAME, NAME);
    LeasingTransport leasing = new LeasingTransport(s);
    NodeKeys node = start("node1", leasing);
    KeyProvider provider = provider("node1");
    TdeKeyProvider.AppendOnlyFile file = TdeKeyProvider.AppendOnlyFile.create(provider, NAME, A);
    assertEquals(AliasCodec.encode(first.id()), file.alias());

    KeyHandle second = TdeKeyProvider.rotate(coordinator, NAME, Duration.ZERO);
    advance(61);
    write(provider, A);
    runRefreshes();
    assertEquals(AliasCodec.encode(second.id()), write(provider, B).alias(), "new files moved");
    leasing.reset();
    file.append(provider, B);
    assertTrue(
        leasing.trace.contains("ObtainLease " + first.id()),
        "the open file's key, validated for Encrypt: " + leasing.trace);
    for (int i = 0; i < 10; i++) file.append(provider, A);
    assertEquals(12, file.chunks().size());
    assertTrue(file.chunks().stream().allMatch(c -> c.alias().equals(file.alias())));

    // The KMS unreachable: the chunk fails, and the file stays open to retry.
    s.unreachable(true);
    node.forget(file.alias());
    assertThrows(TdeKeyProvider.KeyUnavailableException.class, () -> file.append(provider, B));
    assertFalse(file.closed(), "a transient failure does not end the file");
    s.unreachable(false);
    advance(2); // past the cache's retry backoff
    file.append(provider, A);
    assertEquals(13, file.chunks().size());

    coordinator.keys().handle(first.id()).deactivate();
    node.forget(file.alias()); // ask now, rather than at the next refresh
    TdeKeyProvider.KeyUnavailableException stopped =
        assertThrows(TdeKeyProvider.KeyUnavailableException.class, () -> file.append(provider, B));
    assertTrue(stopped.getMessage().contains("start a new file"), stopped.getMessage());
    assertTrue(file.closed());
    assertThrows(
        IOException.class, () -> file.append(provider, B), "a closed file takes nothing more");
    assertEquals(13, file.chunks().size(), "nothing written under the refused key");
    Replay replay = TdeKeyProvider.replay(provider, file.chunks());
    assertEquals(
        13, replay.read().size(), "a Deactivated key still decrypts where the server leases it");
    TdeKeyProvider.AppendOnlyFile next = TdeKeyProvider.AppendOnlyFile.create(provider, NAME, B);
    assertEquals(AliasCodec.encode(second.id()), next.alias());
  }

  /**
   * A server that leases only Active keys, as keytend-kmip-server does under --lease-states active.
   * After a rotation the old key stays
   * Active, so a restarted node replays the files under it. Deactivating it while files still need
   * it is the mistake this recipe avoids: the server then refuses its lease, the files under it
   * are kept (not corrupt), and the error says why; a file that does not authenticate is corrupt.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aServerThatLeasesOnlyActiveKeysStillReplaysAfterRotation(KmipVersion version)
      throws Exception {
    InMemoryKmipServer s = server(version);
    Kms coordinator = coordinator(s);
    KeyHandle first = TdeKeyProvider.provision(coordinator, NAME, NAME);
    LeasingTransport leasing = new LeasingTransport(s);
    s.leaseTime(Duration.ofHours(1)).leasesOnlyForActive(true);
    NodeKeys node = start("node1", leasing);
    Segment a = write(provider("node1"), A);
    KeyHandle second = TdeKeyProvider.rotate(coordinator, NAME, Duration.ZERO);
    advance(61);
    write(provider("node1"), A);
    runRefreshes();
    Segment b = write(provider("node1"), B);
    assertEquals(AliasCodec.encode(second.id()), b.alias());

    node.stop();
    assertThrows(
        IllegalStateException.class,
        () -> provider("node1"),
        "a stopped service gives no providers");
    start("node1", leasing);
    Replay replay = TdeKeyProvider.replay(provider("node1"), List.of(a, b));
    assertEquals(2, replay.read().size(), "the old key is Active, so it is leased");
    assertArrayEquals(A, replay.read().get(0));

    coordinator.keys().handle(first.id()).deactivate();
    nodes.forEach(NodeKeys::stop);
    leasing.reset();
    start("node1", leasing);
    KeyProvider restarted = provider("node1");
    byte[] tampered = b.ciphertext().clone();
    tampered[0] ^= 1;
    Segment damaged = new Segment(b.alias(), b.iv(), tampered);
    replay = TdeKeyProvider.replay(restarted, List.of(a, b, damaged));
    assertEquals(List.of(a), replay.kept(), "a key outage is not corruption: the file is kept");
    assertEquals(List.of(damaged), replay.corrupt());
    assertArrayEquals(B, replay.read().get(0));
    KeyUnavailableException e =
        assertThrows(KeyUnavailableException.class, () -> restarted.getSecretKey(a.alias()));
    StateConflictException refused = assertInstanceOf(StateConflictException.class, e.getCause());
    assertEquals(KeyState.DEACTIVATED, refused.observedState().orElseThrow());
    assertEquals("obtainLease", refused.operation());
    assertTrue(e.getMessage().contains("refused the key a lease"), e.getMessage());
    assertTrue(leasing.obtained.contains(first.id()));
    assertFalse(
        leasing.trace.contains("Get " + first.id()), "refused before any Get: " + leasing.trace);
  }

  /**
   * Retirement after flush and scans: keys no file names are destroyed, the oldest one a file
   * names and every newer one are kept; a scan naming a key outside the lineage retires nothing.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void retirementDestroysOnlyUnreferencedKeys(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms coordinator = coordinator(s);
    KeyHandle first = TdeKeyProvider.provision(coordinator, NAME, NAME);
    LeasingTransport leasing = new LeasingTransport(s);
    leasing.everyObject = 3600L;
    start("node1", leasing);
    KeyProvider provider = provider("node1");
    Segment a = write(provider, A);
    KeyHandle second = TdeKeyProvider.rotate(coordinator, NAME, Duration.ZERO);
    advance(61);
    write(provider, A);
    runRefreshes();
    Segment b = write(provider, B);
    KeyHandle third = TdeKeyProvider.rotate(coordinator, NAME, Duration.ZERO);

    String outside =
        AliasCodec.encode(
            coordinator
                .keys()
                .createAes(256)
                .custom(TdeKeyProvider.FAMILY, NAME)
                .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                .create()
                .id());
    assertThrows(
        IllegalStateException.class,
        () -> TdeKeyProvider.retireUnreferenced(coordinator, NAME, List.of(b.alias(), outside)));
    assertEquals(
        List.of(),
        ids(TdeKeyProvider.retireUnreferenced(coordinator, NAME, List.of(a.alias(), b.alias()))));
    assertTrue(s.hasMaterial(first.id()));
    // The segment under the first key was recycled: the scans name only the second.
    assertEquals(
        List.of(first.id()),
        ids(TdeKeyProvider.retireUnreferenced(coordinator, NAME, List.of(b.alias()))));
    assertFalse(s.hasMaterial(first.id()), "the first key is destroyed");
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(second.id()));
    assertEquals(Optional.of(KeyState.ACTIVE), s.state(third.id()));
    assertArrayEquals(B, decryptSegment(provider, b));
  }

  /**
   * Startup with the KMS down: starting sends nothing; the first file connects, waiting as long as
   * connectRetry allows. When the KMS stays down, a new file fails closed (nothing written, no key
   * created), and it works once the KMS is back.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void startsWithTheKmsDownAndFailsClosedUntilItReturns(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms coordinator = coordinator(s);
    KeyHandle first = TdeKeyProvider.provision(coordinator, NAME, NAME);
    LeasingTransport leasing = new LeasingTransport(s);
    leasing.everyObject = 3600L;
    List<String> unreachable = new CopyOnWriteArrayList<>();
    KmsListener comesBack =
        new KmsListener() {
          @Override
          public void endpointUnavailable(String endpoint, String why) {
            unreachable.add(endpoint);
            if (unreachable.size() == 2) s.unreachable(false);
          }
        };
    s.unreachable(true);
    int exchanges = s.exchanges();
    start(
        "node1",
        nodeConfig(leasing)
            .retryPolicy(QUICK)
            .connectRetry(Duration.ofSeconds(3))
            .addListener(comesBack)
            .build());
    KeyProvider provider = provider("node1");
    assertEquals(exchanges, s.exchanges(), "starting sends nothing");
    Segment a = write(provider, A);
    assertEquals(2, unreachable.size(), "two attempts failed before the KMS came back");
    assertEquals(AliasCodec.encode(first.id()), a.alias());
    nodes.forEach(NodeKeys::stop);

    List<String> before = s.ids();
    s.unreachable(true);
    start(
        "node2",
        nodeConfig(leasing).retryPolicy(QUICK).connectRetry(Duration.ofMillis(300)).build());
    KeyProvider down = provider("node2");
    KeyUnavailableException e =
        assertThrows(KeyUnavailableException.class, () -> write(down, A), "fails closed");
    assertInstanceOf(TransientException.class, e.getCause());
    assertThrows(KeyUnavailableException.class, () -> down.getSecretKey(a.alias()));
    s.unreachable(false);
    advance(2); // past the cache's short back-off
    assertArrayEquals(A, decryptSegment(down, a));
    assertEquals(a.alias(), write(down, B).alias());
    assertEquals(before, s.ids(), "no key created");
  }

  /**
   * Each call hands out its own copy: destroying one (as the database does after Cipher.init)
   * leaves the next one, and the cache, intact; alias and key of a new file come together.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void copiesHandedOutAreIndependent(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms coordinator = coordinator(s);
    KeyHandle first = TdeKeyProvider.provision(coordinator, NAME, NAME);
    LeasingTransport leasing = new LeasingTransport(s);
    leasing.everyObject = 0L;
    start("node1", leasing);
    KeyProvider provider = provider("node1");
    KeyForFile forFile = provider.keyForNewFile(NAME);
    assertEquals(AliasCodec.encode(first.id()), forFile.alias());
    byte[] bytes = forFile.key().getEncoded();
    forFile.key().destroy();
    KeyForFile next = provider.keyForNewFile(NAME);
    assertNotSame(forFile.key(), next.key());
    assertFalse(next.key().isDestroyed());
    assertArrayEquals(bytes, next.key().getEncoded());

    Key read = provider.getSecretKey(forFile.alias());
    assertArrayEquals(bytes, read.getEncoded());
    DestroyableSecretKey.destroyQuietly(read);
    Key again = provider.getSecretKey(forFile.alias());
    assertNotSame(read, again);
    assertArrayEquals(bytes, again.getEncoded(), "destroying a copy does not touch the next");
    assertArrayEquals(bytes, next.key().getEncoded(), "nor one already handed out");
  }

  /**
   * A compromise: replaced once from the coordinator; nodes move new files to the replacement at
   * the refresh, and files under the compromised key can no longer be read (LocalKeys refuses it).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aCompromiseMovesNewFilesAndItsFilesCannotBeRead(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms coordinator = coordinator(s);
    KeyHandle first = TdeKeyProvider.provision(coordinator, NAME, NAME);
    LeasingTransport leasing = new LeasingTransport(s);
    leasing.everyObject = 3600L;
    NodeKeys node = start("node1", leasing);
    KeyProvider provider = provider("node1");
    Segment a = write(provider, A);

    KeyHandle replacement =
        TdeKeyProvider.replaceCompromised(coordinator, a.alias(), Instant.now());
    assertEquals(Optional.of(KeyState.COMPROMISED), s.state(first.id()));
    advance(61);
    write(provider, A);
    runRefreshes();
    assertEquals(
        AliasCodec.encode(replacement.id()),
        write(provider, B).alias(),
        "new files go under the replacement");
    assertEquals(Optional.of(replacement.id()), node.currentWriteId());
    node.forget(a.alias());
    KeyUnavailableException e =
        assertThrows(KeyUnavailableException.class, () -> provider.getSecretKey(a.alias()));
    assertInstanceOf(StateConflictException.class, e.getCause());
    assertEquals(List.of(a), TdeKeyProvider.replay(provider, List.of(a)).kept());
  }

  /**
   * The stable scope: a header naming a key outside the family is refused, whatever the key, and
   * a key outside the family is never selected for writing even under the name.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void keysOutsideTheFamilyAreRefused(KmipVersion version) throws Exception {
    InMemoryKmipServer s = server(version);
    Kms coordinator = coordinator(s);
    TdeKeyProvider.provision(coordinator, NAME, NAME);
    KeyHandle other = TdeKeyProvider.provision(coordinator, "other", "other-family");
    KeyHandle unscoped =
        coordinator
            .keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .extractable(true)
            .create();
    start("node1", new LeasingTransport(s));
    KeyProvider provider = provider("node1");
    for (KeyHandle k : List.of(other, unscoped)) {
      KeyUnavailableException e =
          assertThrows(
              KeyUnavailableException.class,
              () -> provider.getSecretKey(AliasCodec.encode(k.id())));
      assertInstanceOf(KeyMismatchException.class, e.getCause(), k.id());
    }
  }

  /**
   * Malformed aliases are refused before any request: other prefixes (a keystore alias), padding,
   * characters outside base64url, a non-canonical encoding, bytes that are not UTF-8, an over-long
   * alias. A name is not an alias, nor a key_alias other than the node's write name.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void malformedAliasesAndForeignNamesAreRefusedBeforeAnyRequest(KmipVersion version)
      throws Exception {
    InMemoryKmipServer s = server(version);
    Kms coordinator = coordinator(s);
    KeyHandle first = TdeKeyProvider.provision(coordinator, NAME, NAME);
    start("node1", new LeasingTransport(s));
    KeyProvider provider = provider("node1");
    String valid = AliasCodec.encode(first.id());
    String payload = valid.substring(AliasCodec.PREFIX.length());
    List<String> refused =
        new ArrayList<>(
            Arrays.asList(
                null,
                "",
                "kmip:",
                "jks:tde-key",
                NAME,
                "KMIP:" + payload,
                " " + valid,
                valid + " ",
                valid + "=",
                valid + "==",
                "kmip:" + payload.replace('-', '+').replace('_', '/') + "+/",
                "kmip:QR",
                "kmip:_w",
                "kmip:" + "A".repeat(2_000)));
    int before = s.exchanges();
    for (String alias : refused) {
      IOException e = assertThrows(IOException.class, () -> provider.getSecretKey(alias), alias);
      assertFalse(e instanceof KeyUnavailableException, "malformed, not unavailable: " + alias);
    }
    assertThrows(
        IllegalArgumentException.class,
        () -> provider("node1", valid),
        "key_alias is the name, not an alias");
    assertThrows(IllegalArgumentException.class, () -> provider("node1", "other"));
    assertThrows(IllegalArgumentException.class, () -> provider.keyForNewFile("other"));
    assertThrows(
        IllegalStateException.class, () -> provider("node2"), "no service running for node2");
    assertThrows(
        IllegalStateException.class,
        () -> start("node1", new LeasingTransport(s)),
        "one service per node");
    assertEquals(before, s.exchanges(), "nothing sent");
    assertNotNull(provider.getSecretKey(valid));
  }

  /**
   * The alias codec on its own: identifiers with any characters round-trip, and decoding accepts
   * only the one canonical form.
   */
  @Test
  void aliasesAreDecodedStrictly() {
    for (String id :
        List.of("1", "a:b/c#d", "2f8c1e6a-0b7e-4a1c-9d3f-6f0e5a7c2b11", "clé é 鍵", "x".repeat(700)))
      assertEquals(id, AliasCodec.decode(AliasCodec.encode(id)), id);
    assertEquals("kmip:QQ", AliasCodec.encode("A"));
    assertEquals("A", AliasCodec.decode("kmip:QQ"), "QQ is the canonical form; QR has stray bits");
    for (String alias :
        Arrays.asList(
            null,
            "",
            "kmip:",
            "kmip:QR",
            "kmip:QQ=",
            "kmip:QQ==",
            "kmip:Q",
            "kmip:+/",
            "kmip:Q Q",
            "Kmip:QQ",
            "jks:QQ",
            "kmip:_w",
            "kmip:" + "Q".repeat(1_100)))
      assertThrows(
          IllegalArgumentException.class, () -> AliasCodec.decode(alias), String.valueOf(alias));
    assertThrows(IllegalArgumentException.class, () -> AliasCodec.encode(""));
  }

  /** Every line of the guide section's code blocks is in sample A8, so the guide shows what runs. */
  @Test
  void theGuideSectionShowsTheSamplesCode() throws Exception {
    String guide = Files.readString(Path.of("../docs/local-keys.md"));
    int start = guide.indexOf("\n## Transparent data encryption keys\n");
    assertTrue(start > 0);
    String section = guide.substring(start, guide.indexOf("\n## ", start + 5));
    List<String> source =
        Files.readAllLines(
                Path.of("src/test/java/dev/keytend/kmip/kms/samples/TdeKeyProvider.java"))
            .stream()
            .map(String::strip)
            .toList();
    Matcher block = Pattern.compile("```java\\n(.*?)```", Pattern.DOTALL).matcher(section);
    int blocks = 0;
    while (block.find()) {
      blocks++;
      for (String line : block.group(1).split("\n"))
        if (!line.isBlank() && !line.strip().equals("..."))
          assertTrue(source.contains(line.strip()), "not in the sample: " + line);
      // Whole statements: every brace a block opens, it closes.
      String code = block.group(1);
      assertEquals(
          code.chars().filter(c -> c == '{').count(),
          code.chars().filter(c -> c == '}').count(),
          "unbalanced: " + code);
    }
    assertTrue(blocks >= 3, blocks + " blocks");
    // The rotation job uses the entry point docs/choosing-an-api.md names.
    assertTrue(
        source.stream()
            .anyMatch(l -> l.contains("kms.keys().current(keyName).rotateIfActiveFor(period)")),
        "rotates through current(name)");
    assertTrue(
        Files.readString(Path.of("../docs/choosing-an-api.md"))
            .contains("`kms.keys().current(name).rotateIfActiveFor(period)`"));
    for (String link : List.of("(#keys-taken-out-of-the-kms)", "TdeKeyProvider.java", "(#leases)"))
      assertTrue(section.contains(link), link);
    assertFalse(section.contains("deactivateOld"), "no deactivate-old step");
    String takenOut =
        guide.substring(
            guide.indexOf("\n## Keys taken out of the KMS\n"), guide.indexOf("\n### Raw keys\n"));
    assertTrue(
        takenOut.contains("(#transparent-data-encryption-keys)"),
        "linked from Keys taken out of the KMS");
    int rawAt = guide.indexOf("\n### Raw keys\n");
    String raw = guide.substring(rawAt, guide.indexOf("\n## ", rawAt + 1));
    assertTrue(raw.contains("(#transparent-data-encryption-keys)"), "linked from Raw keys");
  }
}
