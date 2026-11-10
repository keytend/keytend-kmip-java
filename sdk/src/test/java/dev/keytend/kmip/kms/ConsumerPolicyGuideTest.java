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

import static dev.keytend.kmip.kms.TlsIdentityTest.HOURLY;
import static dev.keytend.kmip.kms.TlsIdentityTest.SCHEDULER;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.model.WireEnums;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.function.Consumer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The guide's table "What each consumer's credential needs" (docs/production.md) against what
 * each consumer sends: every operation a consumer's calls send, on KMIP 1.4, 2.1 and 3.0, against a
 * server that leases, is in its row, so a credential granted only that row's operations works.
 */
class ConsumerPolicyGuideTest {
  static final CustomAttribute FAMILY = CustomAttribute.client("tde-family");
  static final CustomAttribute TAG = CustomAttribute.client("tls");

  /** The operations sent through it, by wire name. */
  static final class Recording {
    final Set<String> sent = new ConcurrentSkipListSet<>();
    final InMemoryKmipServer server;

    Recording(InMemoryKmipServer server) {
      this.server = server;
    }

    Kms connect() {
      return Kms.connect(
          server
              .configure()
              .maximumVersion(KmipVersion.V3_0)
              .callTimeout(Duration.ofSeconds(10))
              .transport(
                  e ->
                      request -> {
                        for (Ttlv item : request.children(Tag.BATCH_ITEM))
                          sent.add(
                              WireEnums.fromCode(
                                      Operation.class, item.require(Tag.OPERATION).intValue())
                                  .map(Operation::wireName)
                                  .orElse("?"));
                        return server.exchange(request);
                      })
              .build());
    }
  }

  /** The guide's table: the operations of each row, by its first cell. */
  static Map<String, Set<String>> table() throws IOException {
    String guide = Files.readString(Path.of("../docs/production.md"));
    int start = guide.indexOf("\n## What each consumer's credential needs\n");
    assertTrue(start > 0, "the guide has the section");
    String section = guide.substring(start, guide.indexOf("\n## ", start + 5));
    Map<String, Set<String>> rows = new LinkedHashMap<>();
    Matcher row = Pattern.compile("(?m)^\\| ([^|]+) \\| ([^|]+) \\|").matcher(section);
    while (row.find()) {
      String consumer = row.group(1).strip(), operations = row.group(2).strip();
      if (consumer.equals("Consumer") || consumer.startsWith("---")) continue;
      Set<String> ops = new TreeSet<>();
      for (String op : operations.split(",")) ops.add(normal(op));
      rows.put(consumer, ops);
    }
    return rows;
  }

  /** An operation's name without spaces, hyphens or case: "Re-key" is the wire's ReKey. */
  static String normal(String operation) {
    return operation.strip().replace(" ", "").replace("-", "").toLowerCase(Locale.ROOT);
  }

  /** What {@code calls} sends through a fresh connection, after the connection's own negotiation. */
  static Set<String> sent(InMemoryKmipServer server, Consumer<Kms> calls) {
    Recording r = new Recording(server);
    try (Kms kms = r.connect()) {
      calls.accept(kms);
    }
    return new TreeSet<>(r.sent);
  }

  static void within(Map<String, Set<String>> table, String consumer, Set<String> sent) {
    Set<String> allowed = table.get(consumer);
    assertNotNull(allowed, "the guide's table has a row for " + consumer + ": " + table.keySet());
    Set<String> extra = new TreeSet<>();
    for (String op : sent) extra.add(normal(op));
    extra.removeAll(allowed);
    assertEquals(
        Set.of(),
        extra,
        consumer + " sends operations its row does not list (it sent " + sent + ")");
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void eachConsumerSendsOnlyWhatItsRowGrants(KmipVersion version) throws Exception {
    Map<String, Set<String>> table = table();
    InMemoryKmipServer server = InMemoryKmipServer.of(version).leaseTime(Duration.ofHours(1));
    try (Kms admin = server.connect()) {
      Set<String> provisioning0 =
          sent(
              server,
              kms -> {
                kms.keys()
                    .createAes(256)
                    .named("provisioned")
                    .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                    .findOrCreate();
                kms.keys()
                    .createAes(256)
                    .named("provisioned")
                    .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                    .findOrCreate();
              });
      within(table, "An operator that provisions keys (`findOrCreate`)", provisioning0);
      // Provisioned by an operator.
      KeyCreation tde =
          admin
              .keys()
              .createAes(256)
              .custom(FAMILY, "orders")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .named("orders-write");
      if (version.compareTo(KmipVersion.V1_4) >= 0) tde.extractable(true);
      KeyHandle tdeKey = tde.create();
      admin
          .keys()
          .createAes(256)
          .named("orders-kek")
          .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
          .findOrCreate();
      admin.keys().registerSecret("s3cret".toCharArray()).named("db-password").register();

      Set<String> local =
          sent(
              server,
              kms -> {
                try (LocalKeys keys =
                    kms.keys()
                        .localKeys("orders-write")
                        .scope(KeyQuery.all().custom(FAMILY, "orders"))
                        .expect(Expect.aes(256))
                        .open()) {
                  try (LocalKeys.Use use = keys.forEncrypt()) {
                    assertEquals(tdeKey.id(), use.id());
                  }
                  keys.invalidateAll();
                  try (LocalKeys.Use use = keys.forAppend(tdeKey.id())) {
                    assertEquals(tdeKey.id(), use.id());
                  }
                  try (LocalKeys.Use use = keys.forDecrypt(tdeKey.id())) {
                    assertEquals(tdeKey.id(), use.id());
                  }
                }
              });
      within(table, "A node's `LocalKeys` (SSTable, commit log and hints keys)", local);

      Set<String> envelope =
          sent(
              server,
              kms -> {
                try {
                  CurrentKey kek = kms.keys().current("orders-kek");
                  byte[] aad = "order-1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                  assertArrayEquals(aad, kek.open(kek.seal(aad, aad), aad));
                  byte[] fileId = "file-1".getBytes(java.nio.charset.StandardCharsets.UTF_8);
                  try (ChunkedSealer sealer = kek.chunkedSealer(fileId)) {
                    byte[] chunk = sealer.sealFinal(0, aad);
                    try (ChunkedOpener opener = kek.chunkedOpener(sealer.header(), fileId)) {
                      assertArrayEquals(aad, opener.openFinal(0, chunk));
                    }
                  }
                  Path dir = Files.createTempDirectory("policy");
                  kek.sealTo(dir.resolve("sealed"), new ByteArrayInputStream(aad), aad);
                  kek.openTo(dir.resolve("sealed"), dir.resolve("opened"), aad);
                } catch (IOException e) {
                  throw new java.io.UncheckedIOException(e);
                }
              });
      within(
          table, "A node that seals and opens with `CurrentKey` (envelope encryption)", envelope);

      Set<String> secret =
          sent(
              server,
              kms -> {
                try (SecretData value =
                    kms.keys().findByName("db-password").orElseThrow().asSecretData()) {
                  assertEquals("s3cret", new String(value.chars()));
                }
              });
      within(table, "An application that reads a secret", secret);

      // TLS: provisioning, and a node's followers.
      TlsIdentityTest.Pki pki = new TlsIdentityTest.Pki();
      KeyPair k1 = TestPki.ec(), k2 = TestPki.ec();
      Set<String> provisioning =
          sent(
              server,
              kms -> {
                try {
                  kms.keys().register(pki.root.certificate()).custom(TAG, "ca").register();
                  TlsIdentityHandle node =
                      kms.tls()
                          .register(k1.getPrivate(), pki.chain(pki.leaf("node1", k1)))
                          .named("node1")
                          .custom(TAG, "peer")
                          .register();
                  node = node.renew(pki.chain(pki.leaf("node1", k1)));
                  node = node.rekey(k2.getPrivate(), pki.chain(pki.leaf("node1", k2)));
                  kms.tls()
                      .register(k1.getPrivate(), pki.chain(pki.leaf("node2", k1)))
                      .named("node2")
                      .custom(TAG, "peer")
                      .register()
                      .revoke(RevocationReason.keyCompromise("lost", Instant.now()));
                } catch (Exception e) {
                  throw new IllegalStateException(e);
                }
              });
      within(
          table,
          "The place that issues TLS identities (`register`, `renew`, `rekey`, `revoke`)",
          provisioning);

      Issued renewedPeer = pki.leaf("peer", TestPki.ec()),
          unknown = pki.leaf("unknown", TestPki.ec());
      Set<String> followers =
          sent(
              server,
              kms -> {
                try (TlsIdentityFollower identity = kms.tls().follow("node1", HOURLY, SCHEDULER);
                    TlsTrustFollower trust =
                        kms.tls()
                            .trustAnchors(
                                KeyQuery.all().custom(TAG, "ca"),
                                KeyQuery.all().custom(TAG, "peer"),
                                HOURLY,
                                SCHEDULER)
                            .unknownPeerCheckInHandshake(true)) {
                  admin.keys().register(renewedPeer.certificate()).custom(TAG, "peer").register();
                  identity.refresh();
                  trust.refresh();
                  trust.trustManager().checkClientTrusted(pki.chain(unknown), "EC");
                } catch (java.security.cert.CertificateException expected) {
                  // the unknown certificate is refused, after its check of the KMS
                }
              });
      within(table, "A node's TLS followers (`follow`, `trustAnchors`)", followers);

      Set<String> rotation =
          sent(
              server,
              kms -> {
                CurrentKey kek = kms.keys().current("orders-kek");
                kek.rotateIfActiveFor(Duration.ZERO);
                KeyHandle newest = kek.rotateIfActiveFor(Duration.ZERO);
                newest.retirePredecessorsOlderThan(newest, RevocationReason.superseded("retired"));
                kms.keys().handle(tdeKey.id()).rotateIfActiveFor(Duration.ZERO);
              });
      within(table, "The rotation job (run from one place)", rotation);

      KeyHandle replacement =
          admin
              .keys()
              .createAes(256)
              .custom(FAMILY, "orders")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
      String holder = admin.keys().findByName("orders-write").orElseThrow().id();
      Set<String> move =
          sent(server, kms -> kms.keys().moveName("orders-write", holder, replacement.id()));
      within(table, "An operator that moves a write name (`moveName`)", move);
    }
  }
}
