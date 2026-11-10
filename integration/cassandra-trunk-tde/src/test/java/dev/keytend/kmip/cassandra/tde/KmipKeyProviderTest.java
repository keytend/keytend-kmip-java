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

package dev.keytend.kmip.cassandra.tde;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.keytend.kmip.kms.Expect;
import dev.keytend.kmip.kms.KeyHandle;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.LocalUse;
import dev.keytend.kmip.kms.RevocationReason;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import javax.crypto.Cipher;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.config.TransparentDataEncryptionOptions;
import org.apache.cassandra.metrics.CassandraMetricsRegistry;
import org.apache.cassandra.security.EncryptionContext;
import org.apache.cassandra.utils.Hex;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

/**
 * Commit log and hints keys from a KMIP server through {@code LocalKeys}, on KMIP 1.4, 2.1 and
 * 3.0, through Cassandra's own (patched) {@link EncryptionContext} and {@code CipherFactory}.
 */
@RunWith(Parameterized.class)
public class KmipKeyProviderTest {
  private static final String NAME = "cassandra-tde";
  private static final byte[] DATA = "a commit log chunk".getBytes(StandardCharsets.UTF_8);

  @Parameterized.Parameter public KmipVersion version;

  private TestKms kms;
  private Kms admin;

  @Parameterized.Parameters(name = "KMIP {0}")
  public static Collection<Object[]> versions() {
    return Arrays.asList(new Object[][] {{KmipVersion.V1_4}, {KmipVersion.V2_1}, {KmipVersion.V3_0}});
  }

  @BeforeClass
  public static void setup() {
    DatabaseDescriptor.clientInitialization();
  }

  @Before
  public void start() {
    kms = new TestKms(version);
    admin = kms.admin();
  }

  @After
  public void stop() {
    admin.close();
    kms.close();
  }

  @Test
  public void startsWithoutTheKmsAndFailsOnlyAtTheFirstFile() {
    kms.down(true, true);
    EncryptionContext context = new EncryptionContext(TestKms.tdeOptions(NAME));
    assertThatThrownBy(context::forNewFile).isInstanceOf(IOException.class).hasMessageContaining("No KMIP key for new files");
  }

  @Test
  public void newFilesRecordTheirKeyAndReadBackByIt() throws Exception {
    KeyHandle key = kms.createKey(admin, NAME);
    EncryptionContext context = new EncryptionContext(TestKms.tdeOptions(NAME));
    EncryptionContext.NewFile file = context.forNewFile();
    assertThat(file.context.toHeaderParameters()).containsEntry(EncryptionContext.ENCRYPTION_KEY_ALIAS, NAME + '#' + key.id());
    byte[] encrypted = file.cipher.doFinal(DATA);
    assertThat(decrypt(context, file, encrypted)).isEqualTo(DATA);
    // the material is the KMS key's
    KmipKeyProvider provider = new KmipKeyProvider(TestKms.tdeOptions(NAME));
    assertThat(provider.getSecretKey(NAME + '#' + key.id()).getEncoded())
        .isEqualTo(key.asSecretKey(Expect.aes(256), LocalUse.DECRYPT).getEncoded());
    // an alias that names no identifier, or another key name, is a key that cannot be had
    assertThatThrownBy(() -> provider.getSecretKey(NAME)).isInstanceOf(IOException.class).hasMessageContaining("names no KMIP key");
    assertThatThrownBy(() -> provider.getSecretKey(NAME + '#')).isInstanceOf(IOException.class);
    assertThatThrownBy(() -> provider.getSecretKey("other#" + key.id())).isInstanceOf(IOException.class)
        .hasMessageContaining("this provider serves " + NAME);
    assertThatThrownBy(() -> provider.currentAlias(NAME)).isInstanceOf(UnsupportedOperationException.class);
  }

  @Test
  public void rotationRetirementAndKeysOutsideTheFamily() throws Exception {
    KeyHandle first = kms.createKey(admin, NAME);
    EncryptionContext context = new EncryptionContext(
        TestKms.tdeOptions(NAME, KmipKeyProvider.CACHE_TTL, "2s", KmipKeyProvider.CACHE_REFRESH, "100ms"));
    EncryptionContext.NewFile before = context.forNewFile();
    byte[] old = before.cipher.doFinal(DATA);

    tool("key-rotate", NAME);
    KeyHandle second = admin.keys().findByName(NAME).orElseThrow();
    assertThat(second.id()).isNotEqualTo(first.id());
    assertThat(kms.state(first.id())).isEqualTo(KeyState.ACTIVE);
    // the node moves new files to the new key at a refresh, without a restart
    EncryptionContext.NewFile after = awaitNewFileUnder(context, second.id());
    assertThat(decrypt(context, after, after.cipher.doFinal(DATA))).isEqualTo(DATA);
    assertThat(decrypt(context, before, old)).isEqualTo(DATA);

    // a file naming a key of another family is refused, whatever its header says
    KeyHandle stranger = admin.keys().createAes(256).named("other").custom(KmipKeyProvider.FAMILY_ATTRIBUTE, "other")
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).extractable(true).create();
    assertThatThrownBy(() -> new KmipKeyProvider(TestKms.tdeOptions(NAME)).getSecretKey(NAME + '#' + stranger.id()))
        .isInstanceOf(IOException.class);

    // retirement keeps what a scan names, and destroys only older keys
    Path dir = Files.createTempDirectory("kmip-scan");
    Path scan = Files.write(dir.resolve("node1.scan"), List.of(NAME + '#' + first.id(), NAME + '#' + second.id()));
    tool("key-retire", NAME, scan.toString());
    assertThat(kms.state(first.id())).isEqualTo(KeyState.ACTIVE);
    Files.write(scan, List.of(NAME + '#' + second.id()));
    tool("key-retire", NAME, scan.toString());
    assertThat(kms.state(first.id())).isEqualTo(KeyState.DESTROYED);
    assertThat(kms.state(second.id())).isEqualTo(KeyState.ACTIVE);
    // a scan naming a key outside the lineage refuses the whole retirement
    Files.write(scan, List.of(NAME + '#' + stranger.id()));
    assertThatThrownBy(() -> tool("key-retire", NAME, scan.toString())).isInstanceOf(IllegalStateException.class);
    assertThat(kms.state(second.id())).isEqualTo(KeyState.ACTIVE);
  }

  @Test
  public void noKeyOrCipherOutlivesItsAuthorization() throws Exception {
    kms.createKey(admin, NAME);
    EncryptionContext context = new EncryptionContext(TestKms.tdeOptions(NAME, KmipKeyProvider.CACHE_TTL, "1s"));
    EncryptionContext.NewFile file = context.forNewFile();
    byte[] encrypted = file.cipher.doFinal(DATA);
    EncryptionContext reading = reading(context, file);
    Cipher one = reading.getDecryptor();
    assertThat(reading.getDecryptor()).isNotSameAs(one); // no thread-local cipher cache
    assertThat(KmipMetrics.writeFailing(NAME)).isZero();

    // one replica down: the other serves
    kms.down(true, false);
    assertThat(reading.getDecryptor().doFinal(encrypted)).isEqualTo(DATA);
    // the KMS down: keys are used until the TTL ends, then refused, on the same thread
    kms.down(true, true);
    assertThat(reading.getDecryptor().doFinal(encrypted)).isEqualTo(DATA);
    TimeUnit.MILLISECONDS.sleep(1500);
    assertThatThrownBy(reading::getDecryptor).isInstanceOf(IOException.class);
    assertThatThrownBy(context::forNewFile).isInstanceOf(IOException.class);
    // the health gauges: nothing usable, and the write key's validation failing (not an idle node)
    assertThat(KmipMetrics.usableForSeconds(NAME)).isZero();
    assertThat(KmipMetrics.writeFailing(NAME)).isEqualTo(1);
    // and back
    kms.down(false, false);
    TimeUnit.MILLISECONDS.sleep(200);
    assertThat(reading.getDecryptor().doFinal(encrypted)).isEqualTo(DATA);
    awaitNewFile(context);
    assertThat(KmipMetrics.writeFailing(NAME)).isZero();
    assertThat(KmipMetrics.usableForSeconds(NAME)).isBetween(0L, 1L);
  }

  @Test
  public void anOpenFileAsksForItsOwnKeyBeforeEachChunk() throws Exception {
    // as keytend-kmip-server by default: every key states a Lease Time, and Active and Deactivated
    // keys are leased (--lease-states active-deactivated)
    kms.a.leaseTime(Duration.ofSeconds(60)).leasesOnlyForActive(false);
    kms.b.leaseTime(Duration.ofSeconds(60)).leasesOnlyForActive(false);
    KeyHandle first = kms.createKey(admin, NAME);
    TransparentDataEncryptionOptions options =
        TestKms.tdeOptions(NAME, KmipKeyProvider.CACHE_TTL, "1s", KmipKeyProvider.CACHE_REFRESH, "100ms");
    EncryptionContext context = new EncryptionContext(options);
    KmipKeyProvider provider = new KmipKeyProvider(options);
    assertThat(provider.usableFor()).contains(Duration.ZERO); // no write key yet
    assertThat(provider.writeFailure()).isEmpty();
    EncryptionContext.NewFile file = context.forNewFile();
    assertThat(provider.usableFor().orElseThrow()).isPositive().isLessThanOrEqualTo(Duration.ofSeconds(1));
    assertThat(provider.currentWriteId()).contains(first.id());
    byte[] chunk1 = file.cipher.doFinal(DATA);

    // rotated: new files move to the new key, and the open file keeps its own, which may still encrypt (Active)
    tool("key-rotate", NAME);
    KeyHandle second = admin.keys().findByName(NAME).orElseThrow();
    awaitNewFileUnder(context, second.id());
    TimeUnit.MILLISECONDS.sleep(1100); // past the TTL of what the first file got: each chunk is authorized anew
    file.context.reauthorize(file.cipher);
    byte[] chunk2 = file.cipher.doFinal(DATA);
    assertThat(decrypt(context, file, chunk1)).isEqualTo(DATA);
    assertThat(decrypt(context, file, chunk2)).isEqualTo(DATA);

    // the open file's key deactivated: its next chunk is refused within the TTL, whatever the server's lease policy
    admin.keys().handle(first.id()).revoke(RevocationReason.cessationOfOperation("test"));
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (true) {
      try {
        file.context.reauthorize(file.cipher);
      } catch (IOException refused) {
        assertThat(refused).hasMessageContaining("may no longer encrypt");
        break;
      }
      assertThat(System.nanoTime()).as("refused within the TTL").isLessThan(deadline);
      TimeUnit.MILLISECONDS.sleep(100);
    }
    // what it holds stays readable on a server that leases Deactivated keys, past the TTL (a new lease) too
    TimeUnit.MILLISECONDS.sleep(1100);
    assertThat(decrypt(context, file, chunk1)).isEqualTo(DATA);
    assertThat(decrypt(context, file, chunk2)).isEqualTo(DATA);
    // and not on one that leases only Active keys (--lease-states active):
    // a Decrypt copy already handed out is served until its own TTL, then the lease is refused
    kms.a.leasesOnlyForActive(true);
    kms.b.leasesOnlyForActive(true);
    deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (true) {
      try {
        decrypt(context, file, chunk1);
      } catch (IOException refused) {
        assertThat(refused).hasMessageContaining("refused to lease");
        break;
      }
      assertThat(System.nanoTime()).as("reading refused within the TTL").isLessThan(deadline);
      TimeUnit.MILLISECONDS.sleep(100);
    }
    // new files are unaffected
    assertThat(context.forNewFile().context.toHeaderParameters())
        .containsEntry(EncryptionContext.ENCRYPTION_KEY_ALIAS, NAME + '#' + second.id());
  }

  @Test
  public void compromisedKeyIsReplacedAndRefused() throws Exception {
    KeyHandle first = kms.createKey(admin, NAME);
    EncryptionContext context = new EncryptionContext(
        TestKms.tdeOptions(NAME, KmipKeyProvider.CACHE_TTL, "2s", KmipKeyProvider.CACHE_REFRESH, "100ms"));
    EncryptionContext.NewFile before = context.forNewFile();
    tool("key-replace-compromised", NAME, Instant.now().minusSeconds(60).toString());
    KeyHandle replacement = admin.keys().findByName(NAME).orElseThrow();
    awaitNewFileUnder(context, replacement.id());
    // LocalKeys refuses Compromised keys, also for reading: recovery is a separate process
    EncryptionContext reading = reading(context, before);
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5);
    while (true) {
      try {
        reading.getDecryptor();
      } catch (IOException refused) {
        break;
      }
      assertThat(System.nanoTime()).isLessThan(deadline);
      TimeUnit.MILLISECONDS.sleep(100);
    }
    assertThat(kms.state(first.id())).isEqualTo(KeyState.COMPROMISED);
  }

  @Test
  public void aCompromisedKeyIsRevokedByIdentifierAfterTheRotation() throws Exception {
    KeyHandle first = kms.createKey(admin, NAME);
    String since = Instant.now().minusSeconds(60).toString();
    // the name's own key is refused: that is key-replace-compromised's job
    assertThatThrownBy(() -> tool("key-revoke-compromised", NAME, first.id(), since))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("key-rotate first");
    tool("key-rotate", NAME);
    KeyHandle second = admin.keys().findByName(NAME).orElseThrow();
    assertThat(second.id()).isNotEqualTo(first.id());
    // an identifier outside the name's lineage is refused
    KeyHandle other = kms.createKey(admin, NAME + "-other");
    assertThatThrownBy(() -> tool("key-revoke-compromised", NAME, other.id(), since))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("not in the lineage");
    // the old key is revoked, and the replacement the name now points to is untouched
    tool("key-revoke-compromised", NAME, first.id(), since);
    assertThat(kms.state(first.id())).isEqualTo(KeyState.COMPROMISED);
    assertThat(kms.state(second.id())).isEqualTo(KeyState.ACTIVE);
    assertThat(kms.state(other.id())).isEqualTo(KeyState.ACTIVE);
    assertThat(admin.keys().findByName(NAME).orElseThrow().id()).isEqualTo(second.id());
  }

  @Test
  public void theGaugesAreCassandraMetricsAndTheScanReadsFileHeaders() throws Exception {
    kms.createKey(admin, NAME);
    EncryptionContext context = new EncryptionContext(TestKms.tdeOptions(NAME));
    EncryptionContext.NewFile file = context.forNewFile();
    String alias = file.context.toHeaderParameters().get(EncryptionContext.ENCRYPTION_KEY_ALIAS);
    // registered under the Kmip group (patch 0004), scope the key name
    assertThat(CassandraMetricsRegistry.Metrics.getGauges((n, m) -> n.contains("type=Kmip") || n.contains(".Kmip."))
        .keySet()).anySatisfy(n -> assertThat(n).contains(NAME).contains(KmipMetrics.USABLE_FOR))
        .anySatisfy(n -> assertThat(n).contains(NAME).contains(KmipMetrics.WRITE_FAILING));
    assertThat(KmipMetrics.usableForSeconds(NAME)).isPositive();

    // the scan finds the alias in commit log and hints headers, and ignores other files
    Path dir = Files.createTempDirectory("kmip-headers");
    String header = "{\"encCipher\":\"AES/CBC/PKCS5Padding\",\"encKeyAlias\":\"" + alias + "\",\"encIV\":\"00\"}";
    Files.writeString(dir.resolve("CommitLog-8-1.log"), "\0\0" + header + "\0binary");
    Files.writeString(dir.resolve("host-1-1.hints"), header);
    Files.writeString(dir.resolve("other.txt"), header.replace(alias, NAME + "#elsewhere"));
    assertThat(KmipTool.scan(List.of(dir.toString()))).containsExactly(alias);
  }

  private EncryptionContext.NewFile awaitNewFileUnder(EncryptionContext context, String id) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (true) {
      EncryptionContext.NewFile file = context.forNewFile();
      if (file.context.toHeaderParameters().get(EncryptionContext.ENCRYPTION_KEY_ALIAS).equals(NAME + '#' + id))
        return file;
      assertThat(System.nanoTime()).as("new files move to " + id).isLessThan(deadline);
      TimeUnit.MILLISECONDS.sleep(50);
    }
  }

  private static void awaitNewFile(EncryptionContext context) throws Exception {
    long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10);
    while (true) {
      try {
        context.forNewFile();
        return;
      } catch (IOException notYet) {
        // within the short transient backoff
      }
      assertThat(System.nanoTime()).as("new files after recovery").isLessThan(deadline);
      TimeUnit.MILLISECONDS.sleep(100);
    }
  }

  /** The context a reader rebuilds from a file's header. */
  private static EncryptionContext reading(EncryptionContext context, EncryptionContext.NewFile file) {
    Map<String, Object> header = new HashMap<>(file.context.toHeaderParameters());
    header.put(EncryptionContext.ENCRYPTION_IV, Hex.bytesToHex(file.cipher.getIV()));
    return EncryptionContext.createFromMap(header, context);
  }

  private static byte[] decrypt(EncryptionContext context, EncryptionContext.NewFile file, byte[] encrypted)
      throws Exception {
    return reading(context, file).getDecryptor().doFinal(encrypted);
  }

  private void tool(String... args) throws Exception {
    KmipTool.run(admin, args[0], List.of(args).subList(1, args.length));
  }
}
