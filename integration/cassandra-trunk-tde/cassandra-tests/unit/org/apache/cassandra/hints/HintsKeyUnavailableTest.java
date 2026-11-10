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

package org.apache.cassandra.hints;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.common.collect.ImmutableMap;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import javax.crypto.spec.SecretKeySpec;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.config.ParameterizedClass;
import org.apache.cassandra.config.TransparentDataEncryptionOptions;
import org.apache.cassandra.security.EncryptionContext;
import org.apache.cassandra.security.EncryptionKeyUnavailableException;
import org.apache.cassandra.security.KeyProvider;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * The hints changes of this integration's patch 0003, with a provider whose keys may not be cached
 * and whose KMS can be switched off: hints are never written unencrypted, are read only when the
 * key can be had, and a file being written asks for its key again before it grows. No SDK: this
 * is Cassandra's side of the contract.
 */
public class HintsKeyUnavailableTest {
  private static EncryptionContext context;

  /** A provider whose key is authorized for a limited time, and whose KMS can be switched off. */
  public static class SwitchableKeyProvider implements KeyProvider {
    static volatile boolean down;
    static volatile boolean appendRefused;
    static final AtomicInteger appends = new AtomicInteger();

    public SwitchableKeyProvider(TransparentDataEncryptionOptions options) {}

    @Override
    public Key getSecretKey(String alias) throws IOException {
      if (down) throw new IOException("KMS unreachable");
      return new SecretKeySpec(new byte[16], "AES");
    }

    @Override
    public Key keyForAppend(String alias) throws IOException {
      appends.incrementAndGet();
      if (appendRefused) throw new IOException("the key may no longer encrypt");
      return getSecretKey(alias);
    }

    @Override
    public boolean keysMayBeCached() {
      return false;
    }
  }

  @BeforeClass
  public static void setup() {
    DatabaseDescriptor.daemonInitialization();
    TransparentDataEncryptionOptions options = new TransparentDataEncryptionOptions(true, "AES/CBC/PKCS5Padding", "k",
        new ParameterizedClass(SwitchableKeyProvider.class.getName(), new HashMap<>()));
    context = new EncryptionContext(options);
    DatabaseDescriptor.setEncryptionContext(context);
  }

  @Test
  public void neverWritesUnencryptedAndReadsOnlyWithTheKey() {
    ImmutableMap<String, Object> params =
        ImmutableMap.of(HintsDescriptor.ENCRYPTION, ImmutableMap.copyOf(context.toHeaderParameters()));
    UUID host = UUID.randomUUID();
    SwitchableKeyProvider.down = false;
    HintsDescriptor written = new HintsDescriptor(host, 1L, params);
    assertThat(written.isEncrypted()).isTrue();

    // the key cannot be had: the new file is refused, rather than written unencrypted
    SwitchableKeyProvider.down = true;
    assertThatThrownBy(() -> new HintsDescriptor(host, 2L, params)).isInstanceOf(EncryptionKeyUnavailableException.class);

    // a file being read is listed without its key; its decryptor needs the key, and the file stays intact
    HintsDescriptor read = new HintsDescriptor(host, written.version, written.timestamp, written.parameters);
    assertThat(read.isEncrypted()).isTrue();
    assertThatThrownBy(read::getCipher).isInstanceOf(EncryptionKeyUnavailableException.class);
    SwitchableKeyProvider.down = false;
    assertThat(read.getCipher().getIV()).isEqualTo(written.getCipher().getIV());
  }

  @Test
  public void aFileBeingWrittenAsksForItsKeyAgainBeforeItGrows() throws Exception {
    ImmutableMap<String, Object> params =
        ImmutableMap.of(HintsDescriptor.ENCRYPTION, ImmutableMap.copyOf(context.toHeaderParameters()));
    UUID host = UUID.randomUUID();
    SwitchableKeyProvider.down = false;
    SwitchableKeyProvider.appendRefused = false;
    HintsDescriptor written = new HintsDescriptor(host, 3L, params);
    byte[] iv = written.getCipher().getIV();
    int before = SwitchableKeyProvider.appends.get();
    written.reauthorizeCipher();
    assertThat(SwitchableKeyProvider.appends.get()).isEqualTo(before + 1);
    // the same key and IV: what the file holds stays readable by the decryptor its header describes
    assertThat(written.getCipher().getIV()).isEqualTo(iv);
    byte[] hint = "a hint".getBytes(StandardCharsets.UTF_8);
    byte[] chunk = written.getCipher().doFinal(hint);
    HintsDescriptor read = new HintsDescriptor(host, written.version, written.timestamp, written.parameters);
    assertThat(read.getCipher().doFinal(chunk)).isEqualTo(hint);

    // the key may no longer encrypt: the file is not appended to (the writer moves to a new file)
    SwitchableKeyProvider.appendRefused = true;
    assertThatThrownBy(written::reauthorizeCipher).isInstanceOf(EncryptionKeyUnavailableException.class)
        .hasMessageContaining("cannot append to hints file");
    // a file being read is never appended to
    int refusedAt = SwitchableKeyProvider.appends.get();
    read.reauthorizeCipher();
    assertThat(SwitchableKeyProvider.appends.get()).isEqualTo(refusedAt);
    SwitchableKeyProvider.appendRefused = false;
  }
}
