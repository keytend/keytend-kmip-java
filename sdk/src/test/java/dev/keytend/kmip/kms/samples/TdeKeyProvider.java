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

package dev.keytend.kmip.kms.samples;

import dev.keytend.kmip.kms.*;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;

/**
 * A8. Keys for a database's commit log and hints encryption, lease-compliant: every key comes from
 * one {@link LocalKeys} per node, which obtains the KMIP lease a server requires before it hands a
 * key out. The shape is Apache Cassandra's {@code KeyProvider}, with no Cassandra dependency:
 * {@link KeyProvider} and {@link TdeOptions} stand in for Cassandra's types. The database encrypts
 * locally with the key's value, so the key must leave the KMS (it is created extractable).
 *
 * <p><b>The rules.</b>
 *
 * <ul>
 *   <li><b>An alias names one key, forever.</b> Each segment or hints file records the alias it
 *       was encrypted under, and is decrypted with exactly that key at replay, perhaps years later.
 *       So the alias is the key's KMIP unique identifier, {@code kmip:<base64url(UTF-8
 *       identifier)>} ({@link AliasCodec}), decoded strictly, and read by that identifier only
 *       ({@link LocalKeys#forDecrypt}). A name is never resolved to decrypt: a name moves to each
 *       new key at rotation, and AES-CBC cannot tell a wrong key from the right one. (An alias of
 *       the form {@code <name>#<id>} would do too, but a server identifier may itself contain
 *       {@code #}; the encoding takes any identifier.)
 *   <li><b>One handout gives a new file its alias and its key</b> ({@link
 *       KeyProvider#keyForNewFile}: one {@link LocalKeys#forEncrypt}). Asking for the alias and
 *       then for the key by that alias would be two authorizations: the second goes through
 *       {@code forDecrypt}, which also accepts a Deactivated key (or one past its Protect Stop
 *       Date) and so would encrypt new data under a key no longer allowed to encrypt; and between
 *       the two calls the write key may change, or its lease end.
 *   <li><b>An append-only file asks for its own key again before each chunk</b> ({@link
 *       KeyProvider#keyForAppend}: {@link LocalKeys#forAppend(String)} with the identifier its
 *       header names). A commit log segment or hints file may stay open for hours; asking per
 *       chunk makes a key that may no longer encrypt (deactivated, compromised, past its Protect
 *       Stop Date, refused a lease) stop that file's writes within one TTL, not only the next
 *       file's ({@link AppendOnlyFile}). A refusal closes the file; the database starts a new one
 *       under {@code keyForNewFile}, and what was written stays readable by its alias.
 *   <li><b>No key is kept beyond one handout.</b> Each call copies the key out of a {@link
 *       LocalKeys.Use} and closes the use; the copy is the database's, to destroy once its cipher
 *       is initialized. The database must not cache keys or initialized ciphers for this
 *       provider: an authorization (TTL, lease) is checked only when a key is handed out.
 *   <li><b>One key service per node</b> ({@link NodeKeys}): one {@link LocalKeys} that owns a
 *       lazily connected KMS ({@link LocalKeys#builder(KmsConfig, String)}), started and stopped by
 *       the node, and shared by every provider the database instantiates reflectively (Cassandra
 *       makes one per encryption context, also when it replays a file). Starting sends nothing:
 *       the first key use connects, within {@link KmsConfig.Builder#connectRetry} and the call
 *       timeout, so a node starts while the KMS is down and fails only at its first file.
 *   <li><b>A stable scope</b>: keys whose custom attribute {@link #FAMILY} is the family, set at
 *       {@link #provision} and copied by Re-key. A file header naming a key outside it is refused,
 *       whatever the key. Custom attributes work on KMIP 1.4, 2.1 and the 3.0 draft alike.
 *   <li><b>A key that cannot be had is not corruption</b> ({@link KeyUnavailableException}): new
 *       files fail closed (never written unencrypted), and a file whose key the KMS refuses or
 *       cannot give now is kept for a later attempt, not deleted ({@link #replay}).
 * </ul>
 *
 * <p><b>Rotation and retirement</b> run from one place ({@link #provision}, {@link #rotate},
 * {@link #retireUnreferenced}, {@link #replaceCompromised}), never from the nodes. Rotation leaves
 * the old key Active: a server that leases only Active keys (keytend-kmip-server with --lease-states active) refuses a Deactivated key
 * a lease, so its files could not be replayed. A key is retired (destroyed) only once no file
 * names it. Nodes move new files to the new key at their first key use after the refresh
 * interval.
 *
 * <p><b>Limits.</b> {@link LocalKeys} refuses Compromised keys, and nothing here bypasses that:
 * files under a Compromised key cannot be read, so a node's unflushed commit log under it is
 * recovered from replicas (repair) and its hints for it are truncated. (A separately configured
 * maintenance start, {@link LocalKeys.Builder#allowCompromisedForDecrypt()}, can replay data only
 * a node holds, where the server still leases the key; this sample has no such mode.) Revoking a key at the KMS
 * does not revoke a copy already in this JVM or in an initialized cipher; an append-only file
 * that asks per chunk ({@link AppendOnlyFile}) stops within one TTL or lease. A key-encryption key for envelope encryption is the
 * opposite case: create it non-extractable and keep it on the server
 * (docs/envelope-encryption.md, "Keys that never leave the KMS").
 *
 * <p><b>Why the SDK has no {@code Kms.shared(config)}.</b> {@link KmsConfig} has no meaningful
 * equality (it holds suppliers, listeners and transports), and a static registry in a library
 * outlives the class loaders of the applications that use it: an in-JVM test cluster would share,
 * and leak, one node's connections and threads into the next. So the node owns the lifecycle
 * ({@link NodeKeys#start}, {@link NodeKeys#stop}); the registry of running services ({@link
 * NodeKeys#running}) is application code, holds a service only between its start and stop, and
 * lives in the node's class loader.
 */
public final class TdeKeyProvider {
  private TdeKeyProvider() {}

  /** The custom attribute naming the family a key belongs to: the node's stable scope. */
  public static final CustomAttribute FAMILY = CustomAttribute.client("tde-family");

  /**
   * The shape of Cassandra's {@code org.apache.cassandra.security.KeyProvider}, with the two
   * handouts a lease-compliant write path needs ({@code keyForNewFile}, {@code keyForAppend}).
   */
  public interface KeyProvider {
    /** The key a file's alias names, for reading it; the caller destroys it after {@code Cipher.init}. */
    Key getSecretKey(String alias) throws IOException;

    /** The alias and key of a new file, from one authorization; the caller destroys the key. */
    KeyForFile keyForNewFile(String configuredAlias) throws IOException;

    /**
     * The key an open append-only file's alias names, for its next chunk, only while that key may
     * still encrypt; the caller destroys it after {@code Cipher.init}. A {@link
     * KeyUnavailableException} means: close the file, and start a new one with {@link
     * #keyForNewFile}.
     */
    Key keyForAppend(String alias) throws IOException;
  }

  /** A new file's alias, to record in its header, and its key, the caller's to destroy. */
  public record KeyForFile(String alias, DestroyableSecretKey key) {}

  /**
   * Stands in for Cassandra's {@code TransparentDataEncryptionOptions}: the configured {@code
   * key_alias} and the provider's parameters.
   */
  public record TdeOptions(String keyAlias, Map<String, String> parameters) {
    public TdeOptions {
      Objects.requireNonNull(keyAlias, "keyAlias");
      parameters = Map.copyOf(parameters);
    }
  }

  /**
   * The key cannot be had now; the file is intact. A new file is not written, and a file being
   * read is kept and tried again later, never taken for corrupt.
   */
  public static final class KeyUnavailableException extends IOException {
    public KeyUnavailableException(String message, Throwable cause) {
      super(message, cause);
    }
  }

  /**
   * The provider the database instantiates reflectively, as often as it likes. It holds no
   * connection of its own: it finds the node's running {@link NodeKeys}, and fails when the node
   * has not started it (rather than connecting by itself).
   */
  public static final class KmipKeyProvider implements KeyProvider {
    /** The parameter naming the node's key service; one node per JVM can leave it out. */
    public static final String NODE_KEYS = "node_keys";

    private final NodeKeys keys;

    /**
     * @throws IllegalArgumentException when {@code key_alias} is not the KMIP Name the node's
     *     service writes under (an old {@code kmip:} alias here would pin new files to one key)
     */
    public KmipKeyProvider(TdeOptions options) {
      keys = NodeKeys.running(options.parameters().getOrDefault(NODE_KEYS, NodeKeys.DEFAULT_NODE));
      keys.checkName(options.keyAlias());
    }

    /**
     * A copy of the key {@code alias} names, from {@link LocalKeys#forDecrypt}. Refused before any
     * request when the alias is malformed or not a {@code kmip:} alias.
     */
    @Override
    public Key getSecretKey(String alias) throws IOException {
      return keys.secretKey(alias);
    }

    @Override
    public KeyForFile keyForNewFile(String configuredAlias) throws IOException {
      keys.checkName(configuredAlias);
      return keys.keyForNewFile();
    }

    /**
     * A copy of the key {@code alias} names, from {@link LocalKeys#forAppend(String)}: only while
     * it is Active, in the family, before its protection deadline and leased.
     */
    @Override
    public Key keyForAppend(String alias) throws IOException {
      return keys.keyForAppend(alias);
    }
  }

  /**
   * Immutable aliases: {@code kmip:} and the base64url (no padding) of the key's unique identifier
   * in UTF-8. Server identifiers may contain any character (a colon, a slash, a {@code #}), so they
   * are encoded rather than embedded. Decoding is strict: one canonical form per identifier, so an
   * alias cannot be made to name a key some other way.
   */
  public static final class AliasCodec {
    public static final String PREFIX = "kmip:";
    /** Longer aliases are refused unread; server identifiers are far shorter. */
    static final int MAX_LENGTH = 1024;

    private AliasCodec() {}

    public static String encode(String keyId) {
      if (keyId == null || keyId.isEmpty()) throw new IllegalArgumentException("No key identifier");
      return PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(keyId.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * The key identifier {@code alias} names.
     *
     * @throws IllegalArgumentException when it is not exactly what {@link #encode} makes of an
     *     identifier: another prefix (a name, a keystore alias), padding, characters outside
     *     base64url, a non-canonical encoding, or bytes that are not UTF-8 text
     */
    public static String decode(String alias) {
      if (alias == null || !alias.startsWith(PREFIX))
        throw new IllegalArgumentException("Not a kmip: alias, so not an immutable key identifier: " + alias);
      if (alias.length() > MAX_LENGTH) throw new IllegalArgumentException("Alias longer than " + MAX_LENGTH);
      String encoded = alias.substring(PREFIX.length());
      for (int i = 0; i < encoded.length(); i++) {
        char c = encoded.charAt(i);
        boolean base64url =
            (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
        if (!base64url) throw new IllegalArgumentException("Not base64url without padding: " + alias);
      }
      byte[] bytes;
      try {
        bytes = Base64.getUrlDecoder().decode(encoded);
      } catch (IllegalArgumentException e) {
        throw new IllegalArgumentException("Not base64url: " + alias, e);
      }
      String id;
      try {
        id =
            StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(bytes))
                .toString();
      } catch (CharacterCodingException e) {
        throw new IllegalArgumentException("Not a UTF-8 identifier: " + alias, e);
      }
      // Unused low bits in the last character would let several aliases name one key.
      if (id.isEmpty() || !encode(id).equals(alias))
        throw new IllegalArgumentException("Not the canonical alias of an identifier: " + alias);
      return id;
    }
  }

  /**
   * What a node's key service is started with.
   *
   * @param keyName the KMIP Name new files go under (the configured {@code key_alias}); used only
   *     to select the write key, never to decrypt
   * @param family the value of {@link #FAMILY} on every key files may name
   * @param ttl the longest a key is handed out without the KMS confirming it (and so the longest
   *     a node writes through a KMS outage, if no lease ends sooner)
   * @param refreshAfter when a used key is confirmed again in the background: rotation is followed
   *     within this, at the next key use
   * @param capacity how many keys the node's cache holds, the write key included
   */
  public record Settings(String keyName, String family, Duration ttl, Duration refreshAfter, int capacity) {
    public Settings {
      Objects.requireNonNull(keyName, "keyName");
      Objects.requireNonNull(family, "family");
      Objects.requireNonNull(ttl, "ttl");
      Objects.requireNonNull(refreshAfter, "refreshAfter");
    }

    /** The family named as the key; a 10-minute TTL, refreshed after a minute; 64 keys. */
    public static Settings of(String keyName) {
      return new Settings(keyName, keyName, Duration.ofMinutes(10), Duration.ofMinutes(1), 64);
    }

    /** The node's cache, configured and not yet opened: it owns a KMS connected at first use. */
    public LocalKeys.Builder localKeys(KmsConfig config) {
      return LocalKeys.builder(config, keyName)
          .scope(KeyQuery.all().custom(FAMILY, family))
          .expect(Expect.aes()) // any AES size: a lineage's size may change
          .ttl(ttl)
          .refreshAfter(refreshAfter)
          .capacity(capacity);
    }
  }

  /**
   * The node's key service: one {@link LocalKeys}. The node calls {@link #start} before it opens
   * its commit log (and before replay), and {@link #stop} after it stopped writing and replaying.
   */
  public static final class NodeKeys implements AutoCloseable {
    static final String DEFAULT_NODE = "node";
    /** Running services by node, between start and stop only. Application code, not the SDK's. */
    private static final Map<String, NodeKeys> RUNNING = new ConcurrentHashMap<>();

    private final String node;
    private final String keyName;
    private final LocalKeys keys;
    private volatile boolean stopped;

    private NodeKeys(String node, String keyName, LocalKeys keys) {
      this.node = node;
      this.keyName = keyName;
      this.keys = keys;
    }

    /**
     * Starts the node's key service. Sends nothing: the first key use connects, waiting for the
     * KMS as long as {@code config}'s {@code connectRetry} and call timeout allow.
     */
    public static NodeKeys start(String node, KmsConfig config, Settings settings) {
      return start(node, settings.keyName(), settings.localKeys(config).open());
    }

    /** Starts the service on {@code keys}, opened for {@code keyName}; it owns and closes them. */
    public static NodeKeys start(String node, String keyName, LocalKeys keys) {
      NodeKeys started = new NodeKeys(node, keyName, keys);
      if (RUNNING.putIfAbsent(node, started) != null) {
        keys.close();
        throw new IllegalStateException("Node keys already running for " + node);
      }
      return started;
    }

    /** The service {@code node} started, for a provider the database instantiated. */
    public static NodeKeys running(String node) {
      NodeKeys keys = RUNNING.get(node);
      if (keys == null)
        throw new IllegalStateException("The node's key service " + node + " is not running: start it before TDE");
      return keys;
    }

    /** The alias and a copy of the key for a new file, from one {@link LocalKeys#forEncrypt}. */
    public KeyForFile keyForNewFile() throws IOException {
      requireRunning();
      try (LocalKeys.Use use = keys.forEncrypt()) {
        return new KeyForFile(AliasCodec.encode(use.id()), copyOf(use.key()));
      } catch (KmsException e) {
        throw unavailable("No key for new files under " + keyName, e);
      } catch (IllegalStateException e) {
        throw stopped(e);
      }
    }

    /** A copy of the key {@code alias} names for an open file's next chunk; see {@link KmipKeyProvider#keyForAppend}. */
    public DestroyableSecretKey keyForAppend(String alias) throws IOException {
      String id = decoded(alias);
      requireRunning();
      try (LocalKeys.Use use = keys.forAppend(id)) {
        return copyOf(use.key());
      } catch (KmsException e) {
        throw unavailable("Cannot append under key " + id + " for " + alias + "; start a new file", e);
      } catch (IllegalStateException e) {
        throw stopped(e);
      }
    }

    /** A copy of the key {@code alias} names; see {@link KmipKeyProvider#getSecretKey}. */
    public DestroyableSecretKey secretKey(String alias) throws IOException {
      String id = decoded(alias);
      requireRunning();
      try (LocalKeys.Use use = keys.forDecrypt(id)) {
        return copyOf(use.key());
      } catch (KmsException e) {
        throw unavailable("Cannot use key " + id + " for " + alias, e);
      } catch (IllegalStateException e) {
        throw stopped(e);
      }
    }

    /**
     * Drops this node's cached authorization of the key {@code alias} names, so its next use asks
     * the KMS again: after the coordinator revoked it, sooner than the refresh would notice.
     */
    public void forget(String alias) throws IOException {
      keys.invalidate(decoded(alias));
    }

    /**
     * The key new files go under, as far as this node's cache knows, without asking the KMS: for
     * confirming that a node has moved to a new key. Never an authorization.
     */
    public Optional<String> currentWriteId() {
      return keys.currentWriteId();
    }

    /** Wipes every cached key and closes the connection. Idempotent. */
    public void stop() {
      if (stopped) return;
      stopped = true;
      RUNNING.remove(node, this);
      keys.close();
    }

    @Override
    public void close() {
      stop();
    }

    void checkName(String configuredAlias) {
      if (!keyName.equals(configuredAlias))
        throw new IllegalArgumentException("key_alias must be the KMIP Name " + keyName
            + " that new files go under (files record kmip:<id>), not " + configuredAlias);
    }

    private void requireRunning() throws IOException {
      if (stopped) throw stopped(null);
    }

    private KeyUnavailableException stopped(Throwable cause) {
      return new KeyUnavailableException("The node's key service " + node + " is stopped", cause);
    }

    private static KeyUnavailableException unavailable(String what, KmsException e) {
      String why = "";
      // A refused lease: STATE (with the state) for a key that is not Active, else the server's type.
      if ("obtainLease".equals(e.operation()) && (e instanceof StateConflictException || e instanceof PermissionDeniedException))
        why = "; the server refused the key a lease (a server that leases only Active keys refuses a"
            + " Deactivated one: never deactivate a key that files still need there)";
      return new KeyUnavailableException(
          what + " now (" + e.category() + why + "); the file is intact: " + e.getMessage(), e);
    }

    private static String decoded(String alias) throws IOException {
      try {
        return AliasCodec.decode(alias);
      } catch (IllegalArgumentException e) {
        throw new IOException(e.getMessage(), e);
      }
    }

    private static DestroyableSecretKey copyOf(DestroyableSecretKey key) {
      byte[] bytes = key.getEncoded();
      try {
        return new DestroyableSecretKey(bytes, key.getAlgorithm());
      } finally {
        Arrays.fill(bytes, (byte) 0);
      }
    }
  }

  // ---- What the database does with the provider (Cassandra's commit log and hints) ----

  /** An encrypted file: the alias in its header, its IV and its ciphertext. */
  public record Segment(String alias, byte[] iv, byte[] ciphertext) {}

  private static final SecureRandom RANDOM = new SecureRandom();

  /**
   * A new segment or hints file: alias and key from one handout, the key destroyed once the cipher
   * holds it, nothing cached. Fails closed: when the key cannot be had, nothing is written,
   * encrypted or not. AES-GCM here is this sample's choice; the provider supplies keys, not the
   * database's cipher (Cassandra's is its {@code cipher} setting, AES/CBC by default).
   */
  public static Segment encryptSegment(KeyProvider provider, String configuredAlias, byte[] plaintext)
      throws IOException, GeneralSecurityException {
    KeyForFile forFile = provider.keyForNewFile(configuredAlias);
    byte[] iv = new byte[12];
    RANDOM.nextBytes(iv);
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    try {
      cipher.init(Cipher.ENCRYPT_MODE, forFile.key(), new GCMParameterSpec(128, iv));
    } finally {
      forFile.key().destroy(); // ours; the cipher holds its own
    }
    cipher.updateAAD(forFile.alias().getBytes(StandardCharsets.UTF_8));
    return new Segment(forFile.alias(), iv, cipher.doFinal(plaintext));
  }

  /**
   * An append-only file (a commit log segment, a hints file): one alias, recorded once in its
   * header, and chunks appended for as long as the file is open, each under a fresh cipher
   * initialized with a key the provider hands out again for that chunk ({@link
   * KeyProvider#keyForAppend}). So a key that may no longer encrypt stops the file within one TTL
   * (or its lease), and its refusal closes the file. Each chunk is a {@link Segment} under the
   * file's alias, read back with {@link #decryptSegment}.
   */
  public static final class AppendOnlyFile {
    private final String alias;
    private final List<Segment> chunks = new ArrayList<>();
    private boolean closed;

    private AppendOnlyFile(String alias) {
      this.alias = alias;
    }

    /** A new file under the key new files use now, with its first chunk; nothing written when the key cannot be had. */
    public static AppendOnlyFile create(KeyProvider provider, String configuredAlias, byte[] first)
        throws IOException, GeneralSecurityException {
      KeyForFile forFile = provider.keyForNewFile(configuredAlias);
      AppendOnlyFile file = new AppendOnlyFile(forFile.alias());
      file.chunks.add(encrypt(forFile.alias(), forFile.key(), first));
      return file;
    }

    /**
     * Appends {@code chunk} under the file's own key, asked for again now. When the key can no
     * longer encrypt (a definite refusal), closes the file and throws: the database starts a new
     * one with {@link #create}. A transient failure (the KMS unreachable) throws and leaves the file
     * open, to retry.
     */
    public void append(KeyProvider provider, byte[] chunk) throws IOException, GeneralSecurityException {
      if (closed) throw new IOException("The file " + alias + " is closed: start a new one");
      Key key;
      try {
        key = provider.keyForAppend(alias);
      } catch (IOException e) {
        // A definite refusal ends the file; a transient failure (the KMS unreachable) may be retried.
        if (!(e.getCause() instanceof TransientException)) closed = true;
        throw e;
      }
      chunks.add(encrypt(alias, key, chunk));
    }

    public String alias() {
      return alias;
    }

    public boolean closed() {
      return closed;
    }

    /** The chunks written, in order. */
    public List<Segment> chunks() {
      return List.copyOf(chunks);
    }

    private static Segment encrypt(String alias, Key key, byte[] plaintext) throws GeneralSecurityException {
      byte[] iv = new byte[12];
      RANDOM.nextBytes(iv);
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      try {
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
      } finally {
        DestroyableSecretKey.destroyQuietly(key); // ours; the cipher holds its own
      }
      cipher.updateAAD(alias.getBytes(StandardCharsets.UTF_8));
      return new Segment(alias, iv, cipher.doFinal(plaintext));
    }
  }

  /** Reading: the key the segment's own alias names, whatever key new files use now. */
  public static byte[] decryptSegment(KeyProvider provider, Segment segment) throws IOException, GeneralSecurityException {
    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
    Key key = provider.getSecretKey(segment.alias());
    try {
      cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, segment.iv()));
    } finally {
      DestroyableSecretKey.destroyQuietly(key);
    }
    cipher.updateAAD(segment.alias().getBytes(StandardCharsets.UTF_8));
    return cipher.doFinal(segment.ciphertext());
  }

  /** What {@link #replay} did: the plaintexts read, the files kept for later, the corrupt ones. */
  public record Replay(List<byte[]> read, List<Segment> kept, List<Segment> corrupt) {}

  /**
   * Replay or hint delivery: a file whose key cannot be had now is kept for the next attempt, not
   * taken for corrupt (and deleted); only a file that fails authentication is corrupt.
   */
  public static Replay replay(KeyProvider provider, List<Segment> files) throws GeneralSecurityException {
    List<byte[]> read = new ArrayList<>();
    List<Segment> kept = new ArrayList<>(), corrupt = new ArrayList<>();
    for (Segment file : files) {
      try {
        read.add(decryptSegment(provider, file));
      } catch (KeyUnavailableException e) {
        kept.add(file);
      } catch (IOException | javax.crypto.AEADBadTagException e) {
        corrupt.add(file); // a malformed alias in the header, or ciphertext that does not authenticate
      }
    }
    return new Replay(read, kept, corrupt);
  }

  // ---- The coordinator: run from one place, never from every node ----

  /**
   * Creates the key once, before TDE is enabled: AES-256, in {@code family}, extractable, since the
   * database encrypts with its value (KMIP 1.4 and later). Give the nodes' KMS identity access to
   * these keys only (Get, Get Attributes, Locate, Obtain Lease): whoever can Get them has their
   * value. Node credentials must not be able to change the family attribute.
   */
  public static KeyHandle provision(Kms kms, String keyName, String family) {
    return kms.keys().createAes(256).named(keyName)
        .custom(FAMILY, family)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .extractable(true)
        .findOrCreate();
  }

  /**
   * The scheduled rotation: a Re-key, which moves the name and copies the family. The old key
   * stays Active, so files under it replay on a server that leases only Active keys; nodes move
   * new files to the new key at their first key use after the refresh interval.
   */
  public static KeyHandle rotate(Kms kms, String keyName, Duration period) {
    return kms.keys().current(keyName).rotateIfActiveFor(period); // the rotation job's entry point
  }

  /**
   * Destroys the keys of the lineage older than every key a file still names: {@code
   * referencedAliases} are the aliases every node's scan found (after a flush recycled the
   * segments and the hints drained). Refuses, destroying nothing, when a referenced key is not in
   * the lineage the listing reaches.
   */
  public static List<KeyHandle> retireUnreferenced(Kms kms, String keyName, Collection<String> referencedAliases) {
    Set<String> referenced = new HashSet<>();
    for (String alias : referencedAliases) referenced.add(AliasCodec.decode(alias));
    KeyHandle current = kms.keys().findByName(keyName).orElseThrow();
    List<LineageKey> versions = current.lineage(); // newest first: the last referenced is the oldest kept
    String keepFrom = current.id();
    Set<String> listed = new HashSet<>();
    for (LineageKey v : versions) {
      listed.add(v.id());
      if (referenced.contains(v.id())) keepFrom = v.id();
    }
    if (!listed.containsAll(referenced))
      throw new IllegalStateException("A file names a key outside the lineage listed; retiring nothing");
    return current.retirePredecessorsOlderThan(kms.keys().handle(keepFrom), RevocationReason.superseded("rotated"));
  }

  /**
   * The compromise of the key {@code alias} names, by its exact identifier: revoked as
   * Compromised, and replaced once by an Active key with its name and family. Nodes move new files
   * to the replacement at their next key use after the refresh interval (at once after {@link
   * NodeKeys#forget}). Files under the compromised key can no longer be read.
   */
  public static KeyHandle replaceCompromised(Kms kms, String alias, Instant since) {
    KeyHandle compromised = kms.keys().handle(AliasCodec.decode(alias));
    return compromised.replaceCompromised(RevocationReason.keyCompromise("TDE key exposed", since));
  }
}
