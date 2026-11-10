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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.channels.OverlappingFileLockException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.function.Function;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The files of a client certificate renewal ({@link ClientRenewal}): the configured identity files
 * ({@link KmsConfig.Builder#clientIdentityPem}, {@link KmsConfig.Builder#clientIdentityKeyStore}),
 * and the pending file beside them, named after the key file (or key store) with {@link #SUFFIX}.
 *
 * <p>The pending file is PEM: a few header lines (what it is, the fingerprint of the certificate it
 * replaces, the new public key, the server's time when the key was written, and once issued the new
 * certificate's identifier), then, once the server issued it, the new certificate chain, then the
 * new private key, encrypted (PBES2) under the key's password when the key file is encrypted and
 * always for a key store. It is written before anything is sent, holding the key only, and again
 * once the new certificate is checked, holding both; so a crash or a lost reply never loses the
 * private key. The switch then replaces the identity files (the chain file before the key file)
 * and deletes the pending file. Every write is atomic and durable ({@link StagedFiles#write}); the
 * key, a combined file and a key store are written for the owner only, and a chain file keeps its
 * permissions.
 *
 * <p>A pending key is never deleted while the server might still issue a certificate for it. When
 * it is no longer used, but an earlier message that carried it may still commit, it is moved aside
 * ({@link #setAside}) to {@code <pending file>.<time>.unresolved}, with {@code -<n>} after the
 * time when that name is taken: a move never replaces another file.
 */
final class RenewalFiles {
  /** The suffix of the pending file. */
  static final String SUFFIX = ".renewal";

  /** The suffix of a pending file moved aside while the server might still issue for its key. */
  static final String UNRESOLVED = ".unresolved";

  /** The suffix of a pending file moved aside because it was written for other identity files. */
  static final String ORPHANED = ".orphaned";

  /** PBKDF2 iterations for a new encrypted key: current PBKDF2-HMAC-SHA256 guidance. */
  static final int ITERATIONS = 600_000;

  /**
   * The first header line, then the format's version: {@link #MARK} {@link #FORMAT}. A later
   * release reads every earlier version (docs/compatibility.md, "Stored formats").
   */
  private static final String MARK = "keytend-kmip client certificate renewal";

  /** The version of the format this release writes. */
  static final int FORMAT = 1;

  private static final String REPLACES = "replaces: ",
      CERTIFICATE = "certificate: ",
      PUBLIC_KEY = "public-key: ",
      SERVER_TIME = "server-time: ";
  private static final String PBES2 = "1.2.840.113549.1.5.13",
      PBKDF2 = "1.2.840.113549.1.5.12",
      HMAC_SHA256 = "1.2.840.113549.2.9",
      AES256_CBC = "2.16.840.1.101.3.4.1.42";

  /** The alias of the one key entry of the in-memory stores {@link PemIdentity} makes. */
  private static final String PEM_ALIAS = "identity";

  final TlsFiles.Identity identity;
  private final SecureRandom random = new SecureRandom();

  RenewalFiles(TlsFiles.Identity identity) {
    this.identity = identity;
  }

  /** The pending file: the key file's (or key store's) name with {@link #SUFFIX}, beside it. */
  Path pendingFile() {
    Path base = identity.store != null ? identity.store : identity.key;
    return base.resolveSibling(base.getFileName() + SUFFIX);
  }

  /**
   * The lock file: the pending file's name with {@code .lock}, beside it. An attempt holds an
   * exclusive lock on it from start to end, so that processes renewing the same files take turns.
   * It holds nothing and is never deleted: deleting a lock file would let two processes lock two
   * different files of one name.
   */
  Path lockFile() {
    Path pending = pendingFile();
    return pending.resolveSibling(pending.getFileName() + ".lock");
  }

  /**
   * The pending file with its directory's real path, which names these files the same way from
   * every configuration of this process.
   */
  Path realPendingFile() {
    Path pending = pendingFile().toAbsolutePath().normalize();
    Path dir = pending.getParent();
    Path name = pending.getFileName();
    if (dir == null || name == null) return pending;
    Path realDir;
    try {
      realDir = dir.toRealPath();
    } catch (IOException e) {
      return pending;
    }
    return realDir.resolve(name.toString());
  }

  /** Read and write for the owner only, where {@code file}'s file system has POSIX permissions. */
  static FileAttribute<?>[] ownerOnly(Path file) {
    if (!file.getFileSystem().supportedFileAttributeViews().contains("posix"))
      return new FileAttribute<?>[0];
    return new FileAttribute<?>[] {
      PosixFilePermissions.asFileAttribute(
          EnumSet.of(PosixFilePermission.OWNER_READ, PosixFilePermission.OWNER_WRITE))
    };
  }

  /** The configured files, comma-separated, for messages. */
  String names() {
    StringBuilder out = new StringBuilder();
    for (Path p : identity.files()) out.append(out.length() == 0 ? "" : ", ").append(p);
    return out.toString();
  }

  /** The identity as its files hold it now; a key store's entries too. */
  record Current(
      List<X509Certificate> chain,
      PrivateKey key,
      boolean encrypted,
      KeyStore store,
      String alias) {
    X509Certificate leaf() {
      return chain.get(0);
    }
  }

  /**
   * Reads the identity files, checked as the builder checks them.
   *
   * @throws IllegalArgumentException naming the file, as the builder methods
   */
  Current read(char[] password) {
    try {
      if (identity.kind == TlsFiles.IdentityKind.PEM) {
        KeyStore store =
            PemIdentity.keyStore(identity.chain, identity.key, password, TlsFiles.WHOLE);
        return new Current(
            x509(store.getCertificateChain(PEM_ALIAS)),
            (PrivateKey) store.getKey(PEM_ALIAS, new char[0]),
            encrypted(identity.key),
            null,
            null);
      }
      KeyStore store =
          KeyStoreFiles.read(identity.store, null, password, TlsFiles.WHOLE, "key store");
      String alias = null;
      for (String a : Collections.list(store.aliases()))
        if (store.isKeyEntry(a)) {
          if (alias != null)
            throw new IllegalArgumentException(
                identity.store + " holds several private keys; exactly one is needed");
          alias = a;
        }
      if (alias == null)
        throw new IllegalArgumentException(identity.store + " holds no private key");
      Key key = store.getKey(alias, password);
      Certificate[] chain = store.getCertificateChain(alias);
      if (!(key instanceof PrivateKey privateKey) || chain == null || chain.length == 0)
        throw new IllegalArgumentException(
            identity.store + " holds a private key without its certificate chain");
      List<X509Certificate> certificates = x509(chain);
      if (!PemIdentity.matches(privateKey, certificates.get(0).getPublicKey(), identity.store))
        throw new IllegalArgumentException(
            "The private key in "
                + identity.store
                + " does not match the first certificate of its chain");
      return new Current(certificates, privateKey, true, store, alias);
    } catch (GeneralSecurityException e) {
      throw new IllegalArgumentException("Cannot use the private key in " + keyFile(), e);
    }
  }

  /**
   * The certificate the files present now: the first of the chain file (no password needed), or
   * of the key store.
   */
  X509Certificate currentLeaf(char[] password) {
    if (identity.kind == TlsFiles.IdentityKind.KEY_STORE) return read(password).leaf();
    if (!PemIdentity.combined(identity.chain, identity.key))
      return PemIdentity.certificates(identity.chain, TlsFiles.WHOLE).get(0);
    byte[] text = TlsFiles.WHOLE.read(identity.chain, "certificate file");
    try {
      return PemIdentity.certificates(text, identity.chain, true, false).get(0);
    } finally {
      Arrays.fill(text, (byte) 0);
    }
  }

  /** Whether the PEM private key file holds an encrypted key. */
  private static boolean encrypted(Path keyFile) {
    byte[] text = TlsFiles.WHOLE.read(keyFile, "private key file");
    try {
      for (Pem.Block b : Pem.blocks(text, keyFile))
        if (b.label().equals("ENCRYPTED PRIVATE KEY")) return true;
      return false;
    } finally {
      Arrays.fill(text, (byte) 0);
    }
  }

  /**
   * Whether a pending file of these files is encrypted: when the PEM key file is encrypted, and
   * always for a key store.
   */
  boolean keyEncrypted() {
    return identity.kind == TlsFiles.IdentityKind.KEY_STORE || encrypted(identity.key);
  }

  private Path keyFile() {
    return identity.store != null ? identity.store : identity.key;
  }

  /**
   * What the pending file holds: the new key pair; once issued, the new chain and its identifier;
   * the fingerprint of the certificate it replaces; when the file was last written, by this
   * machine's clock; and the server's time when the key was written (null when not recorded).
   */
  record Pending(
      PrivateKey key,
      PublicKey publicKey,
      List<X509Certificate> chain,
      String replaces,
      String certificateId,
      Instant written,
      Instant serverTime) {
    boolean issued() {
      return !chain.isEmpty();
    }
  }

  /**
   * The pending file, or null when there is none.
   *
   * @throws IOException when it cannot be read
   * @throws IllegalArgumentException when it is not a pending file this class wrote, or its key
   *     does not decrypt with {@code password}
   */
  Pending readPending(char[] password) throws IOException {
    Path file = pendingFile();
    if (!Files.exists(file)) return null;
    if (Files.size(file) == 0) {
      // Claimed by writeNewPending, which stopped before it wrote the key: nothing was sent.
      Files.deleteIfExists(file);
      return null;
    }
    return readPending(file, password);
  }

  /**
   * The pending file {@code file}, which may be one moved aside ({@link #unresolved()}).
   *
   * @throws IOException when it cannot be read
   * @throws IllegalArgumentException when it is not a pending file this class wrote, or its key
   *     does not decrypt with {@code password}
   */
  static Pending readPending(Path file, char[] password) throws IOException {
    Instant written = Files.getLastModifiedTime(file).toInstant();
    byte[] text = Files.readAllBytes(file);
    try {
      String replaces = null, certificateId = null, publicKey = null, serverTime = null;
      boolean marked = false;
      int certificates = 0;
      String all = new String(text, StandardCharsets.US_ASCII);
      int body = all.indexOf("-----BEGIN");
      for (String line : (body < 0 ? all : all.substring(0, body)).split("\n")) {
        line = line.strip();
        if (line.startsWith(MARK)) {
          int format = format(line);
          if (format > FORMAT)
            throw new IllegalArgumentException(
                file
                    + " is a pending renewal file of format "
                    + format
                    + ", which a later release of this SDK wrote; this release reads up to "
                    + FORMAT);
          marked = format > 0;
        } else if (line.startsWith(REPLACES)) replaces = line.substring(REPLACES.length());
        else if (line.startsWith(CERTIFICATE)) certificateId = line.substring(CERTIFICATE.length());
        else if (line.startsWith(PUBLIC_KEY)) publicKey = line.substring(PUBLIC_KEY.length());
        else if (line.startsWith(SERVER_TIME)) serverTime = line.substring(SERVER_TIME.length());
      }
      if (!marked || replaces == null || publicKey == null)
        throw new IllegalArgumentException(
            file + " is not a pending renewal file of this SDK (no header); move it away");
      for (Pem.Block b : Pem.blocks(text, file))
        if (!b.label().endsWith("PRIVATE KEY")) certificates++;
      List<X509Certificate> chain =
          certificates == 0 ? List.of() : PemIdentity.certificates(text, file, true, false);
      PrivateKey key = PemIdentity.privateKey(text, file, password);
      PublicKey pub;
      try {
        pub = ClientRenewal.publicKey(key.getAlgorithm(), Base64.getDecoder().decode(publicKey));
      } catch (GeneralSecurityException | IllegalArgumentException e) {
        throw new IllegalArgumentException(file + ": the public key in its header is malformed");
      }
      if (!PemIdentity.matches(key, pub, file)
          || (!chain.isEmpty()
              && !Arrays.equals(chain.get(0).getPublicKey().getEncoded(), pub.getEncoded())))
        throw new IllegalArgumentException(
            "The private key in " + file + " does not match the public key or certificate in it");
      Instant server;
      try {
        server = serverTime == null ? null : Instant.parse(serverTime);
      } catch (java.time.format.DateTimeParseException e) {
        throw new IllegalArgumentException(file + ": the server time in its header is malformed");
      }
      return new Pending(key, pub, chain, replaces, certificateId, written, server);
    } finally {
      Arrays.fill(text, (byte) 0);
    }
  }

  /**
   * Writes the pending file: {@code key} (encrypted under {@code password} when it is not null)
   * and its {@code publicKey}, and once issued its {@code chain} and {@code certificateId} (null
   * before); {@code serverTime}, the server's time when the key was first written, when known.
   */
  void writePending(
      PrivateKey key,
      List<X509Certificate> chain,
      String replaces,
      String certificateId,
      PublicKey publicKey,
      char[] password,
      Instant serverTime)
      throws IOException, GeneralSecurityException {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    String header =
        MARK
            + " "
            + FORMAT
            + "\n"
            + REPLACES
            + replaces
            + "\n"
            + PUBLIC_KEY
            + Base64.getEncoder().encodeToString(publicKey.getEncoded())
            + "\n"
            + (serverTime == null ? "" : SERVER_TIME + serverTime + "\n")
            + (certificateId == null ? "" : CERTIFICATE + oneLine(certificateId) + "\n");
    out.writeBytes(header.getBytes(StandardCharsets.US_ASCII));
    for (X509Certificate c : chain) out.writeBytes(pem("CERTIFICATE", c.getEncoded()));
    byte[] keyBlock = keyBlock(key, password);
    out.writeBytes(keyBlock);
    Arrays.fill(keyBlock, (byte) 0);
    byte[] content = out.toByteArray();
    try {
      StagedFiles.write(pendingFile(), content, null);
    } finally {
      Arrays.fill(content, (byte) 0);
    }
  }

  /**
   * Writes the first pending file of an attempt, which holds only {@code key}, as {@link
   * #writePending} does; but the name is claimed first with {@code CREATE_NEW}, so a pending file
   * another holder wrote since this attempt read it is never replaced.
   *
   * @param claimed the failure to throw when the pending file exists
   */
  void writeNewPending(
      PrivateKey key,
      String replaces,
      PublicKey publicKey,
      char[] password,
      Instant serverTime,
      Function<Path, RuntimeException> claimed)
      throws IOException, GeneralSecurityException {
    Path file = pendingFile();
    try {
      Files.newByteChannel(
              file,
              EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
              ownerOnly(file))
          .close();
    } catch (FileAlreadyExistsException e) {
      throw claimed.apply(file);
    }
    try {
      writePending(key, List.of(), replaces, null, publicKey, password, serverTime);
    } catch (IOException | GeneralSecurityException | RuntimeException e) {
      // Nothing was sent: leave no claim behind (an empty file is read as none anyway).
      if (Files.size(file) == 0) Files.deleteIfExists(file);
      throw e;
    }
  }

  /**
   * Moves the pending file aside, to {@code <pending file>.<time>.orphaned}, and forces its
   * directory: it was written for other identity files, and may hold the only copy of a key.
   *
   * @return where it is now
   */
  Path orphanPending(Instant now) throws IOException {
    return moveAside(now, ORPHANED);
  }

  /**
   * Moves the pending file aside, to {@code <pending file>.<time>.unresolved}, and forces its
   * directory: its key is no longer used, but a message that carried it may still commit, so the
   * server may still issue a certificate for it. Moved aside rather than deleted, it can still be
   * used to recover from a lockout.
   *
   * @return where it is now
   */
  Path setAside(Instant now) throws IOException {
    return moveAside(now, UNRESOLVED);
  }

  /** The most names {@link #moveAside} tries for one time before it gives up. */
  static final int ASIDE_ATTEMPTS = 1000;

  /**
   * Moves the pending file to {@code <pending file>.<time><suffix>}, or {@code
   * <pending file>.<time>-<n><suffix>} when that name is taken (a clock that stepped back, or two
   * moves in one millisecond): the name is reserved first with {@code CREATE_NEW}, so an earlier
   * file moved aside, which may hold the only copy of a key, is never replaced. The move then
   * replaces only that empty reservation, atomically, and the directory is forced.
   */
  private Path moveAside(Instant now, String suffix) throws IOException {
    Path file = pendingFile();
    String time =
        DateTimeFormatter.ofPattern("uuuuMMdd'T'HHmmssSSS'Z'").withZone(ZoneOffset.UTC).format(now);
    Path target = null;
    for (int n = 0; target == null; n++) {
      if (n == ASIDE_ATTEMPTS)
        throw new IOException(
            "cannot move "
                + file
                + " aside: "
                + ASIDE_ATTEMPTS
                + " names for "
                + time
                + " are taken already");
      Path candidate =
          file.resolveSibling(file.getFileName() + "." + time + (n == 0 ? "" : "-" + n) + suffix);
      try {
        Files.newByteChannel(
                candidate,
                EnumSet.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE),
                ownerOnly(candidate))
            .close();
        target = candidate;
      } catch (FileAlreadyExistsException taken) {
        // Another file moved aside has that name: try the next.
      }
    }
    try {
      Files.move(file, target, StandardCopyOption.ATOMIC_MOVE);
    } catch (IOException | RuntimeException e) {
      try {
        Files.deleteIfExists(target);
      } catch (IOException suppressed) {
        e.addSuppressed(suppressed);
      }
      throw e;
    }
    Path dir = target.toAbsolutePath().getParent();
    if (dir != null) StagedFiles.directorySync.force(dir);
    return target;
  }

  /**
   * The pending files moved aside with {@link #setAside}, in the order of their names (the time
   * they were moved aside); empty when there are none or the directory cannot be listed. An empty
   * file is a name {@link #moveAside} reserved and did not move to (the process stopped in
   * between): it holds nothing, and is not listed.
   */
  List<Path> unresolved() {
    Path pending = pendingFile();
    Path dir = pending.toAbsolutePath().getParent();
    String prefix = pending.getFileName() + ".";
    List<Path> out = new ArrayList<>();
    if (dir == null) return out;
    try (java.util.stream.Stream<Path> listed = Files.list(dir)) {
      listed
          .filter(
              p -> {
                Path name = p.getFileName();
                return name != null
                    && name.toString().startsWith(prefix)
                    && name.toString().endsWith(UNRESOLVED)
                    && !empty(p);
              })
          .sorted()
          .forEach(out::add);
    } catch (IOException | RuntimeException e) {
      return out;
    }
    return out;
  }

  /** What the pending file holds, as far as its header and PEM labels show. */
  enum State {
    NONE,
    EMPTY,
    KEY,
    ISSUED,
    UNREADABLE;

    /** The state of {@code file}, the pending file, for a message. */
    String describe(Path file) {
      return switch (this) {
        case NONE -> "no pending file (" + file + ")";
        case EMPTY -> file + " is empty (claimed, but no key was written to it)";
        case KEY -> file + " holds the new private key only";
        case ISSUED -> file + " holds the new private key and the certificate the server issued";
        case UNREADABLE -> file + " cannot be read as a pending renewal file";
      };
    }
  }

  /**
   * What the pending file holds, read from its header and its PEM labels alone: no key is
   * decrypted, so no password is needed.
   */
  State pendingState() {
    Path file = pendingFile();
    if (!Files.exists(file)) return State.NONE;
    byte[] text;
    try {
      text = Files.readAllBytes(file);
    } catch (IOException | RuntimeException e) {
      return State.UNREADABLE;
    }
    try {
      if (text.length == 0) return State.EMPTY;
      if (replaces(file) == null) return State.UNREADABLE;
      String all = new String(text, StandardCharsets.US_ASCII);
      if (!all.contains("PRIVATE KEY-----")) return State.UNREADABLE;
      return all.contains("-----BEGIN CERTIFICATE-----") ? State.ISSUED : State.KEY;
    } finally {
      Arrays.fill(text, (byte) 0);
    }
  }

  /**
   * The fingerprint on the {@code replaces:} line of the pending file {@code file}, read from its
   * header alone (the key is not decrypted); null when it cannot be read or is not one.
   */
  static String replaces(Path file) {
    byte[] text;
    try {
      text = Files.readAllBytes(file);
    } catch (IOException | RuntimeException e) {
      return null;
    }
    try {
      String all = new String(text, StandardCharsets.US_ASCII);
      int body = all.indexOf("-----BEGIN");
      boolean marked = false;
      String replaces = null;
      for (String line : (body < 0 ? all : all.substring(0, body)).split("\n")) {
        line = line.strip();
        if (line.startsWith(MARK)) marked = format(line) > 0;
        else if (line.startsWith(REPLACES)) replaces = line.substring(REPLACES.length());
      }
      return marked ? replaces : null;
    } finally {
      Arrays.fill(text, (byte) 0);
    }
  }

  /**
   * The format version of the header line {@code line}, which starts with {@link #MARK}: the number
   * it ends with; 0 when it is not a header (no number, or not one alone).
   */
  static int format(String line) {
    String rest = line.substring(MARK.length());
    if (rest.isEmpty() || rest.charAt(0) != ' ') return 0;
    rest = rest.substring(1);
    if (rest.isEmpty() || rest.length() > 9 || !rest.chars().allMatch(c -> c >= '0' && c <= '9'))
      return 0;
    return Integer.parseInt(rest);
  }

  /** Whether {@code file} is empty; false when its size cannot be read. */
  private static boolean empty(Path file) {
    try {
      return Files.size(file) == 0;
    } catch (IOException | RuntimeException e) {
      return false;
    }
  }

  /** {@code id} on one line: an identifier the server chose may hold anything. */
  private static String oneLine(String id) {
    StringBuilder out = new StringBuilder();
    for (char c : id.toCharArray()) out.append(c < 0x20 || c > 0x7e ? '?' : c);
    return out.toString();
  }

  /** Deletes the pending file, durably. */
  void deletePending() throws IOException {
    StagedFiles.delete(pendingFile());
  }

  /**
   * Replaces the identity files with {@code key} and {@code chain}: the chain file then the key
   * file, one combined file, or the key store (its other entries kept, under the same alias and
   * password). A PEM key is encrypted when the key file is now; a key store is always.
   */
  void switchTo(PrivateKey key, List<X509Certificate> chain, char[] password)
      throws IOException, GeneralSecurityException {
    if (identity.kind == TlsFiles.IdentityKind.PEM) {
      byte[] keyBlock = keyBlock(key, encrypted(identity.key) ? password : null);
      ByteArrayOutputStream certificates = new ByteArrayOutputStream();
      for (X509Certificate c : chain) certificates.writeBytes(pem("CERTIFICATE", c.getEncoded()));
      try {
        if (PemIdentity.combined(identity.chain, identity.key)) {
          byte[] both = new byte[certificates.size() + keyBlock.length];
          System.arraycopy(certificates.toByteArray(), 0, both, 0, certificates.size());
          System.arraycopy(keyBlock, 0, both, certificates.size(), keyBlock.length);
          try {
            StagedFiles.write(identity.chain, both, null);
          } finally {
            Arrays.fill(both, (byte) 0);
          }
        } else {
          StagedFiles.write(
              identity.chain, certificates.toByteArray(), permissions(identity.chain));
          StagedFiles.write(identity.key, keyBlock, null);
        }
      } finally {
        Arrays.fill(keyBlock, (byte) 0);
      }
      return;
    }
    Current now = read(password);
    KeyStore next = KeyStore.getInstance(now.store().getType());
    next.load(null, password);
    for (String alias : Collections.list(now.store().aliases())) {
      if (alias.equals(now.alias()))
        next.setKeyEntry(alias, key, password, chain.toArray(Certificate[]::new));
      else if (now.store().isCertificateEntry(alias))
        next.setCertificateEntry(alias, now.store().getCertificate(alias));
    }
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    next.store(out, password);
    byte[] content = out.toByteArray();
    try {
      StagedFiles.write(identity.store, content, null);
    } finally {
      Arrays.fill(content, (byte) 0);
    }
  }

  /** {@code file}'s POSIX permissions, or null where they cannot be read. */
  private static Set<PosixFilePermission> permissions(Path file) {
    try {
      return Files.getPosixFilePermissions(file);
    } catch (IOException | UnsupportedOperationException e) {
      return null;
    }
  }

  /**
   * Finishes a renewal whose switch did not finish (a process that stopped in between): then the
   * files are switched and the pending file deleted. That is a pending file holding the issued
   * certificate, when the files still present the certificate it replaced, or already the new one;
   * or a pending file holding only the key, when the chain file of a PEM key and chain already
   * holds a certificate for that key (the switch stopped between the chain file and the key file).
   *
   * @return the pending renewal finished, with the chain the files now hold; or null when there was
   *     none to finish
   * @throws IOException when the pending file or the identity files cannot be read or written
   */
  Pending finishIssued(char[] password) throws IOException, GeneralSecurityException {
    Pending p = readPending(password);
    if (p == null) return null;
    X509Certificate leaf;
    try {
      leaf = currentLeaf(password);
    } catch (IllegalArgumentException unreadable) {
      return null;
    }
    if (!p.issued()) {
      // Only a two-file PEM switch writes the chain and the key apart.
      if (identity.kind != TlsFiles.IdentityKind.PEM
          || PemIdentity.combined(identity.chain, identity.key)
          || !Arrays.equals(leaf.getPublicKey().getEncoded(), p.publicKey().getEncoded()))
        return null;
      List<X509Certificate> chain;
      try {
        chain = PemIdentity.certificates(identity.chain, TlsFiles.WHOLE);
      } catch (IllegalArgumentException unreadable) {
        return null;
      }
      switchTo(p.key(), chain, password);
      deletePending();
      return new Pending(
          p.key(), p.publicKey(), chain, p.replaces(), null, p.written(), p.serverTime());
    }
    String now = fingerprint(leaf);
    if (!now.equals(p.replaces()) && !now.equals(fingerprint(p.chain().get(0)))) return null;
    switchTo(p.key(), p.chain(), password);
    deletePending();
    return p;
  }

  /**
   * For {@link KmsConfig.Builder}'s identity methods, before they read the files: finishes a
   * renewal whose switch stopped ({@link #finishIssued}). A pending file that cannot be read is
   * left as it is; a switch that fails to write is an {@link IllegalArgumentException} naming the
   * files.
   */
  static void finishBeforeLoad(TlsFiles.Identity identity) {
    RenewalFiles files = new RenewalFiles(identity);
    if (!Files.exists(files.pendingFile())) return;
    char[] password = identity.passwordForUse();
    // A renewal running in another process finishes the switch itself.
    try (FileChannel lock = files.tryLock()) {
      if (lock == null) return;
      Pending p;
      try {
        p = files.readPending(password);
      } catch (IOException | IllegalArgumentException unreadable) {
        return;
      }
      if (p == null) return;
      try {
        files.finishIssued(password);
      } catch (IOException | GeneralSecurityException e) {
        throw new IllegalArgumentException(
            "A client certificate renewal was issued but its files were not all switched, and"
                + " finishing it failed: "
                + files.names()
                + " (the new key and certificate are in "
                + files.pendingFile()
                + "): "
                + e.getMessage(),
            e);
      }
    } catch (IOException cannotLock) {
      // The lock file cannot be made (a read-only directory): finishing would fail too.
    } finally {
      if (password != null) Arrays.fill(password, '\0');
    }
  }

  /**
   * The exclusive lock on {@link #lockFile()}: the locked channel, whose closing releases it; null
   * when another holder has it (another process, or code of this process that locked it without
   * this class).
   */
  FileChannel tryLock() throws IOException {
    Path file = lockFile();
    FileChannel channel =
        FileChannel.open(
            file, Set.of(StandardOpenOption.CREATE, StandardOpenOption.WRITE), ownerOnly(file));
    try {
      if (channel.tryLock() != null) return channel;
      channel.close();
      return null;
    } catch (OverlappingFileLockException heldHere) {
      channel.close();
      return null;
    } catch (IOException | RuntimeException e) {
      channel.close();
      throw e;
    }
  }

  /** The SHA-256 fingerprint of {@code certificate}'s DER, lowercase hex. */
  static String fingerprint(X509Certificate certificate) {
    try {
      return HexFormat.of()
          .formatHex(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException("No SHA-256 or no certificate encoding", e);
    }
  }

  private static List<X509Certificate> x509(Certificate[] chain) {
    List<X509Certificate> out = new ArrayList<>();
    if (chain != null) for (Certificate c : chain) out.add((X509Certificate) c);
    if (out.isEmpty()) throw new IllegalArgumentException("No certificate chain");
    return out;
  }

  /** {@code key} as a PKCS#8 PEM block, encrypted under {@code password} when it is not null. */
  private byte[] keyBlock(PrivateKey key, char[] password) throws GeneralSecurityException {
    byte[] pkcs8 = key.getEncoded();
    if (pkcs8 == null || !"PKCS#8".equals(key.getFormat()))
      throw new GeneralSecurityException("The new private key has no PKCS#8 encoding");
    try {
      if (password == null) return pem("PRIVATE KEY", pkcs8);
      byte[] encrypted = encrypt(pkcs8, password);
      return pem("ENCRYPTED PRIVATE KEY", encrypted);
    } finally {
      Arrays.fill(pkcs8, (byte) 0);
    }
  }

  /**
   * A DER EncryptedPrivateKeyInfo of {@code pkcs8}: PBES2 with PBKDF2-HMAC-SHA256 ({@link
   * #ITERATIONS}, a 16-byte salt) and AES-256-CBC, as {@code openssl pkcs8 -topk8 -v2 aes-256-cbc}
   * writes it.
   */
  byte[] encrypt(byte[] pkcs8, char[] password) throws GeneralSecurityException {
    byte[] salt = new byte[16], iv = new byte[16];
    random.nextBytes(salt);
    random.nextBytes(iv);
    PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, 256);
    byte[] derived = null;
    try {
      derived =
          SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
      Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
      aes.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(derived, "AES"), new IvParameterSpec(iv));
      byte[] encrypted = aes.doFinal(pkcs8);
      byte[] parameters =
          Der.sequence(
              Der.sequence(
                  Der.oid(PBKDF2),
                  Der.sequence(
                      Der.octetString(salt),
                      Der.integer(ITERATIONS),
                      Der.sequence(Der.oid(HMAC_SHA256), Der.nul()))),
              Der.sequence(Der.oid(AES256_CBC), Der.octetString(iv)));
      return Der.sequence(Der.sequence(Der.oid(PBES2), parameters), Der.octetString(encrypted));
    } finally {
      spec.clearPassword();
      if (derived != null) Arrays.fill(derived, (byte) 0);
    }
  }

  /** A PEM block: 64 Base64 characters a line. */
  static byte[] pem(String label, byte[] der) {
    byte[] body = Base64.getMimeEncoder(64, new byte[] {'\n'}).encode(der);
    byte[] begin = ("-----BEGIN " + label + "-----\n").getBytes(StandardCharsets.US_ASCII);
    byte[] end = ("\n-----END " + label + "-----\n").getBytes(StandardCharsets.US_ASCII);
    byte[] out = new byte[begin.length + body.length + end.length];
    System.arraycopy(begin, 0, out, 0, begin.length);
    System.arraycopy(body, 0, out, begin.length, body.length);
    System.arraycopy(end, 0, out, begin.length + body.length, end.length);
    Arrays.fill(body, (byte) 0);
    return out;
  }
}
