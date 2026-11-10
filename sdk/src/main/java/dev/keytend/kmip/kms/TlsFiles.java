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

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.FileTime;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.StringJoiner;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import java.util.function.Supplier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/**
 * TLS settings read from files, and reading them again when they change, for {@link
 * KmsConfig.Builder#reloadOnChange(Duration)}.
 */
final class TlsFiles {
  private TlsFiles() {}

  /** The largest TLS file a reload reads: a CA bundle of public CAs is a few hundred KiB. */
  static final int MAX_FILE_BYTES = 1 << 20;

  /** Checks in a row that may put off reading files that change again each time. */
  static final int MAX_DEFERRALS = 4;

  /**
   * Reads in a row that may find a key and certificate that do not match (two files, settled) and
   * take them for a renewal between its files: reported as still changing, then as a failure at the
   * next read, two intervals after the first, or later: see {@link #MISMATCH_FLOOR}.
   */
  static final int MISMATCH_GRACE = 2;

  /**
   * The least time, from the first read that found a key and certificate not matching, that they
   * are taken for a renewal between its files, however short the interval: a mismatch is a failure
   * only once both {@link #MISMATCH_GRACE} reads and this long have passed.
   */
  static final Duration MISMATCH_FLOOR = Duration.ofSeconds(10);

  /**
   * Reads a TLS file for a loader, which parses only the bytes returned and never opens the file
   * again; {@code what} names the kind of file for the message. Failures are {@link
   * IllegalArgumentException}s naming the file.
   */
  interface Reader {
    byte[] read(Path file, String what);
  }

  /** The builder's and the factories' reads: the whole file. */
  static final Reader WHOLE =
      (file, what) -> {
        try {
          return Files.readAllBytes(file);
        } catch (IOException e) {
          throw new IllegalArgumentException("Cannot read the " + what + " " + file, e);
        }
      };

  /**
   * A reload's reads: at most {@link #MAX_FILE_BYTES} bytes from the opened file, whatever its size
   * was when it was stat-ed (it may have grown, or been replaced, since).
   */
  static byte[] bounded(Path file, String what) {
    byte[] data;
    try (InputStream in = Files.newInputStream(file)) {
      data = in.readNBytes(MAX_FILE_BYTES + 1);
    } catch (IOException e) {
      throw new IllegalArgumentException("Cannot read the " + what + " " + file, e);
    }
    if (data.length > MAX_FILE_BYTES) {
      Arrays.fill(data, (byte) 0);
      throw new IllegalArgumentException(
          "The TLS file "
              + file
              + " has more than the "
              + MAX_FILE_BYTES
              + " bytes a reload reads");
    }
    return data;
  }

  /**
   * After a failed load of files that have not changed since, the checks that read them again:
   * the 1st, 2nd, 4th, 8th, ... up to the 64th, then every 64th, so a key that only became readable
   * is picked up while an encrypted key that will not decrypt does not cost its key derivation on
   * every check.
   */
  static boolean retries(int checksSinceFailure) {
    int n = checksSinceFailure;
    return n <= 64 ? (n & (n - 1)) == 0 : n % 64 == 0;
  }

  /** What a {@code stat} says about a file; a file that cannot be read has all fields null or -1. */
  record Stamp(FileTime modified, long size, Object fileKey) {
    static final Stamp UNREADABLE = new Stamp(null, -1, null);
  }

  /** The state of each file, in order; taken before the files are read. */
  static List<Stamp> stamps(Path... files) {
    List<Stamp> out = new ArrayList<>();
    for (Path f : files) {
      try {
        BasicFileAttributes a = Files.readAttributes(f, BasicFileAttributes.class);
        out.add(new Stamp(a.lastModifiedTime(), a.size(), a.fileKey()));
      } catch (IOException | RuntimeException e) {
        out.add(Stamp.UNREADABLE);
      }
    }
    return out;
  }

  /**
   * The password of a TLS file: the builder's own copy, or the caller's supplier, asked at each
   * read. {@link #get} gives an array the caller wipes after use.
   */
  abstract static class Password {
    /** A new array holding the password, for one read of {@code file}; the caller wipes it. */
    abstract char[] get(Path file);

    /** This password for another builder or configuration: a copy of a held one. */
    abstract Password copy();

    /** Wipes a held copy; a supplier holds none. */
    abstract void wipe();

    /** For tests: the array a held password holds; null for a supplier. */
    char[] held() {
      return null;
    }

    /** {@code password} copied: the caller may erase its array. */
    static Password copyOf(char[] password) {
      return new Held(password.clone());
    }

    /** {@code supplier}, asked at each read. */
    static Password from(Supplier<char[]> supplier) {
      return new Supplied(supplier);
    }
  }

  private static final class Held extends Password {
    private final char[] password;

    Held(char[] password) {
      this.password = password;
    }

    @Override
    char[] get(Path file) {
      return password.clone();
    }

    @Override
    Password copy() {
      return new Held(password.clone());
    }

    @Override
    void wipe() {
      Arrays.fill(password, '\0');
    }

    @Override
    char[] held() {
      return password;
    }
  }

  /**
   * A supplier's password. Each array it returns is wiped after its read, so a supplier that
   * returns the same array twice would give an erased password the second time: refused, by the
   * identity of the array returned last (kept, wiped, as the only trace).
   */
  private static final class Supplied extends Password {
    private final Supplier<char[]> supplier;
    private char[] last;

    Supplied(Supplier<char[]> supplier) {
      this.supplier = supplier;
    }

    @Override
    synchronized char[] get(Path file) {
      char[] p;
      try {
        p = supplier.get();
      } catch (RuntimeException e) {
        // Its message is the supplier's, which might quote what it read: not in this message. It
        // stays the cause, so a stack trace the application chooses to log prints it.
        throw new IllegalArgumentException(
            "The password supplier for " + file + " failed (" + e.getClass().getName() + ")", e);
      }
      if (p == null)
        throw new IllegalArgumentException("The password supplier for " + file + " returned null");
      if (p == last)
        throw new IllegalArgumentException(
            "The password supplier for "
                + file
                + " returned the array it returned before, which was wiped after use: return a"
                + " new array each time");
      last = p;
      return p;
    }

    @Override
    Password copy() {
      return this;
    }

    @Override
    void wipe() {}
  }

  /** The kinds of client identity files. */
  enum IdentityKind {
    PEM,
    /** A PKCS#12 or JKS key store, told from its contents. */
    KEY_STORE
  }

  /**
   * A client identity read from files: a PKCS#12 or JKS key store, or a PEM chain and private key;
   * {@code read} is the files' state before they were read. A held password is this object's own
   * copy.
   */
  static final class Identity {
    final IdentityKind kind;
    final Path store, chain, key;
    private final Password password;
    final List<Stamp> read;

    Identity(
        IdentityKind kind, Path store, Path chain, Path key, Password password, List<Stamp> read) {
      this.kind = kind;
      this.store = store;
      this.chain = chain;
      this.key = key;
      this.password = password;
      this.read = List.copyOf(read);
    }

    List<Path> files() {
      return store != null ? List.of(store) : pemFiles(chain, key);
    }

    /** The files of a PEM identity: one when the chain and the key are one file. */
    static List<Path> pemFiles(Path chain, Path key) {
      return PemIdentity.combined(chain, key) ? List.of(chain) : List.of(chain, key);
    }

    KeyManager[] load(Reader reader) {
      return loadKeys(reader).managers();
    }

    /** {@link #load}, with the leaf certificate the key managers present. */
    KmsConfig.Keys loadKeys(Reader reader) {
      char[] p = password == null ? null : password.get(store != null ? store : key);
      try {
        return switch (kind) {
          case KEY_STORE -> KeyStoreFiles.identityKeys(store, null, p, reader);
          case PEM -> KmsConfig.pemIdentityKeys(chain, key, p, reader);
        };
      } finally {
        if (p != null) Arrays.fill(p, '\0');
      }
    }

    Identity copy() {
      return new Identity(kind, store, chain, key, password == null ? null : password.copy(), read);
    }

    void wipe() {
      if (password != null) password.wipe();
    }

    /** For tests: the password this object holds; null for none or a supplier. */
    char[] password() {
      return password == null ? null : password.held();
    }

    /**
     * The password for one use of the files (a renewal's), a new array the caller wipes; null when
     * the identity has none.
     */
    char[] passwordForUse() {
      return password == null ? null : password.get(store != null ? store : key);
    }
  }

  /**
   * CA certificates read from a file: a PEM file ({@code password} null), or a JKS or PKCS#12
   * trust store; {@code read} is its state before it was read.
   */
  static final class Trust {
    final Path file;
    private final Password password;
    final List<Stamp> read;

    Trust(Path file, Password password, List<Stamp> read) {
      this.file = file;
      this.password = password;
      this.read = List.copyOf(read);
    }

    TrustManager[] load(Reader reader) {
      if (password == null) return KmsConfig.pemTrust(file, reader);
      char[] p = password.get(file);
      try {
        return KeyStoreFiles.trust(file, p, reader);
      } finally {
        Arrays.fill(p, '\0');
      }
    }

    Trust copy() {
      return password == null ? this : new Trust(file, password.copy(), read);
    }

    void wipe() {
      if (password != null) password.wipe();
    }

    /** For tests: the password this object holds; null for none or a supplier. */
    char[] password() {
      return password == null ? null : password.held();
    }
  }

  /**
   * What a configuration with {@code reloadOnChange} watches: the files (null when that part is not
   * read from a file), the settings not read from files, the context {@code build()} made from
   * them, and how often to check.
   */
  static final class Watch {
    final Identity identity;
    final KeyManager[] fixedIdentity;
    final Trust trust;
    final TrustManager[] fixedTrust;
    final SSLContext initial;
    final Duration every;

    Watch(
        Identity identity,
        KeyManager[] fixedIdentity,
        Trust trust,
        TrustManager[] fixedTrust,
        SSLContext initial,
        Duration every) {
      this.identity = identity;
      this.fixedIdentity = fixedIdentity;
      this.trust = trust;
      this.fixedTrust = fixedTrust;
      this.initial = initial;
      this.every = every;
    }

    List<Path> files() {
      List<Path> out = new ArrayList<>();
      if (identity != null) out.addAll(identity.files());
      if (trust != null) out.add(trust.file);
      return out;
    }

    List<Stamp> read() {
      List<Stamp> out = new ArrayList<>();
      if (identity != null) out.addAll(identity.read);
      if (trust != null) out.addAll(trust.read);
      return out;
    }

    /**
     * The whole context, from the files as {@code reader} reads them now; IllegalArgumentException
     * as the builder.
     */
    SSLContext load(Reader reader) {
      return loadAll(reader).context();
    }

    /** {@link #load}, with the trust managers the context was made with. */
    Loaded loadAll(Reader reader) {
      KeyManager[] keys = identity != null ? identity.load(reader) : fixedIdentity;
      return loadWith(keys, reader);
    }

    /** The trust as {@code reader} reads it now, with the identity {@code keys}, not the files'. */
    Loaded loadWith(KeyManager[] keys, Reader reader) {
      TrustManager[] trusted = trust != null ? trust.load(reader) : fixedTrust;
      return new Loaded(KmsConfig.context(keys, trusted), trusted);
    }

    /** A new reloading source for one {@link Kms}; {@code fire} delivers listener events. */
    Reloading start(Consumer<Consumer<KmsListener>> fire) {
      return new Reloading(this, fire);
    }
  }

  /** A context the files loaded into, and the trust managers it was made with. */
  record Loaded(SSLContext context, TrustManager[] trust) {}

  /**
   * The TLS context of one {@link Kms} with {@code reloadOnChange}: consulted before each request,
   * it stats the files at most once per interval, on the calling thread, and builds the context
   * again when they changed and then stayed so for an interval (by their modification times, or
   * until the next check; at most {@link #MAX_DEFERRALS} checks put off), from one bounded read
   * of each file ({@link #bounded}), publishing it only if the files are still as stat-ed after
   * that; while that fails it keeps the previous one. Files read after {@link #MAX_DEFERRALS}
   * checks put off that are not whole yet ({@link Pem.Incomplete}), or that changed while read,
   * are still changing, not failing ({@link KmsListener#credentialsStillChanging}): they are read
   * again once they stop changing, or after as many checks again. So is a key file and a chain file
   * that do not match ({@link PemIdentity.Mismatch}), read once they settled after a change, for
   * {@link #MISMATCH_GRACE} reads in a row and at least {@link #MISMATCH_FLOOR} (a renewal written
   * one file at a time); the next read that finds them so is a failure. One thread checks at a time; the others return the current context
   * without waiting.
   */
  static final class Reloading implements Supplier<SSLContext> {
    private final Watch watch;
    private final Consumer<Consumer<KmsListener>> fire;
    private final List<Path> files;
    private final String names;
    private final long everyNanos;
    private final Duration every;

    /** Checks in a row that found the files changed again and so did not read them; guarded by {@link #checking}. */
    private int deferrals;

    private final AtomicBoolean checking = new AtomicBoolean();
    private volatile SSLContext current;

    /**
     * The trust managers {@link #current} was made with (null: the JDK's defaults): a renewal makes
     * its context with them.
     */
    private volatile List<TrustManager> trusted;

    private volatile long nextCheck;

    /**
     * An identity a client certificate renewal of this process made and has not yet written to the
     * files, which still hold the certificate the server retired: a reload keeps it, and reads
     * only the trust; null otherwise. Guarded by {@link #checking}.
     */
    private KeyManager[] pinned;

    /** The files' state when they were last read; guarded by {@link #checking}. */
    private List<Stamp> seen;

    /**
     * The files' state at the last check, when it differed from {@link #seen}: they are read when
     * the next check finds them the same; guarded by {@link #checking}.
     */
    private List<Stamp> pending;

    /** Whether the last read of the files failed; guarded by {@link #checking}. */
    private boolean failing;

    /**
     * When a check first saw the files differ from {@link #seen} (System.nanoTime()), for {@link
     * KmsListener#credentialsStillChanging}; guarded by {@link #checking}.
     */
    private long changedSince;

    /** Checks of unchanged files since the last failed read; guarded by {@link #checking}. */
    private int sinceFailure;

    /**
     * Reads in a row that found the key and the certificate not matching ({@link
     * PemIdentity.Mismatch}); guarded by {@link #checking}.
     */
    private int mismatches;

    /** When the first of {@link #mismatches} was read ({@link #nanos}); guarded by {@link #checking}. */
    private long mismatchSince;

    /** The clock of {@link #MISMATCH_FLOOR}: System.nanoTime(), or a test's. */
    java.util.function.LongSupplier nanos = System::nanoTime;

    /** For tests: how many times the files were stat-ed, read, and found changed while read. */
    final AtomicInteger checks = new AtomicInteger(),
        loads = new AtomicInteger(),
        changedWhileRead = new AtomicInteger();

    Reloading(Watch watch, Consumer<Consumer<KmsListener>> fire) {
      this.watch = watch;
      this.fire = fire;
      files = watch.files();
      StringJoiner j = new StringJoiner(", ");
      for (Path f : files) j.add(f.toString());
      names = j.toString();
      long every;
      try {
        every = watch.every.toNanos();
      } catch (ArithmeticException tooLong) {
        every = Long.MAX_VALUE;
      }
      everyNanos = every;
      this.every = watch.every;
      current = watch.initial;
      trusted = trustList(watch.fixedTrust);
      seen = watch.read();
      // The first request checks: the files may have changed since build() read them.
      nextCheck = System.nanoTime();
    }

    @Override
    public SSLContext get() {
      if (System.nanoTime() - nextCheck >= 0 && checking.compareAndSet(false, true)) {
        try {
          // Another thread may have checked between the two tests.
          if (System.nanoTime() - nextCheck >= 0)
            try {
              check();
            } finally {
              long now = System.nanoTime();
              nextCheck = everyNanos > Long.MAX_VALUE - now ? Long.MAX_VALUE : now + everyNanos;
            }
        } finally {
          checking.set(false);
        }
      }
      return current;
    }

    /** The trust managers of the context in use (null: the JDK's defaults). */
    TrustManager[] trust() {
      List<TrustManager> t = trusted;
      return t == null ? null : t.toArray(TrustManager[]::new);
    }

    private static List<TrustManager> trustList(TrustManager[] managers) {
      return managers == null ? null : List.of(managers);
    }

    /**
     * Uses {@code identity}, which a client certificate renewal of this process made, with the
     * trust in use, from now on; the files as they are now count as read, so they are not read
     * again for it. With {@code unwritten} the renewal's files are not all written: until {@link
     * #release()}, a reload keeps {@code identity} and reads only the trust, since the identity
     * files still hold the certificate the server retired. Waits for a check in progress to end.
     */
    void adopt(KeyManager[] identity, boolean unwritten) {
      while (!checking.compareAndSet(false, true))
        java.util.concurrent.locks.LockSupport.parkNanos(1_000_000);
      try {
        // The files as they are now count as read; a check that finds them unchanged reads them
        // again only after a failed read, which then loads this identity again.
        current = KmsConfig.context(identity, trust());
        pinned = unwritten ? identity : null;
        seen = stamps(files.toArray(Path[]::new));
        pending = null;
      } finally {
        checking.set(false);
      }
    }

    /**
     * The renewal {@link #adopt} kept is written to the files now: a reload reads the identity
     * from them again. Waits for a check in progress to end.
     */
    void release() {
      while (!checking.compareAndSet(false, true))
        java.util.concurrent.locks.LockSupport.parkNanos(1_000_000);
      try {
        pinned = null;
      } finally {
        checking.set(false);
      }
    }

    /** For tests: one check now, whatever the interval. */
    void checkNow() {
      if (checking.compareAndSet(false, true))
        try {
          check();
        } finally {
          checking.set(false);
        }
    }

    /** Tells the listener that the files are still changing, since {@link #changedSince}. */
    private void stillChanging() {
      Duration changingFor = Duration.ofNanos(Math.max(0, System.nanoTime() - changedSince));
      fire.accept(l -> l.credentialsStillChanging(names, changingFor));
    }

    /** Whether every file was last modified at least an interval ago, by this machine's clock. */
    private boolean quiet(List<Stamp> stamps) {
      java.time.Instant now = java.time.Instant.now();
      for (Stamp s : stamps)
        if (s.modified() == null
            || Duration.between(s.modified().toInstant(), now).compareTo(every) < 0) return false;
      return true;
    }

    private void check() {
      checks.incrementAndGet();
      List<Stamp> now = stamps(files.toArray(Path[]::new));
      boolean changed = !now.equals(seen);
      // Read although the files changed again since the last check (after MAX_DEFERRALS checks).
      boolean forced = false;
      List<Stamp> before = seen;
      boolean wasFailing = failing;
      if (changed) {
        if (pending == null && deferrals == 0) changedSince = System.nanoTime();
        // Read once the files stayed as they are for an interval (their modification times, or
        // from one check to the next): a writer that pauses between writes (at a PEM boundary, say,
        // where what is written so far is valid) is not read in the middle. Files changed again at
        // every check are read after MAX_DEFERRALS checks all the same.
        boolean settled = now.equals(pending) || quiet(now);
        forced = !settled && ++deferrals > MAX_DEFERRALS;
        pending = now;
        if (!settled && !forced) return;
        sinceFailure = 0;
      } else {
        pending = null;
        deferrals = 0;
        if (!failing || !retries(++sinceFailure)) return;
      }
      pending = null;
      deferrals = 0;
      seen = now;
      loads.incrementAndGet();
      // Failing until it loads, also when the load throws an Error: then it is reported and
      // retried like any other failure.
      failing = true;
      Loaded loaded = null;
      RuntimeException failed = null;
      try {
        // Each file is read once, at most MAX_FILE_BYTES of it, and parsed from those bytes only.
        // While a renewal's identity is not written, the identity files hold the retired one:
        // only the trust is read, with the renewed identity.
        KeyManager[] keep = pinned;
        loaded =
            keep != null
                ? watch.loadWith(keep, TlsFiles::bounded)
                : watch.loadAll(TlsFiles::bounded);
      } catch (RuntimeException e) {
        failed = e;
      } catch (Error e) {
        // Reported; the request ends, the previous context stays, and the next checks retry.
        if (changed)
          fire.accept(
              l -> l.credentialsReloadFailed(names, "unexpected " + e.getClass().getName()));
        throw e;
      }
      // The files must be the ones this check stat-ed: a file written, grown or replaced while it
      // was read is neither the old file nor the new one. Not published, and not reported: the
      // next check sees the change and reads the files again.
      List<Stamp> after = stamps(files.toArray(Path[]::new));
      if (!after.equals(now)) {
        changedWhileRead.incrementAndGet();
        // As first seen now: read at the next check if they stay so. A forced read that a write
        // overlapped is a writer still writing, and said so (one that never pauses would otherwise
        // go unreported).
        pending = after;
        if (forced) stillChanging();
        return;
      }
      mismatches = failed instanceof PemIdentity.Mismatch ? mismatches + 1 : 0;
      if (mismatches == 1) mismatchSince = nanos.getAsLong();
      boolean grace =
          mismatches <= MISMATCH_GRACE
              || nanos.getAsLong() - mismatchSince < MISMATCH_FLOOR.toNanos();
      if (failed instanceof PemIdentity.Mismatch && changed && !forced && grace) {
        // A key and a certificate that do not match, read just after they changed: a renewal
        // written one file at a time, read between its files (the certificate new, the key not
        // yet). Still changing, as below, until MISMATCH_GRACE reads in a row have found it and
        // MISMATCH_FLOOR has passed since the first; the next one is a failure. A forced read is
        // not given this grace: its files have changed for MAX_DEFERRALS checks already.
        seen = before;
        failing = wasFailing;
        pending = now;
        stillChanging();
        return;
      }
      if (failed instanceof Pem.Incomplete && forced) {
        // Files still changing that are not whole yet (cut short, empty) are a writer not done,
        // not a failure: they are read again once they stop changing, as if not read now, and a
        // failure is reported then. Files that are whole but do not load (a key that does not
        // match, a job copying a bad file over and over) are a failure, reported below.
        seen = before;
        failing = wasFailing;
        pending = now;
        stillChanging();
        return;
      }
      if (failed != null) {
        // A mismatch reported starts a new count: the next change gets the grace again.
        if (failed instanceof PemIdentity.Mismatch) mismatches = 0;
        // Builder messages name the file and never quote key material; others are unexpected.
        String why =
            failed instanceof IllegalArgumentException
                ? failed.getMessage()
                : "unexpected " + failed.getClass().getName();
        // Once for each state of the files; a retry of the same files says nothing new.
        if (changed) fire.accept(l -> l.credentialsReloadFailed(names, why));
        return;
      }
      current = loaded.context();
      trusted = trustList(loaded.trust());
      failing = false;
      sinceFailure = 0;
      fire.accept(l -> l.credentialsReloaded(names));
    }
  }
}
