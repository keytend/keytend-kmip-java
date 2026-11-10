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

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.client.KmipClient;
import dev.keytend.kmip.client.KmipException;
import dev.keytend.kmip.client.LocateRequest;
import dev.keytend.kmip.client.Request;
import dev.keytend.kmip.client.RequestOptions;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.client.Response;
import dev.keytend.kmip.client.Result;
import dev.keytend.kmip.model.Attributes;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.ProtocolVersion;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.RequestNotSentException;
import dev.keytend.kmip.transport.Tls;
import dev.keytend.kmip.transport.TlsTransport;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.channels.FileChannel;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Consumer;
import java.util.function.Supplier;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * Renewal of the configuration's own client certificate with KMIP Re-Provision ({@link
 * KmsConfig.Builder#clientCertificateRenewal}, {@link Kms#renewClientCertificate()}): one per
 * configuration, sharing its state with every other configuration of this process that renews the
 * same files, and used by every {@link Kms} connected with them.
 *
 * <p>An attempt, one at a time for the same files: in this process (a lock by the real path of
 * the pending file) and across processes (an exclusive lock on {@link RenewalFiles#lockFile()}):
 *
 * <ol>
 *   <li>A renewal this process made whose files were not all written is written now; a pending file
 *       holding an issued certificate for the files' current certificate is switched to ({@link
 *       RenewalFiles}). A pending file written for other identity files is moved aside, never
 *       deleted: it may hold the only copy of a key the server issued a certificate for.
 *   <li>Two connections are opened on the current certificate, F: one to send on, one held open
 *       (the standby) to read with afterwards, since the server refuses F on new connections once
 *       it issued the replacement. The standby's Discover Versions also shows whether the server
 *       still accepts F, and reads the server's clock.
 *   <li>A key pair like F's (RSA of the same modulus size, or EC on the same curve) is made and
 *       written to the pending file, which must not exist yet, with the server's time, before
 *       anything is sent. A pending key from an earlier attempt that stopped is used again, after a
 *       search for a certificate the server issued for it.
 *   <li>{@code [Re-Provision(PKCS#10), Get(ID Placeholder)]} goes in one message, with a requested
 *       validity as a Critical Message Extension on the Re-Provision item ({@link
 *       ReProvisionValidity}).
 *   <li>The certificate is checked ({@link #verify}). The server has retired F by then, so it is
 *       refused only when it cannot serve as this client's TLS certificate now: not for the new
 *       key, not F's subject and subjectAltName, expired, a CA, or a key usage or extended key
 *       usage that excludes client authentication. Such a certificate is a possible lockout. What
 *       the server judges by its own clock or policy (the period, a notBefore ahead of this
 *       machine's clock, an issuer signature this client cannot verify) is reported with {@link
 *       KmsListener#clientCertificateRenewalWarning} instead ({@link #warnings}).
 *   <li>The new identity is used in memory at once (every {@code Kms} of the files, through {@link
 *       Source}, and every configuration of the files built later in this process), then written:
 *       the pending file with the certificate, then the identity files, then the pending file is
 *       deleted. A write that fails is a {@link RenewalNotSavedException}, which carries the
 *       certificate. Automatic renewal writes an unwritten one again, with its failure backoff,
 *       before it looks at expiry.
 * </ol>
 *
 * <p>The search for a certificate the server issued for the new key (Locate of certificates
 * created around the attempt, by the server's clock, every page, then Get) runs through the
 * standby, then through the idle connections of the {@code Kms} on F, then through a new
 * connection. It runs after a lost reply, before a resumed attempt sends its key again, after the
 * server refuses a resumed attempt (an earlier message may have committed since), and when the
 * server refuses F on new connections while a pending key, or a key moved aside, exists. Found,
 * the attempt finishes. A search that could not finish keeps the key; when the server may have
 * retired F, the client may be locked out ({@link KmsListener#clientCertificateMayBeLockedOut},
 * {@link OutcomeUnknownException}).
 *
 * <p>A pending key is deleted only when the server provably never accepted, or definitively
 * refused, the one message that carried it: the message was not sent ({@link
 * RequestNotSentException}), or the server refused it with no lost reply before. A search that
 * finds nothing proves absence only at that moment, since an earlier message whose reply was lost
 * may still commit: so when a resumed attempt is refused, or the server refuses F on new
 * connections, and a full search finds nothing, the pending key is moved aside ({@link
 * RenewalFiles#setAside}) rather than deleted, and the failure names the file.
 *
 * <p>{@link Kms#close()} stops an attempt that has not sent its request: it checks just before
 * the send, and before each search or write for a certificate the server issued ({@link
 * Worker#commit}). It waits for one that has, up to {@link #closeWait}, and afterwards the
 * attempt's events go to the SDK's log only ({@link #close}).
 */
final class ClientRenewal {
  /** The operation name of failures and events. */
  static final String OP = "renewClientCertificate";

  /** Where the SDK's guide to renewal is. */
  static final String GUIDE =
      "https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/production.md#renew-the-client-certificate";

  /** How far around the attempt the search after a lost reply looks (Initial Date). */
  static final Duration SEARCH_WINDOW = Duration.ofHours(1);

  /**
   * The certificates a search reads at most, a page of {@link #SEARCH_PAGE} at a time: far more
   * than a client's certificates created within {@link #SEARCH_WINDOW} of an attempt. A search
   * that would read more stops, and is not taken as proof that nothing was issued.
   */
  static final int SEARCH_PAGE = 100, SEARCH_LIMIT = 10_000;

  /** {@link #SEARCH_PAGE} and {@link #SEARCH_LIMIT}; tests make them small. */
  static volatile int searchPage = SEARCH_PAGE, searchLimit = SEARCH_LIMIT;

  /** The clientAuth extended key usage. */
  static final String CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";

  /** The anyExtendedKeyUsage extended key usage. */
  static final String ANY_EXTENDED_KEY_USAGE = "2.5.29.37.0";

  /**
   * The longest wait between two checks of an automatic renewal, and the backoff after a failure.
   */
  static volatile Duration maxCheck = Duration.ofHours(1),
      firstBackoff = Duration.ofMinutes(1),
      maxBackoff = Duration.ofHours(1);

  /**
   * Times the automatic checks: its one thread only hands each check to {@link #WORKERS}, so a
   * check that waits on the network never delays another configuration's. While an automatic
   * renewal runs, its keep-alive is the longest wait between checks ({@link #timerKeepAlive()}), so
   * the thread waiting for the next check wakes at most that often; once the last one stops, it is
   * a second again, and the idle thread ends.
   */
  private static final ScheduledThreadPoolExecutor SCHEDULER =
      SdkThreads.scheduler("keytend-kmip-certificate-renewal-timer");

  /** Guards {@link #automaticRunning} and the timer's keep-alive. */
  private static final Object RUNNING = new Object();

  /** The automatic renewals running; guarded by {@link #RUNNING}. */
  private static int automaticRunning;

  /**
   * Runs the automatic checks and attempts: a thread for each one running, each ending when idle.
   * One {@link Auto} runs one check at a time, and attempts on the same files take turns ({@link
   * Shared#attempt}).
   */
  private static final java.util.concurrent.ExecutorService WORKERS =
      SdkThreads.cached("keytend-kmip-certificate-renewal");

  /**
   * The renewal state of each set of identity files in this process, by the real path of their
   * pending file: every configuration that renews the same files shares one.
   */
  private static final ConcurrentHashMap<Path, Shared> SHARED = new ConcurrentHashMap<>();

  /**
   * For tests: run just before the Re-Provision message is sent, after the pending file is written
   * and any search of a resumed attempt is done.
   */
  static volatile Runnable beforeReProvision;

  final CertificateRenewal options;
  final RenewalFiles files;

  /** The configuration's trust of the server (null: the JDK's defaults), without reloadOnChange. */
  private final TrustManager[] trust;

  /** The state of these identity files in this process, shared with other configurations. */
  private final Shared shared;

  /**
   * The last renewal of these files made in this process whose identity this configuration
   * already has. Renewals after it are used instead of the identity the configuration was built
   * with. When the configuration was built with a certificate a renewal in this process retired
   * (a builder that read the files before that renewal, or reused after it, or files that were
   * not all written), the last renewal is not among them: the configuration uses it.
   */
  private final long baseline;

  /**
   * Guards {@link #workers} and {@link #open}, and each {@link Worker}'s commitment against its
   * {@link Kms}'s close: a worker commits only while its {@code Kms} is open, and {@link #close}
   * marks the {@code Kms} closed under this lock.
   */
  private final Object closing = new Object();

  /**
   * The renewals running for the {@link Kms}es of this configuration; guarded by {@link #closing}.
   */
  private final Set<Worker> workers = new HashSet<>();

  /** The {@link Kms}es of this configuration that are open; guarded by {@link #closing}. */
  private int open;

  /**
   * @param loaded the leaf certificate of the identity the builder loaded, which the
   *     configuration's TLS context holds; the builder keeps it beside the key managers, whose
   *     alias names depend on the key manager algorithm. Null when not known.
   */
  ClientRenewal(
      CertificateRenewal options,
      TlsFiles.Identity identity,
      TrustManager[] trust,
      X509Certificate loaded) {
    this.options = options;
    this.files = new RenewalFiles(identity);
    this.trust = trust;
    this.shared = SHARED.computeIfAbsent(files.realPendingFile(), p -> new Shared());
    String held = loaded == null ? null : fingerprint(loaded);
    synchronized (shared) {
      Renewed r = shared.renewed;
      if (r == null) baseline = 0;
      else if (held != null ? shared.retired.contains(held) : !r.written())
        baseline = r.generation() - 1;
      else baseline = r.generation();
    }
  }

  /** The renewal state of one set of identity files in this process. */
  private static final class Shared {
    /** One attempt at a time, for every Kms of every configuration of these files. */
    final ReentrantLock attempt = new ReentrantLock();

    /** The generation of the last renewal; guarded by this object. */
    long generations;

    /**
     * The fingerprints of the certificates renewals in this process retired; guarded by this
     * object.
     */
    final Set<String> retired = new HashSet<>();

    /**
     * The identity of the last renewal of these files made in this process; null before one.
     * Written under this object's lock, with {@link #generations} and {@link #retired}.
     */
    volatile Renewed renewed;
  }

  /**
   * A renewal made in this process: the identity every Kms of the files uses from now, and the
   * file that holds its key until the identity files do ({@code keyFile}).
   */
  private record Renewed(
      long generation,
      KeyManager[] identity,
      PrivateKey key,
      List<X509Certificate> chain,
      String certificateId,
      String previous,
      Path keyFile,
      boolean written) {}

  /**
   * The TLS contexts of one {@link Kms}: the configuration's (or its reloading files'), until a
   * renewal of its files in this process; then the renewed identity. While the renewal's files are
   * not all written, the files still hold the certificate the server retired: the renewed identity
   * then stays the one used whatever a reload of the files reads, and only the trust is reloaded
   * ({@link TlsFiles.Reloading#adopt}). Once they are written, a reload reads the files again.
   */
  final class Source implements Supplier<SSLContext> {
    private final TlsFiles.Reloading reloading;
    private final SSLContext initial;
    private long seen;
    private boolean seenWritten;
    private SSLContext renewedContext;

    Source(TlsFiles.Reloading reloading, SSLContext initial) {
      this.reloading = reloading;
      this.initial = initial;
    }

    @Override
    public SSLContext get() {
      Renewed r = current();
      if (r == null) return reloading == null ? initial : reloading.get();
      synchronized (this) {
        if (r.generation() != seen) {
          if (reloading != null) reloading.adopt(r.identity(), !r.written());
          else renewedContext = KmsConfig.context(r.identity(), trust);
          seen = r.generation();
          seenWritten = r.written();
        } else if (r.written() && !seenWritten) {
          // Written now: the files hold the renewed identity, and a reload may read them again.
          if (reloading != null) reloading.release();
          seenWritten = true;
        }
        return reloading != null ? reloading.get() : renewedContext;
      }
    }

    /** The trust managers new contexts are made with. */
    TrustManager[] trust() {
      return reloading != null ? reloading.trust() : trust;
    }
  }

  Source source(TlsFiles.Reloading reloading, SSLContext initial) {
    return new Source(reloading, initial);
  }

  /**
   * The renewal of these files made in this process since this configuration was built; or null.
   */
  private Renewed current() {
    Renewed r = shared.renewed;
    return r != null && r.generation() > baseline ? r : null;
  }

  /**
   * {@code denied}, a refusal of a call of a running {@link Kms} on a connection it opened for the
   * call. That may be the server's policy for the operation, not a refusal of the certificate: so
   * only when a renewal left a key ({@link #connectRefused}) and one Discover Versions on another
   * new connection with the same identity is refused too does the message say what that means.
   */
  KmsException callRefused(Kms kms, Source source, PermissionDeniedException denied) {
    if (!java.nio.file.Files.exists(files.pendingFile()) && files.unresolved().isEmpty())
      return denied;
    if (source == null || !refusedOnNewConnection(kms, source)) return denied;
    return connectRefused(denied);
  }

  /**
   * {@code denied}, the server's refusal of the client certificate on a new connection's first
   * exchange (a connect's Discover Versions, or one {@link #callRefused} sent), with what a renewal
   * that did not finish means for it: the server may have retired the certificate. {@code denied}
   * itself when no renewal left a key.
   */
  KmsException connectRefused(PermissionDeniedException denied) {
    if (java.nio.file.Files.exists(files.pendingFile()))
      return noted(
          denied,
          "A renewal of the client certificate began and did not finish (its new key is in "
              + files.pendingFile()
              + "), so the server may have retired this certificate and the client may be locked"
              + " out. See "
              + GUIDE);
    List<Path> aside = files.unresolved();
    if (aside.isEmpty()) return denied;
    return noted(
        denied,
        "An earlier renewal of the client certificate left keys that the server may still"
            + " have issued a certificate for ("
            + aside
            + "): if it did, it retired this certificate, and the client may be locked out."
            + " renewClientCertificate() on a Kms that still has a connection open on this"
            + " certificate looks for it, as automatic renewal does. See "
            + GUIDE);
  }

  /**
   * The identity a renewal made, and its leaf certificate, for {@link KmsConfig#toBuilder()}; null
   * before one.
   */
  KmsConfig.Keys renewedIdentity() {
    Renewed r = current();
    return r == null ? null : new KmsConfig.Keys(r.identity(), r.chain().get(0));
  }

  /**
   * Renews now, on demand ({@link Kms#renewClientCertificate}): one {@link Worker} of {@code kms}.
   *
   * @throws IllegalStateException when {@code kms} is closed, or closes before the request is sent
   */
  RenewedCertificate renew(Kms kms, Source source) throws IOException {
    Worker w = enter(kms);
    if (w == null) throw closed();
    try {
      return renew(kms, source, false, w);
    } finally {
      leave(w);
    }
  }

  /**
   * Renews now, as {@code w}. An automatic attempt does not wait for another one: it returns null
   * when one is running, in this process or in another.
   */
  private RenewedCertificate renew(Kms kms, Source source, boolean automatic, Worker w)
      throws IOException {
    boolean locked;
    try {
      locked =
          automatic
              ? shared.attempt.tryLock()
              : shared.attempt.tryLock(kms.callTimeout().toNanos(), TimeUnit.NANOSECONDS);
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new TransientException(
          OP + ": interrupted while waiting for another renewal to finish",
          e,
          OP,
          null,
          null,
          null);
    }
    if (!locked) {
      if (automatic) return null;
      throw new TransientException(
          OP + ": another renewal of this certificate is still running",
          null,
          OP,
          null,
          null,
          null);
    }
    // Processes renewing the same files (an application and the CLI, say) take turns.
    try (FileChannel held = files.tryLock()) {
      if (held == null) {
        if (automatic) return null;
        throw new TransientException(
            OP
                + ": another process is renewing this certificate (it holds "
                + files.lockFile()
                + "); call renewClientCertificate() again once it is done",
            null,
            OP,
            null,
            null,
            null);
      }
      Attempt a = new Attempt(kms, source, w);
      w.attempt = a;
      try {
        RenewedCertificate done = a.run();
        w.fire(
            l ->
                l.clientCertificateRenewed(
                    done.previousFingerprint(), done.fingerprint(), done.notAfter()));
        return done;
      } catch (IOException | RuntimeException e) {
        String why = e.getMessage() == null ? e.getClass().getName() : e.getMessage();
        if (a.lockedOut) w.fire(l -> l.clientCertificateMayBeLockedOut(a.previous, why));
        else w.fire(l -> l.clientCertificateRenewalFailed(a.previous, why));
        throw e;
      }
    } finally {
      shared.attempt.unlock();
    }
  }

  /** One attempt. */
  final class Attempt {
    final Kms kms;
    final Source source;
    final Worker worker;
    final ProtocolVersion version;
    final Duration timeout;

    /** The fingerprint of the certificate being replaced, once read. */
    volatile String previous;

    /** Whether the failure thrown is one after which the client may be locked out. */
    volatile boolean lockedOut;

    RenewalFiles.Current current;

    /** The password of the identity files (null for none), wiped at the end. */
    char[] password;

    /**
     * The endpoint, and the TLS context on the current certificate, of this attempt's connections.
     */
    KmsConfig.Endpoint endpoint;

    SSLContext f;

    Attempt(Kms kms, Source source, Worker worker) {
      this.kms = kms;
      this.source = source;
      this.worker = worker;
      this.version = kms.protocolVersion();
      this.timeout = kms.callTimeout();
    }

    RenewedCertificate run() throws IOException {
      password = files.identity.passwordForUse();
      try {
        // For the events: the certificate this attempt would replace, when it can be read.
        try {
          previous = fingerprint(files.currentLeaf(password));
        } catch (RuntimeException unreadable) {
          previous = null;
        }
        if (!version.atLeast(ProtocolVersion.V2_0))
          throw new UnsupportedException(
              OP
                  + ": Re-Provision needs KMIP 2.0 or later; this connection uses KMIP "
                  + KmipVersion.of(version),
              null,
              OP,
              null,
              null,
              null);
        return renew();
      } catch (GeneralSecurityException e) {
        throw new IOException(OP + ": " + e.getMessage(), e);
      } finally {
        if (password != null) Arrays.fill(password, '\0');
      }
    }

    /** The password the pending file is encrypted under: the key's, or none. */
    char[] pendingPassword() {
      return current.encrypted() ? password : null;
    }

    private RenewedCertificate renew() throws IOException, GeneralSecurityException {
      // Nothing is done for a Kms that is closed.
      worker.open();
      // 1. A renewal of this process whose files were not all written.
      Renewed r = shared.renewed;
      if (r != null && !r.written()) {
        previous = r.previous();
        worker.commit("writing a renewal this process made to the files");
        // The pending file may hold only the key: the certificate goes in it before the switch,
        // so that a stop during the switch can be finished from it.
        save(
            r.key(),
            r.chain(),
            r.certificateId(),
            r.chain().get(0).getPublicKey(),
            files.keyEncrypted() ? password : null,
            r.keyFile());
        written(r);
        dropUnresolved();
        return new RenewedCertificate(
            r.chain(), r.certificateId(), r.previous(), fingerprint(r.chain().get(0)), true);
      }
      try {
        current = files.read(password);
      } catch (IllegalArgumentException unreadable) {
        // A two-file PEM switch that stopped between its files: finish it.
        worker.commit("finishing the switch of the files from the pending file");
        RenewalFiles.Pending done;
        try {
          done = files.finishIssued(password);
        } catch (IllegalArgumentException e) {
          done = null;
        }
        if (done == null)
          throw new IOException(
              OP + ": cannot read the client identity files: " + unreadable.getMessage(),
              unreadable);
        previous = done.replaces();
        adopt(
            done.key(),
            done.chain(),
            done.certificateId(),
            done.replaces(),
            files.pendingFile(),
            true);
        dropUnresolved();
        return new RenewedCertificate(
            done.chain(),
            done.certificateId(),
            done.replaces(),
            fingerprint(done.chain().get(0)),
            true);
      }
      previous = fingerprint(current.leaf());

      // 2. A pending file.
      RenewalFiles.Pending pending;
      try {
        pending = files.readPending(password);
      } catch (IllegalArgumentException e) {
        throw new IOException(OP + ": " + e.getMessage(), e);
      }
      if (pending != null && pending.issued()) {
        String issued = fingerprint(pending.chain().get(0));
        if (previous.equals(pending.replaces()) || previous.equals(issued)) {
          worker.commit("switching the files to the certificate in the pending file");
          files.switchTo(pending.key(), pending.chain(), password);
          files.deletePending();
          adopt(
              pending.key(),
              pending.chain(),
              pending.certificateId(),
              pending.replaces(),
              files.pendingFile(),
              true);
          if (previous.equals(issued)) previous = pending.replaces();
          dropUnresolved();
          return new RenewedCertificate(
              pending.chain(), pending.certificateId(), pending.replaces(), issued, true);
        }
        // Written for other files than these: someone changed the identity since.
        orphan(
            "it holds certificate "
                + issued
                + ", issued to replace "
                + pending.replaces()
                + ", not the current certificate");
        pending = null;
      } else if (pending != null && !pending.replaces().equals(previous)) {
        orphan(
            "it holds the key of a renewal of certificate "
                + pending.replaces()
                + ", not of the current certificate");
        pending = null;
      } else if (pending != null && !sameKind(pending.publicKey(), current.leaf().getPublicKey())) {
        orphan("its key is not of the current certificate's algorithm and size or curve");
        pending = null;
      }

      // 3. Connections on the current certificate.
      f = KmsConfig.context(KmsConfig.keyManagers(current.key(), current.chain()), source.trust());
      endpoint = kms.renewalEndpoint();
      try (Connection standby = open(endpoint, f);
          Connection sender = open(endpoint, f)) {
        Clocks clocks;
        try {
          clocks = clocks(standby.client, RequestOptions.DEFAULT, timeout, this::now);
        } catch (KmipException e) {
          if (!denied(e)) throw read(e);
          // The search may find a certificate the server issued, which is then written.
          if (pending != null) {
            worker.commit("looking for a certificate issued for the pending key");
            return refusedOnNewConnections(pending, e);
          }
          if (!keysAside().isEmpty())
            worker.commit("looking for a certificate issued for a key moved aside");
          return refusedWithKeysAside(e);
        } catch (IOException e) {
          throw read(e);
        }
        KeyPair pair;
        boolean resumed = pending != null;
        Since since;
        if (resumed) {
          // An earlier attempt sent this key: look for what the server issued for it first.
          worker.commit("looking for a certificate issued for the pending key");
          since = since(pending);
          Searched s = lookFor(standby, pending.publicKey(), since, true);
          if (s.found() != null)
            return finish(
                s.found(), pending.publicKey(), pending.key(), true, files.pendingFile(), since);
          if (s.kind() != Searched.Kind.EXHAUSTED) throw notTold(s, false, null);
          pair = new KeyPair(pending.publicKey(), pending.key());
        } else {
          worker.open();
          pair = like(current.leaf().getPublicKey());
          Instant written = now();
          since = new Since(written, clocks.onServer(written));
          files.writeNewPending(
              pair.getPrivate(),
              previous,
              pair.getPublic(),
              pendingPassword(),
              since.server(),
              this::claimed);
        }
        Duration validFor = options.validFor().orElse(null);
        // By the server's clock, which dates the certificate, as the search does.
        Instant notAfter =
            validFor == null
                ? null
                : ReProvisionValidity.notAfter(validFor, clocks.onServer(now()));
        Request.Builder reProvisionItem =
            Requests.reProvision()
                .add(
                    structure(
                        CERTIFICATE_REQUEST,
                        enumeration(CERTIFICATE_REQUEST_TYPE, Enums.CertificateRequestType.PKCS_10),
                        bytes(
                            CERTIFICATE_REQUEST_VALUE,
                            Pkcs10.request(current.leaf().getSubjectX500Principal(), pair))));
        // The requested validity: a Critical Message Extension on this batch item.
        if (notAfter != null) reProvisionItem.extension(ReProvisionValidity.extension(notAfter));
        Request reProvision = reProvisionItem.build();
        Request get =
            version.atLeast(ProtocolVersion.V3_0)
                ? Requests.get()
                    .add(enumeration(UNIQUE_IDENTIFIER, Enums.UniqueIdentifier.ID_PLACEHOLDER))
                    .build()
                : Requests.get().build();
        Runnable hook = beforeReProvision;
        if (hook != null) hook.run();
        // Just before the send: a Kms closed by now sends nothing. Its own new key, which no
        // message carried, is deleted; a resumed attempt's key, which one did, is kept.
        try {
          worker.commit("sending Re-Provision and waiting for the reply");
        } catch (IllegalStateException closed) {
          if (!resumed)
            try {
              files.deletePending();
            } catch (IOException io) {
              closed.addSuppressed(io);
            }
          throw closed;
        }
        Response response;
        try {
          response =
              sender.client.batch(List.of(reProvision, get), RequestOptions.DEFAULT, context());
        } catch (RequestNotSentException e) {
          // The only message that carried a new key was never sent: nothing can issue for it.
          if (!resumed) files.deletePending();
          throw Failures.classify(new Failures.Call(OP, false, null, false), version, e);
        } catch (IOException e) {
          return afterLostReply(standby, pair, since, e);
        }
        Result first = response.results().get(0);
        Result item = response.messageLevelFailure() ? first : response.resultFor(0).orElse(null);
        if (item == null || !item.successful()) {
          Result failed = item == null ? first : item;
          KmsException refused =
              Failures.fromResult(new Failures.Call(OP, false, null, false), OP, failed, null);
          KmsException told =
              validFor == null
                  ? refused
                  : ReProvisionValidity.refused(
                      refused, failed, response.messageLevelFailure(), validFor, notAfter);
          if (resumed) {
            // An earlier attempt sent this key and its outcome is not known: it may have
            // committed since the search above (the server then refuses this message, for a
            // retired certificate or a key it has seen). Look again.
            Searched s = lookFor(standby, pair.getPublic(), since, true);
            if (s.found() != null)
              return finish(
                  s.found(), pair.getPublic(), pair.getPrivate(), true, files.pendingFile(), since);
            if (s.kind() != Searched.Kind.EXHAUSTED)
              throw notTold(s, failed.hasReason(Enums.ResultReason.PERMISSION_DENIED), refused);
            // Nothing issued yet; but the earlier message may still commit, so the key is moved
            // aside, not deleted: it is the only key for a certificate the server may yet issue.
            Path aside;
            try {
              aside = files.setAside(now());
            } catch (IOException io) {
              KmsException kept =
                  noted(
                      told,
                      "The earlier attempt's request, whose reply was lost, may still be issued a"
                          + " certificate for the pending key, which stays in "
                          + files.pendingFile()
                          + ": moving it aside failed ("
                          + message(io)
                          + "). Keep it; the next call looks for that certificate again");
              kept.addSuppressed(io);
              throw kept;
            }
            throw noted(
                told,
                "The earlier attempt's request, whose reply was lost, may still be issued a"
                    + " certificate for the pending key, so the key was moved to "
                    + aside
                    + " rather than deleted"
                    + asideAdvice(aside));
          }
          // The first and only message that carried this key was refused: nothing was issued
          // for it, and nothing can be.
          try {
            files.deletePending();
          } catch (IOException io) {
            told.addSuppressed(io);
          }
          // Permission Denied may mean that a late commit of an earlier attempt's message retired
          // the current certificate: look for a certificate for the keys it moved aside, through
          // the standby, which is still open on the current certificate.
          if (failed.hasReason(Enums.ResultReason.PERMISSION_DENIED)) {
            KeysAside keys = keysAside();
            if (!keys.isEmpty()) return searchAside(keys, standby, told, false, true);
          }
          throw told;
        }
        Result fetched = response.resultFor(1).orElse(null);
        X509Certificate issued =
            fetched != null && fetched.successful() ? certificate(fetched) : null;
        String id;
        try {
          id = item.uniqueIdentifier();
        } catch (RuntimeException e) {
          id = null;
        }
        if (issued == null || id == null)
          // Issued, perhaps, but not delivered: look for it as after a lost reply.
          return afterLostReply(
              standby, pair, since, new IOException("the response carried no certificate"));
        return finish(
            new Found(id, issued),
            pair.getPublic(),
            pair.getPrivate(),
            false,
            files.pendingFile(),
            since);
      }
    }

    /** The pending file existed when this attempt meant to create it: another holder wrote it. */
    private TransientException claimed(Path file) {
      return new TransientException(
          OP
              + ": "
              + file
              + " appeared while this attempt was starting: another renewal of these files is"
              + " running. Nothing was sent; call renewClientCertificate() again once it is done",
          null,
          OP,
          null,
          null,
          null);
    }

    /**
     * Moves away a pending file written for other identity files than these ({@code why}): it may
     * hold the only copy of the private key of a certificate the server holds as active.
     */
    private void orphan(String why) throws IOException {
      Path moved = files.orphanPending(now());
      String told =
          "the pending file was not written for the current identity files ("
              + why
              + " ("
              + previous
              + ")), so it was moved to "
              + moved
              + ". It may hold the only copy of the private key of a certificate the server"
              + " issued: keep it until you know that no client needs it. This attempt starts"
              + " afresh. See "
              + GUIDE;
      worker.fire(l -> l.clientCertificateRenewalWarning(previous, told));
    }

    /**
     * When {@code aside} may be deleted, and how it helps after a lockout: for the messages of an
     * attempt whose key was moved aside.
     */
    private String asideAdvice(Path aside) {
      return ". Keep it until a later renewal of this certificate ("
          + previous
          + ") succeeds: the server then retires this certificate and refuses any message still"
          + " sent on it, so it can no longer issue a certificate for the key. Until then, if the"
          + " server refuses this certificate on new connections, renewClientCertificate() on a"
          + " Kms with a connection still open on it looks for a certificate for the key and"
          + " finishes the renewal; otherwise "
          + aside
          + " holds the private key for the server's lockout recovery. See "
          + GUIDE;
    }

    /**
     * The server refused the current certificate on a new connection, and an earlier attempt left
     * {@code pending}: it may have renewed the certificate. Looks for the new certificate through
     * the connections this process still has on the current one.
     */
    private RenewedCertificate refusedOnNewConnections(
        RenewalFiles.Pending pending, KmipException denial)
        throws IOException, GeneralSecurityException {
      Searched s = lookFor(null, pending.publicKey(), since(pending), false);
      if (s.found() != null)
        return finish(
            s.found(),
            pending.publicKey(),
            pending.key(),
            true,
            files.pendingFile(),
            since(pending));
      if (s.kind() != Searched.Kind.EXHAUSTED)
        throw lockout(
            "the server refuses the current certificate on new connections, so an earlier"
                + " attempt, whose reply was lost, may have renewed it, and the SDK could not look"
                + " for the new certificate ("
                + s.why()
                + ")",
            denial);
      // A full search found no certificate for the key now. A message still in flight may yet
      // commit, so the key is moved aside rather than deleted.
      Path aside;
      try {
        aside = files.setAside(now());
      } catch (IOException io) {
        PermissionDeniedException kept =
            new PermissionDeniedException(
                OP
                    + ": the server refuses the current certificate ("
                    + previous
                    + ") on new connections, and a search through a connection this process still"
                    + " has on it found no certificate for the key of the earlier attempt, which"
                    + " stays in "
                    + files.pendingFile()
                    + ": moving it aside failed ("
                    + message(io)
                    + "). Keep it: the server may still issue a certificate for it. See "
                    + GUIDE,
                denial,
                OP,
                null,
                null,
                null);
        kept.addSuppressed(io);
        throw kept;
      }
      throw new PermissionDeniedException(
          OP
              + ": the server refuses the current certificate ("
              + previous
              + ") on new connections: a renewal by another client with this certificate retired"
              + " it, or the server's policy does not list it. A search through a connection"
              + " this process still has on it found no certificate for the key of the earlier"
              + " attempt, which was moved to "
              + aside
              + asideAdvice(aside),
          denial,
          OP,
          null,
          null,
          null);
    }

    /**
     * The server refused the current certificate on a new connection, and no key is pending. A key
     * an earlier attempt moved aside ({@link RenewalFiles#setAside}) may have been issued the
     * certificate since, by a message that committed late: each one for this certificate is looked
     * for through the connections this process still has on it, and a certificate found finishes
     * the renewal.
     */
    private RenewedCertificate refusedWithKeysAside(KmipException denial)
        throws IOException, GeneralSecurityException {
      KeysAside keys = keysAside();
      PermissionDeniedException refused =
          new PermissionDeniedException(
              OP
                  + ": the server refuses the current certificate ("
                  + previous
                  + ") on new connections: a renewal retired it, or the server's policy does not"
                  + " list it",
              denial,
              OP,
              null,
              null,
              null);
      if (keys.isEmpty()) throw refused;
      return searchAside(keys, null, refused, true, false);
    }

    /** The keys earlier attempts moved aside for the current certificate, and their files. */
    private KeysAside keysAside() {
      KeysAside out = new KeysAside(new ArrayList<>(), new ArrayList<>());
      for (Path p : files.unresolved()) {
        RenewalFiles.Pending k;
        try {
          k = RenewalFiles.readPending(p, pendingPassword());
        } catch (IOException | IllegalArgumentException unreadable) {
          continue; // another password, or not a pending file: left as it is
        }
        if (!k.issued() && k.replaces().equals(previous)) {
          out.files().add(p);
          out.keys().add(k);
        }
      }
      return out;
    }

    /**
     * Looks for a certificate for each of {@code aside}'s keys, through {@code standby} (when
     * there is one), then the connections of this {@link Kms} open on the current certificate, and
     * (with {@code fresh}) a new connection, and finishes the renewal with the one found. Otherwise
     * throws {@code refused}, noting the search; or, when a search could not finish and the server
     * may have retired the current certificate ({@code retired}, or a search met it refused on a
     * new connection), a possible lockout.
     */
    private RenewedCertificate searchAside(
        KeysAside aside, Connection standby, KmsException refused, boolean retired, boolean fresh)
        throws IOException, GeneralSecurityException {
      List<String> unsure = new ArrayList<>();
      boolean refusedOnNew = retired;
      for (int i = 0; i < aside.keys().size(); i++) {
        RenewalFiles.Pending k = aside.keys().get(i);
        Searched s = lookFor(standby, k.publicKey(), since(k), fresh);
        if (s.found() != null)
          return finish(s.found(), k.publicKey(), k.key(), true, aside.files().get(i), since(k));
        if (s.kind() != Searched.Kind.EXHAUSTED) {
          unsure.add(aside.files().get(i) + " (" + s.why() + ")");
          refusedOnNew |= s.refusedOnNew();
        }
      }
      if (!unsure.isEmpty() && refusedOnNew)
        throw lockout(
            new OutcomeUnknownException(
                OP
                    + ": the client may be locked out of the KMS: "
                    + withoutOperation(refused.getMessage())
                    + ". An earlier attempt left keys that the server may have issued a"
                    + " certificate for since, retiring the current certificate ("
                    + previous
                    + "), which the SDK could not look for: "
                    + String.join("; ", unsure)
                    + ". Calling renewClientCertificate() on a Kms that still has a connection"
                    + " open on the current certificate looks again. Otherwise follow the server's"
                    + " lockout recovery (keytend-kmip-server: docs/re-provision.md, \"Lockout"
                    + " recovery\") with the key in that file, and "
                    + GUIDE,
                refused,
                OP,
                null,
                null,
                null));
      if (!unsure.isEmpty())
        throw noted(
            refused,
            "The SDK could not look for a certificate for the keys earlier attempts moved aside: "
                + String.join("; ", unsure));
      throw noted(
          refused,
          "A search through a connection this process still has on the current certificate found"
              + " no certificate for the keys earlier attempts moved aside ("
              + aside.files()
              + ")");
    }

    /**
     * After a lost reply (or a reply without the certificate): the certificate issued for {@code
     * pair}, looked for since {@code since}; a transient failure when the server issued none; a
     * lockout when it cannot be told.
     */
    private RenewedCertificate afterLostReply(
        Connection standby, KeyPair pair, Since since, IOException lost)
        throws IOException, GeneralSecurityException {
      Searched s = lookFor(standby, pair.getPublic(), since, true);
      if (s.found() != null)
        return finish(
            s.found(), pair.getPublic(), pair.getPrivate(), false, files.pendingFile(), since);
      if (s.kind() != Searched.Kind.EXHAUSTED) throw notTold(s, true, lost);
      throw new TransientException(
          OP
              + ": the reply to Re-Provision was lost ("
              + lost.getMessage()
              + "). When the SDK looked, through a connection on the current certificate, the"
              + " server had issued no certificate for the new key. The key stays in "
              + files.pendingFile()
              + ". Call renewClientCertificate() again: it looks for the certificate again,"
              + " finishes the renewal if a slow server issued it meanwhile, and otherwise sends"
              + " the request again with the same key",
          lost,
          OP,
          null,
          null,
          null);
    }

    /**
     * The failure for a search that neither found the certificate nor showed that none was issued.
     * When the server may have retired the current certificate ({@code mayBeRetired} and no new
     * connection on it was accepted since, or the search met it refused on a new connection), the
     * client may be locked out; otherwise the pending key is kept and nothing changed.
     */
    private KmsException notTold(Searched s, boolean mayBeRetired, Throwable cause) {
      if ((mayBeRetired && !s.accepted()) || s.refusedOnNew())
        return lockout(
            "the SDK could not tell whether the server issued it (" + s.why() + ")", cause);
      if (s.kind() == Searched.Kind.POLICY_DENIED)
        return new PermissionDeniedException(
            OP
                + ": the search for a certificate the server may have issued for the key in "
                + files.pendingFile()
                + " was refused ("
                + s.why()
                + "). The server's policy must allow Locate (8) and Get (10) for this client. The"
                + " key is kept, and nothing changed",
            cause,
            OP,
            null,
            null,
            null);
      return new TransientException(
          OP
              + ": the search for a certificate the server may have issued for the key in "
              + files.pendingFile()
              + " did not finish ("
              + s.why()
              + "). The key is kept, and nothing changed: calling renewClientCertificate() again"
              + " searches again",
          cause,
          OP,
          null,
          null,
          null);
    }

    /**
     * Checks the issued certificate, uses it, and writes it. {@code keyFile} holds {@code key} now:
     * the pending file, or a file an earlier attempt moved it to ({@link RenewalFiles#setAside}).
     * {@code since} is when {@code key} was first written, from which the notAfter a request for it
     * asked for is known ({@link #asked}).
     */
    private RenewedCertificate finish(
        Found found,
        PublicKey requested,
        PrivateKey key,
        boolean resumed,
        Path keyFile,
        Since since)
        throws IOException, GeneralSecurityException {
      List<X509Certificate> known =
          new ArrayList<>(current.chain().subList(1, current.chain().size()));
      for (TrustManager t : trustManagers())
        if (t instanceof X509TrustManager x) known.addAll(Arrays.asList(x.getAcceptedIssuers()));
      // The server has retired the current certificate by now: the certificate is refused only when
      // it cannot serve as this client's TLS certificate now. What the server judges by its own
      // clock or policy (its period, its notBefore, its issuer) is reported, never refused: that
      // would leave the client with a retired certificate and a refused one.
      Instant now = now();
      String problem = verify(found.certificate, current.leaf(), requested, key, now);
      if (problem != null) {
        String refused =
            "the server issued certificate "
                + found.id
                + " ("
                + fingerprint(found.certificate)
                + "), which this client refuses: "
                + problem;
        // The server has retired the current certificate: a lockout, told as every other one.
        throw lockout(
            new OutcomeUnknownException(
                OP
                    + ": the client may be locked out of the KMS: "
                    + refused
                    + ". The server has retired the current certificate ("
                    + previous
                    + ") for new connections; open connections keep working until they close. The"
                    + " new private key is in "
                    + keyFile
                    + ". Follow the server's lockout recovery (keytend-kmip-server:"
                    + " docs/re-provision.md, \"Lockout recovery\") and "
                    + GUIDE,
                new ProtocolViolationException(OP + ": " + refused, null, OP, found.id, null, null),
                OP,
                found.id,
                null,
                null));
      }
      String issued = fingerprint(found.certificate);
      List<String> warnings = new ArrayList<>(warnings(found.certificate, known, now));
      String period = periodWarning(found.certificate, asked(since));
      if (period != null) warnings.add(period);
      for (String warning : warnings)
        worker.fire(
            l ->
                l.clientCertificateRenewalWarning(
                    issued,
                    "the server issued certificate "
                        + found.id
                        + " ("
                        + issued
                        + "), which the SDK uses, since the server retired the current one ("
                        + previous
                        + "): "
                        + warning));
      List<X509Certificate> chain = chain(found.certificate, current.chain());
      Renewed r = adopt(key, chain, found.id, previous, keyFile, false);
      save(key, chain, found.id, requested, pendingPassword(), keyFile);
      written(r);
      dropUnresolved();
      return new RenewedCertificate(chain, found.id, previous, issued, resumed);
    }

    /**
     * The notAfter dates the requests for a key first written at {@code since} asked for, by the
     * server's clock: from {@link CertificateRenewal#validFor} after the server's time when the key
     * was written (the first request) to that much after the time since then by this machine's
     * clock (a request sent again with it later). Null without a {@code validFor}.
     */
    private Asked asked(Since since) {
      Duration validFor = options.validFor().orElse(null);
      if (validFor == null) return null;
      Instant first =
          ReProvisionValidity.notAfter(
              validFor, since.server() != null ? since.server() : since.here());
      Duration elapsed = Duration.between(since.here(), now());
      return new Asked(validFor, first, elapsed.isNegative() ? first : first.plus(elapsed));
    }

    /**
     * After a renewal of {@code previous} succeeded: deletes the keys earlier attempts moved aside
     * for it ({@link RenewalFiles#setAside}). The server retired that certificate and refuses any
     * message still sent with it, so it can no longer issue a certificate for them; the key of the
     * certificate just used, if it was one of them, is in the identity files now. Reported with
     * {@link KmsListener#clientCertificateRenewalWarning}; a file that cannot be deleted is named.
     */
    private void dropUnresolved() {
      if (previous == null) return;
      List<Path> deleted = new ArrayList<>();
      List<String> left = new ArrayList<>();
      for (Path p : files.unresolved()) {
        if (!previous.equals(RenewalFiles.replaces(p))) continue;
        try {
          StagedFiles.delete(p);
          deleted.add(p);
        } catch (IOException | RuntimeException e) {
          left.add(p + " (" + message(e) + ")");
        }
      }
      if (deleted.isEmpty() && left.isEmpty()) return;
      String retired = previous;
      String told =
          "the renewal retired certificate "
              + retired
              + ", so the server can no longer issue a certificate for the keys earlier attempts"
              + " moved aside for it"
              + (deleted.isEmpty() ? "" : "; deleted " + deleted)
              + (left.isEmpty() ? "" : "; could not delete " + left + ": delete them by hand")
              + ". See "
              + GUIDE;
      worker.fire(l -> l.clientCertificateRenewalWarning(retired, told));
    }

    /**
     * Writes a renewal this process uses: the pending file with the certificate, then the identity
     * files, then deletes the pending file. {@code keyFile} holds {@code key} until the pending
     * file is written.
     *
     * @throws RenewalNotSavedException when a write fails; it carries the certificate
     */
    private void save(
        PrivateKey key,
        List<X509Certificate> chain,
        String id,
        PublicKey requested,
        char[] pendingPassword,
        Path keyFile)
        throws RenewalNotSavedException {
      String step = "the pending file " + files.pendingFile();
      try {
        worker.stage = "writing the issued certificate to " + files.pendingFile();
        files.writePending(key, chain, previous, id, requested, pendingPassword, null);
        step = files.names();
        worker.stage = "switching " + files.names() + " to the issued certificate";
        files.switchTo(key, chain, password);
      } catch (IOException | GeneralSecurityException e) {
        String pem = RenewalNotSavedException.pem(chain);
        boolean switching = step.equals(files.names());
        throw new RenewalNotSavedException(
            OP
                + ": the server issued the new certificate "
                + (id == null ? "" : id + " ")
                + "("
                + fingerprint(chain.get(0))
                + ") and this process uses it, but writing "
                + step
                + " failed ("
                + e.getClass().getSimpleName()
                + ": "
                + message(e)
                + ")"
                + ". Fix the cause and call renewClientCertificate() again: it writes the files."
                + " With automatic renewal the SDK tries again after the failure backoff."
                + (switching
                    ? " A restart finishes the switch from " + files.pendingFile() + " first."
                    : " Do it before this process stops: a restart would read the retired"
                        + " certificate, and the only other copy of the new one is below. The new"
                        + " private key is in "
                        + keyFile
                        + "; "
                        + (files.identity.kind == TlsFiles.IdentityKind.PEM
                                && !PemIdentity.combined(files.identity.chain, files.identity.key)
                            ? "writing the chain below to "
                                + files.identity.chain
                                + " lets the next start finish the switch with it."
                            : "put it and the chain below in the configured files."))
                + " See "
                + GUIDE
                + ". The new certificate chain, which is public:\n"
                + pem,
            e,
            pem);
      }
      try {
        files.deletePending();
      } catch (IOException leftOver) {
        // Harmless: the next attempt or start sees it holds the files' certificate and deletes it.
      }
    }

    /**
     * The certificate the server issued for {@code key} since {@code since}, looked for through
     * the standby (when there is one), then through the connections of this {@link Kms} that are
     * open on the current certificate, then (with {@code fresh}) through a new connection. A
     * connection that fails, or one refused because it is new, passes the search to the next.
     */
    private Searched lookFor(Connection standby, PublicKey key, Since since, boolean fresh) {
      worker.stage = "looking for the certificate the server issued";
      List<String> failures = new ArrayList<>();
      boolean refusedOnNew = false, accepted = false;
      List<Searched> tried = new ArrayList<>();
      if (standby != null)
        tried.add(
            searchOn(
                standby.client,
                RequestOptions.DEFAULT,
                standby.transport,
                key,
                since,
                "the standby connection"));
      if (!tried.isEmpty() && !tried.get(0).unusable()) return tried.get(0);
      for (Pooled p : kms.renewalPools()) {
        Searched s =
            searchOn(
                p.client(),
                p.options(),
                p.transport(),
                key,
                since,
                "an open connection of this Kms");
        if (!s.unusable()) return s;
        tried.add(s);
      }
      if (fresh) {
        try (Connection c = open(endpoint, f)) {
          c.client.call(Requests.discoverVersions().build(), context());
          // The server accepts the current certificate on a new connection: it has not retired it.
          accepted = true;
          Searched s =
              searchOn(
                  c.client, RequestOptions.DEFAULT, c.transport, key, since, "a new connection");
          if (!s.unusable()) return s;
          tried.add(s);
        } catch (KmipException e) {
          tried.add(
              denied(e)
                  ? Searched.refused(
                      "the server refuses the current certificate on new connections ("
                          + e.getMessage()
                          + ")")
                  : Searched.unusable("a new connection: " + e.getMessage()));
        } catch (IOException | RuntimeException e) {
          tried.add(Searched.unusable("a new connection: " + message(e)));
        }
      }
      for (Searched s : tried) {
        failures.add(s.why());
        refusedOnNew |= s.refusedOnNew();
      }
      if (failures.isEmpty())
        failures.add("no connection on the current certificate is left to look with");
      String why = String.join("; ", failures);
      if (refusedOnNew) return Searched.refused(why);
      return new Searched(null, Searched.Kind.UNUSABLE, why, accepted);
    }

    /** {@link #search} through {@code client}, whose connections {@code transport} opens. */
    private Searched searchOn(
        KmipClient client,
        RequestOptions options,
        TlsTransport transport,
        PublicKey key,
        Since since,
        String label) {
      long opened = transport.connectionsOpened();
      try {
        Found found = search(client, options, key, since, timeout, this::now);
        return found != null ? Searched.found(found) : Searched.EXHAUSTED;
      } catch (Truncated e) {
        return new Searched(null, Searched.Kind.TRUNCATED, label + ": " + e.getMessage());
      } catch (KmipException e) {
        if (denied(e) && transport.connectionsOpened() > opened)
          // The connection was gone, and a new one on the current certificate was refused.
          return Searched.refused(
              label
                  + " was closed, and the server refused a new connection on the current"
                  + " certificate ("
                  + e.getMessage()
                  + ")");
        if (denied(e))
          return new Searched(
              null,
              Searched.Kind.POLICY_DENIED,
              label
                  + ": "
                  + e.getMessage()
                  + "; the server's policy must allow Locate (8) and Get (10)");
        return Searched.unusable(label + ": " + e.getMessage());
      } catch (IOException | RuntimeException e) {
        return Searched.unusable(label + ": " + message(e));
      }
    }

    /**
     * When the key of {@code pending} was first written: by this machine's clock and the server's.
     */
    private Since since(RenewalFiles.Pending pending) {
      return new Since(pending.written(), pending.serverTime());
    }

    /** A lockout: the message says what is on disk and how to recover. */
    private KmsException lockout(String why, Throwable cause) {
      return lockout(
          new OutcomeUnknownException(
              OP
                  + ": the client may be locked out of the KMS: "
                  + why
                  + ". If the server issued the new certificate, it retired the current one ("
                  + previous
                  + ") for new connections. The new private key is in "
                  + files.pendingFile()
                  + ". Calling renewClientCertificate() again looks for the new certificate"
                  + " through a connection on the current certificate (an open connection of a"
                  + " Kms of this configuration, or a new one while the server still accepts the"
                  + " certificate) and finishes the renewal if the server issued it. Otherwise"
                  + " follow the server's lockout recovery (keytend-kmip-server:"
                  + " docs/re-provision.md, \"Lockout recovery\") and "
                  + GUIDE,
              cause,
              OP,
              null,
              null,
              null));
    }

    /** {@code failure}, after which the client may be locked out: told as such. */
    private KmsException lockout(KmsException failure) {
      lockedOut = true;
      return failure;
    }

    private KmsException read(Exception e) {
      return Failures.classify(new Failures.Call(OP, true, null, false), version, e);
    }

    private CallContext context() {
      return CallContext.withTimeout(timeout);
    }

    private Instant now() {
      return kms.now();
    }

    private TrustManager[] trustManagers() {
      TrustManager[] t = source.trust();
      return t == null ? new TrustManager[0] : t;
    }

    /** A connection on the current certificate, to the endpoint the Kms uses. */
    private Connection open(KmsConfig.Endpoint endpoint, SSLContext f) {
      return ClientRenewal.open(kms, version, endpoint, f);
    }
  }

  /**
   * The server's clock and this machine's at one moment, to place this machine's times on the
   * server's clock: the server sets the Initial Date the search looks by.
   */
  record Clocks(Instant server, Instant here) {
    Instant onServer(Instant t) {
      return t.plus(Duration.between(here, server));
    }
  }

  /**
   * Reads the server's clock through {@code client}: the Time Stamp of the header of a Discover
   * Versions response, against this machine's clock halfway through the exchange.
   *
   * @throws KmipException when the server refuses Discover Versions
   */
  static Clocks clocks(
      KmipClient client, RequestOptions options, Duration timeout, Supplier<Instant> clock)
      throws IOException {
    Instant before = clock.get();
    Response r =
        client.batch(
            List.of(Requests.discoverVersions().build()),
            options,
            CallContext.withTimeout(timeout));
    Instant after = clock.get();
    if (r.results().isEmpty()) throw new IOException("Discover Versions returned no result");
    r.results().get(0).requireSuccess();
    Instant here = before.plus(Duration.between(before, after).dividedBy(2));
    return new Clocks(r.timestamp() == null ? here : r.timestamp(), here);
  }

  /**
   * When a key was first written, before it was sent: by this machine's clock, and by the server's
   * when known (null when not).
   */
  record Since(Instant here, Instant server) {}

  /**
   * The certificate the server holds for {@code key}, created around {@code since}: Initial Date
   * from an hour before {@code since} to an hour after the server's time now, both by the server's
   * clock (read through {@code client} first, so a server whose clock differs from this machine's
   * is searched at the right time); null when a full search found none.
   *
   * @throws Truncated when the search stopped before it saw every candidate
   * @throws KmipException when the server refused a Locate or a Get
   */
  static Found search(
      KmipClient client,
      RequestOptions options,
      PublicKey key,
      Since since,
      Duration timeout,
      Supplier<Instant> clock)
      throws IOException, Truncated {
    Clocks c = clocks(client, options, timeout, clock);
    Instant start = since.server() != null ? since.server() : c.onServer(since.here());
    // At least the hour around the server's now, whatever the times recorded.
    Instant earliest = c.server().minus(SEARCH_WINDOW);
    Instant from = start.minus(SEARCH_WINDOW);
    if (from.isAfter(earliest)) from = earliest;
    // KMIP dates are whole seconds.
    from = from.truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
    Instant to = c.server().plus(SEARCH_WINDOW).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
    LocateRequest locate =
        LocateRequest.builder()
            .objectType(Enums.ObjectType.CERTIFICATE)
            .attribute(Attributes.attribute("Initial Date", dateTime(INITIAL_DATE, from)))
            .attribute(Attributes.attribute("Initial Date", dateTime(INITIAL_DATE, to)))
            .build();
    byte[] wanted = key.getEncoded();
    Set<String> seen = new HashSet<>();
    int limit = searchLimit, size = searchPage;
    for (int offset = 0; ; ) {
      LocateRequest.Page page =
          LocateRequest.result(
              client.call(locate.page(offset, size), CallContext.withTimeout(timeout)));
      List<String> ids = page.identifiers();
      int unseen = 0;
      for (String id : ids) {
        if (!seen.add(id)) continue;
        unseen++;
        if (seen.size() > limit)
          throw new Truncated(
              "more than "
                  + limit
                  + " certificates were created around the attempt; the search stopped there");
        Result got;
        try {
          got =
              client.call(
                  Requests.get().uniqueIdentifier(id).build(), CallContext.withTimeout(timeout));
        } catch (KmipException e) {
          // Only an object that is gone may be passed over: anything else could hide it.
          if (e.result().hasReason(Enums.ResultReason.ITEM_NOT_FOUND)
              || e.result().hasReason(Enums.ResultReason.OBJECT_NOT_FOUND)) continue;
          throw e;
        }
        X509Certificate cert = certificate(got);
        if (cert != null && Arrays.equals(cert.getPublicKey().getEncoded(), wanted))
          return new Found(id, cert);
      }
      offset += ids.size();
      Integer located = page.locatedItems();
      // Done at an empty page, or once the count the server gave is reached. A short page
      // without a count may be the server's own limit, so the next page is asked for.
      if (ids.isEmpty() || (located != null && offset >= located)) return null;
      if (unseen == 0)
        throw new Truncated("the server repeated a page of Locate results (Offset Items ignored)");
    }
  }

  /**
   * {@code f} with {@code note} added to its message: the same type, reason and result, and {@code
   * f} as the cause.
   */
  static KmsException noted(KmsException f, String note) {
    String m = f.getMessage() + ". " + note;
    String op = f.operation(), id = f.objectId().orElse(null);
    Result r = f.result().orElse(null);
    Ttlv response = f.response().orElse(null);
    if (f instanceof PermissionDeniedException)
      return new PermissionDeniedException(m, f, op, id, r, response);
    if (f instanceof InvalidRequestException)
      return new InvalidRequestException(m, f, op, id, r, response);
    if (f instanceof UnsupportedException)
      return new UnsupportedException(m, f, op, id, r, response);
    if (f instanceof NotFoundException) return new NotFoundException(m, f, op, id, r, response);
    if (f instanceof StateConflictException)
      return new StateConflictException(m, f, op, id, r, response);
    if (f instanceof ServerFailureException)
      return new ServerFailureException(m, f, op, id, r, response);
    if (f instanceof TransientException) return new TransientException(m, f, op, id, r, response);
    if (f instanceof OutcomeUnknownException)
      return new OutcomeUnknownException(m, f, op, id, r, response);
    if (f instanceof KeyMismatchException)
      return new KeyMismatchException(m, f, op, id, r, response);
    if (f instanceof CryptographicFailureException)
      return new CryptographicFailureException(m, f, op, id, r, response);
    return new ProtocolViolationException(m, f, op, id, r, response);
  }

  /** {@code message} without the leading operation name a failure's message starts with. */
  private static String withoutOperation(String message) {
    return message != null && message.startsWith(OP + ": ")
        ? message.substring(OP.length() + 2)
        : String.valueOf(message);
  }

  /** The keys earlier attempts moved aside for one certificate, and the files that hold them. */
  private record KeysAside(List<Path> files, List<RenewalFiles.Pending> keys) {
    boolean isEmpty() {
      return keys.isEmpty();
    }
  }

  /** A failure's message, or its class when it has none. */
  private static String message(Throwable e) {
    return e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
  }

  /** What a search for the new certificate showed. */
  private record Searched(Found found, Kind kind, String why, boolean accepted) {
    enum Kind {
      /** The certificate. */
      FOUND,
      /** Every candidate was seen, and none is for the key: the server holds none. */
      EXHAUSTED,
      /** The search stopped before it saw every candidate. */
      TRUNCATED,
      /** The server refused Locate or Get on a connection it accepts: its policy. */
      POLICY_DENIED,
      /** The connection failed; another may do. */
      UNUSABLE,
      /** The server refused the current certificate on a new connection; another may do. */
      REFUSED_ON_NEW
    }

    static final Searched EXHAUSTED = new Searched(null, Kind.EXHAUSTED, "nothing found", false);

    Searched(Found found, Kind kind, String why) {
      this(found, kind, why, false);
    }

    static Searched found(Found found) {
      return new Searched(found, Kind.FOUND, "found");
    }

    static Searched unusable(String why) {
      return new Searched(null, Kind.UNUSABLE, why);
    }

    static Searched refused(String why) {
      return new Searched(null, Kind.REFUSED_ON_NEW, why);
    }

    boolean unusable() {
      return kind == Kind.UNUSABLE || kind == Kind.REFUSED_ON_NEW;
    }

    boolean refusedOnNew() {
      return kind == Kind.REFUSED_ON_NEW;
    }
  }

  /** A search that stopped before it saw every candidate. */
  static final class Truncated extends Exception {
    private static final long serialVersionUID = 1L;

    Truncated(String message) {
      super(message, null, false, false);
    }
  }

  /**
   * The open connections of a {@link Kms} on its current TLS context, for a renewal's search, and
   * the transport that counts the connections it opens.
   */
  record Pooled(KmipClient client, TlsTransport transport, RequestOptions options) {}

  /** A connection of an attempt's own; closed when the attempt ends. */
  private record Connection(TlsTransport transport, KmipClient client) implements AutoCloseable {
    @Override
    public void close() {
      try {
        transport.close();
      } catch (IOException ignored) {
        // closing
      }
    }
  }

  /** A certificate the server issued, and its identifier. */
  record Found(String id, X509Certificate certificate) {}

  /** Uses {@code key} and {@code chain} in memory, for every Kms of these files. */
  private Renewed adopt(
      PrivateKey key,
      List<X509Certificate> chain,
      String certificateId,
      String previous,
      Path keyFile,
      boolean written) {
    KeyManager[] identity = KmsConfig.keyManagers(key, chain);
    synchronized (shared) {
      Renewed r =
          new Renewed(
              ++shared.generations,
              identity,
              key,
              chain,
              certificateId,
              previous,
              keyFile,
              written);
      if (previous != null) shared.retired.add(previous);
      shared.renewed = r;
      return r;
    }
  }

  /** Marks {@code r} written to the files, unless a later renewal replaced it. */
  private void written(Renewed r) {
    synchronized (shared) {
      if (shared.renewed == r)
        shared.renewed =
            new Renewed(
                r.generation(),
                r.identity(),
                r.key(),
                r.chain(),
                r.certificateId(),
                r.previous(),
                r.keyFile(),
                true);
    }
  }

  // ---- checks ----

  /**
   * Why {@code issued} must be refused, or null when it may replace {@code replaced}. The server
   * has retired {@code replaced} by then, so only what makes {@code issued} unusable as this
   * client's TLS certificate now refuses it: it must be for {@code newKey} (and {@code key} must
   * sign for it), have {@code replaced}'s subject and subjectAltName, not have expired at {@code
   * now}, not be a CA, allow digitalSignature when it states a key usage, and allow clientAuth (or
   * any extended key usage) when it states an extended key usage. What the server judges by its
   * own clock or policy is reported instead ({@link #warnings}).
   */
  static String verify(
      X509Certificate issued,
      X509Certificate replaced,
      PublicKey newKey,
      PrivateKey key,
      Instant now) {
    if (!Arrays.equals(issued.getPublicKey().getEncoded(), newKey.getEncoded()))
      return "it is not for the new key";
    if (!PemIdentity.matches(key, issued.getPublicKey(), null))
      return "the new private key does not sign for it";
    if (!issued.getSubjectX500Principal().equals(replaced.getSubjectX500Principal()))
      return "its subject ("
          + issued.getSubjectX500Principal()
          + ") is not the current certificate's ("
          + replaced.getSubjectX500Principal()
          + ")";
    try {
      if (!names(issued).equals(names(replaced)))
        return "its subjectAltName "
            + names(issued)
            + " is not the current certificate's "
            + names(replaced);
    } catch (CertificateParsingException e) {
      return "its subjectAltName cannot be read";
    }
    Instant notAfter = issued.getNotAfter().toInstant();
    if (!notAfter.isAfter(now)) return "it has expired (notAfter " + notAfter + ")";
    if (issued.getBasicConstraints() != -1) return "it is a CA certificate";
    try {
      // TLS takes a certificate without the extension as unrestricted.
      List<String> eku = issued.getExtendedKeyUsage();
      if (eku != null && !eku.contains(CLIENT_AUTH) && !eku.contains(ANY_EXTENDED_KEY_USAGE))
        return "its extended key usage " + eku + " does not allow clientAuth";
    } catch (CertificateParsingException e) {
      return "its extended key usage cannot be read";
    }
    boolean[] usage = issued.getKeyUsage();
    if (usage != null && (usage.length == 0 || !usage[0]))
      return "its key usage does not allow digitalSignature";
    return null;
  }

  /**
   * What needs attention in {@code issued}, a certificate {@link #verify} accepted, though it is
   * no reason to refuse it after the server retired the one it replaces: a notBefore after this
   * machine's {@code now} (the server dates it by its own clock), and a signature that does not
   * verify with the issuer's certificate in {@code known} of that name (the server's trust of
   * client certificates decides).
   */
  static List<String> warnings(X509Certificate issued, List<X509Certificate> known, Instant now) {
    List<String> out = new ArrayList<>();
    Instant notBefore = issued.getNotBefore().toInstant();
    if (notBefore.isAfter(now))
      out.add(
          "it is valid from "
              + notBefore
              + ", after this machine's time ("
              + now
              + "). The server dates it by its own clock, so this machine's clock is likely behind"
              + " the server's: correct it, since anything that checks the certificate by this"
              + " clock refuses it until then");
    boolean issuerKnown = false, verified = false;
    for (X509Certificate k : known)
      if (k.getSubjectX500Principal().equals(issued.getIssuerX500Principal())) {
        issuerKnown = true;
        try {
          issued.verify(k.getPublicKey());
          verified = true;
          break;
        } catch (GeneralSecurityException | RuntimeException e) {
          // another certificate of that name may verify it
        }
      }
    if (issuerKnown && !verified)
      out.add(
          "its signature does not verify with the certificate this client has for its issuer "
              + issued.getIssuerX500Principal()
              + ". The server's trust of client certificates decides whether it is accepted;"
              + " check that the client's trust and chain files hold the provisioning CA the"
              + " server uses");
    return out;
  }

  /** How far an issued notAfter may be from the one asked for before it is reported. */
  static final Duration PERIOD_TOLERANCE = Duration.ofMinutes(1);

  /**
   * The notAfter a renewal asked for ({@link CertificateRenewal#validFor}): {@code from} to {@code
   * to}, which differ when the request was sent again with the same key later.
   */
  record Asked(Duration validFor, Instant from, Instant to) {}

  /**
   * The warning for {@code issued} when its notAfter is not the one {@code asked} for, give or take
   * {@link #PERIOD_TOLERANCE}: the server chose another period, which the SDK uses since the server
   * retired the certificate it replaces. Null when it is, or nothing was asked.
   */
  static String periodWarning(X509Certificate issued, Asked asked) {
    if (asked == null) return null;
    Instant notAfter = issued.getNotAfter().toInstant();
    if (!notAfter.isBefore(asked.from().minus(PERIOD_TOLERANCE))
        && !notAfter.isAfter(asked.to().plus(PERIOD_TOLERANCE))) return null;
    String wanted =
        asked.from().equals(asked.to())
            ? asked.from().toString()
            : "between " + asked.from() + " and " + asked.to();
    return "it is valid until "
        + notAfter
        + ", not the notAfter the request asked for ("
        + wanted
        + ", validFor "
        + asked.validFor()
        + "). The server chose another period: check that it supports the requested validity, or"
        + " that its policy allows this period";
  }

  /** The subjectAltName entries of {@code c}, comparable: type and value. */
  private static Set<String> names(X509Certificate c) throws CertificateParsingException {
    Set<String> out = new TreeSet<>();
    Collection<List<?>> all = c.getSubjectAlternativeNames();
    if (all != null)
      for (List<?> n : all)
        out.add(
            n.get(0)
                + ":"
                + (n.get(1) instanceof byte[] b ? HexFormat.of().formatHex(b) : n.get(1)));
    return out;
  }

  /**
   * The chain to write: {@code issued}, then the certificates of the previous chain from the one
   * that issued it on (an intermediate the server does not hold), when one did.
   */
  static List<X509Certificate> chain(X509Certificate issued, List<X509Certificate> previous) {
    List<X509Certificate> out = new ArrayList<>(List.of(issued));
    for (int i = 1; i < previous.size(); i++) {
      X509Certificate c = previous.get(i);
      if (!c.getSubjectX500Principal().equals(issued.getIssuerX500Principal())) continue;
      try {
        issued.verify(c.getPublicKey());
        out.addAll(previous.subList(i, previous.size()));
        break;
      } catch (GeneralSecurityException | RuntimeException e) {
        // not this one
      }
    }
    return out;
  }

  /** The X.509 certificate a Get returned, or null when it returned something else. */
  static X509Certificate certificate(Result got) {
    try {
      Ttlv object = got.payload().flatMap(p -> p.child(CERTIFICATE)).orElse(null);
      if (object == null) return null;
      if (object.require(CERTIFICATE_TYPE).intValue() != Enums.CertificateType.X_509.code())
        return null;
      byte[] der = object.require(CERTIFICATE_VALUE).bytesValue();
      return (X509Certificate)
          CertificateFactory.getInstance("X.509")
              .generateCertificate(new ByteArrayInputStream(der));
    } catch (CertificateException | RuntimeException e) {
      return null;
    }
  }

  /** Whether {@code e} is a refusal of the credentials. */
  private static boolean denied(KmipException e) {
    return e.result().hasReason(Enums.ResultReason.PERMISSION_DENIED)
        || e.result().hasReason(Enums.ResultReason.AUTHENTICATION_NOT_SUCCESSFUL);
  }

  /** Whether two public keys are of one kind: RSA of one modulus size, or EC on one curve. */
  static boolean sameKind(PublicKey a, PublicKey b) {
    if (a instanceof RSAPublicKey r && b instanceof RSAPublicKey s)
      return a.getAlgorithm().equals(b.getAlgorithm())
          && r.getModulus().bitLength() == s.getModulus().bitLength();
    if (a instanceof ECPublicKey e && b instanceof ECPublicKey f) {
      ECParameterSpec p = e.getParams(), q = f.getParams();
      return p.getCurve().equals(q.getCurve())
          && p.getGenerator().equals(q.getGenerator())
          && p.getOrder().equals(q.getOrder())
          && p.getCofactor() == q.getCofactor();
    }
    return false;
  }

  /** A new key pair of {@code current}'s kind. */
  static KeyPair like(PublicKey current) throws GeneralSecurityException {
    if (current instanceof RSAPublicKey r && current.getAlgorithm().equals("RSA")) {
      KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
      g.initialize(
          new RSAKeyGenParameterSpec(r.getModulus().bitLength(), RSAKeyGenParameterSpec.F4));
      return g.generateKeyPair();
    }
    if (current instanceof ECPublicKey e) {
      KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
      g.initialize(e.getParams());
      return g.generateKeyPair();
    }
    throw new UnsupportedException(
        OP
            + ": renewal makes RSA and EC keys; the current certificate's key is "
            + current.getAlgorithm(),
        null,
        OP,
        null,
        null,
        null);
  }

  /** The public key of {@code algorithm} in X.509 SubjectPublicKeyInfo {@code der}. */
  static PublicKey publicKey(String algorithm, byte[] der) throws GeneralSecurityException {
    return KeyFactory.getInstance(algorithm)
        .generatePublic(new java.security.spec.X509EncodedKeySpec(der));
  }

  static String fingerprint(X509Certificate c) {
    return RenewalFiles.fingerprint(c);
  }

  // ---- the Kms's close ----

  /** The failure of a renewal of a {@link Kms} that is closed, as for its other calls. */
  static IllegalStateException closed() {
    return new IllegalStateException("Kms is closed");
  }

  /**
   * How long {@link Kms#close()} waits for the renewals that committed ({@link Worker#commit}):
   * three times the call timeout they use ({@link Worker#timeout}, the largest of them, and at
   * least the configured one). One for the reply to Re-Provision, whose wait the call timeout
   * bounds, and two for the search after a lost reply (its clock read, Locate pages and Gets, each
   * bounded by the call timeout, and usually far quicker) and the local writes.
   */
  static Duration closeWait(Duration callTimeout) {
    try {
      return callTimeout.multipliedBy(3);
    } catch (ArithmeticException tooLong) {
      return callTimeout;
    }
  }

  /** {@code kms}, a Kms of this configuration, is open now. */
  void opened() {
    synchronized (closing) {
      open++;
    }
  }

  /** For tests: the renewals running for this configuration's Kms instances. */
  int runningWorkers() {
    synchronized (closing) {
      return workers.size();
    }
  }

  /** Whether the current thread runs a renewal of this configuration, of any of its Kms. */
  boolean onRenewalThread() {
    Thread current = Thread.currentThread();
    synchronized (closing) {
      for (Worker w : workers) if (w.thread == current) return true;
    }
    return false;
  }

  /** A renewal of {@code kms} starts: its worker, or null when {@code kms} is closed. */
  private Worker enter(Kms kms) {
    synchronized (closing) {
      if (kms.closed()) return null;
      Worker w = new Worker(kms);
      workers.add(w);
      return w;
    }
  }

  /** The renewal {@code w} has ended. */
  private void leave(Worker w) {
    synchronized (closing) {
      workers.remove(w);
    }
    w.done.countDown();
  }

  /**
   * One renewal running for a {@link Kms}, on one thread: an attempt, on demand or automatic, or an
   * automatic check. Until it {@linkplain #commit commits}, it has sent nothing that the server may
   * act on, and found nothing it must write: the Kms's close does not wait for it, and it stops at
   * its next commitment. Once committed, the close waits for it to end, up to {@link #closeWait}.
   * After the close returns, its events go to the SDK's log only ({@link #fire}).
   */
  final class Worker {
    final Kms kms;
    final Thread thread = Thread.currentThread();

    /**
     * The call timeout the renewal uses: that of the Kms it runs on, a {@link Kms#withTimeout}
     * view's for a renewal through one. Its reply waits are bounded by it, so the close's wait is.
     */
    final Duration timeout;

    /** Ends when the renewal ends. */
    final java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(1);

    /** Held while an event is delivered, so that the close never returns during one. */
    private final ReentrantLock firing = new ReentrantLock();

    /** Whether the renewal committed; guarded by {@link #closing}. */
    private boolean committed;

    /** Whether the Kms's close has returned: events go to the SDK's log only. */
    private volatile boolean silenced;

    /** What the renewal does now, for the close's report. */
    volatile String stage = "starting";

    /** The attempt, once one runs. */
    volatile Attempt attempt;

    Worker(Kms kms) {
      this.kms = kms;
      this.timeout = kms.callTimeout();
    }

    /** Throws {@link IllegalStateException} when the Kms is closed. */
    void open() {
      if (kms.closed()) throw closed();
    }

    /**
     * Commits to {@code stage}: a send the server may act on (Re-Provision), or a search or write
     * for a certificate the server issued, which the close waits for. Throws {@link
     * IllegalStateException} instead when the Kms is closed: nothing of {@code stage} was done.
     */
    void commit(String stage) {
      synchronized (closing) {
        if (kms.closed()) throw closed();
        committed = true;
        this.stage = stage;
      }
    }

    /**
     * Tells the Kms's listeners {@code event}, one at a time, each isolated ({@link Kms#fire}).
     * Before each listener, the renewal looks whether the Kms's close has returned: from then on
     * the event goes to the SDK's log only. So a listener that closes the Kms, or a close whose
     * wait runs out while a listener runs, keeps the event from the listeners after it; the one
     * running then finishes its callback.
     */
    void fire(Consumer<KmsListener> event) {
      firing.lock();
      try {
        KmsListener all = kms.listener();
        List<KmsListener> each =
            all instanceof KmsListeners listeners ? listeners.listeners() : List.of(all);
        boolean logged = false;
        for (KmsListener l : each) {
          boolean log = l == LoggingListener.INSTANCE;
          if (silenced && !log) continue;
          logged |= log;
          Kms.fire(l, event);
        }
        if (silenced && !logged) Kms.fire(LoggingListener.INSTANCE, event);
      } finally {
        firing.unlock();
      }
    }

    /**
     * Sends later events to the SDK's log only. Waits for an event being delivered on another
     * thread until {@code deadline} ({@link System#nanoTime}); one on this thread (a listener that
     * closes the Kms) is done once it returns.
     */
    void silence(long deadline) {
      boolean held = false;
      try {
        held = firing.tryLock(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
      }
      silenced = true;
      if (held) firing.unlock();
    }
  }

  /**
   * {@link Kms#close()} of {@code kms}, a Kms of this configuration: marks it closed ({@code
   * markClosed}, under the lock that orders it with each {@link Worker#commit}), then waits up to
   * {@link #closeWait} for the renewals of {@code kms} that committed, and of every Kms of this
   * configuration when {@code kms} is the last one open. A renewal running on this thread (a
   * listener or a renewal step that closes the Kms) is not waited for. Afterwards every one of them
   * is silenced. For one still running, the Kms's listeners are told what is on disk, and how the
   * next start recovers if the process stops before it ends. Runs once for each {@code kms}: its
   * first close ({@link Kms#close()} returns at once, or waits for that one, on a later call).
   */
  void close(Kms kms, Runnable markClosed) {
    List<Worker> waited = new ArrayList<>(), others = new ArrayList<>();
    synchronized (closing) {
      markClosed.run();
      boolean last = --open <= 0;
      for (Worker w : workers) {
        if (!last && !w.kms.sameKms(kms)) continue;
        if (w.committed && w.thread != Thread.currentThread()) waited.add(w);
        else others.add(w);
      }
    }
    // The longest reply wait of the renewals waited for: a renewal through a view has the view's.
    Duration timeout = kms.config.callTimeout;
    for (Worker w : waited) if (w.timeout.compareTo(timeout) > 0) timeout = w.timeout;
    Duration bound = closeWait(timeout);
    long deadline = System.nanoTime() + nanos(bound);
    List<Worker> running = new ArrayList<>();
    boolean interrupted = false;
    for (Worker w : waited) {
      try {
        if (interrupted
            || !w.done.await(Math.max(0, deadline - System.nanoTime()), TimeUnit.NANOSECONDS))
          running.add(w);
      } catch (InterruptedException e) {
        interrupted = true;
        running.add(w);
      }
    }
    if (interrupted) Thread.currentThread().interrupt();
    for (Worker w : others) w.silence(deadline);
    for (Worker w : waited) w.silence(deadline);
    for (Worker w : running) {
      Attempt a = w.attempt;
      String previous = a == null ? null : a.previous;
      String report = stillRunning(w, bound, interrupted);
      Kms.fire(kms.listener(), l -> l.clientCertificateRenewalWarning(previous, report));
    }
  }

  /**
   * For a close that returned while {@code w} still runs: what it does, what is on disk now, and
   * how the next start recovers if the process stops before it ends.
   */
  private String stillRunning(Worker w, Duration bound, boolean interrupted) {
    Attempt a = w.attempt;
    String previous = a == null ? null : a.previous;
    String identity;
    String held = null;
    char[] password = files.identity.passwordForUse();
    try {
      held = fingerprint(files.currentLeaf(password));
      identity =
          "the identity files ("
              + files.names()
              + ") hold certificate "
              + held
              + (held.equals(previous) ? ", the one being replaced" : "");
    } catch (RuntimeException e) {
      identity = "the identity files (" + files.names() + ") cannot be read (" + message(e) + ")";
    } finally {
      if (password != null) Arrays.fill(password, '\0');
    }
    RenewalFiles.State pending = files.pendingState();
    List<Path> aside = files.unresolved();
    String recovery;
    if (pending == RenewalFiles.State.ISSUED)
      recovery =
          "the next start finishes the switch from "
              + files.pendingFile()
              + " (KmsConfig.Builder does so before it reads the identity files)";
    else if (pending == RenewalFiles.State.KEY)
      recovery =
          "the next renewClientCertificate(), automatic renewal or the CLI's renew-certificate"
              + " looks for a certificate the server issued for the key in "
              + files.pendingFile()
              + " and finishes the renewal with it. If the server issued one, it retired the"
              + " current certificate, and a new process cannot connect with it: Kms.connect"
              + " fails with PermissionDeniedException naming that file, and the recovery is the"
              + " server's lockout procedure (keytend-kmip-server: docs/re-provision.md, \"Lockout"
              + " recovery\") with the key in it";
    else if (held != null && previous != null && !held.equals(previous))
      recovery = "nothing is left to recover: the identity files hold the new certificate";
    else
      recovery =
          "the next start uses the identity files as they are"
              + (aside.isEmpty()
                  ? ""
                  : ", and a renewal looks for a certificate issued for the keys moved aside");
    return "Kms.close() "
        + (interrupted ? "was interrupted while it waited" : "waited " + bound)
        + " for a renewal of the client certificate that had sent its request, or was finishing"
        + " one the server issued, and returned while it still runs ("
        + w.stage
        + "). On disk now: "
        + pending.describe(files.pendingFile())
        + "; "
        + identity
        + (aside.isEmpty() ? "" : "; keys moved aside: " + aside)
        + ". The renewal goes on in its thread, a daemon, and its events go to the SDK's log only."
        + " If the process stops before it ends, "
        + recovery
        + ". See "
        + GUIDE;
  }

  // ---- automatic renewal ----

  /** Starts automatic renewal for {@code kms}; null when the options do not ask for it. */
  Auto startAutomatic(Kms kms, Source source) {
    if (options.renewBefore().isEmpty()) return null;
    Auto a = new Auto(kms, source, options.renewBefore().get());
    a.running();
    a.schedule(Duration.ZERO);
    return a;
  }

  /**
   * The checks of one Kms: the certificate's notAfter, and a renewal once it is in the window. The
   * timer thread only starts each check on a worker of its own ({@link #WORKERS}).
   */
  final class Auto implements Runnable {
    private final Kms kms;
    private final Source source;
    private final Duration renewBefore;
    private final java.util.concurrent.atomic.AtomicInteger failures =
        new java.util.concurrent.atomic.AtomicInteger();

    /** The checks in a row that found keys moved aside and the current certificate accepted. */
    private final java.util.concurrent.atomic.AtomicInteger probes =
        new java.util.concurrent.atomic.AtomicInteger();

    private volatile boolean stopped;
    private ScheduledFuture<?> next;

    Auto(Kms kms, Source source, Duration renewBefore) {
      this.kms = kms;
      this.source = source;
      this.renewBefore = renewBefore;
    }

    synchronized void schedule(Duration delay) {
      if (stopped) return;
      next = SCHEDULER.schedule(this::start, nanos(delay), TimeUnit.NANOSECONDS);
    }

    /** Counts this automatic renewal as running ({@link #SCHEDULER}'s keep-alive). */
    private void running() {
      synchronized (RUNNING) {
        if (automaticRunning++ == 0)
          SCHEDULER.setKeepAliveTime(nanos(timerKeepAlive()), TimeUnit.NANOSECONDS);
      }
    }

    /** On the timer thread: hands the check to a worker, so the timer never waits on one. */
    private void start() {
      if (stopped || kms.closed()) return;
      try {
        WORKERS.execute(this);
      } catch (java.util.concurrent.RejectedExecutionException e) {
        schedule(backoff());
      }
    }

    void stop() {
      synchronized (this) {
        if (stopped) return;
        stopped = true;
        if (next != null) next.cancel(false);
      }
      synchronized (RUNNING) {
        // The last one: the timer's idle thread ends after a second, its queue empty.
        if (--automaticRunning == 0)
          SCHEDULER.setKeepAliveTime(SdkThreads.IDLE_MILLIS, TimeUnit.MILLISECONDS);
      }
    }

    @Override
    public void run() {
      if (stopped) return;
      Worker w = enter(kms);
      if (w == null) return;
      Duration delay;
      try {
        delay = check(w);
      } catch (RuntimeException e) {
        failures.incrementAndGet();
        delay = backoff();
      } finally {
        leave(w);
      }
      schedule(delay);
    }

    /** One check, as {@code w}; the delay to the next. */
    private Duration check(Worker w) {
      // An unfinished renewal comes before the expiry: one whose files this process has not all
      // written (the new certificate is in use, the files still hold the retired one), or a
      // pending file. It is tried again, with the failure backoff, until it is done.
      Renewed unwritten = shared.renewed;
      boolean unfinished =
          (unwritten != null && !unwritten.written())
              || java.nio.file.Files.exists(files.pendingFile());
      if (!unfinished) {
        X509Certificate leaf;
        try {
          leaf = currentLeaf();
        } catch (RuntimeException e) {
          failures.incrementAndGet();
          String why = "cannot read the client certificate: " + e.getMessage();
          w.fire(l -> l.clientCertificateRenewalFailed(null, why));
          return backoff();
        }
        Instant now = kms.now(), due = leaf.getNotAfter().toInstant().minus(renewBefore);
        if (now.isBefore(due)) {
          Duration wait = shortest(Duration.between(now, due), maxCheck);
          // A key an earlier attempt moved aside may still be issued a certificate by a message
          // that commits late, which retires this one. While there is one, a new connection's
          // Discover Versions shows whether the server still accepts this certificate; once it
          // refuses it, the attempt looks for that certificate through the connections still
          // open on this one, before they close.
          if (!keysAside(fingerprint(leaf))) {
            probes.set(0);
            return wait;
          }
          if (!refusedOnNewConnection(kms, source)) {
            int n = probes.incrementAndGet();
            return shortest(wait, doubled(n));
          }
        }
      }
      probes.set(0);
      RenewedCertificate done;
      try {
        done = renew(kms, source, true, w);
      } catch (IOException | RuntimeException e) {
        failures.incrementAndGet();
        return backoff();
      }
      if (done == null) return firstBackoff;
      failures.set(0);
      Instant now = kms.now();
      Instant nextDue = done.notAfter().minus(renewBefore);
      if (nextDue.isAfter(now)) return shortest(Duration.between(now, nextDue), maxCheck);
      Duration wait = renewAgainIn(now, done.notAfter());
      // Shorter than a validity validFor may ask for, less a minute for the server's whole-second
      // dates and the time the renewal took: the server issued less than renewal is meant for.
      boolean tooShort =
          Duration.between(now, done.notAfter())
                  .compareTo(CertificateRenewal.MIN_VALIDITY.minus(Duration.ofMinutes(1)))
              < 0;
      String why =
          "the new certificate expires at "
              + done.notAfter()
              + ", within renewBefore ("
              + renewBefore
              + ") already, so the next automatic renewal is after half its remaining validity,"
              + " in "
              + wait
              + ". Shorten renewBefore below the validity of the certificates the server issues"
              + (tooShort
                  ? ", and have the server issue certificates valid for at least "
                      + CertificateRenewal.MIN_VALIDITY
                      + ": this one leaves little time to renew again, or to retry a failure"
                  : "");
      w.fire(l -> l.clientCertificateRenewalWarning(done.fingerprint(), why));
      return wait;
    }

    /** Whether a key an earlier attempt moved aside is for the certificate {@code current}. */
    private boolean keysAside(String current) {
      for (Path p : files.unresolved()) if (current.equals(RenewalFiles.replaces(p))) return true;
      return false;
    }

    private X509Certificate currentLeaf() {
      char[] password = files.identity.passwordForUse();
      try {
        return files.currentLeaf(password);
      } finally {
        if (password != null) Arrays.fill(password, '\0');
      }
    }

    private Duration backoff() {
      return doubled(failures.get());
    }
  }

  /** {@link #firstBackoff}, doubled for each of {@code n} times in a row after the first. */
  private static Duration doubled(int n) {
    Duration d = firstBackoff;
    for (int i = 1; i < n && d.compareTo(maxBackoff) < 0; i++) d = d.multipliedBy(2);
    return shortest(d, maxBackoff);
  }

  /**
   * Whether the server refuses, on a new connection, the identity {@code source} gives {@code
   * kms}'s new connections: one Discover Versions. False when it accepts it, or when the
   * connection fails for another reason.
   */
  private static boolean refusedOnNewConnection(Kms kms, Source source) {
    try (Connection c = open(kms, kms.protocolVersion(), kms.renewalEndpoint(), source.get())) {
      c.client.call(
          Requests.discoverVersions().build(), CallContext.withTimeout(kms.callTimeout()));
      return false;
    } catch (KmipException e) {
      return denied(e);
    } catch (IOException | RuntimeException e) {
      return false;
    }
  }

  /** A connection with {@code tls} to {@code endpoint}, with {@code kms}'s transport settings. */
  private static Connection open(
      Kms kms, ProtocolVersion version, KmsConfig.Endpoint endpoint, SSLContext tls) {
    KmsConfig config = kms.config;
    TlsTransport.Builder b =
        TlsTransport.builder(endpoint.host(), endpoint.port(), tls)
            .connectTimeout(config.connectTimeout)
            .readTimeout(Kms.readLimit(config))
            .pool(1, Duration.ofHours(1))
            .validateAfterIdle(config.validateAfterIdle);
    if (config.cipherSuites != null) b.cipherSuites(config.cipherSuites);
    else if (config.kmipCipherSuites) b.cipherSuites(Tls.kmipCipherSuites(tls));
    TlsTransport t = b.build();
    return new Connection(t, new KmipClient(t, version, RequestOptions.DEFAULT));
  }

  /**
   * When to renew again a certificate that expires at {@code notAfter}, within the automatic
   * renewal's window already: after half its remaining validity, so always before it expires;
   * zero once it has expired.
   */
  static Duration renewAgainIn(Instant now, Instant notAfter) {
    Duration half = Duration.between(now, notAfter).dividedBy(2);
    return half.isNegative() ? Duration.ZERO : half;
  }

  /**
   * The timer's keep-alive while an automatic renewal runs: the longest wait between checks or
   * after a failure, at least a second.
   */
  static Duration timerKeepAlive() {
    Duration longest = maxCheck.compareTo(maxBackoff) >= 0 ? maxCheck : maxBackoff;
    Duration floor = Duration.ofMillis(SdkThreads.IDLE_MILLIS);
    return longest.compareTo(floor) >= 0 ? longest : floor;
  }

  /** For tests: the timer's keep-alive now. */
  static Duration timerKeepAliveNow() {
    return Duration.ofNanos(SCHEDULER.getKeepAliveTime(TimeUnit.NANOSECONDS));
  }

  private static Duration shortest(Duration a, Duration b) {
    return a.compareTo(b) <= 0 ? a : b;
  }

  private static long nanos(Duration d) {
    try {
      return Math.max(0, d.toNanos());
    } catch (ArithmeticException tooLong) {
      return Long.MAX_VALUE;
    }
  }
}
