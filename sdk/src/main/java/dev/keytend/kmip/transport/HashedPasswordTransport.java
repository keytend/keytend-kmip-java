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

package dev.keytend.kmip.transport;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.client.ProtocolException;
import dev.keytend.kmip.model.*;
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

/**
 * KMIP 2.x/3.0 SHA-256 hashed-password credentials and mandatory server-proof verification.
 *
 * <p>Exchanges are serialized so that credential timestamps reach the server in increasing order;
 * a connection pool underneath therefore gains nothing. Callers wait for the exchange lock in
 * arrival order, at most until the earlier of their {@link CallContext} deadline and the
 * transport's maximum wait (60 s by default); {@link CallContext#cancel()} and interrupting the
 * thread end the wait at once. A wait that ends this way, like a call made after {@link #close()},
 * fails with a local {@link RequestNotSentException} (see {@link CallContext}). A {@link
 * RequestNotSentException} from the delegate passes through unchanged.
 * {@link #close()} does not wait for an exchange in progress: it closes the delegate at once,
 * which cancels that exchange, and the derived secrets are wiped when it ends.
 *
 * <p><b>What the server proof shows.</b> ServerHashedPassword is H(TimeStamp || S1 || H(S2)) over
 * the response header's TimeStamp. It shows that the responder knows the password-derived
 * secrets; it does not cover the response body and is not bound to this request, so TLS remains
 * the integrity and server-authentication mechanism. A proof is not checked for freshness.
 *
 * @since 0.10.0
 */
public final class HashedPasswordTransport implements KmipTransport {
  private final KmipTransport delegate;
  private final String username;
  private final byte[] s1, s2;
  private final long maxWaitNanos;

  /** One permit: the exchange lock. Also guards {@link #wiped} and the secrets. */
  private final Permits exchanges = new Permits(1);

  private long lastTimestamp;
  private volatile boolean closed;
  private boolean wiped;

  /** Tests only: runs while an exchange still holds the lock, just before it lets go. */
  volatile Runnable beforeUnlock;

  /** A transport whose callers wait at most 60 s for the exchange lock. */
  public HashedPasswordTransport(KmipTransport delegate, String username, char[] password) {
    this(delegate, username, password, Duration.ofSeconds(60));
  }

  /**
   * @param maxWait the longest a caller waits for the exchange lock when its {@link CallContext}
   *     allows longer (or has no deadline)
   */
  @SuppressWarnings("ByteBufferBackingArray") // the encoder's own heap buffer, offset 0, wiped
  public HashedPasswordTransport(
      KmipTransport delegate, String username, char[] password, Duration maxWait) {
    if (maxWait.isNegative() || maxWait.isZero())
      throw new IllegalArgumentException("Maximum wait must be positive");
    long wait;
    try {
      wait = maxWait.toNanos();
    } catch (ArithmeticException tooLong) {
      wait = Long.MAX_VALUE / 2;
    }
    this.maxWaitNanos = Math.min(wait, Long.MAX_VALUE / 2);
    this.delegate = Objects.requireNonNull(delegate);
    this.username = Objects.requireNonNull(username);
    ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
    byte[] secret = new byte[encoded.remaining()];
    encoded.get(secret);
    byte[] user = username.getBytes(StandardCharsets.UTF_8);
    try {
      s1 = hash(user, secret);
      s2 = hash(secret, user);
    } finally {
      Arrays.fill(secret, (byte) 0);
      if (encoded.hasArray()) Arrays.fill(encoded.array(), (byte) 0);
    }
  }

  @Override
  public Ttlv exchange(Ttlv request) throws IOException {
    return exchange(request, CallContext.NONE);
  }

  @Override
  public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
    Ttlv header = request.require(REQUEST_HEADER);
    if (dev.keytend.kmip.client.Messages.version(header).legacyAttributes())
      throw new IllegalArgumentException("Hashed password requires KMIP 2.0+");
    if (closed)
      throw new RequestNotSentException(
          "KMIP request not sent", new IOException("Hashed password transport closed"), true);
    try {
      exchanges.acquire(
          context,
          context.deadlineBefore(System.nanoTime() + maxWaitNanos),
          "Timed out waiting for the hashed-password exchange lock");
    } catch (IOException e) {
      // A wait that was granted the lock as it gave up has released it again.
      wipeIfClosed();
      throw new RequestNotSentException("KMIP request not sent: " + e.getMessage(), e, true);
    }
    try {
      if (closed)
        throw new RequestNotSentException(
            "KMIP request not sent", new IOException("Hashed password transport closed"), true);
      context.checkNotSent();
      return authenticated(request, header, context);
    } finally {
      unlock();
    }
  }

  /**
   * Lets go of the lock, then wipes the secrets if the transport was closed meanwhile. close()
   * wipes only when it can take the lock; when it cannot, the holder at that moment releases later
   * and then sees {@code closed} (set before close() tried the lock), so one of them always wipes.
   */
  private void unlock() {
    Runnable hook = beforeUnlock;
    if (hook != null) hook.run();
    exchanges.release();
    wipeIfClosed();
  }

  private void wipeIfClosed() {
    if (closed && exchanges.tryAcquire())
      try {
        wipe();
      } finally {
        exchanges.release();
      }
  }

  /** Tests only: whether the derived secrets have been wiped. */
  boolean wiped() {
    if (!exchanges.tryAcquire()) return false;
    try {
      return wiped;
    } finally {
      exchanges.release();
    }
  }

  private Ttlv authenticated(Ttlv request, Ttlv header, CallContext context) throws IOException {
    Instant now = Instant.now();
    long micros =
        Math.addExact(Math.multiplyExact(now.getEpochSecond(), 1_000_000L), now.getNano() / 1000);
    lastTimestamp = Math.max(micros, lastTimestamp + 1);
    byte[] timestamp = ByteBuffer.allocate(8).putLong(lastTimestamp).array(),
        first = hash(s1, timestamp),
        credentialValue = new byte[first.length + s2.length];
    System.arraycopy(first, 0, credentialValue, 0, first.length);
    System.arraycopy(s2, 0, credentialValue, first.length, s2.length);
    Ttlv credential =
        Credentials.credential(
            Enums.CredentialType.HASHED_PASSWORD,
            text(USERNAME, username),
            Ttlv.of(TIME_STAMP.code(), Ttlv.Type.DATE_TIME_EXTENDED, lastTimestamp),
            enumeration(HASHING_ALGORITHM, Enums.HashingAlgorithm.SHA_256),
            bytes(HASHED_PASSWORD, credentialValue));
    List<Ttlv> fields = new ArrayList<>(header.children());
    List<Ttlv> credentials = new ArrayList<>();
    header.child(AUTHENTICATION).ifPresent(n -> credentials.addAll(n.children()));
    credentials.add(credential);
    fields.removeIf(n -> n.tag() == AUTHENTICATION.code());
    fields.add(structure(AUTHENTICATION, credentials));
    Ttlv updated =
        Structures.canonical(
            dev.keytend.kmip.client.Messages.version(header), structure(REQUEST_HEADER, fields));
    List<Ttlv> roots = new ArrayList<>(request.children());
    roots.set(roots.indexOf(header), updated);
    try {
      Ttlv response = delegate.exchange(structure(REQUEST_MESSAGE, roots), context);
      try {
        Ttlv replyHeader = response.require(RESPONSE_HEADER);
        long replyTimestamp = replyHeader.require(TIME_STAMP).longValue();
        byte[] proof = replyHeader.require(SERVER_HASHED_PASSWORD).bytesValue();
        byte[] expected =
            hash(ByteBuffer.allocate(8).putLong(replyTimestamp).array(), s1, hash(s2));
        if (!MessageDigest.isEqual(expected, proof))
          throw new ProtocolException("Invalid server hashed-password proof", response, null);
      } catch (IllegalArgumentException | IllegalStateException e) {
        throw new ProtocolException(
            "Missing or malformed server hashed-password proof", response, e);
      }
      return response;
    } finally {
      Arrays.fill(first, (byte) 0);
      Arrays.fill(credentialValue, (byte) 0);
    }
  }

  private static byte[] hash(byte[]... values) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      for (byte[] value : values) digest.update(value);
      return digest.digest();
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  /** Called with the {@link #exchanges} permit held. */
  private void wipe() {
    if (wiped) return;
    wiped = true;
    Arrays.fill(s1, (byte) 0);
    Arrays.fill(s2, (byte) 0);
  }

  /**
   * Closes the delegate immediately, canceling an exchange in progress, without waiting for it.
   * The secrets are wiped now if no exchange is running, otherwise when it ends.
   */
  @Override
  public void close() throws IOException {
    closed = true;
    try {
      delegate.close();
    } finally {
      if (exchanges.tryAcquire())
        try {
          wipe();
        } finally {
          exchanges.release();
        }
    }
  }
}
