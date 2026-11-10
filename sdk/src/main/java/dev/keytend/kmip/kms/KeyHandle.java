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

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import javax.crypto.SecretKey;

/**
 * A managed object on the server (a key, certificate or secret), named by its identifier.
 *
 * <p>Get one with {@link KmsKeys#handle(String) kms.keys().handle(id)} for an identifier you
 * stored, {@link KmsKeys#findByName(String)} for a name, a creation builder's {@link
 * KeyCreation#findOrCreate()} or {@link KeyCreation#create()}, or {@link CurrentKey#handle()} for
 * the key that seals now.
 *
 * <pre>{@code
 * KeyHandle kek = kms.keys().findByName("invoices-kek").orElseThrow();
 * KeyState state = kek.attributes().state();    // one Get Attributes
 * KeyHandle same = kms.keys().handle(kek.id());  // sends nothing
 * }</pre>
 *
 * <p>A handle from creation, registration or a lookup by kind knows its {@link ObjectKind}. It
 * refuses an operation that kind cannot perform, such as encrypting with a certificate, with {@link
 * KeyMismatchException} before sending. A handle from {@code handle(id)} leaves that check to the
 * server, which reports the same exception.
 *
 * <p>Read-only methods ({@link #attributes()}, the {@code as...} conversions and the cryptographic
 * operations) are retried as the {@link RetryPolicy} says. Lifecycle and attribute changes are
 * never re-sent: after an {@link OutcomeUnknownException}, check the object's state before you
 * repeat one.
 *
 * <p>Handles are immutable and thread-safe. A handle holds no resources of its own: its calls go
 * through its {@link Kms}. Rotation, retirement and compromise recovery are described in <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md">Key
 * lifecycle</a>.
 *
 * <p>Two handles are equal when they name the same identifier through the same {@link Kms} or its
 * views. The views {@link #allowingCompromised()} and {@link #acceptingOriginalId} are equal to
 * their base handle, because what a view permits is not part of its identity. So do not use handles
 * as the keys of a map that grants permissions.
 *
 * @since 0.10.0
 */
public final class KeyHandle {
  private static final SecureRandom RANDOM = new SecureRandom();
  private final KmsKeys keys;
  final Kms kms;
  private final String id;
  private final ObjectKind kind;
  private final boolean compromisedAllowed;
  private final Set<String> originalIds;

  /**
   * The key's kind and usages once read (or known from its creation), shared with this handle's
   * views: the check before encrypting reads them at most once per handle. Null until then.
   */
  private final java.util.concurrent.atomic.AtomicReference<Usages> usages;

  /** What the check before encrypting needs to know of a key. */
  record Usages(ObjectKind kind, Set<KeyUsage> usages, int rawMask) {
    static Usages of(KeyAttributes a) {
      return new Usages(a.kind(), a.usages(), a.rawUsageMask());
    }
  }

  KeyHandle(KmsKeys keys, String id, ObjectKind kind) {
    this(keys, id, kind, false, Set.of(), new java.util.concurrent.atomic.AtomicReference<>());
  }

  private KeyHandle(
      KmsKeys keys,
      String id,
      ObjectKind kind,
      boolean compromisedAllowed,
      Set<String> originalIds,
      java.util.concurrent.atomic.AtomicReference<Usages> usages) {
    this.keys = keys;
    this.kms = keys.kms();
    this.id = id;
    this.kind = kind;
    this.compromisedAllowed = compromisedAllowed;
    this.originalIds = Set.copyOf(originalIds);
    this.usages = usages;
  }

  /** This handle, knowing its key's kind and usages from {@code a} (read for another reason). */
  KeyHandle knowing(KeyAttributes a) {
    if (a.id().equals(id)) usages.compareAndSet(null, Usages.of(a));
    return this;
  }

  /** This handle, knowing that its key was created as a symmetric key with {@code requested}. */
  KeyHandle knowing(Set<KeyUsage> requested) {
    usages.compareAndSet(
        null,
        new Usages(ObjectKind.SYMMETRIC_KEY, Set.copyOf(requested), KeyUsage.mask(requested)));
    return this;
  }

  /**
   * The object's Unique Identifier on its server.
   *
   * @return the identifier
   */
  public String id() {
    return id;
  }

  /**
   * The object's kind when this handle knows it without asking the server.
   *
   * @return the kind; empty when this handle has not read it
   */
  public Optional<ObjectKind> knownKind() {
    return Optional.ofNullable(kind);
  }

  /**
   * This object, also willing to be read ({@code as...}), decrypt, unwrap and verify while
   * Compromised: for forensic recovery or re-encryption after a compromise.
   *
   * <p>Without this view those operations refuse a Compromised object with {@link
   * StateConflictException}. A Destroyed object is always refused, and so is one whose State the
   * server does not report or reports as an unknown value ({@link ProtocolViolationException}). The
   * view covers this object only. A ciphertext that names another Compromised key of the lineage is
   * still refused. Use that key's own view, taken from a source you trust, such as {@link
   * #compromisedPredecessors()} of its replacement. The view is equal to this handle.
   *
   * <p>Never build the view from an identifier read out of the data. Anyone who can create keys can
   * seal a record under their own key and revoke it. Use the identifier only to choose among keys
   * you already trust.
   *
   * @return a view of this object; this handle is unchanged
   */
  public KeyHandle allowingCompromised() {
    return new KeyHandle(keys, id, kind, true, originalIds, usages);
  }

  /**
   * This key, also decrypting and unwrapping ciphertexts that name {@code originalId}: the
   * identifier the same key material had on another server before it was migrated here.
   *
   * <p>Ciphertexts bind the identifier they were made with into their authenticated header. With
   * this view the Decrypt goes to this key and the header still binds the original identifier, so
   * nothing needs re-encrypting. Name only identifiers this key really replaces: a ciphertext
   * naming one is accepted as this key's own. Call it again to add more identifiers.
   *
   * <p>The view belongs to the key that holds the migrated material. After that key is rotated,
   * decrypt such ciphertexts with {@code kms.keys().handle(migratedId).acceptingOriginalId(oldId)},
   * not with the replacement, whose material differs.
   *
   * @param originalId the identifier on the other server
   * @return a view of this key; this handle is unchanged
   * @throws IllegalArgumentException when {@code originalId} is empty
   */
  public KeyHandle acceptingOriginalId(String originalId) {
    Objects.requireNonNull(originalId, "originalId");
    if (originalId.isEmpty()) throw new IllegalArgumentException("Empty key identifier");
    Set<String> ids = new HashSet<>(originalIds);
    ids.add(originalId);
    return new KeyHandle(keys, id, kind, compromisedAllowed, ids, usages);
  }

  /**
   * All attributes, read with Get Attributes.
   *
   * @return the attributes, a snapshot
   */
  public KeyAttributes attributes() {
    Request request = Requests.getAttributes().uniqueIdentifier(id).build();
    return kms.execute("attributes", Kms.Kind.READ, id, s -> readAttributes(s.call(request)));
  }

  static KeyAttributes readAttributes(Result result) throws ProtocolException {
    try {
      return AttributeReader.read(result.requirePayload());
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new ProtocolException("Malformed Get Attributes response", result.batchItem(), null);
    }
  }

  // ---- retrieval ----

  private <T> T get(String operation, Enums.KeyFormatType format, Kms.GetReader<T> reader) {
    Request.Builder builder = Requests.get().uniqueIdentifier(id);
    if (format != null) builder.add(enumeration(KEY_FORMAT_TYPE, format));
    Request request = builder.build();
    return kms.execute(
        operation,
        Kms.Kind.READ,
        id,
        s -> {
          Result result = s.call(request);
          Ttlv payload;
          try {
            payload = result.requirePayload();
          } catch (IllegalStateException e) {
            throw new ProtocolException("Get response has no payload", result.batchItem(), null);
          }
          return reader.read(payload);
        });
  }

  /**
   * Refuses to read a Destroyed object, or a Compromised one unless this handle is {@link
   * #allowingCompromised()} (one Get Attributes before the Get). An object whose State the server
   * does not report, or reports as a value this SDK does not know, is refused too ({@link
   * #knownState}).
   */
  private KeyAttributes requireReadable(String operation) {
    return requireReadable(operation, attributes());
  }

  /** {@link #requireReadable(String)} on attributes {@code a} of this key, already read. */
  private KeyAttributes requireReadable(String operation, KeyAttributes a) {
    KeyState state = knownState(operation, id, a);
    boolean destroyed = state == KeyState.DESTROYED || state == KeyState.DESTROYED_COMPROMISED;
    if (destroyed || (state == KeyState.COMPROMISED && !compromisedAllowed))
      throw new StateConflictException(
              operation
                  + ": "
                  + id
                  + " is "
                  + state
                  + (destroyed
                      ? ""
                      : "; use handle.allowingCompromised()."
                          + operation
                          + "(...) to read it anyway"),
              null,
              operation,
              id,
              null,
              null)
          .observed(state);
    return a;
  }

  /**
   * Refuses to hand out a key for {@code use} (attributes {@code a}, already {@link
   * #requireReadable readable}) when its state or usages do not allow it: once its value has left
   * the server, nothing checks them again.
   */
  private void requireFor(String operation, KeyAttributes a, LocalUse use) {
    KeyState state = a.state();
    if (!use.states().contains(state))
      throw new StateConflictException(
              operation
                  + ": "
                  + id
                  + " is "
                  + state
                  + ", so it is not handed out to "
                  + use
                  + (use.protecting()
                      ? " (only an Active key protects new data: find the current key, for example"
                          + " kms.keys().findByName(name), or CurrentKey)"
                      : state == KeyState.PRE_ACTIVE
                          ? " (a Pre-Active key has protected nothing yet)"
                          : ""),
              null,
              operation,
              id,
              null,
              null)
          .observed(state);
    if (!a.usages().contains(use.usage()))
      throw new KeyMismatchException(
          operation
              + ": "
              + id
              + " does not permit "
              + use.usage()
              + " (its usages are "
              + a.usages()
              + (a.rawUsageMask() == 0 ? ", or the server did not state them" : "")
              + "), so it is not handed out to "
              + use,
          null,
          operation,
          id,
          null,
          null);
  }

  /**
   * The symmetric key as a JCA key, for one stated use. {@link DestroyableSecretKey#destroy()}
   * wipes the copy. Nothing on the server checks the key once its value has left it, so it is
   * handed out only when its state and usages allow {@code use}:
   *
   * <ul>
   *   <li>{@link LocalUse#ENCRYPT} (and {@link LocalUse#WRAP}): Active, with the Encrypt (Wrap Key)
   *       usage. Take this key from a name lookup or {@link CurrentKey}.
   *   <li>{@link LocalUse#DECRYPT} (and {@link LocalUse#UNWRAP}): Active or Deactivated, with the
   *       Decrypt (Unwrap Key) usage; Compromised only through {@link #allowingCompromised()}. Take
   *       this key from the identifier stored with the data, never from a name lookup.
   * </ul>
   *
   * <p>When the key states a Lease Time (any value, zero too), an Obtain Lease is sent first. Under
   * the default {@link LeasePolicy#REQUIRE}, the value is read only once the server grants it.
   * Under {@link LeasePolicy#HONOR_IF_SUPPORTED}, a server confirmed not to implement Obtain Lease
   * lets a positive stated Lease Time stand in for the grant, as a local bound. Use the copy within
   * that lease or bound: the SDK cannot recall it.
   *
   * <pre>{@code
   * KeyHandle kek = kms.keys().findByName("invoices-kek").orElseThrow();
   * DestroyableSecretKey dek = kek.asSecretKey(Expect.aes(), LocalUse.ENCRYPT);
   * // store kek.id() with what dek encrypts; later, storedId is that identifier:
   * KeyHandle stored = kms.keys().handle(storedId);
   * DestroyableSecretKey old = stored.asSecretKey(Expect.aes(), LocalUse.DECRYPT);
   * }</pre>
   *
   * <p><b>Advanced.</b> A one-shot copy for immediate use. Raw keys that a database keeps, even for
   * a few seconds, go through {@link LocalKeys}. It checks a key's state and scope when it loads or
   * revalidates the key, and hands out a copy only while its TTL and lease run. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/local-keys.md#keys-taken-out-of-the-kms">Keys
   * taken out of the KMS</a>.
   *
   * @param expect what the key must be; not null
   * @param use what the caller will do with it; not null
   * @return a new key, owned by the caller, who destroys it
   * @throws StateConflictException when its state does not allow {@code use}, it is Destroyed, or
   *     the server refused the lease of a key that is not Active ({@link
   *     StateConflictException#observedState()} is the state)
   * @throws KeyMismatchException when its usages lack what {@code use} needs (also when the server
   *     states none), or it is not an unwrapped key of the expected algorithm and size
   * @throws PermissionDeniedException when the server refuses to release it, for example {@link
   *     KmsReason#NOT_EXTRACTABLE}
   * @throws KmsException when the lease of an Active key is refused or cannot be obtained ({@code
   *     operation()} is {@code obtainLease}); no value is read without a lease, or the local bound
   *     of {@link LeasePolicy#HONOR_IF_SUPPORTED}
   * @since 0.10.0
   */
  public DestroyableSecretKey asSecretKey(Expect expect, LocalUse use) {
    return asSecretKey(expect, use, null);
  }

  /**
   * Checks an SDK-owned raw-key cache's obligations (its lease among them) on the loader's own
   * attributes, before Get; null for the caller's one-shot read, whose lease is obtained here.
   */
  DestroyableSecretKey asSecretKey(
      Expect expect, LocalUse use, java.util.function.Consumer<KeyAttributes> checked) {
    return asSecretKey(expect, use, null, checked);
  }

  /**
   * As {@link #asSecretKey(Expect, LocalUse, java.util.function.Consumer)}, with this key's
   * attributes already read by the cache's own validation ({@code read}; null: read them here). The
   * same checks run on them, and no second Get Attributes is sent; the cache's {@code checked}
   * confirms they name this key.
   */
  DestroyableSecretKey asSecretKey(
      Expect expect,
      LocalUse use,
      KeyAttributes read,
      java.util.function.Consumer<KeyAttributes> checked) {
    Objects.requireNonNull(expect, "expect");
    Objects.requireNonNull(use, "use");
    requireKind("asSecretKey", ObjectKind.SYMMETRIC_KEY);
    return kms.call(
        "asSecretKey",
        () -> {
          KeyAttributes attributes =
              read != null ? requireReadable("asSecretKey", read) : requireReadable("asSecretKey");
          if (checked != null) checked.accept(attributes);
          requireFor("asSecretKey", attributes, use);
          long lease = checked != null ? Long.MAX_VALUE : lease("asSecretKey", attributes);
          return leased(
              "asSecretKey",
              lease,
              get("asSecretKey", null, payload -> KeyReader.secretKey(payload, id, expect)));
        });
  }

  /**
   * The lease a one-shot read of key material obtains before its Get: when the attributes
   * just read state a Lease Time (any value, zero and a malformed one too: KMIP 1.4 §3.20, 2.1
   * §4.30), one Obtain Lease. A grant of zero is no limit (1.4 §4.17, 2.1 §6.1.35), a positive one
   * is held to a positive stated maximum. The server's refusal is thrown ({@link Leases#refused})
   * and nothing is read; another failure is thrown as it is, since no lease was granted.
   *
   * @return the {@link System#nanoTime()} at which the lease ends, timed from before the request
   *     was sent; {@link Long#MAX_VALUE} when there is no limit, or no lease is needed
   */
  private long lease(String operation, KeyAttributes attributes) {
    Duration stated = attributes.leaseToObtain();
    if (stated == null) return Long.MAX_VALUE;
    Request request = Requests.obtainLease().uniqueIdentifier(id).build();
    long sent = System.nanoTime();
    long seconds;
    try {
      seconds =
          kms.execute("obtainLease", Kms.Kind.READ, id, s -> Leases.granted(s.call(request), id));
    } catch (KmsException f) {
      // A server that does not implement Obtain Lease, under LeasePolicy.HONOR_IF_SUPPORTED.
      seconds = Leases.unsupportedBound(kms, f, id, stated);
      if (seconds < 0 && !Leases.refusal(f)) throw f;
      if (seconds < 0) throw Leases.refused(kms, f, id, operation, attributes.state());
    }
    if (seconds == 0) return Long.MAX_VALUE;
    long granted = java.util.concurrent.TimeUnit.SECONDS.toNanos(seconds),
        maximum = stated.toNanos();
    return sent + (maximum > 0 ? Math.min(granted, maximum) : granted);
  }

  /** {@code material}, read under a lease ending at {@code end}; destroyed and refused when it has ended. */
  private <T> T leased(String operation, long end, T material) {
    if (end == Long.MAX_VALUE || System.nanoTime() - end < 0) return material;
    if (material instanceof javax.security.auth.Destroyable d)
      try {
        d.destroy();
      } catch (javax.security.auth.DestroyFailedException ignored) {
        // A JDK private key cannot be wiped; it is dropped.
      }
    throw new TransientException(
        operation
            + ": the lease of "
            + id
            + " ended before its value arrived; nothing is handed out",
        null,
        operation,
        id,
        null,
        null);
  }

  /**
   * The public key (RSA or EC) as a JCA key. Its kind, algorithm and size are checked against
   * {@code expect}, and a Destroyed key, or a Compromised one without {@link
   * #allowingCompromised()}, is refused. Public data is not leased.
   *
   * @param expect what the key must be
   * @return the public key
   */
  public PublicKey asPublicKey(Expect expect) {
    Objects.requireNonNull(expect, "expect");
    requireKind("asPublicKey", ObjectKind.PUBLIC_KEY);
    return kms.call(
        "asPublicKey",
        () -> {
          requireReadable("asPublicKey");
          return publicKey(expect);
        });
  }

  private PublicKey publicKey(Expect expect) {
    Kms.GetReader<PublicKey> reader =
        payload ->
            dev.keytend.kmip.model.Keys.publicKey(
                payload, id, KeyReader.declared(payload, PUBLIC_KEY, expect), expect.bits());
    try {
      return get("asPublicKey", null, reader);
    } catch (KeyMismatchException e) {
      // The server's default format may be one this SDK cannot convert (some servers use their own
      // "Raw" layout); ask once for X.509 SubjectPublicKeyInfo, which servers convert to.
      if (!(e.getCause() instanceof java.security.spec.InvalidKeySpecException)) throw e;
      return get("asPublicKey", Enums.KeyFormatType.X_509, reader);
    }
  }

  /**
   * The private key (RSA or EC) as a JCA key. Its kind, algorithm and size are checked against
   * {@code expect}. A Destroyed key is refused, and so is a Compromised one without {@link
   * #allowingCompromised()}. Its state and usages are not checked against a purpose. A key that
   * states a Lease Time is read under a lease, as for {@link #asSecretKey(Expect, LocalUse)}.
   *
   * <p><b>Advanced.</b> A one-shot copy for immediate use: the SDK cannot recall it, and a JDK
   * private key cannot be wiped, so drop the reference as soon as you can. Nodes present their TLS
   * private keys through the followers of {@link Kms#tls()}. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">the
   * advanced alternatives</a>.
   *
   * @param expect what the key must be
   * @return the private key, owned by the caller
   */
  public PrivateKey asPrivateKey(Expect expect) {
    return asPrivateKey(expect, null);
  }

  /**
   * Lets an SDK-owned cache check the loader's attributes (its lease among them) before the private
   * key leaves the server; null for the caller's one-shot read, whose lease is obtained here.
   */
  PrivateKey asPrivateKey(Expect expect, java.util.function.Consumer<KeyAttributes> checked) {
    Objects.requireNonNull(expect, "expect");
    requireKind("asPrivateKey", ObjectKind.PRIVATE_KEY);
    return kms.call(
        "asPrivateKey",
        () -> {
          KeyAttributes attributes = requireReadable("asPrivateKey");
          if (checked != null) checked.accept(attributes);
          long lease = checked != null ? Long.MAX_VALUE : lease("asPrivateKey", attributes);
          return leased(
              "asPrivateKey",
              lease,
              get(
                  "asPrivateKey",
                  null,
                  payload ->
                      dev.keytend.kmip.model.Keys.privateKey(
                          payload,
                          id,
                          KeyReader.declared(payload, PRIVATE_KEY, expect),
                          expect.bits())));
        });
  }

  /**
   * The certificate. Its encoding and identity are checked, not its trust: validate the chain with
   * PKIX before you rely on it.
   *
   * <p><b>Advanced.</b> For tooling that reads certificates. Nodes present and check TLS material
   * through the followers of {@link Kms#tls()}. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">the
   * advanced alternatives</a>.
   *
   * @return the certificate
   * @throws StateConflictException when the certificate is Destroyed, or Compromised and this
   *     handle is not {@link #allowingCompromised()}
   */
  public X509Certificate asCertificate() {
    requireKind("asCertificate", ObjectKind.CERTIFICATE);
    return kms.call(
        "asCertificate",
        () -> {
          requireReadable("asCertificate");
          return get("asCertificate", null, payload -> ObjectViews.certificate(payload, id));
        });
  }

  /**
   * The Secret Data (a password or other secret), in a holder whose {@link SecretData#destroy()}
   * wipes its copy. A secret that states a Lease Time is read under a lease, as {@link
   * #asSecretKey(Expect, LocalUse)} describes.
   *
   * @return a new holder, owned by the caller, who destroys it
   * @throws KeyMismatchException when the object is not Secret Data or is wrapped
   * @throws StateConflictException when it is Destroyed, or Compromised and this handle is not
   *     {@link #allowingCompromised()}
   */
  public SecretData asSecretData() {
    requireKind("asSecretData", ObjectKind.SECRET_DATA);
    return kms.call(
        "asSecretData",
        () -> {
          long lease = lease("asSecretData", requireReadable("asSecretData"));
          return leased(
              "asSecretData",
              lease,
              get("asSecretData", null, payload -> KeyReader.secretData(payload, id)));
        });
  }

  // ---- lifecycle ----

  /**
   * Activates the object (Pre-Active to Active). One request, and a Get Attributes when the server
   * refuses it.
   *
   * <p>An object that is not Pre-Active is refused with a {@link StateConflictException} naming its
   * state, on every KMIP version. The usual cause is another caller that activated it first: check
   * {@link #attributes()} and go on if it is Active. Only refusals that may be about the state are
   * read back (Permission Denied, Illegal Operation, Wrong Key Lifecycle State). A refusal of this
   * client's credentials, such as Not Authorised or a refused TLS handshake, stays a {@link
   * PermissionDeniedException}.
   *
   * @throws StateConflictException when the object is not Pre-Active
   * @throws PermissionDeniedException when the server refuses to activate a Pre-Active object
   */
  public void activate() {
    Request request = Requests.activate().uniqueIdentifier(id).build();
    kms.run(
        "activate",
        () -> {
          try {
            kms.execute("activate", Kms.Kind.MUTATION, id, s -> s.call(request));
          } catch (PermissionDeniedException | StateConflictException e) {
            // Only a refusal that may be about the state is read back (an authentication failure is
            // not).
            if (e instanceof AlreadyExistsException || !Failures.lifecycleAmbiguous(e)) throw e;
            KeyState state;
            try {
              state = attributes().state();
            } catch (KmsException | IllegalStateException unreadable) {
              e.addSuppressed(unreadable);
              throw e;
            }
            if (state == KeyState.PRE_ACTIVE || state == KeyState.UNKNOWN) throw e;
            throw new StateConflictException(
                    "activate: "
                        + id
                        + " is "
                        + state
                        + ", not Pre-Active, so the server refused it"
                        + (state == KeyState.ACTIVE ? " (another caller activated it first)" : ""),
                    e,
                    "activate",
                    id,
                    e.result().orElse(null),
                    null)
                .observed(state);
          }
        });
  }

  /**
   * Rotates this symmetric key with KMIP Re-key, and returns the replacement, Active.
   *
   * <p>The server makes a key with new material and the same attributes, and links the two ({@link
   * KeyAttributes#replacementLink()}, {@link KeyAttributes#replacedLink()}). The old key keeps decrypting
   * what it encrypted, and stays as the server left it, usually Active: {@link #rotate(Rotation)}
   * with a grace period schedules its deactivation. Servers differ in which key keeps the name, so
   * find the current key with {@link #latest()} or {@link KmsKeys#findByName(String)}. The Re-key
   * copies the old key's Deactivation and Protect Stop Dates, so a date a server policy set on the
   * old key applies to the replacement too; {@link RotationDates#SHIFTED} sends an Offset instead.
   * Four requests, and an Activate when the server leaves the replacement Pre-Active. Key pairs are
   * not rotated here: send Re-key Key Pair through {@link Kms#protocol()}.
   *
   * <p><b>Refusals.</b> A Compromised or Deactivated key is refused before the Re-key: recover a
   * Compromised key with {@link #replaceCompromised}. A key that was already replaced is not
   * rotated again, so a repeat after an {@link OutcomeUnknownException} cannot fork the lineage.
   *
   * <p><b>A single-actor job.</b> Rotate a key from one place, such as one scheduled job. Callers
   * that rotate the same key at the same moment may each get a replacement, leaving several newest
   * keys. Every record still opens. Join them with {@link #reconcile()} before you retire old
   * keys. A server that refuses the second Re-key makes the losing call a
   * {@link StateConflictException} that names the winner. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#several-instances">Several
   * instances</a>.
   *
   * <p><b>Advanced.</b> For a rotation that is not on a schedule. A scheduled job calls {@link
   * #rotateIfActiveFor(Duration)} or {@link CurrentKey#rotateIfActiveFor(Duration)}.
   *
   * @return the replacement key, Active
   * @throws KeyMismatchException when the object is not a symmetric key; no Re-key is sent
   * @throws StateConflictException when this key was already replaced or another caller replaced
   *     it meanwhile, so the server refused the Re-key ({@link
   *     StateConflictException.Conflict#REPLACED}); or when it is Compromised or Deactivated (only
   *     a Get Attributes was sent), or the server refused the Re-key because of its state ({@link
   *     StateConflictException.Conflict#STATE})
   * @throws PartialCompletionException when the replacement was made but a later step failed:
   *     activating it, reading the keys, a replacement neither Pre-Active nor Active, or one that
   *     does not keep this key's Extractable false or Sensitive true ({@link
   *     Rotation#extractable(boolean)}). The message says what to do with {@link
   *     PartialCompletionException#created()}, which is never to destroy it. When the Re-key's
   *     reply was lost and the replacement was found by reading back, it is in {@link
   *     PartialCompletionException#found()} instead, with the lost Re-key as {@link
   *     PartialCompletionException#recoveredFrom()}: this call or another caller made it
   */
  public KeyHandle rotate() {
    return rotate(Rotation.of(RotationDates.COPIED));
  }

  /**
   * {@link #rotate()} with the replacement's dates and the old key's grace period that {@code
   * rotation} gives.
   *
   * <p>{@link RotationDates#SHIFTED} sends the Re-key with an Offset of 0, so a key under a
   * cryptoperiod policy gets its cryptoperiod from now. {@link RotationDates#COPIED}, the default,
   * sends none. A server that does not support an Offset refuses the Re-key. With a {@link
   * Rotation#grace(Duration) grace period}, this key's Deactivation Date is set after the Re-key to
   * now plus the grace period, unless it has an earlier one. That costs one Get Attributes and one
   * Add or Modify Attribute more, and a lost reply on that step is read back.
   *
   * <pre>{@code
   * KeyHandle kek = kms.keys().findByName("invoices-kek").orElseThrow();
   * KeyHandle current = kek.rotate(Rotation.grace(Duration.ofDays(7)));
   * // kek still encrypts for 7 days, then only decrypts; current encrypts from now on
   * }</pre>
   *
   * <p><b>Advanced.</b> As {@link #rotate()}.
   *
   * @param rotation how to rotate
   * @return the replacement key, Active
   * @throws PartialCompletionException when the rotation was made but scheduling this key's
   *     deactivation failed or was refused: {@link PartialCompletionException#created()} holds the
   *     replacement ({@link PartialCompletionException#found()} when it was found after a lost
   *     reply), this key stays Active, and the message says what to do instead
   * @throws KmsException as {@link #rotate()}
   * @see <a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#rotation-with-a-grace-period">Rotation
   *     with a grace period</a>
   */
  public KeyHandle rotate(Rotation rotation) {
    Objects.requireNonNull(rotation, "rotation");
    // The call ends after returned(), which throws a grace period that was not scheduled.
    return kms.call("rotate", () -> rotated(false, rotation).returned());
  }

  /**
   * The outcome of a rotation with a {@link Rotation}: the key considered ({@code previous}), the
   * key returned, whether this call's Re-key made it ({@code made}) or a replacement was found after
   * its outcome was unknown ({@code recovered}, that Re-key's failure; null otherwise), the
   * Deactivation Date the grace period set or kept on {@code previous} (null when nothing was
   * scheduled), and the failure to schedule it (null when there was none).
   */
  record Rotated(
      KeyHandle previous,
      KeyHandle key,
      boolean made,
      OutcomeUnknownException recovered,
      Instant deactivation,
      PartialCompletionException graceNotScheduled) {
    KeyHandle returned() {
      if (graceNotScheduled != null) throw graceNotScheduled;
      return key;
    }

    RotationResult result() {
      returned();
      RotationResult.Outcome outcome =
          recovered != null
              ? RotationResult.Outcome.RECOVERED
              : made
                  ? RotationResult.Outcome.ROTATED
                  : key.id().equals(previous.id())
                      ? RotationResult.Outcome.NOT_DUE
                      : RotationResult.Outcome.FOLLOWED;
      return new RotationResult(outcome, previous, key, deactivation, recovered);
    }
  }

  /**
   * {@link #rotate(boolean, boolean, ReKeyTrace, boolean, Protection)} of this key as {@code
   * rotation} says, in the call of the public method that returns or throws its outcome ({@link
   * Rotated#returned()}): a call that ended here would report a grace period that was not
   * scheduled as SUCCEEDED.
   */
  Rotated rotated(boolean orLatest, Rotation rotation) {
    rotation
        .protection()
        .require(kms.protocolVersion(), Kms.named(orLatest ? "rotateOrLatest" : "rotate"));
    ReKeyTrace trace = new ReKeyTrace();
    KeyHandle key =
        rotate(
            orLatest,
            true,
            trace,
            rotation.rotationDates() == RotationDates.SHIFTED,
            rotation.protection());
    boolean made = trace.reKeyed && trace.lost == null;
    OutcomeUnknownException recovered = trace.lost;
    Duration grace = rotation.gracePeriod().orElse(null);
    if (grace == null || key.id().equals(id))
      return new Rotated(this, key, made, recovered, null, null);
    Grace scheduled = graceDeactivation(grace, key, made, trace.lost);
    return new Rotated(this, key, made, recovered, scheduled.date(), scheduled.failed());
  }

  /**
   * What {@link #rotate(boolean, boolean, ReKeyTrace, boolean, Protection)} learned, for its
   * callers.
   */
  static final class ReKeyTrace {
    /** The {@link KmsListener#concurrentReplacement listener} was told of another caller's key. */
    boolean told;

    /** The key returned is the replacement a Re-key gave: this call's, or found after {@link #lost}. */
    boolean reKeyed;

    /**
     * The Re-key whose outcome was unknown, when reading back found the replacement: this call or
     * another caller made it. Null when the reply named it.
     */
    OutcomeUnknownException lost;

    /**
     * Whether, after a lost reply, a compromise replacement goes on with a replacement it finds,
     * which this call or another caller made: false for a plan-bound call, which cannot prove that
     * key its own ({@link #appeared}).
     */
    boolean adopts = true;

    /**
     * The replacements a lost Re-key's read-back found when {@link #adopts} is false: the call
     * stopped with the unknown outcome instead of going on with one; or null.
     */
    List<KeyAttributes> appeared;
  }

  /**
   * Rotates this key ({@link #rotate()}), or returns the key {@link #latest()} chooses when this
   * key was already replaced.
   *
   * <p>"Already replaced" covers a key that names a replacement, and a Re-key the server refused
   * because another caller replaced the key meanwhile. So a second call from the same handle
   * returns the first call's replacement instead of failing or forking the lineage. This call does
   * not decide whether a rotation is due: a job that looks the key up by name at each firing
   * rotates it each time. {@link #rotateIfActiveFor(Duration)} decides that.
   *
   * <p>Newest keys descending from this key that are still Pre-Active are activated first, as their
   * creator would next. No other key is changed. The cost is that of {@link #rotate()}, or of the
   * walk of {@link #latest()} (one Get Attributes per key) when the key was already replaced.
   *
   * <p><b>Advanced.</b> For a rotation that is not on a schedule. A scheduled job calls {@link
   * #rotateIfActiveFor(Duration)} or {@link CurrentKey#rotateIfActiveFor(Duration)}.
   *
   * @return this call's replacement, or the current key of the lineage, Active
   * @throws StateConflictException when this key, not replaced, is Compromised or Deactivated
   *     (nothing is sent but the Get Attributes), when the current key is not Active afterwards, or
   *     as {@link #rotate()}
   * @throws KmsException as {@link #rotate()} and {@link #latest()}
   * @see #rotateOrLatest(Rotation)
   */
  public KeyHandle rotateOrLatest() {
    return rotateOrLatest(Rotation.of(RotationDates.COPIED));
  }

  /**
   * {@link #rotateOrLatest()} as {@code rotation} says (see {@link #rotate(Rotation)}).
   *
   * <p>With a grace period, this key's deactivation is scheduled also when it was replaced already.
   * So repeating the call from this key's handle finishes a grace period that an earlier call did
   * not schedule. A key whose Deactivation Date comes sooner keeps it.
   *
   * <p><b>Advanced.</b> As {@link #rotateOrLatest()}.
   *
   * @param rotation how to rotate
   * @return this call's replacement, or the current key of the lineage, Active
   * @throws PartialCompletionException as {@link #rotate(Rotation)}; {@link
   *     PartialCompletionException#created()} is empty when this call made no replacement
   * @throws KmsException as {@link #rotateOrLatest()}
   * @see <a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#rotation-with-a-grace-period">Rotation
   *     with a grace period</a>
   */
  public KeyHandle rotateOrLatest(Rotation rotation) {
    Objects.requireNonNull(rotation, "rotation");
    return kms.call("rotateOrLatest", () -> rotated(true, rotation).returned());
  }

  /**
   * Rotates the current key of this key's lineage when it has been Active for at least {@code
   * period}, and otherwise returns it unchanged. This is the call for a scheduled rotation job.
   *
   * <pre>{@code
   * // in one scheduled job, run daily: rotates once the current key is 30 days old
   * KeyHandle kek = kms.keys().findByName("invoices-kek").orElseThrow();
   * KeyHandle current = kek.rotateIfActiveFor(Duration.ofDays(30));
   * }</pre>
   *
   * <p>Run it from one scheduled job; the other instances follow the new key through {@link
   * CurrentKey}. A repeated firing of that job finds the new key, too new to rotate, and returns
   * it. That holds for a firing that looks the key up again by name, one that holds an old handle,
   * and one repeated after an {@link OutcomeUnknownException}.
   *
   * <p>The current key is this key, or, when this key was replaced, the key {@link
   * #rotateOrLatest()} would return without rotating. Its age is measured from the later of its
   * Activation Date and Initial Date, by this machine's clock. Both are read because a Re-key
   * copies the old key's Activation Date to the replacement. Clock skew with the server shifts the
   * due time by as much. A current key that is not Active is handed to {@link #rotateOrLatest()}
   * whatever the period, so a Compromised or Deactivated one is refused: recover a Compromised key
   * with {@link #replaceCompromised}. One Get Attributes when this key is current and not due.
   *
   * @param period how long the current key must have been Active to be rotated; {@link
   *     Duration#ZERO} always rotates
   * @return the replacement this call made, or the current key; Active
   * @throws IllegalArgumentException when {@code period} is negative
   * @throws ProtocolViolationException when the current key is Active and the server reported
   *     neither its Activation Date nor its Initial Date (nothing is sent but the reads)
   * @throws KmsException as {@link #rotateOrLatest()}
   * @see #rotateIfActiveFor(Duration, Rotation)
   * @see <a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#rotate-on-a-schedule">Rotate
   *     on a schedule</a>
   */
  public KeyHandle rotateIfActiveFor(Duration period) {
    return rotateIfActiveFor(period, Rotation.of(RotationDates.COPIED));
  }

  /**
   * {@link #rotateIfActiveFor(Duration)} as {@code rotation} says (see {@link #rotate(Rotation)}).
   * When it rotates, the key it rotated gets its deactivation scheduled after the grace period.
   * When it does not rotate, nothing is scheduled.
   *
   * <pre>{@code
   * // in one scheduled job, run daily; kek is a KeyHandle of the lineage
   * // a new key every 30 days; each old key stops encrypting 7 days after it was replaced
   * kek.rotateIfActiveFor(Duration.ofDays(30), Rotation.grace(Duration.ofDays(7)));
   * }</pre>
   *
   * <p>Choose a grace period longer than the check interval of the instances' {@link CurrentKey},
   * so that each moves to the new key before the old one stops encrypting. One that has not moved
   * does so on its first refused seal.
   *
   * <p>On a server whose policy gives keys a Deactivation Date (a cryptoperiod), rotate with {@link
   * RotationDates#SHIFTED} dates and a {@code period} shorter than the cryptoperiod. Each key is
   * then replaced before its Deactivation Date, since a current key past it is Deactivated and
   * refused. The due time is the same as with {@link RotationDates#COPIED}: {@code period} after
   * the key was made.
   *
   * <pre>{@code
   * // the server's policy deactivates keys 90 days after activation
   * kek.rotateIfActiveFor(Duration.ofDays(60), Rotation.of(RotationDates.SHIFTED));
   * }</pre>
   *
   * @param period how long the current key may be Active before it is due
   * @param rotation how to rotate
   * @return the replacement this call made, or the current key; Active
   * @throws PartialCompletionException as {@link #rotate(Rotation)}
   * @throws KmsException as {@link #rotateIfActiveFor(Duration)} and {@link #rotate(Rotation)}
   * @see <a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#rotation-with-a-grace-period">Rotation
   *     with a grace period</a>
   */
  public KeyHandle rotateIfActiveFor(Duration period, Rotation rotation) {
    return kms.call(
        "rotateIfActiveFor", () -> rotatedIfActiveFor(period, rotation, null).returned());
  }

  /**
   * {@link #rotateIfActiveFor(Duration, Rotation)}, with the outcome of a grace period; refused
   * when {@code expected} (may be null: any) is not the lineage's current key.
   */
  Rotated rotatedIfActiveFor(Duration period, Rotation rotation, KeyHandle expected) {
    Objects.requireNonNull(period, "period");
    Objects.requireNonNull(rotation, "rotation");
    if (period.isNegative())
      throw new IllegalArgumentException("period must not be negative: " + period);
    if (expected != null && !expected.sameKms(kms))
      throw new IllegalArgumentException(
          "rotateIfActiveFor: expectedCurrent ("
              + expected.id
              + ") is a handle of another Kms; an identifier names an object only on its own"
              + " server");
    // Refused whether or not a rotation is due, before anything is sent.
    rotation.protection().require(kms.protocolVersion(), "rotateIfActiveFor");
    requireKind("rotateIfActiveFor", ObjectKind.SYMMETRIC_KEY);
    KeyAttributes a = attributes();
    if (a.kind() != ObjectKind.SYMMETRIC_KEY)
      throw new KeyMismatchException(
          "rotateIfActiveFor: " + id + " is a " + a.kind() + "; only symmetric keys are rotated",
          null,
          "rotateIfActiveFor",
          id,
          null,
          null);
    KeyAttributes current =
        Lineage.existingReplacements("rotate", a, keys::read).isEmpty() ? a : currentKey(a, null);
    if (expected != null && !current.id().equals(expected.id))
      throw new StateConflictException(
              "rotateIfActiveFor: the current key of the lineage is "
                  + current.id()
                  + ", not "
                  + expected.id
                  + " as expected (another caller rotated it meanwhile); nothing was changed:"
                  + " decide again from "
                  + current.id(),
              null,
              "rotateIfActiveFor",
              current.id(),
              null,
              null)
          .because(StateConflictException.Conflict.NOT_AS_PLANNED);
    // Zero is always due, also when the server's clock is ahead of this machine's.
    if (!period.isZero() && current.state() == KeyState.ACTIVE && !activeFor(current, period)) {
      KeyHandle due = handleOf(current);
      return new Rotated(due, due, false, null, null, null);
    }
    return handleOf(current).rotated(true, rotation);
  }

  /**
   * {@link #rotateIfActiveFor(Duration, Rotation)}, saying what it did: rotated the lineage's
   * current key, found it not due, or followed the replacement another caller made meanwhile. Same
   * requests, refusals and failures. A scheduled job logs or counts the outcome:
   *
   * <pre>{@code
   * RotationResult r = kek.rotateIfActiveForResult(Duration.ofDays(30), Rotation.grace(Duration.ofDays(7)));
   * if (r.outcome() == RotationResult.Outcome.ROTATED)
   *   log.info("rotated {} to {}", r.previous().id(), r.current().id());
   * }</pre>
   *
   * <p>After a person approved rotating one key, use {@link #rotateIfActiveForResult(Duration,
   * Rotation, KeyHandle)}, which refuses instead of following another caller's rotation.
   *
   * @param period how long the current key may be Active before it is due
   * @param rotation how to rotate
   * @return what the call did; {@link RotationResult#current()} is what {@link
   *     #rotateIfActiveFor(Duration, Rotation)} returns
   * @throws PartialCompletionException as {@link #rotate(Rotation)}
   * @throws KmsException as {@link #rotateIfActiveFor(Duration, Rotation)}
   * @since 0.10.0
   */
  public RotationResult rotateIfActiveForResult(Duration period, Rotation rotation) {
    return kms.call("rotateIfActiveFor", () -> rotatedIfActiveFor(period, rotation, null).result());
  }

  /**
   * {@link #rotateIfActiveForResult(Duration, Rotation)} that acts only on {@code
   * expectedCurrent}: when the lineage's current key is another key, it refuses instead of
   * following it. Use it after a person approved rotating that key, or scheduling its
   * deactivation:
   *
   * <pre>{@code
   * KeyHandle current = kms.keys().findByName("invoices-kek").orElseThrow();
   * // show current and the grace period, and ask for approval, then:
   * RotationResult r = current.rotateIfActiveForResult(Duration.ofDays(30), Rotation.grace(week), current);
   * }</pre>
   *
   * <p>The check is made once, before the Re-key. A rotation by another caller after it is
   * followed as {@link RotationResult.Outcome#FOLLOWED}, and the grace period is then scheduled on
   * {@code expectedCurrent}, the key approved.
   *
   * @param period how long the current key may be Active before it is due
   * @param rotation how to rotate
   * @param expectedCurrent the key that must be the lineage's current key, a handle of the same
   *     {@link Kms}
   * @return what the call did
   * @throws IllegalArgumentException when {@code expectedCurrent} is a handle of another {@link
   *     Kms}
   * @throws StateConflictException ({@link StateConflictException.Conflict#NOT_AS_PLANNED}) when
   *     the lineage's current key is not {@code expectedCurrent},
   *     also when it would not be due; nothing is sent but reads
   * @throws KmsException as {@link #rotateIfActiveForResult(Duration, Rotation)}
   * @since 0.10.0
   */
  public RotationResult rotateIfActiveForResult(
      Duration period, Rotation rotation, KeyHandle expectedCurrent) {
    Objects.requireNonNull(expectedCurrent, "expectedCurrent");
    return kms.call(
        "rotateIfActiveFor", () -> rotatedIfActiveFor(period, rotation, expectedCurrent).result());
  }

  /**
   * {@link #rotate(Rotation)}, saying what it did: {@link RotationResult.Outcome#ROTATED}, or
   * {@link RotationResult.Outcome#RECOVERED} when the Re-key's outcome was unknown and a
   * replacement was found by reading back. Same requests, refusals and failures. {@link
   * RotationResult#previousDeactivationDate()} gives the date the grace period set, without
   * another read.
   *
   * @param rotation how to rotate
   * @return what the call did; {@link RotationResult#previous()} is this key
   * @throws KmsException as {@link #rotate(Rotation)}
   * @since 0.10.0
   */
  public RotationResult rotateResult(Rotation rotation) {
    Objects.requireNonNull(rotation, "rotation");
    return kms.call("rotate", () -> rotated(false, rotation).result());
  }

  /**
   * {@link #rotateOrLatest(Rotation)}, saying what it did: {@link RotationResult.Outcome#ROTATED},
   * {@link RotationResult.Outcome#RECOVERED}, or {@link RotationResult.Outcome#FOLLOWED} when this
   * key had been replaced already. Same requests, refusals and failures.
   *
   * @param rotation how to rotate
   * @return what the call did; {@link RotationResult#previous()} is this key
   * @throws KmsException as {@link #rotateOrLatest(Rotation)}
   * @since 0.10.0
   */
  public RotationResult rotateOrLatestResult(Rotation rotation) {
    Objects.requireNonNull(rotation, "rotation");
    return kms.call("rotateOrLatest", () -> rotated(true, rotation).result());
  }

  /**
   * Sets this key's Deactivation Date to {@code at}, unless it has one that comes no later, and
   * returns the date in effect. From then the key no longer encrypts, wraps, signs or computes
   * MACs, and still decrypts, unwraps and verifies where the server's policy allows. Use it to stop
   * a key at a date without rotating it, such as at the end of a key switch.
   *
   * <pre>{@code
   * Instant date = key.deactivateAt(Instant.parse("2026-12-01T00:00:00Z"));
   * }</pre>
   *
   * <p>{@code at} is rounded up to a whole second. A date is never postponed: a key whose
   * Deactivation Date is no later than {@code at} keeps it, nothing is sent but the read, and that
   * date is returned. Otherwise one Get Attributes and an Add Attribute, or a Modify Attribute when
   * the key has a date, on every KMIP version. A reply that is lost, or a refusal that may be about
   * the key's state, is read back: a date no later than {@code at} counts as done.
   *
   * <p>A date is written only on an Active or Pre-Active key; a key in another state whose date
   * is no later than {@code at} returns it, as above. On a Pre-Active key the date applies once the
   * key is Active: KMIP has no transition from Pre-Active to Deactivated, and a date that passes first is
   * handled as the server decides. KMIP has no compare-and-set, so a date another client sets
   * between the read and the write can be replaced: change a key's lifecycle from one place at a
   * time. {@link Rotation#grace(Duration)} schedules a rotated key's deactivation this way.
   *
   * @param at when the key is to be deactivated; not before now
   * @return the Deactivation Date in effect: {@code at} rounded up, or the earlier date the key had
   * @throws IllegalArgumentException when {@code at} is before now; nothing is sent
   * @throws UnsupportedException when the server does not let clients set the Deactivation Date
   *     (Attribute Read Only, from KMIP 2.0); deactivate the key with {@link
   *     #deactivate(RevocationReason)} at that time instead. A KMIP 1.x server answers Permission
   *     Denied, a {@link PermissionDeniedException}
   * @throws StateConflictException when the key is neither Active nor Pre-Active and has no
   *     Deactivation Date at or before {@code at}, with its {@link
   *     StateConflictException#observedState() state}
   * @throws OutcomeUnknownException when the reply was lost and the key does not read back with the
   *     date
   * @since 0.10.0
   */
  public Instant deactivateAt(Instant at) {
    Objects.requireNonNull(at, "at");
    if (at.isBefore(kms.now()))
      throw new IllegalArgumentException(
          "deactivateAt: "
              + at
              + " is in the past; deactivate the key now with deactivate(reason) instead");
    return kms.call(
        "deactivateAt",
        () -> {
          return deactivationDate("deactivateAt", wholeSecond(at), true, new KeyState[1]);
        });
  }

  /** {@code at}, rounded up to a whole second. */
  private static Instant wholeSecond(Instant at) {
    Instant whole = at.truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
    return whole.isBefore(at) ? whole.plusSeconds(1) : whole;
  }

  /**
   * Sets this key's Deactivation Date to {@code date} (whole seconds), unless it has one no later:
   * {@link #deactivateAt}. Returns the date in effect. A key that is neither Active nor Pre-Active
   * is a {@link StateConflictException} with {@code refuse}, and null without. {@code seen[0]} is
   * set to the key's state each time it is read.
   */
  private Instant deactivationDate(
      String operation, Instant date, boolean refuse, KeyState[] seen) {
    KeyAttributes a = attributes();
    seen[0] = a.state();
    Optional<Instant> existing = a.deactivationDate();
    if (existing.isPresent() && !existing.get().isAfter(date)) return existing.get();
    if (a.state() != KeyState.ACTIVE && a.state() != KeyState.PRE_ACTIVE)
      return notSchedulable(operation, a.state(), null, refuse);
    Ttlv attribute = Attributes.attribute("Deactivation Date", dateTime(DEACTIVATION_DATE, date));
    Request request =
        (existing.isPresent() ? Requests.modifyAttribute() : Requests.addAttribute())
            .uniqueIdentifier(id)
            .attribute(attribute)
            .build();
    try {
      kms.execute(operation, Kms.Kind.MUTATION, id, s -> s.call(request));
      return date;
    } catch (KmsException e) {
      Enums.ResultReason reason = e.protocolReason().orElse(null);
      if (reason == Enums.ResultReason.ATTRIBUTE_READ_ONLY
          || reason == Enums.ResultReason.READ_ONLY_ATTRIBUTE)
        throw new UnsupportedException(
            Kms.named(operation)
                + ": the server does not let clients set the Deactivation Date of "
                + id
                + " ("
                + e.getMessage()
                + "); deactivate it at that time instead",
            e,
            Kms.named(operation),
            id,
            e.result().orElse(null),
            null);
      boolean unknown = e instanceof OutcomeUnknownException;
      boolean readBack =
          unknown
              || e instanceof InvalidRequestException
              || (!(e instanceof AlreadyExistsException) && Failures.lifecycleAmbiguous(e));
      if (!readBack || Failures.credentialsRefused(e)) throw e;
      KeyAttributes now;
      try {
        now = attributes();
      } catch (KmsException | IllegalStateException unreadable) {
        e.addSuppressed(unreadable);
        throw e;
      }
      seen[0] = now.state();
      Optional<Instant> set = now.deactivationDate();
      if (set.isPresent() && !set.get().isAfter(date)) return set.get();
      if (now.state() != KeyState.ACTIVE && now.state() != KeyState.PRE_ACTIVE)
        return notSchedulable(operation, now.state(), e, refuse);
      throw e;
    }
  }

  /** The refusal of a Deactivation Date for a key in {@code state}; null when not {@code refuse}. */
  private Instant notSchedulable(
      String operation, KeyState state, KmsException cause, boolean refuse) {
    if (!refuse) return null;
    throw new StateConflictException(
            Kms.named(operation)
                + ": "
                + id
                + " is "
                + state
                + ", not Active or Pre-Active, so its Deactivation Date is not set",
            cause,
            Kms.named(operation),
            id,
            cause == null ? null : cause.result().orElse(null),
            null)
        .observed(state);
  }

  /** The Deactivation Date a grace period set or kept (null: none), or the failure to schedule it. */
  private record Grace(Instant date, PartialCompletionException failed) {}

  /**
   * Schedules this key's deactivation {@code grace} from now, after a rotation of it that returned
   * {@code current} ({@code made}: by this call's Re-key; {@code lost}: found after that Re-key's
   * outcome was unknown, so this call or another caller made it): {@link #deactivationDate} at now plus
   * {@code grace}, rounded up to a whole second, after the Re-key so that the replacement does not
   * copy it. Nothing is sent when this key is no longer Active or Pre-Active, or when its
   * Deactivation Date comes no later. On failure, the {@link PartialCompletionException} that tells
   * the caller the rotation was made, this key is still Active, and what to do.
   */
  private Grace graceDeactivation(
      Duration grace, KeyHandle current, boolean made, OutcomeUnknownException lost) {
    String operation = Kms.named("rotate");
    Instant date;
    try {
      date = wholeSecond(kms.now().plus(grace));
    } catch (java.time.DateTimeException | ArithmeticException never) {
      return new Grace(null, null); // beyond any date: never deactivated, as without a grace
    }
    KeyState[] seen = {KeyState.ACTIVE};
    try {
      return new Grace(deactivationDate(operation, date, false, seen), null);
    } catch (KmsException | IllegalStateException failed) {
      KeyState state = seen[0] == KeyState.PRE_ACTIVE ? KeyState.PRE_ACTIVE : KeyState.ACTIVE;
      boolean refused =
          failed instanceof KmsException k
              && !(k instanceof OutcomeUnknownException)
              && (k instanceof PermissionDeniedException
                  || k instanceof InvalidRequestException
                  || k instanceof UnsupportedException
                  || k instanceof StateConflictException)
              && !Failures.credentialsRefused(k);
      String step =
          "scheduling the deactivation of "
              + id
              + " at "
              + date
              + " (a grace period of "
              + written(grace)
              + ") failed";
      String advice =
          current.id()
              + " is the current key, Active, and "
              + id
              + " stays "
              + (state == KeyState.PRE_ACTIVE ? "Pre-Active" : "Active")
              + (refused
                  ? ": the server did not let this client set "
                      + id
                      + "'s Deactivation Date, so run"
                      + " deactivatePredecessors() from "
                      + current.id()
                      + " once the grace period is over instead"
                      + " (operating-keys.md, \"Rotation with a grace period\")"
                  : ": repeat rotateOrLatest(rotation) from "
                      + id
                      + "'s handle to schedule it (it does not rotate"
                      + " "
                      + id
                      + " again), or run deactivatePredecessors() from "
                      + current.id()
                      + " once the grace"
                      + " period is over");
      return new Grace(
          null,
          made
              ? PartialCompletionException.of(
                  operation, List.of(current), null, step, advice, failed)
              : lost != null
                  ? PartialCompletionException.found(
                      operation, List.of(current), lost, step, advice, failed)
                  : PartialCompletionException.interrupted(operation, step, advice, failed));
    }
  }

  /** {@code d} as a person writes it: {@code 7d}, {@code 36h}, {@code 90m} or {@code 45s}; else ISO. */
  static String written(Duration d) {
    if (d.isZero()) return "0s";
    if (d.toNanosPart() == 0 && !d.isNegative()) {
      long s = d.toSeconds();
      if (s % 86_400 == 0) return s / 86_400 + "d";
      if (s % 3_600 == 0) return s / 3_600 + "h";
      if (s % 60 == 0) return s / 60 + "m";
      return s + "s";
    }
    return d.toString();
  }

  /**
   * Whether {@code key} has been Active for {@code period} by this machine's clock, from the later
   * of its Activation and Initial Dates: a Re-key copies the Activation Date (see {@link
   * #rotateIfActiveFor}).
   */
  private boolean activeFor(KeyAttributes key, Duration period) {
    Optional<Instant> activated = key.activationDate(), created = key.creationDate();
    if (activated.isEmpty() && created.isEmpty())
      throw new ProtocolViolationException(
          "rotateIfActiveFor: the server reported neither an Activation Date nor an Initial Date for "
              + key.id()
              + ", so how long it has been Active cannot be told (KMIP requires an Initial Date on every object);"
              + " nothing was rotated",
          null,
          "rotateIfActiveFor",
          key.id(),
          null,
          null);
    Instant since =
        activated.isEmpty()
            ? created.get()
            : created.isEmpty() || activated.get().isAfter(created.get())
                ? activated.get()
                : created.get();
    // Not Duration.between(...).compareTo(period): it overflows for dates far apart.
    try {
      return !since.plus(period).isAfter(kms.now());
    } catch (java.time.DateTimeException | ArithmeticException farFuture) {
      return false;
    }
  }

  /**
   * {@link #rotate()}, or with {@code orLatest} {@link #rotateOrLatest()}; {@code trace} says
   * whether the {@link KmsListener#concurrentReplacement listener} was told of another caller's
   * replacement (a refused Re-key), so a caller does not tell it again, and whether the key
   * returned is the Re-key's replacement, made by this call or found after its reply was lost.
   * After a lost reply, a later failure lists the replacement as {@link
   * PartialCompletionException#found()}, never as created. {@code routine} is false
   * only for {@link #replaceCompromised}, which re-keys a Compromised key on purpose. With {@code
   * shifted} the Re-key carries an Offset of 0: the server activates the replacement now and moves
   * the old key's other dates by as much as its Activation Date moved (KMIP 1.4 §4.4).
   */
  private KeyHandle rotate(
      boolean orLatest, boolean routine, ReKeyTrace trace, boolean shifted, Protection asked) {
    requireKind("rotate", ObjectKind.SYMMETRIC_KEY);
    return kms.call(
        orLatest ? "rotateOrLatest" : "rotate",
        () -> {
          KeyAttributes current = attributes();
          // A handle that does not know its kind: the same refusal on every version, before the
          // Re-key.
          if (current.kind() != ObjectKind.SYMMETRIC_KEY)
            throw new KeyMismatchException(
                "rotate: " + id + " is a " + current.kind() + "; only symmetric keys are rotated",
                null,
                "rotate",
                id,
                null,
                null);
          // Replacements that were destroyed and purged do not count: they cannot be followed.
          List<String> already = Lineage.existingReplacements("rotate", current, keys::read);
          if (!already.isEmpty() && orLatest) return current(current, null);
          if (!already.isEmpty())
            throw new StateConflictException(
                    "rotate: "
                        + id
                        + " was already replaced by "
                        + String.join(", ", already)
                        + "; use latest() to find the current key, and rotate that",
                    null,
                    "rotate",
                    id,
                    null,
                    null)
                .because(StateConflictException.Conflict.REPLACED);
          if (routine) refuseRetired(current, shifted);
          Request.Builder reKey = Requests.reKey().uniqueIdentifier(id);
          if (shifted) reKey.add(interval(OFFSET, 0));
          // Only what the caller asked: otherwise KMIP's Re-key copies the old key's protection,
          // which
          // is
          // checked below.
          if (asked.any()) reKey.template(asked.attributes().toArray(Ttlv[]::new));
          Request request = reKey.build();
          String replacement;
          try {
            replacement =
                kms.execute(
                    "rotate", Kms.Kind.MUTATION, id, s -> KmsKeys.identifier(s.call(request)));
          } catch (OutcomeUnknownException unknown) {
            replacement = routine ? reKeyedAfterAll(unknown) : reKeyedInstead(unknown, trace);
            // This Re-key or another caller's: which one made it cannot be told.
            trace.lost = unknown;
          } catch (PermissionDeniedException | StateConflictException refused) {
            if (refused instanceof AlreadyExistsException || !Failures.lifecycleAmbiguous(refused))
              throw refused;
            List<KeyAttributes> read = refusedReKey(refused);
            trace.told = true;
            if (orLatest) return current(read.get(0), refused);
            List<String> winners =
                read.subList(1, read.size()).stream().map(KeyAttributes::id).toList();
            throw new StateConflictException(
                    Kms.named("rotate")
                        + ": "
                        + id
                        + " was replaced meanwhile by "
                        + String.join(", ", winners)
                        + " (another caller rotated it at the same moment, and the server refused a second Re-key);"
                        + " use latest() to find the current key",
                    refused,
                    Kms.named("rotate"),
                    id,
                    refused.result().orElse(null),
                    null)
                .because(StateConflictException.Conflict.REPLACED);
          }
          KeyHandle created = new KeyHandle(keys, replacement, ObjectKind.SYMMETRIC_KEY);
          KeyAttributes mine, old;
          try {
            mine = created.attributes();
            old = attributes();
          } catch (KmsException | IllegalStateException e) {
            throw afterReKey(
                trace,
                created,
                "reading the keys failed",
                "do not rotate "
                    + id
                    + " again (it was replaced): check "
                    + replacement
                    + " with attributes(),"
                    + " activate it if it is Pre-Active, and use it",
                e);
          }
          // Re-key replies carry only an identifier: it must name a symmetric key that replaced
          // this
          // one, confirmed by both keys, before anything is activated or returned (as for
          // Register).
          created.knowing(mine);
          if (mine.kind() != ObjectKind.SYMMETRIC_KEY || !Lineage.replaced(mine, old))
            throw new OutcomeUnknownException(
                "rotate: the server's reply names "
                    + replacement
                    + ", which is "
                    + (mine.kind() != ObjectKind.SYMMETRIC_KEY
                        ? "a " + mine.kind()
                        : "not linked to " + id + " as its replacement")
                    + "; the rotation may have taken effect under another identifier",
                null,
                "rotate",
                id,
                null,
                null);
          // Never weakened by a rotation: the replacement states what was asked, or else keeps
          // this key's Extractable false and Sensitive true, which KMIP's Re-key copies. A server
          // that
          // drops them would hand out the replacement's value; it is not activated or returned.
          KeyMismatchException weaker =
              KmsKeys.unprotected(Kms.named("rotate"), replacement, mine, asked.keeping(old));
          if (weaker != null)
            throw afterReKey(
                trace,
                created,
                "the replacement does not keep the protection "
                    + (asked.any() ? "asked" : "of " + id),
                "do not use "
                    + replacement
                    + " ("
                    + mine.state()
                    + "): the server may release its value, and it has "
                    + id
                    + "'s names now (a Re-key moves them), so lookups by name find it; set its Extractable and"
                    + " Sensitive by hand where the server allows it, or, if its value may have left the server,"
                    + " replace it with replaceCompromised; do not rotate "
                    + id
                    + " again (it was replaced)",
                weaker);
          // Returned Active: a Pre-Active replacement is activated (it is this call's own key), and
          // one
          // in any other state (a server or another client revoked it already) is reported rather
          // than
          // handed out for use. Another caller's replacement of this key is never touched.
          KeyState state = mine.state();
          // (Inside replaceCompromised, its advice: repeating it resumes.)
          if (state == KeyState.PRE_ACTIVE && trace.lost == null)
            keys.activateCreated(Kms.named("rotate"), List.of(created));
          else if (state == KeyState.PRE_ACTIVE)
            keys.activateFound(Kms.named("rotate"), created, trace.lost);
          else if (state != KeyState.ACTIVE) {
            RuntimeException why;
            try {
              knownState("rotate", replacement, mine);
              why =
                  new StateConflictException(
                          "rotate: the replacement "
                              + replacement
                              + " is "
                              + state
                              + ", not Active",
                          null,
                          "rotate",
                          replacement,
                          null,
                          null)
                      .observed(state);
            } catch (ProtocolViolationException unknown) {
              why = unknown;
            }
            throw afterReKey(
                trace,
                created,
                "the replacement was not usable",
                "do not encrypt with "
                    + replacement
                    + ", and do not rotate "
                    + id
                    + " again (it was replaced):"
                    + " replace it in turn (replaceCompromised when it is Compromised; a new key when it is Deactivated,"
                    + (shifted
                        ? " since the server did not move "
                            + id
                            + "'s Deactivation Date for the Offset sent;"
                        : " since a Re-key copies " + id + "'s Deactivation Date;")
                    + " rotate otherwise); check its state with attributes()",
                why);
          }
          reportConcurrent("rotate", old);
          trace.reKeyed = true;
          return created;
        });
  }

  /**
   * A failure after the Re-key that gave {@code replacement}: a {@link PartialCompletionException}
   * that lists it as created when the Re-key's reply named it, or as {@link
   * PartialCompletionException#found()} with the lost Re-key when it was found by reading back.
   */
  private static PartialCompletionException afterReKey(
      ReKeyTrace trace, KeyHandle replacement, String step, String advice, RuntimeException cause) {
    String operation = Kms.named("rotate");
    return trace.lost == null
        ? PartialCompletionException.of(operation, List.of(replacement), null, step, advice, cause)
        : PartialCompletionException.found(
            operation, List.of(replacement), trace.lost, step, advice, cause);
  }

  /**
   * A routine rotation sends no Re-key for a Compromised or Deactivated key. KMIP lets
   * a server re-key either. A Compromised key's replacement would be Active, and the instance would
   * move on to it without the compromise being handled: its records are not re-sealed, and nothing
   * is told. A Deactivated key's replacement gets the copied Deactivation Date, which has passed, so
   * it is Deactivated too (on a server that follows KMIP); with {@code shifted} (an Offset of 0) the
   * server moves that date forward instead, so the message says what the Offset would do.
   * Other states are left to the server.
   */
  private void refuseRetired(KeyAttributes current, boolean shifted) {
    String operation = Kms.named("rotate");
    KeyState state = current.state();
    if (state == KeyState.COMPROMISED)
      throw new StateConflictException(
              operation
                  + ": "
                  + id
                  + " is COMPROMISED, so it is not rotated as routine (its records would stay"
                  + " under it, unreadable, with nothing to say so): recover it with replaceCompromised(reason),"
                  + " then re-seal its records (operating-keys.md, \"A compromised key\")",
              null,
              operation,
              id,
              null,
              null)
          .observed(KeyState.COMPROMISED);
    if (state == KeyState.DEACTIVATED)
      throw new StateConflictException(
              operation
                  + ": "
                  + id
                  + " is DEACTIVATED and names no replacement, so it is not rotated ("
                  + (shifted
                      ? "a routine rotation replaces an Active key; the Offset RotationDates.SHIFTED sends would move "
                          + id
                          + "'s Deactivation Date forward, and the replacement would be Active only as long as "
                          + id
                          + " was, from now"
                      : "a Re-key copies its Deactivation Date, so the replacement would be Deactivated too")
                  + "): when its lineage has"
                  + " another current key (a branch reconcile superseded), use latest() to find it, and rotate that;"
                  + " otherwise create a new key (records under "
                  + id
                  + " still open through its handle)",
              null,
              operation,
              id,
              null,
              null)
          .observed(KeyState.DEACTIVATED);
  }

  /**
   * The server refused this key's Re-key: this key is read again. When it has confirmed
   * replacements now (another caller re-keyed it since this call's check), the listener hears of
   * them, and the result is the key as read, then those replacements. Otherwise a Permission Denied for a key that names
   * replacements none of which is confirmed (destroyed and purged, unreadable, or not naming it
   * back: a server that refuses a second Re-key goes by the link), or for a key whose state forbids
   * a Re-key, is STATE; any other refusal is rethrown unchanged (also when the key cannot be read).
   * Only a refusal that may be about the key's state ({@link Failures#lifecycleAmbiguous}) gets here.
   */
  private List<KeyAttributes> refusedReKey(KmsException refused) {
    String operation = Kms.named("rotate");
    KeyAttributes now;
    List<KeyAttributes> winners;
    try {
      now = attributes();
      winners = Lineage.replacements("rotate", now, keys::read);
    } catch (KmsException | IllegalStateException unreadable) {
      refused.addSuppressed(unreadable);
      throw refused;
    }
    if (!winners.isEmpty()) {
      kms.concurrentReplacement(id, winners.stream().map(KeyAttributes::id).toList());
      List<KeyAttributes> read = new ArrayList<>(List.of(now));
      read.addAll(winners);
      return read;
    }
    if (!(refused instanceof PermissionDeniedException)) throw refused;
    List<String> named = now.links(LinkKind.REPLACEMENT).stream().distinct().toList();
    if (!named.isEmpty())
      throw new StateConflictException(
              operation
                  + ": "
                  + id
                  + " names "
                  + String.join(", ", named)
                  + " as its replacement, which cannot be"
                  + " followed (destroyed and purged, not readable with these credentials, or not naming "
                  + id
                  + " back), and the server refused to re-key it again: find the current key by name (findByName),"
                  + " or use a handle on the key you know is current",
              refused,
              operation,
              id,
              refused.result().orElse(null),
              null)
          .because(StateConflictException.Conflict.LINEAGE);
    KeyState state = now.state();
    if (state != KeyState.ACTIVE && state != KeyState.PRE_ACTIVE && state != KeyState.UNKNOWN)
      throw new StateConflictException(
              operation
                  + ": "
                  + id
                  + " is "
                  + state
                  + ", so the server refused to re-key it"
                  + (state == KeyState.COMPROMISED ? ": replace it with replaceCompromised()" : ""),
              refused,
              operation,
              id,
              refused.result().orElse(null),
              null)
          .observed(state);
    throw refused;
  }

  /**
   * {@link #rotateOrLatest()} when this key ({@code start}, as read) was replaced already: the key
   * {@link #latest()} chooses, Active, after activating the Pre-Active newest keys that descend from
   * this key (and only those). {@code refused} is the server's refusal of this call's Re-key, if there
   * was one, kept on a failure.
   */
  private KeyHandle current(KeyAttributes start, KmsException refused) {
    return handleOf(currentKey(start, refused));
  }

  /** {@link #current}'s key, as read. */
  private KeyAttributes currentKey(KeyAttributes start, KmsException refused) {
    String operation = Kms.named("rotateOrLatest");
    try {
      Lineage.Tree tree = Lineage.tree(operation, start, true, null, keys::read);
      List<KeyAttributes> tips = tree.tips();
      List<KeyAttributes> mine =
          tips.stream()
              .filter(
                  t ->
                      t.state() == KeyState.PRE_ACTIVE
                          && !t.id().equals(id)
                          && tree.descends(t.id(), id))
              .toList();
      if (!mine.isEmpty()) {
        Map<String, KeyAttributes> activated = new HashMap<>();
        for (KeyAttributes k : activated(mine)) activated.put(k.id(), k);
        tips =
            tips.stream().map(t -> activated.getOrDefault(t.id(), t)).sorted(Lineage.TIPS).toList();
      }
      KeyAttributes a = tips.get(0);
      if (a.state() == KeyState.ACTIVE) return a;
      KeyState state = knownState(operation, a.id(), a);
      throw new StateConflictException(
              operation
                  + ": "
                  + id
                  + " was replaced already, and the current key "
                  + a.id()
                  + " is "
                  + state
                  + (state == KeyState.COMPROMISED
                      ? ": replace it with replaceCompromised()"
                      : ", not Active"),
              refused,
              operation,
              a.id(),
              null,
              null)
          .observed(state);
    } catch (KmsException | IllegalStateException e) {
      if (refused != null && e.getCause() != refused) e.addSuppressed(refused);
      throw e;
    }
  }

  /** A handle on {@code a}'s key that knows {@code a}: this one when it is this key. */
  KeyHandle handleOf(KeyAttributes a) {
    return a.id().equals(id) ? knowing(a) : new KeyHandle(keys, a.id(), kind).knowing(a);
  }

  /**
   * The Re-key's reply was lost: this key is read back. When it has a replacement now (it had
   * none before the Re-key), the Re-key took effect, or another caller's did at the same moment;
   * either is a valid replacement, so the Pre-Active ones are activated (a replacement left
   * Pre-Active would keep the names a server's Re-key gave it from every lookup of Active keys) and
   * the one {@link #latest()} would choose among them is the call's result. When it has none, or
   * cannot be read, the outcome stays unknown ({@link #replacementsAfterLost}).
   */
  private String reKeyedAfterAll(OutcomeUnknownException unknown) {
    return activated(replacementsAfterLost(unknown)).stream().min(Lineage.TIPS).orElseThrow().id();
  }

  /**
   * {@link #reKeyedAfterAll} for a compromise replacement, which acts on one replacement only:
   * the one it would finish with ({@link #FINISHED_FIRST}), activated later if Pre-Active, and no
   * other. A plan-bound call ({@code trace.adopts} false) goes on with none: this call's Re-key or
   * another caller's made them, which cannot be told, so it records them in {@code
   * trace.appeared} and throws {@code unknown}.
   */
  private String reKeyedInstead(OutcomeUnknownException unknown, ReKeyTrace trace) {
    List<KeyAttributes> made = replacementsAfterLost(unknown);
    if (!trace.adopts) {
      trace.appeared = made;
      throw unknown;
    }
    return made.stream().min(FINISHED_FIRST).orElseThrow().id();
  }

  /**
   * This key's replacements, read back after its Re-key's reply was lost ({@code unknown}): not
   * empty. When it has none, or cannot be read, an {@link OutcomeUnknownException} that says so.
   */
  private List<KeyAttributes> replacementsAfterLost(OutcomeUnknownException unknown) {
    String operation = Kms.named("rotate");
    String repeat =
        " repeat "
            + operation
            + "() ("
            + (operation.equals("rotate")
                ? "it refuses this key if the Re-key took effect; then use latest())"
                : "it uses the replacement if the Re-key took effect)");
    List<KeyAttributes> made;
    try {
      made = Lineage.replacements("rotate", attributes(), keys::read);
    } catch (KmsException | IllegalStateException e) {
      OutcomeUnknownException still =
          new OutcomeUnknownException(
              operation
                  + ": the reply of the Re-key of "
                  + id
                  + " was lost ("
                  + unknown.getMessage()
                  + "), and "
                  + id
                  + " could not be read back:"
                  + repeat,
              unknown,
              operation,
              id,
              null,
              null);
      still.addSuppressed(e);
      throw still;
    }
    if (made.isEmpty())
      throw new OutcomeUnknownException(
          operation
              + ": the reply of the Re-key of "
              + id
              + " was lost, and "
              + id
              + " shows no replacement:"
              + repeat,
          unknown,
          operation,
          id,
          null,
          null);
    return made;
  }

  /**
   * {@code keys} as they are after activating the Pre-Active ones: replacements of the key a call
   * was asked to replace, made by it or by another caller at the same moment (activating one is the
   * step its creator takes next, and leaves nothing stranded). A failed activation leaves the
   * key as it was read.
   */
  private List<KeyAttributes> activated(List<KeyAttributes> keys) {
    List<KeyAttributes> out = new ArrayList<>();
    for (KeyAttributes k : keys) {
      if (k.state() != KeyState.PRE_ACTIVE) {
        out.add(k);
        continue;
      }
      KeyHandle h = new KeyHandle(this.keys, k.id(), ObjectKind.SYMMETRIC_KEY);
      try {
        h.activate();
      } catch (KmsException | IllegalStateException e) {
        // Not when the server refused this client's credentials.
        if (e instanceof KmsException refused && Failures.credentialsRefused(refused))
          throw refused;
        // Activated by its creator meanwhile, or not activatable: as read again below.
      }
      try {
        out.add(this.keys.read(k.id()).orElse(k));
      } catch (KmsException | IllegalStateException unreadable) {
        out.add(k);
      }
    }
    return out;
  }

  /**
   * Tells the {@link KmsListener#concurrentReplacement listener} when {@code old} (as read after
   * this call's replacement was made) has more than one confirmed replacement: other callers
   * replaced it at the same time. Reads the replacements only then; failures are passed over.
   */
  private void reportConcurrent(String operation, KeyAttributes old) {
    if (old.links(LinkKind.REPLACEMENT).stream().distinct().count() < 2) return;
    try {
      List<KeyAttributes> all = Lineage.replacements(operation, old, keys::read);
      if (all.size() > 1)
        kms.concurrentReplacement(old.id(), all.stream().map(KeyAttributes::id).toList());
    } catch (KmsException | IllegalStateException unreadable) {
      // Only a notice: the replacement is made either way.
    }
  }

  /**
   * The current key of this key's rotation lineage: its newest key, which is this key when it was
   * never rotated.
   *
   * <p>The lineage is every key reached from this one through Replacement Object and Replaced
   * Object links, each step confirmed by both keys' links, within 64 rotations either way (see
   * {@link #lineage()}). One Get Attributes per key. Callers that rotated one key at the same time
   * leave several newest keys. Then the one chosen is, in order: Active, holding a name, created
   * first (Initial Date, then the lowest identifier). Every caller that sees the same keys chooses
   * the same one, and {@link KmsKeys#findByName(String)} chooses the same among the Active keys
   * with a name. {@link #reconcile()} leaves one.
   *
   * <p>A replacement that cannot be resolved (destroyed and purged, unreadable with these
   * credentials, or an invalid reply) is passed over when another replacement of that key is
   * confirmed. When none is, this is a {@link StateConflictException} that names the link: find the
   * current key by name. Purging a key in the middle of a chain has that effect. A key that is no
   * longer Active or Pre-Active, and whose replacements are all gone or destroyed, is passed over
   * when another newest key remains.
   *
   * @return the current key of the lineage; this handle when it is the current key
   * @throws StateConflictException when a key's replacements cannot be resolved and none is
   *     confirmed
   * @throws ProtocolViolationException when a key names replacements that exist and none names it
   *     back (and none is unresolved), the links form a cycle, or the walk reads more than 256 keys
   * @throws UnsupportedException when the lineage continues more than 64 rotations on
   */
  public KeyHandle latest() {
    return handleOf(newest());
  }

  /** The attributes, as read, of the key {@link #latest()} returns. */
  KeyAttributes newest() {
    return walk().newest();
  }

  /** What {@link #newest()} read: this key's attributes and the newest key's, from one walk. */
  record Walk(KeyAttributes own, KeyAttributes newest) {}

  /** {@link #newest()}, with this key's own attributes as the walk read them (no other request). */
  Walk walk() {
    return kms.call(
        "latest",
        () -> {
          KeyAttributes own = attributes();
          return new Walk(own, Lineage.tree("latest", own, true, null, keys::read).chosen());
        });
  }

  /**
   * Whether this key is the key {@link #latest()} returns.
   *
   * <p>False at once (one Get Attributes) when this key names a replacement. Otherwise the lineage
   * is read as for {@link #latest()}, and the result is false when another newest key is chosen.
   * False also when the replacement it names was destroyed and purged since: {@link #latest()} may
   * then fail, so find the current key by name. Tells the {@link KmsListener#staleHandle listener}
   * when false.
   *
   * <p>A handle kept while another instance rotates the key goes on encrypting under the old key,
   * without an error, while the server keeps it Active. Poll this now and then, or seal through a
   * {@link CurrentKey}, which follows the newest key:
   *
   * <pre>{@code
   * if (!kek.isLatest()) kek = kek.latest();
   * }</pre>
   *
   * @return whether this key is the current key of its lineage
   * @throws KmsException as {@link #latest()} when the lineage must be read and cannot be
   */
  public boolean isLatest() {
    return kms.call(
        "isLatest",
        () -> {
          KeyAttributes a = attributes();
          knowing(a);
          kms.stale(a);
          if (!a.links(LinkKind.REPLACEMENT).isEmpty()) return false;
          KeyAttributes chosen = Lineage.tree("isLatest", a, true, null, keys::read).chosen();
          if (chosen.id().equals(id)) return true;
          kms.stale(id, List.of(chosen.id()));
          return false;
        });
  }

  /**
   * The Compromised keys this key descends from, nearest first, each as an {@link
   * #allowingCompromised()} view. These are the keys whose records a compromise recovery re-seals
   * under this key.
   *
   * <p>Call it on the replacement that {@link #replaceCompromised} or {@code
   * .replacingCompromised().findOrCreate()} returned. It works also in a process that never held the
   * revoked key's handle:
   *
   * <pre>{@code
   * // current: the replacement; store: your record store
   * Map<String, KeyHandle> compromised = new HashMap<>();
   * for (KeyHandle k : current.compromisedPredecessors()) compromised.put(k.id(), k);
   * for (Record r : store.all()) {
   *   KeyHandle from = compromised.getOrDefault(KmsKeys.sealedKeyId(r.sealed()), current);
   *   store.put(r.id(), from.rewrapTo(current, r.sealed(), r.aad()));
   * }
   * }</pre>
   *
   * <p>A key is listed only when every step back to it is confirmed by both keys' links, as {@link
   * #latest()} follows them. So a key someone else created and revoked, naming yours, is never
   * listed. A Compromised key that {@link #reconcile()} joined into one of them is listed too.
   * Destroyed keys are left out, and so are keys more than 64 rotations back or beyond a link that
   * cannot be resolved. When the server refused both the Re-key and the links, {@link
   * #replaceCompromised} ended in a {@link PartialCompletionException}, and nothing is listed:
   * recover through the revoked key's own handle. One Get Attributes per key of the lineage.
   *
   * @return the Compromised predecessors, nearest first; unmodifiable, empty when there are none
   * @throws ProtocolViolationException when the walk meets its limits (more than 256 keys, or a key
   *     with more than 32 links)
   */
  public List<KeyHandle> compromisedPredecessors() {
    return kms.call(
        "compromisedPredecessors",
        () -> {
          KeyAttributes a = attributes();
          knowing(a);
          if (a.links(LinkKind.REPLACED).isEmpty()) return List.of();
          Lineage.Tree tree = Lineage.tree("compromisedPredecessors", a, true, null, keys::read);
          if (tree.limit() != null) throw tree.limit();
          Map<String, KeyAttributes> byId = new HashMap<>();
          for (KeyAttributes k : tree.keys()) byId.put(k.id(), k);
          List<KeyHandle> out = new ArrayList<>();
          Deque<String> queue = new ArrayDeque<>(older(tree, id));
          Set<String> seen = new HashSet<>(queue);
          seen.add(id);
          while (!queue.isEmpty()) {
            KeyAttributes k = byId.get(queue.poll());
            if (k == null) continue;
            if (k.state() == KeyState.COMPROMISED)
              out.add(
                  new KeyHandle(keys, k.id(), ObjectKind.SYMMETRIC_KEY)
                      .knowing(k)
                      .allowingCompromised());
            for (String p : older(tree, k.id())) if (seen.add(p)) queue.add(p);
          }
          return List.copyOf(out);
        });
  }

  /** The keys {@code id} replaced and the keys joined into it ({@link #reconcile()}), sorted. */
  private static List<String> older(Lineage.Tree tree, String id) {
    Set<String> ids = new HashSet<>(tree.predecessors(id));
    ids.addAll(tree.joinedFrom(id));
    return ids.stream().sorted(Lineage.IDENTIFIERS).toList();
  }

  /**
   * Replaces this symmetric key after a compromise, and returns the replacement, Active. It does
   * the steps of <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#a-compromised-key">A
   * compromised key</a> in one call. This key is revoked with {@code reason}, unless it is
   * Compromised already. A successor is made with Re-key, which links the two keys. Where the server
   * refuses the Re-key, a new key with this key's algorithm, size, usages, groups and custom
   * attributes is created, activated and linked instead, with no lifecycle dates. This key's names
   * then move to the replacement, so {@link KmsKeys#findByName(String)} and {@link
   * KeyCreation#findOrCreate()} return it.
   *
   * <p>From then on this key refuses to encrypt. Reading its material, decrypting and opening need
   * {@link #allowingCompromised()}. Re-seal its records with {@code
   * key.allowingCompromised().rewrapTo(replacement, record, aad)}, a loop that can be repeated. A
   * process that holds only the replacement gets the revoked keys from {@link
   * #compromisedPredecessors()}. Data sealed after the compromise happened may be an attacker's.
   *
   * <p>A key past its Deactivation Date is re-keyed with an Offset of 0. The replacement then keeps
   * the spans from this key's Activation Date to its Deactivation and Protect Stop Dates, when each
   * span is at least a day. Otherwise it has no lifecycle dates. {@link
   * #replaceCompromised(RevocationReason, Rotation)} lets you choose.
   *
   * <p>Run it from one place, as for {@link #rotate()}. Repeat a failed call when its message says
   * so. It does not revoke twice, and it finishes with a replacement already linked to this key. A
   * key another caller compromised first keeps that compromise's reason and dates. Callers that
   * replace the key at once may each make a replacement. Every record still opens through the
   * lineage, and {@link #reconcile()} joins the replacements.
   *
   * <p>It acts on the keys {@link #compromisePlan()} would name. When the lineage forked, it
   * finishes with the one newest key the plan chooses (activating that key only) and leaves the
   * others as they are, for {@link #reconcile()}. It differs from the plan-bound {@link
   * #replaceCompromisedResult(RevocationReason, CompromisePlan)} in three ways:
   *
   * <ul>
   *   <li>It does not compare the changes with an approved plan.
   *   <li>If another caller's replacement appears while it runs, it finishes with that key and
   *       activates only that key, where the plan-bound call stops. It finds such a replacement
   *       when its own Re-key or links are refused because of it, or after its own Re-key's reply
   *       was lost.
   *   <li>It does not look for a key an earlier call created and did not link, which may be
   *       another caller's being made at that moment. A plan refuses while one exists.
   * </ul>
   *
   * <p>Where the server refuses Re-key, the replacement is created under a temporary name that
   * only this call uses ({@code keytend-replacing-}, this key's identifier and a random suffix). Its
   * client attribute {@code x-keytend-replacement-of} records this key's identifier. When the
   * Create's reply is lost, the call goes on only with a key it can confirm it created (<a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/kms-design.md#a-lost-create-or-register-reply">A
   * lost Create or Register reply</a>). Otherwise it stops, and its message gives the name and what
   * was found. {@link KmsException#objectId()} is the one object found, when there is one. Look the
   * key up before you repeat.
   *
   * <p>When the server refuses both the Re-key and the links, the replacement is still finished,
   * Active and named, and the call throws {@link PartialCompletionException} naming both keys. Use
   * that replacement, and re-seal this key's records through this key's own handle. Do not repeat
   * the call, because it would make another replacement.
   *
   * @param reason a compromise reason ({@link RevocationReason#keyCompromise} or {@link
   *     RevocationReason#caCompromise}); used only if this key is not Compromised yet
   * @return the replacement, Active
   * @throws IllegalArgumentException when {@code reason} is not a compromise
   * @throws KeyMismatchException when this object is not a symmetric key (nothing is changed)
   * @throws StateConflictException when this key is destroyed (nothing is changed)
   * @throws OutcomeUnknownException when the replacement cannot be confirmed from this key's links
   *     (a Re-key reply naming a key not linked to it): find the current key by name
   * @throws PartialCompletionException when the replacement was made and a later step failed, or
   *     the server refused to link it; the message says whether repeating resumes
   */
  public KeyHandle replaceCompromised(RevocationReason reason) {
    return replacedAfterCompromise(reason, null, Protection.NONE);
  }

  /**
   * {@link #replaceCompromised(RevocationReason)} with the replacement's dates and protection that
   * {@code rotation} gives.
   *
   * <p>The one-argument form takes a span of at least a day from a retired key's Activation Date to
   * its Deactivation Date for a policy's cryptoperiod. The server cannot tell that from a key
   * retired by hand, so say which it is:
   *
   * <ul>
   *   <li>{@code Rotation.of(RotationDates.SHIFTED)}: a Re-key with an Offset of 0 whatever the
   *       span, so the replacement keeps this key's cryptoperiod from now.
   *   <li>{@code Rotation.of(RotationDates.COPIED)}: a Re-key that copies this key's dates. When
   *       its Deactivation Date has passed, a new key without lifecycle dates is made and linked
   *       instead.
   * </ul>
   *
   * <pre>{@code
   * // retired by hand, then found compromised: a replacement without this key's dates
   * KeyHandle replacement = key.replaceCompromised(reason, Rotation.of(RotationDates.COPIED));
   * }</pre>
   *
   * <p>Where the server refuses the Re-key or its Offset, a new key without dates is made either
   * way. The Extractable and Sensitive values of {@code rotation} are checked as {@link
   * #rotate(Rotation)} checks them; without them the replacement keeps this key's. A replacement an
   * earlier call or another caller made is returned as it is.
   *
   * @param reason a compromise reason ({@link RevocationReason#keyCompromise} or {@link
   *     RevocationReason#caCompromise}); used only if this key is not Compromised yet
   * @param rotation the replacement's dates and protection, without a grace period: a Compromised
   *     key is revoked at once
   * @return the replacement, Active
   * @throws IllegalArgumentException when {@code reason} is not a compromise, or {@code rotation}
   *     has a grace period ({@link Rotation#grace(Duration)}); nothing is sent
   * @throws UnsupportedException below KMIP 1.4 when {@code rotation} asks for Extractable or
   *     Sensitive (nothing is sent)
   * @throws KmsException as {@link #replaceCompromised(RevocationReason)}
   * @since 0.10.0
   */
  public KeyHandle replaceCompromised(RevocationReason reason, Rotation rotation) {
    requireNoGrace(rotation);
    rotation.protection().require(kms.protocolVersion(), Kms.named("replaceCompromised"));
    return replacedAfterCompromise(reason, rotation.rotationDates(), rotation.protection());
  }

  /**
   * Reads what {@link #replaceCompromisedResult(RevocationReason, CompromisePlan)} would do, and
   * changes nothing: whether this key is revoked first, which existing replacement the call
   * finishes with, whether a Compromised key descending from it is replaced in turn, and whether a
   * key is created. The call acts on those keys only: other newest keys of a forked lineage
   * ({@link CompromisePlan#otherDescendants()}) are left as they are. It refuses what that call
   * would refuse before its first change. Show the plan, have it approved, then pass it to that
   * call, which acts only if the keys are still as planned.
   *
   * <pre>{@code
   * CompromisePlan plan = key.compromisePlan();
   * // show plan.attributes(), revokes(), existingReplacement(), replacedInTurn() and creates(),
   * // and ask for approval
   * CompromiseResult r = key.replaceCompromisedResult(RevocationReason.keyCompromise(why, since), plan);
   * }</pre>
   *
   * <p>One Get Attributes, and, when this key has replacements, one for each key of its lineage the
   * plan reads to find the newest key descending from it. When the key a replacement would be made
   * for is Compromised already, one Locate by its client attribute {@code x-keytend-replacement-of}
   * for a key an earlier call created for it and did not link (a lost Create's reply, or a call
   * that stopped before its links), and a Get Attributes of each object it returns, up to 256.
   * Where that search cannot be made (the server refuses it, does not filter by client attributes,
   * or returns more than that), the plan says so ({@link CompromisePlan#checkedForUnlinkedKeys()}):
   * look for such a key yourself before you approve it. An object it returns that cannot be read
   * is named ({@link CompromisePlan#unreadableCandidates()}): have it read before you approve.
   *
   * @return the plan
   * @throws KeyMismatchException when this object is not a symmetric key
   * @throws StateConflictException ({@link StateConflictException.Conflict#STATE}) when this key is
   *     destroyed (nothing is left to replace), or when the newest key descending from it is
   *     neither Active, Pre-Active nor Compromised (it cannot be the replacement; {@link
   *     KmsException#objectId()} names it); ({@link StateConflictException.Conflict#LINEAGE}) when a
   *     replacement link cannot be followed; ({@link
   *     StateConflictException.Conflict#UNLINKED_REPLACEMENT}) when the search finds a key that an
   *     earlier call created to replace it (or the descendant replaced in turn) and did not link: a
   *     second replacement would leave that key unaccounted for ({@link KmsException#objectId()}
   *     names it)
   * @throws TransientException when a read, the search included, failed transiently or its reply
   *     was lost (a busy server, a dropped connection): the plan changes nothing, so make it again.
   *     It is never reported as a server that cannot be searched
   * @since 0.10.0
   */
  public CompromisePlan compromisePlan() {
    requireKind("compromisePlan", ObjectKind.SYMMETRIC_KEY);
    return kms.call(
        "compromisePlan",
        () -> {
          String operation = Kms.named("compromisePlan");
          KeyAttributes current = compromiseCandidate(operation);
          List<KeyAttributes> replacements = confirmedReplacements(operation, current);
          List<KeyAttributes> tips = descendingTips(operation, current);
          KeyAttributes newest = plannedDescendant(operation, current, tips);
          KmsKeys.Search unlinked = refuseUnlinked(operation, current, newest);
          return new CompromisePlan(
              kms.owner(),
              allowingCompromised(),
              current,
              replacements.stream().map(KeyAttributes::id).toList(),
              tips.stream().sorted(FINISHED_FIRST).toList(),
              newest,
              unfinishedMoves(replacements),
              unlinked == null || unlinked.complete(),
              unlinked == null ? List.of() : unlinked.unreadable());
        });
  }

  /**
   * The name moves earlier calls stopped part-way, recorded on {@code replacements} (a key's
   * confirmed replacements): each one's identifier and the names it records ({@link
   * #pendingNames}), sorted; the procedure finishes them ({@link #finishPending}).
   */
  static Map<String, List<String>> unfinishedMoves(List<KeyAttributes> replacements) {
    Map<String, List<String>> out = new TreeMap<>(Lineage.IDENTIFIERS);
    for (KeyAttributes r : replacements) {
      List<String> names = pendingNames(r);
      if (!names.isEmpty()) out.put(r.id(), names.stream().sorted().toList());
    }
    return out;
  }

  /**
   * The key a plan's call gives a new replacement to: {@code newest} when it is Compromised (it is
   * replaced in turn), {@code current} when it has no replacement; null when the call finishes
   * with an existing key.
   */
  private static KeyAttributes replacedLast(KeyAttributes current, KeyAttributes newest) {
    return newest == null ? current : newest.state() == KeyState.COMPROMISED ? newest : null;
  }

  /**
   * The search a plan makes for an earlier call's unlinked key ({@link #unlinkedReplacements}) of
   * {@link #replacedLast}: null when there is nothing to look for, because the call creates nothing
   * or that key is not Compromised yet (the procedure revokes a key before it creates its
   * replacement, so no earlier call can have made one).
   */
  private KmsKeys.Search unlinkedFor(KeyAttributes current, KeyAttributes newest) {
    KeyAttributes last = replacedLast(current, newest);
    if (last == null || last.state() != KeyState.COMPROMISED) return null;
    return unlinkedReplacements(last.id());
  }

  /**
   * Refuses ({@link StateConflictException.Conflict#UNLINKED_REPLACEMENT}) a plan whose call would
   * create a replacement of {@link #replacedLast} while an earlier call's key for it exists that is
   * not linked to it ({@link #unlinkedFor}): a second one would leave that key unaccounted for.
   * Returns the search, which found none: whether it could tell ({@link
   * CompromisePlan#checkedForUnlinkedKeys()}) and what it could not read ({@link
   * CompromisePlan#unreadableCandidates()}); null when there is nothing to look for.
   */
  private KmsKeys.Search refuseUnlinked(
      String operation, KeyAttributes current, KeyAttributes newest) {
    KmsKeys.Search search = unlinkedFor(current, newest);
    if (search == null) return null;
    List<KeyAttributes> made = search.found();
    if (made.isEmpty()) return search;
    String replaced = replacedLast(current, newest).id();
    List<String> ids = made.stream().map(KeyAttributes::id).toList();
    // Never activated and never given a name of its own: never used to encrypt.
    boolean staged =
        made.stream()
            .allMatch(
                a ->
                    a.state() == KeyState.PRE_ACTIVE
                        && a.names().stream().allMatch(KeyHandle::temporaryName));
    String created =
        made.stream()
            .map(a -> a.id() + a.creationDate().map(d -> " at " + d).orElse(""))
            .collect(java.util.stream.Collectors.joining(", "));
    throw new StateConflictException(
            operation
                + ": "
                + String.join(", ", ids)
                + (ids.size() == 1 ? " records" : " record")
                + " that an earlier call created "
                + (ids.size() == 1 ? "it" : "them")
                + " to replace "
                + replaced
                + " (the client attribute "
                + REPLACEMENT_OF
                + "), and "
                + (ids.size() == 1 ? "it is" : "they are")
                + " not linked to it, so nothing was changed: "
                + (staged
                    ? "that call's Create reply was lost or it stopped, or another caller is"
                        + " replacing "
                        + replaced
                        + " now (created "
                        + created
                        + "). When "
                        + (ids.size() == 1 ? "it is" : "they are")
                        + " still unlinked a few minutes after that and no other replacement of "
                        + replaced
                        + " is running, destroy "
                        + String.join(", ", ids)
                        + " (Pre-Active, never activated), then make a new plan;"
                        + " a second key beside it would leave it unaccounted for"
                    : "the server refused its links: use it as the replacement, as that call"
                        + " said, rather than make another"),
            null,
            operation,
            ids.get(0),
            null,
            null)
        .because(StateConflictException.Conflict.UNLINKED_REPLACEMENT);
  }

  /**
   * {@link #replaceCompromised(RevocationReason)}, bound to {@code plan} and saying what it did.
   * It acts on the keys the plan names and on no other: it revokes this key if the plan {@link
   * CompromisePlan#revokes()}, then finishes with {@link CompromisePlan#existingReplacement()}
   * (activating only that key), or replaces {@link CompromisePlan#replacedInTurn()} or this key
   * with a key it creates; other newest keys of a forked lineage stay as they are.
   *
   * <p>Before the first change it reads this key and its lineage again, makes the plan again from
   * what it read, and refuses with {@link StateConflictException} ({@link
   * StateConflictException.Conflict#NOT_AS_PLANNED}, nothing changed) when that plan differs from
   * {@code plan}: this key's state, Compromise Occurrence Date, names or replacements, the newest
   * keys descending from it with their states and names (which decide the key the call finishes
   * with), or the unfinished name moves it finishes. It refuses the same way when an unlinked
   * key created to replace the key it would replace exists now and the plan did not see it, or
   * when the plan could search for such a key ({@link CompromisePlan#checkedForUnlinkedKeys()})
   * and the search cannot be made now.
   *
   * <p>Each later step checks the keys it reads against the plan as well: when another caller's
   * replacement appears after the comparison (this call's Re-key or links refused because of it),
   * the call stops there, with {@code NOT_AS_PLANNED} as the cause of a {@link
   * PartialCompletionException} when it had changed something, rather than finish with that key.
   * A step that fails stops the call: a refused activation of the planned key is never followed by
   * a replacement of another.
   *
   * <p>Recovery after a lost reply keeps to the same keys. A lost Revoke, link, Activate or name
   * change is read back. After a lost Re-key reply the key's replacements cannot tell whether this
   * call's Re-key or another caller's made them, so the call activates, links and names none of
   * them and stops with that unknown outcome (a {@link PartialCompletionException} when it had
   * revoked the key): make a new plan, which shows them. After a lost fallback Create reply the
   * call goes on only with the key its own temporary name finds, as the Create left it; otherwise
   * it stops, and says what the search for that name found.
   *
   * <p>Same requests, other refusals and failures as {@link #replaceCompromised(RevocationReason)}.
   * KMIP has no transactions: a change another caller makes to a key the call has already read is
   * not detected.
   *
   * @param reason a compromise reason ({@link RevocationReason#keyCompromise} or {@link
   *     RevocationReason#caCompromise}); used only if the plan {@link CompromisePlan#revokes()}
   * @param plan the plan from {@link #compromisePlan()} of this key
   * @return what the call did
   * @throws IllegalArgumentException when {@code reason} is not a compromise, or {@code plan} was
   *     made from another key or {@link Kms}; nothing is sent
   * @throws StateConflictException ({@link StateConflictException.Conflict#NOT_AS_PLANNED}) when
   *     this key is no longer as planned, or the plan could search for an earlier call's unlinked
   *     key and that search cannot tell now; nothing was changed. Never for a transient failure of
   *     that search, which is thrown as it is ({@link TransientException}), nothing changed
   * @throws KmsException as {@link #replaceCompromised(RevocationReason)}
   * @since 0.10.0
   */
  public CompromiseResult replaceCompromisedResult(RevocationReason reason, CompromisePlan plan) {
    return replacedAfterCompromise(reason, null, Protection.NONE, plan);
  }

  /**
   * {@link #replaceCompromisedResult(RevocationReason, CompromisePlan)} with the replacement's
   * dates and protection that {@code rotation} gives, as {@link
   * #replaceCompromised(RevocationReason, Rotation)}.
   *
   * @param reason a compromise reason; used only if the plan {@link CompromisePlan#revokes()}
   * @param rotation the replacement's dates and protection, without a grace period
   * @param plan the plan from {@link #compromisePlan()} of this key
   * @return what the call did
   * @throws IllegalArgumentException as {@link #replaceCompromised(RevocationReason, Rotation)},
   *     and when {@code plan} was made from another key or {@link Kms}; nothing is sent
   * @throws UnsupportedException below KMIP 1.4 when {@code rotation} asks for Extractable or
   *     Sensitive (nothing is sent)
   * @throws KmsException as {@link #replaceCompromisedResult(RevocationReason, CompromisePlan)}
   * @since 0.10.0
   */
  public CompromiseResult replaceCompromisedResult(
      RevocationReason reason, Rotation rotation, CompromisePlan plan) {
    requireNoGrace(rotation);
    rotation.protection().require(kms.protocolVersion(), Kms.named("replaceCompromised"));
    return replacedAfterCompromise(reason, rotation.rotationDates(), rotation.protection(), plan);
  }

  /** Refuses a {@code rotation} with a grace period: a Compromised key is revoked at once. */
  private static void requireNoGrace(Rotation rotation) {
    Objects.requireNonNull(rotation, "rotation");
    if (rotation.gracePeriod().isPresent())
      throw new IllegalArgumentException(
          "replaceCompromised: a Compromised key is revoked at once, so a grace period does not apply; use"
              + " Rotation.of(dates), with extractable(...) or sensitive(...) if needed, not "
              + rotation);
  }

  /**
   * The public forms; {@code dates} null: chosen from this key's dates; {@code asked}: the
   * protection asked for the replacement ({@link Protection#NONE}: this key's is kept).
   */
  private KeyHandle replacedAfterCompromise(
      RevocationReason reason, RotationDates dates, Protection asked) {
    requireCompromise(reason);
    requireKind("replaceCompromised", ObjectKind.SYMMETRIC_KEY);
    return kms.call(
        "replaceCompromised",
        () -> {
          KeyAttributes current = attributes();
          requireSymmetric(current);
          return replaceCompromised(current, reason, null, dates, asked);
        });
  }

  /** The plan-bound forms: as above, after comparing this key with {@code plan}. */
  private CompromiseResult replacedAfterCompromise(
      RevocationReason reason, RotationDates dates, Protection asked, CompromisePlan plan) {
    requireCompromise(reason);
    Objects.requireNonNull(plan, "plan");
    if (plan.owner() != kms.owner() || !plan.key().id().equals(id))
      throw new IllegalArgumentException(
          "replaceCompromised: the plan was made from "
              + plan.key().id()
              + (plan.owner() != kms.owner() ? " on another Kms" : "")
              + ", not from "
              + id
              + "; make the plan from this handle");
    requireKind("replaceCompromised", ObjectKind.SYMMETRIC_KEY);
    return kms.call(
        "replaceCompromised",
        () -> {
          String operation = Kms.named("replaceCompromised");
          KeyAttributes current = attributes();
          requireSymmetric(current);
          String changed = unlike(operation, current, plan);
          if (changed != null) throw notAsPlanned(operation, id, changed, current.state(), true);
          CompromiseTrace trace = new CompromiseTrace();
          trace.plan = plan;
          KeyHandle replacement = replaceCompromised(current, reason, null, dates, asked, trace);
          return trace.result(allowingCompromised(), replacement);
        });
  }

  /**
   * How the plan made again from {@code current} and its lineage, as read now, differs from {@code
   * plan}, for the refusal's message; null when it is the same plan. Read in the order a
   * difference is cheapest to find: every fact the plan's decision depends on is compared, so
   * when this returns null the call makes the plan's decision (the descendant is chosen from the
   * same keys, states and names).
   */
  private String unlike(String operation, KeyAttributes current, CompromisePlan plan) {
    KeyAttributes planned = plan.attributes();
    if (current.state() != planned.state())
      return " is " + current.state() + ", not " + planned.state();
    if (!current.compromiseOccurrenceDate().equals(planned.compromiseOccurrenceDate()))
      return " has the Compromise Occurrence Date "
          + current.compromiseOccurrenceDate().map(Object::toString).orElse("none")
          + ", not "
          + planned.compromiseOccurrenceDate().map(Object::toString).orElse("none");
    if (!Set.copyOf(current.names()).equals(Set.copyOf(planned.names())))
      return " has the names " + current.names() + ", not " + planned.names();
    List<KeyAttributes> confirmed = confirmedReplacements(operation, current);
    List<String> replacements = confirmed.stream().map(KeyAttributes::id).toList();
    if (!Set.copyOf(replacements).equals(Set.copyOf(plan.replacementIds())))
      return (replacements.isEmpty() ? " has no replacement" : " is replaced by " + replacements)
          + ", not "
          + (plan.replacementIds().isEmpty() ? "none" : "by " + plan.replacementIds());
    Map<String, List<String>> moves = unfinishedMoves(confirmed);
    if (!moves.equals(plan.unfinishedNameMoves()))
      return "'s replacements record the unfinished name moves "
          + moves
          + ", not "
          + plan.unfinishedNameMoves();
    List<KeyAttributes> tips = descendingTips(operation, current);
    String tipsChanged = tipsUnlike(tips, plan.descendants());
    if (tipsChanged != null) return tipsChanged;
    // The same keys in the same states with the same names: the same choice, compared anyway.
    KeyAttributes newest = plannedDescendant(operation, current, tips);
    String chosen = newest == null ? null : newest.id();
    String plannedChoice = plan.newest() == null ? null : plan.newest().id();
    if (!Objects.equals(chosen, plannedChoice))
      return " leads to " + chosen + " first, not " + plannedChoice;
    KmsKeys.Search unlinked = unlinkedFor(current, newest);
    if (unlinked == null) return null;
    String replaced = replacedLast(current, newest).id();
    List<String> found = unlinked.found().stream().map(KeyAttributes::id).toList();
    // A key the plan did not see: most likely another caller's, being made and linked now.
    if (!found.isEmpty())
      throw new StateConflictException(
              operation
                  + ": "
                  + String.join(", ", found)
                  + (found.size() == 1 ? " records" : " record")
                  + " that a call created "
                  + (found.size() == 1 ? "it" : "them")
                  + " to replace "
                  + replaced
                  + " and "
                  + (found.size() == 1 ? "is" : "are")
                  + " not linked to it, and the plan "
                  + (plan.checkedForUnlinkedKeys()
                      ? "found none: another caller is likely replacing " + replaced + " now"
                      : "could not search for such a key")
                  + ", so nothing was changed: wait for that caller to finish, then make a new"
                  + " plan",
              null,
              operation,
              id,
              null,
              null)
          .because(StateConflictException.Conflict.NOT_AS_PLANNED);
    if (plan.checkedForUnlinkedKeys() && !unlinked.complete())
      throw new StateConflictException(
              operation
                  + ": the plan searched for a key an earlier call created to replace "
                  + replaced
                  + " and did not link, and that search cannot tell now"
                  + unlinked.why()
                  + ", so nothing was changed: make a new plan, which says whether it could"
                  + " search",
              null,
              operation,
              id,
              null,
              null)
          .because(StateConflictException.Conflict.NOT_AS_PLANNED);
    return null;
  }

  /**
   * How the newest descending keys {@code now} differ from {@code planned}: in which keys they
   * are, or in a key's state or names; null when they do not.
   */
  private static String tipsUnlike(List<KeyAttributes> now, List<KeyAttributes> planned) {
    Map<String, String> read = described(now), was = described(planned);
    return read.equals(was) ? null : " leads to " + read + ", not " + was;
  }

  /** The identifiers of {@code keys}, each with its state and names, for comparing and showing. */
  private static Map<String, String> described(List<KeyAttributes> keys) {
    Map<String, String> out = new TreeMap<>(Lineage.IDENTIFIERS);
    for (KeyAttributes k : keys)
      out.put(
          k.id(),
          k.state() + (k.names().isEmpty() ? "" : " named " + new TreeSet<>(k.names()).toString()));
    return out;
  }

  /** The refusal of a plan-bound call whose keys are not as planned ({@code changed} says how). */
  private static StateConflictException notAsPlanned(
      String operation, String id, String changed, KeyState observed, boolean before) {
    StateConflictException e =
        new StateConflictException(
                operation
                    + ": "
                    + id
                    + changed
                    + " as in the plan: another caller changed it since the plan was made;"
                    + (before ? " nothing was changed" : " this call stopped there")
                    + ": make a new plan",
                null,
                operation,
                id,
                null,
                null)
            .because(StateConflictException.Conflict.NOT_AS_PLANNED);
    return observed == null ? e : e.observed(observed);
  }

  /**
   * The newest keys descending from {@code current} (the tips of its lineage past it), as read: a
   * compromise replacement of it finishes with, or replaces in turn, the first of them in {@link
   * #FINISHED_FIRST} order ({@link #existingReplacement}); empty when it has no replacement.
   */
  private List<KeyAttributes> descendingTips(String operation, KeyAttributes current) {
    if (Lineage.existingReplacements(operation, current, keys::read).isEmpty()) return List.of();
    Lineage.Tree tree = Lineage.tree(operation, current, true, null, keys::read);
    return tree.tips().stream()
        .filter(t -> !t.id().equals(current.id()) && tree.descends(t.id(), current.id()))
        .toList();
  }

  /**
   * The order a compromise replacement chooses among the newest descending keys in, from their
   * states as read ({@link #plannedDescendant}): {@link Lineage#TIPS}, except that a Pre-Active key
   * ranks as an Active one, since the call activates the key it chooses (that one only).
   */
  static final Comparator<KeyAttributes> FINISHED_FIRST =
      Comparator.comparing(
              (KeyAttributes a) -> a.state() != KeyState.ACTIVE && a.state() != KeyState.PRE_ACTIVE)
          .thenComparing(a -> a.names().isEmpty())
          .thenComparing(Lineage.EARLIEST);

  /**
   * The key among {@code tips} (from {@link #descendingTips}) that a compromise replacement of
   * {@code current} finishes with, or replaces in turn when it is Compromised; null when there is
   * none. The one decision of the plan, its comparison and the procedure ({@link
   * #existingReplacement}), from the tips as read: a newest key in another state is refused.
   */
  private static KeyAttributes plannedDescendant(
      String operation, KeyAttributes current, List<KeyAttributes> tips) {
    if (tips.isEmpty()) return null;
    KeyAttributes newest = tips.stream().sorted(FINISHED_FIRST).findFirst().orElseThrow();
    KeyState state = knownState(operation, newest.id(), newest);
    if (state == KeyState.ACTIVE || state == KeyState.PRE_ACTIVE || state == KeyState.COMPROMISED)
      return newest;
    throw unusableDescendant(operation, current.id(), newest, state);
  }

  /**
   * The refusal of a replacement of {@code replaced} whose newest descendant, {@code newest}, is in
   * {@code state}, which a replacement cannot be in.
   */
  private static StateConflictException unusableDescendant(
      String operation, String replaced, KeyAttributes newest, KeyState state) {
    return new StateConflictException(
            operation
                + ": "
                + replaced
                + " was replaced already, and the newest key descending from it, "
                + newest.id()
                + ", is "
                + state
                + ", so it cannot be the replacement; find the current key by name, or replace "
                + newest.id()
                + " instead",
            null,
            operation,
            newest.id(),
            null,
            null)
        .observed(state);
  }

  /**
   * The replacements of {@code key}, as read, each confirmed by both keys' links. A
   * Replacement Object link to an existing object that does not name {@code key} back is refused
   * ({@link StateConflictException.Conflict#LINEAGE}): whether the key was replaced cannot be told,
   * so a plan would show either a replacement that is not one or a new one the call cannot link.
   */
  private List<KeyAttributes> confirmedReplacements(String operation, KeyAttributes key) {
    List<KeyAttributes> read = Lineage.replacements(operation, key, keys::read);
    List<String> confirmed = read.stream().map(KeyAttributes::id).toList();
    List<String> oneSided =
        Lineage.existingReplacements(operation, key, keys::read).stream()
            .filter(r -> !confirmed.contains(r))
            .toList();
    if (!oneSided.isEmpty())
      throw new StateConflictException(
              operation
                  + ": "
                  + key.id()
                  + " names "
                  + oneSided
                  + " as its replacement, but "
                  + (oneSided.size() == 1 ? "that object does" : "those objects do")
                  + " not name it back, so whether "
                  + key.id()
                  + " was replaced cannot be told and nothing was changed: revoke it yourself"
                  + " (revoke(reason)) to stop its use, then check "
                  + oneSided
                  + " and remove the link that is not yours",
              null,
              operation,
              key.id(),
              null,
              null)
          .because(StateConflictException.Conflict.LINEAGE);
    return read;
  }

  /** Refuses a {@code reason} that is not a compromise. */
  private static void requireCompromise(RevocationReason reason) {
    Objects.requireNonNull(reason, "reason");
    if (reason.kind() != RevocationReason.Kind.KEY_COMPROMISE
        && reason.kind() != RevocationReason.Kind.CA_COMPROMISE)
      throw new IllegalArgumentException(
          "replaceCompromised needs a compromise reason (RevocationReason.keyCompromise(...)), not "
              + reason.kind());
  }

  /** Refuses a key that is not symmetric: only those are replaced after a compromise. */
  private void requireSymmetric(KeyAttributes current) {
    if (current.kind() != ObjectKind.SYMMETRIC_KEY)
      throw new KeyMismatchException(
          Kms.named("replaceCompromised")
              + ": "
              + id
              + " is a "
              + current.kind()
              + "; only symmetric keys are replaced after a compromise",
          null,
          Kms.named("replaceCompromised"),
          id,
          null,
          null);
  }

  /**
   * This key's attributes for a compromise plan: refused as {@link #replaceCompromised} refuses
   * them before any change (not a symmetric key; destroyed).
   */
  private KeyAttributes compromiseCandidate(String operation) {
    KeyAttributes current = attributes();
    if (current.kind() != ObjectKind.SYMMETRIC_KEY)
      throw new KeyMismatchException(
          operation
              + ": "
              + id
              + " is a "
              + current.kind()
              + "; only symmetric keys are replaced after a compromise",
          null,
          operation,
          id,
          null,
          null);
    KeyState state = knownState(operation, id, current);
    if (state == KeyState.DESTROYED || state == KeyState.DESTROYED_COMPROMISED)
      throw new StateConflictException(
              operation
                  + ": "
                  + id
                  + " is "
                  + state
                  + "; nothing is left to replace: create a new key",
              null,
              operation,
              id,
              null,
              null)
          .observed(state);
    return current;
  }

  /**
   * What a replacement after a compromise did, for its {@link CompromiseResult}: filled in by
   * {@link #replaceCompromised(KeyAttributes, RevocationReason, ObjectOptions, RotationDates,
   * Protection, CompromiseTrace)} as it goes.
   */
  static final class CompromiseTrace {
    /** This call's Revoke took effect, its reply confirming it. */
    boolean revoked;

    /** The replacement this call's Re-key or Create made, its reply confirming it; or null. */
    KeyHandle created;

    /** A step whose outcome was unknown, read back past; or null. */
    OutcomeUnknownException lost;

    /** Keys this call created that lost to another caller's linked replacement. */
    final List<KeyHandle> lostRaces = new ArrayList<>();

    /** The Compromised descendants replaced in turn, in order, as allowingCompromised() views. */
    final List<KeyHandle> inTurn = new ArrayList<>();

    /** The Compromise Occurrence Date read after the revocation; or null. */
    Instant occurrence;

    /** The plan a plan-bound call acts on; null for {@link #replaceCompromised(RevocationReason)}. */
    CompromisePlan plan;

    /**
     * The step whose outcome stayed unknown and at which the call stopped, rather than go on with
     * a key it cannot prove its own (a fallback Create, or a plan-bound call's Re-key); or null.
     */
    Unsettled unsettled;

    /**
     * A step whose outcome stayed unknown, {@code unknown}, at which the call stopped: {@code what}
     * the step was and what reading back found, and {@code advice}, what to do instead of a plain
     * repeat, which a lost reply alone does not make safe.
     */
    record Unsettled(OutcomeUnknownException unknown, String what, String advice) {}

    /**
     * In a plan-bound call, refuses ({@link StateConflictException.Conflict#NOT_AS_PLANNED}) the
     * newest keys {@code tips} descending from {@code key} unless they are the plan's: the plan's
     * descendants for the key it was made for, none for the key it replaces in turn (a newest key
     * itself). The only keys of this call's own are created after these reads.
     */
    void expectTips(String operation, KeyAttributes key, List<KeyAttributes> tips) {
      if (plan == null) return;
      List<KeyAttributes> expected =
          key.id().equals(plan.key().id())
              ? plan.descendants()
              : plan.replacedInTurn().filter(d -> d.id().equals(key.id())).isPresent()
                  ? List.of()
                  : null;
      String changed =
          expected == null ? " is not a key the plan acts on, and" : tipsUnlike(tips, expected);
      if (changed != null) throw notAsPlanned(operation, key.id(), changed, key.state(), false);
    }

    /**
     * Which recorded name moves on the replacements of {@code key} the call finishes: every one,
     * except in a plan-bound call, where only those the plan names for the key it was made for
     * ({@link CompromisePlan#unfinishedNameMoves()}).
     */
    java.util.function.BiPredicate<String, String> plannedMove(String key) {
      if (plan == null) return (holder, name) -> true;
      if (!key.equals(plan.key().id())) return (holder, name) -> false;
      Map<String, List<String>> moves = plan.unfinishedNameMoves();
      return (holder, name) -> moves.getOrDefault(holder, List.of()).contains(name);
    }

    /** Whether {@code key} is this call's own creation, confirmed. */
    boolean made(KeyHandle key) {
      return created != null && created.equals(key);
    }

    /**
     * A failure after the replacement {@code replacement} was made or found: listed as created
     * when this call made it, otherwise as {@link PartialCompletionException#found()}.
     */
    PartialCompletionException failed(
        String operation, KeyHandle replacement, String step, String advice, RuntimeException e) {
      return made(replacement)
          ? PartialCompletionException.of(operation, List.of(replacement), null, step, advice, e)
          : PartialCompletionException.found(
              operation, List.of(replacement), lost, step, advice, e);
    }

    CompromiseResult result(KeyHandle compromised, KeyHandle replacement) {
      CompromiseResult.Outcome outcome =
          lost != null
              ? CompromiseResult.Outcome.RECOVERED
              : made(replacement)
                  ? revoked ? CompromiseResult.Outcome.REPLACED : CompromiseResult.Outcome.COMPLETED
                  : CompromiseResult.Outcome.EXISTING;
      List<KeyHandle> mine = new ArrayList<>();
      if (made(replacement)) mine.add(replacement);
      mine.addAll(lostRaces);
      // Each step's own reply: a lost Re-key does not make a confirmed Revoke uncertain.
      return new CompromiseResult(
          outcome, compromised, replacement, revoked, occurrence, mine, inTurn, lost);
    }

    /**
     * Whether a step changed something, or may have: a failure is then a partial completion. The
     * step the call stopped at ({@link #unsettled}) is that failure itself.
     */
    boolean changed() {
      return revoked || lost != null || created != null || !lostRaces.isEmpty();
    }

    /**
     * {@code e}, the failure of a call that changed nothing, with what was found and the advice
     * when {@code e} is the unknown outcome the call stopped at ({@link #unsettled}).
     */
    RuntimeException unchanged(String operation, RuntimeException e) {
      if (unsettled == null || e != unsettled.unknown()) return e;
      return new OutcomeUnknownException(
          operation + ": " + unsettled.what() + " (" + e.getMessage() + "); " + unsettled.advice(),
          e,
          operation,
          unsettled.unknown().objectId().orElse(null),
          null,
          null);
    }

    /**
     * The failure {@code e} of a replacement of {@code key} after a step changed something (or may
     * have): a {@link PartialCompletionException} that keeps every earlier fact, merged with {@code
     * e}'s own when it is one (an inner step's): the confirmed Revoke in {@link
     * PartialCompletionException#deactivated()}, the keys this call created, and the step whose
     * reply was lost in {@link PartialCompletionException#recoveredFrom()}.
     */
    PartialCompletionException progress(String operation, KeyHandle key, RuntimeException e) {
      List<KeyHandle> mine = new ArrayList<>();
      if (created != null) mine.add(created);
      mine.addAll(lostRaces);
      List<String> done = new ArrayList<>();
      if (revoked) done.add("revoked " + key.id() + " as compromised");
      if (lost != null)
        done.add("went on past a step whose reply was lost (" + lost.getMessage() + ")");
      if (created != null) done.add("created " + created.id());
      for (KeyHandle k : lostRaces)
        done.add(
            "created "
                + k.id()
                + ", which lost to another caller's replacement and is left Pre-Active, unnamed and"
                + " unlinked");
      return PartialCompletionException.withProgress(
          operation,
          String.join(" and ", done),
          mine,
          revoked ? List.of(key) : List.of(),
          lost,
          (unsettled != null && e == unsettled.unknown()
              ? unsettled.what()
                  + ": "
                  + unsettled.advice()
                  + (revoked
                      ? " (" + key.id() + " is Compromised, and keeps this call's reason and dates)"
                      : "")
              : "repeat "
                  + operation
                  + "() to resume"
                  + (revoked
                      ? " (" + key.id() + " is Compromised, and keeps this call's reason and dates)"
                      : "")
                  + "; for the plan-bound form, make a new compromisePlan() first"),
          e);
    }
  }

  /**
   * The procedure of {@link #replaceCompromised(RevocationReason)} for a key whose attributes are
   * {@code current}: {@code reason} null when it is Compromised already, and {@code fresh} (may be
   * null) the options of a new key when Re-key is refused (default: this key's own).
   */
  KeyHandle replaceCompromised(
      KeyAttributes current, RevocationReason reason, ObjectOptions fresh) {
    return replaceCompromised(current, reason, fresh, null, Protection.NONE);
  }

  /**
   * {@link #replaceCompromised(KeyAttributes, RevocationReason, ObjectOptions)} with the dates the
   * caller asked for ({@link #replaceCompromised(RevocationReason, Rotation)}); null: chosen from
   * this key's dates. {@code asked}: the protection asked for the replacement when {@code
   * fresh} is null (with {@code fresh}, its own).
   */
  KeyHandle replaceCompromised(
      KeyAttributes current,
      RevocationReason reason,
      ObjectOptions fresh,
      RotationDates dates,
      Protection asked) {
    return replaceCompromised(current, reason, fresh, dates, asked, new CompromiseTrace());
  }

  /**
   * {@link #replaceCompromised(KeyAttributes, RevocationReason, ObjectOptions, RotationDates,
   * Protection)}, recording in {@code trace} what it did. A failure after the replacement is made
   * or found lists it as created only when this call made it ({@link CompromiseTrace#failed}).
   */
  KeyHandle replaceCompromised(
      KeyAttributes current,
      RevocationReason reason,
      ObjectOptions fresh,
      RotationDates dates,
      Protection asked,
      CompromiseTrace trace) {
    String operation = Kms.named("replaceCompromised");
    try {
      return replacementSteps(current, reason, fresh, dates, asked, trace);
    } catch (PartialCompletionException e) {
      // An inner step's partial completion: keeps what came before it too.
      throw trace.changed() ? trace.progress(operation, this, e) : e;
    } catch (KmsException | IllegalStateException e) {
      // After the Revoke (confirmed, or read back past a lost reply), every failure is a partial
      // completion: the key stays Compromised whatever happens next.
      if (!trace.changed()) throw trace.unchanged(operation, e);
      throw trace.progress(operation, this, e);
    }
  }

  /**
   * The steps of {@link #replaceCompromised(KeyAttributes, RevocationReason, ObjectOptions,
   * RotationDates, Protection, CompromiseTrace)}, for this key or, in turn, a Compromised key
   * descending from it, recording in {@code trace} what they did.
   */
  private KeyHandle replacementSteps(
      KeyAttributes current,
      RevocationReason reason,
      ObjectOptions fresh,
      RotationDates dates,
      Protection asked,
      CompromiseTrace trace) {
    String operation = Kms.named("replaceCompromised");
    KeyState state = knownState(operation, id, current);
    if (state == KeyState.DESTROYED || state == KeyState.DESTROYED_COMPROMISED)
      throw new StateConflictException(
              operation
                  + ": "
                  + id
                  + " is "
                  + state
                  + "; nothing is left to replace: create a new key",
              null,
              operation,
              id,
              null,
              null)
          .observed(state);
    // Security first, and idempotent: revoke unless an earlier call (or an operator) did.
    boolean raced = false;
    // The replacements this key had when this call read it: a routine rotation's, from before.
    Set<String> linkedBefore = Set.copyOf(current.links(LinkKind.REPLACEMENT));
    if (state != KeyState.COMPROMISED) {
      if (reason == null)
        throw new StateConflictException(
                operation + ": " + id + " is " + state + ", not Compromised",
                null,
                operation,
                id,
                null,
                null)
            .observed(state);
      // A replacement this key has already (a routine rotation's) must be one the procedure can
      // finish with: refused before the Revoke, as compromisePlan() refuses it.
      if (!linkedBefore.isEmpty())
        plannedDescendant(operation, current, descendingTips(operation, current));
      try {
        revoke(reason);
        trace.revoked = true;
      } catch (OutcomeUnknownException unknown) {
        // Read back: the revocation took effect, or the call cannot go on. A read that fails
        // proves nothing: the unknown Revoke stands, with the read's failure on it.
        boolean revoked;
        try {
          revoked = compromised(attributes());
        } catch (KmsException | IllegalStateException unreadable) {
          unknown.addSuppressed(unreadable);
          throw unknown;
        }
        if (!revoked) throw unknown;
        // This call's Revoke or another caller's: which one cannot be told.
        trace.lost = unknown;
      } catch (StateConflictException refused) {
        // Another caller compromised the key since it was read, and the server refused a second
        // Revoke (KMIP lists no transition out of Compromised but Destroy): revoke() read it back.
        // Go on as if this call had revoked it, keeping the first compromise's reason and dates.
        // Any other refusal, or one whose read-back failed, stands as it was.
        KeyState now = refused.observedState().orElse(null);
        if (now == KeyState.DESTROYED_COMPROMISED)
          throw new StateConflictException(
                  operation
                      + ": "
                      + id
                      + " is "
                      + now
                      + "; nothing is left to replace: create a new key",
                  refused,
                  operation,
                  id,
                  refused.result().orElse(null),
                  null)
              .observed(now);
        if (now != KeyState.COMPROMISED) throw refused;
        raced = true;
      }
      current = attributes();
    }
    // A replacement an earlier call made (or another instance): finish with it.
    KeyHandle replacement = existingReplacement(operation, current, fresh, dates, asked, trace);
    // The server's refusal of the links, when it refused them: the call then ends in a
    // PartialCompletionException naming both keys, never in an unlinked replacement.
    KmsException unlinked = null;
    KmsException[] refusedLinks = new KmsException[1];
    ReKeyTrace reKey = new ReKeyTrace();
    // A plan-bound call never goes on with a key a lost Re-key's read-back finds.
    reKey.adopts = trace.plan == null;
    // The caller that compromised the key first made this replacement (linked to this key since
    // this
    // call read it, not a routine rotation's from before): told as a refused Re-key is.
    if (raced
        && replacement != null
        && current.links(LinkKind.REPLACEMENT).contains(replacement.id())
        && !linkedBefore.contains(replacement.id())) {
      kms.concurrentReplacement(id, List.of(replacement.id()));
      reKey.told = true;
    }
    // A Deactivation Date that has passed (a key retired, then found compromised): a Re-key without
    // an Offset copies it, so on a server that follows KMIP the replacement would be Deactivated
    // too. With an Offset of 0 the server moves it forward by as long as the key was Active before
    // it: sent when that is a cryptoperiod. Otherwise, and where the server refuses the
    // Re-key, a new key, linked by hand.
    boolean retired = current.deactivationDate().map(d -> !d.isAfter(kms.now())).orElse(false);
    // The caller's choice, or the span a Re-key with an Offset carries is taken for a
    // policy's cryptoperiod when it is at least a day.
    boolean shifted =
        dates != null ? dates == RotationDates.SHIFTED : retired && keepsACryptoperiod(current);
    if (replacement == null && retired && !shifted) {
      replacement = successor(current, fresh, refusedLinks, dates, asked, trace);
      unlinked = refusedLinks[0];
    } else if (replacement == null)
      try {
        // Re-key links the keys.
        replacement =
            rotate(false, false, reKey, shifted, fresh == null ? asked : fresh.protection());
        if (reKey.lost == null) trace.created = replacement;
        else if (trace.lost == null) trace.lost = reKey.lost;
      } catch (OutcomeUnknownException unknown) {
        if (reKey.appeared != null) trace.unsettled = reKeyUnsettled(unknown, reKey.appeared);
        throw unknown;
      } catch (StateConflictException
          | PermissionDeniedException
          | UnsupportedException
          | InvalidRequestException refused) {
        if (refused instanceof AlreadyExistsException || Failures.credentialsRefused(refused))
          throw refused;
        // rotate() also refuses a key another instance re-keyed since this call looked: use that
        // one.
        replacement = existingReplacement(operation, attributes(), fresh, dates, asked, trace);
        if (replacement == null) {
          // The server will not re-key a Compromised key: a new key, linked by hand where allowed.
          replacement = successor(current, fresh, refusedLinks, dates, asked, trace);
          unlinked = refusedLinks[0];
        }
      }
    List<String> names = List.of();
    try {
      KeyAttributes mine = replacement.attributes();
      replacement.knowing(mine);
      // Returned Active. It is this call's key, or the replacement of this key an earlier call or
      // another instance made: activating it is the step that call would take next.
      if (mine.state() == KeyState.PRE_ACTIVE && trace.made(replacement))
        keys.activateCreated(operation, List.of(replacement));
      else if (mine.state() == KeyState.PRE_ACTIVE) {
        // The one key this call activates beside its own: a lost reply read back Active is this
        // call's Activate or another caller's, so it is recovered from, not claimed.
        OutcomeUnknownException lostActivate =
            keys.activateFound(operation, replacement, trace.lost);
        if (lostActivate != null && trace.lost == null) trace.lost = lostActivate;
      }
      KeyAttributes now = attributes();
      trace.occurrence = now.compromiseOccurrenceDate().orElse(null);
      // A name an earlier attempt (this call's, or another caller's) took off this key and did not
      // give yet: it is recorded on a replacement of this key, and goes to this one. A record whose
      // name this key still holds is another caller's move that has not taken it off yet: kept.
      // In a plan-bound call, only the moves the plan names (CompromisePlan.unfinishedNameMoves()).
      finishPending(
          operation,
          Lineage.replacements(operation, now, keys::read),
          replacement,
          id::equals,
          trace.plannedMove(id));
      // The names go from this key, and only while it holds them (read now, not before the
      // replacement was made): another caller's replacement may have them already.
      names = now.names();
      for (String name : names) moveName(operation, name, this, replacement);
      // Told already when the server refused this call's Re-key because of another caller's.
      if (!reKey.told) reportConcurrent(operation, now);
    } catch (PartialCompletionException e) {
      // Unlinked, its finishing (activation, a name) failed too: never the advice to repeat, which
      // would make another unlinked key.
      if (unlinked != null
          && !e.created().isEmpty()
          && e.created().get(0).id().equals(replacement.id()))
        throw unlinked(operation, current, replacement, List.of(), unlinked, e, "");
      throw e;
    } catch (KmsException | IllegalStateException e) {
      // A name taken off this key (names are unique) and not yet given: a repeat would not see it.
      List<String> stranded = stranded(names, this, replacement);
      String give =
          stranded.isEmpty()
              ? ""
              : "give "
                  + replacement.id()
                  + " the names "
                  + stranded
                  + " by hand (they were taken off "
                  + id
                  + " and are on neither key: kms.keys().handle(\""
                  + replacement.id()
                  + "\").addName(...)), then ";
      if (unlinked != null)
        throw unlinked(operation, current, replacement, List.of(), unlinked, e, give);
      throw trace.failed(
          operation,
          replacement,
          "finishing the replacement failed",
          give + "repeat " + operation + "() to resume",
          e);
    }
    if (unlinked != null)
      throw unlinked(operation, current, replacement, names, unlinked, null, "");
    return replacement;
  }

  /**
   * A plan-bound call's Re-key of this key had the unknown outcome {@code unknown}, and reading back
   * found the replacements {@code appeared}: what the call stopped at, and what to do.
   */
  private CompromiseTrace.Unsettled reKeyUnsettled(
      OutcomeUnknownException unknown, List<KeyAttributes> appeared) {
    boolean one = appeared.size() == 1;
    return new CompromiseTrace.Unsettled(
        unknown,
        "re-keying "
            + id
            + " had an unknown outcome, and "
            + id
            + " now shows "
            + (one ? "the replacement " : "the replacements ")
            + described(appeared)
            + ", which this call's Re-key or another caller's made: which cannot be told, so this"
            + " call did not activate, link or name "
            + (one ? "it" : "any of them"),
        "make a new compromisePlan(), which shows "
            + (one ? "it" : "them")
            + ", and approve that (this plan no longer matches)");
  }

  /**
   * The end of a replacement the server would not link to {@code old} (it refused the links, {@code
   * refused}): the replacement is Active and has {@code names}, but nothing leads from one key to
   * the other, so {@link #compromisedPredecessors()} and {@link #latest()} cannot find {@code old}'s
   * records' key, and a repeat would make another replacement. A {@link
   * PartialCompletionException} naming both keys, so a recovery job stops and someone re-seals
   * from the compromised key's own handle. With {@code failed}, finishing the replacement
   * failed as well (it may be Pre-Active, or lack names; {@code give} says which names to give by
   * hand): the advice then says to finish it by hand first, and {@code failed} is suppressed on the
   * exception.
   */
  private static PartialCompletionException unlinked(
      String operation,
      KeyAttributes old,
      KeyHandle replacement,
      List<String> names,
      KmsException refused,
      RuntimeException failed,
      String give) {
    String state =
        failed == null
            ? replacement.id()
                + " is Active"
                + (names.isEmpty() ? "" : " and has the names " + names)
                + ", but it"
            : "finishing "
                + replacement.id()
                + " failed too ("
                // Not an inner PartialCompletionException's own advice, which would say to repeat.
                + (failed instanceof PartialCompletionException && failed.getCause() != null
                    ? failed.getCause().getMessage()
                    : failed.getMessage())
                + "): "
                + give
                + "activate "
                + replacement.id()
                + " if it is Pre-Active and give it the names "
                + old.names()
                + " where it lacks"
                + " them; it";
    PartialCompletionException e =
        PartialCompletionException.of(
            operation,
            List.of(replacement),
            null,
            "the server refused the links between "
                + old.id()
                + " and its replacement "
                + replacement.id(),
            state
                + " is not linked to the Compromised key "
                + old.id()
                + ", so compromisedPredecessors() and latest()"
                + " do not lead from one to the other: use "
                + replacement.id()
                + " from now on (CurrentKey.moveTo),"
                + " and re-seal "
                + old.id()
                + "'s records from its own handle, kms.keys().handle(\""
                + old.id()
                + "\")"
                + ".allowingCompromised().rewrapTo(replacement, record, aad), as operating-keys.md \"A compromised"
                + " key\" says; do not repeat "
                + operation
                + "() (it would make another replacement)",
            refused);
    if (failed != null) e.addSuppressed(failed);
    return e;
  }

  /**
   * The replacement of {@code current} to finish with, for a repeated or concurrent replacement: the
   * newest key descending from it that {@link #plannedDescendant} chooses, as read; null when it has
   * none. Only that key is acted on: it is activated later if Pre-Active, and other newest keys of
   * a forked lineage are left as they are ({@link #reconcile()} joins them). A newest key that is
   * Compromised too is replaced in turn; one in another state cannot be handed out as the
   * replacement: STATE. In a plan-bound call the keys read must be the plan's ({@link
   * CompromiseTrace#expectTips}).
   */
  private KeyHandle existingReplacement(
      String operation,
      KeyAttributes current,
      ObjectOptions fresh,
      RotationDates dates,
      Protection asked,
      CompromiseTrace trace) {
    List<KeyAttributes> descending = descendingTips(operation, current);
    trace.expectTips(operation, current, descending);
    KeyAttributes newest = plannedDescendant(operation, current, descending);
    if (newest == null) return null;
    KeyHandle handle = new KeyHandle(keys, newest.id(), ObjectKind.SYMMETRIC_KEY);
    if (newest.state() != KeyState.COMPROMISED) return handle;
    // Replaced in turn: its replacement is this key's too (CompromisePlan.replacedInTurn()).
    trace.inTurn.add(handle.allowingCompromised());
    return handle.replacementSteps(newest, null, fresh, dates, asked, trace);
  }

  /**
   * The client attribute a key created to replace another records that key's identifier in
   * ({@link #createSuccessor}): when a call stops before its links (or a crash stops it), the key
   * it made is linked to nothing, and this is how a plan finds it ({@link #unlinkedReplacements})
   * and refuses to make a second one beside it. It stays once the key is linked: the record of
   * which key it was made to replace. A Re-key copies it, but a key made by a Re-key has a Replaced
   * Object link to another key, so a plan never takes it for an unlinked one.
   */
  static final CustomAttribute REPLACEMENT_OF = CompromisePlan.REPLACEMENT_RECORD;

  /**
   * How the temporary name a fallback Create gives its key begins ({@link #successor}): then the
   * key it replaces and a random suffix, so that only that call uses the name. A Locate by Name,
   * which every server supports, finds the key after the Create's reply is lost.
   */
  static final String TEMPORARY = CompromisePlan.TEMPORARY_NAME_PREFIX;

  /** Whether {@code name} is a fallback Create's temporary name ({@link #TEMPORARY}). */
  static boolean temporaryName(String name) {
    return name.startsWith(TEMPORARY);
  }

  /**
   * The search for keys an earlier call created to replace {@code replaced} and did not link to it
   * (it stopped before the links, or the server refused them): what it found, earliest first, are
   * Active or Pre-Active symmetric keys whose {@link #REPLACEMENT_OF} names {@code replaced}, with
   * no replacement and no Replaced Object link to another key. One Locate, and a Get Attributes of
   * each object it returns; {@link KmsKeys.Search#complete()} false where the server cannot search
   * client attributes, or an object it returns cannot be read. A transient failure or an unknown
   * outcome of the search is thrown: nothing has changed when it runs, and it says nothing about
   * what the server can search.
   */
  private KmsKeys.Search unlinkedReplacements(String replaced) {
    KmsKeys.Search found = keys.recording(REPLACEMENT_OF, replaced);
    return found.keeping(
        Lineage.EARLIEST,
        a ->
            a.kind() == ObjectKind.SYMMETRIC_KEY
                && (a.state() == KeyState.ACTIVE || a.state() == KeyState.PRE_ACTIVE)
                && !a.id().equals(replaced)
                && a.links(LinkKind.REPLACEMENT).isEmpty()
                && a.links(LinkKind.REPLACED).stream().allMatch(replaced::equals));
  }

  /**
   * The shortest span between a retired key's Activation Date and its Deactivation (or Protect Stop)
   * Date that {@link #replaceCompromised} carries to the replacement with a Re-key Offset of 0
   *: a key retired sooner was retired by hand, and its replacement would be retired as soon.
   */
  static final Duration CRYPTOPERIOD_FLOOR = Duration.ofDays(1);

  /**
   * Whether a Re-key of {@code key} with an Offset of 0 gives a replacement that stays Active and
   * protects for at least {@link #CRYPTOPERIOD_FLOOR}: the server moves the Deactivation and Protect
   * Stop Dates by as much as the Activation Date moves (DT2 = DT1 + (AT2 - AT1), KMIP 1.4 §4.4), so
   * the replacement keeps the span the key had from its Activation Date to each. False without an
   * Activation Date (the dates cannot be moved).
   */
  private static boolean keepsACryptoperiod(KeyAttributes key) {
    Optional<Instant> activated = key.activationDate();
    if (activated.isEmpty()) return false;
    List<Instant> ends = new ArrayList<>();
    key.deactivationDate().ifPresent(ends::add);
    for (Ttlv a : key.protocolAttributes())
      if (a.tag() == PROTECT_STOP_DATE.code()) ends.add(a.instantValue());
    for (Instant end : ends)
      if (activated.get().plus(CRYPTOPERIOD_FLOOR).isAfter(end)) return false;
    return true;
  }

  /**
   * A new successor of {@code current} ({@link #createSuccessor}), linked to it by hand ({@link
   * #linked}) once its temporary name is removed ({@link #dropTemporary}). When the Create's reply
   * is lost, the key it made is looked for by that name ({@link #madeAfterAll}): found as the
   * Create left it, it is linked as this call's key would be, and the lost Create is {@link
   * CompromiseTrace#lost}; otherwise that unknown outcome stands, and {@link
   * CompromiseTrace#unsettled} says what the search found.
   */
  private KeyHandle successor(
      KeyAttributes current,
      ObjectOptions fresh,
      KmsException[] refused,
      RotationDates dates,
      Protection asked,
      CompromiseTrace trace) {
    String operation = Kms.named("replaceCompromised");
    String temporary = TEMPORARY + current.id() + "-" + UUID.randomUUID();
    Protection wanted = (fresh == null ? asked : fresh.protection()).keeping(current);
    KeyHandle made;
    boolean mine;
    try {
      made = createSuccessor(current, fresh, wanted, temporary);
      mine = true;
    } catch (OutcomeUnknownException unknown) {
      made = madeAfterAll(operation, current, temporary, unknown, trace);
      mine = false;
      // Found by the name only this call's Create used: it made this key, though no reply
      // confirmed it, so it is reported as recovered from, not as created.
      if (trace.lost == null) trace.lost = unknown;
      KeyMismatchException weaker =
          KmsKeys.unprotected(operation, made.id(), made.attributes(), wanted);
      if (weaker != null)
        throw PartialCompletionException.found(
            operation,
            List.of(made),
            trace.lost,
            "the server did not keep the protection asked",
            "do not activate or use "
                + made.id()
                + ": it is Pre-Active, and the server may release its value",
            weaker);
    }
    dropTemporary(operation, made, mine, temporary, trace);
    return linked(current, made, mine, fresh, refused, dates, asked, trace);
  }

  /**
   * The fallback Create's reply was lost ({@code unknown}): the key it made, found by the {@code
   * temporary} name only this call used, when the search can tell it is the only object with that
   * name and it is as the Create left it, recording {@code current} ({@link KmsKeys#madeUnder}).
   * Otherwise the unknown outcome is thrown, and {@link CompromiseTrace#unsettled} says what the
   * search found: none (where the search could tell, so the Create made nothing), objects that are
   * not as the Create left a key (another caller changed it, or re-keyed it: a Re-key moves names),
   * or nothing it could rely on (the server refused the search, did not filter it, or returned an
   * object these credentials cannot read).
   */
  private KeyHandle madeAfterAll(
      String operation,
      KeyAttributes current,
      String temporary,
      OutcomeUnknownException unknown,
      CompromiseTrace trace) {
    KmsKeys.Made found =
        keys.madeUnder(
            temporary,
            ObjectKind.SYMMETRIC_KEY,
            a -> current.id().equals(a.custom().get(REPLACEMENT_OF)),
            unknown);
    if (found.made().isPresent())
      return new KeyHandle(keys, found.made().get().id(), ObjectKind.SYMMETRIC_KEY)
          .knowing(found.made().get());
    String what =
        "creating a replacement of "
            + current.id()
            + " had an unknown outcome, and "
            + found.described(temporary, "the Create left a key", ", recording " + current.id());
    List<String> ids = found.holders();
    String advice;
    if (found.none())
      advice = "the Create probably did not take effect: repeat " + operation + "() to resume";
    else if (!ids.isEmpty())
      advice =
          "this call changed none of them: check "
              + String.join(", ", ids)
              + " (attributes()) before you repeat "
              + operation
              + "()";
    else
      advice =
          "the Create may have made a key with that name (Pre-Active and linked to nothing): look"
              + " for it (kms.keys().list(KeyQuery.byName(\""
              + temporary
              + "\"))) before you repeat "
              + operation
              + "(). A new compromisePlan() refuses while that key is unlinked where the server can"
              + " search the client attribute "
              + REPLACEMENT_OF
              + ", and says when it cannot (checkedForUnlinkedKeys()); an unbound repeat would"
              + " create another";
    // The one object found, or located and unreadable, named by the stop's objectId().
    OutcomeUnknownException stop =
        found.concerned().isEmpty()
            ? unknown
            : new OutcomeUnknownException(
                unknown.getMessage(),
                unknown,
                operation,
                found.concerned().get(),
                unknown.result().orElse(null),
                unknown.response().orElse(null));
    trace.unsettled = new CompromiseTrace.Unsettled(stop, what, advice);
    throw stop;
  }

  /**
   * Removes the {@code temporary} name from {@code made} before it is linked, so a linked key
   * never has it; a lost reply is read back, and when the name is gone it is {@link
   * CompromiseTrace#lost} (unless an earlier step is). A failure stops the call: {@code made} is
   * Pre-Active and linked to nothing, and a new plan names it.
   */
  private void dropTemporary(
      String operation, KeyHandle made, boolean mine, String temporary, CompromiseTrace trace) {
    RuntimeException failed;
    try {
      made.removeName(temporary);
      return;
    } catch (OutcomeUnknownException unknown) {
      try {
        if (!made.attributes().names().contains(temporary)) {
          // Read back past: the result's recoveredFrom() unless an earlier step's was.
          if (trace.lost == null) trace.lost = unknown;
          return;
        }
      } catch (KmsException | IllegalStateException unreadable) {
        unknown.addSuppressed(unreadable);
      }
      failed = unknown;
    } catch (KmsException | IllegalStateException e) {
      failed = e;
    }
    String step = "removing its temporary name " + temporary + " failed";
    String advice =
        "do not use "
            + made.id()
            + " yet (it is Pre-Active and linked to nothing): remove the name by hand"
            + " (kms.keys().handle(\""
            + made.id()
            + "\").removeName(\""
            + temporary
            + "\")), then make a new compromisePlan(), which names "
            + made.id()
            + " as an earlier call's unlinked key and says what to do with it";
    throw mine
        ? PartialCompletionException.of(operation, List.of(made), null, step, advice, failed)
        : PartialCompletionException.found(
            operation, List.of(made), trace.lost, step, advice, failed);
  }

  /**
   * Links {@code made} to {@code current} by hand ({@link #link}): a key this call created, its
   * reply confirming it ({@code mine}), or found by its temporary name after a lost reply; {@code
   * refused[0]} is set to the server's refusal of
   * the links when it refused them. When that refusal came because another caller's replacement
   * was linked to {@code current} first (a server that allows one Replacement Object link, as KMIP
   * does, refuses the second), this call lost a race, as when the server refuses a second Re-key:
   * the other replacement is used instead (the newest key descending from {@code current}, {@link
   * #existingReplacement}), and the {@link KmsListener#concurrentReplacement listener} hears of
   * it; in a plan-bound call, that key is not the plan's, and the call stops there. This call's key
   * stays as it is, Pre-Active, unnamed and unlinked: it never encrypted, and the SDK destroys
   * nothing it was not asked to.
   */
  private KeyHandle linked(
      KeyAttributes current,
      KeyHandle made,
      boolean mine,
      ObjectOptions fresh,
      KmsException[] refused,
      RotationDates dates,
      Protection asked,
      CompromiseTrace trace) {
    String operation = Kms.named("replaceCompromised");
    KmsException links = link(current, made);
    if (links == null) {
      if (mine) trace.created = made;
      return made;
    }
    KeyHandle other;
    try {
      other = existingReplacement(operation, attributes(), fresh, dates, asked, trace);
    } catch (StateConflictException notPlanned) {
      if (notPlanned.conflict() != StateConflictException.Conflict.NOT_AS_PLANNED)
        throw unreadable(operation, made, mine, links, notPlanned);
      // Another caller's replacement, which the plan does not name: this call's key lost to it.
      if (mine) trace.lostRaces.add(made);
      notPlanned.addSuppressed(links);
      throw notPlanned;
    } catch (KmsException | IllegalStateException e) {
      throw unreadable(operation, made, mine, links, e);
    }
    if (other == null || other.id().equals(made.id())) {
      refused[0] = links;
      if (mine) trace.created = made;
      return made;
    }
    // This call's key lost the race: another caller's replacement is used.
    if (mine) trace.lostRaces.add(made);
    kms.concurrentReplacement(id, List.of(other.id()));
    return other;
  }

  /**
   * The links to {@code made} were refused ({@code links}), and reading this key again failed
   * ({@code e}): not known to be a server that refuses links, since the refusal may be another
   * caller's link having come first. Nothing is activated or named; the repeat reads again.
   */
  private PartialCompletionException unreadable(
      String operation, KeyHandle made, boolean mine, KmsException links, RuntimeException e) {
    links.addSuppressed(e);
    String step =
        "the server refused the link from " + id + " to it, and reading " + id + " again failed";
    String advice =
        "do not use "
            + made.id()
            + " yet (it is unnamed and not linked); repeat "
            + operation
            + "() to resume: it finishes with the replacement another caller linked to "
            + id
            + ", if one did, and otherwise links "
            + made.id();
    return mine
        ? PartialCompletionException.of(operation, List.of(made), null, step, advice, links)
        : PartialCompletionException.found(operation, List.of(made), null, step, advice, links);
  }

  /**
   * A new key like {@code old} (or {@code fresh}), without its names: they are given once the
   * replacement is settled ({@link #moveName}), so a name lookup never finds a key that may still
   * give way to another instance's. It has the call's {@code temporary} name only, and records
   * {@code old}'s identifier in {@link #REPLACEMENT_OF}. {@code wanted}: the protection it gets
   * (asked, or else {@code old}'s Extractable false and Sensitive true, as a Re-key copies them).
   */
  private KeyHandle createSuccessor(
      KeyAttributes old, ObjectOptions fresh, Protection wanted, String temporary) {
    ObjectOptions options = new ObjectOptions();
    if (fresh == null) {
      options.usages(old.usages().toArray(KeyUsage[]::new));
      if (kms.protocolVersion() != ProtocolVersion.V3_0)
        for (String g : old.groups()) options.group(g);
      // Not the old key's records of names being moved to it, or of the key it was made to
      // replace: they are about that key.
      for (var e : old.custom().entrySet())
        if (!isPendingRecord(e.getKey()) && !e.getKey().equals(REPLACEMENT_OF))
          options.custom(e.getKey(), e.getValue());
    } else {
      options.usages.addAll(fresh.usages);
      options.groups.addAll(fresh.groups);
      options.custom.putAll(fresh.custom);
    }
    // Found by these: by this call after a lost reply (its temporary name), or by a plan.
    options.names.add(temporary);
    options.custom(REPLACEMENT_OF, old.id());
    // Read back once the key is made.
    options.protection(wanted);
    Algorithm algorithm =
        old.algorithm()
            .orElseThrow(
                () ->
                    new KeyMismatchException(
                        Kms.named("replaceCompromised")
                            + ": "
                            + id
                            + " has no Cryptographic Algorithm to give its replacement",
                        null,
                        Kms.named("replaceCompromised"),
                        id,
                        null,
                        null));
    int bits =
        old.length()
            .orElseThrow(
                () ->
                    new KeyMismatchException(
                        Kms.named("replaceCompromised")
                            + ": "
                            + id
                            + " has no Cryptographic Length to give its replacement",
                        null,
                        Kms.named("replaceCompromised"),
                        id,
                        null,
                        null));
    return keys.createSymmetric(algorithm, bits, options);
  }

  /**
   * Links {@code replacement} to {@code old} as Re-key would, the replacement's Replaced Object link
   * first: until the old key's link follows, walks from the old key ({@link #latest()}, another
   * instance's replacement) do not see the replacement, rather than meeting a link it does not
   * confirm. Null when both links were made; the server's refusal when it refuses either (a refused
   * second link is taken back, since the replacement's lineage would look broken). A change whose
   * reply is lost is settled by reading the key again; one that cannot be settled, or another
   * failure, is a {@link PartialCompletionException} that says how to finish, since repeating would
   * make another key.
   */
  private KmsException link(KeyAttributes old, KeyHandle replacement) {
    String operation = Kms.named("replaceCompromised");
    KeyHandle oldKey = keys.handle(old.id());
    String names = old.names().isEmpty() ? "" : " and give it the names " + old.names();
    String unlinked =
        "add the links by hand ("
            + replacement.id()
            + "'s Replaced Object link to "
            + old.id()
            + ", then "
            + old.id()
            + "'s Replacement Object link to "
            + replacement.id()
            + ") and repeat "
            + operation
            + "() to"
            + " finish; where the server refuses links, activate "
            + replacement.id()
            + names
            + " instead, and do not repeat";
    KmsException refused =
        changed(
            operation,
            () ->
                replacement.add(
                    operation, Attributes.link(Enums.LinkType.REPLACED_OBJECT_LINK, old.id())),
            () -> linksTo(replacement, LinkKind.REPLACED, old.id()),
            replacement,
            "linking the replacement to " + old.id(),
            unlinked);
    if (refused != null) return refused;
    refused =
        changed(
            operation,
            () ->
                oldKey.add(
                    operation,
                    Attributes.link(Enums.LinkType.REPLACEMENT_OBJECT_LINK, replacement.id())),
            () -> linksTo(oldKey, LinkKind.REPLACEMENT, replacement.id()),
            replacement,
            "linking " + old.id() + " to its replacement",
            unlinked);
    if (refused == null) return null;
    // A link the old key does not confirm would make the replacement's lineage look broken: take it
    // back.
    boolean removed =
        replacement.unlink(operation, Enums.LinkType.REPLACED_OBJECT_LINK, old.id())
            || !readable(() -> linksTo(replacement, LinkKind.REPLACED, old.id()), true);
    if (!removed)
      throw PartialCompletionException.of(
          operation,
          List.of(replacement),
          null,
          "the server refused "
              + old.id()
              + "'s link to the replacement, and the replacement's link to "
              + old.id()
              + " could not be removed",
          "do not repeat: remove the Replaced Object link to "
              + old.id()
              + " from "
              + replacement.id()
              + ", then activate "
              + replacement.id()
              + " if needed"
              + names,
          new StateConflictException(
                  operation + ": " + replacement.id() + " still links to " + old.id(),
                  refused,
                  operation,
                  replacement.id(),
                  null,
                  null)
              .because(StateConflictException.Conflict.LINEAGE));
    return refused;
  }

  /**
   * Makes one attribute change of {@link #link}: null when it took effect, the server's refusal when
   * it refused it. An unknown outcome is settled by {@code check}; when that cannot be read, or the
   * change failed otherwise (nothing was decided), a {@link PartialCompletionException} naming
   * {@code replacement}, with {@code advice}.
   */
  private static KmsException changed(
      String operation,
      Runnable change,
      java.util.function.BooleanSupplier check,
      KeyHandle replacement,
      String what,
      String advice) {
    try {
      change.run();
      return null;
    } catch (OutcomeUnknownException unknown) {
      try {
        if (check.getAsBoolean()) return null;
      } catch (KmsException | IllegalStateException unreadable) {
        unknown.addSuppressed(unreadable);
      }
      throw PartialCompletionException.of(
          operation,
          List.of(replacement),
          null,
          what + " had an unknown outcome, which reading the key did not settle",
          advice,
          unknown);
    } catch (StateConflictException
        | PermissionDeniedException
        | UnsupportedException
        | InvalidRequestException refused) {
      // The server refusing this link, not this client's credentials (those are a failure).
      if (Failures.credentialsRefused(refused))
        throw PartialCompletionException.of(
            operation, List.of(replacement), null, what + " failed", advice, refused);
      return refused;
    } catch (KmsException | IllegalStateException failed) {
      throw PartialCompletionException.of(
          operation, List.of(replacement), null, what + " failed", advice, failed);
    }
  }

  /** Whether {@code key} has a link of {@code kind} to {@code target}, as read now. */
  private static boolean linksTo(KeyHandle key, LinkKind kind, String target) {
    return key.attributes().links(kind).contains(target);
  }

  /** {@code check}'s answer, or {@code otherwise} when it cannot be read. */
  private static boolean readable(java.util.function.BooleanSupplier check, boolean otherwise) {
    try {
      return check.getAsBoolean();
    } catch (KmsException | IllegalStateException e) {
      return otherwise;
    }
  }

  /**
   * Moves the name {@code name} from {@code from}, the key being replaced, to {@code to}, but only
   * while {@code from} still holds it: when another caller's replacement (another branch of the
   * lineage) took it first, it stays there. Added to {@code to} first, then taken off {@code
   * from}; where names are unique, the addition is refused while {@code from} holds the name, so it
   * is taken off first. A lost reply is settled by reading the key again; on 1.x a refusal while
   * another caller moves the name (no holder left to confirm it as a name in use) is read again too.
   * At most three attempts.
   */
  private static void moveName(String operation, String name, KeyHandle from, KeyHandle to) {
    boolean taken = false, recorded = false;
    for (int attempt = 1; ; attempt++) {
      if (to.attributes().names().contains(name)) break;
      if (!taken && !from.attributes().names().contains(name)) return;
      try {
        to.addName(name);
        break;
      } catch (OutcomeUnknownException unknown) {
        if (attempt == 3) throw unknown;
      } catch (AlreadyExistsException unique) {
        // Another key holds it: the old key, which is taken off first, or another caller's
        // replacement, which keeps it.
        if (!from.attributes().names().contains(name)) {
          if (recorded) settledPending(operation, to, name);
          return;
        }
        if (attempt == 3) throw unique;
        // Between taking it off and giving it the name is on no key: written down on the key that
        // gets it first, so a repeat (or reconcile) can finish the move.
        recorded |= pending(to, name);
        removeNameRead(from, name);
        taken = true;
      } catch (InvalidRequestException | StateConflictException refused) {
        // Refused again once the old key gave the name up, with no holder to confirm a name in use:
        // the first refusal was not one either. The name goes back to the old key.
        if (taken) {
          giveBack(operation, name, from, to, recorded, refused);
          throw refused;
        }
        // 1.x: a name another caller was moving at that moment (no holder left to confirm it).
        if (!to.kms.protocolVersion().legacyAttributes()
            || !KmsKeys.nameRefusal(refused)
            || attempt == 3) throw refused;
      }
    }
    // Duplicate-name servers: off the old key too, so another caller sees the name has moved.
    if (!taken)
      try {
        removeNameRead(from, name);
      } catch (KmsException | IllegalStateException kept) {
        // It ranks after the replacement either way.
      }
    if (recorded) settledPending(operation, to, name);
  }

  /**
   * Puts {@code name} back on {@code from}, which gave it up for {@code to} to refuse it: then
   * {@code to}'s record of the move, if any, is settled. A failure is suppressed on {@code refused};
   * the record then stays, so a repeat (or reconcile) can finish the move.
   */
  private static void giveBack(
      String operation,
      String name,
      KeyHandle from,
      KeyHandle to,
      boolean recorded,
      KmsException refused) {
    try {
      if (!from.attributes().names().contains(name)) from.addName(name);
      if (recorded) settledPending(operation, to, name);
    } catch (KmsException | IllegalStateException failed) {
      refused.addSuppressed(failed);
    }
  }

  /**
   * The client attribute that records {@code name} as being moved to a key: one attribute per name,
   * whose value is the name, so that moves of different names to one key (two callers finishing one
   * replacement) do not overwrite each other's record. Written before the name is taken off
   * the key it leaves (where names are unique), removed once the key has it.
   */
  static CustomAttribute pendingName(String name) {
    byte[] digest;
    try {
      digest =
          java.security.MessageDigest.getInstance("SHA-256")
              .digest(name.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    return CustomAttribute.client(
        PENDING_PREFIX + java.util.HexFormat.of().formatHex(digest, 0, 16));
  }

  /** The prefix of {@link #pendingName}'s attributes. */
  static final String PENDING_PREFIX = "keytend-pending-name-";

  /** Whether {@code attribute} is a {@link #pendingName} record (of any name). */
  static boolean isPendingRecord(CustomAttribute attribute) {
    return attribute.vendor().equals("x") && attribute.name().startsWith(PENDING_PREFIX);
  }

  /** The names {@code key} records as being moved to it ({@link #pendingName}). */
  static List<String> pendingNames(KeyAttributes key) {
    List<String> out = new ArrayList<>();
    for (var e : key.custom().entrySet())
      if (isPendingRecord(e.getKey())
          && e.getValue() instanceof String name
          && e.getKey().equals(pendingName(name))) out.add(name);
    return out;
  }

  /**
   * Records on {@code to} that {@code name} is being moved to it; a server that refuses is passed
   * over. False when it surely was not written (then there is nothing to remove).
   */
  private static boolean pending(KeyHandle to, String name) {
    try {
      to.setCustomAttribute(pendingName(name), name);
      return true;
    } catch (OutcomeUnknownException unknown) {
      return true;
    } catch (KmsException | IllegalStateException refused) {
      // Without it, a failure before the name arrives is reported with the name to give by hand.
      return false;
    }
  }

  /**
   * Removes {@code to}'s record that {@code name} is being moved to it, and no other name's; a lost
   * reply is read back. A failure ends {@code operation} as a {@link PartialCompletionException}
   *: a record left behind makes {@code findOrCreate} refuse once no key holds the name (a
   * retired lineage), so the call reports it, and its repeat (or {@link #reconcile()}) removes it.
   * The advice says that the move itself is done.
   */
  private static void settledPending(String operation, KeyHandle to, String name) {
    try {
      try {
        to.removeCustomAttribute(pendingName(name));
      } catch (OutcomeUnknownException lost) {
        if (pendingNames(to.attributes()).contains(name)) throw lost;
      }
    } catch (KmsException | IllegalStateException failed) {
      String step =
          "removing " + to.id() + "'s record that the name " + name + " is being moved to it";
      String advice =
          "the name has arrived (it is on "
              + to.id()
              + " or on another key), so only that record is left; it"
              + " makes findOrCreate refuse once no key has the name: repeat "
              + operation
              + "() to remove it, or,"
              + " if the server keeps refusing, kms.keys().clearPendingName(\""
              + name
              + "\") once no move of the"
              + " name is running";
      throw operation.equals("reconcile")
          ? PartialCompletionException.interrupted(operation, step, advice, failed)
          : PartialCompletionException.of(operation, List.of(to), null, step, advice, failed);
    }
  }

  /**
   * Finishes the name moves earlier calls stopped in: for each name each of {@code keys}
   * records as pending, the name goes to {@code target} when no object holds it (a move that took
   * it off one key and did not give it), and that record is removed (also when another key holds
   * the name: that move finished, or another caller's replacement took it). A record whose name is
   * held only by keys {@code movedFrom} accepts (those this call moves names from next) is kept: a
   * move writes its record before it takes the name off, so that move may be running and not have
   * taken it off yet, and without the record nothing would finish it if it stopped after doing so;
   * this call's own move of the name, or that one, removes it once the name has arrived. One
   * Locate per record found; a lost reply is read back.
   */
  private void finishPending(
      String operation,
      Collection<KeyAttributes> keys,
      KeyHandle target,
      java.util.function.Predicate<String> movedFrom) {
    finishPending(operation, keys, target, movedFrom, (holder, name) -> true);
  }

  /**
   * {@link #finishPending(String, Collection, KeyHandle, java.util.function.Predicate)} for the
   * records {@code planned} accepts (the identifier of the key that holds one, and its name) only.
   */
  private void finishPending(
      String operation,
      Collection<KeyAttributes> keys,
      KeyHandle target,
      java.util.function.Predicate<String> movedFrom,
      java.util.function.BiPredicate<String, String> planned) {
    for (KeyAttributes k : keys)
      for (String name : pendingNames(k)) {
        if (!planned.test(k.id(), name)) continue;
        List<String> holders = this.keys.nameHolders(name);
        if (!holders.isEmpty() && holders.stream().allMatch(movedFrom)) continue;
        if (holders.isEmpty())
          for (int attempt = 1; ; attempt++) {
            try {
              target.addName(name);
              break;
            } catch (OutcomeUnknownException unknown) {
              if (target.attributes().names().contains(name)) break;
              if (attempt == 3) throw unknown;
            } catch (AlreadyExistsException elsewhere) {
              break; // another key took it since: it stays there
            }
          }
        settledPending(operation, new KeyHandle(this.keys, k.id(), ObjectKind.SYMMETRIC_KEY), name);
      }
  }

  /**
   * The names of {@code names} that neither {@code from} nor {@code to} holds as read now, and that
   * {@code to} does not record as pending (a move that took a name off {@code from}, failed to give
   * it, and could not write it down); empty when they cannot be read.
   */
  private static List<String> stranded(List<String> names, KeyHandle from, KeyHandle to) {
    if (names.isEmpty()) return List.of();
    try {
      List<String> held = new ArrayList<>(from.attributes().names());
      KeyAttributes target = to.attributes();
      held.addAll(target.names());
      // A name recorded as pending on the target is not stranded: a repeat finishes the move.
      held.addAll(pendingNames(target));
      return names.stream().filter(n -> !held.contains(n)).toList();
    } catch (KmsException | IllegalStateException unreadable) {
      return List.of();
    }
  }

  /** Removes {@code name} from {@code key}, reading back a lost reply. */
  private static void removeNameRead(KeyHandle key, String name) {
    try {
      key.removeName(name);
    } catch (OutcomeUnknownException lost) {
      if (key.attributes().names().contains(name)) throw lost;
    }
  }

  /** Removes this key's link of {@code type} to {@code target}; false when that failed. */
  private boolean unlink(String operation, Enums.LinkType type, String target) {
    try {
      removeLink(operation, type, target);
      return true;
    } catch (KmsException | IllegalStateException failed) {
      return false;
    }
  }

  /**
   * Removes this object's link of {@code type} to {@code target}: by value from KMIP 2.0, by the
   * Attribute Index the server reports for it on 1.x; nothing happens when it has no such link.
   */
  void removeLink(String operation, Enums.LinkType type, String target) {
    remove(
        operation,
        "Link",
        Attributes.link(type, target),
        v ->
            v.child(LINKED_OBJECT_IDENTIFIER).map(Ttlv::textValue).map(target::equals).orElse(false)
                && v.child(LINK_TYPE).map(Ttlv::intValue).map(t -> t == type.code()).orElse(false));
  }

  /**
   * Joins the newest keys of this key's rotation lineage into one, and returns the winner, Active.
   *
   * <p>Callers that rotated or replaced one key at the same time leave several newest keys (see
   * {@link #rotate()}). Records stay readable meanwhile, but retirement needs one newest key. Run
   * this from the place that rotates keys, one call at a time. The steps:
   *
   * <ol>
   *   <li>The newest key is chosen as {@link #latest()} chooses it: the winner, which must be
   *       Active.
   *   <li>Every other newest key that is not Compromised gets a Replacement Object link to the
   *       winner, so it is no longer a newest key. Nothing is added to the winner, and the keys
   *       stay in one lineage, so everything still opens. A Compromised one is left for {@link
   *       #replaceCompromised}, since its records need re-sealing.
   *   <li>The names of every other key of the lineage move to the winner.
   *   <li>Only then is every other Active key of the lineage deactivated ({@link
   *       #deactivate(RevocationReason)}, superseded). An instance still encrypting with one is
   *       refused and moves to {@link #latest()}. A key with more than 64 rotations after it stays
   *       Active.
   * </ol>
   *
   * <p>Nothing is destroyed. A change whose reply is lost is read back. A change that fails is a
   * {@link PartialCompletionException} whose advice is to repeat {@code reconcile()}: it is
   * idempotent and resumes where it stopped. Afterwards the winner is the only Active key of the
   * lineage with the names, and {@link #latest()} and {@link KmsKeys#findByName} return it from
   * everywhere.
   *
   * @return the winner, Active
   * @throws StateConflictException when the chosen newest key is not Active, the lineage cannot be
   *     followed (as {@link #latest()}), or it has more keys than one walk reads (256); nothing is
   *     joined
   * @throws UnsupportedException when the server refuses the links; nothing was deactivated
   * @throws PartialCompletionException when a step failed, also when another caller rotated the
   *     winner while this call ran; repeat the call, which chooses again
   */
  public KeyHandle reconcile() {
    return reconcile(true);
  }

  /**
   * {@link #reconcile()}; {@code own} false when this key was found from data others may control
   * (a pending-name record, {@link KmsKeys#reconcile(String)}), so its walk is bounded as one from a
   * stored record's key.
   */
  KeyHandle reconcile(boolean own) {
    return reconcile(own, null);
  }

  /**
   * What {@link #reconcile(boolean)} from this key would change now, for the name {@code name}
   * ({@link KmsKeys#reconcilePlan}): the same walk and refusals, and no change.
   */
  ReconcilePlan reconcilePlan(boolean own, String name) {
    requireKind("reconcile", ObjectKind.SYMMETRIC_KEY);
    return kms.call(
        "reconcilePlan",
        () -> {
          return planOf(name, reconcileTree(own));
        });
  }

  /**
   * {@link #reconcile(boolean)}; with {@code bound} ({@link KmsKeys#reconcile(String,
   * ReconcilePlan)}), refused before any change when it would do anything the plan does not list,
   * and then changing only what that check found.
   */
  KeyHandle reconcile(boolean own, ReconcilePlan bound) {
    requireKind("reconcile", ObjectKind.SYMMETRIC_KEY);
    return kms.call(
        "reconcile",
        () -> {
          Lineage.Tree tree = reconcileTree(own);
          ReconcilePlan now = null;
          if (bound != null) {
            now = planOf(bound.name(), tree);
            List<String> beyond = bound.beyond(now);
            if (!beyond.isEmpty())
              throw new StateConflictException(
                      "reconcile: the lineage the name "
                          + bound.name()
                          + " leads to changed since the plan was made: "
                          + String.join("; ", beyond)
                          + "; make a new plan. Nothing was changed",
                      null,
                      "reconcile",
                      now.winner().id(),
                      null,
                      null)
                  .because(StateConflictException.Conflict.NOT_AS_PLANNED);
          }
          ReconcilePlan within = now;
          List<KeyAttributes> tips = tree.tips();
          KeyAttributes first = tips.get(0);
          KeyHandle winner =
              new KeyHandle(keys, first.id(), ObjectKind.SYMMETRIC_KEY).knowing(first);
          Set<String> joining =
              within == null
                  ? null
                  : new HashSet<>(within.joined().stream().map(KeyAttributes::id).toList());
          List<KeyAttributes> others =
              tips.subList(1, tips.size()).stream()
                  .filter(t -> !compromised(t) && !destroyed(t))
                  .filter(t -> joining == null || joining.contains(t.id()))
                  .toList();
          // Each joined into the winner by its own Replacement Object link only: the winner has a
          // Replaced Object link already, and KMIP allows one of each.
          for (KeyAttributes other : others) join(other, winner);
          // A name an earlier run took off another key and did not give yet; then the names, then
          // the
          // states, of every other key of the tree, as read now (the joins changed links).
          Lineage.Tree joined =
              Lineage.tree("reconcile", winner.attributes(), true, null, keys::read);
          // The keys whose names go to the winner below: a record whose name one of them still
          // holds is
          // kept (a move that has not taken it off yet).
          Set<String> movedFrom = new HashSet<>();
          for (KeyAttributes k : joined.keys())
            if (!k.id().equals(winner.id()) && !joined.descends(k.id(), winner.id()))
              movedFrom.add(k.id());
          try {
            finishPending(
                "reconcile",
                joined.keys().stream()
                    .filter(k -> within == null || within.lineage().contains(k.id()))
                    .toList(),
                winner,
                movedFrom::contains);
          } catch (PartialCompletionException e) {
            throw e;
          } catch (KmsException | IllegalStateException e) {
            throw interrupted("giving " + first.id() + " a name an earlier move left on no key", e);
          }
          joined = Lineage.tree("reconcile", winner.attributes(), true, null, keys::read);
          // Rotated meanwhile by another caller: the winner is no longer the newest key, and
          // choosing
          // again is the repeat's job; a key newer than the winner is never superseded by it.
          if (!joined.newer(winner.id()).isEmpty())
            throw interrupted(
                "choosing the newest key",
                new StateConflictException(
                        "reconcile: "
                            + winner.id()
                            + " was replaced meanwhile by "
                            + joined.newer(winner.id()),
                        null,
                        "reconcile",
                        winner.id(),
                        null,
                        null)
                    .because(StateConflictException.Conflict.REPLACED));
          Lineage.Tree tree2 = joined;
          java.util.function.Predicate<KeyAttributes> older =
              k -> !k.id().equals(winner.id()) && !tree2.descends(k.id(), winner.id());
          for (KeyAttributes k : joined.keys())
            if (older.test(k) && !destroyed(k))
              for (String name : k.names())
                if (within == null
                    || within.namesMoved().getOrDefault(k.id(), List.of()).contains(name))
                  settledName(new KeyHandle(keys, k.id(), ObjectKind.SYMMETRIC_KEY), name, winner);
          // Only a key whose latest() is not cut short is revoked: its instances move to the winner
          // when
          // it refuses to encrypt. One with more than LIMIT rotations after it (a lineage
          // longer than latest() follows) stays Active: it still works, and nothing is lost.
          Set<String> superseded =
              within == null
                  ? null
                  : new HashSet<>(within.deactivated().stream().map(KeyAttributes::id).toList());
          Map<String, Integer> after = new HashMap<>();
          List<KeyHandle> deactivated = new ArrayList<>();
          for (KeyAttributes k : joined.keys())
            if (older.test(k)
                && k.state() == KeyState.ACTIVE
                && (superseded == null || superseded.contains(k.id()))
                && longestAfter(joined, k.id(), after) <= Lineage.LIMIT) {
              try {
                deactivate(k, winner);
              } catch (PartialCompletionException e) {
                if (deactivated.isEmpty() || !(e.getCause() instanceof RuntimeException cause))
                  throw e;
                throw PartialCompletionException.progress(
                    "reconcile",
                    deactivated,
                    List.of(),
                    "deactivating " + k.id() + " (superseded) failed",
                    cause);
              }
              deactivated.add(new KeyHandle(keys, k.id(), ObjectKind.SYMMETRIC_KEY));
            }
          return winner;
        });
  }

  /**
   * {@link #reconcile()}'s walk from this key, refused when it cannot choose a winner: more keys
   * than one walk reads, or a chosen newest key that is not Active.
   */
  private Lineage.Tree reconcileTree(boolean own) {
    Lineage.Tree tree = Lineage.tree("reconcile", attributes(), own, null, keys::read);
    // More keys than one walk reads (a fork of some 250 newest keys or more): nothing can be
    // chosen for everyone.
    if (tree.limit() != null)
      throw new StateConflictException(
              "reconcile: the rotation lineage of "
                  + id
                  + " cannot be read in one walk ("
                  + tree.limit().getMessage()
                  + "), so its newest key cannot be chosen: choose the key to keep by hand, give it the names, and"
                  + " deactivate the other newest keys (KeyHandle.deactivate(); they still decrypt through their own"
                  + " handles)",
              null,
              "reconcile",
              id,
              null,
              null)
          .because(StateConflictException.Conflict.LINEAGE);
    KeyAttributes first = tree.tips().get(0);
    if (first.state() != KeyState.ACTIVE)
      throw new StateConflictException(
              "reconcile: the newest key of the lineage of "
                  + id
                  + ", "
                  + first.id()
                  + ", is "
                  + first.state()
                  + ", not Active; activate it, or replace it (replaceCompromised when it is Compromised),"
                  + " then reconcile",
              null,
              "reconcile",
              first.id(),
              null,
              null)
          .observed(first.state());
    return tree;
  }

  /** The plan of {@link #reconcile()} on {@code tree} ({@link #reconcileTree}), for {@code name}. */
  private ReconcilePlan planOf(String name, Lineage.Tree tree) {
    List<KeyAttributes> tips = tree.tips();
    KeyAttributes winner = tips.get(0);
    List<KeyAttributes> joined =
        tips.subList(1, tips.size()).stream()
            .filter(t -> !compromised(t) && !destroyed(t))
            .toList();
    // Once the others are joined, every key but the winner is older than it: the names of each
    // move, and the Active ones are deactivated (a join is not a confirmed step, so it does not
    // lengthen a key's reach).
    List<KeyAttributes> others =
        tree.keys().stream()
            .filter(k -> !k.id().equals(winner.id()) && !destroyed(k))
            .sorted(Comparator.comparing(KeyAttributes::id, Lineage.IDENTIFIERS))
            .toList();
    Map<String, List<String>> names = new LinkedHashMap<>();
    for (KeyAttributes k : others) if (!k.names().isEmpty()) names.put(k.id(), k.names());
    Map<String, Integer> after = new HashMap<>();
    List<KeyAttributes> deactivated =
        others.stream()
            .filter(
                k ->
                    k.state() == KeyState.ACTIVE
                        && longestAfter(tree, k.id(), after) <= Lineage.LIMIT)
            .toList();
    Set<String> lineage = new HashSet<>();
    for (KeyAttributes k : tree.keys()) lineage.add(k.id());
    return new ReconcilePlan(kms.owner(), name, winner, joined, names, deactivated, lineage);
  }

  /**
   * The most confirmed steps forward from {@code id} within {@code tree} (memoized in {@code
   * known}); a cycle counts as more than {@link Lineage#LIMIT}.
   */
  private static int longestAfter(Lineage.Tree tree, String id, Map<String, Integer> known) {
    Integer done = known.get(id);
    if (done != null) return done;
    known.put(id, Lineage.LIMIT + 1); // while on the path: a cycle is too long
    int most = 0;
    for (String s : tree.successors(id))
      most = Math.max(most, Math.min(Lineage.LIMIT + 1, 1 + longestAfter(tree, s, known)));
    known.put(id, most);
    return most;
  }

  private static boolean destroyed(KeyAttributes k) {
    return k.state() == KeyState.DESTROYED || k.state() == KeyState.DESTROYED_COMPROMISED;
  }

  /**
   * {@link #reconcile()}'s join of {@code tip} into {@code winner}: the tip's Replacement Object link
   * to the winner, read back when its reply is lost, and nothing on the winner. The tip has
   * no Replacement Object link (it is a newest key) and the winner has its Replaced Object link
   * already, so no key gets a second link of either kind (KMIP 1.4 §3.35, 2.1 §4.30, 3.0 §4.35.18
   * allow one replacement object; the 3.0 Replaced Object Link is single-instance).
   */
  private void join(KeyAttributes tip, KeyHandle winner) {
    KeyHandle t = new KeyHandle(keys, tip.id(), ObjectKind.SYMMETRIC_KEY);
    String what = "linking " + tip.id() + " into " + winner.id();
    if (linksTo(t, LinkKind.REPLACEMENT, winner.id())) return;
    try {
      settled(
          what,
          () ->
              t.add(
                  "reconcile",
                  Attributes.link(Enums.LinkType.REPLACEMENT_OBJECT_LINK, winner.id())),
          () -> linksTo(t, LinkKind.REPLACEMENT, winner.id()));
    } catch (UnsupportedException refused) {
      // The tip may have been replaced since the walk read it (another caller's Re-key, or an
      // overlapping reconcile), and a server allows one Replacement Object link: read it again.
      List<String> now;
      try {
        now = t.attributes().links(LinkKind.REPLACEMENT);
      } catch (KmsException | IllegalStateException unreadable) {
        refused.addSuppressed(unreadable);
        throw refused;
      }
      if (now.isEmpty()) throw refused;
      throw interrupted(
          what,
          new StateConflictException(
                  "reconcile: "
                      + tip.id()
                      + " names "
                      + now
                      + " as its replacement now (another caller rotated or"
                      + " joined it meanwhile), so the server refused a second link",
                  refused,
                  "reconcile",
                  tip.id(),
                  null,
                  null)
              .because(StateConflictException.Conflict.REPLACED));
    }
  }

  /** {@link #reconcile()}'s move of {@code name} from {@code from} to {@code winner}. */
  private void settledName(KeyHandle from, String name, KeyHandle winner) {
    String what = "moving the name " + name + " from " + from.id() + " to " + winner.id();
    try {
      moveName("reconcile", name, from, winner);
    } catch (PartialCompletionException e) {
      throw e;
    } catch (KmsException | IllegalStateException e) {
      if (stranded(List.of(name), from, winner).isEmpty()) throw interrupted(what, e);
      // Taken off (names are unique) and not given: a repeat would not see it.
      throw PartialCompletionException.interrupted(
          "reconcile",
          what,
          "give "
              + winner.id()
              + " the name "
              + name
              + " by hand (it was taken off "
              + from.id()
              + " and is on neither key: kms.keys().handle(\""
              + winner.id()
              + "\").addName(\""
              + name
              + "\")), then"
              + " repeat reconcile() to resume",
          e);
    }
  }

  /**
   * {@link #reconcile()}'s deactivation of {@code k}, superseded by {@code winner} ({@link
   * #deactivate(RevocationReason)}: a Deactivate on KMIP 3.0, where a Revoke compromises), read back
   * when its reply is lost: done only when {@code k} is Deactivated.
   */
  private void deactivate(KeyAttributes k, KeyHandle winner) {
    KeyHandle h = new KeyHandle(keys, k.id(), ObjectKind.SYMMETRIC_KEY);
    settled(
        "deactivating " + k.id() + " (superseded)",
        () -> h.deactivate(RevocationReason.superseded("reconciled into " + winner.id())),
        () -> h.attributes().state() == KeyState.DEACTIVATED);
  }

  /**
   * One change of {@link #reconcile()}: done, or read back by {@code check} when its outcome is
   * unknown. A refusal of a link means the server will not link ({@link UnsupportedException}); any
   * other failure, or an outcome the check cannot settle, interrupts the call ({@link
   * PartialCompletionException}, repeat to resume).
   */
  private void settled(String what, Runnable change, java.util.function.BooleanSupplier check) {
    try {
      change.run();
    } catch (OutcomeUnknownException unknown) {
      try {
        if (check.getAsBoolean()) return;
      } catch (KmsException | IllegalStateException unreadable) {
        unknown.addSuppressed(unreadable);
      }
      throw interrupted(
          what + " had an unknown outcome, which reading the key did not settle", unknown);
    } catch (UnsupportedException | InvalidRequestException | PermissionDeniedException refused) {
      if (!what.startsWith("linking") || Failures.credentialsRefused(refused))
        throw interrupted(what, refused);
      throw new UnsupportedException(
          "reconcile: the server refused "
              + what
              + " ("
              + refused.getMessage()
              + "), so the newest keys"
              + " cannot be joined; nothing was deactivated. Choose the key to keep, give it the names, and"
              + " deactivate the others by hand (KeyHandle.deactivate(); they still decrypt, through their own"
              + " handles)",
          refused,
          "reconcile",
          id,
          null,
          null);
    } catch (KmsException | IllegalStateException failed) {
      throw interrupted(what + " failed", failed);
    }
  }

  private static PartialCompletionException interrupted(String what, RuntimeException cause) {
    return PartialCompletionException.interrupted(
        "reconcile", what, "repeat reconcile() to resume: it is idempotent", cause);
  }

  /**
   * Destroys the older keys of this key's rotation lineage, and returns the keys this call
   * destroyed. This is the last step of a rotation, once nothing needs the old keys.
   *
   * <p><b>This cannot be undone.</b> Destroyed keys decrypt nothing. Retire only after every record
   * and every retained copy, such as backups and snapshots, has moved to the newest key ({@link
   * CurrentKey#rewrapRecord}, {@link CurrentKey#rewrapKey}, {@link CurrentKey#rewrapHeader}). Run it
   * from the rotation job, or while that job does not run. Call it on the lineage's only newest key.
   * Get that key from {@link CurrentKey#refresh()}, because {@link CurrentKey#handle()} may hold an
   * older key until its next check. Check the lineage with {@link #lineage()}. When callers rotated
   * at the same time, join the newest keys with {@link #reconcile()} first.
   *
   * <pre>{@code
   * // current: the CurrentKey of "invoices-kek"; every record is under its newest key now
   * KeyHandle newest = current.refresh();
   * List<KeyHandle> destroyed = newest.retirePredecessors(RevocationReason.superseded("rotated"));
   * }</pre>
   *
   * <p>Active keys are revoked with {@code reason} and then destroyed, so with a reason that is not
   * a compromise they end Destroyed, not Destroyed Compromised. Deactivated and Compromised keys are
   * destroyed without another Revoke. A Pre-Active key is destroyed as it is, unless the reason is a
   * compromise. Only keys of the confirmed lineage are touched, never keys that only share its name
   * ({@link #leftovers()} lists those). The order keeps every remaining key linked to this one, so
   * a call that stops part-way never leaves a gap in the chain. Repeat a failed call, and it
   * continues where it stopped. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/kms-design.md#retiring-keys">Retiring
   * keys</a> for the exact order and reach.
   *
   * @param reason the revocation reason, usually {@link RevocationReason#superseded}
   * @return the keys destroyed by this call, in that order; empty when there was nothing to retire
   * @throws StateConflictException when this key is Compromised (replace it with {@link
   *     #replaceCompromised} and retire from the replacement), the lineage has a newest key other
   *     than this one (reconcile first), or it cannot be followed back past a key that exists but
   *     cannot be read; nothing is destroyed
   * @throws OutcomeUnknownException when the first key's request has an unknown outcome that
   *     cannot be confirmed; repeat the call
   * @throws PartialCompletionException when a step failed after a key was deactivated or destroyed:
   *     {@link PartialCompletionException#destroyed()} and {@link
   *     PartialCompletionException#deactivated()} list them, and the cause is the step's failure;
   *     repeat the call to continue
   * @throws UnsupportedException when more than 64 rotations that are not destroyed lie behind this
   *     key; nothing is destroyed. Retire in two steps, first with {@link
   *     #retirePredecessorsOlderThan}
   * @see <a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#retire-old-keys">Retire
   *     old keys</a>
   */
  public List<KeyHandle> retirePredecessors(RevocationReason reason) {
    Objects.requireNonNull(reason, "reason");
    return kms.call(
        "retirePredecessors",
        () -> {
          return retired(
              "retirePredecessors", predecessors("retirePredecessors", attributes()), reason);
        });
  }

  /**
   * The keys {@link #retirePredecessors(RevocationReason)} would destroy now, in the order it
   * destroys them, without changing anything. Show it, have it confirmed, then retire exactly
   * these keys with {@link #retirePredecessors(RevocationReason, RetirementPlan)}:
   *
   * <pre>{@code
   * RetirementPlan plan = newest.retirementPlan();
   * // show plan.keys() and ask for approval, then:
   * newest.retirePredecessors(RevocationReason.superseded("rotated"), plan);
   * }</pre>
   *
   * <p>The plan comes from the walk and the checks the retirement makes, so it is refused in the
   * same cases. Keys already destroyed are left out. Same reads as the retirement, no change.
   *
   * @return the plan; its {@link RetirementPlan#keys()} are empty when there is nothing to retire
   * @throws StateConflictException as {@link #retirePredecessors(RevocationReason)}
   * @throws UnsupportedException as {@link #retirePredecessors(RevocationReason)}
   * @since 0.10.0
   */
  public RetirementPlan retirementPlan() {
    return kms.call(
        "retirementPlan",
        () -> {
          return plan(null, predecessors("retirementPlan", attributes()));
        });
  }

  /**
   * The keys {@link #retirePredecessorsOlderThan} would destroy now, keeping {@code keepFrom} and
   * every newer key, in the order it destroys them, without changing anything. As {@link
   * #retirementPlan()}; the walk starts at {@code keepFrom}, as the retirement's does, so it
   * reaches 64 rotations either way. {@code keepFrom} equal to this key is {@link
   * #retirementPlan()}.
   *
   * @param keepFrom the oldest key to keep, a handle of the same {@link Kms}
   * @return the plan
   * @throws IllegalArgumentException when {@code keepFrom} is a handle of another {@link Kms}
   * @throws KmsException as {@link #retirePredecessorsOlderThan}
   * @since 0.10.0
   */
  public RetirementPlan retirementPlanOlderThan(KeyHandle keepFrom) {
    Objects.requireNonNull(keepFrom, "keepFrom");
    return kms.call(
        "retirementPlanOlderThan",
        () ->
            keepFrom.id.equals(id) && keepFrom.sameKms(kms)
                ? retirementPlan()
                : plan(keepFrom.id, olderThan("retirementPlanOlderThan", keepFrom)));
  }

  /**
   * Retires the keys of {@code plan}, and no other: {@link #retirePredecessors(RevocationReason)}
   * for a plan from {@link #retirementPlan()}, {@link #retirePredecessorsOlderThan} for one from
   * {@link #retirementPlanOlderThan}. Use it after the plan was shown and confirmed.
   *
   * <p>The set is computed again, as the retirement always does, and compared with the plan before
   * anything is changed. When it has a key the plan does not list, or a key of the plan is no
   * longer in it but not destroyed (another caller rotated, reconciled or retired meanwhile), the
   * call is refused and nothing is changed: make a new plan. Then only the keys compared are
   * retired. Keys of the plan destroyed meanwhile are passed over, so repeating the call with the
   * same plan resumes a retirement that stopped. The comparison is made once, before the first
   * change: a change another caller makes after it is not detected, so change a lineage from one
   * place at a time.
   *
   * @param reason the revocation reason, usually {@link RevocationReason#superseded}
   * @param plan a plan this key made, on this {@code Kms}
   * @return the keys destroyed by this call, in that order
   * @throws IllegalArgumentException when {@code plan} was made from another key or {@link Kms}
   * @throws StateConflictException ({@link StateConflictException.Conflict#NOT_AS_PLANNED}) when the
   *     keys to retire are no longer those of the plan, or as
   *     the retirement; nothing is changed
   * @throws PartialCompletionException as {@link #retirePredecessors(RevocationReason)}
   * @throws KmsException as {@link #retirePredecessors(RevocationReason)}
   * @since 0.10.0
   */
  public List<KeyHandle> retirePredecessors(RevocationReason reason, RetirementPlan plan) {
    Objects.requireNonNull(reason, "reason");
    Objects.requireNonNull(plan, "plan");
    madeHere("retirePredecessors", plan);
    String operation =
        plan.keepFromId().isPresent() ? "retirePredecessorsOlderThan" : "retirePredecessors";
    return kms.call(
        operation,
        () -> {
          List<KeyAttributes> now =
              plan.keepFromId().isPresent()
                  ? olderThan(operation, keys.handle(plan.keepFromId().get()))
                  : predecessors(operation, attributes());
          matchesPlan(operation, plan, now, false);
          return retired(operation, now, reason);
        });
  }

  /** Refuses ({@link IllegalArgumentException}) a plan made from another key or {@link Kms}. */
  private void madeHere(String operation, RetirementPlan plan) {
    if (plan.owner() != kms.owner() || !plan.newestId().equals(id))
      throw new IllegalArgumentException(
          operation
              + ": the plan was made from "
              + plan.newestId()
              + (plan.owner() != kms.owner() ? " on another Kms" : "")
              + ", not from "
              + id
              + "; make the plan from this handle");
  }

  /**
   * Compares {@code now}, the keys to act on as computed again, with {@code plan}, before anything
   * is changed: refused when a key that is not destroyed is not in the plan, or a key of the plan is
   * no longer in the set and not destroyed. With {@code deactivating}, also when a key is Active
   * now that the plan does not list as Active (it was activated since the plan was made).
   */
  private void matchesPlan(
      String operation, RetirementPlan plan, List<KeyAttributes> now, boolean deactivating) {
    Map<String, KeyState> planned = new HashMap<>();
    for (KeyAttributes k : plan.keys()) planned.put(k.id(), k.state());
    List<String> unplanned = new ArrayList<>();
    List<String> activated = new ArrayList<>();
    Set<String> present = new HashSet<>();
    for (KeyAttributes k : now) {
      if (Lineage.destroyed(k)) continue;
      present.add(k.id());
      KeyState was = planned.get(k.id());
      if (was == null) unplanned.add(k.id());
      else if (deactivating && k.state() == KeyState.ACTIVE && was != KeyState.ACTIVE)
        activated.add(k.id());
    }
    List<String> moved = new ArrayList<>();
    for (String p : plan.ids()) {
      if (present.contains(p)) continue;
      Optional<KeyAttributes> read = keys.read(p);
      if (read.isPresent() && !Lineage.destroyed(read.get())) moved.add(p);
    }
    if (unplanned.isEmpty() && moved.isEmpty() && activated.isEmpty()) return;
    List<String> first = new ArrayList<>(unplanned);
    first.addAll(activated);
    first.addAll(moved);
    throw new StateConflictException(
            Kms.named(operation)
                + ": the keys to "
                + (deactivating ? "deactivate" : "retire")
                + " are no longer those of the plan"
                + (unplanned.isEmpty() ? "" : "; not planned: " + unplanned)
                + (activated.isEmpty() ? "" : "; Active now, not when planned: " + activated)
                + (moved.isEmpty() ? "" : "; planned but no longer older: " + moved)
                + " (the lineage changed since the plan was made); make a new plan. Nothing was "
                + (deactivating ? "deactivated" : "retired"),
            null,
            Kms.named(operation),
            first.get(0),
            null,
            null)
        .because(StateConflictException.Conflict.NOT_AS_PLANNED);
  }

  /** The plan of {@code retiring} (destroyed keys left out), from this key, keeping {@code keepFrom}. */
  private RetirementPlan plan(String keepFrom, List<KeyAttributes> retiring) {
    List<KeyAttributes> left = new ArrayList<>();
    for (KeyAttributes k : retiring) {
      KeyState state = knownState("retirementPlan", k.id(), k);
      if (state != KeyState.DESTROYED && state != KeyState.DESTROYED_COMPROMISED) left.add(k);
    }
    return new RetirementPlan(kms.owner(), id, keepFrom, left);
  }

  /**
   * Retires {@code keys}, in their order, as {@link #retirePredecessors} does: each revoked with
   * {@code reason} (unless Deactivated or Compromised already, or Pre-Active and {@code reason} is
   * not a compromise) and destroyed; destroyed keys passed over. A failure once a key was changed
   * is a {@link PartialCompletionException} that lists the keys changed.
   */
  private List<KeyHandle> retired(
      String operation, List<KeyAttributes> keys, RevocationReason reason) {
    List<KeyHandle> retired = new ArrayList<>();
    for (KeyAttributes k : keys) {
      KeyHandle h = new KeyHandle(this.keys, k.id(), ObjectKind.SYMMETRIC_KEY);
      boolean revoked = false;
      String step = "retiring " + k.id() + " failed";
      try {
        KeyState state = knownState(operation, k.id(), k);
        if (state == KeyState.DESTROYED || state == KeyState.DESTROYED_COMPROMISED) continue;
        // A Deactivated key (deactivatePredecessors, or its Deactivation Date came) is not revoked
        // again. A Pre-Active key is destroyed as it is, unless the reason is a compromise: KMIP
        // has no transition from Pre-Active to Deactivated.
        if (state == KeyState.ACTIVE || (state == KeyState.PRE_ACTIVE && reason.compromise())) {
          step = "revoking " + k.id() + " failed";
          revoked = revokedOrRetired(h, reason);
        }
        step = "destroying " + k.id() + " failed";
        h.destroy();
      } catch (KmsException | IllegalStateException e) {
        if (retired.isEmpty() && !revoked) throw e;
        throw PartialCompletionException.progress(
            Kms.named(operation), revoked ? List.of(h) : List.of(), retired, step, e);
      }
      retired.add(h);
    }
    return retired;
  }

  /**
   * Destroys the keys of this key's rotation lineage that are older than {@code keepFrom}, and
   * keeps {@code keepFrom} and every newer key. Use it when records under {@code keepFrom} are still
   * needed but the keys before it are not.
   *
   * <p><b>This cannot be undone.</b> Choose {@code keepFrom} from {@link #lineage()} after checking
   * that nothing still needs a key older than it:
   *
   * <pre>{@code
   * // kek: the lineage's only newest key; oldestStillNeeded: one of the listed identifiers
   * List<LineageKey> keys = kek.lineage();                      // newest first
   * KeyHandle keepFrom = kms.keys().handle(oldestStillNeeded);
   * kek.retirePredecessorsOlderThan(keepFrom, RevocationReason.superseded("rotated"));
   * }</pre>
   *
   * <p>The keys older than {@code keepFrom} are those it descends from, and the keys {@link
   * #reconcile()} joined into one of them (see {@link LineageKey}). Everything else is as for
   * {@link #retirePredecessors}. {@code keepFrom} equal to this key is {@link #retirePredecessors}.
   * The call is also refused when keeping {@code keepFrom} would cut a key off from this one, such
   * as a branch {@link #reconcile()} joined into a key newer than {@code keepFrom}. Keep from an
   * older key then, or re-seal those keys' records and retire the whole lineage.
   *
   * <p>The walk starts at {@code keepFrom} and reaches 64 rotations either way. When {@link
   * #retirePredecessors} refuses a lineage as too long, {@link #lineage()} on this key refuses it
   * too. Retire it in two steps, which reach up to 128 rotations: first this call, with a {@code
   * keepFrom} at most 64 rotations from each end, then {@link #retirePredecessors}. To choose
   * {@code keepFrom}, call {@link #lineage()} on a key nearer the middle.
   *
   * @param keepFrom the oldest key to keep, a handle of the same {@link Kms}; not null
   * @param reason the revocation reason, usually {@link RevocationReason#superseded}; not null
   * @return the keys destroyed by this call, in that order; empty when there was nothing to retire
   * @throws IllegalArgumentException when {@code keepFrom} is a handle of another {@link Kms}
   * @throws KeyMismatchException when {@code keepFrom} is not in this key's lineage; nothing is
   *     retired
   * @throws StateConflictException when this key is Compromised, the lineage has a newest key other
   *     than this one (reconcile first), cannot be followed past a key that exists but cannot be
   *     read, or keeping {@code keepFrom} would cut keys off from this one; nothing is retired
   * @throws UnsupportedException when the keys older than {@code keepFrom} lie more than 64
   *     rotations before it, or this key more than 64 after it (nothing is retired)
   * @throws PartialCompletionException as {@link #retirePredecessors(RevocationReason)}
   * @see <a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#retiring-part-of-a-lineage">Retiring
   *     part of a lineage</a>
   * @since 0.10.0
   */
  public List<KeyHandle> retirePredecessorsOlderThan(KeyHandle keepFrom, RevocationReason reason) {
    Objects.requireNonNull(keepFrom, "keepFrom");
    Objects.requireNonNull(reason, "reason");
    String operation = "retirePredecessorsOlderThan";
    return kms.call(
        operation,
        () ->
            keepFrom.id.equals(id) && keepFrom.sameKms(kms)
                ? retirePredecessors(reason)
                : retired(operation, olderThan(operation, keepFrom), reason));
  }

  /**
   * The keys {@link #retirePredecessorsOlderThan} retires, oldest first, after its checks; the
   * walk starts at {@code keepFrom}.
   */
  private List<KeyAttributes> olderThan(String operation, KeyHandle keepFrom) {
    if (!keepFrom.sameKms(kms))
      throw new IllegalArgumentException(
          operation
              + ": keepFrom ("
              + keepFrom.id
              + ") is a handle of another Kms; an identifier names an object"
              + " only on its own server");
    KeyAttributes mine = attributes();
    knowing(mine);
    notCompromised(operation, mine);
    // Walked from keepFrom, which must reach the oldest keys and this one: so a lineage up to
    // twice as long as one walk follows can be retired in steps.
    Lineage.Tree tree =
        Lineage.tree(operation, keepFrom.attributes(), true, null, keys::read, false);
    if (tree.keys().stream().noneMatch(k -> k.id().equals(id))) {
      if (tree.limit() != null) throw tree.limit();
      if (tree.beyondForward())
        throw new UnsupportedException(
            operation
                + ": "
                + id
                + " is not within "
                + Lineage.LIMIT
                + " rotations after "
                + keepFrom.id
                + ", as far as its lineage was followed; keep from a newer key. Nothing was retired",
            null,
            operation,
            keepFrom.id,
            null,
            null);
      List<Lineage.Gap> gaps = new ArrayList<>(tree.gapsForward());
      gaps.addAll(tree.gapsBack());
      if (!gaps.isEmpty())
        throw Lineage.broken(
            operation,
            keepFrom.id,
            "this key, " + id + ",",
            gaps,
            "keep from a key whose lineage reaches it. Nothing was retired");
      throw new KeyMismatchException(
          operation
              + ": "
              + keepFrom.id
              + " is not in the rotation lineage of "
              + id
              + " (no step confirmed by"
              + " both keys' links leads from one to the other), so it cannot say which of its keys are older;"
              + " choose keepFrom from "
              + id
              + "'s lineage(). Nothing was retired",
          null,
          operation,
          keepFrom.id,
          null,
          null);
    }
    if (tree.beyondBack())
      throw new UnsupportedException(
          operation
              + ": "
              + keepFrom.id
              + " has more than "
              + Lineage.LIMIT
              + " rotations behind it that are not"
              + " destroyed, so the oldest keys cannot be reached; retire in steps, keeping from an older key"
              + " first. Nothing was retired",
          null,
          operation,
          keepFrom.id,
          null,
          null);
    onlyNewest(operation, tree);
    noUnreadableLinks(operation, tree);
    // The keys keepFrom descends from, joins included.
    Set<String> older = new HashSet<>();
    Deque<String> queue = new ArrayDeque<>(older(tree, keepFrom.id));
    while (!queue.isEmpty()) {
      String k = queue.poll();
      if (older.add(k)) queue.addAll(older(tree, k));
    }
    older.remove(id);
    // What is kept must still reach this key by confirmed steps through kept keys: the walks
    // never
    // follow a join, and the keys retired may be purged.
    Set<String> reached = new HashSet<>(Set.of(id));
    Deque<String> around = new ArrayDeque<>(List.of(id));
    while (!around.isEmpty()) {
      String k = around.poll();
      Set<String> next = new LinkedHashSet<>(tree.successors(k));
      next.addAll(tree.predecessors(k));
      for (String n : next) if (!older.contains(n) && reached.add(n)) around.add(n);
    }
    List<String> cut =
        tree.keys().stream()
            .filter(
                k -> !older.contains(k.id()) && !reached.contains(k.id()) && !Lineage.destroyed(k))
            .map(KeyAttributes::id)
            .sorted(Lineage.IDENTIFIERS)
            .toList();
    if (!cut.isEmpty())
      throw new StateConflictException(
              operation
                  + ": retiring the keys older than "
                  + keepFrom.id
                  + " would cut "
                  + cut
                  + " off from "
                  + id
                  + ": their only confirmed links to it pass through keys this call would retire (a branch"
                  + " reconcile() joined into a key newer than "
                  + keepFrom.id
                  + ", or one a stopped retirement left);"
                  + " keep from an older key, or re-seal their records and retire the whole lineage"
                  + " (retirePredecessors). Nothing was retired",
              null,
              operation,
              keepFrom.id,
              null,
              null)
          .because(StateConflictException.Conflict.LINEAGE);
    return oldestFirst(tree).stream().filter(k -> older.contains(k.id())).toList();
  }

  /**
   * The keys of this key's rotation lineage, newest first, with where each stands ({@link
   * LineageKey}).
   *
   * <p>A rotation lineage is a key and every key that replaced it or that it replaced, by rotation
   * or by compromise replacement. Records sealed under any key of it open through any other while
   * those keys exist and lie within 64 rotations. The SDK follows only steps that both keys
   * confirm: the newer key's Replaced Object link and the older key's Replacement Object link,
   * which Re-key sets. A name or a one-sided link proves nothing (see {@link
   * KeyAttributes#replacedLink()}).
   *
   * <p>The listing is the lineage {@link #latest()} reads, the same from any of its keys within
   * reach. It includes the other branches of a key callers rotated at the same time, and the keys
   * {@link #reconcile()} joined in. Each key comes before every key it replaced, so a lineage
   * without branches is listed from its current key back to its first. Going back, the listing
   * stops at a destroyed key, since the keys before it were retired before it. A key that was
   * destroyed and purged is not listed.
   *
   * <p>Use it to choose what to retire ({@link #retirePredecessorsOlderThan}), for status pages, or
   * for a list of the keys an application trusts ({@code KeyQuery.byIds(...)}). One Get
   * Attributes per key listed, a few more for joined keys and purged links, and never more than 256
   * reads in all. No key is changed.
   *
   * @return the keys, newest first; this key among them; unmodifiable, never empty
   * @throws UnsupportedException when the lineage goes more than 64 rotations back from this key
   *     (keys behind a destroyed one do not count) or on from it, or has more than 256 keys: list
   *     it from a key nearer its oldest or newest end, and retire the oldest keys to keep it within
   *     reach
   * @throws StateConflictException when a link names a key that exists but cannot be read, or the
   *     newest key cannot be found (as {@link #latest()})
   * @throws ProtocolViolationException when the links form a cycle
   * @since 0.10.0
   */
  public List<LineageKey> lineage() {
    return kms.call(
        "lineage",
        () -> {
          KeyAttributes mine = attributes();
          knowing(mine);
          Lineage.Tree tree = Lineage.tree("lineage", mine, true, null, keys::read, false);
          if (tree.limit() != null)
            throw new UnsupportedException(
                "lineage: the rotation lineage of "
                    + id
                    + " has more keys than one walk reads ("
                    + Lineage.BUDGET
                    + "), so it cannot be listed; list it from a handle on a key nearer its oldest or newest end",
                tree.limit(),
                "lineage",
                id,
                null,
                null);
          if (tree.beyondBack())
            throw new UnsupportedException(
                "lineage: "
                    + id
                    + " has more than "
                    + Lineage.LIMIT
                    + " rotations behind it that are not destroyed,"
                    + " so its oldest keys cannot be listed; list them from a handle on an older key, and retire the"
                    + " oldest keys (retirePredecessorsOlderThan) to keep the lineage within reach",
                null,
                "lineage",
                id,
                null,
                null);
          noUnreadableLinks("lineage", tree);
          List<KeyAttributes> tips = tree.tips();
          Set<String> newest = new HashSet<>();
          for (KeyAttributes t : tips) newest.add(t.id());
          String chosen = tips.get(0).id();
          // The chosen newest key and the keys it descends from by confirmed steps: the rest are
          // branches.
          Set<String> main = new HashSet<>(Set.of(chosen));
          Deque<String> back = new ArrayDeque<>(List.of(chosen));
          while (!back.isEmpty())
            for (String p : tree.predecessors(back.poll())) if (main.add(p)) back.add(p);
          Set<String> in = new HashSet<>();
          for (KeyAttributes k : tree.keys()) in.add(k.id());
          Comparator<KeyAttributes> order =
              Comparator.comparing((KeyAttributes k) -> !k.id().equals(chosen))
                  .thenComparing(Lineage.EARLIEST.reversed());
          List<KeyAttributes> left = new ArrayList<>(tree.keys());
          Set<String> listed = new HashSet<>();
          List<LineageKey> out = new ArrayList<>();
          while (!left.isEmpty()) {
            KeyAttributes next =
                left.stream()
                    .filter(
                        k ->
                            tree.newer(k.id()).stream()
                                .allMatch(n -> listed.contains(n) || !in.contains(n)))
                    .min(order)
                    .orElseThrow(
                        () ->
                            new ProtocolViolationException(
                                "lineage: the links of " + id + "'s lineage form a cycle",
                                null,
                                "lineage",
                                id,
                                null,
                                null));
            left.remove(next);
            listed.add(next.id());
            String k = next.id();
            out.add(
                new LineageKey(
                    next,
                    tree.predecessors(k).stream()
                        .filter(in::contains)
                        .sorted(Lineage.IDENTIFIERS)
                        .toList(),
                    tree.successors(k).stream()
                        .filter(in::contains)
                        .sorted(Lineage.IDENTIFIERS)
                        .toList(),
                    tree.joinedInto(k).stream().sorted(Lineage.IDENTIFIERS).toList(),
                    newest.contains(k),
                    !main.contains(k)));
          }
          return List.copyOf(out);
        });
  }

  /**
   * Deactivates the older keys of this key's rotation lineage without destroying them: {@link
   * #deactivatePredecessors(RevocationReason)} with {@link RevocationReason#superseded}
   * ("rotated"). This is the middle step of a rotation with a grace period.
   *
   * @return the keys this call deactivated, in {@link #retirePredecessors}'s order; empty when
   *     there was nothing to do
   * @throws KmsException as {@link #deactivatePredecessors(RevocationReason)}
   * @see <a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#rotation-with-a-grace-period">Rotation
   *     with a grace period</a>
   */
  public List<KeyHandle> deactivatePredecessors() {
    return deactivatePredecessors(RevocationReason.superseded("rotated"));
  }

  /**
   * Deactivates the older keys of this key's rotation lineage, and destroys nothing. Run it once
   * the grace period after a rotation is over; {@link #retirePredecessors} destroys the keys later.
   *
   * <p>Each key is deactivated as {@link #deactivate(RevocationReason)} does: a Revoke with {@code
   * reason} up to KMIP 2.1, and the Deactivate operation on the KMIP 3.0 draft, where a Revoke
   * would make it Compromised. It no longer encrypts, and still decrypts where the server's policy
   * allows. Instances still sealing under one are refused, and a {@link CurrentKey} moves to this
   * key.
   *
   * <p>The keys are those {@link #retirePredecessors} would retire, in the same order and under the
   * same refusals. This key must be Active. Keys already Deactivated, Compromised or destroyed are
   * passed over, and so are Pre-Active keys, since KMIP has no transition from Pre-Active to
   * Deactivated. Idempotent: repeat a failed call to continue where it stopped. A request whose
   * outcome is unknown, or refused because of the key's state, is read back first. To have the
   * keys approved first, use {@link #deactivatePredecessors(RevocationReason, RetirementPlan)}.
   *
   * @param reason the revocation reason, usually {@link RevocationReason#superseded}; not a
   *     compromise
   * @return the keys this call deactivated, in {@link #retirePredecessors}'s order; empty when
   *     there was nothing to do
   * @throws IllegalArgumentException when {@code reason} is a compromise ({@link
   *     #replaceCompromised} handles a compromise)
   * @throws StateConflictException when this key is not Active, the lineage has a newest key other
   *     than this one (reconcile first), or it cannot be followed back past a key that exists but
   *     cannot be read; nothing is deactivated
   * @throws UnsupportedException when more than 64 rotations that are not destroyed lie behind this
   *     key (nothing is deactivated)
   * @throws PartialCompletionException when a step failed after a key was deactivated: {@link
   *     PartialCompletionException#deactivated()} lists them; repeat the call to continue
   * @see <a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#rotation-with-a-grace-period">Rotation
   *     with a grace period</a>
   */
  public List<KeyHandle> deactivatePredecessors(RevocationReason reason) {
    notCompromise(reason);
    return kms.call(
        "deactivatePredecessors",
        () -> {
          KeyAttributes mine = activeNewest();
          return deactivated(predecessors("deactivatePredecessors", mine), reason);
        });
  }

  /**
   * Deactivates the keys of {@code plan} that were Active when it was made, and no other: {@link
   * #deactivatePredecessors(RevocationReason)} bound to a plan from {@link #retirementPlan()}. Use it
   * after the plan was shown and confirmed; deactivation is the first half of a retirement, over the
   * same keys in the same order.
   *
   * <pre>{@code
   * RetirementPlan plan = newest.retirementPlan();
   * // show the Active keys of plan.keys() and ask for approval, then:
   * newest.deactivatePredecessors(RevocationReason.superseded("rotated"), plan);
   * }</pre>
   *
   * <p>The keys are computed again and compared with the plan before anything is changed. When the
   * set has a key the plan does not list, a key of the plan is no longer in it but not destroyed,
   * or a key is Active now that was not Active in the plan (activated meanwhile), the call is
   * refused and nothing is changed: make a new plan. A key planned Active that is no longer Active
   * is passed over. The comparison is made once, before the first change: change a lineage from one
   * place at a time.
   *
   * @param reason the revocation reason, usually {@link RevocationReason#superseded}; not a
   *     compromise
   * @param plan a plan this key made with {@link #retirementPlan()}, on this {@code Kms}
   * @return the keys this call deactivated, in the plan's order
   * @throws IllegalArgumentException when {@code reason} is a compromise, or {@code plan} was made
   *     from another key or {@link Kms}, or by {@link #retirementPlanOlderThan}
   * @throws StateConflictException ({@link StateConflictException.Conflict#NOT_AS_PLANNED}) when the
   *     keys to deactivate are no longer those of the plan, or
   *     as {@link #deactivatePredecessors(RevocationReason)}; nothing is changed
   * @throws PartialCompletionException as {@link #deactivatePredecessors(RevocationReason)}
   * @throws KmsException as {@link #deactivatePredecessors(RevocationReason)}
   * @since 0.10.0
   */
  public List<KeyHandle> deactivatePredecessors(RevocationReason reason, RetirementPlan plan) {
    notCompromise(reason);
    Objects.requireNonNull(plan, "plan");
    madeHere("deactivatePredecessors", plan);
    if (plan.keepFromId().isPresent())
      throw new IllegalArgumentException(
          "deactivatePredecessors: the plan keeps from "
              + plan.keepFromId().get()
              + " (retirementPlanOlderThan); deactivatePredecessors takes a plan from"
              + " retirementPlan()");
    return kms.call(
        "deactivatePredecessors",
        () -> {
          KeyAttributes mine = activeNewest();
          List<KeyAttributes> now = predecessors("deactivatePredecessors", mine);
          matchesPlan("deactivatePredecessors", plan, now, true);
          Set<String> active = new HashSet<>();
          for (KeyAttributes k : plan.keys()) if (k.state() == KeyState.ACTIVE) active.add(k.id());
          return deactivated(now.stream().filter(k -> active.contains(k.id())).toList(), reason);
        });
  }

  private static void notCompromise(RevocationReason reason) {
    Objects.requireNonNull(reason, "reason");
    if (reason.compromise())
      throw new IllegalArgumentException(
          "deactivatePredecessors: "
              + reason.kind()
              + " makes the keys Compromised, not Deactivated; recover a"
              + " compromised key with replaceCompromised(reason)");
  }

  /** This key, as read, refused unless Active: {@link #deactivatePredecessors}' newest key. */
  private KeyAttributes activeNewest() {
    KeyAttributes mine = attributes();
    KeyState own = knownState("deactivatePredecessors", id, mine);
    if (own != KeyState.ACTIVE)
      throw new StateConflictException(
              "deactivatePredecessors: "
                  + id
                  + " is "
                  + own
                  + ", not Active, so deactivating the keys before it"
                  + " would leave its lineage nothing to seal under; nothing was deactivated",
              null,
              "deactivatePredecessors",
              id,
              null,
              null)
          .observed(own);
    return mine;
  }

  /**
   * Deactivates the Active keys of {@code keys}, in order, as {@link #deactivatePredecessors}
   * does; a failure once a key was deactivated is a {@link PartialCompletionException}.
   */
  private List<KeyHandle> deactivated(List<KeyAttributes> keys, RevocationReason reason) {
    List<KeyHandle> deactivated = new ArrayList<>();
    for (KeyAttributes k : keys) {
      try {
        KeyState state = knownState("deactivatePredecessors", k.id(), k);
        // A Pre-Active key is passed over: KMIP has no transition from Pre-Active to
        // Deactivated, and it encrypts nothing until it is Active.
        if (state != KeyState.ACTIVE) continue;
        KeyHandle h = new KeyHandle(this.keys, k.id(), ObjectKind.SYMMETRIC_KEY);
        if (revokedOrRetired(h, reason)) deactivated.add(h);
      } catch (KmsException | IllegalStateException e) {
        if (deactivated.isEmpty()) throw e;
        throw PartialCompletionException.progress(
            "deactivatePredecessors",
            deactivated,
            List.of(),
            "deactivating " + k.id() + " failed",
            e);
      }
    }
    return deactivated;
  }

  /**
   * The keys {@link #retirePredecessors} and {@link #deactivatePredecessors} act on, oldest first,
   * after their checks: this key ({@code mine}, as read) must be the lineage's only newest key, the
   * lineage within reach, and no link unresolved to a key that still exists.
   */
  private List<KeyAttributes> predecessors(String operation, KeyAttributes mine) {
    boolean retire = operation.startsWith("retire");
    if (retire) notCompromised(operation, mine);
    // Going back, the walk stops at a destroyed key: the keys before it were retired before it, and
    // a server that keeps destroyed keys with their links would otherwise stop every retirement
    // after 64 rotations, however often it ran.
    Lineage.Tree tree = Lineage.tree(operation, mine, true, null, keys::read, false);
    if (tree.beyondBack())
      throw new UnsupportedException(
          operation
              + ": "
              + id
              + " has more than "
              + Lineage.LIMIT
              + " rotations behind it that are not"
              + " destroyed, so its oldest keys cannot be reached; "
              + (retire
                  ? "retire them in steps with retirePredecessorsOlderThan(keepFrom, reason), keeping from a key at"
                      + " most "
                      + Lineage.LIMIT
                      + " rotations from the oldest key and from this one"
                  : "retire the oldest keys first (retirePredecessorsOlderThan), or deactivate them by hand, oldest"
                      + " first (KeyHandle.deactivate())")
              + ". Nothing was "
              + (retire ? "retired" : "deactivated"),
          null,
          operation,
          id,
          null,
          null);
    onlyNewest(operation, tree);
    noUnreadableLinks(operation, tree);
    return oldestFirst(tree);
  }

  /**
   * Refuses a retirement from this key ({@code mine}, as read) when it is Compromised: the keys
   * before it may be the lineage's only keys that are not, and its records need a replacement.
   */
  private void notCompromised(String operation, KeyAttributes mine) {
    if (mine.state() != KeyState.COMPROMISED) return;
    throw new StateConflictException(
            Kms.named(operation)
                + ": "
                + id
                + " is COMPROMISED, so the keys before it are not retired (they may be the"
                + " lineage's only keys that are not compromised): replace it first with"
                + " replaceCompromised(reason), re-seal its records under the replacement, then"
                + " retire from the replacement. Nothing was retired",
            null,
            Kms.named(operation),
            id,
            null,
            null)
        .observed(KeyState.COMPROMISED);
  }

  /**
   * Refuses, for {@link #retirePredecessors} and {@link #deactivatePredecessors} (by {@code
   * operation}), a lineage {@code tree} whose only newest key is not this one.
   */
  private void onlyNewest(String operation, Lineage.Tree tree) {
    boolean retire = operation.startsWith("retire");
    String done = retire ? "retired" : "deactivated";
    List<KeyAttributes> tips = tree.tips();
    List<String> others = tips.stream().map(KeyAttributes::id).filter(t -> !t.equals(id)).toList();
    if (!others.isEmpty())
      throw new StateConflictException(
              operation
                  + ": the rotation lineage of "
                  + id
                  + " has "
                  + (tree.newer(id).isEmpty()
                      ? "other newest keys, "
                          + others
                          + " (callers that rotated a key at the same time), whose"
                          + (retire
                              ? " records retiring would cut off from " + id
                              : " sealing deactivating would stop too")
                          + "; join them first with reconcile(), then "
                          + (retire ? "retire" : "deactivate")
                          + " from the key it returns"
                          + (tips.stream().anyMatch(KeyHandle::compromised)
                              ? " (reconcile leaves a Compromised one: replace it first with replaceCompromised, then"
                                  + " reconcile)"
                              : "")
                          + (retire
                              ? "; where the server refuses links (reconcile is UnsupportedException), retire the"
                                  + " keys by hand, oldest first, once their records are re-sealed"
                              : "; where the server refuses links (reconcile is UnsupportedException), deactivate"
                                  + " the keys by hand (KeyHandle.deactivate())")
                      : "newer keys, "
                          + others
                          + ": "
                          + (retire ? "retire" : "deactivate")
                          + " from the key latest()"
                          + " returns (when several newest keys are listed, callers rotated at once: reconcile() first)")
                  + ". Nothing was "
                  + done,
              null,
              operation,
              id,
              null,
              null)
          .because(StateConflictException.Conflict.LINEAGE);
  }

  /**
   * Refuses a lineage {@code tree} with an unresolved link to a key that still exists (one Get
   * Attributes per unresolved link): fine when its key is gone (an earlier retirement), but one
   * that exists and cannot be read may have keys behind it, kept by someone.
   */
  private void noUnreadableLinks(String operation, Lineage.Tree tree) {
    boolean retire = operation.startsWith("retire");
    String done = retire ? "retired" : operation.equals("lineage") ? "listed" : "deactivated";
    List<Lineage.Gap> gaps = new ArrayList<>(tree.gapsBack());
    gaps.addAll(tree.gapsForward());
    for (Lineage.Gap gap : gaps) {
      boolean gone;
      try {
        gone = keys.read(gap.id()).isEmpty();
      } catch (KmsException e) {
        if (!Lineage.unresolvable(e)) throw e;
        gone = false;
      }
      if (!gone)
        throw new StateConflictException(
                operation
                    + ": the rotation lineage of "
                    + id
                    + " cannot be followed past "
                    + gap.from()
                    + ", which names "
                    + gap.id()
                    + " (it exists but cannot be read as its predecessor);"
                    + (retire
                        ? " retiring the keys after it would destroy keys in the middle of a chain"
                        : operation.equals("lineage")
                            ? " the keys behind it, kept by someone, would be left out"
                            : " the keys before it would stay Active")
                    + ", so nothing was "
                    + done,
                null,
                operation,
                gap.id(),
                null,
                null)
            .because(StateConflictException.Conflict.LINEAGE);
    }
  }

  /**
   * Revokes {@code h} with {@code reason} ({@link #revoke}: a reason that is not a compromise
   * deactivates it, by a Deactivate on KMIP 3.0): true when this call did so. A request whose
   * outcome is unknown is read back, and done only when the key is in the state the request gives
   * (Deactivated, or Compromised for a compromise reason); one the server refused in a way that may
   * be about the key's state ({@link Failures#lifecycleAmbiguous}) is read back too, and a key that
   * is no longer Active or Pre-Active is passed over (false: its Deactivation Date came, or another
   * caller revoked it, meanwhile). Otherwise, or when the key cannot be read, the failure stands.
   */
  private boolean revokedOrRetired(KeyHandle h, RevocationReason reason) {
    try {
      h.revoke(reason);
      return true;
    } catch (KmsException e) {
      boolean unknown = e instanceof OutcomeUnknownException;
      if (!unknown && (e instanceof AlreadyExistsException || !Failures.lifecycleAmbiguous(e)))
        throw e;
      // A refusal retire() read back already carries the state it read: not read twice.
      KeyState now =
          e instanceof StateConflictException read ? read.observedState().orElse(null) : null;
      if (now == null)
        try {
          now = h.attributes().state();
        } catch (KmsException | IllegalStateException unreadable) {
          e.addSuppressed(unreadable);
          throw e;
        }
      if (unknown) {
        if (now == (reason.compromise() ? KeyState.COMPROMISED : KeyState.DEACTIVATED)) return true;
        throw e;
      }
      if (now == KeyState.ACTIVE || now == KeyState.PRE_ACTIVE || now == KeyState.UNKNOWN) throw e;
      return false;
    }
  }

  /** Whether the negotiated version is the KMIP 3.0 draft, where a Revoke always compromises. */
  private boolean draft() {
    return kms.protocolVersion().atLeast(ProtocolVersion.V3_0);
  }

  /**
   * The keys of {@code tree} other than this one, in the order they are retired. First the keys of
   * branches {@link #reconcile()} joined in, which reach this key only through the key their
   * branch replaced: each before every key it replaced, the latest created first, so that a
   * retirement that stops part-way never leaves one cut off from this key (a purged key between
   * them). Then the keys this key descends from, each after every key it replaced (in the tree),
   * {@link Lineage#EARLIEST} first among the keys whose predecessors are all listed.
   */
  private List<KeyAttributes> oldestFirst(Lineage.Tree tree) {
    Set<String> ancestors = new HashSet<>();
    Deque<String> back = new ArrayDeque<>(List.of(id));
    while (!back.isEmpty())
      for (String p : tree.predecessors(back.poll())) if (ancestors.add(p)) back.add(p);
    List<KeyAttributes> branch = new ArrayList<>(tree.keys());
    branch.removeIf(k -> k.id().equals(id) || ancestors.contains(k.id()));
    List<KeyAttributes> out = new ArrayList<>();
    Set<String> gone = new HashSet<>();
    while (!branch.isEmpty()) {
      KeyAttributes next =
          branch.stream()
              .filter(
                  k ->
                      tree.newer(k.id()).stream()
                          .allMatch(n -> gone.contains(n) || !inBranch(branch, n)))
              .max(Lineage.EARLIEST)
              .orElseThrow(
                  () ->
                      new ProtocolViolationException(
                          Kms.named("retirePredecessors")
                              + ": the links of "
                              + id
                              + "'s lineage form a cycle",
                          null,
                          Kms.named("retirePredecessors"),
                          id,
                          null,
                          null));
      branch.remove(next);
      gone.add(next.id());
      out.add(next);
    }
    List<KeyAttributes> left = new ArrayList<>(tree.keys());
    left.removeIf(k -> !ancestors.contains(k.id()));
    Set<String> done = new HashSet<>();
    while (!left.isEmpty()) {
      KeyAttributes next =
          left.stream()
              .filter(
                  k ->
                      tree.predecessors(k.id()).stream()
                          .allMatch(p -> done.contains(p) || p.equals(id)))
              .min(Lineage.EARLIEST)
              .orElseThrow(
                  () ->
                      new ProtocolViolationException(
                          Kms.named("retirePredecessors")
                              + ": the links of "
                              + id
                              + "'s lineage form a cycle",
                          null,
                          Kms.named("retirePredecessors"),
                          id,
                          null,
                          null));
      left.remove(next);
      done.add(next.id());
      out.add(next);
    }
    return out;
  }

  private static boolean inBranch(List<KeyAttributes> branch, String id) {
    return branch.stream().anyMatch(k -> k.id().equals(id));
  }

  /**
   * The objects that look like keys a {@link KeyCreation#findOrCreate()} race left behind under one
   * of this key's names, for the caller to review.
   *
   * <p>A candidate has this key's kind, algorithm and length, is Pre-Active, was never activated
   * and has no links. It is the key a creator left when another caller's key ranked first, or one a
   * call cut short after its Create. This is only a hint: a name proves nothing about who made an
   * object, and another instance may still activate a key it created a moment ago. Destroy ({@link
   * #destroy()}) only what you know is yours and nothing uses. One Get Attributes, one Locate per
   * name, and one Get Attributes per object found.
   *
   * @return the candidates, lowest identifier first; empty when there are none
   */
  public List<KeyHandle> leftovers() {
    return kms.call(
        "leftovers",
        () -> {
          KeyAttributes mine = attributes();
          Set<String> seen = new HashSet<>(Set.of(id));
          List<String> found = new ArrayList<>();
          for (String name : mine.names())
            for (String other : keys.namedIn(name, KeyState.PRE_ACTIVE)) {
              if (!seen.add(other)) continue;
              Optional<KeyAttributes> a = keys.read(other);
              if (a.isPresent()
                  && a.get().kind() == mine.kind()
                  && a.get().algorithm().isPresent()
                  && a.get().algorithm().equals(mine.algorithm())
                  && a.get().length().isPresent()
                  && a.get().length().equals(mine.length())
                  && a.get().state() == KeyState.PRE_ACTIVE
                  && a.get().activationDate().isEmpty()
                  && a.get().links().isEmpty()) found.add(other);
            }
          found.sort(Lineage.IDENTIFIERS);
          return found.stream().map(keys::handle).toList();
        });
  }

  /**
   * Revokes the object. A compromise reason ({@link RevocationReason#keyCompromise}, {@link
   * RevocationReason#caCompromise}) makes it Compromised, with the reason's occurrence date. Any
   * other reason deactivates it, as {@link #deactivate(RevocationReason)} does.
   *
   * <p>On KMIP 1.x to 2.1 both are a Revoke with the reason. On the KMIP 3.0 draft a Revoke makes
   * the object Compromised whatever its reason, so there a reason that is not a compromise is sent
   * as the draft's Deactivate operation, without the reason. This call never makes an object
   * Compromised unless the reason says it was compromised. To send the protocol's own Revoke, use
   * {@code Requests.revoke} through {@link Kms#protocol()}.
   *
   * @param reason why the object is revoked
   * @throws StateConflictException when the server refuses because of the object's state: for a
   *     reason that is not a compromise, any object that is not Active; for a compromise, an object
   *     Compromised already, which keeps its first compromise's reason and dates (read back with
   *     one Get Attributes)
   */
  public void revoke(RevocationReason reason) {
    Objects.requireNonNull(reason, "reason");
    retire("revoke", reason);
  }

  /**
   * Deactivates the object without compromising it: {@link #deactivate(RevocationReason)} with
   * {@link RevocationReason#unspecified()}.
   *
   * @throws KmsException as {@link #deactivate(RevocationReason)}
   */
  public void deactivate() {
    deactivate(RevocationReason.unspecified());
  }

  /**
   * Deactivates the object without compromising it, on every KMIP version.
   *
   * <p>A Deactivated key no longer encrypts, wraps, signs or computes MACs. It still decrypts,
   * unwraps and verifies what it protected where the server's policy allows, and a strict server
   * refuses even that. Instances still sealing under it are refused ({@link
   * StateConflictException}, observed state {@code DEACTIVATED}), and a {@link CurrentKey} moves to
   * its replacement.
   *
   * <p>On KMIP 1.x to 2.1 this is a Revoke with {@code reason}. On the KMIP 3.0 draft, where a
   * Revoke makes the object Compromised whatever its reason, it is the draft's Deactivate
   * operation, sent without a reason. One request; a lost reply is not read back.
   *
   * <p>Only an Active object can be deactivated, because KMIP has no transition from Pre-Active to
   * Deactivated. Destroy a Pre-Active key instead, or activate it first. Some servers accept a
   * Revoke of a Pre-Active key and deactivate it, and the SDK does not refuse it before sending.
   * Servers differ on a key that is Deactivated already: some refuse, others accept. A refusal that
   * may be about the object's state is read back (one Get Attributes). An object that is not Active
   * then is a {@link StateConflictException} with its state and the server's reason.
   *
   * @param reason why, not a compromise (usually {@link RevocationReason#superseded}); recorded as
   *     the Revocation Reason up to KMIP 2.1
   * @throws IllegalArgumentException when {@code reason} is a compromise: {@link #revoke} or {@link
   *     #replaceCompromised} handle a compromise
   * @throws StateConflictException when the server refuses because of the object's state
   * @see <a
   *     href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#rotation-with-a-grace-period">Rotation
   *     with a grace period</a>
   */
  public void deactivate(RevocationReason reason) {
    Objects.requireNonNull(reason, "reason");
    if (reason.compromise())
      throw new IllegalArgumentException(
          "deactivate: "
              + reason.kind()
              + " makes the object Compromised, not Deactivated; use revoke(reason),"
              + " or replaceCompromised(reason) for a key");
    retire("deactivate", reason);
  }

  /**
   * {@link #revoke} and {@link #deactivate}: a Revoke with {@code reason}, except a reason that is not
   * a compromise on KMIP 3.0, which is a Deactivate. A request the server refuses in a way
   * that may be about the key's state (Permission Denied, the only such reason on KMIP 1.x; Illegal Operation; Wrong Key
   * Lifecycle State) is read back, as {@link #activate()} does: a key the request cannot move (one
   * not Active for a deactivation; one Compromised already for a compromise) is a {@link
   * StateConflictException} with its state and the server's reason, not an access failure. When the
   * read-back fails, or finds a state the request could have moved, the refusal stands.
   */
  private void retire(String operation, RevocationReason reason) {
    Request request;
    if (!reason.compromise() && draft()) {
      request = Requests.deactivate().uniqueIdentifier(id).build();
    } else {
      List<Ttlv> fields = new ArrayList<>();
      fields.add(enumeration(REVOCATION_REASON_CODE, reason.kind().protocolValue()));
      reason.message().ifPresent(m -> fields.add(text(REVOCATION_MESSAGE, m)));
      Request.Builder b =
          Requests.revoke().uniqueIdentifier(id).add(structure(REVOCATION_REASON, fields));
      reason.compromiseOccurred().ifPresent(t -> b.add(dateTime(COMPROMISE_OCCURRENCE_DATE, t)));
      request = b.build();
    }
    kms.run(
        operation,
        () -> {
          try {
            kms.execute(operation, Kms.Kind.MUTATION, id, s -> s.call(request));
          } catch (PermissionDeniedException | StateConflictException e) {
            if (e instanceof AlreadyExistsException || !Failures.lifecycleAmbiguous(e)) throw e;
            KeyState state;
            try {
              state = attributes().state();
            } catch (KmsException | IllegalStateException unreadable) {
              e.addSuppressed(unreadable);
              throw e;
            }
            if (reason.compromise()) {
              // KMIP lists no transition out of Compromised but Destroy: another caller compromised
              // the
              // key first, and the server keeps that compromise's reason and dates.
              if (state != KeyState.COMPROMISED && state != KeyState.DESTROYED_COMPROMISED) throw e;
              throw new StateConflictException(
                      operation
                          + ": "
                          + id
                          + " is "
                          + state
                          + " already, so the server refused to revoke it again; it"
                          + " keeps the first compromise's reason and dates",
                      e,
                      operation,
                      id,
                      e.result().orElse(null),
                      null)
                  .observed(state);
            }
            // KMIP has no transition from Pre-Active to Deactivated on any version.
            if (state == KeyState.ACTIVE || state == KeyState.UNKNOWN) throw e;
            throw new StateConflictException(
                    operation
                        + ": "
                        + id
                        + " is "
                        + state
                        + ", not Active, so the server refused to deactivate it"
                        + (state == KeyState.PRE_ACTIVE
                            ? " (KMIP has no transition from Pre-Active to Deactivated; a Pre-Active key encrypts"
                                + " nothing until it is activated)"
                            : ""),
                    e,
                    operation,
                    id,
                    e.result().orElse(null),
                    null)
                .observed(state);
          }
        });
  }

  /**
   * Destroys the object's material. <b>This cannot be undone:</b> nothing the key protected can be
   * decrypted afterwards. Servers refuse to destroy an Active key: deactivate it first ({@link
   * #deactivate()}). To retire the old keys of a rotation, use {@link #retirePredecessors}, which
   * destroys them in an order that keeps the lineage linked.
   */
  public void destroy() {
    Request request = Requests.destroy().uniqueIdentifier(id).build();
    kms.execute("destroy", Kms.Kind.MUTATION, id, s -> s.call(request));
  }

  // ---- attribute changes ----

  /**
   * Adds a name (objects may have several).
   *
   * @param name the name to add
   * @throws AlreadyExistsException when the server refuses the name because another object has
   *     it: Non Unique Name Attribute (KMIP 2.0 and later), or on KMIP 1.x, which has no such reason,
   *     Invalid Field or Illegal Operation that a Locate confirms by finding another object with it
   */
  public void addName(String name) {
    Objects.requireNonNull(name, "name");
    // The confirming Locate (on 1.x) shares the call's deadline: caught inside the scope (a catch
    // of the try-with-resources would run after it closed, with a deadline of its own).
    kms.run(
        "addName",
        () -> {
          try {
            add("addName", Attributes.name(name));
          } catch (InvalidRequestException | StateConflictException e) {
            throw keys.duplicateName(e, List.of(name), id);
          }
        });
  }

  /**
   * Removes a name; nothing happens when the object does not have it.
   *
   * @param name the name to remove
   */
  public void removeName(String name) {
    Objects.requireNonNull(name, "name");
    remove(
        "removeName",
        "Name",
        Attributes.name(name),
        v -> v.require(NAME_VALUE).textValue().equals(name));
  }

  /**
   * Adds the object to a group. Not available on the KMIP 3.0 draft, which has no Object Group: where
   * 3.0 may be negotiated, use a custom attribute, which every version supports.
   *
   * @param group the group's name
   */
  public void addToGroup(String group) {
    Objects.requireNonNull(group, "group");
    keys.requireGroups("addToGroup");
    add("addToGroup", KmsKeys.group(group));
  }

  /**
   * Removes the object from a group; nothing happens when it is not in it.
   *
   * @param group the group's name
   */
  public void removeFromGroup(String group) {
    Objects.requireNonNull(group, "group");
    keys.requireGroups("removeFromGroup");
    remove(
        "removeFromGroup", "Object Group", KmsKeys.group(group), v -> v.textValue().equals(group));
  }

  /**
   * Sets a custom attribute. On KMIP 2.x this is one Set Attribute request, which is atomic. On
   * 1.x it is a Modify Attribute; when the attribute has no instance at index 0, a Get Attributes
   * finds the instance that exists and modifies it, or an Add Attribute adds it: up to three
   * requests, and not atomic (another client can change the attribute in between). See {@link
   * KeyAttributes} for the value types.
   *
   * @param name the attribute
   * @param value its value, of a type {@link KeyAttributes} lists
   */
  public void setCustomAttribute(CustomAttribute name, Object value) {
    Objects.requireNonNull(name, "name");
    Ttlv attribute = keys.custom(name, Objects.requireNonNull(value, "value"));
    if (!kms.protocolVersion().legacyAttributes()) {
      Request set =
          Request.operation(Operation.SET_ATTRIBUTE)
              .uniqueIdentifier(id)
              .attribute(attribute)
              .build();
      kms.execute("setCustomAttribute", Kms.Kind.MUTATION, id, s -> s.call(set));
      return;
    }
    kms.run(
        "setCustomAttribute",
        () -> {
          Request modify =
              Requests.modifyAttribute().uniqueIdentifier(id).attribute(attribute).build();
          try {
            kms.execute("setCustomAttribute", Kms.Kind.MUTATION, id, s -> s.call(modify));
          } catch (NotFoundException | InvalidRequestException e) {
            // Item Not Found can also mean that the object is missing: the Get Attributes below
            // then
            // fails with NotFoundException, so it needs no separate check.
            if (!attributeMissing(e, false)) throw e;
            // No instance at index 0: modify the instance that exists (its index is stable even
            // after
            // others were deleted), or add one.
            String legacyName = name.vendor() + "-" + name.name();
            List<Integer> existing = legacyIndexes(legacyName, v -> true);
            if (existing.isEmpty()) add("setCustomAttribute", attribute);
            else {
              Request at =
                  Requests.modifyAttribute()
                      .uniqueIdentifier(id)
                      .attribute(
                          Attributes.attribute(
                              legacyName, existing.get(0), AttributeReader.encode(value)))
                      .build();
              kms.execute("setCustomAttribute", Kms.Kind.MUTATION, id, s -> s.call(at));
            }
          }
        });
  }

  /**
   * Removes a custom attribute; nothing happens when the object does not have it.
   *
   * @param name the attribute
   */
  public void removeCustomAttribute(CustomAttribute name) {
    Objects.requireNonNull(name, "name");
    boolean legacyVendor = name.vendor().equals("x") || name.vendor().equals("y");
    if (kms.protocolVersion().legacyAttributes()) {
      if (!legacyVendor) keys.custom(name, ""); // the capability check: vendors need 2.0
      removeLegacy("removeCustomAttribute", name.vendor() + "-" + name.name(), v -> true);
      return;
    }
    Request request =
        Requests.deleteAttribute()
            .uniqueIdentifier(id)
            .add(ModernAttributes.vendorReference(name.vendor(), name.name()))
            .build();
    deleting("removeCustomAttribute", request);
  }

  /**
   * Removes one instance of the name {@code name} with one Delete Attribute: by value on 2.x, by
   * the Attribute Index of the first such instance on 1.x (one Get Attributes first). Unlike
   * {@link #removeName}, it never sends a second Delete: a caller that must see the object before
   * each change reads it again, then calls this again while the name is still there.
   */
  void removeOneName(String name) {
    removeOne(
        "removeName",
        "Name",
        Attributes.name(name),
        v -> v.require(NAME_VALUE).textValue().equals(name));
  }

  /**
   * Removes one instance of the custom attribute {@code name} whose value is the text {@code
   * value}, with one Delete Attribute, as {@link #removeOneName} does; an instance of another
   * value is left.
   */
  void removeOneCustom(CustomAttribute name, String value) {
    removeOne(
        "removeCustomAttribute",
        name.vendor() + "-" + name.name(),
        keys.custom(name, value),
        v -> v.type() == Ttlv.Type.TEXT_STRING && v.textValue().equals(value));
  }

  private void removeOne(
      String operation,
      String attributeName,
      Ttlv attribute,
      java.util.function.Predicate<Ttlv> value) {
    if (!kms.protocolVersion().legacyAttributes()) {
      deleting(
          operation, Requests.deleteAttribute().uniqueIdentifier(id).attribute(attribute).build());
      return;
    }
    kms.run(
        operation,
        () -> {
          List<Integer> indexes = legacyIndexes(attributeName, value);
          if (indexes.isEmpty()) return;
          deleting(
              operation,
              Requests.deleteAttribute()
                  .uniqueIdentifier(id)
                  .add(text(ATTRIBUTE_NAME, attributeName))
                  .add(integer(ATTRIBUTE_INDEX, indexes.get(0)))
                  .build());
        });
  }

  private void add(String operation, Ttlv attribute) {
    Request request = Requests.addAttribute().uniqueIdentifier(id).attribute(attribute).build();
    kms.execute(operation, Kms.Kind.MUTATION, id, s -> s.call(request));
  }

  /**
   * Deletes one value of a multi-valued attribute: by value on 2.x (Current Attribute); on 1.x by
   * the Attribute Index the server reports for that value (read first; indexes do not change when
   * other instances are deleted, KMIP 1.4 section 2.1.1).
   */
  private void remove(
      String operation,
      String attributeName,
      Ttlv attribute,
      java.util.function.Predicate<Ttlv> value) {
    if (kms.protocolVersion().legacyAttributes()) {
      removeLegacy(operation, attributeName, value);
      return;
    }
    deleting(
        operation, Requests.deleteAttribute().uniqueIdentifier(id).attribute(attribute).build());
  }

  private void removeLegacy(
      String operation, String attributeName, java.util.function.Predicate<Ttlv> value) {
    kms.run(
        operation,
        () -> {
          for (int index : legacyIndexes(attributeName, value))
            deleting(
                operation,
                Requests.deleteAttribute()
                    .uniqueIdentifier(id)
                    .add(text(ATTRIBUTE_NAME, attributeName))
                    .add(integer(ATTRIBUTE_INDEX, index))
                    .build());
        });
  }

  /** KMIP 1.x: the Attribute Index of every instance of {@code attributeName} whose value matches. */
  private List<Integer> legacyIndexes(
      String attributeName, java.util.function.Predicate<Ttlv> value) {
    Request request =
        Requests.getAttributes()
            .uniqueIdentifier(id)
            .add(text(ATTRIBUTE_NAME, attributeName))
            .build();
    return kms.execute(
        "attributes",
        Kms.Kind.READ,
        id,
        s -> {
          Result result = s.call(request);
          try {
            List<Integer> out = new ArrayList<>();
            List<Ttlv> instances = new ArrayList<>();
            for (Ttlv a : result.payload().map(p -> p.children(ATTRIBUTE)).orElse(List.of()))
              if (a.require(ATTRIBUTE_NAME).textValue().equals(attributeName)) instances.add(a);
            // An omitted Attribute Index means 0 (KMIP 1.4 section 2.1.1); two instances with the
            // same index (for example two that omit it) cannot be told apart.
            Set<Integer> indexes = new HashSet<>();
            for (Ttlv a : instances)
              if (!indexes.add(a.child(ATTRIBUTE_INDEX).map(Ttlv::intValue).orElse(0)))
                throw new ProtocolException(
                    "Get Attributes returned two instances with the same Attribute Index",
                    result.batchItem(),
                    null);
            for (Ttlv a : instances)
              if (value.test(a.require(ATTRIBUTE_VALUE)))
                out.add(a.child(ATTRIBUTE_INDEX).map(Ttlv::intValue).orElse(0));
            return out;
          } catch (IllegalArgumentException | IllegalStateException e) {
            throw new ProtocolException(
                "Malformed Get Attributes response", result.batchItem(), null);
          }
        });
  }

  private void deleting(String operation, Request request) {
    // Caught inside the scope, so the confirming read shares the call's deadline.
    kms.run(
        operation,
        () -> {
          try {
            kms.execute(operation, Kms.Kind.MUTATION, id, s -> s.call(request));
          } catch (NotFoundException | InvalidRequestException e) {
            if (!attributeMissing(e, true)) throw e;
          }
        });
  }

  /**
   * A failure that says the attribute (not the object) is absent: Attribute Not Found or Attribute
   * Instance Not Found. Item Not Found is ambiguous (1.x servers use it for both), so with {@code
   * confirm} the object is then read: if it is missing too, the failure stands.
   */
  private boolean attributeMissing(KmsException e, boolean confirm) {
    Enums.ResultReason r = e.protocolReason().orElse(null);
    if (r == Enums.ResultReason.ATTRIBUTE_NOT_FOUND
        || r == Enums.ResultReason.ATTRIBUTE_INSTANCE_NOT_FOUND) return true;
    if (r != Enums.ResultReason.ITEM_NOT_FOUND) return false;
    if (!confirm) return true;
    // Part of the call that failed with e (attributes' own when there is none).
    try {
      attributes();
      return true;
    } catch (NotFoundException gone) {
      return false;
    }
  }

  // ---- cryptography ----

  /**
   * Encrypts on the server without additional data.
   *
   * <p><b>Advanced.</b> As {@link #encrypt(CipherSpec, byte[], byte[])}.
   *
   * @param spec how to encrypt
   * @param plaintext the data to encrypt
   * @return the ciphertext, which names this key and the spec
   */
  public Ciphertext encrypt(CipherSpec spec, byte[] plaintext) {
    return encrypt(spec, plaintext, null);
  }

  /**
   * Encrypts on the server. The SDK picks the IV or nonce.
   *
   * <p>For AEAD specs, {@code aad} is authenticated together with the ciphertext header (see {@link
   * Ciphertext}), and so is it for RSA-OAEP from KMIP 1.4, as the OAEP label (see {@link
   * CipherSpec#rsaOaep(Hash, Hash)}). For other specs it must be null or empty.
   *
   * <p><b>Usages.</b> A symmetric key that permits Encrypt but not Decrypt (nor Unwrap Key, for AES
   * key wrap) would encrypt data nobody can decrypt. Such a key is refused with {@link
   * KeyMismatchException} (FIX_REQUEST) before anything is sent. The handle reads the key's kind
   * and usages once (one Get Attributes, shared with its views), and a handle from {@code create},
   * {@code findOrCreate}, {@code rotate} or {@code latest} knows them already. A usage mask changed
   * on the server later is not seen by that handle. A key without a usage mask, and a public key,
   * are left to the server.
   *
   * <p><b>Advanced.</b> The KMS encrypts every byte: fine for small values. For records and files,
   * {@link CurrentKey#seal} encrypts locally under a data key the KMS wraps, one request whatever
   * the size. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/envelope-encryption.md#encrypt-on-the-server">Encrypt
   * on the server</a>.
   *
   * @param spec how to encrypt
   * @param plaintext the data to encrypt
   * @param aad the additional data to authenticate; null or empty for none
   * @return the ciphertext, which names this key and the spec
   * @throws UnsupportedException for a spec the negotiated version cannot express, for example
   *     AES-GCM before KMIP 1.4, or RSA-OAEP with additional data before KMIP 1.4
   * @throws KeyMismatchException when the key is a symmetric key that cannot decrypt what it would
   *     encrypt (no Decrypt usage), or is not a key that encrypts
   * @throws StateConflictException when the key is not Active (Pre-Active, Deactivated,
   *     Compromised), with the same message on every version
   */
  public Ciphertext encrypt(CipherSpec spec, byte[] plaintext, byte[] aad) {
    Objects.requireNonNull(spec, "spec");
    Objects.requireNonNull(plaintext, "plaintext");
    ProtocolVersion version = kms.protocolVersion();
    boolean withAad = aad != null && aad.length > 0;
    if (withAad && !spec.bindsAad(version)) {
      if (spec.rsaOaep())
        throw new UnsupportedException(
            Kms.named("encrypt")
                + ": binding additional data to RSA-OAEP (P Source) needs KMIP 1.4; this connection uses "
                + kms.version(),
            null,
            Kms.named("encrypt"),
            id,
            null,
            null);
      throw new IllegalArgumentException(spec + " does not authenticate additional data");
    }
    requireKind(Kms.named("encrypt"), ObjectKind.SYMMETRIC_KEY, ObjectKind.PUBLIC_KEY);
    return kms.call(
        "encrypt",
        () -> {
          requireDecryptable(Kms.named("encrypt"), spec);
          return encryptChecked(spec, plaintext, aad, version);
        });
  }

  /**
   * Refuses a symmetric key whose usages cannot decrypt what {@code spec} encrypts: read once per handle and kept, only when the check passes, so a key whose mask is fixed
   * on the server is read again.
   */
  private void requireDecryptable(String operation, CipherSpec spec) {
    if (kind != null && kind != ObjectKind.SYMMETRIC_KEY) return;
    Usages known = usages.get();
    if (known == null)
      try {
        KeyAttributes a = attributes();
        kms.stale(a);
        known = Usages.of(a);
      } catch (PermissionDeniedException unreadable) {
        if (Failures.credentialsRefused(unreadable)) throw unreadable;
        // A client allowed to encrypt but not to read the key: leave the usages to the server.
        usages.compareAndSet(null, new Usages(ObjectKind.OTHER, Set.of(), 0));
        return;
      }
    if (known.kind() != ObjectKind.SYMMETRIC_KEY || known.rawMask() == 0) {
      usages.compareAndSet(null, known);
      return;
    }
    Set<KeyUsage> inverse = decrypting(spec).usages();
    if (Collections.disjoint(known.usages(), inverse))
      throw new KeyMismatchException(
          operation
              + ": "
              + id
              + " permits "
              + known.usages()
              + " but not "
              + (inverse.size() == 1 ? inverse.iterator().next() : "any of " + inverse)
              + ", so nothing could decrypt what it encrypts; give the key the Decrypt usage, or use another key",
          null,
          operation,
          id,
          null,
          null);
    usages.compareAndSet(null, known);
  }

  private Ciphertext encryptChecked(
      CipherSpec spec, byte[] plaintext, byte[] aad, ProtocolVersion version) {
    String stored = spec.storedName(version);
    CryptoParameters parameters =
        spec.parameters(
            version,
            Kms.named("encrypt"),
            id,
            spec.rsaOaep() && spec.bindsAad(version) ? Ciphertext.boundAad(id, stored, aad) : null);
    return diagnosed(
        Kms.named("encrypt"),
        encrypting(spec),
        () ->
            kms.execute(
                Kms.named("encrypt"),
                Kms.Kind.READ_CRYPTO,
                id,
                s -> {
                  byte[] iv = spec.ivLength() > 0 ? random(spec.ivLength()) : null;
                  CryptoRequests.Builder b =
                      CryptoRequests.encrypt(id).parameters(parameters).data(plaintext);
                  if (iv != null) b.iv(iv);
                  if (spec.authenticated()) b.aad(Ciphertext.boundAad(id, stored, aad));
                  CryptoResult r = CryptoResult.of(s.call(b.build()));
                  byte[] data = data(r, version, spec, plaintext.length, true);
                  byte[] tag = r.authenticatedEncryptionTag().orElse(null);
                  if (spec.authenticated() && tag == null) {
                    // Some servers append the tag to the ciphertext instead of returning it
                    // separately.
                    if (data.length < spec.tagLength())
                      throw Kms.missing("AuthenticatedEncryptionTag");
                    tag = Arrays.copyOfRange(data, data.length - spec.tagLength(), data.length);
                    data = Arrays.copyOf(data, data.length - spec.tagLength());
                  }
                  if (!spec.authenticated() && tag != null)
                    throw new ProtocolException(
                        "Encrypt returned a tag for a mode without one", null, null);
                  if (spec.authenticated() && tag.length != spec.tagLength())
                    throw new ProtocolException(
                        "Encrypt returned a tag of the wrong length", null, null);
                  byte[] returned = r.ivCounterNonce().orElse(null);
                  if (returned != null && iv != null && !Arrays.equals(returned, iv))
                    throw new ProtocolException(
                        "Encrypt used another IV than the one sent", null, null);
                  byte[] used = returned != null ? returned : iv;
                  if (!spec.custom() && (used == null ? 0 : used.length) != spec.ivLength())
                    throw new ProtocolException(
                        "Encrypt returned an IV of the wrong length", null, null);
                  int expected = spec.outputLength(plaintext.length, true);
                  if (expected >= 0 && data.length != expected)
                    throw new ProtocolException(
                        "Encrypt returned ciphertext of the wrong length for " + spec, null, null);
                  return new Ciphertext(id, stored, data, used, tag);
                }));
  }

  /**
   * The Data of an Encrypt or Decrypt response. KMIP 2.0 made it optional, which a server may use
   * only when the result is empty: a Data-less reply is accepted only when {@code spec} says the
   * output for this input is empty (GCM or CTR with empty input), so a faulty reply cannot pass
   * for "no data". CBC pads empty input to a block, RSA-OAEP output has the modulus size, and a
   * custom spec's length is unknown: those need Data.
   */
  private static byte[] data(
      CryptoResult r, ProtocolVersion version, CipherSpec spec, int inputLength, boolean encrypt)
      throws ProtocolException {
    Optional<byte[]> data = r.data();
    if (data.isPresent()) return data.get();
    if (version.atLeast(ProtocolVersion.V2_0) && spec.outputLength(inputLength, encrypt) == 0)
      return new byte[0];
    throw Kms.missing("Data");
  }

  /**
   * Decrypts on the server a ciphertext that this key, or a key of its rotation lineage, produced,
   * with the spec the ciphertext names: AES-GCM or AES key wrap. For RSA-OAEP, CBC and CTR, name
   * the spec with {@link #decrypt(CipherSpec, Ciphertext, byte[])}.
   *
   * <p><b>Which key.</b> The ciphertext must name this key, another key of its lineage within 64
   * rotations (see {@link #lineage()}), or an identifier given to {@link #acceptingOriginalId}. So
   * a handle kept from startup also decrypts what was encrypted after another instance rotated the
   * key. The ciphertext alone never chooses a key. One Get Attributes per key read.
   *
   * <p><b>State.</b> A Destroyed key is always refused. A Compromised key is refused unless it is
   * this handle's own key and the handle is {@link #allowingCompromised()}.
   *
   * <p><b>A broken lineage.</b> A link the walk cannot resolve, such as a purged key, proves
   * nothing. When the ciphertext's key is not found another way, the decrypt is a {@link
   * StateConflictException} that names the link. So purging a key in the middle of a chain stops
   * the keys on either side from decrypting each other's data.
   *
   * <p><b>Advanced.</b> The KMS decrypts every byte: fine for small values. Records sealed with
   * {@link CurrentKey#seal} open through {@link CurrentKey#open}. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">the
   * advanced alternatives</a>.
   *
   * @param ciphertext the ciphertext
   * @param aad the additional data given when encrypting; null or empty for none
   * @return the plaintext, a new array
   * @throws CryptographicFailureException when the ciphertext is malformed or names a spec that is
   *     not taken from ciphertexts ({@link CryptographicFailureException.Kind#INVALID_CIPHERTEXT}),
   *     or does not authenticate
   * @throws KeyMismatchException when the ciphertext names a key outside this key's lineage, also a
   *     key that exists beyond an unresolved link and lacks the link it would need
   * @throws StateConflictException when the key that would decrypt is Compromised or Destroyed, or
   *     the ciphertext's key is not found and a link of the chain cannot be resolved
   * @throws UnsupportedException when the ciphertext's key is not found within 64 rotations and the
   *     lineage goes on: decrypt such records with {@link KmsKeys#decrypt(KeyQuery, Ciphertext,
   *     byte[])} and a query their key matches, such as {@link KeyQuery#ids}
   */
  public byte[] decrypt(Ciphertext ciphertext, byte[] aad) {
    Objects.requireNonNull(ciphertext, "ciphertext");
    return decrypt(storedSpec(ciphertext), ciphertext, aad, true);
  }

  /**
   * Decrypts on the server with an expected spec: the ciphertext must name exactly this spec, and
   * its IV and tag must have the spec's lengths. Use this for RSA-OAEP, CBC, CTR and {@link
   * CipherSpec#fromProtocol protocol-defined} specs. A private RSA key also accepts a ciphertext
   * made with its linked public key. The key and state rules are those of {@link
   * #decrypt(Ciphertext, byte[])}.
   *
   * <p><b>Advanced.</b> As {@link #decrypt(Ciphertext, byte[])}.
   *
   * @param spec the spec the ciphertext must have been made with
   * @param ciphertext the ciphertext
   * @param aad the additional data given when encrypting; null or empty for none
   * @return the plaintext, a new array
   * @throws CryptographicFailureException when the ciphertext names another spec or has an IV or
   *     tag of the wrong length, or is RSA-OAEP without a bound label while additional data is
   *     given ({@link CryptographicFailureException.Kind#INVALID_CIPHERTEXT}), or when an AEAD tag
   *     or OAEP label does not verify (the ciphertext, nonce, tag, header or additional data
   *     changed)
   * @throws KeyMismatchException when the ciphertext names a key outside this key's lineage (as for
   *     {@link #decrypt(Ciphertext, byte[])})
   * @throws StateConflictException when the key that would decrypt is Compromised or Destroyed, or
   *     the ciphertext's key is not found and a link of the chain cannot be resolved
   * @throws IllegalArgumentException for additional data with a spec that does not authenticate it
   */
  public byte[] decrypt(CipherSpec spec, Ciphertext ciphertext, byte[] aad) {
    Objects.requireNonNull(spec, "spec");
    Objects.requireNonNull(ciphertext, "ciphertext");
    return decrypt(spec, ciphertext, aad, false);
  }

  private byte[] decrypt(CipherSpec spec, Ciphertext ciphertext, byte[] aad, boolean stored) {
    check(spec, ciphertext, aad, stored);
    requireKind(Kms.named("decrypt"), ObjectKind.SYMMETRIC_KEY, ObjectKind.PRIVATE_KEY);
    return kms.call(
        "decrypt",
        () -> {
          return decryptor(Kms.named("decrypt"), spec, ciphertext.keyId())
              .decryptChecked(spec, ciphertext, aad);
        });
  }

  /**
   * The key that decrypts a ciphertext naming {@code namedId}: this key (also for its migrated
   * identifiers, and for RSA-OAEP its linked public key), a key it replaced, or a key that replaced
   * it; checked for state.
   */
  private KeyHandle decryptor(String operation, CipherSpec spec, String namedId) {
    KeyAttributes mine = attributes();
    kms.stale(mine);
    boolean own =
        namedId.equals(id)
            || originalIds.contains(namedId)
            // Anchored on this private key's own Public Key link: nothing is asked of the id the
            // ciphertext names.
            || (spec.rsaOaep()
                && mine.kind() == ObjectKind.PRIVATE_KEY
                && mine.link(LinkKind.PUBLIC_KEY).map(namedId::equals).orElse(false));
    if (own) {
      requireUsable(operation, id, mine);
      requireSuited(operation, id, mine, decrypting(spec));
      return this;
    }
    // Another key of this key's lineage tree, each step confirmed by both keys' links, so that
    // neither key's links alone can attach a key to it: first the keys that replaced this
    // one (another instance rotated after this handle was made: free for a current key, which has
    // no replacement), then the keys it replaced, then the other branches (callers that rotated a
    // key at the same time). One Get Attributes per key read.
    Lineage.Tree tree =
        Lineage.tree(operation, mine, true, k -> k.id().equals(namedId), keys::read);
    if (tree.found().isPresent()) {
      // The opt-in covers this key only: a Compromised key of the lineage must be named to be used.
      KeyHandle other = new KeyHandle(keys, namedId, kind);
      other.requireUsable(operation, namedId, tree.found().get());
      requireSuited(operation, namedId, tree.found().get(), decrypting(spec));
      return other;
    }
    // Older data must stay readable: a lineage longer than the walk is a limit, not a mismatch.
    if (tree.beyondBack() || tree.beyondForward())
      throw new UnsupportedException(
          operation
              + ": the ciphertext names key "
              + namedId
              + ", which is not in the rotation lineage of "
              + id
              + " as far as it was followed: the lineage continues more than "
              + Lineage.LIMIT
              + " rotations"
              + " from "
              + id
              + ", and a handle walks no further. Open records that old by the key they name,"
              + " bound to keys you trust: kms.keys().open(query, ...) or decrypt(query, ...) with a query the"
              + " record's own key matches, an attribute Re-key copies and only your keys carry"
              + " (KeyQuery.all().custom(...), under access control) or a manifest of your keys' identifiers"
              + " (KeyQuery.byIds(...)); see docs/operating-keys.md, \"Records older than "
              + Lineage.LIMIT
              + " rotations\"",
          null,
          operation,
          id,
          null,
          null);
    if (tree.limit() != null) throw tree.limit();
    if (tree.cycle() != null) throw tree.cycle();
    List<Lineage.Gap> gaps = new ArrayList<>(tree.gapsForward());
    gaps.addAll(tree.gapsBack());
    // A link of the tree that cannot be resolved (a key destroyed and purged, unreadable, an
    // invalid
    // reply) proves nothing: the ciphertext's key may be beyond it, so this is not BAD_DATA, unless
    // that key provably lies beyond none of the gaps (one more Get Attributes, on this failure
    // only):
    // after the oldest keys are purged every walk back ends at a gap, and a stranger's key must
    // still
    // be BAD_DATA.
    boolean ownKeyGone = gaps.stream().anyMatch(g -> g.id().equals(namedId));
    // The ciphertext's key, read once on this failure path (empty when it cannot be resolved): for
    // a
    // gap, and for a symmetric key's records; a private key never asks about the identifier
    // a ciphertext names unless a gap makes it.
    Optional<KeyAttributes> named =
        ownKeyGone || (gaps.isEmpty() && mine.kind() != ObjectKind.SYMMETRIC_KEY)
            ? Optional.empty()
            : readQuietly(namedId);
    boolean gapsBack = !tree.gapsBack().isEmpty(), gapsForward = !tree.gapsForward().isEmpty();
    if (!gaps.isEmpty()
        && !ownKeyGone
        && named.map(k -> Lineage.beyondNone(k, gapsBack, gapsForward)).orElse(false)) gaps.clear();
    if (!gaps.isEmpty())
      throw Lineage.broken(
          operation,
          id,
          "the ciphertext's key " + namedId,
          gaps,
          (ownKeyGone
                  ? ""
                  : "if records under "
                      + namedId
                      + " are expected, check that it is one of your keys (its"
                      + " name or group in kms.keys().handle(\""
                      + namedId
                      + "\").attributes()) before"
                      + " decrypting with its own handle; ")
              + "find the current key by name. Purging a key in the middle of a chain breaks"
              + " this check: retire the oldest keys first (docs/kms-design.md, \"Retiring keys\")");
    // A record under an existing Compromised key is a recovery case, not bad data: after a
    // compromise
    // whose replacement could not be linked, every old record names such a key.
    if (named.isPresent() && compromised(named.get()))
      throw underCompromised(
          operation, namedId, named.get(), "is not in the rotation chain of " + id);
    throw KeyMismatchException.ciphertext(
        operation
            + ": the ciphertext was made with key "
            + namedId
            + ", which is neither "
            + id
            + ", nor a key it replaced, nor a key that replaced it, nor another key of its rotation lineage",
        operation,
        id);
  }

  /** {@code keyId}'s attributes, or empty when it no longer exists or cannot be resolved ({@link Lineage#unresolvable}). */
  private Optional<KeyAttributes> readQuietly(String keyId) {
    try {
      return keys.read(keyId);
    } catch (KmsException e) {
      if (!Lineage.unresolvable(e)) throw e;
      return Optional.empty();
    }
  }

  /** Whether a key is Compromised (destroyed or not). */
  static boolean compromised(KeyAttributes key) {
    return key.state() == KeyState.COMPROMISED || key.state() == KeyState.DESTROYED_COMPROMISED;
  }

  /**
   * The failure for a ciphertext or sealed record made under {@code keyId}, which exists and is
   * Compromised, and is outside the expected key ({@code why}): STATE, since the record is probably
   * good data whose key was compromised (and perhaps replaced without a link), not a misfiled one.
   * Whoever controls a Compromised key can make a record that names it, so the advice is to check
   * that the key is the caller's before recovering with it.
   */
  static StateConflictException underCompromised(
      String operation, String keyId, KeyAttributes key, String why) {
    boolean destroyed = key.state() == KeyState.DESTROYED_COMPROMISED;
    return new StateConflictException(
            operation
                + ": the record was sealed under key "
                + keyId
                + ", which is "
                + key.state()
                + " and "
                + why
                + (destroyed
                    ? "; it was destroyed, so the record cannot be recovered"
                    : "; recover it only if "
                        + keyId
                        + " is a key you revoked yourself (a name proves nothing:"
                        + " anyone who can create keys can name one like yours, seal a record under it and"
                        + " revoke it), with that key's handle, as docs/operating-keys.md (\"A compromised"
                        + " key\") describes; otherwise treat the record as forged"),
            null,
            operation,
            keyId,
            null,
            null)
        .observed(key.state());
  }

  /**
   * Refuses a Destroyed key, and a Compromised one unless this handle allows it: decrypting,
   * unwrapping or verifying with a compromised key accepts data an attacker may have made.
   */
  void requireUsable(String operation, String keyId, KeyAttributes attributes) {
    KeyState state = knownState(operation, keyId, attributes);
    boolean destroyed = state == KeyState.DESTROYED || state == KeyState.DESTROYED_COMPROMISED;
    if (destroyed || (state == KeyState.COMPROMISED && !compromisedAllowed))
      throw new StateConflictException(
              operation
                  + ": key "
                  + keyId
                  + " is "
                  + state
                  + (destroyed
                      ? ""
                      : "; use kms.keys().handle(\""
                          + keyId
                          + "\").allowingCompromised() to "
                          + operation
                          + " with it anyway, for example to recover data"),
              null,
              operation,
              keyId,
              null,
              null)
          .observed(state);
  }

  /**
   * The object's State, for the checks that refuse Compromised and Destroyed objects. Those checks
   * fail closed: a Get Attributes response without State, or with a State this SDK does not know
   * (a vendor or later value), cannot show that the object is neither, so it is a {@link
   * ProtocolViolationException}, also for a handle that is {@link #allowingCompromised()}.
   */
  static KeyState knownState(String operation, String keyId, KeyAttributes attributes) {
    KeyState state = attributes.state();
    if (state == KeyState.UNKNOWN)
      throw new ProtocolViolationException(
          operation
              + ": the server reported "
              + (attributes.rawState() == 0
                  ? "no State"
                  : "an unknown State (" + attributes.rawState() + ")")
              + " for "
              + keyId
              + ", so it cannot be shown not to be Compromised or Destroyed",
          null,
          operation,
          keyId,
          null,
          null);
    return state;
  }

  /** What an operation needs of a key: one of its kinds, and one of its usages. */
  record Use(Set<ObjectKind> kinds, Set<KeyUsage> usages) {}

  /** Encrypt needs the Encrypt usage; AES key wrap also accepts Wrap Key. */
  static Use encrypting(CipherSpec spec) {
    return new Use(
        EnumSet.of(ObjectKind.SYMMETRIC_KEY, ObjectKind.PUBLIC_KEY),
        spec.keyWrapMode()
            ? EnumSet.of(KeyUsage.ENCRYPT, KeyUsage.WRAP_KEY)
            : EnumSet.of(KeyUsage.ENCRYPT));
  }

  /** Decrypt needs the Decrypt usage; AES key wrap also accepts Unwrap Key. */
  static Use decrypting(CipherSpec spec) {
    return new Use(
        EnumSet.of(ObjectKind.SYMMETRIC_KEY, ObjectKind.PRIVATE_KEY),
        spec.keyWrapMode()
            ? EnumSet.of(KeyUsage.DECRYPT, KeyUsage.UNWRAP_KEY)
            : EnumSet.of(KeyUsage.DECRYPT));
  }

  static final Use SIGNING = new Use(EnumSet.of(ObjectKind.PRIVATE_KEY), EnumSet.of(KeyUsage.SIGN));
  static final Use VERIFYING =
      new Use(
          EnumSet.of(ObjectKind.PUBLIC_KEY, ObjectKind.CERTIFICATE), EnumSet.of(KeyUsage.VERIFY));
  static final Use MACING =
      new Use(EnumSet.of(ObjectKind.SYMMETRIC_KEY), EnumSet.of(KeyUsage.MAC_GENERATE));
  static final Use MAC_VERIFYING =
      new Use(EnumSet.of(ObjectKind.SYMMETRIC_KEY), EnumSet.of(KeyUsage.MAC_VERIFY));

  /**
   * The {@link KeyMismatchException} the attributes show for {@code use}, or null: the object is
   * another kind, or it has a usage mask without any usage the operation needs. A key without a
   * usage mask is left to the server.
   */
  static KeyMismatchException mismatch(
      String operation, String keyId, KeyAttributes a, Use use, Throwable cause) {
    if (a.kind() != ObjectKind.OTHER && !use.kinds().contains(a.kind()))
      return new KeyMismatchException(
          operation + ": " + keyId + " is a " + a.kind() + ", not " + use.kinds(),
          cause,
          operation,
          keyId,
          null,
          null);
    if (a.rawUsageMask() != 0 && Collections.disjoint(a.usages(), use.usages()))
      return new KeyMismatchException(
          operation
              + ": "
              + keyId
              + " does not permit "
              + use.usages()
              + " (its usages are "
              + a.usages()
              + ")",
          cause,
          operation,
          keyId,
          null,
          null);
    return null;
  }

  static void requireSuited(String operation, String keyId, KeyAttributes a, Use use) {
    KeyMismatchException e = mismatch(operation, keyId, a, use, null);
    if (e != null) throw e;
  }

  /**
   * Runs a cryptographic call and, when the server refuses it in a way that can mean the wrong kind
   * of object or a missing usage (KMIP 1.x servers report those as Permission Denied, Invalid Field
   * or General Failure), reads the key's attributes and reports a {@link KeyMismatchException} if
   * they show one, with the server's failure as its cause. A Permission Denied for a key that is not
   * Active is a {@link StateConflictException}: KMIP 1.x servers refuse a key that cannot be used
   * (KMIP 1.4 sections 11.30 and 11.31) with Permission Denied, where 2.x says Wrong Key Lifecycle
   * State, and the same failure must have the same category, and the same message, on every
   * version (so a state refusal is read too, for the state-specific advice). Otherwise the failure
   * is unchanged, and so is any other access refusal ({@link Failures#lifecycleAmbiguous}).
   */
  private <T> T diagnosed(String operation, Use use, java.util.function.Supplier<T> call) {
    return kms.call(
        operation,
        () -> {
          try {
            return call.get();
          } catch (PermissionDeniedException
              | InvalidRequestException
              | ServerFailureException
              | CryptographicFailureException
              | StateConflictException e) {
            if (e instanceof AlreadyExistsException) throw e;
            if (e instanceof CryptographicFailureException c
                && c.kind() != CryptographicFailureException.Kind.UNCONFIRMED) throw e;
            // An access refusal other than Permission Denied (authentication, Not Authorised, a TLS
            // refusal) says nothing about the key: as the server said.
            if (e instanceof PermissionDeniedException && !Failures.lifecycleAmbiguous(e)) throw e;
            KeyAttributes a;
            try {
              a = attributes();
            } catch (KmsException | IllegalStateException unreadable) {
              throw e;
            }
            KeyMismatchException m =
                e instanceof StateConflictException ? null : mismatch(operation, id, a, use, e);
            if (m != null) throw m;
            if ((e instanceof PermissionDeniedException || e instanceof StateConflictException)
                && a.state() != KeyState.ACTIVE
                && a.state() != KeyState.UNKNOWN) {
              // Read anyway: a handle kept from before a rotation hears of the replacement.
              kms.stale(a);
              List<String> newer = a.links(LinkKind.REPLACEMENT).stream().distinct().toList();
              throw new StateConflictException(
                      operation
                          + ": key "
                          + id
                          + " is "
                          + a.state()
                          + unusable(a.state())
                          + (newer.isEmpty()
                              ? ""
                              : "; "
                                  + id
                                  + " names "
                                  + String.join(", ", newer)
                                  + " as its replacement"),
                      e,
                      operation,
                      id,
                      e.result().orElse(null),
                      null)
                  .observed(a.state());
            }
            throw e;
          }
        });
  }

  /**
   * Decrypt, verify and MAC verify: a Permission Denied (or a state refusal) for a key in a state
   * that forbids processing (Pre-Active, Destroyed) is a {@link StateConflictException}, as {@link
   * #diagnosed} makes it for encrypt, sign and MAC (KMIP 1.x servers refuse such a key with
   * Permission Denied, where 2.x says Wrong Key Lifecycle State), with one message on every
   * version, naming the state. A Deactivated or Compromised key may still process, so a refusal of
   * one stays as the server said, and so does a refusal that cannot be about the state ({@link
   * Failures#lifecycleAmbiguous}). {@code known} is the key's attributes when the call read them
   * already; otherwise they are read on that failure only.
   */
  private <T> T stateRefusal(
      String operation, KeyAttributes known, java.util.function.Supplier<T> call) {
    return kms.call(
        operation,
        () -> {
          try {
            return call.get();
          } catch (PermissionDeniedException | StateConflictException e) {
            if (e instanceof AlreadyExistsException || !Failures.lifecycleAmbiguous(e)) throw e;
            KeyAttributes a = known;
            if (a == null)
              try {
                a = attributes();
              } catch (KmsException | IllegalStateException unreadable) {
                throw e;
              }
            KeyState state = a.state();
            // Only states that forbid processing: a Deactivated or Compromised key may still
            // decrypt
            // and verify, so a refusal of one is the server's access policy.
            if (state != KeyState.PRE_ACTIVE
                && state != KeyState.DESTROYED
                && state != KeyState.DESTROYED_COMPROMISED) throw e;
            throw new StateConflictException(
                operation
                    + ": key "
                    + id
                    + " is "
                    + state
                    + (state == KeyState.PRE_ACTIVE
                        ? unusable(state)
                        : ", so the server refused it"),
                e,
                operation,
                id,
                e.result().orElse(null),
                null);
          }
        });
  }

  /** What to do about a key that is not Active, for the state messages of cryptographic calls. */
  static String unusable(KeyState state) {
    return switch (state) {
      case PRE_ACTIVE -> ", so the server refused it: a Pre-Active key needs activate() first";
      case DEACTIVATED ->
          ", so the server refused it: a Deactivated key no longer encrypts, signs or computes MACs: use the current"
              + " key (latest(), or findByName)";
      case COMPROMISED ->
          ", so the server refused it: a Compromised key no longer protects data: replace it (replaceCompromised())"
              + " and re-seal under the replacement";
      default -> ", so the server refused it";
    };
  }

  /** The spec a stored ciphertext names, if a stored ciphertext may choose it. */
  static CipherSpec storedSpec(Ciphertext ciphertext) {
    CipherSpec spec = CipherSpec.forName(ciphertext.specName());
    if (spec.rsaOaep())
      throw Ciphertext.invalid(
          "names "
              + spec
              + ", which anyone with the public key can produce; decrypt it with the"
              + " expected CipherSpec",
          ciphertext.keyId());
    if (!spec.selectableByCiphertext())
      throw Ciphertext.invalid(
          "names "
              + spec
              + ", which is not tamper-evident; decrypt it with the expected CipherSpec",
          ciphertext.keyId());
    return spec;
  }

  /**
   * The checks that need no server: spec name, IV and tag lengths, additional data. With a spec
   * taken from the stored ciphertext ({@code stored}), additional data the spec cannot take means
   * the ciphertext was relabeled: an invalid ciphertext, not a caller error.
   */
  static void check(CipherSpec spec, Ciphertext ciphertext, byte[] aad, boolean stored) {
    if (!spec.accepts(ciphertext.specName()))
      throw Ciphertext.invalid(
          "was made with " + ciphertext.specName() + ", not " + spec, ciphertext.keyId());
    if (!spec.authenticated() && aad != null && aad.length > 0) {
      if (spec.rsaOaep()) {
        if (!ciphertext.specName().endsWith(CipherSpec.BOUND))
          throw Ciphertext.invalid(
              "was made without binding additional data (before KMIP 1.4), but additional data was given",
              ciphertext.keyId());
      } else if (stored)
        throw Ciphertext.invalid(
            "names " + spec + ", which takes no additional data, but additional data was given",
            ciphertext.keyId());
      else throw new IllegalArgumentException(spec + " does not authenticate additional data");
    }
    int ivLength = ciphertext.iv().length, tagLength = ciphertext.tag().length;
    if (!spec.custom() && ivLength != spec.ivLength())
      throw Ciphertext.invalid(
          "has a " + ivLength + "-byte IV; " + spec + " uses " + spec.ivLength(),
          ciphertext.keyId());
    if (tagLength != spec.tagLength())
      throw Ciphertext.invalid(
          "has a " + tagLength + "-byte tag; " + spec + " uses " + spec.tagLength(),
          ciphertext.keyId());
  }

  /**
   * {@link KeyPairHandle#decrypt}: the pair was established by the SDK, so the ciphertext may name
   * either key; this private key's state and usages are checked as for {@link #decrypt}.
   */
  byte[] decryptForPair(CipherSpec spec, Ciphertext ciphertext, byte[] aad) {
    return kms.call(
        "decrypt",
        () -> {
          KeyAttributes mine = attributes();
          requireUsable(Kms.named("decrypt"), id, mine);
          requireSuited(Kms.named("decrypt"), id, mine, decrypting(spec));
          return decryptChecked(spec, ciphertext, aad);
        });
  }

  /** Decrypts after the ciphertext, spec and key were checked. */
  byte[] decryptChecked(CipherSpec spec, Ciphertext ciphertext, byte[] aad) {
    ProtocolVersion version = kms.protocolVersion();
    boolean label = spec.rsaOaep() && ciphertext.specName().endsWith(CipherSpec.BOUND);
    CryptoParameters parameters =
        spec.parameters(
            version,
            Kms.named("decrypt"),
            id,
            label ? Ciphertext.boundAad(ciphertext.keyId(), ciphertext.specName(), aad) : null);
    boolean integrity = spec.tamperEvident() || spec.authenticated();
    return stateRefusal(
        Kms.named("decrypt"),
        null,
        () ->
            kms.execute(
                Kms.named("decrypt"),
                Kms.Kind.READ_CRYPTO,
                id,
                integrity,
                s -> {
                  CryptoRequests.Builder b =
                      CryptoRequests.decrypt(id).parameters(parameters).data(ciphertext.data());
                  if (ciphertext.iv().length > 0) b.iv(ciphertext.iv());
                  if (spec.authenticated()) {
                    b.aad(Ciphertext.boundAad(ciphertext.keyId(), ciphertext.specName(), aad));
                    b.tag(ciphertext.tag());
                  }
                  byte[] out =
                      data(
                          CryptoResult.of(s.call(b.build())),
                          version,
                          spec,
                          ciphertext.data().length,
                          false);
                  int expected = spec.outputLength(ciphertext.data().length, false);
                  if (expected >= 0 && out.length != expected)
                    throw new ProtocolException(
                        "Decrypt returned plaintext of the wrong length for " + spec, null, null);
                  return out;
                }));
  }

  /** {@link CurrentKey#wrapKey(SecretKey, byte[])} under this key: AES-GCM. */
  Ciphertext wrapKey(SecretKey key, byte[] aad) {
    return wrapKey(CipherSpec.aesGcm(), key, aad);
  }

  /**
   * Wraps a local key with this key on the server, using {@code spec}, and binds {@code aad} where
   * the spec authenticates additional data. This is the KMIP Encrypt operation, so the key needs
   * the Encrypt usage (and Decrypt for {@link #unwrapKey(CipherSpec, Expect, Ciphertext, byte[])}).
   *
   * <p><b>Advanced.</b> For a spec of your choice: AES key wrap ({@link CipherSpec#keyWrap()}), or
   * RSA-OAEP under a public key, unwrapped later through the private key's handle. To wrap data
   * keys with AES-GCM under the key in force, use {@link CurrentKey#wrapKey(SecretKey, byte[])}.
   * See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">the
   * advanced alternatives</a>.
   *
   * @param spec how to wrap
   * @param key the key to wrap; not destroyed
   * @param aad the additional data to bind; null or empty for none
   * @return the wrapped key
   */
  public Ciphertext wrapKey(CipherSpec spec, SecretKey key, byte[] aad) {
    Objects.requireNonNull(key, "key");
    Objects.requireNonNull(spec, "spec");
    byte[] raw = key.getEncoded();
    if (raw == null) throw new IllegalArgumentException("The key cannot be exported");
    try {
      return Kms.named(
          "wrapKey",
          () -> {
            return encrypt(spec, raw, aad);
          });
    } finally {
      Arrays.fill(raw, (byte) 0);
    }
  }

  /**
   * Unwraps a key wrapped by {@link CurrentKey#wrapKey(SecretKey, byte[])} or {@link
   * #wrapKey(CipherSpec, SecretKey, byte[])} (with AES-GCM or AES key wrap), with the same
   * additional data. The key and state rules are those of {@link #decrypt(Ciphertext, byte[])}: the
   * wrapped key must name this key or a key of its lineage. The unwrapped key must be what {@code
   * expect} describes. Destroy the result when finished.
   *
   * <p><b>Advanced.</b> Unwraps with the key this handle names, such as a Compromised key during
   * recovery, through {@link #allowingCompromised()}. {@link CurrentKey#unwrapKey} unwraps what was
   * wrapped under the key in force and its lineage. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">the
   * advanced alternatives</a>.
   *
   * @param expect what the unwrapped key must be
   * @param wrapped the wrapped key
   * @param aad the additional data given when wrapping; null or empty for none
   * @return a new key, owned by the caller, who destroys it
   * @throws KeyMismatchException when the unwrapped key does not have the expected size, or the
   *     wrapped key names a key outside this key's lineage
   * @throws CryptographicFailureException as for {@link #decrypt(Ciphertext, byte[])}
   */
  public DestroyableSecretKey unwrapKey(Expect expect, Ciphertext wrapped, byte[] aad) {
    Objects.requireNonNull(expect, "expect");
    Objects.requireNonNull(wrapped, "wrapped");
    String jca = KeyReader.jcaSecretName(expect);
    return Kms.named(
        "unwrapKey",
        () -> {
          requireKind(Kms.named("unwrapKey"), ObjectKind.SYMMETRIC_KEY, ObjectKind.PRIVATE_KEY);
          return unwrapped(decrypt(wrapped, aad), expect, jca, id);
        });
  }

  /**
   * Unwraps with an expected spec, for keys wrapped with RSA-OAEP or another spec a stored
   * ciphertext may not choose. RSA-OAEP says nothing about who wrapped the key: see {@link
   * CipherSpec#rsaOaep(Hash, Hash)}.
   *
   * <p><b>Advanced.</b> For a spec of your choice, the other side of {@link #wrapKey(CipherSpec,
   * SecretKey, byte[])}. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">the
   * advanced alternatives</a>.
   *
   * @param spec the spec the key must have been wrapped with
   * @param expect what the unwrapped key must be
   * @param wrapped the wrapped key
   * @param aad the additional data given when wrapping; null or empty for none
   * @return a new key, owned by the caller, who destroys it
   */
  public DestroyableSecretKey unwrapKey(
      CipherSpec spec, Expect expect, Ciphertext wrapped, byte[] aad) {
    Objects.requireNonNull(spec, "spec");
    Objects.requireNonNull(expect, "expect");
    Objects.requireNonNull(wrapped, "wrapped");
    String jca = KeyReader.jcaSecretName(expect);
    return Kms.named(
        "unwrapKey",
        () -> {
          requireKind(Kms.named("unwrapKey"), ObjectKind.SYMMETRIC_KEY, ObjectKind.PRIVATE_KEY);
          return unwrapped(decrypt(spec, wrapped, aad), expect, jca, id);
        });
  }

  /** The unwrapped key, after checking its size; {@code raw} is wiped. */
  static DestroyableSecretKey unwrapped(byte[] raw, Expect expect, String jca, String kekId) {
    try {
      int bytes = raw.length;
      String problem = null;
      if (bytes == 0) problem = "the unwrapped key is empty";
      else if (expect.bits() != 0 && bytes * 8 != expect.bits())
        problem = "expected a " + expect.bits() + "-bit key, the unwrapped key has " + bytes * 8;
      else if (expect.algorithm() == Algorithm.AES && bytes != 16 && bytes != 24 && bytes != 32)
        problem = "the unwrapped key has " + bytes * 8 + " bits, which is not an AES key size";
      if (problem != null) {
        String operation = Kms.named("unwrapKey");
        // Inside open, the size is the container's, not the caller's expectation: a bad record.
        if (operation.equals("open"))
          throw KeyMismatchException.ciphertext(
              "open: the sealed data's " + problem.replace("the unwrapped key", "data key"),
              operation,
              kekId);
        throw new KeyMismatchException(
            operation + ": " + problem, null, operation, kekId, null, null);
      }
      return new DestroyableSecretKey(raw, jca);
    } finally {
      Arrays.fill(raw, (byte) 0);
    }
  }

  /** {@link CurrentKey#generateDataKey} under this key, which stays fixed (see there). */
  DataKey generateDataKey(int bits, byte[] aad) {
    Expect.aes(bits);
    byte[] raw = random(bits / 8);
    DestroyableSecretKey key = new DestroyableSecretKey(raw, "AES");
    Arrays.fill(raw, (byte) 0);
    try {
      return Kms.named(
          "generateDataKey",
          () -> {
            return new DataKey(key, wrapKey(key, aad));
          });
    } catch (RuntimeException e) {
      key.destroy();
      throw e;
    }
  }

  /** {@link CurrentKey#seal} under this key, which stays fixed (see there). */
  byte[] seal(byte[] plaintext, byte[] aad) {
    return Kms.named(
        "seal",
        () -> {
          return Envelopes.seal(this, plaintext, aad);
        });
  }

  /**
   * Opens data sealed by {@link CurrentKey#seal} under this key, or another key of its rotation
   * lineage, with the same additional data. The data key is unwrapped on the server with the rules
   * of {@link #unwrapKey(Expect, Ciphertext, byte[])} (one Get Attributes and one Decrypt), then
   * the data is decrypted locally.
   *
   * <p><b>Advanced.</b> Opens with the key this handle names. {@link CurrentKey#open} opens what
   * was sealed under the key in force and its lineage. Use this for a key you name, such as a
   * Compromised key during recovery:
   *
   * <pre>{@code
   * // replacement: the key that replaced the compromised one
   * // stored: a record sealed under a key that is Compromised now; aad: its additional data
   * Map<String, KeyHandle> trusted = new HashMap<>();
   * for (KeyHandle k : replacement.compromisedPredecessors()) trusted.put(k.id(), k);
   * KeyHandle compromised = trusted.get(KmsKeys.sealedKeyId(stored));
   * if (compromised == null) throw new IllegalStateException("not under a key we revoked");
   * byte[] plaintext = compromised.open(stored, aad);
   * }</pre>
   *
   * See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/envelope-encryption.md#seal-and-open-records">Seal
   * and open records</a>.
   *
   * @param sealed the sealed record
   * @param aad the additional data given when sealing; null or empty for none
   * @return the plaintext, a new array
   * @throws CryptographicFailureException when the container is malformed ({@code
   *     INVALID_CIPHERTEXT}), or the data key or data does not authenticate ({@code
   *     AUTHENTICATION_FAILED}): the container or the additional data changed
   * @throws KeyMismatchException when the container names a key outside this key's lineage (as for
   *     {@link #decrypt(Ciphertext, byte[])})
   * @throws StateConflictException when that key is Compromised or Destroyed, or the container's
   *     key is not found and a link of the chain cannot be resolved
   * @throws UnsupportedException when the container's key is not found within 64 rotations of this
   *     key and the lineage goes on (as for {@link #decrypt(Ciphertext, byte[])})
   */
  public byte[] open(byte[] sealed, byte[] aad) {
    return Kms.named(
        "open",
        () -> {
          return Envelopes.open(sealed, aad, wrapped -> unwrapKey(Expect.aes(256), wrapped, aad));
        });
  }

  /**
   * A stream that seals what is written to it under this key, for data too large to hold in memory.
   * It encrypts locally with AES-256-GCM under a fresh data key, in 64 KiB chunks, and writes to
   * {@code out}.
   *
   * <p>The data key is wrapped now: one Encrypt, plus one Get Attributes the first time on a handle
   * that does not know its key's usages. No request is sent per chunk. Call {@link
   * SealingStream#finish()} before closing: only a finished stream can be opened, and closing an
   * unfinished one throws {@link IOException}. So a job that fails part-way never leaves an
   * authentic but truncated stream. Closing destroys the data key. Writes throw {@link IOException}
   * for errors of {@code out}, and after 2^32 chunks (256 TiB). Not thread-safe.
   *
   * <pre>{@code
   * // upload: your destination; source: an InputStream of the plaintext
   * try (SealingStream sealed = kek.sealing(upload.start(), recordId)) {
   *   source.transferTo(sealed);
   *   sealed.finish();
   * }
   * upload.commit(); // only once the stream is finished and closed
   * }</pre>
   *
   * <p><b>Advanced.</b> A stream under the key this handle names, which a refusal does not move.
   * Seal streams under the key in force with {@link CurrentKey#sealing}, which follows a rotation,
   * and files with {@link CurrentKey#sealTo}, which moves the output into place only once it is
   * finished. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/envelope-encryption.md#stream-large-data">Stream
   * large data</a>.
   *
   * @param out where the sealed form goes; the returned stream owns it, and this method closes it
   *     before it throws
   * @param aad the additional data to bind; null or empty for none
   * @return a stream to write the plaintext to, owned by the caller, who finishes and closes it
   * @throws UnsupportedException before KMIP 1.4
   * @throws KeyMismatchException when this is a symmetric key that cannot decrypt what it would
   *     encrypt (no Decrypt usage), checked before anything is sent
   * @throws StateConflictException when the key is not Active (Pre-Active, Deactivated,
   *     Compromised), on every version
   */
  public SealingStream sealing(OutputStream out, byte[] aad) {
    return Kms.named(
        "sealing",
        () ->
            StreamEnvelopes.sealing(
                this, out, aad, StreamEnvelopes.CHUNK, StreamEnvelopes.MAX_CHUNKS));
  }

  /**
   * Opens a stream written by {@link #sealing}, under this key or another key of its rotation
   * lineage, with the same additional data. The data key is unwrapped now with the rules of {@link
   * #open}, so key, state and lineage errors come from this method. No request is sent per chunk.
   *
   * <p>Each chunk's plaintext is released only once its tag has verified, but only reaching the end
   * ({@code read} returning -1) proves the data complete. A read that fails throws {@link
   * CryptographicFailureException} ({@code BAD_DATA}): the stream was cut, extended, reordered or
   * changed, or {@code aad} differs. What was read before is authentic but may be incomplete, so
   * keep the result only once the end was read. {@link #openTo} does this for a file. Closing the
   * returned stream closes {@code in} and destroys the data key. Not thread-safe.
   *
   * <pre>{@code
   * // download: your source; staging: a temporary destination
   * try (InputStream plain = kek.opening(download.stream(), recordId)) {
   *   plain.transferTo(staging);
   * }
   * staging.commit(); // only once the end was read
   * }</pre>
   *
   * <p><b>Advanced.</b> Opens with the key this handle names. {@link CurrentKey#opening} opens
   * what was sealed under the key in force and its lineage, and a sealed file opens through {@link
   * CurrentKey#openTo}. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/envelope-encryption.md#stream-large-data">Stream
   * large data</a>.
   *
   * @param in the sealed stream; the returned stream owns it, and this method closes it before it
   *     throws
   * @param aad the additional data given when sealing; null or empty for none
   * @return a stream of the plaintext, owned by the caller, who closes it
   * @throws IOException for errors of {@code in} while the header is read
   * @throws CryptographicFailureException when the header is malformed or truncated, or its chunk
   *     size is outside 4 KiB..1 MiB ({@code INVALID_CIPHERTEXT}), or the data key does not
   *     authenticate ({@code AUTHENTICATION_FAILED})
   * @throws KeyMismatchException as for {@link #open}
   * @throws StateConflictException as for {@link #open}
   */
  public InputStream opening(InputStream in, byte[] aad) throws IOException {
    return Kms.named(
        "opening",
        () ->
            StreamEnvelopes.opening(
                in,
                aad,
                wrapped -> unwrapKey(Expect.aes(256), wrapped, aad),
                StreamEnvelopes.MAX_CHUNKS));
  }

  /** {@link CurrentKey#chunkedSealer} under this key, which stays fixed (see there). */
  ChunkedSealer chunkedSealer(byte[] fileId) {
    return Kms.named(
        "seal",
        () -> {
          return ChunkedEnvelopes.sealer(id, fileId, (key, aad) -> wrapKey(key, aad));
        });
  }

  /**
   * An opener for the chunks of a file sealed by {@link CurrentKey#chunkedSealer}, under this key
   * or another key of its rotation lineage, with the same file identifier. The header is parsed and
   * the data key unwrapped now, with the rules of {@link #open}, and checked against the header's
   * key commitment: one Get Attributes and one Decrypt, plus one Get Attributes per rotation
   * crossed. Opening chunks sends no request. The opener never seals.
   *
   * <p><b>Advanced.</b> Opens with the key this handle names. {@link CurrentKey#chunkedOpener}
   * opens what was sealed under the key in force and its lineage. Use this for a key you name, such
   * as a Compromised key during recovery:
   *
   * <pre>{@code
   * // trusted: the compromisedPredecessors() of the replacement, by identifier
   * KeyHandle compromised = trusted.get(KmsKeys.chunkedHeaderKeyId(header));
   * if (compromised == null) throw new IllegalStateException("not under a key we revoked");
   * ChunkedOpener opener = compromised.chunkedOpener(header, fileId);
   * }</pre>
   *
   * See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/envelope-encryption.md#seal-files-chunk-by-chunk">Seal
   * files chunk by chunk</a>.
   *
   * @param header the file's header, {@link ChunkedSealer#header()} (not null; copied)
   * @param fileId the file identifier it was sealed with (not null; copied)
   * @return a new opener, which owns the chunk key: close it with the file
   * @throws CryptographicFailureException when the header is malformed ({@code
   *     INVALID_CIPHERTEXT}), or the data key does not authenticate with this file identifier, or
   *     does not match the header's key commitment ({@code AUTHENTICATION_FAILED})
   * @throws KeyMismatchException as for {@link #open}
   * @throws StateConflictException as for {@link #open}
   * @throws UnsupportedException before KMIP 1.4
   * @since 0.10.0
   */
  public ChunkedOpener chunkedOpener(byte[] header, byte[] fileId) {
    return Kms.named(
        "chunkedOpener",
        () -> {
          return ChunkedEnvelopes.opener(
              header, fileId, (wrapped, aad) -> unwrapKey(Expect.aes(256), wrapped, aad));
        });
  }

  /**
   * {@link CurrentKey#rewrapHeader} to this key: the header's data key is unwrapped with this
   * handle's rules ({@link #chunkedOpener}), checked against its key commitment, and wrapped by this
   * key; a header already under it is returned unchanged.
   */
  byte[] rewrapHeader(byte[] header, byte[] fileId) {
    ChunkedEnvelopes.Header h = ChunkedEnvelopes.parse(header);
    Objects.requireNonNull(fileId, "fileId");
    if (h.wrappedKey().keyId().equals(id)) return header;
    return kms.call(
        "rewrapHeader",
        () -> {
          requireKind("rewrapHeader", ObjectKind.SYMMETRIC_KEY);
          requireDecryptable("rewrapHeader", CipherSpec.aesGcm());
          return ChunkedEnvelopes.rewrapped(
              h,
              fileId.clone(),
              aad -> unwrapKey(Expect.aes(256), h.wrappedKey(), aad),
              (key, aad) -> wrapKey(key, aad));
        });
  }

  /** {@link CurrentKey#sealTo(java.nio.file.Path, InputStream, byte[])} under this key (see there). */
  void sealTo(java.nio.file.Path target, InputStream plaintext, byte[] aad) throws IOException {
    sealTo(target, plaintext, aad, FileDurability.DURABLE);
  }

  /** {@link CurrentKey#sealTo(java.nio.file.Path, InputStream, byte[], FileDurability)} under this key. */
  void sealTo(
      java.nio.file.Path target, InputStream plaintext, byte[] aad, FileDurability durability)
      throws IOException {
    StagedFiles.sealTo(target, plaintext, durability, out -> sealing(out, aad));
  }

  /**
   * Opens the sealed file {@code sealed} into the file {@code target}, and replaces {@code target}
   * only once the whole stream has verified. {@code sealed} was written by {@link
   * CurrentKey#sealTo} or {@link #sealing}, under this key or another key of its rotation lineage.
   *
   * <p>The plaintext goes to a temporary file next to {@code target}, named {@code
   * .<name>.<random>.partial}. It is forced to the storage device and moved onto {@code target}
   * atomically once the end was read. A failure before the move leaves {@code target} as it was and
   * deletes the temporary file. A failure to force the directory comes after the move: {@code
   * target} is then the new file, not yet confirmed durable. The server requests are made before
   * any file is created. The call deadline does not cover the file I/O. {@code sealed} may be
   * {@code target}. Permissions, concurrent calls and durability are as for {@link
   * CurrentKey#sealTo}.
   *
   * <p><b>This writes plaintext to disk.</b> A crash can leave the temporary file
   * behind (delete such files at startup, as {@link CurrentKey#sealTo} says), and owner-only
   * permissions do not encrypt at rest. To keep data encrypted at rest, read it with {@link
   * #opening} instead.
   *
   * <p><b>Advanced.</b> Opens with the key this handle names, such as a Compromised key during
   * recovery through {@link #allowingCompromised()}. {@link CurrentKey#openTo} opens what was
   * sealed under the key in force and its lineage. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/envelope-encryption.md#seal-and-open-files">Seal
   * and open files</a>.
   *
   * @param sealed the sealed file
   * @param target the file to write
   * @param aad the additional data given when sealing; null or empty for none
   * @throws IOException for errors of the file system: a {@link java.nio.file.NoSuchFileException}
   *     when {@code sealed} or the directory of {@code target} does not exist, and a {@link
   *     java.nio.file.FileSystemException} when {@code target} is a directory, both before anything
   *     is sent; a {@link java.nio.file.FileSystemException} naming the directory when it opens but
   *     cannot be forced after the move, the one failure after which {@code target} is the new file
   * @throws IllegalArgumentException when {@code target} has no file name (a root)
   * @throws CryptographicFailureException as for {@link #opening} ({@code BAD_DATA}), from the
   *     header or from any chunk, the last included
   * @throws KeyMismatchException as for {@link #open}
   * @throws StateConflictException as for {@link #open}
   */
  public void openTo(java.nio.file.Path sealed, java.nio.file.Path target, byte[] aad)
      throws IOException {
    openTo(sealed, target, aad, FileDurability.DURABLE);
  }

  /**
   * {@link #openTo(java.nio.file.Path, java.nio.file.Path, byte[])} with the durability chosen, as
   * for {@link CurrentKey#sealTo(java.nio.file.Path, InputStream, byte[], FileDurability)}.
   *
   * <p><b>Advanced.</b> As {@link #openTo(java.nio.file.Path, java.nio.file.Path, byte[])}.
   *
   * @param sealed the sealed file
   * @param target the file to write
   * @param aad the additional data given when sealing; null or empty for none
   * @param durability whether the directory is forced after the move
   * @throws IOException as for {@link #openTo(java.nio.file.Path, java.nio.file.Path, byte[])}, and,
   *     for {@link FileDurability#DURABLE}, when the directory opens but cannot be forced: {@code
   *     target} was replaced already (the message says so)
   * @since 0.10.0
   */
  public void openTo(
      java.nio.file.Path sealed, java.nio.file.Path target, byte[] aad, FileDurability durability)
      throws IOException {
    Kms.runNamed(
        "openTo", () -> StagedFiles.openTo(sealed, target, durability, in -> opening(in, aad)));
  }

  /**
   * Whether {@code opening} (this handle opening or unwrapping a record that names its key, for a
   * rewrap from another {@code Kms}) succeeds: false when it fails as {@code BAD_DATA}, which means
   * the record is another server's with a colliding identifier. The result is wiped.
   */
  private boolean authenticates(java.util.function.Supplier<byte[]> opening) {
    byte[] plaintext;
    try {
      plaintext = opening.get();
    } catch (KmsException e) {
      if (e.category() == KmsException.Category.BAD_DATA) return false;
      throw e;
    }
    wipe(plaintext);
    return true;
  }

  /** Tests only: sees each buffer of intermediate plaintext or key material {@code rewrap} wipes, just before. */
  static volatile java.util.function.Consumer<byte[]> beforeWipe;

  private static void wipe(byte[] buffer) {
    java.util.function.Consumer<byte[]> hook = beforeWipe;
    if (hook != null) hook.accept(buffer);
    Arrays.fill(buffer, (byte) 0);
  }

  /** {@link #rewrapTo rewrapTo(this, sealed, aad)}: a record moved to this key. */
  byte[] rewrap(byte[] sealed, byte[] aad) {
    return rewrapTo(this, sealed, aad);
  }

  /** {@link #rewrap}, saying whether the record changed ({@link CurrentKey#rewrapRecord}). */
  Rewrapped rewrapRecord(byte[] sealed, byte[] aad) {
    return rewrapRecordTo(this, sealed, aad);
  }

  /**
   * {@link #rewrapTo}, saying whether the record changed: unchanged exactly when {@code rewrapTo}
   * would return the array it was given (the record is {@code target}'s already). Same requests and
   * exceptions as {@link #rewrapTo}.
   *
   * <p><b>Advanced.</b> As {@link #rewrapTo}.
   *
   * @param target the key to seal under
   * @param sealed the sealed record
   * @param aad the additional data given when sealing; null or empty for none
   * @return the record and whether it changed
   */
  public Rewrapped rewrapRecordTo(KeyHandle target, byte[] sealed, byte[] aad) {
    return kms.call(
        "rewrapRecordTo",
        () -> {
          byte[] out = rewrapTo(target, sealed, aad);
          return new Rewrapped(out, out != sealed, KmsKeys.sealedKeyId(out));
        });
  }

  /**
   * Re-seals a record made by {@link CurrentKey#seal} under {@code target}, without the plaintext
   * leaving the SDK.
   *
   * <p>The record is opened with this handle's rules ({@link #open}), sealed under {@code target}
   * with a fresh data key and the same additional data, and the plaintext in between is wiped. The
   * data key is fresh because after a compromise the old one must be taken as exposed. Three
   * requests (Get Attributes, Decrypt, Encrypt), plus one Get Attributes per rotation crossed. A
   * record that already names {@code target}'s key is returned unchanged, without a request and
   * without being authenticated, so a re-sealing job can be repeated. {@link #rewrapRecordTo} says
   * whether it changed.
   *
   * <p><b>Another {@code Kms}.</b> {@code target} may come from another {@link Kms}, such as
   * another server: the record is then migrated. An identifier names an object only on its own
   * server, so there the record is returned unchanged only when the target can open it (two more
   * requests). A {@code BAD_DATA} failure means another server's key with a colliding identifier,
   * and the record is migrated.
   *
   * <p><b>Advanced.</b> Moves records to a key you name: compromise recovery ({@code
   * key.allowingCompromised().rewrapTo(replacement, record, aad)}), or another {@link Kms}. After a
   * rotation, {@link CurrentKey#rewrapRecord} moves them to the key in force. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#a-compromised-key">A
   * compromised key</a>.
   *
   * @param target the key to seal under
   * @param sealed the sealed record
   * @param aad the additional data given when sealing; null or empty for none
   * @return the record under {@code target}: {@code sealed} itself (the same array) when it is
   *     under {@code target} already, otherwise a new array
   * @throws KeyMismatchException when {@code target} cannot decrypt what it would seal (checked
   *     before opening), or as for {@link #open}
   * @throws CryptographicFailureException as for {@link #open}; nothing is sealed then
   * @throws StateConflictException as for {@link #open}
   */
  public byte[] rewrapTo(KeyHandle target, byte[] sealed, byte[] aad) {
    Objects.requireNonNull(target, "target");
    boolean named = KmsKeys.sealedKeyId(sealed).equals(target.id);
    if (named && target.sameKms(kms)) return sealed;
    return kms.call(
        "rewrapTo",
        () -> {
          target.requireKind("rewrap", ObjectKind.SYMMETRIC_KEY);
          target.requireDecryptable("rewrap", CipherSpec.aesGcm());
          if (named && target.authenticates(() -> target.open(sealed, aad))) return sealed;
          byte[] plaintext = open(sealed, aad);
          try {
            return target.seal(plaintext, aad);
          } finally {
            wipe(plaintext);
          }
        });
  }

  /** {@link #rewrapKeyTo rewrapKeyTo(this, wrapped, aad)}: a wrapped key moved to this key. */
  Ciphertext rewrapKey(Ciphertext wrapped, byte[] aad) {
    return rewrapKeyTo(this, wrapped, aad);
  }

  /**
   * Wraps the key inside {@code wrapped} under {@code target} instead, with the same spec (AES-GCM
   * or AES key wrap) and additional data, without the key leaving the SDK.
   *
   * <p>The key is unwrapped with this handle's rules ({@link #unwrapKey(Expect, Ciphertext,
   * byte[])}), wrapped by {@code target}, and the unwrapped bytes are wiped. Three requests (Get
   * Attributes, Decrypt, Encrypt), plus one Get Attributes per rotation crossed and one for {@code
   * target}'s usages if its handle does not know them. A wrapped key that already names {@code
   * target}'s key is returned unchanged without a request. For a target of another {@link Kms},
   * that happens only once the target has unwrapped it, as for {@link #rewrapTo}. The data the key
   * protects is not touched: after a compromise of the old wrapping key, re-encrypt that data under
   * a new data key instead.
   *
   * <p><b>Advanced.</b> Moves wrapped keys to a key you name, as {@link #rewrapTo} moves records.
   * After a rotation, {@link CurrentKey#rewrapKey} moves them to the key in force. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">the
   * advanced alternatives</a>.
   *
   * @param target the key to wrap under
   * @param wrapped the wrapped key
   * @param aad the additional data given when wrapping; null or empty for none
   * @return the key wrapped by {@code target}: {@code wrapped} itself when it is under {@code
   *     target} already
   * @throws KeyMismatchException when {@code target} cannot decrypt what it would wrap, or as for
   *     {@link #unwrapKey(Expect, Ciphertext, byte[])}
   * @throws CryptographicFailureException as for {@link #decrypt(Ciphertext, byte[])}
   * @throws StateConflictException as for {@link #decrypt(Ciphertext, byte[])} (a Compromised or
   *     Destroyed key), or when {@code target} is not Active
   */
  public Ciphertext rewrapKeyTo(KeyHandle target, Ciphertext wrapped, byte[] aad) {
    Objects.requireNonNull(target, "target");
    Objects.requireNonNull(wrapped, "wrapped");
    boolean named = wrapped.keyId().equals(target.id);
    if (named && target.sameKms(kms)) return wrapped;
    CipherSpec spec = storedSpec(wrapped);
    return kms.call(
        "rewrapKeyTo",
        () -> {
          target.requireKind("rewrapKey", ObjectKind.SYMMETRIC_KEY);
          target.requireDecryptable("rewrapKey", spec);
          if (named && target.authenticates(() -> target.decrypt(spec, wrapped, aad, true)))
            return wrapped;
          requireKind("rewrapKey", ObjectKind.SYMMETRIC_KEY, ObjectKind.PRIVATE_KEY);
          byte[] raw = decrypt(spec, wrapped, aad, true);
          try {
            return target.encrypt(spec, raw, aad);
          } finally {
            wipe(raw);
          }
        });
  }

  /**
   * Signs {@code message} on the server.
   *
   * @param spec how to sign
   * @param message the message to sign
   * @return the signature, a new array
   * @throws UnsupportedException for a spec the negotiated version cannot express (RSA-PSS before
   *     KMIP 1.4)
   */
  public byte[] sign(SignatureSpec spec, byte[] message) {
    Objects.requireNonNull(spec, "spec");
    Objects.requireNonNull(message, "message");
    requireKind("sign", ObjectKind.PRIVATE_KEY);
    spec.requireVersion(kms.protocolVersion(), "sign", id);
    Request request = CryptoRequests.sign(id).parameters(spec.parameters()).data(message).build();
    return diagnosed(
        "sign",
        SIGNING,
        () ->
            kms.execute(
                "sign",
                Kms.Kind.READ_CRYPTO,
                id,
                s ->
                    CryptoResult.of(s.call(request))
                        .signatureData()
                        .orElseThrow(() -> Kms.missing("SignatureData"))));
  }

  /**
   * Verifies a signature on the server. Only {@link VerifyResult#VALID} means it is good. Before the
   * server is asked, the states of this object and of its private key are checked:
   *
   * <ul>
   *   <li><b>This object.</b> It is read first, with one Get Attributes. A Compromised one is
   *       refused unless this handle is {@link #allowingCompromised()}, since its signatures may be
   *       forged. A Destroyed one is always refused.
   *   <li><b>A confirmed private key.</b> When this object has a Private Key link, that private key
   *       is read too, with one more Get Attributes. The link is confirmed when the private key's
   *       Public Key or Certificate link names this object back. A confirmed private key that is
   *       Compromised, or Destroyed after a compromise, is refused the same way. One that was only
   *       destroyed does not matter.
   *   <li><b>No confirmed private key.</b> When there is no Private Key link, the link is not
   *       confirmed, or the private key cannot be read, only this object's own state is checked.
   * </ul>
   *
   * <p>So when a private key is compromised, revoke its public key too. {@link KeyPairHandle#revoke}
   * revokes both keys of a pair. KMIP links a certificate to its public key, not to its private key,
   * and this method does not follow that chain. So revoke the pair's certificates too.
   *
   * @param spec how the message was signed
   * @param message the signed message
   * @param signature the signature
   * @return the server's verdict; only {@link VerifyResult#VALID} means the signature is good
   * @throws StateConflictException when the key, or its linked private key, is Compromised, or the
   *     key is Destroyed
   */
  public VerifyResult verify(SignatureSpec spec, byte[] message, byte[] signature) {
    Objects.requireNonNull(spec, "spec");
    requireKind("verify", ObjectKind.PUBLIC_KEY, ObjectKind.CERTIFICATE);
    spec.requireVersion(kms.protocolVersion(), "verify", id);
    Request request =
        CryptoRequests.signatureVerify(id)
            .parameters(spec.parameters())
            .data(Objects.requireNonNull(message, "message"))
            .signature(Objects.requireNonNull(signature, "signature"))
            .build();
    return kms.call(
        "verify",
        () -> {
          KeyAttributes a = attributes();
          requireUsable("verify", id, a);
          requireSuited("verify", id, a, VERIFYING);
          requireSignerUsable(a);
          return stateRefusal(
              "verify",
              a,
              () ->
                  kms.execute(
                      "verify",
                      Kms.Kind.READ_CRYPTO,
                      id,
                      s -> verdict(CryptoResult.of(s.call(request)))));
        });
  }

  /** Refuses to verify when the private key that signs for this object is known to be Compromised. */
  private void requireSignerUsable(KeyAttributes mine) {
    for (String privateId : mine.links(LinkKind.PRIVATE_KEY)) {
      KeyAttributes signer;
      try {
        signer = keys.handle(privateId).attributes();
      } catch (NotFoundException | PermissionDeniedException unreadable) {
        if (Failures.credentialsRefused(unreadable)) throw unreadable;
        continue;
      }
      boolean confirmed =
          signer.kind() == ObjectKind.PRIVATE_KEY
              && (signer.links(LinkKind.PUBLIC_KEY).contains(id)
                  || signer.links(LinkKind.CERTIFICATE).contains(id));
      if (!confirmed) continue;
      KeyState state = knownState("verify", privateId, signer);
      if ((state == KeyState.COMPROMISED || state == KeyState.DESTROYED_COMPROMISED)
          && !compromisedAllowed)
        throw new StateConflictException(
            "verify: the private key "
                + privateId
                + " of "
                + id
                + " is "
                + state
                + ", so signatures it made may be forged; use allowingCompromised() on this handle to verify anyway",
            null,
            "verify",
            id,
            null,
            null);
    }
  }

  /**
   * Computes a MAC on the server.
   *
   * @param spec how to compute the MAC
   * @param message the message
   * @return the MAC, a new array
   */
  public byte[] mac(MacSpec spec, byte[] message) {
    Objects.requireNonNull(spec, "spec");
    requireKind("mac", ObjectKind.SYMMETRIC_KEY);
    CryptoRequests.Builder b =
        CryptoRequests.mac(id).data(Objects.requireNonNull(message, "message"));
    if (spec.parameters() != null) b.parameters(spec.parameters());
    Request request = b.build();
    return diagnosed(
        "mac",
        MACING,
        () ->
            kms.execute(
                "mac",
                Kms.Kind.READ_CRYPTO,
                id,
                s ->
                    CryptoResult.of(s.call(request))
                        .macData()
                        .orElseThrow(() -> Kms.missing("MACData"))));
  }

  /**
   * Verifies a MAC on the server; the state rule is that of {@link #verify}.
   *
   * @param spec how the MAC was computed
   * @param message the message
   * @param mac the MAC
   * @return the server's verdict; only {@link VerifyResult#VALID} means the MAC is good
   */
  public VerifyResult macVerify(MacSpec spec, byte[] message, byte[] mac) {
    Objects.requireNonNull(spec, "spec");
    requireKind("macVerify", ObjectKind.SYMMETRIC_KEY);
    CryptoRequests.Builder b =
        CryptoRequests.macVerify(id)
            .data(Objects.requireNonNull(message, "message"))
            .macData(Objects.requireNonNull(mac, "mac"));
    if (spec.parameters() != null) b.parameters(spec.parameters());
    Request request = b.build();
    return kms.call(
        "macVerify",
        () -> {
          KeyAttributes a = attributes();
          requireUsable("macVerify", id, a);
          requireSuited("macVerify", id, a, MAC_VERIFYING);
          return stateRefusal(
              "macVerify",
              a,
              () ->
                  kms.execute(
                      "macVerify",
                      Kms.Kind.READ_CRYPTO,
                      id,
                      s -> verdict(CryptoResult.of(s.call(request)))));
        });
  }

  private static VerifyResult verdict(CryptoResult r) {
    return r.validity()
        .map(
            v ->
                switch (v) {
                  case VALID -> VerifyResult.VALID;
                  case INVALID -> VerifyResult.INVALID;
                  default -> VerifyResult.UNKNOWN;
                })
        .orElse(VerifyResult.UNKNOWN);
  }

  /** Refuses, before sending, an operation this handle's known kind cannot perform. */
  private void requireKind(String operation, ObjectKind... allowed) {
    if (kind == null) return;
    for (ObjectKind k : allowed) if (k == kind) return;
    throw new KeyMismatchException(
        operation + ": " + id + " is a " + kind + ", not " + Arrays.toString(allowed),
        null,
        operation,
        id,
        null,
        null);
  }

  private static byte[] random(int length) {
    byte[] b = new byte[length];
    RANDOM.nextBytes(b);
    return b;
  }

  /**
   * Whether this handle addresses objects through {@code other} or a {@link Kms#withTimeout} view
   * of it (or the {@code Kms} {@code other} is a view of): an identifier names an object only on
   * its own server, so an identifier from a handle of another {@code Kms} must not be used here.
   */
  boolean sameKms(Kms other) {
    return kms.owner() == other.owner();
  }

  @Override
  public boolean equals(Object o) {
    return o instanceof KeyHandle k && k.id.equals(id) && k.kms.owner() == kms.owner();
  }

  @Override
  public int hashCode() {
    return id.hashCode();
  }

  @Override
  public String toString() {
    return "KeyHandle[" + id + (kind == null ? "" : ", " + kind) + "]";
  }
}
