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
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.*;
import java.util.*;
import java.util.stream.*;
import javax.crypto.SecretKey;

/**
 * Creates, registers and finds keys, certificates and other managed objects, and opens stored data
 * by a query. Get it from {@link Kms#keys()}.
 *
 * <pre>{@code
 * KmsKeys keys = kms.keys();
 * keys.createAes(256).named("invoices-kek")
 *     .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).findOrCreate();
 * CurrentKey kek = keys.current("invoices-kek");
 * Optional<KeyHandle> found = keys.findByName("invoices-kek");
 * String keyId = found.orElseThrow().id();
 * }</pre>
 *
 * <p>A key name is not an access-control boundary, because anyone who may create keys on the
 * server can create one with your name (see <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/getting-started.md#key-names-are-not-access-control">Key
 * names are not access control</a>).
 *
 * <p>{@code KmsKeys} is thread-safe, and the builders it returns are not. It holds no resource of
 * its own and works while its {@code Kms} is open.
 *
 * @since 0.10.0
 */
public final class KmsKeys {
  private final Kms kms;
  private volatile boolean batchGetAttributes = true;

  KmsKeys(Kms kms) {
    this.kms = kms;
  }

  Kms kms() {
    return kms;
  }

  // ---- creation ----

  /**
   * A 128-, 192- or 256-bit AES key.
   *
   * @param bits 128, 192 or 256
   * @return a new builder
   * @throws IllegalArgumentException for any other size
   */
  public KeyCreation createAes(int bits) {
    Expect.aes(bits);
    return new KeyCreation(this, Algorithm.AES, bits);
  }

  /**
   * A symmetric key of another algorithm, for example {@code HMAC_SHA256} with 256 bits.
   *
   * @param algorithm a symmetric algorithm
   * @param bits the key size in bits, positive (128, 192 or 256 for AES)
   * @return a new builder
   * @throws IllegalArgumentException for an algorithm that is not symmetric, or an invalid size
   */
  public KeyCreation createSymmetric(Algorithm algorithm, int bits) {
    Objects.requireNonNull(algorithm, "algorithm");
    if (!algorithm.symmetric())
      throw new IllegalArgumentException(algorithm + " is not a symmetric algorithm");
    if (algorithm == Algorithm.AES) Expect.aes(bits);
    if (bits < 1) throw new IllegalArgumentException("Invalid key size");
    return new KeyCreation(this, algorithm, bits);
  }

  /**
   * An asymmetric key pair; see {@link KeyPairCreation}.
   *
   * @param spec the algorithm and size of the pair
   * @return a new builder
   */
  public KeyPairCreation createKeyPair(KeyPairSpec spec) {
    return new KeyPairCreation(this, Objects.requireNonNull(spec, "spec"));
  }

  // ---- registration ----

  /**
   * Registers a JCA secret key (AES, Triple DES, ChaCha20 or HMAC).
   *
   * @param key the key; its encoded form is read when the registration is sent, not now
   * @return a new builder
   */
  public KeyRegistration register(SecretKey key) {
    Objects.requireNonNull(key, "key");
    Algorithm algorithm = Algorithm.fromJca(key.getAlgorithm());
    return new KeyRegistration(
        this,
        new Registrable(ObjectKind.SYMMETRIC_KEY, false) {
          @Override
          Request build(KmsKeys keys, ObjectOptions options, Algorithm ec) {
            byte[] raw = key.getEncoded();
            if (raw == null) throw new IllegalArgumentException("The key cannot be exported");
            try {
              Ttlv object = ManagedObjects.rawSymmetricKey(raw, algorithm.requireWire());
              return keys.register(
                  object, keys.attributes(algorithm.requireWire(), raw.length * 8, options));
            } finally {
              Arrays.fill(raw, (byte) 0);
            }
          }
        });
  }

  /**
   * Registers an RSA or EC private key (sent as PKCS#8).
   *
   * @param key the private key
   * @return a new builder
   */
  public KeyRegistration register(PrivateKey key) {
    Objects.requireNonNull(key, "key");
    requireRsaOrEc(key);
    return new KeyRegistration(
        this,
        new Registrable(ObjectKind.PRIVATE_KEY, key instanceof ECKey) {
          @Override
          Request build(KmsKeys keys, ObjectOptions options, Algorithm ec) {
            Enums.CryptographicAlgorithm algorithm = keys.asymmetricAlgorithm(key, ec);
            byte[] der = key.getEncoded();
            if (der == null || !"PKCS#8".equals(key.getFormat()))
              throw new IllegalArgumentException("The private key cannot be exported as PKCS#8");
            try {
              Ttlv object =
                  ManagedObjects.privateKey(
                      ManagedObjects.keyBlock(
                          Enums.KeyFormatType.PKCS_8,
                          bytes(KEY_MATERIAL, der),
                          algorithm,
                          bits(key)));
              return keys.register(object, keys.attributes(algorithm, bits(key), options));
            } finally {
              Arrays.fill(der, (byte) 0);
            }
          }
        });
  }

  /**
   * Registers an RSA or EC public key (sent as X.509 SubjectPublicKeyInfo).
   *
   * @param key the public key
   * @return a new builder
   */
  public KeyRegistration register(PublicKey key) {
    Objects.requireNonNull(key, "key");
    requireRsaOrEc(key);
    return new KeyRegistration(
        this,
        new Registrable(ObjectKind.PUBLIC_KEY, key instanceof ECKey) {
          @Override
          Request build(KmsKeys keys, ObjectOptions options, Algorithm ec) {
            Enums.CryptographicAlgorithm algorithm = keys.asymmetricAlgorithm(key, ec);
            Ttlv object =
                ManagedObjects.publicKey(
                    ManagedObjects.keyBlock(
                        Enums.KeyFormatType.X_509,
                        bytes(KEY_MATERIAL, key.getEncoded()),
                        algorithm,
                        bits(key)));
            return keys.register(object, keys.attributes(algorithm, bits(key), options));
          }
        });
  }

  /**
   * Registers an X.509 certificate. The algorithm and length of its subject key and the
   * certificate's length are derived.
   *
   * <p>Usages come from the builder. Without {@link KeyRegistration#usages}, they come from the
   * certificate's X.509 Key Usage extension, mapped as KMIP 1.x servers map them:
   *
   * <ul>
   *   <li>{@code digitalSignature}: Verify
   *   <li>{@code keyEncipherment}: Wrap Key
   *   <li>{@code dataEncipherment}: Encrypt
   *   <li>{@code keyAgreement}: Key Agreement
   *   <li>{@code keyCertSign}: Certificate Sign
   *   <li>{@code cRLSign}: CRL Sign
   * </ul>
   *
   * <p>A certificate without the extension gets Verify. A CA certificate without it also gets
   * Certificate Sign and CRL Sign. An extension that grants none of these gives Verify.
   *
   * <p>A KMIP 1.x server may refuse usages that claim more than the extension grants, as
   * keytend-kmip-server does. For example, a CA certificate with only {@code keyCertSign} and
   * {@code cRLSign}, registered with Verify, is refused.
   *
   * @param certificate the certificate
   * @return a new builder
   */
  public KeyRegistration register(X509Certificate certificate) {
    Objects.requireNonNull(certificate, "certificate");
    return new KeyRegistration(
        this,
        new Registrable(ObjectKind.CERTIFICATE, certificate.getPublicKey() instanceof ECPublicKey) {
          @Override
          Request build(KmsKeys keys, ObjectOptions options, Algorithm ec) {
            UsageMask usage =
                UsageMask.of(options.usages.stream().map(KeyUsage::protocolValue).toList());
            CertificateRegistration registration = CertificateRegistration.of(certificate, usage);
            if (ellipticCurve()) registration.ecAlgorithm(keys.ecDefault(ec));
            for (String n : options.names) registration.name(n);
            for (Ttlv a : keys.extraAttributes(options)) registration.attribute(a);
            return registration.build();
          }

          @Override
          Set<KeyUsage> defaultUsages() {
            return KeyUsage.of(certificate);
          }
        });
  }

  /**
   * Registers a secret that is not a key as KMIP Secret Data of {@code type}: {@link
   * SecretData.Type#PASSWORD} for credentials (passwords, API tokens, connection secrets), {@link
   * SecretData.Type#SEED} for random material other keys or values are derived from. KMIP has no
   * other standard Secret Data type, so {@code OTHER} is refused. The bytes are copied at once,
   * and the copy is wiped once registration succeeds, so the caller may wipe its array. A failed
   * attempt can be repeated with the same builder.
   *
   * <p>To replace a secret, register the new one with {@link KeyRegistration#replace(KeyHandle)}.
   * {@code kms.keys().registerSecret(newPassword).named("db-password").replace(old)} moves the
   * name from {@code old} to the new secret and deactivates {@code old} if it is Active. A step
   * that fails is reported with {@link PartialCompletionException}. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#replacing-a-secret">Replacing
   * a secret</a>.
   *
   * @param type {@link SecretData.Type#PASSWORD} or {@link SecretData.Type#SEED}
   * @param secret the secret; copied, so the caller may wipe its array at once
   * @return a new builder
   * @throws IllegalArgumentException for {@link SecretData.Type#OTHER}
   */
  public KeyRegistration registerSecret(SecretData.Type type, byte[] secret) {
    Objects.requireNonNull(type, "type");
    Objects.requireNonNull(secret, "secret");
    if (type.protocolValue() == null)
      throw new IllegalArgumentException(
          "Register a PASSWORD or SEED; KMIP defines no other Secret Data type");
    return secretData(type.protocolValue(), secret.clone());
  }

  /**
   * Registers a password as KMIP Secret Data of type Password, encoded as UTF-8 ({@link
   * SecretData#chars()} reads it back). The characters are copied at once, and the copy is wiped
   * once registration succeeds, so the caller may wipe its array. To replace a password, see
   * {@link #registerSecret(SecretData.Type, byte[])}.
   *
   * @param password the password; copied
   * @return a new builder
   */
  @SuppressWarnings("ByteBufferBackingArray") // the encoder's own heap buffer, offset 0, wiped
  public KeyRegistration registerSecret(char[] password) {
    Objects.requireNonNull(password, "password");
    ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password));
    byte[] utf8 = Arrays.copyOf(encoded.array(), encoded.limit());
    Arrays.fill(encoded.array(), (byte) 0);
    return secretData(Enums.SecretDataType.PASSWORD, utf8);
  }

  private KeyRegistration secretData(Enums.SecretDataType type, byte[] secret) {
    return new KeyRegistration(
        this,
        new Registrable(ObjectKind.SECRET_DATA, false) {
          @Override
          Request build(KmsKeys keys, ObjectOptions options, Algorithm ec) {
            byte[] copy = secret.clone();
            try {
              Ttlv object =
                  ManagedObjects.secretData(
                      type,
                      ManagedObjects.keyBlock(
                          Enums.KeyFormatType.OPAQUE, bytes(KEY_MATERIAL, copy), null, null));
              List<Ttlv> attributes = new ArrayList<>();
              if (!options.usages.isEmpty()) attributes.add(usage(options.usages));
              attributes.addAll(keys.namesAndExtras(options));
              return keys.register(object, attributes);
            } finally {
              Arrays.fill(copy, (byte) 0);
            }
          }

          @Override
          void registered() {
            // Kept until registration succeeds, so a retry after a failure sends the secret again.
            Arrays.fill(secret, (byte) 0);
          }
        });
  }

  /** Something to register: it builds its Register request from the builder's options. */
  abstract static class Registrable {
    private final ObjectKind kind;
    private final boolean ellipticCurve;

    Registrable(ObjectKind kind, boolean ellipticCurve) {
      this.kind = kind;
      this.ellipticCurve = ellipticCurve;
    }

    ObjectKind kind() {
      return kind;
    }

    boolean ellipticCurve() {
      return ellipticCurve;
    }

    /** The usages registered when the builder gives none; empty when some are required. */
    Set<KeyUsage> defaultUsages() {
      return Set.of();
    }

    abstract Request build(KmsKeys keys, ObjectOptions options, Algorithm ec);

    /** Called once the object was registered. */
    void registered() {}
  }

  KeyHandle registerObject(Registrable object, ObjectOptions options, Algorithm ec) {
    Request request = object.build(this, options, ec);
    // The confirming Locate (on 1.x) shares the call's deadline: caught inside the call.
    String id =
        kms.call(
            "register",
            () -> {
              try {
                return kms.execute(
                    "register", Kms.Kind.MUTATION, null, s -> identifier(s.call(request)));
              } catch (InvalidRequestException | StateConflictException e) {
                throw duplicateName(e, options.names);
              }
            });
    object.registered();
    return new KeyHandle(this, id, object.kind());
  }

  private Request register(Ttlv object, List<Ttlv> attributes) {
    return Requests.registerObject(object, attributes.toArray(Ttlv[]::new));
  }

  private List<Ttlv> attributes(
      Enums.CryptographicAlgorithm algorithm, int bits, ObjectOptions options) {
    List<Ttlv> a = new ArrayList<>();
    a.add(Attributes.algorithm(algorithm));
    a.add(Attributes.length(bits));
    a.add(usage(options.usages));
    a.addAll(namesAndExtras(options));
    return a;
  }

  private List<Ttlv> namesAndExtras(ObjectOptions options) {
    return namesAndExtras(options, "register");
  }

  /** Names, groups and custom attributes; {@code operation} names the method in errors. */
  private List<Ttlv> namesAndExtras(ObjectOptions options, String operation) {
    List<Ttlv> a = new ArrayList<>();
    for (String n : options.names) a.add(Attributes.name(n));
    a.addAll(extraAttributes(options, operation));
    return a;
  }

  private List<Ttlv> extraAttributes(ObjectOptions options) {
    return extraAttributes(options, "register");
  }

  /**
   * Groups, custom attributes and the protection asked (Extractable, Sensitive: refused below KMIP
   * 1.4 before anything is sent); {@code operation} names the method in errors.
   */
  private List<Ttlv> extraAttributes(ObjectOptions options, String operation) {
    List<Ttlv> a = new ArrayList<>();
    if (!options.groups.isEmpty()) requireGroups(operation);
    Protection protection = options.protection();
    protection.require(kms.protocolVersion(), Kms.named(operation));
    for (String g : options.groups) a.add(group(g));
    for (var e : options.custom.entrySet()) a.add(custom(e.getKey(), e.getValue()));
    a.addAll(protection.attributes());
    return a;
  }

  /**
   * The {@link KeyMismatchException} for an object made with {@code asked} whose attributes {@code
   * read} do not state it (null when they do): the server ignored or changed the protection, or does
   * not report it, and the object is not to be used as if it had it.
   */
  static KeyMismatchException unprotected(
      String operation, String id, KeyAttributes read, Protection asked) {
    List<String> differences = asked.differences(read);
    if (differences.isEmpty()) return null;
    return new KeyMismatchException(
        operation
            + ": "
            + id
            + " was made with "
            + asked
            + ", but "
            + String.join("; ", differences),
        null,
        operation,
        id,
        null,
        null);
  }

  /**
   * Checks an object just made, Pre-Active, against the protection asked ({@link #unprotected}): a
   * {@link PartialCompletionException} naming it when it does not state it, so it is not activated
   * or returned. {@code read} null: it is read here (one Get Attributes).
   */
  void checkProtection(String operation, KeyHandle created, KeyAttributes read, Protection asked) {
    if (!asked.any()) return;
    String advice =
        "do not activate or use "
            + created.id()
            + ": it is Pre-Active, and the server may release its value;"
            + " remove its names (removeName) so that no lookup finds it, and keep the protection on the server"
            + " some other way, or ask for none";
    if (read == null)
      try {
        read = created.attributes();
      } catch (KmsException | IllegalStateException e) {
        throw PartialCompletionException.of(
            operation,
            List.of(created),
            null,
            "reading it back to check its " + asked + " failed",
            "check with attributes() that "
                + created.id()
                + " has the protection asked ("
                + asked
                + "), and activate it only if it has; if not, do not activate or use it, and"
                + " remove its names (removeName) so that no lookup finds it",
            e);
      }
    KeyMismatchException m = unprotected(operation, created.id(), read, asked);
    if (m != null)
      throw PartialCompletionException.of(
          operation,
          List.of(created),
          null,
          "the server did not keep the protection asked",
          advice,
          m);
  }

  private static void requireRsaOrEc(Key key) {
    if (!(key instanceof RSAKey) && !(key instanceof ECKey))
      throw new IllegalArgumentException(
          "Only RSA and EC keys are supported, not " + key.getAlgorithm());
  }

  private Enums.CryptographicAlgorithm asymmetricAlgorithm(Key key, Algorithm ec) {
    return key instanceof RSAKey ? Enums.CryptographicAlgorithm.RSA : ecDefault(ec);
  }

  private Enums.CryptographicAlgorithm ecDefault(Algorithm ec) {
    if (ec != null) return ec.requireWire();
    return kms.protocolVersion().atLeast(Enums.CryptographicAlgorithm.EC.since())
        ? Enums.CryptographicAlgorithm.EC
        : Enums.CryptographicAlgorithm.ECDSA;
  }

  private static int bits(Key key) {
    if (key instanceof RSAKey rsa) return rsa.getModulus().bitLength();
    return ((ECKey) key).getParams().getCurve().getField().getFieldSize();
  }

  // ---- lookup ----

  /**
   * A handle for an existing object; nothing is sent.
   *
   * @param id the object's identifier
   * @return the handle
   */
  public KeyHandle handle(String id) {
    return new KeyHandle(this, Objects.requireNonNull(id, "id"), null);
  }

  /**
   * The key pair of an existing private key: its Public Key link names the public key, whose
   * Private Key link must name it back (two Get Attributes).
   *
   * @param privateKeyId the private key's identifier
   * @return the key pair
   * @throws KeyMismatchException when {@code privateKeyId} is not a private key, or the two keys do
   *     not link to each other
   */
  public KeyPairHandle keyPair(String privateKeyId) {
    Objects.requireNonNull(privateKeyId, "privateKeyId");
    return kms.call(
        "keyPair",
        () -> {
          KeyAttributes mine = handle(privateKeyId).attributes();
          if (mine.kind() != ObjectKind.PRIVATE_KEY)
            throw new KeyMismatchException(
                "keyPair: " + privateKeyId + " is a " + mine.kind() + ", not a private key",
                null,
                "keyPair",
                privateKeyId,
                null,
                null);
          String publicId =
              mine.link(LinkKind.PUBLIC_KEY)
                  .orElseThrow(
                      () ->
                          new KeyMismatchException(
                              "keyPair: private key " + privateKeyId + " has no Public Key link",
                              null,
                              "keyPair",
                              privateKeyId,
                              null,
                              null));
          KeyAttributes theirs = handle(publicId).attributes();
          if (theirs.kind() != ObjectKind.PUBLIC_KEY
              || !theirs.link(LinkKind.PRIVATE_KEY).map(privateKeyId::equals).orElse(false))
            throw new KeyMismatchException(
                "keyPair: public key "
                    + publicId
                    + " does not link back to private key "
                    + privateKeyId,
                null,
                "keyPair",
                privateKeyId,
                null,
                null);
          return new KeyPairHandle(
              new KeyHandle(this, privateKeyId, ObjectKind.PRIVATE_KEY),
              new KeyHandle(this, publicId, ObjectKind.PUBLIC_KEY));
        });
  }

  /**
   * The current key named {@code name}, followed as other instances rotate it ({@link
   * CurrentKey}). Sealing goes under the key {@link KeyHandle#latest()} returns. That is checked
   * once a minute, and whenever sealing is refused because the key is not Active, so the
   * application needs no refresh-and-retry code. Starts from {@link #findByName(String)}'s key.
   *
   * @param name the key's name
   * @return a new follower of the key
   * @throws NotFoundException when no Active key has the name (create it with {@link
   *     KeyCreation#findOrCreate()} first)
   */
  public CurrentKey current(String name) {
    Objects.requireNonNull(name, "name");
    return kms.call("current", () -> current(findCurrent(name)).observing(KeyState.ACTIVE));
  }

  /** The Active key {@code name} names, for {@link #current(String)}. */
  private KeyHandle findCurrent(String name) {
    return findByName(name)
        .orElseThrow(
            () ->
                new NotFoundException(
                    "current: no Active key is named "
                        + name
                        + "; create it with findOrCreate() first",
                    null,
                    "current",
                    null,
                    null,
                    null));
  }

  /**
   * {@code key}, followed as other instances rotate it ({@link CurrentKey}), for example the handle
   * {@link KeyCreation#findOrCreate()} returned at startup. No request.
   *
   * @param key the key to start from
   * @return a new follower of the key
   */
  public CurrentKey current(KeyHandle key) {
    return new CurrentKey(
        Objects.requireNonNull(key, "key"), CurrentKey.DEFAULT_CHECK_EVERY, System::nanoTime);
  }

  /**
   * Configures a {@link LocalKeys} cache of symmetric keys used locally, refreshed ahead of a hard
   * TTL. The write key is selected by name, not by lineage, because an external tool owns
   * creation, rotation and retirement. A stable scope must also be configured, for reads of older
   * keys by identifier. Nothing is sent until the cache is used. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/local-keys.md#keys-taken-out-of-the-kms">Keys
   * taken out of the KMS</a>.
   *
   * @param writeKeyName the name external tools give the current Active write key, not empty
   * @return a new builder; configure it, then call {@link LocalKeys.Builder#open()}
   * @throws IllegalArgumentException when the name is empty
   * @since 0.10.0
   */
  public LocalKeys.Builder localKeys(String writeKeyName) {
    return new LocalKeys.Builder(this, writeKeyName);
  }

  /**
   * The Active object with this name, found with one state-filtered Locate. Pre-Active,
   * Deactivated, Compromised and Destroyed objects with the name are ignored; name other states
   * with {@link #findByName(String, KeyState, KeyState...)}. When several Active objects have the
   * name, one is chosen as described there.
   *
   * @param name the name
   * @return empty when no Active object has the name
   */
  public Optional<KeyHandle> findByName(String name) {
    return findByName(name, KeyState.ACTIVE);
  }

  /**
   * The object with this name in one of the states: one state-filtered Locate per state.
   *
   * <p>Servers that do not enforce unique names can hold several objects with one name, for
   * example after replicas raced to create a key. Their attributes are then read, and every caller
   * that sees the same objects chooses the same one. The rotation lineage whose first key was
   * created earliest wins. Within it the newest key with the name comes first, an Active one
   * before others, as {@link KeyHandle#latest()} chooses. So a key keeps its name after rotation,
   * and a later duplicate is not chosen over it.
   *
   * <p>Names are not access control. Anyone who controls a key created before yours can claim the
   * name through that key's links. Where others may create objects, use a server that enforces
   * unique names, or find keys by an attribute only you can set.
   *
   * <p>When the objects cannot be ranked safely, this throws instead of guessing. That happens for
   * an object with the name these credentials cannot read, or a lineage whose start cannot be
   * followed (for example a predecessor destroyed and purged while a duplicate exists). Remove the
   * name from the unwanted object to fix that. A
   * Pre-Active key left by a {@code findOrCreate} call cut short counts as a duplicate, so destroy
   * such leftovers that are yours ({@link KeyHandle#leftovers()}) before retiring old keys. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/kms-design.md#names-lookup-findorcreate-and-duplicates">Names,
   * lookup, findOrCreate and duplicates</a>.
   *
   * @param name the name
   * @param state a state to look for
   * @param more more states to look for
   * @return empty when no object with the name is in those states
   * @throws StateConflictException when the objects with the name cannot be ranked, as above
   * @throws UnsupportedException for a lineage longer than 64 rotations that would not rank first
   */
  public Optional<KeyHandle> findByName(String name, KeyState state, KeyState... more) {
    Objects.requireNonNull(name, "name");
    EnumSet<KeyState> states = EnumSet.of(Objects.requireNonNull(state, "state"));
    for (KeyState s : more) states.add(Objects.requireNonNull(s, "state"));
    Set<String> ids = new LinkedHashSet<>();
    return kms.call(
        "findByName",
        () -> {
          for (KeyState s : states) ids.addAll(identifiers(KeyQuery.byName(name).state(s)));
          if (ids.size() <= 1) return ids.stream().findFirst().map(this::handle);
          return chooseAmong(new ArrayList<>(ids));
        });
  }

  /**
   * Joins the newest keys of the rotation lineage that the name {@code name} leads to: {@link
   * KeyHandle#reconcile()} from the key {@link #findByName(String, KeyState, KeyState...)} chooses
   * among the objects with the name in any state but Destroyed. When no object has the name, it
   * starts from a key that records the name as being moved to it, and finishes that move. Anyone
   * can write that record on a key of their own, so check that such a key is yours first, because
   * reconcile gives it the name. An operator's call, from the place that rotates keys. To have
   * it approved first, show {@link #reconcilePlan(String)} and pass it to {@link
   * #reconcile(String, ReconcilePlan)}.
   *
   * @param name the name
   * @return the lineage's remaining newest key, Active; empty when no object has the name
   * @throws KmsException as {@link KeyHandle#reconcile()}, and as {@link #findByName(String,
   *     KeyState, KeyState...)} when the objects with the name cannot be ranked
   */
  public Optional<KeyHandle> reconcile(String name) {
    Objects.requireNonNull(name, "name");
    return kms.call(
        "reconcile",
        () -> {
          return reconcileStart(name).map(start -> start.key().reconcile(start.own(), null));
        });
  }

  /**
   * What {@link #reconcile(String)} would change now, without changing anything: the newest key it
   * keeps, the newest keys it joins into it, the names it moves and the keys it deactivates. Show
   * it, have it approved, then reconcile exactly this with {@link #reconcile(String,
   * ReconcilePlan)}.
   *
   * <p>The plan comes from the walk and the checks the reconcile makes, so it is refused in the
   * same cases, such as a chosen newest key that is not Active. Same reads as the reconcile, no
   * change.
   *
   * @param name the name
   * @return the plan; empty when {@link #reconcile(String)} would return empty (no object has the
   *     name, and no key records a move of it)
   * @throws KmsException as {@link #reconcile(String)}, before anything is changed
   * @since 0.10.0
   */
  public Optional<ReconcilePlan> reconcilePlan(String name) {
    Objects.requireNonNull(name, "name");
    return kms.call(
        "reconcilePlan",
        () -> {
          return reconcileStart(name).map(start -> start.key().reconcilePlan(start.own(), name));
        });
  }

  /**
   * Reconciles the name as {@code plan} says, and changes nothing else: {@link #reconcile(String)}
   * bound to a plan from {@link #reconcilePlan(String)}. Use it after the plan was shown and
   * confirmed.
   *
   * <p>The name is looked up again and the plan computed again, before anything is changed. When the
   * name now leads to another newest key, or the reconcile would join, move or deactivate anything
   * the plan does not list (the name was moved to another lineage, another caller rotated, a key
   * was activated), the call is refused and nothing is changed: make a new plan. Then only what was
   * checked is changed. Planned steps done meanwhile are passed over, so a new plan after a {@link
   * PartialCompletionException} resumes. The check is made once, before the first change: change a
   * name's lineage from one place at a time.
   *
   * @param name the name
   * @param plan a plan for {@code name} from this {@code Kms}
   * @return the lineage's remaining newest key, Active: {@link ReconcilePlan#winner()}
   * @throws IllegalArgumentException when {@code plan} is for another name or from another {@link
   *     Kms}
   * @throws StateConflictException ({@link StateConflictException.Conflict#NOT_AS_PLANNED}) when no object has the name and no key records a move of it, or
   *     the reconcile would change something the plan does not list; nothing is changed
   * @throws KmsException as {@link #reconcile(String)}
   * @since 0.10.0
   */
  public KeyHandle reconcile(String name, ReconcilePlan plan) {
    Objects.requireNonNull(name, "name");
    Objects.requireNonNull(plan, "plan");
    if (plan.owner() != kms.owner() || !plan.name().equals(name))
      throw new IllegalArgumentException(
          "reconcile: the plan is for the name "
              + plan.name()
              + (plan.owner() != kms.owner() ? " on another Kms" : "")
              + ", not for "
              + name
              + "; make the plan with reconcilePlan(name) on this Kms");
    return kms.call(
        "reconcile",
        () -> {
          ReconcileStart start =
              reconcileStart(name)
                  .orElseThrow(
                      () ->
                          new StateConflictException(
                                  "reconcile: no object is named "
                                      + name
                                      + " now, and no key records a move of it; the plan kept "
                                      + plan.winner().id()
                                      + ". Nothing was changed: make a new plan",
                                  null,
                                  "reconcile",
                                  plan.winner().id(),
                                  null,
                                  null)
                              .because(StateConflictException.Conflict.NOT_AS_PLANNED));
          return start.key().reconcile(start.own(), plan);
        });
  }

  /** Where {@link #reconcile(String)} starts: a key, and whether it was found from a name. */
  private record ReconcileStart(KeyHandle key, boolean own) {}

  /**
   * The key {@link #reconcile(String)} starts from: the one the name chooses, else the key that
   * records a move of the name, after its checks; empty when there is neither.
   */
  private Optional<ReconcileStart> reconcileStart(String name) {
    Optional<KeyHandle> named =
        findByName(
            name, KeyState.ACTIVE, KeyState.PRE_ACTIVE, KeyState.DEACTIVATED, KeyState.COMPROMISED);
    if (named.isPresent()) return Optional.of(new ReconcileStart(named.get(), true));
    // On no key: a move between keys that stopped (where names are unique) left it recorded as
    // pending on the key that was to get it. Only within one lineage: records on keys of
    // several lineages (a stranger can write one on a key of its own) decide nothing.
    List<String> pending = pendingName(name);
    if (pending.isEmpty()) return Optional.empty();
    Set<String> lineage = new HashSet<>();
    Lineage.Tree tree =
        Lineage.tree("reconcile", handle(pending.get(0)).attributes(), false, null, this::read);
    for (KeyAttributes k : tree.keys()) lineage.add(k.id());
    List<String> outside = pending.stream().filter(p -> !lineage.contains(p)).toList();
    if (!outside.isEmpty())
      throw new StateConflictException(
              "reconcile: no object is named "
                  + name
                  + ", and the keys that record it as a name being moved to them, "
                  + pending
                  + ", belong to more than one rotation lineage, so which is yours cannot be decided; give"
                  + " the name by hand to the key of yours that should have it, then reconcile",
              null,
              "reconcile",
              pending.get(0),
              null,
              null)
          .because(StateConflictException.Conflict.NAME);
    // A lineage whose newest key is not Active (retired on purpose, its names removed, and a
    // record left behind): nothing to give the name to.
    KeyAttributes newest = tree.chosen();
    if (newest.state() != KeyState.ACTIVE)
      throw new StateConflictException(
              "reconcile: no object is named "
                  + name
                  + ", and the keys that record it as a name being moved to them, "
                  + pending
                  + ", belong to a lineage whose newest key, "
                  + newest.id()
                  + ", is "
                  + newest.state()
                  + ", not Active; if that lineage was retired on purpose, remove the records:"
                  + " kms.keys().clearPendingName(\""
                  + name
                  + "\"); otherwise activate "
                  + newest.id()
                  + " (or replace it with replaceCompromised when it is Compromised), then reconcile",
              null,
              "reconcile",
              newest.id(),
              null,
              null)
          .because(StateConflictException.Conflict.NAME);
    // Found from a record anyone can write on a key of their own: bounded as a stranger's walk.
    return Optional.of(new ReconcileStart(handle(pending.get(0)), false));
  }

  /**
   * Moves one name from the object {@code fromId} to the object {@code toId}, for an operator that
   * owns names outside the SDK's rotation (an external key tool, a database's write-key name).
   * Nothing else about either object changes, and neither is checked for any purpose.
   *
   * <p>It reads both objects' names, then sends one ordered batch that removes the name from
   * {@code fromId} and adds it to {@code toId}, with Batch Error Continuation Undo. The batch is
   * sent once, never again nor split. Then both objects are read again, within the same deadline.
   * When the first reads find the name already on {@code toId} only, it returns and nothing is
   * sent.
   *
   * <p>It returns once the last reads observe {@code toId} with the name and {@code fromId}
   * without it. A refusal the server acknowledged is thrown typed (for example {@link
   * AlreadyExistsException} for Non Unique Name), but only when the last reads observe the
   * original state. Anything else after the batch may have been sent is an {@link
   * OutcomeUnknownException} whose message says what each object held. Undo alone is never taken
   * as proof that nothing changed. After an unknown outcome, read both objects and find out why
   * before you repeat the move.
   *
   * <p>The batch is not a transaction or compare-and-swap. Another client can change either object
   * meanwhile, and some servers can show a moment where no object has the name. Run one operator
   * at a time for a name.
   *
   * <p><b>Advanced.</b> A scheduled rotation re-keys through {@link
   * CurrentKey#rotateIfActiveFor(Duration)}, and the server moves the name itself (see <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">The
   * advanced alternatives</a>).
   *
   * @param name the name to move, not blank
   * @param fromId the object that has the name, not blank
   * @param toId the object to give it to, not blank and not {@code fromId}
   * @throws IllegalArgumentException when an argument is blank, or the identifiers are equal
   * @throws StateConflictException when the first reads find both objects, or neither, with the
   *     name, or {@code fromId} with it more than once; nothing was sent
   * @throws NotFoundException when either object does not exist at the first reads
   * @throws UnsupportedException when the version or the server cannot do the exact deletion or
   *     the batch
   * @throws OutcomeUnknownException when the batch may have been sent and neither the move nor a
   *     refusal with the original state was observed
   * @throws KmsException other typed failures of the first reads, of a batch that was not sent, or
   *     a refusal the server acknowledged
   * @throws IllegalStateException when this {@code Kms} is closed before the batch is sent
   * @since 0.10.0
   */
  public void moveName(String name, String fromId, String toId) {
    requireText(name, "name");
    requireText(fromId, "fromId");
    requireText(toId, "toId");
    if (fromId.equals(toId))
      throw new IllegalArgumentException("fromId and toId are the same object: " + fromId);
    NameTransfer.move(kms, name, fromId, toId);
  }

  private static void requireText(String value, String what) {
    Objects.requireNonNull(value, what);
    if (value.isBlank()) throw new IllegalArgumentException(what + " is blank");
  }

  /**
   * Removes every record that the name {@code name} is being moved to a key, and returns the keys
   * it was removed from. Where names are unique, a compromise replacement or {@link
   * #reconcile(String)} writes such a record and removes it once the key has the name. While no
   * object has the name, a record makes {@code findOrCreate} refuse. Use this for a record whose
   * move cannot be finished, such as one a stranger wrote on a key of their own. Call it only when
   * no compromise replacement or reconcile of the name is running. To finish a stopped move
   * instead, use {@link #reconcile(String)}. A server that cannot search client attributes finds
   * no records.
   *
   * @param name the name
   * @return the identifiers of the keys whose record was removed
   * @throws KmsException when a record cannot be removed; repeat the call
   */
  public List<String> clearPendingName(String name) {
    Objects.requireNonNull(name, "name");
    return kms.call(
        "clearPendingName",
        () -> {
          List<String> cleared = new ArrayList<>();
          for (String id : pendingName(name)) {
            KeyHandle key = handle(id);
            try {
              key.removeCustomAttribute(KeyHandle.pendingName(name));
            } catch (OutcomeUnknownException lost) {
              if (KeyHandle.pendingNames(key.attributes()).contains(name)) throw lost;
            }
            cleared.add(id);
          }
          return cleared;
        });
  }

  /**
   * The objects named {@code name}, from one Locate without a state filter (a snapshot: a name
   * moving from one key to another between two state-filtered Locates would be missed by both), and
   * one batched Get Attributes; objects destroyed since the Locate are left out.
   */
  List<KeyAttributes> named(String name) {
    List<String> ids = identifiers(KeyQuery.byName(name));
    return ids.isEmpty() ? List.of() : candidates(Kms.named("findByName"), ids);
  }

  /**
   * Refuses {@code names} when an object that is not destroyed has one of them ({@link
   * KeyCreation#refusingExistingName()}): one Locate per name, without a state filter, and Get
   * Attributes of what it finds. An object that cannot be read fails the call; one that is gone is
   * passed over.
   *
   * @throws AlreadyExistsException naming the holders of the first name taken
   */
  void refuseExistingNames(String operation, Collection<String> names) {
    for (String name : names) {
      List<String> holders = new ArrayList<>();
      for (KeyAttributes a : attributesOf(identifiers(KeyQuery.byName(name))))
        if (a.state() != KeyState.DESTROYED && a.state() != KeyState.DESTROYED_COMPROMISED)
          holders.add(a.id());
      if (!holders.isEmpty())
        throw new AlreadyExistsException(
            operation
                + ": the name "
                + name
                + " is taken by "
                + String.join(", ", holders)
                + " (not destroyed), so nothing was "
                + (operation.startsWith("register") ? "registered" : "created"),
            null,
            operation,
            holders.get(0),
            null,
            null);
    }
  }

  /** {@link #singleFlight} for {@link KeyCreation#findOrCreateResult()}: a caller that waited found the key. */
  FindOrCreateResult singleFlightResult(
      Object key, java.util.function.Supplier<FindOrCreateResult> work) {
    return singleFlight(
        key,
        work,
        r -> List.of(r.key().id()),
        ids ->
            new FindOrCreateResult(
                new KeyHandle(this, ids.get(0), ObjectKind.SYMMETRIC_KEY),
                FindOrCreateResult.Outcome.FOUND,
                List.of(),
                null));
  }

  /**
   * The objects that record {@code name} as a name being moved to them ({@link
   * KeyHandle#pendingName}): one Locate, and batched Get Attributes of what it found, each checked
   * locally. Best effort: a server that cannot search client attributes finds none, and one that
   * does not filter by them is read only as far as its first {@link Lineage#FANOUT} objects. A
   * record missed here is found again by the next caller that looks, so the cost stays bounded
   * where the search cannot be made.
   */
  List<String> pendingName(String name) {
    Search found =
        search(
            KeyQuery.all().custom(KeyHandle.pendingName(name), name),
            true,
            a -> name.equals(a.custom().get(KeyHandle.pendingName(name))));
    return found.found().stream().map(KeyAttributes::id).toList();
  }

  /**
   * What a search found: the objects that matched, each read and checked locally, and whether
   * that is every object the server holds that matches ({@code complete}). Not complete when the
   * server refused the Locate (servers that cannot search client attributes: PyKMIP answers General
   * Failure), when it did not filter (it returned objects that do not match: some servers ignore
   * a client-attribute filter, and a server may cap what it returns), when it returned more than
   * one search reads ({@link Lineage#BUDGET}), or when an object it returned could not be read
   * ({@code unreadable}: these credentials may not read it, or the server's reply was not valid),
   * which may be one that matches. Callers that act on absence act only on a complete search with
   * nothing found; matches are real either way.
   */
  record Search(List<KeyAttributes> found, boolean complete, List<String> unreadable) {
    Search {
      found = List.copyOf(found);
      unreadable = List.copyOf(unreadable);
      complete &= unreadable.isEmpty();
    }

    Search(List<KeyAttributes> found, boolean complete) {
      this(found, complete, List.of());
    }

    /** A search that could not be made: nothing found, and absence not established. */
    static Search unknown() {
      return new Search(List.of(), false);
    }

    /** This search with only the objects {@code kept} accepts, in {@code order}; the same completeness. */
    Search keeping(
        Comparator<KeyAttributes> order, java.util.function.Predicate<KeyAttributes> kept) {
      return new Search(found.stream().filter(kept).sorted(order).toList(), complete, unreadable);
    }

    /**
     * Why it is not complete, for a message: "" when it is; otherwise a clause beginning with a
     * space, naming the objects it could not read.
     */
    String why() {
      if (complete) return "";
      return unreadable.isEmpty()
          ? " (the server refused it, did not filter it, or returned more than one search reads)"
          : " (it found "
              + String.join(", ", unreadable)
              + ", which could not be read: access was refused, or the server's reply was not valid)";
    }
  }

  /**
   * The objects whose client attribute {@code attribute} is {@code value}, as read now: one
   * Locate, and batched Get Attributes of up to {@link Lineage#BUDGET} objects it returns, each
   * checked locally. Strict ({@link Search#complete()}): for a caller that acts on finding none.
   */
  Search recording(CustomAttribute attribute, String value) {
    return search(
        KeyQuery.all().custom(attribute, value),
        false,
        a -> value.equals(a.custom().get(attribute)));
  }

  /**
   * The objects named {@code name}, as read now: one Locate by Name (which every server supports),
   * and batched Get Attributes of up to {@link Lineage#BUDGET} objects it returns, each checked
   * locally. Strict ({@link Search#complete()}): for a caller that finds the object its own lost
   * request made by a name only that request used.
   */
  Search holding(String name) {
    return search(KeyQuery.byName(name), false, a -> a.names().contains(name));
  }

  /**
   * What a request that makes one object under a {@code temporary} name only it uses made, after
   * its reply was lost ({@link #madeUnder}): the object, when it is proved its own and unchanged,
   * and otherwise what the search found.
   *
   * @param made the object, when the search could tell that it is the only one with the name and
   *     it is as the request left it
   * @param search what the search for the name found, every holder included
   */
  record Made(Optional<KeyAttributes> made, Search search) {
    /** Whether the search could tell that no object has the name: the request made nothing. */
    boolean none() {
      return made.isEmpty() && search.found().isEmpty() && search.complete();
    }

    /** The holders found, none of them proved the request's own. */
    List<String> holders() {
      return made.isPresent() ? List.of() : search.found().stream().map(KeyAttributes::id).toList();
    }

    /**
     * The one object the unknown outcome concerns, for its {@link KmsException#objectId()}: the
     * only holder found or the only object located that could not be read, when there is exactly
     * one of them; empty when the request's object was found, or none or several were.
     */
    Optional<String> concerned() {
      if (made.isPresent()) return Optional.empty();
      java.util.Set<String> ids = new java.util.LinkedHashSet<>(holders());
      ids.addAll(search.unreadable());
      return ids.size() == 1 ? Optional.of(ids.iterator().next()) : Optional.empty();
    }

    /**
     * What the search found, for the message of the unknown outcome when {@link #made} is empty,
     * after "and": none, holders that are not as {@code leftAs} says ("the Create left a key") with
     * the properties {@link #asMade} checks and {@code recorded} ("" or ", recording K": what
     * {@link #madeUnder}'s own predicate requires), holders it cannot show are the only ones, or
     * nothing it can rely on.
     */
    String described(String temporary, String leftAs, String recorded) {
      List<String> ids = holders();
      boolean one = ids.size() == 1;
      if (!ids.isEmpty() && search.complete())
        return (one ? "the object" : "the objects")
            + " with its temporary name "
            + temporary
            + ", "
            + String.join(", ", ids)
            + (one ? ", is" : ", are")
            + " not as "
            + leftAs
            + " (Pre-Active, linked to nothing, with that name alone"
            + recorded
            + (one ? "" : ", and the only object with it")
            + "): another caller changed "
            + (one ? "it" : "them")
            + ", or made "
            + (one ? "it" : "them")
            + " from that object with a Re-key, which moves names";
      if (!ids.isEmpty())
        return String.join(", ", ids)
            + (one ? " has" : " have")
            + " its temporary name "
            + temporary
            + ", but the search cannot show "
            + (one ? "it is the only object" : "which object")
            + " with that name"
            + search.why();
      if (search.complete()) return "no object has its temporary name " + temporary;
      return "the server could not be searched for its temporary name " + temporary + search.why();
    }
  }

  /**
   * The object a request of {@code kind} made under {@code temporary}, a name only that request
   * used, after its reply was lost, or after the server refused the name as in use (a TLS
   * identity's registration: {@code unknown}, on which a failed search is suppressed). It is taken
   * as the request's own only when the search could tell ({@link Search#complete()}) that it is the
   * only object with the name, and only when it is as that request left it: Pre-Active, of that
   * kind, linked to nothing (the requests recovered submit no link), with that name alone, and as
   * {@code recorded} requires. A key another caller re-keyed from it has the name (a Re-key moves
   * names and copies every other attribute) and a Replaced Object link, so it is not.
   */
  Made madeUnder(
      String temporary,
      ObjectKind kind,
      java.util.function.Predicate<KeyAttributes> recorded,
      KmsException unknown) {
    return madeUnder(temporary, kind, List::isEmpty, recorded, unknown);
  }

  /**
   * {@link #madeUnder(String, ObjectKind, java.util.function.Predicate, KmsException)} of a request
   * that leaves the object with links ({@code linksAsMade} says which it may have): a Create Key
   * Pair links each key to the other, and a Certify links the certificate to its public key and its
   * issuer.
   */
  Made madeUnder(
      String temporary,
      ObjectKind kind,
      java.util.function.Predicate<List<Link>> linksAsMade,
      java.util.function.Predicate<KeyAttributes> recorded,
      KmsException unknown) {
    Search search;
    try {
      search = holding(temporary);
    } catch (KmsException | IllegalStateException unsearchable) {
      unknown.addSuppressed(unsearchable);
      search = Search.unknown();
    }
    List<KeyAttributes> holders = search.found();
    if (search.complete()
        && holders.size() == 1
        && asMade(holders.get(0), kind, temporary)
        && linksAsMade.test(holders.get(0).links())
        && recorded.test(holders.get(0))) return new Made(Optional.of(holders.get(0)), search);
    return new Made(Optional.empty(), search);
  }

  /**
   * {@link #madeUnder}'s check that {@code a} is as a request that made it under {@code temporary}
   * left it, its links aside (checked by the caller's predicate).
   */
  private static boolean asMade(KeyAttributes a, ObjectKind kind, String temporary) {
    return a.kind() == kind
        && a.state() == KeyState.PRE_ACTIVE
        && a.names().equals(List.of(temporary));
  }

  /**
   * One Locate by {@code query}, whose answers are read and kept when {@code matches} them. With
   * {@code sampled} (best effort), a server that returns more than {@link Lineage#FANOUT} objects,
   * none of the first {@link Lineage#FANOUT} matching, is taken not to filter, and the rest are not
   * read; objects it cannot read are passed over. Strict, an object it returned that cannot be
   * read makes the search incomplete, as one that does not match does. A refusal of this client's
   * credentials, a transient failure and an unknown outcome are thrown; another refusal is a search
   * that could not be made.
   */
  private Search search(
      KeyQuery query, boolean sampled, java.util.function.Predicate<KeyAttributes> matches) {
    List<String> found;
    try {
      found = identifiers(query);
    } catch (TransientException | OutcomeUnknownException failed) {
      throw failed;
    } catch (KmsException unsearchable) {
      // Not a server that cannot search: a refusal of this client's credentials.
      if (Failures.credentialsRefused(unsearchable)) throw unsearchable;
      // Servers that cannot search client attributes (PyKMIP answers General Failure).
      return Search.unknown();
    }
    // Servers that ignore the filter return objects that do not match: each is read and
    // checked, the first FANOUT first. One that cannot be read may match: it is not a sign of
    // absence.
    List<String> unreadable = new ArrayList<>();
    int sample = Math.min(found.size(), Lineage.FANOUT);
    List<KeyAttributes> read = readable(found.subList(0, sample), unreadable);
    List<KeyAttributes> out = new ArrayList<>(read.stream().filter(matches).toList());
    boolean filtered = out.size() == read.size();
    if (sample < found.size() && !(sampled && out.isEmpty())) {
      // Many matches (many callers replaced one key at once), or a strict search: the rest, as far
      // as one walk reads.
      List<KeyAttributes> rest =
          readable(found.subList(sample, Math.min(found.size(), Lineage.BUDGET)), unreadable);
      List<KeyAttributes> kept = rest.stream().filter(matches).toList();
      filtered &= kept.size() == rest.size();
      out.addAll(kept);
    }
    if (sampled) return new Search(out, false);
    return new Search(out, filtered && found.size() <= Lineage.BUDGET, unreadable);
  }

  /**
   * The attributes of those of {@code ids} these credentials can read, as read now; the
   * identifiers of those that cannot be read (with these credentials, or the server's reply is not
   * valid) are added to {@code unreadable}. One that no longer exists is passed over. A refusal of
   * this client's credentials, rather than of one object, is thrown.
   */
  private List<KeyAttributes> readable(List<String> ids, List<String> unreadable) {
    if (ids.isEmpty()) return List.of();
    try {
      return attributesOf(ids);
    } catch (PermissionDeniedException | ProtocolViolationException denied) {
      if (Failures.credentialsRefused(denied)) throw denied;
      List<KeyAttributes> read = new ArrayList<>();
      for (String id : ids)
        try {
          read(id).ifPresent(read::add);
        } catch (PermissionDeniedException | ProtocolViolationException e) {
          if (Failures.credentialsRefused(e)) throw e;
          unreadable.add(id);
        }
      return read;
    }
  }

  /**
   * The objects with a link of {@code kind} to {@code id}, as read now: one Locate by that link,
   * each object it returns read and checked here. Strict ({@link Search#complete()}): complete
   * only when the server filtered, and every object it returned was read; a server that cannot
   * search by link gives an incomplete search with nothing found.
   */
  Search linkedTo(LinkKind kind, String id) {
    return search(KeyQuery.all().linkedTo(kind, id), false, a -> a.links(kind).contains(id));
  }

  /** The identifiers of the objects named {@code name}, in any state (one Locate). */
  List<String> nameHolders(String name) {
    return identifiers(KeyQuery.byName(name));
  }

  /** The identifiers of the objects named {@code name} in {@code state} (one state-filtered Locate). */
  List<String> namedIn(String name, KeyState state) {
    return identifiers(KeyQuery.byName(name).state(state));
  }

  /**
   * Every identifier matching {@code query}: one Locate without Maximum Items, then paging only
   * when Located Items says the server returned fewer than it found.
   */
  private List<String> identifiers(KeyQuery query) {
    LocateRequest locate = locateRequest(query);
    LocateRequest.Page page =
        kms.execute(
            "locate", Kms.Kind.READ, null, s -> LocateRequest.result(s.call(locate.toRequest())));
    List<String> ids = new ArrayList<>(new LinkedHashSet<>(page.identifiers()));
    if (page.locatedItems() == null || page.locatedItems() <= ids.size()) return ids;
    // More exist: page on from what this Locate returned, rather than fetching it again.
    Iterator<List<String>> rest =
        pages(locate, new HashSet<>(ids), page.identifiers().size(), page.locatedItems());
    while (rest.hasNext()) ids.addAll(rest.next());
    return ids;
  }

  /** The object every caller chooses among several with one name; see {@link #findByName(String, KeyState, KeyState...)}. */
  private Optional<KeyHandle> chooseAmong(List<String> ids) {
    return chooseAmongRead(candidates(Kms.named("findByName"), ids));
  }

  /** {@link #chooseAmong} for objects already read. */
  Optional<KeyHandle> chooseAmongRead(List<KeyAttributes> candidates) {
    // findOrCreate's name when called from it.
    String operation = Kms.named("findByName");
    if (candidates.isEmpty()) return Optional.empty(); // all destroyed since the Locate
    if (candidates.size() == 1) return Optional.of(handle(candidates.get(0).id()));
    Map<String, KeyAttributes> known = new HashMap<>();
    for (KeyAttributes a : candidates) known.put(a.id(), a);
    Lineage.Reader cached =
        id -> {
          KeyAttributes a = known.get(id);
          if (a != null) return Optional.of(a);
          Optional<KeyAttributes> read = read(id);
          read.ifPresent(r -> known.put(id, r));
          return read;
        };
    // Each candidate's lineage, oldest key first and the candidate last.
    Map<String, List<KeyAttributes>> lineages = new HashMap<>();
    Set<String> truncated = new HashSet<>();
    Map<String, List<String>> unresolved = new LinkedHashMap<>();
    for (KeyAttributes c : candidates) {
      Lineage.Back back = Lineage.back(c, cached);
      lineages.put(c.id(), back.keys());
      if (back.truncated()) truncated.add(c.id());
      if (!back.unresolved().isEmpty()) unresolved.put(c.id(), back.unresolved());
    }
    KeyAttributes first =
        lineages.values().stream().map(l -> l.get(0)).min(Lineage.EARLIEST).orElseThrow();
    // A lineage longer than the walk started before the key it reached: if that key does not rank
    // first, the true first key might, and the lineages cannot be ranked.
    for (String c : truncated)
      if (!lineages.get(c).get(0).id().equals(first.id()))
        throw new UnsupportedException(
            operation
                + ": "
                + c
                + " has the name and more than "
                + Lineage.LIMIT
                + " rotations behind it,"
                + " so the objects with the name cannot be ranked; remove the name from the ones not"
                + " in use (docs/kms-design.md, \"Duplicate names\")",
            null,
            operation,
            c,
            null,
            null);
    // Likewise a lineage whose first key names a replaced object the walk could not follow
    // (destroyed and purged, not readable with these credentials, answered with an invalid reply,
    // or not linking back): it may
    // start earlier, at a key whose identifier is unknown, so unless its start was created strictly
    // before every other lineage's, choosing would be a guess that a purge or a planted link could
    // decide.
    for (Map.Entry<String, List<String>> u : unresolved.entrySet()) {
      KeyAttributes start = lineages.get(u.getKey()).get(0);
      Optional<java.time.Instant> created = start.creationDate();
      boolean strictlyFirst =
          created.isPresent()
              && lineages.values().stream()
                  .map(l -> l.get(0))
                  .filter(other -> !other.id().equals(start.id()))
                  .allMatch(
                      other -> other.creationDate().map(created.get()::isBefore).orElse(true));
      if (!strictlyFirst)
        throw new StateConflictException(
                operation
                    + ": "
                    + candidates.stream()
                        .map(KeyAttributes::id)
                        .sorted(Lineage.IDENTIFIERS)
                        .toList()
                    + " have the name, and the lineage of "
                    + u.getKey()
                    + " continues past "
                    + start.id()
                    + " to "
                    + u.getValue()
                    + ", which cannot be followed (destroyed and purged, not readable"
                    + " with these credentials, answered with an invalid reply, or not linking back), so which of them has the name cannot be"
                    + " decided; remove the"
                    + " name from the ones not in use with KeyHandle.removeName (docs/kms-design.md,"
                    + " \"Duplicate names\")"
                    + leftovers(candidates),
                null,
                operation,
                u.getKey(),
                null,
                null)
            .because(StateConflictException.Conflict.NAME);
    }
    List<KeyAttributes> lineage =
        candidates.stream()
            .filter(c -> rotationsAfter(lineages.get(c.id()), first.id()) >= 0)
            .toList();
    // Newest keys of the lineage first (callers that rotated one key at the same time leave
    // several),
    // chosen as latest() chooses among them: an Active one, then the one created first.
    Optional<KeyAttributes> tip =
        lineage.size() == 1
            ? Optional.empty()
            : lineage.stream().filter(c -> isTip(c, cached, first.id())).min(Lineage.TIPS);
    KeyAttributes chosen =
        tip.orElseGet(
            () ->
                lineage.stream()
                    .max(
                        Comparator.comparingInt(
                                (KeyAttributes c) ->
                                    rotationsAfter(lineages.get(c.id()), first.id()))
                            .thenComparing(Lineage.EARLIEST.reversed()))
                    .orElseThrow());
    return Optional.of(handle(chosen.id()));
  }

  /**
   * Whether {@code key} has no confirmed replacement and was not joined into a key of its lineage
   * (whose first key is {@code firstId}) by {@link KeyHandle#reconcile()}: a newest key of its
   * lineage, as {@link KeyHandle#latest()} takes it. A key with more than {@link Lineage#FANOUT}
   * replacement links, or whose replacements cannot all be read, is not taken for one.
   */
  private static boolean isTip(KeyAttributes key, Lineage.Reader read, String firstId) {
    List<String> ids = key.links(LinkKind.REPLACEMENT).stream().distinct().toList();
    if (ids.isEmpty()) return true;
    if (ids.size() > Lineage.FANOUT) return false;
    try {
      for (String id : ids) {
        Optional<KeyAttributes> r = read.read(id);
        if (r.isEmpty()) continue;
        if (Lineage.replaced(r.get(), key)) return false;
        // Joined: the key it names is of the same lineage.
        if (!r.get().id().equals(key.id())
            && rotationsAfter(Lineage.back(r.get(), read).keys(), firstId) >= 0) return false;
      }
      return true;
    } catch (KmsException | IllegalStateException unreadable) {
      return false;
    }
  }

  /**
   * The attributes of the objects a name lookup found. One that cannot be read with these
   * credentials, or whose reply is not valid, cannot be ranked, so the lookup cannot decide: STATE naming it, not a
   * permission failure of the lookup, as for an unreadable link. A refusal of the client's
   * credentials ({@link Failures#credentialsRefused}) is not about one object: it propagates.
   */
  private List<KeyAttributes> candidates(String operation, List<String> ids) {
    try {
      return attributesOf(ids);
    } catch (PermissionDeniedException | ProtocolViolationException denied) {
      if (Failures.credentialsRefused(denied)) throw denied;
      List<KeyAttributes> read = new ArrayList<>();
      List<String> unreadable = new ArrayList<>();
      for (String id : ids)
        try {
          read(id).ifPresent(read::add);
        } catch (PermissionDeniedException | ProtocolViolationException e) {
          if (Failures.credentialsRefused(e)) throw e;
          unreadable.add(id);
        }
      if (unreadable.isEmpty()) return read;
      throw new StateConflictException(
              operation
                  + ": "
                  + ids.stream().sorted(Lineage.IDENTIFIERS).toList()
                  + " have the name, and "
                  + unreadable
                  + " cannot be read (with these"
                  + " credentials, or the server's reply is not valid), so which of them has the name cannot be decided; remove the name from the"
                  + " ones not in use with KeyHandle.removeName, or let this client read them"
                  + " (docs/kms-design.md, \"Duplicate names\")",
              denied,
              operation,
              unreadable.get(0),
              null,
              null)
          .because(StateConflictException.Conflict.NAME);
    }
  }

  /**
   * The advice for candidates that look like a lost findOrCreate race: Pre-Active, never activated,
   * without links. Such a key was never used, so destroying it is the fix; the advice is only
   * a hint, since it may also be another caller's key about to be activated.
   */
  private static String leftovers(List<KeyAttributes> candidates) {
    List<String> unused =
        candidates.stream()
            .filter(
                c ->
                    c.state() == KeyState.PRE_ACTIVE
                        && c.activationDate().isEmpty()
                        && c.links().isEmpty())
            .map(KeyAttributes::id)
            .sorted(Lineage.IDENTIFIERS)
            .toList();
    return unused.isEmpty()
        ? ""
        : ". "
            + unused
            + (unused.size() == 1 ? " is" : " are")
            + " Pre-Active, never activated and without"
            + " links, probably left by a findOrCreate call cut short on another instance: if "
            + (unused.size() == 1 ? "it is" : "they are")
            + " yours (a name proves nothing about who made a key),"
            + " destroy "
            + (unused.size() == 1 ? "it" : "them")
            + " (kms.keys().handle(id).destroy()), and destroy"
            + " such leftovers before retiring old keys (KeyHandle.leftovers(); docs/kms-design.md, \"Retiring keys\")";
  }

  /** How many rotations the last key of {@code lineage} is after {@code firstId}; -1 when not after it. */
  private static int rotationsAfter(List<KeyAttributes> lineage, String firstId) {
    for (int i = 0; i < lineage.size(); i++)
      if (lineage.get(i).id().equals(firstId)) return lineage.size() - 1 - i;
    return -1;
  }

  /**
   * Every object matching {@code query}, in the server's order. The stream is lazy: pages are
   * requested as it is consumed (KMIP 1.3+), each with its own call deadline, so a failure can
   * surface while iterating, as a {@link KmsException}. Use {@link #list} to fetch everything at once.
   *
   * @param query the query
   * @return a lazy stream of handles, which the caller consumes once
   */
  public Stream<KeyHandle> locate(KeyQuery query) {
    ObjectKind kind = Objects.requireNonNull(query, "query").kind;
    return StreamSupport.stream(
            Spliterators.spliteratorUnknownSize(
                named("locate", query, page -> page), Spliterator.ORDERED | Spliterator.NONNULL),
            false)
        .flatMap(List::stream)
        .map(id -> new KeyHandle(this, id, kind));
  }

  /**
   * Every object matching {@code query}, fetched before returning: the pages of {@link #locate},
   * each with its own call deadline, so a large listing is not cut short by one call timeout. It
   * is one application call ({@link KmsListener#callStarted}), {@code "list"}.
   *
   * @param query the query
   * @return the handles, in the server's order; unmodifiable
   */
  public List<KeyHandle> list(KeyQuery query) {
    // One call named "list", without a deadline of its own: each page's request has the call
    // timeout, as locate's do.
    return Kms.named("list", () -> locate(query).toList());
  }

  /**
   * The attributes of every object matching {@code query}, fetched with one batched request of Get
   * Attributes per Locate page instead of one request per object (servers that do not take batches
   * get one request per object). Lazy, like {@link #locate}. An object destroyed between the
   * Locate and the Get Attributes is skipped.
   *
   * @param query the query
   * @return a lazy stream of attributes, which the caller consumes once
   */
  public Stream<KeyAttributes> locateWithAttributes(KeyQuery query) {
    Objects.requireNonNull(query, "query");
    return StreamSupport.stream(
            Spliterators.spliteratorUnknownSize(
                named("locateWithAttributes", query, this::attributesOf),
                Spliterator.ORDERED | Spliterator.NONNULL),
            false)
        .flatMap(List::stream);
  }

  /**
   * The pages {@code query} matches, each read with {@code read} applied, as an application call
   * {@code operation} of its own when the stream asks for it (a lazy stream is consumed after its
   * method returned, so each page is one call, named after that method).
   */
  private <T> Iterator<List<T>> named(
      String operation, KeyQuery query, java.util.function.Function<List<String>, List<T>> read) {
    Iterator<List<String>> pages = Kms.named(operation, () -> pages(query));
    return new Iterator<>() {
      private List<T> next;

      @Override
      public boolean hasNext() {
        if (next != null) return true;
        // The page and what is read of it, in one call.
        next = Kms.named(operation, () -> pages.hasNext() ? read.apply(pages.next()) : null);
        return next != null;
      }

      @Override
      public List<T> next() {
        if (!hasNext()) throw new java.util.NoSuchElementException();
        List<T> page = next;
        next = null;
        return page;
      }
    };
  }

  List<KeyAttributes> attributesOf(List<String> ids) {
    return attributesOf(ids, (id, a) -> {});
  }

  /** Publishes each correlated success or absence (null), even if another item or chunk fails. */
  List<KeyAttributes> attributesOf(
      List<String> ids, java.util.function.BiConsumer<String, KeyAttributes> observed) {
    return attributesOf(ids, observed, null);
  }

  /** Selection-only variant: an object-level denied candidate may be skipped by the caller. */
  List<KeyAttributes> attributesOf(
      List<String> ids,
      java.util.function.BiConsumer<String, KeyAttributes> observed,
      java.util.function.BiConsumer<String, PermissionDeniedException> inaccessible) {
    if (ids.size() > 1 && batchGetAttributes)
      try {
        return batchedAttributes(ids, observed, inaccessible);
      } catch (UnsupportedException e) {
        // The server does not process batches: ask per object from now on.
        batchGetAttributes = false;
      } catch (InvalidRequestException e) {
        // Invalid Message is how some servers refuse a batch: ask per object from now on. Other
        // reasons concern this batch only.
        if (e.protocolReason().map(r -> r == Enums.ResultReason.INVALID_MESSAGE).orElse(true))
          batchGetAttributes = false;
      } catch (ServerFailureException | ProtocolViolationException e) {
        // One failed batch says nothing lasting about the server: ask per object for this page.
      }
    List<KeyAttributes> out = new ArrayList<>();
    for (String id : ids)
      try {
        KeyAttributes attributes = handle(id).attributes();
        observed.accept(id, attributes);
        out.add(attributes);
      } catch (NotFoundException gone) {
        observed.accept(id, null);
      } catch (PermissionDeniedException denied) {
        if (inaccessible == null || Failures.credentialsRefused(denied)) throw denied;
        inaccessible.accept(id, denied);
      }
    return out;
  }

  private List<KeyAttributes> batchedAttributes(
      List<String> ids,
      java.util.function.BiConsumer<String, KeyAttributes> observed,
      java.util.function.BiConsumer<String, PermissionDeniedException> inaccessible) {
    List<KeyAttributes> out = new ArrayList<>();
    int limit = Messages.MAX_BATCH_ITEMS;
    for (int from = 0; from < ids.size(); from += limit) {
      List<String> chunk = ids.subList(from, Math.min(ids.size(), from + limit));
      List<Request> requests =
          chunk.stream().map(id -> Requests.getAttributes().uniqueIdentifier(id).build()).toList();
      out.addAll(
          kms.execute(
              "locateWithAttributes",
              Kms.Kind.READ,
              null,
              s -> {
                Response response =
                    s.batch(
                        requests,
                        RequestOptions.DEFAULT.batching(
                            true, Enums.BatchErrorContinuation.CONTINUE));
                List<KeyAttributes> read = new ArrayList<>();
                Exception failure = null;
                for (int i = 0; i < requests.size(); i++) {
                  try {
                    Result r =
                        response
                            .resultFor(i)
                            .orElseThrow(
                                () ->
                                    new ProtocolException(
                                        "Batch item without a result", null, null));
                    if (!r.successful()) {
                      if (r.hasReason(Enums.ResultReason.ITEM_NOT_FOUND)
                          || r.hasReason(Enums.ResultReason.OBJECT_NOT_FOUND)
                          || r.hasReason(Enums.ResultReason.OBJECT_DESTROYED)) {
                        observed.accept(chunk.get(i), null);
                        continue;
                      }
                      if (inaccessible != null) {
                        String id = chunk.get(i);
                        KmsException error =
                            Failures.fromResult(
                                new Failures.Call("locateWithAttributes", true, id, false),
                                "locateWithAttributes " + id,
                                r,
                                null);
                        if (error instanceof PermissionDeniedException denied
                            && !Failures.credentialsRefused(denied)) {
                          inaccessible.accept(id, denied);
                          continue;
                        }
                      }
                      throw new KmipException(r);
                    }
                    KeyAttributes attributes = KeyHandle.readAttributes(r);
                    observed.accept(attributes.id(), attributes);
                    read.add(attributes);
                  } catch (KmipException | ProtocolException e) {
                    // CONTINUE permits successes after a failure; retain all of their evidence.
                    if (failure == null) failure = e;
                  }
                }
                if (failure instanceof ProtocolException malformed) throw malformed;
                if (failure instanceof KmipException refused) throw refused;
                return read;
              }));
    }
    return out;
  }

  /** The Locate request for {@code query}, after the version's capability checks. */
  private LocateRequest locateRequest(KeyQuery query) {
    if (query.ids != null)
      throw new UnsupportedException(
          "locate: a query with identifiers (KeyQuery.ids) is checked against the key a record names, never"
              + " searched (KMIP has no search by identifier); read those keys with handle(id)",
          null,
          "locate",
          null,
          null,
          null);
    if (query.group != null) requireGroups("locate");
    LocateRequest.Builder b = LocateRequest.builder();
    if (query.name != null) b.name(query.name);
    if (query.group != null) b.objectGroup(query.group);
    if (query.state != null) b.state(query.state.protocolValue());
    if (query.kind != null) b.objectType(query.kind.protocolValue());
    if (query.algorithm != null) b.algorithm(query.algorithm.requireWire());
    for (var e : query.custom.entrySet()) b.attribute(custom(e.getKey(), e.getValue()));
    for (KeyQuery.LinkFilter l : query.links)
      b.attribute(
          Attributes.attribute(
              "Link",
              structure(
                  LINK,
                  enumeration(LINK_TYPE, l.kind().protocolValue()),
                  text(LINKED_OBJECT_IDENTIFIER, l.targetId()))));
    if (query.createdFrom != null) {
      b.attribute(Attributes.attribute("Initial Date", dateTime(INITIAL_DATE, query.createdFrom)));
      b.attribute(Attributes.attribute("Initial Date", dateTime(INITIAL_DATE, query.createdTo)));
    }
    if (query.activatedFrom != null) {
      b.attribute(
          Attributes.attribute("Activation Date", dateTime(ACTIVATION_DATE, query.activatedFrom)));
      b.attribute(
          Attributes.attribute("Activation Date", dateTime(ACTIVATION_DATE, query.activatedTo)));
    }
    return b.build();
  }

  /** The identifiers matching {@code query}, a page at a time. */
  private Iterator<List<String>> pages(KeyQuery query) {
    return pages(locateRequest(query), new HashSet<>(), 0, null);
  }

  /**
   * The identifiers {@code locate} matches, a page at a time from {@code start}, after the ones in
   * {@code received} (which a first Locate returned, {@code total} being its Located Items).
   */
  private Iterator<List<String>> pages(
      LocateRequest locate, Set<String> received, int start, Integer known) {
    ProtocolVersion version = kms.protocolVersion();
    if (!version.atLeast(ProtocolVersion.V1_3)) {
      // No Offset Items: one request for at most locateLimit + 1, refusing to truncate.
      int limit = kms.config.locateLimit;
      LocateRequest.Page page = page(locate, 0, limit + 1);
      List<String> ids = new ArrayList<>(new LinkedHashSet<>(page.identifiers()));
      if (ids.size() > limit
          || (page.locatedItems() != null && page.locatedItems() > page.identifiers().size()))
        throw new UnsupportedException(
            "locate: more matches than "
                + Math.min(limit, ids.size())
                + " and KMIP "
                + version
                + " cannot page; narrow the query",
            null,
            "locate",
            null,
            null,
            null);
      ids.removeAll(received);
      return List.of(ids).iterator();
    }
    int size = kms.config.pageSize;
    return new Iterator<>() {
      private final Set<String> seen = received;
      private List<String> next;
      private int offset = start;
      private Integer total = known;
      private boolean exhausted;

      @Override
      public boolean hasNext() {
        while (next == null && !exhausted) {
          LocateRequest.Page page = page(locate, offset, size);
          List<String> ids = page.identifiers();
          if (page.locatedItems() != null) total = page.locatedItems();
          if (ids.isEmpty()) {
            // The end, unless Located Items (this page's, else the last one sent) says more exist;
            // a server that lost objects meanwhile lowers it.
            if (total != null && seen.size() < total)
              throw truncated("returned an empty page before reaching its Located Items");
            exhausted = true;
            break;
          }
          List<String> fresh = new ArrayList<>();
          for (String id : ids) if (seen.add(id)) fresh.add(id);
          offset += ids.size();
          // Maximum Items is only an upper bound: a short page is not the end, an empty page or the
          // Located Items total is. A page larger than asked for means the server ignored Maximum
          // Items and returned everything, which must then be the total.
          boolean more = total != null && seen.size() < total;
          if (!more && total != null) exhausted = true;
          else if (ids.size() > size) {
            if (more)
              throw truncated("returned more than asked for, but fewer than its Located Items");
            exhausted = true;
          } else if (fresh.isEmpty()) {
            // Nothing new: the server ignores Offset Items. Without a total, a short page is taken
            // as the end; a full one, or a total still ahead, means it cannot page this query.
            if (more)
              throw truncated(
                  "returned the same page again, before its Located Items were reached");
            if (ids.size() < size) exhausted = true;
            else throw truncated("returned the same page again; it ignores Offset Items");
          }
          if (!fresh.isEmpty()) next = fresh;
        }
        return next != null;
      }

      @Override
      public List<String> next() {
        if (!hasNext()) throw new NoSuchElementException();
        List<String> out = next;
        next = null;
        return out;
      }
    };
  }

  private static ProtocolViolationException truncated(String why) {
    return new ProtocolViolationException(
        "locate: the server " + why, null, "locate", null, null, null);
  }

  private LocateRequest.Page page(LocateRequest locate, int offset, int maximum) {
    return kms.execute(
        "locate",
        Kms.Kind.READ,
        null,
        s -> LocateRequest.result(s.call(locate.page(offset, maximum))));
  }

  /**
   * Decrypts with the key that produced {@code ciphertext} (see {@link Ciphertext#keyId()}), once
   * that key is shown to match {@code expected}. The ciphertext alone never chooses the key. The
   * named key, or another key of its rotation lineage (at most 64 rotations either way), must
   * match every filter of {@code expected}. So {@code KeyQuery.byName("orders-kek")} keeps working
   * after the name moved to a newer key. Only AES-GCM and AES key wrap ciphertexts are accepted
   * (name the spec of others with {@link #decrypt(KeyQuery, CipherSpec, Ciphertext, byte[])}). A
   * Compromised or Destroyed key is refused. To recover data after a compromise, use the
   * compromised key's handle from a set you trust, such as the replacement's {@link
   * KeyHandle#compromisedPredecessors()}, never one built from the ciphertext's identifier. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#after-a-restart">After
   * a restart</a>.
   *
   * <pre>{@code
   * byte[] plain = kms.keys().decrypt(KeyQuery.all().group("orders"), ciphertext, orderId);
   * }</pre>
   *
   * <p>The query is only as strong as the attributes it names. On a server that does not enforce
   * unique names, anyone allowed to create keys can create one named {@code orders-kek}. Where that
   * is possible, filter on an attribute others cannot set, or decrypt with the expected key's
   * handle. A name moves to each new key, so for records more than 64 rotations old query an
   * attribute Re-key copies to every key of the lineage, or {@link KeyQuery#ids}.
   *
   * <p><b>Advanced.</b> The KMS decrypts every byte, and a name or attribute query trusts every
   * key it matches. For records, {@link CurrentKey#open} opens what {@link CurrentKey#seal} sealed
   * (see <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/choosing-an-api.md#the-advanced-alternatives">The
   * advanced alternatives</a>).
   *
   * @param expected what the key must match
   * @param ciphertext the ciphertext
   * @param aad the additional data given when encrypting; null or empty for none
   * @return the plaintext, a new array
   * @throws KeyMismatchException when no key of the lineage matches {@code expected}: category
   *     {@code BAD_DATA}, or {@code FIX_REQUEST} when nothing on the server matches the query
   * @throws StateConflictException when the named key is Compromised or Destroyed, or a
   *     replacement link that might lead to a matching key cannot be followed
   * @throws NotFoundException when the key the ciphertext names does not exist (a purged key, or a
   *     forged record), and {@link PermissionDeniedException} when these credentials cannot read it
   * @throws IllegalArgumentException when {@code expected} has no filter
   */
  public byte[] decrypt(KeyQuery expected, Ciphertext ciphertext, byte[] aad) {
    Objects.requireNonNull(expected, "expected");
    Objects.requireNonNull(ciphertext, "ciphertext");
    if (expected.isEmpty())
      throw new IllegalArgumentException("State the expected key: KeyQuery.all() matches any key");
    CipherSpec spec = KeyHandle.storedSpec(ciphertext);
    KeyHandle.check(spec, ciphertext, aad, true);
    return kms.call(
        "decrypt",
        () -> {
          return expectedKey(Kms.named("decrypt"), expected, spec, ciphertext)
              .decryptChecked(spec, ciphertext, aad);
        });
  }

  /**
   * Decrypts with an expected spec, with the key rules of {@link #decrypt(KeyQuery, Ciphertext,
   * byte[])}: the key the ciphertext names, or another key of its lineage, must match {@code
   * expected}. The ciphertext must name exactly {@code spec}, with the spec's IV and tag lengths,
   * as for {@link KeyHandle#decrypt(CipherSpec, Ciphertext, byte[])}. Use it for symmetric specs a
   * stored ciphertext may not choose: AES-CBC, AES-CTR and {@link CipherSpec#fromProtocol
   * protocol-defined} specs. They are not tamper-evident, so a record's integrity must come from
   * elsewhere.
   *
   * <pre>{@code
   * KeyQuery expected = KeyQuery.byName("orders-kek");
   * byte[] plain = kms.keys().decrypt(expected, CipherSpec.cbc(), ciphertext, null);
   * }</pre>
   *
   * <p><b>Advanced.</b> As {@link #decrypt(KeyQuery, Ciphertext, byte[])}.
   *
   * @param expected what the key must match
   * @param spec the spec the ciphertext must have been made with
   * @param ciphertext the ciphertext
   * @param aad the additional data given when encrypting; null or empty for none
   * @return the plaintext, a new array
   * @throws CryptographicFailureException when the ciphertext names another spec or has an IV or
   *     tag of the wrong length ({@link CryptographicFailureException.Kind#INVALID_CIPHERTEXT}), or
   *     when an AEAD tag does not verify
   * @throws KeyMismatchException as for {@link #decrypt(KeyQuery, Ciphertext, byte[])}
   * @throws StateConflictException as for {@link #decrypt(KeyQuery, Ciphertext, byte[])}
   * @throws NotFoundException as for {@link #decrypt(KeyQuery, Ciphertext, byte[])}
   * @throws IllegalArgumentException when {@code expected} has no filter, for additional data with
   *     a spec that does not authenticate it, and for RSA-OAEP (a ciphertext names the public key
   *     and the private key decrypts it: use {@link KeyPairHandle#decrypt} or the private key's
   *     handle)
   * @since 0.10.0
   */
  public byte[] decrypt(KeyQuery expected, CipherSpec spec, Ciphertext ciphertext, byte[] aad) {
    Objects.requireNonNull(expected, "expected");
    Objects.requireNonNull(spec, "spec");
    Objects.requireNonNull(ciphertext, "ciphertext");
    if (expected.isEmpty())
      throw new IllegalArgumentException("State the expected key: KeyQuery.all() matches any key");
    if (spec.rsaOaep())
      throw new IllegalArgumentException(
          "decrypt: an RSA-OAEP ciphertext names the public key; decrypt it with the key pair or the private key's handle");
    KeyHandle.check(spec, ciphertext, aad, false);
    return kms.call(
        "decrypt",
        () -> {
          return expectedKey(Kms.named("decrypt"), expected, spec, ciphertext)
              .decryptChecked(spec, ciphertext, aad);
        });
  }

  /**
   * Unwraps a key wrapped with AES-GCM or AES key wrap by the key that {@code expected} describes,
   * with the rules of {@link #decrypt(KeyQuery, Ciphertext, byte[])}, after a rotation too. The
   * unwrapped key must be what {@code expect} describes; destroy it when finished.
   *
   * <p><b>Advanced.</b> For wrapped keys whose key a query names (a tenant's keys, say) rather
   * than one lineage. {@link CurrentKey#unwrapKey} opens what its lineage wrapped.
   *
   * @param expected what the wrapping key must match
   * @param expect what the unwrapped key must be
   * @param wrapped the wrapped key
   * @param aad the additional data given when wrapping; null or empty for none
   * @return a new key, owned by the caller, who destroys it
   * @throws KeyMismatchException when the wrapping key does not match {@code expected}, or the
   *     unwrapped key does not match {@code expect}
   */
  public DestroyableSecretKey unwrapKey(
      KeyQuery expected, Expect expect, Ciphertext wrapped, byte[] aad) {
    Objects.requireNonNull(expect, "expect");
    String jca = KeyReader.jcaSecretName(expect);
    return Kms.named(
        "unwrapKey",
        () -> {
          byte[] raw = decrypt(expected, wrapped, aad);
          return KeyHandle.unwrapped(raw, expect, jca, wrapped.keyId());
        });
  }

  /**
   * Opens data sealed by {@link CurrentKey#seal}, with the key rules of {@link #decrypt(KeyQuery,
   * Ciphertext, byte[])}: the key the container names, or another key of its lineage, must match
   * {@code expected}.
   *
   * <p><b>Advanced.</b> For records whose key a query names (a tenant's keys, say) rather than one
   * lineage. {@link CurrentKey#open} opens what its lineage sealed.
   *
   * @param expected what the key must match
   * @param sealed the sealed record
   * @param aad the additional data given when sealing; null or empty for none
   * @return the plaintext, a new array
   * @throws CryptographicFailureException as for {@link KeyHandle#open}
   * @throws KeyMismatchException when the key does not match {@code expected}
   * @throws StateConflictException as for {@link #decrypt(KeyQuery, Ciphertext, byte[])}
   */
  public byte[] open(KeyQuery expected, byte[] sealed, byte[] aad) {
    Objects.requireNonNull(expected, "expected");
    return Kms.named(
        "open",
        () -> {
          return Envelopes.open(
              sealed, aad, wrapped -> unwrapKey(expected, Expect.aes(256), wrapped, aad));
        });
  }

  /**
   * The identifier of the key-encryption key that sealed {@code sealed} ({@link CurrentKey#seal}),
   * read from the container without contacting the server, as {@link Ciphertext#keyId()} is for a
   * ciphertext.
   *
   * <p>The identifier is routing data, not authorization. During recovery, use it only to pick a
   * key from a set you trust, such as the replacement's {@link KeyHandle#compromisedPredecessors()}.
   * Never build an {@link KeyHandle#allowingCompromised()} handle from it, and quarantine a record
   * whose key is not in that set. See <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/operating-keys.md#after-a-restart">After
   * a restart</a>.
   *
   * @param sealed the sealed record
   * @return the key identifier
   * @throws CryptographicFailureException of kind {@code INVALID_CIPHERTEXT} when {@code sealed} is
   *     not a well-formed container
   */
  public static String sealedKeyId(byte[] sealed) {
    return Envelopes.parse(sealed).wrappedKey().keyId();
  }

  /**
   * Opens a stream written by {@link KeyHandle#sealing}, with the key rules of {@link #open(KeyQuery,
   * byte[], byte[])}: the key the stream names, or another key of its lineage, must match {@code
   * expected}. Otherwise as {@link KeyHandle#opening}: the header is read and the data key
   * unwrapped before this returns, and the chunks are verified as they are read. {@code in} is
   * closed by the returned stream, or before this method throws.
   *
   * <p><b>Advanced.</b> For streams whose key a query names rather than one lineage. A sealed file
   * opens through {@link CurrentKey#openTo}.
   *
   * @param expected what the key must match
   * @param in the sealed stream; the returned stream owns it
   * @param aad the additional data given when sealing; null or empty for none
   * @return a stream of the plaintext, owned by the caller, who closes it
   * @throws IOException for errors of {@code in} while the header is read
   * @throws CryptographicFailureException as for {@link KeyHandle#opening}
   * @throws KeyMismatchException when the key does not match {@code expected}
   * @throws StateConflictException as for {@link #decrypt(KeyQuery, Ciphertext, byte[])}
   */
  public InputStream opening(KeyQuery expected, InputStream in, byte[] aad) throws IOException {
    if (expected == null) {
      NullPointerException e = new NullPointerException("expected");
      if (in != null) StreamEnvelopes.closing(in, e);
      throw e;
    }
    return Kms.named(
        "opening",
        () ->
            StreamEnvelopes.opening(
                in,
                aad,
                wrapped -> unwrapKey(expected, Expect.aes(256), wrapped, aad),
                StreamEnvelopes.MAX_CHUNKS));
  }

  /**
   * Opens the chunks of a file sealed by {@link CurrentKey#chunkedSealer}, with the key rules of
   * {@link #open(KeyQuery, byte[], byte[])}: the key the header names, or another key of its
   * lineage, must match {@code expected}. Otherwise as {@link KeyHandle#chunkedOpener}: the data
   * key is unwrapped before this returns and checked against the header's key commitment. Opening
   * chunks sends no request.
   *
   * <p><b>Advanced.</b> For files whose key a query names (a tenant's keys, say) rather than one
   * lineage. {@link CurrentKey#chunkedOpener} opens what its lineage sealed.
   *
   * @param expected the key the header must be under (not null, not {@code KeyQuery.all()})
   * @param header the file's header, {@link ChunkedSealer#header()} (not null; copied)
   * @param fileId the file identifier it was sealed with (not null; copied)
   * @return a new opener, which owns the chunk key: close it with the file
   * @throws CryptographicFailureException as for {@link KeyHandle#chunkedOpener}
   * @throws KeyMismatchException when the key does not match {@code expected}
   * @throws StateConflictException as for {@link #decrypt(KeyQuery, Ciphertext, byte[])}
   * @throws IllegalArgumentException when {@code expected} has no filter
   * @since 0.10.0
   */
  public ChunkedOpener chunkedOpener(KeyQuery expected, byte[] header, byte[] fileId) {
    Objects.requireNonNull(expected, "expected");
    return Kms.named(
        "chunkedOpener",
        () -> {
          return ChunkedEnvelopes.opener(
              header, fileId, (wrapped, aad) -> unwrapKey(expected, Expect.aes(256), wrapped, aad));
        });
  }

  /**
   * The identifier of the key-encryption key that wraps a chunked file's data key ({@link
   * CurrentKey#chunkedSealer}), read from its header without contacting the server, as {@link
   * #sealedKeyId(byte[])} is for a sealed container. Like that identifier, it is routing data, not
   * authorization: during recovery, use it only to pick a key you already trust.
   *
   * @param header the chunked file's header
   * @return the key identifier
   * @throws CryptographicFailureException of kind {@code INVALID_CIPHERTEXT} when {@code header} is
   *     not a well-formed chunked header
   * @since 0.10.0
   */
  public static String chunkedHeaderKeyId(byte[] header) {
    return ChunkedEnvelopes.parse(header).wrappedKey().keyId();
  }

  /**
   * Opens the file {@code sealed}, written by {@link CurrentKey#sealTo} or {@link
   * KeyHandle#sealing}, into the file {@code target}, with the key rules of {@link
   * #opening(KeyQuery, InputStream, byte[])}: the key the stream names, or another key of its
   * lineage, must match {@code expected}. Otherwise as {@link KeyHandle#openTo}. The plaintext is
   * staged in a temporary file next to {@code target} (owner-only where the file system supports
   * POSIX permissions). It is moved onto {@code target} atomically once the whole stream has
   * verified, and the directory is then forced ({@link FileDurability#DURABLE}). A failure before
   * the move leaves {@code target} as it was. A failure to force the directory comes after the
   * move, so {@code target} is then the new file. This writes plaintext to disk, the temporary file
   * included.
   *
   * <p><b>Advanced.</b> For files whose key a query names (a tenant's keys, say) rather than one
   * lineage. {@link CurrentKey#openTo} opens what its lineage sealed.
   *
   * @param expected what the key must match
   * @param sealed the sealed file
   * @param target the file to write
   * @param aad the additional data given when sealing; null or empty for none
   * @throws IOException as for {@link KeyHandle#openTo}
   * @throws IllegalArgumentException when {@code target} has no file name (a root)
   * @throws CryptographicFailureException as for {@link KeyHandle#openTo}
   * @throws KeyMismatchException when the key does not match {@code expected}
   * @throws StateConflictException as for {@link #decrypt(KeyQuery, Ciphertext, byte[])}
   */
  public void openTo(
      KeyQuery expected, java.nio.file.Path sealed, java.nio.file.Path target, byte[] aad)
      throws IOException {
    openTo(expected, sealed, target, aad, FileDurability.DURABLE);
  }

  /**
   * {@link #openTo(KeyQuery, java.nio.file.Path, java.nio.file.Path, byte[])} with the durability
   * chosen, as for {@link CurrentKey#sealTo(java.nio.file.Path, InputStream, byte[],
   * FileDurability)}.
   *
   * <p><b>Advanced.</b> As {@link #openTo(KeyQuery, java.nio.file.Path, java.nio.file.Path,
   * byte[])}.
   *
   * @param expected what the key must match
   * @param sealed the sealed file
   * @param target the file to write
   * @param aad the additional data given when sealing; null or empty for none
   * @param durability whether the directory is forced after the move
   * @throws IOException as for {@link #openTo(KeyQuery, java.nio.file.Path, java.nio.file.Path,
   *     byte[])}, and, for {@link FileDurability#DURABLE}, when the directory opens but cannot be
   *     forced: {@code target} was replaced already (the message says so)
   * @since 0.10.0
   */
  public void openTo(
      KeyQuery expected,
      java.nio.file.Path sealed,
      java.nio.file.Path target,
      byte[] aad,
      FileDurability durability)
      throws IOException {
    Objects.requireNonNull(expected, "expected");
    Kms.runNamed(
        "openTo",
        () -> StagedFiles.openTo(sealed, target, durability, in -> opening(expected, in, aad)));
  }

  /**
   * The identifier of the key-encryption key that sealed a stream ({@link KeyHandle#sealing}), as
   * {@link #sealedKeyId(byte[])} is for a sealed container: reads only the header from {@code in},
   * without contacting the server, and leaves {@code in} open after it. Like that identifier, it is
   * routing data, not authorization: during recovery, use it only to pick a key you already trust,
   * then open the data again from the start.
   *
   * @param in the sealed stream, left open with its header read
   * @return the key identifier
   * @throws IOException for errors of {@code in}
   * @throws CryptographicFailureException of kind {@code INVALID_CIPHERTEXT} when the header is not
   *     well formed
   */
  public static String sealedStreamKeyId(InputStream in) throws IOException {
    return StreamEnvelopes.readHeader(in).wrappedKey().keyId();
  }

  /** The key a ciphertext names, once it (or another key of its lineage) matches {@code expected}. */
  private KeyHandle expectedKey(
      String operation, KeyQuery expected, CipherSpec spec, Ciphertext ciphertext) {
    KeyHandle named = handle(ciphertext.keyId());
    KeyAttributes attributes = named.attributes();
    // The key a record names, or another key of its lineage tree: its successors, its
    // predecessors, and the other branches of callers that rotated a key at the same time. Each
    // step
    // is confirmed by both keys' links, so a stranger's key cannot join the tree of the caller's.
    Lineage.Tree tree =
        expected.matches(attributes)
            ? null
            : Lineage.tree(operation, attributes, false, expected::matches, this::read);
    boolean found = tree == null || tree.found().isPresent();
    if (!found && (tree.beyondForward() || tree.beyondBack()))
      throw new UnsupportedException(
          operation
              + ": the ciphertext names key "
              + ciphertext.keyId()
              + ", which does not match "
              + expected
              + ", and its rotation lineage continues more than "
              + Lineage.LIMIT
              + " rotations from it, so no"
              + " walk reaches a key that does. A name moves to each new key: bind old records to keys you trust"
              + " by an attribute that matches the record's own key, which Re-key copies and only your keys"
              + " carry (KeyQuery.all().custom(...), under access control), or by a manifest of your keys'"
              + " identifiers (KeyQuery.byIds(...)); see docs/operating-keys.md, \"Records older than "
              + Lineage.LIMIT
              + " rotations\"",
          null,
          operation,
          ciphertext.keyId(),
          null,
          null);
    // The walk from the key the stored data names stopped at its limits: more links on that key
    // than
    // FANOUT (whoever made the data may control it, so it fails fast), or more keys than BUDGET. A
    // valid record of a wide fork (many callers rotated one key at once) meets them too, so the
    // walk
    // is made again from the keys that match, within one budget.
    Boolean nothing = null;
    if (!found && tree.limit() != null) {
      List<String> anchors;
      try {
        anchors = page(locateRequest(expected), 0, Lineage.FANOUT + 1).identifiers();
      } catch (UnsupportedException unsearchable) {
        anchors = null; // a query the server cannot search: as before, the limit decides
      }
      if (anchors != null) {
        nothing = anchors.isEmpty();
        Optional<Boolean> member =
            nothing
                ? Optional.of(false)
                : reaches(operation, expected, anchors, ciphertext.keyId(), tree.reads());
        if (member.isEmpty())
          throw new StateConflictException(
                  operation
                      + ": the ciphertext names key "
                      + ciphertext.keyId()
                      + ", which does not match "
                      + expected
                      + ", and its rotation lineage is wider than one walk follows ("
                      + tree.limit().getMessage()
                      + "), and so is that of the keys that match, so whether it belongs to them cannot be decided;"
                      + " open it through the handle of the current key (findByName), whose walk starts there",
                  null,
                  operation,
                  ciphertext.keyId(),
                  null,
                  null)
              .because(StateConflictException.Conflict.LINEAGE);
        if (!member.get())
          throw outside(
              operation,
              expected,
              ciphertext.keyId(),
              operation
                  + ": the ciphertext names key "
                  + ciphertext.keyId()
                  + ", which does not match "
                  + expected
                  + ", and is in the rotation lineage of no key that does",
              nothing);
        found = true;
      }
    }
    // The links start at the key the stored data names, which whoever made the data may control:
    // links that break the walk's limits say the data is bad, not the server or the caller.
    RuntimeException limit = found ? null : tree.limit() != null ? tree.limit() : tree.cycle();
    if (limit != null)
      throw outside(
          operation,
          expected,
          ciphertext.keyId(),
          operation
              + ": the ciphertext names key "
              + ciphertext.keyId()
              + ", which does not match "
              + expected
              + ", and its replacement links cannot be followed: "
              + limit.getMessage());
    // A link that cannot be resolved (destroyed and purged, unreadable, an invalid reply) proves
    // nothing: a key beyond it may match.
    List<Lineage.Gap> gaps = new ArrayList<>();
    if (!found) {
      gaps.addAll(tree.gapsForward());
      gaps.addAll(tree.gapsBack());
    }
    if (!found
        && !gaps.isEmpty()
        && !(nothing = nothing != null ? nothing : matchesNothing(expected)))
      throw Lineage.broken(
          operation,
          ciphertext.keyId(),
          "a key matching " + expected,
          gaps,
          "find the current key by name, or decrypt with the handle of the key the ciphertext names if"
              + " it is yours. Purging a key in the middle of a chain breaks this check: retire the oldest"
              + " keys first (docs/kms-design.md, \"Retiring keys\")");
    if (!found) {
      if (nothing == null) nothing = matchesNothing(expected);
      if (!nothing && KeyHandle.compromised(attributes))
        throw KeyHandle.underCompromised(
            operation, ciphertext.keyId(), attributes, "does not match " + expected);
      throw outside(
          operation,
          expected,
          ciphertext.keyId(),
          operation
              + ": the ciphertext names key "
              + ciphertext.keyId()
              + ", which does not match "
              + expected
              + ", and neither does another key of its rotation lineage",
          nothing);
    }
    // The key comes from the record, and a query by name proves nothing about who made it (anyone
    // who can create keys can name one like the caller's, seal under it and revoke it): the advice
    // for a Compromised key is the one that does not trust the name.
    if (KeyHandle.compromised(attributes))
      throw KeyHandle.underCompromised(
          operation,
          ciphertext.keyId(),
          attributes,
          expected.matches(attributes)
              ? "matches " + expected
              : "is in the rotation lineage of a key that matches " + expected);
    named.requireUsable(operation, ciphertext.keyId(), attributes);
    KeyHandle.requireSuited(operation, ciphertext.keyId(), attributes, KeyHandle.decrypting(spec));
    return named;
  }

  /** A walk's reads beyond the budget {@link #reaches} shares among its walks. */
  private static final class Spent extends RuntimeException {
    Spent() {
      super(null, null, false, false);
    }
  }

  /**
   * Whether {@code recordKey} is in the rotation lineage of one of {@code anchors} that matches
   * {@code expected} (a walk from each, bounded as one from a stored record's key, stopping at the
   * record's key), all the walks within {@link Lineage#BUDGET} reads together with the {@code spent}
   * reads of the walk from the record's key: true when one reaches
   * it, false when every walk was complete without reaching it, empty when that cannot be decided
   * (more than {@link Lineage#FANOUT} anchors, a walk's limits, links that cannot be resolved).
   */
  private Optional<Boolean> reaches(
      String operation, KeyQuery expected, List<String> anchors, String recordKey, int spent) {
    if (anchors.size() > Lineage.FANOUT) return Optional.empty();
    int[] reads = {spent};
    Lineage.Reader shared =
        id -> {
          if (++reads[0] > Lineage.BUDGET) throw new Spent();
          return read(id);
        };
    boolean undecided = false;
    try {
      for (String anchor : anchors) {
        Optional<KeyAttributes> start;
        try {
          start = shared.read(anchor);
        } catch (KmsException unreadable) {
          if (!Lineage.unresolvable(unreadable)) throw unreadable;
          undecided = true;
          continue;
        }
        if (start.isEmpty() || !expected.matches(start.get())) continue;
        Lineage.Tree walk =
            Lineage.tree(operation, start.get(), false, k -> k.id().equals(recordKey), shared);
        if (walk.found().isPresent()) return Optional.of(true);
        if (walk.limit() != null
            || walk.beyondForward()
            || walk.beyondBack()
            || !walk.gapsForward().isEmpty()
            || !walk.gapsBack().isEmpty()
            || walk.cycle() != null) undecided = true;
      }
    } catch (Spent over) {
      return Optional.empty();
    }
    return undecided ? Optional.empty() : Optional.of(false);
  }

  /**
   * The failure for a ciphertext whose key is outside {@code expected}: BAD_DATA (the record names
   * the wrong key) when something on the server matches the query, but when nothing does (one
   * Locate for at most one object), the query is wrong, not the data: FIX_REQUEST.
   */
  private KeyMismatchException outside(
      String operation, KeyQuery expected, String keyId, String message) {
    return outside(operation, expected, keyId, message, null);
  }

  /** As above, with {@code nothing}, when not null, the answer of a {@link #matchesNothing} already asked. */
  private KeyMismatchException outside(
      String operation, KeyQuery expected, String keyId, String message, Boolean nothing) {
    if (nothing != null ? nothing : matchesNothing(expected))
      return new KeyMismatchException(
          operation
              + ": no object on the server matches "
              + expected
              + ", so the query is wrong, not the"
              + " data (a misspelt name, or a group or attribute the keys do not have); the ciphertext names"
              + " key "
              + keyId,
          null,
          operation,
          keyId,
          null,
          null);
    return KeyMismatchException.ciphertext(message, operation, keyId);
  }

  /** Whether no object on the server matches {@code expected} (one Locate for at most one object). */
  private boolean matchesNothing(KeyQuery expected) {
    try {
      return page(locateRequest(expected), 0, 1).identifiers().isEmpty();
    } catch (UnsupportedException unsearchable) {
      // A query that cannot be searched (groups on 3.0) cannot be shown to match nothing.
      return false;
    }
  }

  /** A key's attributes, or empty when it no longer exists. */
  Optional<KeyAttributes> read(String id) {
    try {
      return Optional.of(handle(id).attributes());
    } catch (NotFoundException gone) {
      return Optional.empty();
    }
  }

  // ---- shared helpers ----

  void requireGroups(String operation) {
    if (kms.protocolVersion() == ProtocolVersion.V3_0)
      throw new UnsupportedException(
          operation
              + ": object groups are not available with the KMIP 3.0 draft; give the keys of one"
              + " purpose a custom attribute instead (custom(CustomAttribute.client(...), value) and"
              + " KeyQuery.all().custom(...)), which every version supports",
          null,
          operation,
          null,
          null,
          null);
  }

  static Ttlv usage(Set<KeyUsage> usages) {
    return Attributes.attribute(
        "Cryptographic Usage Mask", integer(CRYPTOGRAPHIC_USAGE_MASK, KeyUsage.mask(usages)));
  }

  static Ttlv group(String group) {
    return Attributes.attribute("Object Group", text(OBJECT_GROUP, group));
  }

  /** A custom attribute in the form the negotiated version needs. */
  Ttlv custom(CustomAttribute name, Object value) {
    Ttlv encoded = AttributeReader.encode(value);
    boolean legacyVendor = name.vendor().equals("x") || name.vendor().equals("y");
    if (legacyVendor) return Attributes.attribute(name.vendor() + "-" + name.name(), encoded);
    if (kms.protocolVersion().legacyAttributes())
      throw new UnsupportedException(
          "Vendor attributes other than x and y need KMIP 2.0; this connection uses "
              + kms.version(),
          null,
          "custom attribute",
          null,
          null,
          null);
    return ModernAttributes.vendor(name.vendor(), name.name(), encoded);
  }

  KeyHandle createSymmetric(Algorithm algorithm, int bits, ObjectOptions options) {
    List<Ttlv> template = new ArrayList<>();
    template.add(Attributes.algorithm(algorithm.requireWire()));
    template.add(Attributes.length(bits));
    template.add(usage(options.usages));
    template.addAll(namesAndExtras(options, "create"));
    Request request =
        Requests.create()
            .add(enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY))
            .template(template.toArray(Ttlv[]::new))
            .build();
    String id =
        kms.call(
            "create",
            () -> {
              try {
                return kms.execute(
                    "create", Kms.Kind.MUTATION, null, s -> identifier(s.call(request)));
              } catch (InvalidRequestException | StateConflictException e) {
                throw duplicateName(e, options.names);
              }
            });
    KeyHandle key = new KeyHandle(this, id, ObjectKind.SYMMETRIC_KEY);
    // A protection asked is read back before anything activates the key: a server that ignores the
    // attribute must not hand out an extractable key as a non-extractable one.
    checkProtection(Kms.named("create"), key, null, options.protection());
    return key;
  }

  KeyPairHandle createPair(
      KeyPairSpec spec,
      Set<KeyUsage> privateUsages,
      Set<KeyUsage> publicUsages,
      String privateName,
      String publicName,
      ObjectOptions common) {
    KeyPairRequest request =
        spec.curve() == null
            ? KeyPairRequest.rsa(spec.bits())
            : KeyPairRequest.ec(spec.curve().protocolValue(), ecDefault(null));
    request.privateUsage(
        UsageMask.of(privateUsages.stream().map(KeyUsage::protocolValue).toList()));
    request.publicUsage(UsageMask.of(publicUsages.stream().map(KeyUsage::protocolValue).toList()));
    if (privateName != null) request.privateAttribute(Attributes.name(privateName));
    if (publicName != null) request.publicAttribute(Attributes.name(publicName));
    for (Ttlv a : extraAttributes(common, "createKeyPair")) request.commonAttribute(a);
    Request built = request.build();
    KeyPairRequest.Ids ids =
        kms.call(
            "create",
            () -> {
              try {
                return kms.execute(
                    "createKeyPair",
                    Kms.Kind.MUTATION,
                    null,
                    s -> KeyPairRequest.result(s.call(built)));
              } catch (InvalidRequestException | StateConflictException e) {
                List<String> names = new ArrayList<>();
                if (privateName != null) names.add(privateName);
                if (publicName != null) names.add(publicName);
                throw duplicateName(e, names);
              }
            });
    return new KeyPairHandle(
        new KeyHandle(this, ids.privateKeyId(), ObjectKind.PRIVATE_KEY),
        new KeyHandle(this, ids.publicKeyId(), ObjectKind.PUBLIC_KEY));
  }

  /**
   * The same failure on every version for a name already in use. KMIP 2.0 and later report it as
   * Non Unique Name Attribute ({@link AlreadyExistsException}), but KMIP 1.x has no such reason and
   * servers differ: Invalid Field (KMIP 1.4 Table 328, "a new object with the same Name attribute
   * value as an existing object"), or Illegal Operation (an earlier keytend-kmip-server build, to Add
   * Attribute). So such a refusal ({@link #nameRefusal}) of a request that set {@code names} is
   * confirmed with a Locate by each name (only on this failure): when an object other than {@code target} (the object the request
   * names, null for a new one, and those {@code others}) has one, the failure is an {@link AlreadyExistsException} (STATE)
   * naming it, with the server's failure as its cause; otherwise, or when the Locate fails, it
   * stands. Not a guess: the name must be in use elsewhere. Every request that adds a Name (create,
   * register, Add Attribute, and the name moves of replace, rotation, TLS renewal and {@link
   * #moveName}) is settled by this one rule. From KMIP 2.0, where Non Unique Name Attribute
   * exists, these reasons mean something else and stand.
   */
  KmsException duplicateName(
      KmsException e, Collection<String> names, String target, String... others) {
    // From 2.0 a name in use has its own reason, so these mean something else there.
    if (e instanceof AlreadyExistsException
        || names.isEmpty()
        || !nameRefusal(e)
        || kms.protocolVersion().atLeast(ProtocolVersion.V2_0)) return e;
    for (String name : names) {
      List<String> holders;
      try {
        holders = identifiers(KeyQuery.byName(name));
      } catch (KmsException | IllegalStateException unknown) {
        return e;
      }
      List<String> skip = List.of(others);
      holders = holders.stream().filter(h -> !h.equals(target) && !skip.contains(h)).toList();
      if (!holders.isEmpty())
        return new AlreadyExistsException(
            e.operation()
                + ": an object named "
                + name
                + " already exists ("
                + String.join(", ", holders)
                + "; the server answered "
                + e.serverReason().map(Object::toString).orElse("a refusal")
                + ", as KMIP 1.x servers may for a name in use): "
                + e.getMessage(),
            e,
            e.operation(),
            e.objectId().orElse(null),
            e.result().orElse(null),
            null);
    }
    return e;
  }

  /** {@link #duplicateName(KmsException, Collection, String, String...)} for a new object. */
  KmsException duplicateName(KmsException e, Collection<String> names) {
    return duplicateName(e, names, null);
  }

  /**
   * Whether {@code e} is a server's refusal that may mean a name in use on a server without Non
   * Unique Name Attribute (KMIP 1.x): Invalid Field or Illegal Operation, never an access, absence
   * or availability refusal. Only a KMIP 1.x Locate that finds the name elsewhere makes it one.
   */
  static boolean nameRefusal(KmsException e) {
    Enums.ResultReason reason = e.result().flatMap(Result::reasonEnum).orElse(null);
    return (e instanceof InvalidRequestException || e instanceof StateConflictException)
        && (reason == Enums.ResultReason.INVALID_FIELD
            || reason == Enums.ResultReason.ILLEGAL_OPERATION);
  }

  /** The {@link #singleFlight} work each thread is running, to refuse waiting for itself. */
  private static final ThreadLocal<Set<java.util.concurrent.CompletableFuture<List<String>>>>
      RUNNING =
          ThreadLocal.withInitial(
              () -> java.util.Collections.newSetFromMap(new java.util.IdentityHashMap<>()));

  /** {@link #singleFlight(Object, java.util.function.Supplier, java.util.function.Function, java.util.function.Function)} for one key. */
  KeyHandle singleFlight(Object key, ObjectKind kind, java.util.function.Supplier<KeyHandle> work) {
    return singleFlight(
        key, work, h -> List.of(h.id()), ids -> new KeyHandle(this, ids.get(0), kind));
  }

  /** {@link #singleFlight(Object, java.util.function.Supplier, java.util.function.Function, java.util.function.Function)} for a key pair. */
  FindOrCreatePairResult singleFlightPair(
      Object key, java.util.function.Supplier<FindOrCreatePairResult> work) {
    return singleFlight(
        key,
        work,
        r -> List.of(r.pair().privateKey().id(), r.pair().publicKey().id()),
        ids ->
            new FindOrCreatePairResult(
                new KeyPairHandle(
                    new KeyHandle(this, ids.get(0), ObjectKind.PRIVATE_KEY),
                    new KeyHandle(this, ids.get(1), ObjectKind.PUBLIC_KEY)),
                FindOrCreateResult.Outcome.FOUND,
                List.of(),
                null));
  }

  /**
   * Runs {@code work} for {@code key} unless the same key's work is already running through this
   * {@code Kms} (or a view of it): then waits for it, within the call's deadline, and returns
   * handles ({@code handles}) for the identifiers ({@code ids}) of what it found or created. If
   * that work failed, this caller runs its own.
   *
   * @throws TransientException when the deadline passes or the thread is interrupted while waiting
   * @throws IllegalStateException when this thread is running that work already (a {@link
   *     KmsListener} calling {@code findOrCreate} for the key being found or created), which would
   *     otherwise wait for itself until the deadline
   */
  @SuppressWarnings("UndefinedEquals") // each future is removed by identity, as it was added
  private <T> T singleFlight(
      Object key,
      java.util.function.Supplier<T> work,
      java.util.function.Function<T, List<String>> ids,
      java.util.function.Function<List<String>, T> handles) {
    var flights = kms.flights();
    while (true) {
      var mine = new java.util.concurrent.CompletableFuture<List<String>>();
      var running = flights.putIfAbsent(key, mine);
      if (running == null) {
        RUNNING.get().add(mine);
        try {
          T result = work.get();
          mine.complete(ids.apply(result));
          return result;
        } catch (RuntimeException | Error e) {
          mine.completeExceptionally(e);
          throw e;
        } finally {
          RUNNING.get().remove(mine);
          flights.remove(key, mine);
        }
      }
      if (RUNNING.get().contains(running))
        throw new IllegalStateException(
            "findOrCreate: called again for the same key from inside that findOrCreate (a KmsListener?);"
                + " it would wait for itself");
      try {
        return handles.apply(
            running.get(
                Math.max(0, kms.remainingNanos()), java.util.concurrent.TimeUnit.NANOSECONDS));
      } catch (java.util.concurrent.ExecutionException failed) {
        // The other call's failure is its own: try again, perhaps as the one that runs.
      } catch (java.util.concurrent.TimeoutException e) {
        throw new TransientException(
            "findOrCreate: the call deadline passed while waiting for another findOrCreate of the same key in this process",
            null,
            "findOrCreate",
            null,
            null,
            null);
      } catch (InterruptedException e) {
        Thread.currentThread().interrupt();
        throw new TransientException(
            "findOrCreate: interrupted while waiting for another findOrCreate of the same key in this process",
            null,
            "findOrCreate",
            null,
            null,
            null);
      }
    }
  }

  /**
   * Register and Create Key Pair replies carry only identifiers, so before handles that claim
   * a kind are handed out or activated, the objects they name are read (one batched Get
   * Attributes): each must exist and be of the kind created, and a pair's two identifiers must
   * differ. A reply that names something else is a protocol violation of a mutation: {@link
   * OutcomeUnknownException}, since the object may have been created under another identifier.
   */
  List<KeyAttributes> checkCreated(String operation, List<KeyHandle> created, KeyPairHandle pair) {
    return checkCreated(operation, created, pair, null);
  }

  /**
   * {@link #checkCreated(String, List, KeyPairHandle)} of an object made with the protection {@code
   * asked} (null for none): when reading it back fails, the advice says to check that protection
   * before activating it.
   */
  List<KeyAttributes> checkCreated(
      String operation, List<KeyHandle> created, KeyPairHandle pair, Protection asked) {
    List<String> ids = created.stream().map(KeyHandle::id).toList();
    if (new HashSet<>(ids).size() != ids.size())
      throw new OutcomeUnknownException(
          operation
              + ": the server's reply names "
              + ids.get(0)
              + " for both keys; the operation may have taken effect",
          null,
          operation,
          null,
          null,
          null);
    List<KeyAttributes> read;
    try {
      read = Kms.named(operation, () -> attributesOf(ids));
    } catch (KmsException | IllegalStateException e) {
      throw PartialCompletionException.of(
          operation,
          created,
          pair,
          "reading the created object(s) failed",
          asked != null && asked.any()
              ? "check their kinds and that they have the protection asked ("
                  + asked
                  + ") with attributes(), and activate them only if they have, instead of repeating"
                  + " the call; if not, do not activate or use them, and remove their names"
                  + " (removeName) so that no lookup finds them"
              : "check their kinds with attributes(), then activate them instead of repeating the"
                  + " call; keep them either way: once a name lookup finds them, another instance"
                  + " may already use them",
          e);
    }
    for (KeyHandle k : created) {
      ObjectKind expected = k.knownKind().orElseThrow();
      ObjectKind actual =
          read.stream()
              .filter(a -> a.id().equals(k.id()))
              .findFirst()
              .map(KeyAttributes::kind)
              .orElse(null);
      if (actual != expected)
        throw new OutcomeUnknownException(
            operation
                + ": the server's reply names "
                + k.id()
                + ", which "
                + (actual == null ? "does not exist" : "is a " + actual)
                + ", not the "
                + expected
                + " just made; the operation may have taken effect under another identifier",
            null,
            operation,
            k.id(),
            null,
            null);
    }
    return read;
  }

  /** Activates newly created objects; a failure becomes {@link PartialCompletionException}. */
  void activateCreated(String operation, List<KeyHandle> created) {
    activateCreated(operation, created, null);
  }

  void activateCreated(String operation, KeyPairHandle pair) {
    activateCreated(operation, List.of(pair.privateKey(), pair.publicKey()), pair);
  }

  /**
   * Every path after a successful creation surfaces the created handles: a failed activation is
   * re-checked (another caller may have activated the key, or an unknown outcome may have taken
   * effect), and a {@link Kms} closed meanwhile is a partial completion too.
   */
  private void activateCreated(String operation, List<KeyHandle> created, KeyPairHandle pair) {
    for (KeyHandle key : created)
      try {
        key.activate();
      } catch (KmsException e) {
        if (Failures.credentialsRefused(e) || !activeAfterAll(key))
          throw PartialCompletionException.of(operation, created, pair, e);
      } catch (IllegalStateException closed) {
        throw PartialCompletionException.of(operation, created, pair, closed);
      }
  }

  /**
   * Activates {@code key}, which the call went on with but did not confirm creating (found by
   * reading back after {@code lost}, or made by an earlier call or another caller when {@code lost}
   * is null), as {@link #activateCreated(String, List)} activates a created key: a failure lists it
   * as {@link PartialCompletionException#found()}. Returns the Activate whose reply was lost when
   * reading back found the key Active (this call's Activate or another caller's took effect), so
   * the caller can report it; null when the reply came, or another caller's activation came first.
   */
  OutcomeUnknownException activateFound(
      String operation, KeyHandle key, OutcomeUnknownException lost) {
    RuntimeException failed;
    try {
      key.activate();
      return null;
    } catch (KmsException e) {
      if (!Failures.credentialsRefused(e) && activeAfterAll(key))
        return e instanceof OutcomeUnknownException unknown ? unknown : null;
      failed = e;
    } catch (IllegalStateException closed) {
      failed = closed;
    }
    throw PartialCompletionException.found(
        operation,
        List.of(key),
        lost,
        "activation failed",
        PartialCompletionException.activationAdvice(operation),
        failed);
  }

  private static boolean activeAfterAll(KeyHandle key) {
    try {
      return key.attributes().state() == KeyState.ACTIVE;
    } catch (KmsException | IllegalStateException e) {
      return false;
    }
  }

  static String identifier(Result result) throws ProtocolException {
    try {
      return result.uniqueIdentifier();
    } catch (IllegalArgumentException | IllegalStateException e) {
      throw new ProtocolException("Response missing UniqueIdentifier", result.batchItem(), null);
    }
  }
}
