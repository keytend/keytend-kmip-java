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

package dev.keytend.kmip.testing;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.client.Messages;
import dev.keytend.kmip.client.Response;
import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.kms.KeyState;
import dev.keytend.kmip.kms.KeyUsage;
import dev.keytend.kmip.kms.KmipVersion;
import dev.keytend.kmip.kms.Kms;
import dev.keytend.kmip.kms.KmsConfig;
import dev.keytend.kmip.kms.LinkKind;
import dev.keytend.kmip.kms.ObjectKind;
import dev.keytend.kmip.model.Attributes;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Enums.BlockCipherMode;
import dev.keytend.kmip.model.Enums.CryptographicAlgorithm;
import dev.keytend.kmip.model.Enums.CryptographicUsageMask;
import dev.keytend.kmip.model.Enums.HashingAlgorithm;
import dev.keytend.kmip.model.Enums.KeyFormatType;
import dev.keytend.kmip.model.Enums.LinkType;
import dev.keytend.kmip.model.Enums.ObjectType;
import dev.keytend.kmip.model.Enums.PaddingMethod;
import dev.keytend.kmip.model.Enums.ResultReason;
import dev.keytend.kmip.model.Enums.State;
import dev.keytend.kmip.model.Enums.ValidityIndicator;
import dev.keytend.kmip.model.KeyMaterials;
import dev.keytend.kmip.model.Keys;
import dev.keytend.kmip.model.ManagedObjects;
import dev.keytend.kmip.model.ModernAttributes;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.ProtocolVersion;
import dev.keytend.kmip.model.Structures;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.model.VersionValidator;
import dev.keytend.kmip.model.WireEnums;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import dev.keytend.kmip.transport.RequestNotSentException;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.io.InterruptedIOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.function.BiPredicate;
import java.util.function.Function;
import java.util.function.Supplier;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

/**
 * An in-memory KMIP server for tests, in the {@code keytend-kmip-testing} artifact. A real {@link
 * Kms} connects to it in process, without an external server. It is test support, not a key
 * manager, so never give it real keys. Add the artifact in test scope (<a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/getting-started.md#test-without-a-server">Test
 * without a server</a>). Like the rest of
 * this package, it is outside the SDK's compatibility promises (<a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/compatibility.md#the-testing-package">The
 * testing package</a>).
 *
 * <pre>{@code
 * InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
 * try (Kms kms = server.connect()) {
 *   KeyHandle key = kms.keys().createAes(256).named("invoices-kek")
 *       .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
 *   // ... code under test ...
 *   server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
 *   assertThrows(PermissionDeniedException.class, () -> key.attributes());
 *   assertEquals(Optional.of(KeyState.ACTIVE), server.state(key.id()));
 *   assertEquals(List.of(), server.violations());
 * }
 * }</pre>
 *
 * <p>The assertions are JUnit 5's. {@link #of(KmipVersion...)} creates a server with no objects.
 * {@link #connect()} returns a {@code Kms} connected to it, which the test closes. To change the
 * retry policy, timeouts or listener first, build the {@code Kms} from {@link #configure()}.
 *
 * <p><b>Versions and operations.</b> By default the server speaks KMIP 1.2, 1.3, 1.4, 2.0, 2.1 and
 * 3.0 (CSD02), each with its exact wire shapes. It implements Discover Versions, Query, Create,
 * Create Key Pair, Register, Certify (with a CA the client registered), Get, Get Attributes, Get
 * Attribute List, Add, Modify, Set and Delete Attribute, Locate, Activate, Revoke, Deactivate
 * (3.0), Destroy, Re-Key, Encrypt, Decrypt, Sign, Signature Verify, MAC, MAC Verify and RNG
 * Retrieve, Obtain Lease once {@link #leaseTime} is set, and Re-Provision (2.0 and later) through a
 * {@link TlsListener} with a provisioning CA ({@link TlsListener.Builder#provisioningCa}). Other
 * operations answer Operation Not Supported. Multi-part cryptography, templates, wrapped Register
 * and Key Compression are not supported. How the server answers on each version, from result
 * reasons on 1.x to IV defaults, wrapped Get and Locate, is in <a
 * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/in-memory-server.md">In-memory
 * test server</a>.
 *
 * <p><b>Application-level methods.</b> These use only {@code dev.keytend.kmip.kms} types:
 *
 * <ul>
 *   <li>What the server holds: {@link #ids()}, {@link #exists}, {@link #state}, {@link #kind},
 *       {@link #usages}, {@link #names}, {@link #links}, {@link #hasMaterial}.
 *   <li>Faults: {@link #failNext(ServerOperation, Fault)} makes the next matching request fail as
 *       a real server or network would. {@link #unreachable(boolean)} switches the server off and
 *       on. {@link #slowReplyDelay} sets how long a {@link Fault#SLOW} reply is held.
 *   <li>Checks: {@link #violations()} lists requests that break the version's wire shapes. Assert
 *       that it is empty. {@link
 *       #exchanges()}, {@link #closed()} and {@link #closeCount()} count calls.
 *   <li>Control: {@link #identifierSource} for identifiers that do not sort in creation order, and
 *       {@link #clock} for dates the test sets.
 *   <li>Behavior that real servers differ on: {@link #uniqueNames}, {@link
 *       #destroyedObjectsKeepNames}, {@link #refuseSecondReKey}, {@link #freshDatesOnReKey}, {@link
 *       #refuseClientDeactivationDate}, {@link #linkCardinality}, {@link #leaseTime}, {@link
 *       #leasesOnlyForActive} and {@link #certifyHonorsDates}.
 *   <li>Failover: {@link #replica()} and {@link #configureReplicas} give several endpoints that
 *       share one store.
 *   <li>TLS: {@link #tlsListener()} builds a listener that serves the server over TLS on a loopback
 *       port ({@link TlsListener}), to test the SDK's TLS transport and client credentials against
 *       it.
 * </ul>
 *
 * <p><b>Protocol-level hooks.</b> For protocol tests, these expose KMIP messages and types: {@link
 * #protocolRequests()}, {@link #protocolState}, {@link #protocolLink}, {@link #protocolAttributes},
 * {@link #protocolVersions()}, {@link #failNext(ServerOperation, ResultReason)}, {@link
 * #legacyNonUniqueNameReason}, and {@link #injectBeforeProcessing} and {@link
 * #injectAfterProcessing}, which throw any {@code IOException}. For other failures, wrap the server
 * in a {@code KmipTransport} passed to {@link KmsConfig.Builder#transport}.
 *
 * <p><b>Concurrency.</b> The server is thread-safe. Every public method holds one lock, shared by
 * all replicas of a store, so requests are processed one at a time and inspection sees a
 * consistent store. A {@link Fault#HANG} or {@link Fault#SLOW} exchange releases the lock before it
 * waits, so it does not block other clients or replicas. Hooks ({@link #identifierSource}, {@link
 * #injectBeforeProcessing}, ...) are called with the lock held.
 *
 * @since 0.10.0
 */
public final class InMemoryKmipServer implements KmipTransport {
  private static final List<ProtocolVersion> DEFAULT_VERSIONS =
      List.of(
          ProtocolVersion.V1_2,
          ProtocolVersion.V1_3,
          ProtocolVersion.V1_4,
          ProtocolVersion.V2_0,
          ProtocolVersion.V2_1,
          ProtocolVersion.V3_0);
  private static final ProtocolVersion V3_0 = ProtocolVersion.V3_0;

  /** Attributes only the server sets. */
  private static final Set<Tag> SERVER_ONLY =
      Set.of(
          UNIQUE_IDENTIFIER,
          OBJECT_TYPE,
          STATE,
          INITIAL_DATE,
          DESTROY_DATE,
          COMPROMISE_DATE,
          COMPROMISE_OCCURRENCE_DATE,
          LAST_CHANGE_DATE,
          REVOCATION_REASON,
          DEACTIVATION_REASON,
          DIGEST);

  /** The lifecycle dates a Re-key without an Offset copies to the replacement (KMIP 1.4 §4.4). */
  private static final Set<Tag> DATES =
      Set.of(ACTIVATION_DATE, PROCESS_START_DATE, PROTECT_STOP_DATE, DEACTIVATION_DATE);

  /** Attributes Add/Modify/Set/Delete Attribute may not change. */
  private static final Set<Tag> READ_ONLY =
      union(
          SERVER_ONLY,
          Set.of(
              CRYPTOGRAPHIC_ALGORITHM, CRYPTOGRAPHIC_LENGTH, CERTIFICATE_LENGTH, CERTIFICATE_TYPE));

  private static final Set<Tag> MULTI_VALUED =
      Set.of(
          NAME,
          OBJECT_GROUP,
          LINK,
          CRYPTOGRAPHIC_PARAMETERS,
          APPLICATION_SPECIFIC_INFORMATION,
          ALTERNATIVE_NAME,
          DIGEST);

  private static final Set<Integer> ID_TAGS =
      Set.of(
          UNIQUE_IDENTIFIER.code(),
          PRIVATE_KEY_UNIQUE_IDENTIFIER.code(),
          PUBLIC_KEY_UNIQUE_IDENTIFIER.code());

  private static final Set<CryptographicAlgorithm> EC_FAMILY =
      EnumSet.of(
          CryptographicAlgorithm.EC, CryptographicAlgorithm.ECDSA, CryptographicAlgorithm.ECDH);

  private static final Set<KeyFormatType> PRIVATE_FORMATS =
      EnumSet.of(
          KeyFormatType.PKCS_8,
          KeyFormatType.PKCS_1,
          KeyFormatType.ECPRIVATE_KEY,
          KeyFormatType.TRANSPARENT_RSA_PRIVATE_KEY,
          KeyFormatType.TRANSPARENT_EC_PRIVATE_KEY,
          KeyFormatType.TRANSPARENT_ECDSA_PRIVATE_KEY,
          KeyFormatType.TRANSPARENT_ECDH_PRIVATE_KEY);

  private static final Set<KeyFormatType> PUBLIC_FORMATS =
      EnumSet.of(
          KeyFormatType.X_509,
          KeyFormatType.PKCS_1,
          KeyFormatType.TRANSPARENT_RSA_PUBLIC_KEY,
          KeyFormatType.TRANSPARENT_EC_PUBLIC_KEY,
          KeyFormatType.TRANSPARENT_ECDSA_PUBLIC_KEY,
          KeyFormatType.TRANSPARENT_ECDH_PUBLIC_KEY);

  private static final Set<Operation> IMPLEMENTED =
      EnumSet.of(
          Operation.DISCOVER_VERSIONS,
          Operation.QUERY,
          Operation.CREATE,
          Operation.CREATE_KEY_PAIR,
          Operation.REGISTER,
          Operation.CERTIFY,
          Operation.RE_KEY,
          Operation.LOCATE,
          Operation.GET,
          Operation.GET_ATTRIBUTES,
          Operation.GET_ATTRIBUTE_LIST,
          Operation.ADD_ATTRIBUTE,
          Operation.MODIFY_ATTRIBUTE,
          Operation.SET_ATTRIBUTE,
          Operation.DELETE_ATTRIBUTE,
          Operation.ACTIVATE,
          Operation.REVOKE,
          Operation.DEACTIVATE,
          Operation.DESTROY,
          Operation.ENCRYPT,
          Operation.DECRYPT,
          Operation.SIGN,
          Operation.SIGNATURE_VERIFY,
          Operation.MAC,
          Operation.MAC_VERIFY,
          Operation.RNG_RETRIEVE);

  /** Operations whose 2.x/3.0 payloads must not carry 1.x Attribute or AttributeName fields. */
  private static final Set<Operation> ATTRIBUTE_CARRIERS =
      EnumSet.of(
          Operation.CREATE,
          Operation.CREATE_KEY_PAIR,
          Operation.REGISTER,
          Operation.RE_KEY,
          Operation.LOCATE,
          Operation.GET_ATTRIBUTES,
          Operation.GET_ATTRIBUTE_LIST,
          Operation.ADD_ATTRIBUTE,
          Operation.MODIFY_ATTRIBUTE,
          Operation.SET_ATTRIBUTE,
          Operation.DELETE_ATTRIBUTE);

  /** Link Type code to its KMIP 3.0 per-type link attribute. */
  private static final Map<Integer, Tag> LINK_TAGS = linkTags();

  /** DER DigestInfo prefixes (RFC 8017 §9.2) for RSA PKCS#1 v1.5 over a precomputed digest. */
  private static final Map<String, String> DIGEST_INFO =
      Map.of(
          "SHA-1", "3021300906052b0e03021a05000414",
          "SHA-224", "302d300d06096086480165030402040500041c",
          "SHA-256", "3031300d060960864801650304020105000420",
          "SHA-384", "3041300d060960864801650304020205000430",
          "SHA-512", "3051300d060960864801650304020305000440");

  /** How long a {@link Fault#HANG} waits at most: when the exchange has no earlier deadline. */
  private static final Duration HANG_LIMIT = Duration.ofSeconds(60);

  private final List<ProtocolVersion> supported;

  /** The objects and settings shared with every replica; its monitor is their one lock. */
  private final Store store;

  /** The lock every replica of the store holds while it reads or changes anything. */
  private final Object lock;

  /** {@code store.objects}. */
  private final Map<String, Obj> objects;

  // Per-replica state, guarded by lock.
  private final List<Ttlv> requests = new ArrayList<>();
  private final List<String> violations = new ArrayList<>();
  private final SecureRandom random = new SecureRandom();
  private Function<Ttlv, IOException> before, after;

  /** Faults armed with {@code failNext}, in arming order. */
  private final List<Armed> armed = new ArrayList<>();

  private int exchanges, closed;

  /** How long a {@link Fault#SLOW} reply is held. */
  private Duration slowReplyDelay = Duration.ofSeconds(1);

  /** Whether {@link #unreachable(boolean)} switched this server off. */
  private volatile boolean unreachable;

  /** Whether {@link #unreachable(boolean)} switched this server off: a {@link TlsListener} asks. */
  boolean isUnreachable() {
    return unreachable;
  }

  // Per-exchange state, guarded by lock.
  private ProtocolVersion v;
  private String placeholder;

  /** The TLS connection of this exchange ({@link TlsListener}); null for an in-process exchange. */
  private Channel channel;

  /** This message's header and items, and the position of the item being processed. */
  private Ttlv messageHeader;

  private List<Ttlv> messageItems = List.of();
  private int itemIndex;

  /** Whether this message had a Re-Provision item, run or refused. */
  private boolean reProvisionTried;

  /** The replacement this message's Re-Provision made, until the message commits or fails. */
  private Replacement replacement;

  /**
   * A TLS connection to the server ({@link TlsListener}): the client's certificate chain and the
   * listener's provisioning CA (null without one).
   */
  static final class Channel {
    final X509Certificate[] chain;
    final Provisioning provisioning;

    Channel(X509Certificate[] chain, Provisioning provisioning) {
      this.chain = chain;
      this.provisioning = provisioning;
    }
  }

  /**
   * A Re-Provision's work in its message: the certificate issued and its key (the hex
   * SubjectPublicKeyInfo), and the certificate it replaces.
   */
  private record Replacement(
      String id, X509Certificate replaced, X509Certificate issued, String newKey) {}

  /** The armed Result Reason fault this message selected, until an item fires it. */
  private Armed selected;

  /**
   * Protocol-level form of {@link #of(KmipVersion...)}: a server that speaks {@code supported}.
   *
   * @param supported the versions to accept; none means 1.2, 1.3, 1.4, 2.0, 2.1 and 3.0
   */
  public InMemoryKmipServer(ProtocolVersion... supported) {
    List<ProtocolVersion> list =
        new ArrayList<>(
            new TreeSet<>(supported.length == 0 ? DEFAULT_VERSIONS : Arrays.asList(supported)));
    Collections.reverse(list);
    this.supported = List.copyOf(list);
    this.store = new Store();
    this.lock = store;
    this.objects = store.objects;
  }

  /** A replica of {@code of}: the same versions and store. */
  private InMemoryKmipServer(InMemoryKmipServer of) {
    this.supported = of.supported;
    this.store = of.store;
    this.lock = store;
    this.objects = store.objects;
  }

  /**
   * A server that speaks {@code versions} (none: 1.2, 1.3, 1.4, 2.0, 2.1 and 3.0). A {@code Kms}
   * from {@link #configure()} or {@link #connect()} negotiates what production would: 2.1 on the
   * default server, not the 3.0 draft. Name the version a test needs: {@code
   * InMemoryKmipServer.of(KmipVersion.V2_1)}.
   *
   * @param versions the versions to speak; none for the default set
   * @return a new server, with no objects
   */
  public static InMemoryKmipServer of(KmipVersion... versions) {
    ProtocolVersion[] p = new ProtocolVersion[versions.length];
    for (int i = 0; i < versions.length; i++) p[i] = versions[i].protocolValue();
    return new InMemoryKmipServer(p);
  }

  /**
   * A {@link KmsConfig} builder for this server: one endpoint ({@code in-memory:5696}) whose
   * transport is this server, and a version range from the lowest version it speaks up to the
   * highest one within the production default ({@link KmsConfig.Builder#maximumVersion}, 2.1), so
   * the version negotiated is the one a default {@code Kms} would negotiate with a real server that
   * speaks the same versions (except that the minimum is the server's lowest version, not 1.4, so
   * {@code of(KmipVersion.V1_2)} connects at 1.2). Only a server that speaks nothing up to 2.1 (for example {@code
   * of(KmipVersion.V3_0)}) negotiates the 3.0 draft. Change what the test needs (retry policy,
   * timeouts, listener, {@code maximumVersion(KmipVersion.V3_0)}) and build.
   *
   * @return a new builder, which the test may change before building
   */
  public KmsConfig.Builder configure() {
    return versions(KmsConfig.builder().endpoints("in-memory:5696").transport(endpoint -> this));
  }

  /**
   * A TLS listener for this server, to set up and {@link TlsListener.Builder#start() start}: a
   * {@code Kms} then connects over the SDK's TLS transport, with its own client credentials, as to
   * a real KMS. Give it the server's identity and the trust of client certificates. Connect with
   * {@link TlsListener#configure()}, which has this server's version range. Several listeners may
   * serve one server, and a {@link #replica()} its own.
   *
   * @return a new listener builder
   */
  public TlsListener.Builder tlsListener() {
    return new TlsListener.Builder(this);
  }

  /** {@code builder} with {@link #configure()}'s version range. */
  KmsConfig.Builder versions(KmsConfig.Builder builder) {
    ProtocolVersion highest =
        supported.stream()
            .filter(v -> !v.atLeast(ProtocolVersion.V3_0))
            .findFirst()
            .orElse(supported.get(0));
    return builder
        .minimumVersion(KmipVersion.fromProtocol(supported.get(supported.size() - 1)))
        .maximumVersion(KmipVersion.fromProtocol(highest));
  }

  /**
   * A {@link Kms} connected to this server with {@link #configure()}'s settings.
   *
   * @return a connected {@code Kms}, which the test closes
   */
  public Kms connect() {
    return Kms.connect(configure().build());
  }

  /**
   * A new server that shares this one's objects, as a replica of a real KMS does: an object
   * created, changed or destroyed through one is seen through all, and they share the identifier
   * sequence, {@link #identifierSource}, {@link #clock}, {@link #uniqueNames} and {@link
   * #refuseSecondReKey} (setting one on
   * any replica sets it for all). Each replica has its own armed faults ({@link #failNext}, {@link
   * #injectBeforeProcessing}, {@link #injectAfterProcessing}), {@link #slowReplyDelay}, {@link
   * #protocolRequests()}, {@link #violations()}, {@link #exchanges()} and close count, so a test
   * can make one replica fail and see which one each request reached. It speaks the same versions.
   * A replica of a replica belongs to the same set. All replicas process one request at a time
   * between them (they share one lock), so the store stays consistent; {@link Fault#HANG} and
   * {@link Fault#SLOW} wait without that lock. Connect to several with {@link #configureReplicas}.
   *
   * @return a new server sharing this one's objects
   */
  public InMemoryKmipServer replica() {
    return new InMemoryKmipServer(this);
  }

  /**
   * A {@link KmsConfig} builder for several replicas of one store, like {@link #configure()} (same
   * version range) but with one endpoint per server, in order: this server as {@code
   * in-memory:5696}, then {@code others} as {@code in-memory-2:5696}, {@code in-memory-3:5696},
   * ... Each endpoint's transport is its server, so a fault armed on one replica affects only the
   * endpoint it backs, and the {@code Kms} fails over between them as it does between real
   * replicas ({@link dev.keytend.kmip.kms.KmsListener#endpointUnavailable} names the endpoint by
   * these labels).
   *
   * @param others replicas of this server ({@link #replica()}), each given once
   * @return a new builder, which the test may change before building
   * @throws IllegalArgumentException if a server does not share this one's objects, or appears
   *     twice (this server included)
   */
  public KmsConfig.Builder configureReplicas(InMemoryKmipServer... others) {
    List<InMemoryKmipServer> all = new ArrayList<>(List.of(this));
    for (InMemoryKmipServer other : others) {
      Objects.requireNonNull(other, "replica");
      if (other.store != store)
        throw new IllegalArgumentException(
            "configureReplicas: a server that does not share this server's objects is not a"
                + " replica; create replicas with replica()");
      for (InMemoryKmipServer seen : all)
        if (seen == other)
          throw new IllegalArgumentException(
              "configureReplicas: a server appears twice; give each replica once");
      all.add(other);
    }
    String[] labels = new String[all.size()];
    Map<String, InMemoryKmipServer> byHost = new HashMap<>();
    for (int i = 0; i < all.size(); i++) {
      String host = i == 0 ? "in-memory" : "in-memory-" + (i + 1);
      labels[i] = host + ":5696";
      byHost.put(host, all.get(i));
    }
    return versions(
        KmsConfig.builder().endpoints(labels).transport(endpoint -> byHost.get(endpoint.host())));
  }

  /**
   * Makes the server (and its replicas) refuse a Name that another object which is not destroyed
   * already has, as servers that enforce unique names do; off by default, when any number of
   * objects may share a name. When on, Create, Create Key Pair, Register, Re-Key and Add or Modify
   * Attribute of a Name fail before they change anything (Set Attribute cannot set a Name on this
   * server at all) with:
   *
   * <ul>
   *   <li>KMIP 2.0 and later: Non Unique Name Attribute;
   *   <li>KMIP 1.x: Invalid Field, which the 1.x error tables prescribe for "trying to create a new
   *       object with the same Name attribute value as an existing object" (KMIP 1.4 Table 328), or
   *       the reason {@link #legacyNonUniqueNameReason} sets.
   * </ul>
   *
   * The Result Message is "Name is not unique: " and the name. Destroyed objects do not hold their
   * names (servers differ here; this one lets a name be reused once its holder is destroyed).
   * Re-Key moves the old key's names to the replacement, which is not a conflict; a Name the
   * request adds that another object holds is. A refusal is an ordinary server answer, not a
   * {@link #violations() violation}.
   *
   * @param unique whether names must be unique
   * @return this server
   */
  public InMemoryKmipServer uniqueNames(boolean unique) {
    synchronized (lock) {
      store.uniqueNames = unique;
      return this;
    }
  }

  /**
   * The Result Reason that a Name refused by {@link #uniqueNames} gets on KMIP 1.x. KMIP 1.x has no
   * reason for a name in use, so servers differ. One server answers Illegal Operation to Add
   * Attribute, and Invalid Field to Create and Register.
   *
   * <ul>
   *   <li>A reason: every request refused for its name gets it.
   *   <li>Null, the default: Invalid Field.
   * </ul>
   *
   * <p>KMIP 2.0 and later keep Non Unique Name Attribute. Applies to this server and its replicas.
   *
   * @param reason the 1.x reason, for example {@link ResultReason#ILLEGAL_OPERATION}; null for the
   *     default
   * @return this server
   * @since 0.10.0
   */
  public InMemoryKmipServer legacyNonUniqueNameReason(ResultReason reason) {
    synchronized (lock) {
      store.legacyNonUniqueReason = reason;
      return this;
    }
  }

  /**
   * Whether the server and its replicas refuse a Re-Key of a symmetric key that was already
   * re-keyed, that is, one that names a replacement with a Replacement Object link.
   *
   * <ul>
   *   <li>On: such a Re-Key is refused with Permission Denied on every version, and the Result
   *       Message "already replaced by " followed by the replacement's identifier. Two callers that
   *       rotate one key at the same moment then never fork its lineage, because the second is
   *       refused. keytend-kmip-server answers so.
   *   <li>Off, the default: every Re-Key succeeds, and such callers each get a replacement.
   * </ul>
   *
   * <p>A refusal is an ordinary server answer, not a {@link #violations() violation}. KMIP 1.4
   * Table 331 prescribes Permission Denied for a key that "is not able to be re-keyed". The 2.x
   * Re-Key error tables list it, and no lifecycle reason.
   *
   * @param refuse whether to refuse a second Re-Key
   * @return this server
   */
  public InMemoryKmipServer refuseSecondReKey(boolean refuse) {
    synchronized (lock) {
      store.refuseSecondReKey = refuse;
      return this;
    }
  }

  /**
   * Whether the server and its replicas give a Re-Key's replacement new lifecycle dates, as some
   * servers do.
   *
   * <ul>
   *   <li>On: the replacement gets none of the old key's Activation, Process Start, Protect Stop
   *       and Deactivation Dates. It is activated now when the old key is Active. Otherwise it is
   *       left Pre-Active, as some servers leave the replacement of a revoked key. An Offset in the
   *       request is ignored.
   *   <li>Off, the default: without an Offset, the replacement copies those dates from the old key,
   *       and only its Initial Date is now. Its State follows from its dates, so the replacement of
   *       an Active key is Active, with the old key's Activation Date. With an Offset, the
   *       replacement is activated Offset seconds after its Initial Date, and the other dates move
   *       by as much. keytend-kmip-server does the same.
   * </ul>
   *
   * <p>The default follows KMIP 1.4 §4.4, 2.0 §6.1.42 and 2.1 §6.1.46.
   *
   * @param fresh whether a replacement gets new dates
   * @return this server
   */
  public InMemoryKmipServer freshDatesOnReKey(boolean fresh) {
    synchronized (lock) {
      store.freshDatesOnReKey = fresh;
      return this;
    }
  }

  /**
   * Whether the server and its replicas refuse a client's Add Attribute, Modify Attribute or Set
   * Attribute of a Deactivation Date, as some servers do.
   *
   * <ul>
   *   <li>On: the request is refused with Attribute Read Only. KMIP 1.x has no such reason, so
   *       there it is Permission Denied.
   *   <li>Off, the default: a client may set the date while the object is Pre-Active or Active, as
   *       KMIP 1.4 Table 114 allows. The object is Deactivated once the date has come.
   * </ul>
   *
   * <p>Either way, a client cannot delete a Deactivation Date. A refusal is an ordinary server
   * answer, not a {@link #violations() violation}.
   *
   * @param refuse whether to refuse a client's Deactivation Date
   * @return this server
   */
  public InMemoryKmipServer refuseClientDeactivationDate(boolean refuse) {
    synchronized (lock) {
      store.refuseClientDeactivationDate = refuse;
      return this;
    }
  }

  /**
   * Whether Certify takes the request's dates as the certificate's validity, as keytend-kmip-server
   * does. On by default: the Activation Date is the notBefore (now without one) and
   * the Deactivation Date the notAfter (without one, 365 days from the notBefore, cut short at the
   * issuing CA's notAfter). An Activation Date at or after the CA's notAfter, a Deactivation Date
   * after it (never cut short), and a Deactivation Date at or before the notBefore are Invalid
   * Field. Off models servers that ignore the dates (earlier keytend-kmip-server builds): the
   * certificate is valid from now for 365 days, capped at the CA's notAfter, whatever dates the
   * request asks for. Either way the stored certificate gets only the dates asked, as its
   * attributes, so one asked with a Deactivation Date and no Activation Date stays Pre-Active.
   * Applies to this server and its replicas.
   *
   * @param honor whether Certify takes the dates asked as the validity
   * @return this server
   * @since 0.10.0
   */
  public InMemoryKmipServer certifyHonorsDates(boolean honor) {
    synchronized (lock) {
      store.certifyHonorsDates = honor;
      return this;
    }
  }

  /**
   * Whether the server and its replicas refuse a client's Add Attribute of a second link of a type
   * an object may have once, as keytend-kmip-server does.
   *
   * <ul>
   *   <li>On, the default: a second Replacement Object link is refused on every version, with
   *       Invalid Field in KMIP 1.x and Attribute Single Valued from 2.0. In KMIP 3.0, a second
   *       link of any type is refused, with Attribute Single Valued, except Certificate,
   *       Derivation Base Object and Derived Key links. That includes Replaced Object links.
   *   <li>Off: every link is added, for a test that needs an object with several links of one such
   *       type.
   * </ul>
   *
   * <p>The server's own Re-Key of a key already replaced still adds a second Replacement Object
   * link, as servers that re-key a key twice do. {@link #refuseSecondReKey} refuses that Re-Key, as
   * keytend-kmip-server does. A refusal is an ordinary server answer, not a {@link #violations()
   * violation}.
   *
   * <p>KMIP 1.4 §3.35, 2.1 §4.30 and 3.0 §4.35.18 allow one replacement object. KMIP 3.0 Table 162
   * marks the other single links "Multiple instances permitted: No".
   *
   * @param enforce whether to refuse a second link of such a type
   * @return this server
   */
  public InMemoryKmipServer linkCardinality(boolean enforce) {
    synchronized (lock) {
      store.linkCardinality = enforce;
      return this;
    }
  }

  /**
   * Makes the server take the identifier of each object it creates or registers from {@code
   * source} from now on, instead of {@code mock-1}, {@code mock-2}, ... in creation order. Real
   * servers often use random identifiers, which do not sort in creation order: {@code () ->
   * UUID.randomUUID().toString()} reproduces that, and a fixed sequence lets a test choose how
   * identifiers sort. {@code source} is called with the server's lock held, once per new object
   * (also for objects a batch with Batch Error Continuation Option Undo later discards). A null or
   * empty identifier, or one an object on the server has (destroyed objects included), fails the
   * request with General Failure and is recorded in {@link #violations()}.
   *
   * @param source the identifiers to use, one call per new object
   * @return this server
   */
  public InMemoryKmipServer identifierSource(Supplier<String> source) {
    synchronized (lock) {
      store.identifiers = Objects.requireNonNull(source, "source");
      return this;
    }
  }

  /**
   * Makes the server read the time from {@code clock} from now on, instead of the system clock:
   * the Initial Date of new objects, the Activation, Deactivation, Compromise and Destroy Dates it
   * sets, whether a requested Activation Date has passed, when an object's Activation and
   * Deactivation Dates change its State, and the response Time Stamp. Dates are
   * truncated to whole seconds, as KMIP Date-Time values are. A fixed clock ({@link Clock#fixed})
   * gives objects created at different moments the same Initial Date.
   *
   * @param clock the clock to use
   * @return this server
   */
  public InMemoryKmipServer clock(Clock clock) {
    synchronized (lock) {
      store.clock = Objects.requireNonNull(clock, "clock");
      return this;
    }
  }

  /**
   * Makes the server (and its replicas) lease objects, as keytend-kmip-server does (KMIP 1.4 §3.20 and
   * §4.17, 2.1 §4.30 and §6.1.35): from now on Get Attributes and Get Attribute List state the Lease
   * Time {@code time} for every object (an object that stores a Lease Time of its own states and
   * is granted that one), and Obtain Lease grants it. Its reply names the object,
   * states that Lease Time and the object's Last Change Date (its Initial Date when it has none).
   * Obtain Lease of an unknown or destroyed object is Item Not Found; {@link #leasesOnlyForActive}
   * refuses the others that are not Active. Zero is stated and granted as zero, which a grant means
   * as no lease limit (keytend-kmip-server's {@code --max-lease-seconds 0} states it too). The server does
   * not enforce leases: Get, Encrypt and the other operations do not ask for one, since using an
   * object only within its lease is the client's obligation. Null, the default, states no Lease
   * Time, and Obtain Lease answers Operation Not Supported.
   *
   * @param time the Lease Time, in whole seconds, at most 2^32 - 1 (a KMIP Interval); null for none
   * @return this server
   * @throws IllegalArgumentException when {@code time} is negative, has a fraction of a second or is too long
   * @since 0.10.0
   */
  public InMemoryKmipServer leaseTime(Duration time) {
    if (time != null
        && (time.isNegative() || time.getNano() != 0 || time.getSeconds() > 0xffff_ffffL))
      throw new IllegalArgumentException(
          "Lease Time must be whole seconds from 0 to 2^32 - 1: " + time);
    synchronized (lock) {
      store.leaseTime = time;
      return this;
    }
  }

  /**
   * With {@link #leaseTime} set, whether Obtain Lease refuses an object that is not Active, as
   * keytend-kmip-server does under {@code --lease-states active} (its default also leases
   * Deactivated objects), and as other servers do: here with Permission Denied (on every version)
   * and the Result Message "Only active objects may receive a lease" (keytend-kmip-server's
   * messages name the state). Off by default, when every object that is not destroyed is
   * leased. Applies to this server and its replicas. A refusal is an ordinary server answer, not a
   * {@link #violations() violation}.
   *
   * @param only whether only Active objects are leased
   * @return this server
   * @since 0.10.0
   */
  public InMemoryKmipServer leasesOnlyForActive(boolean only) {
    synchronized (lock) {
      store.leasesOnlyForActive = only;
      return this;
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Transport and inspection API

  /** {@link #exchange(Ttlv, CallContext)} without a deadline. */
  @Override
  public Ttlv exchange(Ttlv request) throws IOException {
    return exchange(request, CallContext.NONE);
  }

  /**
   * Processes one request message. Requests to this server and its replicas are processed one at a
   * time; a {@link Fault#HANG} or {@link Fault#SLOW} waits after taking its request off the lock,
   * so other clients and replicas go on meanwhile. Fails with {@link SocketTimeoutException} when
   * {@code context}'s deadline passes during such a wait, and with {@link InterruptedIOException}
   * when the context is canceled or the thread interrupted, as the TLS transport does.
   */
  @Override
  public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
    return exchange(request, context, null);
  }

  /** {@link #exchange(Ttlv, CallContext)} on a TLS connection, for {@link TlsListener}. */
  Ttlv exchange(Ttlv request, CallContext context, Channel on) throws IOException {
    context.check();
    if (unreachable)
      throw new RequestNotSentException(
          "Unreachable (InMemoryKmipServer.unreachable)",
          new ConnectException("Connection refused"));
    Ttlv response;
    Duration delay;
    synchronized (lock) {
      exchanges++;
      requests.add(request);
      if (before != null) {
        IOException fault = before.apply(request);
        if (fault != null) {
          before = null;
          throw fault;
        }
      }
      Armed chosen = select(request);
      if (chosen != null && chosen.fault == Fault.UNREACHABLE) {
        armed.remove(chosen);
        throw new RequestNotSentException(
            "Injected fault UNREACHABLE", new ConnectException("Connection refused"));
      }
      if (chosen != null && chosen.fault == Fault.HANG) {
        armed.remove(chosen);
        response = null;
        delay = HANG_LIMIT;
      } else {
        try {
          selected = chosen != null && chosen.reason() != null ? chosen : null;
          channel = on;
          datesPassed();
          response = respond(request);
        } finally {
          selected = null;
          channel = null;
        }
        // The mock holds itself to the response payload tables the client enforces.
        // (Negotiation legitimately answers another version's header at the server's own version.)
        try {
          Response parsed = Messages.response(response);
          if (parsed.version() == Messages.version(request.require(REQUEST_HEADER)))
            Messages.correlate(request, parsed);
        } catch (IOException | RuntimeException e) {
          violations.add("nonconformant response: " + e.getMessage());
        }
        if (chosen != null && chosen.fault == Fault.REPLY_LOST) {
          armed.remove(chosen);
          throw new SocketTimeoutException("Read timed out (injected fault REPLY_LOST)");
        }
        if (chosen != null && chosen.fault == Fault.MALFORMED_REPLY) {
          armed.remove(chosen);
          return withoutResultStatus(response);
        }
        if (after != null) {
          IOException fault = after.apply(request);
          if (fault != null) {
            after = null;
            throw fault;
          }
        }
        delay = null;
        if (chosen != null && chosen.fault == Fault.SLOW) {
          armed.remove(chosen);
          delay = slowReplyDelay;
        }
      }
    }
    if (delay == null) return response;
    // Waits without the lock: a hung or slow request does not stop the other replicas' traffic.
    boolean waited = hold(context, delay);
    if (response == null || !waited)
      throw new SocketTimeoutException(
          waited
              ? "Read timed out (injected fault HANG: no reply in " + HANG_LIMIT.toSeconds() + " s)"
              : "KMIP exchange deadline exceeded");
    return response;
  }

  /**
   * Waits for {@code delay} or until {@code context}'s deadline, whichever is first.
   *
   * @return true when the delay ended first (or at the same time), false when the deadline did
   * @throws InterruptedIOException the context was canceled or the thread interrupted (the
   *     interrupt flag is kept)
   */
  private static boolean hold(CallContext context, Duration delay) throws IOException {
    long until = System.nanoTime() + delay.toNanos();
    long end = context.deadlineBefore(until);
    CountDownLatch canceled = new CountDownLatch(1);
    try (Closeable cancellation = context.onCancel(canceled::countDown)) {
      for (long left; (left = end - System.nanoTime()) > 0; )
        if (canceled.await(left, TimeUnit.NANOSECONDS))
          throw new InterruptedIOException("KMIP call canceled");
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new InterruptedIOException("KMIP exchange interrupted");
    }
    if (context.isCancelled()) throw new InterruptedIOException("KMIP call canceled");
    if (Thread.currentThread().isInterrupted())
      throw new InterruptedIOException("KMIP exchange interrupted");
    return end == until;
  }

  /**
   * How long a {@link Fault#SLOW} reply is held after its request is processed (default 1 second),
   * unless the exchange's deadline comes first. Tests can rely on the bounds: the hold is measured
   * with {@code System.nanoTime()} from the end of processing.
   *
   * @param delay the hold, not negative
   * @return this server
   * @throws IllegalArgumentException if {@code delay} is negative or longer than 60 seconds (the
   *     limit of a {@link Fault#HANG} without a deadline)
   */
  public InMemoryKmipServer slowReplyDelay(Duration delay) {
    Objects.requireNonNull(delay, "delay");
    if (delay.isNegative()) throw new IllegalArgumentException("Negative delay " + delay);
    if (delay.compareTo(HANG_LIMIT) > 0)
      throw new IllegalArgumentException(
          "A slow reply delay of "
              + delay
              + " exceeds the "
              + HANG_LIMIT.toSeconds()
              + " s limit; use Fault.HANG for a server that never answers");
    synchronized (lock) {
      slowReplyDelay = delay;
      return this;
    }
  }

  /**
   * With {@link #uniqueNames} on, makes destroyed objects keep holding their names: no other object
   * may take them, ever. Locate still passes destroyed objects over (unless it filters by State), so
   * a client cannot see who holds such a name, as on servers that keep the names of destroyed
   * objects and refuse changes to them (keytend-kmip-server on KMIP 2.x and the 3.0 draft). Off by default.
   * Applies to this server and its replicas.
   *
   * @param keep whether destroyed objects keep their names
   * @return this server
   * @since 0.10.0
   */
  public InMemoryKmipServer destroyedObjectsKeepNames(boolean keep) {
    synchronized (lock) {
      store.destroyedKeepNames = keep;
      return this;
    }
  }

  /**
   * Makes this server (not its replicas) unreachable, or reachable again: while it is, every
   * exchange fails as {@link Fault#UNREACHABLE} does (connection refused, nothing processed, not
   * counted in {@link #exchanges()}), until it is switched back. For tests of what an application
   * does while the KMS, or one replica, is down.
   *
   * @param unreachable whether the server is unreachable
   * @return this server
   * @since 0.10.0
   */
  public InMemoryKmipServer unreachable(boolean unreachable) {
    this.unreachable = unreachable;
    return this;
  }

  /**
   * Makes the next request for {@code operation} fail with {@code fault}, once; see {@link Fault}
   * for what each one sends and the exception the application then sees. Each call arms one more
   * fault: arming the same fault three times fails three matching requests (for example every
   * attempt of a read the SDK retries). Requests that do not match are processed normally, and the
   * request after the failed one is too.
   *
   * <p>Two faults have no Result Reason in early versions: {@link Fault#ALREADY_EXISTS} (none
   * before 1.4) and {@link Fault#SERVER_BUSY} (none before 2.0). On a server that speaks no
   * version able to express the fault, arming it throws. On a server that speaks both kinds of
   * version, the version the request uses decides: a request in a version that cannot express the
   * fault gets the closest equivalent (Illegal Operation; General Failure), and the substitution is
   * recorded in {@link #violations()}.
   *
   * <p>At most one armed fault fires per request message: the first armed (in arming order) whose
   * {@link ServerOperation} matches an item of the message. A fault that answers with a Result
   * Reason fails the first matching item before it is processed. The rest of a batch follows the
   * Batch Error Continuation Option. A transport fault applies to the whole message. A fault stays
   * armed until a request it matches reaches it, and {@link #injectBeforeProcessing} runs first.
   * Faults are armed per server: one armed on a {@link #replica()} fires only for requests that
   * replica receives. {@link Fault#HANG} waits for the exchange's {@link CallContext} deadline or
   * cancellation, so test it with a short call timeout. {@link Fault#SLOW} holds the reply for
   * {@link #slowReplyDelay} and times out only if the deadline comes first.
   *
   * @param operation the operation to fail, or {@link ServerOperation#ANY}
   * @param fault how it fails
   * @throws IllegalArgumentException if no version this server speaks can express {@code fault}
   */
  public void failNext(ServerOperation operation, Fault fault) {
    synchronized (lock) {
      Objects.requireNonNull(operation, "operation");
      Objects.requireNonNull(fault, "fault");
      if (supported.stream().allMatch(fault::inexpressible))
        throw new IllegalArgumentException(
            "Fault "
                + fault
                + " cannot be produced by a server that speaks only KMIP "
                + supported
                + ": "
                + fault.reason().wireName()
                + " exists from KMIP "
                + fault.reason().since()
                + "; arm Fault."
                + fault.nearest()
                + " instead");
      armed.add(new Armed(operation, fault, null));
    }
  }

  /**
   * Protocol-level hook: makes the next request for {@code operation} fail with Result Reason
   * {@code reason}, once, before it is processed. A reason the request's version does not define
   * is mapped to its 1.x equivalent, as the server's own failures are (see <a
   * href="https://github.com/keytend/keytend-kmip-java/blob/v0.10.0-rc.1/docs/in-memory-server.md#result-reasons-on-kmip-1x">
   * Result reasons on KMIP 1.x</a>). Other reasons are sent as given. Prefer {@link
   * #failNext(ServerOperation, Fault)}, whose outcome is documented.
   *
   * @param operation the operation to fail, or {@link ServerOperation#ANY}
   * @param reason the Result Reason to fail it with
   */
  public void failNext(ServerOperation operation, ResultReason reason) {
    synchronized (lock) {
      armed.add(
          new Armed(
              Objects.requireNonNull(operation, "operation"),
              null,
              Objects.requireNonNull(reason, "reason")));
    }
  }

  /**
   * Protocol-level hook: arms a fault checked before each request message is processed. When
   * {@code fault} returns an exception it is thrown instead of processing (nothing changes) and the
   * hook is disarmed; while it returns null the hook stays armed, so it can wait for a particular
   * request.
   *
   * @param fault the hook: given each request message, returns the exception to throw, or null to
   *     process it; null disarms the hook
   */
  public void injectBeforeProcessing(Function<Ttlv, IOException> fault) {
    synchronized (lock) {
      before = fault;
    }
  }

  /**
   * Protocol-level hook: arms a fault checked after each request message is processed. When
   * {@code fault} returns an exception, the request has taken effect but the exception is thrown
   * instead of the response (a reply lost after a mutation) and the hook is disarmed; while it
   * returns null it stays armed.
   *
   * @param fault the hook: given each request message, returns the exception to throw instead of
   *     the response, or null to send it; null disarms the hook
   */
  public void injectAfterProcessing(Function<Ttlv, IOException> fault) {
    synchronized (lock) {
      after = fault;
    }
  }

  /** The first armed fault, in arming order, that matches an item of {@code request}. */
  private Armed select(Ttlv request) {
    if (armed.isEmpty()) return null;
    List<Operation> ops = new ArrayList<>();
    try {
      for (Ttlv item : request.children(BATCH_ITEM))
        item.child(OPERATION)
            .flatMap(o -> WireEnums.fromCode(Operation.class, o.intValue()))
            .ifPresent(ops::add);
    } catch (RuntimeException notAMessage) {
      return null;
    }
    for (Armed a : armed) for (Operation op : ops) if (a.operation.matches(op)) return a;
    return null;
  }

  /** Fires the selected Result Reason fault on the first item it matches. */
  private void injected(Operation op) throws Fail {
    if (selected == null || !selected.operation.matches(op)) return;
    Armed a = selected;
    selected = null;
    armed.remove(a);
    if (a.fault == null)
      throw new Fail(a.protocolReason, "Injected fault " + a.protocolReason.wireName());
    if (a.fault.inexpressible(v)) {
      violations.add(
          v
              + " "
              + op.wireName()
              + ": injected fault "
              + a.fault
              + " cannot be expressed in KMIP "
              + v
              + " (no "
              + a.fault.reason().wireName()
              + "); answered "
              + a.fault.fallback().wireName());
      throw new Fail(a.fault.fallback(), "Injected fault " + a.fault);
    }
    throw new Fail(a.fault.reason(), "Injected fault " + a.fault);
  }

  /** {@code response} with no Result Status in its batch items: a reply the SDK must reject. */
  private static Ttlv withoutResultStatus(Ttlv response) {
    List<Ttlv> fields = new ArrayList<>();
    for (Ttlv f : response.children())
      fields.add(
          f.tag() == BATCH_ITEM.code()
              ? structure(
                  BATCH_ITEM.code(),
                  f.children().stream().filter(c -> c.tag() != RESULT_STATUS.code()).toList())
              : f);
    return structure(response.tag(), fields);
  }

  /**
   * Counts the call and changes nothing else: the server keeps its objects and keeps answering, so
   * several clients can share it and it can be connected to again.
   */
  @Override
  public void close() {
    synchronized (lock) {
      closed++;
    }
  }

  /**
   * Whether {@link #close()}, the {@link KmipTransport} close, was called at least once. A {@link
   * Kms} connected with {@link #configure()} or {@link #connect()} opens this server as the
   * transport of its one endpoint and calls it exactly once: when the {@code Kms} is closed (again
   * does nothing, and closing a {@link Kms#withTimeout} view does not close it), or when {@link
   * Kms#connect} fails. It does not mean the server stopped (see {@link #close()}), and with
   * several clients it means only that one of them closed: count with {@link #closeCount()}.
   *
   * @return whether the transport was closed
   */
  public boolean closed() {
    synchronized (lock) {
      return closed > 0;
    }
  }

  /**
   * How many times {@link #close()} was called: with only {@code Kms} clients from {@link
   * #configure()}, the number of them that were closed or failed to connect.
   *
   * @return the number of closes
   */
  public int closeCount() {
    synchronized (lock) {
      return closed;
    }
  }

  /**
   * Protocol-level hook: every request message received, in arrival order, including faulted and
   * rejected ones.
   *
   * @return the request messages, a copy
   */
  public List<Ttlv> protocolRequests() {
    synchronized (lock) {
      return List.copyOf(requests);
    }
  }

  /**
   * The number of {@code exchange} calls.
   *
   * @return the number of exchanges
   */
  public int exchanges() {
    synchronized (lock) {
      return exchanges;
    }
  }

  /**
   * Descriptions of the problems the server found in the requests it received, in arrival order.
   * Tests of well-formed traffic should assert that this list is empty.
   *
   * <p>Every request is checked with {@link VersionValidator}, and with shape rules the validator
   * cannot express:
   *
   * <ul>
   *   <li>1.x payloads carry {@code Attribute} and {@code TemplateAttribute} fields with canonical
   *       1.x attribute names ("Cryptographic Algorithm", "x-Custom").
   *   <li>2.x and 3.0 payloads carry {@code Attributes}, {@code NewAttribute}, {@code
   *       CurrentAttribute} and {@code AttributeReference}, and no top-level 1.x {@code Attribute}
   *       or {@code AttributeName}.
   *   <li>3.0 has no Batch Count or Unique Batch Item ID. Its identifiers are Identifier or
   *       Reference typed, and Name is a Text String.
   *   <li>Batch Count matches the items. Unique Batch Item IDs are present and distinct when there
   *       is more than one item.
   *   <li>Required fields and attributes are present. Create needs Cryptographic Algorithm, Length
   *       and Usage Mask. Certificate Register needs Cryptographic Algorithm, Cryptographic Length,
   *       Certificate Length and Cryptographic Usage Mask.
   * </ul>
   *
   * <p>A violation fails that item with Invalid Message, Invalid Field or Missing Data. Ordinary
   * server outcomes (unknown object, wrong state, missing usage, cryptographic failure,
   * unsupported feature) are failures but not violations. The list also records a fault that the
   * request's version cannot express ({@link #failNext(ServerOperation, Fault)}), a bad identifier
   * from {@link #identifierSource}, and a response of the server's own that breaks the response
   * tables.
   *
   * @return the descriptions, a copy
   */
  public List<String> violations() {
    synchronized (lock) {
      return List.copyOf(violations);
    }
  }

  /**
   * Protocol-level hook: the versions this server speaks, highest first.
   *
   * @return the versions, unmodifiable
   */
  public List<ProtocolVersion> protocolVersions() {
    return supported;
  }

  /**
   * Every object identifier ever created or registered, in creation order.
   *
   * @return the identifiers, a copy
   */
  public List<String> ids() {
    synchronized (lock) {
      return List.copyOf(objects.keySet());
    }
  }

  /**
   * Whether {@code id} names an object that has not been destroyed.
   *
   * @param id the object identifier
   * @return whether the object exists and is not destroyed
   */
  public boolean exists(String id) {
    synchronized (lock) {
      Obj o = objects.get(id);
      return o != null && !o.destroyed();
    }
  }

  /**
   * The object's state (also Destroyed / Destroyed Compromised); empty for an unknown id.
   *
   * @param id the object identifier
   * @return the state; empty for an unknown id
   */
  public Optional<KeyState> state(String id) {
    synchronized (lock) {
      datesPassed();
      return Optional.ofNullable(objects.get(id))
          .map(o -> wire(KeyState.values(), KeyState::protocolValue, o.state(), KeyState.UNKNOWN));
    }
  }

  /**
   * Protocol-level hook: the object's KMIP State; empty for an unknown id.
   *
   * @param id the object identifier
   * @return the KMIP State; empty for an unknown id
   */
  public Optional<State> protocolState(String id) {
    synchronized (lock) {
      datesPassed();
      return Optional.ofNullable(objects.get(id)).map(Obj::state);
    }
  }

  /**
   * The kind of object {@code id} is; empty for an unknown id.
   *
   * @param id the object identifier
   * @return the kind; empty for an unknown id
   */
  public Optional<ObjectKind> kind(String id) {
    synchronized (lock) {
      return Optional.ofNullable(objects.get(id))
          .map(o -> wire(ObjectKind.values(), ObjectKind::protocolValue, o.type, ObjectKind.OTHER));
    }
  }

  /**
   * The usages in the object's Cryptographic Usage Mask (other bits are left out); empty for an
   * unknown id or an object without a mask.
   *
   * @param id the object identifier
   * @return the usages, unmodifiable
   */
  public Set<KeyUsage> usages(String id) {
    synchronized (lock) {
      Obj o = objects.get(id);
      EnumSet<KeyUsage> out = EnumSet.noneOf(KeyUsage.class);
      if (o != null)
        for (KeyUsage u : KeyUsage.values())
          if ((o.usage() & u.protocolValue().code()) != 0) out.add(u);
      return Collections.unmodifiableSet(out);
    }
  }

  /**
   * The object's Name values in order; empty for an unknown id.
   *
   * @param id the object identifier
   * @return the names, a copy
   */
  public List<String> names(String id) {
    synchronized (lock) {
      Obj o = objects.get(id);
      if (o == null) return List.of();
      return o.values(NAME).stream().map(n -> n.require(NAME_VALUE).textValue()).toList();
    }
  }

  /**
   * The identifiers the object links to with links of {@code kind}, in order ({@link
   * LinkKind#OTHER}: links of any type without a {@code LinkKind}); empty for an unknown id.
   *
   * @param id the object identifier
   * @param kind the link kind
   * @return the linked identifiers, a copy
   */
  public List<String> links(String id, LinkKind kind) {
    synchronized (lock) {
      Objects.requireNonNull(kind, "kind");
      Obj o = objects.get(id);
      if (o == null) return List.of();
      return o.values(LINK).stream()
          .filter(l -> linkKind(l.require(LINK_TYPE).intValue()) == kind)
          .map(l -> l.require(LINKED_OBJECT_IDENTIFIER).textValue())
          .toList();
    }
  }

  /**
   * Protocol-level hook: the first linked object of KMIP Link Type {@code type}.
   *
   * @param id the object identifier
   * @param type the KMIP Link Type
   * @return the linked identifier; empty for an unknown id or no such link
   */
  public Optional<String> protocolLink(String id, LinkType type) {
    synchronized (lock) {
      Obj o = objects.get(id);
      if (o == null) return Optional.empty();
      return o.values(LINK).stream()
          .filter(l -> l.require(LINK_TYPE).intValue() == type.code())
          .map(l -> l.require(LINKED_OBJECT_IDENTIFIER).textValue())
          .findFirst();
    }
  }

  private static LinkKind linkKind(int code) {
    for (LinkKind k : LinkKind.values())
      if (k.protocolValue() != null && k.protocolValue().code() == code) return k;
    return LinkKind.OTHER;
  }

  /** The application value whose protocol value is {@code value}, else {@code otherwise}. */
  private static <A, P> A wire(A[] values, Function<A, P> protocol, P value, A otherwise) {
    for (A a : values) if (value != null && value.equals(protocol.apply(a))) return a;
    return otherwise;
  }

  /**
   * Whether the object still holds key material, a certificate or secret data.
   *
   * @param id the object identifier
   * @return whether the object holds material; false for an unknown id
   */
  public boolean hasMaterial(String id) {
    synchronized (lock) {
      Obj o = objects.get(id);
      return o != null
          && (o.secret != null || o.privateKey != null || o.publicKey != null || o.der != null);
    }
  }

  /**
   * Protocol-level hook: the stored attributes of {@code id} keyed by 1.x attribute name
   * ("Cryptographic Algorithm", "Name", "x-Owner"), in the version-neutral internal form: standard
   * values tagged with the attribute's own tag (Name a {@code Name} structure, links {@code Link}
   * structures, identifiers Text Strings), custom/vendor values tagged {@code AttributeValue}.
   * Empty for an unknown id.
   *
   * @param id the object identifier
   * @return the attributes, unmodifiable
   */
  public Map<String, List<Ttlv>> protocolAttributes(String id) {
    synchronized (lock) {
      datesPassed();
      Obj o = objects.get(id);
      Map<String, List<Ttlv>> out = new LinkedHashMap<>();
      if (o != null) o.attrs.forEach((k, values) -> out.put(k.legacyName(), List.copyOf(values)));
      return Collections.unmodifiableMap(out);
    }
  }

  // ---------------------------------------------------------------------------------------------
  // Message handling

  private Ttlv respond(Ttlv request) {
    Ttlv header = null;
    ProtocolVersion version = null;
    if (request.tag() == REQUEST_MESSAGE.code() && request.type() == Ttlv.Type.STRUCTURE) {
      header = request.child(REQUEST_HEADER).orElse(null);
      try {
        if (header != null) version = Messages.version(header);
      } catch (RuntimeException unknownVersion) {
        version = null;
      }
    }
    if (header == null) {
      violations.add("Not a RequestMessage with a RequestHeader: " + request.tagName());
      return messageFailure(supported.get(0), ResultReason.INVALID_MESSAGE, "Malformed message");
    }
    if (version == null || !supported.contains(version)) {
      ProtocolVersion highest = supported.get(0);
      return messageFailure(
          highest,
          highest.legacyAttributes()
              ? ResultReason.INVALID_MESSAGE
              : ResultReason.UNSUPPORTED_PROTOCOL_VERSION,
          "Unsupported protocol version");
    }
    v = version;
    placeholder = null;
    reProvisionTried = false;
    replacement = null;
    List<Ttlv> items = request.children(BATCH_ITEM);
    messageHeader = header;
    messageItems = items;
    String problem = headerProblem(header, items);
    if (problem != null) {
      violations.add(v + " RequestHeader: " + problem);
      return messageFailure(v, ResultReason.INVALID_MESSAGE, problem);
    }
    if (unknownCriticalExtension(items))
      return messageFailure(
          v,
          v.atLeast(ProtocolVersion.V2_0)
              ? ResultReason.UNKNOWN_MESSAGE_EXTENSION
              : ResultReason.FEATURE_NOT_SUPPORTED,
          "Unknown critical message extension");
    int continuation = header.child(BATCH_ERROR_CONTINUATION_OPTION).map(Ttlv::intValue).orElse(2);
    Map<String, Obj> snapshot = new LinkedHashMap<>();
    int snapshotId = store.nextId;
    if (continuation == 3) for (Obj o : objects.values()) snapshot.put(o.id, o.copy());
    List<Ttlv> out = new ArrayList<>();
    boolean delivered = false;
    itemIndex = 0;
    for (Ttlv item : items) {
      Ttlv result = item(item);
      itemIndex++;
      if (replacement != null
          && result.require(RESULT_STATUS).intValue() == 0
          && item.child(OPERATION).map(Ttlv::intValue).orElse(0) == Operation.GET.code()
          && result
              .child(RESPONSE_PAYLOAD)
              .flatMap(r -> r.child(UNIQUE_IDENTIFIER))
              .map(Ttlv::textValue)
              .filter(replacement.id()::equals)
              .isPresent()) delivered = true;
      boolean failed = result.require(RESULT_STATUS).intValue() == 1;
      if (failed && continuation == 3) {
        objects.clear();
        objects.putAll(snapshot);
        store.nextId = snapshotId;
        out.replaceAll(InMemoryKmipServer::undone);
      }
      out.add(result);
      if (failed && continuation != 1) break;
    }
    Replacement made = replacement;
    replacement = null;
    if (made != null) {
      if (!delivered) {
        // keytend-kmip-server: nothing commits unless the message delivers the new certificate.
        objects.remove(made.id());
        return messageFailure(
            v,
            ResultReason.INVALID_FIELD,
            "Re-Provision must be followed by a successful Get of the ID Placeholder");
      }
      // Only a committed renewal uses up its keys: one rolled back may be sent again.
      store.retired.put(fingerprint(made.replaced()), made.replaced());
      store.usedKeys.add(made.newKey());
      store.usedKeys.add(HexFormat.of().formatHex(made.replaced().getPublicKey().getEncoded()));
    }
    return response(v, out);
  }

  /** Whether {@code certificate} was retired by a Re-Provision ({@link TlsListener}). */
  boolean retired(X509Certificate certificate) {
    synchronized (lock) {
      return store.retired.containsKey(fingerprint(certificate));
    }
  }

  /** The certificates retired by Re-Provision, in order. */
  List<X509Certificate> retiredCertificates() {
    synchronized (lock) {
      return List.copyOf(store.retired.values());
    }
  }

  /**
   * The answer of a connection whose certificate was retired, to its first request, as
   * keytend-kmip-server gives it (its unlisted path): Permission Denied for each item, as an item
   * failure that names the item's operation, under the message's Batch Error Continuation Option
   * (Continue answers every item; Stop and Undo end at the first). The listener then closes the
   * connection. A message it cannot read gets a message-level failure.
   */
  Ttlv refuseRetired(Ttlv request) {
    synchronized (lock) {
      ProtocolVersion version;
      Ttlv header = request.child(REQUEST_HEADER).orElse(null);
      try {
        version = header == null ? null : Messages.version(header);
      } catch (RuntimeException e) {
        version = null;
      }
      List<Ttlv> items = request.children(BATCH_ITEM);
      if (version == null || !supported.contains(version) || items.isEmpty())
        return messageFailure(
            version != null && supported.contains(version) ? version : supported.get(0),
            ResultReason.INVALID_MESSAGE,
            "Malformed message");
      int continuation =
          header.child(BATCH_ERROR_CONTINUATION_OPTION).map(Ttlv::intValue).orElse(2);
      List<Ttlv> out = new ArrayList<>();
      for (Ttlv item : items) {
        List<Ttlv> fields = new ArrayList<>();
        item.child(OPERATION).ifPresent(fields::add);
        item.child(UNIQUE_BATCH_ITEM_ID).ifPresent(fields::add);
        fields.add(enumeration(RESULT_STATUS, 1));
        fields.add(enumeration(RESULT_REASON, ResultReason.PERMISSION_DENIED));
        fields.add(text(RESULT_MESSAGE, "Operation denied by certificate policy"));
        out.add(structure(BATCH_ITEM, fields));
        if (continuation != 1) break;
      }
      return response(version, out);
    }
  }

  private static String fingerprint(X509Certificate c) {
    try {
      return HexFormat.of()
          .formatHex(java.security.MessageDigest.getInstance("SHA-256").digest(c.getEncoded()));
    } catch (GeneralSecurityException e) {
      throw new IllegalStateException(e);
    }
  }

  private String headerProblem(Ttlv header, List<Ttlv> items) {
    try {
      VersionValidator.validate(v, header);
      if (items.isEmpty()) return "no BatchItem";
      if (v != V3_0) {
        Optional<Ttlv> count = header.child(BATCH_COUNT);
        if (count.isEmpty()) return "missing BatchCount";
        if (count.get().intValue() != items.size())
          return "BatchCount " + count.get().intValue() + " but " + items.size() + " items";
        if (items.size() > 1) {
          Set<String> ids = new HashSet<>();
          for (Ttlv item : items) {
            Optional<Ttlv> id = item.child(UNIQUE_BATCH_ITEM_ID);
            if (id.isEmpty()) return "UniqueBatchItemID is required when BatchCount > 1";
            if (!ids.add(HexFormat.of().formatHex(id.get().bytesValue())))
              return "duplicate UniqueBatchItemID";
          }
        }
      }
      if (items.size() == 1 && header.child(BATCH_ERROR_CONTINUATION_OPTION).isPresent())
        return "BatchErrorContinuationOption is only allowed when BatchCount > 1";
      return null;
    } catch (RuntimeException e) {
      return e.getMessage();
    }
  }

  /**
   * Whether an item carries a Critical Message Extension this server does not understand, which
   * rejects the whole message before anything runs (KMIP 2.1 section 9.13), as keytend-kmip-server
   * does. The only one it understands is its own on a Re-Provision item ({@link
   * #requestedNotAfter}); on any other operation that one is not read either.
   */
  private static boolean unknownCriticalExtension(List<Ttlv> items) {
    for (Ttlv item : items) {
      boolean reProvision =
          item.child(OPERATION).map(Ttlv::intValue).orElse(0) == Operation.RE_PROVISION.code();
      for (Ttlv extension : item.children(MESSAGE_EXTENSION)) {
        boolean critical =
            extension
                .child(CRITICALITY_INDICATOR)
                .filter(c -> c.type() == Ttlv.Type.BOOLEAN)
                .map(Ttlv::booleanValue)
                .orElse(false);
        if (critical && !(reProvision && ours(extension))) return true;
      }
    }
    return false;
  }

  /** keytend-kmip-server's message for Certify, Re-certify and Re-Provision under Undo. */
  private static final String UNDO_REFUSED =
      "Certify, Re-certify and Re-Provision are not supported in Undo batches";

  /** Whether this message's Batch Error Continuation Option is Undo. */
  private boolean undoBatch() {
    return messageHeader.child(BATCH_ERROR_CONTINUATION_OPTION).map(Ttlv::intValue).orElse(2) == 3;
  }

  /** The Vendor Identification of keytend-kmip-server's Message Extension. */
  static final String EXTENSION_VENDOR = "keytend_kmip_server";

  private static boolean ours(Ttlv extension) {
    return extension
        .child(VENDOR_IDENTIFICATION)
        .filter(n -> n.type() == Ttlv.Type.TEXT_STRING)
        .map(Ttlv::textValue)
        .filter(EXTENSION_VENDOR::equals)
        .isPresent();
  }

  /**
   * The notAfter a Re-Provision item asks for, as keytend-kmip-server reads it: its
   * Message Extension (Vendor Identification {@value #EXTENSION_VENDOR}, Critical or not) whose
   * Vendor Extension holds exactly one Deactivation Date. Null without one; Invalid Field for two,
   * or for a Vendor Extension that holds anything else.
   */
  private static Instant requestedNotAfter(Ttlv item) throws Fail {
    Instant found = null;
    for (Ttlv extension : item.children(MESSAGE_EXTENSION)) {
      if (!ours(extension)) continue;
      List<Ttlv> fields =
          extension
              .child(VENDOR_EXTENSION)
              .filter(n -> n.type() == Ttlv.Type.STRUCTURE)
              .map(Ttlv::children)
              .orElse(List.of());
      if (found != null
          || fields.size() != 1
          || fields.get(0).tag() != DEACTIVATION_DATE.code()
          || fields.get(0).type() != Ttlv.Type.DATE_TIME)
        throw new Fail(
            ResultReason.INVALID_FIELD,
            "The keytend_kmip_server Message Extension holds one Deactivation Date");
      found = fields.get(0).instantValue();
    }
    return found;
  }

  private Ttlv item(Ttlv item) {
    List<Ttlv> fields = new ArrayList<>();
    String label = "BatchItem";
    try {
      Optional<Ttlv> op = item.child(OPERATION);
      op.ifPresent(fields::add);
      item.child(UNIQUE_BATCH_ITEM_ID).ifPresent(fields::add);
      if (op.isPresent())
        label =
            WireEnums.fromCode(Operation.class, op.get().intValue())
                .map(Operation::wireName)
                .orElse(String.format("0x%08X", op.get().intValue()));
      List<Ttlv> payload = process(item);
      fields.add(enumeration(RESULT_STATUS, 0));
      fields.add(structure(RESPONSE_PAYLOAD, payload));
      updatePlaceholder(payload);
    } catch (Fail f) {
      if (f.violation) violations.add(v + " " + label + ": " + f.getMessage());
      fields.add(enumeration(RESULT_STATUS, 1));
      fields.add(enumeration(RESULT_REASON, reasonCode(f.reason)));
      fields.add(text(RESULT_MESSAGE, Objects.toString(f.getMessage(), f.reason.wireName())));
    } catch (IllegalArgumentException | IllegalStateException e) {
      // A required field is missing or has the wrong type.
      violations.add(v + " " + label + ": malformed request: " + e.getMessage());
      fields.add(enumeration(RESULT_STATUS, 1));
      fields.add(enumeration(RESULT_REASON, ResultReason.INVALID_MESSAGE));
      fields.add(text(RESULT_MESSAGE, "Malformed request: " + e.getMessage()));
    }
    return structure(BATCH_ITEM, fields);
  }

  private List<Ttlv> process(Ttlv item) throws Fail {
    Ttlv opField =
        item.child(OPERATION)
            .orElseThrow(
                () -> violation(ResultReason.INVALID_MESSAGE, "BatchItem without Operation"));
    try {
      VersionValidator.validate(v, item);
    } catch (IllegalArgumentException e) {
      throw violation(ResultReason.INVALID_MESSAGE, e.getMessage());
    }
    Operation op =
        WireEnums.fromCode(Operation.class, opField.intValue())
            .orElseThrow(
                () -> new Fail(ResultReason.OPERATION_NOT_SUPPORTED, "Unknown operation code"));
    if (!v.atLeast(op.since()))
      throw violation(
          ResultReason.OPERATION_NOT_SUPPORTED, op.wireName() + " requires KMIP " + op.since());
    Ttlv p =
        item.child(REQUEST_PAYLOAD)
            .orElseThrow(() -> violation(ResultReason.INVALID_MESSAGE, "no RequestPayload"));
    checkShape(op, p);
    if (reProvisionTried
        && op != Operation.GET
        && op != Operation.GET_ATTRIBUTES
        && op != Operation.GET_ATTRIBUTE_LIST)
      throw new Fail(
          ResultReason.PERMISSION_DENIED,
          op == Operation.RE_PROVISION
              ? "Only one Re-Provision may run in a message"
              : "Only Get, Get Attributes and Get Attribute List may follow a Re-Provision in its"
                  + " message");
    injected(op);
    return switch (op) {
      case DISCOVER_VERSIONS -> discoverVersions(p);
      case QUERY -> query(p);
      case CREATE -> create(p);
      case CREATE_KEY_PAIR -> createKeyPair(p);
      case REGISTER -> register(p);
      case RE_KEY -> reKey(p);
      case LOCATE -> locate(p);
      case GET -> get(p);
      case GET_ATTRIBUTES -> getAttributes(p);
      case GET_ATTRIBUTE_LIST -> getAttributeList(p);
      case ADD_ATTRIBUTE -> addAttribute(p);
      case MODIFY_ATTRIBUTE -> modifyAttribute(p);
      case SET_ATTRIBUTE -> setAttribute(p);
      case DELETE_ATTRIBUTE -> deleteAttribute(p);
      case ACTIVATE -> activate(p);
      case REVOKE -> revoke(p);
      case DEACTIVATE -> deactivate(p);
      case DESTROY -> destroy(p);
      case ENCRYPT -> cipher(p, true);
      case DECRYPT -> cipher(p, false);
      case SIGN -> sign(p);
      case SIGNATURE_VERIFY -> verify(p);
      case MAC -> mac(p, false);
      case MAC_VERIFY -> mac(p, true);
      case RNG_RETRIEVE -> rngRetrieve(p);
      case OBTAIN_LEASE -> obtainLease(p);
      case RE_PROVISION -> reProvision(p);
      case CERTIFY -> certify(p);
      default ->
          throw new Fail(
              ResultReason.OPERATION_NOT_SUPPORTED, op.wireName() + " is not implemented");
    };
  }

  /** Shape rules {@link VersionValidator} cannot express (it rejects tags a version lacks). */
  private void checkShape(Operation op, Ttlv p) throws Fail {
    if (v.legacyAttributes()) return;
    if (ATTRIBUTE_CARRIERS.contains(op)) {
      if (!p.children(ATTRIBUTE).isEmpty())
        throw violation(
            ResultReason.INVALID_FIELD,
            "top-level 1.x Attribute in a " + v + " " + op.wireName() + " payload");
      if (!p.children(ATTRIBUTE_NAME).isEmpty())
        throw violation(
            ResultReason.INVALID_FIELD,
            "1.x AttributeName in a " + v + " " + op.wireName() + " payload");
    }
    if (v == V3_0) {
      String text = textIdentifier(p);
      if (text != null)
        throw violation(
            ResultReason.INVALID_FIELD,
            text + " must be an Identifier or Reference in KMIP 3.0, not a Text String");
    }
  }

  private static String textIdentifier(Ttlv n) {
    if (n.type() == Ttlv.Type.STRUCTURE) {
      for (Ttlv c : n.children()) {
        String found = textIdentifier(c);
        if (found != null) return found;
      }
      return null;
    }
    return ID_TAGS.contains(n.tag()) && n.type() == Ttlv.Type.TEXT_STRING ? n.tagName() : null;
  }

  private void updatePlaceholder(List<Ttlv> payload) {
    for (Tag t : List.of(PRIVATE_KEY_UNIQUE_IDENTIFIER, UNIQUE_IDENTIFIER))
      for (Ttlv f : payload)
        if (f.tag() == t.code()) {
          placeholder = f.textValue();
          return;
        }
  }

  private int reasonCode(ResultReason r) {
    if (v.atLeast(r.since())) return r.code();
    ResultReason legacy =
        switch (r) {
          case WRONG_KEY_LIFECYCLE_STATE, ATTRIBUTE_SINGLE_VALUED, MULTI_VALUED_ATTRIBUTE ->
              ResultReason.ILLEGAL_OPERATION;
          case INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK,
              ATTRIBUTE_READ_ONLY,
              READ_ONLY_ATTRIBUTE,
              SENSITIVE,
              NOT_EXTRACTABLE ->
              ResultReason.PERMISSION_DENIED;
          case ATTRIBUTE_NOT_FOUND,
              ATTRIBUTE_INSTANCE_NOT_FOUND,
              OBJECT_NOT_FOUND,
              OBJECT_DESTROYED,
              WRAPPING_OBJECT_NOT_FOUND ->
              ResultReason.ITEM_NOT_FOUND;
          case MISSING_INITIALIZATION_VECTOR -> ResultReason.MISSING_DATA;
          case UNSUPPORTED_PROTOCOL_VERSION -> ResultReason.INVALID_MESSAGE;
          case ILLEGAL_OBJECT_TYPE,
              INVALID_OBJECT_TYPE,
              BAD_CRYPTOGRAPHIC_PARAMETERS,
              UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS,
              INVALID_ATTRIBUTE,
              INVALID_ATTRIBUTE_VALUE ->
              ResultReason.INVALID_FIELD;
          default -> ResultReason.GENERAL_FAILURE;
        };
    return legacy.code();
  }

  private static Ttlv undone(Ttlv item) {
    List<Ttlv> fields = new ArrayList<>();
    item.child(OPERATION).ifPresent(fields::add);
    item.child(UNIQUE_BATCH_ITEM_ID).ifPresent(fields::add);
    fields.add(enumeration(RESULT_STATUS, 3));
    return structure(BATCH_ITEM, fields);
  }

  private Ttlv messageFailure(ProtocolVersion version, ResultReason reason, String why) {
    return response(
        version,
        List.of(
            structure(
                BATCH_ITEM,
                enumeration(RESULT_STATUS, 1),
                enumeration(RESULT_REASON, reason),
                text(RESULT_MESSAGE, why))));
  }

  private Ttlv response(ProtocolVersion version, List<Ttlv> items) {
    List<Ttlv> header = new ArrayList<>();
    header.add(Messages.protocolVersion(version));
    header.add(dateTime(TIME_STAMP, now()));
    if (version != V3_0) header.add(integer(BATCH_COUNT, items.size()));
    List<Ttlv> fields = new ArrayList<>();
    fields.add(structure(RESPONSE_HEADER, header));
    fields.addAll(items);
    Ttlv message = structure(RESPONSE_MESSAGE, fields);
    if (version == V3_0) message = identifiers(message);
    try {
      VersionValidator.validate(version, message);
    } catch (IllegalArgumentException e) {
      throw new IllegalStateException(
          "InMemoryKmipServer built an invalid " + version + " response: " + e.getMessage(), e);
    }
    return message;
  }

  /** KMIP 3.0 responses name objects with Identifier-typed values. */
  private static Ttlv identifiers(Ttlv n) {
    if (n.type() == Ttlv.Type.STRUCTURE)
      return structure(
          n.tag(), n.children().stream().map(InMemoryKmipServer::identifiers).toList());
    if (ID_TAGS.contains(n.tag())
        && (n.type() == Ttlv.Type.TEXT_STRING || n.type() == Ttlv.Type.REFERENCE))
      return Ttlv.of(n.tag(), Ttlv.Type.IDENTIFIER, n.textValue());
    return n;
  }

  // ---------------------------------------------------------------------------------------------
  // Attributes: parsing and rendering

  private Attr parse(Ttlv a) throws Fail {
    if (a.tag() == ATTRIBUTE.code()) {
      Optional<Ttlv> vendor = a.child(VENDOR_IDENTIFICATION);
      String name = a.require(ATTRIBUTE_NAME).textValue();
      Ttlv value = a.require(ATTRIBUTE_VALUE);
      if (v.legacyAttributes()) {
        if (vendor.isPresent())
          throw violation(ResultReason.INVALID_FIELD, "VendorIdentification in a 1.x Attribute");
        AttrKey key = legacyKey(name);
        return new Attr(key, plain(key.tag() == null ? value : value.retag(key.tag())));
      }
      if (vendor.isEmpty())
        throw violation(
            ResultReason.INVALID_FIELD, "1.x Attribute '" + name + "' in a " + v + " payload");
      return new Attr(new AttrKey(null, vendor.get().textValue(), name), plain(value));
    }
    if (v.legacyAttributes())
      throw violation(ResultReason.INVALID_FIELD, a.tagName() + " where 1.x needs an Attribute");
    Tag tag =
        a.standardTag()
            .orElseThrow(
                () -> violation(ResultReason.INVALID_FIELD, "unknown attribute " + a.tagName()));
    if (v == V3_0) {
      if (tag == NAME) {
        if (a.type() != Ttlv.Type.TEXT_STRING)
          throw violation(ResultReason.INVALID_FIELD, "KMIP 3.0 Name is a Text String");
        return new Attr(AttrKey.std(NAME), name(a.textValue()));
      }
      Integer linkType = linkType(tag);
      if (linkType != null) {
        // An identifier: a Reference in 3.0, as keytend-kmip-server and the Unique Identifier rule
        // above.
        if (a.type() != Ttlv.Type.REFERENCE)
          throw violation(
              ResultReason.INVALID_FIELD,
              a.tagName() + " must be a Reference in KMIP 3.0, not a " + a.type());
        return new Attr(AttrKey.std(LINK), link(linkType, a.textValue()));
      }
    } else if (tag == NAME && a.type() != Ttlv.Type.STRUCTURE)
      throw violation(ResultReason.INVALID_FIELD, "KMIP " + v + " Name is a structure");
    return new Attr(AttrKey.std(tag), plain(a));
  }

  /** The attribute named by a 1.x Attribute Name: standard (exact spec name) or x-/y- custom. */
  private static AttrKey legacyKey(String name) throws Fail {
    if (name.length() > 2 && (name.startsWith("x-") || name.startsWith("y-")))
      return new AttrKey(null, name.substring(0, 1), name.substring(2));
    Tag tag;
    try {
      tag = Tag.fromName(name);
    } catch (IllegalArgumentException e) {
      throw violation(ResultReason.INVALID_FIELD, "unknown 1.x attribute name '" + name + "'");
    }
    if (!spaced(tag).equals(name) && tag.wireName().chars().allMatch(Character::isLetter))
      throw violation(
          ResultReason.INVALID_FIELD,
          "1.x attribute name '" + name + "' should be '" + spaced(tag) + "'");
    return AttrKey.std(tag);
  }

  /** The value of a single-child NewAttribute/CurrentAttribute. */
  private static Ttlv single(Ttlv wrapper) throws Fail {
    if (wrapper.children().size() != 1)
      throw violation(ResultReason.INVALID_FIELD, wrapper.tagName() + " needs one attribute");
    return wrapper.children().get(0);
  }

  /** Every attribute of a template-family (1.x) or Attributes-family (2.x/3.0) payload field. */
  private List<Attr> attributes(Ttlv p, Tag legacy, Tag modern) throws Fail {
    List<Attr> out = new ArrayList<>();
    for (Ttlv holder : p.children(v.legacyAttributes() ? legacy : modern)) {
      if (!holder.children(NAME).isEmpty() && v.legacyAttributes())
        throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, "Template references are unsupported");
      for (Ttlv a : holder.children()) out.add(parse(a));
    }
    return out;
  }

  /** Applies client-supplied attributes at creation time. */
  private static void apply(Obj o, List<Attr> attrs) throws Fail {
    for (Attr a : attrs) {
      if (a.key().tag() != null && SERVER_ONLY.contains(a.key().tag()))
        throw new Fail(
            ResultReason.ATTRIBUTE_READ_ONLY, a.key().legacyName() + " is set by the server");
      if (!a.key().multi()) o.attrs.put(a.key(), new ArrayList<>(List.of(a.value())));
      else if (!o.attrs.getOrDefault(a.key(), List.of()).contains(a.value()))
        o.add(a.key(), a.value());
    }
  }

  private static void writable(AttrKey key) throws Fail {
    if (key.tag() != null && READ_ONLY.contains(key.tag()))
      throw new Fail(ResultReason.ATTRIBUTE_READ_ONLY, key.legacyName() + " is read-only");
  }

  /** A client may not delete a Deactivation Date (KMIP 1.4 Table 114: "Deletable by client: No"). */
  private static void deletable(AttrKey key) throws Fail {
    if (key.tag() == DEACTIVATION_DATE)
      throw new Fail(ResultReason.ATTRIBUTE_READ_ONLY, "A Deactivation Date cannot be deleted");
  }

  /**
   * A client may add or change a Deactivation Date only while the object is Pre-Active or Active
   * (KMIP 1.4 §3.27 and Table 114, 2.1 §4.18: "only while in Pre-Active or Active state"): Wrong Key
   * Lifecycle State otherwise (Illegal Operation in 1.x). {@link #refuseClientDeactivationDate}
   * refuses it always, as some servers do.
   */
  private void datable(Obj o, AttrKey key) throws Fail {
    if (key.tag() != DEACTIVATION_DATE) return;
    if (store.refuseClientDeactivationDate)
      throw new Fail(ResultReason.ATTRIBUTE_READ_ONLY, "Deactivation Date is read-only");
    if (o.state() != State.PRE_ACTIVE && o.state() != State.ACTIVE)
      throw new Fail(
          ResultReason.WRONG_KEY_LIFECYCLE_STATE,
          "The Deactivation Date of a " + o.state() + " object cannot be changed");
  }

  /**
   * Refuses a second link of a type {@code o} may have once ({@link #linkCardinality}), as
   * keytend-kmip-server's {@code validate_link_cardinality}: Replacement Object Link on every version, and
   * in 3.0 every type but Certificate, Derivation Base Object and Derived Key Link.
   */
  private void singleLink(Obj o, Ttlv link) throws Fail {
    if (!store.linkCardinality) return;
    int type = link.require(LINK_TYPE).intValue();
    boolean single =
        type == LinkType.REPLACEMENT_OBJECT_LINK.code()
            || (v == V3_0
                && type != LinkType.CERTIFICATE_LINK.code()
                && type != LinkType.DERIVATION_BASE_OBJECT_LINK.code()
                && type != LinkType.DERIVED_KEY_LINK.code());
    if (!single) return;
    for (Ttlv l : o.values(LINK))
      if (l.require(LINK_TYPE).intValue() == type)
        throw new Fail(
            v.legacyAttributes()
                ? ResultReason.INVALID_FIELD
                : ResultReason.ATTRIBUTE_SINGLE_VALUED,
            "Link attribute is single valued");
  }

  /** One stored value in this version's wire form, or null when the version cannot express it. */
  private Ttlv render(AttrKey key, Ttlv value, int index) {
    Tag tag = key.tag();
    boolean modernLink = v == V3_0 && tag == LINK;
    if (tag != null && !modernLink && !(v.atLeast(tag.since()) && tag.definedIn(v))) return null;
    Ttlv wire;
    if (v.legacyAttributes())
      wire = Attributes.attribute(key.legacyName(), index == 0 ? null : index, value);
    else if (tag == null) wire = ModernAttributes.vendor(key.vendor(), key.name(), value);
    else if (v == V3_0 && tag == NAME) wire = text(NAME, value.require(NAME_VALUE).textValue());
    else if (modernLink) {
      Tag linkTag = LINK_TAGS.get(value.require(LINK_TYPE).intValue());
      if (linkTag == null) return null;
      wire = reference(linkTag, value.require(LINKED_OBJECT_IDENTIFIER).textValue());
    } else wire = value;
    try {
      VersionValidator.validate(v, wire);
      return wire;
    } catch (IllegalArgumentException e) {
      return null;
    }
  }

  private List<Ttlv> renderAll(Obj o, BiPredicate<AttrKey, Ttlv> select) {
    List<Ttlv> out = new ArrayList<>();
    o.attrs.forEach(
        (key, values) -> {
          for (int i = 0; i < values.size(); i++)
            if (select.test(key, values.get(i))) {
              Ttlv wire = render(key, values.get(i), o.index(key, i));
              if (wire != null) out.add(wire);
            }
        });
    return out;
  }

  /** The attribute an Attribute Reference (2.x/3.0) names. */
  private Ref resolve(Ttlv r) throws Fail {
    if (r.type() == Ttlv.Type.STRUCTURE)
      return new Ref(
          new AttrKey(
              null,
              r.require(VENDOR_IDENTIFICATION).textValue(),
              r.require(ATTRIBUTE_NAME).textValue()),
          null);
    Tag tag =
        Tag.fromCode(r.intValue())
            .orElseThrow(() -> violation(ResultReason.INVALID_FIELD, "unknown AttributeReference"));
    Integer linkType = v == V3_0 ? linkType(tag) : null;
    return linkType != null
        ? new Ref(AttrKey.std(LINK), linkType)
        : new Ref(AttrKey.std(tag), null);
  }

  /** The attributes a Get Attributes request selects; all when it names none. */
  private BiPredicate<AttrKey, Ttlv> selector(Ttlv p) throws Fail {
    List<Ref> wanted = new ArrayList<>();
    if (v.legacyAttributes())
      for (Ttlv n : p.children(ATTRIBUTE_NAME)) wanted.add(new Ref(legacyKey(n.textValue()), null));
    else for (Ttlv r : p.children(ATTRIBUTE_REFERENCE)) wanted.add(resolve(r));
    if (wanted.isEmpty()) return (key, value) -> true;
    return (key, value) -> wanted.stream().anyMatch(r -> r.test(key, value));
  }

  // ---------------------------------------------------------------------------------------------
  // Operations

  private List<Ttlv> discoverVersions(Ttlv p) {
    List<Ttlv> listed = p.children(PROTOCOL_VERSION);
    Set<ProtocolVersion> asked = new HashSet<>();
    for (Ttlv pv : listed)
      try {
        asked.add(
            ProtocolVersion.of(
                pv.require(PROTOCOL_VERSION_MAJOR).intValue(),
                pv.require(PROTOCOL_VERSION_MINOR).intValue()));
      } catch (IllegalArgumentException unknownVersion) {
        // not offered
      }
    return supported.stream()
        .filter(s -> listed.isEmpty() || asked.contains(s))
        .map(Messages::protocolVersion)
        .toList();
  }

  private List<Ttlv> query(Ttlv p) {
    Set<Integer> functions = new HashSet<>();
    for (Ttlv f : p.children(QUERY_FUNCTION)) functions.add(f.intValue());
    List<Ttlv> out = new ArrayList<>();
    if (functions.contains(Enums.QueryFunction.QUERY_OPERATIONS.code()))
      for (Operation op : IMPLEMENTED)
        if (v.atLeast(op.since())) out.add(enumeration(OPERATION, op));
    if (functions.contains(Enums.QueryFunction.QUERY_OPERATIONS.code()) && store.leaseTime != null)
      out.add(enumeration(OPERATION, Operation.OBTAIN_LEASE));
    // Offered on a connection whose listener has a provisioning CA, from 2.0, as
    // keytend-kmip-server.
    if (functions.contains(Enums.QueryFunction.QUERY_OPERATIONS.code())
        && channel != null
        && channel.provisioning != null
        && v.atLeast(Operation.RE_PROVISION.since()))
      out.add(enumeration(OPERATION, Operation.RE_PROVISION));
    if (functions.contains(Enums.QueryFunction.QUERY_OBJECTS.code()))
      for (ObjectType t :
          List.of(
              ObjectType.CERTIFICATE,
              ObjectType.SYMMETRIC_KEY,
              ObjectType.PUBLIC_KEY,
              ObjectType.PRIVATE_KEY,
              ObjectType.SECRET_DATA)) out.add(enumeration(OBJECT_TYPE, t));
    if (functions.contains(Enums.QueryFunction.QUERY_SERVER_INFORMATION.code()))
      out.add(text(VENDOR_IDENTIFICATION, "keytend-kmip InMemoryKmipServer"));
    return out;
  }

  private List<Ttlv> create(Ttlv p) throws Fail {
    if (p.require(OBJECT_TYPE).intValue() != ObjectType.SYMMETRIC_KEY.code())
      throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, "Create supports Symmetric Key only");
    Obj o = newObject(ObjectType.SYMMETRIC_KEY);
    apply(o, attributes(p, TEMPLATE_ATTRIBUTE, ATTRIBUTES));
    unique(o.values(NAME));
    int algorithm = required(o, CRYPTOGRAPHIC_ALGORITHM, "Create");
    int bits = required(o, CRYPTOGRAPHIC_LENGTH, "Create");
    required(o, CRYPTOGRAPHIC_USAGE_MASK, "Create");
    CryptographicAlgorithm alg = CryptographicAlgorithm.fromCode(algorithm).orElse(null);
    if (alg == CryptographicAlgorithm.AES) {
      if (bits != 128 && bits != 192 && bits != 256)
        throw new Fail(ResultReason.INVALID_FIELD, "AES keys are 128, 192 or 256 bits");
    } else if (hmac(alg) != null) {
      if (bits < 8 || bits % 8 != 0)
        throw new Fail(ResultReason.INVALID_FIELD, "HMAC key length must be whole bytes");
    } else
      throw new Fail(ResultReason.INVALID_FIELD, "Create supports AES and HMAC keys, not " + alg);
    o.secret = randomBytes(bits / 8);
    o.format = KeyFormatType.RAW;
    store(o);
    return List.of(
        enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY), text(UNIQUE_IDENTIFIER, o.id));
  }

  private List<Ttlv> createKeyPair(Ttlv p) throws Fail {
    List<Attr> common = attributes(p, COMMON_TEMPLATE_ATTRIBUTE, COMMON_ATTRIBUTES);
    Obj sk = newObject(ObjectType.PRIVATE_KEY), pk = newObject(ObjectType.PUBLIC_KEY);
    apply(sk, common);
    apply(sk, attributes(p, PRIVATE_KEY_TEMPLATE_ATTRIBUTE, PRIVATE_KEY_ATTRIBUTES));
    apply(pk, common);
    apply(pk, attributes(p, PUBLIC_KEY_TEMPLATE_ATTRIBUTE, PUBLIC_KEY_ATTRIBUTES));
    unique(sk.values(NAME));
    unique(pk.values(NAME));
    if (store.uniqueNames)
      for (Ttlv name : pk.values(NAME)) if (named(sk, name)) throw nonUnique(name);
    CryptographicAlgorithm alg =
        CryptographicAlgorithm.fromCode(required(sk, CRYPTOGRAPHIC_ALGORITHM, "Create Key Pair"))
            .orElse(null);
    KeyPair pair;
    try {
      if (alg == CryptographicAlgorithm.RSA) {
        int bits = required(sk, CRYPTOGRAPHIC_LENGTH, "RSA Create Key Pair");
        if (bits < 1024 || bits > 8192)
          throw new Fail(ResultReason.INVALID_FIELD, "Unsupported RSA modulus size " + bits);
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits, random);
        pair = g.generateKeyPair();
      } else if (EC_FAMILY.contains(alg)) {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new ECGenParameterSpec(curveName(sk)), random);
        pair = g.generateKeyPair();
      } else throw new Fail(ResultReason.INVALID_FIELD, "Create Key Pair supports RSA and EC keys");
    } catch (GeneralSecurityException e) {
      throw new Fail(ResultReason.CRYPTOGRAPHIC_FAILURE, e.toString());
    }
    int bits = bits(pair.getPublic());
    for (Obj o : List.of(sk, pk)) {
      if (o.values(CRYPTOGRAPHIC_ALGORITHM).isEmpty())
        o.put(enumeration(CRYPTOGRAPHIC_ALGORITHM, alg));
      if (o.values(CRYPTOGRAPHIC_LENGTH).isEmpty()) o.put(integer(CRYPTOGRAPHIC_LENGTH, bits));
    }
    sk.privateKey = pair.getPrivate();
    sk.format = KeyFormatType.PKCS_8;
    pk.publicKey = pair.getPublic();
    pk.format = KeyFormatType.X_509;
    sk.add(AttrKey.std(LINK), link(LinkType.PUBLIC_KEY_LINK.code(), pk.id));
    pk.add(AttrKey.std(LINK), link(LinkType.PRIVATE_KEY_LINK.code(), sk.id));
    store(sk);
    store(pk);
    return List.of(
        text(PRIVATE_KEY_UNIQUE_IDENTIFIER, sk.id), text(PUBLIC_KEY_UNIQUE_IDENTIFIER, pk.id));
  }

  /**
   * Certify, as keytend-kmip-server does it with a CA the client registered: the request's
   * Certificate link names the CA certificate, whose Public Key link names the CA public key,
   * whose Private Key link names the CA private key. The CA certificate must be an Active CA
   * certificate (basicConstraints cA=TRUE, keyCertSign when it has Key Usage) within its validity;
   * the CA private key Active, with the Certificate Sign usage, and the private half of the
   * certificate's key. The Unique Identifier names a Pre-Active or Active public key, which the
   * PKCS#10 (or PEM) request must hold. The certificate is issued as {@link CertificateIssuance}
   * says, stored with the request's attributes, Pre-Active unless they say otherwise, and linked to
   * the public key and back. The dates asked set its validity as keytend-kmip-server
   * does, unless {@link #certifyHonorsDates} is off: then it is from now for 365 days, capped at
   * the CA's notAfter. This server has no owners, so any CA it holds signs.
   */
  private List<Ttlv> certify(Ttlv p) throws Fail {
    // An undone certificate would still be a valid certificate: keytend-kmip-server refuses
    // Certify under Undo before it issues anything.
    if (undoBatch()) throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, UNDO_REFUSED);
    boolean modern = v.atLeast(ProtocolVersion.V2_0);
    Optional<Ttlv> type = p.child(CERTIFICATE_REQUEST_TYPE);
    Optional<Ttlv> value = p.child(modern ? CERTIFICATE_REQUEST_VALUE : CERTIFICATE_REQUEST);
    if (type.isEmpty() && value.isEmpty())
      throw new Fail(
          ResultReason.FEATURE_NOT_SUPPORTED,
          "Certify without a Certificate Request is not supported");
    if (type.isEmpty() || value.isEmpty())
      throw new Fail(ResultReason.INVALID_FIELD, "Certificate Request Type and value are required");
    int requestType = type.get().intValue();
    ResultReason invalid = modern ? ResultReason.INVALID_CSR : ResultReason.INVALID_FIELD;
    CertificateIssuance.Request request;
    try {
      byte[] der = value.get().bytesValue();
      if (requestType == Enums.CertificateRequestType.PEM.code())
        der = CertificateIssuance.fromPem(der);
      else if (requestType != Enums.CertificateRequestType.PKCS_10.code())
        throw new Fail(
            ResultReason.FEATURE_NOT_SUPPORTED,
            "Only PKCS#10 and PEM certificate requests are supported");
      request = CertificateIssuance.parse(der);
    } catch (CertificateIssuance.Refused r) {
      if (r.curve) throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, r.getMessage());
      throw new Fail(r.names ? ResultReason.INVALID_FIELD : invalid, r.getMessage());
    }
    Obj key = lookup(p, false);
    if (key.type != ObjectType.PUBLIC_KEY)
      throw new Fail(
          modern ? ResultReason.INVALID_OBJECT_TYPE : ResultReason.PERMISSION_DENIED,
          "Object type cannot be certified");
    if (key.state() != State.PRE_ACTIVE && key.state() != State.ACTIVE)
      throw new Fail(
          ResultReason.PERMISSION_DENIED, "Public key state does not permit certification");
    if (!Arrays.equals(key.publicKey.getEncoded(), request.publicKey().getEncoded()))
      throw new Fail(
          ResultReason.INVALID_FIELD, "Certificate Request key does not match the Public Key");
    List<Attr> asked = attributes(p, TEMPLATE_ATTRIBUTE, ATTRIBUTES);
    List<String> issuers = new ArrayList<>();
    for (Attr a : asked)
      if (a.key().tag() == LINK) {
        int linkType = a.value().require(LINK_TYPE).intValue();
        if (linkType == LinkType.CERTIFICATE_LINK.code())
          issuers.add(a.value().require(LINKED_OBJECT_IDENTIFIER).textValue());
        else if (linkType == LinkType.PUBLIC_KEY_LINK.code()
            || linkType == LinkType.PRIVATE_KEY_LINK.code()
            || linkType == LinkType.REPLACEMENT_OBJECT_LINK.code()
            || linkType == LinkType.REPLACED_OBJECT_LINK.code())
          throw new Fail(
              ResultReason.INVALID_FIELD,
              "Certificate key and replacement links are assigned by the server");
      }
    if (issuers.isEmpty())
      throw new Fail(
          ResultReason.PERMISSION_DENIED,
          "Certify requires a Certificate Link to a caller-owned issuing CA certificate");
    if (issuers.size() > 1)
      throw new Fail(
          ResultReason.INVALID_FIELD, "Only one issuing CA certificate may be designated");
    Instant now = now();
    Obj ca = objects.get(issuers.get(0));
    if (ca == null || ca.destroyed()) throw new Fail(ResultReason.ITEM_NOT_FOUND, "No issuer");
    if (ca.type != ObjectType.CERTIFICATE || ca.der == null)
      throw new Fail(ResultReason.PERMISSION_DENIED, "Issuer must be an X.509 certificate");
    if (ca.state() != State.ACTIVE)
      throw new Fail(ResultReason.PERMISSION_DENIED, "Issuer certificate is not Active");
    Obj caPublic =
        linked(ca, LinkType.PUBLIC_KEY_LINK, "Issuer certificate has no Public Key Link");
    Obj caPrivate =
        linked(caPublic, LinkType.PRIVATE_KEY_LINK, "Issuer public key has no Private Key Link");
    if (caPublic.type != ObjectType.PUBLIC_KEY || caPrivate.type != ObjectType.PRIVATE_KEY)
      throw new Fail(ResultReason.PERMISSION_DENIED, "Issuer key links do not form a key pair");
    if (caPrivate.state() != State.ACTIVE
        || (caPrivate.usage() & CryptographicUsageMask.CERTIFICATE_SIGN.code()) == 0)
      throw new Fail(
          ResultReason.PERMISSION_DENIED,
          "The issuer private key must be Active and permit Certificate Sign");
    X509Certificate caCertificate;
    try {
      caCertificate =
          (X509Certificate)
              CertificateFactory.getInstance("X.509")
                  .generateCertificate(new ByteArrayInputStream(ca.der));
      boolean[] caUsage = caCertificate.getKeyUsage();
      caCertificate.checkValidity(java.util.Date.from(now));
      if (caCertificate.getBasicConstraints() < 0
          || (caUsage != null && (caUsage.length <= 5 || !caUsage[5]))
          || !matches(caPrivate.privateKey, caCertificate.getPublicKey()))
        throw new GeneralSecurityException("not a CA that may sign");
    } catch (GeneralSecurityException e) {
      throw new Fail(ResultReason.PERMISSION_DENIED, "Issuer cannot sign certificates now");
    }
    PublicKey subjectKey = key.publicKey;
    if (!CertificateIssuance.supportedKey(subjectKey, request.publicKeyInfo()))
      throw new Fail(
          ResultReason.FEATURE_NOT_SUPPORTED, "Subject key must be RSA-2048+ or EC P-256/384/521");
    int usage = key.usage();
    for (Attr a : asked)
      if (a.key().tag() == CRYPTOGRAPHIC_USAGE_MASK) usage = a.value().intValue();
    if ((usage
            & (CryptographicUsageMask.CERTIFICATE_SIGN.code()
                | CryptographicUsageMask.CRL_SIGN.code()))
        != 0)
      throw new Fail(ResultReason.PERMISSION_DENIED, "Only end-entity certificates are issued");
    if (request.emptySubject() && request.altNames() == null)
      throw new Fail(ResultReason.INVALID_FIELD, "An empty subject requires alternative names");
    Instant caEnd = caCertificate.getNotAfter().toInstant();
    Instant notBefore = now, notAfter = now.plus(Duration.ofDays(365));
    if (store.certifyHonorsDates) {
      // keytend-kmip-server: the Activation Date is the notBefore and the Deactivation
      // Date the notAfter; without a Deactivation Date, 365 days from the notBefore, cut short at
      // the CA's notAfter. A requested date past the CA's notAfter is refused, never cut short.
      Instant activation = null, deactivation = null;
      for (Attr a : asked) {
        if (a.key().tag() == ACTIVATION_DATE) activation = a.value().instantValue();
        if (a.key().tag() == DEACTIVATION_DATE) deactivation = a.value().instantValue();
      }
      if ((activation != null && !activation.isBefore(caEnd))
          || (deactivation != null && deactivation.isAfter(caEnd)))
        throw new Fail(
            ResultReason.INVALID_FIELD,
            "The requested validity ends after the issuing CA's notAfter");
      if (activation != null) notBefore = activation;
      if (deactivation != null && !deactivation.isAfter(notBefore))
        throw new Fail(
            ResultReason.INVALID_FIELD,
            "The Deactivation Date (notAfter) must be later than the Activation Date (notBefore)");
      notAfter = deactivation != null ? deactivation : notBefore.plus(Duration.ofDays(365));
      if (notAfter.isAfter(caEnd)) notAfter = caEnd;
      if (!notAfter.isAfter(notBefore))
        throw new Fail(ResultReason.PERMISSION_DENIED, "Issuer cannot sign certificates now");
    } else if (notAfter.isAfter(caEnd)) notAfter = caEnd;
    int keyUsage = 0;
    int[] byBit = {0x1 | 0x2, 0x400, 0x10 | 0x20, 0x4 | 0x8, 0x800, 0x1000, 0x2000};
    for (int bit = 0; bit < byBit.length; bit++)
      if ((usage & byBit[bit]) != 0) keyUsage |= 1 << bit;
    byte[] der;
    try {
      der =
          CertificateIssuance.issue(
              request, caCertificate, caPrivate.privateKey, notBefore, notAfter, keyUsage, random);
    } catch (GeneralSecurityException e) {
      throw new Fail(ResultReason.CRYPTOGRAPHIC_FAILURE, "Certificate issuance failed");
    }
    Obj o = newObject(ObjectType.CERTIFICATE);
    List<Attr> kept = new ArrayList<>();
    for (Attr a : asked)
      if (a.key().tag() != CRYPTOGRAPHIC_ALGORITHM
          && a.key().tag() != CRYPTOGRAPHIC_LENGTH
          && a.key().tag() != CRYPTOGRAPHIC_USAGE_MASK
          && a.key().tag() != CERTIFICATE_LENGTH
          && a.key().tag() != CERTIFICATE_TYPE) kept.add(a);
    apply(o, kept);
    unique(o.values(NAME));
    o.der = der;
    o.publicKey = subjectKey;
    o.put(enumeration(CERTIFICATE_TYPE, Enums.CertificateType.X_509));
    o.put(integer(CERTIFICATE_LENGTH, der.length));
    key.first(CRYPTOGRAPHIC_ALGORITHM).ifPresent(o::put);
    o.put(integer(CRYPTOGRAPHIC_LENGTH, bits(subjectKey)));
    o.put(integer(CRYPTOGRAPHIC_USAGE_MASK, usage));
    o.add(AttrKey.std(LINK), link(LinkType.PUBLIC_KEY_LINK.code(), key.id));
    stateFromDates(o);
    store(o);
    key.add(AttrKey.std(LINK), link(LinkType.CERTIFICATE_LINK.code(), o.id));
    return List.of(text(UNIQUE_IDENTIFIER, o.id));
  }

  /** The one object {@code o}'s link of {@code type} names; Permission Denied otherwise. */
  private Obj linked(Obj o, LinkType type, String none) throws Fail {
    List<String> ids = new ArrayList<>();
    for (Ttlv l : o.values(LINK))
      if (l.require(LINK_TYPE).intValue() == type.code())
        ids.add(l.require(LINKED_OBJECT_IDENTIFIER).textValue());
    if (ids.isEmpty()) throw new Fail(ResultReason.PERMISSION_DENIED, none);
    if (ids.size() > 1)
      throw new Fail(ResultReason.PERMISSION_DENIED, "Issuer key links are ambiguous");
    Obj target = objects.get(ids.get(0));
    if (target == null || target.destroyed())
      throw new Fail(ResultReason.ITEM_NOT_FOUND, "No object " + ids.get(0));
    return target;
  }

  /** Whether {@code key} is the private half of {@code certified}: it signs, the other verifies. */
  private static boolean matches(PrivateKey key, PublicKey certified) {
    if (key == null) return false;
    try {
      String name = "RSA".equals(key.getAlgorithm()) ? "SHA256withRSA" : "SHA256withECDSA";
      byte[] probe = "keytend-kmip in-memory issuer check".getBytes(StandardCharsets.US_ASCII);
      Signature s = Signature.getInstance(name);
      s.initSign(key);
      s.update(probe);
      byte[] signature = s.sign();
      Signature check = Signature.getInstance(name);
      check.initVerify(certified);
      check.update(probe);
      return check.verify(signature);
    } catch (GeneralSecurityException e) {
      return false;
    }
  }

  private static String curveName(Obj o) throws Fail {
    Optional<Integer> curve =
        o.first(CRYPTOGRAPHIC_DOMAIN_PARAMETERS)
            .flatMap(d -> d.child(RECOMMENDED_CURVE))
            .map(Ttlv::intValue);
    int bits =
        curve.isPresent()
            ? curve.get() == Enums.RecommendedCurve.P_256.code()
                ? 256
                : curve.get() == Enums.RecommendedCurve.P_384.code()
                    ? 384
                    : curve.get() == Enums.RecommendedCurve.P_521.code() ? 521 : -1
            : o.intAttr(CRYPTOGRAPHIC_LENGTH, 0);
    return switch (bits) {
      case 256 -> "secp256r1";
      case 384 -> "secp384r1";
      case 521 -> "secp521r1";
      case 0 ->
          throw violation(
              ResultReason.MISSING_DATA,
              "EC Create Key Pair needs Cryptographic Domain Parameters or Cryptographic Length");
      default ->
          throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, "Supported curves: P-256/384/521");
    };
  }

  private List<Ttlv> register(Ttlv p) throws Fail {
    ObjectType type =
        ObjectType.fromCode(p.require(OBJECT_TYPE).intValue())
            .orElseThrow(() -> new Fail(ResultReason.FEATURE_NOT_SUPPORTED, "Unknown object type"));
    Tag objectTag =
        switch (type) {
          case SYMMETRIC_KEY -> SYMMETRIC_KEY;
          case PRIVATE_KEY -> PRIVATE_KEY;
          case PUBLIC_KEY -> PUBLIC_KEY;
          case CERTIFICATE -> CERTIFICATE;
          case SECRET_DATA -> SECRET_DATA;
          default -> throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, "Cannot register " + type);
        };
    Ttlv object =
        p.child(objectTag)
            .orElseThrow(
                () ->
                    violation(
                        ResultReason.MISSING_DATA,
                        "Register of " + type.wireName() + " has no " + objectTag.wireName()));
    Obj o = newObject(type);
    apply(o, attributes(p, TEMPLATE_ATTRIBUTE, ATTRIBUTES));
    unique(o.values(NAME));
    switch (type) {
      case SYMMETRIC_KEY -> {
        Ttlv block = object.require(KEY_BLOCK);
        Ttlv material = keyValue(block).require(KEY_MATERIAL);
        o.format = format(block);
        if (o.format == KeyFormatType.RAW) o.secret = material.bytesValue();
        else if (o.format == KeyFormatType.TRANSPARENT_SYMMETRIC_KEY)
          o.secret = material.require(KEY).bytesValue();
        else throw new Fail(ResultReason.KEY_FORMAT_TYPE_NOT_SUPPORTED, "Symmetric key format");
        metadata(o, block, o.secret.length * 8);
        if (o.values(CRYPTOGRAPHIC_ALGORITHM).isEmpty())
          throw violation(ResultReason.MISSING_DATA, "symmetric key without an algorithm");
      }
      case PRIVATE_KEY, PUBLIC_KEY -> registerAsymmetric(o, object, type == ObjectType.PRIVATE_KEY);
      case CERTIFICATE -> registerCertificate(o, object);
      default -> {
        o.secretDataType = object.require(SECRET_DATA_TYPE).intValue();
        Ttlv block = object.require(KEY_BLOCK);
        o.format = format(block);
        if (o.format != KeyFormatType.RAW && o.format != KeyFormatType.OPAQUE)
          throw new Fail(ResultReason.KEY_FORMAT_TYPE_NOT_SUPPORTED, "Secret data format");
        o.secret = keyValue(block).require(KEY_MATERIAL).bytesValue();
        metadata(o, block, 0);
      }
    }
    store(o);
    return List.of(text(UNIQUE_IDENTIFIER, o.id));
  }

  private void registerAsymmetric(Obj o, Ttlv object, boolean isPrivate) throws Fail {
    Ttlv block = object.require(KEY_BLOCK);
    keyValue(block);
    KeyFormatType format = format(block);
    if (!(isPrivate ? PRIVATE_FORMATS : PUBLIC_FORMATS).contains(format))
      throw new Fail(ResultReason.KEY_FORMAT_TYPE_NOT_SUPPORTED, "Unsupported format " + format);
    int code =
        block
            .child(CRYPTOGRAPHIC_ALGORITHM)
            .map(Ttlv::intValue)
            .orElse(o.intAttr(CRYPTOGRAPHIC_ALGORITHM, 0));
    if (code == 0) throw violation(ResultReason.MISSING_DATA, "key without an algorithm");
    CryptographicAlgorithm alg =
        CryptographicAlgorithm.fromCode(code)
            .filter(a -> a == CryptographicAlgorithm.RSA || EC_FAMILY.contains(a))
            .orElseThrow(
                () -> new Fail(ResultReason.FEATURE_NOT_SUPPORTED, "RSA and EC keys only"));
    // Keys converts a Get-shaped payload whose key block names the algorithm.
    List<Ttlv> fields = new ArrayList<>(block.children());
    if (block.child(CRYPTOGRAPHIC_ALGORITHM).isEmpty())
      fields.add(enumeration(CRYPTOGRAPHIC_ALGORITHM, alg));
    Ttlv payload =
        structure(
            RESPONSE_PAYLOAD,
            enumeration(OBJECT_TYPE, o.type),
            text(UNIQUE_IDENTIFIER, o.id),
            structure(object.tag(), List.of(structure(KEY_BLOCK, fields))));
    try {
      if (isPrivate) o.privateKey = Keys.privateKey(payload, o.id, alg, 0);
      else o.publicKey = Keys.publicKey(payload, o.id, alg, 0);
    } catch (GeneralSecurityException e) {
      throw violation(ResultReason.INVALID_FIELD, "malformed key material: " + e.getMessage());
    }
    o.format = format == KeyFormatType.ECPRIVATE_KEY ? KeyFormatType.PKCS_8 : format;
    if (o.values(CRYPTOGRAPHIC_ALGORITHM).isEmpty())
      o.put(enumeration(CRYPTOGRAPHIC_ALGORITHM, alg));
    metadata(o, block, bits(isPrivate ? o.privateKey : o.publicKey));
  }

  private void registerCertificate(Obj o, Ttlv object) throws Fail {
    for (Tag t :
        List.of(
            CRYPTOGRAPHIC_ALGORITHM,
            CRYPTOGRAPHIC_LENGTH,
            CERTIFICATE_LENGTH,
            CRYPTOGRAPHIC_USAGE_MASK))
      if (o.values(t).isEmpty())
        throw violation(ResultReason.MISSING_DATA, "Certificate Register requires " + spaced(t));
    if (object.require(CERTIFICATE_TYPE).intValue() != Enums.CertificateType.X_509.code())
      throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, "X.509 certificates only");
    byte[] der = object.require(CERTIFICATE_VALUE).bytesValue();
    if (o.intAttr(CERTIFICATE_LENGTH, -1) != der.length)
      throw violation(ResultReason.INVALID_FIELD, "Certificate Length does not match the DER");
    try {
      X509Certificate cert =
          (X509Certificate)
              CertificateFactory.getInstance("X.509")
                  .generateCertificate(new ByteArrayInputStream(der));
      o.publicKey = cert.getPublicKey();
      boolean[] keyUsage = cert.getKeyUsage();
      if (!v.atLeast(ProtocolVersion.V2_0)
          && keyUsage != null
          && (o.usage() & KEY_USAGE_GOVERNED & ~keyUsageMask(keyUsage)) != 0)
        throw new Fail(
            ResultReason.INVALID_FIELD,
            "Cryptographic Usage Mask conflicts with the certificate Key Usage");
    } catch (GeneralSecurityException e) {
      throw violation(ResultReason.INVALID_FIELD, "malformed certificate: " + e.getMessage());
    }
    o.der = der;
    o.put(enumeration(CERTIFICATE_TYPE, Enums.CertificateType.X_509));
  }

  /** The Cryptographic Usage Mask bits KMIP 1.x's mapping of X.509 Key Usage speaks about. */
  private static final int KEY_USAGE_GOVERNED = 0x3c3f;

  /**
   * The Cryptographic Usage Mask an X.509 Key Usage extension permits (KMIP 1.0 §3.14, 1.1 to 1.4
   * §3.19, 1.4 Table 96; bit n is RFC 5280's named bit n; an "X or Y" row permits both).
   */
  private static int keyUsageMask(boolean[] keyUsage) {
    int[] byBit = {0x1 | 0x2, 0x400, 0x10 | 0x20, 0x4 | 0x8, 0x800, 0x1000, 0x2000, 0x4, 0x8};
    int mask = 0;
    for (int bit = 0; bit < byBit.length && bit < keyUsage.length; bit++)
      if (keyUsage[bit]) mask |= byBit[bit];
    return mask;
  }

  /** The Key Value of an unwrapped key block. */
  private static Ttlv keyValue(Ttlv block) throws Fail {
    Ttlv value = block.require(KEY_VALUE);
    if (value.type() != Ttlv.Type.STRUCTURE || block.child(KEY_WRAPPING_DATA).isPresent())
      throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, "Registering wrapped keys is unsupported");
    return value;
  }

  private static KeyFormatType format(Ttlv block) throws Fail {
    return KeyFormatType.fromCode(block.require(KEY_FORMAT_TYPE).intValue())
        .orElseThrow(() -> new Fail(ResultReason.KEY_FORMAT_TYPE_NOT_SUPPORTED, "Unknown format"));
  }

  /** Records the key block's algorithm and length unless the client gave them as attributes. */
  private static void metadata(Obj o, Ttlv block, int bits) {
    if (o.values(CRYPTOGRAPHIC_ALGORITHM).isEmpty())
      block.child(CRYPTOGRAPHIC_ALGORITHM).ifPresent(o::put);
    if (o.values(CRYPTOGRAPHIC_LENGTH).isEmpty()) {
      Optional<Ttlv> length = block.child(CRYPTOGRAPHIC_LENGTH);
      if (length.isPresent()) o.put(length.get());
      else if (bits > 0) o.put(integer(CRYPTOGRAPHIC_LENGTH, bits));
    }
  }

  private List<Ttlv> reKey(Ttlv p) throws Fail {
    Obj old = lookup(p, false);
    if (old.type != ObjectType.SYMMETRIC_KEY)
      throw new Fail(ResultReason.ILLEGAL_OBJECT_TYPE, "Re-Key supports symmetric keys only");
    if (store.refuseSecondReKey)
      for (Ttlv l : old.values(LINK))
        if (l.require(LINK_TYPE).intValue() == LinkType.REPLACEMENT_OBJECT_LINK.code())
          throw new Fail(
              ResultReason.PERMISSION_DENIED,
              "already replaced by " + l.require(LINKED_OBJECT_IDENTIFIER).textValue());
    Optional<Long> offset = p.child(OFFSET).map(Ttlv::longValue);
    boolean freshDates = store.freshDatesOnReKey;
    Set<Tag> fresh =
        union(
            SERVER_ONLY,
            freshDates || offset.isPresent() ? union(DATES, Set.of(LINK)) : Set.of(LINK));
    Obj n = newObject(ObjectType.SYMMETRIC_KEY);
    old.attrs.forEach(
        (k, values) -> {
          if (k.tag() == null || !fresh.contains(k.tag())) n.attrs.put(k, new ArrayList<>(values));
        });
    if (offset.isPresent() && !freshDates) shiftDates(old, n, offset.get());
    apply(n, attributes(p, TEMPLATE_ATTRIBUTE, ATTRIBUTES));
    // The old key's names move to the replacement: only another object's name conflicts.
    unique(n.values(NAME), old.id);
    old.attrs.remove(AttrKey.std(NAME));
    n.secret = randomBytes(old.secret.length);
    n.format = old.format;
    if (freshDates) {
      if (old.state() == State.ACTIVE) activateNow(n);
    } else stateFromDates(n);
    old.add(AttrKey.std(LINK), link(LinkType.REPLACEMENT_OBJECT_LINK.code(), n.id));
    n.add(AttrKey.std(LINK), link(LinkType.REPLACED_OBJECT_LINK.code(), old.id));
    store(n);
    return List.of(text(UNIQUE_IDENTIFIER, n.id));
  }

  /**
   * A Re-key with an Offset (KMIP 1.4 §4.4, 2.1 §6.1.46): the replacement is activated Offset
   * seconds after its Initial Date (IT2), and the old key's other dates move by as much as its
   * Activation Date did (DT2 = DT1 + (AT2 - AT1)). An old key with other dates and no Activation
   * Date cannot be shifted: Wrong Key Lifecycle State (Illegal Operation in 1.x, as keytend-kmip-server
   * answers).
   */
  private void shiftDates(Obj old, Obj n, long offset) throws Fail {
    Optional<Ttlv> was = old.first(ACTIVATION_DATE);
    try {
      Instant activation = now().plusSeconds(offset);
      for (Tag t : List.of(PROCESS_START_DATE, PROTECT_STOP_DATE, DEACTIVATION_DATE)) {
        Optional<Ttlv> date = old.first(t);
        if (date.isEmpty()) continue;
        if (was.isEmpty())
          throw new Fail(
              ResultReason.WRONG_KEY_LIFECYCLE_STATE,
              "Re-Key with an Offset: the key has a "
                  + spaced(t)
                  + " and no Activation Date to shift it by");
        Duration shift = Duration.between(was.get().instantValue(), activation);
        n.put(dateTime(t, date.get().instantValue().plus(shift)));
      }
      n.put(dateTime(ACTIVATION_DATE, activation));
    } catch (java.time.DateTimeException | ArithmeticException tooFar) {
      throw violation(
          ResultReason.INVALID_FIELD, "Offset " + offset + " moves a date out of range");
    }
  }

  /**
   * The State a new object's dates give it (KMIP 1.4 Table 21): Active from its Activation Date,
   * Deactivated from its Deactivation Date, otherwise Pre-Active.
   */
  private void stateFromDates(Obj o) {
    Instant now = now();
    Optional<Ttlv> activation = o.first(ACTIVATION_DATE), deactivation = o.first(DEACTIVATION_DATE);
    if (deactivation.isPresent() && !deactivation.get().instantValue().isAfter(now))
      o.put(enumeration(STATE, State.DEACTIVATED));
    else if (activation.isPresent() && !activation.get().instantValue().isAfter(now))
      o.put(enumeration(STATE, State.ACTIVE));
  }

  private List<Ttlv> locate(Ttlv p) throws Fail {
    List<Attr> filters = new ArrayList<>();
    if (v.legacyAttributes()) for (Ttlv a : p.children(ATTRIBUTE)) filters.add(parse(a));
    else for (Ttlv s : p.children(ATTRIBUTES)) for (Ttlv a : s.children()) filters.add(parse(a));
    Integer max = p.child(MAXIMUM_ITEMS).map(Ttlv::intValue).orElse(null);
    int offset = p.child(OFFSET_ITEMS).map(Ttlv::intValue).orElse(0);
    boolean byState = filters.stream().anyMatch(f -> f.key().tag() == STATE);
    List<String> found =
        objects.values().stream()
            .filter(o -> byState || !o.destroyed())
            .filter(o -> matches(o, filters))
            .map(o -> o.id)
            .toList();
    List<Ttlv> out = new ArrayList<>();
    if ((max != null || p.child(OFFSET_ITEMS).isPresent()) && v.atLeast(ProtocolVersion.V1_3))
      out.add(integer(LOCATED_ITEMS, found.size()));
    found.stream()
        .skip(offset)
        .limit(max == null ? Long.MAX_VALUE : max)
        .forEach(id -> out.add(text(UNIQUE_IDENTIFIER, id)));
    return out;
  }

  private static boolean matches(Obj o, List<Attr> filters) {
    Map<AttrKey, List<Ttlv>> grouped = new LinkedHashMap<>();
    for (Attr f : filters) grouped.computeIfAbsent(f.key(), k -> new ArrayList<>()).add(f.value());
    for (Map.Entry<AttrKey, List<Ttlv>> e : grouped.entrySet()) {
      List<Ttlv> have = o.attrs.getOrDefault(e.getKey(), List.of());
      List<Ttlv> want = e.getValue();
      if (want.size() == 2 && want.get(0).type() == Ttlv.Type.DATE_TIME) {
        long a = want.get(0).longValue(), b = want.get(1).longValue();
        long lo = Math.min(a, b), hi = Math.max(a, b);
        if (have.stream().noneMatch(h -> h.longValue() >= lo && h.longValue() <= hi)) return false;
      } else
        for (Ttlv w : want) if (have.stream().noneMatch(h -> same(e.getKey(), h, w))) return false;
    }
    return true;
  }

  private static boolean same(AttrKey key, Ttlv have, Ttlv want) {
    if (key.tag() == NAME)
      return have.require(NAME_VALUE).textValue().equals(want.require(NAME_VALUE).textValue());
    if (key.tag() == CRYPTOGRAPHIC_USAGE_MASK)
      return (have.intValue() & want.intValue()) == want.intValue();
    return have.equals(want);
  }

  private List<Ttlv> get(Ttlv p) throws Fail {
    Obj o = lookup(p, false);
    // KMIP 1.4 §3.50 and §3.48: Extractable False, the value is never returned; Sensitive True,
    // only
    // wrapped by another key (Not Extractable and Sensitive, Permission Denied below 1.4).
    if (!o.first(EXTRACTABLE).map(Ttlv::booleanValue).orElse(true))
      throw new Fail(ResultReason.NOT_EXTRACTABLE, "Object is not Extractable");
    if (o.first(SENSITIVE).map(Ttlv::booleanValue).orElse(false)
        && p.child(KEY_WRAPPING_SPECIFICATION).isEmpty())
      throw new Fail(ResultReason.SENSITIVE, "Object is Sensitive: it is returned only wrapped");
    if (p.child(KEY_COMPRESSION_TYPE).isPresent())
      throw new Fail(ResultReason.KEY_COMPRESSION_TYPE_NOT_SUPPORTED, "No key compression");
    KeyFormatType requested = null;
    if (p.child(KEY_FORMAT_TYPE).isPresent()) requested = format(p);
    Ttlv object = object(o, requested);
    Optional<Ttlv> spec = p.child(KEY_WRAPPING_SPECIFICATION);
    if (spec.isPresent()) object = wrap(object, spec.get());
    return List.of(enumeration(OBJECT_TYPE, o.type), text(UNIQUE_IDENTIFIER, o.id), object);
  }

  /** The managed object in {@code requested} format, or the stored one. */
  private Ttlv object(Obj o, KeyFormatType requested) throws Fail {
    KeyFormatType f = requested != null ? requested : o.format;
    Ttlv result =
        switch (o.type) {
          case SYMMETRIC_KEY -> {
            Ttlv material =
                switch (f) {
                  case RAW -> bytes(KEY_MATERIAL, o.secret);
                  case TRANSPARENT_SYMMETRIC_KEY -> KeyMaterials.symmetric(o.secret);
                  default -> throw unsupported(f);
                };
            yield structure(SYMMETRIC_KEY, keyBlock(o, f, material));
          }
          case PRIVATE_KEY ->
              structure(PRIVATE_KEY, keyBlock(o, f, privateMaterial(o.privateKey, f)));
          case PUBLIC_KEY -> structure(PUBLIC_KEY, keyBlock(o, f, publicMaterial(o.publicKey, f)));
          case CERTIFICATE -> {
            if (requested != null) throw unsupported(f);
            yield ManagedObjects.certificate(Enums.CertificateType.X_509, o.der);
          }
          case SECRET_DATA -> {
            if (f != o.format) throw unsupported(f);
            yield structure(
                SECRET_DATA,
                enumeration(SECRET_DATA_TYPE, o.secretDataType),
                keyBlock(o, f, bytes(KEY_MATERIAL, o.secret)));
          }
          default -> throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, "Cannot get " + o.type);
        };
    return Structures.canonical(v, result);
  }

  private static Fail unsupported(KeyFormatType f) {
    return new Fail(ResultReason.KEY_FORMAT_TYPE_NOT_SUPPORTED, f.wireName() + " is not available");
  }

  private static Ttlv keyBlock(Obj o, KeyFormatType format, Ttlv material) {
    List<Ttlv> fields = new ArrayList<>();
    fields.add(enumeration(KEY_FORMAT_TYPE, format));
    fields.add(structure(KEY_VALUE, material.retag(KEY_MATERIAL)));
    o.first(CRYPTOGRAPHIC_ALGORITHM).ifPresent(fields::add);
    o.first(CRYPTOGRAPHIC_LENGTH).ifPresent(fields::add);
    return structure(KEY_BLOCK, fields);
  }

  private static Ttlv privateMaterial(PrivateKey key, KeyFormatType f) throws Fail {
    try {
      switch (f) {
        case PKCS_8:
          return bytes(KEY_MATERIAL, key.getEncoded());
        case PKCS_1:
          if (!(key instanceof RSAPrivateKey)) break;
          ByteBuffer info = der(ByteBuffer.wrap(key.getEncoded()), 0x30);
          der(info, 0x02);
          der(info, 0x30);
          return bytes(KEY_MATERIAL, remaining(der(info, 0x04)));
        case TRANSPARENT_RSA_PRIVATE_KEY:
          if (key instanceof RSAPrivateCrtKey k)
            return KeyMaterials.rsaPrivate(
                k.getModulus(),
                k.getPrivateExponent(),
                bigInteger(PUBLIC_EXPONENT, k.getPublicExponent()),
                bigInteger(P, k.getPrimeP()),
                bigInteger(Q, k.getPrimeQ()),
                bigInteger(PRIME_EXPONENT_P, k.getPrimeExponentP()),
                bigInteger(PRIME_EXPONENT_Q, k.getPrimeExponentQ()),
                bigInteger(CRT_COEFFICIENT, k.getCrtCoefficient()));
          if (key instanceof RSAPrivateKey k)
            return KeyMaterials.rsaPrivate(k.getModulus(), k.getPrivateExponent());
          break;
        case TRANSPARENT_EC_PRIVATE_KEY:
        case TRANSPARENT_ECDSA_PRIVATE_KEY:
        case TRANSPARENT_ECDH_PRIVATE_KEY:
          if (key instanceof ECPrivateKey k)
            return KeyMaterials.ecPrivate(Keys.recommendedCurve(k.getParams()), k.getS());
          break;
        default:
          break;
      }
    } catch (GeneralSecurityException e) {
      throw new Fail(ResultReason.CRYPTOGRAPHIC_FAILURE, e.toString());
    }
    throw unsupported(f);
  }

  private static Ttlv publicMaterial(PublicKey key, KeyFormatType f) throws Fail {
    try {
      switch (f) {
        case X_509:
          return bytes(KEY_MATERIAL, key.getEncoded());
        case PKCS_1:
          if (!(key instanceof RSAPublicKey)) break;
          ByteBuffer info = der(ByteBuffer.wrap(key.getEncoded()), 0x30);
          der(info, 0x30);
          ByteBuffer bitString = der(info, 0x03);
          bitString.get(); // unused-bits octet
          return bytes(KEY_MATERIAL, remaining(bitString));
        case TRANSPARENT_RSA_PUBLIC_KEY:
          if (key instanceof RSAPublicKey k)
            return KeyMaterials.rsaPublic(k.getModulus(), k.getPublicExponent());
          break;
        case TRANSPARENT_EC_PUBLIC_KEY:
        case TRANSPARENT_ECDSA_PUBLIC_KEY:
        case TRANSPARENT_ECDH_PUBLIC_KEY:
          if (key instanceof ECPublicKey k)
            return KeyMaterials.ecPublic(Keys.recommendedCurve(k.getParams()), Keys.encodePoint(k));
          break;
        default:
          break;
      }
    } catch (GeneralSecurityException e) {
      throw new Fail(ResultReason.CRYPTOGRAPHIC_FAILURE, e.toString());
    }
    throw unsupported(f);
  }

  /** Applies a Key Wrapping Specification (Encrypt only) to a key object. */
  private Ttlv wrap(Ttlv object, Ttlv spec) throws Fail {
    if (spec.require(WRAPPING_METHOD).intValue() != Enums.WrappingMethod.ENCRYPT.code()
        || spec.child(MAC_SIGNATURE_KEY_INFORMATION).isPresent())
      throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, "Only the Encrypt wrapping method");
    Optional<Ttlv> block = object.child(KEY_BLOCK);
    if (block.isEmpty())
      throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, "Only keys are wrapped");
    Ttlv info = spec.require(ENCRYPTION_KEY_INFORMATION);
    String kekId = info.require(UNIQUE_IDENTIFIER).textValue();
    Obj kek = objects.get(kekId);
    if (kek == null || kek.destroyed())
      throw new Fail(ResultReason.ITEM_NOT_FOUND, "No wrapping key " + kekId);
    if (kek.type != ObjectType.SYMMETRIC_KEY || kek.algorithm() != CryptographicAlgorithm.AES)
      throw new Fail(ResultReason.INVALID_FIELD, "The wrapping key is not an AES key");
    if (kek.state() != State.ACTIVE)
      throw new Fail(ResultReason.INVALID_FIELD, "The wrapping key is not Active");
    if ((kek.usage() & CryptographicUsageMask.WRAP_KEY.code()) == 0)
      throw new Fail(ResultReason.INVALID_FIELD, "The wrapping key lacks Wrap Key usage");
    Integer requested =
        info.child(CRYPTOGRAPHIC_PARAMETERS)
            .flatMap(c -> c.child(BLOCK_CIPHER_MODE))
            .map(Ttlv::intValue)
            .orElse(null);
    Integer mode =
        kek.values(CRYPTOGRAPHIC_PARAMETERS).stream()
            .map(c -> c.child(BLOCK_CIPHER_MODE).map(Ttlv::intValue).orElse(null))
            .filter(m -> m != null && (requested == null || m.equals(requested)))
            .findFirst()
            .orElseThrow(
                () ->
                    new Fail(
                        ResultReason.INVALID_FIELD,
                        "The wrapping key has no Cryptographic Parameters with "
                            + (requested == null ? "a Block Cipher Mode" : "the requested mode")));
    String transformation;
    if (mode == BlockCipherMode.NISTKEY_WRAP.code()) transformation = "AESWrap";
    else if (mode == BlockCipherMode.AESKEY_WRAP_PADDING.code()) transformation = "AESWrapPad";
    else throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, "Only AES key wrap modes");
    Optional<Ttlv> encoding = spec.child(ENCODING_OPTION);
    Ttlv value = block.get().require(KEY_VALUE);
    byte[] plain;
    if (encoding.isPresent()
        && encoding.get().intValue() == Enums.EncodingOption.NO_ENCODING.code()) {
      Ttlv material = value.require(KEY_MATERIAL);
      if (material.type() != Ttlv.Type.BYTE_STRING)
        throw new Fail(ResultReason.ENCODING_OPTION_ERROR, "No Encoding needs byte key material");
      plain = material.bytesValue();
    } else plain = new TtlvCodec().encode(value);
    byte[] wrapped;
    try {
      Cipher c = Cipher.getInstance(transformation);
      c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(kek.secret, "AES"));
      wrapped = c.doFinal(plain);
    } catch (GeneralSecurityException e) {
      throw new Fail(ResultReason.CRYPTOGRAPHIC_FAILURE, e.toString());
    } finally {
      Arrays.fill(plain, (byte) 0);
    }
    List<Ttlv> wrapping = new ArrayList<>(List.of(enumeration(WRAPPING_METHOD, 1), info));
    encoding.ifPresent(wrapping::add);
    List<Ttlv> blockFields = new ArrayList<>();
    for (Ttlv f : block.get().children())
      blockFields.add(f.tag() == KEY_VALUE.code() ? bytes(KEY_VALUE, wrapped) : f);
    blockFields.add(structure(KEY_WRAPPING_DATA, wrapping));
    List<Ttlv> fields = new ArrayList<>();
    for (Ttlv f : object.children())
      fields.add(f.tag() == KEY_BLOCK.code() ? structure(KEY_BLOCK, blockFields) : f);
    return Structures.canonical(v, structure(object.tag(), fields));
  }

  private List<Ttlv> getAttributes(Ttlv p) throws Fail {
    Obj o = lookup(p, true);
    BiPredicate<AttrKey, Ttlv> select = selector(p);
    List<Ttlv> found = renderAll(o, select);
    Ttlv lease = leaseTime(o);
    if (lease != null && select.test(AttrKey.std(LEASE_TIME), lease)) {
      Ttlv wire = render(AttrKey.std(LEASE_TIME), lease, 0);
      if (wire != null) found.add(wire);
    }
    List<Ttlv> out = new ArrayList<>(List.of(text(UNIQUE_IDENTIFIER, o.id)));
    if (v.legacyAttributes()) out.addAll(found);
    else out.add(structure(ATTRIBUTES, found));
    return out;
  }

  private List<Ttlv> getAttributeList(Ttlv p) throws Fail {
    Obj o = lookup(p, true);
    Set<Ttlv> names = new LinkedHashSet<>();
    o.attrs.forEach(
        (key, values) -> {
          for (int i = 0; i < values.size(); i++) {
            if (render(key, values.get(i), i) == null) continue;
            if (v.legacyAttributes()) names.add(text(ATTRIBUTE_NAME, key.legacyName()));
            else if (key.tag() == null)
              names.add(ModernAttributes.vendorReference(key.vendor(), key.name()));
            else if (v == V3_0 && key.tag() == LINK)
              names.add(
                  ModernAttributes.reference(
                      LINK_TAGS.get(values.get(i).require(LINK_TYPE).intValue())));
            else names.add(ModernAttributes.reference(key.tag()));
          }
        });
    Ttlv lease = leaseTime(o);
    if (lease != null && render(AttrKey.std(LEASE_TIME), lease, 0) != null)
      names.add(
          v.legacyAttributes()
              ? text(ATTRIBUTE_NAME, AttrKey.std(LEASE_TIME).legacyName())
              : ModernAttributes.reference(LEASE_TIME));
    List<Ttlv> out = new ArrayList<>(List.of(text(UNIQUE_IDENTIFIER, o.id)));
    out.addAll(names);
    return out;
  }

  /**
   * The Lease Time {@link #leaseTime} states for {@code o}, as a stored value; null when the server
   * does not lease, or the object stores a Lease Time of its own.
   */
  private Ttlv leaseTime(Obj o) {
    Duration time = store.leaseTime;
    if (time == null || o.first(LEASE_TIME).isPresent()) return null;
    return Ttlv.interval(LEASE_TIME, time.toSeconds());
  }

  /**
   * Obtain Lease ({@link #leaseTime}): the object, the Lease Time granted and its Last Change Date.
   * Item Not Found for a destroyed object; Permission Denied for one that is not Active when
   * {@link #leasesOnlyForActive} is set.
   */
  private List<Ttlv> obtainLease(Ttlv p) throws Fail {
    Duration time = store.leaseTime;
    if (time == null)
      throw new Fail(ResultReason.OPERATION_NOT_SUPPORTED, "Obtain Lease is not implemented");
    Obj o = lookup(p, false);
    if (store.leasesOnlyForActive && o.state() != State.ACTIVE)
      throw new Fail(ResultReason.PERMISSION_DENIED, "Only active objects may receive a lease");
    Ttlv changed =
        o.first(LAST_CHANGE_DATE)
            .or(() -> o.first(INITIAL_DATE))
            .orElse(dateTime(LAST_CHANGE_DATE, now()));
    // An object's own Lease Time is the one its attributes state, and so the one granted.
    long seconds = o.first(LEASE_TIME).map(Ttlv::longValue).orElse(time.toSeconds());
    return List.of(
        text(UNIQUE_IDENTIFIER, o.id),
        Ttlv.interval(LEASE_TIME, seconds),
        dateTime(LAST_CHANGE_DATE, changed.instantValue()));
  }

  private List<Ttlv> addAttribute(Ttlv p) throws Fail {
    Obj o = lookup(p, true);
    Ttlv raw = v.legacyAttributes() ? p.require(ATTRIBUTE) : single(p.require(NEW_ATTRIBUTE));
    if (v.legacyAttributes() && raw.child(ATTRIBUTE_INDEX).isPresent())
      throw violation(ResultReason.INVALID_FIELD, "Add Attribute takes no AttributeIndex");
    Attr a = parse(raw);
    writable(a.key());
    datable(o, a.key());
    List<Ttlv> values = o.attrs.getOrDefault(a.key(), List.of());
    if (!a.key().multi() && !values.isEmpty())
      throw new Fail(ResultReason.ATTRIBUTE_SINGLE_VALUED, a.key().legacyName() + " is set");
    if (a.key().equals(AttrKey.std(LINK))) singleLink(o, a.value());
    if (a.key().equals(AttrKey.std(NAME))) unique(List.of(a.value()), o.id);
    o.add(a.key(), a.value());
    datesPassed();
    return echo(o, a.key(), a.value(), o.index(a.key(), o.attrs.get(a.key()).size() - 1));
  }

  private List<Ttlv> modifyAttribute(Ttlv p) throws Fail {
    Obj o = lookup(p, true);
    Ttlv raw = v.legacyAttributes() ? p.require(ATTRIBUTE) : single(p.require(NEW_ATTRIBUTE));
    Attr a = parse(raw);
    writable(a.key());
    datable(o, a.key());
    List<Ttlv> values = o.attrs.get(a.key());
    if (values == null || values.isEmpty())
      throw new Fail(ResultReason.ATTRIBUTE_NOT_FOUND, "No " + a.key().legacyName() + " to modify");
    int index = 0;
    if (v.legacyAttributes())
      index = o.position(a.key(), raw.child(ATTRIBUTE_INDEX).map(Ttlv::intValue).orElse(0));
    else if (p.child(CURRENT_ATTRIBUTE).isPresent()) {
      Attr current = parse(single(p.require(CURRENT_ATTRIBUTE)));
      if (!current.key().equals(a.key()))
        throw violation(ResultReason.INVALID_FIELD, "CurrentAttribute and NewAttribute differ");
      index = values.indexOf(current.value());
    } else if (values.size() > 1)
      throw violation(
          ResultReason.INVALID_FIELD,
          "CurrentAttribute is required for a multi-instance attribute");
    if (index < 0 || index >= values.size())
      throw new Fail(ResultReason.ATTRIBUTE_INSTANCE_NOT_FOUND, "No such attribute instance");
    if (a.key().equals(AttrKey.std(NAME))) unique(List.of(a.value()), o.id);
    values.set(index, a.value());
    datesPassed();
    return echo(o, a.key(), a.value(), o.index(a.key(), index));
  }

  private List<Ttlv> setAttribute(Ttlv p) throws Fail {
    Obj o = lookup(p, true);
    Attr a = parse(single(p.require(NEW_ATTRIBUTE)));
    writable(a.key());
    datable(o, a.key());
    if (a.key().tag() != null && MULTI_VALUED.contains(a.key().tag()))
      throw new Fail(
          ResultReason.MULTI_VALUED_ATTRIBUTE, "Set Attribute cannot set " + a.key().legacyName());
    o.attrs.put(a.key(), new ArrayList<>(List.of(a.value())));
    datesPassed();
    return List.of(text(UNIQUE_IDENTIFIER, o.id));
  }

  private List<Ttlv> deleteAttribute(Ttlv p) throws Fail {
    Obj o = lookup(p, true);
    if (v.legacyAttributes()) {
      AttrKey key = legacyKey(p.require(ATTRIBUTE_NAME).textValue());
      int index = p.child(ATTRIBUTE_INDEX).map(Ttlv::intValue).orElse(0);
      writable(key);
      deletable(key);
      List<Ttlv> values = o.attrs.get(key);
      int position = values == null ? -1 : o.position(key, index);
      if (position < 0)
        throw new Fail(ResultReason.ATTRIBUTE_NOT_FOUND, "No " + key.legacyName() + " to delete");
      List<Ttlv> out = echo(o, key, values.get(position), index);
      o.removeAt(key, position);
      return out;
    }
    if (p.child(CURRENT_ATTRIBUTE).isPresent()) {
      Attr current = parse(single(p.require(CURRENT_ATTRIBUTE)));
      writable(current.key());
      deletable(current.key());
      List<Ttlv> values = o.attrs.get(current.key());
      int position = values == null ? -1 : values.indexOf(current.value());
      if (position < 0) throw new Fail(ResultReason.ATTRIBUTE_NOT_FOUND, "No such attribute value");
      o.removeAt(current.key(), position);
    } else if (p.child(ATTRIBUTE_REFERENCE).isPresent()) {
      Ref ref = resolve(p.require(ATTRIBUTE_REFERENCE));
      writable(ref.key());
      deletable(ref.key());
      List<Ttlv> values = o.attrs.get(ref.key());
      boolean removed = false;
      for (int i = values == null ? -1 : values.size() - 1; i >= 0; i--)
        if (ref.test(ref.key(), values.get(i))) {
          o.removeAt(ref.key(), i);
          removed = true;
        }
      if (!removed)
        throw new Fail(ResultReason.ATTRIBUTE_NOT_FOUND, "No " + ref.key().legacyName());
    } else
      throw violation(
          ResultReason.MISSING_DATA,
          "Delete Attribute needs CurrentAttribute or AttributeReference");
    return List.of(text(UNIQUE_IDENTIFIER, o.id));
  }

  /** The 1.x Add/Modify/Delete Attribute response echoes the attribute; 2.x+ only the id. */
  private List<Ttlv> echo(Obj o, AttrKey key, Ttlv value, int index) {
    List<Ttlv> out = new ArrayList<>(List.of(text(UNIQUE_IDENTIFIER, o.id)));
    if (v.legacyAttributes()) {
      Ttlv wire = render(key, value, index);
      if (wire != null) out.add(wire);
    }
    return out;
  }

  /**
   * Activate. An object that is not Pre-Active is Wrong Key Lifecycle State from 2.0; KMIP 1.x has
   * no such reason, and its Activate error table prescribes Permission Denied for "Object is not in
   * Pre-Active state" (KMIP 1.4 Table 346), as real 1.x servers answer.
   */
  private List<Ttlv> activate(Ttlv p) throws Fail {
    Obj o = lookup(p, false);
    if (o.state() != State.PRE_ACTIVE)
      throw new Fail(
          v.atLeast(ResultReason.WRONG_KEY_LIFECYCLE_STATE.since())
              ? ResultReason.WRONG_KEY_LIFECYCLE_STATE
              : ResultReason.PERMISSION_DENIED,
          "Activate needs Pre-Active, not " + o.state());
    activateNow(o);
    return List.of(text(UNIQUE_IDENTIFIER, o.id));
  }

  /**
   * Revoke. Up to 2.1 a Key or CA Compromise reason makes the object Compromised and any other
   * reason Deactivated (from Active only: a Pre-Active object is refused, Permission Denied on 1.x
   * and Wrong Key Lifecycle State from 2.0). On the 3.0 draft every Revoke makes it Compromised,
   * and an omitted Revocation Reason is Unspecified (CSD02 §6.1.51; the Deactivate operation
   * deactivates). A Revoke of an object that is Compromised already is refused the same way, on
   * every version, and changes nothing: its first reason and dates stay. Entering Compromised, the request's Compromise Occurrence Date is
   * recorded; from 1.3 one the request omits is the object's Initial Date (the SHOULD of the Revoke
   * operation from 1.3, KMIP 1.4 §4.20 and CSD02 §6.1.51), as keytend-kmip-server records; before 1.3 (1.1,
   * 1.2) a Key Compromise without one is Missing Data, recorded as a violation (1.1 Table 170, 1.2
   * Table 185 make it required, as keytend-kmip-server answers).
   */
  private List<Ttlv> revoke(Ttlv p) throws Fail {
    Obj o = lookup(p, false);
    // Only the transitions KMIP lists are permitted (1.4 §3.22, 2.1 §4.57, CSD02 §4.67): none
    // leaves
    // Compromised but Destroy, so a second Revoke is refused, as keytend-kmip-server refuses it,
    // and the first
    // compromise's reason and dates stay.
    if (o.state() == State.COMPROMISED || o.state() == State.DESTROYED_COMPROMISED)
      throw new Fail(stateRefusal(), o.id + " is " + o.state() + " already");
    Optional<Ttlv> given = p.child(REVOCATION_REASON);
    Ttlv reason =
        v.atLeast(V3_0) && given.isEmpty()
            ? structure(
                REVOCATION_REASON,
                List.of(
                    enumeration(REVOCATION_REASON_CODE, Enums.RevocationReasonCode.UNSPECIFIED)))
            : p.require(REVOCATION_REASON);
    int code = reason.require(REVOCATION_REASON_CODE).intValue();
    if (!v.atLeast(ProtocolVersion.V1_3)
        && code == Enums.RevocationReasonCode.KEY_COMPROMISE.code()
        && p.child(COMPROMISE_OCCURRENCE_DATE).isEmpty())
      throw violation(
          ResultReason.MISSING_DATA,
          "Key Compromise requires a Compromise Occurrence Date before KMIP 1.3");
    if (v.atLeast(V3_0)
        || code == Enums.RevocationReasonCode.KEY_COMPROMISE.code()
        || code == Enums.RevocationReasonCode.CA_COMPROMISE.code()) {
      o.put(enumeration(STATE, State.COMPROMISED));
      o.put(dateTime(COMPROMISE_DATE, now()));
      Optional<Ttlv> occurred = p.child(COMPROMISE_OCCURRENCE_DATE);
      if (occurred.isPresent()) o.put(occurred.get());
      else if (v.atLeast(ProtocolVersion.V1_3))
        o.first(INITIAL_DATE).ifPresent(i -> o.put(i.retag(COMPROMISE_OCCURRENCE_DATE)));
    } else {
      // Up to 2.1 a Revoke deactivates only an Active object (transition 6): KMIP has no transition
      // from Pre-Active to Deactivated, and keytend-kmip-server refuses one.
      if (o.state() == State.PRE_ACTIVE)
        throw new Fail(
            stateRefusal(), "Cannot deactivate a Pre-Active object: KMIP has no such transition");
      if (o.state() != State.ACTIVE)
        throw new Fail(
            ResultReason.WRONG_KEY_LIFECYCLE_STATE, "Cannot deactivate a " + o.state() + " object");
      o.put(enumeration(STATE, State.DEACTIVATED));
      o.put(dateTime(DEACTIVATION_DATE, now()));
    }
    o.put(plain(reason));
    return List.of(text(UNIQUE_IDENTIFIER, o.id));
  }

  /**
   * The refusal of a request the object's state forbids, as keytend-kmip-server answers it: Wrong Key
   * Lifecycle State from 2.0, Permission Denied on KMIP 1.x, which has no such reason.
   */
  private ResultReason stateRefusal() {
    return v.atLeast(ResultReason.WRONG_KEY_LIFECYCLE_STATE.since())
        ? ResultReason.WRONG_KEY_LIFECYCLE_STATE
        : ResultReason.PERMISSION_DENIED;
  }

  /**
   * Deactivate (KMIP 3.0 CSD02 §6.1.14): an Active object becomes Deactivated, with its Deactivation
   * Date now (or the request's Deactivation Date, which may not be in the future) and its
   * Deactivation Reason the request's, Unspecified when it has none. Only from Active (transition 6:
   * the draft has no transition from Pre-Active or any other state to Deactivated), otherwise Wrong
   * Key Lifecycle State.
   */
  private List<Ttlv> deactivate(Ttlv p) throws Fail {
    Obj o = lookup(p, false);
    if (o.state() != State.ACTIVE)
      throw new Fail(
          ResultReason.WRONG_KEY_LIFECYCLE_STATE, "Deactivate needs Active, not " + o.state());
    Instant at = now();
    Optional<Ttlv> date = p.child(DEACTIVATION_DATE);
    if (date.isPresent()) {
      if (date.get().instantValue().isAfter(at))
        throw violation(ResultReason.INVALID_FIELD, "Deactivation Date in the future");
      at = date.get().instantValue();
    }
    Ttlv reason =
        p.child(DEACTIVATION_REASON)
            .orElse(
                structure(
                    DEACTIVATION_REASON,
                    List.of(
                        enumeration(
                            DEACTIVATION_REASON_CODE, Enums.DeactivationReasonCode.UNSPECIFIED))));
    reason.require(DEACTIVATION_REASON_CODE);
    o.put(enumeration(STATE, State.DEACTIVATED));
    o.put(dateTime(DEACTIVATION_DATE, at));
    o.put(plain(reason));
    return List.of(text(UNIQUE_IDENTIFIER, o.id));
  }

  private List<Ttlv> destroy(Ttlv p) throws Fail {
    Obj o = lookup(p, false);
    if (o.state() == State.ACTIVE)
      throw new Fail(
          ResultReason.WRONG_KEY_LIFECYCLE_STATE,
          "An Active object cannot be destroyed; revoke it");
    o.put(
        enumeration(
            STATE, o.state() == State.COMPROMISED ? State.DESTROYED_COMPROMISED : State.DESTROYED));
    o.put(dateTime(DESTROY_DATE, now()));
    if (o.secret != null) Arrays.fill(o.secret, (byte) 0);
    o.secret = null;
    o.privateKey = null;
    o.publicKey = null;
    o.der = null;
    return List.of(text(UNIQUE_IDENTIFIER, o.id));
  }

  private List<Ttlv> cipher(Ttlv p, boolean encrypt) throws Fail {
    Obj o = cryptoKey(p, encrypt);
    Ttlv cp = params(p, o);
    byte[] data =
        p.child(DATA)
            .map(Ttlv::bytesValue)
            .orElseThrow(() -> violation(ResultReason.MISSING_DATA, "no Data"));
    byte[] iv = p.child(IV_COUNTER_NONCE).map(Ttlv::bytesValue).orElse(null);
    byte[] aad =
        p.child(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA).map(Ttlv::bytesValue).orElse(null);
    List<Ttlv> out = new ArrayList<>(List.of(text(UNIQUE_IDENTIFIER, o.id)));
    int cipherMode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
    try {
      if (o.type == ObjectType.SYMMETRIC_KEY && o.algorithm() == CryptographicAlgorithm.AES) {
        BlockCipherMode mode =
            Optional.ofNullable(field(cp, BLOCK_CIPHER_MODE))
                .flatMap(BlockCipherMode::fromCode)
                .orElseThrow(
                    () ->
                        new Fail(
                            ResultReason.BAD_CRYPTOGRAPHIC_PARAMETERS, "no Block Cipher Mode"));
        boolean keyWrap =
            mode == BlockCipherMode.NISTKEY_WRAP || mode == BlockCipherMode.AESKEY_WRAP_PADDING;
        requireUsage(
            o,
            encrypt ? CryptographicUsageMask.ENCRYPT : CryptographicUsageMask.DECRYPT,
            keyWrap
                ? (encrypt ? CryptographicUsageMask.WRAP_KEY : CryptographicUsageMask.UNWRAP_KEY)
                : null);
        SecretKeySpec key = new SecretKeySpec(o.secret, "AES");
        // KMIP requires IV Length for variable-IV modes once the field exists (1.2).
        if ((mode == BlockCipherMode.GCM || mode == BlockCipherMode.CTR)
            && v.atLeast(ProtocolVersion.V1_2)) {
          Integer ivBits = field(cp, IV_LENGTH);
          if (ivBits == null)
            throw violation(ResultReason.INVALID_FIELD, mode + " without IV Length");
          if (iv != null && iv.length * 8 != ivBits)
            throw violation(ResultReason.INVALID_FIELD, "IV does not match IV Length");
        }
        switch (mode) {
          case GCM -> {
            int tagLength = Optional.ofNullable(field(cp, TAG_LENGTH)).orElse(16);
            boolean separateTag = v.atLeast(ProtocolVersion.V1_4);
            Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
            if (encrypt) {
              boolean generated = iv == null;
              if (generated)
                iv = randomBytes(Optional.ofNullable(field(cp, IV_LENGTH)).orElse(96) / 8);
              c.init(cipherMode, key, new GCMParameterSpec(tagLength * 8, iv));
              if (aad != null) c.updateAAD(aad);
              byte[] sealed = c.doFinal(data);
              int split = separateTag ? sealed.length - tagLength : sealed.length;
              out.add(bytes(DATA, Arrays.copyOfRange(sealed, 0, split)));
              if (generated) out.add(bytes(IV_COUNTER_NONCE, iv));
              if (separateTag)
                out.add(
                    bytes(
                        AUTHENTICATED_ENCRYPTION_TAG,
                        Arrays.copyOfRange(sealed, split, sealed.length)));
            } else {
              if (iv == null)
                throw new Fail(ResultReason.MISSING_INITIALIZATION_VECTOR, "GCM needs an IV");
              byte[] tag = p.child(AUTHENTICATED_ENCRYPTION_TAG).map(Ttlv::bytesValue).orElse(null);
              if (separateTag && tag == null)
                throw violation(
                    ResultReason.MISSING_DATA, "GCM Decrypt needs AuthenticatedEncryptionTag");
              if (tag != null) tagLength = tag.length;
              c.init(cipherMode, key, new GCMParameterSpec(tagLength * 8, iv));
              if (aad != null) c.updateAAD(aad);
              out.add(bytes(DATA, c.doFinal(tag == null ? data : concat(data, tag))));
            }
          }
          case CBC, ECB -> {
            Integer padding = field(cp, PADDING_METHOD);
            String pad;
            if (padding == null || padding == PaddingMethod.PKCS5.code()) pad = "PKCS5Padding";
            else if (padding == PaddingMethod.NONE.code()) pad = "NoPadding";
            else throw new Fail(ResultReason.UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS, "AES padding");
            out.addAll(
                blockCipher(
                    "AES/" + mode.wireName() + "/" + pad,
                    key,
                    mode == BlockCipherMode.CBC,
                    data,
                    iv,
                    encrypt));
          }
          case CTR -> out.addAll(blockCipher("AES/CTR/NoPadding", key, true, data, iv, encrypt));
          case NISTKEY_WRAP, AESKEY_WRAP_PADDING -> {
            Cipher c =
                Cipher.getInstance(mode == BlockCipherMode.NISTKEY_WRAP ? "AESWrap" : "AESWrapPad");
            c.init(cipherMode, key);
            out.add(bytes(DATA, c.doFinal(data)));
          }
          default ->
              throw new Fail(
                  ResultReason.UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS,
                  "AES " + mode + " is unsupported");
        }
      } else if (o.algorithm() == CryptographicAlgorithm.RSA
          && o.type == (encrypt ? ObjectType.PUBLIC_KEY : ObjectType.PRIVATE_KEY)) {
        requireUsage(
            o, encrypt ? CryptographicUsageMask.ENCRYPT : CryptographicUsageMask.DECRYPT, null);
        Integer padding = field(cp, PADDING_METHOD);
        Cipher c;
        if (padding != null && padding == PaddingMethod.OAEP.code()) {
          c = Cipher.getInstance("RSA/ECB/OAEPPadding");
          String hash = jcaHash(field(cp, HASHING_ALGORITHM), "SHA-1");
          String mgf = jcaHash(field(cp, MASK_GENERATOR_HASHING_ALGORITHM), "SHA-1");
          PSource source =
              cp.child(P_SOURCE)
                  .<PSource>map(s -> new PSource.PSpecified(s.bytesValue()))
                  .orElse(PSource.PSpecified.DEFAULT);
          c.init(
              cipherMode,
              encrypt ? o.publicKey : o.privateKey,
              new OAEPParameterSpec(hash, "MGF1", new MGF1ParameterSpec(mgf), source));
        } else if (padding != null && padding == PaddingMethod.PKCS1_V1_5.code()) {
          c = Cipher.getInstance("RSA/ECB/PKCS1Padding");
          c.init(cipherMode, encrypt ? o.publicKey : o.privateKey);
        } else
          throw new Fail(ResultReason.BAD_CRYPTOGRAPHIC_PARAMETERS, "RSA needs OAEP or PKCS1 v1.5");
        out.add(bytes(DATA, c.doFinal(data)));
      } else
        throw new Fail(
            ResultReason.ILLEGAL_OBJECT_TYPE,
            o.id + " cannot " + (encrypt ? "encrypt" : "decrypt"));
    } catch (AEADBadTagException e) {
      throw new Fail(ResultReason.CRYPTOGRAPHIC_FAILURE, "Authentication tag mismatch");
    } catch (GeneralSecurityException e) {
      throw new Fail(ResultReason.CRYPTOGRAPHIC_FAILURE, e.toString());
    }
    return out;
  }

  private List<Ttlv> blockCipher(
      String transformation,
      SecretKeySpec key,
      boolean needsIv,
      byte[] data,
      byte[] iv,
      boolean encrypt)
      throws Fail, GeneralSecurityException {
    Cipher c = Cipher.getInstance(transformation);
    int mode = encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
    boolean generated = false;
    if (!needsIv) c.init(mode, key);
    else {
      if (iv == null) {
        if (!encrypt) throw new Fail(ResultReason.MISSING_INITIALIZATION_VECTOR, "IV required");
        iv = randomBytes(16);
        generated = true;
      }
      c.init(mode, key, new IvParameterSpec(iv));
    }
    List<Ttlv> out = new ArrayList<>(List.of(bytes(DATA, c.doFinal(data))));
    if (generated) out.add(bytes(IV_COUNTER_NONCE, iv));
    return out;
  }

  private List<Ttlv> sign(Ttlv p) throws Fail {
    Obj o = cryptoKey(p, true);
    requireUsage(o, CryptographicUsageMask.SIGN, null);
    if (o.type != ObjectType.PRIVATE_KEY)
      throw new Fail(ResultReason.ILLEGAL_OBJECT_TYPE, "Sign needs a private key");
    Optional<Ttlv> digested = p.child(DIGESTED_DATA);
    byte[] input =
        digested
            .or(() -> p.child(DATA))
            .map(Ttlv::bytesValue)
            .orElseThrow(() -> violation(ResultReason.MISSING_DATA, "no Data or DigestedData"));
    try {
      Signer signer = signer(o, params(p, o), digested.isPresent());
      signer.signature().initSign(o.privateKey);
      signer.signature().update(signer.prepare(input));
      return List.of(
          text(UNIQUE_IDENTIFIER, o.id), bytes(SIGNATURE_DATA, signer.signature().sign()));
    } catch (GeneralSecurityException e) {
      throw new Fail(ResultReason.CRYPTOGRAPHIC_FAILURE, e.toString());
    }
  }

  private List<Ttlv> verify(Ttlv p) throws Fail {
    Obj o = cryptoKey(p, false);
    requireUsage(o, CryptographicUsageMask.VERIFY, null);
    if (o.type != ObjectType.PUBLIC_KEY && o.type != ObjectType.CERTIFICATE)
      throw new Fail(ResultReason.ILLEGAL_OBJECT_TYPE, "Signature Verify needs a public key");
    Optional<Ttlv> digested = p.child(DIGESTED_DATA);
    byte[] input =
        digested
            .or(() -> p.child(DATA))
            .map(Ttlv::bytesValue)
            .orElseThrow(() -> violation(ResultReason.MISSING_DATA, "no Data or DigestedData"));
    byte[] signature =
        p.child(SIGNATURE_DATA)
            .map(Ttlv::bytesValue)
            .orElseThrow(() -> violation(ResultReason.MISSING_DATA, "no SignatureData"));
    boolean valid;
    try {
      Signer signer = signer(o, params(p, o), digested.isPresent());
      signer.signature().initVerify(o.publicKey);
      signer.signature().update(signer.prepare(input));
      valid = signer.signature().verify(signature);
    } catch (SignatureException malformed) {
      valid = false;
    } catch (GeneralSecurityException e) {
      throw new Fail(ResultReason.CRYPTOGRAPHIC_FAILURE, e.toString());
    }
    return List.of(
        text(UNIQUE_IDENTIFIER, o.id),
        enumeration(
            VALIDITY_INDICATOR, valid ? ValidityIndicator.VALID : ValidityIndicator.INVALID));
  }

  private record Signer(Signature signature, byte[] prefix) {
    byte[] prepare(byte[] input) {
      return prefix == null ? input : concat(prefix, input);
    }
  }

  private static Signer signer(Obj o, Ttlv cp, boolean digested)
      throws Fail, GeneralSecurityException {
    CryptographicAlgorithm keyAlg = o.algorithm();
    boolean rsa = keyAlg == CryptographicAlgorithm.RSA, ec = EC_FAMILY.contains(keyAlg);
    Integer dsa = field(cp, DIGITAL_SIGNATURE_ALGORITHM), padding = field(cp, PADDING_METHOD);
    String kind, hash;
    if (dsa != null) {
      Enums.DigitalSignatureAlgorithm d =
          Enums.DigitalSignatureAlgorithm.fromCode(dsa)
              .orElseThrow(
                  () -> new Fail(ResultReason.BAD_CRYPTOGRAPHIC_PARAMETERS, "unknown DSA"));
      String name = d.wireName();
      if (d == Enums.DigitalSignatureAlgorithm.RSASSA_PSS_PKCS_1_V2_1) {
        kind = "PSS";
        hash = jcaHash(field(cp, HASHING_ALGORITHM), "SHA-256");
      } else if (name.contains("RSA")) {
        kind = "RSA";
        hash = name.startsWith("SHA3_") ? "SHA3-" + name.substring(5, 8) : "SHA-" + digits(name);
      } else if (name.startsWith("ECDSA")) {
        kind = "ECDSA";
        hash = "SHA-" + digits(name);
      } else
        throw new Fail(ResultReason.UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS, name + " unsupported");
    } else {
      hash = jcaHash(field(cp, HASHING_ALGORITHM), null);
      if (hash == null)
        throw new Fail(ResultReason.BAD_CRYPTOGRAPHIC_PARAMETERS, "no Hashing Algorithm");
      if (rsa && padding != null && padding == PaddingMethod.PSS.code()) kind = "PSS";
      else if (rsa && (padding == null || padding == PaddingMethod.PKCS1_V1_5.code())) kind = "RSA";
      else if (ec) kind = "ECDSA";
      else throw new Fail(ResultReason.BAD_CRYPTOGRAPHIC_PARAMETERS, "no signature scheme for key");
    }
    if (kind.equals("ECDSA") ? !ec : !rsa)
      throw new Fail(ResultReason.BAD_CRYPTOGRAPHIC_PARAMETERS, kind + " does not match the key");
    String jca = hash.startsWith("SHA3") ? hash : hash.replace("-", "");
    switch (kind) {
      case "RSA" -> {
        if (!digested) return new Signer(Signature.getInstance(jca + "withRSA"), null);
        String prefix = DIGEST_INFO.get(hash);
        if (prefix == null)
          throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, "DigestedData with " + hash);
        return new Signer(Signature.getInstance("NONEwithRSA"), HexFormat.of().parseHex(prefix));
      }
      case "ECDSA" -> {
        return new Signer(
            Signature.getInstance(digested ? "NONEwithECDSA" : jca + "withECDSA"), null);
      }
      default -> {
        if (digested)
          throw new Fail(
              ResultReason.FEATURE_NOT_SUPPORTED, "PSS over DigestedData is unsupported");
        Signature s = Signature.getInstance("RSASSA-PSS");
        int salt =
            Optional.ofNullable(field(cp, SALT_LENGTH))
                .orElse(MessageDigest.getInstance(hash).getDigestLength());
        String mgf = jcaHash(field(cp, MASK_GENERATOR_HASHING_ALGORITHM), "SHA-1");
        s.setParameter(new PSSParameterSpec(hash, "MGF1", new MGF1ParameterSpec(mgf), salt, 1));
        return new Signer(s, null);
      }
    }
  }

  private static String digits(String name) {
    String d = name.replaceAll("^\\D*?(\\d+).*$", "$1");
    return d.equals("1") ? "1" : d;
  }

  private List<Ttlv> mac(Ttlv p, boolean verify) throws Fail {
    Obj o = cryptoKey(p, !verify);
    requireUsage(
        o, verify ? CryptographicUsageMask.MAC_VERIFY : CryptographicUsageMask.MAC_GENERATE, null);
    String name = o.type == ObjectType.SYMMETRIC_KEY ? hmac(o.algorithm()) : null;
    if (name == null)
      throw new Fail(ResultReason.ILLEGAL_OBJECT_TYPE, o.id + " is not an HMAC key");
    Integer requested = field(params(p, o), CRYPTOGRAPHIC_ALGORITHM);
    if (requested != null && requested != o.algorithm().code())
      throw new Fail(ResultReason.BAD_CRYPTOGRAPHIC_PARAMETERS, "algorithm differs from the key");
    byte[] data =
        p.child(DATA)
            .map(Ttlv::bytesValue)
            .orElseThrow(() -> violation(ResultReason.MISSING_DATA, "no Data"));
    byte[] computed;
    try {
      Mac m = Mac.getInstance(name);
      m.init(new SecretKeySpec(o.secret, name));
      computed = m.doFinal(data);
    } catch (GeneralSecurityException e) {
      throw new Fail(ResultReason.CRYPTOGRAPHIC_FAILURE, e.toString());
    }
    if (!verify) return List.of(text(UNIQUE_IDENTIFIER, o.id), bytes(MAC_DATA, computed));
    byte[] expected =
        p.child(MAC_DATA)
            .map(Ttlv::bytesValue)
            .orElseThrow(() -> violation(ResultReason.MISSING_DATA, "no MACData"));
    return List.of(
        text(UNIQUE_IDENTIFIER, o.id),
        enumeration(
            VALIDITY_INDICATOR,
            MessageDigest.isEqual(computed, expected)
                ? ValidityIndicator.VALID
                : ValidityIndicator.INVALID));
  }

  /**
   * Re-Provision (2.1 section 6.1.48) in the certificate-request form, as keytend-kmip-server runs
   * it: on a TLS connection whose listener has a provisioning CA, without header credentials, once
   * per message and once per certificate (a retired certificate is refused on every connection open
   * on it), followed in the message by a Get of the ID Placeholder. The new key must be new, of the
   * current certificate's kind, and RSA of 2048 bits or more or EC on P-256, P-384 or P-521 ({@link
   * Provisioning#requestKey}); a key is used up only when its message commits. The replaced
   * certificate is retired when the message commits ({@link #respond}). The item's {@value
   * #EXTENSION_VENDOR} Message Extension sets the notAfter and the stored Deactivation Date ({@link
   * #requestedNotAfter}); a date that has passed or is after the provisioning CA's notAfter is
   * Invalid Field, as is the extension with the certificate form.
   */
  private List<Ttlv> reProvision(Ttlv p) throws Fail {
    reProvisionTried = true;
    Channel on = channel;
    if (on == null || on.provisioning == null)
      throw new Fail(ResultReason.OPERATION_NOT_SUPPORTED, "Re-Provision is not configured");
    if (undoBatch()) throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, UNDO_REFUSED);
    if (messageHeader.child(AUTHENTICATION).isPresent())
      throw new Fail(
          ResultReason.PERMISSION_DENIED,
          "Re-Provision acts for the certificate principal; send it without header credentials");
    if (on.chain == null || on.chain.length == 0)
      throw new Fail(ResultReason.PERMISSION_DENIED, "Re-Provision needs a client certificate");
    // Retirement is by certificate, so it also covers other connections open on it.
    if (store.retired.containsKey(fingerprint(on.chain[0])))
      throw new Fail(
          ResultReason.PERMISSION_DENIED,
          "This connection's certificate has already been replaced");
    X509Certificate current = on.chain[0];
    try {
      current.checkValidity(java.util.Date.from(now()));
    } catch (java.security.cert.CertificateException e) {
      throw new Fail(
          ResultReason.PERMISSION_DENIED,
          "The current client certificate no longer passes verification");
    }
    Instant notAfter = requestedNotAfter(messageItems.get(itemIndex));
    if (notAfter != null && p.child(CERTIFICATE).isPresent())
      throw new Fail(
          ResultReason.INVALID_FIELD,
          "The keytend_kmip_server Message Extension does not apply to the certificate form");
    if (p.child(CERTIFICATE).isPresent())
      throw new Fail(
          ResultReason.FEATURE_NOT_SUPPORTED,
          "Only the certificate-request form of Re-Provision is implemented");
    Ttlv request =
        p.child(CERTIFICATE_REQUEST)
            .orElseThrow(
                () ->
                    new Fail(
                        ResultReason.FEATURE_NOT_SUPPORTED,
                        "Only the certificate-request form of Re-Provision is implemented"));
    boolean fetched = false;
    for (int i = itemIndex + 1; i < messageItems.size(); i++) {
      Ttlv later = messageItems.get(i);
      if (later.child(OPERATION).map(Ttlv::intValue).orElse(0) != Operation.GET.code()) continue;
      Optional<Ttlv> id = later.child(REQUEST_PAYLOAD).flatMap(r -> r.child(UNIQUE_IDENTIFIER));
      if (id.isEmpty()
          || (id.get().type() == Ttlv.Type.ENUMERATION
              && id.get().intValue() == Enums.UniqueIdentifier.ID_PLACEHOLDER.code()))
        fetched = true;
    }
    if (!fetched)
      throw new Fail(
          ResultReason.INVALID_FIELD,
          "Re-Provision must be followed in the same message by a Get of the ID Placeholder");
    // A requested notAfter: Invalid Field when it has passed or is past the provisioning CA's
    // notAfter, never cut short.
    if (notAfter != null && !notAfter.isAfter(now()))
      throw new Fail(ResultReason.INVALID_FIELD, "The requested Deactivation Date has passed");
    if (notAfter != null && notAfter.isAfter(on.provisioning.ca.getNotAfter().toInstant()))
      throw new Fail(
          ResultReason.INVALID_FIELD,
          "The requested validity ends after the provisioning CA's notAfter");
    int type = request.require(CERTIFICATE_REQUEST_TYPE).intValue();
    byte[] value = request.require(CERTIFICATE_REQUEST_VALUE).bytesValue();
    if (type == Enums.CertificateRequestType.PEM.code()) value = pemRequest(value);
    else if (type != Enums.CertificateRequestType.PKCS_10.code())
      throw new Fail(
          ResultReason.FEATURE_NOT_SUPPORTED, "Only PKCS#10 and PEM certificate requests");
    PublicKey key;
    X509Certificate issued;
    String spki;
    try {
      key = Provisioning.requestKey(value);
      if (!Provisioning.sameKind(key, current.getPublicKey()))
        throw new Provisioning.Refused(Provisioning.UNSUPPORTED_KEY);
      spki = HexFormat.of().formatHex(key.getEncoded());
      if (store.usedKeys.contains(spki)
          || Arrays.equals(key.getEncoded(), current.getPublicKey().getEncoded()))
        throw new Provisioning.Refused("Re-Provision needs a key never used before");
      try {
        issued = on.provisioning.issue(current, key, now(), notAfter);
      } catch (Provisioning.Refused r) {
        throw new Fail(ResultReason.CRYPTOGRAPHIC_FAILURE, r.getMessage());
      }
    } catch (Provisioning.Refused r) {
      throw new Fail(ResultReason.INVALID_FIELD, r.getMessage());
    } catch (GeneralSecurityException e) {
      throw new Fail(ResultReason.GENERAL_FAILURE, "Issuing failed: " + e.getMessage());
    }
    Obj o = newObject(ObjectType.CERTIFICATE);
    o.der = encoded(issued);
    o.publicKey = key;
    o.put(enumeration(CERTIFICATE_TYPE, Enums.CertificateType.X_509));
    o.put(integer(CERTIFICATE_LENGTH, o.der.length));
    o.put(
        enumeration(
            CRYPTOGRAPHIC_ALGORITHM,
            key instanceof java.security.interfaces.RSAPublicKey
                ? CryptographicAlgorithm.RSA
                : CryptographicAlgorithm.EC));
    o.put(integer(CRYPTOGRAPHIC_LENGTH, bits(key)));
    o.put(integer(CRYPTOGRAPHIC_USAGE_MASK, 0x1 | 0x2));
    o.put(dateTime(ACTIVATION_DATE, now()));
    if (notAfter != null) o.put(dateTime(DEACTIVATION_DATE, notAfter));
    store(o);
    replacement = new Replacement(o.id, current, issued, spki);
    return List.of(text(UNIQUE_IDENTIFIER, o.id));
  }

  private static byte[] encoded(X509Certificate c) {
    try {
      return c.getEncoded();
    } catch (java.security.cert.CertificateEncodingException e) {
      throw new IllegalStateException(e);
    }
  }

  /** The DER of a PEM certificate request (Certificate Request Type PEM). */
  private static byte[] pemRequest(byte[] pem) throws Fail {
    String text = new String(pem, java.nio.charset.StandardCharsets.US_ASCII);
    int begin = text.indexOf("-----BEGIN CERTIFICATE REQUEST-----"),
        end = text.indexOf("-----END CERTIFICATE REQUEST-----");
    if (begin < 0 || end < begin) throw new Fail(ResultReason.INVALID_FIELD, "Invalid PEM request");
    try {
      return Base64.getMimeDecoder()
          .decode(text.substring(begin + "-----BEGIN CERTIFICATE REQUEST-----".length(), end));
    } catch (IllegalArgumentException e) {
      throw new Fail(ResultReason.INVALID_FIELD, "Invalid PEM request");
    }
  }

  private List<Ttlv> rngRetrieve(Ttlv p) throws Fail {
    int length = p.require(DATA_LENGTH).intValue();
    if (length < 1 || length > 1 << 20)
      throw new Fail(ResultReason.INVALID_FIELD, "Data Length must be 1..1048576");
    return List.of(bytes(DATA, randomBytes(length)));
  }

  // ---------------------------------------------------------------------------------------------
  // Helpers

  private Obj newObject(ObjectType type) throws Fail {
    String id = store.identifiers == null ? "mock-" + store.nextId++ : store.identifiers.get();
    if (id == null || id.isEmpty())
      throw violation(ResultReason.GENERAL_FAILURE, "the identifier source gave no identifier");
    if (objects.containsKey(id))
      throw violation(
          ResultReason.GENERAL_FAILURE, "the identifier source gave " + id + ", which is in use");
    Obj o = new Obj(id, type);
    o.put(text(UNIQUE_IDENTIFIER, o.id));
    o.put(enumeration(OBJECT_TYPE, type));
    o.put(enumeration(STATE, State.PRE_ACTIVE));
    o.put(dateTime(INITIAL_DATE, now()));
    return o;
  }

  /**
   * With {@link #uniqueNames} on, refuses {@code names} when an object that is not destroyed (or any
   * object, with {@link #destroyedObjectsKeepNames}), other than those {@code ignoring} names, has
   * one of them.
   */
  private void unique(List<Ttlv> names, String... ignoring) throws Fail {
    if (!store.uniqueNames) return;
    List<String> skip = Arrays.asList(ignoring);
    for (Ttlv name : names)
      for (Obj other : objects.values())
        if ((store.destroyedKeepNames || !other.destroyed())
            && !skip.contains(other.id)
            && named(other, name)) throw nonUnique(name);
  }

  /** Whether {@code o} has a Name with the value of {@code name}. */
  private static boolean named(Obj o, Ttlv name) {
    String value = name.require(NAME_VALUE).textValue();
    for (Ttlv n : o.values(NAME)) if (n.require(NAME_VALUE).textValue().equals(value)) return true;
    return false;
  }

  /**
   * The refusal of a Name another object has: Non Unique Name Attribute from 2.0, Invalid Field in
   * 1.x (KMIP 1.4 Table 328: "Trying to create a new object with the same Name attribute value as
   * an existing object").
   */
  private Fail nonUnique(Ttlv name) {
    ResultReason reason =
        v.atLeast(ResultReason.NON_UNIQUE_NAME_ATTRIBUTE.since())
            ? ResultReason.NON_UNIQUE_NAME_ATTRIBUTE
            : store.legacyNonUniqueReason != null
                ? store.legacyNonUniqueReason
                : ResultReason.INVALID_FIELD;
    return new Fail(reason, "Name is not unique: " + name.require(NAME_VALUE).textValue());
  }

  /** Stores a new object; an Activation Date not in the future activates it when it is Pre-Active. */
  private void store(Obj o) {
    // KMIP 1.4 §3.48 and §3.50: every object has a Sensitive and an Extractable value, False and
    // True unless the client set them (rendered from 1.4 on, as every attribute 1.4 introduced).
    if (o.first(SENSITIVE).isEmpty()) o.put(bool(SENSITIVE, false));
    if (o.first(EXTRACTABLE).isEmpty()) o.put(bool(EXTRACTABLE, true));
    Optional<Ttlv> activation = o.first(ACTIVATION_DATE);
    if (o.state() == State.PRE_ACTIVE
        && activation.isPresent()
        && !activation.get().instantValue().isAfter(now())) o.put(enumeration(STATE, State.ACTIVE));
    objects.put(o.id, o);
  }

  private void activateNow(Obj o) {
    o.put(enumeration(STATE, State.ACTIVE));
    o.put(dateTime(ACTIVATION_DATE, now()));
  }

  /**
   * The object a payload's Unique Identifier (or the ID Placeholder) names. KMIP 1.x and 2.x use
   * the placeholder when the field is omitted; KMIP 3.0 requires the field in every request that
   * names an object (3.0 §6.1) and names the placeholder with its enumeration (§11.60).
   */
  private Obj lookup(Ttlv p, boolean allowDestroyed) throws Fail {
    Optional<Ttlv> field = p.child(UNIQUE_IDENTIFIER);
    String id;
    if (field.isEmpty() && v == ProtocolVersion.V3_0)
      throw violation(
          ResultReason.MISSING_DATA,
          "KMIP 3.0 requires the Unique Identifier; the ID Placeholder is its enumeration");
    if (field.isPresent() && field.get().type() != Ttlv.Type.ENUMERATION)
      id = field.get().textValue();
    else if (placeholder != null) id = placeholder;
    else throw violation(ResultReason.MISSING_DATA, "no Unique Identifier and no ID Placeholder");
    Obj o = objects.get(id);
    if (o == null || (!allowDestroyed && o.destroyed()))
      throw new Fail(ResultReason.ITEM_NOT_FOUND, "No object " + id);
    return o;
  }

  /**
   * The key for a cryptographic operation, checked for state. A state that forbids the operation is
   * Wrong Key Lifecycle State from 2.0; KMIP 1.x has no such reason, and its error tables for the
   * cryptographic operations (KMIP 1.4 section 11.30 ff.) answer Permission Denied, as real 1.x
   * servers do.
   */
  private Obj cryptoKey(Ttlv p, boolean protect) throws Fail {
    if (p.child(INIT_INDICATOR).isPresent() || p.child(CORRELATION_VALUE).isPresent())
      throw new Fail(ResultReason.FEATURE_NOT_SUPPORTED, "Multi-part operations are unsupported");
    Obj o = lookup(p, false);
    State s = o.state();
    if (!(s == State.ACTIVE || (!protect && (s == State.DEACTIVATED || s == State.COMPROMISED))))
      throw new Fail(
          v.atLeast(ResultReason.WRONG_KEY_LIFECYCLE_STATE.since())
              ? ResultReason.WRONG_KEY_LIFECYCLE_STATE
              : ResultReason.PERMISSION_DENIED,
          o.id + " is " + s);
    return o;
  }

  private static void requireUsage(Obj o, CryptographicUsageMask usage, CryptographicUsageMask alt)
      throws Fail {
    int mask = o.usage();
    if ((mask & usage.code()) == 0 && (alt == null || (mask & alt.code()) == 0))
      throw new Fail(
          ResultReason.INCOMPATIBLE_CRYPTOGRAPHIC_USAGE_MASK, o.id + " lacks " + usage.wireName());
  }

  /** Request Cryptographic Parameters, else the key's first stored instance, else empty. */
  private static Ttlv params(Ttlv p, Obj o) {
    return p.child(CRYPTOGRAPHIC_PARAMETERS)
        .or(() -> o.first(CRYPTOGRAPHIC_PARAMETERS))
        .orElse(structure(CRYPTOGRAPHIC_PARAMETERS));
  }

  private static Integer field(Ttlv structure, Tag tag) {
    return structure.child(tag).map(Ttlv::intValue).orElse(null);
  }

  private static String jcaHash(Integer code, String otherwise) throws Fail {
    if (code == null) return otherwise;
    HashingAlgorithm h =
        HashingAlgorithm.fromCode(code)
            .orElseThrow(() -> new Fail(ResultReason.BAD_CRYPTOGRAPHIC_PARAMETERS, "unknown hash"));
    return switch (h) {
      case SHA_1 -> "SHA-1";
      case SHA_224 -> "SHA-224";
      case SHA_256 -> "SHA-256";
      case SHA_384 -> "SHA-384";
      case SHA_512 -> "SHA-512";
      case SHA_3_224 -> "SHA3-224";
      case SHA_3_256 -> "SHA3-256";
      case SHA_3_384 -> "SHA3-384";
      case SHA_3_512 -> "SHA3-512";
      default ->
          throw new Fail(ResultReason.UNSUPPORTED_CRYPTOGRAPHIC_PARAMETERS, h + " unsupported");
    };
  }

  private static String hmac(CryptographicAlgorithm alg) {
    if (alg == null) return null;
    return switch (alg) {
      case HMAC_SHA1 -> "HmacSHA1";
      case HMAC_SHA224 -> "HmacSHA224";
      case HMAC_SHA256 -> "HmacSHA256";
      case HMAC_SHA384 -> "HmacSHA384";
      case HMAC_SHA512 -> "HmacSHA512";
      case HMAC_MD5 -> "HmacMD5";
      case HMAC_SHA3_224 -> "HmacSHA3-224";
      case HMAC_SHA3_256 -> "HmacSHA3-256";
      case HMAC_SHA3_384 -> "HmacSHA3-384";
      case HMAC_SHA3_512 -> "HmacSHA3-512";
      default -> null;
    };
  }

  private static int required(Obj o, Tag tag, String operation) throws Fail {
    return o.first(tag)
        .map(Ttlv::intValue)
        .orElseThrow(
            () -> violation(ResultReason.MISSING_DATA, operation + " requires " + spaced(tag)));
  }

  private static int bits(java.security.Key key) {
    return key instanceof RSAKey r
        ? r.getModulus().bitLength()
        : ((ECKey) key).getParams().getCurve().getField().getFieldSize();
  }

  private byte[] randomBytes(int n) {
    byte[] b = new byte[n];
    random.nextBytes(b);
    return b;
  }

  Instant now() {
    return store.clock.instant().truncatedTo(ChronoUnit.SECONDS);
  }

  /**
   * Gives every object the State its dates give it now (KMIP 1.4 §3.22, transitions 4 and 6), as
   * keytend-kmip-server does: a Pre-Active object whose Activation Date has come is Active, and an Active
   * object whose Deactivation Date has come is Deactivated (also both, in that order). Revoked and
   * destroyed objects keep their State. Before each request message and each inspection of a State.
   */
  private void datesPassed() {
    Instant now = now();
    for (Obj o : objects.values()) {
      State s = o.state();
      if (s != State.PRE_ACTIVE && s != State.ACTIVE) continue;
      if (s == State.PRE_ACTIVE
          && o.first(ACTIVATION_DATE).map(d -> !d.instantValue().isAfter(now)).orElse(false)) {
        o.put(enumeration(STATE, State.ACTIVE));
        s = State.ACTIVE;
      }
      if (s == State.ACTIVE
          && o.first(DEACTIVATION_DATE).map(d -> !d.instantValue().isAfter(now)).orElse(false))
        o.put(enumeration(STATE, State.DEACTIVATED));
    }
  }

  /**
   * The 1.x attribute name for a tag: "CryptographicUsageMask" becomes "Cryptographic Usage Mask".
   */
  private static String spaced(Tag tag) {
    return tag.wireName().replaceAll("(?<=[a-z])(?=[A-Z])", " ");
  }

  private static Ttlv name(String value) {
    return structure(
        NAME,
        text(NAME_VALUE, value),
        enumeration(NAME_TYPE, Enums.NameType.UNINTERPRETED_TEXT_STRING));
  }

  private static Ttlv link(int type, String id) {
    return structure(LINK, enumeration(LINK_TYPE, type), text(LINKED_OBJECT_IDENTIFIER, id));
  }

  private static Integer linkType(Tag tag) {
    for (Map.Entry<Integer, Tag> e : LINK_TAGS.entrySet())
      if (e.getValue() == tag) return e.getKey();
    return null;
  }

  private static Map<Integer, Tag> linkTags() {
    Map<Integer, Tag> tags = new HashMap<>();
    for (LinkType t : LinkType.values()) {
      String name =
          switch (t) {
            case DERIVATION_BASE_OBJECT_LINK -> "DerivationObjectLink";
            case DERIVED_KEY_LINK -> "DerivedObjectLink";
            default -> t.wireName();
          };
      try {
        Tag tag = Tag.fromName(name);
        if (tag.definedIn(V3_0)) tags.put(t.code(), tag);
      } catch (IllegalArgumentException noThreeZeroTag) {
        // no 3.0 equivalent
      }
    }
    return Map.copyOf(tags);
  }

  /** Identifier, Reference and Name Reference values become Text Strings. */
  private static Ttlv plain(Ttlv n) {
    if (n.type() == Ttlv.Type.STRUCTURE)
      return structure(n.tag(), n.children().stream().map(InMemoryKmipServer::plain).toList());
    if (n.type() == Ttlv.Type.IDENTIFIER
        || n.type() == Ttlv.Type.REFERENCE
        || n.type() == Ttlv.Type.NAME_REFERENCE)
      return Ttlv.of(n.tag(), Ttlv.Type.TEXT_STRING, n.textValue());
    return n;
  }

  /** The contents of the DER element with {@code tag} at the start of {@code in}, advancing it. */
  private static ByteBuffer der(ByteBuffer in, int tag) {
    if ((in.get() & 0xff) != tag) throw new IllegalStateException("Unexpected DER tag");
    int length = in.get() & 0xff;
    if (length > 0x7f) {
      int octets = length & 0x7f;
      length = 0;
      for (int i = 0; i < octets; i++) length = (length << 8) | (in.get() & 0xff);
    }
    ByteBuffer value = in.slice();
    value.limit(length);
    in.position(in.position() + length);
    return value;
  }

  private static byte[] remaining(ByteBuffer b) {
    byte[] out = new byte[b.remaining()];
    b.get(out);
    return out;
  }

  private static byte[] concat(byte[] a, byte[] b) {
    byte[] out = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, out, a.length, b.length);
    return out;
  }

  @SafeVarargs
  private static <T> Set<T> union(Set<T>... sets) {
    Set<T> out = new HashSet<>();
    for (Set<T> s : sets) out.addAll(s);
    return Set.copyOf(out);
  }

  private static Fail violation(ResultReason reason, String message) {
    return new Fail(reason, message, true);
  }

  // ---------------------------------------------------------------------------------------------
  // Model

  /** An attribute identity: a standard tag, or a vendor (1.x x-/y- custom) attribute. */
  private record AttrKey(Tag tag, String vendor, String name) {
    static AttrKey std(Tag tag) {
      return new AttrKey(tag, null, null);
    }

    String legacyName() {
      return tag != null ? spaced(tag) : vendor + "-" + name;
    }

    boolean multi() {
      return tag == null || MULTI_VALUED.contains(tag);
    }
  }

  private record Attr(AttrKey key, Ttlv value) {}

  /** A fault armed with {@code failNext}: an application {@code fault}, or a protocol {@code reason}. */
  private record Armed(ServerOperation operation, Fault fault, ResultReason protocolReason) {
    /** The Result Reason it answers with; null for transport faults. */
    ResultReason reason() {
      return fault != null ? fault.reason() : protocolReason;
    }
  }

  /** A selected attribute; {@code linkType} narrows Link values (3.0 per-type link references). */
  private record Ref(AttrKey key, Integer linkType) {
    boolean test(AttrKey k, Ttlv value) {
      return k.equals(key) && (linkType == null || value.require(LINK_TYPE).intValue() == linkType);
    }
  }

  private static final class Obj {
    final String id;
    final ObjectType type;
    final Map<AttrKey, List<Ttlv>> attrs = new LinkedHashMap<>();

    /** KMIP 1.x Attribute Index of each stored value; stable when other instances are deleted. */
    final Map<AttrKey, List<Integer>> indexes = new HashMap<>();

    byte[] secret, der;
    PublicKey publicKey;
    PrivateKey privateKey;
    KeyFormatType format;
    int secretDataType;

    Obj(String id, ObjectType type) {
      this.id = id;
      this.type = type;
    }

    Obj copy() {
      Obj o = new Obj(id, type);
      attrs.forEach((k, values) -> o.attrs.put(k, new ArrayList<>(values)));
      indexes.forEach((k, ix) -> o.indexes.put(k, new ArrayList<>(ix)));
      o.secret = secret == null ? null : secret.clone();
      o.der = der;
      o.publicKey = publicKey;
      o.privateKey = privateKey;
      o.format = format;
      o.secretDataType = secretDataType;
      return o;
    }

    List<Ttlv> values(Tag tag) {
      return attrs.getOrDefault(AttrKey.std(tag), List.of());
    }

    Optional<Ttlv> first(Tag tag) {
      return values(tag).stream().findFirst();
    }

    int intAttr(Tag tag, int otherwise) {
      return first(tag).map(Ttlv::intValue).orElse(otherwise);
    }

    void put(Ttlv value) {
      attrs.put(AttrKey.std(value.standardTag().orElseThrow()), new ArrayList<>(List.of(value)));
    }

    void add(AttrKey key, Ttlv value) {
      List<Integer> ix = indexes(key);
      attrs.computeIfAbsent(key, k -> new ArrayList<>()).add(value);
      ix.add(ix.isEmpty() ? 0 : Collections.max(ix) + 1);
    }

    /** The Attribute Index of each value of {@code key}, in storage order. */
    List<Integer> indexes(AttrKey key) {
      int size = attrs.getOrDefault(key, List.of()).size();
      List<Integer> ix = indexes.get(key);
      if (ix == null || ix.size() != size) {
        ix = new ArrayList<>();
        for (int i = 0; i < size; i++) ix.add(i);
        indexes.put(key, ix);
      }
      return ix;
    }

    int index(AttrKey key, int position) {
      return indexes(key).get(position);
    }

    /** The storage position of the value with Attribute Index {@code index}, or -1. */
    int position(AttrKey key, int index) {
      return indexes(key).indexOf(index);
    }

    @SuppressWarnings("ListRemoveAmbiguous") // by position, in both lists
    void removeAt(AttrKey key, int position) {
      List<Integer> ix = indexes(key);
      List<Ttlv> values = attrs.get(key);
      values.remove(position);
      ix.remove(position);
      if (values.isEmpty()) {
        attrs.remove(key);
        indexes.remove(key);
      }
    }

    State state() {
      return State.fromCode(intAttr(STATE, 0)).orElseThrow();
    }

    boolean destroyed() {
      return state() == State.DESTROYED || state() == State.DESTROYED_COMPROMISED;
    }

    int usage() {
      return intAttr(CRYPTOGRAPHIC_USAGE_MASK, 0);
    }

    CryptographicAlgorithm algorithm() {
      return CryptographicAlgorithm.fromCode(intAttr(CRYPTOGRAPHIC_ALGORITHM, 0)).orElse(null);
    }
  }

  /** What replicas share: the objects, how new ones are named, the clock and the name rule. */
  private static final class Store {
    final Map<String, Obj> objects = new LinkedHashMap<>();
    int nextId = 1;

    /** The identifiers of new objects; null for mock-1, mock-2, ... */
    Supplier<String> identifiers;

    /** The source of Initial Date and the other dates the server sets. */
    Clock clock = Clock.systemUTC();

    /** Whether a Name may belong to only one object that is not destroyed. */
    boolean uniqueNames;

    /** Whether destroyed objects keep holding their names for {@link #uniqueNames}. */
    boolean destroyedKeepNames;

    /** The 1.x reason for a Name in use; null for Invalid Field. */
    ResultReason legacyNonUniqueReason;

    /** Whether a key that names a replacement may be re-keyed again. */
    boolean refuseSecondReKey;

    /** Whether a Re-key gives the replacement new dates instead of the old key's. */
    boolean freshDatesOnReKey;

    /** Whether a client's Add, Modify or Set Attribute of a Deactivation Date is refused. */
    boolean refuseClientDeactivationDate;

    /** Whether a client's second link of a single-instance type is refused. */
    boolean linkCardinality = true;

    /** The Lease Time every object states and Obtain Lease grants; null when the server does not lease. */
    Duration leaseTime;

    /** Whether Obtain Lease refuses an object that is not Active. */
    boolean leasesOnlyForActive;

    /** Client certificates Re-Provision retired, by SHA-256 fingerprint, in order. */
    final Map<String, X509Certificate> retired = new LinkedHashMap<>();

    /** The public keys Re-Provision has seen (hex SubjectPublicKeyInfo): never accepted again. */
    final Set<String> usedKeys = new HashSet<>();

    /** Whether Certify takes the Activation and Deactivation Dates asked as the validity. */
    boolean certifyHonorsDates = true;
  }

  private static final class Fail extends Exception {
    final ResultReason reason;
    final boolean violation;

    Fail(ResultReason reason, String message) {
      this(reason, message, false);
    }

    Fail(ResultReason reason, String message, boolean violation) {
      super(message, null, false, false);
      this.reason = reason;
      this.violation = violation;
    }
  }
}
