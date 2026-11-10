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

package dev.keytend.kmip.interop;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static java.nio.charset.StandardCharsets.UTF_8;

import dev.keytend.kmip.client.Messages;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.nio.file.*;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * The live catalog run against the in-process InMemoryKmipServer (keytend-kmip-testing) instead of a server, so
 * every fixture request is built, version-validated and encoded for a given version without a
 * container. The second identity ("client-b") sees a tiny access policy that mimics the live
 * grant adapters (nothing, an exact-object Get grant, or a list-only grant), so the permission
 * scenarios reach their write attempts. TLS, restart, reference-client and proxy scenarios still
 * point at a closed local port and end BLOCKED_ENV; they build only simple Get/Create requests.
 */
final class CatalogDryRun implements AutoCloseable {
  enum Grant {
    NONE,
    GET,
    LIST
  }

  record Exchange(Ttlv request, Ttlv response) {}

  final KmipTransport peer;
  final CatalogFixture fixture;
  final byte[] known = new byte[32];

  /** Every exchange of the owner identity, in order (the second identity's are not recorded). */
  final List<Exchange> exchanges = Collections.synchronizedList(new ArrayList<>());

  private volatile Grant grant = Grant.NONE;

  CatalogDryRun(String server, ProtocolVersion version, Path certs) throws Exception {
    peer = mock(version);
    int closed;
    try (ServerSocket s = new ServerSocket(0)) {
      closed = s.getLocalPort();
    }
    fixture =
        new CatalogFixture(
            ROOT,
            server,
            "localhost",
            closed,
            certs,
            version,
            "dry-run",
            "sha256:" + "0".repeat(64),
            "uncommitted",
            "0".repeat(64),
            recording(),
            principal -> principal.equals("client-b") ? restricted(version) : recording());
    fixture.readOnlyRole = true;
    fixture.grant = () -> grant = Grant.GET;
    fixture.revokeGrant = () -> grant = Grant.NONE;
    fixture.listOnlyGrant = () -> grant = Grant.LIST;
    // The same bytes the independent reference client registers (KEY-01's known answer).
    for (int i = 0; i < known.length; i++) known[i] = (byte) i;
    fixture.knownUid =
        fixture.client.register(
            ManagedObjects.rawSymmetricKey(known, Enums.CryptographicAlgorithm.AES),
            Attributes.algorithm(Enums.CryptographicAlgorithm.AES),
            Attributes.length(256),
            Attributes.usage(
                Enums.CryptographicUsageMask.ENCRYPT, Enums.CryptographicUsageMask.DECRYPT));
    fixture.knownSha = Catalog.digest(known);
  }

  private static final Path ROOT =
      Path.of(System.getProperty("project.root", "..")).toAbsolutePath().normalize();

  /** The SDK's published in-memory KMIP server. */
  static KmipTransport mock(ProtocolVersion version) {
    return new InMemoryKmipServer(version);
  }

  /** Runs one catalog case and returns the owner exchanges it made; its outcome is ignored. */
  List<Exchange> exchangesOf(String id) {
    int from = exchanges.size();
    try {
      new CatalogLiveSuite(fixture).execute(id);
    } catch (Exception | AssertionError ignored) {
      // Only the requests matter here; the full-catalog test classifies outcomes.
    }
    return List.copyOf(exchanges.subList(from, exchanges.size()));
  }

  private KmipTransport recording() {
    return request -> {
      Ttlv response = isExport(request) ? export(request) : peer.exchange(request);
      exchanges.add(new Exchange(request, response));
      return response;
    };
  }

  private static boolean isExport(Ttlv request) {
    List<Ttlv> items = request.children(BATCH_ITEM);
    return items.size() == 1
        && items.get(0).require(OPERATION).intValue() == Operation.EXPORT.code();
  }

  /**
   * The in-memory server has no Export, so the dry run answers one the way a server does (KMIP 1.4
   * §4.40, 2.1 §6.1.20): the object from the in-memory server's Get, and all its attributes from
   * Get Attributes, in the version's own form (repeated Attribute fields in 1.x, one Attributes
   * structure in 2.x and 3.0), including the Unique Identifier attribute. A failed Get (missing or
   * non-extractable object) is answered as a failed Export. This lets the contract tests see the
   * Import the fixtures build from a real export.
   */
  private Ttlv export(Ttlv request) throws IOException {
    Ttlv get = peer.exchange(withOperation(request, Operation.GET));
    Ttlv item = get.require(BATCH_ITEM);
    if (item.require(RESULT_STATUS).intValue() != 0) return withOperation(get, Operation.EXPORT);
    Ttlv object = item.require(RESPONSE_PAYLOAD);
    Ttlv listed =
        peer.exchange(withOperation(request, Operation.GET_ATTRIBUTES))
            .require(BATCH_ITEM)
            .require(RESPONSE_PAYLOAD);
    String uid = object.require(UNIQUE_IDENTIFIER).textValue();
    List<Ttlv> payload = new ArrayList<>();
    payload.add(object.require(OBJECT_TYPE));
    payload.add(object.require(UNIQUE_IDENTIFIER));
    Optional<Ttlv> modern = listed.child(ATTRIBUTES);
    if (modern.isPresent()) {
      List<Ttlv> attributes = new ArrayList<>(modern.get().children());
      if (modern.get().child(UNIQUE_IDENTIFIER).isEmpty())
        attributes.add(0, text(UNIQUE_IDENTIFIER, uid));
      payload.add(structure(ATTRIBUTES, attributes));
    } else {
      List<Ttlv> attributes = listed.children(ATTRIBUTE);
      if (attributes.stream()
          .noneMatch(a -> a.require(ATTRIBUTE_NAME).textValue().equals("Unique Identifier")))
        payload.add(
            structure(
                ATTRIBUTE, text(ATTRIBUTE_NAME, "Unique Identifier"), text(ATTRIBUTE_VALUE, uid)));
      payload.addAll(attributes);
    }
    for (Ttlv field : object.children())
      if (field.tag() != OBJECT_TYPE.code() && field.tag() != UNIQUE_IDENTIFIER.code())
        payload.add(field);
    List<Ttlv> answer = new ArrayList<>();
    for (Ttlv field : item.children())
      answer.add(
          field.tag() == RESPONSE_PAYLOAD.code()
              ? structure(RESPONSE_PAYLOAD, payload)
              : field.tag() == OPERATION.code()
                  ? enumeration(OPERATION, Operation.EXPORT.code())
                  : field);
    List<Ttlv> message = new ArrayList<>();
    for (Ttlv field : get.children())
      message.add(field.tag() == BATCH_ITEM.code() ? structure(BATCH_ITEM, answer) : field);
    return structure(get.tag(), message);
  }

  /** {@code message} with the operation of its batch item replaced (same payload). */
  private static Ttlv withOperation(Ttlv message, Operation operation) {
    List<Ttlv> fields = new ArrayList<>();
    for (Ttlv field : message.children()) {
      if (field.tag() != BATCH_ITEM.code()) {
        fields.add(field);
        continue;
      }
      List<Ttlv> item = new ArrayList<>();
      for (Ttlv part : field.children())
        item.add(part.tag() == OPERATION.code() ? enumeration(OPERATION, operation.code()) : part);
      fields.add(structure(BATCH_ITEM, item));
    }
    return structure(message.tag(), fields);
  }

  private KmipTransport restricted(ProtocolVersion version) {
    return request -> {
      for (Ttlv item : request.children(BATCH_ITEM)) {
        int op = item.require(OPERATION).intValue();
        boolean allowed =
            op == Operation.QUERY.code()
                || op == Operation.DISCOVER_VERSIONS.code()
                || (grant == Grant.GET
                    && (op == Operation.GET.code() || op == Operation.GET_ATTRIBUTES.code()))
                || (grant == Grant.LIST && op == Operation.LOCATE.code());
        if (!allowed) return denied(request, version);
      }
      return peer.exchange(request);
    };
  }

  private static Ttlv denied(Ttlv request, ProtocolVersion version) {
    List<Ttlv> header = new ArrayList<>();
    header.add(Messages.protocolVersion(version));
    header.add(dateTime(TIME_STAMP, Instant.now().truncatedTo(ChronoUnit.SECONDS)));
    List<Ttlv> items = request.children(BATCH_ITEM);
    if (version != ProtocolVersion.V3_0) header.add(integer(BATCH_COUNT, items.size()));
    List<Ttlv> fields = new ArrayList<>();
    fields.add(structure(RESPONSE_HEADER, header));
    for (Ttlv item : items) {
      List<Ttlv> result = new ArrayList<>();
      item.child(OPERATION).ifPresent(result::add);
      item.child(UNIQUE_BATCH_ITEM_ID).ifPresent(result::add);
      result.add(enumeration(RESULT_STATUS, 1));
      result.add(enumeration(RESULT_REASON, Enums.ResultReason.PERMISSION_DENIED));
      result.add(text(RESULT_MESSAGE, "Dry run: identity not permitted"));
      fields.add(structure(BATCH_ITEM, result));
    }
    return structure(RESPONSE_MESSAGE, fields);
  }

  private static Path certificates;

  /**
   * A CA and a "chain-server" identity (a localhost leaf signed by the CA, with its chain), as
   * keytool would make them, built with Bouncy Castle: enough for the certificate and
   * application-TLS scenarios. The CA ({@code ca.pem}) is RSA 2048, {@code CN=dry-run-ca}, with a
   * critical Basic Constraints CA extension and a critical Key Usage of keyCertSign and cRLSign;
   * the leaf ({@code chain-server.p12}, alias {@code server}, with the CA in its chain) is RSA
   * 2048, {@code CN=localhost}, with {@code dns:localhost} and a Key Usage of digitalSignature and
   * keyEncipherment, as the catalog PKI has them; both valid for two days, with key identifiers.
   * The replacement identity is a copy, since the dry run checks requests, not the rotation
   * itself. {@code ec.der} is a self-signed EC (P-256) certificate, without Key Usage, for the EC
   * certificate registration shape. Made once per JVM.
   */
  static synchronized Path certificates() throws Exception {
    if (certificates != null) return certificates;
    Path dir = Files.createTempDirectory("keytend-catalog-dry-run-");
    char[] password = "changeit".toCharArray();
    KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
    rsa.initialize(2048);
    KeyPair caKey = rsa.generateKeyPair(), serverKey = rsa.generateKeyPair();
    X509Certificate ca =
        certificate("dry-run-ca", caKey.getPublic(), null, caKey.getPrivate(), true, null);
    X509Certificate server =
        certificate("localhost", serverKey.getPublic(), ca, caKey.getPrivate(), false, "localhost");
    Files.writeString(
        dir.resolve("ca.pem"),
        "-----BEGIN CERTIFICATE-----\n"
            + Base64.getMimeEncoder(64, "\n".getBytes(UTF_8)).encodeToString(ca.getEncoded())
            + "\n-----END CERTIFICATE-----\n");
    KeyStore chain = KeyStore.getInstance("PKCS12");
    chain.load(null, null);
    chain.setKeyEntry(
        "server",
        serverKey.getPrivate(),
        password,
        new java.security.cert.Certificate[] {server, ca});
    try (var out = Files.newOutputStream(dir.resolve("chain-server.p12"))) {
      chain.store(out, password);
    }
    Files.copy(dir.resolve("chain-server.p12"), dir.resolve("replacement-server.p12"));
    KeyPairGenerator ec = KeyPairGenerator.getInstance("EC");
    ec.initialize(new ECGenParameterSpec("secp256r1"));
    KeyPair ecKey = ec.generateKeyPair();
    Files.write(
        dir.resolve("ec.der"),
        certificate("dry-run-ec", ecKey.getPublic(), null, ecKey.getPrivate(), false, null)
            .getEncoded());
    dir.toFile().deleteOnExit();
    try (var files = Files.list(dir)) {
      files.forEach(p -> p.toFile().deleteOnExit());
    }
    return certificates = dir;
  }

  /**
   * A certificate for {@code CN=commonName}, self-signed when {@code issuer} is null, valid from
   * now for two days, with a Subject Key Identifier (and an Authority Key Identifier when issued),
   * a critical CA Basic Constraints extension when {@code ca}, and a DNS name when {@code dns} is
   * not null.
   */
  private static X509Certificate certificate(
      String commonName,
      PublicKey key,
      X509Certificate issuer,
      PrivateKey signer,
      boolean ca,
      String dns)
      throws Exception {
    X500Name subject = new X500NameBuilder(BCStyle.INSTANCE).addRDN(BCStyle.CN, commonName).build();
    Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
    X509v3CertificateBuilder b =
        new JcaX509v3CertificateBuilder(
            issuer == null
                ? subject
                : X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded()),
            new BigInteger(64, new SecureRandom()),
            Date.from(now),
            Date.from(now.plus(2, ChronoUnit.DAYS)),
            subject,
            key);
    JcaX509ExtensionUtils ids = new JcaX509ExtensionUtils();
    if (ca) b.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
    // The Key Usage of the catalog PKI (integration/catalog/generate-pki.sh): a 1.x server may
    // refuse a usage mask the extension does not grant (KMIP 1.4 Table 96).
    if (ca)
      b.addExtension(
          Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
    else if (dns != null)
      b.addExtension(
          Extension.keyUsage,
          false,
          new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
    if (dns != null)
      b.addExtension(
          Extension.subjectAlternativeName,
          false,
          new GeneralNames(new GeneralName(GeneralName.dNSName, dns)));
    b.addExtension(Extension.subjectKeyIdentifier, false, ids.createSubjectKeyIdentifier(key));
    if (issuer != null)
      b.addExtension(
          Extension.authorityKeyIdentifier,
          false,
          ids.createAuthorityKeyIdentifier(issuer.getPublicKey()));
    String algorithm = signer.getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256withRSA";
    return new JcaX509CertificateConverter()
        .getCertificate(b.build(new JcaContentSignerBuilder(algorithm).build(signer)));
  }

  @Override
  public void close() throws Exception {
    fixture.close();
  }
}
