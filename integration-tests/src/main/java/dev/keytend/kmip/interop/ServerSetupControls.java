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

import static dev.keytend.kmip.model.Enums.*;
import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.*;
import java.util.*;

/**
 * Live controls for the generic suite's corrected setups, pinned to the keytend-kmip-server build
 * tools/kmip-server pins, with the configured setup of integration/keytend-kmip-server.
 * For each corrected scenario of the version it sends the request of the earlier suite
 * and requires the server's exact refusal (Result Reason and Result Message), then sends
 * the corrected setup and requires success and its result. A control that no longer matches
 * fails, so a changed server or a regressed scenario is visible.
 *
 * <p>Arguments: {@code <host> <port> <cert-directory> <version>}, the directory as for {@link
 * InteropApplication} with {@code admin-credential.properties}. Prints one line per check and exits
 * 1 when any fails.
 */
public final class ServerSetupControls {
  @FunctionalInterface
  interface Step {
    Result run() throws Exception;
  }

  @FunctionalInterface
  interface Checked {
    void run() throws Exception;
  }

  private final KmipClient client;
  private final ProtocolVersion version;
  private final Path certificates;
  private final Ttlv administrator;
  private final Set<String> resources = new LinkedHashSet<>();
  private int passed, failed;

  private ServerSetupControls(
      KmipClient client, ProtocolVersion version, Path certificates, Ttlv administrator) {
    this.client = client;
    this.version = version;
    this.certificates = certificates;
    this.administrator = administrator;
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      System.err.println("Usage: ServerSetupControls <host> <port> <cert-directory> <version>");
      System.exit(2);
    }
    Path certs = Path.of(args[2]);
    ProtocolVersion version = ProtocolVersion.valueOf("V" + args[3].replace('.', '_'));
    var ssl =
        Tls.context(certs.resolve("client.p12"), "changeit".toCharArray(), certs.resolve("ca.pem"));
    Ttlv administrator =
        InteropApplication.administrator(certs.resolve("admin-credential.properties"));
    if (administrator == null) throw new IllegalArgumentException("admin-credential.properties");
    int failed;
    try (var client =
        new KmipClient(new TlsTransport(args[0], Integer.parseInt(args[1]), ssl), version)) {
      var controls = new ServerSetupControls(client, version, certs, administrator);
      if (version.legacyAttributes()) controls.legacy();
      else controls.modern();
      System.out.println(
          "SUMMARY " + version + " pass=" + controls.passed + " fail=" + controls.failed);
      failed = controls.failed;
    }
    if (failed > 0) System.exit(1);
  }

  private void legacy() throws Exception {
    // GetUsageAllocation: the earlier suite allocated from a key without Usage Limits.
    String plain = aes(128);
    client.activate(plain);
    refused(
        "GetUsageAllocation without Usage Limits",
        () -> client.execute(allocation(plain)),
        ResultReason.ILLEGAL_OPERATION,
        "Object has no Usage Limits");
    accepted(
        "GetUsageAllocation from a key created with Usage Limits",
        () -> {
          String limited =
              created(
                  client.call(
                      Requests.create()
                          .add(enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY))
                          .template(
                              Attributes.algorithm(CryptographicAlgorithm.AES),
                              Attributes.length(128),
                              Attributes.usage(
                                  CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT),
                              Attributes.attribute(
                                  "Usage Limits",
                                  structure(
                                      USAGE_LIMITS,
                                      longInteger(USAGE_LIMITS_TOTAL, 10),
                                      enumeration(USAGE_LIMITS_UNIT, UsageLimitsUnit.OBJECT))))
                          .build()));
          client.activate(limited);
          client.call(allocation(limited));
        });

    // DeriveKey: the earlier suite derived from a password it never activated.
    String password = password();
    refused(
        "DeriveKey from a Pre-Active password",
        () -> client.execute(pbkdf2(password)),
        ResultReason.INVALID_FIELD,
        "Source object cannot be used to derive a key");
    accepted(
        "DeriveKey from an Active password",
        () -> {
          client.activate(password);
          String derived = created(client.call(pbkdf2(password)));
          var spec =
              new javax.crypto.spec.PBEKeySpec(
                  "test-password".toCharArray(), new byte[] {1, 2, 3, 4, 5, 6, 7, 8}, 1000, 128);
          byte[] expected =
              javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                  .generateSecret(spec)
                  .getEncoded();
          require(
              Arrays.equals(expected, InteropSuite.keyBytes(client.get(derived).requirePayload())),
              "PBKDF2 differs from JCE");
        });

    if (version == ProtocolVersion.V1_4) {
      refused(
          "Import with creation-style attributes",
          () ->
              client.execute(
                  Requests.importObject()
                      .add(
                          text(UNIQUE_IDENTIFIER, "keytend-import-" + UUID.randomUUID()),
                          enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY),
                          bool(REPLACE_EXISTING, false),
                          Attributes.template(
                              Attributes.usage(
                                  CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT)),
                          ManagedObjects.rawSymmetricKey(new byte[16], CryptographicAlgorithm.AES))
                      .build()),
          ResultReason.MISSING_DATA,
          "Required imported attribute missing");
      accepted("Import restoring the server's Export", this::restore);
    }

    // Certify: the earlier suite certified a server-generated public key with client.csr, which is
    // for the client's key. With the right key, keytend-kmip-server still needs the issuing CA
    // named.
    Result pair =
        client.call(
            Requests.createKeyPair()
                .add(
                    structure(
                        COMMON_TEMPLATE_ATTRIBUTE,
                        Attributes.algorithm(CryptographicAlgorithm.RSA),
                        Attributes.length(2048),
                        Attributes.usage(
                            CryptographicUsageMask.SIGN, CryptographicUsageMask.VERIFY)))
                .build());
    String serverPublic = pair.requirePayload().require(PUBLIC_KEY_UNIQUE_IDENTIFIER).textValue();
    resources.add(pair.requirePayload().require(PRIVATE_KEY_UNIQUE_IDENTIFIER).textValue());
    resources.add(serverPublic);
    refused(
        "Certify a public key the request is not for",
        () ->
            client.execute(
                Requests.certify()
                    .uniqueIdentifier(serverPublic)
                    .add(
                        enumeration(CERTIFICATE_REQUEST_TYPE, CertificateRequestType.PKCS_10),
                        bytes(CERTIFICATE_REQUEST, pem("client.csr")))
                    .template()
                    .build()),
        ResultReason.INVALID_FIELD,
        "Certificate Request key does not match the Public Key");
    String subject =
        created(
            client.call(
                Requests.registerObject(
                    InteropSuite.rsaPublicKey(
                        InteropSuite.x509(certificates, "client.pem").getPublicKey()),
                    Attributes.usage(CryptographicUsageMask.VERIFY))));
    refused(
        "Certify the request's key without an issuing CA",
        () -> client.execute(certify(subject)),
        ResultReason.PERMISSION_DENIED,
        "Certify requires a Certificate Link to a caller-owned issuing CA certificate");
    String ca = InteropSuite.registerIssuingCa(client, certificates, resources);
    String[] certificate = new String[1];
    java.security.cert.X509Certificate[] issued = new java.security.cert.X509Certificate[1];
    accepted(
        "Certify the request's key, issued by the named CA",
        () -> {
          certificate[0] =
              created(
                  client.call(certify(subject, Attributes.link(LinkType.CERTIFICATE_LINK, ca))));
          issued[0] =
              InteropSuite.verifyIssuedCertificate(client, certificates, certificate[0], true);
        });

    // ReCertify: the earlier suite re-certified the public key, with no request.
    refused(
        "ReCertify a public key",
        () -> client.execute(Requests.reCertify().uniqueIdentifier(serverPublic).build()),
        ResultReason.PERMISSION_DENIED,
        "Object type cannot be certified");
    if (certificate[0] != null) {
      accepted(
          "ReCertify the certificate with its request",
          () -> {
            String renewed =
                created(
                    client.call(
                        Requests.reCertify()
                            .uniqueIdentifier(certificate[0])
                            .add(
                                enumeration(
                                    CERTIFICATE_REQUEST_TYPE, CertificateRequestType.PKCS_10),
                                bytes(CERTIFICATE_REQUEST, pem("client.csr")))
                            .build()));
            InteropSuite.verifyRenewedCertificate(
                client, certificates, certificate[0], renewed, issued[0], true);
          });
    }

    validate();

    if (version.atLeast(ProtocolVersion.V1_2)) {
      // Create Split Key: the earlier suite asked for Symmetric Key objects.
      String key = aes(256);
      client.activate(key);
      refused(
          "CreateSplitKey of Symmetric Key objects",
          () ->
              client.execute(
                  Requests.createSplitKey()
                      .add(
                          enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY),
                          text(UNIQUE_IDENTIFIER, key),
                          integer(SPLIT_KEY_PARTS, 3),
                          integer(SPLIT_KEY_THRESHOLD, 3),
                          enumeration(SPLIT_KEY_METHOD, SplitKeyMethod.XOR),
                          Attributes.template(
                              Attributes.algorithm(CryptographicAlgorithm.AES),
                              Attributes.length(128),
                              Attributes.usage(
                                  CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT)))
                      .build()),
          ResultReason.INVALID_FIELD,
          "Create Split Key requires Object Type Split Key");
      accepted(
          "CreateSplitKey of Split Key objects, joined",
          () -> splitAndJoin(key, Attributes.template()));
    }

    // Poll and Cancel of a correlation value no operation has. The earlier suite required Poll to
    // succeed; Item Not Found is the 1.x answer.
    refused(
        "Poll unknown correlation",
        () ->
            client.execute(
                Requests.poll()
                    .add(bytes(ASYNCHRONOUS_CORRELATION_VALUE, new byte[] {1, 2, 3}))
                    .build()),
        ResultReason.ITEM_NOT_FOUND,
        "No outstanding asynchronous operation has this correlation value");
    cancelUnknown();
    cleanup();
  }

  private void modern() throws Exception {
    refused(
        "Import with creation-style attributes",
        () ->
            client.execute(
                Requests.importObject()
                    .uniqueIdentifier("keytend-import-" + UUID.randomUUID())
                    .add(
                        enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY),
                        bool(REPLACE_EXISTING, false),
                        ModernAttributes.of(integer(CRYPTOGRAPHIC_USAGE_MASK, 12)),
                        ManagedObjects.rawSymmetricKey(new byte[16], CryptographicAlgorithm.AES))
                    .build()),
        ResultReason.INVALID_FIELD,
        "Required imported attribute missing");
    accepted("Import restoring the server's Export", this::restore);

    String key = aes(256);
    client.activate(key);
    refused(
        "CreateSplitKey of Symmetric Key objects",
        () -> client.execute(oldSplit(key, ObjectType.SYMMETRIC_KEY)),
        ResultReason.ILLEGAL_OBJECT_TYPE,
        "Create Split Key requires Object Type Split Key");
    refused(
        "CreateSplitKey of Split Key objects without Attributes",
        () -> client.execute(oldSplit(key, ObjectType.SPLIT_KEY)),
        ResultReason.INVALID_FIELD,
        "Invalid field or missing required data");
    accepted(
        "CreateSplitKey of Split Key objects with Attributes, joined",
        () -> splitAndJoin(key, ModernAttributes.of()));

    // AdjustAttribute: the earlier suite incremented the usage mask of an Active key.
    refused(
        "AdjustAttribute of a usage mask",
        () ->
            client.execute(
                Requests.adjustAttribute()
                    .uniqueIdentifier(key)
                    .attributeReference(CRYPTOGRAPHIC_USAGE_MASK)
                    .add(
                        enumeration(ADJUSTMENT_TYPE, AdjustmentType.INCREMENT),
                        integer(ADJUSTMENT_VALUE, CryptographicUsageMask.WRAP_KEY.code()))
                    .build()),
        ResultReason.READ_ONLY_ATTRIBUTE,
        "Attribute is read-only");
    accepted(
        "AdjustAttribute of a Deactivation Date",
        () -> {
          String uid = aes(128);
          Instant date =
              Instant.now()
                  .plus(Duration.ofDays(1))
                  .truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
          client.call(
              Requests.setAttribute()
                  .uniqueIdentifier(uid)
                  .newAttribute(dateTime(DEACTIVATION_DATE, date))
                  .build());
          client.call(
              Requests.adjustAttribute()
                  .uniqueIdentifier(uid)
                  .attributeReference(DEACTIVATION_DATE)
                  .add(
                      enumeration(ADJUSTMENT_TYPE, AdjustmentType.INCREMENT),
                      interval(ADJUSTMENT_VALUE, 3600))
                  .build());
          Instant adjusted =
              client
                  .call(
                      Requests.getAttributes()
                          .uniqueIdentifier(uid)
                          .add(ModernAttributes.reference(DEACTIVATION_DATE))
                          .build())
                  .requirePayload()
                  .require(ATTRIBUTES)
                  .require(DEACTIVATION_DATE)
                  .instantValue();
          require(adjusted.equals(date.plusSeconds(3600)), "Adjusted " + adjusted);
        });

    // GetUsageAllocation: the earlier suite set Usage Limits on a key that had already been used.
    String used = aes(256);
    client.activate(used);
    client.call(
        Requests.encrypt()
            .uniqueIdentifier(used)
            .cryptographicParameters(
                enumeration(CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.AES),
                enumeration(BLOCK_CIPHER_MODE, BlockCipherMode.CBC),
                enumeration(PADDING_METHOD, PaddingMethod.PKCS5))
            .data("used".getBytes(StandardCharsets.UTF_8))
            .add(bytes(IV_COUNTER_NONCE, new byte[16]))
            .build());
    Ttlv limits =
        Structures.structure(
            USAGE_LIMITS,
            longInteger(USAGE_LIMITS_TOTAL, 10),
            enumeration(USAGE_LIMITS_UNIT, UsageLimitsUnit.OBJECT));
    refused(
        "SetAttribute Usage Limits on a used key",
        () ->
            client.execute(
                Requests.setAttribute().uniqueIdentifier(used).newAttribute(limits).build()),
        ResultReason.ATTRIBUTE_READ_ONLY,
        "Attribute is read-only");
    accepted(
        "GetUsageAllocation from a key created with Usage Limits",
        () -> {
          String uid =
              created(
                  client.call(
                      Requests.create()
                          .add(
                              enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY),
                              ModernAttributes.of(
                                  enumeration(CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.AES),
                                  integer(CRYPTOGRAPHIC_LENGTH, 128),
                                  integer(CRYPTOGRAPHIC_USAGE_MASK, 12),
                                  limits))
                          .build()));
          client.activate(uid);
          client.call(allocation(uid));
        });

    validate();

    // SetEndpointRole: Client needs a client endpoint in this principal's policy (the configured
    // setup gives one only to the reverse-only principals of EndpointRoleReversal).
    refused(
        "SetEndpointRole Client without a client endpoint",
        () ->
            client.execute(
                Requests.setEndpointRole()
                    .add(enumeration(ENDPOINT_ROLE, EndpointRole.CLIENT))
                    .build()),
        ResultReason.PERMISSION_DENIED,
        "Server policy configures no client endpoint for this principal");
    accepted(
        "SetEndpointRole Server",
        () ->
            require(
                client
                        .call(
                            Requests.setEndpointRole()
                                .add(enumeration(ENDPOINT_ROLE, EndpointRole.SERVER))
                                .build())
                        .requirePayload()
                        .require(ENDPOINT_ROLE)
                        .intValue()
                    == EndpointRole.SERVER.code(),
                "Endpoint role"));

    refused(
        "Poll unknown token",
        () ->
            client.execute(
                Requests.poll().add(bytes(ASYNCHRONOUS_CORRELATION_VALUE, new byte[] {1})).build()),
        ResultReason.INVALID_ASYNCHRONOUS_CORRELATION_VALUE,
        null);
    cancelUnknown();

    if (version == ProtocolVersion.V3_0) systemObjects();
    cleanup();
  }

  private void systemObjects() throws Exception {
    String required = "System Objects require a verified user credential in the request header";
    refused(
        "Login without a header credential",
        () -> client.execute(Requests.login().build()),
        ResultReason.PERMISSION_DENIED,
        "Login requires a password credential");
    accepted(
        "Login and Logout with the administrator's credential",
        () -> {
          Ttlv ticket = administrative(Requests.login().build()).requirePayload().require(TICKET);
          client.call(Requests.logout().add(ticket).build());
        });
    Request group =
        Requests.createGroup().attributes(text(NAME, "group-" + UUID.randomUUID())).build();
    refused(
        "CreateGroup without a header credential",
        () -> client.execute(group),
        ResultReason.PERMISSION_DENIED,
        required);
    accepted(
        "CreateGroup and Obliterate with the administrator's credential",
        () ->
            administrative(
                Requests.obliterate()
                    .uniqueIdentifier(administrative(group).uniqueIdentifier())
                    .build()));
    Request credential =
        Requests.createCredential()
            .add(
                enumeration(CREDENTIAL_TYPE, CredentialType.PASSWORD),
                ModernAttributes.of(),
                structure(PASSWORD_CREDENTIAL, text(PASSWORD, "test-password")))
            .build();
    refused(
        "CreateCredential without a header credential",
        () -> client.execute(credential),
        ResultReason.PERMISSION_DENIED,
        required);
    Request user =
        Requests.createUser()
            .add(ModernAttributes.of(text(NAME, "user-" + UUID.randomUUID())))
            .build();
    refused(
        "CreateUser without a header credential",
        () -> client.execute(user),
        ResultReason.PERMISSION_DENIED,
        required);
    refused(
        "CreateUser without a Credential Link",
        () -> administrativeResult(user),
        ResultReason.INVALID_FIELD,
        "A User requires one to eight Credential Links");
    accepted(
        "CreateCredential and CreateUser linking it, with the administrator's credential",
        () -> {
          String password = administrative(credential).uniqueIdentifier();
          String created =
              administrative(
                      Requests.createUser()
                          .add(
                              ModernAttributes.of(
                                  text(NAME, "user-" + UUID.randomUUID()),
                                  reference(CREDENTIAL_LINK, password)))
                          .build())
                  .uniqueIdentifier();
          administrative(Requests.obliterate().uniqueIdentifier(created).build());
          administrative(Requests.obliterate().uniqueIdentifier(password).build());
        });
  }

  private void validate() {
    // The unchanged scenario needs only server configuration: --validation-ca names the trust
    // anchor (without it, see the minimal-setup run).
    accepted(
        "Validate against the configured trust anchor",
        () -> {
          Request request =
              version.legacyAttributes()
                  ? Requests.validate()
                      .add(ManagedObjects.certificate(CertificateType.X_509, pem("ca.pem")))
                      .build()
                  : Requests.validate()
                      .uniqueIdentifier(
                          created(
                              client.call(
                                  CertificateRegistration.of(
                                          InteropSuite.x509(certificates, "ca.pem"),
                                          UsageMask.of(
                                              CryptographicUsageMask.CERTIFICATE_SIGN,
                                              CryptographicUsageMask.CRL_SIGN))
                                      .build())))
                      .build();
          require(
              client.call(request).requirePayload().require(VALIDITY_INDICATOR).intValue()
                  == ValidityIndicator.VALID.code(),
              "Validity");
        });
  }

  private void cancelUnknown() {
    accepted(
        "Cancel unknown correlation answers Unavailable",
        () ->
            require(
                client
                        .call(
                            Requests.cancel()
                                .add(bytes(ASYNCHRONOUS_CORRELATION_VALUE, new byte[] {1, 2, 3}))
                                .build())
                        .requirePayload()
                        .require(CANCELLATION_RESULT)
                        .intValue()
                    == CancellationResult.UNAVAILABLE.code(),
                "Cancellation Result"));
  }

  private void restore() throws Exception {
    var fixture = InteropSuite.prepareRestore(client, resources);
    InteropSuite.verifyRestore(
        client,
        fixture,
        client.call(InteropSuite.restoreRequest(version, fixture.id(), fixture.exported())));
  }

  private void splitAndJoin(String key, Ttlv attributes) throws Exception {
    byte[] material = InteropSuite.keyBytes(client.get(key).requirePayload());
    List<String> parts =
        client
            .call(InteropSuite.splitRequest(key, attributes))
            .requirePayload()
            .children(UNIQUE_IDENTIFIER)
            .stream()
            .map(Ttlv::textValue)
            .toList();
    require(parts.size() == 3, "Split parts");
    resources.addAll(parts);
    Request.Builder join =
        Requests.joinSplitKey().add(enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY));
    parts.forEach(join::uniqueIdentifier);
    String joined = created(client.call(join.build()));
    require(
        Arrays.equals(material, InteropSuite.keyBytes(client.get(joined).requirePayload())),
        "Joined material");
  }

  private static Request oldSplit(String key, ObjectType type) {
    return Requests.createSplitKey()
        .add(
            enumeration(OBJECT_TYPE, type),
            text(UNIQUE_IDENTIFIER, key),
            integer(SPLIT_KEY_PARTS, 3),
            integer(SPLIT_KEY_THRESHOLD, 3),
            enumeration(SPLIT_KEY_METHOD, SplitKeyMethod.XOR))
        .build();
  }

  private Request certify(String subject, Ttlv... template) throws Exception {
    return Requests.certify()
        .uniqueIdentifier(subject)
        .add(
            enumeration(CERTIFICATE_REQUEST_TYPE, CertificateRequestType.PKCS_10),
            bytes(CERTIFICATE_REQUEST, pem("client.csr")))
        .template(template)
        .build();
  }

  private static Request allocation(String id) {
    return Requests.getUsageAllocation()
        .uniqueIdentifier(id)
        .add(longInteger(USAGE_LIMITS_COUNT, 1))
        .build();
  }

  private Request pbkdf2(String base) {
    return Requests.deriveKey()
        .add(
            enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY),
            text(UNIQUE_IDENTIFIER, base),
            enumeration(DERIVATION_METHOD, DerivationMethod.PBKDF2),
            structure(
                DERIVATION_PARAMETERS,
                structure(
                    CRYPTOGRAPHIC_PARAMETERS,
                    enumeration(HASHING_ALGORITHM, HashingAlgorithm.SHA_256)),
                bytes(SALT, new byte[] {1, 2, 3, 4, 5, 6, 7, 8}),
                integer(ITERATION_COUNT, 1000)),
            Attributes.template(
                Attributes.algorithm(CryptographicAlgorithm.AES),
                Attributes.length(128),
                Attributes.usage(CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT)))
        .build();
  }

  private String password() throws Exception {
    return created(
        client.call(
            Requests.registerObject(
                ManagedObjects.secretData(
                    SecretDataType.PASSWORD,
                    ManagedObjects.keyBlock(
                        KeyFormatType.RAW,
                        bytes(KEY_MATERIAL, "test-password".getBytes(StandardCharsets.UTF_8)),
                        null,
                        null)),
                Attributes.usage(CryptographicUsageMask.DERIVE_KEY))));
  }

  private String aes(int bits) throws Exception {
    return created(
        client.call(
            Requests.createSymmetricKey(
                CryptographicAlgorithm.AES,
                bits,
                CryptographicUsageMask.ENCRYPT,
                CryptographicUsageMask.DECRYPT)));
  }

  private Result administrative(Request request) throws Exception {
    return administrativeResult(request).requireSuccess();
  }

  private Result administrativeResult(Request request) throws Exception {
    return client
        .batch(List.of(request), RequestOptions.builder().authentication(administrator).build())
        .results()
        .get(0);
  }

  private String created(Result r) {
    resources.add(r.uniqueIdentifier());
    return r.uniqueIdentifier();
  }

  private byte[] pem(String name) throws Exception {
    return InteropSuite.pem(certificates, name);
  }

  /**
   * The earlier setup: the server must refuse it with {@code reason} and, when given, exactly {@code
   * message}.
   */
  private void refused(String name, Step step, ResultReason reason, String message) {
    String detail;
    boolean ok;
    try {
      Result r = step.run();
      ok =
          !r.successful()
              && r.hasReason(reason)
              && (message == null || message.equals(r.message()));
      detail = r.successful() ? "succeeded" : r.reason() + " " + r.message();
    } catch (Exception | AssertionError e) {
      ok = false;
      detail = e.toString();
    }
    record("old setup refused: " + name, ok, (ok ? reason.wireName() + " " : "") + detail);
  }

  /** The corrected setup: it must succeed. */
  private void accepted(String name, Checked body) {
    try {
      body.run();
      record("corrected setup: " + name, true, "");
    } catch (Exception | AssertionError e) {
      record(
          "corrected setup: " + name,
          false,
          e + (e instanceof KmipException k ? " " + k.result().message() : ""));
    }
  }

  private void record(String name, boolean ok, String detail) {
    if (ok) passed++;
    else failed++;
    System.out.println(
        (ok ? "PASS " : "FAIL ") + version + " " + name + (detail.isEmpty() ? "" : ": " + detail));
  }

  private void cleanup() {
    for (String id : resources) {
      try {
        client.execute(Requests.revoke(id, RevocationReasonCode.CESSATION_OF_OPERATION, "cleanup"));
        client.execute(Requests.destroy().uniqueIdentifier(id).build());
      } catch (Exception ignored) {
        // Best effort on a throwaway store.
      }
    }
  }

  private static void require(boolean condition, String message) {
    InteropSuite.require(condition, message);
  }
}
