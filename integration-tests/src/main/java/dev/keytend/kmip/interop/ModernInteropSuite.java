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
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/** Workflows for the modern attribute model, administrative operations and KMIP 3.0 PQC KEMs. */
public final class ModernInteropSuite {
  @FunctionalInterface
  interface Task {
    void run() throws Exception;
  }

  private final java.nio.file.Path certificates;
  private final KmipClient client;
  private final String server;
  private final String identity;
  private final Ttlv administrator;
  private final List<InteropSuite.Check> checks = new ArrayList<>();
  private final Set<Operation> exercised = EnumSet.noneOf(Operation.class);
  private final Set<String> resources = new LinkedHashSet<>();
  private String id;
  private byte[] key;
  private final String name = "keytend-" + UUID.randomUUID();

  /**
   * A suite for a server whose build is not known: the limitations pinned to a build ({@link
   * InteropSuite#PQCTODAY_BUILD}) do not apply, so those checks fail.
   */
  public ModernInteropSuite(KmipClient client, String server, java.nio.file.Path certificates) {
    this(client, server, InteropSuite.UNVERIFIED, certificates);
  }

  /** @param identity the running build, as for {@link InteropSuite} */
  public ModernInteropSuite(
      KmipClient client, String server, String identity, java.nio.file.Path certificates) {
    this(client, server, identity, certificates, null);
  }

  /**
   * @param administrator a Credential for the request header of the draft 3.0 Login and System
   *     Object requests, for a server whose policy requires one (keytend-kmip-server: a users-file
   *     administrator), or null to send none
   */
  public ModernInteropSuite(
      KmipClient client,
      String server,
      String identity,
      java.nio.file.Path certificates,
      Ttlv administrator) {
    this.client = client;
    this.server = server;
    this.identity = identity;
    this.certificates = certificates;
    this.administrator = administrator;
  }

  /**
   * PQC-EXPORT-OBJECT: the KMIP 3.0 Export response must carry the exported object, and the
   * PQCToday build {@link InteropSuite#PQCTODAY_BUILD} can omit it. The SDK rejects such a reply
   * with exactly this message. Only that build, version, check and message are excused.
   */
  static boolean pqctodayExportWithoutObject(
      String server, String identity, ProtocolVersion version, String check, String message) {
    return server.equals("pqctoday")
        && InteropSuite.PQCTODAY_BUILD.equals(identity)
        && version == ProtocolVersion.V3_0
        // Import restores what an Export returned, so it meets the same reply.
        && (check.equals("Export") || check.equals("Import"))
        && "Export response missing its object".equals(message);
  }

  /**
   * PQC-ADJUST-INTERVAL, PQC-USAGE-LIMITS and PQC-CANCEL-UNKNOWN: the PQCToday build {@link
   * InteropSuite#PQCTODAY_BUILD} refuses an Interval Adjustment Value for a date, does not keep the
   * Usage Limits given at Create, and answers Cancel of an unknown correlation value with an error
   * instead of the Cancellation Result Unavailable. Only that build, KMIP 3.0, the check, the
   * reason and the server's exact message are excused; the label, or null.
   */
  static String pqctodayLimitation(
      String server,
      String identity,
      ProtocolVersion version,
      String check,
      Integer reason,
      String message) {
    if (!server.equals("pqctoday")
        || !InteropSuite.PQCTODAY_BUILD.equals(identity)
        || version != ProtocolVersion.V3_0
        || reason == null
        || message == null) return null;
    if (check.equals("AdjustAttribute Deactivation Date")
        && reason == ResultReason.INVALID_MESSAGE.code()
        && message.endsWith(
            "unexpected item type for tag 0x420162 (Adjustment Value): expected Integer or LongInteger"))
      return "PQC-ADJUST-INTERVAL: an Interval Adjustment Value for a date is refused ("
          + message
          + ")";
    if (check.equals("GetUsageAllocation")
        && reason == ResultReason.ATTRIBUTE_NOT_FOUND.code()
        && message.endsWith("has no Usage Limits attribute"))
      return "PQC-USAGE-LIMITS: the Usage Limits given at Create are not kept (" + message + ")";
    if (check.equals("Cancel unknown token")
        && reason == ResultReason.INVALID_ASYNCHRONOUS_CORRELATION_VALUE.code()
        && message.endsWith("unknown Asynchronous Correlation Value"))
      return "PQC-CANCEL-UNKNOWN: Cancel of an unknown correlation value is an error, not Unavailable ("
          + message
          + ")";
    return null;
  }

  public List<InteropSuite.Check> run() {
    if (server.equals("pqctoday")) setupCa();
    test(
        "Query capabilities",
        () -> {
          Result r =
              call(
                  Requests.query()
                      .add(
                          enumeration(QUERY_FUNCTION, QueryFunction.QUERY_OPERATIONS),
                          enumeration(QUERY_FUNCTION, QueryFunction.QUERY_OBJECTS))
                      .build());
          require(!r.requirePayload().children(OPERATION).isEmpty(), "No advertised operations");
        });
    test(
        "DiscoverVersions",
        () -> {
          exercised.add(Operation.DISCOVER_VERSIONS);
          require(client.discoverVersions().contains(client.version()), "Version not advertised");
        });
    test(
        "Create AES with direct attributes",
        () -> {
          id =
              created(
                  call(
                      Requests.create()
                          .add(
                              enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY),
                              ModernAttributes.of(
                                  nameAttribute(),
                                  enumeration(CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.AES),
                                  integer(CRYPTOGRAPHIC_LENGTH, 256),
                                  integer(CRYPTOGRAPHIC_USAGE_MASK, 12)))
                          .build()));
        });
    if (id != null) {
      test(
          "Get AES and key material",
          () -> {
            key =
                InteropSuite.keyBytes(
                    call(Requests.get().uniqueIdentifier(id).build()).requirePayload());
            require(key.length == 32, "Key length");
          });
      test(
          "GetAttributes uses AttributeReference",
          () -> {
            Ttlv attrs =
                call(Requests.getAttributes()
                        .uniqueIdentifier(id)
                        .add(ModernAttributes.reference(CRYPTOGRAPHIC_LENGTH))
                        .build())
                    .requirePayload()
                    .require(ATTRIBUTES);
            require(attrs.require(CRYPTOGRAPHIC_LENGTH).intValue() == 256, "Cryptographic length");
          });
      test(
          "GetAttributeList",
          () -> {
            require(
                !call(Requests.getAttributeList().uniqueIdentifier(id).build())
                    .requirePayload()
                    .children(ATTRIBUTE_REFERENCE)
                    .isEmpty(),
                "Attribute references");
          });
      test(
          "Locate by name",
          () -> {
            Result r = call(Requests.locate().add(nameAttribute()).build());
            require(
                r.requirePayload().children(UNIQUE_IDENTIFIER).stream()
                    .anyMatch(n -> n.textValue().equals(id)),
                "Located ID");
          });
      test("Activate", () -> call(Requests.activate().uniqueIdentifier(id).build()));
      test(
          "AddAttribute",
          () ->
              call(
                  Requests.addAttribute()
                      .uniqueIdentifier(id)
                      .add(ModernAttributes.newAttribute(text(DESCRIPTION, "first")))
                      .build()));
      test(
          "ModifyAttribute",
          () ->
              call(
                  Requests.modifyAttribute()
                      .uniqueIdentifier(id)
                      .add(
                          ModernAttributes.currentAttribute(text(DESCRIPTION, "first")),
                          ModernAttributes.newAttribute(text(DESCRIPTION, "second")))
                      .build()));
      test(
          "SetAttribute",
          () ->
              call(
                  Requests.setAttribute()
                      .uniqueIdentifier(id)
                      .add(ModernAttributes.newAttribute(text(DESCRIPTION, "third")))
                      .build()));
      test(
          "DeleteAttribute",
          () ->
              call(
                  Requests.deleteAttribute()
                      .uniqueIdentifier(id)
                      .add(ModernAttributes.currentAttribute(text(DESCRIPTION, "third")))
                      .build()));
      test(
          "AES-CBC agrees with JCE",
          () -> {
            byte[] data = "modern KMIP client".getBytes(StandardCharsets.UTF_8), iv = new byte[16];
            Ttlv[] params = {
              enumeration(CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.AES),
              enumeration(BLOCK_CIPHER_MODE, BlockCipherMode.CBC),
              enumeration(PADDING_METHOD, PaddingMethod.PKCS5)
            };
            Result encrypted =
                call(
                    Requests.encrypt()
                        .uniqueIdentifier(id)
                        .cryptographicParameters(params)
                        .data(data)
                        .add(bytes(IV_COUNTER_NONCE, iv))
                        .build());
            byte[] ciphertext = encrypted.requirePayload().require(DATA).bytesValue();
            Cipher jce = Cipher.getInstance("AES/CBC/PKCS5Padding");
            jce.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            require(Arrays.equals(jce.doFinal(data), ciphertext), "JCE encryption");
            Result decrypted =
                call(
                    Requests.decrypt()
                        .uniqueIdentifier(id)
                        .cryptographicParameters(params)
                        .data(ciphertext)
                        .add(bytes(IV_COUNTER_NONCE, iv))
                        .build());
            require(
                Arrays.equals(data, decrypted.requirePayload().require(DATA).bytesValue()),
                "Decryption");
          });
      test(
          "AES-GCM with AAD and tag",
          () -> {
            byte[] data = {1, 2, 3, 4}, nonce = new byte[12], aad = {5, 6};
            Ttlv params =
                structure(
                    CRYPTOGRAPHIC_PARAMETERS, enumeration(BLOCK_CIPHER_MODE, BlockCipherMode.GCM));
            Ttlv encrypted =
                call(Requests.encrypt()
                        .uniqueIdentifier(id)
                        .add(
                            params,
                            bytes(DATA, data),
                            bytes(IV_COUNTER_NONCE, nonce),
                            bytes(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA, aad))
                        .build())
                    .requirePayload();
            byte[] ct = encrypted.require(DATA).bytesValue(),
                tag = encrypted.require(AUTHENTICATED_ENCRYPTION_TAG).bytesValue();
            Cipher jce = Cipher.getInstance("AES/GCM/NoPadding");
            jce.init(
                Cipher.ENCRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(tag.length * 8, nonce));
            jce.updateAAD(aad);
            byte[] both = new byte[ct.length + tag.length];
            System.arraycopy(ct, 0, both, 0, ct.length);
            System.arraycopy(tag, 0, both, ct.length, tag.length);
            require(Arrays.equals(both, jce.doFinal(data)), "AEAD vs JCE");
            Ttlv plaintext =
                call(Requests.decrypt()
                        .uniqueIdentifier(id)
                        .add(
                            params,
                            bytes(DATA, ct),
                            bytes(IV_COUNTER_NONCE, nonce),
                            bytes(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA, aad),
                            bytes(AUTHENTICATED_ENCRYPTION_TAG, tag))
                        .build())
                    .requirePayload();
            require(Arrays.equals(data, plaintext.require(DATA).bytesValue()), "AEAD decrypt");
            tag[0] ^= 1;
            Result failure =
                client.execute(
                    Requests.decrypt()
                        .uniqueIdentifier(id)
                        .add(
                            params,
                            bytes(DATA, ct),
                            bytes(IV_COUNTER_NONCE, nonce),
                            bytes(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA, aad),
                            bytes(AUTHENTICATED_ENCRYPTION_TAG, tag))
                        .build());
            require(!failure.successful(), "Tampered AEAD was accepted");
          });
      test(
          "Batch Get/GetAttributes",
          () -> {
            Response r =
                client.batch(
                    List.of(
                        Requests.get().uniqueIdentifier(id).build(),
                        Requests.getAttributes().uniqueIdentifier(id).build()));
            require(r.results().size() == 2, "Batch count");
            r.results().forEach(Result::requireSuccess);
          });
      test("Export", () -> call(Requests.export().uniqueIdentifier(id).build()));
      test(
          "Check usage",
          () ->
              call(
                  Requests.check()
                      .uniqueIdentifier(id)
                      .add(integer(CRYPTOGRAPHIC_USAGE_MASK, 4))
                      .build()));
      test("ObtainLease", () -> call(Requests.obtainLease().uniqueIdentifier(id).build()));
    }
    test(
        "Register portable builder",
        () -> {
          byte[] data = new byte[16];
          Arrays.fill(data, (byte) 0x17);
          String uid =
              created(
                  call(
                      Requests.registerObject(
                          ManagedObjects.rawSymmetricKey(data, CryptographicAlgorithm.AES),
                          Attributes.usage(
                              CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT))));
          require(
              Arrays.equals(data, InteropSuite.keyBytes(client.get(uid).requirePayload())),
              "Registered key bytes");
        });
    test(
        "Import",
        () -> {
          var fixture = InteropSuite.prepareRestore(client, resources);
          InteropSuite.verifyRestore(
              client,
              fixture,
              call(
                  InteropSuite.restoreRequest(client.version(), fixture.id(), fixture.exported())));
        });
    test(
        "ReKey",
        () -> {
          String original =
              created(
                  call(
                      Requests.createSymmetricKey(
                          CryptographicAlgorithm.AES,
                          128,
                          CryptographicUsageMask.ENCRYPT,
                          CryptographicUsageMask.DECRYPT)));
          client.activate(original);
          created(call(Requests.reKey().uniqueIdentifier(original).build()));
        });
    test(
        "DeriveKey PBKDF2 agrees with JCE",
        () -> {
          byte[] password = "test-password".getBytes(StandardCharsets.UTF_8),
              salt = {1, 2, 3, 4, 5, 6, 7, 8};
          String base =
              created(
                  call(
                      Requests.registerObject(
                          ManagedObjects.secretData(
                              SecretDataType.PASSWORD,
                              ManagedObjects.keyBlock(
                                  KeyFormatType.RAW, bytes(KEY_MATERIAL, password), null, null)),
                          Attributes.usage(CryptographicUsageMask.DERIVE_KEY))));
          client.activate(base);
          Result r =
              call(
                  Requests.deriveKey()
                      .add(
                          enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY),
                          text(UNIQUE_IDENTIFIER, base),
                          enumeration(DERIVATION_METHOD, DerivationMethod.PBKDF2),
                          structure(
                              DERIVATION_PARAMETERS,
                              structure(
                                  CRYPTOGRAPHIC_PARAMETERS,
                                  enumeration(HASHING_ALGORITHM, HashingAlgorithm.SHA_256)),
                              bytes(SALT, salt),
                              integer(ITERATION_COUNT, 1000)),
                          ModernAttributes.of(
                              enumeration(CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.AES),
                              integer(CRYPTOGRAPHIC_LENGTH, 128),
                              integer(CRYPTOGRAPHIC_USAGE_MASK, 12)))
                      .build());
          String derived = created(r);
          PBEKeySpec spec = new PBEKeySpec("test-password".toCharArray(), salt, 1000, 128);
          require(
              Arrays.equals(
                  SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                      .generateSecret(spec)
                      .getEncoded(),
                  InteropSuite.keyBytes(client.get(derived).requirePayload())),
              "Derived key");
          spec.clearPassword();
        });
    if (id != null) {
      test(
          "CreateSplitKey/JoinSplitKey XOR",
          () -> {
            // Create Split Key names Object Type Split Key and an Attributes structure for the
            // parts (2.1 section 6.1.10).
            Result r = call(InteropSuite.splitRequest(id, ModernAttributes.of()));
            List<String> parts =
                r.requirePayload().children(UNIQUE_IDENTIFIER).stream()
                    .map(Ttlv::textValue)
                    .toList();
            require(parts.size() == 3, "Split parts");
            resources.addAll(parts);
            Request.Builder join =
                Requests.joinSplitKey().add(enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY));
            parts.forEach(join::uniqueIdentifier);
            String joined = created(call(join.build()));
            require(
                Arrays.equals(key, InteropSuite.keyBytes(client.get(joined).requirePayload())),
                "Reconstructed material");
          });
    }
    test(
        "AdjustAttribute Deactivation Date",
        () -> {
          // Increment adjusts a numeric or date value (2.1 section 6.1.3, Table 428); a usage mask
          // is a set of flags, not a quantity. A Deactivation Date a day ahead moves one hour.
          String uid =
              created(
                  call(
                      Requests.createSymmetricKey(
                          CryptographicAlgorithm.AES, 128, CryptographicUsageMask.ENCRYPT)));
          java.time.Instant date =
              java.time.Instant.now()
                  .plus(java.time.Duration.ofDays(1))
                  .truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
          call(
              Requests.setAttribute()
                  .uniqueIdentifier(uid)
                  .newAttribute(dateTime(DEACTIVATION_DATE, date))
                  .build());
          call(
              Requests.adjustAttribute()
                  .uniqueIdentifier(uid)
                  .attributeReference(DEACTIVATION_DATE)
                  .add(
                      enumeration(ADJUSTMENT_TYPE, AdjustmentType.INCREMENT),
                      interval(ADJUSTMENT_VALUE, 3600))
                  .build());
          Ttlv adjusted =
              call(Requests.getAttributes()
                      .uniqueIdentifier(uid)
                      .add(ModernAttributes.reference(DEACTIVATION_DATE))
                      .build())
                  .requirePayload()
                  .require(ATTRIBUTES)
                  .require(DEACTIVATION_DATE);
          require(
              adjusted.instantValue().equals(date.plusSeconds(3600)), "Adjusted Deactivation Date");
        });
    test(
        "GetUsageAllocation",
        () -> {
          // An allocation draws on the object's Usage Limits (2.1 section 6.1.23), so the key is
          // created with them rather than given them after it has been used.
          String uid =
              created(
                  call(
                      Requests.create()
                          .add(
                              enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY),
                              ModernAttributes.of(
                                  enumeration(CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.AES),
                                  integer(CRYPTOGRAPHIC_LENGTH, 128),
                                  integer(CRYPTOGRAPHIC_USAGE_MASK, 12),
                                  Structures.structure(
                                      USAGE_LIMITS,
                                      longInteger(USAGE_LIMITS_TOTAL, 10),
                                      enumeration(USAGE_LIMITS_UNIT, UsageLimitsUnit.OBJECT))))
                          .build()));
          client.activate(uid);
          require(
              call(Requests.getUsageAllocation()
                      .uniqueIdentifier(uid)
                      .add(longInteger(USAGE_LIMITS_COUNT, 1))
                      .build())
                  .uniqueIdentifier()
                  .equals(uid),
              "Usage allocation ID");
          Ttlv limits =
              call(Requests.getAttributes()
                      .uniqueIdentifier(uid)
                      .add(ModernAttributes.reference(USAGE_LIMITS))
                      .build())
                  .requirePayload()
                  .require(ATTRIBUTES)
                  .require(USAGE_LIMITS);
          require(
              limits.require(USAGE_LIMITS_COUNT).longValue() == 9,
              "Usage Limits Count after allocation");
        });
    test(
        "Archive/Recover",
        () -> {
          String uid =
              created(
                  call(
                      Requests.createSymmetricKey(
                          CryptographicAlgorithm.AES, 128, CryptographicUsageMask.ENCRYPT)));
          call(Requests.archive().uniqueIdentifier(uid).build());
          call(Requests.recover().uniqueIdentifier(uid).build());
        });
    test(
        "Interop Begin/End",
        () -> {
          String token = "keytend-" + UUID.randomUUID();
          call(
              Requests.interop()
                  .add(
                      enumeration(INTEROP_FUNCTION, InteropFunction.BEGIN),
                      text(INTEROP_IDENTIFIER, token))
                  .build());
          call(
              Requests.interop()
                  .add(
                      enumeration(INTEROP_FUNCTION, InteropFunction.END),
                      text(INTEROP_IDENTIFIER, token))
                  .build());
        });
    test("ReProvision", () -> call(Requests.reProvision().build()));
    test(
        "DelegatedLogin delegating Query",
        () -> {
          // One Right: 2.1 Table 387 lets Rights be empty, a ticket that permits nothing, but a
          // server may refuse that (keytend-kmip-server answers Invalid Field).
          Ttlv query = structure(OPERATIONS, enumeration(OPERATION, Operation.QUERY));
          Result r =
              call(
                  Requests.delegatedLogin()
                      .add(structure(RIGHTS, structure(RIGHT, query)))
                      .build());
          call(Requests.logout().add(r.requirePayload().require(TICKET)).build());
        });
    test(
        "Hash SHA256 agrees with JCA",
        () -> {
          byte[] data = {1, 2, 3};
          Result r =
              call(
                  Requests.hash()
                      .cryptographicParameters(
                          enumeration(HASHING_ALGORITHM, HashingAlgorithm.SHA_256))
                      .data(data)
                      .build());
          require(
              Arrays.equals(
                  MessageDigest.getInstance("SHA-256").digest(data),
                  r.requirePayload().require(DATA).bytesValue()),
              "Hash");
        });
    test(
        "HMAC and MACVerify agree with JCE",
        () -> {
          byte[] material = new byte[32], data = {1, 2, 3};
          String uid =
              created(
                  call(
                      Requests.registerObject(
                          ManagedObjects.rawSymmetricKey(
                              material, CryptographicAlgorithm.HMAC_SHA256),
                          Attributes.usage(
                              CryptographicUsageMask.MAC_GENERATE,
                              CryptographicUsageMask.MAC_VERIFY))));
          client.activate(uid);
          Ttlv[] params = {
            enumeration(HASHING_ALGORITHM, HashingAlgorithm.SHA_256),
            enumeration(CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.HMAC_SHA256)
          };
          byte[] mac =
              call(Requests.mac()
                      .uniqueIdentifier(uid)
                      .cryptographicParameters(params)
                      .data(data)
                      .build())
                  .requirePayload()
                  .require(MAC_DATA)
                  .bytesValue();
          Mac jce = Mac.getInstance("HmacSHA256");
          jce.init(new SecretKeySpec(material, "HmacSHA256"));
          require(Arrays.equals(jce.doFinal(data), mac), "MAC");
          Result r =
              call(
                  Requests.macVerify()
                      .uniqueIdentifier(uid)
                      .cryptographicParameters(params)
                      .data(data)
                      .add(bytes(MAC_DATA, mac))
                      .build());
          require(
              r.requirePayload().require(VALIDITY_INDICATOR).intValue() == 1, "MAC verification");
        });
    test(
        "Validate independent CA certificate",
        () -> {
          // Certificate Register requires algorithm, length, certificate length and usage.
          java.security.cert.X509Certificate cert =
              (java.security.cert.X509Certificate)
                  java.security.cert.CertificateFactory.getInstance("X.509")
                      .generateCertificate(new java.io.ByteArrayInputStream(pem("ca.pem")));
          CertificateRegistration registration =
              CertificateRegistration.of(
                  cert,
                  UsageMask.of(
                      CryptographicUsageMask.CERTIFICATE_SIGN,
                      CryptographicUsageMask.CRL_SIGN,
                      CryptographicUsageMask.VERIFY));
          if (cert.getPublicKey() instanceof java.security.interfaces.ECPublicKey)
            registration.ecAlgorithm(CryptographicAlgorithm.EC);
          String ca = created(call(registration.build()));
          require(
              call(Requests.validate().uniqueIdentifier(ca).build())
                      .requirePayload()
                      .require(VALIDITY_INDICATOR)
                      .intValue()
                  == 1,
              "Self-signed root validation");
        });
    rsa();
    test(
        "RNGRetrieve",
        () ->
            require(
                call(Requests.rngRetrieve().add(integer(DATA_LENGTH, 32)).build())
                        .requirePayload()
                        .require(DATA)
                        .bytesValue()
                        .length
                    == 32,
                "RNG size"));
    test("RNGSeed", () -> call(Requests.rngSeed().data(new byte[] {1, 2, 3, 4}).build()));
    test(
        "Log",
        () -> call(Requests.log().add(text(LOG_MESSAGE, "keytend-kmip integration")).build()));
    test(
        "PKCS11 initialize/get-info/finalize",
        () -> {
          Result init =
              call(
                  Requests.pkcs11()
                      .add(
                          enumeration(PKCS_11_FUNCTION, 1),
                          bytes(PKCS_11_INPUT_PARAMETERS, new byte[] {1}))
                      .build());
          Ttlv token = init.requirePayload().child(CORRELATION_VALUE).orElse(null);
          Request.Builder get = Requests.pkcs11().add(enumeration(PKCS_11_FUNCTION, 3));
          if (token != null) get.add(token);
          call(get.build());
          Request.Builder done = Requests.pkcs11().add(enumeration(PKCS_11_FUNCTION, 2));
          if (token != null) done.add(token);
          call(done.build());
        });
    test(
        "Login and Logout ticket",
        () -> {
          // Login issues a ticket to the user the request header authenticates (draft 3.0 section
          // 6.1.36).
          Ttlv ticket = administrative(Requests.login().build()).requirePayload().require(TICKET);
          call(Requests.logout().add(ticket).build());
        });
    test(
        "SetEndpointRole",
        () -> {
          // Endpoint Role Client would make the server the client on this channel (2.1 section
          // 6.1.54), and this suite continues as a client: it asks for the role the server already
          // has. EndpointRoleReversal exercises the reversal itself.
          Result r =
              call(
                  Requests.setEndpointRole()
                      .add(enumeration(ENDPOINT_ROLE, EndpointRole.SERVER))
                      .build());
          require(
              r.requirePayload().require(ENDPOINT_ROLE).intValue() == EndpointRole.SERVER.code(),
              "Accepted endpoint role");
        });
    if (client.version().atLeast(ProtocolVersion.V2_1)) {
      test("Ping", () -> call(Requests.ping().build()));
      test("QueryAsynchronousRequests", () -> call(Requests.queryAsynchronousRequests().build()));
      test("GetConstraints", () -> call(Requests.getConstraints().build()));
      test(
          "SetConstraints empty",
          () -> call(Requests.setConstraints().add(structure(CONSTRAINTS)).build()));
      test("SetDefaults empty", () -> call(Requests.setDefaults().build()));
      negative(
          "Process unknown token",
          Requests.process().add(bytes(ASYNCHRONOUS_CORRELATION_VALUE, new byte[] {1})).build());
    }
    test(
        "Poll unknown token",
        () -> {
          Result r =
              client.execute(
                  Requests.poll()
                      .add(bytes(ASYNCHRONOUS_CORRELATION_VALUE, new byte[] {1}))
                      .build());
          exercised.add(Operation.POLL);
          if (r.hasReason(ResultReason.OPERATION_NOT_SUPPORTED)
              || r.hasReason(ResultReason.FEATURE_NOT_SUPPORTED)) r.requireSuccess();
          require(
              !r.successful() && r.hasReason(ResultReason.INVALID_ASYNCHRONOUS_CORRELATION_VALUE),
              "Unexpected unknown-token Poll response: " + r);
        });
    test(
        "Cancel unknown token",
        () -> {
          // Cancel answers a Cancellation Result, Unavailable for a correlation value that matches
          // no operation (2.1 section 6.1.5); it must not report a cancellation.
          Result r =
              call(
                  Requests.cancel()
                      .add(bytes(ASYNCHRONOUS_CORRELATION_VALUE, new byte[] {1}))
                      .build());
          require(
              r.requirePayload().require(CANCELLATION_RESULT).intValue()
                  == CancellationResult.UNAVAILABLE.code(),
              "Unknown token canceled: " + r);
        });
    if (client.version() == ProtocolVersion.V3_0) {
      // System Objects are created and obliterated by an administrator the request header
      // authenticates (draft 3.0 section 2.1: special authentication SHOULD be enforced). They are
      // not managed objects, so each scenario obliterates its own.
      test(
          "CreateGroup and Obliterate",
          () -> {
            String group =
                administrative(
                        Requests.createGroup()
                            .attributes(text(NAME, "group-" + UUID.randomUUID()))
                            .build())
                    .uniqueIdentifier();
            administrative(Requests.obliterate().uniqueIdentifier(group).build());
          });
      test(
          "CreateUser",
          () -> {
            // A User has one to eight Credential Links (draft 3.0 section 6.1.13, Table 3).
            String credential = passwordCredential();
            String user =
                administrative(
                        Requests.createUser()
                            .add(
                                ModernAttributes.of(
                                    text(NAME, "user-" + UUID.randomUUID()),
                                    reference(CREDENTIAL_LINK, credential)))
                            .build())
                    .uniqueIdentifier();
            administrative(Requests.obliterate().uniqueIdentifier(user).build());
            administrative(Requests.obliterate().uniqueIdentifier(credential).build());
          });
      test(
          "CreateCredential password",
          () ->
              administrative(Requests.obliterate().uniqueIdentifier(passwordCredential()).build()));
      kem();
      if (id != null)
        test("Deactivate", () -> call(Requests.deactivate().uniqueIdentifier(id).build()));
    }
    for (String uid : resources)
      test(
          "Destroy resource",
          () -> {
            client.execute(
                Requests.revoke(uid, RevocationReasonCode.CESSATION_OF_OPERATION, "cleanup"));
            exercised.add(Operation.REVOKE);
            Result result = client.execute(Requests.destroy().uniqueIdentifier(uid).build());
            exercised.add(Operation.DESTROY);
            if (!result.successful() && client.version() == ProtocolVersion.V3_0) {
              call(Requests.obliterate().uniqueIdentifier(uid).build());
            } else result.requireSuccess();
          });
    for (Operation op : Operation.values())
      if (client.version().atLeast(op.since()) && !exercised.contains(op))
        checks.add(
            new InteropSuite.Check(
                op.wireName(),
                op.serverToClient() ? "CALLBACK" : "UNEXERCISED",
                "Covered by generic API and wire-model tests; no successful scenario in this run"));
    return List.copyOf(checks);
  }

  private void setupCa() {
    test(
        "Import test CA material",
        () -> {
          // Fixed by the pinned pqctoday image (integration/pqctoday/Dockerfile, --ca-key and
          // --ca-cert):
          // that configuration is hashed into the catalog evidence, so these keep its spelling.
          String keyId = "urn:keytend:test-ca-key", certId = "urn:keytend:test-ca-cert";
          created(
              call(
                  Requests.importObject()
                      .add(
                          identifier(UNIQUE_IDENTIFIER, keyId),
                          enumeration(OBJECT_TYPE, ObjectType.PRIVATE_KEY),
                          bool(REPLACE_EXISTING, false),
                          ModernAttributes.of(
                              integer(
                                  CRYPTOGRAPHIC_USAGE_MASK,
                                  CryptographicUsageMask.SIGN.code()
                                      | CryptographicUsageMask.CERTIFICATE_SIGN.code())),
                          ManagedObjects.privateKey(
                              ManagedObjects.keyBlock(
                                  KeyFormatType.PKCS_8,
                                  bytes(KEY_MATERIAL, pem("ca-key.pem")),
                                  CryptographicAlgorithm.RSA,
                                  2048)))
                      .build()));
          client.activate(keyId);
          created(
              call(
                  Requests.importObject()
                      .add(
                          identifier(UNIQUE_IDENTIFIER, certId),
                          enumeration(OBJECT_TYPE, ObjectType.CERTIFICATE),
                          bool(REPLACE_EXISTING, false),
                          ModernAttributes.of(),
                          ManagedObjects.certificate(CertificateType.X_509, pem("ca.pem")))
                      .build()));
        });
  }

  private byte[] pem(String name) throws Exception {
    return Base64.getMimeDecoder()
        .decode(
            java.nio.file.Files.readString(certificates.resolve(name))
                .replaceAll("-----[^\\r\\n]+-----", ""));
  }

  private void rsa() {
    test(
        "RSA CreateKeyPair",
        () -> {
          Result pair =
              call(
                  Requests.createKeyPair()
                      .add(
                          structure(
                              COMMON_ATTRIBUTES,
                              enumeration(CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.RSA),
                              integer(CRYPTOGRAPHIC_LENGTH, 2048),
                              integer(CRYPTOGRAPHIC_USAGE_MASK, 3)))
                      .build());
          String
              privateId = pair.requirePayload().require(PRIVATE_KEY_UNIQUE_IDENTIFIER).textValue(),
              publicId = pair.requirePayload().require(PUBLIC_KEY_UNIQUE_IDENTIFIER).textValue();
          resources.addAll(List.of(privateId, publicId));
          client.activate(privateId);
          client.activate(publicId);
          test(
              "Certify public key",
              () -> {
                // The client can see its imported CA. The independent server's infrastructure
                // resolver may use another ownership scope.
                if (server.equals("pqctoday"))
                  call(
                      Requests.getAttributes().uniqueIdentifier("urn:keytend:test-ca-key").build());
                String cert =
                    created(
                        call(
                            Requests.certify()
                                .uniqueIdentifier(publicId)
                                .attributes(
                                    client.version() == ProtocolVersion.V3_0
                                        ? text(CERTIFICATE_SUBJECT_DN, "CN=keytend-test")
                                        : text(CERTIFICATE_SUBJECT_CN, "keytend-test"))
                                .build()));
                test(
                    "Validate issued certificate",
                    () -> {
                      Request.Builder request = Requests.validate().uniqueIdentifier(cert);
                      if (server.equals("pqctoday"))
                        request.uniqueIdentifier("urn:keytend:test-ca-cert");
                      require(
                          call(request.build())
                                  .requirePayload()
                                  .require(VALIDITY_INDICATOR)
                                  .intValue()
                              == 1,
                          "Certificate chain");
                    });
                test(
                    "ReCertify",
                    () -> created(call(Requests.reCertify().uniqueIdentifier(cert).build())));
              });
          test(
              "ReKeyKeyPair",
              () -> {
                Result r = call(Requests.reKeyKeyPair().uniqueIdentifier(privateId).build());
                resources.add(
                    r.requirePayload().require(PRIVATE_KEY_UNIQUE_IDENTIFIER).textValue());
                resources.add(r.requirePayload().require(PUBLIC_KEY_UNIQUE_IDENTIFIER).textValue());
              });
        });
    test(
        "RSA Sign/SignatureVerify against independently generated JCA keys",
        () -> {
          KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
          generator.initialize(2048);
          KeyPair pair = generator.generateKeyPair();
          String priv =
              created(
                  call(
                      Requests.registerObject(
                          ManagedObjects.privateKey(
                              ManagedObjects.keyBlock(
                                  KeyFormatType.PKCS_8,
                                  bytes(KEY_MATERIAL, pair.getPrivate().getEncoded()),
                                  CryptographicAlgorithm.RSA,
                                  2048)),
                          Attributes.usage(CryptographicUsageMask.SIGN))));
          String pub =
              created(
                  call(
                      Requests.registerObject(
                          ManagedObjects.publicKey(
                              ManagedObjects.keyBlock(
                                  KeyFormatType.X_509,
                                  bytes(KEY_MATERIAL, pair.getPublic().getEncoded()),
                                  CryptographicAlgorithm.RSA,
                                  2048)),
                          Attributes.usage(CryptographicUsageMask.VERIFY))));
          client.activate(priv);
          client.activate(pub);
          byte[] data = {1, 2, 3};
          Ttlv[] cp = {
            enumeration(
                DIGITAL_SIGNATURE_ALGORITHM,
                DigitalSignatureAlgorithm.SHA_256_WITH_RSA_ENCRYPTION_PKCS_1_V1_5),
            enumeration(PADDING_METHOD, PaddingMethod.PKCS1_V1_5),
            enumeration(HASHING_ALGORITHM, HashingAlgorithm.SHA_256),
            enumeration(CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.RSA)
          };
          byte[] sig =
              call(Requests.sign()
                      .uniqueIdentifier(priv)
                      .cryptographicParameters(cp)
                      .data(data)
                      .build())
                  .requirePayload()
                  .require(SIGNATURE_DATA)
                  .bytesValue();
          Signature jca = Signature.getInstance("SHA256withRSA");
          jca.initVerify(pair.getPublic());
          jca.update(data);
          require(jca.verify(sig), "JCA signature verification");
          require(
              call(Requests.signatureVerify()
                          .uniqueIdentifier(pub)
                          .cryptographicParameters(cp)
                          .data(data)
                          .add(bytes(SIGNATURE_DATA, sig))
                          .build())
                      .requirePayload()
                      .require(VALIDITY_INDICATOR)
                      .intValue()
                  == 1,
              "Server signature verification");
        });
  }

  private void kem() {
    test(
        "ML-KEM-768 Encapsulate/Decapsulate",
        () -> {
          Result pair =
              call(
                  Requests.createKeyPair()
                      .add(
                          structure(
                              COMMON_ATTRIBUTES,
                              enumeration(
                                  CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.ML_KEM_768),
                              integer(CRYPTOGRAPHIC_USAGE_MASK, 12)))
                      .build());
          String priv = pair.requirePayload().require(PRIVATE_KEY_UNIQUE_IDENTIFIER).textValue(),
              pub = pair.requirePayload().require(PUBLIC_KEY_UNIQUE_IDENTIFIER).textValue();
          resources.addAll(List.of(priv, pub));
          client.activate(priv);
          client.activate(pub);
          Ttlv encapsulated =
              call(Requests.encapsulate().uniqueIdentifier(pub).build()).requirePayload();
          byte[] ct = encapsulated.require(DATA).bytesValue();
          String shared = encapsulated.require(UNIQUE_IDENTIFIER).textValue();
          resources.add(shared);
          String recovered =
              created(call(Requests.decapsulate().uniqueIdentifier(priv).data(ct).build()));
          require(
              Arrays.equals(
                  InteropSuite.keyBytes(client.get(shared).requirePayload()),
                  InteropSuite.keyBytes(client.get(recovered).requirePayload())),
              "KEM shared secrets differ");
        });
  }

  private String passwordCredential() throws Exception {
    return administrative(
            Requests.createCredential()
                .add(
                    enumeration(CREDENTIAL_TYPE, CredentialType.PASSWORD),
                    ModernAttributes.of(),
                    structure(PASSWORD_CREDENTIAL, text(PASSWORD, "test-" + UUID.randomUUID())))
                .build())
        .uniqueIdentifier();
  }

  /** A request carrying the administrator's credential in its header, when one is configured. */
  private Result administrative(Request request) throws Exception {
    if (administrator == null) return call(request);
    exercised.add(request.operation());
    return client
        .batch(List.of(request), RequestOptions.builder().authentication(administrator).build())
        .results()
        .get(0)
        .requireSuccess();
  }

  private Ttlv nameAttribute() {
    return client.version() == ProtocolVersion.V3_0
        ? text(NAME, name)
        : structure(
            NAME,
            text(NAME_VALUE, name),
            enumeration(NAME_TYPE, NameType.UNINTERPRETED_TEXT_STRING));
  }

  private String created(Result result) {
    String uid = result.uniqueIdentifier();
    resources.add(uid);
    return uid;
  }

  private Result call(Request request) throws Exception {
    exercised.add(request.operation());
    return client.call(request);
  }

  private void negative(String name, Request request) {
    test(
        name,
        () -> {
          exercised.add(request.operation());
          require(!client.execute(request).successful(), "Invalid token accepted");
        });
  }

  private void test(String name, Task body) {
    try {
      body.run();
      checks.add(new InteropSuite.Check(name, "PASS", ""));
    } catch (KmipException e) {
      if (server.equals("pqctoday")
          && name.equals("Certify public key")
          && e.result().reason() != null
          && e.result().reason() == 55
          && e.result().message() != null
          && e.result().message().contains("urn:keytend:test-ca-key"))
        checks.add(
            new InteropSuite.Check(
                name,
                "SERVER_LIMITATION",
                "PQC-CA-SCOPE: the client can retrieve its imported CA, but the server"
                    + " infrastructure CA resolver cannot; native CA bootstrap is required"));
      else if (pqctodayLimitation(
              server, identity, client.version(), name, e.result().reason(), e.result().message())
          != null)
        checks.add(
            new InteropSuite.Check(
                name,
                "SERVER_LIMITATION",
                pqctodayLimitation(
                    server,
                    identity,
                    client.version(),
                    name,
                    e.result().reason(),
                    e.result().message())));
      else if (server.equals("pqctoday")
          && name.equals("Certify public key")
          && e.result().reason() != null
          && e.result().reason() == 12)
        checks.add(
            new InteropSuite.Check(
                name, "UNSUPPORTED", "Server CA is not configured: " + e.result().message()));
      else if (e.result().reason() != null
          && (e.result().reason() == 5 || e.result().reason() == 8))
        checks.add(new InteropSuite.Check(name, "UNSUPPORTED", e.result().message()));
      else checks.add(new InteropSuite.Check(name, "FAIL", e + " " + e.result().message()));
    } catch (dev.keytend.kmip.client.ProtocolException e) {
      if (pqctodayExportWithoutObject(server, identity, client.version(), name, e.getMessage()))
        checks.add(
            new InteropSuite.Check(
                name,
                "SERVER_LIMITATION",
                "PQC-EXPORT-OBJECT: the Export response omits the exported object ("
                    + InteropSuite.payloadTags(e.response())
                    + ")"));
      else checks.add(new InteropSuite.Check(name, "FAIL", e.toString()));
    } catch (Exception | AssertionError e) {
      checks.add(new InteropSuite.Check(name, "FAIL", e.toString()));
    }
  }

  private static void require(boolean value, String message) {
    InteropSuite.require(value, message);
  }
}
