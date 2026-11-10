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
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * Real server workflows; unexpected errors fail. Unsupported and known server limitations are
 * recorded explicitly.
 */
public final class InteropSuite {
  public record Check(String name, String outcome, String detail) {}

  @FunctionalInterface
  interface Checked {
    void run() throws Exception;

    /** A call that returns its result. */
    @FunctionalInterface
    interface Call {
      Result call() throws Exception;
    }
  }

  /**
   * The PQCToday build ({@code integration/pqctoday}) the pinned limitations were diagnosed on:
   * the SHA-256 of {@code /usr/local/bin/pqctoday-kmip} and of the fixture sources, the identity of
   * {@code KmsSamplesIT.PQCTODAY_BUILD}.
   */
  static final String PQCTODAY_BUILD =
      "binary:810052c387b90350e09492675d30cf9e2ddfe4669fda9ddaf64318d1676d24f7"
          + ":cf3e662bc0ec7171f0f1bb6632605f7dd443629d2d37173810cfa4c7adc7c635";

  /**
   * The PyKMIP build ({@code integration/pykmip}) the PY-USAGE-LIMITS and PY-CONTACT-INFORMATION
   * limitations were diagnosed on: the SHA-256 of its image's layer list and of the fixture
   * sources, the identity of {@code KmsSamplesIT.PYKMIP_BUILD}.
   */
  static final String PYKMIP_BUILD =
      "layers:b75ccb50552a827d6271b2eccbc796e6c90c6318be18ec6b8c56180d5cc67dd7"
          + ":afbced4ad84a2ebfc597ce1dfeeca0193cf546a0536d557936b45074cc46bf1e";

  /** The identity of a server whose build was not inspected; no pinned limitation matches it. */
  static final String UNVERIFIED = "unverified";

  /**
   * The server label of keytend-kmip-server, as
   * integration/keytend-kmip-server passes it: it selects the issuing CA of Certify ({@link
   * #issuer()}) and the verification of the issued certificate.
   */
  static final String KEYTEND_SERVER = "keytend-kmip-server";

  private final KmipClient client;
  private final String server;
  private final String identity;
  private final List<Check> checks = new ArrayList<>();
  private final Set<Operation> advertised = EnumSet.noneOf(Operation.class),
      exercised = EnumSet.noneOf(Operation.class);
  private final Path certificates;
  private final Set<String> resources = new LinkedHashSet<>();
  private String aesId;
  private byte[] aesKey;

  /**
   * A suite for a server whose build is not known (for example {@link InteropApplication} against
   * an external server): the limitations pinned to a build ({@link #PQCTODAY_BUILD}) do not apply,
   * so those checks fail.
   */
  public InteropSuite(KmipClient client, String server, Path certificates) {
    this(client, server, UNVERIFIED, certificates);
  }

  /**
   * @param identity the running build, {@code binary:<executable SHA-256>:<fixture configuration
   *     SHA-256>} for PQCToday, as {@code KmsSamplesIT.identity} reads it
   */
  public InteropSuite(KmipClient client, String server, String identity, Path certificates) {
    this.client = client;
    this.server = server;
    this.identity = identity;
    this.certificates = certificates;
  }

  /**
   * PyKMIP's answer to a request message it cannot parse: a KMIP 1.0 header and Invalid Message
   * "Error parsing request message. See server logs for more information." (PY-UNSUPPORTED-PARSER).
   */
  static boolean pykmipParseFailure(Ttlv response) {
    if (response == null) return false;
    Ttlv h = response.child(RESPONSE_HEADER).orElse(null),
        b = response.child(BATCH_ITEM).orElse(null);
    return h != null
        && b != null
        && h.require(PROTOCOL_VERSION).require(PROTOCOL_VERSION_MINOR).intValue() == 0
        && b.require(RESULT_STATUS).intValue() == 1
        && b.child(RESULT_REASON).map(n -> n.intValue() == 4).orElse(false)
        && b.child(RESULT_MESSAGE)
            .map(Ttlv::textValue)
            .orElse("")
            .equals("Error parsing request message. See server logs for more information.");
  }

  /**
   * PY-USAGE-LIMITS: PyKMIP has no parser for the Usage Limits attribute (its attribute value
   * factory raises NotImplementedError), so the Create that gives the Get Usage Allocation key its
   * Usage Limits draws PyKMIP's parse failure.
   */
  private Result pykmipUsageLimits(Checked.Call create) throws Exception {
    try {
      return create.call();
    } catch (ProtocolException e) {
      if (server.equals("pykmip")
          && PYKMIP_BUILD.equals(identity)
          && pykmipParseFailure(e.response()))
        throw new ServerLimitation(
            "PY-USAGE-LIMITS: a Create with Usage Limits draws PyKMIP's parse failure (KMIP 1.0"
                + " header, Invalid Message): it has no Usage Limits attribute, and no Get Usage"
                + " Allocation");
      throw e;
    }
  }

  /**
   * PY-CONTACT-INFORMATION: PyKMIP refuses the Contact Information attribute at Create with Invalid
   * Field and exactly this message (KMIP 1.4).
   */
  static boolean pykmipContactInformation(
      String server, String identity, ProtocolVersion version, Result r) {
    return server.equals("pykmip")
        && PYKMIP_BUILD.equals(identity)
        && version == ProtocolVersion.V1_4
        && r.hasReason(ResultReason.INVALID_FIELD)
        && "The Contact Information attribute is unsupported.".equals(r.message());
  }

  /** The tags of a response's first Response Payload, for a limitation's detail. */
  static String payloadTags(Ttlv response) {
    if (response == null) return "no response";
    var item = response.child(BATCH_ITEM);
    var payload = item.flatMap(b -> b.child(RESPONSE_PAYLOAD));
    if (payload.isEmpty()) return "no ResponsePayload";
    return "ResponsePayload: "
        + String.join(", ", payload.get().children().stream().map(Ttlv::tagName).toList());
  }

  public List<Check> run() {
    test(
        "Query operations and objects",
        () -> {
          Result result = client.query(QueryFunction.QUERY_OPERATIONS, QueryFunction.QUERY_OBJECTS);
          exercised.add(Operation.QUERY);
          for (Ttlv op : result.requirePayload().children(OPERATION))
            advertised.add(Operation.fromCode(op.intValue()));
          require(
              advertised.containsAll(List.of(Operation.CREATE, Operation.GET, Operation.DESTROY)),
              "Baseline operations absent");
          if (result.requirePayload().children(OBJECT_TYPE).isEmpty()) {
            if (server.equals("pykmip"))
              throw new ServerLimitation(
                  "PY-QUERY-OBJECTS: upstream QueryObjects returns an empty list");
            throw new AssertionError("No object types");
          }
        });
    test(
        "DiscoverVersions",
        () -> {
          List<ProtocolVersion> versions = client.discoverVersions();
          exercised.add(Operation.DISCOVER_VERSIONS);
          require(versions.contains(client.version()), "Requested version absent");
        });
    test(
        "Create AES-256",
        () -> {
          aesId =
              created(
                  call(
                      Requests.create()
                          .add(enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY))
                          .template(
                              Attributes.name("keytend-" + UUID.randomUUID()),
                              Attributes.algorithm(CryptographicAlgorithm.AES),
                              Attributes.length(256),
                              Attributes.usage(
                                  CryptographicUsageMask.ENCRYPT,
                                  CryptographicUsageMask.DECRYPT,
                                  CryptographicUsageMask.DERIVE_KEY))
                          .build()));
        });
    if (aesId != null) {
      test(
          "Get key material and metadata",
          () -> {
            Result r = call(Requests.get().uniqueIdentifier(aesId).build());
            aesKey = keyBytes(r.requirePayload());
            require(aesKey.length == 32, "AES-256 key length");
            require(
                r.requirePayload().require(OBJECT_TYPE).intValue()
                    == ObjectType.SYMMETRIC_KEY.code(),
                "Object type");
          });
      test(
          "GetAttributes",
          () -> {
            Result r =
                call(
                    Requests.getAttributes()
                        .uniqueIdentifier(aesId)
                        .add(
                            text(ATTRIBUTE_NAME, "Cryptographic Length"),
                            text(ATTRIBUTE_NAME, "State"))
                        .build());
            require(r.requirePayload().children(ATTRIBUTE).size() == 2, "Attribute count");
          });
      optional(
          "GetAttributeList",
          Requests.getAttributeList().uniqueIdentifier(aesId).build(),
          r ->
              require(
                  !r.requirePayload().children(ATTRIBUTE_NAME).isEmpty(), "Empty attribute names"));
      test(
          "Locate by unique identifier",
          () -> {
            Result r =
                call(
                    Requests.locate()
                        .attribute(Attributes.textAttribute("Unique Identifier", aesId))
                        .build());
            require(
                r.requirePayload().children(UNIQUE_IDENTIFIER).stream()
                    .anyMatch(v -> v.textValue().equals(aesId)),
                "Locate did not find key");
          });
      test(
          "Activate",
          () -> {
            require(
                call(Requests.activate().uniqueIdentifier(aesId).build())
                    .uniqueIdentifier()
                    .equals(aesId),
                "Activate ID");
          });
      optional(
          "Check usage",
          Requests.check()
              .uniqueIdentifier(aesId)
              .add(integer(CRYPTOGRAPHIC_USAGE_MASK, CryptographicUsageMask.ENCRYPT.code()))
              .build(),
          r -> require(r.uniqueIdentifier().equals(aesId), "Check ID"));
      optional(
          "ObtainLease",
          Requests.obtainLease().uniqueIdentifier(aesId).build(),
          r -> require(r.requirePayload().require(LEASE_TIME).longValue() > 0, "Lease time"));
      final String[] limited = new String[1];
      optional(
          "GetUsageAllocation",
          Operation.GET_USAGE_ALLOCATION,
          () -> {
            // An allocation draws on the object's Usage Limits (1.4 section 4.18), so the key is
            // created with them; a key without Usage Limits has nothing to allocate from.
            limited[0] =
                created(
                    pykmipUsageLimits(
                        () ->
                            call(
                                Requests.create()
                                    .add(enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY))
                                    .template(
                                        Attributes.algorithm(CryptographicAlgorithm.AES),
                                        Attributes.length(128),
                                        Attributes.usage(
                                            CryptographicUsageMask.ENCRYPT,
                                            CryptographicUsageMask.DECRYPT),
                                        Attributes.attribute(
                                            "Usage Limits",
                                            structure(
                                                USAGE_LIMITS,
                                                longInteger(USAGE_LIMITS_TOTAL, 10),
                                                enumeration(
                                                    USAGE_LIMITS_UNIT, UsageLimitsUnit.OBJECT))))
                                    .build())));
            client.activate(limited[0]);
            return Requests.getUsageAllocation()
                .uniqueIdentifier(limited[0])
                .add(longInteger(USAGE_LIMITS_COUNT, 1))
                .build();
          },
          r -> {
            require(r.uniqueIdentifier().equals(limited[0]), "Usage allocation ID");
            Ttlv attributes =
                call(Requests.getAttributes()
                        .uniqueIdentifier(limited[0])
                        .add(text(ATTRIBUTE_NAME, "Usage Limits"))
                        .build())
                    .requirePayload();
            Ttlv count = find(attributes, USAGE_LIMITS_COUNT);
            require(count != null && count.longValue() == 9, "Usage Limits Count after allocation");
          });
      attributes();
      if (client.version().atLeast(ProtocolVersion.V1_2)) {
        aesCrypto();
      }
      derive();
      test(
          "ReKey",
          () -> {
            String base =
                created(
                    call(
                        Requests.createSymmetricKey(
                            CryptographicAlgorithm.AES,
                            128,
                            CryptographicUsageMask.ENCRYPT,
                            CryptographicUsageMask.DECRYPT)));
            client.activate(base);
            optional(
                "ReKey operation",
                Requests.reKey().uniqueIdentifier(base).build(),
                r -> created(r));
          });
      if (client.version() == ProtocolVersion.V1_4) importExport();
      optional("Archive", Requests.archive().uniqueIdentifier(aesId).build(), r -> {});
      optional("Recover", Requests.recover().uniqueIdentifier(aesId).build(), r -> {});
    }
    test(
        "Register and retrieve symmetric key",
        () -> {
          byte[] material = HexFormat.of().parseHex("00112233445566778899aabbccddeeff");
          String id =
              created(
                  call(
                      Requests.registerObject(
                          ManagedObjects.rawSymmetricKey(material, CryptographicAlgorithm.AES),
                          Attributes.usage(
                              CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT))));
          require(
              Arrays.equals(
                  material,
                  keyBytes(call(Requests.get().uniqueIdentifier(id).build()).requirePayload())),
              "Registered material differs");
        });
    test(
        "Register and retrieve SecretData",
        () -> {
          Ttlv secret =
              ManagedObjects.secretData(
                  SecretDataType.PASSWORD,
                  ManagedObjects.keyBlock(
                      KeyFormatType.RAW,
                      bytes(KEY_MATERIAL, "test-secret".getBytes(StandardCharsets.UTF_8)),
                      null,
                      null));
          String id = created(call(Requests.registerObject(secret)));
          require(
              Arrays.equals(
                  "test-secret".getBytes(StandardCharsets.UTF_8),
                  keyBytes(call(Requests.get().uniqueIdentifier(id).build()).requirePayload())),
              "SecretData differs");
        });
    asymmetric();
    if (client.version().atLeast(ProtocolVersion.V1_2)) {
      hashMacRandomSplit();
    }
    // No operation has this correlation value: Poll fails with Item Not Found (1.4 section 4.28),
    // and Cancel answers Cancellation Result Unavailable (1.4 section 4.27).
    negative(
        "Poll unknown correlation",
        Requests.poll().add(bytes(ASYNCHRONOUS_CORRELATION_VALUE, new byte[] {1, 2, 3})).build(),
        ResultReason.ITEM_NOT_FOUND);
    optional(
        "Cancel unknown correlation",
        Requests.cancel().add(bytes(ASYNCHRONOUS_CORRELATION_VALUE, new byte[] {1, 2, 3})).build(),
        r ->
            require(
                r.requirePayload().require(CANCELLATION_RESULT).intValue()
                    == CancellationResult.UNAVAILABLE.code(),
                "Cancellation Result"));
    if (aesId != null) {
      test(
          "Batch Get/GetAttributes",
          () -> {
            Response response =
                client.batch(
                    List.of(
                        Requests.get().uniqueIdentifier(aesId).build(),
                        Requests.getAttributes()
                            .uniqueIdentifier(aesId)
                            .add(text(ATTRIBUTE_NAME, "State"))
                            .build()));
            require(response.results().size() == 2, "Batch result count");
            for (Result r : response.results()) r.requireSuccess();
          });
      test(
          "Failed Get preserves KMIP reason",
          () -> {
            Result r =
                client.execute(
                    Requests.get().uniqueIdentifier("keytend-absent-" + UUID.randomUUID()).build());
            require(r.status() == 1 && r.reason() != null, "Missing structured failure");
            if (r.reason() != ResultReason.ITEM_NOT_FOUND.code()) {
              throw new AssertionError("Expected ItemNotFound, got " + r.reason());
            }
          });
      test(
          "Revoke",
          () -> {
            call(
                Requests.revoke(
                    aesId, RevocationReasonCode.CESSATION_OF_OPERATION, "integration test"));
          });
    }
    for (String id : new ArrayList<>(resources))
      test(
          "Destroy resource",
          () -> {
            // Revocation also permits cleanup of active asymmetric keys.
            client.execute(
                Requests.revoke(id, RevocationReasonCode.CESSATION_OF_OPERATION, "cleanup"));
            Result r = client.execute(Requests.destroy().uniqueIdentifier(id).build());
            exercised.add(Operation.DESTROY);
            require(
                r.successful()
                    || (r.reason() != null && r.reason() == ResultReason.ITEM_NOT_FOUND.code()),
                "Cleanup failed " + r);
          });
    for (Operation op : Operation.values()) {
      if (!client.version().atLeast(op.since()))
        checks.add(new Check(op.wireName(), "VERSION", "Requires " + op.since()));
      else if (op.serverToClient())
        checks.add(
            new Check(
                op.wireName(),
                "CALLBACK",
                "Tested with the SDK mTLS callback listener; this server does not initiate"
                    + " callbacks"));
      else if (!exercised.contains(op))
        checks.add(
            new Check(
                op.wireName(),
                advertised.contains(op) ? "UNEXERCISED" : "UNSUPPORTED",
                "No successful scenario on this server"));
    }
    return List.copyOf(checks);
  }

  private void attributes() {
    String name = "x-keytend-text";
    optional(
        "AddAttribute",
        Requests.addAttribute()
            .uniqueIdentifier(aesId)
            .attribute(Attributes.textAttribute(name, "one"))
            .build(),
        r -> {});
    if (advertised.contains(Operation.ADD_ATTRIBUTE)) {
      optional(
          "ModifyAttribute",
          Requests.modifyAttribute()
              .uniqueIdentifier(aesId)
              .attribute(Attributes.attribute(name, 0, text(ATTRIBUTE_VALUE, "two")))
              .build(),
          r -> {});
      optional(
          "DeleteAttribute",
          Requests.deleteAttribute()
              .uniqueIdentifier(aesId)
              .add(text(ATTRIBUTE_NAME, name), integer(ATTRIBUTE_INDEX, 0))
              .build(),
          r -> {});
    } else {
      // PyKMIP supports modifying/deleting names, despite omitting these from Query.
      optional(
          "ModifyAttribute",
          Requests.modifyAttribute()
              .uniqueIdentifier(aesId)
              .attribute(
                  Attributes.attribute(
                      "Name",
                      0,
                      structure(
                          NAME,
                          text(NAME_VALUE, "keytend-renamed"),
                          enumeration(NAME_TYPE, NameType.UNINTERPRETED_TEXT_STRING))))
              .build(),
          r -> {});
      optional(
          "DeleteAttribute",
          Requests.deleteAttribute()
              .uniqueIdentifier(aesId)
              .add(text(ATTRIBUTE_NAME, "Name"), integer(ATTRIBUTE_INDEX, 0))
              .build(),
          r -> {});
    }
  }

  private void aesCrypto() {
    test(
        "AES-CBC encryption/decryption against JCE",
        () -> {
          byte[] plain = "KMIP interoperability: Java 17, 21, 25".getBytes(StandardCharsets.UTF_8),
              iv = new byte[16];
          Arrays.fill(iv, (byte) 0x3c);
          Ttlv[] params = {
            enumeration(CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.AES),
            enumeration(BLOCK_CIPHER_MODE, BlockCipherMode.CBC),
            enumeration(PADDING_METHOD, PaddingMethod.PKCS5)
          };
          Result encrypted =
              call(
                  Requests.encrypt()
                      .uniqueIdentifier(aesId)
                      .cryptographicParameters(params)
                      .data(plain)
                      .add(bytes(IV_COUNTER_NONCE, iv))
                      .build());
          byte[] ciphertext = encrypted.requirePayload().require(DATA).bytesValue();
          Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
          cipher.init(
              Cipher.ENCRYPT_MODE, new SecretKeySpec(aesKey, "AES"), new IvParameterSpec(iv));
          require(Arrays.equals(cipher.doFinal(plain), ciphertext), "Ciphertext differs from JCE");
          Result decrypted =
              call(
                  Requests.decrypt()
                      .uniqueIdentifier(aesId)
                      .cryptographicParameters(params)
                      .data(ciphertext)
                      .add(bytes(IV_COUNTER_NONCE, iv))
                      .build());
          require(
              Arrays.equals(plain, decrypted.requirePayload().require(DATA).bytesValue()),
              "Decrypted plaintext differs");
        });
  }

  private void derive() {
    test(
        "DeriveKey PBKDF2",
        () -> {
          byte[] password = "test-password".getBytes(StandardCharsets.UTF_8),
              salt = {1, 2, 3, 4, 5, 6, 7, 8};
          Ttlv secret =
              ManagedObjects.secretData(
                  SecretDataType.PASSWORD,
                  ManagedObjects.keyBlock(
                      KeyFormatType.RAW, bytes(KEY_MATERIAL, password), null, null));
          String base =
              created(
                  call(
                      Requests.registerObject(
                          secret, Attributes.usage(CryptographicUsageMask.DERIVE_KEY))));
          // Derive Key uses the base object, which must be Active (1.4 section 3.22).
          client.activate(base);
          optional(
              "DeriveKey PBKDF2 operation",
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
                      Attributes.template(
                          Attributes.algorithm(CryptographicAlgorithm.AES),
                          Attributes.length(128),
                          Attributes.usage(
                              CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT)))
                  .build(),
              r -> {
                String id = created(r);
                byte[] key = keyBytes(client.get(id).requirePayload());
                PBEKeySpec spec = new PBEKeySpec("test-password".toCharArray(), salt, 1000, 128);
                byte[] expected =
                    SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                        .generateSecret(spec)
                        .getEncoded();
                spec.clearPassword();
                require(Arrays.equals(expected, key), "PBKDF2 differs from JCE");
              });
        });
  }

  private void importExport() {
    optional(
        "Export",
        Requests.export().uniqueIdentifier(aesId).build(),
        r ->
            require(
                r.requirePayload().child(SYMMETRIC_KEY).isPresent(), "Exported object missing"));
    final RestoreFixture[] restored = new RestoreFixture[1];
    optional(
        "Import",
        Operation.IMPORT,
        () -> {
          try {
            restored[0] = prepareRestore(client, resources);
          } catch (KmipException e) {
            if (pykmipContactInformation(server, identity, client.version(), e.result()))
              throw new ServerLimitation(
                  "PY-CONTACT-INFORMATION: the restore fixture's nondefault Contact Information"
                      + " is refused at Create ("
                      + e.result().message()
                      + "); PyKMIP implements no"
                      + " Import either");
            throw e;
          }
          return restoreRequest(client.version(), restored[0].id(), restored[0].exported());
        },
        r -> verifyRestore(client, restored[0], r));
  }

  /**
   * An Import that restores {@code exported}, an Export response payload, over the object it came
   * from (Replace Existing): the exported object with every exported attribute.
   */
  static Request restoreRequest(ProtocolVersion version, String id, Ttlv exported) {
    Ttlv object = null;
    for (Ttlv field : exported.children())
      if (List.of(SYMMETRIC_KEY.code(), PUBLIC_KEY.code(), PRIVATE_KEY.code(), SECRET_DATA.code())
          .contains(field.tag())) object = field;
    if (object == null) throw new AssertionError("Exported object missing");
    Request.Builder restore =
        Requests.importObject()
            .uniqueIdentifier(id)
            .add(exported.require(OBJECT_TYPE), bool(REPLACE_EXISTING, true));
    if (version.legacyAttributes()) exported.children(ATTRIBUTE).forEach(restore::add);
    else restore.add(exported.require(ATTRIBUTES));
    return restore.add(object).build();
  }

  /** Export a nondefault Active object, then destroy its material before attempting restoration. */
  static RestoreFixture prepareRestore(KmipClient client, Set<String> resources) throws Exception {
    String contact = "restore-" + UUID.randomUUID();
    String id =
        client
            .call(
                Requests.create()
                    .add(enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY))
                    .template(
                        Attributes.algorithm(CryptographicAlgorithm.AES),
                        Attributes.length(128),
                        Attributes.usage(
                            CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT),
                        Attributes.textAttribute("Contact Information", contact))
                    .build())
            .uniqueIdentifier();
    resources.add(id);
    client.activate(id);
    Ttlv exported = client.call(Requests.export().uniqueIdentifier(id).build()).requirePayload();
    require(
        attributeValue(exported, STATE, "State").intValue() == State.ACTIVE.code(),
        "Export must contain Active state");
    require(
        attributeValue(exported, CONTACT_INFORMATION, "Contact Information")
            .textValue()
            .equals(contact),
        "Export must contain the nondefault contact information");
    client.revoke(id, RevocationReasonCode.CESSATION_OF_OPERATION, "restore control");
    client.destroy(id);
    require(
        !client.execute(Requests.get().uniqueIdentifier(id).build()).successful(),
        "Destroyed source must not return material before Import");
    return new RestoreFixture(id, exported);
  }

  static void verifyRestore(KmipClient client, RestoreFixture fixture, Result result)
      throws Exception {
    require(result.uniqueIdentifier().equals(fixture.id()), "Imported ID");
    require(
        Arrays.equals(
            keyBytes(fixture.exported()), keyBytes(client.get(fixture.id()).requirePayload())),
        "Restored material differs");
    Ttlv actual =
        client
            .call(Requests.getAttributes().uniqueIdentifier(fixture.id()).build())
            .requirePayload();
    for (var field :
        List.of(
            Map.entry(STATE, "State"),
            Map.entry(CONTACT_INFORMATION, "Contact Information"),
            Map.entry(ACTIVATION_DATE, "Activation Date"))) {
      Ttlv expected = attributeValue(fixture.exported(), field.getKey(), field.getValue());
      Ttlv received = attributeValue(actual, field.getKey(), field.getValue());
      require(
          expected.retag(field.getKey()).equals(received.retag(field.getKey())),
          "Restored " + field.getValue() + " differs");
    }
  }

  private static Ttlv attributeValue(Ttlv payload, Tag tag, String legacyName) {
    Ttlv direct = find(payload, tag);
    if (direct != null) return direct;
    for (Ttlv attribute : payload.children(ATTRIBUTE))
      if (attribute.require(ATTRIBUTE_NAME).textValue().equals(legacyName))
        return attribute.require(ATTRIBUTE_VALUE);
    throw new AssertionError("Missing restored/exported " + legacyName);
  }

  record RestoreFixture(String id, Ttlv exported) {}

  /** Parse the issued object and prove its subject, key and (for our selected CA) issuer. */
  @SuppressWarnings("JavaUtilDate") // X509Certificate states its validity as Dates
  static java.security.cert.X509Certificate verifyIssuedCertificate(
      KmipClient client, Path certificates, String id, boolean selectedCa) throws Exception {
    byte[] der =
        client
            .get(id)
            .requirePayload()
            .require(CERTIFICATE)
            .require(CERTIFICATE_VALUE)
            .bytesValue();
    var issued =
        (java.security.cert.X509Certificate)
            java.security.cert.CertificateFactory.getInstance("X.509")
                .generateCertificate(new java.io.ByteArrayInputStream(der));
    var requested = x509(certificates, "client.pem");
    require(
        Arrays.equals(issued.getPublicKey().getEncoded(), requested.getPublicKey().getEncoded()),
        "Issued key differs from CSR key");
    require(
        issued.getSubjectX500Principal().equals(requested.getSubjectX500Principal()),
        "Issued subject differs from CSR subject");
    issued.checkValidity();
    if (selectedCa) {
      var ca = x509(certificates, "ca.pem");
      issued.verify(ca.getPublicKey());
      require(
          issued.getIssuerX500Principal().equals(ca.getSubjectX500Principal()), "Issuing CA name");
      require(
          !issued.getNotAfter().after(ca.getNotAfter())
              && !issued.getNotBefore().before(ca.getNotBefore()),
          "Issued validity exceeds CA validity");
    }
    return issued;
  }

  static void verifyRenewedCertificate(
      KmipClient client,
      Path certificates,
      String previousId,
      String renewedId,
      java.security.cert.X509Certificate previous,
      boolean selectedCa)
      throws Exception {
    require(!previousId.equals(renewedId), "Renewal must return a new certificate ID");
    var renewed = verifyIssuedCertificate(client, certificates, renewedId, selectedCa);
    require(
        !previous.getSerialNumber().equals(renewed.getSerialNumber()),
        "Renewal must change serial");
    require(
        Arrays.equals(previous.getPublicKey().getEncoded(), renewed.getPublicKey().getEncoded()),
        "Renewal must preserve subject key");
  }

  private void asymmetric() {
    final String[] pair = new String[2];
    test(
        "CreateKeyPair RSA-2048",
        () -> {
          Result r =
              call(
                  Requests.createKeyPair()
                      .add(
                          structure(
                              COMMON_TEMPLATE_ATTRIBUTE,
                              Attributes.algorithm(CryptographicAlgorithm.RSA),
                              Attributes.length(2048),
                              Attributes.usage(
                                  CryptographicUsageMask.SIGN, CryptographicUsageMask.VERIFY)))
                      .build());
          pair[0] = r.requirePayload().require(PRIVATE_KEY_UNIQUE_IDENTIFIER).textValue();
          pair[1] = r.requirePayload().require(PUBLIC_KEY_UNIQUE_IDENTIFIER).textValue();
          resources.addAll(List.of(pair));
        });
    if (pair[0] == null) return;
    test(
        "Activate asymmetric pair",
        () -> {
          client.activate(pair[0]);
          client.activate(pair[1]);
        });
    if (client.version().atLeast(ProtocolVersion.V1_2))
      test(
          "RSA signing and verification against JCA",
          () -> {
            byte[] data = "KMIP RSA signature".getBytes(StandardCharsets.UTF_8);
            Ttlv[] params = {
              enumeration(CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.RSA),
              enumeration(
                  DIGITAL_SIGNATURE_ALGORITHM,
                  DigitalSignatureAlgorithm.SHA_256_WITH_RSA_ENCRYPTION_PKCS_1_V1_5),
              enumeration(PADDING_METHOD, PaddingMethod.PKCS1_V1_5),
              enumeration(HASHING_ALGORITHM, HashingAlgorithm.SHA_256)
            };
            Result r =
                call(
                    Requests.sign()
                        .uniqueIdentifier(pair[0])
                        .cryptographicParameters(params)
                        .data(data)
                        .build());
            byte[] sig = r.requirePayload().require(SIGNATURE_DATA).bytesValue();
            Result pub = client.call(Requests.get().uniqueIdentifier(pair[1]).build());
            PublicKey key = Keys.rsaPublicKey(pub.requirePayload().require(PUBLIC_KEY));
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(key);
            verifier.update(data);
            require(verifier.verify(sig), "JCA verification failed");
            Result verify =
                call(
                    Requests.signatureVerify()
                        .uniqueIdentifier(pair[1])
                        .cryptographicParameters(params)
                        .data(data)
                        .add(bytes(SIGNATURE_DATA, sig))
                        .build());
            if (verify.requirePayload().require(VALIDITY_INDICATOR).intValue()
                != ValidityIndicator.VALID.code()) {
              throw new AssertionError("Signature validity");
            }
          });
    optional(
        "ReKeyKeyPair",
        Requests.reKeyKeyPair().add(text(PRIVATE_KEY_UNIQUE_IDENTIFIER, pair[0])).build(),
        r -> {
          resources.add(r.requirePayload().require(PRIVATE_KEY_UNIQUE_IDENTIFIER).textValue());
          resources.add(r.requirePayload().require(PUBLIC_KEY_UNIQUE_IDENTIFIER).textValue());
        });
    final String[] certificate = new String[1];
    final java.security.cert.X509Certificate[] issued = new java.security.cert.X509Certificate[1];
    optional(
        "Certify",
        Operation.CERTIFY,
        () -> {
          // The Certificate Request (client.csr) carries and is signed by the client's key, so the
          // Public Key certified is that key; a request for another key cannot certify it (1.4
          // section 4.7).
          String subject =
              created(
                  call(
                      Requests.registerObject(
                          rsaPublicKey(x509("client.pem").getPublicKey()),
                          Attributes.usage(CryptographicUsageMask.VERIFY))));
          return Requests.certify()
              .uniqueIdentifier(subject)
              .add(
                  enumeration(CERTIFICATE_REQUEST_TYPE, CertificateRequestType.PKCS_10),
                  bytes(CERTIFICATE_REQUEST, pem("client.csr")))
              .template(issuer())
              .build();
        },
        r -> {
          certificate[0] = created(r);
          issued[0] =
              verifyIssuedCertificate(
                  client, certificates, certificate[0], server.equals(KEYTEND_SERVER));
        });
    // Re-certify renews a certificate, not a key. The 1.x request table marks the Certificate
    // Request required, while the 1.1-1.4 prose lets it be omitted; supplying it satisfies both.
    if (certificate[0] != null)
      optional(
          "ReCertify",
          Requests.reCertify()
              .uniqueIdentifier(certificate[0])
              .add(
                  enumeration(CERTIFICATE_REQUEST_TYPE, CertificateRequestType.PKCS_10),
                  bytes(CERTIFICATE_REQUEST, pemUnchecked("client.csr")))
              .build(),
          r ->
              verifyRenewedCertificate(
                  client,
                  certificates,
                  certificate[0],
                  created(r),
                  issued[0],
                  server.equals(KEYTEND_SERVER)));
    optional(
        "Validate certificate",
        Requests.validate()
            .add(ManagedObjects.certificate(CertificateType.X_509, pemUnchecked("ca.pem")))
            .build(),
        r ->
            require(
                r.requirePayload().require(VALIDITY_INDICATOR).intValue()
                    == ValidityIndicator.VALID.code(),
                "Certificate validation"));
  }

  /**
   * Create Split Key of {@code keyId} into three XOR parts. The objects created are Split Keys, so
   * Object Type is Split Key (1.2 section 4.38; OASIS TC-SJ-1-14). The attributes describe those
   * parts; like TC-SJ-1-14 the suite sets none.
   */
  static Request splitRequest(String keyId, Ttlv attributes) {
    return Requests.createSplitKey()
        .add(
            enumeration(OBJECT_TYPE, ObjectType.SPLIT_KEY),
            text(UNIQUE_IDENTIFIER, keyId),
            integer(SPLIT_KEY_PARTS, 3),
            integer(SPLIT_KEY_THRESHOLD, 3),
            enumeration(SPLIT_KEY_METHOD, SplitKeyMethod.XOR),
            attributes)
        .build();
  }

  /**
   * The template attributes naming the CA that issues a Certify request's certificate. KMIP leaves
   * the CA to the server (1.0 section 4.6). keytend-kmip-server has none of its own: the caller
   * names a CA certificate it owns with a Certificate Link, linked to the CA's public key and that
   * to its private key (its docs/certify-and-server-to-client.md). For keytend-kmip-server the test
   * CA (ca.pem, ca-key.pem) is registered that way; other servers use their own CA.
   */
  private Ttlv[] issuer() throws Exception {
    if (!server.equals(KEYTEND_SERVER)) return new Ttlv[0];
    return new Ttlv[] {
      Attributes.link(LinkType.CERTIFICATE_LINK, registerIssuingCa(client, certificates, resources))
    };
  }

  /** Registers and activates the test CA's key pair and certificate, linked; the certificate ID. */
  static String registerIssuingCa(KmipClient client, Path certificates, Set<String> resources)
      throws Exception {
    java.security.cert.X509Certificate ca = x509(certificates, "ca.pem");
    String privateKey =
        client
            .call(
                Requests.registerObject(
                    ManagedObjects.privateKey(
                        ManagedObjects.keyBlock(
                            KeyFormatType.PKCS_8,
                            bytes(KEY_MATERIAL, pem(certificates, "ca-key.pem")),
                            CryptographicAlgorithm.RSA,
                            2048)),
                    Attributes.usage(
                        CryptographicUsageMask.SIGN, CryptographicUsageMask.CERTIFICATE_SIGN)))
            .uniqueIdentifier();
    resources.add(privateKey);
    String publicKey =
        client
            .call(
                Requests.registerObject(
                    rsaPublicKey(ca.getPublicKey()),
                    Attributes.usage(CryptographicUsageMask.VERIFY),
                    Attributes.link(LinkType.PRIVATE_KEY_LINK, privateKey)))
            .uniqueIdentifier();
    resources.add(publicKey);
    String certificate =
        client
            .call(
                Requests.registerObject(
                    ManagedObjects.certificate(CertificateType.X_509, ca.getEncoded()),
                    // The usage mask agrees with the certificate's keyUsage, keyCertSign and
                    // cRLSign (1.4 Table 96).
                    Attributes.usage(
                        CryptographicUsageMask.CERTIFICATE_SIGN, CryptographicUsageMask.CRL_SIGN),
                    Attributes.link(LinkType.PUBLIC_KEY_LINK, publicKey)))
            .uniqueIdentifier();
    resources.add(certificate);
    for (String id : List.of(privateKey, publicKey, certificate)) client.activate(id);
    return certificate;
  }

  static Ttlv rsaPublicKey(PublicKey key) {
    return ManagedObjects.publicKey(
        ManagedObjects.keyBlock(
            KeyFormatType.X_509,
            bytes(KEY_MATERIAL, key.getEncoded()),
            CryptographicAlgorithm.RSA,
            ((java.security.interfaces.RSAPublicKey) key).getModulus().bitLength()));
  }

  private java.security.cert.X509Certificate x509(String name) throws Exception {
    return x509(certificates, name);
  }

  static java.security.cert.X509Certificate x509(Path certificates, String name) throws Exception {
    return (java.security.cert.X509Certificate)
        java.security.cert.CertificateFactory.getInstance("X.509")
            .generateCertificate(new java.io.ByteArrayInputStream(pem(certificates, name)));
  }

  private void hashMacRandomSplit() {
    optional(
        "Hash SHA-256",
        Requests.hash()
            .cryptographicParameters(enumeration(HASHING_ALGORITHM, HashingAlgorithm.SHA_256))
            .data(new byte[] {1, 2, 3})
            .build(),
        r ->
            require(
                Arrays.equals(
                    MessageDigest.getInstance("SHA-256").digest(new byte[] {1, 2, 3}),
                    r.requirePayload().require(DATA).bytesValue()),
                "Hash differs from JCA"));
    if (advertised.contains(Operation.MAC))
      test(
          "HMAC-SHA256 against JCE",
          () -> {
            byte[] key = new byte[32], data = {1, 2, 3};
            Arrays.fill(key, (byte) 0x42);
            String id =
                created(
                    call(
                        Requests.registerObject(
                            ManagedObjects.rawSymmetricKey(key, CryptographicAlgorithm.HMAC_SHA256),
                            Attributes.usage(
                                CryptographicUsageMask.MAC_GENERATE,
                                CryptographicUsageMask.MAC_VERIFY))));
            client.activate(id);
            Result r =
                call(
                    Requests.mac()
                        .uniqueIdentifier(id)
                        .cryptographicParameters(
                            enumeration(
                                CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.HMAC_SHA256),
                            enumeration(HASHING_ALGORITHM, HashingAlgorithm.SHA_256))
                        .data(data)
                        .build());
            byte[] mac = r.requirePayload().require(MAC_DATA).bytesValue();
            Mac expected = Mac.getInstance("HmacSHA256");
            expected.init(new SecretKeySpec(key, "HmacSHA256"));
            require(Arrays.equals(expected.doFinal(data), mac), "MAC differs from JCE");
            optional(
                "MACVerify",
                Requests.macVerify()
                    .uniqueIdentifier(id)
                    .cryptographicParameters(
                        enumeration(CRYPTOGRAPHIC_ALGORITHM, CryptographicAlgorithm.HMAC_SHA256),
                        enumeration(HASHING_ALGORITHM, HashingAlgorithm.SHA_256))
                    .data(data)
                    .add(bytes(MAC_DATA, mac))
                    .build(),
                v ->
                    require(
                        v.requirePayload().require(VALIDITY_INDICATOR).intValue()
                            == ValidityIndicator.VALID.code(),
                        "MAC validity"));
          });
    optional(
        "RNGRetrieve",
        Requests.rngRetrieve().add(integer(DATA_LENGTH, 32)).build(),
        r -> require(r.requirePayload().require(DATA).bytesValue().length == 32, "RNG length"));
    optional(
        "RNGSeed", Requests.rngSeed().data(new byte[] {1, 2, 3, 4, 5, 6, 7, 8}).build(), r -> {});
    optional(
        "CreateSplitKey XOR",
        splitRequest(aesId, Attributes.template()),
        r -> {
          List<String> ids =
              r.requirePayload().children(UNIQUE_IDENTIFIER).stream().map(Ttlv::textValue).toList();
          require(ids.size() == 3, "Split parts");
          resources.addAll(ids);
          Request.Builder join =
              Requests.joinSplitKey().add(enumeration(OBJECT_TYPE, ObjectType.SYMMETRIC_KEY));
          for (String id : ids) join.uniqueIdentifier(id);
          join.template(
              Attributes.usage(CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT));
          optional(
              "JoinSplitKey",
              join.build(),
              j ->
                  require(
                      Arrays.equals(aesKey, keyBytes(client.get(created(j)).requirePayload())),
                      "Joined material differs"));
        });
  }

  @FunctionalInterface
  interface ResultCheck {
    void accept(Result result) throws Exception;
  }

  /** Builds a scenario's request; its setup calls count as part of the check. */
  @FunctionalInterface
  interface Prepared {
    Request get() throws Exception;
  }

  private void optional(String name, Request request, ResultCheck validate) {
    optional(name, request.operation(), () -> request, validate);
  }

  private void optional(String name, Operation operation, Prepared prepared, ResultCheck validate) {
    if (!client.version().atLeast(operation.since())) return;
    test(
        name,
        () -> {
          Request request = prepared.get();
          exercised.add(operation);
          Result r = exchange(request);
          if (!r.successful()) {
            unsupported(r);
            throw new KmipException(r);
          }
          validate.accept(r);
        });
  }

  /**
   * A request the server must refuse with {@code expected}. A server without the operation is
   * recorded as not supporting it.
   */
  private void negative(String name, Request request, ResultReason expected) {
    if (!client.version().atLeast(request.operation().since())) return;
    test(
        name,
        () -> {
          exercised.add(request.operation());
          Result r = exchange(request);
          require(!r.successful(), "Accepted: " + r);
          unsupported(r);
          require(
              r.hasReason(expected),
              "Expected " + expected.wireName() + ", got " + r.reason() + " " + r.message());
        });
  }

  private Result exchange(Request request) throws Exception {
    try {
      return client.execute(request);
    } catch (ProtocolException e) {
      Ttlv h = e.response().require(RESPONSE_HEADER), b = e.response().require(BATCH_ITEM);
      if (server.equals("pykmip")
          && !advertised.contains(request.operation())
          && h.require(PROTOCOL_VERSION).require(PROTOCOL_VERSION_MINOR).intValue() == 0
          && b.require(RESULT_STATUS).intValue() == 1
          && b.require(RESULT_REASON).intValue() == 4
          && b.require(RESULT_MESSAGE)
              .textValue()
              .equals("Error parsing request message. See server logs for more information."))
        throw new ServerLimitation(
            "PY-UNSUPPORTED-PARSER: unsupported operation produces an InvalidMessage with a"
                + " KMIP 1.0 header");
      throw e;
    }
  }

  /** Throws when a failed result means the operation is unsupported. */
  private void unsupported(Result r) throws Exception {
    if (r.reason() != null && (r.reason() == 5 || r.reason() == 8)) {
      throw new Unsupported(r);
    }
  }

  private Result call(Request request) throws Exception {
    exercised.add(request.operation());
    return client.call(request);
  }

  private String created(Result r) {
    String id = r.uniqueIdentifier();
    resources.add(id);
    return id;
  }

  private void test(String name, Checked body) {
    try {
      body.run();
      checks.add(new Check(name, "PASS", ""));
    } catch (ProtocolException e) {
      Ttlv raw = e.response();
      Ttlv header = raw.child(RESPONSE_HEADER).orElse(null);
      Ttlv batch = raw.child(BATCH_ITEM).orElse(null);
      if (server.equals("pykmip")
          && header != null
          && batch != null
          && header.require(PROTOCOL_VERSION).require(PROTOCOL_VERSION_MINOR).intValue() == 0
          && batch.require(RESULT_STATUS).intValue() == 1
          && batch.child(RESULT_REASON).map(n -> n.intValue() == 5).orElse(false))
        checks.add(
            new Check(
                name,
                "SERVER_LIMITATION",
                "PY-ERROR-VERSION: unsupported operation returned a KMIP 1.0 error header"));
      else checks.add(new Check(name, "FAIL", e + " cause=" + e.getCause()));
    } catch (ServerLimitation e) {
      checks.add(new Check(name, "SERVER_LIMITATION", e.getMessage()));
    } catch (Unsupported e) {
      checks.add(new Check(name, "UNSUPPORTED", e.getMessage()));
    } catch (Exception | AssertionError e) {
      checks.add(
          new Check(
              name,
              "FAIL",
              e.toString() + (e instanceof KmipException k ? " " + k.result().message() : "")));
    }
  }

  private byte[] pemUnchecked(String name) {
    try {
      return pem(name);
    } catch (Exception e) {
      throw new IllegalStateException("Cannot load integration certificate", e);
    }
  }

  private byte[] pem(String name) throws Exception {
    return pem(certificates, name);
  }

  static byte[] pem(Path certificates, String name) throws Exception {
    String text = Files.readString(certificates.resolve(name));
    return Base64.getMimeDecoder().decode(text.replaceAll("-----[^\\r\\n]+-----", ""));
  }

  static final class ServerLimitation extends Exception {
    ServerLimitation(String message) {
      super(message);
    }
  }

  static final class Unsupported extends Exception {
    Unsupported(Result r) {
      super("status=" + r.status() + ", reason=" + r.reason());
    }
  }

  static void require(boolean condition, String message) {
    if (!condition) throw new AssertionError(message);
  }

  static Ttlv find(Ttlv root, Tag tag) {
    if (root.tag() == tag.code()) return root;
    if (root.type() == Ttlv.Type.STRUCTURE)
      for (Ttlv c : root.children()) {
        Ttlv found = find(c, tag);
        if (found != null) return found;
      }
    return null;
  }

  static byte[] keyBytes(Ttlv payload) {
    Ttlv material = find(payload, KEY_MATERIAL);
    if (material == null) throw new AssertionError("No key material");
    return material.type() == Ttlv.Type.BYTE_STRING
        ? material.bytesValue()
        : material.require(KEY).bytesValue();
  }

  /**
   * The report of one run: the server, the version, the JDK and each check (name, outcome,
   * detail), in that order, as indented JSON ({@link Catalog#indentedJson}).
   */
  public static void writeReport(
      Path path, String server, ProtocolVersion version, List<Check> checks) throws Exception {
    Files.createDirectories(path.toAbsolutePath().getParent());
    Map<String, Object> report = new LinkedHashMap<>();
    report.put("server", server);
    report.put("version", version.toString());
    report.put("java", System.getProperty("java.version"));
    List<Map<String, Object>> entries = new ArrayList<>();
    for (Check c : checks) {
      Map<String, Object> entry = new LinkedHashMap<>();
      entry.put("name", c.name());
      entry.put("outcome", c.outcome());
      entry.put("detail", c.detail());
      entries.add(entry);
    }
    report.put("checks", entries);
    Files.writeString(path, Catalog.indentedJson(report) + "\n");
  }
}
