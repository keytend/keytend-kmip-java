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

package dev.keytend.kmip;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.codec.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.HashedPasswordTransport;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.stream.*;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;

/**
 * Wire field order of request structures. Expected orders are typed
 * in from the OASIS tables, independently of the generated order registry, and compared against
 * the element order of the encoded request.
 */
class FieldOrderTest {
  private static final TtlvCodec CODEC = new TtlvCodec();

  /** Element order after encoding to the wire and decoding again. */
  private static List<String> wireOrder(Ttlv message, Tag structure) throws IOException {
    Ttlv decoded = CODEC.decode(CODEC.encode(message));
    Ttlv found = find(decoded, structure.code());
    assertNotNull(found, structure.wireName() + " not on the wire");
    return found.children().stream().map(Ttlv::tagName).toList();
  }

  private static Ttlv find(Ttlv node, int tag) {
    if (node.tag() == tag) return node;
    if (node.type() != Ttlv.Type.STRUCTURE) return null;
    for (Ttlv child : node.children()) {
      Ttlv found = find(child, tag);
      if (found != null) return found;
    }
    return null;
  }

  private static List<Ttlv> reversed(List<Ttlv> fields) {
    List<Ttlv> copy = new ArrayList<>(fields);
    Collections.reverse(copy);
    return copy;
  }

  private static Ttlv big(Tag tag) {
    return bigInteger(tag, BigInteger.valueOf(tag.code()));
  }

  /**
   * KMIP 1.1 Tables 13-25, 1.4 Tables 14-28, 2.1 Tables 18-26 and 3.0 CSD02 Tables 38-47: Key
   * Material Object Structure for each transparent Key Format Type.
   */
  private static final Map<Enums.KeyFormatType, List<Tag>> KEY_MATERIAL_TABLES =
      Map.ofEntries(
          Map.entry(Enums.KeyFormatType.TRANSPARENT_SYMMETRIC_KEY, List.of(KEY)),
          Map.entry(Enums.KeyFormatType.TRANSPARENT_DSA_PRIVATE_KEY, List.of(P, Q, G, X)),
          Map.entry(Enums.KeyFormatType.TRANSPARENT_DSA_PUBLIC_KEY, List.of(P, Q, G, Y)),
          Map.entry(
              Enums.KeyFormatType.TRANSPARENT_RSA_PRIVATE_KEY,
              List.of(
                  MODULUS,
                  PRIVATE_EXPONENT,
                  PUBLIC_EXPONENT,
                  P,
                  Q,
                  PRIME_EXPONENT_P,
                  PRIME_EXPONENT_Q,
                  CRT_COEFFICIENT)),
          Map.entry(
              Enums.KeyFormatType.TRANSPARENT_RSA_PUBLIC_KEY, List.of(MODULUS, PUBLIC_EXPONENT)),
          Map.entry(Enums.KeyFormatType.TRANSPARENT_DH_PRIVATE_KEY, List.of(P, Q, G, J, X)),
          Map.entry(Enums.KeyFormatType.TRANSPARENT_DH_PUBLIC_KEY, List.of(P, Q, G, J, Y)),
          Map.entry(
              Enums.KeyFormatType.TRANSPARENT_ECDSA_PRIVATE_KEY, List.of(RECOMMENDED_CURVE, D)),
          Map.entry(
              Enums.KeyFormatType.TRANSPARENT_ECDSA_PUBLIC_KEY,
              List.of(RECOMMENDED_CURVE, Q_STRING)),
          Map.entry(
              Enums.KeyFormatType.TRANSPARENT_ECDH_PRIVATE_KEY, List.of(RECOMMENDED_CURVE, D)),
          Map.entry(
              Enums.KeyFormatType.TRANSPARENT_ECDH_PUBLIC_KEY,
              List.of(RECOMMENDED_CURVE, Q_STRING)),
          Map.entry(
              Enums.KeyFormatType.TRANSPARENT_ECMQV_PRIVATE_KEY, List.of(RECOMMENDED_CURVE, D)),
          Map.entry(
              Enums.KeyFormatType.TRANSPARENT_ECMQV_PUBLIC_KEY,
              List.of(RECOMMENDED_CURVE, Q_STRING)),
          Map.entry(Enums.KeyFormatType.TRANSPARENT_EC_PRIVATE_KEY, List.of(RECOMMENDED_CURVE, D)),
          Map.entry(
              Enums.KeyFormatType.TRANSPARENT_EC_PUBLIC_KEY, List.of(RECOMMENDED_CURVE, Q_STRING)),
          Map.entry(Enums.KeyFormatType.SEED_PRIVATE_KEY, List.of(SEED, KEY)));

  private static Ttlv field(Tag tag) {
    return switch (tag) {
      case KEY, Q_STRING, SEED -> bytes(tag, new byte[] {1, 2, 3});
      case RECOMMENDED_CURVE -> enumeration(tag, Enums.RecommendedCurve.P_256);
      default -> big(tag);
    };
  }

  @TestFactory
  Stream<DynamicTest> transparentKeyMaterialFollowsTheKeyFormatTypeTable() {
    List<DynamicTest> tests = new ArrayList<>();
    for (ProtocolVersion version : ProtocolVersion.values())
      for (var entry : KEY_MATERIAL_TABLES.entrySet()) {
        Enums.KeyFormatType format = entry.getKey();
        // 2.0 turned the Transparent EC* formats into Reserved values.
        if (!format.definedIn(version)
            || entry.getValue().stream().anyMatch(t -> !version.atLeast(t.since()))) continue;
        tests.add(
            DynamicTest.dynamicTest(
                version + " " + format.wireName(),
                () -> {
                  List<Ttlv> fields = entry.getValue().stream().map(FieldOrderTest::field).toList();
                  // Supplied in reverse table order through the low-level, order-preserving API.
                  Ttlv material = structure(KEY_MATERIAL, reversed(fields));
                  Ttlv object =
                      ManagedObjects.privateKey(
                          ManagedObjects.keyBlock(format, material, null, null));
                  Ttlv message =
                      Messages.request(
                          version,
                          List.of(
                              Requests.register()
                                  .add(
                                      enumeration(OBJECT_TYPE, Enums.ObjectType.PRIVATE_KEY),
                                      object)
                                  .build()),
                          RequestOptions.DEFAULT);
                  assertEquals(
                      entry.getValue().stream().map(Tag::wireName).toList(),
                      wireOrder(message, KEY_MATERIAL));
                }));
      }
    return tests.stream();
  }

  /** KMIP 1.4 Tables 4-6, 2.1 Tables 411-416 and 3.0 CSD02 Tables 519-524. */
  private static final Map<Enums.CredentialType, List<Ttlv>> CREDENTIAL_VALUE_TABLES =
      Map.of(
          Enums.CredentialType.USERNAME_AND_PASSWORD,
          List.of(text(USERNAME, "u"), text(PASSWORD, "p")),
          Enums.CredentialType.DEVICE,
          List.of(
              text(DEVICE_SERIAL_NUMBER, "serial"),
              text(PASSWORD, "p"),
              text(DEVICE_IDENTIFIER, "device"),
              text(NETWORK_IDENTIFIER, "network"),
              text(MACHINE_IDENTIFIER, "machine"),
              text(MEDIA_IDENTIFIER, "media")),
          Enums.CredentialType.ATTESTATION,
          List.of(
              structure(NONCE, bytes(NONCE_ID, new byte[] {1}), bytes(NONCE_VALUE, new byte[] {2})),
              enumeration(ATTESTATION_TYPE, Enums.AttestationType.TPM_QUOTE),
              bytes(ATTESTATION_MEASUREMENT, new byte[] {3}),
              bytes(ATTESTATION_ASSERTION, new byte[] {4})),
          Enums.CredentialType.ONE_TIME_PASSWORD,
          List.of(text(USERNAME, "u"), text(PASSWORD, "p"), text(ONE_TIME_PASSWORD, "123456")),
          Enums.CredentialType.HASHED_PASSWORD,
          List.of(
              text(USERNAME, "u"),
              Ttlv.of(TIME_STAMP.code(), Ttlv.Type.DATE_TIME_EXTENDED, 1L),
              enumeration(HASHING_ALGORITHM, Enums.HashingAlgorithm.SHA_256),
              bytes(HASHED_PASSWORD, new byte[] {5})));

  @TestFactory
  Stream<DynamicTest> credentialValueFollowsTheCredentialTypeTable() {
    List<DynamicTest> tests = new ArrayList<>();
    for (ProtocolVersion version : ProtocolVersion.values())
      for (var entry : CREDENTIAL_VALUE_TABLES.entrySet()) {
        if (!version.atLeast(entry.getKey().since())) continue;
        tests.add(
            DynamicTest.dynamicTest(
                version + " " + entry.getKey().wireName(),
                () -> {
                  Ttlv credential =
                      structure(
                          CREDENTIAL,
                          enumeration(CREDENTIAL_TYPE, entry.getKey()),
                          structure(CREDENTIAL_VALUE, reversed(entry.getValue())));
                  Ttlv message =
                      Messages.request(
                          version,
                          List.of(Requests.query().build()),
                          RequestOptions.DEFAULT.authentication(
                              structure(AUTHENTICATION, credential)));
                  assertEquals(
                      entry.getValue().stream().map(Ttlv::tagName).toList(),
                      wireOrder(message, CREDENTIAL_VALUE));
                  // The typed builder emits the same order without canonicalization.
                  assertEquals(
                      entry.getValue().stream().map(Ttlv::tagName).toList(),
                      Credentials.credential(
                              entry.getKey(), reversed(entry.getValue()).toArray(Ttlv[]::new))
                          .require(CREDENTIAL_VALUE)
                          .children()
                          .stream()
                          .map(Ttlv::tagName)
                          .toList());
                }));
      }
    return tests.stream();
  }

  @Test
  void hashedPasswordCredentialKeepsTimestampSecondOnTheWire_kmip21Table415() throws Exception {
    List<Ttlv> sent = new ArrayList<>();
    var transport =
        new HashedPasswordTransport(
            request -> {
              sent.add(request);
              throw new IOException("captured");
            },
            "alice",
            "secret".toCharArray());
    try (var client = new KmipClient(transport, ProtocolVersion.V2_1)) {
      assertThrows(IOException.class, () -> client.call(Requests.query().build()));
    }
    assertEquals(
        List.of("Username", "TimeStamp", "HashingAlgorithm", "HashedPassword"),
        wireOrder(sent.get(0), CREDENTIAL_VALUE));
  }

  @Test
  void unknownCredentialTypesAndKeyFormatsKeepTheSuppliedOrder() throws IOException {
    Ttlv credential =
        structure(
            CREDENTIAL,
            enumeration(CREDENTIAL_TYPE, 0x80000001),
            structure(CREDENTIAL_VALUE, text(PASSWORD, "p"), text(USERNAME, "u")));
    Ttlv message =
        Messages.request(
            ProtocolVersion.V2_1,
            List.of(Requests.query().build()),
            RequestOptions.DEFAULT.authentication(structure(AUTHENTICATION, credential)));
    assertEquals(List.of("Password", "Username"), wireOrder(message, CREDENTIAL_VALUE));
  }

  @Test
  void unlistedFieldsKeepTheirPositionInsteadOfMovingToTheEnd() {
    Ttlv vendor = Ttlv.of(0x540001, Ttlv.Type.TEXT_STRING, "vendor");
    Ttlv block =
        structure(
            KEY_BLOCK,
            enumeration(KEY_FORMAT_TYPE, Enums.KeyFormatType.RAW),
            vendor,
            structure(KEY_VALUE, bytes(KEY_MATERIAL, new byte[16])),
            integer(CRYPTOGRAPHIC_LENGTH, 128),
            enumeration(CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.AES));
    assertEquals(
        List.of(
            "KeyFormatType",
            "0x540001",
            "KeyValue",
            "CryptographicAlgorithm",
            "CryptographicLength"),
        Structures.canonical(ProtocolVersion.V1_4, block).children().stream()
            .map(Ttlv::tagName)
            .toList());
  }

  @Test
  void dhBuildersEmitJBeforeTheKey_kmip14Tables19And20() {
    BigInteger one = BigInteger.ONE;
    assertEquals(
        List.of("P", "Q", "G", "J", "Y"),
        KeyMaterials.dhPublic(one, one, one, bigInteger(J, one), bigInteger(Q, one))
            .children()
            .stream()
            .map(Ttlv::tagName)
            .toList());
    assertEquals(
        List.of("P", "Q", "G", "J", "X"),
        KeyMaterials.dhPrivate(one, one, one, one, one).children().stream()
            .map(Ttlv::tagName)
            .toList());
    assertEquals(
        List.of("P", "G", "X"),
        KeyMaterials.dhPrivate(one, null, one, null, one).children().stream()
            .map(Ttlv::tagName)
            .toList());
    assertEquals(
        List.of("Modulus", "PrivateExponent", "PublicExponent", "P", "Q"),
        KeyMaterials.rsaPrivate(one, one, big(Q), big(P), big(PUBLIC_EXPONENT)).children().stream()
            .map(Ttlv::tagName)
            .toList());
  }

  /** Every OASIS request vector is already in normative order, so canonicalization is identity. */
  @Test
  void canonicalizationLeavesEveryOasisRequestVectorUnchanged() throws Exception {
    int requests = 0;
    List<String> changed = new ArrayList<>();
    try (var walk = Files.walk(Path.of("src/test/resources/oasis"))) {
      for (Path path : walk.filter(p -> p.toString().endsWith(".xml")).sorted().toList()) {
        List<Ttlv> nodes =
            new XmlCodec()
                .decodeAll(
                    OasisVectorsTest.resolve(Files.readString(path))
                        .getBytes(StandardCharsets.UTF_8));
        for (Ttlv node : nodes) {
          if (node.tag() != REQUEST_MESSAGE.code()) continue;
          ProtocolVersion version;
          try {
            version = Messages.version(node.require(REQUEST_HEADER));
          } catch (IllegalArgumentException outOfScope) {
            continue; // KMIP 1.0 negative vectors
          }
          requests++;
          if (!Structures.canonical(version, node).equals(node)) changed.add(path.toString());
        }
      }
    }
    assertTrue(requests > 3000, "OASIS request vectors must be available");
    assertEquals(List.of(), changed);
  }

  /** Every operation name in the generated registries resolves to an Operation. */
  @Test
  void registriesUseOperationWireNames_hashInKmip12To14() throws Exception {
    Set<String> names =
        Arrays.stream(Operation.values()).map(Operation::wireName).collect(Collectors.toSet());
    for (String resource : List.of("payloads.tsv", "order.tsv"))
      try (var in = Structures.class.getResourceAsStream("/dev/keytend/kmip/" + resource)) {
        for (String line : new String(in.readAllBytes(), StandardCharsets.UTF_8).split("\n")) {
          String[] cells = line.split("\t");
          String op =
              resource.equals("payloads.tsv")
                  ? cells[1]
                  : cells[0].contains(":RequestPayload:") ? cells[0].split(":")[2] : null;
          if (op != null) assertTrue(names.contains(op), resource + ": " + op);
        }
      }
    for (ProtocolVersion v :
        List.of(ProtocolVersion.V1_2, ProtocolVersion.V1_3, ProtocolVersion.V1_4))
      assertFalse(
          ProtocolSchema.fields(v, Operation.HASH, ProtocolSchema.Direction.REQUEST).isEmpty(),
          v.toString());
  }
}
