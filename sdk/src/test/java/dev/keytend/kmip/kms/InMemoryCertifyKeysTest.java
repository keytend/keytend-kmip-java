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

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.Request;
import dev.keytend.kmip.client.RequestOptions;
import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.client.Response;
import dev.keytend.kmip.client.Result;
import dev.keytend.kmip.model.Attributes;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Enums.ResultReason;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.security.KeyPair;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The in-memory server's Certify takes the subject keys keytend-kmip-server issues for: RSA of 2048
 * bits or more, or EC on P-256, P-384 or P-521. Others are Feature Not Supported. Certify is
 * refused in Undo batches, as there.
 */
class InMemoryCertifyKeysTest {
  static final X500Principal SUBJECT = new X500Principal("CN=certify");

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void subjectKeysAreRsa2048OrTheNistCurves(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    try (Kms kms = TlsIdentityTest.connect(server)) {
      TlsIssuer issuer = TlsIssueTest.register(kms, TlsIssueTest.Ca.ec("Issuing CA"));
      String issuerId = issuer.certificate().id();
      KeyPair p256 = InMemoryReProvisionTest.ecKey("secp256r1");
      String p256Id =
          kms.keys()
              .register(p256.getPublic())
              .named("p256")
              .usages(KeyUsage.VERIFY)
              .register()
              .id();

      // Another named curve: refused from the request, before the public key is looked at.
      for (String curve : List.of("brainpoolP256r1", "secp256k1")) {
        Result r =
            kms.protocol()
                .execute(
                    certify(
                        kms,
                        p256Id,
                        InMemoryReProvisionTest.otherCurveRequest(SUBJECT, curve),
                        issuerId));
        assertEquals(ResultReason.FEATURE_NOT_SUPPORTED, r.reasonEnum().orElseThrow(), curve);
        assertEquals("Unsupported EC curve", r.message(), curve);
      }

      // RSA under 2048 bits.
      KeyPair small = InMemoryReProvisionTest.rsaKey(1024);
      String smallId =
          kms.keys()
              .register(small.getPublic())
              .named("small")
              .usages(KeyUsage.VERIFY)
              .register()
              .id();
      Result r =
          kms.protocol().execute(certify(kms, smallId, Pkcs10.request(SUBJECT, small), issuerId));
      assertEquals(ResultReason.FEATURE_NOT_SUPPORTED, r.reasonEnum().orElseThrow());

      // P-256, P-384, P-521 and RSA-2048 are issued.
      for (KeyPair ok :
          List.of(
              p256,
              InMemoryReProvisionTest.ecKey("secp384r1"),
              InMemoryReProvisionTest.ecKey("secp521r1"),
              InMemoryReProvisionTest.rsaKey(2048))) {
        String id =
            ok == p256
                ? p256Id
                : kms.keys()
                    .register(ok.getPublic())
                    .named("ok/" + java.util.UUID.randomUUID())
                    .usages(KeyUsage.VERIFY)
                    .register()
                    .id();
        Result issued =
            kms.protocol().execute(certify(kms, id, Pkcs10.request(SUBJECT, ok), issuerId));
        assertTrue(issued.successful(), issued.toString());
      }
      assertEquals(List.of(), server.violations());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void certifyIsRefusedInUndoBatchesBeforeAnythingIsIssued(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    try (Kms kms = TlsIdentityTest.connect(server)) {
      TlsIssuer issuer = TlsIssueTest.register(kms, TlsIssueTest.Ca.ec("Issuing CA"));
      String issuerId = issuer.certificate().id();
      KeyPair key = InMemoryReProvisionTest.ecKey("secp256r1");
      String publicId =
          kms.keys()
              .register(key.getPublic())
              .named("undo")
              .usages(KeyUsage.VERIFY)
              .register()
              .id();
      List<String> before = server.ids();
      RequestOptions undo =
          RequestOptions.builder()
              .batchErrorContinuation(Enums.BatchErrorContinuation.UNDO)
              .build();
      Request certify = certify(kms, publicId, Pkcs10.request(SUBJECT, key), issuerId);
      // An undone certificate would still be valid: refused before it is issued, whether the rest
      // of the batch would succeed or a later item would fail.
      for (Request later :
          List.of(
              Requests.getAttributes().uniqueIdentifier(publicId).build(),
              Requests.get().uniqueIdentifier("no-such-object").build())) {
        Response r = kms.protocol().batch(List.of(certify, later), undo);
        Result first = r.results().get(0);
        assertEquals(
            ResultReason.FEATURE_NOT_SUPPORTED, first.reasonEnum().orElseThrow(), r.toString());
        assertEquals(
            "Certify, Re-certify and Re-Provision are not supported in Undo batches",
            first.message());
        assertEquals(before, server.ids(), "no certificate");
        assertTrue(
            kms.keys().handle(publicId).attributes().links().stream()
                .noneMatch(l -> l.kind() == LinkKind.CERTIFICATE),
            "no link to a certificate");
        assertTrue(
            kms.keys().handle(issuerId).attributes().links().stream()
                .noneMatch(l -> l.targetId().equals(publicId)),
            "nothing links the CA to the key");
      }
      // Without Undo the same request is issued.
      assertTrue(kms.protocol().execute(certify).successful());
      assertEquals(List.of(), server.violations());
    }
  }

  /** A Certify of the public key {@code publicId} with {@code csr}, issued by {@code issuerId}. */
  static Request certify(Kms kms, String publicId, byte[] csr, String issuerId) {
    boolean legacy = kms.protocolVersion().legacyAttributes();
    return Requests.certify()
        .uniqueIdentifier(publicId)
        .add(Ttlv.enumeration(Tag.CERTIFICATE_REQUEST_TYPE, Enums.CertificateRequestType.PKCS_10))
        .add(Ttlv.bytes(legacy ? Tag.CERTIFICATE_REQUEST : Tag.CERTIFICATE_REQUEST_VALUE, csr))
        .template(Attributes.link(Enums.LinkType.CERTIFICATE_LINK, issuerId))
        .build();
  }
}
