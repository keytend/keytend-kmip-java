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
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.TlsListener;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The wire shape of the requests for client certificate renewal (Re-Provision) and KMS-issued TLS
 * identities (Certify), as the SDK sends them over TLS at each KMIP version that has the
 * operation. The requests are taken from the in-memory server as it decoded them off the wire, and
 * their tags, types and field order are checked against the specification's tables, so a change in
 * what the SDK encodes fails here without a live server.
 */
class CertificateOperationsWireTest {
  /**
   * Re-Provision with a PKCS#10 Certificate Request and keytend-kmip-server's validity extension,
   * then a Get of the ID Placeholder, in one message (KMIP 2.0 and 2.1 section 6.1.48, 3.0 draft).
   * The Get has no Unique Identifier on 2.x, and the ID Placeholder enumeration on 3.0.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V2_0", "V2_1", "V3_0"})
  void reProvisionAndItsGet(KmipVersion version, @TempDir Path dir) throws Exception {
    ClientCertificateRenewalTest.Pki pki = new ClientCertificateRenewalTest.Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    X509Certificate before = pki.client.certificate();
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.renewing(tls, CertificateRenewal.onDemand().validFor(Duration.ofDays(30)))
                    .maximumVersion(KmipVersion.V3_0)
                    .build())) {
      assertEquals(version, kms.version());
      RenewedCertificate renewed = kms.renewClientCertificate();
      Ttlv message = only(server, Operation.RE_PROVISION);

      // The header and two batch items, in that order.
      assertEquals(
          names(REQUEST_HEADER, BATCH_ITEM, BATCH_ITEM), names(message.children()), "message");
      Ttlv header = message.require(REQUEST_HEADER);
      Ttlv protocol = header.require(PROTOCOL_VERSION);
      assertEquals(
          version.protocolValue().major(),
          field(protocol, PROTOCOL_VERSION_MAJOR, Ttlv.Type.INTEGER).intValue());
      assertEquals(
          version.protocolValue().minor(),
          field(protocol, PROTOCOL_VERSION_MINOR, Ttlv.Type.INTEGER).intValue());
      assertTrue(header.child(AUTHENTICATION).isEmpty(), "no header credentials");
      header.child(BATCH_COUNT).ifPresent(c -> assertEquals(2, c.intValue()));
      List<Ttlv> items = message.children(BATCH_ITEM);

      // Batch item 1: Operation, Unique Batch Item ID (2.x), Request Payload, Message Extension.
      boolean v3 = version.atLeast(KmipVersion.V3_0);
      Ttlv reProvision = items.get(0);
      assertEquals(
          v3
              ? names(OPERATION, REQUEST_PAYLOAD, MESSAGE_EXTENSION)
              : names(OPERATION, UNIQUE_BATCH_ITEM_ID, REQUEST_PAYLOAD, MESSAGE_EXTENSION),
          names(reProvision.children()),
          "Re-Provision batch item");
      assertEquals(
          Operation.RE_PROVISION.code(),
          field(reProvision, OPERATION, Ttlv.Type.ENUMERATION).intValue());

      // Its payload: one Certificate Request, of type PKCS#10, for the new key and the subject of
      // the certificate it replaces.
      Ttlv payload = field(reProvision, REQUEST_PAYLOAD, Ttlv.Type.STRUCTURE);
      assertEquals(names(CERTIFICATE_REQUEST), names(payload.children()), "Re-Provision payload");
      Ttlv request = field(payload, CERTIFICATE_REQUEST, Ttlv.Type.STRUCTURE);
      assertEquals(
          names(CERTIFICATE_REQUEST_TYPE, CERTIFICATE_REQUEST_VALUE),
          names(request.children()),
          "Certificate Request");
      assertEquals(
          Enums.CertificateRequestType.PKCS_10.code(),
          field(request, CERTIFICATE_REQUEST_TYPE, Ttlv.Type.ENUMERATION).intValue());
      JcaPKCS10CertificationRequest csr =
          pkcs10(field(request, CERTIFICATE_REQUEST_VALUE, Ttlv.Type.BYTE_STRING).bytesValue());
      assertEquals(
          before.getSubjectX500Principal(), new X500Principal(csr.getSubject().getEncoded()));
      assertEquals(renewed.certificate().getPublicKey(), csr.getPublicKey());

      // The Message Extension: keytend-kmip-server's, Critical, with one Deactivation Date, the
      // notAfter asked for and issued.
      Ttlv extension = field(reProvision, MESSAGE_EXTENSION, Ttlv.Type.STRUCTURE);
      assertEquals(
          names(VENDOR_IDENTIFICATION, CRITICALITY_INDICATOR, VENDOR_EXTENSION),
          names(extension.children()),
          "Message Extension");
      assertEquals(
          "keytend_kmip_server",
          field(extension, VENDOR_IDENTIFICATION, Ttlv.Type.TEXT_STRING).textValue());
      assertTrue(field(extension, CRITICALITY_INDICATOR, Ttlv.Type.BOOLEAN).booleanValue());
      Ttlv vendor = field(extension, VENDOR_EXTENSION, Ttlv.Type.STRUCTURE);
      assertEquals(names(DEACTIVATION_DATE), names(vendor.children()), "Vendor Extension");
      assertEquals(
          renewed.certificate().getNotAfter().toInstant(),
          field(vendor, DEACTIVATION_DATE, Ttlv.Type.DATE_TIME).instantValue());

      // Batch item 2: the Get of the ID Placeholder, without a Message Extension.
      Ttlv get = items.get(1);
      assertEquals(
          v3
              ? names(OPERATION, REQUEST_PAYLOAD)
              : names(OPERATION, UNIQUE_BATCH_ITEM_ID, REQUEST_PAYLOAD),
          names(get.children()),
          "Get batch item");
      assertEquals(Operation.GET.code(), field(get, OPERATION, Ttlv.Type.ENUMERATION).intValue());
      if (!v3)
        assertFalse(
            Arrays.equals(
                field(reProvision, UNIQUE_BATCH_ITEM_ID, Ttlv.Type.BYTE_STRING).bytesValue(),
                field(get, UNIQUE_BATCH_ITEM_ID, Ttlv.Type.BYTE_STRING).bytesValue()),
            "distinct batch item IDs");
      Ttlv getPayload = field(get, REQUEST_PAYLOAD, Ttlv.Type.STRUCTURE);
      if (v3) {
        assertEquals(names(UNIQUE_IDENTIFIER), names(getPayload.children()), "3.0 Get payload");
        assertEquals(
            Enums.UniqueIdentifier.ID_PLACEHOLDER.code(),
            field(getPayload, UNIQUE_IDENTIFIER, Ttlv.Type.ENUMERATION).intValue());
      } else assertEquals(List.of(), getPayload.children(), "2.x Get payload: none");
      assertEquals(List.of(), server.violations());
    }
  }

  /**
   * Certify of the new public key with a PKCS#10 request, a Certificate link to the issuing CA and
   * a Deactivation Date: a Template-Attribute of Attribute structures on 1.x (1.4 section 4.7), an
   * Attributes structure from 2.0 (2.1 section 6.1.6), with a Link structure on 2.x and a
   * Certificate Link Reference on 3.0. No Activation Date is sent.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_0", "V2_1", "V3_0"})
  void certifyWithItsCertificateLinkAndDeactivationDate(KmipVersion version, @TempDir Path dir)
      throws Exception {
    ClientCertificateRenewalTest.Pki pki = new ClientCertificateRenewalTest.Pki(dir);
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    TlsIssueTest.Ca ca = TlsIssueTest.Ca.ec("Issuing CA");
    try (TlsListener tls = pki.listener(server).start();
        Kms kms =
            Kms.connect(
                pki.client(tls)
                    .clientIdentityPem(pki.chain, pki.key)
                    .minimumVersion(KmipVersion.V1_2)
                    .maximumVersion(KmipVersion.V3_0)
                    .build())) {
      assertEquals(version, kms.version());
      TlsIssuer issuer = TlsIssueTest.register(kms, ca);
      TlsIdentityHandle h =
          kms.tls()
              .issue("node1")
              .keyPair(KeyPairSpec.ec(Curve.P_256))
              .subject("CN=node1,O=cluster1")
              .dnsNames("node1.cluster1.internal")
              .validFor(Duration.ofDays(30))
              .issuedBy(issuer)
              .issue();
      X509Certificate issued = TlsIssueTest.certificate(kms, h.certificate());
      Ttlv message = only(server, Operation.CERTIFY);
      Ttlv item = null;
      for (Ttlv i : message.children(BATCH_ITEM))
        if (i.require(OPERATION).intValue() == Operation.CERTIFY.code()) item = i;
      assertNotNull(item);
      assertEquals(
          Operation.CERTIFY.code(), field(item, OPERATION, Ttlv.Type.ENUMERATION).intValue());
      Ttlv payload = field(item, REQUEST_PAYLOAD, Ttlv.Type.STRUCTURE);
      boolean legacy = !version.atLeast(KmipVersion.V2_0);
      Tag value = legacy ? CERTIFICATE_REQUEST : CERTIFICATE_REQUEST_VALUE;
      Tag attributes = legacy ? TEMPLATE_ATTRIBUTE : ATTRIBUTES;
      assertEquals(
          names(UNIQUE_IDENTIFIER, CERTIFICATE_REQUEST_TYPE, value, attributes),
          names(payload.children()),
          "Certify payload");

      // The public key certified, and the request for it.
      // An identifier is a Text String until 3.0, which has the Reference type for it.
      Ttlv.Type identifier =
          version.atLeast(KmipVersion.V3_0) ? Ttlv.Type.REFERENCE : Ttlv.Type.TEXT_STRING;
      String publicId = field(payload, UNIQUE_IDENTIFIER, identifier).textValue();
      assertEquals(List.of(publicId), server.links(h.certificate().id(), LinkKind.PUBLIC_KEY));
      assertEquals(
          Enums.CertificateRequestType.PKCS_10.code(),
          field(payload, CERTIFICATE_REQUEST_TYPE, Ttlv.Type.ENUMERATION).intValue());
      JcaPKCS10CertificationRequest csr =
          pkcs10(field(payload, value, Ttlv.Type.BYTE_STRING).bytesValue());
      assertEquals(issued.getPublicKey(), csr.getPublicKey());
      assertEquals(
          new X500Principal("CN=node1,O=cluster1"),
          new X500Principal(csr.getSubject().getEncoded()));

      // The attributes: a Certificate link to the CA certificate and a Deactivation Date, the
      // issued notAfter; no Activation Date.
      Ttlv sent = field(payload, attributes, Ttlv.Type.STRUCTURE);
      Ttlv link = null, deactivation;
      if (legacy) {
        for (Ttlv a : sent.children())
          assertEquals(ATTRIBUTE.wireName(), a.tagName(), "Template-Attribute holds Attributes");
        link = attribute(sent, "Link", Ttlv.Type.STRUCTURE);
        deactivation = attribute(sent, "Deactivation Date", Ttlv.Type.DATE_TIME);
        assertNull(attributeOrNull(sent, "Activation Date"));
      } else {
        assertTrue(sent.children(ATTRIBUTE).isEmpty(), "no Attribute wrappers from 2.0");
        if (version.atLeast(KmipVersion.V3_0)) {
          // 3.0 has a tag per link type, holding the linked object's Reference.
          assertTrue(sent.children(LINK).isEmpty(), "no Link structure on 3.0");
          assertEquals(
              issuer.certificate().id(),
              field(sent, CERTIFICATE_LINK, Ttlv.Type.REFERENCE).textValue());
        } else link = field(sent, LINK, Ttlv.Type.STRUCTURE);
        deactivation = field(sent, DEACTIVATION_DATE, Ttlv.Type.DATE_TIME);
        assertTrue(sent.child(ACTIVATION_DATE).isEmpty());
      }
      if (link != null) {
        assertEquals(names(LINK_TYPE, LINKED_OBJECT_IDENTIFIER), names(link.children()), "Link");
        assertEquals(
            Enums.LinkType.CERTIFICATE_LINK.code(),
            field(link, LINK_TYPE, Ttlv.Type.ENUMERATION).intValue());
        assertEquals(
            issuer.certificate().id(),
            field(link, LINKED_OBJECT_IDENTIFIER, Ttlv.Type.TEXT_STRING).textValue());
      }
      assertEquals(issued.getNotAfter().toInstant(), deactivation.instantValue());
      assertEquals(List.of(), server.violations());
    }
  }

  /** The one request message that has a batch item of {@code operation}. */
  static Ttlv only(InMemoryKmipServer server, Operation operation) {
    List<Ttlv> found = new ArrayList<>();
    for (Ttlv message : server.protocolRequests())
      for (Ttlv item : message.children(BATCH_ITEM))
        if (item.require(OPERATION).intValue() == operation.code()) {
          found.add(message);
          break;
        }
    assertEquals(1, found.size(), operation.wireName() + " messages: " + found);
    return found.get(0);
  }

  static List<String> names(Tag... tags) {
    return Arrays.stream(tags).map(Tag::wireName).toList();
  }

  static List<String> names(List<Ttlv> fields) {
    return fields.stream().map(Ttlv::tagName).toList();
  }

  /** The one {@code tag} field of {@code structure}, which must be of {@code type}. */
  static Ttlv field(Ttlv structure, Tag tag, Ttlv.Type type) {
    List<Ttlv> all = structure.children(tag);
    assertEquals(1, all.size(), tag.wireName() + " in " + structure.tagName());
    assertEquals(type, all.get(0).type(), tag.wireName());
    return all.get(0);
  }

  /** The Attribute Value of the 1.x Attribute named {@code name}, which must be of {@code type}. */
  static Ttlv attribute(Ttlv template, String name, Ttlv.Type type) {
    Ttlv value = attributeOrNull(template, name);
    assertNotNull(value, name);
    assertEquals(type, value.type(), name);
    return value;
  }

  static Ttlv attributeOrNull(Ttlv template, String name) {
    Ttlv found = null;
    for (Ttlv a : template.children(ATTRIBUTE)) {
      if (!name.equals(a.require(ATTRIBUTE_NAME).textValue())) continue;
      assertNull(found, "one " + name);
      List<String> fields = names(a.children());
      assertTrue(
          fields.equals(names(ATTRIBUTE_NAME, ATTRIBUTE_VALUE))
              || fields.equals(names(ATTRIBUTE_NAME, ATTRIBUTE_INDEX, ATTRIBUTE_VALUE)),
          name + ": " + fields);
      assertEquals(Ttlv.Type.TEXT_STRING, a.require(ATTRIBUTE_NAME).type());
      found = a.require(ATTRIBUTE_VALUE);
    }
    return found;
  }

  /** The PKCS#10 request {@code der}, whose self-signature must verify. */
  static JcaPKCS10CertificationRequest pkcs10(byte[] der) throws Exception {
    JcaPKCS10CertificationRequest csr = new JcaPKCS10CertificationRequest(der);
    assertTrue(
        csr.isSignatureValid(new JcaContentVerifierProviderBuilder().build(csr.getPublicKey())),
        "the request's self-signature verifies");
    assertArrayEquals(der, new PKCS10CertificationRequest(der).getEncoded(), "DER as sent");
    return csr;
  }
}
