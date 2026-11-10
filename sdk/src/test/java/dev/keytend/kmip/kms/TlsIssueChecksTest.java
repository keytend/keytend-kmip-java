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

import static dev.keytend.kmip.kms.TlsIssueTest.NAME;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.TestX509;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.jupiter.api.Test;

/**
 * The checks of an issued certificate beyond what was asked: the chain it is presented with
 * verifies, certificate by certificate, also when the server's own CA signs; and its key usages
 * let a node present it at both ends of a TLS connection. A Certify a test answers itself stands
 * for a server that issues such a certificate.
 */
class TlsIssueChecksTest {
  private static final String SERVER_AUTH = "1.3.6.1.5.5.7.3.1",
      CLIENT_AUTH = "1.3.6.1.5.5.7.3.2",
      EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4",
      ANY_PURPOSE = "2.5.29.37.0";

  /** A {@code Kms} whose Certify requests {@code certify} answers, the others the server. */
  static Kms connect(InMemoryKmipServer server, UnaryOperator<Ttlv> certify) {
    return Kms.connect(
        server
            .configure()
            .retryPolicy(RetryPolicy.none())
            .transport(
                e ->
                    r -> {
                      for (Ttlv item : r.children(Tag.BATCH_ITEM))
                        if (item.require(Tag.OPERATION).intValue() == Operation.CERTIFY.code())
                          return certify.apply(r);
                      return server.exchange(r);
                    })
            .build());
  }

  /**
   * A server with a CA of its own: it links each certificate it issues without an issuer named to
   * {@code caId}, and signs it with that CA's key.
   */
  static UnaryOperator<Ttlv> ownCa(InMemoryKmipServer server, String caId) {
    Ttlv link =
        Ttlv.structure(
            Tag.LINK,
            Ttlv.enumeration(Tag.LINK_TYPE, Enums.LinkType.CERTIFICATE_LINK),
            Ttlv.text(Tag.LINKED_OBJECT_IDENTIFIER, caId));
    return r -> {
      try {
        return server.exchange(linked(r).isPresent() ? r : withAttribute(r, link));
      } catch (java.io.IOException e) {
        throw new java.io.UncheckedIOException(e);
      }
    };
  }

  private static Ttlv withAttribute(Ttlv t, Ttlv extra) {
    if (t.type() != Ttlv.Type.STRUCTURE) return t;
    List<Ttlv> children = new ArrayList<>();
    for (Ttlv c : t.children()) children.add(withAttribute(c, extra));
    if (t.tag() == Tag.ATTRIBUTES.code()) children.add(extra);
    return Ttlv.structure(t.tag(), children);
  }

  /** The request's Certificate link, if it has one. */
  private static Optional<String> linked(Ttlv request) {
    return attributes(request).children(Tag.LINK).stream()
        .map(l -> l.require(Tag.LINKED_OBJECT_IDENTIFIER).textValue())
        .findFirst();
  }

  private static Ttlv payload(Ttlv request) {
    return request.require(Tag.BATCH_ITEM).require(Tag.REQUEST_PAYLOAD);
  }

  private static Ttlv attributes(Ttlv request) {
    return payload(request).require(Tag.ATTRIBUTES);
  }

  /**
   * A server that issues what {@code make} makes for the requested key, instead of the in-memory
   * server's Certify: the certificate is registered Pre-Active under the request's name, linked to
   * the public key and back, and to {@code issuerId} (null: the request's issuer), as Certify
   * leaves it.
   */
  static UnaryOperator<Ttlv> issues(
      InMemoryKmipServer server, Function<PublicKey, X509Certificate> make, String issuerId) {
    return r -> {
      try (Kms admin = TlsIdentityTest.connect(server)) {
        Ttlv p = payload(r);
        String publicId = p.require(Tag.UNIQUE_IDENTIFIER).textValue();
        PublicKey key =
            new JcaPKCS10CertificationRequest(p.require(Tag.CERTIFICATE_REQUEST_VALUE).bytesValue())
                .getPublicKey();
        String name = attributes(r).require(Tag.NAME).require(Tag.NAME_VALUE).textValue();
        KeyHandle leaf = admin.keys().register(make.apply(key)).named(name).registerPreActive();
        String issuer = issuerId != null ? issuerId : linked(r).orElseThrow();
        TlsRepeatTest.link(admin, leaf.id(), Enums.LinkType.PUBLIC_KEY_LINK, publicId);
        TlsRepeatTest.link(admin, leaf.id(), Enums.LinkType.CERTIFICATE_LINK, issuer);
        TlsRepeatTest.link(admin, publicId, Enums.LinkType.CERTIFICATE_LINK, leaf.id());
        assertEquals(KeyState.PRE_ACTIVE, server.state(leaf.id()).orElseThrow());
        return issued(r, leaf.id());
      } catch (Exception e) {
        throw new IllegalStateException(e);
      }
    };
  }

  /** The response to the Certify {@code request} that made the certificate {@code id}. */
  private static Ttlv issued(Ttlv request, String id) {
    Ttlv item = request.require(Tag.BATCH_ITEM);
    List<Ttlv> fields = new ArrayList<>();
    fields.add(Ttlv.enumeration(Tag.OPERATION, Operation.CERTIFY.code()));
    item.child(Tag.UNIQUE_BATCH_ITEM_ID).ifPresent(fields::add);
    fields.add(Ttlv.enumeration(Tag.RESULT_STATUS, 0));
    fields.add(Ttlv.structure(Tag.RESPONSE_PAYLOAD, Ttlv.text(Tag.UNIQUE_IDENTIFIER, id)));
    return Ttlv.structure(
        Tag.RESPONSE_MESSAGE,
        Ttlv.structure(
            Tag.RESPONSE_HEADER,
            request.require(Tag.REQUEST_HEADER).require(Tag.PROTOCOL_VERSION),
            Ttlv.dateTime(Tag.TIME_STAMP, Instant.now().truncatedTo(ChronoUnit.SECONDS)),
            Ttlv.integer(Tag.BATCH_COUNT, 1)),
        Ttlv.structure(Tag.BATCH_ITEM, fields));
  }

  static TlsIdentityIssuance request(Kms kms, KeyPairSpec spec) {
    return kms.tls()
        .issue(NAME)
        .keyPair(spec)
        .subject("CN=node1")
        .dnsNames("node1.cluster1.internal");
  }

  /** The objects the server holds now that it did not hold in {@code before}. */
  static List<String> made(InMemoryKmipServer server, Set<String> before) {
    List<String> out = new ArrayList<>(server.ids());
    out.removeAll(before);
    return out;
  }

  /** A refused issue: nothing of the identity, and the new key pair and leaf left over, listed. */
  static void leftOver(
      InMemoryKmipServer server, Kms kms, Set<String> before, KmsException refused) {
    List<String> left = made(server, before);
    assertEquals(3, left.size(), left.toString());
    for (String id : left) {
      assertTrue(refused.getMessage().contains(id), refused.getMessage());
      assertFalse(server.names(id).contains(NAME), id);
    }
    assertTrue(refused.getMessage().contains("left over"), refused.getMessage());
    assertTrue(kms.tls().identity(NAME).isEmpty());
  }

  /**
   * Where the server's own CA signs, the chain is what the leaf's links lead to; a chain that does
   * not verify above the leaf is refused at the issue, at a repeat after success, and at a
   * reissue that takes the issuer from the links.
   */
  @Test
  void aChainOfTheServersOwnCaThatDoesNotVerifyIsRefused() throws Exception {
    TestPki.Issued root = TestPki.ca("Root", TestPki.KEY_CERT_SIGN);
    TestPki.Issued ca = TestPki.intermediate("Server CA", root, TestPki.KEY_CERT_SIGN);
    TestPki.Issued stranger = TestPki.ca("Stranger", TestPki.KEY_CERT_SIGN);
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms setup = TlsIdentityTest.connect(server)) {
      TlsIssuer issuer =
          setup
              .tls()
              .registerIssuer(ca.key(), ca.certificate(), root.certificate())
              .named("server/ca")
              .register();
      String caId = issuer.certificate().id(), rootId = issuer.chain().get(1).id();
      String strangerId = setup.keys().register(stranger.certificate()).register().id();
      try (Kms kms = connect(server, ownCa(server, caId))) {
        // The links lead to a chain that verifies: the identity's chain.
        TlsIdentityHandle h = request(kms, KeyPairSpec.ec(Curve.P_256)).issue();
        assertEquals(List.of(h.certificate().id(), caId, rootId), TlsRepeatTest.chainIds(h));
        // The CA's link then leads to a certificate that did not issue it.
        setup.keys().handle(caId).removeLink("by hand", Enums.LinkType.CERTIFICATE_LINK, rootId);
        TlsRepeatTest.link(setup, caId, Enums.LinkType.CERTIFICATE_LINK, strangerId);
        Set<String> before = Set.copyOf(server.ids());
        // A repeat after success: nothing is changed.
        KeyMismatchException repeat =
            assertThrows(
                KeyMismatchException.class,
                () -> request(kms, KeyPairSpec.ec(Curve.P_256)).issue());
        assertTrue(repeat.getMessage().contains("its chain does not verify"), repeat.getMessage());
        assertTrue(
            repeat.getMessage().contains("certificate 1 of the chain (CN=Server CA)"),
            repeat.getMessage());
        assertTrue(repeat.getMessage().contains("nothing was changed"), repeat.getMessage());
        assertEquals(before, Set.copyOf(server.ids()));
        // A reissue that takes the issuer from the links: refused before its switch.
        KeyMismatchException reissue =
            assertThrows(KeyMismatchException.class, h::reissueWithNewKey);
        assertTrue(
            reissue.getMessage().contains("its chain does not verify"), reissue.getMessage());
        assertTrue(reissue.getMessage().contains("left over"), reissue.getMessage());
        assertEquals(3, made(server, before).size());
        assertEquals(
            h.certificate().id(), kms.tls().identity(NAME).orElseThrow().certificate().id());
        // A first issue under another name.
        Set<String> beforeOther = Set.copyOf(server.ids());
        KeyMismatchException first =
            assertThrows(
                KeyMismatchException.class,
                () -> kms.tls().issue("other/node").subject("CN=other").issue());
        assertTrue(first.getMessage().contains("certificate 1 of the chain"), first.getMessage());
        List<String> left = made(server, beforeOther);
        assertEquals(3, left.size(), left.toString());
        for (String id : left) assertTrue(first.getMessage().contains(id), first.getMessage());
        assertTrue(kms.tls().identity("other/node").isEmpty());
      }
    }
  }

  /**
   * A leaf that its server's CA certificate, as the links name it, did not sign: the same name as
   * that CA, another key.
   */
  @Test
  void aLeafTheLinkedCaDidNotSignIsRefused() throws Exception {
    TlsIssueTest.Ca ca = TlsIssueTest.Ca.ec("Server CA");
    TlsIssueTest.Ca impostor = TlsIssueTest.Ca.ec("Server CA");
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms setup = TlsIdentityTest.connect(server)) {
      String caId = setup.keys().register(ca.certificate).register().id();
      Set<String> before = Set.copyOf(server.ids());
      try (Kms kms =
          connect(
              server,
              issues(
                  server,
                  key ->
                      TestX509.certificate("node1", key)
                          .issuedBy(impostor.certificate, impostor.key.getPrivate())
                          .dns("node1.cluster1.internal")
                          .keyUsage(TestX509.DIGITAL_SIGNATURE)
                          .build(),
                  caId))) {
        KeyMismatchException e =
            assertThrows(
                KeyMismatchException.class,
                () -> request(kms, KeyPairSpec.ec(Curve.P_256)).issue());
        assertTrue(
            e.getMessage().contains("certificate 0 of the chain (CN=node1)"), e.getMessage());
        leftOver(server, kms, before, e);
      }
    }
  }

  /** Key usages that cannot do TLS at both ends are refused; the others are taken. */
  @Test
  void keyUsagesThatCannotDoTlsAreRefused() throws Exception {
    TlsIssueTest.Ca ca = TlsIssueTest.Ca.ec("Issuing CA");
    record Case(KeyPairSpec spec, int[] keyUsage, String[] purposes, String refused) {}
    List<Case> cases =
        List.of(
            // EC with keyAgreement alone (static ECDH): no handshake signature.
            new Case(
                KeyPairSpec.ec(Curve.P_256),
                new int[] {TestX509.KEY_AGREEMENT},
                null,
                "no digitalSignature"),
            // RSA with keyEncipherment alone: RSA key transport, a TLS 1.2 server only.
            new Case(
                KeyPairSpec.rsa(2048),
                new int[] {TestX509.KEY_ENCIPHERMENT},
                null,
                "no digitalSignature"),
            new Case(
                KeyPairSpec.ec(Curve.P_256),
                new int[] {TestX509.DIGITAL_SIGNATURE},
                new String[] {EMAIL_PROTECTION},
                "does not have both serverAuth and clientAuth"),
            new Case(
                KeyPairSpec.ec(Curve.P_256),
                new int[] {TestX509.DIGITAL_SIGNATURE},
                new String[] {SERVER_AUTH},
                "does not have both serverAuth and clientAuth"),
            new Case(
                KeyPairSpec.rsa(2048),
                new int[] {TestX509.DIGITAL_SIGNATURE},
                new String[] {CLIENT_AUTH},
                "does not have both serverAuth and clientAuth"),
            // Taken: digitalSignature (with keyEncipherment for RSA), both purposes or any, or
            // neither extension.
            new Case(
                KeyPairSpec.rsa(2048),
                new int[] {TestX509.DIGITAL_SIGNATURE, TestX509.KEY_ENCIPHERMENT},
                new String[] {SERVER_AUTH, CLIENT_AUTH},
                null),
            new Case(
                KeyPairSpec.ec(Curve.P_256),
                new int[] {TestX509.DIGITAL_SIGNATURE, TestX509.KEY_AGREEMENT},
                new String[] {ANY_PURPOSE},
                null),
            new Case(KeyPairSpec.ec(Curve.P_256), new int[0], null, null));
    for (Case c : cases) {
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      try (Kms setup = TlsIdentityTest.connect(server)) {
        TlsIssuer issuer = TlsIssueTest.register(setup, ca);
        Set<String> before = Set.copyOf(server.ids());
        Function<PublicKey, X509Certificate> make =
            key -> {
              TestX509.Builder b =
                  TestX509.certificate("node1", key)
                      .issuedBy(ca.certificate, ca.key.getPrivate())
                      .dns("node1.cluster1.internal")
                      .keyUsage(c.keyUsage());
              if (c.purposes() != null) b.extendedKeyUsage(c.purposes());
              return b.build();
            };
        try (Kms kms = connect(server, issues(server, make, null))) {
          TlsIdentityIssuance request = request(kms, c.spec()).issuedBy(issuer);
          String what = c.toString();
          if (c.refused() == null) {
            TlsIdentityHandle h = request.issue();
            assertEquals(KeyState.ACTIVE, server.state(h.certificate().id()).orElseThrow(), what);
            assertEquals(List.of(), server.violations(), what);
            continue;
          }
          KeyMismatchException e = assertThrows(KeyMismatchException.class, request::issue, what);
          assertTrue(e.getMessage().contains(c.refused()), e.getMessage());
          assertTrue(e.getMessage().contains("is not what was requested"), e.getMessage());
          leftOver(server, kms, before, e);
        }
      }
    }
  }
}
