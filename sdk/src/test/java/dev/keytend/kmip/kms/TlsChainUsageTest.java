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

import static dev.keytend.kmip.kms.TestPki.CRL_SIGN;
import static dev.keytend.kmip.kms.TestPki.DIGITAL_SIGNATURE;
import static dev.keytend.kmip.kms.TestPki.KEY_AGREEMENT;
import static dev.keytend.kmip.kms.TestPki.KEY_CERT_SIGN;
import static dev.keytend.kmip.kms.TestPki.KEY_ENCIPHERMENT;
import static dev.keytend.kmip.kms.TlsIdentityTest.HOURLY;
import static dev.keytend.kmip.kms.TlsIdentityTest.SCHEDULER;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TestPki.Issued;
import dev.keytend.kmip.model.Enums.ResultReason;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.security.KeyPair;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Each certificate of a TLS identity's chain, and a certificate registered without usages, gets the
 * usages its own X.509 Key Usage extension grants: a KMIP 1.x server maps the extension to the
 * mask and may refuse a mask that claims more (KMIP 1.4 Table 96), so a
 * CA that has only keyCertSign and cRLSign is not registered with Verify.
 */
class TlsChainUsageTest {
  static final CustomAttribute TAG = CustomAttribute.client("tls");

  /** A server with unique names that refuses a 1.x name in use with Illegal Operation. */
  static InMemoryKmipServer server(KmipVersion version) {
    return InMemoryKmipServer.of(version)
        .uniqueNames(true)
        .legacyNonUniqueNameReason(ResultReason.ILLEGAL_OPERATION);
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aChainWithACaKeyUsageRegistersRenewsAndRekeys(KmipVersion version) throws Exception {
    InMemoryKmipServer server = server(version);
    Issued root = TestPki.ca("Root", KEY_CERT_SIGN, CRL_SIGN);
    Issued issuing = TestPki.intermediate("Issuing", root, KEY_CERT_SIGN, CRL_SIGN);
    KeyPair k1 = TestPki.ec(), k2 = TestPki.ec();
    try (Kms kms = TlsIdentityTest.connect(server)) {
      TlsIdentityHandle node =
          kms.tls()
              .register(
                  k1.getPrivate(),
                  TestPki.leaf("node1", k1, issuing, DIGITAL_SIGNATURE).certificate(),
                  issuing.certificate())
              .named("cassandra/node1")
              .custom(TAG, "identity")
              .register();
      List<KeyHandle> chain = node.chain();
      assertEquals(
          Set.of(KeyUsage.VERIFY), server.usages(chain.get(0).id()), "the leaf: digitalSignature");
      assertEquals(
          Set.of(KeyUsage.CERTIFICATE_SIGN, KeyUsage.CRL_SIGN),
          server.usages(chain.get(1).id()),
          "the CA");
      assertEquals(Set.of(KeyUsage.SIGN), server.usages(node.privateKey().id()));
      try (TlsIdentityFollower follower = kms.tls().follow("cassandra/node1", HOURLY, SCHEDULER)) {
        // Renew (the same key) and re-key, on 1.x through the name move that Illegal Operation
        // takes.
        node =
            node.renew(
                TestPki.leaf("node1", k1, issuing, DIGITAL_SIGNATURE).certificate(),
                issuing.certificate());
        follower.refresh();
        assertEquals(node.certificate().id(), follower.identity().orElseThrow().certificateId());
        node =
            node.rekey(
                k2.getPrivate(),
                TestPki.leaf("node1", k2, issuing, DIGITAL_SIGNATURE).certificate(),
                issuing.certificate());
        follower.refresh();
        assertEquals(node.certificate().id(), follower.identity().orElseThrow().certificateId());
        assertEquals(TlsIdentityFollower.Status.CURRENT, follower.status());
        assertEquals(Set.of(KeyUsage.VERIFY), server.usages(node.certificate().id()));
      }
      // An anchor registered without usages takes them from its certificate, and the follower
      // trusts it.
      KeyHandle anchor = kms.keys().register(root.certificate()).custom(TAG, "ca").register();
      assertEquals(
          Set.of(KeyUsage.CERTIFICATE_SIGN, KeyUsage.CRL_SIGN), server.usages(anchor.id()));
      try (TlsTrustFollower trust =
          kms.tls()
              .trustAnchors(
                  KeyQuery.all().custom(TAG, "ca"),
                  KeyQuery.all().custom(TAG, "identity"),
                  HOURLY,
                  SCHEDULER)) {
        assertTrue(
            trust.allows(
                node.chain().stream()
                    .map(TlsChainUsageTest::certificate)
                    .toArray(java.security.cert.X509Certificate[]::new)));
      }
      assertEquals(List.of(), server.violations());
    }
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void onKmip1AMaskTheKeyUsageDoesNotGrantIsRefused(KmipVersion version) throws Exception {
    InMemoryKmipServer server = server(version);
    Issued root = TestPki.ca("Root", KEY_CERT_SIGN, CRL_SIGN);
    try (Kms kms = TlsIdentityTest.connect(server)) {
      KeyRegistration verify = kms.keys().register(root.certificate()).usages(KeyUsage.VERIFY);
      if (version.compareTo(KmipVersion.V2_0) < 0) {
        KmsException refused =
            assertThrows(KmsException.class, verify::register, "Verify on a CA without that usage");
        assertEquals(KmsReason.INVALID_FIELD, refused.serverReason().orElseThrow());
      } else {
        assertEquals(
            Set.of(KeyUsage.VERIFY), server.usages(verify.register().id()), "2.x keeps any mask");
      }
    }
  }

  @Test
  void aRetryAfterAFailureUsesTheCallersUsagesNotTheDefaults() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Issued root = TestPki.ca("Root", KEY_CERT_SIGN, CRL_SIGN);
    try (Kms kms = TlsIdentityTest.connect(server)) {
      KeyRegistration r = kms.keys().register(root.certificate());
      server.failNext(
          dev.keytend.kmip.testing.ServerOperation.REGISTER,
          dev.keytend.kmip.testing.Fault.PERMISSION_DENIED);
      assertThrows(PermissionDeniedException.class, r::register);
      assertEquals(
          Set.of(KeyUsage.VERIFY), server.usages(r.usages(KeyUsage.VERIFY).register().id()));
    }
  }

  @Test
  void theUsagesFollowKeyUsageAndBasicConstraints() throws Exception {
    KeyPair ec = TestPki.ec();
    Issued plainCa = TestPki.ca("Plain CA");
    assertEquals(
        Set.of(KeyUsage.VERIFY, KeyUsage.CERTIFICATE_SIGN, KeyUsage.CRL_SIGN),
        KeyUsage.of(plainCa.certificate()),
        "no Key Usage: a CA may sign certificates and CRLs");
    assertEquals(
        Set.of(KeyUsage.VERIFY), KeyUsage.of(TestPki.leaf("plain", ec, plainCa).certificate()));
    assertEquals(
        Set.of(KeyUsage.CERTIFICATE_SIGN),
        KeyUsage.of(TestPki.ca("Signs only", KEY_CERT_SIGN).certificate()));
    assertEquals(
        Set.of(KeyUsage.WRAP_KEY),
        KeyUsage.of(TestPki.leaf("rsa-kex", ec, plainCa, KEY_ENCIPHERMENT).certificate()));
    assertEquals(
        Set.of(KeyUsage.VERIFY, KeyUsage.KEY_AGREEMENT),
        KeyUsage.of(
            TestPki.leaf("ecdh", ec, plainCa, DIGITAL_SIGNATURE, KEY_AGREEMENT).certificate()));
    assertEquals(
        Set.of(KeyUsage.VERIFY),
        KeyUsage.of(TestPki.leaf("commitment", ec, plainCa, 1).certificate()),
        "nothing it grants has a usage here: Verify");
    assertEquals(
        Set.of(KeyUsage.KEY_AGREEMENT),
        KeyUsage.of(TestPki.leaf("decipher", ec, plainCa, KEY_AGREEMENT, 8).certificate()),
        "decipherOnly, past the first byte, adds nothing");
  }

  private static java.security.cert.X509Certificate certificate(KeyHandle h) {
    return h.asCertificate();
  }
}
