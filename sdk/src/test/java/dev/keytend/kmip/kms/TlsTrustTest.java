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

import static dev.keytend.kmip.kms.TlsIdentityTest.HOURLY;
import static dev.keytend.kmip.kms.TlsIdentityTest.SCHEDULER;
import static dev.keytend.kmip.kms.TlsIdentityTest.connect;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/** Trust anchors and allowed peers from the KMS, read in batches and cached by identifier. */
class TlsTrustTest {
  static final CustomAttribute TAG = CustomAttribute.client("tls");

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void customTimestampsMatchAtKmipSecondPrecision(KmipVersion version) throws Exception {
    try (var server = InMemoryKmipServer.of(version);
        Kms kms = connect(server)) {
      Instant at = Instant.parse("2026-10-29T12:00:00.123456789Z");
      var ca = TestPki.ca("timestamp root");
      KeyHandle anchor =
          kms.keys().register(ca.certificate()).usages(KeyUsage.VERIFY).custom(TAG, at).register();
      kms.keys()
          .register(TestPki.ca("other time").certificate())
          .usages(KeyUsage.VERIFY)
          .custom(TAG, at.plusSeconds(1))
          .register();
      KeyQuery query = KeyQuery.all().custom(TAG, at);
      assertTrue(query.matches(anchor.attributes()));
      assertEquals(List.of(anchor.id()), List.copyOf(kms.tls().certificates(query).keySet()));
      try (TlsTrustFollower trust = kms.tls().trustAnchors(query, HOURLY, SCHEDULER)) {
        assertEquals(List.of(anchor.id()), List.copyOf(trust.anchors().keySet()));
        var peer = TestPki.leaf("node", TestPki.ec(), ca);
        assertDoesNotThrow(() -> trust.trustManager().checkClientTrusted(peer.chain(ca), "EC"));
      }
    }
  }

  /** The operations of each request message sent since {@code from}, in order. */
  static List<List<String>> messages(InMemoryKmipServer server, int from) {
    List<List<String>> out = new ArrayList<>();
    List<Ttlv> all = server.protocolRequests();
    for (Ttlv m : all.subList(from, all.size())) {
      List<String> ops = new ArrayList<>();
      for (Ttlv item : m.children(Tag.BATCH_ITEM)) {
        int code = item.require(Tag.OPERATION).intValue();
        for (Operation o : Operation.values()) if (o.code() == code) ops.add(o.name());
      }
      out.add(ops);
    }
    return out;
  }

  static List<KeyHandle> anchors(Kms kms, int n, String tag) throws Exception {
    List<KeyHandle> out = new ArrayList<>();
    for (int i = 0; i < n; i++)
      out.add(
          kms.keys()
              .register(TestPki.ca("CA " + tag + i).certificate())
              .usages(KeyUsage.VERIFY)
              .custom(TAG, tag)
              .register());
    return out;
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void oneLocateThenOneBatchedGetForTheNewCertificatesOnly(KmipVersion version) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    try (Kms kms = connect(server)) {
      List<KeyHandle> cas = anchors(kms, 5, "ca");
      anchors(kms, 2, "other");
      int from = server.protocolRequests().size();
      try (TlsTrustFollower trust =
          kms.tls().trustAnchors(KeyQuery.all().custom(TAG, "ca"), HOURLY, SCHEDULER)) {
        assertEquals(
            List.of(
                List.of("LOCATE"),
                List.of(
                    "GET_ATTRIBUTES",
                    "GET_ATTRIBUTES",
                    "GET_ATTRIBUTES",
                    "GET_ATTRIBUTES",
                    "GET_ATTRIBUTES"),
                List.of("GET", "GET", "GET", "GET", "GET")),
            messages(server, from));
        assertEquals(5, trust.anchors().size());
        assertEquals(5, trust.trustManager().getAcceptedIssuers().length);
        // Nothing new: one Locate and one batched Get Attributes, no Get.
        from = server.protocolRequests().size();
        assertFalse(trust.refresh());
        assertEquals(
            List.of(
                List.of("LOCATE"),
                List.of(
                    "GET_ATTRIBUTES",
                    "GET_ATTRIBUTES",
                    "GET_ATTRIBUTES",
                    "GET_ATTRIBUTES",
                    "GET_ATTRIBUTES")),
            messages(server, from));
        // One new: one Get. One revoked: not an anchor any more, and nothing read.
        anchors(kms, 1, "ca");
        cas.get(0).revoke(RevocationReason.caCompromise("compromised", Instant.now()));
        from = server.protocolRequests().size();
        assertTrue(trust.refresh());
        assertEquals(
            List.of(
                List.of("LOCATE"),
                List.of(
                    "GET_ATTRIBUTES",
                    "GET_ATTRIBUTES",
                    "GET_ATTRIBUTES",
                    "GET_ATTRIBUTES",
                    "GET_ATTRIBUTES"),
                List.of("GET")),
            messages(server, from));
        assertEquals(5, trust.anchors().size());
        assertFalse(trust.anchors().containsKey(cas.get(0).id()));
        // Deactivated: not an anchor either.
        cas.get(1).deactivate();
        assertTrue(trust.refresh());
        assertFalse(trust.anchors().containsKey(cas.get(1).id()));
      }
      // The one-shot read: one Locate, one batched Get.
      from = server.protocolRequests().size();
      Map<String, X509Certificate> all =
          kms.tls().certificates(KeyQuery.all().custom(TAG, "other"));
      assertEquals(2, all.size());
      assertEquals(
          List.of(
              List.of("LOCATE"),
              List.of("GET_ATTRIBUTES", "GET_ATTRIBUTES"),
              List.of("GET", "GET")),
          messages(server, from));
      assertEquals(List.of(), server.violations());
    }
  }

  @Test
  void aServerThatRefusesTheBatchIsAskedOnceForEach() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = connect(server)) {
      anchors(kms, 3, "ca");
      server.failNext(ServerOperation.GET, Fault.UNSUPPORTED);
      int from = server.protocolRequests().size();
      Map<String, X509Certificate> read = kms.tls().certificates(KeyQuery.all().custom(TAG, "ca"));
      assertEquals(3, read.size());
      assertEquals(
          List.of(
              List.of("LOCATE"),
              List.of("GET_ATTRIBUTES", "GET_ATTRIBUTES", "GET_ATTRIBUTES"),
              List.of("GET", "GET", "GET"),
              List.of("GET"),
              List.of("GET"),
              List.of("GET")),
          messages(server, from));
    }
  }

  /** {@code t} without the custom attributes of its Locate requests, as a server that ignores them sees it. */
  static Ttlv withoutCustomFilters(Ttlv t) {
    if (t.type() != Ttlv.Type.STRUCTURE) return t;
    List<Ttlv> kept = new ArrayList<>();
    for (Ttlv c : t.children()) {
      if (c.tag() == Tag.ATTRIBUTE.code()
          && (c.child(Tag.VENDOR_IDENTIFICATION).isPresent()
              || c.child(Tag.ATTRIBUTE_NAME)
                  .map(n -> n.textValue().startsWith("x-"))
                  .orElse(false))) continue;
      kept.add(withoutCustomFilters(c));
    }
    return Ttlv.structure(t.tag(), kept);
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aServerThatIgnoresCustomFiltersDoesNotWidenTheAnchorsOrThePeers(KmipVersion version)
      throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    dev.keytend.kmip.transport.KmipTransport ignoring =
        new dev.keytend.kmip.transport.KmipTransport() {
          @Override
          public Ttlv exchange(Ttlv request) throws java.io.IOException {
            return exchange(request, dev.keytend.kmip.transport.CallContext.NONE);
          }

          @Override
          public Ttlv exchange(Ttlv request, dev.keytend.kmip.transport.CallContext c)
              throws java.io.IOException {
            boolean locate =
                request.require(Tag.BATCH_ITEM).require(Tag.OPERATION).intValue()
                    == Operation.LOCATE.code();
            return server.exchange(locate ? withoutCustomFilters(request) : request, c);
          }
        };
    try (Kms kms = Kms.connect(server.configure().transport(e -> ignoring).build())) {
      List<KeyHandle> cas = anchors(kms, 2, "ca");
      anchors(kms, 3, "other");
      assertEquals(
          5,
          kms.keys().list(KeyQuery.all().custom(TAG, "ca")).size(),
          "the server ignores the filter");
      try (TlsTrustFollower trust =
          kms.tls()
              .trustAnchors(
                  KeyQuery.all().custom(TAG, "ca"),
                  KeyQuery.all().custom(TAG, "none"),
                  HOURLY,
                  SCHEDULER)) {
        assertEquals(
            cas.stream().map(KeyHandle::id).toList(), List.copyOf(trust.anchors().keySet()));
        assertEquals(Map.of(), trust.allowedPeers().orElseThrow());
      }
      assertEquals(2, kms.tls().certificates(KeyQuery.all().custom(TAG, "ca")).size());
    }
  }

  @Test
  void onlyActiveCertificatesAreAnchorsWhateverTheQuerySaysAndAnOutageKeepsThem() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = connect(server)) {
      List<KeyHandle> cas = anchors(kms, 2, "ca");
      cas.get(0).revoke(RevocationReason.caCompromise("compromised", Instant.now()));
      KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).custom(TAG, "ca").create();
      try (TlsTrustFollower trust =
          kms.tls()
              .trustAnchors(
                  KeyQuery.all()
                      .custom(TAG, "ca")
                      .state(KeyState.COMPROMISED)
                      .kind(ObjectKind.SYMMETRIC_KEY),
                  HOURLY,
                  SCHEDULER)) {
        assertEquals(List.of(cas.get(1).id()), List.copyOf(trust.anchors().keySet()));
        assertTrue(trust.allowedPeers().isEmpty());
        List<String> told = new ArrayList<>();
        trust.onChange(() -> told.add("changed"));
        server.unreachable(true);
        assertFalse(trust.refresh());
        assertInstanceOf(TransientException.class, trust.failure().orElseThrow());
        assertEquals(1, trust.anchors().size());
        server.unreachable(false);
        anchors(kms, 1, "ca");
        assertTrue(trust.refresh());
        assertTrue(trust.failure().isEmpty());
        assertEquals(2, trust.anchors().size());
        assertEquals(List.of("changed"), told);
        trust.close();
        assertThrows(
            java.security.cert.CertificateException.class,
            () ->
                trust
                    .trustManager()
                    .checkClientTrusted(
                        new X509Certificate[] {trust.anchors().values().iterator().next()}, "EC"));
      }
      assertNotNull(key);
    }
  }
}
