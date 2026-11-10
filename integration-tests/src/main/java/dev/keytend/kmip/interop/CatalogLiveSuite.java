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

import static dev.keytend.kmip.interop.Catalog.*;
import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.*;
import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.net.ssl.*;

/** Shared, capability-observing scenarios. Optional peer failures never become positive passes. */
public final class CatalogLiveSuite {
  /**
   * The SDK's message for a response header without its mandatory TimeStamp, as the retry fault
   * proxy meets it from {@code Messages.response} directly.
   */
  static final String MISSING_TIMESTAMP = "ResponseHeader missing TimeStamp";

  final CatalogFixture f;
  final List<Map<String, Object>> records = new ArrayList<>();

  public CatalogLiveSuite(CatalogFixture fixture) {
    f = fixture;
  }

  public Map<String, Object> run() throws Exception {
    for (Catalog.Case c : CASES) {
      Instant start = Instant.now();
      long nanos = System.nanoTime();
      f.evidence.clear();
      f.lastResponseShape = List.of();
      f.lastRequestShape = List.of();
      Outcome state = Outcome.PASS;
      String reason = "Assertions completed";
      // A rejection is not proof of a server fault. The raw outcome stays as measured;
      // the attribution says who may be at fault and that nobody has reviewed it yet.
      String attribution = null;
      try {
        if (!c.servers().contains("all_applicable") && !c.servers().contains(f.server))
          outside("Vendor-specific scenario for another product");
        if (Set.of("codec_harness", "controlled_peer").contains(c.layer()))
          outside("Executed once in CatalogPeerIT, not credited to a live server");
        execute(c.id());
      } catch (Classification e) {
        state = e.outcome;
        reason = e.getMessage();
      } catch (KmipException e) {
        state =
            (e.result().reason() != null
                    && Set.of(5, 8, 15, 16, 17, 31, 62, 63).contains(e.result().reason()))
                ? Outcome.UNSUPPORTED_SERVER
                : Outcome.FAIL_SERVER;
        reason =
            "Peer returned operation="
                + e.result().operation()
                + " status="
                + e.result().status()
                + " reason="
                + e.result().reason();
        f.evidence.put("result_status", e.result().status());
        f.evidence.put("result_reason", e.result().reason());
        // Invalid Message, Missing Data, Invalid Field, Permission Denied and the like often mean
        // the request or fixture was wrong, not the server.
        attribution = failureAttribution(e.result().reason());
        if (e.result().message() != null)
          f.evidence.put(
              "peer_message_sha256",
              digest(e.result().message().getBytes(java.nio.charset.StandardCharsets.UTF_8)));
      } catch (ProtocolException e) {
        state = Outcome.FAIL_SERVER;
        reason = "Rejected peer response: " + e.getMessage();
        attribution =
            "unreviewed: the SDK rejected the response; an SDK correlation rule or a server"
                + " defect";
        // The rejected reply can still carry the server's Result Message (PyKMIP answers a 2.0
        // request it cannot parse with a 1.0 header).
        String peerMessage = rejectedResultMessage(e.response());
        if (peerMessage != null)
          f.evidence.put(
              "peer_message_sha256",
              digest(peerMessage.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
      } catch (AssertionError e) {
        state = Outcome.FAIL_CLIENT;
        reason = e.getMessage();
      } catch (IOException e) {
        state = Outcome.BLOCKED_ENV;
        reason = "Transport/reference fixture: " + e.getClass().getSimpleName();
        if (e.getMessage() != null && e.getMessage().equals(MISSING_TIMESTAMP)) {
          state = Outcome.FAIL_SERVER;
          reason = "Rejected peer response: " + e.getMessage();
          f.evidence.put("backend_protocol_rejection", true);
        } else if (e.getCause() instanceof ProtocolException cause) {
          state = Outcome.FAIL_SERVER;
          reason = "Rejected peer response: " + cause.getMessage();
          f.evidence.put("backend_protocol_rejection", true);
        }
      } catch (Exception e) {
        state = Outcome.FAIL_SERVER;
        reason = "Scenario could not consume peer result: " + e.getClass().getSimpleName();
        attribution = "unreviewed: scenario could not consume the result; fixture suspected";
        // A fixture request the SDK refuses to build never reached the server, so it is a
        // client or fixture failure, never a server observation.
        if (builtLocally(e)) {
          state = Outcome.FAIL_CLIENT;
          reason =
              "Fixture request could not be built: "
                  + e.getClass().getSimpleName()
                  + ": "
                  + e.getMessage();
          attribution = "client or fixture: the request was rejected locally and never sent";
          f.evidence.put("local_request_construction", true);
        }
        if ((e instanceof IllegalArgumentException || e instanceof IllegalStateException)
            && e.getMessage() != null
            && e.getMessage().matches("[A-Za-z][A-Za-z0-9]* missing [A-Za-z][A-Za-z0-9]*"))
          f.evidence.put("schema_violation", e.getMessage());
        if (e instanceof ExecutionException && e.getCause() instanceof ProtocolException cause) {
          reason = "Rejected peer response: " + cause.getMessage();
          f.evidence.put("async_protocol_rejection", true);
        }
        f.evidence.put(
            "exception_origin",
            Arrays.stream(e.getStackTrace()).limit(4).map(StackTraceElement::toString).toList());
      }
      Map<String, Object> r = new LinkedHashMap<>(f.provenance());
      r.put("test_id", c.id());
      r.put(
          "actual_layer",
          c.layer().equals("database_integration")
              ? "database_integration"
              : c.layer().equals("fault_proxy_and_live_server")
                  ? "fault_proxy_and_live_server"
                  : Set.of("OBS-01", "OBS-04", "OBS-05", "ENV-01", "VER-08").contains(c.id())
                      ? "harness_inspection"
                      : "live_server");
      r.put("planned_layer", c.layer());
      f.evidence.put("last_response_shape", f.lastResponseShape);
      f.evidence.put("last_request_shape", f.lastRequestShape);
      r.put("case_parameters", new LinkedHashMap<>(f.evidence));
      r.put("priority", c.priority());
      r.put("started_at", start.toString());
      r.put("duration_ms", (System.nanoTime() - nanos) / 1_000_000);
      r.put("outcome", state.name());
      r.put("reason", reason);
      r.put("attribution", attribution(state, attribution));
      r.put("review_status", reviewStatus(state));
      r.put(
          "issue_id",
          state == Outcome.FAIL_SERVER
              ? "CATALOG-" + f.server.toUpperCase(Locale.ROOT) + "-" + c.id()
              : null);
      r.put("evidence_refs", List.of("catalog.json#" + c.id()));
      records.add(r);
    }
    List<String> required =
        List.of(
            "DISC-02", "KEY-01", "KEY-02", "KEY-03", "LIFE-01", "LIFE-02", "LIFE-03", "LIFE-05");
    boolean qualifies =
        records.stream()
            .filter(r -> required.contains(r.get("test_id")))
            .allMatch(r -> r.get("outcome").equals("PASS"));
    Map<String, Object> report = new LinkedHashMap<>(f.provenance());
    report.put("catalog_schema", "1.0");
    boolean complete =
        records.stream()
            .filter(
                r -> r.get("priority").equals("P0") && !r.get("outcome").equals("NOT_APPLICABLE"))
            .allMatch(r -> r.get("outcome").equals("PASS"));
    report.put(
        "qualification",
        Map.of(
            "candidate_profiles",
            List.of("READ_AES", "MANAGE_AES"),
            "qualified",
            complete,
            "smoke_workflows_passed",
            qualifies,
            "smoke_required_cases",
            required,
            "rule",
            "Unsupported required capabilities and blocked P0 cases do not qualify; controlled"
                + " evidence is separate"));
    report.put(
        "client_assertions",
        Map.of(
            "no_client_failures_observed",
                records.stream().noneMatch(r -> r.get("outcome").equals("FAIL_CLIENT")),
            "unconfirmed_peer_observations",
                records.stream().filter(r -> r.get("outcome").equals("FAIL_SERVER")).count(),
            "scope",
                "no_client_failures_observed covers client-side assertions only. It does not show"
                    + " that the SDK is free of defects: FAIL_SERVER records are unreviewed and"
                    + " can be client, fixture or correlation faults (see each record's"
                    + " attribution)."));
    report.put("records", records);
    report.put("documented_capabilities", "Pinned upstream handlers; see server-inventory.json");
    report.put("discovered_capabilities", new LinkedHashMap<>(f.snapshot));
    report.put(
        "demonstrated_cases",
        records.stream()
            .filter(r -> r.get("outcome").equals("PASS"))
            .map(r -> r.get("test_id"))
            .toList());
    Map<String, List<Object>> byLayer = new LinkedHashMap<>();
    for (var r : records)
      if (r.get("outcome").equals("PASS"))
        byLayer
            .computeIfAbsent(r.get("actual_layer").toString(), ignored -> new ArrayList<>())
            .add(r.get("test_id"));
    report.put("demonstrated_cases_by_layer", byLayer);
    return report;
  }

  void execute(String id) throws Exception {
    if (id.equals("VER-09")
        && f.version != ProtocolVersion.V2_0
        && f.version != ProtocolVersion.V2_1)
      outside("This case specifically qualifies 2.0 and 2.1 independently");
    switch (id) {
      case "ENV-01" -> {
        if (!f.image.matches("sha256:[0-9a-f]{64}") || f.commit.equals("uncommitted"))
          blocked("This endpoint has no recorded image digest or client revision");
        require(f.configurationHash.length() == 64, "Configuration hash required");
      }
      case "ENV-02", "TLS-01" -> {
        f.handshake("client");
        f.provision();
        aes(f.knownUid, 256);
      }
      case "ENV-03" -> {
        f.provision();
        var r = f.reference("get", f.knownUid);
        peer(r.get("sha256").equals(f.knownSha), "Independent material mismatch");
      }
      case "ENV-04", "DISC-01" -> {
        var r =
            call(
                Requests.query()
                    .add(
                        enumeration(QUERY_FUNCTION, Enums.QueryFunction.QUERY_OPERATIONS),
                        enumeration(QUERY_FUNCTION, Enums.QueryFunction.QUERY_OBJECTS))
                    .build());
        f.snapshot.put(
            "operations_and_objects",
            r.requirePayload().children().stream()
                .map(
                    n ->
                        n.tagName()
                            + ":"
                            + (n.type() == Ttlv.Type.ENUMERATION ? n.intValue() : n.type()))
                .toList());
        f.evidence.put("capabilities_snapshot", new LinkedHashMap<>(f.snapshot));
      }
      case "ENV-05" -> {
        String key = create(128);
        peer(f.owned.contains(key), "Object not registered");
        retire(key);
        f.owned.remove(key);
        peer(!f.owned.contains(key), "Cleanup registry incorrect");
      }
      case "ENV-06", "KEY-04" -> {
        f.provision();
        String before = digest(aes(f.knownUid, 256).getEncoded());
        String generated = null, generatedDigest = null;
        if (id.equals("KEY-04") && !f.server.equals("krypton")) {
          generated = create(256);
          generatedDigest = digest(aes(generated, 256).getEncoded());
        }
        f.evidence.put("clock_offset_ms", f.clockOffsetMillis);
        if (f.clockOffsetMillis != null && Math.abs(f.clockOffsetMillis) > 60000)
          blocked("Server clock is outside the fixture's 60-second tolerance");
        if (f.restart == null) blocked("Persistent server restart hook not configured");
        f.restart.run();
        peer(
            digest(aes(f.knownUid, 256).getEncoded()).equals(before),
            "Restart changed persistent key");
        if (generated != null) {
          peer(
              digest(aes(generated, 256).getEncoded()).equals(generatedDigest),
              "Restart changed server-generated key");
          f.evidence.put("key_origins", List.of("independently registered", "server generated"));
        } else f.evidence.put("key_origins", List.of("pre-provisioned native fixture"));
      }
      case "TLS-05" -> {
        denyHandshake(null);
        denyHandshake("untrusted-client");
      }
      case "TLS-06" -> {
        f.handshake("client");
        denyHandshake("wrong-eku");
      }
      case "TLS-07", "TLS-11", "TLS-13" -> CatalogTls.execute(id, f);
      case "TLS-08" -> {
        List<String> accepted = new ArrayList<>();
        for (String p : List.of("TLSv1.2", "TLSv1.3"))
          try {
            f.handshake("client", p);
            accepted.add(p);
          } catch (IOException ignored) {
          }
        peer(!accepted.isEmpty(), "No permitted TLS protocol");
        denyProtocol("TLSv1.1");
        f.evidence.put("negotiated_protocols", accepted);
      }
      case "TLS-09" -> {
        try {
          Tls.context(
              f.certs.resolve("client.p12"), "wrong".toCharArray(), f.certs.resolve("ca.pem"));
          throw new AssertionError("Wrong PKCS12 password accepted");
        } catch (GeneralSecurityException | IOException expected) {
        }
        f.provision();
        KeyStore identity = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(f.certs.resolve("client.p12"))) {
          identity.load(in, "changeit".toCharArray());
        }
        String alias = Collections.list(identity.aliases()).get(0);
        CatalogTls.get(
            f,
            Tls.context(
                f.certs.resolve("client.p12"),
                "changeit".toCharArray(),
                f.certs.resolve("ca.pem"),
                alias));
        try {
          Tls.context(
              f.certs.resolve("client.p12"),
              "changeit".toCharArray(),
              f.certs.resolve("ca.pem"),
              f.namespace + "-absent-alias");
          throw new AssertionError("Absent private-key alias accepted");
        } catch (KeyStoreException expected) {
        }
        CatalogTls.get(f, CatalogTls.jksContext(f));
        f.evidence.put(
            "formats",
            "PKCS12 with explicit alias and PEM CA; application-created JKS key/trust stores"
                + " supplied through SSLContext; wrong password and absent alias rejected");
      }
      case "TLS-10", "AUTH-05" -> {
        try (var a = f.identity("client");
            var b = f.identity("client-b")) {
          f.provision();
          a.get(f.knownUid);
          Result r = b.execute(Requests.get().uniqueIdentifier(f.knownUid).build());
          f.evidence.put("other_identity_status", r.status());
        }
        f.evidence.put(
            "session_model",
            "fresh socket per exchange; no shared connection pool or credential cache");
      }
      case "TLS-12" -> {
        f.provision();
        try (var c =
            new KmipClient(
                new TlsTransport(
                    "localhost",
                    f.port,
                    Tls.context(
                        f.certs.resolve("client.p12"),
                        "changeit".toCharArray(),
                        f.certs.resolve("ca.pem"))),
                f.version)) {
          peer(
              c.get(f.knownUid).uniqueIdentifier().equals(f.knownUid),
              "Alternate trusted endpoint UID");
        }
        f.evidence.put(
            "address_variants",
            List.of(f.host, f.host.equals("localhost") ? "127.0.0.1" : "localhost"));
        f.evidence.put(
            "unconfigured_address_variants",
            "Mutable DNS and published IPv6 container ports are not configured");
      }
      case "VER-01", "VER-03", "VER-07", "VER-09" -> {
        f.provision();
        peer(aes(f.knownUid, 256).getEncoded().length == 32, "Forced version workflow");
        f.evidence.put("forced_version", f.version.toString());
      }
      case "VER-02" -> {
        var supported = f.client.discoverVersions();
        try (var negotiated = f.identity("client")) {
          var selected = negotiated.negotiate();
          peer(
              selected.version().code() <= f.version.code()
                  && supported.contains(selected.version()),
              "Negotiated outside permitted intersection");
          f.evidence.put("selected", selected.version().toString());
        }
      }
      case "VER-04", "VER-05", "VER-06" -> {
        f.evidence.put("controlled_counterpart", "CatalogPeerIT");
        f.provision();
        aes(f.knownUid, 256);
      }
      case "VER-08" -> {
        Operation op =
            f.version.atLeast(ProtocolVersion.V2_0) ? Operation.CREATE_GROUP : Operation.LOGIN;
        if (f.version == ProtocolVersion.V3_0) outside("No operation newer than pinned 3.0 draft");
        long before = f.attempts;
        try {
          call(Request.operation(op).build());
          throw new AssertionError("Version-incompatible operation reached peer");
        } catch (IllegalArgumentException expected) {
        }
        require(f.attempts == before, "Incompatible operation made network request");
      }
      case "VER-10" -> {
        f.provision();
        try (var a = f.identity("client");
            var b = f.identity("client-b")) {
          a.get(f.knownUid);
          b.execute(
              Requests.query()
                  .add(enumeration(QUERY_FUNCTION, Enums.QueryFunction.QUERY_OPERATIONS))
                  .build());
        }
        f.evidence.put(
            "cache", "No capability cache in SDK; per-instance version remains " + f.version);
      }
      case "DISC-02" -> {
        f.provision();
        call(Requests.getAttributes().uniqueIdentifier(f.knownUid).build());
        call(
            Requests.getAttributes()
                .uniqueIdentifier(f.knownUid)
                .add(text(ATTRIBUTE_NAME, "Cryptographic Length"))
                .build());
      }
      case "DISC-03" -> {
        String key = create(256);
        call(
            Requests.addAttribute()
                .uniqueIdentifier(key)
                .attribute(Attributes.name(f.namespace + "-second"))
                .build());
        var r = call(Requests.getAttributes().uniqueIdentifier(key).build());
        peer(r.requirePayload().children().size() > 1, "Attribute multiplicity lost");
      }
      case "DISC-04" -> {
        peer(locate(f.namespace + "-absent").isEmpty(), "Absent name returned a key");
        String key = createNamed(256, f.namespace + "-one");
        var hits = locate(f.namespace + "-one");
        peer(hits.size() == 1 && hits.contains(key), "Exact name resolution");
        if (!OBJECT_GROUP.definedIn(f.version))
          outside(objectGroupAbsent("Exact-name checks passed"));
        String group = f.namespace + "-multi";
        register(known(16), Attributes.textAttribute("Object Group", group));
        register(known(32), Attributes.textAttribute("Object Group", group));
        var r =
            call(
                Requests.locate()
                    .attribute(Attributes.textAttribute("Object Group", group))
                    .build());
        peer(
            r.requirePayload().children(UNIQUE_IDENTIFIER).size() == 2,
            "Ambiguous group did not preserve both matches");
      }
      case "DISC-05" -> {
        String key = createNamed(256, f.namespace + "-filter");
        var r =
            call(
                Requests.locate()
                    .attribute(Attributes.name(f.namespace + "-filter"))
                    .attribute(Attributes.algorithm(Enums.CryptographicAlgorithm.AES))
                    .build());
        peer(
            r.requirePayload().children(UNIQUE_IDENTIFIER).stream()
                .anyMatch(n -> n.textValue().equals(key)),
            "Filter dropped intended key");
      }
      case "DISC-06" -> pagination();
      case "DISC-07" -> opaqueIdentifiers();
      case "KEY-01" -> {
        f.provision();
        byte[] bytes = aes(f.knownUid, 256).getEncoded();
        peer(digest(bytes).equals(f.knownSha), "Known independent material differs");
        if (!f.server.equals("krypton")) {
          Cipher c = Cipher.getInstance("AES/ECB/NoPadding");
          c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(bytes, "AES"));
          peer(
              HexFormat.of()
                  .formatHex(c.doFinal(HexFormat.of().parseHex("00112233445566778899aabbccddeeff")))
                  .equals("8ea2b7ca516745bfeafc49904b496089"),
              "AES256 known-answer mismatch");
        }
        f.evidence.put(
            "provisioning",
            f.server.equals("krypton")
                ? "native Go manager/vault fixture"
                : "independent Python mTLS client");
      }
      case "DISC-08" -> {
        f.provision();
        aes(f.knownUid, 256);
        f.evidence.put("negative_counterpart", "KEY-06 / CatalogPeerIT");
      }
      case "KEY-02" -> {
        aes(create(128), 128);
        aes(create(256), 256);
      }
      case "KEY-03" -> {
        byte[] b = known(32);
        String uid = register(b);
        peer(Arrays.equals(aes(uid, 256).getEncoded(), b), "Register/Get changed bytes");
        peer(f.reference("get", uid).get("sha256").equals(digest(b)), "Independent Get differs");
      }
      case "KEY-05" -> exportPolicy();
      case "KEY-07", "KEY-08", "AUTH-03" -> wrap(id);
      case "KEY-10" -> {
        if (!f.version.atLeast(ProtocolVersion.V1_4)) outside("Export introduced in KMIP 1.4");
        String key = create(256);
        Ttlv a = f.client.get(key).requirePayload(),
            b = call(Requests.export().uniqueIdentifier(key).build()).requirePayload();
        peer(
            Arrays.equals(
                Keys.aesKey(a, key, 256).getEncoded(), Keys.aesKey(b, key, 256).getEncoded()),
            "Get/Export material mismatch");
      }
      case "KEY-11" -> {
        String key = create(256);
        for (Enums.KeyFormatType format :
            List.of(Enums.KeyFormatType.RAW, Enums.KeyFormatType.TRANSPARENT_SYMMETRIC_KEY)) {
          Ttlv p =
              call(Requests.get()
                      .uniqueIdentifier(key)
                      .add(enumeration(KEY_FORMAT_TYPE, format))
                      .build())
                  .requirePayload();
          Keys.aesKey(p, key, 256);
        }
      }
      case "ASYM-01", "ASYM-02", "ASYM-08" -> rsaFormats(id);
      case "ASYM-03", "CRYPTO-05" -> ec(id);
      case "ASYM-04", "ASYM-05", "ASYM-07" -> certificates(id);
      case "ASYM-06", "ASYM-09" -> CatalogDatabase.execute(id, f);
      case "LIFE-01" -> {
        String uid = create(128);
        f.client.activate(uid);
        peer(state(uid) == 2, "Activation state not Active");
      }
      case "LIFE-02" -> {
        String uid = create(128);
        f.client.activate(uid);
        f.client.revoke(uid, Enums.RevocationReasonCode.CESSATION_OF_OPERATION, "catalog");
        peer(state(uid) == 3 || state(uid) == 4, "Revocation state unchanged");
      }
      case "LIFE-03" -> {
        String uid = create(128);
        retire(uid);
        Result r = f.client.execute(Requests.get().uniqueIdentifier(uid).build());
        if (r.successful()) {
          var value =
              r.requirePayload()
                  .child(SYMMETRIC_KEY)
                  .flatMap(n -> n.child(KEY_BLOCK))
                  .flatMap(n -> n.child(KEY_VALUE));
          peer(
              value.isEmpty()
                  || (value.get().type() == Ttlv.Type.STRUCTURE
                      && value.get().children().isEmpty()),
              "Destroyed key returned usable material");
        }
      }
      case "LIFE-04" -> {
        String uid = create(128);
        f.client.activate(uid);
        Result repeated = f.client.execute(Requests.activate().uniqueIdentifier(uid).build());
        peer(state(uid) == 2, "Repeated activate corrupted state");
        f.evidence.put("repeated_status", repeated.status());
      }
      case "LIFE-05" -> rotation();
      case "AUTH-01", "SV-PY-01" -> permissions(id);
      case "AUTH-02" -> listingPermissions();
      case "LIFE-06" -> {
        if (!f.readOnlyRole)
          blocked(
              "Global read-only role not configured; an object Get grant alone does not deny"
                  + " creation");
        permissions(id);
      }
      case "LIFE-07", "LIFE-08", "SV-KR-02" -> isolation();
      case "LIFE-09" -> {
        if (!f.version.atLeast(ProtocolVersion.V1_2))
          outside("Remote encryption introduced in KMIP 1.2");
        String uid = register(known(32), Attributes.usage(Enums.CryptographicUsageMask.DECRYPT));
        f.client.activate(uid);
        Result denied =
            f.client.execute(
                Requests.encrypt()
                    .uniqueIdentifier(uid)
                    .cryptographicParameters(
                        enumeration(BLOCK_CIPHER_MODE, Enums.BlockCipherMode.CBC),
                        enumeration(PADDING_METHOD, Enums.PaddingMethod.PKCS5))
                    .data(known(16))
                    .add(bytes(IV_COUNTER_NONCE, known(16)))
                    .build());
        peer(!denied.successful(), "Disallowed encryption succeeded");
      }
      case "AUTH-04" -> {
        exportPolicy();
        f.evidence.put("fallback", "No operation fallback/retry in SDK");
      }
      case "CRYPTO-01" -> symmetric(false);
      case "CRYPTO-02" -> symmetric(true);
      case "CRYPTO-03", "CRYPTO-04" -> rsaCrypto(id);
      case "CRYPTO-06" -> CatalogObjects.mac(this);
      case "CRYPTO-07" -> {
        if (!f.version.atLeast(ProtocolVersion.V1_2)) outside("Remote crypto introduced in 1.2");
        String uid = create(128);
        f.client.activate(uid);
        Result r =
            f.client.execute(
                Requests.encrypt()
                    .uniqueIdentifier(uid)
                    .cryptographicParameters(enumeration(BLOCK_CIPHER_MODE, 0x7ffffffe))
                    .data(known(16))
                    .build());
        peer(!r.successful(), "Unknown cipher mode silently substituted");
      }
      case "CRYPTO-08" -> streaming();
      case "BATCH-01" -> {
        f.provision();
        var r =
            f.client.batch(
                List.of(
                    Requests.get().uniqueIdentifier(f.knownUid).build(),
                    Requests.getAttributes().uniqueIdentifier(f.knownUid).build()));
        peer(r.results().size() == 2, "Missing batch results");
        r.results().forEach(Result::requireSuccess);
      }
      case "BATCH-02" -> {
        try {
          ordered();
        } catch (KmipException rejection) {
          if (rejection.result().operation() != null || rejection.result().payload().isPresent())
            throw rejection;
          throw new Classification(
              Outcome.UNSUPPORTED_SERVER,
              "Peer rejected the optional ordered batch as a whole; rejection preserved without"
                  + " fallback");
        }
      }
      case "BATCH-04", "BATCH-05", "BATCH-06" -> batchErrors(id);
      case "BATCH-07" -> {
        Result r =
            f.client.execute(Requests.get().uniqueIdentifier(f.namespace + "missing").build());
        peer(!r.successful() && r.reason() != null, "Missing typed error");
      }
      case "BATCH-08" -> {
        f.provision();
        RequestOptions options =
            f.version.legacyAttributes()
                ? RequestOptions.DEFAULT.asynchronous(false)
                : RequestOptions.DEFAULT.asynchronous(Enums.AsynchronousIndicator.PROHIBITED);
        var r =
            f.client.batch(List.of(Requests.get().uniqueIdentifier(f.knownUid).build()), options);
        peer(!r.results().get(0).pending(), "Async-prohibited request returned Pending");
        r.results().get(0).requireSuccess();
      }
      case "BATCH-09" -> {
        long attempts = f.attempts;
        try {
          ordered();
          outside(
              "Server accepted ordered processing; unsupported-option rejection is tested in"
                  + " CatalogPeerIT");
        } catch (KmipException rejected) {
          if (rejected.result().operation() != null || rejected.result().payload().isPresent())
            throw rejected;
          require(
              f.attempts == attempts + 1,
              "Ordering rejection triggered an automatic fallback/retry");
          f.evidence.put("preserved_rejection_status", rejected.result().status());
          f.evidence.put("preserved_rejection_reason", rejected.result().reason());
          f.evidence.put("network_attempts", f.attempts - attempts);
        }
      }
      case "RETRY-01",
          "RETRY-02",
          "RETRY-03",
          "RETRY-04",
          "RETRY-05",
          "RETRY-06",
          "RETRY-07",
          "RETRY-08",
          "RETRY-09",
          "RETRY-10" ->
          CatalogFaults.execute(id, f);
      case "DB-01",
          "DB-02",
          "DB-03",
          "DB-04",
          "DB-05",
          "DB-06",
          "DB-07",
          "DB-08",
          "DB-09",
          "DB-10",
          "DB-11",
          "DB-12" ->
          CatalogDatabase.execute(id, f);
      case "JAVA-01" -> {
        require(Set.of(17, 21, 25).contains(Runtime.version().feature()), "Unsupported JDK");
        f.provision();
        aes(f.knownUid, 256);
      }
      case "JAVA-02" -> {
        f.provision();
        aes(f.knownUid, 256);
        outside(
            "This tuple is binary mTLS; HTTPS encodings have separate controlled-peer execution"
                + " records");
      }
      case "JAVA-03" -> concurrent();
      case "JAVA-04" -> {
        isolation();
        f.evidence.put("namespace_cache", "No key cache or global UID map is shipped");
      }
      case "JAVA-05" -> performance();
      case "JAVA-06" -> soak();
      case "JAVA-07" -> previousRelease();
      case "JAVA-08" -> {
        try (var c = f.identity("client")) {
          f.provision();
          c.get(f.knownUid);
          c.close();
          c.close();
          try {
            c.get(f.knownUid);
            throw new AssertionError("Closed client delivered key");
          } catch (IOException expected) {
          }
        }
      }
      case "OBS-01", "OBS-02", "OBS-03", "OBS-04", "OBS-05", "OBS-06" -> observe(id);
      case "SV-PY-02" -> {
        f.provision();
        List<String> outcomes = new ArrayList<>();
        for (Request r :
            List.of(
                Requests.reKey().uniqueIdentifier(f.knownUid).build(),
                Requests.export().uniqueIdentifier(f.knownUid).build(),
                Requests.addAttribute()
                    .uniqueIdentifier(f.knownUid)
                    .attribute(Attributes.name(f.namespace))
                    .build()))
          try {
            if (!f.version.atLeast(r.operation().since())) {
              outcomes.add(r.operation() + ":NOT_APPLICABLE_VERSION");
              continue;
            }
            outcomes.add(r.operation() + ":" + f.client.execute(r).status());
          } catch (ProtocolException e) {
            throw e;
          }
        f.evidence.put("handler_probe", outcomes);
        aes(f.knownUid, 256);
      }
      case "SV-KR-01" -> {
        f.provision();
        aes(f.knownUid, 256);
        blocked(
            "Restricted native handler fixture has one provisioned version; full root"
                + " administrative rotation is not configured");
      }
      default -> throw new AssertionError("No live implementation registered for " + id);
    }
  }

  Result call(Request r) throws Exception {
    return f.client.call(r);
  }

  static byte[] known(int n) {
    byte[] b = new byte[n];
    for (int i = 0; i < n; i++) b[i] = (byte) i;
    return b;
  }

  static void peer(boolean yes, String reason) throws Classification {
    if (!yes) throw new Classification(Outcome.FAIL_SERVER, reason);
  }

  SecretKey aes(String uid, int bits) throws Exception {
    return Keys.aesKey(f.client.get(uid).requirePayload(), uid, bits);
  }

  String create(int bits) throws Exception {
    return createNamed(bits, f.namespace + "-" + UUID.randomUUID());
  }

  String createNamed(int bits, String name) throws Exception {
    String uid =
        call(Requests.create()
                .add(enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY))
                .template(
                    Attributes.algorithm(Enums.CryptographicAlgorithm.AES),
                    Attributes.length(bits),
                    Attributes.usage(
                        Enums.CryptographicUsageMask.ENCRYPT, Enums.CryptographicUsageMask.DECRYPT),
                    Attributes.name(name))
                .build())
            .uniqueIdentifier();
    f.owned.add(uid);
    return uid;
  }

  /**
   * Who may be at fault for a record. The raw outcome is kept as measured; a FAIL_SERVER
   * record is never attributed to the server without review.
   */
  static String attribution(Outcome state, String detail) {
    return switch (state) {
      case PASS -> "none";
      case FAIL_CLIENT -> detail != null ? detail : "client assertion";
      case FAIL_SERVER ->
          detail != null
              ? detail
              : "unreviewed: classified by the harness, fault owner not established";
      default -> "not a fault";
    };
  }

  /** SDK classes that build or validate requests before anything is sent. */
  private static final Set<String> REQUEST_BUILDERS =
      Set.of(
          "dev.keytend.kmip.client.Requests",
          "dev.keytend.kmip.client.Request",
          "dev.keytend.kmip.client.RequestOptions",
          "dev.keytend.kmip.client.VersionedPayloads",
          "dev.keytend.kmip.client.CertificateRegistration",
          "dev.keytend.kmip.client.ImportRequest",
          "dev.keytend.kmip.client.KeyWrapping",
          "dev.keytend.kmip.client.CryptoParameters",
          "dev.keytend.kmip.client.CryptoRequests",
          "dev.keytend.kmip.client.KeyPairRequest",
          "dev.keytend.kmip.client.LocateRequest",
          "dev.keytend.kmip.client.SplitKeyRequests",
          "dev.keytend.kmip.model.VersionValidator",
          "dev.keytend.kmip.model.Attributes",
          "dev.keytend.kmip.model.ModernAttributes",
          "dev.keytend.kmip.model.ManagedObjects",
          "dev.keytend.kmip.model.UsageMask",
          "dev.keytend.kmip.model.Operation",
          "dev.keytend.kmip.model.Structures",
          "dev.keytend.kmip.model.KeyMaterials",
          "dev.keytend.kmip.model.Credentials");

  /**
   * Whether {@code e} was thrown while the SDK built or version-checked a request, so the request
   * never reached the peer. Decided by the innermost SDK frame: a request builder or
   * validator (including {@code Messages.request}) means yes; response decoding or key conversion
   * means no. {@code Ttlv} itself serves both directions and is skipped.
   */
  static boolean builtLocally(Throwable e) {
    if (!(e instanceof IllegalArgumentException
        || e instanceof IllegalStateException
        || e instanceof NullPointerException)) return false;
    for (StackTraceElement frame : e.getStackTrace()) {
      String type = frame.getClassName().replaceFirst("\\$.*", "");
      if (!type.startsWith("dev.keytend.kmip.") || type.equals("dev.keytend.kmip.model.Ttlv"))
        continue;
      if (type.equals("dev.keytend.kmip.client.Messages"))
        return frame.getMethodName().equals("request");
      return REQUEST_BUILDERS.contains(type);
    }
    return false;
  }

  static String reviewStatus(Outcome state) {
    return state == Outcome.FAIL_SERVER ? "unreviewed" : "n/a";
  }

  /**
   * Invalid Message, Missing Data, Invalid Field, Permission Denied and Encoding Option Error often
   * mean the request or the fixture was wrong, not the server.
   */
  static String failureAttribution(Integer reason) {
    return reason != null && Set.of(4, 6, 7, 12, 18).contains(reason)
        ? "unreviewed: peer rejected the request as invalid; client or fixture suspected"
        : "unreviewed: peer returned a failure result";
  }

  /**
   * The Result Message of a reply the SDK rejected, when the reply has exactly one batch item and
   * that item failed with a text message; otherwise null. The record keeps its SHA-256.
   */
  static String rejectedResultMessage(Ttlv response) {
    if (response == null || response.type() != Ttlv.Type.STRUCTURE) return null;
    List<Ttlv> items = response.children(BATCH_ITEM);
    if (items.size() != 1) return null;
    Ttlv item = items.get(0);
    var status = item.child(RESULT_STATUS);
    var message = item.child(RESULT_MESSAGE);
    if (status.isEmpty()
        || status.get().type() != Ttlv.Type.ENUMERATION
        || status.get().intValue() != 1
        || message.isEmpty()
        || message.get().type() != Ttlv.Type.TEXT_STRING) return null;
    return message.get().textValue();
  }

  String register(byte[] b, Ttlv... attrs) throws Exception {
    List<Ttlv> a =
        new ArrayList<>(
            List.of(
                Attributes.algorithm(Enums.CryptographicAlgorithm.AES),
                Attributes.length(b.length * 8),
                Attributes.usage(
                    Enums.CryptographicUsageMask.ENCRYPT, Enums.CryptographicUsageMask.DECRYPT)));
    if (Arrays.stream(attrs)
        .anyMatch(
            n ->
                n.child(ATTRIBUTE_NAME)
                    .map(v -> v.textValue().equals("Cryptographic Usage Mask"))
                    .orElse(false)))
      a.removeIf(n -> n.require(ATTRIBUTE_NAME).textValue().equals("Cryptographic Usage Mask"));
    a.addAll(List.of(attrs));
    String uid =
        f.client.register(
            ManagedObjects.rawSymmetricKey(b, Enums.CryptographicAlgorithm.AES),
            a.toArray(Ttlv[]::new));
    f.owned.add(uid);
    return uid;
  }

  void retire(String uid) throws Exception {
    try {
      f.client.revoke(uid, Enums.RevocationReasonCode.CESSATION_OF_OPERATION, "catalog");
    } catch (KmipException ignored) {
    }
    f.client.destroy(uid);
    f.owned.remove(uid);
  }

  int state(String uid) throws Exception {
    Ttlv p =
        call(Requests.getAttributes()
                .uniqueIdentifier(uid)
                .add(text(ATTRIBUTE_NAME, "State"))
                .build())
            .requirePayload();
    if (!f.version.legacyAttributes()) return p.require(ATTRIBUTES).require(STATE).intValue();
    return p.children(ATTRIBUTE).stream()
        .filter(n -> n.require(ATTRIBUTE_NAME).textValue().equals("State"))
        .findFirst()
        .orElseThrow()
        .require(ATTRIBUTE_VALUE)
        .intValue();
  }

  List<String> locate(String name) throws Exception {
    return call(Requests.locate().attribute(Attributes.name(name)).build())
        .requirePayload()
        .children(UNIQUE_IDENTIFIER)
        .stream()
        .map(Ttlv::textValue)
        .toList();
  }

  void opaqueIdentifiers() throws Exception {
    f.provision();
    aes(f.knownUid, 256);
    if (f.server.equals("krypton")) {
      f.evidence.put(
          "identifier_shape",
          "tenantID:keyID:keyVersion, opaque to Java; native fixture has fixed versioned"
              + " identifiers");
      return;
    }
    if (!f.version.atLeast(ProtocolVersion.V1_4))
      outside(
          "Get of server-generated IDs succeeded; explicit caller-chosen UID import requires 1.4");
    String uid = f.namespace + ":雪:" + "x".repeat(256);
    // Import restores an object with complete attributes, not a Register with a chosen ID (KMIP
    // 1.4 §4.41): export a known key, then import that export, in the version's own shape (1.4
    // repeated Attribute fields, 2.x Attributes), under the opaque identifier.
    String source = register(known(32));
    Ttlv exported = call(Requests.export().uniqueIdentifier(source).build()).requirePayload();
    Result imported = call(ImportRequest.restoreAs(exported, uid, false));
    String actual = imported.uniqueIdentifier();
    f.owned.add(actual);
    peer(actual.equals(uid), "Imported Unicode UID was normalized or remapped");
    peer(Arrays.equals(aes(uid, 256).getEncoded(), known(32)), "Opaque UID retrieved another key");
    f.evidence.put("uid_utf8_bytes", uid.getBytes(java.nio.charset.StandardCharsets.UTF_8).length);
  }

  void pagination() throws Exception {
    if (!f.version.atLeast(ProtocolVersion.V1_3)) outside("OffsetItems introduced in 1.3");
    if (!OBJECT_GROUP.definedIn(f.version)) outside(objectGroupAbsent("Pagination not run"));
    String group = f.namespace + "-page";
    Set<String> want = new HashSet<>();
    for (int i = 0; i < 5; i++)
      want.add(register(known(32), Attributes.textAttribute("Object Group", group)));
    Set<String> got = new HashSet<>();
    for (int offset = 0; offset < 8; offset += 2) {
      var p =
          call(Requests.locate()
                  .attribute(Attributes.textAttribute("Object Group", group))
                  .add(integer(MAXIMUM_ITEMS, 2), integer(OFFSET_ITEMS, offset))
                  .build())
              .requirePayload()
              .children(UNIQUE_IDENTIFIER);
      if (p.isEmpty()) break;
      for (Ttlv uid : p) peer(got.add(uid.textValue()), "Duplicate pagination item");
    }
    peer(got.equals(want), "Incomplete paginated Locate");
  }

  /**
   * The grouping cases select their objects by the Object Group attribute, which the KMIP 3.0
   * draft removed (groups are Group objects reached through GroupLink). Sending it anyway would be
   * a non-conformant request, which the SDK now refuses to build.
   */
  String objectGroupAbsent(String done) {
    return done
        + "; the Object Group attribute these fixtures group by is not defined in KMIP "
        + f.version
        + " (Group objects and GroupLink replace it)";
  }

  void denyHandshake(String identity) throws Exception {
    try {
      f.handshake(identity);
      throw new Classification(
          Outcome.FAIL_SERVER, "Listener accepted invalid client identity " + identity);
    } catch (IOException | GeneralSecurityException expected) {
    }
  }

  void denyProtocol(String protocol) throws Exception {
    try {
      f.handshake("client", protocol);
      throw new Classification(Outcome.FAIL_SERVER, "Prohibited TLS protocol accepted");
    } catch (IOException | IllegalArgumentException expected) {
    }
  }

  void exportPolicy() throws Exception {
    if (!f.version.atLeast(ProtocolVersion.V1_4))
      outside("Sensitive/Extractable introduced in KMIP 1.4");
    String allowed =
        register(known(32), Attributes.attribute("Extractable", bool(ATTRIBUTE_VALUE, true)));
    String denied =
        register(known(32), Attributes.attribute("Extractable", bool(ATTRIBUTE_VALUE, false)));
    aes(allowed, 256);
    Result r = f.client.execute(Requests.get().uniqueIdentifier(denied).build());
    peer(!r.successful(), "Non-extractable key returned plaintext");
    if (f.version.atLeast(ProtocolVersion.V1_4)) {
      Result exported = f.client.execute(Requests.export().uniqueIdentifier(denied).build());
      peer(!exported.successful(), "Export bypassed extractability");
    }
  }

  void rotation() throws Exception {
    String first = create(256), second = create(256);
    byte[] plain = known(32), iv = known(16);
    Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
    c.init(Cipher.ENCRYPT_MODE, aes(first, 256), new IvParameterSpec(iv));
    byte[] enc = c.doFinal(plain);
    c.init(Cipher.DECRYPT_MODE, aes(first, 256), new IvParameterSpec(iv));
    peer(Arrays.equals(c.doFinal(enc), plain), "Historical key no longer decrypts");
    peer(
        !Arrays.equals(aes(first, 256).getEncoded(), aes(second, 256).getEncoded()),
        "Rotation remapped key material");
  }

  void isolation() throws Exception {
    f.provision();
    try (var a = f.identity("client");
        var b = f.identity("client-b")) {
      a.get(f.knownUid);
      Result foreign = b.execute(Requests.get().uniqueIdentifier(f.knownUid).build());
      peer(!foreign.successful(), "Foreign principal retrieved owner key");
      a.get(f.knownUid);
      if (!f.server.equals("krypton")) {
        Result metadata = b.execute(Requests.getAttributes().uniqueIdentifier(f.knownUid).build());
        peer(!metadata.successful(), "Foreign metadata exposed");
      }
    }
  }

  void permissions(String id) throws Exception {
    if (f.grant == null || f.revokeGrant == null)
      blocked("Explicit grant/revoke management adapter not configured for this target");
    f.provision();
    try (var b = f.identity("client-b")) {
      peer(
          !b.execute(Requests.get().uniqueIdentifier(f.knownUid).build()).successful(),
          "Initial access was already granted");
      f.grant.run();
      try {
        Keys.aesKey(b.get(f.knownUid).requirePayload(), f.knownUid, 256);
        if (id.equals("LIFE-06")) {
          peer(
              !b.execute(
                      Requests.createSymmetricKey(
                          Enums.CryptographicAlgorithm.AES,
                          128,
                          Enums.CryptographicUsageMask.ENCRYPT,
                          Enums.CryptographicUsageMask.DECRYPT))
                  .successful(),
              "Read-only role created key");
          peer(
              !b.execute(
                      Requests.addAttribute()
                          .uniqueIdentifier(f.knownUid)
                          .attribute(Attributes.name(f.namespace + "-denied-write"))
                          .build())
                  .successful(),
              "Read-only role modified key");
          peer(
              !b.execute(Requests.destroy().uniqueIdentifier(f.knownUid).build()).successful(),
              "Read-only role destroyed key");
          peer(
              digest(Keys.aesKey(b.get(f.knownUid).requirePayload(), f.knownUid, 256).getEncoded())
                  .equals(f.knownSha),
              "Denied writes changed allowed key");
          f.evidence.put("denied_writes", List.of("Create", "AddAttribute", "Destroy"));
          f.evidence.put(
              "role_policy",
              "Native privileged_users=[client]; client-b has only an exact-object Get grant");
        }
      } finally {
        f.revokeGrant.run();
      }
      peer(
          !b.execute(Requests.get().uniqueIdentifier(f.knownUid).build()).successful(),
          "Revoked grant retained on fresh socket");
    }
  }

  void listingPermissions() throws Exception {
    if (f.grant == null || f.revokeGrant == null || f.listOnlyGrant == null)
      blocked("Exclusive list/get policies are not configured on this target");
    f.provision();
    try (var b = f.identity("client-b")) {
      Request locate =
          Requests.locate()
              .attribute(Attributes.textAttribute("Unique Identifier", f.knownUid))
              .build();
      try {
        f.grant.run();
        b.get(f.knownUid);
        Result hidden = b.execute(locate);
        peer(
            !hidden.successful() || hidden.requirePayload().children(UNIQUE_IDENTIFIER).isEmpty(),
            "Get-only object leaked into restricted listing");
        f.listOnlyGrant.run();
        Result visible = b.call(locate);
        peer(
            visible.requirePayload().children(UNIQUE_IDENTIFIER).stream()
                .anyMatch(n -> n.textValue().equals(f.knownUid)),
            "List-only policy did not expose permitted metadata");
        peer(
            !b.execute(Requests.get().uniqueIdentifier(f.knownUid).build()).successful(),
            "Listing permission granted retrieval");
      } finally {
        f.revokeGrant.run();
      }
    }
  }

  void symmetric(boolean gcm) throws Exception {
    if (!f.version.atLeast(ProtocolVersion.V1_2)) outside("Remote crypto introduced in 1.2");
    if (gcm && !f.version.atLeast(ProtocolVersion.V1_4))
      outside("AEAD additional-data/tag fields require KMIP 1.4");
    String uid = create(256);
    f.client.activate(uid);
    SecretKey key = aes(uid, 256);
    byte[] data = known(31), iv = known(gcm ? 12 : 16), aad = known(9);
    var params =
        gcm
            ? List.of(
                enumeration(CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.AES),
                enumeration(BLOCK_CIPHER_MODE, Enums.BlockCipherMode.GCM),
                integer(IV_LENGTH, 96),
                integer(TAG_LENGTH, 16))
            : List.of(
                enumeration(CRYPTOGRAPHIC_ALGORITHM, Enums.CryptographicAlgorithm.AES),
                enumeration(BLOCK_CIPHER_MODE, Enums.BlockCipherMode.CBC),
                enumeration(PADDING_METHOD, Enums.PaddingMethod.PKCS5));
    Request.Builder enc =
        Requests.encrypt()
            .uniqueIdentifier(uid)
            .cryptographicParameters(params.toArray(Ttlv[]::new))
            .data(data)
            .add(bytes(IV_COUNTER_NONCE, iv));
    if (gcm) enc.add(bytes(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA, aad));
    var p = call(enc.build()).requirePayload();
    byte[] ct = p.require(DATA).bytesValue();
    f.evidence.put("ciphertext_bytes", ct.length);
    if (gcm)
      peer(
          p.child(AUTHENTICATED_ENCRYPTION_TAG).isPresent(),
          "AES-GCM reply missing separate authentication tag");
    else peer(ct.length % 16 == 0, "AES-CBC ciphertext length is not a multiple of 16");
    Cipher local = Cipher.getInstance(gcm ? "AES/GCM/NoPadding" : "AES/CBC/PKCS5Padding");
    local.init(
        Cipher.DECRYPT_MODE, key, gcm ? new GCMParameterSpec(128, iv) : new IvParameterSpec(iv));
    if (gcm) local.updateAAD(aad);
    byte[] whole = gcm ? concat(ct, p.require(AUTHENTICATED_ENCRYPTION_TAG).bytesValue()) : ct;
    peer(Arrays.equals(local.doFinal(whole), data), "Independent AES decrypt mismatch");
    Request.Builder dec =
        Requests.decrypt()
            .uniqueIdentifier(uid)
            .cryptographicParameters(params.toArray(Ttlv[]::new))
            .data(ct)
            .add(bytes(IV_COUNTER_NONCE, iv));
    if (gcm)
      dec.add(
          bytes(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA, aad),
          p.require(AUTHENTICATED_ENCRYPTION_TAG));
    peer(
        Arrays.equals(call(dec.build()).requirePayload().require(DATA).bytesValue(), data),
        "Server AES roundtrip mismatch");
    if (gcm)
      for (int change = 0; change < 3; change++) {
        byte[] badCt = ct.clone(),
            badAad = aad.clone(),
            badTag = p.require(AUTHENTICATED_ENCRYPTION_TAG).bytesValue();
        if (change == 0) badCt[0] ^= 1;
        else if (change == 1) badAad[0] ^= 1;
        else badTag[0] ^= 1;
        Result r =
            f.client.execute(
                Requests.decrypt()
                    .uniqueIdentifier(uid)
                    .cryptographicParameters(params.toArray(Ttlv[]::new))
                    .data(badCt)
                    .add(
                        bytes(IV_COUNTER_NONCE, iv),
                        bytes(AUTHENTICATED_ENCRYPTION_ADDITIONAL_DATA, badAad),
                        bytes(AUTHENTICATED_ENCRYPTION_TAG, badTag))
                    .build());
        peer(!r.successful(), "Tampered AEAD input returned plaintext");
      }
  }

  static byte[] concat(byte[] a, byte[] b) {
    byte[] r = Arrays.copyOf(a, a.length + b.length);
    System.arraycopy(b, 0, r, a.length, b.length);
    return r;
  }

  void ordered() throws Exception {
    Request create =
        Requests.createSymmetricKey(
            Enums.CryptographicAlgorithm.AES,
            128,
            Enums.CryptographicUsageMask.ENCRYPT,
            Enums.CryptographicUsageMask.DECRYPT);
    // An item without a Unique Identifier uses the ID Placeholder in KMIP 1.x and 2.x; KMIP 3.0
    // requires the field and names the placeholder with its enumeration (3.0 §6.1, §11.60).
    Request
        activate =
            f.version == ProtocolVersion.V3_0
                ? Requests.activate().add(placeholder()).build()
                : Requests.activate().build(),
        get =
            f.version == ProtocolVersion.V3_0
                ? Requests.get().add(placeholder()).build()
                : Requests.get().build();
    var r =
        f.client.batch(
            List.of(create, activate, get),
            RequestOptions.DEFAULT.batching(true, Enums.BatchErrorContinuation.STOP));
    for (Result result : r.results()) result.requireSuccess();
    String uid = r.results().get(0).uniqueIdentifier();
    f.owned.add(uid);
    peer(
        r.results().get(2).uniqueIdentifier().equals(uid),
        "Ordered placeholder resolved another key");
  }

  static Ttlv placeholder() {
    return enumeration(UNIQUE_IDENTIFIER, Enums.UniqueIdentifier.ID_PLACEHOLDER);
  }

  void batchErrors(String id) throws Exception {
    String beforeName = f.namespace + "-" + id + "-before-error",
        lastName = f.namespace + "-" + id + "-after-error";
    var option =
        id.equals("BATCH-04")
            ? Enums.BatchErrorContinuation.STOP
            : id.equals("BATCH-05")
                ? Enums.BatchErrorContinuation.CONTINUE
                : Enums.BatchErrorContinuation.UNDO;
    Request first =
        Requests.create()
            .add(enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY))
            .template(
                Attributes.algorithm(Enums.CryptographicAlgorithm.AES),
                Attributes.length(128),
                Attributes.usage(
                    Enums.CryptographicUsageMask.ENCRYPT, Enums.CryptographicUsageMask.DECRYPT),
                Attributes.name(beforeName))
            .build();
    Request last =
        Requests.create()
            .add(enumeration(OBJECT_TYPE, Enums.ObjectType.SYMMETRIC_KEY))
            .template(
                Attributes.algorithm(Enums.CryptographicAlgorithm.AES),
                Attributes.length(128),
                Attributes.usage(
                    Enums.CryptographicUsageMask.ENCRYPT, Enums.CryptographicUsageMask.DECRYPT),
                Attributes.name(lastName))
            .build();
    var r =
        f.client.batch(
            List.of(first, Requests.get().uniqueIdentifier(f.namespace + "-missing").build(), last),
            RequestOptions.DEFAULT.batching(true, option));
    List<String> prior = locate(beforeName), after = locate(lastName);
    f.owned.addAll(prior);
    f.owned.addAll(after);
    f.evidence.put(
        "batch_statuses", r.results().stream().map(x -> x.status() + ":" + x.reason()).toList());
    if (r.results().size() == 1
        && !r.results().get(0).successful()
        && r.results().get(0).operation() == null
        && r.results().get(0).payload().isEmpty()) {
      peer(
          prior.isEmpty() && after.isEmpty(),
          "Whole-message batch rejection left committed mutations");
      throw new Classification(
          Outcome.UNSUPPORTED_SERVER,
          "Peer rejected optional ordered/continuation batching without side effects; no fallback"
              + " sent");
    }
    if (id.equals("BATCH-06")) {
      peer(prior.isEmpty() && after.isEmpty(), "Undo left committed mutations");
      f.evidence.put(
          "undo_feature",
          r.results().stream().anyMatch(x -> x.status() == 3)
              ? "rollback observed"
              : "whole batch rejection without side effects");
      return;
    }
    peer(
        r.results().size() >= 2
            && r.results().get(0).successful()
            && !r.results().get(1).successful(),
        "Mixed batch results lost");
    peer(prior.size() == 1, "First ordered mutation missing");
    peer(
        id.equals("BATCH-05") ? after.size() == 1 : after.isEmpty(),
        "Continuation state contradicted requested semantics");
  }

  void concurrent() throws Exception {
    f.provision();
    for (int count : List.of(1, 8, 32, 128)) {
      ExecutorService pool = Executors.newFixedThreadPool(Math.min(count, 16));
      try {
        List<Future<String>> tasks = new ArrayList<>();
        for (int i = 0; i < count; i++)
          tasks.add(pool.submit(() -> digest(aes(f.knownUid, 256).getEncoded())));
        for (Future<String> task : tasks)
          peer(
              task.get(30, TimeUnit.SECONDS).equals(f.knownSha), "Concurrent key crossed requests");
      } finally {
        pool.shutdownNow();
      }
    }
    f.evidence.put("callers", List.of(1, 8, 32, 128));
    f.evidence.put("executor_threads", 16);
  }

  void performance() throws Exception {
    f.provision();
    long coldStart = System.nanoTime();
    try (var cold = f.identity("client")) {
      Keys.aesKey(cold.get(f.knownUid).requirePayload(), f.knownUid, 256);
    }
    f.evidence.put("cold_context_and_get_us", (System.nanoTime() - coldStart) / 1000);
    List<Long> times = new ArrayList<>();
    for (int i = 0; i < 100; i++) {
      long t = System.nanoTime();
      peer(
          digest(aes(f.knownUid, 256).getEncoded()).equals(f.knownSha),
          "Latency sample key mismatch");
      times.add((System.nanoTime() - t) / 1000);
    }
    Collections.sort(times);
    long p95 = times.get(94), p99 = times.get(98);
    f.evidence.put("p95_get_us", p95);
    f.evidence.put("p99_get_us", p99);
    f.evidence.put("samples", 100);
    f.evidence.put(
        "latency_scope",
        "Local container network; warm SSL context, fresh socket per Get. End-to-end timing"
            + " includes server processing; server CPU time is not separately instrumented.");
    String budget = System.getProperty("kmip.catalog.p95Millis"),
        tailBudget = System.getProperty("kmip.catalog.p99Millis");
    if (budget == null || tailBudget == null)
      blocked(
          "Latency measured; pre-approved p95 and p99 budgets required (-Dkmip.catalog.p95Millis"
              + " and -Dkmip.catalog.p99Millis)");
    f.evidence.put("p95_budget_ms", Double.parseDouble(budget));
    f.evidence.put("p99_budget_ms", Double.parseDouble(tailBudget));
    f.evidence.put("percentile_method", "Nearest rank: sorted sample 95 and 99 of 100");
    require(p95 <= Double.parseDouble(budget) * 1000, "Configured p95 latency budget exceeded");
    require(p99 <= Double.parseDouble(tailBudget) * 1000, "Configured p99 latency budget exceeded");
  }

  void soak() throws Exception {
    String configured = System.getProperty("kmip.catalog.soak");
    if (configured == null) blocked("24-hour lane is opt-in: -Dkmip.catalog.soak=PT24H");
    Duration duration = Duration.parse(configured);
    if (duration.compareTo(Duration.ofHours(24)) < 0)
      blocked("Full soak requires at least PT24H; a short smoke is not credited");
    f.evidence.putAll(CatalogSoak.run(f, duration, null));
  }

  void previousRelease() throws Exception {
    String configured = System.getProperty("kmip.catalog.previousArtifact");
    // The previous release's packages: an artifact given explicitly is a keytend-kmip release's SDK
    // JAR.
    String packages = "dev.keytend.kmip";
    String kind = "explicit_external_artifact";
    if (configured == null)
      blocked(
          "No previous release artifact: supply -Dkmip.catalog.previousArtifact=/path/to/keytend-kmip-X.Y.Z.jar");
    f.evidence.put("baseline_kind", kind);
    Path previous = Path.of(configured).toAbsolutePath();
    if (!Files.isRegularFile(previous)) blocked("Configured previous release artifact is absent");
    f.provision();
    aes(f.knownUid, 256); // Establish a valid peer response before attributing a baseline failure.
    Path directory = Files.createTempDirectory("keytend-previous-client-");
    try {
      Path source = directory.resolve("PreviousProbe.java");
      // Compiled against the previous release's JAR, in its packages.
      Files.writeString(
          source,
          """
          import PACKAGES.client.*;
          import PACKAGES.model.*;
          import PACKAGES.transport.*;
          import java.nio.file.*;
          import java.security.*;
          import java.util.*;
          public class PreviousProbe {
            public static void main(String[] a)throws Exception {
              Path p=Path.of(a[2]);String[] v=a[3].split("[.]");
              try(var c=new KmipClient(new TlsTransport(a[0],Integer.parseInt(a[1]),Tls.context(p.resolve("client.p12"),"changeit".toCharArray(),p.resolve("ca.pem"))),ProtocolVersion.of(Integer.parseInt(v[0]),Integer.parseInt(v[1])))) {
                var r=c.get(a[4]).requirePayload();if(!r.require(Tag.UNIQUE_IDENTIFIER).textValue().equals(a[4]))throw new AssertionError("UID mismatch");
                byte[] key=r.require(Tag.SYMMETRIC_KEY).require(Tag.KEY_BLOCK).require(Tag.KEY_VALUE).require(Tag.KEY_MATERIAL).bytesValue();
                String hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(key));if(!hash.equals(a[5]))throw new AssertionError("Key mismatch");
                System.out.println("COMPATIBLE");
              }
            }
          }
          """
              .replace("PACKAGES", packages));
      var compiler = javax.tools.ToolProvider.getSystemJavaCompiler();
      if (compiler == null) blocked("Previous-release consumer compilation needs a JDK");
      ByteArrayOutputStream diagnostics = new ByteArrayOutputStream();
      int status =
          compiler.run(
              null,
              diagnostics,
              diagnostics,
              "--release",
              "17",
              "-cp",
              previous.toString(),
              "-d",
              directory.toString(),
              source.toString());
      require(status == 0, "Previous release public API did not compile this exact-ID consumer");
      Process process =
          new ProcessBuilder(
                  Path.of(System.getProperty("java.home"), "bin/java").toString(),
                  "-cp",
                  previous + java.io.File.pathSeparator + directory,
                  "PreviousProbe",
                  f.host,
                  Integer.toString(f.port),
                  f.certs.toString(),
                  f.version.toString(),
                  f.knownUid,
                  f.knownSha)
              .redirectErrorStream(true)
              .start();
      if (!process.waitFor(15, TimeUnit.SECONDS)) {
        process.destroyForcibly();
        throw new AssertionError("Previous-release client deadline");
      }
      require(
          process.exitValue() == 0, "Previous-release client did not read exact historical key");
      aes(f.knownUid, 256);
      f.evidence.put("previous_artifact_sha256", digest(Files.readAllBytes(previous)));
      f.evidence.put(
          "rollback",
          "Previous artifact and candidate read identical exact UID under unchanged fixture"
              + " configuration");
    } finally {
      try (var walk = Files.walk(directory)) {
        for (Path p : walk.sorted(Comparator.reverseOrder()).toList()) Files.deleteIfExists(p);
      }
    }
  }

  void observe(String id) throws Exception {
    if (id.equals("OBS-06")) {
      require(f.provenance().containsKey("configuration_hash"), "No triage identity");
      return;
    }
    if (id.equals("OBS-04")) {
      for (Map<String, Object> r : records)
        require(!json(r).contains("PRIVATE KEY"), "Secret in report");
      return;
    }
    if (id.equals("OBS-03")) {
      long before = f.attempts;
      f.provision();
      f.client.execute(Requests.get().uniqueIdentifier(f.knownUid).build());
      require(f.attempts > before, "Attempt counter missing");
      f.evidence.put("attempts", f.attempts - before);
      f.evidence.put("metrics", "Harness observations; no SDK metrics exporter");
      return;
    }
    if (id.equals("OBS-02")) {
      var r = f.client.execute(Requests.get().uniqueIdentifier(f.namespace + "-absent").build());
      peer(r.reason() != null, "Missing structured reason");
      return;
    }
    byte[] marker =
        "SYNTHETIC_SECRET_MARKER_123456789".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    Ttlv n = bytes(KEY_MATERIAL, marker);
    require(!n.toString().contains("SYNTHETIC"), "TTLV leaked secret");
    byte[] b = n.bytesValue();
    b[0] = 0;
    require(n.bytesValue()[0] != 0, "Secret buffer alias");
    Arrays.fill(b, (byte) 0);
    f.evidence.put(
        "memory_clearing",
        "Caller-owned copies only; immutable model/JCA/GC copies cannot be guaranteed erased");
  }

  // Complex format, wrapping and signing scenarios are kept in a separate shared component.
  void wrap(String id) throws Exception {
    CatalogObjects.wrapping(id, this);
  }

  void rsaFormats(String id) throws Exception {
    CatalogObjects.rsaFormats(id, this);
  }

  void rsaCrypto(String id) throws Exception {
    CatalogObjects.rsaCrypto(id, this);
  }

  void ec(String id) throws Exception {
    CatalogObjects.ec(id, this);
  }

  void certificates(String id) throws Exception {
    if (id.equals("ASYM-07") && !f.version.atLeast(ProtocolVersion.V1_2))
      outside("Parent certificate links require 1.2; direct certificate IDs are tested separately");
    CatalogObjects.certificates(id, this);
  }

  void streaming() throws Exception {
    CatalogObjects.streaming(this);
  }
}
