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

import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/**
 * Every public method of {@link Kms}, the SDK's key objects and its TLS objects that sends a
 * request is one application call ({@link KmsListener#callStarted}) named after the method, whose
 * attempts carry that name, and whose outcome is what the method did: SUCCEEDED when it returned,
 * FAILED with what it threw. A tour calls each of them, each overload by its parameter types; a
 * public method or overload the tour does not call, and that is not listed as sending nothing,
 * fails the test, so a new public method or overload is checked too.
 */
class CallNamesTest {
  static final Duration HOURLY = Duration.ofHours(1);

  /** The classes whose public methods are checked. */
  static final List<Class<?>> CLASSES =
      List.of(
          CurrentKey.class,
          KeyHandle.class,
          KmsKeys.class,
          KeyPairHandle.class,
          KeyCreation.class,
          KeyPairCreation.class,
          KeyRegistration.class,
          LocalKeys.class,
          LocalKeys.SharedKms.class,
          Kms.class,
          KmsTls.class,
          TlsIdentityRegistration.class,
          TlsIssuerRegistration.class,
          TlsIdentityIssuance.class,
          TlsIssuer.class,
          TlsReissue.class,
          TlsIdentityHandle.class,
          TlsIdentityFollower.class,
          TlsTrustFollower.class);

  /** Public methods that send no request: configuration, builders, local reads. */
  static final Set<String> LOCAL =
      Set.of(
          "CurrentKey.checkingEvery",
          "CurrentKey.refreshingEvery", // its checks are background calls (KmsCallEventsTest)
          "CurrentKey.onChange",
          "CurrentKey.close",
          "CurrentKey.moveTo", // holds the key given, without a request
          "KeyHandle.id",
          "KeyHandle.knownKind",
          "KeyHandle.allowingCompromised",
          "KeyHandle.acceptingOriginalId",
          "KmsKeys.createAes",
          "KmsKeys.createSymmetric",
          "KmsKeys.createKeyPair",
          "KmsKeys.register",
          "KmsKeys.registerSecret",
          "KmsKeys.handle",
          "KmsKeys.current(KeyHandle)", // holds the key given, without a request
          "KmsKeys.localKeys",
          "KmsKeys.sealedKeyId",
          "KmsKeys.chunkedHeaderKeyId",
          "KmsKeys.sealedStreamKeyId",
          "KeyPairHandle.privateKey",
          "KeyPairHandle.publicKey",
          "LocalKeys.builder",
          "LocalKeys.ttl",
          "LocalKeys.refreshAfter",
          "LocalKeys.invalidate",
          "LocalKeys.invalidateAll",
          "LocalKeys.currentWriteId",
          "LocalKeys.name",
          "LocalKeys.usableFor",
          "LocalKeys.writeFailure",
          "LocalKeys.stats",
          "LocalKeys.close",
          "LocalKeys.sharedKms",
          "SharedKms.localKeys",
          "SharedKms.connectionStats",
          "SharedKms.close",
          "SharedKms.toString",
          "CurrentKey.toString",
          "KeyHandle.toString",
          "KeyHandle.equals",
          "KeyHandle.hashCode",
          "KeyPairHandle.toString",
          "KeyPairHandle.equals",
          "KeyPairHandle.hashCode",
          // the builders' settings
          "KeyCreation.named",
          "KeyCreation.usages",
          "KeyCreation.group",
          "KeyCreation.custom",
          "KeyCreation.extractable",
          "KeyCreation.sensitive",
          "KeyCreation.replacingCompromised",
          "KeyCreation.refusingExistingName",
          "KeyCreation.refusingPreActive",
          "KeyCreation.allowingPreActive",
          "KeyPairCreation.named",
          "KeyPairCreation.privateUsages",
          "KeyPairCreation.publicUsages",
          "KeyPairCreation.group",
          "KeyPairCreation.custom",
          "KeyRegistration.named",
          "KeyRegistration.usages",
          "KeyRegistration.group",
          "KeyRegistration.custom",
          "KeyRegistration.extractable",
          "KeyRegistration.sensitive",
          "KeyRegistration.ecAlgorithm",
          "KeyRegistration.refusingExistingName",
          // Kms: connecting negotiates before any application call; the rest are local.
          "Kms.connect",
          "Kms.version",
          "Kms.keys",
          "Kms.tls",
          "Kms.withTimeout",
          "Kms.callTimeout",
          "Kms.protocol",
          "Kms.connectionStats",
          "Kms.close",
          "Kms.toString",
          // Its own connections on the current certificate, told by the renewal events
          // (ClientCertificateRenewalTest), not as a call.
          "Kms.renewClientCertificate",
          // TLS: the builder, a handle's parts, the followers' reads from memory and settings.
          "KmsTls.register",
          "TlsIdentityRegistration.named",
          "TlsIdentityRegistration.custom",
          "KmsTls.registerIssuer",
          "KmsTls.issue",
          "TlsIssuerRegistration.named",
          "TlsIssuerRegistration.custom",
          "TlsIdentityIssuance.keyPair",
          "TlsIdentityIssuance.subject",
          "TlsIdentityIssuance.dnsNames",
          "TlsIdentityIssuance.ipAddresses",
          "TlsIdentityIssuance.uris",
          "TlsIdentityIssuance.emails",
          "TlsIdentityIssuance.validFor",
          "TlsIdentityIssuance.issuedBy",
          "TlsIdentityIssuance.custom",
          "TlsIdentityIssuance.toString",
          "TlsIssuer.name",
          "TlsIssuer.certificate",
          "TlsIssuer.publicKey",
          "TlsIssuer.privateKey",
          "TlsIssuer.chain",
          "TlsIssuer.toString",
          "TlsReissue.sameKey",
          "TlsReissue.newKey",
          "TlsReissue.validFor",
          "TlsReissue.issuedBy",
          "TlsReissue.toString",
          "TlsIdentityHandle.name",
          "TlsIdentityHandle.certificate",
          "TlsIdentityHandle.privateKey",
          "TlsIdentityHandle.chain",
          "TlsIdentityHandle.toString",
          "TlsIdentityFollower.name",
          "TlsIdentityFollower.keyManager",
          "TlsIdentityFollower.identity",
          "TlsIdentityFollower.state",
          "TlsIdentityFollower.usableFor",
          "TlsIdentityFollower.status",
          "TlsIdentityFollower.onChange",
          "TlsIdentityFollower.close",
          "TlsIdentityFollower.toString",
          "TlsTrustFollower.trustManager",
          "TlsTrustFollower.anchors",
          "TlsTrustFollower.allowedPeers",
          "TlsTrustFollower.allows",
          "TlsTrustFollower.usableFor",
          "TlsTrustFollower.failure",
          "TlsTrustFollower.onChange",
          "TlsTrustFollower.unknownPeerCheck",
          "TlsTrustFollower.unknownPeerCheckInHandshake",
          "TlsTrustFollower.unknownPeerCheckPerCertificate",
          "TlsTrustFollower.unknownPeerCheckGap",
          "TlsTrustFollower.unknownPeerCheckQueue",
          "TlsTrustFollower.close",
          "TlsTrustFollower.toString");

  /**
   * The call names that are not the method's own: a {@code ...Result} form is its rotation's call,
   * a {@link LocalKeys} use is the cache's load, a TLS follower's refresh is named after the
   * method that made it. {@code method} is {@code Class.name}, or {@code Class.name(Types)} for an
   * overload.
   */
  static String expectedName(String method) {
    int paren = method.indexOf('(');
    if (paren >= 0) method = method.substring(0, paren);
    String name = method.substring(method.indexOf('.') + 1);
    if (method.startsWith("LocalKeys.")) return "localKeys";
    if (method.startsWith("TlsIdentityFollower.")) return "follow";
    if (method.startsWith("TlsTrustFollower.")) return "trustAnchors";
    // An issuer's registration is named after the method that made it.
    if (method.equals("TlsIssuerRegistration.register")) return "registerIssuer";
    // A ...Result form takes its method's name: rotateResult is rotate.
    if (name.endsWith("Result")) return name.substring(0, name.length() - "Result".length());
    return name;
  }

  @FunctionalInterface
  interface Step {
    void run() throws Exception;
  }

  /** The tour: each step one public method, recorded. */
  static final class Tour {
    final KmsCallEventsTest.Recorder r = new KmsCallEventsTest.Recorder();
    final Map<String, Integer> called = new LinkedHashMap<>();
    final List<String> problems = new ArrayList<>();

    /** Calls {@code method} through {@code step}, and checks its call. */
    void step(String method, Step step) {
      step(method, false, step);
    }

    /**
     * {@link #step(String, Step)} of a method returning a lazy stream: a call per page read, each
     * named after the method.
     */
    void stream(String method, Step step) {
      step(method, true, step);
    }

    private void step(String method, boolean pages, Step step) {
      r.clear();
      Throwable thrown = null;
      try {
        step.run();
      } catch (Exception e) {
        thrown = e;
      }
      called.merge(method, 1, Integer::sum);
      try {
        r.checkWellFormed();
      } catch (AssertionError e) {
        problems.add(method + ": " + e.getMessage());
        return;
      }
      List<KmsEvent> calls = r.finishedCalls();
      if (pages && !calls.isEmpty() && thrown == null) {
        for (KmsEvent page : calls)
          if (!expectedName(method).equals(page.operation()))
            problems.add(method + ": a page's call is named " + page.operation());
        return;
      }
      if (calls.size() != 1) {
        problems.add(
            method
                + ": "
                + calls.size()
                + " calls, not one: "
                + calls
                + (thrown == null ? "" : " (it threw " + thrown + ")"));
        return;
      }
      KmsEvent call = calls.get(0);
      String expected = expectedName(method);
      if (!expected.equals(call.operation()))
        problems.add(method + ": the call is named " + call.operation() + ", not " + expected);
      KmsEvent.Outcome outcome =
          thrown == null ? KmsEvent.Outcome.SUCCEEDED : KmsEvent.Outcome.FAILED;
      if (call.outcome() != outcome)
        problems.add(
            method
                + ": "
                + call.outcome()
                + " but it "
                + (thrown == null ? "returned" : "threw " + thrown));
      if (thrown instanceof KmsException k && call.failure().orElse(null) != k)
        problems.add(method + ": the call's failure is not what it threw: " + call.failure());
    }
  }

  static KeyHandle aes(Kms kms, String name) {
    return kms.keys()
        .createAes(256)
        .named(name)
        .extractable(true)
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT, KeyUsage.WRAP_KEY, KeyUsage.UNWRAP_KEY)
        .create();
  }

  @Test
  void everyPublicMethodIsOneCallNamedAfterItWithItsOutcome(@TempDir Path dir) throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Tour t = new Tour();
    byte[] data = {1, 2, 3, 4};
    byte[] fileId = {9};
    try (Kms kms = Kms.connect(server.configure().addListener(t.r).build())) {
      assertEquals(List.of(), t.r.finishedCalls(), "connecting is no application call");
      KmsKeys keys = kms.keys();
      KeyHandle key = aes(kms, "tour");
      CustomAttribute tourFamily = CustomAttribute.client("tour-family");
      key.setCustomAttribute(tourFamily, "tour");
      KeyQuery family = KeyQuery.byName("tour");

      // CurrentKey, a check due on every call.
      CurrentKey kek = keys.current(key).checkingEvery(Duration.ofNanos(1));
      byte[][] sealed = {null};
      Ciphertext[] wrapped = {null};
      byte[][] header = {null};
      t.step("CurrentKey.handle", kek::handle);
      t.step("CurrentKey.refresh", kek::refresh);
      t.step("CurrentKey.seal", () -> sealed[0] = kek.seal(data, null));
      t.step("CurrentKey.open", () -> kek.open(sealed[0], null));
      t.step("CurrentKey.rewrapRecord", () -> kek.rewrapRecord(sealed[0], null));
      t.step("CurrentKey.generateDataKey", () -> kek.generateDataKey(256, null).key().destroy());
      t.step(
          "CurrentKey.wrapKey(SecretKey,byte[])",
          () -> wrapped[0] = kek.wrapKey(new SecretKeySpec(new byte[16], "AES"), null));
      t.step(
          "CurrentKey.wrapKey(CipherSpec,SecretKey,byte[])",
          () -> kek.wrapKey(CipherSpec.aesGcm(), new SecretKeySpec(new byte[16], "AES"), null));
      t.step(
          "CurrentKey.unwrapKey", () -> kek.unwrapKey(Expect.aes(128), wrapped[0], null).destroy());
      t.step("CurrentKey.rewrapKey", () -> kek.rewrapKey(wrapped[0], null));
      t.step(
          "CurrentKey.chunkedSealer",
          () -> {
            try (ChunkedSealer sealer = kek.chunkedSealer(fileId)) {
              header[0] = sealer.header();
            }
          });
      t.step("CurrentKey.chunkedOpener", () -> kek.chunkedOpener(header[0], fileId).close());
      t.step("CurrentKey.rewrapHeader", () -> kek.rewrapHeader(header[0], fileId));
      Path plain = Files.write(dir.resolve("plain"), data);
      Path sealedFile = dir.resolve("sealed");
      t.step(
          "CurrentKey.sealTo(Path,InputStream,byte[])",
          () -> kek.sealTo(sealedFile, new ByteArrayInputStream(data), null));
      t.step(
          "CurrentKey.sealTo(Path,InputStream,byte[],FileDurability)",
          () ->
              kek.sealTo(
                  sealedFile, new ByteArrayInputStream(data), null, FileDurability.CONTENT_ONLY));
      t.step(
          "CurrentKey.openTo(Path,Path,byte[])",
          () -> kek.openTo(sealedFile, dir.resolve("out1"), null));
      t.step(
          "CurrentKey.openTo(Path,Path,byte[],FileDurability)",
          () -> kek.openTo(sealedFile, dir.resolve("out2"), null, FileDurability.CONTENT_ONLY));
      ByteArrayOutputStream kekStream = new ByteArrayOutputStream();
      t.step(
          "CurrentKey.sealing",
          () -> {
            try (SealingStream out = kek.sealing(kekStream, null)) {
              out.write(data);
              out.finish();
            }
          });
      // Refused, with no newer key to follow: FAILED with what it threw.
      KeyHandle lone = aes(kms, "tour-lone");
      lone.deactivate();
      CurrentKey refusedKek = keys.current(lone);
      t.step("CurrentKey.sealing", () -> refusedKek.sealing(new ByteArrayOutputStream(), null));
      t.step(
          "CurrentKey.opening",
          () -> {
            try (InputStream in =
                kek.opening(new ByteArrayInputStream(kekStream.toByteArray()), null)) {
              in.readAllBytes();
            }
          });
      t.step("CurrentKey.rotateOrLatest()", kek::rotateOrLatest);
      t.step(
          "CurrentKey.rotateOrLatest(Rotation)",
          () -> kek.rotateOrLatest(Rotation.of(RotationDates.COPIED)));
      t.step(
          "CurrentKey.rotateIfActiveFor(Duration)",
          () -> kek.rotateIfActiveFor(Duration.ofDays(9)));
      t.step(
          "CurrentKey.rotateIfActiveFor(Duration,Rotation)",
          () -> kek.rotateIfActiveFor(Duration.ofDays(9), Rotation.of(RotationDates.COPIED)));
      assertNotNull(plain);

      // KeyHandle: reads, cryptography, lifecycle.
      KeyHandle k = aes(kms, "tour-key");
      t.step("KeyHandle.attributes", k::attributes);
      t.step("KeyHandle.latest", k::latest);
      t.step("KeyHandle.isLatest", k::isLatest);
      t.step("KeyHandle.lineage", k::lineage);
      t.step("KeyHandle.leftovers", k::leftovers);
      t.step("KeyHandle.compromisedPredecessors", k::compromisedPredecessors);
      t.step("KeyHandle.retirementPlan", k::retirementPlan);
      t.step("KeyHandle.retirementPlanOlderThan", () -> k.retirementPlanOlderThan(k));
      t.step(
          "KeyHandle.asSecretKey",
          () -> k.asSecretKey(Expect.aes(256), LocalUse.ENCRYPT).destroy());
      KeyPairHandle ec =
          keys.createKeyPair(KeyPairSpec.ec(Curve.P_256))
              .named("tour-ec", "tour-ec-pub")
              .privateUsages(KeyUsage.SIGN)
              .publicUsages(KeyUsage.VERIFY)
              .create();
      t.step("KeyHandle.asPublicKey", () -> ec.publicKey().asPublicKey(Expect.ec(Curve.P_256)));
      t.step("KeyHandle.asPrivateKey", () -> ec.privateKey().asPrivateKey(Expect.ec(Curve.P_256)));
      // A handle that does not know its kind reads it: a refusal after a request.
      t.step("KeyHandle.asCertificate", () -> keys.handle(k.id()).asCertificate());
      KeyHandle secret =
          keys.registerSecret("tour-password".toCharArray()).named("tour-secret").register();
      t.step("KeyHandle.asSecretData", secret::asSecretData);
      Ciphertext[] ct = {null};
      t.step(
          "KeyHandle.encrypt(CipherSpec,byte[])",
          () -> ct[0] = k.encrypt(CipherSpec.aesGcm(), data));
      t.step(
          "KeyHandle.encrypt(CipherSpec,byte[],byte[])",
          () -> k.encrypt(CipherSpec.aesGcm(), data, new byte[] {7}));
      t.step("KeyHandle.decrypt(Ciphertext,byte[])", () -> k.decrypt(ct[0], null));
      t.step(
          "KeyHandle.decrypt(CipherSpec,Ciphertext,byte[])",
          () -> k.decrypt(CipherSpec.aesGcm(), ct[0], null));
      Ciphertext[] wk = {null};
      t.step(
          "KeyHandle.wrapKey",
          () ->
              wk[0] = k.wrapKey(CipherSpec.aesGcm(), new SecretKeySpec(new byte[16], "AES"), null));
      t.step(
          "KeyHandle.unwrapKey(Expect,Ciphertext,byte[])",
          () -> k.unwrapKey(Expect.aes(128), wk[0], null).destroy());
      t.step(
          "KeyHandle.unwrapKey(CipherSpec,Expect,Ciphertext,byte[])",
          () -> k.unwrapKey(CipherSpec.aesGcm(), Expect.aes(128), wk[0], null).destroy());
      byte[] sealedByK = k.seal(data, null);
      t.step("KeyHandle.open", () -> k.open(sealedByK, null));
      ByteArrayOutputStream stream = new ByteArrayOutputStream();
      t.step(
          "KeyHandle.sealing",
          () -> {
            try (SealingStream out = k.sealing(stream, null)) {
              out.write(data);
              out.finish();
            }
          });
      t.step(
          "KeyHandle.opening",
          () -> {
            try (InputStream in = k.opening(new ByteArrayInputStream(stream.toByteArray()), null)) {
              in.readAllBytes();
            }
          });
      byte[] chunkHeader;
      try (ChunkedSealer sealer = keys.current(k).chunkedSealer(fileId)) {
        chunkHeader = sealer.header();
      }
      t.step("KeyHandle.chunkedOpener", () -> k.chunkedOpener(chunkHeader, fileId).close());
      Path fileByK = dir.resolve("sealed-by-k");
      keys.current(k).sealTo(fileByK, new ByteArrayInputStream(data), null);
      t.step(
          "KeyHandle.openTo(Path,Path,byte[])", () -> k.openTo(fileByK, dir.resolve("out3"), null));
      t.step(
          "KeyHandle.openTo(Path,Path,byte[],FileDurability)",
          () -> k.openTo(fileByK, dir.resolve("out4"), null, FileDurability.CONTENT_ONLY));
      KeyHandle other = aes(kms, "tour-other");
      t.step("KeyHandle.rewrapTo", () -> k.rewrapTo(other, sealedByK, null));
      t.step("KeyHandle.rewrapRecordTo", () -> k.rewrapRecordTo(other, sealedByK, null));
      t.step("KeyHandle.rewrapKeyTo", () -> k.rewrapKeyTo(other, wk[0], null));
      byte[][] signature = {new byte[64]};
      t.step(
          "KeyHandle.sign",
          () -> signature[0] = ec.privateKey().sign(SignatureSpec.ecdsa(Hash.SHA_256), data));
      t.step(
          "KeyHandle.verify",
          () -> ec.publicKey().verify(SignatureSpec.ecdsa(Hash.SHA_256), data, signature[0]));
      t.step("KeyHandle.mac", () -> k.mac(MacSpec.hmac(Hash.SHA_256), data));
      t.step(
          "KeyHandle.macVerify", () -> k.macVerify(MacSpec.hmac(Hash.SHA_256), data, new byte[32]));
      t.step("KeyHandle.addName", () -> k.addName("tour-key-alias"));
      t.step("KeyHandle.removeName", () -> k.removeName("tour-key-alias"));
      t.step("KeyHandle.addToGroup", () -> k.addToGroup("tour-group"));
      t.step("KeyHandle.removeFromGroup", () -> k.removeFromGroup("tour-group"));
      CustomAttribute attribute = CustomAttribute.client("tour-attribute");
      t.step("KeyHandle.setCustomAttribute", () -> k.setCustomAttribute(attribute, "v"));
      t.step("KeyHandle.removeCustomAttribute", () -> k.removeCustomAttribute(attribute));
      t.step(
          "KeyHandle.deactivateAt", () -> k.deactivateAt(Instant.now().plus(Duration.ofDays(30))));

      // Rotation and its lineage.
      t.step("KeyHandle.rotate()", k::rotate);
      KeyHandle r1 = k.latest();
      t.step("KeyHandle.rotate(Rotation)", () -> r1.rotate(Rotation.of(RotationDates.COPIED)));
      KeyHandle r2 = r1.latest();
      t.step("KeyHandle.rotateResult", () -> r2.rotateResult(Rotation.of(RotationDates.COPIED)));
      KeyHandle r3 = r2.latest();
      t.step("KeyHandle.rotateOrLatest()", r3::rotateOrLatest);
      t.step(
          "KeyHandle.rotateOrLatest(Rotation)",
          () -> r3.rotateOrLatest(Rotation.of(RotationDates.COPIED)));
      t.step(
          "KeyHandle.rotateOrLatestResult",
          () -> r3.rotateOrLatestResult(Rotation.of(RotationDates.COPIED)));
      KeyHandle r4 = r3.latest();
      t.step(
          "KeyHandle.rotateIfActiveFor(Duration)", () -> r4.rotateIfActiveFor(Duration.ofDays(9)));
      t.step(
          "KeyHandle.rotateIfActiveFor(Duration,Rotation)",
          () -> r4.rotateIfActiveFor(Duration.ofDays(9), Rotation.of(RotationDates.COPIED)));
      t.step(
          "KeyHandle.rotateIfActiveForResult(Duration,Rotation)",
          () -> r4.rotateIfActiveForResult(Duration.ofDays(9), Rotation.of(RotationDates.COPIED)));
      t.step(
          "KeyHandle.rotateIfActiveForResult(Duration,Rotation,KeyHandle)",
          () ->
              r4.rotateIfActiveForResult(
                  Duration.ofDays(9), Rotation.of(RotationDates.COPIED), r4));
      t.step("KeyHandle.reconcile", r4::reconcile);
      t.step("KeyHandle.deactivatePredecessors()", r4::deactivatePredecessors);
      t.step(
          "KeyHandle.deactivatePredecessors(RevocationReason)",
          () -> r4.deactivatePredecessors(RevocationReason.superseded("tour")));
      RetirementPlan deactivation = r4.retirementPlan();
      t.step(
          "KeyHandle.deactivatePredecessors(RevocationReason,RetirementPlan)",
          () -> r4.deactivatePredecessors(RevocationReason.superseded("tour"), deactivation));
      t.step(
          "KeyHandle.retirePredecessors(RevocationReason)",
          () -> r4.retirePredecessors(RevocationReason.superseded("tour")));
      RetirementPlan retirement = r4.retirementPlan();
      t.step(
          "KeyHandle.retirePredecessors(RevocationReason,RetirementPlan)",
          () -> r4.retirePredecessors(RevocationReason.superseded("tour"), retirement));
      t.step(
          "KeyHandle.retirePredecessorsOlderThan",
          () -> r4.retirePredecessorsOlderThan(r4, RevocationReason.superseded("tour")));

      // Lifecycle of fresh keys.
      KeyHandle pre =
          keys.createAes(256).named("tour-pre").usages(KeyUsage.ENCRYPT).createPreActive();
      t.step("KeyHandle.activate", pre::activate);
      t.step("KeyHandle.revoke", () -> pre.revoke(RevocationReason.superseded("tour")));
      KeyHandle d1 = aes(kms, "tour-d1");
      t.step("KeyHandle.deactivate()", d1::deactivate);
      KeyHandle d2 = aes(kms, "tour-d2");
      t.step(
          "KeyHandle.deactivate(RevocationReason)",
          () -> d2.deactivate(RevocationReason.superseded("tour")));
      t.step("KeyHandle.destroy", d2::destroy);
      KeyHandle c1 = aes(kms, "tour-c1");
      t.step(
          "KeyHandle.replaceCompromised(RevocationReason)",
          () -> c1.replaceCompromised(RevocationReason.keyCompromise("tour", Instant.now())));
      KeyHandle c2 = aes(kms, "tour-c2");
      t.step(
          "KeyHandle.replaceCompromised(RevocationReason,Rotation)",
          () ->
              c2.replaceCompromised(
                  RevocationReason.keyCompromise("tour", Instant.now()),
                  Rotation.of(RotationDates.COPIED)));
      KeyHandle c3 = aes(kms, "tour-c3");
      t.step("KeyHandle.compromisePlan", c3::compromisePlan);
      CompromisePlan plan3 = c3.compromisePlan();
      t.step(
          "KeyHandle.replaceCompromisedResult(RevocationReason,CompromisePlan)",
          () ->
              c3.replaceCompromisedResult(
                  RevocationReason.keyCompromise("tour", Instant.now()), plan3));
      KeyHandle c4 = aes(kms, "tour-c4");
      CompromisePlan plan4 = c4.compromisePlan();
      t.step(
          "KeyHandle.replaceCompromisedResult(RevocationReason,Rotation,CompromisePlan)",
          () ->
              c4.replaceCompromisedResult(
                  RevocationReason.keyCompromise("tour", Instant.now()),
                  Rotation.of(RotationDates.COPIED),
                  plan4));

      // KmsKeys.
      t.step("KmsKeys.current(String)", () -> keys.current("tour"));
      t.step("KmsKeys.keyPair", () -> keys.keyPair("no-such-pair"));
      t.step("KmsKeys.findByName(String)", () -> keys.findByName("tour"));
      t.step(
          "KmsKeys.findByName(String,KeyState,KeyState[])",
          () -> keys.findByName("tour", KeyState.ACTIVE));
      t.step("KmsKeys.reconcile(String)", () -> keys.reconcile("tour"));
      t.step("KmsKeys.reconcilePlan", () -> keys.reconcilePlan("tour"));
      ReconcilePlan plan = keys.reconcilePlan("tour").orElseThrow();
      t.step("KmsKeys.reconcile(String,ReconcilePlan)", () -> keys.reconcile("tour", plan));
      t.step("KmsKeys.clearPendingName", () -> keys.clearPendingName("tour-none"));
      KeyHandle m1 = aes(kms, "tour-m1");
      KeyHandle m2 = aes(kms, "tour-m2");
      t.step("KmsKeys.moveName", () -> keys.moveName("tour-m1", m1.id(), m2.id()));
      t.stream("KmsKeys.locate", () -> assertNotNull(keys.locate(family).toList()));
      t.step("KmsKeys.list", () -> keys.list(family));
      t.stream(
          "KmsKeys.locateWithAttributes",
          () -> assertNotNull(keys.locateWithAttributes(family).toList()));
      CustomAttribute queried = CustomAttribute.client("tour-query");
      KeyHandle q =
          keys.createAes(256)
              .named("tour-q")
              .custom(queried, "q")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
      KeyQuery any = KeyQuery.all().custom(queried, "q");
      CurrentKey qk = keys.current(q);
      Ciphertext ctK = q.encrypt(CipherSpec.aesGcm(), data);
      t.step("KmsKeys.decrypt(KeyQuery,Ciphertext,byte[])", () -> keys.decrypt(any, ctK, null));
      t.step(
          "KmsKeys.decrypt(KeyQuery,CipherSpec,Ciphertext,byte[])",
          () -> keys.decrypt(any, CipherSpec.aesGcm(), ctK, null));
      Ciphertext wrappedK = qk.wrapKey(new SecretKeySpec(new byte[16], "AES"), null);
      t.step(
          "KmsKeys.unwrapKey",
          () -> keys.unwrapKey(any, Expect.aes(128), wrappedK, null).destroy());
      byte[] sealedK = qk.seal(data, null);
      t.step("KmsKeys.open", () -> keys.open(any, sealedK, null));
      ByteArrayOutputStream streamK = new ByteArrayOutputStream();
      try (SealingStream out = q.sealing(streamK, null)) {
        out.write(data);
        out.finish();
      }
      t.step(
          "KmsKeys.opening",
          () -> {
            try (InputStream in =
                keys.opening(any, new ByteArrayInputStream(streamK.toByteArray()), null)) {
              in.readAllBytes();
            }
          });
      byte[] headerK;
      try (ChunkedSealer sealer = qk.chunkedSealer(fileId)) {
        headerK = sealer.header();
      }
      t.step("KmsKeys.chunkedOpener", () -> keys.chunkedOpener(any, headerK, fileId).close());
      Path fileK = dir.resolve("sealed-k");
      qk.sealTo(fileK, new ByteArrayInputStream(data), null);
      t.step(
          "KmsKeys.openTo(KeyQuery,Path,Path,byte[])",
          () -> keys.openTo(any, fileK, dir.resolve("out5"), null));
      t.step(
          "KmsKeys.openTo(KeyQuery,Path,Path,byte[],FileDurability)",
          () -> keys.openTo(any, fileK, dir.resolve("out6"), null, FileDurability.CONTENT_ONLY));

      // The builders' requests.
      t.step(
          "KeyCreation.create",
          () -> keys.createAes(256).named("tour-b1").usages(KeyUsage.ENCRYPT).create());
      t.step(
          "KeyCreation.createPreActive",
          () -> keys.createAes(256).named("tour-b2").usages(KeyUsage.ENCRYPT).createPreActive());
      t.step(
          "KeyCreation.findOrCreate",
          () -> keys.createAes(256).named("tour-b3").usages(KeyUsage.ENCRYPT).findOrCreate());
      t.step(
          "KeyCreation.findOrCreateResult",
          () -> keys.createAes(256).named("tour-b3").usages(KeyUsage.ENCRYPT).findOrCreateResult());
      SecretKeySpec raw = new SecretKeySpec(new byte[32], "AES");
      t.step(
          "KeyRegistration.register",
          () -> keys.register(raw).named("tour-r1").usages(KeyUsage.ENCRYPT).register());
      t.step(
          "KeyRegistration.registerPreActive",
          () -> keys.register(raw).named("tour-r2").usages(KeyUsage.ENCRYPT).registerPreActive());
      KeyHandle old = aes(kms, "tour-r3");
      t.step(
          "KeyRegistration.replace(KeyHandle)",
          () -> keys.register(raw).named("tour-r3").usages(KeyUsage.ENCRYPT).replace(old));
      KeyHandle staged = aes(kms, "tour-r4");
      KeyAttributes stagedPlan = staged.attributes();
      t.step(
          "KeyRegistration.replace(KeyHandle,KeyAttributes)",
          () ->
              keys.register(raw)
                  .named("tour-r4")
                  .usages(KeyUsage.ENCRYPT)
                  .replace(staged, stagedPlan));
      KeyHandle old5 = aes(kms, "tour-r5");
      t.step(
          "KeyRegistration.replaceResult(KeyHandle)",
          () -> keys.register(raw).named("tour-r5").usages(KeyUsage.ENCRYPT).replaceResult(old5));
      KeyHandle old6 = aes(kms, "tour-r6");
      KeyAttributes plan6 = old6.attributes();
      t.step(
          "KeyRegistration.replaceResult(KeyHandle,KeyAttributes)",
          () ->
              keys.register(raw)
                  .named("tour-r6")
                  .usages(KeyUsage.ENCRYPT)
                  .replaceResult(old6, plan6));
      KeyPairHandle[] pair = {null};
      t.step(
          "KeyPairCreation.create",
          () ->
              pair[0] =
                  keys.createKeyPair(KeyPairSpec.ec(Curve.P_256))
                      .named("tour-p1", "tour-p1-pub")
                      .privateUsages(KeyUsage.SIGN)
                      .publicUsages(KeyUsage.VERIFY)
                      .create());
      t.step(
          "KeyPairCreation.createPreActive",
          () ->
              keys.createKeyPair(KeyPairSpec.ec(Curve.P_256))
                  .named("tour-p2", "tour-p2-pub")
                  .privateUsages(KeyUsage.SIGN)
                  .publicUsages(KeyUsage.VERIFY)
                  .createPreActive());
      t.step(
          "KeyPairCreation.findOrCreate",
          () ->
              keys.createKeyPair(KeyPairSpec.ec(Curve.P_256))
                  .named("tour-p3", "tour-p3-pub")
                  .privateUsages(KeyUsage.SIGN)
                  .publicUsages(KeyUsage.VERIFY)
                  .findOrCreate());
      t.step(
          "KeyPairCreation.findOrCreateResult",
          () ->
              keys.createKeyPair(KeyPairSpec.ec(Curve.P_256))
                  .named("tour-p3", "tour-p3-pub")
                  .privateUsages(KeyUsage.SIGN)
                  .publicUsages(KeyUsage.VERIFY)
                  .findOrCreateResult());

      // KeyPairHandle.
      KeyPairHandle rsa =
          keys.createKeyPair(KeyPairSpec.rsa(2048))
              .named("tour-rsa", "tour-rsa-pub")
              .privateUsages(KeyUsage.DECRYPT)
              .publicUsages(KeyUsage.ENCRYPT)
              .create();
      CipherSpec oaep = CipherSpec.rsaOaep(Hash.SHA_256);
      Ciphertext[] rct = {null};
      t.step("KeyPairHandle.encrypt(CipherSpec,byte[])", () -> rct[0] = rsa.encrypt(oaep, data));
      t.step(
          "KeyPairHandle.encrypt(CipherSpec,byte[],byte[])", () -> rsa.encrypt(oaep, data, null));
      t.step("KeyPairHandle.decrypt", () -> rsa.decrypt(oaep, rct[0], null));
      t.step("KeyPairHandle.deactivate()", rsa::deactivate);
      t.step(
          "KeyPairHandle.deactivate(RevocationReason)",
          () -> rsa.deactivate(RevocationReason.superseded("tour")));
      t.step("KeyPairHandle.revoke", () -> rsa.revoke(RevocationReason.superseded("tour")));

      // LocalKeys: a use that loads.
      try (LocalKeys cache =
          keys.localKeys("tour")
              .scope(KeyQuery.all().custom(tourFamily, "tour"))
              .expect(Expect.aes(256))
              .ttl(Duration.ofMinutes(10))
              .open()) {
        String[] id = {null};
        t.step(
            "LocalKeys.forEncrypt",
            () -> {
              try (LocalKeys.Use use = cache.forEncrypt()) {
                id[0] = use.id();
              }
            });
        cache.invalidateAll();
        t.step("LocalKeys.forDecrypt", () -> cache.forDecrypt(id[0]).close());
        cache.invalidateAll();
        t.step("LocalKeys.forAppend", () -> cache.forAppend(id[0]).close());
      }

      // Kms itself.
      t.step("Kms.random", () -> kms.random(16));
      t.step("Kms.ping", kms::ping);
      t.step("Kms.serverVersions", kms::serverVersions);
      t.step("Kms.serverInfo", kms::serverInfo);

      // TLS identities, and their followers.
      KmsTls tls = kms.tls();
      TlsIdentityTest.Pki pki = new TlsIdentityTest.Pki();
      KeyPair k1 = TestPki.ec(), k2 = TestPki.ec();
      TlsIdentityHandle[] identity = {null};
      t.step(
          "TlsIdentityRegistration.register",
          () ->
              identity[0] =
                  tls.register(k1.getPrivate(), pki.chain(pki.leaf("tour-node", k1)))
                      .named("tour/node")
                      .register());
      t.step("KmsTls.identity", () -> assertTrue(tls.identity("tour/node").isPresent()));
      t.step("KmsTls.certificates", () -> tls.certificates(KeyQuery.byName("tour/node")));
      keys.register(pki.root.certificate())
          .usages(KeyUsage.VERIFY)
          .custom(tourFamily, "tour-ca")
          .register();
      KeyQuery anchors = KeyQuery.all().custom(tourFamily, "tour-ca");
      CurrentKeyFollowerTest.Manual manual = new CurrentKeyFollowerTest.Manual();
      TlsIdentityFollower[] follower = {null};
      TlsTrustFollower[] trust = {null, null};
      try {
        t.step("KmsTls.follow", () -> follower[0] = tls.follow("tour/node", HOURLY, manual));
        t.step("TlsIdentityFollower.refresh", () -> follower[0].refresh());
        t.step(
            "KmsTls.trustAnchors(KeyQuery,Duration,ScheduledExecutorService)",
            () -> trust[0] = tls.trustAnchors(anchors, HOURLY, manual));
        t.step(
            "KmsTls.trustAnchors(KeyQuery,KeyQuery,Duration,ScheduledExecutorService)",
            () -> trust[1] = tls.trustAnchors(anchors, anchors, HOURLY, manual));
        t.step("TlsTrustFollower.refresh", () -> trust[0].refresh());
      } finally {
        for (AutoCloseable c : new AutoCloseable[] {follower[0], trust[0], trust[1]})
          if (c != null) c.close();
        manual.shutdownNow();
      }
      t.step(
          "TlsIdentityHandle.renew",
          () -> identity[0] = identity[0].renew(pki.chain(pki.leaf("tour-node", k1))));
      t.step(
          "TlsIdentityHandle.rekey",
          () ->
              identity[0] =
                  identity[0].rekey(k2.getPrivate(), pki.chain(pki.leaf("tour-node", k2))));
      t.step(
          "TlsIdentityHandle.revoke",
          () -> identity[0].revoke(RevocationReason.superseded("tour")));

      // Identities the KMS issues.
      TlsIssueTest.Ca ca = TlsIssueTest.Ca.ec("Tour Issuing CA");
      TlsIssuer[] issuer = {null};
      t.step(
          "TlsIssuerRegistration.register",
          () ->
              issuer[0] =
                  tls.registerIssuer(ca.key.getPrivate(), ca.certificate)
                      .named("tour/ca")
                      .register());
      t.step("KmsTls.issuer", () -> assertTrue(tls.issuer("tour/ca").isPresent()));
      TlsIdentityHandle[] issued = {null};
      t.step(
          "TlsIdentityIssuance.issue",
          () ->
              issued[0] = tls.issue("tour/issued").subject("CN=tour").issuedBy(issuer[0]).issue());
      t.step("TlsIdentityHandle.reissue()", () -> issued[0] = issued[0].reissue());
      t.step(
          "TlsIdentityHandle.reissue(TlsReissue)",
          () -> issued[0] = issued[0].reissue(TlsReissue.sameKey()));
      t.step(
          "TlsIdentityHandle.reissueWithNewKey", () -> issued[0] = issued[0].reissueWithNewKey());
      t.step(
          "TlsIdentityHandle.reissueIfExpiresWithin(Duration)",
          () -> issued[0] = issued[0].reissueIfExpiresWithin(Duration.ofDays(400)));
      t.step(
          "TlsIdentityHandle.reissueIfExpiresWithin(Duration,TlsReissue)",
          () ->
              issued[0] =
                  issued[0].reissueIfExpiresWithin(Duration.ofDays(400), TlsReissue.newKey()));
    }

    // Every public method was called, each overload by its parameter types, or sends nothing.
    Set<String> missing = new TreeSet<>(), known = new TreeSet<>();
    for (Class<?> c : CLASSES) {
      Map<String, Integer> overloads = new LinkedHashMap<>();
      for (Method m : publicMethods(c)) overloads.merge(m.getName(), 1, Integer::sum);
      for (Method m : publicMethods(c)) {
        String method = c.getSimpleName() + "." + m.getName();
        String key = overloads.get(m.getName()) > 1 ? method + parameters(m) : method;
        known.add(key);
        if (!LOCAL.contains(method) && !LOCAL.contains(key) && !t.called.containsKey(key))
          missing.add(key);
      }
    }
    assertEquals(Set.of(), missing, "public methods the tour does not call");
    Set<String> unknown = new TreeSet<>(t.called.keySet());
    unknown.removeAll(known);
    assertEquals(Set.of(), unknown, "steps that name no public method (or an overload by name)");
    assertEquals(List.of(), t.problems);
  }

  static List<Method> publicMethods(Class<?> c) {
    List<Method> out = new ArrayList<>();
    for (Method m : c.getDeclaredMethods())
      if (Modifier.isPublic(m.getModifiers()) && !m.isSynthetic()) out.add(m);
    return out;
  }

  /** {@code (Type,Type)}: the simple names of {@code m}'s parameter types. */
  static String parameters(Method m) {
    StringBuilder out = new StringBuilder("(");
    for (Class<?> p : m.getParameterTypes())
      out.append(out.length() > 1 ? "," : "").append(p.getSimpleName());
    return out.append(')').toString();
  }
}
