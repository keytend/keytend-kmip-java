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

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.ProtocolVersion;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * {@link KmsSamplesIT}'s server-specific expectations (UNSUPPORTED and SERVER_LIMITATION) hold only
 * on the server build they were diagnosed on. Runs without containers.
 */
class KmsSamplesPinningTest {
  static {
    // KmsSamplesIT and CatalogContainersIT read this when they load.
    if (System.getProperty("project.root") == null)
      System.setProperty("project.root", Path.of("..").toAbsolutePath().normalize().toString());
  }

  static final String REBUILT_IMAGE =
      "layers:" + "1".repeat(64) + ":" + KmsSamplesIT.PYKMIP_BUILD.split(":")[2];

  /**
   * {@code RootFS.Layers} of the qualified image, as recorded when it was qualified ({@code
   * pykmip.layers.evidence} in integration/catalog/qualified-images.properties), not a copy.
   */
  static final java.util.List<String> QUALIFIED_LAYERS = recordedLayers();

  /** The layer evidence file named by the manifest. */
  static Path layerEvidence() {
    Path project = Path.of(System.getProperty("project.root")).toAbsolutePath().normalize();
    var manifest = new java.util.Properties();
    try (var in =
        java.nio.file.Files.newInputStream(
            project.resolve("integration/catalog/qualified-images.properties"))) {
      manifest.load(in);
    } catch (java.io.IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
    return project.resolve(manifest.getProperty("pykmip.layers.evidence"));
  }

  /** The {@code image_layers} array of {@link #layerEvidence()}, in order. */
  static java.util.List<String> recordedLayers() {
    try {
      return jsonStrings(java.nio.file.Files.readString(layerEvidence()), "image_layers");
    } catch (java.io.IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
  }

  /** The strings of a flat JSON array field (enough for the layer record). */
  static java.util.List<String> jsonStrings(String json, String field) {
    var array =
        java.util.regex.Pattern.compile("\"" + field + "\"\\s*:\\s*\\[([^\\]]*)\\]").matcher(json);
    assertTrue(array.find(), field);
    var item = java.util.regex.Pattern.compile("\"([^\"]*)\"").matcher(array.group(1));
    var values = new java.util.ArrayList<String>();
    while (item.find()) values.add(item.group(1));
    return java.util.List.copyOf(values);
  }

  /**
   * The PyKMIP pin is the qualified image's filesystem plus the fixture directory (which sets the
   * entrypoint, command and environment); changing any layer, or the fixture, changes it.
   */
  @Test
  void thePykmipPinIsTheQualifiedImagesLayers() throws Exception {
    String configuration =
        CatalogContainersIT.digestDirectory(
            java.nio.file.Path.of("..").resolve("integration/pykmip"));
    assertEquals(
        KmsSamplesIT.PYKMIP_BUILD, KmsSamplesIT.layers(QUALIFIED_LAYERS) + ":" + configuration);
    assertTrue(
        java.nio.file.Files.readString(
                java.nio.file.Path.of("../integration/catalog/qualified-images.properties"))
            .contains("pykmip.configuration=" + configuration),
        "the fixture is the qualified configuration");
    String qualifiedLayers =
        KmsSamplesIT.PYKMIP_BUILD.substring(0, KmsSamplesIT.PYKMIP_BUILD.lastIndexOf(':'));
    assertEquals(qualifiedLayers, KmsSamplesIT.layers(QUALIFIED_LAYERS));
    var changed = new java.util.ArrayList<>(QUALIFIED_LAYERS);
    changed.set(changed.size() - 1, "sha256:" + "0".repeat(64)); // for example another server.py
    assertNotEquals(qualifiedLayers, KmsSamplesIT.layers(changed));
    assertNotEquals(
        qualifiedLayers,
        KmsSamplesIT.layers(QUALIFIED_LAYERS.subList(0, QUALIFIED_LAYERS.size() - 1)));
  }

  @Test
  void everyServerSpecificExpectationIsPinnedToABuild() {
    for (var server : KmsSamplesIT.versions().entrySet())
      for (ProtocolVersion version : server.getValue())
        for (var cell : KmsSamplesIT.EXPECTED.get(server.getKey() + " " + version).entrySet()) {
          String value = cell.getValue();
          if (value.equals("PASS")) continue;
          ProtocolVersion lifted = KmsSamplesIT.SDK_REFUSALS.get(value);
          boolean sdk = lifted != null && !version.atLeast(lifted);
          boolean pinned =
              KmsSamplesIT.LIMITATIONS.stream()
                  .anyMatch(
                      l ->
                          l.server().equals(server.getKey())
                              && l.sample().equals(cell.getKey())
                              && l.expected().equals(value)
                              && l.identity().matches("(layers|binary):[0-9a-f]{64}:[0-9a-f]{64}"));
          assertTrue(
              sdk || pinned, server.getKey() + " " + version + " " + cell.getKey() + ": " + value);
        }
  }

  @Test
  void onTheDiagnosedBuildTheLimitationsHold() {
    String py = KmsSamplesIT.PYKMIP_BUILD, pqc = KmsSamplesIT.PQCTODAY_BUILD;
    assertEquals(
        "UNSUPPORTED:rotate",
        KmsSamplesIT.expectation("pykmip", py, ProtocolVersion.V1_4, "A5 LifecycleRotation"));
    assertEquals(
        "SERVER_LIMITATION",
        KmsSamplesIT.expectation("pykmip", py, ProtocolVersion.V1_4, "A6 CertificateStorage"));
    assertTrue(
        KmsSamplesIT.limitation("pykmip", py, "A6 CertificateStorage", certificateFailure())
            .isPresent());
    assertEquals(
        "UNSUPPORTED:asPublicKey",
        KmsSamplesIT.expectation("pqctoday", pqc, ProtocolVersion.V3_0, "A4 RemoteSignVerify"));
    assertTrue(
        KmsSamplesIT.limitation(
                "pqctoday", pqc, "A6 CertificateStorage", pqctodayCertificateFailure())
            .isPresent());
    // Narrowed: the message before the check of the reply's object, another operation, or
    // another exception type is not excused.
    for (String other :
        List.of(
            "dev.keytend.kmip.kms.ProtocolViolationException: asCertificate x: invalid response:"
                + " ResponsePayload missing Certificate",
            pqctodayCertificateFailure().replace("asCertificate", "asPublicKey"),
            pqctodayCertificateFailure()
                .replace("ProtocolViolationException", "OutcomeUnknownException"),
            pqctodayCertificateFailure() + " <- java.io.IOException: more"))
      assertEquals(
          Optional.empty(),
          KmsSamplesIT.limitation("pqctoday", pqc, "A6 CertificateStorage", other),
          other);
  }

  /**
   * A rebuilt server (other image layers for PyKMIP, another executable or fixture configuration
   * for PQCToday) is expected to pass: a limitation it still has is a FAIL, not silently excused.
   */
  @Test
  void aRebuiltServerTurnsItsLimitationsOff() {
    for (var c :
        Map.of(
                "A5 LifecycleRotation", ProtocolVersion.V1_4,
                "A6 CertificateStorage", ProtocolVersion.V1_2)
            .entrySet()) {
      String expected = KmsSamplesIT.expectation("pykmip", REBUILT_IMAGE, c.getValue(), c.getKey());
      assertTrue(expected.startsWith("PASS (the "), c.getKey() + ": " + expected);
      assertTrue(expected.contains(KmsSamplesIT.PYKMIP_BUILD), expected);
      // The sample passing on the rebuilt server is what the rule now expects
      // (before, "PASS (the ... rule is off ...)" never equaled "PASS").
      assertEquals(
          Optional.empty(),
          KmsSamplesIT.mismatch(
              "pykmip",
              REBUILT_IMAGE,
              c.getValue(),
              new KmsSamplesIT.Outcome(c.getKey(), "PASS", "", "")));
      assertTrue(
          KmsSamplesIT.mismatch(
                  "pykmip",
                  REBUILT_IMAGE,
                  c.getValue(),
                  new KmsSamplesIT.Outcome(c.getKey(), "SERVER_LIMITATION", "", ""))
              .isPresent());
    }
    assertEquals(
        Optional.empty(),
        KmsSamplesIT.limitation(
            "pykmip", REBUILT_IMAGE, "A6 CertificateStorage", certificateFailure()));
    String executable = KmsSamplesIT.PQCTODAY_BUILD.split(":")[1];
    for (String rebuilt :
        new String[] {
          "binary:" + "2".repeat(64) + ":" + KmsSamplesIT.PQCTODAY_BUILD.split(":")[2],
          "binary:" + executable + ":" + "3".repeat(64)
        }) {
      assertTrue(
          KmsSamplesIT.expectation("pqctoday", rebuilt, ProtocolVersion.V3_0, "A4 RemoteSignVerify")
              .startsWith("PASS"),
          rebuilt);
      assertEquals(
          Optional.empty(),
          KmsSamplesIT.limitation(
              "pqctoday", rebuilt, "A6 CertificateStorage", pqctodayCertificateFailure()));
    }
    // An outcome a rebuilt server still produces is then reported as a mismatch.
    var stillUnsupported =
        new KmsSamplesIT.Outcome(
            "A5 LifecycleRotation", "UNSUPPORTED", "Operation Not Supported", "rotate");
    assertTrue(
        KmsSamplesIT.mismatch("pykmip", REBUILT_IMAGE, ProtocolVersion.V1_4, stillUnsupported)
            .isPresent());
    assertTrue(
        KmsSamplesIT.mismatch(
                "pykmip", KmsSamplesIT.PYKMIP_BUILD, ProtocolVersion.V1_4, stillUnsupported)
            .isEmpty());
  }

  /** The SDK's own version refusals do not depend on the server build. */
  @Test
  void sdkVersionRefusalsHoldOnAnyBuild() {
    // seal names itself (A2, and the quickstart Q); A3 still reaches encrypt directly.
    assertEquals(
        "UNSUPPORTED:seal",
        KmsSamplesIT.expectation(
            "pykmip", REBUILT_IMAGE, ProtocolVersion.V1_2, "A2 EnvelopeEncryption"));
    assertEquals(
        "UNSUPPORTED:seal",
        KmsSamplesIT.expectation("pykmip", REBUILT_IMAGE, ProtocolVersion.V1_2, "Q Quickstart"));
    assertEquals(
        "UNSUPPORTED:encrypt",
        KmsSamplesIT.expectation("pykmip", REBUILT_IMAGE, ProtocolVersion.V1_2, "A3 RemoteAead"));
    // From 1.4, A2's non-extractable KEK is a limitation of the diagnosed build only.
    String rebuilt =
        KmsSamplesIT.expectation(
            "pykmip", REBUILT_IMAGE, ProtocolVersion.V1_4, "A2 EnvelopeEncryption");
    assertTrue(rebuilt.startsWith("PASS (the SERVER_LIMITATION rule is off"), rebuilt);
  }

  /**
   * Sample A2's non-extractable KEK is excused on the diagnosed PyKMIP and PQCToday builds
   * only for exactly the failure recorded there; another failure of A2 is a FAIL.
   */
  @Test
  void theExtractableLimitationsMatchOnlyTheObservedFailures() {
    String sample = "A2 EnvelopeEncryption";
    assertEquals(
        "SERVER_LIMITATION",
        KmsSamplesIT.expectation(
            "pykmip", KmsSamplesIT.PYKMIP_BUILD, ProtocolVersion.V1_4, sample));
    assertEquals(
        "SERVER_LIMITATION",
        KmsSamplesIT.expectation(
            "pqctoday", KmsSamplesIT.PQCTODAY_BUILD, ProtocolVersion.V3_0, sample));
    assertTrue(
        KmsSamplesIT.limitation(
                "pykmip",
                KmsSamplesIT.PYKMIP_BUILD,
                sample,
                KmsSamplesIT.PYKMIP_EXTRACTABLE_FAILURE)
            .isPresent());
    String pq =
        "dev.keytend.kmip.kms.PartialCompletionException: findOrCreate: created [urn:pqctoday:obj:0f09], then the"
            + " server did not keep the protection asked: findOrCreate: urn:pqctoday:obj:0f09 was made with Extractable"
            + " false, but its Extractable is true, not false; do not activate or use it <- dev.keytend.kmip.kms.KeyMismatchException:"
            + " findOrCreate: urn:pqctoday:obj:0f09 was made with Extractable false, but its Extractable is true, not false";
    assertTrue(
        KmsSamplesIT.limitation("pqctoday", KmsSamplesIT.PQCTODAY_BUILD, sample, pq).isPresent());
    for (String other :
        List.of(
            KmsSamplesIT.PYKMIP_EXTRACTABLE_FAILURE.replace(
                "InvalidField (0x00000007)", "PermissionDenied (0x00000002)"),
            pq.replace("Extractable", "Sensitive"),
            "dev.keytend.kmip.kms.ServerFailureException: findOrCreate failed"))
      assertTrue(
          KmsSamplesIT.limitation("pykmip", KmsSamplesIT.PYKMIP_BUILD, sample, other).isEmpty()
              && KmsSamplesIT.limitation("pqctoday", KmsSamplesIT.PQCTODAY_BUILD, sample, other)
                  .isEmpty(),
          other);
  }

  /**
   * The PyKMIP A6 limitation excuses exactly the failure recorded on the diagnosed build
   * (integration/reports/kms-samples-pykmip-1.2 and -1.4), not any Register General Failure: a
   * failure that differs in reason, operation, exception or cause is a FAIL.
   */
  @Test
  void thePykmipCertificateLimitationMatchesOnlyTheObservedFailure() {
    String py = KmsSamplesIT.PYKMIP_BUILD, sample = "A6 CertificateStorage";
    String observed = certificateFailure();
    assertTrue(KmsSamplesIT.limitation("pykmip", py, sample, observed).isPresent());
    for (String other :
        java.util.List.of(
            observed.replace("GeneralFailure (0x00000100)", "InvalidField (0x00000007)"),
            observed.replace("KMIP Register", "KMIP Get"),
            observed.replace("ServerFailureException", "OutcomeUnknownException"),
            observed.substring(0, observed.indexOf(" <- ")),
            observed + " <- java.io.IOException: closed",
            "PREFIX " + observed,
            // Another server message, or none: not the failure diagnosed.
            observed.replace(
                "Operation failed. See the server logs",
                "Certificate store full. See the server logs"),
            observed.replace(
                " (server message: \"Operation failed. See the server logs for more information.\")",
                ""),
            // What the earlier pattern (.*Register returned OperationFailed.*GeneralFailure.*)
            // also accepted:
            "KmsException: Register returned OperationFailed (GeneralFailure)",
            "dev.keytend.kmip.kms.KeyMismatchException: asCertificate: Register returned"
                + " OperationFailed after GeneralFailure"))
      assertEquals(Optional.empty(), KmsSamplesIT.limitation("pykmip", py, sample, other), other);
  }

  /** The chain sample A6 recorded on {@link KmsSamplesIT#PQCTODAY_BUILD} (KMIP 3.0). */
  private static String pqctodayCertificateFailure() {
    return "dev.keytend.kmip.kms.ProtocolViolationException: asCertificate"
        + " urn:pqctoday:obj:99f2eb96-6d66-4767-bcb6-846b5c00d479: invalid response: Get response object"
        + " does not match its ObjectType <- dev.keytend.kmip.client.ProtocolException: Get response"
        + " object does not match its ObjectType";
  }

  /**
   * The chain sample A6 records on {@link KmsSamplesIT#PYKMIP_BUILD} (KMIP 1.2 and 1.4), with the
   * server's message the SDK's message ends with.
   */
  private static String certificateFailure() {
    return "dev.keytend.kmip.kms.ServerFailureException: registerPreActive failed: KMIP Register"
        + " returned OperationFailed (1), reason GeneralFailure (0x00000100)"
        + " (server message: \"Operation failed. See the server logs for more information.\") <-"
        + " dev.keytend.kmip.client.KmipException: KMIP Register returned OperationFailed (1),"
        + " reason GeneralFailure (0x00000100)";
  }
}
