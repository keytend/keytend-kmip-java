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

  static final String ANOTHER_BUILD =
      "files:" + "1".repeat(64) + ":" + KmsSamplesIT.PYKMIP_BUILD.split(":")[2];

  private static final Path PROJECT =
      Path.of(System.getProperty("project.root")).toAbsolutePath().normalize();

  /** integration/catalog/qualified-images.properties, where the pins are recorded. */
  static java.util.Properties manifest() {
    var manifest = new java.util.Properties();
    try (var in =
        java.nio.file.Files.newInputStream(
            PROJECT.resolve("integration/catalog/qualified-images.properties"))) {
      manifest.load(in);
    } catch (java.io.IOException e) {
      throw new java.io.UncheckedIOException(e);
    }
    return manifest;
  }

  /**
   * The file list of the qualified build, as integration/pykmip/build-identity.py --list printed it
   * in that build's container ({@code pykmip.files.evidence} in the manifest), not a copy.
   */
  static String qualifiedFiles() throws java.io.IOException {
    return java.nio.file.Files.readString(
        PROJECT.resolve(manifest().getProperty("pykmip.files.evidence")));
  }

  static String sha256(String text) throws Exception {
    return java.util.HexFormat.of()
        .formatHex(
            java.security.MessageDigest.getInstance("SHA-256")
                .digest(text.getBytes(java.nio.charset.StandardCharsets.UTF_8)));
  }

  /**
   * The PyKMIP pin is the qualified build's files plus the fixture directory (which holds
   * server.py and sets the entrypoint, command and environment); changing any file, or the
   * fixture, changes it.
   */
  @Test
  void thePykmipPinIsTheQualifiedBuildsFiles() throws Exception {
    String configuration =
        CatalogContainersIT.digestDirectory(PROJECT.resolve("integration/pykmip"));
    String files = qualifiedFiles();
    assertEquals(
        KmsSamplesIT.PYKMIP_BUILD, KmsSamplesIT.files(sha256(files)) + ":" + configuration);
    assertEquals(configuration, manifest().getProperty("pykmip.configuration"), "the fixture");
    assertEquals(sha256(files), manifest().getProperty("pykmip.files"));
    assertTrue(files.startsWith("python 3.12.15\n"), files.lines().findFirst().orElse(""));
    assertTrue(files.contains("\ndist pykmip-0.12.0.dev0\n"));
    String engine = "(?m)^(kmip/services/server/engine\\.py  )[0-9a-f]{64}$";
    assertTrue(java.util.regex.Pattern.compile(engine).matcher(files).find(), "PyKMIP's engine");
    String changed = files.replaceFirst(engine, "$1" + "0".repeat(64));
    assertNotEquals(KmsSamplesIT.files(sha256(files)), KmsSamplesIT.files(sha256(changed)));
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
                              && l.identity().matches("(files|binary):[0-9a-f]{64}:[0-9a-f]{64}"));
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
   * Another server build (other installed files for PyKMIP, another executable for PQCToday, or
   * another fixture configuration) is expected to pass: a limitation it still has is a FAIL, not
   * silently excused.
   */
  @Test
  void aRebuiltServerTurnsItsLimitationsOff() {
    for (var c :
        Map.of(
                "A5 LifecycleRotation", ProtocolVersion.V1_4,
                "A6 CertificateStorage", ProtocolVersion.V1_2)
            .entrySet()) {
      String expected = KmsSamplesIT.expectation("pykmip", ANOTHER_BUILD, c.getValue(), c.getKey());
      assertTrue(expected.startsWith("PASS (the "), c.getKey() + ": " + expected);
      assertTrue(expected.contains(KmsSamplesIT.PYKMIP_BUILD), expected);
      // The sample passing on the rebuilt server is what the rule now expects
      // (before, "PASS (the ... rule is off ...)" never equaled "PASS").
      assertEquals(
          Optional.empty(),
          KmsSamplesIT.mismatch(
              "pykmip",
              ANOTHER_BUILD,
              c.getValue(),
              new KmsSamplesIT.Outcome(c.getKey(), "PASS", "", "")));
      assertTrue(
          KmsSamplesIT.mismatch(
                  "pykmip",
                  ANOTHER_BUILD,
                  c.getValue(),
                  new KmsSamplesIT.Outcome(c.getKey(), "SERVER_LIMITATION", "", ""))
              .isPresent());
    }
    assertEquals(
        Optional.empty(),
        KmsSamplesIT.limitation(
            "pykmip", ANOTHER_BUILD, "A6 CertificateStorage", certificateFailure()));
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
        KmsSamplesIT.mismatch("pykmip", ANOTHER_BUILD, ProtocolVersion.V1_4, stillUnsupported)
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
            "pykmip", ANOTHER_BUILD, ProtocolVersion.V1_2, "A2 EnvelopeEncryption"));
    assertEquals(
        "UNSUPPORTED:seal",
        KmsSamplesIT.expectation("pykmip", ANOTHER_BUILD, ProtocolVersion.V1_2, "Q Quickstart"));
    assertEquals(
        "UNSUPPORTED:encrypt",
        KmsSamplesIT.expectation("pykmip", ANOTHER_BUILD, ProtocolVersion.V1_2, "A3 RemoteAead"));
    // From 1.4, A2's non-extractable KEK is a limitation of the diagnosed build only.
    String rebuilt =
        KmsSamplesIT.expectation(
            "pykmip", ANOTHER_BUILD, ProtocolVersion.V1_4, "A2 EnvelopeEncryption");
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
