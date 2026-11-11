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
import java.util.Optional;
import org.junit.jupiter.api.Test;

/**
 * {@link KmsSamplesIT}'s server-specific expectations (UNSUPPORTED and SERVER_LIMITATION) are
 * each backed by a limitation or an SDK refusal, and a limitation holds only on its server, for
 * its sample and the exact failure seen there. Runs without containers.
 */
class KmsSamplesLimitationTest {
  static {
    // KmsSamplesIT reads this when it loads.
    if (System.getProperty("project.root") == null)
      System.setProperty("project.root", Path.of("..").toAbsolutePath().normalize().toString());
  }

  @Test
  void everyServerSpecificExpectationIsBacked() {
    for (var server : KmsSamplesIT.versions().entrySet())
      for (ProtocolVersion version : server.getValue())
        for (var cell : KmsSamplesIT.EXPECTED.get(server.getKey() + " " + version).entrySet()) {
          String value = cell.getValue();
          String where = server.getKey() + " " + version + " " + cell.getKey() + ": " + value;
          assertEquals(
              value,
              assertDoesNotThrow(
                  () -> KmsSamplesIT.expectation(server.getKey(), version, cell.getKey()), where),
              where);
          if (value.equals("PASS")) continue;
          ProtocolVersion lifted = KmsSamplesIT.SDK_REFUSALS.get(value);
          boolean sdk = lifted != null && !version.atLeast(lifted);
          boolean limitation =
              KmsSamplesIT.LIMITATIONS.stream()
                  .anyMatch(
                      l ->
                          l.server().equals(server.getKey())
                              && l.sample().equals(cell.getKey())
                              && l.expected().equals(value));
          assertTrue(sdk || limitation, where);
        }
  }

  @Test
  void theLimitationsHoldOnTheirServer() {
    assertEquals(
        "UNSUPPORTED:rotate",
        KmsSamplesIT.expectation("pykmip", ProtocolVersion.V1_4, "A5 LifecycleRotation"));
    assertEquals(
        "SERVER_LIMITATION",
        KmsSamplesIT.expectation("pykmip", ProtocolVersion.V1_4, "A6 CertificateStorage"));
    assertTrue(
        KmsSamplesIT.limitation("pykmip", "A6 CertificateStorage", certificateFailure())
            .isPresent());
    assertEquals(
        "UNSUPPORTED:asPublicKey",
        KmsSamplesIT.expectation("pqctoday", ProtocolVersion.V3_0, "A4 RemoteSignVerify"));
    assertTrue(
        KmsSamplesIT.limitation("pqctoday", "A6 CertificateStorage", pqctodayCertificateFailure())
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
          KmsSamplesIT.limitation("pqctoday", "A6 CertificateStorage", other),
          other);
  }

  /**
   * A limitation excuses its own server and sample only: the same failure on another server, or
   * from another sample, is a FAIL, and an outcome the table does not expect at this version is a
   * mismatch.
   */
  @Test
  void aLimitationMatchesOnlyItsServerSampleAndVersion() {
    String sample = "A6 CertificateStorage";
    for (String other : List.of("pqctoday", "keytend-kmip-server", "krypton"))
      assertEquals(
          Optional.empty(), KmsSamplesIT.limitation(other, sample, certificateFailure()), other);
    for (String other : List.of("pykmip", "keytend-kmip-server", "krypton"))
      assertEquals(
          Optional.empty(),
          KmsSamplesIT.limitation(other, sample, pqctodayCertificateFailure()),
          other);
    assertEquals(
        Optional.empty(),
        KmsSamplesIT.limitation("pykmip", "A5 LifecycleRotation", certificateFailure()));
    var unsupported =
        new KmsSamplesIT.Outcome(
            "A5 LifecycleRotation", "UNSUPPORTED", "Operation Not Supported", "rotate");
    assertEquals(
        Optional.empty(), KmsSamplesIT.mismatch("pykmip", ProtocolVersion.V1_4, unsupported));
    // At 1.2 the table expects the SDK to refuse AES-GCM, so a Re-key refusal there is a mismatch.
    assertTrue(KmsSamplesIT.mismatch("pykmip", ProtocolVersion.V1_2, unsupported).isPresent());
    // An unexpected pass is a mismatch too: update the table deliberately.
    assertTrue(
        KmsSamplesIT.mismatch(
                "pykmip",
                ProtocolVersion.V1_4,
                new KmsSamplesIT.Outcome("A5 LifecycleRotation", "PASS", "", ""))
            .isPresent());
    // A server without a row has no expectation.
    assertTrue(
        KmsSamplesIT.mismatch(
                "krypton",
                ProtocolVersion.V1_4,
                new KmsSamplesIT.Outcome("A5 LifecycleRotation", "PASS", "", ""))
            .isPresent());
  }

  /** The SDK's own version refusals do not depend on the server. */
  @Test
  void sdkVersionRefusalsHoldAtTheirVersion() {
    // seal names itself (A2, and the quickstart Q); A3 still reaches encrypt directly.
    assertEquals(
        "UNSUPPORTED:seal",
        KmsSamplesIT.expectation("pykmip", ProtocolVersion.V1_2, "A2 EnvelopeEncryption"));
    assertEquals(
        "UNSUPPORTED:seal",
        KmsSamplesIT.expectation("pykmip", ProtocolVersion.V1_2, "Q Quickstart"));
    assertEquals(
        "UNSUPPORTED:encrypt",
        KmsSamplesIT.expectation("pykmip", ProtocolVersion.V1_2, "A3 RemoteAead"));
    // From 1.4, A2's non-extractable KEK is a limitation of the server, not an SDK refusal.
    assertEquals(
        "SERVER_LIMITATION",
        KmsSamplesIT.expectation("pykmip", ProtocolVersion.V1_4, "A2 EnvelopeEncryption"));
  }

  /**
   * Sample A2's non-extractable KEK is excused on PyKMIP and PQCToday only for exactly the failure
   * recorded there; another failure of A2 is a FAIL.
   */
  @Test
  void theExtractableLimitationsMatchOnlyTheObservedFailures() {
    String sample = "A2 EnvelopeEncryption";
    assertEquals(
        "SERVER_LIMITATION", KmsSamplesIT.expectation("pykmip", ProtocolVersion.V1_4, sample));
    assertEquals(
        "SERVER_LIMITATION", KmsSamplesIT.expectation("pqctoday", ProtocolVersion.V3_0, sample));
    assertTrue(
        KmsSamplesIT.limitation("pykmip", sample, KmsSamplesIT.PYKMIP_EXTRACTABLE_FAILURE)
            .isPresent());
    String pq =
        "dev.keytend.kmip.kms.PartialCompletionException: findOrCreate: created [urn:pqctoday:obj:0f09], then the"
            + " server did not keep the protection asked: findOrCreate: urn:pqctoday:obj:0f09 was made with Extractable"
            + " false, but its Extractable is true, not false; do not activate or use it <- dev.keytend.kmip.kms.KeyMismatchException:"
            + " findOrCreate: urn:pqctoday:obj:0f09 was made with Extractable false, but its Extractable is true, not false";
    assertTrue(KmsSamplesIT.limitation("pqctoday", sample, pq).isPresent());
    for (String other :
        List.of(
            KmsSamplesIT.PYKMIP_EXTRACTABLE_FAILURE.replace(
                "InvalidField (0x00000007)", "PermissionDenied (0x00000002)"),
            pq.replace("Extractable", "Sensitive"),
            "dev.keytend.kmip.kms.ServerFailureException: findOrCreate failed"))
      assertTrue(
          KmsSamplesIT.limitation("pykmip", sample, other).isEmpty()
              && KmsSamplesIT.limitation("pqctoday", sample, other).isEmpty(),
          other);
  }

  /**
   * The PyKMIP A6 limitation excuses exactly the failure recorded on PyKMIP
   * (integration/reports/kms-samples-pykmip-1.2 and -1.4), not any Register General Failure: a
   * failure that differs in reason, operation, exception or cause is a FAIL.
   */
  @Test
  void thePykmipCertificateLimitationMatchesOnlyTheObservedFailure() {
    String sample = "A6 CertificateStorage";
    String observed = certificateFailure();
    assertTrue(KmsSamplesIT.limitation("pykmip", sample, observed).isPresent());
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
      assertEquals(Optional.empty(), KmsSamplesIT.limitation("pykmip", sample, other), other);
  }

  /** The chain sample A6 recorded on PQCToday (KMIP 3.0). */
  private static String pqctodayCertificateFailure() {
    return "dev.keytend.kmip.kms.ProtocolViolationException: asCertificate"
        + " urn:pqctoday:obj:99f2eb96-6d66-4767-bcb6-846b5c00d479: invalid response: Get response object"
        + " does not match its ObjectType <- dev.keytend.kmip.client.ProtocolException: Get response"
        + " object does not match its ObjectType";
  }

  /**
   * The chain sample A6 records on PyKMIP (KMIP 1.2 and 1.4), with the
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
