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
import org.junit.jupiter.api.Test;

/**
 * The interop suites' SERVER_LIMITATION rules (PQC-EXPORT-OBJECT, the other PQCToday rules and
 * the PyKMIP rules) hold only on the server build they were diagnosed on, for the version, check
 * and exact message they were seen with. Runs without containers.
 */
class InteropLimitationPinningTest {
  static {
    // KmsSamplesIT and CatalogContainersIT read this when they load.
    if (System.getProperty("project.root") == null)
      System.setProperty("project.root", Path.of("..").toAbsolutePath().normalize().toString());
  }

  private static final String EXPORT = "Export response missing its object";

  /**
   * The configuration part of each pin is today's fixture, so the default run applies them, and
   * the samples use the same PQCToday build.
   */
  @Test
  void thePinsAreTheDiagnosedBuilds() throws Exception {
    Path root = Path.of(System.getProperty("project.root")).toAbsolutePath().normalize();
    assertEquals(KmsSamplesIT.PQCTODAY_BUILD, InteropSuite.PQCTODAY_BUILD);
    assertEquals(
        CatalogContainersIT.digestDirectory(root.resolve("integration/pqctoday")),
        InteropSuite.PQCTODAY_BUILD.split(":")[2],
        "integration/pqctoday is the diagnosed configuration");
  }

  @Test
  void pqctodayExportLimitationHoldsOnlyOnTheDiagnosedBuildVersionCheckAndMessage() {
    String build = InteropSuite.PQCTODAY_BUILD;
    var v = ProtocolVersion.V3_0;
    assertTrue(
        ModernInteropSuite.pqctodayExportWithoutObject("pqctoday", build, v, "Export", EXPORT));
    for (ProtocolVersion other :
        List.of(ProtocolVersion.V1_4, ProtocolVersion.V2_0, ProtocolVersion.V2_1))
      assertFalse(
          ModernInteropSuite.pqctodayExportWithoutObject(
              "pqctoday", build, other, "Export", EXPORT),
          other + ": seen on 3.0 only");
    for (String other : rebuilt(build))
      assertFalse(
          ModernInteropSuite.pqctodayExportWithoutObject("pqctoday", other, v, "Export", EXPORT),
          other);
    assertFalse(
        ModernInteropSuite.pqctodayExportWithoutObject("pykmip", build, v, "Export", EXPORT));
    assertFalse(
        ModernInteropSuite.pqctodayExportWithoutObject("pqctoday", build, v, "Get", EXPORT),
        "another check");
    for (String other : List.of("Get response missing its object", EXPORT + " (and more)", ""))
      assertFalse(
          ModernInteropSuite.pqctodayExportWithoutObject("pqctoday", build, v, "Export", other),
          other);
  }

  @Test
  void pqctodayImportMeetsTheSameExportReplyOnly() {
    String build = InteropSuite.PQCTODAY_BUILD;
    assertTrue(
        ModernInteropSuite.pqctodayExportWithoutObject(
            "pqctoday", build, ProtocolVersion.V3_0, "Import", EXPORT));
    assertFalse(
        ModernInteropSuite.pqctodayExportWithoutObject(
            "pqctoday", build, ProtocolVersion.V3_0, "ReKey", EXPORT));
  }

  @Test
  void
      pqctodayAsyncAdjustAndUsageLimitationsHoldOnlyOnTheDiagnosedBuildVersionCheckReasonAndMessage() {
    String build = InteropSuite.PQCTODAY_BUILD;
    var v = ProtocolVersion.V3_0;
    String adjust =
        "KMIP InvalidMessage (0x00000004): unexpected item type for tag 0x420162 (Adjustment Value): expected Integer or LongInteger";
    String usage =
        "KMIP AttributeNotFound (0x00000021): UID \"urn:pqctoday:obj:1\" has no Usage Limits attribute";
    String cancel =
        "KMIP InvalidAsynchronousCorrelationValue (0x0000002b): unknown Asynchronous Correlation Value";
    record Case(String check, int reason, String message, String label) {}
    for (Case c :
        List.of(
            new Case("AdjustAttribute Deactivation Date", 0x04, adjust, "PQC-ADJUST-INTERVAL"),
            new Case("GetUsageAllocation", 0x21, usage, "PQC-USAGE-LIMITS"),
            new Case("Cancel unknown token", 0x2B, cancel, "PQC-CANCEL-UNKNOWN"))) {
      String label =
          ModernInteropSuite.pqctodayLimitation(
              "pqctoday", build, v, c.check(), c.reason(), c.message());
      assertNotNull(label, c.check());
      assertTrue(label.startsWith(c.label()), label);
      for (String other : rebuilt(build))
        assertNull(
            ModernInteropSuite.pqctodayLimitation(
                "pqctoday", other, v, c.check(), c.reason(), c.message()),
            other);
      assertNull(
          ModernInteropSuite.pqctodayLimitation(
              "pqctoday", build, ProtocolVersion.V2_1, c.check(), c.reason(), c.message()));
      assertNull(
          ModernInteropSuite.pqctodayLimitation(
              "pykmip", build, v, c.check(), c.reason(), c.message()));
      assertNull(
          ModernInteropSuite.pqctodayLimitation(
              "pqctoday", build, v, "Another check", c.reason(), c.message()));
      assertNull(
          ModernInteropSuite.pqctodayLimitation(
              "pqctoday", build, v, c.check(), 0x01, c.message()));
      assertNull(
          ModernInteropSuite.pqctodayLimitation(
              "pqctoday", build, v, c.check(), c.reason(), c.message() + " (and more)"));
    }
  }

  @Test
  void pykmipContactInformationAndParseFailureAreRecognizedExactly() {
    var refused =
        new dev.keytend.kmip.client.Result(
            dev.keytend.kmip.model.Operation.CREATE,
            1,
            0x07,
            "The Contact Information attribute is unsupported.",
            null);
    assertTrue(
        InteropSuite.pykmipContactInformation(
            "pykmip", InteropSuite.PYKMIP_BUILD, ProtocolVersion.V1_4, refused));
    assertFalse(
        InteropSuite.pykmipContactInformation(
            "pqctoday", InteropSuite.PYKMIP_BUILD, ProtocolVersion.V1_4, refused));
    assertFalse(
        InteropSuite.pykmipContactInformation(
            "pykmip", InteropSuite.PYKMIP_BUILD, ProtocolVersion.V1_2, refused));
    assertFalse(
        InteropSuite.pykmipContactInformation(
            "pykmip",
            "layers:" + "1".repeat(64) + ":" + InteropSuite.PYKMIP_BUILD.split(":")[2],
            ProtocolVersion.V1_4,
            refused),
        "another build");
    assertFalse(
        InteropSuite.pykmipContactInformation(
            "pykmip",
            InteropSuite.PYKMIP_BUILD,
            ProtocolVersion.V1_4,
            new dev.keytend.kmip.client.Result(
                dev.keytend.kmip.model.Operation.CREATE, 1, 0x07, "Another field.", null)));
    dev.keytend.kmip.model.Ttlv parse =
        reply(0, 4, "Error parsing request message. See server logs for more information.");
    assertTrue(InteropSuite.pykmipParseFailure(parse));
    assertFalse(
        InteropSuite.pykmipParseFailure(
            reply(4, 4, "Error parsing request message. See server logs for more information.")),
        "a 1.4 header");
    assertFalse(
        InteropSuite.pykmipParseFailure(
            reply(0, 7, "Error parsing request message. See server logs for more information.")));
    assertFalse(InteropSuite.pykmipParseFailure(reply(0, 4, "Something else")));
    assertFalse(InteropSuite.pykmipParseFailure(null));
  }

  private static dev.keytend.kmip.model.Ttlv reply(int minor, int reason, String message) {
    return dev.keytend.kmip.model.Ttlv.structure(
        dev.keytend.kmip.model.Tag.RESPONSE_MESSAGE,
        dev.keytend.kmip.model.Ttlv.structure(
            dev.keytend.kmip.model.Tag.RESPONSE_HEADER,
            dev.keytend.kmip.model.Ttlv.structure(
                dev.keytend.kmip.model.Tag.PROTOCOL_VERSION,
                dev.keytend.kmip.model.Ttlv.integer(
                    dev.keytend.kmip.model.Tag.PROTOCOL_VERSION_MAJOR, 1),
                dev.keytend.kmip.model.Ttlv.integer(
                    dev.keytend.kmip.model.Tag.PROTOCOL_VERSION_MINOR, minor))),
        dev.keytend.kmip.model.Ttlv.structure(
            dev.keytend.kmip.model.Tag.BATCH_ITEM,
            dev.keytend.kmip.model.Ttlv.enumeration(dev.keytend.kmip.model.Tag.RESULT_STATUS, 1),
            dev.keytend.kmip.model.Ttlv.enumeration(
                dev.keytend.kmip.model.Tag.RESULT_REASON, reason),
            dev.keytend.kmip.model.Ttlv.text(dev.keytend.kmip.model.Tag.RESULT_MESSAGE, message)));
  }

  /** Another executable, another fixture configuration, and a build that was not inspected. */
  private static List<String> rebuilt(String build) {
    String[] part = build.split(":");
    return List.of(
        "binary:" + "2".repeat(64) + ":" + part[2],
        "binary:" + part[1] + ":" + "3".repeat(64),
        InteropSuite.UNVERIFIED,
        "binary:unverified:" + part[2]);
  }
}
