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
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * The interop suites' SERVER_LIMITATION rules (PQC-EXPORT-OBJECT, the other PQCToday rules and
 * the PyKMIP rules) hold only on the server they were diagnosed on, for the version, check and
 * exact message they were seen with. Runs without containers.
 */
class InteropLimitationTest {
  private static final String EXPORT = "Export response missing its object";

  @Test
  void pqctodayExportLimitationHoldsOnlyOnItsServerVersionCheckAndMessage() {
    var v = ProtocolVersion.V3_0;
    assertTrue(ModernInteropSuite.pqctodayExportWithoutObject("pqctoday", v, "Export", EXPORT));
    for (ProtocolVersion other :
        List.of(ProtocolVersion.V1_4, ProtocolVersion.V2_0, ProtocolVersion.V2_1))
      assertFalse(
          ModernInteropSuite.pqctodayExportWithoutObject("pqctoday", other, "Export", EXPORT),
          other + ": seen on 3.0 only");
    for (String other : List.of("pykmip", "keytend-kmip-server", "krypton"))
      assertFalse(
          ModernInteropSuite.pqctodayExportWithoutObject(other, v, "Export", EXPORT), other);
    assertFalse(
        ModernInteropSuite.pqctodayExportWithoutObject("pqctoday", v, "Get", EXPORT),
        "another check");
    for (String other : List.of("Get response missing its object", EXPORT + " (and more)", ""))
      assertFalse(
          ModernInteropSuite.pqctodayExportWithoutObject("pqctoday", v, "Export", other), other);
  }

  @Test
  void pqctodayImportMeetsTheSameExportReplyOnly() {
    assertTrue(
        ModernInteropSuite.pqctodayExportWithoutObject(
            "pqctoday", ProtocolVersion.V3_0, "Import", EXPORT));
    assertFalse(
        ModernInteropSuite.pqctodayExportWithoutObject(
            "pqctoday", ProtocolVersion.V3_0, "ReKey", EXPORT));
  }

  @Test
  void pqctodayAsyncAdjustAndUsageLimitationsHoldOnlyOnItsServerVersionCheckReasonAndMessage() {
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
          ModernInteropSuite.pqctodayLimitation("pqctoday", v, c.check(), c.reason(), c.message());
      assertNotNull(label, c.check());
      assertTrue(label.startsWith(c.label()), label);
      assertNull(
          ModernInteropSuite.pqctodayLimitation(
              "pqctoday", ProtocolVersion.V2_1, c.check(), c.reason(), c.message()));
      for (String other : List.of("pykmip", "keytend-kmip-server", "krypton"))
        assertNull(
            ModernInteropSuite.pqctodayLimitation(other, v, c.check(), c.reason(), c.message()),
            other);
      assertNull(
          ModernInteropSuite.pqctodayLimitation(
              "pqctoday", v, "Another check", c.reason(), c.message()));
      assertNull(
          ModernInteropSuite.pqctodayLimitation("pqctoday", v, c.check(), 0x01, c.message()));
      assertNull(
          ModernInteropSuite.pqctodayLimitation(
              "pqctoday", v, c.check(), c.reason(), c.message() + " (and more)"));
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
    assertTrue(InteropSuite.pykmipContactInformation("pykmip", ProtocolVersion.V1_4, refused));
    for (String other : List.of("pqctoday", "keytend-kmip-server", "krypton"))
      assertFalse(
          InteropSuite.pykmipContactInformation(other, ProtocolVersion.V1_4, refused), other);
    assertFalse(InteropSuite.pykmipContactInformation("pykmip", ProtocolVersion.V1_2, refused));
    assertFalse(
        InteropSuite.pykmipContactInformation(
            "pykmip",
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
}
