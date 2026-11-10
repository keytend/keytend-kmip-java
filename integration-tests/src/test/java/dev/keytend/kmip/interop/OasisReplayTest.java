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

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.codec.XmlCodec;
import dev.keytend.kmip.model.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class OasisReplayTest {
  @TempDir Path directory;

  @Test
  void unsupportedSuccessPayloadDoesNotLeaveUnboundBinaryVariables() throws Exception {
    fixture();
    var replay =
        new OasisReplay(
            request ->
                response(1, enumeration(RESULT_REASON, Enums.ResultReason.OPERATION_NOT_SUPPORTED)),
            ProtocolVersion.V1_4);
    var result = replay.runAll(directory).get(0);
    assertEquals("UNSUPPORTED", result.outcome());
    assertTrue(result.detail().contains("reason=5"));
  }

  @Test
  void missingFieldsAreReportedBeforeUnboundVariablesAreDecoded() throws Exception {
    fixture();
    var replay =
        new OasisReplay(
            request -> response(0, structure(RESPONSE_PAYLOAD, text(UNIQUE_IDENTIFIER, "key"))),
            ProtocolVersion.V1_4);
    var result = replay.runAll(directory).get(0);
    assertEquals("FAIL", result.outcome());
    assertEquals("Missing response field Data", result.detail());
  }

  @Test
  void publishedOpaqueServerCorrelationStringsAreBound() throws Exception {
    fixture();
    Path file = directory.resolve("scenario.xml");
    String text =
        Files.readString(file)
            .replace(
                "</ResponseHeader>",
                "<ServerCorrelationValue type=\"TextString\""
                    + " value=\"published-example\"/></ResponseHeader>");
    Files.writeString(file, text);
    var replay =
        new OasisReplay(
            request -> {
              Ttlv r = response(0, structure(RESPONSE_PAYLOAD, bytes(DATA, new byte[] {1, 2})));
              var header = new java.util.ArrayList<>(r.require(RESPONSE_HEADER).children());
              header.add(text(SERVER_CORRELATION_VALUE, "actual-opaque-correlation"));
              return structure(
                  RESPONSE_MESSAGE, structure(RESPONSE_HEADER, header), r.require(BATCH_ITEM));
            },
            ProtocolVersion.V1_4);
    assertEquals("PASS", replay.runAll(directory).get(0).outcome());
  }

  @Test
  void optionalResultMessagesMayBeOmittedOrDifferButReasonsRemainRequired() throws Exception {
    for (String message : new String[] {null, "Different vendor diagnostic"}) {
      fixture();
      Path file = directory.resolve("scenario.xml");
      Files.writeString(
          file,
          Files.readString(file)
              .replace("value=\"Success\"", "value=\"OperationFailed\"")
              .replaceAll(
                  "(?s)<ResponsePayload>.*?</ResponsePayload>",
                  "<ResultReason type=\"Enumeration\" value=\"InvalidField\"/><ResultMessage"
                      + " type=\"TextString\" value=\"Published diagnostic\"/>"));
      var replay =
          new OasisReplay(
              request -> {
                Ttlv r = response(1, enumeration(RESULT_REASON, Enums.ResultReason.INVALID_FIELD));
                var fields = new java.util.ArrayList<>(r.require(BATCH_ITEM).children());
                if (message != null) fields.add(text(RESULT_MESSAGE, message));
                return structure(
                    RESPONSE_MESSAGE, r.require(RESPONSE_HEADER), structure(BATCH_ITEM, fields));
              },
              ProtocolVersion.V1_4);
      assertEquals("PASS", replay.runAll(directory).get(0).outcome());
    }
    var missingReason =
        new OasisReplay(
            request -> response(1, text(RESULT_MESSAGE, "Required reason absent")),
            ProtocolVersion.V1_4);
    assertEquals(
        "Missing response field ResultReason", missingReason.runAll(directory).get(0).detail());
  }

  @Test
  void generatedDigestsMayVaryWhileRegisteredDigestsRemainExact() throws Exception {
    for (boolean generated : new boolean[] {true, false}) {
      digestFixture(generated, 1);
      var calls = new java.util.concurrent.atomic.AtomicInteger();
      var replay =
          new OasisReplay(
              request -> {
                int call = calls.getAndIncrement();
                Ttlv r = digestResponse(call, 32, (byte) 1);
                return !generated && call == 0 ? operation(r, Operation.REGISTER) : r;
              },
              ProtocolVersion.V1_4);
      var result = replay.runAll(directory).get(0);
      assertEquals(generated ? "PASS" : "FAIL", result.outcome());
      if (!generated) assertEquals("Value mismatch for DigestValue", result.detail());
    }
  }

  @Test
  void generatedDigestLengthAndConsistencyStillFailWhenInvalid() throws Exception {
    digestFixture(true, 1);
    var calls = new java.util.concurrent.atomic.AtomicInteger();
    var truncated =
        new OasisReplay(
            request -> digestResponse(calls.getAndIncrement(), 31, (byte) 1), ProtocolVersion.V1_4);
    assertEquals(
        "Invalid SHA-256 generated digest length", truncated.runAll(directory).get(0).detail());
    digestFixture(true, 2);
    calls.set(0);
    var changed =
        new OasisReplay(
            request -> {
              int call = calls.getAndIncrement();
              return digestResponse(call, 32, (byte) call);
            },
            ProtocolVersion.V1_4);
    assertEquals("Value mismatch for DigestValue", changed.runAll(directory).get(0).detail());
  }

  private Ttlv operation(Ttlv response, Operation operation) {
    return structure(
        RESPONSE_MESSAGE,
        response.require(RESPONSE_HEADER),
        structure(
            BATCH_ITEM,
            response.require(BATCH_ITEM).children().stream()
                .map(n -> n.tag() == OPERATION.code() ? enumeration(OPERATION, operation) : n)
                .toList()));
  }

  private Ttlv digestResponse(int call, int length, byte fill) {
    byte[] bytes = new byte[length];
    java.util.Arrays.fill(bytes, fill);
    Ttlv payload =
        call == 0
            ? structure(RESPONSE_PAYLOAD, text(UNIQUE_IDENTIFIER, "generated-key"))
            : structure(
                RESPONSE_PAYLOAD,
                text(UNIQUE_IDENTIFIER, "generated-key"),
                structure(
                    ATTRIBUTE,
                    text(ATTRIBUTE_NAME, "Digest"),
                    structure(
                        ATTRIBUTE_VALUE,
                        enumeration(HASHING_ALGORITHM, Enums.HashingAlgorithm.SHA_256),
                        bytes(DIGEST_VALUE, bytes))));
    return structure(
        RESPONSE_MESSAGE,
        structure(
            RESPONSE_HEADER,
            Messages.protocolVersion(ProtocolVersion.V1_4),
            dateTime(TIME_STAMP, Instant.ofEpochSecond(1700000000)),
            integer(BATCH_COUNT, 1)),
        structure(
            BATCH_ITEM,
            enumeration(OPERATION, call == 0 ? Operation.CREATE : Operation.GET_ATTRIBUTES),
            enumeration(RESULT_STATUS, 0),
            payload));
  }

  private void digestFixture(boolean generated, int reads) throws Exception {
    var codec = new XmlCodec();
    var initial =
        Messages.request(
            ProtocolVersion.V1_4,
            List.of(
                generated
                    ? Requests.createSymmetricKey(
                        Enums.CryptographicAlgorithm.AES, 128, Enums.CryptographicUsageMask.ENCRYPT)
                    : Requests.registerObject(
                        ManagedObjects.rawSymmetricKey(
                            new byte[16], Enums.CryptographicAlgorithm.AES))),
            RequestOptions.DEFAULT);
    StringBuilder fixture = new StringBuilder("<KMIP>");
    fixture.append(new String(codec.encode(initial), StandardCharsets.UTF_8));
    Ttlv first = digestResponse(0, 32, (byte) 0);
    fixture.append(
        new String(
            codec.encode(generated ? first : operation(first, Operation.REGISTER)),
            StandardCharsets.UTF_8));
    for (int i = 0; i < reads; i++) {
      fixture.append(
          new String(
              codec.encode(
                  Messages.request(
                      ProtocolVersion.V1_4,
                      List.of(Requests.getAttributes().uniqueIdentifier("generated-key").build()),
                      RequestOptions.DEFAULT)),
              StandardCharsets.UTF_8));
      fixture.append(
          new String(codec.encode(digestResponse(1, 32, (byte) 0)), StandardCharsets.UTF_8));
    }
    Files.writeString(directory.resolve("scenario.xml"), fixture.append("</KMIP>").toString());
  }

  private void fixture() throws Exception {
    var request =
        Messages.request(
            ProtocolVersion.V1_4,
            List.of(Requests.get().uniqueIdentifier("key").build()),
            RequestOptions.DEFAULT);
    String expected =
        """
        <ResponseMessage><ResponseHeader>
        <ProtocolVersion><ProtocolVersionMajor type="Integer" value="1"/>
        <ProtocolVersionMinor type="Integer" value="4"/></ProtocolVersion>
        <TimeStamp type="DateTime" value="$NOW"/><BatchCount type="Integer" value="1"/>
        </ResponseHeader><BatchItem><Operation type="Enumeration" value="Get"/>
        <ResultStatus type="Enumeration" value="Success"/>
        <ResponsePayload><Data type="ByteString" value="$DATA"/></ResponsePayload>
        </BatchItem></ResponseMessage>
        """;
    Files.writeString(
        directory.resolve("scenario.xml"),
        "<KMIP>"
            + new String(new XmlCodec().encode(request), StandardCharsets.UTF_8)
            + expected
            + "</KMIP>");
  }

  private Ttlv response(int status, Ttlv field) {
    return structure(
        RESPONSE_MESSAGE,
        structure(
            RESPONSE_HEADER,
            Messages.protocolVersion(ProtocolVersion.V1_4),
            dateTime(TIME_STAMP, Instant.ofEpochSecond(1700000000)),
            integer(BATCH_COUNT, 1)),
        structure(
            BATCH_ITEM,
            enumeration(OPERATION, Operation.GET),
            enumeration(RESULT_STATUS, status),
            field));
  }
}
