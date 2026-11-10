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

import static dev.keytend.kmip.model.Enums.*;
import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import javax.net.ssl.*;

/**
 * Set Endpoint Role with Endpoint Role Client (2.0 section 6.1.48, 2.1 section 6.1.54) against a
 * server whose policy gives the principal a client endpoint in this version
 * (keytend-kmip-server: integration/keytend-kmip-server). After the server accepts, this program
 * takes the server role on the same channel: it answers the server's Discover Versions and Query
 * (2.1 sections 6.2.1, 6.2.4), receives the Put and Notify (6.2.2-6.2.3) for a key that a second
 * connection registers and changes, answers the server's own Set Endpoint Role that hands the channel back (6.2.5), and
 * then uses the channel as a client again. In draft 3.0, and in a version other than the
 * endpoint's, the request must be refused.
 *
 * <p>Responses go through the SDK's {@code CallbackMessages}; this application supplies the
 * operation-specific payloads and manages which role the channel takes.
 *
 * <p>Arguments: {@code <host> <port> <cert-directory> <2.0|2.1|3.0>}; the directory holds {@code
 * reverse-2.0.p12}, {@code reverse-2.1.p12} (password changeit) and {@code ca.pem}. Prints one
 * line per check and exits 1 when any fails.
 */
public final class EndpointRoleReversal {
  private static final TtlvCodec CODEC = new TtlvCodec();
  private final String host;
  private final int port;
  private final Path certificates;
  private final ProtocolVersion version;
  private int failures;

  private EndpointRoleReversal(String host, int port, Path certificates, ProtocolVersion version) {
    this.host = host;
    this.port = port;
    this.certificates = certificates;
    this.version = version;
  }

  public static void main(String[] args) throws Exception {
    if (args.length != 4) {
      System.err.println("Usage: EndpointRoleReversal <host> <port> <cert-directory> <version>");
      System.exit(2);
    }
    ProtocolVersion version = ProtocolVersion.valueOf("V" + args[3].replace('.', '_'));
    var run =
        new EndpointRoleReversal(args[0], Integer.parseInt(args[1]), Path.of(args[2]), version);
    run.run();
    System.out.println("SUMMARY " + version + " failures=" + run.failures);
    if (run.failures > 0) System.exit(1);
  }

  private void run() throws Exception {
    if (version == ProtocolVersion.V3_0) {
      // keytend-kmip-server has no draft 3.0 server-to-client delivery; client endpoints are
      // 1.0-2.1.
      refused("draft 3.0 reversal refused", "reverse-2.1");
      return;
    }
    refused(
        "reversal in another version than the endpoint's refused",
        version == ProtocolVersion.V2_0 ? "reverse-2.1" : "reverse-2.0");
    reverse("reverse-" + version);
  }

  private SSLContext tls(String principal) throws Exception {
    return Tls.context(
        certificates.resolve(principal + ".p12"),
        "changeit".toCharArray(),
        certificates.resolve("ca.pem"));
  }

  private SSLSocket connect(String principal) throws Exception {
    SSLSocket socket = (SSLSocket) tls(principal).getSocketFactory().createSocket(host, port);
    socket.setSoTimeout(150_000);
    socket.startHandshake();
    return socket;
  }

  private static Ttlv setEndpointRole(ProtocolVersion version, EndpointRole role) {
    return Messages.request(
        version,
        List.of(Requests.setEndpointRole().add(enumeration(ENDPOINT_ROLE, role)).build()),
        RequestOptions.DEFAULT);
  }

  private void refused(String name, String principal) throws Exception {
    try (SSLSocket socket = connect(principal)) {
      Result r = exchange(socket, setEndpointRole(version, EndpointRole.CLIENT));
      check(name, !r.successful() && r.hasReason(ResultReason.FEATURE_NOT_SUPPORTED), r.toString());
    }
  }

  private void reverse(String principal) throws Exception {
    try (SSLSocket channel = connect(principal);
        KmipClient other = new KmipClient(new TlsTransport(host, port, tls(principal)), version)) {
      InputStream in = new BufferedInputStream(channel.getInputStream());
      OutputStream out = channel.getOutputStream();
      Result accepted = exchange(channel, setEndpointRole(version, EndpointRole.CLIENT));
      check(
          "Set Endpoint Role Client accepted",
          accepted.successful()
              && accepted.requirePayload().require(ENDPOINT_ROLE).intValue()
                  == EndpointRole.CLIENT.code(),
          accepted.toString());
      if (!accepted.successful()) return;

      Ttlv discover = expect(in, Operation.DISCOVER_VERSIONS);
      // The offer may include editions the SDK does not speak (1.0), so compare numbers.
      List<String> offered = new ArrayList<>();
      for (Ttlv v :
          discover.require(BATCH_ITEM).require(REQUEST_PAYLOAD).children(PROTOCOL_VERSION))
        offered.add(
            v.require(PROTOCOL_VERSION_MAJOR).intValue()
                + "."
                + v.require(PROTOCOL_VERSION_MINOR).intValue());
      check(
          "server offers the endpoint version first",
          !offered.isEmpty() && offered.get(0).equals(version.toString()),
          offered.toString());
      reply(out, discover, structure(RESPONSE_PAYLOAD, Messages.protocolVersion(version)));
      Ttlv query = expect(in, Operation.QUERY);
      check(
          "server asks Query Operations",
          query.require(BATCH_ITEM).require(REQUEST_PAYLOAD).children(QUERY_FUNCTION).stream()
              .anyMatch(f -> f.intValue() == QueryFunction.QUERY_OPERATIONS.code()),
          query.toString());
      reply(
          out,
          query,
          structure(
              RESPONSE_PAYLOAD,
              enumeration(OPERATION, Operation.NOTIFY.code()),
              enumeration(OPERATION, Operation.PUT.code())));

      // A key the other connection registers is pushed with Put; a change to it with Notify.
      byte[] material = new byte[16];
      new java.security.SecureRandom().nextBytes(material);
      String id =
          other
              .call(
                  Requests.registerObject(
                      ManagedObjects.rawSymmetricKey(material, CryptographicAlgorithm.AES),
                      Attributes.usage(
                          CryptographicUsageMask.ENCRYPT, CryptographicUsageMask.DECRYPT)))
              .uniqueIdentifier();
      Ttlv put = expect(in, Operation.PUT);
      Ttlv putPayload = put.require(BATCH_ITEM).require(REQUEST_PAYLOAD);
      check(
          "Put of the registered key over the reversed channel",
          putPayload.require(UNIQUE_IDENTIFIER).textValue().equals(id)
              && Arrays.equals(material, InteropSuite.keyBytes(putPayload)),
          putPayload.toString());
      reply(out, put, null);
      other.call(
          Requests.addAttribute()
              .uniqueIdentifier(id)
              .add(ModernAttributes.newAttribute(text(DESCRIPTION, "reversed channel")))
              .build());
      Ttlv notify = expect(in, Operation.NOTIFY);
      Ttlv notifyPayload = notify.require(BATCH_ITEM).require(REQUEST_PAYLOAD);
      Ttlv description = InteropSuite.find(notifyPayload, DESCRIPTION);
      check(
          "Notify of the change over the reversed channel",
          notifyPayload.require(UNIQUE_IDENTIFIER).textValue().equals(id)
              && description != null
              && description.textValue().equals("reversed channel"),
          notifyPayload.children().stream().map(Ttlv::tagName).toList().toString());
      reply(out, notify, null);

      // After 30 s without a message the server hands the channel back (2.1 section 6.2.5). That
      // is keytend-kmip-server's fixed limit of a reversed channel, not its --idle-timeout (300 s
      // by default).
      Ttlv handBack = expect(in, Operation.SET_ENDPOINT_ROLE);
      check(
          "server hands the channel back with Endpoint Role Client",
          handBack.require(BATCH_ITEM).require(REQUEST_PAYLOAD).require(ENDPOINT_ROLE).intValue()
              == EndpointRole.CLIENT.code(),
          handBack.toString());
      reply(
          out,
          handBack,
          structure(RESPONSE_PAYLOAD, enumeration(ENDPOINT_ROLE, EndpointRole.CLIENT)));
      Result again =
          exchange(
              channel,
              Messages.request(
                  version,
                  List.of(
                      Requests.query()
                          .add(enumeration(QUERY_FUNCTION, QueryFunction.QUERY_OPERATIONS))
                          .build()),
                  RequestOptions.DEFAULT));
      check("the channel serves client requests again", again.successful(), again.toString());
    }
  }

  private Result exchange(SSLSocket socket, Ttlv request) throws IOException {
    OutputStream out = socket.getOutputStream();
    out.write(CODEC.encode(request));
    out.flush();
    return Messages.response(CODEC.read(socket.getInputStream())).results().get(0);
  }

  /** The next message on the channel, a request for {@code operation} in this version. */
  private Ttlv expect(InputStream in, Operation operation) throws IOException {
    Ttlv message = CODEC.read(in);
    if (message.tag() != REQUEST_MESSAGE.code())
      throw new AssertionError("Expected a " + operation.wireName() + " request: " + message);
    ProtocolVersion received = Messages.version(message.require(REQUEST_HEADER));
    int code = message.require(BATCH_ITEM).require(OPERATION).intValue();
    if (received != version || code != operation.code())
      throw new AssertionError(
          "Expected " + operation.wireName() + " in " + version + ": " + message);
    return message;
  }

  /** A successful response to {@code request}, with {@code payload} (may be null). */
  private void reply(OutputStream out, Ttlv request, Ttlv payload) throws IOException {
    Ttlv response =
        dev.keytend.kmip.server.CallbackMessages.respond(
            request,
            (operation, received) ->
                dev.keytend.kmip.server.CallbackHandler.Reply.success(payload));
    Result dispatched = Messages.response(response).results().get(0);
    if (!dispatched.successful())
      throw new AssertionError(
          "Callback dispatch refused the expected server request: " + dispatched);
    out.write(CODEC.encode(response));
    out.flush();
  }

  private void check(String name, boolean passed, String detail) {
    if (!passed) failures++;
    System.out.println(
        (passed ? "PASS " : "FAIL ") + version + " " + name + (passed ? "" : ": " + detail));
  }
}
