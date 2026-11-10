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

package dev.keytend.kmip;

import static dev.keytend.kmip.model.Tag.*;
import static dev.keytend.kmip.model.Ttlv.*;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.server.*;
import dev.keytend.kmip.transport.TlsTransport;
import java.io.*;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.Test;

/** Callback listener hardening. */
class CallbackTest {
  private static final InetSocketAddress LOCAL = new InetSocketAddress("127.0.0.1", 0);

  private static CallbackHandler.Reply stored(Operation op, Ttlv payload) {
    return CallbackHandler.Reply.success(
        structure(RESPONSE_PAYLOAD, text(UNIQUE_IDENTIFIER, "stored")));
  }

  private static Ttlv notifyMessage(ProtocolVersion version) {
    return Messages.request(
        version, List.of(Requests.notifyRequest().build()), RequestOptions.DEFAULT);
  }

  private static Ttlv send(CallbackServer server, String identity, Ttlv message) throws Exception {
    try (var transport =
        new TlsTransport(
            "localhost",
            server.port(),
            TestTls.context(identity, "listener"),
            Duration.ofSeconds(5),
            Duration.ofSeconds(5),
            new dev.keytend.kmip.codec.TtlvCodec())) {
      return transport.exchange(message);
    }
  }

  @Test
  void idleUnauthenticatedSocketsCannotLockOutTheKmipServer() throws Exception {
    List<IOException> errors = new CopyOnWriteArrayList<>();
    try (var server =
        CallbackServer.builder(LOCAL, TestTls.context("listener", "kms"), CallbackTest::stored)
            .errors(errors::add)
            .concurrency(1)
            .pendingHandshakes(4)
            .handshakeTimeout(Duration.ofSeconds(30))
            .build()) {
      List<Socket> idle = new ArrayList<>();
      try {
        // More idle TCP connections than workers, queue slots and handshake slots together.
        for (int i = 0; i < 20; i++) idle.add(new Socket("127.0.0.1", server.port()));
        Thread.sleep(100);
        Response r = Messages.response(send(server, "kms", notifyMessage(ProtocolVersion.V1_4)));
        assertTrue(r.results().get(0).successful());
      } finally {
        for (Socket s : idle) s.close();
      }
    }
  }

  @Test
  void handshakeHasAnAbsoluteDeadline() throws Exception {
    try (var server =
            CallbackServer.builder(LOCAL, TestTls.context("listener", "kms"), CallbackTest::stored)
                .handshakeTimeout(Duration.ofMillis(200))
                .readTimeout(Duration.ofSeconds(30))
                .build();
        var idle = new Socket("127.0.0.1", server.port())) {
      idle.setSoTimeout(5000);
      long start = System.nanoTime();
      // The listener closes the connection; the read sees EOF or a reset well before 30 s.
      try {
        // A TLS alert may precede EOF.
        idle.getInputStream().readAllBytes();
      } catch (SocketException reset) {
        // also acceptable
      }
      assertTrue(System.nanoTime() - start < TimeUnit.SECONDS.toNanos(4));
    }
  }

  @Test
  void peerIdentityIsAuthorizedAndVisibleToTheHandler() throws Exception {
    List<String> subjects = new CopyOnWriteArrayList<>();
    List<IOException> errors = new CopyOnWriteArrayList<>();
    ContextualCallbackHandler handler =
        (context, op, payload) -> {
          subjects.add(context.peerCertificates().get(0).getSubjectX500Principal().getName());
          assertEquals(ProtocolVersion.V1_4, context.version());
          return CallbackHandler.Reply.success(structure(RESPONSE_PAYLOAD));
        };
    // A shared trust store admits both identities; the authorizer narrows it to the KMS.
    try (var server =
        CallbackServer.builder(LOCAL, TestTls.context("listener", "kms", "other"), handler)
            .errors(errors::add)
            .authorize(
                session -> {
                  try {
                    return session.getPeerPrincipal().getName().equals("CN=kms");
                  } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
                    return false;
                  }
                })
            .build()) {
      assertTrue(
          Messages.response(send(server, "kms", notifyMessage(ProtocolVersion.V1_4)))
              .results()
              .get(0)
              .successful());
      assertThrows(
          IOException.class, () -> send(server, "other", notifyMessage(ProtocolVersion.V1_4)));
      assertEquals(List.of("CN=kms"), subjects);
      TestAwait.await("an error is reported").until(() -> !errors.isEmpty());
      assertTrue(
          errors.stream().anyMatch(e -> e.getMessage().contains("not authorized")),
          errors.toString());
    }
  }

  @Test
  void laterBadItemsDoNotAbortTheReplyAfterSideEffects() {
    List<Operation> handled = new ArrayList<>();
    CallbackHandler handler =
        (op, payload) -> {
          handled.add(op);
          return CallbackHandler.Reply.success(structure(RESPONSE_PAYLOAD));
        };
    Ttlv request =
        withItem(
            Messages.request(
                ProtocolVersion.V1_4,
                List.of(Requests.notifyRequest().build(), Requests.notifyRequest().build()),
                RequestOptions.DEFAULT.batching(true, Enums.BatchErrorContinuation.CONTINUE)),
            1,
            0x80000001);
    Ttlv response = CallbackMessages.respond(request, handler);
    List<Ttlv> items = response.children(BATCH_ITEM);
    assertEquals(List.of(Operation.NOTIFY), handled);
    assertEquals(2, items.size());
    assertEquals(0, items.get(0).require(RESULT_STATUS).intValue());
    assertEquals(0x80000001, items.get(1).require(OPERATION).intValue());
    assertEquals(
        Enums.ResultReason.OPERATION_NOT_SUPPORTED.code(),
        items.get(1).require(RESULT_REASON).intValue());

    // Under Stop (the default) a bad first item means nothing reaches the handler.
    handled.clear();
    Ttlv stop =
        withItem(
            Messages.request(
                ProtocolVersion.V1_4,
                List.of(Requests.notifyRequest().build(), Requests.notifyRequest().build()),
                RequestOptions.DEFAULT),
            0,
            0x80000001);
    assertEquals(1, CallbackMessages.respond(stop, handler).children(BATCH_ITEM).size());
    assertEquals(List.of(), handled);
  }

  /** Replaces the Operation of batch item {@code index} with a raw code. */
  private static Ttlv withItem(Ttlv request, int index, int operation) {
    List<Ttlv> roots = new ArrayList<>(request.children());
    Ttlv item = roots.get(index + 1);
    List<Ttlv> fields = new ArrayList<>(item.children());
    fields.set(0, enumeration(OPERATION, operation));
    roots.set(index + 1, structure(BATCH_ITEM, fields));
    return structure(REQUEST_MESSAGE, roots);
  }

  @Test
  void unknownCriticalExtensionRejectsTheWholeMessage_kmip21Section9_13() throws Exception {
    List<Operation> handled = new ArrayList<>();
    Ttlv extension = Credentials.extension("acme", true, text(COMMENT, "x"));
    Ttlv request =
        Messages.request(
            ProtocolVersion.V2_1,
            List.of(
                Requests.notifyRequest().build(),
                Requests.notifyRequest().extension(extension).build()),
            RequestOptions.DEFAULT.batching(true, Enums.BatchErrorContinuation.CONTINUE));
    Ttlv response =
        CallbackMessages.respond(
            request,
            (op, p) -> {
              handled.add(op);
              return CallbackHandler.Reply.success(structure(RESPONSE_PAYLOAD));
            });
    assertEquals(List.of(), handled);
    Response parsed = Messages.correlate(request, Messages.response(response));
    assertTrue(parsed.messageLevelFailure());
    assertEquals(
        Enums.ResultReason.UNKNOWN_MESSAGE_EXTENSION.code(), parsed.results().get(0).reason());
    // A listener configured with the vendor accepts it.
    Ttlv accepted =
        CallbackMessages.respond(
            request,
            (op, p) -> CallbackHandler.Reply.success(structure(RESPONSE_PAYLOAD)),
            Set.of("acme"));
    assertEquals(2, accepted.children(BATCH_ITEM).size());
  }

  @Test
  void headerProblemsGetKmipErrorsInsteadOfADroppedConnection() throws Exception {
    // Unsupported version 4.0: the reply echoes the version and reports the problem.
    Ttlv v4 =
        structure(
            REQUEST_MESSAGE,
            structure(
                REQUEST_HEADER,
                structure(
                    PROTOCOL_VERSION,
                    integer(PROTOCOL_VERSION_MAJOR, 4),
                    integer(PROTOCOL_VERSION_MINOR, 0)),
                integer(BATCH_COUNT, 1)),
            structure(
                BATCH_ITEM, enumeration(OPERATION, Operation.NOTIFY), structure(REQUEST_PAYLOAD)));
    Ttlv item = CallbackMessages.respond(v4, CallbackTest::stored).require(BATCH_ITEM);
    assertEquals(1, item.require(RESULT_STATUS).intValue());
    assertEquals(
        Enums.ResultReason.UNSUPPORTED_PROTOCOL_VERSION.code(),
        item.require(RESULT_REASON).intValue());
    // Batch Count mismatch.
    Ttlv request = notifyMessage(ProtocolVersion.V1_4);
    List<Ttlv> roots = new ArrayList<>(request.children());
    roots.add(roots.get(1));
    Ttlv mismatch = structure(REQUEST_MESSAGE, roots);
    Response r = Messages.response(CallbackMessages.respond(mismatch, CallbackTest::stored));
    assertEquals(Enums.ResultReason.INVALID_MESSAGE.code(), r.results().get(0).reason());
    // An operation newer than the message version (Set Endpoint Role is 2.0) on a 1.1 message.
    Ttlv old = withItem(notifyMessage(ProtocolVersion.V1_1), 0, Operation.SET_ENDPOINT_ROLE.code());
    Ttlv reply = CallbackMessages.respond(old, CallbackTest::stored).require(BATCH_ITEM);
    assertEquals(
        Enums.ResultReason.OPERATION_NOT_SUPPORTED.code(), reply.require(RESULT_REASON).intValue());
  }

  @Test
  void handlerFailuresAreReportedAndKnownExtensionsConfigurable() throws Exception {
    List<IOException> errors = new CopyOnWriteArrayList<>();
    try (var server =
        CallbackServer.builder(
                LOCAL,
                TestTls.context("listener", "kms"),
                (op, payload) -> {
                  throw new IllegalStateException("storage bug");
                })
            .errors(errors::add)
            .knownExtensions(Set.of("acme"))
            .build()) {
      Ttlv request =
          Messages.request(
              ProtocolVersion.V1_4,
              List.of(
                  Requests.notifyRequest()
                      .extension(Credentials.extension("acme", true, text(COMMENT, "x")))
                      .build()),
              RequestOptions.DEFAULT);
      Result result = Messages.response(send(server, "kms", request)).results().get(0);
      assertEquals(Enums.ResultReason.GENERAL_FAILURE.code(), result.reason());
      TestAwait.await("an error is reported").until(() -> !errors.isEmpty());
      assertEquals("storage bug", errors.get(0).getCause().getMessage());
    }
  }

  @Test
  void replyRejectsShapesThatPeersWouldRefuse() {
    assertThrows(
        IllegalArgumentException.class,
        () -> new CallbackHandler.Reply(1, null, "nope", null, List.of()));
    assertThrows(
        IllegalArgumentException.class,
        () -> new CallbackHandler.Reply(2, null, null, null, List.of()));
    Ttlv extension = Credentials.extension("acme", false);
    Ttlv response =
        CallbackMessages.respond(
            notifyMessage(ProtocolVersion.V1_4),
            (op, p) ->
                new CallbackHandler.Reply(
                    0, null, null, structure(RESPONSE_PAYLOAD), List.of(extension)));
    List<String> order =
        response.require(BATCH_ITEM).children().stream().map(Ttlv::tagName).toList();
    assertEquals(
        List.of("Operation", "ResultStatus", "ResponsePayload", "MessageExtension"), order);
  }

  // ---- reply fields, authorization and handshake floods ----

  /** Every Response Batch Item field occurs once; extraFields cannot repeat or override. */
  @Test
  void replyRejectsDuplicateAndReservedBatchItemFields() {
    Ttlv payload = structure(RESPONSE_PAYLOAD);
    Ttlv extension = Credentials.extension("acme", false);
    Ttlv correlation = bytes(ASYNCHRONOUS_CORRELATION_VALUE, new byte[] {1});
    for (Ttlv reserved :
        List.of(
            enumeration(RESULT_STATUS, 1),
            enumeration(RESULT_REASON, 1),
            text(RESULT_MESSAGE, "x"),
            enumeration(OPERATION, Operation.NOTIFY.code()),
            bytes(UNIQUE_BATCH_ITEM_ID, new byte[] {1}),
            structure(RESPONSE_PAYLOAD)))
      assertThrows(
          IllegalArgumentException.class,
          () -> new CallbackHandler.Reply(0, null, null, payload, List.of(reserved)),
          reserved.tagName());
    assertThrows(
        IllegalArgumentException.class,
        () -> new CallbackHandler.Reply(0, null, null, payload, List.of(extension, extension)));
    assertThrows(
        IllegalArgumentException.class,
        () -> new CallbackHandler.Reply(2, null, null, null, List.of(correlation, correlation)));
    var ok = new CallbackHandler.Reply(2, null, null, null, List.of(correlation, extension));
    Ttlv item =
        CallbackMessages.respond(notifyMessage(ProtocolVersion.V1_4), (op, p) -> ok)
            .require(BATCH_ITEM);
    assertEquals(
        List.of("Operation", "ResultStatus", "AsynchronousCorrelationValue", "MessageExtension"),
        item.children().stream().map(Ttlv::tagName).toList());
  }

  /** An exception thrown by the authorizer refuses the peer and reaches the error hook. */
  @Test
  void anAuthorizerExceptionIsReportedWithItsCause() throws Exception {
    List<IOException> errors = new CopyOnWriteArrayList<>();
    try (var server =
        CallbackServer.builder(LOCAL, TestTls.context("listener", "kms"), CallbackTest::stored)
            .errors(errors::add)
            .authorize(
                session -> {
                  throw new IllegalStateException("directory unavailable");
                })
            .build()) {
      assertThrows(
          IOException.class, () -> send(server, "kms", notifyMessage(ProtocolVersion.V1_4)));
      TestAwait.await("an error is reported").until(() -> !errors.isEmpty());
      assertTrue(
          errors.stream()
              .anyMatch(
                  e ->
                      e.getCause() instanceof IllegalStateException cause
                          && cause.getMessage().equals("directory unavailable")),
          errors.toString());
    }
  }

  /** Connections from addresses outside {@code peerAddresses} never reach a handshake. */
  @Test
  void peerAddressesRefuseStrangersBeforeTheHandshake() throws Exception {
    List<IOException> errors = new CopyOnWriteArrayList<>();
    try (var closedToAll =
            CallbackServer.builder(LOCAL, TestTls.context("listener", "kms"), CallbackTest::stored)
                .errors(errors::add)
                .peerAddresses(address -> false)
                .build();
        var loopbackOnly =
            CallbackServer.builder(LOCAL, TestTls.context("listener", "kms"), CallbackTest::stored)
                .peerAddresses(InetAddress::isLoopbackAddress)
                .build()) {
      assertThrows(
          IOException.class, () -> send(closedToAll, "kms", notifyMessage(ProtocolVersion.V1_4)));
      TestAwait.await("an error is reported").until(() -> !errors.isEmpty());
      assertTrue(
          errors.stream().anyMatch(e -> e.getMessage().contains("refused")), errors.toString());
      assertFalse(
          errors.stream().anyMatch(e -> e.getMessage().contains("handshake")), errors.toString());
      assertTrue(
          Messages.response(send(loopbackOnly, "kms", notifyMessage(ProtocolVersion.V1_4)))
              .results()
              .get(0)
              .successful());
    }
  }

  /**
   * When the handshake pool is full, a flood from one source address evicts its own pending
   * handshakes, not the older pending handshake of the KMIP server at another address. The flood
   * needs a second local source address. This variant uses 127.0.0.2, which Linux routes on its
   * loopback interface but macOS does not configure by default (add it with {@code sudo ifconfig
   * lo0 alias 127.0.0.2}). Where it is unavailable the test is skipped with that reason, and {@link
   * #aHandshakeFloodFromIpv6LoopbackEvictsItsOwnConnections} covers the same behavior with the
   * IPv6 loopback address, present by default on macOS and Linux.
   */
  @Test
  void aHandshakeFloodFromOneAddressEvictsItsOwnConnections() throws Exception {
    InetAddress flooder = InetAddress.getByName("127.0.0.2");
    org.junit.jupiter.api.Assumptions.assumeTrue(
        bindable(flooder),
        "127.0.0.2 is not a local address here (macOS: sudo ifconfig lo0 alias 127.0.0.2); the"
            + " IPv6 variant of this test covers the flood");
    floodFrom(flooder, new InetSocketAddress("0.0.0.0", 0), new InetSocketAddress("127.0.0.1", 0));
  }

  /**
   * Portable variant: the listener is bound to the IPv6 wildcard (dual stack), the KMIP
   * server connects over IPv4 from 127.0.0.1 and the flood comes from the IPv6 loopback {@code
   * ::1}, a different source address on any host with IPv6 loopback (the macOS and Linux default).
   * Skipped, with that reason, only where IPv6 or dual-stack sockets are disabled.
   */
  @Test
  void aHandshakeFloodFromIpv6LoopbackEvictsItsOwnConnections() throws Exception {
    InetAddress flooder = InetAddress.getByName("::1");
    org.junit.jupiter.api.Assumptions.assumeTrue(
        bindable(flooder), "the IPv6 loopback address ::1 is not available (IPv6 disabled)");
    floodFrom(flooder, dualStackWildcard(), new InetSocketAddress("127.0.0.1", 0));
  }

  /** The IPv6 wildcard address, after checking that a listener there accepts IPv4 too. */
  private static InetSocketAddress dualStackWildcard() throws IOException {
    InetSocketAddress wildcard = new InetSocketAddress(InetAddress.getByName("::"), 0);
    try (ServerSocket dual = new ServerSocket()) {
      dual.bind(wildcard);
      try (Socket v4 = new Socket()) {
        v4.connect(new InetSocketAddress("127.0.0.1", dual.getLocalPort()), 2_000);
      }
    } catch (IOException noDualStack) {
      org.junit.jupiter.api.Assumptions.assumeTrue(
          false, "an IPv6 wildcard listener does not accept IPv4 here (no dual-stack sockets)");
    }
    return wildcard;
  }

  /**
   * When every connection holding the handshake pool comes from a different address, a
   * new connection evicts the oldest pending handshake and is served. Here an idle connection from
   * {@code ::1} holds the only handshake thread and the KMIP server then connects from 127.0.0.1
   * (portable: dual stack, as above). Before, the KMIP server was closed after about 100 ms.
   */
  @Test
  void withEveryHandshakeFromADifferentAddressANewConnectionEvictsTheOldest() throws Exception {
    InetAddress other = InetAddress.getByName("::1");
    org.junit.jupiter.api.Assumptions.assumeTrue(
        bindable(other), "the IPv6 loopback address ::1 is not available (IPv6 disabled)");
    InetSocketAddress wildcard = dualStackWildcard();
    List<IOException> errors = new CopyOnWriteArrayList<>();
    try (var server =
            CallbackServer.builder(
                    wildcard, TestTls.context("listener", "kms"), CallbackTest::stored)
                .errors(errors::add)
                .pendingHandshakes(1)
                .handshakeTimeout(Duration.ofSeconds(30))
                .build();
        Socket idle = new Socket()) {
      idle.bind(new InetSocketAddress(other, 0));
      idle.connect(new InetSocketAddress(other, server.port()));
      Thread.sleep(100); // accepted and holding the only handshake thread
      assertTrue(isOpen(idle, 200));
      assertKmipServerIsServed(server);
      assertFalse(isOpen(idle, 2_000), "the oldest pending handshake was evicted");
      assertFalse(
          errors.stream().anyMatch(e -> e.getMessage().contains("capacity")), errors.toString());
    }
  }

  /**
   * Eviction with many addresses (127.0.0.10 to .19; Linux routes all of 127/8 on loopback, macOS
   * only 127.0.0.1, so this variant is skipped there and the test above covers the rule): ten idle
   * connections from different addresses meet a two-thread handshake pool. Each evicts the oldest,
   * so only the newest two stay open: the bound holds. The KMIP server then still gets through.
   */
  @Test
  void aFloodFromManyAddressesStaysWithinTheBoundAndCannotKeepOutTheKmipServer() throws Exception {
    org.junit.jupiter.api.Assumptions.assumeTrue(
        bindable(InetAddress.getByName("127.0.0.10")),
        "127.0.0.10 is not a local address here (macOS); the dual-stack variant covers the rule");
    List<IOException> errors = new CopyOnWriteArrayList<>();
    try (var server =
        CallbackServer.builder(LOCAL, TestTls.context("listener", "kms"), CallbackTest::stored)
            .errors(errors::add)
            .pendingHandshakes(2)
            .handshakeTimeout(Duration.ofSeconds(30))
            .build()) {
      List<Socket> flood = new ArrayList<>();
      try {
        for (int i = 0; i < 10; i++) {
          InetAddress from = InetAddress.getByName("127.0.0." + (10 + i));
          Socket s = new Socket();
          s.bind(new InetSocketAddress(from, 0));
          s.connect(new InetSocketAddress("127.0.0.1", server.port()));
          flood.add(s);
        }
        for (int i = 0; i < 8; i++)
          assertFalse(isOpen(flood.get(i), 5_000), "flood connection " + i + " was evicted");
        assertTrue(isOpen(flood.get(8), 200) && isOpen(flood.get(9), 200), "the newest two hold");
        assertKmipServerIsServed(server);
        assertFalse(isOpen(flood.get(8), 2_000), "the KMIP server evicted the oldest");
        assertFalse(
            errors.stream().anyMatch(e -> e.getMessage().contains("capacity")), errors.toString());
      } finally {
        for (Socket s : flood) s.close();
      }
    }
  }

  /** False once the listener has closed {@code socket}; true if it is still open after the wait. */
  private static boolean isOpen(Socket socket, int waitMillis) throws IOException {
    socket.setSoTimeout(waitMillis);
    try {
      return socket.getInputStream().read() >= 0;
    } catch (SocketTimeoutException stillOpen) {
      return true;
    } catch (SocketException reset) {
      return false;
    }
  }

  /** The KMIP server (from 127.0.0.1) completes its handshake and its Notify succeeds. */
  private static void assertKmipServerIsServed(CallbackServer server) throws Exception {
    var tls =
        (javax.net.ssl.SSLSocket)
            TestTls.context("kms", "listener").getSocketFactory().createSocket();
    try (tls) {
      tls.connect(new InetSocketAddress("127.0.0.1", server.port()), 5_000);
      tls.setSoTimeout(5_000);
      tls.startHandshake();
      var codec = new dev.keytend.kmip.codec.TtlvCodec();
      tls.getOutputStream().write(codec.encode(notifyMessage(ProtocolVersion.V1_4)));
      tls.getOutputStream().flush();
      Response r = Messages.response(codec.read(tls.getInputStream()));
      assertTrue(r.results().get(0).successful());
    }
  }

  private static boolean bindable(InetAddress address) {
    try (Socket probe = new Socket()) {
      probe.bind(new InetSocketAddress(address, 0));
      return true;
    } catch (IOException unavailable) {
      return false;
    }
  }

  /**
   * The KMIP server connects from {@code kmsSource}'s address and stalls before its handshake; 20
   * connections from {@code flooder} then fill the two-slot handshake pool. The KMIP server's
   * handshake must still complete and its Notify succeed.
   */
  private static void floodFrom(
      InetAddress flooder, InetSocketAddress bind, InetSocketAddress kmsSource) throws Exception {
    List<IOException> errors = new CopyOnWriteArrayList<>();
    try (var server =
        CallbackServer.builder(bind, TestTls.context("listener", "kms"), CallbackTest::stored)
            .errors(errors::add)
            .pendingHandshakes(2)
            .handshakeTimeout(Duration.ofSeconds(30))
            .build()) {
      // The KMIP server connects first and is slow to start its handshake.
      Socket kms = new Socket();
      kms.bind(kmsSource);
      kms.connect(new InetSocketAddress(kmsSource.getAddress(), server.port()));
      List<Socket> flood = new ArrayList<>();
      try {
        Thread.sleep(100);
        for (int i = 0; i < 20; i++) {
          Socket s = new Socket();
          s.bind(new InetSocketAddress(flooder, 0));
          s.connect(new InetSocketAddress(flooder, server.port()));
          flood.add(s);
        }
        Thread.sleep(300);
        var tls =
            (javax.net.ssl.SSLSocket)
                TestTls.context("kms", "listener")
                    .getSocketFactory()
                    .createSocket(kms, "localhost", server.port(), true);
        tls.setSoTimeout(5_000);
        tls.startHandshake();
        var codec = new dev.keytend.kmip.codec.TtlvCodec();
        tls.getOutputStream().write(codec.encode(notifyMessage(ProtocolVersion.V1_4)));
        tls.getOutputStream().flush();
        Response r = Messages.response(codec.read(tls.getInputStream()));
        assertTrue(r.results().get(0).successful());
      } finally {
        kms.close();
        for (Socket s : flood) s.close();
      }
    }
  }

  /** A TLS peer that sends one Query and then never reads (a tiny receive window). */
  private static Socket stalledPeer(CallbackServer server) throws Exception {
    var tls =
        (javax.net.ssl.SSLSocket)
            TestTls.context("kms", "listener").getSocketFactory().createSocket();
    tls.setReceiveBufferSize(4096);
    tls.connect(new InetSocketAddress("127.0.0.1", server.port()), 5_000);
    tls.startHandshake();
    tls.getOutputStream()
        .write(
            new dev.keytend.kmip.codec.TtlvCodec()
                .encode(
                    Messages.request(
                        ProtocolVersion.V1_4,
                        List.of(Requests.query().build()),
                        RequestOptions.DEFAULT)));
    tls.getOutputStream().flush();
    return tls;
  }

  /** A handler whose reply (12 MB) cannot fit in the socket buffers of a peer that never reads. */
  private static CallbackHandler hugeReply(CountDownLatch handled) {
    return (op, payload) -> {
      handled.countDown();
      return CallbackHandler.Reply.success(
          structure(RESPONSE_PAYLOAD, bytes(DATA, new byte[12 << 20])));
    };
  }

  /**
   * The frame deadline closes a connection whose peer stopped reading in the middle of the
   * reply, without blocking the JVM-wide deadline thread: another listener's handshake deadline
   * still fires afterwards.
   */
  @Test
  void aPeerThatStopsReadingCannotStallTheFrameDeadline() throws Exception {
    List<IOException> errors = new CopyOnWriteArrayList<>();
    CountDownLatch handled = new CountDownLatch(1);
    try (var server =
            CallbackServer.builder(LOCAL, TestTls.context("listener", "kms"), hugeReply(handled))
                .errors(errors::add)
                .frameTimeout(Duration.ofMillis(500))
                .build();
        Socket peer = stalledPeer(server)) {
      assertTrue(handled.await(5, TimeUnit.SECONDS));
      for (int i = 0; i < 250 && errors.isEmpty(); i++) Thread.sleep(20);
      assertTrue(
          errors.stream().anyMatch(e -> e.getMessage().contains("deadline")), errors.toString());
      // The shared deadline thread is still free: another listener's handshake deadline fires.
      try (var other =
              CallbackServer.builder(
                      LOCAL, TestTls.context("listener", "kms"), CallbackTest::stored)
                  .handshakeTimeout(Duration.ofMillis(200))
                  .build();
          var idle = new Socket("127.0.0.1", other.port())) {
        idle.setSoTimeout(5_000);
        long start = System.nanoTime();
        try {
          idle.getInputStream().readAllBytes();
        } catch (SocketException reset) {
          // also acceptable
        }
        assertTrue(
            System.nanoTime() - start < TimeUnit.SECONDS.toNanos(3),
            "the deadline thread is blocked");
      }
    }
  }

  /** Close() returns promptly while a worker is blocked writing to a peer that never reads. */
  @Test
  void closeDoesNotWaitForAPeerThatStoppedReading() throws Exception {
    CountDownLatch handled = new CountDownLatch(1);
    var server =
        CallbackServer.builder(LOCAL, TestTls.context("listener", "kms"), hugeReply(handled))
            .frameTimeout(Duration.ofSeconds(60))
            .build();
    try (Socket peer = stalledPeer(server)) {
      assertTrue(handled.await(5, TimeUnit.SECONDS));
      Thread.sleep(500); // the worker is now blocked in the reply write
      ExecutorService closer = Executors.newSingleThreadExecutor();
      try {
        Future<?> closing =
            closer.submit(
                () -> {
                  server.close();
                  return null;
                });
        closing.get(3, TimeUnit.SECONDS); // TimeoutException here means close() hung
      } finally {
        closer.shutdownNow();
      }
    }
  }
}
