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

import static dev.keytend.kmip.kms.KmsContractTest.AAD;
import static dev.keytend.kmip.kms.KmsContractTest.PLAIN;
import static dev.keytend.kmip.kms.KmsContractTest.sent;
import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import dev.keytend.kmip.TestTls;
import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.HttpsTransport;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.net.*;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * Response validation and call deadlines: missing or unknown states, connect bounded by the call
 * timeout, HTTP content types kept out of errors, Correlation Values, Locate paging and closes
 * between creation and activation.
 */
class KmsResponseValidationTest {
  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  Kms connect(InMemoryKmipServer server, KmsConfig.Builder builder) {
    servers.add(server);
    Kms kms = Kms.connect(builder.build());
    clients.add(kms);
    return kms;
  }

  // ---- the state checks fail closed ----

  /** How the client sees the State in Get Attributes responses. */
  enum StateView {
    AS_SENT,
    MISSING,
    UNKNOWN_VALUE
  }

  /**
   * A Compromised key whose Get Attributes response leaves State out, or gives a value the
   * SDK does not know, was taken as not Compromised: retrieval, decryption, unwrapping and
   * verification all went ahead. Now each is a protocol violation, before the Get or the
   * cryptographic request, also for a handle allowing Compromised keys.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aMissingOrUnknownStateIsRefusedNotTakenAsUsable(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    AtomicReference<StateView> view = new AtomicReference<>(StateView.AS_SENT);
    Kms kms =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(e -> request -> rewriteState(server.exchange(request), view.get())));
    KeyHandle kek =
        kms.keys().createAes(128).named("kek").usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    Ciphertext c = kek.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    Ciphertext wrapped;
    try (DataKey dek = kek.generateDataKey(128, AAD)) {
      wrapped = dek.wrapped();
    }
    KeyHandle mac =
        kms.keys()
            .createSymmetric(Algorithm.HMAC_SHA256, 256)
            .usages(KeyUsage.MAC_GENERATE, KeyUsage.MAC_VERIFY)
            .create();
    byte[] tag = mac.mac(MacSpec.hmac(Hash.SHA_256), PLAIN);
    KeyPairHandle signer =
        kms.keys()
            .createKeyPair(KeyPairSpec.ec(Curve.P_256))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .create();
    byte[] sig = signer.privateKey().sign(SignatureSpec.ecdsa(Hash.SHA_256), PLAIN);
    Instant when = Instant.now().minusSeconds(60);
    for (KeyHandle k : List.of(kek, mac, signer.publicKey()))
      k.revoke(RevocationReason.keyCompromise("leaked", when));

    for (StateView shown : List.of(StateView.MISSING, StateView.UNKNOWN_VALUE)) {
      view.set(shown);
      long gets = sent(server, Operation.GET), decrypts = sent(server, Operation.DECRYPT);
      long verifies = sent(server, Operation.SIGNATURE_VERIFY),
          macVerifies = sent(server, Operation.MAC_VERIFY);
      // This must not return the Compromised key.
      assertNoState(shown, () -> kek.asSecretKey(Expect.aes(128), LocalUse.DECRYPT));
      assertNoState(
          shown, () -> kek.allowingCompromised().asSecretKey(Expect.aes(128), LocalUse.DECRYPT));
      assertNoState(shown, () -> kek.decrypt(c, AAD));
      assertNoState(shown, () -> kek.allowingCompromised().decrypt(c, AAD));
      assertNoState(shown, () -> kms.keys().decrypt(KeyQuery.byName("kek"), c, AAD));
      assertNoState(shown, () -> kek.unwrapKey(Expect.aes(128), wrapped, AAD));
      assertNoState(
          shown, () -> kms.keys().unwrapKey(KeyQuery.byName("kek"), Expect.aes(128), wrapped, AAD));
      assertNoState(shown, () -> mac.macVerify(MacSpec.hmac(Hash.SHA_256), PLAIN, tag));
      assertNoState(
          shown, () -> signer.publicKey().verify(SignatureSpec.ecdsa(Hash.SHA_256), PLAIN, sig));
      assertNoState(shown, () -> signer.publicKey().asPublicKey(Expect.ec(Curve.P_256)));
      assertEquals(gets, sent(server, Operation.GET), "nothing retrieved");
      assertEquals(decrypts, sent(server, Operation.DECRYPT), "nothing decrypted");
      assertEquals(verifies, sent(server, Operation.SIGNATURE_VERIFY), "nothing verified");
      assertEquals(macVerifies, sent(server, Operation.MAC_VERIFY), "no MAC verified");
    }
    // The control: the same calls with the State as the server sent it.
    view.set(StateView.AS_SENT);
    KmsContractTest.assertCompromised(() -> kek.asSecretKey(Expect.aes(128), LocalUse.DECRYPT));
    KmsContractTest.assertCompromised(() -> kek.decrypt(c, AAD));
    assertArrayEquals(PLAIN, kek.allowingCompromised().decrypt(c, AAD));
  }

  static void assertNoState(StateView shown, Executable call) {
    ProtocolViolationException e = assertThrows(ProtocolViolationException.class, call);
    String expected = shown == StateView.MISSING ? "no State" : "an unknown State";
    assertTrue(e.getMessage().contains(expected), e.getMessage());
  }

  /** A vendor-range State value, which {@link KeyState} does not know. */
  static final int VENDOR_STATE = 0x80000001;

  /** Removes the State from Get Attributes responses (1.x and 2.x forms), or changes its value. */
  static Ttlv rewriteState(Ttlv node, StateView view) {
    if (view == StateView.AS_SENT || node.type() != Ttlv.Type.STRUCTURE) return node;
    List<Ttlv> children = new ArrayList<>();
    for (Ttlv child : node.children()) {
      boolean state1x =
          child.tag() == Tag.ATTRIBUTE.code()
              && child
                  .child(Tag.ATTRIBUTE_NAME)
                  .map(n -> n.textValue().equals("State"))
                  .orElse(false);
      boolean state2x = child.tag() == Tag.STATE.code() && child.type() == Ttlv.Type.ENUMERATION;
      if (view == StateView.MISSING && (state1x || state2x)) continue;
      if (view == StateView.UNKNOWN_VALUE && state2x)
        child = Ttlv.enumeration(Tag.STATE, VENDOR_STATE);
      else if (view == StateView.UNKNOWN_VALUE && state1x)
        child =
            Ttlv.structure(
                Tag.ATTRIBUTE,
                child.require(Tag.ATTRIBUTE_NAME),
                Ttlv.enumeration(Tag.ATTRIBUTE_VALUE, VENDOR_STATE));
      else child = rewriteState(child, view);
      children.add(child);
    }
    return Ttlv.structure(node.tag(), children);
  }

  // ---- Kms.connect() has one deadline ----

  /**
   * The initial negotiation in {@code Kms.connect()} sends Discover Versions under the call's
   * deadline, so the call timeout bounds it (without one, an 80 ms call timeout completed after
   * 417 ms). Against two endpoints that accept TCP and never handshake, connect
   * gives up when the call timeout has passed, for both endpoints together, rather than waiting
   * for each endpoint's handshake.
   */
  @Test
  void connectEndsAtTheCallTimeoutAcrossEndpoints() throws Exception {
    try (ServerSocket a = new ServerSocket(0, 50, InetAddress.getLoopbackAddress());
        ServerSocket b = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
      KmsConfig config =
          KmsConfig.builder()
              .endpoints("localhost:" + a.getLocalPort(), "localhost:" + b.getLocalPort())
              .tls(TestTls.context("client", "server"))
              .connectTimeout(Duration.ofSeconds(10))
              .callTimeout(Duration.ofMillis(400))
              .build();
      long start = System.nanoTime();
      KmsException e =
          assertTimeoutPreemptively(
              Duration.ofSeconds(8),
              () -> assertThrows(KmsException.class, () -> Kms.connect(config)));
      long millis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
      assertTrue(millis >= 350 && millis < 2_000, "took " + millis + " ms");
      assertInstanceOf(TransientException.class, e, e.toString());
    }
  }

  /**
   * Every request a {@code Kms} sends carries a deadline no later than the call timeout,
   * from the first Discover Versions (with a version fallback: a 1.4 server asked in 3.0) through
   * application calls. Without one ({@link CallContext#NONE}) the connect requests would be
   * bounded only by the transport's own read limit.
   */
  @Test
  void everyRequestFromConnectOnHasTheCallDeadline() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V1_4);
    Duration callTimeout = Duration.ofSeconds(20);
    List<String> unbounded = new CopyOnWriteArrayList<>();
    List<Long> remaining = new CopyOnWriteArrayList<>();
    Kms kms =
        connect(
            server,
            server
                .configure()
                .maximumVersion(KmipVersion.V3_0)
                .callTimeout(callTimeout)
                .transport(
                    e ->
                        new KmipTransport() {
                          @Override
                          public Ttlv exchange(Ttlv request) throws IOException {
                            unbounded.add(operation(request));
                            return server.exchange(request);
                          }

                          @Override
                          public Ttlv exchange(Ttlv request, CallContext context)
                              throws IOException {
                            if (!context.hasDeadline()) unbounded.add(operation(request));
                            else remaining.add(context.remainingNanos());
                            return server.exchange(request);
                          }
                        }));
    assertEquals(KmipVersion.V1_4, kms.version());
    KeyHandle key = KmsContractTest.aes(kms, "k");
    key.decrypt(key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD), AAD);
    assertEquals(List.of(), unbounded, "requests sent without a deadline");
    assertTrue(remaining.size() >= 4, remaining.toString());
    for (long nanos : remaining)
      assertTrue(nanos > 0 && nanos <= callTimeout.toNanos(), nanos + " ns");
  }

  static String operation(Ttlv request) {
    return request.children(Tag.BATCH_ITEM).stream()
        .map(i -> String.valueOf(Operation.fromCode(i.require(Tag.OPERATION).intValue())))
        .toList()
        .toString();
  }

  // ---- an HTTP header value never reaches messages ----

  /**
   * An unexpected Content-Type was quoted verbatim in {@code KmsException.getMessage()} and
   * in the listener's failure event. Now neither the exception (its message, causes and suppressed
   * exceptions) nor any event mentions it.
   */
  @Test
  void anHttpContentTypeNeverReachesExceptionsOrEvents() throws Exception {
    InMemoryKmipServer kmip = InMemoryKmipServer.of(KmipVersion.V2_1);
    TtlvCodec codec = new TtlvCodec();
    AtomicBoolean secretType = new AtomicBoolean();
    HttpsServer https = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    https.setHttpsConfigurator(new HttpsConfigurator(TestTls.context("server", "client")));
    https.createContext(
        "/kmip",
        exchange -> {
          byte[] reply =
              codec.encode(kmip.exchange(codec.decode(exchange.getRequestBody().readAllBytes())));
          exchange
              .getResponseHeaders()
              .add(
                  "Content-Type",
                  secretType.get() ? "SECRET-MATERIAL-987654321" : "application/octet-stream");
          exchange.sendResponseHeaders(200, reply.length);
          exchange.getResponseBody().write(reply);
          exchange.close();
        });
    https.start();
    List<String> events = new CopyOnWriteArrayList<>();
    KmsListener listener =
        new KmsListener() {
          @Override
          public void finished(KmsEvent event) {
            events.add(event.toString());
            event.failure().ifPresent(f -> events.add(f.getMessage()));
          }

          @Override
          public void retrying(KmsEvent failed, Duration delay) {
            finished(failed);
          }

          @Override
          public void endpointUnavailable(String endpoint, String why) {
            events.add(why);
          }
        };
    try {
      URI uri = URI.create("https://localhost:" + https.getAddress().getPort() + "/kmip");
      javax.net.ssl.SSLContext tls = TestTls.context("client", "server");
      Kms kms =
          connect(
              kmip,
              kmip.configure()
                  .addListener(listener)
                  .transport(e -> new HttpsTransport(uri, tls, HttpsTransport.Encoding.TTLV)));
      KeyHandle key = KmsContractTest.aes(kms, "k");
      secretType.set(true);
      KmsException e = assertThrows(KmsException.class, key::attributes);
      assertFalse(events.isEmpty());
      assertNotQuoted(e);
      for (String event : events) assertFalse(event.contains("SECRET"), event);
    } finally {
      https.stop(0);
    }
  }

  static void assertNotQuoted(Throwable e) {
    for (Throwable t = e; t != null; t = t.getCause()) {
      assertFalse(String.valueOf(t).contains("SECRET"), t.toString());
      for (Throwable suppressed : t.getSuppressed()) assertNotQuoted(suppressed);
    }
  }

  // ---- Correlation Values, Locate paging, closes between Create and Activate ----

  /**
   * A response Correlation Value on a single-part Encrypt must not let a response without
   * Data through. On 2.x, where the table makes Data optional, the kms layer still refuses it for
   * non-empty input; the Correlation Value changes nothing. Protocol-level cases are in
   * {@code ResponsePayloadTablesTest}.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void anUnsolicitedCorrelationValueDoesNotExcuseAMissingEncryptOutput(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    AtomicBoolean tamper = new AtomicBoolean();
    Kms kms =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request -> {
                          Ttlv response = server.exchange(request);
                          return tamper.get() && KmsContractTest.is(request, Operation.ENCRYPT)
                              ? withCorrelationInsteadOfData(response)
                              : response;
                        }));
    KeyHandle key = KmsContractTest.aes(kms, "k");
    tamper.set(true);
    assertThrows(
        ProtocolViolationException.class, () -> key.encrypt(CipherSpec.aesGcm(), PLAIN, AAD));
    assertThrows(
        ProtocolViolationException.class, () -> key.encrypt(CipherSpec.cbc(), PLAIN, null));
    assertThrows(ProtocolViolationException.class, () -> key.seal(PLAIN, AAD));
  }

  /** The response payload without Data, with a Correlation Value the request never asked for. */
  static Ttlv withCorrelationInsteadOfData(Ttlv node) {
    if (node.type() != Ttlv.Type.STRUCTURE) return node;
    List<Ttlv> children = new ArrayList<>();
    for (Ttlv c : node.children())
      if (c.tag() != Tag.DATA.code()) children.add(withCorrelationInsteadOfData(c));
    if (node.tag() == Tag.RESPONSE_PAYLOAD.code())
      children.add(Ttlv.bytes(Tag.CORRELATION_VALUE, new byte[] {9}));
    return Ttlv.structure(node.tag(), children);
  }

  /**
   * Locate answering {@code Located Items 7} with the same one-element page every time must not
   * give {@code count() == 1} without an error. Paging that makes no progress while the
   * total says more is a protocol violation, for the stream, {@code list} and {@code findByName}.
   */
  @Test
  void locatedItemsSevenWithARepeatedOneElementPageIsAViolation() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    AtomicBoolean lie = new AtomicBoolean();
    AtomicInteger locates = new AtomicInteger();
    Kms kms =
        connect(
            server,
            server
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request -> {
                          if (!lie.get() || !KmsContractTest.is(request, Operation.LOCATE))
                            return server.exchange(request);
                          locates.incrementAndGet();
                          return locatedItems(server.exchange(capOneWithoutOffset(request)), 7);
                        }));
    KeyHandle only = KmsContractTest.aes(kms, "one");
    lie.set(true);
    assertThrows(
        ProtocolViolationException.class, () -> kms.keys().locate(KeyQuery.byName("one")).count());
    assertThrows(ProtocolViolationException.class, () -> kms.keys().list(KeyQuery.byName("one")));
    assertThrows(ProtocolViolationException.class, () -> kms.keys().findByName("one"));
    assertTrue(locates.get() >= 4, "paged at least twice per call that pages");
    lie.set(false);
    assertEquals(List.of(only), kms.keys().list(KeyQuery.byName("one")));
  }

  /** The request with Maximum Items 1 and no Offset Items: the same first page every time. */
  static Ttlv capOneWithoutOffset(Ttlv request) {
    return KmsExecutionTest.capMaximumItems(
        KmsFailureHandlingTest.withoutOffset(withMaximumItems(request)), 1);
  }

  /** Adds Maximum Items to a Locate payload that has none (findByName sends no item limit). */
  static Ttlv withMaximumItems(Ttlv node) {
    if (node.type() != Ttlv.Type.STRUCTURE) return node;
    List<Ttlv> children = new ArrayList<>();
    for (Ttlv c : node.children()) children.add(withMaximumItems(c));
    if (node.tag() == Tag.REQUEST_PAYLOAD.code() && node.child(Tag.MAXIMUM_ITEMS).isEmpty())
      children.add(0, Ttlv.integer(Tag.MAXIMUM_ITEMS, 1));
    return Ttlv.structure(node.tag(), children);
  }

  /** Sets Located Items in a Locate response payload. */
  static Ttlv locatedItems(Ttlv node, int total) {
    if (node.type() != Ttlv.Type.STRUCTURE) return node;
    List<Ttlv> children = new ArrayList<>();
    for (Ttlv c : node.children())
      if (c.tag() != Tag.LOCATED_ITEMS.code()) children.add(locatedItems(c, total));
    if (node.tag() == Tag.RESPONSE_PAYLOAD.code())
      children.add(0, Ttlv.integer(Tag.LOCATED_ITEMS, total));
    return Ttlv.structure(node.tag(), children);
  }

  /**
   * A {@code close()} between Create and Activate must not lose the created handle. {@link
   * KmsContractTest} covers {@code create()} and {@code findOrCreate()}; this covers the other terminals
   * that create and then activate, {@code register()} and key pairs: each reports what it created in
   * a {@code PartialCompletionException} whose cause is the closed {@code Kms}'s
   * {@code IllegalStateException}.
   */
  @Test
  void closingBetweenRegisterOrKeyPairCreationAndActivationReportsWhatWasCreated() {
    for (int kind = 0; kind < 2; kind++) {
      InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
      Kms kms = connect(server, server.configure());
      Operation made = kind == 0 ? Operation.REGISTER : Operation.CREATE_KEY_PAIR;
      server.injectAfterProcessing(
          r -> {
            if (KmsContractTest.is(r, made)) kms.close();
            return null;
          });
      PartialCompletionException e =
          assertThrows(
              PartialCompletionException.class,
              kind == 0
                  ? () ->
                      kms.keys()
                          .register(new SecretKeySpec(new byte[16], "AES"))
                          .usages(KeyUsage.ENCRYPT)
                          .register()
                  : () ->
                      kms.keys()
                          .createKeyPair(KeyPairSpec.ec(Curve.P_256))
                          .privateUsages(KeyUsage.SIGN)
                          .publicUsages(KeyUsage.VERIFY)
                          .create());
      assertInstanceOf(IllegalStateException.class, e.getCause());
      assertEquals(kind == 0 ? 1 : 2, e.created().size(), e.created().toString());
      for (KeyHandle created : e.created()) assertTrue(server.exists(created.id()));
      assertEquals(kind == 1, e.createdPair().isPresent());
      assertTrue(e.getMessage().contains("instead of repeating"), e.getMessage());
    }
  }
}
