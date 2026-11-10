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

import dev.keytend.kmip.TestTls;
import dev.keytend.kmip.client.Result;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.RequestNotSentException;
import java.io.*;
import java.net.*;
import java.security.KeyStore;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import javax.net.ssl.*;
import org.junit.jupiter.api.Test;

/**
 * TLS certificate failures are classified by exception types and TLS alert names, not by
 * English message text; a server that refuses this client's certificate is FIX_ACCESS, also when
 * TLS 1.3 reports it only after the request was written.
 */
class ClassificationTest {
  private static final Failures.Call READ = new Failures.Call("get", true, "k", false);
  private static final Failures.Call MUTATION = new Failures.Call("create", false, null, false);

  /** The RFC 8446 alerts about certificates (and access) that a server sends to refuse a client. */
  private static final List<String> ALERTS =
      List.of(
          "bad_certificate",
          "unsupported_certificate",
          "certificate_revoked",
          "certificate_expired",
          "certificate_unknown",
          "unknown_ca",
          "access_denied",
          "certificate_required");

  private static <T extends Throwable> T caused(T outer, Throwable cause) {
    outer.initCause(cause);
    return outer;
  }

  private static RequestNotSentException notSent(Throwable cause) {
    return new RequestNotSentException("KMIP request not sent: handshake", cause);
  }

  // ---- this client rejects the server's certificate: exception types in the cause chain ----

  @Test
  void aCertificateExceptionAnywhereInTheChainIsAnUntrustedServer() {
    for (Exception local :
        List.of(
            new CertificateException("whatever the JDK says"),
            new CertPathValidatorException("whatever the JDK says"),
            new CertPathBuilderException("whatever the JDK says"))) {
      // Wording-free: neither message mentions certificates or PKIX.
      Exception chain =
          notSent(
              caused(
                  new SSLHandshakeException("handshake failed"),
                  caused(new IOException("x"), local)));
      KmsException k = Failures.classify(READ, null, chain);
      assertInstanceOf(PermissionDeniedException.class, k, local.toString());
      assertEquals(KmsException.Category.FIX_ACCESS, k.category());
      assertTrue(k.getMessage().startsWith("get k: TLS handshake rejected: "), k.getMessage());
      assertTrue(Failures.serverNotTrusted(chain), local.toString());
    }
  }

  // ---- the server rejects this client's certificate: the TLS alert name ----

  @Test
  void aReceivedCertificateAlertIsPermissionDeniedInEveryWording() {
    for (String alert : ALERTS)
      for (String message :
          List.of(
              "Received fatal alert: " + alert, // JDK 17 and 21
              "(" + alert + ") Received fatal alert: " + alert, // JDK 25
              "Fatale Warnung erhalten: " + alert, // another wording
              "org.bouncycastle.tls.TlsFatalAlertReceived: " + alert + "(42)", // BCJSSE
              "error:10000416:SSL routines:OPENSSL_internal:SSLV3_ALERT_"
                  + alert.toUpperCase(Locale.ROOT))) {
        for (Exception tls :
            List.of(new SSLHandshakeException(message), new SSLException(message))) {
          // Before sending (handshake) and, as TLS 1.3 reports a refused client certificate, at the
          // first read after the request was written: neither is a transient failure, and a
          // mutation refused in the handshake cannot have taken effect.
          for (Exception chain : List.of(notSent(tls), tls, new IOException("read failed", tls)))
            for (Failures.Call call : List.of(READ, MUTATION)) {
              KmsException k = Failures.classify(call, null, chain);
              assertInstanceOf(PermissionDeniedException.class, k, message + " / " + chain);
              assertTrue(k.getMessage().contains("TLS handshake rejected"), k.getMessage());
              assertFalse(
                  Failures.serverNotTrusted(chain), "the peer refused this client: " + message);
            }
        }
      }
  }

  /** Text that merely mentions certificates, and alerts about something else, stay transient. */
  @Test
  void otherHandshakeFailuresAreTransientWhateverTheirText() {
    for (Exception tls :
        List.of(
            caused(
                new SSLHandshakeException("Remote host terminated the handshake"),
                new EOFException("SSL peer shut down incorrectly")),
            caused(
                new SSLHandshakeException(
                    "Could not read the server certificate: connection reset"),
                new SocketException("Connection reset")),
            new SSLHandshakeException("PKIX certificate path"),
            new SSLHandshakeException(
                "(handshake_failure) Received fatal alert: handshake_failure"),
            new SSLHandshakeException("(protocol_version) Received fatal alert: protocol_version"),
            new SSLHandshakeException("Received fatal alert: bad_certificate_status_response"),
            new SSLHandshakeException("Received fatal alert: xbad_certificate"))) {
      KmsException k = Failures.classify(READ, null, notSent(tls));
      assertInstanceOf(TransientException.class, k, tls.toString());
      assertFalse(Failures.serverNotTrusted(notSent(tls)));
      // After the request was written, an unrelated failure of a mutation stays unknown.
      assertInstanceOf(
          OutcomeUnknownException.class, Failures.classify(MUTATION, null, tls), tls.toString());
    }
    // An alert name is only read from an SSLException's message.
    assertInstanceOf(
        TransientException.class,
        Failures.classify(READ, null, notSent(new SocketException("access_denied"))));
  }

  // ---- real handshakes ----

  /** Trusts "client" but presents no CA names, so any client certificate is sent and checked. */
  private static SSLContext serverTrustingOnlyClient() throws Exception {
    KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmf.init(TestTls.identity("server"), "changeit".toCharArray());
    KeyStore trust = KeyStore.getInstance("PKCS12");
    trust.load(null, null);
    trust.setCertificateEntry("client", TestTls.certificate("client"));
    TrustManagerFactory tmf =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmf.init(trust);
    X509TrustManager real = (X509TrustManager) tmf.getTrustManagers()[0];
    X509TrustManager anyIssuer =
        new X509TrustManager() {
          @Override
          public void checkClientTrusted(X509Certificate[] chain, String type)
              throws CertificateException {
            real.checkClientTrusted(chain, type);
          }

          @Override
          public void checkServerTrusted(X509Certificate[] chain, String type)
              throws CertificateException {
            real.checkServerTrusted(chain, type);
          }

          @Override
          public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
          }
        };
    SSLContext context = SSLContext.getInstance("TLS");
    context.init(kmf.getKeyManagers(), new TrustManager[] {anyIssuer}, null);
    return context;
  }

  private static KmsConfig config(SSLContext client, RecordingTlsServer... servers) {
    String[] endpoints =
        Arrays.stream(servers).map(RecordingTlsServer::endpoint).toArray(String[]::new);
    return KmsConfig.builder().endpoints(endpoints).tls(client).build();
  }

  /**
   * Real TLS, both directions: this client refusing the server's certificate is skipped on a
   * replica and FIX_ACCESS alone; the server refusing this client's certificate (TLS 1.3 reports it
   * at the first read, after the request was written) is FIX_ACCESS at once, not RETRY.
   */
  @Test
  void realHandshakesAreClassifiedInBothDirections() throws Exception {
    SSLContext client = TestTls.context("client", "server");
    try (RecordingTlsServer impostor =
            new RecordingTlsServer(TestTls.context("stranger", "client"));
        RecordingTlsServer good = new RecordingTlsServer(TestTls.context("server", "client"));
        RecordingTlsServer refusing = new RecordingTlsServer(serverTrustingOnlyClient())) {
      // This client refuses the server.
      PermissionDeniedException untrusted =
          assertThrows(
              PermissionDeniedException.class, () -> Kms.connect(config(client, impostor)));
      assertEquals(KmsException.Category.FIX_ACCESS, untrusted.category());
      assertTrue(Failures.serverNotTrusted(untrusted.getCause()));
      try (Kms kms = Kms.connect(config(client, impostor, good))) {
        assertEquals(KmipVersion.V2_1, kms.version(), "the untrusted replica is skipped");
      }

      // The server refuses this client's certificate (certificate_unknown) ...
      SSLContext stranger = TestTls.context("stranger", "server");
      int goodBefore = good.peers.size() + good.refused.get();
      PermissionDeniedException refused =
          assertThrows(
              PermissionDeniedException.class, () -> Kms.connect(config(stranger, refusing, good)));
      assertEquals(KmsException.Category.FIX_ACCESS, refused.category());
      assertFalse(Failures.serverNotTrusted(refused.getCause()));
      assertEquals(
          goodBefore,
          good.peers.size() + good.refused.get(),
          "every replica would refuse it: the next one is not tried");
      // The server counts a refused handshake on its connection thread, after the client saw it.
      RecordingTlsServer.await(() -> refusing.refused.get() >= 1, "the server refused it");
      // ... or sends no CA name it has, so this client sends none (certificate_required).
      assertThrows(PermissionDeniedException.class, () -> Kms.connect(config(stranger, good)));
    }
  }

  /**
   * After credentials rotate to a certificate the server refuses, a mutation fails with
   * PermissionDeniedException, not OutcomeUnknownException (the server refused the handshake, so it
   * cannot have run the request), and a read is not retried as transient.
   */
  @Test
  void aRefusedCertificateAfterRotationIsPermissionDeniedForMutationsAndReads() throws Exception {
    AtomicReference<SSLContext> current =
        new AtomicReference<>(TestTls.context("client", "server"));
    java.util.concurrent.atomic.AtomicInteger attempts =
        new java.util.concurrent.atomic.AtomicInteger();
    KmsListener listener =
        new KmsListener() {
          @Override
          public void started(KmsEvent event) {
            attempts.incrementAndGet();
          }
        };
    try (RecordingTlsServer server = new RecordingTlsServer(serverTrustingOnlyClient());
        Kms kms =
            Kms.connect(
                KmsConfig.builder()
                    .endpoints(server.endpoint())
                    .tls(current::get)
                    .addListener(listener)
                    .build())) {
      KeyHandle key = kms.keys().createAes(256).named("before").usages(KeyUsage.ENCRYPT).create();
      current.set(TestTls.context("stranger", "server"));
      PermissionDeniedException create =
          assertThrows(
              PermissionDeniedException.class,
              () -> kms.keys().createAes(256).named("after").usages(KeyUsage.ENCRYPT).create());
      assertTrue(
          create.getMessage().startsWith("create: TLS handshake rejected"), create.getMessage());
      attempts.set(0);
      assertThrows(PermissionDeniedException.class, key::attributes);
      assertEquals(1, attempts.get(), "not retried");
    }
  }

  /** A server that answers the ClientHello with a plaintext fatal access_denied alert. */
  @Test
  void anAccessDeniedAlertIsPermissionDenied() throws Exception {
    try (ServerSocket listener = new ServerSocket(0, 50, InetAddress.getLoopbackAddress())) {
      Thread server =
          new Thread(
              () -> {
                try (Socket s = listener.accept()) {
                  s.getInputStream().read(new byte[5]);
                  // TLS record: alert, legacy version 3.3, length 2, fatal (2), access_denied (49).
                  s.getOutputStream().write(new byte[] {0x15, 3, 3, 0, 2, 2, 49});
                  s.getOutputStream().flush();
                  s.getInputStream().read(new byte[4096]);
                } catch (IOException ignored) {
                }
              });
      server.setDaemon(true);
      server.start();
      PermissionDeniedException e =
          assertThrows(
              PermissionDeniedException.class,
              () ->
                  Kms.connect(
                      KmsConfig.builder()
                          .endpoints("localhost:" + listener.getLocalPort())
                          .tls(TestTls.context("client", "server"))
                          .build()));
      assertTrue(e.getMessage().contains("access_denied"), e.getMessage());
      assertFalse(Failures.serverNotTrusted(e.getCause()));
    }
  }

  // ---- protocolReason() ----

  /**
   * protocolReason() is the Result Reason under the prefix rule, and serverReason() is the
   * kms-level reason.
   */
  @Test
  void protocolReasonIsTheEscapeHatchAndReasonIsRemoved() throws Exception {
    Result result =
        new Result(
            Operation.LOCATE,
            1,
            Enums.ResultReason.SERVER_LIMIT_EXCEEDED.code(),
            "busy",
            Ttlv.structure(Tag.BATCH_ITEM, List.of()));
    KmsException busy = Failures.fromResult(READ, "get k", result, null);
    assertEquals(Optional.of(Enums.ResultReason.SERVER_LIMIT_EXCEEDED), busy.protocolReason());
    assertEquals(Optional.of(KmsReason.SERVER_BUSY), busy.serverReason());
    assertTrue(Failures.busy(busy), "the busy check reads the server's reason");
    assertEquals(Optional.empty(), new PermissionDeniedException("p").protocolReason());
    assertThrows(NoSuchMethodException.class, () -> KmsException.class.getMethod("reason"));
    assertNull(KmsException.class.getMethod("protocolReason").getAnnotation(Deprecated.class));
  }
}
