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

import static dev.keytend.kmip.interop.Catalog.*;
import static dev.keytend.kmip.interop.CatalogLiveSuite.*;
import static dev.keytend.kmip.model.Tag.*;

import dev.keytend.kmip.client.*;
import dev.keytend.kmip.codec.TtlvCodec;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.transport.*;
import java.io.*;
import java.net.*;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
import javax.net.ssl.*;

/** TLS-terminating owned fault proxy. A committed mutation is observed before its reply is lost. */
final class CatalogFaults {
  enum Mode {
    DROP_AFTER_COMMIT,
    STALL_AFTER_COMMIT,
    TRUNCATE
  }

  static final class Proxy implements AutoCloseable {
    final SSLServerSocket listener;
    final ExecutorService worker = Executors.newSingleThreadExecutor();
    final AtomicInteger requests = new AtomicInteger();
    final CountDownLatch committed = new CountDownLatch(1);
    final CatalogFixture fixture;
    final Mode mode;
    volatile Ttlv reply;
    volatile Throwable failure;
    volatile SSLSocket active;
    final Future<?> task;

    Proxy(CatalogFixture f, Mode mode) throws Exception {
      fixture = f;
      this.mode = mode;
      SSLContext server =
          Tls.context(
              f.certs.resolve("server.p12"), "changeit".toCharArray(), f.certs.resolve("ca.pem"));
      listener =
          (SSLServerSocket)
              server
                  .getServerSocketFactory()
                  .createServerSocket(0, 8, InetAddress.getLoopbackAddress());
      listener.setNeedClientAuth(true);
      listener.setSoTimeout(4000);
      task =
          worker.submit(
              () -> {
                try (SSLSocket s = (SSLSocket) listener.accept();
                    TlsTransport backend = f.transport("client")) {
                  active = s;
                  s.setSoTimeout(3000);
                  s.startHandshake();
                  Ttlv request = new TtlvCodec().read(s.getInputStream());
                  requests.incrementAndGet();
                  reply = backend.exchange(request);
                  committed.countDown();
                  if (mode == Mode.STALL_AFTER_COMMIT) {
                    try {
                      Thread.sleep(4000);
                    } catch (InterruptedException ignored) {
                      Thread.currentThread().interrupt();
                    }
                  } else if (mode == Mode.TRUNCATE) {
                    byte[] bytes = new TtlvCodec().encode(reply);
                    s.getOutputStream().write(bytes, 0, bytes.length - 1);
                    s.getOutputStream().flush();
                  }
                } catch (Throwable e) {
                  failure = e;
                  committed.countDown();
                }
              });
    }

    KmipClient client() throws Exception {
      return new KmipClient(
          new TlsTransport(
              "localhost",
              listener.getLocalPort(),
              Tls.context(
                  fixture.certs.resolve("client.p12"),
                  "changeit".toCharArray(),
                  fixture.certs.resolve("ca.pem")),
              Duration.ofMillis(300),
              Duration.ofMillis(700),
              new TtlvCodec(1024 * 1024, 32)),
          fixture.version);
    }

    Result committedResult() throws Exception {
      require(committed.await(5, TimeUnit.SECONDS), "Proxy commit observation timeout");
      if (failure != null) throw new IOException("Fault proxy backend failed", failure);
      return Messages.response(reply).results().get(0);
    }

    @Override
    public void close() throws Exception {
      listener.close();
      if (active != null) active.close();
      task.cancel(true);
      worker.shutdownNow();
      worker.awaitTermination(2, TimeUnit.SECONDS);
    }
  }

  static void execute(String id, CatalogFixture f) throws Exception {
    f.provision();
    switch (id) {
      case "RETRY-01" -> {
        // This is a real stalled TLS handshake, not an unreachable public IP assumption.
        try (ServerSocket raw = new ServerSocket(0, 8, InetAddress.getLoopbackAddress())) {
          ExecutorService e = Executors.newSingleThreadExecutor();
          try {
            Future<?> sleeper =
                e.submit(
                    () -> {
                      try (Socket accepted = raw.accept()) {
                        Thread.sleep(2000);
                      } catch (Exception ignored) {
                      }
                    });
            long start = System.nanoTime();
            try (var c =
                new KmipClient(
                    new TlsTransport(
                        "localhost",
                        raw.getLocalPort(),
                        Tls.context(
                            f.certs.resolve("client.p12"),
                            "changeit".toCharArray(),
                            f.certs.resolve("ca.pem")),
                        Duration.ofMillis(100),
                        Duration.ofMillis(100),
                        new TtlvCodec()),
                    f.version)) {
              try {
                c.get(f.knownUid);
                throw new AssertionError("Stalled TLS handshake succeeded");
              } catch (IOException expected) {
              }
            }
            require(
                System.nanoTime() - start < TimeUnit.SECONDS.toNanos(2),
                "Handshake deadline exceeded");
            sleeper.cancel(true);
            f.evidence.put(
                "fault",
                "owned TCP accept without TLS handshake; network blackhole is not simulated");
          } finally {
            e.shutdownNow();
          }
        }
      }
      case "RETRY-03", "RETRY-08" -> {
        try (Proxy proxy =
                new Proxy(f, id.equals("RETRY-08") ? Mode.TRUNCATE : Mode.DROP_AFTER_COMMIT);
            var c = proxy.client()) {
          try {
            c.get(f.knownUid);
            throw new AssertionError("Lost/truncated reply returned a key");
          } catch (IOException expected) {
          }
          proxy.committedResult().requireSuccess();
          require(proxy.requests.get() == 1, "Implicit retry after response loss");
        }
        // The application, not the SDK, explicitly chooses this one bounded read retry.
        peer(
            digest(
                    Keys.aesKey(f.client.get(f.knownUid).requirePayload(), f.knownUid, 256)
                        .getEncoded())
                .equals(f.knownSha),
            "Fresh read consumed stale response");
        f.evidence.put("retry_policy", "zero SDK retries; one explicit caller read retry");
      }
      case "RETRY-04", "RETRY-05" -> {
        String uid;
        try (Proxy proxy = new Proxy(f, Mode.DROP_AFTER_COMMIT);
            var c = proxy.client()) {
          Request mutation =
              id.equals("RETRY-04")
                  ? Requests.createSymmetricKey(
                      Enums.CryptographicAlgorithm.AES,
                      256,
                      Enums.CryptographicUsageMask.ENCRYPT,
                      Enums.CryptographicUsageMask.DECRYPT)
                  : Requests.registerObject(
                      ManagedObjects.rawSymmetricKey(known(32), Enums.CryptographicAlgorithm.AES),
                      Attributes.usage(
                          Enums.CryptographicUsageMask.ENCRYPT,
                          Enums.CryptographicUsageMask.DECRYPT));
          try {
            c.call(mutation);
            throw new AssertionError("Lost mutation reply reported success");
          } catch (IOException expected) {
          }
          Result committed = proxy.committedResult().requireSuccess();
          uid = committed.uniqueIdentifier();
          f.owned.add(uid);
          require(proxy.requests.get() == 1, "Mutation was replayed");
        }
        var ref = f.reference("get", uid);
        peer(ref.containsKey("sha256"), "Committed object not independently found");
        f.evidence.put(
            "mutation_outcome",
            "transport IOException is uncertain; proxy side channel plus independent Get reconciled"
                + " exact UID");
      }
      case "RETRY-06" -> {
        try (Proxy proxy = new Proxy(f, Mode.TRUNCATE);
            var c = proxy.client()) {
          try {
            c.get(f.knownUid);
            throw new AssertionError("Truncated lookup returned key");
          } catch (IOException expected) {
          }
          proxy.committedResult().requireSuccess();
          require(proxy.requests.get() == 1, "Lookup performed another operation");
        }
      }
      case "RETRY-07" -> {
        try (Proxy proxy = new Proxy(f, Mode.STALL_AFTER_COMMIT);
            var c = proxy.client()) {
          AtomicBoolean delivered = new AtomicBoolean();
          Thread t =
              new Thread(
                  () -> {
                    try {
                      c.get(f.knownUid);
                      delivered.set(true);
                    } catch (IOException expected) {
                    }
                  });
          t.start();
          proxy.committedResult().requireSuccess();
          t.interrupt();
          t.join(1500);
          require(
              !t.isAlive() && !delivered.get(),
              "Interrupted socket delivered late key or failed to release");
        }
      }
      case "RETRY-09" -> {
        // A reachable independent namespace with no such key is not a replica.
        try (var b = f.identity("client-b")) {
          Result r =
              b.execute(
                  Requests.get().uniqueIdentifier(f.namespace + "-missing-replica-id").build());
          peer(!r.successful(), "Missing failover key returned material");
        }
        f.evidence.put(
            "failover_policy",
            "SDK has no automatic failover; explicit alternate identity must resolve exact UID");
      }
      case "RETRY-10" ->
          outside(
              "No automatic retry, connection pool, circuit breaker or reconnect storm policy is"
                  + " shipped; application policy must be qualified separately");
      default -> throw new AssertionError("Controlled counterpart required for " + id);
    }
  }
}
