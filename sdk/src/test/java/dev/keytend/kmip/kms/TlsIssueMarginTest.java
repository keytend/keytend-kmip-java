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

import static dev.keytend.kmip.kms.TlsIssueTest.NAME;
import static dev.keytend.kmip.kms.TlsIssueTest.has;
import static dev.keytend.kmip.kms.TlsIssueTest.holdsText;
import static dev.keytend.kmip.kms.TlsIssueTest.isSwitch;
import static dev.keytend.kmip.kms.TlsIssueTest.register;
import static dev.keytend.kmip.kms.TlsIssueTest.request;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.TlsIssueTest.Ca;
import dev.keytend.kmip.kms.TlsIssueTest.Issuing;
import dev.keytend.kmip.kms.TlsIssueTest.MovingClock;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.testing.TlsListener;
import java.nio.file.Path;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * The safety margin an issued certificate must outlast at each change of the identity, checked
 * just before each change is sent, after the attempt's {@link KmsListener#started} callbacks; and
 * the shortest validity a call asks for.
 */
class TlsIssueMarginTest {
  static final Duration TIMEOUT = Duration.ofSeconds(10), DAY = Duration.ofDays(1);

  /** The changes of the identity's objects a call sends. */
  static final Operation[] CHANGES = {
    Operation.ADD_ATTRIBUTE,
    Operation.SET_ATTRIBUTE,
    Operation.MODIFY_ATTRIBUTE,
    Operation.DELETE_ATTRIBUTE,
    Operation.ACTIVATE,
    Operation.REVOKE
  };

  /** The reads a call sends. */
  static final Operation[] READS = {
    Operation.GET, Operation.GET_ATTRIBUTES, Operation.GET_ATTRIBUTE_LIST, Operation.LOCATE
  };

  /**
   * A run of {@code issuing} with a one-day validity: the requests the server processed from the
   * first issue on (none for an issue), the number of started callbacks, the identity's first
   * certificate (null for an issue), the server, and what the call threw (null for none).
   */
  record Run(
      List<Ttlv> requests,
      int started,
      String first,
      InMemoryKmipServer server,
      Exception thrown) {}

  /**
   * What a run's hooks see: the server, the Kms's clock, the requests the server processed from
   * the first issue on (Discover Versions left out) and when it processed each ({@link
   * System#nanoTime}), the started callbacks counted, whether the call under test runs, and the
   * Kms.
   */
  record Hooks(
      InMemoryKmipServer server,
      MovingClock clock,
      List<Ttlv> requests,
      List<Long> processed,
      AtomicInteger started,
      AtomicBoolean armed,
      AtomicReference<Kms> kms) {}

  /**
   * Runs {@code issuing} with a one-day validity on a new server, through the in-memory transport
   * or, with {@code tls}, the SDK's TLS transport with one pooled connection and a call timeout of
   * {@code timeout}. {@code listener} is the Kms's listener (null for none); {@code arm} sets the
   * server's hooks once the identity to reissue exists, before the call under test.
   */
  static Run run(
      Issuing issuing,
      boolean unique,
      InMemoryTlsListenerTest.Pki tls,
      Duration timeout,
      java.util.function.Function<Hooks, KmsListener> listener,
      java.util.function.Consumer<Hooks> arm)
      throws Exception {
    Ca ca = Ca.ec("Issuing CA");
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1).uniqueNames(unique);
    Hooks hooks =
        new Hooks(
            server,
            new MovingClock(),
            Collections.synchronizedList(new ArrayList<>()),
            Collections.synchronizedList(new ArrayList<>()),
            new AtomicInteger(),
            new AtomicBoolean(),
            new AtomicReference<>());
    KmsListener l = listener == null ? null : listener.apply(hooks);
    TlsListener served = tls == null ? null : tls.listener(server).start();
    try {
      KmsConfig.Builder b =
          served == null
              ? server.configure()
              : tls.client(served).poolSize(1).connectTimeout(timeout);
      b.maximumVersion(KmipVersion.V3_0).callTimeout(timeout);
      if (l != null) b.addListener(l);
      try (Kms kms = Kms.connect(b.build())) {
        hooks.kms().set(kms);
        kms.clock(hooks.clock());
        TlsIssuer issuer = register(kms, ca);
        TlsIdentityHandle h = issuing == Issuing.ISSUE ? null : request(kms, issuer).issue();
        server.injectAfterProcessing(
            request -> {
              if (!has(request, Operation.DISCOVER_VERSIONS))
                synchronized (hooks) {
                  hooks.requests().add(request);
                  hooks.processed().add(System.nanoTime());
                }
              return null;
            });
        arm.accept(hooks);
        hooks.armed().set(true);
        Exception thrown = null;
        try {
          switch (issuing) {
            case ISSUE -> request(kms, issuer).validFor(DAY).issue();
            case SAME_KEY -> h.reissue(TlsReissue.sameKey().validFor(DAY));
            case NEW_KEY -> h.reissue(TlsReissue.newKey().validFor(DAY));
          }
        } catch (KmsException e) {
          thrown = e;
        }
        hooks.armed().set(false);
        server.injectAfterProcessing(null);
        server.injectBeforeProcessing(null);
        return new Run(
            List.copyOf(hooks.requests()),
            hooks.started().get(),
            h == null ? null : h.certificate().id(),
            server,
            thrown);
      }
    } finally {
      if (served != null) served.close();
    }
  }

  /**
   * Runs {@code issuing} with a one-day validity on a new server, the Kms's clock moved {@code
   * ahead} inside the {@link KmsListener#started} callback of request {@code at} (counted as {@link
   * Run#requests} are), before that request is sent; {@code at} below 0 moves nothing.
   */
  static Run startedAt(Issuing issuing, int at, Duration ahead, boolean unique) throws Exception {
    return run(
        issuing,
        unique,
        null,
        TIMEOUT,
        hooks ->
            new KmsListener() {
              @Override
              public void started(KmsEvent event) {
                if (!hooks.armed().get()) return;
                hooks.started().incrementAndGet();
                // The callback of the attempt that sends request "at": the server has processed
                // the ones before it.
                if (hooks.requests().size() == at) hooks.clock().ahead = ahead;
              }
            },
        hooks -> {});
  }

  /**
   * Runs {@code issuing} where request {@code lose} (counted as {@link Run#requests} are) fails
   * before the server processes it, the Kms's clock moved {@code ahead} meanwhile. With {@code
   * notSent}, it fails as not sent, and the Kms retries it (a read); otherwise its reply is lost,
   * and the call reads whether it took effect and, as it did not, sends it again (a change).
   */
  static Run lostAt(Issuing issuing, int lose, Duration ahead, boolean unique, boolean notSent)
      throws Exception {
    return run(
        issuing,
        unique,
        null,
        TIMEOUT,
        null,
        hooks ->
            hooks
                .server()
                .injectBeforeProcessing(
                    request -> {
                      if (!hooks.armed().get()
                          || hooks.requests().size() != lose
                          || has(request, Operation.DISCOVER_VERSIONS)) return null;
                      hooks.clock().ahead = ahead;
                      return notSent
                          ? new dev.keytend.kmip.transport.RequestNotSentException(
                              "connection refused", new java.net.ConnectException("refused"))
                          : new java.net.SocketTimeoutException("reply lost");
                    }));
  }

  /** The call timeout of the runs over TLS: the deadline of the whole call. */
  static final Duration TLS_TIMEOUT = Duration.ofSeconds(3);

  /** A run over TLS, and when the request waited at was processed after its check (null: never). */
  record Waited(Run run, Duration sentAfter) {}

  /**
   * Runs {@code issuing} over TLS with one pooled connection, which another caller's Discover
   * Versions (through a view with a long timeout) holds for {@code hold} from the started callback
   * of request {@code at} on: that request's check passes, and then it waits for the connection.
   * {@code at} below 0 holds nothing.
   */
  static Waited waitingAt(Issuing issuing, int at, Duration hold, InMemoryTlsListenerTest.Pki pki)
      throws Exception {
    Thread caller = Thread.currentThread();
    AtomicBoolean fired = new AtomicBoolean();
    CountDownLatch received = new CountDownLatch(1);
    AtomicReference<Long> checked = new AtomicReference<>();
    AtomicReference<Hooks> seen = new AtomicReference<>();
    Run run =
        run(
            issuing,
            false,
            pki,
            TLS_TIMEOUT,
            hooks ->
                new KmsListener() {
                  @Override
                  public void started(KmsEvent event) {
                    if (!hooks.armed().get()
                        || Thread.currentThread() != caller
                        || hooks.requests().size() != at
                        || !fired.compareAndSet(false, true)) return;
                    hooks.server().slowReplyDelay(hold);
                    hooks.server().failNext(ServerOperation.DISCOVER_VERSIONS, Fault.SLOW);
                    Kms longer = hooks.kms().get().withTimeout(Duration.ofSeconds(30));
                    Thread holder =
                        new Thread(
                            () -> {
                              try {
                                longer.ping();
                              } catch (RuntimeException closed) {
                                // the Kms closed under it at the end of the run
                              }
                            },
                            "holder");
                    holder.setDaemon(true);
                    holder.start();
                    try {
                      assertTrue(received.await(10, TimeUnit.SECONDS), "the holder's request");
                    } catch (InterruptedException e) {
                      Thread.currentThread().interrupt();
                    }
                    // The callback ends: the request's check runs now, then it waits.
                    checked.set(System.nanoTime());
                  }
                },
            hooks -> {
              seen.set(hooks);
              hooks
                  .server()
                  .injectBeforeProcessing(
                      request -> {
                        if (fired.get() && has(request, Operation.DISCOVER_VERSIONS))
                          received.countDown();
                        return null;
                      });
            });
    Hooks hooks = seen.get();
    Duration sentAfter = null;
    synchronized (hooks) {
      if (at >= 0 && checked.get() != null && hooks.processed().size() > at)
        sentAfter = Duration.ofNanos(hooks.processed().get(at) - checked.get());
    }
    return new Waited(run, sentAfter);
  }

  /**
   * That {@code slow} stopped at the guarded change {@code at}, the switch being request {@code
   * sw}: neither it nor any change after it was sent. At the switch, the certificate is refused as
   * too short-lived, with nothing of the identity changed; after it, the call stops with what it
   * replaced still Active. {@code expired} says whether the clock went past the notAfter, or into
   * the margin.
   */
  static void assertStopped(Run slow, int at, int sw, boolean expired, String where) {
    Duration margin = TlsIssue.margin(TIMEOUT);
    assertNotNull(slow.thrown(), where);
    String m = slow.thrown().getMessage();
    assertTrue(
        m.contains(expired ? "expired at" : "within the safety margin of " + margin),
        where + ": " + m);
    for (int i = at; i < slow.requests().size(); i++)
      assertFalse(has(slow.requests().get(i), CHANGES), where + ": a change sent at " + i);
    InMemoryKmipServer server = slow.server();
    if (at == sw) {
      assertInstanceOf(KeyMismatchException.class, slow.thrown(), where);
      assertTrue(m.contains("is too short-lived to use safely"), where + ": " + m);
      assertTrue(m.contains("before the switch"), where + ": " + m);
      assertTrue(
          m.contains(
              "Ask for a longer validity (validFor), or call through a Kms with a shorter call"
                  + " timeout"),
          where + ": " + m);
      assertFalse(m.contains("is not what was requested"), where + ": " + m);
      if (slow.first() != null) {
        assertEquals(List.of(), server.links(slow.first(), LinkKind.REPLACEMENT), where);
        assertEquals(KeyState.ACTIVE, server.state(slow.first()).orElseThrow(), where);
      } else for (String id : server.ids()) assertFalse(server.names(id).contains(NAME), where);
      return;
    }
    assertInstanceOf(StateConflictException.class, slow.thrown(), where);
    assertTrue(m.contains("this call's switch"), where + ": " + m);
    if (slow.first() != null)
      assertEquals(KeyState.ACTIVE, server.state(slow.first()).orElseThrow(), where);
  }

  /** The changes among {@code run}'s requests. */
  static long changes(Run run) {
    return run.requests().stream().filter(r -> has(r, CHANGES)).count();
  }

  /**
   * The guarded changes of a run where nothing was slow: the switch (the Replacement Object link,
   * or an issue's name), a kept key's link, each activation, the first change of the name's move
   * and the first deactivation (for an issue, its certificate's Activate is the last), by request.
   */
  static List<Integer> guarded(Issuing issuing, Run plain) {
    List<Ttlv> r = plain.requests();
    List<Integer> out = new ArrayList<>();
    int sw = -1;
    for (int i = 0; i < r.size(); i++)
      if (isSwitch(issuing, r.get(i))) {
        sw = i;
        break;
      }
    assertTrue(sw > 0, "no switch");
    out.add(sw);
    boolean activated = false, moved = issuing == Issuing.ISSUE;
    for (int i = sw + 1; i < r.size(); i++) {
      Ttlv q = r.get(i);
      if (has(q, Operation.ACTIVATE)) {
        out.add(i);
        activated = true;
      } else if (!activated && issuing == Issuing.SAME_KEY && has(q, Operation.ADD_ATTRIBUTE))
        out.add(i); // the kept key's Certificate link to the new certificate
      else if (activated
          && !moved
          && has(q, Operation.ADD_ATTRIBUTE, Operation.SET_ATTRIBUTE)
          && holdsText(q, NAME)) {
        out.add(i); // the first change of the name's move: the name, or its record
        moved = true;
      } else if (has(q, Operation.REVOKE)) {
        out.add(i);
        break;
      }
    }
    return out;
  }

  /**
   * Each guarded change, with the Kms's clock moved inside the started callback of its own
   * attempt, after any earlier check: past the certificate's notAfter, or within the safety margin
   * of it. The change is not sent, nor is any change after it. At the switch, the certificate is
   * refused with nothing of the identity changed; after it, the call stops with what it replaced
   * still Active.
   */
  @ParameterizedTest
  @CsvSource({
    "ISSUE, false",
    "ISSUE, true",
    "SAME_KEY, false",
    "SAME_KEY, true",
    "NEW_KEY, false",
    "NEW_KEY, true"
  })
  void aSlowStartedCallbackBeforeAnyGuardedChangeKeepsItFromBeingSent(
      Issuing issuing, boolean unique) throws Exception {
    Run plain = startedAt(issuing, -1, Duration.ZERO, unique);
    assertNull(plain.thrown(), () -> String.valueOf(plain.thrown()));
    // One started callback per request: the index of a request is that of its attempt.
    assertEquals(plain.requests().size(), plain.started());
    List<Integer> guarded = guarded(issuing, plain);
    int sw = guarded.get(0);
    Duration margin = TlsIssue.margin(TIMEOUT);
    for (Duration ahead : List.of(Duration.ofDays(2), DAY.minus(margin.dividedBy(2)))) {
      boolean expired = ahead.compareTo(DAY) > 0;
      for (int at : guarded) {
        Run slow = startedAt(issuing, at, ahead, unique);
        assertStopped(
            slow,
            at,
            sw,
            expired,
            issuing + " slow in the callback of request " + at + " (switch at " + sw + ")");
      }
    }
  }

  /**
   * A change sent again after a lost reply is checked again just before it goes out: the reply to
   * each guarded change is lost before the server processes it, and the Kms's clock moves into the
   * margin meanwhile. The call reads that the change did not take effect, and does not send it
   * again, nor any change after it. With the clock left alone, it sends the change again and
   * finishes.
   */
  @ParameterizedTest
  @CsvSource({
    "ISSUE, false",
    "ISSUE, true",
    "SAME_KEY, false",
    "SAME_KEY, true",
    "NEW_KEY, false",
    "NEW_KEY, true"
  })
  void aChangeSentAgainAfterALostReplyIsCheckedAgain(Issuing issuing, boolean unique)
      throws Exception {
    Run plain = startedAt(issuing, -1, Duration.ZERO, unique);
    assertNull(plain.thrown(), () -> String.valueOf(plain.thrown()));
    List<Integer> guarded = guarded(issuing, plain);
    int sw = guarded.get(0);
    Duration within = DAY.minus(TlsIssue.margin(TIMEOUT).dividedBy(2));
    for (int at : guarded) {
      String where = issuing + " reply lost at request " + at + " (switch at " + sw + ")";
      Run resent = lostAt(issuing, at, Duration.ZERO, unique, false);
      assertNull(resent.thrown(), () -> where + ": " + resent.thrown());
      assertEquals(changes(plain), changes(resent), where + ": the lost change sent again");
      assertStopped(lostAt(issuing, at, within, unique, false), at, sw, false, where);
    }
  }

  /**
   * A read that the Kms retries just before a guarded change, the Kms's clock moved into the
   * margin while its first attempt fails: the change is checked when it goes out, after the
   * retry, and is not sent.
   */
  @ParameterizedTest
  @CsvSource({"ISSUE", "SAME_KEY", "NEW_KEY"})
  void aReadRetriedBeforeAGuardedChangeDoesNotCarryItPastTheCheck(Issuing issuing)
      throws Exception {
    Run plain = startedAt(issuing, -1, Duration.ZERO, false);
    List<Integer> guarded = guarded(issuing, plain);
    int sw = guarded.get(0);
    Duration within = DAY.minus(TlsIssue.margin(TIMEOUT).dividedBy(2));
    int tested = 0;
    for (int k = 0; k < guarded.size(); k++) {
      int at = guarded.get(k), after = k == 0 ? -1 : guarded.get(k - 1);
      int read = -1;
      for (int i = at - 1; i > after && read < 0; i--)
        if (has(plain.requests().get(i), READS)) read = i;
      if (read < 0) continue;
      String where =
          issuing + " read " + read + " retried before request " + at + " (switch at " + sw + ")";
      assertStopped(lostAt(issuing, read, within, false, true), at, sw, false, where);
      tested++;
    }
    assertTrue(tested >= guarded.size() - 1, issuing + ": " + tested + " of " + guarded);
  }

  /**
   * A guarded change that waits for a connection after its check: the Kms's only pooled
   * connection is busy with another caller's request. A wait that ends within the call's deadline
   * sends the change within one call timeout of its check, which the margin allows for; a wait
   * that outlasts the deadline sends nothing, and the call stops there.
   */
  @ParameterizedTest
  @CsvSource({"ISSUE", "SAME_KEY", "NEW_KEY"})
  void aChangeThatWaitsForAConnectionIsSentWithinTheCallDeadlineOrNotAtAll(
      Issuing issuing, @TempDir Path dir) throws Exception {
    InMemoryTlsListenerTest.Pki pki = new InMemoryTlsListenerTest.Pki(dir);
    Run plain = waitingAt(issuing, -1, Duration.ZERO, pki).run();
    assertNull(plain.thrown(), () -> String.valueOf(plain.thrown()));
    List<Integer> guarded = guarded(issuing, plain);
    int sw = guarded.get(0);
    for (int at : guarded) {
      String where = issuing + " waiting at request " + at + " (switch at " + sw + ")";
      Waited w = waitingAt(issuing, at, Duration.ofMillis(300), pki);
      assertNull(w.run().thrown(), () -> where + ": " + w.run().thrown());
      assertNotNull(w.sentAfter(), where);
      assertTrue(w.sentAfter().compareTo(Duration.ofMillis(250)) >= 0, where + ": " + w);
      assertTrue(w.sentAfter().compareTo(TLS_TIMEOUT) < 0, where + ": " + w);
    }
    for (int at : List.of(sw, guarded.get(1))) {
      String where = issuing + " waiting past the deadline at " + at + " (switch at " + sw + ")";
      Waited w = waitingAt(issuing, at, TLS_TIMEOUT.multipliedBy(2), pki);
      Run slow = w.run();
      assertNotNull(slow.thrown(), where);
      assertNull(w.sentAfter(), where);
      for (int i = at; i < slow.requests().size(); i++)
        assertFalse(has(slow.requests().get(i), CHANGES), where + ": a change sent at " + i);
      if (slow.first() != null)
        assertEquals(KeyState.ACTIVE, slow.server().state(slow.first()).orElseThrow(), where);
    }
  }

  /** A certificate with more than the margin left goes on. */
  @Test
  void aCertificateThatOutlastsTheMarginIsUsed() throws Exception {
    Run plain = startedAt(Issuing.NEW_KEY, -1, Duration.ZERO, false);
    int sw = guarded(Issuing.NEW_KEY, plain).get(0);
    Duration ahead = DAY.minus(TlsIssue.margin(TIMEOUT).multipliedBy(2));
    Run run = startedAt(Issuing.NEW_KEY, sw, ahead, false);
    assertNull(run.thrown(), () -> String.valueOf(run.thrown()));
    assertEquals(KeyState.DEACTIVATED, run.server().state(run.first()).orElseThrow());
  }

  @Test
  void theMarginAndTheShortestValidityFollowTheCallTimeout() {
    assertEquals(Duration.ofMinutes(5).plusSeconds(20), TlsIssue.margin(TIMEOUT));
    assertEquals(Duration.ofMinutes(10).plusSeconds(30), TlsIssue.shortestValidity(TIMEOUT));
    assertEquals(Duration.ofMinutes(25), TlsIssue.margin(Duration.ofMinutes(10)));
    assertEquals(Duration.ofMinutes(40), TlsIssue.shortestValidity(Duration.ofMinutes(10)));
  }

  /**
   * A validity shorter than the margin leaves room for is refused before anything is sent, by the
   * call timeout of the Kms the call runs on: a view's for a call through one.
   */
  @Test
  void aValidityTooShortForTheMarginIsRefusedBeforeAnythingIsSent() throws Exception {
    Ca ca = Ca.ec("Issuing CA");
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    try (Kms kms = TlsIdentityTest.connect(server)) {
      TlsIssuer issuer = register(kms, ca);
      AtomicInteger sent = new AtomicInteger();
      server.injectAfterProcessing(
          request -> {
            sent.incrementAndGet();
            return null;
          });
      Duration shortest = TlsIssue.shortestValidity(kms.callTimeout());
      InvalidRequestException e =
          assertThrows(
              InvalidRequestException.class,
              () -> request(kms, issuer).validFor(shortest.minusSeconds(1)).issue());
      assertTrue(e.getMessage().contains("is shorter than " + shortest), e.getMessage());
      assertTrue(e.getMessage().contains("Nothing was changed"), e.getMessage());
      assertEquals(0, sent.get(), "nothing sent");
      TlsIdentityHandle h = request(kms, issuer).validFor(shortest).issue();
      // Through a view with a longer timeout, the same validity is too short.
      Kms view = kms.withTimeout(Duration.ofMinutes(1));
      TlsIdentityHandle viewed = view.tls().identity(NAME).orElseThrow();
      sent.set(0);
      for (TlsReissue how :
          List.of(
              TlsReissue.sameKey().validFor(shortest), TlsReissue.newKey().validFor(shortest))) {
        InvalidRequestException tooShort =
            assertThrows(InvalidRequestException.class, () -> viewed.reissue(how));
        assertTrue(
            tooShort
                .getMessage()
                .contains("is shorter than " + TlsIssue.shortestValidity(Duration.ofMinutes(1))),
            tooShort.getMessage());
      }
      assertEquals(0, sent.get(), "nothing sent");
      server.injectAfterProcessing(null);
      assertEquals(h.certificate().id(), kms.tls().identity(NAME).orElseThrow().certificate().id());
    }
  }
}
