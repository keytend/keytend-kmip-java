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

import static dev.keytend.kmip.kms.TlsIdentityTest.HOURLY;
import static dev.keytend.kmip.kms.TlsIdentityTest.SCHEDULER;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.client.Messages;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Operation;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.net.ConnectException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Known unsafe states survive retries and mixed Get Attributes batches. */
class TlsSafetyRegressionTest {
  static final String NAME = "tls-safety/node";

  static Kms connect(InMemoryKmipServer server, KmipTransport transport) {
    return Kms.connect(
        server
            .configure()
            .maximumVersion(KmipVersion.V3_0)
            .retryPolicy(RetryPolicy.none())
            .transport(e -> transport)
            .build());
  }

  static Stream<Arguments> loaderStates() {
    return Stream.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0)
        .flatMap(
            version ->
                Stream.of(false, true)
                    .flatMap(
                        unique ->
                            Stream.of(
                                    KeyState.COMPROMISED,
                                    KeyState.DESTROYED,
                                    KeyState.DESTROYED_COMPROMISED)
                                .flatMap(
                                    state ->
                                        Stream.of(false, true)
                                            .map(
                                                shared ->
                                                    Arguments.of(
                                                        version, unique, state, shared)))));
  }

  static Stream<Arguments> fetchStates() {
    return Stream.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0)
        .flatMap(
            version ->
                Stream.of(false, true)
                    .flatMap(
                        unique ->
                            Stream.of(KeyState.DESTROYED, KeyState.DESTROYED_COMPROMISED)
                                .flatMap(
                                    state ->
                                        Stream.of(false, true)
                                            .flatMap(
                                                shared ->
                                                    (version == KmipVersion.V1_4
                                                            ? Stream.of(
                                                                Enums.ResultReason.ITEM_NOT_FOUND)
                                                            : Stream.of(
                                                                Enums.ResultReason.ITEM_NOT_FOUND,
                                                                Enums.ResultReason
                                                                    .OBJECT_DESTROYED))
                                                        .map(
                                                            reason ->
                                                                Arguments.of(
                                                                    version, unique, state, shared,
                                                                    reason))))));
  }

  @ParameterizedTest
  @MethodSource("fetchStates")
  void aMissingKeyAtFetchTimeCannotRemainPresented(
      KmipVersion version,
      boolean unique,
      KeyState unsafeState,
      boolean sharedKey,
      Enums.ResultReason reason)
      throws Exception {
    checkLoaderRefusal(version, unique, unsafeState, sharedKey, reason);
  }

  @ParameterizedTest
  @MethodSource("loaderStates")
  void aLoadersUnsafeStateAppliesToEveryAliasOfThatKey(
      KmipVersion version, boolean unique, KeyState unsafeState, boolean sharedKey)
      throws Exception {
    checkLoaderRefusal(version, unique, unsafeState, sharedKey, null);
  }

  private void checkLoaderRefusal(
      KmipVersion version,
      boolean unique,
      KeyState unsafeState,
      boolean sharedKey,
      Enums.ResultReason fetchReason)
      throws Exception {
    try (var server = InMemoryKmipServer.of(version).uniqueNames(unique);
        var writer =
            Kms.connect(
                server
                    .configure()
                    .maximumVersion(KmipVersion.V3_0)
                    .retryPolicy(RetryPolicy.none())
                    .build())) {
      var ca = TestPki.ca("loader root");
      var pair = TestPki.ec();
      var initial =
          writer
              .tls()
              .register(pair.getPrivate(), TestPki.leaf("node", pair, ca).chain(ca))
              .named(NAME)
              .register();
      AtomicBoolean armed = new AtomicBoolean(),
          loadedCertificate = new AtomicBoolean(),
          checkedKey = new AtomicBoolean();
      AtomicBoolean injected = new AtomicBoolean(), delivered = new AtomicBoolean();
      java.util.concurrent.atomic.AtomicReference<KeyHandle> target =
          new java.util.concurrent.atomic.AtomicReference<>();
      java.util.concurrent.atomic.AtomicReference<String> targetCertificate =
          new java.util.concurrent.atomic.AtomicReference<>();
      List<String> changes = new ArrayList<>();
      KmsListener listener =
          new KmsListener() {
            @Override
            public void keyStateChanged(String id, KeyState from, KeyState to) {
              changes.add(id + " " + from + "->" + to);
            }
          };
      KmipTransport transport =
          new KmipTransport() {
            @Override
            public Ttlv exchange(Ttlv request) throws IOException {
              return exchange(request, CallContext.NONE);
            }

            @Override
            public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
              var items = request.children(Tag.BATCH_ITEM);
              boolean checking =
                  armed.get()
                      && loadedCertificate.get()
                      && items.size() == 1
                      && items.get(0).require(Tag.OPERATION).intValue()
                          == Operation.GET_ATTRIBUTES.code()
                      && items
                          .get(0)
                          .require(Tag.REQUEST_PAYLOAD)
                          .require(Tag.UNIQUE_IDENTIFIER)
                          .textValue()
                          .equals(target.get().id());
              boolean fetching =
                  armed.get()
                      && checkedKey.get()
                      && items.size() == 1
                      && items.get(0).require(Tag.OPERATION).intValue() == Operation.GET.code()
                      && items
                          .get(0)
                          .require(Tag.REQUEST_PAYLOAD)
                          .require(Tag.UNIQUE_IDENTIFIER)
                          .textValue()
                          .equals(target.get().id());
              boolean loading = fetchReason == null ? checking : fetching;
              if (loading && injected.compareAndSet(false, true)) {
                if (unsafeState == KeyState.DESTROYED)
                  target.get().revoke(RevocationReason.cessationOfOperation("retired"));
                else target.get().revoke(RevocationReason.keyCompromise("exposed", Instant.now()));
                if (unsafeState != KeyState.COMPROMISED) target.get().destroy();
                if (fetchReason == Enums.ResultReason.OBJECT_DESTROYED)
                  server.failNext(ServerOperation.GET, fetchReason);
              }
              Ttlv response = server.exchange(request, context);
              if (armed.get()
                  && items.size() == 1
                  && items.get(0).require(Tag.OPERATION).intValue() == Operation.GET.code()
                  && items
                      .get(0)
                      .require(Tag.REQUEST_PAYLOAD)
                      .require(Tag.UNIQUE_IDENTIFIER)
                      .textValue()
                      .equals(targetCertificate.get())) loadedCertificate.set(true);
              if (checking) checkedKey.set(true);
              if (loading)
                delivered.set(
                    fetchReason == null
                        ? KeyHandle.readAttributes(Messages.response(response).results().get(0))
                                .state()
                            == unsafeState
                        : Messages.response(response).results().get(0).hasReason(fetchReason));
              return response;
            }
          };
      try (var reader =
              Kms.connect(
                  server
                      .configure()
                      .maximumVersion(KmipVersion.V3_0)
                      .retryPolicy(RetryPolicy.none())
                      .transport(e -> transport)
                      .addListener(listener)
                      .build());
          var follower = reader.tls().follow(NAME, HOURLY, SCHEDULER)) {
        String previousAlias = follower.keyManager().chooseServerAlias("EC", null, null);
        var held = initial.renew(TestPki.leaf("node", pair, ca).chain(ca));
        assertEquals(TlsIdentityFollower.Status.CURRENT, follower.refresh().status());
        String heldAlias = follower.keyManager().chooseServerAlias("EC", null, null);
        assertNotEquals(previousAlias, heldAlias);
        assertNotNull(
            follower.keyManager().getPrivateKey(previousAlias), "safe previous alias is retained");
        var replacementPair = sharedKey ? pair : TestPki.ec();
        var replacement =
            sharedKey
                ? held.renew(TestPki.leaf("node", replacementPair, ca).chain(ca))
                : held.rekey(
                    replacementPair.getPrivate(),
                    TestPki.leaf("node", replacementPair, ca).chain(ca));
        target.set(replacement.privateKey());
        targetCertificate.set(replacement.certificate().id());
        changes.clear();
        armed.set(true);
        var result = follower.refresh();
        assertEquals(TlsIdentityFollower.Status.STALE, result.status(), result.toString());
        KmsException failure;
        if (fetchReason == null) {
          var conflict =
              assertInstanceOf(StateConflictException.class, result.failure().orElseThrow());
          assertEquals(unsafeState, conflict.observedState().orElseThrow());
          failure = conflict;
        } else {
          failure = assertInstanceOf(NotFoundException.class, result.failure().orElseThrow());
          assertEquals(fetchReason, failure.protocolReason().orElseThrow());
          assertEquals(unsafeState, server.state(target.get().id()).orElseThrow());
        }
        assertEquals(target.get().id(), failure.objectId().orElseThrow());
        assertTrue(injected.get());
        assertTrue(delivered.get(), "the loader received the state or not-found refusal");
        if (sharedKey) {
          assertNothingPresented(follower, heldAlias);
          assertNull(follower.keyManager().getPrivateKey(previousAlias));
          assertNull(follower.keyManager().getCertificateChain(previousAlias));
          if (fetchReason == null)
            assertTrue(
                changes.contains(target.get().id() + " ACTIVE->" + unsafeState),
                changes.toString());
          else
            assertTrue(
                changes.stream().noneMatch(c -> c.startsWith(target.get().id() + " ")),
                "a not-found reason alone does not establish a lifecycle state: " + changes);
        } else {
          assertNothingPresented(follower, heldAlias);
          assertNull(
              follower.keyManager().getPrivateKey(previousAlias),
              "a distinct unsafe replacement cannot justify signing with the Deactivated held key");
        }
        changes.clear();
        server.unreachable(true);
        assertEquals(TlsIdentityFollower.Status.STALE, follower.refresh().status());
        assertNothingPresented(follower, heldAlias);
        assertTrue(changes.isEmpty(), "an outage does not repeat state-change events");
        if (sharedKey && fetchReason != null) {
          armed.set(false);
          server.unreachable(false);
          follower.refresh();
          assertNothingPresented(follower, heldAlias);
          assertTrue(
              changes.contains(target.get().id() + " ACTIVE->" + unsafeState),
              "later actual state read is reported");
          changes.clear();
          follower.refresh();
          assertTrue(changes.isEmpty(), "actual unsafe state is reported once");
        }
      }
    }
  }

  static void assertNothingPresented(TlsIdentityFollower follower, String oldAlias) {
    assertTrue(follower.identity().isEmpty(), follower.state().toString());
    assertNull(follower.keyManager().chooseServerAlias("EC", null, null));
    assertNull(follower.keyManager().chooseClientAlias(new String[] {"EC"}, null, null));
    assertNull(follower.keyManager().getPrivateKey(oldAlias));
    assertNull(follower.keyManager().getCertificateChain(oldAlias));
  }

  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void aRetryCannotForgetTheHeldKeysCompromise(KmipVersion version, boolean unique)
      throws Exception {
    try (var server = InMemoryKmipServer.of(version).uniqueNames(unique)) {
      AtomicBoolean armed = new AtomicBoolean(), sawCompromise = new AtomicBoolean();
      AtomicInteger locates = new AtomicInteger();
      KmipTransport transport =
          new KmipTransport() {
            @Override
            public Ttlv exchange(Ttlv request) throws IOException {
              return exchange(request, CallContext.NONE);
            }

            @Override
            public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
              int operation = request.require(Tag.BATCH_ITEM).require(Tag.OPERATION).intValue();
              if (armed.get()
                  && operation == Operation.LOCATE.code()
                  && locates.incrementAndGet() >= 2)
                throw new ConnectException("second identity read unavailable");
              Ttlv response = server.exchange(request, context);
              if (armed.get() && operation == Operation.GET_ATTRIBUTES.code())
                for (var result : Messages.response(response).results())
                  if (result.successful()
                      && KeyHandle.readAttributes(result).state() == KeyState.COMPROMISED)
                    sawCompromise.set(true);
              return response;
            }
          };
      try (Kms kms = connect(server, transport)) {
        var ca = TestPki.ca("retry root");
        var first = TestPki.ec();
        var second = TestPki.ec();
        var old =
            kms.tls()
                .register(first.getPrivate(), TestPki.leaf("node", first, ca).chain(ca))
                .named(NAME)
                .register();
        try (var follower = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
          String alias = follower.keyManager().chooseServerAlias("EC", null, null);
          var replacement =
              old.rekey(second.getPrivate(), TestPki.leaf("node", second, ca).chain(ca));
          old.privateKey().revoke(RevocationReason.keyCompromise("exposed", Instant.now()));
          replacement.revoke(RevocationReason.cessationOfOperation("retired replacement"));
          armed.set(true);
          assertEquals(TlsIdentityFollower.Status.STALE, follower.refresh().status());
          assertTrue(
              sawCompromise.get(), "the first read delivered the held key's Compromised state");
          assertEquals(2, locates.get(), "the follower still performs a fresh second read");
          assertNothingPresented(follower, alias);
          // A later outage must not resurrect the discarded pair.
          server.unreachable(true);
          assertEquals(TlsIdentityFollower.Status.STALE, follower.refresh().status());
          assertNothingPresented(follower, alias);
        }
      }
    }
  }

  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void successfulUnsafeItemsSurviveAnErrorBeforeOrAfterThem(KmipVersion version, boolean unique)
      throws Exception {
    checkMixedBatch(version, unique, false);
  }

  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void missingItemsSurviveAnErrorBeforeOrAfterThem(KmipVersion version, boolean unique)
      throws Exception {
    checkMixedBatch(version, unique, true);
  }

  private void checkMixedBatch(KmipVersion version, boolean unique, boolean missing)
      throws Exception {
    for (int failureIndex : List.of(0, 1)) {
      try (var server = InMemoryKmipServer.of(version).uniqueNames(unique)) {
        AtomicBoolean armed = new AtomicBoolean(),
            outage = new AtomicBoolean(),
            sawCompromise = new AtomicBoolean();
        KmipTransport transport =
            new KmipTransport() {
              @Override
              public Ttlv exchange(Ttlv request) throws IOException {
                return exchange(request, CallContext.NONE);
              }

              @Override
              public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
                if (outage.get()) throw new ConnectException("unavailable after mixed batch");
                Ttlv response = server.exchange(request, context);
                if (armed.get()
                    && request.children(Tag.BATCH_ITEM).size() > 1
                    && request.require(Tag.BATCH_ITEM).require(Tag.OPERATION).intValue()
                        == Operation.GET_ATTRIBUTES.code()) {
                  var results = Messages.response(response).results();
                  assertEquals(
                      KeyState.COMPROMISED,
                      KeyHandle.readAttributes(results.get(1 - failureIndex)).state());
                  sawCompromise.set(true);
                  List<Ttlv> fields = new ArrayList<>();
                  for (Ttlv field : response.children(Tag.BATCH_ITEM).get(failureIndex).children())
                    if (field.tag() != Tag.RESPONSE_PAYLOAD.code()
                        && field.tag() != Tag.RESULT_STATUS.code()
                        && field.tag() != Tag.RESULT_REASON.code()
                        && field.tag() != Tag.RESULT_MESSAGE.code()) fields.add(field);
                  fields.add(
                      Ttlv.enumeration(Tag.RESULT_STATUS, Enums.ResultStatus.OPERATION_FAILED));
                  fields.add(
                      Ttlv.enumeration(Tag.RESULT_REASON, Enums.ResultReason.PERMISSION_DENIED));
                  List<Ttlv> top = new ArrayList<>();
                  int index = 0;
                  for (Ttlv field : response.children()) {
                    if (field.tag() != Tag.BATCH_ITEM.code()) top.add(field);
                    else if (index++ == failureIndex)
                      top.add(Ttlv.structure(Tag.BATCH_ITEM, fields));
                    else if (!missing) top.add(field);
                    else {
                      List<Ttlv> absent = new ArrayList<>();
                      for (Ttlv part : field.children())
                        if (part.tag() != Tag.RESPONSE_PAYLOAD.code()
                            && part.tag() != Tag.RESULT_STATUS.code()
                            && part.tag() != Tag.RESULT_REASON.code()
                            && part.tag() != Tag.RESULT_MESSAGE.code()) absent.add(part);
                      absent.add(
                          Ttlv.enumeration(Tag.RESULT_STATUS, Enums.ResultStatus.OPERATION_FAILED));
                      absent.add(
                          Ttlv.enumeration(Tag.RESULT_REASON, Enums.ResultReason.ITEM_NOT_FOUND));
                      top.add(Ttlv.structure(Tag.BATCH_ITEM, absent));
                    }
                  }
                  outage.set(true);
                  return Ttlv.structure(response.tag(), top);
                }
                return response;
              }
            };
        try (Kms kms = connect(server, transport)) {
          var ca = TestPki.ca("mixed root");
          var pair = TestPki.ec();
          var identity =
              kms.tls()
                  .register(pair.getPrivate(), TestPki.leaf("node", pair, ca).chain(ca))
                  .named(NAME)
                  .register();
          try (var follower = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
            String alias = follower.keyManager().chooseServerAlias("EC", null, null);
            identity.revoke(RevocationReason.keyCompromise("exposed", Instant.now()));
            armed.set(true);
            assertEquals(TlsIdentityFollower.Status.STALE, follower.refresh().status());
            assertTrue(sawCompromise.get(), "a correlated successful item states Compromised");
            assertNothingPresented(follower, alias);
          }
        }
      }
    }
  }

  @ParameterizedTest
  @org.junit.jupiter.params.provider.EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void successesFromAnEarlierBatchChunkSurviveALaterOutage(KmipVersion version) throws Exception {
    try (var server = InMemoryKmipServer.of(version)) {
      AtomicBoolean armed = new AtomicBoolean(), outage = new AtomicBoolean();
      AtomicInteger batches = new AtomicInteger();
      KmipTransport transport =
          new KmipTransport() {
            @Override
            public Ttlv exchange(Ttlv request) throws IOException {
              return exchange(request, CallContext.NONE);
            }

            @Override
            public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
              if (outage.get()) throw new ConnectException("outage after first chunk");
              if (armed.get()
                  && request.require(Tag.BATCH_ITEM).require(Tag.OPERATION).intValue()
                      == Operation.GET_ATTRIBUTES.code()
                  && batches.incrementAndGet() == 2) {
                outage.set(true);
                throw new ConnectException("second chunk unavailable");
              }
              return server.exchange(request, context);
            }
          };
      try (Kms kms = connect(server, transport)) {
        var key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
        var other = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
        key.revoke(RevocationReason.keyCompromise("exposed", Instant.now()));
        List<String> ids =
            new ArrayList<>(java.util.Collections.nCopies(Messages.MAX_BATCH_ITEMS, key.id()));
        ids.add(other.id());
        java.util.Map<String, KeyAttributes> observed = new java.util.HashMap<>();
        armed.set(true);
        assertThrows(
            TransientException.class, () -> TlsIdentities.readAll(kms.keys(), ids, observed));
        assertEquals(2, batches.get());
        assertEquals(
            KeyState.COMPROMISED,
            observed.get(key.id()).state(),
            "the earlier successful chunk is retained");
      }
    }
  }

  @ParameterizedTest
  @MethodSource("dev.keytend.kmip.kms.TlsIdentityTest#servers")
  void aSuccessfulReplacementDoesNotRetainAKnownCompromisedPreviousAlias(
      KmipVersion version, boolean unique) throws Exception {
    try (var server = InMemoryKmipServer.of(version).uniqueNames(unique);
        Kms kms = TlsIdentityTest.connect(server)) {
      var ca = TestPki.ca("replacement root");
      var first = TestPki.ec();
      var second = TestPki.ec();
      var identity =
          kms.tls()
              .register(first.getPrivate(), TestPki.leaf("node", first, ca).chain(ca))
              .named(NAME)
              .register();
      try (var follower = kms.tls().follow(NAME, HOURLY, SCHEDULER)) {
        String alias = follower.keyManager().chooseServerAlias("EC", null, null);
        var replacement =
            identity.rekey(second.getPrivate(), TestPki.leaf("node", second, ca).chain(ca));
        identity.privateKey().revoke(RevocationReason.keyCompromise("exposed", Instant.now()));
        assertEquals(TlsIdentityFollower.Status.CURRENT, follower.refresh().status());
        assertEquals(
            replacement.certificate().id(), follower.identity().orElseThrow().certificateId());
        assertNull(
            follower.keyManager().getPrivateKey(alias),
            "known compromised material cannot serve an in-flight alias");
        assertNull(follower.keyManager().getCertificateChain(alias));
      }
    }
  }
}
