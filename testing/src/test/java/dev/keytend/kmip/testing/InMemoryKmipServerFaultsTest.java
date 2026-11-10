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

package dev.keytend.kmip.testing;

import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.kms.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The in-memory server's application-level inspection and fault injection. Uses only
 * the application API and {@code dev.keytend.kmip.testing}, as an application's tests would.
 */
class InMemoryKmipServerFaultsTest {
  static final byte[] PLAIN = "faults".getBytes(StandardCharsets.UTF_8);
  final List<Kms> clients = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
  }

  Kms connect(InMemoryKmipServer server, RetryPolicy retry) {
    Kms kms = Kms.connect(server.configure().retryPolicy(retry).build());
    clients.add(kms);
    return kms;
  }

  static KeyHandle aes(Kms kms) {
    return kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
  }

  /** The documented exception of {@code fault} (the Fault Javadoc table). */
  static Class<? extends KmsException> expected(Fault fault, KmipVersion version, boolean read) {
    boolean v1 = version.compareTo(KmipVersion.V2_0) < 0;
    return switch (fault) {
      case NOT_FOUND -> NotFoundException.class;
      case PERMISSION_DENIED -> PermissionDeniedException.class;
      case INVALID_REQUEST -> InvalidRequestException.class;
      case UNSUPPORTED -> UnsupportedException.class;
      case STATE_CONFLICT -> StateConflictException.class;
      // 1.2 and 1.3 have no Object Already Exists: the superclass, from Illegal Operation.
      case ALREADY_EXISTS ->
          version.compareTo(KmipVersion.V1_4) < 0
              ? StateConflictException.class
              : AlreadyExistsException.class;
      case SERVER_FAILURE -> ServerFailureException.class;
      // 1.x has no Server Limit Exceeded: General Failure.
      case SERVER_BUSY -> read && !v1 ? TransientException.class : ServerFailureException.class;
      case UNREACHABLE -> TransientException.class;
      case REPLY_LOST -> read ? TransientException.class : OutcomeUnknownException.class;
      case MALFORMED_REPLY ->
          read ? ProtocolViolationException.class : OutcomeUnknownException.class;
      // Under a call timeout shorter than the slow-reply delay, with one endpoint.
      case HANG, SLOW -> read ? TransientException.class : OutcomeUnknownException.class;
    };
  }

  static final Map<Class<? extends KmsException>, KmsException.Category> CATEGORY =
      Map.ofEntries(
          Map.entry(NotFoundException.class, KmsException.Category.NOT_FOUND),
          Map.entry(PermissionDeniedException.class, KmsException.Category.FIX_ACCESS),
          Map.entry(InvalidRequestException.class, KmsException.Category.FIX_REQUEST),
          Map.entry(UnsupportedException.class, KmsException.Category.FIX_REQUEST),
          Map.entry(StateConflictException.class, KmsException.Category.STATE),
          Map.entry(AlreadyExistsException.class, KmsException.Category.STATE),
          Map.entry(ServerFailureException.class, KmsException.Category.SERVER),
          Map.entry(ProtocolViolationException.class, KmsException.Category.SERVER),
          Map.entry(TransientException.class, KmsException.Category.RETRY),
          Map.entry(OutcomeUnknownException.class, KmsException.Category.OUTCOME_UNKNOWN));

  static boolean inexpressible(Fault fault, KmipVersion version) {
    return (fault == Fault.ALREADY_EXISTS && version.compareTo(KmipVersion.V1_4) < 0)
        || (fault == Fault.SERVER_BUSY && version.compareTo(KmipVersion.V2_0) < 0);
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void everyFaultProducesItsDocumentedExceptionThenTheServerAnswersAgain(KmipVersion version) {
    for (Fault fault : Fault.values()) {
      String where = version + " " + fault;
      InMemoryKmipServer server = InMemoryKmipServer.of(version);
      Kms kms = connect(server, RetryPolicy.none());
      if (fault == Fault.HANG || fault == Fault.SLOW) {
        // These wait for the call deadline: a short one.
        kms =
            Kms.connect(
                server
                    .configure()
                    .retryPolicy(RetryPolicy.none())
                    .callTimeout(java.time.Duration.ofMillis(250))
                    .build());
        clients.add(kms);
      }
      if (inexpressible(fault, version)) {
        // A server speaking only this version could never send it (see the test below).
        assertThrows(
            IllegalArgumentException.class,
            () -> server.failNext(ServerOperation.GET_ATTRIBUTES, fault),
            where);
        continue;
      }

      // A read: attributes() sends one Get Attributes.
      KeyHandle key = aes(kms);
      server.failNext(ServerOperation.GET_ATTRIBUTES, fault);
      KmsException read = assertThrows(KmsException.class, key::attributes, where);
      assertEquals(expected(fault, version, true), read.getClass(), where + ": " + read);
      assertEquals(CATEGORY.get(read.getClass()), read.category(), where);
      assertEquals(KeyState.ACTIVE, key.attributes().state(), where + ": the next read succeeds");

      // A mutation: activate() sends one Activate.
      KeyHandle staged = kms.keys().createAes(128).usages(KeyUsage.ENCRYPT).createPreActive();
      server.failNext(ServerOperation.ACTIVATE, fault);
      KmsException mutation = assertThrows(KmsException.class, staged::activate, where);
      assertEquals(expected(fault, version, false), mutation.getClass(), where + ": " + mutation);
      assertEquals(CATEGORY.get(mutation.getClass()), mutation.category(), where);
      boolean processed =
          fault == Fault.REPLY_LOST || fault == Fault.MALFORMED_REPLY || fault == Fault.SLOW;
      assertEquals(
          Optional.of(processed ? KeyState.ACTIVE : KeyState.PRE_ACTIVE),
          server.state(staged.id()),
          where + ": a fault answered with a Result Reason changes nothing");
      if (!processed) staged.activate();
      assertEquals(Optional.of(KeyState.ACTIVE), server.state(staged.id()), where);

      assertEquals(List.of(), server.violations(), where);
    }
  }

  /**
   * A fault no version of the server can express is refused when it is armed, rather
   * than answered with another reason. Where the server speaks versions with and without the
   * reason, the request's version decides, and a substitution is recorded as a violation.
   */
  @Test
  void aFaultNoVersionOfTheServerCanExpressIsRefusedWhenArmed() {
    InMemoryKmipServer v1 = InMemoryKmipServer.of(KmipVersion.V1_2, KmipVersion.V1_4);
    IllegalArgumentException busy =
        assertThrows(
            IllegalArgumentException.class,
            () -> v1.failNext(ServerOperation.ENCRYPT, Fault.SERVER_BUSY));
    assertTrue(busy.getMessage().contains("SERVER_BUSY"), busy.getMessage());
    assertTrue(busy.getMessage().contains("SERVER_FAILURE"), busy.getMessage());
    v1.failNext(ServerOperation.ACTIVATE, Fault.ALREADY_EXISTS); // 1.4 expresses it
    InMemoryKmipServer v12 = InMemoryKmipServer.of(KmipVersion.V1_2, KmipVersion.V1_3);
    IllegalArgumentException exists =
        assertThrows(
            IllegalArgumentException.class,
            () -> v12.failNext(ServerOperation.CREATE, Fault.ALREADY_EXISTS));
    assertTrue(exists.getMessage().contains("STATE_CONFLICT"), exists.getMessage());

    // Nothing was armed by the refused call.
    Kms kms12 = connect(v12, RetryPolicy.none());
    KeyHandle key12 = aes(kms12);
    assertEquals(KeyState.ACTIVE, key12.attributes().state());
    assertEquals(List.of(), v12.violations());

    // A server speaking 1.2 and 2.1: the version of the request decides.
    InMemoryKmipServer mixed = InMemoryKmipServer.of(KmipVersion.V1_2, KmipVersion.V2_1);
    Kms old =
        Kms.connect(
            mixed
                .configure()
                .maximumVersion(KmipVersion.V1_2)
                .retryPolicy(RetryPolicy.none())
                .build());
    clients.add(old);
    Kms modern = connect(mixed, RetryPolicy.none());
    assertEquals(KmipVersion.V1_2, old.version());
    assertEquals(KmipVersion.V2_1, modern.version());
    KeyHandle key = aes(old);
    mixed.failNext(ServerOperation.GET_ATTRIBUTES, Fault.SERVER_BUSY);
    assertEquals(
        ServerFailureException.class, assertThrows(KmsException.class, key::attributes).getClass());
    KeyHandle staged = old.keys().createAes(128).usages(KeyUsage.ENCRYPT).createPreActive();
    mixed.failNext(ServerOperation.ACTIVATE, Fault.ALREADY_EXISTS);
    assertEquals(
        StateConflictException.class,
        assertThrows(KmsException.class, staged::activate).getClass());
    List<String> violations = mixed.violations();
    assertEquals(2, violations.size(), violations.toString());
    assertTrue(violations.get(0).contains("SERVER_BUSY"), violations.get(0));
    assertTrue(violations.get(1).contains("ALREADY_EXISTS"), violations.get(1));

    KeyHandle same = modern.keys().handle(key.id());
    mixed.failNext(ServerOperation.GET_ATTRIBUTES, Fault.SERVER_BUSY);
    assertThrows(TransientException.class, same::attributes);
    KeyHandle staged2 = modern.keys().createAes(128).usages(KeyUsage.ENCRYPT).createPreActive();
    mixed.failNext(ServerOperation.ACTIVATE, Fault.ALREADY_EXISTS);
    assertThrows(AlreadyExistsException.class, staged2::activate);
    assertEquals(violations, mixed.violations(), "2.1 expresses both");
  }

  /** In 1.x a server failure on an authenticated decryption is General Failure. */
  @Test
  void aServerFailureOnAnAuthenticatedDecryptionIsUnconfirmedOnlyIn1x() {
    for (KmipVersion version : List.of(KmipVersion.V1_4, KmipVersion.V2_1)) {
      InMemoryKmipServer server = InMemoryKmipServer.of(version);
      Kms kms = connect(server, RetryPolicy.none());
      KeyHandle key = aes(kms);
      Ciphertext sealed = key.encrypt(CipherSpec.aesGcm(), PLAIN, null);

      server.failNext(ServerOperation.DECRYPT, Fault.SERVER_FAILURE);
      KmsException e = assertThrows(KmsException.class, () -> key.decrypt(sealed, null));
      if (version == KmipVersion.V1_4) {
        CryptographicFailureException c = assertInstanceOf(CryptographicFailureException.class, e);
        assertEquals(CryptographicFailureException.Kind.UNCONFIRMED, c.kind());
      } else {
        assertEquals(ServerFailureException.class, e.getClass());
      }
      server.failNext(ServerOperation.DECRYPT, Fault.INVALID_REQUEST);
      assertThrows(
          InvalidRequestException.class, () -> key.decrypt(sealed, null), version.toString());
      assertArrayEquals(PLAIN, key.decrypt(sealed, null));
      assertEquals(List.of(), server.violations());
    }
  }

  @Test
  void aFaultWaitsForItsOperationAndEachArmingFailsOneRequest() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server, RetryPolicy.none());
    KeyHandle key = aes(kms);
    server.failNext(ServerOperation.DESTROY, Fault.NOT_FOUND);
    server.failNext(ServerOperation.ENCRYPT, Fault.PERMISSION_DENIED);
    server.failNext(ServerOperation.ENCRYPT, Fault.SERVER_BUSY);
    assertEquals(KeyState.ACTIVE, key.attributes().state(), "Get Attributes is not armed");
    assertThrows(
        PermissionDeniedException.class, () -> key.encrypt(CipherSpec.aesGcm(), PLAIN, null));
    assertThrows(TransientException.class, () -> key.encrypt(CipherSpec.aesGcm(), PLAIN, null));
    key.encrypt(CipherSpec.aesGcm(), PLAIN, null);
    key.revoke(RevocationReason.cessationOfOperation("retired"));
    assertThrows(NotFoundException.class, key::destroy);
    assertEquals(Optional.of(KeyState.DEACTIVATED), server.state(key.id()));
    key.destroy();
    assertEquals(Optional.of(KeyState.DESTROYED), server.state(key.id()));

    server.failNext(ServerOperation.ANY, Fault.STATE_CONFLICT);
    assertThrows(StateConflictException.class, () -> kms.random(16), "ANY matches RNG Retrieve");
    assertEquals(16, kms.random(16).length);
    assertEquals(List.of(), server.violations());
  }

  @Test
  void theSdkRetriesAReadUntilItsAttemptsAreUsedUp() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms =
        connect(
            server,
            RetryPolicy.builder().maxAttempts(3).initialBackoff(java.time.Duration.ZERO).build());
    KeyHandle key = aes(kms);
    for (int i = 0; i < 2; i++) server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.REPLY_LOST);
    assertEquals(KeyState.ACTIVE, key.attributes().state(), "two lost replies, then an answer");
    for (int i = 0; i < 3; i++) server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.UNREACHABLE);
    assertThrows(TransientException.class, key::attributes, "three attempts, three refusals");
    assertEquals(KeyState.ACTIVE, key.attributes().state());
    // Mutations are never re-sent: one lost reply is enough.
    KeyHandle staged = kms.keys().createAes(128).usages(KeyUsage.ENCRYPT).createPreActive();
    server.failNext(ServerOperation.ACTIVATE, Fault.REPLY_LOST);
    assertThrows(OutcomeUnknownException.class, staged::activate);
    assertEquals(Optional.of(KeyState.ACTIVE), server.state(staged.id()), "it did take effect");
    assertEquals(List.of(), server.violations());
  }

  @Test
  void faultsAreThreadSafe() throws Exception {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Kms kms = connect(server, RetryPolicy.none());
    KeyHandle key = aes(kms);
    int armed = 20;
    for (int i = 0; i < armed; i++)
      server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.NOT_FOUND);
    AtomicInteger failed = new AtomicInteger();
    ExecutorService pool = Executors.newFixedThreadPool(8);
    try {
      List<Future<?>> calls = new ArrayList<>();
      for (int i = 0; i < 100; i++)
        calls.add(
            pool.submit(
                () -> {
                  try {
                    key.attributes();
                  } catch (NotFoundException e) {
                    failed.incrementAndGet();
                  }
                }));
      for (Future<?> f : calls) f.get(30, TimeUnit.SECONDS);
    } finally {
      pool.shutdownNow();
    }
    assertEquals(armed, failed.get());
    assertEquals(List.of(), server.violations());
  }

  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V2_1", "V3_0"})
  void inspectionUsesApplicationTypes(KmipVersion version) {
    InMemoryKmipServer server = InMemoryKmipServer.of(version);
    Kms kms = connect(server, RetryPolicy.none());
    KeyHandle key =
        kms.keys()
            .createAes(256)
            .named("orders")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .create();
    assertEquals(Optional.of(KeyState.ACTIVE), server.state(key.id()));
    assertEquals(Optional.of(ObjectKind.SYMMETRIC_KEY), server.kind(key.id()));
    assertEquals(Set.of(KeyUsage.ENCRYPT, KeyUsage.DECRYPT), server.usages(key.id()));
    assertEquals(List.of("orders"), server.names(key.id()));

    KeyHandle next = key.rotate();
    assertEquals(List.of(next.id()), server.links(key.id(), LinkKind.REPLACEMENT));
    assertEquals(List.of(key.id()), server.links(next.id(), LinkKind.REPLACED));
    assertEquals(List.of(), server.links(key.id(), LinkKind.REPLACED));
    assertEquals(List.of(), server.links(key.id(), LinkKind.OTHER));
    assertEquals(List.of("orders"), server.names(next.id()), "Re-key moves the name");

    KeyPairHandle pair =
        kms.keys()
            .createKeyPair(KeyPairSpec.rsa(2048))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY)
            .createPreActive();
    String priv = pair.privateKey().id(), pub = pair.publicKey().id();
    assertEquals(Optional.of(ObjectKind.PRIVATE_KEY), server.kind(priv));
    assertEquals(Optional.of(ObjectKind.PUBLIC_KEY), server.kind(pub));
    assertEquals(Set.of(KeyUsage.SIGN), server.usages(priv));
    assertEquals(List.of(pub), server.links(priv, LinkKind.PUBLIC_KEY));
    assertEquals(List.of(priv), server.links(pub, LinkKind.PRIVATE_KEY));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(priv));

    key.revoke(RevocationReason.keyCompromise("leaked", java.time.Instant.now()));
    assertEquals(Optional.of(KeyState.COMPROMISED), server.state(key.id()));
    key.destroy();
    assertEquals(Optional.of(KeyState.DESTROYED_COMPROMISED), server.state(key.id()));
    assertFalse(server.exists(key.id()));

    assertEquals(Optional.empty(), server.state("no-such-id"));
    assertEquals(Optional.empty(), server.kind("no-such-id"));
    assertEquals(Set.of(), server.usages("no-such-id"));
    assertEquals(List.of(), server.links("no-such-id", LinkKind.REPLACEMENT));
    assertEquals(List.of(), server.violations());
  }
}
