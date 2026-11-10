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

import dev.keytend.kmip.client.Result;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.model.Enums.ResultReason;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** {@link KmsException#serverReason()} and {@link KmsReason}, the kms-level reason. */
class KmsReasonTest {
  private static final Failures.Call MUTATION = new Failures.Call("create", false, null, false);

  /** The documented mapping; every Result Reason not listed here is OTHER. */
  static final Map<ResultReason, KmsReason> NAMED =
      Map.ofEntries(
          Map.entry(ResultReason.ITEM_NOT_FOUND, KmsReason.NOT_FOUND),
          Map.entry(ResultReason.OBJECT_NOT_FOUND, KmsReason.NOT_FOUND),
          Map.entry(ResultReason.OBJECT_DESTROYED, KmsReason.OBJECT_DESTROYED),
          Map.entry(ResultReason.OBJECT_ARCHIVED, KmsReason.OBJECT_ARCHIVED),
          Map.entry(ResultReason.PERMISSION_DENIED, KmsReason.PERMISSION_DENIED),
          Map.entry(ResultReason.NOT_AUTHORISED, KmsReason.PERMISSION_DENIED),
          Map.entry(ResultReason.AUTHENTICATION_NOT_SUCCESSFUL, KmsReason.AUTHENTICATION_FAILED),
          Map.entry(ResultReason.BAD_PASSWORD, KmsReason.AUTHENTICATION_FAILED),
          Map.entry(ResultReason.SENSITIVE, KmsReason.NOT_EXTRACTABLE),
          Map.entry(ResultReason.NOT_EXTRACTABLE, KmsReason.NOT_EXTRACTABLE),
          Map.entry(ResultReason.WRONG_KEY_LIFECYCLE_STATE, KmsReason.WRONG_LIFECYCLE_STATE),
          Map.entry(ResultReason.ILLEGAL_OPERATION, KmsReason.ILLEGAL_OPERATION),
          Map.entry(ResultReason.OBJECT_ALREADY_EXISTS, KmsReason.ALREADY_EXISTS),
          Map.entry(ResultReason.NON_UNIQUE_NAME_ATTRIBUTE, KmsReason.ALREADY_EXISTS),
          Map.entry(ResultReason.INVALID_MESSAGE, KmsReason.INVALID_MESSAGE),
          Map.entry(ResultReason.INVALID_FIELD, KmsReason.INVALID_FIELD),
          Map.entry(ResultReason.MISSING_DATA, KmsReason.MISSING_DATA),
          Map.entry(ResultReason.OPERATION_NOT_SUPPORTED, KmsReason.OPERATION_NOT_SUPPORTED),
          Map.entry(ResultReason.FEATURE_NOT_SUPPORTED, KmsReason.FEATURE_NOT_SUPPORTED),
          Map.entry(ResultReason.CRYPTOGRAPHIC_FAILURE, KmsReason.CRYPTOGRAPHIC_FAILURE),
          Map.entry(ResultReason.SERVER_LIMIT_EXCEEDED, KmsReason.SERVER_BUSY),
          Map.entry(ResultReason.PROTECTION_STORAGE_UNAVAILABLE, KmsReason.SERVER_BUSY),
          Map.entry(ResultReason.PRIVATE_PROTECTION_STORAGE_UNAVAILABLE, KmsReason.SERVER_BUSY),
          Map.entry(ResultReason.PUBLIC_PROTECTION_STORAGE_UNAVAILABLE, KmsReason.SERVER_BUSY),
          Map.entry(ResultReason.USAGE_LIMIT_EXCEEDED, KmsReason.USAGE_LIMIT_EXCEEDED),
          Map.entry(ResultReason.GENERAL_FAILURE, KmsReason.SERVER_ERROR),
          Map.entry(ResultReason.INTERNAL_SERVER_ERROR, KmsReason.SERVER_ERROR));

  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  static KmsException failure(Failures.Call call, int code) {
    Result result =
        new Result(Operation.CREATE, 1, code, "msg", Ttlv.structure(Tag.BATCH_ITEM, List.of()));
    return Failures.fromResult(call, call.operation(), result, null);
  }

  /**
   * Every protocol Result Reason maps to the constant the table above (and the Javadoc) gives, or
   * to OTHER: iterating values() means a new protocol reason cannot fall through unnoticed.
   */
  @Test
  void everyProtocolReasonMapsToItsDocumentedConstantOrOther() {
    Set<KmsReason> reached = EnumSet.noneOf(KmsReason.class);
    for (ResultReason r : ResultReason.values()) {
      KmsReason expected = NAMED.getOrDefault(r, KmsReason.OTHER);
      assertEquals(expected, KmsReason.of(r), r.toString());
      assertEquals(expected, KmsReason.of(r.code()), r + " by code");
      KmsException e = failure(MUTATION, r.code());
      assertEquals(Optional.of(expected), e.serverReason(), r + ": " + e);
      assertEquals(Optional.of(r), e.protocolReason(), "the escape hatch keeps the exact reason");
      reached.add(expected);
    }
    assertEquals(EnumSet.allOf(KmsReason.class), reached, "every constant is reachable");
  }

  /** A vendor, future or reserved code is OTHER; reasonCode() keeps it, protocolReason() has no constant. */
  @Test
  void vendorAndUnknownCodesAreOther() {
    for (int code : new int[] {0x80000001, 0x7FFFFFFF, 0x0000004E, 0x00000027, 0}) {
      KmsException e = failure(MUTATION, code);
      assertEquals(Optional.of(KmsReason.OTHER), e.serverReason(), Integer.toHexString(code));
      assertEquals(Optional.of(code), e.reasonCode());
      assertEquals(KmsReason.OTHER, KmsReason.of(code));
    }
    assertTrue(failure(MUTATION, 0x80000001).protocolReason().isEmpty());
  }

  /** No server failure result, or one without a reason: empty, as reasonCode(). */
  @Test
  void noServerResultMeansNoReason() {
    for (KmsException e :
        List.of(
            new PermissionDeniedException("p"),
            new NotFoundException("n"),
            Failures.classify(MUTATION, ProtocolVersion.V2_1, new java.io.IOException("reset")),
            Failures.fromResult(
                MUTATION,
                "create",
                new Result(
                    Operation.CREATE,
                    1,
                    null,
                    "no reason",
                    Ttlv.structure(Tag.BATCH_ITEM, List.of())),
                null))) {
      assertEquals(Optional.empty(), e.serverReason(), e.toString());
      assertEquals(Optional.empty(), e.reasonCode(), e.toString());
    }
  }

  /**
   * The reasons merged into one constant are the same refusal: the SDK classifies all of them as
   * the same exception type (here for a mutation, where busy is not retried).
   */
  @Test
  void theReasonsOfOneConstantGiveTheSameException() {
    Map<KmsReason, Set<Class<?>>> types = new EnumMap<>(KmsReason.class);
    for (var e : NAMED.entrySet())
      types
          .computeIfAbsent(e.getValue(), k -> new HashSet<>())
          .add(failure(MUTATION, e.getKey().code()).getClass());
    for (var e : types.entrySet())
      assertEquals(1, e.getValue().size(), e.getKey() + ": " + e.getValue());
  }

  /** The busy check that decides retries reads the same set as SERVER_BUSY. */
  @Test
  void theBusyCheckIsServerBusy() {
    Failures.Call read = new Failures.Call("get", true, "k", false);
    for (ResultReason r : ResultReason.values()) {
      boolean busy = NAMED.get(r) == KmsReason.SERVER_BUSY;
      KmsException e = failure(read, r.code());
      assertEquals(busy, Failures.busy(e), r.toString());
      assertEquals(busy, e instanceof TransientException, r + ": " + e);
    }
  }

  Kms connect(InMemoryKmipServer server) {
    servers.add(server);
    Kms kms = Kms.connect(server.configure().build());
    clients.add(kms);
    return kms;
  }

  /** End to end on 1.4 and 2.1: the in-memory server's not-found and permission-denied answers. */
  @Test
  void notFoundAndPermissionDeniedOnTheInMemoryServer() {
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1)) {
      InMemoryKmipServer server = InMemoryKmipServer.of(v);
      Kms kms = connect(server);
      assertEquals(v, kms.version());
      NotFoundException missing =
          assertThrows(
              NotFoundException.class, () -> kms.keys().handle("no-such-key").attributes());
      assertEquals(
          Optional.of(KmsReason.NOT_FOUND),
          missing.serverReason(),
          v + ": " + missing.protocolReason());

      KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
      // The injected not-found is Object Not Found on 2.1 and Item Not Found on 1.4: one constant.
      server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.NOT_FOUND);
      NotFoundException injected = assertThrows(NotFoundException.class, key::attributes);
      assertEquals(Optional.of(KmsReason.NOT_FOUND), injected.serverReason(), v.toString());
      assertEquals(
          Optional.of(
              v == KmipVersion.V1_4 ? ResultReason.ITEM_NOT_FOUND : ResultReason.OBJECT_NOT_FOUND),
          injected.protocolReason());

      server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
      PermissionDeniedException denied =
          assertThrows(PermissionDeniedException.class, key::attributes);
      assertEquals(Optional.of(KmsReason.PERMISSION_DENIED), denied.serverReason(), v.toString());

      // A lost reply carries no reason.
      server.failNext(ServerOperation.CREATE, Fault.REPLY_LOST);
      OutcomeUnknownException lost =
          assertThrows(
              OutcomeUnknownException.class,
              () -> kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create());
      assertEquals(Optional.empty(), lost.serverReason(), lost.toString());
    }
  }

  /**
   * The reason is the server's word and the category the SDK's verdict: a Pre-Active key refused
   * for encryption is STATE on both versions, but a 1.4 server says Permission Denied.
   */
  @Test
  void theReasonIsTheServersWordAndTheCategoryIsNormalized() {
    for (KmipVersion v : List.of(KmipVersion.V1_4, KmipVersion.V2_1)) {
      Kms kms = connect(InMemoryKmipServer.of(v));
      KeyHandle key =
          kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
      KmsException e =
          assertThrows(KmsException.class, () -> key.encrypt(CipherSpec.aesGcm(), new byte[16]));
      assertEquals(StateConflictException.class, e.getClass(), v + ": " + e);
      assertEquals(KmsException.Category.STATE, e.category());
      KmsReason said =
          v == KmipVersion.V1_4 ? KmsReason.PERMISSION_DENIED : KmsReason.WRONG_LIFECYCLE_STATE;
      assertEquals(Optional.of(said), e.serverReason(), v.toString());
    }
  }
}
