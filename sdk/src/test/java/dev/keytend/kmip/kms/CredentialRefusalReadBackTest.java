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

import dev.keytend.kmip.client.Requests;
import dev.keytend.kmip.model.*;
import dev.keytend.kmip.model.Enums.ResultReason;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * A read-back turns only a refusal that may be about
 * the object's lifecycle (Permission Denied, Illegal Operation, Wrong Key Lifecycle State) into
 * STATE; an explicit refusal of this client's credentials (Authentication Not Successful, Bad
 * Password, a refused TLS handshake), or an authorization reason such as Not Authorised, stays as
 * the server said, at every read-back site and at every place that takes a
 * refusal for a fact about an object.
 */
class CredentialRefusalReadBackTest {
  static final byte[] PLAIN = ConcurrentReplacementChecks.PLAIN,
      AAD = ConcurrentReplacementChecks.AAD;
  static final String NAME = "vault";
  static final ResultReason AUTH = ResultReason.AUTHENTICATION_NOT_SUCCESSFUL;

  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
  }

  Kms connect(InMemoryKmipServer server) {
    Kms kms = server.connect();
    clients.add(kms);
    return kms;
  }

  static KeyCreation aes(Kms kms) {
    return kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).named(NAME);
  }

  static RevocationReason leaked() {
    return RevocationReason.keyCompromise(
        "leaked", java.time.Instant.parse("2026-10-27T10:00:00Z"));
  }

  /** Whether {@code request} is a {@code op} request naming {@code id} (anywhere in it), or any id when null. */
  static Predicate<Ttlv> request(Operation op, String id) {
    return r -> RotationAndNameChoiceTest.isOperation(r, op) && (id == null || names(r, id));
  }

  /** Whether {@code request} sets a Link attribute (a Link structure from 2.0, an attribute named "Link" before). */
  static boolean linking(Ttlv t) {
    if (t.tag() == Tag.LINK.code()) return true;
    if (t.type() == Ttlv.Type.TEXT_STRING && t.textValue().equals("Link")) return true;
    return t.type() == Ttlv.Type.STRUCTURE
        && t.children().stream().anyMatch(CredentialRefusalReadBackTest::linking);
  }

  private static boolean names(Ttlv t, String id) {
    if (t.tag() == Tag.UNIQUE_IDENTIFIER.code()
        && t.type() == Ttlv.Type.TEXT_STRING
        && id.equals(t.textValue())) return true;
    return t.type() == Ttlv.Type.STRUCTURE && t.children().stream().anyMatch(c -> names(c, id));
  }

  /**
   * A client, on its own replica of {@code server}, whose requests matching {@code which} the
   * server refuses with {@code reason} (as {@code fault}), every time; {@code before} runs once,
   * before the first of them is sent (another caller's move, through another client).
   */
  Kms refusing(
      InMemoryKmipServer server,
      Predicate<Ttlv> which,
      ServerOperation fault,
      ResultReason reason,
      Runnable before) {
    InMemoryKmipServer replica = server.replica();
    boolean[] ran = {false};
    Kms kms =
        Kms.connect(
            replica
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request -> {
                          if (which.test(request)) {
                            if (!ran[0] && before != null) {
                              ran[0] = true;
                              before.run();
                            }
                            replica.failNext(fault, reason);
                          }
                          return replica.exchange(request);
                        })
                .build());
    clients.add(kms);
    return kms;
  }

  /**
   * A client, on its own replica of {@code server}, whose batched Get Attributes the server refuses
   * with {@code batch} (when not null), and whose Get Attributes of {@code id} alone with {@code
   * single} (when not null).
   */
  Kms refusingReads(InMemoryKmipServer server, ResultReason batch, String id, ResultReason single) {
    InMemoryKmipServer replica = server.replica();
    Kms kms =
        Kms.connect(
            replica
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request -> {
                          if (RotationAndNameChoiceTest.isOperation(
                              request, Operation.GET_ATTRIBUTES)) {
                            if (request.children(Tag.BATCH_ITEM).size() > 1) {
                              if (batch != null)
                                replica.failNext(ServerOperation.GET_ATTRIBUTES, batch);
                            } else if (single != null && names(request, id))
                              replica.failNext(ServerOperation.GET_ATTRIBUTES, single);
                          }
                          return replica.exchange(request);
                        })
                .build());
    clients.add(kms);
    return kms;
  }

  static void assertAccess(KmsException e, KmsReason reason) {
    assertInstanceOf(PermissionDeniedException.class, e, e.toString());
    assertEquals(KmsException.Category.FIX_ACCESS, e.category(), e.getMessage());
    assertEquals(Optional.of(reason), e.serverReason());
  }

  /** The explicit access refusals of {@code version}: Authentication Not Successful, and from 2.0 Bad Password and Not Authorised. */
  static List<ResultReason> accessReasons(KmipVersion version) {
    return version.compareTo(KmipVersion.V2_0) >= 0
        ? List.of(AUTH, ResultReason.BAD_PASSWORD, ResultReason.NOT_AUTHORISED)
        : List.of(AUTH);
  }

  static KmsReason kmsReason(ResultReason reason) {
    return KmsReason.of(reason);
  }

  // ---- the read-backs: activate, rotate, cryptographic calls ----

  /**
   * Activate: an Active key whose Activate the server refuses with an
   * explicit access reason is FIX_ACCESS with that reason, not STATE "is ACTIVE, not Pre-Active";
   * a Permission Denied for it (the 1.x lifecycle answer) is still read back as STATE.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void anActivateRefusedForAccessIsNotReadBack(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    Kms admin = connect(s);
    KeyHandle key = aes(admin).create();
    for (ResultReason reason : accessReasons(version)) {
      Kms restricted =
          refusing(s, request(Operation.ACTIVATE, null), ServerOperation.ACTIVATE, reason, null);
      assertAccess(
          assertThrows(KmsException.class, () -> restricted.keys().handle(key.id()).activate()),
          kmsReason(reason));
    }
    Kms denied =
        refusing(
            s,
            request(Operation.ACTIVATE, null),
            ServerOperation.ACTIVATE,
            ResultReason.PERMISSION_DENIED,
            null);
    StateConflictException state =
        assertThrows(StateConflictException.class, () -> denied.keys().handle(key.id()).activate());
    assertTrue(state.getMessage().contains("is ACTIVE, not Pre-Active"), state.getMessage());
  }

  /**
   * Re-key: another caller rotates the key just before this caller's
   * Re-key, which the server refuses with an explicit access reason: {@code rotate()} and {@code
   * rotateOrLatest()} are FIX_ACCESS, not "replaced meanwhile" (nor the winner); a Deactivated key
   * nobody replaced, refused that way, is FIX_ACCESS too, not STATE naming its state.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void aReKeyRefusedForAccessIsNotReadBack(KmipVersion version) {
    for (ResultReason reason : accessReasons(version)) {
      InMemoryKmipServer s = InMemoryKmipServer.of(version);
      Kms admin = connect(s);
      KeyHandle old = aes(admin).create();
      Kms restricted =
          refusing(
              s,
              request(Operation.RE_KEY, null),
              ServerOperation.RE_KEY,
              reason,
              () -> old.rotate());
      assertAccess(
          assertThrows(KmsException.class, () -> restricted.keys().handle(old.id()).rotate()),
          kmsReason(reason));

      KeyHandle other =
          admin.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
      Kms orLatest =
          refusing(
              s,
              request(Operation.RE_KEY, null),
              ServerOperation.RE_KEY,
              reason,
              () -> other.rotate());
      assertAccess(
          assertThrows(
              KmsException.class, () -> orLatest.keys().handle(other.id()).rotateOrLatest()),
          kmsReason(reason));

      // Deactivated after the SDK's read, just before its Re-key: a Deactivated key is refused
      // before
      // anything is sent, so only a revocation in between reaches the server.
      KeyHandle retired =
          admin.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
      Kms plain =
          refusing(
              s,
              request(Operation.RE_KEY, null),
              ServerOperation.RE_KEY,
              reason,
              () -> retired.revoke(RevocationReason.superseded("retired")));
      assertAccess(
          assertThrows(KmsException.class, () -> plain.keys().handle(retired.id()).rotate()),
          kmsReason(reason));
    }
  }

  /**
   * The cryptographic read-backs: an encrypt or MAC with a Deactivated key, and a decrypt whose key
   * was destroyed meanwhile, refused with Authentication Not Successful, are FIX_ACCESS, not STATE
   * naming the state; a MAC with a key without the MAC usage, refused that way, is FIX_ACCESS, not
   * a key mismatch.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void cryptographicCallsRefusedForAccessAreNotReadBack(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    Kms admin = connect(s);
    KeyHandle deactivated = aes(admin).create();
    deactivated.revoke(RevocationReason.superseded("retired"));
    Kms encrypting =
        refusing(s, request(Operation.ENCRYPT, null), ServerOperation.ENCRYPT, AUTH, null);
    assertAccess(
        assertThrows(
            KmsException.class,
            () ->
                encrypting
                    .keys()
                    .handle(deactivated.id())
                    .encrypt(CipherSpec.aesGcm(), PLAIN, AAD)),
        KmsReason.AUTHENTICATION_FAILED);

    KeyHandle macKey =
        admin
            .keys()
            .createSymmetric(Algorithm.HMAC_SHA256, 256)
            .usages(KeyUsage.MAC_GENERATE)
            .create();
    macKey.revoke(RevocationReason.superseded("retired"));
    Kms macing = refusing(s, request(Operation.MAC, null), ServerOperation.MAC, AUTH, null);
    assertAccess(
        assertThrows(
            KmsException.class,
            () -> macing.keys().handle(macKey.id()).mac(MacSpec.hmac(Hash.SHA_256), PLAIN)),
        KmsReason.AUTHENTICATION_FAILED);
    KeyHandle noMac =
        admin.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    assertAccess(
        assertThrows(
            KmsException.class,
            () -> macing.keys().handle(noMac.id()).mac(MacSpec.hmac(Hash.SHA_256), PLAIN)),
        KmsReason.AUTHENTICATION_FAILED);

    KeyHandle doomed = aes(admin).create();
    Ciphertext sealed = doomed.encrypt(CipherSpec.aesGcm(), PLAIN, AAD);
    Kms decrypting =
        refusing(
            s,
            request(Operation.DECRYPT, null),
            ServerOperation.DECRYPT,
            AUTH,
            () -> {
              doomed.revoke(RevocationReason.superseded("retired"));
              doomed.destroy();
            });
    assertAccess(
        assertThrows(
            KmsException.class, () -> decrypting.keys().handle(doomed.id()).decrypt(sealed, AAD)),
        KmsReason.AUTHENTICATION_FAILED);
  }

  // ---- refusals taken for facts about an object ----

  /**
   * {@code replaceCompromised}: a Re-key of the Compromised key refused because of the client's
   * credentials ends the call, FIX_ACCESS, creating nothing; before, it was taken for a server that
   * will not re-key a Compromised key, and a new key was created and linked by hand.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void aCompromiseReplacementRefusedForCredentialsCreatesNothing(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    Kms admin = connect(s);
    KeyHandle key = aes(admin).create();
    key.revoke(leaked());
    int objects = s.ids().size();
    Kms restricted =
        refusing(s, request(Operation.RE_KEY, null), ServerOperation.RE_KEY, AUTH, null);
    assertAccess(
        assertThrows(
            KmsException.class,
            () -> restricted.keys().handle(key.id()).replaceCompromised(leaked())),
        KmsReason.AUTHENTICATION_FAILED);
    assertEquals(objects, s.ids().size(), "no fallback key");
  }

  /**
   * The links {@code replaceCompromised} makes by hand (on a server that will not re-key a
   * Compromised key): a link refused because of the client's credentials is a failure of the call
   * ({@link PartialCompletionException}, the replacement named, the refusal its cause), not a server
   * that does not link.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aLinkRefusedForCredentialsIsAFailure(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    Kms admin = connect(s);
    KeyHandle key = aes(admin).create();
    key.revoke(leaked());
    InMemoryKmipServer replica = s.replica();
    Kms restricted =
        Kms.connect(
            replica
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request -> {
                          if (RotationAndNameChoiceTest.isOperation(request, Operation.RE_KEY))
                            replica.failNext(
                                ServerOperation.RE_KEY, ResultReason.OPERATION_NOT_SUPPORTED);
                          if (RotationAndNameChoiceTest.isOperation(
                                  request, Operation.ADD_ATTRIBUTE)
                              && linking(request))
                            replica.failNext(ServerOperation.ADD_ATTRIBUTE, AUTH);
                          return replica.exchange(request);
                        })
                .build());
    clients.add(restricted);
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () -> restricted.keys().handle(key.id()).replaceCompromised(leaked()));
    assertEquals(1, e.created().size(), e.getMessage());
    assertAccess(
        assertInstanceOf(KmsException.class, e.getCause()), KmsReason.AUTHENTICATION_FAILED);
  }

  /**
   * {@code reconcile}'s links: refused because of the client's credentials, the call is
   * interrupted (repeat to resume), not reported as a server that will not link (FIX_REQUEST).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aReconcileLinkRefusedForCredentialsInterruptsIt(KmipVersion version) throws Exception {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    Kms admin = connect(s);
    KeyHandle old = aes(admin).create();
    // A fork: two Re-keys of one key (this server re-keys a key twice).
    admin.protocol().call(Requests.reKey().uniqueIdentifier(old.id()).build());
    admin.protocol().call(Requests.reKey().uniqueIdentifier(old.id()).build());
    Kms restricted =
        refusing(
            s,
            r -> RotationAndNameChoiceTest.isOperation(r, Operation.ADD_ATTRIBUTE) && linking(r),
            ServerOperation.ADD_ATTRIBUTE,
            AUTH,
            null);
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class, () -> restricted.keys().handle(old.id()).reconcile());
    assertAccess(
        assertInstanceOf(KmsException.class, e.getCause()), KmsReason.AUTHENTICATION_FAILED);
  }

  /**
   * A lineage walk: a replacement whose read is refused because of the client's credentials fails
   * the walk, FIX_ACCESS, rather than being a gap ("cannot be read with these credentials", STATE).
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void aLineageReadRefusedForCredentialsFailsTheWalk(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    Kms admin = connect(s);
    KeyHandle old = aes(admin).create();
    KeyHandle next = old.rotate();
    Kms restricted =
        refusing(
            s,
            request(Operation.GET_ATTRIBUTES, next.id()),
            ServerOperation.GET_ATTRIBUTES,
            AUTH,
            null);
    assertAccess(
        assertThrows(KmsException.class, () -> restricted.keys().handle(old.id()).latest()),
        KmsReason.AUTHENTICATION_FAILED);
  }

  /**
   * Name lookups read what they found in one batch, then one by one when the batch is refused: a
   * candidate (two keys with the name) or a key with a pending-name record whose read is refused
   * because of the client's credentials, in the batch or alone after a batch refused with
   * Permission Denied, is FIX_ACCESS, not "cannot be read" (STATE) nor passed over.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aNameLookupReadRefusedForCredentialsIsAccess(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    Kms admin = connect(s);
    aes(admin).create();
    KeyHandle second = aes(admin).create();
    assertAccess(
        assertThrows(
            KmsException.class, () -> refusingReads(s, AUTH, null, null).keys().findByName(NAME)),
        KmsReason.AUTHENTICATION_FAILED);
    assertAccess(
        assertThrows(
            KmsException.class,
            () ->
                refusingReads(s, ResultReason.PERMISSION_DENIED, second.id(), AUTH)
                    .keys()
                    .findByName(NAME)),
        KmsReason.AUTHENTICATION_FAILED);

    for (int i = 0; i < 2; i++)
      admin
          .keys()
          .createAes(256)
          .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
          .create()
          .setCustomAttribute(KeyHandle.pendingName("other"), "other");
    String recorded = admin.keys().pendingName("other").get(1);
    // The Locate for records refused: not a server that cannot search.
    Kms locating = refusing(s, request(Operation.LOCATE, null), ServerOperation.LOCATE, AUTH, null);
    assertAccess(
        assertThrows(KmsException.class, () -> locating.keys().pendingName("other")),
        KmsReason.AUTHENTICATION_FAILED);
    assertAccess(
        assertThrows(
            KmsException.class,
            () -> refusingReads(s, AUTH, null, null).keys().pendingName("other")),
        KmsReason.AUTHENTICATION_FAILED);
    assertAccess(
        assertThrows(
            KmsException.class,
            () ->
                refusingReads(s, ResultReason.PERMISSION_DENIED, recorded, AUTH)
                    .keys()
                    .pendingName("other")),
        KmsReason.AUTHENTICATION_FAILED);
  }

  /**
   * The reads before a cryptographic call: the key's usages before an encrypt, and the private
   * key's state before a verify, refused because of the client's credentials, are FIX_ACCESS; before,
   * the read was passed over as a key this client may not read, and the call went ahead.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1"})
  void aReadBeforeACryptographicCallRefusedForCredentialsIsAccess(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    Kms admin = connect(s);
    KeyHandle key = aes(admin).create();
    Kms encrypting =
        refusing(
            s,
            request(Operation.GET_ATTRIBUTES, key.id()),
            ServerOperation.GET_ATTRIBUTES,
            AUTH,
            null);
    assertAccess(
        assertThrows(
            KmsException.class,
            () -> encrypting.keys().handle(key.id()).encrypt(CipherSpec.aesGcm(), PLAIN, AAD)),
        KmsReason.AUTHENTICATION_FAILED);

    KeyPairHandle pair = KeyPairsAndSecretsTest.signer(admin).create();
    byte[] signature = pair.privateKey().sign(SignatureSpec.ecdsa(Hash.SHA_256), PLAIN);
    Kms verifying =
        refusing(
            s,
            request(Operation.GET_ATTRIBUTES, pair.privateKey().id()),
            ServerOperation.GET_ATTRIBUTES,
            AUTH,
            null);
    assertAccess(
        assertThrows(
            KmsException.class,
            () ->
                verifying
                    .keys()
                    .handle(pair.publicKey().id())
                    .verify(SignatureSpec.ecdsa(Hash.SHA_256), PLAIN, signature)),
        KmsReason.AUTHENTICATION_FAILED);
  }

  /**
   * The Activates the SDK sends itself: {@code findOrCreate} (a key and a key pair) and {@code
   * create} whose Activate is refused because of the client's credentials, after another caller
   * activated the key, fail FIX_ACCESS ({@code create}: a partial completion with that cause)
   * rather than returning the key read back as Active.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1"})
  void theSdksOwnActivatesRefusedForCredentialsAreNotReadBack(KmipVersion version)
      throws Exception {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    Kms admin = connect(s);
    KeyHandle left = aes(admin).createPreActive();
    Kms finding =
        refusing(
            s,
            request(Operation.ACTIVATE, null),
            ServerOperation.ACTIVATE,
            AUTH,
            () -> left.activate());
    assertAccess(
        assertThrows(KmsException.class, () -> aes(finding).findOrCreate()),
        KmsReason.AUTHENTICATION_FAILED);

    KeyPairHandle pair = KeyPairsAndSecretsTest.signer(admin).createPreActive();
    Kms pairs =
        refusing(
            s,
            request(Operation.ACTIVATE, null),
            ServerOperation.ACTIVATE,
            AUTH,
            () -> {
              admin.keys().handle(pair.privateKey().id()).activate();
              admin.keys().handle(pair.publicKey().id()).activate();
            });
    assertAccess(
        assertThrows(KmsException.class, () -> KeyPairsAndSecretsTest.signer(pairs).findOrCreate()),
        KmsReason.AUTHENTICATION_FAILED);

    // rotateOrLatest's activation of a Pre-Active current key that descends from the handle's key.
    KeyHandle key = admin.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    KeyHandle next =
        admin.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).createPreActive();
    KmsContractTest.link(admin, key.id(), Enums.LinkType.REPLACEMENT_OBJECT_LINK, next.id());
    KmsContractTest.link(admin, next.id(), Enums.LinkType.REPLACED_OBJECT_LINK, key.id());
    Kms following =
        refusing(
            s,
            request(Operation.ACTIVATE, null),
            ServerOperation.ACTIVATE,
            AUTH,
            () -> next.activate());
    assertAccess(
        assertThrows(KmsException.class, () -> following.keys().handle(key.id()).rotateOrLatest()),
        KmsReason.AUTHENTICATION_FAILED);

    InMemoryKmipServer replica = s.replica();
    Kms creating =
        Kms.connect(
            replica
                .configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        request -> {
                          if (RotationAndNameChoiceTest.isOperation(request, Operation.ACTIVATE)) {
                            String id =
                                request
                                    .children(Tag.BATCH_ITEM)
                                    .get(0)
                                    .require(Tag.REQUEST_PAYLOAD)
                                    .require(Tag.UNIQUE_IDENTIFIER)
                                    .textValue();
                            admin.keys().handle(id).activate();
                            replica.failNext(ServerOperation.ACTIVATE, AUTH);
                          }
                          return replica.exchange(request);
                        })
                .build());
    clients.add(creating);
    PartialCompletionException e =
        assertThrows(
            PartialCompletionException.class,
            () ->
                creating.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create());
    assertAccess(
        assertInstanceOf(KmsException.class, e.getCause()), KmsReason.AUTHENTICATION_FAILED);
  }
}
