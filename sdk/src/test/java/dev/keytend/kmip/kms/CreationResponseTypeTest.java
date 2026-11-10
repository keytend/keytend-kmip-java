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

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * A creation response that names another object. A server that answers an
 * AES Create with the identifier of an existing Pre-Active Secret Data object and Object Type
 * Secret Data; {@code createAes().create()} accepted it, activated the secret, left the new key
 * Pre-Active and returned a symmetric-key handle for the secret. The Object Type must now be the
 * requested one; a mismatch is a protocol violation, so the mutation's outcome is unknown and
 * nothing is activated.
 */
class CreationResponseTypeTest {
  final List<Kms> clients = new ArrayList<>();
  final List<InMemoryKmipServer> servers = new ArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    for (InMemoryKmipServer s : servers) assertEquals(List.of(), s.violations());
  }

  /**
   * A server whose replies to {@code op} name {@link #secret} instead of what the server created,
   * with Object Type Secret Data (added when the reply has none), while {@link #secret} is set.
   */
  final class Relabeled {
    final InMemoryKmipServer server;
    final Kms kms;
    final AtomicReference<String> secret = new AtomicReference<>();

    Relabeled(KmipVersion version, Operation op) {
      this(version, op, null);
    }

    /** With {@code identifier}: only that identifier of the reply is replaced, no Object Type added. */
    Relabeled(KmipVersion version, Operation op, Tag identifier) {
      server = InMemoryKmipServer.of(version);
      servers.add(server);
      kms =
          Kms.connect(
              server
                  .configure()
                  .retryPolicy(RetryPolicy.none())
                  .transport(
                      e ->
                          request ->
                              identifier == null
                                  ? relabel(server.exchange(request), op, secret.get())
                                  : swap(server.exchange(request), op, identifier, secret.get()))
                  .build());
      clients.add(kms);
    }

    /** Registers a Pre-Active secret and points the rewritten replies at it. */
    String plantSecret() {
      String id =
          kms.keys()
              .registerSecret(SecretData.Type.SEED, new byte[] {1, 2, 3})
              .named("planted")
              .registerPreActive()
              .id();
      assertEquals(Optional.of(KeyState.PRE_ACTIVE), server.state(id));
      secret.set(id);
      return id;
    }

    /** The identifiers that Activate requests named. */
    List<String> activated() {
      List<String> ids = new ArrayList<>();
      for (Ttlv message : server.protocolRequests())
        for (Ttlv item : message.children(Tag.BATCH_ITEM))
          if (item.require(Tag.OPERATION).intValue() == Operation.ACTIVATE.code())
            ids.add(item.require(Tag.REQUEST_PAYLOAD).require(Tag.UNIQUE_IDENTIFIER).textValue());
      return ids;
    }

    /** The last object of {@code kind} the server made, other than the planted secret. */
    String lastMade(ObjectKind kind) {
      List<String> ids = new ArrayList<>(server.ids());
      Collections.reverse(ids);
      return ids.stream()
          .filter(id -> !id.equals(secret.get()) && server.kind(id).equals(Optional.of(kind)))
          .findFirst()
          .orElseThrow();
    }
  }

  static Ttlv relabel(Ttlv response, Operation op, String secret) {
    if (secret == null) return response;
    List<Ttlv> items = new ArrayList<>();
    for (Ttlv child : response.children()) {
      Optional<Ttlv> payload = child.child(Tag.RESPONSE_PAYLOAD);
      if (child.tag() != Tag.BATCH_ITEM.code()
          || child.require(Tag.OPERATION).intValue() != op.code()
          || payload.isEmpty()) {
        items.add(child);
        continue;
      }
      List<Ttlv> fields = new ArrayList<>();
      fields.add(Ttlv.enumeration(Tag.OBJECT_TYPE, Enums.ObjectType.SECRET_DATA));
      for (Ttlv f : payload.get().children())
        if (f.tag() == Tag.UNIQUE_IDENTIFIER.code()) fields.add(Ttlv.of(f.tag(), f.type(), secret));
        else if (f.tag() != Tag.OBJECT_TYPE.code()) fields.add(f);
      List<Ttlv> rewritten = new ArrayList<>();
      for (Ttlv f : child.children())
        rewritten.add(
            f.tag() == Tag.RESPONSE_PAYLOAD.code()
                ? Ttlv.structure(Tag.RESPONSE_PAYLOAD, fields)
                : f);
      items.add(Ttlv.structure(Tag.BATCH_ITEM, rewritten));
    }
    return Ttlv.structure(response.tag(), items);
  }

  /** Replaces the identifier {@code tag} in the reply to {@code op} with {@code secret}. */
  static Ttlv swap(Ttlv response, Operation op, Tag tag, String secret) {
    if (secret == null) return response;
    List<Ttlv> items = new ArrayList<>();
    for (Ttlv child : response.children()) {
      Optional<Ttlv> payload = child.child(Tag.RESPONSE_PAYLOAD);
      if (child.tag() != Tag.BATCH_ITEM.code()
          || child.require(Tag.OPERATION).intValue() != op.code()
          || payload.isEmpty()) {
        items.add(child);
        continue;
      }
      List<Ttlv> fields = new ArrayList<>();
      for (Ttlv f : payload.get().children())
        fields.add(f.tag() == tag.code() ? Ttlv.text(tag, secret) : f);
      List<Ttlv> rewritten = new ArrayList<>();
      for (Ttlv f : child.children())
        rewritten.add(
            f.tag() == Tag.RESPONSE_PAYLOAD.code()
                ? Ttlv.structure(Tag.RESPONSE_PAYLOAD, fields)
                : f);
      items.add(Ttlv.structure(Tag.BATCH_ITEM, rewritten));
    }
    return Ttlv.structure(response.tag(), items);
  }

  /**
   * The kms layer: Register and Create Key Pair replies carry no Object Type, so a reply
   * that only swaps an identifier passed every protocol check, and {@code register()} or a key
   * pair's {@code create()} activated the planted secret. The SDK now reads what the reply names
   * before handing out or activating a handle.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void anIdentifierOnlySwapInARegisterOrKeyPairReplyIsCaught(KmipVersion version) {
    Relabeled r = new Relabeled(version, Operation.REGISTER, Tag.UNIQUE_IDENTIFIER);
    String secret = r.plantSecret();
    OutcomeUnknownException e =
        assertThrows(
            OutcomeUnknownException.class,
            () ->
                r.kms
                    .keys()
                    .register(new SecretKeySpec(new byte[32], "AES"))
                    .usages(KeyUsage.ENCRYPT)
                    .register());
    assertTrue(
        e.getMessage().contains("which is a SECRET_DATA, not the SYMMETRIC_KEY just made"),
        e.getMessage());
    assertThrows(
        OutcomeUnknownException.class,
        () ->
            r.kms
                .keys()
                .register(new SecretKeySpec(new byte[32], "AES"))
                .usages(KeyUsage.ENCRYPT)
                .registerPreActive());
    assertEquals(List.of(), r.activated(), "nothing activated");
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), r.server.state(secret));

    Relabeled p =
        new Relabeled(version, Operation.CREATE_KEY_PAIR, Tag.PUBLIC_KEY_UNIQUE_IDENTIFIER);
    String planted = p.plantSecret();
    KeyPairCreation pair =
        p.kms
            .keys()
            .createKeyPair(KeyPairSpec.ec(Curve.P_256))
            .privateUsages(KeyUsage.SIGN)
            .publicUsages(KeyUsage.VERIFY);
    assertThrows(OutcomeUnknownException.class, pair::create);
    assertEquals(List.of(), p.activated(), "nothing activated");
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), p.server.state(planted));
    assertThrows(IllegalStateException.class, pair::create, "the builder made its pair");
  }

  /** The probe: {@code create()} activated the secret. Now nothing is activated. */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void createDoesNotActivateAnObjectOfAnotherType(KmipVersion version) {
    Relabeled s = new Relabeled(version, Operation.CREATE);
    String secret = s.plantSecret();
    OutcomeUnknownException e =
        assertThrows(
            OutcomeUnknownException.class,
            () ->
                s.kms
                    .keys()
                    .createAes(256)
                    .named("k")
                    .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
                    .create());
    assertTrue(e.getMessage().contains("Create response has another ObjectType"), e.getMessage());
    assertEquals(List.of(), s.activated(), "nothing activated");
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(secret));
    // The server did create the key; it stays Pre-Active, as after any unknown outcome.
    assertEquals(
        Optional.of(KeyState.PRE_ACTIVE), s.server.state(s.lastMade(ObjectKind.SYMMETRIC_KEY)));

    assertThrows(
        OutcomeUnknownException.class,
        () -> s.kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).createPreActive());
    assertEquals(List.of(), s.activated());
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(secret));
  }

  /**
   * {@code findOrCreate()} treats the unknown outcome as it does any other: it looks the name up
   * again, finds the key the server really created, and activates that one. The secret is never
   * activated or returned.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void findOrCreateResumesWithTheKeyTheServerCreated(KmipVersion version) {
    Relabeled s = new Relabeled(version, Operation.CREATE);
    String secret = s.plantSecret();
    KeyHandle key =
        s.kms
            .keys()
            .createAes(256)
            .named("k")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .findOrCreate();
    String created = s.lastMade(ObjectKind.SYMMETRIC_KEY);
    assertEquals(created, key.id());
    assertEquals(List.of(created), s.activated());
    assertEquals(Optional.of(KeyState.ACTIVE), s.server.state(created));
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(secret));
    assertEquals(Optional.of(ObjectKind.SYMMETRIC_KEY), s.server.kind(key.id()));
  }

  /**
   * Register responses have no Object Type in any version, so a reply that only swaps the
   * identifier cannot be detected from the reply; one that also names another Object Type is a
   * protocol violation, and {@code register()} then activates nothing.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void registerDoesNotActivateAnObjectOfAnotherObjectType(KmipVersion version) {
    Relabeled s = new Relabeled(version, Operation.REGISTER);
    String secret = s.plantSecret();
    OutcomeUnknownException e =
        assertThrows(
            OutcomeUnknownException.class,
            () ->
                s.kms
                    .keys()
                    .register(new SecretKeySpec(new byte[32], "AES"))
                    .usages(KeyUsage.ENCRYPT)
                    .register());
    assertTrue(e.getMessage().contains("Register response has another ObjectType"), e.getMessage());
    assertEquals(List.of(), s.activated(), "nothing activated");
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.server.state(secret));
  }
}
