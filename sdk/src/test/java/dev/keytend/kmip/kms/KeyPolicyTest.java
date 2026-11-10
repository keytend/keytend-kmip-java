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

import static dev.keytend.kmip.kms.ScheduledRotationTest.NAME;
import static dev.keytend.kmip.kms.ScheduledRotationTest.aes;
import static org.junit.jupiter.api.Assertions.*;

import dev.keytend.kmip.model.*;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.BiFunction;
import java.util.function.Function;
import java.util.function.UnaryOperator;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * A key's Extractable and Sensitive policy (asked, read, checked and kept), raw material handed
 * out for one stated purpose ({@link LocalUse}), and {@link Expect#aes()} of any AES size.
 */
class KeyPolicyTest {
  static final Instant START = RotationJobTest.START;

  final List<InMemoryKmipServer> servers = new CopyOnWriteArrayList<>();
  final List<Kms> clients = new CopyOnWriteArrayList<>();

  @AfterEach
  void cleanUp() {
    clients.forEach(Kms::close);
    servers.forEach(InMemoryKmipServer::close);
  }

  InMemoryKmipServer server(KmipVersion version) {
    InMemoryKmipServer s = InMemoryKmipServer.of(version);
    s.clock(new RotationJobTest.TestClock(START));
    servers.add(s);
    return s;
  }

  Kms connect(InMemoryKmipServer server) {
    return connect(server, UnaryOperator.identity(), (request, reply) -> reply);
  }

  /** A client whose requests and replies pass through {@code requests} and {@code replies}. */
  Kms connect(
      InMemoryKmipServer server,
      UnaryOperator<Ttlv> requests,
      BiFunction<Ttlv, Ttlv, Ttlv> replies) {
    Kms kms =
        Kms.connect(
            server
                .configure()
                .transport(
                    e ->
                        r -> {
                          Ttlv sent = requests.apply(r);
                          return replies.apply(sent, server.exchange(sent));
                        })
                .build());
    clients.add(kms);
    return kms;
  }

  static boolean is(Ttlv request, Operation operation) {
    return RotationAndNameChoiceTest.isOperation(request, operation);
  }

  /** The Unique Identifier a request names, or null. */
  static String target(Ttlv request) {
    return request
        .require(Tag.BATCH_ITEM)
        .require(Tag.REQUEST_PAYLOAD)
        .child(Tag.UNIQUE_IDENTIFIER)
        .map(Ttlv::textValue)
        .orElse(null);
  }

  /**
   * {@code node} with {@code f} applied to it and to every node under it, top down: f returns the
   * node to keep (its children are then rewritten), another node, or null to drop it.
   */
  static Ttlv rewrite(Ttlv node, Function<Ttlv, Ttlv> f) {
    Ttlv n = f.apply(node);
    if (n == null || n.type() != Ttlv.Type.STRUCTURE) return n;
    List<Ttlv> children = new ArrayList<>();
    for (Ttlv c : n.children()) {
      Ttlv r = rewrite(c, f);
      if (r != null) children.add(r);
    }
    return Ttlv.structure(n.tag(), children);
  }

  /** Whether {@code a} is the attribute {@code tag}, in the 1.x form (named) or the 2.x form. */
  static boolean attribute(Ttlv a, Tag tag, String name) {
    if (a.tag() == tag.code()) return true;
    return a.tag() == Tag.ATTRIBUTE.code()
        && a.child(Tag.ATTRIBUTE_NAME).map(t -> t.textValue().equals(name)).orElse(false);
  }

  /** {@code message} without the attribute {@code tag} anywhere. */
  static Ttlv without(Ttlv message, Tag tag, String name) {
    return rewrite(message, a -> attribute(a, tag, name) ? null : a);
  }

  /** {@code message} with every value of the Boolean attribute {@code tag} set to {@code value}. */
  static Ttlv stating(Ttlv message, Tag tag, String name, boolean value) {
    return rewrite(
        message,
        a ->
            a.tag() == tag.code()
                ? Ttlv.bool(tag, value)
                : attribute(a, tag, name) ? Attributes.attribute(name, Ttlv.bool(tag, value)) : a);
  }

  static PermissionDeniedException refusedRelease(KeyHandle key) {
    PermissionDeniedException e =
        assertThrows(
            PermissionDeniedException.class,
            () -> key.asSecretKey(Expect.aes(256), LocalUse.ENCRYPT));
    assertEquals(Optional.of(KmsReason.NOT_EXTRACTABLE), e.serverReason(), e.getMessage());
    return e;
  }

  // ---- Extractable and Sensitive ----

  /**
   * From KMIP 1.4 the builders send Extractable and Sensitive, {@link KeyAttributes} reads them, and
   * the server refuses to release a key that is not Extractable, or Sensitive (Get without
   * wrapping), while the key still seals and opens on the server. A create that asks for a
   * protection reads the key back once, before activating it. Every other key states KMIP's
   * defaults (Extractable true, Sensitive false), and an explicit {@code extractable(true)} key is
   * released.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_0", "V2_1", "V3_0"})
  void theProtectionIsSentReadAndEnforced(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    int before = s.exchanges();
    KeyHandle plain = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
    int plainCost = s.exchanges() - before;
    assertEquals(Optional.of(true), plain.attributes().extractable());
    assertEquals(Optional.of(false), plain.attributes().sensitive());

    before = s.exchanges();
    KeyHandle kek =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .extractable(false)
            .create();
    assertEquals(plainCost + 1, s.exchanges() - before, "one Get Attributes more: the read-back");
    assertEquals(Optional.of(false), kek.attributes().extractable());
    refusedRelease(kek);
    byte[] record = "record".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    assertArrayEquals(
        record, kek.open(kek.seal(record, null), null), "the KEK still works on the server");

    KeyHandle sensitive =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).sensitive(true).create();
    assertEquals(Optional.of(true), sensitive.attributes().sensitive());
    assertEquals(Optional.of(true), sensitive.attributes().extractable());
    refusedRelease(sensitive);

    KeyHandle raw =
        kms.keys()
            .createAes(128)
            .usages(KeyUsage.ENCRYPT)
            .extractable(true)
            .sensitive(false)
            .create();
    assertEquals(16, raw.asSecretKey(Expect.aes(128), LocalUse.ENCRYPT).getEncoded().length);

    // Registration: the reply is read back anyway, so no request more.
    before = s.exchanges();
    KeyHandle registered =
        kms.keys()
            .register(new SecretKeySpec(new byte[32], "AES"))
            .usages(KeyUsage.ENCRYPT)
            .extractable(false)
            .register();
    int protectedRegister = s.exchanges() - before;
    before = s.exchanges();
    kms.keys().register(new SecretKeySpec(new byte[32], "AES")).usages(KeyUsage.ENCRYPT).register();
    assertEquals(s.exchanges() - before, protectedRegister);
    assertEquals(Optional.of(false), registered.attributes().extractable());
    refusedRelease(registered);

    // A replaced secret keeps its predecessor's protection unless the builder sets another.
    KeyHandle secret =
        kms.keys().registerSecret("old".toCharArray()).named("pw").extractable(false).register();
    KeyHandle next = kms.keys().registerSecret("new".toCharArray()).named("pw").replace(secret);
    assertEquals(Optional.of(false), next.attributes().extractable());
    assertThrows(PermissionDeniedException.class, next::asSecretData);
    KeyHandle open =
        kms.keys()
            .registerSecret("newer".toCharArray())
            .named("pw")
            .extractable(true)
            .replace(next);
    assertEquals("newer", new String(open.asSecretData().chars()));
    assertEquals(List.of(), s.violations());
  }

  /**
   * Below KMIP 1.4 neither attribute exists: every way to ask for one is refused before anything is
   * sent ({@link UnsupportedException}), never sent without it; and {@link KeyAttributes} states
   * neither (unknown, not "extractable").
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_3"})
  void belowKmip14ItIsRefusedBeforeAnythingIsSent(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle key = aes(kms).create();
    CurrentKey current = kms.keys().current(NAME);
    assertEquals(Optional.empty(), key.attributes().extractable());
    assertEquals(Optional.empty(), key.attributes().sensitive());
    int before = s.exchanges();
    List<org.junit.jupiter.api.function.Executable> asks =
        List.of(
            () -> aes(kms).extractable(false).create(),
            () -> aes(kms).sensitive(true).createPreActive(),
            () -> aes(kms).extractable(true).findOrCreate(),
            () ->
                kms.keys()
                    .register(new SecretKeySpec(new byte[32], "AES"))
                    .usages(KeyUsage.ENCRYPT)
                    .extractable(false)
                    .register(),
            () ->
                kms.keys()
                    .registerSecret("pw".toCharArray())
                    .named("pw")
                    .sensitive(true)
                    .replace(key),
            () -> key.rotate(Rotation.of(RotationDates.COPIED).extractable(false)),
            () -> key.rotateOrLatest(Rotation.grace(java.time.Duration.ofDays(1)).sensitive(true)),
            () ->
                key.rotateIfActiveFor(
                    java.time.Duration.ofDays(365),
                    Rotation.of(RotationDates.SHIFTED).extractable(false)),
            () -> current.rotateOrLatest(Rotation.of(RotationDates.COPIED).extractable(false)));
    for (var ask : asks) {
      UnsupportedException e = assertThrows(UnsupportedException.class, ask);
      assertTrue(e.getMessage().contains("needs KMIP 1.4"), e.getMessage());
    }
    assertEquals(before, s.exchanges(), "nothing was sent");
    assertEquals(1, s.ids().size());
  }

  /**
   * {@code findOrCreate} checks an existing key's protection against what was asked, and refuses a
   * key that states another value, or does not state it at all (the attribute absent from the
   * reply), with {@link KeyMismatchException}: the protection is never relaxed. Nothing is created
   * meanwhile. Without a protection asked, nothing is checked.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void findOrCreateNeverRelaxesTheProtection(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    boolean[] hide = new boolean[1];
    Kms kms =
        connect(
            s,
            UnaryOperator.identity(),
            (request, reply) ->
                hide[0] && is(request, Operation.GET_ATTRIBUTES)
                    ? without(reply, Tag.EXTRACTABLE, "Extractable")
                    : reply);
    KeyHandle extractable = aes(kms).create();
    KeyHandle kek =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .named("kek")
            .extractable(false)
            .create();
    int objects = s.ids().size();

    KeyMismatchException weaker =
        assertThrows(KeyMismatchException.class, () -> aes(kms).extractable(false).findOrCreate());
    assertTrue(
        weaker.getMessage().contains("its Extractable is true, not false"), weaker.getMessage());
    assertEquals(Optional.of(extractable.id()), weaker.objectId());
    assertEquals(extractable, aes(kms).extractable(true).findOrCreate());
    assertEquals(extractable, aes(kms).findOrCreate());

    KeyCreation kekBuilder = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).named("kek");
    assertEquals(kek, kekBuilder.extractable(false).findOrCreate());
    KeyMismatchException stricter =
        assertThrows(
            KeyMismatchException.class,
            () ->
                kms.keys()
                    .createAes(256)
                    .usages(KeyUsage.ENCRYPT)
                    .named("kek")
                    .extractable(true)
                    .findOrCreate());
    assertTrue(
        stricter.getMessage().contains("its Extractable is false, not true"),
        stricter.getMessage());
    KeyMismatchException sensitive =
        assertThrows(
            KeyMismatchException.class,
            () ->
                kms.keys()
                    .createAes(256)
                    .usages(KeyUsage.ENCRYPT)
                    .named("kek")
                    .sensitive(true)
                    .findOrCreate());
    assertTrue(
        sensitive.getMessage().contains("its Sensitive is false, not true"),
        sensitive.getMessage());

    hide[0] = true;
    KeyMismatchException unstated =
        assertThrows(
            KeyMismatchException.class,
            () ->
                kms.keys()
                    .createAes(256)
                    .usages(KeyUsage.ENCRYPT)
                    .named("kek")
                    .extractable(false)
                    .findOrCreate());
    assertTrue(
        unstated.getMessage().contains("the server does not state its Extractable attribute"),
        unstated.getMessage());
    assertEquals(
        kek,
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).named("kek").findOrCreate(),
        "nothing asked, nothing checked");
    assertEquals(objects, s.ids().size(), "nothing was created");
  }

  /**
   * A server that ignores the attribute (here, a transport drops it from the Create, so the server
   * makes an extractable key) or does not state it in its reply: the key made is not activated or
   * returned ({@link PartialCompletionException} naming it, the cause a {@link
   * KeyMismatchException}); it stays Pre-Active. The same for {@code findOrCreate} and a
   * registration.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aServerThatDropsTheProtectionIsCaughtBeforeActivation(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms =
        connect(
            s,
            r ->
                is(r, Operation.CREATE) || is(r, Operation.REGISTER)
                    ? without(r, Tag.EXTRACTABLE, "Extractable")
                    : r,
            (request, reply) -> reply);
    PartialCompletionException created =
        assertThrows(PartialCompletionException.class, () -> aes(kms).extractable(false).create());
    assertInstanceOf(KeyMismatchException.class, created.getCause());
    assertTrue(
        created.getMessage().contains("its Extractable is true, not false"), created.getMessage());
    String id = created.created().get(0).id();
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(id), "never activated");

    PartialCompletionException found =
        assertThrows(
            PartialCompletionException.class,
            () ->
                kms.keys()
                    .createAes(256)
                    .usages(KeyUsage.ENCRYPT)
                    .named("other")
                    .extractable(false)
                    .findOrCreate());
    assertInstanceOf(KeyMismatchException.class, found.getCause());
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(found.created().get(0).id()));

    PartialCompletionException registered =
        assertThrows(
            PartialCompletionException.class,
            () ->
                kms.keys()
                    .register(new SecretKeySpec(new byte[32], "AES"))
                    .usages(KeyUsage.ENCRYPT)
                    .extractable(false)
                    .register());
    assertInstanceOf(KeyMismatchException.class, registered.getCause());
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(registered.created().get(0).id()));
  }

  /**
   * When reading a registered object back fails, the advice says to check the protection asked
   * before activating it, and says nothing of it when none was asked.
   */
  @Test
  void aFailedReadBackOfARegistrationSaysToCheckTheProtectionAsked() {
    InMemoryKmipServer s = server(KmipVersion.V2_1);
    Kms kms =
        Kms.connect(
            s.configure()
                .retryPolicy(RetryPolicy.none())
                .transport(
                    e ->
                        r -> {
                          if (is(r, Operation.GET_ATTRIBUTES))
                            throw new java.io.IOException("the read-back fails");
                          return s.exchange(r);
                        })
                .build());
    clients.add(kms);
    PartialCompletionException asked =
        assertThrows(
            PartialCompletionException.class,
            () ->
                kms.keys()
                    .register(new SecretKeySpec(new byte[32], "AES"))
                    .usages(KeyUsage.ENCRYPT)
                    .extractable(false)
                    .register());
    assertTrue(
        asked
            .getMessage()
            .contains(
                "check their kinds and that they have the protection asked (Extractable false)"),
        asked.getMessage());
    assertTrue(asked.getMessage().contains("remove their names"), asked.getMessage());
    assertEquals(Optional.of(KeyState.PRE_ACTIVE), s.state(asked.created().get(0).id()));
    PartialCompletionException none =
        assertThrows(
            PartialCompletionException.class,
            () ->
                kms.keys()
                    .register(new SecretKeySpec(new byte[32], "AES"))
                    .usages(KeyUsage.ENCRYPT)
                    .register());
    assertTrue(none.getMessage().contains("check their kinds with"), none.getMessage());
    assertTrue(none.getMessage().contains("keep them either way"), none.getMessage());
  }

  /**
   * A rotation keeps the protection: KMIP's Re-key copies Extractable and Sensitive (1.4 §4.4, 2.1
   * §6.1.46), the Re-key sends neither unless the {@link Rotation} asks, and the replacement is
   * checked. A {@link Rotation} that asks sends it and the replacement states it. A replacement
   * that does not keep the old key's protection (here a server made it extractable) is not
   * returned: {@link PartialCompletionException} naming it.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aRotationKeepsTheProtection(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    boolean[] weaken = new boolean[1];
    List<Ttlv> reKeys = new ArrayList<>();
    Kms kms =
        connect(
            s,
            r -> {
              if (!is(r, Operation.RE_KEY)) return r;
              reKeys.add(r);
              if (!weaken[0]) return r;
              // A server that does not copy the protection: its replacement is extractable.
              return rewrite(
                  r,
                  n -> {
                    if (n.tag() != Tag.REQUEST_PAYLOAD.code()) return n;
                    List<Ttlv> c = new ArrayList<>(n.children());
                    Ttlv x = Attributes.attribute("Extractable", Ttlv.bool(Tag.EXTRACTABLE, true));
                    c.add(
                        version.atLeast(KmipVersion.V2_0)
                            ? Ttlv.structure(Tag.ATTRIBUTES, Ttlv.bool(Tag.EXTRACTABLE, true))
                            : Attributes.template(x));
                    return Ttlv.structure(n.tag(), c);
                  });
            },
            (request, reply) -> reply);
    KeyHandle k0 = aes(kms).extractable(false).create();
    KeyHandle k1 = k0.rotate();
    assertEquals(Optional.of(false), k1.attributes().extractable());
    refusedRelease(k1);
    assertFalse(
        sends(reKeys.get(0), Tag.EXTRACTABLE, "Extractable"), "a plain rotation asks for nothing");

    KeyHandle k2 = k1.rotate(Rotation.of(RotationDates.COPIED).sensitive(true));
    assertTrue(sends(reKeys.get(1), Tag.SENSITIVE, "Sensitive"));
    assertEquals(Optional.of(true), k2.attributes().sensitive());
    assertEquals(Optional.of(false), k2.attributes().extractable(), "the rest is copied");

    weaken[0] = true;
    PartialCompletionException e = assertThrows(PartialCompletionException.class, k2::rotate);
    assertInstanceOf(KeyMismatchException.class, e.getCause());
    assertTrue(
        e.getMessage().contains("does not keep the protection of " + k2.id()), e.getMessage());
    assertTrue(
        e.getCause().getMessage().contains("its Extractable is true, not false"),
        e.getCause().getMessage());
    String k3 = e.created().get(0).id();
    assertEquals(List.of(k3), s.links(k2.id(), LinkKind.REPLACEMENT));
    assertEquals(List.of(), s.violations());
  }

  static boolean sends(Ttlv request, Tag tag, String name) {
    boolean[] found = new boolean[1];
    rewrite(
        request,
        n -> {
          if (attribute(n, tag, name)) found[0] = true;
          return n;
        });
    return found[0];
  }

  /**
   * A Compromised non-extractable key's replacement is non-extractable: by Re-key (copied), and
   * where the server refuses the Re-key, as the new key {@code replaceCompromised} makes and links
   * (the old key's Extractable false is sent, and read back). {@code findOrCreate} with {@code
   * replacingCompromised()} gives its replacement the builder's protection.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void aCompromiseReplacementKeepsTheProtection(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle k0 = aes(kms).extractable(false).create();
    KeyHandle byReKey = k0.replaceCompromised(RevocationReason.keyCompromise("leaked", START));
    assertEquals(Optional.of(false), byReKey.attributes().extractable());

    KeyHandle other =
        kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).named("other").sensitive(true).create();
    s.failNext(ServerOperation.RE_KEY, dev.keytend.kmip.testing.Fault.UNSUPPORTED);
    KeyHandle successor = other.replaceCompromised(RevocationReason.keyCompromise("leaked", START));
    assertNotEquals(other, successor);
    assertEquals(
        Optional.of(true),
        successor.attributes().sensitive(),
        "a new key, given the old key's Sensitive");
    assertEquals(List.of(other.id()), s.links(successor.id(), LinkKind.REPLACED));

    KeyHandle third = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).named("third").create();
    third.revoke(RevocationReason.keyCompromise("leaked", START));
    KeyHandle replaced =
        kms.keys()
            .createAes(256)
            .usages(KeyUsage.ENCRYPT)
            .named("third")
            .extractable(false)
            .replacingCompromised()
            .findOrCreate();
    assertEquals(
        Optional.of(false),
        replaced.attributes().extractable(),
        "the builder's protection, sent with the Re-key");
  }

  // ---- raw material for one stated purpose ----

  /**
   * {@code asSecretKey(Expect, LocalUse)}: ENCRYPT and WRAP need an Active key, DECRYPT and UNWRAP
   * an Active or Deactivated one (Compromised only through {@code allowingCompromised()}); every use
   * refuses Pre-Active and Destroyed keys ({@link StateConflictException} with the state), and a key
   * whose usage mask lacks the use's usage ({@link KeyMismatchException}). A refusal costs the one
   * Get Attributes; a key handed out costs the same requests whatever the use.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void rawKeysAreHandedOutForTheirPurposeOnly(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle active = aes(kms).create();
    int before = s.exchanges();
    active.asSecretKey(Expect.aes(256), LocalUse.DECRYPT);
    int plain = s.exchanges() - before;
    before = s.exchanges();
    assertEquals(32, active.asSecretKey(Expect.aes(256), LocalUse.ENCRYPT).getEncoded().length);
    assertEquals(plain, s.exchanges() - before, "the same requests");
    active.asSecretKey(Expect.aes(), LocalUse.DECRYPT);

    KeyHandle preActive = aes(kms).named("pre").createPreActive();
    for (LocalUse use : LocalUse.values()) refused(s, preActive, use, KeyState.PRE_ACTIVE);

    KeyHandle deactivated = aes(kms).named("old").create();
    deactivated.deactivate();
    refused(s, deactivated, LocalUse.ENCRYPT, KeyState.DEACTIVATED);
    deactivated.asSecretKey(Expect.aes(256), LocalUse.DECRYPT);

    KeyHandle compromised = aes(kms).named("leaked").create();
    compromised.revoke(RevocationReason.keyCompromise("leaked", START));
    refused(s, compromised, LocalUse.DECRYPT, KeyState.COMPROMISED);
    refused(s, compromised.allowingCompromised(), LocalUse.ENCRYPT, KeyState.COMPROMISED);
    compromised.allowingCompromised().asSecretKey(Expect.aes(256), LocalUse.DECRYPT);

    KeyHandle destroyed = aes(kms).named("gone").create();
    destroyed.deactivate();
    destroyed.destroy();
    refused(s, destroyed, LocalUse.DECRYPT, KeyState.DESTROYED);

    KeyHandle decryptOnly = kms.keys().createAes(256).usages(KeyUsage.DECRYPT).create();
    before = s.exchanges();
    KeyMismatchException usage =
        assertThrows(
            KeyMismatchException.class,
            () -> decryptOnly.asSecretKey(Expect.aes(256), LocalUse.ENCRYPT));
    assertTrue(usage.getMessage().contains("does not permit ENCRYPT"), usage.getMessage());
    assertEquals(before + 1, s.exchanges(), "refused after the Get Attributes, before the Get");
    decryptOnly.asSecretKey(Expect.aes(256), LocalUse.DECRYPT);
    assertThrows(
        KeyMismatchException.class,
        () -> decryptOnly.asSecretKey(Expect.aes(256), LocalUse.UNWRAP));

    KeyHandle wrapping =
        kms.keys().createAes(256).usages(KeyUsage.WRAP_KEY, KeyUsage.UNWRAP_KEY).create();
    wrapping.asSecretKey(Expect.aes(256), LocalUse.WRAP);
    wrapping.asSecretKey(Expect.aes(256), LocalUse.UNWRAP);
    assertThrows(
        KeyMismatchException.class, () -> wrapping.asSecretKey(Expect.aes(256), LocalUse.ENCRYPT));

    before = s.exchanges();
    assertThrows(NullPointerException.class, () -> active.asSecretKey(Expect.aes(256), null));
    assertEquals(before, s.exchanges());
  }

  static void refused(InMemoryKmipServer s, KeyHandle key, LocalUse use, KeyState state) {
    int before = s.exchanges();
    StateConflictException e =
        assertThrows(StateConflictException.class, () -> key.asSecretKey(Expect.aes(256), use));
    assertEquals(Optional.of(state), e.observedState(), use + ": " + e.getMessage());
    assertEquals(before + 1, s.exchanges(), use + ": the Get Attributes only");
  }

  // ---- Expect.aes() ----

  /**
   * {@link Expect#aes()} takes a key of each AES size, and still refuses material of another size
   * and a declared length that differs from the material; {@code aes(bits)} stays exact.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V2_1", "V3_0"})
  void anyAesSizeIsAcceptedAndNothingElse(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    boolean[] misdeclare = new boolean[1];
    Kms kms =
        connect(
            s,
            UnaryOperator.identity(),
            (request, reply) ->
                misdeclare[0] && is(request, Operation.GET)
                    ? rewrite(
                        reply,
                        n ->
                            n.tag() == Tag.CRYPTOGRAPHIC_LENGTH.code()
                                ? Ttlv.integer(Tag.CRYPTOGRAPHIC_LENGTH, 128)
                                : n)
                    : reply);
    for (int bits : new int[] {128, 192, 256}) {
      KeyHandle key = kms.keys().createAes(bits).usages(KeyUsage.ENCRYPT).create();
      assertEquals(bits / 8, key.asSecretKey(Expect.aes(), LocalUse.ENCRYPT).getEncoded().length);
    }
    KeyHandle k256 = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
    assertThrows(
        KeyMismatchException.class, () -> k256.asSecretKey(Expect.aes(128), LocalUse.ENCRYPT));

    KeyHandle odd =
        kms.keys()
            .register(new SecretKeySpec(new byte[20], "AES"))
            .usages(KeyUsage.ENCRYPT)
            .register();
    KeyMismatchException size =
        assertThrows(
            KeyMismatchException.class, () -> odd.asSecretKey(Expect.aes(), LocalUse.ENCRYPT));
    assertTrue(
        size.getCause().getMessage().contains("128, 192 or 256 bits, the key has 160"),
        size.getCause().getMessage());
    assertThrows(
        KeyMismatchException.class,
        () -> odd.asSecretKey(Expect.of(Algorithm.AES, 0), LocalUse.ENCRYPT));

    misdeclare[0] = true;
    KeyMismatchException declared =
        assertThrows(
            KeyMismatchException.class, () -> k256.asSecretKey(Expect.aes(), LocalUse.ENCRYPT));
    assertTrue(
        declared.getCause().getMessage().contains("Declared length"),
        declared.getCause().getMessage());
    assertEquals(Expect.of(Algorithm.AES, 0), Expect.aes());
  }

  // ---- the guide and the sample ----

  /** The envelope sample's KEK is created non-extractable where the version allows (1.4 on). */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_2", "V1_4", "V2_1", "V3_0"})
  void theEnvelopeSamplesKekIsNotExtractable(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    KeyHandle kek = dev.keytend.kmip.kms.samples.EnvelopeEncryption.createKek(kms, "envelope-kek");
    if (version.atLeast(KmipVersion.V1_4)) {
      assertEquals(Optional.of(false), kek.attributes().extractable());
      refusedRelease(kek);
    } else assertEquals(Optional.empty(), kek.attributes().extractable());
    assertEquals(
        kek, dev.keytend.kmip.kms.samples.EnvelopeEncryption.createKek(kms, "envelope-kek"));
  }

  /**
   * The flow of docs/local-keys.md, "Raw keys": an extractable key, the write key by name for
   * ENCRYPT with its identifier stored, a rotation and the old key deactivated, then the stored
   * identifier for DECRYPT (the name now finds another key, which is why a name never decrypts),
   * and the old key refused for ENCRYPT.
   */
  @ParameterizedTest
  @EnumSource(
      value = KmipVersion.class,
      names = {"V1_4", "V2_1", "V3_0"})
  void theGuidesRawKeysFlow(KmipVersion version) {
    InMemoryKmipServer s = server(version);
    Kms kms = connect(s);
    kms.keys()
        .createAes(256)
        .named("tde")
        .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
        .extractable(true)
        .findOrCreate();

    KeyHandle current = kms.keys().findByName("tde").orElseThrow();
    DestroyableSecretKey writeKey = current.asSecretKey(Expect.aes(), LocalUse.ENCRYPT);
    String storedKeyId = current.id();

    current.rotate().deactivatePredecessors();
    DestroyableSecretKey readKey =
        kms.keys().handle(storedKeyId).asSecretKey(Expect.aes(), LocalUse.DECRYPT);
    assertArrayEquals(writeKey.getEncoded(), readKey.getEncoded());
    KeyHandle byName = kms.keys().findByName("tde").orElseThrow();
    assertNotEquals(storedKeyId, byName.id());
    assertFalse(
        Arrays.equals(
            writeKey.getEncoded(),
            byName.asSecretKey(Expect.aes(), LocalUse.DECRYPT).getEncoded()));
    refused(s, kms.keys().handle(storedKeyId), LocalUse.ENCRYPT, KeyState.DEACTIVATED);
  }
}
