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

import dev.keytend.kmip.kms.LeasingTransport.Refuse;
import dev.keytend.kmip.model.Enums;
import dev.keytend.kmip.model.Tag;
import dev.keytend.kmip.model.Ttlv;
import dev.keytend.kmip.testing.Fault;
import dev.keytend.kmip.testing.InMemoryKmipServer;
import dev.keytend.kmip.testing.ServerOperation;
import dev.keytend.kmip.transport.CallContext;
import dev.keytend.kmip.transport.KmipTransport;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Every {@link KmsException} the SDK makes from a server's failure result ends its message with
 * the server's Result Message, sanitized, exactly once; messages without one are unchanged.
 */
class ServerMessageTest {
  /**
   * What a hostile server says: line breaks, separators, bidirectional controls, a bell, quotes, too
   * long. (A lone surrogate cannot be sent: the codec refuses it.)
   */
  static final String HOSTILE =
      "denied\nby policy\r\n\u2028line\u2029para \u202Eevil\u202C \u0007bell \"quoted\" "
          + "\uD83D\uDD11 "
          + "y".repeat(300);

  /**
   * In front of the in-memory server: the Result Message of every failed batch item becomes {@link
   * #said} (none when null).
   */
  static final class Saying implements KmipTransport {
    final KmipTransport next;
    volatile String said = HOSTILE;

    Saying(KmipTransport next) {
      this.next = next;
    }

    @Override
    public Ttlv exchange(Ttlv request) throws IOException {
      return exchange(request, CallContext.NONE);
    }

    @Override
    public Ttlv exchange(Ttlv request, CallContext context) throws IOException {
      Ttlv response = next.exchange(request, context);
      List<Ttlv> top = new ArrayList<>();
      for (Ttlv field : response.children())
        top.add(field.tag() == Tag.BATCH_ITEM.code() ? item(field) : field);
      return Ttlv.structure(response.tag(), top);
    }

    private Ttlv item(Ttlv item) {
      boolean failed = item.child(Tag.RESULT_STATUS).map(s -> s.intValue() != 0).orElse(false);
      if (!failed) return item;
      List<Ttlv> fields = new ArrayList<>();
      for (Ttlv f : item.children()) {
        if (f.tag() == Tag.RESULT_MESSAGE.code()) continue;
        fields.add(f);
        if (f.tag() == Tag.RESULT_REASON.code() && said != null)
          fields.add(Ttlv.text(Tag.RESULT_MESSAGE, said));
      }
      return Ttlv.structure(Tag.BATCH_ITEM, fields);
    }
  }

  static final class Fixture implements AutoCloseable {
    final InMemoryKmipServer server;
    final LeasingTransport leasing;
    final Saying saying;
    final Kms admin, client;
    final KmipVersion version;

    Fixture(KmipVersion version) {
      this.version = version;
      server = InMemoryKmipServer.of(version);
      leasing = new LeasingTransport(server);
      saying = new Saying(leasing);
      admin = server.connect();
      client =
          Kms.connect(
              server
                  .configure()
                  .retryPolicy(RetryPolicy.none())
                  .callTimeout(Duration.ofSeconds(5))
                  .transport(e -> saying)
                  .build());
    }

    KeyHandle key() {
      KeyCreation c = admin.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT);
      if (version.compareTo(KmipVersion.V1_4) >= 0) c.extractable(true);
      return client.keys().handle(c.create().id());
    }

    @Override
    public void close() {
      client.close();
      admin.close();
      server.close();
    }
  }

  /** One way to a failure result: what it arms, what it calls, and the exception it expects. */
  interface Path {
    KmsException run(Fixture f);
  }

  static Arguments path(String name, Class<? extends KmsException> type, Path path) {
    return Arguments.of(name, type, path);
  }

  static <T extends KmsException> T thrown(
      Class<T> type, org.junit.jupiter.api.function.Executable call) {
    return assertThrows(type, call);
  }

  static Stream<Arguments> paths() {
    List<Arguments> paths =
        List.of(
            path(
                "not found",
                NotFoundException.class,
                f -> {
                  KeyHandle key = f.key();
                  f.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.NOT_FOUND);
                  return thrown(KmsException.class, key::attributes);
                }),
            path(
                "permission denied",
                PermissionDeniedException.class,
                f -> {
                  KeyHandle key = f.key();
                  f.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.PERMISSION_DENIED);
                  return thrown(KmsException.class, key::attributes);
                }),
            path(
                "invalid request",
                InvalidRequestException.class,
                f -> {
                  KeyHandle key = f.key();
                  f.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.INVALID_REQUEST);
                  return thrown(KmsException.class, key::attributes);
                }),
            path(
                "unsupported",
                UnsupportedException.class,
                f -> {
                  KeyHandle key = f.key();
                  f.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.UNSUPPORTED);
                  return thrown(KmsException.class, key::attributes);
                }),
            path(
                "state conflict",
                StateConflictException.class,
                f -> {
                  KeyHandle key = f.key();
                  f.server.failNext(
                      f.version == KmipVersion.V3_0
                          ? ServerOperation.DEACTIVATE
                          : ServerOperation.REVOKE,
                      Fault.STATE_CONFLICT);
                  return thrown(KmsException.class, key::deactivate);
                }),
            path(
                "already exists",
                AlreadyExistsException.class,
                f -> {
                  f.server.failNext(ServerOperation.CREATE, Fault.ALREADY_EXISTS);
                  return thrown(
                      KmsException.class,
                      () ->
                          f.client
                              .keys()
                              .createAes(256)
                              .usages(KeyUsage.ENCRYPT)
                              .named("dup")
                              .create());
                }),
            path(
                "server failure",
                ServerFailureException.class,
                f -> {
                  KeyHandle key = f.key();
                  f.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.SERVER_FAILURE);
                  return thrown(KmsException.class, key::attributes);
                }),
            path(
                "2.x: busy read (transient)",
                TransientException.class,
                f -> {
                  KeyHandle key = f.key();
                  f.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.SERVER_BUSY);
                  return thrown(KmsException.class, key::attributes);
                }),
            path(
                "2.x: key mismatch",
                KeyMismatchException.class,
                f -> {
                  KeyHandle key = f.key();
                  f.server.failNext(
                      ServerOperation.ENCRYPT, Enums.ResultReason.ILLEGAL_OBJECT_TYPE);
                  return thrown(
                      KmsException.class, () -> key.encrypt(CipherSpec.aesGcm(), new byte[16]));
                }),
            path(
                "cryptographic failure",
                CryptographicFailureException.class,
                f -> {
                  KeyHandle key = f.key();
                  Ciphertext c = key.encrypt(CipherSpec.aesGcm(), new byte[16]);
                  f.server.failNext(
                      ServerOperation.DECRYPT, Enums.ResultReason.CRYPTOGRAPHIC_FAILURE);
                  return thrown(KmsException.class, () -> key.decrypt(c, null));
                }),
            path(
                "a Deactivated key's encryption, read back (the SDK's own message)",
                StateConflictException.class,
                f -> {
                  KeyHandle key = f.key();
                  f.admin.keys().handle(key.id()).deactivate();
                  return thrown(
                      KmsException.class, () -> key.encrypt(CipherSpec.aesGcm(), new byte[16]));
                }),
            path(
                "a failed activation after a creation (the cause's message inside)",
                PartialCompletionException.class,
                f -> {
                  f.server.failNext(ServerOperation.ACTIVATE, Fault.SERVER_FAILURE);
                  return thrown(
                      KmsException.class,
                      () -> f.client.keys().createAes(256).usages(KeyUsage.ENCRYPT).create());
                }),
            path(
                "a refused lease (already quoted)",
                PermissionDeniedException.class,
                f -> {
                  KeyHandle key = f.key();
                  f.leasing.everyObject = 60L;
                  f.leasing.answer = id -> new Refuse(Enums.ResultReason.PERMISSION_DENIED);
                  return thrown(
                      KmsException.class, () -> key.asSecretKey(Expect.aes(256), LocalUse.DECRYPT));
                }));
    return Stream.of(KmipVersion.V1_4, KmipVersion.V2_1, KmipVersion.V3_0)
        .flatMap(
            v ->
                paths.stream()
                    // KMIP 1.x has neither Server Limit Exceeded nor Illegal Object Type.
                    .filter(a -> v != KmipVersion.V1_4 || !a.get()[0].toString().startsWith("2.x"))
                    .map(a -> Arguments.of(v, a.get()[0], a.get()[1], a.get()[2])));
  }

  static int count(String text, String part) {
    int n = 0;
    for (int i = text.indexOf(part); i >= 0; i = text.indexOf(part, i + 1)) n++;
    return n;
  }

  @ParameterizedTest(name = "{0} {1}")
  @MethodSource("paths")
  void theServersMessageIsInTheMessageOnceAndSanitized(
      KmipVersion version, String name, Class<? extends KmsException> type, Path path) {
    String said = KmsException.sanitized(HOSTILE);
    try (Fixture f = new Fixture(version)) {
      KmsException e = path.run(f);
      if (type != null) assertInstanceOf(type, e, e.toString());
      String m = e.getMessage();
      assertEquals(1, count(m, "\"" + said + "\""), m);
      assertEquals(1, count(m, "denied by policy"), m);
      for (char c : new char[] {'\n', '\r', '\u2028', '\u2029', '\u202E', '\u202C', '\u0007'})
        assertEquals(-1, m.indexOf(c), Integer.toHexString(c) + " in " + m);
      assertTrue(m.contains("\uD83D\uDD11"), "a printable supplementary character is kept: " + m);
      assertEquals(0, count(m, "y".repeat(201)), "capped: " + m);
      // The structured fields are as the server sent them.
      assertEquals(java.util.Optional.of(HOSTILE), e.serverMessage(), name);
      assertTrue(e.result().isPresent(), name);
      assertEquals(m, e.toString().substring(e.getClass().getName().length() + 2));

      // Without a message, or with a blank one, nothing is added (and no empty quotes).
      for (String none : new String[] {null, "", " \n\u202E "}) {
        f.saying.said = none;
        KmsException bare = path.run(f);
        assertFalse(bare.getMessage().contains("server message"), bare.getMessage());
        assertFalse(bare.getMessage().contains("\"\""), bare.getMessage());
      }
    }
  }

  @Test
  void theSuffixIsOneQuotedLineAtTheEnd() {
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      f.saying.said = "no such\tkey";
      f.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.NOT_FOUND);
      KmsException e = assertThrows(NotFoundException.class, key::attributes);
      assertTrue(
          e.getMessage()
              .endsWith(
                  " failed: KMIP GetAttributes returned OperationFailed (1), reason ObjectNotFound"
                      + " (0x00000037) (server message: \"no such key\")"),
          e.getMessage());
    }
  }

  @Test
  void theSanitizedTextIsOneShortLine() {
    String s = KmsException.sanitized("  a\nb\"c\uD800d\u200Fe  ");
    assertEquals("a b c d e", s);
    String longer = KmsException.sanitized("\uD83D\uDD11".repeat(250));
    assertEquals(
        200, longer.codePointCount(0, longer.length()) - 3, "200 code points and an ellipsis");
    assertTrue(longer.endsWith("..."));
    assertEquals("x".repeat(200), KmsException.sanitized("x".repeat(200)), "200 is not cut");
    assertEquals(
        StandardCharsets.UTF_8.decode(StandardCharsets.UTF_8.encode(longer)).toString(),
        longer,
        "well-formed");
  }

  @Test
  void onlyAFailureResultsMessageIsAdded() {
    var failed = new dev.keytend.kmip.client.Result(null, 1, null, "said", null);
    var success = new dev.keytend.kmip.client.Result(null, 0, null, "said", null);
    assertEquals(
        "get k failed (server message: \"said\")",
        new ServerFailureException("get k failed", null, "get", "k", failed, null).getMessage());
    assertEquals(
        "get k",
        new ProtocolViolationException("get k", null, "get", "k", success, null).getMessage());
    assertEquals(
        "x \"said\" y",
        new ServerFailureException("x \"said\" y", null, "get", "k", failed, null).getMessage());
  }

  @Test
  void exceptionsWithoutAServerResultAreUnchanged() {
    // An application's exceptions, also one whose cause has a server result.
    try (Fixture f = new Fixture(KmipVersion.V2_1)) {
      KeyHandle key = f.key();
      f.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.SERVER_FAILURE);
      KmsException cause = assertThrows(ServerFailureException.class, key::attributes);
      assertEquals("mine", new PartialCompletionException("mine", List.of(), cause).getMessage());
      assertEquals("mine", new NotFoundException("mine", cause).getMessage());
      // A refusal after a successful read, and a transport failure.
      KmsException local =
          assertThrows(
              KeyMismatchException.class, () -> key.asSecretKey(Expect.aes(128), LocalUse.DECRYPT));
      assertFalse(local.getMessage().contains("server message"), local.getMessage());
      f.server.failNext(ServerOperation.GET_ATTRIBUTES, Fault.UNREACHABLE);
      KmsException transport = assertThrows(TransientException.class, key::attributes);
      assertFalse(transport.getMessage().contains("server message"), transport.getMessage());
    }
  }
}
