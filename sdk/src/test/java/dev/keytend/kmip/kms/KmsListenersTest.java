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

import dev.keytend.kmip.testing.InMemoryKmipServer;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

/**
 * Several listeners per configuration, each isolated: one that throws, an {@link Error} included,
 * changes no outcome and keeps no other listener from hearing of the event.
 */
class KmsListenersTest {
  /** Records the operations of the attempts it saw start. */
  static final class Started implements KmsListener {
    final List<String> operations = new CopyOnWriteArrayList<>();

    @Override
    public void started(KmsEvent event) {
      operations.add(event.operation());
    }
  }

  @Test
  void theCompositeOverridesEveryListenerMethod() throws Exception {
    List<String> missing = new ArrayList<>();
    for (Method m : KmsListener.class.getDeclaredMethods()) {
      if (Modifier.isStatic(m.getModifiers()) || m.isSynthetic()) continue;
      Method own = KmsListeners.class.getDeclaredMethod(m.getName(), m.getParameterTypes());
      if (own.getDeclaringClass() != KmsListeners.class) missing.add(m.getName());
    }
    assertEquals(List.of(), missing, "KmsListeners must forward every KmsListener method");
  }

  @Test
  void aListenerThatThrowsAnErrorChangesNothingAndTheNextStillHears() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Started first = new Started(), last = new Started();
    KmsListener failing =
        new KmsListener() {
          @Override
          public void started(KmsEvent event) {
            throw new NoClassDefFoundError("an optional library a listener needs is missing");
          }

          @Override
          public void finished(KmsEvent event) {
            throw new StackOverflowError();
          }
        };
    try (Kms kms =
        Kms.connect(
            server.configure().addListener(first).addListener(failing).addListener(last).build())) {
      KeyHandle key =
          kms.keys()
              .createAes(256)
              .named("isolated")
              .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
              .create();
      byte[] aad = {1}, plaintext = {2, 3};
      Ciphertext sealed = key.encrypt(CipherSpec.aesGcm(), plaintext, aad);
      assertArrayEquals(plaintext, key.decrypt(sealed, aad));
    }
    assertFalse(first.operations.isEmpty());
    assertEquals(first.operations, last.operations, "the listener after the failing one heard all");
  }

  @Test
  void addListenerAddsOneBesideTheOthers() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    Started first = new Started(), kept = new Started(), added = new Started();
    KmsConfig config =
        server.configure().addListener(first).addListener(kept).addListener(added).build();
    assertEquals(List.of(first, kept, added), config.listeners());
    assertThrows(UnsupportedOperationException.class, () -> config.listeners().clear());
    try (Kms kms = Kms.connect(config)) {
      kms.keys().createAes(256).named("listeners").usages(KeyUsage.ENCRYPT).create();
    }
    assertEquals(kept.operations, first.operations);
    assertFalse(kept.operations.isEmpty());
    assertEquals(kept.operations, added.operations);
    try (Kms kms = Kms.connect(config.toBuilder().build())) {
      kms.keys().createAes(256).named("listeners-again").usages(KeyUsage.ENCRYPT).create();
    }
    assertEquals(kept.operations, added.operations, "toBuilder keeps both");
  }

  @Test
  void aListenerAddedTwiceHearsEachCallAndAttemptOnce() {
    InMemoryKmipServer server = InMemoryKmipServer.of(KmipVersion.V2_1);
    KmsCallEventsTest.Recorder r = new KmsCallEventsTest.Recorder();
    KmsConfig config =
        server.configure().addListener(r).addListener(KmsListener.all(r, r)).addListener(r).build();
    try (Kms kms = Kms.connect(config)) {
      r.clear();
      kms.keys().createAes(256).named("twice").usages(KeyUsage.ENCRYPT).create();
    }
    r.checkWellFormed();
    assertEquals(1, r.finishedCalls().size(), r.events.toString());
    long attempts =
        r.events.stream()
            .filter(e -> e.kind() == KmsEvent.Kind.ATTEMPT)
            .filter(e -> e.outcome() == KmsEvent.Outcome.STARTED)
            .count();
    assertEquals(r.finishedCalls().get(0).attempt(), attempts, "each attempt once: " + r.events);
    List<String> heard = new ArrayList<>();
    KmsListener a =
        new KmsListener() {
          @Override
          public void endpointAvailable(String endpoint) {
            heard.add(endpoint);
          }
        };
    KmsListener.all(a, KmsListener.all(a)).endpointAvailable("kms-1:5696");
    assertEquals(List.of("kms-1:5696"), heard);
  }

  @Test
  void allCallsEachInOrder() {
    List<String> heard = new ArrayList<>();
    KmsListener a =
        new KmsListener() {
          @Override
          public void endpointAvailable(String endpoint) {
            heard.add("a " + endpoint);
          }
        };
    KmsListener b =
        new KmsListener() {
          @Override
          public void endpointAvailable(String endpoint) {
            heard.add("b " + endpoint);
          }
        };
    KmsListener.all(a, b).endpointAvailable("kms-1:5696");
    assertEquals(List.of("a kms-1:5696", "b kms-1:5696"), heard);
    assertThrows(NullPointerException.class, () -> KmsListener.all(a, null));
  }
}
