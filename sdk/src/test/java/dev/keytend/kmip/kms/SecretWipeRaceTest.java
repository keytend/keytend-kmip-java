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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.junit.jupiter.api.Test;

/**
 * A copy taken while another thread destroys the key is the whole key or an
 * IllegalStateException, never a partly or fully wiped key (which JCA would accept as a valid AES
 * key and encrypt under, unrecoverably).
 */
class SecretWipeRaceTest {
  private static final int ROUNDS = 200_000;

  @Test
  void aKeyCopiedWhileItIsDestroyedIsWholeOrRefused() throws Exception {
    race(
        bytes -> {
          DestroyableSecretKey k = new DestroyableSecretKey(bytes, "AES");
          return new Target(k::getEncoded, k::destroy);
        });
  }

  @Test
  void aSecretCopiedWhileItIsDestroyedIsWholeOrRefused() throws Exception {
    race(
        bytes -> {
          SecretData s = new SecretData(SecretData.Type.PASSWORD, bytes);
          return new Target(s::bytes, s::destroy);
        });
    race(
        bytes -> {
          SecretData s = new SecretData(SecretData.Type.PASSWORD, bytes);
          return new Target(
              () -> new String(s.chars()).getBytes(StandardCharsets.UTF_8), s::destroy);
        });
  }

  private record Target(java.util.function.Supplier<byte[]> read, Runnable destroy) {}

  private static void race(Function<byte[], Target> make) throws Exception {
    byte[] original = new byte[32];
    Arrays.fill(
        original, (byte) 'k'); // nonzero ASCII, so a wiped byte always shows, also through chars()
    CyclicBarrier start = new CyclicBarrier(2);
    AtomicInteger wrong = new AtomicInteger();
    AtomicInteger whole = new AtomicInteger();
    Target[] current = new Target[1];
    Thread destroyer =
        new Thread(
            () -> {
              try {
                for (int i = 0; i < ROUNDS; i++) {
                  start.await();
                  current[0].destroy().run();
                  start.await();
                }
              } catch (Exception e) {
                throw new AssertionError(e);
              }
            });
    destroyer.start();
    for (int i = 0; i < ROUNDS; i++) {
      current[0] = make.apply(original);
      start.await();
      try {
        byte[] copy = current[0].read().get();
        if (Arrays.equals(copy, original)) whole.incrementAndGet();
        else wrong.incrementAndGet();
      } catch (IllegalStateException expected) {
        // destroyed first: refused, as documented
      }
      start.await();
    }
    destroyer.join();
    assertEquals(
        0, wrong.get(), "copies that were neither the whole key nor refused (" + whole + " whole)");
  }
}
