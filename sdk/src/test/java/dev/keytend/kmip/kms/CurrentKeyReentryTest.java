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
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Test;

/**
 * A scheduled check still running when {@link CurrentKey#close()} returns moves nothing.
 */
class CurrentKeyReentryTest {
  static final byte[] PLAIN = {1, 2, 3};
  static final byte[] AAD = "record".getBytes(StandardCharsets.UTF_8);

  static KeyHandle aes(Kms kms) {
    return kms.keys().createAes(256).usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT).create();
  }

  /**
   * {@code close()} returns while a scheduled check waits for the KMS: the check ends without
   * moving the key held.
   */
  @Test
  void aCheckRunningWhenCloseReturnsMovesNothing() throws Exception {
    InMemoryKmipServer s = InMemoryKmipServer.of(KmipVersion.V2_1);
    CurrentKeyFollowerTest.Manual executor = new CurrentKeyFollowerTest.Manual();
    try (Kms kms = Kms.connect(s.configure().retryPolicy(RetryPolicy.none()).build())) {
      KeyHandle key = aes(kms);
      CurrentKey kek = kms.keys().current(key).refreshingEvery(Duration.ofMinutes(1), executor);
      KeyHandle replacement = kms.keys().handle(key.id()).rotate();
      CountDownLatch inCheck = new CountDownLatch(1), release = new CountDownLatch(1);
      s.injectBeforeProcessing(
          request -> {
            inCheck.countDown();
            try {
              release.await(10, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
              Thread.currentThread().interrupt();
            }
            return null;
          });
      Thread check = new Thread(executor::check);
      check.start();
      assertTrue(inCheck.await(10, TimeUnit.SECONDS));
      kek.close();
      String heldWhenCloseReturned = kek.handle().id();
      release.countDown(); // the hook runs with the server's lock held: release before disarming
      check.join(10_000);
      s.injectBeforeProcessing(null);
      String heldAfter = kek.handle().id();
      assertEquals(key.id(), heldWhenCloseReturned);
      assertEquals(key.id(), heldAfter, "a check running when close() returned moved the key held");
      assertEquals(
          replacement.id(),
          kms.keys().handle(key.id()).latest().id(),
          "there was a key to move to");
    } finally {
      executor.shutdownNow();
      s.close();
    }
  }
}
