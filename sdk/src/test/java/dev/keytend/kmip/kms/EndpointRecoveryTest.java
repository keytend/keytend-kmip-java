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
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.Test;

/**
 * {@link KmsListener#endpointAvailable}: once per recovery, when an endpoint told unavailable
 * answers again, and never for one that was not told unavailable.
 */
class EndpointRecoveryTest {
  static final String FIRST = "in-memory:5696", SECOND = "in-memory-2:5696";

  /** The endpoint events, in order: "down host:port" and "up host:port". */
  static final class Recorder implements KmsListener {
    final List<String> events = new CopyOnWriteArrayList<>();

    @Override
    public void endpointUnavailable(String endpoint, String why) {
      events.add("down " + endpoint);
    }

    @Override
    public void endpointAvailable(String endpoint) {
      events.add("up " + endpoint);
    }
  }

  /** Two replicas; no cool-down, so a recovered endpoint is used again at once. */
  static KmsConfig.Builder replicas(InMemoryKmipServer first, InMemoryKmipServer second) {
    return first
        .configureReplicas(second)
        .retryPolicy(
            RetryPolicy.builder()
                .maxAttempts(3)
                .initialBackoff(Duration.ofMillis(1))
                .cooldown(Duration.ZERO)
                .build());
  }

  @Test
  void anEndpointThatAnswersAgainIsAvailableOncePerRecovery() {
    InMemoryKmipServer first = InMemoryKmipServer.of(KmipVersion.V2_1), second = first.replica();
    Recorder r = new Recorder();
    try (Kms kms = Kms.connect(replicas(first, second).addListener(r).build())) {
      KeyHandle key = kms.keys().createAes(256).usages(KeyUsage.ENCRYPT).create();
      assertEquals(List.of(), r.events, "nothing goes up that was never down");

      first.unreachable(true);
      key.attributes(); // fails over to the second
      assertEquals(List.of("down " + FIRST), r.events);

      first.unreachable(false);
      second.unreachable(true);
      key.attributes(); // the second is down, the first answers again
      assertEquals(List.of("down " + FIRST, "down " + SECOND, "up " + FIRST), r.events);

      key.attributes();
      key.attributes();
      assertEquals(3, r.events.size(), "once per recovery: " + r.events);

      // A second outage of the first, and its recovery, are told again.
      second.unreachable(false);
      first.unreachable(true);
      key.attributes();
      first.unreachable(false);
      assertEquals(
          List.of(
              "down " + FIRST, "down " + SECOND, "up " + FIRST, "down " + FIRST, "up " + SECOND),
          r.events);
      second.unreachable(true);
      key.attributes();
      assertEquals("up " + FIRST, r.events.get(r.events.size() - 1), r.events.toString());
    }
  }

  @Test
  void aFailureResultIsAnAnswerToo() {
    InMemoryKmipServer first = InMemoryKmipServer.of(KmipVersion.V2_1), second = first.replica();
    Recorder r = new Recorder();
    try (Kms kms = Kms.connect(replicas(first, second).addListener(r).build())) {
      first.unreachable(true);
      assertThrows(NotFoundException.class, () -> kms.keys().handle("missing").attributes());
      assertEquals(List.of("down " + FIRST), r.events);
      first.unreachable(false);
      second.unreachable(true);
      assertThrows(NotFoundException.class, () -> kms.keys().handle("missing").attributes());
      assertEquals(List.of("down " + FIRST, "down " + SECOND, "up " + FIRST), r.events);
    }
  }

  @Test
  void anEndpointDownAtConnectIsAvailableWhenItAnswers() {
    InMemoryKmipServer first = InMemoryKmipServer.of(KmipVersion.V2_1), second = first.replica();
    Recorder r = new Recorder();
    first.unreachable(true);
    try (Kms kms = Kms.connect(replicas(first, second).addListener(r).build())) {
      assertEquals(List.of("down " + FIRST), r.events, "connected to the second");
      first.unreachable(false);
      second.unreachable(true);
      assertThrows(NotFoundException.class, () -> kms.keys().handle("missing").attributes());
      assertEquals(List.of("down " + FIRST, "down " + SECOND, "up " + FIRST), r.events);
    }
  }
}
