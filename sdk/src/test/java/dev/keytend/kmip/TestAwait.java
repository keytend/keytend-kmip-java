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

package dev.keytend.kmip;

import java.time.Duration;
import org.awaitility.Awaitility;
import org.awaitility.core.ConditionFactory;

/**
 * The tests' waits for an eventual condition (Awaitility): every one is bounded by {@link
 * #TIMEOUT} unless it says otherwise, checks at once and then every {@link #POLL}, in the test's
 * own thread (a condition may call the SDK, and its exceptions fail the test as they are), and
 * names what it waits for in the failure. Not for what a test is about: latches, barriers, manual
 * clocks and deliberate sleeps stay as they are.
 */
public final class TestAwait {
  /** The bound on an eventual condition: generous, as only a stuck condition reaches it. */
  public static final Duration TIMEOUT = Duration.ofSeconds(10);

  /** How often a condition is checked. */
  public static final Duration POLL = Duration.ofMillis(10);

  private TestAwait() {}

  /** A wait for {@code what}, up to {@link #TIMEOUT}. */
  public static ConditionFactory await(String what) {
    return Awaitility.await(what)
        .atMost(TIMEOUT)
        .pollDelay(Duration.ZERO)
        .pollInterval(POLL)
        .pollInSameThread();
  }
}
