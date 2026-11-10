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

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.LongSupplier;

/**
 * At most one log line per key per window, for the SDK's warnings: an endpoint that keeps failing,
 * a refresh that keeps failing. The first event of a key is logged; the others within the window
 * after it are counted, and the first one after the window is logged with that count. One
 * timestamp and one counter per key; at most {@link #MAX_KEYS} keys are remembered (beyond that
 * all are forgotten, so a key may be logged once more early).
 */
final class LogLimiter {
  /** How many keys are remembered at most. */
  static final int MAX_KEYS = 4096;

  /** {@link #permit}'s answer for an event not to log. */
  static final long SUPPRESSED = -1;

  private final long windowNanos;
  private final LongSupplier clock;
  private final ConcurrentMap<String, Slot> slots = new ConcurrentHashMap<>();

  /** One key's state: when its next line may be logged, and the events suppressed since its last. */
  private static final class Slot {
    long next;
    long suppressed;
  }

  /**
   * @param windowNanos the window, in nanoseconds
   * @param clock the monotonic clock ({@code System::nanoTime}; tests set another)
   */
  LogLimiter(long windowNanos, LongSupplier clock) {
    this.windowNanos = windowNanos;
    this.clock = clock;
  }

  /**
   * Whether an event of {@code key} is logged now: {@link #SUPPRESSED} when not (it is counted),
   * otherwise the number of events of {@code key} suppressed since its last line, zero or more.
   */
  long permit(String key) {
    if (slots.size() >= MAX_KEYS && !slots.containsKey(key)) slots.clear();
    Slot slot = slots.computeIfAbsent(key, k -> new Slot());
    long now = clock.getAsLong();
    synchronized (slot) {
      if (slot.next != 0 && now - slot.next < 0) {
        slot.suppressed++;
        return SUPPRESSED;
      }
      long suppressed = slot.suppressed;
      slot.suppressed = 0;
      // Never 0, which means "never logged".
      slot.next = now + windowNanos == 0 ? 1 : now + windowNanos;
      return suppressed;
    }
  }
}
