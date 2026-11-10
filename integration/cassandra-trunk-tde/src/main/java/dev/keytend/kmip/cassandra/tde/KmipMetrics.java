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

package dev.keytend.kmip.cassandra.tde;

import com.codahale.metrics.Gauge;
import dev.keytend.kmip.kms.LocalKeys;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.cassandra.metrics.CassandraMetricsRegistry;
import org.apache.cassandra.metrics.DefaultNameFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * How long a node can go on without the KMS, for alarms before writes stop. Diagnostics read from
 * memory, never authorizations; scope {@code <key_alias>}, group {@value #TYPE}:
 *
 * <ul>
 *   <li>{@code org.apache.cassandra.metrics:type=Kmip,scope=<key_alias>,name=KeyUsableForSeconds}:
 *       how long new commit log segments and hints files can still get their key without the KMS
 *       ({@link LocalKeys#usableFor()}). 0 also when no write key is cached: before the first file,
 *       and on a node that has written nothing for a TTL (an unused cache is not refreshed).
 *   <li>{@code type=Kmip,scope=<key_alias>,name=WriteKeyFailing}: 1 while the write key's last
 *       validation failed ({@link LocalKeys#writeFailure()}), 0 otherwise.
 * </ul>
 *
 * <p>Trunk accepts only metric groups it lists, so the group needs this integration's patch {@code
 * 0004}. Without it the gauges are not registered (a warning says so), and the provider works.
 */
final class KmipMetrics {
  private static final Logger logger = LoggerFactory.getLogger(KmipMetrics.class);

  static final String TYPE = "Kmip";
  static final String USABLE_FOR = "KeyUsableForSeconds";
  static final String WRITE_FAILING = "WriteKeyFailing";

  /** The cache each key name's gauges read now: a cache closed and opened again replaces it. */
  private static final Map<String, LocalKeys> current = new ConcurrentHashMap<>();

  private KmipMetrics() {}

  /** Points the gauges of {@code keyName} at {@code keys}, registering them the first time. */
  static void register(String keyName, LocalKeys keys) {
    if (current.put(keyName, keys) != null) return;
    try {
      gauge(keyName, USABLE_FOR, () -> usableForSeconds(keyName));
      gauge(keyName, WRITE_FAILING, () -> writeFailing(keyName));
    } catch (RuntimeException e) {
      logger.warn("KMIP key {}: metrics not registered (does this Cassandra list the {} metric group?): {}",
          keyName, TYPE, e.toString());
    }
  }

  private static void gauge(String keyName, String metric, Gauge<Long> gauge) {
    CassandraMetricsRegistry.Metrics.register(new DefaultNameFactory(TYPE, keyName).createMetricName(metric), gauge);
  }

  static long usableForSeconds(String keyName) {
    LocalKeys keys = current.get(keyName);
    return keys == null ? 0 : keys.usableFor().map(Duration::toSeconds).orElse(-1L);
  }

  static long writeFailing(String keyName) {
    LocalKeys keys = current.get(keyName);
    return keys != null && keys.writeFailure().isPresent() ? 1 : 0;
  }

  /** The caches are closed: the gauges read 0 until a provider opens one again. */
  static void clear() {
    current.clear();
  }
}
