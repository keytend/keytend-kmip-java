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
package dev.keytend.kmip.opentelemetry;

import static io.opentelemetry.api.common.AttributeKey.doubleKey;
import static io.opentelemetry.api.common.AttributeKey.longKey;
import static io.opentelemetry.api.common.AttributeKey.stringKey;

import dev.keytend.kmip.kms.KmsException;
import io.opentelemetry.api.common.AttributeKey;
import io.opentelemetry.api.common.Attributes;
import io.opentelemetry.api.common.AttributesBuilder;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;

/**
 * The module's attribute keys, its histogram boundaries and its helpers. The semantic conventions'
 * own keys ({@code error.type}, {@code server.address}, {@code server.port}, {@code
 * network.protocol.*}) where one fits; the {@code kmip.} namespace otherwise.
 */
final class Keys {
  private Keys() {}

  // ---- metrics and spans ----

  /** The public method the application called: {@code findOrCreate}, {@code seal}, ... */
  static final AttributeKey<String> OPERATION = stringKey("kmip.operation");

  /** On a failure only: the SDK's category of it, lower case, or {@code _OTHER}. */
  static final AttributeKey<String> ERROR_TYPE = stringKey("error.type");

  /** On a failure the server reported: its Result Reason, lower case. */
  static final AttributeKey<String> RESULT_REASON = stringKey("kmip.result_reason");

  static final AttributeKey<String> SERVER_ADDRESS = stringKey("server.address");
  static final AttributeKey<Long> SERVER_PORT = longKey("server.port");

  /** The negotiated KMIP version: {@code 1.4}, {@code 2.1}, {@code 3.0}, ... */
  static final AttributeKey<String> PROTOCOL_VERSION = stringKey("network.protocol.version");

  static final AttributeKey<String> FAILOVER_FROM = stringKey("kmip.failover.from");
  static final AttributeKey<String> FAILOVER_TO = stringKey("kmip.failover.to");

  /** A {@code LocalKeys} cache's name ({@code LocalKeys.name()}, its write key name). */
  static final AttributeKey<String> CACHE = stringKey("kmip.localkeys.name");

  static final AttributeKey<String> PURPOSE = stringKey("kmip.localkeys.purpose");
  static final AttributeKey<String> CACHE_RESULT = stringKey("kmip.localkeys.result");
  static final AttributeKey<String> LEASE_RESULT = stringKey("kmip.lease.result");
  static final AttributeKey<String> RELOAD_RESULT = stringKey("kmip.tls.reload.result");
  static final AttributeKey<String> RENEWAL_RESULT = stringKey("kmip.tls.renewal.result");
  static final AttributeKey<String> STATE_FROM = stringKey("kmip.key.state.from");
  static final AttributeKey<String> STATE_TO = stringKey("kmip.key.state.to");
  static final AttributeKey<String> REPLACEMENT_KIND = stringKey("kmip.key.replacement.kind");
  static final AttributeKey<String> CONNECTION_STATE = stringKey("kmip.connection.state");

  /** A TLS identity follower's name. */
  static final AttributeKey<String> IDENTITY = stringKey("kmip.tls.identity");

  // ---- spans only: identifiers, never on a metric ----

  static final AttributeKey<String> PROTOCOL_NAME = stringKey("network.protocol.name");
  static final AttributeKey<Long> CALL_ID = longKey("kmip.call.id");
  static final AttributeKey<String> STEP = stringKey("kmip.step");
  static final AttributeKey<Long> ATTEMPT_NUMBER = longKey("kmip.attempt.number");
  static final AttributeKey<Long> ATTEMPT_COUNT = longKey("kmip.attempt.count");
  static final AttributeKey<String> OBJECT_ID = stringKey("kmip.object.id");
  static final AttributeKey<Double> RETRY_DELAY = doubleKey("kmip.retry.delay");

  /** The keys outside the {@code kmip.} namespace that the module sets. */
  static final Set<String> CONVENTIONS =
      Set.of(
          ERROR_TYPE.getKey(),
          SERVER_ADDRESS.getKey(),
          SERVER_PORT.getKey(),
          PROTOCOL_VERSION.getKey(),
          PROTOCOL_NAME.getKey());

  /**
   * The semantic conventions' boundaries for durations in seconds (those of {@code
   * http.client.request.duration}): advice, which a View of the application's SDK can replace.
   */
  static final List<Double> DURATION_BUCKETS =
      List.of(0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0);

  /** {@code attributes}, checked: none in the {@code kmip.} namespace or of {@link #CONVENTIONS}. */
  static Attributes own(Attributes attributes) {
    attributes.forEach(
        (key, value) -> {
          String name = key.getKey();
          if (name.startsWith("kmip.") || CONVENTIONS.contains(name))
            throw new IllegalArgumentException(
                "The attribute " + name + " is the module's own; give yours another key");
        });
    return attributes;
  }

  /** {@code duration} in seconds. */
  static double seconds(Duration duration) {
    return duration.getSeconds() + duration.getNano() / 1e9;
  }

  static String lower(Enum<?> value) {
    return value.name().toLowerCase(Locale.ROOT);
  }

  /**
   * Puts {@code error.type} and {@code kmip.result_reason} of a failure: the SDK's category and
   * the server's reason, or {@code _OTHER} for a failure that is not a {@link KmsException}.
   */
  static AttributesBuilder failure(AttributesBuilder out, Optional<KmsException> failure) {
    KmsException f = failure.orElse(null);
    if (f == null) return out.put(ERROR_TYPE, "_OTHER");
    out.put(ERROR_TYPE, lower(f.category()));
    f.serverReason().ifPresent(r -> out.put(RESULT_REASON, lower(r)));
    return out;
  }

  /**
   * An endpoint's {@code host:port} as {@code server.address} and {@code server.port}: the address
   * without an IPv6 literal's brackets; the whole text as the address, and no port, when it has
   * none.
   */
  static AttributesBuilder endpoint(AttributesBuilder out, String endpoint) {
    int colon = endpoint.lastIndexOf(':');
    long port = -1;
    if (colon > 0 && colon < endpoint.length() - 1)
      try {
        port = Long.parseLong(endpoint.substring(colon + 1));
      } catch (NumberFormatException notAPort) {
        port = -1;
      }
    if (port < 0 || (endpoint.indexOf(':') != colon && endpoint.charAt(0) != '['))
      return out.put(SERVER_ADDRESS, endpoint);
    String host = endpoint.substring(0, colon);
    if (host.startsWith("[") && host.endsWith("]")) host = host.substring(1, host.length() - 1);
    return out.put(SERVER_ADDRESS, host).put(SERVER_PORT, port);
  }
}
