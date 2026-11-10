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

package dev.keytend.kmip.client;

import dev.keytend.kmip.model.Ttlv;
import java.io.IOException;

/**
 * A rejected wire response. Raw fields remain available for diagnosing nonconformant peers.
 *
 * @since 0.10.0
 */
public final class ProtocolException extends IOException {
  private final Ttlv response;

  public ProtocolException(String message, Ttlv response, Throwable cause) {
    super(message, cause);
    this.response = response;
  }

  public Ttlv response() {
    return response;
  }
}
