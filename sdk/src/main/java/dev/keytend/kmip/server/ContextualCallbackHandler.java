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

package dev.keytend.kmip.server;

import dev.keytend.kmip.model.*;

/**
 * A {@link CallbackHandler} that sees the authenticated peer. Use it to check that a Put or Notify
 * came from the expected KMIP server, in addition to (not instead of) a trust store that admits
 * only that server; see {@link CallbackServer}.
 *
 * @since 0.10.0
 */
@FunctionalInterface
public interface ContextualCallbackHandler extends CallbackHandler {
  @Override
  Reply handle(CallbackContext context, Operation operation, Ttlv payload);

  /** Not used: {@link CallbackMessages} always calls the contextual method. */
  @Override
  default Reply handle(Operation operation, Ttlv payload) {
    return handle(CallbackContext.NONE, operation, payload);
  }
}
