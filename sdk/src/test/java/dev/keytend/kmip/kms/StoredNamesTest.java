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
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

/**
 * What the SDK stores on a KMS server under its own name is spelled {@code keytend}.
 */
class StoredNamesTest {
  @Test
  void theNameMoveRecordIsAKeytendClientAttribute() throws Exception {
    String hash =
        HexFormat.of()
            .formatHex(
                MessageDigest.getInstance("SHA-256")
                    .digest("orders".getBytes(StandardCharsets.UTF_8)),
                0,
                16);
    CustomAttribute record = KeyHandle.pendingName("orders");
    assertEquals(new CustomAttribute("x", "keytend-pending-name-" + hash), record);
    assertTrue(KeyHandle.isPendingRecord(record));
  }
}
