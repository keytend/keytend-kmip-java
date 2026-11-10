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

package dev.keytend.kmip.model;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.ByteBuffer;
import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.*;
import org.junit.jupiter.api.Test;

/** Temporary private-key encodings built during conversion are zeroed. */
class KeysWipeTest {
  @Test
  void sec1ToPkcs8ZeroesItsPkcs8Copy() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(new ECGenParameterSpec("secp256r1"));
    ECPrivateKey key = (ECPrivateKey) generator.generateKeyPair().getPrivate();
    byte[] s = key.getS().toByteArray();
    byte[] d = new byte[32];
    int n = Math.min(32, s.length);
    System.arraycopy(s, s.length - n, d, 32 - n, n);
    byte[] secp256r1 = {0x06, 0x08, 0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x03, 0x01, 0x07};
    byte[] sec1 = new byte[2 + 3 + 2 + 32 + 2 + secp256r1.length];
    ByteBuffer b = ByteBuffer.wrap(sec1);
    b.put((byte) 0x30).put((byte) (sec1.length - 2)).put(new byte[] {0x02, 0x01, 0x01});
    b.put((byte) 0x04).put((byte) 32).put(d);
    b.put((byte) 0xa0).put((byte) secp256r1.length).put(secp256r1);

    byte[][] seen = new byte[1][];
    KeyFactory factory = KeyFactory.getInstance("EC");
    ECPrivateKey converted =
        (ECPrivateKey)
            Keys.withPkcs8(
                sec1,
                pkcs8 -> {
                  seen[0] = pkcs8;
                  return factory.generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
                });
    assertEquals(key.getS(), converted.getS());
    assertNotNull(seen[0]);
    for (byte x : seen[0]) assertEquals(0, x, "the PKCS#8 encoding still holds the private key");
  }
}
