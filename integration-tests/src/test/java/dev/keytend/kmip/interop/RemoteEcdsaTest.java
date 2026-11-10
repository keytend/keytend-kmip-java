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

package dev.keytend.kmip.interop;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Arrays;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

/**
 * CatalogObjects.verifyRemoteEcdsa: a server's ECDSA signature verifies in the wire encoding it
 * was sent in (fixed-width r||s or DER), which is reported, on every NIST curve including P-521,
 * whose DER SEQUENCE needs a long-form length.
 */
class RemoteEcdsaTest {
  private static final byte[] DATA = "catalog CRYPTO-05".getBytes(StandardCharsets.UTF_8);
  private static final String RAW = "fixed-width r||s (IEEE P1363)";

  private static KeyPair pair(String curve) throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    g.initialize(new ECGenParameterSpec(curve));
    return g.generateKeyPair();
  }

  private static byte[] sign(KeyPair p, String algorithm) throws Exception {
    Signature s = Signature.getInstance(algorithm);
    s.initSign(p.getPrivate());
    s.update(DATA);
    return s.sign();
  }

  @ParameterizedTest
  @CsvSource({"secp256r1, SHA256, 32", "secp384r1, SHA384, 48", "secp521r1, SHA384, 66"})
  void bothWireEncodingsVerifyAndAreReported(String curve, String hash, int width)
      throws Exception {
    KeyPair p = pair(curve);
    for (int i = 0; i < 8; i++) {
      byte[] raw = sign(p, hash + "withECDSAinP1363Format");
      assertEquals(2 * width, raw.length);
      assertEquals(RAW, CatalogObjects.verifyRemoteEcdsa(p.getPublic(), hash, DATA, raw));
      byte[] der = sign(p, hash + "withECDSA");
      assertEquals(0x30, der[0] & 0xff);
      if (width == 66) assertEquals(0x81, der[1] & 0xff, "P-521 DER needs a long-form length");
      assertEquals("DER", CatalogObjects.verifyRemoteEcdsa(p.getPublic(), hash, DATA, der));
    }
  }

  @ParameterizedTest
  @CsvSource({"secp256r1, SHA256", "secp384r1, SHA384", "secp521r1, SHA384"})
  void tamperedTruncatedOrForeignSignaturesDoNotVerify(String curve, String hash) throws Exception {
    KeyPair p = pair(curve), other = pair(curve);
    for (String algorithm : new String[] {hash + "withECDSAinP1363Format", hash + "withECDSA"}) {
      byte[] good = sign(p, algorithm);
      byte[] flipped = good.clone();
      flipped[flipped.length - 1] ^= 1;
      assertNull(CatalogObjects.verifyRemoteEcdsa(p.getPublic(), hash, DATA, flipped));
      byte[] truncated = Arrays.copyOf(good, good.length - 1);
      assertNull(CatalogObjects.verifyRemoteEcdsa(p.getPublic(), hash, DATA, truncated));
      assertNull(CatalogObjects.verifyRemoteEcdsa(other.getPublic(), hash, DATA, good));
      assertNull(
          CatalogObjects.verifyRemoteEcdsa(
              p.getPublic(), hash, "other".getBytes(StandardCharsets.UTF_8), good));
    }
    assertNull(CatalogObjects.verifyRemoteEcdsa(p.getPublic(), hash, DATA, new byte[0]));
  }

  @ParameterizedTest
  @CsvSource({"SHA256", "SHA384"})
  void aFixedWidthSignatureOfAnotherCurveIsNotReadAsRawForThisKey(String hash) throws Exception {
    // A P-384 key's r||s is 96 bytes; a P-256 key reads 64-byte r||s only.
    KeyPair p256 = pair("secp256r1"), p384 = pair("secp384r1");
    byte[] raw384 = sign(p384, hash + "withECDSAinP1363Format");
    assertNull(CatalogObjects.verifyRemoteEcdsa(p256.getPublic(), hash, DATA, raw384));
    byte[] raw256 = sign(p256, hash + "withECDSAinP1363Format");
    assertNull(CatalogObjects.verifyRemoteEcdsa(p384.getPublic(), hash, DATA, raw256));
  }

  @ParameterizedTest
  @CsvSource({"SHA256", "SHA384"})
  void theHashIsPartOfTheCheck(String hash) throws Exception {
    KeyPair p = pair("secp384r1");
    String otherHash = hash.equals("SHA256") ? "SHA384" : "SHA256";
    byte[] raw = sign(p, otherHash + "withECDSAinP1363Format");
    assertNull(CatalogObjects.verifyRemoteEcdsa(p.getPublic(), hash, DATA, raw));
    byte[] der = sign(p, otherHash + "withECDSA");
    assertNull(CatalogObjects.verifyRemoteEcdsa(p.getPublic(), hash, DATA, der));
  }
}
