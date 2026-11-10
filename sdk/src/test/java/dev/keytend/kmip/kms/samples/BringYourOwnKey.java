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

package dev.keytend.kmip.kms.samples;

import dev.keytend.kmip.kms.*;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.crypto.SecretKey;

/**
 * A7. Bring your own key: import keys generated outside the KMS (a JCA {@link SecretKey}, an RSA
 * or EC {@link PrivateKey} and its {@link PublicKey}) with attributes and usage, and read them
 * back as JCA keys.
 */
public final class BringYourOwnKey {
  private BringYourOwnKey() {}

  public record Imported(KeyHandle secret, KeyHandle privateKey, KeyHandle publicKey) {}

  public static Imported importKeys(Kms kms, SecretKey secret, KeyPair pair, String name) {
    KeyHandle s =
        kms.keys()
            .register(secret)
            .named(name + "-aes")
            .usages(KeyUsage.ENCRYPT, KeyUsage.DECRYPT)
            .register();
    KeyHandle priv =
        kms.keys().register(pair.getPrivate()).named(name + "-private").usages(KeyUsage.SIGN).registerPreActive();
    KeyHandle pub =
        kms.keys().register(pair.getPublic()).named(name + "-public").usages(KeyUsage.VERIFY).registerPreActive();
    return new Imported(s, priv, pub);
  }

  public static SecretKey readSecret(KeyHandle handle, int bits) {
    return handle.asSecretKey(Expect.aes(bits), LocalUse.DECRYPT);
  }

  public static PrivateKey readPrivate(KeyHandle handle, Expect expect) {
    return handle.asPrivateKey(expect);
  }

  public static PublicKey readPublic(KeyHandle handle, Expect expect) {
    return handle.asPublicKey(expect);
  }
}
