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

import dev.keytend.kmip.model.Enums;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Objects;
import javax.security.auth.Destroyable;

/**
 * Secret Data (a password, API token or other secret that is not a key) read with {@link
 * KeyHandle#asSecretData()}. It holds its own copy, which {@link #destroy()} (or {@link #close()})
 * wipes; the accessors return fresh copies for the caller to wipe.
 *
 * @since 0.10.0
 */
public final class SecretData implements Destroyable, AutoCloseable {
  /** The KMIP Secret Data Type. */
  public enum Type {
    /** A password, API token or other credential. */
    PASSWORD(Enums.SecretDataType.PASSWORD),
    /** Random material that keys or other values are derived from (KMIP Seed). */
    SEED(Enums.SecretDataType.SEED),
    /** A vendor or future type. */
    OTHER(null);

    private final Enums.SecretDataType wire;

    Type(Enums.SecretDataType wire) {
      this.wire = wire;
    }

    /**
     * The protocol-layer value, or null for {@link #OTHER}.
     *
     * @return the protocol-layer value, or null for {@link #OTHER}
     */
    public Enums.SecretDataType protocolValue() {
      return wire;
    }

    static Type of(int code) {
      for (Type t : values()) if (t.wire != null && t.wire.code() == code) return t;
      return OTHER;
    }
  }

  private final Type type;
  private final byte[] secret;
  private volatile boolean destroyed;

  SecretData(Type type, byte[] secret) {
    this.type = Objects.requireNonNull(type, "type");
    this.secret = secret.clone();
  }

  /**
   * The KMIP Secret Data Type; still available after {@link #destroy()}.
   *
   * @return the type
   */
  public Type type() {
    return type;
  }

  /**
   * A copy of the secret bytes: the whole secret or, once it is destroyed (also by another thread at
   * the same moment), an {@link IllegalStateException}; never a partly wiped secret.
   *
   * @return a new copy of the secret, owned by the caller (wipe it after use)
   * @throws IllegalStateException when the secret has been destroyed
   */
  public synchronized byte[] bytes() {
    check();
    return secret.clone();
  }

  /**
   * A copy of the secret as characters, decoding UTF-8 (the form {@link
   * KmsKeys#registerSecret(char[])} stores).
   *
   * @return a new copy of the secret as characters, owned by the caller (wipe it after use)
   * @throws IllegalStateException when the bytes are not UTF-8, or the secret has been destroyed
   */
  public synchronized char[] chars() {
    check();
    try {
      CharBuffer chars =
          StandardCharsets.UTF_8
              .newDecoder()
              .onMalformedInput(CodingErrorAction.REPORT)
              .onUnmappableCharacter(CodingErrorAction.REPORT)
              .decode(ByteBuffer.wrap(secret));
      char[] out = Arrays.copyOf(chars.array(), chars.limit());
      Arrays.fill(chars.array(), '\0');
      return out;
    } catch (CharacterCodingException e) {
      throw new IllegalStateException("The secret is not UTF-8 text");
    }
  }

  private void check() {
    if (destroyed) throw new IllegalStateException("Secret destroyed");
  }

  @Override
  public synchronized void destroy() {
    destroyed = true;
    Arrays.fill(secret, (byte) 0);
  }

  @Override
  public boolean isDestroyed() {
    return destroyed;
  }

  /** Destroys the secret, so it can be used in try-with-resources. */
  @Override
  public void close() {
    destroy();
  }

  @Override
  public String toString() {
    return "SecretData["
        + type
        + ", "
        + secret.length
        + " bytes"
        + (destroyed ? ", destroyed]" : "]");
  }
}
