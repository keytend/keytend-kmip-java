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

import java.io.*;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.SecretKey;
import javax.security.auth.Destroyable;

/**
 * A {@link SecretKey} whose own copy of the key bytes is zeroed by {@link #destroy()}. JCA
 * providers copy the bytes when a cipher is initialized, and {@link #getEncoded()} returns a copy;
 * those copies are outside this object's reach, so destroying it limits, but does not guarantee,
 * how long the key stays in memory. It cannot be serialized.
 *
 * <p>Thread-safe: {@link #getEncoded()} and {@link #destroy()} exclude each other, so a copy is
 * either the whole key or an {@link IllegalStateException}, never a partly wiped key, even when
 * another thread destroys the key at the same moment.
 *
 * @since 0.10.0
 */
public final class DestroyableSecretKey implements SecretKey, Destroyable, AutoCloseable {
  @Serial private static final long serialVersionUID = 1L;

  /** The JCA algorithm name. */
  private final String algorithm;

  /** The SDK's copy of the key bytes, zeroed by {@link #destroy()}. */
  private final byte[] key;

  /** Whether {@link #destroy()} was called. */
  private volatile boolean destroyed;

  /**
   * Copies {@code key}; the caller may wipe its array afterwards. Applications can hold their own
   * key bytes in it, for example a key to {@link KmsKeys#register register} or
   * {@link CurrentKey#wrapKey(javax.crypto.SecretKey, byte[]) wrap}, so that one {@code destroy()} wipes the copy.
   *
   * @param key the key bytes; copied
   * @param algorithm the JCA algorithm name, for example {@code "AES"}
   */
  public DestroyableSecretKey(byte[] key, String algorithm) {
    this.key = Objects.requireNonNull(key, "key").clone();
    this.algorithm = Objects.requireNonNull(algorithm, "algorithm");
  }

  @Override
  public String getAlgorithm() {
    return algorithm;
  }

  @Override
  public String getFormat() {
    return "RAW";
  }

  /**
   * A copy of the key bytes.
   *
   * @throws IllegalStateException when the key has been destroyed
   */
  @Override
  public synchronized byte[] getEncoded() {
    if (destroyed) throw new IllegalStateException("Key destroyed");
    return key.clone();
  }

  @Override
  public synchronized void destroy() {
    destroyed = true;
    Arrays.fill(key, (byte) 0);
  }

  /** Destroys the key, so it can be used in try-with-resources. */
  @Override
  public void close() {
    destroy();
  }

  @Override
  public boolean isDestroyed() {
    return destroyed;
  }

  @Override
  public String toString() {
    return "DestroyableSecretKey[" + algorithm + ", " + key.length * 8 + " bits]";
  }

  @Override
  public boolean equals(Object o) {
    return o == this;
  }

  @Override
  public int hashCode() {
    return System.identityHashCode(this);
  }

  /**
   * Destroys {@code key} if it supports destruction; keys that cannot be destroyed (most JDK keys)
   * are left alone.
   *
   * @param key the key to destroy, or null (nothing is done)
   */
  public static void destroyQuietly(java.security.Key key) {
    if (key instanceof javax.security.auth.Destroyable d && !d.isDestroyed())
      try {
        d.destroy();
      } catch (javax.security.auth.DestroyFailedException ignored) {
        // JDK keys that do not support destruction
      }
  }

  /**
   * Refuses serialization: key material is not serialized.
   *
   * @return nothing: it always throws
   * @throws ObjectStreamException always ({@link NotSerializableException})
   */
  private Object writeReplace() throws ObjectStreamException {
    throw new NotSerializableException("Key material is not serializable");
  }

  /**
   * Refuses deserialization: key material is not serialized.
   *
   * @param in the stream
   * @throws IOException always ({@link NotSerializableException})
   */
  private void readObject(ObjectInputStream in) throws IOException {
    throw new NotSerializableException("Key material is not serializable");
  }
}
