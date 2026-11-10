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

import java.util.Objects;
import javax.security.auth.Destroyable;

/**
 * A data-encryption key from {@link CurrentKey#generateDataKey}: the plaintext key for local use,
 * and the same key wrapped by the key-encryption key for storage. {@link #destroy()} wipes the
 * plaintext key; the wrapped form is not secret.
 *
 * @since 0.10.0
 */
public final class DataKey implements Destroyable, AutoCloseable {
  private final DestroyableSecretKey key;
  private final Ciphertext wrapped;

  DataKey(DestroyableSecretKey key, Ciphertext wrapped) {
    this.key = Objects.requireNonNull(key, "key");
    this.wrapped = Objects.requireNonNull(wrapped, "wrapped");
  }

  /**
   * The plaintext key (the same object every time; destroying this data key destroys it).
   *
   * @return the plaintext key, owned by this data key
   * @throws IllegalStateException when the data key has been destroyed
   */
  public DestroyableSecretKey key() {
    if (key.isDestroyed()) throw new IllegalStateException("Data key destroyed");
    return key;
  }

  /**
   * The key wrapped by the key-encryption key, to store next to the data.
   *
   * @return the wrapped key; not secret, and still available after {@link #destroy()}
   */
  public Ciphertext wrapped() {
    return wrapped;
  }

  @Override
  public void destroy() {
    key.destroy();
  }

  /** Destroys the plaintext key, so a data key can be used in try-with-resources. */
  @Override
  public void close() {
    destroy();
  }

  @Override
  public boolean isDestroyed() {
    return key.isDestroyed();
  }

  @Override
  public String toString() {
    return "DataKey[" + wrapped + (isDestroyed() ? ", destroyed]" : "]");
  }
}
